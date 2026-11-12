# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Run collection integration test targets against a live Falcon tenant.

Ansible requires content to live in an ``ansible_collections/<ns>/<name>/``
directory layout, and ``ansible-test`` scrubs the environment so credentials
passed as env vars never reach the module. This wrapper works around both:

  * it stages a symlinked ``ansible_collections/crowdstrike/falcon`` layout in a
    temp dir (no copying - the symlink points at this checkout), and
  * it runs each target's ``tasks/main.yml`` through plain ``ansible-playbook``
    so the process environment (and therefore ``lookup('env', ...)``) is intact.

Each target runs in its own ``ansible-playbook`` process, so a failed target
does not stop the others and facts do not leak between targets. A summary is
printed at the end, and the exit code is non-zero if any target failed.

Credentials are read from a ``.env`` file (via python-dotenv, if present) or from
the existing process environment. Use ``--env-file`` to read another file
instead of ``.env``, for example the credentials of a different tenant. Required: ``FALCON_CLIENT_ID`` and
``FALCON_CLIENT_SECRET``; optional: ``FALCON_CLOUD``.

Some targets need a subscription or a type of tenant that not every test tenant
has. They skip their tests unless you opt in:

  * ``FALCON_TEST_HUNTING=1``: hunting_rule_download in the intel_rules target
    (needs Falcon Adversary Intelligence Premium)
  * ``FALCON_TEST_FLIGHT_CONTROL=1``: the flight_control target (needs a
    Flight Control parent CID)

Usage:
    uv run tests/integration/run.py                       # run all targets
    uv run tests/integration/run.py ngsiem_data_connection # run specific target(s)
    uv run tests/integration/run.py --list                # list available targets
    uv run tests/integration/run.py --env-file .env.flight-control flight_control
    uv run tests/integration/run.py -- -vvv               # pass extra args to ansible-playbook
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# This file lives at <collection>/tests/integration/run.py
INTEGRATION_DIR = Path(__file__).resolve().parent
COLLECTION_ROOT = INTEGRATION_DIR.parent.parent
TARGETS_DIR = INTEGRATION_DIR / "targets"

NAMESPACE = "crowdstrike"
COLLECTION = "falcon"

REQUIRED_ENV = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")


def discover_targets():
    """Return the sorted names of integration targets that have a tasks/main.yml."""
    if not TARGETS_DIR.is_dir():
        return []
    return sorted(
        p.name
        for p in TARGETS_DIR.iterdir()
        if p.is_dir() and (p / "tasks" / "main.yml").is_file()
    )


def load_dotenv_if_present(env_file=None):
    """Load a .env file into the environment, if available.

    Reads env_file if given, else the .env file in the collection root.

    Existing environment variables always win over .env values, so creds already
    exported in the shell take precedence. python-dotenv is optional; if it is not
    installed we simply rely on the current environment.
    """
    if env_file is None:
        env_file = COLLECTION_ROOT / ".env"
    if not env_file.is_file():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        sys.stderr.write(
            "note: found .env but python-dotenv is not installed; "
            "relying on existing environment variables.\n"
        )
        return
    load_dotenv(dotenv_path=env_file, override=False)


def detect_interpreter():
    """Return a Python interpreter that can import falconpy.

    Prefers the interpreter running this script (typically 'uv run' with falconpy
    available). Falls back to the collection's local .venv.
    """
    candidates = [sys.executable, str(COLLECTION_ROOT / ".venv" / "bin" / "python3")]
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        probe = subprocess.run(
            [candidate, "-c", "import falconpy"],
            capture_output=True,
            check=False,
        )
        if probe.returncode == 0:
            return candidate
    return None


def find_ansible_playbook():
    """Return the ansible-playbook to run, or None.

    Prefers the one installed next to the Python running this script, because
    lookups and inventory plugins run in the controller's Python and need
    falconpy there too. Falls back to the one on PATH.
    """
    local = Path(sys.executable).parent / "ansible-playbook"
    if local.exists():
        return str(local)
    return shutil.which("ansible-playbook")


def build_playbook(staging_dir, targets):
    """Write a wrapper playbook that includes each target's tasks and return its path."""
    rel = f"ansible_collections/{NAMESPACE}/{COLLECTION}/tests/integration/targets"
    tasks = "\n".join(
        f"    - name: Run target '{t}'\n"
        f"      ansible.builtin.include_tasks: "
        f'"{{{{ playbook_dir }}}}/{rel}/{t}/tasks/main.yml"'
        for t in targets
    )
    content = (
        "---\n"
        "- name: CrowdStrike Falcon integration tests\n"
        "  hosts: localhost\n"
        "  gather_facts: false\n"
        "  tasks:\n"
        f"{tasks}\n"
    )
    playbook = staging_dir / "run_integration.yml"
    playbook.write_text(content)
    return playbook


def main():
    """Parse arguments, stage the layout, and run the requested targets."""
    # Split on '--': everything after it is passed through to ansible-playbook.
    argv = sys.argv[1:]
    passthrough = []
    if "--" in argv:
        idx = argv.index("--")
        argv, passthrough = argv[:idx], argv[idx + 1:]

    parser = argparse.ArgumentParser(
        description="Run collection integration targets against a live tenant.",
        epilog="Args after '--' are passed through to ansible-playbook.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target name(s) to run. Defaults to all discovered targets.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Read credentials from this file instead of the .env file in the collection root.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available integration targets and exit.",
    )
    args = parser.parse_args(argv)

    available = discover_targets()

    if args.list:
        if available:
            print("Available integration targets:")
            for name in available:
                print(f"  {name}")
        else:
            print("No integration targets found.")
        return 0

    targets = args.targets or available
    if not targets:
        sys.stderr.write("error: no integration targets found to run.\n")
        return 1

    unknown = [t for t in targets if t not in available]
    if unknown:
        sys.stderr.write(
            f"error: unknown target(s): {', '.join(unknown)}\n"
            f"available: {', '.join(available) or '(none)'}\n"
        )
        return 1

    if args.env_file and not args.env_file.is_file():
        sys.stderr.write(f"error: env file not found: {args.env_file}\n")
        return 1
    load_dotenv_if_present(args.env_file)

    missing = [var for var in REQUIRED_ENV if not os.environ.get(var)]
    if missing:
        sys.stderr.write(
            f"error: missing required environment variable(s): {', '.join(missing)}\n"
            "Set them in the environment or in a .env file at the collection root.\n"
        )
        return 1

    interpreter = detect_interpreter()
    if not interpreter:
        sys.stderr.write(
            "error: could not find a Python interpreter with falconpy installed.\n"
            "Run this via 'uv run tests/integration/run.py' or install falconpy.\n"
        )
        return 1

    ansible_playbook = find_ansible_playbook()
    if not ansible_playbook:
        sys.stderr.write("error: ansible-playbook not found on PATH.\n")
        return 1

    staging_dir = Path(tempfile.mkdtemp(prefix="cs-falcon-itest-"))
    try:
        link_parent = staging_dir / "ansible_collections" / NAMESPACE
        link_parent.mkdir(parents=True)
        (link_parent / COLLECTION).symlink_to(COLLECTION_ROOT)

        env = os.environ.copy()
        env["ANSIBLE_COLLECTIONS_PATH"] = str(staging_dir)

        # Flush, so that this comes before the ansible-playbook output
        print(f"Running targets: {', '.join(targets)}")
        print(f"Interpreter: {interpreter}\n", flush=True)

        results = {}
        for target in targets:
            playbook = build_playbook(staging_dir, [target])
            cmd = [
                ansible_playbook,
                str(playbook),
                "-e",
                f"ansible_python_interpreter={interpreter}",
                *passthrough,
            ]
            completed = subprocess.run(cmd, env=env, check=False)
            results[target] = completed.returncode

        print("\nSummary:")
        for target, returncode in results.items():
            status = "ok" if returncode == 0 else f"FAILED (exit {returncode})"
            print(f"  {target}: {status}")
        return 0 if all(rc == 0 for rc in results.values()) else 1
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
