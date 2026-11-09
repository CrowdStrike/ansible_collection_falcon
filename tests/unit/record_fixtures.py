# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Record Falcon API responses as sanitized unit test fixtures.

The unit tests in tests/unit/plugins do not call the API. They replay the
responses that this script records from a real tenant. Run it again when a
plugin starts to use a new API call, or when FalconPy or the API changes.

The script calls FalconPy directly. For the services that can change state it
makes throwaway objects named 'ansible-unit-fixture-*' and deletes them when it
is done. It does not change hosts or other objects that it did not make.

Every response goes through the Sanitizer before it is written: IDs, emails,
IP and MAC addresses, host names and tokens are replaced. Then the script
checks that no credential and no original ID is left in the output. If one is
found, it writes no files.

Credentials are read from a .env file (via python-dotenv) or from the process
environment. Required: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET. Optional:
FALCON_CLOUD and FALCON_MEMBER_CID.

Usage:
    uv run --with crowdstrike-falconpy --with python-dotenv \\
        tests/unit/record_fixtures.py [--env-file PATH] [--dry-run] [SERVICE ...]
    uv run tests/unit/record_fixtures.py --list
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

UNIT_DIR = Path(__file__).resolve().parent
COLLECTION_ROOT = UNIT_DIR.parent.parent
FIXTURES_DIR = UNIT_DIR / "plugins" / "fixtures"

REQUIRED_ENV = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")
# Values that must never appear in a fixture.
SECRET_ENV = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_MEMBER_CID", "FALCON_CID")

PREFIX = "ansible-unit-fixture"

HEX32_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
UUID_RE = re.compile(
    r"(?<![0-9a-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
GROUPING_TAG_RE = re.compile(r"((?:Sensor|Falcon)GroupingTags/)[^,\"'\s]+")

TOKEN_KEYS = {
    "access_token",
    "refresh_token",
    "token",
    "uninstall_token",
    "ingest_token",
    "provisioning_token",
    "api_key",
    "client_secret",
}
HOST_KEYS = {
    "hostname",
    "computer_name",
    "machine_domain",
    "site_name",
    "ou",
    "serial_number",
    "instance_id",
    "service_provider_account_id",
    "pod_name",
    "pod_namespace",
    "pod_hostname",
}
DROP_KEYS = {"trace_id", "powered_by"}


def is_fake_hex32(value):
    """Return True for an ID that the Sanitizer made."""
    return value.isdigit() and int(value) < 10**8


def is_fake_uuid(value):
    """Return True for a UUID that the Sanitizer made."""
    return value.startswith("00000000-0000-0000-0000-")


class Sanitizer:
    """Replace tenant data in API responses with stable fake values.

    The same input value always gets the same fake value, also across
    fixture files, so the links between objects (a group ID in a host, for
    example) stay correct.
    """

    def __init__(self):
        self.maps = {"hex": {}, "uuid": {}, "email": {}, "host": {}, "ip": {}, "mac": {}, "tag": {}}

    def _fake(self, kind, value, make):
        table = self.maps[kind]
        key = value.lower()
        if key not in table:
            table[key] = make(len(table) + 1)
        return table[key]

    def _string(self, value):
        value = HEX32_RE.sub(
            lambda m: m.group(0)
            if is_fake_hex32(m.group(0))
            else self._fake("hex", m.group(0), lambda n: "%032d" % n),
            value,
        )
        value = UUID_RE.sub(
            lambda m: m.group(0)
            if is_fake_uuid(m.group(0))
            else self._fake("uuid", m.group(0), lambda n: "00000000-0000-0000-0000-%012d" % n),
            value,
        )
        value = EMAIL_RE.sub(
            lambda m: m.group(0)
            if m.group(0).endswith("@example.com")
            else self._fake("email", m.group(0), lambda n: "user%d@example.com" % n),
            value,
        )
        return GROUPING_TAG_RE.sub(
            lambda m: m.group(1) + self._fake("tag", m.group(0), lambda n: "tag%d" % n),
            value,
        )

    def _ip(self, value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return self._string(value)
        if address.version == 4:
            return self._fake("ip", value, lambda n: "192.0.2.%d" % (n % 254 + 1))
        return self._fake("ip", value, lambda n: "2001:db8::%x" % n)

    def _by_key(self, key, value):
        """Sanitize a string value with rules that depend on its key."""
        key = key.lower()
        if key in TOKEN_KEYS:
            return "REDACTED" if value else value
        if key in HOST_KEYS:
            return self._fake("host", value, lambda n: "host%d" % n) if value else value
        if "mac_address" in key:
            return self._fake("mac", value, lambda n: "00-00-5e-00-53-%02x" % (n % 256))
        if key.endswith("_ip") or key.endswith("ip_address") or key == "ip":
            return self._ip(value)
        return self._string(value)

    def clean(self, data, key=""):
        """Return a sanitized copy of data."""
        if isinstance(data, dict):
            return {
                k: self.clean(v, k) for k, v in data.items() if k not in DROP_KEYS
            }
        if isinstance(data, list):
            return [self.clean(v, key) for v in data]
        if isinstance(data, str):
            return self._by_key(key, data)
        return data

    def leaks(self, text, secrets):
        """Return a description of each original value found in text."""
        lowered = text.lower()
        found = ["env:%s" % name for name, value in secrets.items() if value.lower() in lowered]
        for kind, table in self.maps.items():
            # Short host names such as 'ou' values can also be normal words.
            found += [
                "%s value #%d" % (kind, i)
                for i, original in enumerate(table, 1)
                if len(original) >= 6 and original in lowered
            ]
        return found


class Recorder:
    """Collect sanitized responses for one service."""

    def __init__(self, service, sanitizer, dry_run):
        self.service = service
        self.sanitizer = sanitizer
        self.dry_run = dry_run
        self.files = {}

    def save(self, case, method, response):
        """Sanitize a FalconPy response and keep it as fixtures/<service>/<case>.json."""
        print("  %s/%s <- %s (HTTP %s)" % (self.service, case, method, response.get("status_code")))
        data = {
            "method": method,
            "status_code": response["status_code"],
            "body": response["body"],
        }
        self.files[case] = self.sanitizer.clean(data)
        return response

    def call(self, case, method, func, **kwargs):
        """Call func(**kwargs), save the response as case, and return it."""
        if self.dry_run:
            print("  %s/%s <- %s(%s)" % (self.service, case, method, ", ".join(sorted(kwargs))))
            return {"status_code": 0, "body": {"resources": [], "errors": []}}
        return self.save(case, method, func(**kwargs))


def resources(response):
    """Return the resources list of a response, or an empty list."""
    return (response.get("body") or {}).get("resources") or []


def record_host_group(rec, creds):
    """Record the HostGroup calls used by host_group and host_group_info."""
    from falconpy import HostGroup

    falcon = HostGroup(**creds)
    names = ["%s-%s" % (PREFIX, suffix) for suffix in ("a", "b", "c")]
    name_filter = "name:[%s]" % ",".join("'%s'" % name for name in names)
    rule = "tags:'SensorGroupingTags/%s'" % PREFIX

    def cleanup():
        if rec.dry_run:
            return
        ids = [g["id"] for g in resources(falcon.query_combined_host_groups(filter=name_filter))]
        ids += [g["id"] for g in resources(falcon.query_combined_host_groups(filter="name:'%s-dynamic'" % PREFIX))]
        if ids:
            falcon.delete_host_groups(ids=ids)

    cleanup()
    try:
        created = rec.call(
            "create_static", "create_host_groups", falcon.create_host_groups,
            name=names[0], group_type="static", description="Fixture group",
        )
        group_id = (resources(created) or [{"id": "0" * 32}])[0]["id"]
        for name in names[1:]:
            if not rec.dry_run:
                falcon.create_host_groups(name=name, group_type="static")
        rec.call(
            "create_dynamic", "create_host_groups", falcon.create_host_groups,
            name="%s-dynamic" % PREFIX, group_type="dynamic", assignment_rule=rule,
        )
        rec.call(
            "create_duplicate", "create_host_groups", falcon.create_host_groups,
            name=names[0], group_type="static",
        )
        rec.call("get_one", "get_host_groups", falcon.get_host_groups, ids=[group_id])
        rec.call(
            "query_by_name", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter="name:'%s'" % names[0], limit=1,
        )
        rec.call(
            "query_by_name_missing", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter="name:'%s-missing'" % PREFIX, limit=1,
        )
        rec.call(
            "query_page1", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter=name_filter, limit=2, offset=0, sort="name.asc",
        )
        rec.call(
            "query_page2", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter=name_filter, limit=2, offset=2, sort="name.asc",
        )
        rec.call(
            "query_bad_filter", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter="name:'", limit=1,
        )
        rec.call(
            "update_description", "update_host_groups", falcon.update_host_groups,
            id=group_id, description="Fixture group, updated",
        )
        rec.call("get_after_update", "get_host_groups", falcon.get_host_groups, ids=[group_id])
        rec.call(
            "members_empty", "query_combined_group_members", falcon.query_combined_group_members,
            id=group_id, limit=5000,
        )
        rec.call(
            "add_hosts_missing_host", "perform_group_action", falcon.perform_group_action,
            action_name="add-hosts", ids=[group_id], filter='device_id:["%s"]' % ("f" * 32),
        )
        rec.call("delete", "delete_host_groups", falcon.delete_host_groups, ids=[group_id])
        rec.call("get_missing", "get_host_groups", falcon.get_host_groups, ids=[group_id])
    finally:
        cleanup()


def record_sensor_update_policy(rec, creds):
    """Record the SensorUpdatePolicy calls used by the sensor update modules and the maintenance_token lookup."""
    from falconpy import SensorUpdatePolicy

    falcon = SensorUpdatePolicy(**creds)
    names = ["%s-%s" % (PREFIX, suffix) for suffix in ("a", "b", "c")]
    name_filter = "name.raw:[%s]+platform_name:'Linux'" % ",".join("'%s'" % name for name in names)
    scheduler = {
        "enabled": True,
        "timezone": "Etc/UTC",
        "schedules": [{"start": "08:00", "end": "14:00", "days": [1, 2, 3, 4, 5]}],
    }
    missing_id = "f" * 32

    def cleanup():
        if rec.dry_run:
            return
        for policy in resources(falcon.query_combined_policies_v2(filter=name_filter)):
            if policy.get("enabled"):
                falcon.perform_policies_action(action_name="disable", ids=[policy["id"]])
            falcon.delete_policies(ids=[policy["id"]])

    builds = rec.call(
        "builds_linux", "query_combined_builds", falcon.query_combined_builds,
        platform="linux", stage="prod",
    )
    build = (resources(builds) or [{"build": "00000|n|tagged|1"}])[0]["build"]
    rec.call(
        "builds_bad_platform", "query_combined_builds", falcon.query_combined_builds,
        platform="not-a-platform",
    )

    kernels = rec.call(
        "kernels_page", "query_combined_kernels", falcon.query_combined_kernels, limit=2,
    )
    release = (resources(kernels) or [{"release": "0"}])[0]["release"]
    rec.call(
        "kernels_filtered", "query_combined_kernels", falcon.query_combined_kernels,
        filter="release:'%s'" % release, offset=None, limit=500,
    )

    rec.call(
        "token_bulk", "reveal_uninstall_token", falcon.reveal_uninstall_token,
        audit_message="Ansible unit test fixture recording", device_id="MAINTENANCE",
    )
    rec.call(
        "token_missing_device", "reveal_uninstall_token", falcon.reveal_uninstall_token,
        audit_message="Ansible unit test fixture recording", device_id=missing_id,
    )

    def policy_body(name, **settings):
        policy = {"name": name, "platform_name": "Linux", "description": "Fixture policy"}
        if settings:
            policy["settings"] = settings
        return {"resources": [policy]}

    cleanup()
    try:
        created = rec.call(
            "create", "create_policies_v2", falcon.create_policies_v2,
            body=policy_body(names[0], build=build, uninstall_protection="DISABLED", scheduler=scheduler),
        )
        policy_id = (resources(created) or [{"id": "0" * 32}])[0]["id"]
        for name in names[1:]:
            if not rec.dry_run:
                falcon.create_policies_v2(body=policy_body(name))
        rec.call(
            "create_duplicate", "create_policies_v2", falcon.create_policies_v2,
            body=policy_body(names[0]),
        )
        rec.call("get_one", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
        rec.call(
            "query_by_name", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter="name.raw:'%s'+platform_name:'Linux'" % names[0], limit=1,
        )
        rec.call(
            "query_by_name_missing", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter="name.raw:'%s-missing'+platform_name:'Linux'" % PREFIX, limit=1,
        )
        page1 = rec.call(
            "query_page1", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter=name_filter, offset=None, limit=2,
        )
        next_offset = ((page1.get("body") or {}).get("meta") or {}).get("pagination", {}).get("offset", 2)
        rec.call(
            "query_page2", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter=name_filter, offset=next_offset, limit=2,
        )
        rec.call(
            "query_bad_filter", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter="name.raw:'", limit=1,
        )
        rec.call(
            "update_description", "update_policies_v2", falcon.update_policies_v2,
            body={"resources": [{"id": policy_id, "description": "Fixture policy, updated"}]},
        )
        rec.call("get_after_update", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
        rec.call(
            "enable", "perform_policies_action", falcon.perform_policies_action,
            action_name="enable", ids=[policy_id],
        )
        rec.call("get_after_enable", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
        rec.call(
            "add_host_group_missing", "perform_policies_action", falcon.perform_policies_action,
            action_name="add-host-group", ids=[policy_id],
            action_parameters=[{"name": "group_id", "value": missing_id}],
        )
        rec.call(
            "disable", "perform_policies_action", falcon.perform_policies_action,
            action_name="disable", ids=[policy_id],
        )
        rec.call("delete", "delete_policies", falcon.delete_policies, ids=[policy_id])
        rec.call("get_missing", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
    finally:
        cleanup()


SCENARIOS = {
    "host_group": record_host_group,
    "sensor_update_policy": record_sensor_update_policy,
}


def load_env(env_file):
    """Load env_file into the environment, if it exists. Existing variables win."""
    if not env_file.is_file():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        sys.stderr.write("note: python-dotenv is not installed; using the existing environment.\n")
        return
    load_dotenv(dotenv_path=env_file, override=False)


def main():
    """Parse arguments, run the requested scenarios, and write the fixtures."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("services", nargs="*", help="Services to record. Default: all.")
    parser.add_argument("--env-file", type=Path, default=COLLECTION_ROOT / ".env")
    parser.add_argument("--dry-run", action="store_true", help="List the calls; do not call the API.")
    parser.add_argument("--list", action="store_true", help="List the services and exit.")
    args = parser.parse_args()

    if args.list:
        print("\n".join(sorted(SCENARIOS)))
        return 0

    services = args.services or sorted(SCENARIOS)
    unknown = [s for s in services if s not in SCENARIOS]
    if unknown:
        sys.stderr.write("error: unknown service(s): %s\n" % ", ".join(unknown))
        return 1

    creds = {}
    secrets = {}
    if not args.dry_run:
        load_env(args.env_file)
        missing = [var for var in REQUIRED_ENV if not os.environ.get(var)]
        if missing:
            sys.stderr.write("error: missing environment variable(s): %s\n" % ", ".join(missing))
            return 1
        creds = {
            "client_id": os.environ["FALCON_CLIENT_ID"],
            "client_secret": os.environ["FALCON_CLIENT_SECRET"],
            "base_url": os.environ.get("FALCON_CLOUD") or "us-1",
        }
        if os.environ.get("FALCON_MEMBER_CID"):
            creds["member_cid"] = os.environ["FALCON_MEMBER_CID"]
        secrets = {name: os.environ[name] for name in SECRET_ENV if len(os.environ.get(name, "")) >= 6}

    sanitizer = Sanitizer()
    recorders = []
    for service in services:
        print("Recording %s" % service)
        rec = Recorder(service, sanitizer, args.dry_run)
        SCENARIOS[service](rec, creds)
        recorders.append(rec)

    if args.dry_run:
        return 0

    # Check every file before any file is written.
    outputs = {}
    problems = []
    for rec in recorders:
        for case, data in rec.files.items():
            text = json.dumps(data, indent=2, sort_keys=True) + "\n"
            leaks = sanitizer.leaks(text, secrets)
            if leaks:
                problems.append("%s/%s: %s" % (rec.service, case, ", ".join(leaks)))
            outputs[FIXTURES_DIR / rec.service / (case + ".json")] = text
    if problems:
        sys.stderr.write("error: tenant data found after sanitizing; no files written:\n")
        sys.stderr.write("".join("  %s\n" % p for p in problems))
        return 1

    for path, text in sorted(outputs.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print("Wrote %d fixture file(s) to %s" % (len(outputs), FIXTURES_DIR))
    return 0


if __name__ == "__main__":
    sys.exit(main())
