# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import contextlib
import json
from unittest.mock import patch

import pytest

from ansible.module_utils import basic
from ansible.module_utils.common import warnings
from ansible.module_utils.common.text.converters import to_bytes

FALCONCTL = "/opt/CrowdStrike/falconctl"


@contextlib.contextmanager
def _module_args(args):
    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:  # ansible-core < 2.19
        serialized = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
        with patch.object(basic, "_ANSIBLE_ARGS", serialized):
            yield
    else:
        with patch_module_args(args):
            yield


def _reset_warnings(monkeypatch):
    # Deprecations and warnings are kept in module-level state, so start
    # each test with empty ones.
    monkeypatch.setattr(
        warnings, "_global_deprecations", type(warnings._global_deprecations)()
    )
    monkeypatch.setattr(
        warnings, "_global_warnings", type(warnings._global_warnings)()
    )


@pytest.fixture
def run_module(monkeypatch, capsys):
    """Return a function that runs module.main() and returns its JSON result."""
    _reset_warnings(monkeypatch)

    def run(module, args, check_mode=False):
        if check_mode:
            args = dict(args, _ansible_check_mode=True)
        with _module_args(args), pytest.raises(SystemExit):
            module.main()
        return json.loads(capsys.readouterr().out)

    return run


class FakeSensor(object):
    """A stateful stand-in for falconctl.

    'falconctl -s/-d' change the stored options and 'falconctl -g' prints
    them in the sensor's '<option>=<value>.' format, so a module can be run
    twice to check idempotence.
    """

    def __init__(self, run_module):
        self.options = {}
        self.commands = []
        # stderr for the next 'falconctl -s/-d' calls, e.g. an error message
        self.stderr = ""
        self._run_module = run_module

    def run_command(self, cmd):
        """Handle 'falconctl -g' and record 'falconctl -s/-d'."""
        if cmd[1] == "-g":
            return self.get(cmd)
        return self.set_or_delete(cmd)

    def get(self, cmd):
        opt = cmd[2][2:]
        value = self.options.get(opt)
        if value is None:
            return (0, "%s is not set.\n" % opt, "")
        # The sensor quotes only some values (see test_falconctl_utils.py).
        if opt in ("cid", "aid", "tags"):
            value = '"%s"' % value
        return (0, "%s=%s.\n" % (opt, value), "")

    def set_or_delete(self, cmd):
        self.commands.append(cmd)
        if self.stderr:
            return (0, "", self.stderr)
        for arg in cmd[3:]:
            if cmd[1] == "-d":
                self.options.pop(arg[2:], None)
                continue
            opt, value = arg[2:].split("=", 1)
            # The sensor stores the CID without its checksum, in lowercase,
            # and prints apd in uppercase.
            if opt == "cid":
                value = value.lower()[:32]
            elif opt == "apd":
                value = value.upper()
            self.options[opt] = value
        return (0, "", "")

    def run(self, module, args, check_mode=False):
        """Run module.main() and return its JSON result."""
        self.commands = []
        return self._run_module(module, args, check_mode)


@pytest.fixture
def fake_sensor(monkeypatch, run_module):
    """Patch falconctl execution and return the FakeSensor."""
    sensor = FakeSensor(run_module)

    monkeypatch.setattr(
        basic.AnsibleModule, "get_bin_path", lambda self, *a, **kw: FALCONCTL
    )
    monkeypatch.setattr(
        basic.AnsibleModule,
        "run_command",
        lambda self, cmd, **kw: sensor.run_command(cmd),
    )
    return sensor
