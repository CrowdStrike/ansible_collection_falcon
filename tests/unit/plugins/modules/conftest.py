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

from ansible_collections.crowdstrike.falcon.plugins.module_utils import (
    falconctl_utils,
)

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


class FakeSensor(object):
    """A stateful stand-in for falconctl.

    'falconctl -s/-d' change the stored options and 'falconctl -g' prints
    them in the sensor's '<option>=<value>.' format, so a module can be run
    twice to check idempotence.
    """

    def __init__(self, capsys):
        self.options = {}
        self.commands = []
        # stderr for the next 'falconctl -s/-d' calls, e.g. an error message
        self.stderr = ""
        self._capsys = capsys

    def get(self, cmd, **kwargs):
        opt = cmd[2][2:]
        value = self.options.get(opt)
        if value is None:
            return "%s is not set.\n" % opt
        # The sensor quotes only some values (see test_falconctl_utils.py).
        if opt in ("cid", "aid", "tags"):
            value = '"%s"' % value
        return "%s=%s.\n" % (opt, value)

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
        if check_mode:
            args = dict(args, _ansible_check_mode=True)
        with _module_args(args), pytest.raises(SystemExit):
            module.main()
        return json.loads(self._capsys.readouterr().out)


@pytest.fixture
def fake_sensor(monkeypatch, capsys):
    """Patch falconctl execution and return the FakeSensor."""
    # Deprecations and warnings are kept in module-level state, so start
    # each test with empty ones.
    monkeypatch.setattr(
        warnings, "_global_deprecations", type(warnings._global_deprecations)()
    )
    monkeypatch.setattr(
        warnings, "_global_warnings", type(warnings._global_warnings)()
    )

    sensor = FakeSensor(capsys)

    monkeypatch.setattr(falconctl_utils, "check_output", sensor.get)
    monkeypatch.setattr(falconctl_utils, "_FALCONCTL", FALCONCTL, raising=False)
    monkeypatch.setattr(falconctl_utils, "FALCONCTL_NOT_FOUND", False)
    monkeypatch.setattr(
        basic.AnsibleModule, "get_bin_path", lambda self, *a, **kw: FALCONCTL
    )
    monkeypatch.setattr(
        basic.AnsibleModule,
        "run_command",
        lambda self, cmd, **kw: sensor.set_or_delete(cmd),
    )
    return sensor
