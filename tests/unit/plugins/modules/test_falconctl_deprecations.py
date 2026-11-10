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

from ansible_collections.crowdstrike.falcon.plugins.modules import (
    falconctl,
    falconctl_info,
)

FALCONCTL = "/opt/CrowdStrike/falconctl"


@contextlib.contextmanager
def module_args(args):
    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:  # ansible-core < 2.19
        serialized = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
        with patch.object(basic, "_ANSIBLE_ARGS", serialized):
            yield
    else:
        with patch_module_args(args):
            yield


@pytest.fixture
def run_module(monkeypatch, capsys):
    """Run a module's main() against a fake falconctl and return its result."""
    # Deprecations are kept in module-level state (a list before ansible-core
    # 2.19, a dict after), so start each test with an empty one.
    monkeypatch.setattr(
        warnings, "_global_deprecations", type(warnings._global_deprecations)()
    )

    commands = []

    def fake_run_command(self, cmd, **kwargs):
        # Linux sensors 7.21+ exit 1 for 'falconctl -g --message-log'.
        if cmd[1] == "-g":
            return (1, "", "")
        commands.append(cmd)
        return (0, "", "")

    monkeypatch.setattr(
        basic.AnsibleModule, "get_bin_path", lambda self, *a, **kw: FALCONCTL
    )
    monkeypatch.setattr(basic.AnsibleModule, "run_command", fake_run_command)

    def run(module, args):
        with module_args(args), pytest.raises(SystemExit):
            module.main()
        result = json.loads(capsys.readouterr().out)
        result["commands"] = commands
        return result

    return run


def message_log_deprecations(result):
    # ansible-core 2.19+ moves the message into an "event" dict.
    return [
        d
        for d in result.get("deprecations", [])
        if "message_log" in d.get("msg", d.get("event", {}).get("msg", ""))
    ]


def test_falconctl_message_log_is_deprecated(run_module):
    result = run_module(falconctl, {"state": "present", "message_log": "true"})

    deprecations = message_log_deprecations(result)
    assert len(deprecations) == 1
    assert deprecations[0]["version"] == "5.0.0"


def test_falconctl_message_log_is_still_sent_to_falconctl(run_module):
    # Older sensors may still support --message-log, so keep passing it on.
    result = run_module(falconctl, {"state": "present", "message_log": "true"})

    assert result["commands"] == [[FALCONCTL, "-s", "-f", "--message-log=true"]]


def test_falconctl_without_message_log_is_not_deprecated(run_module):
    result = run_module(falconctl, {"state": "present", "trace": "warn"})

    assert message_log_deprecations(result) == []


def test_falconctl_info_message_log_is_deprecated(run_module):
    result = run_module(falconctl_info, {"name": ["message_log"]})

    deprecations = message_log_deprecations(result)
    assert len(deprecations) == 1
    assert deprecations[0]["version"] == "5.0.0"
    # The option is still a valid choice, so existing tasks keep working.
    assert result["falconctl_info"] == {"message_log": None}


def test_falconctl_info_all_options_is_not_deprecated(run_module):
    # Without name, every option is queried. Do not warn users who did not
    # ask for message_log.
    result = run_module(falconctl_info, {})

    assert message_log_deprecations(result) == []
    assert result["falconctl_info"]["message_log"] is None
