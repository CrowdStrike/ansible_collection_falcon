# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import (
    falconctl,
    falconctl_info,
)

FALCONCTL = "/opt/CrowdStrike/falconctl"
CID = "0123456789ABCDEF0123456789ABCDEF-12"
SENSOR_CID = "0123456789abcdef0123456789abcdef"


def warning_text(result):
    # ansible-core 2.19+ returns warnings as dicts, 2.20 nests the text.
    return " ".join(
        w if isinstance(w, str) else w.get("msg", w.get("event", {}).get("msg", ""))
        for w in result.get("warnings", [])
    )


def test_present_sets_options_and_reports_diff(fake_sensor):
    result = fake_sensor.run(falconctl, {"state": "present", "cid": CID, "trace": "debug"})

    assert result["changed"] is True
    assert fake_sensor.commands == [
        [FALCONCTL, "-s", "-f", "--cid=%s" % CID, "--trace=debug"]
    ]
    assert result["diff"]["before"] == {"cid": None, "trace": None}
    assert result["diff"]["after"] == {"cid": SENSOR_CID, "trace": "debug"}


def test_present_second_run_is_not_changed(fake_sensor):
    args = {"state": "present", "cid": CID, "trace": "debug"}
    fake_sensor.run(falconctl, args)

    result = fake_sensor.run(falconctl, args)

    assert result["changed"] is False
    assert "diff" not in result


def test_absent_deletes_options(fake_sensor):
    fake_sensor.options.update(aph="proxy.example.com", app="8080")

    result = fake_sensor.run(falconctl, {"state": "absent", "aph": "", "app": ""})

    assert result["changed"] is True
    assert fake_sensor.commands == [[FALCONCTL, "-d", "-f", "--aph", "--app"]]
    assert fake_sensor.options == {}


def test_absent_second_run_is_not_changed(fake_sensor):
    args = {"state": "absent", "aph": "", "app": ""}
    fake_sensor.options.update(aph="proxy.example.com", app="8080")
    fake_sensor.run(falconctl, args)

    assert fake_sensor.run(falconctl, args)["changed"] is False


def test_check_mode_runs_nothing_and_predicts_sensor_values(fake_sensor):
    result = fake_sensor.run(
        falconctl, {"state": "present", "cid": CID, "apd": "true"}, check_mode=True
    )

    assert fake_sensor.commands == []
    assert result["changed"] is True
    # The predicted values must match what the sensor would print, so a
    # check-mode run after a real run is not reported as changed.
    assert result["diff"]["after"] == {"cid": SENSOR_CID, "apd": "TRUE"}


def test_check_mode_after_real_run_is_not_changed(fake_sensor):
    args = {"state": "present", "cid": CID, "apd": "true"}
    fake_sensor.run(falconctl, args)

    assert fake_sensor.run(falconctl, args, check_mode=True)["changed"] is False


def test_check_mode_absent_predicts_unset_values(fake_sensor):
    fake_sensor.options.update(aph="proxy.example.com")

    result = fake_sensor.run(falconctl, {"state": "absent", "aph": ""}, check_mode=True)

    assert fake_sensor.commands == []
    # An empty value is not in the 'before' read, so the diff has every option.
    assert result["diff"]["before"]["aph"] == "proxy.example.com"
    assert result["diff"]["after"]["aph"] is None


def test_option_names_use_dashes_on_command_line(fake_sensor):
    fake_sensor.run(
        falconctl,
        {"state": "present", "cid": CID, "provisioning_token": "1234abcd"},
    )

    assert fake_sensor.commands[0][-1] == "--provisioning-token=1234abcd"


def test_feature_list_is_joined(fake_sensor):
    fake_sensor.run(
        falconctl, {"state": "present", "feature": ["enableLog", "disableLogBuffer"]}
    )

    assert fake_sensor.commands == [
        [FALCONCTL, "-s", "-f", "--feature=enableLog,disableLogBuffer"]
    ]


def test_unrecognized_option_warns_instead_of_failing(fake_sensor):
    fake_sensor.stderr = "falconctl: unrecognized option '--backend=bpf'\n"

    result = fake_sensor.run(falconctl, {"state": "present", "backend": "bpf"})

    assert not result.get("failed")
    assert "--backend was skipped" in warning_text(result)


def test_error_from_falconctl_fails(fake_sensor):
    fake_sensor.stderr = "ERROR: simulated failure\nmore detail\n"

    result = fake_sensor.run(falconctl, {"state": "present", "trace": "debug"})

    assert result["failed"] is True
    assert result["msg"] == "ERROR: ERROR: simulated failure"


@pytest.mark.parametrize(
    "args, message",
    [
        ({"state": "absent", "feature": ["enableLog"]}, "Cannot use 'feature' with state 'absent'"),
        ({"state": "present", "aid": True}, "Cannot use 'aid' with state 'present'"),
        ({"state": "present", "provisioning_token": "1234abcd"}, "provisioning_token requires cid"),
        ({"state": "present", "cid": CID, "provisioning_token": "xyz"}, "Invalid provisioning token"),
        ({"state": "present", "cid": "0123456789abcdef"}, "Invalid CrowdStrike CID"),
        ({"state": "present", "billing": "monthly"}, "Value of billing must be one of"),
        ({"state": "present", "apd": "yes"}, "Value of apd must be one of"),
        ({"state": "present", "backend": "ebpf"}, "Value of backend must be one of"),
    ],
    ids=[
        "absent-only-option",
        "present-aid",
        "token-without-cid",
        "bad-token",
        "bad-cid",
        "bad-billing",
        "bad-apd",
        "bad-backend",
    ],
)
def test_invalid_arguments_fail_before_falconctl_runs(fake_sensor, args, message):
    result = fake_sensor.run(falconctl, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert fake_sensor.commands == []


@pytest.mark.parametrize("value", ["TRUE", "False", ""], ids=["upper", "mixed", "empty"])
def test_apd_is_case_insensitive(fake_sensor, value):
    result = fake_sensor.run(falconctl, {"state": "present", "apd": value})

    assert not result.get("failed")


def test_falconctl_info_returns_requested_options(fake_sensor):
    fake_sensor.options.update(cid=SENSOR_CID, aph="proxy.example.com", app="8080")

    result = fake_sensor.run(falconctl_info, {"name": ["cid", "aph", "app", "trace"]})

    assert result["changed"] is False
    assert result["falconctl_info"] == {
        "cid": SENSOR_CID,
        "aph": "proxy.example.com",
        "app": "8080",
        "trace": None,
    }


def test_falconctl_info_reads_back_what_falconctl_set(fake_sensor):
    fake_sensor.run(
        falconctl, {"state": "present", "cid": CID, "aph": "proxy.example.com", "app": "8080"}
    )

    result = fake_sensor.run(falconctl_info, {"name": ["cid", "aph", "app"]})

    assert result["falconctl_info"] == {
        "cid": SENSOR_CID,
        "aph": "proxy.example.com",
        "app": "8080",
    }
