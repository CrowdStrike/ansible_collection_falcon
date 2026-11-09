# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import sensor_update_policy

NAME = "ansible-unit-fixture-a"
POLICY_ID = "00000000000000000000000000000004"
BUILD = "19403|n-1|tagged|5"
SCHEDULER = {
    "enabled": True,
    "timezone": "Etc/UTC",
    "schedules": [{"start": "08:00", "end": "14:00", "days": [1, 2, 3, 4, 5]}],
}
# The arguments that match the recorded policy.
MATCHING = {
    "name": NAME,
    "platform_name": "Linux",
    "description": "Fixture policy",
    "build": BUILD,
    "uninstall_protection": "DISABLED",
    "scheduler": SCHEDULER,
}


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches sensor_update_policy with recorded responses."""

    def make(**responses):
        return falcon_api(
            sensor_update_policy,
            {
                method: [fixture("sensor_update_policy/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def methods(service):
    return [method for method, _kwargs in service.calls]


def test_present_creates_missing_policy(api, run_module):
    service = api(
        query_combined_policies_v2=["query_by_name_missing"],
        create_policies_v2=["create"],
        get_policies_v2=["get_one"],
    )

    result = run_module(sensor_update_policy, MATCHING)

    assert result["changed"] is True
    assert result["sensor_update_policy"]["id"] == POLICY_ID
    assert service.called("query_combined_policies_v2") == [
        {"filter": "name.raw:'%s'+platform_name:'Linux'" % NAME, "limit": 1}
    ]
    assert service.called("create_policies_v2") == [
        {
            "body": {
                "resources": [
                    {
                        "name": NAME,
                        "platform_name": "Linux",
                        "description": "Fixture policy",
                        "settings": {
                            "build": BUILD,
                            "uninstall_protection": "DISABLED",
                            "scheduler": SCHEDULER,
                        },
                    }
                ]
            }
        }
    ]


def test_present_matching_policy_is_not_changed(api, run_module):
    # The API stores the scheduler as sent, so it compares equal.
    service = api(
        query_combined_policies_v2=["query_by_name"],
        get_policies_v2=["get_one"],
    )

    result = run_module(sensor_update_policy, MATCHING)

    assert result["changed"] is False
    assert methods(service) == ["query_combined_policies_v2", "get_policies_v2"]


def test_present_updates_changed_description(api, run_module):
    service = api(
        query_combined_policies_v2=["query_by_name"],
        update_policies_v2=["update_description"],
        get_policies_v2=["get_after_update"],
    )

    result = run_module(
        sensor_update_policy,
        {"name": NAME, "platform_name": "Linux", "description": "Fixture policy, updated"},
    )

    assert result["changed"] is True
    assert result["sensor_update_policy"]["description"] == "Fixture policy, updated"
    assert service.called("update_policies_v2") == [
        {"body": {"resources": [{"id": POLICY_ID, "name": NAME, "description": "Fixture policy, updated"}]}}
    ]


def test_present_enables_disabled_policy(api, run_module):
    service = api(
        query_combined_policies_v2=["query_by_name"],
        perform_policies_action=["enable"],
        get_policies_v2=["get_after_enable"],
    )

    result = run_module(sensor_update_policy, {"name": NAME, "platform_name": "Linux", "enabled": True})

    assert result["changed"] is True
    assert result["sensor_update_policy"]["enabled"] is True
    assert service.called("perform_policies_action") == [{"action_name": "enable", "ids": [POLICY_ID]}]


def test_present_enabled_policy_by_id_is_not_changed(api, run_module):
    service = api(get_policies_v2=["get_after_enable"])

    result = run_module(sensor_update_policy, {"sensor_update_policy": POLICY_ID, "enabled": True})

    assert result["changed"] is False
    assert methods(service) == ["get_policies_v2", "get_policies_v2"]


def test_check_mode_predicts_create_without_writing(api, run_module):
    service = api(query_combined_policies_v2=["query_by_name_missing"])

    result = run_module(sensor_update_policy, MATCHING, check_mode=True)

    assert result["changed"] is True
    assert result["sensor_update_policy"]["name"] == NAME
    assert methods(service) == ["query_combined_policies_v2"]


def test_check_mode_predicts_update_without_writing(api, run_module):
    service = api(query_combined_policies_v2=["query_by_name"])

    result = run_module(
        sensor_update_policy,
        {"name": NAME, "platform_name": "Linux", "description": "changed"},
        check_mode=True,
    )

    assert result["changed"] is True
    assert methods(service) == ["query_combined_policies_v2"]


def test_absent_disables_enabled_policy_before_delete(api, run_module):
    service = api(
        get_policies_v2=["get_after_enable"],
        perform_policies_action=["disable"],
        delete_policies=["delete"],
    )

    result = run_module(sensor_update_policy, {"sensor_update_policy": POLICY_ID, "state": "absent"})

    assert result["changed"] is True
    assert methods(service) == ["get_policies_v2", "perform_policies_action", "delete_policies"]
    assert service.called("perform_policies_action") == [{"action_name": "disable", "ids": [POLICY_ID]}]
    assert service.called("delete_policies") == [{"ids": [POLICY_ID]}]


def test_absent_missing_policy_is_not_changed(api, run_module):
    service = api(query_combined_policies_v2=["query_by_name_missing"])

    result = run_module(sensor_update_policy, {"name": NAME, "platform_name": "Linux", "state": "absent"})

    assert result["changed"] is False
    assert methods(service) == ["query_combined_policies_v2"]


def test_absent_by_id_that_does_not_exist_fails(api, run_module):
    api(get_policies_v2=["get_missing"])

    result = run_module(sensor_update_policy, {"sensor_update_policy": POLICY_ID, "state": "absent"})

    assert result["failed"] is True
    assert result["msg"] == "Sensor update policy with ID '%s' not found" % POLICY_ID


def test_duplicate_name_fails_with_api_message(api, run_module):
    api(
        query_combined_policies_v2=["query_by_name_missing"],
        create_policies_v2=["create_duplicate"],
    )

    result = run_module(sensor_update_policy, {"name": NAME, "platform_name": "Linux"})

    assert result["failed"] is True
    assert result["msg"] == "Duplicate policy name ansible-unit-fixture-a for Linux platform."


def test_add_host_group_sends_group_parameters(api, run_module):
    group_id = "00000000000000000000000000000009"
    service = api(
        query_combined_policies_v2=["query_by_name"],
        perform_policies_action=["add_host_group_missing"],
        get_policies_v2=["get_one"],
    )

    result = run_module(
        sensor_update_policy,
        {"name": NAME, "platform_name": "Linux", "host_groups": [group_id], "host_group_action": "add"},
    )

    assert service.called("perform_policies_action") == [
        {
            "action_name": "add-host-group",
            "ids": [POLICY_ID],
            "action_parameters": [{"name": "group_id", "value": group_id}],
        }
    ]
    # current behavior: the API returns 200 with no resources for a group
    # that does not exist, and the module reports a change for every action.
    assert result["changed"] is True
    assert result["host_group_results"] == {"successful_groups": [], "failed_groups": []}


@pytest.mark.parametrize(
    "args, message",
    [
        ({"name": NAME}, "'platform_name' is required when creating"),
        ({"name": NAME, "state": "absent"}, "'platform_name' is required when using 'name'"),
        ({"state": "absent"}, "Either 'sensor_update_policy'"),
        ({"sensor_update_policy": POLICY_ID, "host_groups": ["x"]}, "'host_group_action' is required"),
        ({"sensor_update_policy": POLICY_ID, "host_group_action": "add"}, "'host_groups' is required"),
    ],
    ids=["create-no-platform", "absent-no-platform", "absent-no-id", "groups-no-action", "action-no-groups"],
)
def test_invalid_arguments_fail_before_api_calls(api, run_module, args, message):
    service = api()

    result = run_module(sensor_update_policy, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
