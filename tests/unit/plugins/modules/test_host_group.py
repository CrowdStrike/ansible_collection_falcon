# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import host_group

NAME = "ansible-unit-fixture-a"
MIXED_NAME = "Ansible-Unit-Fixture-A"
GROUP_ID = "00000000000000000000000000000001"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches host_group with recorded responses."""

    def make(**responses):
        return falcon_api(
            host_group,
            {method: [fixture("host_group/" + case) for case in cases] for method, cases in responses.items()},
        )

    return make


def test_present_creates_missing_group(api, run_module):
    service = api(
        query_combined_host_groups=["query_by_name_missing"],
        create_host_groups=["create_static"],
    )

    result = run_module(host_group, {"name": NAME, "description": "Fixture group"})

    assert result["changed"] is True
    assert result["host_group"]["id"] == GROUP_ID
    assert service.called("query_combined_host_groups") == [
        {"filter": "name:'%s'" % NAME, "limit": host_group.NAME_SEARCH_LIMIT}
    ]
    assert service.called("create_host_groups") == [
        {"name": NAME, "group_type": "static", "description": "Fixture group"}
    ]


def mixed_case_query(fixture):
    """Return query_by_name with the group name in mixed case.

    The API name filter only matches the lowercase form of a name, and the
    response has the name as it was created.
    """
    response = copy.deepcopy(fixture("host_group/query_by_name"))
    response["body"]["resources"][0]["name"] = MIXED_NAME
    return response


@pytest.mark.parametrize("state", ["present", "absent"])
def test_mixed_case_name_is_searched_in_lowercase(falcon_api, fixture, run_module, state):
    service = falcon_api(
        host_group,
        {
            "query_combined_host_groups": [mixed_case_query(fixture)],
            "delete_host_groups": [fixture("host_group/delete")],
        },
    )

    result = run_module(host_group, {"name": MIXED_NAME, "description": "Fixture group", "state": state})

    assert service.called("query_combined_host_groups") == [
        {"filter": "name:'%s'" % NAME, "limit": host_group.NAME_SEARCH_LIMIT}
    ]
    if state == "present":
        # No create response is given, so a second create fails the test.
        assert result["changed"] is False
        assert result["host_group"]["id"] == GROUP_ID
    else:
        assert result["changed"] is True
        assert service.called("delete_host_groups") == [{"ids": [GROUP_ID]}]


def test_name_with_other_case_updates_the_name(falcon_api, fixture, run_module):
    service = falcon_api(
        host_group,
        {
            "query_combined_host_groups": [mixed_case_query(fixture)],
            "update_host_groups": [fixture("host_group/update_description")],
            "get_host_groups": [fixture("host_group/get_after_update")],
        },
    )

    result = run_module(host_group, {"name": NAME})

    assert result["changed"] is True
    assert service.called("update_host_groups") == [{"id": GROUP_ID, "name": NAME}]


def test_name_search_picks_the_group_with_that_name(api, run_module):
    # query_page1 has the groups '...-a' and '...-b'.
    service = api(query_combined_host_groups=["query_page1"], delete_host_groups=["delete"])

    result = run_module(host_group, {"name": "ansible-unit-fixture-b", "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_host_groups") == [{"ids": ["00000000000000000000000000000004"]}]


def test_name_search_ignores_groups_with_other_names(api, run_module):
    service = api(query_combined_host_groups=["query_page1"])

    result = run_module(host_group, {"name": "ansible-unit-fixture", "state": "absent"})

    assert result["changed"] is False
    assert "failed" not in result
    assert [method for method, _kwargs in service.calls] == ["query_combined_host_groups"]


def test_name_search_escapes_quotes(api, run_module):
    service = api(query_combined_host_groups=["query_by_name_missing"])

    run_module(host_group, {"name": "O'Brien \\ Hosts", "state": "absent"})

    assert service.called("query_combined_host_groups")[0]["filter"] == "name:'o\\'brien \\\\ hosts'"


def test_present_creates_dynamic_group_with_rule(api, run_module):
    service = api(
        query_combined_host_groups=["query_by_name_missing"],
        create_host_groups=["create_dynamic"],
    )
    rule = "tags:'SensorGroupingTags/tag1'"

    result = run_module(
        host_group,
        {"name": "ansible-unit-fixture-dynamic", "group_type": "dynamic", "assignment_rule": rule},
    )

    assert result["changed"] is True
    assert result["host_group"]["assignment_rule"] == rule
    assert service.called("create_host_groups")[0]["assignment_rule"] == rule


def test_present_matching_group_is_not_changed(api, run_module):
    # No create or update response is given, so any write call fails the test.
    service = api(query_combined_host_groups=["query_by_name"])

    result = run_module(host_group, {"name": NAME, "description": "Fixture group"})

    assert result["changed"] is False
    assert result["host_group"]["description"] == "Fixture group"
    assert [method for method, _kwargs in service.calls] == ["query_combined_host_groups"]


def test_present_updates_changed_description(api, run_module):
    service = api(
        query_combined_host_groups=["query_by_name"],
        update_host_groups=["update_description"],
        get_host_groups=["get_after_update"],
    )

    result = run_module(host_group, {"name": NAME, "description": "Fixture group, updated"})

    assert result["changed"] is True
    assert result["host_group"]["description"] == "Fixture group, updated"
    assert service.called("update_host_groups") == [
        {"id": GROUP_ID, "name": NAME, "description": "Fixture group, updated"}
    ]


def test_present_by_id_that_does_not_exist_fails(api, run_module):
    api(get_host_groups=["get_missing"])

    result = run_module(host_group, {"host_group": GROUP_ID})

    assert result["failed"] is True
    assert result["msg"] == "Host group with ID '%s' not found" % GROUP_ID


def test_present_duplicate_name_fails_with_api_message(api, run_module):
    # The name search found nothing, but the API reports a duplicate.
    api(
        query_combined_host_groups=["query_by_name_missing"],
        create_host_groups=["create_duplicate"],
    )

    result = run_module(host_group, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"] == "Duplicate group name ansible-unit-fixture-a."


def test_add_hosts_uses_device_id_filter(api, run_module):
    service = api(
        query_combined_host_groups=["query_by_name"],
        perform_group_action=["add_hosts_missing_host"],
    )
    host_id = "00000000000000000000000000000009"

    result = run_module(
        host_group, {"name": NAME, "hosts": [host_id], "host_action": "add"}
    )

    assert service.called("perform_group_action") == [
        {"action_name": "add-hosts", "ids": [GROUP_ID], "filter": 'device_id:["%s"]' % host_id}
    ]
    # current behavior: the API returns the group, not the hosts, so the
    # group ID is reported as a successful host and the task is changed even
    # when the host does not exist.
    assert result["changed"] is True
    assert result["action_results"]["successful_hosts"] == [GROUP_ID]


def test_absent_deletes_existing_group(api, run_module):
    service = api(
        query_combined_host_groups=["query_by_name"],
        delete_host_groups=["delete"],
    )

    result = run_module(host_group, {"name": NAME, "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_host_groups") == [{"ids": [GROUP_ID]}]


def test_absent_missing_group_is_not_changed(api, run_module):
    api(query_combined_host_groups=["query_by_name_missing"])

    result = run_module(host_group, {"name": NAME, "state": "absent"})

    assert result["changed"] is False


def test_check_mode_makes_no_api_calls(api, run_module):
    service = api(query_combined_host_groups=["query_by_name_missing"])

    result = run_module(host_group, {"name": NAME}, check_mode=True)

    # current behavior: check mode exits before it reads the group, so it
    # never predicts a change.
    assert result["changed"] is False
    assert service.calls == []


@pytest.mark.parametrize(
    "args, message",
    [
        ({}, "Either 'name' (for new groups) or 'host_group'"),
        ({"state": "absent"}, "Either 'host_group' (ID) or 'name' is required"),
        ({"name": NAME, "group_type": "dynamic"}, "'assignment_rule' is required"),
        ({"name": NAME, "hosts": ["x"]}, "'host_action' is required"),
        ({"name": NAME, "host_action": "add"}, "'hosts' is required"),
    ],
    ids=["no-name", "absent-no-name", "dynamic-no-rule", "hosts-no-action", "action-no-hosts"],
)
def test_invalid_arguments_fail_before_api_calls(api, run_module, args, message):
    service = api()

    result = run_module(host_group, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
