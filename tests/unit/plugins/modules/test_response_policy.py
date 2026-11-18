# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import response_policy

# The policies that record_response_policy() made for the response_policy cases.
NAME = "ansible-unit-fixture-crud"
# The fake IDs that the Sanitizer gave them: the Linux and the Windows policy.
POLICY_ID = "00000000000000000000000000000007"
WINDOWS_ID = "00000000000000000000000000000008"
# The ID that does not exist ("f" * 32 in the recorder), after sanitizing.
MISSING_ID = "00000000000000000000000000000005"
# The two static groups that the recorder made, after sanitizing.
GROUP_1 = "00000000000000000000000000000009"
GROUP_2 = "00000000000000000000000000000010"
UPDATED = "Updated fixture policy"
HEX_ID = "abcdef1234567890abcdef1234567890"

# The settings of the recorded Linux policy: created with real_time_functionality on.
LINUX_SETTINGS = {
    "real_time_functionality": True,
    "custom_scripts": False,
    "get_command": False,
    "put_command": False,
    "exec_command": False,
}
WINDOWS_OFF = {
    "real_time_functionality": False,
    "custom_scripts": False,
    "falcon_scripts": False,
    "get_command": False,
    "put_command": False,
    "exec_command": False,
    "put_and_run_command": False,
    "memdump_command": False,
    "xmemdump_command": False,
}


@pytest.fixture
def api(monkeypatch, falcon_api, fixture):
    """Return a function that gives each service class its own FakeService.

    The module calls authenticate(module, ResponsePolicies) and, to check the
    groups to add, authenticate(module, HostGroup). The patched authenticate
    picks the fake by the class name and keeps the names in order.
    """

    def load(cases):
        return [case if isinstance(case, (dict, Exception)) else fixture("response_policy/" + case) for case in cases]

    def make(host_group=None, **responses):
        policy = falcon_api(response_policy, {method: load(cases) for method, cases in responses.items()})
        # attr: a name that the module does not use, so that this call does
        # not replace the patched authenticate of the policy service.
        groups = falcon_api(
            response_policy, {"get_host_groups": load(host_group or [])}, attr="_unit_test_host_group"
        )
        built = []

        def authenticate(module, service_class):
            built.append(service_class.__name__)
            return groups if service_class.__name__ == "HostGroup" else policy

        monkeypatch.setattr(response_policy, "authenticate", authenticate)
        return policy, groups, built

    return make


def by_name(platform="Linux", **kwargs):
    return dict({"name": NAME, "platform_name": platform}, **kwargs)


def search_call(name=NAME, platform="Linux"):
    return ("query_combined_policies", {"filter": "name:~'%s'+platform_name:'%s'" % (name, platform), "limit": 5000})


def get_call(policy_id=POLICY_ID):
    return ("get_policies", {"ids": [policy_id]})


def action_call(action, policy_id=POLICY_ID):
    return ("perform_policies_action", {"action_name": action, "ids": [policy_id]})


def setting(setting_id, enabled=True):
    return {"id": setting_id, "value": {"enabled": enabled}}


def update_call(**resource):
    return ("update_policies", {"body": {"resources": [dict({"id": POLICY_ID}, **resource)]}})


def create_call(platform="Linux", **extra):
    return ("create_policies", {"body": {"resources": [dict({"name": NAME, "platform_name": platform}, **extra)]}})


def hg_call(*ids):
    return ("get_host_groups", {"ids": list(ids)})


def group_action_call(action, *ids):
    return (
        "perform_policies_action",
        {
            "action_name": "%s-host-group" % action,
            "ids": [POLICY_ID],
            "action_parameters": [{"name": "group_id", "value": group_id} for group_id in ids],
        },
    )


def without_errors(response, status_code):
    """Return a copy of a recorded response with another status and no errors.

    The tenant does not return a 5xx or an error status with an empty errors
    list on demand. The copy tests the fallback message of check_status.
    """
    response = copy.deepcopy(response)
    response["status_code"] = status_code
    response["body"]["errors"] = []
    return response


# Argument validation


@pytest.mark.parametrize("key", ["name", "policy_id"])
def test_empty_name_or_id_fails_before_any_call(api, run_module, key):
    policy, groups, built = api()
    args = {"policy_id": ""} if key == "policy_id" else by_name(name="")

    result = run_module(response_policy, args)

    assert result["failed"] is True
    assert result["msg"] == "Parameter '%s' must not be empty" % key
    assert built == []
    assert policy.calls == []


def test_name_without_platform_fails(api, run_module):
    policy, groups, built = api()

    result = run_module(response_policy, {"name": NAME})

    assert result["failed"] is True
    assert "platform_name" in result["msg"]
    assert built == []


def test_empty_host_group_id_fails_before_any_call(api, run_module):
    policy, groups, built = api()

    result = run_module(response_policy, by_name(host_groups=[GROUP_1, ""]))

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'host_groups' must not contain an empty ID"
    assert built == []
    assert policy.calls == []
    assert groups.calls == []


@pytest.mark.parametrize("option", ["falcon_scripts", "memdump_command", "xmemdump_command", "put_and_run_command"])
def test_setting_not_on_platform_by_name_fails_before_any_call(api, run_module, option):
    policy, groups, built = api()

    result = run_module(response_policy, by_name(**{option: True}))

    assert result["failed"] is True
    assert result["msg"] == "Setting '%s' is not available for Linux response policies" % option
    assert built == []
    assert policy.calls == []


def test_setting_not_on_platform_by_id_fails_after_read_before_write(api, run_module):
    policy, groups, built = api(get_policies=["get_disabled"])

    result = run_module(response_policy, {"policy_id": POLICY_ID, "falcon_scripts": False})

    assert result["failed"] is True
    assert result["msg"] == "Setting 'falcon_scripts' is not available for Linux response policies"
    assert policy.calls == [get_call()]


def test_setting_not_on_platform_is_ignored_for_absent(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(response_policy, by_name(state="absent", falcon_scripts=True))

    assert result["changed"] is False
    assert policy.calls == [search_call()]


# Create


def test_present_creates_linux_policy_with_settings(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create"],
        get_policies=["get_disabled"],
    )

    result = run_module(
        response_policy,
        by_name(description="Fixture policy", real_time_functionality=True, _ansible_diff=True),
    )

    assert result["changed"] is True
    assert result["response_policy"]["id"] == POLICY_ID
    assert result["diff"] == {
        "before": {},
        "after": {
            "name": NAME,
            "platform_name": "Linux",
            "description": "Fixture policy",
            "enabled": False,
            "settings": LINUX_SETTINGS,
        },
    }
    assert built == ["ResponsePolicies"]
    assert policy.calls == [
        search_call(),
        create_call(description="Fixture policy", settings=[setting("RealTimeFunctionality")]),
        get_call(),
    ]


def test_present_creates_windows_policy_with_falcon_scripts(api, run_module):
    # The recorded empty search result; the filter in the kwargs is the Windows one.
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create_windows"],
        get_policies=["get_windows"],
    )

    result = run_module(
        response_policy,
        by_name(platform="Windows", description="Fixture policy", falcon_scripts=True, _ansible_diff=True),
    )

    assert result["changed"] is True
    assert result["response_policy"]["id"] == WINDOWS_ID
    assert result["diff"]["after"]["settings"] == dict(WINDOWS_OFF, falcon_scripts=True)
    assert policy.calls == [
        search_call(platform="Windows"),
        create_call(platform="Windows", description="Fixture policy", settings=[setting("FalconScripts")]),
        get_call(WINDOWS_ID),
    ]


def test_present_creates_policy_without_settings_sends_none(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create"],
        get_policies=["get_disabled"],
    )

    result = run_module(response_policy, by_name())

    assert result["changed"] is True
    assert "diff" not in result
    assert policy.calls == [search_call(), create_call(), get_call()]


def test_present_creates_and_enables_policy(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create"],
        perform_policies_action=["enable"],
        get_policies=["get_enabled"],
    )

    result = run_module(response_policy, by_name(enabled=True))

    assert result["changed"] is True
    assert result["response_policy"]["enabled"] is True
    assert policy.calls == [search_call(), create_call(), action_call("enable"), get_call()]


def test_check_mode_predicts_create_without_writing(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(
        response_policy, by_name(enabled=True, custom_scripts=True, _ansible_diff=True), check_mode=True
    )

    assert result["changed"] is True
    assert result["diff"]["after"]["enabled"] is True
    assert result["diff"]["after"]["settings"] == dict(LINUX_SETTINGS, real_time_functionality=False, custom_scripts=True)
    assert result["response_policy"]["name"] == NAME
    assert result["response_policy"]["enabled"] is True
    assert policy.calls == [search_call()]


def test_create_error_fails_with_api_message(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create_duplicate"],
    )

    result = run_module(response_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "Duplicate policy name ansible-unit-fixture-crud for Linux platform."
    assert policy.calls == [search_call(), create_call()]


# Update and idempotence


def test_present_with_same_values_makes_no_write(api, run_module):
    """configured is false in the fixture while enabled is true, so this also shows that configured is ignored."""
    policy, groups, built = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(
        response_policy,
        by_name(description="Fixture policy", enabled=False, real_time_functionality=True, custom_scripts=False),
    )

    assert result["changed"] is False
    assert result["response_policy"]["id"] == POLICY_ID
    assert policy.calls == [search_call()]


def test_name_in_other_case_finds_policy(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(response_policy, by_name(name=NAME.upper()))

    assert result["changed"] is False
    assert result["response_policy"]["name"] == NAME
    assert policy.calls == [search_call(name=NAME.upper())]


def test_name_with_quote_is_escaped(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name_missing"])

    run_module(response_policy, by_name(name="it's\\x"), check_mode=True)

    assert policy.calls == [search_call(name="it\\'s\\\\x")]


def test_present_updates_description_only(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_description"],
        get_policies=["get_disabled"],
    )

    result = run_module(response_policy, by_name(description=UPDATED, _ansible_diff=True))

    assert result["changed"] is True
    assert result["diff"]["before"]["description"] == "Fixture policy"
    assert result["diff"]["after"]["description"] == UPDATED
    assert result["diff"]["after"]["settings"] == LINUX_SETTINGS
    assert policy.calls == [search_call(), update_call(description=UPDATED), get_call()]


def test_present_clears_description(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_description"],
        get_policies=["get_disabled"],
    )

    result = run_module(response_policy, by_name(description=""))

    assert result["changed"] is True
    assert policy.calls == [search_call(), update_call(description=""), get_call()]


def test_present_updates_settings_only(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_settings"],
        get_policies=["get_updated"],
    )

    result = run_module(
        response_policy,
        by_name(real_time_functionality=True, custom_scripts=True, _ansible_diff=True),
    )

    assert result["changed"] is True
    assert result["diff"]["before"]["settings"] == LINUX_SETTINGS
    assert result["diff"]["after"]["settings"] == dict(LINUX_SETTINGS, custom_scripts=True)
    assert settings_of(result["response_policy"])["CustomScripts"] is True
    # Only the changed setting is sent.
    assert policy.calls == [search_call(), update_call(settings=[setting("CustomScripts")]), get_call()]


def test_present_turns_a_setting_off(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_settings"],
        get_policies=["get_updated"],
    )

    result = run_module(response_policy, by_name(real_time_functionality=False))

    assert result["changed"] is True
    assert policy.calls == [
        search_call(),
        update_call(settings=[setting("RealTimeFunctionality", False)]),
        get_call(),
    ]


def test_present_updates_description_and_settings_in_one_call(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_both"],
        get_policies=["get_updated"],
    )

    result = run_module(
        response_policy,
        by_name(description=UPDATED, real_time_functionality=True, custom_scripts=True, get_command=True),
    )

    assert result["changed"] is True
    assert policy.calls == [
        search_call(),
        update_call(description=UPDATED, settings=[setting("CustomScripts"), setting("GetCommand")]),
        get_call(),
    ]


def test_present_enables_policy(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        perform_policies_action=["enable"],
        get_policies=["get_enabled"],
    )

    result = run_module(response_policy, by_name(enabled=True))

    assert result["changed"] is True
    assert result["response_policy"]["enabled"] is True
    assert policy.calls == [search_call(), action_call("enable"), get_call()]


def test_present_by_id_disables_policy(api, run_module):
    policy, groups, built = api(get_policies=["get_enabled", "get_disabled"], perform_policies_action=["disable"])

    result = run_module(response_policy, {"policy_id": POLICY_ID, "enabled": False})

    assert result["changed"] is True
    assert result["response_policy"]["enabled"] is False
    assert policy.calls == [get_call(), action_call("disable"), get_call()]


def test_check_mode_predicts_update_without_writing(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(
        response_policy,
        by_name(description=UPDATED, enabled=True, get_command=True, _ansible_diff=True),
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["diff"]["after"]["description"] == UPDATED
    assert result["diff"]["after"]["enabled"] is True
    assert result["diff"]["after"]["settings"] == dict(LINUX_SETTINGS, get_command=True)
    assert result["response_policy"]["description"] == "Fixture policy"
    assert policy.calls == [search_call()]


def test_update_error_fails_with_api_message(api, run_module):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_missing"],
    )

    result = run_module(response_policy, by_name(description=UPDATED))

    assert result["failed"] is True
    assert result["msg"] == "policy id %s not found" % MISSING_ID
    assert policy.calls == [search_call(), update_call(description=UPDATED)]


def test_update_5xx_without_errors_fails_with_status(api, run_module, fixture):
    policy, groups, built = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=[without_errors(fixture("response_policy/update_description"), 500)],
    )

    result = run_module(response_policy, by_name(description=UPDATED))

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while updating the response policy"
    assert policy.calls == [search_call(), update_call(description=UPDATED)]


def settings_of(policy):
    return {s["id"]: s["value"]["enabled"] for c in policy["settings"] for s in c["settings"]}


# Lookup


def test_present_by_id_not_found_fails(api, run_module):
    policy, groups, built = api(get_policies=["get_missing"])

    result = run_module(response_policy, {"policy_id": MISSING_ID})

    assert result["failed"] is True
    assert result["msg"] == "Response policy not found: %s" % MISSING_ID
    assert policy.calls == [get_call(MISSING_ID)]


def test_policy_id_is_sent_in_lower_case(api, run_module):
    """The Sanitizer writes digit-only IDs, so this sends an upper-case ID with letters."""
    policy, groups, built = api(get_policies=["get_missing"])

    run_module(response_policy, {"policy_id": HEX_ID.upper(), "state": "absent"})

    assert policy.calls == [get_call(HEX_ID)]


def test_get_error_fails_with_api_message(api, run_module):
    policy, groups, built = api(get_policies=["get_short_id"])

    result = run_module(response_policy, {"policy_id": "abcdefg"})

    assert result["failed"] is True
    assert result["msg"] == "An item in query string parameter 'ids' has length 7, at least 32 expected"
    assert policy.calls == [get_call("abcdefg")]


def test_two_policies_with_the_name_fail(api, run_module, fixture):
    """Two exact matches on one platform fail.

    The recorder cannot record this: the API does not allow two policies with
    the same name on one platform. The copy adds a second policy with another
    ID and the name in another case.
    """
    response = copy.deepcopy(fixture("response_policy/query_by_exact_name"))
    other = copy.deepcopy(response["body"]["resources"][0])
    other["id"] = HEX_ID
    other["name"] = NAME.upper()
    response["body"]["resources"].append(other)
    policy, groups, built = api(query_combined_policies=[response])

    result = run_module(response_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "More than one response policy is named '%s' on Linux" % NAME
    assert policy.calls == [search_call()]


def test_policy_on_other_platform_is_not_a_match(api, run_module, fixture):
    """A search result on another platform is not a match.

    The search filters on platform_name, so the tenant does not return such a
    result. The copy changes the platform of the recorded policy.
    """
    response = copy.deepcopy(fixture("response_policy/query_by_exact_name"))
    response["body"]["resources"][0]["platform_name"] = "Windows"
    policy, groups, built = api(query_combined_policies=[response])

    result = run_module(response_policy, by_name(_ansible_diff=True), check_mode=True)

    assert result["changed"] is True
    assert result["diff"]["before"] == {}
    assert policy.calls == [search_call()]


def test_search_error_fails_with_api_message(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_bad_filter"])

    result = run_module(response_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"
    assert policy.calls == [search_call()]


def test_search_4xx_without_errors_fails_with_status(api, run_module, fixture):
    policy, groups, built = api(
        query_combined_policies=[without_errors(fixture("response_policy/query_bad_filter"), 403)]
    )

    result = run_module(response_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 403 while searching for the response policy"
    assert policy.calls == [search_call()]


def test_exception_fails_with_message(api, run_module):
    policy, groups, built = api(query_combined_policies=[Exception("boom")])

    result = run_module(response_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "An error occurred while managing the response policy: boom"
    assert policy.calls == [search_call()]


# Delete


def test_absent_deletes_disabled_policy(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name"], delete_policies=["delete"])

    result = run_module(response_policy, by_name(state="absent", _ansible_diff=True))

    assert result["changed"] is True
    assert result["diff"]["after"] == {}
    assert result["diff"]["before"]["name"] == NAME
    assert result["diff"]["before"]["settings"] == LINUX_SETTINGS
    assert policy.calls == [search_call(), ("delete_policies", {"ids": [POLICY_ID]})]


def test_absent_disables_enabled_policy_before_delete(api, run_module):
    policy, groups, built = api(
        get_policies=["get_enabled"],
        perform_policies_action=["disable"],
        delete_policies=["delete"],
    )

    result = run_module(response_policy, {"policy_id": POLICY_ID, "state": "absent"})

    assert result["changed"] is True
    assert policy.calls == [get_call(), action_call("disable"), ("delete_policies", {"ids": [POLICY_ID]})]


def test_absent_missing_policy_is_unchanged(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(response_policy, by_name(state="absent"))

    assert result["changed"] is False
    assert policy.calls == [search_call()]


def test_absent_by_missing_id_is_unchanged(api, run_module):
    policy, groups, built = api(get_policies=["get_missing"])

    result = run_module(response_policy, {"policy_id": MISSING_ID, "state": "absent"})

    assert result["changed"] is False
    assert policy.calls == [get_call(MISSING_ID)]


def test_check_mode_predicts_delete_without_writing(api, run_module):
    policy, groups, built = api(get_policies=["get_enabled"])

    result = run_module(response_policy, {"policy_id": POLICY_ID, "state": "absent"}, check_mode=True)

    assert result["changed"] is True
    assert policy.calls == [get_call()]


def test_delete_of_enabled_policy_error_fails(api, run_module):
    # The recorded 400 of a delete before the disable, given here to the delete
    # after the disable to test the status check of the delete call.
    policy, groups, built = api(
        get_policies=["get_enabled"],
        perform_policies_action=["disable"],
        delete_policies=["delete_enabled"],
    )

    result = run_module(response_policy, {"policy_id": POLICY_ID, "state": "absent"})

    assert result["failed"] is True
    assert result["msg"] == "Policy ansible-unit-fixture-crud is enabled, cannot delete enabled policies"
    assert policy.calls == [get_call(), action_call("disable"), ("delete_policies", {"ids": [POLICY_ID]})]


def test_delete_5xx_with_null_errors_fails_with_status(api, run_module, fixture):
    response = copy.deepcopy(fixture("response_policy/delete"))
    # The recorded delete has errors: null; only the status is changed (see without_errors).
    response["status_code"] = 500
    policy, groups, built = api(get_policies=["get_disabled"], delete_policies=[response])

    result = run_module(response_policy, {"policy_id": POLICY_ID, "state": "absent"})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while deleting the response policy"
    assert policy.calls == [get_call(), ("delete_policies", {"ids": [POLICY_ID]})]


# Host groups


def test_host_groups_not_set_makes_no_group_call(api, run_module):
    policy, groups, built = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(response_policy, by_name(purge_host_groups=True, _ansible_diff=True))

    assert result["changed"] is False
    assert built == ["ResponsePolicies"]
    assert groups.calls == []
    assert policy.calls == [search_call()]


def test_present_adds_host_groups_on_update(api, run_module):
    policy, groups, built = api(
        host_group=["hg_get_found"],
        query_combined_policies=["query_by_exact_name"],
        perform_policies_action=["add_groups"],
        get_policies=["get_with_groups"],
    )

    result = run_module(response_policy, by_name(host_groups=[GROUP_2, GROUP_1], _ansible_diff=True))

    assert result["changed"] is True
    assert [g["id"] for g in result["response_policy"]["groups"]] == [GROUP_1, GROUP_2]
    assert result["diff"]["before"]["groups"] == []
    assert result["diff"]["after"]["groups"] == [GROUP_1, GROUP_2]
    assert built == ["ResponsePolicies", "HostGroup"]
    assert groups.calls == [hg_call(GROUP_1, GROUP_2)]
    assert policy.calls == [search_call(), group_action_call("add", GROUP_1, GROUP_2), get_call()]


def test_present_adds_host_groups_after_create(api, run_module):
    policy, groups, built = api(
        host_group=["hg_get_found"],
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create"],
        perform_policies_action=["add_groups"],
        get_policies=["get_with_groups"],
    )

    result = run_module(response_policy, by_name(host_groups=[GROUP_1, GROUP_2], _ansible_diff=True))

    assert result["changed"] is True
    assert result["diff"]["after"]["groups"] == [GROUP_1, GROUP_2]
    assert groups.calls == [hg_call(GROUP_1, GROUP_2)]
    assert policy.calls == [search_call(), create_call(), group_action_call("add", GROUP_1, GROUP_2), get_call()]


def test_purge_removes_only_current_members_not_wanted(api, run_module):
    policy, groups, built = api(
        get_policies=["get_with_groups", "get_after_remove"],
        perform_policies_action=["remove_group"],
    )

    result = run_module(
        response_policy,
        {"policy_id": POLICY_ID, "host_groups": [GROUP_2], "purge_host_groups": True, "_ansible_diff": True},
    )

    assert result["changed"] is True
    assert result["diff"]["before"]["groups"] == [GROUP_1, GROUP_2]
    assert result["diff"]["after"]["groups"] == [GROUP_2]
    assert [g["id"] for g in result["response_policy"]["groups"]] == [GROUP_2]
    # Nothing to add, so the module does not build a HostGroup client.
    assert built == ["ResponsePolicies"]
    assert groups.calls == []
    assert policy.calls == [get_call(), group_action_call("remove", GROUP_1), get_call()]


def test_without_purge_extra_groups_stay(api, run_module):
    policy, groups, built = api(get_policies=["get_with_groups"])

    result = run_module(response_policy, {"policy_id": POLICY_ID, "host_groups": [GROUP_2]})

    assert result["changed"] is False
    assert built == ["ResponsePolicies"]
    assert policy.calls == [get_call()]


def test_check_mode_predicts_group_update_with_reads_only(api, run_module):
    policy, groups, built = api(host_group=["hg_get_found"], query_combined_policies=["query_by_exact_name"])

    result = run_module(response_policy, by_name(host_groups=[GROUP_1, GROUP_2], _ansible_diff=True), check_mode=True)

    assert result["changed"] is True
    assert result["diff"]["after"]["groups"] == [GROUP_1, GROUP_2]
    assert groups.calls == [hg_call(GROUP_1, GROUP_2)]
    assert policy.calls == [search_call()]


def test_check_mode_predicts_create_with_groups_with_reads_only(api, run_module):
    policy, groups, built = api(host_group=["hg_get_found"], query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(response_policy, by_name(host_groups=[GROUP_2, GROUP_1], _ansible_diff=True), check_mode=True)

    assert result["changed"] is True
    assert result["diff"]["after"]["groups"] == [GROUP_1, GROUP_2]
    assert result["response_policy"]["groups"] == [{"id": GROUP_1}, {"id": GROUP_2}]
    assert groups.calls == [hg_call(GROUP_1, GROUP_2)]
    assert policy.calls == [search_call()]


def test_upper_case_and_duplicate_ids_are_sent_once_in_lower_case(api, run_module):
    """The recorded IDs have only digits, so .lower() cannot change them.

    A hex ID with letters shows the case handling. Only the kwargs matter
    here; the recorded 200 responses are reused for the calls.
    """
    policy, groups, built = api(
        host_group=["hg_get_found"],
        query_combined_policies=["query_by_exact_name"],
        perform_policies_action=["add_groups"],
        get_policies=["get_with_groups"],
    )

    result = run_module(response_policy, by_name(host_groups=[HEX_ID.upper(), HEX_ID, GROUP_1, GROUP_1]))

    assert result["changed"] is True
    assert groups.calls == [hg_call(GROUP_1, HEX_ID)]
    assert policy.calls == [search_call(), group_action_call("add", GROUP_1, HEX_ID), get_call()]


def test_missing_host_group_fails_before_any_write(api, run_module):
    policy, groups, built = api(host_group=["hg_get_some_missing"], query_combined_policies=["query_by_exact_name"])

    result = run_module(response_policy, by_name(host_groups=[GROUP_1, MISSING_ID], description=UPDATED))

    assert result["failed"] is True
    assert result["msg"] == "Host groups not found: %s" % MISSING_ID
    assert groups.calls == [hg_call(MISSING_ID, GROUP_1)]
    assert policy.calls == [search_call()]


def test_missing_host_group_fails_before_create(api, run_module):
    policy, groups, built = api(host_group=["hg_get_all_missing"], query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(response_policy, by_name(host_groups=[MISSING_ID]))

    assert result["failed"] is True
    assert result["msg"] == "Host groups not found: %s" % MISSING_ID
    assert groups.calls == [hg_call(MISSING_ID)]
    assert policy.calls == [search_call()]


def test_host_group_check_error_fails_with_api_message(api, run_module):
    policy, groups, built = api(host_group=["hg_get_bad_id"], query_combined_policies=["query_by_exact_name"])

    result = run_module(response_policy, by_name(host_groups=["abcdefg"]))

    assert result["failed"] is True
    assert result["msg"] == "An item in query string parameter 'ids' has length 7, at least 32 expected"
    assert groups.calls == [hg_call("abcdefg")]
    assert policy.calls == [search_call()]


def test_add_host_groups_error_fails_with_api_message(api, run_module):
    policy, groups, built = api(
        host_group=["hg_get_found"],
        query_combined_policies=["query_by_exact_name"],
        perform_policies_action=["add_groups_missing_policy"],
    )

    result = run_module(response_policy, by_name(host_groups=[GROUP_1]))

    assert result["failed"] is True
    assert result["msg"] == "Policy %s not found for update." % MISSING_ID
    assert policy.calls == [search_call(), group_action_call("add", GROUP_1)]


def test_absent_ignores_host_groups(api, run_module):
    policy, groups, built = api(get_policies=["get_disabled"], delete_policies=["delete"])

    result = run_module(
        response_policy,
        {"policy_id": POLICY_ID, "state": "absent", "host_groups": [GROUP_1], "_ansible_diff": True},
    )

    assert result["changed"] is True
    assert "groups" not in result["diff"]["before"]
    assert built == ["ResponsePolicies"]
    assert groups.calls == []
    assert policy.calls == [get_call(), ("delete_policies", {"ids": [POLICY_ID]})]
