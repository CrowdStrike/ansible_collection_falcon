# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import prevention_policy

# The policy that record_prevention_policy() made for the prevention_policy cases.
NAME = "ansible-unit-fixture-crud"
# The fake ID that the Sanitizer gave it.
POLICY_ID = "00000000000000000000000000000007"
# The ID that does not exist ("f" * 32 in the recorder), after sanitizing.
MISSING_ID = "00000000000000000000000000000005"
FQL = "name:~'%s'+platform_name:'Linux'" % NAME
UPDATED = "Updated fixture policy"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches prevention_policy with recorded responses."""

    def make(**responses):
        return falcon_api(
            prevention_policy,
            {
                method: [
                    case if isinstance(case, (dict, Exception)) else fixture("prevention_policy/" + case)
                    for case in cases
                ]
                for method, cases in responses.items()
            },
        )

    return make


def by_name(**kwargs):
    return dict({"name": NAME, "platform_name": "Linux"}, **kwargs)


def search_call(name=NAME, platform="Linux"):
    return ("query_combined_policies", {"filter": "name:~'%s'+platform_name:'%s'" % (name, platform), "limit": 5000})


def get_call(policy_id=POLICY_ID):
    return ("get_policies", {"ids": [policy_id]})


def action_call(action):
    return ("perform_policies_action", {"action_name": action, "ids": [POLICY_ID]})


def update_call(description):
    return ("update_policies", {"body": {"resources": [{"id": POLICY_ID, "description": description}]}})


def create_call(**extra):
    return ("create_policies", {"body": {"resources": [dict({"name": NAME, "platform_name": "Linux"}, **extra)]}})


# Argument validation


@pytest.mark.parametrize("key", ["name", "policy_id"])
def test_empty_name_or_id_fails_before_any_call(api, run_module, key):
    service = api()
    args = {"policy_id": ""} if key == "policy_id" else {"name": "", "platform_name": "Linux"}

    result = run_module(prevention_policy, args)

    assert result["failed"] is True
    assert result["msg"] == "Parameter '%s' must not be empty" % key
    assert service.calls == []


def test_name_without_platform_fails(api, run_module):
    service = api()

    result = run_module(prevention_policy, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"] == "missing parameter(s) required by 'name': platform_name"
    assert service.calls == []


# Create


def test_present_creates_missing_policy(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create"],
        get_policies=["get_disabled"],
    )

    result = run_module(prevention_policy, by_name(description="Fixture policy", _ansible_diff=True))

    assert result["changed"] is True
    assert result["prevention_policy"]["id"] == POLICY_ID
    assert result["diff"] == {
        "before": {},
        "after": {"name": NAME, "platform_name": "Linux", "description": "Fixture policy", "enabled": False},
    }
    assert service.calls == [search_call(), create_call(description="Fixture policy"), get_call()]


def test_present_creates_and_enables_policy(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create"],
        perform_policies_action=["enable"],
        get_policies=["get_enabled"],
    )

    result = run_module(prevention_policy, by_name(enabled=True))

    assert result["changed"] is True
    assert result["prevention_policy"]["enabled"] is True
    assert "diff" not in result
    assert service.calls == [search_call(), create_call(), action_call("enable"), get_call()]


def test_check_mode_predicts_create_without_writing(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(prevention_policy, by_name(enabled=True), check_mode=True)

    assert result["changed"] is True
    assert result["prevention_policy"] == {"name": NAME, "platform_name": "Linux", "enabled": True}
    assert service.calls == [search_call()]


def test_create_error_fails_with_api_message(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name_missing"],
        create_policies=["create_duplicate"],
    )

    result = run_module(prevention_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "Duplicate policy name ansible-unit-fixture-crud for Linux platform."
    assert service.calls == [search_call(), create_call()]


# Update and idempotence


def test_present_with_same_values_makes_no_write(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(prevention_policy, by_name(description="Fixture policy", enabled=False))

    assert result["changed"] is False
    assert result["prevention_policy"]["id"] == POLICY_ID
    assert service.calls == [search_call()]


def test_name_in_other_case_finds_policy(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(prevention_policy, by_name(name=NAME.upper()))

    assert result["changed"] is False
    assert result["prevention_policy"]["name"] == NAME
    assert service.calls == [search_call(name=NAME.upper())]


def test_name_with_quote_is_escaped(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name_missing"])

    run_module(prevention_policy, by_name(name="it's\\x"), check_mode=True)

    assert service.calls == [search_call(name="it\\'s\\\\x")]


def test_present_updates_description(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_description"],
        get_policies=["get_disabled"],
    )

    result = run_module(prevention_policy, by_name(description=UPDATED, _ansible_diff=True))

    assert result["changed"] is True
    assert result["prevention_policy"]["description"] == UPDATED
    assert result["diff"]["before"]["description"] == "Fixture policy"
    assert result["diff"]["after"]["description"] == UPDATED
    assert service.calls == [search_call(), update_call(UPDATED), get_call()]


def test_present_clears_description(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_description"],
        get_policies=["get_disabled"],
    )

    result = run_module(prevention_policy, by_name(description=""))

    assert result["changed"] is True
    assert service.calls == [search_call(), update_call(""), get_call()]


def test_present_enables_policy(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name"],
        perform_policies_action=["enable"],
        get_policies=["get_enabled"],
    )

    result = run_module(prevention_policy, by_name(enabled=True))

    assert result["changed"] is True
    assert result["prevention_policy"]["enabled"] is True
    assert service.calls == [search_call(), action_call("enable"), get_call()]


def test_present_by_id_disables_policy(api, run_module):
    service = api(get_policies=["get_enabled", "get_disabled"], perform_policies_action=["disable"])

    result = run_module(prevention_policy, {"policy_id": POLICY_ID, "enabled": False})

    assert result["changed"] is True
    assert result["prevention_policy"]["enabled"] is False
    assert service.calls == [get_call(), action_call("disable"), get_call()]


def test_check_mode_predicts_update_without_writing(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name"])

    result = run_module(prevention_policy, by_name(description=UPDATED, enabled=True, _ansible_diff=True), check_mode=True)

    assert result["changed"] is True
    assert result["diff"]["after"]["description"] == UPDATED
    assert result["diff"]["after"]["enabled"] is True
    assert service.calls == [search_call()]


def test_update_error_fails_with_api_message(api, run_module):
    service = api(
        query_combined_policies=["query_by_exact_name"],
        update_policies=["update_missing"],
    )

    result = run_module(prevention_policy, by_name(description=UPDATED))

    assert result["failed"] is True
    assert result["msg"] == "Policy %s not found for update." % MISSING_ID
    assert service.calls == [search_call(), update_call(UPDATED)]


# Lookup


def test_present_by_id_not_found_fails(api, run_module):
    service = api(get_policies=["get_missing"])

    result = run_module(prevention_policy, {"policy_id": MISSING_ID})

    assert result["failed"] is True
    assert result["msg"] == "Prevention policy not found: %s" % MISSING_ID
    assert service.calls == [get_call(MISSING_ID)]


def test_policy_id_is_sent_in_lower_case(api, run_module):
    """The Sanitizer writes digit-only IDs, so this sends an upper-case ID with letters."""
    service = api(get_policies=["get_missing"])

    run_module(prevention_policy, {"policy_id": "ABCDEF1234567890ABCDEF1234567890", "state": "absent"})

    assert service.calls == [get_call("abcdef1234567890abcdef1234567890")]


def test_two_policies_with_the_name_fail(api, run_module, fixture):
    """Two exact matches on one platform fail.

    The recorder cannot record this: the API does not allow two policies with
    the same name on one platform. The copy adds a second policy with another
    ID and the name in another case.
    """
    response = copy.deepcopy(fixture("prevention_policy/query_by_exact_name"))
    other = copy.deepcopy(response["body"]["resources"][0])
    other["id"] = "abcdef1234567890abcdef1234567890"
    other["name"] = NAME.upper()
    response["body"]["resources"].append(other)
    service = api(query_combined_policies=[response])

    result = run_module(prevention_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "More than one prevention policy is named '%s' on Linux" % NAME
    assert service.calls == [search_call()]


def test_policy_on_other_platform_is_not_a_match(api, run_module, fixture):
    """A search result on another platform is not a match.

    The search filters on platform_name, so the tenant does not return such a
    result. The copy changes the platform of the recorded policy to check
    that the module does not depend on the filter alone.
    """
    response = copy.deepcopy(fixture("prevention_policy/query_by_exact_name"))
    response["body"]["resources"][0]["platform_name"] = "Windows"
    service = api(query_combined_policies=[response])

    result = run_module(prevention_policy, by_name(), check_mode=True)

    assert result["changed"] is True
    assert result["prevention_policy"] == {"name": NAME, "platform_name": "Linux", "enabled": False}
    assert service.calls == [search_call()]


def test_search_error_fails_with_api_message(api, run_module):
    service = api(query_combined_policies=["query_bad_filter"])

    result = run_module(prevention_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"
    assert service.calls == [search_call()]


def test_exception_fails_with_message(api, run_module):
    service = api(query_combined_policies=[Exception("boom")])

    result = run_module(prevention_policy, by_name())

    assert result["failed"] is True
    assert result["msg"] == "An error occurred while managing the prevention policy: boom"
    assert service.calls == [search_call()]


# Delete


def test_absent_deletes_disabled_policy(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name"], delete_policies=["delete"])

    result = run_module(prevention_policy, by_name(state="absent", _ansible_diff=True))

    assert result["changed"] is True
    assert result["diff"]["after"] == {}
    assert result["diff"]["before"]["name"] == NAME
    assert service.calls == [search_call(), ("delete_policies", {"ids": [POLICY_ID]})]


def test_absent_disables_enabled_policy_before_delete(api, run_module):
    service = api(
        get_policies=["get_enabled"],
        perform_policies_action=["disable"],
        delete_policies=["delete"],
    )

    result = run_module(prevention_policy, {"policy_id": POLICY_ID, "state": "absent"})

    assert result["changed"] is True
    assert service.calls == [get_call(), action_call("disable"), ("delete_policies", {"ids": [POLICY_ID]})]


def test_absent_missing_policy_is_unchanged(api, run_module):
    service = api(query_combined_policies=["query_by_exact_name_missing"])

    result = run_module(prevention_policy, by_name(state="absent"))

    assert result["changed"] is False
    assert service.calls == [search_call()]


def test_absent_by_missing_id_is_unchanged(api, run_module):
    service = api(get_policies=["get_missing"])

    result = run_module(prevention_policy, {"policy_id": MISSING_ID, "state": "absent"})

    assert result["changed"] is False
    assert service.calls == [get_call(MISSING_ID)]


def test_check_mode_predicts_delete_without_writing(api, run_module):
    service = api(get_policies=["get_enabled"])

    result = run_module(prevention_policy, {"policy_id": POLICY_ID, "state": "absent"}, check_mode=True)

    assert result["changed"] is True
    assert service.calls == [get_call()]


def test_delete_of_enabled_policy_error_fails(api, run_module):
    # The recorded 400 of a delete before the disable, given here to the delete
    # after the disable to test the status check of the delete call.
    service = api(
        get_policies=["get_enabled"],
        perform_policies_action=["disable"],
        delete_policies=["delete_enabled"],
    )

    result = run_module(prevention_policy, {"policy_id": POLICY_ID, "state": "absent"})

    assert result["failed"] is True
    assert result["msg"] == "Policy ansible-unit-fixture-crud is enabled, cannot delete enabled policies"
    assert service.calls == [get_call(), action_call("disable"), ("delete_policies", {"ids": [POLICY_ID]})]
