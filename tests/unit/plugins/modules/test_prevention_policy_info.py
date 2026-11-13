# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.crowdstrike.falcon.plugins.modules import prevention_policy_info

# The names that record_prevention_policy() used for its throwaway policies.
PREFIX = "ansible-unit-fixture"
SHARED = "ansible-unit-fixture-shared"
MIXED = "ansible-unit-fixture-Mixed-Case"
# The fake IDs that the Sanitizer gave them: the shared policy on Linux, the
# shared policy on Windows, and the mixed-case policy on Linux.
LINUX_ID = "00000000000000000000000000000001"
WINDOWS_ID = "00000000000000000000000000000004"
MIXED_ID = "00000000000000000000000000000006"
# The ID that does not exist ("f" * 32 in the recorder), after sanitizing.
MISSING_ID = "00000000000000000000000000000005"
SHORT_ID = "abcdefg"
# An ID with hex letters, as the API returns them: lower case. The module example uses it.
LETTERS_ID = "12345678901234567890abcdef123456"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches prevention_policy_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            prevention_policy_info,
            {
                method: [
                    case if isinstance(case, (dict, Exception)) else fixture("prevention_policy/" + case)
                    for case in cases
                ]
                for method, cases in responses.items()
            },
        )

    return make


def search_kwargs(**kwargs):
    """Return the kwargs of the first search call that the module makes."""
    return dict(kwargs, offset=None, limit=5000)


def page(fixture, start, end, total):
    """Return one page of the recorded query_sorted response.

    The module always asks for pages of 5000, and the recorder does not make
    5001 policies, so the tenant cannot give a second page with the module's
    kwargs. This splits the three recorded policies into pages.
    """
    response = copy.deepcopy(fixture("prevention_policy/query_sorted"))
    body = response["body"]
    body["resources"] = body["resources"][start:end]
    body["meta"]["pagination"]["offset"] = end
    body["meta"]["pagination"]["total"] = total
    return response


def ids_of(result):
    return [p["id"] for p in result["prevention_policies"]]


# Get by ID


def test_get_by_one_id(api, run_module):
    service = api(get_policies=["get_one"])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID]})

    assert result["changed"] is False
    assert ids_of(result) == [LINUX_ID]
    assert result["prevention_policies"][0]["name"] == SHARED
    assert service.calls == [("get_policies", {"ids": [LINUX_ID]})]


def test_get_by_several_ids_keeps_order(api, run_module):
    service = api(get_policies=["get_several"])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID, WINDOWS_ID]})

    assert ids_of(result) == [LINUX_ID, WINDOWS_ID]
    assert [p["platform_name"] for p in result["prevention_policies"]] == ["Linux", "Windows"]
    assert service.calls == [("get_policies", {"ids": [LINUX_ID, WINDOWS_ID]})]


def test_get_by_ids_sends_each_id_once(api, run_module):
    # The API returns a repeated ID twice, so the module sends each ID once, in order.
    service = api(get_policies=["get_several"])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID, WINDOWS_ID, LINUX_ID]})

    assert ids_of(result) == [LINUX_ID, WINDOWS_ID]
    assert service.calls == [("get_policies", {"ids": [LINUX_ID, WINDOWS_ID]})]


def get_one_with_letters(fixture):
    """Return the recorded get_one response with an ID that has hex letters.

    The fake IDs of the fixtures are only digits, so their upper case form is
    the same string. The tenant IDs have letters, and the recorder cannot keep
    them. This changes only the ID of the policy.
    """
    response = copy.deepcopy(fixture("prevention_policy/get_one"))
    response["body"]["resources"][0]["id"] = LETTERS_ID
    return response


def test_get_by_upper_case_id_sends_lower_case(api, fixture, run_module):
    # The API returns 404 for the upper case form of a real ID, so the module sends lower case.
    service = api(get_policies=[get_one_with_letters(fixture)])

    result = run_module(prevention_policy_info, {"policy_ids": [LETTERS_ID.upper()]})

    assert not result.get("failed"), result.get("msg")
    assert ids_of(result) == [LETTERS_ID]
    assert service.calls == [("get_policies", {"ids": [LETTERS_ID]})]


def test_get_by_id_in_two_cases_sends_it_once(api, fixture, run_module):
    service = api(get_policies=[get_one_with_letters(fixture)])

    result = run_module(prevention_policy_info, {"policy_ids": [LETTERS_ID, LETTERS_ID.upper()]})

    assert ids_of(result) == [LETTERS_ID]
    assert service.calls == [("get_policies", {"ids": [LETTERS_ID]})]


def test_get_by_id_success_has_no_errors_key(api, run_module):
    service = api(get_policies=["get_one"])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID]})

    assert not result.get("failed"), result.get("msg")
    assert "errors" not in result
    assert service.calls == [("get_policies", {"ids": [LINUX_ID]})]


def test_get_by_id_error_status_with_no_errors_fails(api, fixture, run_module):
    """Fail on a status that is not 200 when the API sends no errors.

    The tenant cannot give a 500 with errors: [] on demand, so this copies
    the recorded get_one response and changes only the status and the errors.
    """
    response = copy.deepcopy(fixture("prevention_policy/get_one"))
    response["status_code"] = 500
    response["body"]["errors"] = []
    service = api(get_policies=[response])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID]})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while getting prevention policies"
    assert result["errors"] == []
    assert service.calls == [("get_policies", {"ids": [LINUX_ID]})]


def test_get_by_empty_id_list_makes_no_call(api, run_module):
    # An empty list means "no IDs", not "every policy".
    service = api()

    result = run_module(prevention_policy_info, {"policy_ids": []})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert result["prevention_policies"] == []
    assert service.calls == []


def test_get_missing_id_fails(api, run_module):
    service = api(get_policies=["get_missing"])

    result = run_module(prevention_policy_info, {"policy_ids": [MISSING_ID]})

    assert result["failed"] is True
    assert result["msg"] == "Prevention policy not found: %s" % MISSING_ID
    assert result["prevention_policies"] == []
    assert result["errors"] == [{"code": 404, "id": MISSING_ID, "message": "Not Found"}]
    assert service.calls == [("get_policies", {"ids": [MISSING_ID]})]


def test_get_real_and_missing_id_fails_with_found_policy(api, run_module):
    service = api(get_policies=["get_one_missing"])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID, MISSING_ID]})

    assert result["failed"] is True
    assert result["msg"] == "Prevention policy not found: %s" % MISSING_ID
    # The policy that exists is in the failed result.
    assert ids_of(result) == [LINUX_ID]
    assert result["errors"] == [{"code": 404, "id": MISSING_ID, "message": "Not Found"}]
    assert service.calls == [("get_policies", {"ids": [LINUX_ID, MISSING_ID]})]


def test_get_short_id_fails_with_api_message(api, run_module):
    service = api(get_policies=["get_short_id"])

    result = run_module(prevention_policy_info, {"policy_ids": [SHORT_ID]})

    assert result["failed"] is True
    assert result["msg"] == "An item in query string parameter 'ids' has length 7, at least 32 expected"
    assert result["prevention_policies"] == []
    assert service.calls == [("get_policies", {"ids": [SHORT_ID]})]


def test_api_exception_fails_with_message(api, run_module):
    service = api(get_policies=[Exception("connection reset")])

    result = run_module(prevention_policy_info, {"policy_ids": [LINUX_ID]})

    assert result["failed"] is True
    assert result["msg"] == "An error occurred while getting prevention policies: connection reset"
    assert result["prevention_policies"] == []
    assert service.calls == [("get_policies", {"ids": [LINUX_ID]})]


# Search


def test_search_with_no_option_reads_all(api, run_module):
    # The real response would be every policy in the tenant, so a recorded
    # search response stands in for it. The kwargs are what this test checks.
    service = api(query_combined_policies=["query_sorted"])

    result = run_module(prevention_policy_info, {})

    assert result["changed"] is False
    assert ids_of(result) == [MIXED_ID, WINDOWS_ID, LINUX_ID]
    assert service.calls == [("query_combined_policies", search_kwargs())]


def test_search_with_filter_only(api, run_module):
    service = api(query_combined_policies=["query_sorted"])

    result = run_module(prevention_policy_info, {"filter": "name:~'%s'" % PREFIX})

    assert ids_of(result) == [MIXED_ID, WINDOWS_ID, LINUX_ID]
    assert service.calls == [("query_combined_policies", search_kwargs(filter="name:~'%s'" % PREFIX))]


def test_search_with_sort_only(api, run_module):
    service = api(query_combined_policies=["query_sorted"])

    run_module(prevention_policy_info, {"sort": "name.asc"})

    assert service.calls == [("query_combined_policies", search_kwargs(sort="name.asc"))]


def test_search_with_filter_and_sort(api, run_module):
    service = api(query_combined_policies=["query_sorted"])

    result = run_module(prevention_policy_info, {"filter": "name:~'%s'" % PREFIX, "sort": "name.asc"})

    # name.asc sorts upper case before lower case, as the API returns it.
    assert [p["name"] for p in result["prevention_policies"]] == [MIXED, SHARED, SHARED]
    assert service.calls == [
        ("query_combined_policies", search_kwargs(filter="name:~'%s'" % PREFIX, sort="name.asc"))
    ]


def test_search_reads_second_page(api, fixture, run_module):
    service = api(
        query_combined_policies=[page(fixture, 0, 2, total=3), page(fixture, 2, 3, total=3)],
    )

    result = run_module(prevention_policy_info, {"filter": "name:~'%s'" % PREFIX})

    assert ids_of(result) == [MIXED_ID, WINDOWS_ID, LINUX_ID]
    # The next offset is the number of policies read so far.
    assert service.called("query_combined_policies") == [
        {"filter": "name:~'%s'" % PREFIX, "offset": None, "limit": 5000},
        {"filter": "name:~'%s'" % PREFIX, "offset": 2, "limit": 5000},
    ]


def test_search_by_name_returns_policies_of_both_platforms(api, run_module):
    # A name is unique only for each platform, so two policies match.
    service = api(query_combined_policies=["query_by_name"])

    result = run_module(prevention_policy_info, {"name": SHARED})

    assert ids_of(result) == [LINUX_ID, WINDOWS_ID]
    assert [p["platform_name"] for p in result["prevention_policies"]] == ["Linux", "Windows"]
    assert service.calls == [("query_combined_policies", search_kwargs(filter="name:~'%s'" % SHARED))]


def test_search_by_name_with_empty_filter_sends_only_the_name(api, run_module):
    service = api(query_combined_policies=["query_by_name"])

    result = run_module(prevention_policy_info, {"name": SHARED, "filter": ""})

    assert ids_of(result) == [LINUX_ID, WINDOWS_ID]
    assert service.calls == [
        ("query_combined_policies", {"filter": "name:~'%s'" % SHARED, "offset": None, "limit": 5000})
    ]


def test_search_by_name_and_platform_filter(api, run_module):
    # The user filter goes in parentheses so that a "," in it stays under the "+".
    service = api(query_combined_policies=["query_by_name_platform"])

    result = run_module(prevention_policy_info, {"name": SHARED, "filter": "platform_name:'Windows'"})

    assert ids_of(result) == [WINDOWS_ID]
    assert service.calls == [
        (
            "query_combined_policies",
            search_kwargs(filter="name:~'%s'+(platform_name:'Windows')" % SHARED),
        )
    ]


def test_search_by_name_and_sort(api, run_module):
    service = api(query_combined_policies=["query_by_name"])

    run_module(prevention_policy_info, {"name": SHARED, "sort": "name.desc"})

    assert service.calls == [
        ("query_combined_policies", search_kwargs(filter="name:~'%s'" % SHARED, sort="name.desc"))
    ]


def test_search_by_name_ignores_case(api, run_module):
    service = api(query_combined_policies=["query_by_name_mixed_case"])

    result = run_module(prevention_policy_info, {"name": MIXED.upper()})

    assert ids_of(result) == [MIXED_ID]
    # The API stores the name as it was sent.
    assert result["prevention_policies"][0]["name"] == MIXED
    assert service.calls == [("query_combined_policies", search_kwargs(filter="name:~'%s'" % MIXED.upper()))]


def test_search_by_name_keeps_only_exact_names(api, run_module):
    # name:~ matches the words of a name, so the prefix finds all three
    # fixture policies. None of them has the prefix as its full name.
    service = api(query_combined_policies=["query_by_name_partial"])

    result = run_module(prevention_policy_info, {"name": PREFIX})

    assert not result.get("failed"), result.get("msg")
    assert result["prevention_policies"] == []
    assert service.calls == [("query_combined_policies", search_kwargs(filter="name:~'%s'" % PREFIX))]


def test_search_by_name_escapes_quote_and_backslash(api, run_module):
    service = api(query_combined_policies=["query_by_name_quote"])

    result = run_module(prevention_policy_info, {"name": "%s-it's\\x" % PREFIX})

    assert not result.get("failed"), result.get("msg")
    assert result["prevention_policies"] == []
    assert service.calls == [
        ("query_combined_policies", search_kwargs(filter="name:~'%s-it\\'s\\\\x'" % PREFIX))
    ]


def test_search_with_no_match_returns_empty_list(api, run_module):
    # A search with no match returns resources: null.
    service = api(query_combined_policies=["query_by_name_missing"])

    result = run_module(prevention_policy_info, {"name": SHARED, "filter": "platform_name:'Mac'"})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert result["prevention_policies"] == []
    assert service.calls == [
        ("query_combined_policies", search_kwargs(filter="name:~'%s'+(platform_name:'Mac')" % SHARED))
    ]


def test_search_bad_filter_fails_with_api_message(api, run_module):
    service = api(query_combined_policies=["query_bad_filter"])

    result = run_module(prevention_policy_info, {"filter": "name:'"})

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"
    assert result["errors"] == [{"code": 400, "message": "Invalid filter expression supplied"}]
    assert result["prevention_policies"] == []
    assert service.calls == [("query_combined_policies", search_kwargs(filter="name:'"))]


def test_search_error_status_with_no_errors_fails(api, fixture, run_module):
    """Fail on a search status that is not 200 when the API sends no errors.

    The tenant cannot give a 500 with errors: [] on demand, so this copies
    the recorded query_by_name response and changes only the status and the errors.
    """
    response = copy.deepcopy(fixture("prevention_policy/query_by_name"))
    response["status_code"] = 500
    response["body"]["errors"] = []
    service = api(query_combined_policies=[response])

    result = run_module(prevention_policy_info, {"name": SHARED})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while getting prevention policies"
    assert result["errors"] == []
    assert result["prevention_policies"] == []
    assert service.calls == [("query_combined_policies", search_kwargs(filter="name:~'%s'" % SHARED))]


# Check mode and repeated runs


@pytest.mark.parametrize(
    "args, responses, calls",
    [
        (
            {"policy_ids": [LINUX_ID]},
            {"get_policies": ["get_one"]},
            [("get_policies", {"ids": [LINUX_ID]})],
        ),
        (
            {"name": SHARED},
            {"query_combined_policies": ["query_by_name"]},
            [("query_combined_policies", search_kwargs(filter="name:~'%s'" % SHARED))],
        ),
    ],
    ids=["by-id", "by-name"],
)
def test_check_mode_makes_the_same_read_calls(api, run_module, args, responses, calls):
    normal = api(**responses)
    expected = run_module(prevention_policy_info, args)
    checked = api(**responses)

    result = run_module(prevention_policy_info, args, check_mode=True)

    assert result["changed"] is False
    assert result["prevention_policies"] == expected["prevention_policies"]
    assert normal.calls == calls
    assert checked.calls == calls


def test_repeated_search_is_not_changed(api, run_module):
    service = api(query_combined_policies=["query_by_name"])

    first = run_module(prevention_policy_info, {"name": SHARED})
    second = run_module(prevention_policy_info, {"name": SHARED})

    assert first["changed"] is False
    assert second["changed"] is False
    assert second["prevention_policies"] == first["prevention_policies"]
    assert [m for m, _kwargs in service.calls] == ["query_combined_policies", "query_combined_policies"]


# Argument validation


@pytest.mark.parametrize(
    "args, message",
    [
        ({"name": ""}, "Parameter 'name' must not be empty"),
        ({"policy_ids": [LINUX_ID, ""]}, "Parameter 'policy_ids' must not contain an empty ID"),
        ({"policy_ids": [LINUX_ID], "name": SHARED}, "parameters are mutually exclusive: policy_ids|name"),
        ({"policy_ids": [LINUX_ID], "filter": "x"}, "parameters are mutually exclusive: policy_ids|filter"),
        ({"policy_ids": [LINUX_ID], "sort": "name.asc"}, "parameters are mutually exclusive: policy_ids|sort"),
    ],
    ids=["empty-name", "empty-id", "ids-and-name", "ids-and-filter", "ids-and-sort"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(prevention_policy_info, args)

    assert result["failed"] is True
    assert result["msg"] == message
    assert service.calls == []


def test_sort_outside_choices_fails(api, run_module):
    # platform_name.asc returns a 500 from the API, so it is not a choice.
    service = api()

    result = run_module(prevention_policy_info, {"sort": "platform_name.asc"})

    assert result["failed"] is True
    assert result["msg"].startswith("value of sort must be one of: name.asc, name.desc,")
    assert result["msg"].endswith("got: platform_name.asc")
    assert service.calls == []


def test_missing_falconpy_fails(api, run_module, monkeypatch):
    monkeypatch.setattr(prevention_policy_info, "HAS_FALCONPY", False)
    monkeypatch.setattr(prevention_policy_info, "FALCONPY_IMPORT_ERROR", "ImportError: falconpy")
    service = api()

    result = run_module(prevention_policy_info, {})

    assert result["failed"] is True
    assert result["msg"] == missing_required_lib("falconpy")
    assert service.calls == []
