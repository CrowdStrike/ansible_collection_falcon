# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.crowdstrike.falcon.plugins.module_utils import falconpy_utils
from ansible_collections.crowdstrike.falcon.plugins.modules import case_info

# The test cases that record_case() read, and the fake IDs that the Sanitizer gave them.
PREFIX_FILTER = "name:*'ansible-dev-case-*'"
CASE_ID = "00000000-0000-0000-0000-000000000002"
CASE_NAME = "ansible-dev-case-20261118214348"
DUP_ID = "00000000-0000-0000-0000-000000000001"
DUP_NAME = "ansible-dev-case-20261118214348-dup"
# The ID that does not exist, as the recorder sent it. The get_missing response has no ID.
MISSING_ID = "f" * 32


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches case_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            case_info,
            {
                method: [
                    case if isinstance(case, (dict, Exception)) else fixture("case/" + case)
                    for case in cases
                ]
                for method, cases in responses.items()
            },
        )

    return make


def query(**kwargs):
    """Return the kwargs of a query_case_ids call that the module makes."""
    return dict({"limit": 100, "offset": 0}, **kwargs)


def ids_of(result):
    return [c["id"] for c in result["cases"]]


# Get by ID


def test_get_by_ids(api, run_module):
    service = api(get_cases=["get_several"])

    result = run_module(case_info, {"ids": [CASE_ID, DUP_ID]})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert ids_of(result) == [CASE_ID, DUP_ID]
    assert [c["name"] for c in result["cases"]] == [CASE_NAME, DUP_NAME]
    assert service.calls == [("get_cases", {"body": {"ids": [CASE_ID, DUP_ID]}})]


def test_get_by_ids_keeps_the_order_of_the_ids(api, run_module):
    """The recorded get_several response has CASE_ID first; ask for DUP_ID first."""
    service = api(get_cases=["get_several"])

    result = run_module(case_info, {"ids": [DUP_ID, CASE_ID]})

    assert ids_of(result) == [DUP_ID, CASE_ID]
    assert service.calls == [("get_cases", {"body": {"ids": [DUP_ID, CASE_ID]}})]


def test_get_by_duplicate_ids_sends_each_id_once(api, run_module):
    service = api(get_cases=["get_several"])

    result = run_module(case_info, {"ids": [CASE_ID, DUP_ID, CASE_ID]})

    assert ids_of(result) == [CASE_ID, DUP_ID]
    assert service.calls == [("get_cases", {"body": {"ids": [CASE_ID, DUP_ID]}})]


def test_get_by_unknown_id_returns_empty_list(api, run_module):
    # The API returns 200 and no resources for an unknown ID.
    service = api(get_cases=["get_missing"])

    result = run_module(case_info, {"ids": [MISSING_ID]})

    assert not result.get("failed"), result.get("msg")
    assert result["cases"] == []
    assert service.calls == [("get_cases", {"body": {"ids": [MISSING_ID]}})]


def test_get_by_empty_id_list_makes_no_call(api, run_module):
    # An empty list means "no IDs", not "every case".
    service = api()

    result = run_module(case_info, {"ids": []})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert result["cases"] == []
    assert service.calls == []


def test_get_by_ids_in_batches_of_100(api, fixture, run_module):
    """Send at most 100 IDs in one get_cases call.

    The tenant has two test cases, so the recorder cannot get 101 cases.
    The test reuses the recorded get_missing response for each batch.
    """
    ids = ["%08d-0000-0000-0000-000000000000" % n for n in range(101)]
    service = api(get_cases=["get_missing", "get_missing"])

    result = run_module(case_info, {"ids": ids})

    assert not result.get("failed"), result.get("msg")
    assert service.calls == [
        ("get_cases", {"body": {"ids": ids[:100]}}),
        ("get_cases", {"body": {"ids": ids[100:]}}),
    ]


def test_get_by_id_error_status_with_no_errors_fails(api, fixture, run_module):
    """Fail on a status that is not 200 when the API sends no errors.

    The tenant cannot give a 500 with errors: [] on demand, so this copies
    the recorded get_several response and changes only the status.
    """
    response = copy.deepcopy(fixture("case/get_several"))
    response["status_code"] = 500
    response["body"]["errors"] = []
    service = api(get_cases=[response])

    result = run_module(case_info, {"ids": [CASE_ID]})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while getting cases"
    assert result["cases"] == []
    assert service.calls == [("get_cases", {"body": {"ids": [CASE_ID]}})]


def test_get_by_id_exception_fails(api, run_module):
    service = api(get_cases=[RuntimeError("connection reset")])

    result = run_module(case_info, {"ids": [CASE_ID]})

    assert result["failed"] is True
    assert result["msg"] == "An error occurred while getting cases: connection reset"
    assert service.calls == [("get_cases", {"body": {"ids": [CASE_ID]}})]


# Search


def test_search_all_with_no_option(api, run_module):
    service = api(query_case_ids=["query_by_prefix"], get_cases=["get_several"])

    result = run_module(case_info, {})

    assert not result.get("failed"), result.get("msg")
    assert ids_of(result) == [DUP_ID, CASE_ID]
    assert service.calls == [
        ("query_case_ids", query()),
        ("get_cases", {"body": {"ids": [DUP_ID, CASE_ID]}}),
    ]


def test_search_with_filter(api, run_module):
    service = api(query_case_ids=["query_by_prefix"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": PREFIX_FILTER})

    assert ids_of(result) == [DUP_ID, CASE_ID]
    assert service.calls == [
        ("query_case_ids", query(filter=PREFIX_FILTER)),
        ("get_cases", {"body": {"ids": [DUP_ID, CASE_ID]}}),
    ]


def test_search_with_status_filter(api, run_module):
    flt = "%s+status:'closed'" % PREFIX_FILTER
    service = api(query_case_ids=["query_closed"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": flt})

    assert [c["status"] for c in result["cases"]] == ["closed", "closed"]
    assert service.calls == [
        ("query_case_ids", query(filter=flt)),
        ("get_cases", {"body": {"ids": [DUP_ID, CASE_ID]}}),
    ]


def test_search_with_q(api, run_module):
    service = api(query_case_ids=["query_q"], get_cases=["get_several"])

    result = run_module(case_info, {"q": "ansible-dev-case-"})

    assert ids_of(result) == [DUP_ID, CASE_ID]
    assert service.calls == [
        ("query_case_ids", query(q="ansible-dev-case-")),
        ("get_cases", {"body": {"ids": [DUP_ID, CASE_ID]}}),
    ]


def test_search_with_sort_sends_ids_in_sort_order(api, run_module):
    service = api(query_case_ids=["query_by_prefix_sorted"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": PREFIX_FILTER, "sort": "name.asc"})

    assert not result.get("failed"), result.get("msg")
    assert ids_of(result) == [CASE_ID, DUP_ID]
    assert service.calls == [
        ("query_case_ids", query(filter=PREFIX_FILTER, sort="name.asc")),
        ("get_cases", {"body": {"ids": [CASE_ID, DUP_ID]}}),
    ]


def test_search_with_limit_stops_at_limit(api, run_module):
    service = api(query_case_ids=["query_page_1"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": PREFIX_FILTER, "sort": "name.asc", "limit": 1})

    assert not result.get("failed"), result.get("msg")
    assert service.calls == [
        ("query_case_ids", query(filter=PREFIX_FILTER, sort="name.asc", limit=1)),
        ("get_cases", {"body": {"ids": [CASE_ID]}}),
    ]


def test_search_reads_every_page(api, run_module):
    """Read the next page until the offset reaches the total.

    The module asks for pages of 100 and the tenant has two test cases, so
    the recorder records the two pages with limit=1. The module kwargs are
    those of a search with no limit.
    """
    service = api(query_case_ids=["query_page_1", "query_page_2"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": PREFIX_FILTER, "sort": "name.asc"})

    assert not result.get("failed"), result.get("msg")
    assert service.calls == [
        ("query_case_ids", query(filter=PREFIX_FILTER, sort="name.asc")),
        ("query_case_ids", query(filter=PREFIX_FILTER, sort="name.asc", offset=1)),
        ("get_cases", {"body": {"ids": [CASE_ID, DUP_ID]}}),
    ]


def test_search_with_limit_asks_for_what_is_left(api, run_module):
    """Ask only for the cases that are left to reach the limit.

    The recorded pages have one case each, so a limit of 2 needs a second
    page, asked with limit=1.
    """
    service = api(query_case_ids=["query_page_1", "query_page_2"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": PREFIX_FILTER, "sort": "name.asc", "limit": 2})

    assert not result.get("failed"), result.get("msg")
    assert service.calls == [
        ("query_case_ids", query(filter=PREFIX_FILTER, sort="name.asc", limit=2)),
        ("query_case_ids", query(filter=PREFIX_FILTER, sort="name.asc", limit=1, offset=1)),
        ("get_cases", {"body": {"ids": [CASE_ID, DUP_ID]}}),
    ]


def test_search_empty_result_makes_no_get_call(api, run_module):
    flt = "name:'ansible-dev-none-xyz'"
    service = api(query_case_ids=["query_empty"])

    result = run_module(case_info, {"filter": flt})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert result["cases"] == []
    assert service.calls == [("query_case_ids", query(filter=flt))]


def test_search_bad_filter_fails(api, run_module):
    service = api(query_case_ids=["query_bad_filter"])

    result = run_module(case_info, {"filter": "name:"})

    assert result["failed"] is True
    assert result["msg"] == "invalid query filter in request"
    assert result["errors"] == [{"code": 400, "message": "invalid query filter in request"}]
    assert service.calls == [("query_case_ids", query(filter="name:"))]


def test_search_bad_sort_fails(api, run_module):
    service = api(query_case_ids=["query_bad_sort"])

    result = run_module(case_info, {"filter": PREFIX_FILTER, "sort": "nosuchfield.asc"})

    assert result["failed"] is True
    assert result["msg"] == "invalid field for sort"
    assert result["errors"] == [{"code": 400, "message": "invalid field for sort"}]
    assert service.calls == [("query_case_ids", query(filter=PREFIX_FILTER, sort="nosuchfield.asc"))]


def test_search_error_status_with_no_errors_fails(api, fixture, run_module):
    """Fail on a status that is not 200 when the API sends no errors.

    The tenant cannot give a 500 with errors: [] on demand, so this copies
    the recorded query_bad_filter response and changes the status and the errors.
    """
    response = copy.deepcopy(fixture("case/query_bad_filter"))
    response["status_code"] = 500
    response["body"]["errors"] = []
    service = api(query_case_ids=[response])

    result = run_module(case_info, {"filter": PREFIX_FILTER})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while searching for cases"
    assert service.calls == [("query_case_ids", query(filter=PREFIX_FILTER))]


# Arguments


@pytest.mark.parametrize("limit", [0, -1])
def test_limit_below_one_fails_before_any_call(api, run_module, limit):
    service = api()

    result = run_module(case_info, {"limit": limit})

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'limit' must be 1 or greater"
    assert service.calls == []


def test_empty_id_fails_before_any_call(api, run_module):
    service = api()

    result = run_module(case_info, {"ids": [CASE_ID, ""]})

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'ids' must not contain an empty ID"
    assert service.calls == []


@pytest.mark.parametrize("other", ["filter", "q", "sort", "limit"])
def test_ids_with_search_option_fails(api, run_module, other):
    service = api()

    result = run_module(case_info, {"ids": [CASE_ID], other: "x"})

    assert result["failed"] is True
    assert result["msg"] == "parameters are mutually exclusive: ids|%s" % other
    assert service.calls == []


def test_check_mode_reads(api, run_module):
    service = api(query_case_ids=["query_by_prefix"], get_cases=["get_several"])

    result = run_module(case_info, {"filter": PREFIX_FILTER, "_ansible_check_mode": True})

    assert result["changed"] is False
    assert ids_of(result) == [DUP_ID, CASE_ID]
    assert service.calls == [
        ("query_case_ids", query(filter=PREFIX_FILTER)),
        ("get_cases", {"body": {"ids": [DUP_ID, CASE_ID]}}),
    ]


def test_falconpy_below_1_5_5_fails(api, run_module, monkeypatch):
    monkeypatch.setattr(falconpy_utils, "_VERSION", "1.5.4")
    service = api()

    result = run_module(case_info, {})

    assert result["failed"] is True
    assert result["msg"] == "Unsupported FalconPy version: 1.5.4. Upgrade to 1.5.5 or higher."
    assert service.calls == []


def test_missing_falconpy_fails(api, run_module, monkeypatch):
    monkeypatch.setattr(case_info, "HAS_FALCONPY", False)
    monkeypatch.setattr(case_info, "FALCONPY_IMPORT_ERROR", "ImportError: falconpy")
    service = api()

    result = run_module(case_info, {})

    assert result["failed"] is True
    assert result["msg"] == missing_required_lib("falconpy")
    assert service.calls == []
