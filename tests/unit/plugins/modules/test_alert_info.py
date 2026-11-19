# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.crowdstrike.falcon.plugins.modules import alert_info

# The composite IDs that record_alerts() read, after sanitizing: the first
# four epp alerts by created_timestamp ascending.
CID = "00000000000000000000000000000001"
AID = "00000000000000000000000000000002"
ID_A = CID + ":ind:" + AID + ":1792077572829695362-10304-186479376"
ID_B = CID + ":ind:" + AID + ":1792078110912749620-10303-186520592"
ID_C = CID + ":ind:" + AID + ":1792079001424043070-10304-186602768"
ID_D = CID + ":ind:" + AID + ":1792427481589501975-10304-214484240"
# The ID that does not exist (CID of the tenant, "f" * 32 as the agent ID).
MISSING_ID = CID + ":ind:00000000000000000000000000000003:0-0-0"
BAD_CID_ID = "f" * 32 + ":ind:" + "f" * 32 + ":0-0-0"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches alert_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            alert_info,
            {
                method: [
                    case if isinstance(case, (dict, Exception)) else fixture("alerts/" + case)
                    for case in cases
                ]
                for method, cases in responses.items()
            },
        )

    return make


def ids_of(result):
    return [a["composite_id"] for a in result["alerts"]]


# Get by composite ID


def test_get_by_ids_returns_user_order(api, run_module):
    # The API does not keep the order of the IDs, so the module uses the order of the list.
    service = api(get_alerts_v2=["get_several"])

    result = run_module(alert_info, {"composite_ids": [ID_C, ID_A, ID_B]})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert ids_of(result) == [ID_C, ID_A, ID_B]
    assert "errors" not in result
    assert service.calls == [("get_alerts_v2", {"composite_ids": [ID_C, ID_A, ID_B]})]


def test_get_by_ids_sends_each_id_once(api, run_module):
    service = api(get_alerts_v2=["get_several"])

    result = run_module(alert_info, {"composite_ids": [ID_B, ID_A, ID_B, ID_A]})

    assert ids_of(result) == [ID_B, ID_A]
    assert service.calls == [("get_alerts_v2", {"composite_ids": [ID_B, ID_A]})]


def test_get_by_ids_in_chunks(api, run_module, monkeypatch):
    # The tenant cannot hold 1001 test alerts, so a small chunk size stands in for MAX_IDS.
    monkeypatch.setattr(alert_info, "MAX_IDS", 2)
    service = api(get_alerts_v2=["get_several", "get_several"])

    result = run_module(alert_info, {"composite_ids": [ID_C, ID_A, ID_C, ID_B]})

    assert not result.get("failed"), result.get("msg")
    assert ids_of(result) == [ID_C, ID_A, ID_B]
    assert service.calls == [
        ("get_alerts_v2", {"composite_ids": [ID_C, ID_A]}),
        ("get_alerts_v2", {"composite_ids": [ID_B]}),
    ]


def test_get_missing_id_fails_with_found_alert(api, run_module):
    service = api(get_alerts_v2=["get_one_missing"])

    result = run_module(alert_info, {"composite_ids": [MISSING_ID, ID_A]})

    assert result["failed"] is True
    assert result["msg"] == "Alert not found: %s" % MISSING_ID
    assert ids_of(result) == [ID_A]
    assert result["errors"] == [
        {
            "code": 404,
            "id": MISSING_ID,
            "message": "could not find detection with ID %s" % MISSING_ID,
        }
    ]
    assert service.calls == [("get_alerts_v2", {"composite_ids": [MISSING_ID, ID_A]})]


def test_get_bad_cid_fails(api, run_module):
    service = api(get_alerts_v2=["get_bad_cid"])

    result = run_module(alert_info, {"composite_ids": [BAD_CID_ID]})

    assert result["failed"] is True
    assert result["msg"] == "invalid CID provided"
    assert result["alerts"] == []
    assert result["errors"] == [{"code": 400, "message": "invalid CID provided"}]
    assert service.calls == [("get_alerts_v2", {"composite_ids": [BAD_CID_ID]})]


def test_get_error_status_with_no_errors_fails(api, fixture, run_module):
    """Fail on a status that is not 200 when the API sends no errors.

    The tenant cannot give a 500 with errors: [] on demand, so this copies
    the recorded get_several response and changes only the status and the
    resources.
    """
    response = copy.deepcopy(fixture("alerts/get_several"))
    response["status_code"] = 500
    response["body"]["resources"] = response["body"]["resources"][:1]
    service = api(get_alerts_v2=[response])

    result = run_module(alert_info, {"composite_ids": [ID_A]})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while getting alerts"
    assert ids_of(result) == [ID_A]
    assert result["errors"] == []
    assert service.calls == [("get_alerts_v2", {"composite_ids": [ID_A]})]


def test_search_error_status_with_no_errors_fails(api, fixture, run_module):
    """Fail on a later page with a status that is not 200 and no errors.

    The tenant cannot give a 500 with errors: [] on demand, so this copies
    the recorded combined_page2 response and changes only the status and the
    resources. The alerts of page 1 stay in the result.
    """
    page1 = fixture("alerts/combined_page1")
    response = copy.deepcopy(fixture("alerts/combined_page2"))
    response["status_code"] = 500
    response["body"]["resources"] = []
    service = api(get_alerts_combined=[page1, response])

    result = run_module(alert_info, {"filter": "product:'epp'"})

    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 500 while getting alerts"
    assert ids_of(result) == [a["composite_id"] for a in page1["body"]["resources"]]
    after = page1["body"]["meta"]["pagination"]["after"]
    assert service.calls == [
        ("get_alerts_combined", {"filter": "product:'epp'", "limit": 1000}),
        ("get_alerts_combined", {"filter": "product:'epp'", "limit": 1000, "after": after}),
    ]


def test_get_by_empty_id_list_makes_no_call(api, run_module):
    # An empty list means "no IDs", not "every alert".
    service = api()

    result = run_module(alert_info, {"composite_ids": []})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert result["alerts"] == []
    assert service.calls == []


def test_api_exception_fails_with_message(api, run_module):
    service = api(get_alerts_v2=[Exception("connection reset")])

    result = run_module(alert_info, {"composite_ids": [ID_A]})

    assert result["failed"] is True
    assert result["msg"] == "An error occurred while getting alerts: connection reset"
    assert result["alerts"] == []
    assert service.calls == [("get_alerts_v2", {"composite_ids": [ID_A]})]


# Search


ALL_PAGES = ["combined_page1", "combined_page2", "combined_last"]


def test_search_reads_all_pages_with_after(api, run_module):
    # combined_last stands in for the last page: it has no after token.
    service = api(get_alerts_combined=ALL_PAGES)

    result = run_module(alert_info, {})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert ids_of(result) == [ID_A, ID_B, ID_C, ID_D, ID_A]
    assert "meta" not in result
    assert service.calls == [
        ("get_alerts_combined", {"limit": 1000}),
        ("get_alerts_combined", {"limit": 1000, "after": "opaque-token-1"}),
        ("get_alerts_combined", {"limit": 1000, "after": "opaque-token-2"}),
    ]


def test_search_with_filter_and_sort(api, run_module):
    service = api(get_alerts_combined=["combined_last"])

    result = run_module(
        alert_info,
        {"filter": "composite_id:'%s'" % ID_A, "sort": "created_timestamp.asc"},
    )

    assert not result.get("failed"), result.get("msg")
    assert ids_of(result) == [ID_A]
    assert service.calls == [
        (
            "get_alerts_combined",
            {"filter": "composite_id:'%s'" % ID_A, "sort": "created_timestamp.asc", "limit": 1000},
        )
    ]


def test_search_limit_stops_early_and_truncates(api, run_module):
    # The second page asks only for the one alert that is still needed.
    service = api(get_alerts_combined=ALL_PAGES)

    result = run_module(alert_info, {"filter": "product:'epp'", "limit": 3})

    assert not result.get("failed"), result.get("msg")
    assert ids_of(result) == [ID_A, ID_B, ID_C]
    assert service.calls == [
        ("get_alerts_combined", {"filter": "product:'epp'", "limit": 3}),
        ("get_alerts_combined", {"filter": "product:'epp'", "limit": 1, "after": "opaque-token-1"}),
    ]


def test_search_limit_reached_on_first_page(api, run_module):
    service = api(get_alerts_combined=ALL_PAGES)

    result = run_module(alert_info, {"limit": 2})

    assert ids_of(result) == [ID_A, ID_B]
    assert service.calls == [("get_alerts_combined", {"limit": 2})]


def test_search_large_limit_sends_max_page(api, run_module):
    service = api(get_alerts_combined=ALL_PAGES)

    result = run_module(alert_info, {"limit": 5000})

    assert ids_of(result) == [ID_A, ID_B, ID_C, ID_D, ID_A]
    assert service.calls == [
        ("get_alerts_combined", {"limit": 1000}),
        ("get_alerts_combined", {"limit": 1000, "after": "opaque-token-1"}),
        ("get_alerts_combined", {"limit": 1000, "after": "opaque-token-2"}),
    ]


def test_search_no_match_returns_empty(api, run_module):
    service = api(get_alerts_combined=["combined_empty"])

    result = run_module(alert_info, {"filter": "product:'none'"})

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert result["alerts"] == []
    assert service.calls == [("get_alerts_combined", {"filter": "product:'none'", "limit": 1000})]


def test_search_bad_filter_fails(api, run_module):
    service = api(get_alerts_combined=["combined_bad_filter"])

    result = run_module(alert_info, {"filter": "status:"})

    assert result["failed"] is True
    assert result["msg"] == "invalid query filter in request"
    assert result["alerts"] == []
    assert result["errors"] == [{"code": 400, "message": "invalid query filter in request"}]
    assert service.calls == [("get_alerts_combined", {"filter": "status:", "limit": 1000})]


def test_search_error_on_second_page_keeps_alerts(api, run_module):
    # The recorded bad filter error stands in for an error on a later page.
    service = api(get_alerts_combined=["combined_page1", "combined_bad_filter"])

    result = run_module(alert_info, {})

    assert result["failed"] is True
    assert result["msg"] == "invalid query filter in request"
    assert ids_of(result) == [ID_A, ID_B]
    assert service.calls == [
        ("get_alerts_combined", {"limit": 1000}),
        ("get_alerts_combined", {"limit": 1000, "after": "opaque-token-1"}),
    ]


def test_check_mode_reads_only(api, run_module):
    service = api(get_alerts_combined=ALL_PAGES)

    result = run_module(alert_info, {"limit": 2}, check_mode=True)

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert ids_of(result) == [ID_A, ID_B]
    assert service.calls == [("get_alerts_combined", {"limit": 2})]


# Argument validation


def test_empty_composite_id_fails(api, run_module):
    service = api()

    result = run_module(alert_info, {"composite_ids": [ID_A, ""]})

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'composite_ids' must not contain an empty ID"
    assert service.calls == []


@pytest.mark.parametrize("limit", [0, -1])
def test_limit_below_one_fails(api, run_module, limit):
    service = api()

    result = run_module(alert_info, {"limit": limit})

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'limit' must be 1 or greater"
    assert service.calls == []


@pytest.mark.parametrize(
    "args, msg",
    [
        ({"composite_ids": [ID_A], "filter": "x"}, "parameters are mutually exclusive: composite_ids|filter"),
        (
            {"composite_ids": [ID_A], "sort": "severity.asc"},
            "parameters are mutually exclusive: composite_ids|sort",
        ),
        ({"composite_ids": [ID_A], "limit": 1}, "parameters are mutually exclusive: composite_ids|limit"),
    ],
)
def test_mutually_exclusive_options_fail(api, run_module, args, msg):
    service = api()

    result = run_module(alert_info, args)

    assert result["failed"] is True
    assert result["msg"] == msg
    assert service.calls == []


def test_sort_outside_choices_fails(api, run_module):
    service = api()

    result = run_module(alert_info, {"sort": "name.asc"})

    assert result["failed"] is True
    assert result["msg"].startswith("value of sort must be one of: created_timestamp.asc,")
    assert result["msg"].endswith("got: name.asc")
    assert service.calls == []


def test_missing_falconpy_fails(api, run_module, monkeypatch):
    monkeypatch.setattr(alert_info, "HAS_FALCONPY", False)
    monkeypatch.setattr(alert_info, "FALCONPY_IMPORT_ERROR", "ImportError: falconpy")
    service = api()

    result = run_module(alert_info, {})

    assert result["failed"] is True
    assert result["msg"] == missing_required_lib("falconpy")
    assert service.calls == []
