# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import ngsiem_data_connection_info

CONNECTION_ID = "00000000000000000000000000000007"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches ngsiem_data_connection_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            ngsiem_data_connection_info,
            {
                method: [fixture("ngsiem/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def test_get_by_ids(api, run_module):
    service = api(get_connection_by_id=["connection_get"])

    result = run_module(ngsiem_data_connection_info, {"connection_ids": [CONNECTION_ID]})

    assert service.called("get_connection_by_id") == [{"ids": [CONNECTION_ID]}]
    assert [c["id"] for c in result["data_connections"]] == [CONNECTION_ID]
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 1, "total": 1}


def test_search_passes_query_options(api, run_module):
    service = api(list_data_connections=["connection_list_by_name"])
    query = {"filter": "name:'ansible-unit-fixture-connection'", "sort": "name", "limit": 1, "offset": 0}

    result = run_module(ngsiem_data_connection_info, query)

    assert service.called("list_data_connections") == [query]
    assert result["data_connections"][0]["name"] == "ansible-unit-fixture-connection"
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 1, "total": 1}


def test_include_status_adds_provisioning_status(api, run_module):
    service = api(
        list_data_connections=["connection_list_by_name"],
        get_provisioning_status=["connection_status"],
    )

    result = run_module(ngsiem_data_connection_info, {"include_status": True})

    assert service.called("get_provisioning_status") == [{"ids": CONNECTION_ID}]
    assert result["data_connections"][0]["provisioning_status"]["status"] == "Idle"


def test_empty_result(api, run_module):
    service = api(list_data_connections=["connection_list_missing"])

    result = run_module(ngsiem_data_connection_info, {"filter": "name:'missing'", "include_status": True})

    assert result["data_connections"] == []
    assert result["meta"]["pagination"]["total"] == 0
    assert "get_provisioning_status" not in [method for method, _kwargs in service.calls]


@pytest.mark.parametrize(
    "args, method, case, message",
    [
        ({"connection_ids": [CONNECTION_ID]}, "get_connection_by_id", "connection_get_missing", "Not Found"),
        ({"filter": "name:'"}, "list_data_connections", "connection_list_bad_filter", "could not parse filter"),
    ],
    ids=["missing-id", "bad-filter"],
)
def test_api_error_fails_with_message(api, run_module, args, method, case, message):
    api(**{method: [case]})

    result = run_module(ngsiem_data_connection_info, args)

    assert result["failed"] is True
    assert result["msg"] == message


@pytest.mark.parametrize(
    "args, message",
    [
        ({"connection_ids": [CONNECTION_ID], "filter": "x"}, "mutually exclusive"),
        ({"limit": 0}, "between 1 and 500"),
        ({"limit": 501}, "between 1 and 500"),
        ({"offset": -1}, "0 or greater"),
    ],
    ids=["ids-and-filter", "limit-0", "limit-501", "negative-offset"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(ngsiem_data_connection_info, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
