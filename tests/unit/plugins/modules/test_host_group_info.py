# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import host_group_info

GROUP_ID = "00000000000000000000000000000001"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches host_group_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            host_group_info,
            {method: [fixture("host_group/" + case) for case in cases] for method, cases in responses.items()},
        )

    return make


def test_get_by_ids(api, run_module):
    service = api(get_host_groups=["get_one"])

    result = run_module(host_group_info, {"host_groups": [GROUP_ID]})

    assert result["changed"] is False
    assert [g["id"] for g in result["host_groups"]] == [GROUP_ID]
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 1, "total": 1}
    assert service.called("get_host_groups") == [{"ids": [GROUP_ID]}]


def test_search_passes_query_options_and_reports_total(api, run_module):
    service = api(query_combined_host_groups=["query_page1"])
    query = {"filter": "name:'x'", "sort": "name.asc", "limit": 2, "offset": 0}

    result = run_module(host_group_info, query)

    assert service.called("query_combined_host_groups") == [query]
    assert len(result["host_groups"]) == 2
    # total comes from the API; offset and limit are the requested values.
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 2, "total": 3}


def test_second_page(api, run_module):
    api(query_combined_host_groups=["query_page2"])

    result = run_module(host_group_info, {"limit": 2, "offset": 2})

    assert [g["name"] for g in result["host_groups"]] == ["ansible-unit-fixture-c"]
    assert result["meta"]["pagination"]["total"] == 3


@pytest.mark.xfail(
    strict=True,
    reason="A search with no match returns resources: null, and the total "
    "fallback calls len(None) before .get() can use the API total.",
)
def test_empty_result(api, run_module):
    api(query_combined_host_groups=["query_by_name_missing"])

    result = run_module(host_group_info, {"filter": "name:'missing'"})

    assert not result.get("failed"), result.get("msg")
    assert result["meta"]["pagination"]["total"] == 0


def test_include_members_queries_each_group(api, run_module):
    service = api(
        query_combined_host_groups=["query_page1"],
        query_combined_group_members=["members_empty"],
    )

    result = run_module(host_group_info, {"limit": 2, "include_members": True})

    group_ids = [g["id"] for g in result["host_groups"]]
    assert service.called("query_combined_group_members") == [
        {"id": group_id, "limit": 5000} for group_id in group_ids
    ]
    # An empty group has resources: null, which is returned as is.
    assert [g["members"] for g in result["host_groups"]] == [None, None]


def test_api_error_fails_with_message(api, run_module):
    api(query_combined_host_groups=["query_bad_filter"])

    result = run_module(host_group_info, {"filter": "name:'"})

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"


@pytest.mark.parametrize(
    "args, message",
    [
        ({"host_groups": [GROUP_ID], "filter": "x"}, "mutually exclusive"),
        ({"limit": 0}, "between 1 and 5000"),
        ({"limit": 5001}, "between 1 and 5000"),
        ({"offset": -1}, "0 or greater"),
    ],
    ids=["ids-and-filter", "limit-0", "limit-5001", "negative-offset"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(host_group_info, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
