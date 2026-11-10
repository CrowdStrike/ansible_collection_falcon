# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import intel_rule_info

PAGE1_IDS = ["1793955604", "1793350804"]
PAGE2_IDS = ["1792746004", "1792141204"]


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches intel_rule_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            intel_rule_info,
            {
                method: [fixture("intel/" + c) if isinstance(c, str) else c for c in cases]
                for method, cases in responses.items()
            },
        )

    return make


def test_limit_queries_one_page(api, run_module):
    service = api(query_rule_ids=["rule_ids_page1"], get_rule_entities=["rules"])

    result = run_module(intel_rule_info, {"type": "yara-master", "sort": "created_date|desc", "limit": 2})

    assert service.called("query_rule_ids") == [{"type": "yara-master", "sort": "created_date|desc", "limit": 2}]
    assert service.called("get_rule_entities") == [{"ids": PAGE1_IDS}]
    assert [r["name"] for r in result["rules"]] == [
        "CrowdStrike Intelligence Feed: YARA Master - 2026/11/06",
        "CrowdStrike Intelligence Feed: YARA Master - 2026/10/30",
    ]


def test_filters_are_passed_through(api, run_module):
    service = api(query_rule_ids=["rule_ids_empty"])

    run_module(
        intel_rule_info,
        {"type": "yara-master", "name": ["a"], "description": ["b"], "tags": ["c"], "q": "d", "limit": 1},
    )

    assert service.called("query_rule_ids") == [
        {"type": "yara-master", "name": ["a"], "description": ["b"], "tags": ["c"], "q": "d", "limit": 1}
    ]


def test_without_limit_reads_every_page(api, run_module):
    service = api(
        query_rule_ids=["rule_ids_page1", "rule_ids_page2", "rule_ids_empty"],
        get_rule_entities=["rules"],
    )

    run_module(intel_rule_info, {"type": "yara-master"})

    assert service.called("get_rule_entities") == [{"ids": PAGE1_IDS + PAGE2_IDS}]
    assert [c["limit"] for c in service.called("query_rule_ids")] == [5000] * 3


def test_without_limit_moves_to_the_next_page(api, run_module):
    service = api(
        query_rule_ids=["rule_ids_page1", "rule_ids_page2", "rule_ids_empty"],
        get_rule_entities=["rules"],
    )

    run_module(intel_rule_info, {"type": "yara-master"})

    # The recorded pages have a limit of 2.
    assert [c["offset"] for c in service.called("query_rule_ids")] == [None, 2, 4]


def test_rule_details_are_requested_in_batches_of_10(api, run_module, fixture):
    page = copy.deepcopy(fixture("intel/rule_ids_page1"))
    page["body"]["resources"] = [str(n) for n in range(12)]
    service = api(query_rule_ids=[page], get_rule_entities=["rules"])

    run_module(intel_rule_info, {"type": "yara-master", "limit": 12})

    assert [len(c["ids"]) for c in service.called("get_rule_entities")] == [10, 2]


def test_no_rules(api, run_module):
    service = api(query_rule_ids=["rule_ids_empty"])

    result = run_module(intel_rule_info, {"type": "yara-master", "limit": 2})

    assert result["rules"] == []
    assert "get_rule_entities" not in [method for method, _kwargs in service.calls]


def test_api_error_fails_with_message(api, run_module):
    api(query_rule_ids=["rule_ids_bad_type"])

    result = run_module(intel_rule_info, {"type": "yara-master", "limit": 2})

    assert result["failed"] is True
    assert result["msg"] == "Rule type invalid"
