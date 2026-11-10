# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import correlation_rule_info

RULE_ID = "00000000000000000000000000000002"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches correlation_rule_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            correlation_rule_info,
            {
                method: [fixture("correlation_rule/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def test_get_by_ids(api, run_module):
    service = api(get_rules=["get_one"])

    result = run_module(correlation_rule_info, {"rule_ids": [RULE_ID]})

    assert [r["rule_id"] for r in result["correlation_rules"]] == [RULE_ID]
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 1, "total": 1}
    assert service.called("get_rules") == [{"ids": [RULE_ID]}]


def test_search_passes_query_options_and_reports_total(api, run_module):
    service = api(get_rules_combined=["query_page1"])
    query = {"filter": "name:'x'", "sort": "name", "limit": 2, "offset": 0}

    result = run_module(correlation_rule_info, query)

    assert service.called("get_rules_combined") == [query]
    assert len(result["correlation_rules"]) == 2
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 2, "total": 3}


def test_include_latest_version_matches_by_rule_id(api, run_module):
    service = api(get_rules_combined=["query_page1"], get_latest_rule_versions=["latest_versions"])

    result = run_module(correlation_rule_info, {"limit": 2, "include_latest_version": True})

    rule_ids = [r["rule_id"] for r in result["correlation_rules"]]
    assert service.called("get_latest_rule_versions") == [{"rule_ids": rule_ids}]
    # The recorded response has the latest version of the first rule only.
    latest = [r["latest_version"] for r in result["correlation_rules"]]
    assert latest[0]["rule_id"] == RULE_ID
    assert latest[1] is None


def test_empty_result(api, run_module):
    api(get_rules_combined=["query_by_name_missing"])

    result = run_module(correlation_rule_info, {"filter": "name:'missing'"})

    assert result["correlation_rules"] == []
    assert result["meta"]["pagination"]["total"] == 0


def test_api_error_fails_with_message(api, run_module):
    api(get_rules_combined=["query_bad_filter"])

    result = run_module(correlation_rule_info, {"filter": "name:'"})

    assert result["failed"] is True
    assert result["msg"].startswith("could not parse filter")


@pytest.mark.parametrize(
    "args, message",
    [
        ({"rule_ids": [RULE_ID], "filter": "x"}, "mutually exclusive"),
        ({"limit": 0}, "between 1 and 500"),
        ({"limit": 501}, "between 1 and 500"),
        ({"offset": -1}, "0 or greater"),
    ],
    ids=["ids-and-filter", "limit-0", "limit-501", "negative-offset"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(correlation_rule_info, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
