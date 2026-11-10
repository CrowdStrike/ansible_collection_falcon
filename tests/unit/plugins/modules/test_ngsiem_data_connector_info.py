# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import ngsiem_data_connector_info


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches ngsiem_data_connector_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            ngsiem_data_connector_info,
            {
                method: [fixture("ngsiem/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def test_list_reports_total(api, run_module):
    service = api(list_data_connectors=["connectors_page"])

    result = run_module(ngsiem_data_connector_info, {"limit": 2})

    assert service.called("list_data_connectors") == [{"limit": 2, "offset": 0}]
    assert len(result["data_connectors"]) == 2
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 2, "total": 300}


def test_search_passes_query_options(api, run_module):
    service = api(list_data_connectors=["connectors_push"])
    query = {"filter": "type:'PUSH'", "sort": "name", "limit": 2, "offset": 0}

    result = run_module(ngsiem_data_connector_info, query)

    assert service.called("list_data_connectors") == [query]
    assert {c["type"] for c in result["data_connectors"]} == {"PUSH"}
    assert result["meta"]["pagination"]["total"] == 215


def test_api_error_fails_with_message(api, run_module):
    api(list_data_connectors=["connectors_bad_filter"])

    result = run_module(ngsiem_data_connector_info, {"filter": "type:'"})

    assert result["failed"] is True
    assert result["msg"] == "could not parse filter"


@pytest.mark.parametrize(
    "args, message",
    [
        ({"limit": 0}, "between 1 and 500"),
        ({"limit": 501}, "between 1 and 500"),
        ({"offset": -1}, "0 or greater"),
    ],
    ids=["limit-0", "limit-501", "negative-offset"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(ngsiem_data_connector_info, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
