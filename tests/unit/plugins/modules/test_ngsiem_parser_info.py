# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import ngsiem_parser_info

REPO = "parsers-repository"
PARSER_ID = "00000000000000000000000000000001:1.4.0"
CLONE_ID = "00000000000000000000000000000002:1.2.0"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches ngsiem_parser_info with recorded responses."""

    def make(**responses):
        return falcon_api(
            ngsiem_parser_info,
            {
                method: [fixture("ngsiem/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def test_search_passes_filters_and_normalizes_keys(api, run_module):
    service = api(list_parsers=["parser_info_page"])

    result = run_module(
        ngsiem_parser_info,
        {"name": "ansible-unit-fixture", "parser_type": "custom", "limit": 2, "definitions": False},
    )

    assert service.called("list_parsers") == [
        {
            "repository": REPO,
            "limit": 2,
            "offset": 0,
            "filter": "name:~'ansible-unit-fixture'",
            "parser_type": "custom",
        }
    ]
    # The list endpoint returns ID and Name; the module returns id and name.
    assert [p["id"] for p in result["parsers"]] == [CLONE_ID, PARSER_ID]
    assert "ID" not in result["parsers"][0]
    assert result["parsers"][0]["name"] == "custom-ansible-unit-fixture-clone"
    assert result["meta"]["pagination"] == {"offset": 0, "limit": 2, "total": 2}


def test_definitions_are_merged_with_summaries(api, run_module):
    service = api(list_parsers=["parser_info_page"], get_parser=["parser_get_clone", "parser_get_after_update"])

    result = run_module(ngsiem_parser_info, {"name": "ansible-unit-fixture", "limit": 2})

    assert service.called("get_parser") == [
        {"ids": CLONE_ID, "repository": REPO},
        {"ids": PARSER_ID, "repository": REPO},
    ]
    parser = result["parsers"][1]
    assert parser["script"].startswith("parseJson()")
    # Summary-only fields stay in the result.
    assert parser["parser_type"] == "custom"


def test_parser_ids_skip_the_search(api, run_module):
    service = api(get_parser=["parser_get_after_update"])

    result = run_module(ngsiem_parser_info, {"parser_ids": [PARSER_ID]})

    assert "list_parsers" not in [method for method, _kwargs in service.calls]
    assert result["parsers"][0]["name"] == "custom-ansible-unit-fixture-parser"
    assert result["meta"]["pagination"]["total"] == 1


def test_missing_definition_keeps_summary(api, run_module):
    # A recorded 404 from get_parser.
    api(get_parser=["parser_get_missing"])

    result = run_module(ngsiem_parser_info, {"parser_ids": [PARSER_ID]})

    assert result["parsers"] == [{"id": PARSER_ID}]


def test_update_available_is_sent_as_lowercase_string(api, run_module):
    service = api(list_parsers=["parser_list_missing"])

    run_module(ngsiem_parser_info, {"update_available": True, "definitions": False})

    assert service.called("list_parsers")[0]["update_available"] == "true"


def test_empty_result(api, run_module):
    api(list_parsers=["parser_list_missing"])

    result = run_module(ngsiem_parser_info, {"name": "missing"})

    assert result["parsers"] == []
    assert result["meta"]["pagination"]["total"] == 0


def test_api_error_fails_with_message(api, run_module):
    api(list_parsers=["parser_list_bad_filter"])

    result = run_module(ngsiem_parser_info, {"name": "'"})

    assert result["failed"] is True
    assert result["msg"].startswith("invalid filter syntax")


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

    result = run_module(ngsiem_parser_info, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
