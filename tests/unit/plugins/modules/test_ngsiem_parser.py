# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import ngsiem_parser

REPO = "parsers-repository"
NAME = "ansible-unit-fixture-parser"
# The API adds 'custom-' to the names of custom parsers.
STORED_NAME = "custom-" + NAME
PARSER_ID = "00000000000000000000000000000001:1.2.0"
# The ID that update_parser_from_template returns.
UPDATED_ID = PARSER_ID + ":1.2.0"
CLONE_NAME = "ansible-unit-fixture-clone"
CLONE_ID = "00000000000000000000000000000003:1.1.0"
EXTENSION_ID = "00000000000000000000000000000004:1.0.0"

# The template that tests/unit/record_fixtures.py used to create the parser.
YAML = """$schema: https://schemas.humio.com/parser/v0.3.0
name: {name}
fieldsToBeRemovedBeforeParsing: []
testCases: []
script: |-
  parseJson()
  | Cps.version := "1.0.0"
  | Vendor := "ansible"
  | ecs.version := "9.0.0"
  | event.dataset := "ansible.{dataset}"
  | event.kind := "event"
  | event.module := "ansible"
  | event.outcome := "success"
  | observer.type := "test"
tagFields:
  - Cps.version
  - Vendor
  - ecs.version
  - event.dataset
  - event.kind
  - event.module
  - event.outcome
  - observer.type
"""
CREATED_YAML = YAML.format(name=NAME, dataset="fixture")
UPDATED_YAML = YAML.format(name=NAME, dataset="fixture.updated")


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches ngsiem_parser with recorded responses."""

    def make(**responses):
        return falcon_api(
            ngsiem_parser,
            {
                method: [fixture("ngsiem/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def methods(service):
    return [method for method, _kwargs in service.calls]


def test_present_creates_missing_parser(api, run_module):
    service = api(
        list_parsers=["parser_list_missing"],
        create_parser_from_template=["parser_create"],
        get_parser=["parser_get"],
    )

    result = run_module(ngsiem_parser, {"name": NAME, "parser_yaml": CREATED_YAML})

    assert result["changed"] is True
    assert result["parser"]["id"] == PARSER_ID
    assert result["parser"]["name"] == STORED_NAME
    assert service.called("list_parsers") == [
        {"repository": REPO, "filter": "name:~'%s'" % NAME, "limit": 100}
    ]
    assert service.called("create_parser_from_template") == [
        {"repository": REPO, "name": NAME, "yaml_template": CREATED_YAML}
    ]
    assert service.called("get_parser") == [{"ids": PARSER_ID, "repository": REPO}]


def test_present_matching_parser_is_not_changed(api, run_module):
    # Only the script, tagFields and testCases are compared, so the name and
    # version in the stored template do not cause an update.
    service = api(
        list_parsers=["parser_list_by_name"],
        get_parser_template=["parser_template"],
        get_parser=["parser_get"],
    )

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "parser_yaml": CREATED_YAML})

    assert result["changed"] is False
    assert result["parser"]["id"] == PARSER_ID
    assert "update_parser_from_template" not in methods(service)


@pytest.mark.xfail(
    strict=True,
    reason="The API adds 'custom-' to the names of custom parsers and "
    "find_parser_by_name needs an exact match, so the module does not find "
    "the parser that it created and tries to create it again.",
)
def test_present_finds_parser_by_the_name_it_was_created_with(api, run_module):
    service = api(
        list_parsers=["parser_list_by_name"],
        get_parser_template=["parser_template"],
        create_parser_from_template=["parser_create"],
        get_parser=["parser_get"],
    )

    result = run_module(ngsiem_parser, {"name": NAME, "parser_yaml": CREATED_YAML})

    assert "create_parser_from_template" not in methods(service)
    assert result["changed"] is False


def test_present_changed_yaml_updates_parser(api, run_module):
    service = api(
        list_parsers=["parser_list_by_name"],
        get_parser_template=["parser_template"],
        update_parser_from_template=["parser_update"],
        get_parser=["parser_get_after_update"],
    )

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "parser_yaml": UPDATED_YAML})

    assert result["changed"] is True
    assert service.called("update_parser_from_template") == [
        {"ids": PARSER_ID, "repository": REPO, "yaml_template": UPDATED_YAML}
    ]
    # current behavior: the update returns '<id>:<version>:<version>' and
    # get_parser with that ID returns 404, so the module returns only the ID.
    assert service.called("get_parser") == [{"ids": UPDATED_ID, "repository": REPO}]
    assert result["parser"] == {"id": UPDATED_ID}


def test_check_mode_reports_update_without_updating(api, run_module):
    service = api(list_parsers=["parser_list_by_name"], get_parser_template=["parser_template"])

    result = run_module(
        ngsiem_parser, {"name": STORED_NAME, "parser_yaml": UPDATED_YAML}, check_mode=True
    )

    assert result["changed"] is True
    assert methods(service) == ["list_parsers", "get_parser_template"]


def test_check_mode_reports_create_without_creating(api, run_module):
    service = api(list_parsers=["parser_list_missing"])

    result = run_module(ngsiem_parser, {"name": NAME, "parser_yaml": CREATED_YAML}, check_mode=True)

    assert result["changed"] is True
    assert methods(service) == ["list_parsers"]


def test_clone_creates_parser(api, run_module):
    service = api(
        list_parsers=["parser_list_missing"],
        clone_parser=["parser_clone"],
        get_parser=["parser_get_clone"],
    )

    result = run_module(ngsiem_parser, {"name": CLONE_NAME, "clone_from": PARSER_ID})

    assert result["changed"] is True
    assert result["parser"]["id"] == CLONE_ID
    assert service.called("clone_parser") == [{"source_id": PARSER_ID, "new_name": CLONE_NAME}]


def test_extension_creates_parser(api, run_module):
    service = api(
        list_parsers=["parser_list_missing"],
        create_parser_extension=["parser_extension"],
        # A 404, so the module returns only the ID of the extension.
        get_parser=["parser_get_after_update"],
    )

    result = run_module(ngsiem_parser, {"name": "ansible-unit-fixture-ext", "extension_of": "microsoft-edge"})

    assert result["changed"] is True
    assert result["parser"] == {"id": EXTENSION_ID}
    assert service.called("create_parser_extension") == [
        {"base_parser_id": "microsoft-edge", "extension_name": "ansible-unit-fixture-ext"}
    ]


def test_extension_of_versioned_base_fails_with_api_message(api, run_module):
    api(
        list_parsers=["parser_list_missing"],
        create_parser_extension=["parser_extension_versioned_base"],
    )

    result = run_module(
        ngsiem_parser, {"name": "ansible-unit-fixture-ext", "extension_of": "microsoft-edge:1.0.0"}
    )

    assert result["failed"] is True
    assert result["msg"].startswith("base_parser_id cannot contain version identifiers")


def test_present_by_parser_id_returns_parser(api, run_module):
    service = api(list_parsers=["parser_list_by_name"], get_parser=["parser_get"])

    result = run_module(ngsiem_parser, {"parser_id": PARSER_ID})

    assert result["changed"] is False
    assert result["parser"]["name"] == STORED_NAME
    # A lookup by ID lists the parsers without a filter.
    assert service.called("list_parsers") == [{"repository": REPO, "limit": 500}]


def test_present_by_parser_id_that_does_not_exist_fails(api, run_module):
    api(list_parsers=["parser_list_missing"])

    result = run_module(ngsiem_parser, {"parser_id": PARSER_ID})

    assert result["failed"] is True
    assert result["msg"] == "Parser with ID '%s' not found" % PARSER_ID


def test_present_missing_parser_without_input_fails(api, run_module):
    service = api(list_parsers=["parser_list_missing"])

    result = run_module(ngsiem_parser, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"].startswith("One of 'parser_yaml', 'clone_from', or 'extension_of'")
    assert methods(service) == ["list_parsers"]


def test_absent_deletes_existing_parser(api, run_module):
    service = api(list_parsers=["parser_list_by_name"], delete_parser=["parser_delete"])

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_parser") == [{"ids": PARSER_ID, "repository": REPO}]


def test_absent_missing_parser_is_not_changed(api, run_module):
    service = api(list_parsers=["parser_list_missing"])

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "state": "absent"})

    assert result["changed"] is False
    assert "delete_parser" not in methods(service)


def test_absent_delete_404_is_not_changed(api, run_module):
    # The list can show a parser that is already deleted.
    api(list_parsers=["parser_list_by_name"], delete_parser=["parser_delete_missing"])

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "state": "absent"})

    assert result["changed"] is False
    assert not result.get("failed")


def test_check_mode_reports_delete_without_deleting(api, run_module):
    service = api(list_parsers=["parser_list_by_name"])

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "state": "absent"}, check_mode=True)

    assert result["changed"] is True
    assert methods(service) == ["list_parsers"]


@pytest.mark.parametrize(
    "args, message",
    [
        ({}, "Either 'name' or 'parser_id' is required"),
        ({"name": NAME, "parser_yaml": CREATED_YAML, "clone_from": PARSER_ID}, "mutually exclusive"),
        ({"parser_id": PARSER_ID, "clone_from": PARSER_ID}, "'name' is required"),
        ({"parser_id": PARSER_ID, "extension_of": "microsoft-edge"}, "'name' is required"),
    ],
    ids=["no-name-or-id", "yaml-and-clone", "clone-without-name", "extension-without-name"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(ngsiem_parser, args)

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
