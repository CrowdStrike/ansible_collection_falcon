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
UNVERSIONED_ID = "00000000000000000000000000000001"
PARSER_ID = UNVERSIONED_ID + ":1.7.0"
# The ID of the new version that update_parser_from_template makes.
UPDATED_ID = UNVERSIONED_ID + ":1.8.0"
OTHER_ID = "00000000000000000000000000000005:1.0.0"
CLONE_NAME = "ansible-unit-fixture-clone"
CLONE_UNVERSIONED_ID = "00000000000000000000000000000002"
CLONE_ID = CLONE_UNVERSIONED_ID + ":1.4.0"
EXTENSION_ID = "00000000000000000000000000000003:1.3.0"
EXT_NAME = "ansible-unit-fixture-ext"
BASE_ID = "00000000000000000000000000000008"
# The API names an extension '<base parser>-<name>'.
STORED_EXT_NAME = "microsoft-edge-" + EXT_NAME

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
        {"repository": REPO, "filter": "name:~'%s'" % NAME, "limit": 500, "offset": 0}
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


def test_present_finds_parser_by_the_name_it_was_created_with(api, run_module):
    # The API stores the parser as 'custom-<name>'.
    service = api(
        list_parsers=["parser_list_by_name"],
        get_parser_template=["parser_template"],
        create_parser_from_template=["parser_create"],
        get_parser=["parser_get"],
    )

    result = run_module(ngsiem_parser, {"name": NAME, "parser_yaml": CREATED_YAML})

    assert "create_parser_from_template" not in methods(service)
    assert result["changed"] is False
    assert result["parser"]["name"] == STORED_NAME


@pytest.mark.parametrize(
    "name", [NAME, STORED_NAME], ids=["custom-name-first", "exact-name-first"]
)
def test_find_parser_by_name_match_order(falcon_api, fixture, run_module, name):
    # Not recorded: the recorded list plus a parser named NAME and a parser
    # named 'custom-<STORED_NAME>', so two parsers match each name.
    listed = fixture("ngsiem/parser_list_by_name")
    stored = listed["body"]["resources"][0]
    listed["body"]["resources"] = [
        dict(stored, ID=OTHER_ID, Name="custom-" + STORED_NAME),
        dict(stored, ID=OTHER_ID, Name=NAME),
        stored,
    ]
    service = falcon_api(
        ngsiem_parser, {"list_parsers": [listed], "get_parser": [fixture("ngsiem/parser_get")]}
    )

    run_module(ngsiem_parser, {"name": name})

    assert service.called("get_parser") == [{"ids": PARSER_ID, "repository": REPO}]


def test_present_changed_yaml_updates_parser(api, run_module):
    service = api(
        list_parsers=["parser_list_by_name"],
        get_parser_template=["parser_template"],
        update_parser_from_template=["parser_update"],
        get_parser=["parser_get_after_update"],
    )

    result = run_module(ngsiem_parser, {"name": STORED_NAME, "parser_yaml": UPDATED_YAML})

    assert result["changed"] is True
    # An update with the versioned ID changes nothing, so the module sends the
    # ID without the version. The API returns the ID of the new version.
    assert service.called("update_parser_from_template") == [
        {"ids": UNVERSIONED_ID, "repository": REPO, "yaml_template": UPDATED_YAML}
    ]
    assert service.called("get_parser") == [{"ids": UPDATED_ID, "repository": REPO}]
    assert result["parser"]["id"] == UPDATED_ID
    assert 'event.dataset := "ansible.fixture.updated"' in result["parser"]["script"]


def test_present_after_update_is_not_changed(api, run_module):
    # The next run with the same YAML finds the new version and its template.
    service = api(
        list_parsers=["parser_list_after_update"],
        get_parser_template=["parser_template_after_update"],
        get_parser=["parser_get_after_update"],
    )

    result = run_module(ngsiem_parser, {"name": NAME, "parser_yaml": UPDATED_YAML})

    assert result["changed"] is False
    assert "update_parser_from_template" not in methods(service)
    assert service.called("get_parser_template") == [{"ids": UPDATED_ID, "repository": REPO}]
    assert result["parser"]["id"] == UPDATED_ID


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
        # The base parser, then a 404, so the module returns only the ID of
        # the extension.
        get_parser=["parser_get_base", "parser_get_missing"],
    )

    result = run_module(ngsiem_parser, {"name": EXT_NAME, "extension_of": BASE_ID})

    assert result["changed"] is True
    assert result["parser"] == {"id": EXTENSION_ID}
    assert service.called("create_parser_extension") == [
        {"base_parser_id": BASE_ID, "extension_name": EXT_NAME}
    ]


def test_extension_of_versioned_base_fails_with_api_message(api, run_module):
    api(
        list_parsers=["parser_list_missing"],
        get_parser=["parser_get_base"],
        create_parser_extension=["parser_extension_versioned_base"],
    )

    result = run_module(ngsiem_parser, {"name": EXT_NAME, "extension_of": BASE_ID + ":1.0.0"})

    assert result["failed"] is True
    assert result["msg"].startswith("base_parser_id cannot contain version identifiers")


@pytest.mark.parametrize("name", [EXT_NAME, STORED_EXT_NAME], ids=["created-name", "stored-name"])
def test_extension_that_exists_is_not_created_again(api, run_module, name):
    # A second create_parser_extension with the same name returns 404
    # 'parser not found', so the module must find the extension.
    service = api(
        list_parsers=["parser_list_extension"],
        get_parser=["parser_get_base", "parser_get_extension"],
    )

    result = run_module(ngsiem_parser, {"name": name, "extension_of": BASE_ID})

    assert result["changed"] is False
    assert "create_parser_extension" not in methods(service)
    assert result["parser"]["id"] == EXTENSION_ID
    assert result["parser"]["name"] == STORED_EXT_NAME
    assert service.called("get_parser") == [
        {"ids": BASE_ID, "repository": REPO},
        {"ids": EXTENSION_ID, "repository": REPO},
    ]


def test_extension_of_another_base_is_created(api, run_module):
    # The base parser has another name, so the extension that exists is not
    # a match.
    service = api(
        list_parsers=["parser_list_extension"],
        get_parser=["parser_get_clone", "parser_get_missing"],
        create_parser_extension=["parser_extension"],
    )

    result = run_module(ngsiem_parser, {"name": EXT_NAME, "extension_of": CLONE_UNVERSIONED_ID})

    assert result["changed"] is True
    assert service.called("create_parser_extension") == [
        {"base_parser_id": CLONE_UNVERSIONED_ID, "extension_name": EXT_NAME}
    ]


def test_absent_deletes_extension_by_created_name(api, run_module):
    service = api(
        list_parsers=["parser_list_extension", "parser_list_base"],
        delete_parser=["parser_delete_extension"],
    )

    result = run_module(ngsiem_parser, {"name": EXT_NAME, "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_parser") == [{"ids": EXTENSION_ID, "repository": REPO}]
    # The second search checks that 'microsoft-edge' is a base parser.
    assert service.called("list_parsers")[1] == {
        "repository": REPO, "filter": "name:~'microsoft-edge'", "limit": 500, "offset": 0,
    }


def test_absent_deletes_extension_with_extension_of(api, run_module):
    service = api(
        list_parsers=["parser_list_extension"],
        get_parser=["parser_get_base"],
        delete_parser=["parser_delete_extension"],
    )

    result = run_module(ngsiem_parser, {"name": EXT_NAME, "extension_of": BASE_ID, "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_parser") == [{"ids": EXTENSION_ID, "repository": REPO}]


def test_absent_suffix_of_extension_name_is_not_a_match(api, run_module):
    # 'fixture-ext' is also a suffix of the extension name, but there is no
    # base parser named 'microsoft-edge-ansible-unit'.
    service = api(list_parsers=["parser_list_extension", "parser_list_missing"])

    result = run_module(ngsiem_parser, {"name": "fixture-ext", "state": "absent"})

    assert result["changed"] is False
    assert "delete_parser" not in methods(service)


def test_absent_two_extensions_with_the_name_fails(falcon_api, fixture, run_module):
    # Not recorded: the recorded extension, and the same extension of a
    # second base parser.
    listed = fixture("ngsiem/parser_list_extension")
    ext = listed["body"]["resources"][0]
    other = dict(ext, ID=OTHER_ID, Name="watchguard-firebox-" + EXT_NAME)
    listed["body"]["resources"] = [ext, other]
    bases = fixture("ngsiem/parser_list_base")
    other_bases = fixture("ngsiem/parser_list_base")
    other_bases["body"]["resources"][0]["Name"] = "watchguard-firebox"
    service = falcon_api(ngsiem_parser, {"list_parsers": [listed, bases, other_bases]})

    result = run_module(ngsiem_parser, {"name": EXT_NAME, "state": "absent"})

    assert result["failed"] is True
    assert "More than one extension is named '%s'" % EXT_NAME in result["msg"]
    assert "delete_parser" not in methods(service)


def test_custom_parser_name_does_not_find_extension(api, run_module):
    # parser_yaml makes a custom parser, which is never an extension.
    service = api(
        list_parsers=["parser_list_extension"],
        create_parser_from_template=["parser_create"],
        get_parser=["parser_get"],
    )

    result = run_module(
        ngsiem_parser, {"name": EXT_NAME, "parser_yaml": YAML.format(name=EXT_NAME, dataset="fixture")}
    )

    assert result["changed"] is True
    assert service.called("list_parsers") == [
        {"repository": REPO, "filter": "name:~'%s'" % EXT_NAME, "limit": 500, "offset": 0}
    ]


def test_list_reads_all_pages(falcon_api, fixture, run_module, monkeypatch):
    # Pages of one parser: the clone, then the extension.
    monkeypatch.setattr(ngsiem_parser, "LIST_PAGE_SIZE", 1)
    service = falcon_api(
        ngsiem_parser,
        {
            "list_parsers": [fixture("ngsiem/parser_list_page1"), fixture("ngsiem/parser_list_page2")],
            "get_parser": [fixture("ngsiem/parser_get_extension")],
        },
    )

    result = run_module(ngsiem_parser, {"parser_id": EXTENSION_ID})

    assert result["parser"]["id"] == EXTENSION_ID
    assert service.called("list_parsers") == [
        {"repository": REPO, "limit": 1, "offset": 0},
        {"repository": REPO, "limit": 1, "offset": 1},
    ]


def test_list_stops_at_the_total(falcon_api, fixture, run_module, monkeypatch):
    # The second page is full, but the total says that it is the last one.
    monkeypatch.setattr(ngsiem_parser, "LIST_PAGE_SIZE", 1)
    service = falcon_api(
        ngsiem_parser,
        {"list_parsers": [fixture("ngsiem/parser_list_page1"), fixture("ngsiem/parser_list_page2")]},
    )

    result = run_module(ngsiem_parser, {"parser_id": OTHER_ID})

    assert result["failed"] is True
    assert len(service.called("list_parsers")) == 2


def test_present_by_parser_id_returns_parser(api, run_module):
    service = api(list_parsers=["parser_list_by_name"], get_parser=["parser_get"])

    result = run_module(ngsiem_parser, {"parser_id": PARSER_ID})

    assert result["changed"] is False
    assert result["parser"]["name"] == STORED_NAME
    # A lookup by ID lists the parsers without a filter.
    assert service.called("list_parsers") == [{"repository": REPO, "limit": 500, "offset": 0}]


@pytest.mark.parametrize(
    "parser_id", [PARSER_ID, UNVERSIONED_ID], ids=["earlier-version", "no-version"]
)
def test_present_by_parser_id_finds_latest_version(api, run_module, parser_id):
    # After an update the list shows only the new version.
    service = api(list_parsers=["parser_list_after_update"], get_parser=["parser_get_after_update"])

    result = run_module(ngsiem_parser, {"parser_id": parser_id})

    assert result["changed"] is False
    assert service.called("get_parser") == [{"ids": UPDATED_ID, "repository": REPO}]


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
