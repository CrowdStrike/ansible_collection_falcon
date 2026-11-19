# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.module_utils import falconpy_utils
from ansible_collections.crowdstrike.falcon.plugins.modules import case

# The cases that record_case_write() made, and the fake IDs that the Sanitizer gave them.
NAME = "ansible-dev-case-unit-20261119104803"
NAME_FILTER = "name:'%s'" % NAME
CASE_ID = "00000000-0000-0000-0000-000000000001"
DUP_ID = "00000000-0000-0000-0000-000000000002"
MISSING_ID = "00000000-0000-0000-0000-000000000000"
ALERT_ID = "fixture-cid:cwpp:fixture-aid:fixture-alert-1"
USER_UUID = "00000000-0000-0000-0000-0000000000aa"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches case with recorded responses."""

    def make(**responses):
        return falcon_api(
            case,
            {
                method: [
                    item if isinstance(item, (dict, Exception)) else fixture("case_write/" + item)
                    for item in items
                ]
                for method, items in responses.items()
            },
        )

    return make


def search(fql=None, offset=0):
    return ("query_case_ids", {"filter": fql or NAME_FILTER, "limit": 100, "offset": offset})


def get(*ids):
    return ("get_cases", {"body": {"ids": list(ids)}})


def update(fields, version, case_id=CASE_ID):
    return ("update_case_fields", {"body": {"id": case_id, "expected_version": version, "fields": fields}})


# Argument validation (no call)


@pytest.mark.parametrize(
    "args, msg",
    [
        ({"name": NAME, "severity": 0}, "Parameter 'severity' must be from 1 to 100"),
        ({"name": NAME, "severity": 101}, "Parameter 'severity' must be from 1 to 100"),
        ({"name": NAME, "tags": ["a", ""]}, "Parameter 'tags' must not contain an empty value"),
        ({"name": NAME, "alerts": [""]}, "Parameter 'alerts' must not contain an empty value"),
        ({"description": "x"}, "one of the following is required: id, name"),
        ({"id": ""}, "Parameter 'id' must not be empty"),
        ({"name": "", "severity": 30}, "Parameter 'name' must not be empty"),
    ],
)
def test_invalid_args_fail_before_any_call(api, run_module, args, msg):
    service = api()

    result = run_module(case, args)

    assert result["failed"] is True
    assert result["msg"] == msg
    assert service.calls == []


def test_falconpy_below_1_5_5_fails(api, run_module, monkeypatch):
    monkeypatch.setattr(falconpy_utils, "_VERSION", "1.5.4")
    service = api()

    result = run_module(case, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"] == "Unsupported FalconPy version: 1.5.4. Upgrade to 1.5.5 or higher."
    assert service.calls == []


# Create


def test_create_with_tags_and_alerts(api, run_module):
    service = api(query_case_ids=["query_name_none"], create_case=["create"], get_cases=["get_created"])

    result = run_module(case, {
        "name": NAME, "description": "Unit fixture case", "severity": 30,
        "tags": ["ansible-dev-t1", "ansible-dev-t1"], "alerts": [ALERT_ID], "_ansible_diff": True,
    })

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is True
    assert result["case"]["id"] == CASE_ID
    assert service.calls == [
        search(),
        ("create_case", {"body": {
            "name": NAME, "description": "Unit fixture case", "severity": 30,
            "tags": ["ansible-dev-t1"], "evidence": {"alerts": [{"id": ALERT_ID}]},
        }}),
        get(CASE_ID),
    ]
    assert result["diff"] == {"before": {}, "after": {
        "name": NAME, "description": "Unit fixture case", "status": "new", "severity": 30,
        "assigned_to_user_uuid": "", "tags": ["ansible-dev-t1"], "alerts": [ALERT_ID],
    }}


def test_create_without_tags_or_alerts(api, run_module):
    service = api(query_case_ids=["query_name_none"], create_case=["create_plain"], get_cases=["get_plain"])

    result = run_module(case, {"name": NAME, "description": "Unit fixture case", "severity": 30})

    assert result["changed"] is True
    assert result["case"]["id"] == DUP_ID
    assert "diff" not in result
    assert service.calls == [
        search(),
        ("create_case", {"body": {"name": NAME, "description": "Unit fixture case", "severity": 30}}),
        get(DUP_ID),
    ]


def test_create_without_severity_fails_before_the_create(api, run_module):
    """The API gives 400 for a new case with no severity, so the module fails first."""
    service = api(query_case_ids=["query_name_none"])

    result = run_module(case, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'severity' is required to create a case"
    assert service.calls == [search()]


def test_create_check_mode_makes_no_write(api, run_module):
    service = api(query_case_ids=["query_name_none"])

    result = run_module(case, {"name": NAME, "severity": 30}, check_mode=True)

    assert result["changed"] is True
    assert result["case"] == {"name": NAME, "severity": 30}
    assert service.calls == [search()]


@pytest.mark.parametrize(
    "name, fql",
    [
        ("it's a case", "name:*'it*'"),
        ("a \\ b 'c'", "name:*'a *'"),
    ],
)
def test_name_with_quote_or_backslash_searches_with_a_prefix(api, run_module, name, fql):
    """An exact name filter finds no name with ' or \\ (record row 51), so use the prefix."""
    service = api(query_case_ids=["query_name_none"])

    result = run_module(case, {"name": name, "severity": 30}, check_mode=True)

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is True
    assert result["case"]["name"] == name
    assert service.calls == [search(fql)]


@pytest.mark.parametrize("name", ["'quoted'", "\\path"])
def test_name_that_starts_with_quote_or_backslash_fails(api, run_module, name):
    service = api()

    result = run_module(case, {"name": name, "severity": 30})

    assert result["failed"] is True
    assert "Use 'id' to choose the case" in result["msg"]
    assert service.calls == []


def pages_of(fixture, query, read):
    """Split a recorded search and its read into two pages of one case each.

    Built from the recorded query_name_two and get_two responses (two cases
    with the same name, total 2): page 1 and read 1 hold the first case,
    page 2 and read 2 the second.
    """
    two = fixture("case_write/" + query)
    both = fixture("case_write/" + read)
    pages, reads = [], []
    for n in (0, 1):
        page = copy.deepcopy(two)
        page.pop("method")
        page["body"]["resources"] = two["body"]["resources"][n:n + 1]
        pages.append(page)
        found = copy.deepcopy(both)
        found.pop("method")
        # Each read returns the case of its own page.
        found["body"]["resources"] = [
            c for c in both["body"]["resources"] if c["id"] == two["body"]["resources"][n]
        ]
        reads.append(found)
    return pages, reads, two["body"]["resources"]


def test_prefix_search_reads_every_page_and_compares_names(api, fixture, run_module):
    """No case has the exact name, so the module reads both pages and plans a create."""
    pages, reads, ids = pages_of(fixture, "query_name_two", "get_two")
    service = api(query_case_ids=pages, get_cases=reads)
    prefix_name = NAME + "-x'y"

    result = run_module(case, {"name": prefix_name, "severity": 30}, check_mode=True)

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is True
    assert "id" not in result["case"]
    fql = "name:*'%s*'" % (NAME + "-x")
    assert service.calls == [search(fql), get(ids[0]), search(fql, offset=1), get(ids[1])]


def test_name_search_stops_at_the_second_exact_match(api, fixture, run_module):
    """Two exact matches on pages 1 and 2 of a search with a total of 3.

    The total of each page is set to 3, so a module that does not stop
    would ask for page 3; the fake service has no third response.
    """
    pages, reads, ids = pages_of(fixture, "query_name_two", "get_two")
    for page in pages:
        page["body"]["meta"]["pagination"]["total"] = 3
    service = api(query_case_ids=pages, get_cases=reads)

    result = run_module(case, {"name": NAME, "severity": 30})

    assert result["failed"] is True
    assert result["msg"] == (
        "More than one case has the name '%s', for example %s, %s. Use 'id' to choose the case."
        % (NAME, ids[0], ids[1])
    )
    assert service.calls == [search(), get(ids[0]), search(offset=1), get(ids[1])]


def test_failed_read_after_create_keeps_changed_and_the_case(api, fixture, run_module):
    """The read after the create fails: the case exists, so changed and its ID stay."""
    error = copy.deepcopy(fixture("case_write/get_created"))
    error.pop("method", None)
    error["status_code"] = 500
    error["body"]["resources"] = []
    error["body"]["errors"] = [{"code": 500, "message": "Internal Server Error"}]
    api(query_case_ids=["query_name_none"], create_case=["create"], get_cases=[error])

    result = run_module(case, {"name": NAME, "severity": 30})

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["case"]["id"] == CASE_ID


# Find


def test_duplicate_name_fails_and_lists_ids(api, run_module):
    service = api(query_case_ids=["query_name_two"], get_cases=["get_two"])

    result = run_module(case, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"] == (
        "More than one case has the name '%s', for example %s, %s. Use 'id' to choose the case."
        % (NAME, CASE_ID, DUP_ID)
    )
    assert service.calls == [search(), get(DUP_ID, CASE_ID)]


def test_unknown_id_fails_before_any_write(api, run_module):
    service = api(get_cases=["get_missing"])

    result = run_module(case, {"id": MISSING_ID, "severity": 60})

    assert result["failed"] is True
    assert result["msg"] == "Case not found: %s" % MISSING_ID
    assert service.calls == [get(MISSING_ID)]


# Update


def test_update_no_change_makes_no_write(api, run_module):
    service = api(query_case_ids=["query_name_one"], get_cases=["get_created"])

    result = run_module(case, {
        "name": NAME, "description": "Unit fixture case", "severity": 30,
        "tags": ["ansible-dev-t1"], "alerts": [ALERT_ID], "assigned_to_user_uuid": "", "_ansible_diff": True,
    })

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is False
    assert "diff" not in result
    assert service.calls == [search(), get(CASE_ID)]


def test_update_one_field(api, run_module):
    service = api(
        query_case_ids=["query_name_one"], get_cases=["get_created", "get_after_description"],
        update_case_fields=["update_description"],
    )

    result = run_module(case, {"name": NAME, "description": "Unit fixture case updated", "_ansible_diff": True})

    assert result["changed"] is True
    assert result["case"]["description"] == "Unit fixture case updated"
    assert service.calls == [
        search(), get(CASE_ID), update({"description": "Unit fixture case updated"}, 1), get(CASE_ID),
    ]
    assert result["diff"]["before"]["description"] == "Unit fixture case"
    assert result["diff"]["after"]["description"] == "Unit fixture case updated"


def test_update_several_fields_by_id(api, run_module):
    service = api(get_cases=["get_after_description", "get_after_several"], update_case_fields=["update_several"])

    result = run_module(case, {"id": CASE_ID, "status": "in_progress", "severity": 50})

    assert result["changed"] is True
    assert service.calls == [
        get(CASE_ID), update({"status": "in_progress", "severity": 50}, 2), get(CASE_ID),
    ]


def test_update_close(api, run_module):
    service = api(get_cases=["get_two", "get_after_close"], update_case_fields=["update_close"])

    result = run_module(case, {"id": CASE_ID, "status": "closed"})

    assert result["case"]["status"] == "closed"
    assert service.calls == [get(CASE_ID), update({"status": "closed"}, 6), get(CASE_ID)]


def test_id_and_name_renames(api, run_module):
    service = api(get_cases=["get_created", "get_created"], update_case_fields=["update_description"])

    result = run_module(case, {"id": CASE_ID, "name": "renamed"})

    assert result["changed"] is True
    assert service.calls == [get(CASE_ID), update({"name": "renamed"}, 1), get(CASE_ID)]


def test_update_conflict_fails(api, run_module):
    service = api(get_cases=["get_created"], update_case_fields=["update_conflict"])

    result = run_module(case, {"id": CASE_ID, "severity": 60})

    assert result["failed"] is True
    assert result["msg"] == "The case changed since the module read it; run again"
    assert service.calls == [get(CASE_ID), update({"severity": 60}, 1)]


def test_update_not_found_fails(api, run_module):
    """get_cases found the case, then it was gone: a 404 from the PATCH."""
    service = api(get_cases=["get_created"], update_case_fields=["update_missing"])

    result = run_module(case, {"id": CASE_ID, "severity": 60})

    assert result["failed"] is True
    assert result["msg"] == "Case not found: %s" % CASE_ID
    assert service.calls == [get(CASE_ID), update({"severity": 60}, 1)]


def test_unknown_assignee_fails_with_api_error(api, run_module):
    service = api(get_cases=["get_after_unassign"], update_case_fields=["update_bad_assignee"])

    result = run_module(case, {"id": CASE_ID, "assigned_to_user_uuid": MISSING_ID})

    assert result["failed"] is True
    assert result["msg"] == 'resolve assignee "00000000-0000-0000-0000-000000000000": invalid user ID'
    assert service.calls == [get(CASE_ID), update({"assigned_to_user_uuid": MISSING_ID}, 6)]


def assigned(fixture):
    """Return get_after_unassign with an assignee.

    The recorder sets no real assignee, because the user would get an email.
    """
    response = copy.deepcopy(fixture("case_write/get_after_unassign"))
    response["body"]["resources"][0]["assigned_to"] = {"uuid": USER_UUID, "email": "user1@example.com"}
    return response


def test_remove_assignee(api, fixture, run_module):
    service = api(get_cases=[assigned(fixture), "get_after_unassign"], update_case_fields=["update_unassign"])

    result = run_module(case, {"id": CASE_ID, "assigned_to_user_uuid": ""})

    assert result["changed"] is True
    assert service.calls == [get(CASE_ID), update({"remove_user_assignment": True}, 6), get(CASE_ID)]


def test_set_assignee(api, fixture, run_module):
    service = api(get_cases=["get_after_unassign", assigned(fixture)], update_case_fields=["update_unassign"])

    result = run_module(case, {"id": CASE_ID, "assigned_to_user_uuid": USER_UUID})

    assert result["changed"] is True
    assert service.calls == [get(CASE_ID), update({"assigned_to_user_uuid": USER_UUID}, 6), get(CASE_ID)]


def test_same_assignee_in_upper_case_makes_no_write(api, fixture, run_module):
    service = api(get_cases=[assigned(fixture)])

    result = run_module(case, {"id": CASE_ID, "assigned_to_user_uuid": USER_UUID.upper()})

    assert result["changed"] is False
    assert service.calls == [get(CASE_ID)]


# Tags and alerts


def test_add_only_missing_tags(api, run_module):
    service = api(
        get_cases=["get_after_several", "get_after_add_tags"],
        add_case_tags=["add_tags"],
    )

    result = run_module(case, {"id": CASE_ID, "tags": ["ansible-dev-t1", "ansible-dev-t2"]})

    assert result["changed"] is True
    assert service.calls == [
        get(CASE_ID), ("add_case_tags", {"body": {"id": CASE_ID, "tags": ["ansible-dev-t2"]}}), get(CASE_ID),
    ]


def test_purge_tags_removes_only_extra_tags(api, run_module):
    service = api(
        get_cases=["get_after_add_tags", "get_after_delete_tag"],
        delete_case_tags=["delete_tag"],
    )

    result = run_module(case, {"id": CASE_ID, "tags": ["ansible-dev-t2"], "purge_tags": True, "_ansible_diff": True})

    assert result["changed"] is True
    assert service.calls == [
        get(CASE_ID), ("delete_case_tags", {"id": CASE_ID, "tag": "ansible-dev-t1"}), get(CASE_ID),
    ]
    assert result["diff"]["before"]["tags"] == ["ansible-dev-t1", "ansible-dev-t2"]
    assert result["diff"]["after"]["tags"] == ["ansible-dev-t2"]


def test_tags_without_purge_keep_extra_tags(api, run_module):
    service = api(get_cases=["get_after_add_tags"])

    result = run_module(case, {"id": CASE_ID, "tags": ["ansible-dev-t2"]})

    assert result["changed"] is False
    assert service.calls == [get(CASE_ID)]


def test_add_only_missing_alerts(api, run_module):
    service = api(get_cases=["get_plain", "get_after_add_alerts"], add_case_alert_evidence=["add_alerts"])

    result = run_module(case, {"id": DUP_ID, "alerts": [ALERT_ID, ALERT_ID]})

    assert result["changed"] is True
    assert service.calls == [
        get(DUP_ID),
        ("add_case_alert_evidence", {"body": {"id": DUP_ID, "alerts": [{"id": ALERT_ID}]}}),
        get(DUP_ID),
    ]


def test_alert_in_case_makes_no_write(api, run_module):
    service = api(get_cases=["get_after_add_alerts"])

    result = run_module(case, {"id": DUP_ID, "alerts": [ALERT_ID]})

    assert result["changed"] is False
    assert service.calls == [get(DUP_ID)]


# Check mode and order of writes


def test_update_check_mode_reads_only(api, run_module):
    service = api(query_case_ids=["query_name_one"], get_cases=["get_created"])

    result = run_module(
        case,
        {"name": NAME, "severity": 50, "tags": ["ansible-dev-t2"], "purge_tags": True, "_ansible_diff": True},
        check_mode=True,
    )

    assert result["changed"] is True
    assert service.calls == [search(), get(CASE_ID)]
    assert result["diff"]["after"]["severity"] == 50
    assert result["diff"]["after"]["tags"] == ["ansible-dev-t2"]


def test_update_writes_fields_then_tags_then_alerts(api, run_module):
    service = api(
        get_cases=["get_plain", "get_after_add_alerts"], update_case_fields=["update_description"],
        add_case_tags=["add_tags"], add_case_alert_evidence=["add_alerts"],
    )

    result = run_module(case, {"id": DUP_ID, "severity": 40, "tags": ["t"], "alerts": [ALERT_ID]})

    assert result["changed"] is True
    assert [method for method, _kwargs in service.calls] == [
        "get_cases", "update_case_fields", "add_case_tags", "add_case_alert_evidence", "get_cases",
    ]
    assert service.calls[1] == update({"severity": 40}, 1, DUP_ID)
