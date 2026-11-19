# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import alert

# The two alerts that record_alert_write() changed, after sanitizing.
CID = "00000000000000000000000000000002"
AID = "00000000000000000000000000000003"
ID_A = CID + ":ind:" + AID + ":1795099186111222947-10304-11423760"
ID_B = CID + ":ind:" + AID + ":1795099196699211637-10303-11427088"
MISSING_ID = CID + ":ind:00000000000000000000000000000004:0-0-0"
TAG = "ansible-unit-fixture-tag"
USER_UUID = "00000000-0000-0000-0000-000000000001"
USER_ID = "user1@example.com"
OLD_COMMENT = "ansible-dev-probe-20261119150817"
NEW_COMMENT = "ansible-unit-fixture-comment-2026.11.19T152941Z"
BOTH = [ID_A, ID_B]


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches alert with recorded responses."""

    def make(**responses):
        return falcon_api(
            alert,
            {
                method: [
                    case if isinstance(case, (dict, Exception)) else fixture("alert_write/" + case)
                    for case in cases
                ]
                for method, cases in responses.items()
            },
        )

    return make


def methods(service):
    return [m for m, _kwargs in service.calls]


def updates(service):
    return service.called("update_alerts_v3")


def write_case(api, run_module, args, update, after, actions, ids=None):
    service = api(get_alerts_v2=["get_before", after], update_alerts_v3=[update])
    result = run_module(alert, dict({"composite_ids": BOTH}, **args))
    assert result["changed"] is True
    assert methods(service) == ["get_alerts_v2", "update_alerts_v3", "get_alerts_v2"]
    assert service.called("get_alerts_v2") == [{"composite_ids": BOTH}, {"composite_ids": BOTH}]
    assert updates(service) == [{"composite_ids": ids or BOTH, "action_parameters": actions}]
    return result


def with_comment(fixture):
    """Return get_after_show_in_ui with NEW_COMMENT on ID_A.

    The read after a comment is a copy of a recorded response with the comment added,
    because a new recording would add a comment that cannot be removed.
    """
    response = copy.deepcopy(fixture("alert_write/get_after_show_in_ui"))
    for item in response["body"]["resources"]:
        if item["composite_id"] == ID_A:
            item["comments"] = item.get("comments", []) + [
                {"falcon_user_id": "00000000000000000000000000000001",
                 "timestamp": "2026-11-19T15:29:42.384003095Z", "value": NEW_COMMENT}]
    return response


def by_id(result):
    return {a["composite_id"]: a for a in result["alerts"]}


# Each compare branch


def test_status_changed(api, run_module):
    result = write_case(
        api, run_module, {"status": "in_progress"}, "update_status", "get_after_status",
        [{"name": "update_status", "value": "in_progress"}],
    )
    assert [a["status"] for a in result["alerts"]] == ["in_progress", "in_progress"]
    # The module keeps the order of the user list.
    assert [a["composite_id"] for a in result["alerts"]] == BOTH


def test_resolution_and_tags_added(api, run_module):
    result = write_case(
        api, run_module, {"resolution": "true_positive", "tags": [TAG, TAG]},
        "update_tags", "get_after_tags",
        [{"name": "add_tag", "value": "true_positive"}, {"name": "add_tag", "value": TAG}],
    )
    assert by_id(result)[ID_A]["resolution"] == "true_positive"


def test_resolution_change_adds_only_new_resolution(api, run_module):
    service = api(get_alerts_v2=["get_after_tags", "get_after_resolution_change"], update_alerts_v3=["update_resolution_change"])
    result = run_module(alert, {"composite_ids": BOTH, "resolution": "false_positive", "tags": [TAG]})
    assert result["changed"] is True
    assert updates(service) == [{"composite_ids": BOTH, "action_parameters": [{"name": "add_tag", "value": "false_positive"}]}]


def test_resolution_none_and_purge_tags_remove(api, run_module):
    service = api(get_alerts_v2=["get_after_resolution_change", "get_after_remove_tags"], update_alerts_v3=["update_remove_tags"])
    result = run_module(alert, {"composite_ids": BOTH, "resolution": "none", "tags": [], "purge_tags": True})
    assert result["changed"] is True
    # Both alerts need the same actions, so one call; the IDs keep the order of the user list.
    assert updates(service) == [{
        "composite_ids": BOTH,
        "action_parameters": [{"name": "remove_tag", "value": "false_positive"}, {"name": "remove_tag", "value": TAG}],
    }]
    assert all(a.get("tags") is None for a in result["alerts"])


def test_tags_without_purge_keep_other_tags(api, run_module):
    service = api(get_alerts_v2=["get_after_tags"])
    result = run_module(alert, {"composite_ids": BOTH, "tags": []})
    assert result["changed"] is False
    assert methods(service) == ["get_alerts_v2"]


def test_assign_by_uuid(api, run_module):
    service = api(get_alerts_v2=["get_after_remove_tags", "get_after_assign_uuid"], update_alerts_v3=["update_assign_uuid"])
    result = run_module(alert, {"composite_ids": BOTH, "assigned_to_uuid": USER_UUID})
    assert result["changed"] is True
    assert updates(service) == [{"composite_ids": BOTH, "action_parameters": [{"name": "assign_to_uuid", "value": USER_UUID}]}]
    assert by_id(result)[ID_A]["assigned_to_uuid"] == USER_UUID


def test_unassign_with_empty_value(api, run_module):
    service = api(get_alerts_v2=["get_after_assign_uuid", "get_after_unassign"], update_alerts_v3=["update_unassign"])
    result = run_module(alert, {"composite_ids": BOTH, "assigned_to_uuid": ""})
    assert result["changed"] is True
    assert updates(service) == [{"composite_ids": BOTH, "action_parameters": [{"name": "unassign", "value": ""}]}]


def test_unassign_when_not_assigned_no_change(api, run_module):
    service = api(get_alerts_v2=["get_before"])
    result = run_module(alert, {"composite_ids": BOTH, "assigned_to_user_id": ""})
    assert result["changed"] is False
    assert methods(service) == ["get_alerts_v2"]


def test_assign_by_user_id(api, run_module):
    service = api(get_alerts_v2=["get_after_unassign", "get_after_assign_user_id"], update_alerts_v3=["update_assign_user_id"])
    result = run_module(alert, {"composite_ids": BOTH, "assigned_to_user_id": USER_ID})
    assert result["changed"] is True
    assert updates(service) == [{"composite_ids": BOTH, "action_parameters": [{"name": "assign_to_user_id", "value": USER_ID}]}]


def test_show_in_ui_sends_string(api, run_module):
    service = api(get_alerts_v2=["get_after_assign_user_id", "get_after_show_in_ui"], update_alerts_v3=["update_show_in_ui"])
    result = run_module(alert, {"composite_ids": BOTH, "show_in_ui": False})
    assert result["changed"] is True
    # The API accepts only the strings "true" and "false".
    assert updates(service) == [{"composite_ids": BOTH, "action_parameters": [{"name": "show_in_ui", "value": "false"}]}]
    assert [a["show_in_ui"] for a in result["alerts"]] == [False, False]


def test_comment_new_only_where_missing(api, run_module):
    # ID_A already has OLD_COMMENT, so only ID_B needs it: the groups differ by alert.
    service = api(get_alerts_v2=["get_before", "get_before"], update_alerts_v3=["update_comment"])
    result = run_module(alert, {"composite_ids": BOTH, "comment": OLD_COMMENT})
    assert result["changed"] is True
    assert updates(service) == [{"composite_ids": [ID_B], "action_parameters": [{"name": "append_comment", "value": OLD_COMMENT}]}]


def test_comment_added(api, run_module, fixture):
    service = api(get_alerts_v2=["get_after_show_in_ui", with_comment(fixture)], update_alerts_v3=["update_comment"])
    result = run_module(alert, {"composite_ids": [ID_A], "comment": NEW_COMMENT})
    assert result["changed"] is True
    assert service.called("get_alerts_v2") == [{"composite_ids": [ID_A]}, {"composite_ids": [ID_A]}]
    assert updates(service) == [{"composite_ids": [ID_A], "action_parameters": [{"name": "append_comment", "value": NEW_COMMENT}]}]
    assert by_id(result)[ID_A]["comments"][-1]["value"] == NEW_COMMENT


def test_comment_already_there_no_change(api, run_module, fixture):
    service = api(get_alerts_v2=[with_comment(fixture)])
    result = run_module(alert, {"composite_ids": [ID_A], "comment": NEW_COMMENT})
    assert result["changed"] is False
    assert methods(service) == ["get_alerts_v2"]


# Groups and chunks


def test_alerts_with_different_actions_get_one_call_each(api, run_module):
    # ID_A has the comment, ID_B does not: two groups.
    service = api(get_alerts_v2=["get_before", "get_before"], update_alerts_v3=["update_status", "update_status"])
    run_module(alert, {"composite_ids": BOTH, "status": "closed", "comment": OLD_COMMENT})
    assert updates(service) == [
        {"composite_ids": [ID_A], "action_parameters": [{"name": "update_status", "value": "closed"}]},
        {"composite_ids": [ID_B], "action_parameters": [
            {"name": "update_status", "value": "closed"}, {"name": "append_comment", "value": OLD_COMMENT}]},
    ]


def test_chunks_over_max_ids(api, run_module, monkeypatch):
    monkeypatch.setattr(alert, "MAX_IDS", 1)
    service = api(
        get_alerts_v2=["get_before", "get_before", "get_after_status", "get_after_status"],
        update_alerts_v3=["update_status", "update_status"],
    )
    result = run_module(alert, {"composite_ids": BOTH, "status": "in_progress"})
    assert result["changed"] is True
    assert service.called("get_alerts_v2") == [{"composite_ids": [ID_A]}, {"composite_ids": [ID_B]}] * 2
    assert updates(service) == [
        {"composite_ids": [ID_A], "action_parameters": [{"name": "update_status", "value": "in_progress"}]},
        {"composite_ids": [ID_B], "action_parameters": [{"name": "update_status", "value": "in_progress"}]},
    ]


# Errors


def test_missing_id_fails_before_any_write(api, run_module):
    service = api(get_alerts_v2=["get_one_missing"])
    result = run_module(alert, {"composite_ids": [ID_A, MISSING_ID], "status": "closed"})
    assert result["failed"] is True
    assert result["msg"] == "Alert not found: " + MISSING_ID
    assert methods(service) == ["get_alerts_v2"]
    assert [a["composite_id"] for a in result["alerts"]] == [ID_A]


def test_patch_error_fails_and_reads_again(api, run_module):
    service = api(get_alerts_v2=["get_before", "get_before"], update_alerts_v3=["update_unknown_uuid"])
    result = run_module(alert, {"composite_ids": BOTH, "assigned_to_uuid": "11111111-2222-3333-4444-555555555555"})
    assert result["failed"] is True
    assert result["msg"] == "bad request"
    assert result["changed"] is True
    assert methods(service) == ["get_alerts_v2", "update_alerts_v3", "get_alerts_v2"]


def test_patch_error_kept_when_read_again_fails(api, run_module, fixture):
    service = api(get_alerts_v2=["get_before", fixture("alerts/get_bad_cid")], update_alerts_v3=["update_unknown_uuid"])
    result = run_module(alert, {"composite_ids": BOTH, "assigned_to_uuid": "11111111-2222-3333-4444-555555555555"})
    assert result["failed"] is True
    assert result["msg"] == "bad request"
    assert result["changed"] is True
    assert result["errors"] == [{"code": 400, "message": "bad request"}]
    assert result["alerts"] == []
    assert methods(service) == ["get_alerts_v2", "update_alerts_v3", "get_alerts_v2"]


def test_read_error_fails_without_update(api, run_module, fixture):
    service = api(get_alerts_v2=[fixture("alerts/get_bad_cid")])
    result = run_module(alert, {"composite_ids": BOTH, "status": "closed"})
    assert result["failed"] is True
    assert result["msg"] == "invalid CID provided"
    assert service.calls == [("get_alerts_v2", {"composite_ids": BOTH})]


def test_read_other_error_with_200_fails(api, run_module, fixture):
    """The tenant gives no 200 with a non-404 error on demand; add one to a recorded read."""
    response = copy.deepcopy(fixture("alert_write/get_before"))
    response["body"]["errors"] = [{"code": 500, "message": "internal error"}]
    service = api(get_alerts_v2=[response])
    result = run_module(alert, {"composite_ids": BOTH, "status": "closed"})
    assert result["failed"] is True
    assert result["msg"] == "internal error"
    assert methods(service) == ["get_alerts_v2"]


def test_read_id_missing_without_404_fails(api, run_module, fixture):
    """The tenant always reports a missing ID with a 404; drop it from a recorded read."""
    response = copy.deepcopy(fixture("alert_write/get_one_missing"))
    response["body"]["errors"] = []
    response["status_code"] = 200
    service = api(get_alerts_v2=[response])
    result = run_module(alert, {"composite_ids": [ID_A, MISSING_ID], "status": "closed"})
    assert result["failed"] is True
    assert result["msg"] == "Alert not found: " + MISSING_ID
    assert methods(service) == ["get_alerts_v2"]


def test_patch_error_without_errors_uses_status(api, run_module, fixture):
    """The tenant always sends errors with a 400; drop them to test the fallback message."""
    response = copy.deepcopy(fixture("alert_write/update_unknown_uuid"))
    response["body"]["errors"] = None
    service = api(get_alerts_v2=["get_before", "get_before"], update_alerts_v3=[response])
    result = run_module(alert, {"composite_ids": BOTH, "status": "closed"})
    assert result["failed"] is True
    assert result["msg"] == "Unexpected status 400 while updating alerts"
    assert len(updates(service)) == 1


# Check mode, idempotence, diff


def test_check_mode_reads_only_and_predicts_change(api, run_module):
    service = api(get_alerts_v2=["get_before"])
    result = run_module(alert, {"composite_ids": BOTH, "status": "in_progress"}, check_mode=True)
    assert result["changed"] is True
    assert methods(service) == ["get_alerts_v2"]


def test_check_mode_no_change(api, run_module):
    service = api(get_alerts_v2=["get_after_status"])
    result = run_module(alert, {"composite_ids": BOTH, "status": "in_progress"}, check_mode=True)
    assert result["changed"] is False
    assert methods(service) == ["get_alerts_v2"]


def test_idempotent_second_run(api, run_module):
    service = api(get_alerts_v2=["get_after_tags"])
    result = run_module(alert, {"composite_ids": BOTH + [ID_A], "status": "in_progress", "resolution": "true_positive", "tags": [TAG]})
    assert result["changed"] is False
    assert service.called("get_alerts_v2") == [{"composite_ids": BOTH}]


def test_diff_before_after(api, run_module):
    api(get_alerts_v2=["get_before", "get_after_status"], update_alerts_v3=["update_status"])
    result = run_module(alert, {"composite_ids": BOTH, "status": "in_progress", "_ansible_diff": True})
    assert result["diff"]["before"][ID_A]["status"] == "new"
    assert result["diff"]["after"][ID_A]["status"] == "in_progress"
    assert result["diff"]["before"][ID_A]["comments"] == [OLD_COMMENT]


def test_diff_check_mode_predicts_after(api, run_module):
    api(get_alerts_v2=["get_before"])
    result = run_module(alert, {"composite_ids": BOTH, "resolution": "ignored", "_ansible_diff": True}, check_mode=True)
    assert result["diff"]["after"][ID_B]["resolution"] == "ignored"
    assert result["diff"]["after"][ID_B]["tags"] == ["ignored"]
    assert result["diff"]["before"][ID_B]["resolution"] is None


def test_diff_check_mode_assign_predicts_all_assignee_fields(api, run_module):
    service = api(get_alerts_v2=["get_after_assign_uuid"])
    result = run_module(
        alert, {"composite_ids": BOTH, "assigned_to_user_id": "other@example.com", "_ansible_diff": True}, check_mode=True,
    )
    assert result["changed"] is True
    assert result["diff"]["before"][ID_A]["assigned_to_uuid"] == USER_UUID
    after = result["diff"]["after"][ID_A]
    assert (after["assigned_to_uid"], after["assigned_to_uuid"], after["assigned_to_name"]) == ("other@example.com", None, None)
    assert methods(service) == ["get_alerts_v2"]


# Argument validation (no API call)


@pytest.mark.parametrize("args, msg", [
    ({"composite_ids": [ID_A, ""], "status": "new"}, "Parameter 'composite_ids' must not contain an empty ID"),
    ({"composite_ids": [ID_A], "tags": ["ignored"]},
     "Parameter 'tags' must not contain the resolution ignored; use the 'resolution' parameter"),
    ({"composite_ids": [ID_A], "status": "new", "purge_tags": True}, "Parameter 'purge_tags' requires 'tags'"),
    ({"composite_ids": [ID_A], "comment": ""}, "Parameter 'comment' must not be empty"),
    ({"composite_ids": [ID_A], "assigned_to_uuid": USER_UUID, "assigned_to_user_id": USER_ID},
     "parameters are mutually exclusive: assigned_to_uuid|assigned_to_user_id"),
    ({"composite_ids": [ID_A]},
     "one of the following is required: status, resolution, tags, assigned_to_uuid, "
     "assigned_to_user_id, show_in_ui, comment"),
])
def test_argument_validation(api, run_module, args, msg):
    service = api()
    result = run_module(alert, args)
    assert result["failed"] is True
    assert result["msg"] == msg
    assert service.calls == []


def test_empty_id_list_makes_no_call(api, run_module):
    service = api()
    result = run_module(alert, {"composite_ids": [], "status": "new"})
    assert result["changed"] is False
    assert result["alerts"] == []
    assert "failed" not in result
    assert service.calls == []
