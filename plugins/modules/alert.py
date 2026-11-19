#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: alert

short_description: Update Falcon alerts

version_added: "4.15.0"

description:
  - Update the status, resolution, tags, assignee, visibility and comments
    of existing Falcon alerts.
  - Alerts cannot be created or deleted with the API, so this module has no
    I(state) option.
  - The module reads the alerts first and changes only the values that are
    different. A second run with the same options makes no change.
  - When one of the composite IDs does not exist, the module fails before it
    changes any alert.

options:
  composite_ids:
    description:
      - The composite IDs of the alerts to update, in the form
        C(<cid>:<product>:<...>). This is the C(composite_id) key of an alert,
        not its C(id) key.
      - A repeated ID is used once.
      - An empty list changes nothing.
    type: list
    elements: str
    required: true
  status:
    description:
      - The status of the alerts.
    type: str
    choices: ["new", "in_progress", "reopened", "closed"]
  resolution:
    description:
      - The resolution of the alerts.
      - The API stores the resolution as the tag of the same name, so the
        resolution is also in the C(tags) of the alert.
      - An alert has one resolution at a time. A new resolution replaces the
        one that the alert has.
      - C(none) removes the resolution of the alert.
    type: str
    choices: ["true_positive", "false_positive", "ignored", "none"]
  tags:
    description:
      - The tags that the alerts must have.
      - Tags are case-sensitive.
      - The values C(true_positive), C(false_positive) and C(ignored) are
        resolutions. Use I(resolution) to set them.
    type: list
    elements: str
  purge_tags:
    description:
      - Remove the tags of the alerts that are not in I(tags).
      - The resolution tag of an alert is never removed. Use I(resolution=none)
        to remove it.
      - Requires I(tags).
    type: bool
    default: false
  assigned_to_uuid:
    description:
      - The UUID of the user to assign the alerts to.
      - An empty string unassigns the alerts.
      - Mutually exclusive with I(assigned_to_user_id).
    type: str
  assigned_to_user_id:
    description:
      - The user ID (the email address) of the user to assign the alerts to.
      - This is compared with the C(assigned_to_uid) key of an alert.
      - An empty string unassigns the alerts.
      - Mutually exclusive with I(assigned_to_uuid).
    type: str
  show_in_ui:
    description:
      - Whether the alerts are shown in the Falcon console.
    type: bool
  comment:
    description:
      - A comment to add to the alerts.
      - The comment is added only to the alerts that have no comment with
        exactly this text, so a second run adds no comment.
      - Comments cannot be changed or removed.
    type: str

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth
  - ansible.builtin.action_common_attributes

attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all

notes:
  - At least one of I(status), I(resolution), I(tags), I(assigned_to_uuid),
    I(assigned_to_user_id), I(show_in_ui) or I(comment) is required.

seealso:
  - module: crowdstrike.falcon.alert_info
  - name: Alerts API reference
    description: The CrowdStrike API operations that this module uses.
    link: https://developer.crowdstrike.com/api-reference/collections/alerts

requirements:
  - Alerts [B(READ), B(WRITE)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Close an alert as a false positive with a comment
  crowdstrike.falcon.alert:
    composite_ids:
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    status: closed
    resolution: false_positive
    comment: "Known admin tool, closed after review"

- name: Set alerts in progress and assign them by user ID
  crowdstrike.falcon.alert:
    composite_ids:
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-987654321"
    status: in_progress
    assigned_to_user_id: "user@example.com"

- name: Add tags to an alert
  crowdstrike.falcon.alert:
    composite_ids:
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    tags:
      - triage
      - team-a

- name: Unassign an alert
  crowdstrike.falcon.alert:
    composite_ids:
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    assigned_to_uuid: ""

- name: Find the new low severity alerts
  crowdstrike.falcon.alert_info:
    filter: "status:'new'+severity:<30"
  register: low_alerts

- name: Close the alerts that were found
  crowdstrike.falcon.alert:
    composite_ids: "{{ low_alerts.alerts | map(attribute='composite_id') | list }}"
    status: closed
    resolution: ignored

- name: Hide an alert in the Falcon console
  crowdstrike.falcon.alert:
    composite_ids:
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    show_in_ui: false
"""

RETURN = r"""
alerts:
  description:
    - The alerts, in the order of I(composite_ids).
    - After a change, the alerts are read again from the API. In check mode
      and when nothing changed, these are the alerts as read before.
    - Each alert has all the keys that M(crowdstrike.falcon.alert_info)
      returns. The keys that this module compares are listed here.
    - With diff mode, the diff has C(before) and C(after) dicts keyed by
      composite ID, with the compared keys only.
  type: list
  elements: dict
  returned: success
  contains:
    composite_id:
      description: The composite ID of the alert.
      type: str
      returned: success
      sample: "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    status:
      description: The status of the alert.
      type: str
      returned: success
      sample: "closed"
    resolution:
      description: The resolution of the alert.
      type: str
      returned: when the alert has a resolution tag
      sample: "false_positive"
    tags:
      description: The tags of the alert, with the resolution tag.
      type: list
      elements: str
      returned: when the alert has tags
      sample: ["false_positive", "triage"]
    assigned_to_uuid:
      description: The UUID of the user that the alert is assigned to.
      type: str
      returned: when the alert is assigned
      sample: "12345678-90ab-cdef-1234-567890abcdef"
    assigned_to_uid:
      description: The user ID of the user that the alert is assigned to.
      type: str
      returned: when the alert is assigned
      sample: "user@example.com"
    assigned_to_name:
      description: The name of the user that the alert is assigned to.
      type: str
      returned: when the alert is assigned
      sample: "Example User"
    show_in_ui:
      description: Whether the alert is shown in the Falcon console.
      type: bool
      returned: success
      sample: true
    comments:
      description: The comments of the alert.
      type: list
      elements: dict
      returned: when the alert has a comment
      contains:
        falcon_user_id:
          description: The ID of the user or API client that added the comment.
          type: str
          returned: success
          sample: "12345678-90ab-cdef-1234-567890abcdef"
        timestamp:
          description: The time when the comment was added.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        value:
          description: The text of the comment.
          type: str
          returned: success
          sample: "Known admin tool, closed after review"
    updated_timestamp:
      description: The time when the alert was last changed.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
    handle_return_errors,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Alerts

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# The largest number of composite IDs that one request accepts.
MAX_IDS = 1000

# The API stores a resolution as the tag of the same name.
RESOLUTION_TAGS = ("true_positive", "false_positive", "ignored")

CHANGE_OPTIONS = (
    "status",
    "resolution",
    "tags",
    "assigned_to_uuid",
    "assigned_to_user_id",
    "show_in_ui",
    "comment",
)

ALERT_ARGS = {
    "composite_ids": {"type": "list", "elements": "str", "required": True},
    "status": {
        "type": "str",
        "choices": ["new", "in_progress", "reopened", "closed"],
        "required": False,
    },
    "resolution": {
        "type": "str",
        "choices": list(RESOLUTION_TAGS) + ["none"],
        "required": False,
    },
    "tags": {"type": "list", "elements": "str", "required": False},
    "purge_tags": {"type": "bool", "default": False, "required": False},
    "assigned_to_uuid": {"type": "str", "required": False},
    "assigned_to_user_id": {"type": "str", "required": False},
    "show_in_ui": {"type": "bool", "required": False},
    "comment": {"type": "str", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(ALERT_ARGS)

    return args


def validate_params(module):
    """Validate module parameters before any API call."""
    if any(not object_id for object_id in module.params["composite_ids"]):
        module.fail_json(msg="Parameter 'composite_ids' must not contain an empty ID")

    # required_by would also fail on the default purge_tags=false, so check it here.
    if module.params["purge_tags"] and module.params["tags"] is None:
        module.fail_json(msg="Parameter 'purge_tags' requires 'tags'")

    tags = module.params["tags"] or []
    resolution_tags = [tag for tag in tags if tag in RESOLUTION_TAGS]
    if resolution_tags:
        module.fail_json(
            msg=(
                f"Parameter 'tags' must not contain the resolution "
                f"{', '.join(resolution_tags)}; use the 'resolution' parameter"
            )
        )

    if module.params["comment"] is not None and not module.params["comment"]:
        module.fail_json(msg="Parameter 'comment' must not be empty")


def unique_ids(ids):
    """Return the IDs without repeats, in the order of the list."""
    seen = set()
    result = []
    for object_id in ids:
        if object_id not in seen:
            seen.add(object_id)
            result.append(object_id)

    return result


def fetch_alerts(falcon, ids):
    """Get the alerts by composite ID without failing.

    Return the alerts that exist in the order of ids, the API errors, and the
    first response that failed with a status other than a missing ID, or None.
    """
    found = {}
    errors = []
    failed = None
    for start in range(0, len(ids), MAX_IDS):
        query_result = falcon.get_alerts_v2(composite_ids=ids[start:start + MAX_IDS])
        body = query_result["body"]
        # A missing ID gives 404, and the alerts that exist are in resources.
        for alert in body.get("resources") or []:
            found[alert.get("composite_id")] = alert
        chunk_errors = body.get("errors") or []
        errors.extend(chunk_errors)

        missing_in_chunk = any(
            err.get("code") == 404 and err.get("id") for err in chunk_errors
        )
        if query_result["status_code"] != 200 and not missing_in_chunk and failed is None:
            failed = query_result

    # The API does not keep the order of the IDs, so use the order of the user list.
    return [found[i] for i in ids if i in found], errors, failed


def read_alerts(falcon, module, ids, result):
    """Get the alerts by composite ID and fail when an ID does not exist."""
    alerts, errors, failed = fetch_alerts(falcon, ids)

    if failed is not None:
        result["alerts"] = alerts
        handle_return_errors(module, result, failed)
        # handle_return_errors does not fail when errors is empty or null.
        module.fail_json(
            msg=f"Unexpected status {failed['status_code']} while getting alerts",
            **result,
        )

    other = [err for err in errors if not (err.get("code") == 404 and err.get("id"))]
    if other:
        result["alerts"] = alerts
        result["errors"] = errors
        module.fail_json(msg=other[0].get("message") or "An unknown error occurred.", **result)

    found = {alert.get("composite_id") for alert in alerts}
    reported = {err.get("id") for err in errors}
    missing = [err.get("id") for err in errors if err.get("code") == 404 and err.get("id")]
    # An ID that is neither found nor reported as missing is also not found.
    missing.extend(i for i in ids if i not in found and i not in reported)
    if missing:
        result["alerts"] = alerts
        result["errors"] = errors
        module.fail_json(msg=f"Alert not found: {', '.join(missing)}", **result)

    return alerts


def is_assigned(alert):
    """Return True when the alert has an assignee."""
    return any(
        alert.get(key)
        for key in ("assigned_to_uuid", "assigned_to_uid", "assigned_to_name")
    )


def compare_fields(alert):
    """Return the fields of an alert that the module compares."""
    return {
        "status": alert.get("status"),
        "resolution": alert.get("resolution"),
        "tags": sorted(alert.get("tags") or []),
        "assigned_to_uuid": alert.get("assigned_to_uuid"),
        "assigned_to_uid": alert.get("assigned_to_uid"),
        "assigned_to_name": alert.get("assigned_to_name"),
        "show_in_ui": alert.get("show_in_ui"),
        "comments": [c.get("value") for c in alert.get("comments") or []],
    }


def assignment_actions(params, current, after):
    """Return the assign actions for one alert and update the predicted fields."""
    actions = []
    for option, key, action in (
        ("assigned_to_uuid", "assigned_to_uuid", "assign_to_uuid"),
        ("assigned_to_user_id", "assigned_to_uid", "assign_to_user_id"),
    ):
        wanted = params[option]
        if wanted is None:
            continue
        if wanted == "":
            # An empty assign value gives 400, so unassign instead.
            if is_assigned(current):
                actions.append({"name": "unassign", "value": ""})
                after["assigned_to_uuid"] = None
                after["assigned_to_uid"] = None
                after["assigned_to_name"] = None
        elif current.get(key) != wanted:
            actions.append({"name": action, "value": wanted})
            # The API sets all three assignee fields; the read after the write gives the other two.
            after["assigned_to_uuid"] = None
            after["assigned_to_uid"] = None
            after["assigned_to_name"] = None
            after[key] = wanted

    return actions


def tag_actions(params, current, after):
    """Return the resolution and tag actions for one alert."""
    actions = []
    tags = list(current.get("tags") or [])

    resolution = params["resolution"]
    current_resolution = current.get("resolution")
    if resolution == "none":
        if current_resolution:
            actions.append({"name": "remove_tag", "value": current_resolution})
            tags = [tag for tag in tags if tag != current_resolution]
            after["resolution"] = None
    elif resolution is not None and current_resolution != resolution:
        actions.append({"name": "add_tag", "value": resolution})
        # The API keeps one resolution tag and removes the other one.
        tags = [tag for tag in tags if tag not in RESOLUTION_TAGS] + [resolution]
        after["resolution"] = resolution

    if params["tags"] is not None:
        wanted = unique_ids(params["tags"])
        plain = [tag for tag in tags if tag not in RESOLUTION_TAGS]
        for tag in wanted:
            if tag not in plain:
                actions.append({"name": "add_tag", "value": tag})
                tags.append(tag)
        if params["purge_tags"]:
            for tag in plain:
                if tag not in wanted:
                    actions.append({"name": "remove_tag", "value": tag})
                    tags.remove(tag)

    after["tags"] = sorted(tags)

    return actions


def alert_actions(params, alert):
    """Return the actions that one alert needs, and its predicted fields."""
    after = compare_fields(alert)
    actions = []

    if params["status"] is not None and alert.get("status") != params["status"]:
        actions.append({"name": "update_status", "value": params["status"]})
        after["status"] = params["status"]

    actions.extend(tag_actions(params, alert, after))
    actions.extend(assignment_actions(params, alert, after))

    show_in_ui = params["show_in_ui"]
    if show_in_ui is not None and alert.get("show_in_ui") != show_in_ui:
        # The API accepts only the strings "true" and "false" here.
        actions.append({"name": "show_in_ui", "value": "true" if show_in_ui else "false"})
        after["show_in_ui"] = show_in_ui

    comment = params["comment"]
    if comment is not None and comment not in after["comments"]:
        actions.append({"name": "append_comment", "value": comment})
        after["comments"] = after["comments"] + [comment]

    return actions, after


def group_by_actions(alerts, params):
    """Group the alerts that need the same action list, in order."""
    groups = {}
    predicted = {}
    for alert in alerts:
        actions, after = alert_actions(params, alert)
        predicted[alert["composite_id"]] = after
        if not actions:
            continue
        key = tuple((action["name"], action["value"]) for action in actions)
        groups.setdefault(key, {"actions": actions, "ids": []})
        groups[key]["ids"].append(alert["composite_id"])

    return list(groups.values()), predicted


def write_groups(falcon, module, groups, ids, result):
    """Send one update per group and chunk, and fail with the API error."""
    for group in groups:
        for start in range(0, len(group["ids"]), MAX_IDS):
            query_result = falcon.update_alerts_v3(
                composite_ids=group["ids"][start:start + MAX_IDS],
                action_parameters=group["actions"],
            )
            status_code = query_result["status_code"]
            errors = query_result["body"].get("errors")
            if status_code != 200 or errors:
                result["changed"] = True
                if errors:
                    result["errors"] = errors
                # Return the alerts with the writes that passed. A failed read
                # here must not hide the update error, so it does not fail.
                result["alerts"] = fetch_alerts(falcon, ids)[0]
                handle_return_errors(module, result, query_result)
                # handle_return_errors does not fail when errors is empty or null.
                module.fail_json(
                    msg=f"Unexpected status {status_code} while updating alerts",
                    **result,
                )


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=[("assigned_to_uuid", "assigned_to_user_id")],
        required_one_of=[CHANGE_OPTIONS],
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)

    validate_params(module)

    result = dict(changed=False, alerts=[])

    ids = unique_ids(module.params["composite_ids"])
    if not ids:
        module.exit_json(**result)

    falcon = authenticate(module, Alerts)

    alerts = read_alerts(falcon, module, ids, result)
    groups, predicted = group_by_actions(alerts, module.params)

    if module._diff:  # pylint: disable=protected-access
        result["diff"] = {
            "before": {alert["composite_id"]: compare_fields(alert) for alert in alerts},
            "after": predicted,
        }

    result["alerts"] = alerts
    if not groups:
        module.exit_json(**result)

    result["changed"] = True
    if module.check_mode:
        module.exit_json(**result)

    write_groups(falcon, module, groups, ids, result)

    # The update returns no alerts, so read them again.
    result["alerts"] = read_alerts(falcon, module, ids, result)
    if "diff" in result:
        result["diff"]["after"] = {
            alert["composite_id"]: compare_fields(alert) for alert in result["alerts"]
        }

    module.exit_json(**result)


if __name__ == "__main__":
    main()
