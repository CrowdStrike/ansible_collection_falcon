#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: case

short_description: Manage Falcon cases

version_added: "4.15.0"

description:
  - Create and update Falcon cases.
  - The same task creates the case when it is missing and updates it when it is different.
  - The API cannot delete a case. To end the work on a case, set I(status=closed).
  - Closing a case does not change the alerts in it. Use the alerts API to close them.

options:
  id:
    description:
      - The ID of the case to update.
      - The module fails when no case has this ID.
      - With I(id), I(name) is the new name of the case.
    type: str
  name:
    description:
      - The name of the case.
      - Required to create a case.
      - With no I(id), the module finds the case by this exact, case-sensitive name.
        It creates the case when no case has this name, and updates it when one case has it.
        It fails when more than one case has this name; give I(id) in that case.
      - For a name with a single quote or a backslash, the module searches with the
        part of the name before that character, then compares the full names.
        It fails when the name starts with one of these characters; give I(id) in that case.
      - The name search does not see a new case for about 20 seconds.
        A later task in the same play that changes this case should use the I(id)
        from the C(case) return value.
    type: str
  description:
    description:
      - The description of the case.
      - An empty string clears the description.
    type: str
  status:
    description:
      - The status of the case.
      - A new case has the status C(new) when this option is not set.
    type: str
    choices: ["new", "in_progress", "reopened", "closed"]
  severity:
    description:
      - The severity of the case, from 1 to 100.
      - Required to create a case.
    type: int
  assigned_to_user_uuid:
    description:
      - The UUID of the user that the case is assigned to.
      - An empty string removes the assignee.
    type: str
  tags:
    description:
      - The tags of the case.
      - Tags are case sensitive.
      - The module adds the tags that the case does not have.
      - With I(purge_tags=true), the module also removes the tags that are not in this list.
    type: list
    elements: str
  purge_tags:
    description:
      - Remove the tags of the case that are not in I(tags).
      - With I(purge_tags=true) and no I(tags), the module does not change the tags.
    type: bool
    default: false
  alerts:
    description:
      - The composite IDs of the alerts to add to the case as evidence.
      - The module only adds alerts. It does not remove an alert that is not in this list.
    type: list
    elements: str

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

seealso:
  - module: crowdstrike.falcon.case_info
    description: Get information about Falcon cases.
  - module: crowdstrike.falcon.host_contain
    description: Contain or lift containment on Falcon hosts.
  - name: Case Management API reference
    description: The CrowdStrike API operations that this module uses.
    link: https://developer.crowdstrike.com/api-reference/collections/case-management

requirements:
  - Cases [B(READ), B(WRITE)] API scope
  - CrowdStrike FalconPy >= 1.5.5

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Create a case with an alert as evidence
  crowdstrike.falcon.case:
    name: "Phishing investigation"
    description: "Investigate the phishing alerts of the finance team"
    severity: 50
    tags:
      - phishing
    alerts:
      - "0123456789abcdef0123456789abcdef:ind:fedcba9876543210fedcba9876543210-123456789012345"
  register: new_case

- name: Set the status to in_progress and add tags, by ID
  crowdstrike.falcon.case:
    id: "{{ new_case.case.id }}"
    status: in_progress
    tags:
      - finance

- name: Assign the case to a user
  crowdstrike.falcon.case:
    id: "{{ new_case.case.id }}"
    assigned_to_user_uuid: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"

- name: Remove the assignee of the case
  crowdstrike.falcon.case:
    id: "{{ new_case.case.id }}"
    assigned_to_user_uuid: ""

- name: Close the case
  crowdstrike.falcon.case:
    id: "{{ new_case.case.id }}"
    status: closed
"""

RETURN = r"""
case:
  description:
    - The case after the change, read again from the API.
    - In check mode, the current case, or the wanted values with no C(id) when the case does not exist.
  type: dict
  returned: success
  contains:
    id:
      description: The ID of the case.
      type: str
      returned: success
      sample: "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
    name:
      description: The name of the case.
      type: str
      returned: success
      sample: "Phishing investigation"
    description:
      description: The description of the case.
      type: str
      returned: success
      sample: "Investigate the phishing alerts of the finance team"
    status:
      description: The status of the case.
      type: str
      returned: success
      sample: "closed"
    severity:
      description: The severity of the case.
      type: int
      returned: success
      sample: 50
    severity_info:
      description: The severity details of the case.
      type: dict
      returned: success
      contains:
        level:
          description: The severity level of the case.
          type: str
          returned: success
          sample: "Medium"
    version:
      description: The version of the case.
      type: int
      returned: success
      sample: 3
    consistency:
      description: The consistency data of the case.
      type: dict
      returned: success
      contains:
        version:
          description: The consistency version of the case.
          type: int
          returned: success
          sample: 3
        consistent:
          description: Whether the case data is consistent.
          type: bool
          returned: success
          sample: true
    tags:
      description: The tags of the case.
      type: list
      elements: str
      returned: success
      sample: ["malware"]
    assigned_to:
      description: The user that the case is assigned to.
      type: dict
      returned: success
      contains:
        uuid:
          description: The UUID of the user.
          type: str
          returned: success
          sample: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"
        email:
          description: The email address of the user.
          type: str
          returned: success
          sample: "analyst@example.com"
        full_name:
          description: The full name of the user.
          type: str
          returned: success
          sample: "Example Analyst"
    assigned_to_groups:
      description: The user groups that the case is assigned to.
      type: list
      elements: dict
      returned: success
      sample: null
    evidence:
      description:
        - The evidence of the case, by type.
        - Each type has a list of C(records).
      type: dict
      returned: success
    analysis_results:
      description:
        - The analysis results of the case, by type.
        - Each type has a list of C(records).
      type: dict
      returned: success
    cid:
      description: The customer ID that the case belongs to.
      type: str
      returned: success
      sample: "0123456789abcdef0123456789abcdef"
    start_timestamp:
      description: The start time of the case.
      type: str
      returned: success
      sample: null
    created_by:
      description: The user that created the case.
      type: dict
      returned: success
      contains:
        uuid:
          description: The UUID of the user.
          type: str
          returned: success
          sample: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"
        email:
          description: The email address of the user.
          type: str
          returned: success
          sample: "analyst@example.com"
        full_name:
          description: The full name of the user.
          type: str
          returned: success
          sample: "Example Analyst"
    last_updated_by:
      description: The user that last updated the case.
      type: dict
      returned: success
      contains:
        uuid:
          description: The UUID of the user.
          type: str
          returned: success
          sample: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"
        email:
          description: The email address of the user.
          type: str
          returned: success
          sample: "analyst@example.com"
        full_name:
          description: The full name of the user.
          type: str
          returned: success
          sample: "Example Analyst"
    creation_actor:
      description: The actor that created the case.
      type: dict
      returned: success
      contains:
        type:
          description: The type of the actor.
          type: str
          returned: success
          sample: "user"
    update_actor:
      description: The actor that last updated the case.
      type: dict
      returned: success
      contains:
        type:
          description: The type of the actor.
          type: str
          returned: success
          sample: "user"
    created_timestamp:
      description: The time when the case was created.
      type: str
      returned: success
      sample: "2026-11-18T21:43:48Z"
    updated_timestamp:
      description: The time when the case was last updated.
      type: str
      returned: success
      sample: "2026-11-18T21:50:12Z"
    end_timestamp:
      description: The time when the case was closed.
      type: str
      returned: success
      sample: "2026-11-18T22:05:00Z"
    reference_id:
      description: The reference ID of the case.
      type: str
      returned: success
      sample: "CASE-123"
    read_only:
      description: The read-only state of the case.
      type: dict
      returned: success
      contains:
        is_read_only:
          description: Whether the case is read only.
          type: bool
          returned: success
          sample: false
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
    from falconpy import CaseManagement

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# CaseManagement and its methods exist from FalconPy 1.5.5.
MINIMUM_FALCONPY_VERSION = "1.5.5"

# Names are not unique, so ask for several matches and keep the exact ones.
NAME_SEARCH_LIMIT = 100

# The scalar options that the module compares and sends on create and update.
SCALAR_FIELDS = ("name", "description", "status", "severity")

CASE_ARGS = {
    "id": {"type": "str", "required": False},
    "name": {"type": "str", "required": False},
    "description": {"type": "str", "required": False},
    "status": {
        "type": "str",
        "required": False,
        "choices": ["new", "in_progress", "reopened", "closed"],
    },
    "severity": {"type": "int", "required": False},
    "assigned_to_user_uuid": {"type": "str", "required": False},
    "tags": {"type": "list", "elements": "str", "required": False},
    "purge_tags": {"type": "bool", "default": False},
    "alerts": {"type": "list", "elements": "str", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(CASE_ARGS)

    return args


def validate_params(module):
    """Validate module parameters before any API call."""
    for key in ("id", "name"):
        if module.params[key] is not None and not module.params[key]:
            module.fail_json(msg=f"Parameter '{key}' must not be empty")

    severity = module.params["severity"]
    if severity is not None and not 1 <= severity <= 100:
        module.fail_json(msg="Parameter 'severity' must be from 1 to 100")

    for key in ("tags", "alerts"):
        values = module.params[key]
        if values is not None and any(not value for value in values):
            module.fail_json(msg=f"Parameter '{key}' must not contain an empty value")


def check_status(module, result, api_result, action):
    """Fail on an API error, also when the API returns no error message."""
    status_code = api_result["status_code"]
    if status_code in (200, 201):
        return
    handle_return_errors(module, result, api_result)
    # handle_return_errors does not fail when errors is empty or null.
    module.fail_json(msg=f"Unexpected status {status_code} while {action}", **result)


def get_cases(falcon, module, ids, result=None):
    """Return the cases with these IDs. Unknown IDs are left out by the API."""
    query_result = falcon.get_cases(body={"ids": ids})
    check_status(module, result or {}, query_result, "getting cases")
    return query_result["body"].get("resources") or []


def get_by_id(falcon, module, case_id, result=None):
    """Return the case with this ID, or fail when it does not exist."""
    cases = get_cases(falcon, module, [case_id], result)
    if not cases:
        module.fail_json(msg=f"Case not found: {case_id}", **(result or {}))
    return cases[0]


def name_filter(module, name):
    """Return the FQL filter that finds the cases with this name.

    An exact name:'x' filter finds no case whose name holds a single quote
    or a backslash, also when they are escaped. For such a name, search with
    the part before the first of them as a prefix. find_by_name compares the
    names in Python.
    """
    special = [i for i in (name.find("'"), name.find("\\")) if i >= 0]
    if not special:
        return f"name:'{name}'"
    prefix = name[:min(special)]
    if not prefix:
        module.fail_json(
            msg=(
                "The case API cannot search for a name that starts with a single quote "
                "or a backslash. Use 'id' to choose the case."
            )
        )
    return f"name:*'{prefix}*'"


def search_pages(falcon, module, fql):
    """Yield the case IDs that the filter finds, one page at a time."""
    offset = 0
    while True:
        query_result = falcon.query_case_ids(filter=fql, limit=NAME_SEARCH_LIMIT, offset=offset)
        check_status(module, {}, query_result, "searching for cases")
        body = query_result["body"]
        page = body.get("resources") or []
        if page:
            yield page
        offset += len(page)
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)
        if not page or offset >= total:
            return


def find_by_name(falcon, module, name):
    """Return the case with exactly this name, or None.

    A prefix search (for a name with a quote or a backslash) can find many
    cases, so the pages are read one at a time, and the search stops at the
    second exact match.
    """
    matches = []
    for ids in search_pages(falcon, module, name_filter(module, name)):
        matches.extend(c for c in get_cases(falcon, module, ids) if c.get("name") == name)
        if len(matches) > 1:
            module.fail_json(
                msg=(
                    f"More than one case has the name '{name}', for example "
                    f"{', '.join(c['id'] for c in matches)}. Use 'id' to choose the case."
                )
            )
    return matches[0] if matches else None


def case_alert_ids(case):
    """Return the alert IDs in the evidence of the case."""
    records = ((case.get("evidence") or {}).get("alerts") or {}).get("records") or []
    return [
        (record.get("selector") or {}).get("id")
        for record in records
        if (record.get("selector") or {}).get("id")
    ]


def case_state(case):
    """Return the compared fields of a case, for the diff."""
    return {
        "name": case.get("name"),
        "description": case.get("description"),
        "status": case.get("status"),
        "severity": case.get("severity"),
        "assigned_to_user_uuid": (case.get("assigned_to") or {}).get("uuid") or "",
        "tags": sorted(case.get("tags") or []),
        "alerts": sorted(case_alert_ids(case)),
    }


def plan_changes(module, current):
    """Return the field changes, the tags to add and remove, and the alerts to add."""
    params = module.params
    before = case_state(current)

    fields = {
        key: params[key]
        for key in SCALAR_FIELDS
        if params[key] is not None and params[key] != before[key]
    }

    assignee = params["assigned_to_user_uuid"]
    if assignee is not None and assignee.lower() != before["assigned_to_user_uuid"].lower():
        if assignee:
            fields["assigned_to_user_uuid"] = assignee
        else:
            fields["remove_user_assignment"] = True

    tags = params["tags"]
    current_tags = set(before["tags"])
    add_tags = [] if tags is None else [t for t in dict.fromkeys(tags) if t not in current_tags]
    remove_tags = []
    if tags is not None and params["purge_tags"]:
        remove_tags = sorted(current_tags - set(tags))

    current_alerts = set(before["alerts"])
    add_alerts = [a for a in dict.fromkeys(params["alerts"] or []) if a not in current_alerts]

    return fields, add_tags, remove_tags, add_alerts


def predicted_state(before, fields, add_tags, remove_tags, add_alerts):
    """Return the compared fields after the planned changes, for the diff."""
    after = dict(before)
    for key in SCALAR_FIELDS:
        if key in fields:
            after[key] = fields[key]
    if "assigned_to_user_uuid" in fields:
        after["assigned_to_user_uuid"] = fields["assigned_to_user_uuid"]
    if fields.get("remove_user_assignment"):
        after["assigned_to_user_uuid"] = ""
    after["tags"] = sorted((set(before["tags"]) | set(add_tags)) - set(remove_tags))
    after["alerts"] = sorted(set(before["alerts"]) | set(add_alerts))
    return after


def create_body(module):
    """Return the create_case body from the options that the user set."""
    params = module.params
    body = {key: params[key] for key in SCALAR_FIELDS if params[key] is not None}
    if params["assigned_to_user_uuid"]:
        body["assigned_to_user_uuid"] = params["assigned_to_user_uuid"]
    if params["tags"]:
        body["tags"] = list(dict.fromkeys(params["tags"]))
    if params["alerts"]:
        body["evidence"] = {
            "alerts": [{"id": alert_id} for alert_id in dict.fromkeys(params["alerts"])]
        }
    return body


def handle_create(falcon, module, result):
    """Create the case."""
    # The API refuses a new case with no severity (400, value out of range).
    if module.params["severity"] is None:
        module.fail_json(msg="Parameter 'severity' is required to create a case", **result)
    body = create_body(module)
    result["changed"] = True
    after = {key: body.get(key) for key in SCALAR_FIELDS}
    after["status"] = body.get("status", "new")
    after["assigned_to_user_uuid"] = body.get("assigned_to_user_uuid", "")
    after["tags"] = sorted(body.get("tags", []))
    after["alerts"] = sorted(a["id"] for a in body.get("evidence", {}).get("alerts", []))
    result["diff"] = {"before": {}, "after": after}

    if module.check_mode:
        result["case"] = body
        return

    create_result = falcon.create_case(body=body)
    check_status(module, result, create_result, "creating the case")
    # Keep the created case in the result, so a failed read still gives its ID.
    result["case"] = create_result["body"]["resources"][0]
    result["case"] = get_by_id(falcon, module, result["case"]["id"], result)


def apply_changes(falcon, module, result, current, changes):
    """Make the write calls: fields, then tags, then alerts."""
    fields, add_tags, remove_tags, add_alerts = changes
    case_id = current["id"]

    if fields:
        update_result = falcon.update_case_fields(
            body={
                "id": case_id,
                "expected_version": current.get("version"),
                "fields": fields,
            }
        )
        if update_result["status_code"] == 404:
            module.fail_json(msg=f"Case not found: {case_id}", **result)
        if update_result["status_code"] == 409:
            module.fail_json(
                msg="The case changed since the module read it; run again", **result
            )
        check_status(module, result, update_result, "updating the case")

    if add_tags:
        tags_result = falcon.add_case_tags(body={"id": case_id, "tags": add_tags})
        check_status(module, result, tags_result, "adding tags to the case")

    for tag in remove_tags:
        tag_result = falcon.delete_case_tags(id=case_id, tag=tag)
        check_status(module, result, tag_result, "removing a tag from the case")

    if add_alerts:
        alerts_result = falcon.add_case_alert_evidence(
            body={"id": case_id, "alerts": [{"id": alert_id} for alert_id in add_alerts]}
        )
        check_status(module, result, alerts_result, "adding alerts to the case")


def handle_update(falcon, module, result, current):
    """Update the values of the case that differ."""
    changes = plan_changes(module, current)
    result["case"] = current
    if not any(changes):
        return

    before = case_state(current)
    result["changed"] = True
    result["diff"] = {"before": before, "after": predicted_state(before, *changes)}
    if module.check_mode:
        return

    apply_changes(falcon, module, result, current, changes)
    # Read again: the write responses do not hold the whole case.
    result["case"] = get_by_id(falcon, module, current["id"], result)


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        required_one_of=[("id", "name")],
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module, minimum_version=MINIMUM_FALCONPY_VERSION)
    validate_params(module)

    result = dict(changed=False)
    falcon = authenticate(module, CaseManagement)

    try:
        case_id = module.params["id"]
        if case_id:
            current = get_by_id(falcon, module, case_id)
        else:
            current = find_by_name(falcon, module, module.params["name"])

        if current is None:
            handle_create(falcon, module, result)
        else:
            handle_update(falcon, module, result, current)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while managing the case: {str(e)}",
            **result,
        )

    if not module._diff:  # pylint: disable=protected-access
        result.pop("diff", None)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
