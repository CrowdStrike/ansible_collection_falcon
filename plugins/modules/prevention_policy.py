#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: prevention_policy

short_description: Manage Falcon prevention policies

version_added: "4.15.0"

description:
  - Create, update, enable, disable and delete Falcon prevention policies.
  - The same task creates the prevention policy when it is missing, updates it when
    it is different, and deletes it with I(state=absent).
  - The module finds a policy by I(policy_id), or by I(name) and I(platform_name).
  - The module does not manage the prevention settings or the IOA rule groups of the policy.

options:
  state:
    description:
      - The desired state of the prevention policy.
      - With I(state=absent), the module disables an enabled policy before it deletes it,
        because the API does not delete an enabled policy.
    type: str
    choices: ["present", "absent"]
    default: present
  name:
    description:
      - The name of the prevention policy.
      - The module finds an existing policy by this exact name on the platform in I(platform_name),
        without regard to case.
      - The module does not change the name of an existing policy. A name that differs
        only in case finds the same policy.
      - Requires I(platform_name).
      - Mutually exclusive with I(policy_id).
    type: str
  policy_id:
    description:
      - The ID of an existing prevention policy.
      - The ID is compared without regard to case.
      - With I(state=present), the module fails when the ID does not exist.
      - Mutually exclusive with I(name) and I(platform_name).
    type: str
  platform_name:
    description:
      - The platform of the prevention policy. The value is case-sensitive.
      - A name is unique only for each platform, so the module uses the platform to find
        the policy by I(name).
      - The platform of an existing policy cannot change.
      - Required with I(name).
    type: str
    choices: ["Windows", "Windows_Legacy", "Linux", "Mac"]
  description:
    description:
      - The description of the prevention policy.
      - An empty string clears the description.
      - When not set, the module does not change the description.
    type: str
  enabled:
    description:
      - Whether the prevention policy is enabled.
      - A new policy is disabled unless this is C(true).
      - When not set, the module does not change it.
    type: bool
  host_groups:
    description:
      - The IDs of the host groups to assign the prevention policy to.
      - The IDs are compared without regard to case. An ID that is in the list more than once
        counts once.
      - The module fails before any change when a host group to add does not exist.
      - When not set, the module does not change the host groups of the policy.
      - Ignored with I(state=absent).
    type: list
    elements: str
  purge_host_groups:
    description:
      - If I(purge_host_groups=true) and I(host_groups) is set, the module removes the host groups
        of the policy that are not in I(host_groups).
      - If I(host_groups) is not set, the module does not change the host groups, even if
        I(purge_host_groups=true).
      - With I(host_groups=[]) and I(purge_host_groups=true), the module removes all the host groups
        of the policy.
    type: bool
    default: false

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
  - module: crowdstrike.falcon.prevention_policy_info
    description: Get information about Falcon prevention policies.
  - module: crowdstrike.falcon.host_group
    description: Manage Falcon host groups.
  - module: crowdstrike.falcon.host_group_info
    description: Get information about Falcon host groups.
  - name: Prevention Policy API reference
    description: The CrowdStrike API operations that this module uses.
    link: https://developer.crowdstrike.com/api-reference/collections/prevention-policy

requirements:
  - Prevention policies [B(READ), B(WRITE)] API scope
  - Host Groups [B(READ)] API scope, only when I(host_groups) adds host groups

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Create an enabled Windows prevention policy
  crowdstrike.falcon.prevention_policy:
    name: "Example prevention policy"
    platform_name: Windows
    description: "Managed by Ansible"
    enabled: true

- name: Update the description of the policy
  crowdstrike.falcon.prevention_policy:
    name: "Example prevention policy"
    platform_name: Windows
    description: "Updated by Ansible"

- name: Disable the policy
  crowdstrike.falcon.prevention_policy:
    name: "Example prevention policy"
    platform_name: Windows
    enabled: false

- name: Assign the policy to two host groups
  crowdstrike.falcon.prevention_policy:
    name: "Example prevention policy"
    platform_name: Windows
    host_groups:
      - "abcdef1234567890abcdef1234567890"
      - "1234567890abcdef1234567890abcdef"

- name: Set the exact host groups of the policy and remove the others
  crowdstrike.falcon.prevention_policy:
    name: "Example prevention policy"
    platform_name: Windows
    host_groups:
      - "abcdef1234567890abcdef1234567890"
    purge_host_groups: true

- name: Delete the policy by name and platform
  crowdstrike.falcon.prevention_policy:
    name: "Example prevention policy"
    platform_name: Windows
    state: absent

- name: Delete a prevention policy by ID
  crowdstrike.falcon.prevention_policy:
    policy_id: "12345678901234567890abcdef123456"
    state: absent
"""

RETURN = r"""
prevention_policy:
  description:
    - The prevention policy after the change, read again from the API.
    - In check mode, the current policy, or the wanted values when the policy does not exist.
  type: dict
  returned: when state=present
  contains:
    id:
      description: The ID of the prevention policy.
      type: str
      returned: success
      sample: "12345678901234567890abcdef123456"
    cid:
      description: The customer ID that the policy belongs to.
      type: str
      returned: success
      sample: "abcdef1234567890abcdef1234567890"
    name:
      description: The name of the prevention policy.
      type: str
      returned: success
      sample: "Example prevention policy"
    description:
      description: The description of the prevention policy. Can be empty.
      type: str
      returned: success
      sample: "Example description"
    platform_name:
      description: The platform of the prevention policy.
      type: str
      returned: success
      sample: "Windows"
    enabled:
      description: Whether the prevention policy is enabled.
      type: bool
      returned: success
      sample: true
    groups:
      description: The host groups that the policy is assigned to.
      type: list
      elements: dict
      returned: success
      contains:
        id:
          description: The ID of the host group.
          type: str
          returned: success
          sample: "abcdef1234567890abcdef1234567890"
        group_type:
          description: The type of the host group.
          type: str
          returned: success
          sample: "static"
        name:
          description: The name of the host group.
          type: str
          returned: success
          sample: "Example host group"
        description:
          description: The description of the host group.
          type: str
          returned: success
          sample: "Example host group description"
        assignment_rule:
          description: The assignment rule of the host group.
          type: str
          returned: success
          sample: "hostname:['example-host']"
        created_by:
          description: The user who created the host group.
          type: str
          returned: success
          sample: "user@example.com"
        created_timestamp:
          description: The time when the host group was created.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        modified_by:
          description: The user who last changed the host group.
          type: str
          returned: success
          sample: "user@example.com"
        modified_timestamp:
          description: The time when the host group was last changed.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
    created_by:
      description: The user who created the prevention policy.
      type: str
      returned: success
      sample: "user@example.com"
    created_timestamp:
      description: The time when the prevention policy was created.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
    modified_by:
      description: The user who last changed the prevention policy.
      type: str
      returned: success
      sample: "user@example.com"
    modified_timestamp:
      description: The time when the prevention policy was last changed.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
    prevention_settings:
      description: The prevention settings of the policy, in categories.
      type: list
      elements: dict
      returned: success
      contains:
        name:
          description: The name of the settings category.
          type: str
          returned: success
          sample: "Example category"
        settings:
          description: The settings in the category.
          type: list
          elements: dict
          returned: success
          contains:
            id:
              description: The ID of the setting.
              type: str
              returned: success
              sample: "ExampleSetting"
            name:
              description: The name of the setting.
              type: str
              returned: success
              sample: "Example setting"
            type:
              description: The type of the setting.
              type: str
              returned: success
              sample: "toggle"
            description:
              description: The description of the setting.
              type: str
              returned: success
              sample: "Example setting description"
            value:
              description:
                - The value of the setting. The keys depend on the type of the setting.
                - A C(toggle) setting has C(enabled) and most have C(configured).
                  An C(mlslider) setting has C(detection) and most have C(prevention).
              type: dict
              returned: success
              sample: {"configured": true, "enabled": true}
    ioa_rule_groups:
      description: The custom IOA rule groups that are assigned to the policy.
      type: list
      elements: dict
      returned: success
      contains:
        id:
          description: The ID of the rule group.
          type: str
          returned: success
          sample: "abcdef1234567890abcdef1234567890"
        customer_id:
          description: The customer ID that the rule group belongs to.
          type: str
          returned: success
          sample: "abcdef1234567890abcdef1234567890"
        enabled:
          description: Whether the rule group is enabled.
          type: bool
          returned: success
          sample: true
        name:
          description: The name of the rule group.
          type: str
          returned: success
          sample: "Example rule group"
        description:
          description: The description of the rule group.
          type: str
          returned: success
          sample: "Example rule group description"
        platform:
          description: The platform of the rule group.
          type: str
          returned: success
          sample: "windows"
        deleted:
          description: Whether the rule group is deleted.
          type: bool
          returned: success
          sample: false
        rule_ids:
          description: The IDs of the rules in the rule group.
          type: list
          elements: str
          returned: success
          sample: ["1", "2"]
        comment:
          description: The comment of the last change to the rule group.
          type: str
          returned: success
          sample: "Example comment"
        version:
          description: The version of the rule group.
          type: int
          returned: success
          sample: 1
        created_by:
          description: The user who created the rule group.
          type: str
          returned: success
          sample: "user@example.com"
        created_timestamp:
          description: The time when the rule group was created.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        modified_by:
          description: The user who last changed the rule group.
          type: str
          returned: success
          sample: "user@example.com"
        modified_timestamp:
          description: The time when the rule group was last changed.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        committed_timestamp:
          description: The time when the last change to the rule group was committed.
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
    from falconpy import HostGroup, PreventionPolicy

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# The name filter also matches longer names, so ask for the largest page that
# the search accepts and keep the exact match.
NAME_SEARCH_LIMIT = 5000

# The fields in the diff.
DIFF_FIELDS = ("name", "platform_name", "description", "enabled")

PREVENTION_POLICY_ARGS = {
    "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
    "name": {"type": "str", "required": False},
    "policy_id": {"type": "str", "required": False},
    "platform_name": {
        "type": "str",
        "choices": ["Windows", "Windows_Legacy", "Linux", "Mac"],
        "required": False,
    },
    "description": {"type": "str", "required": False},
    "enabled": {"type": "bool", "required": False},
    "host_groups": {"type": "list", "elements": "str", "required": False},
    "purge_host_groups": {"type": "bool", "default": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(PREVENTION_POLICY_ARGS)

    return args


def validate_params(module):
    """Validate module parameters before any API call."""
    for key in ("name", "policy_id"):
        if module.params[key] is not None and not module.params[key]:
            module.fail_json(msg=f"Parameter '{key}' must not be empty")
    if module.params["host_groups"] is not None and not all(module.params["host_groups"]):
        module.fail_json(msg="Parameter 'host_groups' must not contain an empty ID")


def escape_fql_value(value):
    """Escape a value for a single-quoted FQL string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def check_status(module, result, api_result, action):
    """Fail when the API call did not succeed."""
    status_code = api_result["status_code"]
    if status_code not in (200, 201):
        handle_return_errors(module, result, api_result)
        # handle_return_errors does not fail when errors is empty or null.
        module.fail_json(
            msg=f"Unexpected status {status_code} while {action} the prevention policy",
            **result,
        )


def get_by_id(falcon, module, result, policy_id):
    """Return the policy with this ID, or None when the API returns 404."""
    api_result = falcon.get_policies(ids=[policy_id])
    if api_result["status_code"] == 404:
        return None
    check_status(module, result, api_result, "getting")
    return (api_result["body"].get("resources") or [None])[0]


def find_by_name(falcon, module, result, name, platform_name):
    """Return the policy with this name on this platform, or None."""
    fql = f"name:~'{escape_fql_value(name)}'+platform_name:'{platform_name}'"
    api_result = falcon.query_combined_policies(filter=fql, limit=NAME_SEARCH_LIMIT)
    check_status(module, result, api_result, "searching for")

    # name:~ also matches longer names and ignores case, so keep only the exact name on this platform.
    wanted = name.casefold()
    matches = [
        policy
        for policy in api_result["body"].get("resources") or []
        if (policy.get("name") or "").casefold() == wanted
        and policy.get("platform_name") == platform_name
    ]
    if len(matches) > 1:
        module.fail_json(
            msg=f"More than one prevention policy is named '{name}' on {platform_name}",
            **result,
        )
    return matches[0] if matches else None


def wanted_group_ids(module):
    """Return the set of wanted host group IDs, or None when host_groups is not set."""
    if module.params["host_groups"] is None:
        return None
    # The API IDs are lower case, and the API ignores the upper-case form of an ID.
    return {group_id.lower() for group_id in module.params["host_groups"]}


def current_group_ids(policy):
    """Return the set of host group IDs that the policy is assigned to."""
    return {(group.get("id") or "").lower() for group in policy.get("groups") or []}


def group_changes(module, policy):
    """Return the sorted host group IDs to add and to remove."""
    wanted = wanted_group_ids(module)
    if wanted is None:
        return [], []
    current = current_group_ids(policy) if policy else set()
    to_add = sorted(wanted - current)
    to_remove = sorted(current - wanted) if module.params["purge_host_groups"] else []
    return to_add, to_remove


def check_host_groups(module, result, group_ids):
    """Fail when a host group to add does not exist."""
    if not group_ids:
        return
    host_group = authenticate(module, HostGroup)
    api_result = host_group.get_host_groups(ids=group_ids)
    if api_result["status_code"] == 200:
        return
    if api_result["status_code"] == 404:
        # The API returns 404 with the found groups in resources (or null).
        found = {
            (group.get("id") or "").lower()
            for group in api_result["body"].get("resources") or []
        }
        missing = sorted(set(group_ids) - found)
        if missing:
            module.fail_json(msg=f"Host groups not found: {', '.join(missing)}", **result)
    check_status(module, result, api_result, "checking the host groups of")


def change_groups(falcon, module, result, policy_id, changes):
    """Remove, then add host groups of a policy, with one call for each action.

    changes maps the action ("remove" or "add") to the sorted host group IDs.
    """
    for action in ("remove", "add"):
        group_ids = changes.get(action)
        if not group_ids:
            continue
        api_result = falcon.perform_policies_action(
            action_name=f"{action}-host-group",
            ids=[policy_id],
            action_parameters=[{"name": "group_id", "value": group_id} for group_id in group_ids],
        )
        check_status(module, result, api_result, f"trying to {action} host groups of")


def diff_view(module, policy, group_ids=None):
    """Return the fields of a policy that the diff shows."""
    view = {key: policy.get(key) for key in DIFF_FIELDS if key in policy}
    if module.params["host_groups"] is not None and module.params["state"] == "present":
        view["groups"] = sorted(current_group_ids(policy) if group_ids is None else group_ids)
    return view


def set_enabled(falcon, module, result, policy_id, enabled):
    """Enable or disable a policy."""
    action = "enable" if enabled else "disable"
    api_result = falcon.perform_policies_action(action_name=action, ids=[policy_id])
    check_status(module, result, api_result, f"trying to {action}")


def create_policy(falcon, module, result):
    """Create the policy, and enable it when asked."""
    params = module.params
    wanted = {"name": params["name"], "platform_name": params["platform_name"]}
    if params["description"] is not None:
        wanted["description"] = params["description"]
    # A new policy is disabled.
    after = dict(wanted, enabled=bool(params["enabled"]))
    to_add = group_changes(module, None)[0]

    # Check the host groups first, so a missing ID fails before the policy exists.
    check_host_groups(module, result, to_add)

    result["changed"] = True
    result["diff"] = {"before": {}, "after": diff_view(module, after, to_add)}
    if module.check_mode:
        if params["host_groups"] is not None:
            after["groups"] = [{"id": group_id} for group_id in to_add]
        result["prevention_policy"] = after
        return

    create_result = falcon.create_policies(body={"resources": [wanted]})
    check_status(module, result, create_result, "creating")
    new_id = create_result["body"]["resources"][0]["id"]

    if params["enabled"]:
        set_enabled(falcon, module, result, new_id, True)

    change_groups(falcon, module, result, new_id, {"add": to_add})

    result["prevention_policy"] = get_by_id(falcon, module, result, new_id)


def update_policy(falcon, module, result, current):
    """Update the description and the enabled state when they differ."""
    params = module.params
    result["prevention_policy"] = current

    new_description = None
    if params["description"] is not None and (current.get("description") or "") != params["description"]:
        new_description = params["description"]

    new_enabled = None
    if params["enabled"] is not None and bool(current.get("enabled")) != params["enabled"]:
        new_enabled = params["enabled"]

    to_add, to_remove = group_changes(module, current)

    if new_description is None and new_enabled is None and not to_add and not to_remove:
        return

    check_host_groups(module, result, to_add)

    after = diff_view(module, current)
    if new_description is not None:
        after["description"] = new_description
    if new_enabled is not None:
        after["enabled"] = new_enabled
    if "groups" in after:
        after["groups"] = sorted((set(after["groups"]) - set(to_remove)) | set(to_add))

    result["changed"] = True
    result["diff"] = {"before": diff_view(module, current), "after": after}
    if module.check_mode:
        return

    if new_description is not None:
        # The body sends an empty description, which clears it.
        update_result = falcon.update_policies(
            body={"resources": [{"id": current["id"], "description": new_description}]}
        )
        check_status(module, result, update_result, "updating")

    if new_enabled is not None:
        set_enabled(falcon, module, result, current["id"], new_enabled)

    change_groups(falcon, module, result, current["id"], {"remove": to_remove, "add": to_add})

    # Read again: the write responses can be incomplete.
    result["prevention_policy"] = get_by_id(falcon, module, result, current["id"])


def delete_policy(falcon, module, result, current):
    """Delete the policy when it exists, after disabling it."""
    if current is None:
        return

    result["changed"] = True
    result["diff"] = {"before": diff_view(module, current), "after": {}}
    if module.check_mode:
        return

    # The API does not delete an enabled policy.
    if current.get("enabled"):
        set_enabled(falcon, module, result, current["id"], False)

    delete_result = falcon.delete_policies(ids=[current["id"]])
    check_status(module, result, delete_result, "deleting")


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=[("name", "policy_id"), ("platform_name", "policy_id")],
        required_one_of=[("name", "policy_id")],
        required_by={"name": "platform_name"},
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)
    validate_params(module)

    result = dict(changed=False)
    falcon = authenticate(module, PreventionPolicy)

    try:
        policy_id = module.params["policy_id"]
        if policy_id is not None:
            # The API IDs are lower case.
            policy_id = policy_id.lower()
            current = get_by_id(falcon, module, result, policy_id)
            if current is None and module.params["state"] == "present":
                module.fail_json(msg=f"Prevention policy not found: {policy_id}", **result)
        else:
            current = find_by_name(
                falcon, module, result, module.params["name"], module.params["platform_name"]
            )

        if module.params["state"] == "present":
            if current is None:
                create_policy(falcon, module, result)
            else:
                update_policy(falcon, module, result, current)
        else:
            delete_policy(falcon, module, result, current)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while managing the prevention policy: {str(e)}",
            **result,
        )

    if not module._diff:  # pylint: disable=protected-access
        result.pop("diff", None)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
