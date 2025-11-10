#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: host_group

short_description: Manage Falcon host groups

version_added: "4.10.0"

description:
  - Create, update, delete, and manage Falcon host groups.
  - Supports static, dynamic, and staticByID group types.
  - Can manage host group membership by adding or removing hosts.
  - Provides idempotent operations that only make changes when necessary.

options:
  state:
    description:
      - The desired state of the host group.
      - C(present) ensures the host group exists with the specified configuration.
      - C(absent) ensures the host group does not exist.
    type: str
    choices: ["present", "absent"]
    default: present
  name:
    description:
      - The name of the host group.
      - Required when I(state=present) and creating a new group.
      - Can be used for I(state=absent) to delete by name (supports true idempotency).
      - Cannot be used to rename existing groups (use I(host_group) to identify the group).
    type: str
    required: false
  host_group:
    description:
      - The ID of an existing host group.
      - Can be used with I(state=absent) for deletion by ID.
      - If provided with I(state=present), the module will update the existing group.
      - "B(Note): Either I(name) or I(host_group) is required for I(state=absent)."
    type: str
    required: false
  description:
    description:
      - A description for the host group.
      - Only used when I(state=present).
    type: str
    required: false
  group_type:
    description:
      - The type of host group to create or validate.
      - C(static) groups contain manually assigned hosts.
      - C(dynamic) groups automatically include hosts based on assignment rules.
      - C(staticByID) groups contain hosts assigned by their device IDs.
      - Cannot be changed after group creation.
    type: str
    choices: ["static", "dynamic", "staticByID"]
    default: static
  assignment_rule:
    description:
      - FQL (Falcon Query Language) filter for dynamic group membership.
      - Required when I(group_type=dynamic).
      - Ignored for static and staticByID groups.
      - "Examples: C(platform_name:'Linux'), C(tags:'production'+os_version:'*Server*')."
    type: str
    required: false
  hosts:
    description:
      - List of host IDs (AIDs) to add to or remove from the host group.
      - Use with I(host_action) to specify the operation.
      - Only applicable for existing groups and when I(state=present).
    type: list
    elements: str
    required: false
  host_action:
    description:
      - The action to perform with the hosts specified in I(hosts).
      - C(add) adds hosts to the group.
      - C(remove) removes hosts from the group.
      - Requires I(hosts) to be specified.
    type: str
    choices: ["add", "remove"]
    required: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - B(Idempotency:) This module is idempotent and will only make changes when the
    current state differs from the desired state.
  - B(Group Types:) The group type cannot be changed after creation. To change
    a group's type, delete the existing group and create a new one.
  - B(Dynamic Groups:) Assignment rules for dynamic groups are evaluated by
    CrowdStrike's backend and may take some time to reflect membership changes.
  - B(Host Management:) Adding or removing hosts only works with existing groups.
    Host operations are performed after group creation/update operations.

requirements:
  - Host Groups [B(READ), B(WRITE)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
# PRIMARY WORKFLOW: Name-based Operations

- name: Create a static host group using names (recommended)
  crowdstrike.falcon.host_group:
    name: "Web Servers"
    description: "All web server hosts in the environment"
    group_type: static

- name: Create a dynamic host group with assignment rules
  crowdstrike.falcon.host_group:
    name: "Linux Production Hosts"
    description: "All Linux hosts with production tags"
    group_type: dynamic
    assignment_rule: "platform_name:'Linux'+tags:'production'"

- name: Create a staticByID host group for device ID management
  crowdstrike.falcon.host_group:
    name: "Critical Infrastructure"
    description: "Manually assigned critical infrastructure hosts"
    group_type: staticByID

- name: Update an existing group using name (detects changes automatically)
  crowdstrike.falcon.host_group:
    name: "Web Servers"
    description: "Updated description for all web server hosts"

- name: Update dynamic group assignment rule using name
  crowdstrike.falcon.host_group:
    name: "Linux Production Hosts"
    assignment_rule: "platform_name:'Linux'+(tags:'production'+tags:'web')"

- name: Delete a host group using name (true idempotency - recommended)
  crowdstrike.falcon.host_group:
    name: "Web Servers"
    state: absent

# TRUE IDEMPOTENCY PATTERN: Same Task Definition for Entire Lifecycle

- name: Manage host group lifecycle with identical task definition
  crowdstrike.falcon.host_group:
    name: "Application Servers"
    description: "All application server hosts"
    group_type: static
    state: "{{ desired_state }}"  # 'present' for create/update, 'absent' for delete

- name: Complete dynamic group lifecycle example
  crowdstrike.falcon.host_group:
    name: "Windows Domain Controllers"
    description: "All Windows domain controller hosts"
    group_type: dynamic
    assignment_rule: "platform_name:'Windows'+tags:'domain-controller'"
    state: "{{ lifecycle_state | default('present') }}"

# HOST MANAGEMENT: Adding and Removing Hosts from Groups

- name: Create group first, then manage hosts using returned ID
  crowdstrike.falcon.host_group:
    name: "Database Servers"
    description: "All database server hosts"
    group_type: static
  register: db_group_result

- name: Add hosts to the database group
  crowdstrike.falcon.host_group:
    host_group: "{{ db_group_result.host_group.id }}"
    hosts:
      - "15dbb9d8f06b45fe9f61eb46e829d986"
      - "2ae94761f78e4a6d9e2f8b5c4d1a7b3e"
    host_action: add

- name: Remove specific hosts from the group
  crowdstrike.falcon.host_group:
    host_group: "{{ db_group_result.host_group.id }}"
    hosts:
      - "15dbb9d8f06b45fe9f61eb46e829d986"
    host_action: remove

# DYNAMIC HOST MANAGEMENT: Using host_ids Lookup Plugin

- name: Create group and populate with Windows hosts dynamically
  crowdstrike.falcon.host_group:
    name: "Windows Production Servers"
    description: "All Windows hosts in production environment"
    group_type: static
    hosts: "{{ lookup('crowdstrike.falcon.host_ids', 'platform_name:\"Windows\"+tags:\"production\"') }}"
    host_action: add

# ID-BASED OPERATIONS: When Working with Existing Groups

- name: Update existing group using ID (when you have the group ID)
  crowdstrike.falcon.host_group:
    host_group: "a1b2c3d4e5f6789012345678901234ab"
    description: "Updated description using group ID"

- name: Delete a host group using ID (legacy approach)
  crowdstrike.falcon.host_group:
    host_group: "a1b2c3d4e5f6789012345678901234ab"
    state: absent

# ADVANCED PATTERNS: Complex Assignment Rules and Error Handling

- name: Create dynamic group with complex FQL assignment rule
  crowdstrike.falcon.host_group:
    name: "High-Risk Linux Servers"
    description: "Linux servers requiring enhanced monitoring"
    group_type: dynamic
    assignment_rule: "platform_name:'Linux'+(tags:'production'+tags:'database'+!tags:'patched')"

- name: Conditional group management with error handling
  crowdstrike.falcon.host_group:
    name: "{{ group_name }}"
    description: "{{ group_description | default('Managed by Ansible') }}"
    group_type: "{{ group_type | default('static') }}"
    assignment_rule: "{{ assignment_rule | default(omit) }}"
    state: present
  register: group_result
  failed_when: false  # Handle errors gracefully

- name: Verify group creation succeeded before proceeding
  ansible.builtin.assert:
    that:
      - group_result is succeeded
      - group_result.host_group.name == group_name
    fail_msg: "Failed to create or update host group {{ group_name }}"
"""

RETURN = r"""
host_group:
  description:
    - Information about the host group that was created, updated, or managed.
  type: dict
  returned: when state=present
  contains:
    id:
      description: The unique identifier of the host group.
      type: str
      returned: success
      sample: "12345678901234567890abcdef123456"
    name:
      description: The name of the host group.
      type: str
      returned: success
      sample: "Web Servers"
    description:
      description: The description of the host group.
      type: str
      returned: success
      sample: "All web server hosts"
    group_type:
      description: The type of host group (static, dynamic, or staticByID).
      type: str
      returned: success
      sample: "static"
    assignment_rule:
      description: The assignment rule for dynamic groups.
      type: str
      returned: when group_type=dynamic
      sample: "platform_name:'Linux'+tags:'production'"
    created_by:
      description: The user who created the host group.
      type: str
      returned: success
      sample: "user@example.com"
    created_timestamp:
      description: The timestamp when the host group was created.
      type: str
      returned: success
      sample: "2024-01-15T10:30:00.000000Z"
    modified_by:
      description: The user who last modified the host group.
      type: str
      returned: success
      sample: "admin@example.com"
    modified_timestamp:
      description: The timestamp when the host group was last modified.
      type: str
      returned: success
      sample: "2024-02-01T14:22:30.000000Z"
action_results:
  description:
    - Results of host management actions (add/remove hosts).
  type: dict
  returned: when host_action is performed
  contains:
    successful_hosts:
      description: List of host IDs that were successfully added or removed.
      type: list
      returned: success
      elements: str
      sample: ["d78cd791785442a98ec75249d8c385dd"]
    failed_hosts:
      description: List of host IDs that failed to be added or removed.
      type: list
      returned: when some hosts fail
      elements: dict
      contains:
        id:
          description: The host ID that failed.
          type: str
          returned: success
          sample: "a1b2c3d4e5f6789012345678901234ab"
        code:
          description: The error code returned by the API.
          type: int
          returned: success
          sample: 404
        message:
          description: The error message returned by the API.
          type: str
          returned: success
          sample: "Host not found"
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
    from falconpy import HostGroup

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

HOST_GROUP_ARGS = {
    "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
    "name": {"type": "str", "required": False},
    "host_group": {"type": "str", "required": False},
    "description": {"type": "str", "required": False},
    "group_type": {
        "type": "str",
        "choices": ["static", "dynamic", "staticByID"],
        "default": "static",
    },
    "assignment_rule": {"type": "str", "required": False},
    "hosts": {"type": "list", "elements": "str", "required": False},
    "host_action": {"type": "str", "choices": ["add", "remove"], "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(HOST_GROUP_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    state = module.params["state"]
    name = module.params.get("name")
    host_group = module.params.get("host_group")
    group_type = module.params["group_type"]
    assignment_rule = module.params.get("assignment_rule")
    hosts = module.params.get("hosts")
    host_action = module.params.get("host_action")

    # Validate required parameters for different states
    if state == "present":
        if not host_group and not name:
            module.fail_json(
                msg="Either 'name' (for new groups) or 'host_group' (for existing groups) is required when state=present"
            )
    elif state == "absent":
        if not host_group and not name:
            module.fail_json(
                msg="Either 'host_group' (ID) or 'name' is required when state=absent"
            )

    # Validate dynamic group requirements
    if group_type == "dynamic" and state == "present" and not assignment_rule:
        module.fail_json(
            msg="Parameter 'assignment_rule' is required when group_type=dynamic"
        )

    # Validate host action parameters
    if host_action and not hosts:
        module.fail_json(
            msg="Parameter 'hosts' is required when 'host_action' is specified"
        )

    if hosts and not host_action:
        module.fail_json(
            msg="Parameter 'host_action' is required when 'hosts' is specified"
        )


def get_existing_group(falcon, host_group_id):
    """Get an existing host group by ID."""
    result = falcon.get_host_groups(ids=[host_group_id])
    if result["status_code"] == 200 and result["body"]["resources"]:
        return result["body"]["resources"][0]
    return None


def find_group_by_name(falcon, name):
    """Find a host group by name using search."""
    result = falcon.query_combined_host_groups(filter=f"name:'{name}'", limit=1)
    if result["status_code"] == 200 and result["body"]["resources"]:
        return result["body"]["resources"][0]
    return None


def create_host_group(falcon, module):
    """Create a new host group."""
    params = {
        "name": module.params["name"],
        "group_type": module.params["group_type"],
    }

    if module.params.get("description"):
        params["description"] = module.params["description"]

    if module.params.get("assignment_rule"):
        params["assignment_rule"] = module.params["assignment_rule"]

    return falcon.create_host_groups(**params)


def update_host_group(falcon, module, group_id):
    """Update an existing host group."""
    params = {
        "id": group_id,
    }

    # Only include parameters that should be updated
    if module.params.get("name"):
        params["name"] = module.params["name"]

    if module.params.get("description") is not None:
        params["description"] = module.params["description"]

    if module.params.get("assignment_rule") is not None:
        params["assignment_rule"] = module.params["assignment_rule"]

    return falcon.update_host_groups(**params)


def delete_host_group(falcon, host_group_id):
    """Delete a host group."""
    return falcon.delete_host_groups(ids=[host_group_id])


def perform_host_action(falcon, module, group_id):
    """Add or remove hosts from a group."""
    action_name = (
        "add-hosts" if module.params["host_action"] == "add" else "remove-hosts"
    )

    # Create filter for the hosts
    host_ids = module.params["hosts"]
    quoted_ids = '","'.join(host_ids)
    device_filter = f'device_id:["{quoted_ids}"]'

    return falcon.perform_group_action(
        action_name=action_name, ids=[group_id], filter=device_filter
    )


def process_host_action_results(result):
    """Process the results of a host action to separate successful and failed hosts."""
    successful_hosts = []
    failed_hosts = []

    # Extract successful operations
    if "resources" in result["body"] and result["body"]["resources"]:
        for resource in result["body"]["resources"]:
            if "id" in resource:
                successful_hosts.append(resource["id"])

    # Extract failed operations
    if "errors" in result["body"] and result["body"]["errors"]:
        for error in result["body"]["errors"]:
            failed_hosts.append(
                {
                    "code": error.get("code", 0),
                    "message": error.get("message", "Unknown error"),
                }
            )

    return {"successful_hosts": successful_hosts, "failed_hosts": failed_hosts}


def group_needs_update(current_group, module):
    """Check if the current group needs to be updated based on module parameters."""
    needs_update = False

    # Check name (only if provided and different)
    if module.params.get("name") and current_group.get("name") != module.params["name"]:
        needs_update = True

    # Check description (only if provided and different)
    if (
        module.params.get("description") is not None
        and current_group.get("description") != module.params["description"]
    ):
        needs_update = True

    # Check assignment_rule for dynamic groups (only if provided and different)
    if (
        module.params.get("assignment_rule") is not None
        and current_group.get("assignment_rule") != module.params["assignment_rule"]
    ):
        needs_update = True

    return needs_update


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)
    validate_params(module)

    state = module.params["state"]
    host_group = module.params.get("host_group")
    name = module.params.get("name")

    result = dict(
        changed=False,
    )

    if module.check_mode:
        module.exit_json(**result)

    falcon = authenticate(module, HostGroup)

    try:
        if state == "present":
            current_group = None

            # Find existing group
            if host_group:
                current_group = get_existing_group(falcon, host_group)
                if not current_group:
                    module.fail_json(msg=f"Host group with ID '{host_group}' not found")
            elif name:
                current_group = find_group_by_name(falcon, name)

            if current_group:
                # Update existing group if needed
                if group_needs_update(current_group, module):
                    update_result = update_host_group(
                        falcon, module, current_group["id"]
                    )
                    if update_result["status_code"] != 200:
                        handle_return_errors(module, result, update_result)
                    result["changed"] = True

                    # Get updated group info
                    updated_group = get_existing_group(falcon, current_group["id"])
                    result["host_group"] = (
                        updated_group if updated_group else current_group
                    )
                else:
                    result["host_group"] = current_group

                # Perform host actions if specified
                if module.params.get("hosts") and module.params.get("host_action"):
                    action_result = perform_host_action(
                        falcon, module, current_group["id"]
                    )
                    if action_result["status_code"] != 200:
                        # For host actions, we may have partial success, so process the results
                        result["action_results"] = process_host_action_results(
                            action_result
                        )
                        if result["action_results"]["successful_hosts"]:
                            result["changed"] = True
                    else:
                        result["action_results"] = process_host_action_results(
                            action_result
                        )
                        result["changed"] = True

            else:
                # Create new group
                create_result = create_host_group(falcon, module)
                if create_result["status_code"] != 201:
                    handle_return_errors(module, result, create_result)

                if create_result["body"]["resources"]:
                    new_group_id = create_result["body"]["resources"][0]["id"]
                    result["host_group"] = create_result["body"]["resources"][0]
                    result["changed"] = True

                    # Perform host actions if specified for new group
                    if module.params.get("hosts") and module.params.get("host_action"):
                        action_result = perform_host_action(
                            falcon, module, new_group_id
                        )
                        result["action_results"] = process_host_action_results(
                            action_result
                        )
                        if result["action_results"]["successful_hosts"]:
                            result["changed"] = True

        elif state == "absent":
            current_group = None

            # Find existing group by ID or name
            if host_group:
                current_group = get_existing_group(falcon, host_group)
                if not current_group:
                    module.fail_json(msg=f"Host group with ID '{host_group}' not found")
            elif name:
                current_group = find_group_by_name(falcon, name)

            if current_group:
                # Delete the group
                delete_result = delete_host_group(falcon, current_group["id"])
                if delete_result["status_code"] != 200:
                    handle_return_errors(module, result, delete_result)
                result["changed"] = True

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while managing the host group: {str(e)}", **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
