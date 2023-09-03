#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: host_hide

short_description: Hide/Unhide hosts from the Falcon console

version_added: "4.0.0"

description:
  - Manages the visibility of hosts in the Falcon console.
  - To prevent unnecessary detections from an inactive or a duplicate host,
    you can opt to hide the host from the console. This action does not uninstall or
    deactivate the sensor. Detection reporting resumes after a host is unhidden.
  - The module will return a list of successfull and failed hosts IDs for the action performed.

options:
  action:
    description:
      - The type of action to perform on the host(s).
    type: str
    default: hide
    choices:
      - hide
      - unhide
  host_ids:
    description:
      - A list of host IDs to perform the action on.
    type: list
    elements: str
    required: true

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - Hosts [B(WRITE)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Hide hosts from the Falcon console
  crowdstrike.falcon.host_hide:
    action: hide
    host_ids: "12345678901234567890"

- name: Unhide hosts from the Falcon console
  crowdstrike.falcon.host_hide:
    action: unhide
    host_ids:
      - "12345678901234567890"
      - "09876543210987654321"
"""

RETURN = r"""
hosts:
  description:
    - A list of host IDs that were successfully hidden or unhidden.
  type: list
  returned: always
  elements: str
failed_hosts:
  description:
    - A list of dictionaries containing host IDs that failed to be hidden or unhidden.
  type: list
  returned: always
  elements: dict
  contains:
    id:
      description:
        - The host ID that failed to be hidden or unhidden.
      type: str
    code:
      description:
        - The error code returned by the API.
      type: int
    message:
      description:
        - The error message returned by the API.
      type: str
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
    from falconpy import Hosts

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

HOSTS_ARGS = dict(
    action=dict(
        type="str",
        default="hide",
        choices=["hide", "unhide"],
    ),
    host_ids=dict(type="list", elements="str", required=True),
)


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()

    args.update(HOSTS_ARGS)

    return args


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

    action = module.params["action"]
    host_ids = module.params["host_ids"]

    # Setup the return values
    result = dict(
        changed=False,
        hosts=[],
        failed_hosts=[],
    )

    if module.check_mode:
        module.exit_json(**result)

    falcon = authenticate(module, Hosts)

    action_name = "hide_host" if action == "hide" else "unhide_host"

    query_result = falcon.perform_action(action_name=action_name, ids=host_ids)

    # The API returns both successful and failed hosts in the same response. This
    # means we need to handle errors differently than we normally would.
    good = query_result["body"]["resources"]
    bad = query_result["body"]["errors"]

    # If we get nothing back, handle the error
    if not good and not bad:
        handle_return_errors(module, falcon, query_result)

    # Create a mapping for passed-in host IDs to easily manage their states
    host_mapping = {host_id: "" for host_id in host_ids}

    # For hosts in 'good', add the ID to the hosts list
    if good:
        result["changed"] = True
        for host in good:
            host_mapping[host["id"]] = host["id"]

    # For hosts in 'bad', set message based on status code
    if bad:
        for host in bad:
            message = host["message"]
            for host_id in host_mapping.keys():
                if host_id in message:
                    if host["code"] == 409:  # Host already in desired state
                        host_mapping[host_id] = host_id
                    else:
                        result["failed_hosts"].append(
                            {
                                "id": host_id,
                                "code": host["code"],
                                "message": host["message"],
                            }
                        )

    # Add the hosts to the result
    result["hosts"] = [value for value in host_mapping.values() if value]

    # If no good hosts, then fail the module
    if not result["hosts"]:
        module.fail_json(
            msg=f"All host(s) failed to {action}. Check failed_hosts for details.",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
