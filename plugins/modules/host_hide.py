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
  - The module will return a list of successfull and failed hosts agent IDs (AIDs) for
    the action performed.

options:
  hidden:
    description:
      - Whether to hide or unhide the hosts.
    type: bool
    default: true
  hosts:
    description:
      - A list of host agent IDs (AIDs) to perform the action on.
      - Use the P(crowdstrike.falcon.host_ids#lookup) lookup plugin to get a list of host IDs matching
        specific criteria.
    type: list
    elements: str
    required: true

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - This module handles the 100 hosts per request limit by the Falcon API. This
    means that if more than 100 hosts are passed to the module, it will process
    them in batches of 100 automatically.
  - For large numbers of hosts, this module may take some time to complete.
  - B(Failure Handling:) This module will not fail if some hosts could not be
    hidden or unhidden. Instead, it will populate the 'failed_hosts' list
    with the relevant host IDs and error details. This is designed to allow
    the user greater flexibility in handling failures, especially when this
    module is used in a loop. If strict failure handling is needed, users
    should explicitly check the 'failed_hosts' list after execution. See the
    examples for more details.

requirements:
  - Hosts [B(WRITE)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Hide a host from the Falcon console
  crowdstrike.falcon.host_hide:
    hosts: "12345678901234567890"

- name: Unhide hosts from the Falcon console
  crowdstrike.falcon.host_hide:
    hosts:
      - "12345678901234567890"
      - "09876543210987654321"
    hidden: false

- name: Hide all stale hosts that have not checked in for 30 days (using host_ids lookup)
  crowdstrike.falcon.host_hide:
    hosts: "{{ lookup('crowdstrike.falcon.host_ids', stale_filter) }}"
  vars:
    stale_filter: 'last_seen:<="now-15d"'

- name: Individually hide hosts with a list from the Falcon console
  crowdstrike.falcon.host_hide:
    auth: "{{ falcon.auth }}"  # Use auth saved from crowdstrike.falcon.auth module
    hosts: "{{ item }}"
  loop: "{{ host_ids }}"
  register: hide_result

- name: Fail if any hosts could not be hidden
  fail:
    msg: "Hosts could not be hidden: {{ hide_result.failed_hosts }}"
  when: hide_result.failed_hosts | length > 0
"""

RETURN = r"""
hosts:
  description:
    - A list of host agent IDs (AIDs) that were successfully hidden or unhidden.
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
        - The host agent ID that failed to be hidden or unhidden.
      type: str
      returned: when a host agent ID fails
    code:
      description:
        - The error code returned by the API.
      type: int
      returned: when a host agent ID fails
    message:
      description:
        - The error message returned by the API.
      type: str
      returned: when a host agent ID fails
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
    hidden=dict(
        type="bool",
        default="true",
    ),
    hosts=dict(type="list", elements="str", required=True),
)


def handle_good_hosts(good, host_mapping):
    """Handle the hosts that were successfully hidden or unhidden."""
    for host in good:
        host_mapping[host["id"]] = host["id"]


def handle_bad_hosts(bad, host_mapping, result):
    """Handle the hosts that failed to be hidden or unhidden."""
    for host in bad:
        message, code = host["message"], host["code"]

        for host_id in host_mapping.keys():
            if host_id not in message:
                continue

            if code == 409:  # Host already in desired state
                host_mapping[host_id] = host_id
            else:
                result["failed_hosts"].append(
                    {
                        "id": host_id,
                        "code": code,
                        "message": message,
                    }
                )


def process_hosts(module, falcon, action_name, hosts, result):
    """Process the hosts to hide or unhide."""
    query_result = falcon.perform_action(action_name=action_name, ids=hosts)

    # The API returns both successful and failed hosts in the same response. This
    # means we need to handle errors differently than we normally would.
    good = query_result["body"]["resources"]
    bad = query_result["body"]["errors"]

    # If we get nothing back, handle the error
    if not good and not bad:
        handle_return_errors(module, falcon, query_result)

    # Create a mapping for passed-in host IDs to manage their states
    host_mapping = {host_id: "" for host_id in hosts}

    # For hosts in 'good', add the ID to the hosts list
    if good:
        result["changed"] = True
        handle_good_hosts(good, host_mapping)

    # For hosts in 'bad', manage state and failed_hosts
    handle_bad_hosts(bad, host_mapping, result)

    # Append the hosts to the result
    for value in host_mapping.values():
        if value:
            result["hosts"].append(value)


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

    hidden = module.params["hidden"]
    hosts = module.params["hosts"]

    # Setup the return values
    result = dict(
        changed=False,
        hosts=[],
        failed_hosts=[],
    )

    if module.check_mode:
        module.exit_json(**result)

    falcon = authenticate(module, Hosts)

    action_name = "hide_host" if hidden else "unhide_host"

    # API can only process 100 hosts at a time
    for i in range(0, len(hosts), 100):
        process_hosts(module, falcon, action_name, hosts[i:i + 100], result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
