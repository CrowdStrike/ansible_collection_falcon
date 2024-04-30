#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: host_contain

short_description: Network contain hosts in Falcon

version_added: "4.1.0"

description:
  - Manages the network containment state of Falcon hosts.
  - To restrict a host that may be compromised from making network connections, contain
    it within the network. Lift containment to restore its regular communication capabilities.
  - The module will return a list of successfull and failed hosts agent IDs (AIDs) for
    the action performed.

options:
  contained:
    description:
      - Whether to contain or lift containment on the hosts.
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
  - B(Failure Handling:) This module will not fail if some hosts could not be
    contained or lifted from containment. Instead, it will populate the 'failed_hosts' list
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
- name: Contain a single host
  crowdstrike.falcon.host_contain:
    hosts: "12345678901234567890"

- name: Lift containment on a list of hosts
  crowdstrike.falcon.host_contain:
    hosts:
      - "12345678901234567890"
      - "09876543210987654321"
    contained: no

- name: Contain all Linux hosts in RFM (using host_ids lookup)
  crowdstrike.falcon.host_contain:
    hosts: "{{ lookup('crowdstrike.falcon.host_ids', contain_filter) }}"
    contained: yes
  vars:
    linux_rfm_filter: >
      platform_name:'Linux' +
      reduced_functionality_mode:'yes'

- name: Individually contain hosts within a list
  crowdstrike.falcon.host_contain:
    auth: "{{ falcon.auth }}"  # Use auth saved from crowdstrike.falcon.auth module
    hosts: "{{ item }}"
  loop: "{{ host_ids }}"
  register: contain_results

- name: Fail if any hosts could not be contained
  fail:
    msg: "Hosts could not be contained: {{ contain_results.failed_hosts }}"
  when: contain_results.failed_hosts | length > 0
"""

RETURN = r"""
hosts:
  description:
    - A list of host agent IDs (AIDs) that were successfully contained or lifted
      from containment.
  type: list
  returned: always
  elements: str
failed_hosts:
  description:
    - A list of dictionaries containing host IDs that failed to be contained or
      lifted from containment.
  type: list
  returned: always
  elements: dict
  contains:
    id:
      description:
        - The host agent ID that failed to be contained or lifted from containment.
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
    contained=dict(
        type="bool",
        default="true",
    ),
    hosts=dict(type="list", elements="str", required=True),
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

    contained = module.params["contained"]
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

    action_name = "contain" if contained else "lift_containment"

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
        for host in good:
            host_mapping[host["id"]] = host["id"]

    # For hosts in 'bad', manage state and failed_hosts
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

    # Add the hosts to the result
    result["hosts"] = [value for value in host_mapping.values() if value]

    module.exit_json(**result)


if __name__ == "__main__":
    main()
