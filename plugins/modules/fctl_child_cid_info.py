#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fctl_child_cid_info

short_description: Retrieve details about Flight Control child CIDs

version_added: "4.5.0"

description:
  - This module fetches and returns detailed information about specified Flight Control child CIDs.

options:
  cids:
    description:
      - A list of child CIDs to retrieve information for.
      - Consider using the P(crowdstrike.falcon.fctl_child_cids#lookup) lookup plugin
        to obtain a list of child CIDs.
    type: list
    elements: str
    required: true

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - Flight Control [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get information about a single child CID
  crowdstrike.falcon.fctl_child_cid_info:
    cids: "12345678901234567890"

- name: Get information about more than one child CID
  crowdstrike.falcon.fctl_child_cid_info:
    cids:
      - "12345678901234567890"
      - "09876543210987654321"

- name: Get information about all child CIDs (using fctl_child_cids lookup)
  crowdstrike.falcon.fctl_child_cid_info:
    cids: "{{ lookup('crowdstrike.falcon.fctl_child_cids') }}"

- name: Get information about all child CIDs from a secondary parent CID (using fctl_child_cids lookup)
  crowdstrike.falcon.fctl_child_cid_info:
    cids: "{{ lookup('crowdstrike.falcon.fctl_child_cids', '12345678901234567890') }}"
"""

RETURN = r"""
child_cids:
  description:
    - A list of dictionaries containing information about the child CIDs.
  type: list
  returned: success
  elements: dict
  contains:
    child_cid:
      description: The unique identifier of the child CID.
      type: str
      returned: success
      sample: "12345678901234567890"
    child_gcid:
      description: The global CID of the child CID.
      type: str
      returned: success
      sample: "g12345678901234567890"
    child_of:
      description: The unique identifier of the parent CID.
      type: str
      returned: success
      sample: "09876543210987654321"
    name:
      description: The name of the child CID.
      type: str
      returned: success
      sample: "Flight Control Child 1"
    checksum:
      description: The checksum of the child CID.
      type: str
      returned: success
      sample: "xy"
    domains:
      description: A list of domains associated with the child CID.
      type: list
      returned: success
      elements: str
      sample: ["example.com"]
    status:
      description: The status of the child CID.
      type: str
      returned: success
      sample: "active"
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
    from falconpy import FlightControl

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

FCTL_CID_ARGS = {
    "cids": {"type": "list", "elements": "str", "required": True},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(FCTL_CID_ARGS)

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

    cids = module.params["cids"]
    child_cid_details = []
    falcon = authenticate(module, FlightControl)

    result = dict(
        changed=False,
    )

    # Use FalconPy override functionality to support backward compatibility
    query_result = falcon.override("POST", "/mssp/entities/children/GET/v2", body={"ids": cids})

    if query_result["status_code"] == 200:
        child_cid_details.extend(query_result["body"]["resources"])

    result.update(
        child_cids=child_cid_details,
    )

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
