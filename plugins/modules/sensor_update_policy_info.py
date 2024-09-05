#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sensor_update_policy_info

short_description: Get information about Falcon Update Sensor Policies

version_added: "4.0.0"

description:
  - Returns a set of Sensor Update Policies which match the filter criteria.
  - See the L(FalconPy documentation,https://falconpy.io/Service-Collections/Sensor-Update-Policy.html#queryCombinedSensorUpdatePoliciesV2)
    for more information about the available filters and sort options.

options:
  filter:
    description:
      - The filter expression that should be used to limit the results using FQL (Falcon Query Language) syntax.
      - See the L(FalconPy documentation,https://www.falconpy.io/Service-Collections/Sensor-Update-Policy.html#available-filters-2)
        for more information about the available filters.
    type: str

extends_documentation_fragment:
    - crowdstrike.falcon.credentials
    - crowdstrike.falcon.credentials.auth
    - crowdstrike.falcon.info
    - crowdstrike.falcon.info.sort

requirements:
  - Sensor update policies [B(READ)] API scope

author:
  - Frank Falor (@ffalor)
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all Sensor Policies
  crowdstrike.falcon.sensor_update_policy_info:

- name: Get enabled windows Sensor Policies
  crowdstike.falcon.sensor_update_policy_info:
    filter: "platform_name:'Windows'+enabled:'true'"

- name: Get Sensor Policies and sort assending by platform_name
  crowdstike.falcon.sensor_update_policy_info:
    sort: "platform_name.asc"
"""

RETURN = r"""
policies:
    description:
      - Array of Sensor Update Policies matching the filter criteria.
    type: list
    returned: success
    elements: dict
    contains:
      id:
        description: The unique identifier of the policy.
        type: str
        returned: success
        sample: "d78cd791785442a98ec75249d8c385dd"
      cid:
        description: The unique identifier of the customer.
        type: str
        returned: success
        sample: "d78cd791785442a98ec75249d8c385dd"
      name:
        description: The name of the policy.
        type: str
        returned: success
        sample: "Windows 10 Sensor Policy"
      description:
        description: The description of the policy.
        type: str
        returned: success
        sample: "Windows 10 Sensor Policy"
      enabled:
        description: Whether the policy is enabled.
        type: bool
        returned: success
        sample: true
      platform_name:
        description: The name of the platform.
        type: str
        returned: success
        sample: "Windows"
      groups:
        description: The groups associated with the policy.
        type: list
        elements: dict
        returned: success
        sample: []
        contains:
          id:
            description: The unique identifier of the group.
            type: str
            returned: success
            sample: "d78cd791785442a98ec75249d8c385dd"
          group_type:
            description: The type of the group.
            type: str
            returned: success
            sample: "static"
          name:
            description: The name of the group.
            type: str
            returned: success
            sample: "Windows 10 Sensor Policy"
          description:
            description: The description of the group.
            type: str
            returned: success
            sample: "Windows 10 Sensor Policy"
          assignment_rule:
            description: The assignment rule of the group.
            type: str
            returned: success
            sample: "hostname:['demo-win10-1']"
          created_by:
            description: The user who created the group.
            type: str
            returned: success
            sample: "user@example.com"
          created_timestamp:
            description: The timestamp when the group was created.
            type: str
            returned: success
            sample: "2021-03-01T00:00:00Z"
          modified_by:
            description: The user who last modified the group.
            type: str
            returned: success
            sample: "user@example.com"
          modified_timestamp:
            description: The timestamp when the group was last modified.
            type: str
            returned: success
            sample: "2021-03-01T00:00:00Z"
      created_by:
        description: The user who created the policy.
        type: str
        returned: success
        sample: "user@example.com"
      created_timestamp:
        description: The timestamp when the policy was created.
        type: str
        returned: success
        sample: "2021-03-01T00:00:00Z"
      modified_by:
        description: The user who last modified the policy.
        type: str
        returned: success
        sample: "user"
      modified_timestamp:
        description: The timestamp when the policy was last modified.
        type: str
        returned: success
        sample: "2021-03-01T00:00:00Z"
      settings:
        description: The settings of the policy.
        type: dict
        returned: success
        sample: {
          "build": "n-1|tagged"
        }
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
    get_paginated_results_info,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import SensorUpdatePolicy

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

POLICY_ARGS = {
    "filter": {"type": "str", "required": False},
    "sort": {"type": "str", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(POLICY_ARGS)

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

    args = {}
    for key, value in module.params.items():
        if key in POLICY_ARGS:
            args[key] = value

    max_limit = 5000

    falcon = authenticate(module, SensorUpdatePolicy)

    result = get_paginated_results_info(
        module,
        args,
        max_limit,
        falcon.query_combined_policies_v2,
        list_name="policies"
    )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
