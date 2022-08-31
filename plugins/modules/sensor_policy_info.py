#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible info module used to query options for the CrowdStrike Falcon Sensor on Linux systems.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sensor_policy_info

short_description: Get information about Falcon Update Sensor Policies

version_added: "3.2.0"

description:
  - Returns a set of Sensor Update Policies which match the filter criteria.

options:
  filter:
    description:
      - The filter expression that should be used to limit the results using FQL (Falcon Query Language) syntax.
      - See L(Avaiable filters,https://www.falconpy.io/Service-Collections/Sensor-Update-Policy.html#available-filters-2).
    type: str
  limit:
    description:
      - The maximum number of records to return. [1-5000]
    type: int
  offset:
    description:
      - The offset to start retrieving records from.
    type: int
  sort:
    description:
      - The property to sort by in FQL (Falcon Query Language) syntax.
    type: str

extends_documentation_fragment:
    - crowdstrike.falcon.credentials

author:
  - Frank Falor (@ffalor)
'''

EXAMPLES = r'''
- name: Get all Sensor Policies
  crowdstrike.falcon.sensor_policy_info:

- name: Get enabled windows Sensor Policies
  crowdstike.falcon.sensor_policy_info:
    filter: "platform_name:'Windows'+enabled:'true'"

- name: Get Sensor Policies with a limit of 10
  crowdstike.falcon.sensor_policy_info:
    limit: 10

- name: Get Sensor Policies and sort assending by platform_name
  crowdstike.falcon.sensor_policy_info:
    sort: "platform_name.asc"
'''

RETURN = r'''
status_code:
  description: The HTTP status code returned by the request.
  returned: always
  type: int
  sample: 200
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
        suboptions:
          build:
            description: The build of the policy.
            type: str
            returned: success
            sample: "n-1|tagged"
        sample: {
          "build": "n-1|tagged"
        }
headers:
    description:
      - The HTTP headers returned from the API.
    type: dict
    returned: always
    sample: {
        "X-Ratelimit-Limit": "6000",
        "X-Ratelimit-Remaining": "5999"
    }
meta:
    description:
      - The metadata returned from the API.
      - Contains pagination information.
    type: dict
    returned: always
    sample: {
        "pagination": {
            "limit": 5000,
            "offset": 0,
            "total": 1
        },
        "query_time": 0.012
    }
'''

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crowdstrike.falcon.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import get_falconpy_credentials

from falconpy import SensorUpdatePolicy


def argspec():
    """Define the module's argument spec."""
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(
        filter=dict(type='str', required=False),
        limit=dict(type='int', required=False),
        offset=dict(type='int', required=False),
        sort=dict(type='str', required=False)
    )
    return args


def main():
    """Main entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
    )

    args = {}
    for key, value in module.params.items():
        if key not in ['client_id', 'client_secret']:
            if value is not None:
                args[key] = value

    falcon = SensorUpdatePolicy(**get_falconpy_credentials(module))

    query_result = falcon.query_combined_policies(**args)

    result = dict(
        changed=False,
    )

    result['status_code'] = query_result['status_code']
    result['meta'] = query_result['body']['meta']
    result['headers'] = query_result['headers']

    if query_result['status_code'] == 200:
        result['policies'] = query_result['body']['resources']
    else:
        result['errors'] = query_result['body']['errors']

        if len(result['errors']) > 0:
            msg = result['errors'][0]['message']
        else:
            msg = 'An unknown error occurred.'
        module.fail_json(msg=msg, **result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
