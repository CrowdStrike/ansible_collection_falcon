#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sensor_update_builds_info

short_description: Get a list of available sensor build versions

version_added: "4.4.0"

description:
  - Returns a list of the available sensor build versions that you can use in your policies.

options:
  platform:
    description:
      - Limit the results to a specific platform.
      - If not specified, builds for all platforms are returned.
    type: str
    choices:
      - windows
      - linux
      - linuxarm64
      - zlinux
      - mac
  stage:
    description:
      - Limit the results to a specific stage.
      - If not specified, only builds in the prod stage are returned.
    type: str
    choices:
      - prod
      - early_adopter
    default: prod

extends_documentation_fragment:
    - crowdstrike.falcon.credentials
    - crowdstrike.falcon.credentials.auth

requirements:
  - Sensor update policies [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all sensor build versions
  crowdstrike.falcon.sensor_update_builds_info:

- name: Get all sensor build versions for the Windows platform
  crowdstrike.falcon.sensor_update_builds_info:
    platform: windows
"""

RETURN = r"""
builds:
    description:
      - A list of available sensor build versions.
    type: list
    returned: success
    elements: dict
    contains:
      build:
        description:
          - The complete build version value.
          - For automatic builds, this can include build stage and tagged identifiers.
        type: str
        returned: success
        sample: "16410|n|tagged|11"
      platform:
        description: The platform for which the build is available.
        type: str
        returned: success
        sample: "Windows"
      sensor_version:
        description: The version of the sensor associated with the build.
        type: str
        returned: success
        sample: "6.49.16303"
      stage:
        description: The stage of the build.
        type: str
        returned: success
        sample: "prod"
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
    from falconpy import SensorUpdatePolicy

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

POLICY_ARGS = {
    "platform": {
        "type": "str",
        "required": False,
        "choices": ["windows", "linux", "linuxarm64", "zlinux", "mac"]
    },
    "stage": {
        "type": "str",
        "required": False,
        "choices": ["prod", "early_adopter"],
        "default": "prod"
    },
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

    falcon = authenticate(module, SensorUpdatePolicy)

    query_result = falcon.query_combined_builds(**args)

    result = dict(
        changed=False,
    )

    if query_result["status_code"] == 200:
        result.update(
            builds=query_result["body"]["resources"],
        )

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
