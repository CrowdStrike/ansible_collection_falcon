#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cid_info

short_description: Get CID with checksum

version_added: "4.0.0"

requirements:
  - Sensor download [B(READ)] API scope

description:
  - Returns the Customer ID (CID) with checksum based on the provided API credentials.
  - CID with checksum must be provided when installing the Falcon sensor.

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get CID with checksum
  crowdstrike.falcon.cid_info:
  register: cid_info
"""

RETURN = r"""
cid:
  description: The CID with checksum
  returned: success
  type: str
  sample: 0123456789ABCDEFGHIJKLMNOPQRSTUV-WX
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
    from falconpy import SensorDownload

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=falconpy_arg_spec(),
        supports_check_mode=True,
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)

    falcon = authenticate(module, SensorDownload)

    query_result = falcon.get_sensor_installer_ccid()

    result = dict(
        changed=False,
    )

    if query_result["status_code"] == 200:
        result.update(
            cid=query_result["body"]["resources"][0],
        )

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
