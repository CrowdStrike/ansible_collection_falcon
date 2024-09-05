#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: kernel_support_info

short_description: Get information about kernels supported by the Falcon Sensor for Linux

version_added: "4.1.0"

description:
  - Retrieve details about the kernels supported by the Falcon sensor
    for Linux (kernel mode), matching the specified filter criteria.
  - See the L(CrowdStrike documentation,https://falcon.crowdstrike.com/login/?unilogin=true&next=/documentation/page/cf432222/sensor-update-policy-apis#t6a20418)
    for more information about available filters.
    # noqa: E501

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth
  - crowdstrike.falcon.info

notes:
  - This module will return a list of supported kernel information for kernel mode only of the
    Falcon sensor for Linux. B(This is not for user mode).
  - To help with your filters, you can use the kernel and sensor support distinct values API to
    retrieve a list of distinct values, with proper syntax, for any field. For more info, see
    L(Retrieving field values for kernel support filters,https://falcon.crowdstrike.com/login/?unilogin=true&next=/documentation/page/cf432222/sensor-update-policy-apis#v3cee3bb).
    # noqa: E501

requirements:
  - Sensor update policies [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Show support info for all Ubuntu 20 kernels that have a release starting with 5.8
  crowdstrike.falcon.kernel_support_info:
    filter: "vendor:'ubuntu'+distro:'ubuntu20'+release:*'5.8.*'"

- name: Show support info for kernels with a release of 5.4.0-1040-gcp and an architecture of x86_64
  crowdstrike.falcon.kernel_support_info:
    filter: "release:'5.4.0-1040-gcp'+architecture:'x86_64'"

- name: Show support info using kernel and architecture from ansible_facts
  crowdstrike.falcon.kernel_support_info:
    filter: "release:'{{ ansible_facts['kernel'] }}'+architecture:'{{ ansible_facts['architecture'] }}'"
"""

RETURN = r"""
info:
  description: A list of support information for the kernels that match the filter criteria
  returned: success
  type: list
  elements: dict
  contains:
    architecture:
      description: The Linux kernel architecture.
      returned: success
      type: str
      sample: x86_64
    base_package_supported_sensor_versions:
      description:
        - Sensor versions that support the specified kernel in the base sensor package.
        - These sensor versions support the kernel when they are installed.
      returned: success
      type: list
      elements: str
      sample: [
        "X.YY.Z-1101",
        "X.YY.Z-1102"
      ]
    created_timestamp:
      description: The timestamp when the kernel support information was created.
      returned: success
      type: str
      sample: "2021-01-01 00:00:00"
    distro:
      description: The Linux distribution associated with the kernel.
      returned: success
      type: str
      sample: ubuntu20
    distro_version:
      description: The Linux distribution version associated with the kernel.
      returned: success
      type: str
      sample: 18.x
    flavor:
      description: The Linux kernel flavor.
      returned: success
      type: str
      sample: generic
    id:
      description: The unique identifier of the kernel support information.
      returned: success
      type: str
      sample: 8s0t9k3zr2o7h5x1d4g6nqjfywlbepmau
    modified_timestamp:
      description: The timestamp when the kernel support information was last modified.
      returned: success
      type: str
      sample: "2021-01-01 00:00:00"
    release:
      description: The Linux kernel release version.
      returned: success
      type: str
      sample: 5.4.0-1040-gcp
    vendor:
      description: The Linux vendor associated with the kernel.
      returned: success
      type: str
      sample: ubuntu
    version:
      description: Full Linux OS version identifier.
      returned: success
      type: str
      sample: "#95-Ubuntu SMP Wed Sep 9 15:51:28 UTC 2020"
    ztl_module_supported_sensor_versions:
      description:
        - Sensor versions that added support using the ZTL module support method.
        - These updates are generated without source modifications to the deployed sensor
          and enable the sensor to support the new kernel via offset mapping without having
          to upgrade to a newer sensor version.
      returned: success
      type: list
      elements: str
      sample: [
        "X.YY.Z-1101",
        "X.YY.Z-1102"
      ]
    ztl_supported_sensor_versions:
      description:
        - Sensor versions that added support using the Zero Touch Linux (ZTL) support method.
        - This method adds support for kernels through channel files without requiring a sensor update.
      returned: success
      type: list
      elements: str
      sample: [
        "X.YY.Z-1101",
        "X.YY.Z-1102"
      ]
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
    "filter": {"type": "str", "required": False}
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

    max_limit = 500

    falcon = authenticate(module, SensorUpdatePolicy)

    result = get_paginated_results_info(
        module,
        args,
        max_limit,
        falcon.query_combined_kernels,
        list_name="info"
    )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
