#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: host_info

short_description: Get information about Falcon hosts

version_added: "4.4.0"

description:
  - Returns detailed information for one or more hosts.
  - Some of the details returned include software information, such as platform,
    OS version, kernel version, and OS build ID (OS build ID available for Windows
    and macOS only); network information, such as IP addresses and MAC addresses; sensor
    information, such as its version; status information, such as last seen time and network
    containment status; and more.

options:
  hosts:
    description:
      - A list of host agent IDs (AIDs) to get information about.
      - Use the P(crowdstrike.falcon.host_ids#lookup) lookup plugin to get a list of host IDs matching
        specific criteria.
    type: list
    elements: str
    required: true

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - Hosts [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get information about a single host
  crowdstrike.falcon.host_info:
    hosts: "12345678901234567890"

- name: Get information about more than one host
  crowdstrike.falcon.host_info:
    hosts:
      - "12345678901234567890"
      - "09876543210987654321"

- name: Get information about all Windows hosts (using host_ids lookup)
  crowdstrike.falcon.host_info:
    hosts: "{{ lookup('crowdstrike.falcon.host_ids', windows_host_filter) }}"
  vars:
    windows_host_filter: 'platform_name:"Windows"'

- name: Get information about all Linux hosts in reduced functionality mode (using host_ids lookup)
  crowdstrike.falcon.host_info:
    hosts: >
      {{
        lookup('crowdstrike.falcon.host_ids',
          'platform_name:"Linux"
          + reduced_functionality_mode:"yes"')
      }}
"""

RETURN = r"""
hosts:
  description:
    - A list of host IDs (AIDs) that match the search criteria.
  type: list
  returned: success
  elements: dict
  contains:
    device_id:
      description: The host ID (AID).
      type: str
      returned: success
      sample: "d78cd791785442a98ec75249d8c385dd"
    cid:
      description: The unique identifier of the customer.
      type: str
      returned: success
      sample: "d78cd791785442a98ec75249d8c385dd"
    agent_load_flags:
      description: Flags indicating the load state of the agent.
      type: str
      returned: success
      sample: "0"
    agent_local_time:
      description: The local time of the agent.
      type: str
      returned: success
      sample: "2024-03-15T03:06:29.257Z"
    agent_version:
      description: The version of the agent.
      type: str
      returned: success
      sample: "7.11.16405.0"
    bios_manufacturer:
      description: The manufacturer of the BIOS.
      type: str
      returned: success
      sample: "Xen"
    bios_version:
      description: The version of the BIOS.
      type: str
      returned: success
      sample: "4.11.amazon"
    config_id_base:
      description: The base configuration ID.
      type: str
      returned: success
      sample: "65994763"
    config_id_build:
      description: The build configuration ID.
      type: str
      returned: success
      sample: "16405"
    config_id_platform:
      description: The platform configuration ID.
      type: str
      returned: success
      sample: "8"
    cpu_signature:
      description: The signature of the CPU.
      type: str
      returned: success
      sample: "198386"
    cpu_vendor:
      description: The vendor of the CPU.
      type: str
      returned: success
      sample: "0"
    external_ip:
      description: The external IP address of the host.
      type: str
      returned: success
      sample: "10.10.10.10"
    mac_address:
      description: The MAC address of the host.
      type: str
      returned: success
      sample: "11-11-b0-44-4e-a5"
    instance_id:
      description:
        - The cloud ID of the instance.
        - This field is only available for cloud-based hosts.
      type: str
      returned: success
      sample: "i-ab89723sdf87"
    service_provider:
      description: The cloud service provider of the host.
      type: str
      returned: success
      sample: "AWS_EC2_V2"
    service_provider_account_id:
      description: The account ID of the cloud service provider.
      type: str
      returned: success
      sample: "112233445566"
    hostname:
      description: The hostname of the host.
      type: str
      returned: success
      sample: "example.local"
    first_seen:
      description: The timestamp of when the host was first seen.
      type: str
      returned: success
      sample: "2024-03-15T03:06:30Z"
    last_seen:
      description: The timestamp of when the host was last seen.
      type: str
      returned: success
      sample: "2024-03-15T03:06:41Z"
    local_ip:
      description: The local IP address of the host.
      type: str
      returned: success
      sample: "10.10.10.10"
    major_version:
      description: The major version of the host.
      type: str
      returned: success
      sample: "6"
    minor_version:
      description: The minor version of the host.
      type: str
      returned: success
      sample: "1"
    os_version:
      description: The version of the operating system.
      type: str
      returned: success
      sample: "Amazon Linux 2023"
    platform_id:
      description: The platform ID of the host.
      type: str
      returned: success
      sample: "3"
    platform_name:
      description: The platform name of the host.
      type: str
      returned: success
      sample: "Linux"
    policies:
      description: The list of policies applied to the host.
      type: list
      returned: success
      elements: dict
      contains:
        policy_type:
          description: The type of policy.
          type: str
          returned: success
          sample: "prevention"
        policy_id:
          description: The ID of the policy.
          type: str
          returned: success
          sample: "aaabbbdddcccddd"
        applied:
          description: Indicates if the policy is applied.
          type: bool
          returned: success
          sample: false
        settings_hash:
          description: The hash of the policy settings.
          type: str
          returned: success
          sample: "aaabbbdddcccdddeee"
        assigned_date:
          description: The timestamp of when the policy was assigned.
          type: str
          returned: success
          sample: "2024-03-15T03:06:41.651213667Z"
        applied_date:
          description: The timestamp of when the policy was applied.
          type: str
          returned: success
          sample: null
        rule_groups:
          description: The list of rule groups within the policy.
          type: list
          returned: success
          sample: []
    reduced_functionality_mode:
      description: Indicates if the host is in reduced functionality mode.
      type: str
      returned: success
      sample: "yes"
    device_policies:
      description: The policies applied to the device.
      type: dict
      returned: success
      elements: dict
      sample: {
        "prevention": {
          "policy_type": "prevention",
          "policy_id": "aaabbbdddcccddd",
          "applied": true,
          "settings_hash": "ed4a7460",
          "assigned_date": "2017-09-14T13:03:33.038805882Z",
          "applied_date": "2017-09-14T13:03:45.823683755Z"
        },
        "sensor_update": {
          "policy_type": "sensor-update",
          "policy_id": "aaabbbdddcccddd",
          "applied": true,
          "settings_hash": "65994753|3|2|automatic",
          "assigned_date": "2017-09-14T05:15:40.878196578Z",
          "applied_date": "2017-09-14T05:16:20.847887649Z"
        }
      }
    groups:
      description: The list of groups the host belongs to.
      type: list
      returned: success
      sample: []
    group_hash:
      description: The hash of the groups the host belongs to.
      type: str
      returned: success
      sample: "aaabbbdddcccdddeeefff"
    product_type_desc:
      description: The description of the product type.
      type: str
      returned: success
      sample: "Server"
    serial_number:
      description: The serial number of the host.
      type: str
      returned: success
      sample: "aaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    status:
      description: The containment status of the host.
      type: str
      returned: success
      sample: "normal"
    system_manufacturer:
      description: The manufacturer of the system.
      type: str
      returned: success
      sample: "VMware, Inc."
    system_product_name:
      description: The product name of the system.
      type: str
      returned: success
      sample: "VMware Virtual Platform"
    tags:
      description: The list of tags associated with the host.
      type: list
      returned: success
      sample: ["Example/tag1", "Example/tag2"]
    modified_timestamp:
      description: The timestamp of when the host was last modified.
      type: str
      returned: success
      sample: "2024-03-15T03:08:21Z"
    meta:
      description: Additional metadata about the host.
      type: dict
      returned: success
      contains:
        version:
          description: Version metadata.
          type: str
          returned: success
          sample: "6"
        version_string:
          description: Version string metadata.
          type: str
          returned: success
          sample: "1:1239010923"
    zone_group:
      description:
        - The cloud zone the host belongs to.
        - This field is only available for cloud-based hosts.
      type: str
      returned: success
      sample: "us-west-2a"
    kernel_version:
      description: The version of the kernel.
      type: str
      returned: success
      sample: "6.1.79-99.164.amzn2023.x86_64"
    chassis_type:
      description: The type of chassis.
      type: str
      returned: success
      sample: "1"
    chassis_type_desc:
      description: The description of the chassis type.
      type: str
      returned: success
      sample: "Other"
    connection_ip:
      description: The IP address used for connection.
      type: str
      returned: success
      sample: "10.10.10.10"
    default_gateway_ip:
      description: The IP address of the default gateway.
      type: str
      returned: success
      sample: "10.10.10.10"
    connection_mac_address:
      description: The MAC address used for connection.
      type: str
      returned: success
      sample: "11-11-b0-44-4e-a5"
    linux_sensor_mode:
      description: The mode of the Linux sensor.
      type: str
      returned: success
      sample: "Kernel Mode"
    deployment_type:
      description: The type of Linux deployment.
      type: str
      returned: success
      sample: "Standard"
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

HOSTS_ARGS = {
    "hosts": {"type": "list", "elements": "str", "required": True},
}


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

    hosts = module.params["hosts"]
    host_details = []
    falcon = authenticate(module, Hosts)

    result = dict(
        changed=False,
    )

    # Batch the hosts in groups of 5000 (the maximum allowed by the API)
    for i in range(0, len(hosts), 5000):
        query_result = falcon.get_device_details(ids=hosts[i:i + 5000])

        if query_result["status_code"] == 200:
            host_details.extend(query_result["body"]["resources"])

    result.update(
        hosts=host_details,
    )

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
