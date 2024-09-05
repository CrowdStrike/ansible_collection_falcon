#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sensor_download_info

short_description: Get information about Falcon Sensor Installers

version_added: "4.0.0"

description:
  - Returns a set of Sensor Installers which match the filter criteria.

options:
  filter:
    description:
      - The filter expression that should be used to limit the results using FQL (Falcon Query Language) syntax.
      - See the return values or CrowdStrike docs for more information about the available filters that can be used.
    type: str

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth
  - crowdstrike.falcon.info.sort

requirements:
  - Sensor download [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all Linux Sensor Installers
  crowdstrike.falcon.sensor_download_info:
    filter: "platform:'linux'"

- name: Get all Windows Sensor Installers sorted by version
  crowdstrike.falcon.sensor_download_info:
    filter: "platform:'windows'"
    sort: "version|desc"

- name: Get all zLinux(s390x) Sensor Installers
  crowdstrike.falcon.sensor_download_info:
    filter: "platform:'linux' + architectures:'s390x'"
"""

RETURN = r"""
installers:
  description: A list of matching Sensor Installers
  returned: success
  type: list
  elements: dict
  contains:
    description:
      description: The description of the Sensor Installer.
      returned: success
      type: str
      sample: Falcon Sensor for Ubuntu 18.04
    file_size:
      description: The size of the Sensor Installer in bytes.
      returned: success
      type: int
      sample: 123456789
    file_type:
      description: The type of the Sensor Installer.
      returned: success
      type: str
      sample: rpm
    name:
      description: The name of the Sensor Installer.
      returned: success
      type: str
      sample: falcon-sensor-X.YY.Z-11404.el7.x86_64.rpm
    os:
      description: The operating system associated with the Sensor Installer.
      returned: success
      type: str
      sample: Ubuntu
    os_version:
      description: The operating system version associated with the Sensor Installer.
      returned: success
      type: str
      sample: 16/18/20/22
    platform:
      description: The platform associated with the Sensor Installer.
      returned: success
      type: str
      sample: linux
    release_date:
      description: The release date of the Sensor Installer.
      returned: success
      type: str
      sample: "2021-01-01T00:00:00Z"
    sha256:
      description:
        - The SHA256 checksum of the Sensor Installer.
        - This value is generally used to download the Sensor Installer.
      returned: success
      type: str
      sample: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    version:
      description: The version of the Sensor Installer.
      returned: success
      type: str
      sample: 6.22.11404
    architectures:
      description: A list of architectures supported by the Sensor Installer.
      returned: success
      type: list
      elements: str
      sample: x86_64
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

DOWNLOAD_INFO_ARGS = {
    "filter": {"type": "str", "required": False},
    "sort": {"type": "str", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(DOWNLOAD_INFO_ARGS)

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
        if key in DOWNLOAD_INFO_ARGS:
            args[key] = value

    falcon = authenticate(module, SensorDownload)

    # Pagination is not supported, so we can just call the API directly
    query_result = falcon.override("GET", "/sensors/combined/installers/v2", parameters={**args})

    result = dict(
        changed=False,
    )

    if query_result["status_code"] == 200:
        result.update(
            installers=query_result["body"]["resources"],
        )

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
