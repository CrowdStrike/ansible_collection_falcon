#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to download the Falcon sensor.
# Copyright: (c) 2022, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: example_template

author:
  - Carlos Matos (@carlosmmatos)

short_description: Falcon example template module.

version_added: "4.0.0"

description:
  - Falcon example template description.

options:
  destination:
    description:
      - The path to the directory.
    type: str
    required: true

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
'''

EXAMPLES = r'''
- name: Example template module
  crowdstrike.falcon.example_template:
    destination: /tmp/sensor
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import get_falconpy_credentials


class ExampleTemplate(object):
    """Example template module"""
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.credentials = get_falconpy_credentials(module)

    def download(self):
        """Example module function"""
        return "Example module function"


def main():  # pylint: disable=missing-function-docstring
    module = AnsibleModule(
        argument_spec=dict(
            destination=dict(type='str', required=True),
            client_id=dict(type='str', aliases=['falcon_client_id'], required=False, no_log=True),
            client_secret=dict(type='str', aliases=['falcon_client_secret'], required=False, no_log=True)
        ),
        supports_check_mode=True,
    )

    example_template = ExampleTemplate(module)

    result = dict(
        changed=False
    )

    example_template.download()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
