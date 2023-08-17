#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible info module used to query options for the CrowdStrike Falcon Sensor on Linux systems.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: oauth2_token

short_description: Get OAuth2 token

version_added: "4.0.0"

description:
  - Get an OAuth2 token for use with CrowdStrike Falcon API calls.
  - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis)
    for more information about OAuth2 authentication.

extends_documentation_fragment:
  - crowdstrike.falcon.credentials

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get OAuth2 token
  crowdstrike.falcon.oauth2_token:
    client_id: 1234567890abcdef12345678
    client_secret: 1234567890abcdef1234567890abcdef12345678
  register: token

- name: Get OAuth2 token with member CID
  crowdstrike.falcon.oauth2_token:
    client_id: 1234567890abcdef12345678
    client_secret: 1234567890abcdef1234567890abcdef12345678
    member_cid: 1234567890abcdef12345678
  register: token
"""

RETURN = r"""
access_token:
  description: The OAuth2 access token.
  returned: success
  type: str
base_url:
  description:
    - The base URL used for authentication. This can differ from the module's
      C(base_url) argument due to autodiscovery.
  returned: success
  type: str
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.args_common import (
    auth_required_by, falconpy_arg_spec)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate, handle_return_errors)

try:
    from falconpy import OAuth2
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_FALCONPY = True


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=falconpy_arg_spec(),
        required_by=auth_required_by(),
        supports_check_mode=True,
    )

    if not HAS_FALCONPY:
        module.fail_json(msg=missing_required_lib("falconpy"), exception="test")

    falcon = authenticate(module, OAuth2)

    query_result = falcon.token()

    result = dict(
        changed=False,
    )

    if query_result["status_code"] == 201:
        result.update(
            access_token=falcon.token_value,
            base_url=falcon.base_url,
        )
    else:
        handle_return_errors(query_result, falcon, module)

    module.exit_json(**result)
