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
module: auth

short_description: Manage OAuth2 tokens

version_added: "4.0.0"

description:
  - Generate or revoke OAuth2 tokens for use with the CrowdStrike Falcon API.
  - Access tokens can be useful when needing to make multiple API calls against multiple hosts.
    Helps to avoid rate limiting issues.
  - This module never reports changed.
  - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis)
    for more information about OAuth2 authentication.

options:
  action:
    description:
      - The action to perform.
    type: str
    choices:
      - generate
      - revoke
    default: generate
  access_token:
    description:
      - The OAuth2 access token to revoke.
      - Required when I(action) is C(revoke).
    type: str

extends_documentation_fragment:
  - crowdstrike.falcon.credentials

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get auth information
  crowdstrike.falcon.auth:

- name: Get auth information with member CID
  crowdstrike.falcon.auth:
    member_cid: 1234567890abcdef12345678

- name: Revoke OAuth2 token
  crowdstrike.falcon.auth:
    action: revoke
    access_token: "{{ access_token }}"
"""

RETURN = r"""
auth:
  description: The OAuth2 authentication information.
  returned: success
  type: dict
  contains:
    access_token:
      description: The OAuth2 access token.
      returned: success
      type: str
    base_url:
      description:
        - The base URL used for authentication. This can differ from the module's
          C(cloud) argument due to autodiscovery.
      returned: success
      type: str
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.args_common import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    get_falconpy_credentials,
    handle_return_errors,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import OAuth2

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


def argspec():
    """Define the modules's argument spec."""
    args = falconpy_arg_spec()
    args.pop("auth")
    args.update(
        action=dict(
            type="str",
            choices=["generate", "revoke"],
            default="generate",
        ),
        access_token=dict(
            type="str",
            required=False,
            no_log=True,
        ),
    )

    return args


def generate(falcon):
    """Generate a new OAuth2 token."""
    return falcon.login()


def revoke(falcon, access_token):
    """Revoke an OAuth2 token.

    This method currently has to login first, in order to properly
    revoke a token. It then logs out after the token is revoked to
    revoke the session token as well.

    @jshcodes: This is a workaround for the Falcon API.
    """
    falcon.login()  # Needs to authenticate first
    revoked = falcon.revoke(token=access_token)
    falcon.logout()
    return revoked


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        required_if=[
            ("action", "revoke", ("access_token",)),
        ],
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    result = dict(
        changed=False,
        auth=dict(
            access_token=None,
            base_url=None,
        ),
    )

    falcon = OAuth2(**get_falconpy_credentials(module))

    if module.params.get("action") == "generate":
        query_result = generate(falcon)
        if query_result["status_code"] == 201:
            result.update(
                auth=dict(
                    access_token=falcon.token_value,
                    base_url=falcon.base_url,
                )
            )
    else:
        query_result = revoke(falcon, module.params["access_token"])

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
