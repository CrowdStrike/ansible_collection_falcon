#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: auth

short_description: Manage authentication

version_added: "4.0.0"

description:
  - Manage token authentication with CrowdStrike Falcon API.
  - Utilizing access tokens can enhance efficiency when making multiple API calls
    helping to circumvent rate-limiting constraints.
  - The module will not report changes.
  - Refer to the
    L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis)
    for detailed information on OAuth2 authentication with CrowdStrike Falcon.

options:
  action:
    description:
      - Define the action to be performed.
      - When I(action=generate), this module returns authentication credentials,
        which include the OAuth2 access token and cloud region.
      - When I(action=revoke), this module revokes the OAuth2 token specified in
        the I(access_token) parameter.
    type: str
    choices:
      - generate
      - revoke
    default: generate
  access_token:
    description:
      - The OAuth2 access token to be revoked.
      - Required if I(action=revoke).
    type: str

extends_documentation_fragment:
  - crowdstrike.falcon.credentials

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Generate Authentication Credentials (access token and cloud region)
  crowdstrike.falcon.auth:

- name: Generate Authentication Credentials with specific member CID
  crowdstrike.falcon.auth:
    member_cid: "{{ member_cid_var }}"

- name: Revoke an OAuth2 token
  crowdstrike.falcon.auth:
    action: revoke
    access_token: "{{ access_token_var }}"
"""

RETURN = r"""
auth:
  description: The authentication credentials (OAuth2 access token and cloud region).
  returned: success
  type: dict
  contains:
    access_token:
      description:
        - The generated OAuth2 access token.
        - Returned when action is set to C(generate).
      returned: success
      type: str
    cloud:
      description:
        - The CrowdStrike cloud region to use. This may differ from the module's
          I(cloud) argument due to the autodiscovery process.
        - Returned when action is set to C(generate).
      returned: success
      type: str
"""


import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    get_falconpy_credentials,
    handle_return_errors,
    get_cloud_from_url,
    check_falconpy_version,
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

    check_falconpy_version(module)

    result = dict(
        changed=False,
        auth=dict(
            access_token=None,
            cloud=None,
        ),
    )

    falcon = OAuth2(**get_falconpy_credentials(module))

    if module.params.get("action") == "generate":
        query_result = generate(falcon)
        if query_result["status_code"] == 201:
            result.update(
                auth=dict(
                    access_token=falcon.token_value,
                    cloud=get_cloud_from_url(module, falcon.base_url),
                )
            )
    else:
        query_result = revoke(falcon, module.params["access_token"])

    handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
