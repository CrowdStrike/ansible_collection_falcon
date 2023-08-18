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
  - Useful when needing to make multiple API calls against multiple hosts. Helps to avoid
    rate limiting issues.
  - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis)
    for more information about OAuth2 authentication.

options:
  client_id:
    description:
      - The CrowdStrike API client ID to use.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#understanding-api-clients)
        for more information about API clients.
      - The C(FALCON_CLIENT_ID) environment variable can also be used.
    type: str
    aliases: [ falcon_client_id ]
  client_secret:
    description:
      - The CrowdStrike API secret that corresponds to the client ID.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#understanding-api-clients)
        for more information about API clients.
      - The C(FALCON_CLIENT_SECRET) environment variable can also be used.
    type: str
    aliases: [ falcon_client_secret ]
  member_cid:
    type: str
    description:
      - The CrowdStrike member CID for MSSP authentication.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#understanding-api-clients)
        for more information about API clients.
      - The C(FALCON_MEMBER_CID) environment variable can also be used.
  base_url:
    type: str
    description:
      - The CrowdStrike base address target for API operations performed using this class.
      - You can use either the short name or the full URL.
      - The C(FALCON_BASE_URL) environment variable can also be used.
    choices:
      - us-1
      - https://api.crowdstrike.com
      - us-2
      - https://api.us-2.crowdstrike.com
      - us-gov-1
      - https://api.laggar.gcw.crowdstrike.com
      - eu-1
      - https://api.eu-1.crowdstrike.com
  user_agent:
    type: str
    description:
      - Custom User-Agent string to use for requests to the API.
        The user agent string is prepended to the default user agent string
        (C(crowdstrike-ansible/<version>)).
      - See L(RFC 7231,https://tools.ietf.org/html/rfc7231#section-5.5.3) for more information.
      - The C(FALCON_USER_AGENT) environment variable can also be used.
  ext_headers:
    type: dict
    description:
      - Extended headers that are prepended to the default headers dictionary for
        the newly created Service Class.
      - See the L(FalconPy documentation,https://www.falconpy.io/Usage/Environment-Configuration.html#extended-headers)
        for more information about extended headers

requirements:
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get OAuth2 token
  crowdstrike.falcon.oauth2_token:
    client_id: 1234567890abcdef12345678
    client_secret: 1234567890abcdef1234567890abcdef12345678

- name: Get OAuth2 token with member CID
  crowdstrike.falcon.oauth2_token:
    client_id: 1234567890abcdef12345678
    client_secret: 1234567890abcdef1234567890abcdef12345678
    member_cid: 1234567890abcdef12345678
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
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    handle_return_errors,
)

try:
    from falconpy import OAuth2
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_FALCONPY = True


def argspec():
    """Define the modules's argument spec."""
    args = falconpy_arg_spec()
    # Remove the "access_token" argument from the spec
    args.pop("access_token")

    return args


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
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
        handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
