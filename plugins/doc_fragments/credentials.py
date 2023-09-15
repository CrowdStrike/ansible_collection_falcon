# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    """Module doc fragment for credentials"""

    # Plugin options for CrowdStrike Falcon API credentials
    DOCUMENTATION = r"""
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
    description:
      - The CrowdStrike member CID for MSSP authentication.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#understanding-api-clients)
        for more information about API clients.
      - The C(FALCON_MEMBER_CID) environment variable can also be used.
    type: str
  cloud:
    description:
      - The CrowdStrike cloud region to use.
      - All clouds are automatically discovered if not specified, except for the C(us-gov-1) cloud.
      - The C(FALCON_CLOUD) environment variable can also be used.
    choices:
      - us-1
      - us-2
      - us-gov-1
      - eu-1
    default: us-1
    type: str
  user_agent:
    description:
      - Custom User-Agent string to use for requests to the API.
      - The user agent string is prepended to the default user agent string
        (C(crowdstrike-ansible/<version>)).
      - See L(RFC 7231,https://tools.ietf.org/html/rfc7231#section-5.5.3) for more information.
      - The C(FALCON_USER_AGENT) environment variable can also be used.
    type: str
  ext_headers:
    description:
      - Extended headers that are prepended to the default headers dictionary.
    type: dict
requirements:
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0
"""

    AUTH = r"""
options:
  auth:
    description:
      - The registered result of the M(crowdstrike.falcon.auth) module, or a dictionary containing
        the I(access_token) and I(cloud) keys.
      - If provided, the I(client_id), I(client_secret), I(member_cid), and I(cloud) options are ignored.
      - Useful when needing to make multiple API calls to avoid rate limiting issues.
    type: dict
    suboptions:
      access_token:
        description:
          - The OAuth2 access token to use for authentication.
        type: str
      cloud:
        description:
          - The CrowdStrike cloud region to use.
          - This can differ from the module's I(cloud) argument due to autodiscovery.
        type: str
"""
