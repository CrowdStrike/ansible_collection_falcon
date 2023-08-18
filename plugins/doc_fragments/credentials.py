# -*- coding: utf-8 -*-

# Copyright: (c) 2017,  Ansible Project
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
  access_token:
    description:
      - The CrowdStrike API access token to use instead of client ID and secret.
      - This must also be used with I(base_url).
    type: str
  base_url:
    description:
      - The CrowdStrike base address target for API operations performed using this class.
      - You can use either the short name or the full URL.
      - The C(FALCON_BASE_URL) environment variable can also be used.
    type: str
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
    description:
      - Custom User-Agent string to use for requests to the API.
        The user agent string is prepended to the default user agent string
        (C(crowdstrike-ansible/<version>)).
      - See L(RFC 7231,https://tools.ietf.org/html/rfc7231#section-5.5.3) for more information.
      - The C(FALCON_USER_AGENT) environment variable can also be used.
    type: str
  ext_headers:
    description:
      - Extended headers that are prepended to the default headers dictionary for
        the newly created Service Class.
    type: dict
requirements:
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0
"""
