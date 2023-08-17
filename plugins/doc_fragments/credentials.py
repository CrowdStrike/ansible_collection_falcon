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
      - See the L(Falcon Docs,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#api-clients)
        for more information about creating API clients.
      - The C(FALCON_CLIENT_ID) environment variable can also be used.
    type: str
    aliases: [ falcon_client_id ]
  client_secret:
    description:
      - The CrowdStrike API secret that corresponds to the client ID.
      - See the L(Falcon Docs,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#api-clients)
        for more information about creating API clients.
      - The C(FALCON_CLIENT_SECRET) environment variable can also be used.
    type: str
    aliases: [ falcon_client_secret ]
  member_cid:
    type: str
    description:
      - The CrowdStrike member CID for MSSP authentication.
      - See the L(Falcon Docs,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#api-clients)
        for more information about creating API clients.
      - The C(FALCON_MEMBER_CID) environment variable can also be used.
  access_token:
    type: str
    description:
      - The CrowdStrike API access token to use instead of client ID and secret.
      - This must also be used with I(base_url).
  base_url:
    type: str
    description:
      - The CrowdStrike base address target for API operations performed using this class.
      - The C(FALCON_BASE_URL) environment variable can also be used.
    choices:
      - us-1 | https://api.crowdstrike.com
      - us-2 | https://api.us-2.crowdstrike.com
      - us-gov-1 | https://api.laggar.gcw.crowdstrike.com
      - eu-1 | https://api.eu-1.crowdstrike.com
  user_agent:
    type: str
    description:
      - Custom User-Agent string to use for requests to the API.
        The user agent string is prepended to the default user agent string.
      - See L(RFC 7231,https://tools.ietf.org/html/rfc7231#section-5.5.3) for more information.
      - The C(FALCON_USER_AGENT) environment variable can also be used.
    default: crowdstrike-ansible/VERSION
  ext_headers:
    type: dict
    description:
      - Extended headers that are prepended to the default headers dictionary for
        the newly created Service Class.
      - See the L(FalconPy documentation,https://www.falconpy.io/Usage/Environment-Configuration.html#extended-headers)
        for more information about extended headers
      - The C(FALCON_EXT_HEADERS) environment variable can also be used.
"""
