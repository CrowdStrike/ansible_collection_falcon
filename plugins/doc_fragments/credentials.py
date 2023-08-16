# -*- coding: utf-8 -*-

# Copyright: (c) 2017,  Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    """Module doc fragment for credentials"""

    # Plugin options for CrowdStrike Falcon API credentials
    DOCUMENTATION = r'''
options:
  client_id:
    description:
      - The CrowdStrike API client ID to use.
      - See the FalconPy documentation for more information about authenticating
      - U(https://www.falconpy.io/Usage/Authenticating-to-the-API.html)
      - The C(FALCON_CLIENT_ID) environment variable can also be used.
    type: str
    aliases: [ falcon_client_id ]
  client_secret:
    description:
      - The CrowdStrike API secret that corresponds to the client ID.
      - See the FalconPy documentation for more information about authenticating
      - U(https://www.falconpy.io/Usage/Authenticating-to-the-API.html)
      - The C(FALCON_CLIENT_SECRET) environment variable can also be used.
    type: str
    aliases: [ falcon_client_secret ]
  member_cid:
    type: str
    description:
      - The CrowdStrike member CID for MSSP authentication.
      - See the FalconPy documentation for more information about authenticating
      - U(https://www.falconpy.io/Usage/Authenticating-to-the-API.html)
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
      - See the FalconPy documentation for more information about specifying a base URL
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#base-url)
      - The C(FALCON_BASE_URL) environment variable can also be used.
    default: US1
  proxy:
    type: dict
    description:
      - A dictionary containing a list of proxy servers to utilize for making requests
        to the CrowdStrike API.
      - See the FalconPy documentation for more information about proxy configuration
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#proxy)
    suboptions:
      http:
        description:
          - The proxy server to utilize for making HTTP requests.
        type: str
      https:
        description:
          - The proxy server to utilize for making HTTPS requests.
        type: str
  pythonic:
    type: bool
    description:
      - Flag indicating that API responses received using this class should be
        delivered as L(Python Objects,https://www.falconpy.io/Usage/Response-Handling#pythonic-responses)
        as opposed to JSON dictionaries.
      - See the FalconPy documentation for more information about Pythonic responses
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#enabling-pythonic-responses)
      - The C(FALCON_PYTHONIC) environment variable can also be used.
  renew_window:
    type: int
    description:
      - Amount of buffer time allotted before token expiration where a token is
        refreshed automatically.
      - See the FalconPy documentation for more information about token renewal
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#renew-window)
      - The C(FALCON_RENEW_WINDOW) environment variable can also be used.
  ssl_verify:
    type: bool
    description:
      - Boolean flag used to specify SSL verification configuration, or a string
        representing the path to a CA_BUNDLE file or directory with certificates of trusted CAs.
      - When set to False, API requests will accept any TLS certificate presented, and
        will ignore hostname mismatches and/or expired certificates.
      - See the FalconPy documentation for more information about SSL verification
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#ssl-verify)
      - The C(FALCON_SSL_VERIFY) environment variable can also be used.
  timeout:
    type: float
    description:
      - Connect / Read or Total timeout for requests made to the CrowdStrike API.
      - See the FalconPy documentation for more information about request timeouts
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#timeout)
      - The C(FALCON_TIMEOUT) environment variable can also be used.
  user_agent:
    type: str
    description:
      - Custom User-Agent string to use for requests to the API.
      - See the FalconPy documentation for more information about custom User-Agent strings
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#user-agent)
      - The C(FALCON_USER_AGENT) environment variable can also be used.
    default: crowdstrike-ansible/VERSION
  ext_headers:
    type: dict
    description:
      - Extended headers that are prepended to the default headers dictionary for
        the newly created Service Class.
      - See the FalconPy documentation for more information about extended headers
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#extended-headers)
      - The C(FALCON_EXT_HEADERS) environment variable can also be used.
  validate_payloads:
    type: bool
    description:
      - Flag indicating that payloads should be validated before the API request
        is performed.
      - See the FalconPy documentation for more information about validating payloads
      - U(https://www.falconpy.io/Usage/Environment-Configuration.html#validating-payloads)
      - The C(FALCON_VALIDATE_PAYLOADS) environment variable can also be used.
'''
