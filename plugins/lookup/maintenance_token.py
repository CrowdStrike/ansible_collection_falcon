# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: maintenance_token

short_description: fetch maintenance token

version_added: "4.4.0"

description:
  - This lookup returns a maintenance token which can be used for uninstalls and other maintenance
    operations not done by the Falcon platform.

options:
  _terms:
    description:
      - The host ID (AID) for which the maintenance token should be fetched.
      - If O(bulk) is set to true, this parameter is ignored.
  bulk:
    description:
      - Retrieve a bulk maintenance token.
    type: bool
    default: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials

requirements:
  - Sensor update policies [B(WRITE)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Print maintenance token for a specific host
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.maintenance_token', '12345678901234567890') }}"

- name: Print maintenance token for multiple hosts
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.maintenance_token', '12345678901234567890', '09876543210987654321') }}"

- name: Print bulk maintenance token
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.maintenance_token', bulk=true) }}"
"""

RETURN = r"""
_raw:
  description: One or more maintenance tokens.
  type: list
  elements: str
"""

import os
import traceback
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display


FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import SensorUpdatePolicy
    from falconpy._version import _VERSION

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

display = Display()


class LookupModule(LookupBase):
    """Lookup plugin for fetching host IDs based on filter expressions."""

    def _credential_setup(self):
        """Setup credentials for FalconPy."""
        cred_mapping = {
            "client_id": "FALCON_CLIENT_ID",
            "client_secret": "FALCON_CLIENT_SECRET",
            "member_cid": "FALCON_MEMBER_CID",
            "cloud": "FALCON_CLOUD",
        }

        creds = {}
        for key, env in cred_mapping.items():
            value = self.get_option(key) or os.getenv(env)
            if value:
                if key == "cloud":
                    self._verify_cloud(value)
                    creds["base_url"] = value
                else:
                    creds[key] = value

        # Make sure we have client_id and client_secret
        if "client_id" not in creds or "client_secret" not in creds:
            raise AnsibleError(
                "You must provide a client_id and client_secret to authenticate to the Falcon API."
            )

        return creds

    def _verify_cloud(self, cloud):
        """Verify the cloud region."""
        valid_clouds = ["us-1", "us-2", "eu-1", "us-gov-1"]
        if cloud not in valid_clouds:
            raise AnsibleError(
                f"Invalid cloud region: '{cloud}'. Valid values are {', '.join(valid_clouds)}"
            )

    def _authenticate(self):
        """Authenticate to the CrowdStrike Falcon API."""
        creds = self._credential_setup()

        return SensorUpdatePolicy(**creds)

    def _fetch_token(self, falcon, device_id):
        """Fetch maintenance token"""
        token = None
        try:
            result = falcon.reveal_uninstall_token(
                audit_message="Ansible maintenance token lookup",
                device_id=device_id,
            )

            if result["status_code"] != 200:
                raise AnsibleError(
                    f"Unable to fetch maintenance token: {result['body']['errors']}"
                )

            token = result["body"]["resources"][0]["uninstall_token"]
        except Exception as e:
            raise AnsibleError(f"Failed to fetch bulk maintenance token: {e}") from e

        return token

    def run(self, terms, variables=None, **kwargs):
        """Fetch host IDs based on the provided filter expression."""

        # Check if the 'falconpy' library is installed
        if not HAS_FALCONPY:
            raise AnsibleError(
                "The 'crowdstrike.falcon.maintenance_token' lookup cannot be run because the 'falconpy' library is not installed."
            )

        # Check if the 'falconpy' library is compatible
        if _VERSION < "1.3.0":
            raise AnsibleError(
                f"Unsupported FalconPy version: {_VERSION}. Upgrade to 1.3.0 or higher."
            )

        self.set_options(var_options=variables, direct=kwargs)

        falcon = self._authenticate()
        ret = []

        # Check if we should fetch a bulk maintenance token
        if self.get_option("bulk"):
            display.debug("Fetching bulk maintenance token")
            ret.append(self._fetch_token(falcon, "MAINTENANCE"))
        else:
            for term in terms:
                display.debug(f"Fetching maintenance token for device_id: {term}")
                ret.append(self._fetch_token(falcon, term))

        return ret
