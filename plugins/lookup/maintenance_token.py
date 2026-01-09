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

import traceback
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from ansible_collections.crowdstrike.falcon.plugins.plugin_utils.falconpy_utils import (
    authenticate,
    check_falconpy,
)


FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import SensorUpdatePolicy

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    SensorUpdatePolicy = None
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

display = Display()


class LookupModule(LookupBase):
    """Lookup plugin for fetching maintenance tokens."""

    def _authenticate(self):
        """Authenticate to the CrowdStrike Falcon API."""
        return authenticate(SensorUpdatePolicy, self.get_option)

    def _fetch_token(self, falcon, device_id):
        """Fetch maintenance token."""
        try:
            result = falcon.reveal_uninstall_token(
                audit_message="Ansible maintenance token lookup",
                device_id=device_id,
            )

            if result["status_code"] != 200:
                raise AnsibleError(
                    f"Unable to fetch maintenance token: {result['body']['errors']}"
                )

            return result["body"]["resources"][0]["uninstall_token"]
        except AnsibleError:
            raise
        except Exception as e:
            raise AnsibleError(f"Failed to fetch maintenance token: {e}") from e

    def run(self, terms, variables=None, **kwargs):
        """Fetch maintenance tokens for the provided device IDs."""
        check_falconpy("crowdstrike.falcon.maintenance_token")

        self.set_options(var_options=variables, direct=kwargs)

        falcon = self._authenticate()
        ret = []

        if self.get_option("bulk"):
            display.debug("Fetching bulk maintenance token")
            ret.append(self._fetch_token(falcon, "MAINTENANCE"))
        else:
            for term in terms:
                display.debug(f"Fetching maintenance token for device_id: {term}")
                ret.append(self._fetch_token(falcon, term))

        return ret
