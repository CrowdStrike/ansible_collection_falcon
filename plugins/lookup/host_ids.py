# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: host_ids

short_description: fetch host IDs (AIDs)

version_added: "4.4.0"

description:
  - This lookup returns a list of host IDs (AIDs) which match the search criteria.
  - You can use optional FQL filters in your requests to find host IDs based on specific
    attributes, such as platform, hostname, or IP.
  - Can be used for other modules that require a list of host IDs as input.

options:
  _terms:
    description:
      - The filter expression that should be used to limit the results using FQL (Falcon Query Language) syntax.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/page/c0b16f1b/host-and-host-group-management-apis#qadd6f8f)
        for more information about the available filters.

extends_documentation_fragment:
  - crowdstrike.falcon.credentials

notes:
  - This plugin will automatically handle pagination for you, so you do not need to worry about it.
  - You can avoid escaping double quotes by using a multiline string or setting a variable. See examples.

requirements:
  - Hosts [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Print all hosts IDs
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.host_ids', '') }}"

- name: Print all Windows hosts IDs (escaped double quotes)
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.host_ids', 'platform_name:\"Windows\"') }}"

- name: Print all Linux hosts IDs in reduced functionality mode (multiline string)
  ansible.builtin.debug:
    msg: >
      {{
        lookup('crowdstrike.falcon.host_ids',
          'platform_name:"Linux"
          + reduced_functionality_mode:"yes"')
      }}

- name: Hide stale devices that haven't been seen in 15 days (using a filter variable)
  crowdstrike.falcon.host_hide:
    hidden: true
    hosts: "{{ lookup('crowdstrike.falcon.host_ids', stale_filter) }}"
  vars:
    stale_filter: 'last_seen:<="now-15d"'
"""

RETURN = r"""
_raw:
  description:
    - A list of host IDs (AIDs) that match the search criteria.
  type: list
  returned: success
  elements: str
"""

import os
import traceback
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display


FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Hosts
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

        return Hosts(**creds)

    def _get_device_ids(self, falcon, term):
        """Fetch host IDs based on the provided filter expression."""
        max_limit = 5000
        host_ids = []
        running = True
        offset = None
        while running:
            host_lookup = falcon.query_devices_by_filter_scroll(filter=term, offset=offset, limit=max_limit)
            if host_lookup["status_code"] != 200:
                raise AnsibleError(
                    f"Unable to query hosts: {host_lookup['body']['errors']}"
                )

            if host_lookup["body"]["resources"]:
                host_ids.extend(host_lookup["body"]["resources"])
            else:
                return host_ids

            # Check if we need to continue
            offset = host_lookup["body"]["meta"]["pagination"]["offset"]
            if host_lookup["body"]["meta"]["pagination"]["total"] <= len(host_ids):
                running = False

        return host_ids

    def run(self, terms, variables=None, **kwargs):
        """Fetch host IDs based on the provided filter expression."""

        # Check if the 'falconpy' library is installed
        if not HAS_FALCONPY:
            raise AnsibleError(
                "The 'crowdstrike.falcon.host_ids' lookup cannot be run because the 'falconpy' library is not installed."
            )

        # Check if the 'falconpy' library is compatible
        if _VERSION < "1.3.0":
            raise AnsibleError(
                f"Unsupported FalconPy version: {_VERSION}. Upgrade to 1.3.0 or higher."
            )

        self.set_options(var_options=variables, direct=kwargs)

        falcon = self._authenticate()
        ret = []

        for term in terms:
            display.debug(f"Fetching host IDs with filter expression: {term}")
            try:
                # Fetch host IDs based on the provided filter expression
                display.vvv(f"FQL Filter used: {term}")
                ret.append(self._get_device_ids(falcon, term))
            except Exception as e:  # pylint: disable=broad-except
                raise AnsibleError(f"Failed to fetch host IDs: {e}") from e

        return ret
