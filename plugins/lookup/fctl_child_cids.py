# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: fctl_child_cids

short_description: fetch Flight Control child CIDs

version_added: "4.5.0"

description:
  - This lookup returns a list of Flight Control child CIDs from your given parent credentials.
  - You can further limit the results by passing in a secondary parent CID.

options:
  _terms:
    description:
      - Optionally pass in a secondary parent CID to limit the results.
      - If no terms are passed in, all child CIDs associated with the parent credentials will be returned.

extends_documentation_fragment:
  - crowdstrike.falcon.credentials

notes:
  - This plugin will automatically handle pagination for you, so you do not need to worry about it.

requirements:
  - Flight Control [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Print all child CIDs
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.fctl_child_cids') }}"

- name: Print all child CIDs for a secondary parent CID
  ansible.builtin.debug:
    msg: "{{ lookup('crowdstrike.falcon.fctl_child_cids', '123456789abcdefg') }}"

- name: Get information about all child CIDs
  crowdstrike.falcon.fctl_child_cid_info:
    cids: "{{ lookup('crowdstrike.falcon.fctl_child_cids') }}"
"""

RETURN = r"""
_raw:
  description:
    - A list of Flight Control child CIDs.
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
    from falconpy import FlightControl
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

        return FlightControl(**creds)

    def _get_child_cids(self, falcon, term):
        """Fetch Flight Control child CIDs based on the provided filter expression."""
        max_limit = 1000
        child_cids = []
        running = True
        offset = None
        while running:
            child_lookup = falcon.query_children(filter=term, offset=offset, limit=max_limit)
            if child_lookup["status_code"] != 200:
                raise AnsibleError(
                    f"Unable to query children: {child_lookup['body']['errors']}"
                )

            if child_lookup["body"]["resources"]:
                child_cids.extend(child_lookup["body"]["resources"])
            else:
                return child_cids

            # Check if we need to continue
            offset = child_lookup["body"]["meta"]["pagination"]["offset"]
            if child_lookup["body"]["meta"]["pagination"]["total"] <= len(child_cids):
                running = False

        return child_cids

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

        # Handle case where no terms are provided
        if not terms:
            display.debug("Fetching all child CIDs")
            try:
                ret = self._get_child_cids(falcon, None)
            except Exception as e:  # pylint: disable=broad-except
                raise AnsibleError(f"Failed to fetch child CIDs: {e}") from e
        else:
            for term in terms:
                # Fetch child CIDs based on the provided filter expression
                cid_term = f"cid:'{term}'"
                display.debug(f"Fetching child CIDs with filter expression: {cid_term}")
                try:
                    # Fetch child CIDs based on the provided filter expression
                    display.vvv(f"FQL Filter used: {cid_term}")
                    ret.append(self._get_child_cids(falcon, cid_term))
                except Exception as e:  # pylint: disable=broad-except
                    raise AnsibleError(f"Failed to fetch child CIDs: {e}") from e

        return ret
