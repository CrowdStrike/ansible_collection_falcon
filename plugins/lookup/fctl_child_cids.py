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
    from falconpy import FlightControl

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FlightControl = None
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

display = Display()


class LookupModule(LookupBase):
    """Lookup plugin for fetching Flight Control child CIDs."""

    def _authenticate(self):
        """Authenticate to the CrowdStrike Falcon API."""
        return authenticate(FlightControl, self.get_option)

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

            offset = child_lookup["body"]["meta"]["pagination"]["offset"]
            if child_lookup["body"]["meta"]["pagination"]["total"] <= len(child_cids):
                running = False

        return child_cids

    def run(self, terms, variables=None, **kwargs):
        """Fetch Flight Control child CIDs."""
        check_falconpy("crowdstrike.falcon.fctl_child_cids")

        self.set_options(var_options=variables, direct=kwargs)

        falcon = self._authenticate()
        ret = []

        if not terms:
            display.debug("Fetching all child CIDs")
            try:
                ret = self._get_child_cids(falcon, None)
            except AnsibleError:
                raise
            except Exception as e:
                raise AnsibleError(f"Failed to fetch child CIDs: {e}") from e
        else:
            for term in terms:
                cid_term = f"cid:'{term}'"
                display.debug(f"Fetching child CIDs with filter expression: {cid_term}")
                try:
                    display.vvv(f"FQL Filter used: {cid_term}")
                    ret.append(self._get_child_cids(falcon, cid_term))
                except AnsibleError:
                    raise
                except Exception as e:
                    raise AnsibleError(f"Failed to fetch child CIDs: {e}") from e

        return ret
