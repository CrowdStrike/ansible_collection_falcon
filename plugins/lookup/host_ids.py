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
"""

RETURN = r"""
_raw:
  description:
    - A list of host IDs (AIDs) that match the search criteria.
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
    from falconpy import Hosts

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    Hosts = None
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

display = Display()


class LookupModule(LookupBase):
    """Lookup plugin for fetching host IDs based on filter expressions."""

    def _authenticate(self):
        """Authenticate to the CrowdStrike Falcon API."""
        return authenticate(Hosts, self.get_option)

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

            offset = host_lookup["body"]["meta"]["pagination"]["offset"]
            if host_lookup["body"]["meta"]["pagination"]["total"] <= len(host_ids):
                running = False

        return host_ids

    def run(self, terms, variables=None, **kwargs):
        """Fetch host IDs based on the provided filter expression."""
        check_falconpy("crowdstrike.falcon.host_ids")

        self.set_options(var_options=variables, direct=kwargs)

        falcon = self._authenticate()
        ret = []

        for term in terms:
            display.debug(f"Fetching host IDs with filter expression: {term}")
            try:
                display.vvv(f"FQL Filter used: {term}")
                ret.append(self._get_device_ids(falcon, term))
            except AnsibleError:
                raise
            except Exception as e:
                raise AnsibleError(f"Failed to fetch host IDs: {e}") from e

        return ret
