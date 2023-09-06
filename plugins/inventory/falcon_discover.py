# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
name: crowdstrike.falcon.falcon_discover
short_description: CrowdStrike Falcon Discover inventory source
description:
  - Query asset details from the CrowdStrike Falcon Discover API. To learn more about Falcon Discover and
    Exposure Management, see the
    L(Falcon documentation,https://falcon.crowdstrike.com/documentation/page/f2197af5/asset-management-overview-discover)
  - The inventory file is a YAML configuration and must end with C(falcon_discover.{yml|yaml}).
  - "Example: C(my_inventory.falcon_discover.yml)"
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
  filter:
    description:
      - The filter expression that should be used to limit the results using FQL
        (Falcon Query Language) syntax.
    type: str
requirements:
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0
notes:
  - If no credentials are provided, FalconPy will attempt to use the API credentials via environment variables.
author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
# Minimal example - Get all hosts (assume credentials are provided via environment variables)
plugin: crowdstrike.falcon.falcon_discover

# Get unmanaged hosts within the past day(passing credentials)
plugin: crowdstrike.falcon.falcon_discover
client_id: 1234567890abcdef12345678
client_secret: 1234567890abcdef1234567890abcdef12345
cloud: us-1
filter: "entity_type:'unmanaged'+first_seen_timestamp:>'now-1d'"
"""

import os
import re
import traceback

from ansible.plugins.inventory import BaseInventoryPlugin

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Discover
    from falconpy._version import _VERSION
    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

class InventoryModule(BaseInventoryPlugin):
    """CrowdStrike Falcon Discover dynamic inventory plugin for Ansible."""

    NAME = "crowdstrike.falcon.falcon_discover"

    def verify_file(self, path):
        if super(InventoryModule, self).verify_file(path):
            if re.match(r'.{0,}falcon_discover\.(yml|yaml)$', path):
                return True
        return False

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
                    creds["base_url"] = value
                else:
                    creds[key] = value

        if not creds["client_id"] or not creds["client_secret"]:
            # Fail if no credentials are provided
            raise ValueError(
                "Missing required parameters: client_id, client_secret. See module documentation for help."
            )

        return creds

    def _authenticate(self):
        """Authenticate to the CrowdStrike Falcon API."""
        creds = self._credential_setup()

        return Discover(**creds)


    def _get_host_details(self, falcon, fql):
        """Query hosts from Falcon Discover."""
        max_limit = 100  # Maximum limit allowed by Falcon Discover
        host_ids = []
        host_details = []
        running = True
        offset = None
        while running:
            host_lookup = falcon.query_hosts(filter=fql, offset=offset, limit=max_limit)
            if host_lookup["status_code"] != 200:
                raise SystemExit(
                    "Unable to query hosts from Falcon Discover."
                )

            if host_lookup["body"]["resources"]:
                host_ids = host_lookup["body"]["resources"]
            else:
                raise SystemExit(
                    "No hosts were identified by the filter expression."
                )

            # Get host details
            details = falcon.get_hosts(ids=host_ids)["body"]["resources"]
            host_details.extend(details)

            # Check if we need to continue
            offset = host_lookup["body"]["meta"]["pagination"]["offset"] + max_limit
            if host_lookup["body"]["meta"]["pagination"]["total"] <= len(host_details):
                running = False

        return host_details


    def _hostvars(self, host):
        """Return host variables."""
        # todo: this is a common list of fields that are returned by the FalconPy API
        hostvar_mapping = {
            "id": "id",
            "cid": "cid",
            "aid": "aid",
            "hostname": "hostname",
            "asset_type": "entity_type",
            "first_seen": "first_seen_timestamp",
            "last_seen": "last_seen_timestamp",
            "country": "country",
            "city": "city",
            "os_name": "platform_name",
            "os_version": "os_version",
            "kernel_version": "kernel_version",
            "tags": "tags",
            "groups": "groups",
            "sensor_version": "agent_version",
            "public_ip": "external_ip",
            "private_ip": "current_local_ip",
            "rfm": "reduced_functionality_mode",
            "mac_address": "mac_address",
            "fqdn": "fqdn",
            "location": "location",
            "state": "state",
            "confidence": "confidence",
            "managed_by": "managed_by",
            "owned_by": "owned_by",
            "used_for": "used_for",
            "department": "department",
            "cloud_provider": "cloud_provider",
            "cloud_account_id": "cloud_account_id",
            "cloud_region": "cloud_region",
            "cloud_resource_id": "cloud_resource_id",
            "cloud_registered": "cloud_registered",
            "cloud_instance_id": "cloud_instance_id",
        }

        hostvars = {}
        for key, value in hostvar_mapping.items():
            if value in host:
                hostvars[key] = host[value]

        return hostvars


    def _get_ip_address(self, hostvars):
        """Return the IP address for a host."""
        ip_address = None
        if "public_ip" in hostvars:
            ip_address = hostvars["public_ip"]
        elif "private_ip" in hostvars:
            ip_address = hostvars["private_ip"][0]

        return ip_address


    def _get_hostname(self, hostvars):
        """Return the hostname for a host."""
        hostname = hostvars.get("hostname", "unknown")

        return hostname


    def parse(self, inventory, loader, path, cache=True):
        """Parse the inventory file and return JSON data structure."""
        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)

        # Check if FalconPy is installed
        if not HAS_FALCONPY:
            raise ImportError(
                "The crowdstrike.falcon.falcon_discover plugin requires falconpy to be installed."
            )

        # Check FalconPy version
        if _VERSION < "1.3.0":
            raise ImportError(
                "The crowdstrike.falcon.falcon_discover plugin requires falconpy 1.3.0 or higher."
            )

        falcon = self._authenticate()

        # Get the filter expression
        fql = self.get_option("filter")

        # Get host details
        host_details = self._get_host_details(falcon, fql)

        # Add hosts to inventory
        for host in host_details:
            hostvars = self._hostvars(host)
            # Only process hosts that have an IP address (reachable)?
            ip_address = self._get_ip_address(hostvars)
            if not ip_address:
                continue

            # Get the hostname
            hostname = self._get_hostname(hostvars)

            # Add the host to the inventory
            self.inventory.add_host(hostname)
            self.inventory.set_variable(hostname, "ansible_host", ip_address)

            # Add host variables
            for key, value in hostvars.items():
                self.inventory.set_variable(hostname, key, value)
