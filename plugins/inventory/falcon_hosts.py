# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
name: falcon_hosts
short_description: CrowdStrike Falcon Hosts inventory source
description:
  - Query asset details from the CrowdStrike Falcon Hosts API.
  - The inventory file is a YAML configuration and must end with C(falcon_hosts.{yml|yaml}).
  - "Example: C(my_inventory.falcon_hosts.yml)"
version_added: "4.3.0"
extends_documentation_fragment:
  - constructed
  - inventory_cache
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
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/page/c0b16f1b/host-and-host-group-management-apis#qadd6f8f)
        for more information about what filters are available for this inventory.
    type: str
requirements:
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0
notes:
  - If no credentials are provided, FalconPy will attempt to use the API credentials via environment variables.
  - The current behavior is to use the hostname if it exists, otherwise we will attemp to use either the external
    IP address or the local IP address. If neither of those exist, the host will be skipped as Ansible would not
    be able to connect to it.
author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
# sample file: my_inventory.falcon_hosts.yml

# required for all falcon_hosts inventory configs
plugin: crowdstrike.falcon.falcon_hosts

# authentication credentials (required if not using environment variables)
#client_id: 1234567890abcdef12345678
#client_secret: 1234567890abcdef1234567890abcdef12345
#cloud: us-1

# fql filter expression to limit results (by default all hosts are returned)
# examples below:

# return all Windows hosts
#filter: "platform_name:'Windows'"

# return stale devices that haven't checked in for 15 days
#filter: "last_seen:<='now-15d'"

# return all new Linux hosts within the past week
#filter: "first_seen:<='now-1w' + platform_name:'Linux'"

# return all hosts seen in the last 12 hours that are in RFM mode
#filter: "reduced_functionality_mode:'yes' + last_seen:>='now-12h'"

# return all Linux hosts running in eBPF User Mode
#filter: "linux_sensor_mode:'User Mode'"

# place hosts into dynamically created groups based on variable values
keyed_groups:
  # places host in a group named tag_<tags> for each tag on a host
  - prefix: tag
    key: tags
  # places host in a group named platform_<platform_name> based on the platform name (Linux, Windows, etc.)
  - prefix: platform
    key: platform_name
  # places host in a group named rfm_<Yes|No> to see if the host is in reduced functionality mode
  - prefix: rfm
    key: reduced_functionality_mode

# place hosts in named groups based on conditional statements <evaluated as true>
groups:
  # places hosts in a group named windows_hosts if the platform_name is Windows
  windows_hosts: "platform_name == 'Windows'"

  # place hosts in a group named aws_us_west_2 if the zone_group is in us-west-2
  aws_us_west_2: "'us-west-2' in zone_group and 'Amazon' in system_manufacturer"

# create and modify host variables from Jinja2 expressions
# compose:
#   # this sets the ansible_host variable to the external_ip address
#   ansible_host: external_ip
#   # this defines combinations of host servers, IP addresses, and related SSH private keys.
#   ansible_host: external_ip
#   ansible_user: "'root'"
#   ansible_ssh_private_key_file: "'/path/to/private_key_file'"

# caching is supported for this inventory plugin.
# caching can be configured in the ansible.cfg file or in the inventory file.
cache: true
cache_plugin: jsonfile
cache_connection: /tmp/falcon_inventory
cache_timeout: 1800
cache_prefix: falcon_hosts
"""

import os
import re
import traceback

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Hosts
    from falconpy._version import _VERSION

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """CrowdStrike Falcon Hosts dynamic inventory plugin for Ansible."""

    NAME = "crowdstrike.falcon.falcon_hosts"

    def verify_file(self, path):
        """Verify the inventory file."""
        if super().verify_file(path):
            if re.match(r".{0,}falcon_hosts\.(yml|yaml)$", path):
                return True
        return False

    def parse(self, inventory, loader, path, cache=True):
        """Parse the inventory file and return JSON data structure."""
        super().parse(inventory, loader, path)

        self._read_config_data(path)
        cache_key = self.get_cache_key(path)

        # Check if FalconPy is installed
        if not HAS_FALCONPY:
            raise ImportError(
                "The crowdstrike.falcon.falcon_hosts plugin requires falconpy to be installed."
            )

        # Check FalconPy version
        if _VERSION < "1.3.0":
            raise ImportError(
                "The crowdstrike.falcon.falcon_hosts plugin requires falconpy 1.3.0 or higher."
            )

        # cache may be True or False at this point to indicate if the inventory is being refreshed
        # get the user's cache option too to see if we should save the cache if it is changing
        user_cache_setting = self.get_option("cache")

        # read if the user has caching enabled and the cache isn't being refreshed
        attempt_to_read_cache = user_cache_setting and cache
        # update if the user has caching enabled and the cache is being refreshed; update this value to True if the cache has expired below
        cache_needs_update = user_cache_setting and not cache

        # attempt to read the cache if inventory isn't being refreshed and the user has caching enabled
        if attempt_to_read_cache:
            try:
                host_details = self._cache[cache_key]
            except KeyError:
                # This occurs if the cache_key is not in the cache or if the cache_key expired, so the cache needs to be updated
                cache_needs_update = True
        if not attempt_to_read_cache or cache_needs_update:
            # parse the provided inventory source
            falcon = self._authenticate()
            # Get the filter expression
            fql = self.get_option("filter")
            # Get host details
            host_details = self._get_host_details(falcon, fql)
        if cache_needs_update:
            self._cache[cache_key] = host_details

        # Add hosts to inventory
        self._add_host_to_inventory(host_details)

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

        # Make sure we have client_id and client_secret
        if "client_id" not in creds or "client_secret" not in creds:
            raise ValueError(
                "You must provide a client_id and client_secret to authenticate to the Falcon API."
            )

        return creds

    def _authenticate(self):
        """Authenticate to the CrowdStrike Falcon API."""
        creds = self._credential_setup()

        return Hosts(**creds)

    def _get_host_details(self, falcon, fql):
        """Query hosts from Falcon Discover."""
        max_limit = 5000  # Maximum limit allowed by Falcon Hosts Query API
        host_ids = []
        host_details = []
        running = True
        offset = None
        while running:
            host_lookup = falcon.query_devices_by_filter_scroll(filter=fql, offset=offset, limit=max_limit)
            if host_lookup["status_code"] != 200:
                raise SystemExit(
                    f"Unable to query hosts: {host_lookup['body']['errors']}"
                )

            if host_lookup["body"]["resources"]:
                host_ids = host_lookup["body"]["resources"]
            else:
                # No hosts found
                return host_details

            # Get host details
            details = falcon.get_device_details(ids=host_ids)["body"]["resources"]
            host_details.extend(details)

            # Check if we need to continue
            offset = host_lookup["body"]["meta"]["pagination"]["offset"]
            if host_lookup["body"]["meta"]["pagination"]["total"] <= len(host_details):
                running = False

        return host_details

    def _hostvars(self, host):
        """Return host variables."""
        hostvars = {}
        for key, value in host.items():
            hostvars[key] = value

        return hostvars

    def _get_ip_address(self, hostvars):
        """Return the IP address for a host."""
        ip_address = None
        if "external_ip" in hostvars:
            ip_address = hostvars["external_ip"]
        elif "local_ip" in hostvars:
            ip_address = hostvars["local_ip"]

        return ip_address

    def _get_hostname(self, hostvars):
        """Return the hostname for a host."""
        hostname = None

        if hostvars.get("hostname"):
            hostname = hostvars.get("hostname")
        else:
            # Use the IP address as the hostname if no hostname is available
            ipaddress = self._get_ip_address(hostvars)
            if ipaddress:
                hostname = ipaddress

        return hostname

    def _add_host_to_inventory(self, host_details):
        """Add host to inventory."""
        for host in host_details:
            hostvars = self._hostvars(host)

            # Get the hostname
            hostname = self._get_hostname(hostvars)
            if not hostname:
                # Skip the host if no hostname is available
                continue

            # Add the host to the inventory
            self.inventory.add_host(hostname)

            # Add host variables
            for key, value in hostvars.items():
                self.inventory.set_variable(hostname, key, value)

            # Add host groups
            strict = self.get_option("strict")
            self._set_composite_vars(self.get_option("compose"), hostvars, hostname, strict)

            # Create user-defined groups based on variables/jinja2 conditionals
            self._add_host_to_composed_groups(
                self.get_option("groups"), hostvars, hostname, strict
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"), hostvars, hostname, strict
            )
