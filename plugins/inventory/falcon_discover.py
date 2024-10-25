# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
name: falcon_discover
short_description: CrowdStrike Falcon Discover inventory source
description:
  - Query asset details from the CrowdStrike Falcon Discover API. To learn more about Falcon Discover and
    Exposure Management, see the
    L(Falcon documentation,https://falcon.crowdstrike.com/documentation/page/f2197af5/asset-management-overview-discover)
  - The inventory file is a YAML configuration and must end with C(falcon_discover.{yml|yaml}).
  - "Example: C(my_inventory.falcon_discover.yml)"
version_added: "4.0.0"
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
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/page/a9df69ec/asset-management-apis#t0e123bd)
        for more information about what filters are available for this inventory.
    type: str
  allow_duplicates:
    description:
      - Allow duplicate hosts to be added to the inventory by adding the asset ID as a suffix to the hostname.
      - By default, duplicate hostnames are not allowed.
    type: bool
    default: false
requirements:
  - Assets [B(READ)] API scope
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0
notes:
  - If no credentials are provided, FalconPy will attempt to use the API credentials via environment variables.
  - Hostnames are set to the C(hostname) hostvar if it exists, otherwise the IP address is used.
  - The current behavior for assigning an IP address to a host is to use the external IP address if it exists,
    otherwise the current local IP address is used. If neither of those exist, the host is skipped as Ansible
    would not be able to connect to it.
author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
# sample file: my_inventory.falcon_discover.yml

# required for all falcon_discover inventory configs
plugin: crowdstrike.falcon.falcon_discover

# authentication credentials (required if not using environment variables)
#client_id: 1234567890abcdef12345678
#client_secret: 1234567890abcdef1234567890abcdef12345
#cloud: us-1

# fql filter expression to limit results (by default all assets are returned)
# examples below:

# return unmanaged assets discovered in the past day
#filter: "entity_type:'unmanaged'+first_seen_timestamp:>'now-1d'"

# return all new assets within the past week
#filter: "first_seen_timestamp:>'now-1w'"

# return all assets that have been seen in the past 3 days
#filter: "last_seen_timestamp:>'now-3d'"

# return all assets seen in the last 12 hours that are in RFM mode
#filter: "reduced_functionality_mode:Yes+last_seen_timestamp:>'now-12h'"

# return all AWS assets
#filter: "cloud_provider:'AWS'"

# allow duplicate hostnames to be added to the inventory
# example: If you two hosts with the same hostname, they will be added as:
#     hostnameA
#     hostnameA_1234567890abcdef12345678
#
#allow_duplicates: true

# place hosts into dynamically created groups based on variable values
keyed_groups:
  # places host in a group named cloud_<cloud_provider> (e.g. cloud_AWS) if the asset is a cloud asset
  - prefix: cloud
    key: cloud_provider
  # places host in a group named platform_<platform_name> based on the platform name (Linux, Windows, etc.)
  - prefix: platform
    key: platform_name
  # places host in a group named tag_<tags> for each tag on a host
  - prefix: tag
    key: tags
  # places host in a group named rfm_<Yes|No> to see if the host is in reduced functionality mode
  - prefix: rfm
    key: reduced_functionality_mode
  # places host in a group named location_<city> based on the city the host is located in
  - prefix: location
    key: city

# place hosts in named groups based on conditional statements <evaluated as true>
groups:
  # places host in a group named unmanaged_assets if the entity_type is unmanaged
  unmanaged_assets: "entity_type == 'unmanaged'"
  # places host in a group named cloud_assets if the entity_type is cloud
  cloud_assets: "cloud_provider != None"

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
cache_prefix: falcon_discover
"""

import os
import re
import traceback

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Discover
    from falconpy._version import _VERSION

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """CrowdStrike Falcon Discover dynamic inventory plugin for Ansible."""

    NAME = "crowdstrike.falcon.falcon_discover"

    def verify_file(self, path):
        """Verify the inventory file."""
        if super().verify_file(path):
            if re.match(r".{0,}falcon_discover\.(yml|yaml)$", path):
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
                "The crowdstrike.falcon.falcon_discover plugin requires falconpy to be installed."
            )

        # Check FalconPy version
        if _VERSION < "1.3.0":
            raise ImportError(
                "The crowdstrike.falcon.falcon_discover plugin requires falconpy 1.3.0 or higher."
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
                    f"Unable to query hosts: {host_lookup['body']['errors']}"
                )

            if host_lookup["body"]["resources"]:
                host_ids = host_lookup["body"]["resources"]
            else:
                # No hosts found
                return host_details

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
        hostvar_opts = [
            "id",
            "cid",
            "aid",
            "hostname",
            "entity_type",
            "first_seen_timestamp",
            "last_seen_timestamp",
            "country",
            "city",
            "platform_name",
            "os_version",
            "kernel_version",
            "tags",  # list
            "groups",
            "agent_version",
            "external_ip",
            "current_local_ip",
            "local_ip_addresses",  # list
            "reduced_functionality_mode",
            "mac_address",
            "fqdn",
            "location",
            "state",
            "confidence",
            "managed_by",
            "owned_by",
            "used_for",
            "department",
            "cloud_provider",
            "cloud_account_id",
            "cloud_region",
            "cloud_resource_id",
            "cloud_registered",
            "cloud_instance_id",
        ]

        hostvars = {}
        for item in hostvar_opts:
            if item in host:
                hostvars[item] = host[item]

        return hostvars

    def _get_ip_address(self, hostvars):
        """Return the IP address for a host."""
        ip_address = None
        if "external_ip" in hostvars:
            ip_address = hostvars["external_ip"]
        elif "current_local_ip" in hostvars:
            ip_address = hostvars["current_local_ip"]
        elif "local_ip_addresses" in hostvars:
            ip_address = hostvars["local_ip_addresses"][0]

        return ip_address

    def _get_hostname(self, hostvars, ip_address):
        """Return the hostname for a host."""
        hostname = hostvars.get("hostname", ip_address)

        return hostname

    def _add_host_to_inventory(self, host_details):
        """Add host to inventory."""
        for host in host_details:
            hostvars = self._hostvars(host)
            # Only process hosts that have an IP address (reachable)?
            ip_address = self._get_ip_address(hostvars)
            if not ip_address:
                continue

            # Get the hostname
            hostname = self._get_hostname(hostvars, ip_address)

            # Check if we allow duplicate hostnames
            if self.get_option("allow_duplicates"):
                # If the hostname already exists, add the asset ID as a suffix
                if hostname in self.inventory.hosts:
                    hostname = f"{hostname}_{hostvars['id']}"

            # Add the host to the inventory
            self.inventory.add_host(hostname)
            self.inventory.set_variable(hostname, "ansible_host", ip_address)

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
