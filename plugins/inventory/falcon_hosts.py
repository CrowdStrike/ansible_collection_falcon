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
      - This option can be set using a Jinja2 template value.
    type: str
    aliases: [ falcon_client_id ]
  client_secret:
    description:
      - The CrowdStrike API secret that corresponds to the client ID.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#understanding-api-clients)
        for more information about API clients.
      - The C(FALCON_CLIENT_SECRET) environment variable can also be used.
      - This option can be set using a Jinja2 template value.
    type: str
    aliases: [ falcon_client_secret ]
  member_cid:
    description:
      - The CrowdStrike member CID for MSSP authentication.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis#understanding-api-clients)
        for more information about API clients.
      - The C(FALCON_MEMBER_CID) environment variable can also be used.
      - This option can be set using a Jinja2 template value.
    type: str
  cloud:
    description:
      - The CrowdStrike cloud region to use.
      - All clouds are automatically discovered if not specified, except for the C(us-gov-1) cloud.
      - The C(FALCON_CLOUD) environment variable can also be used.
      - This option can be set using a Jinja2 template value.
      - Valid values are C(us-1), C(us-2), C(eu-1), C(us-gov-1).
    default: us-1
    type: str
  filter:
    description:
      - The filter expression that should be used to limit the results using FQL
        (Falcon Query Language) syntax.
      - See the L(Falcon documentation,https://falcon.crowdstrike.com/documentation/page/c0b16f1b/host-and-host-group-management-apis#qadd6f8f)
        for more information about what filters are available for this inventory.
    type: str
  hostnames:
      description:
      - A list of templates in order of precedence to compose C(inventory_hostname).
      - Ignores template if resulted in an empty string or None value.
      - You can use any host variable as a template.
      - The default is to use the hostname, external_ip, and local_ip in that order.
      type: list
      elements: string
      default: ['hostname', 'external_ip', 'local_ip']
requirements:
  - Hosts [B(READ)] API scope
  - python >= 3.6
  - crowdstrike-falconpy >= 1.3.0
notes:
  - By default, Ansible will deduplicate the C(inventory_hostname), so if multiple hosts have the same hostname, only
    the last one will be used. In this case, consider using the C(device_id) as the first preference in the C(hostnames).
    You can use C(compose) to specify how Ansible will connectz to the host with the C(ansible_host) variable.
  - If no credentials are provided, FalconPy will attempt to use the API credentials via environment variables.
  - The current behavior is to use the hostname if it exists, otherwise we will attemp to use either the external
    IP address or the local IP address. If neither of those exist, the host will be skipped as Ansible would not
    be able to connect to it.
author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
# sample file: my_inventory.falcon_hosts.yml

# required for all falcon_hosts inventory plugin configs
plugin: crowdstrike.falcon.falcon_hosts

# authentication credentials (required if not using environment variables)
# client_id: 1234567890abcdef12345678
# client_secret: 1234567890abcdef1234567890abcdef12345
# cloud: us-1

# authentication example using hashicorp vault lookup plugin
# client_id: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=path/to/secret:client_id') }}"
# client_secret: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=path/to/secret:client_secret') }}"
# cloud: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=path/to/secret:cloud') }}"

# return all Windows hosts (authentication via environment variables)
# filter: "platform_name:'Windows'"

# return all Linux hosts in reduced functionality mode
# filter: "platform_name:'Linux' + reduced_functionality_mode:'yes'"

# return stale devices that haven't checked in for 15 days
# filter: "last_seen:<='now-15d'"

# return all Linux hosts running in eBPF User Mode
# filter: "linux_sensor_mode:'User Mode'"

# place hosts into dynamically created groups based on variable values
keyed_groups:
  # places host in a group named tag_<tags> for each tag on a host
  - prefix: tag
    key: tags
  # places host in a group named platform_<platform_name> based on the
  # platform name (Linux, Windows, etc.)
  - prefix: platform
    key: platform_name
  # places host in a group named tag_<tags> for each tag on a host
  - prefix: rfm
    key: reduced_functionality_mode

# place hosts into dynamically created groups based on conditional statements
groups:
  # places hosts in a group named windows_hosts if the platform_name is Windows
  windows_hosts: "platform_name == 'Windows'"
  # place hosts in a group named aws_us_west_2 if the zone_group is in us-west-2
  aws_us_west_2: "'us-west-2' in zone_group and 'Amazon' in system_manufacturer"

# compose inventory_hostname from Jinja2 expressions
# hostnames:
#   - hostname|lower

# compose inventory_hostname from Jinja2 expressions with order of precedence
# hostnames:
#   - external_ip
#   - local_ip
#   - serial_number

# use device_id as the inventory_hostname to prevent deduplication and set ansible_host
# to a reachable attribute
# hostnames:
#   - device_id
# compose:
#   ansible_host: hostname | default(external_ip) | default(local_ip) | default(None)

# compose connection variables for each host
# compose:
#   ansible_host: external_ip
#   ansible_user: "'root'"
#   ansible_ssh_private_key_file: "'/path/to/private_key_file'"

# Use caching for the inventory
# cache: true
# cache_plugin: jsonfile
# cache_connection: /tmp/falcon_inventory
# cache_timeout: 1800
# cache_prefix: falcon_hosts
"""

import os
import re
import traceback

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_native, to_text
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
            if self.templar.is_template(value):
                value = self.templar.template(variable=value, disable_lookups=False)
            if value:
                if key == "cloud":
                    self._verify_cloud(value)
                    creds["base_url"] = value
                else:
                    creds[key] = value

        # Make sure we have client_id and client_secret
        if "client_id" not in creds or "client_secret" not in creds:
            raise ValueError(
                "You must provide a client_id and client_secret to authenticate to the Falcon API."
            )

        return creds

    def _verify_cloud(self, cloud):
        """Verify the cloud region."""
        valid_clouds = ["us-1", "us-2", "eu-1", "us-gov-1"]
        if cloud not in valid_clouds:
            raise ValueError(
                f"Invalid cloud region: '{cloud}'. Valid values are {', '.join(valid_clouds)}"
            )

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

    def _get_hostname(self, hostvars, hostnames=None, strict=False):
        """Return the hostname for a host."""
        hostname = None
        errors = []

        for preference in hostnames:
            try:
                hostname = self._compose(preference, hostvars)
            except Exception as e:  # pylint: disable=broad-except
                if strict:
                    raise AnsibleError(
                        "Could not compose %s as hostnames - %s" % (preference, to_native(e))
                    ) from e

                errors.append(
                    (preference, str(e))
                )
            if hostname:
                return to_text(hostname)

        raise AnsibleError(
            'Could not template any hostname for host, errors for each preference: %s' % (
                ', '.join(['%s: %s' % (pref, err) for pref, err in errors])
            )
        )

    def _add_host_to_inventory(self, host_details):
        """Add host to inventory."""
        strict = self.get_option("strict")
        hostnames = self.get_option("hostnames")

        for host in host_details:
            hostvars = self._hostvars(host)

            # Get the hostname
            hostname = self._get_hostname(hostvars, hostnames, strict)

            # Add the host to the inventory
            self.inventory.add_host(hostname)

            # Add host variables
            for key, value in hostvars.items():
                self.inventory.set_variable(hostname, key, value)

            # Create composite vars
            self._set_composite_vars(self.get_option("compose"), hostvars, hostname, strict)

            # Create user-defined groups based on variables/jinja2 conditionals
            self._add_host_to_composed_groups(
                self.get_option("groups"), hostvars, hostname, strict
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"), hostvars, hostname, strict
            )
