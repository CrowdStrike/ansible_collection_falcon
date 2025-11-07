#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: host_group_info

short_description: Get information about Falcon host groups

version_added: "4.10.0"

description:
  - Returns detailed information for one or more host groups.
  - Some of the details returned include group name, description, group type,
    assignment rules, creation and modification timestamps, and member counts.
  - Can retrieve specific host groups by ID or search for groups using FQL filters.
  - Optionally includes detailed member information for each group.

options:
  host_groups:
    description:
      - A list of host group IDs to get information about.
      - If not provided, all accessible host groups will be returned (subject to filter and pagination).
    type: list
    elements: str
    required: false
  filter:
    description:
      - FQL (Falcon Query Language) filter expression to limit results.
      - "Examples: C(name:'Production*'), C(group_type:'dynamic'), C(created_timestamp:>'2024-01-01T00:00:00Z')."
      - Cannot be used together with I(host_groups).
    type: str
    required: false
  limit:
    description:
      - Maximum number of host groups to return.
      - Must be between 1 and 5000.
    type: int
    default: 100
  offset:
    description:
      - Starting index for pagination.
      - Use with I(limit) to paginate through large result sets.
    type: int
    default: 0
  sort:
    description:
      - Property to sort results by.
      - Prefix with C(-) for descending order.
      - "Examples: C(name), C(-created_timestamp), C(group_type)."
    type: str
    required: false
  include_members:
    description:
      - Whether to include detailed member information for each host group.
      - When enabled, adds a C(members) list to each group with host details.
      - This may significantly increase response time and size for groups with many members.
    type: bool
    default: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - Host Groups [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get information about all host groups
  crowdstrike.falcon.host_group_info:

- name: Get information about specific host groups
  crowdstrike.falcon.host_group_info:
    host_groups:
      - "12345678901234567890abcdef123456"
      - "abcdef123456789012345678901234"

- name: Search for host groups by name pattern
  crowdstrike.falcon.host_group_info:
    filter: "name:'Production*'"
    limit: 50

- name: Get dynamic host groups created in the last 7 days
  crowdstrike.falcon.host_group_info:
    filter: "group_type:'dynamic'+created_timestamp:>'{{ (ansible_date_time.epoch | int - 604800) }}'"
    sort: "-created_timestamp"

- name: Get host group information including member details
  crowdstrike.falcon.host_group_info:
    host_groups: ["12345678901234567890abcdef123456"]
    include_members: true

- name: Paginate through all host groups
  crowdstrike.falcon.host_group_info:
    limit: 100
    offset: "{{ page * 100 }}"
  loop: "{{ range(0, total_groups // 100 + 1) | list }}"
  loop_control:
    loop_var: page
"""

RETURN = r"""
host_groups:
  description:
    - A list of host groups that match the search criteria.
  type: list
  returned: success
  elements: dict
  contains:
    id:
      description: The unique identifier of the host group.
      type: str
      returned: success
      sample: "12345678901234567890abcdef123456"
    name:
      description: The name of the host group.
      type: str
      returned: success
      sample: "Production Servers"
    description:
      description: The description of the host group.
      type: str
      returned: success
      sample: "All production server hosts"
    group_type:
      description: The type of host group (static, dynamic, or staticByID).
      type: str
      returned: success
      sample: "dynamic"
    assignment_rule:
      description: The assignment rule for dynamic groups (FQL filter).
      type: str
      returned: success
      sample: "platform_name:'Linux'+tags:'production'"
    created_by:
      description: The user who created the host group.
      type: str
      returned: success
      sample: "user@example.com"
    created_timestamp:
      description: The timestamp when the host group was created.
      type: str
      returned: success
      sample: "2024-01-15T10:30:00.000000Z"
    modified_by:
      description: The user who last modified the host group.
      type: str
      returned: success
      sample: "admin@example.com"
    modified_timestamp:
      description: The timestamp when the host group was last modified.
      type: str
      returned: success
      sample: "2024-02-01T14:22:30.000000Z"
    group_hash:
      description: A hash representing the current state of the group.
      type: str
      returned: success
      sample: "abc123def456789"
    members:
      description: List of host group members (only when include_members=true).
      type: list
      returned: when include_members=true
      elements: dict
      contains:
        device_id:
          description: The host ID (AID) of the member.
          type: str
          returned: success
          sample: "d78cd791785442a98ec75249d8c385dd"
        hostname:
          description: The hostname of the member host.
          type: str
          returned: success
          sample: "web-server-01"
        platform_name:
          description: The platform of the member host.
          type: str
          returned: success
          sample: "Linux"
        last_seen:
          description: When the member host was last seen.
          type: str
          returned: success
          sample: "2024-02-01T15:45:00Z"
meta:
  description: Metadata about the query results.
  type: dict
  returned: success
  contains:
    query_time:
      description: Time taken to execute the query in seconds.
      type: float
      returned: success
      sample: 0.123
    pagination:
      description: Pagination information.
      type: dict
      returned: success
      contains:
        offset:
          description: The starting index used for this query.
          type: int
          returned: success
          sample: 0
        limit:
          description: The limit used for this query.
          type: int
          returned: success
          sample: 100
        total:
          description: Total number of host groups matching the query.
          type: int
          returned: success
          sample: 1247
"""

import traceback
import time

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
    handle_return_errors,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import HostGroup

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

HOST_GROUP_INFO_ARGS = {
    "host_groups": {"type": "list", "elements": "str", "required": False},
    "filter": {"type": "str", "required": False},
    "limit": {"type": "int", "default": 100},
    "offset": {"type": "int", "default": 0},
    "sort": {"type": "str", "required": False},
    "include_members": {"type": "bool", "default": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(HOST_GROUP_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    # Check mutually exclusive parameters
    if module.params.get("host_groups") and module.params.get("filter"):
        module.fail_json(
            msg="Parameters 'host_groups' and 'filter' are mutually exclusive"
        )

    # Validate limit range
    limit = module.params["limit"]
    if limit < 1 or limit > 5000:
        module.fail_json(msg="Parameter 'limit' must be between 1 and 5000")

    # Validate offset
    offset = module.params["offset"]
    if offset < 0:
        module.fail_json(msg="Parameter 'offset' must be 0 or greater")


def get_host_groups_by_ids(falcon, host_group_ids):
    """Retrieve host groups by their IDs."""
    return falcon.get_host_groups(ids=host_group_ids)


def search_host_groups(falcon, module):
    """Search for host groups using filters and pagination."""
    params = {
        "limit": module.params["limit"],
        "offset": module.params["offset"],
    }

    if module.params.get("filter"):
        params["filter"] = module.params["filter"]

    if module.params.get("sort"):
        params["sort"] = module.params["sort"]

    return falcon.query_combined_host_groups(**params)


def get_group_members(falcon, group_id):
    """Get detailed member information for a host group."""
    return falcon.query_combined_group_members(id=group_id, limit=5000)


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)
    validate_params(module)

    start_time = time.time()
    host_groups = []
    falcon = authenticate(module, HostGroup)

    result = dict(
        changed=False,
        host_groups=[],
        meta={},
    )

    try:
        # Determine which API method to use
        if module.params.get("host_groups"):
            # Get specific host groups by ID
            query_result = get_host_groups_by_ids(
                falcon, module.params["host_groups"]
            )

            if query_result["status_code"] == 200:
                host_groups = query_result["body"]["resources"]

                # Set pagination info for ID-based queries
                result["meta"] = {
                    "query_time": time.time() - start_time,
                    "pagination": {
                        "offset": 0,
                        "limit": len(host_groups),
                        "total": len(host_groups),
                    },
                }
        else:
            # Search for host groups using filters
            query_result = search_host_groups(falcon, module)

            if query_result["status_code"] == 200:
                host_groups = query_result["body"]["resources"]

                # Extract pagination metadata
                meta = query_result["body"].get("meta", {})
                result["meta"] = {
                    "query_time": time.time() - start_time,
                    "pagination": {
                        "offset": module.params["offset"],
                        "limit": module.params["limit"],
                        "total": meta.get("pagination", {}).get(
                            "total", len(host_groups)
                        ),
                    },
                }

        # Add member information if requested
        if module.params["include_members"] and host_groups:
            for group in host_groups:
                members_result = get_group_members(falcon, group["id"])
                if members_result["status_code"] == 200:
                    group["members"] = members_result["body"]["resources"]
                else:
                    # If we can't get members, add empty list and continue
                    group["members"] = []

        result["host_groups"] = host_groups

        # Handle API errors
        handle_return_errors(module, result, query_result)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while retrieving host group information: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
