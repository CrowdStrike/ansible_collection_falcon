#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ngsiem_data_connection_info

short_description: Get information about NG-SIEM data connections

version_added: "4.13.0"

description:
  - Returns detailed information for one or more NG-SIEM data connections.
  - Some of the details returned include connection name, vendor, parser, status,
    source type, and ingest URL.
  - Can retrieve specific connections by ID or search for connections using FQL filters.
  - Optionally enriches each result with its current provisioning status.

options:
  connection_ids:
    description:
      - A list of data connection IDs to get information about.
      - If not provided, connections will be returned based on filter and pagination settings.
      - Cannot be used together with I(filter).
    type: list
    elements: str
    required: false
  filter:
    description:
      - FQL (Falcon Query Language) filter expression to limit results.
      - "Supported fields: C(name), C(id), C(vendor_name), C(vendor_product_name),
        C(status), C(type)."
      - "C(status) accepts: C(Pending), C(Active), C(Disconnected), C(Error), C(Idle), C(Paused)."
      - "C(type) accepts: C(PUSH), C(PULL)."
      - "Examples: C(name:'*edge*'), C(status:'Active'), C(type:'PUSH')."
      - Cannot be used together with I(connection_ids).
    type: str
    required: false
  limit:
    description:
      - Maximum number of data connections to return.
      - Must be between 1 and 500.
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
      - "B(Note:) Only C(name.asc) is supported by the API. Other sort values are rejected."
    type: str
    required: false
  include_status:
    description:
      - Whether to enrich each connection with its current provisioning status.
      - When enabled, adds a C(provisioning_status) field to each connection.
      - This requires an additional API call per connection.
    type: bool
    default: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - NGSIEM Data Connections [B(READ)] API scope
  - CrowdStrike FalconPy >= 1.5.0

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all data connections
  crowdstrike.falcon.ngsiem_data_connection_info:

- name: Get specific data connections by ID
  crowdstrike.falcon.ngsiem_data_connection_info:
    connection_ids:
      - "abcdef1234567890abcdef1234567890"
      - "1234567890abcdef1234567890abcdef"

- name: Search connections by name pattern
  crowdstrike.falcon.ngsiem_data_connection_info:
    filter: "name:'*edge*'"
    limit: 50

- name: Filter connections by status
  crowdstrike.falcon.ngsiem_data_connection_info:
    filter: "status:'Active'"
    sort: "name.asc"

- name: Filter PUSH connections and include provisioning status
  crowdstrike.falcon.ngsiem_data_connection_info:
    filter: "type:'PUSH'"
    include_status: true
"""

RETURN = r"""
data_connections:
  description:
    - A list of data connections that match the search criteria.
  type: list
  returned: success
  elements: dict
  contains:
    id:
      description: The unique identifier of the data connection.
      type: str
      returned: success
      sample: "abcdef1234567890abcdef1234567890"
    name:
      description: The name of the data connection.
      type: str
      returned: success
      sample: "Edge browser logs"
    vendor_name:
      description: The vendor name associated with the connection.
      type: str
      returned: success
      sample: "Microsoft"
    vendor_product_name:
      description: The vendor product name associated with the connection.
      type: str
      returned: success
      sample: "Edge"
    parser_name:
      description: The parser applied to the connection's data.
      type: str
      returned: success
      sample: "microsoft-edge"
    status:
      description: The current status of the connection.
      type: str
      returned: success
      sample: "Active"
    source_type:
      description: The source type of the connection.
      type: str
      returned: success
    last_ingested_volume_one_day:
      description: The volume ingested in the last day.
      type: int
      returned: success
    ingest_url:
      description: The URL to push logs to (PUSH connections only, after provisioning).
      type: str
      returned: when available
    provisioning_status:
      description: The current provisioning status (only when include_status=true).
      type: dict
      returned: when include_status=true
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
          description: Total number of data connections matching the query.
          type: int
          returned: success
          sample: 42
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
    from falconpy import NGSIEM

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

NGSIEM_DATA_CONNECTION_INFO_ARGS = {
    "connection_ids": {"type": "list", "elements": "str", "required": False},
    "filter": {"type": "str", "required": False},
    "limit": {"type": "int", "default": 100},
    "offset": {"type": "int", "default": 0},
    "sort": {"type": "str", "required": False},
    "include_status": {"type": "bool", "default": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(NGSIEM_DATA_CONNECTION_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    if module.params.get("connection_ids") and module.params.get("filter"):
        module.fail_json(
            msg="Parameters 'connection_ids' and 'filter' are mutually exclusive"
        )

    limit = module.params["limit"]
    if limit < 1 or limit > 500:
        module.fail_json(msg="Parameter 'limit' must be between 1 and 500")

    offset = module.params["offset"]
    if offset < 0:
        module.fail_json(msg="Parameter 'offset' must be 0 or greater")


def get_connections_by_ids(falcon, connection_ids):
    """Retrieve data connections by their IDs."""
    return falcon.get_connection_by_id(ids=connection_ids)


def search_connections(falcon, module):
    """Search for data connections using filters and pagination."""
    params = {
        "limit": module.params["limit"],
        "offset": module.params["offset"],
    }

    if module.params.get("filter"):
        params["filter"] = module.params["filter"]

    if module.params.get("sort"):
        params["sort"] = module.params["sort"]

    return falcon.list_data_connections(**params)


def enrich_status(falcon, connections):
    """Add provisioning status to each connection."""
    for connection in connections:
        status_result = falcon.get_provisioning_status(ids=connection["id"])
        if status_result["status_code"] == 200 and status_result["body"].get("resources"):
            connection["provisioning_status"] = status_result["body"]["resources"][0]
        else:
            connection["provisioning_status"] = {}


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
    data_connections = []
    falcon = authenticate(module, NGSIEM)

    result = dict(
        changed=False,
        data_connections=[],
        meta={},
    )

    try:
        if module.params.get("connection_ids"):
            query_result = get_connections_by_ids(falcon, module.params["connection_ids"])

            if query_result["status_code"] == 200:
                data_connections = query_result["body"]["resources"]

                result["meta"] = {
                    "query_time": time.time() - start_time,
                    "pagination": {
                        "offset": 0,
                        "limit": len(data_connections),
                        "total": len(data_connections),
                    },
                }
        else:
            query_result = search_connections(falcon, module)

            if query_result["status_code"] == 200:
                data_connections = query_result["body"]["resources"]

                meta = query_result["body"].get("meta", {})
                result["meta"] = {
                    "query_time": time.time() - start_time,
                    "pagination": {
                        "offset": module.params["offset"],
                        "limit": module.params["limit"],
                        "total": meta.get("pagination", {}).get(
                            "total", len(data_connections)
                        ),
                    },
                }

        if module.params["include_status"] and data_connections:
            enrich_status(falcon, data_connections)

        result["data_connections"] = data_connections

        handle_return_errors(module, result, query_result)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while retrieving data connection information: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
