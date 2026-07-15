#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ngsiem_data_connector_info

short_description: Get information about available NG-SIEM data connectors

version_added: "4.13.0"

description:
  - Returns the catalog of available NG-SIEM data connectors.
  - Connectors are the templates that data connections are built from. Use this
    module to discover valid I(connector_id) and I(parser) values for
    M(crowdstrike.falcon.ngsiem_data_connection).
  - Some of the details returned include connector name, description, supported
    parsers, vendor, type, and subscription.

options:
  filter:
    description:
      - FQL (Falcon Query Language) filter expression to limit results.
      - "Supported fields: C(name), C(vendor_name), C(type), C(subscription)."
      - "C(type) accepts: C(PUSH), C(PULL)."
      - "Examples: C(name:'*S3*'), C(vendor_name:'AWS'), C(type:'PULL')."
    type: str
    required: false
  limit:
    description:
      - Maximum number of data connectors to return.
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
    type: str
    required: false

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
- name: Get all available data connectors
  crowdstrike.falcon.ngsiem_data_connector_info:

- name: Search connectors by name pattern
  crowdstrike.falcon.ngsiem_data_connector_info:
    filter: "name:'*S3*'"
    limit: 50

- name: Filter connectors by vendor
  crowdstrike.falcon.ngsiem_data_connector_info:
    filter: "vendor_name:'AWS'"

- name: Filter PULL connectors
  crowdstrike.falcon.ngsiem_data_connector_info:
    filter: "type:'PULL'"
"""

RETURN = r"""
data_connectors:
  description:
    - A list of available data connectors that match the search criteria.
  type: list
  returned: success
  elements: dict
  contains:
    id:
      description: The unique identifier of the connector.
      type: str
      returned: success
      sample: "a1bfd0c4380f436790cb41afc2b95f38"
    name:
      description: The name of the connector.
      type: str
      returned: success
      sample: "HTTP Event Connector"
    description:
      description: The description of the connector.
      type: str
      returned: success
    parsers:
      description: The parsers supported by the connector.
      type: list
      returned: success
      elements: str
    vendor_name:
      description: The vendor name associated with the connector.
      type: str
      returned: success
      sample: "Generic"
    vendor_product_name:
      description: The vendor product name associated with the connector.
      type: str
      returned: success
    type:
      description: The connector type (PUSH or PULL).
      type: str
      returned: success
      sample: "PUSH"
    subscription:
      description: The subscription associated with the connector.
      type: str
      returned: success
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
          description: Total number of data connectors matching the query.
          type: int
          returned: success
          sample: 157
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

NGSIEM_DATA_CONNECTOR_INFO_ARGS = {
    "filter": {"type": "str", "required": False},
    "limit": {"type": "int", "default": 100},
    "offset": {"type": "int", "default": 0},
    "sort": {"type": "str", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(NGSIEM_DATA_CONNECTOR_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    limit = module.params["limit"]
    if limit < 1 or limit > 500:
        module.fail_json(msg="Parameter 'limit' must be between 1 and 500")

    offset = module.params["offset"]
    if offset < 0:
        module.fail_json(msg="Parameter 'offset' must be 0 or greater")


def search_connectors(falcon, module):
    """Search for data connectors using filters and pagination."""
    params = {
        "limit": module.params["limit"],
        "offset": module.params["offset"],
    }

    if module.params.get("filter"):
        params["filter"] = module.params["filter"]

    if module.params.get("sort"):
        params["sort"] = module.params["sort"]

    return falcon.list_data_connectors(**params)


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
    data_connectors = []
    falcon = authenticate(module, NGSIEM)

    result = dict(
        changed=False,
        data_connectors=[],
        meta={},
    )

    try:
        query_result = search_connectors(falcon, module)

        if query_result["status_code"] == 200:
            data_connectors = query_result["body"]["resources"]

            meta = query_result["body"].get("meta", {})
            result["meta"] = {
                "query_time": time.time() - start_time,
                "pagination": {
                    "offset": module.params["offset"],
                    "limit": module.params["limit"],
                    "total": meta.get("pagination", {}).get(
                        "total", len(data_connectors)
                    ),
                },
            }

        result["data_connectors"] = data_connectors

        handle_return_errors(module, result, query_result)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while retrieving data connector information: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
