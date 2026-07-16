#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ngsiem_parser_info

short_description: Get information about NG-SIEM parsers

version_added: "4.13.0"

description:
  - Returns detailed information for one or more NG-SIEM parsers in the
    CrowdStrike Falcon platform.
  - Parsers transform raw log data into normalized events for Next-Gen SIEM.
    They come in two types - built-in B(ootb) (out-of-the-box) parsers shipped
    by CrowdStrike, and B(custom) parsers created in your tenant.
  - By default the full parser definition (including the C(script),
    C(fields_to_tag), and C(test_cases)) is returned for each parser. Set
    I(definitions=false) to return only the lightweight list metadata.
  - Use M(crowdstrike.falcon.ngsiem_parser) to create, update, clone, or delete
    parsers.

options:
  parser_ids:
    description:
      - A list of parser IDs to get information about.
      - Parser IDs are version-suffixed (e.g. C(abc123:1.0.0)).
      - When provided, I(name), I(parser_type), and I(update_available) filters
        are ignored.
    type: list
    elements: str
    required: false
  name:
    description:
      - Substring to match against parser names.
      - This maps to the only supported parser query filter (C(name:~'value')),
        which performs a case-insensitive substring match.
    type: str
    required: false
  parser_type:
    description:
      - Filter parsers by type.
      - C(ootb) returns only built-in (out-of-the-box) parsers.
      - C(custom) returns only custom parsers created in your tenant.
    type: str
    choices: ["ootb", "custom"]
    required: false
  update_available:
    description:
      - Filter parsers by whether a newer version is available.
    type: bool
    required: false
  definitions:
    description:
      - Whether to fetch the full definition for each parser.
      - When C(true) (default), an additional API call is made per parser to
        return its C(script), C(fields_to_tag), C(test_cases), and other
        definition fields.
      - When C(false), only the lightweight list metadata is returned.
    type: bool
    default: true
  limit:
    description:
      - Maximum number of parsers to return.
      - Must be between 1 and 500.
    type: int
    default: 100
  offset:
    description:
      - Starting index for pagination.
      - Use with I(limit) to paginate through large result sets.
    type: int
    default: 0
  repository:
    description:
      - The name of the repository to query.
    type: str
    default: parsers-repository

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - B(Filtering:) Only substring matching on I(name) is supported by the API.
    General FQL expressions are not supported. Non-name filters (I(parser_type),
    I(update_available)) are applied as dedicated query parameters.

requirements:
  - NGSIEM Parsers [B(READ)] API scope
  - CrowdStrike FalconPy >= 1.6.3

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all parsers with full definitions
  crowdstrike.falcon.ngsiem_parser_info:

- name: Get only custom parsers
  crowdstrike.falcon.ngsiem_parser_info:
    parser_type: custom

- name: Get parsers whose name contains 'watchguard'
  crowdstrike.falcon.ngsiem_parser_info:
    name: watchguard

- name: Get specific parsers by ID
  crowdstrike.falcon.ngsiem_parser_info:
    parser_ids:
      - "10f55deaa2893f60b87af305f44f80bf:1.0.0"

- name: List parsers that have an update available (metadata only)
  crowdstrike.falcon.ngsiem_parser_info:
    update_available: true
    definitions: false

- name: Get custom parsers using metadata only for a quick inventory
  crowdstrike.falcon.ngsiem_parser_info:
    parser_type: custom
    definitions: false
    limit: 50
"""

RETURN = r"""
parsers:
  description:
    - A list of parsers that match the search criteria.
    - When I(definitions=true) (default), each entry includes the full parser
      definition merged with its list metadata.
  type: list
  returned: success
  elements: dict
  contains:
    id:
      description: The version-suffixed unique identifier of the parser.
      type: str
      returned: success
      sample: "10f55deaa2893f60b87af305f44f80bf:1.0.0"
    name:
      description: The name of the parser.
      type: str
      returned: success
      sample: "redhat-insights"
    parser_type:
      description: The type of the parser (ootb or custom).
      type: str
      returned: success
      sample: "custom"
    current_version:
      description: The currently installed version of the parser.
      type: str
      returned: success
      sample: "1.0.0"
    latest_version:
      description: The latest available version of the parser.
      type: str
      returned: success
      sample: "1.0.0"
    update_available:
      description: Whether a newer version of the parser is available.
      type: bool
      returned: success
      sample: false
    description:
      description: The description of the parser.
      type: str
      returned: when definitions=true
    is_built_in:
      description: Whether the parser is a built-in (out-of-the-box) parser.
      type: bool
      returned: when definitions=true
    script:
      description: The LogScale/CQL parsing script.
      type: str
      returned: when definitions=true
    fields_to_tag:
      description: The list of fields to tag on parsed events.
      type: list
      returned: when definitions=true
    test_cases:
      description: The list of test cases associated with the parser.
      type: list
      returned: when definitions=true
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
          description: Total number of parsers matching the query.
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

# The parser modules require the typed clone/extension methods added in 1.6.3.
MINIMUM_FALCONPY_VERSION = "1.6.3"

NGSIEM_PARSER_INFO_ARGS = {
    "parser_ids": {"type": "list", "elements": "str", "required": False},
    "name": {"type": "str", "required": False},
    "parser_type": {"type": "str", "choices": ["ootb", "custom"], "required": False},
    "update_available": {"type": "bool", "required": False},
    "definitions": {"type": "bool", "default": True},
    "limit": {"type": "int", "default": 100},
    "offset": {"type": "int", "default": 0},
    "repository": {"type": "str", "default": "parsers-repository"},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(NGSIEM_PARSER_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    limit = module.params["limit"]
    if limit < 1 or limit > 500:
        module.fail_json(msg="Parameter 'limit' must be between 1 and 500")

    offset = module.params["offset"]
    if offset < 0:
        module.fail_json(msg="Parameter 'offset' must be 0 or greater")


def list_parsers(falcon, module):
    """List parsers using filters and pagination."""
    params = {
        "repository": module.params["repository"],
        "limit": module.params["limit"],
        "offset": module.params["offset"],
    }

    if module.params.get("name"):
        params["filter"] = f"name:~'{module.params['name']}'"

    if module.params.get("parser_type"):
        params["parser_type"] = module.params["parser_type"]

    if module.params.get("update_available") is not None:
        params["update_available"] = str(module.params["update_available"]).lower()

    return falcon.list_parsers(**params)


def normalize_summary(item):
    """Normalize a list-parser summary item to lowercase-keyed fields.

    The list endpoint returns ``ID``/``Name`` (capitalized) while the get
    endpoint returns ``id``/``name``. Normalize to the lowercase form so the
    returned data is consistent regardless of I(definitions).
    """
    summary = dict(item)
    if "ID" in summary:
        summary["id"] = summary.pop("ID")
    if "Name" in summary:
        summary["name"] = summary.pop("Name")
    return summary


def get_parser_definition(falcon, repository, parser_id):
    """Fetch the full definition for a single parser ID."""
    result = falcon.get_parser(ids=parser_id, repository=repository)
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0]
    return None


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

    check_falconpy_version(module, minimum_version=MINIMUM_FALCONPY_VERSION)
    validate_params(module)

    start_time = time.time()
    repository = module.params["repository"]
    parsers = []
    total = 0
    falcon = authenticate(module, NGSIEM)

    result = dict(
        changed=False,
        parsers=[],
        meta={},
    )

    query_result = None

    try:
        parser_ids = module.params.get("parser_ids")

        if parser_ids:
            # Build lightweight summaries from the explicit IDs; definitions are
            # fetched below when requested.
            parsers = [{"id": pid} for pid in parser_ids]
            total = len(parsers)
        else:
            query_result = list_parsers(falcon, module)
            if query_result["status_code"] == 200:
                summaries = query_result["body"].get("resources") or []
                parsers = [normalize_summary(item) for item in summaries]
                meta = query_result["body"].get("meta", {})
                total = meta.get("pagination", {}).get("total", len(parsers))
            else:
                handle_return_errors(module, result, query_result)

        if module.params["definitions"]:
            enriched = []
            for parser in parsers:
                definition = get_parser_definition(falcon, repository, parser["id"])
                if definition:
                    # Definition fields take precedence but retain summary-only
                    # metadata (parser_type, versions, update_available).
                    merged = dict(parser)
                    merged.update(definition)
                    enriched.append(merged)
                else:
                    enriched.append(parser)
            parsers = enriched

        result["parsers"] = parsers
        result["meta"] = {
            "query_time": time.time() - start_time,
            "pagination": {
                "offset": module.params["offset"],
                "limit": module.params["limit"],
                "total": total,
            },
        }

        if query_result is not None:
            handle_return_errors(module, result, query_result)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while retrieving parser information: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
