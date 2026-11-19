#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: case_info

short_description: Get information about Falcon cases

version_added: "4.15.0"

description:
  - Returns details of Falcon cases.
  - Gets cases by ID, or searches for them with an FQL filter or a free text search.
  - With no option, returns every case.

options:
  ids:
    description:
      - The IDs of the cases to get.
      - An ID that does not exist is left out of the result.
      - An empty list returns no cases.
      - The cases are returned in the order of the IDs.
      - Mutually exclusive with I(filter), I(q), I(sort) and I(limit).
    type: list
    elements: str
  filter:
    description:
      - The FQL filter to search for cases.
      - C(name:'Phishing investigation') is an exact, case-sensitive match of the name.
        A part of the name matches nothing.
      - C(name:*'phishing*') matches the names that start with C(phishing).
      - C(status:'closed') matches the cases with a status.
      - C(tags:'malware') matches the cases with a tag.
      - Join conditions with C(+) (AND).
      - Mutually exclusive with I(ids).
    type: str
  q:
    description:
      - The free text to search for in the cases.
      - Mutually exclusive with I(ids).
    type: str
  sort:
    description:
      - The property and direction to sort the results by,
        for example C(created_timestamp.desc) or C(name.asc).
      - Mutually exclusive with I(ids).
    type: str
  limit:
    description:
      - The maximum number of cases to return.
      - With no limit, the module returns every case that matches.
      - Must be 1 or greater.
      - Mutually exclusive with I(ids).
    type: int

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth
  - ansible.builtin.action_common_attributes

attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
  platform:
    platforms: all

seealso:
  - module: crowdstrike.falcon.host_contain
    description: Contain or lift containment on Falcon hosts.
  - name: Case Management API reference
    description: The CrowdStrike API operations that this module uses.
    link: https://developer.crowdstrike.com/api-reference/collections/case-management

requirements:
  - Cases [B(READ)] API scope
  - CrowdStrike FalconPy >= 1.5.5

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all cases
  crowdstrike.falcon.case_info:

- name: Get cases by ID
  crowdstrike.falcon.case_info:
    ids:
      - "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"

- name: Get the case with an exact name (case sensitive)
  crowdstrike.falcon.case_info:
    filter: "name:'Phishing investigation'"

- name: Get the cases whose name starts with phishing, newest first
  crowdstrike.falcon.case_info:
    filter: "name:*'phishing*'"
    sort: created_timestamp.desc

- name: Get the 10 first closed cases, sorted by name
  crowdstrike.falcon.case_info:
    filter: "status:'closed'"
    sort: name.asc
    limit: 10

- name: Get the cases with a tag
  crowdstrike.falcon.case_info:
    filter: "tags:'malware'"

- name: Search the cases for a text
  crowdstrike.falcon.case_info:
    q: phishing
"""

RETURN = r"""
cases:
  description:
    - The cases that match the IDs, the filter or the search.
    - An empty list when nothing matches.
  type: list
  elements: dict
  returned: success
  contains:
    id:
      description: The ID of the case.
      type: str
      returned: success
      sample: "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
    name:
      description: The name of the case.
      type: str
      returned: success
      sample: "Phishing investigation"
    description:
      description: The description of the case.
      type: str
      returned: success
      sample: "Investigate the phishing alerts of the finance team"
    status:
      description: The status of the case.
      type: str
      returned: success
      sample: "closed"
    severity:
      description: The severity of the case.
      type: int
      returned: success
      sample: 50
    severity_info:
      description: The severity details of the case.
      type: dict
      returned: success
      contains:
        level:
          description: The severity level of the case.
          type: str
          returned: success
          sample: "Medium"
    version:
      description: The version of the case.
      type: int
      returned: success
      sample: 3
    consistency:
      description: The consistency data of the case.
      type: dict
      returned: success
      contains:
        version:
          description: The consistency version of the case.
          type: int
          returned: success
          sample: 3
        consistent:
          description: Whether the case data is consistent.
          type: bool
          returned: success
          sample: true
    tags:
      description: The tags of the case.
      type: list
      elements: str
      returned: success
      sample: ["malware"]
    assigned_to:
      description: The user that the case is assigned to.
      type: dict
      returned: success
      contains:
        uuid:
          description: The UUID of the user.
          type: str
          returned: success
          sample: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"
        email:
          description: The email address of the user.
          type: str
          returned: success
          sample: "analyst@example.com"
        full_name:
          description: The full name of the user.
          type: str
          returned: success
          sample: "Example Analyst"
    assigned_to_groups:
      description: The user groups that the case is assigned to.
      type: list
      elements: dict
      returned: success
      sample: null
    evidence:
      description:
        - The evidence of the case, by type.
        - Each type has a list of C(records).
      type: dict
      returned: success
    analysis_results:
      description:
        - The analysis results of the case, by type.
        - Each type has a list of C(records).
      type: dict
      returned: success
    cid:
      description: The customer ID that the case belongs to.
      type: str
      returned: success
      sample: "0123456789abcdef0123456789abcdef"
    start_timestamp:
      description: The start time of the case.
      type: str
      returned: success
      sample: null
    created_by:
      description: The user that created the case.
      type: dict
      returned: success
      contains:
        uuid:
          description: The UUID of the user.
          type: str
          returned: success
          sample: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"
        email:
          description: The email address of the user.
          type: str
          returned: success
          sample: "analyst@example.com"
        full_name:
          description: The full name of the user.
          type: str
          returned: success
          sample: "Example Analyst"
    last_updated_by:
      description: The user that last updated the case.
      type: dict
      returned: success
      contains:
        uuid:
          description: The UUID of the user.
          type: str
          returned: success
          sample: "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"
        email:
          description: The email address of the user.
          type: str
          returned: success
          sample: "analyst@example.com"
        full_name:
          description: The full name of the user.
          type: str
          returned: success
          sample: "Example Analyst"
    creation_actor:
      description: The actor that created the case.
      type: dict
      returned: success
      contains:
        type:
          description: The type of the actor.
          type: str
          returned: success
          sample: "user"
    update_actor:
      description: The actor that last updated the case.
      type: dict
      returned: success
      contains:
        type:
          description: The type of the actor.
          type: str
          returned: success
          sample: "user"
    created_timestamp:
      description: The time when the case was created.
      type: str
      returned: success
      sample: "2026-11-18T21:43:48Z"
    updated_timestamp:
      description: The time when the case was last updated.
      type: str
      returned: success
      sample: "2026-11-18T21:50:12Z"
    end_timestamp:
      description: The time when the case was closed.
      type: str
      returned: success
      sample: "2026-11-18T22:05:00Z"
    reference_id:
      description: The reference ID of the case.
      type: str
      returned: success
      sample: "CASE-123"
    read_only:
      description: The read-only state of the case.
      type: dict
      returned: success
      contains:
        is_read_only:
          description: Whether the case is read only.
          type: bool
          returned: success
          sample: false
"""

import traceback

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
    from falconpy import CaseManagement

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# CaseManagement and its methods exist from FalconPy 1.5.5.
MINIMUM_FALCONPY_VERSION = "1.5.5"

PAGE_SIZE = 100

CASE_INFO_ARGS = {
    "ids": {"type": "list", "elements": "str", "required": False},
    "filter": {"type": "str", "required": False},
    "q": {"type": "str", "required": False},
    "sort": {"type": "str", "required": False},
    "limit": {"type": "int", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(CASE_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters before any API call."""
    ids = module.params["ids"]
    if ids is not None and any(not case_id for case_id in ids):
        module.fail_json(msg="Parameter 'ids' must not contain an empty ID")

    limit = module.params["limit"]
    if limit is not None and limit < 1:
        module.fail_json(msg="Parameter 'limit' must be 1 or greater")


def get_by_ids(falcon, module, ids):
    """Get cases by ID in batches. Unknown IDs are left out by the API."""
    result = dict(changed=False, cases=[])

    for start in range(0, len(ids), PAGE_SIZE):
        query_result = falcon.get_cases(body={"ids": ids[start:start + PAGE_SIZE]})
        status_code = query_result["status_code"]
        if status_code != 200:
            handle_return_errors(module, result, query_result)
            # handle_return_errors does not fail when errors is empty or null.
            module.fail_json(
                msg=f"Unexpected status {status_code} while getting cases",
                **result,
            )
        result["cases"].extend(query_result["body"].get("resources") or [])

    # get_cases does not keep the order of the IDs, which is the search order.
    order = {case_id: n for n, case_id in enumerate(ids)}
    result["cases"].sort(key=lambda c: order.get(c.get("id"), len(order)))

    return result


def search_ids(falcon, module):
    """Search for case IDs and read the pages until the limit or the total."""
    result = dict(changed=False, cases=[])
    limit = module.params["limit"]
    params = {}
    for key in ("filter", "q", "sort"):
        if module.params[key]:
            params[key] = module.params[key]

    ids = []
    offset = 0
    while True:
        page_size = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - len(ids))
        query_result = falcon.query_case_ids(limit=page_size, offset=offset, **params)
        status_code = query_result["status_code"]
        if status_code != 200:
            handle_return_errors(module, result, query_result)
            module.fail_json(
                msg=f"Unexpected status {status_code} while searching for cases",
                **result,
            )

        body = query_result["body"]
        page = body.get("resources") or []
        ids.extend(page)
        offset += len(page)
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)

        if not page or offset >= total:
            break
        if limit is not None and len(ids) >= limit:
            break

    return ids


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=[
            ("ids", "filter"),
            ("ids", "q"),
            ("ids", "sort"),
            ("ids", "limit"),
        ],
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module, minimum_version=MINIMUM_FALCONPY_VERSION)
    validate_params(module)

    result = dict(
        changed=False,
        cases=[],
    )

    ids = module.params["ids"]
    # An empty list from a playbook means "no IDs", not "all cases".
    # Exit before authenticate(), so that it makes no token request.
    if ids is not None and not ids:
        module.exit_json(**result)

    falcon = authenticate(module, CaseManagement)

    try:
        if ids is None:
            ids = search_ids(falcon, module)
        else:
            ids = list(dict.fromkeys(ids))

        if ids:
            result = get_by_ids(falcon, module, ids)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while getting cases: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
