#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: intel_rule_info

short_description: Get information about CrowdStrike Falcon Intel rules

description:
  - Search for and retrieve details about Intel rules in the CrowdStrike Falcon platform.

options:
  type:
    description:
      - The rule news report type.
    type: str
    required: true
    choices:
      - common-event-format
      - netwitness
      - snort-suricata-changelog
      - snort-suricata-master
      - snort-suricata-update
      - yara-changelog
      - yara-master
      - yara-update
      - cql-master
      - cql-changelog
      - cql-update
  name:
    description:
      - Search by rule title.
    type: list
    elements: str
  description:
    description:
      - Substring match on the description field.
    type: list
    elements: str
  tags:
    description:
      - Search for rule tags.
    type: list
    elements: str
  q:
    description:
      - Perform a generic substring search across all fields.
    type: str
  sort:
    description:
      - The property to sort by in FQL (Falcon Query Language) syntax (e.g. created_date|asc).
      - See the L(FalconPy documentation,https://www.falconpy.io/Usage/Falcon-Query-Language.html#using-fql-in-a-sort)
        for more information about sorting with FQL.
    type: str
  limit:
    description:
      - The maximum number of rule IDs to return. [integer, 1-5000]
    type: int

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - For large sets of Rule IDs (if not using limits) there may be a delay in processing as the current
    API endpoint for retrieving details can only process 10 at a time.

requirements:
  - Rules (Falcon Intelligence) [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)

"""

EXAMPLES = r"""
- name: Get details on the latest 50 YARA rules
  crowdstrike.falcon.intel_rule_info:
    type: "yara-master"
    limit: 50
    sort: "created_date|desc"

- name: Get Snort/Suricata rules with a specific description pattern
  crowdstrike.falcon.intel_rule_info:
    type: "snort-suricata-master"
    description:
      - "FANCY BEAR"

- name: Search for rules with specific tags
  crowdstrike.falcon.intel_rule_info:
    type: "yara-master"
    tags:
      - "intel_feed"
      - "yara"
"""

RETURN = r"""
rules:
  description: List of intel rules and their details
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The ID of the rule
      type: int
      returned: always
      sample: 1745571604
    name:
      description: The name of the rule
      type: str
      returned: always
      sample: "CrowdStrike Intelligence Feed: YARA Master - 2025/04/25"
    type:
      description: Type of rule (yara-master, snort-suricata-master, etc.)
      type: str
      returned: always
      sample: "yara-master"
    created_date:
      description: Unix timestamp when the rule was created
      type: int
      returned: always
      sample: 1745576262
    last_modified_date:
      description: Unix timestamp when the rule was last modified
      type: int
      returned: always
      sample: 1745576262
    description:
      description: Full description of the rule
      type: str
      returned: always
    short_description:
      description: Abbreviated description of the rule
      type: str
      returned: always
    rich_text_description:
      description: HTML-formatted description of the rule
      type: str
      returned: when available
    tags:
      description: List of tags associated with the rule
      type: list
      elements: str
      returned: when available
      sample: ["intel_feed", "yara"]
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
    get_paginated_results_info,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Intel

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(
        type=dict(
            type='str',
            required=True,
            choices=[
                'common-event-format',
                'netwitness',
                'snort-suricata-changelog',
                'snort-suricata-master',
                'snort-suricata-update',
                'yara-changelog',
                'yara-master',
                'yara-update',
                'cql-master',
                'cql-changelog',
                'cql-update'
            ]
        ),
        name=dict(type='list', elements='str'),
        description=dict(type='list', elements='str'),
        tags=dict(type='list', elements='str'),
        q=dict(type='str'),
        sort=dict(type='str'),
        limit=dict(type='int'),
    )
    return args


def _get_rule_ids(module, falcon, query_params, result):
    """Return Intel rule IDs with pagination handling.

    Args:
        module: The AnsibleModule instance
        falcon: The authenticated Intel service instance
        query_params: Dict of parameters to pass to query_rule_ids
        result: Results dict

    Returns:
        A list of Rule IDs
    """
    # Check if limit is specified
    user_limit = module.params.get('limit')
    rule_ids = []

    # If no limit is specified, we'll paginate to get all results
    if user_limit is None:
        max_limit = 5000
        query_result = get_paginated_results_info(
            module,
            query_params,
            max_limit,
            falcon.query_rule_ids,
            list_name="rule_ids"
        )
        # Get the ids
        rule_ids = query_result.get('rule_ids')
    else:
        # User specified a limit, use it directly
        query_params['limit'] = user_limit
        query_result = falcon.query_rule_ids(**query_params)
        if query_result["status_code"] != 200:
            handle_return_errors(module, result, query_result)
        # Get the ids
        rule_ids = query_result.get('body', {}).get('resources', [])

    return rule_ids


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

    falcon = authenticate(module, Intel)

    result = dict(
        changed=False,
        rules=[]
    )

    # Query rule IDs using the correct parameters
    query_params = {}

    # Build query parameters from module parameters based on docstring
    param_mapping = {
        'type': 'type',
        'name': 'name',
        'description': 'description',
        'tags': 'tags',
        'q': 'q',
        'sort': 'sort',
    }

    for ansible_param, api_param in param_mapping.items():
        value = module.params.get(ansible_param)
        if value is not None:
            query_params[api_param] = value

    # If limit is used, then we need to honor it, otherwise, paginate (if needed)
    rule_ids = _get_rule_ids(
        module,
        falcon,
        query_params,
        result
    )

    if not rule_ids:
        module.exit_json(**result)

    # Get rule details in batches
    # Process in batches of 10 (API default limit)
    for i in range(0, len(rule_ids), 10):
        batch_ids = rule_ids[i:i + 10]
        query_result = falcon.get_rule_entities(ids=batch_ids)

        if query_result["status_code"] == 200:
            result["rules"].extend(query_result["body"]["resources"])
        else:
            handle_return_errors(module, result, query_result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
