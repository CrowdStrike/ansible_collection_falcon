#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: correlation_rule_info

short_description: Get information about NG-SIEM correlation rules

version_added: "4.12.0"

description:
  - Returns detailed information for one or more NG-SIEM correlation rules.
  - Some of the details returned include rule name, description, severity, status,
    tactic, technique, search criteria, and creation and modification timestamps.
  - Can retrieve specific rules by ID or search for rules using FQL filters.
  - Optionally includes the latest published version info for each rule.

options:
  rule_ids:
    description:
      - A list of correlation rule IDs to get information about.
      - If not provided, rules will be returned based on filter and pagination settings.
      - Cannot be used together with I(filter).
    type: list
    elements: str
    required: false
  filter:
    description:
      - FQL (Falcon Query Language) filter expression to limit results.
      - "Supported fields: C(customer_id), C(user_id), C(user_uuid), C(status), C(name),
        C(created_on), C(last_updated_on)."
      - "Examples: C(name:'*brute*'), C(status:'enabled'), C(created_on:>='2024-01-01')."
      - Cannot be used together with I(rule_ids).
    type: str
    required: false
  limit:
    description:
      - Maximum number of correlation rules to return.
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
      - Prefix with C(-) for descending order.
      - "Examples: C(name), C(-created_on), C(last_updated_on)."
    type: str
    required: false
  include_latest_version:
    description:
      - Whether to include the latest published version information for each rule.
      - When enabled, adds a C(latest_version) field to each rule with the latest published version details.
      - This requires an additional API call per batch of rules.
    type: bool
    default: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - Correlation Rules [B(READ)] API scope
  - CrowdStrike FalconPy >= 1.5.0

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all correlation rules
  crowdstrike.falcon.correlation_rule_info:

- name: Get specific correlation rules by ID
  crowdstrike.falcon.correlation_rule_info:
    rule_ids:
      - "12345678901234567890abcdef123456"
      - "abcdef123456789012345678901234"

- name: Search rules by name pattern
  crowdstrike.falcon.correlation_rule_info:
    filter: "name:'*brute*'"
    limit: 50

- name: Filter rules by status
  crowdstrike.falcon.correlation_rule_info:
    filter: "status:'enabled'"
    sort: "-last_updated_on"

- name: Get rules with latest version info
  crowdstrike.falcon.correlation_rule_info:
    filter: "status:'enabled'"
    include_latest_version: true

- name: Paginate through all correlation rules
  crowdstrike.falcon.correlation_rule_info:
    limit: 100
    offset: "{{ page * 100 }}"
  loop: "{{ range(0, total_rules // 100 + 1) | list }}"
  loop_control:
    loop_var: page
"""

RETURN = r"""
correlation_rules:
  description:
    - A list of correlation rules that match the search criteria.
  type: list
  returned: success
  elements: dict
  contains:
    id:
      description: The unique identifier of the correlation rule.
      type: str
      returned: success
      sample: "12345678901234567890abcdef123456"
    name:
      description: The name of the correlation rule.
      type: str
      returned: success
      sample: "Brute Force Login Detection"
    description:
      description: The description of the correlation rule.
      type: str
      returned: success
      sample: "Detects repeated failed login attempts"
    severity:
      description: The severity level of the rule.
      type: int
      returned: success
      sample: 3
    status:
      description: The current status of the rule (e.g., enabled, disabled).
      type: str
      returned: success
      sample: "enabled"
    tactic:
      description: The MITRE ATT&CK tactic associated with the rule.
      type: str
      returned: success
      sample: "Credential Access"
    technique:
      description: The MITRE ATT&CK technique associated with the rule.
      type: str
      returned: success
      sample: "Brute Force"
    search:
      description: The search criteria/query for the rule.
      type: dict
      returned: success
    operation:
      description: The operation configuration for the rule.
      type: dict
      returned: success
    notifications:
      description: The notification settings for the rule.
      type: list
      returned: success
      elements: dict
    created_on:
      description: The timestamp when the rule was created.
      type: str
      returned: success
      sample: "2024-01-15T10:30:00.000000Z"
    last_updated_on:
      description: The timestamp when the rule was last updated.
      type: str
      returned: success
      sample: "2024-02-01T14:22:30.000000Z"
    customer_id:
      description: The customer ID that owns the rule.
      type: str
      returned: success
      sample: "abc123def456789"
    latest_version:
      description: Latest published version info for the rule (only when include_latest_version=true).
      type: dict
      returned: when include_latest_version=true
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
          description: Total number of correlation rules matching the query.
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
    from falconpy import CorrelationRules

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

CORRELATION_RULE_INFO_ARGS = {
    "rule_ids": {"type": "list", "elements": "str", "required": False},
    "filter": {"type": "str", "required": False},
    "limit": {"type": "int", "default": 100},
    "offset": {"type": "int", "default": 0},
    "sort": {"type": "str", "required": False},
    "include_latest_version": {"type": "bool", "default": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(CORRELATION_RULE_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    if module.params.get("rule_ids") and module.params.get("filter"):
        module.fail_json(
            msg="Parameters 'rule_ids' and 'filter' are mutually exclusive"
        )

    limit = module.params["limit"]
    if limit < 1 or limit > 500:
        module.fail_json(msg="Parameter 'limit' must be between 1 and 500")

    offset = module.params["offset"]
    if offset < 0:
        module.fail_json(msg="Parameter 'offset' must be 0 or greater")


def get_rules_by_ids(falcon, rule_ids):
    """Retrieve correlation rules by their IDs."""
    return falcon.get_rules(ids=rule_ids)


def search_rules(falcon, module):
    """Search for correlation rules using filters and pagination."""
    params = {
        "limit": module.params["limit"],
        "offset": module.params["offset"],
    }

    if module.params.get("filter"):
        params["filter"] = module.params["filter"]

    if module.params.get("sort"):
        params["sort"] = module.params["sort"]

    return falcon.get_rules_combined(**params)


def get_latest_versions(falcon, rule_ids):
    """Get latest published version info for a list of rule IDs."""
    return falcon.get_latest_rule_versions(rule_ids=rule_ids)


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
    correlation_rules = []
    falcon = authenticate(module, CorrelationRules)

    result = dict(
        changed=False,
        correlation_rules=[],
        meta={},
    )

    try:
        if module.params.get("rule_ids"):
            query_result = get_rules_by_ids(falcon, module.params["rule_ids"])

            if query_result["status_code"] == 200:
                correlation_rules = query_result["body"]["resources"]

                result["meta"] = {
                    "query_time": time.time() - start_time,
                    "pagination": {
                        "offset": 0,
                        "limit": len(correlation_rules),
                        "total": len(correlation_rules),
                    },
                }
        else:
            query_result = search_rules(falcon, module)

            if query_result["status_code"] == 200:
                correlation_rules = query_result["body"]["resources"]

                meta = query_result["body"].get("meta", {})
                result["meta"] = {
                    "query_time": time.time() - start_time,
                    "pagination": {
                        "offset": module.params["offset"],
                        "limit": module.params["limit"],
                        "total": meta.get("pagination", {}).get(
                            "total", len(correlation_rules)
                        ),
                    },
                }

        if module.params["include_latest_version"] and correlation_rules:
            rule_ids = [rule["rule_id"] for rule in correlation_rules]
            latest_result = get_latest_versions(falcon, rule_ids)

            if latest_result["status_code"] == 200:
                latest_by_id = {
                    r["rule_id"]: r
                    for r in (latest_result["body"].get("resources") or [])
                }
                for rule in correlation_rules:
                    rule["latest_version"] = latest_by_id.get(rule["rule_id"])

        result["correlation_rules"] = correlation_rules

        handle_return_errors(module, result, query_result)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while retrieving correlation rule information: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
