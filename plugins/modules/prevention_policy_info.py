#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: prevention_policy_info

short_description: Get information about Falcon prevention policies

version_added: "4.15.0"

description:
  - Returns details of Falcon prevention policies.
  - Gets prevention policies by ID, by name, or searches for them with an FQL filter.
  - With no option, returns every prevention policy.
  - The module returns every match. It reads more pages when there are more
    than 5000 matches.
  - Each policy has all its prevention settings, so the result can be large.
    Use a Jinja filter to keep only the keys that you need.

options:
  policy_ids:
    description:
      - The IDs of the prevention policies to get.
      - An empty list returns no prevention policies.
      - The module fails when an ID does not exist.
        Then the failed result has the policies that were found in RV(prevention_policies), and the API errors.
      - The IDs are compared without regard to case.
      - Mutually exclusive with I(name), I(filter) and I(sort).
    type: list
    elements: str
  name:
    description:
      - The exact name of the prevention policies to get, compared without regard to case.
      - A name is unique only for each platform, so more than one policy can match.
        Add I(filter) with C(platform_name:'Windows') to get the policy of one platform.
      - Can be combined with I(filter).
      - Mutually exclusive with I(policy_ids).
    type: str
  filter:
    description:
      - The FQL filter to search for prevention policies.
      - C(platform_name:'Windows') matches the platform name exactly and is case-sensitive.
        The values are C(Windows), C(Windows_Legacy), C(Linux), C(Mac), C(iOS) and C(Android).
      - C(platform_name:['Windows','Mac']) matches any of the platforms in the list.
      - C(enabled:'true') and C(enabled:'false') match enabled or disabled policies.
      - C(description:~'word') matches whole words of the description without regard to case,
        in any order. Part of a word does not match.
      - C(name:~'text') matches whole words of the name without regard to case, in any order.
        C(name:'text') without C(~) matches only a lowercase word. Use I(name) to get a policy by its full name.
      - C(created_timestamp:>'2024-01-01T00:00:00Z') and C(created_timestamp:<'2022-01-01T00:00:00Z')
        match the creation time, and C(modified_timestamp:>'2026-01-01T00:00:00Z') the last change.
        The value must be a timestamp.
      - Join conditions with C(+) (AND), for example C(platform_name:'Windows'+enabled:'true').
      - Mutually exclusive with I(policy_ids).
    type: str
  sort:
    description:
      - The property and direction to sort the results by.
      - C(name) sorts upper case letters before lower case letters.
      - C(created_timestamp) and C(modified_timestamp) sort to the second.
      - Mutually exclusive with I(policy_ids).
    type: str
    choices:
      - name.asc
      - name.desc
      - created_timestamp.asc
      - created_timestamp.desc
      - modified_timestamp.asc
      - modified_timestamp.desc
      - enabled.asc
      - enabled.desc
      - created_by.asc
      - created_by.desc
      - modified_by.asc
      - modified_by.desc

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
  - module: crowdstrike.falcon.prevention_policy
    description: Create, update and delete Falcon prevention policies.
  - name: Prevention Policy API reference
    description: The CrowdStrike API operations that this module uses.
    link: https://developer.crowdstrike.com/api-reference/collections/prevention-policy

requirements:
  - Prevention policies [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get all prevention policies
  crowdstrike.falcon.prevention_policy_info:

- name: Get prevention policies by ID
  crowdstrike.falcon.prevention_policy_info:
    policy_ids:
      - "12345678901234567890abcdef123456"

- name: Get the prevention policies with a name
  crowdstrike.falcon.prevention_policy_info:
    name: platform_default

- name: Get the prevention policy with a name for one platform
  crowdstrike.falcon.prevention_policy_info:
    name: platform_default
    filter: "platform_name:'Windows'"

- name: Get the enabled Windows prevention policies, sorted by name
  crowdstrike.falcon.prevention_policy_info:
    filter: "platform_name:'Windows'+enabled:'true'"
    sort: name.asc
"""

RETURN = r"""
prevention_policies:
  description:
    - The prevention policies that match the IDs, the name or the filter.
    - An empty list when nothing matches.
  type: list
  elements: dict
  returned: success
  contains:
    id:
      description: The ID of the prevention policy.
      type: str
      returned: success
      sample: "12345678901234567890abcdef123456"
    cid:
      description: The customer ID that the policy belongs to.
      type: str
      returned: success
      sample: "abcdef1234567890abcdef1234567890"
    name:
      description: The name of the prevention policy.
      type: str
      returned: success
      sample: "Example prevention policy"
    description:
      description: The description of the prevention policy. Can be empty.
      type: str
      returned: success
      sample: "Example description"
    platform_name:
      description: The platform of the prevention policy.
      type: str
      returned: success
      sample: "Windows"
    enabled:
      description: Whether the prevention policy is enabled.
      type: bool
      returned: success
      sample: true
    groups:
      description: The host groups that the policy is assigned to.
      type: list
      elements: dict
      returned: success
      contains:
        id:
          description: The ID of the host group.
          type: str
          returned: success
          sample: "abcdef1234567890abcdef1234567890"
        group_type:
          description: The type of the host group.
          type: str
          returned: success
          sample: "static"
        name:
          description: The name of the host group.
          type: str
          returned: success
          sample: "Example host group"
        description:
          description: The description of the host group.
          type: str
          returned: success
          sample: "Example host group description"
        assignment_rule:
          description: The assignment rule of the host group.
          type: str
          returned: success
          sample: "hostname:['example-host']"
        created_by:
          description: The user who created the host group.
          type: str
          returned: success
          sample: "user@example.com"
        created_timestamp:
          description: The time when the host group was created.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        modified_by:
          description: The user who last changed the host group.
          type: str
          returned: success
          sample: "user@example.com"
        modified_timestamp:
          description: The time when the host group was last changed.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
    created_by:
      description: The user who created the prevention policy.
      type: str
      returned: success
      sample: "user@example.com"
    created_timestamp:
      description: The time when the prevention policy was created.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
    modified_by:
      description: The user who last changed the prevention policy.
      type: str
      returned: success
      sample: "user@example.com"
    modified_timestamp:
      description: The time when the prevention policy was last changed.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
    prevention_settings:
      description: The prevention settings of the policy, in categories.
      type: list
      elements: dict
      returned: success
      contains:
        name:
          description: The name of the settings category.
          type: str
          returned: success
          sample: "Example category"
        settings:
          description: The settings in the category.
          type: list
          elements: dict
          returned: success
          contains:
            id:
              description: The ID of the setting.
              type: str
              returned: success
              sample: "ExampleSetting"
            name:
              description: The name of the setting.
              type: str
              returned: success
              sample: "Example setting"
            type:
              description: The type of the setting.
              type: str
              returned: success
              sample: "toggle"
            description:
              description: The description of the setting.
              type: str
              returned: success
              sample: "Example setting description"
            value:
              description:
                - The value of the setting. The keys depend on the type of the setting.
                - A C(toggle) setting has C(enabled) and most have C(configured).
                  An C(mlslider) setting has C(detection) and most have C(prevention).
              type: dict
              returned: success
              sample: {"configured": true, "enabled": true}
    ioa_rule_groups:
      description: The custom IOA rule groups that are assigned to the policy.
      type: list
      elements: dict
      returned: success
      contains:
        id:
          description: The ID of the rule group.
          type: str
          returned: success
          sample: "abcdef1234567890abcdef1234567890"
        customer_id:
          description: The customer ID that the rule group belongs to.
          type: str
          returned: success
          sample: "abcdef1234567890abcdef1234567890"
        enabled:
          description: Whether the rule group is enabled.
          type: bool
          returned: success
          sample: true
        name:
          description: The name of the rule group.
          type: str
          returned: success
          sample: "Example rule group"
        description:
          description: The description of the rule group.
          type: str
          returned: success
          sample: "Example rule group description"
        platform:
          description: The platform of the rule group.
          type: str
          returned: success
          sample: "windows"
        deleted:
          description: Whether the rule group is deleted.
          type: bool
          returned: success
          sample: false
        rule_ids:
          description: The IDs of the rules in the rule group.
          type: list
          elements: str
          returned: success
          sample: ["1", "2"]
        comment:
          description: The comment of the last change to the rule group.
          type: str
          returned: success
          sample: "Example comment"
        version:
          description: The version of the rule group.
          type: int
          returned: success
          sample: 1
        created_by:
          description: The user who created the rule group.
          type: str
          returned: success
          sample: "user@example.com"
        created_timestamp:
          description: The time when the rule group was created.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        modified_by:
          description: The user who last changed the rule group.
          type: str
          returned: success
          sample: "user@example.com"
        modified_timestamp:
          description: The time when the rule group was last changed.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        committed_timestamp:
          description: The time when the last change to the rule group was committed.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
    get_paginated_results_info,
    handle_return_errors,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import PreventionPolicy

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# The largest page that the search accepts.
MAX_LIMIT = 5000

SORT_CHOICES = [
    "name.asc",
    "name.desc",
    "created_timestamp.asc",
    "created_timestamp.desc",
    "modified_timestamp.asc",
    "modified_timestamp.desc",
    "enabled.asc",
    "enabled.desc",
    "created_by.asc",
    "created_by.desc",
    "modified_by.asc",
    "modified_by.desc",
]

PREVENTION_POLICY_INFO_ARGS = {
    "policy_ids": {"type": "list", "elements": "str", "required": False},
    "name": {"type": "str", "required": False},
    "filter": {"type": "str", "required": False},
    "sort": {"type": "str", "choices": SORT_CHOICES, "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(PREVENTION_POLICY_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters before any API call."""
    # name:~'' matches nothing, so an empty name is a mistake.
    if module.params["name"] is not None and not module.params["name"]:
        module.fail_json(msg="Parameter 'name' must not be empty")

    policy_ids = module.params["policy_ids"]
    if policy_ids is not None and any(not pid for pid in policy_ids):
        module.fail_json(msg="Parameter 'policy_ids' must not contain an empty ID")


def escape_fql_value(value):
    """Escape a value for a single-quoted FQL string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_filter(module):
    """Build the FQL filter from the name and filter options."""
    name = module.params["name"]
    user_filter = module.params["filter"]

    if name is None:
        return user_filter

    name_filter = f"name:~'{escape_fql_value(name)}'"
    if user_filter:
        # The parentheses keep a "," (OR) in the user filter under the "+" (AND).
        return f"{name_filter}+({user_filter})"

    return name_filter


def get_by_ids(falcon, module, policy_ids):
    """Get prevention policies by ID and fail when an ID does not exist."""
    result = dict(changed=False, prevention_policies=[])

    query_result = falcon.get_policies(ids=policy_ids)
    body = query_result["body"]
    # A missing ID gives 404, and the policies that exist are in resources.
    result["prevention_policies"] = body.get("resources") or []

    errors = body.get("errors") or []
    missing = [err.get("id") for err in errors if err.get("code") == 404 and err.get("id")]
    if missing:
        result["errors"] = errors
        module.fail_json(
            msg=f"Prevention policy not found: {', '.join(missing)}",
            **result,
        )

    status_code = query_result["status_code"]
    if status_code != 200:
        handle_return_errors(module, result, query_result)
        # handle_return_errors does not fail when errors is empty or null.
        module.fail_json(
            msg=f"Unexpected status {status_code} while getting prevention policies",
            **result,
        )

    return result


def search(falcon, module):
    """Search for prevention policies and read every page."""
    args = {}
    fql = build_filter(module)
    if fql:
        args["filter"] = fql
    if module.params["sort"]:
        args["sort"] = module.params["sort"]

    def query(**kwargs):
        query_result = falcon.query_combined_policies(**kwargs)
        status_code = query_result["status_code"]
        if status_code != 200:
            # The helper fails only when errors is not empty, so fail here
            # for a status with no errors, as get_by_ids does.
            failed = dict(changed=False, prevention_policies=[])
            handle_return_errors(module, failed, query_result)
            module.fail_json(
                msg=f"Unexpected status {status_code} while getting prevention policies",
                **failed,
            )
        return query_result

    result = get_paginated_results_info(
        module,
        args,
        MAX_LIMIT,
        query,
        "prevention_policies",
    )

    name = module.params["name"]
    if name is not None:
        # name:~ matches words in any order, so keep only the exact names.
        wanted = name.casefold()
        result["prevention_policies"] = [
            policy
            for policy in result["prevention_policies"]
            if (policy.get("name") or "").casefold() == wanted
        ]

    return result


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=[
            ("policy_ids", "name"),
            ("policy_ids", "filter"),
            ("policy_ids", "sort"),
        ],
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)
    validate_params(module)

    result = dict(
        changed=False,
        prevention_policies=[],
    )

    policy_ids = module.params["policy_ids"]
    # An empty list from a playbook means "no IDs", not "all policies".
    if policy_ids is not None and not policy_ids:
        module.exit_json(**result)

    falcon = authenticate(module, PreventionPolicy)

    try:
        if policy_ids is not None:
            # The API IDs are lower case, and repeated IDs come back repeated,
            # so send each ID once, in lower case and in order.
            result = get_by_ids(falcon, module, list(dict.fromkeys(pid.lower() for pid in policy_ids)))
        else:
            result = search(falcon, module)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while getting prevention policies: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
