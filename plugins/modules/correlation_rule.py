#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: correlation_rule

short_description: Manage NG-SIEM correlation rules

version_added: "4.12.0"

description:
  - Create, update, and delete NG-SIEM correlation rules in the CrowdStrike Falcon platform.
  - Supports idempotent operations that only make changes when necessary.
  - Can optionally publish a rule version after create or update.
  - The customer ID (CID) is automatically resolved from the authenticated API session.

options:
  state:
    description:
      - The desired state of the correlation rule.
      - C(present) ensures the rule exists with the specified configuration.
      - C(absent) ensures the rule does not exist.
    type: str
    choices: ["present", "absent"]
    default: present
  name:
    description:
      - The name of the correlation rule.
      - Required when creating a new rule and I(rule_id) is not provided.
      - Used to look up an existing rule when I(rule_id) is not specified.
    type: str
    required: false
  rule_id:
    description:
      - The ID of an existing correlation rule.
      - Preferred for identifying existing rules during update or delete operations.
      - If provided with I(state=present), the module will update the existing rule.
      - If provided with I(state=absent), the module will delete the rule by ID.
    type: str
    required: false
  description:
    description:
      - A description for the correlation rule.
    type: str
    required: false
  comment:
    description:
      - A comment associated with the rule change.
    type: str
    required: false
  severity:
    description:
      - The severity level of the rule.
      - "Valid values: C(10) (informational), C(30) (low), C(50) (medium), C(70) (high), C(90) (critical)."
    type: int
    choices: [10, 30, 50, 70, 90]
    required: false
  status:
    description:
      - The operational status of the rule.
      - C(active) enables the rule.
      - C(inactive) disables the rule without deleting it.
    type: str
    choices: ["active", "inactive"]
    required: false
  tactic:
    description:
      - The MITRE ATT&CK tactic associated with the rule.
    type: str
    required: false
  technique:
    description:
      - The MITRE ATT&CK technique associated with the rule.
    type: str
    required: false
  search:
    description:
      - Search criteria for the correlation rule.
      - Required when creating a new rule.
    type: dict
    required: false
    suboptions:
      filter:
        description: CQL filter string for the search query.
        type: str
      lookback:
        description: Lookback period for the search (e.g., C(5m), C(1h), C(24h)).
        type: str
      outcome:
        description:
          - The outcome type when the rule triggers.
          - "Valid values: C(detection), C(incident), C(case), C(event)."
          - "B(Note:) The C(incident) outcome is deprecated and will be retired on June 8, 2026.
            Rules using C(incident) will be automatically switched to C(detection). Use C(detection) instead."
        type: str
      trigger_mode:
        description: Trigger mode for the rule.
        type: str
  operation:
    description:
      - Scheduling configuration for the rule.
      - Required when creating a new rule.
    type: dict
    required: false
    suboptions:
      schedule:
        description:
          - Schedule definition dict containing a C(definition) key with a cron expression.
          - "Example: C({'definition': '*/5 * * * *'}) for every 5 minutes."
        type: dict
      start_on:
        description: ISO 8601 datetime string for when the rule becomes active.
        type: str
      stop_on:
        description: ISO 8601 datetime string for when the rule stops being active.
        type: str
  notifications:
    description:
      - List of notification configurations for the rule.
    type: list
    elements: dict
    required: false
  trigger_on_create:
    description:
      - Whether the rule triggers on creation.
      - Only applicable when creating a new rule.
    type: bool
    required: false
    default: false
  publish:
    description:
      - Whether to publish the rule version after a create or update operation.
      - When C(true), the module will retrieve the latest rule version and publish it.
    type: bool
    required: false
    default: false

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - B(Idempotency:) This module is idempotent and will only make changes when the
    current state differs from the desired state.
  - B(Rule Lookup:) When I(rule_id) is not provided, the module searches by I(name).
    If multiple rules share the same name, the first match is used. Prefer I(rule_id)
    for precise targeting.
  - B(Publishing:) Setting I(publish=true) will publish the latest rule version after
    any create or update. Publishing is skipped when no changes are made.
  - B(State Management:) For I(state=absent), if the rule is not found, the module
    exits successfully without making any changes (idempotent).

requirements:
  - Correlation Rules [B(READ), B(WRITE)] API scope
  - Sensor Download [B(READ)] API scope (for CID auto-detection)
  - CrowdStrike FalconPy >= 1.5.0

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Create a correlation rule
  crowdstrike.falcon.correlation_rule:
    name: "Detect suspicious logins"
    description: "Alert on multiple failed logins followed by success"
    severity: 50
    status: active
    search:
      filter: "#event_simpleName=UserLogon"
      lookback: "10m"
      outcome: "detection"
    operation:
      schedule:
        definition: "*/5 * * * *"

- name: Create a rule with MITRE ATT&CK mapping
  crowdstrike.falcon.correlation_rule:
    name: "Brute Force Detection"
    description: "Detects brute force login attempts"
    severity: 70
    status: active
    tactic: "Credential Access"
    technique: "Brute Force"
    search:
      filter: "#event_simpleName=UserLogon"
      lookback: "10m"
      outcome: "detection"
    operation:
      schedule:
        definition: "*/5 * * * *"

- name: Update an existing rule by name
  crowdstrike.falcon.correlation_rule:
    name: "Detect suspicious logins"
    description: "Updated description for suspicious login detection"
    severity: 70

- name: Update a rule by ID
  crowdstrike.falcon.correlation_rule:
    rule_id: "a1b2c3d4e5f6789012345678901234ab"
    status: inactive
    comment: "Disabling temporarily for maintenance"

- name: Delete a rule by name
  crowdstrike.falcon.correlation_rule:
    name: "Detect suspicious logins"
    state: absent

- name: Delete a rule by ID
  crowdstrike.falcon.correlation_rule:
    rule_id: "a1b2c3d4e5f6789012345678901234ab"
    state: absent

- name: Create and publish a rule
  crowdstrike.falcon.correlation_rule:
    name: "Lateral Movement Detection"
    description: "Detects potential lateral movement activity"
    severity: 70
    status: active
    tactic: "Lateral Movement"
    search:
      filter: "#event_simpleName=NetworkConnectIP4"
      lookback: "15m"
      outcome: "detection"
    operation:
      schedule:
        definition: "*/10 * * * *"
    publish: true
"""

RETURN = r"""
correlation_rule:
  description:
    - Information about the correlation rule that was created or updated.
  type: dict
  returned: when state=present
  contains:
    id:
      description: The unique identifier of the correlation rule.
      type: str
      returned: success
      sample: "a1b2c3d4e5f6789012345678901234ab"
    name:
      description: The name of the correlation rule.
      type: str
      returned: success
      sample: "Detect suspicious logins"
    description:
      description: The description of the correlation rule.
      type: str
      returned: success
      sample: "Alert on multiple failed logins followed by success"
    severity:
      description: The severity level of the rule.
      type: int
      returned: success
      sample: 50
    status:
      description: The operational status of the rule.
      type: str
      returned: success
      sample: "active"
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
      description: The search criteria for the rule.
      type: dict
      returned: success
    operation:
      description: The scheduling configuration for the rule.
      type: dict
      returned: when configured
    notifications:
      description: The list of notification configurations for the rule.
      type: list
      returned: when configured
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
      description: The customer ID associated with the rule.
      type: str
      returned: success
      sample: "0123456789abcdef0123456789abcdef"
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
    from falconpy import CorrelationRules, SensorDownload

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

CORRELATION_RULE_ARGS = {
    "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
    "name": {"type": "str", "required": False},
    "rule_id": {"type": "str", "required": False},
    "description": {"type": "str", "required": False},
    "comment": {"type": "str", "required": False},
    "severity": {
        "type": "int",
        "choices": [10, 30, 50, 70, 90],
        "required": False,
    },
    "status": {"type": "str", "choices": ["active", "inactive"], "required": False},
    "tactic": {"type": "str", "required": False},
    "technique": {"type": "str", "required": False},
    "search": {"type": "dict", "required": False},
    "operation": {"type": "dict", "required": False},
    "notifications": {"type": "list", "elements": "dict", "required": False},
    "trigger_on_create": {"type": "bool", "required": False, "default": False},
    "publish": {"type": "bool", "required": False, "default": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(CORRELATION_RULE_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    state = module.params["state"]
    name = module.params.get("name")
    rule_id = module.params.get("rule_id")

    if state == "present":
        if not rule_id and not name:
            module.fail_json(
                msg="Either 'name' or 'rule_id' is required when state=present"
            )

    elif state == "absent":
        if not rule_id and not name:
            module.fail_json(
                msg="Either 'rule_id' or 'name' is required when state=absent"
            )


def resolve_customer_id(module):
    """Resolve the customer ID from the authenticated API session."""
    falcon_sd = authenticate(module, SensorDownload)
    ccid_result = falcon_sd.get_sensor_installer_ccid()
    if ccid_result["status_code"] != 200 or not ccid_result["body"].get("resources"):
        module.fail_json(msg="Failed to resolve customer ID (CID) from API")

    ccid = ccid_result["body"]["resources"][0]
    return ccid.split("-")[0].lower()


def get_existing_rule(falcon, rule_id):
    """Get an existing correlation rule by ID."""
    result = falcon.get_rules(ids=[rule_id])
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0]
    return None


def find_rule_by_name(falcon, name):
    """Find a correlation rule by name."""
    result = falcon.get_rules_combined(filter=f"name:'{name}'", limit=1)
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0]
    return None


def create_rule(falcon, module, customer_id):
    """Create a new correlation rule."""
    params = {
        "name": module.params["name"],
        "customer_id": customer_id,
    }

    for field in ["description", "comment", "severity", "status", "tactic", "technique",
                  "search", "operation", "notifications"]:
        if module.params.get(field) is not None:
            params[field] = module.params[field]

    if module.params.get("trigger_on_create"):
        params["trigger_on_create"] = module.params["trigger_on_create"]

    return falcon.create_rule(**params)


def update_rule(falcon, module, rule_id, customer_id):
    """Update an existing correlation rule."""
    params = {
        "id": rule_id,
        "customer_id": customer_id,
    }

    for field in ["name", "description", "comment", "severity", "status", "tactic",
                  "technique", "search", "operation", "notifications"]:
        if module.params.get(field) is not None:
            params[field] = module.params[field]

    return falcon.update_rule(**params)


def delete_rule(falcon, rule_id):
    """Delete a correlation rule."""
    return falcon.delete_rules(ids=[rule_id])


def publish_rule(falcon, module, result, rule_id):
    """Publish the latest version of a rule."""
    version_result = falcon.get_latest_rule_versions(rule_ids=[rule_id])
    if version_result["status_code"] != 200:
        handle_return_errors(module, result, version_result)

    resources = version_result["body"].get("resources", [])
    if not resources:
        module.fail_json(
            msg=f"No rule versions found for rule ID '{rule_id}'", **result
        )

    version_id = resources[0]["id"]
    publish_result = falcon.publish_rule_version(id=version_id)
    if publish_result["status_code"] != 200:
        handle_return_errors(module, result, publish_result)


TRANSITION_STATUSES = ("creating", "updating", "deleting")


def rule_needs_update(current_rule, module):
    """Check if the current rule needs to be updated based on module parameters."""
    if current_rule.get("status") in TRANSITION_STATUSES:
        return False

    needs_update = False

    simple_fields = ["name", "description", "severity", "tactic", "technique"]
    for field in simple_fields:
        value = module.params.get(field)
        if value is not None and current_rule.get(field) != value:
            needs_update = True

    if module.params.get("status") is not None:
        current_status = current_rule.get("status")
        if current_status not in TRANSITION_STATUSES:
            if current_status != module.params["status"]:
                needs_update = True

    for field in ["search", "operation"]:
        value = module.params.get(field)
        if value is not None:
            current = current_rule.get(field, {}) or {}
            for key, val in value.items():
                if current.get(key) != val:
                    needs_update = True

    if module.params.get("notifications") is not None:
        if current_rule.get("notifications") != module.params["notifications"]:
            needs_update = True

    return needs_update


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

    state = module.params["state"]
    rule_id = module.params.get("rule_id")
    name = module.params.get("name")

    result = dict(
        changed=False,
    )

    if module.check_mode:
        module.exit_json(**result)

    falcon = authenticate(module, CorrelationRules)

    try:
        if state == "present":
            customer_id = resolve_customer_id(module)
            current_rule = None

            if rule_id:
                current_rule = get_existing_rule(falcon, rule_id)
                if not current_rule:
                    module.fail_json(msg=f"Correlation rule with ID '{rule_id}' not found")
            elif name:
                current_rule = find_rule_by_name(falcon, name)

            if current_rule:
                if rule_needs_update(current_rule, module):
                    update_result = update_rule(
                        falcon, module, current_rule["id"], customer_id
                    )
                    if update_result["status_code"] != 200:
                        handle_return_errors(module, result, update_result)
                    result["changed"] = True

                    updated_rule = get_existing_rule(falcon, current_rule["id"])
                    result["correlation_rule"] = (
                        updated_rule if updated_rule else current_rule
                    )

                    if module.params.get("publish"):
                        publish_rule(falcon, module, result, current_rule["id"])
                else:
                    result["correlation_rule"] = current_rule

            else:
                create_result = create_rule(falcon, module, customer_id)
                if create_result["status_code"] != 200:
                    handle_return_errors(module, result, create_result)

                if create_result["body"].get("resources"):
                    new_rule = create_result["body"]["resources"][0]
                    result["correlation_rule"] = new_rule
                    result["changed"] = True

                    if module.params.get("publish"):
                        publish_rule(falcon, module, result, new_rule["id"])

        elif state == "absent":
            current_rule = None

            if rule_id:
                current_rule = get_existing_rule(falcon, rule_id)
                if not current_rule:
                    module.fail_json(msg=f"Correlation rule with ID '{rule_id}' not found")
            elif name:
                current_rule = find_rule_by_name(falcon, name)

            if current_rule:
                delete_result = delete_rule(falcon, current_rule["id"])
                if delete_result["status_code"] != 200:
                    handle_return_errors(module, result, delete_result)
                result["changed"] = True

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while managing the correlation rule: {str(e)}", **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
