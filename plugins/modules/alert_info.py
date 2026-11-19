#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: alert_info

short_description: Get information about Falcon alerts

version_added: "4.15.0"

description:
  - Returns details of Falcon alerts.
  - Gets alerts by composite ID, or searches for them with an FQL filter.
  - With no option, returns every alert.
  - The search reads all pages until there are no more matches, or until
    I(limit) alerts are read.
  - Hidden alerts are returned too. Use the filter C(show_in_ui:true) to leave them out.

options:
  composite_ids:
    description:
      - The composite IDs of the alerts to get, in the form
        C(<cid>:<product>:<...>). This is the C(composite_id) key of an alert,
        not its C(id) key.
      - The IDs are sent as given. An ID with a wrong CID or in upper case
        makes the API fail the whole request.
      - The alerts are returned in the order of this list. A repeated ID
        returns one alert.
      - An empty list returns no alerts.
      - The module fails when an ID does not exist.
        Then the failed result has the alerts that were found in RV(alerts), and the API errors.
      - Mutually exclusive with I(filter), I(sort) and I(limit).
    type: list
    elements: str
  filter:
    description:
      - The FQL filter to search for alerts.
      - C(status:'closed') matches alerts with that status exactly.
      - C(status:!'new') matches alerts that do not have that status.
      - C(product:'epp') matches the alerts of one product exactly.
      - C(severity:>=50) matches alerts with a severity of 50 or more.
      - C(created_timestamp:>'2026-11-01T00:00:00Z') matches alerts created after that time.
      - C(tags:'false_positive') matches alerts that have that tag.
      - C(resolution:'false_positive') matches closed alerts with that resolution.
      - C(assigned_to_name:*'name*') matches alerts whose assignee name starts with the text.
      - C(composite_id:'<id>') matches the alert with that composite ID.
      - C(show_in_ui:false) matches hidden alerts, and C(show_in_ui:true) leaves them out.
      - Join conditions with C(+) (AND), for example C(status:!'closed'+severity:>=70).
      - A filter on an unknown field returns no alerts, with no error.
      - Mutually exclusive with I(composite_ids).
    type: str
  sort:
    description:
      - The property and direction to sort the results by.
      - With C(severity), alerts that have no severity come last in both directions.
      - Mutually exclusive with I(composite_ids).
    type: str
    choices:
      - created_timestamp.asc
      - created_timestamp.desc
      - updated_timestamp.asc
      - updated_timestamp.desc
      - timestamp.asc
      - timestamp.desc
      - severity.asc
      - severity.desc
      - status.asc
      - status.desc
      - composite_id.asc
      - composite_id.desc
  limit:
    description:
      - The maximum number of alerts to return.
      - When not set, the module returns every match.
      - Must be 1 or greater.
      - Mutually exclusive with I(composite_ids).
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
  - module: crowdstrike.falcon.alert
  - name: Alerts API reference
    description: The CrowdStrike API operations that this module uses.
    link: https://developer.crowdstrike.com/api-reference/collections/alerts

requirements:
  - Alerts [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Get the closed endpoint alerts, newest first
  crowdstrike.falcon.alert_info:
    filter: "status:'closed'+product:'epp'"
    sort: created_timestamp.desc

- name: Get the 10 newest alerts
  crowdstrike.falcon.alert_info:
    sort: created_timestamp.desc
    limit: 10

- name: Get alerts by composite ID
  crowdstrike.falcon.alert_info:
    composite_ids:
      - "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"

- name: Get all alerts except the hidden alerts
  crowdstrike.falcon.alert_info:
    filter: "show_in_ui:true"

- name: Get the open alerts of high severity
  crowdstrike.falcon.alert_info:
    filter: "status:!'closed'+severity:>=70"
"""

RETURN = r"""
alerts:
  description:
    - The alerts that match the composite IDs or the filter.
    - For composite IDs, in the order of I(composite_ids).
    - An empty list when nothing matches.
    - The keys below are common to most alerts. Other keys depend on the product
      of the alert.
  type: list
  elements: dict
  returned: success
  contains:
    composite_id:
      description: The composite ID of the alert.
      type: str
      returned: success
      sample: "1234567890abcdef1234567890abcdef:ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    id:
      description: The ID of the alert, which is the composite ID without the leading customer ID.
      type: str
      returned: success
      sample: "ind:abcdef1234567890abcdef1234567890:1234567890123456789-10304-123456789"
    aggregate_id:
      description: The ID of the aggregate that the alert belongs to.
      type: str
      returned: success
      sample: "aggind:abcdef1234567890abcdef1234567890:123456789012"
    agent_id:
      description: The ID of the sensor that reported the alert.
      type: str
      returned: success
      sample: "abcdef1234567890abcdef1234567890"
    cid:
      description: The customer ID that the alert belongs to.
      type: str
      returned: success
      sample: "1234567890abcdef1234567890abcdef"
    product:
      description: The short name of the product that made the alert.
      type: str
      returned: success
      sample: "epp"
    type:
      description: The type of the alert.
      type: str
      returned: success
      sample: "ldt"
    name:
      description: The name of the alert.
      type: str
      returned: success
      sample: "ExampleDetection"
    display_name:
      description: The display name of the alert.
      type: str
      returned: when the product sets it
      sample: "Example detection"
    description:
      description: The description of the alert.
      type: str
      returned: success
      sample: "Example alert description"
    status:
      description: The status of the alert.
      type: str
      returned: success
      sample: "new"
    resolution:
      description:
        - The resolution of the alert, for example C(false_positive) or C(ignored).
      type: str
      returned: when the alert is closed
      sample: "false_positive"
    severity:
      description: The severity of the alert as a number.
      type: int
      returned: when the alert has a severity
      sample: 70
    severity_name:
      description: The name of the severity of the alert.
      type: str
      returned: when the alert has a severity
      sample: "High"
    show_in_ui:
      description: Whether the alert is shown in the Falcon console. C(false) for a hidden alert.
      type: bool
      returned: success
      sample: true
    tags:
      description: The tags of the alert.
      type: list
      elements: str
      returned: when the alert has tags
      sample: ["false_positive"]
    assigned_to_name:
      description: The name of the user that the alert is assigned to.
      type: str
      returned: when the alert is assigned
      sample: "Example User"
    assigned_to_uid:
      description: The user name of the user that the alert is assigned to.
      type: str
      returned: when the alert is assigned
      sample: "user@example.com"
    assigned_to_uuid:
      description: The UUID of the user that the alert is assigned to.
      type: str
      returned: when the alert is assigned
      sample: "12345678-90ab-cdef-1234-567890abcdef"
    comments:
      description: The comments of the alert.
      type: list
      elements: dict
      returned: when the alert has a comment
      contains:
        falcon_user_id:
          description: The ID of the user who added the comment.
          type: str
          returned: success
          sample: "12345678-90ab-cdef-1234-567890abcdef"
        timestamp:
          description: The time when the comment was added.
          type: str
          returned: success
          sample: "2026-01-01T00:00:00.000000000Z"
        value:
          description: The text of the comment.
          type: str
          returned: success
          sample: "Example comment"
    created_timestamp:
      description: The time when the alert was created.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
    updated_timestamp:
      description: The time when the alert was last changed.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000000000Z"
    timestamp:
      description: The time of the event that made the alert.
      type: str
      returned: success
      sample: "2026-01-01T00:00:00.000Z"
    seconds_to_resolved:
      description: The number of seconds from the creation of the alert to its resolution.
      type: int
      returned: success
      sample: 0
    seconds_to_triaged:
      description: The number of seconds from the creation of the alert to its triage.
      type: int
      returned: success
      sample: 0
    source_products:
      description: The products that are the source of the alert.
      type: list
      elements: str
      returned: success
      sample: ["Falcon Insight"]
    device:
      description: The host that the alert is about.
      type: dict
      returned: for endpoint alerts
      sample: {"device_id": "abcdef1234567890abcdef1234567890", "hostname": "example-host"}
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
    from falconpy import Alerts

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# The largest page that the combined search accepts (1001 gives an error).
MAX_LIMIT = 1000

# The largest number of composite IDs that one get request accepts.
MAX_IDS = 1000

SORT_CHOICES = [
    "created_timestamp.asc",
    "created_timestamp.desc",
    "updated_timestamp.asc",
    "updated_timestamp.desc",
    "timestamp.asc",
    "timestamp.desc",
    "severity.asc",
    "severity.desc",
    "status.asc",
    "status.desc",
    "composite_id.asc",
    "composite_id.desc",
]

ALERT_INFO_ARGS = {
    "composite_ids": {"type": "list", "elements": "str", "required": False},
    "filter": {"type": "str", "required": False},
    "sort": {"type": "str", "choices": SORT_CHOICES, "required": False},
    "limit": {"type": "int", "required": False},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(ALERT_INFO_ARGS)

    return args


def validate_params(module):
    """Validate module parameters before any API call."""
    ids = module.params["composite_ids"]
    if ids is not None and any(not object_id for object_id in ids):
        module.fail_json(msg="Parameter 'composite_ids' must not contain an empty ID")

    limit = module.params["limit"]
    if limit is not None and limit < 1:
        module.fail_json(msg="Parameter 'limit' must be 1 or greater")


def get_by_ids(falcon, module, ids):
    """Get alerts by composite ID and fail when an ID does not exist."""
    result = dict(changed=False, alerts=[])

    found = {}
    errors = []
    for start in range(0, len(ids), MAX_IDS):
        query_result = falcon.get_alerts_v2(composite_ids=ids[start:start + MAX_IDS])
        body = query_result["body"]
        # A missing ID gives 404, and the alerts that exist are in resources.
        for alert in body.get("resources") or []:
            found[alert.get("composite_id")] = alert
        chunk_errors = body.get("errors") or []
        errors.extend(chunk_errors)

        missing_in_chunk = any(
            err.get("code") == 404 and err.get("id") for err in chunk_errors
        )
        status_code = query_result["status_code"]
        if status_code != 200 and not missing_in_chunk:
            result["alerts"] = [found[i] for i in ids if i in found]
            handle_return_errors(module, result, query_result)
            # handle_return_errors does not fail when errors is empty or null.
            module.fail_json(
                msg=f"Unexpected status {status_code} while getting alerts",
                **result,
            )

    # The API does not keep the order of the IDs, so use the order of the user list.
    result["alerts"] = [found[i] for i in ids if i in found]

    missing = [err.get("id") for err in errors if err.get("code") == 404 and err.get("id")]
    if missing:
        result["errors"] = errors
        module.fail_json(
            msg=f"Alert not found: {', '.join(missing)}",
            **result,
        )

    return result


def search(falcon, module):
    """Search for alerts and follow the after token over every page."""
    result = dict(changed=False, alerts=[])
    limit = module.params["limit"]

    args = {}
    for key in ("filter", "sort"):
        if module.params.get(key):
            args[key] = module.params[key]

    alerts = []
    after = None
    while True:
        remaining = MAX_LIMIT if limit is None else limit - len(alerts)
        # Never send limit=0: the API then returns its default page of 100.
        page_args = dict(args, limit=min(MAX_LIMIT, remaining))
        if after:
            page_args["after"] = after

        query_result = falcon.get_alerts_combined(**page_args)
        result["alerts"] = alerts
        handle_return_errors(module, result, query_result)
        status_code = query_result["status_code"]
        if status_code != 200:
            # handle_return_errors does not fail when errors is empty or null.
            module.fail_json(
                msg=f"Unexpected status {status_code} while getting alerts",
                **result,
            )

        body = query_result["body"]
        alerts.extend(body.get("resources") or [])

        after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
        if not after or (limit is not None and len(alerts) >= limit):
            break

    result["alerts"] = alerts if limit is None else alerts[:limit]

    return result


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=[
            ("composite_ids", "filter"),
            ("composite_ids", "sort"),
            ("composite_ids", "limit"),
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
        alerts=[],
    )

    ids = module.params["composite_ids"]
    # An empty list from a playbook means "no IDs", not "all objects".
    # Exit before authenticate(), so that it makes no token request.
    if ids is not None and not ids:
        module.exit_json(**result)

    falcon = authenticate(module, Alerts)

    try:
        if ids is not None:
            # A repeated ID returns one alert. The IDs are sent as given,
            # because the API checks the CID part with its case.
            result = get_by_ids(falcon, module, list(dict.fromkeys(ids)))
        else:
            result = search(falcon, module)

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while getting alerts: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
