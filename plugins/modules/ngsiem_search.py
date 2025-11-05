#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ngsiem_search

short_description: Execute searches against CrowdStrike Next-Gen SIEM repositories

version_added: "4.10.0"

description:
  - Execute CQL (CrowdStrike Query Language) searches against Next-Gen SIEM repositories.
  - Provides asynchronous job-based searching with automatic polling for results.
  - Can correlate network connections with process data for incident response.
  - Supports all available repositories including search-all, investigate_view, and others.
  - Jobs automatically timeout after 90 seconds of inactivity to prevent resource waste.

options:
  repository:
    description:
      - The repository to search against.
      - C(search-all) searches all event data from CrowdStrike and third-party sources.
      - C(investigate_view) searches endpoint event data and sensor events (requires Falcon Insight XDR).
      - C(third-party) searches event data from third-party sources (requires Falcon LogScale).
      - C(falcon_for_it_view) searches data collected by Falcon for IT module (requires Falcon for IT).
      - C(forensics_view) searches triage data from Falcon Forensics module (requires Falcon Forensics).
    type: str
    choices:
      - search-all
      - investigate_view
      - third-party
      - falcon_for_it_view
      - forensics_view
    default: search-all
  query_string:
    description:
      - The CQL query to execute against the repository.
      - Use CrowdStrike Query Language syntax for filtering and correlation.
      - Double quotes and backslashes must be escaped in the query string.
      - Can include variables using C(?param) syntax when used with I(arguments).
    type: str
    required: true
  arguments:
    description:
      - Dictionary of arguments for variables specified in queries with C(?param) syntax.
      - Values must be simple strings.
      - Explicit values in query like C(?param=value) override values provided here.
    type: dict
  start:
    description:
      - Starting point for search results based on event timestamp.
      - Can use relative time like C(1d), C(24h), or absolute timestamps.
      - If I(end) is provided, start must be less than or equal to end.
    type: str
  end:
    description:
      - Ending point for search results based on event timestamp.
      - Can use relative time like C(now), C(1h) ago, or absolute timestamps.
      - If I(start) is provided, end must be greater than or equal to start.
    type: str
  timeout:
    description:
      - Maximum time in seconds to wait for query completion.
      - Query will be canceled if it exceeds this timeout.
      - Set to 0 to disable timeout (use with caution for long-running queries).
    type: int
    default: 300
  poll_interval:
    description:
      - Interval in seconds between status checks while waiting for results.
      - Must be at least 5 seconds to avoid rate limiting.
      - Should not exceed 90 seconds to prevent job timeout.
    type: int
    default: 10

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

requirements:
  - NGSIEM [B(READ), B(WRITE)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Search for all logs from a specific agent ID in the last 24 hours
  crowdstrike.falcon.ngsiem_search:
    query_string: 'aid=abc123'
    start: '1d'
    end: 'now'

- name: Find processes that initiated connections to a specific IP
  crowdstrike.falcon.ngsiem_search:
    repository: investigate_view
    query_string: |
      #event_simpleName=ProcessRollup2
      | join({#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=?target_ip},
             key=ContextProcessId, field=TargetProcessId)
      | table([ImageFileName, CommandLine, ParentProcessId, RemoteAddressIP4])
    arguments:
      target_ip: "192.168.1.50"
    start: '24h'

- name: Search for network connections between specific IPs
  crowdstrike.falcon.ngsiem_search:
    query_string: |
      #event_simpleName=NetworkConnectIP4
      | LocalAddressIP4=?source_ip RemoteAddressIP4=?dest_ip
      | table([ImageFileName, CommandLine, LocalAddressIP4, RemoteAddressIP4, RemotePort])
    arguments:
      source_ip: "10.1.1.100"
      dest_ip: "192.168.1.50"
    timeout: 600

- name: Find failed authentication attempts in the last hour
  crowdstrike.falcon.ngsiem_search:
    repository: search-all
    query_string: |
      #event_simpleName=UserLogon
      | LogonType_decimal=?logon_type
      | table([ComputerName, UserName, LogonTime, FailureReason])
    arguments:
      logon_type: "3"
    start: '1h'
    poll_interval: 5
"""

RETURN = r"""
query_job_id:
  description: The ID of the executed query job.
  type: str
  returned: always
  sample: "P22-xxxx23Nw"
events:
  description: List of events found by the search query.
  type: list
  returned: success
  elements: dict
  sample: [
    {
      "timestamp": "1736264422005",
      "ImageSubsystem": "2",
      "aid": "abc123",
      "name": "ProcessRollup2V19",
      "UserName": "USER3"
    }
  ]
cancelled:
  description: Whether the query was cancelled before completion.
  type: bool
  returned: always
  sample: false
done:
  description: Whether the query completed successfully.
  type: bool
  returned: always
  sample: true
total_events:
  description: Total number of events returned by the search.
  type: int
  returned: success
  sample: 1247
execution_time:
  description: Time taken to execute the query in seconds.
  type: float
  returned: success
  sample: 45.2
"""

import time
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
    from falconpy import NGSIEM

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


NGSIEM_SEARCH_ARGS = {
    "repository": {
        "type": "str",
        "choices": [
            "search-all",
            "investigate_view",
            "third-party",
            "falcon_for_it_view",
            "forensics_view",
        ],
        "default": "search-all",
    },
    "query_string": {"type": "str", "required": True},
    "arguments": {"type": "dict", "required": False},
    "start": {"type": "str", "required": False},
    "end": {"type": "str", "required": False},
    "timeout": {"type": "int", "default": 300},
    "poll_interval": {"type": "int", "default": 10},
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(NGSIEM_SEARCH_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    # Validate poll_interval
    poll_interval = module.params["poll_interval"]
    if poll_interval < 5:
        module.fail_json(
            msg="poll_interval must be at least 5 seconds to avoid rate limiting"
        )
    if poll_interval > 90:
        module.fail_json(
            msg="poll_interval should not exceed 90 seconds to prevent job timeout"
        )

    # Validate timeout
    timeout = module.params["timeout"]
    if timeout < 0:
        module.fail_json(msg="timeout must be a positive number or 0 to disable")


def start_search(falcon, module):
    """Start a NGSIEM search job."""
    params = {
        "repository": module.params["repository"],
        "query_string": module.params["query_string"],
    }

    # Add optional parameters if provided
    if module.params.get("arguments"):
        params["arguments"] = module.params["arguments"]
    if module.params.get("start"):
        params["start"] = module.params["start"]
    if module.params.get("end"):
        params["end"] = module.params["end"]

    return falcon.start_search(**params)


def get_search_results(falcon, module, job_id):
    """Get results for a NGSIEM search job."""
    return falcon.get_search_status(
        repository=module.params["repository"],
        search_id=job_id
    )


def stop_search(falcon, module, job_id):
    """Stop a running NGSIEM search job."""
    return falcon.stop_search(
        repository=module.params["repository"],
        id=job_id
    )


def wait_for_completion(falcon, module, job_id):
    """Wait for search job completion with polling."""
    timeout = module.params["timeout"]
    poll_interval = module.params["poll_interval"]
    start_time = time.time()

    while True:
        # Check if we've exceeded the timeout
        if timeout > 0 and (time.time() - start_time) > timeout:
            # Try to cancel the job before failing
            try:
                stop_search(falcon, module, job_id)
            except Exception:
                # Ignore cancel errors since we're already timing out
                pass
            module.fail_json(
                msg=f"Query timed out after {timeout} seconds",
                query_job_id=job_id
            )

        # Get current status
        result = get_search_results(falcon, module, job_id)

        if result["status_code"] != 200:
            module.fail_json(
                msg="Failed to get search status",
                query_job_id=job_id,
                api_error=result
            )

        # Check if job is complete
        body = result["body"]
        if body.get("done", False):
            return body

        # Check if job was cancelled
        if body.get("cancelled", False):
            return body

        # Wait before next poll
        time.sleep(poll_interval)


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

    result = dict(
        changed=False,
        query_job_id=None,
        events=[],
        cancelled=False,
        done=False,
        total_events=0,
        execution_time=0.0,
    )

    falcon = authenticate(module, NGSIEM)
    start_time = time.time()

    try:
        # Start the search
        query_result = start_search(falcon, module)

        if query_result["status_code"] != 200:
            handle_return_errors(module, result, query_result)

        job_id = query_result["body"]["id"]
        result["query_job_id"] = job_id

        # Wait for completion and get results
        if not module.check_mode:
            search_results = wait_for_completion(falcon, module, job_id)

            result.update({
                "events": search_results.get("events", []),
                "cancelled": search_results.get("cancelled", False),
                "done": search_results.get("done", False),
                "total_events": len(search_results.get("events", [])),
                "execution_time": time.time() - start_time,
            })

            # If the job was cancelled or failed, indicate it in the result
            if search_results.get("cancelled", False):
                result["msg"] = "Search job was cancelled"
            elif not search_results.get("done", False):
                result["msg"] = "Search job did not complete successfully"
        else:
            result["msg"] = "Check mode - search job started but not executed"

    except Exception as e:
        module.fail_json(
            msg=f"An error occurred during search execution: {str(e)}",
            **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
