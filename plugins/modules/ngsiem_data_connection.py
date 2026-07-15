#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: ngsiem_data_connection

short_description: Manage NG-SIEM data connections

version_added: "4.13.0"

description:
  - Create, update, delete, and pause/resume NG-SIEM data connections in the
    CrowdStrike Falcon platform.
  - Data connections feed third-party log sources into Next-Gen SIEM. They come
    in two shapes - B(PULL) connections (e.g. AWS S3, Azure Event Hubs) where Falcon
    pulls from your source using credentials in a C(config) block, and B(PUSH)
    connections (e.g. HEC / HTTP Event Connector) where you push logs to an
    C(ingest_url) using an ingest token.
  - Supports idempotent operations that only make changes when necessary.
  - Use M(crowdstrike.falcon.ngsiem_data_connector_info) to discover valid
    I(connector_id) and I(parser) values.

options:
  state:
    description:
      - The desired state of the data connection.
      - C(present) ensures the connection exists with the specified configuration.
      - C(absent) ensures the connection does not exist.
    type: str
    choices: ["present", "absent"]
    default: present
  connection_id:
    description:
      - The ID of an existing data connection.
      - Preferred for identifying existing connections during update, delete, or
        pause/resume operations.
      - Either I(connection_id) or I(name) is required.
    type: str
    required: false
  name:
    description:
      - The name of the data connection.
      - Required when creating a new connection and I(connection_id) is not provided.
      - Used to look up an existing connection when I(connection_id) is not specified.
    type: str
    required: false
  connector_id:
    description:
      - The ID of the connector this connection is based on.
      - Required when creating a new connection.
      - Use M(crowdstrike.falcon.ngsiem_data_connector_info) to discover available connectors.
    type: str
    required: false
  parser:
    description:
      - The parser to apply to the connection's data.
      - Required when creating a new connection.
      - The value must be valid for the chosen connector (e.g. C(microsoft-edge)).
        The API is the source of truth and will reject invalid parsers.
    type: str
    required: false
  vendor_name:
    description:
      - The vendor name associated with the connection.
    type: str
    required: false
  vendor_product_name:
    description:
      - The vendor product name associated with the connection.
    type: str
    required: false
  description:
    description:
      - A description for the data connection.
      - "B(Note:) This field is write-only. It is applied on create but is never
        returned by the API, so changes to it alone cannot be detected for idempotency."
    type: str
    required: false
  config:
    description:
      - A free-form configuration dict for the connection.
      - Used by PULL connectors to supply authentication and parameters
        (e.g. C(config.auth), C(config.params)).
      - "B(Note:) This field is write-only. It is applied on create but is never
        returned by the API, so changes to it alone cannot be detected for idempotency."
    type: dict
    required: false
  config_id:
    description:
      - The ID of a saved connector config to associate with the connection.
    type: str
    required: false
  connector_type:
    description:
      - The type of the connector.
    type: str
    required: false
  log_sources:
    description:
      - A list of log sources for the connection.
    type: list
    elements: str
    required: false
  enable_host_enrichment:
    description:
      - Whether to enable host enrichment for the connection.
      - "B(Note:) This field is write-only. It is applied on create but is never
        returned by the API, so changes to it alone cannot be detected for idempotency."
    type: bool
    required: false
  enable_user_enrichment:
    description:
      - Whether to enable user enrichment for the connection.
      - "B(Note:) This field is write-only. It is applied on create but is never
        returned by the API, so changes to it alone cannot be detected for idempotency."
    type: bool
    required: false
  enabled:
    description:
      - Whether the connection should be running (resumed) or paused.
      - C(true) resumes a paused connection; C(false) pauses a running connection.
      - Only applied when the connection already exists.
      - Pausing is only valid when the connection is in an C(Active), C(Error), or
        C(Idle) state; the module reads the current status first and no-ops otherwise.
    type: bool
    required: false
  wait_for_ingest_token:
    description:
      - Whether to wait for the ingest token to become available when creating a
        PUSH connection.
      - The token is minted on the first successful request, but immediately after
        create the connection is still provisioning and the token endpoint returns
        "not ready". When C(true), the module polls until the token is available or
        I(wait_timeout) is reached.
      - The token is a one-time secret - it can only be retrieved once, so enabling
        this is the only reliable way to capture it during creation.
      - Only applies to the create of a PUSH connection.
    type: bool
    required: false
    default: true
  wait_timeout:
    description:
      - Maximum number of seconds to wait for the ingest token when
        I(wait_for_ingest_token) is C(true).
      - If the token is still not available after this timeout, the connection is
        left created and the module returns without the token (with a warning)
        rather than failing.
    type: int
    required: false
    default: 120

extends_documentation_fragment:
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - B(Idempotency:) This module is idempotent and will only make changes when the
    current state differs from the desired state.
  - B(Drift detection:) Idempotency is determined by comparing I(name) and
    I(parser) against the existing connection. Vendor fields are not compared
    because some connectors (e.g. the built-in HEC connector) override
    I(vendor_product_name) with their own value on create. Changes to
    I(description), I(config), or the enrichment flags cannot be detected either
    (the API never returns them); they are only applied on create.
  - B(Connection Lookup:) When I(connection_id) is not provided, the module searches
    by I(name). Prefer I(connection_id) for precise targeting.
  - B(Ingest token:) For PUSH connections, an ingest token is minted and returned
    once on create as the C(ingest_token) value alongside C(ingest_url). The token
    cannot be retrieved again, so it is a sensitive value - handle and store it
    securely. Because the connection is still provisioning immediately after create,
    the module waits for the token by default (see I(wait_for_ingest_token) and
    I(wait_timeout)). Token rotation is not supported in this module.
  - B(State Management:) For I(state=absent), if the connection is not found, the
    module exits successfully without making any changes (idempotent).

requirements:
  - NGSIEM Data Connections [B(READ), B(WRITE)] API scope
  - CrowdStrike FalconPy >= 1.5.0

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Create a PUSH (HEC) data connection
  crowdstrike.falcon.ngsiem_data_connection:
    name: "Edge browser logs"
    connector_id: "a1bfd0c4380f436790cb41afc2b95f38"
    parser: "microsoft-edge"
    vendor_name: "Microsoft"
    vendor_product_name: "Edge"
  register: hec_connection

- name: Show the ingest URL (the token is sensitive and only returned once on create)
  ansible.builtin.debug:
    var: hec_connection.data_connection.ingest_url

- name: Create a PULL (S3) data connection with auth config
  crowdstrike.falcon.ngsiem_data_connection:
    name: "AWS S3 CloudTrail"
    connector_id: "0123456789abcdef0123456789abcdef"
    parser: "aws-cloudtrail"
    vendor_name: "AWS"
    vendor_product_name: "CloudTrail"
    config:
      auth:
        access_key_id: "{{ aws_access_key_id }}"
        secret_access_key: "{{ aws_secret_access_key }}"
      params:
        bucket: "my-cloudtrail-bucket"
        region: "us-east-1"

- name: Update a connection's name by ID
  crowdstrike.falcon.ngsiem_data_connection:
    connection_id: "abcdef1234567890abcdef1234567890"
    name: "Edge browser logs (renamed)"

- name: Pause a connection
  crowdstrike.falcon.ngsiem_data_connection:
    connection_id: "abcdef1234567890abcdef1234567890"
    enabled: false

- name: Resume a connection
  crowdstrike.falcon.ngsiem_data_connection:
    connection_id: "abcdef1234567890abcdef1234567890"
    enabled: true

- name: Delete a connection by name
  crowdstrike.falcon.ngsiem_data_connection:
    name: "Edge browser logs"
    state: absent

- name: Delete a connection by ID
  crowdstrike.falcon.ngsiem_data_connection:
    connection_id: "abcdef1234567890abcdef1234567890"
    state: absent
"""

RETURN = r"""
data_connection:
  description:
    - Information about the data connection that was created or updated.
    - Only fields returned by the API are included.
  type: dict
  returned: when state=present
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
      sample: "https://ingest.us-2.crowdstrike.com/services/collector/..."
ingest_token:
  description:
    - The ingest token for a PUSH connection.
    - Minted and returned B(only once), on create of a PUSH connection. It cannot
      be retrieved again.
    - This is a sensitive value; handle and store it securely.
  type: str
  returned: on create of a PUSH connection
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
    from falconpy import NGSIEM, APIHarnessV2

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

# Operation ID for the raw ingest-token command (see fetch_ingest_token).
INGEST_TOKEN_OPERATION = "ExternalGetDataConnectionToken"

# Fields the API returns for an existing connection that we can compare against
# module params for drift detection. description/config/enrichment flags are
# write-only (never returned) so they cannot be compared here.
READABLE_FIELDS = (
    "id",
    "name",
    "vendor_name",
    "vendor_product_name",
    "parser_name",
    "status",
    "source_type",
    "last_ingested_volume_one_day",
    "ingest_url",
)

# Provisioning states from which a Pause is accepted by the API.
PAUSABLE_STATUSES = ("Active", "Error", "Idle")

NGSIEM_DATA_CONNECTION_ARGS = {
    "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
    "connection_id": {"type": "str", "required": False},
    "name": {"type": "str", "required": False},
    "connector_id": {"type": "str", "required": False},
    "parser": {"type": "str", "required": False},
    "vendor_name": {"type": "str", "required": False},
    "vendor_product_name": {"type": "str", "required": False},
    "description": {"type": "str", "required": False},
    "config": {"type": "dict", "required": False},
    "config_id": {"type": "str", "required": False},
    "connector_type": {"type": "str", "required": False},
    "log_sources": {"type": "list", "elements": "str", "required": False},
    "enable_host_enrichment": {"type": "bool", "required": False},
    "enable_user_enrichment": {"type": "bool", "required": False},
    "enabled": {"type": "bool", "required": False},
    "wait_for_ingest_token": {"type": "bool", "required": False, "default": True},
    "wait_timeout": {"type": "int", "required": False, "default": 120},
}

# Body fields passed through on create/update, mapped from module param names to
# the API body key.
BODY_FIELDS = {
    "name": "name",
    "connector_id": "connector_id",
    "parser": "parser",
    "vendor_name": "vendor_name",
    "vendor_product_name": "vendor_product_name",
    "description": "description",
    "config": "config",
    "config_id": "config_id",
    "connector_type": "connector_type",
    "log_sources": "log_sources",
    "enable_host_enrichment": "enable_host_enrichment",
    "enable_user_enrichment": "enable_user_enrichment",
}


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(NGSIEM_DATA_CONNECTION_ARGS)

    return args


def validate_params(module):
    """Validate module parameters."""
    connection_id = module.params.get("connection_id")
    name = module.params.get("name")

    if not connection_id and not name:
        module.fail_json(
            msg="Either 'connection_id' or 'name' is required"
        )


def build_body(module):
    """Build the create/update request body from module params."""
    body = {}
    for param, key in BODY_FIELDS.items():
        value = module.params.get(param)
        if value is not None:
            body[key] = value
    return body


def get_existing(falcon, connection_id):
    """Get an existing data connection by ID."""
    result = falcon.get_connection_by_id(ids=[connection_id])
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0]
    return None


def find_connection_by_name(falcon, name):
    """Find a data connection by name."""
    result = falcon.list_data_connections(filter=f"name:'{name}'", limit=1)
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0]
    return None


def connection_needs_update(current, module):
    """Check if the connection needs updating based on readable fields only.

    Only ``name`` and ``parser`` are compared. Vendor fields are excluded on
    purpose: some connectors (e.g. the built-in HEC connector) override
    ``vendor_product_name`` (and potentially ``vendor_name``) with their own
    value on create, so comparing them would report drift on every run and
    trigger an endless update loop. ``description``/``config``/enrichment flags
    are write-only and never returned, so they cannot be compared either.
    """
    comparisons = (
        ("name", "name"),
        ("parser", "parser_name"),
    )
    for param, current_key in comparisons:
        value = module.params.get(param)
        if value is not None and current.get(current_key) != value:
            return True
    return False


def get_current_status(falcon, connection_id):
    """Return the current provisioning status of a connection, or None."""
    result = falcon.get_provisioning_status(ids=connection_id)
    if result["status_code"] == 200 and result["body"].get("resources"):
        return result["body"]["resources"][0].get("status")
    return None


def apply_enabled(falcon, module, result, connection_id):
    """Pause or resume a connection to match the desired 'enabled' state."""
    enabled = module.params.get("enabled")
    if enabled is None:
        return

    current_status = get_current_status(falcon, connection_id)

    if enabled is False:
        # Only pause from a pausable state, and only if not already paused.
        if current_status in PAUSABLE_STATUSES:
            status_result = falcon.update_connection_status(
                ids=connection_id, status="Pause"
            )
            if status_result["status_code"] != 200:
                handle_return_errors(module, result, status_result)
            result["changed"] = True
    else:
        # Resume only if currently paused.
        if current_status == "Paused":
            status_result = falcon.update_connection_status(
                ids=connection_id, status="Resume"
            )
            if status_result["status_code"] != 200:
                handle_return_errors(module, result, status_result)
            result["changed"] = True


def _extract_token(token_result, result):
    """Pull token/url out of a token command response. Returns True if a token was found.

    The ingest-token endpoint returns ``resources`` as a *dict* (not a list):
      - 200: ``{"token": ..., "ingest_url": ..., "created_at": ..., "expires_at": ...}``
      - 202: ``{"error": "ConnectionNotReady", "message": ...}`` (still provisioning)
    """
    if token_result.get("status_code") != 200:
        return False
    token_data = (token_result.get("body") or {}).get("resources")
    if not isinstance(token_data, dict):
        return False
    token = token_data.get("token")
    if token:
        result["ingest_token"] = token
    ingest_url = token_data.get("ingest_url") or token_data.get("url")
    if ingest_url and not result["data_connection"].get("ingest_url"):
        result["data_connection"]["ingest_url"] = ingest_url
    return bool(token)


def _attempt_token(uber, result, connection_id):
    """Make a single token request via the raw command interface.

    Returns one of:
      - "found"    : the token was captured into result
      - "retry"    : not ready yet (202); poll again
      - "terminal" : a definitive non-200/202 (e.g. a PULL connection with no token)

    IMPORTANT: this uses the uber-class ``command`` rather than the typed
    ``NGSIEM.get_ingest_token``. In FalconPy 1.6.1 the typed method assumes
    ``resources`` is a list and does ``resources[0]``, but this endpoint returns a
    dict - so the typed call raises ``KeyError(0)`` on every request, including the
    one that mints the token. Because the token is minted exactly once (subsequent
    calls return 400 "already generated"), that crash permanently loses the secret.
    The raw command returns the unparsed body, so we read the dict directly.
    """
    token_result = uber.command(INGEST_TOKEN_OPERATION, ids=connection_id)
    if _extract_token(token_result, result):
        return "found"
    if token_result.get("status_code") == 202:
        return "retry"
    return "terminal"


def fetch_ingest_token(module, result, connection_id):
    """Mint/fetch the ingest token for a freshly created connection.

    Only meaningful for PUSH connections. The token is minted on the first
    successful (200) request; immediately after create the connection is still
    provisioning and the endpoint returns 202 ("ConnectionNotReady"). When
    I(wait_for_ingest_token) is set the module polls until the token is available
    or I(wait_timeout) is reached. For non-PUSH connections the endpoint returns a
    terminal non-200 and we simply skip it.

    Token retrieval happens *after* the connection is already created, so nothing
    here fails the task (that would orphan the connection) - a missing token is a
    warning, never an error. The uber-class is authenticated with the same
    credentials as the main service.
    """
    try:
        uber = authenticate(module, APIHarnessV2)

        outcome = _attempt_token(uber, result, connection_id)
        if outcome in ("found", "terminal"):
            return

        # Not ready yet.
        if not module.params.get("wait_for_ingest_token"):
            module.warn(
                "Ingest token is not ready yet (connection still provisioning). "
                "Set wait_for_ingest_token=true to poll for it. The token can only "
                "be retrieved once and is not available on later runs."
            )
            return

        timeout = module.params.get("wait_timeout")
        interval = 5
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(interval)
            outcome = _attempt_token(uber, result, connection_id)
            if outcome in ("found", "terminal"):
                return

        module.warn(
            f"Timed out after {timeout}s waiting for the ingest token to become "
            "available. The connection was created, but the token could not be "
            "retrieved. It can only be retrieved once and is not available on later runs."
        )
    except Exception as e:  # pragma: no cover - never fail the task over the token
        module.warn(
            f"The connection was created but retrieving the ingest token failed: {e}. "
            "The token can only be retrieved once and is not available on later runs."
        )


def filter_readable(connection):
    """Return only the API-returned fields for a connection."""
    return {k: connection[k] for k in READABLE_FIELDS if k in connection}


def handle_present(falcon, module, result):
    """Handle state=present (create or update)."""
    connection_id = module.params.get("connection_id")
    name = module.params.get("name")

    current = None
    if connection_id:
        current = get_existing(falcon, connection_id)
        if not current:
            module.fail_json(
                msg=f"Data connection with ID '{connection_id}' not found"
            )
    elif name:
        current = find_connection_by_name(falcon, name)

    if current:
        cid = current["id"]
        if connection_needs_update(current, module):
            body = build_body(module)
            # NOTE: the API reads the connection ID from the 'parameters' dict.
            # Passing ids= is silently ignored and returns a 400. See the
            # feasibility investigation for details.
            update_result = falcon.update_data_connection(
                parameters={"ids": cid}, body=body
            )
            if update_result["status_code"] not in (200, 201):
                handle_return_errors(module, result, update_result)
            result["changed"] = True
            updated = get_existing(falcon, cid)
            result["data_connection"] = filter_readable(updated or current)
        else:
            result["data_connection"] = filter_readable(current)

        apply_enabled(falcon, module, result, cid)
    else:
        # Creating a new connection requires connector_id and parser.
        for required in ("connector_id", "parser"):
            if not module.params.get(required):
                module.fail_json(
                    msg=f"Parameter '{required}' is required when creating a data connection"
                )

        body = build_body(module)
        create_result = falcon.create_data_connection(body=body)
        if create_result["status_code"] not in (200, 201):
            handle_return_errors(module, result, create_result)

        resources = create_result["body"].get("resources") or []
        if resources:
            new_id = resources[0]["id"]
            result["changed"] = True

            created = get_existing(falcon, new_id)
            result["data_connection"] = filter_readable(created) if created else {"id": new_id}

            # PUSH connections mint an ingest token on first ready fetch. For
            # non-PUSH connections this is a no-op.
            fetch_ingest_token(module, result, new_id)


def handle_absent(falcon, module, result):
    """Handle state=absent (delete)."""
    connection_id = module.params.get("connection_id")
    name = module.params.get("name")

    current = None
    if connection_id:
        current = get_existing(falcon, connection_id)
    elif name:
        current = find_connection_by_name(falcon, name)

    if current:
        delete_result = falcon.delete_data_connection(ids=current["id"])
        if delete_result["status_code"] not in (200, 201):
            handle_return_errors(module, result, delete_result)
        result["changed"] = True


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
    )

    if module.check_mode:
        module.exit_json(**result)

    falcon = authenticate(module, NGSIEM)

    try:
        if module.params["state"] == "present":
            handle_present(falcon, module, result)
        else:
            handle_absent(falcon, module, result)
    except Exception as e:
        module.fail_json(
            msg=f"An error occurred while managing the data connection: {str(e)}",
            **result,
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
