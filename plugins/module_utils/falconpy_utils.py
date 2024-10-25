# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from ansible_collections.crowdstrike.falcon.plugins.module_utils.version import (
    __version__,
)

FALCONPY_IMPORT_ERROR = None

try:
    from falconpy._version import _VERSION
except (ImportError, ModuleNotFoundError) as e:
    FALCONPY_IMPORT_ERROR = e

__metaclass__ = type


def check_falconpy_version(module):
    """Ensure FalconPy version is compatible."""
    minumum_version = "1.3.0"

    if FALCONPY_IMPORT_ERROR:
        module.fail_json(
            msg=f"Unable to import FalconPy: {FALCONPY_IMPORT_ERROR}. See module documentation for help."
        )

    if _VERSION < minumum_version:
        module.fail_json(
            msg=f"Unsupported FalconPy version: {_VERSION}. Upgrade to {minumum_version} or higher."
        )


def get_falconpy_credentials(module):
    """Check module args for credentials, if not then check for env variables."""
    cred_vars = [
        "client_id",
        "client_secret",
        "member_cid",
    ]

    creds = {}

    for var in cred_vars:
        value = module.params.get(var)
        if not value and var != "member_cid":
            module.fail_json(
                msg=f"Missing required parameter: {var}. See module documentation for help."
            )
        if value:
            creds[var] = value

    config = environ_configuration(module)

    if config:
        creds.update(config)

    return creds


def environ_configuration(module):
    """Check module args for environment configurations used with FalconPy."""
    environ_config = [
        "cloud",
        "ext_headers",
    ]

    default_user_agent = f"crowdstrike-ansible/{__version__}"
    config = {}

    # Handle the user_agent parameter specially
    user_agent = module.params.get("user_agent")
    if user_agent:
        config["user_agent"] = f"{user_agent} {default_user_agent}"
    else:
        config["user_agent"] = default_user_agent

    # Handle the other environment variables normally
    for var in environ_config:
        value = module.params.get(var)
        if value:
            if var == "cloud":
                config["base_url"] = value
            else:
                config[var] = value

    return config


def authenticate(module, service_class):
    """Authenticate to the CrowdStrike Falcon API."""
    if module.params.get("auth"):
        service = service_class(
            access_token=module.params["auth"]["access_token"],
            base_url=module.params["auth"]["cloud"],
        )
    else:
        service = service_class(**get_falconpy_credentials(module))

    return service


def handle_return_errors(module, result, query_result):
    """Handle errors returned from the Falcon API."""
    if "errors" in query_result["body"]:
        result["errors"] = query_result["body"]["errors"]

        if len(result["errors"]) > 0:
            msg = result["errors"][0]["message"]
            if not msg:
                msg = "An unknown error occurred."
            module.fail_json(msg=msg, **result)


def get_paginated_results_info(module, args, limit, method, list_name):
    """Return paginated results from the Falcon API for info modules."""
    result = dict(
        changed=False,
        **{list_name: []},
    )

    max_limit = limit
    offset = None
    running = True
    while running:
        query_result = method(**args, offset=offset, limit=max_limit)
        if query_result["status_code"] != 200:
            handle_return_errors(module, result, query_result)

        if query_result["body"]["resources"]:
            result[list_name].extend(query_result["body"]["resources"])
        else:
            return result

        # Check if we need to continue
        offset = query_result["body"]["meta"]["pagination"]["offset"]
        if query_result["body"]["meta"]["pagination"]["total"] <= len(result[list_name]):
            running = False

    return result


def get_cloud_from_url(module, base_url):
    """Return the cloud name from a base URL."""
    mapping = {
        "https://api.crowdstrike.com": "us-1",
        "https://api.us-2.crowdstrike.com": "us-2",
        "https://api.eu-1.crowdstrike.com": "eu-1",
        "https://api.laggar.gcw.crowdstrike.com": "us-gov-1",
    }

    # fail if the base_url is not in the mapping
    cloud = mapping[base_url]

    if not cloud:
        module.fail_json(
            msg=f"Unknown cloud: {base_url}. See module documentation for help."
        )

    return cloud
