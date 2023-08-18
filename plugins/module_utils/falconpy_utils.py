# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from ansible_collections.crowdstrike.falcon.plugins.module_utils.version import (
    __version__,
)

__metaclass__ = type


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
            base_url=module.params["auth"]["base_url"],
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
