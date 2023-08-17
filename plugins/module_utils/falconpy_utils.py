# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import os

from ansible_collections.crowdstrike.falcon.plugins.module_utils.version import (
    __version__,
)

__metaclass__ = type


def get_falconpy_credentials(module):
    """Check module args for credentials, if not then check for env variables."""
    cred_env_map = {
        "client_id": "FALCON_CLIENT_ID",
        "client_secret": "FALCON_CLIENT_SECRET",
        "member_cid": "FALCON_MEMBER_CID",
    }

    creds = {}

    for param, env_var in cred_env_map.items():
        value = module.params.get(param)
        if not value:
            value = os.environ.get(env_var)
            # If we still don't have a value, fail, except for member_cid (which is optional)
            if not value and param != "member_cid":
                module.fail_json(
                    msg=f"Missing required parameter: {param} or environment variable: {env_var}. See module documentation for help."
                )
        # If we have a value, add it to the creds dict
        if value:
            creds[param] = value

    config = environ_configuration(module)

    if config:
        creds.update(config)

    return creds


def environ_configuration(module):
    """Check module args for common envrionment configurations used with FalconPy."""
    environ_config_map = {
        "base_url": "FALCON_BASE_URL",
        "user_agent": "FALCON_USER_AGENT",
        "ext_headers": "FALCON_EXT_HEADERS",
    }

    default_user_agent = f"crowdstrike-ansible/{__version__}"
    config = {}

    for param, env_var in environ_config_map.items():
        value = module.params.get(param)
        if not value:
            value = os.environ.get(env_var)
        # If we have a value, add it to the config dict
        if value:
            if param == "user_agent":
                value = f"{value} {default_user_agent}"
            config[param] = value

    return config


def authenticate(module, service_class):
    """Authenticate to the CrowdStrike Falcon API."""
    if module.params.get("access_token"):
        service = service_class(
            access_token=module.params["access_token"],
            base_url=module.params["base_url"],
        )
    else:
        service = service_class(**get_falconpy_credentials(module))

    return service


def handle_return_errors(module, result, query_result):
    """Handle errors returned from the Falcon API."""
    result["errors"] = query_result["body"]["errors"]

    if len(result["errors"]) > 0:
        msg = result["errors"][0]["message"]
    else:
        msg = "An unknown error occurred."
    module.fail_json(msg=msg, **result)
