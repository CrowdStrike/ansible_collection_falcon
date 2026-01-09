# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared FalconPy utilities for lookup and inventory plugins."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import traceback

from ansible.errors import AnsibleError

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy._version import _VERSION
    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    _VERSION = None
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

MINIMUM_FALCONPY_VERSION = "1.3.0"
VALID_CLOUDS = ["us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2"]


def check_falconpy(plugin_name):
    """Verify FalconPy is installed and meets minimum version requirements.

    Args:
        plugin_name: Name of the plugin for error messages (e.g., 'crowdstrike.falcon.host_ids')

    Raises:
        AnsibleError: If FalconPy is not installed or version is too old
    """
    if not HAS_FALCONPY:
        raise AnsibleError(
            f"The '{plugin_name}' lookup cannot be run because the 'crowdstrike-falconpy' "
            "library is not installed."
        )

    if _VERSION < MINIMUM_FALCONPY_VERSION:
        raise AnsibleError(
            f"Unsupported FalconPy version: {_VERSION}. "
            f"Upgrade to {MINIMUM_FALCONPY_VERSION} or higher."
        )


def get_falconpy_credentials(get_option_func):
    """Setup credentials for FalconPy from plugin options or environment variables.

    Args:
        get_option_func: A callable that retrieves plugin options (e.g., self.get_option)

    Returns:
        dict: Credential dictionary suitable for FalconPy service class initialization

    Raises:
        AnsibleError: If required credentials are missing or cloud region is invalid
    """
    cred_mapping = {
        "client_id": "FALCON_CLIENT_ID",
        "client_secret": "FALCON_CLIENT_SECRET",
        "member_cid": "FALCON_MEMBER_CID",
        "cloud": "FALCON_CLOUD",
    }

    creds = {}
    for key, env in cred_mapping.items():
        value = get_option_func(key) or os.getenv(env)
        if value:
            if key == "cloud":
                if value not in VALID_CLOUDS:
                    raise AnsibleError(
                        f"Invalid cloud region: '{value}'. Valid values are {', '.join(VALID_CLOUDS)}"
                    )
                creds["base_url"] = value
            else:
                creds[key] = value

    if "client_id" not in creds or "client_secret" not in creds:
        raise AnsibleError(
            "You must provide a client_id and client_secret to authenticate to the Falcon API."
        )

    return creds


def validate_authentication(falcon):
    """Validate that authentication to the Falcon API was successful.

    Args:
        falcon: A FalconPy service class instance

    Raises:
        AnsibleError: If authentication failed with details about the failure
    """
    if not falcon.auth_object.token_valid:
        raise AnsibleError(
            f"Unable to authenticate to the CrowdStrike Falcon API: "
            f"{falcon.auth_object.token_fail_reason}"
        )


def authenticate(service_class, get_option_func):
    """Authenticate to the CrowdStrike Falcon API and validate the connection.

    Args:
        service_class: The FalconPy service class to instantiate (e.g., Hosts, SensorUpdatePolicy)
        get_option_func: A callable that retrieves plugin options (e.g., self.get_option)

    Returns:
        An authenticated instance of the service class

    Raises:
        AnsibleError: If credentials are invalid or authentication fails
    """
    creds = get_falconpy_credentials(get_option_func)
    falcon = service_class(**creds)
    validate_authentication(falcon)
    return falcon
