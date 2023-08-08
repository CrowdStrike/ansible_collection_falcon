# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
import os
import traceback
try:
    from falconpy import OAuth2
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_FALCONPY = True

__metaclass__ = type


def authenticate(module):
    """
    Authenticate to the CrowdStrike Falcon API.

    :param module: Ansible module object
    :return: Falcon OAuth2 object
    """
    falcon_credentials = get_falconpy_credentials(module)
    falcon_config = environ_configuration(module)

    if falcon_config:
        falcon_credentials.update(falcon_config)

    # module.fail_json(msg=falcon_credentials)

    falcon = OAuth2(**falcon_credentials)

    return falcon

    # # Debug falcon object
    # module.fail_json(msg=falcon.token())

    # try:
    #     token = falcon.token()['body']['access_token']
    #     # We need to set the right base_url for the API
    #     # based on the "X-Cs-Region" header returned by the auth call

    # except KeyError:
    #     error_message = falcon.token()['body']['errors']
    #     module.fail_json(msg=f"Failed to authenticate to CrowdStrike Falcon API: {error_message}")

    # return token


def get_falconpy_credentials(module):
    """
    Check module args for credentials, if not then check for env variables.

    :param module: Ansible module object
    :return: Dictionary with falcon connection info
    """
    cred_env_map = {
        'client_id': 'FALCON_CLIENT_ID',
        'client_secret': 'FALCON_CLIENT_SECRET',
        'member_cid': 'FALCON_MEMBER_CID',
    }

    creds = {}

    for param, env_var in cred_env_map.items():
        value = module.params.get(param)
        if not value:
            value = os.environ.get(env_var)
            # If we still don't have a value, fail, except for member_cid (which is optional)
            if not value and param != 'member_cid':
                module.fail_json(msg=f"Missing required parameter: {param} or environment variable: {env_var}. See module documentation for help.")
        # If we have a value, add it to the creds dict
        if value:
            creds[param] = value

    return creds

def environ_configuration(module):
    """
    Check module args for common envrionment configurations used with FalconPy.

    :param module: Ansible module object
    :return: Dictionary with falcon connection info
    """
    environ_config_map = {
        'base_url': 'FALCON_BASE_URL',
        'proxy': 'FALCON_PROXY',
        'ssl_verify': 'FALCON_SSL_VERIFY',
        'timeout': 'FALCON_TIMEOUT',
        'user_agent': 'FALCON_USER_AGENT',
        'renew_window': 'FALCON_RENEW_WINDOW',
        'ext_headers': 'FALCON_EXT_HEADERS'
    }

    config = {}

    for param, env_var in environ_config_map.items():
        value = module.params.get(param)
        if not value:
            value = os.environ.get(env_var)
        # If we have a value, add it to the config dict
        if value:
            config[param] = value

    return config
