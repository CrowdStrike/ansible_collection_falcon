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


AUTH_ARG_SPEC = {
    "client_id": {
        "type": "str",
        "aliases": ["falcon_client_id"],
        "required": False,
        "no_log": True,
    },
    "client_secret": {
        "type": "str",
        "aliases": ["falcon_client_secret"],
        "required": False,
        "no_log": True,
    },
    "member_cid": {"type": "str", "required": False, "no_log": False},
    "access_token": {"type": "str", "required": False, "no_log": True},
}

ENV_CONFIG_SPEC = {
    "base_url": {"type": "str", "default": "US1", "required": False, "no_log": False},
    "proxy": {"type": "dict", "required": False, "no_log": False},
    "pythonic": {"type": "bool", "required": False, "no_log": False},
    "renew_window": {"type": "int", "required": False, "no_log": False},
    "ssl_verify": {"type": "bool", "required": False, "no_log": False},
    "timeout": {"type": "float", "required": False, "no_log": False},
    "user_agent": {
        "type": "str",
        "default": f"crowdstrike-ansible/{__version__}",
        "required": False,
        "no_log": False,
    },
    "ext_headers": {"type": "dict", "default": {}, "required": False, "no_log": False},
    "validate_payloads": {"type": "bool", "required": False, "no_log": False},
}


def falconpy_arg_spec():
    """Returns the FalconPy argument specification dictionary."""
    arg_spec = AUTH_ARG_SPEC.copy()
    arg_spec.update(ENV_CONFIG_SPEC)
    return arg_spec
