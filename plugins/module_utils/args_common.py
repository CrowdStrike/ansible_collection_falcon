# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

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
    "member_cid": {
        "type": "str",
        "required": False,
    },
    "access_token": {"type": "str", "required": False, "no_log": True},
}

ENV_CONFIG_SPEC = {
    "base_url": {
        "type": "str",
        "required": False,
        "choices": [
            "us-1",
            "us-2",
            "us-gov-1",
            "eu-1",
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.laggar.gcw.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        ],
    },
    "user_agent": {
        "type": "str",
        "required": False,
    },
    "ext_headers": {
        "type": "dict",
        "required": False,
    },
}


def falconpy_arg_spec():
    """Returns the FalconPy argument specification dictionary."""
    arg_spec = AUTH_ARG_SPEC.copy()
    arg_spec.update(ENV_CONFIG_SPEC)
    return arg_spec


def auth_required_by():
    """Returns the dict of mappings for access_token and base_url."""
    return {
        "access_token": ["base_url"],
    }
