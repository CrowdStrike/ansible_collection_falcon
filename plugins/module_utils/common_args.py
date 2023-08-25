# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import env_fallback

__metaclass__ = type


AUTH_ARG_SPEC = dict(
    client_id=dict(
        fallback=(env_fallback, ["FALCON_CLIENT_ID"]),
        type="str",
        aliases=["falcon_client_id"],
        required=False,
        no_log=True,
    ),
    client_secret=dict(
        fallback=(env_fallback, ["FALCON_CLIENT_SECRET"]),
        type="str",
        aliases=["falcon_client_secret"],
        required=False,
        no_log=True,
    ),
    member_cid=dict(
        fallback=(env_fallback, ["FALCON_MEMBER_CID"]),
        type="str",
        required=False,
    ),
    auth=dict(
        type="dict",
        required=False,
        options=dict(
            access_token=dict(
                type="str",
                no_log=True,
            ),
            cloud=dict(
                type="str",
            ),
        ),
    ),
)

ENV_CONFIG_SPEC = dict(
    cloud=dict(
        fallback=(env_fallback, ["FALCON_CLOUD"]),
        type="str",
        choices=["us-1", "us-2", "us-gov-1", "eu-1"],
        default="us-1",
        required=False,
    ),
    user_agent=dict(
        fallback=(env_fallback, ["FALCON_USER_AGENT"]),
        type="str",
        required=False,
    ),
    ext_headers=dict(
        type="dict",
        required=False,
    ),
)


def falconpy_arg_spec():
    """Returns the FalconPy argument specification dictionary."""
    arg_spec = AUTH_ARG_SPEC.copy()
    arg_spec.update(ENV_CONFIG_SPEC)
    return arg_spec
