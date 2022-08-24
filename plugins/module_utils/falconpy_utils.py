# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
import os
__metaclass__ = type


def get_falconpy_credentials(module):
    """
    Check module args for credentials, if not then check for env variables.

    :param module: Ansible module object
    :return: Dictionary with falcon connection info
    """

    # Ensure we have credentials to work with:
    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_secret')

    if not client_id and not client_secret:
        module.fail_json(msg="CrowdStrike Falcon API credentials are required. See module documentation for help.")

    if not client_id:
        if 'FALCON_CLIENT_ID' in os.environ:
            client_id = os.environ['FALCON_CLIENT_ID']
        else:
            module.fail_json(msg='client_id is required. Check your parameters or set FALCON_CLIENT_ID')

    if not client_secret:
        if 'FALCON_CLIENT_SECRET' in os.environ:
            client_secret = os.environ['FALCON_CLIENT_SECRET']
        else:
            module.fail_json(msg='client_secret is required. Check your parameters or set FALCON_CLIENT_SECRET')

    # Return the credentials:
    return dict(falcon_client_id=client_id, falcon_client_secret=client_secret)
