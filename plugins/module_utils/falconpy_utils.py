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
    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_secret')

    missing_params = []

    if not client_id:
        client_id = os.environ.get('FALCON_CLIENT_ID', None)
        if not client_id:
            missing_params.append('client_id')

    if not client_secret:
        client_secret = os.environ.get('FALCON_CLIENT_SECRET', None)
        if not client_secret:
            missing_params.append('client_secret')

    if missing_params:
        module.fail_json(msg="Missing required parameters: {0}. See module documentation for help.".format(missing_params))

    # Return the credentials:
    return dict(client_id=client_id, client_secret=client_secret)
