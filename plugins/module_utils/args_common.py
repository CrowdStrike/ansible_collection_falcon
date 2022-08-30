# -*- coding: utf-8 -*-

# Common helper functions for FalconPy modules.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


AUTH_ARG_SPEC = {
    "client_id": { "type": "str", "aliases": ["falcon_client_id"], "required": False, "no_log": False },
    "client_secret": { "type": "str", "aliases": ["falcon_client_secret"], "required": False, "no_log": False },
}
