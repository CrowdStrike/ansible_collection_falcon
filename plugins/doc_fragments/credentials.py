
# -*- coding: utf-8 -*-

# Copyright: (c) 2017,  Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    # Plugin options for CrowdStrike Falcon API credentials
    DOCUMENTATION = r'''
options:
  client_id:
    description: The CrowdStrike API client ID to use.
    type: str
    env:
      - name: FALCON_CLIENT_ID
  client_secret:
    description: The CrowdStrike API secret that corresponds to the client ID.
    type: str
    env:
      - name: FALCON_CLIENT_SECRET
'''
