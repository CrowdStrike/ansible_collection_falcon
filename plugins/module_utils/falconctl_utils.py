# -*- coding: utf-8 -*-

# Ansible module utility used for returning Falcon Sensor GET options.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re
import traceback
from subprocess import check_output, STDOUT, CalledProcessError  # nosec

from ansible.module_utils.common.process import get_bin_path

# Constants
FALCONCTL_GET_OPTIONS = [
    'cid',
    'aid',
    'apd',
    'aph',
    'app',
    'trace',
    'feature',
    'metadata_query',
    'message_log',
    'billing',
    'tags',
    # 'provisioning_token', # Taking it out since this does not seem to be a perm option
    'version',
    'rfm_state',
    'rfm_reason',
    'backend'
]

# Private use only. This is to ensure that the command is checked
# prior to execution, and w/o the overhead of passing in the executable
# along with options.
# Fake instantiation to make use of AnsibleModule funcs()
FALCONCTL_NOT_FOUND = False
FALCONCTL_VALUE_ERROR = None
_cs_path = "/opt/CrowdStrike"
try:
    _FALCONCTL = get_bin_path(
        'falconctl', required=True, opt_dirs=[_cs_path]
    )
except ValueError:
    FALCONCTL_NOT_FOUND = True
    FALCONCTL_VALUE_ERROR = traceback.format_exc()


def __get(opt):
    if opt not in FALCONCTL_GET_OPTIONS:
        raise Exception("Invalid falconctl get option: %s" % opt)
    if not FALCONCTL_NOT_FOUND:
        cmd = [_FALCONCTL, "-g"]
    else:
        raise Exception(FALCONCTL_VALUE_ERROR)
    # make sure opt is translated prior to execution
    opt = opt.replace("_", "-")
    cmd.append("--%s" % opt)
    try:
        stdout = check_output(cmd, universal_newlines=True, stderr=STDOUT, shell=False)
    except CalledProcessError:
        stdout = ""

    return format_stdout(stdout)


def __get_many(opts):
    return {opt: __get(opt) for opt in opts}


def format_stdout(stdout):
    """Formats output from falconctl"""
    # Format stdout
    if stdout == "" or "not set" in stdout:
        return None

    # Expect stdout in <option>=<value>
    if 'version' in stdout:
        output = re.sub(r"[\"\s\n]|\(.*\)", "", stdout).split("=")[1]
    elif 'rfm-reason' in stdout:
        output = re.sub(r"^rfm-reason=|[\"\s\n\.]|\(.*\)", "", stdout)
    elif 'aph' in stdout:
        output = re.sub(r"\.$\n", "", stdout).split("=")[1]
    else:
        output = re.sub(r"[\"\s\n\.]|\(.*\)", "", stdout).split("=")[1]
    return output if output else None


def get_options(opts):
    """Return falconctl -g valid options"""
    requested = opts if opts else FALCONCTL_GET_OPTIONS
    return __get_many(requested)
