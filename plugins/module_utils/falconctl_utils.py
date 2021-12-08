# -*- coding: utf-8 -*-

# Ansible module utility used for returning Falcon Sensor GET options.
# Copyright: (c) 2021, CrowdStrike Inc.

# Unlicense (see LICENSE or https://www.unlicense.org)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re
from subprocess import check_output, STDOUT, CalledProcessError

# Let's use the more robust run_command from AnsibleModule
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
    'provisioning_token'
]

# Private use only. This is to ensure that the command is checked
# prior to execution, and w/o the overhead of passing in the executable
# along with options.
# Fake instantiation to make use of AnsibleModule funcs()
_cs_path = "/opt/CrowdStrike"
_FALCONCTL = get_bin_path(
    'falconctl', required=True, opt_dirs=[_cs_path]
)


def __get(opt):
    if opt not in FALCONCTL_GET_OPTIONS:
        raise Exception("Invalid falconctl get option: %s" % opt)

    cmd = [_FALCONCTL, "-g"]
    # make sure opt is translated prior to execution
    opt = opt.replace("_", "-")
    cmd.append("--%s" % opt)
    try:
        stdout = check_output(cmd, universal_newlines=True, stderr=STDOUT)
    except CalledProcessError:
        stdout = ""

    return format_stdout(stdout)


def __get_many(opts):
    return {opt: __get(opt) for opt in opts}


def format_stdout(stdout):
    # Format stdout
    if stdout == "" or "not set" in stdout:
        return None
    else:
        # Expect stdout in <option>=<value>
        return re.sub(r"[\"\s\\n\.]", "", stdout).split("=")[1]


def get_options(opts):
    requested = opts if opts else FALCONCTL_GET_OPTIONS
    return __get_many(requested)
