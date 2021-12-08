#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to configure CrowdStrike Falcon Sensor on Linux systems.
# Copyright: (c) 2021, CrowdStrike Inc.

# Unlicense (see LICENSE or https://www.unlicense.org)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: falconctl
author:
  - Gabriel Alford <redhatrises@gmail.com>
  - Carlos Matos <matosc15@gmail.com>
short_description: Configure CrowdStrike Falcon Sensor
description:
  - Configures CrowdStrike Falcon Sensor on Linux systems
options:
    cid:
      description:
        - CrowdStrike Falcon Customer ID (CID).
      type: str
    state:
      description:
        - If falconctl will set, delete, or only return configuration settings.
      type: str
      default: present
      choices: [ absent, present ]
    force:
      description:
        - Force falconctl to configure settings.
      type: bool
      default: "no"
    provisioning_token:
      description:
        - Installation tokens prevent unauthorized hosts from being accidentally or maliciously added to your customer ID (CID).
        - Optional security measure for your CID.
      type: str
extends_documentation_fragment:
    - action_common_attributes
attributes:
    check_mode:
        support: full
    diff_mode:
        support: full
    platform:
        support: full
        platforms: posix
"""

EXAMPLES = """
- name: Set CrowdStrike Falcon CID
  crowdstrike.falcon.falconctl:
    state: present
    cid: 1234567890ABCDEF1234567890ABCDEF-12

- name: Delete CrowdStrike Falcon CID
  crowdstrike.falcon.falconctl:
    state: absent
    cid: 1234567890ABCDEF1234567890ABCDEF-12
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconctl_utils import FALCONCTL_GET_OPTIONS, get_options, format_stdout


VALID_PARAMS = {
    "s": [
        "cid",
        "apd",
        "aph",
        "app",
        "trace",
        "feature",
        "metadata_query",
        "message_log",
        "billing",
        "tags",
        "provisioning_token",
    ],
    "d": [
        "cid",
        "aid",
        "apd",
        "aph",
        "app",
        "trace",
        "billing",
        "tags",
        "provisioning_token",
    ],
}

class FalconCtl(object):

    def __init__(self, module):
        self.module = module
        self.params = self.module.params

        self.cs_path = "/opt/CrowdStrike"
        self.falconctl = self.module.get_bin_path(
            "falconctl", required=True, opt_dirs=[self.cs_path])
        self.states = {"present": "s", "absent": "d"}
        self.valid_params = VALID_PARAMS

        self.validate_params(self.params)
        self.state = self.params["state"]


    def __list_to_string(self, value):
        """Converts paramaters passed as lists to strings"""
        if type(value) is list:
            # Make a copy and return it
            new_value = value.copy()
            return ','.join(new_value)
        return value


    def __run_command(self, cmd):
        rc, stdout, stderr = self.module.run_command(
            cmd, use_unsafe_shell=False)

        # return formatted stdout
        return format_stdout(stdout)


    def __validate_regex(self, string, regex, flags=re.IGNORECASE):
        """Validate whether option matches specified format"""
        return re.match(
            regex, string, flags=flags)


    def add_args(self, state):
        fstate = self.states[state]
        args = [self.falconctl, "-%s" % fstate, "-f"]

        for k in self.params:
            if self.params[k]:
                if k in self.valid_params[fstate]:
                    key = k.replace("_", "-")
                    if state == "present":
                        args.append("--%s=%s" %
                                    (key, self.__list_to_string(self.params[k])))
                    else:
                        args.append("--%s" % (key))
                else:
                    if k != "state":
                        self.module.fail_json(
                            msg=("Cannot use '%s' with state '%s'. Valid options for "
                                 "state '%s' are: %s." % (k, state, state, ', '.join(VALID_PARAMS[fstate])))
                        )
        return args


    def sanitize_opt(self, key, value):
        """Returns a sanitized representation of the Falcon Sensor option.

        There are edge cases dealing with some of the available GET options
        that need to be addressed prior to utilizing stdout.
        """
        # Deal with CID
        if key == "cid":
            # Get the 32 chars in lowercase
            return value.lower()[:32]
        # Deal with list valueions
        if type(value) is list:
            if key == "feature":
                if 'none' in value and len(value) > 1:
                    # remove none from list by making copy, to keep orig intact
                    new_list = value.copy()
                    new_list.remove('none')
                    return self.__list_to_string(new_list)
            return self.__list_to_string(value)

        return value.lower()


    def check_mode(self, before):

        values = {}
        # Use before to validate keys
        if self.state == "present":
            values.update({k: self.sanitize_opt(k, self.params[k]) for k in before})
        else:
            values.update({k: None for k in before})

        return values

    def execute(self):
        cmd = self.add_args(self.params["state"])
        if not self.module.check_mode:
            self.__run_command(cmd)

    def get_values(self):
        values = []

        for k in self.params:
            if self.params[k]:
                if k in FALCONCTL_GET_OPTIONS:
                    values.append(k)

        # get current values
        return get_options(values)

    def validate_params(self, params):
        """Check parameters that are conditionally required"""
        if params["metadata_query"]:
            choices_str = ["enable", "disable"]
            choices_list = ["enableAWS", "enableAzure", "enableGCP",
                            "disableAWS", "disableAzure", "disableGCP"]
            mq = params["metadata_query"]
            if mq not in choices_str and \
                    not all(item in choices_list for item in mq.split(",")):
                self.module.fail_json(
                    msg="value of %s must be one of: enable, disable, got: %s" % ("metadata_query", mq))

        if params["provisioning_token"]:
            # Ensure cid is also passed
            if not params["cid"]:
                self.module.fail_json(
                    msg="provisioning_token requires cid!"
                )

            valid_token = self.__validate_regex(
                params["provisioning_token"], "^[0-9a-fA-F]{8}$")
            if not valid_token:
                self.module.fail_json(
                    msg="Invalid provisioning token: '%s'" % (params["provisioning_token"]))

        if params["cid"]:
            valid_cid = self.__validate_regex(
                params["cid"], "^[0-9a-fA-F]{32}-[0-9a-fA-F]{2}$")
            if not valid_cid:
                self.module.fail_json(
                    msg="Invalid CrowdStrike CID: '%s'" % (params["cid"]))

        if params["tags"]:
            valid_tags = self.__validate_regex(
                params["tags"], r"^[a-zA-Z0-9\/\-_\,]+$")
            if not valid_tags:
                self.module.fail_json(
                    msg="value of tags must be one of: all alphanumerics, '/', '-', '_', and ',', got %s" % (params["tags"]))


def main():
    module_args = dict(
        state=dict(default="present", choices=[
                   "absent", "present"], type="str"),
        cid=dict(required=False, no_log=False, type="str"),
        provisioning_token=dict(required=False, type="str"),
        aid=dict(required=False, type="bool"),
        apd=dict(required=False, type="bool"),
        aph=dict(required=False, type="str"),
        app=dict(required=False, type="int"),
        trace=dict(required=False, choices=[
                   "none", "err", "warn", "info", "debug"], type="str"),
        feature=dict(required=False, choices=[
            "none", "enableLog", "disableLogBuffer", "disableOsfm", "emulateUpdate"], type="list"),
        metadata_query=dict(required=False, type="str"),
        message_log=dict(required=False, type="bool"),
        billing=dict(required=False, choices=[
                     "default", "metered"], type="str"),
        tags=dict(required=False, type="str"),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Instantiate class
    falcon = FalconCtl(module)

    result = dict(
        changed=False
    )

    before = falcon.get_values()

    # Perform action set/delete
    falcon.execute()

    # After
    if not module.check_mode:
        after = falcon.get_values()
    else:
        # after = {"rc": 0, "stdout": module.params}
        after = falcon.check_mode(before)

    if before != after:
        result["changed"] = True
        result["diff"] = dict(
            before=before,
            after=after
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
