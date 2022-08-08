#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to configure CrowdStrike Falcon Sensor on Linux systems.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: falconctl

author:
  - Gabriel Alford (@redhatrises)
  - Carlos Matos (@carlosmmatos)

short_description: Configure CrowdStrike Falcon Sensor

version_added: "3.2.0"

description:
  - Configures CrowdStrike Falcon Sensor on Linux systems

options:
  state:
    description:
      - Ensures that requested parameters are removed (absent) or added (present) to the Falcon sensor.
    type: str
    required: yes
    choices: [ absent, present ]
  cid:
    description:
      - CrowdStrike Falcon Customer ID (CID).
    type: str
  provisioning_token:
    description:
      - Installation tokens prevent unauthorized hosts from being accidentally or maliciously added to your customer ID (CID).
      - Optional security measure for your CID.
      - This paramter requires supplying a C(cid).
    type: str
  aid:
    description:
      - Whether or not you would like to delete the associated Agent ID.
      - Useful when preparing a host as a master image for cloning or virtualization.
      - This applies only to C(state=absent).
    type: bool
  apd:
    description:
      - Whether to enable or disable the Falcon sensor to use a proxy.
      - To enable the proxy, set to C(false|no).
    type: str
    choices: [ 'True', 'true', 'False', 'false', '""' ]
  aph:
    description:
      - Specifies the application proxy host to use for Falcon sensor proxy configuration.
    type: str
  app:
    description:
      - Specifies the application proxy port to use for Falcon sensor proxy configuration.
    type: str
  trace:
    description:
      - Configure the appropriate trace level.
    type: str
    choices: [ none, err, warn, info, debug ]
  feature:
    description:
      - Configure the Falcon sensor feature flags.
    type: list
    elements: str
    choices: [ none, enableLog, disableLogBuffer ]
  message_log:
    description:
      - Whether or not you would like to log messages to disk.
    type: str
    choices: [ 'True', 'true', 'False', 'false' ]
  billing:
    description:
      - Specify the (Pay-As-You-Go) billing model for Cloud Workloads.
      - Falcon for Cloud Workloads (Pay-As-You-Go) is a billing model for your hosts that run in
        Amazon Web Services (AWS), Google Cloud Platform (GCP), and Microsoft Azure.
      - For ephemeral workloads in these cloud environments, you pay only for the hours that hosts
        are active each month C(metered), rather than a full annual contract price per sensor C(default).
    type: str
    choices: [ metered, default, '""' ]
  tags:
    description:
      - Sensor grouping tags are optional, user-defined identifiers you can use to group and filter hosts.
      - To assign multiple tags, separate tags with commas.
      - I(The combined length of all tags for a host, including comma separators, cannot exceed 256 characters).
    type: str
'''

EXAMPLES = r'''
- name: Set CrowdStrike Falcon CID
  crowdstrike.falcon.falconctl:
    state: present
    cid: 1234567890ABCDEF1234567890ABCDEF-12

- name: Set CrowdStrike Falcon CID with Provisioning Token
  crowdstrike.falcon.falconctl:
    state: present
    cid: 1234567890ABCDEF1234567890ABCDEF-12
    provisioning_token: 12345678

- name: Delete CrowdStrike Falcon CID
  crowdstrike.falcon.falconctl:
    state: absent
    cid: ""

- name: Delete Agent ID to Prep Master Image
  crowdstrike.falcon.falconctl:
    state: absent
    aid: yes

- name: Configure Falcon Sensor Proxy
  crowdstrike.falcon.falconctl:
    state: present
    apd: no
    aph: http://example.com
    app: 8080
'''

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconctl_utils import FALCONCTL_GET_OPTIONS, get_options


VALID_PARAMS = {
    "s": [
        "cid",
        "apd",
        "aph",
        "app",
        "trace",
        "feature",
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
    """Falonctl Class for running falconctl -s or -d"""

    def __init__(self, module):
        self.module = module
        self.params = self.module.params

        self.cs_path = "/opt/CrowdStrike"
        self.falconctl = self.module.get_bin_path(
            "falconctl", required=True, opt_dirs=[self.cs_path])
        self.states = {"present": "s", "absent": "d"}
        self.valid_params = VALID_PARAMS
        self.state = self.params["state"]

        if self.state == "present":
            self.validate_params(self.params)

    @classmethod
    def __list_to_string(cls, value):
        """Converts paramaters passed as lists to strings"""
        if isinstance(value, list):
            # Make a copy and return it
            new_value = value[:]
            return ','.join(new_value)
        return value

    def __run_command(self, cmd):
        output = self.module.run_command(
            cmd, use_unsafe_shell=False)

        # Add some error checking/reporting
        if "ERROR" in output[2] or "not a valid" in output[2]:
            self.module.fail_json(
                msg="ERROR executing %s: OUTPUT = %s" % (cmd, output[2])
            )

    @classmethod
    def __validate_regex(cls, string, regex, flags=re.IGNORECASE):
        """Validate whether option matches specified format"""
        return re.match(
            regex, string, flags=flags)

    def add_args(self, state):
        """Add correct falconctl args for valid states"""
        fstate = self.states[state]
        args = [self.falconctl, "-%s" % fstate, "-f"]

        for k in self.params:
            if self.params[k] or self.params[k] == "":
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
        """
        Returns a sanitized representation of the Falcon Sensor option.

        There are edge cases dealing with some of the available GET options
        that need to be addressed prior to utilizing stdout.
        """
        # Deal with CID
        if key == "cid":
            # Get the 32 chars in lowercase
            return value.lower()[:32]
        # Deal with message_log
        if key == "message_log":
            return value.lower()
        # Deal with apd
        if key == "apd":
            return value.upper()
        # Deal with list evaluations
        if isinstance(value, list):
            if key == "feature":
                if 'none' in value and len(value) > 1:
                    # remove none from list by making copy, to keep orig intact
                    new_list = value[:]
                    new_list.remove('none')
                    return self.__list_to_string(new_list)
            return self.__list_to_string(value)

        # return value
        return value

    def check_mode(self, before):
        """Ansible check_mode with falconctl return values with pretty formatting"""
        values = {}
        # Use before to validate keys
        if self.state == "present":
            values.update({k: self.sanitize_opt(
                k, self.params[k]) for k in before})
        else:
            values.update({k: None for k in before})

        return values

    def execute(self):
        """Run the falconctl commmand"""
        cmd = self.add_args(self.params["state"])
        if not self.module.check_mode:
            self.__run_command(cmd)

    def get_values(self):
        """Return falconctl -g options for diff mode"""
        values = []

        for k in self.params:
            if self.params[k]:
                if k in FALCONCTL_GET_OPTIONS:
                    values.append(k)

        # get current values
        return get_options(values)

    def validate_params(self, params):
        """Check parameters that are conditionally required"""

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

        if params["billing"]:
            valid_choices = ["default", "metered"]
            if params["billing"] not in valid_choices:
                self.module.fail_json(
                    msg="Value of billing must be one of: default|metered, got %s" % (params["billing"]))

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


def main():  # pylint: disable=missing-function-docstring
    module_args = dict(
        state=dict(required=True, choices=[
                   "absent", "present"], type="str"),
        cid=dict(required=False, type="str"),
        provisioning_token=dict(required=False, no_log=True, type="str"),
        aid=dict(required=False, type="bool"),
        apd=dict(required=False, choices=["True", "true", "False", "false", '""'], type="str"),
        aph=dict(required=False, type="str"),
        app=dict(required=False, type="str"),
        trace=dict(required=False, choices=[
                   "none", "err", "warn", "info", "debug"], type="str"),
        feature=dict(required=False, choices=[
            "none", "enableLog", "disableLogBuffer"], type="list", elements="str"),
        message_log=dict(required=False, choices=["True", "true", "False", "false"], type="str"),
        billing=dict(required=False, choices=["metered", "default", '""'], type="str"),
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
