#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: intel_rule_download

short_description: Download CrowdStrike Falcon Intel rule files

description:
  - Downloads CrowdStrike Falcon Intel rule files (YARA, Snort, etc.).
  - By default, downloads the latest rule file for the specified type.
  - Can also download a specific rule file when provided with a C(rule_id).

options:
  type:
    description:
      - The rule news report type.
      - Required when C(rule_id) is not provided.
      - Used to fetch the latest rule file of this type when C(rule_id) is not specified.
    type: str
    choices:
      - common-event-format
      - netwitness
      - snort-suricata-changelog
      - snort-suricata-master
      - snort-suricata-update
      - yara-changelog
      - yara-master
      - yara-update
      - cql-master
      - cql-changelog
      - cql-update
  rule_id:
    description:
      - The ID of a specific rule to download.
      - If provided, the type parameter is ignored.
    type: str
  format:
    description:
      - The format of the rule file to download.
    type: str
    choices:
      - zip
      - gzip
    default: zip
  dest:
    description:
      - The directory path to save the rule file.
      - If not specified, a temporary directory will be created using
        the system's default temporary directory.
    type: path
  name:
    description:
      - The filename to save the rule file as.
      - If not specified, it will use the name provided by the API.
    type: str

extends_documentation_fragment:
  - files
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - This module implements file locking to ensure safe concurrent downloads by preventing multiple
    instances from accessing the same file simultaneously.
  - When downloading the latest rule file without specifying a C(rule_id), the module will automatically
    query for the most recent rule of the specified type.

requirements:
  - Rules (Falcon Intelligence) [B(READ)] API scope

author:
  - CrowdStrike (@crowdstrike)
"""

EXAMPLES = r"""
- name: Download the latest YARA master rule file
  crowdstrike.falcon.intel_rule_download:
    type: "yara-master"
    dest: "/tmp/rules"

- name: Download a specific rule file by ID
  crowdstrike.falcon.intel_rule_download:
    rule_id: "1234567890"
    dest: "/tmp/rules"
    name: "custom_rule.zip"

- name: Download the latest Snort rule file in gzip format
  crowdstrike.falcon.intel_rule_download:
    type: "snort-suricata-master"
    format: "gzip"
    dest: "/tmp/rules"
"""

RETURN = r"""
path:
  description: The full path of the downloaded rule file.
  returned: success
  type: str
  sample: /tmp/rules/yara-master-20231015.zip
rule_id:
  description: The ID of the downloaded rule.
  returned: success
  type: str
  sample: "1234567890"
rule_name:
  description: The name of the downloaded rule.
  returned: success
  type: str
  sample: "CrowdStrike Intelligence Feed: YARA Master - 2023/10/15"
rule_type:
  description: The type of the downloaded rule.
  returned: success
  type: str
  sample: "yara-master"
"""

import errno
import fcntl
import traceback
import os
import time
import random
from tempfile import mkdtemp

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
    handle_return_errors,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Intel

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(
        type=dict(
            type='str',
            choices=[
                'common-event-format',
                'netwitness',
                'snort-suricata-changelog',
                'snort-suricata-master',
                'snort-suricata-update',
                'yara-changelog',
                'yara-master',
                'yara-update',
                'cql-master',
                'cql-changelog',
                'cql-update'
            ]
        ),
        rule_id=dict(type='str'),
        format=dict(
            type='str',
            choices=['zip', 'gzip'],
            default='zip'
        ),
        dest=dict(type='path'),
        name=dict(type='str'),
    )
    return args


def lock_file(file_path, exclusive=True, timeout=300, retry_interval=5):
    """Lock a file for reading or writing."""
    lock_file_path = file_path + ".lock"
    # Ignore the pylint warning here as a with block will close the file handle immediately
    # and we need to keep it open to maintain the lock
    lock_file_handle = open(lock_file_path, 'w', encoding='utf-8')  # pylint: disable=consider-using-with
    start_time = time.time()
    # Implement a delay to prevent thundering herd
    delay = random.random()  # nosec

    while True:
        try:
            if exclusive:
                fcntl.flock(lock_file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                fcntl.flock(lock_file_handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return lock_file_handle
        except IOError as e:
            if e.errno != errno.EAGAIN:
                raise
            if time.time() - start_time > timeout:
                return None
            time.sleep(delay + retry_interval)
            delay = 0


def unlock_file(locked_file):
    """Unlock a file and remove the lock file."""
    lock_path = locked_file.name  # Get the path of the lock file
    fcntl.flock(locked_file, fcntl.LOCK_UN)
    locked_file.close()

    # Remove the lock file
    try:
        os.unlink(lock_path)
    except (OSError, IOError):
        # Don't fail if we can't remove the lock file
        pass


def check_destination_path(module, dest):
    """Check if the destination path is valid."""
    if not os.path.isdir(dest):
        module.fail_json(msg=f"Destination path does not exist or is not a directory: {dest}")

    if not os.access(dest, os.W_OK):
        module.fail_json(msg=f"Destination path is not writable: {dest}")


def update_permissions(module, changed, path):
    """Update the permissions on the file if needed."""
    file_args = module.load_file_common_arguments(module.params, path=path)

    return module.set_fs_attributes_if_different(file_args, changed=changed)


def get_latest_rule_id(module, falcon, rule_type, result):
    """Get the latest rule ID for the specified type."""
    query_params = {
        'type': rule_type,
        'sort': 'created_date|desc',
        'limit': 1
    }

    query_result = falcon.query_rule_ids(**query_params)

    handle_return_errors(module, result, query_result)

    rule_ids = query_result.get('body', {}).get('resources', [])
    if not rule_ids:
        module.fail_json(msg=f"No rules found for type: {rule_type}")

    return rule_ids[0]


def get_rule_details(module, falcon, rule_id, result):
    """Get details about a specific rule."""
    query_result = falcon.get_rule_entities(ids=[rule_id])

    handle_return_errors(module, result, query_result)

    rules = query_result.get('body', {}).get('resources', [])
    if not rules:
        module.fail_json(msg=f"No rule found with ID: {rule_id}")

    return rules[0]


def download_rule_file(module, falcon, rule_id, compression_format):
    """Download a rule file."""
    if module.params.get('rule_id'):
        # Download specific rule file by ID
        download = falcon.get_rule_file(id=rule_id, format=compression_format)
    else:
        # Download latest rule file by type
        download = falcon.get_latest_rule_file(type=module.params.get('type'), format=compression_format)

    if isinstance(download, dict) and "status_code" in download:
        # Error occurred
        module.fail_json(
            msg=f"Failed to download rule file: {download.get('body', {}).get('errors', [{'message': 'Unknown error'}])[0].get('message')}"
        )

    return download


def handle_existing_file(module, result, path):
    """Handle the case where the file already exists."""
    # We can't reliably check the content without downloading again,
    # so we'll assume it needs to be updated if it exists
    msg = "File already exists but may have been updated."

    if update_permissions(module, result["changed"], path):
        msg += " Permissions were updated."
        result.update(changed=True)

    module.exit_json(
        msg=msg,
        path=path,
        **result,
    )


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        add_file_common_args=True,
        supports_check_mode=True,
        required_one_of=[['type', 'rule_id']],
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)

    rule_id = module.params.get("rule_id")
    rule_type = module.params.get("type")
    compression_format = module.params.get("format")
    dest = module.params.get("dest")
    name = module.params.get("name")
    tmp_dir = False

    if not dest:
        dest = mkdtemp()
        os.chmod(dest, 0o755)  # nosec
        tmp_dir = True

    # Make sure path exists and is a directory
    check_destination_path(module, dest)

    # Authenticate and initialize
    falcon = authenticate(module, Intel)
    result = dict(
        changed=False,
    )

    # If rule_id is not provided, get the latest rule ID for the specified type
    if not rule_id:
        if not rule_type:
            module.fail_json(msg="Either rule_id or type must be provided.")
        rule_id = get_latest_rule_id(module, falcon, rule_type, result)

    # Get rule details to include in the result
    rule_details = get_rule_details(module, falcon, rule_id, result)
    result.update(
        rule_id=rule_id,
        rule_name=rule_details.get('name'),
        rule_type=rule_details.get('type')
    )

    # Set the filename if not provided
    if not name:
        rule_type_name = rule_details.get('type', 'rule')
        name = f"{rule_type_name}-{rule_id}.{compression_format}"

    path = os.path.join(dest, name)
    lock = None

    try:
        lock = lock_file(path, timeout=300, retry_interval=5)
        if not lock:
            module.fail_json(msg=f"Unable to acquire lock for file: {path} after 5 minutes.", **result)

        # Check if the file already exists
        if not tmp_dir and os.path.isfile(path):
            handle_existing_file(module, result, path)

        # If we get here, the file either doesn't exist or has changed
        result.update(changed=True)

        if module.check_mode:
            module.exit_json(
                msg=f"File would have been downloaded: {path}",
                path=path,
                **result,
            )

        # Download the rule file
        file_content = download_rule_file(module, falcon, rule_id, compression_format)

        # Save the file
        with open(path, "wb") as save_file:
            save_file.write(file_content)

        # Set permissions on the file
        update_permissions(module, result["changed"], path)

        result.update(path=path)
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=f"Error downloading rule file: {str(e)}", **result)
    finally:
        if lock:
            unlock_file(lock)


if __name__ == "__main__":
    main()
