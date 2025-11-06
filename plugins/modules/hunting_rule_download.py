#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: hunting_rule_download

short_description: Download CrowdStrike Falcon Hunting rule archives

version_added: "4.10.0"

description:
  - Downloads CrowdStrike Falcon Hunting rule archives with advanced filtering capabilities.
  - Supports downloading hunting rules for multiple languages including CQL, Snort, Suricata, and YARA.
  - Provides FQL (Falcon Query Language) filtering for precise rule selection.
  - Downloads rule collections as ZIP or GZIP archives.

options:
  language:
    description:
      - The language of the hunting rules to download.
      - Supported languages include CQL, Snort, Suricata, and YARA.
    type: str
    choices:
      - cql
      - snort
      - suricata
      - yara
    required: true
  filter:
    description:
      - FQL (Falcon Query Language) filter to apply for precise rule selection.
      - Allows filtering rules by adversary, reports, metadata, or other criteria.
      - If not specified, all rules for the specified language will be downloaded.
    type: str
  archive_type:
    description:
      - The compression format for the downloaded archive.
    type: str
    choices:
      - zip
      - gzip
    default: zip
  dest:
    description:
      - The directory path to save the hunting rule archive.
      - If not specified, a temporary directory will be created using
        the system's default temporary directory.
    type: path
  name:
    description:
      - The filename to save the hunting rule archive as.
      - If not specified, it will generate a name based on language and timestamp.
    type: str

extends_documentation_fragment:
  - files
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - This module implements file locking to ensure safe concurrent downloads by preventing multiple
    instances from accessing the same file simultaneously.
  - Requires CAO Hunting [B(READ)] API scope and Falcon Adversary Intelligence Premium subscription.
  - Uses advanced FQL filtering capabilities for precise hunting rule selection.

requirements:
  - CAO Hunting [B(READ)] API scope
  - Falcon Adversary Intelligence Premium subscription

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Download all YARA hunting rules
  crowdstrike.falcon.hunting_rule_download:
    language: "yara"
    dest: "/tmp/hunting_rules"

- name: Download CQL hunting rules with FQL filter
  crowdstrike.falcon.hunting_rule_download:
    language: "cql"
    filter: "adversaries:'FANCY BEAR'"
    dest: "/tmp/hunting_rules"
    name: "spider_cql_rules.zip"

- name: Download Snort rules in GZIP format
  crowdstrike.falcon.hunting_rule_download:
    language: "snort"
    archive_type: "gzip"
    dest: "/tmp/hunting_rules"

- name: Download Suricata rules filtered by report
  crowdstrike.falcon.hunting_rule_download:
    language: "suricata"
    filter: "reports:'APT1'"
    dest: "/tmp/hunting_rules"
"""

RETURN = r"""
path:
  description: The full path of the downloaded hunting rule archive.
  returned: success
  type: str
  sample: /tmp/hunting_rules/yara-hunting-rules-20231015.zip
language:
  description: The language of the downloaded hunting rules.
  returned: success
  type: str
  sample: "yara"
archive_type:
  description: The compression format of the downloaded archive.
  returned: success
  type: str
  sample: "zip"
filter:
  description: The FQL filter applied to the rule selection (if any).
  returned: success
  type: str
  sample: "adversaries:'FANCY BEAR'"
"""

import errno
import fcntl
import traceback
import os
import time
import random
from datetime import datetime
from tempfile import mkdtemp

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.crowdstrike.falcon.plugins.module_utils.common_args import (
    falconpy_arg_spec,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconpy_utils import (
    authenticate,
    check_falconpy_version,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import CAOHunting

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()
    args.update(
        language=dict(
            type="str", choices=["cql", "snort", "suricata", "yara"], required=True
        ),
        filter=dict(type="str"),
        archive_type=dict(type="str", choices=["zip", "gzip"], default="zip"),
        dest=dict(type="path"),
        name=dict(type="str"),
    )
    return args


def lock_file(file_path, exclusive=True, timeout=300, retry_interval=5):
    """Lock a file for reading or writing."""
    lock_file_path = file_path + ".lock"
    # Ignore the pylint warning here as a with block will close the file handle immediately
    # and we need to keep it open to maintain the lock
    lock_file_handle = open(lock_file_path, "w", encoding="utf-8")  # pylint: disable=consider-using-with
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
        module.fail_json(
            msg=f"Destination path does not exist or is not a directory: {dest}"
        )

    if not os.access(dest, os.W_OK):
        module.fail_json(msg=f"Destination path is not writable: {dest}")


def update_permissions(module, changed, path):
    """Update the permissions on the file if needed."""
    file_args = module.load_file_common_arguments(module.params, path=path)

    return module.set_fs_attributes_if_different(file_args, changed=changed)


def download_hunting_archive(module, falcon, language, fql_filter, archive_type):
    """Download hunting rule archive using CAO Hunting API."""
    params = {"language": language, "archive_type": archive_type}

    # Add FQL filter if provided
    if fql_filter:
        params["filter"] = fql_filter

    download = falcon.create_export_archive(**params)

    if isinstance(download, dict) and "status_code" in download:
        # Error occurred
        error_msg = "Unknown error"
        if (
            "body" in download
            and "errors" in download["body"]
            and download["body"]["errors"]
        ):
            error_msg = download["body"]["errors"][0].get("message", error_msg)
        module.fail_json(msg=f"Failed to download hunting rule archive: {error_msg}")

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


def prepare_download_path(module, dest, name, language, archive_type):
    """Prepare the download path for the hunting rule archive."""
    # Check if destination directory exists
    if not dest:
        dest = mkdtemp()
        os.chmod(dest, 0o755)  # nosec
        tmp_dir = True
    else:
        tmp_dir = False
        # Make sure path exists and is a directory
        check_destination_path(module, dest)

    # Set the filename if not provided
    if not name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{language}-hunting-rules-{timestamp}.{archive_type}"

    path = os.path.join(dest, name)

    return path, tmp_dir


def main():
    """Entry point for module execution."""
    module = AnsibleModule(
        argument_spec=argspec(),
        add_file_common_args=True,
        supports_check_mode=True,
    )

    if not HAS_FALCONPY:
        module.fail_json(
            msg=missing_required_lib("falconpy"), exception=FALCONPY_IMPORT_ERROR
        )

    check_falconpy_version(module)

    # Get parameters
    language = module.params.get("language")
    fql_filter = module.params.get("filter")
    archive_type = module.params.get("archive_type")
    dest = module.params.get("dest")
    name = module.params.get("name")

    # Authenticate and initialize
    falcon = authenticate(module, CAOHunting)
    result = dict(
        changed=False, language=language, archive_type=archive_type, filter=fql_filter
    )

    # Prepare the download path
    path, tmp_dir = prepare_download_path(module, dest, name, language, archive_type)
    lock = None

    try:
        lock = lock_file(path, timeout=300, retry_interval=5)
        if not lock:
            module.fail_json(
                msg=f"Unable to acquire lock for file: {path} after 5 minutes.",
                **result,
            )

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

        # Download the hunting rule archive
        file_content = download_hunting_archive(
            module, falcon, language, fql_filter, archive_type
        )

        # Save the file
        with open(path, "wb") as save_file:
            save_file.write(file_content)

        # Set permissions on the file
        update_permissions(module, result["changed"], path)

        result.update(path=path)
        module.exit_json(**result)
    except Exception as e:  # pylint: disable=broad-exception-caught
        module.fail_json(
            msg=f"Error downloading hunting rule archive: {str(e)}", **result
        )
    finally:
        if lock:
            unlock_file(lock)


if __name__ == "__main__":
    main()
