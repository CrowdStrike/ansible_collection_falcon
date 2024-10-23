#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sensor_download

short_description: Download Falcon Sensor Installer

version_added: "4.0.0"

description:
  - Downloads the Falcon Sensor Installer by SHA256 hash to the specified path.
  - This module does not copy the sensor installer to the target host. For that,
    use the M(ansible.builtin.copy) or M(ansible.windows.win_copy) module.

options:
  hash:
    description:
      - The SHA256 hash of the Falcon Sensor Installer to download.
      - This can be obtained from the C(sha256) return value of the
        M(crowdstrike.falcon.sensor_download_info) module.
    type: str
    required: true
  dest:
    description:
      - The directory path to save the Falcon Sensor Installer.
      - If not specified, a temporary directory will be created using
        the system's default temporary directory.
    type: path
    required: false
  name:
    description:
      - The name to save the Falcon Sensor Installer as.
      - If not specified, it will default to the name of the Falcon Sensor Installer.
      - "Example: falcon-sensor_6.78.9-12345.deb"
    type: str
    required: false

extends_documentation_fragment:
  - files
  - crowdstrike.falcon.credentials
  - crowdstrike.falcon.credentials.auth

notes:
  - This module implements file locking to ensure safe concurrent downloads by preventing multiple
    instances from accessing the same file simultaneously. As a result, a temporary 0-byte .lock
    file will be created in the same directory as the downloaded file. If needed, this lock file
    can be safely removed in a subsequent task after the download completes.

requirements:
  - Sensor download [B(READ)] API scope

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
- name: Download the Falcon Sensor Installer
  crowdstrike.falcon.sensor_download:
    hash: "1234567890123456789012345678901234567890123456789012345678901234"

- name: Download Windows Sensor Installer with custom name
  crowdstrike.falcon.sensor_download:
    hash: "1234567890123456789012345678901234567890123456789012345678901234"
    dest: "/tmp/windows"
    name: falcon-sensor.exe

- name: Download the Falcon Sensor Installer to a temporary directory and set permissions
  crowdstrike.falcon.sensor_download:
    hash: "1234567890123456789012345678901234567890123456789012345678901234"
    mode: "0644"
    owner: "root"
    group: "root"
"""

RETURN = r"""
path:
  description: The full path of the downloaded Falcon Sensor Installer.
  returned: success
  type: str
  sample: /tmp/tmpzy7hn29t/falcon-sensor.deb
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
    from falconpy import SensorDownload

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    FALCONPY_IMPORT_ERROR = traceback.format_exc()


def argspec():
    """Define the module's argument spec."""
    args = falconpy_arg_spec()

    args.update(
        hash=dict(type="str", required=True),
        dest=dict(type="path", required=False),
        name=dict(type="str", required=False),
    )

    return args


def update_permissions(module, changed, path):
    """Update the permissions on the file if needed."""
    file_args = module.load_file_common_arguments(module.params, path=path)

    return module.set_fs_attributes_if_different(file_args, changed=changed)


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
    """Unlock a file."""
    fcntl.flock(locked_file, fcntl.LOCK_UN)
    locked_file.close()


def check_destination_path(module, dest):
    """Check if the destination path is valid."""
    if not os.path.isdir(dest):
        module.fail_json(msg=f"Destination path does not exist or is not a directory: {dest}")

    if not os.access(dest, os.W_OK):
        module.fail_json(msg=f"Destination path is not writable: {dest}")


def handle_existing_file(module, result, path, sensor_hash):
    """Handle the case where the file already exists."""
    # Compare sha256 hashes to see if any changes have been made
    dest_hash = module.sha256(path)
    if dest_hash == sensor_hash:
        # File already exists and content is the same. Update permissions if needed.
        msg = "File already exists and content is the same."

        if update_permissions(module, result["changed"], path):
            msg += " Permissions were updated."
            result.update(changed=True)

        module.exit_json(
            msg=msg,
            path=path,
            **result,
        )


def download_sensor_installer(module, result, falcon, sensor_hash, path):
    """Download the sensor installer."""
    # Because this returns a binary, we need to handle errors differently
    download = falcon.download_sensor_installer(id=sensor_hash)

    if isinstance(download, dict):
        # Error as download should not be a dict (from FalconPy)
        module.fail_json(msg="Unable to download sensor installer", **result)

    with open(path, "wb") as save_file:
        save_file.write(download)


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

    sensor_hash = module.params["hash"]
    dest = module.params["dest"]
    name = module.params["name"]
    tmp_dir = False

    if not dest:
        dest = mkdtemp()
        os.chmod(dest, 0o755)  # nosec
        tmp_dir = True

    # Make sure path exists and is a directory
    check_destination_path(module, dest)

    falcon = authenticate(module, SensorDownload)

    result = dict(
        changed=False,
    )
    # First, ensure the sensor installer exists
    sensor_check = falcon.get_sensor_installer_entities(ids=[sensor_hash])
    handle_return_errors(module, result, sensor_check)

    if sensor_check["status_code"] == 200:
        # Get the name of the sensor installer
        if not name:
            name = sensor_check["body"]["resources"][0]["name"]

        path = os.path.join(dest, name)
        lock = None

        try:
            lock = lock_file(path, timeout=300, retry_interval=5)
            if not lock:
                module.fail_json(msg=f"Unable to acquire lock for file: {path} after 5 minutes.", **result)

            # Check if the file already exists
            if not tmp_dir and os.path.isfile(path):
                handle_existing_file(module, result, path, sensor_hash)

            # If we get here, the file either doesn't exist or has changed
            result.update(changed=True)

            if module.check_mode:
                module.exit_json(
                    msg=f"File would have been downloaded: {path}",
                    path=path,
                    **result,
                )

            # Download the sensor installer
            download_sensor_installer(module, result, falcon, sensor_hash, path)

            # Set permissions on the file
            update_permissions(module, result["changed"], path)

            result.update(path=path)
            module.exit_json(**result)
        finally:
            if lock:
                unlock_file(lock)
    else:
        # Should be caught by handle_return_errors, but just in case.
        module.fail_json(
            msg=f"Could not find installer with hash: {sensor_hash}", **result
        )


if __name__ == "__main__":
    main()
