# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import sensor_download

INSTALLER = "falcon-sensor_8.11.0-19508_amd64.deb"
HASH = "efe5dc643c3dc292e2c7dfd4698315f098e9d76584fa3ac830298c020250aefc"
# The tests download these bytes instead of a sensor installer.
CONTENT = b"FAKE"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches sensor_download with recorded responses."""

    def make(entity="installer_entity", download=CONTENT):
        responses = {"get_sensor_installer_entities": [fixture("sensor_download/" + entity)]}
        if download is not None:
            responses["download_sensor_installer"] = [download]
        return falcon_api(sensor_download, responses)

    return make


def methods(service):
    return [method for method, _kwargs in service.calls]


def test_downloads_installer_with_its_name(api, run_module, tmp_path):
    service = api()

    result = run_module(sensor_download, {"hash": HASH, "dest": str(tmp_path)})

    path = tmp_path / INSTALLER
    assert result["changed"] is True
    assert result["path"] == str(path)
    assert path.read_bytes() == CONTENT
    assert service.called("get_sensor_installer_entities") == [{"ids": [HASH]}]
    assert service.called("download_sensor_installer") == [{"id": HASH}]


def test_name_sets_file_name(api, run_module, tmp_path):
    api()

    result = run_module(sensor_download, {"hash": HASH, "dest": str(tmp_path), "name": "sensor.deb"})

    assert result["path"] == str(tmp_path / "sensor.deb")


def test_existing_file_with_same_hash_is_not_downloaded(api, run_module, tmp_path):
    (tmp_path / INSTALLER).write_bytes(CONTENT)
    service = api()

    result = run_module(sensor_download, {"hash": hashlib.sha256(CONTENT).hexdigest(), "dest": str(tmp_path)})

    assert result["changed"] is False
    assert result["msg"] == "File already exists and content is the same."
    assert "download_sensor_installer" not in methods(service)


def test_existing_file_with_other_content_is_downloaded_again(api, run_module, tmp_path):
    (tmp_path / INSTALLER).write_bytes(b"OLD")
    api()

    result = run_module(sensor_download, {"hash": HASH, "dest": str(tmp_path)})

    assert result["changed"] is True
    assert (tmp_path / INSTALLER).read_bytes() == CONTENT


def test_check_mode_does_not_download(api, run_module, tmp_path):
    service = api()

    result = run_module(sensor_download, {"hash": HASH, "dest": str(tmp_path)}, check_mode=True)

    assert result["changed"] is True
    assert result["msg"] == "File would have been downloaded: %s" % (tmp_path / INSTALLER)
    assert "download_sensor_installer" not in methods(service)
    assert not (tmp_path / INSTALLER).exists()


def test_unknown_hash_fails_with_api_message(api, run_module, tmp_path):
    api(entity="installer_entity_missing", download=None)

    result = run_module(sensor_download, {"hash": "0" * 64, "dest": str(tmp_path)})

    assert result["failed"] is True
    assert result["msg"] == "Installer not found for SHA256: %s" % ("0" * 64)


def test_download_error_fails(api, run_module, tmp_path, fixture):
    # The download call returns a dict, not bytes, on an error.
    api(download=fixture("sensor_download/download_missing"))

    result = run_module(sensor_download, {"hash": HASH, "dest": str(tmp_path)})

    assert result["failed"] is True
    assert result["msg"] == "Unable to download sensor installer"


def test_dest_that_is_not_a_directory_fails(api, run_module, tmp_path):
    service = api()

    result = run_module(sensor_download, {"hash": HASH, "dest": str(tmp_path / "missing")})

    assert result["failed"] is True
    assert result["msg"].startswith("Destination path does not exist or is not a directory")
    assert service.calls == []
