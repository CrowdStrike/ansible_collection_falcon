# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import re

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import hunting_rule_download

# The tests download these bytes instead of a rule archive.
CONTENT = b"FAKE"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches hunting_rule_download with an export response."""

    def make(*responses):
        return falcon_api(
            hunting_rule_download,
            {"create_export_archive": [fixture("hunting/" + r) if isinstance(r, str) else r for r in responses]},
        )

    return make


def test_downloads_archive_with_default_name(api, run_module, tmp_path):
    service = api(CONTENT)

    result = run_module(hunting_rule_download, {"language": "yara", "dest": str(tmp_path)})

    assert result["changed"] is True
    assert re.match(r"yara-hunting-rules-\d{8}_\d{6}\.zip$", os.path.basename(result["path"]))
    with open(result["path"], "rb") as f:
        assert f.read() == CONTENT
    assert service.called("create_export_archive") == [{"language": "yara", "archive_type": "zip"}]


def test_filter_and_archive_type_are_passed(api, run_module, tmp_path):
    service = api(CONTENT)

    result = run_module(
        hunting_rule_download,
        {"language": "cql", "archive_type": "gzip", "filter": "name:'x'", "dest": str(tmp_path), "name": "cql.gz"},
    )

    assert result["path"] == str(tmp_path / "cql.gz")
    assert result["filter"] == "name:'x'"
    assert service.called("create_export_archive") == [
        {"language": "cql", "archive_type": "gzip", "filter": "name:'x'"}
    ]


def test_existing_file_is_not_downloaded_again(api, run_module, tmp_path):
    (tmp_path / "yara.zip").write_bytes(b"OLD")
    service = api(CONTENT)

    result = run_module(hunting_rule_download, {"language": "yara", "dest": str(tmp_path), "name": "yara.zip"})

    # current behavior: the module does not compare the content, so an
    # existing file is never replaced.
    assert result["changed"] is False
    assert service.calls == []


def test_check_mode_does_not_download(api, run_module, tmp_path):
    service = api(CONTENT)

    result = run_module(hunting_rule_download, {"language": "yara", "dest": str(tmp_path)}, check_mode=True)

    assert result["changed"] is True
    assert result["msg"].startswith("File would have been downloaded")
    assert service.calls == []


def test_api_error_fails_with_message(api, run_module, tmp_path):
    api("export_bad_filter")

    result = run_module(hunting_rule_download, {"language": "yara", "filter": "name:'", "dest": str(tmp_path)})

    assert result["failed"] is True
    assert result["msg"] == "Failed to download hunting rule archive: unable to parse the 'filter' param"
