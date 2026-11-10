# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import intel_rule_download

RULE_ID = "1793955604"
RULE_NAME = "CrowdStrike Intelligence Feed: YARA Master - 2026/11/06"
# The tests download these bytes instead of a rule file.
CONTENT = b"FAKE"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches intel_rule_download with recorded responses."""

    def make(**responses):
        return falcon_api(
            intel_rule_download,
            {
                method: [fixture("intel/" + c) if isinstance(c, str) else c for c in cases]
                for method, cases in responses.items()
            },
        )

    return make


def methods(service):
    return [method for method, _kwargs in service.calls]


def test_download_by_rule_id(api, run_module, tmp_path):
    service = api(get_rule_entities=["rules"], get_rule_file=[CONTENT])

    result = run_module(intel_rule_download, {"rule_id": RULE_ID, "dest": str(tmp_path)})

    path = tmp_path / ("yara-master-%s.zip" % RULE_ID)
    assert result["changed"] is True
    assert result["path"] == str(path)
    assert path.read_bytes() == CONTENT
    assert (result["rule_id"], result["rule_name"], result["rule_type"]) == (RULE_ID, RULE_NAME, "yara-master")
    assert service.called("get_rule_entities") == [{"ids": [RULE_ID]}]
    assert service.called("get_rule_file") == [{"id": RULE_ID, "format": "zip"}]


def test_download_latest_by_type(api, run_module, tmp_path):
    service = api(
        query_rule_ids=["rule_ids_page1"], get_rule_entities=["rules"], get_latest_rule_file=[CONTENT]
    )

    result = run_module(
        intel_rule_download, {"type": "yara-master", "format": "gzip", "dest": str(tmp_path), "name": "rules.gz"}
    )

    assert result["path"] == str(tmp_path / "rules.gz")
    assert result["rule_id"] == RULE_ID
    assert service.called("query_rule_ids") == [{"type": "yara-master", "sort": "created_date|desc", "limit": 1}]
    assert service.called("get_latest_rule_file") == [{"type": "yara-master", "format": "gzip"}]


def test_existing_file_is_not_downloaded_again(api, run_module, tmp_path):
    (tmp_path / "rules.zip").write_bytes(b"OLD")
    service = api(get_rule_entities=["rules"])

    result = run_module(intel_rule_download, {"rule_id": RULE_ID, "dest": str(tmp_path), "name": "rules.zip"})

    # current behavior: the module does not compare the content, so an
    # existing file is never replaced.
    assert result["changed"] is False
    assert result["msg"] == "File already exists but may have been updated."
    assert "get_rule_file" not in methods(service)


def test_check_mode_does_not_download(api, run_module, tmp_path):
    service = api(get_rule_entities=["rules"])

    result = run_module(intel_rule_download, {"rule_id": RULE_ID, "dest": str(tmp_path)}, check_mode=True)

    assert result["changed"] is True
    assert result["msg"].startswith("File would have been downloaded")
    assert "get_rule_file" not in methods(service)


def test_unknown_rule_id_fails(api, run_module, tmp_path):
    api(get_rule_entities=["rules_missing"])

    result = run_module(intel_rule_download, {"rule_id": "0", "dest": str(tmp_path)})

    assert result["failed"] is True
    assert result["msg"] == "No rule found with ID: 0"


def test_type_with_no_rules_fails(api, run_module, tmp_path):
    api(query_rule_ids=["rule_ids_empty"])

    result = run_module(intel_rule_download, {"type": "yara-master", "dest": str(tmp_path)})

    assert result["failed"] is True
    assert result["msg"] == "No rules found for type: yara-master"


def test_download_error_fails_with_api_message(api, run_module, tmp_path):
    api(get_rule_entities=["rules"], get_rule_file=["rule_file_missing"])

    result = run_module(intel_rule_download, {"rule_id": RULE_ID, "dest": str(tmp_path)})

    assert result["failed"] is True
    assert result["msg"] == "Failed to download rule file: Rule not found"


def test_rule_id_or_type_is_required(api, run_module, tmp_path):
    service = api()

    result = run_module(intel_rule_download, {"dest": str(tmp_path)})

    assert result["failed"] is True
    assert "type, rule_id" in result["msg"]
    assert service.calls == []
