# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import host_info

HOSTS = ["%032d" % n for n in (1, 2, 3, 4)]
MISSING_ID = "%032d" % 33


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches host_info with recorded responses."""

    def make(*cases):
        return falcon_api(
            host_info, {"get_device_details": [fixture("hosts/" + case) for case in cases]}
        )

    return make


def test_returns_host_details(api, run_module):
    service = api("details_page1")

    result = run_module(host_info, {"hosts": HOSTS[:2]})

    assert result["changed"] is False
    assert [h["device_id"] for h in result["hosts"]] == HOSTS[:2]
    assert result["hosts"][0]["hostname"] == "host1"
    assert service.called("get_device_details") == [{"ids": HOSTS[:2]}]


def test_hosts_are_requested_in_batches_of_5000(api, run_module):
    service = api("details_page1", "details_page2")
    hosts = HOSTS[:2] * 2500 + HOSTS[2:]

    result = run_module(host_info, {"hosts": hosts})

    assert [len(c["ids"]) for c in service.called("get_device_details")] == [5000, 2]
    assert [h["device_id"] for h in result["hosts"]] == HOSTS


def test_invalid_host_id_fails_with_api_message(api, run_module):
    api("details_missing")

    result = run_module(host_info, {"hosts": [MISSING_ID]})

    assert result["failed"] is True
    assert result["msg"] == "invalid device id [%s]" % MISSING_ID


@pytest.mark.xfail(
    strict=True,
    raises=UnboundLocalError,
    reason="With an empty hosts list the loop does not run, so query_result "
    "is not set when the module passes it to handle_return_errors.",
)
def test_empty_hosts_list_returns_no_hosts(api, run_module):
    api("details_page1")

    result = run_module(host_info, {"hosts": []})

    assert result["hosts"] == []
