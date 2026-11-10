# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.crowdstrike.falcon.plugins.modules import sensor_download_info

ROUTE = "override:GET /sensors/combined/installers/v2"


def test_returns_installers(falcon_api, fixture, run_module):
    service = falcon_api(sensor_download_info, {ROUTE: [fixture("sensor_download/installers_linux")]})

    result = run_module(sensor_download_info, {"filter": "platform:'linux'", "sort": "version|desc"})

    assert result["changed"] is False
    assert [i["name"] for i in result["installers"]] == [
        "falcon-sensor_8.11.0-19508_amd64.deb",
        "falcon-sensor_8.11.0-19508_arm64.deb",
    ]
    assert service.called(ROUTE) == [{"parameters": {"filter": "platform:'linux'", "sort": "version|desc"}}]


def test_options_that_are_not_set_are_sent_as_none(falcon_api, fixture, run_module):
    service = falcon_api(sensor_download_info, {ROUTE: [fixture("sensor_download/installers_linux")]})

    run_module(sensor_download_info, {})

    # current behavior: FalconPy drops the None values from the query string.
    assert service.called(ROUTE) == [{"parameters": {"filter": None, "sort": None}}]


def test_api_error_fails_with_message(falcon_api, fixture, run_module):
    falcon_api(sensor_download_info, {ROUTE: [fixture("sensor_download/installers_bad_filter")]})

    result = run_module(sensor_download_info, {"filter": "platform:'"})

    assert result["failed"] is True
    assert result["msg"].startswith("Failed to parse filter expression.")
