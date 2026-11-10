# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.crowdstrike.falcon.plugins.modules import cid_info


def test_returns_ccid(falcon_api, fixture, run_module):
    service = falcon_api(cid_info, {"get_sensor_installer_ccid": [fixture("sensor_download/ccid")]})

    result = run_module(cid_info, {})

    assert result["changed"] is False
    assert result["cid"] == "00000000000000000000000000000001-0F"
    assert service.called("get_sensor_installer_ccid") == [{}]


def test_api_error_fails_with_message(falcon_api, fixture, run_module):
    # A recorded 403 for an API client without the needed scope.
    falcon_api(cid_info, {"get_sensor_installer_ccid": [fixture("flight_control/children_page1")]})

    result = run_module(cid_info, {})

    assert result["failed"] is True
    assert result["msg"] == "access denied, scope not permitted"
    assert "cid" not in result
