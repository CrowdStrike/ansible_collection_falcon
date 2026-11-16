# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

from ansible_collections.crowdstrike.falcon.plugins.modules import cid_info


def test_returns_ccid(falcon_api, fixture, run_module):
    service = falcon_api(cid_info, {"get_sensor_installer_ccid": [fixture("sensor_download/ccid")]})

    result = run_module(cid_info, {})

    assert result["changed"] is False
    assert result["cid"] == "00000000000000000000000000000001-0F"
    assert service.called("get_sensor_installer_ccid") == [{}]


def test_api_error_fails_with_message(falcon_api, fixture, run_module):
    # The recorder's API client has the Sensor Download scope, so it cannot
    # record the 403: change a copy of a recorded response.
    response = copy.deepcopy(fixture("sensor_download/ccid"))
    del response["method"]
    response["status_code"] = 403
    response["body"]["resources"] = []
    response["body"]["errors"] = [{"code": 403, "message": "access denied, scope not permitted"}]
    falcon_api(cid_info, {"get_sensor_installer_ccid": [response]})

    result = run_module(cid_info, {})

    assert result["failed"] is True
    assert result["msg"] == "access denied, scope not permitted"
    assert "cid" not in result
