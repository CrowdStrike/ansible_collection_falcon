# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

from ansible_collections.crowdstrike.falcon.plugins.lookup import maintenance_token

DEVICE_ID = "00000000000000000000000000000003"


@pytest.fixture
def lookup(falcon_api, fixture):
    """Return a function that loads the lookup with recorded responses."""

    def make(*cases):
        service = falcon_api(
            maintenance_token,
            {"reveal_uninstall_token": [fixture("sensor_update_policy/" + case) for case in cases]},
        )
        return lookup_loader.get("crowdstrike.falcon.maintenance_token"), service

    return make


def test_bulk_token(lookup):
    plugin, service = lookup("token_bulk")

    assert plugin.run([], variables={}, bulk=True) == ["REDACTED"]
    assert service.called("reveal_uninstall_token") == [
        {"audit_message": "Ansible maintenance token lookup", "device_id": "MAINTENANCE"}
    ]


def test_token_for_each_device(lookup):
    plugin, service = lookup("token_missing_device")

    assert plugin.run([DEVICE_ID, DEVICE_ID], variables={}) == ["REDACTED", "REDACTED"]
    assert [c["device_id"] for c in service.called("reveal_uninstall_token")] == [DEVICE_ID, DEVICE_ID]


def test_api_error_raises(falcon_api, fixture):
    # The token API returns a token for a device ID that does not exist, so
    # the recorder cannot record an error: change a copy of a recorded response.
    response = copy.deepcopy(fixture("sensor_update_policy/token_missing_device"))
    del response["method"]
    response["status_code"] = 404
    response["body"]["resources"] = []
    response["body"]["errors"] = [{"code": 404, "message": "Not Found"}]
    falcon_api(maintenance_token, {"reveal_uninstall_token": [response]})
    plugin = lookup_loader.get("crowdstrike.falcon.maintenance_token")

    with pytest.raises(AnsibleError, match="Unable to fetch maintenance token: .*Not Found"):
        plugin.run([DEVICE_ID], variables={})
