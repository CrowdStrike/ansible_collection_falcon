# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import host_hide

HOST_ID = "%032d" % 1
MISSING_ID = "%032d" % 33


def action_response(fixture, case, resources=None, errors=None, status_code=None):
    """Return a recorded perform_action response, changed as requested.

    The recorder does not hide real hosts, so it records only the response
    for a host that does not exist. A success or a 409 ("already in that
    state") response is that recorded response with other resources and
    errors.
    """
    response = copy.deepcopy(fixture("hosts/" + case))
    if resources is not None:
        response["body"]["resources"] = resources
    if errors is not None:
        response["body"]["errors"] = errors
    if status_code is not None:
        response["status_code"] = status_code
    return response


@pytest.fixture
def api(falcon_api):
    """Return a function that patches host_hide with perform_action responses."""

    def make(*responses):
        return falcon_api(host_hide, {"perform_action": list(responses)})

    return make


def hidden(fixture, case, host_ids):
    return action_response(
        fixture, case, resources=[{"id": h, "path": ""} for h in host_ids], errors=[], status_code=202
    )


def test_hide_host(api, run_module, fixture):
    service = api(hidden(fixture, "action_hide_host_missing", [HOST_ID]))

    result = run_module(host_hide, {"hosts": [HOST_ID]})

    assert result["changed"] is True
    assert result["hosts"] == [HOST_ID]
    assert service.called("perform_action") == [{"action_name": "hide_host", "ids": [HOST_ID]}]


def test_unhide_host(api, run_module, fixture):
    service = api(hidden(fixture, "action_unhide_host_missing", [HOST_ID]))

    result = run_module(host_hide, {"hosts": [HOST_ID], "hidden": False})

    assert result["changed"] is True
    assert service.called("perform_action") == [{"action_name": "unhide_host", "ids": [HOST_ID]}]


def test_hosts_are_sent_in_batches_of_100(api, run_module, fixture):
    hosts = ["%032d" % n for n in range(1, 102)]
    service = api(
        hidden(fixture, "action_hide_host_missing", hosts[:100]),
        hidden(fixture, "action_hide_host_missing", hosts[100:]),
    )

    result = run_module(host_hide, {"hosts": hosts})

    assert [len(c["ids"]) for c in service.called("perform_action")] == [100, 1]
    assert result["hosts"] == hosts


def test_host_already_hidden_is_not_changed(api, run_module, fixture):
    api(
        action_response(
            fixture, "action_hide_host_missing",
            errors=[{"code": 409, "message": "Host %s is already in the requested state" % HOST_ID}],
            status_code=409,
        )
    )

    result = run_module(host_hide, {"hosts": [HOST_ID]})

    assert result["changed"] is False
    assert result["hosts"] == [HOST_ID]
    assert result["failed_hosts"] == []


def test_host_that_does_not_exist_is_a_failed_host(api, run_module, fixture):
    api(fixture("hosts/action_hide_host_missing"))

    result = run_module(host_hide, {"hosts": [MISSING_ID]})

    assert not result.get("failed")
    assert result["changed"] is False
    assert result["failed_hosts"] == [
        {"id": MISSING_ID, "code": 404, "message": "No matching device found for ID %s" % MISSING_ID}
    ]


def test_check_mode_makes_no_api_calls(api, run_module):
    service = api()

    result = run_module(host_hide, {"hosts": [HOST_ID]}, check_mode=True)

    # current behavior: check mode exits before any API call, so it never
    # predicts a change.
    assert result["changed"] is False
    assert service.calls == []
