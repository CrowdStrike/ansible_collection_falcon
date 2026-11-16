# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for the FakeService in conftest.py."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import types

import pytest


@pytest.fixture
def service(falcon_api):
    """Return a function that makes a FakeService for a stand-in plugin."""

    def make(responses):
        plugin = types.SimpleNamespace(authenticate=None)
        return falcon_api(plugin, responses)

    return make


def test_fixture_from_the_called_method_is_returned(service, fixture):
    fake = service({"get_host_groups": [fixture("host_group/get_one")]})

    result = fake.get_host_groups(ids=["1"])

    assert result["status_code"] == 200
    assert "method" not in result
    assert fake.unexpected == []


def test_fixture_from_another_method_fails_the_test(service, fixture):
    fake = service({"create_host_groups": [fixture("host_group/get_one")]})

    with pytest.raises(AssertionError) as err:
        fake.create_host_groups(body={})

    assert str(err.value) == "response recorded from get_host_groups returned for create_host_groups"
    # _no_unexpected_api_calls fails the test at teardown for this entry, so
    # clear it after the check.
    assert fake.unexpected == [("create_host_groups", {"body": {}})]
    fake.unexpected = []


def test_override_and_command_fixtures_match_their_keys(service, fixture):
    fake = service(
        {
            "override:GET /sensors/combined/installers/v2": [fixture("sensor_download/installers_linux")],
            "command:ExternalGetDataConnectionToken": [fixture("ngsiem/token_first")],
        }
    )

    fake.override("GET", "/sensors/combined/installers/v2", parameters={})
    fake.command("ExternalGetDataConnectionToken", id="1")

    assert fake.unexpected == []


def test_response_without_method_key_is_returned(service, fixture):
    response = copy.deepcopy(fixture("host_group/get_one"))
    del response["method"]
    fake = service({"create_host_groups": [response, {"status_code": 500, "body": {}}]})

    assert fake.create_host_groups(body={})["status_code"] == 200
    assert fake.create_host_groups(body={})["status_code"] == 500
    assert fake.unexpected == []
