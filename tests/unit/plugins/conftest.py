# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared fixtures for unit tests of the plugins that call the Falcon API.

The tests do not call the API. A FakeService stands in for the FalconPy
service class and returns responses that tests/unit/record_fixtures.py
recorded from a real tenant and sanitized.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import json
import os

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES_DIR, name + ".json")) as f:
        return json.load(f)


class FakeAuthObject(object):
    token_valid = True


class FakeService(object):
    """A stand-in for a FalconPy service class.

    responses maps a method name to a list of responses. Each call returns
    the next response, and the last one repeats. A call to a method that is
    not in responses raises AssertionError, so a test fails when a plugin
    makes a call that the test did not expect.

    override() is keyed as "override:<METHOD> <route>" and command() as
    "command:<operation_id>".
    """

    token_value = "fake-token"
    base_url = "https://api.crowdstrike.com"

    def __init__(self, responses):
        self._responses = {k: list(v) for k, v in responses.items()}
        self.calls = []
        self.auth_object = FakeAuthObject()

    def _respond(self, name, kwargs):
        self.calls.append((name, kwargs))
        if name not in self._responses:
            raise AssertionError("unexpected API call: %s" % name)
        queue = self._responses[name]
        response = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(response, (bytes, Exception)):
            if isinstance(response, Exception):
                raise response
            return response
        # Plugins may change the response, so each call gets its own copy.
        result = {k: copy.deepcopy(v) for k, v in response.items() if k != "method"}
        result.setdefault("headers", {})
        return result

    def override(self, method, route, **kwargs):
        return self._respond("override:%s %s" % (method, route), kwargs)

    def command(self, operation_id, **kwargs):
        return self._respond("command:%s" % operation_id, kwargs)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *args, **kwargs: self._respond(name, kwargs)

    def called(self, name):
        """Return the kwargs of every call to the named method."""
        return [kwargs for method, kwargs in self.calls if method == name]


class FakeClock(object):
    """A stand-in for the time module in a plugin that polls.

    sleep() moves the clock forward and does not wait.
    """

    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch):
    """Return a function that puts a FakeClock in a plugin as its time module."""

    def make(plugin):
        clock = FakeClock()
        monkeypatch.setattr(plugin, "time", clock)
        return clock

    return make


@pytest.fixture
def fixture():
    """Return a function that loads a recorded response by name.

    fixture("host_group/get_one") reads fixtures/host_group/get_one.json.
    """
    return _load


@pytest.fixture
def falcon_api(monkeypatch):
    """Return a function that makes a FakeService and puts it in a plugin.

    falcon_api(plugin, responses) patches plugin.authenticate, which every
    module uses to build its FalconPy client. Pass attr to patch a different
    name, for example a service class that a plugin builds itself.
    """

    def make(plugin, responses, attr="authenticate"):
        service = FakeService(responses)
        if attr == "authenticate":
            monkeypatch.setattr(plugin, attr, lambda *args, **kwargs: service)
        else:
            monkeypatch.setattr(
                plugin, attr, lambda *args, **kwargs: service, raising=False
            )
        return service

    return make
