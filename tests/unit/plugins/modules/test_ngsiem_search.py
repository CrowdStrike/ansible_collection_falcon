# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import ngsiem_search

REPO = "search-all"
QUERY = 'createEvents(["fixture=a", "fixture=b"]) | kvParse()'
JOB_ID = "P656-Y5Jqftis4Rm6Et5EjijUmgDm"


@pytest.fixture
def clock(fake_clock):
    return fake_clock(ngsiem_search)


@pytest.fixture
def api(falcon_api, fixture, clock):
    """Return a function that patches ngsiem_search with recorded responses.

    Values in responses are fixture names or response dicts. The polling
    uses a FakeClock (the clock fixture).
    """

    def make(**responses):
        return falcon_api(
            ngsiem_search,
            {
                method: [fixture("ngsiem/" + c) if isinstance(c, str) else c for c in cases]
                for method, cases in responses.items()
            },
        )

    return make


def running(fixture):
    """Return the recorded finished search as a search that is still running."""
    response = copy.deepcopy(fixture("ngsiem/search_status"))
    response["body"].update(done=False, events=[])
    return response


def test_search_returns_events(api, run_module):
    service = api(start_search=["search_start"], get_search_status=["search_status"])

    result = run_module(ngsiem_search, {"query_string": QUERY, "start": "1h"})

    assert service.called("start_search") == [{"repository": REPO, "query_string": QUERY, "start": "1h"}]
    assert service.called("get_search_status") == [{"repository": REPO, "search_id": JOB_ID}]
    assert result["query_job_id"] == JOB_ID
    assert result["done"] is True
    assert result["total_events"] == 2
    assert [e["fixture"] for e in result["events"]] == ["a", "b"]
    assert "msg" not in result


def test_search_polls_until_done(api, run_module, fixture, clock):
    service = api(
        start_search=["search_start"],
        get_search_status=[running(fixture), running(fixture), "search_status"],
    )

    result = run_module(ngsiem_search, {"query_string": QUERY, "poll_interval": 5})

    assert len(service.called("get_search_status")) == 3
    assert clock.sleeps == [5, 5]
    assert result["total_events"] == 2


def test_search_with_no_events(api, run_module):
    api(start_search=["search_empty_start"], get_search_status=["search_empty_status"])

    result = run_module(ngsiem_search, {"query_string": "#event_simpleName=AnsibleUnitFixtureNoSuchEvent | head(1)"})

    assert result["done"] is True
    assert result["events"] == []
    assert result["total_events"] == 0


def test_search_timeout_stops_job_and_fails(api, run_module, fixture):
    # No stop_search response is recorded, so the stop call raises. The
    # module ignores errors from the stop call and fails with the timeout.
    service = api(
        start_search=["search_start"],
        get_search_status=[running(fixture)],
        stop_search=[Exception("stop_search failed")],
    )

    result = run_module(ngsiem_search, {"query_string": QUERY, "timeout": 15, "poll_interval": 10})

    assert result["failed"] is True
    assert result["msg"] == "Query timed out after 15 seconds"
    assert result["query_job_id"] == JOB_ID
    assert service.called("stop_search") == [{"repository": REPO, "id": JOB_ID}]


def test_bad_query_fails_with_api_message(api, run_module):
    # start_search returns its errors in a top-level 'resources'.
    api(start_search=["search_bad_query"])

    result = run_module(ngsiem_search, {"query_string": "| | not a query ("})

    assert result["failed"] is True
    assert "Expected an expression" in result["msg"]
    assert result["errors"][0]["code"] == 400


def test_check_mode_starts_search_but_does_not_wait(api, run_module):
    service = api(start_search=["search_start"])

    result = run_module(ngsiem_search, {"query_string": QUERY}, check_mode=True)

    # current behavior: check mode still starts a search job.
    assert service.called("start_search")
    assert "get_search_status" not in [method for method, _kwargs in service.calls]
    assert result["query_job_id"] == JOB_ID
    assert result["msg"] == "Check mode - search job started but not executed"


@pytest.mark.parametrize(
    "args, message",
    [
        ({"poll_interval": 4}, "at least 5 seconds"),
        ({"poll_interval": 91}, "should not exceed 90 seconds"),
        ({"timeout": -1}, "positive number or 0"),
    ],
    ids=["poll-too-short", "poll-too-long", "negative-timeout"],
)
def test_invalid_arguments_fail(api, run_module, args, message):
    service = api()

    result = run_module(ngsiem_search, dict(args, query_string=QUERY))

    assert result["failed"] is True
    assert message in result["msg"]
    assert service.calls == []
