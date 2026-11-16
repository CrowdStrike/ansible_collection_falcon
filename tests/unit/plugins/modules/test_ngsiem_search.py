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
JOB_ID = "P656-kFRk311Xmal8zlXu1ISrnhSd"


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


def cancelled(fixture):
    """Return the recorded finished search as a search that was cancelled.

    No live response had "cancelled": true. The API deletes a stopped job,
    and its next status call returns an error (search_status_stopped), so
    this copy of the same method sets the fields that the module reads.
    """
    response = copy.deepcopy(fixture("ngsiem/search_status"))
    response.pop("method", None)
    response["body"].update(cancelled=True, done=False, events=[])
    return response


def status_error_msg(fixture, case, job_id=JOB_ID):
    """Return the module msg for a recorded status error."""
    response = fixture("ngsiem/" + case)
    message = response["body"]["errors"][0]["message"]
    return f"Failed to get the status of search job {job_id} (HTTP {response['status_code']}): {message}"


def test_search_returns_events(api, run_module):
    service = api(start_search=["search_start"], get_search_status=["search_status"])

    result = run_module(ngsiem_search, {"query_string": QUERY, "start": "1h"})

    assert service.called("start_search") == [{"repository": REPO, "query_string": QUERY, "start": "1h"}]
    assert service.called("get_search_status") == [{"repository": REPO, "search_id": JOB_ID}]
    assert result["query_job_id"] == JOB_ID
    assert result["done"] is True
    assert result["cancelled"] is False
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
    # current behavior: the module ignores an error of the stop call and
    # fails with the timeout. Here the stop call raises.
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


def test_search_timeout_stops_job_once(api, run_module, fixture, clock):
    service = api(
        start_search=["search_start"],
        get_search_status=[running(fixture)],
        stop_search=["search_stopped_stop"],
    )

    result = run_module(ngsiem_search, {"query_string": QUERY, "timeout": 15, "poll_interval": 10})

    assert result["failed"] is True
    assert result["msg"] == "Query timed out after 15 seconds"
    assert result["query_job_id"] == JOB_ID
    assert service.called("stop_search") == [{"repository": REPO, "id": JOB_ID}]
    methods = [method for method, _kwargs in service.calls]
    assert methods[-1] == "stop_search"
    assert methods.count("stop_search") == 1


@pytest.mark.parametrize(
    "start, case",
    [
        # The recorded status is for a job ID that never existed, so its
        # message names another ID than the job of search_start.
        ("search_start", "search_status_missing"),
        # The recorder started this job, stopped it, then read its status.
        ("search_stopped_start", "search_status_stopped"),
    ],
    ids=["job-not-found", "job-stopped"],
)
def test_search_status_error_fails_with_api_error(api, run_module, fixture, clock, start, case):
    service = api(start_search=[start], get_search_status=[case])
    job_id = fixture("ngsiem/" + start)["resources"]["id"]

    result = run_module(ngsiem_search, {"query_string": QUERY, "start": "1h"})

    assert result["failed"] is True
    assert result["msg"] == status_error_msg(fixture, case, job_id)
    assert result["query_job_id"] == job_id
    assert result["errors"] == fixture("ngsiem/" + case)["body"]["errors"]
    assert result["api_error"]["status_code"] == fixture("ngsiem/" + case)["status_code"]
    assert [method for method, _kwargs in service.calls] == ["start_search", "get_search_status"]
    assert service.called("get_search_status") == [{"repository": REPO, "search_id": job_id}]
    assert clock.sleeps == []


def test_search_status_error_after_running_poll_fails(api, run_module, fixture, clock):
    service = api(
        start_search=["search_start"],
        get_search_status=[running(fixture), "search_status_missing"],
    )

    result = run_module(ngsiem_search, {"query_string": QUERY})

    assert result["failed"] is True
    assert result["msg"] == status_error_msg(fixture, "search_status_missing")
    assert result["errors"] == fixture("ngsiem/search_status_missing")["body"]["errors"]
    assert [method for method, _kwargs in service.calls] == ["start_search", "get_search_status", "get_search_status"]
    assert clock.sleeps == [10]


def test_search_query_fails_while_running(api, run_module, fixture, clock):
    service = api(
        start_search=["search_lookup_missing_start"],
        get_search_status=["search_status_lookup_missing"],
    )
    job_id = fixture("ngsiem/search_lookup_missing_start")["resources"]["id"]
    errors = fixture("ngsiem/search_status_lookup_missing")["body"]["errors"]

    result = run_module(ngsiem_search, {"query_string": QUERY})

    assert result["failed"] is True
    assert result["msg"] == f"Failed to get the status of search job {job_id} (HTTP 400): {errors[0]['message']}"
    assert "Can't find" in result["msg"]
    assert result["query_job_id"] == job_id
    assert result["errors"] == errors
    assert service.called("get_search_status") == [{"repository": REPO, "search_id": job_id}]
    assert "stop_search" not in [method for method, _kwargs in service.calls]
    assert clock.sleeps == []


def test_search_cancelled_job_fails(api, run_module, fixture, clock):
    service = api(start_search=["search_start"], get_search_status=[cancelled(fixture)])

    result = run_module(ngsiem_search, {"query_string": QUERY, "start": "1h"})

    assert result["failed"] is True
    assert result["msg"] == f"Search job {JOB_ID} was cancelled"
    assert result["cancelled"] is True
    assert result["query_job_id"] == JOB_ID
    assert [method for method, _kwargs in service.calls] == ["start_search", "get_search_status"]
    assert service.called("get_search_status") == [{"repository": REPO, "search_id": JOB_ID}]
    assert clock.sleeps == []


def test_search_cancelled_after_running_poll_fails(api, run_module, fixture, clock):
    # The last response repeats, so a module that kept polling would make a third status call.
    service = api(
        start_search=["search_start"],
        get_search_status=[running(fixture), cancelled(fixture)],
    )

    result = run_module(ngsiem_search, {"query_string": QUERY, "poll_interval": 5})

    assert result["failed"] is True
    assert result["msg"] == f"Search job {JOB_ID} was cancelled"
    assert [method for method, _kwargs in service.calls] == ["start_search", "get_search_status", "get_search_status"]
    assert clock.sleeps == [5]


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
