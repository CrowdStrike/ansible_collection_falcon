# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import types

import pytest

from ansible_collections.crowdstrike.falcon.plugins.plugin_utils import rtr as rtr_utils

# The recorder wraps its scripts with this marker, so the recorded stdout has it.
MARKER = "__ANSIBLE_RTR_RC_0123456789abcdef__="
SESSION_ID = "00000000-0000-0000-0000-000000000001"
CRID = "00000000-0000-0000-0000-000000000002"
AID = "%032d" % 2
TIMEOUT = 30
FIXTURE_DIR = "/tmp/ansible-unit-fixture-dir"
MISSING_DIR = "/tmp/ansible-unit-fixture-missing"
CONTACT_SUPPORT = "Contact support. The command triggered an unknown error. Error code 9a4aae\n"
# A complete runscript with empty output and rc 0 (the recorded last fetch part).
RC0 = "fetch_part1_complete"
# A complete runscript with stdout 'out', stderr 'err' and rc 3.
RC3 = "runscript_complete"


def hexid(n):
    return "%032x" % n


NAME = "ansible-rtr-" + hexid(1)
STAGE = "/tmp/.ansible-rtr-" + hexid(2)


def raw(body):
    """The command string of a wrapped runscript, as run_with_rc sends it."""
    return "runscript -Raw=```" + rtr_utils.wrap_script(body, MARKER) + "``` -Timeout=%d" % TIMEOUT


def plain(script):
    """The command string of a runscript that run_raw sends without a wrapper."""
    return "runscript -Raw=```" + script + "``` -Timeout=%d" % TIMEOUT


def pvar(name, path):
    """The shell line that sets a variable to a path sent as base64."""
    return "%s=$(printf %%s '%s' | base64 $__b)" % (name, rtr_utils.b64(path))


def mv_body(src, dest, extra=""):
    return pvar("s", src) + "\n" + pvar("p", dest) + '\nmv -f "$s" "$p"' + extra


def rm_script(path):
    return rtr_utils._DECODE_FLAG + "\n" + pvar("p", path) + '\nrm -rf "$p"\n'


def execute(base_command, command_string):
    return {
        "base_command": base_command,
        "command_string": command_string,
        "session_id": SESSION_ID,
        "persist": False,
    }


def status(seq=0):
    return {"cloud_request_id": CRID, "sequence_id": seq}


def with_status(response, code, message="error", headers=None):
    """Return a copy of a recorded response with another status code.

    The tenant does not give 429 or 5xx responses on demand.
    """
    response = copy.deepcopy(response)
    response["status_code"] = code
    response["body"]["resources"] = []
    response["body"]["errors"] = [{"code": code, "message": message}]
    if headers:
        response["headers"] = headers
    return response


def with_stderr(response, stderr):
    """Return a copy of a recorded built-in result with another stderr.

    The "Contact support." stderr of fact 18 came once and cannot be made on demand.
    """
    response = copy.deepcopy(response)
    response["body"]["resources"][0]["stderr"] = stderr
    return response


@pytest.fixture(autouse=True)
def fixed_ids(monkeypatch, tmp_path):
    """Make the marker and the uuid names fixed, and put the lock folder under tmp_path."""
    count = iter(range(1, 100))
    monkeypatch.setattr(rtr_utils, "new_marker", lambda: MARKER)
    monkeypatch.setattr(rtr_utils, "uuid", types.SimpleNamespace(uuid4=lambda: types.SimpleNamespace(hex=hexid(next(count)))))
    monkeypatch.setenv("HOME", str(tmp_path))


@pytest.fixture
def make(falcon_api, fixture, fake_clock):
    """Return a function that builds an RTRSession on fake RTR and admin services."""

    def load(responses):
        return {
            method: [fixture("rtr/" + r) if isinstance(r, str) else r for r in items]
            for method, items in responses.items()
        }

    def build(admin=None, rtr=None):
        holder = types.SimpleNamespace()
        rtr_api = falcon_api(holder, load(rtr or {}), attr="rtr")
        admin_api = falcon_api(holder, load(admin or {}), attr="admin")
        logs = []
        warns = []
        session = rtr_utils.RTRSession(rtr_api, admin_api, poll_interval=0.5, log=logs.append, warn=warns.append)
        clock = fake_clock(rtr_utils)
        session.sleep = clock.sleep
        session.clock = clock.time
        session.device_id = AID
        session.session_id = SESSION_ID
        return types.SimpleNamespace(session=session, admin=admin_api, rtr=rtr_api, clock=clock, logs=logs, warns=warns)

    return build


# Marker and scripts


def test_parse_marker_found():
    assert rtr_utils.parse_marker("out\n\n%s3\n" % MARKER, "err\n", MARKER) == (3, "out\n", "err\n")


def test_parse_marker_missing():
    assert rtr_utils.parse_marker("out\n", "x", MARKER) == (255, "out\n", "RTR did not return an exit code. x")


def test_parse_marker_not_an_int():
    stdout = "out\n%sabc\n" % MARKER
    assert rtr_utils.parse_marker(stdout, None, MARKER) == (255, stdout, "RTR did not return an exit code. ")


def test_parse_marker_uses_the_last_marker():
    stdout = "a\n%s1\nb\n%s0\n" % (MARKER, MARKER)
    assert rtr_utils.parse_marker(stdout, "", MARKER) == (0, "a\n%s1\nb" % MARKER, "")


def test_wrap_script_prints_rc_after_cleanup():
    assert rtr_utils.wrap_script("echo a", MARKER, cleanup="rm -f x") == (
        'export HOME="${HOME:-/root}"\n'
        "__b=-d; printf %s eA== | base64 -d >/dev/null 2>&1 || __b=-D\n"
        "(\necho a\n)\n__rc=$?\nrm -f x\n"
        "printf '\\n" + MARKER + "%s\\n' \"$__rc\"\n"
    )


def test_wrap_script_without_cleanup():
    assert "rm -f" not in rtr_utils.wrap_script("echo a", MARKER)


def test_build_exec_script_writes_base64_and_removes_the_file():
    path = "/tmp/.ansible-rtr-%s.sh" % hexid(1)
    body = "(umask 077; printf %%s '%s' | base64 $__b > %s)\n/bin/sh %s" % (
        rtr_utils.b64("echo 'a'"), path, path,
    )
    assert rtr_utils.build_exec_script("echo 'a'", MARKER) == rtr_utils.wrap_script(body, MARKER, cleanup="rm -f " + path)


def test_b64_of_text_and_bytes():
    assert rtr_utils.b64("hi") == rtr_utils.b64(b"hi") == "aGk="


# resolve_device_id


@pytest.fixture
def hosts(falcon_api, fixture):
    def one(item):
        return fixture("rtr/" + item) if isinstance(item, str) else item

    def build(query, details=None):
        queries = query if isinstance(query, list) else [query]
        responses = {"query_devices_by_filter": [one(q) for q in queries]}
        if details is not None:
            items = details if isinstance(details, list) else [details]
            responses["get_device_details"] = [one(d) for d in items]
        return falcon_api(types.SimpleNamespace(), responses, attr="hosts")

    return build


def test_resolve_aid_is_used_as_is():
    assert rtr_utils.resolve_device_id(None, AID) == AID


def test_resolve_aid_upper_case_is_lowered():
    """The fake IDs have no letters, so a hex ID with letters tests the case change."""
    assert rtr_utils.resolve_device_id(None, "ABCDEF1234567890ABCDEF1234567890") == "abcdef1234567890abcdef1234567890"


def test_resolve_name_without_hosts_fails():
    with pytest.raises(rtr_utils.RTRError) as exc:
        rtr_utils.resolve_device_id(None, "host1")
    assert exc.value.message == "'host1' is not a device ID and no Hosts service is available."


@pytest.mark.parametrize("name", ["host1", "HOST1"])
def test_resolve_name_one_match(hosts, name):
    api = hosts("query_by_name", "device_details")
    assert rtr_utils.resolve_device_id(api, name) == AID
    assert api.calls == [
        ("query_devices_by_filter", {"filter": "hostname:'%s'" % name, "limit": 100, "offset": 0}),
        ("get_device_details", {"ids": [AID]}),
    ]


def test_resolve_name_escapes_quotes(hosts):
    api = hosts("query_by_name_missing")
    with pytest.raises(rtr_utils.RTRError):
        rtr_utils.resolve_device_id(api, "o'b\\x")
    assert api.called("query_devices_by_filter") == [{"filter": "hostname:'o\\'b\\\\x'", "limit": 100, "offset": 0}]


def test_resolve_name_no_match(hosts):
    api = hosts("query_by_name_missing")
    with pytest.raises(rtr_utils.RTRError) as exc:
        rtr_utils.resolve_device_id(api, "host1")
    assert exc.value.message == "No host named 'host1' was found in Falcon."
    assert [call[0] for call in api.calls] == ["query_devices_by_filter"]


def test_resolve_name_prefix_match_is_not_a_match(hosts):
    # The hostname filter matches a prefix (fact 26), so 'host' finds host1.
    api = hosts("query_by_name", "device_details")
    with pytest.raises(rtr_utils.RTRError) as exc:
        rtr_utils.resolve_device_id(api, "host")
    assert exc.value.message == "No host named 'host' was found in Falcon."


def test_resolve_name_two_matches(hosts, fixture):
    """The test tenant has one host with this name; a copy adds a second one."""
    details = copy.deepcopy(fixture("rtr/device_details"))
    second = copy.deepcopy(details["body"]["resources"][0])
    second["device_id"] = "%032d" % 99
    details["body"]["resources"].append(second)
    api = hosts("query_by_name", details)
    with pytest.raises(rtr_utils.RTRError) as exc:
        rtr_utils.resolve_device_id(api, "host1")
    assert exc.value.message == "2 hosts are named 'host1': give the device ID instead."


def query_page(fixture, ids, total):
    """Return a copy of the recorded query with other IDs and another total.

    The test tenant has no host name that matches more than 100 hosts.
    """
    page = copy.deepcopy(fixture("rtr/query_by_name"))
    page["body"]["resources"] = ids
    page["body"]["meta"]["pagination"]["total"] = total
    return page


def details_page(fixture, ids, name="other"):
    """Return a copy of the recorded details with one host for each ID (see query_page)."""
    details = copy.deepcopy(fixture("rtr/device_details"))
    host = details["body"]["resources"][0]
    details["body"]["resources"] = [dict(copy.deepcopy(host), device_id=i, hostname=name) for i in ids]
    return details


def test_resolve_name_reads_all_pages(hosts, fixture):
    first = ["%032d" % n for n in range(100, 200)]
    api = hosts(
        [query_page(fixture, first, 101), "query_by_name"],
        [details_page(fixture, first), "device_details"],
    )
    assert rtr_utils.resolve_device_id(api, "host1") == AID
    assert api.calls == [
        ("query_devices_by_filter", {"filter": "hostname:'host1'", "limit": 100, "offset": 0}),
        ("query_devices_by_filter", {"filter": "hostname:'host1'", "limit": 100, "offset": 100}),
        ("get_device_details", {"ids": first}),
        ("get_device_details", {"ids": [AID]}),
    ]


def test_resolve_name_stops_on_an_empty_page(hosts, fixture):
    api = hosts([query_page(fixture, [AID], 5), query_page(fixture, [], 5)], "device_details")
    assert rtr_utils.resolve_device_id(api, "host1") == AID
    assert [kw.get("offset") for m, kw in api.calls if m == "query_devices_by_filter"] == [0, 1]
    assert api.called("get_device_details") == [{"ids": [AID]}]


def test_resolve_query_error_fails(hosts):
    api = hosts("query_by_name_bad_filter")
    with pytest.raises(rtr_utils.RTRError) as exc:
        rtr_utils.resolve_device_id(api, "host1")
    assert exc.value.message == "Unable to search hosts named 'host1': Invalid filter expression supplied"
    assert exc.value.status_code == 400
    assert [call[0] for call in api.calls] == ["query_devices_by_filter"]


def test_resolve_details_error_fails(hosts):
    api = hosts("query_by_name", "device_details_missing")
    with pytest.raises(rtr_utils.RTRError) as exc:
        rtr_utils.resolve_device_id(api, "host1")
    assert exc.value.message == "Unable to read hosts named 'host1': invalid device id [%032d]" % 12
    assert exc.value.status_code == 400


# Session


def test_init_returns_the_session_id(make):
    t = make(rtr={"init_session": ["init_session"]})
    t.session.session_id = None
    assert t.session.init(AID) == SESSION_ID
    assert (t.session.device_id, t.session.session_id) == (AID, SESSION_ID)
    assert t.rtr.calls == [("init_session", {"device_id": AID, "queue_offline": False})]


def test_init_missing_host_fails(make):
    t = make(rtr={"init_session": ["init_session_missing"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.init("f" * 32)
    assert exc.value.message == "RTR session to %s failed with status 404: device not found" % ("f" * 32)
    assert (exc.value.status_code, exc.value.code) == (404, 40401)


def test_init_rtr_disabled_has_the_policy_hint(make, fixture):
    """A host whose RTR policy is not applied yet (fact 1) cannot be made on demand."""
    response = with_status(fixture("rtr/init_session_missing"), 403, "the response policy for this host has rtr disabled")
    response["body"]["errors"][0]["code"] = 40301
    t = make(rtr={"init_session": [response]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.init(AID)
    assert exc.value.message == (
        "RTR session to %s refused: the response policy for this host has rtr disabled. %s" % (AID, rtr_utils.RTR_DISABLED_HINT)
    )


def test_init_after_rate_limit(make, fixture):
    limited = with_status(fixture("rtr/init_session"), 429, "rate limit", {"X-RateLimit-RetryAfter": "7"})
    t = make(rtr={"init_session": [limited, "init_session"]})
    assert t.session.init(AID) == SESSION_ID
    assert len(t.rtr.called("init_session")) == 2
    assert t.clock.sleeps == [7]


def test_init_rate_limit_past_the_retries_fails(make, fixture):
    limited = with_status(fixture("rtr/init_session"), 429, "rate limit")
    t = make(rtr={"init_session": [limited]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.init(AID)
    assert exc.value.message == "RTR session to %s failed with status 429: rate limit" % AID
    assert len(t.rtr.called("init_session")) == 6
    assert t.clock.sleeps == [5] * 5


@pytest.mark.parametrize(
    "header, now, wait",
    [(None, 0, 5), ("x", 0, 5), ("0", 0, 1), ("12", 0, 12), ("999", 0, 60), ("2000000007", 2000000000, 7)],
)
def test_rate_limit_wait(make, header, now, wait):
    t = make()
    t.clock.now = now
    headers = {"X-RateLimit-RetryAfter": header} if header else {}
    assert t.session._rate_limit_wait({"headers": headers}) == wait


def test_delete_without_session_makes_no_call(make):
    t = make()
    t.session.session_id = None
    t.session.delete()
    assert t.rtr.calls == []


def test_delete_ends_the_session(make):
    t = make(rtr={"delete_session": ["delete_session"]})
    t.session.delete()
    assert t.rtr.calls == [("delete_session", {"session_id": SESSION_ID})]
    assert t.session.session_id is None
    assert t.logs == []


def test_delete_error_is_logged(make, fixture):
    """A failed delete_session cannot be made on demand for a real session."""
    t = make(rtr={"delete_session": [with_status(fixture("rtr/delete_session"), 404, "session not found")]})
    t.session.delete()
    assert t.logs == ["RTR delete_session returned 404: session not found"]
    assert t.session.session_id is None


# Commands


def test_execute_returns_the_cloud_request_id(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"]})
    assert t.session._execute("cd", "cd /") == CRID
    assert t.admin.calls == [("execute_admin_command", execute("cd", "cd /"))]


def test_execute_stray_backtick_fails(make):
    t = make(admin={"execute_admin_command": ["runscript_backtick"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session._execute("runscript", "runscript -Raw=```echo a``` `")
    assert exc.value.message == "RTR runscript failed with status 400: Illegal characters found:   in  "
    assert (exc.value.status_code, exc.value.code) == (400, 40015)


def test_execute_after_rate_limit(make, fixture):
    limited = with_status(fixture("rtr/runscript_submit"), 429, "rate limit", {"X-RateLimit-RetryAfter": "2"})
    t = make(admin={"execute_admin_command": [limited, "runscript_submit"]})
    assert t.session._execute("cd", "cd /") == CRID
    assert t.admin.called("execute_admin_command") == [execute("cd", "cd /")] * 2
    assert t.clock.sleeps == [2]


def test_execute_exception_is_not_retried(make):
    """A connection reset on the submit (as fact 13 on the poll) cannot be made on demand.

    The API can have started the command already, so a submit is not sent again.
    """
    t = make(admin={"execute_admin_command": [Exception("Connection reset by peer"), "runscript_submit"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session._execute("cd", "cd /")
    assert exc.value.message == "RTR cd failed with status 500: Connection reset by peer"
    assert exc.value.status_code == 500
    assert t.admin.called("execute_admin_command") == [execute("cd", "cd /")]
    assert t.clock.sleeps == []


def test_execute_500_is_not_retried(make, fixture):
    t = make(admin={"execute_admin_command": [with_status(fixture("rtr/runscript_submit"), 500, "Connection reset by peer"), "runscript_submit"]})
    with pytest.raises(rtr_utils.RTRError):
        t.session._execute("cd", "cd /")
    assert len(t.admin.called("execute_admin_command")) == 1
    assert t.clock.sleeps == []


def test_read_500_is_retried(make, fixture):
    """FalconPy gives a connection error as a 500 response; a read is safe to send again."""
    t = make(admin={"list_put_files": [with_status(fixture("rtr/list_put_files"), 500, "Connection reset by peer"), "list_put_files"]})
    assert t.session._put_file_ids(NAME) == ["%032d" % 1]
    assert t.admin.called("list_put_files") == [{"filter": "name:'%s'" % NAME}] * 2
    assert t.clock.sleeps == [2]


def test_read_exceptions_past_the_limit_fail(make):
    t = make(admin={"list_put_files": [Exception("Connection reset by peer")]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session._put_file_ids(NAME)
    assert "Connection reset by peer" in exc.value.message
    assert len(t.admin.called("list_put_files")) == 6
    assert t.clock.sleeps == [2] * 5


def test_poll_one_complete_part(make):
    t = make(admin={"check_admin_command_status": [RC3]})
    assert t.session._poll(CRID, TIMEOUT) == ("out\n\n%s3\n" % MARKER, "err\n")
    assert t.admin.calls == [("check_admin_command_status", status(0))]


def test_poll_joins_the_parts(make):
    t = make(admin={"check_admin_command_status": ["parts_waiting", "parts_next", "parts_complete"]})
    assert t.session._poll(CRID, TIMEOUT) == ("first\nsecond\n\n%s0\n" % MARKER, "")
    assert t.admin.called("check_admin_command_status") == [status(0), status(0), status(1)]
    assert t.clock.sleeps == [0.5]


def test_poll_waits_after_rate_limit(make, fixture):
    limited = with_status(fixture("rtr/runscript_complete"), 429, "rate limit", {"X-RateLimit-RetryAfter": "3"})
    t = make(admin={"check_admin_command_status": [limited, RC3]})
    assert t.session._poll(CRID, TIMEOUT)[1] == "err\n"
    assert t.clock.sleeps == [3]


def test_poll_retries_server_errors(make, fixture):
    """A 500 and a connection reset (fact 13) cannot be made on demand."""
    error = with_status(fixture("rtr/runscript_complete"), 500, "server error")
    t = make(admin={"check_admin_command_status": [error, Exception("Connection reset by peer"), RC3]})
    assert t.session._poll(CRID, TIMEOUT)[1] == "err\n"
    assert t.admin.called("check_admin_command_status") == [status(0)] * 3
    assert t.clock.sleeps == [2, 2]


def test_poll_server_errors_past_the_limit_fail(make, fixture):
    error = with_status(fixture("rtr/runscript_complete"), 502, "bad gateway")
    t = make(admin={"check_admin_command_status": [error]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session._poll(CRID, TIMEOUT)
    assert exc.value.message == "RTR status check failed with status 502: bad gateway"
    assert len(t.admin.calls) == 6
    assert t.clock.sleeps == [2] * 5


def test_poll_status_error_fails(make):
    t = make(admin={"check_admin_command_status": ["status_missing"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session._poll(CRID, TIMEOUT)
    assert exc.value.message == "RTR status check failed with status 403: unknown user"
    assert exc.value.status_code == 403
    assert len(t.admin.calls) == 1


def test_poll_timeout(make):
    t = make(admin={"check_admin_command_status": ["parts_waiting"]})
    with pytest.raises(rtr_utils.RTRTimeout) as exc:
        t.session._poll(CRID, 1)
    assert exc.value.message == "RTR command timed out"
    assert exc.value.status_code is None
    assert t.clock.now > 1000 + 1 + rtr_utils.TIMEOUT_GRACE
    assert set(t.clock.sleeps) == {0.5}


def test_run_raw_too_large_makes_no_call(make):
    t = make()
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.run_raw("x" * 32767, TIMEOUT)
    assert exc.value.message == "The RTR script is 32767 bytes; the API limit is 32766 bytes."
    assert t.admin.calls == []


def test_run_raw_sends_the_script(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [RC3]})
    t.session.run_raw("echo a", TIMEOUT)
    assert t.admin.calls == [
        ("execute_admin_command", execute("runscript", plain("echo a"))),
        ("check_admin_command_status", status(0)),
    ]


def test_run_builtin_success(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": ["cd_dir_complete"]})
    assert t.session.run_builtin("cd", "cd " + FIXTURE_DIR, TIMEOUT) == (FIXTURE_DIR + "\n", "")
    assert t.admin.called("execute_admin_command") == [execute("cd", "cd " + FIXTURE_DIR)]


def test_run_builtin_retries_contact_support(make, fixture):
    flaky = with_stderr(fixture("rtr/cd_root_complete"), CONTACT_SUPPORT)
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [flaky, "cd_root_complete"]})
    assert t.session.run_builtin("cd", "cd /", TIMEOUT) == ("", "")
    assert t.admin.called("execute_admin_command") == [execute("cd", "cd /")] * 2
    assert "RTR cd gave a temporary error (attempt 1)" in t.logs


def test_run_builtin_contact_support_past_the_limit_fails(make, fixture):
    flaky = with_stderr(fixture("rtr/cd_root_complete"), CONTACT_SUPPORT)
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [flaky]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.run_builtin("cd", "cd /", TIMEOUT)
    assert exc.value.message == "RTR cd failed: " + CONTACT_SUPPORT.strip()
    assert len(t.admin.called("execute_admin_command")) == 4


def test_run_builtin_other_stderr_fails_at_once(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": ["cd_missing_complete"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.run_builtin("cd", "cd " + MISSING_DIR, TIMEOUT)
    assert exc.value.message == "RTR cd failed: cd: %s: No such file or directory" % MISSING_DIR
    assert len(t.admin.called("execute_admin_command")) == 1


def test_exec_command_returns_rc_and_output(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [RC3]})
    assert t.session.exec_command("echo out", TIMEOUT) == (3, "out\n", "err\n")
    path = "/tmp/.ansible-rtr-%s.sh" % hexid(1)
    body = "(umask 077; printf %%s 'ZWNobyBvdXQ=' | base64 $__b > %s)\n/bin/sh %s" % (path, path)
    script = rtr_utils.wrap_script(body, MARKER, cleanup="rm -f " + path)
    assert t.admin.called("execute_admin_command") == [execute("runscript", plain(script))]


def test_exec_command_rtr_timeout_has_no_rc(make):
    # The recorded -Timeout=2 result on 'sleep 5' (fact 12) has no marker.
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": ["timeout_complete"]})
    assert t.session.exec_command("sleep 5", TIMEOUT) == (255, "", "RTR did not return an exit code. ")


def test_exec_command_too_large_makes_no_call(make):
    t = make()
    cmd = "x" * 24000
    size = len(rtr_utils.build_exec_script(cmd, MARKER))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.exec_command(cmd, TIMEOUT)
    assert exc.value.message == "The command is too large for RTR: %d bytes after encoding, the limit is 32000." % size
    assert exc.value.status_code is None
    assert t.admin.calls == []


# Files


def test_put_inline_success(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [RC0]})
    t.session.put_inline(b"hi", "/tmp/x y", TIMEOUT)
    body = pvar("p", "/tmp/x y") + '\nprintf %s \'aGk=\' | base64 $__b > "$p.rtrtmp" && mv -f "$p.rtrtmp" "$p"'
    assert t.admin.called("execute_admin_command") == [execute("runscript", raw(body))]


def test_put_inline_path_with_a_backtick_is_not_in_the_script(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [RC0]})
    path = "/tmp/a `id` b"
    t.session.put_inline(b"hi", path, TIMEOUT)
    sent = t.admin.called("execute_admin_command")[0]["command_string"]
    assert sent == raw(pvar("p", path) + '\nprintf %s \'aGk=\' | base64 $__b > "$p.rtrtmp" && mv -f "$p.rtrtmp" "$p"')
    assert "`" not in sent.replace("```", "")


def test_put_inline_rc_error(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": [RC3]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.put_inline(b"hi", "/tmp/x", TIMEOUT)
    assert exc.value.message == "Upload to /tmp/x failed (rc 3): err"
    assert exc.value.rc == 3


def putfile_admin(statuses, listed=("list_put_files",)):
    return {
        "create_put_files": ["create_put_files"],
        "list_put_files": list(listed),
        "delete_put_files": ["delete_put_files"],
        "execute_admin_command": ["runscript_submit"],
        "check_admin_command_status": statuses,
    }


def create_call():
    return (
        "create_put_files",
        {
            "files": [("file", (NAME, b"data", "application/octet-stream"))],
            "name": NAME,
            "description": "Ansible crowdstrike.falcon.rtr transfer",
            "comments_for_audit_log": "Ansible crowdstrike.falcon.rtr put_file",
        },
    )


LIST_CALL = ("list_put_files", {"filter": "name:'%s'" % NAME})
DELETE_CALL = ("delete_put_files", {"ids": ["%032d" % 1]})


def cmd(base_command, command_string):
    return [("execute_admin_command", execute(base_command, command_string)), ("check_admin_command_status", status(0))]


def test_upload_into_existing_parent(make):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC0]))
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert t.admin.calls == (
        [create_call(), LIST_CALL]
        + cmd("cd", "cd " + FIXTURE_DIR)
        + cmd("put", "put " + NAME)
        + cmd("cd", "cd /")
        + cmd("runscript", raw(mv_body("%s/%s" % (FIXTURE_DIR, NAME), FIXTURE_DIR + "/mod.py")))
        + [DELETE_CALL]
    )


def test_upload_missing_parent_uses_stage(make):
    t = make(admin=putfile_admin(["cd_missing_complete", RC0, "cd_dir_complete", "put_complete", "cd_root_complete", RC0]))
    t.session.upload_putfile(b"data", MISSING_DIR + "/mod.py", TIMEOUT)
    assert t.admin.calls == (
        [create_call(), LIST_CALL]
        + cmd("cd", "cd " + MISSING_DIR)
        + cmd("runscript", raw("mkdir -m 700 -p " + STAGE))
        + cmd("cd", "cd " + STAGE)
        + cmd("put", "put " + NAME)
        + cmd("cd", "cd /")
        + cmd("runscript", raw(mv_body("%s/%s" % (STAGE, NAME), MISSING_DIR + "/mod.py", " && rmdir " + STAGE)))
        + [DELETE_CALL]
    )


# A macOS host prints "<path> does not exist" for cd to a missing folder (seen
# live on macOS 26). The recorder runs on one Linux test host, so it cannot record it.
MACOS_CD_MISSING = MISSING_DIR + " does not exist\n"


def test_upload_missing_parent_on_macos_uses_stage(make, fixture):
    missing = with_stderr(fixture("rtr/cd_missing_complete"), MACOS_CD_MISSING)
    t = make(admin=putfile_admin([missing, RC0, "cd_dir_complete", "put_complete", "cd_root_complete", RC0]))
    t.session.upload_putfile(b"data", MISSING_DIR + "/mod.py", TIMEOUT)
    assert [kw["command_string"] for kw in t.admin.called("execute_admin_command")] == [
        "cd " + MISSING_DIR,
        raw("mkdir -m 700 -p " + STAGE),
        "cd " + STAGE,
        "put " + NAME,
        "cd /",
        raw(mv_body("%s/%s" % (STAGE, NAME), MISSING_DIR + "/mod.py", " && rmdir " + STAGE)),
    ]


def test_upload_cd_other_does_not_exist_text_raises(make, fixture):
    """A "does not exist" error for another path is not the missing-folder case."""
    other = with_stderr(fixture("rtr/cd_missing_complete"), "/other does not exist\n")
    t = make(admin=putfile_admin([other]))
    with pytest.raises(rtr_utils.RTRError) as err:
        t.session.upload_putfile(b"data", MISSING_DIR + "/mod.py", TIMEOUT)
    assert err.value.message == "RTR cd failed: /other does not exist"


def test_upload_unsafe_parent_uses_stage(make):
    t = make(admin=putfile_admin([RC0, "cd_dir_complete", "put_complete", "cd_root_complete", RC0]))
    t.session.upload_putfile(b"data", "/tmp/a b/mod.py", TIMEOUT)
    assert [kw["command_string"] for kw in t.admin.called("execute_admin_command")] == [
        raw("mkdir -m 700 -p " + STAGE),
        "cd " + STAGE,
        "put " + NAME,
        "cd /",
        raw(mv_body("%s/%s" % (STAGE, NAME), "/tmp/a b/mod.py", " && rmdir " + STAGE)),
    ]


def test_upload_stage_mkdir_fails(make):
    t = make(admin=putfile_admin([RC3, RC0]))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", "/tmp/a b/mod.py", TIMEOUT)
    assert exc.value.message == "Unable to make %s (rc 3): err" % STAGE
    # No cd happened, so no cd /; the put-file and the stage folder are removed.
    assert t.admin.calls == (
        [create_call(), LIST_CALL]
        + cmd("runscript", raw("mkdir -m 700 -p " + STAGE))
        + [DELETE_CALL]
        + cmd("runscript", plain(rm_script(STAGE)))
    )


def test_upload_put_error_cleans_up(make):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_exists_complete", "cd_root_complete", RC0]))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "RTR put failed: put: Destination already exists."
    assert t.admin.calls == (
        [create_call(), LIST_CALL]
        + cmd("cd", "cd " + FIXTURE_DIR)
        + cmd("put", "put " + NAME)
        + cmd("cd", "cd /")
        + [DELETE_CALL]
        + cmd("runscript", plain(rm_script("%s/%s" % (FIXTURE_DIR, NAME))))
    )


def test_upload_cleanup_error_keeps_first_error(make):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_exists_complete", "status_missing"]))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "RTR put failed: put: Destination already exists."
    assert [kw["command_string"] for kw in t.admin.called("execute_admin_command")] == [
        "cd " + FIXTURE_DIR, "put " + NAME, "cd /", "cd /", "cd /", plain(rm_script("%s/%s" % (FIXTURE_DIR, NAME))),
    ]
    assert t.clock.sleeps == [2, 2]
    assert "RTR cd / after a failed put did not work: RTR status check failed with status 403: unknown user" in t.logs
    assert t.logs[-1] == (
        "RTR upload leftover %s/%s was not removed: RTR status check failed with status 403: unknown user" % (FIXTURE_DIR, NAME)
    )
    assert t.warns == []


def test_upload_cd_root_retries(make):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_complete", "status_missing", "cd_root_complete", RC0]))
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert [kw["command_string"] for kw in t.admin.called("execute_admin_command")] == [
        "cd " + FIXTURE_DIR, "put " + NAME, "cd /", "cd /", raw(mv_body("%s/%s" % (FIXTURE_DIR, NAME), FIXTURE_DIR + "/mod.py")),
    ]
    assert t.clock.sleeps == [2]


def test_upload_lists_put_file_again_when_empty(make):
    # The recorded empty list stands for a list that comes right after the create.
    t = make(admin=putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC0],
                                 listed=("list_put_files_missing", "list_put_files")))
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert t.admin.calls[:3] == [create_call(), LIST_CALL, LIST_CALL]
    assert t.admin.called("list_put_files") == [LIST_CALL[1]] * 2
    assert t.admin.called("delete_put_files") == [DELETE_CALL[1]]
    assert t.clock.sleeps == [2]
    assert t.warns == []


def test_upload_put_file_never_listed_warns(make):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC0],
                                 listed=("list_put_files_missing",)))
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    # 1 + 3 retries after the create, then 1 more before the delete.
    assert t.admin.called("list_put_files") == [LIST_CALL[1]] * 5
    assert t.admin.called("delete_put_files") == []
    assert t.clock.sleeps == [2, 2, 2]
    assert t.warns == [
        "RTR put-file %s could not be deleted: no put-file with this name was found; "
        "delete it from the RTR put-files library" % NAME
    ]


def test_upload_move_fails(make):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC3, RC0]))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "Upload to %s/mod.py failed (rc 3): err" % FIXTURE_DIR
    assert exc.value.rc == 3
    assert t.admin.calls[-3:] == [DELETE_CALL] + cmd("runscript", plain(rm_script("%s/%s" % (FIXTURE_DIR, NAME))))


def test_upload_create_500_deletes_a_put_file_that_was_made(make, fixture):
    """A create_put_files that gives a 5xx is not sent again.

    After a 5xx the API can have made the put-file, so the plugin looks for
    the name and deletes what it finds.
    """
    admin = putfile_admin([])
    admin["create_put_files"] = [with_status(fixture("rtr/create_put_files"), 500, "server error")]
    t = make(admin=admin)
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "Unable to create the RTR put-file: server error"
    assert t.admin.calls == [create_call(), LIST_CALL, DELETE_CALL]
    assert t.warns == []


def test_upload_list_error_fails_and_cleans_up(make, fixture):
    """A failed list_put_files cannot be made on demand."""
    t = make(admin=putfile_admin([RC0], listed=(with_status(fixture("rtr/list_put_files"), 500, "server error"),)))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "Unable to list RTR put-files: server error"
    # A list is a read, so each of the two lists is sent 1 + 5 times.
    assert t.admin.calls == [create_call()] + [LIST_CALL] * 12 + cmd(
        "runscript", plain(rm_script("%s/%s" % (FIXTURE_DIR, NAME)))
    )
    assert t.clock.sleeps == [2] * 10
    assert t.warns == [
        "RTR put-file %s could not be deleted: Unable to list RTR put-files: server error; "
        "delete it from the RTR put-files library" % NAME
    ]


def test_upload_delete_error_is_logged(make, fixture):
    """A failed delete_put_files cannot be made on demand."""
    admin = putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC0])
    admin["delete_put_files"] = [with_status(fixture("rtr/delete_put_files"), 500, "server error")]
    t = make(admin=admin)
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert t.warns == [
        "RTR put-file %s could not be deleted: server error; delete it from the RTR put-files library" % NAME
    ]


def test_upload_delete_exception_warns(make):
    """An exception on every delete_put_files call cannot be made on demand."""
    admin = putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC0])
    admin["delete_put_files"] = [Exception("Connection reset by peer")]
    t = make(admin=admin)
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert t.admin.called("delete_put_files") == [DELETE_CALL[1]] * 6
    assert t.warns == [
        "RTR put-file %s could not be deleted: Connection reset by peer; delete it from the RTR put-files library" % NAME
    ]


def test_upload_create_exception_is_not_retried(make):
    """A connection reset on create_put_files cannot be made on demand.

    The API can have made the put-file already, so create is not sent again,
    and the plugin looks for the name and deletes what it finds.
    """
    admin = putfile_admin([])
    admin["create_put_files"] = [Exception("Connection reset by peer")]
    t = make(admin=admin)
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "Unable to create the RTR put-file: Connection reset by peer"
    assert t.admin.calls == [create_call(), LIST_CALL, DELETE_CALL]
    assert t.warns == []


def test_upload_create_500_with_no_put_file_does_not_warn(make):
    admin = putfile_admin([], listed=("list_put_files_missing",))
    admin["create_put_files"] = [Exception("Connection reset by peer")]
    t = make(admin=admin)
    with pytest.raises(rtr_utils.RTRError):
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert t.admin.calls == [create_call(), LIST_CALL]
    assert t.warns == []


def test_upload_create_400_does_not_look_for_the_put_file(make, fixture):
    """The API refused the create, so there is nothing to delete."""
    admin = putfile_admin([])
    admin["create_put_files"] = [with_status(fixture("rtr/create_put_files"), 400, "bad file")]
    t = make(admin=admin)
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message == "Unable to create the RTR put-file: bad file"
    assert t.admin.calls == [create_call()]


def test_upload_lock_folder_is_private(make, tmp_path):
    t = make(admin=putfile_admin(["cd_dir_complete", "put_complete", "cd_root_complete", RC0]))
    t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    folder = tmp_path / ".ansible" / "tmp" / "rtr-locks"
    assert oct(folder.stat().st_mode & 0o777) == "0o700"
    assert oct((folder / (AID + ".lock")).stat().st_mode & 0o777) == "0o600"


def test_upload_lock_error_is_an_rtr_error(make, tmp_path):
    (tmp_path / ".ansible").write_text("not a folder")
    t = make(admin=putfile_admin([RC0]))
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.upload_putfile(b"data", FIXTURE_DIR + "/mod.py", TIMEOUT)
    assert exc.value.message.startswith("Unable to open the RTR lock file in %s: " % (tmp_path / ".ansible" / "tmp" / "rtr-locks"))
    assert [call[0] for call in t.admin.calls] == [
        "create_put_files", "list_put_files", "delete_put_files", "execute_admin_command", "check_admin_command_status",
    ]


SRC = FIXTURE_DIR + "/fetch"
PATH_EXPR = pvar("p", SRC) + '\ntest -f "$p" || exit 1\n'
TMP = "/tmp/.ansible-rtr-" + hexid(1)
SIZE = raw(PATH_EXPR + 'wc -c < "$p"')


def read_cmd(path_expr=PATH_EXPR):
    body = path_expr + "umask 077\nbase64 < \"$p\" > %s.b64 || exit 2\ntr -d '\\n' < %s.b64" % (TMP, TMP)
    return "runscript -Raw=```" + rtr_utils.wrap_script(body, MARKER, cleanup="rm -f %s.b64" % TMP) + "``` -Timeout=%d" % TIMEOUT


def part_cmd(part):
    body = (
        PATH_EXPR
        + "umask 077\n"
        + "dd if=\"$p\" bs=1048576 skip=%d count=1 2>/dev/null > %s.raw || exit 2\n" % (part, TMP)
        + "base64 < %s.raw > %s.b64 || exit 2\n" % (TMP, TMP)
        + "tr -d '\\n' < %s.b64" % TMP
    )
    cleanup = "rm -f %s.raw %s.b64" % (TMP, TMP)
    return "runscript -Raw=```" + rtr_utils.wrap_script(body, MARKER, cleanup=cleanup) + "``` -Timeout=%d" % TIMEOUT


def with_stdout(response, stdout):
    """Return a copy of a recorded runscript result with another stdout.

    A read that ends early with rc 0 cannot be made on demand on the test host.
    """
    response = copy.deepcopy(response)
    response["body"]["resources"][0]["stdout"] = stdout
    return response


def test_fetch_small_file(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", "fetch_read_complete"]})
    assert t.session.fetch(SRC, TIMEOUT) == b"hello"
    assert [kw["command_string"] for kw in t.admin.called("execute_admin_command")] == [SIZE, read_cmd()]


def test_fetch_path_with_a_backtick_is_not_in_the_script(make):
    path = "/tmp/a `id` b"
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", "fetch_read_complete"]})
    assert t.session.fetch(path, TIMEOUT) == b"hello"
    path_expr = pvar("p", path) + '\ntest -f "$p" || exit 1\n'
    sent = [kw["command_string"] for kw in t.admin.called("execute_admin_command")]
    assert sent == [raw(path_expr + 'wc -c < "$p"'), read_cmd(path_expr)]
    assert all("`" not in c.replace("```", "") for c in sent)


def test_fetch_missing_file_has_rc_1(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": ["fetch_missing_complete"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(MISSING_DIR, TIMEOUT)
    assert exc.value.message == "%s is not a file on the host" % MISSING_DIR
    assert exc.value.rc == 1
    assert len(t.admin.called("execute_admin_command")) == 1


def test_fetch_size_parse_error(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"], "check_admin_command_status": ["parts_complete"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(SRC, TIMEOUT)
    assert exc.value.message == "Unable to read the size of %s: second " % SRC
    assert exc.value.rc is None


def test_fetch_read_error(make):
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", RC3]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(SRC, TIMEOUT)
    assert exc.value.message == "Unable to read %s (rc 3): err" % SRC


def test_fetch_reader_failure_is_rc_2(make, fixture):
    """A base64 that fails on the host (rc 2 of the read script) cannot be made on demand."""
    failed = with_stdout(fixture("rtr/runscript_complete"), "\n%s2\n" % MARKER)
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", failed]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(SRC, TIMEOUT)
    assert exc.value.message == "Unable to read %s (rc 2): err" % SRC
    assert exc.value.rc == 2


def test_fetch_short_data_fails(make, fixture):
    short = with_stdout(fixture("rtr/fetch_read_complete"), "aGVs\n%s0\n" % MARKER)
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", short]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(SRC, TIMEOUT)
    assert exc.value.message == "Read 3 bytes of %s, but the file has 5 bytes." % SRC
    assert exc.value.rc is None


def test_fetch_large_file_in_parts(make, monkeypatch):
    # The part reads reuse the recorded base64 read of the same 5 byte file.
    monkeypatch.setattr(rtr_utils, "FETCH_SINGLE_MAX", 2)
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", "fetch_read_complete", "fetch_part1_complete"]})
    assert t.session.fetch(SRC, TIMEOUT) == b"hello"
    assert [kw["command_string"] for kw in t.admin.called("execute_admin_command")] == [SIZE, part_cmd(0), part_cmd(1)]


def test_fetch_parts_short_data_fails(make, monkeypatch):
    # An empty first part (the recorded last part) ends the loop before 5 bytes.
    monkeypatch.setattr(rtr_utils, "FETCH_SINGLE_MAX", 2)
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", "fetch_part1_complete"]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(SRC, TIMEOUT)
    assert exc.value.message == "Read 0 bytes of %s, but the file has 5 bytes." % SRC


def test_fetch_part_error(make, monkeypatch):
    monkeypatch.setattr(rtr_utils, "FETCH_SINGLE_MAX", 2)
    t = make(admin={"execute_admin_command": ["runscript_submit"],
                    "check_admin_command_status": ["fetch_size_complete", RC3]})
    with pytest.raises(rtr_utils.RTRError) as exc:
        t.session.fetch(SRC, TIMEOUT)
    assert exc.value.message == "Unable to read %s (rc 3): err" % SRC
