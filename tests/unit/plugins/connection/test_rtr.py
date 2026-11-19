# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import types

import pytest

from ansible.errors import AnsibleConnectionFailure, AnsibleError, AnsibleFileNotFound
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.crowdstrike.falcon.plugins.connection import rtr as rtr_connection
from ansible_collections.crowdstrike.falcon.plugins.plugin_utils import rtr as rtr_utils

AID = "%032d" % 2
SESSION_ID = "00000000-0000-0000-0000-000000000001"


def load(play_context=None, **options):
    """Load the plugin as Ansible does and set its options."""
    conn = connection_loader.get("crowdstrike.falcon.rtr", play_context or PlayContext(), None)
    conn.set_options(direct=options)
    return conn


class FakeSession(object):
    """A stand-in for RTRSession that records the calls of the Connection."""

    def __init__(self, result=None, error=None):
        self.device_id = AID
        self.calls = []
        self.result = result
        self.error = error

    def _call(self, name, *args):
        self.calls.append((name,) + args)
        if self.error is not None:
            raise self.error
        return self.result

    def exec_command(self, cmd, timeout):
        return self._call("exec_command", cmd, timeout)

    def put_inline(self, data, out_path, timeout):
        return self._call("put_inline", data, out_path, timeout)

    def upload_putfile(self, data, out_path, timeout):
        return self._call("upload_putfile", data, out_path, timeout)

    def fetch(self, in_path, timeout):
        return self._call("fetch", in_path, timeout)

    def delete(self):
        return self._call("delete")


def connected(session, **options):
    conn = load(device_id=AID, **options)
    conn._session = session
    conn._connected = True
    return conn


# Options


def test_options_defaults():
    conn = load()
    assert conn.transport == "crowdstrike.falcon.rtr"
    assert conn.has_pipelining is False
    assert conn.get_option("cloud") == "us-1"
    assert conn.get_option("command_timeout") == 600
    assert conn.get_option("poll_interval") == 0.5
    assert conn.get_option("inline_max_bytes") == 16384
    assert conn.get_option("device_id") is None


def test_options_set_directly():
    conn = load(device_id="host1", cloud="us-2", command_timeout=30, poll_interval=1, inline_max_bytes=100)
    assert [conn.get_option(o) for o in ("device_id", "cloud", "command_timeout", "poll_interval", "inline_max_bytes")] == [
        "host1", "us-2", 30, 1.0, 100,
    ]


@pytest.mark.parametrize("value", [1, 600])
def test_timeout_in_bounds(value):
    assert load(command_timeout=value)._timeout() == value


@pytest.mark.parametrize("value", [0, 601])
def test_timeout_out_of_bounds_fails(value):
    with pytest.raises(AnsibleError, match="^command_timeout must be from 1 to 600, got %d.$" % value):
        load(command_timeout=value)._timeout()


def test_device_value_from_the_option():
    assert load(device_id=" host1 ")._device_value() == "host1"


def test_device_value_falls_back_to_remote_addr():
    context = PlayContext()
    context.remote_addr = AID
    assert load(context)._device_value() == AID


def test_device_value_empty_fails():
    with pytest.raises(AnsibleError, match="^Set ansible_rtr_device_id or ansible_host to the device ID or name of the host.$"):
        load()._device_value()


# _connect


@pytest.fixture
def services(falcon_api, fixture, monkeypatch):
    """Patch authenticate and the FalconPy classes of the connection module.

    falcon_api patches authenticate. The two classes are patched with
    monkeypatch, because the test also asserts the kwargs that build them.
    """

    def make(init="init_session", hosts=None, delete=None):
        responses = {"init_session": [fixture("rtr/" + init)]}
        if delete:
            responses["delete_session"] = [fixture("rtr/" + delete)]
        rtr = falcon_api(rtr_connection, responses)
        holder = types.SimpleNamespace()
        admin = falcon_api(holder, {}, attr="admin")
        host_api = falcon_api(holder, {k: [fixture("rtr/" + v)] for k, v in (hosts or {}).items()}, attr="hosts")
        built = {"admin": [], "hosts": []}
        monkeypatch.setattr(rtr_connection, "check_falconpy", lambda name: built.setdefault("check", name))
        monkeypatch.setattr(
            rtr_connection, "RealTimeResponseAdmin", lambda **kw: built["admin"].append(kw) or admin
        )
        monkeypatch.setattr(rtr_connection, "Hosts", lambda **kw: built["hosts"].append(kw) or host_api)
        return types.SimpleNamespace(rtr=rtr, admin=admin, hosts=host_api, built=built)

    return make


HEX_AID = "abcdef1234567890abcdef1234567890"


def test_connect_with_an_aid_builds_no_hosts_service(services):
    """The fake IDs have no letters, so a hex ID with letters tests the case change."""
    api = services()
    conn = load(device_id=HEX_AID.upper(), poll_interval=2)
    assert conn._connect() is conn
    assert api.built["check"] == "crowdstrike.falcon.rtr"
    assert api.built["hosts"] == []
    assert api.built["admin"] == [{"auth_object": api.rtr.auth_object}]
    assert api.rtr.calls == [("init_session", {"device_id": HEX_AID, "queue_offline": False})]
    assert conn._session.session_id == SESSION_ID
    assert conn._session.poll_interval == 2.0
    assert conn._connected is True


def test_connect_with_a_name_resolves_it(services):
    api = services(hosts={"query_devices_by_filter": "query_by_name", "get_device_details": "device_details"})
    conn = load(device_id="host1")
    conn._connect()
    assert api.built["hosts"] == [{"auth_object": api.rtr.auth_object}]
    assert [call[0] for call in api.hosts.calls] == ["query_devices_by_filter", "get_device_details"]
    assert api.rtr.calls == [("init_session", {"device_id": AID, "queue_offline": False})]


def test_connect_twice_opens_one_session(services):
    api = services()
    conn = load(device_id=AID)
    conn._connect()
    conn._connect()
    assert len(api.rtr.calls) == 1


def test_connect_name_not_found_fails(services):
    api = services(hosts={"query_devices_by_filter": "query_by_name_missing"})
    with pytest.raises(AnsibleConnectionFailure, match="^No host named 'nohost' was found in Falcon.$"):
        load(device_id="nohost")._connect()
    assert api.rtr.calls == []


@pytest.mark.parametrize(
    "options, message",
    [
        ({"command_timeout": 0}, "command_timeout must be from 1 to 600, got 0."),
        ({"command_timeout": 601}, "command_timeout must be from 1 to 600, got 601."),
        ({"poll_interval": 0}, "poll_interval must be more than 0 and at most 60, got 0.0."),
        ({"poll_interval": -1}, "poll_interval must be more than 0 and at most 60, got -1.0."),
        ({"poll_interval": 60.5}, "poll_interval must be more than 0 and at most 60, got 60.5."),
        ({"inline_max_bytes": -1}, "inline_max_bytes must be 0 or more, got -1."),
    ],
)
def test_connect_bad_option_fails_before_any_api_call(services, options, message):
    api = services()
    with pytest.raises(AnsibleError, match="^%s$" % message.replace(".", "\\.")) as exc:
        load(device_id=AID, **options)._connect()
    assert not isinstance(exc.value, AnsibleConnectionFailure)
    assert "check" not in api.built
    assert api.built["admin"] == [] and api.built["hosts"] == []
    assert api.rtr.calls == []


@pytest.mark.parametrize("options", [{"poll_interval": 60}, {"inline_max_bytes": 0}, {"inline_max_bytes": 50000}])
def test_connect_option_bounds_are_accepted(services, options):
    api = services()
    load(device_id=AID, **options)._connect()
    assert api.rtr.calls == [("init_session", {"device_id": AID, "queue_offline": False})]


def test_connect_sets_the_warning_callback(services):
    services()
    conn = load(device_id=AID)
    conn._connect()
    assert conn._session.warn == rtr_connection.display.warning


def test_connect_init_error_fails(services):
    services(init="init_session_missing")
    conn = load(device_id="f" * 32)
    with pytest.raises(AnsibleConnectionFailure, match="failed with status 404: device not found$"):
        conn._connect()
    assert conn._connected is False
    assert conn._session is None


# exec_command


def test_exec_command_returns_bytes():
    session = FakeSession(result=(3, "out\n", "érr\n"))
    conn = connected(session, command_timeout=30)
    assert conn.exec_command("echo out") == (3, b"out\n", "érr\n".encode("utf-8"))
    assert session.calls == [("exec_command", "echo out", 30)]


def test_exec_command_with_in_data_fails():
    session = FakeSession(result=(0, "", ""))
    with pytest.raises(AnsibleError, match="^rtr does not support pipelining$"):
        connected(session).exec_command("cat", in_data=b"x")
    assert session.calls == []


def test_exec_command_size_error_is_an_ansible_error():
    session = FakeSession(error=rtr_utils.RTRError("too large"))
    with pytest.raises(AnsibleError, match="^too large$") as exc:
        connected(session).exec_command("x")
    assert not isinstance(exc.value, AnsibleConnectionFailure)


@pytest.mark.parametrize(
    "error",
    [rtr_utils.RTRError("RTR runscript failed", status_code=400), rtr_utils.RTRTimeout("RTR command timed out")],
)
def test_exec_command_api_error_is_a_connection_failure(error):
    with pytest.raises(AnsibleConnectionFailure, match="^%s$" % error.message):
        connected(FakeSession(error=error)).exec_command("x")


# put_file


@pytest.fixture
def local_file(tmp_path):
    def make(size):
        path = tmp_path / "in.bin"
        path.write_bytes(b"a" * size)
        return str(path)

    return make


def test_put_file_missing_local_file_fails(tmp_path):
    session = FakeSession()
    missing = str(tmp_path / "missing")
    with pytest.raises(AnsibleFileNotFound, match="file or module does not exist: "):
        connected(session).put_file(missing, "/tmp/x")
    assert session.calls == []


@pytest.mark.parametrize("size, method", [(100, "put_inline"), (101, "upload_putfile")])
def test_put_file_uses_inline_up_to_the_limit(local_file, size, method):
    session = FakeSession()
    connected(session, inline_max_bytes=100, command_timeout=40).put_file(local_file(size), "/tmp/x")
    assert session.calls == [(method, b"a" * size, "/tmp/x", 40)]


def test_put_file_inline_limit_is_capped(local_file):
    session = FakeSession()
    connected(session, inline_max_bytes=50000).put_file(local_file(22001), "/tmp/x")
    assert [c[0] for c in session.calls] == ["upload_putfile"]


def test_put_file_rc_error_is_an_ansible_error(local_file):
    with pytest.raises(AnsibleError, match="^Upload failed$") as exc:
        connected(FakeSession(error=rtr_utils.RTRError("Upload failed", rc=1))).put_file(local_file(1), "/tmp/x")
    assert not isinstance(exc.value, AnsibleConnectionFailure)


def test_put_file_transport_error_is_a_connection_failure(local_file):
    with pytest.raises(AnsibleConnectionFailure, match="^RTR put failed$"):
        connected(FakeSession(error=rtr_utils.RTRError("RTR put failed"))).put_file(local_file(1), "/tmp/x")


# fetch_file


def test_fetch_file_writes_the_file(tmp_path):
    session = FakeSession(result=b"hello")
    out = tmp_path / "new" / "out.txt"
    connected(session, command_timeout=50).fetch_file("/tmp/in", str(out))
    assert out.read_bytes() == b"hello"
    assert session.calls == [("fetch", "/tmp/in", 50)]


def test_fetch_file_missing_is_file_not_found(tmp_path):
    error = rtr_utils.RTRError("/tmp/in is not a file on the host", rc=1)
    with pytest.raises(AnsibleFileNotFound, match="/tmp/in is not a file on the host"):
        connected(FakeSession(error=error)).fetch_file("/tmp/in", str(tmp_path / "out"))
    assert not (tmp_path / "out").exists()


def test_fetch_file_rc_error_is_an_ansible_error(tmp_path):
    with pytest.raises(AnsibleError, match="^read failed$") as exc:
        connected(FakeSession(error=rtr_utils.RTRError("read failed", rc=3))).fetch_file("/tmp/in", str(tmp_path / "out"))
    assert not isinstance(exc.value, (AnsibleConnectionFailure, AnsibleFileNotFound))


def test_fetch_file_transport_error_is_a_connection_failure(tmp_path):
    with pytest.raises(AnsibleConnectionFailure, match="^status failed$"):
        connected(FakeSession(error=rtr_utils.RTRError("status failed", status_code=500))).fetch_file("/tmp/in", str(tmp_path / "out"))


# close and reset


def test_close_drops_the_session():
    session = FakeSession()
    conn = connected(session)
    conn.close()
    assert (conn._session, conn._connected) == (None, False)
    assert session.calls == []


def test_reset_opens_and_deletes_the_session(services):
    # Ansible calls close() after each task, so reset starts with no session.
    api = services(delete="delete_session")
    conn = load(device_id=AID)
    conn.reset()
    assert api.rtr.calls == [
        ("init_session", {"device_id": AID, "queue_offline": False}),
        ("delete_session", {"session_id": SESSION_ID}),
    ]
    assert (conn._session, conn._connected) == (None, False)


def test_reset_with_a_session_deletes_it():
    session = FakeSession()
    conn = connected(session)
    conn.reset()
    assert session.calls == [("delete",)]
    assert (conn._session, conn._connected) == (None, False)


def test_reset_delete_error_is_logged(monkeypatch):
    logged = []
    monkeypatch.setattr(rtr_connection.display, "vvv", lambda msg, host=None: logged.append(msg))
    conn = connected(FakeSession(error=RuntimeError("boom")))
    conn.reset()
    assert logged == ["RTR delete_session failed: boom"]
    assert (conn._session, conn._connected) == (None, False)


def test_reset_connect_error_is_logged(services, monkeypatch):
    api = services(init="init_session_missing")
    logged = []
    monkeypatch.setattr(rtr_connection.display, "vvv", lambda msg, host=None: logged.append(msg))
    conn = load(device_id="f" * 32)
    conn.reset()
    assert logged[-1] == "RTR delete_session failed: RTR session to %s failed with status 404: device not found" % ("f" * 32)
    assert [call[0] for call in api.rtr.calls] == ["init_session"]
    assert (conn._session, conn._connected) == (None, False)


def test_reset_without_a_device_does_not_fail(services):
    api = services()
    conn = load()
    conn.reset()
    assert api.rtr.calls == []
    assert conn._connected is False
