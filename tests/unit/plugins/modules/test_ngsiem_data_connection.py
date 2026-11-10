# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import ngsiem_data_connection

NAME = "ansible-unit-fixture-connection"
CONNECTION_ID = "00000000000000000000000000000007"
# The built-in HEC connector, from the module examples.
HEC_CONNECTOR = "a1bfd0c4380f436790cb41afc2b95f38"
TOKEN = "command:ExternalGetDataConnectionToken"
# The arguments that tests/unit/record_fixtures.py used to create the connection.
CREATE = {
    "name": NAME,
    "connector_id": HEC_CONNECTOR,
    "parser": "microsoft-edge",
    "vendor_name": "Ansible",
    "vendor_product_name": "UnitFixture",
}
# The connection as get_connection_by_id returns it.
READABLE = {
    "id": CONNECTION_ID,
    "last_ingested_volume_one_day": "0 B",
    "name": NAME,
    "parser_name": "microsoft-edge",
    "source_type": "Push",
    "status": "Pending",
    "vendor_name": "Ansible",
    "vendor_product_name": "HEC",
}


@pytest.fixture
def clock(fake_clock):
    return fake_clock(ngsiem_data_connection)


@pytest.fixture
def api(falcon_api, fixture, clock):
    """Return a function that patches ngsiem_data_connection with recorded responses.

    The module builds an NGSIEM and an APIHarnessV2 client for the ingest
    token; both come from the same FakeService. The token polling uses a
    FakeClock (the clock fixture).
    """

    def make(**responses):
        return falcon_api(
            ngsiem_data_connection,
            {
                method: [fixture("ngsiem/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def methods(service):
    return [method for method, _kwargs in service.calls]


def warning_text(result):
    # ansible-core 2.19+ returns warnings as dicts, 2.20 nests the text.
    return " ".join(
        w if isinstance(w, str) else w.get("msg", w.get("event", {}).get("msg", ""))
        for w in result.get("warnings", [])
    )


def create_api(api, tokens):
    return api(
        list_data_connections=["connection_list_missing"],
        create_data_connection=["connection_create"],
        get_connection_by_id=["connection_get"],
        **{TOKEN: tokens}
    )


def test_create_waits_for_ingest_token(api, run_module, clock):
    service = create_api(api, ["token_first", "token_ready"])

    result = run_module(ngsiem_data_connection, CREATE)

    assert result["changed"] is True
    assert service.called("list_data_connections") == [{"filter": "name:'%s'" % NAME, "limit": 1}]
    assert service.called("create_data_connection") == [{"body": CREATE}]
    # The first request returns 202 while the connection is provisioned.
    assert service.called(TOKEN) == [{"ids": CONNECTION_ID}, {"ids": CONNECTION_ID}]
    assert clock.sleeps == [5]
    assert result["ingest_token"] == "REDACTED"
    assert result["data_connection"] == dict(
        READABLE, ingest_url="https://ingest.example.com/services/collector"
    )


def test_create_without_wait_warns_that_token_is_not_ready(api, run_module):
    service = create_api(api, ["token_first"])

    result = run_module(ngsiem_data_connection, dict(CREATE, wait_for_ingest_token=False))

    assert result["changed"] is True
    assert "ingest_token" not in result
    assert len(service.called(TOKEN)) == 1
    assert "Ingest token is not ready yet" in warning_text(result)


def test_create_token_wait_times_out_with_warning(api, run_module, clock):
    service = create_api(api, ["token_first"])

    result = run_module(ngsiem_data_connection, dict(CREATE, wait_timeout=10))

    assert result["changed"] is True
    assert "ingest_token" not in result
    assert clock.sleeps == [5, 5]
    assert len(service.called(TOKEN)) == 3
    assert "Timed out after 10s" in warning_text(result)


def test_create_token_already_generated_is_skipped(api, run_module):
    create_api(api, ["token_again"])

    result = run_module(ngsiem_data_connection, CREATE)

    assert result["changed"] is True
    assert "ingest_token" not in result
    assert warning_text(result) == ""


def test_create_without_connector_fails(api, run_module):
    service = api(list_data_connections=["connection_list_missing"])

    result = run_module(ngsiem_data_connection, {"name": NAME, "parser": "microsoft-edge"})

    assert result["failed"] is True
    assert result["msg"] == "Parameter 'connector_id' is required when creating a data connection"
    assert "create_data_connection" not in methods(service)


def test_present_matching_connection_is_not_changed(api, run_module):
    service = api(list_data_connections=["connection_list_by_name"])

    result = run_module(ngsiem_data_connection, CREATE)

    # The HEC connector stores vendor_product_name as 'HEC', so the module
    # does not compare the vendor fields.
    assert result["changed"] is False
    assert result["data_connection"] == READABLE
    assert methods(service) == ["list_data_connections"]


def test_present_changed_name_updates_connection(api, run_module):
    service = api(
        get_connection_by_id=["connection_get"],
        update_data_connection=["connection_update"],
    )

    result = run_module(ngsiem_data_connection, {"connection_id": CONNECTION_ID, "name": NAME + "-renamed"})

    assert result["changed"] is True
    # The API reads the connection ID from 'parameters', not from ids=.
    assert service.called("update_data_connection") == [
        {"parameters": {"ids": CONNECTION_ID}, "body": {"name": NAME + "-renamed"}}
    ]
    assert service.called("get_connection_by_id") == [{"ids": [CONNECTION_ID]}] * 2


def test_present_by_id_that_does_not_exist_fails(api, run_module):
    api(get_connection_by_id=["connection_get_missing"])

    result = run_module(ngsiem_data_connection, {"connection_id": CONNECTION_ID})

    assert result["failed"] is True
    assert result["msg"] == "Data connection with ID '%s' not found" % CONNECTION_ID


@pytest.mark.parametrize(
    "enabled, status, action",
    [
        (False, "connection_status", "Pause"),
        (True, "connection_status_paused", "Resume"),
    ],
    ids=["pause-idle", "resume-paused"],
)
def test_enabled_pauses_or_resumes(api, run_module, enabled, status, action):
    service = api(
        list_data_connections=["connection_list_by_name"],
        get_provisioning_status=[status],
        update_connection_status=["connection_pause" if action == "Pause" else "connection_resume"],
    )

    result = run_module(ngsiem_data_connection, {"name": NAME, "enabled": enabled})

    assert result["changed"] is True
    assert service.called("get_provisioning_status") == [{"ids": CONNECTION_ID}]
    assert service.called("update_connection_status") == [{"ids": CONNECTION_ID, "status": action}]


@pytest.mark.parametrize(
    "enabled, status",
    [
        (False, "connection_status_new"),
        (False, "connection_status_paused"),
        (True, "connection_status"),
    ],
    ids=["pending-cannot-pause", "already-paused", "already-running"],
)
def test_enabled_in_matching_or_wrong_state_is_not_changed(api, run_module, enabled, status):
    service = api(list_data_connections=["connection_list_by_name"], get_provisioning_status=[status])

    result = run_module(ngsiem_data_connection, {"name": NAME, "enabled": enabled})

    assert result["changed"] is False
    assert "update_connection_status" not in methods(service)


def test_absent_deletes_existing_connection(api, run_module):
    service = api(
        list_data_connections=["connection_list_by_name"],
        delete_data_connection=["connection_delete"],
    )

    result = run_module(ngsiem_data_connection, {"name": NAME, "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_data_connection") == [{"ids": CONNECTION_ID}]


def test_absent_missing_connection_is_not_changed(api, run_module):
    service = api(list_data_connections=["connection_list_missing"])

    result = run_module(ngsiem_data_connection, {"name": NAME, "state": "absent"})

    assert result["changed"] is False
    assert "delete_data_connection" not in methods(service)


def test_check_mode_makes_no_api_calls(api, run_module):
    service = api(list_data_connections=["connection_list_missing"])

    result = run_module(ngsiem_data_connection, CREATE, check_mode=True)

    # current behavior: check mode exits before it reads the connection, so
    # it never predicts a change.
    assert result["changed"] is False
    assert service.calls == []


def test_name_or_connection_id_is_required(api, run_module):
    service = api()

    result = run_module(ngsiem_data_connection, {"parser": "microsoft-edge"})

    assert result["failed"] is True
    assert result["msg"] == "Either 'connection_id' or 'name' is required"
    assert service.calls == []
