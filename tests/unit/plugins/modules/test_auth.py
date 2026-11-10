# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import auth

CREDS = {"client_id": "fake-id", "client_secret": "fake-secret"}


@pytest.fixture(autouse=True)
def _no_env_credentials(monkeypatch):
    for name in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_MEMBER_CID", "FALCON_CLOUD"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches the OAuth2 class with recorded responses."""

    def make(**responses):
        return falcon_api(
            auth,
            {method: [fixture("auth/" + case) for case in cases] for method, cases in responses.items()},
            attr="OAuth2",
        )

    return make


def test_generate_returns_token_and_cloud(api, run_module):
    service = api(login=["login"])

    result = run_module(auth, CREDS)

    assert result["changed"] is False
    # The token is the client's token_value, not the one in the response body.
    assert result["auth"] == {"access_token": service.token_value, "cloud": "us-1"}


def test_generate_with_bad_credentials_fails(api, run_module):
    api(login=["login_bad_credentials"])

    result = run_module(auth, CREDS)

    assert result["failed"] is True
    assert result["msg"].startswith("Unauthorized")
    assert result["auth"] == {"access_token": None, "cloud": None}


def test_revoke_logs_in_revokes_and_logs_out(api, run_module):
    service = api(login=["login"], revoke=["revoke"], logout=["logout"])

    result = run_module(auth, dict(CREDS, action="revoke", access_token="token-to-revoke"))

    assert not result.get("failed")
    assert [method for method, _kwargs in service.calls] == ["login", "revoke", "logout"]
    assert service.called("revoke") == [{"token": "token-to-revoke"}]


def test_revoke_requires_access_token(api, run_module):
    service = api()

    result = run_module(auth, dict(CREDS, action="revoke"))

    assert result["failed"] is True
    assert "access_token" in result["msg"]
    assert service.calls == []


def test_missing_client_id_fails(api, run_module):
    api(login=["login"])

    result = run_module(auth, {"client_secret": "fake-secret"})

    assert result["failed"] is True
    assert result["msg"].startswith("Missing required parameter: client_id")


@pytest.mark.xfail(
    strict=True,
    raises=KeyError,
    reason="get_cloud_from_url looks up the base URL in a dict, so an unknown "
    "URL raises KeyError instead of a module failure.",
)
def test_unknown_base_url_fails_with_message(api, run_module):
    service = api(login=["login"])
    service.base_url = "https://api.example.com"

    result = run_module(auth, CREDS)

    assert result["failed"] is True
