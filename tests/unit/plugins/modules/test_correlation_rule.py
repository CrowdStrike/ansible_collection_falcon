# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import correlation_rule

NAME = "ansible-unit-fixture-a"
RULE_ID = "00000000000000000000000000000002"
CUSTOMER_ID = "00000000000000000000000000000001"
SEARCH = {"filter": "#event_simpleName=ProcessRollup2", "lookback": "5m", "outcome": "detection"}
OPERATION = {"schedule": {"definition": "*/5 * * * *"}}
# The arguments that match the recorded rule.
MATCHING = {
    "name": NAME,
    "description": "Fixture rule",
    "severity": 30,
    "status": "inactive",
    "search": SEARCH,
    "operation": OPERATION,
}


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches correlation_rule with recorded responses.

    The module builds a CorrelationRules and a SensorDownload client; both
    come from the same FakeService.
    """

    def make(**responses):
        responses.setdefault("get_sensor_installer_ccid", ["ccid"])
        return falcon_api(
            correlation_rule,
            {
                method: [fixture("correlation_rule/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def methods(service):
    return [method for method, _kwargs in service.calls]


def test_present_creates_missing_rule(api, run_module):
    service = api(get_rules_combined=["query_by_name_missing"], create_rule=["create"])

    result = run_module(correlation_rule, MATCHING)

    assert result["changed"] is True
    assert result["correlation_rule"]["rule_id"] == RULE_ID
    assert service.called("get_rules_combined") == [{"filter": "name:'%s'" % NAME, "limit": 1}]
    # The customer ID is the CCID without its checksum, in lowercase.
    assert service.called("create_rule") == [dict(MATCHING, customer_id=CUSTOMER_ID)]


def test_present_matching_rule_is_not_changed(api, run_module):
    # The API adds search keys such as execution_mode; only the keys in the
    # task are compared.
    service = api(get_rules_combined=["query_by_name"])

    result = run_module(correlation_rule, MATCHING)

    assert result["changed"] is False
    assert methods(service) == ["get_sensor_installer_ccid", "get_rules_combined"]


def test_present_rule_in_transition_is_not_updated(api, run_module):
    # The API refuses updates while a rule is 'creating', so the module
    # leaves it alone even when the task asks for a change.
    service = api(get_rules_combined=["query_by_name_creating"])

    result = run_module(correlation_rule, dict(MATCHING, description="changed"))

    assert result["changed"] is False
    assert "update_rule" not in methods(service)


def test_present_updates_changed_description(api, run_module):
    service = api(
        get_rules_combined=["query_by_name"],
        update_rule=["update_description"],
        get_rules=["get_after_update"],
    )

    result = run_module(correlation_rule, {"name": NAME, "description": "Fixture rule, updated"})

    assert result["changed"] is True
    assert result["correlation_rule"]["description"] == "Fixture rule, updated"
    assert service.called("update_rule") == [
        {"id": RULE_ID, "customer_id": CUSTOMER_ID, "name": NAME, "description": "Fixture rule, updated"}
    ]


@pytest.mark.xfail(
    strict=True,
    reason="update_rule publishes the new version, so publish_rule_version "
    "returns 409 'version is already published' and the module fails.",
)
def test_present_update_with_publish_does_not_fail(api, run_module):
    api(
        get_rules_combined=["query_by_name"],
        update_rule=["update_description"],
        get_rules=["get_after_update"],
        get_latest_rule_versions=["latest_versions_after_update"],
        publish_rule_version=["publish"],
    )

    result = run_module(
        correlation_rule, {"name": NAME, "description": "Fixture rule, updated", "publish": True}
    )

    assert not result.get("failed"), result.get("msg")
    assert result["changed"] is True


def test_present_by_id_that_does_not_exist_fails(api, run_module):
    api(get_rules=["get_missing"])

    result = run_module(correlation_rule, {"rule_id": RULE_ID})

    assert result["failed"] is True
    assert result["msg"] == "Correlation rule with ID '%s' not found" % RULE_ID


def test_customer_id_lookup_failure_fails(api, run_module):
    api(get_sensor_installer_ccid=["query_bad_filter"])

    result = run_module(correlation_rule, MATCHING)

    assert result["failed"] is True
    assert result["msg"] == "Failed to resolve customer ID (CID) from API"


def test_absent_deletes_existing_rule(api, run_module):
    service = api(get_rules_combined=["query_by_name"], delete_rules=["delete"])

    result = run_module(correlation_rule, {"name": NAME, "state": "absent"})

    assert result["changed"] is True
    assert service.called("delete_rules") == [{"ids": [RULE_ID]}]
    # Deleting does not need the customer ID.
    assert "get_sensor_installer_ccid" not in methods(service)


def test_absent_rule_in_transition_fails_with_api_message(api, run_module):
    api(get_rules_combined=["query_by_name_creating"], delete_rules=["delete_in_transition"])

    result = run_module(correlation_rule, {"name": NAME, "state": "absent"})

    assert result["failed"] is True
    assert result["msg"] == "cannot delete unpublished version while rule is in transition state"


def test_absent_missing_rule_is_not_changed(api, run_module):
    service = api(get_rules_combined=["query_by_name_missing"])

    result = run_module(correlation_rule, {"name": NAME, "state": "absent"})

    assert result["changed"] is False
    assert "delete_rules" not in methods(service)


def test_check_mode_makes_no_api_calls(api, run_module):
    service = api(get_rules_combined=["query_by_name_missing"])

    result = run_module(correlation_rule, MATCHING, check_mode=True)

    # current behavior: check mode exits before it reads the rule, so it
    # never predicts a change.
    assert result["changed"] is False
    assert service.calls == []


@pytest.mark.parametrize("state", ["present", "absent"])
def test_name_or_rule_id_is_required(api, run_module, state):
    service = api()

    result = run_module(correlation_rule, {"state": state})

    assert result["failed"] is True
    assert "Either" in result["msg"]
    assert service.calls == []
