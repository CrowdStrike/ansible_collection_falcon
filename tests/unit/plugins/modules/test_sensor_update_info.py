# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for the read-only modules that use the SensorUpdatePolicy service."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import (
    kernel_support_info,
    sensor_update_builds_info,
    sensor_update_policy_info,
)


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches a module with recorded responses."""

    def make(module, **responses):
        return falcon_api(
            module,
            {
                method: [fixture("sensor_update_policy/" + case) for case in cases]
                for method, cases in responses.items()
            },
        )

    return make


def test_policy_info_follows_pagination(api, run_module):
    service = api(sensor_update_policy_info, query_combined_policies_v2=["query_page1", "query_page2"])

    result = run_module(sensor_update_policy_info, {"filter": "name:'x'", "sort": "name.asc"})

    assert [p["name"] for p in result["policies"]] == [
        "ansible-unit-fixture-a",
        "ansible-unit-fixture-b",
        "ansible-unit-fixture-c",
    ]
    # The next offset comes from meta.pagination.offset of the previous page.
    assert service.called("query_combined_policies_v2") == [
        {"filter": "name:'x'", "sort": "name.asc", "offset": None, "limit": 5000},
        {"filter": "name:'x'", "sort": "name.asc", "offset": 2, "limit": 5000},
    ]


def test_policy_info_empty_result(api, run_module):
    api(sensor_update_policy_info, query_combined_policies_v2=["query_by_name_missing"])

    result = run_module(sensor_update_policy_info, {"filter": "name:'missing'"})

    assert result["changed"] is False
    assert result["policies"] == []


def test_policy_info_api_error_fails(api, run_module):
    api(sensor_update_policy_info, query_combined_policies_v2=["query_bad_filter"])

    result = run_module(sensor_update_policy_info, {"filter": "name.raw:'"})

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"


def test_builds_info_returns_builds(api, run_module):
    service = api(sensor_update_builds_info, query_combined_builds=["builds_linux"])

    result = run_module(sensor_update_builds_info, {"platform": "linux"})

    assert service.called("query_combined_builds") == [{"platform": "linux", "stage": "prod"}]
    assert result["builds"][0]["build"] == "19403|n-1|tagged|5"
    assert all(" " not in b["sensor_version"] for b in result["builds"])


def test_builds_info_api_error_fails(api, run_module):
    # Any error response has the same shape; the builds API itself returns
    # 200 for a platform it does not know.
    api(sensor_update_builds_info, query_combined_builds=["query_bad_filter"])

    result = run_module(sensor_update_builds_info, {})

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"


def test_kernel_support_info_returns_kernels(api, run_module):
    service = api(kernel_support_info, query_combined_kernels=["kernels_filtered"])

    result = run_module(kernel_support_info, {"filter": "release:'x'"})

    assert service.called("query_combined_kernels") == [
        {"filter": "release:'x'", "offset": None, "limit": 500}
    ]
    assert len(result["info"]) == 1
    assert result["info"][0]["vendor"] == "oracle"


def test_kernel_support_info_api_error_fails(api, run_module):
    api(kernel_support_info, query_combined_kernels=["query_bad_filter"])

    result = run_module(kernel_support_info, {"filter": "release:'"})

    assert result["failed"] is True
    assert result["msg"] == "Invalid filter expression supplied"
