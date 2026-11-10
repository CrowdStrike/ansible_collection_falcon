# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

from ansible_collections.crowdstrike.falcon.plugins.modules import fctl_child_cid_info

ROUTE = "override:POST /mssp/entities/children/GET/v2"
CIDS = ["%032d" % n for n in (11, 12)]


def children(fixture, cids):
    """Return a child CID details response.

    The recording tenant is not a Flight Control parent, so only a 403 is
    recorded. This is that response with child CID records.
    """
    response = copy.deepcopy(fixture("flight_control/children_get"))
    response["status_code"] = 200
    response["body"]["errors"] = []
    response["body"]["resources"] = [
        {"child_cid": cid, "name": "child-cid-%d" % n, "status": "active"}
        for n, cid in enumerate(cids, 1)
    ]
    return response


def test_returns_child_cid_details(falcon_api, fixture, run_module):
    service = falcon_api(fctl_child_cid_info, {ROUTE: [children(fixture, CIDS)]})

    result = run_module(fctl_child_cid_info, {"cids": CIDS})

    assert result["changed"] is False
    assert [c["child_cid"] for c in result["child_cids"]] == CIDS
    assert service.called(ROUTE) == [{"body": {"ids": CIDS}}]


def test_missing_scope_fails_with_message(falcon_api, fixture, run_module):
    falcon_api(fctl_child_cid_info, {ROUTE: [fixture("flight_control/children_get")]})

    result = run_module(fctl_child_cid_info, {"cids": CIDS})

    assert result["failed"] is True
    assert result["msg"] == "access denied, scope not permitted"
    assert result["child_cids"] == []
