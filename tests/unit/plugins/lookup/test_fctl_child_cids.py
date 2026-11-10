# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

from ansible_collections.crowdstrike.falcon.plugins.lookup import fctl_child_cids

CIDS = ["%032d" % n for n in (11, 12, 13)]


def page(fixture, cids, offset, total):
    """Return a query_children page.

    The recording tenant is not a Flight Control parent, so only a 403 is
    recorded. This is that response with child CIDs and pagination.
    """
    response = copy.deepcopy(fixture("flight_control/children_page1"))
    response["status_code"] = 200
    response["body"]["errors"] = []
    response["body"]["resources"] = cids
    response["body"]["meta"]["pagination"] = {"offset": offset, "limit": 1000, "total": total}
    return response


@pytest.fixture
def lookup(falcon_api):
    """Return a function that loads the lookup with query_children responses."""

    def make(*responses):
        service = falcon_api(fctl_child_cids, {"query_children": list(responses)})
        return lookup_loader.get("crowdstrike.falcon.fctl_child_cids"), service

    return make


def test_no_terms_returns_all_children(lookup, fixture):
    plugin, service = lookup(page(fixture, CIDS[:2], 2, 3), page(fixture, CIDS[2:], 3, 3))

    assert plugin.run([], variables={}) == CIDS
    assert service.called("query_children") == [
        {"filter": None, "offset": None, "limit": 1000},
        {"filter": None, "offset": 2, "limit": 1000},
    ]


def test_each_term_is_a_cid_filter(lookup, fixture):
    plugin, service = lookup(page(fixture, CIDS[:1], 1, 1), page(fixture, CIDS[1:2], 1, 1))

    assert plugin.run(CIDS[:2], variables={}) == [CIDS[:1], CIDS[1:2]]
    assert [c["filter"] for c in service.called("query_children")] == ["cid:'%s'" % c for c in CIDS[:2]]


def test_no_children(lookup, fixture):
    plugin, _service = lookup(page(fixture, [], 0, 0))

    assert plugin.run([], variables={}) == []


def test_missing_scope_raises(lookup, fixture):
    plugin, _service = lookup(fixture("flight_control/children_page1"))

    with pytest.raises(AnsibleError, match="Unable to query children: .*scope not permitted"):
        plugin.run([], variables={})
