# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

import pytest

from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

from ansible_collections.crowdstrike.falcon.plugins.lookup import host_ids

HOSTS = ["%032d" % n for n in (1, 2, 3, 4)]
FQL = "platform_name:'Linux'"


@pytest.fixture
def lookup(falcon_api, fixture):
    """Return a function that loads the lookup with recorded scroll responses."""

    def make(*responses):
        service = falcon_api(
            host_ids,
            {
                "query_devices_by_filter_scroll": [
                    fixture("hosts/" + r) if isinstance(r, str) else r for r in responses
                ]
            },
        )
        return lookup_loader.get("crowdstrike.falcon.host_ids"), service

    return make


def test_scrolls_until_an_empty_page(lookup):
    plugin, service = lookup("scroll_page1", "scroll_page2", "scroll_empty")

    assert plugin.run([FQL], variables={}) == [HOSTS]
    assert service.called("query_devices_by_filter_scroll") == [
        {"filter": FQL, "offset": None, "limit": 5000},
        {"filter": FQL, "offset": "opaque-token-1", "limit": 5000},
        {"filter": FQL, "offset": "opaque-token-2", "limit": 5000},
    ]


def test_stops_when_total_is_reached(lookup, fixture):
    page = copy.deepcopy(fixture("hosts/scroll_page1"))
    page["body"]["meta"]["pagination"]["total"] = 2
    plugin, service = lookup(page)

    assert plugin.run([FQL], variables={}) == [HOSTS[:2]]
    assert len(service.called("query_devices_by_filter_scroll")) == 1


def test_each_term_gives_one_list(lookup):
    plugin, _service = lookup("scroll_empty")

    assert plugin.run(["hostname:'a'", "hostname:'b'"], variables={}) == [[], []]


def test_api_error_raises(lookup):
    plugin, _service = lookup("scroll_bad_filter")

    with pytest.raises(AnsibleError, match="Unable to query hosts: .*Invalid filter expression"):
        plugin.run(["hostname:'"], variables={})
