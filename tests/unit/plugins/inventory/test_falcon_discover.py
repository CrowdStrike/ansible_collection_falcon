# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

import pytest

from ansible.inventory.data import InventoryData
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.loader import inventory_loader

from ansible_collections.crowdstrike.falcon.plugins.inventory import falcon_discover

PLUGIN = "crowdstrike.falcon.falcon_discover"
CID = "%032d" % 1
ASSETS = ["%s_asset%d" % (CID, n) for n in (1, 2, 3, 4)]
CREDS = {"client_id": "fake-id", "client_secret": "fake-secret"}


@pytest.fixture(autouse=True)
def _no_env_credentials(monkeypatch):
    for name in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_MEMBER_CID", "FALCON_CLOUD"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches the Discover class with recorded responses."""

    def make(query=("query_page1", "query_page2", "query_empty"), hosts=("hosts_page1", "hosts_page2")):
        responses = {"query_hosts": [fixture("discover/" + c) for c in query]}
        if hosts:
            responses["get_hosts"] = [fixture("discover/" + c) for c in hosts]
        return falcon_api(falcon_discover, responses, attr="Discover")

    return make


@pytest.fixture
def parse(tmp_path):
    """Return a function that parses an inventory source with the given options."""

    def run(options=None, creds=True):
        config = dict(plugin=PLUGIN, **(options or {}))
        if creds:
            config.update(CREDS)
        path = tmp_path / "test.falcon_discover.yml"
        # JSON is valid YAML.
        path.write_text(json.dumps(config))
        inventory = InventoryData()
        inventory_loader.get(PLUGIN).parse(inventory, DataLoader(), str(path), cache=False)
        return inventory

    return run


def test_adds_hosts_from_all_pages(api, parse):
    service = api()

    inventory = parse({"filter": "platform_name:'Linux'"})

    assert sorted(inventory.hosts) == ["host1", "host2", "host3", "host4"]
    # The next offset is the current offset plus the page size of 100.
    assert [c["offset"] for c in service.called("query_hosts")] == [None, 100, 102]
    assert service.called("query_hosts")[0] == {"filter": "platform_name:'Linux'", "offset": None, "limit": 100}
    assert service.called("get_hosts") == [{"ids": ASSETS[:2]}, {"ids": ASSETS[2:]}]


def test_ansible_host_is_the_external_ip(api, parse):
    api()

    inventory = parse()

    host_vars = inventory.get_host("host1").vars
    assert host_vars["ansible_host"] == "192.0.2.2"
    assert host_vars["current_local_ip"] == "192.0.2.3"
    assert host_vars["id"] == ASSETS[0]


def test_only_known_fields_become_host_variables(api, parse):
    api()

    inventory = parse()

    # product_type_desc is in the API response but not in the plugin's list.
    assert "product_type_desc" not in inventory.get_host("host1").vars
    assert inventory.get_host("host3").vars["tags"] == ["SensorGroupingTags/tag1"]


@pytest.mark.parametrize("allow_duplicates, expected", [(False, 2), (True, 4)])
def test_duplicate_hostnames(api, parse, allow_duplicates, expected):
    # get_hosts returns the same two hosts for both pages.
    api(hosts=("hosts_page1",))

    inventory = parse({"allow_duplicates": allow_duplicates})

    assert len(inventory.hosts) == expected
    if allow_duplicates:
        assert "host1_%s" % ASSETS[0] in inventory.hosts


def test_keyed_groups(api, parse):
    api()

    inventory = parse({"keyed_groups": [{"key": "platform_name", "prefix": "platform"}]})

    assert len(inventory.groups["platform_Linux"].get_hosts()) == 4


def test_no_hosts(api, parse):
    service = api(query=("query_empty",), hosts=())

    inventory = parse()

    assert inventory.hosts == {}
    assert "get_hosts" not in [m for m, _kwargs in service.calls]


def test_missing_credentials_raise(api, parse):
    service = api(query=(), hosts=())

    with pytest.raises(Exception, match="You must provide a client_id and client_secret"):
        parse(creds=False)
    assert service.calls == []


def test_api_error_exits(api, parse):
    api(query=("query_bad_filter",), hosts=())

    # current behavior: the plugin raises SystemExit, not AnsibleError.
    with pytest.raises(SystemExit, match="Unable to query hosts: .*cannot be parsed"):
        parse({"filter": "hostname:'"})


@pytest.mark.parametrize(
    "name, valid",
    [("test.falcon_discover.yml", True), ("test.falcon_discover.yaml", True), ("test.yml", False)],
)
def test_verify_file(tmp_path, name, valid):
    path = tmp_path / name
    path.write_text("plugin: %s\n" % PLUGIN)

    assert inventory_loader.get(PLUGIN).verify_file(str(path)) is valid
