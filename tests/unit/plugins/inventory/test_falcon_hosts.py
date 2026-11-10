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

from ansible_collections.crowdstrike.falcon.plugins.inventory import falcon_hosts

PLUGIN = "crowdstrike.falcon.falcon_hosts"
HOSTS = ["%032d" % n for n in (1, 2, 3, 4)]
CREDS = {"client_id": "fake-id", "client_secret": "fake-secret"}


@pytest.fixture(autouse=True)
def _no_env_credentials(monkeypatch):
    for name in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_MEMBER_CID", "FALCON_CLOUD"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches the Hosts class with recorded responses."""

    def make(scroll=("scroll_page1", "scroll_page2", "scroll_empty"), details=("details_page1", "details_page2")):
        responses = {"query_devices_by_filter_scroll": [fixture("hosts/" + c) for c in scroll]}
        if details:
            responses["get_device_details"] = [fixture("hosts/" + c) for c in details]
        return falcon_api(falcon_hosts, responses, attr="Hosts")

    return make


@pytest.fixture
def parse(tmp_path):
    """Return a function that parses an inventory source with the given options."""

    def run(options=None, creds=True, cache=True, inventory=None):
        config = dict(plugin=PLUGIN, **(options or {}))
        if creds:
            config.update(CREDS)
        path = tmp_path / "test.falcon_hosts.yml"
        # JSON is valid YAML.
        path.write_text(json.dumps(config))
        plugin = inventory_loader.get(PLUGIN)
        inventory = inventory or InventoryData()
        plugin.parse(inventory, DataLoader(), str(path), cache=cache)
        return inventory, plugin

    return run


def test_adds_hosts_from_all_pages(api, parse):
    service = api()

    inventory, _plugin = parse({"filter": "platform_name:'Linux'"})

    # The fourth host has no hostname, so its external IP is used.
    assert sorted(inventory.hosts) == ["192.0.2.6", "host1", "host2", "host3"]
    assert [c["offset"] for c in service.called("query_devices_by_filter_scroll")] == [
        None, "opaque-token-1", "opaque-token-2",
    ]
    assert service.called("query_devices_by_filter_scroll")[0]["filter"] == "platform_name:'Linux'"
    assert service.called("get_device_details") == [{"ids": HOSTS[:2]}, {"ids": HOSTS[2:]}]


def test_host_variables_are_the_api_fields(api, parse):
    api()

    inventory, _plugin = parse()

    host_vars = inventory.get_host("host1").vars
    assert host_vars["device_id"] == HOSTS[0]
    assert host_vars["platform_name"] == "Linux"
    assert host_vars["local_ip"] == "192.0.2.3"


def test_hostnames_preference(api, parse):
    api()

    inventory, _plugin = parse({"hostnames": ["device_id"]})

    assert sorted(inventory.hosts) == HOSTS


def test_compose_and_groups(api, parse):
    api()

    inventory, _plugin = parse(
        {
            "compose": {"ansible_host": "external_ip"},
            "groups": {"servers": "product_type_desc == 'Server'"},
            "keyed_groups": [{"key": "platform_name", "prefix": "platform"}],
        }
    )

    assert inventory.get_host("host1").vars["ansible_host"] == "192.0.2.2"
    # The fourth record is a Kubernetes cluster, not a server.
    assert sorted(h.name for h in inventory.groups["servers"].get_hosts()) == ["host1", "host2", "host3"]
    assert [h.name for h in inventory.groups["platform_K8S"].get_hosts()] == ["192.0.2.6"]
    assert "platform_Linux" in inventory.groups


def test_no_hosts(api, parse):
    service = api(scroll=("scroll_empty",), details=())

    inventory, _plugin = parse()

    assert inventory.hosts == {}
    assert "get_device_details" not in [m for m, _kwargs in service.calls]


def test_cached_hosts_are_used(api, parse, tmp_path):
    options = {
        "cache": True,
        "cache_plugin": "ansible.builtin.jsonfile",
        "cache_connection": str(tmp_path / "cache"),
    }
    api()
    # A refresh (cache=False) gets the hosts from the API and stores them.
    _inventory, plugin = parse(options, cache=False)
    plugin.update_cache_if_changed()
    service = api(scroll=(), details=())

    inventory, _plugin = parse(options)

    assert sorted(inventory.hosts) == ["192.0.2.6", "host1", "host2", "host3"]
    assert service.calls == []


def test_credentials_from_environment(monkeypatch, api, parse):
    monkeypatch.setenv("FALCON_CLIENT_ID", "env-id")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "env-secret")
    service = api(scroll=("scroll_empty",), details=())
    created = []
    monkeypatch.setattr(falcon_hosts, "Hosts", lambda **kwargs: created.append(kwargs) or service)

    parse(creds=False)

    assert created == [{"client_id": "env-id", "client_secret": "env-secret", "base_url": "us-1"}]


@pytest.mark.xfail(
    strict=True,
    reason="The cloud option has the default 'us-1', so get_option() never "
    "returns an empty value and FALCON_CLOUD is not used.",
)
def test_cloud_from_environment(monkeypatch, api, parse):
    monkeypatch.setenv("FALCON_CLOUD", "eu-1")
    service = api(scroll=("scroll_empty",), details=())
    created = []
    monkeypatch.setattr(falcon_hosts, "Hosts", lambda **kwargs: created.append(kwargs) or service)

    parse()

    assert created[0]["base_url"] == "eu-1"


@pytest.mark.parametrize(
    "options, creds, message",
    [
        ({}, False, "You must provide a client_id and client_secret"),
        ({"cloud": "mars-1"}, True, "Invalid cloud region: 'mars-1'"),
    ],
    ids=["no-credentials", "bad-cloud"],
)
def test_invalid_configuration_raises(api, parse, options, creds, message):
    service = api(scroll=(), details=())

    with pytest.raises(Exception, match=message):
        parse(options, creds=creds)
    assert service.calls == []


def test_api_error_exits(api, parse):
    api(scroll=("scroll_bad_filter",), details=())

    # current behavior: the plugin raises SystemExit, not AnsibleError.
    with pytest.raises(SystemExit, match="Unable to query hosts: .*Invalid filter expression"):
        parse({"filter": "hostname:'"})


@pytest.mark.parametrize(
    "name, valid",
    [("test.falcon_hosts.yml", True), ("test.falcon_hosts.yaml", True), ("test.yml", False)],
)
def test_verify_file(tmp_path, name, valid):
    path = tmp_path / name
    path.write_text("plugin: %s\n" % PLUGIN)

    assert inventory_loader.get(PLUGIN).verify_file(str(path)) is valid
