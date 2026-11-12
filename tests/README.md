# Testing the collection

This file is the test standard for this collection. It tells you how the
tests work, how to write new ones, and how to run them. A pull request that
adds or changes a module, lookup or inventory plugin must follow it.

The roles have their own tests (molecule scenarios). They are described at the
end of this file.

## The three layers

| Layer | Where | What it proves | Who runs it |
| --- | --- | --- | --- |
| Sanity | the whole collection | The code imports and compiles on the supported Python versions, the module documentation matches the argument spec, and pylint, pep8 and yamllint pass. | CI on every pull request, and you |
| Unit | `tests/unit` | Each code branch of a plugin does the right thing with real API responses: the calls it makes, the arguments it sends, its result, check mode and idempotence. No API calls are made. | CI on every pull request, and you |
| Integration | `tests/integration` | The plugin works against a live Falcon tenant. | Only you, with your own API credentials |

CI (`.github/workflows/ansible-test.yml`) runs `ansible-test sanity --docker`
and `ansible-test units --docker` when a pull request changes `plugins/` or
`tests/unit/`. It runs them on ansible-core 2.16, 2.18, 2.20, 2.21, 2.22 and
`devel` (`devel` only reports). CI has no Falcon credentials, so it never runs
the integration targets. Run the targets for the plugins that you changed
before you open the pull request, and say in the pull request which ones you
ran.

Other CI workflows run `ansible-lint`, `yamllint`, pylint on `plugins/`, a
Python 2.7 compile check for `falconctl` and `falconctl_info`, and the molecule
scenarios.

## Layout

```text
tests/
  config.yml                       ansible-test configuration
  unit/
    requirements.txt               installed by ansible-test units
    record_fixtures.py             records the fixtures from a real tenant
    plugins/
      conftest.py                  FakeService, falcon_api, fixture, fake_clock
      test_fixtures_clean.py       checks that no fixture has tenant data
      fixtures/<service>/<case>.json
      modules/conftest.py          run_module, fake_sensor
      modules/test_<module>.py
      module_utils/test_<name>.py
      lookup/test_<lookup>.py
      inventory/test_<inventory>.py
  integration/
    run.py                         runs the targets against a live tenant
    targets/<target>/aliases       contains "unsupported"
    targets/<target>/tasks/main.yml
```

The unit test tree mirrors `plugins/`. A plugin in `plugins/modules/foo.py`
has its tests in `tests/unit/plugins/modules/test_foo.py`. Closely related info
modules can share a file (`test_sensor_update_info.py` tests
`sensor_update_policy_info`, `sensor_update_builds_info` and
`kernel_support_info`).

## Unit tests

The unit tests do not call the API. A `FakeService` takes the place of the
FalconPy service class and returns responses that `record_fixtures.py`
recorded from a real tenant and sanitized.

### The fixtures in `conftest.py`

`tests/unit/plugins/conftest.py` is shared by all unit tests.

`fixture(name)` loads a recorded response.
`fixture("host_group/get_one")` reads `fixtures/host_group/get_one.json`.

`falcon_api(plugin, responses, attr="authenticate")` makes a `FakeService`
and patches it into the plugin. It returns the `FakeService`.

- By default it replaces `plugin.authenticate`. All modules and lookups get
  their FalconPy client from `authenticate`, so this is what you use for them.
- If the plugin builds a service class itself, pass that name as `attr`. The
  inventory plugins use `attr="Hosts"` and `attr="Discover"`, and the `auth`
  module uses `attr="OAuth2"`.

`responses` maps a FalconPy method name to a list of responses:

- Each call returns the next response in the list. The last response repeats.
- A call to a method that is not in `responses` raises `AssertionError`
  ("unexpected API call: <name>").
- A response can be a dict (a fixture), `bytes` (returned as is, for a file
  download) or an exception (raised).
- `override()` calls use the key `"override:<METHOD> <route>"`, for example
  `"override:GET /sensors/combined/installers/v2"`.
- `command()` calls use the key `"command:<operation_id>"`, for example
  `"command:ExternalGetDataConnectionToken"`.

The `FakeService` records every call:

- `service.calls` is a list of `(method, kwargs)` tuples in call order.
- `service.called(name)` returns the kwargs of each call to `name`.

`fake_clock(plugin)` replaces the `time` module of a plugin that polls with a
`FakeClock`. `sleep()` does not wait. It moves the clock forward and records
the value in `clock.sleeps`. Use it for every plugin that calls `time.sleep()`
or `time.time()`, so that a test never waits (see `test_ngsiem_search.py` and
`test_ngsiem_data_connection.py`).

### The fixtures in `modules/conftest.py`

These fixtures are available only to the tests in `tests/unit/plugins/modules`.

`run_module(module, args, check_mode=False)` runs `module.main()` with `args`
and returns the module's JSON result as a dict. `check_mode=True` runs the
module in check mode. It resets the global warnings and deprecations before
each test, and it works with ansible-core before and after 2.19. A failed
module returns a result with `failed: true` and `msg`. It does not raise.

`fake_sensor` is for `falconctl` and `falconctl_info`. It patches
`AnsibleModule.run_command` and `get_bin_path` with a `FakeSensor` that keeps
the sensor options in `fake_sensor.options`. `falconctl -s` and `-d` change
them and `falconctl -g` prints them as the real sensor does, so a second run
can check idempotence. `fake_sensor.run(module, args, check_mode=False)` runs
the module and clears `fake_sensor.commands`, which then holds the `-s` and
`-d` commands of that run. Set `fake_sensor.stderr` to make the next `-s` or
`-d` command print an error.

### An example

This is the pattern of `tests/unit/plugins/modules/test_host_group.py`. Copy
it for a new module.

```python
import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import host_group

# The name that record_host_group() used for its throwaway group.
NAME = "ansible-unit-fixture-a"
# The fake ID that the Sanitizer gave that group. It is the first ID that the
# host_group service saw, so it ends in 1.
GROUP_ID = "00000000000000000000000000000001"


@pytest.fixture
def api(falcon_api, fixture):
    """Return a function that patches host_group with recorded responses."""

    def make(**responses):
        return falcon_api(
            host_group,
            {method: [fixture("host_group/" + case) for case in cases] for method, cases in responses.items()},
        )

    return make


def test_present_creates_missing_group(api, run_module):
    # The search finds nothing, so the module must create the group.
    service = api(
        query_combined_host_groups=["query_by_name_missing"],
        create_host_groups=["create_static"],
    )

    result = run_module(host_group, {"name": NAME, "description": "Fixture group"})

    assert result["changed"] is True
    assert result["host_group"]["id"] == GROUP_ID
    # Assert the exact arguments of each call, not only that it was made.
    assert service.called("create_host_groups") == [
        {"name": NAME, "group_type": "static", "description": "Fixture group"}
    ]


def test_present_matching_group_is_not_changed(api, run_module):
    # Idempotence: no create or update response is given, so a write call
    # raises AssertionError in the FakeService.
    service = api(query_combined_host_groups=["query_by_name"])

    result = run_module(host_group, {"name": NAME, "description": "Fixture group"})

    assert result["changed"] is False
    # The module catches exceptions and calls fail_json, so also check the
    # calls. Without this line, an unexpected write could pass the test.
    assert [method for method, _kwargs in service.calls] == ["query_combined_host_groups"]


def test_present_duplicate_name_fails_with_api_message(api, run_module):
    # An API error path: the module must fail with the API's message.
    api(
        query_combined_host_groups=["query_by_name_missing"],
        create_host_groups=["create_duplicate"],
    )

    result = run_module(host_group, {"name": NAME})

    assert result["failed"] is True
    assert result["msg"] == "Duplicate group name ansible-unit-fixture-a."
```

Name each test for the behavior that it checks: `test_<state or action>_<condition>_<result>`.

### Required cases for every module

A new module, or a module that gets a new feature, must have tests for all of
these:

1. **Each code branch.** Every `state`, every option that changes which calls
   are made, every lookup by name and by ID, every "found" and "not found"
   path. Use `pytest.mark.parametrize` for cases that differ only in their
   input.
2. **Argument validation.** Each `fail_json` that the module calls before it
   calls the API, with the message, and `service.calls == []`.
3. **Check mode makes no write calls.** Run with `check_mode=True` and assert
   the exact list of calls (only reads, or none). Also assert `changed`: if
   the module predicts a change in check mode, the prediction must be
   correct.
4. **Idempotence.** Give the responses for an object that already matches the
   arguments, and give no response for any write method. Assert
   `changed is False` and assert the exact list of calls. Do the same for
   `state: absent` on an object that does not exist.
5. **API error paths.** Use the recorded error fixtures (`*_bad_filter`,
   `*_missing`, `*_duplicate` and so on) and assert `failed is True` and the
   `msg` that the user sees.
6. **Exact kwargs.** For every call that the module makes, assert the kwargs
   with `service.called(name) == [...]`. This is what catches a wrong filter,
   a missing escape or a changed limit.

Many modules catch `Exception` and call `fail_json`. Then the `AssertionError`
from an unexpected call becomes a failed result, not a test error. A test that
asserts only `changed` can pass when the module made a call that it must not
make. Always assert `service.calls` (or `service.called(...)`) and, where the
module must succeed, `"failed" not in result`.

When a test pins down behavior that looks wrong but is how the module works
today, start the comment with `current behavior:` and say what happens. This
makes it easy to find these cases later.

### Lookup plugins

Load the lookup with `lookup_loader` and patch it with `falcon_api`. Lookups
use `authenticate`, so the default `attr` is correct. `run_module` is not
available here.

```python
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

from ansible_collections.crowdstrike.falcon.plugins.lookup import host_ids


@pytest.fixture
def lookup(falcon_api, fixture):
    def make(*cases):
        service = falcon_api(
            host_ids,
            {"query_devices_by_filter_scroll": [fixture("hosts/" + case) for case in cases]},
        )
        return lookup_loader.get("crowdstrike.falcon.host_ids"), service

    return make


def test_api_error_raises(lookup):
    plugin, _service = lookup("scroll_bad_filter")

    with pytest.raises(AnsibleError, match="Unable to query hosts: .*Invalid filter expression"):
        plugin.run(["hostname:'"], variables={})
```

Pass the lookup options as keyword arguments to `plugin.run()`, for example
`plugin.run([], variables={}, bulk=True)`. Test pagination (assert the
`offset` of each call), each term, and each error.

### Inventory plugins

The inventory plugins build their service class themselves, so patch that
name with `attr`. Write the inventory source to `tmp_path` and parse it into
an `InventoryData`. See `tests/unit/plugins/inventory/test_falcon_hosts.py`.

```python
@pytest.fixture
def api(falcon_api, fixture):
    def make(scroll=("scroll_page1", "scroll_page2", "scroll_empty")):
        responses = {"query_devices_by_filter_scroll": [fixture("hosts/" + c) for c in scroll]}
        return falcon_api(falcon_hosts, responses, attr="Hosts")

    return make


@pytest.fixture
def parse(tmp_path):
    def run(options=None):
        config = dict(plugin="crowdstrike.falcon.falcon_hosts", client_id="fake-id", client_secret="fake-secret", **(options or {}))
        path = tmp_path / "test.falcon_hosts.yml"
        # JSON is valid YAML.
        path.write_text(json.dumps(config))
        inventory = InventoryData()
        inventory_loader.get("crowdstrike.falcon.falcon_hosts").parse(inventory, DataLoader(), str(path), cache=False)
        return inventory

    return run
```

### Credentials in the environment

The plugins read `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`,
`FALCON_MEMBER_CID` and `FALCON_CLOUD` from the environment. A test that
checks how credentials or the cloud are chosen must remove them first, so that
the values in your shell do not change the result. Use an autouse fixture, as
`test_auth.py`, `test_falcon_hosts.py` and `test_falcon_discover.py` do:

```python
@pytest.fixture(autouse=True)
def _no_env_credentials(monkeypatch):
    for name in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_MEMBER_CID", "FALCON_CLOUD"):
        monkeypatch.delenv(name, raising=False)
```

## Fixtures

### Rules

- Fixtures are recorded from a real tenant with `tests/unit/record_fixtures.py`.
  Do not write a fixture file by hand, and do not edit one.
- Sometimes the tenant cannot give the response that a test needs, for
  example a success for an action on a real host, or a Flight Control parent
  response. Then copy a recorded response in the test with `copy.deepcopy`,
  change only what you need, and say in a docstring why the recorder cannot
  record it. See `action_response()` in `test_host_hide.py` and `page()` in
  `test_fctl_child_cids.py`. Do not save the changed copy as a fixture file.
- Fake values in tests must look like the Sanitizer's values (see below), or
  `test_fixtures_clean.py` and secret scanners can report them.

### File names

A fixture is `tests/unit/plugins/fixtures/<service>/<case>.json`.

- `<service>` is the name of the recorder function without `record_`
  (`host_group`, `hosts`, `intel`, `ngsiem` ...). It is the FalconPy service
  area, not always the module name.
- `<case>` says what the call did and what came back, in snake_case. Reuse the
  names that exist: `create`, `create_duplicate`, `get_one`, `get_missing`,
  `get_after_update`, `query_by_name`, `query_by_name_missing`,
  `query_page1`, `query_page2`, `query_bad_filter`, `update_description`,
  `delete`.

Each file has the keys of the FalconPy response except the headers
(`status_code`, `body`, and for some methods `resources`), and a `method` key
with the FalconPy method name. `FakeService` removes `method` and adds empty
`headers`.

### How the fixtures are protected

`record_fixtures.py` sends every response through the `Sanitizer` before it
writes a file. The Sanitizer replaces:

- 32-character hex IDs with `00000000000000000000000000000001`, `...0002` and so on
- UUIDs with `00000000-0000-0000-0000-000000000001` and so on
- emails with `user1@example.com` and so on
- IP addresses with `192.0.2.x` and `2001:db8::x`, and MAC addresses with `00-00-5e-00-53-xx`
- host names and other host fields with `host1`, `host2` ...
- grouping tags with `tag1`, `tag2` ..., Discover asset IDs with `asset1` ...
- pagination tokens (`offset`, `after`, `next_token`) with `opaque-token-1` ...
- token values with `REDACTED`, and the host part of ingest URLs with `ingest.example.com`

It drops `trace_id` and `powered_by`. The same input always gets the same fake
value, so links between objects stay correct.

Then the script searches each output file for every original value that it
replaced and for the credentials in the environment. If it finds one, it
writes no files at all.

`tests/unit/plugins/test_fixtures_clean.py` runs with the unit tests in CI. It
fails if a fixture has a 32-character hex ID or a UUID that is not a fake one,
an email that is not at `example.com`, a token key with a value that is not
empty or `REDACTED`, an opaque string of 40 or more characters (SHA256 hashes
are allowed), an `api-client-id:<hex>` string, or a `trace_id`.

If a new response has a field with tenant data that the Sanitizer does not
know, add the key to the Sanitizer (`TOKEN_KEYS`, `HOST_KEYS`, `URL_KEYS`,
`OPAQUE_KEYS` or `DROP_KEYS`), or keep only the fields that the plugin needs
with `keep_fields()`, as `record_hosts()` and `record_intel()` do.

### Adding a recorder

When a plugin starts to use a new API call, or you add a plugin for a new
service, add the call to a `record_<service>()` function in
`record_fixtures.py`:

```python
def record_host_group(rec, creds):
    """Record the HostGroup calls used by host_group and host_group_info."""
    from falconpy import HostGroup

    falcon = HostGroup(**creds)
    names = ["%s-%s" % (PREFIX, suffix) for suffix in ("a", "b", "c")]

    def cleanup():
        if rec.dry_run:
            return
        # find the objects named PREFIX-* and delete them

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        created = rec.call(
            "create_static", "create_host_groups", falcon.create_host_groups,
            name=names[0], group_type="static", description="Fixture group",
        )
        # In a dry run there is no real ID, so use a placeholder.
        group_id = (resources(created) or [{"id": "0" * 32}])[0]["id"]
        rec.call("get_one", "get_host_groups", falcon.get_host_groups, ids=[group_id])
        ...
    finally:
        cleanup()
```

- `rec.call(case, method, func, **kwargs)` calls `func(**kwargs)` and saves the
  response as `<case>.json`. `method` is the key that the test gives to
  `falcon_api`: the FalconPy method name that the plugin calls, or
  `"override:<METHOD> <route>"`, or `"command:<operation_id>"`.
- Call the API with the same kwargs that the plugin sends, so the recorded
  response is the one the plugin gets.
- Name every object that the recorder makes `ansible-unit-fixture-*`
  (`PREFIX`). Delete them in `cleanup()`, before the run and in `finally`.
  `--cleanup` calls only `cleanup()`.
- Never change an object that the recorder did not make. For a call that acts
  on hosts, use a device ID that does not exist (`"f" * 32`) and record the
  error. For a search, use a filter that matches nothing, or keep only the
  fields that the plugin needs.
- For a download, wrap the call in `errors_only()`, so that no file content is
  saved.
- Record the error responses too: a bad filter, a missing ID, a duplicate.
- In a dry run, `rec.call()` makes no call and returns an empty response. Do
  not make other API calls when `rec.dry_run` is true.

Add the function to the `SCENARIOS` map at the end of the file, with the
service name as the key.

### Recording and re-recording

```shell
# List the services
uv run tests/unit/record_fixtures.py --list

# Show the calls that a service makes, with no API calls
uv run --with crowdstrike-falconpy --with python-dotenv tests/unit/record_fixtures.py --dry-run host_group

# Record one service
uv run --with crowdstrike-falconpy --with python-dotenv tests/unit/record_fixtures.py host_group

# Delete the ansible-unit-fixture-* objects that an interrupted run left behind
uv run --with crowdstrike-falconpy --with python-dotenv tests/unit/record_fixtures.py --cleanup host_group
```

With no service names, the script records every service. `--env-file PATH`
reads the credentials from another file. `--wait SECONDS` sets how long the
`correlation_rule` recorder waits for new rules to leave their "creating"
status (default 2700).

Each service has its own Sanitizer. A fake ID is the order in which that
service saw the real ID: `...0001` is the first ID that the service saw. If
you add, remove or move a call in a recorder, the fake IDs after it can
change. After you record:

1. Read `git diff tests/unit/plugins/fixtures` and check that no tenant data
   is in it.
2. Run the unit tests.
3. Fix the ID constants in the tests of that service (`GROUP_ID` and so on) if
   they changed.

The script writes files but does not delete them. If you remove a case from a
recorder, delete its fixture file.

## Integration targets

The integration targets run the plugins against a live tenant. Each target is
a directory in `tests/integration/targets`:

```text
tests/integration/targets/<target>/
  aliases            one line: unsupported
  tasks/main.yml
```

`aliases` is `unsupported` so that `ansible-test integration` does not run the
target. `ansible-test` removes the environment variables, so the credentials
would not reach the modules. Use `tests/integration/run.py` instead (see
[Running the tests](#running-the-tests)). It links the checkout into a
temporary `ansible_collections/crowdstrike/falcon` directory and runs each
target's `tasks/main.yml` in its own `ansible-playbook` process, with the
environment kept.

### The header

`tasks/main.yml` starts with a comment that says what the target tests, the
environment variables, the API scopes, and what the target changes in the
tenant:

```yaml
---
# Integration tests for host_group and host_group_info modules
#
# Requirements:
#   FALCON_CLIENT_ID     - API client ID
#   FALCON_CLIENT_SECRET - API client secret
#   FALCON_CLOUD         - Falcon cloud region (optional, defaults to us-1)
#
# API scopes: Host Groups [READ, WRITE]
#
# The test makes its own host groups and deletes them at the end. It never
# adds a real host: host actions use a device ID that does not exist, and the
# dynamic group rule matches a grouping tag that no host has.
```

### The first tasks

Every target checks the credentials first. A target that makes objects
gathers the date and sets a unique prefix:

```yaml
- name: Gather minimal facts for timestamp
  ansible.builtin.setup:
    gather_subset:
      - date_time

- name: Validate required environment variables
  ansible.builtin.assert:
    that:
      - lookup('env', 'FALCON_CLIENT_ID') | length > 0
      - lookup('env', 'FALCON_CLIENT_SECRET') | length > 0
    fail_msg: "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set"

- name: Set test variables
  ansible.builtin.set_fact:
    hg_prefix: "ansible-int-hg-{{ ansible_facts.date_time.iso8601_basic_short | lower }}"
```

Name every object `ansible-int-<target>-<timestamp>` (a short form of the
target name is fine, for example `hg` or `sup`), with a suffix for each
object. The timestamp keeps two runs apart. Use lowercase where the API
filters by lowercase names.

### The lifecycle

A target for a module that changes state runs this lifecycle, in this order,
inside one `block` with an `always` cleanup:

1. CREATE: create the object. Assert `changed` and the returned fields.
2. CREATE again with the same arguments. Assert `not changed` and the same ID.
3. UPDATE: change one or more fields. Assert `changed` and the new values.
4. UPDATE again with the same arguments. Assert `not changed`.
5. CHECK: run a change with `check_mode: true`. Then read the object with the
   `_info` module and assert that nothing changed.
6. DELETE with `state: absent`. Assert `changed`.
7. DELETE again. Assert `not changed`.

Also test the error paths that the API gives: an ID that does not exist, a
bad filter, a value that the API refuses. Use `ignore_errors: true` and then
assert `is failed` and the message.

Verify the real state with the matching `_info` module after each change, not
only the result of the module under test. For example, after a delete, search
for the prefix and assert that nothing is found.

Start each task name with its phase, so the output is easy to read:
`"CREATE | ..."`, `"IDEMPOTENT | ..."`, `"UPDATE | ..."`, `"READ | ..."`,
`"CHECK | ..."`, `"DELETE | ..."`, `"CLEANUP | ..."`.

```yaml
- name: Run host group lifecycle tests
  block:
    - name: "CREATE | Create a static host group"
      crowdstrike.falcon.host_group:
        name: "{{ hg_static_name }}"
        description: "Ansible integration test"
      register: hg_create

    - name: "CREATE | Verify the static group was created"
      ansible.builtin.assert:
        that:
          - hg_create is changed
          - hg_create.host_group.name == hg_static_name
        fail_msg: "Static group creation failed or returned unexpected data"

    # ... the other phases ...

  always:
    - name: "CLEANUP | Find any leftover test groups"
      crowdstrike.falcon.host_group_info:
        filter: "name:*'{{ hg_prefix }}*'"
      register: hg_leftover
      failed_when: false

    - name: "CLEANUP | Delete leftover test groups by ID"
      crowdstrike.falcon.host_group:
        host_group: "{{ item.id }}"
        state: absent
      loop: "{{ hg_leftover.host_groups | default([]) }}"
      loop_control:
        label: "{{ item.name | default(item.id) }}"
      failed_when: false
```

The cleanup finds the objects by the unique prefix of this run and deletes
them by ID. It uses `failed_when: false`, so a cleanup error does not hide the
first failure. Delete in dependency order (for example a policy before the
host group that it uses). If the target writes files, make a temporary
directory with `ansible.builtin.tempfile` (prefix `ansible-int-<target>-`) and
remove it in `always`.

### Rules for targets

- Use the FQCN for every module and lookup: `crowdstrike.falcon.host_group`,
  `ansible.builtin.assert`, `query('crowdstrike.falcon.fctl_child_cids')`.
- Never change or delete an object that the target did not make. Cleanup
  searches only for the prefix of this run.
- Never act on a real host. Use a device ID that does not exist
  (`ffffffffffffffffffffffffffffffff`) and filters that match nothing. A
  dynamic group rule must match a tag that no host has.
- Set `no_log: true` on a task that returns a token, a secret or tenant data,
  and `quiet: true` on an assert that would print it.
- When a plugin cannot be tested without a risk to real data, make a
  read-only target. `hosts_readonly` tests `host_info`, `host_contain`,
  `host_hide`, the `host_ids` and `maintenance_token` lookups, and the
  inventory plugins only with a device ID that does not exist and filters that
  match nothing. It tests the inventory plugins by running `ansible-inventory`
  on a config in a temporary directory.

### Opt-in flags

Some features need a subscription or a type of tenant that not every test
tenant has. Their tests run only when a flag is set:

| Flag | Target | Needs |
| --- | --- | --- |
| `FALCON_TEST_HUNTING=1` | `intel_rules` (the `hunting_rule_download` tests) | Falcon Adversary Intelligence Premium |
| `FALCON_TEST_FLIGHT_CONTROL=1` | `flight_control` | the credentials of a Flight Control parent CID, and no `FALCON_MEMBER_CID` |

A target with a flag prints why it skips, and puts its tests in a block with
the opposite condition:

```yaml
- name: "SKIP | Skip the Flight Control tests"
  ansible.builtin.debug:
    msg: "Set FALCON_TEST_FLIGHT_CONTROL=1 to run the Flight Control tests (needs a parent CID)"
  when: lookup('env', 'FALCON_TEST_FLIGHT_CONTROL') != '1'

- name: Run Flight Control tests
  when: lookup('env', 'FALCON_TEST_FLIGHT_CONTROL') == '1'
  block:
    ...
```

A new flag is named `FALCON_TEST_<FEATURE>=1`. Add it to the header comment of
the target, to the docstring of `run.py` and to the table above.

## Running the tests

### Credentials

The scripts read the credentials from a `.env` file at the collection root, or
from the environment. Variables that are already set in the environment win.
`.env` is in `.gitignore`. Never commit it.

```shell
FALCON_CLIENT_ID=...
FALCON_CLIENT_SECRET=...
# Optional
FALCON_CLOUD=us-1
FALCON_MEMBER_CID=...
```

Both `run.py` and `record_fixtures.py` take `--env-file PATH` to read another
file, for example the credentials of a Flight Control parent CID.

### The collection layout

`ansible-test` needs the checkout in an `ansible_collections/crowdstrike/falcon`
directory:

```shell
mkdir -p ~/src/ansible_collections/crowdstrike
git clone https://github.com/CrowdStrike/ansible_collection_falcon.git ~/src/ansible_collections/crowdstrike/falcon
cd ~/src/ansible_collections/crowdstrike/falcon
```

Run the `ansible-test` commands from that directory. `run.py` and
`record_fixtures.py` make their own layout, so they work from any checkout.

### Sanity tests

Sanity tests need Docker or Podman:

```shell
ansible-test sanity --docker
ansible-test sanity --docker --test validate-modules
```

To use a given ansible-core version with `uv`:

```shell
uv run --with 'ansible-core~=2.16.0' ansible-test sanity --docker
```

CI deletes `.devcontainer/`, `.git*` and `.pre-commit-config.yaml` before it
runs the tests.

### Unit tests

In a container, as CI does. The container installs
`tests/unit/requirements.txt` from PyPI:

```shell
ansible-test units --docker
ansible-test units --docker tests/unit/plugins/modules/test_host_group.py
```

Without a container, with `uv`. Give the same Python version to `uv` and to
`ansible-test`:

```shell
uv run --python 3.13 --with 'ansible-core~=2.20.0' \
    --with pytest --with pytest-xdist --with pytest-mock --with pytest-forked \
    --with crowdstrike-falconpy --with pyyaml \
    ansible-test units --local --python 3.13

# One file
uv run --python 3.13 --with 'ansible-core~=2.20.0' \
    --with pytest --with pytest-xdist --with pytest-mock --with pytest-forked \
    --with crowdstrike-falconpy --with pyyaml \
    ansible-test units --local --python 3.13 tests/unit/plugins/modules/test_host_group.py
```

ansible-core 2.16 needs Python 3.12 or older (`--python 3.12` and
`'ansible-core~=2.16.0'`). `ansible-test` runs the tests in three groups:
`modules`, `module_utils` and `controller` (lookups, inventory plugins and
`test_fixtures_clean.py`). Plain `pytest` does not set up the collection
loader, so the lookup and inventory tests fail with it. Use `ansible-test`.

### Integration tests

`run.py` needs FalconPy and `ansible-playbook` in the Python that runs it,
because the lookups and inventory plugins run in the controller:

```shell
# List the targets
uv run tests/integration/run.py --list

# Run some targets
uv run --with ansible-core --with crowdstrike-falconpy --with python-dotenv \
    tests/integration/run.py host_group sensor_update_policy

# Run all targets
uv run --with ansible-core --with crowdstrike-falconpy --with python-dotenv \
    tests/integration/run.py

# Use other credentials, and pass arguments to ansible-playbook after --
FALCON_TEST_FLIGHT_CONTROL=1 uv run --with ansible-core --with crowdstrike-falconpy --with python-dotenv \
    tests/integration/run.py --env-file .env.flight-control flight_control -- -vvv
```

If the Python that runs `run.py` cannot import FalconPy, `run.py` tries
`.venv/bin/python3` in the collection root. If `ansible-playbook` is not next
to that Python, it uses the one on `PATH`. At the end it prints a summary for
each target, and it exits with 1 if a target failed.

## Role tests

The roles are tested with molecule scenarios in `extensions/molecule`. They
use a systemd container and a stub `falconctl`, so they need no credentials.
See the Testing section of the [top-level README](../README.md#testing) for how
to run them.

## Checklist for a pull request with a new module

- [ ] `tests/unit/plugins/modules/test_<module>.py` with tests for each code
      branch, argument validation, check mode (no write calls), idempotence
      (no write response given), API errors with their `msg`, and the exact
      kwargs of each call.
- [ ] Each test asserts `service.calls` or `service.called(...)`, not only
      `changed`.
- [ ] The fixtures that the tests use are recorded with a `record_<service>()`
      function in `tests/unit/record_fixtures.py`, registered in `SCENARIOS`.
      No fixture file is written or edited by hand.
- [ ] `test_fixtures_clean.py` passes, and `git diff` of the fixtures has no
      tenant data.
- [ ] `tests/integration/targets/<target>/` with `aliases` (`unsupported`) and
      `tasks/main.yml` with the header comment, the credential assert, a
      unique `ansible-int-*` prefix, the full lifecycle in `block`/`always`,
      checks with the `_info` module, and FQCNs.
- [ ] An opt-in flag if the feature needs a special subscription or tenant.
- [ ] `ansible-test sanity --docker` and `ansible-test units` pass.
- [ ] You ran the integration target against a tenant, and the pull request
      says so.
- [ ] `version_added` in the module documentation. The changelog lists new
      modules from it, so a new module needs no fragment. A change to an
      existing module needs a fragment in `changelogs/fragments/`.

A lookup or inventory plugin needs the same, with its unit tests in
`tests/unit/plugins/lookup/` or `tests/unit/plugins/inventory/`, and integration
tests in a target (read-only if it reads hosts).
