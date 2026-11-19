# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# 'uv run' reads this block and installs the dependencies (PEP 723).
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "crowdstrike-falconpy>=1.6.3",
#     "python-dotenv",
# ]
# ///

"""Record Falcon API responses as sanitized unit test fixtures.

The unit tests in tests/unit/plugins do not call the API. They replay the
responses that this script records from a real tenant. Run it again when a
plugin starts to use a new API call, or when FalconPy or the API changes.

The script calls FalconPy directly. For the services that can change state it
makes throwaway objects named 'ansible-unit-fixture-*' and deletes them when it
is done. It does not change hosts or other objects that it did not make.

The one exception is alert_write: the API cannot create alerts, so it changes
the two test alerts that FALCON_TEST_ALERT_IDS names (comma-separated
composite IDs, the same variable as the alert integration target) and puts
them back at the end. Each recording adds one comment, which cannot be removed.

Every response goes through the Sanitizer before it is written: IDs, emails,
IP and MAC addresses, host names and tokens are replaced. Then the script
checks that no credential and no original ID is left in the output. If one is
found, it writes no files.

Credentials are read from a .env file (via python-dotenv) or from the process
environment. Required: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET. Optional:
FALCON_CLOUD and FALCON_MEMBER_CID.

Each service is sanitized on its own, so a fake ID such as
'00000000000000000000000000000001' is the first ID that its service saw. The
tests use these fake IDs, so check the tests of a service after you record it
again.

--only writes only the named cases and keeps the other files of the service.
It still makes every call of the service, so the Sanitizer sees the real IDs
in the same order and gives the same fake IDs. Before it writes, it compares
the fake values of each case that it does not write with the file of that
case. If an object has another fake ID than in its file (two objects that
the service saw first in one list changed places, for example), it writes no
files: then record the whole service. A list of objects with a unique name
and platform can come back in another order; that is not a difference.

'uv run' reads the script metadata at the top of this file and installs
FalconPy and python-dotenv in a temporary environment.

Usage:
    uv run tests/unit/record_fixtures.py [--env-file PATH] [--dry-run] [SERVICE ...]
    uv run tests/unit/record_fixtures.py [--env-file PATH] SERVICE --only CASE [CASE ...]
    uv run tests/unit/record_fixtures.py [--env-file PATH] --only SERVICE:CASE [SERVICE:CASE ...]
    uv run tests/unit/record_fixtures.py --list

--dry-run SERVICE lists the cases of a service. --cleanup deletes the fixture
objects that an interrupted run left behind.
"""

import argparse
import base64
import contextlib
import functools
import io
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

UNIT_DIR = Path(__file__).resolve().parent
COLLECTION_ROOT = UNIT_DIR.parent.parent
FIXTURES_DIR = UNIT_DIR / "plugins" / "fixtures"

REQUIRED_ENV = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")
# Values that must never appear in a fixture.
SECRET_ENV = ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_MEMBER_CID", "FALCON_CID")

PREFIX = "ansible-unit-fixture"
# The cases that case_info reads. The API cannot delete a case, so the
# recorder reads these existing test cases and creates none.
CASE_PREFIX = "ansible-dev-case-"

HEX32_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
UUID_RE = re.compile(
    r"(?<![0-9a-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
GROUPING_TAG_RE = re.compile(r"((?:Sensor|Falcon)GroupingTags/)[^,\"'\s]+")
# A Discover asset ID is '<cid>_<opaque ID>'. This matches after the CID is faked.
ASSET_ID_RE = re.compile(r"(?<=\d{32}_)[A-Za-z0-9_-]{20,}")
# 'api-client-id:<32 hex>' looks like an API client ID to secret scanners,
# also with a fake ID, so the fake ID is written as a name.
CLIENT_ID_RE = re.compile(r"api-client-id:0{24}(\d{8})")

TOKEN_KEYS = {
    "access_token",
    "refresh_token",
    "token",
    "uninstall_token",
    "ingest_token",
    "provisioning_token",
    "api_key",
    "client_secret",
}
HOST_KEYS = {
    "hostname",
    "computer_name",
    "machine_domain",
    "fqdn",
    "site_name",
    "ou",
    "serial_number",
    "instance_id",
    "service_provider_account_id",
    "pod_name",
    "pod_namespace",
    "pod_hostname",
}
URL_KEYS = {"ingest_url"}
# Opaque pagination tokens. A scroll offset encodes a device ID.
OPAQUE_KEYS = {"offset", "after", "next_token"}
DROP_KEYS = {"trace_id", "powered_by"}
# The values that the Sanitizer makes. --only compares them across runs.
FAKE_VALUE_RE = re.compile(
    r"0{24}\d{8}|00000000-0000-0000-0000-\d{12}|user\d+@example\.com|192\.0\.2\.\d+|2001:db8::[0-9a-f]+"
    r"|00-00-5e-00-53-[0-9a-f]{2}|opaque-token-\d+|\b(?:host|tag|asset)\d+\b"
)


def is_fake_hex32(value):
    """Return True for an ID that the Sanitizer made."""
    return value.isdigit() and int(value) < 10**8


def is_fake_uuid(value):
    """Return True for a UUID that the Sanitizer made."""
    return value.startswith("00000000-0000-0000-0000-")


class Sanitizer:
    """Replace tenant data in API responses with stable fake values.

    The same input value always gets the same fake value, also across
    fixture files, so the links between objects (a group ID in a host, for
    example) stay correct.
    """

    def __init__(self):
        self.maps = {
            "hex": {}, "uuid": {}, "email": {}, "host": {}, "ip": {}, "mac": {}, "tag": {},
            "asset": {}, "opaque": {},
        }

    def _fake(self, kind, value, make):
        table = self.maps[kind]
        key = value.lower()
        if key not in table:
            table[key] = make(len(table) + 1)
        return table[key]

    def _string(self, value):
        value = HEX32_RE.sub(
            lambda m: m.group(0)
            if is_fake_hex32(m.group(0))
            else self._fake("hex", m.group(0), lambda n: "%032d" % n),
            value,
        )
        value = UUID_RE.sub(
            lambda m: m.group(0)
            if is_fake_uuid(m.group(0))
            else self._fake("uuid", m.group(0), lambda n: "00000000-0000-0000-0000-%012d" % n),
            value,
        )
        value = EMAIL_RE.sub(
            lambda m: m.group(0)
            if m.group(0).endswith("@example.com")
            else self._fake("email", m.group(0), lambda n: "user%d@example.com" % n),
            value,
        )
        value = CLIENT_ID_RE.sub(lambda m: "api-client-id:fixture-client-%d" % int(m.group(1)), value)
        value = ASSET_ID_RE.sub(
            lambda m: self._fake("asset", m.group(0), lambda n: "asset%d" % n),
            value,
        )
        return GROUPING_TAG_RE.sub(
            lambda m: m.group(1) + self._fake("tag", m.group(0), lambda n: "tag%d" % n),
            value,
        )

    def _ip(self, value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return self._string(value)
        if address.version == 4:
            return self._fake("ip", value, lambda n: "192.0.2.%d" % (n % 254 + 1))
        return self._fake("ip", value, lambda n: "2001:db8::%x" % n)

    def _by_key(self, key, value):
        """Sanitize a string value with rules that depend on its key."""
        key = key.lower()
        if key in TOKEN_KEYS:
            return "REDACTED" if value else value
        if key in OPAQUE_KEYS and value:
            return self._fake("opaque", value, lambda n: "opaque-token-%d" % n)
        if key in URL_KEYS and value:
            # The host name can identify the tenant; keep only the path.
            return "https://ingest.example.com/" + value.split("://", 1)[-1].partition("/")[2]
        if key in HOST_KEYS:
            return self._fake("host", value, lambda n: "host%d" % n) if value else value
        if "mac_address" in key:
            return self._fake("mac", value, lambda n: "00-00-5e-00-53-%02x" % (n % 256))
        if key.endswith("_ip") or key.endswith("ip_address") or key.endswith("ip_addresses") or key == "ip":
            return self._ip(value)
        return self._string(value)

    def clean(self, data, key=""):
        """Return a sanitized copy of data."""
        if isinstance(data, dict):
            return {
                k: self.clean(v, k) for k, v in data.items() if k not in DROP_KEYS
            }
        if isinstance(data, list):
            return [self.clean(v, key) for v in data]
        if isinstance(data, str):
            return self._by_key(key, data)
        return data

    def leaks(self, text, secrets):
        """Return a description of each original value found in text."""
        lowered = text.lower()
        found = ["env:%s" % name for name, value in secrets.items() if value.lower() in lowered]
        for kind, table in self.maps.items():
            # Short host names such as 'ou' values can also be normal words.
            found += [
                "%s value #%d" % (kind, i)
                for i, original in enumerate(table, 1)
                if len(original) >= 6 and original in lowered
            ]
        return found


class Recorder:
    """Collect sanitized responses for one service."""

    def __init__(self, service, sanitizer, dry_run, wait=2700, cleanup_only=False):
        self.service = service
        self.sanitizer = sanitizer
        self.dry_run = dry_run
        self.wait = wait
        self.cleanup_only = cleanup_only
        # Only the rtr service uses it: the AID of a test host that the user owns.
        self.rtr_device_id = None
        self.files = {}
        # The case names in call order, also in a dry run.
        self.cases = []

    def save(self, case, method, response):
        """Sanitize a FalconPy response and keep it as fixtures/<service>/<case>.json."""
        print("  %s/%s <- %s (HTTP %s)" % (self.service, case, method, response.get("status_code")))
        # Keep every key except the headers. Most methods return their data in
        # 'body', but some (start_search) return a top-level 'resources'.
        data = {"method": method}
        data.update((k, v) for k, v in response.items() if k != "headers")
        self.files[case] = self.sanitizer.clean(data)
        return response

    def call(self, case, method, func, **kwargs):
        """Call func(**kwargs), save the response as case, and return it."""
        self.cases.append(case)
        if self.dry_run:
            print("  %s/%s <- %s(%s)" % (self.service, case, method, ", ".join(sorted(kwargs))))
            return {"status_code": 0, "body": {"resources": [], "errors": []}}
        return self.save(case, method, func(**kwargs))


def resources(response):
    """Return the resources list of a response, or an empty list."""
    return (response.get("body") or {}).get("resources") or []


def record_host_group(rec, creds):
    """Record the HostGroup calls used by host_group and host_group_info."""
    from falconpy import HostGroup

    falcon = HostGroup(**creds)
    names = ["%s-%s" % (PREFIX, suffix) for suffix in ("a", "b", "c")]
    name_filter = "name:[%s]" % ",".join("'%s'" % name for name in names)
    rule = "tags:'SensorGroupingTags/%s'" % PREFIX

    def cleanup():
        if rec.dry_run:
            return
        ids = [g["id"] for g in resources(falcon.query_combined_host_groups(filter=name_filter))]
        ids += [g["id"] for g in resources(falcon.query_combined_host_groups(filter="name:'%s-dynamic'" % PREFIX))]
        if ids:
            falcon.delete_host_groups(ids=ids)

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        created = rec.call(
            "create_static", "create_host_groups", falcon.create_host_groups,
            name=names[0], group_type="static", description="Fixture group",
        )
        group_id = (resources(created) or [{"id": "0" * 32}])[0]["id"]
        for name in names[1:]:
            if not rec.dry_run:
                falcon.create_host_groups(name=name, group_type="static")
        rec.call(
            "create_dynamic", "create_host_groups", falcon.create_host_groups,
            name="%s-dynamic" % PREFIX, group_type="dynamic", assignment_rule=rule,
        )
        rec.call(
            "create_duplicate", "create_host_groups", falcon.create_host_groups,
            name=names[0], group_type="static",
        )
        rec.call("get_one", "get_host_groups", falcon.get_host_groups, ids=[group_id])
        rec.call(
            "query_by_name", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter="name:'%s'" % names[0], limit=1,
        )
        rec.call(
            "query_by_name_missing", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter="name:'%s-missing'" % PREFIX, limit=1,
        )
        rec.call(
            "query_page1", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter=name_filter, limit=2, offset=0, sort="name.asc",
        )
        rec.call(
            "query_page2", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter=name_filter, limit=2, offset=2, sort="name.asc",
        )
        # 500 is the largest page size that the search API accepts.
        rec.call(
            "query_sort_desc", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter=name_filter, limit=500, offset=0, sort="name.desc",
        )
        rec.call(
            "query_bad_filter", "query_combined_host_groups", falcon.query_combined_host_groups,
            filter="name:'", limit=1,
        )
        rec.call(
            "update_description", "update_host_groups", falcon.update_host_groups,
            id=group_id, description="Fixture group, updated",
        )
        rec.call("get_after_update", "get_host_groups", falcon.get_host_groups, ids=[group_id])
        rec.call(
            "members_empty", "query_combined_group_members", falcon.query_combined_group_members,
            id=group_id, limit=5000,
        )
        rec.call(
            "add_hosts_missing_host", "perform_group_action", falcon.perform_group_action,
            action_name="add-hosts", ids=[group_id], filter='device_id:["%s"]' % ("f" * 32),
        )
        rec.call("delete", "delete_host_groups", falcon.delete_host_groups, ids=[group_id])
        rec.call("get_missing", "get_host_groups", falcon.get_host_groups, ids=[group_id])
    finally:
        cleanup()


def record_sensor_update_policy(rec, creds):
    """Record the SensorUpdatePolicy calls used by the sensor update modules and the maintenance_token lookup."""
    from falconpy import SensorUpdatePolicy

    falcon = SensorUpdatePolicy(**creds)
    names = ["%s-%s" % (PREFIX, suffix) for suffix in ("a", "b", "c")]
    name_filter = "name.raw:[%s]+platform_name:'Linux'" % ",".join("'%s'" % name for name in names)
    scheduler = {
        "enabled": True,
        "timezone": "Etc/UTC",
        "schedules": [{"start": "08:00", "end": "14:00", "days": [1, 2, 3, 4, 5]}],
    }
    missing_id = "f" * 32

    def cleanup():
        if rec.dry_run:
            return
        for policy in resources(falcon.query_combined_policies_v2(filter=name_filter)):
            if policy.get("enabled"):
                falcon.perform_policies_action(action_name="disable", ids=[policy["id"]])
            falcon.delete_policies(ids=[policy["id"]])

    if rec.cleanup_only:
        cleanup()
        return

    builds = rec.call(
        "builds_linux", "query_combined_builds", falcon.query_combined_builds,
        platform="linux", stage="prod",
    )
    build = (resources(builds) or [{"build": "00000|n|tagged|1"}])[0]["build"]

    kernels = rec.call(
        "kernels_page", "query_combined_kernels", falcon.query_combined_kernels, limit=2,
    )
    release = (resources(kernels) or [{"release": "0"}])[0]["release"]
    rec.call(
        "kernels_filtered", "query_combined_kernels", falcon.query_combined_kernels,
        filter="release:'%s'" % release, offset=None, limit=500,
    )
    rec.call(
        "kernels_bad_filter", "query_combined_kernels", falcon.query_combined_kernels,
        filter="release:'", offset=None, limit=500,
    )

    rec.call(
        "token_bulk", "reveal_uninstall_token", falcon.reveal_uninstall_token,
        audit_message="Ansible unit test fixture recording", device_id="MAINTENANCE",
    )
    rec.call(
        "token_missing_device", "reveal_uninstall_token", falcon.reveal_uninstall_token,
        audit_message="Ansible unit test fixture recording", device_id=missing_id,
    )

    def policy_body(name, **settings):
        policy = {"name": name, "platform_name": "Linux", "description": "Fixture policy"}
        if settings:
            policy["settings"] = settings
        return {"resources": [policy]}

    cleanup()
    try:
        created = rec.call(
            "create", "create_policies_v2", falcon.create_policies_v2,
            body=policy_body(names[0], build=build, uninstall_protection="DISABLED", scheduler=scheduler),
        )
        policy_id = (resources(created) or [{"id": "0" * 32}])[0]["id"]
        for name in names[1:]:
            if not rec.dry_run:
                falcon.create_policies_v2(body=policy_body(name))
        rec.call(
            "create_duplicate", "create_policies_v2", falcon.create_policies_v2,
            body=policy_body(names[0]),
        )
        rec.call("get_one", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
        rec.call(
            "query_by_name", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter="name.raw:'%s'+platform_name:'Linux'" % names[0], limit=1,
        )
        rec.call(
            "query_by_name_missing", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter="name.raw:'%s-missing'+platform_name:'Linux'" % PREFIX, limit=1,
        )
        page1 = rec.call(
            "query_page1", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter=name_filter, offset=None, limit=2,
        )
        next_offset = ((page1.get("body") or {}).get("meta") or {}).get("pagination", {}).get("offset", 2)
        rec.call(
            "query_page2", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter=name_filter, offset=next_offset, limit=2,
        )
        rec.call(
            "query_bad_filter", "query_combined_policies_v2", falcon.query_combined_policies_v2,
            filter="name.raw:'", limit=1,
        )
        rec.call(
            "update_description", "update_policies_v2", falcon.update_policies_v2,
            body={"resources": [{"id": policy_id, "description": "Fixture policy, updated"}]},
        )
        rec.call("get_after_update", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
        rec.call(
            "enable", "perform_policies_action", falcon.perform_policies_action,
            action_name="enable", ids=[policy_id],
        )
        rec.call("get_after_enable", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
        rec.call(
            "add_host_group_missing", "perform_policies_action", falcon.perform_policies_action,
            action_name="add-host-group", ids=[policy_id],
            action_parameters=[{"name": "group_id", "value": missing_id}],
        )
        rec.call(
            "disable", "perform_policies_action", falcon.perform_policies_action,
            action_name="disable", ids=[policy_id],
        )
        rec.call("delete", "delete_policies", falcon.delete_policies, ids=[policy_id])
        rec.call("get_missing", "get_policies_v2", falcon.get_policies_v2, ids=[policy_id])
    finally:
        cleanup()


def drop_long_setting_ids(func):
    """Wrap a PreventionPolicy call so that settings with a long ID are left out.

    Some public setting IDs have 40 or more characters, and
    test_fixtures_clean.py treats such a string as an opaque token.
    """

    @functools.wraps(func)
    def call(**kwargs):
        response = func(**kwargs)
        for policy in resources(response):
            for category in policy.get("prevention_settings") or []:
                category["settings"] = [
                    s for s in category.get("settings") or [] if len(s.get("id") or "") < 40
                ]
        return response

    return call


def record_prevention_policy(rec, creds):
    """Record the PreventionPolicy calls used by prevention_policy and prevention_policy_info.

    The searches use the kwargs of the module: filter and sort only when set,
    offset=None and limit=5000. Each filter matches only the fixture policies.
    """
    from falconpy import HostGroup, PreventionPolicy

    falcon = PreventionPolicy(**creds)
    groups = HostGroup(**creds)
    shared = "%s-shared" % PREFIX
    mixed = "%s-Mixed-Case" % PREFIX
    created_names = [(shared, "Linux"), (shared, "Windows"), (mixed, "Linux")]
    missing_id = "f" * 32
    get_policies = drop_long_setting_ids(falcon.get_policies)

    def fixture_policies():
        found = resources(falcon.query_combined_policies(filter="name:~'%s'" % PREFIX, offset=None, limit=5000))
        return [p for p in found if p.get("name", "").casefold().startswith(PREFIX)]

    def cleanup():
        if rec.dry_run:
            return
        # The API creates the policies disabled, but the lifecycle below
        # enables one, so a run that stopped early can leave it enabled.
        found = fixture_policies()
        enabled = [p["id"] for p in found if p.get("enabled")]
        if enabled:
            # The API does not delete an enabled policy.
            falcon.perform_policies_action(action_name="disable", ids=enabled)
        ids = [p["id"] for p in found]
        if ids:
            falcon.delete_policies(ids=ids)
        left = fixture_policies()
        if left:
            sys.stderr.write("warning: %d prevention policy fixture(s) were not deleted\n" % len(left))
        group_ids = [g["id"] for g in resources(groups.query_combined_host_groups(filter="name:*'%s-pp-*'" % PREFIX))]
        if group_ids:
            groups.delete_host_groups(ids=group_ids)

    def search(case, **kwargs):
        return rec.call(
            case, "query_combined_policies", drop_long_setting_ids(falcon.query_combined_policies),
            offset=None, limit=5000, **kwargs,
        )

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        ids = []
        for name, platform in created_names:
            if rec.dry_run:
                ids.append("0" * 32)
                continue
            response = falcon.create_policies(
                body={"resources": [{"name": name, "platform_name": platform, "description": "Fixture policy"}]}
            )
            ids.append(resources(response)[0]["id"])

        rec.call("get_one", "get_policies", get_policies, ids=[ids[0]])
        rec.call("get_several", "get_policies", get_policies, ids=[ids[0], ids[1]])
        rec.call("get_missing", "get_policies", get_policies, ids=[missing_id])
        rec.call("get_one_missing", "get_policies", get_policies, ids=[ids[0], missing_id])
        rec.call("get_short_id", "get_policies", get_policies, ids=["abcdefg"])

        # name: shared, on Linux and Windows.
        search("query_by_name", filter="name:~'%s'" % shared)
        # name: shared, filter: platform_name:'Windows'.
        search("query_by_name_platform", filter="name:~'%s'+(platform_name:'Windows')" % shared)
        # name: the mixed-case name in another case.
        search("query_by_name_mixed_case", filter="name:~'%s'" % mixed.upper())
        # name: the prefix, which is only a part of each fixture name.
        search("query_by_name_partial", filter="name:~'%s'" % PREFIX)
        # name: a value with a quote and a backslash, escaped as the module does.
        search("query_by_name_quote", filter="name:~'%s-it\\'s\\\\x'" % PREFIX)
        # name: shared, filter: a platform with no fixture policy.
        search("query_by_name_missing", filter="name:~'%s'+(platform_name:'Mac')" % shared)
        # filter and sort.
        search("query_sorted", filter="name:~'%s'" % PREFIX, sort="name.asc")
        search("query_bad_filter", filter="name:'")

        # prevention_policy: the lifecycle of one more policy, with the kwargs of the module.
        crud = "%s-crud" % PREFIX
        created = rec.call(
            "create", "create_policies", drop_long_setting_ids(falcon.create_policies),
            body={"resources": [{"name": crud, "platform_name": "Linux", "description": "Fixture policy"}]},
        )
        crud_id = "0" * 32 if rec.dry_run else resources(created)[0]["id"]
        rec.call(
            "query_by_exact_name", "query_combined_policies", drop_long_setting_ids(falcon.query_combined_policies),
            filter="name:~'%s'+platform_name:'Linux'" % crud, limit=5000,
        )
        rec.call(
            "query_by_exact_name_missing", "query_combined_policies",
            drop_long_setting_ids(falcon.query_combined_policies),
            filter="name:~'%s'+platform_name:'Mac'" % crud, limit=5000,
        )
        # A second policy with the name of the crud policy on the same platform.
        rec.call(
            "create_duplicate", "create_policies", drop_long_setting_ids(falcon.create_policies),
            body={"resources": [{"name": crud, "platform_name": "Linux"}]},
        )
        rec.call(
            "update_missing", "update_policies", drop_long_setting_ids(falcon.update_policies),
            body={"resources": [{"id": missing_id, "description": "x"}]},
        )
        rec.call(
            "update_description", "update_policies", drop_long_setting_ids(falcon.update_policies),
            body={"resources": [{"id": crud_id, "description": "Updated fixture policy"}]},
        )
        rec.call(
            "enable", "perform_policies_action", drop_long_setting_ids(falcon.perform_policies_action),
            action_name="enable", ids=[crud_id],
        )
        rec.call("get_enabled", "get_policies", get_policies, ids=[crud_id])
        rec.call("delete_enabled", "delete_policies", falcon.delete_policies, ids=[crud_id])
        rec.call(
            "disable", "perform_policies_action", drop_long_setting_ids(falcon.perform_policies_action),
            action_name="disable", ids=[crud_id],
        )
        rec.call("get_disabled", "get_policies", get_policies, ids=[crud_id])

        # prevention_policy host_groups: two new static groups, added to and removed from the crud policy.
        group_ids = ["1" * 32, "2" * 32]
        if not rec.dry_run:
            group_ids = [
                resources(groups.create_host_groups(name="%s-pp-%s" % (PREFIX, suffix), group_type="static"))[0]["id"]
                for suffix in ("a", "b")
            ]
        rec.call("hg_get_found", "get_host_groups", groups.get_host_groups, ids=group_ids)
        rec.call("hg_get_some_missing", "get_host_groups", groups.get_host_groups, ids=[group_ids[0], missing_id])
        rec.call("hg_get_all_missing", "get_host_groups", groups.get_host_groups, ids=[missing_id])
        rec.call("hg_get_bad_id", "get_host_groups", groups.get_host_groups, ids=["abcdefg"])
        action = drop_long_setting_ids(falcon.perform_policies_action)
        rec.call(
            "add_groups", "perform_policies_action", action, action_name="add-host-group", ids=[crud_id],
            action_parameters=[{"name": "group_id", "value": g} for g in group_ids],
        )
        rec.call("get_with_groups", "get_policies", get_policies, ids=[crud_id])
        rec.call(
            "remove_group", "perform_policies_action", action, action_name="remove-host-group", ids=[crud_id],
            action_parameters=[{"name": "group_id", "value": group_ids[0]}],
        )
        # Only IDs that the calls above saw, so the fake IDs of the cases below do not move.
        rec.call("get_after_remove", "get_policies", get_policies, ids=[crud_id])
        rec.call(
            "add_groups_missing_policy", "perform_policies_action", action, action_name="add-host-group",
            ids=[missing_id], action_parameters=[{"name": "group_id", "value": group_ids[0]}],
        )
        rec.call(
            "remove_groups_missing_policy", "perform_policies_action", action, action_name="remove-host-group",
            ids=[missing_id], action_parameters=[{"name": "group_id", "value": group_ids[0]}],
        )
        rec.call("delete", "delete_policies", falcon.delete_policies, ids=[crud_id])
    finally:
        cleanup()


def record_correlation_rule(rec, creds):
    """Record the CorrelationRules calls used by correlation_rule and correlation_rule_info.

    A new rule stays in the 'creating' status for some time, and the API
    refuses updates and deletes until it leaves that status. The reads and
    the in-transition errors are recorded first. Then the script waits up to
    --wait seconds before it records the update, publish and delete calls.
    """
    import time

    from falconpy import CorrelationRules, SensorDownload

    falcon = CorrelationRules(**creds)
    names = ["%s-%s" % (PREFIX, suffix) for suffix in ("a", "b", "c")]
    name_filter = "name:[%s]" % ",".join("'%s'" % name for name in names)
    search = {"filter": "#event_simpleName=ProcessRollup2", "lookback": "5m", "outcome": "detection"}
    operation = {"schedule": {"definition": "*/5 * * * *"}}
    transition = ("creating", "updating", "deleting")

    def wait_ready(rule_ids, timeout):
        """Wait until no rule in rule_ids is in a transition status. Return True when ready."""
        if rec.dry_run:
            return True
        deadline = time.time() + timeout
        while True:
            rules = resources(falcon.get_rules(ids=rule_ids))
            if all(r.get("status") not in transition for r in rules):
                return True
            if time.time() > deadline:
                return False
            print("  waiting for the rules to leave their transition status")
            time.sleep(30)

    def cleanup():
        if rec.dry_run:
            return
        rules = resources(falcon.get_rules_combined(filter=name_filter, limit=100))
        ready = [r["rule_id"] for r in rules if r.get("status") not in transition]
        if ready:
            falcon.delete_rules(ids=ready)
        if len(ready) < len(rules):
            sys.stderr.write(
                "warning: %d fixture rule(s) are still in a transition status and were not "
                "deleted. Run this script again later with --cleanup correlation_rule.\n"
                % (len(rules) - len(ready))
            )

    if rec.cleanup_only:
        cleanup()
        return

    ccid = rec.call(
        "ccid", "get_sensor_installer_ccid", SensorDownload(**creds).get_sensor_installer_ccid,
    )
    customer_id = (resources(ccid) or ["0" * 32 + "-00"])[0].split("-")[0].lower()

    def rule(name, **extra):
        params = dict(
            name=name, customer_id=customer_id, severity=30, status="inactive",
            search=search, operation=operation,
        )
        params.update(extra)
        return params

    cleanup()
    try:
        created = rec.call(
            "create", "create_rule", falcon.create_rule,
            **rule(names[0], description="Fixture rule")
        )
        rule_id = (resources(created) or [{"rule_id": "0" * 32}])[0]["rule_id"]
        all_ids = [rule_id]
        for name in names[1:]:
            if not rec.dry_run:
                all_ids += [r["rule_id"] for r in resources(falcon.create_rule(**rule(name)))]

        # Phase A: reads, and the errors for a rule in transition.
        rec.call("get_creating", "get_rules", falcon.get_rules, ids=[rule_id])
        rec.call(
            "query_by_name_creating", "get_rules_combined", falcon.get_rules_combined,
            filter="name:'%s'" % names[0], limit=1,
        )
        rec.call(
            "query_by_name_missing", "get_rules_combined", falcon.get_rules_combined,
            filter="name:'%s-missing'" % PREFIX, limit=1,
        )
        rec.call(
            "query_page1", "get_rules_combined", falcon.get_rules_combined,
            filter=name_filter, limit=2, offset=0,
        )
        rec.call(
            "query_page2", "get_rules_combined", falcon.get_rules_combined,
            filter=name_filter, limit=2, offset=2,
        )
        rec.call(
            "query_bad_filter", "get_rules_combined", falcon.get_rules_combined,
            filter="name:'", limit=1,
        )
        rec.call(
            "latest_versions", "get_latest_rule_versions", falcon.get_latest_rule_versions,
            rule_ids=[rule_id],
        )
        rec.call(
            "update_in_transition", "update_rule", falcon.update_rule,
            id=rule_id, customer_id=customer_id, description="Fixture rule, updated",
        )
        rec.call("delete_in_transition", "delete_rules", falcon.delete_rules, ids=[rule_id])

        # Phase B: calls that need the rule to leave its transition status.
        if not wait_ready(all_ids, rec.wait):
            sys.stderr.write(
                "warning: the rules did not leave their transition status in %ds; "
                "update, publish and delete were not recorded.\n" % rec.wait
            )
            return
        rec.call("get_one", "get_rules", falcon.get_rules, ids=[rule_id])
        rec.call(
            "query_by_name", "get_rules_combined", falcon.get_rules_combined,
            filter="name:'%s'" % names[0], limit=1,
        )
        rec.call(
            "update_description", "update_rule", falcon.update_rule,
            id=rule_id, customer_id=customer_id, description="Fixture rule, updated",
        )
        rec.call("get_after_update", "get_rules", falcon.get_rules, ids=[rule_id])
        versions = rec.call(
            "latest_versions_after_update", "get_latest_rule_versions",
            falcon.get_latest_rule_versions, rule_ids=[rule_id],
        )
        version_id = (resources(versions) or [{"id": "0" * 32}])[0]["id"]
        rec.call("publish", "publish_rule_version", falcon.publish_rule_version, id=version_id)
        if wait_ready([rule_id], rec.wait):
            rec.call("delete", "delete_rules", falcon.delete_rules, ids=[rule_id])
            rec.call("get_missing", "get_rules", falcon.get_rules, ids=[rule_id])
    finally:
        cleanup()


PARSER_YAML = """$schema: https://schemas.humio.com/parser/v0.3.0
name: {name}
fieldsToBeRemovedBeforeParsing: []
testCases: []
script: |-
  parseJson()
  | Cps.version := "1.0.0"
  | Vendor := "ansible"
  | ecs.version := "9.0.0"
  | event.dataset := "ansible.{dataset}"
  | event.kind := "event"
  | event.module := "ansible"
  | event.outcome := "success"
  | observer.type := "test"
tagFields:
  - Cps.version
  - Vendor
  - ecs.version
  - event.dataset
  - event.kind
  - event.module
  - event.outcome
  - observer.type
"""


def record_ngsiem(rec, creds):
    """Record the NGSIEM calls used by the ngsiem_* modules.

    Searches use only synthetic events from createEvents() and a query that
    finds nothing, so no real event data is recorded.
    """
    import time

    from falconpy import NGSIEM, APIHarnessV2

    falcon = NGSIEM(**creds)
    uber = APIHarnessV2(**creds)
    repo = "parsers-repository"
    parser_name = "%s-parser" % PREFIX
    clone_name = "%s-clone" % PREFIX
    ext_name = "%s-ext" % PREFIX
    connection_name = "%s-connection" % PREFIX
    hec_connector = "a1bfd0c4380f436790cb41afc2b95f38"

    def parser_id_of(response):
        data = (response.get("body") or {}).get("resources")
        # Same shapes as ngsiem_parser._extract_parser_id: a dict for clone,
        # and a list of dicts or of ID strings for the other calls.
        if isinstance(data, dict):
            return data.get("id")
        if data:
            return data[0].get("id") if isinstance(data[0], dict) else data[0]
        return None

    def cleanup():
        if rec.dry_run:
            return
        listed = falcon.list_parsers(repository=repo, filter="name:~'%s'" % PREFIX, limit=100)
        for parser in resources(listed):
            # The API adds a 'custom-' prefix to custom parser names.
            if PREFIX in parser.get("Name", ""):
                falcon.delete_parser(ids=parser["ID"], repository=repo)
        listed = falcon.list_data_connections(filter="name:'%s'" % connection_name, limit=10)
        for connection in resources(listed):
            falcon.delete_data_connection(ids=connection["id"])

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        # Parsers
        created = rec.call(
            "parser_create", "create_parser_from_template", falcon.create_parser_from_template,
            repository=repo, name=parser_name,
            yaml_template=PARSER_YAML.format(name=parser_name, dataset="fixture"),
        )
        parser_id = parser_id_of(created) or "0" * 32
        rec.call(
            "parser_list_by_name", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % parser_name, limit=500, offset=0,
        )
        rec.call(
            "parser_list_missing", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s-missing'" % PREFIX, limit=500, offset=0,
        )
        rec.call(
            "parser_list_bad_filter", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'", limit=500, offset=0,
        )
        rec.call(
            "parser_template", "get_parser_template", falcon.get_parser_template,
            ids=parser_id, repository=repo,
        )
        rec.call("parser_get", "get_parser", falcon.get_parser, ids=parser_id, repository=repo)
        # An update with the versioned ID returns 200 but changes nothing, so
        # the module sends the ID without the version.
        updated = rec.call(
            "parser_update", "update_parser_from_template", falcon.update_parser_from_template,
            ids=parser_id.split(":")[0], repository=repo,
            yaml_template=PARSER_YAML.format(name=parser_name, dataset="fixture.updated"),
        )
        parser_id = parser_id_of(updated) or parser_id
        rec.call(
            "parser_list_after_update", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % parser_name, limit=500, offset=0,
        )
        rec.call(
            "parser_template_after_update", "get_parser_template", falcon.get_parser_template,
            ids=parser_id, repository=repo,
        )
        rec.call(
            "parser_get_after_update", "get_parser", falcon.get_parser, ids=parser_id, repository=repo,
        )
        clone = rec.call(
            "parser_clone", "clone_parser", falcon.clone_parser,
            source_id=parser_id, new_name=clone_name,
        )
        clone_id = parser_id_of(clone)
        rec.call(
            "parser_get_clone", "get_parser", falcon.get_parser, ids=clone_id, repository=repo,
        )
        base = resources(falcon.list_parsers(
            repository=repo, filter="name:~'microsoft-edge'", parser_type="ootb", limit=10,
        )) if not rec.dry_run else []
        base_id = next((p["ID"] for p in base if p.get("Name") == "microsoft-edge"), "0" * 32)
        # create_parser_extension refuses a base ID with a version suffix.
        rec.call(
            "parser_extension_versioned_base", "create_parser_extension", falcon.create_parser_extension,
            base_parser_id=base_id, extension_name=ext_name,
        )
        base_id = base_id.split(":")[0]
        extension = rec.call(
            "parser_extension", "create_parser_extension", falcon.create_parser_extension,
            base_parser_id=base_id, extension_name=ext_name,
        )
        ext_id = parser_id_of(extension) or "0" * 32
        rec.call(
            "parser_info_page", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % PREFIX, parser_type="custom", limit=2, offset=0,
        )
        rec.call("parser_delete", "delete_parser", falcon.delete_parser, ids=parser_id, repository=repo)
        rec.call(
            "parser_delete_missing", "delete_parser", falcon.delete_parser, ids=parser_id, repository=repo,
        )
        rec.call("parser_get_missing", "get_parser", falcon.get_parser, ids=parser_id, repository=repo)

        # Data connectors and connections
        rec.call(
            "connectors_page", "list_data_connectors", falcon.list_data_connectors, limit=2, offset=0,
        )
        rec.call(
            "connectors_push", "list_data_connectors", falcon.list_data_connectors,
            filter="type:'PUSH'", limit=2, offset=0,
        )
        rec.call(
            "connectors_bad_filter", "list_data_connectors", falcon.list_data_connectors,
            filter="type:'", limit=2,
        )
        body = {
            "name": connection_name, "connector_id": hec_connector, "parser": "microsoft-edge",
            "vendor_name": "Ansible", "vendor_product_name": "UnitFixture",
        }
        created = rec.call(
            "connection_create", "create_data_connection", falcon.create_data_connection, body=body,
        )
        connection_id = (resources(created) or [{"id": "0" * 32}])[0]["id"]
        rec.call(
            "connection_get", "get_connection_by_id", falcon.get_connection_by_id, ids=[connection_id],
        )
        rec.call(
            "connection_list_by_name", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s'" % connection_name, limit=500, offset=0,
        )
        rec.call(
            "connection_list_missing", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s-missing'" % PREFIX, limit=500, offset=0,
        )
        rec.call(
            "connection_list_bad_filter", "list_data_connections", falcon.list_data_connections,
            filter="name:'", limit=1,
        )
        # The name filter is a substring match that ignores case. A second
        # connection with a longer name shows the results that the module
        # must not use.
        if not rec.dry_run:
            falcon.create_data_connection(body=dict(body, name=connection_name + "-renamed"))
        partial = connection_name[:-4]
        rec.call(
            "connection_list_near_match", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s'" % partial, limit=500, offset=0,
        )
        rec.call(
            "connection_list_near_match_page1", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s'" % partial, limit=1, offset=0,
        )
        rec.call(
            "connection_list_near_match_page2", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s'" % partial, limit=1, offset=1,
        )
        rec.call(
            "connection_list_upper_case", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s'" % connection_name.upper(), limit=500, offset=0,
        )
        rec.call(
            "connection_status_new", "get_provisioning_status", falcon.get_provisioning_status,
            ids=connection_id,
        )

        def get_token(case):
            return rec.call(
                case, "command:ExternalGetDataConnectionToken", uber.command,
                action="ExternalGetDataConnectionToken", ids=connection_id,
            )

        token = get_token("token_first")
        deadline = time.time() + 180
        while not rec.dry_run and token.get("status_code") == 202 and time.time() < deadline:
            time.sleep(5)
            token = get_token("token_ready")
        if rec.dry_run:
            # The loop above does not run in a dry run. List its case, so that --only accepts it.
            get_token("token_ready")
        get_token("token_again")
        rec.call(
            "connection_update", "update_data_connection", falcon.update_data_connection,
            parameters={"ids": connection_id}, body=dict(body, parser="microsoft-edge"),
        )
        status = rec.call(
            "connection_status", "get_provisioning_status", falcon.get_provisioning_status,
            ids=connection_id,
        )
        if rec.dry_run or (resources(status) or [{}])[0].get("status") in ("Active", "Error", "Idle"):
            rec.call(
                "connection_pause", "update_connection_status", falcon.update_connection_status,
                ids=connection_id, status="Pause",
            )
            rec.call(
                "connection_status_paused", "get_provisioning_status", falcon.get_provisioning_status,
                ids=connection_id,
            )
            rec.call(
                "connection_resume", "update_connection_status", falcon.update_connection_status,
                ids=connection_id, status="Resume",
            )
        rec.call(
            "connection_delete", "delete_data_connection", falcon.delete_data_connection,
            ids=connection_id,
        )
        rec.call(
            "connection_get_missing", "get_connection_by_id", falcon.get_connection_by_id,
            ids=[connection_id],
        )

        # Searches (synthetic events only)
        for case, query in (
            ("search", 'createEvents(["fixture=a", "fixture=b"]) | kvParse()'),
            ("search_empty", "#event_simpleName=AnsibleUnitFixtureNoSuchEvent | head(1)"),
        ):
            started = rec.call(
                case + "_start", "start_search", falcon.start_search,
                repository="search-all", query_string=query, start="1h",
            )
            job_id = (started.get("resources") or {}).get("id", "0")
            status = rec.call(
                case + "_status", "get_search_status", falcon.get_search_status,
                repository="search-all", search_id=job_id,
            )
            deadline = time.time() + 120
            while not rec.dry_run and not (status.get("body") or {}).get("done") and time.time() < deadline:
                time.sleep(5)
                status = rec.call(
                    case + "_done", "get_search_status", falcon.get_search_status,
                    repository="search-all", search_id=job_id,
                )
            if rec.dry_run:
                # The loop above does not run in a dry run. List its case, so that --only accepts it.
                rec.call(
                    case + "_done", "get_search_status", falcon.get_search_status,
                    repository="search-all", search_id=job_id,
                )
            # A fast search can be done on the first status call.
            rec.files.setdefault(case + "_done", rec.files.get(case + "_status"))
        rec.call(
            "search_bad_query", "start_search", falcon.start_search,
            repository="search-all", query_string="| | not a query (", start="1h",
        )

        # Extensions. These calls come last, so that the fake IDs of the
        # calls above do not change. The clone and the extension still exist.
        # The API names an extension '<base parser>-<name>'.
        rec.call("parser_get_base", "get_parser", falcon.get_parser, ids=base_id, repository=repo)
        rec.call(
            "parser_list_extension", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % ext_name, limit=500, offset=0,
        )
        rec.call(
            "parser_list_base", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'microsoft-edge'", limit=500, offset=0,
        )
        rec.call("parser_get_extension", "get_parser", falcon.get_parser, ids=ext_id, repository=repo)
        rec.call(
            "parser_info_extension", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % PREFIX, parser_type="extension", limit=100, offset=0,
        )
        # Two pages: the clone and the extension.
        rec.call(
            "parser_list_page1", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % PREFIX, limit=1, offset=0,
        )
        rec.call(
            "parser_list_page2", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % PREFIX, limit=1, offset=1,
        )
        rec.call(
            "parser_delete_extension", "delete_parser", falcon.delete_parser, ids=ext_id, repository=repo,
        )

        # Search status errors. These calls come after the extensions, so
        # that the fake IDs of the calls above do not change.
        rec.call(
            "search_status_missing", "get_search_status", falcon.get_search_status,
            repository="search-all", search_id="P000-AnsibleUnitFixtureNoSuchSearch",
        )
        # The API deletes a job that is stopped, so the next status call is an
        # error and never returns "cancelled": true.
        no_event_query = "#event_simpleName=AnsibleUnitFixtureNoSuchEvent | head(1)"
        started = rec.call(
            "search_stopped_start", "start_search", falcon.start_search,
            repository="search-all", query_string=no_event_query, start="1h",
        )
        stopped_id = (started.get("resources") or {}).get("id", "0")
        try:
            rec.call(
                "search_stopped_stop", "stop_search", falcon.stop_search,
                repository="search-all", id=stopped_id,
            )
            rec.call(
                "search_status_stopped", "get_search_status", falcon.get_search_status,
                repository="search-all", search_id=stopped_id,
            )
        finally:
            if not rec.dry_run:
                # A second stop of a job that is gone returns 404.
                falcon.stop_search(repository="search-all", id=stopped_id)
        # A query that starts and then fails while it runs: the lookup file does not exist.
        started = rec.call(
            "search_lookup_missing_start", "start_search", falcon.start_search,
            repository="search-all", start="1h",
            query_string=(
                'createEvents(["fixture=a"]) | kvParse() '
                '| match(file="ansible-unit-fixture-no-such-file.csv", field=fixture)'
            ),
        )
        lookup_id = (started.get("resources") or {}).get("id", "0")
        try:
            status = rec.call(
                "search_status_lookup_missing", "get_search_status", falcon.get_search_status,
                repository="search-all", search_id=lookup_id,
            )
            deadline = time.time() + 30
            while (
                not rec.dry_run and status.get("status_code") == 200
                and not (status.get("body") or {}).get("done") and time.time() < deadline
            ):
                time.sleep(2)
                status = rec.call(
                    "search_status_lookup_missing", "get_search_status", falcon.get_search_status,
                    repository="search-all", search_id=lookup_id,
                )
        finally:
            if not rec.dry_run:
                falcon.stop_search(repository="search-all", id=lookup_id)
    finally:
        cleanup()


# Host records have many fields that can identify a tenant (users, serial
# numbers, locations, policies). The host scenarios keep only these fields,
# and the Sanitizer then replaces their values.
HOST_FIELDS = (
    "device_id", "cid", "hostname", "platform_name", "os_version", "agent_version",
    "local_ip", "external_ip", "mac_address", "product_type_desc", "status",
    "first_seen", "last_seen", "tags", "groups", "reduced_functionality_mode",
)
DISCOVER_FIELDS = (
    "id", "cid", "aid", "hostname", "entity_type", "first_seen_timestamp",
    "last_seen_timestamp", "platform_name", "os_version", "kernel_version", "tags",
    "groups", "agent_version", "external_ip", "current_local_ip", "local_ip_addresses",
    "product_type_desc", "confidence",
)


def keep_fields(func, fields):
    """Wrap func so that each host record in its response keeps only fields."""

    def call(**kwargs):
        response = func(**kwargs)
        body = response.get("body") or {}
        if isinstance(body.get("resources"), list):
            body["resources"] = [
                {k: v for k, v in item.items() if k in fields} if isinstance(item, dict) else item
                for item in body["resources"]
            ]
        return response

    return call


def scroll_ids(rec, falcon, case, **kwargs):
    """Record one page of query_devices_by_filter_scroll and return it."""
    return rec.call(
        case, "query_devices_by_filter_scroll", falcon.query_devices_by_filter_scroll, **kwargs
    )


def record_hosts(rec, creds):
    """Record the Hosts calls used by host_info, host_contain, host_hide, host_ids and falcon_hosts.

    Read-only: the host actions are called only with a device ID that does
    not exist, so no real host is contained or hidden.
    """
    from falconpy import Hosts

    falcon = Hosts(**creds)
    missing_id = "f" * 32
    details = keep_fields(falcon.get_device_details, HOST_FIELDS)

    page1 = scroll_ids(rec, falcon, "scroll_page1", limit=2)
    offset = ((page1.get("body") or {}).get("meta") or {}).get("pagination", {}).get("offset")
    page2 = scroll_ids(rec, falcon, "scroll_page2", limit=2, offset=offset)
    scroll_ids(rec, falcon, "scroll_empty", filter="hostname:'%s-missing'" % PREFIX, limit=2)
    scroll_ids(rec, falcon, "scroll_bad_filter", filter="hostname:'", limit=2)
    rec.call("details_page1", "get_device_details", details, ids=resources(page1) or [missing_id])
    rec.call("details_page2", "get_device_details", details, ids=resources(page2) or [missing_id])
    rec.call("details_missing", "get_device_details", details, ids=[missing_id])
    for action in ("contain", "lift_containment", "hide_host", "unhide_host"):
        rec.call(
            "action_%s_missing" % action, "perform_action", falcon.perform_action,
            action_name=action, ids=[missing_id],
        )


def record_discover(rec, creds):
    """Record the Discover calls used by the falcon_discover inventory plugin."""
    from falconpy import Discover

    falcon = Discover(**creds)
    get_hosts = keep_fields(falcon.get_hosts, DISCOVER_FIELDS)

    page1 = rec.call("query_page1", "query_hosts", falcon.query_hosts, limit=2, offset=0)
    page2 = rec.call("query_page2", "query_hosts", falcon.query_hosts, limit=2, offset=2)
    rec.call(
        "query_empty", "query_hosts", falcon.query_hosts,
        filter="hostname:'%s-missing'" % PREFIX, limit=2,
    )
    rec.call("query_bad_filter", "query_hosts", falcon.query_hosts, filter="hostname:'", limit=2)
    # A dry run lists these cases too, so that --only accepts them.
    if resources(page1) or rec.dry_run:
        rec.call("hosts_page1", "get_hosts", get_hosts, ids=resources(page1))
    if resources(page2) or rec.dry_run:
        rec.call("hosts_page2", "get_hosts", get_hosts, ids=resources(page2))


def errors_only(func):
    """Wrap a download call so that a file is never saved.

    A download call returns the file as bytes and an error as a dict. Only
    the error dict is kept; for bytes the size is printed and the call
    returns an empty dict, which Recorder.save writes with no body.
    """

    def call(**kwargs):
        response = func(**kwargs)
        if isinstance(response, dict):
            return response
        print("    (not saved: %d bytes)" % len(response))
        return {"status_code": None, "body": {"note": "the API returned a file; it is not saved"}}

    return call


def record_auth(rec, creds):
    """Record the OAuth2 calls used by the auth module.

    The token that the scenario gets is revoked at the end.
    """
    from falconpy import OAuth2

    falcon = OAuth2(**creds)
    rec.call("login", "login", falcon.login)
    token = falcon.token_value if not rec.dry_run else ""
    rec.call("revoke", "revoke", falcon.revoke, token=token)
    rec.call("logout", "logout", falcon.logout)
    bad = OAuth2(
        client_id="%s-bad-id" % PREFIX, client_secret="%s-bad-secret" % PREFIX,
        base_url=creds.get("base_url", "us-1"),
    )
    rec.call("login_bad_credentials", "login", bad.login)


def record_sensor_download(rec, creds):
    """Record the SensorDownload calls used by cid_info, sensor_download and sensor_download_info.

    No installer is downloaded; only the error for a hash that does not exist.
    """
    from falconpy import SensorDownload

    falcon = SensorDownload(**creds)
    route = "/sensors/combined/installers/v2"
    missing_hash = "0" * 64

    rec.call("ccid", "get_sensor_installer_ccid", falcon.get_sensor_installer_ccid)
    installers = rec.call(
        "installers_linux", "override:GET " + route, functools.partial(falcon.override, "GET", route),
        parameters={"filter": "platform:'linux'+os:'Ubuntu'", "sort": "version|desc", "limit": 2},
    )
    rec.call(
        "installers_bad_filter", "override:GET " + route, functools.partial(falcon.override, "GET", route),
        parameters={"filter": "platform:'"},
    )
    sha = (resources(installers) or [{"sha256": missing_hash}])[0]["sha256"]
    rec.call("installer_entity", "get_sensor_installer_entities", falcon.get_sensor_installer_entities, ids=[sha])
    rec.call(
        "installer_entity_missing", "get_sensor_installer_entities", falcon.get_sensor_installer_entities,
        ids=[missing_hash],
    )
    rec.call(
        "download_missing", "download_sensor_installer",
        errors_only(falcon.download_sensor_installer), id=missing_hash,
    )


def fake_child_names(func):
    """Wrap a Flight Control call so that child CID names are fake.

    The name of a child CID is a customer name.
    """
    names = {}

    def call(**kwargs):
        response = func(**kwargs)
        for item in resources(response):
            if isinstance(item, dict) and item.get("name"):
                item["name"] = names.setdefault(item["name"], "child-cid-%d" % (len(names) + 1))
        return response

    return call


def record_flight_control(rec, creds):
    """Record the FlightControl calls used by fctl_child_cid_info and the fctl_child_cids lookup."""
    from falconpy import FlightControl

    falcon = FlightControl(**creds)
    route = "/mssp/entities/children/GET/v2"

    page1 = rec.call("children_page1", "query_children", falcon.query_children, limit=2)
    # The fctl_child_cids lookup passes the returned offset to the next call.
    offset = ((page1.get("body") or {}).get("meta") or {}).get("pagination", {}).get("offset")
    rec.call("children_page2", "query_children", falcon.query_children, limit=2, offset=offset)
    rec.call("children_bad_filter", "query_children", falcon.query_children, filter="cid:'", limit=2)
    rec.call(
        "children_get", "override:POST " + route,
        fake_child_names(functools.partial(falcon.override, "POST", route)), body={"ids": resources(page1) or ["0" * 32]},
    )
    rec.call(
        "children_get_missing", "override:POST " + route, functools.partial(falcon.override, "POST", route),
        body={"ids": ["0" * 32]},
    )


# Intel rule records also have descriptions and tags from CrowdStrike
# Intelligence reports. The fixtures keep only these fields.
INTEL_RULE_FIELDS = ("id", "name", "type", "created_date", "last_modified_date")


def record_intel(rec, creds):
    """Record the Intel calls used by intel_rule_info and intel_rule_download.

    No rule file is downloaded; only the errors for a rule that does not exist.
    """
    from falconpy import Intel

    falcon = Intel(**creds)
    page1 = rec.call(
        "rule_ids_page1", "query_rule_ids", falcon.query_rule_ids,
        type="yara-master", sort="created_date|desc", limit=2,
    )
    rec.call(
        "rule_ids_page2", "query_rule_ids", falcon.query_rule_ids,
        type="yara-master", sort="created_date|desc", limit=2, offset=2,
    )
    rec.call(
        "rule_ids_empty", "query_rule_ids", falcon.query_rule_ids,
        type="yara-master", name=["%s-missing" % PREFIX], limit=2,
    )
    rec.call("rule_ids_bad_type", "query_rule_ids", falcon.query_rule_ids, type="not-a-type", limit=2)
    rules = keep_fields(falcon.get_rule_entities, INTEL_RULE_FIELDS)
    rec.call("rules", "get_rule_entities", rules, ids=resources(page1) or [0])
    rec.call("rules_missing", "get_rule_entities", falcon.get_rule_entities, ids=[0])
    rec.call(
        "rule_file_missing", "get_rule_file", errors_only(falcon.get_rule_file), id=0, format="zip",
    )
    rec.call(
        "latest_rule_file_bad_type", "get_latest_rule_file",
        errors_only(falcon.get_latest_rule_file), type="not-a-type", format="zip",
    )


def record_hunting(rec, creds):
    """Record the CAOHunting errors used by hunting_rule_download. No archive is saved."""
    from falconpy import CAOHunting

    falcon = CAOHunting(**creds)
    export = errors_only(falcon.create_export_archive)
    rec.call(
        "export_bad_filter", "create_export_archive", export,
        language="yara", archive_type="zip", filter="name:'",
    )
    rec.call(
        "export_bad_language", "create_export_archive", export,
        language="not-a-language", archive_type="zip",
    )


def record_case(rec, creds):
    """Record the CaseManagement calls used by case_info.

    Read only: the API cannot delete a case, so this records the cases that
    exist and creates none. Every filter matches only the test cases, whose
    names start with CASE_PREFIX. The searches use the kwargs of the module:
    limit and offset, and filter, q and sort only when set.

    The tenant must have at least two cases whose names start with
    CASE_PREFIX, all of them closed, and at least one of them with a tag.
    Make them once with the Falcon console or the API and close them.
    """
    from falconpy import CaseManagement

    falcon = CaseManagement(**creds)
    prefix = "name:*'%s*'" % CASE_PREFIX

    def search(case, limit=100, offset=0, **kwargs):
        return rec.call(case, "query_case_ids", falcon.query_case_ids, limit=limit, offset=offset, **kwargs)

    if rec.cleanup_only:
        return

    if not rec.dry_run:
        # Check before any recording, so that no fixture is written.
        existing = resources(falcon.query_case_ids(limit=100, offset=0, filter=prefix))
        if len(existing) < 2:
            raise SystemExit(
                "case: found %d case(s) whose names start with %s, need at least 2. "
                "Make them with the Falcon console or the API and close them."
                % (len(existing), CASE_PREFIX)
            )

    found = search("query_by_prefix", filter=prefix)
    search("query_by_prefix_sorted", filter=prefix, sort="name.asc")
    search("query_closed", filter="%s+status:'closed'" % prefix)
    search("query_q", q=CASE_PREFIX)
    search("query_page_1", limit=1, offset=0, filter=prefix, sort="name.asc")
    search("query_page_2", limit=1, offset=1, filter=prefix, sort="name.asc")
    search("query_empty", filter="name:'ansible-dev-none-xyz'")
    search("query_bad_filter", filter="name:")
    search("query_bad_sort", filter=prefix, sort="nosuchfield.asc")

    def get_cases(**kwargs):
        # An alert ID has a hash of 64 characters, which test_fixtures_clean.py
        # treats as a token, so the alert records of the evidence are left out.
        response = falcon.get_cases(**kwargs)
        for case in resources(response):
            for part in ("evidence", "analysis_results"):
                alerts = (case.get(part) or {}).get("alerts")
                if alerts:
                    alerts["records"] = []
        return response

    ids = sorted(resources(found)) if not rec.dry_run else ["0" * 32, "1" * 32]
    rec.call("get_several", "get_cases", get_cases, body={"ids": ids})
    rec.call("get_missing", "get_cases", get_cases, body={"ids": ["f" * 32]})


# The fake alert ID that the case_write fixtures hold instead of the real one.
FAKE_ALERT_ID = "fixture-cid:cwpp:fixture-aid:fixture-alert-1"
# The environment variable with the ID of the one alert that case_write adds
# as evidence (an alert of the test tenant). The alert status is not changed.
CASE_ALERT_ENV = "FALCON_CASE_ALERT_ID"


def replace_strings(data, old, new):
    """Return a copy of data with old replaced by new in every string."""
    if isinstance(data, dict):
        return {k: replace_strings(v, old, new) for k, v in data.items()}
    if isinstance(data, list):
        return [replace_strings(v, old, new) for v in data]
    if isinstance(data, str):
        return data.replace(old, new)
    return data


def record_case_write(rec, creds):
    """Record the CaseManagement write calls used by case.

    The API cannot delete a case. This makes at most two cases with the same
    name, ansible-dev-case-unit-<timestamp>, and closes each of them in the
    finally path; closed cases stay in the tenant. It adds one existing
    alert as evidence and does not change the alert. It sets no real
    assignee, so no user gets an email.

    The alert ID holds the CID and a hash of 64 characters, which
    test_fixtures_clean.py treats as a token, so each response gets
    FAKE_ALERT_ID instead of the real ID before it is saved.
    """
    import time

    from falconpy import Alerts, CaseManagement

    falcon = CaseManagement(**creds)
    name = "ansible-dev-case-unit-%s" % time.strftime("%Y%m%d%H%M%S")
    name_filter = "name:'%s'" % name
    missing_id = "00000000-0000-0000-0000-000000000000"
    made = []
    closed = set()

    if rec.cleanup_only:
        return

    alert_id = "cwpp:alert"
    if not rec.dry_run:
        if not os.environ.get(CASE_ALERT_ENV):
            raise SystemExit("case_write: set %s to the ID of a test alert." % CASE_ALERT_ENV)
        alert_filter = "id:'%s'" % os.environ[CASE_ALERT_ENV]
        alert_ids = resources(Alerts(**creds).query_alerts_v2(filter=alert_filter))
        if len(alert_ids) != 1:
            raise SystemExit("case_write: found %d alert(s) for the evidence, need 1." % len(alert_ids))
        alert_id = alert_ids[0]
    alert_hash = alert_id.rsplit(":", 1)[-1]

    def fake_alert(func):
        def call(**kwargs):
            response = func(**kwargs)
            if rec.dry_run:
                return response
            response = replace_strings(response, alert_id, FAKE_ALERT_ID)
            return replace_strings(response, alert_hash, "fixture-alert-hash")
        return call

    def search(case):
        return rec.call(case, "query_case_ids", falcon.query_case_ids, filter=name_filter, limit=100, offset=0)

    def wait_for(count):
        # The name search does not see a new case for about 20 seconds.
        deadline = time.time() + 60
        while not rec.dry_run and time.time() < deadline:
            if len(resources(falcon.query_case_ids(filter=name_filter, limit=100))) >= count:
                return
            time.sleep(5)
        if not rec.dry_run:
            raise SystemExit("case_write: the name search did not find %d case(s) in 60 s." % count)

    def get(case, ids):
        return rec.call(case, "get_cases", fake_alert(falcon.get_cases), body={"ids": ids})

    def version(case_id):
        if rec.dry_run:
            return 1
        return resources(falcon.get_cases(body={"ids": [case_id]}))[0]["version"]

    def update(case, case_id, fields, expected=None):
        return rec.call(
            case, "update_case_fields", fake_alert(falcon.update_case_fields),
            body={
                "id": case_id,
                "expected_version": version(case_id) if expected is None else expected,
                "fields": fields,
            },
        )

    def new_id(response):
        found = resources(response)
        if found:
            made.append(found[0]["id"])
            return found[0]["id"]
        return "00000000-0000-0000-0000-00000000000%d" % (len(made) + 1)

    try:
        search("query_name_none")
        case_id = new_id(rec.call(
            "create", "create_case", fake_alert(falcon.create_case),
            body={
                "name": name, "description": "Unit fixture case", "severity": 30,
                "tags": ["ansible-dev-t1"], "evidence": {"alerts": [{"id": alert_id}]},
            },
        ))
        get("get_created", [case_id])
        wait_for(1)
        search("query_name_one")

        update("update_description", case_id, {"description": "Unit fixture case updated"})
        get("get_after_description", [case_id])
        update("update_several", case_id, {"status": "in_progress", "severity": 50})
        get("get_after_several", [case_id])
        rec.call(
            "add_tags", "add_case_tags", fake_alert(falcon.add_case_tags),
            body={"id": case_id, "tags": ["ansible-dev-t2"]},
        )
        get("get_after_add_tags", [case_id])
        rec.call(
            "delete_tag", "delete_case_tags", fake_alert(falcon.delete_case_tags), id=case_id, tag="ansible-dev-t1"
        )
        get("get_after_delete_tag", [case_id])
        update("update_unassign", case_id, {"remove_user_assignment": True})
        get("get_after_unassign", [case_id])
        update("update_conflict", case_id, {"severity": 60}, expected=version(case_id) + 5)
        update("update_missing", missing_id, {"severity": 60}, expected=1)
        update("update_bad_assignee", case_id, {"assigned_to_user_uuid": missing_id})
        get("get_missing", [missing_id])

        # The second case has the same name, no tags and no alerts.
        dup_id = new_id(rec.call(
            "create_plain", "create_case", fake_alert(falcon.create_case),
            body={"name": name, "description": "Unit fixture case", "severity": 30},
        ))
        get("get_plain", [dup_id])
        rec.call(
            "add_alerts", "add_case_alert_evidence", fake_alert(falcon.add_case_alert_evidence),
            body={"id": dup_id, "alerts": [{"id": alert_id}]},
        )
        get("get_after_add_alerts", [dup_id])
        wait_for(2)
        search("query_name_two")
        get("get_two", sorted([case_id, dup_id]))

        update("update_close", case_id, {"status": "closed"})
        closed.add(case_id)
        get("get_after_close", [case_id])
    finally:
        for made_id in made:
            if made_id not in closed:
                falcon.update_case_fields(
                    body={"id": made_id, "expected_version": version(made_id), "fields": {"status": "closed"}}
                )
        for made_id in made:
            print("  case_write: made case %s, status %s" % (
                made_id, resources(falcon.get_cases(body={"ids": [made_id]}))[0]["status"]))


ALERT_FIELDS = (
    "composite_id", "id", "cid", "product", "type", "status", "severity", "severity_name",
    "show_in_ui", "created_timestamp", "updated_timestamp",
)


def record_alerts(rec, creds):
    """Record the Alerts calls used by alert_info.

    Read-only. Each alert keeps only a few fields, so the fixtures stay small
    and hold no host or user data.
    """
    from falconpy import Alerts

    falcon = Alerts(**creds)
    combined = keep_fields(falcon.get_alerts_combined, ALERT_FIELDS)
    get_alerts = keep_fields(falcon.get_alerts_v2, ALERT_FIELDS)
    search = {"filter": "product:'epp'", "sort": "created_timestamp.asc"}

    page1 = rec.call("combined_page1", "get_alerts_combined", combined, limit=2, **search)
    after = (((page1.get("body") or {}).get("meta") or {}).get("pagination") or {}).get("after")
    page2 = rec.call("combined_page2", "get_alerts_combined", combined, limit=2, after=after, **search)
    ids = [a["composite_id"] for a in resources(page1) + resources(page2)] or ["x:ind:x:0"]
    rec.call(
        "combined_last", "get_alerts_combined", combined,
        filter="composite_id:'%s'" % ids[0], limit=2,
    )
    rec.call(
        "combined_empty", "get_alerts_combined", combined,
        filter="product:'%s-missing'" % PREFIX, limit=2,
    )
    rec.call("combined_bad_filter", "get_alerts_combined", combined, filter="status:", limit=2)
    cid = ids[0].split(":", 1)[0]
    missing_id = "%s:ind:%s:0-0-0" % (cid, "f" * 32)
    rec.call("get_several", "get_alerts_v2", get_alerts, composite_ids=ids[:3])
    rec.call("get_one_missing", "get_alerts_v2", get_alerts, composite_ids=[ids[0], missing_id])
    rec.call(
        "get_bad_cid", "get_alerts_v2", get_alerts,
        composite_ids=["%s:ind:%s:0-0-0" % ("f" * 32, "f" * 32)],
    )


ALERT_WRITE_FIELDS = (
    "composite_id", "status", "resolution", "tags", "assigned_to_uuid", "assigned_to_uid",
    "assigned_to_name", "show_in_ui", "comments",
)


def record_alert_write(rec, creds):
    """Record the Alerts calls used by alert.

    The API cannot create alerts, so this writes to the two test alerts in
    FALCON_TEST_ALERT_IDS (the same variable as the alert integration target),
    and puts back their status, tags, resolution, assignee and show_in_ui at
    the end. A comment cannot be removed, so the recorder adds one comment only.
    The assign cases reuse the assignee of an alert that is already assigned.
    """
    import datetime
    import uuid
    from falconpy import Alerts

    falcon = Alerts(**creds)

    def hide_names(func):
        # The assignee name is a person name, so the fixture keeps a fixed text.
        def call(**kwargs):
            response = func(**kwargs)
            for item in resources(response):
                if isinstance(item, dict) and item.get("assigned_to_name"):
                    item["assigned_to_name"] = "fixture-user"
            return response
        return call

    get_alerts = hide_names(keep_fields(falcon.get_alerts_v2, ALERT_WRITE_FIELDS))
    if rec.dry_run:
        ids = ["x:ind:x:1", "x:ind:x:2"]
    else:
        ids = sorted({i.strip() for i in os.environ.get("FALCON_TEST_ALERT_IDS", "").split(",") if i.strip()})
        if len(ids) != 2:
            raise SystemExit(
                "alert_write: set FALCON_TEST_ALERT_IDS to the composite IDs of 2 test alerts "
                "that the recording may change (found %d)" % len(ids)
            )
        found = resources(falcon.get_alerts_v2(composite_ids=ids))
        if len(found) != 2:
            raise SystemExit("alert_write: FALCON_TEST_ALERT_IDS must name 2 alerts that exist (found %d)" % len(found))
    if rec.cleanup_only:
        return

    def state():
        body = falcon.get_alerts_v2(composite_ids=ids)["body"]
        return {a["composite_id"]: {k: a.get(k) for k in ALERT_WRITE_FIELDS} for a in body.get("resources") or []}

    def summary(states):
        # Print no assignee name or email, only whether the alert has one.
        return [
            {"status": v["status"], "resolution": v["resolution"], "tags": v["tags"],
             "assigned": bool(v["assigned_to_uuid"] or v["assigned_to_name"]),
             "show_in_ui": v["show_in_ui"], "comments": len(v["comments"] or [])}
            for _key, v in sorted(states.items())
        ]

    def update(case, actions, target=None):
        return rec.call(case, "update_alerts_v3", falcon.update_alerts_v3,
                        composite_ids=target or ids, action_parameters=actions)

    def get(case, target=None):
        return rec.call(case, "get_alerts_v2", get_alerts, composite_ids=target or ids)

    before = {} if rec.dry_run else state()
    print("  before: %s" % summary(before))
    assignee = {}
    if not rec.dry_run:
        assigned = [
            a for a in resources(falcon.get_alerts_combined(filter="assigned_to_uuid:*'*'", limit=50))
            if a.get("assigned_to_uuid") and a.get("assigned_to_uid")
        ]
        if assigned:
            assignee = {"uuid": assigned[0]["assigned_to_uuid"], "uid": assigned[0]["assigned_to_uid"]}
    tag = "%s-tag" % PREFIX
    first = before.get(ids[0], {})
    status = "reopened" if first.get("status") == "in_progress" else "in_progress"
    cid = ids[0].split(":", 1)[0]
    missing_id = "%s:ind:%s:0-0-0" % (cid, "f" * 32)
    try:
        get("get_before")
        get("get_one_missing", target=[ids[0], missing_id])
        update("update_status", [{"name": "update_status", "value": status}])
        get("get_after_status")
        update("update_tags", [{"name": "add_tag", "value": "true_positive"}, {"name": "add_tag", "value": tag}])
        get("get_after_tags")
        update("update_resolution_change", [{"name": "add_tag", "value": "false_positive"}])
        get("get_after_resolution_change")
        update("update_remove_tags", [{"name": "remove_tag", "value": "false_positive"}, {"name": "remove_tag", "value": tag}])
        get("get_after_remove_tags")
        if assignee or rec.dry_run:
            update("update_assign_uuid", [{"name": "assign_to_uuid", "value": assignee.get("uuid", "x")}])
            get("get_after_assign_uuid")
            update("update_unassign", [{"name": "unassign", "value": ""}])
            get("get_after_unassign")
            update("update_assign_user_id", [{"name": "assign_to_user_id", "value": assignee.get("uid", "x")}])
            get("get_after_assign_user_id")
        flip = "true" if first.get("show_in_ui") is False else "false"
        update("update_show_in_ui", [{"name": "show_in_ui", "value": flip}])
        get("get_after_show_in_ui")
        # The dots keep the text under 40 characters of one run, which test_fixtures_clean.py rejects.
        text = "%s-comment-%s" % (PREFIX, datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%dT%H%M%SZ"))
        update("update_comment", [{"name": "append_comment", "value": text}], target=[ids[0]])
        update("update_unknown_uuid", [{"name": "assign_to_uuid", "value": str(uuid.uuid4())}])
    finally:
        if not rec.dry_run:
            now = state()
            for cid_, old in before.items():
                cur = now.get(cid_, {})
                actions = [{"name": "update_status", "value": old["status"]}]
                for t in set(cur.get("tags") or []) - set(old.get("tags") or []):
                    actions.append({"name": "remove_tag", "value": t})
                for t in set(old.get("tags") or []) - set(cur.get("tags") or []):
                    actions.append({"name": "add_tag", "value": t})
                if old.get("assigned_to_uuid"):
                    if cur.get("assigned_to_uuid") != old["assigned_to_uuid"]:
                        actions.append({"name": "assign_to_uuid", "value": old["assigned_to_uuid"]})
                elif any(cur.get(k) for k in ("assigned_to_uuid", "assigned_to_uid", "assigned_to_name")):
                    actions.append({"name": "unassign", "value": ""})
                actions.append({"name": "show_in_ui", "value": "true" if old.get("show_in_ui") else "false"})
                falcon.update_alerts_v3(composite_ids=[cid_], action_parameters=actions)
            after = state()
            same = all(
                {k: v for k, v in after[i].items() if k != "comments"} == {k: v for k, v in before[i].items() if k != "comments"}
                for i in before
            )
            print("  restored: %s" % same)
            print("  after: %s" % summary(after))


def record_response_policy(rec, creds):
    """Record the ResponsePolicies calls used by response_policy and response_policy_info.

    The searches use the kwargs of the module: filter and sort only when set,
    offset=None and limit=5000. Each filter matches only the fixture policies.
    """
    from falconpy import HostGroup, ResponsePolicies

    falcon = ResponsePolicies(**creds)
    groups = HostGroup(**creds)
    shared = "%s-shared" % PREFIX
    mixed = "%s-Mixed-Case" % PREFIX
    created_names = [(shared, "Linux"), (shared, "Windows"), (mixed, "Linux")]
    missing_id = "f" * 32

    def fixture_policies():
        # name:*'x*' finds nothing when the value has a "-", so use ~ and check the prefix here.
        found = resources(falcon.query_combined_policies(filter="name:~'%s'" % PREFIX, offset=None, limit=5000))
        return [p for p in found if p.get("name", "").casefold().startswith(PREFIX)]

    def cleanup():
        if rec.dry_run:
            return
        found = fixture_policies()
        enabled = [p["id"] for p in found if p.get("enabled")]
        if enabled:
            # The API does not delete an enabled policy.
            falcon.perform_policies_action(action_name="disable", ids=enabled)
        ids = [p["id"] for p in found]
        if ids:
            falcon.delete_policies(ids=ids)
        left = fixture_policies()
        if left:
            sys.stderr.write("warning: %d response policy fixture(s) were not deleted\n" % len(left))
        group_ids = [g["id"] for g in resources(groups.query_combined_host_groups(filter="name:*'%s-rp-*'" % PREFIX))]
        if group_ids:
            groups.delete_host_groups(ids=group_ids)

    def search(case, **kwargs):
        return rec.call(case, "query_combined_policies", falcon.query_combined_policies, offset=None, limit=5000, **kwargs)

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        ids = []
        for name, platform in created_names:
            if rec.dry_run:
                ids.append("0" * 32)
                continue
            response = falcon.create_policies(
                body={"resources": [{"name": name, "platform_name": platform, "description": "Fixture policy"}]}
            )
            ids.append(resources(response)[0]["id"])

        rec.call("get_one", "get_policies", falcon.get_policies, ids=[ids[0]])
        rec.call("get_several", "get_policies", falcon.get_policies, ids=[ids[0], ids[1]])
        rec.call("get_missing", "get_policies", falcon.get_policies, ids=[missing_id])
        rec.call("get_one_missing", "get_policies", falcon.get_policies, ids=[ids[0], missing_id])
        rec.call("get_short_id", "get_policies", falcon.get_policies, ids=["abcdefg"])

        # name: shared, on Linux and Windows.
        search("query_by_name", filter="name:~'%s'" % shared)
        # name: shared, filter: platform_name:'Windows'.
        search("query_by_name_platform", filter="name:~'%s'+(platform_name:'Windows')" % shared)
        # name: the mixed-case name in another case.
        search("query_by_name_mixed_case", filter="name:~'%s'" % mixed.upper())
        # name: the prefix, which is only a part of each fixture name.
        search("query_by_name_partial", filter="name:~'%s'" % PREFIX)
        # name: a value with a quote and a backslash, escaped as the module does.
        search("query_by_name_quote", filter="name:~'%s-it\\'s\\\\x'" % PREFIX)
        # name: shared, filter: a platform with no fixture policy.
        search("query_by_name_missing", filter="name:~'%s'+(platform_name:'Mac')" % shared)
        # filter and sort.
        search("query_sorted", filter="name:~'%s'" % PREFIX, sort="name.asc")
        search("query_bad_filter", filter="name:'")

        # response_policy: the lifecycle of one more policy, with the kwargs of the module.
        crud = "%s-crud" % PREFIX

        def setting(setting_id):
            return [{"id": setting_id, "value": {"enabled": True}}]

        created = rec.call(
            "create", "create_policies", falcon.create_policies,
            body={"resources": [{
                "name": crud, "platform_name": "Linux", "description": "Fixture policy",
                "settings": setting("RealTimeFunctionality"),
            }]},
        )
        crud_id = "0" * 32 if rec.dry_run else resources(created)[0]["id"]
        created_windows = rec.call(
            "create_windows", "create_policies", falcon.create_policies,
            body={"resources": [{
                "name": crud, "platform_name": "Windows", "description": "Fixture policy",
                "settings": setting("FalconScripts"),
            }]},
        )
        windows_id = "0" * 32 if rec.dry_run else resources(created_windows)[0]["id"]
        rec.call("get_windows", "get_policies", falcon.get_policies, ids=[windows_id])
        rec.call(
            "query_by_exact_name", "query_combined_policies", falcon.query_combined_policies,
            filter="name:~'%s'+platform_name:'Linux'" % crud, limit=5000,
        )
        rec.call(
            "query_by_exact_name_missing", "query_combined_policies", falcon.query_combined_policies,
            filter="name:~'%s'+platform_name:'Mac'" % crud, limit=5000,
        )
        # A second policy with the name of the crud policy on the same platform.
        rec.call(
            "create_duplicate", "create_policies", falcon.create_policies,
            body={"resources": [{"name": crud, "platform_name": "Linux"}]},
        )
        rec.call(
            "update_missing", "update_policies", falcon.update_policies,
            body={"resources": [{"id": missing_id, "description": "x"}]},
        )
        rec.call(
            "update_description", "update_policies", falcon.update_policies,
            body={"resources": [{"id": crud_id, "description": "Updated fixture policy"}]},
        )
        rec.call(
            "update_settings", "update_policies", falcon.update_policies,
            body={"resources": [{"id": crud_id, "settings": setting("CustomScripts")}]},
        )
        rec.call(
            "update_both", "update_policies", falcon.update_policies,
            body={"resources": [{"id": crud_id, "description": "Fixture policy", "settings": setting("GetCommand")}]},
        )
        rec.call("get_updated", "get_policies", falcon.get_policies, ids=[crud_id])
        rec.call("enable", "perform_policies_action", falcon.perform_policies_action, action_name="enable", ids=[crud_id])
        rec.call("get_enabled", "get_policies", falcon.get_policies, ids=[crud_id])
        rec.call("delete_enabled", "delete_policies", falcon.delete_policies, ids=[crud_id])
        rec.call(
            "disable", "perform_policies_action", falcon.perform_policies_action, action_name="disable", ids=[crud_id]
        )
        rec.call("get_disabled", "get_policies", falcon.get_policies, ids=[crud_id])

        # response_policy host_groups: two new static groups, added to and removed from the crud policy.
        group_ids = ["1" * 32, "2" * 32]
        if not rec.dry_run:
            group_ids = [
                resources(groups.create_host_groups(name="%s-rp-%s" % (PREFIX, suffix), group_type="static"))[0]["id"]
                for suffix in ("a", "b")
            ]
        rec.call("hg_get_found", "get_host_groups", groups.get_host_groups, ids=group_ids)
        rec.call("hg_get_some_missing", "get_host_groups", groups.get_host_groups, ids=[group_ids[0], missing_id])
        rec.call("hg_get_all_missing", "get_host_groups", groups.get_host_groups, ids=[missing_id])
        rec.call("hg_get_bad_id", "get_host_groups", groups.get_host_groups, ids=["abcdefg"])
        rec.call(
            "add_groups", "perform_policies_action", falcon.perform_policies_action,
            action_name="add-host-group", ids=[crud_id],
            action_parameters=[{"name": "group_id", "value": g} for g in group_ids],
        )
        rec.call("get_with_groups", "get_policies", falcon.get_policies, ids=[crud_id])
        rec.call(
            "remove_group", "perform_policies_action", falcon.perform_policies_action,
            action_name="remove-host-group", ids=[crud_id],
            action_parameters=[{"name": "group_id", "value": group_ids[0]}],
        )
        rec.call("get_after_remove", "get_policies", falcon.get_policies, ids=[crud_id])
        rec.call(
            "add_groups_missing_policy", "perform_policies_action", falcon.perform_policies_action,
            action_name="add-host-group", ids=[missing_id],
            action_parameters=[{"name": "group_id", "value": group_ids[0]}],
        )
        rec.call("delete", "delete_policies", falcon.delete_policies, ids=[crud_id])
    finally:
        cleanup()


RTR_SESSION_FIELDS = ("session_id", "created_at", "pwd", "offline_queued", "existing_aid_sessions")
# A fixed rc marker, so that the tests can parse the recorded stdout.
RTR_MARKER = "__ANSIBLE_RTR_RC_0123456789abcdef__="
RTR_DIR = "/tmp/%s-dir" % PREFIX
RTR_PUT_NAME = "%s-put" % PREFIX


def load_rtr_utils():
    """Load plugins/plugin_utils/rtr.py by path; it needs only the standard library."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "rtr_utils", COLLECTION_ROOT / "plugins" / "plugin_utils" / "rtr.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def until_complete(admin, limit=120):
    """Wrap check_admin_command_status so that it polls until the command is complete.

    It follows sequence_id as the plugin does and returns the last response.
    """
    import time

    def call(cloud_request_id, sequence_id):
        deadline = time.time() + limit
        while True:
            response = admin.check_admin_command_status(cloud_request_id=cloud_request_id, sequence_id=sequence_id)
            part = (resources(response) or [{}])[0]
            if response.get("status_code") != 200 or part.get("complete") or time.time() > deadline:
                return response
            if part.get("sequence_id") not in (None, sequence_id):
                sequence_id = part["sequence_id"]
                continue
            time.sleep(0.5)

    return call


def record_rtr(rec, creds):
    """Record the RTR calls used by the rtr connection plugin.

    This is the only recorder that runs commands on a host. It runs only on the
    host that --rtr-device-id names, uses only PREFIX names and /tmp/PREFIX-*
    paths, runs harmless commands (echo, printf, sleep, mkdir, rm of its own
    files), and deletes its put-file and files at the end.
    """
    import time

    from falconpy import Hosts, RealTimeResponse, RealTimeResponseAdmin

    device_id = rec.rtr_device_id
    if not device_id:
        print("  rtr: needs --rtr-device-id <AID of a test host that you own>; no host calls are made.")
        if not rec.dry_run:
            return
    rtr_utils = load_rtr_utils()
    # A dry run makes no service objects; rec.call() does not call func then.
    rtr = admin = hosts = None
    if not rec.dry_run:
        rtr = RealTimeResponse(**creds)
        admin = RealTimeResponseAdmin(auth_object=rtr.auth_object)
        hosts = Hosts(auth_object=rtr.auth_object)
    session = {"id": ""}
    poll = until_complete(admin) if admin else None
    init = keep_fields(rtr.init_session, RTR_SESSION_FIELDS) if rtr else None
    if not rec.dry_run:
        # The Linux fixtures MUST NOT come from a Windows host; record_rtr_windows records that one.
        if rtr_platform(rtr, device_id) == "Windows":
            print("  rtr: %s is a Windows host; record it with the rtr_windows service. Nothing recorded." % device_id)
            return

    def submit(base_command, command_string):
        """Submit a command that is not saved, and return its cloud_request_id."""
        if rec.dry_run:
            print("  rtr/(not saved) <- execute_admin_command(%s)" % base_command)
            return "0" * 32
        response = admin.execute_admin_command(
            base_command=base_command, command_string=command_string,
            session_id=session["id"], persist=False,
        )
        return (resources(response) or [{}])[0].get("cloud_request_id", "")

    def run(base_command, command_string):
        """Run a command that is not saved and wait for it."""
        crid = submit(base_command, command_string)
        if not rec.dry_run:
            poll(cloud_request_id=crid, sequence_id=0)

    def raw(body):
        return "runscript -Raw=```" + rtr_utils.wrap_script(body, RTR_MARKER) + "``` -Timeout=30"

    def put_file_ids():
        listed = admin.list_put_files(filter="name:'%s'" % RTR_PUT_NAME)
        return resources(listed)

    def cleanup():
        if rec.dry_run:
            return
        if not session["id"]:
            opened = rtr.init_session(device_id=device_id, queue_offline=False)
            session["id"] = (resources(opened) or [{}])[0].get("session_id", "")
        run("cd", "cd /")
        run("runscript", raw("rm -f %s/*; rmdir %s 2>/dev/null; true" % (RTR_DIR, RTR_DIR)))
        ids = put_file_ids()
        if ids:
            admin.delete_put_files(ids=ids)

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        # Sessions
        opened = rec.call("init_session", "init_session", init, device_id=device_id, queue_offline=False)
        session["id"] = (resources(opened) or [{"session_id": ""}])[0].get("session_id", session["id"])
        rec.call("init_session_missing", "init_session", init, device_id="f" * 32, queue_offline=False)

        # runscript: one complete result with stdout, stderr and the rc marker
        body = "mkdir -p %s && echo out && echo err >&2 && exit 3" % RTR_DIR
        submitted = rec.call(
            "runscript_submit", "execute_admin_command", admin.execute_admin_command if admin else None,
            base_command="runscript", command_string=raw(body), session_id=session["id"], persist=False,
        )
        crid = (resources(submitted) or [{"cloud_request_id": "0" * 32}])[0]["cloud_request_id"]
        rec.call(
            "runscript_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0,
        )

        # runscript: output in parts. Each first response of a kind is saved in order.
        crid = submit("runscript", raw("echo first; sleep 3; echo second"))
        seq = 0
        saved = set()
        deadline = time.time() + 120
        while not rec.dry_run and time.time() < deadline:
            response = admin.check_admin_command_status(cloud_request_id=crid, sequence_id=seq)
            part = (resources(response) or [{}])[0]
            if part.get("complete"):
                rec.cases.append("parts_complete")
                rec.save("parts_complete", "check_admin_command_status", response)
                break
            if part.get("sequence_id") not in (None, seq):
                if "parts_next" not in saved:
                    saved.add("parts_next")
                    rec.cases.append("parts_next")
                    rec.save("parts_next", "check_admin_command_status", response)
                seq = part["sequence_id"]
                continue
            if "parts_waiting" not in saved:
                saved.add("parts_waiting")
                rec.cases.append("parts_waiting")
                rec.save("parts_waiting", "check_admin_command_status", response)
            time.sleep(0.5)
        if rec.dry_run:
            # The loop above does not run in a dry run. List its cases, so that --only accepts them.
            for case in ("parts_waiting", "parts_next", "parts_complete"):
                rec.call(case, "check_admin_command_status", None, cloud_request_id=crid, sequence_id=seq)

        # runscript: the RTR timeout of the script
        crid = submit("runscript", "runscript -Raw=```sleep 5``` -Timeout=2")
        rec.call("timeout_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)

        # A stray backtick is refused before anything runs.
        rec.call(
            "runscript_backtick", "execute_admin_command", admin.execute_admin_command if admin else None,
            base_command="runscript", command_string="runscript -Raw=```echo a``` `",
            session_id=session["id"], persist=False,
        )

        # Put-files
        content = b"ansible unit fixture\n"
        rec.call(
            "create_put_files", "create_put_files", admin.create_put_files if admin else None,
            files=[("file", (RTR_PUT_NAME, content, "application/octet-stream"))], name=RTR_PUT_NAME,
            description="Ansible crowdstrike.falcon.rtr transfer",
            comments_for_audit_log="Ansible crowdstrike.falcon.rtr put_file",
        )
        listed = rec.call(
            "list_put_files", "list_put_files", admin.list_put_files if admin else None,
            filter="name:'%s'" % RTR_PUT_NAME,
        )
        rec.call(
            "list_put_files_missing", "list_put_files", admin.list_put_files if admin else None,
            filter="name:'%s-missing'" % PREFIX,
        )

        # cd and put
        for case, path in (("cd_missing", "/tmp/%s-missing" % PREFIX), ("cd_dir", RTR_DIR)):
            crid = submit("cd", "cd %s" % path)
            rec.call(case + "_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)
        for case in ("put", "put_exists"):
            crid = submit("put", "put %s" % RTR_PUT_NAME)
            rec.call(case + "_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)
        crid = submit("cd", "cd /")
        rec.call("cd_root_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)

        rec.call(
            "delete_put_files", "delete_put_files", admin.delete_put_files if admin else None,
            ids=resources(listed) or ["0" * 32],
        )

        # Hosts: the name lookup of the plugin. The host name comes from the API.
        details = keep_fields(hosts.get_device_details, HOST_FIELDS) if hosts else None
        found = rec.call("device_details", "get_device_details", details, ids=[device_id])
        hostname = (resources(found) or [{"hostname": "%s-host" % PREFIX}])[0].get("hostname") or ""
        rec.call(
            "query_by_name", "query_devices_by_filter", hosts.query_devices_by_filter if hosts else None,
            filter="hostname:'%s'" % hostname, limit=100,
        )
        rec.call(
            "query_by_name_missing", "query_devices_by_filter", hosts.query_devices_by_filter if hosts else None,
            filter="hostname:'%s-missing'" % PREFIX, limit=100,
        )
        # Added after the cases above, so that their fake IDs stay the same.
        rec.call(
            "query_by_name_bad_filter", "query_devices_by_filter", hosts.query_devices_by_filter if hosts else None,
            filter="hostname:'", limit=100,
        )
        rec.call("device_details_missing", "get_device_details", details, ids=["f" * 32])
        rec.call(
            "status_missing", "check_admin_command_status",
            admin.check_admin_command_status if admin else None,
            cloud_request_id="ffffffff-ffff-ffff-ffff-ffffffffffff", sequence_id=0,
        )

        # fetch: the scripts of RTRSession.fetch on a 5 byte file
        src = "%s/fetch" % RTR_DIR
        run("runscript", raw("mkdir -p %s && printf hello > %s" % (RTR_DIR, src)))
        fetch_scripts = (
            ("fetch_missing", "test -f /tmp/%s-missing || exit 1\nwc -c < /tmp/%s-missing" % (PREFIX, PREFIX)),
            ("fetch_size", "test -f %s || exit 1\nwc -c < %s" % (src, src)),
            ("fetch_read", "test -f %s || exit 1\nbase64 < %s | tr -d '\\n'" % (src, src)),
        ) + tuple(
            (
                "fetch_part%d" % part,
                "test -f %s || exit 1\ndd if=%s bs=1048576 skip=%d count=1 2>/dev/null | base64 | tr -d '\\n'"
                % (src, src, part),
            )
            for part in (1,)
        )
        for case, body in fetch_scripts:
            crid = submit("runscript", raw(body))
            rec.call(case + "_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)
    finally:
        cleanup()
    rec.call("delete_session", "delete_session", rtr.delete_session if rtr else None, session_id=session["id"])


def rtr_platform(rtr, device_id):
    """Return the platform that init_session reports for the host, or None."""
    opened = rtr.init_session(device_id=device_id, queue_offline=False)
    return (resources(opened) or [{}])[0].get("platform")


RTR_WIN_SESSION_FIELDS = RTR_SESSION_FIELDS + ("platform",)
RTR_WIN_DIR = "C:\\Windows\\Temp\\%s-dir" % PREFIX
RTR_WIN_PUT_NAME = "%s-win-put" % PREFIX


def record_rtr_windows(rec, creds):
    """Record the RTR calls of the rtr connection plugin on a Windows host.

    It runs only on the host that --rtr-device-id names, and only when
    init_session reports the platform Windows. The scripts come from the
    PowerShell builders of plugins/plugin_utils/rtr.py, so the recorded output
    is what the plugin parses. It runs harmless commands (Write-Output, exit
    codes, New-Item and Remove-Item of its own files), uses only PREFIX names
    and C:\\Windows\\Temp\\PREFIX-* paths, and deletes its put-file and files
    at the end.
    """
    from falconpy import RealTimeResponse, RealTimeResponseAdmin

    device_id = rec.rtr_device_id
    if not device_id:
        print("  rtr_windows: needs --rtr-device-id <AID of a Windows test host that you own>; no host calls are made.")
        if not rec.dry_run:
            return
    rtr_utils = load_rtr_utils()
    rtr = admin = None
    if not rec.dry_run:
        rtr = RealTimeResponse(**creds)
        admin = RealTimeResponseAdmin(auth_object=rtr.auth_object)
        platform = rtr_platform(rtr, device_id)
        if platform != "Windows":
            print("  rtr_windows: %s is not a Windows host (platform %s). Nothing recorded." % (device_id, platform))
            return
    session = {"id": ""}
    poll = until_complete(admin) if admin else None
    init = keep_fields(rtr.init_session, RTR_WIN_SESSION_FIELDS) if rtr else None

    def submit(base_command, command_string):
        """Submit a command that is not saved, and return its cloud_request_id."""
        if rec.dry_run:
            print("  rtr_windows/(not saved) <- execute_admin_command(%s)" % base_command)
            return "0" * 32
        response = admin.execute_admin_command(
            base_command=base_command, command_string=command_string,
            session_id=session["id"], persist=False,
        )
        return (resources(response) or [{}])[0].get("cloud_request_id", "")

    def run(base_command, command_string):
        """Run a command that is not saved and wait for it."""
        crid = submit(base_command, command_string)
        if not rec.dry_run:
            poll(cloud_request_id=crid, sequence_id=0)

    def runscript(script):
        return "runscript -Raw=```" + script + "``` -Timeout=30"

    def wrapped(body):
        """A body wrapped as RTRSession.run_with_rc wraps it on Windows."""
        return runscript(rtr_utils.ps_wrap(body, RTR_MARKER))

    def record(case, base_command, command_string):
        crid = submit(base_command, command_string)
        rec.call(case + "_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)

    def put_file_ids():
        listed = admin.list_put_files(filter="name:'%s'" % RTR_WIN_PUT_NAME)
        return resources(listed)

    def cleanup():
        if rec.dry_run:
            return
        if not session["id"]:
            opened = rtr.init_session(device_id=device_id, queue_offline=False)
            session["id"] = (resources(opened) or [{}])[0].get("session_id", "")
        run("cd", "cd C:\\")
        run("runscript", wrapped(
            "if (Test-Path -LiteralPath (%s)) { Remove-Item -LiteralPath (%s) -Recurse -Force }"
            % (rtr_utils.ps_text(RTR_WIN_DIR), rtr_utils.ps_text(RTR_WIN_DIR))
        ))
        ids = put_file_ids()
        if ids:
            admin.delete_put_files(ids=ids)

    if rec.cleanup_only:
        cleanup()
        return

    cleanup()
    try:
        opened = rec.call("init_session", "init_session", init, device_id=device_id, queue_offline=False)
        session["id"] = (resources(opened) or [{"session_id": ""}])[0].get("session_id", session["id"])

        # exec_command with no stdin: rc 3, stdout and stderr apart
        # At exit the child host writes a CLIXML progress record to stderr. Its base64
        # in the marker line is one long opaque string, so these commands end with
        # [Environment]::Exit, which skips that record.
        script = rtr_utils.ps_exec_script(
            "[Console]::Out.WriteLine('out'); [Console]::Error.WriteLine('err'); [Environment]::Exit(3)", RTR_MARKER
        )
        submitted = rec.call(
            "runscript_submit", "execute_admin_command", admin.execute_admin_command if admin else None,
            base_command="runscript", command_string=runscript(script), session_id=session["id"], persist=False,
        )
        crid = (resources(submitted) or [{"cloud_request_id": "0" * 32}])[0]["cloud_request_id"]
        rec.call("exec_complete", "check_admin_command_status", poll, cloud_request_id=crid, sequence_id=0)

        stdin_cmd = "[Console]::Out.WriteLine('in=' + (@($input) -join ',')); [Environment]::Exit(0)"
        record("exec_inline", "runscript", runscript(rtr_utils.ps_exec_script(stdin_cmd, RTR_MARKER, stdin_data=b"a\nb\n")))
        # The CLIXML stderr of a child that writes an error record. Its base64 in a
        # marker line is one long opaque string, so this script prints it as text.
        child = base64.b64encode((rtr_utils.PS_UTF8_PREFIX + "Write-Error 'boom'").encode("utf-16-le")).decode("ascii")
        record("clixml_text", "runscript", runscript(
            "$__psi = New-Object System.Diagnostics.ProcessStartInfo\n"
            "$__psi.FileName = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'\n"
            "$__psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s'\n"
            "$__psi.UseShellExecute = $false; $__psi.CreateNoWindow = $true\n"
            "$__psi.RedirectStandardInput = $true; $__psi.RedirectStandardError = $true\n"
            "$__p = [System.Diagnostics.Process]::Start($__psi); $__p.StandardInput.Close()\n"
            "$__e = $__p.StandardError.ReadToEnd(); $__p.WaitForExit()\n"
            "Write-Output $__e" % child
        ))
        record("win_temp", "runscript", wrapped("$__o = [IO.Path]::GetFullPath($env:TEMP)"))

        # An error record that escapes a plain runscript: RTR drops the stdout before it.
        record("runscript_error", "runscript", runscript("Write-Output out\nWrite-Error err"))
        # The RTR timeout of the script
        record("timeout", "runscript", "runscript -Raw=```Start-Sleep 25``` -Timeout=10")

        # Put-files
        content = b"a\nb\n"
        rec.call(
            "create_put_files", "create_put_files", admin.create_put_files if admin else None,
            files=[("file", (RTR_WIN_PUT_NAME, content, "application/octet-stream"))], name=RTR_WIN_PUT_NAME,
            description="Ansible crowdstrike.falcon.rtr transfer",
            comments_for_audit_log="Ansible crowdstrike.falcon.rtr put_file",
        )
        listed = rec.call(
            "list_put_files", "list_put_files", admin.list_put_files if admin else None,
            filter="name:'%s'" % RTR_WIN_PUT_NAME,
        )

        # cd, the stage folder, put, cd C:\
        record("cd_missing", "cd", "cd C:\\Windows\\Temp\\%s-missing" % PREFIX)
        record("mkdir", "runscript", wrapped(
            "$null = New-Item -ItemType Directory -Force -Path (%s)" % rtr_utils.ps_text(RTR_WIN_DIR)
        ))
        record("cd_dir", "cd", "cd %s" % RTR_WIN_DIR)
        record("put", "put", "put %s" % RTR_WIN_PUT_NAME)
        record("put_exists", "put", "put %s" % RTR_WIN_PUT_NAME)
        record("cd_root", "cd", "cd C:\\")

        rec.call(
            "delete_put_files", "delete_put_files", admin.delete_put_files if admin else None,
            ids=resources(listed) or ["0" * 32],
        )

        # exec_command with stdin from the put-file; the script removes the file.
        stdin_path = RTR_WIN_DIR + "\\" + RTR_WIN_PUT_NAME
        record("exec_file", "runscript", runscript(rtr_utils.ps_exec_script(stdin_cmd, RTR_MARKER, stdin_path=stdin_path)))

        # put_inline, the move of an upload, and fetch: the bodies of RTRSession on Windows
        inline = RTR_WIN_DIR + "\\inline"
        src = RTR_WIN_DIR + "\\fetch"
        record("put_inline", "runscript", wrapped(
            "$__p = %s\n" % rtr_utils.ps_text(inline)
            + "[IO.File]::WriteAllBytes($__p + '.rtrtmp', [Convert]::FromBase64String('%s'))\n" % rtr_utils.b64(b"hello")
            + "Move-Item -LiteralPath ($__p + '.rtrtmp') -Destination $__p -Force"
        ))
        record("move", "runscript", wrapped(
            "Move-Item -LiteralPath (%s) -Destination (%s) -Force" % (rtr_utils.ps_text(inline), rtr_utils.ps_text(src))
        ))

        def size_body(path):
            return (
                "$__p = %s\n" % rtr_utils.ps_text(path)
                + "if (-not (Test-Path -LiteralPath $__p -PathType Leaf)) { $__rc = 1 }"
                + " else { $__o = [string](Get-Item -LiteralPath $__p).Length }"
            )

        record("fetch_missing", "runscript", wrapped(size_body("C:\\Windows\\Temp\\%s-missing" % PREFIX)))
        record("fetch_size", "runscript", wrapped(size_body(src)))
        record("fetch_read", "runscript", wrapped(
            "$__p = %s\n" % rtr_utils.ps_text(src) + "$__o = [Convert]::ToBase64String([IO.File]::ReadAllBytes($__p))"
        ))
    finally:
        cleanup()
    rec.call("delete_session", "delete_session", rtr.delete_session if rtr else None, session_id=session["id"])


SCENARIOS = {
    "alert_write": record_alert_write,
    "alerts": record_alerts,
    "auth": record_auth,
    "case": record_case,
    "case_write": record_case_write,
    "correlation_rule": record_correlation_rule,
    "discover": record_discover,
    "flight_control": record_flight_control,
    "host_group": record_host_group,
    "hosts": record_hosts,
    "hunting": record_hunting,
    "intel": record_intel,
    "ngsiem": record_ngsiem,
    "prevention_policy": record_prevention_policy,
    "response_policy": record_response_policy,
    "rtr": record_rtr,
    "rtr_windows": record_rtr_windows,
    "sensor_download": record_sensor_download,
    "sensor_update_policy": record_sensor_update_policy,
}


def load_env(env_file):
    """Load env_file into the environment, if it exists. Existing variables win."""
    if not env_file.is_file():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        sys.stderr.write("note: python-dotenv is not installed; using the existing environment.\n")
        return
    load_dotenv(dotenv_path=env_file, override=False)


def parse_only(names, services):
    """Return {service: set of cases} for the --only names, or raise ValueError.

    A name is SERVICE:CASE, or only CASE when the command names one service.
    The cases of each service come from a dry run, so a wrong name fails
    before any API call.
    """
    selected = {}
    for name in names:
        service, _sep, case = name.rpartition(":")
        if not service:
            if len(services) != 1:
                raise ValueError("--only %s: name one service, or use SERVICE:CASE" % name)
            service = services[0]
        if service not in SCENARIOS:
            raise ValueError("--only %s: unknown service %s" % (name, service))
        if services and service not in services:
            raise ValueError("--only %s: %s is not one of the services to record" % (name, service))
        selected.setdefault(service, set()).add(case)
    unselected = [s for s in services if s not in selected]
    if unselected:
        raise ValueError("--only names no case of: %s" % ", ".join(unselected))
    for service, cases in sorted(selected.items()):
        rec = Recorder(service, Sanitizer(), dry_run=True)
        with contextlib.redirect_stdout(io.StringIO()):
            SCENARIOS[service](rec, {})
        unknown = sorted(cases - set(rec.cases))
        if unknown:
            raise ValueError(
                "--only: %s does not record %s. Run --dry-run %s to list its cases."
                % (service, ", ".join(unknown), service)
            )
    return selected


def identity(item):
    """Return the name and platform of an API object, or None if it has no name."""
    if not isinstance(item, dict):
        return None
    name = item.get("name") or item.get("Name")
    return (name, str(item.get("platform_name"))) if isinstance(name, str) else None


def fake_values(data):
    """Return the fake values in data, to compare two recordings of a case.

    An object with a fake value also adds its name, so that two objects
    that changed places in a list are found, also when the list is the
    first place where the service saw their IDs. A list of objects with a
    unique name and platform is compared in any order, because the API
    does not always return such a list in the same order. Each object
    still keeps its own fake values.
    """
    if isinstance(data, dict):
        found = [v for _k, value in sorted(data.items()) for v in fake_values(value)]
        name = data.get("name") or data.get("Name")
        if found and isinstance(name, str):
            found.insert(0, "name=" + name)
        return found
    if isinstance(data, list):
        items = [fake_values(value) for value in data]
        keys = [identity(value) for value in data]
        if None not in keys and len(set(keys)) == len(keys):
            items = [found for _key, found in sorted(zip(keys, items))]
        return [v for found in items for v in found]
    if isinstance(data, str):
        return FAKE_VALUE_RE.findall(data)
    return []


def order_problems(rec, cases):
    """Return the cases not in cases whose fake values differ from their fixture file.

    The Sanitizer gives fake values in the order in which it sees the real
    values. If a case that is not written now has other fake values than its
    file, the order changed since the files were recorded, and the new files
    would not agree with the old ones.
    """
    problems = []
    for case, data in rec.files.items():
        path = FIXTURES_DIR / rec.service / (case + ".json")
        if case in cases or data is None or not path.is_file():
            continue
        if fake_values(data) != fake_values(json.loads(path.read_text())):
            problems.append("%s/%s" % (rec.service, case))
    return problems


def main():
    """Parse arguments, run the requested scenarios, and write the fixtures."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("services", nargs="*", help="Services to record. Default: all.")
    parser.add_argument("--env-file", type=Path, default=COLLECTION_ROOT / ".env")
    parser.add_argument("--dry-run", action="store_true", help="List the calls; do not call the API.")
    parser.add_argument("--list", action="store_true", help="List the services and exit.")
    parser.add_argument(
        "--wait", type=int, default=2700,
        help="Seconds to wait for objects that the API is still provisioning (default: 2700).",
    )
    parser.add_argument(
        "--cleanup", action="store_true",
        help="Only delete the fixture objects that an earlier run left behind.",
    )
    parser.add_argument(
        "--only", nargs="+", metavar="CASE",
        help="Write only these cases (SERVICE:CASE, or CASE with one service). "
        "Every call of the service still runs, so the fake IDs stay the same.",
    )
    parser.add_argument(
        "--rtr-device-id", metavar="AID",
        help="Device ID of a test host that you own. The rtr service runs commands only on this host, "
        "and records nothing without it.",
    )
    args = parser.parse_args()

    if args.list:
        print("\n".join(sorted(SCENARIOS)))
        return 0

    services = args.services or sorted(SCENARIOS)
    unknown = [s for s in services if s not in SCENARIOS]
    if unknown:
        sys.stderr.write("error: unknown service(s): %s\n" % ", ".join(unknown))
        return 1

    only = None
    if args.only:
        if args.cleanup:
            sys.stderr.write("error: --only cannot be used with --cleanup\n")
            return 1
        try:
            only = parse_only(args.only, args.services)
        except ValueError as error:
            sys.stderr.write("error: %s\n" % error)
            return 1
        services = args.services or sorted(only)

    creds = {}
    secrets = {}
    if not args.dry_run:
        load_env(args.env_file)
        missing = [var for var in REQUIRED_ENV if not os.environ.get(var)]
        if missing:
            sys.stderr.write("error: missing environment variable(s): %s\n" % ", ".join(missing))
            return 1
        creds = {
            "client_id": os.environ["FALCON_CLIENT_ID"],
            "client_secret": os.environ["FALCON_CLIENT_SECRET"],
            "base_url": os.environ.get("FALCON_CLOUD") or "us-1",
        }
        if os.environ.get("FALCON_MEMBER_CID"):
            creds["member_cid"] = os.environ["FALCON_MEMBER_CID"]
        secrets = {name: os.environ[name] for name in SECRET_ENV if len(os.environ.get(name, "")) >= 6}

    recorders = []
    for service in services:
        print("Recording %s" % service)
        # Each service gets its own Sanitizer, so its fake IDs do not depend
        # on the other services that are recorded in the same run.
        rec = Recorder(service, Sanitizer(), args.dry_run, args.wait, args.cleanup)
        rec.rtr_device_id = args.rtr_device_id
        SCENARIOS[service](rec, creds)
        recorders.append(rec)

    if args.dry_run or args.cleanup:
        return 0

    if only:
        problems = []
        for rec in recorders:
            # A case that depends on a live response (a paused connection,
            # for example) is not always recorded.
            missing = sorted(case for case in only[rec.service] if rec.files.get(case) is None)
            problems += ["%s/%s was not recorded" % (rec.service, case) for case in missing]
            problems += ["%s has other fake values than its file" % name for name in order_problems(rec, only[rec.service])]
        if problems:
            sys.stderr.write(
                "error: --only cannot keep the other files of the service; no files written. "
                "Record the whole service instead:\n"
            )
            sys.stderr.write("".join("  %s\n" % p for p in problems))
            return 1
        for rec in recorders:
            rec.files = {case: data for case, data in rec.files.items() if case in only[rec.service]}

    # Check every file before any file is written.
    outputs = {}
    problems = []
    for rec in recorders:
        for case, data in rec.files.items():
            text = json.dumps(data, indent=2, sort_keys=True) + "\n"
            # Check against the values that every service saw.
            leaks = sorted({found for other in recorders for found in other.sanitizer.leaks(text, secrets)})
            if leaks:
                problems.append("%s/%s: %s" % (rec.service, case, ", ".join(leaks)))
            outputs[FIXTURES_DIR / rec.service / (case + ".json")] = text
    if problems:
        sys.stderr.write("error: tenant data found after sanitizing; no files written:\n")
        sys.stderr.write("".join("  %s\n" % p for p in problems))
        return 1

    for path, text in sorted(outputs.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print("Wrote %d fixture file(s) to %s" % (len(outputs), FIXTURES_DIR))
    return 0


if __name__ == "__main__":
    sys.exit(main())
