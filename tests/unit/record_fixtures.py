# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Record Falcon API responses as sanitized unit test fixtures.

The unit tests in tests/unit/plugins do not call the API. They replay the
responses that this script records from a real tenant. Run it again when a
plugin starts to use a new API call, or when FalconPy or the API changes.

The script calls FalconPy directly. For the services that can change state it
makes throwaway objects named 'ansible-unit-fixture-*' and deletes them when it
is done. It does not change hosts or other objects that it did not make.

Every response goes through the Sanitizer before it is written: IDs, emails,
IP and MAC addresses, host names and tokens are replaced. Then the script
checks that no credential and no original ID is left in the output. If one is
found, it writes no files.

Credentials are read from a .env file (via python-dotenv) or from the process
environment. Required: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET. Optional:
FALCON_CLOUD and FALCON_MEMBER_CID.

Usage:
    uv run --with crowdstrike-falconpy --with python-dotenv \\
        tests/unit/record_fixtures.py [--env-file PATH] [--dry-run] [SERVICE ...]
    uv run tests/unit/record_fixtures.py --list
"""

import argparse
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

HEX32_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
UUID_RE = re.compile(
    r"(?<![0-9a-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
GROUPING_TAG_RE = re.compile(r"((?:Sensor|Falcon)GroupingTags/)[^,\"'\s]+")

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
DROP_KEYS = {"trace_id", "powered_by"}


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
        self.maps = {"hex": {}, "uuid": {}, "email": {}, "host": {}, "ip": {}, "mac": {}, "tag": {}}

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
        if key in URL_KEYS and value:
            # The host name can identify the tenant; keep only the path.
            return "https://ingest.example.com/" + value.split("://", 1)[-1].partition("/")[2]
        if key in HOST_KEYS:
            return self._fake("host", value, lambda n: "host%d" % n) if value else value
        if "mac_address" in key:
            return self._fake("mac", value, lambda n: "00-00-5e-00-53-%02x" % (n % 256))
        if key.endswith("_ip") or key.endswith("ip_address") or key == "ip":
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
        self.files = {}

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
    rec.call(
        "builds_bad_platform", "query_combined_builds", falcon.query_combined_builds,
        platform="not-a-platform",
    )

    kernels = rec.call(
        "kernels_page", "query_combined_kernels", falcon.query_combined_kernels, limit=2,
    )
    release = (resources(kernels) or [{"release": "0"}])[0]["release"]
    rec.call(
        "kernels_filtered", "query_combined_kernels", falcon.query_combined_kernels,
        filter="release:'%s'" % release, offset=None, limit=500,
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
            repository=repo, filter="name:~'%s'" % parser_name, limit=100,
        )
        rec.call(
            "parser_list_missing", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s-missing'" % PREFIX, limit=100,
        )
        rec.call(
            "parser_list_bad_filter", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'", limit=100,
        )
        rec.call(
            "parser_template", "get_parser_template", falcon.get_parser_template,
            ids=parser_id, repository=repo,
        )
        rec.call("parser_get", "get_parser", falcon.get_parser, ids=parser_id, repository=repo)
        created_id = parser_id
        updated = rec.call(
            "parser_update", "update_parser_from_template", falcon.update_parser_from_template,
            ids=parser_id, repository=repo,
            yaml_template=PARSER_YAML.format(name=parser_name, dataset="fixture.updated"),
        )
        parser_id = parser_id_of(updated) or parser_id
        rec.call(
            "parser_get_created_id_after_update", "get_parser", falcon.get_parser,
            ids=created_id, repository=repo,
        )
        rec.call(
            "parser_list_after_update", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % parser_name, limit=100,
        )
        rec.call(
            "parser_template_after_update", "get_parser_template", falcon.get_parser_template,
            ids=created_id, repository=repo,
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
        rec.call(
            "parser_extension", "create_parser_extension", falcon.create_parser_extension,
            base_parser_id=base_id, extension_name=ext_name,
        )
        rec.call(
            "parser_info_page", "list_parsers", falcon.list_parsers,
            repository=repo, filter="name:~'%s'" % PREFIX, parser_type="custom", limit=2, offset=0,
        )
        rec.call("parser_delete", "delete_parser", falcon.delete_parser, ids=parser_id, repository=repo)
        rec.call(
            "parser_delete_missing", "delete_parser", falcon.delete_parser, ids=parser_id, repository=repo,
        )

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
            filter="name:'%s'" % connection_name, limit=1,
        )
        rec.call(
            "connection_list_missing", "list_data_connections", falcon.list_data_connections,
            filter="name:'%s-missing'" % PREFIX, limit=1,
        )
        rec.call(
            "connection_list_bad_filter", "list_data_connections", falcon.list_data_connections,
            filter="name:'", limit=1,
        )
        rec.call(
            "connection_status_new", "get_provisioning_status", falcon.get_provisioning_status,
            ids=connection_id,
        )
        token = rec.call(
            "token_first", "command:ExternalGetDataConnectionToken", uber.command,
            action="ExternalGetDataConnectionToken", ids=connection_id,
        )
        deadline = time.time() + 180
        while not rec.dry_run and token.get("status_code") == 202 and time.time() < deadline:
            time.sleep(5)
            token = rec.call(
                "token_ready", "command:ExternalGetDataConnectionToken", uber.command,
                action="ExternalGetDataConnectionToken", ids=connection_id,
            )
        rec.call(
            "token_again", "command:ExternalGetDataConnectionToken", uber.command,
            action="ExternalGetDataConnectionToken", ids=connection_id,
        )
        rec.call(
            "connection_update", "update_data_connection", falcon.update_data_connection,
            parameters={"ids": connection_id}, body=dict(body, parser="microsoft-edge"),
        )
        status = rec.call(
            "connection_status", "get_provisioning_status", falcon.get_provisioning_status,
            ids=connection_id,
        )
        if (resources(status) or [{}])[0].get("status") in ("Active", "Error", "Idle"):
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
            # A fast search can be done on the first status call.
            rec.files.setdefault(case + "_done", rec.files.get(case + "_status"))
        rec.call(
            "search_bad_query", "start_search", falcon.start_search,
            repository="search-all", query_string="| | not a query (", start="1h",
        )
    finally:
        cleanup()


SCENARIOS = {
    "correlation_rule": record_correlation_rule,
    "host_group": record_host_group,
    "ngsiem": record_ngsiem,
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
    args = parser.parse_args()

    if args.list:
        print("\n".join(sorted(SCENARIOS)))
        return 0

    services = args.services or sorted(SCENARIOS)
    unknown = [s for s in services if s not in SCENARIOS]
    if unknown:
        sys.stderr.write("error: unknown service(s): %s\n" % ", ".join(unknown))
        return 1

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

    sanitizer = Sanitizer()
    recorders = []
    for service in services:
        print("Recording %s" % service)
        rec = Recorder(service, sanitizer, args.dry_run, args.wait, args.cleanup)
        SCENARIOS[service](rec, creds)
        recorders.append(rec)

    if args.dry_run or args.cleanup:
        return 0

    # Check every file before any file is written.
    outputs = {}
    problems = []
    for rec in recorders:
        for case, data in rec.files.items():
            text = json.dumps(data, indent=2, sort_keys=True) + "\n"
            leaks = sanitizer.leaks(text, secrets)
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
