# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.module_utils import (
    falconctl_utils,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconctl_utils import (
    format_stdout,
    get_options,
    resolve_tags,
    tags_equal,
)


# Tag values that contain the name of another option ("version", "aph",
# "rfm-reason") used to route the output to that option's parser, which left
# quotes and trailing dots in the value.
@pytest.mark.parametrize(
    "stdout, expected",
    [
        ('tags="graphql,prod".', "graphql,prod"),
        ('tags="graph-db".\n', "graph-db"),
        ('tags="conversion".', "conversion"),
        ('tags="v2-version".\n', "v2-version"),
        ('tags="prod-aph".\n', "prod-aph"),
        ('tags="rfm-reason-test".\n', "rfm-reason-test"),
        # Captured from sensors 7.21 through 8.11: no quotes around the value.
        ("tags=graph-db,prod-aph,v2-version.\n", "graph-db,prod-aph,v2-version"),
        # Linux sensors accept '.' and '@' in tags; only the sentence dot at
        # the end is removed.
        ("tags=v1.2,team@corp,graph-db.\n", "v1.2,team@corp,graph-db"),
        ('tags="v1.2".', "v1.2"),
        # A user-defined tag may legitimately contain the word "deprecated";
        # it must not be mistaken for a deprecation notice and dropped.
        ('tags="deprecated-web,prod".', "deprecated-web,prod"),
    ],
    ids=[
        "graph",
        "graph-db",
        "conversion",
        "version",
        "aph",
        "rfm-reason",
        "sensor-format",
        "dots-and-at",
        "quoted-dots",
        "deprecated",
    ],
)
def test_tag_values_are_not_routed_by_content(stdout, expected):
    assert format_stdout(stdout, "tags") == expected


@pytest.mark.parametrize(
    "opt, stdout, expected",
    [
        # The version branch must keep dots in the value.
        ("version", "version = 7.40.19311.0\n", "7.40.19311.0"),
        # The aph branch keeps dots inside the host name and drops the
        # trailing sentence dot, with or without a newline.
        ("aph", "aph=proxy.example.com.\n", "proxy.example.com"),
        ("aph", "aph=proxy.example.com.", "proxy.example.com"),
        # Captured from sensors 7.40 and 8.11.
        ("rfm_reason", "rfm-reason=None, code=0x0.\n", "None,code=0x0"),
        ("rfm_state", "rfm-state=false.\n", "false"),
        (
            "aid",
            'aid="2f87f0a9e0b74fcc8b375dec8827a3eb".',
            "2f87f0a9e0b74fcc8b375dec8827a3eb",
        ),
        (
            "cid",
            'cid="0123456789abcdef0123456789abcdef-12".\n',
            "0123456789abcdef0123456789abcdef-12",
        ),
        ("app", "app=8080.\n", "8080"),
        # Parenthesized notes are removed from the value.
        ("trace", "trace=none (default).\n", "none"),
    ],
    ids=[
        "version",
        "aph-newline",
        "aph-no-newline",
        "rfm_reason",
        "rfm_state",
        "aid",
        "cid",
        "app",
        "parenthesized-note",
    ],
)
def test_value_is_extracted(opt, stdout, expected):
    assert format_stdout(stdout, opt) == expected


def test_empty_returns_none():
    assert format_stdout("", "tags") is None


def test_not_set_returns_none():
    assert format_stdout("apd is not set.", "apd") is None


@pytest.mark.parametrize(
    "opt, stdout",
    [
        # Sensor 7.40+ deprecated the --backend option; it prints a notice
        # with no '=' delimiter, which used to raise IndexError (issue #709).
        (
            "backend",
            "This option is deprecated and will be ignored. "
            "It may be removed in a future sensor release.\n",
        ),
        ("cloud", "some unexpected output\n"),
    ],
    ids=["backend-deprecation-notice", "unexpected-output"],
)
def test_missing_delimiter_returns_none(opt, stdout):
    assert format_stdout(stdout, opt) is None


class FakeModule(object):
    """Stand-in for AnsibleModule that returns canned falconctl output.

    outputs maps an option flag to (rc, stdout, stderr).
    """

    def __init__(self):
        self.outputs = {}
        self.calls = []
        self.bin_path_calls = []

    def get_bin_path(self, arg, required=False, opt_dirs=None):
        self.bin_path_calls.append((arg, required, opt_dirs))
        return "/opt/CrowdStrike/falconctl"

    def run_command(self, cmd, **kwargs):
        self.calls.append(cmd)
        return self.outputs[cmd[-1]]


@pytest.fixture
def module():
    return FakeModule()


def test_get_options_parses_tags_by_option_name(module):
    module.outputs["--tags"] = (0, 'tags="graph-db,prod".\n', "")

    assert get_options(module, ["tags"]) == {"tags": "graph-db,prod"}
    assert module.calls == [["/opt/CrowdStrike/falconctl", "-g", "--tags"]]


def test_get_options_translates_underscores_on_command_line(module):
    module.outputs["--metadata-query"] = (0, "metadata-query=enable.\n", "")

    assert get_options(module, ["metadata_query"]) == {"metadata_query": "enable"}
    assert module.calls[0][-1] == "--metadata-query"


def test_get_options_returns_none_when_falconctl_fails(module):
    module.outputs["--apd"] = (255, "apd=TRUE.\n", "error")

    assert get_options(module, ["apd"]) == {"apd": None}


def test_get_options_reads_stderr(module):
    module.outputs["--cid"] = (0, "", "cid is not set.\n")
    module.outputs["--backend"] = (
        0,
        "backend=bpf.\n",
        "This option is deprecated and will be ignored.\n",
    )

    assert get_options(module, ["cid", "backend"]) == {"cid": None, "backend": "bpf"}


def test_get_options_rejects_unknown_option(module):
    with pytest.raises(ValueError, match="Invalid falconctl get option"):
        get_options(module, ["not_an_option"])


def test_get_options_finds_falconctl_once(module):
    module.outputs["--cid"] = (0, "cid=abc.\n", "")
    module.outputs["--aid"] = (0, "aid=def.\n", "")

    get_options(module, ["cid", "aid"])
    # required=True makes the module fail when falconctl is not found
    assert module.bin_path_calls == [("falconctl", True, ["/opt/CrowdStrike"])]


def test_get_options_without_names_returns_every_option(module):
    module.outputs = dict(
        ("--%s" % opt.replace("_", "-"), (0, "", "%s is not set.\n" % opt))
        for opt in falconctl_utils.FALCONCTL_GET_OPTIONS
    )

    result = get_options(module, [])
    assert sorted(result) == sorted(falconctl_utils.FALCONCTL_GET_OPTIONS)
    assert set(result.values()) == {None}


def test_resolve_tags_present_merges_with_existing():
    assert resolve_tags("tag1,tag2", ["tag3"], "present") == "tag1,tag2,tag3"


def test_resolve_tags_present_existing_tag_is_unchanged():
    assert resolve_tags("tag1,tag2", ["tag2"], "present") == "tag1,tag2"


def test_resolve_tags_present_with_no_current_tags():
    assert resolve_tags(None, ["tag1", "tag2"], "present") == "tag1,tag2"


def test_resolve_tags_present_dedupes_requested():
    assert resolve_tags("tag1", ["tag2", "tag2"], "present") == "tag1,tag2"


def test_resolve_tags_exclusive_replaces_existing():
    assert resolve_tags("tag1,old", ["tag1", "tag2"], "present", True) == "tag1,tag2"


def test_resolve_tags_exclusive_empty_list_clears():
    assert resolve_tags("tag1,tag2", [], "present", True) is None


def test_resolve_tags_absent_removes_only_listed():
    assert resolve_tags("tag1,tagLegacy,tag2", ["tagLegacy"], "absent") == "tag1,tag2"


def test_resolve_tags_absent_last_tag_clears():
    assert resolve_tags("tagLegacy", ["tagLegacy"], "absent") is None


def test_resolve_tags_absent_missing_tag_is_unchanged():
    assert resolve_tags("tag1", ["nope"], "absent") == "tag1"


def test_resolve_tags_absent_with_no_current_tags():
    assert resolve_tags(None, ["tag1"], "absent") is None


def test_tags_equal_ignores_order():
    assert tags_equal("tag1,tag2", "tag2,tag1")
    assert tags_equal(None, "")
    assert not tags_equal("tag1", "tag1,tag2")
