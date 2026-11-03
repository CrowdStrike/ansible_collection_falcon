# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from subprocess import CalledProcessError

import pytest

from ansible_collections.crowdstrike.falcon.plugins.module_utils import (
    falconctl_utils,
)
from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconctl_utils import (
    format_stdout,
    get_options,
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


@pytest.fixture
def falconctl(monkeypatch):
    """Replace the falconctl binary with canned output per option flag."""
    outputs = {}
    calls = []

    def fake_check_output(cmd, **kwargs):
        calls.append(cmd)
        result = outputs[cmd[-1]]
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(falconctl_utils, "check_output", fake_check_output)
    monkeypatch.setattr(
        falconctl_utils, "_FALCONCTL", "/opt/CrowdStrike/falconctl", raising=False
    )
    monkeypatch.setattr(falconctl_utils, "FALCONCTL_NOT_FOUND", False)
    return outputs, calls


def test_get_options_parses_tags_by_option_name(falconctl):
    outputs, calls = falconctl
    outputs["--tags"] = 'tags="graph-db,prod".\n'

    assert get_options(["tags"]) == {"tags": "graph-db,prod"}
    assert calls == [["/opt/CrowdStrike/falconctl", "-g", "--tags"]]


def test_get_options_translates_underscores_on_command_line(falconctl):
    outputs, calls = falconctl
    outputs["--metadata-query"] = "metadata-query=enable.\n"

    assert get_options(["metadata_query"]) == {"metadata_query": "enable"}
    assert calls[0][-1] == "--metadata-query"


def test_get_options_returns_none_when_falconctl_fails(falconctl):
    outputs = falconctl[0]
    outputs["--apd"] = CalledProcessError(255, ["falconctl"])

    assert get_options(["apd"]) == {"apd": None}


def test_get_options_rejects_unknown_option(falconctl):
    with pytest.raises(ValueError, match="Invalid falconctl get option"):
        get_options(["not_an_option"])


def test_get_options_raises_when_falconctl_missing(falconctl, monkeypatch):
    monkeypatch.setattr(falconctl_utils, "FALCONCTL_NOT_FOUND", True)
    monkeypatch.setattr(falconctl_utils, "FALCONCTL_VALUE_ERROR", "not found")

    with pytest.raises(ValueError, match="not found"):
        get_options(["cid"])
