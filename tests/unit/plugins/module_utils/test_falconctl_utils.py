# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.crowdstrike.falcon.plugins.module_utils.falconctl_utils import (
    format_stdout,
)


def test_backend_deprecation_notice_returns_none():
    # Sensor 7.40+ deprecated the --backend option; it prints a notice with
    # no '=' delimiter, which used to raise IndexError (issue #709).
    stdout = (
        "This option is deprecated and will be ignored. "
        "It may be removed in a future sensor release.\n"
    )
    assert format_stdout(stdout) is None


def test_version_preserves_dots():
    # The version branch must keep dots in the value.
    assert format_stdout("version = 7.40.19311.0\n") == "7.40.19311.0"


def test_aid_value_is_extracted():
    assert (
        format_stdout('aid="2f87f0a9e0b74fcc8b375dec8827a3eb".')
        == "2f87f0a9e0b74fcc8b375dec8827a3eb"
    )


def test_tag_value_containing_deprecated_is_not_dropped():
    # A user-defined tag may legitimately contain the word "deprecated";
    # it must not be mistaken for a deprecation notice and dropped.
    assert format_stdout('tags="deprecated-web,prod".') == "deprecated-web,prod"


def test_empty_returns_none():
    assert format_stdout("") is None


def test_not_set_returns_none():
    assert format_stdout("apd is not set.") is None


def test_missing_delimiter_returns_none():
    # General safety net: any option whose output lacks '=' degrades to None
    # rather than raising IndexError.
    assert format_stdout("some unexpected output\n") is None
