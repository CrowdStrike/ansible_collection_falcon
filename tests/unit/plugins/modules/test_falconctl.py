# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import falconctl

FALCONCTL = "/opt/CrowdStrike/falconctl"


class FailJson(Exception):
    pass


class FakeModule(object):
    def __init__(self, **params):
        self.params = dict.fromkeys(
            [
                "cid", "provisioning_token", "aid", "apd", "aph", "app", "trace",
                "feature", "message_log", "billing", "tags", "tags_list",
                "backend", "cloud", "maintenance_token",
            ]
        )
        self.params["exclusive"] = False
        self.params.update(params)
        self.check_mode = False
        self.commands = []

    def get_bin_path(self, *args, **kwargs):
        return FALCONCTL

    def run_command(self, cmd, **kwargs):
        self.commands.append(cmd)
        return (0, "", "")

    def fail_json(self, msg):
        raise FailJson(msg)

    def warn(self, msg):
        pass


@pytest.fixture
def current_tags(monkeypatch):
    state = {"tags": None}
    monkeypatch.setattr(falconctl, "get_options", lambda opts: {o: state[o] for o in opts})
    return state


def run(module):
    falcon = falconctl.FalconCtl(module)
    falcon.execute()
    return falcon


def test_present_adds_tag_to_existing(current_tags):
    current_tags["tags"] = "tag1,tag2"
    module = FakeModule(state="present", tags_list=["tag3"])
    run(module)
    assert module.commands == [[FALCONCTL, "-s", "-f", "--tags=tag1,tag2,tag3"]]


def test_present_already_satisfied_runs_nothing(current_tags):
    current_tags["tags"] = "tag1,tag2"
    module = FakeModule(state="present", tags_list=["tag2"])
    run(module)
    assert module.commands == []


def test_exclusive_same_set_different_order_runs_nothing(current_tags):
    current_tags["tags"] = "tag1,tag2"
    module = FakeModule(state="present", exclusive=True, tags_list=["tag2", "tag1"])
    run(module)
    assert module.commands == []


def test_absent_removes_only_listed_tag(current_tags):
    current_tags["tags"] = "tag1,tagLegacy"
    module = FakeModule(state="absent", tags_list=["tagLegacy"])
    run(module)
    assert module.commands == [[FALCONCTL, "-s", "-f", "--tags=tag1"]]


def test_absent_last_tag_clears_tags(current_tags):
    current_tags["tags"] = "tagLegacy"
    module = FakeModule(state="absent", tags_list=["tagLegacy"])
    run(module)
    assert module.commands == [[FALCONCTL, "-d", "-f", "--tags"]]


def test_tags_list_with_other_options_runs_both(current_tags):
    module = FakeModule(state="present", trace="debug", tags_list=["tag1"])
    run(module)
    assert module.commands == [
        [FALCONCTL, "-s", "-f", "--trace=debug"],
        [FALCONCTL, "-s", "-f", "--tags=tag1"],
    ]


def test_check_mode_reports_resolved_tags(current_tags):
    current_tags["tags"] = "tag1,tagLegacy"
    module = FakeModule(state="absent", tags_list=["tagLegacy"])
    module.check_mode = True
    falcon = run(module)
    before = falcon.get_values()
    assert module.commands == []
    assert falcon.check_mode(before) == {"tags": "tag1"}


def test_exclusive_with_absent_fails(current_tags):
    with pytest.raises(FailJson, match="state 'present'"):
        run(FakeModule(state="absent", exclusive=True, tags_list=["tag1"]))


def test_exclusive_without_tags_list_fails(current_tags):
    with pytest.raises(FailJson, match="requires tags_list"):
        run(FakeModule(state="present", exclusive=True))


def test_invalid_tag_fails(current_tags):
    with pytest.raises(FailJson, match="Each tag"):
        run(FakeModule(state="present", tags_list=["bad,tag"]))


def test_resolved_tags_over_256_chars_fails(current_tags):
    current_tags["tags"] = "a" * 250
    with pytest.raises(FailJson, match="256"):
        run(FakeModule(state="present", tags_list=["tag1234"]))


def test_tags_string_still_replaces(current_tags):
    module = FakeModule(state="present", tags="tag1,tag2")
    run(module)
    assert module.commands == [[FALCONCTL, "-s", "-f", "--tags=tag1,tag2"]]
