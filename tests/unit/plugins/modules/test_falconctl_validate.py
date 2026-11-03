# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.crowdstrike.falcon.plugins.modules import falconctl


class FailJson(Exception):
    pass


class FakeModule(object):
    """Just enough of AnsibleModule for FalconCtl parameter validation."""

    def __init__(self, **params):
        self.params = dict.fromkeys(
            [
                "cid",
                "provisioning_token",
                "apd",
                "message_log",
                "billing",
                "tags",
                "backend",
            ]
        )
        self.params.update(state="present", **params)

    def get_bin_path(self, *args, **kwargs):
        return "/opt/CrowdStrike/falconctl"

    def fail_json(self, **kwargs):
        raise FailJson(kwargs["msg"])


@pytest.mark.parametrize(
    "tags",
    [
        "Washington/DC_USA,Production",
        # Linux sensors 7.21 through 8.11 accept '.' and '@' in tags.
        "v1.2,team@corp",
    ],
    ids=["documented-example", "dots-and-at"],
)
def test_valid_tags_are_accepted(tags):
    falconctl.FalconCtl(FakeModule(tags=tags))


@pytest.mark.parametrize(
    "tags",
    ["has space", "semi;colon", "quote'"],
    ids=["space", "semicolon", "quote"],
)
def test_invalid_tags_are_rejected(tags):
    with pytest.raises(FailJson, match="Value of tags"):
        falconctl.FalconCtl(FakeModule(tags=tags))
