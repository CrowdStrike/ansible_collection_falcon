# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Check that the user agent version agrees with galaxy.yml.

falconpy_utils sends crowdstrike-ansible/<__version__> as the user agent.
A release that changes only galaxy.yml makes the user agent send an old version.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

import yaml

from ansible_collections.crowdstrike.falcon.plugins.module_utils.version import (
    __version__,
)

COLLECTION_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def test_version_matches_galaxy_yml():
    with open(os.path.join(COLLECTION_ROOT, "galaxy.yml"), encoding="utf-8") as galaxy:
        galaxy_version = str(yaml.safe_load(galaxy)["version"])

    assert __version__ == galaxy_version, (
        "plugins/module_utils/version.py has __version__ = %r, but galaxy.yml has version %r. "
        "Set __version__ to the galaxy.yml version." % (__version__, galaxy_version)
    )
