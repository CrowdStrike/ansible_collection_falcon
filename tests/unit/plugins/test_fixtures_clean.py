# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Check that the recorded fixtures contain no tenant data.

tests/unit/record_fixtures.py sanitizes every response before it writes it.
This test catches a fixture that was edited by hand or written another way.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

HEX32_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
UUID_RE = re.compile(
    r"(?<![0-9a-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# A long opaque string (a base64 token, for example) can encode tenant IDs.
OPAQUE_RE = re.compile(r"[A-Za-z0-9+/_-]{40,}")
FAKE_HEX32_RE = re.compile(r"(?<![0-9a-fA-F])0{24}[0-9]{8}(?![0-9a-fA-F])")
TOKEN_KEYS = ("access_token", "refresh_token", "uninstall_token", "ingest_token", "token")


def fixture_files():
    for root, _dirs, files in os.walk(FIXTURES_DIR):
        for name in sorted(files):
            if name.endswith(".json"):
                yield os.path.relpath(os.path.join(root, name), FIXTURES_DIR)


def token_values(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if key in TOKEN_KEYS and isinstance(value, str):
                yield key, value
            else:
                yield from token_values(value)
    elif isinstance(data, list):
        for value in data:
            yield from token_values(value)


@pytest.mark.parametrize("path", list(fixture_files()))
def test_fixture_has_no_tenant_data(path):
    with open(os.path.join(FIXTURES_DIR, path)) as f:
        text = f.read()
    data = json.loads(text)

    real_ids = [v for v in HEX32_RE.findall(text) if not (v.isdigit() and int(v) < 10**8)]
    real_uuids = [v for v in UUID_RE.findall(text) if not v.startswith("00000000-0000-0000-0000-")]
    real_emails = [d for d in EMAIL_RE.findall(text) if d != "example.com"]
    tokens = [k for k, v in token_values(data) if v not in ("", "REDACTED")]
    opaque = OPAQUE_RE.findall(FAKE_HEX32_RE.sub("", text))

    assert real_ids == []
    assert real_uuids == []
    assert real_emails == []
    assert tokens == []
    assert opaque == []
    assert "trace_id" not in text
