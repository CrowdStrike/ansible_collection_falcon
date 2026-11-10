# -*- coding: utf-8 -*-

# Ansible module utility used for returning Falcon Sensor GET options.
# Copyright: (c) 2021, CrowdStrike Inc.
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re

# Constants
CS_PATH = "/opt/CrowdStrike"

FALCONCTL_GET_OPTIONS = [
    "cid",
    "aid",
    "apd",
    "aph",
    "app",
    "trace",
    "feature",
    "metadata_query",
    "message_log",
    "billing",
    "tags",
    "version",
    "rfm_state",
    "rfm_reason",
    "backend",
    "cloud",
]


def __get(module, falconctl, opt):
    if opt not in FALCONCTL_GET_OPTIONS:
        raise ValueError("Invalid falconctl get option: %s" % opt)
    # make sure opt is translated prior to execution
    cmd = [falconctl, "-g", "--%s" % opt.replace("_", "-")]
    rc, stdout, stderr = module.run_command(cmd)
    if rc != 0:
        return None

    # falconctl can print notices on stderr. Put them before stdout so that
    # the '<option>=<value>' part stays last and _split_value drops them.
    return format_stdout(stderr + stdout, opt)


def __get_many(module, opts):
    falconctl = module.get_bin_path("falconctl", required=True, opt_dirs=[CS_PATH])
    return {opt: __get(module, falconctl, opt) for opt in opts}


def _split_value(cleaned):
    """Return the value from an '<option>=<value>' string.

    Returns None when no '=' delimiter is present instead of raising
    IndexError on sensors that changed an option's output format (e.g. the
    backend option on 7.40+, which prints a deprecation notice with no '=').
    """
    parts = cleaned.split("=", 1)
    return parts[1] if len(parts) > 1 else None


def format_stdout(stdout, opt):
    """Formats output from falconctl -g for the given option.

    The parser is chosen by option name, not by searching stdout, so a value
    that contains another option's name (e.g. a "graph-db" tag) is not parsed
    as that option.
    """
    # Format stdout
    if stdout == "" or "not set" in stdout:
        return None

    # Expect stdout in <option>=<value>
    if opt == "version":
        output = _split_value(re.sub(r"[\"\s\n]|\(.*\)", "", stdout))
    elif opt == "rfm_reason":
        output = re.sub(r"^rfm-reason=|[\"\s\n\.]|\(.*\)", "", stdout)
    elif opt == "aph":
        output = _split_value(re.sub(r"\.?\s*$", "", stdout))
    elif opt == "tags":
        # Tags may contain '.', so only drop quotes, whitespace and the
        # trailing sentence dot.
        output = _split_value(re.sub(r"[\"\s]", "", stdout).rstrip("."))
    else:
        output = _split_value(re.sub(r"[\"\s\n\.]|\(.*\)", "", stdout))
    return output if output else None


def split_tags(tags):
    """Split a comma-separated sensor tag string into a list, dropping blanks"""
    if not tags:
        return []
    return [tag.strip() for tag in tags.split(",") if tag.strip()]


def resolve_tags(current, requested, state, exclusive=False):
    """Return the sensor tag string that results from applying tags_list.

    falconctl can only replace the whole tag string (-s --tags) or clear it
    (-d --tags), so individual tags are added/removed by merging against the
    current value. Existing order is preserved and new tags are appended.
    Returns None when no tags should remain.
    """
    current_tags = split_tags(current)
    requested_tags = []
    for tag in requested or []:
        if tag not in requested_tags:
            requested_tags.append(tag)

    if state == "present":
        if exclusive:
            resolved = requested_tags
        else:
            resolved = current_tags + [
                tag for tag in requested_tags if tag not in current_tags
            ]
    else:
        resolved = [tag for tag in current_tags if tag not in requested_tags]

    return ",".join(resolved) if resolved else None


def tags_equal(first, second):
    """Compare two tag strings regardless of order"""
    return set(split_tags(first)) == set(split_tags(second))


def get_options(module, opts):
    """Return falconctl -g valid options, run through the AnsibleModule"""
    requested = opts if opts else FALCONCTL_GET_OPTIONS
    return __get_many(module, requested)
