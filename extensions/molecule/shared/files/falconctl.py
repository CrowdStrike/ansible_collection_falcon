"""A stand-in for /opt/CrowdStrike/falconctl, for the molecule scenarios.

build-dummy-sensor.sh installs it as falconctl with a python3 shebang.

It keeps the sensor options in a JSON file and prints them in the
'<option>=<value>.' format that crowdstrike.falcon.falconctl_info parses.
'falconctl daemon' is the ExecStart of the dummy falcon-sensor service: like
the real sensor, it creates an AID when it starts with a CID set.

Every call is logged to /var/log/falconctl-stub.log, with the maintenance
token value hidden, so a verify playbook can check what the roles ran.
"""

import json
import os
import sys
import time
import uuid

STATE = "/opt/CrowdStrike/falconstore"
VERSION_FILE = "/opt/CrowdStrike/VERSION"
LOG = "/var/log/falconctl-stub.log"

GET_OPTIONS = {
    "cid", "aid", "apd", "aph", "app", "trace", "feature", "metadata-query",
    "message-log", "billing", "tags", "version", "rfm-state", "rfm-reason",
    "backend", "cloud",
}
SET_OPTIONS = {
    "cid", "apd", "aph", "app", "trace", "feature", "metadata-query",
    "message-log", "billing", "tags", "provisioning-token", "backend", "cloud",
    "maintenance-token",
}
DELETE_OPTIONS = {
    "cid", "aid", "apd", "aph", "app", "trace", "billing", "tags",
    "provisioning-token", "backend", "cloud",
}
# The sensor prints these values in quotes.
QUOTED = {"cid", "aid", "tags"}


def load():
    if os.path.exists(STATE):
        with open(STATE) as handle:
            return json.load(handle)
    return {}


def save(state):
    with open(STATE, "w") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def log(args):
    shown = []
    for arg in args:
        if arg.startswith("--maintenance-token="):
            arg = "--maintenance-token=<hidden>"
        shown.append(arg)
    with open(LOG, "a") as handle:
        handle.write(" ".join(shown) + "\n")


def unrecognized(arg):
    sys.stderr.write("falconctl: unrecognized option '%s'\n" % arg)
    return 1


def get(state, args):
    for arg in args:
        opt = arg[2:]
        if opt not in GET_OPTIONS:
            return unrecognized(arg)
        if opt == "version":
            with open(VERSION_FILE) as handle:
                print("version = %s" % handle.read().strip())
            continue
        if opt == "rfm-state":
            print("rfm-state=false.")
            continue
        value = state.get(opt)
        if value is None:
            print("%s is not set." % opt)
        elif opt in QUOTED:
            print('%s="%s".' % (opt, value))
        else:
            print("%s=%s." % (opt, value))
    return 0


def set_options(state, args):
    for arg in args:
        opt, value = (arg[2:].split("=", 1) + [""])[:2]
        if opt not in SET_OPTIONS:
            return unrecognized(arg)
        if opt == "maintenance-token":
            state["maintenance-token-applied"] = True
            continue
        # The sensor stores the CID without its checksum, in lowercase,
        # and prints apd in uppercase.
        if opt == "cid":
            value = value.lower()[:32]
        elif opt == "apd":
            value = value.upper()
        state[opt] = value
    save(state)
    return 0


def delete_options(state, args):
    for arg in args:
        opt = arg[2:]
        if opt not in DELETE_OPTIONS:
            return unrecognized(arg)
        state.pop(opt, None)
    save(state)
    return 0


def daemon(state):
    state["starts"] = state.get("starts", 0) + 1
    if state.get("cid") and not state.get("aid"):
        state["aid"] = uuid.uuid4().hex
    save(state)
    while True:
        time.sleep(3600)


def main(argv):
    if not argv:
        sys.stderr.write("usage: falconctl -g|-s|-d [-f] --option[=value] ...\n")
        return 1
    log(argv)
    state = load()
    if argv[0] == "daemon":
        return daemon(state)
    action = argv[0]
    args = [arg for arg in argv[1:] if arg != "-f"]
    if action == "-g":
        return get(state, args)
    if action == "-s":
        return set_options(state, args)
    if action == "-d":
        return delete_options(state, args)
    return unrecognized(action)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
