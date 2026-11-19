# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: rtr

short_description: run tasks on Falcon hosts through Real Time Response

version_added: "4.15.0"

description:
  - This connection plugin runs Ansible tasks on a host through CrowdStrike Falcon
    Real Time Response (RTR). The controller talks only to the Falcon API; the host
    needs no SSH access and no open inbound port.
  - RTR keeps working when Falcon network containment isolates the host, so Ansible
    can collect data from or fix a contained host.
  - Modules run the normal way. The plugin uploads each module file (small files as
    base64 in one RTR C(runscript), larger files as an RTR put-file and the C(put)
    command), then runs it with the Python of the host.
  - The RTR response policy of the host must turn on Real Time Response, custom scripts
    and the C(put) command.
  - Read-only access to the RTR API is equivalent to Domain Admin level access. Give
    the API client only to trusted users.
  - This version supports Linux and macOS hosts with the C(sh) shell. Windows hosts are not
    supported.

options:
  device_id:
    description:
      - The host to connect to.
      - A value of 32 hexadecimal characters is used as the device ID (AID).
        Any other value is a host name, which the plugin resolves with the Hosts API.
        The name must match one host exactly (case does not matter).
      - When not set, the plugin uses the address of the host (V(ansible_host) or the
        inventory host name).
    type: str
    vars:
      - name: ansible_host
      - name: ansible_rtr_device_id
  client_id:
    description:
      - The CrowdStrike API client ID to use.
    type: str
    vars:
      - name: ansible_falcon_client_id
    env:
      - name: FALCON_CLIENT_ID
  client_secret:
    description:
      - The CrowdStrike API secret that corresponds to the client ID.
    type: str
    vars:
      - name: ansible_falcon_client_secret
    env:
      - name: FALCON_CLIENT_SECRET
  member_cid:
    description:
      - The CrowdStrike member CID for MSSP authentication.
    type: str
    vars:
      - name: ansible_falcon_member_cid
    env:
      - name: FALCON_MEMBER_CID
  cloud:
    description:
      - The CrowdStrike cloud region to use.
    type: str
    default: us-1
    choices: [us-1, us-2, us-3, eu-1, us-gov-1, us-gov-2]
    vars:
      - name: ansible_falcon_cloud
    env:
      - name: FALCON_CLOUD
  command_timeout:
    description:
      - The number of seconds that one RTR command can run on the host, from 1 to 600.
      - The plugin stops waiting for the result 60 seconds after this time.
    type: int
    default: 600
    vars:
      - name: ansible_rtr_command_timeout
    ini:
      - section: rtr_connection
        key: command_timeout
  poll_interval:
    description:
      - The number of seconds between two status checks of a running RTR command.
      - The value must be more than 0 and at most 60.
    type: float
    default: 0.5
    vars:
      - name: ansible_rtr_poll_interval
  inline_max_bytes:
    description:
      - Files up to this size in bytes are uploaded as base64 in one RTR command.
        Larger files use an RTR put-file.
      - The value must be 0 or more. A value above 22000 is used as 22000, because the RTR
        API limits the size of a script.
    type: int
    default: 16384
    vars:
      - name: ansible_rtr_inline_max_bytes

notes:
  - The host needs Python 3 for modules. Tasks run as root.
  - Pipelining is not supported. A module file is too large for one RTR command, so the
    plugin always uploads it first.
  - Use C(become) only with C(sudo) to another user, or not at all.
    RTR gives no terminal, so a become password prompt cannot be answered.
  - One RTR command can run for at most 10 minutes. Use C(async) for longer tasks.
  - Under network containment, the host can reach only the Falcon cloud. Tasks that need
    other network access (package mirrors, for example) fail.
  - RTR records the text of each command in its audit log, and the sensor records the same
    text as a process command line in the Falcon event data. This text holds the commands
    that Ansible runs, and the base64 content of each file that the plugin uploads inline
    (up to O(inline_max_bytes)), also for tasks with C(no_log). Do not send secrets in
    small files or in C(raw) commands through this plugin.
  - Module files (with the module arguments) go up as RTR put-files. The plugin deletes
    each put-file after the transfer. Other RTR administrators can see it while it exists.
  - C(fetch) reads the whole file into memory on the controller.
  - The plugin locks each host for the C(cd) and C(put) steps of an upload, for the forks
    of one controller only. Two controllers that use the same API client on the same host
    at the same time can collide during uploads.
  - The RTR session ends on the Falcon side after 10 minutes without commands.

requirements:
  - crowdstrike-falconpy >= 1.5.0
  - Real time response [B(READ)] and [B(WRITE)] API scopes
  - Real time response (admin) [B(WRITE)] API scope
  - Hosts [B(READ)] API scope when O(device_id) is a host name

seealso:
  - module: crowdstrike.falcon.host_contain
  - plugin: crowdstrike.falcon.falcon_hosts
    plugin_type: inventory

author:
  - Carlos Matos (@carlosmmatos)
"""

EXAMPLES = r"""
# Static inventory (inventory.yml) with the device ID of each host:
#
# all:
#   hosts:
#     web01:
#       ansible_connection: crowdstrike.falcon.rtr
#       ansible_rtr_device_id: 0123456789abcdef0123456789abcdef
#
# The credentials come from FALCON_CLIENT_ID, FALCON_CLIENT_SECRET and
# FALCON_CLOUD, or from the ansible_falcon_* variables.

# Dynamic inventory (falcon_hosts.yml) that reaches each host over RTR:
#
# plugin: crowdstrike.falcon.falcon_hosts
# filter: "platform_name:['Linux','Mac']"
# hostnames:
#   - device_id
# compose:
#   ansible_connection: "'crowdstrike.falcon.rtr'"

# Contain a host, then collect data from it over RTR.
- name: Contain the host
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Contain the host in Falcon
      crowdstrike.falcon.host_contain:
        hosts:
          - "{{ hostvars['web01'].ansible_rtr_device_id }}"
        contained: true

- name: Collect data from the contained host
  hosts: web01
  gather_facts: false
  tasks:
    - name: List the open connections
      ansible.builtin.command: ss -tanp
      register: connections
      changed_when: false

    - name: Fetch the authentication log
      ansible.builtin.fetch:
        src: /var/log/auth.log
        dest: "evidence/{{ inventory_hostname }}/"
"""

import os
import traceback

from ansible.errors import AnsibleConnectionFailure, AnsibleError, AnsibleFileNotFound
from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display
from ansible_collections.crowdstrike.falcon.plugins.plugin_utils.falconpy_utils import (
    authenticate,
    check_falconpy,
)
from ansible_collections.crowdstrike.falcon.plugins.plugin_utils.rtr import (
    AID_RE,
    INLINE_MAX_BYTES_LIMIT,
    RTRError,
    RTRSession,
    RTRTimeout,
    resolve_device_id,
)

FALCONPY_IMPORT_ERROR = None
try:
    from falconpy import Hosts, RealTimeResponse, RealTimeResponseAdmin

    HAS_FALCONPY = True
except ImportError:
    HAS_FALCONPY = False
    Hosts = RealTimeResponse = RealTimeResponseAdmin = None
    FALCONPY_IMPORT_ERROR = traceback.format_exc()

display = Display()


class Connection(ConnectionBase):
    """Run commands and move files over CrowdStrike Falcon Real Time Response."""

    transport = "crowdstrike.falcon.rtr"
    has_pipelining = False
    # stdin is /dev/null in RTR scripts, so no prompt can be answered.
    has_tty = False
    module_implementation_preferences = ("",)
    allow_executable = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._connected = False
        self._session = None

    def _timeout(self):
        timeout = self.get_option("command_timeout")
        if timeout is None or not 1 <= int(timeout) <= 600:
            raise AnsibleError(f"command_timeout must be from 1 to 600, got {timeout}.")
        return int(timeout)

    def _check_options(self):
        """Validate the options before any API call."""
        self._timeout()
        try:
            interval = float(self.get_option("poll_interval"))
        except (TypeError, ValueError) as exc:
            raise AnsibleError(f"poll_interval must be a number, got {self.get_option('poll_interval')}.") from exc
        if not 0 < interval <= 60:
            raise AnsibleError(f"poll_interval must be more than 0 and at most 60, got {interval}.")
        inline = self.get_option("inline_max_bytes")
        if inline is None or int(inline) < 0:
            raise AnsibleError(f"inline_max_bytes must be 0 or more, got {inline}.")

    def _device_value(self):
        value = self.get_option("device_id") or self._play_context.remote_addr
        if not value:
            raise AnsibleError("Set ansible_rtr_device_id or ansible_host to the device ID or name of the host.")
        return str(value).strip()

    def _connect(self):
        if self._connected:
            return self
        self._check_options()
        check_falconpy("crowdstrike.falcon.rtr")
        rtr = authenticate(RealTimeResponse, self.get_option)
        admin = RealTimeResponseAdmin(auth_object=rtr.auth_object)
        value = self._device_value()
        hosts = None if AID_RE.match(value) else Hosts(auth_object=rtr.auth_object)
        session = RTRSession(
            rtr,
            admin,
            poll_interval=float(self.get_option("poll_interval")),
            log=display.vvv,
            warn=display.warning,
        )
        session.debug_log = display.vvvvv
        try:
            aid = resolve_device_id(hosts, value, session.sleep)
            display.vvv(f"RTR init_session for {aid}", host=value)
            session.init(aid)
        except RTRError as exc:
            raise AnsibleConnectionFailure(exc.message) from exc
        self._session = session
        self._connected = True
        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        """Run a command on the host with one RTR runscript."""
        super().exec_command(cmd, in_data=in_data, sudoable=sudoable)
        if in_data is not None:
            raise AnsibleError("rtr does not support pipelining")
        display.vvv(f"RTR exec ({len(cmd)} characters)", host=self._session.device_id)
        display.vvvvv(f"RTR exec command: {cmd}", host=self._session.device_id)
        try:
            rc, stdout, stderr = self._session.exec_command(to_text(cmd), self._timeout())
        except RTRError as exc:
            if exc.status_code is None and not isinstance(exc, RTRTimeout):
                # A size check before any API call: the command itself is wrong.
                raise AnsibleError(exc.message) from exc
            raise AnsibleConnectionFailure(exc.message) from exc
        return rc, to_bytes(stdout, errors="surrogate_or_strict"), to_bytes(stderr, errors="surrogate_or_strict")

    def put_file(self, in_path, out_path):
        """Upload a file inline (small) or with an RTR put-file (large)."""
        super().put_file(in_path, out_path)
        if not os.path.isfile(to_bytes(in_path, errors="surrogate_or_strict")):
            raise AnsibleFileNotFound(f"file or module does not exist: {in_path}")
        with open(to_bytes(in_path, errors="surrogate_or_strict"), "rb") as handle:
            data = handle.read()
        limit = min(int(self.get_option("inline_max_bytes")), INLINE_MAX_BYTES_LIMIT)
        display.vvv(f"RTR PUT {in_path} TO {out_path} ({len(data)} bytes)", host=self._session.device_id)
        try:
            if len(data) <= limit:
                self._session.put_inline(data, out_path, self._timeout())
            else:
                self._session.upload_putfile(data, out_path, self._timeout())
        except RTRError as exc:
            if exc.rc is not None:
                raise AnsibleError(exc.message) from exc
            raise AnsibleConnectionFailure(exc.message) from exc

    def fetch_file(self, in_path, out_path):
        """Read a file from the host as base64 and write it on the controller."""
        super().fetch_file(in_path, out_path)
        display.vvv(f"RTR FETCH {in_path} TO {out_path}", host=self._session.device_id)
        try:
            data = self._session.fetch(in_path, self._timeout())
        except RTRError as exc:
            if exc.rc == 1:
                raise AnsibleFileNotFound(exc.message) from exc
            if exc.rc is not None:
                raise AnsibleError(exc.message) from exc
            raise AnsibleConnectionFailure(exc.message) from exc
        b_out = to_bytes(out_path, errors="surrogate_or_strict")
        parent = os.path.dirname(b_out)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(b_out, "wb") as handle:
            handle.write(data)

    def close(self):
        """Drop the session object."""
        # The RTR session stays open on the Falcon side and ends after 10 minutes idle.
        self._session = None
        self._connected = False

    def reset(self):
        """End the RTR session, so that the next task opens a new one."""
        # Ansible calls close() after each task and meta: reset_connection uses a new
        # connection object, so connect first: init_session returns the open session.
        try:
            self._connect()
            self._session.delete()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            display.vvv(f"RTR delete_session failed: {exc}")
        self.close()
