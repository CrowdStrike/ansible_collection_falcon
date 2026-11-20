# -*- coding: utf-8 -*-

# Copyright: (c) 2026, CrowdStrike Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Real Time Response (RTR) transport helpers for the crowdstrike.falcon.rtr connection plugin.

This file has no Ansible connection code. The FalconPy service objects are
passed in, so unit tests can give fakes, and the sleep and clock functions
can be replaced.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import contextlib
import fcntl
import functools
import ntpath
import os
import posixpath
import re
import secrets
import time
import uuid

# Limits of the RTR API.
SCRIPT_MAX_BYTES = 32766
COMMAND_STRING_MAX = 50000
# Room left for the wrapper around a base64 command in exec_command.
EXEC_SCRIPT_MAX = 32000
INLINE_MAX_BYTES_LIMIT = 22000
FETCH_SINGLE_MAX = 2 * 1024 * 1024
FETCH_PART_BYTES = 1048576
HOSTS_PAGE_LIMIT = 100

POLL_RETRIES = 5
POLL_RETRY_DELAY = 2
RATE_LIMIT_DEFAULT_WAIT = 5
RATE_LIMIT_MAX_WAIT = 60
RATE_LIMIT_RETRIES = 5
BUILTIN_RETRIES = 3
# create_put_files returns no ID, and a list right after it can be empty.
PUT_FILE_LIST_RETRIES = 3
CD_ROOT_RETRIES = 2
TIMEOUT_GRACE = 60

RETRYABLE_BUILTIN_STDERR = "Contact support."
# cd to a missing folder: "cd: <path>: No such file or directory" on Linux,
# "<path> does not exist" on macOS.
CD_MISSING_LINUX = "No such file or directory"
CD_MISSING_MAC = " does not exist"
# Windows: "Cannot find path, '<path>' does not exist", or "Try an absolute path" for a relative one.
CD_MISSING_WIN = "Cannot find path"
CD_MISSING_WIN_RELATIVE = "Try an absolute path"
RTR_DISABLED_CODE = 40301
RTR_DISABLED_HINT = (
    "Check the RTR response policy of the host; a new host can need up to an hour before RTR works."
)

AID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
# Folders that the cd admin command takes as is, without quotes.
SAFE_DIR_RE = re.compile(r"^/[A-Za-z0-9_./-]*$")
SAFE_WIN_DIR_RE = re.compile(r"^[A-Za-z]:\\[A-Za-z0-9_.\\-]*$")


class RTRError(Exception):
    """An RTR API or transport failure.

    ``rc`` is set when the API calls worked but the script on the host
    returned a non-zero exit code.
    """

    def __init__(self, message, status_code=None, code=None, rc=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.rc = rc


class RTRTimeout(RTRError):
    """The poll limit of an RTR command was reached."""


def _noop(*_args, **_kwargs):
    return None


def first_error(response):
    """Return (code, message) of the first API error of a FalconPy response."""
    body = response.get("body") or {}
    errors = body.get("errors") or []
    if errors and isinstance(errors[0], dict):
        return errors[0].get("code"), errors[0].get("message", "")
    return None, ""


def _first_resource(response):
    body = response.get("body") or {}
    resources = body.get("resources") or []
    return resources[0] if resources else None


def b64(data):
    """Return the base64 text of str or bytes data."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def new_marker():
    """Return a random exit code marker that command output cannot guess."""
    return f"__ANSIBLE_RTR_RC_{secrets.token_hex(8)}__="


# Picks the base64 decode flag: -d on Linux and new macOS, -D on old macOS.
_DECODE_FLAG = "__b=-d; printf %s eA== | base64 -d >/dev/null 2>&1 || __b=-D"


def wrap_script(body, marker, cleanup=""):
    """Wrap a shell body so that its exit code is printed after a marker line."""
    lines = [
        'export HOME="${HOME:-/root}"',
        _DECODE_FLAG,
        "(",
        body,
        ")",
        "__rc=$?",
    ]
    if cleanup:
        lines.append(cleanup)
    lines.append(f"printf '\\n{marker}%s\\n' \"$__rc\"")
    return "\n".join(lines) + "\n"


def parse_marker(stdout, stderr, marker):
    """Split the rc marker from stdout.

    Returns (rc, stdout, stderr). Without a marker (for example after an RTR
    timeout) rc is 255 and stderr says that no exit code came back.
    """
    stdout = stdout or ""
    stderr = stderr or ""
    idx = stdout.rfind("\n" + marker)
    if idx == -1:
        return 255, stdout, "RTR did not return an exit code. " + stderr
    tail = stdout[idx + 1 + len(marker):].strip()
    try:
        rc = int(tail)
    except ValueError:
        return 255, stdout, "RTR did not return an exit code. " + stderr
    return rc, stdout[:idx], stderr


def path_var(name, path):
    """Return a shell line that sets variable name to path, sent as base64.

    The path never appears as text in the script, so no character in it can
    change the script. Use it as "$name". Needs $__b from wrap_script.
    """
    return f"{name}=$(printf %s '{b64(path)}' | base64 $__b)"


def build_exec_script(cmd, marker):
    """Build the runscript text for exec_command."""
    path = f"/tmp/.ansible-rtr-{uuid.uuid4().hex}.sh"
    body = (
        f"(umask 077; printf %s '{b64(cmd)}' | base64 $__b > {path})\n"
        f"/bin/sh {path}"
    )
    return wrap_script(body, marker, cleanup=f"rm -f {path}")


# PowerShell (Windows) helpers. RTR returns only the success pipeline, and any
# error record drops all stdout, so each script catches every error and writes
# one marker line: <marker><rc>:<base64 stdout>:<base64 stderr>.

# The child powershell.exe writes in the OEM code page unless it is told otherwise.
PS_UTF8_PREFIX = "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\n"


def ps_text(value):
    """Return a PowerShell expression for value, sent as base64 UTF-8.

    The value never appears as text in the script, so no character in it can
    change the script.
    """
    return f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64(value)}'))"


def ps_wrap(body, marker, cleanup=""):
    """Wrap a PowerShell body that sets $__rc, $__o and $__e; print them after a marker."""
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "$__u = New-Object System.Text.UTF8Encoding $false",
        "$__rc = 0; $__o = ''; $__e = ''",
        "try {",
        body,
        "} catch {",
        "  $__rc = 1; $__e = [string]$__e + $_.Exception.Message",
        "} finally {",
    ]
    for line in cleanup.splitlines() if cleanup else []:
        lines.append(f"  try {{ {line} }} catch {{ }}")
    lines.append("}")
    lines.append(
        f"Write-Output ('{marker}' + $__rc + ':' + [Convert]::ToBase64String($__u.GetBytes([string]$__o))"
        " + ':' + [Convert]::ToBase64String($__u.GetBytes([string]$__e)))"
    )
    return "\n".join(lines) + "\n"


def ps_parse(stdout, stderr, marker):
    """Split the marker line of a ps_wrap script.

    Returns (rc, stdout, stderr). Without a marker (for example after an RTR
    timeout) rc is 255 and stderr says that no exit code came back.
    """
    stdout = stdout or ""
    stderr = stderr or ""
    idx = stdout.rfind(marker)
    while idx > 0 and stdout[idx - 1] not in "\r\n":
        idx = stdout.rfind(marker, 0, idx)
    if idx == -1:
        return 255, stdout, "RTR did not return an exit code. " + stderr
    parts = stdout[idx + len(marker):].strip().split(":")
    try:
        rc = int(parts[0])
        out = base64.b64decode(parts[1]).decode("utf-8", errors="replace")
        err = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
    except (IndexError, ValueError):
        return 255, stdout, "RTR did not return an exit code. " + stderr
    return rc, out, err


def ps_exec_script(cmd, marker, stdin_data=None, stdin_path=None):
    """Build the runscript text that runs cmd as PowerShell text in a child powershell.exe.

    The child gives the exit code rules of the Windows connection plugins of
    Ansible, and its stdout and stderr come back apart. stdin is stdin_data
    (bytes, inline) or the file stdin_path, which the script removes.
    """
    enc = base64.b64encode((PS_UTF8_PREFIX + cmd).encode("utf-16-le")).decode("ascii")
    lines = []
    if stdin_path is not None:
        # Open before the start, so that a missing file does not leave the child waiting.
        lines.append(f"$__fs = [IO.File]::OpenRead({ps_text(stdin_path)})")
    lines += [
        "$__psi = New-Object System.Diagnostics.ProcessStartInfo",
        "$__psi.FileName = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'",
        f"$__psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}'",
        "$__psi.UseShellExecute = $false; $__psi.CreateNoWindow = $true",
        "$__psi.RedirectStandardInput = $true",
        "$__psi.RedirectStandardOutput = $true; $__psi.RedirectStandardError = $true",
        "$__psi.StandardOutputEncoding = $__u; $__psi.StandardErrorEncoding = $__u",
        "$__p = [System.Diagnostics.Process]::Start($__psi)",
        "$__ot = $__p.StandardOutput.ReadToEndAsync(); $__et = $__p.StandardError.ReadToEndAsync()",
    ]
    # A write error means that the child closed stdin early; its output tells why.
    if stdin_data is not None:
        lines.append(
            f"try {{ $__b = [Convert]::FromBase64String('{b64(stdin_data)}'); "
            "$__p.StandardInput.BaseStream.Write($__b, 0, $__b.Length) } catch { }"
        )
    elif stdin_path is not None:
        lines.append("try { $__fs.CopyTo($__p.StandardInput.BaseStream) } catch { } finally { $__fs.Close() }")
    lines += [
        "try { $__p.StandardInput.Close() } catch { }",
        "$__p.WaitForExit()",
        "$__rc = $__p.ExitCode; $__o = $__ot.Result; $__e = $__et.Result",
    ]
    cleanup = ""
    if stdin_path is not None:
        cleanup = f"if ($__fs) {{ $__fs.Close() }}\nRemove-Item -LiteralPath ({ps_text(stdin_path)}) -Force"
    return ps_wrap("\n".join(lines), marker, cleanup=cleanup)


def ps_fetch_part_body(path, offset, count):
    """Return a ps_wrap body that sets $__o to the base64 of up to count bytes of path at offset.

    FileShare ReadWrite, as winrm does: a file that another process writes (a log) still opens.
    """
    return (
        f"$__p = {ps_text(path)}\n"
        f"$__b = New-Object byte[] {count}\n"
        "$__fs = New-Object IO.FileStream($__p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)\n"
        f"try {{ $null = $__fs.Seek({offset}, [IO.SeekOrigin]::Begin); $__n = 0\n"
        "while ($__n -lt $__b.Length) { $__r = $__fs.Read($__b, $__n, $__b.Length - $__n); if ($__r -le 0) { break }; $__n += $__r }\n"
        "$__o = [Convert]::ToBase64String($__b, 0, $__n) } finally { $__fs.Close() }"
    )


def escape_fql(value):
    """Escape a value for a single-quoted FQL string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _rate_limit_wait(resp):
    headers = resp.get("headers") or {}
    value = headers.get("X-RateLimit-RetryAfter")
    try:
        wait = int(value)
    except (TypeError, ValueError):
        return RATE_LIMIT_DEFAULT_WAIT
    # The header can be an epoch time or a number of seconds.
    if wait > 1000000000:
        wait = wait - int(time.time())
    return min(max(wait, 1), RATE_LIMIT_MAX_WAIT)


def with_retries(call, sleep=None, safe=True):
    """Run an API call again after HTTP 429, and a safe call also after an error.

    A 429 is retried up to RATE_LIMIT_RETRIES times: the API refused the call.
    A safe call (a read or a delete) is also retried after a 5xx response or an
    exception, up to POLL_RETRIES times. FalconPy gives most connection errors
    as a 500 response. A call that is not safe (a command submit or a put-file
    create) is not retried after an error, because the API can have done it
    already. An exception becomes a 500 response, so that the caller raises
    RTRError.
    """
    sleep = sleep or time.sleep
    limited = failures = 0
    while True:
        try:
            resp = call()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            resp = {"status_code": 500, "body": {"errors": [{"message": str(exc)}]}}
        status = resp.get("status_code")
        if status == 429 and limited < RATE_LIMIT_RETRIES:
            limited += 1
            sleep(_rate_limit_wait(resp))
            continue
        if safe and (status is None or status >= 500) and failures < POLL_RETRIES:
            failures += 1
            sleep(POLL_RETRY_DELAY)
            continue
        return resp


def resolve_device_id(hosts, value, sleep=None):
    """Return the AID for value: an AID as is, else the one host with that name.

    The hostname filter matches prefixes and ignores case, so all pages are
    read and the full name is compared here.
    """
    if AID_RE.match(value):
        return value.lower()
    if hosts is None:
        raise RTRError(f"'{value}' is not a device ID and no Hosts service is available.")
    fql = f"hostname:'{escape_fql(value)}'"
    ids = []
    while True:
        resp = with_retries(
            functools.partial(hosts.query_devices_by_filter, filter=fql, limit=HOSTS_PAGE_LIMIT, offset=len(ids)),
            sleep,
        )
        if resp.get("status_code") != 200:
            code, msg = first_error(resp)
            raise RTRError(f"Unable to search hosts named '{value}': {msg}", resp.get("status_code"), code)
        body = resp.get("body") or {}
        page = body.get("resources") or []
        ids.extend(page)
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
        if not page or total is None or len(ids) >= total:
            break
    matches = []
    for start in range(0, len(ids), HOSTS_PAGE_LIMIT):
        resp = with_retries(functools.partial(hosts.get_device_details, ids=ids[start:start + HOSTS_PAGE_LIMIT]), sleep)
        if resp.get("status_code") != 200:
            code, msg = first_error(resp)
            raise RTRError(f"Unable to read hosts named '{value}': {msg}", resp.get("status_code"), code)
        for host in (resp.get("body") or {}).get("resources") or []:
            if (host.get("hostname") or "").lower() == value.lower():
                matches.append(host.get("device_id"))
    if not matches:
        raise RTRError(f"No host named '{value}' was found in Falcon.")
    if len(matches) > 1:
        raise RTRError(f"{len(matches)} hosts are named '{value}': give the device ID instead.")
    return matches[0]


def lock_dir():
    """Return the folder of the host lock files, in the home of the controller user."""
    return os.path.join(os.path.expanduser("~"), ".ansible", "tmp", "rtr-locks")


@contextlib.contextmanager
def host_lock(aid):
    """Hold a file lock for one host.

    ``cd`` changes the cwd of the session that all forks share, so the
    cd/put/cd sequence runs under this lock. It covers one controller only.
    """
    folder = lock_dir()
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        fd = os.open(
            os.path.join(folder, f"{aid}.lock"),
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise RTRError(f"Unable to open the RTR lock file in {folder}: {exc}") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class RTRSession:
    """One RTR session on one host."""

    def __init__(self, rtr, admin, poll_interval=0.5, log=None, warn=None, *, shell="sh"):  # pylint: disable=too-many-arguments
        self.rtr = rtr
        self.admin = admin
        self.poll_interval = poll_interval
        self.log = log or _noop
        # Shown to the user: a put-file that could not be deleted stays in the tenant.
        self.warn = warn or _noop
        # Script text is logged only at a higher verbosity; tests replace sleep and clock.
        self.debug_log = _noop
        self.sleep = time.sleep
        self.clock = time.monotonic
        self.device_id = None
        self.session_id = None
        # shell "powershell" selects the Windows scripts; "sh" the POSIX ones.
        self.windows = shell == "powershell"
        self.platform = None
        self._win_temp = None

    # Session

    def init(self, device_id):
        """Open (or reuse) the RTR session of the host."""
        resp = self._with_rate_limit(lambda: self.rtr.init_session(device_id=device_id, queue_offline=False))
        status = resp.get("status_code")
        resource = _first_resource(resp)
        if status == 201 and resource and resource.get("session_id"):
            self.device_id = device_id
            self.session_id = resource["session_id"]
            self.platform = resource.get("platform")
            return self.session_id
        code, msg = first_error(resp)
        if status == 403 and code == RTR_DISABLED_CODE:
            raise RTRError(f"RTR session to {device_id} refused: {msg}. {RTR_DISABLED_HINT}", status, code)
        raise RTRError(f"RTR session to {device_id} failed with status {status}: {msg}", status, code)

    def delete(self):
        """End the RTR session. Errors are logged and ignored."""
        if not self.session_id:
            return
        resp = self._with_rate_limit(lambda: self.rtr.delete_session(session_id=self.session_id))
        if resp.get("status_code") not in (200, 204):
            _code, msg = first_error(resp)
            self.log(f"RTR delete_session returned {resp.get('status_code')}: {msg}")
        self.session_id = None

    # Commands

    def _execute(self, base_command, command_string):
        resp = self._with_rate_limit(
            lambda: self.admin.execute_admin_command(
                base_command=base_command,
                command_string=command_string,
                session_id=self.session_id,
                persist=False,
            ),
            safe=False,
        )
        status = resp.get("status_code")
        resource = _first_resource(resp)
        if status == 201 and resource and resource.get("cloud_request_id"):
            return resource["cloud_request_id"]
        code, msg = first_error(resp)
        raise RTRError(f"RTR {base_command} failed with status {status}: {msg}", status, code)

    def _rate_limit_wait(self, resp):
        return _rate_limit_wait(resp)

    def _with_rate_limit(self, call, safe=True):
        """Run an API call again after HTTP 429, and a safe call also after an error (see with_retries)."""
        return with_retries(call, self.sleep, safe)

    def _poll(self, crid, timeout):
        deadline = self.clock() + timeout + TIMEOUT_GRACE
        seq = 0
        stdout_parts = []
        stderr_parts = []
        failures = 0
        while True:
            if self.clock() > deadline:
                raise RTRTimeout("RTR command timed out")
            try:
                resp = self.admin.check_admin_command_status(cloud_request_id=crid, sequence_id=seq)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                resp = {"status_code": 500, "body": {"errors": [{"message": str(exc)}]}}
            status = resp.get("status_code")
            if status == 429:
                self.sleep(self._rate_limit_wait(resp))
                continue
            if status is None or status >= 500:
                failures += 1
                if failures > POLL_RETRIES:
                    code, msg = first_error(resp)
                    raise RTRError(f"RTR status check failed with status {status}: {msg}", status, code)
                self.sleep(POLL_RETRY_DELAY)
                continue
            if status != 200:
                code, msg = first_error(resp)
                raise RTRError(f"RTR status check failed with status {status}: {msg}", status, code)
            failures = 0
            part = _first_resource(resp) or {}
            if part.get("complete"):
                stdout_parts.append(part.get("stdout") or "")
                stderr_parts.append(part.get("stderr") or "")
                return "".join(stdout_parts), "".join(stderr_parts)
            next_seq = part.get("sequence_id")
            if next_seq is not None and next_seq != seq:
                stdout_parts.append(part.get("stdout") or "")
                stderr_parts.append(part.get("stderr") or "")
                seq = next_seq
                continue
            self.sleep(self.poll_interval)

    def run_raw(self, script, timeout):
        """Run a script with ``runscript -Raw`` and return (stdout, stderr)."""
        size = len(script.encode("utf-8"))
        if size > SCRIPT_MAX_BYTES:
            raise RTRError(f"The RTR script is {size} bytes; the API limit is {SCRIPT_MAX_BYTES} bytes.")
        command_string = "runscript -Raw=```" + script + "``` -Timeout=" + str(timeout)
        if len(command_string) > COMMAND_STRING_MAX:
            raise RTRError(
                f"The RTR command string is {len(command_string)} characters; "
                f"the API limit is {COMMAND_STRING_MAX}."
            )
        self.log(f"RTR runscript ({size} bytes)")
        self.debug_log(f"RTR runscript text:\n{script}")
        crid = self._execute("runscript", command_string)
        return self._poll(crid, timeout)

    def run_builtin(self, base_command, command_string, timeout):
        """Run a built-in admin command (``cd``, ``put``) and return (stdout, stderr)."""
        stdout = stderr = ""
        for attempt in range(BUILTIN_RETRIES + 1):
            self.log(f"RTR {base_command}: {command_string}")
            crid = self._execute(base_command, command_string)
            stdout, stderr = self._poll(crid, timeout)
            if not stderr.startswith(RETRYABLE_BUILTIN_STDERR):
                break
            self.log(f"RTR {base_command} gave a temporary error (attempt {attempt + 1})")
        if stderr:
            raise RTRError(f"RTR {base_command} failed: {stderr.strip()}")
        return stdout, stderr

    def run_with_rc(self, body, timeout, cleanup=""):
        """Run a shell body (PowerShell on Windows) and return (rc, stdout, stderr)."""
        marker = new_marker()
        if self.windows:
            stdout, stderr = self.run_raw(ps_wrap(body, marker, cleanup), timeout)
            return ps_parse(stdout, stderr, marker)
        stdout, stderr = self.run_raw(wrap_script(body, marker, cleanup), timeout)
        return parse_marker(stdout, stderr, marker)

    def exec_command(self, cmd, timeout, in_data=None, inline_max=INLINE_MAX_BYTES_LIMIT):
        """Run an Ansible command and return (rc, stdout, stderr) as text.

        in_data (bytes, Windows only) is sent to the stdin of the command:
        inline when it is at most inline_max bytes and the script fits, else
        with an RTR put-file.
        """
        if self.windows:
            return self._ps_exec_command(cmd, timeout, in_data, inline_max)
        marker = new_marker()
        script = build_exec_script(cmd, marker)
        size = len(script.encode("utf-8"))
        if size > EXEC_SCRIPT_MAX:
            raise RTRError(
                f"The command is too large for RTR: {size} bytes after encoding, the limit is {EXEC_SCRIPT_MAX}."
            )
        stdout, stderr = self.run_raw(script, timeout)
        return parse_marker(stdout, stderr, marker)

    def _check_exec_size(self, script):
        size = len(script.encode("utf-8"))
        if size > EXEC_SCRIPT_MAX:
            raise RTRError(
                f"The command is too large for RTR: {size} bytes after encoding, the limit is {EXEC_SCRIPT_MAX}."
            )

    def _ps_exec_command(self, cmd, timeout, in_data, inline_max):
        marker = new_marker()
        limit = min(inline_max, INLINE_MAX_BYTES_LIMIT)
        if in_data is None or len(in_data) <= limit:
            script = ps_exec_script(cmd, marker, stdin_data=in_data)
            if in_data is None or len(script.encode("utf-8")) <= EXEC_SCRIPT_MAX:
                self._check_exec_size(script)
                stdout, stderr = self.run_raw(script, timeout)
                return ps_parse(stdout, stderr, marker)
        # Check the size of the command before the upload.
        stdin_path = ntpath.join(self.win_temp(timeout), f".ansible-rtr-{uuid.uuid4().hex}.in")
        script = ps_exec_script(cmd, marker, stdin_path=stdin_path)
        self._check_exec_size(script)
        self.upload_putfile(in_data, stdin_path, timeout)
        try:
            stdout, stderr = self.run_raw(script, timeout)
        except Exception:
            # The script removes the file; it did not run, so remove it here.
            self._remove_leftover(stdin_path, timeout)
            raise
        rc, out, err = ps_parse(stdout, stderr, marker)
        if rc == 255 and marker not in (stdout or ""):
            # No marker: RTR stopped the script (timeout), so its finally block may not have
            # run. The file holds the module and its arguments.
            self._remove_leftover(stdin_path, timeout)
        return rc, out, err

    def win_temp(self, timeout):
        """Return the full path of the Windows temp folder, read once per session."""
        if self._win_temp is None:
            rc, out, err = self.run_with_rc("$__o = [IO.Path]::GetFullPath($env:TEMP)", timeout)
            path = out.strip()
            if rc != 0 or not path:
                raise RTRError(f"Unable to read the Windows temp folder (rc {rc}): {err.strip()}")
            # Keep the backslash of a drive root such as C:\.
            self._win_temp = path if len(path) <= 3 else path.rstrip("\\")
        return self._win_temp

    def _remove_leftover(self, path, timeout):
        """Remove a file or folder that a failed transfer left on the host. Errors are logged."""
        try:
            if self.windows:
                marker = new_marker()
                self.run_raw(
                    ps_wrap(f"Remove-Item -LiteralPath ({ps_text(path)}) -Recurse -Force", marker),
                    timeout,
                )
            else:
                self.run_raw(_DECODE_FLAG + "\n" + path_var("p", path) + '\nrm -rf "$p"\n', timeout)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.log(f"RTR upload leftover {path} was not removed: {exc}")

    # Files

    def put_inline(self, data, out_path, timeout):
        """Write a small file with one runscript."""
        self.log(f"RTR inline upload of {len(data)} bytes")
        if self.windows:
            body = (
                f"$__p = {ps_text(out_path)}\n"
                f"[IO.File]::WriteAllBytes($__p + '.rtrtmp', [Convert]::FromBase64String('{b64(data)}'))\n"
                "Move-Item -LiteralPath ($__p + '.rtrtmp') -Destination $__p -Force"
            )
            rc, _out, err = self.run_with_rc(body, timeout)
            if rc != 0:
                raise RTRError(f"Upload to {out_path} failed (rc {rc}): {err.strip()}", rc=rc)
            return
        body = (
            path_var("p", out_path)
            + "\n"
            + f"printf %s '{b64(data)}' | base64 $__b > \"$p.rtrtmp\" && mv -f \"$p.rtrtmp\" \"$p\""
        )
        rc, _out, err = self.run_with_rc(body, timeout)
        if rc != 0:
            raise RTRError(f"Upload to {out_path} failed (rc {rc}): {err.strip()}", rc=rc)

    def _put_file_ids(self, name, retries=0):
        """Return the IDs of the put-file; list again up to retries times while empty."""
        for attempt in range(retries + 1):
            resp = self._with_rate_limit(lambda: self.admin.list_put_files(filter=f"name:'{name}'"))
            if resp.get("status_code") != 200:
                code, msg = first_error(resp)
                raise RTRError(f"Unable to list RTR put-files: {msg}", resp.get("status_code"), code)
            ids = (resp.get("body") or {}).get("resources") or []
            if ids or attempt == retries:
                return ids
            self.sleep(POLL_RETRY_DELAY)
        return []

    def _delete_put_files(self, name, ids, missing_ok=False):
        """Delete the put-file; warn when it can stay in the tenant.

        missing_ok: the create failed, so the put-file is likely not there.
        """
        reason = None
        try:
            if not ids:
                ids = self._put_file_ids(name)
            if not ids:
                if missing_ok:
                    return
                reason = "no put-file with this name was found"
            else:
                resp = self._with_rate_limit(lambda: self.admin.delete_put_files(ids=ids))
                if resp.get("status_code") != 200:
                    _code, msg = first_error(resp)
                    reason = msg or f"status {resp.get('status_code')}"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Cleanup must not hide the first error.
            reason = str(exc)
        if reason:
            self.warn(
                f"RTR put-file {name} could not be deleted: {reason}; delete it from the RTR put-files library"
            )

    def _cd_existing(self, path, timeout):
        """``cd`` into path; return False when the folder does not exist."""
        try:
            self.run_builtin("cd", f"cd {path}", timeout)
        except RTRError as exc:
            text = exc.message[len("RTR cd failed: "):] if exc.message.startswith("RTR cd failed: ") else ""
            if self.windows:
                if (text.startswith(CD_MISSING_WIN) and text.endswith(CD_MISSING_MAC.strip())) or (
                    CD_MISSING_WIN_RELATIVE in text
                ):
                    return False
            elif (text.startswith("cd: ") and CD_MISSING_LINUX in text) or text == f"{path}{CD_MISSING_MAC}":
                return False
            raise
        return True

    def _cd_root(self, timeout):
        """Set the session cwd back to / (C:\\ on Windows), with retries."""
        root = "C:\\" if self.windows else "/"
        for attempt in range(CD_ROOT_RETRIES + 1):
            try:
                self.run_builtin("cd", f"cd {root}", timeout)
                return
            except RTRError as exc:
                if attempt == CD_ROOT_RETRIES:
                    raise
                self.log(f"RTR cd {root} failed (attempt {attempt + 1}): {exc}")
                self.sleep(POLL_RETRY_DELAY)

    def upload_putfile(self, data, out_path, timeout):
        """Upload a large file with an RTR put-file and move it to out_path.

        ``put`` writes to the session cwd, so the file is put in the parent
        folder of out_path and renamed there. A new stage folder is used only
        when that parent does not exist or has characters that ``cd`` cannot take.
        """
        name = f"ansible-rtr-{uuid.uuid4().hex}"
        parent = ntpath.dirname(out_path) if self.windows else posixpath.dirname(out_path)
        sep = "\\" if self.windows else "/"
        safe_re = SAFE_WIN_DIR_RE if self.windows else SAFE_DIR_RE
        stage = None
        self.log(f"RTR put-file {name} ({len(data)} bytes)")
        resp = self._with_rate_limit(
            lambda: self.admin.create_put_files(
                files=[("file", (name, data, "application/octet-stream"))],
                name=name,
                description="Ansible crowdstrike.falcon.rtr transfer",
                comments_for_audit_log="Ansible crowdstrike.falcon.rtr put_file",
            ),
            safe=False,
        )
        if resp.get("status_code") != 200:
            code, msg = first_error(resp)
            if resp.get("status_code") is None or resp.get("status_code") >= 500:
                # The API can have made the put-file before the error.
                self._delete_put_files(name, [], missing_ok=True)
            raise RTRError(f"Unable to create the RTR put-file: {msg}", resp.get("status_code"), code)
        ids = []
        done = False
        folder = parent
        try:
            ids = self._put_file_ids(name, retries=PUT_FILE_LIST_RETRIES)
            with host_lock(self.device_id):
                moved = False
                try:
                    if safe_re.match(parent) and self._cd_existing(parent, timeout):
                        moved = True
                    else:
                        if self.windows:
                            stage = ntpath.join(self.win_temp(timeout), f".ansible-rtr-{uuid.uuid4().hex}")
                            mkdir = f"$null = New-Item -ItemType Directory -Force -Path ({ps_text(stage)})"
                        else:
                            stage = f"/tmp/.ansible-rtr-{uuid.uuid4().hex}"
                            mkdir = f"mkdir -m 700 -p {stage}"
                        folder = stage
                        rc, _out, err = self.run_with_rc(mkdir, timeout)
                        if rc != 0:
                            raise RTRError(f"Unable to make {stage} (rc {rc}): {err.strip()}", rc=rc)
                        self.run_builtin("cd", f"cd {stage}", timeout)
                        moved = True
                    # run_builtin raises on any stderr, also "Destination already exists".
                    self.run_builtin("put", f"put {name}", timeout)
                except Exception:
                    if moved:
                        # Cleanup must not hide the first error.
                        try:
                            self._cd_root(timeout)
                        except Exception as exc:  # pylint: disable=broad-exception-caught
                            self.log(f"RTR cd / after a failed put did not work: {exc}")
                    raise
                # Ansible deletes its tmp folder later; a session whose cwd is gone
                # cannot be opened again, so the cwd MUST go back to /.
                self._cd_root(timeout)
            if self.windows:
                body = (
                    f"Move-Item -LiteralPath ({ps_text(folder + sep + name)}) -Destination ({ps_text(out_path)}) -Force"
                )
                if stage:
                    body += f"\nRemove-Item -LiteralPath ({ps_text(stage)}) -Force"
            else:
                body = path_var("s", folder + "/" + name) + "\n" + path_var("p", out_path) + '\nmv -f "$s" "$p"'
                if stage:
                    body += f" && rmdir {stage}"
            rc, _out, err = self.run_with_rc(body, timeout)
            if rc != 0:
                raise RTRError(f"Upload to {out_path} failed (rc {rc}): {err.strip()}", rc=rc)
            done = True
        finally:
            self._delete_put_files(name, ids)
            if not done:
                self._remove_leftover(stage or folder + sep + name, timeout)

    def fetch(self, in_path, timeout):
        """Return the content of a file on the host as bytes.

        Each read writes the data to a temporary file first, so that a failed
        read gives rc 2 and not empty or short output.
        """
        if self.windows:
            return self._ps_fetch(in_path, timeout)
        path_expr = path_var("p", in_path) + '\ntest -f "$p" || exit 1\n'
        rc, out, err = self.run_with_rc(path_expr + 'wc -c < "$p"', timeout)
        if rc != 0:
            raise RTRError(f"{in_path} is not a file on the host", rc=rc)
        try:
            size = int(out.strip())
        except ValueError as exc:
            raise RTRError(f"Unable to read the size of {in_path}: {out.strip()} {err.strip()}") from exc
        self.log(f"RTR fetch of {in_path} ({size} bytes)")
        tmp = f"/tmp/.ansible-rtr-{uuid.uuid4().hex}"
        tmp_b64 = tmp + ".b64"
        if size <= FETCH_SINGLE_MAX:
            body = path_expr + f"umask 077\nbase64 < \"$p\" > {tmp_b64} || exit 2\ntr -d '\\n' < {tmp_b64}"
            rc, out, err = self.run_with_rc(body, timeout, cleanup=f"rm -f {tmp_b64}")
            if rc != 0:
                raise RTRError(f"Unable to read {in_path} (rc {rc}): {err.strip()}", rc=rc)
            data = [base64.b64decode(out.strip())]
        else:
            tmp_raw = tmp + ".raw"
            data = []
            part = 0
            while True:
                body = (
                    path_expr
                    + "umask 077\n"
                    + f"dd if=\"$p\" bs={FETCH_PART_BYTES} skip={part} count=1 2>/dev/null > {tmp_raw} || exit 2\n"
                    + f"base64 < {tmp_raw} > {tmp_b64} || exit 2\n"
                    + f"tr -d '\\n' < {tmp_b64}"
                )
                rc, out, err = self.run_with_rc(body, timeout, cleanup=f"rm -f {tmp_raw} {tmp_b64}")
                if rc != 0:
                    raise RTRError(f"Unable to read {in_path} (rc {rc}): {err.strip()}", rc=rc)
                chunk = base64.b64decode(out.strip())
                if not chunk:
                    break
                data.append(chunk)
                part += 1
        result = b"".join(data)
        if len(result) != size:
            raise RTRError(f"Read {len(result)} bytes of {in_path}, but the file has {size} bytes.")
        return result

    def _ps_fetch(self, in_path, timeout):
        """Windows fetch: the body sets $__o to the base64 of the bytes."""
        path_expr = f"$__p = {ps_text(in_path)}\n"
        rc, out, err = self.run_with_rc(
            path_expr
            + "if (-not (Test-Path -LiteralPath $__p -PathType Leaf)) { $__rc = 1 }"
            + " else { $__o = [string](Get-Item -LiteralPath $__p).Length }",
            timeout,
        )
        if rc != 0:
            raise RTRError(f"{in_path} is not a file on the host", rc=rc)
        try:
            size = int(out.strip())
        except ValueError as exc:
            raise RTRError(f"Unable to read the size of {in_path}: {out.strip()} {err.strip()}") from exc
        self.log(f"RTR fetch of {in_path} ({size} bytes)")
        # The marker line holds the base64 of the base64 text, so the parts are smaller than on POSIX.
        parts = [
            ps_fetch_part_body(in_path, offset, min(FETCH_PART_BYTES, max(size - offset, 1)))
            for offset in range(0, max(size, 1), FETCH_PART_BYTES)
        ]
        data = []
        for body in parts:
            rc, out, err = self.run_with_rc(body, timeout)
            if rc != 0:
                raise RTRError(f"Unable to read {in_path} (rc {rc}): {err.strip()}", rc=2)
            data.append(base64.b64decode(out.strip()))
        result = b"".join(data)
        if len(result) != size:
            raise RTRError(f"Read {len(result)} bytes of {in_path}, but the file has {size} bytes.")
        return result
