#!/usr/bin/env python3

# Deskflow -- mouse and keyboard sharing utility
# SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
# SPDX-FileCopyrightText: 2025 Symless Ltd.

# A utility to kill processes by name. Using Python avoids writing platform-specific shell scripts.
#
# One function is to kill all but the newest instance of a process, which is useful when developing
# Deskflow to avoid conflicts with multiple instances of the same process. This will be less useful
# when we eventually dedupe the core processes, but even after then this will help with bugs where
# multiple instances of the same process are created.


import argparse
import psutil
import sys
import time


def log(message):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}")

def main():
    parser = argparse.ArgumentParser(
        description="A cross-platform kill utility tuned for Deskflow development."
    )
    parser.add_argument("names", nargs="+", help="Process names to target")
    parser.add_argument(
        "--keep-newest",
        action="store_true",
        help="Keep the newest instance of the process (default: kill all)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watches and keeps looking for processes to kill",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging output"
    )
    args = parser.parse_args()
    try:
        if args.watch:
            log("Watching for processes to kill. Press Ctrl+C to exit.")

        while args.watch:
            kill_all(args.names, args.keep_newest, args.verbose)

            if args.watch:
                time.sleep(1)
    except KeyboardInterrupt:
        log("\nExiting...")
        sys.exit(0)


def get_kill_lists(name, matches, keep_newest, verbose_logs):
    if not keep_newest:
        log(f"Killing all {name} processes ({len(matches)} found)")
        return matches

    # Sort newest first, keep the first, kill the rest
    matches.sort(key=lambda p: p.info.get("create_time", 0), reverse=True)
    to_keep = matches[0]
    if len(matches) == 1:
        if verbose_logs:
            log(f"Keeping only {name} (PID {to_keep.pid}), nothing to kill")
        return []

    to_kill = matches[1:]
    if verbose_logs:
        log(f"Keeping newest {name} (PID {to_keep.pid}), killing {len(to_kill)}")

    return to_kill


def get_process_name(raw_name):
    name = raw_name.lower()
    if sys.platform == "win32" and not name.endswith(".exe"):
        return f"{name}.exe"

    return name


def kill(raw_name, keep_newest, verbose_logs):
    name = get_process_name(raw_name)
    matches = []
    for proc in psutil.process_iter(attrs=["pid", "name", "create_time"]):
        try:
            if name == proc.info["name"].lower():
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            log(f"Process {proc.pid} no longer exists or access denied")
            return False

    if not matches:
        if verbose_logs:
            log(f"No processes found for '{raw_name}'")
        return False

    to_kill = get_kill_lists(name, matches, keep_newest, verbose_logs)

    for proc in to_kill:
        try:
            log(f"Terminating PID {proc.pid} ({proc.info['name']})")
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    _, alive = psutil.wait_procs(to_kill, timeout=2)
    for proc in alive:
        try:
            log(f"Force killing PID {proc.pid} ({proc.info['name']})")
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    return len(to_kill) > 0


def kill_all(names, keep_newest, verbose_logs):
    killed = 0
    for name in names:
        killed += 1 if kill(name, keep_newest, verbose_logs) else 0

    if killed == 0:
        if verbose_logs:
            log("No processes killed")
    else:
        log(f"Processes killed: {killed}")


if __name__ == "__main__":
    main()
