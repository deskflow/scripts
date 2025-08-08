#!/usr/bin/env python3

# Deskflow -- mouse and keyboard sharing utility
# SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
# Copyright (C) 2025 Symless Ltd.

# A utility to kill processes by name. Using Python avoids writing platform-specific shell scripts.
#
# One function is to kill all but the newest instance of a process, which is useful when developing
# Deskflow to avoid conflicts with multiple instances of the same process. This will be less useful
# when we eventually dedupe the core processes, but even after then this will help with bugs where
# multiple instances of the same process are created.


import argparse
import psutil
import sys


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
    args = parser.parse_args()
    kill_all(args.names, args.keep_newest)


def get_kill_lists(name, matches, keep_newest):
    if not keep_newest:
        print(f"Killing all {name} processes ({len(matches)} found)")
        return matches

    # Sort newest first, keep the first, kill the rest
    matches.sort(key=lambda p: p.info.get("create_time", 0), reverse=True)
    to_keep = matches[0]
    if len(matches) == 1:
        print(f"Keeping only {name} (PID {to_keep.pid}), nothing to kill")
        return []

    to_kill = matches[1:]
    print(f"Keeping newest {name} (PID {to_keep.pid}), killing {len(to_kill)}")

    return to_kill


def kill(raw_name, keep_newest):
    name = raw_name.lower()
    matches = []
    for proc in psutil.process_iter(attrs=["pid", "name", "create_time"]):
        try:
            if name == proc.info["name"].lower():
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print(f"Process {proc.pid} no longer exists or access denied")
            return False

    if not matches:
        print(f"No processes found for '{raw_name}'")
        return False

    to_kill = get_kill_lists(name, matches, keep_newest)

    for proc in to_kill:
        try:
            print(f"Terminating PID {proc.pid}")
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    _, alive = psutil.wait_procs(to_kill, timeout=2)
    for proc in alive:
        try:
            print(f"Force killing PID {proc.pid}")
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    return True


def kill_all(names, keep_newest=False):
    killed = 0
    for name in names:
        killed += 1 if kill(name, keep_newest) else 0

    print(f"Processes killed: {killed}")


if __name__ == "__main__":
    main()
