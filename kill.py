#!/usr/bin/env python3

# Deskflow -- mouse and keyboard sharing utility
# SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
# Copyright (C) 2025 Symless Ltd.

# A utility to kill processes by name. Using Python avoids writing platform-specific shell scripts.
#
# One function is to kill all but the newest instance of a process, which is useful when developing
# Deskflow to avoid conflicts with multiple instances of the same process.


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


def kill_all(names, keep_newest=False):
    killed = 0
    for raw in names:
        name = raw.lower()
        matches = []

        if not matches:
            continue

        if keep_newest:
            # Sort newest first, keep the first, kill the rest
            matches.sort(key=lambda p: p.info.get("create_time", 0), reverse=True)
            to_keep = matches[0]
            to_kill = matches[1:]
            print(
                f"Keeping newest {raw} (PID {to_keep.pid}), killing {len(to_kill)} others"
            )
        else:
            to_kill = matches
            print(f"Killing all {raw} processes ({len(to_kill)} found)")

        for proc in to_kill:
            try:
                print(f"Terminating PID {proc.pid}")
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        _, alive = psutil.wait_procs(to_kill, timeout=2)
        for proc in alive:
            try:
                print(f"Force killing PID {proc.pid}")
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        killed += 1

    print(f"Processes killed: {killed}")


if __name__ == "__main__":
    main()
