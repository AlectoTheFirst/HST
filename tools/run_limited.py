#!/usr/bin/env python3
"""Run one validation process with hard wall-clock and address-space limits."""

from __future__ import annotations

import argparse
import os
import resource
import signal
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-mib", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.memory_mib <= 0 or args.timeout <= 0:
        parser.error("positive limits and a command are required")
    memory_bytes = args.memory_mib * 1024 * 1024

    def limits() -> None:
        os.setsid()
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    process = subprocess.Popen(command, preexec_fn=limits)  # noqa: S603
    try:
        status = process.wait(timeout=args.timeout)
        if status < 0:
            signum = -status
            print(
                f"validation terminated by signal {signum} under "
                f"{args.memory_mib} MiB RLIMIT_AS: {command[0]}",
                file=sys.stderr,
            )
            return 128 + signum
        return status
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        print(f"validation timed out after {args.timeout}s: {command[0]}", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
