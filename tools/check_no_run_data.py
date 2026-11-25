#!/usr/bin/env python3
"""Fail if a tracked file is run data.

`python tools/check_no_run_data.py` exits 1 and lists each finding.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Directory names that hold run output wherever they appear in the tree. Matched on any
# path segment.
RUN_DATA_DIRS = {"backups", "snapshots", "dumps", "captures"}

# Top-level paths that are run data in this repo specifically.
RUN_DATA_PREFIXES = ("data/", "raw/")

# Extensions of run output.
RUN_DATA_SUFFIXES = (
    ".dump",  # pg_dump -Fc, neo4j-admin database dump
    ".pcap",
    ".pcapng",
    ".parquet",
    ".jsonl",  # the changes log
)

# Content signatures.
SIGNATURES = (
    # Fernet token prefix: anything sealed with HST_SECRET_KEY (source credentials,
    # AI provider keys, raw snapshots).
    (re.compile(rb"gAAAAA[A-Za-z0-9_-]{20,}"), "a Fernet token (something sealed with HST_SECRET_KEY)"),
    (re.compile(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "a private key"),
    (re.compile(rb"^PGDMP"), "a PostgreSQL dump"),
)

# The checker names these patterns, and CONTRIBUTING quotes the Fernet prefix.
EXEMPT = {"tools/check_no_run_data.py", "CONTRIBUTING.md"}

GUIDANCE = """
Run data does not go into git. A local run file goes under a path that `.gitignore`
covers (`data/`, `raw/`, `backups/`).

A committed file stays in history after it leaves the working tree and counts as
disclosed. A history rewrite needs a decision before any force-push.

Collector tests use hand-written payloads, as in tests/test_nxos.py. The APIC
capture-replay test skips in CI (CONTRIBUTING.md, "Writing a collector").
"""


def tracked_files() -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is not on PATH")
    out = subprocess.run(  # noqa: S603 - git from PATH and literal arguments
        [git, "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.split("\0") if p]


def path_problem(path: str) -> str | None:
    if path.startswith(RUN_DATA_PREFIXES):
        return f"is under {path.split('/')[0]}/, which holds collected data"
    segments = set(Path(path).parts[:-1])
    hit = segments & RUN_DATA_DIRS
    if hit:
        return f"sits in a {next(iter(hit))}/ directory"
    if path.endswith(RUN_DATA_SUFFIXES):
        suffix = Path(path).suffix
        return f"has the {suffix} extension, which is run output"
    return None


def content_problem(path: str) -> str | None:
    full = REPO / path
    try:
        blob = full.read_bytes()
    except OSError:
        return None
    # The magic number of a binary file is in the first 512 bytes.
    head = blob[:512] if b"\0" in blob[:8192] and not blob.startswith(b"PGDMP") else blob
    for pattern, what in SIGNATURES:
        if pattern.search(head):
            return f"contains {what}"
    return None


def main() -> int:
    findings: list[tuple[str, str]] = []
    for path in tracked_files():
        if path in EXEMPT:
            continue
        why = path_problem(path) or content_problem(path)
        if why:
            findings.append((path, why))

    if not findings:
        print("no run data is tracked")
        return 0

    print("Tracked run data:\n", file=sys.stderr)
    for path, why in findings:
        print(f"  {path}\n      {why}", file=sys.stderr)
    print(GUIDANCE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
