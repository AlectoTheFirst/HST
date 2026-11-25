"""Paths of the HST table family in the side store."""

from __future__ import annotations

import contextlib
import os
import shutil
from pathlib import Path

FAMILY = "hst"
SUFFIX = ".parquet"


def table_dir(sidestore_dir: Path, table: str) -> Path:
    return sidestore_dir / FAMILY / table


def table_path(sidestore_dir: Path, table: str, run_key: int) -> Path:
    return table_dir(sidestore_dir, table) / f"{run_key}{SUFFIX}"


def private_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        directory.chmod(0o700)


def private_file(path: Path) -> None:
    private_dir(path.parent)
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))


STAGING = ".staging"


def staging_dir(sidestore_dir: Path, run_key: int) -> Path:
    return sidestore_dir / FAMILY / STAGING / str(run_key)


def staged_path(sidestore_dir: Path, run_key: int, table: str) -> Path:
    return staging_dir(sidestore_dir, run_key) / f"{table}{SUFFIX}"


def publish_staged(sidestore_dir: Path, run_key: int) -> list[str]:
    """Move every staged table of `run_key` to its published path, one rename per file."""
    staged = staging_dir(sidestore_dir, run_key)
    if not staged.is_dir():
        return []
    tables = []
    for path in sorted(staged.glob(f"*{SUFFIX}")):
        table = path.name[: -len(SUFFIX)]
        target = table_path(sidestore_dir, table, run_key)
        private_dir(target.parent)
        path.replace(target)
        tables.append(table)
    shutil.rmtree(staged, ignore_errors=True)
    return tables


def discard_staged(sidestore_dir: Path, run_key: int) -> None:
    shutil.rmtree(staging_dir(sidestore_dir, run_key), ignore_errors=True)
