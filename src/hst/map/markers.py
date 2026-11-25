"""The run marker file `<manifests_dir>/<key>.hst.json`."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import store

SUFFIX = ".hst.json"
SCHEMA_VERSION = 1


def path_for(markers_dir: Path, key: int) -> Path:
    return markers_dir / f"{key}{SUFFIX}"


def keys(markers_dir: Path) -> list[int]:
    """Every run key with a marker, oldest first."""
    if not markers_dir.is_dir():
        return []
    out = []
    for path in markers_dir.iterdir():
        stem = path.name[: -len(SUFFIX)] if path.name.endswith(SUFFIX) else ""
        if stem.isdigit():
            out.append(int(stem))
    return sorted(out)


def read(markers_dir: Path, key: int) -> dict[str, Any] | None:
    try:
        body = path_for(markers_dir, key).read_text()
    except FileNotFoundError:
        return None
    marker: dict[str, Any] = json.loads(body)
    return marker


def write(markers_dir: Path, marker: dict[str, Any]) -> None:
    path = path_for(markers_dir, int(marker["key"]))
    markers_dir.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
    tmp.write_text(json.dumps(marker, sort_keys=True))
    tmp.replace(path)


STAGED_MARKER = "marker.json"


def write_staged(staging_dir: Path, marker: dict[str, Any]) -> None:
    tmp = staging_dir / f"{STAGED_MARKER}.{os.getpid()}.tmp"
    store.private_file(tmp)
    tmp.write_text(json.dumps(marker, sort_keys=True))
    tmp.replace(staging_dir / STAGED_MARKER)


def read_staged(staging_dir: Path) -> dict[str, Any] | None:
    try:
        marker: dict[str, Any] = json.loads((staging_dir / STAGED_MARKER).read_text())
    except FileNotFoundError:
        return None
    return marker
