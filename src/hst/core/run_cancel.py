"""Cancel requests for runs that execute in another process.

`POST /api/runs/{id}/cancel` cancels a run directly when the answering process
executes the run (app/runs_exec.py `cancel_run`). A run that executes elsewhere
(in `hst worker`, on another replica, or in `hst cycle` started from cron) is
cancelled through a file in the directory `run-cancel`. The answering process
writes one request. The executing process polls for the requests of every run
it executes (runs_exec `_watch_cancel_requests`). It takes the request and
cancels the run or the one source of the request.

A request holds the `started_at` of the run next to the run id. A request with
another start time stays on disk until the age sweep removes it.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DIRECTORY = "run-cancel"

# Files older than this are removed by the next request.
MAX_AGE_S = 3600.0


@dataclass(frozen=True)
class CancelRequest:
    run_id: int
    run_started_at: datetime
    # None cancels the whole run. A name cancels that source of the run.
    source: str | None
    by: str
    requested_at_ms: int


def _directory(settings: Any) -> Path:
    return settings.hst_data_dir / DIRECTORY


def _sweep(directory: Path) -> None:
    cutoff = time.time() - MAX_AGE_S
    for path in directory.iterdir():
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
        except OSError:
            continue


def request(settings: Any, run_id: int, run_started_at: datetime, *, by: str, source: str | None) -> Path:
    """Write one cancel request for the run with this id and start time.

    The file is written under a temporary name that the reader does not match,
    and then renamed. The reader sees the whole file or no file. The function
    raises OSError when the directory or the file cannot be written.
    """
    directory = _directory(settings)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _sweep(directory)
    body = {
        "run_id": run_id,
        "run_started_at": run_started_at.isoformat(),
        "source": source,
        "by": by,
        "requested_at_ms": int(time.time() * 1000),
    }
    fd, name = tempfile.mkstemp(prefix=".request-", suffix=".tmp", dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(body, handle)
        path = directory / f"{run_id}-{uuid.uuid4().hex}.json"
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def _parse(row: Any) -> CancelRequest:
    if not isinstance(row, dict):
        raise ValueError("the request is not a JSON object")
    source = row["source"]
    if source is not None and not isinstance(source, str):
        raise ValueError("source is neither null nor a string")
    return CancelRequest(
        run_id=int(row["run_id"]),
        run_started_at=datetime.fromisoformat(row["run_started_at"]),
        source=source,
        by=str(row["by"]),
        requested_at_ms=int(row["requested_at_ms"]),
    )


def take(settings: Any, run_id: int, run_started_at: datetime) -> list[CancelRequest]:
    """Remove and return the requests for the run with this id and start time.

    A request for the same id and another start time is left on disk. A file
    that cannot be read as a request is logged and removed. `take` does not
    create the directory.
    """
    taken = []
    for path in sorted(_directory(settings).glob(f"{run_id}-*.json")):
        try:
            found = _parse(json.loads(path.read_text()))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, TypeError, KeyError) as exc:
            logger.warning("removing the unreadable run cancel request %s (%s)", path.name, exc)
            path.unlink(missing_ok=True)
            continue
        if found.run_id != run_id or found.run_started_at != run_started_at:
            continue
        path.unlink(missing_ok=True)
        taken.append(found)
    return taken
