from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CollectionProgress:
    def __init__(self, settings, source: str):
        self.directory = settings.hst_data_dir / "collection-progress"
        self.path = self.directory / f"{hashlib.sha256(source.encode()).hexdigest()}.json"
        self.data: dict[str, Any] = {
            "source": source,
            "started_at_ms": int(time.time() * 1000),
            "state": "collecting",
        }
        self.phase_started = time.monotonic()
        self.last_write = 0.0

    def phase(self, phase: str, total: int | None = None, **context: Any) -> None:
        self.phase_started = time.monotonic()
        self.data.update(phase=phase, completed=0, total=total, phase_eta_s=None, **context)
        self.write(force=True)

    def advance(self, completed: int) -> None:
        elapsed = time.monotonic() - self.phase_started
        total = self.data.get("total")
        eta = None
        if total is not None and completed >= total:
            eta = 0
        elif total and completed >= 5 and elapsed >= 2:
            eta = round(elapsed * (total - completed) / completed)
        self.data.update(completed=completed, phase_eta_s=eta)
        self.write(force=completed == total)

    def finish(self, success: bool) -> None:
        self.data.update(state="collected" if success else "failed", phase_eta_s=None)
        self.write(force=True)

    def write(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_write < 1:
            return
        self.last_write = now
        self.data["updated_at_ms"] = int(time.time() * 1000)
        temporary: Path | None = None
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix="progress-", dir=self.directory)
            temporary = Path(name)
            with os.fdopen(fd, "w") as handle:
                json.dump(self.data, handle)
            temporary.replace(self.path)
        except OSError:
            logger.warning("Could not write collection progress for %s", self.data["source"])
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def read_progress(settings, *, source: str | None, since_ms: int) -> list[dict[str, Any]]:
    directory = settings.hst_data_dir / "collection-progress"
    paths: Iterable[Path]
    if source is None:
        paths = directory.glob("*.json")
    else:
        paths = [directory / f"{hashlib.sha256(source.encode()).hexdigest()}.json"]
    records = []
    for path in paths:
        try:
            row = json.loads(path.read_text())
            if isinstance(row, dict) and row.get("started_at_ms", 0) >= since_ms:
                records.append(row)
        except (OSError, ValueError, TypeError):
            continue
    return sorted(records, key=lambda row: row.get("source", ""))
