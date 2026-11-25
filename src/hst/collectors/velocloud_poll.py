"""A bounded work queue and an encrypted VCO poll cache.

The cache is separate from snapshot evidence. A reused response keeps its original
observation time. A successful empty response replaces the old entry. A failed read
keeps the old entry.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from hst.app import crypto
from hst.core import rawstore
from hst.core.mtu import canonical_json

logger = logging.getLogger(__name__)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def bounded_map[T, R](
    pool: ThreadPoolExecutor, workers: int, fn: Callable[[T], R], items: Iterable[T]
) -> Iterator[R]:
    items = iter(items)
    pending = deque()
    for _ in range(2 * workers):
        try:
            pending.append(pool.submit(fn, next(items)))
        except StopIteration:
            break
    while pending:
        yield pending.popleft().result()
        with contextlib.suppress(StopIteration):
            pending.append(pool.submit(fn, next(items)))


class PollCache:
    def __init__(self, settings, identity: dict[str, Any], *, enabled: bool):
        self.enabled = enabled
        self.entries: dict[str, dict[str, Any]] = {}
        self.used: set[str] = set()
        self.lock = threading.Lock()
        self.hits = 0
        self.stale = 0
        self.key: str | None = None
        self.directory = settings.raw_dir / "velocloud" / "poll-cache" / digest(identity)
        self.path = self.directory / f"current{rawstore.SUFFIX}"
        try:
            self.key = crypto.dek(settings)
            if enabled and self.path.is_file():
                data = rawstore.read(self.path, self.key)
                if isinstance(data, dict) and data.get("version") == 1:
                    self.entries = {
                        k: v
                        for k, v in data.get("entries", {}).items()
                        if isinstance(v, dict)
                        and isinstance(v.get("observed_at_ms"), int)
                        and "value" in v
                        and isinstance(v.get("signature"), str)
                    }
        except (OSError, EOFError, ValueError, AttributeError, crypto.SecretKeyError):
            logger.warning("velocloud: persistent poll cache unavailable; collecting live")

    def read(
        self,
        key: tuple[str, ...],
        ttl_s: int,
        signature: str,
        fetch: Callable[[], Any],
        *,
        stale_on_error: bool = False,
    ) -> tuple[Any, dict[str, Any]]:
        name = canonical_json(key)
        now_ms = int(time.time() * 1000)
        with self.lock:
            self.used.add(name)
            previous = self.entries.get(name) if self.enabled else None
            if previous and previous["signature"] != signature:
                previous = None
            if previous and 0 <= now_ms - previous["observed_at_ms"] < ttl_s * 1000:
                self.hits += 1
                return previous["value"], self._freshness(previous)
        try:
            value = fetch()
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            transient = (
                isinstance(exc, httpx.TransportError)
                or exc.response.status_code == 429
                or (isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500)
            )
            if not stale_on_error or not transient:
                raise
            with self.lock:
                self.stale += 1
            # Authentication and malformed responses never become cache hits.
            detail = type(exc).__name__
            if previous:
                return previous["value"], {**self._freshness(previous), "stale": True, "error": detail}
            return {
                "_capability": {
                    "status": "unavailable",
                    "operation": key[-1],
                    "reason": "Observation refresh failed",
                    "detail": detail,
                }
            }, {"stale": True, "error": detail}
        entry = {
            "value": value,
            "observed_at_ms": now_ms,
            "signature": signature,
        }
        if not (isinstance(value, dict) and "_capability" in value):
            with self.lock:
                self.entries[name] = entry
        return value, self._freshness(entry)

    @staticmethod
    def _freshness(entry: dict[str, Any]) -> dict[str, Any]:
        return {"observed_at_ms": entry["observed_at_ms"], "stale": False}

    def save(self, *, complete: bool) -> None:
        if self.key is None:
            return
        # Only a complete discovery evicts entries that this poll did not read.
        entries = {k: v for k, v in self.entries.items() if not complete or k in self.used}
        temporary = None
        try:
            temporary = rawstore.write(
                self.directory.parent,
                self.directory.name,
                f"pending-{uuid.uuid4().hex}",
                {"version": 1, "entries": entries},
                key=self.key,
            )
            temporary.replace(self.path)
        except OSError:
            logger.warning("velocloud: could not save poll cache; next poll will refetch")
        finally:
            if temporary is not None:
                with contextlib.suppress(OSError):
                    temporary.unlink(missing_ok=True)
