"""The HST events, with `Event` and `LocalBus`."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import AsyncIterator, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from . import markers, store

logger = logging.getLogger(__name__)

RUN_PUBLISHED = "run.published"
RUN_TIERS_READY = "run.tiers_ready"
DELTA_RECORD = "delta.record"
LAYOUT_CHANGED = "layout.changed"
VERDICT_COMPUTED = "verdict.computed"
TYPES = frozenset({RUN_PUBLISHED, RUN_TIERS_READY, DELTA_RECORD, LAYOUT_CHANGED, VERDICT_COMPUTED})
MARKER_TYPES = frozenset({RUN_PUBLISHED, RUN_TIERS_READY})

GRAPH_DELTA_TABLE = "graph_delta"
LAYOUT_TABLE = "layout"
POLL_INTERVAL_S = 5.0


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class Event:
    type: str
    run_key: int
    seq: int
    payload: dict[str, Any]
    ts: int = field(default_factory=_now_ms, compare=False)

    def __post_init__(self) -> None:
        if self.type not in TYPES:
            raise ValueError(f"unknown event type {self.type!r}")
        if self.seq < 0:
            raise ValueError(f"negative seq {self.seq}")

    @property
    def position(self) -> tuple[int, int]:
        return (self.run_key, self.seq)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "run_key": self.run_key,
            "seq": self.seq,
            "ts": self.ts,
            "payload": self.payload,
        }


def published_payload(marker: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": marker.get("kind"),
        "parent": marker.get("parent"),
        "published": marker.get("published_ts"),
        "counts": marker.get("counts", {}),
    }


def tiers_ready_payload(marker: dict[str, Any]) -> dict[str, Any]:
    return {
        "durations": marker.get("durations_ms", {}),
        "peak_memory_bytes": marker.get("peak_memory_bytes", 0),
        "replan_recommended": bool(marker.get("replan_recommended", False)),
        "state": marker.get("state"),
    }


def _row_count(path: Path) -> int:
    try:
        return int(pq.read_metadata(path).num_rows)
    except FileNotFoundError:
        return 0


def _rows(path: Path) -> Iterator[dict[str, Any]]:
    try:
        parquet = pq.ParquetFile(path)
    except FileNotFoundError:
        return
    for batch in parquet.iter_batches():
        yield from batch.to_pylist()


@dataclass
class _Subscriber:
    types: frozenset[str]
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue[Event]

    def deliver(self, event: Event) -> None:
        try:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, event)
        except RuntimeError:
            logger.debug("[hst.events] subscriber loop closed; %s dropped", event.type)


class LocalBus:
    """An in-process fan-out of events, with a poll of the markers for the runs that other
    processes published."""

    def __init__(self, markers_dir: Path, sidestore_dir: Path) -> None:
        self._markers_dir = markers_dir
        self._sidestore_dir = sidestore_dir
        self._lock = threading.Lock()
        self._last_seq: dict[int, int] = {}
        self._subscribers: list[_Subscriber] = []
        # The markers present at start count as seen.
        self._seen: dict[int, set[str]] = {key: set(MARKER_TYPES) for key in markers.keys(markers_dir)}

    def publish(self, event: Event) -> None:
        with self._lock:
            last = self._last_seq.get(event.run_key, -1)
            if event.seq <= last:
                raise ValueError(f"run {event.run_key}: seq {event.seq} after seq {last}")
            self._last_seq[event.run_key] = event.seq
            if event.type in MARKER_TYPES:
                self._seen.setdefault(event.run_key, set()).add(event.type)
            targets = [s for s in self._subscribers if event.type in s.types]
        for subscriber in targets:
            subscriber.deliver(event)

    async def subscribe(
        self, types: Iterable[str], since: tuple[int, int] | None = None
    ) -> AsyncIterator[Event]:
        """The events of `types` after `since`. The stored events come first, then the live events."""
        wanted = frozenset(types)
        if not wanted <= TYPES:
            raise ValueError(f"unknown event types {sorted(wanted - TYPES)}")
        subscriber = _Subscriber(wanted, asyncio.get_running_loop(), asyncio.Queue())
        with self._lock:
            self._subscribers.append(subscriber)
        try:
            replayed = since
            if since is not None:
                for key in markers.keys(self._markers_dir):
                    if key < since[0]:
                        continue
                    for event in self.replay(key, wanted):
                        if event.position > since:
                            replayed = event.position
                            yield event
            while True:
                event = await subscriber.queue.get()
                if replayed is not None and event.position <= replayed:
                    continue
                yield event
        finally:
            with self._lock:
                self._subscribers.remove(subscriber)

    def replay(self, run_key: int, types: Iterable[str] = TYPES) -> list[Event]:
        """The sequence the projection published for `run_key`, from the marker and the tables."""
        marker = markers.read(self._markers_dir, run_key)
        if marker is None:
            return []
        wanted = frozenset(types)
        delta_path = store.table_path(self._sidestore_dir, GRAPH_DELTA_TABLE, run_key)
        layout_path = store.table_path(self._sidestore_dir, LAYOUT_TABLE, run_key)
        out: list[Event] = []
        if RUN_PUBLISHED in wanted:
            out.append(Event(RUN_PUBLISHED, run_key, 0, published_payload(marker)))
        seq = 1
        if DELTA_RECORD in wanted:
            for row in _rows(delta_path):
                out.append(Event(DELTA_RECORD, run_key, seq, row))
                seq += 1
        else:
            seq += _row_count(delta_path)
        if LAYOUT_CHANGED in wanted:
            for row in _rows(layout_path):
                out.append(Event(LAYOUT_CHANGED, run_key, seq, row))
                seq += 1
        else:
            seq += _row_count(layout_path)
        if RUN_TIERS_READY in wanted and marker.get("tiers_ready"):
            out.append(Event(RUN_TIERS_READY, run_key, seq, tiers_ready_payload(marker)))
        return out

    def poll_markers(self) -> list[Event]:
        """Publish `run.published` and `run.tiers_ready` for markers this process has not seen."""
        out: list[Event] = []
        for key in markers.keys(self._markers_dir):
            with self._lock:
                missing = MARKER_TYPES - self._seen.get(key, set())
            if not missing:
                continue
            try:
                events = self.replay(key, missing)
            except (OSError, ValueError) as exc:
                logger.warning("[hst.events] marker %s not read: %s", key, exc)
                continue
            for event in events:
                try:
                    self.publish(event)
                except ValueError as exc:
                    logger.warning("[hst.events] %s", exc)
                    continue
                out.append(event)
        return out

    async def run_poll(self, interval: float = POLL_INTERVAL_S) -> None:
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self.poll_markers)


_default: LocalBus | None = None


def set_default_bus(bus: LocalBus | None) -> None:
    """Set the bus to which this process publishes the events of the projection."""
    global _default
    _default = bus


def default_bus() -> LocalBus | None:
    return _default
