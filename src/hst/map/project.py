"""The publish-time projection.

A `Projection` lives for one run under the cycle lock. `observe` takes each
record of the manifest's diff, `prepare` folds the tiers and places the
layout into staged files before the pointer moves, and `publish` makes them
visible, writes the marker and publishes the run's events after it. A
failure is logged and leaves the run with `tiers_ready: false`. It does not
fail the run.
"""

from __future__ import annotations

import logging
import resource
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from . import events, layout, layout_read, markers, site_config, store, timeline
from .graph_delta import TABLE as GRAPH_DELTA_TABLE
from .graph_delta import GraphDeltaWriter, fill_devices
from .tiers import bootstrap
from .tiers.fold import TIER_TABLES, Attribution, Folded, Parent, differences, fold
from .tiers.schemas import RENDER_BINDINGS, SCHEMAS

logger = logging.getLogger(__name__)

ROW_GROUP_ROWS = 10_000
STEPS = ("delta", "attribution", "fold", "layout", "write")


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def peak_memory_bytes() -> int:
    """The peak resident set size of the process in bytes. `ru_maxrss` is in kilobytes on Linux and
    in bytes on macOS."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _write(path: Path, name: str, rows: list[dict[str, Any]] | pa.Table) -> None:
    store.private_file(path)
    table = rows if isinstance(rows, pa.Table) else pa.Table.from_pylist(rows, schema=SCHEMAS[name])
    pq.write_table(table, path, row_group_size=ROW_GROUP_ROWS)


@dataclass
class Projection:
    sidestore_dir: Path
    markers_dir: Path
    run_key: int
    parent_key: int | None
    kind: str
    checkpoint_every: int = 30
    replan: bool = False
    durations_ms: dict[str, int] = field(default_factory=lambda: dict.fromkeys(STEPS, 0))
    failed: str | None = None
    marker: dict[str, Any] | None = None
    differences: list[str] = field(default_factory=list)
    folded: Folded | None = None
    replan_tiers: bool = False

    def __post_init__(self) -> None:
        self._started = time.perf_counter()
        self._writer: GraphDeltaWriter | None = None
        self._attribution: Attribution | None = None
        self._parent: Parent | None = None
        self._rebased = False
        try:
            self._discard_stale_stages()
            self._parent = self._load_parent()
            self._attribution = Attribution(self._parent.tables.get("render_t1", {}), self._parent.groups())
            if self.parent_key is not None:
                self._writer = GraphDeltaWriter(
                    store.staged_path(self.sidestore_dir, self.run_key, GRAPH_DELTA_TABLE),
                    snapshot_ts=self.run_key,
                    parent_ts=self.parent_key,
                )
        except Exception as exc:
            self._fail("start", exc)

    def _load_parent(self) -> Parent:
        """The tiers that the fold diffs against. They are the tiers of the parent run, or of the newest
        earlier run that has tiers.

        A failed projection publishes a run without tables.
        """
        parent = Parent.load(self.sidestore_dir, self.parent_key)
        if self.parent_key is None or not timeline.failed(markers.read(self.markers_dir, self.parent_key)):
            return parent
        self._rebased = True
        ancestor = Parent.load(self.sidestore_dir, timeline.ready_ancestor(self.markers_dir, self.parent_key))
        return ancestor if ancestor.ready else parent

    def _fail(self, step: str, exc: BaseException) -> None:
        self.failed = f"{step}: {type(exc).__name__}: {exc}"
        logger.warning(
            "[hst.project] run %s: projection failed at %s", self.run_key, self.failed, exc_info=exc
        )

    def _discard_stale_stages(self) -> None:
        root = store.staging_dir(self.sidestore_dir, 0).parent
        if root.is_dir():
            for path in root.iterdir():
                if path.name != str(self.run_key):
                    store.discard_staged(self.sidestore_dir, int(path.name) if path.name.isdigit() else 0)

    def observe(self, record: dict[str, Any]) -> None:
        if self.failed is not None or self._attribution is None or self._writer is None:
            return
        started = time.perf_counter()
        try:
            self._writer.add(record, self._attribution.observe(record))
        except Exception as exc:
            self._fail("delta", exc)
        self.durations_ms["delta"] += int((time.perf_counter() - started) * 1000)

    def _timed(self, step: str, work: Callable[[], Any]) -> Any:
        started = time.perf_counter()
        try:
            return work()
        finally:
            self.durations_ms[step] += int((time.perf_counter() - started) * 1000)

    def prepare(self, session: bootstrap.Session, *, complete: bool = True) -> None:
        """Fold the tiers and place the layout into staged files. Runs before the pointer moves.

        `complete` is false when the diff did not finish. Its records are then dropped and every device
        is read.
        """
        if self.failed is not None or self._parent is None or self._attribution is None:
            return
        try:
            if not complete:
                self._writer = None
                self._attribution = Attribution(self._attribution.devices, {})
                store.staged_path(self.sidestore_dir, self.run_key, GRAPH_DELTA_TABLE).unlink(missing_ok=True)
                self.replan_tiers = True
            self._prepare(session, self._parent, self._attribution)
        except Exception as exc:
            self._fail("prepare", exc)

    def _prepare(self, session: bootstrap.Session, parent: Parent, attribution: Attribution) -> None:
        staged = store.staging_dir(self.sidestore_dir, self.run_key)
        if self._writer is not None:
            self._writer.close()
        rows_t = self._timed("attribution", lambda: bootstrap.device_rows(session, self.run_key))
        resolved = self._timed("attribution", lambda: attribution.resolve(rows_t, parent.bindings))
        delta_path = store.staged_path(self.sidestore_dir, self.run_key, GRAPH_DELTA_TABLE)
        self._timed("attribution", lambda: fill_devices(delta_path, resolved))

        config = site_config.read(self.sidestore_dir)
        # A change of the site groups or the named blocks places the layout again in full.
        before = markers.read(self.markers_dir, self.parent_key) if self.parent_key is not None else None
        regroup = before is not None and before.get("site_config") != config.fingerprint()
        position = len(timeline.chain(self.markers_dir))
        # The graph diff of this run covers the span from its parent run only. A fold against an older
        # run reads every device.
        full = (
            not parent.ready
            or self._rebased
            or self.replan
            or self.replan_tiers
            or position % self.checkpoint_every == 0
        )
        affected = None if full else attribution.affected
        folded: Folded = self._timed(
            "fold", lambda: fold(session, self.run_key, parent, affected, rows_t, config)
        )
        if full and parent.ready and not self._rebased:
            incremental = self._timed(
                "fold", lambda: fold(session, self.run_key, parent, attribution.affected, rows_t, config)
            )
            self.differences = differences(incremental, folded)
            for line in self.differences:
                logger.warning("[hst.project] run %s consistency: %s", self.run_key, line)
        self.folded = folded

        current = {uid: layout.Placement.from_row(r) for uid, r in self._current_layout().items()}
        if self.replan or regroup:
            placed = self._timed("layout", lambda: layout.replan(folded.estate, current, self.run_key))
        else:
            placed = self._timed("layout", lambda: layout.place(folded.estate, current, self.run_key))

        def write() -> None:
            for name in TIER_TABLES:
                _write(store.staged_path(self.sidestore_dir, self.run_key, name), name, folded.tables[name])
            for name, rows in folded.deltas.items():
                stamped = [{**r, "snapshot_ts": self.run_key, "parent_ts": self.parent_key} for r in rows]
                _write(store.staged_path(self.sidestore_dir, self.run_key, name), name, stamped)
            _write(
                store.staged_path(self.sidestore_dir, self.run_key, "render_bindings"),
                "render_bindings",
                folded.bindings.cast(RENDER_BINDINGS),
            )
            if placed.rows:
                layout.write(store.staged_path(self.sidestore_dir, self.run_key, layout.TABLE), placed.rows)
            checkpoint = self._layout_checkpoint(current, placed)
            if checkpoint:
                layout.write(
                    store.staged_path(self.sidestore_dir, self.run_key, layout_read.FULL_TABLE), checkpoint
                )

        self._timed("write", write)
        self.marker = self._marker(
            tiers_ready=True,
            counts=folded.counts,
            replan_recommended=placed.replan_recommended,
            layout_version=placed.layout_version,
            site_config=config.fingerprint(),
        )
        markers.write_staged(staged, self.marker)

    def _layout_checkpoint(
        self, current: Mapping[str, layout.Placement], placed: layout.Result
    ) -> list[layout.Placement]:
        """Every row in force after this run, when `checkpoint_every` incremental layout files were
        written since the last checkpoint. The placement at t starts from the newest checkpoint and reads
        at most that many files. A replan places every element, and its checkpoint holds no row of an
        older version. The `removed` rows of this version stay in the checkpoint. They keep an older row
        from coming back."""
        since = (
            layout_read.chain_length(self.sidestore_dir, self.parent_key)
            if self.parent_key is not None
            else 0
        )
        if since + bool(placed.rows) < self.checkpoint_every:
            return []
        in_force: dict[str, layout.Placement] = {}
        if self.parent_key is not None and placed.layout_version == layout.current_version(current):
            held = layout_read.rows_at(self.sidestore_dir, self.parent_key, removed=True)
            in_force = {uid: layout.Placement.from_row(r) for uid, r in held.items()}
        in_force.update({p.uid: p for p in placed.rows})
        return list(in_force.values())

    def _current_layout(self) -> dict[str, dict[str, Any]]:
        if self.parent_key is None:
            return {}
        return layout_read.rows_at(self.sidestore_dir, self.parent_key)

    def _marker(self, **fields: Any) -> dict[str, Any]:
        return {
            "key": self.run_key,
            "kind": self.kind,
            "parent": self.parent_key,
            "published_ts": _now_ms(),
            "state": "warm",
            "tiers_ready": False,
            "counts": {"added": 0, "removed": 0, "changed": 0},
            "replan_recommended": False,
            "layout_version": 0,
            "durations_ms": dict(self.durations_ms),
            "peak_memory_bytes": peak_memory_bytes(),
            "schema_version": markers.SCHEMA_VERSION,
            **fields,
        }

    def publish(self, bus: events.LocalBus | None = None) -> dict[str, Any]:
        """Make the staged files visible, write the marker and publish the events, after the pointer moves."""
        try:
            if self.failed is not None or self.marker is None:
                store.discard_staged(self.sidestore_dir, self.run_key)
                self.marker = self._marker(failure=self.failed)
            store.publish_staged(self.sidestore_dir, self.run_key)
            self.marker = {**self.marker, "durations_ms": dict(self.durations_ms), "published_ts": _now_ms()}
            markers.write(self.markers_dir, self.marker)
        except Exception as exc:
            self._fail("publish", exc)
            return self.marker or {}
        target = bus if bus is not None else events.default_bus()
        if target is not None:
            try:
                for event in target.replay(self.run_key):
                    target.publish(event)
            except Exception as exc:
                logger.warning("[hst.project] run %s: events not published: %s", self.run_key, exc)
        return self.marker


def reconcile(
    sidestore_dir: Path, markers_dir: Path, pointer: int | None, fallback: Callable[[int], Mapping[str, Any]]
) -> bool:
    """Heal the marker of the run the pointer names (`timeline.reconcile`)."""
    try:
        return timeline.reconcile(markers_dir, sidestore_dir, pointer, lambda key: dict(fallback(key)))
    except Exception as exc:
        logger.warning("[hst.project] reconcile of run %s failed: %s", pointer, exc)
        return False
