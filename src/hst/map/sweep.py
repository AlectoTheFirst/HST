"""The HST sweep, run in the graph prune's turn under the cycle lock."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

from . import layout_read, markers, store, timeline
from .tiers.fold import TIER_TABLES

logger = logging.getLogger(__name__)

COLD = "cold"
HISTORY_TABLES = ("graph_delta", "render_t0_delta", "render_t1_delta", "render_t2_delta", "render_bindings")


@dataclass
class Swept:
    cold: list[int] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    markers: list[int] = field(default_factory=list)


def mark_cold(markers_dir: Path, keys: Iterable[int]) -> list[int]:
    """Set `state: cold` on the markers of the runs the graph prune deleted."""
    out = []
    for key in sorted(set(keys)):
        marker = markers.read(markers_dir, key)
        if marker is None or marker.get("state") == COLD:
            continue
        markers.write(markers_dir, {**marker, "state": COLD})
        out.append(key)
    return out


def _unlink(path: Path, out: list[Path]) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    out.append(path)


def _holds_tiers(sidestore_dir: Path, key: int) -> bool:
    return any(store.table_path(sidestore_dir, name, key).exists() for name in TIER_TABLES)


def prune_tiers(sidestore_dir: Path, markers_dir: Path, checkpoint_every: int) -> list[Path]:
    """Delete the tier files of cold runs, except a checkpoint at most every `checkpoint_every` runs.

    A run without tier files of its own composes from the nearest earlier run that holds them, at most
    `checkpoint_every` - 1 runs back (tiers/read.py MAX_COMPOSE). The checkpoints are chosen by that gap
    over the existing files. When a run is out of reach of the last base, the newest cold run before it
    that still holds files is kept as the next base. A run whose parent has no tiers keeps its files.
    The delta of that run is relative to no earlier run, and the runs after it compose from its files.
    """
    marks = timeline.runs(markers_dir)
    entries = [(int(m["key"]), m.get("state") == COLD) for m in marks]
    rebased = {int(m["key"]) for before, m in pairwise(marks) if timeline.failed(before)}
    keep: set[int] = set()
    last: int | None = None  # position of the newest base kept so far
    candidate: int | None = None  # position of the newest cold run holding files since `last`
    for position, (key, cold) in enumerate(entries):
        held = _holds_tiers(sidestore_dir, key)
        if held and (not cold or key in rebased):
            if cold:
                keep.add(key)
            last, candidate = position, None
            continue
        if last is None or position - last >= checkpoint_every:
            if held:
                keep.add(key)
                last, candidate = position, None
                continue
            if candidate is not None:
                keep.add(entries[candidate][0])
                last, candidate = candidate, None
        if held:
            candidate = position
    out: list[Path] = []
    for key, cold in entries:
        if cold and key not in keep:
            for name in TIER_TABLES:
                _unlink(store.table_path(sidestore_dir, name, key), out)
    return out


def prune_history(
    sidestore_dir: Path, markers_dir: Path, days: int, now: datetime
) -> tuple[list[Path], list[int]]:
    """Delete the deltas, bindings, layout files and markers of cold runs older than `days`.

    Only the oldest runs go, up to the first run that stays. The timeline refuses a run whose parent is
    not the run before it. When the first run that stays holds no tier files, the nearest earlier run
    that holds them and the runs after it also stay as its base and its deltas. The layout files in force
    at the oldest run that stays and the layout checkpoint of that run stay. The layout files older than
    that checkpoint and the checkpoints of the deleted runs go.
    """
    cutoff = int((now - timedelta(days=days)).timestamp() * 1000)
    keys = markers.keys(markers_dir)
    prefix: list[int] = []
    first_kept = keys[-1] if keys else None
    for key in keys[:-1]:
        marker = markers.read(markers_dir, key)
        if marker is None:
            continue
        if marker.get("state") != COLD or int(marker.get("published_ts") or key) >= cutoff:
            first_kept = key
            break
        prefix.append(key)
    if first_kept is not None and not _holds_tiers(sidestore_dir, first_kept):
        while prefix and not _holds_tiers(sidestore_dir, prefix[-1]):
            prefix.pop()
        if prefix:
            prefix.pop()
    # The layout runs that the oldest run that stays reads. Every later run reads rows in force at that run.
    staying = [k for k in keys if k not in set(prefix)]
    keep_layout = _layout_in_force(sidestore_dir, staying[0]) if staying else set()
    keep_full = layout_read.checkpoint_run(sidestore_dir, staying[0]) if staying else None
    files: list[Path] = []
    gone: list[int] = []
    for key in prefix:
        for name in HISTORY_TABLES + TIER_TABLES:
            _unlink(store.table_path(sidestore_dir, name, key), files)
        if key not in keep_layout:
            _unlink(store.table_path(sidestore_dir, layout_read.TABLE, key), files)
        if key != keep_full:
            _unlink(store.table_path(sidestore_dir, layout_read.FULL_TABLE, key), files)
        _unlink(markers.path_for(markers_dir, key), files)
        gone.append(key)
    return files, gone


def _layout_in_force(sidestore_dir: Path, key: int) -> set[int]:
    """The runs of the incremental layout files that the placement at `key` reads.

    These files hold the rows in force after the checkpoint of `key` and the `removed` rows that keep an
    older row from coming back. The files older than the checkpoint are not read.
    """
    return layout_read.runs_in_force(sidestore_dir, key)


def sweep(
    sidestore_dir: Path,
    markers_dir: Path,
    pruned: Iterable[int],
    *,
    checkpoint_every: int,
    history_days: int | None,
    now: datetime | None = None,
    leased: Iterable[int] = (),
) -> Swept:
    swept = Swept(cold=mark_cold(markers_dir, pruned))
    held = [k for k in sorted(set(leased)) if (markers.read(markers_dir, k) or {}).get("state") == COLD]
    if held:
        logger.info("[hst.sweep] file deletion deferred: cold run(s) %s are being read", held)
        return swept
    swept.files = prune_tiers(sidestore_dir, markers_dir, checkpoint_every)
    if history_days is not None:
        files, gone = prune_history(sidestore_dir, markers_dir, history_days, now or datetime.now(UTC))
        swept.files += files
        swept.markers = gone
    if swept.cold or swept.files:
        logger.info(
            "[hst.sweep] %d run(s) cold, %d file(s) and %d marker(s) deleted",
            len(swept.cold),
            len(swept.files),
            len(swept.markers),
        )
    return swept
