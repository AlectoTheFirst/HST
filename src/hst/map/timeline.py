"""Timeline reads of the run markers and their
reconciliation."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import markers, store

logger = logging.getLogger(__name__)


def runs(markers_dir: Path) -> list[dict[str, Any]]:
    """The markers oldest first. A run whose parent is not the run before it is refused and logged.

    A run without a parent after other runs is the first run of a new graph after a purge. The result
    starts again at that run.
    """
    out: list[dict[str, Any]] = []
    for key in markers.keys(markers_dir):
        try:
            marker = markers.read(markers_dir, key)
        except ValueError as exc:
            logger.warning("[hst.timeline] marker %s not read: %s", key, exc)
            continue
        if marker is None:
            continue
        if out and marker.get("parent") is None:
            logger.info("[hst.timeline] run %s has no parent: it starts a new timeline", key)
            out = []
        expected = out[-1]["key"] if out else marker.get("parent")
        if marker.get("parent") != expected:
            logger.warning(
                "[hst.timeline] run %s refused: parent %s is not the previous run %s",
                key,
                marker.get("parent"),
                expected,
            )
            continue
        out.append(marker)
    return out


def failed(marker: dict[str, Any] | None) -> bool:
    """True when `tiers_ready` of the marker is false. The run has no tier files and no tier delta."""
    return marker is not None and marker.get("tiers_ready") is False


class Chain(list[int]):
    """The run keys oldest first. `rebased` holds the keys of the runs whose parent has no tiers.

    The fold of a run in `rebased` diffs against the newest earlier run that has tiers. A reader that
    composes a table, or moves one by deltas, starts again at such a run.
    """

    def __init__(self, keys: Iterable[int] = (), rebased: Iterable[int] = ()) -> None:
        super().__init__(keys)
        self.rebased = frozenset(rebased)


def chain(markers_dir: Path) -> Chain:
    entries = runs(markers_dir)
    return Chain(
        (int(m["key"]) for m in entries),
        (int(m["key"]) for before, m in pairwise(entries) if failed(before)),
    )


def ready_ancestor(markers_dir: Path, key: int | None) -> int | None:
    """The newest run at or before `key` whose projection did not fail, following the marker parents."""
    seen: set[int] = set()
    while key is not None and key not in seen:
        seen.add(key)
        try:
            marker = markers.read(markers_dir, key)
        except ValueError:
            return None
        if marker is None:
            return None
        if not failed(marker):
            return key
        parent = marker.get("parent")
        key = None if parent is None else int(parent)
    return None


def timeline(markers_dir: Path, current: int | None = None) -> dict[str, Any]:
    entries = runs(markers_dir)
    rows = [
        {
            "key": m["key"],
            "kind": m.get("kind"),
            "parent": m.get("parent"),
            "published_ts": m.get("published_ts"),
            "state": m.get("state"),
            "tiers_ready": bool(m.get("tiers_ready")),
            "counts": m.get("counts") or {"added": 0, "removed": 0, "changed": 0},
            "replan_recommended": bool(m.get("replan_recommended")),
        }
        for m in entries
    ]
    if current is None and rows:
        current = rows[-1]["key"]
    return {"current": current, "runs": rows}


def reconcile(
    markers_dir: Path,
    sidestore_dir: Path,
    pointer: int | None,
    fallback: Callable[[int], dict[str, Any]],
) -> bool:
    """Write a marker for the run `pointer` if the run has none. True when a marker was written.

    The staged tables and the staged marker of the run are published if they exist. Without them, the
    marker is `fallback(pointer)` with `tiers_ready` false.
    """
    if pointer is None or markers.read(markers_dir, pointer) is not None:
        return False
    staging = store.staging_dir(sidestore_dir, pointer)
    staged = markers.read_staged(staging)
    if staged is not None:
        store.publish_staged(sidestore_dir, pointer)
        markers.write(markers_dir, staged)
        logger.warning("[hst.timeline] run %s: marker healed from its staged projection", pointer)
        return True
    marker = {**fallback(pointer), "key": pointer, "tiers_ready": False, "state": "warm"}
    markers.write(markers_dir, marker)
    logger.warning("[hst.timeline] run %s: marker healed without tiers", pointer)
    return True
