"""Reads of a tier and of a delta at (t, tile), with the composition of cold runs."""

from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from .. import port_groups, store, timeline
from . import delta as deltamod
from .schemas import DELTA_OF, SCHEMAS, TILED, key_of

COMPOSED_CACHE = 32
# A cold read composes the nearest earlier checkpoint with at most this many deltas.
MAX_COMPOSE = 29


class NotFound(LookupError):
    pass


def read_table(sidestore_dir: Path, name: str, run_key: int) -> pa.Table | None:
    path = store.table_path(sidestore_dir, name, run_key)
    if not path.exists():
        return None
    return pq.read_table(path, schema=SCHEMAS[name])


def _tile_filter(table: pa.Table, name: str, tile: str | None) -> pa.Table:
    if name not in TILED or tile is None:
        return table
    if name == "render_t2_cables":
        mask = pc.or_(pc.equal(table["tile_a"], tile), pc.equal(table["tile_b"], tile))
    else:
        mask = pc.equal(table["tile"], tile)
    return table.filter(pc.fill_null(mask, False))


DEVICE_FILTERED = frozenset({"render_t2_ports", "render_t2_cables"})


def device_filter(table: pa.Table, name: str, device: str) -> pa.Table:
    if name == "render_t2_cables":
        mask = pc.or_(pc.equal(table["a_dev"], device), pc.equal(table["b_dev"], device))
    else:
        mask = pc.equal(table["device_uid"], device)
    return table.filter(pc.fill_null(mask, False))


_cache: OrderedDict[tuple[str, str, int], pa.Table] = OrderedDict()
_cache_lock = threading.Lock()


ADDED_LATER = frozenset({"render_t1_circuits", "render_t1_fabric_ports"})


def tier_at(sidestore_dir: Path, name: str, t: int, chain: list[int], tile: str | None = None) -> pa.Table:
    """Tier `name` at run `t`, from its own file or from the nearest earlier file in `chain` and the deltas.

    `chain` is every run key in publish order up to `t`.
    """
    if name in TILED and tile is None:
        raise ValueError(f"{name} is tiled: a tile is required")
    table = read_table(sidestore_dir, name, t)
    if table is None:
        try:
            table = _composed(sidestore_dir, name, t, chain)
        except NotFound:
            if name not in ADDED_LATER:
                raise
            table = SCHEMAS[name].empty_table()
    return _tile_filter(table, name, tile)


def port_groups_at(sidestore_dir: Path, t: int, chain: list[int], tile: str | None) -> list[dict[str, Any]]:
    ports = tier_at(sidestore_dir, "render_t2_ports", t, chain, tile)
    cables = tier_at(sidestore_dir, "render_t2_cables", t, chain, tile)
    return port_groups.groups(
        ports.select(["uid", "device_uid", "tile", "name", "admin_status", "oper_status"]).to_pylist(),
        cables.select(["a_port", "b_port"]).to_pylist(),
    )


def _composed(sidestore_dir: Path, name: str, t: int, chain: list[int]) -> pa.Table:
    key = (str(sidestore_dir), name, t)
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    if t not in chain:
        raise NotFound(f"run {t} is not in the timeline")
    upto = chain[: chain.index(t) + 1]
    # The delta of a run whose parent has no tiers is relative to no earlier run. The base of the
    # composition is the file of that run or of a later run.
    rebased = chain.rebased if isinstance(chain, timeline.Chain) else frozenset()
    floor = max((i for i, run in enumerate(upto) if run in rebased), default=-1)
    for i in range(len(upto) - 1, max(floor - 1, -1, len(upto) - 2 - MAX_COMPOSE), -1):
        base = read_table(sidestore_dir, name, upto[i])
        if base is None:
            continue
        rows = {key_of(name, r): r for r in base.to_pylist()}
        for run in upto[i + 1 :]:
            deltamod.apply(rows, delta_rows(sidestore_dir, DELTA_OF[name], run, table=name))
        if "snapshot_ts" in SCHEMAS[name].names:
            for row in rows.values():
                row["snapshot_ts"] = t
        table = pa.Table.from_pylist(list(rows.values()), schema=SCHEMAS[name])
        with _cache_lock:
            _cache[key] = table
            while len(_cache) > COMPOSED_CACHE:
                _cache.popitem(last=False)
        return table
    raise NotFound(f"no {name} checkpoint within {MAX_COMPOSE} runs before {t}")


def delta_rows(
    sidestore_dir: Path, delta_name: str, run_key: int, *, table: str | None = None, tile: str | None = None
) -> list[dict[str, Any]]:
    data = read_table(sidestore_dir, delta_name, run_key)
    if data is None:
        return []
    if table is not None:
        data = data.filter(pc.equal(data["table"], table))
    if tile is not None:
        data = data.filter(pc.fill_null(pc.equal(data["tile"], tile), False))
    rows: list[dict[str, Any]] = data.to_pylist()
    return rows


def device_delta(sidestore_dir: Path, run_key: int, device_uid: str) -> list[dict[str, Any]]:
    """The `graph_delta` rows of one device at one run. These rows are Tier 3 of a cold run."""
    data = read_table(sidestore_dir, "graph_delta", run_key)
    if data is None:
        return []
    rows: list[dict[str, Any]] = data.filter(
        pc.fill_null(pc.equal(data["device_uid"], device_uid), False)
    ).to_pylist()
    return rows
