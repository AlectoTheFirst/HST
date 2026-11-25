"""Reads of the placement at t and of the layout delta at t from the layout table.

A run that moves a placement writes the rows it changed to `layout/<run>`. Every `checkpoint_every`
such files, the projection also writes `layout_full/<run>` with every row in force at that run. The
placement at t starts from the newest checkpoint at or below t and reads at most `checkpoint_every`
incremental files. The placement at one run is kept (`layout_at`) with an index of its tiles.
"""

from __future__ import annotations

import threading
from array import array
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from . import store
from .layout import LAYOUT, REMOVED

TABLE = "layout"
# The checkpoint table holds every row in force at the run, under the layout version in force.
FULL_TABLE = "layout_full"
# The count of placements kept in memory. The tiles of the current run read one, and a scrub step reads one.
CACHE_SIZE = 2
# The kinds `/layout` serves without a tile. Ports and cables are served per block.
BASE_KINDS = frozenset({"region", "site", "plate", "block", "group", "device"})


def keys(sidestore_dir: Path, table: str = TABLE) -> list[int]:
    """The runs that wrote rows to `table` (the layout, or its checkpoints), oldest first."""
    directory = store.table_dir(sidestore_dir, table)
    if not directory.is_dir():
        return []
    stems = (p.name[: -len(store.SUFFIX)] for p in directory.iterdir() if p.name.endswith(store.SUFFIX))
    return sorted(int(s) for s in stems if s.isdigit())


def _rows(sidestore_dir: Path, key: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = pq.read_table(store.table_path(sidestore_dir, TABLE, key)).to_pylist()
    return rows


def _chain(sidestore_dir: Path, t: int) -> tuple[list[Path], int | None, int]:
    """The files the placement at `t` reads, the run of its checkpoint and the count of incremental files.

    The files are newest first. They are the incremental files after the newest checkpoint at or below
    `t`, then that checkpoint.
    """
    full = [k for k in keys(sidestore_dir, FULL_TABLE) if k <= t]
    base = full[-1] if full else None
    incremental = [k for k in keys(sidestore_dir) if k <= t and (base is None or k > base)]
    paths = [store.table_path(sidestore_dir, TABLE, k) for k in reversed(incremental)]
    if base is not None:
        paths.append(store.table_path(sidestore_dir, FULL_TABLE, base))
    return paths, base, len(incremental)


def chain_length(sidestore_dir: Path, t: int) -> int:
    """How many incremental layout files the placement at `t` reads after its checkpoint."""
    return _chain(sidestore_dir, t)[2]


def _in_force(paths: Sequence[Path]) -> pa.Table:
    """The rows in force from `paths`, newest first, as the first row per uid of the version in force."""
    out: list[pa.Table] = []
    seen: set[str] = set()
    version = None
    for path in paths:
        table = pq.read_table(path)
        if table.num_rows == 0:
            continue
        newest = pc.max(table["layout_version"]).as_py()
        if version is None:
            version = newest
        elif newest < version:
            break
        table = table.filter(pc.equal(table["layout_version"], version))
        take = []
        for i, uid in enumerate(table["uid"].to_pylist()):
            if uid not in seen:
                seen.add(uid)
                take.append(i)
        out.append(table.take(pa.array(take, pa.int64())))
    return pa.concat_tables(out) if out else LAYOUT.empty_table()


class _Slim:
    """The fields of a row that the block walk reads."""

    __slots__ = ("kind", "parent_uid", "uid")

    def __init__(self, uid: str, kind: str, parent_uid: str | None) -> None:
        self.uid = uid
        self.kind = kind
        self.parent_uid = parent_uid

    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)


class Layout:
    """The rows in force at one run, including the `removed` ones, as an Arrow table, with the base kinds
    as dicts and, per tile, the positions of its port and cable rows.

    A cable is in the tile of each of its two ports, as `in_tile` reads it."""

    def __init__(self, table: pa.Table) -> None:
        self.table = table
        uids = table["uid"].to_pylist()
        kinds = table["kind"].to_pylist()
        parents = table["parent_uid"].to_pylist()
        self._removed = bytearray(r == REMOVED for r in table["reason"].to_pylist())
        slim: dict[str, Any] = {u: _Slim(u, k, p) for u, k, p in zip(uids, kinds, parents, strict=True)}
        self._base: dict[str, dict[str, Any]] = {}
        base_at = [i for i, k in enumerate(kinds) if k in BASE_KINDS]
        for row in table.take(pa.array(base_at, pa.int64())).to_pylist():
            self._base[row["uid"]] = row
        blocks: dict[str | None, str | None] = {}

        def block_of(parent: str | None) -> str | None:
            if parent not in blocks:
                blocks[parent] = _block(slim, parent)
            return blocks[parent]

        tiles: dict[str, array[int]] = {}
        for i, (uid, kind, parent) in enumerate(zip(uids, kinds, parents, strict=True)):
            if kind == "port":
                found = {block_of(parent)}
            elif kind == "cable":
                found = {block_of(slim[p].parent_uid) for p in _cable_ports(slim, uid)}
            else:
                continue
            for tile in found:
                if tile is not None:
                    tiles.setdefault(tile, array("l")).append(i)
        self._tiles = tiles

    def is_block(self, tile: str, *, removed: bool = False) -> bool:
        """Whether `tile` is a block of the layout, and not a removed one unless `removed`."""
        row = self._base.get(tile)
        return row is not None and row["kind"] == "block" and (removed or row["reason"] != REMOVED)

    def rows(self, tile: str | None) -> list[dict[str, Any]]:
        """The rows in force in block `tile`, or the base kinds when `tile` is None, without removed rows."""
        if tile is None:
            return [r for r in self._base.values() if r["reason"] != REMOVED]
        at = [i for i in self._tiles.get(tile, ()) if not self._removed[i]]
        return self.table.take(pa.array(at, pa.int64())).to_pylist()

    def delta(self, subset: Sequence[Mapping[str, Any]], tile: str | None) -> list[Mapping[str, Any]]:
        """The rows of `subset`, the rows of one run, that are in block `tile`, or the base kinds."""
        if tile is None:
            return [r for r in subset if r["kind"] in BASE_KINDS]
        inside = set(self._tiles.get(tile, ()))
        if not inside or not subset:
            return []
        found = pc.index_in(
            pa.array([r["uid"] for r in subset], pa.string()), value_set=self.table["uid"].combine_chunks()
        )
        return [r for r, i in zip(subset, found.to_pylist(), strict=True) if i is not None and i in inside]

    def as_dicts(self, *, removed: bool = False) -> dict[str, dict[str, Any]]:
        out = {r["uid"]: r for r in self.table.to_pylist()}
        return out if removed else {u: r for u, r in out.items() if r["reason"] != REMOVED}


_lock = threading.Lock()
_AT: OrderedDict[
    tuple[str, tuple[tuple[str, int, int], ...]], tuple[tuple[tuple[str, int, int], ...], Layout]
] = OrderedDict()


def _stamp(paths: Sequence[Path]) -> tuple[tuple[str, int, int], ...]:
    out = []
    for path in paths:
        info = path.stat()
        out.append((path.name, info.st_mtime_ns, info.st_size))
    return tuple(out)


def layout_at(sidestore_dir: Path, t: int) -> Layout:
    """The layout in force at run `t`, read once.

    The cache key is the name, mtime and size of each file the layout was read from. A run that adds or
    replaces one of the files reads the layout again. The runs that read the same files share one build.
    """
    paths, _, _ = _chain(sidestore_dir, t)
    stamp = _stamp(paths)
    key = (str(sidestore_dir), stamp)
    with _lock:
        cached = _AT.get(key)
        if cached is not None:
            _AT.move_to_end(key)
            return cached[1]
        built = Layout(_in_force(paths))
        _AT[key] = (stamp, built)
        _AT.move_to_end(key)
        while len(_AT) > CACHE_SIZE:
            _AT.popitem(last=False)
        return built


def rows_at(sidestore_dir: Path, t: int, *, removed: bool = False) -> dict[str, dict[str, Any]]:
    """The row in force at `t` per uid, the newest at or below `t` of the layout version in force at `t`.

    A re-plan writes every element under the next version. A checkpoint holds every row in force. The
    files older than a re-plan or a checkpoint are not read. An element whose newest row has
    `reason = removed` has left the layout and has no row, unless `removed`.
    """
    return layout_at(sidestore_dir, t).as_dicts(removed=removed)


def checkpoint_run(sidestore_dir: Path, t: int) -> int | None:
    """The run of the checkpoint the placement at `t` starts from, if there is one."""
    return _chain(sidestore_dir, t)[1]


def runs_in_force(sidestore_dir: Path, t: int) -> set[int]:
    """The incremental layout files that hold a row in force at `t` (with the `removed` rows that keep an
    older row from coming back). The rows a checkpoint holds are read from the checkpoint."""
    base = checkpoint_run(sidestore_dir, t)
    rows = layout_at(sidestore_dir, t).table["valid_from_ts"].to_pylist()
    return {int(v) for v in rows if base is None or v > base}


def delta_at(sidestore_dir: Path, t: int) -> list[dict[str, Any]]:
    """The rows with `valid_from_ts = t`."""
    if not store.table_path(sidestore_dir, TABLE, t).exists():
        return []
    return _rows(sidestore_dir, t)


def _block(rows: Mapping[str, Mapping[str, Any]], uid: str | None) -> str | None:
    row = rows.get(uid) if uid is not None else None
    for _ in range(4):
        if row is None or row["kind"] == "block":
            break
        row = rows.get(row["parent_uid"]) if row["parent_uid"] is not None else None
    return row["uid"] if row is not None and row["kind"] == "block" else None


def _cable_ports(rows: Mapping[str, Mapping[str, Any]], uid: str) -> tuple[str, ...]:
    parts = uid.split("~")
    for i in range(1, len(parts)):
        a, b = "~".join(parts[:i]), "~".join(parts[i:])
        if a in rows and b in rows:
            return a, b
    return ()


def in_tile(rows: Mapping[str, Mapping[str, Any]], row: Mapping[str, Any], tile: str) -> bool:
    """Whether a port or cable row belongs to block `tile`. A cable belongs to the blocks of both ports."""
    if row["kind"] == "port":
        return _block(rows, row["parent_uid"]) == tile
    if row["kind"] == "cable":
        return any(_block(rows, rows[p]["parent_uid"]) == tile for p in _cable_ports(rows, row["uid"]))
    return False


def select(
    rows: Mapping[str, Mapping[str, Any]], subset: Iterable[Mapping[str, Any]], tile: str | None
) -> list[Mapping[str, Any]]:
    """The rows of `subset` in block `tile`, or the base kinds when `tile` is None."""
    if tile is None:
        return [r for r in subset if r["kind"] in BASE_KINDS]
    return [r for r in subset if in_tile(rows, r, tile)]
