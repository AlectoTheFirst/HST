"""Side-store writes from any iterable of rows (core/sidestore.py `write_table`)."""

from __future__ import annotations

import gc
import tracemalloc
import weakref
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, overload

import pytest

pytest.importorskip("pyarrow")

import pyarrow as pa
import pyarrow.parquet as pq

from hst.core import manifest, sidestore

RUN_ID = "1790000000000-abcdef12"
SNAPSHOT_TS = 1_790_000_000_000
_V4_MAPPED = 0xFFFF << 32


def _row(i: int) -> dict[str, Any]:
    """One `rib` row with the LPM columns, unique per `i`. One row in 5 leaves
    `interface` out and one row in 7 holds None in `metric`."""
    base = (10 << 24) + (i << 8)
    row: dict[str, Any] = {
        "device_uid": "dev:r1",
        "vrf": "default",
        "context_uid": "vrf:dev:r1:default",
        "prefix": f"{base >> 24}.{(base >> 16) & 255}.{(base >> 8) & 255}.0/24",
        "next_hop": f"192.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
        "next_hop_context_uid": None,
        "interface": "Ethernet1/1",
        "protocol": "bgp",
        "discard": None,
        "metric": None if i % 7 == 3 else i % 1000,
        "af": 4,
        "prefixlen": 24,
        "lo": (_V4_MAPPED | base).to_bytes(16, "big"),
        "hi": (_V4_MAPPED | base | 0xFF).to_bytes(16, "big"),
    }
    if i % 5 == 2:
        del row["interface"]
    return row


def _rows(n: int) -> Iterator[dict[str, Any]]:
    for i in range(n):
        yield _row(i)


class _RowView(Sequence[dict[str, Any]]):
    """A minimal read-only view that builds each row only when it is read, the
    shape of a collector's lazy row view."""

    def __init__(self, n: int, make: Callable[[int], dict[str, Any]] = _row) -> None:
        self._n = n
        self._make = make

    def __len__(self) -> int:
        return self._n

    @overload
    def __getitem__(self, index: int) -> dict[str, Any]: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[dict[str, Any]]: ...

    def __getitem__(self, index: int | slice) -> dict[str, Any] | Sequence[dict[str, Any]]:
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self._n))]
        if not -self._n <= index < self._n:
            raise IndexError(index)
        return self._make(index % self._n)


def _reference_row_groups(
    rows: list[dict[str, Any]], schema: pa.Schema, run_id: str, snapshot_ts: int, size: int
) -> Iterator[pa.RecordBatch]:
    """The reference of `sidestore._row_groups`, over a list of rows."""
    for start in range(0, len(rows), size):
        stamped = [
            {**row, "run_id": run_id, "snapshot_ts": snapshot_ts} for row in rows[start : start + size]
        ]
        yield pa.RecordBatch.from_pylist(stamped, schema=schema)


def _reference_write(path: Path, rows: list[dict[str, Any]], size: int) -> Path:
    schema = sidestore.SCHEMAS["rib"]
    path.parent.mkdir(parents=True, exist_ok=True)
    sidestore._publish(path, schema, _reference_row_groups(rows, schema, RUN_ID, SNAPSHOT_TS, size))
    return path


def _write(base_dir: Path, host: str, rows: Iterable[dict[str, Any]], size: int) -> Path | None:
    return sidestore.write_table(
        base_dir, "rib", "nxos", host, RUN_ID, rows, SNAPSHOT_TS, row_group_rows=size
    )


def _group_rows(path: Path) -> list[int]:
    with pq.ParquetFile(path) as f:
        return [f.metadata.row_group(i).num_rows for i in range(f.num_row_groups)]


def _cases() -> list[tuple[int, int]]:
    cases = []
    for size in (1, 7, 1000):
        for n in sorted({0, 1, size - 1, size, size + 1, 3 * size + 5}):
            cases.append((size, n))
    return cases


@pytest.mark.parametrize(("size", "n"), _cases())
def test_a_list_a_generator_and_a_view_write_the_reference_file(tmp_path, size, n):
    store = tmp_path / "store"
    written = {
        "list": _write(store, "from-list", [_row(i) for i in range(n)], size),
        "generator": _write(store, "from-generator", _rows(n), size),
        "view": _write(store, "from-view", _RowView(n), size),
    }
    if n == 0:
        assert written == {"list": None, "generator": None, "view": None}
        assert not store.exists()
        return

    reference = _reference_write(tmp_path / "reference" / f"{RUN_ID}.parquet", list(_rows(n)), size)
    expected_rows = pq.read_table(reference).to_pylist()
    expected_facts = manifest.sidestore_row_facts(reference)
    expected_groups = _group_rows(reference)
    assert len(expected_rows) == n
    assert expected_facts[0] == n
    assert len(expected_groups) == -(-n // size)

    for kind, path in written.items():
        assert path is not None, kind
        assert path.name == f"{RUN_ID}.parquet", kind
        assert pq.read_table(path).to_pylist() == expected_rows, kind
        assert manifest.sidestore_row_facts(path) == expected_facts, kind
        assert _group_rows(path) == expected_groups, kind
        with pq.ParquetFile(path) as f:
            assert f.num_row_groups == -(-n // size), kind
        assert path.read_bytes() == reference.read_bytes(), kind


def test_an_empty_generator_writes_nothing_and_creates_no_directory(tmp_path):
    store = tmp_path / "store"
    assert _write(store, "r1", (r for r in ()), 7) is None
    assert _write(store, "r1", iter([]), 7) is None
    assert _write(store, "r1", _RowView(0), 7) is None
    assert not store.exists()


def test_an_unknown_table_with_rows_raises_value_error_and_creates_nothing(tmp_path):
    store = tmp_path / "store"
    with pytest.raises(ValueError, match="unknown side-store table"):
        sidestore.write_table(store, "not-a-table", "nxos", "r1", RUN_ID, _rows(3), SNAPSHOT_TS)
    assert not store.exists()


def test_an_unknown_table_with_no_rows_returns_none(tmp_path):
    store = tmp_path / "store"
    assert sidestore.write_table(store, "not-a-table", "nxos", "r1", RUN_ID, _rows(0), SNAPSHOT_TS) is None
    assert sidestore.write_table(store, "not-a-table", "nxos", "r1", RUN_ID, [], SNAPSHOT_TS) is None
    assert not store.exists()


class _RowMappingFailed(Exception):
    pass


def _rows_then_fail(n: int) -> Iterator[dict[str, Any]]:
    yield from _rows(n)
    raise _RowMappingFailed(f"row {n} could not be mapped")


@pytest.mark.parametrize(
    "fail_after",
    [
        0,  # before the first row: nothing is created
        3,  # inside the first row group, still before the directory exists
        7,  # right after the first row group, while the file is being written
        20,  # inside the third row group
    ],
)
def test_an_error_while_reading_rows_propagates_and_leaves_no_file(tmp_path, fail_after):
    store = tmp_path / "store"
    with pytest.raises(_RowMappingFailed):
        _write(store, "r1", _rows_then_fail(fail_after), 7)
    leftovers = sorted(p.name for p in store.rglob("*") if p.is_file()) if store.exists() else []
    assert leftovers == []


class _TrackedRow(dict[str, Any]):
    """A row that can be weakly referenced, to see when the writer lets go of it."""


def test_no_chunk_of_rows_outlives_its_record_batch(tmp_path, monkeypatch):
    """By the time a row group's batch reaches the parquet writer, nothing in
    the write still holds that group's source rows or any earlier group's:
    not `write_table`'s first chunk, not `_row_groups`' chunk."""
    refs: list[weakref.ref[_TrackedRow]] = []

    def tracked(i: int) -> _TrackedRow:
        row = _TrackedRow(_row(i))
        refs.append(weakref.ref(row))
        return row

    alive_at_each_batch: list[int] = []
    publish = sidestore._publish

    def watching_publish(path: Path, schema: pa.Schema, batches: Iterable[pa.RecordBatch]) -> None:
        def watched() -> Iterator[pa.RecordBatch]:
            for batch in batches:
                gc.collect()
                alive_at_each_batch.append(sum(ref() is not None for ref in refs))
                yield batch

        publish(path, schema, watched())

    monkeypatch.setattr(sidestore, "_publish", watching_publish)
    # map() keeps no reference to a row it has produced.
    path = _write(tmp_path, "r1", map(tracked, range(20)), 7)

    assert path is not None and sum(_group_rows(path)) == 20
    assert len(refs) == 20
    assert alive_at_each_batch == [0, 0, 0]


def _traced_peak(fn: Callable[[], object]) -> int:
    """Bytes traced at the peak of `fn()` above what was traced before it."""
    gc.collect()
    started = not tracemalloc.is_tracing()
    if started:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        fn()
        return tracemalloc.get_traced_memory()[1] - before
    finally:
        if started:
            tracemalloc.stop()


def _stamped_group_bytes(size: int) -> int:
    """Traced bytes one row group of stamped rows holds once built."""
    gc.collect()
    started = not tracemalloc.is_tracing()
    if started:
        tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        group = [{**row, "run_id": RUN_ID, "snapshot_ts": SNAPSHOT_TS} for row in _rows(size)]
        held = tracemalloc.get_traced_memory()[0] - before
    finally:
        if started:
            tracemalloc.stop()
    assert len(group) == size
    return held


def test_a_generator_write_holds_about_one_row_group_of_rows(tmp_path):
    """The traced peak of a generator write stays within 2.5 row groups of stamped rows."""
    size, n = 65_536, 300_000
    group = _stamped_group_bytes(size)

    generator_peak = _traced_peak(lambda: _write(tmp_path, "from-generator", _rows(n), size))

    def from_list() -> None:
        rows = list(_rows(n))
        _write(tmp_path, "from-list", rows, size)

    list_peak = _traced_peak(from_list)

    for host in ("from-generator", "from-list"):
        assert sum(_group_rows(tmp_path / "rib" / "nxos" / host / f"{RUN_ID}.parquet")) == n
    assert generator_peak <= 2.5 * group, (generator_peak, group)
    assert generator_peak < 0.4 * list_peak, (generator_peak, list_peak)
