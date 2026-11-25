"""The DuckDB database a side-store reader opens (`sidestore.connect_reader`)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")
duckdb = pytest.importorskip("duckdb")

from hst.core import sidestore  # noqa: E402

BOUNDS_SQL = (
    "SELECT current_setting('memory_limit') AS memory, current_setting('threads') AS threads, "
    "current_setting('max_temp_directory_size') AS spill"
)
BOUNDS = {
    "memory": f"{sidestore.DUCKDB_MEMORY_LIMIT_MB:.1f} MiB",
    "threads": sidestore.DUCKDB_THREADS,
    "spill": f"{sidestore.DUCKDB_TEMP_LIMIT_MB / 1024:.1f} GiB",
}


def _rib_row(prefix: str) -> dict[str, object]:
    return {"device_uid": "dev:r1", "vrf": "default", "prefix": prefix, "protocol": "static", "metric": 1}


def _store(tmp_path: Path) -> Path:
    base = tmp_path / "sidestore"
    sidestore.write_table(base, "rib", "src", "h1", "1700000000000-aaaaaaaa", [_rib_row("10.0.0.0/8")], 7)
    return base


def test_a_query_runs_within_the_bounds(tmp_path):
    assert sidestore.query(_store(tmp_path), BOUNDS_SQL) == [BOUNDS]


def test_a_reader_prints_no_progress_bar(tmp_path):
    """DuckDB prints its progress bar to stdout for a query past two seconds."""
    sql = "SELECT current_setting('enable_progress_bar') AS bar"
    assert sidestore.query(_store(tmp_path), sql) == [{"bar": False}]


def test_a_query_over_no_store_runs_within_the_bounds(tmp_path):
    assert sidestore.query(tmp_path / "missing", BOUNDS_SQL) == [BOUNDS]


def test_a_query_past_both_limits_fails_with_out_of_memory(tmp_path, monkeypatch):
    """Past the memory limit a query spills, and past the spill limit it fails
    with DuckDB's out-of-memory error, which the caller sees as any failed
    query."""
    monkeypatch.setattr(sidestore, "DUCKDB_MEMORY_LIMIT_MB", 32)
    monkeypatch.setattr(sidestore, "DUCKDB_TEMP_LIMIT_MB", 8)
    heavy = (
        "SELECT count(*) AS n FROM (SELECT i % 800000 AS k, count(*), max(i::VARCHAR) "
        "FROM range(8000000) t(i) GROUP BY k)"
    )
    with pytest.raises(duckdb.OutOfMemoryException):
        sidestore.query(_store(tmp_path), heavy)


def test_a_query_while_another_reader_is_open_reads(tmp_path):
    base = _store(tmp_path)
    held = sidestore.connect_reader(base)
    try:
        held.execute(
            f"CREATE TEMP VIEW rib AS SELECT * FROM read_parquet('{base.as_posix()}/rib/**/*.parquet')"  # noqa: S608
        )
        assert sidestore.query(base, "SELECT prefix FROM rib") == [{"prefix": "10.0.0.0/8"}]
        assert sidestore.query(base, BOUNDS_SQL) == [BOUNDS]
        second = sidestore.connect_reader(base)
        try:
            assert second.execute(BOUNDS_SQL).fetchall() == [tuple(BOUNDS.values())]
        finally:
            second.close()
        assert held.execute("SELECT count(*) FROM rib").fetchone() == (1,)
    finally:
        held.close()


def test_readers_in_8_threads_at_once_all_read(tmp_path):
    base = _store(tmp_path)
    results: list[object] = []
    errors: list[BaseException] = []
    start = threading.Barrier(8)

    def read() -> None:
        start.wait()
        try:
            results.append(sidestore.query(base, "SELECT prefix FROM rib"))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert results == [[{"prefix": "10.0.0.0/8"}]] * 8


def test_a_shared_database_left_open_to_external_access_is_refused(tmp_path):
    base = _store(tmp_path)
    catalog = base / sidestore.QUERY_CATALOG
    duckdb.connect(str(catalog)).close()
    held = duckdb.connect(str(catalog), read_only=True)
    try:
        held.execute("SET lock_configuration=true")
        with pytest.raises(RuntimeError, match="external access on"):
            sidestore.connect_reader(base)
    finally:
        held.close()


def test_a_reader_reads_nothing_outside_the_store(tmp_path):
    base = _store(tmp_path)
    outside = sidestore.write_table(
        tmp_path / "elsewhere", "rib", "src", "h1", "run-x", [_rib_row("10.1.0.0/16")], 7
    )
    assert outside is not None
    con = sidestore.connect_reader(base)
    try:
        with pytest.raises(duckdb.Error):
            con.execute(f"SELECT * FROM read_parquet('{outside.as_posix()}')").fetchall()  # noqa: S608
        with pytest.raises(duckdb.Error):
            con.execute("SET enable_external_access=true")
    finally:
        con.close()
