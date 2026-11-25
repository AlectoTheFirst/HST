"""The RIB, BGP and OSPF readers (core/ribsource.py, bgpsource.py,
ospfsource.py) open their DuckDB connection as every side-store reader does
(`sidestore.connect_reader`): bounded in memory, threads and spill, locked to
the store, and able to open while another reader of the same process holds
the store's catalog open, in either order. A table directory with no parquet
file under it, which a write that failed before its first file leaves, is a
table with nothing to read, not an error."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pyarrow")
pytest.importorskip("duckdb")

from hst.core import sidestore
from hst.core.bgpsource import BgpSource
from hst.core.ospfsource import OspfSource
from hst.core.ribsource import RibSource

BOUNDS_SQL = (
    "SELECT current_setting('memory_limit'), current_setting('threads'), "
    "current_setting('max_temp_directory_size'), current_setting('enable_external_access')"
)
BOUNDS = (
    f"{sidestore.DUCKDB_MEMORY_LIMIT_MB:.1f} MiB",
    sidestore.DUCKDB_THREADS,
    f"{sidestore.DUCKDB_TEMP_LIMIT_MB / 1024:.1f} GiB",
    False,
)


def _store(tmp_path: Path) -> Path:
    base = tmp_path / "sidestore"
    row = {
        "device_uid": "dev:r1",
        "vrf": "default",
        "prefix": "10.0.0.0/8",
        "protocol": "static",
        "metric": 1,
    }
    sidestore.write_table(base, "rib", "src", "h1", "1700000000000-aaaaaaaa", [row], 7)
    (base / "ospf_lsdb").mkdir()
    return base


def _readers(base: Path) -> list[object]:
    return [RibSource(base), BgpSource(base), OspfSource(base)]


@pytest.mark.parametrize("first", ["another reader", "these readers"])
def test_each_reader_opens_within_the_bounds_beside_another(tmp_path: Path, first: str) -> None:
    base = _store(tmp_path)
    held = sidestore.connect_reader(base) if first == "another reader" else None
    readers = _readers(base)
    try:
        rib, bgp, ospf = (reader._connect() for reader in readers)  # type: ignore[attr-defined]
        # the OSPF table directory holds no file: nothing to read
        assert ospf is None
        for con in (rib, bgp):
            assert con is not None
            assert con.execute(BOUNDS_SQL).fetchone() == BOUNDS
        assert rib.execute("SELECT prefix FROM rib").fetchall() == [("10.0.0.0/8",)]
        after = sidestore.connect_reader(base)
        try:
            assert after.execute(BOUNDS_SQL).fetchone() == BOUNDS
        finally:
            after.close()
        assert sidestore.query(base, "SELECT prefix FROM rib") == [{"prefix": "10.0.0.0/8"}]
    finally:
        for reader in readers:
            reader.close()  # type: ignore[attr-defined]
        if held is not None:
            held.close()


def test_a_table_directory_without_a_file_is_nothing_to_read(tmp_path: Path) -> None:
    base = tmp_path / "sidestore"
    for table in ("rib", "ospf_lsdb", "bgp_sessions", "bgp_session_routes"):
        (base / table / "src" / "h1").mkdir(parents=True)
    rib, bgp, ospf = _readers(base)
    try:
        assert rib._connect() is None  # type: ignore[attr-defined]
        assert ospf._connect() is None  # type: ignore[attr-defined]
        assert bgp._connect() is not None  # type: ignore[attr-defined]
        assert bgp._views == set()  # type: ignore[attr-defined]
    finally:
        for reader in (rib, bgp, ospf):
            reader.close()  # type: ignore[attr-defined]


def test_a_route_table_read_in_batches_is_the_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "sidestore"
    rows = [
        {
            "device_uid": "dev:r1",
            "vrf": "default",
            "prefix": f"10.{i}.0.0/16",
            "protocol": "static",
            "metric": i,
            "next_hop": "192.0.2.1",
        }
        for i in range(7)
    ]
    sidestore.write_table(base, "rib", "src", "h1", "1700000000000-aaaaaaaa", rows, 7)

    def read() -> list[dict[str, object]]:
        reader = RibSource(base)
        try:
            return reader.routes("dev:r1", None, legacy_vrf="default")
        finally:
            reader.close()

    whole = read()
    monkeypatch.setattr("hst.core.ribsource.FETCH_ROWS", 2)
    assert len(whole) == 7
    assert read() == whole
