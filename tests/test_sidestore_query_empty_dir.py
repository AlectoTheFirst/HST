"""A side-store table directory with no parquet file under it does not fail
every query (core/sidestore.py `query`)."""

from __future__ import annotations

import pytest

from hst.core import sidestore

pytest.importorskip("pyarrow")
duckdb = pytest.importorskip("duckdb")

SNAPSHOT = 1_700_000_000_000
RUN_ID = "1700000000000-aaaaaaaa"
RIB = [
    {"device_uid": "dev:r1", "vrf": "default", "prefix": "10.0.0.0/24", "protocol": "static", "metric": 1},
    {"device_uid": "dev:r1", "vrf": "default", "prefix": "10.0.1.0/24", "protocol": "static", "metric": 1},
]


def _store(tmp_path):
    base = tmp_path / "sidestore"
    written = sidestore.write_table(base, "rib", "edge", "r1", RUN_ID, RIB, SNAPSHOT)
    assert written is not None
    return base


def test_an_empty_table_directory_beside_a_real_table_leaves_the_real_table_queryable(tmp_path):
    base = _store(tmp_path)
    # what a failed first write of the table leaves: the nested directories
    # write_table creates, and no file
    (base / "arp" / "edge" / "r1").mkdir(parents=True)
    (base / "mac").mkdir()

    assert sidestore.query(base, "SELECT count(*) AS n FROM rib") == [{"n": 2}]
    assert sidestore.query(base, "SELECT 1 AS one") == [{"one": 1}]
    rows = sidestore.query(base, "SELECT prefix FROM rib ORDER BY prefix")
    assert [r["prefix"] for r in rows] == ["10.0.0.0/24", "10.0.1.0/24"]


def test_a_query_naming_the_empty_table_reads_as_one_naming_a_table_never_written(tmp_path):
    empty = _store(tmp_path / "empty")
    (empty / "arp" / "edge" / "r1").mkdir(parents=True)
    never = _store(tmp_path / "never")

    with pytest.raises(duckdb.CatalogException) as with_dir:
        sidestore.query(empty, "SELECT count(*) FROM arp")
    with pytest.raises(duckdb.CatalogException) as without_dir:
        sidestore.query(never, "SELECT count(*) FROM arp")

    assert "arp" in str(with_dir.value)
    assert str(with_dir.value) == str(without_dir.value)


def test_a_temporary_file_alone_does_not_register_the_table(tmp_path):
    """A crash between a write and its rename leaves `<run_id>.parquet.tmp`,
    which no reader matches, so the table still has no file to read."""
    base = _store(tmp_path)
    host = base / "arp" / "edge" / "r1"
    host.mkdir(parents=True)
    (host / f"{RUN_ID}.parquet.tmp").write_bytes(b"not parquet")

    assert sidestore.query(base, "SELECT count(*) AS n FROM rib") == [{"n": 2}]
    with pytest.raises(duckdb.CatalogException):
        sidestore.query(base, "SELECT count(*) FROM arp")


def test_the_table_is_queryable_once_a_file_lands_in_it(tmp_path):
    base = _store(tmp_path)
    (base / "arp" / "edge" / "r1").mkdir(parents=True)
    arp = [{"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.1", "mac": "00:00:5e:00:53:01", "af": 4}]
    assert sidestore.write_table(base, "arp", "edge", "r1", RUN_ID, arp, SNAPSHOT) is not None

    assert sidestore.query(base, "SELECT count(*) AS n FROM arp") == [{"n": 1}]


def test_a_store_without_empty_directories_answers_and_stays_read_only(tmp_path):
    base = _store(tmp_path)

    assert sidestore.query(base, "SELECT count(*) AS n FROM rib") == [{"n": 2}]
    assert sidestore.query(base, "EXPLAIN SELECT count(*) FROM rib")
    with pytest.raises(ValueError, match="read-only"):
        sidestore.query(base, "CREATE TABLE pwn AS SELECT 1")
    with pytest.raises(ValueError, match="read-only"):
        sidestore.query(base, f"COPY (SELECT 1) TO '{base}/out.csv'")
    with pytest.raises(duckdb.Error):
        sidestore.query(base, "SELECT * FROM read_csv('/etc/hosts')")


def test_the_read_only_layers_hold_on_a_store_with_an_empty_directory(tmp_path):
    base = _store(tmp_path)
    (base / "arp").mkdir()

    with pytest.raises(ValueError, match="read-only"):
        sidestore.query(base, f"ATTACH '{base}/other.db'")
    with pytest.raises(duckdb.Error):
        sidestore.query(base, "SELECT * FROM read_csv('/etc/hosts')")
    with pytest.raises(ValueError, match="read-only"):
        sidestore.query(base, "SET enable_external_access=true")


def test_a_statement_registers_only_the_tables_it_names(tmp_path):
    """A view reads the footer of every file under it, so a statement about `arp` must not
    build one over every file of `rib`. A `rib` file that cannot be read fails any statement that
    registers the table, and one that never names it is not touched."""
    base = _store(tmp_path)
    broken = base / "rib" / "edge" / "r2"
    broken.mkdir(parents=True)
    (broken / f"{RUN_ID}.parquet").write_bytes(b"not parquet")
    arp = [{"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.1", "mac": "00:00:5e:00:53:01", "af": 4}]
    assert sidestore.write_table(base, "arp", "edge", "r1", RUN_ID, arp, SNAPSHOT) is not None

    assert sidestore.query(base, "SELECT count(*) AS n FROM arp") == [{"n": 1}]
    assert sidestore.query(base, "SELECT count(*) AS n FROM arp", tables=["arp"]) == [{"n": 1}]
    with pytest.raises(duckdb.Error):
        sidestore.query(base, "SELECT count(*) AS n FROM rib")


def test_the_hst_tiers_and_the_spill_directories_are_never_registered(tmp_path):
    """The tiers the map writes under `hst/` are no side-store table, whatever name a
    statement uses."""
    base = _store(tmp_path)
    tier = base / "hst" / "render_t1"
    tier.mkdir(parents=True)
    (tier / "part.parquet").write_bytes(b"not parquet")

    assert sidestore.query(base, "SELECT count(*) AS n FROM rib") == [{"n": 2}]
    with pytest.raises(duckdb.CatalogException):
        sidestore.query(base, "SELECT count(*) FROM hst")
    (base / "arp").mkdir()
    (base / "mac").mkdir()
    named = sidestore._named_tables(
        base, "select * from RIB r join arp on 1 = 1 where x = 'mac_x' and y = 'hst'"
    )
    assert named == ["arp", "rib"]
    assert sidestore._named_tables(base, "SELECT 1") == []
