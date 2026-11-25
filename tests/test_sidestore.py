"""Parquet side store: high-churn tables keyed to graph uids."""

import os
import stat
import sys

import pytest

pytest.importorskip("pyarrow")
# test_query_missing_duckdb_hints_install runs with duckdb absent.

from hst.app.crypto import generate_key
from hst.core import Settings, ipenc, sidestore


def test_write_and_query_roundtrip(tmp_path):
    pytest.importorskip("duckdb")
    rows = [
        {
            "device_uid": "dev:abc",
            "vrf": "default",
            "prefix": "10.0.0.0/24",
            "next_hop": "10.9.0.1",
            "protocol": "static",
            "metric": 1,
        }
    ]
    p = sidestore.write_table(tmp_path, "rib", "nxos", "", "run-1", rows, 1000)
    assert p is not None and p.suffix == ".parquet"
    out = sidestore.query(tmp_path, "SELECT device_uid, prefix, run_id FROM rib")
    assert out == [{"device_uid": "dev:abc", "prefix": "10.0.0.0/24", "run_id": "run-1"}]


def test_bgp_session_routes_roundtrip(tmp_path):
    """The BGP path observations: two peers supplying one prefix are
    two rows."""
    pytest.importorskip("duckdb")
    lo, hi, prefixlen, af = ipenc.prefix_bounds("10.20.0.0/24")
    common = {
        "device_uid": "dev:abc",
        "context_uid": "vrf:dev:abc:CUST-A",
        "af": af,
        "safi": "unicast",
        "direction": "accepted",
        "rib_type": "loc-rib",
        "policy_stage": "post-import",
        "path_id": "0",
        "prefix": "10.20.0.0/24",
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
        "next_hop_context_uid": None,
        "origin": "i",
        "communities": "65001:100",
    }
    rows = [
        {
            **common,
            "session_uid": "bgp:rproc:dev:abc:cust-a:bgp~10.1.1.2:CUST-A",
            "peer_ip": "10.1.1.2",
            "next_hop": "10.1.1.2",
            "as_path": "",
            "local_pref": 150,
            "med": 0,
            "best": True,
        },
        {
            **common,
            "session_uid": "bgp:rproc:dev:abc:cust-a:bgp~192.0.2.2:CUST-A",
            "peer_ip": "192.0.2.2",
            "next_hop": "192.0.2.2",
            "as_path": "65099",
            "local_pref": 100,
            "med": 50,
            "best": False,
        },
    ]
    path = sidestore.write_table(tmp_path, "bgp_session_routes", "nxos1", "n9k1", "run-1", rows, 1000)
    assert path is not None
    out = sidestore.query(
        tmp_path,
        "SELECT peer_ip, direction, rib_type, policy_stage, local_pref, med, best, prefixlen, run_id "
        "FROM bgp_session_routes ORDER BY peer_ip",
    )
    assert out == [
        {
            "peer_ip": "10.1.1.2",
            "direction": "accepted",
            "rib_type": "loc-rib",
            "policy_stage": "post-import",
            "local_pref": 150,
            "med": 0,
            "best": True,
            "prefixlen": 24,
            "run_id": "run-1",
        },
        {
            "peer_ip": "192.0.2.2",
            "direction": "accepted",
            "rib_type": "loc-rib",
            "policy_stage": "post-import",
            "local_pref": 100,
            "med": 50,
            "best": False,
            "prefixlen": 24,
            "run_id": "run-1",
        },
    ]


def test_bgp_sessions_roundtrip(tmp_path):
    """Observed session state: a session reported down is a row."""
    pytest.importorskip("duckdb")
    rows = [
        {
            "device_uid": "dev:abc",
            "context_uid": "vrf:dev:abc:CUST-A",
            "session_uid": "bgp:rproc:dev:abc:cust-a:bgp~192.0.2.9:CUST-A",
            "peer_ip": "192.0.2.9",
            "af": 4,
            "safi": "unicast",
            "state": "Idle",
            "established_since_ms": None,
            "prefixes_received": None,
            "prefixes_advertised": None,
            "capabilities": None,
        }
    ]
    path = sidestore.write_table(tmp_path, "bgp_sessions", "nxos1", "n9k1", "run-1", rows, 1000)
    assert path is not None
    out = sidestore.query(
        tmp_path,
        "SELECT session_uid, state, established_since_ms, capabilities, snapshot_ts FROM bgp_sessions",
    )
    assert out == [
        {
            "session_uid": "bgp:rproc:dev:abc:cust-a:bgp~192.0.2.9:CUST-A",
            "state": "Idle",
            "established_since_ms": None,
            "capabilities": None,
            "snapshot_ts": 1000,
        }
    ]


def test_every_table_declares_a_schema_version():
    """The manifest records a side-store file's schema version from this map
    (core/manifest.py `file_entry`)."""
    assert set(sidestore.SCHEMA_VERSIONS) == set(sidestore.SCHEMAS)


def test_write_table_nests_under_source_and_host(tmp_path):
    """Files land at <table>/<source>/<host>/<run_id>.parquet."""
    pytest.importorskip("duckdb")
    row = {
        "device_uid": "dev:abc",
        "vrf": "default",
        "prefix": "10.0.0.0/24",
        "next_hop": "10.9.0.1",
        "protocol": "static",
        "metric": 1,
    }
    with_host = sidestore.write_table(tmp_path, "rib", "nxos1", "10.0.0.5", "run-1", [row], 1000)
    no_host = sidestore.write_table(tmp_path, "rib", "apic1", "", "run-2", [row], 1000)
    assert with_host == tmp_path / "rib" / "nxos1" / "10.0.0.5" / "run-1.parquet"
    assert no_host == tmp_path / "rib" / "apic1" / "run-2.parquet"


def test_empty_rows_write_nothing(tmp_path):
    assert sidestore.write_table(tmp_path, "mac", "nxos", "", "run-1", [], 1000) is None
    assert not (tmp_path / "mac").exists()


def test_query_missing_duckdb_hints_install(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "duckdb", None)
    with pytest.raises(RuntimeError, match="sidestore"):
        sidestore.query(tmp_path, "SELECT 1")


def test_cli_missing_duckdb_hint_keeps_sidestore_bracket(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    import hst.cli as cli
    from hst.core import Settings

    monkeypatch.setitem(sys.modules, "duckdb", None)
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None, hst_data_dir=tmp_path))
    runner = CliRunner()
    r = runner.invoke(cli.app, ["sidestore", "query", "SELECT 1"])
    assert r.exit_code == 2, r.output
    assert "[sidestore]" in r.output


def test_cli_query_bad_sql_prints_red_message_and_exits_1(monkeypatch, tmp_path):
    pytest.importorskip("duckdb")
    from typer.testing import CliRunner

    import hst.cli as cli
    from hst.core import Settings

    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None, hst_data_dir=tmp_path))
    runner = CliRunner()
    r = runner.invoke(cli.app, ["sidestore", "query", "SELECT * FROM nope"])
    assert r.exit_code == 1, r.output
    assert "nope" in r.output


def test_query_spans_files_where_one_files_metric_column_is_all_none(tmp_path):
    """The per-table pyarrow schemas fix the type of an all-None `metric` column."""
    pytest.importorskip("duckdb")
    all_none_rows = [
        {
            "device_uid": "dev:a",
            "vrf": "default",
            "prefix": "10.0.0.0/24",
            "next_hop": None,
            "protocol": "connected",
            "metric": None,
        }
    ]
    real_rows = [
        {
            "device_uid": "dev:b",
            "vrf": "default",
            "prefix": "10.1.0.0/24",
            "next_hop": "10.1.0.1",
            "protocol": "static",
            "metric": 1,
        }
    ]
    sidestore.write_table(tmp_path, "rib", "iosxe", "", "run-1", all_none_rows, 1000)
    sidestore.write_table(tmp_path, "rib", "nxos", "", "run-2", real_rows, 2000)
    out = sidestore.query(tmp_path, "SELECT device_uid, metric FROM rib ORDER BY device_uid")
    assert out == [{"device_uid": "dev:a", "metric": None}, {"device_uid": "dev:b", "metric": 1}]


def test_query_connection_is_read_only(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    rows = [
        {
            "device_uid": "dev:abc",
            "vrf": "default",
            "prefix": "10.0.0.0/24",
            "next_hop": None,
            "protocol": "static",
            "metric": 1,
        }
    ]
    sidestore.write_table(tmp_path, "rib", "nxos", "", "run-1", rows, 1000)
    with pytest.raises(ValueError, match="read-only"):
        sidestore.query(tmp_path, "CREATE TABLE pwn AS SELECT 1")
    # statements the read_only catalog alone does not stop
    with pytest.raises(ValueError, match="refusing COPY"):
        sidestore.query(tmp_path, f"COPY (SELECT 1) TO '{tmp_path}/out.csv'")
    with pytest.raises(ValueError, match="refusing ATTACH"):
        sidestore.query(tmp_path, f"ATTACH '{tmp_path}/other.db'")
    # a SELECT that reaches outside the store is stopped by duckdb itself
    with pytest.raises(duckdb.Error):
        sidestore.query(tmp_path, "SELECT * FROM read_csv('/etc/hosts')")
    out = sidestore.query(tmp_path, "SELECT count(*) AS n FROM rib")
    assert out == [{"n": 1}]
    assert sidestore.query(tmp_path, "EXPLAIN SELECT count(*) FROM rib")


def test_query_empty_store_still_locks_file_access(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    with pytest.raises(duckdb.Error):
        sidestore.query(tmp_path / "absent", "SELECT * FROM read_csv('/etc/hosts')")


def test_write_table_unknown_table_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="unknown side-store table"):
        sidestore.write_table(tmp_path, "not-a-table", "nxos", "", "run-1", [{"x": 1}], 1000)


def test_query_unions_old_and_new_rib_schema_by_name(tmp_path):
    """An old rib file's row reads the LPM, `discard` and `next_hop_context_uid` columns back as NULL."""
    pyarrow = pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    import pyarrow.parquet as pq

    old_schema = pyarrow.schema(
        [
            pyarrow.field("device_uid", pyarrow.string()),
            pyarrow.field("vrf", pyarrow.string()),
            pyarrow.field("prefix", pyarrow.string()),
            pyarrow.field("next_hop", pyarrow.string()),
            pyarrow.field("protocol", pyarrow.string()),
            pyarrow.field("metric", pyarrow.int64()),
        ]
    )
    old_row = {
        "device_uid": "dev:old",
        "vrf": "default",
        "prefix": "10.0.0.0/24",
        "next_hop": "10.0.0.1",
        "protocol": "static",
        "metric": 1,
    }
    rib_dir = tmp_path / "rib"
    rib_dir.mkdir(parents=True)
    pq.write_table(pyarrow.Table.from_pylist([old_row], schema=old_schema), rib_dir / "old-run-1.parquet")

    new_row = {
        "device_uid": "dev:new",
        "vrf": "default",
        "prefix": "10.1.0.0/24",
        "next_hop": "10.1.0.1",
        "next_hop_context_uid": "vrf:dev:new:RED",
        "protocol": "bgp",
        "discard": None,
        "metric": 20,
        "af": 4,
        "prefixlen": 24,
        "lo": None,
        "hi": None,
    }
    sidestore.write_table(tmp_path, "rib", "new", "", "run-2", [new_row], 2000)

    out = sidestore.query(tmp_path, "SELECT count(*) AS n FROM rib")
    assert out == [{"n": 2}]

    by_device = {
        r["device_uid"]: r
        for r in sidestore.query(tmp_path, "SELECT device_uid, discard, next_hop_context_uid FROM rib")
    }
    assert by_device["dev:old"] == {
        "device_uid": "dev:old",
        "discard": None,
        "next_hop_context_uid": None,
    }
    assert by_device["dev:new"] == {
        "device_uid": "dev:new",
        "discard": None,
        "next_hop_context_uid": "vrf:dev:new:RED",
    }


def test_write_table_rib_row_missing_context_uid_reads_back_as_none(tmp_path):
    """`context_uid` is optional like every other rib column."""
    pytest.importorskip("duckdb")
    rows = [
        {
            "device_uid": "dev:a",
            "vrf": "default",
            "context_uid": "fc:dev:a:default",
            "prefix": "10.0.0.0/24",
            "next_hop": None,
            "protocol": "static",
            "metric": 1,
        },
        {
            "device_uid": "dev:b",
            "vrf": "default",
            "prefix": "10.1.0.0/24",
            "next_hop": None,
            "protocol": "static",
            "metric": 1,
        },
    ]
    sidestore.write_table(tmp_path, "rib", "nxos", "", "run-1", rows, 1000)
    out = sidestore.query(tmp_path, "SELECT device_uid, context_uid FROM rib ORDER BY device_uid")
    assert out == [
        {"device_uid": "dev:a", "context_uid": "fc:dev:a:default"},
        {"device_uid": "dev:b", "context_uid": None},
    ]


def test_query_unions_old_and_new_arp_schema_by_name(tmp_path):
    """An old arp file's row reads `context_uid` and `af` back as NULL."""
    pyarrow = pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    import pyarrow.parquet as pq

    old_schema = pyarrow.schema(
        [
            pyarrow.field("device_uid", pyarrow.string()),
            pyarrow.field("vrf", pyarrow.string()),
            pyarrow.field("ip", pyarrow.string()),
            pyarrow.field("mac", pyarrow.string()),
            pyarrow.field("interface_name", pyarrow.string()),
        ]
    )
    old_row = {
        "device_uid": "dev:old",
        "vrf": "default",
        "ip": "10.0.0.5",
        "mac": "aabbccddeeff",
        "interface_name": "e1",
    }
    arp_dir = tmp_path / "arp"
    arp_dir.mkdir(parents=True)
    pq.write_table(pyarrow.Table.from_pylist([old_row], schema=old_schema), arp_dir / "old-run-1.parquet")

    new_row = {
        "device_uid": "dev:new",
        "vrf": "default",
        "context_uid": "fc:dev:new:default",
        "ip": "10.1.0.5",
        "mac": "aabbccddee00",
        "interface_name": "e2",
        "af": 4,
    }
    sidestore.write_table(tmp_path, "arp", "new", "", "run-2", [new_row], 2000)

    out = sidestore.query(tmp_path, "SELECT count(*) AS n FROM arp")
    assert out == [{"n": 2}]

    by_device = {
        r["device_uid"]: r for r in sidestore.query(tmp_path, "SELECT device_uid, context_uid, af FROM arp")
    }
    assert by_device["dev:old"] == {"device_uid": "dev:old", "context_uid": None, "af": None}
    assert by_device["dev:new"] == {"device_uid": "dev:new", "context_uid": "fc:dev:new:default", "af": 4}


def test_query_unions_old_and_new_mac_schema_by_name(tmp_path):
    """An old mac file's row reads `bridge_domain_uid` back as NULL."""
    pyarrow = pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    import pyarrow.parquet as pq

    old_schema = pyarrow.schema(
        [
            pyarrow.field("device_uid", pyarrow.string()),
            pyarrow.field("vlan", pyarrow.int64()),
            pyarrow.field("mac", pyarrow.string()),
            pyarrow.field("port_name", pyarrow.string()),
        ]
    )
    old_row = {"device_uid": "dev:old", "vlan": 10, "mac": "aabbccddeeff", "port_name": "e1"}
    mac_dir = tmp_path / "mac"
    mac_dir.mkdir(parents=True)
    pq.write_table(pyarrow.Table.from_pylist([old_row], schema=old_schema), mac_dir / "old-run-1.parquet")

    new_row = {
        "device_uid": "dev:new",
        "vlan": 10,
        "mac": "aabbccddee00",
        "port_name": "e2",
        "bridge_domain_uid": "bd:vlan:fab0:10",
    }
    sidestore.write_table(tmp_path, "mac", "new", "", "run-2", [new_row], 2000)

    out = sidestore.query(tmp_path, "SELECT count(*) AS n FROM mac")
    assert out == [{"n": 2}]

    by_device = {
        r["device_uid"]: r for r in sidestore.query(tmp_path, "SELECT device_uid, bridge_domain_uid FROM mac")
    }
    assert by_device["dev:old"] == {"device_uid": "dev:old", "bridge_domain_uid": None}
    assert by_device["dev:new"] == {"device_uid": "dev:new", "bridge_domain_uid": "bd:vlan:fab0:10"}


def test_query_spans_runs(tmp_path):
    pytest.importorskip("duckdb")
    for run in ("run-1", "run-2"):
        sidestore.write_table(
            tmp_path,
            "arp",
            "nxos",
            "",
            run,
            [
                {
                    "device_uid": "dev:abc",
                    "vrf": "default",
                    "ip": "10.0.0.5",
                    "mac": "aa",
                    "interface_name": "e1",
                }
            ],
            1000,
        )
    out = sidestore.query(tmp_path, "SELECT count(*) AS n FROM arp")
    assert out == [{"n": 2}]


def test_a_table_is_written_in_row_groups_and_reads_back_whole(tmp_path):
    """`sidestore_row_group_rows` bounds what a write holds."""
    pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    rows = [_rib_row(f"10.{i // 256}.{i % 256}.0/24") for i in range(500)]
    split = sidestore.write_table(tmp_path, "rib", "nxos", "r1", "run-1", rows, 1000, row_group_rows=100)
    whole = sidestore.write_table(tmp_path, "rib", "nxos", "r2", "run-1", rows, 1000, row_group_rows=5000)

    assert pq.ParquetFile(split).num_row_groups == 5
    assert pq.ParquetFile(whole).num_row_groups == 1
    read = pq.read_table(split).to_pylist()
    assert [r["prefix"] for r in read] == [r["prefix"] for r in rows]
    assert {r["run_id"] for r in read} == {"run-1"}
    assert {r["snapshot_ts"] for r in read} == {1000}
    assert read == pq.read_table(whole).to_pylist()


def test_execute_writes_side_tables_after_load(tmp_path, monkeypatch):
    pytest.importorskip("duckdb")
    from hst import collectors as coll
    from hst.collectors.base import Collector, SourceConfig
    from hst.collectors.util import GraphBuilder
    from hst.core import Settings

    class FakeSession:  # SessionLike stub
        pass

    class SideCfg(SourceConfig):
        pass

    class SideCollector(Collector):
        name = "sidefake"
        ConfigModel = SideCfg

        def __init__(self, config, settings):
            super().__init__(config, settings)
            self.scope = "sidefake:test"

        def probe(self):
            return "ok"

        def fetch(self):
            return {"x": 1}

        def normalize(self, raw):
            b = GraphBuilder()
            b.node("Device", "dev:sidefake", hostname="h", role="router")
            return b.batch("sidefake", self.scope)

        def side_tables(self, raw):
            assert raw == {"x": 1}
            return {
                "rib": [
                    {
                        "device_uid": "dev:sidefake",
                        "vrf": "d",
                        "prefix": "10.0.0.0/24",
                        "next_hop": None,
                        "protocol": "local",
                        "metric": 0,
                    }
                ],
                "mac": [],
            }

    import hst.collectors.base as base_mod

    monkeypatch.setattr(
        base_mod,
        "load",
        lambda *a, **k: __import__("hst.core.model", fromlist=["RunManifest"]).RunManifest(
            run_id="r", source="sidefake", scope="sidefake:test"
        ),
    )
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    coll.execute(SideCollector(SideCfg(), settings), FakeSession())
    out = sidestore.query(settings.sidestore_dir, "SELECT device_uid FROM rib")
    assert out == [{"device_uid": "dev:sidefake"}]
    assert not (settings.sidestore_dir / "mac").exists()


# --- per-table outcomes -------------------------------------------------------
#
# A run records an outcome for every table its collector declares.


class _FakeSession:  # SessionLike stub
    pass


def _side_collector(declared, produced, stated=None):
    """A collector declaring `declared` side tables, producing `produced`, and
    stating `stated` about what it did not read (`Collector.table_outcomes`)."""
    from hst.collectors.base import Collector, SourceConfig
    from hst.collectors.util import GraphBuilder

    class SideCfg(SourceConfig):
        host: str = "h"

    class SideCollector(Collector):
        name = "sidefake2"
        ConfigModel = SideCfg
        SIDE_TABLES = declared

        def __init__(self, config, settings):
            super().__init__(config, settings)
            self.scope = "sidefake2:test"

        def probe(self):
            return "ok"

        def fetch(self):
            return {"x": 1}

        def normalize(self, raw):
            b = GraphBuilder()
            b.node("Device", "dev:sidefake2", hostname="h", role="router")
            return b.batch("sidefake2", self.scope)

        def side_tables(self, raw):
            return {name: list(rows) for name, rows in produced.items()}

        def table_outcomes(self, raw):
            return dict(stated or {})

    return SideCollector, SideCfg


def _rib_row(prefix):
    return {
        "device_uid": "dev:sidefake2",
        "vrf": "d",
        "prefix": prefix,
        "next_hop": None,
        "protocol": "local",
        "metric": 0,
    }


def _stub_load(monkeypatch):
    import hst.collectors.base as base_mod
    from hst.core.model import RunManifest

    monkeypatch.setattr(
        base_mod,
        "load",
        lambda *a, **k: RunManifest(run_id="r", source="sidefake2", scope="sidefake2:test"),
    )


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def test_execute_survives_a_sidestore_write_failure(tmp_path, monkeypatch, caplog):
    """A side-store write failure does not fail a successful load."""
    from hst import collectors as coll
    from hst.app import runs_exec

    SideCollector, SideCfg = _side_collector(("rib",), {"rib": [_rib_row("10.0.0.0/24")]})

    def _boom(*a, **k):
        raise PermissionError("read-only filesystem")

    _stub_load(monkeypatch)
    monkeypatch.setattr(sidestore, "write_table", _boom)
    settings = _settings(tmp_path)
    manifest = coll.execute(SideCollector(SideCfg(), settings), _FakeSession())

    assert manifest.run_id == "r"
    assert "[sidestore] skipped" in caplog.text
    assert "read-only filesystem" in caplog.text
    rib = manifest.tables["rib"]
    assert rib.status == "failed"
    assert rib.row_count == 1 and rib.path == ""
    assert "read-only filesystem" in rib.detail

    outcome = runs_exec.DeviceOutcome("edge", "h", True, full=True, tables=manifest.tables)
    assert outcome.completeness == "partial"
    assert runs_exec._device_outcome(outcome, "partial") == "partial"


def test_a_declared_table_with_no_rows_records_complete_empty_and_writes_no_file(tmp_path, monkeypatch):
    """`write_table` creates nothing for zero rows."""
    from hst import collectors as coll
    from hst.app import runs_exec

    SideCollector, SideCfg = _side_collector(("rib", "arp"), {"rib": [], "arp": []})
    _stub_load(monkeypatch)
    settings = _settings(tmp_path)
    manifest = coll.execute(SideCollector(SideCfg(), settings), _FakeSession())

    assert {n: o.status for n, o in manifest.tables.items()} == {
        "rib": "complete-empty",
        "arp": "complete-empty",
    }
    assert all(o.row_count == 0 and o.path == "" for o in manifest.tables.values())
    assert not settings.sidestore_dir.exists()

    outcome = runs_exec.DeviceOutcome("edge", "h", True, full=True, tables=manifest.tables)
    assert outcome.completeness == "ok"
    assert runs_exec._device_outcome(outcome, "fresh") == "collected"


def test_a_declared_table_that_was_written_records_complete_with_its_rows_and_file(tmp_path, monkeypatch):
    """A table that landed names its row count and the file that holds them."""
    from hst import collectors as coll

    SideCollector, SideCfg = _side_collector(
        ("rib", "mac"), {"rib": [_rib_row("10.0.0.0/24"), _rib_row("10.0.1.0/24")], "mac": []}
    )
    _stub_load(monkeypatch)
    settings = _settings(tmp_path)
    manifest = coll.execute(SideCollector(SideCfg(), settings), _FakeSession())

    rib = manifest.tables["rib"]
    assert (rib.status, rib.row_count, rib.detail) == ("complete", 2, "")
    written = tmp_path / rib.path
    assert written.is_file() and written.suffix == ".parquet"
    assert rib.path.startswith("sidestore/rib/sidefake2/h/")
    assert manifest.tables["mac"].status == "complete-empty"


def test_a_table_the_run_captured_none_of_records_not_captured(tmp_path, monkeypatch):
    """A table a run asked the device for none of is `not-captured`."""
    from hst import collectors as coll
    from hst.app import runs_exec
    from hst.core.model import TableOutcome

    SideCollector, SideCfg = _side_collector(
        ("rib", "bgp_session_routes"),
        {"rib": [_rib_row("10.0.0.0/24")]},
        {
            "bgp_session_routes": TableOutcome(
                status="not-captured", detail="the source's capture_bgp setting is none"
            )
        },
    )
    _stub_load(monkeypatch)
    settings = _settings(tmp_path)
    manifest = coll.execute(SideCollector(SideCfg(), settings), _FakeSession())

    assert manifest.tables["rib"].status == "complete"
    routes = manifest.tables["bgp_session_routes"]
    assert (routes.status, routes.path) == ("not-captured", "")
    assert routes.detail == "the source's capture_bgp setting is none"

    outcome = runs_exec.DeviceOutcome("edge", "h", True, full=True, tables=manifest.tables)
    assert outcome.completeness == "ok"
    assert runs_exec._table_gaps(manifest.tables) == ""


def test_a_statement_never_overrides_a_table_that_was_written(tmp_path, monkeypatch):
    """A collector's statement fills in for a table with no rows."""
    from hst import collectors as coll
    from hst.core import manifest as manifests
    from hst.core.model import TableOutcome

    session_uid = "bgp:rproc:dev:sidefake2:d:bgp~10.1.1.2:d"
    SideCollector, SideCfg = _side_collector(
        ("rib",),
        {"rib": [_rib_row("10.0.0.0/24")]},
        {
            "rib": TableOutcome(status="not-captured", detail="ignored: the table was written"),
            manifests.bgp_direction_key(session_uid, "received"): TableOutcome(status="not-captured"),
        },
    )
    _stub_load(monkeypatch)
    settings = _settings(tmp_path)
    manifest = coll.execute(SideCollector(SideCfg(), settings), _FakeSession())

    assert manifest.tables["rib"].status == "complete"
    directions = manifests.bgp_direction_outcomes(manifest.tables)
    assert directions == {(session_uid, "received"): TableOutcome(status="not-captured")}


def test_a_table_the_collector_produced_without_declaring_is_still_accounted_for(tmp_path, monkeypatch):
    from hst import collectors as coll

    SideCollector, SideCfg = _side_collector((), {"rib": [_rib_row("10.0.0.0/24")]})
    _stub_load(monkeypatch)
    manifest = coll.execute(SideCollector(SideCfg(), _settings(tmp_path)), _FakeSession())

    assert manifest.tables["rib"].status == "complete"
    assert manifest.tables["rib"].row_count == 1


def test_write_table_never_exposes_a_partial_file(tmp_path, monkeypatch):
    """The write goes through `<run_id>.parquet.tmp` and is renamed into place once complete."""
    from pathlib import Path

    class _PartialWriter:
        """Stands in for `pq.ParquetWriter`: it opens the temporary file, writes
        a fragment and then fails on the first row group."""

        def __init__(self, where, schema, *a, **k):
            Path(where).write_bytes(b"PAR1 half a file")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def write_batch(self, batch, *a, **k):
            raise OSError("disk full")

    monkeypatch.setattr(sidestore.pq, "ParquetWriter", _PartialWriter)
    with pytest.raises(OSError, match="disk full"):
        sidestore.write_table(tmp_path, "rib", "nxos", "", "run-1", [_rib_row("10.0.0.0/24")], 1000)

    assert list(tmp_path.rglob("*.parquet")) == []
    assert list(tmp_path.rglob("*.tmp")) == []


# --- ospf_lsdb: the link-state database table -------------------------------


def _lsa(**over):
    """One router LSA in the `ospf_lsdb` column contract."""
    row = {
        "device_uid": "dev:abc",
        "context_uid": "vrf:dev:abc:default",
        "process": "1",
        "area": "0.0.0.0",  # noqa: S104 - an OSPF area id, not a bind address
        "lsa_type": "router",
        "lsid": "10.255.0.1",
        "adv_router": "10.255.0.1",
        "seq": 0x80000005,
        "age": 120,
        "metric": None,
        "links": [
            {
                "link_type": "point-to-point",
                "link_id": "10.255.0.2",
                "link_data": "10.0.0.1",
                "metric": 40,
            }
        ],
        "attached_routers": None,
        "mask": None,
        "forwarding_address": None,
        "metric_type": None,
    }
    row.update(over)
    return row


def test_ospf_lsdb_roundtrip_keeps_the_typed_lsa_bodies(tmp_path):
    """Every column SPF needs comes back as it went in, the nested router-LSA
    links and network-LSA attached routers included."""
    pytest.importorskip("duckdb")
    rows = [
        _lsa(),
        _lsa(
            lsa_type="network",
            lsid="10.0.0.1",
            links=None,
            attached_routers=["10.255.0.1", "10.255.0.2"],
            mask="255.255.255.0",
        ),
        _lsa(
            lsa_type="external",
            area=None,
            lsid="203.0.113.0",
            links=None,
            mask="255.255.255.0",
            metric=100,
            metric_type=2,
            forwarding_address="10.0.0.2",
        ),
    ]
    path = sidestore.write_table(tmp_path, "ospf_lsdb", "nxos", "n9k1", "run-1", rows, 1000)
    assert path == tmp_path / "ospf_lsdb" / "nxos" / "n9k1" / "run-1.parquet"

    out = sidestore.query(
        tmp_path,
        "SELECT lsa_type, area, lsid, seq, age, metric, metric_type, mask, "
        "forwarding_address, links, attached_routers, run_id, snapshot_ts "
        "FROM ospf_lsdb ORDER BY lsa_type",
    )
    by_type = {r["lsa_type"]: r for r in out}
    assert set(by_type) == {"router", "network", "external"}

    router = by_type["router"]
    assert (router["seq"], router["age"], router["metric"]) == (0x80000005, 120, None)
    assert router["links"] == [
        {"link_type": "point-to-point", "link_id": "10.255.0.2", "link_data": "10.0.0.1", "metric": 40}
    ]
    assert router["attached_routers"] is None
    assert (router["run_id"], router["snapshot_ts"]) == ("run-1", 1000)

    assert by_type["network"]["attached_routers"] == ["10.255.0.1", "10.255.0.2"]
    assert by_type["network"]["links"] is None

    external = by_type["external"]
    # an AS-external LSA is flooded domain-wide and belongs to no area
    assert external["area"] is None
    assert (external["metric"], external["metric_type"]) == (100, 2)
    assert external["forwarding_address"] == "10.0.0.2"


def test_ospf_lsdb_has_a_schema_version(tmp_path):
    """Every table in `SCHEMAS` states its own version."""
    assert set(sidestore.SCHEMA_VERSIONS) == set(sidestore.SCHEMAS)
    assert sidestore.SCHEMA_VERSIONS["ospf_lsdb"] == 1


def test_mac_corroboration_query_counts_a_mac_seen_on_both_sides_once_and_ignores_a_one_sided_one(tmp_path):
    """The vlan-stretch check's corroboration (hst/reasoner.py
    `read_mac_rows` and `observed_mac_count`): a MAC in the circuit's VLAN on
    the circuit-facing port at one site and on a local port at the other
    counts once; a MAC seen at one site only never counts; and only each
    device's newest run at or before the snapshot is read."""
    pytest.importorskip("duckdb")
    from hst import reasoner as rules

    fr2 = [
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/49"},
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee09", "port_name": "Ethernet1/49"},
    ]
    pa3 = [
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/7"},
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee02", "port_name": "Ethernet1/8"},
    ]
    sidestore.write_table(tmp_path, "mac", "nxos", "fr2", "run-1", fr2, 1000)
    sidestore.write_table(tmp_path, "mac", "nxos", "pa3", "run-1", pa3, 1000)
    # a newer PA3 run without the corroborating MAC
    sidestore.write_table(tmp_path, "mac", "nxos", "pa3", "run-2", pa3[1:], 2000)

    observation = {
        "circuit": "eqx:connection:c1",
        "kind": "stretched",
        "vid": 100,
        "vid_z": 100,
        "port_a": "dev:fr2/port/eth1-49",
        "port_z": "dev:pa3/port/eth1-49",
        "device_a": "dev:fr2",
        "device_z": "dev:pa3",
    }
    at_1000 = rules.read_mac_rows(tmp_path, ["dev:fr2", "dev:pa3"], 1000)
    assert len(at_1000) == 4
    assert rules.observed_mac_count(observation, at_1000) == 1

    at_2000 = rules.read_mac_rows(tmp_path, ["dev:fr2", "dev:pa3"], 2000)
    assert {(r["device_uid"], r["mac"]) for r in at_2000} == {
        ("dev:fr2", "aabbccddee01"),
        ("dev:fr2", "aabbccddee09"),
        ("dev:pa3", "aabbccddee02"),
    }
    assert rules.observed_mac_count(observation, at_2000) == 0


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_write_table_creates_private_files_and_directories(tmp_path):
    base = tmp_path / "side"
    row = {"device_uid": "dev:abc", "vrf": "default", "prefix": "10.0.0.0/24"}
    seen = {}

    def rows():
        yield row
        (tmp,) = (base / "rib" / "nxos" / "r1").glob(f"*{sidestore.TMP_SUFFIX}")
        seen["tmp"] = _mode(tmp)
        yield row

    umask = os.umask(0o022)
    try:
        path = sidestore.write_table(base, "rib", "nxos", "r1", "run-1", rows(), 1000, row_group_rows=1)
    finally:
        os.umask(umask)
    assert seen["tmp"] == 0o600
    assert _mode(path) == 0o600
    for directory in (path.parent, path.parent.parent, base / "rib", base):
        assert _mode(directory) == 0o700


def test_connect_reader_creates_a_private_catalog_and_spill_directory(tmp_path):
    pytest.importorskip("duckdb")
    umask = os.umask(0o022)
    try:
        sidestore.connect_reader(tmp_path).close()
    finally:
        os.umask(umask)
    spill = sidestore.spill_dir(tmp_path)
    assert _mode(tmp_path / sidestore.QUERY_CATALOG) == 0o600
    assert _mode(spill) == 0o700
    assert _mode(spill.parent) == 0o700
