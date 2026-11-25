"""Reads that start from the run's own index."""

from __future__ import annotations

import importlib
import ipaddress
import random
from typing import Any

import pytest
from typer.testing import CliRunner

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import reasoner as reasonermod
from hst.core.config import Settings
from hst.path import session as sessionmod
from hst.reasoner import _constants as constants
from hst.reasoner import catalog

# the package exports the function `trace` under the module's name
tracemod = importlib.import_module("hst.path.trace")

# --- the indexes init-db creates -----------------------------------------------------------


def _index_names() -> set[str]:
    return {stmt.split(" IF NOT EXISTS")[0].split()[-1] for stmt in dbmod.CONSTRAINT_STATEMENTS}


@pytest.mark.parametrize(
    "name",
    [
        # the per-label uid indexes
        "interface_uid",
        "device_uid",
        "vrfinstance_uid",
        "prefix_uid",
        "fwrulebase_uid",
        "ipaddress_uid",
        "netobject_uid",
        "pbrpolicy_uid",
        "tunnel_uid",
        "gate_uid",
        "zpaappsegment_uid",
        "virtualservice_uid",
        # a label scan pinned to the run seeks the run's copies of the label
        "device_cts",
        "interface_cts",
        "port_cts",
        "endpoint_cts",
        # nodes that carry no run
        "meta_uid",
        "site_uid",
        "site_code",
        "cyclerun_uid",
        "collectionrun_uid",
        # the reasoner MAC joins and the trace gateway read
        "interface_mac_cts",
        "gateway_for_cts",
    ],
)
def test_init_db_creates_the_index_an_anchor_seeks(name):
    assert name in _index_names()


def test_the_run_bookkeeping_indexes_are_not_uniqueness_constraints():
    """A graph can hold a duplicate uid of these labels."""
    for stmt in dbmod.CONSTRAINT_STATEMENTS:
        if any(f" {n} " in stmt for n in ("meta_uid", "site_uid", "cyclerun_uid", "collectionrun_uid")):
            assert stmt.startswith("CREATE INDEX"), stmt


# --- the reasoner's CLEAR, the one-time sweep, the MAC joins, the timeout -----------------


def test_the_reasoner_clear_starts_from_the_runs_nodes():
    assert constants.CLEAR.startswith("MATCH (n:Obj {collection_ts: $cts})-[r]->() ")
    assert "coalesce" not in constants.CLEAR


class _CaptureRun:
    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def run(self, query: str, **params: Any) -> Any:
        self.queries.append((query, params))

        class _Result:
            def consume(self) -> None:
                return None

        return _Result()


def test_the_sweep_of_unversioned_reasoner_edges_runs_once_in_batches():
    session = _CaptureRun()

    cyclemod.sweep_unversioned_reasoner_edges(session)  # type: ignore[arg-type]

    [(query, params)] = session.queries
    assert "r._scope = 'reasoner' AND r.collection_ts IS NULL" in query
    assert "IN TRANSACTIONS" in query and params == {"batch": cyclemod.BATCH}


class _MetaSiteSession:
    """Answers the count of unversioned operator Sites and records the statements that follow."""

    def __init__(self, found: int) -> None:
        self.found = found
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def execute_read(self, work: Any) -> Any:
        outer = self

        class _Tx:
            def run(self, query: str, **params: Any) -> Any:
                class _Result:
                    def data(self) -> list[dict[str, Any]]:
                        return [{"n": outer.found}]

                return _Result()

        return work(_Tx())

    def run(self, query: str, **params: Any) -> Any:
        self.queries.append((query, params))

        class _Result:
            def consume(self) -> None:
                return None

        return _Result()


def test_the_meta_site_split_adds_every_copy_before_it_drops_the_shared_node():
    session = _MetaSiteSession(found=2)

    assert cyclemod.migrate_meta_sites(session) == 2  # type: ignore[arg-type]

    split, drop = session.queries
    assert split[0] == cyclemod._SPLIT_META_SITES and drop[0] == cyclemod._DROP_META_SITES
    assert split[1] == drop[1] == {"batch": cyclemod.BATCH}
    # the first statement only adds, so a repeat after a failure loses nothing
    assert "DELETE" not in cyclemod._SPLIT_META_SITES
    assert "MERGE (c:Site:Obj {uid: m.uid, collection_ts: d.collection_ts})" in cyclemod._SPLIT_META_SITES
    assert "MERGE (d)-[n:LOCATED_IN]->(c)" in cyclemod._SPLIT_META_SITES
    assert "IN TRANSACTIONS" in cyclemod._SPLIT_META_SITES and "IN TRANSACTIONS" in cyclemod._DROP_META_SITES


def test_the_meta_site_split_does_nothing_on_a_graph_without_the_shared_node():
    session = _MetaSiteSession(found=0)

    assert cyclemod.migrate_meta_sites(session) == 0  # type: ignore[arg-type]
    assert session.queries == []


def test_migrate_cycle_sweeps_after_the_bootstrap(monkeypatch):
    from contextlib import contextmanager

    from hst import cli

    steps: list[str] = []
    monkeypatch.setattr(
        cyclemod, "migrate_bootstrap", lambda s: steps.append("bootstrap") or {"migrated": False}
    )
    monkeypatch.setattr(cyclemod, "sweep_unversioned_reasoner_edges", lambda s: steps.append("sweep"))
    monkeypatch.setattr(cyclemod, "migrate_meta_sites", lambda s: steps.append("meta-sites") or 0)

    @contextmanager
    def session(settings: Any, access_mode: Any = None):
        yield object()

    monkeypatch.setattr(cli.dbmod, "session", session)

    result = CliRunner().invoke(cli.app, ["migrate-cycle"])

    assert result.exit_code == 0, result.output
    assert steps == ["bootstrap", "sweep", "meta-sites"]


def test_the_mac_joins_seek_the_interface_by_mac_at_the_run():
    rules = dict(catalog.RULES)
    assert "(i:Interface:Obj {mac: ep.mac, collection_ts: $cts})" in str(rules["cable-from-endpoint-mac"])
    assert "(i:Interface:Obj {mac: swp.last_conn_mac, collection_ts: $cts})" in str(
        rules["cable-from-last-connection"]
    )


class _WorkCapture:
    def __init__(self) -> None:
        self.timeouts: list[Any] = []

    def execute_read(self, work: Any, query: str, params: Any) -> list[Any]:
        self.timeouts.append(work.timeout)
        return []


def test_the_audit_reads_keep_their_timeout_and_the_finalize_reads_take_the_setting():
    session = _WorkCapture()

    reasonermod.read_topology(session, 5)
    reasonermod.read_connected_to_speed(session, 5, timeout=None)
    reasonermod.read_topology(session, 5, timeout=120.0)

    assert session.timeouts == [reasonermod.AUDIT_READ_TIMEOUT_S, None, 120.0]


def test_the_finalize_derivation_passes_the_setting(monkeypatch, tmp_path):
    seen: list[Any] = []
    monkeypatch.setattr(reasonermod, "read_topology", lambda s, cts, timeout: seen.append(timeout) or _topo())
    monkeypatch.setattr(
        reasonermod, "read_connected_to_speed", lambda s, cts, timeout: seen.append(timeout) or []
    )
    monkeypatch.setattr(reasonermod, "load", lambda *a, **k: None)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    assert settings.reasoner_read_timeout_s is None
    tuned = settings.model_copy(update={"reasoner_read_timeout_s": 90.0})

    for each in (settings, tuned):
        reasonermod.execute_rt_domains(object(), each, collection_ts=7)
        reasonermod.execute_link_speed(object(), each, collection_ts=7)

    assert seen == [None, None, 90.0, 90.0]


def _topo() -> Any:
    return reasonermod.pair_and_group([])


# --- the parent run's observation times, read once ------------------------------------------


class _ReadCapture:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute_read(self, work: Any) -> Any:
        outer = self

        class _Tx:
            def run(self, query: str, **params: Any) -> Any:
                outer.calls.append((query, params))

                class _Result:
                    def data(self) -> list[dict[str, Any]]:
                        return outer.rows

                return _Result()

        return work(_Tx())


def test_the_observation_times_of_many_scopes_are_one_read_of_the_run():
    session = _ReadCapture(
        [{"scope": "vyos:r1", "collected_at": 1500}, {"scope": "vyos:r2", "collected_at": None}]
    )

    found = cyclemod.scopes_collected_at(session, 1000, ["vyos:r2", "vyos:r1", "vyos:r1"])  # type: ignore[arg-type]

    assert found == {"vyos:r1": 1500}
    [(query, params)] = session.calls
    assert "MATCH (n:Obj {collection_ts: $cts})" in query and "n._scope IN $scopes" in query
    assert params == {"cts": 1000, "scopes": ["vyos:r1", "vyos:r2"]}
    assert cyclemod.scopes_collected_at(session, 1000, []) == {}  # type: ignore[arg-type]
    assert len(session.calls) == 1


# --- the site statements --------------------------------------------------------------------


class _WriteCapture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute_write(self, work: Any) -> Any:
        outer = self

        class _Tx:
            def run(self, query: str, **params: Any) -> Any:
                outer.calls.append((query, params))

                class _Result:
                    def data(self) -> list[dict[str, Any]]:
                        return [{"n": 1}]

                return _Result()

        return work(_Tx())


def test_the_meta_sites_are_ensured_once_per_site_not_per_device():
    session = _WriteCapture()

    cyclemod.apply_site_assignments(session, {"dev:1": "hq", "dev:2": "hq", "dev:3": "br"}, 4242)  # type: ignore[arg-type]

    ensure = next(params for query, params in session.calls if "MERGE (m:Site:Obj {uid: row.uid" in query)
    assert ensure["sites"] == [{"uid": "site:br", "code": "br"}, {"uid": "site:hq", "code": "hq"}]


def test_every_site_statement_seeks_the_run_by_uid():
    for query in (
        cyclemod._ENSURE_META_SITES,
        cyclemod._CLEAR_ASSIGNMENTS,
        cyclemod._CARRY_META_SITES,
        cyclemod._APPLY_ASSIGNMENTS,
        cyclemod._CARRY_SITES,
    ):
        assert "collection_ts: $snap}" in query, query
    assert "collection_ts: $parent})" in cyclemod._CARRY_SITES


def test_a_carry_with_no_named_parent_reads_the_newest_run_before_it():
    class _Session(_WriteCapture):
        def __init__(self) -> None:
            super().__init__()
            self.reads: list[dict[str, Any]] = []

        def execute_read(self, work: Any) -> Any:
            outer = self

            class _Tx:
                def run(self, query: str, **params: Any) -> Any:
                    outer.reads.append(params)

                    class _Result:
                        def data(self) -> list[dict[str, Any]]:
                            return [{"prev": 4100}]

                    return _Result()

            return work(_Tx())

    session = _Session()

    assert cyclemod.carry_site_assignments(session, {}, 4242) == 1  # type: ignore[arg-type]

    assert session.reads == [{"snap": 4242}]
    # the previous copy's operator site is made in the run first, then the device is pointed at it
    assert [query for query, _params in session.calls] == [
        cyclemod._CARRY_META_SITES,
        cyclemod._CARRY_SITES,
    ]
    assert all(params == {"resolved": [], "snap": 4242, "parent": 4100} for _query, params in session.calls)


# --- the trace's gateway rows --------------------------------------------------------------


class _GraphSession:
    """The session a CycleSession wraps: answers the run meta node and the
    gateway read, and counts the gateway reads."""

    def __init__(self, meta: dict[str, Any] | None, rows: list[dict[str, Any]]) -> None:
        self.meta = meta
        self.rows = rows
        self.gateway_reads = 0

    def execute_read(self, work: Any) -> Any:
        outer = self

        class _Tx:
            def run(self, query: str, **params: Any) -> Any:
                if "CycleRun" in query:
                    rows = [] if outer.meta is None else [outer.meta]
                else:
                    assert query == sessionmod.GATEWAYS
                    outer.gateway_reads += 1
                    rows = [dict(r) for r in outer.rows]

                class _Result:
                    def data(self) -> list[dict[str, Any]]:
                        return rows

                return _Result()

        return work(_Tx())


_META = {"digest": "abc", "nodes": 10, "rels": 20, "reprocessed_from": None}
_ROWS = [
    {"cidr": "10.0.0.0/24", "if_uid": "if:1", "anchor": "vrf:a"},
    {"cidr": "10.0.0.0/16", "if_uid": "if:2", "anchor": "vrf:a"},
]


@pytest.fixture
def no_gateway_cache():
    sessionmod._GATEWAY_CACHE.clear()
    yield
    sessionmod._GATEWAY_CACHE.clear()


def test_the_gateway_read_starts_from_the_runs_edges():
    assert "[g:GATEWAY_FOR {collection_ts: $snap}]" in sessionmod.GATEWAYS
    assert "(i:Interface:Obj)" in sessionmod.GATEWAYS and "i.collection_ts = $snap" in sessionmod.GATEWAYS
    assert "coalesce" not in sessionmod.GATEWAYS.split("RETURN")[0]


def test_a_published_run_is_read_once_per_process(no_gateway_cache):
    graph = _GraphSession(_META, _ROWS)

    first = sessionmod.load_gateways(sessionmod.CycleSession(graph, 42))
    first[0]["cidr"] = "changed by a caller"
    second = sessionmod.load_gateways(sessionmod.CycleSession(graph, 42))

    assert graph.gateway_reads == 1
    # each caller gets its own rows: a change one makes is not the next one's
    assert second == _ROWS


def test_a_run_rebuilt_under_the_same_key_is_read_again(no_gateway_cache):
    graph = _GraphSession(_META, _ROWS)
    sessionmod.load_gateways(sessionmod.CycleSession(graph, 42))

    graph.meta = {**_META, "digest": "rebuilt"}
    sessionmod.load_gateways(sessionmod.CycleSession(graph, 42))

    assert graph.gateway_reads == 2


def test_an_unpublished_run_or_an_overlay_is_not_kept(no_gateway_cache):
    graph = _GraphSession(None, _ROWS)
    sessionmod.load_gateways(sessionmod.CycleSession(graph, 42))
    sessionmod.load_gateways(sessionmod.CycleSession(graph, 42))
    assert graph.gateway_reads == 2

    graph.meta = _META
    for _ in range(2):
        overlaid = sessionmod.CycleSession(graph, 42)
        overlaid.overlay = lambda query, params, rows: rows  # type: ignore[attr-defined]
        sessionmod.load_gateways(overlaid)
    assert graph.gateway_reads == 4
    assert not sessionmod._GATEWAY_CACHE


def test_the_cache_keeps_the_newest_runs_only(no_gateway_cache):
    graph = _GraphSession(_META, _ROWS)
    for cts in range(sessionmod.GATEWAY_CACHE_RUNS + 2):
        sessionmod.load_gateways(sessionmod.CycleSession(graph, cts))
    assert len(sessionmod._GATEWAY_CACHE) == sessionmod.GATEWAY_CACHE_RUNS


def _brute_containing(rows: list[dict[str, Any]], probe: str) -> list[dict[str, Any]]:
    addr = ipaddress.ip_address(probe)
    out = []
    for g in rows:
        try:
            net = ipaddress.ip_network(g["cidr"])
        except (KeyError, ValueError):
            continue
        if addr.version == net.version and addr in net:
            out.append(g)
    return out


def test_the_prefix_index_finds_what_a_scan_of_every_row_finds():
    rnd = random.Random(7)
    rows: list[dict[str, Any]] = [{"cidr": "not a prefix"}, {"cidr": "10.1.2.3/24"}, {"if_uid": "no cidr"}]
    for i in range(400):
        if i % 3:
            length = rnd.randint(0, 32)
            net = ipaddress.ip_network((rnd.getrandbits(32), length), strict=False)
        else:
            length = rnd.randint(0, 128)
            net = ipaddress.ip_network((rnd.getrandbits(128), length), strict=False)
        rows.append({"cidr": str(net), "if_uid": f"if:{i}"})
    probes = [str(ipaddress.ip_address(rnd.getrandbits(32))) for _ in range(100)]
    probes += [str(ipaddress.ip_address(rnd.getrandbits(128))) for _ in range(50)]
    probes += [r["cidr"].split("/")[0] for r in rows[3:60]] + ["not an address"]

    indexed = sessionmod.GatewayRows(rows)
    for probe in probes:
        expected = [] if probe == "not an address" else _brute_containing(rows, probe)
        assert tracemod._containing(indexed, probe) == expected, probe
        assert tracemod._containing(list(rows), probe) == expected, probe
