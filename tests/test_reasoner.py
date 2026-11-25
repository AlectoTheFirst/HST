"""core.reasoner: RT-import pairing/components (pure), the route-target routes the
readers resolve, and the batches it builds."""

from __future__ import annotations

import random
from typing import Any

import pytest
from typer.testing import CliRunner

import hst.cli as cli
from hst.core import Settings, reasoner, uid
from hst.core.model import Batch, RunManifest

cli_runner = CliRunner()


def _row(vrf_uid: str, kind: str, rt: str) -> dict[str, Any]:
    return {"vrf_uid": vrf_uid, "kind": kind, "rt": rt}


# --- pairing/components: pure --------------------------------------------------------


def test_an_exporter_of_a_single_rt_pairs_with_a_wider_importer():
    rows = [
        _row("vrf:a", "EXPORTS", "rt1"),
        _row("vrf:b", "IMPORTS", "rt1"),
        _row("vrf:b", "IMPORTS", "rt2"),
    ]
    topology = reasoner.pair_and_group(rows)
    assert topology.pairs == (reasoner.RtPairing(importer="vrf:b", exporter="vrf:a", via_rt=("rt1",)),)


def test_pairing_is_directional_not_symmetric():
    rows = [_row("vrf:a", "EXPORTS", "rt1"), _row("vrf:b", "IMPORTS", "rt1")]
    topology = reasoner.pair_and_group(rows)
    assert topology.pairs == (reasoner.RtPairing(importer="vrf:b", exporter="vrf:a", via_rt=("rt1",)),)


def test_pairing_is_bidirectional_only_when_the_reverse_also_holds():
    rows = [
        _row("vrf:a", "EXPORTS", "rt1"),
        _row("vrf:b", "IMPORTS", "rt1"),
        _row("vrf:b", "EXPORTS", "rt2"),
        _row("vrf:a", "IMPORTS", "rt2"),
    ]
    topology = reasoner.pair_and_group(rows)
    assert {(p.importer, p.exporter) for p in topology.pairs} == {
        ("vrf:b", "vrf:a"),
        ("vrf:a", "vrf:b"),
    }


def test_two_import_only_vrfs_sharing_an_rt_do_not_pair():
    rows = [_row("vrf:c", "IMPORTS", "rt1"), _row("vrf:d", "IMPORTS", "rt1")]
    topology = reasoner.pair_and_group(rows)
    assert topology.pairs == ()
    assert topology.components["vrf:c"] != topology.components["vrf:d"]


def test_hub_and_spoke_hub_pairs_both_ways_with_every_spoke_but_spokes_never_pair():
    rows = [
        _row("hub", "EXPORTS", "rt-hub"),
        _row("hub", "IMPORTS", "rt-spoke1"),
        _row("hub", "IMPORTS", "rt-spoke2"),
        _row("spoke1", "IMPORTS", "rt-hub"),
        _row("spoke1", "EXPORTS", "rt-spoke1"),
        _row("spoke2", "IMPORTS", "rt-hub"),
        _row("spoke2", "EXPORTS", "rt-spoke2"),
    ]
    topology = reasoner.pair_and_group(rows)
    pair_set = {(p.importer, p.exporter) for p in topology.pairs}
    assert pair_set == {
        ("spoke1", "hub"),  # spoke1 receives the hub's routes
        ("spoke2", "hub"),  # spoke2 receives the hub's routes
        ("hub", "spoke1"),  # hub receives spoke1's routes
        ("hub", "spoke2"),  # hub receives spoke2's routes
    }
    assert ("spoke1", "spoke2") not in pair_set
    assert ("spoke2", "spoke1") not in pair_set
    assert topology.components["hub"] == topology.components["spoke1"] == topology.components["spoke2"]


def test_a_vrf_that_both_imports_and_exports_the_same_rt_does_not_pair_with_itself():
    rows = [_row("vrf:a", "EXPORTS", "rt1"), _row("vrf:a", "IMPORTS", "rt1")]
    topology = reasoner.pair_and_group(rows)
    assert topology.pairs == ()


def test_pairing_and_components_are_deterministic_regardless_of_row_order():
    rows = [
        _row("hub", "EXPORTS", "rt-hub"),
        _row("hub", "IMPORTS", "rt-spoke1"),
        _row("hub", "IMPORTS", "rt-spoke2"),
        _row("spoke1", "IMPORTS", "rt-hub"),
        _row("spoke1", "EXPORTS", "rt-spoke1"),
        _row("spoke2", "IMPORTS", "rt-hub"),
        _row("spoke2", "EXPORTS", "rt-spoke2"),
        _row("vrf:c", "IMPORTS", "rt-orphan"),
        _row("vrf:d", "IMPORTS", "rt-orphan"),
    ]
    baseline = reasoner.pair_and_group(rows)
    shuffled = list(rows)
    random.Random(7).shuffle(shuffled)
    assert shuffled != rows
    result = reasoner.pair_and_group(shuffled)
    assert result.pairs == baseline.pairs
    assert result.components == baseline.components
    assert result.rts_by_vrf == baseline.rts_by_vrf


def test_a_vrf_with_rt_edges_but_no_pairing_partner_is_still_a_singleton_component():
    rows = [_row("vrf:lonely", "IMPORTS", "rt-nobody-exports")]
    topology = reasoner.pair_and_group(rows)
    assert topology.pairs == ()
    assert topology.components == {"vrf:lonely": "vrf:lonely"}
    assert topology.rts_by_vrf == {"vrf:lonely": ("rt-nobody-exports",)}


# --- route-target routes: resolved where they are read ------------------------------


def test_the_route_target_routes_are_not_written_as_edges():
    for name in ("execute", "derive_batch", "build_learned_routes", "iter_learned_routes", "read_originates"):
        assert not hasattr(reasoner, name), name


def test_the_route_target_routes_fragment_is_one_hop_retirement_aware_and_pinned():
    q = reasoner.RT_IMPORTED_ROUTES
    # the directed pairing: v imports a route target another VRF exports, and
    # receives that exporter's own ORIGINATES prefixes, never its learned ones
    assert (
        "(v)-[im:IMPORTS]->(rt:RouteTarget:Obj)<-[ex:EXPORTS]-(x:VrfInstance)-[o:ORIGINATES]->(p:Prefix)" in q
    )
    assert "LEARNED_ROUTE" not in q
    assert "x <> v" in q
    for rel in ("im", "ex", "o"):
        assert f"{rel}._retired_at IS NULL" in q
    for node in ("rt", "x", "p"):
        assert f"NOT {node}:Retired" in q
        assert f"{node}.collection_ts = $snap" in q
    # one row per (importer, prefix), whatever number of route targets or
    # exporters justify it, and every justifying route target in via_rt, sorted
    assert "WITH DISTINCT v, p" in q
    assert "ORDER BY rt_value" in q
    assert q.rstrip().endswith("AS via_rt")
    # collected per row, never aggregated over the whole expansion, so a
    # caller's LIMIT can stop it early
    assert "collect(" not in q


def test_every_reader_of_learned_routes_resolves_the_route_target_routes():
    import importlib

    from hst.applications import generator_tools
    from hst.twin_tools import routing

    trace = importlib.import_module("hst.path.trace")
    for query in (
        trace._ROUTES_QUERY,
        generator_tools._TABLE_ROUTES,
        generator_tools._INTERFACE_ROUTES,
        routing._PREFIX_ROUTES_QUERY,
    ):
        assert reasoner.RT_IMPORTED_ROUTES in query
        assert "UNION" in query
    branch = trace._ROUTES_QUERY.split("UNION", 1)[1]
    assert "'LEARNED_ROUTE' AS kind" in branch
    assert "'rt-import' AS derived, via_rt" in branch
    assert "null AS next_hop" in branch and "null AS egress_uid" in branch
    # the importing table is the anchor, pinned to the run
    assert "MATCH (v:VrfInstance {uid: $vrf})\nWHERE v:Obj AND v.collection_ts = $snap" in branch
    # the readers that return per-edge rows skip rt-import edges
    for query in (
        generator_tools._TABLE_ROUTES,
        generator_tools._INTERFACE_ROUTES,
        routing._PREFIX_ROUTES_QUERY,
    ):
        assert "coalesce(r.derived, '') <> 'rt-import'" in query
    # the estate-wide search starts from the matching prefixes and stops at its cap
    search = routing._PREFIX_ROUTES_QUERY.split("UNION ALL", 1)[1]
    assert search.lstrip().startswith("MATCH (p:Prefix:Obj)")
    assert "WITH v, p LIMIT $limit" in search


# --- build_rt_domains: pure -------------------------------------------------------------


def test_build_rt_domains_two_member_component_gets_a_routing_domain():
    topology = reasoner.pair_and_group([_row("vrf:a", "EXPORTS", "rt2"), _row("vrf:b", "IMPORTS", "rt2")])
    batch = reasoner.build_rt_domains(topology)

    assert batch.source == "reasoner"
    assert batch.scope == "derived:rt-domains"
    assert len(batch.nodes) == 1
    node = batch.nodes[0]
    du = uid.routing_domain("rt:rt2")
    assert node.label == "RoutingDomain"
    assert node.uid == du
    assert node.props == {"name": "route-target rt2", "basis": "rt-component", "rts": "rt2"}

    member_of = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "MEMBER_OF"}
    assert member_of == {("vrf:a", du), ("vrf:b", du)}
    for r in batch.rels:
        assert r.start_label == "VrfInstance"
        assert r.end_label == "RoutingDomain"
        assert r.key == {"basis": "rt-component"}
        assert r.props == {"basis": "rt-component", "rts": "rt2"}


def test_build_rt_domains_canonical_name_is_the_components_minimum_touched_rt():
    topology = reasoner.pair_and_group(
        [
            _row("vrf:a", "EXPORTS", "rt2"),
            _row("vrf:b", "IMPORTS", "rt2"),
            _row("vrf:a", "IMPORTS", "rt1"),
        ]
    )
    batch = reasoner.build_rt_domains(topology)
    assert [n.uid for n in batch.nodes] == [uid.routing_domain("rt:rt1")]
    assert batch.nodes[0].props["rts"] == "rt1,rt2"


def test_build_rt_domains_singleton_component_produces_nothing():
    topology = reasoner.pair_and_group([_row("vrf:lonely", "IMPORTS", "rt-nobody-exports")])
    batch = reasoner.build_rt_domains(topology)
    assert batch.nodes == []
    assert batch.rels == []


def test_build_rt_domains_two_import_only_vrfs_sharing_an_rt_produce_nothing():
    topology = reasoner.pair_and_group([_row("vrf:c", "IMPORTS", "rt1"), _row("vrf:d", "IMPORTS", "rt1")])
    batch = reasoner.build_rt_domains(topology)
    assert batch.nodes == []
    assert batch.rels == []


def test_build_rt_domains_hub_and_spoke_collapses_to_one_derived_domain():
    """Hub-and-spoke is one *undirected* component
    (test_hub_and_spoke_hub_pairs_both_ways_with_every_spoke_but_spokes_never_pair)."""
    rows = [
        _row("hub", "EXPORTS", "rt-hub"),
        _row("hub", "IMPORTS", "rt-spoke1"),
        _row("hub", "IMPORTS", "rt-spoke2"),
        _row("spoke1", "IMPORTS", "rt-hub"),
        _row("spoke1", "EXPORTS", "rt-spoke1"),
        _row("spoke2", "IMPORTS", "rt-hub"),
        _row("spoke2", "EXPORTS", "rt-spoke2"),
    ]
    topology = reasoner.pair_and_group(rows)
    batch = reasoner.build_rt_domains(topology)

    assert len(batch.nodes) == 1
    du = batch.nodes[0].uid
    assert du == uid.routing_domain("rt:" + min("rt-hub", "rt-spoke1", "rt-spoke2"))
    members = {r.start_uid for r in batch.rels if r.rel_type == "MEMBER_OF"}
    assert members == {"hub", "spoke1", "spoke2"}
    assert all(r.end_uid == du for r in batch.rels)


def test_build_rt_domains_is_deterministic_regardless_of_row_order():
    rows = [
        _row("hub", "EXPORTS", "rt-hub"),
        _row("hub", "IMPORTS", "rt-spoke1"),
        _row("hub", "IMPORTS", "rt-spoke2"),
        _row("spoke1", "IMPORTS", "rt-hub"),
        _row("spoke1", "EXPORTS", "rt-spoke1"),
        _row("spoke2", "IMPORTS", "rt-hub"),
        _row("spoke2", "EXPORTS", "rt-spoke2"),
        _row("vrf:c", "IMPORTS", "rt-orphan"),
        _row("vrf:d", "IMPORTS", "rt-orphan"),
    ]
    baseline = reasoner.build_rt_domains(reasoner.pair_and_group(rows))
    shuffled = list(rows)
    random.Random(11).shuffle(shuffled)
    assert shuffled != rows
    result = reasoner.build_rt_domains(reasoner.pair_and_group(shuffled))
    assert result.nodes == baseline.nodes
    assert result.rels == baseline.rels


def test_build_rt_domains_output_passes_batch_registry_validation():
    topology = reasoner.pair_and_group([_row("vrf:a", "EXPORTS", "rt1"), _row("vrf:b", "IMPORTS", "rt1")])
    batch = reasoner.build_rt_domains(topology)
    batch.validate_registry()  # must not raise


# --- find_domain_splits: pure ----------------------------------------------------------


def test_find_domain_splits_reports_a_component_that_spans_two_domains():
    topology = reasoner.pair_and_group(
        [_row("vrf:dev:a:default", "EXPORTS", "65000:1"), _row("vrf:dev:b:default", "IMPORTS", "65000:1")]
    )
    realizes = [
        {"vrf_uid": "vrf:dev:a:default", "domain_name": "corp-a"},
        {"vrf_uid": "vrf:dev:b:default", "domain_name": "corp-b"},
    ]
    splits = reasoner.find_domain_splits(topology, realizes)
    assert len(splits) == 1
    split = splits[0]
    assert split.rts == ("65000:1",)
    assert split.members == (("vrf:dev:a:default", "dev:a"), ("vrf:dev:b:default", "dev:b"))
    assert split.domains == ("corp-a", "corp-b")


def test_find_domain_splits_says_nothing_about_a_component_within_one_domain():
    topology = reasoner.pair_and_group(
        [_row("vrf:dev:a:default", "EXPORTS", "65000:1"), _row("vrf:dev:b:default", "IMPORTS", "65000:1")]
    )
    realizes = [
        {"vrf_uid": "vrf:dev:a:default", "domain_name": "corp"},
        {"vrf_uid": "vrf:dev:b:default", "domain_name": "corp"},
    ]
    assert reasoner.find_domain_splits(topology, realizes) == []


def test_find_domain_splits_ignores_a_component_with_no_realizes_data():
    topology = reasoner.pair_and_group(
        [_row("vrf:dev:a:default", "EXPORTS", "65000:1"), _row("vrf:dev:b:default", "IMPORTS", "65000:1")]
    )
    assert reasoner.find_domain_splits(topology, []) == []


def test_device_of_parses_the_vrf_uid_scope():
    assert reasoner._device_of("vrf:dev:qemu1234:default") == "dev:qemu1234"
    assert reasoner._device_of("vrf:dev:x:unifi:gw1:default") == "dev:x:unifi:gw1"
    # not the `vrf:` shape at all (e.g. an ACI DN-keyed VrfInstance): returned as-is
    assert reasoner._device_of("aci:fab1:uni/tn-x/ctx-y") == "aci:fab1:uni/tn-x/ctx-y"


# --- graph read + batch build, end to end without Neo4j -------------------------------


class _FakeReadResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows


class _FakeWriteResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows

    def consume(self) -> None:
        return None


class _FakeTx:
    def __init__(
        self,
        rt_rows: list[dict[str, Any]],
        realizes_rows: list[dict[str, Any]],
        link_speed_rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self._rt_rows = rt_rows
        self._realizes_rows = realizes_rows
        self._link_speed_rows = link_speed_rows or []

    def run(self, query: str, **params: Any) -> _FakeReadResult:
        if "CONNECTED_TO" in query:
            return _FakeReadResult(self._link_speed_rows)
        if "RouteTarget" in query:
            return _FakeReadResult(self._rt_rows)
        # REALIZES_AT_CYCLE_QUERY unions a RoutingDomain (declared) clause with an
        # L3Domain clause.
        if "RoutingDomain" in query or "L3Domain" in query:
            return _FakeReadResult(self._realizes_rows)
        return _FakeReadResult([])


class FakeSession:
    """Combines the `execute_read` dispatch tests/test_audit_contexts.py's fake uses
    with tests/test_loader_unit.py's generic `execute_write` query-shape matcher."""

    def __init__(
        self,
        rt_rows: Any = (),
        realizes_rows: Any = (),
        link_speed_rows: Any = (),
        owned_rels: int = 0,
        stale_rels: int = 0,
        current: int | None = None,
    ) -> None:
        self._rt_rows = list(rt_rows)
        self._realizes_rows = list(realizes_rows)
        self._link_speed_rows = list(link_speed_rows)
        self.owned_rels = owned_rels
        self.stale_rels = stale_rels
        self._current = current
        self.pointer_calls = 0
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *a: Any) -> bool:
        return False

    def execute_read(self, work: Any, *args: Any, **kwargs: Any) -> Any:
        tx = _FakeTx(self._rt_rows, self._realizes_rows, self._link_speed_rows)
        return work(tx, *args, **kwargs)

    def execute_write(self, work: Any) -> Any:
        return work(self)

    def run(self, q: str, **p: Any) -> _FakeWriteResult:
        if "CyclePointer" in q:
            # the autocommit pointer read core.cycle.current_ts_or_none issues;
            # _read_cycle calls it when a caller omits collection_ts
            self.pointer_calls += 1
            rows = [{"current": self._current}] if self._current is not None else []
            return _FakeWriteResult(rows)
        self.queries.append((q, p))
        ts = p.get("ts")
        if "UNWIND $rows AS row" in q and "MERGE (n" in q:
            return _FakeWriteResult(
                [
                    {
                        "uid": r["uid"],
                        "before": {},
                        "after": {**r["props"], "_first_seen": ts, "_last_seen": ts},
                    }
                    for r in p["rows"]
                ]
            )
        if "UNWIND $rows" in q and "MERGE (a)-" in q:
            return _FakeWriteResult(
                [
                    {
                        "start": r["start"],
                        "end": r["end"],
                        "before": {},
                        "after": {**r["props"], "_first_seen": ts, "_last_seen": ts},
                    }
                    for r in p["rows"]
                ]
            )
        if "n._last_seen < $ts" in q and "RETURN count(n) AS c" in q:
            return _FakeWriteResult([{"c": 0}])
        if "RETURN count(n) AS c" in q:
            return _FakeWriteResult([{"c": 0}])
        if "r._last_seen < $ts" in q and "RETURN count(r) AS c" in q:
            return _FakeWriteResult([{"c": self.stale_rels}])
        if "RETURN count(r) AS c" in q:
            return _FakeWriteResult([{"c": self.owned_rels}])
        return _FakeWriteResult([])


def test_read_topology_dispatches_the_rt_edges_query():
    rt_rows = [
        {"vrf_uid": "vrf:a", "kind": "EXPORTS", "rt": "rt1"},
        {"vrf_uid": "vrf:b", "kind": "IMPORTS", "rt": "rt1"},
    ]
    topology = reasoner.read_topology(FakeSession(rt_rows=rt_rows))
    assert topology.pairs == (reasoner.RtPairing(importer="vrf:b", exporter="vrf:a", via_rt=("rt1",)),)


def test_read_realizes_dispatches_the_realizes_query():
    realizes_rows = [{"vrf_uid": "vrf:dev:a:default", "domain_name": "corp"}]
    rows = reasoner.read_realizes(FakeSession(realizes_rows=realizes_rows))
    assert rows == realizes_rows


def test_realizes_query_unions_declared_membership_and_legacy_realizes():
    """`hst audit domains` reports for a graph in either shape: the declared
    `MEMBER_OF`/`RoutingDomain`, or `REALIZES`/`L3Domain`."""
    q = reasoner.REALIZES_AT_CYCLE_QUERY
    assert "UNION" in q
    declared, legacy = q.split("UNION", 1)
    assert "MEMBER_OF" in declared and "RoutingDomain" in declared and "basis: 'declared'" in declared
    assert "REALIZES" in legacy and "L3Domain" in legacy
    # retirement-aware on both branches (module comment: "Retirement-aware, matching
    # the idiom in queries.py")
    for clause in (declared, legacy):
        assert "NOT v:Retired" in clause
        assert "NOT d:Retired" in clause
        assert "_retired_at IS NULL" in clause
        # pinned by version key
        assert "v.collection_ts = $cts" in clause
    assert ":Latest" not in q
    # both branches return the same shape, so the UNION is well-formed
    assert q.count("RETURN v.uid AS vrf_uid, d.name AS domain_name") == 2


# --- graph read + batch build: rt-domains -----------------------------------------------


def test_derive_rt_domains_batch_reads_the_graph_and_builds_routing_domains():
    rt_rows = [
        {"vrf_uid": "vrf:a", "kind": "EXPORTS", "rt": "rt1"},
        {"vrf_uid": "vrf:b", "kind": "IMPORTS", "rt": "rt1"},
    ]
    session = FakeSession(rt_rows=rt_rows)

    batch = reasoner.derive_rt_domains_batch(session)

    assert batch.source == "reasoner"
    assert batch.scope == "derived:rt-domains"
    assert len(batch.nodes) == 1
    assert batch.nodes[0].label == "RoutingDomain"
    member_of = {r.start_uid for r in batch.rels if r.rel_type == "MEMBER_OF"}
    assert member_of == {"vrf:a", "vrf:b"}
    batch.validate_registry()


def test_derive_rt_domains_batch_with_no_multi_member_components_is_an_empty_batch():
    rt_rows = [{"vrf_uid": "vrf:lonely", "kind": "IMPORTS", "rt": "rt-nobody-exports"}]
    batch = reasoner.derive_rt_domains_batch(FakeSession(rt_rows=rt_rows))
    assert batch.nodes == []
    assert batch.rels == []
    batch.validate_registry()


def test_execute_rt_domains_loads_through_the_normal_loader_and_returns_a_manifest(tmp_path):
    rt_rows = [
        {"vrf_uid": "vrf:a", "kind": "EXPORTS", "rt": "rt1"},
        {"vrf_uid": "vrf:b", "kind": "IMPORTS", "rt": "rt1"},
    ]
    session = FakeSession(rt_rows=rt_rows)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    manifest = reasoner.execute_rt_domains(session, settings)

    assert manifest.source == "reasoner"
    assert manifest.scope == "derived:rt-domains"
    assert manifest.nodes_upserted == 1
    assert manifest.nodes_created == 1
    assert manifest.rels_upserted == 2
    assert manifest.rels_created == 2
    assert not manifest.retirement_skipped
    assert not manifest.rel_retirement_skipped


# --- deriving over a named cycle --------------------------------------------------------
# `core/finalize.py` runs the derivations inside a cycle, before the label move and the
# pointer switch.


class _RecordingSession(FakeSession):
    """FakeSession that also records what each read was dispatched with."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.reads: list[tuple[str, dict[str, Any]]] = []

    def execute_read(self, work: Any, *args: Any, **kwargs: Any) -> Any:
        self.reads.append((args[0], args[1] if len(args) > 1 else {}))
        return super().execute_read(work, *args, **kwargs)


def _rt_rows() -> list[dict[str, Any]]:
    return [
        {"vrf_uid": "vrf:a", "kind": "EXPORTS", "rt": "rt1"},
        {"vrf_uid": "vrf:b", "kind": "IMPORTS", "rt": "rt1"},
    ]


def test_the_cycle_scoped_queries_select_by_version_key_instead_of_the_latest_label():
    q = reasoner.RT_EDGES_AT_CYCLE_QUERY
    assert ":Latest" not in q
    # one guard per matched node, so neither endpoint can come from another cycle
    assert q.count("collection_ts = $cts") == 2
    assert "(v:VrfInstance:Obj)" in q and "v.collection_ts = $cts" in q
    # and the retirement awareness of the :Latest forms is not lost on the way
    assert "NOT rt:Retired" in q
    assert "NOT v:Retired" in q and "r._retired_at IS NULL" in q


def test_read_topology_resolves_the_pointer_by_default_and_takes_a_cycle_when_named():
    session = _RecordingSession(rt_rows=_rt_rows(), current=9000)
    reasoner.read_topology(session)
    reasoner.read_topology(session, 4242)
    assert session.reads == [
        (reasoner.RT_EDGES_AT_CYCLE_QUERY, {"cts": 9000}),
        (reasoner.RT_EDGES_AT_CYCLE_QUERY, {"cts": 4242}),
    ]
    assert session.pointer_calls == 1  # only the omitted call touches the pointer


def test_read_topology_falls_back_to_the_live_sentinel_with_no_pointer():
    """A graph with no cycle yet reads unpinned via the live sentinel."""
    session = _RecordingSession(rt_rows=_rt_rows(), current=None)
    reasoner.read_topology(session)
    assert session.reads == [(reasoner.RT_EDGES_AT_CYCLE_QUERY, {"cts": "live"})]


def test_execute_rt_domains_reads_and_stamps_the_named_cycle(tmp_path):
    session = _RecordingSession(rt_rows=_rt_rows())
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    manifest = reasoner.execute_rt_domains(session, settings, collection_ts=4242)

    assert [q for q, _ in session.reads] == [reasoner.RT_EDGES_AT_CYCLE_QUERY]
    assert manifest.run_id.startswith("reasoner-rt-domains-4242-")
    assert {p["cts"] for _, p in session.queries if "cts" in p} == {4242}
    assert manifest.nodes_created == 1


# --- CLI: no `hst reason rt-imports` command -------------------------------------------


def test_reason_rt_imports_is_not_a_command():
    """The routes a route-target pairing implies are resolved by the readers, so
    there is nothing for a command to derive."""
    r = cli_runner.invoke(cli.app, ["reason", "rt-imports"])

    assert r.exit_code != 0
    assert "rt-imports" not in [c.name for c in cli.reason_app.registered_commands]


# --- CLI: `hst reason rt-domains` -----------------------------------------------------


def test_reason_rt_domains_cli_prints_the_manifest_line(monkeypatch, tmp_path):
    rt_rows = [
        {"vrf_uid": "vrf:a", "kind": "EXPORTS", "rt": "rt1"},
        {"vrf_uid": "vrf:b", "kind": "IMPORTS", "rt": "rt1"},
    ]
    session = FakeSession(rt_rows=rt_rows)
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None, hst_data_dir=tmp_path))
    monkeypatch.setattr(cli.dbmod, "session", lambda settings: session)

    r = cli_runner.invoke(cli.app, ["reason", "rt-domains"])

    assert r.exit_code == 0, r.output
    assert "nodes:" in r.output
    assert "rels:" in r.output
    assert "+1 new" in r.output  # the one RoutingDomain node created


def test_reason_with_no_subcommand_refuses_and_says_where_the_rules_run(monkeypatch):
    """The cabling/gateway rules delete and re-create their edges inside one run.
    Standalone, that run is the one the pointer names, so a pinned reader running
    several queries could straddle the clear. Every collection
    trigger derives them into the run it is building."""
    from hst import reasoner as cabling_reasoner

    calls = []
    monkeypatch.setattr(cabling_reasoner, "run", lambda s, ts_ms=None: calls.append(s) or [])

    r = cli_runner.invoke(cli.app, ["reason"])

    assert r.exit_code == 1
    assert "runs inside a collection run" in r.output
    assert calls == []


# --- bridge domains -----------------------------------------------------------------------


def test_bridge_components_join_same_vid_across_one_link_only():
    """802.1Q: a VID is significant per link."""
    carriage = [
        {"port_uid": "p:core1:eth0", "vlan_uid": "vlan:core1:105", "vid": 105},
        {"port_uid": "p:sw:24", "vlan_uid": "vlan:unifi:105", "vid": 105},
        {"port_uid": "p:othersite:1", "vlan_uid": "vlan:other:105", "vid": 105},
    ]
    links = [{"a": "p:core1:eth0", "z": "p:sw:24"}]
    components = reasoner.bridge_components(links, carriage)
    assert ("vlan:core1:105", "vlan:unifi:105") in components
    assert ("vlan:other:105",) in components


def test_different_vids_across_one_link_never_join():
    carriage = [
        {"port_uid": "p:a", "vlan_uid": "vlan:a:105", "vid": 105},
        {"port_uid": "p:b", "vlan_uid": "vlan:b:205", "vid": 205},
    ]
    links = [{"a": "p:a", "z": "p:b"}]
    assert reasoner.bridge_components(links, carriage) == [("vlan:a:105",), ("vlan:b:205",)]


def test_the_per_source_scope_split_reports_as_a_merge_finding():
    carriage = [
        {"port_uid": "p:core1:eth0", "vlan_uid": "vlan:core1:105", "vid": 105},
        {"port_uid": "p:sw:24", "vlan_uid": "vlan:unifi:105", "vid": 105},
    ]
    links = [{"a": "p:core1:eth0", "z": "p:sw:24"}]
    realizes = [
        {"vlan_uid": "vlan:core1:105", "vid": 105, "segment_uid": "l2seg:dc-ber-01:vlan105"},
        {"vlan_uid": "vlan:unifi:105", "vid": 105, "segment_uid": "l2seg:home:vlan105"},
    ]
    components = reasoner.bridge_components(links, carriage)
    merges = reasoner.find_segment_merges(components, realizes)
    assert [m.segments for m in merges] == [("l2seg:dc-ber-01:vlan105", "l2seg:home:vlan105")]
    assert merges[0].vids == (105,)
    assert merges[0].members == ("vlan:core1:105", "vlan:unifi:105")


def test_a_declared_segment_with_two_evidenced_islands_is_a_split():
    carriage = [
        {"port_uid": "p:a", "vlan_uid": "vlan:a:10", "vid": 10},
        {"port_uid": "p:b", "vlan_uid": "vlan:b:10", "vid": 10},
        {"port_uid": "p:c", "vlan_uid": "vlan:c:10", "vid": 10},
        {"port_uid": "p:d", "vlan_uid": "vlan:d:10", "vid": 10},
    ]
    links = [{"a": "p:a", "z": "p:b"}, {"a": "p:c", "z": "p:d"}]
    realizes = [
        {"vlan_uid": f"vlan:{x}:10", "vid": 10, "segment_uid": "l2seg:home:vlan10"}
        for x in ("a", "b", "c", "d")
    ]
    components = reasoner.bridge_components(links, carriage)
    splits = reasoner.find_segment_splits(components, realizes)
    assert len(splits) == 1
    assert splits[0].segment == "l2seg:home:vlan10"
    assert splits[0].components == (("vlan:a:10", "vlan:b:10"), ("vlan:c:10", "vlan:d:10"))


def test_members_without_carriage_evidence_never_produce_a_split():
    """A collection gap costs audit coverage, never a finding."""
    carriage = [{"port_uid": "p:a", "vlan_uid": "vlan:a:10", "vid": 10}]
    realizes = [
        {"vlan_uid": "vlan:a:10", "vid": 10, "segment_uid": "l2seg:home:vlan10"},
        {"vlan_uid": "vlan:b:10", "vid": 10, "segment_uid": "l2seg:home:vlan10"},
    ]
    components = reasoner.bridge_components([], carriage)
    assert reasoner.find_segment_splits(components, realizes) == []


# --- read_carriage/read_port_links/read_segment_realizes: pinned, no bare label ------


def test_bridge_domain_queries_are_pinned_by_version_key_not_a_label():
    for q in (
        reasoner.CARRIAGE_AT_CYCLE_QUERY,
        reasoner.PORT_LINKS_AT_CYCLE_QUERY,
        reasoner.SEGMENT_REALIZES_AT_CYCLE_QUERY,
    ):
        assert ":Latest" not in q
        assert ":Obj)" in q and ".collection_ts = $cts" in q and ".collection_ts, $cts)" not in q


def test_read_carriage_resolves_the_pointer_by_default_and_takes_a_cycle_when_named():
    session = _RecordingSession(current=9000)
    reasoner.read_carriage(session)
    reasoner.read_carriage(session, 4242)
    assert session.reads == [
        (reasoner.CARRIAGE_AT_CYCLE_QUERY, {"cts": 9000}),
        (reasoner.CARRIAGE_AT_CYCLE_QUERY, {"cts": 4242}),
    ]
    assert session.pointer_calls == 1


def test_read_port_links_and_read_segment_realizes_share_one_resolution():
    session = _RecordingSession(current=9000)
    reasoner.read_port_links(session)
    reasoner.read_segment_realizes(session)
    assert session.reads == [
        (reasoner.PORT_LINKS_AT_CYCLE_QUERY, {"cts": 9000}),
        (reasoner.SEGMENT_REALIZES_AT_CYCLE_QUERY, {"cts": 9000}),
    ]
    assert session.pointer_calls == 2
    session2 = _RecordingSession(current=9000)
    reasoner.read_port_links(session2, 9000)
    reasoner.read_segment_realizes(session2, 9000)
    assert session2.pointer_calls == 0


# --- CONNECTED_TO link speed ----------------------------------------------------------------


def test_link_speed_agreement_both_known_and_equal_gives_that_value_and_agree():
    assert reasoner.link_speed_agreement(1000, 1000) == (1000, "agree")


def test_link_speed_agreement_both_known_and_different_gives_the_minimum_and_disagree():
    assert reasoner.link_speed_agreement(1000, 100) == (100, "disagree")
    assert reasoner.link_speed_agreement(100, 1000) == (100, "disagree")


def test_link_speed_agreement_one_known_gives_that_value_and_one_side():
    assert reasoner.link_speed_agreement(1000, None) == (1000, "one-side")
    assert reasoner.link_speed_agreement(None, 1000) == (1000, "one-side")


def test_link_speed_agreement_none_known_gives_null_and_unknown():
    assert reasoner.link_speed_agreement(None, None) == (None, "unknown")


def test_build_connected_to_speed_shape():
    """Every RelRecord carries only the two derived props, an empty key (so the
    loader's MERGE matches whatever CONNECTED_TO edge(s) collection already wrote
    between the two ports, see `build_connected_to_speed`'s docstring), and the
    same (a, b) direction the row named."""
    links = [
        {"a_uid": "p:sw1:1", "a_speed": 1000, "b_uid": "p:sw2:1", "b_speed": 1000},
        {"a_uid": "p:sw1:2", "a_speed": 1000, "b_uid": "p:sw2:2", "b_speed": 100},
        {"a_uid": "p:sw1:3", "a_speed": 1000, "b_uid": "p:sw2:3", "b_speed": None},
        {"a_uid": "p:sw1:4", "a_speed": None, "b_uid": "p:sw2:4", "b_speed": None},
    ]
    rels = reasoner.build_connected_to_speed(links)
    assert [r.props for r in rels] == [
        {"speed_mbps": 1000, "speed_agreement": "agree"},
        {"speed_mbps": 100, "speed_agreement": "disagree"},
        {"speed_mbps": 1000, "speed_agreement": "one-side"},
        {"speed_mbps": None, "speed_agreement": "unknown"},
    ]
    for r, link in zip(rels, links, strict=True):
        assert r.rel_type == "CONNECTED_TO"
        assert r.start_label == "Port" and r.end_label == "Port"
        assert (r.start_uid, r.end_uid) == (link["a_uid"], link["b_uid"])
        assert r.key == {}


def test_build_connected_to_speed_output_passes_batch_registry_validation():
    links = [{"a_uid": "p:sw1:1", "a_speed": 1000, "b_uid": "p:sw2:1", "b_speed": 1000}]
    rels = reasoner.build_connected_to_speed(links)
    batch = Batch(source="reasoner", scope="derived:link-speed", nodes=[], rels=rels)
    batch.validate_registry()  # must not raise


def test_connected_to_speed_query_is_pinned_by_version_key_not_a_label_and_coalesces_speed_mbps_with_speed():
    q = reasoner.CONNECTED_TO_SPEED_AT_CYCLE_QUERY
    assert ":Latest" not in q
    assert "a.collection_ts = $cts" in q
    assert "coalesce(a.speed_mbps, a.speed)" in q
    assert "coalesce(b.speed_mbps, b.speed)" in q


def test_connected_to_speed_query_reads_each_edge_in_its_stored_direction():
    """The loader writes the speed with a directed MERGE."""
    q = reasoner.CONNECTED_TO_SPEED_AT_CYCLE_QUERY
    assert "(a:Port:Obj)-[l:CONNECTED_TO]->(b:Port)" in q
    assert "a.uid < b.uid" not in q
    assert "RETURN DISTINCT" in q


def test_a_reverse_direction_edge_yields_a_rel_in_its_stored_direction():
    """A row for an edge stored from the higher uid to the lower one keeps that
    direction through the batch, so the loader's MERGE finds the edge."""
    rows = [
        {
            "a_uid": "dev:pa4/port/eth1-104",
            "a_speed": 10000,
            "b_uid": "dev:fr2/port/eth1-104",
            "b_speed": 10000,
        }
    ]
    batch = reasoner.derive_link_speed_batch(FakeSession(link_speed_rows=rows))
    assert [(r.start_uid, r.end_uid) for r in batch.rels] == [
        ("dev:pa4/port/eth1-104", "dev:fr2/port/eth1-104")
    ]
    assert batch.rels[0].key == {}


def test_derive_link_speed_batch_reads_the_graph_and_builds_connected_to_speed_rels():
    link_speed_rows = [
        {"a_uid": "p:sw1:1", "a_speed": 1000, "b_uid": "p:sw2:1", "b_speed": 1000},
        {"a_uid": "p:sw1:2", "a_speed": 1000, "b_uid": "p:sw2:2", "b_speed": 100},
    ]
    session = FakeSession(link_speed_rows=link_speed_rows)

    batch = reasoner.derive_link_speed_batch(session)

    assert batch.source == "reasoner"
    assert batch.scope == "derived:link-speed"
    assert batch.nodes == []
    assert len(batch.rels) == 2
    assert batch.rels[0].props == {"speed_mbps": 1000, "speed_agreement": "agree"}
    assert batch.rels[1].props == {"speed_mbps": 100, "speed_agreement": "disagree"}
    batch.validate_registry()


def test_derive_link_speed_batch_with_no_links_is_an_empty_batch():
    batch = reasoner.derive_link_speed_batch(FakeSession())
    assert batch.rels == []
    batch.validate_registry()


def test_execute_link_speed_loads_through_the_normal_loader_and_returns_a_manifest(tmp_path):
    link_speed_rows = [{"a_uid": "p:sw1:1", "a_speed": 1000, "b_uid": "p:sw2:1", "b_speed": 1000}]
    session = FakeSession(link_speed_rows=link_speed_rows)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    manifest = reasoner.execute_link_speed(session, settings)

    assert manifest.source == "reasoner"
    assert manifest.scope == "derived:link-speed"
    assert manifest.rels_upserted == 1
    assert manifest.rels_created == 1


def test_execute_link_speed_reads_and_stamps_the_named_cycle(tmp_path):
    link_speed_rows = [{"a_uid": "p:a", "a_speed": 1, "b_uid": "p:b", "b_speed": 1}]
    session = _RecordingSession(link_speed_rows=link_speed_rows)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    manifest = reasoner.execute_link_speed(session, settings, collection_ts=4242)

    assert session.reads == [(reasoner.CONNECTED_TO_SPEED_AT_CYCLE_QUERY, {"cts": 4242})]
    assert manifest.run_id.startswith("reasoner-link-speed-4242-")
    assert {p["cts"] for _, p in session.queries if "cts" in p} == {4242}


def test_reason_link_speed_cli_prints_the_manifest_line(monkeypatch, tmp_path):
    link_speed_rows = [{"a_uid": "p:a", "a_speed": 1000, "b_uid": "p:b", "b_speed": 1000}]
    session = FakeSession(link_speed_rows=link_speed_rows)
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None, hst_data_dir=tmp_path))
    monkeypatch.setattr(cli.dbmod, "session", lambda settings: session)

    r = cli_runner.invoke(cli.app, ["reason", "link-speed"])

    assert r.exit_code == 0, r.output
    assert "rels:" in r.output
    assert "+1 new" in r.output


# --- wired into core/finalize.py's per-cycle derivation order ----------------------------


def test_finalize_derivations_calls_execute_link_speed_once_with_the_cycle_ts():
    """core/finalize.py `finalize_derivations` runs `execute_link_speed` right after
    `rt-domains` and before the site assignments."""
    from hst.core import finalize

    link_speed_calls: list[int | None] = []

    class _RouteTargets:
        def execute_rt_domains(
            self, session: Any, settings: Settings, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(
            self, session: Any, settings: Settings, collection_ts: int | None = None
        ) -> RunManifest:
            link_speed_calls.append(collection_ts)
            return RunManifest(
                run_id="ls", source="reasoner", scope="link-speed", rels_upserted=1, rels_created=1
            )

    class _Rules:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    settings = Settings(_env_file=None, hst_secret_key="finalize-link-speed-wiring-test-key-32-bytes")

    details = finalize.finalize_derivations(
        object(),
        settings,
        4242,
        {},
        rules=_Rules(),
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
    )

    assert link_speed_calls == [4242]
    assert "link-speed: nodes 0 (+0, -0) · rels 1 (+1, -0)" in details


# --- cable-from-fabric-circuit and the vlan-stretch check (hst/reasoner.py) ------------
#
# The rule is Cypher and its graph semantics are asserted behind the `db`
# marker (tests/test_integration_db.py); what a database-free test can pin is
# the rule's place in the list and the shape it MERGEs. The stretch check is
# pure Python over the rows its four reads return, so every observation kind
# and both warnings are asserted here.


def _circuit(
    circuit: str = "eqx:connection:c1",
    *,
    tag_a: int | None = 100,
    tag_z: int | None = 100,
    protocol: str = "dot1q",
    site_a: str | None = "fr2",
    site_z: str | None = "pa3",
) -> dict[str, Any]:
    return {
        "circuit": circuit,
        "tag_a": tag_a,
        "protocol_a": protocol,
        "tag_z": tag_z,
        "protocol_z": protocol,
        "port_a": "dev:fr2/port/eth1-49",
        "port_z": "dev:pa3/port/eth1-49",
        "device_a": "dev:fr2",
        "device_z": "dev:pa3",
        "site_a": site_a,
        "site_z": site_z,
    }


def _carriage(a: tuple[int, ...] = (100,), z: tuple[int, ...] = (100,)) -> list[dict[str, Any]]:
    return [{"port_uid": "dev:fr2/port/eth1-49", "vid": v} for v in a] + [
        {"port_uid": "dev:pa3/port/eth1-49", "vid": v} for v in z
    ]


def test_cable_from_fabric_circuit_runs_after_the_cabling_inferences_and_before_the_gateways():
    from hst import reasoner as rules

    names = [name for name, _ in rules.RULES]
    assert names.index("cable-from-last-connection") < names.index("cable-from-fabric-circuit")
    assert names.index("cable-from-fabric-circuit") < names.index("gateway-from-router-interface")


def test_cable_from_fabric_circuit_needs_both_ends_realized_and_stamps_the_circuit():
    """A half-bound circuit (one end on a cloud on-ramp, or a binding the
    loader refused) matches neither REALIZED_BY pattern and draws nothing."""
    from hst import reasoner as rules

    query = dict(rules.RULES)["cable-from-fabric-circuit"]
    assert query is not None
    assert query.count("REALIZED_BY]->(") == 2
    # an end is a FabricPort, or a Network Edge Interface whose port is on a device
    assert "[ae:A_END]->(fa)-[ra:REALIZED_BY]->(a:Port)" in query
    assert "[ze:Z_END]->(fz)-[rz:REALIZED_BY]->(z:Port)" in query
    assert "(fa:FabricPort OR (fa:Interface AND EXISTS {" in query
    assert "(fz:FabricPort OR (fz:Interface AND EXISTS {" in query
    assert "MERGE (a)-[c:CONNECTED_TO {source: 'equinix-circuit', circuit_uid: vc.uid}]->(z)" in query
    assert "c.derived = true" in query and "c.rule = 'cable-from-fabric-circuit'" in query
    assert "c.vlan_tag_a = ae.vlan_tag" in query and "c.vlan_tag_z = ze.vlan_tag" in query
    assert "vc.collection_ts = $cts" in query


def test_stretched_when_the_tag_is_equal_and_both_ports_carry_it():
    from hst import reasoner as rules

    observations, uncarried = rules.stretch_observations([_circuit()], _carriage())
    assert uncarried == 0
    assert [(o["kind"], o["vid"], o["vid_z"], o["tag_a"], o["tag_z"]) for o in observations] == [
        (rules.STRETCHED, 100, 100, 100, 100)
    ]
    assert observations[0]["site_a"] == "fr2" and observations[0]["site_z"] == "pa3"
    assert observations[0]["observed_macs"] is None


def test_translated_when_the_two_sides_carry_different_tags():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit(tag_a=100, tag_z=200)], _carriage((100,), (200,)))
    assert [(o["kind"], o["vid"], o["vid_z"]) for o in observations] == [(rules.TRANSLATED, 100, 200)]


def test_one_sided_when_only_one_port_carries_its_tag():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit()], _carriage((100,), ()))
    assert [o["kind"] for o in observations] == [rules.ONE_SIDED]
    observations, _ = rules.stretch_observations([_circuit(tag_a=100, tag_z=200)], _carriage((), (200,)))
    assert [o["kind"] for o in observations] == [rules.ONE_SIDED]


def test_port_based_for_an_untagged_circuit_once_per_vlan_both_ports_carry():
    from hst import reasoner as rules

    circuit = _circuit(tag_a=None, tag_z=None, protocol="untagged")
    observations, _ = rules.stretch_observations([circuit], _carriage((10, 20, 30), (10, 20)))
    assert [(o["kind"], o["vid"]) for o in observations] == [
        (rules.PORT_BASED, 10),
        (rules.PORT_BASED, 20),
        (rules.ONE_SIDED, 30),
    ]
    assert all(o["tag_a"] is None and o["tag_z"] is None for o in observations)


def test_a_tagged_circuit_neither_port_carries_is_counted_not_observed():
    from hst import reasoner as rules

    observations, uncarried = rules.stretch_observations([_circuit()], _carriage((), ()))
    assert observations == [] and uncarried == 1


def test_a_side_with_no_tag_on_a_tagged_circuit_reads_as_the_other_sides_tag():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit(tag_z=None)], _carriage())
    assert [(o["kind"], o["tag_a"], o["tag_z"]) for o in observations] == [(rules.STRETCHED, 100, 100)]


def test_observations_are_ordered_by_circuit_uid_regardless_of_row_order():
    from hst import reasoner as rules

    circuits = [_circuit("eqx:connection:b"), _circuit("eqx:connection:a")]
    observations, _ = rules.stretch_observations(circuits, _carriage())
    assert [o["circuit"] for o in observations] == ["eqx:connection:a", "eqx:connection:b"]


def _vlan_sites(vid: int, *sites: str, domain: str = "bd:vlan:fab0:100") -> list[dict[str, Any]]:
    return [{"bridge_domain": domain, "vid": vid, "site": s} for s in sites]


def test_a_vlan_at_two_sites_that_no_circuit_carries_warns():
    from hst import reasoner as rules

    assert rules.stretch_warnings([], _vlan_sites(100, "fr2", "pa3")) == [
        "vlan 100 exists at fr2, pa3 in one bridge domain but no circuit or link carries it "
        "(joined: fr2 | pa3)"
    ]


def test_a_translated_pair_warns_that_the_twin_keeps_them_separate():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit(tag_a=100, tag_z=200)], _carriage((100,), (200,)))
    assert rules.stretch_warnings(observations, []) == [
        "vlan 100 at fr2 is vlan 200 at pa3; the twin keeps them separate"
    ]


def test_a_stretched_pair_with_equal_tags_produces_no_warning():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit()], _carriage())
    assert rules.stretch_warnings(observations, _vlan_sites(100, "fr2", "pa3")) == []


def test_a_port_based_circuit_also_joins_the_sites():
    from hst import reasoner as rules

    circuit = _circuit(tag_a=None, tag_z=None, protocol="untagged")
    observations, _ = rules.stretch_observations([circuit], _carriage())
    assert rules.stretch_warnings(observations, _vlan_sites(100, "fr2", "pa3")) == []


def test_three_sites_joined_by_two_circuits_are_one_domain_and_a_third_unjoined_site_warns():
    from hst import reasoner as rules

    fr2_pa3 = _circuit("eqx:connection:1")
    pa3_pa4 = {
        **_circuit("eqx:connection:2", site_a="pa3", site_z="pa4"),
        "port_a": "dev:pa3/port/eth1-50",
        "port_z": "dev:pa4/port/eth1-49",
    }
    carriage = [
        *_carriage(),
        {"port_uid": "dev:pa3/port/eth1-50", "vid": 100},
        {"port_uid": "dev:pa4/port/eth1-49", "vid": 100},
    ]
    observations, _ = rules.stretch_observations([fr2_pa3, pa3_pa4], carriage)
    assert rules.stretch_warnings(observations, _vlan_sites(100, "fr2", "pa3", "pa4")) == []
    assert rules.stretch_warnings(observations, _vlan_sites(100, "fr2", "pa3", "pa4", "fr6")) == [
        "vlan 100 exists at fr2, fr6, pa3, pa4 in one bridge domain but no circuit or link carries it "
        "(joined: fr2+pa3+pa4 | fr6)"
    ]


def test_a_one_sided_observation_joins_nothing():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit()], _carriage((100,), ()))
    assert rules.stretch_warnings(observations, _vlan_sites(100, "fr2", "pa3")) == [
        "vlan 100 exists at fr2, pa3 in one bridge domain but no circuit or link carries it "
        "(joined: fr2 | pa3)"
    ]


def _cable(
    a: str = "dev:fr2/port/eth1-101",
    z: str = "dev:fr6/port/eth1-101",
    site_a: str | None = "fr2",
    site_z: str | None = "fr6",
    source: str | None = "lldp",
) -> dict[str, Any]:
    return {"a": a, "z": z, "source": source, "site_a": site_a, "site_z": site_z}


def _cable_carriage(a: tuple[int, ...] = (3103,), z: tuple[int, ...] = (3103,)) -> list[dict[str, Any]]:
    return [{"port_uid": "dev:fr2/port/eth1-101", "vid": v} for v in a] + [
        {"port_uid": "dev:fr6/port/eth1-101", "vid": v} for v in z
    ]


def _split(vid: int, *sites: str, joined: str | None = None) -> str:
    groups = joined if joined is not None else " | ".join(sites)
    return (
        f"vlan {vid} exists at {', '.join(sites)} in one bridge domain but no circuit or link carries it "
        f"(joined: {groups})"
    )


def test_a_vlan_at_two_sites_joined_only_by_a_cable_both_ends_carry_does_not_warn():
    from hst import reasoner as rules
    from hst.reasoner import vlan_stretch as vs

    joins = vs.cable_joins([_cable()], _cable_carriage())
    assert joins == [{"vid": 3103, "site_a": "fr2", "site_z": "fr6"}]
    sites = _vlan_sites(3103, "fr2", "fr6", domain="bd:vlan:fab0:3103")
    assert rules.stretch_warnings([], sites, joins) == []


def test_a_cable_whose_ends_carry_different_vlan_ids_joins_nothing():
    from hst import reasoner as rules
    from hst.reasoner import vlan_stretch as vs

    joins = vs.cable_joins([_cable()], _cable_carriage((638,), (639,)))
    assert joins == []
    sites = [
        *_vlan_sites(638, "fr2", "fr6", domain="bd:vlan:fab0:638"),
        *_vlan_sites(639, "fr2", "fr6", domain="bd:vlan:fab0:639"),
    ]
    assert rules.stretch_warnings([], sites, joins) == [_split(638, "fr2", "fr6"), _split(639, "fr2", "fr6")]


def test_a_cable_with_only_one_end_carrying_the_vlan_joins_nothing():
    from hst.reasoner import vlan_stretch as vs

    assert vs.cable_joins([_cable()], _cable_carriage((3103, 875), (875,))) == [
        {"vid": 875, "site_a": "fr2", "site_z": "fr6"}
    ]


def test_a_cable_with_no_source_an_unknown_site_or_one_site_joins_nothing():
    from hst.reasoner import vlan_stretch as vs

    for link in (
        _cable(source=None),
        _cable(source=""),
        _cable(site_z=None),
        _cable(site_a=None),
        _cable(site_z="fr2"),
    ):
        assert vs.cable_joins([link], _cable_carriage()) == [], link


def test_cable_joins_are_sorted_and_free_of_repeats():
    from hst.reasoner import vlan_stretch as vs

    links = [_cable(), _cable(source="nautobot-cable")]
    assert vs.cable_joins(links, _cable_carriage((20, 10), (10, 20))) == [
        {"vid": 10, "site_a": "fr2", "site_z": "fr6"},
        {"vid": 20, "site_a": "fr2", "site_z": "fr6"},
    ]


def test_an_equinix_circuit_link_joins_only_the_circuits_own_tag():
    """cable-from-fabric-circuit draws a CONNECTED_TO between the two trunk
    ports of a circuit."""
    from hst import reasoner as rules
    from hst.reasoner import vlan_stretch as vs

    carriage = _carriage((100, 200, 300), (100, 200, 300))
    circuit_link = _cable(
        "dev:fr2/port/eth1-49", "dev:pa3/port/eth1-49", "fr2", "pa3", source=vs.CIRCUIT_LINK_SOURCE
    )
    assert vs.cable_joins([circuit_link], carriage) == []
    sites = [
        *_vlan_sites(100, "fr2", "pa3"),
        *_vlan_sites(200, "fr2", "pa3", domain="bd:vlan:fab0:200"),
    ]
    session = _StretchSession(_stretch_rows([_circuit()], carriage, sites, links=[circuit_link]))
    report = rules.check_vlan_stretch(session, collection_ts=4242)
    assert report["warnings"] == [_split(200, "fr2", "pa3")]


def test_a_neighbour_link_on_a_circuits_port_pair_joins_nothing():
    """LLDP or CDP seen through a Fabric circuit states a cable between the
    same two trunk ports; it forwards no more VLANs than the circuit does."""
    from hst.reasoner import vlan_stretch as vs

    carriage = _carriage((100, 200), (100, 200))
    pair = ("dev:fr2/port/eth1-49", "dev:pa3/port/eth1-49")
    links = [
        _cable(*pair, "fr2", "pa3", source=vs.CIRCUIT_LINK_SOURCE),
        _cable(*reversed(pair), "pa3", "fr2", source="lldp"),
    ]
    assert vs.cable_joins(links, carriage) == []


def test_a_cable_joining_two_sites_and_a_circuit_joining_the_third_do_not_warn():
    from hst import reasoner as rules
    from hst.reasoner import vlan_stretch as vs

    observations, _ = rules.stretch_observations([_circuit()], _carriage())
    joins = vs.cable_joins([_cable()], _cable_carriage((100,), (100,)))
    assert rules.stretch_warnings(observations, _vlan_sites(100, "fr2", "fr6", "pa3"), joins) == []


def test_cables_within_each_metro_still_warn_for_a_vlan_split_between_the_metros():
    from hst import reasoner as rules
    from hst.reasoner import vlan_stretch as vs

    links = [_cable(), _cable("dev:pa3/port/eth1-101", "dev:pa4/port/eth1-101", "pa3", "pa4")]
    carriage = [
        *_cable_carriage(),
        {"port_uid": "dev:pa3/port/eth1-101", "vid": 3103},
        {"port_uid": "dev:pa4/port/eth1-101", "vid": 3103},
    ]
    sites = _vlan_sites(3103, "fr2", "fr6", "pa3", "pa4", domain="bd:vlan:fab0:3103")
    assert rules.stretch_warnings([], sites, vs.cable_joins(links, carriage)) == [
        _split(3103, "fr2", "fr6", "pa3", "pa4", joined="fr2+fr6 | pa3+pa4")
    ]


def test_check_vlan_stretch_joins_sites_over_a_cable_and_writes_nothing():
    from hst import reasoner as rules
    from hst.reasoner import vlan_stretch as vs

    assert "l.source AS source" in vs.FETCH_PORT_LINKS
    assert "l._retired_at IS NULL AND a.uid < b.uid" in vs.FETCH_PORT_LINKS
    assert "head(collect(DISTINCT coalesce(sa.code, sa.uid))) AS site_a" in vs.FETCH_PORT_LINKS
    sites = _vlan_sites(3103, "fr2", "fr6", domain="bd:vlan:fab0:3103")
    session = _StretchSession(_stretch_rows(carriage=_cable_carriage(), vlan_sites=sites, links=[_cable()]))
    report = rules.check_vlan_stretch(session, collection_ts=4242)
    assert report["warnings"] == [] and report["observations"] == []
    assert session.writes == 0


def test_mac_corroboration_counts_a_mac_seen_through_the_circuit_and_locally_at_the_far_end():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit()], _carriage())
    rows = [
        # seen at FR2 through the circuit-facing port, and locally at PA3
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee01", "port_name": "Eth1/49"},
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/7"},
        # seen at PA3 only
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee02", "port_name": "Ethernet1/8"},
        # seen at both ends but on the circuit-facing port at both: local nowhere
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee03", "port_name": "Ethernet1/49"},
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee03", "port_name": "Ethernet1/49"},
        # the other VLAN
        {"device_uid": "dev:fr2", "vlan": 200, "mac": "aabbccddee04", "port_name": "Ethernet1/49"},
        {"device_uid": "dev:pa3", "vlan": 200, "mac": "aabbccddee04", "port_name": "Ethernet1/7"},
    ]
    assert rules.observed_mac_count(observations[0], rows) == 1


def test_mac_corroboration_reads_the_far_side_vlan_of_a_translated_pair():
    from hst import reasoner as rules

    observations, _ = rules.stretch_observations([_circuit(tag_a=100, tag_z=200)], _carriage((100,), (200,)))
    rows = [
        {"device_uid": "dev:pa3", "vlan": 200, "mac": "aabbccddee05", "port_name": "Ethernet1/49"},
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee05", "port_name": "Ethernet1/3"},
    ]
    assert rules.observed_mac_count(observations[0], rows) == 1


def test_mac_rows_query_quotes_the_devices_and_selects_the_newest_run_per_device():
    from hst import reasoner as rules

    sql = rules.mac_rows_query(["dev:pa3", "dev:fr2", "dev:fr2"], 4242)
    assert "device_uid IN ('dev:fr2', 'dev:pa3')" in sql
    assert "snapshot_ts <= 4242" in sql
    assert "max(m2.snapshot_ts)" in sql
    assert "O''Brien" in rules.mac_rows_query(["dev:O'Brien"], 1)


class _StretchTx:
    def __init__(self, rows_for: Any) -> None:
        self.rows_for = rows_for
        self.queries: list[str] = []

    def run(self, query: str, **params: Any) -> _FakeReadResult:
        self.queries.append(query)
        return _FakeReadResult(self.rows_for(query))


class _StretchSession:
    def __init__(self, rows_for: Any) -> None:
        self.tx = _StretchTx(rows_for)
        self.writes = 0

    def execute_read(self, work: Any, *args: Any) -> Any:
        return work(self.tx, *args)

    def execute_write(self, work: Any) -> Any:  # pragma: no cover - the check must never write
        self.writes += 1
        raise AssertionError("the vlan-stretch check writes nothing")


def _stretch_rows(
    circuits: Any = (), carriage: Any = (), vlan_sites: Any = (), unbound: Any = (), links: Any = ()
) -> Any:
    def rows_for(query: str) -> list[dict[str, Any]]:
        if "CONNECTED_TO" in query:
            return list(links)
        if "VirtualCircuit" in query:
            return list(circuits)
        if "CARRIES]->(v:VlanInstance)" in query and "REALIZES" not in query:
            return list(carriage)
        if "BridgeDomain" in query:
            return list(vlan_sites)
        if "bound_port_uid" in query:
            return list(unbound)
        raise AssertionError(query)

    return rows_for


def test_check_vlan_stretch_reads_five_queries_pinned_to_the_run_and_writes_nothing():
    from hst import reasoner as rules

    session = _StretchSession(_stretch_rows([_circuit()], _carriage(), _vlan_sites(100, "fr2", "pa3")))
    report = rules.check_vlan_stretch(session, collection_ts=4242)
    assert len(session.tx.queries) == 5
    assert all(".collection_ts = $cts" in q and ".collection_ts, $cts)" not in q for q in session.tx.queries)
    assert session.writes == 0
    assert [o["kind"] for o in report["observations"]] == [rules.STRETCHED]
    assert report["warnings"] == [] and report["unbound_ports"] == [] and report["uncarried"] == 0


def test_check_vlan_stretch_reports_a_refused_port_binding_as_a_warning():
    from hst import reasoner as rules

    unbound = [{"fabric_port": "eqx:port:p1", "port_uid": "dev:fr2/port/eth1-99"}]
    report = rules.check_vlan_stretch(_StretchSession(_stretch_rows(unbound=unbound)), collection_ts=1)
    assert report["unbound_ports"] == unbound
    assert report["warnings"] == [
        "equinix port binding refused: eqx:port:p1 names port dev:fr2/port/eth1-99, which is not in this run"
    ]


def test_check_vlan_stretch_counts_macs_from_the_side_store_when_given_one(tmp_path):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst import reasoner as rules
    from hst.core import sidestore

    rows = [
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/49"},
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/7"},
    ]
    sidestore.write_table(tmp_path, "mac", "nxos", "fr2", "run-1", rows[:1], 4242)
    sidestore.write_table(tmp_path, "mac", "nxos", "pa3", "run-1", rows[1:], 4242)
    session = _StretchSession(_stretch_rows([_circuit()], _carriage()))
    report = rules.check_vlan_stretch(session, collection_ts=4242, sidestore_dir=tmp_path)
    assert report["observations"][0]["observed_macs"] == 1


def test_check_vlan_stretch_survives_a_store_with_no_mac_table(tmp_path):
    from hst import reasoner as rules

    session = _StretchSession(_stretch_rows([_circuit()], _carriage()))
    report = rules.check_vlan_stretch(session, collection_ts=4242, sidestore_dir=tmp_path / "absent")
    assert report["observations"][0]["observed_macs"] is None


def test_finalize_derivations_records_the_stretch_findings_and_names_the_warnings():
    """core/finalize.py runs the check after the derivations: the observations
    and warnings land in the findings sink for the manifest, the warnings
    join the detail lines the Runs page shows, and an estate with nothing to
    report adds no line at all."""
    from hst.core import finalize

    class _RouteTargets:
        def execute_rt_domains(
            self, session: Any, settings: Settings, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(
            self, session: Any, settings: Settings, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="ls", source="reasoner", scope="link-speed")

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    class _Rules:
        def __init__(self, report: dict[str, Any]) -> None:
            self.report = report
            self.calls: list[tuple[int, Any]] = []

        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

        def check_vlan_stretch(self, session: Any, *, collection_ts: int, sidestore_dir: Any = None) -> dict:
            self.calls.append((collection_ts, sidestore_dir))
            return self.report

    settings = Settings(_env_file=None, hst_secret_key="finalize-vlan-stretch-wiring-test-key-32-bytes")
    observation = {
        "circuit": "eqx:connection:c1",
        "kind": "translated",
        "vid": 100,
        "vid_z": 200,
        "tag_a": 100,
        "tag_z": 200,
        "port_a": "dev:fr2/port/eth1-49",
        "port_z": "dev:pa3/port/eth1-49",
        "site_a": "fr2",
        "site_z": "pa3",
    }
    warning = "vlan 100 at fr2 is vlan 200 at pa3; the twin keeps them separate"
    rules = _Rules(
        {"observations": [observation], "warnings": [warning], "unbound_ports": [], "uncarried": 0}
    )
    findings = finalize.RunFindings()

    details = finalize.finalize_derivations(
        object(),
        settings,
        4242,
        {},
        rules=rules,
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
        findings=findings,
    )

    assert rules.calls == [(4242, settings.sidestore_dir)]
    assert details[:3] == [
        "reasoner: no rules fired",
        "rt-domains: nodes 0 (+0, -0) · rels 0 (+0, -0)",
        "link-speed: nodes 0 (+0, -0) · rels 0 (+0, -0)",
    ]
    assert (
        details[3]
        == "vlan-stretch: 1 observation(s), 1 warning(s), 0 refused binding(s), 0 uncarried circuit(s)"
    )
    assert details[4] == f"warning: {warning}"
    assert findings.stretch_observations == [observation]
    assert findings.warnings == [warning]

    quiet = _Rules({"observations": [], "warnings": [], "unbound_ports": [], "uncarried": 0})
    details = finalize.finalize_derivations(
        object(), settings, 4242, {}, rules=quiet, route_targets=_RouteTargets(), cycle=_Cycle()
    )
    assert [line.split(":")[0] for line in details] == ["reasoner", "rt-domains", "link-speed"]


def test_finalize_derivations_records_the_rule_warnings():
    from hst.core import finalize

    class _RouteTargets:
        def execute_rt_domains(
            self, session: Any, settings: Settings, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(
            self, session: Any, settings: Settings, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="ls", source="reasoner", scope="link-speed")

    class _Rules:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return [
                {
                    "rule": "fabric-port-from-description",
                    "edges": 0,
                    "conflicts": 1,
                    "ambiguous": 0,
                    "warnings": ["w"],
                }
            ]

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    settings = Settings(_env_file=None, hst_secret_key="finalize-rule-warnings-test-key-32-bytes!!!")
    findings = finalize.RunFindings()
    details = finalize.finalize_derivations(
        object(),
        settings,
        4242,
        {},
        rules=_Rules(),
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
        findings=findings,
    )
    assert details[0] == "reasoner: fabric-port-from-description: 0 (conflicts: 1, ambiguous: 0)"
    speed = next(i for i, line in enumerate(details) if line.startswith("link-speed:"))
    assert details[speed + 1] == "warning: w"
    assert findings.warnings == ["w"]
