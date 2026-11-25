"""Every reader resolves the route-target routes from the IMPORTS/EXPORTS/ORIGINATES
facts of the run it reads (core/reasoner.py `RT_IMPORTED_ROUTES`)."""

from __future__ import annotations

import importlib
import os

import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver

from hst import path as pathmod
from hst.applications import generator_tools
from hst.collectors.util import GraphBuilder
from hst.core import uid as uidmod
from hst.core.loader import load
from hst.path.session import CycleSession
from hst.twin_tools import routing

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

trace = importlib.import_module("hst.path.trace")

SCOPE = "test:rt-import"
RUN, OTHER = 7_390_000_001_000, 7_390_000_002_000
DEVICE = "dev:rt-import"
A, B, C, D = (uidmod.vrf(DEVICE, name) for name in ("a", "b", "c", "d"))


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        s.run("MATCH (n:Obj) WHERE n._scope = $scope DETACH DELETE n", scope=SCOPE).consume()
        yield s
        s.run("MATCH (n:Obj) WHERE n._scope = $scope DETACH DELETE n", scope=SCOPE).consume()


def _batch(extra_prefix: bool = False):
    """a exports rt1 and rt2 and imports rt1 itself; b imports rt1 and rt2; c
    imports rt1 and exports rt3; d imports rt3. Each of a and c originates one
    prefix."""
    b = GraphBuilder()
    b.node("Device", DEVICE, hostname="rt-import", role="router")
    for vrf, name in ((A, "a"), (B, "b"), (C, "c"), (D, "d")):
        b.node("VrfInstance", vrf, name=name, anchor=DEVICE)
    rts = {
        value: b.node("RouteTarget", uidmod.route_target(value), value=value)
        for value in ("rt1", "rt2", "rt3")
    }
    for vrf, kind, value in (
        (A, "EXPORTS", "rt1"),
        (A, "EXPORTS", "rt2"),
        (A, "IMPORTS", "rt1"),
        (B, "IMPORTS", "rt1"),
        (B, "IMPORTS", "rt2"),
        (C, "IMPORTS", "rt1"),
        (C, "EXPORTS", "rt3"),
        (D, "IMPORTS", "rt3"),
    ):
        b.rel(kind, "VrfInstance", vrf, "RouteTarget", rts[value])
    cidrs = {A: ["10.1.0.0/24", *(["10.9.0.0/24"] if extra_prefix else [])], C: ["10.3.0.0/24"]}
    for vrf, values in cidrs.items():
        for cidr in values:
            prefix = b.node("Prefix", uidmod.prefix(vrf, cidr), cidr=cidr, af=4, anchor=vrf)
            b.rel("ORIGINATES", "VrfInstance", vrf, "Prefix", prefix, proto="connected")
    return b.batch("test", SCOPE)


def _routes(session, vrf):
    rows = pathmod._read(CycleSession(session, RUN), trace._ROUTES_QUERY, vrf=vrf)
    return sorted((r["cidr"], r["kind"], r["derived"], r["via_rt"], r["next_hop"]) for r in rows)


def test_the_route_target_routes_are_resolved_where_read_and_never_written(session):
    load(session, _batch(), ts_ms=RUN, run_id="rt-import-1", collection_ts=RUN)
    # another kept run, where a originates one more prefix: never read into RUN
    load(session, _batch(extra_prefix=True), ts_ms=OTHER, run_id="rt-import-2", collection_ts=OTHER)

    learned = session.run(
        "MATCH (v:VrfInstance)-[r:LEARNED_ROUTE]->() WHERE v._scope = $scope RETURN count(r) AS n",
        scope=SCOPE,
    ).single()["n"]
    assert learned == 0

    # both route targets that carry a's prefix to b, sorted into one row
    assert _routes(session, B) == [("10.1.0.0/24", "LEARNED_ROUTE", "rt-import", "rt1,rt2", None)]
    # c receives a's prefix and nothing of its own
    assert _routes(session, C) == [
        ("10.1.0.0/24", "LEARNED_ROUTE", "rt-import", "rt1", None),
        ("10.3.0.0/24", "ORIGINATES", None, None, None),
    ]
    # one hop: d receives c's own prefix, never the one c only learned from a
    assert _routes(session, D) == [("10.3.0.0/24", "LEARNED_ROUTE", "rt-import", "rt3", None)]
    # a imports a route target it exports itself and receives nothing from itself
    assert _routes(session, A) == [("10.1.0.0/24", "ORIGINATES", None, None, None)]

    table = pathmod._read(CycleSession(session, RUN), generator_tools._TABLE_ROUTES, uid=B)
    assert [(r["table_uid"], r["cidr"], r["next_hop"]) for r in table] == [(B, "10.1.0.0/24", None)]

    found = pathmod._read(
        CycleSession(session, RUN),
        routing._PREFIX_ROUTES_QUERY,
        kinds=["LEARNED_ROUTE"],
        cidrs=["10.1.0.0/24"],
        starts=None,
        limit=10,
    )
    assert sorted((r["context_uid"], r["edge"], r["derived"], r["protocol"]) for r in found) == [
        (B, "LEARNED_ROUTE", "rt-import", "bgp"),
        (C, "LEARNED_ROUTE", "rt-import", "bgp"),
    ]


def test_a_run_written_with_rt_import_edges_reads_each_route_once(session):
    load(session, _batch(), ts_ms=RUN, run_id="rt-import-1", collection_ts=RUN)
    session.run(
        "MATCH (v:VrfInstance:Obj {uid: $b, collection_ts: $cts}) "
        "MATCH (p:Prefix:Obj {uid: $p, collection_ts: $cts}) "
        "CREATE (v)-[:LEARNED_ROUTE {derived: 'rt-import', via_rt: 'rt1,rt2', protocol: 'bgp', "
        "collection_ts: $cts, _scope: 'derived:rt'}]->(p)",
        b=B,
        p=uidmod.prefix(A, "10.1.0.0/24"),
        cts=RUN,
    ).consume()

    assert _routes(session, B) == [("10.1.0.0/24", "LEARNED_ROUTE", "rt-import", "rt1,rt2", None)]
    table = pathmod._read(CycleSession(session, RUN), generator_tools._TABLE_ROUTES, uid=B)
    assert len(table) == 1
    found = pathmod._read(
        CycleSession(session, RUN),
        routing._PREFIX_ROUTES_QUERY,
        kinds=["LEARNED_ROUTE"],
        cidrs=["10.1.0.0/24"],
        starts=None,
        limit=10,
    )
    assert sorted(r["context_uid"] for r in found) == [B, C]
