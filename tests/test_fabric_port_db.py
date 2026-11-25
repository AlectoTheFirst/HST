"""The fabric-port-from-description rule against Neo4j: it marks a Fabric port
two port descriptions name, and a later run of the rules clears the marker."""

from __future__ import annotations

import os

import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver

from hst import reasoner
from hst.collectors.util import GraphBuilder
from hst.core.loader import load

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

KEY = 7_370_000_001_000
FP = "eqx:fpdb:port:sec"


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        s.run("MATCH (n:Obj) WHERE n.collection_ts = $key DETACH DELETE n", key=KEY).consume()
        yield s
        s.run("MATCH (n:Obj) WHERE n.collection_ts = $key DETACH DELETE n", key=KEY).consume()


def test_the_fabric_port_rule_marks_and_clears_an_unbound_fabric_port(session):
    b = GraphBuilder()
    b.node("FabricPort", FP, name="ACME-XX1-EXT-SEC-01", cross_connect_ids=["21000002"])
    for name in ("eth1-3", "eth1-4"):
        b.node(
            "Port", f"dev:fpdb/port/{name}", name=name, description="TO EQUINIX FABRIC - ACME-XX1-EXT-SEC-01"
        )
    load(session, b.batch("test", "test:fpdb"), ts_ms=KEY, run_id="fpdb", collection_ts=KEY)
    reasoner.run(session, ts_ms=KEY + 100, collection_ts=KEY)
    row = session.run(
        "MATCH (fp:FabricPort {uid: $uid}) RETURN fp.binding_issue AS issue, fp.binding_ports AS ports",
        uid=FP,
    ).single()
    assert (row["issue"], row["ports"]) == ("several-ports", ["dev:fpdb/port/eth1-3", "dev:fpdb/port/eth1-4"])

    session.run("MATCH (p:Port {uid: 'dev:fpdb/port/eth1-4'}) REMOVE p.description").consume()
    reasoner.run(session, ts_ms=KEY + 200, collection_ts=KEY)
    row = session.run(
        "MATCH (fp:FabricPort {uid: $uid}) "
        "RETURN fp.binding_issue AS issue, EXISTS { (fp)-[:REALIZED_BY]->(:Port) } AS realized",
        uid=FP,
    ).single()
    assert (row["issue"], row["realized"]) == (None, True)
