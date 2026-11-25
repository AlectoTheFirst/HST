"""The IPAdmin register against Neo4j: the annotation writes the register
properties on the run's prefixes, and a run whose import cannot be read keeps
none, while another run keeps its own."""

from __future__ import annotations

import os

import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver
from tests.test_ipam import EXPORT

from hst.app.crypto import generate_key
from hst.collectors.util import GraphBuilder
from hst.core import ipam
from hst.core import uid as uidmod
from hst.core.config import Settings
from hst.core.loader import load

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

RUN_A, RUN_B = 7_380_000_001_000, 7_380_000_002_000


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        s.run("MATCH (n:Obj) WHERE n._scope = 'test:ipam' DETACH DELETE n").consume()
        yield s
        s.run("MATCH (n:Obj) WHERE n._scope = 'test:ipam' DETACH DELETE n").consume()


def _batch(carried: bool = False):
    b = GraphBuilder()
    for anchor in ("vrf:a", "vrf:b"):
        props = {"cidr": "10.1.2.0/24"}
        if carried:
            props["ipam_cidr"] = "10.1.2.0/24"
        b.node("Prefix", uidmod.prefix(anchor, "10.1.2.0/24"), **props)
    return b.batch("test", "test:ipam")


def test_ipam_annotate_writes_and_clears_the_register_on_neo4j(session, tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    ipam.import_export(settings, tmp_path / "export.csv", EXPORT)
    load(session, _batch(), ts_ms=RUN_A, run_id="ipam-a", collection_ts=RUN_A)
    report = ipam.annotate(session, settings, collection_ts=RUN_A)
    assert report is not None and report["written"] == 2
    rows = session.run(
        "MATCH (p:Prefix) WHERE p.collection_ts = $cts RETURN p.ipam_cidr AS cidr, p.ipam_vlan AS vlan",
        cts=RUN_A,
    ).data()
    assert rows == [{"cidr": "10.1.2.0/24", "vlan": 120}] * 2

    load(session, _batch(carried=True), ts_ms=RUN_B, run_id="ipam-b", collection_ts=RUN_B)
    other = settings.model_copy(update={"hst_secret_key": "another-ipam-db-key-long-enough-32b!!"})
    with pytest.raises(Exception):  # noqa: B017 - the read error of a sealed file under another key
        ipam.annotate(session, other, collection_ts=RUN_B)
    left = session.run(
        "MATCH (p:Prefix) WHERE p.collection_ts IN [$a, $b] AND p.ipam_cidr IS NOT NULL "
        "RETURN p.collection_ts AS cts, count(*) AS n",
        a=RUN_A,
        b=RUN_B,
    ).data()
    assert left == [{"cts": RUN_A, "n": 2}]


def test_the_register_queries_report_contexts_and_vlan_mismatches(session):
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}
    b = GraphBuilder()
    prefixes = {}
    for anchor in ("vrf:a", "vrf:b"):
        prefixes[anchor] = b.node(
            "Prefix",
            uidmod.prefix(anchor, "10.1.2.0/24"),
            cidr="10.1.2.0/24",
            l3dom=anchor,
            ipam_cidr="10.1.2.0/24",
            ipam_vlan=120,
        )
    svi = b.node("Interface", "dev:ipam/if/vlan130", name="Vlan130", kind="svi")
    dev = b.node("Device", "dev:ipam", hostname="ipam-sw", role="switch")
    b.rel("ON", "Interface", svi, "Device", dev)
    ip = b.node("IpAddress", "ip:vrf:a:10.1.2.1", ip="10.1.2.1")
    b.rel("HAS_IP", "Interface", svi, "IpAddress", ip)
    b.rel("IN", "IpAddress", ip, "Prefix", prefixes["vrf:a"])
    vlan = b.node("VlanInstance", "vlan:ipam:130", vid=130)
    b.rel("BOUND_TO", "Interface", svi, "VlanInstance", vlan)
    load(session, b.batch("test", "test:ipam"), ts_ms=RUN_A, run_id="ipam-q", collection_ts=RUN_A)
    register = session.run(cypher["ipam-register"], snap=RUN_A).data()
    assert [(r["prefix"], r["contexts"]) for r in register] == [("10.1.2.0/24", 2)]
    mismatch = session.run(cypher["ipam-vlan-mismatch"], snap=RUN_A).data()
    assert [(r["register_vlan"], r["svi_vlans"]) for r in mismatch] == [(120, [130])]
