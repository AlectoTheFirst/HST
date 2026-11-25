"""The /api/sdwan reads against Neo4j: every read compiles, and the topology of
a branch and of a hub answers collector-shaped VeloCloud data."""

from __future__ import annotations

import contextlib
import os
from types import SimpleNamespace
from typing import Any

import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver

from hst.collectors.velocloud import normalize_velocloud
from hst.core.loader import load

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

KEY = 7_360_000_001_000
ENT = "ent-1"


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        yield s
        _cleanup(s)


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n.collection_ts IN $keys DETACH DELETE n", keys=[KEY, KEY + 1]).consume()


def test_every_sdwan_read_compiles(session):
    from hst.app.routes import sdwan

    reads = {name: getattr(sdwan, name) for name in dir(sdwan) if name.startswith("_") and name.isupper()}
    reads = {n: c for n, c in reads.items() if isinstance(c, str) and "MATCH" in c}
    assert len(reads) >= 10
    failures = []
    for name, cypher in sorted(reads.items()):
        params = {"snap": 0, "edge": "x", "hubs": [], "sites": [], "devices": [], "branches": []}
        try:
            session.run("EXPLAIN " + cypher, parameters=params).consume()
        except Exception as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failures, "\n".join(failures)


def _topology(session, monkeypatch, edge: str) -> dict[str, Any]:
    from hst.app.routes import sdwan

    @contextlib.contextmanager
    def cm(settings):
        yield session

    monkeypatch.setattr(sdwan, "_session", cm)
    monkeypatch.setattr(sdwan, "_snap", lambda s, settings: KEY)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=None)))
    return sdwan.get_topology(request, edge)  # type: ignore[arg-type]


def test_the_topology_of_a_branch_and_a_hub_answers_collector_shaped_data(session, monkeypatch):
    from tests.enterprise.test_velocloud import _overlay_raw

    load(session, normalize_velocloud(_overlay_raw()), ts_ms=KEY, run_id="sd-vco", collection_ts=KEY)
    branch = _topology(session, monkeypatch, f"vco:{ENT}:edge:e-br")
    assert branch["edge"]["name"] == "branch-1"
    kinds = {t["peer_kind"] for t in branch["tunnels"]}
    assert "hub" in kinds and "gateway" in kinds
    assert [h["name"] for h in branch["hubs"]] == ["hub-1"]
    hub = _topology(session, monkeypatch, f"vco:{ENT}:edge:e-hub")
    assert hub["edge"]["name"] == "hub-1"
    assert "branch" in {t["peer_kind"] for t in hub["tunnels"]}


def test_two_runs_give_one_candidate_row_per_tunnel_and_the_pair_finds_the_hub(session):
    from tests.enterprise.test_velocloud import _overlay_raw

    from hst.path.gates import sdwan

    for key in (KEY, KEY + 1):
        load(
            session, normalize_velocloud(_overlay_raw()), ts_ms=key, run_id=f"sd-vco-{key}", collection_ts=key
        )
    # a segment that a tunnel from the branch to the hub carries
    seg = session.run(
        "MATCH (t:Tunnel)-[:CARRIES]->(s:SdwanSegment) "
        "WHERE t.collection_ts = $key AND t.uid STARTS WITH $prefix AND t.uid CONTAINS '~link:' "
        "RETURN s.uid AS uid ORDER BY uid LIMIT 1",
        key=KEY + 1,
        prefix=f"vco:{ENT}:path:e-br:",
    ).single()["uid"]
    rows = session.run(
        sdwan._CANDIDATE_TUNNELS_QUERY, dev=f"vco:{ENT}:edge:e-br", seg=seg, snap=KEY + 1
    ).data()
    uids = [r["uid"] for r in rows]
    assert uids and len(uids) == len(set(uids))
    hub_rows = [r for r in rows if "~link:" in r["uid"]]
    assert hub_rows and all(r["far_dev"] == f"vco:{ENT}:edge:e-hub" for r in hub_rows)
    for r in hub_rows:
        peer = session.run(
            "MATCH (t:Tunnel {uid: $uid}) WHERE t.collection_ts = $key "
            "MATCH (p:Tunnel)-[:ENDPOINT]->(:Interface)-[:ON]->(d:Device) "
            "WHERE p.pair = t.pair AND p <> t AND p.collection_ts = $key RETURN d.uid AS dev",
            uid=r["uid"],
            key=KEY + 1,
        ).data()
        assert [p["dev"] for p in peer] == [f"vco:{ENT}:edge:e-hub"]


def test_a_tunnel_to_a_shared_nat_address_reads_one_far_edge(session):
    """Two WAN links hold the same address after NAT, each on its own IpAddress
    node. The tunnel ends on one of them: the gate reads that edge only."""
    from hst.collectors.util import GraphBuilder
    from hst.path.gates import tunnel

    b = GraphBuilder()
    a_dev = b.node("Device", "dev:nat-a", hostname="nat-a", role="sdwan-edge")
    a_if = b.node("Interface", "dev:nat-a/if/GE2", name="GE2")
    b.rel("ON", "Interface", a_if, "Device", a_dev)
    t = b.node("Tunnel", "vco:nat:path:a:l1~link:b1:l2", name="a to b1", encap="velocloud-vcmp")
    b.rel("ENDPOINT", "Tunnel", t, "Interface", a_if)
    for name in ("b1", "b2"):
        dev = b.node("Device", f"dev:nat-{name}", hostname=f"nat-{name}", role="sdwan-edge")
        iface = b.node("Interface", f"dev:nat-{name}/if/GE2", name="GE2")
        b.rel("ON", "Interface", iface, "Device", dev)
        link = b.node("WanLink", f"wan:nat-{name}", name="dia", kind="dia")
        b.rel("ON", "WanLink", link, "Interface", iface)
        ip = b.node("IpAddress", f"ip:nat-{name}:198.51.100.2", ip="198.51.100.2")
        b.rel("HAS_IP", "WanLink", link, "IpAddress", ip)
        if name == "b1":
            b.rel("TERMINATES_ON", "Tunnel", t, "IpAddress", ip)
    load(session, b.batch("test", "test:nat"), ts_ms=KEY, run_id="sd-nat", collection_ts=KEY)
    rows = session.run(tunnel._CANDIDATES, if_uid="dev:nat-a/if/GE2", snap=KEY).data()
    assert {r["remote_device_uid"] for r in rows} == {"dev:nat-b1"}
