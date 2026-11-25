"""Tier 3 against a scratch Neo4j: each query seeks on `obj_uid_cts` and matches the Tier 1 counts."""

import os
from typing import Any

import pytest
from tests.hst.conftest import drop_runs, fixture_batches, load_runs

from hst.map import tier3
from hst.map.tiers import bootstrap
from hst.map.tiers.fold import Parent, fold
from hst.map.tiers.schemas import COUNTS

RUN = 4_500_000_000_000

pytestmark = pytest.mark.db


def _first_leaf(plan: Any) -> Any:
    while plan.get("children"):
        plan = plan["children"][0]
    return plan


def _operators(plan: Any) -> list[str]:
    out = [plan["operatorType"]]
    for child in plan.get("children") or []:
        out += _operators(child)
    return out


@pytest.fixture(scope="module")
def loaded(neo4j_session: Any) -> Any:
    load_runs(neo4j_session, [RUN], lambda run: fixture_batches())
    yield neo4j_session
    drop_runs(neo4j_session, [RUN])


@pytest.mark.parametrize("query", [*tier3.queries(), *bootstrap.queries()])
def test_every_per_device_query_starts_with_a_seek_on_the_uid_constraint(loaded: Any, query: str) -> None:
    summary = loaded.run("EXPLAIN " + query, uids=["dev:x"], cts=RUN, reserved=[]).consume()
    leaf = _first_leaf(summary.plan)
    assert leaf["operatorType"].startswith("NodeUniqueIndexSeek"), (leaf["operatorType"], query)
    assert "uid, collection_ts" in str(leaf.get("args", {}).get("Details", "")), leaf
    # no branch of the plan, an Apply's right-hand side included, scans a label
    # or the whole store across the retained runs
    scans = [op for op in _operators(summary.plan) if op.startswith(("NodeByLabelScan", "AllNodesScan"))]
    assert not scans, (scans, query)


def test_tier3_lists_the_objects_tier1_counts(loaded: Any) -> None:
    folded = fold(loaded, RUN, Parent(None), None)
    for row in folded.tables["render_t1"]:
        found = tier3.read(loaded, row["uid"], RUN)
        got = {name: len(found["categories"].get(name, [])) for name in COUNTS}
        assert got == {name: row[name] for name in COUNTS}, row["uid"]
    fgt = tier3.read(loaded, "dev:fra01-fgt-01", RUN)
    assert {r["label"] for r in fgt["categories"]["n_rules"]} == {"FwRule"}
    assert all(r["uid"] and r["label"] for rows in fgt["categories"].values() for r in rows)
    assert len(fgt["contexts"]) == row_count(folded, "dev:fra01-fgt-01", "n_contexts")


def test_the_fold_gives_a_device_with_clients_a_segment_and_tier3_lists_them(loaded: Any) -> None:
    folded = fold(loaded, RUN, Parent(None), None)
    segments = [r for r in folded.tables["render_t2_segments"] if r["device_uid"] == "dev:leaf101"]
    assert len(segments) == 1
    segment = segments[0]
    assert segment["uid"] == "dev:leaf101/segment/none"
    assert segment["prefix"] == "10.0.250.0/29"
    assert segment["client_count"] == 1
    assert segment["tile"] == next(
        r["block_uid"] for r in folded.tables["render_t1"] if r["uid"] == "dev:leaf101"
    )
    assert "dev:leaf101" in folded.estate.segment_devices
    clients = tier3.segment_clients(loaded, "dev:leaf101", segment["bridge_domain_uid"], RUN)
    assert [(c["name"], c["ip"], c["mac"], c["port"]) for c in clients] == [
        ("cpfw01-inside", ["10.0.250.10"], "00:1c:7f:aa:bb:01", "ethernet1/1")
    ]
    assert tier3.segment_clients(loaded, "dev:leaf101", "bd:none-such", RUN) == []


def row_count(folded: Any, uid: str, column: str) -> int:
    return next(r[column] for r in folded.tables["render_t1"] if r["uid"] == uid)


def test_tier3_opens_its_own_session_from_the_settings(loaded: Any) -> None:
    from hst.core.config import Settings

    settings = Settings(
        _env_file=None,
        neo4j_uri=os.environ["NEO4J_TEST_URI"],
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
    )
    found = tier3.device(settings, "dev:leaf101", RUN)
    assert len(found["categories"]["n_ports"]) == 2


TUNNEL_RUN = 4_500_000_100_000
A, B = "dev:fra01-core-01", "dev:fra01-core-02"


def _tunnels(batch: Any) -> None:
    from hst.core.model import NodeRecord, RelRecord

    if not any(n.uid == A for n in batch.nodes):
        return
    for k, encap in enumerate(("ipsec", "ipsec", "gre")):
        uid = f"tun:{encap}:{A}~{B}:{k}"
        batch.nodes.append(NodeRecord(label="Tunnel", uid=uid, props={"encap": encap}))
        for kind, end in (("ENDPOINT", A), ("TERMINATES_ON", B)):
            batch.rels.append(
                RelRecord(type=kind, start_label="Tunnel", start_uid=uid, end_label="Device", end_uid=end)
            )


def test_a_site_with_3_tunnels_of_2_transports_has_one_edge_and_the_transports_in_tier3(
    neo4j_session: Any,
) -> None:
    load_runs(neo4j_session, [TUNNEL_RUN], lambda run: fixture_batches(_tunnels))
    try:
        folded = fold(neo4j_session, TUNNEL_RUN, Parent(None), None)
        edges = [e for e in folded.tables["render_t1_edges"] if {e["a_uid"], e["b_uid"]} == {A, B}]
        assert [e["tunnel_count"] for e in edges] == [3]
        found = tier3.read(neo4j_session, A, TUNNEL_RUN)
        assert sorted(t["encap"] for t in found["tunnels"]) == ["gre", "ipsec", "ipsec"]
        assert {t["other"] for t in found["tunnels"]} == {B}
    finally:
        drop_runs(neo4j_session, [TUNNEL_RUN])


def test_the_interface_facts_join_the_port_and_the_interface_both_ways(loaded: Any) -> None:
    by_port = tier3.interface(loaded, "dev:fra01-fgt-01/port/port1", RUN)
    by_interface = tier3.interface(loaded, "dev:fra01-fgt-01/if/port1", RUN)
    assert by_port is not None and by_interface is not None
    assert by_port["device_uid"] == by_interface["device_uid"] == "dev:fra01-fgt-01"
    assert by_port["interface"] == by_interface["interface"] and by_port["port"] == by_interface["port"]
    assert by_port["name"] and "collection_ts" not in (by_port["interface"] or {})
    assert (by_port["label"], by_interface["label"]) == ("Port", "Interface")
    assert tier3.interface(loaded, "dev:fra01-fgt-01", RUN) is None


VLAN_RUN = 4_500_000_200_000
PORT = f"{A}/port/eth0"


def _subinterfaces(batch: Any) -> None:
    from hst.core.model import NodeRecord, RelRecord

    if not any(n.uid == A for n in batch.nodes):
        return
    batch.nodes.append(NodeRecord(label="Port", uid=PORT, props={"name": "eth0"}))
    batch.rels.append(RelRecord(type="ON", start_label="Port", start_uid=PORT, end_label="Device", end_uid=A))
    for k, name in enumerate(("eth0.105", "eth0", "eth0.10")):
        uid, ip = f"{A}/if/{name}", f"ip:test:10.0.{k}.1"
        batch.nodes.append(NodeRecord(label="Interface", uid=uid, props={"name": name}))
        batch.nodes.append(NodeRecord(label="IpAddress", uid=ip, props={"ip": f"10.0.{k}.1", "af": 4}))
        for kind, label, end in (
            ("REALIZED_BY", "Port", PORT),
            ("ON", "Device", A),
            ("HAS_IP", "IpAddress", ip),
        ):
            batch.rels.append(
                RelRecord(type=kind, start_label="Interface", start_uid=uid, end_label=label, end_uid=end)
            )


def test_the_facts_of_a_port_realizing_3_interfaces_are_one_record_named_after_the_port(
    neo4j_session: Any,
) -> None:
    load_runs(neo4j_session, [VLAN_RUN], lambda run: fixture_batches(_subinterfaces))
    try:
        params = {"uids": [PORT], "cts": VLAN_RUN, "reserved": []}
        assert len(neo4j_session.run(tier3.INTERFACE, **params).data()) == 1
        facts = tier3.interface(neo4j_session, PORT, VLAN_RUN)
        assert facts is not None and facts["name"] == "eth0" and facts["device_uid"] == A
        assert facts["interfaces"] == ["eth0", "eth0.10", "eth0.105"]
        assert (facts["interface"] or {}).get("uid") == f"{A}/if/eth0"
        assert facts["addresses"] == ["ip:test:10.0.0.1", "ip:test:10.0.1.1", "ip:test:10.0.2.1"]
        sub = tier3.interface(neo4j_session, f"{A}/if/eth0.105", VLAN_RUN)
        assert sub is not None and sub["name"] == "eth0.105" and sub["interfaces"] == ["eth0.105"]
        assert (sub["port"] or {}).get("uid") == PORT and sub["addresses"] == ["ip:test:10.0.0.1"]
    finally:
        drop_runs(neo4j_session, [VLAN_RUN])
