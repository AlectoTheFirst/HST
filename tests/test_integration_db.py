"""The tests delete the data of the NEO4J_TEST_URI database.

NEO4J_TEST_URI=bolt://localhost:7699 NEO4J_TEST_PASSWORD=... pytest -m db
"""

import os
from pathlib import Path
from typing import Any

import pytest

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.fixtures import load_fixture
from hst.core.identity import MemoryResolver
from hst.core.loader import load
from hst.path import CycleSession

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mini-dc.yaml"
ENTERPRISE_FIXTURE = Path(__file__).parents[1] / "fixtures" / "mini-enterprise.yaml"
URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]


def _refuse_if_live() -> None:
    """The guard compares NEO4J_TEST_URI with the live URI by endpoint."""
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This suite deletes data "
            f"in the fixture scopes before and after every test. Point it at a scratch "
            f"database.",
            returncode=2,
        )


@pytest.fixture(scope="module")
def _driver():
    """The module shares one driver."""
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
    yield driver
    driver.close()


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        yield s
        _cleanup(s)


def _cleanup(s):
    s.run("MATCH ()-[r]->() WHERE r._scope = 'reasoner' DELETE r").consume()
    s.run(
        "MATCH (n:Obj) WHERE n._scope IN "
        "['fixture:mini-dc', 'fixture:mini-enterprise', 'meta:runs', 'unifi:default', 'vyos:gw', "
        " 'meta:cycle', 'meta:cycles', 'test:sole-fw-gateway', 'test:fhrp-next-hop', "
        " 'fixture:path-a', 'vyos:patha-edge', "
        " 'test:vsx-gaia', 'test:vsx-mgmt', 'test:vsx-mgmt-other', 'test:vco-nat-hub', 'rtr1', "
        " 'test:sole-segment'] "
        # the twin router named gw loads as vyos:gw-<serial>
        "OR n._scope STARTS WITH 'vyos:gw' OR n._scope IN ['vyos:vyos-a', 'vyos:vyos-b'] "
        "DETACH DELETE n"
    ).consume()


def _publish(session) -> int:
    """Stamp what a test CREATEd as the graph's first run and publish it, as
    `hst migrate-cycle` does for a graph with no run."""
    return cyclemod.migrate_bootstrap(session)["collection_ts"]


def test_cycle_runs_replace_the_retire_revive_lifecycle(session):
    """Cycle model: every run is a full stamped
    copy. Absence from a run IS the retirement; the earlier run keeps the
    object, so history needs no flags."""
    batch = load_fixture(FIXTURE)
    t0, t1, t2 = 1_000_000_000_000, 1_000_000_060_000, 1_000_000_120_000

    # first run: everything is new
    m0 = load(session, batch, ts_ms=t0, run_id="it-run-0", collection_ts=t0)
    cyclemod.set_pointer(session, t0)
    assert m0.nodes_created == len(batch.nodes)
    assert m0.rels_dropped_missing_endpoint == 0

    # second run without leaf102: the device is absent from the current run,
    # and untouched in the previous one
    gone = "dev:leaf102"
    smaller = batch.model_copy(deep=True)
    smaller.nodes = [n for n in smaller.nodes if n.uid != gone]
    smaller.rels = [r for r in smaller.rels if gone not in (r.start_uid, r.end_uid)]
    m1 = load(session, smaller, ts_ms=t1, run_id="it-run-1", collection_ts=t1)
    cyclemod.set_pointer(session, t1)
    assert m1.nodes_created == len(smaller.nodes)  # a run re-creates its objects
    assert cyclemod.current_ts(session) == t1
    assert (
        session.run("MATCH (n:Device {uid: $uid, collection_ts: $cts}) RETURN n", uid=gone, cts=t1).single()
        is None
    )
    row = session.run(
        "MATCH (n:Device {uid: $uid, collection_ts: $cts}) RETURN count(n) AS c", uid=gone, cts=t0
    ).single()
    assert row["c"] == 1

    # third run with the full fixture again: present again, no revive machinery
    load(session, batch, ts_ms=t2, run_id="it-run-2", collection_ts=t2)
    cyclemod.set_pointer(session, t2)
    row = session.run(
        "MATCH (n:Device {uid: $uid, collection_ts: $cts}) RETURN n.collection_ts AS cts",
        uid=gone,
        cts=cyclemod.current_ts(session),
    ).single()
    assert row["cts"] == t2

    # the diff between the runs names the disappearance and the return
    from hst.core.diff import diff_snapshots

    removed = diff_snapshots(session, t0, t1)
    assert gone in [r["uid"] for r in removed["nodes"]["removed"]]
    returned = diff_snapshots(session, t1, t2)
    assert gone in [r["uid"] for r in returned["nodes"]["added"]]


def test_reasoner_stitches_vyos_cable_from_unifi_facts(session):
    """UniFi knows the MAC behind each switch port; VyOS knows its MACs.

    Neither collector alone can draw the cable. The reasoner can.
    """
    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_000_000_000_000,
        run_id="it-unifi",
        collection_ts=3_000_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=3_000_000_000_100,
        run_id="it-vyos",
        collection_ts=3_000_000_000_000,
    )

    results = reasoner.run(session, ts_ms=3_000_000_000_200, collection_ts=3_000_000_000_000)
    cyclemod.set_pointer(session, 3_000_000_000_000)
    assert sum(r["edges"] for r in results) >= 1

    # port1 holds a second, LLDP-sourced cable beside this rule's own.
    row = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth1'})-[c:CONNECTED_TO {source: 'reasoner'}]-"
        "(:Port {uid: 'dev:rack-switch/port/port1'}) "
        "RETURN c.derived AS derived, c.rule AS rule"
    ).single()
    assert row is not None and row["derived"] is True and row["rule"] == "cable-from-endpoint-mac"

    infra = session.run("MATCH (e:Endpoint {mac: 'aabbcc999999'}) RETURN e.infra AS k").single()["k"]
    assert infra is True

    # the router's eth0 is invisible to LLDP and the client table; the switch's
    # last_connection record is the only fact that places it on port 4
    row = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port4'}) "
        "RETURN c.derived AS derived, c.rule AS rule"
    ).single()
    assert row is not None and row["rule"] == "cable-from-last-connection"

    # the router vif addressed inside the IoT prefix is its gateway
    row = session.run(
        "MATCH (:Interface {uid: 'dev:gw/if/eth1.30'})-[g:GATEWAY_FOR]->"
        "(p:Prefix {cidr: '192.168.30.0/24'}) RETURN g.rule AS rule"
    ).single()
    assert row is not None and row["rule"] == "gateway-from-router-interface"

    # reruns leave one derived cable per source between the pair
    reasoner.run(session, ts_ms=3_000_000_000_300, collection_ts=3_000_000_000_000)
    count = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth1'})-[c:CONNECTED_TO {source: 'reasoner'}]-"
        "(:Port {uid: 'dev:rack-switch/port/port1'}) RETURN count(c) AS c"
    ).single()["c"]
    assert count == 1


def test_stated_uplink_wins_over_the_last_connection_inference(session):
    """eth0 has two Ports, so the stated cable resolves only by the LLDP port id."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    switch["uplink"] = {"uplink_mac": "aa:bb:cc:99:99:98", "uplink_remote_port": 0, "port_idx": 4}
    port4 = next(p for p in switch["port_table"] if p["port_idx"] == 4)
    port4["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:98", "port_id": "eth0"}]

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_100_000_000_000,
        run_id="it-unifi-uplink",
        collection_ts=3_100_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=3_100_000_000_100,
        run_id="it-vyos-uplink",
        collection_ts=3_100_000_000_000,
    )

    reasoner.run(session, ts_ms=3_100_000_000_200, collection_ts=3_100_000_000_000)
    cyclemod.set_pointer(session, 3_100_000_000_000)

    rows = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port4'}) "
        "RETURN c.source AS source, c.rule AS rule, c.derived AS derived"
    ).data()
    assert len(rows) == 1, "the last-connection guess must not lay a second edge beside the stated one"
    assert rows[0]["source"] == "unifi-uplink"
    assert rows[0]["rule"] == "cable-from-uplink-record"
    assert rows[0]["derived"] is False


def test_reasoner_states_a_cable_from_a_switchs_lldp_record(session):
    """Port 2 holds only an LLDP hint for the router's eth0 MAC."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    port2 = next(p for p in switch["port_table"] if p["port_idx"] == 2)
    port2["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:98", "port_id": "eth0"}]

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_150_000_000_000,
        run_id="it-unifi-lldp-record",
        collection_ts=3_150_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=3_150_000_000_100,
        run_id="it-vyos-lldp-record",
        collection_ts=3_150_000_000_000,
    )

    reasoner.run(session, ts_ms=3_150_000_000_200, collection_ts=3_150_000_000_000)
    cyclemod.set_pointer(session, 3_150_000_000_000)

    row = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port2'}) "
        "RETURN c.source AS source, c.rule AS rule, c.derived AS derived"
    ).single()
    assert row is not None
    assert row["source"] == "unifi-lldp"
    assert row["rule"] == "cable-from-lldp-record"
    assert row["derived"] is False


def test_reasoner_refuses_to_cable_a_router_to_a_port_with_company(session):
    """The controller lists the router's eth1 MAC as a client on the access switch's uplink Port 5."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import path as pathmod
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    access = next(d for d in raw["devices"] if d["type"] == "usw")
    # the router is not on the access switch at all: port 1 loses RAW's LLDP
    # hint naming it, and port 5 becomes the uplink to the core switch
    next(p for p in access["port_table"] if p["port_idx"] == 1).pop("lldp_table")
    port5 = next(p for p in access["port_table"] if p["port_idx"] == 5)
    port5.update(
        {
            "up": True,
            "speed": 2500,
            "full_duplex": True,
            "lldp_table": [{"chassis_id": "aa:bb:cc:00:00:03", "port_id": "Port 20"}],
            "last_connection": {"mac": "aa:bb:cc:00:00:03", "connected": True},
        }
    )
    raw["devices"].append(
        {
            "type": "usw",
            "mac": "aa:bb:cc:00:00:03",
            "serial": "SW2000003",
            "name": "core-sw",
            "model": "USW-24",
            "version": "6.5.28",
            "ip": "192.168.1.7",
            "port_table": [
                {
                    "port_idx": 20,
                    "name": "Port 20",
                    "up": True,
                    "speed": 2500,
                    "lldp_table": [{"chassis_id": "aa:bb:cc:00:00:01", "port_id": "Port 5"}],
                    "last_connection": {"mac": "aa:bb:cc:00:00:01", "connected": True},
                },
                {
                    "port_idx": 25,
                    "name": "UPPER_LAN",
                    "up": True,
                    "speed": 1000,
                    "last_connection": {"mac": "aa:bb:cc:99:99:99", "connected": True},
                },
            ],
        }
    )
    gw = next(c for c in raw["clients"] if c["mac"] == "aa:bb:cc:99:99:99")
    gw["sw_port"] = 5
    raw["clients"].append(
        {
            "mac": "11:22:33:44:55:77",
            "name": "metavm",
            "is_wired": True,
            "ip": "192.168.1.21",
            "network_id": "n1",
            "sw_mac": "aa:bb:cc:00:00:01",
            "sw_port": 5,
        }
    )

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_200_000_000_000,
        run_id="it-unifi-company",
        collection_ts=3_200_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=3_200_000_000_100,
        run_id="it-vyos-company",
        collection_ts=3_200_000_000_000,
    )

    reasoner.run(session, ts_ms=3_200_000_000_200, collection_ts=3_200_000_000_000)
    cyclemod.set_pointer(session, 3_200_000_000_000)

    # the access switch's uplink port: one cable, the stated one to the core switch
    rows = session.run(
        "MATCH (:Port {uid: 'dev:rack-switch/port/port5'})-[c:CONNECTED_TO]-(o:Port) "
        "RETURN o.uid AS peer, c.source AS source, c.rule AS rule, c.derived AS derived ORDER BY source"
    ).data()
    assert rows == [
        {
            "peer": "dev:core-sw/port/port20",
            "source": "unifi-lldp",
            "rule": "cable-from-lldp-record",
            "derived": False,
        }
    ]
    # the router's port: one cable, from the core switch, never from the access switch
    rows = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth1'})-[c:CONNECTED_TO]-(o:Port) "
        "RETURN o.uid AS peer, c.rule AS rule"
    ).data()
    assert rows == [{"peer": "dev:core-sw/port/port25", "rule": "cable-from-last-connection"}]
    # the router's client-table row on the uplink port is not a cable, so it
    # is not the infrastructure marker either
    infra = session.run("MATCH (e:Endpoint {mac: 'aabbcc999999'}) RETURN e.infra AS k").single()["k"]
    assert not infra

    result = pathmod.trace(session, "192.168.1.0/24", "8.8.8.8", port=443, proto="tcp")
    fabric = [h["uid"] for h in result["hops"] if h["stage"] == "L2_FABRIC"]
    assert fabric == ["dev:core-sw/port/port25", "dev:gw/port/eth1"], result["verdict"]
    assert not any("cables in the twin" in w for w in result["warnings"])


def test_reasoner_leaves_an_ambiguous_lldp_mac_unresolved(session):
    """The stated chassis MAC belongs to two different Devices."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    port2 = next(p for p in switch["port_table"] if p["port_idx"] == 2)
    # eth1's own MAC, reused below by a second VyOS device's eth1
    port2["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:99", "port_id": "eth1"}]

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_200_000_000_000,
        run_id="it-unifi-ambiguous-lldp",
        collection_ts=3_200_000_000_000,
    )
    # one registry, as in one deployment: the twin below has the same hostname
    registry = MemoryResolver()
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
            resolver=registry,
        ),
        ts_ms=3_200_000_000_100,
        run_id="it-vyos-ambiguous-lldp-a",
        collection_ts=3_200_000_000_000,
    )
    # a second appliance with a different serial, whose eth1 has the same MAC
    twin_version = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     QEMU5678\n"
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": twin_version, "links": tv.LINKS},
            l3dom="home",
            source_name="vyos-twin",
            resolver=registry,
        ),
        ts_ms=3_200_000_000_150,
        run_id="it-vyos-ambiguous-lldp-b",
        collection_ts=3_200_000_000_000,
    )

    results = reasoner.run(session, ts_ms=3_200_000_000_200, collection_ts=3_200_000_000_000)
    cyclemod.set_pointer(session, 3_200_000_000_000)

    lldp_record = next(r for r in results if r["rule"] == "cable-from-lldp-record")
    assert lldp_record.get("ambiguous", 0) >= 1

    count = session.run(
        "MATCH (:Port {uid: 'dev:rack-switch/port/port2'})-[c:CONNECTED_TO {source: 'unifi-lldp'}]-() "
        "RETURN count(c) AS c"
    ).single()["c"]
    assert count == 0


def test_reasoner_resolves_the_stated_cable_by_lldp_port_id_when_the_chassis_mac_names_a_different_port(
    session,
):
    """The switch's per-port LLDP record puts the chassis MAC on eth2 but names the port id "eth0"."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    port2 = next(p for p in switch["port_table"] if p["port_idx"] == 2)
    eth2_mac = "aa:bb:cc:99:99:97"
    port2["lldp_table"] = [{"chassis_id": eth2_mac, "port_id": "eth0"}]

    cfg = copy.deepcopy(tv.CONFIG)
    cfg["interfaces"]["ethernet"]["eth2"] = {"description": "third physical port"}
    links = [*tv.LINKS, {"ifname": "eth2", "address": eth2_mac}]

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_220_000_000_000,
        run_id="it-unifi-wrong-port-mac",
        collection_ts=3_220_000_000_000,
    )
    load(
        session,
        normalize_vyos({"config": cfg, "version_text": tv.VERSION, "links": links}, l3dom="home"),
        ts_ms=3_220_000_000_100,
        run_id="it-vyos-wrong-port-mac",
        collection_ts=3_220_000_000_000,
    )

    reasoner.run(session, ts_ms=3_220_000_000_200, collection_ts=3_220_000_000_000)
    cyclemod.set_pointer(session, 3_220_000_000_000)

    # the cable lands on eth0 (the port id), never eth2 (the chassis MAC)
    row = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port2'}) "
        "RETURN c.source AS source, c.rule AS rule, c.derived AS derived"
    ).single()
    assert row is not None
    assert row["source"] == "unifi-lldp"
    assert row["rule"] == "cable-from-lldp-record"
    assert row["derived"] is False

    wrong = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth2'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port2'}) RETURN count(c) AS c"
    ).single()["c"]
    assert wrong == 0


def test_reasoner_replaces_a_stated_cable_when_its_resolution_changes_on_rerun(session):
    """Derived edges are recreated each cycle from that cycle's facts."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    cts = 3_240_000_000_000

    def load_with_port_id(port_id: str, run_id: str, ts_ms: int) -> None:
        raw = copy.deepcopy(tu.RAW)
        switch = next(d for d in raw["devices"] if d["type"] == "usw")
        port2 = next(p for p in switch["port_table"] if p["port_idx"] == 2)
        # eth1's own MAC throughout; only the port id changes between runs
        port2["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:99", "port_id": port_id}]
        load(
            session,
            normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
            ts_ms=ts_ms,
            run_id=run_id,
            collection_ts=cts,
        )

    load_with_port_id("eth0", "it-unifi-replace-1", 3_240_000_000_000)
    load(
        session,
        normalize_vyos({"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS}, l3dom="home"),
        ts_ms=3_240_000_000_100,
        run_id="it-vyos-replace",
        collection_ts=cts,
    )
    reasoner.run(session, ts_ms=3_240_000_000_200, collection_ts=cts)

    def edge_count(port_name: str) -> int:
        return session.run(
            f"MATCH (:Port {{uid: 'dev:gw/port/{port_name}'}})"
            "-[c:CONNECTED_TO {source: 'unifi-lldp'}]-"
            "(:Port {uid: 'dev:rack-switch/port/port2'}) RETURN count(c) AS c"
        ).single()["c"]

    assert edge_count("eth0") == 1
    assert edge_count("eth1") == 0

    # the collector recollects with a different LLDP port id in the same cycle
    load_with_port_id("eth1", "it-unifi-replace-2", 3_240_000_000_300)
    reasoner.run(session, ts_ms=3_240_000_000_400, collection_ts=cts)
    cyclemod.set_pointer(session, cts)

    assert edge_count("eth0") == 0, "the stale resolution must not survive the rerun"
    assert edge_count("eth1") == 1


def test_last_connection_inference_yields_to_a_stated_lldp_edge(session):
    """The LLDP-stated fact wins over the last-connection guess."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    port2 = next(p for p in switch["port_table"] if p["port_idx"] == 2)
    port2["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:98", "port_id": "eth0"}]
    port2["last_connection"] = {"mac": "aa:bb:cc:99:99:98", "connected": True}

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_250_000_000_000,
        run_id="it-unifi-lldp-vs-last-conn",
        collection_ts=3_250_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=3_250_000_000_100,
        run_id="it-vyos-lldp-vs-last-conn",
        collection_ts=3_250_000_000_000,
    )

    reasoner.run(session, ts_ms=3_250_000_000_200, collection_ts=3_250_000_000_000)
    cyclemod.set_pointer(session, 3_250_000_000_000)

    rows = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port2'}) "
        "RETURN c.source AS source, c.rule AS rule"
    ).data()
    assert len(rows) == 1, "the last-connection guess must not lay a second edge beside the stated one"
    assert rows[0]["source"] == "unifi-lldp"
    assert rows[0]["rule"] == "cable-from-lldp-record"


def test_last_connection_yields_to_a_stated_cable_on_the_same_port_naming_a_different_peer(session):
    """The port carries a stated cable, so the last-connection guess does not run."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    eth2_mac = "aa:bb:cc:99:99:97"
    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    switch["uplink"] = {"uplink_mac": "aa:bb:cc:99:99:98", "uplink_remote_port": 0, "port_idx": 4}
    port4 = next(p for p in switch["port_table"] if p["port_idx"] == 4)
    # only the LLDP port id resolves the uplink record to a VyOS port
    port4["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:98", "port_id": "eth0"}]
    # the switch's own connection-table record names eth2
    port4["last_connection"] = {"mac": eth2_mac, "connected": True}

    cfg = copy.deepcopy(tv.CONFIG)
    cfg["interfaces"]["ethernet"]["eth2"] = {"description": "third physical port"}
    links = [*tv.LINKS, {"ifname": "eth2", "address": eth2_mac}]

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_260_000_000_000,
        run_id="it-unifi-last-conn-diff-peer",
        collection_ts=3_260_000_000_000,
    )
    load(
        session,
        normalize_vyos({"config": cfg, "version_text": tv.VERSION, "links": links}, l3dom="home"),
        ts_ms=3_260_000_000_100,
        run_id="it-vyos-last-conn-diff-peer",
        collection_ts=3_260_000_000_000,
    )

    reasoner.run(session, ts_ms=3_260_000_000_200, collection_ts=3_260_000_000_000)
    cyclemod.set_pointer(session, 3_260_000_000_000)

    stated = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port4'}) "
        "RETURN c.source AS source, c.rule AS rule"
    ).single()
    assert stated is not None
    assert stated["source"] == "unifi-uplink"
    assert stated["rule"] == "cable-from-uplink-record"

    # the guard yields on the port
    wrong = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth2'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port4'}) RETURN count(c) AS c"
    ).single()["c"]
    assert wrong == 0


def test_last_connection_does_not_cable_a_second_port_to_an_already_stated_peer(session):
    """A switch port holds one physical link."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    switch["uplink"] = {"uplink_mac": "aa:bb:cc:99:99:98", "uplink_remote_port": 0, "port_idx": 4}
    port4 = next(p for p in switch["port_table"] if p["port_idx"] == 4)
    # a non-UniFi peer needs the LLDP port id
    port4["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:98", "port_id": "eth0"}]
    port6 = next(p for p in switch["port_table"] if p["port_idx"] == 6)
    port6["last_connection"] = {"mac": "aa:bb:cc:99:99:98", "connected": True}

    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_270_000_000_000,
        run_id="it-unifi-peer-already-stated",
        collection_ts=3_270_000_000_000,
    )
    load(
        session,
        normalize_vyos({"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS}, l3dom="home"),
        ts_ms=3_270_000_000_100,
        run_id="it-vyos-peer-already-stated",
        collection_ts=3_270_000_000_000,
    )

    reasoner.run(session, ts_ms=3_270_000_000_200, collection_ts=3_270_000_000_000)
    cyclemod.set_pointer(session, 3_270_000_000_000)

    stated = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port4'}) RETURN c.source AS source"
    ).single()
    assert stated is not None and stated["source"] == "unifi-uplink"

    wrong = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port6'}) RETURN count(c) AS c"
    ).single()["c"]
    assert wrong == 0


def test_last_connection_inference_fires_when_the_port_carries_no_stated_cable(session):
    """Neither port of the pair holds an uplink record or an LLDP hint."""
    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=3_275_000_000_000,
        run_id="it-unifi-last-conn-only",
        collection_ts=3_275_000_000_000,
    )
    load(
        session,
        normalize_vyos({"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS}, l3dom="home"),
        ts_ms=3_275_000_000_100,
        run_id="it-vyos-last-conn-only",
        collection_ts=3_275_000_000_000,
    )

    reasoner.run(session, ts_ms=3_275_000_000_200, collection_ts=3_275_000_000_000)
    cyclemod.set_pointer(session, 3_275_000_000_000)

    row = session.run(
        "MATCH (:Port {uid: 'dev:gw/port/eth0'})-[c:CONNECTED_TO]-"
        "(:Port {uid: 'dev:rack-switch/port/port4'}) "
        "RETURN c.source AS source, c.rule AS rule, c.derived AS derived"
    ).single()
    assert row is not None
    assert row["source"] == "reasoner"
    assert row["rule"] == "cable-from-last-connection"
    assert row["derived"] is True


def test_a_stale_last_connection_inference_does_not_survive_a_rerun_that_adds_a_stated_cable(session):
    """CLEAR wipes every reasoner-owned edge for this cts before the rules rebuild it."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    cts = 3_280_000_000_000

    def edge_to(port_name: str) -> list[dict]:
        return session.run(
            f"MATCH (:Port {{uid: 'dev:gw/port/eth0'}})-[c:CONNECTED_TO]-"
            f"(:Port {{uid: 'dev:rack-switch/port/{port_name}'}}) "
            "RETURN c.source AS source, c.rule AS rule"
        ).data()

    # first collection within the cycle: last_connection only
    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=cts,
        run_id="it-last-conn-stale-1",
        collection_ts=cts,
    )
    load(
        session,
        normalize_vyos({"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS}, l3dom="home"),
        ts_ms=cts + 100,
        run_id="it-vyos-last-conn-stale",
        collection_ts=cts,
    )
    reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)

    first = edge_to("port4")
    assert len(first) == 1 and first[0]["rule"] == "cable-from-last-connection"

    # a later collection, same cycle, also states the uplink record
    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    switch["uplink"] = {"uplink_mac": "aa:bb:cc:99:99:98", "uplink_remote_port": 0, "port_idx": 4}
    port4 = next(p for p in switch["port_table"] if p["port_idx"] == 4)
    port4["lldp_table"] = [{"chassis_id": "aa:bb:cc:99:99:98", "port_id": "eth0"}]
    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=cts + 300,
        run_id="it-last-conn-stale-2",
        collection_ts=cts,
    )
    reasoner.run(session, ts_ms=cts + 400, collection_ts=cts)
    cyclemod.set_pointer(session, cts)

    second = edge_to("port4")
    assert len(second) == 1, "the stale inferred edge must not survive beside the new stated one"
    assert second[0]["source"] == "unifi-uplink"
    assert second[0]["rule"] == "cable-from-uplink-record"


def test_reasoner_derives_cross_source_address_containment(session):
    """Only the address-containment rule emits the IN edge from a UniFi client to a VyOS prefix."""
    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    cts = 3_100_000_000_000
    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=cts,
        run_id="it-unifi-c",
        collection_ts=cts,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=cts + 100,
        run_id="it-vyos-c",
        collection_ts=cts,
    )

    results = reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
    cyclemod.set_pointer(session, cts)
    containment = next(r for r in results if r["rule"] == "address-containment")
    assert containment["edges"] == 3

    # the vlan-30 client is BD-anchored; UniFi's own dom-anchored instance keeps
    # its collector edge, and the gateway chain adds only the VyOS-owned
    # instance the client's bridge domain is served by
    row = session.run(
        "MATCH (:IpAddress {uid: 'ip:bd-vlan-fab0-30:192.168.30.50'})-[e:IN]->(p:Prefix) "
        "RETURN p.uid AS pfx, e.rule AS rule, e.derived AS derived ORDER BY pfx"
    ).data()
    assert [(r["pfx"], r["rule"], r["derived"]) for r in row] == [
        ("pfx:home:192.168.30.0/24", None, None),
        ("pfx:vrf-dev-gw-default:192.168.30.0/24", "address-containment", True),
    ]

    # the vlan-1 client keeps its collector-observed edge and gains the VyOS instance
    rows = session.run(
        "MATCH (:IpAddress {uid: 'ip:bd-vlan-fab0-1:192.168.1.20'})-[e:IN]->(p:Prefix) "
        "RETURN p.uid AS pfx, e.rule AS rule ORDER BY pfx"
    ).data()
    assert [(r["pfx"], r["rule"]) for r in rows] == [
        ("pfx:home:192.168.1.0/24", None),
        ("pfx:vrf-dev-gw-default:192.168.1.0/24", "address-containment"),
    ]

    # the endpoint is reachable from the router-owned prefix instance
    hosts = session.run(
        "MATCH (p:Prefix {uid: 'pfx:vrf-dev-gw-default:192.168.30.0/24'})"
        "<-[:IN]-(:IpAddress)<-[:HAS_IP]-(e:Endpoint) RETURN DISTINCT e.mac AS mac"
    ).data()
    assert [r["mac"] for r in hosts] == ["778899aabbcc"]

    # reruns are idempotent: same counts, no parallel duplicates
    rerun = reasoner.run(session, ts_ms=cts + 300, collection_ts=cts)
    assert next(r for r in rerun if r["rule"] == "address-containment")["edges"] == 3
    count = session.run(
        "MATCH (:IpAddress {uid: 'ip:bd-vlan-fab0-1:192.168.1.20'})-[e:IN]->() RETURN count(e) AS c"
    ).single()["c"]
    assert count == 2


def test_pbr_query_resolves_firewall(session):
    """Cookbook query 2: resolve an EPG pair through contract and PBR to the firewall cluster."""
    load(session, load_fixture(FIXTURE), ts_ms=2_000_000_000_000, run_id="it-run-q")
    row = session.run("""
MATCH (a:Epg {name: 'frontend'})-[:CONSUMES]->(c:Contract)<-[:PROVIDES]-(b:Epg {name: 'backend'})
MATCH (c)-[:HAS]->(s:ContractSubject)-[:APPLIES_GRAPH]->(:ServiceGraphTemplate)
      -[:HAS_NODE]->(:ServiceNode)-[:REDIRECTS_VIA]->(pbr:PbrPolicy)
      -[:HAS_DEST]->(d:PbrDest)-[:RESOLVES_TO]->(:Endpoint)-[:OWNED_BY]->(fw:RedundancyGroup)
MATCH (fw)-[:ENFORCES]->(rb:FwRulebase)-[:HAS_RULE]->(rule:FwRule {action: 'accept'})
RETURN c.name AS contract, pbr.name AS pbr, d.ip AS dest, fw.name AS firewall,
       rb.name AS rulebase, rule.name AS rule
""").single()
    assert row["contract"] == "web-to-db"
    assert row["firewall"] == "cpfw01"
    assert row["dest"] == "10.0.250.10"
    assert row["rule"] == "allow web to db"


def test_trace_shows_every_equal_cost_path(session):
    """ECMP is a set of paths, not one path with the others hidden."""
    import test_unifi as tu
    import test_vyos as tv
    from hst import path as pathmod
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=4_000_000_000_000,
        run_id="it-unifi-ecmp",
        collection_ts=4_000_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=4_000_000_000_100,
        run_id="it-vyos-ecmp",
        collection_ts=4_000_000_000_000,
    )
    reasoner.run(session, ts_ms=4_000_000_000_200, collection_ts=4_000_000_000_000)
    cyclemod.set_pointer(session, 4_000_000_000_000)

    # the CAMERAS client is steered by PBR into table 100, which has two
    # equal-cost defaults (wg0, wg1)
    result = pathmod.trace(session, "192.168.30.50", "8.8.8.8", port=443, proto="tcp")
    assert len(result["legs"]) == 2, result["verdict"]
    egress = {leg["egress"] for leg in result["legs"]}
    assert egress == {"wg0", "wg1"}
    assert "2" in result["verdict"] and "ecmp" in result["verdict"].lower()
    # every leg is drawable: hops carry their own rank and lane
    lanes = {h["lane"] for h in result["hops"]}
    assert lanes == {0, 1}
    egress_lanes = {
        h["lane"] for h in result["hops"] if h["kind"] == "Interface" and h["label"] in ("wg0", "wg1")
    }
    assert egress_lanes == {0, 1}
    # The forward filter gates both legs after the fork.
    ordered = sorted(result["hops"], key=lambda h: h["rank"])
    assert ordered[0]["shared"], "the trail must start on the shared spine"
    fw_hops = [h for h in result["hops"] if h["kind"] == "FwRulebase"]
    assert {h["lane"] for h in fw_hops} == {0, 1}, "each lane carries its own rulebase entry"
    assert not any(h["shared"] for h in fw_hops)


def test_trace_walks_the_l2_fabric_to_the_gateway(session):
    """Every hop between a client and its gateway appears as a real port."""
    import test_unifi as tu
    import test_vyos as tv
    from hst import path as pathmod
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=5_000_000_000_000,
        run_id="it-unifi-l2",
        collection_ts=5_000_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=5_000_000_000_100,
        run_id="it-vyos-l2",
        collection_ts=5_000_000_000_000,
    )
    reasoner.run(session, ts_ms=5_000_000_000_200, collection_ts=5_000_000_000_000)
    cyclemod.set_pointer(session, 5_000_000_000_000)

    result = pathmod.trace(session, "192.168.30.50", "8.8.8.8", port=443, proto="tcp")
    by_uid = {h["uid"]: h for h in result["hops"]}
    l2_chain = [
        "ep:unifi:default:778899aabbcc",  # the client
        "dev:living-room-ap",  # the AP it associates with
        "dev:living-room-ap/port/port0",  # the AP's uplink port
        "dev:rack-switch/port/port2",  # the switch port the AP is cabled to
        "dev:rack-switch",  # the switch
        "dev:rack-switch/port/port1",  # the switch port toward the router
        "dev:gw/port/eth1",  # the router's port
        "dev:gw/if/eth1.30",  # the gateway interface
    ]
    missing = [uid for uid in l2_chain if uid not in by_uid]
    assert not missing, f"missing L2 hops: {missing}; verdict: {result['verdict']}"
    ranks = [by_uid[uid]["rank"] for uid in l2_chain]
    assert ranks == sorted(ranks), f"L2 hops out of order: {ranks}"
    # an AP is a device the client associates with, not a port
    assert by_uid["dev:living-room-ap"]["kind"] == "Device"

    # a wired client on the router's own switch stays a two-station L2 hop
    wired = pathmod.trace(session, "192.168.1.20", "8.8.8.8", port=443, proto="tcp")
    wired_uids = [h["uid"] for h in wired["hops"]]
    assert "dev:rack-switch/port/port3" in wired_uids  # its access port
    assert "dev:rack-switch/port/port1" in wired_uids  # the uplink toward the router
    assert "dev:gw/port/eth1" in wired_uids


def test_network_scoped_trace_partitions_the_source(session):
    """A network is a set of flows: a rule may claim part of it."""
    import test_unifi as tu
    import test_vyos as tv
    from hst import path as pathmod
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    load(
        session,
        normalize_unifi(tu.RAW, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=6_000_000_000_000,
        run_id="it-unifi-net",
        collection_ts=6_000_000_000_000,
    )
    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=6_000_000_000_100,
        run_id="it-vyos-net",
        collection_ts=6_000_000_000_000,
    )
    reasoner.run(session, ts_ms=6_000_000_000_200, collection_ts=6_000_000_000_000)
    cyclemod.set_pointer(session, 6_000_000_000_000)

    # only 192.168.30.50 (CAMERAS) is steered into table 100; the rest of the
    # IoT VLAN takes the main table, so one query must yield both answers
    result = pathmod.trace(session, "192.168.30.0/24", "8.8.8.8", port=443, proto="tcp")
    by_table = {leg["table"] for leg in result["legs"]}
    assert "table100" in by_table and "default" in by_table
    steered = [ll for ll in result["legs"] if ll["table"] == "table100"]
    assert steered and steered[0]["sources"] == ["192.168.30.50/32"]
    rest = [ll for ll in result["legs"] if ll["table"] == "default"]
    assert rest and "192.168.30.50/32" not in rest[0]["sources"]

    # network to network reaches the far side's own interface, so the zone-pair
    # firewall governing that direction is evaluated
    seg = pathmod.trace(session, "192.168.1.0/24", "192.168.30.0/24", port=443)
    assert any(h["kind"] == "FwRulebase" for h in seg["hops"]), seg["verdict"]


def test_find_vlan_query_accepts_bare_id(session):
    """run_query('find-vlan', {'vid': '30'}): a bare VLAN id, string or int."""
    import test_vyos as tv
    from hst.collectors.vyos import normalize_vyos
    from hst.queries import QUERIES

    load(
        session,
        normalize_vyos(
            {"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS},
            l3dom="home",
        ),
        ts_ms=7_000_000_000_000,
        run_id="it-vyos-vlan",
        collection_ts=7_000_000_000_000,
    )
    # the catalog queries pin to the run's collection_ts via $snap
    cyclemod.set_pointer(session, 7_000_000_000_000)

    cypher = next(q["cypher"] for q in QUERIES if q["key"] == "find-vlan")

    for vid in ("30", 30):  # UIs send strings, code sends ints
        rows = session.run(cypher, vid=vid, snap=7_000_000_000_000).data()
        assert len(rows) == 1, rows
        row = rows[0]
        assert row["segment"] == "bd:vlan:fab0:30"
        assert any("eth1.30" in i for i in row["interfaces"])
        assert "192.168.30.0/24" in row["prefixes"]

    assert session.run(cypher, vid="4094", snap=7_000_000_000_000).data() == []


def test_service_group_members_arrive_as_paired_protocol_and_port_arrays(session):
    """A group of tcp/443 and udp/53 does not match tcp/53."""
    from hst import path as pathmod
    from hst.path.gates import firewall

    session.run(
        """
CREATE (rb:Obj:FwRulebase {uid: 'it:rb:svcpair', _scope: 'fixture:mini-dc',
                           name: 'svc-pair', kind: 'access'})
CREATE (r:Obj:FwRule {uid: 'it:rule:svcpair', _scope: 'fixture:mini-dc',
                      position: 1, action: 'accept', enabled: true,
                      src_any: true, dst_any: true, svc_any: false})
CREATE (rb)-[:HAS_RULE]->(r)
CREATE (grp:Obj:SvcObject {uid: 'it:svc:web-and-dns', _scope: 'fixture:mini-dc',
                           name: 'web-and-dns'})
CREATE (https:Obj:SvcObject {uid: 'it:svc:https', _scope: 'fixture:mini-dc',
                             name: 'https', proto: 'tcp', ports: '443'})
CREATE (dns:Obj:SvcObject {uid: 'it:svc:dns', _scope: 'fixture:mini-dc',
                           name: 'dns', proto: 'udp', ports: '53'})
CREATE (r)-[:SVC]->(grp)
CREATE (https)-[:MEMBER_OF]->(grp)
CREATE (dns)-[:MEMBER_OF]->(grp)"""
    ).consume()

    rows = pathmod._read(
        CycleSession(session, _publish(session)), firewall._RULEBASE_RULES, rb="it:rb:svcpair"
    )
    assert len(rows) == 1
    row = rows[0]
    assert len(row["protos"]) == len(row["ports"])
    # the group's own node is the 0-hop member and constrains neither dimension
    pairs = {(p, q) for p, q in zip(row["protos"], row["ports"], strict=True) if p or q}
    assert pairs == {("tcp", "443"), ("udp", "53")}

    src, dst = pathmod._intervals(["10.0.0.5"]), pathmod._intervals(["10.9.9.5"])
    matched = firewall._first_match(rows, None, None, src, dst, 443, "tcp")
    assert matched is not None and matched[0]["uid"] == "it:rule:svcpair"
    # the crossed pairing states nothing either member does
    assert firewall._first_match(rows, None, None, src, dst, 53, "tcp") is None
    assert firewall._first_match(rows, None, None, src, dst, 443, "udp") is None


def test_ecmp_route_with_no_interface_does_not_cross_join_every_via_edge(session):
    """A next-hop-only route is resolved by its next hop alone."""
    from hst import path as pathmod
    from hst.path.trace import _ROUTES_QUERY

    session.run(
        """
CREATE (v:Obj:VrfInstance {uid: 'it:vrf:f128', name: 'default', _scope: 'fixture:mini-dc'})
CREATE (p:Obj:Prefix {uid: 'it:pfx:f128', cidr: '10.128.0.0/24', _scope: 'fixture:mini-dc'})
CREATE (a:Obj:Interface {uid: 'it:if:f128-a', name: 'eth10', _scope: 'fixture:mini-dc'})
CREATE (b:Obj:Interface {uid: 'it:if:f128-b', name: 'eth11', _scope: 'fixture:mini-dc'})
CREATE (p)-[:VIA {vrf: 'it:vrf:f128'}]->(a)
CREATE (p)-[:VIA {vrf: 'it:vrf:f128'}]->(b)
CREATE (v)-[:STATIC_ROUTE {next_hop: '10.128.9.1'}]->(p)"""
    ).consume()

    cts = _publish(session)
    rows = pathmod._read(CycleSession(session, cts), _ROUTES_QUERY, vrf="it:vrf:f128")
    assert len(rows) == 1, rows
    assert rows[0]["next_hop"] == "10.128.9.1"
    assert rows[0]["egress_uid"] is None and rows[0]["egress_name"] is None

    # a route that declares an interface pairs with that one only
    session.run(
        "MATCH (:VrfInstance {uid: 'it:vrf:f128'})-[r:STATIC_ROUTE]->(:Prefix) SET r.interface = 'eth11'"
    ).consume()
    # a new session: a pinned session keeps what it read
    rows = pathmod._read(CycleSession(session, cts), _ROUTES_QUERY, vrf="it:vrf:f128")
    assert [(r["egress_uid"], r["egress_name"]) for r in rows] == [("it:if:f128-b", "eth11")]


def test_routes_query_reads_no_bgp_origination_as_a_connected_route(session):
    """Neither a BGP network statement nor an aggregate reads as a connected route."""
    from hst import path as pathmod
    from hst.path.trace import _ROUTES_QUERY

    session.run(
        """
CREATE (v:Obj:VrfInstance {uid: 'it:vrf:bgporig', name: 'default', _scope: 'fixture:mini-dc'})
CREATE (lan:Obj:Prefix {uid: 'it:pfx:bgporig-lan', cidr: '10.10.10.0/24', _scope: 'fixture:mini-dc'})
CREATE (net:Obj:Prefix {uid: 'it:pfx:bgporig-net', cidr: '10.20.0.0/16', _scope: 'fixture:mini-dc'})
CREATE (agg:Obj:Prefix {uid: 'it:pfx:bgporig-agg', cidr: '10.0.0.0/8', _scope: 'fixture:mini-dc'})
CREATE (v)-[:ORIGINATES {proto: 'connected'}]->(lan)
CREATE (v)-[:ORIGINATES {proto: 'network'}]->(lan)
CREATE (v)-[:ORIGINATES {proto: 'network'}]->(net)
CREATE (v)-[:ORIGINATES {proto: 'aggregate'}]->(agg)"""
    ).consume()

    rows = pathmod._read(CycleSession(session, _publish(session)), _ROUTES_QUERY, vrf="it:vrf:bgporig")
    assert sorted((r["cidr"], r["kind"], r["discard"]) for r in rows) == [
        ("10.0.0.0/8", "AGGREGATE", "blackhole"),
        ("10.10.10.0/24", "ORIGINATES", None),
    ]


def test_routes_query_orders_the_rows_of_both_branches(session):
    """The table's own routes and the route-target imports are
    read in one subquery and ordered after it, so the members of an
    equal-cost route come back by next hop on every read."""
    from hst import path as pathmod
    from hst.path.trace import _ROUTES_QUERY

    session.run(
        """
CREATE (v:Obj:VrfInstance {uid: 'it:vrf:order', name: 'red', _scope: 'fixture:mini-dc'})
CREATE (x:Obj:VrfInstance {uid: 'it:vrf:order-x', name: 'blue', _scope: 'fixture:mini-dc'})
CREATE (rt:Obj:RouteTarget {uid: 'it:rt:order', value: '65000:9', _scope: 'fixture:mini-dc'})
CREATE (p:Obj:Prefix {uid: 'it:pfx:order-p', cidr: '10.70.0.0/24', _scope: 'fixture:mini-dc'})
CREATE (q:Obj:Prefix {uid: 'it:pfx:order-q', cidr: '10.60.0.0/24', _scope: 'fixture:mini-dc'})
CREATE (v)-[:STATIC_ROUTE {next_hop: '10.0.0.9'}]->(p)
CREATE (v)-[:STATIC_ROUTE {next_hop: '10.0.0.2'}]->(p)
CREATE (v)-[:STATIC_ROUTE {next_hop: '10.0.0.5'}]->(p)
CREATE (v)-[:IMPORTS]->(rt)
CREATE (x)-[:EXPORTS]->(rt)
CREATE (x)-[:ORIGINATES {proto: 'connected'}]->(q)"""
    ).consume()

    rows = pathmod._read(CycleSession(session, _publish(session)), _ROUTES_QUERY, vrf="it:vrf:order")
    assert [(r["cidr"], r["kind"], r["next_hop"]) for r in rows] == [
        ("10.60.0.0/24", "LEARNED_ROUTE", None),
        ("10.70.0.0/24", "STATIC_ROUTE", "10.0.0.2"),
        ("10.70.0.0/24", "STATIC_ROUTE", "10.0.0.5"),
        ("10.70.0.0/24", "STATIC_ROUTE", "10.0.0.9"),
    ]


def test_egress_tunnel_query_finds_the_zia_tunnel_a_router_tunnel_carries(session):
    """The router's own GRE Tunnel ends on its tunnel interface, its
    local address is the ZIA tunnel's source_ip and its far end is one of the
    ZIA tunnel's VIPs, so the ZIA tunnel comes back as 'carried' through it.
    A second router tunnel from the same address to a partner is no ZIA
    tunnel's carrier, nor is the WAN interface holding the address a
    tunnel interface."""
    from hst import path as pathmod
    from hst.path.trace import _EGRESS_TUNNEL_QUERY

    session.run(
        """
CREATE (gre1:Obj:Interface {uid: 'it:if:zia-gre1', name: 'Tunnel1', kind: 'tunnel',
                            _scope: 'fixture:mini-dc'})
CREATE (gre2:Obj:Interface {uid: 'it:if:zia-gre2', name: 'Tunnel2', kind: 'tunnel',
                            _scope: 'fixture:mini-dc'})
CREATE (wan:Obj:Interface {uid: 'it:if:zia-wan', name: 'Gi0/0', kind: 'physical', _scope: 'fixture:mini-dc'})
CREATE (pub:Obj:IpAddress {uid: 'it:ip:zia-pub', ip: '198.51.100.20', _scope: 'fixture:mini-dc'})
CREATE (wan)-[:HAS_IP]->(pub)
CREATE (rt1:Obj:Tunnel {uid: 'it:tun:zia-rt1', name: 'Tunnel1', encap: 'gre',
                        local_address: '198.51.100.20', endpoint: '104.129.194.38',
                        _scope: 'fixture:mini-dc'})
CREATE (rt2:Obj:Tunnel {uid: 'it:tun:zia-rt2', name: 'Tunnel2', encap: 'gre',
                        local_address: '198.51.100.20', endpoint: '203.0.113.9',
                        _scope: 'fixture:mini-dc'})
CREATE (rt1)-[:ENDPOINT]->(gre1)
CREATE (rt2)-[:ENDPOINT]->(gre2)
CREATE (z:Obj:Tunnel {uid: 'it:zia:gre:5001', name: 'zia-gre', encap: 'gre', source_ip: '198.51.100.20',
                      _scope: 'fixture:mini-dc'})
CREATE (dc:Obj:ZscalerDc {uid: 'it:zia:dc:zurich', name: 'Zurich', _scope: 'fixture:mini-dc'})
CREATE (z)-[:TERMINATES_ON {role: 'primary', vip: '104.129.194.38'}]->(dc)"""
    ).consume()
    snap = CycleSession(session, _publish(session))

    def rows(u):
        found = pathmod._read(snap, _EGRESS_TUNNEL_QUERY, u=u, tunnel=None, far=None)
        return [(r["uid"], r["binding"], r["via"]) for r in found]

    assert rows("it:if:zia-gre1") == [
        ("it:tun:zia-rt1", "endpoint", None),
        ("it:zia:gre:5001", "carried", "it:tun:zia-rt1"),
    ]
    assert rows("it:if:zia-gre2") == [("it:tun:zia-rt2", "endpoint", None)]
    assert rows("it:if:zia-wan") == [("it:zia:gre:5001", "source", None)]


def test_the_load_balancer_interfaces_are_read_for_a_device_and_a_group(session):
    """The load balancer a VirtualService is ON is the Device itself
    or each Device that is a MEMBER_OF the RedundancyGroup, and the stage
    enters it on its interface on the segment the VIP is delivered on."""
    from hst.path.gates import lb

    session.run(
        """
CREATE (g:Obj:RedundancyGroup {uid: 'it:rgrp:ns-ha', kind: 'ns-ha', _scope: 'fixture:mini-dc'})
CREATE (a:Obj:Device {uid: 'it:dev:ns-a', name: 'ns-a', _scope: 'fixture:mini-dc'})
CREATE (b:Obj:Device {uid: 'it:dev:ns-b', name: 'ns-b', _scope: 'fixture:mini-dc'})
CREATE (a)-[:MEMBER_OF]->(g)
CREATE (b)-[:MEMBER_OF]->(g)
CREATE (ia:Obj:Interface {uid: 'it:if:ns-a-0', name: '0/1', _scope: 'fixture:mini-dc'})
CREATE (ib:Obj:Interface {uid: 'it:if:ns-b-0', name: '0/1', _scope: 'fixture:mini-dc'})
CREATE (im:Obj:Interface {uid: 'it:if:ns-a-mgmt', name: '0/0', _scope: 'fixture:mini-dc'})
CREATE (ia)-[:ON]->(a)
CREATE (ib)-[:ON]->(b)
CREATE (im)-[:ON]->(a)
CREATE (ia)-[:HAS_IP]->(:Obj:IpAddress {uid: 'it:ip:ns-a', ip: '10.0.30.5', _scope: 'fixture:mini-dc'})
CREATE (ib)-[:HAS_IP]->(:Obj:IpAddress {uid: 'it:ip:ns-b', ip: '10.0.30.6', _scope: 'fixture:mini-dc'})
CREATE (im)-[:HAS_IP]->(:Obj:IpAddress {uid: 'it:ip:ns-m', ip: '192.168.9.5', _scope: 'fixture:mini-dc'})"""
    ).consume()
    snap = CycleSession(session, _publish(session))

    group = lb._lb_segment_interfaces(snap, "it:rgrp:ns-ha", "10.0.30.0/24", "10.0.30.10")
    assert [(r["device_uid"], r["if_uid"], r["ip"]) for r in group] == [
        ("it:dev:ns-a", "it:if:ns-a-0", "10.0.30.5"),
        ("it:dev:ns-b", "it:if:ns-b-0", "10.0.30.6"),
    ]
    device = lb._lb_segment_interfaces(snap, "it:dev:ns-b", "10.0.30.0/24", "10.0.30.10")
    assert [(r["device_uid"], r["if_uid"]) for r in device] == [("it:dev:ns-b", "it:if:ns-b-0")]


def test_trace_through_a_sole_firewall_gateway(session):
    """A firewall that is the only device with an interface on a connected prefix gets a
    GATEWAY_FOR edge from its own rule."""
    from hst import path as pathmod
    from hst import reasoner

    session.run(
        """
CREATE (d:Obj:Device {uid: 'it:dev:fw', hostname: 'fw', role: 'firewall', _scope: 'test:sole-fw-gateway'})
CREATE (ig:Obj:Interface {uid: 'it:if:fw-guest', name: 'guest0', _scope: 'test:sole-fw-gateway'})
CREATE (iw:Obj:Interface {uid: 'it:if:fw-wan', name: 'wan0', _scope: 'test:sole-fw-gateway'})
CREATE (ipg:Obj:IpAddress {uid: 'it:ip:guest-gw', ip: '10.50.0.1', af: 4, _scope: 'test:sole-fw-gateway'})
CREATE (ipw:Obj:IpAddress {uid: 'it:ip:fw-wan', ip: '203.0.113.1', af: 4, _scope: 'test:sole-fw-gateway'})
CREATE (pg:Obj:Prefix {uid: 'it:pfx:guest', cidr: '10.50.0.0/24', af: 4, kind: 'connected',
                        l3dom: 'test-guest', anchor: 'test-guest', _scope: 'test:sole-fw-gateway'})
CREATE (pd:Obj:Prefix {uid: 'it:pfx:default', cidr: '0.0.0.0/0', af: 4, _scope: 'test:sole-fw-gateway'})
CREATE (v:Obj:VrfInstance {uid: 'it:vrf:fw', name: 'root', _scope: 'test:sole-fw-gateway'})
CREATE (ig)-[:ON]->(d)
CREATE (iw)-[:ON]->(d)
CREATE (ig)-[:HAS_IP]->(ipg)
CREATE (iw)-[:HAS_IP]->(ipw)
CREATE (ipg)-[:IN]->(pg)
CREATE (ig)-[:IN_VRF]->(v)
CREATE (iw)-[:IN_VRF]->(v)
CREATE (v)-[:STATIC_ROUTE {interface: 'wan0'}]->(pd)
CREATE (pd)-[:VIA {vrf: 'it:vrf:fw'}]->(iw)
// the contested half: a second connected prefix the same firewall serves
// alongside a real router. The sole-owner rule must not fire here, which is
// the regression reasoner.py's own comment warns widening GATEWAY_ROLES into.
CREATE (ic:Obj:Interface {uid: 'it:if:fw-corp', name: 'corp0', _scope: 'test:sole-fw-gateway'})
CREATE (ipc:Obj:IpAddress {uid: 'it:ip:fw-corp', ip: '10.60.0.2', af: 4, _scope: 'test:sole-fw-gateway'})
CREATE (pc:Obj:Prefix {uid: 'it:pfx:corp', cidr: '10.60.0.0/24', af: 4, kind: 'connected',
                        l3dom: 'test-corp', anchor: 'test-corp', _scope: 'test:sole-fw-gateway'})
CREATE (rd:Obj:Device {uid: 'it:dev:rtr', hostname: 'rtr', role: 'router', _scope: 'test:sole-fw-gateway'})
CREATE (ri:Obj:Interface {uid: 'it:if:rtr-corp', name: 'Gi0/1', _scope: 'test:sole-fw-gateway'})
CREATE (rip:Obj:IpAddress {uid: 'it:ip:rtr-corp', ip: '10.60.0.1', af: 4, _scope: 'test:sole-fw-gateway'})
CREATE (ic)-[:ON]->(d)
CREATE (ic)-[:HAS_IP]->(ipc)
CREATE (ipc)-[:IN]->(pc)
CREATE (ri)-[:ON]->(rd)
CREATE (ri)-[:HAS_IP]->(rip)
CREATE (rip)-[:IN]->(pc)"""
    ).consume()

    # before the reasoner runs, the trace dead-ends
    cts = _publish(session)
    dead_end = pathmod.trace(session, "10.50.0.0/24", "8.8.8.8", port=443, proto="tcp")
    assert "no gateway found" in dead_end["verdict"]

    reasoner.run(session, ts_ms=9_000_000_000_000, collection_ts=cts)
    # a published run's gateway rows are kept per process (path/session.py
    # _GATEWAY_CACHE); this run gained its GATEWAY_FOR edges after it was read
    from hst.path import session as sessionmod

    sessionmod._GATEWAY_CACHE.clear()

    result = pathmod.trace(session, "10.50.0.0/24", "8.8.8.8", port=443, proto="tcp")
    assert "no gateway found" not in result["verdict"], result["verdict"]
    assert result["legs"], result["verdict"]
    assert any(leg.get("egress") == "wan0" for leg in result["legs"]), result["legs"]

    # the rule's own Cypher, both halves: the sole-owner prefix is credited to
    # the firewall's interface, and the prefix a router also serves is not
    sole = session.run(
        """
MATCH (i:Interface)-[c:GATEWAY_FOR]->(p:Prefix)
WHERE c.rule = 'gateway-from-sole-firewall-interface'
  AND p.uid IN ['it:pfx:guest', 'it:pfx:corp']
RETURN i.uid AS iface, p.uid AS prefix ORDER BY p.uid"""
    ).data()
    assert [(r["iface"], r["prefix"]) for r in sole] == [("it:if:fw-guest", "it:pfx:guest")]
    # the contested prefix gets its gateway from the router rule
    router = session.run(
        """
MATCH (i:Interface)-[c:GATEWAY_FOR]->(p:Prefix {uid: 'it:pfx:corp'})
WHERE c.rule = 'gateway-from-router-interface'
RETURN i.uid AS iface ORDER BY i.uid"""
    ).data()
    assert [r["iface"] for r in router] == ["it:if:rtr-corp"]


def test_brokered_trace_reads_the_fixture_zpa_policy(session):
    """The brokered entry point runs against a real database, on the fixture's own ZPA wiring."""
    from hst import path as pathmod

    cts = 3_000_000_000_000
    load(session, load_fixture(ENTERPRISE_FIXTURE), ts_ms=cts, run_id="it-run-zpa", collection_ts=cts)
    # the entry point pins a bare session to the pointer's current run, so the
    # run has to be the current one for any of its reads to answer
    cyclemod.set_pointer(session, cts)

    denied = pathmod.trace_from_identity(session, "zpa:acme:idp:7001-77102", "zpa:acme:seg:2001", 443, "tcp")
    rule_hops = [h["uid"] for h in denied["hops"] if h["stage"] == "ACCESS_RULE"]
    assert rule_hops == ["zpa:acme:rule:200"], denied["verdict"]
    assert [ll.get("blocking_uid") for ll in denied["legs"]] == ["zpa:acme:rule:200"]

    allowed = pathmod.trace_from_identity(session, "zpa:acme:idp:7001-77101", "zpa:acme:seg:2001", 443, "tcp")
    assert [h["uid"] for h in allowed["hops"] if h["stage"] == "ACCESS_RULE"] == ["zpa:acme:rule:100"]
    assert [h["uid"] for h in allowed["hops"] if h["stage"] == "CONNECTOR"] == ["zpa:acme:conn:600"]
    assert allowed["verdict"]


# --- acceptance path A -------------------------------------------------------------------------------
#
# fixtures/path-a.yaml and tests/test_vyos.py's CONFIG_PATH_A load into the same run.

PATH_A_FIXTURE = Path(__file__).parents[1] / "fixtures" / "path-a.yaml"

# gates/__init__.py's _Trail.hop keys the rank on depth, stage and sequence.
PATH_A_ORDERED_HOPS = [
    "vyos:patha-edge:pbr:DC-PBR",
    "vyos:patha-edge:pbr:DC-PBR:10",
    "vyos:patha-edge:fw:ipv4-forward",
    "vyos:patha-edge:fw:LAN-WAN",
    "vyos:patha-edge:fw:ipv4-forward:10",
    "vyos:patha-edge:fw:LAN-WAN:10",
    "vyos:patha-edge:nat:source:100",
    "cp:patha:smc:pkg-dc-access",
    "cp:patha:smc:rule-permit-dc",
    "ns:patha:lbvs:web-443",
    "ns:patha:sg:web",
    "ns:patha:sg:web/10.0.10.5:8443",
    "ep:patha:web01",
]


def _load_path_a(session, ts_ms: int) -> None:
    """Load both halves of path A into one snapshot and run the reasoner.

    The VyOS device's own connected interfaces earn their GATEWAY_FOR credit
    only from the reasoner (reasoner-owned, per collectors/util.py's
    connected_address docstring), and so do the Check Point cluster's, whose
    interface addresses sit in the connected prefixes its own table
    originates.
    """
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.vyos import normalize_vyos

    load(session, load_fixture(PATH_A_FIXTURE), ts_ms=ts_ms, run_id="it-path-a", collection_ts=ts_ms)
    load(
        session,
        normalize_vyos(
            {
                "config": tv.CONFIG_PATH_A,
                "version_text": tv.VERSION_PATH_A,
                "links": tv.LINKS_PATH_A,
                "routes_tables": tv.ROUTES_TABLES_PATH_A,
            },
            l3dom="patha",
        ),
        ts_ms=ts_ms + 100,
        run_id="it-path-a-vyos",
        collection_ts=ts_ms,
    )
    reasoner.run(session, ts_ms=ts_ms + 200, collection_ts=ts_ms)
    cyclemod.set_pointer(session, ts_ms)


def test_path_a_hop_sequence_names_every_stage_in_order(session):
    """The ordered hop list, by rank, names every stage and every deciding
    rule: the VyOS forward chain and zone policy
    with the rule each decided by, the masquerade, the PBR redirect, the
    Check Point cluster rulebase with its own deciding rule, the LOAD_BALANCER
    stage (VirtualService, Pool, the up PoolMember) and the member's
    endpoint."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_000_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=443, proto="tcp")
    wanted = set(PATH_A_ORDERED_HOPS)
    on_path = [h for h in result["hops"] if h["uid"] in wanted]
    assert [h["uid"] for h in sorted(on_path, key=lambda h: h["rank"])] == PATH_A_ORDERED_HOPS, [
        (h["rank"], h["stage"], h["uid"]) for h in result["hops"]
    ]
    stages = {h["stage"] for h in result["hops"]}
    assert {"SNAT", "PBR_POLICY", "PBR_RULE", "FILTER_RB", "FILTER_RULE", "LOAD_BALANCER"} <= stages, result[
        "verdict"
    ]


def test_path_a_down_member_gets_a_note_not_a_leg(session):
    """A down pool member is named in a note, never drawn as its own hop or
    leg (gates/lb.py's D-LB3 doctrine)."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_100_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=443, proto="tcp")
    down_uid = "ns:patha:sg:web/10.0.10.6:8443"
    assert not any(h["uid"] == down_uid for h in result["hops"]), result["hops"]
    assert any("skipped as down" in n for n in result["notes"]), result["notes"]
    assert len(result["legs"]) == 1, result["legs"]


def test_path_a_snat_and_dnat_lists_carry_both_transformations_in_order(session):
    """The one surviving leg's snat list carries the VyOS masquerade before
    the NetScaler SNIP rewrite (upstream translation first),
    and its dnat list carries the VIP-to-member rewrite."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_200_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=443, proto="tcp")
    legs = [ll for ll in result["legs"] if not ll.get("indeterminate") and not ll.get("blocked")]
    assert legs, result["verdict"]
    leg = legs[0]
    assert [e["to"] for e in leg["snat"]] == ["10.0.9.1", "10.0.10.1"], leg.get("snat")
    assert leg["dnat"][-1]["to"] == ["10.0.10.5/32"], leg.get("dnat")
    assert leg["dnat"][-1]["rule_uid"] == "ns:patha:sg:web/10.0.10.5:8443", leg.get("dnat")


def test_path_a_hops_carry_layer_and_tier(session):
    """Every hop on the path carries layer and tier."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_300_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=443, proto="tcp")
    assert result["hops"], result["verdict"]
    missing_layer = [h for h in result["hops"] if not h.get("layer")]
    assert not missing_layer, missing_layer
    assert all(h.get("tier") is not None for h in result["hops"])


def test_path_a_verdict_is_not_indeterminate_and_lists_no_unevaluated_gate(session):
    """The permitted flow's verdict is settled: no leg is indeterminate and
    no gate on the path went unevaluated. Both VyOS rulebase models and the
    PBR policy are credited, so nothing on the path is reported as examined
    by nothing."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_400_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=443, proto="tcp")
    assert result["legs"], result["verdict"]
    assert not any(leg.get("indeterminate") for leg in result["legs"]), result["verdict"]
    assert "not evaluated" not in result["verdict"], result["verdict"]


def test_path_a_every_gate_on_the_path_is_credited_on_the_leg(session):
    """The firewall gate reads the RedundancyGroup binding,
    so the cluster rulebase is credited on the leg it decided. Both VyOS
    rulebase models and the PBR policy the redirect came from are credited
    too, each by the accounting of its own stage."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_500_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=443, proto="tcp")
    legs = [ll for ll in result["legs"] if not ll.get("blocked")]
    assert legs, result["verdict"]
    leg = legs[0]
    assert {
        "cp:patha:smc:pkg-dc-access",
        "vyos:patha-edge:fw:ipv4-forward",
        "vyos:patha-edge:fw:LAN-WAN",
    } <= set(leg.get("fw_uids") or []), leg
    assert leg.get("pbr_uids") == ["vyos:patha-edge:pbr:DC-PBR"], leg
    assert leg.get("lb_uids") == ["ns:patha:lbvs:web-443"], leg
    assert not leg.get("indeterminate"), leg


def test_path_a_port_the_vip_does_not_serve_is_blocked_at_the_vip(session):
    """The pool behind the service is never evaluated (decision D-LB5)."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_600_000_000)
    result = pathmod.trace(session, "10.20.1.50", "10.0.30.10", port=8080, proto="tcp")
    assert any(h["uid"] == "ns:patha:lbvs:web-443" for h in result["hops"]), result["hops"]
    assert not any(h["uid"] == "ns:patha:sg:web" for h in result["hops"]), result["hops"]
    blocked = [leg for leg in result["legs"] if leg.get("blocked")]
    assert len(blocked) == 1 and not blocked[0].get("indeterminate"), result["verdict"]
    verdict = blocked[0]["verdict"]
    assert verdict.startswith("BLOCKED at VIP 10.0.30.10: no virtual service serves"), verdict
    assert not any(leg.get("indeterminate") for leg in result["legs"]), result["verdict"]


def test_path_a_denied_post_nat_source_blocks_at_the_cluster_rulebase(session):
    """The Check Point rule written against the branch segment's post-NAT source denies it."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_700_000_000)
    result = pathmod.trace(session, "10.20.2.50", "10.0.30.10", port=443, proto="tcp")
    assert result["legs"], result["verdict"]
    leg = result["legs"][0]
    assert leg.get("blocked"), result["verdict"]
    # the post-NAT source the rule judged, not the client's own address
    assert [e["to"] for e in leg["snat"]] == ["10.0.9.50"], leg.get("snat")
    assert leg["fw_uid"] == "cp:patha:smc:pkg-dc-access", leg
    assert "dc-access" in leg["verdict"], leg["verdict"]
    assert leg["verdict"].startswith("BLOCKED by"), leg["verdict"]
    assert "cp:patha:smc:rule-deny-branch" in [h["uid"] for h in result["hops"]], result["hops"]
    # the block ends the lane: the pool behind the VIP is never evaluated
    assert not any(h["uid"] == "ns:patha:sg:web" for h in result["hops"]), result["hops"]


def test_path_a_simulate_change_raises_the_entry_mtu_and_retraces_against_the_real_evidence_read(session):
    """`fw_overlay_read.simulate_change` runs against a real Neo4j with `pathmod.trace` and
    `read_catalog` not faked."""
    from hst.app import fw_overlay_read
    from hst.path.session import CycleSession

    ts = 8_101_500_000_000
    _load_path_a(session, ts)
    pinned = CycleSession(session, ts)

    flow = {
        "src": "10.20.1.50",
        "dst": "10.0.30.10",
        "port": 443,
        "proto": "tcp",
        "mtu": {"mode": "packet", "ip_packet_bytes": 9000, "ipv4_df": True},
    }
    mtu_intent = {
        "kind": "interface.set_mtu",
        "params": {"interface": "dev:patha-edge/if/eth1", "mtu": 9000},
    }
    unrelated_intent = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "cp:patha:smc:pkg-dc-access",
            "position": 100,
            "action": "drop",
            "source": "any",
            "destination": ["203.0.113.0/24"],
        },
    }

    mtu_result = fw_overlay_read.simulate_change(pinned, intents=[mtu_intent], flows=[flow])
    assert "dev:patha-edge/if/eth1" in mtu_result["mtu_subjects"], mtu_result["mtu_subjects"]
    mtu_flow = mtu_result["flows"][0]
    groups = mtu_flow["paths"]["groups"]
    assert groups, mtu_flow
    before_mtu = groups[0]["mtu_before"]
    after_mtu = groups[0]["mtu_after"]
    assert before_mtu["outcome"] == "fail", before_mtu
    assert before_mtu["known_ceiling_bytes"] == 1500, before_mtu
    assert "dev:patha-edge/if/eth1" in before_mtu["bottleneck"], before_mtu
    # nothing else on Path A holds MTU evidence
    assert after_mtu["outcome"] != "fail", after_mtu
    before_state = (before_mtu["outcome"], before_mtu["bottleneck"])
    after_state = (after_mtu["outcome"], after_mtu["bottleneck"])
    assert before_state != after_state, (before_mtu, after_mtu)

    unrelated_result = fw_overlay_read.simulate_change(pinned, intents=[unrelated_intent], flows=[flow])
    assert not unrelated_result["mtu_subjects"], unrelated_result["mtu_subjects"]
    unrelated_before = unrelated_result["flows"][0]["paths"]["groups"][0]["mtu_before"]
    assert unrelated_before == before_mtu, (unrelated_before, before_mtu)


# --- acceptance path B ---------------------------------------------------------------------------
#
# fixtures/path-a.yaml's own ZPA layer holds the wiring.


def test_path_b_brokered_hop_sequence_names_identity_rule_and_connector(session):
    """The brokered hop sequence: IDENTITY, the
    winning ACCESS_RULE, then CONNECTOR naming the healthy connector. The
    down connector is never drawn as a hop of its own."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_800_000_000)
    result = pathmod.trace_from_identity(session, "idg:scim:patha-ops", "zpa:patha:appseg:web", 443, "tcp")
    assert [h["uid"] for h in result["hops"] if h["stage"] == "IDENTITY"] == ["idg:scim:patha-ops"], result[
        "hops"
    ]
    assert [h["uid"] for h in result["hops"] if h["stage"] == "ACCESS_RULE"] == ["zpa:patha:rule:100"], (
        result["verdict"]
    )
    assert [h["uid"] for h in result["hops"] if h["stage"] == "CONNECTOR"] == [
        "zpa:patha:connector:dc1-01"
    ], result["hops"]
    assert not any(h["uid"] == "zpa:patha:connector:dc1-02" for h in result["hops"]), result["hops"]


def test_path_b_identity_based_match_decides_the_access_rule_hop(session):
    """The deny rule names the contractors group as `blocking_uid`."""
    from hst import path as pathmod

    _load_path_a(session, 8_100_900_000_000)
    denied = pathmod.trace_from_identity(
        session, "idg:scim:patha-contractors", "zpa:patha:appseg:web", 443, "tcp"
    )
    assert [h["uid"] for h in denied["hops"] if h["stage"] == "ACCESS_RULE"] == ["zpa:patha:rule:200"], (
        denied["verdict"]
    )
    assert [ll.get("blocking_uid") for ll in denied["legs"]] == ["zpa:patha:rule:200"]

    unnamed = pathmod.trace_from_identity(
        session, "idg:scim:patha-guests", "zpa:patha:appseg:web", 443, "tcp"
    )
    assert unnamed["indeterminate"], unnamed["verdict"]


def test_path_b_resolves_the_segment_to_the_same_vip_and_pool(session):
    """The segment's RESOLVES_TO chain lands on the VIP address acceptance
    path A reaches, and the walk crosses the same VirtualService, Pool and
    up PoolMember path A's own test asserts."""
    from hst import path as pathmod

    _load_path_a(session, 8_101_000_000_000)
    result = pathmod.trace_from_identity(session, "idg:scim:patha-ops", "zpa:patha:appseg:web", 443, "tcp")
    assert result["hops"], result["verdict"]
    vs_hops = [h for h in result["hops"] if h["uid"] == "ns:patha:lbvs:web-443"]
    assert vs_hops and "10.0.30.10" in vs_hops[0]["note"], result["hops"]
    lb_uids = {h["uid"] for h in result["hops"] if h["stage"] == "LOAD_BALANCER"}
    assert lb_uids == {
        "ns:patha:lbvs:web-443",
        "ns:patha:sg:web",
        "ns:patha:sg:web/10.0.10.5:8443",
    }, result["hops"]


def test_path_b_on_prem_chain_credits_the_cluster_rulebase_and_reaches_the_member(session):
    """The connector's own on-prem address crosses the same Check Point
    cluster rulebase path A's client does: the rulebase decides an allow
    (credited on the leg, not indeterminate), the SNIP source rewrite and
    the member dNAT appear in the leg's snat/dnat lists in order, and the
    walk ends at the member's own endpoint."""
    from hst import path as pathmod

    _load_path_a(session, 8_101_100_000_000)
    result = pathmod.trace_from_identity(session, "idg:scim:patha-ops", "zpa:patha:appseg:web", 443, "tcp")
    legs = [ll for ll in result["legs"] if not ll.get("indeterminate") and not ll.get("blocked")]
    assert legs, result["verdict"]
    leg = legs[0]
    assert "cp:patha:smc:pkg-dc-access" in (leg.get("fw_uids") or []), leg
    assert [e["to"] for e in leg["snat"]] == ["10.0.10.1"], leg.get("snat")
    assert leg["dnat"][-1]["to"] == ["10.0.10.5/32"], leg.get("dnat")
    assert leg["dnat"][-1]["rule_uid"] == "ns:patha:sg:web/10.0.10.5:8443", leg.get("dnat")
    assert any(h["uid"] == "ep:patha:web01" for h in result["hops"]), result["hops"]


def test_path_b_hops_carry_layer_and_tier(session):
    """Every hop on the path carries layer and tier, the brokered stages included."""
    from hst import path as pathmod

    _load_path_a(session, 8_101_200_000_000)
    result = pathmod.trace_from_identity(session, "idg:scim:patha-ops", "zpa:patha:appseg:web", 443, "tcp")
    assert result["hops"], result["verdict"]
    missing_layer = [h for h in result["hops"] if not h.get("layer")]
    assert not missing_layer, missing_layer
    assert all(h.get("tier") is not None for h in result["hops"])


def test_path_b_verdict_is_not_indeterminate_and_lists_no_unevaluated_gate(session):
    """The allowed flow's verdict is settled: no leg is indeterminate and no
    gate on the path went unevaluated."""
    from hst import path as pathmod

    _load_path_a(session, 8_101_300_000_000)
    result = pathmod.trace_from_identity(session, "idg:scim:patha-ops", "zpa:patha:appseg:web", 443, "tcp")
    assert result["legs"], result["verdict"]
    assert not any(leg.get("indeterminate") for leg in result["legs"]), result["verdict"]
    assert "not evaluated" not in result["verdict"], result["verdict"]


def test_path_b_port_the_segment_does_not_serve_blocks_at_the_segment(session):
    """A port outside the segment's own collected tcp_port_ranges is a named
    no-match at the segment itself, decided
    before any access rule is consulted."""
    from hst import path as pathmod

    _load_path_a(session, 8_101_400_000_000)
    result = pathmod.trace_from_identity(session, "idg:scim:patha-ops", "zpa:patha:appseg:web", 8080, "tcp")
    assert [ll.get("blocking_uid") for ll in result["legs"]] == ["zpa:patha:appseg:web"], result["verdict"]
    assert not any(h["stage"] == "ACCESS_RULE" for h in result["hops"]), result["hops"]


def _equinix_circuit_batch():
    """Two NX-OS cores at two sites, each with a Port carrying VLAN 100 into the
    default single-fabric BridgeDomain, two Equinix FabricPorts realized by those
    ports, a circuit with tag 100 on both sides, and a second circuit whose Z
    end sits on a FabricPort whose binding names a port the run lacks (a
    refused `port_bindings` row)."""
    from hst.collectors.util import GraphBuilder
    from hst.core import uid as uidmod

    b = GraphBuilder()
    bd = b.node("BridgeDomain", uidmod.bridge_domain("fab0", 100), name="users")
    for code in ("fr2", "pa3"):
        site = b.node("Site", uidmod.site(code), code=code, kind="colo")
        dev = b.node("Device", f"dev:core-{code}", hostname=f"core-{code}", role="router", platform="nxos")
        b.rel("LOCATED_IN", "Device", dev, "Site", site)
        port = b.node("Port", uidmod.port(dev, "Ethernet1/49"), name="Ethernet1/49", kind="phys")
        b.rel("ON", "Port", port, "Device", dev)
        vlan = b.node("VlanInstance", uidmod.vlan(f"nxos:{code}", 100), vid=100, name="users")
        b.rel("REALIZES", "VlanInstance", vlan, "BridgeDomain", bd)
        b.rel("CARRIES", "Port", port, "VlanInstance", vlan)
        fp = b.node(
            "FabricPort", uidmod.equinix("port", f"port-{code}"), name=f"{code}-10g", bound_port_uid=port
        )
        b.rel("LOCATED_IN", "FabricPort", fp, "Site", site)
        b.rel("REALIZED_BY", "FabricPort", fp, "Port", port)
    provider = b.node("Provider", uidmod.provider("equinix"), name="Equinix", kind="colo")
    vc = b.node("VirtualCircuit", uidmod.equinix("connection", "c-100"), name="fr2-to-pa3", state="ACTIVE")
    b.rel("PROVIDED_BY", "VirtualCircuit", vc, "Provider", provider)
    fr2_port, pa3_port = uidmod.equinix("port", "port-fr2"), uidmod.equinix("port", "port-pa3")
    b.rel("A_END", "VirtualCircuit", vc, "FabricPort", fr2_port, link_protocol="dot1q", vlan_tag=100)
    b.rel("Z_END", "VirtualCircuit", vc, "FabricPort", pa3_port, link_protocol="dot1q", vlan_tag=100)
    # the half-bound circuit: its Z end names a FabricPort with a binding the run lacks
    orphan = b.node(
        "FabricPort",
        uidmod.equinix("port", "port-sv1"),
        name="sv1-10g",
        bound_port_uid="dev:ghost/port/eth1-1",
    )
    b.rel("REALIZED_BY", "FabricPort", orphan, "Port", "dev:ghost/port/eth1-1")
    half = b.node("VirtualCircuit", uidmod.equinix("connection", "c-half"), name="fr2-to-sv1", state="ACTIVE")
    b.rel("A_END", "VirtualCircuit", half, "FabricPort", fr2_port, link_protocol="dot1q", vlan_tag=200)
    b.rel("Z_END", "VirtualCircuit", half, "FabricPort", orphan, link_protocol="dot1q", vlan_tag=200)
    return b.batch("equinix", "test:equinix-circuit")


def test_fabric_circuit_becomes_a_link_and_its_impact_names_both_ports_and_the_stretched_domain(session):
    """cable-from-fabric-circuit draws one CONNECTED_TO for the fully bound
    circuit and none for the half-bound one; the stretch check reads the link
    back as `stretched` with no warning and reports the refused binding; and
    GET /api/impact/link's assessment of the circuit uid names both site
    ports and the BridgeDomain both carry."""
    from hst import path as pathmod
    from hst import reasoner
    from hst.app.routes import impact
    from hst.core import snapshot as snapshotmod
    from hst.core import uid as uidmod

    # the same uid builder the batch used: `uid.port` slugs "Ethernet1/49" to "eth1-49"
    port_fr2 = uidmod.port("dev:core-fr2", "Ethernet1/49")
    port_pa3 = uidmod.port("dev:core-pa3", "Ethernet1/49")
    cts = 3_300_000_000_000
    wipe = "MATCH (n:Obj {_scope: 'test:equinix-circuit'}) DETACH DELETE n"
    session.run(wipe).consume()
    try:
        manifest = load(session, _equinix_circuit_batch(), ts_ms=cts, run_id="it-eqx", collection_ts=cts)
        # the binding to a port the run lacks is refused at load: the edge never lands
        assert manifest.rels_dropped_missing_endpoint == 1

        results = reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
        cyclemod.set_pointer(session, cts)
        circuit_rule = next(r for r in results if r["rule"] == "cable-from-fabric-circuit")
        assert circuit_rule["edges"] == 1

        rows = session.run(
            "MATCH (a:Port)-[c:CONNECTED_TO {source: 'equinix-circuit'}]->(z:Port) "
            "RETURN a.uid AS a, z.uid AS z, c.circuit_uid AS circuit, "
            "c.vlan_tag_a AS ta, c.vlan_tag_z AS tz, c.derived AS derived, c.rule AS rule ORDER BY a"
        ).data()
        assert rows == [
            {
                "a": port_fr2,
                "z": port_pa3,
                "circuit": "eqx:connection:c-100",
                "ta": 100,
                "tz": 100,
                "derived": True,
                "rule": "cable-from-fabric-circuit",
            }
        ]

        report = reasoner.check_vlan_stretch(session, collection_ts=cts)
        assert [(o["kind"], o["vid"], o["site_a"], o["site_z"]) for o in report["observations"]] == [
            ("stretched", 100, "fr2", "pa3")
        ]
        assert report["unbound_ports"] == [
            {"fabric_port": "eqx:port:port-sv1", "port_uid": "dev:ghost/port/eth1-1"}
        ]
        assert report["warnings"] == [
            "equinix port binding refused: eqx:port:port-sv1 names port dev:ghost/port/eth1-1, "
            "which is not in this run"
        ]

        pinned = pathmod.pinned(session, snapshotmod.Snapshot(cts, Settings(_env_file=None)))
        body = impact.assess_link(pinned, "eqx:connection:c-100")
        assert body["circuit"] == {
            "uid": "eqx:connection:c-100",
            "ports": [port_fr2, port_pa3],
            "bridge_domains": [{"uid": "bd:vlan:fab0:100", "name": "users", "vid": 100}],
        }
        assert body["device"] == "dev:core-fr2"
        with pytest.raises(Exception, match="eqx:connection:c-half"):
            impact.assess_link(pinned, "eqx:connection:c-half")
    finally:
        session.run("MATCH ()-[r]->() WHERE r._scope = 'reasoner' DELETE r").consume()
        session.run(wipe).consume()


_EQX_SCOPES = ["test:eqx-runs", "test:eqx-switch"]
_EQX_SWITCH = "dev:eqx-sw-01"


def _eqx_switch_batch(description: str | None = None, bound: str | None = None, bound_mac: str | None = None):
    """The other sources of an Equinix test: one switch with the port
    Ethernet1/3, and, with `bound`, a device of role sdwan-edge whose port
    carries `bound_mac`."""
    from hst.collectors.util import GraphBuilder
    from hst.core import uid as uidmod

    b = GraphBuilder()
    sw = b.node("Device", _EQX_SWITCH, hostname="eqx-sw-01", role="switch", platform="nxos")
    port = b.node(
        "Port", uidmod.port(sw, "Ethernet1/3"), name="Ethernet1/3", kind="phys", description=description
    )
    b.rel("ON", "Port", port, "Device", sw)
    if bound:
        dev = b.node("Device", bound, hostname="eqx-sdwan-01", role="sdwan-edge")
        bp = b.node("Port", uidmod.port(dev, "GE3"), name="GE3", kind="phys", mac=bound_mac)
        b.rel("ON", "Port", bp, "Device", dev)
    return b.batch("test", "test:eqx-switch")


def _eqx_wipe(session) -> None:
    session.run("MATCH ()-[r]->() WHERE r._scope = 'reasoner' DELETE r").consume()
    session.run("MATCH (n:Obj) WHERE n._scope IN $scopes DETACH DELETE n", scopes=_EQX_SCOPES).consume()


def test_equinix_reads_return_one_row_per_circuit_across_two_runs(session):
    """Two runs of the same account: each run holds its own copy of every
    Network Edge device and interface. The route and the catalog read the
    pinned run only: one row per circuit and per device link, the interface
    count of one run, and the cabled flag of that run. The first run binds the
    circuit's Fabric port to a switch port; the second run drops the binding,
    so the circuit is cabled at the first run only."""
    from collections import Counter

    from tests.test_equinix_network_edge import (
        CONNECTION_EDGE,
        EDGE_DEVICE,
        EDGE_HUB_DEVICE,
        EDGE_ROUTER_DEVICE,
        LINK_PAIR,
        PORT_PRI,
        PORTS,
    )

    from hst import reasoner
    from hst.app.routes import equinix as route
    from hst.collectors.equinix import normalize_equinix
    from hst.core import uid as uidmod
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}
    circuit = uidmod.equinix("connection", CONNECTION_EDGE["uuid"])
    switch_port = uidmod.port(_EQX_SWITCH, "Ethernet1/3")
    first, second = 3_600_000_000_000, 3_600_000_060_000

    def equinix_batch(bindings: dict[str, str]):
        raw = {
            "fetched_at_ms": 1,
            "port_pages": [{"data": PORTS}],
            "connection_pages": [{"data": [CONNECTION_EDGE]}],
            "edge_device_pages": [
                {
                    "data": [
                        EDGE_DEVICE,
                        {**EDGE_ROUTER_DEVICE, "metroCode": "XX"},
                        {**EDGE_HUB_DEVICE, "metroCode": "XX"},
                    ]
                }
            ],
            "edge_link_pages": [{"data": [LINK_PAIR]}],
        }
        return normalize_equinix(raw, scope="test:eqx-runs", ibx_sites={}, port_bindings=bindings)

    def cabled(snap: int) -> dict[str, bool]:
        rows = session.run(route._CIRCUITS, metro="XX", snap=snap).data()
        return {row["type"] if row["uid"] != circuit else "circuit": row["cabled"] for row in rows}

    _eqx_wipe(session)
    try:
        for cts, bindings in ((first, {PORT_PRI: switch_port}), (second, {})):
            load(session, _eqx_switch_batch(), ts_ms=cts, run_id=f"it-eqx-sw-{cts}", collection_ts=cts)
            load(session, equinix_batch(bindings), ts_ms=cts, run_id=f"it-eqx-{cts}", collection_ts=cts)
            reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
        cyclemod.set_pointer(session, second)

        rows = session.run(route._CIRCUITS, metro="XX", snap=second).data()
        assert len(rows) == 2
        assert len({row["uid"] for row in rows}) == 2
        assert {row["type"] for row in rows} == {CONNECTION_EDGE["type"], "DEVICE_LINK"}

        links = session.run(cypher["equinix-device-links"], metro="XX", snap=second).data()
        assert len(links) == 1
        assert links[0]["cabled"] is True

        edge = session.run(cypher["equinix-network-edge"], metro="XX", snap=second).data()
        assert {row["device"]: row["interfaces"] for row in edge}["XX-EDGE-FW-01"] == 3

        catalog = session.run(cypher["equinix-circuits"], metro="XX", snap=second).data()
        assert Counter(row["circuit"] for row in catalog) == {
            CONNECTION_EDGE["name"]: 1,
            LINK_PAIR["groupName"]: 1,
        }

        assert cabled(first) == {"circuit": True, "DEVICE_LINK": True}
        assert cabled(second) == {"circuit": False, "DEVICE_LINK": True}
        by_circuit = {
            snap: {
                row["circuit"]: row["cabled"]
                for row in session.run(cypher["equinix-circuits"], metro="XX", snap=snap).data()
            }
            for snap in (first, second)
        }
        assert by_circuit[first][CONNECTION_EDGE["name"]] is True
        assert by_circuit[second][CONNECTION_EDGE["name"]] is False
    finally:
        _eqx_wipe(session)


def test_equinix_reasoner_writes_the_description_and_edge_device_edges(session):
    """One run: a switch port whose description names the SEC Fabric port and
    its cable id, a Network Edge device bound to a device of another source,
    and a circuit from the Network Edge eth0 to the SEC Fabric port. The
    reasoner binds the Fabric port by the description, puts the Network Edge
    interfaces on the bound device, and cables the circuit from the bound
    device's port to the switch port."""
    from tests.test_equinix_network_edge import CONNECTION_EDGE, EDGE_DEVICE, PORT_SEC, PORTS

    from hst import reasoner
    from hst.collectors.equinix import normalize_equinix
    from hst.collectors.util import canonical_mac
    from hst.core import uid as uidmod

    cts = 3_700_000_000_000
    bound = "vco:eqx-test:edge:edge-1"
    edge_dev = uidmod.equinix("device", EDGE_DEVICE["uuid"])
    switch_port = uidmod.port(_EQX_SWITCH, "Ethernet1/3")
    bound_port = uidmod.port(bound, "GE3")
    fabric_sec = uidmod.equinix("port", PORT_SEC)
    circuit = {
        **CONNECTION_EDGE,
        "zSide": {
            "accessPoint": {
                "type": "COLO",
                "port": {"uuid": PORT_SEC},
                "linkProtocol": {"type": "DOT1Q", "vlanTag": 831},
            }
        },
    }
    raw = {
        "fetched_at_ms": 1,
        "port_pages": [{"data": PORTS}],
        "connection_pages": [{"data": [circuit]}],
        "edge_device_pages": [{"data": [EDGE_DEVICE]}],
    }
    others = _eqx_switch_batch(
        description="TO EQUINIX FABRIC - ACME-XX1-EXT-SEC-01 - CABLE ID : 21000002",
        bound=bound,
        bound_mac=canonical_mac("00:00:5e:00:53:01"),
    )
    equinix_batch = normalize_equinix(
        raw,
        scope="test:eqx-runs",
        ibx_sites={},
        port_bindings={},
        edge_device_bindings={EDGE_DEVICE["uuid"]: bound},
    )

    _eqx_wipe(session)
    try:
        load(session, others, ts_ms=cts, run_id="it-eqx-desc-sw", collection_ts=cts)
        load(session, equinix_batch, ts_ms=cts, run_id="it-eqx-desc", collection_ts=cts)
        reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)

        def edges(query: str) -> list[dict]:
            return session.run(query, cts=cts).data()

        assert edges(
            "MATCH (fp:FabricPort {collection_ts: $cts})-[r:REALIZED_BY]->(p:Port) "
            "WHERE r._scope = 'reasoner' "
            "RETURN fp.uid AS fabric_port, p.uid AS port, r.rule AS rule, r.evidence AS evidence"
        ) == [
            {
                "fabric_port": fabric_sec,
                "port": switch_port,
                "rule": "fabric-port-from-description",
                "evidence": "name+cable",
            }
        ]
        assert edges(
            "MATCH (d:Device {collection_ts: $cts})-[r:SAME_AS]->(t:Device) WHERE r._scope = 'reasoner' "
            "RETURN d.uid AS edge_device, t.uid AS device, r.rule AS rule"
        ) == [{"edge_device": edge_dev, "device": bound, "rule": "edge-device-from-binding"}]
        assert edges(
            "MATCH (i:Interface {collection_ts: $cts})-[r:REALIZED_BY]->(p:Port) WHERE r._scope = 'reasoner' "
            "RETURN i.uid AS interface, p.uid AS port"
        ) == [{"interface": uidmod.interface(edge_dev, "eth0"), "port": bound_port}]
        on = edges(
            "MATCH (x:Obj {collection_ts: $cts})-[r:ON]->(t:Device) WHERE r._scope = 'reasoner' "
            "RETURN x.uid AS node, t.uid AS device"
        )
        assert sorted(row["node"] for row in on) == sorted(
            [
                uidmod.interface(edge_dev, "eth1"),
                uidmod.interface(edge_dev, "eth7"),
                uidmod.port(edge_dev, "eth1"),
                uidmod.port(edge_dev, "eth7"),
            ]
        )
        assert {row["device"] for row in on} == {bound}
        assert edges(
            "MATCH (a:Port)-[c:CONNECTED_TO {source: 'equinix-circuit'}]->(z:Port) "
            "WHERE c.collection_ts = $cts RETURN a.uid AS a, z.uid AS z, c.circuit_uid AS circuit"
        ) == [
            {
                "a": bound_port,
                "z": switch_port,
                "circuit": uidmod.equinix("connection", CONNECTION_EDGE["uuid"]),
            }
        ]
    finally:
        _eqx_wipe(session)


_VSX_CTS = 9_100_000_000_000


def _load_vsx(session):
    """A VSX appliance as the Gaia and the management collectors leave it.
    Returns the session pinned to the run the management nodes are stamped
    with, so the exact-current NAT credits read sees them.

    The Gaia source (scope test:vsx-gaia) owns the appliance Device, two
    FirewallInstance nodes for VSID 1 and 2, and each context's VrfInstance and
    interfaces. The management source (scope test:vsx-mgmt) owns one Device per
    virtual system object, carrying the management object uid as cp_raw_uid,
    and binds an access rulebase and a NAT rulebase to each with a configured
    ENFORCES edge. Observed installation bindings on each FirewallInstance
    correlate that context with the configured policy revision. VS 1 permits
    everything and hides behind 203.0.113.11; VS 2 drops everything and hides
    behind 203.0.113.12.

    A second management source (scope test:vsx-mgmt-other) holds a Device with
    the same raw uid as VS 1, bound to a rulebase that drops everything and a
    NAT rulebase that translates to 198.51.100.9. A join without the _scope
    guard would let that rulebase deny the VS 1 flow and that translation
    appear on its leg.
    """
    from hst import reasoner
    from hst.path.session import CycleSession

    session.run(
        """
CREATE (d:Obj:Device {uid: 'it:vsx:dev:appliance', hostname: 'vsx-a', role: 'firewall',
                      platform: 'checkpoint-gaia', _scope: 'test:vsx-gaia'})
CREATE (fi1:Obj:FirewallInstance {uid: 'it:vsx:fi:1', gateway_object_uid: 'vs-1',
                                   authority: 'test:vsx-mgmt', _scope: 'test:vsx-gaia'})
CREATE (fi2:Obj:FirewallInstance {uid: 'it:vsx:fi:2', gateway_object_uid: 'vs-2',
                                   authority: 'test:vsx-mgmt', _scope: 'test:vsx-gaia'})
CREATE (fi1)-[:RUNS_ON]->(d)
CREATE (fi2)-[:RUNS_ON]->(d)
CREATE (v1:Obj:VrfInstance {uid: 'it:vsx:vrf:1', name: 'vs:1', _scope: 'test:vsx-gaia'})
CREATE (v2:Obj:VrfInstance {uid: 'it:vsx:vrf:2', name: 'vs:2', _scope: 'test:vsx-gaia'})
CREATE (v1)-[:OWNED_BY]->(d)
CREATE (v2)-[:OWNED_BY]->(d)
CREATE (v1)-[:IN_CONTEXT]->(fi1)
CREATE (v2)-[:IN_CONTEXT]->(fi2)
CREATE (i1:Obj:Interface {uid: 'it:vsx:if:vs1-in', name: 'eth1.101', vsid: 1, _scope: 'test:vsx-gaia'})
CREATE (o1:Obj:Interface {uid: 'it:vsx:if:vs1-out', name: 'eth2.101', vsid: 1, _scope: 'test:vsx-gaia'})
CREATE (i2:Obj:Interface {uid: 'it:vsx:if:vs2-in', name: 'eth1.102', vsid: 2, _scope: 'test:vsx-gaia'})
CREATE (o2:Obj:Interface {uid: 'it:vsx:if:vs2-out', name: 'eth2.102', vsid: 2, _scope: 'test:vsx-gaia'})
FOREACH (i IN [i1, o1] | CREATE (i)-[:ON]->(d) CREATE (i)-[:IN_VRF]->(v1) CREATE (i)-[:IN_CONTEXT]->(fi1))
FOREACH (i IN [i2, o2] | CREATE (i)-[:ON]->(d) CREATE (i)-[:IN_VRF]->(v2) CREATE (i)-[:IN_CONTEXT]->(fi2))
CREATE (ip1:Obj:IpAddress {uid: 'it:vsx:ip:vs1-in', ip: '10.1.0.1', af: 4, _scope: 'test:vsx-gaia'})
CREATE (ip2:Obj:IpAddress {uid: 'it:vsx:ip:vs2-in', ip: '10.2.0.1', af: 4, _scope: 'test:vsx-gaia'})
CREATE (op1:Obj:IpAddress {uid: 'it:vsx:ip:vs1-out', ip: '203.0.113.1', af: 4, _scope: 'test:vsx-gaia'})
CREATE (op2:Obj:IpAddress {uid: 'it:vsx:ip:vs2-out', ip: '203.0.113.2', af: 4, _scope: 'test:vsx-gaia'})
CREATE (p1:Obj:Prefix {uid: 'it:vsx:pfx:vs1', cidr: '10.1.0.0/24', af: 4, kind: 'connected',
                        l3dom: 'vsx-1', anchor: 'vsx-1', _scope: 'test:vsx-gaia'})
CREATE (p2:Obj:Prefix {uid: 'it:vsx:pfx:vs2', cidr: '10.2.0.0/24', af: 4, kind: 'connected',
                        l3dom: 'vsx-2', anchor: 'vsx-2', _scope: 'test:vsx-gaia'})
CREATE (pd:Obj:Prefix {uid: 'it:vsx:pfx:default', cidr: '0.0.0.0/0', af: 4, _scope: 'test:vsx-gaia'})
CREATE (i1)-[:HAS_IP]->(ip1)
CREATE (i2)-[:HAS_IP]->(ip2)
CREATE (o1)-[:HAS_IP]->(op1)
CREATE (o2)-[:HAS_IP]->(op2)
CREATE (ip1)-[:IN]->(p1)
CREATE (ip2)-[:IN]->(p2)
CREATE (v1)-[:STATIC_ROUTE {interface: 'eth2.101'}]->(pd)
CREATE (v2)-[:STATIC_ROUTE {interface: 'eth2.102'}]->(pd)
CREATE (pd)-[:VIA {vrf: 'it:vsx:vrf:1'}]->(o1)
CREATE (pd)-[:VIA {vrf: 'it:vsx:vrf:2'}]->(o2)
// the management source: one Device per virtual system object, with the
// rulebases the package installation targets bind to it
CREATE (vs1:Obj:Device {uid: 'it:vsx:dev:vs1', hostname: 'vs1', role: 'firewall', platform: 'checkpoint',
                        cp_type: 'CpmiVsClusterNetobj', cp_raw_uid: 'vs-1', _scope: 'test:vsx-mgmt'})
CREATE (vs2:Obj:Device {uid: 'it:vsx:dev:vs2', hostname: 'vs2', role: 'firewall', platform: 'checkpoint',
                        cp_type: 'CpmiVsClusterNetobj', cp_raw_uid: 'vs-2', _scope: 'test:vsx-mgmt'})
CREATE (rb1:Obj:FwRulebase {uid: 'it:vsx:rb:1', name: 'vs1-access', kind: 'access', vendor: 'checkpoint',
                            default_action: 'drop', _scope: 'test:vsx-mgmt'})
CREATE (rb2:Obj:FwRulebase {uid: 'it:vsx:rb:2', name: 'vs2-access', kind: 'access', vendor: 'checkpoint',
                            default_action: 'drop', _scope: 'test:vsx-mgmt'})
CREATE (r1:Obj:FwRule {uid: 'it:vsx:rule:1', name: 'vs1-allow-all', position: 1, action: 'accept',
                       enabled: true, src_any: true, dst_any: true, svc_any: true, _scope: 'test:vsx-mgmt'})
CREATE (r2:Obj:FwRule {uid: 'it:vsx:rule:2', name: 'vs2-drop-all', position: 1, action: 'drop',
                       enabled: true, src_any: true, dst_any: true, svc_any: true, _scope: 'test:vsx-mgmt'})
CREATE (vs1)-[:ENFORCES {configured: true}]->(rb1)
CREATE (vs2)-[:ENFORCES {configured: true}]->(rb2)
CREATE (rb1)-[:HAS_RULE]->(r1)
CREATE (rb2)-[:HAS_RULE]->(r2)
CREATE (n1:Obj:FwRulebase {uid: 'it:vsx:rb:nat1', name: 'NAT:vs1', kind: 'nat', vendor: 'checkpoint',
                           _scope: 'test:vsx-mgmt'})
CREATE (n2:Obj:FwRulebase {uid: 'it:vsx:rb:nat2', name: 'NAT:vs2', kind: 'nat', vendor: 'checkpoint',
                           _scope: 'test:vsx-mgmt'})
CREATE (vs1)-[:ENFORCES {configured: true}]->(n1)
CREATE (vs2)-[:ENFORCES {configured: true}]->(n2)
CREATE (nr1:Obj:NatRule {uid: 'it:vsx:nat:1', name: 'vs1-hide', position: 1, method: 'hide', enabled: true,
                         _scope: 'test:vsx-mgmt'})
CREATE (nr2:Obj:NatRule {uid: 'it:vsx:nat:2', name: 'vs2-hide', position: 1, method: 'hide', enabled: true,
                         _scope: 'test:vsx-mgmt'})
CREATE (n1)-[:HAS_RULE]->(nr1)
CREATE (n2)-[:HAS_RULE]->(nr2)
CREATE (net1:Obj:NetObject {uid: 'it:vsx:obj:net1', name: 'vs1-net', kind: 'network', cidr: '10.1.0.0/24',
                            _scope: 'test:vsx-mgmt'})
CREATE (net2:Obj:NetObject {uid: 'it:vsx:obj:net2', name: 'vs2-net', kind: 'network', cidr: '10.2.0.0/24',
                            _scope: 'test:vsx-mgmt'})
CREATE (h1:Obj:NetObject {uid: 'it:vsx:obj:hide1', name: 'vs1-hide', kind: 'host', ip: '203.0.113.11',
                          _scope: 'test:vsx-mgmt'})
CREATE (h2:Obj:NetObject {uid: 'it:vsx:obj:hide2', name: 'vs2-hide', kind: 'host', ip: '203.0.113.12',
                          _scope: 'test:vsx-mgmt'})
CREATE (nr1)-[:ORIG_SRC]->(net1)
CREATE (nr1)-[:XLATE_SRC]->(h1)
CREATE (nr2)-[:ORIG_SRC]->(net2)
CREATE (nr2)-[:XLATE_SRC]->(h2)
// a second management source with the same raw uid as VS 1
CREATE (ox:Obj:Device {uid: 'it:vsx:dev:other-vs1', hostname: 'vs1', role: 'firewall', platform: 'checkpoint',
                       cp_type: 'CpmiVsClusterNetobj', cp_raw_uid: 'vs-1', _scope: 'test:vsx-mgmt-other'})
CREATE (orb:Obj:FwRulebase {uid: 'it:vsx:rb:other', name: 'other-access', kind: 'access',
                            vendor: 'checkpoint', default_action: 'drop', _scope: 'test:vsx-mgmt-other'})
CREATE (orr:Obj:FwRule {uid: 'it:vsx:rule:other', name: 'other-drop-all', position: 1, action: 'drop',
                        enabled: true, src_any: true, dst_any: true, svc_any: true,
                        _scope: 'test:vsx-mgmt-other'})
CREATE (onb:Obj:FwRulebase {uid: 'it:vsx:rb:other-nat', name: 'NAT:other', kind: 'nat', vendor: 'checkpoint',
                            _scope: 'test:vsx-mgmt-other'})
CREATE (onr:Obj:NatRule {uid: 'it:vsx:nat:other', name: 'other-hide', position: 1, method: 'hide',
                         enabled: true, _scope: 'test:vsx-mgmt-other'})
CREATE (oh:Obj:NetObject {uid: 'it:vsx:obj:other-hide', name: 'other-hide', kind: 'host',
                          ip: '198.51.100.9', _scope: 'test:vsx-mgmt-other'})
CREATE (ox)-[:ENFORCES {configured: true}]->(orb)
CREATE (orb)-[:HAS_RULE]->(orr)
CREATE (ox)-[:ENFORCES {configured: true}]->(onb)
CREATE (onb)-[:HAS_RULE]->(onr)
CREATE (onr)-[:ORIG_SRC]->(net1)
CREATE (onr)-[:XLATE_SRC]->(oh)"""
    ).consume()
    # Management installation targets alone are not evidence that a policy is
    # installed. Bind the observed revision to the exact VS context and family.
    session.run(
        """
UNWIND [
  {fi: 'it:vsx:fi:1', context: 'it:vsx:vrf:1', rulebases: ['it:vsx:rb:1', 'it:vsx:rb:nat1']},
  {fi: 'it:vsx:fi:2', context: 'it:vsx:vrf:2', rulebases: ['it:vsx:rb:2', 'it:vsx:rb:nat2']}
] AS binding
MATCH (fi:FirewallInstance {uid: binding.fi})
UNWIND binding.rulebases AS rulebase_uid
MATCH (rb:FwRulebase {uid: rulebase_uid})
SET rb.configured_revision = 'fixture-revision-1'
CREATE (fi)-[:ENFORCES {
  installed: true, installed_revision: 'fixture-revision-1', coverage: 'complete',
  context_uid: binding.context, ingress_interface_uid: '*', egress_interface_uid: '*',
  address_family: 4, collection_ts: $cts
}]->(rb)""",
        cts=_VSX_CTS,
    ).consume()
    # the management nodes and the FirewallInstances are stamped with the run,
    # the way the loader stamps them: the exact-current NAT credits read
    # accepts no unstamped node. The pinned session reads that run, and every
    # unstamped Gaia node coalesces to it as it does on the point path.
    session.run(
        """
MATCH (n:Obj)
WHERE n._scope IN ['test:vsx-mgmt', 'test:vsx-mgmt-other', 'test:vsx-gaia']
SET n.collection_ts = $cts""",
        cts=_VSX_CTS,
    ).consume()
    session.run(
        "MATCH (a:Obj {collection_ts: $cts})-[r]->(b:Obj {collection_ts: $cts}) "
        "WHERE r.collection_ts IS NULL SET r.collection_ts = $cts",
        cts=_VSX_CTS,
    ).consume()
    # the appliance is the sole owner of both connected prefixes, so the
    # reasoner credits each context's inside interface as the gateway
    reasoner.run(session, ts_ms=_VSX_CTS, collection_ts=_VSX_CTS)
    return CycleSession(session, _VSX_CTS)


def test_vsx_trace_is_judged_by_the_rulebase_of_the_ingress_interfaces_virtual_system(session):
    """The appliance Device carries no ENFORCES edge. The rulebase is found
    through the ingress interface's FirewallInstance, joined by cp_raw_uid to
    the virtual system's own Device under the _scope guard.

    Through VSID 1: permitted by rulebase 1 and by nothing else. Rulebase 2
    and the other management's rulebase both drop everything, and a deny
    from any candidate is the verdict, so a permit proves neither was a
    candidate. The leg names the deciding rulebase in `fw_uid`; `fw_uids`
    holds only the candidates a stage credited without deciding, and a
    Check Point device-wide candidate is never credited that way. Through
    VSID 2: blocked by rulebase 2, and the block is a deny, since the
    binding is configured."""
    from hst import path as pathmod

    pinned = _load_vsx(session)

    result = pathmod.trace(pinned, "10.1.0.0/24", "8.8.8.8", port=443, proto="tcp")
    assert "no gateway found" not in result["verdict"], result["verdict"]
    legs = [ll for ll in result["legs"] if not ll.get("blocked")]
    assert legs, result["verdict"]
    leg = legs[0]
    assert leg.get("egress") == "eth2.101", leg
    assert leg.get("fw_uid") == "it:vsx:rb:1", leg
    assert not leg.get("indeterminate"), leg
    hops = [h["uid"] for h in result["hops"]]
    assert "it:vsx:rule:1" in hops, hops
    assert not {"it:vsx:rb:2", "it:vsx:rule:2", "it:vsx:rb:other", "it:vsx:rule:other"} & set(hops), hops
    assert not result.get("unevaluated_gates"), result.get("unevaluated_gates")

    denied = pathmod.trace(pinned, "10.2.0.0/24", "8.8.8.8", port=443, proto="tcp")
    assert denied["legs"], denied["verdict"]
    leg = denied["legs"][0]
    assert leg.get("blocked"), denied["verdict"]
    assert not leg.get("indeterminate"), leg
    assert leg["fw_uid"] == "it:vsx:rb:2", leg
    assert leg["verdict"].startswith("BLOCKED by"), leg["verdict"]
    assert "it:vsx:rule:2" in [h["uid"] for h in denied["hops"]], denied["hops"]


def test_vsx_trace_applies_the_nat_rulebase_of_the_ingress_interfaces_virtual_system(session):
    """The NAT gate reads the same context branch: the VSID 1 flow leaves as
    VS 1's hide address, the VSID 2 flow as VS 2's, and the other
    management's translation for the same raw uid never appears."""
    from hst import path as pathmod
    from hst.path.gates.nat import _nat_rows, nat_rulebase_credits

    pinned = _load_vsx(session)

    rows = _nat_rows(pinned, "it:vsx:dev:appliance", in_if="it:vsx:if:vs1-in")
    assert [(r["rb_uid"], r["uid"]) for r in rows] == [("it:vsx:rb:nat1", "it:vsx:nat:1")]
    # the credits read is exact-current, so it runs on the pinned session
    credits = nat_rulebase_credits(pinned, "it:vsx:dev:appliance", "it:vsx:if:vs2-in")
    assert [(r["rb_uid"], r["rule_uids"]) for r in credits] == [("it:vsx:rb:nat2", ["it:vsx:nat:2"])]
    assert _nat_rows(pinned, "it:vsx:dev:appliance") == []

    result = pathmod.trace(pinned, "10.1.0.0/24", "8.8.8.8", port=443, proto="tcp")
    legs = [ll for ll in result["legs"] if not ll.get("blocked")]
    assert legs, result["verdict"]
    expected = [{"sources": ["10.1.0.0/24"], "to": "203.0.113.11", "rule_uid": "it:vsx:nat:1"}]
    assert legs[0]["snat"] == expected, legs[0]
    assert not legs[0].get("indeterminate"), legs[0]

    # VS 2 drops the flow at its access rulebase, so no leg carries its
    # translation; the rule rows show which rulebase the context selects
    rows = _nat_rows(pinned, "it:vsx:dev:appliance", in_if="it:vsx:if:vs2-in")
    assert [(r["rb_uid"], r["xlate_src_addrs"]) for r in rows] == [("it:vsx:rb:nat2", ["203.0.113.12"])]


# --- first-hop redundancy: a route whose next hop is a virtual address ------------------


def _fhrp_estate(session, *, with_state: bool) -> None:
    """A firewall whose route to 10.60.0.0/24 points at 10.20.0.1, the HSRP
    virtual address of a core pair. Each core holds the address on its own SVI
    in its own VrfInstance (the anchor the Cisco collectors use), marked with
    the protocol, the group and, when `with_state`, the member's role. The
    active member is core-b, whose uid sorts after core-a, so the lowest-uid
    rule and the state rule name different devices. The three VRFs share one
    declared RoutingDomain, the way a site's group source resolves them.
    """
    state_a = ", state: 'standby'" if with_state else ""
    state_b = ", state: 'active'" if with_state else ""
    session.run(
        """
CREATE (fw:Obj:Device {uid: 'it:dev:fw', hostname: 'fw', role: 'firewall', _scope: 'test:fhrp-next-hop'})
CREATE (fwv:Obj:VrfInstance {uid: 'it:vrf:fw', name: 'root', is_global: true, _scope: 'test:fhrp-next-hop'})
CREATE (fg:Obj:Interface {uid: 'it:if:fw-guest', name: 'guest0', _scope: 'test:fhrp-next-hop'})
CREATE (fc:Obj:Interface {uid: 'it:if:fw-core', name: 'core0', _scope: 'test:fhrp-next-hop'})
CREATE (fgip:Obj:IpAddress {uid: 'it:ip:fw-guest', ip: '10.50.0.1', af: 4, anchor: 'it:vrf:fw',
                             _scope: 'test:fhrp-next-hop'})
CREATE (fcip:Obj:IpAddress {uid: 'it:ip:fw-core', ip: '10.20.0.9', af: 4, anchor: 'it:vrf:fw',
                             _scope: 'test:fhrp-next-hop'})
CREATE (pg:Obj:Prefix {uid: 'it:pfx:fw-guest', cidr: '10.50.0.0/24', af: 4, kind: 'connected',
                        anchor: 'it:vrf:fw', _scope: 'test:fhrp-next-hop'})
CREATE (pt:Obj:Prefix {uid: 'it:pfx:fw-transit', cidr: '10.20.0.0/24', af: 4, kind: 'connected',
                        anchor: 'it:vrf:fw', _scope: 'test:fhrp-next-hop'})
CREATE (pd:Obj:Prefix {uid: 'it:pfx:fw-server', cidr: '10.60.0.0/24', af: 4, anchor: 'it:vrf:fw',
                        _scope: 'test:fhrp-next-hop'})
CREATE (fg)-[:ON]->(fw)
CREATE (fc)-[:ON]->(fw)
CREATE (fg)-[:HAS_IP]->(fgip)
CREATE (fc)-[:HAS_IP]->(fcip)
CREATE (fgip)-[:IN]->(pg)
CREATE (fcip)-[:IN]->(pt)
CREATE (fg)-[:IN_VRF]->(fwv)
CREATE (fc)-[:IN_VRF]->(fwv)
CREATE (fwv)-[:OWNED_BY]->(fw)
CREATE (fwv)-[:ORIGINATES {proto: 'connected'}]->(pt)
CREATE (fwv)-[:STATIC_ROUTE {next_hop: '10.20.0.1', interface: 'core0'}]->(pd)
CREATE (pd)-[:VIA {vrf: 'it:vrf:fw'}]->(fc)
CREATE (rd:Obj:RoutingDomain {uid: 'it:rdom:site', name: 'site', _scope: 'test:fhrp-next-hop'})
CREATE (fwv)-[:MEMBER_OF {basis: 'declared'}]->(rd)
"""
    ).consume()
    for name, own, state in (("core-a", "10.20.0.2", state_a), ("core-b", "10.20.0.3", state_b)):
        session.run(
            f"""
MATCH (rd:RoutingDomain {{uid: 'it:rdom:site'}})
CREATE (d:Obj:Device {{uid: 'it:dev:{name}', hostname: '{name}', role: 'router',
                       _scope: 'test:fhrp-next-hop'}})
CREATE (v:Obj:VrfInstance {{uid: 'it:vrf:{name}', name: 'default', is_global: true,
                            _scope: 'test:fhrp-next-hop'}})
CREATE (svi:Obj:Interface {{uid: 'it:if:{name}-vlan20', name: 'vlan20', kind: 'svi',
                            _scope: 'test:fhrp-next-hop'}})
CREATE (srv:Obj:Interface {{uid: 'it:if:{name}-vlan60', name: 'vlan60', kind: 'svi',
                            _scope: 'test:fhrp-next-hop'}})
CREATE (own:Obj:IpAddress {{uid: 'it:ip:{name}-own', ip: '{own}', af: 4, anchor: 'it:vrf:{name}',
                            _scope: 'test:fhrp-next-hop'}})
CREATE (vip:Obj:IpAddress {{uid: 'it:ip:{name}-vip', ip: '10.20.0.1', af: 4, anchor: 'it:vrf:{name}',
                            _scope: 'test:fhrp-next-hop'}})
CREATE (pt:Obj:Prefix {{uid: 'it:pfx:{name}-transit', cidr: '10.20.0.0/24', af: 4, kind: 'connected',
                        anchor: 'it:vrf:{name}', _scope: 'test:fhrp-next-hop'}})
CREATE (ps:Obj:Prefix {{uid: 'it:pfx:{name}-server', cidr: '10.60.0.0/24', af: 4, kind: 'connected',
                        anchor: 'it:vrf:{name}', _scope: 'test:fhrp-next-hop'}})
CREATE (g:Obj:FhrpGroup {{uid: 'it:fhrp:{name}-shared', kind: 'hsrp', group_id: 20, vip: '10.20.0.1',
                          _scope: 'test:fhrp-next-hop'}})
CREATE (svi)-[:ON]->(d)
CREATE (srv)-[:ON]->(d)
CREATE (svi)-[:HAS_IP]->(own)
CREATE (svi)-[:HAS_IP {{fhrp: 'hsrp', group: 20{state}}}]->(vip)
CREATE (g)-[:HAS_IP]->(vip)
CREATE (svi)-[:MEMBER_OF {{priority: 100{state}}}]->(g)
CREATE (own)-[:IN]->(pt)
CREATE (vip)-[:IN]->(pt)
CREATE (svi)-[:IN_VRF]->(v)
CREATE (srv)-[:IN_VRF]->(v)
CREATE (v)-[:OWNED_BY]->(d)
CREATE (v)-[:ORIGINATES {{proto: 'connected'}}]->(pt)
CREATE (v)-[:STATIC_ROUTE {{interface: 'vlan60'}}]->(ps)
CREATE (ps)-[:VIA {{vrf: 'it:vrf:{name}'}}]->(srv)
CREATE (v)-[:MEMBER_OF {{basis: 'declared'}}]->(rd)
"""
        ).consume()


def _fhrp_trace(session):
    from hst import path as pathmod
    from hst import reasoner

    reasoner.run(session, ts_ms=9_000_000_000_000, collection_ts=_publish(session))
    result = pathmod.trace(session, "10.50.0.0/24", "10.60.0.7", port=443, proto="tcp")
    assert "no gateway found" not in result["verdict"], result["verdict"]
    assert result["legs"], result["verdict"]
    return result


def test_a_next_hop_on_a_virtual_address_lands_on_the_active_member(session):
    """core-a sorts first by uid and is the standby."""
    _fhrp_estate(session, with_state=True)
    result = _fhrp_trace(session)
    devices = [h["uid"] for h in result["hops"] if h["kind"] == "Device"]
    assert "it:dev:core-b" in devices, result["hops"]
    assert "it:dev:core-a" not in devices, result["hops"]
    assert any("2 interfaces hold next hop 10.20.0.1 in one hsrp group 20" in n for n in result["notes"]), (
        result["notes"]
    )
    assert any("traced via core-b vlan20 (hsrp active member)" in n for n in result["notes"]), result["notes"]
    assert not any("owned in 2 forwarding contexts" in w for w in result["warnings"]), result["warnings"]


def test_a_next_hop_on_a_virtual_address_with_no_state_falls_back_to_the_lowest_uid(session):
    """Members whose edges record no state settle by the lowest device uid."""
    _fhrp_estate(session, with_state=False)
    result = _fhrp_trace(session)
    devices = [h["uid"] for h in result["hops"] if h["kind"] == "Device"]
    assert "it:dev:core-a" in devices, result["hops"]
    assert "it:dev:core-b" not in devices, result["hops"]
    assert any("traced via core-a vlan20 (lowest uid)" in n for n in result["notes"]), result["notes"]


def test_every_catalog_query_compiles(session):
    """EXPLAIN every catalog entry against the real server. A catalog query is
    written by hand and runs only when an operator opens it, so a syntax or
    semantics error in one surfaces first in the UI; the planner catches both
    without touching data. Parameters are bound to placeholders: EXPLAIN does
    not evaluate them."""
    from hst.queries import catalog

    failures = []
    for q in catalog():
        params = {"snap": 0, **{p["name"]: "x" for p in q.get("params", [])}}
        try:
            session.run("EXPLAIN " + q["cypher"], parameters=params).consume()
        except Exception as exc:  # every failure is reported together
            failures.append(f"{q['key']}: {type(exc).__name__}: {exc}")
    assert not failures, "\n".join(failures)


def _plan_operators(plan: Any) -> list[str]:
    """Every operator of an EXPLAIN plan, the whole tree."""
    out = [plan["operatorType"]]
    for child in plan.get("children") or []:
        out += _plan_operators(child)
    return out


def test_every_topology_read_compiles(session):
    """EXPLAIN the unified map's reads and its segment list read
    (app/routes/topology.py), for the same reason as the map's. Every read
    after the device read starts from the drawn devices by uid, so its plan
    seeks obj_uid_cts and scans no label of every retained run."""
    from hst.app.routes import topology

    reads = {
        "devices": topology._DEVICES,
        "site_devices": topology._SITE_DEVICES,
        "cables": topology._CABLES,
        "lags": topology._LAGS,
        "groups": topology._GROUPS,
        "wan_devices": topology._WAN_DEVICES,
        "clients": topology._CLIENTS,
        "vlans": topology._VLANS,
        "subnets": topology._SUBNETS,
        "attached": topology._ATTACHED,
        "segment_clients": topology._SEGMENT_CLIENTS,
        "site_segment_clients": topology._SITE_SEGMENT_CLIENTS,
        "segment_page": topology._SEGMENT_PAGE_QUERY,
        "site_segment_page": topology._SITE_SEGMENT_PAGE_QUERY,
    }
    anchored = {
        "cables",
        "lags",
        "groups",
        "wan_devices",
        "clients",
        "vlans",
        "subnets",
        "attached",
        "site_segment_clients",
        "site_segment_page",
    }
    # the parameters of the segment page reads (topology.py `_SEGMENT_PAGE_TAIL`)
    page = {"keep": [], "macs": [], "hex": [], "offset": 0, "limit": 1, "after_name": None, "after_uid": None}
    failures = []
    for name, cypher in reads.items():
        try:
            summary = session.run(
                "EXPLAIN " + cypher,
                parameters={"snap": 0, "site": ["x"], "bd": "x", "devs": ["dev:x"], **page},
            ).consume()
        except Exception as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if name in anchored:
            ops = _plan_operators(summary.plan)
            # obj_uid_cts, or a label's uid index (core/db.py) where the
            # planner prefers it: either seeks the drawn devices by uid
            if not any(op.startswith(("NodeUniqueIndexSeek", "NodeIndexSeek")) for op in ops):
                failures.append(f"{name}: no uid index seek: {ops}")
            scans = [op for op in ops if op.startswith(("NodeByLabelScan", "AllNodesScan"))]
            if scans:
                failures.append(f"{name}: scans {scans}")
    assert not failures, "\n".join(failures)


def test_the_topology_segment_relation_reads_compile(session):
    """EXPLAIN the attachment and bridge-domain prefix reads of app/routes/topology.py."""
    from hst.app.routes import topology

    for cypher in (topology._ATTACHED, topology._SEGMENT_PREFIXES):
        session.run("EXPLAIN " + cypher, parameters={"snap": 0, "devs": ["x"], "bds": ["x"]}).consume()


def test_the_topology_reads_plan_the_enterprise_fixture_site(session):
    """The five reads against the loaded mini-enterprise graph, through the
    planner: the fra01 devices by their site code, the cable that two sources
    report as one line, and the SD-WAN edge anchored by its WAN links."""
    from hst.app.routes import topology
    from hst.diagram import planner

    cts = 3_100_000_000_000
    load(session, load_fixture(ENTERPRISE_FIXTURE), ts_ms=cts, run_id="it-run-topology", collection_ts=cts)
    # the reads take Site uids; the route turns the codes asked for into them
    devices = session.run(
        topology._SITE_DEVICES, parameters={"snap": cts, "site": topology._site_uids(["fra01"])}
    ).data()
    params = {"snap": cts, "devs": sorted({d["uid"] for d in devices})}
    cables = session.run(topology._CABLES, parameters=params).data()
    lags = session.run(topology._LAGS, parameters=params).data()
    groups = session.run(topology._GROUPS, parameters=params).data()
    wan = [r["dev"] for r in session.run(topology._WAN_DEVICES, parameters=params).data()]

    assert {d["site"] for d in devices} == {"fra01"}
    assert "dev:fra01-vce-01" in wan
    model = planner.plan(devices, cables, lags, groups, wan)
    nodes = {n["id"]: n for n in model["nodes"]}
    assert nodes["dev:fra01-vce-01"]["anchor"] == "wan-link"
    assert nodes["dev:fra01-fgt-01"]["parent"].startswith("block:fra01:firewall")
    pairs = sorted(tuple(sorted((c["from"]["dev"], c["to"]["dev"]))) for c in model["cables"])
    assert pairs == [
        ("dev:fra01-core-01", "dev:fra01-core-02"),
        ("dev:fra01-core-01", "dev:fra01-ips-01"),
        ("dev:fra01-fgt-01", "dev:fra01-ips-01"),
    ]


def test_every_site_graph_read_compiles(session):
    """EXPLAIN the site graph route's seven reads (app/routes/site_graph.py),
    for the same reason as the map's."""
    from hst.app.routes import site_graph

    reads = {
        "devices": site_graph._SITE_DEVICES,
        "cables": site_graph._CABLES,
        "circuits": site_graph._CIRCUITS,
        "tunnel_ends": site_graph._TUNNEL_ENDS,
        "subnet_members": site_graph._SUBNET_MEMBERS,
        "bgp": site_graph._BGP,
        "wan": site_graph._WAN,
    }
    failures = []
    for name, cypher in reads.items():
        try:
            session.run("EXPLAIN " + cypher, parameters={"snap": 0}).consume()
        except Exception as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failures, "\n".join(failures)


def test_every_equinix_read_compiles(session):
    """EXPLAIN the Equinix route's five reads (app/routes/equinix.py), for the
    same reason as the map's."""
    from hst.app.routes import equinix as equinix_route

    reads = {
        "metros": equinix_route._METROS,
        "edge_metros": equinix_route._EDGE_METROS,
        "ports": equinix_route._PORTS,
        "edge_devices": equinix_route._EDGE_DEVICES,
        "circuits": equinix_route._CIRCUITS,
    }
    failures = []
    for name, cypher in reads.items():
        try:
            session.run("EXPLAIN " + cypher, parameters={"snap": 0, "metro": "x"}).consume()
        except Exception as exc:
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failures, "\n".join(failures)


def test_reasoner_pairs_a_velocloud_edge_with_its_router_by_bgp_and_cables_it_by_arp(session, tmp_path):
    """The VeloCloud edge publishes no MAC and its switch speaks no LLDP to it.
    Two facts remain: the router's BGP session names the edge's LAN address
    and the edge's names the router's (bgp-peer-from-address); the switch's
    ARP row for the edge address and its MAC table put that MAC alone on one
    port (cable-from-arp-port, read from the side store)."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "enterprise"))
    import test_velocloud as tv

    from hst import reasoner
    from hst.collectors.util import GraphBuilder, connected_address
    from hst.collectors.velocloud import normalize_velocloud
    from hst.core import sidestore, uid

    cts = 3_400_000_000_000
    load(
        session,
        normalize_velocloud(tv._overlay_raw()),
        ts_ms=cts,
        run_id="it-vco",
        collection_ts=cts,
    )

    # a router whose corp VRF peers with the branch edge on 10.9.9.0/24
    b = GraphBuilder()
    dev = b.node("Device", "dev:rtr1", hostname="rtr1", serial="rtr1", role="router", platform="nxos")
    vrf = b.node("VrfInstance", uid.vrf(dev, "corp"), name="corp", is_global=False)
    b.rel("OWNED_BY", "VrfInstance", vrf, "Device", dev)
    iu = b.node("Interface", uid.interface(dev, "Vlan10"), name="Vlan10", kind="svi")
    b.rel("ON", "Interface", iu, "Device", dev)
    b.rel("IN_VRF", "Interface", iu, "VrfInstance", vrf)
    ipu, _ = connected_address(b, "10.9.9.2/24", anchor=vrf, dom="corp", vrf_uid=vrf)
    b.rel("HAS_IP", "Interface", iu, "IpAddress", ipu)
    pu = b.node("Port", uid.port(dev, "Ethernet1/7"), name="Ethernet1/7")
    b.rel("ON", "Port", pu, "Device", dev)
    ru = b.node("RoutingProcess", uid.routing_process(dev, "corp", "bgp"), proto="bgp", asn=65000)
    b.rel("IN_VRF", "RoutingProcess", ru, "VrfInstance", vrf)
    su = b.node(
        "BgpSession",
        uid.bgp_session(ru, "10.9.9.1", "corp"),
        local_asn=65000,
        peer_asn=65010,
        peer_ip="10.9.9.1",
    )
    b.rel("HAS", "RoutingProcess", ru, "BgpSession", su)
    peer = b.node("IpAddress", uid.ip(vrf, "10.9.9.1"), ip="10.9.9.1", af=4, anchor=vrf, l3dom="corp")
    b.rel("ENDPOINT", "BgpSession", su, "IpAddress", peer)
    load(session, b.batch("nxos", "rtr1"), ts_ms=cts + 1, run_id="it-rtr", collection_ts=cts)

    results = reasoner.run(session, ts_ms=cts + 2, collection_ts=cts)
    cyclemod.set_pointer(session, cts)
    bgp = next(r for r in results if r["rule"] == "bgp-peer-from-address")
    assert bgp["edges"] == 1
    row = session.run(
        "MATCH (a:BgpSession)-[p:PEERS_WITH]->(z:BgpSession) "
        "RETURN a.uid AS a, z.uid AS z, p.rule AS rule, p.derived AS derived"
    ).single()
    assert row is not None and row["rule"] == "bgp-peer-from-address" and row["derived"] is True
    edge_session = uid.bgp_session(
        uid.routing_process("vco:ent-1:edge:e-br", "corp", "bgp"), "10.9.9.2", "corp"
    )
    assert {row["a"], row["z"]} == {su, edge_session}

    # the switch side: ARP holds the edge's LAN address, the MAC table puts
    # that MAC alone on Ethernet1/7
    sidestore.write_table(
        tmp_path,
        "arp",
        "nxos",
        "rtr1",
        "it-rtr",
        [
            {
                "device_uid": dev,
                "vrf": "corp",
                "context_uid": vrf,
                "ip": "10.9.9.1",
                "mac": "aabbcc000011",
                "interface_name": "Vlan10",
                "af": 4,
            }
        ],
        snapshot_ts=cts,
    )
    sidestore.write_table(
        tmp_path,
        "mac",
        "nxos",
        "rtr1",
        "it-rtr",
        [
            {
                "device_uid": dev,
                "vlan": 10,
                "mac": "aabbcc000011",
                "port_name": "Ethernet1/7",
                "bridge_domain_uid": None,
            }
        ],
        snapshot_ts=cts,
    )
    report = reasoner.derive_arp_cables(session, collection_ts=cts, sidestore_dir=tmp_path, ts_ms=cts + 3)
    assert report["edges"] == 1, report
    row = session.run(
        "MATCH (:Port {uid: $p})-[c:CONNECTED_TO]-(z:Port) "
        "RETURN z.uid AS z, c.rule AS rule, c.basis AS basis",
        p=pu,
    ).single()
    assert row is not None and row["rule"] == "cable-from-arp-port"
    assert row["z"] == uid.port("vco:ent-1:edge:e-br", "GE3")
    assert row["basis"] == "arp 10.9.9.1 mac aabbcc000011 port Ethernet1/7"


def test_trace_crosses_from_a_branch_to_a_hub_behind_nat(session):
    """A branch LAN host to a hub LAN host in one segment. The hub's public
    link sits behind NAT: its interface holds a private address and the
    orchestrator sees the link by another. The DIA carrier ends on the hub
    through the link that holds the address after NAT, and the inner flow
    resumes there."""
    from enterprise import test_velocloud as tvc
    from hst import path as pathmod
    from hst import reasoner
    from hst.collectors.velocloud import normalize_velocloud

    raw = tvc._overlay_raw()
    ent = raw["enterprises"][0]
    # the profile names the hub in the corp segment too
    ent["profiles"][str(tvc.PROFILE_ID)]["modules"][0]["data"]["segments"][1]["vpn"] = {
        "enabled": True,
        "edgeToEdgeDetail": {"vpnHubs": tvc.HUB_REFS},
    }
    tvc._hub_override(raw)["routedInterfaces"].append(
        {
            "name": "GE2",
            "wanOverlay": "AUTO_DISCOVERED",
            "segmentId": -1,
            "addressing": {"type": "STATIC", "cidrIp": "10.99.0.2", "cidrPrefix": 30, "gateway": "10.99.0.1"},
        }
    )
    # the branch's public link leaves by GE2 toward its WAN next hop: the DIA
    # carrier needs it, and the fixture names no gateway on that interface
    branch = ent["edges"][0]
    assert branch["logicalId"] == "e-br", branch["logicalId"]
    next(
        m["edgeSpecificData"]
        for m in branch["configuration"]["enterprise"]["modules"]
        if m["name"] == "deviceSettings"
    )["routedInterfaces"].append(
        {
            "name": "GE2",
            "wanOverlay": "AUTO_DISCOVERED",
            "segmentId": -1,
            "addressing": {
                "type": "STATIC",
                "cidrIp": "198.51.100.2",
                "cidrPrefix": 30,
                "gateway": "198.51.100.1",
            },
        }
    )
    batch = normalize_velocloud(raw, scope="test:vco-nat-hub")
    load(session, batch, ts_ms=5_000_000_000_000, run_id="it-vco-nat", collection_ts=5_000_000_000_000)
    # the reasoner writes GATEWAY_FOR from the edge LAN interfaces to their prefixes
    reasoner.run(session, ts_ms=5_000_000_000_001, collection_ts=5_000_000_000_000)
    cyclemod.set_pointer(session, 5_000_000_000_000)

    # the source is the branch LAN: a host address needs a node of its own
    result = pathmod.trace(session, "10.10.10.0/24", "10.20.20.30", port=443, proto="tcp")
    verdicts = [(leg.get("carrier") or {}).get("verdict") or "" for leg in result["legs"]]
    assert any("decapsulated on hub-1" in v for v in verdicts), (result["verdict"], verdicts)


# --- ZPA rule scope on collector output -------------------------------------------------------

_ZPA_SCOPES = ["zpa:acme", "zpa:other"]


def _zpa_wipe(session) -> None:
    session.run("MATCH (n:Obj) WHERE n._scope IN $scopes DETACH DELETE n", scopes=_ZPA_SCOPES).consume()


def _zpa_scim(group: int) -> dict:
    return {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": str(group), "idpId": "idp-1"}]}


def _zpa_app(segment: str) -> dict:
    return {"operator": "OR", "operands": [{"objectType": "APP", "rhs": segment}]}


def _zpa_rule(order: int, name: str, action: str, *conditions: dict, **extra) -> dict:
    return {
        "id": f"90{order}",
        "name": name,
        "action": action,
        "ruleOrder": str(order),
        "priority": str(8 - order),
        "conditions": list(conditions),
        **extra,
    }


def _zpa_scope_run(session, cts: int) -> None:
    """Tenant acme: segments CRM, ERP and HR in the app groups crm-apps,
    erp-apps and hr-apps, the SCIM groups IT, Sales, Eng and Contractors, and
    rules 1 to 7 by ruleOrder (priority runs the other way). Tenant other: one
    segment and one deny rule with no conditions."""
    from hst.collectors.zpa import normalize_zpa

    def segment(sid: str, name: str, group: str | None) -> dict:
        seg = {
            "id": sid,
            "name": name,
            "domainNames": [f"{name}.corp.internal"],
            "tcpPortRanges": ["443", "443"],
        }
        return {**seg, "segmentGroupId": group} if group else seg

    acme = {
        "app_segments": [
            segment("2001", "CRM", "3001"),
            segment("2002", "ERP", "3002"),
            segment("2003", "HR", "3003"),
        ],
        "segment_groups": [
            {"id": "3001", "name": "crm-apps"},
            {"id": "3002", "name": "erp-apps"},
            {"id": "3003", "name": "hr-apps"},
        ],
        "scim_groups": [
            {"id": 71, "idpId": "idp-1", "name": "IT"},
            {"id": 72, "idpId": "idp-1", "name": "Sales"},
            {"id": 73, "idpId": "idp-1", "name": "Eng"},
            {"id": 74, "idpId": "idp-1", "name": "Contractors"},
        ],
        "access_rules": [
            _zpa_rule(1, "IT allow all apps", "ALLOW", _zpa_scim(71)),
            _zpa_rule(2, "Sales deny CRM", "DENY", _zpa_app("2001"), _zpa_scim(72), disabled="1"),
            _zpa_rule(3, "Sales allow CRM", "ALLOW", _zpa_app("2001"), _zpa_scim(72)),
            _zpa_rule(4, "Eng approval CRM", "REQUIRE_APPROVAL", _zpa_app("2001"), _zpa_scim(73)),
            _zpa_rule(5, "deny CRM", "DENY", _zpa_app("2001")),
            _zpa_rule(
                6,
                "SAML allow ERP",
                "ALLOW",
                _zpa_app("2002"),
                {"operator": "OR", "operands": [{"objectType": "SAML", "lhs": "attr-1", "rhs": "admins"}]},
            ),
            _zpa_rule(7, "Contractors allow ERP", "ALLOW", _zpa_app("2002"), _zpa_scim(74)),
        ],
    }
    other = {
        "app_segments": [segment("9001", "OTHER", None)],
        "access_rules": [_zpa_rule(1, "other deny all", "DENY")],
    }
    load(
        session, normalize_zpa(acme, tenant="acme"), ts_ms=cts, run_id=f"it-zpa-acme-{cts}", collection_ts=cts
    )
    load(
        session,
        normalize_zpa(other, tenant="other"),
        ts_ms=cts,
        run_id=f"it-zpa-other-{cts}",
        collection_ts=cts,
    )
    cyclemod.set_pointer(session, cts)


def _zpa_ids():
    from hst.core import uid as uidmod

    groups = {
        name: uidmod.zpa("acme", "idp", f"idp-1-{gid}")
        for name, gid in (("IT", 71), ("Sales", 72), ("Eng", 73), ("Contractors", 74))
    }
    segments = {
        name: uidmod.zpa("acme", "seg", sid)
        for name, sid in (("CRM", "2001"), ("ERP", "2002"), ("HR", "2003"))
    }
    rules = {n: uidmod.zpa("acme", "rule", f"90{n}") for n in range(1, 8)}
    return groups, segments, rules


def test_zpa_access_rule_query_reads_rule_scope_on_collector_output(session):
    from hst import path as pathmod
    from hst.core import snapshot as snapshotmod
    from hst.path.gates import zpa as gate

    cts = 3_700_000_000_000
    _zpa_wipe(session)
    try:
        _zpa_scope_run(session, cts)
        pinned = pathmod.pinned(session, snapshotmod.Snapshot(cts, Settings(_env_file=None)))
        groups, segments, rules = _zpa_ids()

        def decide(group: str, segment: str):
            d = gate._access_rule_match(pinned, groups[group], segments[segment])
            return (d.rule["uid"] if d.rule else None), d.action, d.indeterminate, d.reason

        for segment in ("CRM", "ERP", "HR"):
            assert decide("IT", segment)[:3] == (rules[1], "allow", False)
        assert decide("Sales", "CRM")[:3] == (rules[3], "allow", False)
        uid, _action, undecided, reason = decide("Eng", "CRM")
        assert (uid, undecided) == (rules[4], True) and "require_approval" in reason
        assert decide("Contractors", "CRM")[:3] == (rules[5], "deny", False)
        uid, _action, undecided, _reason = decide("Contractors", "ERP")
        assert (uid, undecided) == (rules[6], True)
        for group in groups:
            for segment in segments:
                rule_uid = decide(group, segment)[0]
                assert rule_uid is None or rule_uid.startswith("zpa:acme:"), (group, segment)
    finally:
        _zpa_wipe(session)


def test_both_zpa_engines_choose_the_same_rule_on_collector_output(session):
    from types import SimpleNamespace

    from hst import path as pathmod
    from hst.analysis_model.gates import zpa_rule_decision
    from hst.analysis_model.graph import load_graph
    from hst.core import snapshot as snapshotmod
    from hst.path.gates import zpa as gate

    cts = 3_700_000_060_000
    _zpa_wipe(session)
    try:
        _zpa_scope_run(session, cts)
        pinned = pathmod.pinned(session, snapshotmod.Snapshot(cts, Settings(_env_file=None)))
        graph = load_graph(
            session,
            SimpleNamespace(cts=cts, manifest=object(), settings=Settings(_env_file=None)),
            "a" * 64,
            digest_reader=lambda: "a" * 64,
        )
        groups, segments, _rules = _zpa_ids()
        for group in groups.values():
            for segment in segments.values():
                path_answer = gate._access_rule_match(pinned, group, segment)
                model_answer = zpa_rule_decision(graph, group, segment)
                assert (
                    path_answer.rule["uid"] if path_answer.rule else None,
                    path_answer.action,
                    path_answer.indeterminate,
                ) == (
                    model_answer.rule["uid"] if model_answer.rule else None,
                    model_answer.action,
                    model_answer.indeterminate,
                ), (group, segment)
    finally:
        _zpa_wipe(session)


def test_zpa_catalog_queries_read_rule_scope_on_collector_output(session):
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}
    cts = 3_700_000_120_000
    _zpa_wipe(session)
    try:
        _zpa_scope_run(session, cts)
        rows = session.run(cypher["zpa-groups-without-rules"], snap=cts).data()
        assert [r["segment_group"] for r in rows] == ["hr-apps"]
        assert rows[0]["rules_without_named_apps"] == ["IT allow all apps"]
        it = session.run(cypher["zpa-user-group"], snap=cts, user_group="IT").data()
        assert it[0]["rules"] == 1 and it[0]["rules_without_named_apps"] == ["IT allow all apps"]
        policy = session.run(cypher["zpa-policy-rules"], snap=cts).data()
        everyone = {r["rule"] for r in policy if r["policy"] == "access" and r["everyone"]}
        assert "deny CRM" in everyone and "SAML allow ERP" not in everyone
        crm = session.run(cypher["zpa-app-group"], snap=cts, app_group="crm-apps").data()
        assert "Eng" in {g["name"] for g in crm[0]["_user_groups"]}
    finally:
        _zpa_wipe(session)


def test_only_an_active_fabric_circuit_becomes_a_link(session):
    """Beside the ACTIVE circuit, a PENDING circuit and a circuit with no
    state join the same two bound Fabric ports. Only the ACTIVE one draws a
    CONNECTED_TO and a stretch observation; the rule counts the other two."""
    from hst import reasoner
    from hst.collectors.util import GraphBuilder
    from hst.core import uid as uidmod

    cts = 3_300_000_500_000
    wipe = "MATCH (n:Obj {_scope: 'test:equinix-circuit'}) DETACH DELETE n"
    session.run(wipe).consume()
    batch = _equinix_circuit_batch()
    extra = GraphBuilder()
    fr2_port, pa3_port = uidmod.equinix("port", "port-fr2"), uidmod.equinix("port", "port-pa3")
    for cid, state in (("c-pending", "PENDING"), ("c-none", None)):
        props = {"name": cid, **({"state": state} if state else {})}
        vc = extra.node("VirtualCircuit", uidmod.equinix("connection", cid), **props)
        extra.rel("A_END", "VirtualCircuit", vc, "FabricPort", fr2_port, link_protocol="dot1q", vlan_tag=100)
        extra.rel("Z_END", "VirtualCircuit", vc, "FabricPort", pa3_port, link_protocol="dot1q", vlan_tag=100)
    added = extra.batch("test", "test:equinix-circuit")
    batch.nodes.extend(n for n in added.nodes if n.label == "VirtualCircuit")
    batch.rels.extend(added.rels)
    try:
        load(session, batch, ts_ms=cts, run_id="it-eqx-states", collection_ts=cts)
        results = reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
        cyclemod.set_pointer(session, cts)
        circuit_rule = next(r for r in results if r["rule"] == "cable-from-fabric-circuit")
        assert circuit_rule["edges"] == 1
        assert circuit_rule["not_active"] == 2
        circuits = session.run(
            "MATCH (:Port)-[c:CONNECTED_TO {source: 'equinix-circuit'}]->(:Port) RETURN c.circuit_uid AS uid"
        ).data()
        assert [r["uid"] for r in circuits] == ["eqx:connection:c-100"]
        report = reasoner.check_vlan_stretch(session, collection_ts=cts)
        assert [(o["kind"], o["vid"]) for o in report["observations"]] == [("stretched", 100)]
    finally:
        session.run(wipe).consume()


def test_zpa_segment_domain_to_dns_joins_a_segment_to_the_dns_record_of_its_name(session):
    from hst import reasoner
    from hst.collectors.util import GraphBuilder
    from hst.collectors.zpa import normalize_zpa

    cts = 3_700_000_180_000
    scopes = ["zpa:dns", "test:zpa-dns"]
    wipe = "MATCH (n:Obj) WHERE n._scope IN $scopes DETACH DELETE n"
    session.run(wipe, scopes=scopes).consume()
    seg = {
        "id": "2001",
        "name": "crm",
        "domainNames": ["crm.corp.internal", "gone.corp.internal", "10.20.0.5"],
    }
    b = GraphBuilder()
    rec = b.node("DnsRecord", "dns:crm.corp.internal:A", fqdn="crm.corp.internal", type="A")
    ip = b.node("IpAddress", "ip:zpa-dns:10.40.0.7", ip="10.40.0.7")
    b.rel("RESOLVES_TO", "DnsRecord", rec, "IpAddress", ip)
    try:
        load(
            session,
            normalize_zpa({"app_segments": [seg]}, tenant="dns"),
            ts_ms=cts,
            run_id="it-zpa-dns",
            collection_ts=cts,
        )
        load(session, b.batch("test", "test:zpa-dns"), ts_ms=cts, run_id="it-zpa-dns-rec", collection_ts=cts)
        results = reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
        rule = next(r for r in results if r["rule"] == "zpa-segment-domain-to-dns")
        assert rule["edges"] == 1 and rule["unresolved"] == 1
        rows = session.run(
            "MATCH (s:ZpaAppSegment)-[r:RESOLVES_TO]->(d:DnsRecord) RETURN r.domain AS domain, d.fqdn AS fqdn"
        ).data()
        assert rows == [{"domain": "crm.corp.internal", "fqdn": "crm.corp.internal"}]
    finally:
        session.run(wipe, scopes=scopes).consume()


def test_zia_far_end_roles_and_private_service_edges(session):
    """The secondary data center sorts first by uid and is a Private Service Edge."""
    from tests.test_zia import LOCATION_HQ, RAW

    from hst.collectors.zia import normalize_zia
    from hst.queries import QUERIES

    trace_mod = __import__("sys").modules["hst.path.trace"]
    cypher = {q["key"]: q["cypher"] for q in QUERIES}
    cts = 3_700_000_240_000
    wipe = "MATCH (n:Obj) WHERE n._scope = 'zia:roles' DETACH DELETE n"
    session.run(wipe).consume()
    gre = {
        "id": 5001,
        "sourceIp": LOCATION_HQ["ipAddresses"][0],
        "primaryDestVip": {"virtualIp": "104.129.194.38", "datacenter": "Zurich"},
        "secondaryDestVip": {
            "virtualIp": "10.9.0.1",
            "datacenter": "Amsterdam PSE",
            "privateServiceEdge": True,
        },
    }
    try:
        load(
            session,
            normalize_zia({**RAW, "gre_tunnels": [gre]}, tenant="roles"),
            ts_ms=cts,
            run_id="it-zia-roles",
            collection_ts=cts,
        )
        cyclemod.set_pointer(session, cts)
        row = session.run(trace_mod._CARRIER_TUNNEL_QUERY, uid="zia:roles:gre:5001", snap=cts).single()
        assert (
            row["far_role"] == "primary"
            and row["far_name"] == "Zurich"
            and row["far_vip"] == "104.129.194.38"
        )
        locations = session.run(cypher["zia-location-egress"], snap=cts, location_group="").data()
        hq = [r for r in locations if r["location"] == LOCATION_HQ["name"]]
        assert hq and hq[0]["service_edges"] == ["Amsterdam PSE"] and hq[0]["egress_dcs"] == ["Zurich"]
        assert "fewer than 2 data centers" in hq[0]["gaps"] and hq[0]["primary_dcs"] == ["Zurich"]
        users = session.run(cypher["zia-dc-users"], snap=cts, dc="Zurich").data()
        assert users and users[0]["roles"] == ["primary"]
    finally:
        session.run(wipe).consume()


def test_the_carrier_tunnel_read_counts_every_far_end(session):
    """The carrier's one tunnel read keeps the primary far end and counts
    both data centers the GRE tunnel terminates on."""
    from tests.test_zia import LOCATION_HQ, RAW

    from hst.collectors.zia import normalize_zia

    trace_mod = __import__("sys").modules["hst.path.trace"]
    cts = 3_700_000_250_000
    wipe = "MATCH (n:Obj) WHERE n._scope = 'zia:far-ends' DETACH DELETE n"
    session.run(wipe).consume()
    gre = {
        "id": 5002,
        "sourceIp": LOCATION_HQ["ipAddresses"][0],
        "primaryDestVip": {"virtualIp": "104.129.194.38", "datacenter": "Zurich"},
        "secondaryDestVip": {"virtualIp": "165.225.72.38", "datacenter": "Frankfurt"},
    }
    try:
        load(
            session,
            normalize_zia({**RAW, "gre_tunnels": [gre]}, tenant="far-ends"),
            ts_ms=cts,
            run_id="it-zia-far-ends",
            collection_ts=cts,
        )
        cyclemod.set_pointer(session, cts)
        row = session.run(trace_mod._CARRIER_TUNNEL_QUERY, uid="zia:far-ends:gre:5002", snap=cts).single()
        assert row["far_role"] == "primary" and row["far_name"] == "Zurich"
        assert row["far_ends"] == 2
        assert sorted(row["far_sample"]) == ["Frankfurt", "Zurich"]
    finally:
        session.run(wipe).consume()


def test_check_zscaler_names_a_zia_only_site_and_a_shared_scope(session):
    from tests.test_zia import RAW

    from hst import reasoner
    from hst.collectors.zia import normalize_zia

    cts = 3_700_000_300_000
    wipe = (
        "MATCH (n:Obj) WHERE n._scope = 'zia:acme-x' "
        "OR (n._scope = 'meta:runs' AND n.snapshot_ts = $cts) DETACH DELETE n"
    )
    session.run(wipe, cts=cts).consume()
    try:
        first = normalize_zia(RAW, tenant="acme-x", location_sites={"1001": "zz-zia-only"})
        second = normalize_zia(RAW, tenant="ACME-X")
        load(session, first, ts_ms=cts, run_id="it-zia-a", collection_ts=cts)
        load(session, second, ts_ms=cts, run_id="it-zia-b", collection_ts=cts)
        report = reasoner.check_zscaler(session, collection_ts=cts)
        assert any(w.startswith("ZIA site zz-zia-only:") for w in report["warnings"])
        assert any("write scope zia:acme-x" in w for w in report["warnings"])
    finally:
        session.run(wipe, cts=cts).consume()


def _zia_zpa_join_run(session, cts, *, gateway: bool = False):
    from tests.test_zia import FORWARDING_RULE_ZPA
    from tests.test_zia import RAW as ZIA_RAW

    from hst.collectors.zia import normalize_zia
    from hst.collectors.zpa import normalize_zpa

    def zpa_raw(group_id: str) -> dict:
        return {
            "app_segments": [{"id": "2001", "name": "shared", "segmentGroupId": group_id}],
            "segment_groups": [{"id": group_id, "name": f"grp-{group_id}"}],
            "server_groups": [{"id": f"40{group_id}", "name": f"srv-{group_id}"}],
        }

    rule = {
        **FORWARDING_RULE_ZPA,
        "zpaAppSegments": [],
        "zpaApplicationSegments": [{"zpaId": 2001}],
        "zpaApplicationSegmentGroups": [{"zpaId": 3001}],
    }
    raw = {**ZIA_RAW, "forwarding_rules": [rule]}
    if gateway:
        rule["zpaGateway"] = {"id": 77, "name": "gw-eu"}
        raw["zpa_gateways"] = [{"id": 77, "zpaServerGroup": {"externalId": "403001"}}]
    load(
        session,
        normalize_zpa(zpa_raw("3001"), tenant="t-one"),
        ts_ms=cts,
        run_id="it-zj-1",
        collection_ts=cts,
    )
    load(
        session,
        normalize_zpa(zpa_raw("3002"), tenant="t-two"),
        ts_ms=cts,
        run_id="it-zj-2",
        collection_ts=cts,
    )
    load(session, normalize_zia(raw, tenant="t-zia"), ts_ms=cts, run_id="it-zj-3", collection_ts=cts)
    return rule


_ZJ_WIPE = "MATCH (n:Obj) WHERE n._scope IN ['zpa:t-one', 'zpa:t-two', 'zia:t-zia'] DETACH DELETE n"


def test_zia_forwarding_joins_skip_an_id_that_two_tenants_share(session):
    from hst import reasoner

    cts = 3_700_000_360_000
    session.run(_ZJ_WIPE).consume()
    try:
        _zia_zpa_join_run(session, cts)
        results = {r["rule"]: r for r in reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)}
        assert results["zia-forwarding-to-zpa-segment"]["ambiguous"] == 1
        assert results["zia-forwarding-to-zpa-segment"]["edges"] == 0
        assert results["zia-forwarding-to-zpa-segment-group"]["edges"] == 1
        ends = session.run(
            "MATCH (:ZiaForwardingRule)-[:FORWARDS_TO]->(x:ZpaSegmentGroup) RETURN x.zpa_id AS id"
        ).data()
        assert ends == [{"id": "3001"}]
        assert not session.run("MATCH (:ZiaForwardingRule)-[:FORWARDS_TO]->(x:ZpaAppSegment) RETURN x").data()
    finally:
        session.run(_ZJ_WIPE).consume()


def test_a_zia_rule_steers_via_its_gateway_server_group(session):
    from hst import reasoner

    cts = 3_700_000_420_000
    session.run(_ZJ_WIPE).consume()
    try:
        _zia_zpa_join_run(session, cts, gateway=True)
        reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
        rows = session.run(
            "MATCH (:ZiaForwardingRule)-[:STEERS_VIA]->(s:ZpaServerGroup) RETURN s.zpa_id AS id"
        ).data()
        assert rows == [{"id": "403001"}]
    finally:
        session.run(_ZJ_WIPE).consume()


def test_the_fixture_zscaler_rows_answer_like_collected_data(session):
    """The demo fixture's Zscaler rows have the collector shape, so the
    catalog and the reasoner answer on them as on collected data."""
    from hst import reasoner
    from hst.queries import QUERIES

    cypher = {q["key"]: q["cypher"] for q in QUERIES}
    cts = 3_000_000_000_000
    load(session, load_fixture(ENTERPRISE_FIXTURE), ts_ms=cts, run_id="it-run-zs-fixture", collection_ts=cts)
    reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
    cyclemod.set_pointer(session, cts)
    connectors = {
        r["connector"]: r for r in session.run(cypher["zpa-connectors"], snap=cts, connector_group="").data()
    }
    assert connectors["dc1-conn-01"]["state"] == "active"
    at_risk = session.run(cypher["zpa-segments-at-risk"], snap=cts, app_group="").data()
    assert "webshop-internal" not in [r["segment"] for r in at_risk]
    forwards = session.run(
        "MATCH (f:ZiaForwardingRule)-[r:FORWARDS_TO]->(s:ZpaAppSegment) WHERE r.collection_ts = $cts "
        "RETURN f.name AS rule, s.name AS segment",
        cts=cts,
    ).data()
    assert forwards == [{"rule": "webshop-to-zpa", "segment": "webshop-internal"}]
    same_as = session.run(
        "MATCH (c:ZpaAppConnector)-[r:SAME_AS {basis: 'private_ip'}]->(ip:IpAddress) "
        "WHERE r.collection_ts = $cts "
        "RETURN c.name AS connector, ip.uid AS ip",
        cts=cts,
    ).data()
    assert same_as == [{"connector": "dc1-conn-01", "ip": "ip:corp:10.0.12.6"}]


def test_two_vyos_routers_write_one_overlay_connection_and_the_reasoner_completes_it(session):
    """Each router writes the connection from its own side; the loader merges
    the two writes into one node, and the overlay-connection-ends rule sets
    `observed_from` to both ends and names the connection by both routers."""
    from tests.test_vyos import gre_router_pair

    from hst import reasoner
    from hst.core import uid

    cts = 3_500_000_000_000
    a, b = gre_router_pair()
    load(session, a, ts_ms=cts, run_id="it-oconn-a", collection_ts=cts)
    load(session, b, ts_ms=cts + 1, run_id="it-oconn-b", collection_ts=cts)
    results = reasoner.run(session, ts_ms=cts + 2, collection_ts=cts)
    assert next(r for r in results if r["rule"] == "overlay-connection-ends")["edges"] == 1
    conn = uid.overlay_connection("gre", "192.0.2.1", "198.51.100.7")
    rows = session.run(
        "MATCH (c:OverlayConnection {uid: $uid, collection_ts: $cts}) "
        "OPTIONAL MATCH (c)-[r:REALIZED_BY]->(t:Tunnel) "
        "RETURN c.observed_from AS observed_from, c.name AS name, collect(DISTINCT t.uid) AS tunnels",
        uid=conn,
        cts=cts,
    ).data()
    assert len(rows) == 1
    assert rows[0]["observed_from"] == ["a", "b"]
    assert rows[0]["name"] == "vyos-a to vyos-b"
    assert rows[0]["tunnels"] == [uid.tunnel("gre", "192.0.2.1", "198.51.100.7")]


def test_reasoner_attaches_router_interfaces_to_their_segments(session):
    """eth1 of the VyOS router is untagged and cabled to switch port 1, whose
    native network is Default (VLAN 1): `basis: cable`. eth1.30 and eth1.40 are
    vifs bound to VLANs 30 and 40 on the router itself: `basis: subif`. eth0
    holds no address (dhcp), so the native VLAN of port 4 at its far end
    attaches nothing. The connected prefix of each attached interface is IN
    its bridge domain."""
    import copy

    import test_unifi as tu
    import test_vyos as tv
    from hst import reasoner
    from hst.collectors.unifi import normalize_unifi
    from hst.collectors.vyos import normalize_vyos

    raw = copy.deepcopy(tu.RAW)
    switch = next(d for d in raw["devices"] if d.get("port_table"))
    for port in switch["port_table"]:
        if port["port_idx"] in (1, 4):
            port["native_networkconf_id"] = "n1"
            port["forward"] = "native"
    cts = 3_000_000_000_000
    load(
        session,
        normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default"),
        ts_ms=cts,
        run_id="it-unifi",
        collection_ts=cts,
    )
    load(
        session,
        normalize_vyos({"config": tv.CONFIG, "version_text": tv.VERSION, "links": tv.LINKS}, l3dom="home"),
        ts_ms=cts + 100,
        run_id="it-vyos",
        collection_ts=cts,
    )
    results = reasoner.run(session, ts_ms=cts + 200, collection_ts=cts)
    by_rule = {r["rule"]: r["edges"] for r in results}
    assert by_rule["attached-from-cable"] >= 1 and by_rule["attached-from-vlan-binding"] >= 2

    rows = session.run(
        "MATCH (i:Interface)-[a:ATTACHED_TO]->(bd:BridgeDomain) "
        "WHERE i.uid STARTS WITH 'dev:gw/' AND coalesce(i.collection_ts, $cts) = $cts "
        "RETURN i.uid AS iface, bd.uid AS bd, a.basis AS basis, a.derived AS derived",
        cts=cts,
    ).data()
    got = {(r["iface"], r["bd"].rsplit(":", 1)[1], r["basis"]) for r in rows}
    assert ("dev:gw/if/eth1", "1", "cable") in got
    assert ("dev:gw/if/eth1.30", "30", "subif") in got
    assert ("dev:gw/if/eth1.40", "40", "subif") in got
    assert not any(r["iface"] == "dev:gw/if/eth0" for r in rows)
    assert all(r["derived"] is True for r in rows)

    rows = session.run(
        "MATCH (p:Prefix)-[r:IN]->(bd:BridgeDomain) "
        "WHERE r.rule = 'prefix-in-from-attachment' AND coalesce(p.collection_ts, $cts) = $cts "
        "RETURN p.cidr AS cidr, bd.uid AS bd",
        cts=cts,
    ).data()
    got_prefixes = {(r["cidr"], r["bd"].rsplit(":", 1)[1]) for r in rows}
    assert ("192.168.1.0/24", "1") in got_prefixes
    assert ("192.168.30.0/24", "30") in got_prefixes

    # the unified map reads the same edges back (app/routes/topology.py)
    from hst.app.routes import topology

    attached = session.run(topology._ATTACHED, devs=["dev:gw"], snap=cts).data()
    assert {(r["iface"], r["basis"], r["ip"], r["cidr"]) for r in attached if r["dev"] == "dev:gw"} >= {
        ("eth1", "cable", "192.168.1.1", "192.168.1.0/24"),
        ("eth1.30", "subif", "192.168.30.1", "192.168.30.0/24"),
    }
    bd1 = next(r["bd"] for r in attached if r["iface"] == "eth1")
    cidrs = session.run(topology._SEGMENT_PREFIXES, bds=[bd1], snap=cts).data()
    assert "192.168.1.0/24" in {r["cidr"] for r in cidrs}

    # a rerun rebuilds the same edges, one per pair
    reasoner.run(session, ts_ms=cts + 300, collection_ts=cts)
    count = session.run(
        "MATCH (:Interface {uid: 'dev:gw/if/eth1'})-[a:ATTACHED_TO]->(:BridgeDomain) RETURN count(a) AS c"
    ).single()["c"]
    assert count == 1


def test_the_sole_interface_of_a_segment_is_its_gateway_whatever_the_role(session):
    """A routed-access switch whose role is not a
    gateway role holds the only address on VLAN 20's prefix: its SVI is the
    prefix's gateway, as the map draws it. VLAN 99, where two switches hold
    an SVI each (a management VLAN), credits neither. A routed port attached
    to a segment through its cable has that segment in the tracer's segment
    read, as a VLAN-bound SVI has its own."""
    from hst import path as pathmod
    from hst import reasoner
    from hst.path.trace import _IFACE_SEGMENT_QUERY

    session.run(
        """
CREATE (sw:Obj:Device {uid: 'it:dev:sw7', hostname: 'sw7', role: 'switch', _scope: 'test:sole-segment'})
CREATE (sw8:Obj:Device {uid: 'it:dev:sw8', hostname: 'sw8', role: 'switch', _scope: 'test:sole-segment'})
CREATE (bd20:Obj:BridgeDomain {uid: 'it:bd:20', _scope: 'test:sole-segment'})
CREATE (bd99:Obj:BridgeDomain {uid: 'it:bd:99', _scope: 'test:sole-segment'})
CREATE (v20:Obj:VlanInstance {uid: 'it:vlan:sw7:20', vid: 20, _scope: 'test:sole-segment'})
CREATE (v99:Obj:VlanInstance {uid: 'it:vlan:sw7:99', vid: 99, _scope: 'test:sole-segment'})
CREATE (v99b:Obj:VlanInstance {uid: 'it:vlan:sw8:99', vid: 99, _scope: 'test:sole-segment'})
CREATE (s20:Obj:Interface {uid: 'it:if:sw7-vlan20', name: 'Vlan20', kind: 'svi', _scope: 'test:sole-segment'})
CREATE (s99:Obj:Interface {uid: 'it:if:sw7-vlan99', name: 'Vlan99', kind: 'svi', _scope: 'test:sole-segment'})
CREATE (s99b:Obj:Interface {uid: 'it:if:sw8-vlan99', name: 'Vlan99', kind: 'svi',
                           _scope: 'test:sole-segment'})
CREATE (cab:Obj:Interface {uid: 'it:if:sw8-eth0', name: 'eth0', _scope: 'test:sole-segment'})
CREATE (a20:Obj:IpAddress {uid: 'it:ip:sw7-20', ip: '10.20.7.1', af: 4, _scope: 'test:sole-segment'})
CREATE (a99:Obj:IpAddress {uid: 'it:ip:sw7-99', ip: '10.99.0.7', af: 4, _scope: 'test:sole-segment'})
CREATE (a99b:Obj:IpAddress {uid: 'it:ip:sw8-99', ip: '10.99.0.8', af: 4, _scope: 'test:sole-segment'})
CREATE (p20:Obj:Prefix {uid: 'it:pfx:sw7-20', cidr: '10.20.7.0/24', af: 4, kind: 'connected',
                        l3dom: 'test-seg', anchor: 'it:vrf:sw7', _scope: 'test:sole-segment'})
CREATE (p99:Obj:Prefix {uid: 'it:pfx:sw7-99', cidr: '10.99.0.0/24', af: 4, kind: 'connected',
                        l3dom: 'test-seg', anchor: 'it:vrf:sw7', _scope: 'test:sole-segment'})
CREATE (p99b:Obj:Prefix {uid: 'it:pfx:sw8-99', cidr: '10.99.0.0/24', af: 4, kind: 'connected',
                         l3dom: 'test-seg', anchor: 'it:vrf:sw8', _scope: 'test:sole-segment'})
CREATE (s20)-[:ON]->(sw)
CREATE (s99)-[:ON]->(sw)
CREATE (s99b)-[:ON]->(sw8)
CREATE (cab)-[:ON]->(sw8)
CREATE (s20)-[:BOUND_TO]->(v20)-[:REALIZES]->(bd20)
CREATE (s99)-[:BOUND_TO]->(v99)-[:REALIZES]->(bd99)
CREATE (s99b)-[:BOUND_TO]->(v99b)-[:REALIZES]->(bd99)
CREATE (s20)-[:HAS_IP]->(a20)-[:IN]->(p20)
CREATE (s99)-[:HAS_IP]->(a99)-[:IN]->(p99)
CREATE (s99b)-[:HAS_IP]->(a99b)-[:IN]->(p99b)
// the attachment the cable rule writes for an untagged routed port
CREATE (cab)-[:ATTACHED_TO {basis: 'cable'}]->(bd20)"""
    ).consume()
    cts = _publish(session)
    reasoner.run(session, ts_ms=9_000_000_000_000, collection_ts=cts)

    credited = session.run(
        """
MATCH (i:Interface)-[c:GATEWAY_FOR]->(p:Prefix)
WHERE c.rule = 'gateway-from-sole-segment-interface' AND p.uid STARTS WITH 'it:pfx:sw'
RETURN i.uid AS iface, p.uid AS prefix ORDER BY i.uid"""
    ).data()
    assert [(r["iface"], r["prefix"]) for r in credited] == [("it:if:sw7-vlan20", "it:pfx:sw7-20")]

    pinned = CycleSession(session, cts)
    assert [r["uid"] for r in pathmod._read(pinned, _IFACE_SEGMENT_QUERY, u="it:if:sw7-vlan20")] == [
        "it:bd:20"
    ]
    assert [r["uid"] for r in pathmod._read(pinned, _IFACE_SEGMENT_QUERY, u="it:if:sw8-eth0")] == ["it:bd:20"]


def test_site_graph_bgp_read_takes_the_peer_holder_of_its_own_run(session):
    """The BGP read pins the peer address to the run."""
    from hst.app.routes import site_graph

    t0, t1 = 7_000_000_000_000, 7_000_000_060_000

    def run(ts: int, holder: str) -> None:
        session.run(
            """
UNWIND ['a', 'b', 'c'] AS k
CREATE (d:Obj:Device {uid: 'it:bgp:dev-' + k, hostname: k, collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (s:Obj:Site {uid: 'it:bgp:site-' + k, code: toUpper(k), collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (d)-[:LOCATED_IN]->(s)
WITH collect(d) AS devices
UNWIND devices AS d
WITH d WHERE d.hostname = 'a'
CREATE (v:Obj:VrfInstance {uid: 'it:bgp:vrf-a', name: 'default', collection_ts: $ts,
                           _scope: 'fixture:mini-dc'})
CREATE (rp:Obj:RoutingProcess {uid: 'it:bgp:rp-a', collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (bs:Obj:BgpSession {uid: 'it:bgp:session', peer_ip: '10.9.0.2', local_ip: '10.9.0.1',
                           local_asn: 65001, peer_asn: 65002, collection_ts: $ts,
                           _scope: 'fixture:mini-dc'})
CREATE (v)-[:OWNED_BY]->(d)
CREATE (rp)-[:IN_VRF]->(v)
CREATE (rp)-[:HAS]->(bs)""",
            ts=ts,
        ).consume()
        session.run(
            """
MATCH (d:Obj:Device {uid: 'it:bgp:dev-' + $holder, collection_ts: $ts})
CREATE (i:Obj:Interface {uid: 'it:bgp:if-' + $holder, name: 'eth0', collection_ts: $ts,
                         _scope: 'fixture:mini-dc'})
CREATE (ip:Obj:IpAddress {uid: 'it:bgp:ip-' + $holder + '-' + toString($ts), ip: '10.9.0.2',
                          collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (i)-[:ON]->(d)
CREATE (i)-[:HAS_IP]->(ip)""",
            holder=holder,
            ts=ts,
        ).consume()

    run(t0, "b")
    run(t1, "c")
    now = [r["b_dev"] for r in session.run(site_graph._BGP, snap=t1).data()]
    before = [r["b_dev"] for r in session.run(site_graph._BGP, snap=t0).data()]
    assert now == ["it:bgp:dev-c"]
    assert before == ["it:bgp:dev-b"]


def test_site_prefix_rows_carry_each_sites_own_context_for_a_shared_templated_lan(session):
    """Two sites hold the templated LAN 192.168.1.0/24 in their own VRFs, and one of them also
    holds a management SVI prefix with no route. Each site's rows name the prefix node and the context
    it is addressed in, so a trace can start in the right one; the two LANs are two prefixes of one cidr."""
    from types import SimpleNamespace

    from hst.app.routes import sites as sites_routes
    from hst.core import uid as uidmod

    ts = 7_100_000_000_000
    for code in ("s1", "s2"):
        session.run(
            """
CREATE (site:Obj:Site {uid: $site, code: $code, collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (d:Obj:Device {uid: 'it:xa09:dev-' + $code, hostname: $code, collection_ts: $ts,
                      _scope: 'fixture:mini-dc'})
CREATE (d)-[:LOCATED_IN]->(site)
CREATE (i:Obj:Interface {uid: 'it:xa09:lan-' + $code, name: 'Vlan10', collection_ts: $ts,
                         _scope: 'fixture:mini-dc'})
CREATE (ip:Obj:IpAddress {uid: 'it:xa09:ip-' + $code, ip: '192.168.1.1', collection_ts: $ts,
                          _scope: 'fixture:mini-dc'})
CREATE (p:Obj:Prefix {uid: 'it:xa09:pfx-' + $code, cidr: '192.168.1.0/24', kind: 'connected',
                      anchor: 'it:xa09:vrf-' + $code, collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (i)-[:ON]->(d)
CREATE (i)-[:HAS_IP]->(ip)
CREATE (ip)-[:IN]->(p)""",
            site=uidmod.site(code),
            code=code,
            ts=ts,
        ).consume()
    session.run(
        """
MATCH (d:Obj:Device {uid: 'it:xa09:dev-s1', collection_ts: $ts})
CREATE (i:Obj:Interface {uid: 'it:xa09:mgmt', name: 'Vlan99', collection_ts: $ts,
                         _scope: 'fixture:mini-dc'})
CREATE (ip:Obj:IpAddress {uid: 'it:xa09:ip-mgmt', ip: '10.99.0.1', collection_ts: $ts,
                          _scope: 'fixture:mini-dc'})
CREATE (p:Obj:Prefix {uid: 'it:xa09:pfx-mgmt', cidr: '10.99.0.0/24', kind: 'connected',
                      anchor: 'it:xa09:vrf-s1', collection_ts: $ts, _scope: 'fixture:mini-dc'})
CREATE (i)-[:ON]->(d)
CREATE (i)-[:HAS_IP]->(ip)
CREATE (ip)-[:IN]->(p)""",
        ts=ts,
    ).consume()

    snapshot = SimpleNamespace(cts=ts)
    first = sites_routes.site_prefix_rows(session, snapshot, "s1")
    second = sites_routes.site_prefix_rows(session, snapshot, "s2")
    assert [(p.cidr, p.uid, p.context) for p in first] == [
        ("10.99.0.0/24", "it:xa09:pfx-mgmt", "it:xa09:vrf-s1"),
        ("192.168.1.0/24", "it:xa09:pfx-s1", "it:xa09:vrf-s1"),
    ]
    assert [(p.cidr, p.uid, p.context) for p in second] == [
        ("192.168.1.0/24", "it:xa09:pfx-s2", "it:xa09:vrf-s2")
    ]
    assert sites_routes.site_prefixes(session, snapshot, "s1") == ["10.99.0.0/24", "192.168.1.0/24"]


def test_vlan_stretch_warns_for_devices_placed_by_assignment_after_the_run_loaded(session):
    """The check finds no site before the assignments are applied."""
    from hst import reasoner

    cts = 7_200_000_000_000
    for k in ("a", "b"):
        session.run(
            """
CREATE (d:Obj:Device {uid: 'it:sl03:dev-' + $k, hostname: $k, collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (p:Obj:Port {uid: 'it:sl03:port-' + $k, name: 'eth0', collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (v:Obj:VlanInstance {uid: 'it:sl03:vlan-' + $k, vid: 10, collection_ts: $cts,
                            _scope: 'fixture:mini-dc'})
MERGE (bd:Obj:BridgeDomain {uid: 'bd:vlan:fab0:10', collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (p)-[:ON]->(d)
CREATE (p)-[:CARRIES]->(v)
CREATE (v)-[:REALIZES]->(bd)""",
            k=k,
            cts=cts,
        ).consume()
    cyclemod.set_pointer(session, cts)
    try:
        assert reasoner.check_vlan_stretch(session, collection_ts=cts)["warnings"] == []
        cyclemod.apply_site_assignments(session, {"it:sl03:dev-a": "sa", "it:sl03:dev-b": "sb"}, cts)
        warnings = reasoner.check_vlan_stretch(session, collection_ts=cts)["warnings"]
        assert len(warnings) == 1 and "sa" in warnings[0] and "sb" in warnings[0], warnings
    finally:
        session.run("MATCH (s:Site) WHERE s.uid IN ['site:sa', 'site:sb'] DETACH DELETE s").consume()


def test_link_speed_creates_no_edge_when_every_cable_already_exists_in_either_direction(session, tmp_path):
    """The speed query reads each cable in its stored direction."""
    from hst.core import reasoner

    cts = 7_300_000_000_000
    session.run(
        """
CREATE (fr2:Obj:Port {uid: 'it:speed:fr2/port/eth1-104', name: 'eth1/104', speed_mbps: 10000,
                      collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (pa4:Obj:Port {uid: 'it:speed:pa4/port/eth1-104', name: 'eth1/104', speed_mbps: 10000,
                      collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (x:Obj:Port {uid: 'it:speed:fr2/port/eth1-1', name: 'eth1/1', speed_mbps: 1000,
                    collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (y:Obj:Port {uid: 'it:speed:fr6/port/eth1-1', name: 'eth1/1', speed_mbps: 1000,
                    collection_ts: $cts, _scope: 'fixture:mini-dc'})
CREATE (pa4)-[:CONNECTED_TO {source: 'equinix-circuit', collection_ts: $cts, collected_at: $cts}]->(fr2)
CREATE (x)-[:CONNECTED_TO {source: 'lldp', collection_ts: $cts, collected_at: $cts}]->(y)""",
        cts=cts,
    ).consume()
    try:
        manifest = reasoner.execute_link_speed(
            session, Settings(_env_file=None, hst_data_dir=tmp_path), collection_ts=cts
        )
        assert manifest.rels_created == 0
        rows = session.run(
            "MATCH (a:Port)-[c:CONNECTED_TO]->(b:Port) WHERE a.uid STARTS WITH 'it:speed:' "
            "RETURN a.uid AS a, b.uid AS b, c.source AS source, c.speed_agreement AS agreement "
            "ORDER BY a"
        ).data()
        assert rows == [
            {
                "a": "it:speed:fr2/port/eth1-1",
                "b": "it:speed:fr6/port/eth1-1",
                "source": "lldp",
                "agreement": "agree",
            },
            {
                "a": "it:speed:pa4/port/eth1-104",
                "b": "it:speed:fr2/port/eth1-104",
                "source": "equinix-circuit",
                "agreement": "agree",
            },
        ]
    finally:
        session.run("MATCH (p:Port) WHERE p.uid STARTS WITH 'it:speed:' DETACH DELETE p").consume()
