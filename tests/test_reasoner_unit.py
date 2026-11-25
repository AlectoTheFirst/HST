"""Reasoner structure, against a fake session (no Neo4j)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hst import reasoner
from hst.core import uid
from hst.core.fixtures import load_fixture

FIXTURES = Path(__file__).parents[1] / "fixtures"


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows

    def consume(self):
        return None


class FakeTx:
    def __init__(self, edges_per_rule=1, fail_on=None):
        self.calls: list[tuple[str, dict]] = []
        self.edges_per_rule = edges_per_rule
        self.fail_on = fail_on

    def run(self, query, **params):
        self.calls.append((query, params))
        if self.fail_on and self.fail_on in query:
            raise RuntimeError("rule blew up")
        # only a writing rule reports an edge count; the containment step's reads
        # come back empty, so the plain fake exercises the no-candidates path
        return FakeResult([{"n": self.edges_per_rule}] if "MERGE" in query else [])


class FakeSession:
    """Every transaction runs on the one fake tx, so `tx.calls` is the whole run
    in order; `transactions` groups those calls by the transaction that issued
    them, each tagged "read" or "write"."""

    def __init__(self, tx=None):
        self.tx = tx or FakeTx()
        self.write_calls = 0
        self.read_calls = 0
        self.transactions: list[tuple[str, list[str]]] = []

    def _run(self, kind, work):
        start = len(self.tx.calls)
        try:
            return work(self.tx)
        finally:
            self.transactions.append((kind, [q for q, _ in self.tx.calls[start:]]))

    def execute_write(self, work):
        self.write_calls += 1
        return self._run("write", work)

    def execute_read(self, work):
        self.read_calls += 1
        return self._run("read", work)

    def run(self, *a, **k):  # pragma: no cover
        raise AssertionError("reasoner must not use autocommit; it clears before it rebuilds")


def test_every_rule_reports_its_edge_count():
    s = FakeSession()
    results = reasoner.run(s, ts_ms=1_000)
    assert [r["rule"] for r in results] == [name for name, _ in reasoner.RULES] + ["address-containment"]
    stated_cable_rules = {"cable-from-uplink-record", "cable-from-lldp-record", "cable-from-neighbor-name"}
    python_rules = stated_cable_rules | {
        reasoner.FABRIC_PORT_RULE,
        reasoner.EDGE_DEVICE_RULE,
        reasoner.ZPA_ZIA_SAME_AS_RULE,
    }
    # overlay-connection-ends sets node properties and MERGEs no edge, so the
    # plain fake answers it no row
    property_rules = {"overlay-connection-ends"}
    for r in results[:-1]:
        if r["rule"] in python_rules | property_rules:
            assert r["edges"] == 0
        else:
            assert r["edges"] == 1
    # the fake's reads return no candidates, so the containment step reports 0
    # and, asserted below via the call count, never issues its write
    assert results[-1]["edges"] == 0


def test_clear_and_every_rule_run_in_bounded_transactions_of_their_own():
    s = FakeSession()
    reasoner.run(s, ts_ms=1_000)
    calls = [q for q, _ in s.tx.calls]
    assert calls[:2] == [reasoner.CLEAR, reasoner.CLEAR_PROPS]
    cypher_rules = [q for _, q in reasoner.RULES if q is not None]
    # one write transaction per Cypher rule, CLEAR and CLEAR_PROPS alone
    for query in (reasoner.CLEAR, reasoner.CLEAR_PROPS, *cypher_rules):
        assert ("write", [query]) in s.transactions
    # the fabric-port, edge-device and zscaler rules each in one write
    # transaction; the stated-cable fetches and the containment reads in one
    # read transaction each, and no write for either since the fake's reads
    # resolve nothing
    assert s.write_calls == 2 + len(cypher_rules) + 3
    assert s.read_calls == 2
    assert all(len(queries) <= 4 for _, queries in s.transactions)
    # 2 CLEARs, one call per Cypher rule (RULES minus the 2 stated-cable
    # entries, which share 4 fetch reads and issue no write because the
    # fake's reads yield no switch ports to resolve), the stated-cable
    # rules' 4 shared fetches, the 2 reads of fabric-port-from-description
    # (no write: the fake's reads give it no Fabric port), the 1 read of
    # edge-device-from-binding (no bound device, so no second read and no
    # write), the 1 read of zpa-zia-ip-same-as (no Zscaler address, so no
    # campus read and no write), and the containment step's 3 reads.
    cypher_rules = sum(1 for _, q in reasoner.RULES if q is not None)
    assert len(s.tx.calls) == 2 + cypher_rules + 4 + 2 + 1 + 1 + 3


def test_the_infra_marker_is_reasoner_owned_and_cleared():
    """`cable-from-endpoint-mac` writes its own marker `ep.infra`."""
    for _, query in reasoner.RULES:
        if query is not None:  # cable-from-uplink-record/-lldp-record: query is None
            assert "ep.kind" not in query
    mac_rule = next(q for name, q in reasoner.RULES if name == "cable-from-endpoint-mac")
    assert mac_rule is not None
    assert "ep.infra = true" in mac_rule
    assert "REMOVE ep.infra" in reasoner.CLEAR_PROPS


def test_cable_from_uplink_and_lldp_record_are_resolved_in_python_not_cypher():
    """`resolve_stated_cables` resolves the neighbor Device by chassis MAC, then the
    Port on it by a name-slug match and a "Port N" index parse."""
    by_name = dict(reasoner.RULES)
    assert by_name["cable-from-uplink-record"] is None
    assert by_name["cable-from-lldp-record"] is None


def test_stated_cable_write_states_not_derives():
    assert "c.derived = false" in reasoner.STATED_CABLE_WRITE
    assert "e.rule" in reasoner.STATED_CABLE_WRITE
    assert "e.source" in reasoner.STATED_CABLE_WRITE


def test_cable_from_uplink_record_runs_before_the_last_connection_inference():
    """Rules run in list order inside one transaction (`reasoner.run`)."""
    names = [name for name, _ in reasoner.RULES]
    assert names.index("cable-from-uplink-record") < names.index("cable-from-last-connection")


def test_last_connection_inference_yields_to_an_existing_stated_uplink_edge():
    rule = next(q for name, q in reasoner.RULES if name == "cable-from-last-connection")
    assert rule is not None
    assert "NOT EXISTS" in rule
    assert "unifi-uplink" in reasoner.STATED_CABLE_SOURCES


def test_cable_from_lldp_record_runs_after_the_uplink_record_rule_and_before_last_connection():
    """List order is execution order inside one transaction (`reasoner.run`):
    the uplink-stated fact must exist before this rule's own precedence guard
    runs, and this rule's stated fact must exist before
    cable-from-last-connection's guard (next test) runs."""
    names = [name for name, _ in reasoner.RULES]
    assert names.index("cable-from-uplink-record") < names.index("cable-from-lldp-record")
    assert names.index("cable-from-lldp-record") < names.index("cable-from-last-connection")
    assert "cable-from-lldp" not in names


def test_cable_from_endpoint_mac_runs_after_the_stated_rules_and_before_last_connection():
    """The client-table inference runs after the three stated rules, so its
    own pair guard can see the cables they wrote, and before
    cable-from-last-connection, whose guard yields to nothing this rule
    writes."""
    names = [name for name, _ in reasoner.RULES]
    for stated in ("cable-from-uplink-record", "cable-from-lldp-record", "cable-from-neighbor-name"):
        assert names.index(stated) < names.index("cable-from-endpoint-mac")
    assert names.index("cable-from-endpoint-mac") < names.index("cable-from-last-connection")


def test_cable_from_endpoint_mac_refuses_a_port_with_company():
    """The rule requires no other endpoint on the port, every neighbor record on the
    port (`last_conn_mac`, `lldp_neighbor_mac`, `uplink_mac`) absent or a MAC of the
    endpoint or its device, and no stated cable on either port to a different peer."""
    rule = next(q for name, q in reasoner.RULES if name == "cable-from-endpoint-mac")
    assert rule is not None
    assert "MATCH (other:Endpoint)-[at2:ATTACHED]->(swp)" in rule
    assert "other.uid <> ep.uid" in rule
    assert "all(h IN [swp.last_conn_mac, swp.lldp_neighbor_mac, swp.uplink_mac]" in rule
    assert "h IS NULL OR h = ep.mac OR h IN dev_macs" in rule
    assert "idev.mac" in rule
    assert "o.uid <> z.uid" in rule and "o2.uid <> a.uid" in rule
    assert "u.source IN $stated_cable_sources OR u.derived = false" in rule
    assert "SET ep.infra = true" in rule


def test_mac_owners_include_the_device_chassis_mac():
    """A UniFi device has no Interface node and no Port MAC; its chassis MAC
    sits on the Device node (`collectors/unifi.py`). The owner lookup reads
    it beside every Port and Interface MAC, so a switch that names a UniFi
    peer's chassis MAC over LLDP resolves that peer."""
    assert "MATCH (d:Device:Obj)" in reasoner.FETCH_MAC_OWNERS
    assert "d.mac IS NOT NULL" in reasoner.FETCH_MAC_OWNERS
    assert reasoner.FETCH_MAC_OWNERS.count("UNION") == 2


def test_two_unifi_switches_that_see_each_other_over_lldp_are_cabled_once():
    """The access switch's Port 5 names the core
    switch's chassis MAC and "Port 20"; the core switch's Port 20 names the
    access switch's chassis MAC and "Port 5". Neither port carries an uplink
    record. Both chassis MACs are owned through `Device.mac` (the owner rows
    here are what `FETCH_MAC_OWNERS`'s Device branch returns), so
    cable-from-lldp-record states the one cable from either record, and the
    reverse record resolves the identical pair and is not duplicated."""
    report = reasoner.resolve_stated_cables(
        [
            _swp("dev:942a6f4cc4fa/port/port5", lldp_mac="f4e2c6ace59e", lldp_port="Port 20"),
            _swp("dev:f4e2c6ace59e/port/port20", lldp_mac="942a6f4cc4fa", lldp_port="Port 5"),
        ],
        [_owner("f4e2c6ace59e", "dev:f4e2c6ace59e"), _owner("942a6f4cc4fa", "dev:942a6f4cc4fa")],
        [
            _port_row("dev:f4e2c6ace59e", "dev:f4e2c6ace59e/port/port20"),
            _port_row("dev:f4e2c6ace59e", "dev:f4e2c6ace59e/port/port25"),
            _port_row("dev:942a6f4cc4fa", "dev:942a6f4cc4fa/port/port5"),
            _port_row("dev:942a6f4cc4fa", "dev:942a6f4cc4fa/port/port6"),
        ],
        [],
    )
    lldp = report["cable-from-lldp-record"]
    assert lldp["edges"] == [
        {
            "a": "dev:942a6f4cc4fa/port/port5",
            "z": "dev:f4e2c6ace59e/port/port20",
            "source": "unifi-lldp",
            "rule": "cable-from-lldp-record",
        }
    ]
    assert lldp["unresolved"] == 0
    assert lldp["ambiguous"] == 0


def test_last_connection_inference_yields_to_an_existing_stated_lldp_edge():
    rule = next(q for name, q in reasoner.RULES if name == "cable-from-last-connection")
    assert rule is not None
    assert "unifi-lldp" in reasoner.STATED_CABLE_SOURCES


def test_last_connection_guard_yields_port_level_not_pair_level():
    """The guard checks `a` and `z` each against a stated cable to any peer."""
    rule = next(q for name, q in reasoner.RULES if name == "cable-from-last-connection")
    assert rule is not None
    assert "(a)-[u:CONNECTED_TO]-()" in rule
    assert "(z)-[u2:CONNECTED_TO]-()" in rule
    assert "u.source IN $stated_cable_sources OR u.derived = false" in rule
    assert "u2.source IN $stated_cable_sources OR u2.derived = false" in rule
    assert "source: 'unifi-uplink'" not in rule, "must not be pinned to the pair, only to either port"
    assert "source: 'unifi-lldp'" not in rule, "must not be pinned to the pair, only to either port"
    assert reasoner.STATED_CABLE_SOURCES == ["unifi", "unifi-uplink", "unifi-lldp"]


def test_last_connection_guard_sources_are_a_bound_parameter_not_hardcoded():
    s = FakeSession()
    reasoner.run(s, ts_ms=1_000)
    params = next(p for q, p in s.tx.calls if "cable-from-last-connection" in q)
    assert params["stated_cable_sources"] == reasoner.STATED_CABLE_SOURCES


# --- resolve_stated_cables: device-then-port resolution, no database needed ---------
#
# Pure-Python precedence tests. `tests/test_integration_db.py` proves the same
# behaviour against a real graph (`test_reasoner_stitches_vyos_cable_from_unifi_facts`
# and its neighbors).


def _swp(uid="sw/port/1", *, uplink_mac=None, uplink_remote_port=None, lldp_mac=None, lldp_port=None):
    return {
        "swp_uid": uid,
        "swdev_uid": "sw",
        "uplink_mac": uplink_mac,
        "uplink_remote_port": uplink_remote_port,
        "lldp_neighbor_mac": lldp_mac,
        "lldp_neighbor_port": lldp_port,
    }


def _owner(mac, device_uid):
    return {"mac": mac, "device_uid": device_uid}


def _port_row(device_uid, port_uid, mac=None):
    return {"device_uid": device_uid, "port_uid": port_uid, "mac": mac}


def test_chassis_mac_on_a_different_port_than_the_lldp_port_id_resolves_by_id():
    """The VyOS router's LLDP chassis MAC is eth2's (one system MAC), the
    physical link is eth0, and the LLDP port id names eth0."""
    report = reasoner.resolve_stated_cables(
        [
            _swp(
                "dev:f4e2c6ace59e/port/port25",
                uplink_mac="a8b8e00596d7",
                lldp_mac="a8b8e00596d7",
                lldp_port="eth0",
            )
        ],
        [
            _owner("a8b8e00596d5", "dev:vyos"),
            _owner("a8b8e00596d7", "dev:vyos"),
            _owner("a8b8e00596d6", "dev:vyos"),
        ],
        [
            _port_row("dev:vyos", "dev:vyos/port/eth0", "a8b8e00596d5"),
            _port_row("dev:vyos", "dev:vyos/port/eth1", "a8b8e00596d8"),
            _port_row("dev:vyos", "dev:vyos/port/eth2", "a8b8e00596d7"),
        ],
        [],
    )
    uplink = report["cable-from-uplink-record"]
    assert {e["a"] for e in uplink["edges"]} | {e["z"] for e in uplink["edges"]} == {
        "dev:f4e2c6ace59e/port/port25",
        "dev:vyos/port/eth0",
    }
    assert uplink["edges"][0]["source"] == "unifi-uplink"
    assert uplink["edges"][0]["rule"] == "cable-from-uplink-record"
    # cable-from-lldp-record resolves the identical pair and yields to it
    assert report["cable-from-lldp-record"]["edges"] == []


def test_chassis_mac_alone_on_a_multi_port_device_counts_unresolved():
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc000001")],
        [_owner("aabbcc000001", "dev:multi")],
        [_port_row("dev:multi", "dev:multi/port/eth0"), _port_row("dev:multi", "dev:multi/port/eth1")],
        [],
    )
    assert report["cable-from-lldp-record"]["edges"] == []
    assert report["cable-from-lldp-record"]["unresolved"] == 1
    assert report["cable-from-lldp-record"]["ambiguous"] == 0


def test_chassis_mac_owned_by_two_devices_counts_ambiguous_not_unresolved():
    """More than one Device owns the stated chassis MAC: the *device* is
    ambiguous, a different failure than a device with too many Ports."""
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc000006", lldp_port="eth0")],
        [_owner("aabbcc000006", "dev:a"), _owner("aabbcc000006", "dev:b")],
        [],
        [],
    )
    bucket = report["cable-from-lldp-record"]
    assert bucket["edges"] == []
    assert bucket["ambiguous"] == 1
    assert bucket["unresolved"] == 0


def test_a_device_with_one_port_resolves_to_it_with_no_port_id_at_all():
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc000001")],
        [_owner("aabbcc000001", "dev:single")],
        [_port_row("dev:single", "dev:single/port/eth0")],
        [],
    )
    edges = report["cable-from-lldp-record"]["edges"]
    assert len(edges) == 1
    assert "dev:single/port/eth0" in (edges[0]["a"], edges[0]["z"])


def test_unifi_peer_resolves_by_uplink_remote_port_index():
    report = reasoner.resolve_stated_cables(
        [_swp("sw1/port/4", uplink_mac="aabbcc000002", uplink_remote_port=3)],
        [_owner("aabbcc000002", "dev:sw2")],
        [_port_row("dev:sw2", "dev:sw2/port/port3"), _port_row("dev:sw2", "dev:sw2/port/port4")],
        [],
    )
    edges = report["cable-from-uplink-record"]["edges"]
    assert len(edges) == 1
    assert "dev:sw2/port/port3" in (edges[0]["a"], edges[0]["z"])


@pytest.mark.parametrize("port_id", ["Port 19", "local Port 19", "PORT19"])
def test_lldp_port_id_naming_a_unifi_port_index_resolves_to_it(port_id):
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc000003", lldp_port=port_id)],
        [_owner("aabbcc000003", "dev:sw3")],
        [_port_row("dev:sw3", "dev:sw3/port/port19"), _port_row("dev:sw3", "dev:sw3/port/port2")],
        [],
    )
    edges = report["cable-from-lldp-record"]["edges"]
    assert len(edges) == 1
    assert "dev:sw3/port/port19" in (edges[0]["a"], edges[0]["z"])


def test_a_mac_port_id_resolves_by_mac_within_the_resolved_device_only():
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc000004", lldp_port="aa:bb:cc:00:00:05")],
        [_owner("aabbcc000004", "dev:sw4")],
        [
            _port_row("dev:sw4", "dev:sw4/port/eth0", "aabbcc000004"),
            _port_row("dev:sw4", "dev:sw4/port/eth1", "aabbcc000005"),
        ],
        [],
    )
    edges = report["cable-from-lldp-record"]["edges"]
    assert len(edges) == 1
    assert "dev:sw4/port/eth1" in (edges[0]["a"], edges[0]["z"])


def test_mismatched_chassis_macs_on_one_port_distrust_the_lldp_port_id():
    """The uplink record and the LLDP record on the same switch port name
    different chassis MACs."""
    report = reasoner.resolve_stated_cables(
        [_swp(uplink_mac="aabbcc000007", lldp_mac="aabbcc000008", lldp_port="eth0")],
        [_owner("aabbcc000007", "dev:c")],
        [_port_row("dev:c", "dev:c/port/eth0"), _port_row("dev:c", "dev:c/port/eth1")],
        [],
    )
    bucket = report["cable-from-uplink-record"]
    assert bucket["edges"] == []
    assert bucket["unresolved"] == 1


def test_mismatched_chassis_macs_do_not_let_the_lldp_rule_borrow_the_uplinks_port_index():
    """One switch port states an uplink record for one chassis (dev:ua,
    uplink_remote_port 3) and an LLDP record for a different chassis
    (dev:ub, port id "Port 7")."""
    report = reasoner.resolve_stated_cables(
        [
            _swp(
                "dev:sw/port/port25",
                uplink_mac="aa00000000a1",
                uplink_remote_port=3,
                lldp_mac="bb00000000b1",
                lldp_port="Port 7",
            )
        ],
        [_owner("aa00000000a1", "dev:ua"), _owner("bb00000000b1", "dev:ub")],
        [
            _port_row("dev:ua", "dev:ua/port/port3"),
            _port_row("dev:ub", "dev:ub/port/port3"),
            _port_row("dev:ub", "dev:ub/port/port7"),
        ],
        [],
    )
    uplink = report["cable-from-uplink-record"]
    assert {e["a"] for e in uplink["edges"]} | {e["z"] for e in uplink["edges"]} == {
        "dev:sw/port/port25",
        "dev:ua/port/port3",
    }
    lldp = report["cable-from-lldp-record"]
    assert lldp["edges"] == []
    assert lldp["unresolved"] == 1
    assert lldp["ambiguous"] == 0


def test_a_non_string_lldp_port_id_counts_unresolved_instead_of_raising():
    """A collector can write the port_id as an int from JSON."""
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc00000a", lldp_port=7)],
        [_owner("aabbcc00000a", "dev:e")],
        [_port_row("dev:e", "dev:e/port/eth0"), _port_row("dev:e", "dev:e/port/eth1")],
        [],
    )
    bucket = report["cable-from-lldp-record"]
    assert bucket["edges"] == []
    assert bucket["unresolved"] == 1


def test_an_lldp_port_id_resolves_through_a_realized_interface_when_no_port_shares_its_name():
    """A port id naming an Interface (not a Port directly): resolves to the
    Port that Interface is REALIZED_BY, the same fallback
    `cable-from-endpoint-mac`'s Cypher join uses."""
    report = reasoner.resolve_stated_cables(
        [_swp(lldp_mac="aabbcc000009", lldp_port="eth0")],
        [_owner("aabbcc000009", "dev:d")],
        [_port_row("dev:d", "dev:d/port/phy0"), _port_row("dev:d", "dev:d/port/other")],
        [{"if_uid": "dev:d/if/eth0", "port_uid": "dev:d/port/phy0"}],
    )
    edges = report["cable-from-lldp-record"]["edges"]
    assert len(edges) == 1
    assert "dev:d/port/phy0" in (edges[0]["a"], edges[0]["z"])


def test_a_failing_rule_aborts_the_whole_run():
    """A rule that raises fails the run (core/finalize.py), which is discarded
    unpublished, so the rules committed before it are never read. Nothing after
    the failing rule runs: no later rule and no containment step."""
    s = FakeSession(FakeTx(fail_on="GATEWAY_FOR"))
    with pytest.raises(RuntimeError):
        reasoner.run(s, ts_ms=1_000)
    calls = [q for q, _ in s.tx.calls]
    failed = next(i for i, q in enumerate(calls) if "GATEWAY_FOR" in q)
    assert failed == len(calls) - 1
    assert reasoner.CONTAINMENT_ADDRESSES not in calls
    assert s.transactions[-1] == ("write", [calls[-1]])


def test_gateway_rule_is_parameterised_not_string_matched():
    s = FakeSession()
    reasoner.run(s, ts_ms=1_000)
    gateway = next(q for q, _ in s.tx.calls if "GATEWAY_FOR" in q)
    params = next(p for q, p in s.tx.calls if "GATEWAY_FOR" in q)
    assert "role: 'router'" not in gateway, "role must not be hardcoded in the pattern"
    assert params["gateway_roles"] == reasoner.GATEWAY_ROLES


def test_the_fixtures_satisfy_the_gateway_rule_without_needing_a_database():
    """The `derived-gateway` scenario in demo.py passes only if a fixture device
    completes the rule's whole pattern."""
    nodes, rels = {}, []
    for name in ("mini-dc.yaml", "mini-enterprise.yaml"):
        batch = load_fixture(FIXTURES / name)
        nodes.update({n.uid: n for n in batch.nodes})
        rels.extend(batch.rels)

    def ends(rel_type):
        return {(r.start_uid, r.end_uid) for r in rels if r.rel_type == rel_type}

    on, has_ip, in_ = ends("ON"), ends("HAS_IP"), ends("IN")
    routing = {
        u for u, n in nodes.items() if n.label == "Device" and n.props.get("role") in reasoner.GATEWAY_ROLES
    }
    connected = {u for u, n in nodes.items() if n.label == "Prefix" and n.props.get("kind") == "connected"}

    derived = {
        (nodes[dev].props.get("hostname"), pfx)
        for iface, dev in on
        if dev in routing
        for i2, ip in has_ip
        if i2 == iface
        for ip2, pfx in in_
        if ip2 == ip and pfx in connected
    }
    # the FortiGate (role 'firewall') derives no pair
    assert derived == {
        # pfx:corp:10.20.0.0/24 is anchored on its owning VrfInstance uid;
        # pfx:corp:10.99.0.0/24 has no ORIGINATES edge in the fixture, so it is
        # l3dom-anchored
        ("fra01-core-01", "pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24"),
        ("fra01-core-01", "pfx:corp:10.99.0.0/24"),
        ("fra01-core-02", "pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24"),
    }


def test_every_collector_role_is_a_known_value():
    emitted = {
        "vyos": "router",  # vyos.py
        "cisco-cli": "router",  # cisco_common.py, covers nxos/iosxe/iosxr
        "unifi-gateway": "gateway",  # unifi.py ROLE map: ugw/udm/uxg
        "unifi-switch": "switch",
        "unifi-ap": "ap",
        "checkpoint": "firewall",  # checkpoint.py
        "aci-leaf": "leaf",  # apic.py, from fabricNode
        "aci-spine": "spine",
        "fallback": "unknown",  # apic/unifi/manual when the vendor says nothing
    }
    derives = {k for k, v in emitted.items() if v in reasoner.GATEWAY_ROLES}
    assert derives == {"vyos", "cisco-cli", "unifi-gateway"}


def test_the_fixture_has_exactly_one_firewall_only_connected_prefix():
    """mini-enterprise.yaml pins the shape gateway-from-sole-firewall-interface is written
    for."""
    batch = load_fixture(FIXTURES / "mini-enterprise.yaml")
    nodes = {n.uid: n for n in batch.nodes}
    rels = batch.rels

    def ends(rel_type):
        return {(r.start_uid, r.end_uid) for r in rels if r.rel_type == rel_type}

    on, has_ip, in_ = ends("ON"), ends("HAS_IP"), ends("IN")
    firewalls = {u for u, n in nodes.items() if n.label == "Device" and n.props.get("role") == "firewall"}
    gateway_role_devices = {
        u for u, n in nodes.items() if n.label == "Device" and n.props.get("role") in reasoner.GATEWAY_ROLES
    }
    connected = {u for u, n in nodes.items() if n.label == "Prefix" and n.props.get("kind") == "connected"}

    def owning_devices(pfx: str) -> set[str]:
        return {
            dev
            for iface, dev in on
            for i2, ip in has_ip
            if i2 == iface
            for ip2, p in in_
            if ip2 == ip and p == pfx
        }

    derived = set()
    for iface, dev in on:
        if dev not in firewalls:
            continue
        for i2, ip in has_ip:
            if i2 != iface:
                continue
            for ip2, pfx in in_:
                if ip2 != ip or pfx not in connected:
                    continue
                if not (owning_devices(pfx) & gateway_role_devices):
                    derived.add((dev, pfx))

    assert derived == {("dev:fra01-fgt-01", "pfx:guest:172.31.10.0/24")}


# --- address containment ------------------------------------------------------------


def _addr(uid, ip, l3dom="home", anchor="home"):
    return {"uid": uid, "ip": ip, "l3dom": l3dom, "anchor": anchor}


def _pfx(uid, cidr, l3dom="home", anchor="home"):
    return {"uid": uid, "cidr": cidr, "l3dom": l3dom, "anchor": anchor}


def test_containment_joins_v4_and_v6_by_family():
    pairs = reasoner.containment_pairs(
        [_addr("a4", "10.0.0.5"), _addr("a6", "2001:db8::5")],
        [_pfx("p4", "10.0.0.0/24"), _pfx("p6", "2001:db8::/64")],
        [],
    )
    assert pairs == [{"ip": "a4", "pfx": "p4"}, {"ip": "a6", "pfx": "p6"}]


def test_containment_never_crosses_l3dom_for_scope_anchored_addresses():
    pairs = reasoner.containment_pairs(
        [_addr("a", "10.0.0.5", l3dom="home", anchor="home")],
        [_pfx("p", "10.0.0.0/24", l3dom="lab", anchor="lab")],
        [],
    )
    assert pairs == []


def test_bd_anchor_narrows_to_the_serving_prefixes():
    pairs = reasoner.containment_pairs(
        [_addr("a", "10.0.0.5", l3dom="home", anchor="bd:vlan:fab0:10")],
        [
            _pfx("served", "10.0.0.0/24", l3dom="home", anchor="vrf:dev:r1:default"),
            _pfx("other", "10.0.0.0/24", l3dom="home", anchor="vrf:dev:r2:default"),
        ],
        [{"bd": "bd:vlan:fab0:10", "pfx": "served"}],
    )
    assert pairs == [{"ip": "a", "pfx": "served"}]


def test_bd_anchor_without_a_gateway_chain_falls_back_to_l3dom():
    """A UniFi SVI has no BOUND_TO edge."""
    pairs = reasoner.containment_pairs(
        [_addr("a", "10.0.0.5", l3dom="home", anchor="bd:vlan:fab0:10")],
        [_pfx("p", "10.0.0.0/24", l3dom="home", anchor="vrf:dev:r1:default")],
        [],
    )
    assert pairs == [{"ip": "a", "pfx": "p"}]


def test_vrf_anchor_joins_same_anchor_only_never_by_l3dom():
    """Overlapping address space in two VRFs sharing an l3dom display string: the
    router's own address must join only its VRF's prefix instance."""
    pairs = reasoner.containment_pairs(
        [_addr("a", "10.0.0.1", l3dom="corp", anchor="vrf:dev:r1:red")],
        [
            _pfx("own", "10.0.0.0/24", l3dom="corp", anchor="vrf:dev:r1:red"),
            _pfx("other-vrf", "10.0.0.0/24", l3dom="corp", anchor="vrf:dev:r1:blue"),
        ],
        [],
    )
    assert pairs == [{"ip": "a", "pfx": "own"}]


def test_anycast_style_multiplicity_emits_one_pair_per_instance():
    """Option-1 semantics: N prefix instances of one subnet in one routing domain
    (an anycast/FHRP fabric) each get an edge; readers use DISTINCT."""
    pairs = reasoner.containment_pairs(
        [_addr("a", "10.0.0.5", l3dom="fab", anchor="home-less")],
        [
            _pfx("leaf1", "10.0.0.0/24", l3dom="fab", anchor="vrf:dev:l1:t"),
            _pfx("leaf2", "10.0.0.0/24", l3dom="fab", anchor="vrf:dev:l2:t"),
        ],
        [],
    )
    assert pairs == [{"ip": "a", "pfx": "leaf1"}, {"ip": "a", "pfx": "leaf2"}]


def test_containment_output_is_sorted_and_deduplicated():
    a = _addr("a", "10.0.0.5")
    pairs = reasoner.containment_pairs(
        [a, dict(a)],
        [_pfx("p2", "10.0.0.0/24"), _pfx("p1", "10.0.0.0/25")],
        [],
    )
    assert pairs == [{"ip": "a", "pfx": "p1"}, {"ip": "a", "pfx": "p2"}]


def test_malformed_addresses_and_cidrs_are_skipped_not_raised():
    pairs = reasoner.containment_pairs(
        [_addr("bad", "not-an-ip"), _addr("none", None), _addr("ok", "10.0.0.5")],
        [_pfx("badp", "10.0.0.0/33"), _pfx("nonep", None), _pfx("p", "10.0.0.0/24")],
        [],
    )
    assert pairs == [{"ip": "ok", "pfx": "p"}]


class MarkerTx(FakeTx):
    """Serves canned rows per containment query."""

    def __init__(self, rows_by_marker):
        super().__init__()
        self.rows_by_marker = rows_by_marker

    def run(self, query, **params):
        self.calls.append((query, params))
        for marker, rows in self.rows_by_marker.items():
            if marker in query:
                return FakeResult(rows)
        return FakeResult([{"n": 1}] if "MERGE" in query else [])


def test_containment_write_runs_last_with_sorted_deduped_pairs():
    tx = MarkerTx(
        {
            "MATCH (h)-[r:HAS_IP]": [
                {"uid": "ipb", "ip": "10.0.0.6", "l3dom": "home", "anchor": "home"},
                {"uid": "ipa", "ip": "10.0.0.5", "l3dom": "home", "anchor": "home"},
            ],
            "cidr AS cidr": [{"uid": "p", "cidr": "10.0.0.0/24", "l3dom": "home", "anchor": "vrf:d:r:t"}],
            "AS bd": [],
        }
    )
    s = FakeSession(tx)
    results = reasoner.run(s, ts_ms=1_000)
    write_idx = next(i for i, (q, _) in enumerate(tx.calls) if q == reasoner.CONTAINMENT_WRITE)
    gateway_idx = next(i for i, (q, _) in enumerate(tx.calls) if "GATEWAY_FOR" in q and "MERGE" in q)
    assert write_idx == len(tx.calls) - 1, "the containment write must be the run's last call"
    assert write_idx > gateway_idx, "containment reads the gateway rule's committed writes"
    _, params = tx.calls[write_idx]
    assert params["pairs"] == [{"ip": "ipa", "pfx": "p"}, {"ip": "ipb", "pfx": "p"}]
    assert params["cts"] == params["ts"] == 1_000
    assert results[-1] == {"rule": "address-containment", "edges": 1}


def test_containment_pairing_runs_after_the_rules_commit_and_writes_in_chunks(monkeypatch):
    from hst.core.loader import CHUNK
    from hst.reasoner import runner

    addresses = [_addr(f"ip{i}", f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}") for i in range(CHUNK + 1)]
    tx = MarkerTx({"MATCH (h)-[r:HAS_IP]": addresses, "cidr AS cidr": [_pfx("p", "10.0.0.0/8")], "AS bd": []})

    class TrackingSession(FakeSession):
        in_tx = False

        def execute_write(self, work):
            self.in_tx = True
            try:
                return super().execute_write(work)
            finally:
                self.in_tx = False

    s = TrackingSession(tx)
    paired_in_tx = []
    real_pairs = runner.containment_pairs

    def tracking_pairs(*args):
        paired_in_tx.append(s.in_tx)
        return real_pairs(*args)

    monkeypatch.setattr(runner, "containment_pairs", tracking_pairs)
    results = reasoner.run(s, ts_ms=1_000)
    assert paired_in_tx == [False]
    writes = [p["pairs"] for q, p in tx.calls if q == reasoner.CONTAINMENT_WRITE]
    assert [len(w) for w in writes] == [CHUNK, 1]
    assert [t for t in s.transactions if reasoner.CONTAINMENT_WRITE in t[1]] == [
        ("write", [reasoner.CONTAINMENT_WRITE])
    ] * len(writes)
    assert results[-1] == {"rule": "address-containment", "edges": 2}


def test_the_containment_candidates_are_read_after_the_gateway_rule_commits():
    """The three candidate reads run in one read transaction of their own."""
    s = FakeSession()
    reasoner.run(s, ts_ms=1_000)
    reads = [
        reasoner.CONTAINMENT_ADDRESSES,
        reasoner.CONTAINMENT_PREFIXES,
        reasoner.CONTAINMENT_BD_MAP,
    ]
    assert ("read", reads) in s.transactions
    position = s.transactions.index(("read", reads))
    gateway = next(
        i for i, (_, queries) in enumerate(s.transactions) if any("GATEWAY_FOR" in q for q in queries)
    )
    assert gateway < position


def test_the_containment_reads_start_from_the_runs_own_nodes():
    assert "(ia:IpAddress:Obj {collection_ts: $cts})" in reasoner.CONTAINMENT_ADDRESSES
    assert "MATCH (p:Prefix:Obj {collection_ts: $cts})" in reasoner.CONTAINMENT_PREFIXES
    assert "(s:BridgeDomain:Obj {collection_ts: $cts})" in reasoner.CONTAINMENT_BD_MAP
    for query in (reasoner.CONTAINMENT_ADDRESSES, reasoner.CONTAINMENT_PREFIXES, reasoner.CONTAINMENT_BD_MAP):
        assert "coalesce(" not in query


def test_clear_deletes_chunk_edges_per_transaction_until_fewer_remain():
    from hst.core.loader import CHUNK

    class ClearTx(FakeTx):
        def __init__(self):
            super().__init__()
            self.left = 2 * CHUNK + 3

        def run(self, query, **params):
            if query == reasoner.CLEAR:
                self.calls.append((query, params))
                n = min(self.left, params["limit"])
                self.left -= n
                return FakeResult([{"n": n}])
            return super().run(query, **params)

    tx = ClearTx()
    s = FakeSession(tx)
    reasoner.run(s, ts_ms=1_000)
    clears = [p for q, p in tx.calls if q == reasoner.CLEAR]
    assert [p["limit"] for p in clears] == [CHUNK] * 3
    assert tx.left == 0
    assert s.transactions[:3] == [("write", [reasoner.CLEAR])] * 3
    assert "LIMIT $limit" in reasoner.CLEAR


def test_the_stated_cable_edges_are_written_chunk_at_a_time(monkeypatch):
    """Each rule's count sums its chunks."""
    from hst.core.loader import CHUNK
    from hst.reasoner import stated_cables

    edges = [
        {"a": f"a{i}", "z": f"z{i}", "source": "unifi-uplink", "rule": "cable-from-uplink-record"}
        for i in range(CHUNK + 2)
    ]

    def fake_resolve(*rows):
        return {
            "cable-from-uplink-record": {"edges": edges, "unresolved": 0, "ambiguous": 0},
            "cable-from-lldp-record": {"edges": [], "unresolved": 1, "ambiguous": 0},
        }

    class CableTx(FakeTx):
        def run(self, query, **params):
            self.calls.append((query, params))
            if query == stated_cables.STATED_CABLE_WRITE:
                return FakeResult([{"rule": "cable-from-uplink-record", "n": len(params["edges"])}])
            return FakeResult([])

    monkeypatch.setattr(stated_cables, "resolve_stated_cables", fake_resolve)
    s = FakeSession(CableTx())
    report = stated_cables._run_stated_cable_rules(s, ts=1_000, cts=1_000)
    writes = [p["edges"] for q, p in s.tx.calls if q == stated_cables.STATED_CABLE_WRITE]
    assert [len(w) for w in writes] == [CHUNK, 2]
    assert s.transactions[0] == (
        "read",
        [
            stated_cables.FETCH_STATED_CABLE_PORTS,
            stated_cables.FETCH_MAC_OWNERS,
            stated_cables.FETCH_DEVICE_PORTS,
            stated_cables.FETCH_REALIZED_PORTS,
        ],
    )
    assert s.transactions[1:] == [("write", [stated_cables.STATED_CABLE_WRITE])] * 2
    assert report["cable-from-uplink-record"]["edges"] == CHUNK + 2
    assert report["cable-from-lldp-record"] == {"edges": 0, "unresolved": 1, "ambiguous": 0}


def test_containment_matches_a_brute_force_scan_over_mixed_prefix_lengths():
    """The prefix-length index must choose exactly what testing every address
    against every prefix chose: nested prefixes, a duplicate cidr under two uids,
    both families, and every anchor tier."""
    import ipaddress
    import random

    rng = random.Random(3)
    prefixes = []
    for i in range(300):
        if rng.random() < 0.8:
            n = rng.choice([8, 16, 20, 24, 28, 30, 32])
            net = ipaddress.ip_network(
                (f"10.{rng.randrange(4)}.{rng.randrange(4)}.{rng.randrange(256)}", n), False
            )
        else:
            n = rng.choice([32, 48, 64, 120, 128])
            net = ipaddress.ip_network((f"2001:db8:{rng.randrange(4):x}::{rng.randrange(256):x}", n), False)
        anchor = rng.choice(["home", "lab", "vrf:d:r:t", "vrf:d:r:u"])
        prefixes.append(_pfx(f"p{i}", str(net), l3dom=rng.choice(["home", "lab"]), anchor=anchor))
    prefixes.append(dict(prefixes[0], uid="p-dup"))
    addresses = []
    for i in range(400):
        if rng.random() < 0.8:
            ip = f"10.{rng.randrange(4)}.{rng.randrange(4)}.{rng.randrange(256)}"
        else:
            ip = f"2001:db8:{rng.randrange(4):x}::{rng.randrange(256):x}"
        anchor = rng.choice(["home", "lab", "vrf:d:r:t", "bd:one", "bd:none"])
        addresses.append(_addr(f"a{i}", ip, l3dom=rng.choice(["home", "lab"]), anchor=anchor))
    bd_serving = [{"bd": "bd:one", "pfx": p["uid"]} for p in prefixes[::7]]

    expected = set()
    served = {row["pfx"] for row in bd_serving}
    for a in addresses:
        addr = ipaddress.ip_address(a["ip"])
        containing = [p for p in prefixes if addr in ipaddress.ip_network(p["cidr"])]
        if a["anchor"].startswith("vrf:"):
            chosen = [p for p in containing if p["anchor"] == a["anchor"]]
        elif a["anchor"] == "bd:one":
            chosen = [p for p in containing if p["uid"] in served]
            chosen = chosen or [p for p in containing if p["l3dom"] == a["l3dom"]]
        else:
            chosen = [p for p in containing if p["l3dom"] == a["l3dom"]]
        expected.update((a["uid"], p["uid"]) for p in chosen)

    pairs = reasoner.containment_pairs(addresses, prefixes, bd_serving)
    assert len(expected) > 100
    assert pairs == [{"ip": ip, "pfx": pfx} for ip, pfx in sorted(expected)]


def test_containment_does_not_test_every_address_against_every_prefix(monkeypatch):
    import ipaddress

    tests = 0
    real_contains = ipaddress._BaseNetwork.__contains__

    def counting_contains(self, other):
        nonlocal tests
        tests += 1
        return real_contains(self, other)

    monkeypatch.setattr(ipaddress._BaseNetwork, "__contains__", counting_contains)
    addresses = [_addr(f"a{i}", f"10.1.{i}.5") for i in range(200)]
    prefixes = [_pfx(f"p{i}", f"10.1.{i}.0/24") for i in range(200)]
    pairs = reasoner.containment_pairs(addresses, prefixes, [])
    assert len(pairs) == 200
    assert tests < len(addresses) * len(prefixes) // 10


def test_the_fixtures_satisfy_the_containment_rule_without_needing_a_database():
    """Every pair here exists as a collector-emitted IN edge in the fixtures."""
    nodes, rels = {}, []
    for name in ("mini-dc.yaml", "mini-enterprise.yaml"):
        batch = load_fixture(FIXTURES / name)
        nodes.update({n.uid: n for n in batch.nodes})
        rels.extend(batch.rels)

    def ends(rel_type):
        return {(r.start_uid, r.end_uid) for r in rels if r.rel_type == rel_type}

    on, has_ip, in_ = ends("ON"), ends("HAS_IP"), ends("IN")
    bound_to, realizes = ends("BOUND_TO"), ends("REALIZES")
    routing = {
        u for u, n in nodes.items() if n.label == "Device" and n.props.get("role") in reasoner.GATEWAY_ROLES
    }
    connected = {u for u, n in nodes.items() if n.label == "Prefix" and n.props.get("kind") == "connected"}
    gateway_for = {
        (iface, pfx)
        for iface, dev in on
        if dev in routing
        for i2, ip in has_ip
        if i2 == iface
        for ip2, pfx in in_
        if ip2 == ip and pfx in connected
    }
    bd_serving = [
        {"bd": bd, "pfx": pfx}
        for iface, pfx in gateway_for
        for i2, vlan in bound_to
        if i2 == iface
        for v2, bd in realizes
        if v2 == vlan
    ]
    addresses = [
        {
            "uid": u,
            "ip": nodes[u].props.get("ip"),
            "l3dom": nodes[u].props.get("l3dom"),
            "anchor": nodes[u].props.get("anchor"),
        }
        for u in {ip for _, ip in has_ip}
        if u in nodes and nodes[u].label == "IpAddress"
    ]
    prefixes = [
        {
            "uid": u,
            "cidr": nodes[u].props.get("cidr"),
            "l3dom": nodes[u].props.get("l3dom"),
            "anchor": nodes[u].props.get("anchor"),
        }
        for u in connected
    ]

    pairs = reasoner.containment_pairs(addresses, prefixes, bd_serving)
    assert pairs == [
        {"ip": "ip:corp:10.0.10.5", "pfx": "pfx:vrf-aci-fab1-tn-prod-ctx1:10.0.10.0/24"},
        {"ip": "ip:corp:10.0.20.5", "pfx": "pfx:vrf-aci-fab1-tn-prod-ctx1:10.0.20.0/24"},
        {"ip": "ip:corp:10.20.0.1", "pfx": "pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24"},
        {"ip": "ip:corp:10.20.0.3", "pfx": "pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24"},
        {"ip": "ip:corp:10.99.0.1", "pfx": "pfx:corp:10.99.0.0/24"},
        {"ip": "ip:corp:10.99.0.2", "pfx": "pfx:corp:10.99.0.0/24"},
        {
            "ip": "ip:vrf-dev-fra01-core-01-corp:10.20.0.2",
            "pfx": "pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24",
        },
    ]
    assert all((p["ip"], p["pfx"]) in in_ for p in pairs), (
        "a pair of containment_pairs has no IN edge in the fixture"
    )


# --- cable-from-neighbor-name: serial or name instead of a MAC ---------------------------


def _named_swp(uid="sw/port/1", **hints):
    return {**_swp(uid), **hints}


def _named_port_row(device_uid, port_uid, *, hostname=None, identities=None, serial=None):
    return {
        **_port_row(device_uid, port_uid),
        "hostname": hostname,
        "identities": identities,
        "serial": serial,
    }


def test_cable_from_neighbor_name_is_resolved_in_python_after_the_lldp_record_rule():
    names = [name for name, _ in reasoner.RULES]
    assert dict(reasoner.RULES)["cable-from-neighbor-name"] is None
    assert names.index("cable-from-lldp-record") < names.index("cable-from-neighbor-name")
    assert names.index("cable-from-neighbor-name") < names.index("cable-from-last-connection")


def test_cdp_serial_resolves_the_device_and_the_port_id_resolves_the_port():
    """A Nexus far end's CDP device id carries its serial, which is the device
    uid's own key: the join is exact, whatever either box calls the other."""
    report = reasoner.resolve_stated_cables(
        [
            _named_swp(
                cdp_neighbor_name="core2.example.com",
                cdp_neighbor_serial="ABC1234XYZ",
                cdp_neighbor_port="Ethernet1/30",
            )
        ],
        [],
        [
            _named_port_row(
                "dev:abc1234xyz",
                "dev:abc1234xyz/port/eth1-30",
                hostname="something-else",
                serial="ABC1234XYZ",
            ),
            _named_port_row(
                "dev:abc1234xyz",
                "dev:abc1234xyz/port/eth1-31",
                hostname="something-else",
                serial="ABC1234XYZ",
            ),
        ],
        [],
    )
    bucket = report["cable-from-neighbor-name"]
    assert bucket["edges"] == [
        {
            "a": "dev:abc1234xyz/port/eth1-30",
            "z": "sw/port/1",
            "source": "cdp",
            "rule": "cable-from-neighbor-name",
        }
    ]
    assert bucket["unresolved"] == 0 and bucket["ambiguous"] == 0


def test_lldp_name_resolves_by_full_name_then_short_name_and_abbreviated_port_id():
    report = reasoner.resolve_stated_cables(
        [_named_swp(lldp_neighbor_name="edge1.example.com", lldp_neighbor_port="Gi0/0/0")],
        [],
        [
            _named_port_row("dev:edge", "dev:edge/port/gi0-0-0", hostname="EDGE1", identities=["EDGE1"]),
            _named_port_row("dev:edge", "dev:edge/port/gi0-0-1", hostname="EDGE1", identities=["EDGE1"]),
        ],
        [],
    )
    bucket = report["cable-from-neighbor-name"]
    assert [e["source"] for e in bucket["edges"]] == ["lldp"]
    assert {bucket["edges"][0]["a"], bucket["edges"][0]["z"]} == {"sw/port/1", "dev:edge/port/gi0-0-0"}


def test_a_name_no_device_carries_counts_unresolved_and_a_shared_short_name_ambiguous():
    report = reasoner.resolve_stated_cables(
        [
            _named_swp(
                "sw/port/1", lldp_neighbor_name="carrier-router.isp.net", lldp_neighbor_port="xe-0/2/2"
            ),
            _named_swp("sw/port/2", cdp_neighbor_name="core", cdp_neighbor_port="Ethernet1/1"),
        ],
        [],
        [
            _named_port_row("dev:a", "dev:a/port/eth1-1", hostname="core.site-a.example.com"),
            _named_port_row("dev:b", "dev:b/port/eth1-1", hostname="core.site-b.example.com"),
        ],
        [],
    )
    bucket = report["cable-from-neighbor-name"]
    assert bucket["edges"] == []
    assert bucket["unresolved"] == 1
    assert bucket["ambiguous"] == 1


def test_neighbor_name_yields_to_a_pair_the_mac_rule_already_stated():
    """One port carrying both a chassis MAC and a name for the same far end
    states one cable, from the MAC-resolved rule, never a second beside it."""
    report = reasoner.resolve_stated_cables(
        [{**_swp(lldp_mac="aabbcc000001", lldp_port="eth0"), "lldp_neighbor_name": "single"}],
        [_owner("aabbcc000001", "dev:single")],
        [_named_port_row("dev:single", "dev:single/port/eth0", hostname="single")],
        [],
    )
    assert len(report["cable-from-lldp-record"]["edges"]) == 1
    assert report["cable-from-neighbor-name"]["edges"] == []
    assert report["cable-from-neighbor-name"]["unresolved"] == 0


def test_a_sole_port_device_resolves_from_its_name_with_no_port_id():
    report = reasoner.resolve_stated_cables(
        [_named_swp(cdp_neighbor_name="ap1")],
        [],
        [_named_port_row("dev:ap", "dev:ap/port/eth0", hostname="ap1")],
        [],
    )
    edges = report["cable-from-neighbor-name"]["edges"]
    assert len(edges) == 1 and "dev:ap/port/eth0" in (edges[0]["a"], edges[0]["z"])


def test_stated_cable_port_fetch_reads_the_name_and_serial_hints():
    for column in ("lldp_neighbor_name", "cdp_neighbor_name", "cdp_neighbor_port", "cdp_neighbor_serial"):
        assert column in reasoner.FETCH_STATED_CABLE_PORTS
    for column in ("hostname", "identities", "serial"):
        assert column in reasoner.FETCH_DEVICE_PORTS


# --- cable-from-arp-port and bgp-peer-from-address ---------------------------------------


def _edge_addr(ip: str, edge_port: str | None = "vco:e:edge:e1/port/gi3") -> dict:
    return {"ip": ip, "if_uid": "vco:e:edge:e1/if/gi3", "device_uid": "vco:e:edge:e1", "port_uid": edge_port}


def _arp(ip: str, mac: str, dev: str = "dev:sw1", iface: str = "Vlan10") -> dict:
    return {"device_uid": dev, "ip": ip, "mac": mac, "interface_name": iface}


def _mac(mac: str, port: str, dev: str = "dev:sw1") -> dict:
    return {"device_uid": dev, "vlan": 10, "mac": mac, "port_name": port}


def test_arp_cable_resolves_when_the_mac_sits_alone_on_one_port():
    report = reasoner.resolve_arp_cables(
        [_edge_addr("10.9.9.1")],
        [_arp("10.9.9.1", "aabbcc000001")],
        [_mac("aabbcc000001", "Ethernet1/7")],
    )
    assert report["unresolved"] == 0 and report["shared"] == 0
    assert report["edges"] == [
        {
            "a": "dev:sw1/port/eth1-7",
            "z": "vco:e:edge:e1/port/gi3",
            "basis": "arp 10.9.9.1 mac aabbcc000001 port Ethernet1/7",
        }
    ]


def test_arp_cable_is_unresolved_when_two_edges_hold_the_address():
    """A branch and a hub both number their LAN transit 10.9.9.1: the one
    ARP row cannot say which edge the switch saw, so neither gets a cable."""
    report = reasoner.resolve_arp_cables(
        [_edge_addr("10.9.9.1"), _edge_addr("10.9.9.1", edge_port="vco:e:edge:e2/port/gi3")],
        [_arp("10.9.9.1", "aabbcc000001")],
        [_mac("aabbcc000001", "Ethernet1/7")],
    )
    assert report["edges"] == [] and report["unresolved"] == 2


def test_arp_cable_refuses_a_port_that_carries_other_macs():
    report = reasoner.resolve_arp_cables(
        [_edge_addr("10.9.9.1")],
        [_arp("10.9.9.1", "aabbcc000001")],
        [_mac("aabbcc000001", "Ethernet1/48"), _mac("aabbcc000002", "Ethernet1/48")],
    )
    assert report["edges"] == [] and report["shared"] == 1


def test_arp_cable_is_unresolved_without_a_mac_row_or_without_an_edge_port():
    no_mac = reasoner.resolve_arp_cables([_edge_addr("10.9.9.1")], [_arp("10.9.9.1", "aabbcc000001")], [])
    assert no_mac["edges"] == [] and no_mac["unresolved"] == 1
    no_port = reasoner.resolve_arp_cables(
        [_edge_addr("10.9.9.1", edge_port=None)],
        [_arp("10.9.9.1", "aabbcc000001")],
        [_mac("aabbcc000001", "Ethernet1/7")],
    )
    assert no_port["edges"] == [] and no_port["unresolved"] == 1
    two_devices = reasoner.resolve_arp_cables(
        [_edge_addr("10.9.9.1")],
        [_arp("10.9.9.1", "aabbcc000001"), _arp("10.9.9.1", "aabbcc000001", dev="dev:sw2")],
        [_mac("aabbcc000001", "Ethernet1/7")],
    )
    assert two_devices["edges"] == [] and two_devices["unresolved"] == 1


def test_arp_cable_normalizes_the_arp_mac_before_the_mac_table_join():
    report = reasoner.resolve_arp_cables(
        [_edge_addr("10.9.9.1")],
        [_arp("10.9.9.1", "aabb.cc00.0001")],
        [_mac("aabbcc000001", "Ethernet1/7")],
    )
    assert len(report["edges"]) == 1


def test_bgp_peer_rule_pairs_once_and_carries_its_provenance():
    rule = next(q for name, q in reasoner.RULES if name == "bgp-peer-from-address")
    assert rule is not None
    assert "sa.peer_asn = sb.local_asn AND sb.peer_asn = sa.local_asn" in rule
    assert "da.uid < db.uid" in rule
    assert "p.rule = 'bgp-peer-from-address'" in rule and "p._scope = 'reasoner'" in rule


def test_arp_cable_derivation_reads_only_the_devices_of_the_run(monkeypatch, tmp_path):
    """The side store keeps the newest rows of every uid it ever saw."""
    from hst.core import sidestore

    writes = []

    class _Session:
        def run(self, query, **params):
            if query == reasoner.FETCH_SDWAN_ADDRESSES:
                rows = [_edge_addr("10.9.9.1")]
            elif query == reasoner.FETCH_RUN_DEVICES:
                rows = [{"uid": "dev:sw1"}, {"uid": "vco:e:edge:e1"}]
            else:
                writes.append(params["edges"])
                rows = [{"n": len(params["edges"])}]

            class _R:
                def data(self_inner):
                    return rows

            return _R()

    def query(_store, sql):
        if "FROM arp" in sql:
            return [_arp("10.9.9.1", "aabbcc000001"), _arp("10.9.9.1", "aabbcc000001", dev="dev:fdo1234")]
        assert "dev:fdo1234" not in sql
        return [_mac("aabbcc000001", "Ethernet1/7")]

    monkeypatch.setattr(sidestore, "query", query)
    report = reasoner.derive_arp_cables(_Session(), collection_ts=1, sidestore_dir=tmp_path)

    assert report == {"rule": "cable-from-arp-port", "edges": 1, "unresolved": 0, "shared": 0}
    assert [edge["a"] for edge in writes[0]] == ["dev:sw1/port/eth1-7"]


def test_arp_cable_derivation_skips_the_store_when_no_edge_holds_an_address():
    class _Session:
        def run(self, query, **params):
            class _R:
                def data(self_inner):
                    return []

            return _R()

    report = reasoner.derive_arp_cables(_Session(), collection_ts=1, sidestore_dir=None)
    assert report == {"rule": "cable-from-arp-port", "edges": 0, "unresolved": 0, "shared": 0}


def test_the_zia_forwarding_joins_draw_an_edge_only_for_one_match():
    from hst import reasoner

    names = [name for name, _query in reasoner.RULES]
    rules = dict(reasoner.RULES)
    order = [
        "zia-forwarding-to-zpa-segment",
        "zia-forwarding-to-zpa-segment-group",
        "zia-forwarding-to-zpa-server-group",
    ]
    assert [names.index(n) for n in order] == sorted(names.index(n) for n in order)
    assert names.index(order[1]) == names.index(order[0]) + 1
    for name in order:
        assert "size(found) = 1" in rules[name] and "AS ambiguous" in rules[name]
    assert "STEERS_VIA" in rules["zia-forwarding-to-zpa-server-group"]


def test_the_fabric_port_markers_are_reasoner_owned_and_cleared():
    assert "REMOVE fp.binding_issue, fp.binding_ports" in reasoner.CLEAR_PROPS
    assert "REMOVE ep.infra" in reasoner.CLEAR_PROPS
    assert "SET fp.binding_issue = e.issue, fp.binding_ports = e.ports" in reasoner.FABRIC_PORT_ISSUE_WRITE


# --- the segment attachment rules (reasoner/catalog.py) ----------------------------
#
# Cypher: their graph semantics are asserted behind the `db` marker
# (tests/test_integration_db.py). What a database-free test can pin is their
# place in the list, their guards and the shape they MERGE.

_ATTACH_RULES = ("attached-from-vlan-binding", "attached-from-cable", "prefix-in-from-attachment")


def test_the_attachment_rules_run_after_every_cable_rule_and_the_prefix_rule_runs_last():
    names = [name for name, _ in reasoner.RULES]
    cables = [n for n in names if n.startswith("cable-from-")]
    assert cables
    for rule in _ATTACH_RULES:
        assert all(names.index(c) < names.index(rule) for c in cables), rule
    assert names.index("prefix-in-from-attachment") > names.index("attached-from-vlan-binding")
    assert names.index("prefix-in-from-attachment") > names.index("attached-from-cable")


def test_every_attachment_rule_is_reasoner_owned_and_pinned_to_the_run():
    rules = dict(reasoner.RULES)
    for name in _ATTACH_RULES:
        query = rules[name]
        assert query is not None
        assert f".rule = '{name}'" in query
        assert "derived = true" in query
        assert "_scope = 'reasoner'" in query and ".collection_ts = $cts" in query
        assert "i.collection_ts = $cts" in query


def test_the_vlan_binding_rule_names_an_svi_svi_and_every_other_bound_interface_subif():
    query = dict(reasoner.RULES)["attached-from-vlan-binding"]
    assert query is not None
    assert "(i:Interface:Obj)-[bt:BOUND_TO]->(v:VlanInstance)-[rz:REALIZES]->(bd:BridgeDomain)" in query
    assert "MERGE (i)-[a:ATTACHED_TO {source: 'reasoner'}]->(bd)" in query
    assert "a.basis = CASE WHEN i.kind = 'svi' THEN 'svi' ELSE 'subif' END" in query


def test_the_cable_rule_reads_the_native_vlan_of_the_far_port_for_an_addressed_untagged_interface():
    query = dict(reasoner.RULES)["attached-from-cable"]
    assert query is not None
    assert "(i:Interface:Obj)-[rb:REALIZED_BY]->(p:Port)-[c:CONNECTED_TO]-(far:Port)" in query
    assert "-[cr:CARRIES]->(v:VlanInstance)-[rz:REALIZES]->(bd:BridgeDomain)" in query
    assert "cr.native = true" in query
    assert "NOT coalesce(i.kind, '') IN ['svi', 'subif']" in query
    # an interface with no address is no gateway; one bound to a VLAN is the other rule's
    assert "MATCH (i)-[h:HAS_IP]->(ia:IpAddress)" in query
    assert "AND NOT EXISTS {\n    MATCH (i)-[b:BOUND_TO]->(bv:VlanInstance)" in query
    assert "a.basis = 'cable'" in query


def test_the_prefix_rule_writes_the_endpoint_in_edge_and_leaves_a_stated_pair_alone():
    query = dict(reasoner.RULES)["prefix-in-from-attachment"]
    assert query is not None
    assert "(i:Interface:Obj)-[a:ATTACHED_TO]->(bd:BridgeDomain)" in query
    assert "-[n:IN]->(p:Prefix {kind: 'connected'})" in query
    assert "MERGE (p)-[r:IN {source: 'reasoner'}]->(bd)" in query
    assert "coalesce(e.source, '') <> 'reasoner'" in query
    assert "p.collection_ts = $cts" in query


def test_the_sole_segment_interface_rule_reads_the_attachments_and_leaves_a_served_prefix_alone():
    """The one addressed interface of a segment on its prefix is the
    prefix's gateway whatever its role. It reads the attachment edges, so it
    runs after them, and credits nothing on a segment where another attached
    interface holds the prefix or on a prefix a gateway already serves. Its
    graph semantics are asserted behind the `db` marker
    (test_integration_db.py::test_the_sole_interface_of_a_segment_is_its_gateway_whatever_the_role)."""
    names = [name for name, _ in reasoner.RULES]
    rule = "gateway-from-sole-segment-interface"
    for before in (*_ATTACH_RULES, "gateway-from-router-interface", "gateway-from-sole-firewall-interface"):
        assert names.index(before) < names.index(rule), before
    query = dict(reasoner.RULES)[rule]
    assert query is not None
    assert "(d:Device:Obj)<-[o:ON]-(i:Interface)-[a:ATTACHED_TO]->(bd:BridgeDomain)" in query
    assert "NOT coalesce(d.role, '') IN $gateway_roles AND coalesce(d.role, '') <> 'firewall'" in query
    assert "MATCH (bd)<-[a2:ATTACHED_TO]-(i2:Interface)" in query
    assert "MATCH (p3:Prefix:Obj)<-[g:GATEWAY_FOR]-(i3:Interface)" in query
    assert "MERGE (i)-[c:GATEWAY_FOR {source: 'reasoner'}]->(p)" in query
    assert f".rule = '{rule}'" in query and "derived = true" in query
    assert "_scope = 'reasoner'" in query and "c.collection_ts = $cts" in query


def _interface_port_row(device_uid, port_uid, name):
    return {**_port_row(device_uid, port_uid), "name": name}


@pytest.mark.parametrize(
    ("printed", "port_name"),
    [
        ("Fi1/0/1", "FiveGigabitEthernet1/0/1"),
        ("BE10", "Bundle-Ether10"),
        ("Mg0/RP0/CPU0/0", "MgmtEth0/RP0/CPU0/0"),
    ],
)
def test_a_neighbor_port_id_printed_abbreviated_resolves_against_the_names_of_the_ports(printed, port_name):
    """The far end prints `Fi1/0/1`, `BE10` or `Mg0/RP0/CPU0/0`; its Ports are
    named in full, and the two slug differently. The cable lands on
    the Port whose name the abbreviation names, and on no other."""
    port_uid = uid.port("dev:cat", port_name)
    assert uid.port("dev:cat", printed) != port_uid
    report = reasoner.resolve_stated_cables(
        [_swp("sw/port/1", lldp_mac="aabbccddee01", lldp_port=printed)],
        [_owner("aabbccddee01", "dev:cat")],
        [
            _interface_port_row("dev:cat", port_uid, port_name),
            _interface_port_row(
                "dev:cat", uid.port("dev:cat", "GigabitEthernet1/0/2"), "GigabitEthernet1/0/2"
            ),
        ],
        [],
    )
    lldp = report["cable-from-lldp-record"]
    assert [frozenset((e["a"], e["z"])) for e in lldp["edges"]] == [frozenset(("sw/port/1", port_uid))]
    assert lldp["unresolved"] == 0


def test_a_neighbor_port_id_that_names_two_ports_resolves_to_none():
    report = reasoner.resolve_stated_cables(
        [_swp("sw/port/1", lldp_mac="aabbccddee01", lldp_port="F0/0/0/1")],
        [_owner("aabbccddee01", "dev:cat")],
        [
            _interface_port_row("dev:cat", "dev:cat/port/a", "FortyGigE0/0/0/1"),
            _interface_port_row("dev:cat", "dev:cat/port/b", "FiftyGigE0/0/0/1"),
        ],
        [],
    )
    lldp = report["cable-from-lldp-record"]
    assert lldp["edges"] == []
    assert lldp["unresolved"] == 1
