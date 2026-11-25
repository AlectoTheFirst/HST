"""The tests trace the Oslo office of the demo estate (osl01), a dual-stack VyOS site."""

from __future__ import annotations

import importlib
import importlib.util
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from tests.support.demo_trace_graph import TraceGraph, inline_query

from hst import path
from hst.collectors.unifi import normalize_unifi
from hst.collectors.vyos import normalize_vyos
from hst.core.fixtures import load_fixture
from hst.core.model import Batch

trace_mod = importlib.import_module("hst.path.trace")
nat_mod = importlib.import_module("hst.path.gates.nat")
pbr_mod = importlib.import_module("hst.path.gates.pbr")
# the zone-pair read of the firewall gate: every rule set of the pair, of both families
ZONE_PAIR = inline_query(importlib.import_module("hst.path.gates.firewall"), "co:CONTAINS]-(dst:Zone)")

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "fixtures" / "demo-enterprise"
VERSIONS = (1, 2, 3)

DEV = "dev:osl01-vyos-01"
NS = "vyos:osl01-vyos-01"
MAIN = f"vrf:{DEV}:default"
TABLE_100 = f"vrf:{DEV}:table100"
ETH0, ETH1_10, ETH1_20, WG0 = (f"{DEV}/if/{name}" for name in ("eth0", "eth1.10", "eth1.20", "wg0"))
MASQUERADE = f"{NS}:nat:source:100"
PORT_FORWARD = f"{NS}:nat:destination:10"
NAT66 = f"{NS}:nat66:source:10"
PBR4, PBR6 = f"{NS}:pbr:VPN-PBR", f"{NS}:pbr:ipv6:VPN-PBR6"

LAN_V4, LAN_V6 = "10.18.10.21", "fd00:18:10::21"
NAS_V4, NAS_V6 = "10.18.10.20", "fd00:18:10::20"
VPN_V4, VPN_V6 = "10.18.10.50", "fd00:18:10::50"
IOT_V4, IOT_V6 = "10.18.20.31", "fd00:18:20::31"
GUEST_V4, GUEST_V6 = "10.18.30.41", "fd00:18:30::41"
WAN_V4 = "203.0.113.202"
INTERNET_V4, INTERNET_V6 = "192.0.2.180", "2001:db8:ff00::180"
ENDPOINTS = {
    "osl01-pc-01": (LAN_V4, LAN_V6),
    "osl01-nas-01": (NAS_V4, NAS_V6),
    "osl01-vpn-01": (VPN_V4, VPN_V6),
    "osl01-cam-01": (IOT_V4, IOT_V6),
    "osl01-hub-01": ("10.18.20.32", "fd00:18:20::32"),
    "osl01-guest-01": (GUEST_V4, GUEST_V6),
}

# The router's own WireGuard carriers leave by eth0 in zone WAN and are judged by LOCAL-WAN
# (chain output): rule 10 accepts udp to the VPN provider 198.51.100.180 port 51820 (wg0);
# nothing accepts the partner tunnel's carrier to 198.51.100.190 port 51821 (wg1), so the
# default-action drops it.
LOCAL_WAN = f"{NS}:fw:LOCAL-WAN"
PARTNER_V4 = "172.20.0.10"
# a configured static to a lab network whose next hop 10.18.99.1 is in no connected network:
# FRR does not install it, the RIB rows do not hold it, and the RIB selects the default route
UNINSTALLED_V4 = "192.0.2.10"
# the router's own addresses, the gateway of each VLAN
RTR_LAN_V4, RTR_LAN_V6 = "10.18.10.1", "fd00:18:10::1"
RTR_IOT_V4, RTR_IOT_V6 = "10.18.20.1", "fd00:18:20::1"
RTR_GUEST_V4 = "10.18.30.1"
ADMITTED = "admitted from session state (established=accept, invalid=drop, related=accept)"


@cache
def _generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "gen_demo_enterprise", ROOT / "tools" / "gen_demo_enterprise.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@cache
def _estate(version: int) -> Batch:
    return load_fixture(DEMO_DIR / f"estate-v{version}.yaml")


def _trace(version: int, src: str, dst: str, **kwargs: Any) -> tuple[dict[str, Any], TraceGraph]:
    """`path.trace` on the loaded estate; every read it made was answered."""
    graph = TraceGraph(_estate(version))
    result = path.trace(graph, src, dst, **kwargs)
    assert graph.refused == []
    return result, graph


def _one(result: dict[str, Any]) -> dict[str, Any]:
    (leg,) = result["legs"]
    return leg


def _hops(result: dict[str, Any], stage: str) -> list[str]:
    return [hop["uid"] for hop in result["hops"] if hop["stage"] == stage]


def _rows(graph: TraceGraph, query: str) -> list[dict[str, Any]]:
    return [row for q, _params, rows in graph.reads if q == query for row in rows]


def _decided(leg: dict[str, Any]) -> None:
    assert not leg.get("indeterminate"), leg
    assert leg["device_uid"] == DEV


# --- the shapes ----------------------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_the_router_is_the_vyos_collectors_own_batch(version):
    batch = normalize_vyos(
        _generator().vyos_payload(), l3dom="osl01", l2fabric="osl01", scope=f"vyos:{DEV[4:]}"
    )
    estate = _estate(version)
    nodes = {(n.label, n.uid): n.props for n in estate.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid, tuple(sorted(r.key.items()))): r for r in estate.rels}

    assert batch.warnings == []
    for node in batch.nodes:
        assert nodes[node.label, node.uid] == {k: v for k, v in node.props.items() if v is not None}, node.uid
    for rel in batch.rels:
        held = rels[rel.rel_type, rel.start_uid, rel.end_uid, tuple(sorted(rel.key.items()))]
        assert (held.start_label, held.end_label) == (rel.start_label, rel.end_label)
        assert held.props == rel.props, (rel.rel_type, rel.start_uid, rel.end_uid)
    site = {key: props for key, props in nodes.items() if key[1].startswith(f"{NS}:")}
    assert {
        uid: props["af"] for (label, uid), props in site.items() if label in ("PbrPolicy", "NatRule")
    } == {
        PBR4: 4,
        PBR6: 6,
        MASQUERADE: 4,
        PORT_FORWARD: 4,
        NAT66: 6,
    }
    zoned = [
        props for (label, _uid), props in site.items() if label == "FwRulebase" and props["kind"] == "access"
    ]
    assert len(zoned) == 30 and sorted(props["af"] for props in zoned) == [4] * 15 + [6] * 15


@pytest.mark.parametrize("version", VERSIONS)
def test_the_site_holds_one_router_and_six_dual_stack_endpoints(version):
    estate = _estate(version)
    labels = {n.uid: n.label for n in estate.nodes}
    assert ("LOCATED_IN", DEV, "site:osl01") in {(r.rel_type, r.start_uid, r.end_uid) for r in estate.rels}
    assert [uid for uid, label in labels.items() if label == "Device" and uid.startswith("dev:osl01")] == [
        DEV
    ]
    names = {
        n.props["name"]: n.uid
        for n in estate.nodes
        if n.label == "Endpoint" and n.uid.startswith("ep:osl01:")
    }
    assert set(names) == set(ENDPOINTS)
    graph = TraceGraph(estate)
    for name, addresses in ENDPOINTS.items():
        for address in addresses:
            (row,) = trace_mod._source_candidates(graph, address)
            # owned by the endpoint, attached to the router's trunk, in the VLAN's bridge domain,
            # on a prefix a gateway interface of the router serves
            assert (row["ep_uid"], row["owned"], row["att_is_port"], row["sw_uid"]) == (
                names[name],
                True,
                True,
                DEV,
            )
            assert row["seg_uid"].startswith("bd:vlan:osl01:") and row["anchor"] == MAIN
            assert [gw["dev_uid"] for gw in trace_mod._containing(graph._gateways(4000), address)] == [DEV]


def test_an_endpoint_has_the_shape_the_unifi_collector_gives_a_wired_client():
    switch_mac, client_mac = "02:18:00:00:ff:01", "02:18:00:00:ff:02"
    raw = {
        "devices": [
            {
                "type": "usw",
                "mac": switch_mac,
                "serial": "OSLSW0001",
                "name": "osl01-sw",
                "model": "USW-24",
                "port_table": [{"port_idx": 1, "name": "Port 1", "up": True, "speed": 1000}],
            }
        ],
        "networks": [
            {"_id": "n10", "name": "LAN", "purpose": "corporate", "vlan": 10, "ip_subnet": "10.18.10.1/24"}
        ],
        "wlans": [],
        "clients": [
            {
                "mac": client_mac,
                "name": "client",
                "is_wired": True,
                "ip": "10.18.10.99",
                "network_id": "n10",
                "sw_mac": switch_mac,
                "sw_port": 1,
            }
        ],
    }
    unifi = normalize_unifi(raw, site_code="osl01", l3dom="osl01", unifi_site="default", l2fabric="osl01")

    def shape(batch: Batch, endpoint: str) -> dict[str, Any]:
        labels = {n.uid: n.label for n in batch.nodes}
        props = {n.uid: set(n.props) for n in batch.nodes}
        out = {(r.rel_type, labels[r.end_uid]) for r in batch.rels if r.start_uid == endpoint}
        addresses = [r.end_uid for r in batch.rels if r.start_uid == endpoint and r.rel_type == "HAS_IP"]
        address_out = {(r.rel_type, labels[r.end_uid]) for r in batch.rels if r.start_uid in addresses}
        return {
            "endpoint": props[endpoint],
            "out": out,
            "address": [props[a] for a in addresses],
            "address_out": address_out,
        }

    (client,) = [n.uid for n in unifi.nodes if n.label == "Endpoint"]
    expected = shape(unifi, client)
    estate = _estate(3)
    for endpoint in [n.uid for n in estate.nodes if n.label == "Endpoint" and n.uid.startswith("ep:osl01:")]:
        got = shape(estate, endpoint)
        assert got["endpoint"] == expected["endpoint"]
        assert (
            got["out"]
            == expected["out"]
            == {("IN", "BridgeDomain"), ("HAS_IP", "IpAddress"), ("ATTACHED", "Port")}
        )
        # one address per family here, one address on the UniFi client: the same properties
        assert len(got["address"]) == 2 and all(a == expected["address"][0] for a in got["address"])
        assert got["address_out"] == expected["address_out"] == {("IN", "Prefix")}


# --- 1 and 2: to the internet ----------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_1_an_ipv4_lan_host_reaches_the_internet_masqueraded(version):
    result, _graph = _trace(version, LAN_V4, INTERNET_V4, port=443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert not leg["blocked"] and leg["egress"] == "eth0" and leg["table"] == "default"
    assert leg["firewall"] == "LAN-WAN (LAN→WAN) accept by default-action"
    assert leg["snat"] == [{"sources": [f"{LAN_V4}/32"], "to": WAN_V4, "rule_uid": MASQUERADE}]
    assert _hops(result, "PBR_RULE") == []


@pytest.mark.parametrize("version", VERSIONS)
def test_2_an_ipv6_lan_host_reaches_the_internet_with_no_ipv4_nat_and_no_ipv4_policy_route(version):
    result, graph = _trace(version, LAN_V6, INTERNET_V6, port=443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert not leg["blocked"] and leg["egress"] == "eth0" and leg["table"] == "default"
    assert leg["firewall"] == "LAN-WAN-6 (LAN→WAN) accept by default-action"
    assert leg.get("snat") is None and _hops(result, "SNAT") == [] and _hops(result, "PBR_RULE") == []
    # the masquerade has no address match and leaves by this flow's egress, and the IPv4
    # policy route is bound to its ingress: only their family keeps them off this flow
    (masquerade,) = [r for r in _rows(graph, nat_mod._NAT_RULES_QUERY) if r["uid"] == MASQUERADE]
    assert (masquerade["af"], masquerade["out_if"], masquerade["orig_src_raw"]) == (4, "eth0", None)
    policies = {r["pol_uid"]: r["pol_af"] for r in _rows(graph, pbr_mod._INTERFACE_POLICY_RULES)}
    assert policies == {PBR4: 4, PBR6: 6}


@pytest.mark.parametrize(("src", "dst"), [(LAN_V4, INTERNET_V4), (LAN_V6, INTERNET_V6)])
def test_1_2_the_reply_from_the_internet_is_admitted_from_session_state(src, dst):
    result, _graph = _trace(3, src, dst, port=443, proto="tcp", reply=True)
    reply = result["reply"]
    assert not reply["verdict"].startswith("reply not derived"), reply["verdict"]
    leg = _one(reply)
    assert leg["firewall"].startswith("admitted from session state")
    assert not leg["blocked"] and not leg["indeterminate"]


# --- 3: between zones, by the IPv6 rule set ------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_3_an_ipv6_lan_to_iot_flow_is_permitted_by_the_ipv6_rule_set(version):
    result, graph = _trace(version, LAN_V6, IOT_V6, port=8443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert not leg["blocked"] and leg["egress"] == "eth1.20"
    assert leg["firewall"] == "LAN-IOT-6 (LAN→IOT) accept by rule 10"
    assert _hops(result, "FILTER_RULE") == [f"{NS}:fw:ipv6:LAN-IOT-6:10"]
    # both rule sets of the pair were read; the IPv4 one denies this port (below)
    pair = {r["rb_uid"]: r["af"] for r in _rows(graph, ZONE_PAIR)}
    assert pair == {f"{NS}:fw:LAN-IOT": 4, f"{NS}:fw:ipv6:LAN-IOT-6": 6}

    ipv4, _ = _trace(version, LAN_V4, IOT_V4, port=8443, proto="tcp")
    assert _one(ipv4)["blocked"] and _one(ipv4)["firewall"] == "LAN-IOT (LAN→IOT) drop by default-action"


@pytest.mark.parametrize("version", VERSIONS)
def test_3_an_ipv6_iot_to_lan_flow_is_dropped_by_the_ipv6_rule_set(version):
    result, graph = _trace(version, IOT_V6, NAS_V6, port=1883, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert leg["blocked"] and leg["egress"] == "eth1.10"
    assert leg["firewall"] == "IOT-LAN-6 (IOT→LAN) drop by default-action"
    pair = {r["rb_uid"]: r["af"] for r in _rows(graph, ZONE_PAIR)}
    assert pair == {f"{NS}:fw:IOT-LAN": 4, f"{NS}:fw:ipv6:IOT-LAN-6": 6}

    ipv4, _ = _trace(version, IOT_V4, NAS_V4, port=1883, proto="tcp")
    assert not _one(ipv4)["blocked"] and _one(ipv4)["firewall"] == "IOT-LAN (IOT→LAN) accept by rule 10"


# --- 4: policy routes of one family --------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_4_policy_route_sends_its_ipv4_group_into_the_wireguard_table(version):
    result, _graph = _trace(version, VPN_V4, INTERNET_V4, port=443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert not leg["blocked"] and _hops(result, "PBR_RULE") == [f"{PBR4}:10"]
    assert (leg["table"], leg["egress"]) == ("table100", "wg0")
    assert _hops(result, "VRF") == [TABLE_100]
    _carrier_accepted(result)


def _carrier_accepted(result: dict[str, Any]) -> None:
    carrier = _one(result)["carrier"]
    assert (carrier["endpoint"], carrier["port"], carrier["proto"], carrier["egress"]) == (
        "198.51.100.180",
        51820,
        "udp",
        "eth0",
    )
    assert carrier["firewall"].startswith("LOCAL-WAN (output) accept by rule")
    assert not carrier["verdict"].startswith("BLOCKED")
    assert [h["uid"] for h in result["hops"] if h["stage"] == "CARRIER_FILTER"] == [LOCAL_WAN]


@pytest.mark.parametrize("version", VERSIONS)
def test_4_the_partner_tunnels_carrier_is_blocked_by_local_wan(version):
    """The forward leg is permitted (LAN-WAN), but LOCAL-WAN has no rule for the carrier of
    wg1 (udp 51821 to 198.51.100.190) and drops it by default: the flow does not leave."""
    result, _graph = _trace(version, LAN_V4, PARTNER_V4, port=443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert (leg["table"], leg["egress"]) == ("default", "wg1") and _hops(result, "PBR_RULE") == []
    assert leg["firewall"] == "LAN-WAN (LAN→WAN) accept by default-action"
    carrier = leg["carrier"]
    assert (carrier["endpoint"], carrier["port"], carrier["proto"]) == ("198.51.100.190", 51821, "udp")
    assert carrier["firewall"] == "LOCAL-WAN (output) drop by default-action"
    assert leg["blocked"] and carrier["verdict"] == "BLOCKED by LOCAL-WAN default-action"


def test_4_the_carrier_names_the_rule_that_accepts_it():
    result, _graph = _trace(3, VPN_V4, INTERNET_V4, port=443, proto="tcp")
    assert _one(result)["carrier"]["firewall"] == "LOCAL-WAN (output) accept by rule 10"


@pytest.mark.parametrize("version", VERSIONS)
def test_4_the_ipv4_policy_route_claims_no_ipv6_host_of_the_lan(version):
    result, graph = _trace(version, LAN_V6, INTERNET_V6, port=443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert _hops(result, "PBR_RULE") == [] and leg["table"] == "default" and leg["egress"] == "eth0"
    assert {r["pol_uid"] for r in _rows(graph, pbr_mod._INTERFACE_POLICY_RULES)} == {PBR4, PBR6}


@pytest.mark.parametrize("version", VERSIONS)
def test_4_policy_route6_sends_its_ipv6_group_into_the_wireguard_table(version):
    result, _graph = _trace(version, VPN_V6, INTERNET_V6, port=443, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert not leg["blocked"] and _hops(result, "PBR_RULE") == [f"{PBR6}:10"]
    assert (leg["table"], leg["egress"]) == ("table100", "wg0")
    # the tunnel's carrier is IPv4: the IPv4 rule set LOCAL-WAN decides it
    _carrier_accepted(result)
    # nat66 masquerades the LAN on the tunnel; the IPv4 masquerade leaves by eth0
    assert leg["snat"] == [{"sources": [f"{VPN_V6}/128"], "to": "fd00:18:250::2", "rule_uid": NAT66}]


@pytest.mark.parametrize("version", VERSIONS)
def test_4_policy_route6_claims_no_ipv4_host(version):
    # the IPv4 host of the LAN is claimed by no policy, the IPv4 VPN host by the IPv4 one only
    for source, claimed, table in ((LAN_V4, [], "default"), (VPN_V4, [f"{PBR4}:10"], "table100")):
        result, graph = _trace(version, source, INTERNET_V4, port=443, proto="tcp")
        assert _hops(result, "PBR_RULE") == claimed and _one(result)["table"] == table
        assert {r["pol_uid"]: r["pol_af"] for r in _rows(graph, pbr_mod._INTERFACE_POLICY_RULES)} == {
            PBR4: 4,
            PBR6: 6,
        }


# --- 5: the IPv4 port forward ------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_5_the_ipv4_port_forward_sends_wan_443_to_the_nas(version):
    result, _graph = _trace(version, INTERNET_V4, WAN_V4, port=443, proto="tcp", start_table=MAIN)
    leg = _one(result)

    _decided(leg)
    assert _hops(result, "DNAT") == [PORT_FORWARD]
    assert leg["dnat"][0]["to"] == [f"{NAS_V4}/32"] and leg["dnat"][0]["rule_uid"] == PORT_FORWARD
    assert not leg["blocked"] and leg["egress"] == "eth1.10"
    assert leg["firewall"] == "WAN-LAN (WAN→LAN) accept by rule 10"
    nas = [
        n.uid
        for n in _estate(version).nodes
        if n.label == "Endpoint" and n.props.get("name") == "osl01-nas-01"
    ]
    assert _hops(result, "DST_ENDPOINT") == nas


@pytest.mark.parametrize("version", VERSIONS)
def test_5_the_ipv4_port_forward_claims_no_ipv6_flow_to_the_same_port(version):
    result, graph = _trace(version, INTERNET_V6, NAS_V6, port=443, proto="tcp", start_table=MAIN)
    leg = _one(result)

    _decided(leg)
    assert _hops(result, "DNAT") == [] and leg.get("dnat") is None
    assert leg["blocked"] and leg["firewall"] == "WAN-LAN-6 (WAN→LAN) drop by default-action"
    # the rule matches any destination on eth0 port 443: only its family keeps it off
    (forward,) = [r for r in _rows(graph, nat_mod._NAT_RULES_QUERY) if r["uid"] == PORT_FORWARD]
    assert (forward["af"], forward["in_if"], forward["orig_dst_port"], forward["orig_dst_raw"]) == (
        4,
        "eth0",
        "443",
        None,
    )


# --- 6: a port range, both directions ------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_6_a_port_range_and_its_reply_are_decided(version):
    result, _graph = _trace(version, LAN_V6, IOT_V6, port="8443-8445", proto="tcp", reply=True)
    forward, reply = _one(result["forward"]), _one(result["reply"])

    _decided(forward)
    assert not forward["blocked"] and forward["firewall"] == "LAN-IOT-6 (LAN→IOT) accept by rule 10"
    assert not forward["firewall"].endswith("(matches part of the range only)")
    # IOT-LAN-6 drops every new flow, so only the session state admits the reply
    _decided(reply)
    assert not reply["blocked"] and reply["egress"] == "eth1.10"
    assert (
        reply["firewall"] == "admitted from session state (established=accept, invalid=drop, related=accept)"
    )
    rulebase = {n.uid: n.props for n in _estate(version).nodes}[f"{NS}:fw:ipv6:IOT-LAN-6"]
    assert rulebase["default_action"] == "drop"


# --- 7: a flow to the router's own address -------------------------------------------------------
# Decided by the rule set from the ingress zone to LOCAL, of the flow's family: LAN-LOCAL
# (default accept, rule 10 accepts tcp/22), IOT-LOCAL (default drop, rules 20 and 21 accept
# DNS over udp and tcp), GUEST-LOCAL (default drop, DHCP and DNS only).

ROUTER_LOCAL = [
    # (src, dst, port, proto, ingress, firewall, blocked)
    (LAN_V4, RTR_IOT_V4, 22, "tcp", "eth1.20", "LAN-LOCAL (input) accept by rule 10", False),
    (IOT_V4, RTR_LAN_V4, 53, "udp", "eth1.10", "IOT-LOCAL (input) accept by rule 20", False),
    (IOT_V4, RTR_LAN_V4, 22, "tcp", "eth1.10", "IOT-LOCAL (input) drop by default-action", True),
    (LAN_V6, RTR_IOT_V6, 22, "tcp", "eth1.20", "LAN-LOCAL-6 (input) accept by rule 10", False),
    (IOT_V6, RTR_LAN_V6, 53, "udp", "eth1.10", "IOT-LOCAL-6 (input) accept by rule 20", False),
    (IOT_V6, RTR_LAN_V6, 22, "tcp", "eth1.10", "IOT-LOCAL-6 (input) drop by default-action", True),
    # the guest's own gateway and the router's LAN address: GUEST-LOCAL either way
    (GUEST_V4, RTR_GUEST_V4, 443, "tcp", "eth1.30", "GUEST-LOCAL (input) drop by default-action", True),
    (GUEST_V4, RTR_LAN_V4, 443, "tcp", "eth1.10", "GUEST-LOCAL (input) drop by default-action", True),
]


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(("src", "dst", "port", "proto", "owner", "firewall", "blocked"), ROUTER_LOCAL)
def test_7_a_flow_to_the_router_is_decided_by_its_zone_to_local_rule_set(
    version, src, dst, port, proto, owner, firewall, blocked
):
    result, _graph = _trace(version, src, dst, port=port, proto=proto, reply=not blocked)
    forward = result if blocked else result["forward"]
    leg = _one(forward)

    _decided(leg)
    assert leg["firewall"] == firewall and leg["blocked"] is blocked
    if blocked:
        assert leg["verdict"] == f"BLOCKED by {firewall.split(' ')[0]} default-action"
        return
    assert leg["verdict"] == f"router-local, terminates on osl01-vyos-01 {owner}"
    assert forward["warnings"] == []
    # the rule set back from LOCAL is not asked: the global state policy admits the reply
    reply = result["reply"]
    assert not reply["indeterminate"] and reply["warnings"] == []
    reply_leg = _one(reply)
    _decided(reply_leg)
    assert reply_leg["firewall"] == ADMITTED and not reply_leg["blocked"]


@pytest.mark.parametrize("version", VERSIONS)
def test_7_the_gateway_in_the_sources_own_subnet_is_router_local_not_switched(version):
    result, _graph = _trace(version, LAN_V4, RTR_LAN_V4, port=22, proto="tcp")
    leg = _one(result)

    _decided(leg)
    assert leg["verdict"] == "router-local, terminates on osl01-vyos-01 eth1.10"
    assert leg["firewall"] == "LAN-LOCAL (input) accept by rule 10" and not leg["blocked"]
    assert result["warnings"] == []


def test_7_the_reply_from_the_gateway_in_the_sources_own_subnet_is_admitted():
    result, _graph = _trace(3, LAN_V4, RTR_LAN_V4, port=22, proto="tcp", reply=True)
    reply = result["reply"]
    assert not reply["indeterminate"], reply["verdict"]
    assert _one(reply)["firewall"] == ADMITTED


@pytest.mark.parametrize("version", VERSIONS)
def test_7_a_host_to_another_host_of_its_own_subnet_is_switched(version):
    result, _graph = _trace(version, LAN_V4, NAS_V4, port=445, proto="tcp")
    leg = _one(result)

    assert leg["verdict"] == "switched in 10.18.10.0/24"
    assert not leg.get("router_local") and leg.get("firewall") is None and not leg["blocked"]
    # Both hosts attach to the router's port eth1.
    assert not result["indeterminate"] and not leg["indeterminate"]
    assert result["warnings"] == []


def test_7_hosts_of_one_subnet_on_two_ports_of_the_router_keep_its_rule_sets_on_path():
    """On two ports of the router the frame crosses the router (a bridge); the collector
    records the bridge's VLAN membership and no `firewall bridge` rule set, so the router's
    rule sets stay on the path and the flow is not decided."""
    estate = _estate(3)
    nas_ep = next(
        r.start_uid for r in estate.rels if r.rel_type == "ATTACHED" and r.start_uid.endswith("0a02")
    )
    rels = [
        r.model_copy(update={"end_uid": f"{DEV}/port/eth0"})
        if r.rel_type == "ATTACHED" and r.start_uid == nas_ep
        else r
        for r in estate.rels
    ]
    graph = TraceGraph(estate.model_copy(update={"rels": rels}))
    result = path.trace(graph, LAN_V4, NAS_V4, port=445, proto="tcp")
    assert graph.refused == []

    leg = _one(result)
    assert leg["verdict"] == "switched in 10.18.10.0/24"
    assert result["indeterminate"] and leg["indeterminate"]
    assert any("on path, not evaluated" in w for w in result["warnings"])


def test_7_hosts_of_one_subnet_in_two_vlans_on_one_router_port_keep_its_rule_sets_on_path():
    """One trunk port, two VLANs (bridge domains): the frame between them crosses the router's
    bridge, so its rule sets stay on the path and the flow is not decided."""
    estate = _estate(3)
    nas_ep = next(
        r.start_uid for r in estate.rels if r.rel_type == "HAS_IP" and r.end_uid.endswith(f":{NAS_V4}")
    )
    rels = [
        r.model_copy(update={"end_uid": "bd:vlan:osl01:20"})
        if r.rel_type == "IN" and r.start_uid == nas_ep and r.end_uid.startswith("bd:vlan:osl01:")
        else r
        for r in estate.rels
    ]
    graph = TraceGraph(estate.model_copy(update={"rels": rels}))
    result = path.trace(graph, LAN_V4, NAS_V4, port=445, proto="tcp")
    assert graph.refused == []

    leg = _one(result)
    assert leg["verdict"] == "switched in 10.18.10.0/24"
    assert result["indeterminate"] and leg["indeterminate"]
    assert any("on path, not evaluated" in w for w in result["warnings"])


# --- 8: the routing tables mirrored from the RIB -------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_8_the_main_table_and_table_100_are_mirrored_from_the_rib(version):
    """The payload records an `ok` outcome for each RIB read, so the collector writes
    `rib_mirrored: true` on both tables; every configured static FRR installed is confirmed,
    and the one it did not install (next hop 10.18.99.1 in no connected network) is not."""
    nodes = {n.uid: n.props for n in _estate(version).nodes}
    assert (nodes[MAIN]["rib_mirrored"], nodes[TABLE_100]["rib_mirrored"]) == (True, True)
    statics = sorted(
        (r.start_uid, nodes[r.end_uid]["cidr"], bool(r.props.get("rib_confirmed")))
        for r in _estate(version).rels
        if r.rel_type == "STATIC_ROUTE" and r.start_uid in (MAIN, TABLE_100)
    )
    assert statics == [
        (MAIN, "0.0.0.0/0", True),
        (MAIN, "172.20.0.0/16", True),
        (MAIN, "192.0.2.0/25", False),
        (MAIN, "::/0", True),
        (TABLE_100, "0.0.0.0/0", True),
        (TABLE_100, "::/0", True),
    ]


def test_8_a_static_the_mirrored_rib_does_not_hold_is_not_confirmed():
    result, _graph = _trace(3, LAN_V4, UNINSTALLED_V4, port=443, proto="tcp")
    leg = _one(result)

    assert leg["indeterminate"] and leg["device_uid"] == DEV
    warnings = [w for w in result["warnings"] if "192.0.2.0/25 is a config-only static route" in w]
    assert len(warnings) == 1, result["warnings"]
    assert "does not hold" in warnings[0]
    assert "selects 0.0.0.0/0 via 203.0.113.201" in warnings[0]
