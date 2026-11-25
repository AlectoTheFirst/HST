"""VyOS collector cases: static route options, WireGuard tunnel identity, bonds
and bridges, the neighbor table, the RIB read, the OSPF area id and the dynamic
peers of a BGP listen range."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from hst.collectors import vyos
from hst.collectors.vyos import (
    BGP_SUMMARY_COMMAND,
    VyosCollector,
    bgp_capture_targets,
    neighbor_rows,
    normalize_vyos,
)
from hst.core import uid
from hst.core.l3domain import DEFAULT_VRF

VERSION = "Version:          VyOS 1.4.0\nHardware S/N:     R1\n"


def _batch(cfg: dict[str, Any], **raw: Any):
    cfg = {"system": {"host-name": "r1"}, **cfg}
    return normalize_vyos({"config": cfg, "version_text": VERSION, "links": [], **raw}, l3dom="lab")


def _device(batch) -> str:
    return next(n.uid for n in batch.nodes if n.label == "Device")


def _rels(batch, rel_type: str) -> list:
    return [r for r in batch.rels if r.rel_type == rel_type]


def _nodes(batch, label: str) -> dict[str, dict[str, Any]]:
    return {n.uid: n.props for n in batch.nodes if n.label == label}


# --- static route options ------------------------------------------------------------------


def _static(route: dict[str, Any]):
    return _batch(
        {
            "interfaces": {"ethernet": {"eth0": {"address": ["dhcp"]}, "eth1": {"address": ["fd00::1/64"]}}},
            "protocols": {"static": {"route6": {"2001:db8::/32": route}}},
        }
    )


def test_a_next_hops_own_interface_is_its_egress():
    batch = _static({"next-hop": {"fe80::2": {"interface": "eth1"}}})
    dev = _device(batch)
    [route] = [r for r in _rels(batch, "STATIC_ROUTE") if r.props.get("next_hop") == "fe80::2"]
    assert route.props["rib_interface"] == "eth1"
    assert {r.end_uid for r in _rels(batch, "VIA") if r.start_uid == route.end_uid} == {
        uid.interface(dev, "eth1")
    }


def test_a_dhcp_interface_route_is_an_interface_route_through_the_lease():
    batch = _batch(
        {
            "interfaces": {"ethernet": {"eth0": {"address": ["dhcp"]}}},
            "protocols": {"static": {"route": {"198.51.100.0/24": {"dhcp-interface": "eth0"}}}},
        }
    )
    dev = _device(batch)
    [route] = [r for r in _rels(batch, "STATIC_ROUTE") if r.end_uid.endswith("198.51.100.0/24")]
    assert route.key == {"interface": "eth0"}
    assert route.props["via_dhcp"] is True
    assert route.props["distance"] == 1
    assert {r.end_uid for r in _rels(batch, "VIA") if r.start_uid == route.end_uid} == {
        uid.interface(dev, "eth0")
    }


def test_a_route_without_dhcp_interface_states_no_lease():
    batch = _static({"next-hop": {"2001:db8:ffff::1": {}}})
    [route] = _rels(batch, "STATIC_ROUTE")
    assert "via_dhcp" not in route.props
    assert "rib_interface" not in route.props


# --- WireGuard tunnel identity -------------------------------------------------------------


def test_peers_of_one_name_on_two_interfaces_are_two_tunnels():
    peer = {"allowed-ips": ["10.1.0.0/16"], "port": "51820"}
    batch = _batch(
        {
            "interfaces": {
                "wireguard": {
                    "wg0": {
                        "source-address": "192.0.2.1",
                        "peer": {"hq": {**peer, "address": "198.51.100.1"}},
                    },
                    "wg1": {
                        "source-address": "192.0.2.1",
                        "peer": {
                            "hq": {**peer, "address": "203.0.113.1"},
                            "HQ": {**peer, "address": "203.0.113.2"},
                        },
                    },
                }
            }
        }
    )
    dev = _device(batch)
    tunnels = _nodes(batch, "Tunnel")
    assert {u: p["endpoint"] for u, p in tunnels.items()} == {
        f"tun:wireguard:{dev}~wg0~hq": "198.51.100.1",
        f"tun:wireguard:{dev}~wg1~hq": "203.0.113.1",
        f"tun:wireguard:{dev}~wg1~{uid.exact_slug('HQ')}": "203.0.113.2",
    }
    ends = {(r.start_uid, r.end_uid) for r in _rels(batch, "ENDPOINT") if r.start_uid in tunnels}
    assert (f"tun:wireguard:{dev}~wg0~hq", uid.interface(dev, "wg0")) in ends
    assert (f"tun:wireguard:{dev}~wg0~hq", uid.interface(dev, "wg1")) not in ends


# --- bonds and bridges ----------------------------------------------------------------------

BOND_CFG = {
    "interfaces": {
        "ethernet": {"eth1": {}, "eth2": {}, "eth3": {}},
        "bonding": {
            "bond0": {"mode": "802.3ad", "member": {"interface": ["eth1", "eth2"]}, "vif": {"10": {}}},
        },
        "bridge": {
            "br0": {
                "member": {"interface": {"eth3": {"native-vlan": "20", "allowed-vlan": ["30-40"]}}},
                "vif": {"35": {}, "50": {}},
            }
        },
    }
}
LINKS = [
    {"ifname": "eth1", "address": "02:00:00:00:00:b0", "permaddr": "52:54:00:00:00:01"},
    {"ifname": "eth2", "address": "02:00:00:00:00:b0", "permaddr": "52:54:00:00:00:02"},
    {"ifname": "bond0", "address": "02:00:00:00:00:b0"},
]


def test_a_bond_is_a_lag_of_its_member_ports():
    batch = _batch(BOND_CFG, links=LINKS)
    dev = _device(batch)
    lag = uid.lag(dev, "bond0")
    assert _nodes(batch, "Lag") == {lag: {"name": "bond0", "mode": "802.3ad"}}
    members = {(r.start_uid, r.props["state"]) for r in _rels(batch, "MEMBER_OF") if r.end_uid == lag}
    assert members == {(uid.port(dev, "eth1"), "configured"), (uid.port(dev, "eth2"), "configured")}
    realized = {r.start_uid for r in _rels(batch, "REALIZED_BY") if r.end_uid == lag}
    assert realized == {uid.interface(dev, "bond0"), uid.interface(dev, "bond0.10")}
    vlan10 = uid.vlan(dev, 10)
    carriers = {r.start_uid for r in _rels(batch, "CARRIES") if r.end_uid == vlan10}
    assert carriers == {uid.port(dev, "eth1"), uid.port(dev, "eth2")}


def test_a_bond_member_keeps_its_own_mac_and_the_bond_the_shared_one():
    batch = _batch(BOND_CFG, links=LINKS)
    dev = _device(batch)
    ports = _nodes(batch, "Port")
    interfaces = _nodes(batch, "Interface")
    assert ports[uid.port(dev, "eth1")]["mac"] == "525400000001"
    assert ports[uid.port(dev, "eth2")]["mac"] == "525400000002"
    assert interfaces[uid.interface(dev, "eth1")]["mac"] == "525400000001"
    assert interfaces[uid.interface(dev, "bond0")]["mac"] == "0200000000b0"


def test_a_bridge_member_carries_its_native_vlan_and_the_allowed_vlans_the_bridge_has():
    batch = _batch(BOND_CFG, links=LINKS)
    dev = _device(batch)
    eth3 = uid.port(dev, "eth3")
    carried = {r.end_uid: r.props["native"] for r in _rels(batch, "CARRIES") if r.start_uid == eth3}
    # 50 is outside the allowed range and 30 to 40 other than 35 has no vif
    assert carried == {uid.vlan(dev, 20): True, uid.vlan(dev, 35): False}
    realizes = {(r.start_uid, r.end_uid) for r in _rels(batch, "REALIZES")}
    assert (uid.vlan(dev, 20), uid.bridge_domain("fab0", 20)) in realizes


def test_a_bond_that_is_a_bridge_member_carries_on_its_member_ports():
    cfg = json.loads(json.dumps(BOND_CFG))
    cfg["interfaces"]["bridge"]["br0"]["member"]["interface"] = {"bond0": {"native-vlan": "20"}}
    batch = _batch(cfg, links=LINKS)
    dev = _device(batch)
    vlan20 = uid.vlan(dev, 20)
    carriers = {r.start_uid for r in _rels(batch, "CARRIES") if r.end_uid == vlan20}
    assert carriers == {uid.port(dev, "eth1"), uid.port(dev, "eth2")}


# --- the neighbor table ---------------------------------------------------------------------

NEIGH_CFG = {"interfaces": {"ethernet": {"eth1": {"vrf": "RED", "vif": {"10": {"vrf": "BLUE"}}}, "eth2": {}}}}


def test_the_neighbor_table_is_arp_rows_of_the_resolved_entries():
    raw = {
        "config": NEIGH_CFG,
        "neigh": [
            {"dst": "10.0.0.2", "dev": "eth1", "lladdr": "52:54:00:aa:bb:cc", "state": ["REACHABLE"]},
            {"dst": "10.0.10.2", "dev": "eth1.10", "lladdr": "52:54:00:aa:bb:cd", "state": ["STALE"]},
            {"dst": "2001:db8::2", "dev": "eth2", "lladdr": "52:54:00:aa:bb:ce", "state": ["DELAY"]},
            {"dst": "10.0.0.3", "dev": "eth1", "state": ["FAILED"]},
            {"dst": "10.0.0.4", "dev": "eth1", "lladdr": "52:54:00:aa:bb:cf", "state": ["INCOMPLETE"]},
            {"dst": "10.0.0.5", "dev": "eth1", "state": ["NOARP"]},
            {"dst": "not an address", "dev": "eth1", "lladdr": "52:54:00:aa:bb:d0"},
        ],
    }
    rows = neighbor_rows(raw, "dev:r1")
    assert rows == [
        {
            "device_uid": "dev:r1",
            "vrf": "RED",
            "context_uid": "vrf:dev:r1:red",
            "ip": "10.0.0.2",
            "mac": "525400aabbcc",
            "interface_name": "eth1",
            "af": 4,
        },
        {
            "device_uid": "dev:r1",
            "vrf": "BLUE",
            "context_uid": "vrf:dev:r1:blue",
            "ip": "10.0.10.2",
            "mac": "525400aabbcd",
            "interface_name": "eth1.10",
            "af": 4,
        },
        {
            "device_uid": "dev:r1",
            "vrf": DEFAULT_VRF,
            "context_uid": f"vrf:dev:r1:{DEFAULT_VRF}",
            "ip": "2001:db8::2",
            "mac": "525400aabbce",
            "interface_name": "eth2",
            "af": 6,
        },
    ]
    assert neighbor_rows({"config": NEIGH_CFG, "neigh": []}, "dev:r1") == []


def test_the_neighbor_table_is_an_observation_that_does_not_change_the_configuration_hash():
    assert "arp" in VyosCollector.SIDE_TABLES
    assert VyosCollector.TABLE_SECTIONS["arp"] == ("neigh",)
    assert "neigh" in VyosCollector.VOLATILE_RAW_KEYS
    assert "neigh" in VyosCollector.OBSERVATION_RAW_KEYS
    assert "neigh" in vyos.READ_COMMANDS


def test_a_payload_without_the_neighbor_read_states_arp_not_captured():
    raw = {"config": {"system": {"host-name": "r1"}}, "version_text": VERSION}
    sections = vyos.section_outcomes(raw)
    assert "neigh" not in sections
    sections = vyos.section_outcomes({**raw, "neigh": []})
    assert sections["neigh"].status == "unknown"
    sections = vyos.section_outcomes({**raw, "neigh": [], "_strata_outcomes": {"neigh": {"status": "ok"}}})
    assert sections["neigh"].status == "empty"


# --- the RIB read ---------------------------------------------------------------------------


def _route(prefix: str, ifname: str, table: str = "main") -> dict[str, Any]:
    return {
        "prefix": prefix,
        "protocol": "static",
        "selected": True,
        "installed": True,
        "table": table,
        "nexthops": [{"fib": True, "ip": "192.0.2.254", "interfaceName": ifname}],
    }


VRF_ALL = {
    "default": {
        "0.0.0.0/0": [_route("0.0.0.0/0", "eth0")],
        "198.51.100.0/24": [_route("198.51.100.0/24", "eth1")],
        "198.51.100.128/25": [_route("198.51.100.128/25", "eth2")],
    },
    "RED": {"10.0.0.0/8": [_route("10.0.0.0/8", "eth3", table="100")]},
    "odd": [],
}


def test_the_rib_is_read_one_prefix_at_a_time_as_the_whole_tree_reads():
    text = json.dumps(VRF_ALL, indent=2)
    rows, count, failure = vyos._rib_rows(text, 4, True, {})
    assert failure is None
    tree = [(p, r) for listing in VRF_ALL.values() if isinstance(listing, dict) for p, r in listing.items()]
    assert rows == list(vyos._rib_entries(tree, 4, {}))
    assert count == vyos._route_prefix_count(VRF_ALL) == 4
    table = json.dumps(VRF_ALL["default"])
    rows, count, failure = vyos._rib_rows(table, 4, False, {})
    assert failure is None
    assert len(rows) == 3
    assert count == vyos._route_prefix_count(VRF_ALL["default"])


def test_a_rib_answer_that_breaks_off_reads_as_json_loads_states_it():
    text = json.dumps(VRF_ALL)
    rows, count, failure = vyos._rib_rows(text[: len(text) // 2], 4, True, {})
    assert (rows, count) == ([], 0)
    assert failure is not None and failure.status == "malformed"
    for bad in ('{"default": {}} trailing', '{"default" {}}', "[1, 2]", "% Unknown command"):
        expected = vyos._rib_answer(bad)[1]
        assert vyos._rib_rows(bad, 4, True, {})[2] == expected, bad


def test_the_wireguard_carrier_takes_the_longest_prefix_of_the_main_table():
    rows, _count, _failure = vyos._rib_rows(json.dumps(VRF_ALL), 4, True, {})
    rib = vyos._RibRead(rows, {}, {}, {}, {})
    egress = vyos._carrier_egress_interface
    assert egress(rib, ipaddress.ip_address("198.51.100.200")) == "eth2"
    assert egress(rib, ipaddress.ip_address("198.51.100.20")) == "eth1"
    assert egress(rib, ipaddress.ip_address("203.0.113.9")) == "eth0"
    # the policy table's route is not the main table's
    assert egress(rib, ipaddress.ip_address("10.1.2.3")) == "eth0"
    assert egress(rib, ipaddress.ip_address("2001:db8::1")) is None


# --- the OSPF area id -----------------------------------------------------------------------


def test_the_area_type_frr_prints_is_not_part_of_the_area_id():
    payload = {
        "interfaces": {
            "eth1": {"area": "0.0.0.1 [Stub]", "cost": 10},
            "eth2": {"area": "0.0.0.2 [NSSA]"},
            "eth3": {"area": "0.0.0.3"},
            "eth4": {},
        }
    }
    areas = {row["name"]: row["area"] for row in vyos._ospf_interfaces_of(payload, DEFAULT_VRF)}
    assert areas == {"eth1": "0.0.0.1", "eth2": "0.0.0.2", "eth3": "0.0.0.3"}


# --- the dynamic peers of a listen range -----------------------------------------------------

LISTEN_CFG = {
    "interfaces": {"ethernet": {"eth1": {"address": ["192.168.2.1/24"]}}},
    "protocols": {
        "bgp": {
            "system-as": "64512",
            "listen": {
                "range": {"192.168.2.0/24": {"peer-group": "K8S"}, "192.168.0.0/16": {"peer-group": "WIDE"}}
            },
            "peer-group": {
                "K8S": {
                    "remote-as": "64513",
                    "address-family": {"ipv4-unicast": {"route-map": {"import": "K8S-IN"}}},
                },
                "WIDE": {"remote-as": "64514"},
            },
            "neighbor": {"192.168.2.40": {"remote-as": "64600"}},
        }
    },
    "policy": {"route-map": {"K8S-IN": {"rule": {"10": {"action": "permit"}}}}},
}


def _summary(*peers: str) -> str:
    return json.dumps(
        {
            "default": {
                "ipv4Unicast": {
                    "peers": {
                        peer: {"remoteAs": 64513, "state": "Established", "dynamicPeer": True, "pfxRcd": 1}
                        for peer in peers
                    }
                }
            }
        }
    )


def test_an_observed_peer_of_one_listen_range_is_a_session_of_its_peer_group():
    cfg = json.loads(json.dumps(LISTEN_CFG))
    del cfg["protocols"]["bgp"]["listen"]["range"]["192.168.0.0/16"]
    batch = _batch(cfg, **{BGP_SUMMARY_COMMAND: _summary("192.168.2.30", "192.168.2.40", "10.9.9.9")})
    dev = _device(batch)
    process = uid.routing_process(dev, DEFAULT_VRF, "bgp")
    sessions = _nodes(batch, "BgpSession")
    dynamic = uid.bgp_session(process, "192.168.2.30", DEFAULT_VRF)
    assert set(sessions) == {dynamic, uid.bgp_session(process, "192.168.2.40", DEFAULT_VRF)}
    props = sessions[dynamic]
    assert props["peer_asn"] == 64513
    assert props["peer_group"] == "K8S"
    assert props["dynamic_range"] == "192.168.2.0/24"
    assert props["import_policy_name"] == "K8S-IN"
    assert "dynamic_range" not in sessions[uid.bgp_session(process, "192.168.2.40", DEFAULT_VRF)]
    peer_range = uid.bgp_peer_range(process, "192.168.2.0/24", DEFAULT_VRF)
    assert _nodes(batch, "BgpPeerRange") == {
        peer_range: {"prefix": "192.168.2.0/24", "local_asn": 64512, "peer_group": "K8S"}
    }
    assert {(r.start_uid, r.end_uid) for r in _rels(batch, "MEMBER_OF") if r.end_uid == peer_range} == {
        (dynamic, peer_range)
    }
    assert (process, peer_range) in {(r.start_uid, r.end_uid) for r in _rels(batch, "HAS")}


def test_a_peer_two_listen_ranges_hold_is_no_session():
    batch = _batch(LISTEN_CFG, **{BGP_SUMMARY_COMMAND: _summary("192.168.2.30", "192.168.9.9")})
    peers = {p["peer_ip"] for p in _nodes(batch, "BgpSession").values()}
    assert peers == {"192.168.2.40", "192.168.9.9"}


def test_the_dynamic_peers_are_capture_targets_once_the_summary_lists_them():
    peers = vyos.summary_peers(_summary("192.168.9.9"))
    observed = {key: asn for key, asn in peers.items() if asn is not None}
    assert set(bgp_capture_targets(LISTEN_CFG)) == {(DEFAULT_VRF, "192.168.2.40")}
    assert set(bgp_capture_targets(LISTEN_CFG, observed, peers)) == {
        (DEFAULT_VRF, "192.168.2.40"),
        (DEFAULT_VRF, "192.168.9.9"),
    }


def test_summary_peers_lists_a_peer_with_no_asn_yet():
    text = json.dumps(
        {
            "default": {
                "ipv4Unicast": {
                    "peers": {"192.168.2.30": {"remoteAs": 0}, "192.168.2.31": {"remoteAs": 64513}}
                },
                "ipv6Unicast": {"peers": {"192.168.2.30": {"remoteAs": 64513}}},
            }
        }
    )
    assert vyos.summary_peers(text) == {
        (DEFAULT_VRF, "192.168.2.30"): 64513,
        (DEFAULT_VRF, "192.168.2.31"): 64513,
    }
    assert vyos.summary_peers(json.dumps({"default": {"ipv4Unicast": {"peers": {"10.0.0.1": {}}}}})) == {
        (DEFAULT_VRF, "10.0.0.1"): None
    }
    assert vyos.summary_remote_as(text) == {
        (DEFAULT_VRF, "192.168.2.30"): 64513,
        (DEFAULT_VRF, "192.168.2.31"): 64513,
    }
