"""A BGP `network` or `aggregate-address` statement is an ORIGINATES edge,
and no connected route."""

from __future__ import annotations

import copy

from tests.test_path_trace import GW, _route, _src_row, graph  # noqa: F401

from hst import path
from hst.app import simul_read
from hst.collectors import nxos, vyos
from hst.collectors.auth import SshAgent
from hst.collectors.cisco_common import normalize_cisco
from hst.collectors.cli_collector import CiscoCliCollector
from hst.collectors.nxos import NxosCollector, NxosConfig
from hst.collectors.util import GraphBuilder, connected_address
from hst.core import uid
from hst.core.identity import MemoryResolver
from hst.path.addrsets import _intervals
from hst.path.gates.routing import _route_partition
from hst.path.trace import _ROUTES_QUERY

# --- the route read ----------------------------------------------------------------------


def test_the_routes_query_drops_network_statements_and_reads_aggregates_as_discards():
    """Pinned on the query text: the scripted graph answers whatever it is
    told to, so only the text (and the db test) shows what Neo4j returns."""
    assert "AND NOT (type(r) = 'ORIGINATES' AND coalesce(r.proto, '') = 'network')" in _ROUTES_QUERY
    assert "CASE WHEN is_aggregate THEN 'AGGREGATE' ELSE type(r) END AS kind" in _ROUTES_QUERY
    assert "CASE WHEN is_aggregate THEN 'blackhole' ELSE r.discard END AS discard" in _ROUTES_QUERY


def test_the_simulation_reads_no_bgp_origination_as_a_connected_route():
    assert (
        "AND NOT (type(r) = 'ORIGINATES' AND coalesce(r.proto, '') IN ['network', 'aggregate'])"
        in simul_read._CONTEXT_ROUTES
    )


def _aggregate(cidr):
    """A BGP aggregate as `_ROUTES_QUERY` returns it."""
    return _route(cidr, kind="AGGREGATE", discard="blackhole")


def test_an_aggregate_equal_to_a_connected_prefix_yields_to_it():
    connected = _route("10.20.0.0/16", kind="ORIGINATES")
    parts = _route_partition([connected, _aggregate("10.20.0.0/16")], _intervals(["10.20.1.1"]), None)
    assert [w["kind"] for w in parts[0][1]] == ["ORIGINATES"]


def test_an_aggregate_over_a_recursive_next_hop_does_not_skip_the_devices_between(graph):  # noqa: F811
    """r1's route to 172.16.0.0/16 is an iBGP route via r3's loopback, two
    hops away through a firewall. An aggregate 10.0.0.0/8 covering the
    loopback is a discard route, not a connected prefix: the next hop is not
    one hop away, and the trace does not jump from r1 to r3."""
    graph.sources = [_src_row()]
    graph.default_tables = {GW["if_uid"]: {"uid": "vrf:r1"}, "if:r3-lo0": {"uid": "vrf:r3"}}
    graph.local_vrf = {"vrf_uid": "vrf:r1", "vrf_name": "default"}
    graph.routes = {
        "vrf:r1": [
            _route("10.0.0.0/24", kind="ORIGINATES"),
            _route("192.0.2.0/30", kind="ORIGINATES"),
            _route("172.16.0.0/16", next_hop="10.255.0.3"),
            _aggregate("10.0.0.0/8"),
        ],
        "vrf:r3": [_route("172.16.0.0/16", egress="r3-lan")],
    }
    graph.next_hop_devs = {
        "10.255.0.3": {"dev_uid": "dev:r3", "dev_name": "r3", "if_uid": "if:r3-lo0", "if_name": "lo0"}
    }
    res = path.trace(None, "10.0.0.5", "172.16.1.1", gateways=[GW])
    devices = [h["label"] for h in res["hops"] if h["kind"] == "Device"]
    assert "r3" not in devices, res["verdict"]
    assert [leg["indeterminate"] for leg in res["legs"]] == [True]
    assert "r1 holds a blackhole route 10.0.0.0/8 for next hop 10.255.0.3" in " ".join(res["warnings"])


# --- the collectors ----------------------------------------------------------------------

_BRANCH = {
    "device": {"hostname": "br1", "serial": "FDO1", "platform": "iosxe", "os_version": "17.3"},
    "interfaces": [
        {
            "name": "Vlan10",
            "kind": "svi",
            "mac": "aabbccddee10",
            "admin_up": True,
            "ips": [{"ip": "10.10.10.1", "prefixlen": 24, "vrf": ""}],
            "vlan": 10,
        },
        {
            "name": "GigabitEthernet0/0",
            "kind": "phys",
            "mac": "aabbccddee01",
            "admin_up": True,
            "ips": [{"ip": "192.0.2.1", "prefixlen": 30, "vrf": ""}],
            "vlan": None,
        },
    ],
    "neighbors": [],
    "vlans": [{"vid": 10, "name": "DATA"}],
    "vrfs": [],
    "rib": [],
    "mac_table": [],
    "arp": [],
}


def test_a_network_statement_for_a_connected_subnet_keeps_the_connected_kind():
    inter = copy.deepcopy(_BRANCH)
    inter["routing"] = {
        "bgp": {
            "asn": 65001,
            "router_id": "10.255.0.1",
            "vrf": "default",
            "neighbors": [],
            "networks": [{"prefix": "10.10.10.0/24", "route_map": None}],
            "aggregates": [{"prefix": "192.0.2.0/30"}],
            "redistribute": [],
        }
    }
    batch = normalize_cisco(inter, source="iosxe", scope="iosxe:br1", l3dom="corp", resolver=MemoryResolver())
    kinds = {n.props["cidr"]: n.props.get("kind") for n in batch.nodes if n.label == "Prefix"}
    assert kinds == {"10.10.10.0/24": "connected", "192.0.2.0/30": "connected"}
    cidr_of = {n.uid: n.props["cidr"] for n in batch.nodes if n.label == "Prefix"}
    origins = sorted((cidr_of[r.end_uid], r.props["proto"]) for r in batch.rels if r.rel_type == "ORIGINATES")
    assert origins == [
        ("10.10.10.0/24", "connected"),
        ("10.10.10.0/24", "network"),
        ("192.0.2.0/30", "aggregate"),
        ("192.0.2.0/30", "connected"),
    ]


def test_vyos_network_and_aggregate_statements_keep_the_connected_kind():
    builder = GraphBuilder()
    vrf_uid = "vrf:device-1:default"
    connected_address(builder, "10.0.0.1/24", anchor=vrf_uid, dom="corp", vrf_uid=vrf_uid)
    connected_address(builder, "10.1.0.1/16", anchor=vrf_uid, dom="corp", vrf_uid=vrf_uid)
    vyos._bgp_stage(
        builder,
        {
            "system-as": "65000",
            "address-family": {
                "ipv4-unicast": {"network": {"10.0.0.0/24": {}}, "aggregate-address": {"10.1.0.0/16": {}}}
            },
        },
        "device:1",
        "default",
        vrf_uid,
        "device:1",
        {},
        {},
    )
    batch = builder.batch("vyos", "run")
    for cidr in ("10.0.0.0/24", "10.1.0.0/16"):
        assert builder.props("Prefix", uid.prefix(vrf_uid, cidr))["kind"] == "connected", cidr
    origins = sorted((r.end_uid, r.props["proto"]) for r in batch.rels if r.rel_type == "ORIGINATES")
    assert origins == [
        (uid.prefix(vrf_uid, "10.0.0.0/24"), "connected"),
        (uid.prefix(vrf_uid, "10.0.0.0/24"), "network"),
        (uid.prefix(vrf_uid, "10.1.0.0/16"), "aggregate"),
        (uid.prefix(vrf_uid, "10.1.0.0/16"), "connected"),
    ]


def test_nxos_network_and_aggregate_statements_keep_the_connected_kind(monkeypatch):
    """NX-OS builds its BGP nodes in a batch of their own and appends them to
    the base twin's, so the writer sets the BGP stage's Prefix props last."""
    base = normalize_cisco(
        copy.deepcopy(_BRANCH), source="nxos", scope="nxos:br1", l3dom="corp", resolver=MemoryResolver()
    )
    processes = nxos.parse_bgp_config(
        """router bgp 65001
  address-family ipv4 unicast
    network 10.10.10.0/24
    aggregate-address 192.0.2.0/30
"""
    )
    monkeypatch.setattr(CiscoCliCollector, "normalize", lambda self, raw: base)
    monkeypatch.setattr(NxosCollector, "_inter", lambda self, raw: {"bgp": {"processes": processes}})
    batch = NxosCollector(NxosConfig(host="br1", auth=SshAgent(username="ro")), None).normalize({})
    kinds: dict[str, str] = {}
    for node in batch.nodes:
        if node.label == "Prefix" and "kind" in node.props:
            kinds[node.props["cidr"]] = node.props["kind"]
    assert kinds == {"10.10.10.0/24": "connected", "192.0.2.0/30": "connected"}
    cidr_of = {n.uid: n.props["cidr"] for n in batch.nodes if n.label == "Prefix"}
    origins = {(cidr_of[r.end_uid], r.props["proto"]) for r in batch.rels if r.rel_type == "ORIGINATES"}
    assert origins == {
        ("10.10.10.0/24", "connected"),
        ("10.10.10.0/24", "network"),
        ("192.0.2.0/30", "aggregate"),
        ("192.0.2.0/30", "connected"),
    }
