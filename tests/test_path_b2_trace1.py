"""Trace cases: zone default regions, bridge domains, source rows, carrier routes and the PBR fall-through."""

import importlib

import pytest
from tests.test_path_sdwan import WG_R1, SdwanGraph, _inner_leg, _wireguard
from tests.test_path_trace import (
    GW,
    FakeGraph,
    _l2_source,
    _PrefixTableRib,
    _route,
    _script_l2_trunk,
    _src_row,
)

from hst import path

tracemod = importlib.import_module("hst.path.trace")


@pytest.fixture()
def graph(monkeypatch):
    g = FakeGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


@pytest.fixture()
def sdwan(monkeypatch):
    g = SdwanGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


# --- a zone default-action region is not the region-cap surplus ------------------------------


def _v6_only_pair(graph):
    """A zone pair LAN->WAN that binds a rule set for IPv6 only; WAN drops by default."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.zone_pairs[("if:eth1", "if:eth0")] = {
        "rb_uid": "vyos:r1:fw:ipv6:LAN-WAN-6",
        "rb_name": "LAN-WAN-6",
        "af": 6,
        "default_action": "accept",
        "src_zone": "LAN",
        "dst_zone": "WAN",
        "zone_default": "drop",
    }


def test_a_ranged_query_reads_the_zone_default_of_a_pair_bound_for_the_other_family(graph):
    _v6_only_pair(graph)
    point = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    ranged = path.trace(None, "10.0.0.5", "8.8.8.8", port="80-443", proto="tcp", gateways=[GW])

    (point_leg,) = point["legs"]
    assert point_leg["blocked"] and "default-action" in point_leg["verdict"]
    assert ranged["legs"], "the ranged query produced no leg"
    for leg in ranged["legs"]:
        assert leg["blocked"] and not leg.get("indeterminate")
        assert "path_region_cap" not in (leg.get("firewall") or "")
        assert leg["verdict"] == "BLOCKED by LAN→WAN zone policy default-action"
    assert not any("path_region_cap" in w for w in ranged["warnings"])


# --- carriage reported, but the flow's own bridge domain is unknown --------------------------


def test_ports_that_report_carriage_against_an_unknown_bridge_domain_say_so(graph):
    """The gateway interface records no bridge domain (an untagged routed port) while the
    switch ports on the chain report what they carry: nothing was compared, and a note
    says so; the leg itself is not marked."""
    graph.sources = [_l2_source()]
    _script_l2_trunk(
        graph,
        chain=[
            {
                "uid": "port:sw1-p24",
                "is_port": True,
                "label": "Port 24",
                "dev": "sw1",
                "lag": None,
                "bds": ["bd:vlan:fab0:10"],
            },
            {"uid": "dev:sw2", "is_port": False, "label": "sw2", "dev": None, "lag": None, "bds": []},
        ],
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert any(
        n.startswith("VLAN carriage not verified for the L2_FABRIC leg (the flow's own bridge domain")
        for n in result["notes"]
    )
    assert result["warnings"] == []
    assert result["legs"][0]["indeterminate"] is False


# --- the source row of one endpoint does not follow the database order -----------------------


def _two_segment_rows():
    base = _src_row() | {"ep_uid": "ep:a", "ep_name": "laptop-a", "owned": True}
    return [base | {"seg_uid": "bd:vlan:20"}, base | {"seg_uid": "bd:vlan:10"}]


def test_the_source_row_is_the_same_in_any_read_order(graph):
    rows = _two_segment_rows()
    graph.sources = rows
    first = tracemod._source_candidates(None, "10.0.0.5")
    graph.sources = list(reversed(rows))
    second = tracemod._source_candidates(None, "10.0.0.5")

    assert [r["seg_uid"] for r in first] == [r["seg_uid"] for r in second] == ["bd:vlan:10"]


def test_the_source_query_reads_only_live_segment_and_switch_edges():
    query = tracemod._SOURCE_QUERY
    assert "ein._retired_at IS NULL AND NOT seg:Retired" in query
    assert "aon._retired_at IS NULL AND NOT sw:Retired" in query


# --- an undecided carrier arrival at the far end reaches the answer ---------------------------


def _r2_input(default_action):
    return {
        "rb_uid": "rb:r2-in",
        "rb_name": "r2-input",
        "vendor": "vyos",
        "default_action": default_action,
        "approximate": False,
    }


def test_an_undecided_input_chain_on_the_arriving_carrier_leaves_the_inner_flow_undecided(sdwan):
    _wireguard(sdwan)
    sdwan.rb_by_chain = {"input": _r2_input("inspect")}

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])
    leg = _inner_leg(result)

    assert leg["carrier"]["arrival"]["indeterminate"] is True
    assert leg["indeterminate"] is True
    assert "input chain" in leg["indeterminate_reason"]
    assert result["indeterminate"] is True


def test_a_decided_arrival_keeps_the_inner_flow_decided_and_credits_the_input_chain(sdwan):
    _wireguard(sdwan)
    sdwan.rb_by_chain = {"input": _r2_input("accept")}
    sdwan.gates = [{"uid": "rb:r2-in", "name": "r2-input", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])
    leg = _inner_leg(result)

    assert leg["carrier"]["arrival"]["indeterminate"] is False
    assert leg["verdict"] == "egress via r2-lan"
    assert not leg["indeterminate"] and not result["indeterminate"]
    assert "rb:r2-in" in leg["fw_uids"]


# --- the carrier's own route is a discard, derived or equal-cost route ------------------------


def _wg_trace(sdwan):
    return path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])


def test_a_carrier_whose_route_to_the_peer_is_a_blackhole_is_blocked(sdwan):
    _wireguard(sdwan)
    sdwan.routes["vrf:r1"] = [
        _route("10.2.0.0/16", egress="wg0"),
        _route("203.0.113.0/24", discard="blackhole"),
        _route("0.0.0.0/0", egress="eth0", next_hop="198.51.100.254"),
    ]
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["blocked"] is True
    assert leg["carrier"]["verdict"] == "BLOCKED by blackhole route 203.0.113.0/24"
    assert "resumed" not in leg["carrier"]
    assert any("blackhole route 203.0.113.0/24" in w for w in result["warnings"])


def test_a_carrier_routed_by_a_derived_route_is_undecided(sdwan):
    _wireguard(sdwan)
    sdwan.routes["vrf:r1"] = [
        _route("10.2.0.0/16", egress="wg0"),
        _route("203.0.113.0/24", kind="LEARNED_ROUTE", derived="rt-import", via_rt="65000:1"),
    ]
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["indeterminate"] is True and not leg["blocked"]
    assert any("route-target 65000:1" in w for w in result["warnings"])


def test_equal_cost_carrier_routes_by_two_interfaces_are_undecided_and_named(sdwan):
    _wireguard(sdwan)
    sdwan.routes["vrf:r1"] = [
        _route("10.2.0.0/16", egress="wg0"),
        _route("203.0.113.0/24", egress="eth0"),
        _route("203.0.113.0/24", egress="eth9"),
    ]
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["indeterminate"] is True
    assert any("eth0" in w and "eth9" in w and "equal-cost" in w for w in result["warnings"])


def test_equal_cost_carrier_routes_by_one_interface_stay_decided_with_a_note(sdwan):
    _wireguard(sdwan)
    sdwan.routes["vrf:r1"] = [
        _route("10.2.0.0/16", egress="wg0"),
        _route("203.0.113.0/24", egress="eth0", next_hop="198.51.100.9"),
        _route("203.0.113.0/24", egress="eth0", next_hop="198.51.100.254"),
    ]
    sdwan.next_hop_devs["198.51.100.9"] = {
        "dev_uid": "dev:r2",
        "dev_name": "r2",
        "if_uid": "if:r2-eth0",
        "if_name": "eth0",
        "anchor": "vrf:r2-global",
        "l3dom": "default",
    }
    # r2's global table is in r1's routing domain: the next hop stays in it
    sdwan.domain_mates["vrf:r1"] = ["vrf:r2-global"]
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert result["warnings"] == []
    assert not leg["indeterminate"] and not leg["blocked"]
    assert any("2 equal-cost routes 203.0.113.0/24" in n and "198.51.100.254" in n for n in result["notes"])


def test_a_carrier_route_the_graph_and_the_store_both_hold_is_one_interface(sdwan):
    """The graph row names a next hop and the store row of the same uplink names only
    the interface, so the two are not folded; both leave by eth0, which is one egress
    interface: the carrier stays decided."""
    _wireguard(sdwan)
    sdwan.routes["vrf:r1"] = [
        _route("10.2.0.0/16", egress="wg0"),
        # the collector folded the device's own RIB row onto the graph route
        _route("203.0.113.0/24", egress="eth0", next_hop="198.51.100.254") | {"rib": True},
    ]
    rib = _PrefixTableRib(
        [
            {
                "prefix": "10.2.0.0/16",
                "next_hop": None,
                "interface": "wg0",
                "protocol": "static",
                "metric": None,
                "prefixlen": 16,
                "af": 4,
            },
            {
                "prefix": "203.0.113.0/24",
                "next_hop": None,
                "interface": "eth0",
                "protocol": "static",
                "metric": None,
                "prefixlen": 24,
                "af": 4,
            },
        ]
    )
    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1], rib=rib)
    leg = _inner_leg(result)

    assert any("2 equal-cost routes 203.0.113.0/24" in n for n in result["notes"])
    assert not any("leave by different interfaces" in w for w in result["warnings"])
    assert leg["carrier"]["egress"] == "eth0"
    assert not leg["blocked"]


def test_the_normal_carrier_route_stays_decided(sdwan):
    _wireguard(sdwan)
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["verdict"] == "egress via r2-lan"
    assert not leg["indeterminate"] and not leg["blocked"]
    assert result["warnings"] == []


# --- the carrier's source address is of the peer's family -------------------------------------


def _no_local_address(sdwan, eth0_address):
    _wireguard(sdwan)
    sdwan.tunnel_props_by_uid["tun:r1-wg"]["local_address"] = None
    sdwan.iface_addrs["if:eth0"] = eth0_address


def test_a_carrier_source_of_the_other_family_is_not_taken(sdwan):
    _no_local_address(sdwan, "2001:db8::1")
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["carrier"]["src"] is None
    assert leg["indeterminate"] is True
    assert any("source address" in w and "eth0" in w for w in result["warnings"])


def test_the_single_address_of_the_peers_family_is_the_carrier_source(sdwan):
    _no_local_address(sdwan, "198.51.100.1")
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["carrier"]["src"] == "198.51.100.1"
    assert not leg["indeterminate"]


# --- a far end held by more than one device is named, not picked silently ---------------------


def _holders(monkeypatch, sdwan, row):
    """Answer the holders read (`_FAR_ADDRESS_HOLDERS_QUERY`) with `row`; every other
    read goes to the scripted graph."""

    def read_one(session, query, **p):
        if query == tracemod._FAR_ADDRESS_HOLDERS_QUERY:
            assert p == {"ip": "203.0.113.2"}
            return row
        return sdwan.read_one(query, **p)

    monkeypatch.setattr(path, "_read_one", read_one)


def test_a_far_end_address_two_devices_hold_is_undecided_and_names_them(monkeypatch, sdwan):
    _wireguard(sdwan)
    _holders(monkeypatch, sdwan, {"holders": 2, "names": ["r2", "r9"]})
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert leg["indeterminate"] is True
    assert result["indeterminate"] is True
    assert any("held by 2 devices (r2, r9)" in w for w in result["warnings"])


def test_a_far_end_one_device_holds_stays_decided(monkeypatch, sdwan):
    _wireguard(sdwan)
    _holders(monkeypatch, sdwan, {"holders": 1, "names": ["r2"]})
    result = _wg_trace(sdwan)
    leg = _inner_leg(result)

    assert not leg["indeterminate"] and result["warnings"] == []


def test_the_owner_read_is_ordered_and_the_holders_read_counts_interface_holders():
    assert tracemod._FAR_ADDRESS_OWNER_QUERY.rstrip().endswith("ORDER BY rank, d.uid, i.uid LIMIT 1")
    holders = tracemod._FAR_ADDRESS_HOLDERS_QUERY
    assert "count(DISTINCT d) AS holders" in holders and "WanLink" not in holders
    assert "(ip:IpAddress:Obj {uid: $far, collection_ts: $snap})" in tracemod._FAR_NODE_HOLDERS_QUERY


# --- the PBR fall-through is decided per part of a network destination -----------------------


def _split_tunnel(graph):
    """PBR rule 10 steers every flow into table 100, which holds 10.8.0.0/16 via wg0 and
    no default; the main table sends everything by eth0."""
    graph.sources = [_src_row()]
    graph.pbr = [
        {
            "pol_uid": "pol:1",
            "pol_name": "steer",
            "rule_uid": "rule:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": [],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": "vrf:100",
            "table_name": "100",
        }
    ]
    graph.routes = {
        "vrf:100": [_route("10.8.0.0/16", egress="wg0")],
        "vrf:main": [_route("0.0.0.0/0", egress="eth0")],
    }


def test_a_network_destination_the_pbr_table_covers_in_part_is_split(graph):
    _split_tunnel(graph)
    result = path.trace(None, "10.0.0.5", "10.0.0.0/8", gateways=[GW])

    egresses = sorted((leg["table"], leg["egress"]) for leg in result["legs"])
    assert ("100", "wg0") in egresses and ("default", "eth0") in egresses
    assert not any(leg["verdict"] == "no route found" for leg in result["legs"])
    wg = next(leg for leg in result["legs"] if leg["egress"] == "wg0")
    assert wg["cidr"] == "10.8.0.0/16" and wg["dst_label"] == "10.8.0.0/16"
    eth0 = next(leg for leg in result["legs"] if leg["egress"] == "eth0")
    assert eth0["dst_label"] == "10.0.0.0/13 +7 more (16711680 addresses)"
    assert any("holds a route for 10.8.0.0/16 only" in n for n in result["notes"])
    assert any("falls through" in n for n in result["notes"])


def test_a_covered_first_address_does_not_keep_the_whole_destination_in_the_pbr_table(graph):
    _split_tunnel(graph)
    result = path.trace(None, "10.0.0.5", "10.8.0.0/15", gateways=[GW])

    assert not any(leg["verdict"] == "no route found" for leg in result["legs"])
    assert sorted((leg["table"], leg["egress"]) for leg in result["legs"]) == [
        ("100", "wg0"),
        ("default", "eth0"),
    ]


def test_a_single_address_the_pbr_table_covers_stays_in_it(graph):
    _split_tunnel(graph)
    result = path.trace(None, "10.0.0.5", "10.8.1.1", gateways=[GW])

    ((table, egress),) = [(leg["table"], leg["egress"]) for leg in result["legs"]]
    assert (table, egress) == ("100", "wg0")
    assert not any("falls through" in n for n in result["notes"])


def test_a_single_address_the_pbr_table_misses_falls_through(graph):
    _split_tunnel(graph)
    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    ((table, egress),) = [(leg["table"], leg["egress"]) for leg in result["legs"]]
    assert (table, egress) == ("default", "eth0")
    assert any("falls through" in n for n in result["notes"])
