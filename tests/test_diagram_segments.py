"""The segments of a drawing (hst/diagram/segments.py) on a small home site:

    gw-01 (eth0 192.168.2.1/24, eth0.10 192.168.10.1/24)
      | eth0 -- UPPER_LAN
    sw-01  Port 3 -- eth0  ap-01
      Port 2, Port 21: access ports, no cable

VLAN 1 is the untagged default network: no SVI states it, and the router's
eth0 holds its prefix. VLAN 10 has the SVI eth0.10.
"""

from __future__ import annotations

import random

from hst.diagram import segments as seg

BD1 = "bd:vlan:fab0:1"
BD10 = "bd:vlan:fab0:10"


def _vlan(dev, vid, ports=(), native=(), svi=None, bd=None, name=None):
    return {
        "dev": dev,
        "vid": vid,
        "name": name,
        "segment": name,
        "bd": bd,
        "ports": sorted(ports),
        "native": sorted(native),
        "svi": svi,
    }


def _addr(dev, iface, ip, cidr, af=4, domain="home"):
    return {"dev": dev, "iface": iface, "ip": ip, "cidr": cidr, "af": af, "vrf": "default", "domain": domain}


def _client(uid, dev, port=None, ssid=None, bd=None, cidrs=(), mac=None):
    return {"uid": uid, "dev": dev, "port": port, "ssid": ssid, "bd": bd, "cidrs": list(cidrs), "mac": mac}


CABLES = [
    {"a_dev": "gw-01", "a_port": "eth0", "b_dev": "sw-01", "b_port": "UPPER_LAN"},
    {"a_dev": "sw-01", "a_port": "Port 3", "b_dev": "ap-01", "b_port": "eth0"},
]
VLANS = [
    _vlan("gw-01", 10, ports=["eth0"], svi="eth0.10", bd=BD10),
    _vlan(
        "sw-01",
        1,
        ports=["UPPER_LAN", "Port 3", "Port 21"],
        native=["UPPER_LAN", "Port 21"],
        bd=BD1,
        name="Default",
    ),
    _vlan("sw-01", 10, ports=["UPPER_LAN", "Port 2", "Port 3"], native=["Port 2"], bd=BD10, name="Office"),
    _vlan("ap-01", 10, ports=["eth0"], bd=BD10, name="Office"),
    # a VLAN no bridge domain realizes joins no segment
    _vlan("gw-01", 7, ports=["eth2"], svi="eth2.7"),
]
SUBNETS = [
    _addr("gw-01", "eth0", "192.168.2.1", "192.168.2.0/24"),
    _addr("gw-01", "eth0", "2001:db8:1::1", "2001:db8:1::/64", af=6),
    _addr("gw-01", "eth0.10", "192.168.10.1", "192.168.10.0/24"),
]
CLIENTS = [
    _client("ep:nas", "sw-01", port="Port 21", bd=BD1, cidrs=["192.168.2.0/24"]),
    _client("ep:pc", "sw-01", port="Port 2", bd=BD10, cidrs=["192.168.10.0/24"]),
    _client("ep:phone", "ap-01", ssid="Home", bd=BD10, cidrs=["192.168.10.0/24"]),
    _client("ep:tv", "ap-01", ssid="Home", bd=BD10, cidrs=["192.168.10.0/24"]),
]


def _plan(vlans=VLANS, subnets=SUBNETS, clients=CLIENTS):
    return {s["bd"]: s for s in seg.segments(vlans, subnets, clients, seg.cabled_ports(CABLES))}


def test_a_segment_lists_its_carriers_and_the_access_ports_among_them():
    office = _plan()[BD10]
    assert (office["vid"], office["name"]) == (10, "Office")
    assert [c["dev"] for c in office["carriers"]] == ["ap-01", "gw-01", "sw-01"]
    sw = next(c for c in office["carriers"] if c["dev"] == "sw-01")
    assert sw["ports"] == ["Port 2", "Port 3", "UPPER_LAN"]
    # Port 2 carries it untagged and has no cable: an access port
    assert sw["access"] == ["Port 2"]
    # a native port with a cable is a trunk's native VLAN, not an access port
    default = _plan()[BD1]
    assert next(c for c in default["carriers"] if c["dev"] == "sw-01")["access"] == ["Port 21"]


def test_the_gateway_is_the_svi_with_its_address_and_prefix():
    office = _plan()[BD10]
    assert [(g["dev"], g["iface"], g["ip"], g["cidr"], g["basis"]) for g in office["gateways"]] == [
        ("gw-01", "eth0.10", "192.168.10.1", "192.168.10.0/24", "svi")
    ]
    assert (office["cidrs"], office["cidr_basis"]) == (["192.168.10.0/24"], "gateway")


def test_an_svi_with_no_address_is_a_gateway_without_one():
    [vlan7] = seg.segments([_vlan("gw-01", 7, svi="eth2.7", bd="bd:vlan:fab0:7")], SUBNETS, [], set())
    assert [(g["iface"], g["ip"]) for g in vlan7["gateways"]] == [("eth2.7", None)]
    assert (vlan7["cidrs"], vlan7["cidr_basis"]) == ([], None)


def test_an_untagged_lan_finds_its_gateway_by_the_prefix_of_its_clients():
    """No SVI binds VLAN 1, so its clients' prefix names it, and the router
    interface on that prefix is its gateway, with every address it holds."""
    default = _plan()[BD1]
    assert [(g["dev"], g["iface"], g["ip"], g["basis"]) for g in default["gateways"]] == [
        ("gw-01", "eth0", "192.168.2.1", "cidr"),
        ("gw-01", "eth0", "2001:db8:1::1", "cidr"),
    ]
    assert default["cidrs"] == ["192.168.2.0/24", "2001:db8:1::/64"]
    assert default["cidr_basis"] == "clients"


def test_an_svi_of_another_segment_is_never_a_gateway_by_the_prefix():
    # a client of VLAN 1 that sits in the office prefix does not make eth0.10 its gateway
    clients = [_client("ep:odd", "sw-01", port="Port 21", bd=BD1, cidrs=["192.168.10.0/24"])]
    default = _plan(clients=clients)[BD1]
    assert default["gateways"] == []
    assert (default["cidrs"], default["cidr_basis"]) == (["192.168.10.0/24"], "clients")


def test_client_counts_per_segment_and_per_attachment_point():
    office = _plan()[BD10]
    assert office["clients"] == 3
    assert office["attachments"] == [
        {"dev": "ap-01", "port": None, "ssid": "Home", "count": 2},
        {"dev": "sw-01", "port": "Port 2", "ssid": None, "count": 1},
    ]
    assert _plan()[BD1]["clients"] == 1


def test_a_client_that_is_a_drawn_device_or_sits_on_a_cabled_port_is_not_drawn():
    macs = seg.device_macs([{"uid": "gw-01", "mac": "AA:BB:CC:00:00:01"}, {"uid": "sw-01", "mac": None}])
    cabled = seg.cabled_ports(CABLES)
    assert macs == {"aabbcc000001"}
    assert not seg.visible({"dev": "sw-01", "port": "Port 9", "mac": "aa-bb-cc-00-00-01"}, macs, cabled)
    assert not seg.visible({"dev": "sw-01", "port": "UPPER_LAN", "mac": "112233445566"}, macs, cabled)
    assert seg.visible({"dev": "sw-01", "port": "Port 21", "mac": "112233445566"}, macs, cabled)
    # a wireless client has no port, and a MAC that does not parse matches nothing
    assert seg.visible({"dev": "ap-01", "port": None, "mac": "not-a-mac"}, macs, cabled)


def test_the_segments_are_ordered_and_the_same_for_any_row_order():
    first = seg.segments(VLANS, SUBNETS, CLIENTS, seg.cabled_ports(CABLES))
    assert [s["bd"] for s in first] == [BD1, BD10]
    rng = random.Random(7)
    for _ in range(5):
        vlans, subnets, clients = list(VLANS), list(SUBNETS), list(CLIENTS)
        for rows in (vlans, subnets, clients):
            rng.shuffle(rows)
        assert seg.segments(vlans, subnets, clients, seg.cabled_ports(CABLES)) == first


# --- the graph's attachments: (Interface)-[:ATTACHED_TO {basis}]->(BridgeDomain) ---------


def _attached(dev, iface, bd, basis, ip=None, cidr=None, af=4, vid=None, segment=None):
    return {
        "dev": dev,
        "iface": iface,
        "bd": bd,
        "basis": basis,
        "vid": vid,
        "segment": segment,
        "ip": ip,
        "cidr": cidr,
        "af": af if ip else None,
        "vrf": "default",
        "domain": "home",
        "fhrp": None,
    }


ATTACHED = [
    _attached("gw-01", "eth0", BD1, "cable", "192.168.2.1", "192.168.2.0/24", vid=1),
    _attached("gw-01", "eth0", BD1, "cable", "2001:db8:1::1", "2001:db8:1::/64", af=6, vid=1),
    _attached("gw-01", "eth0.10", BD10, "subif", "192.168.10.1", "192.168.10.0/24", vid=10),
]
PREFIXES = [
    {"bd": BD1, "cidr": "192.168.2.0/24"},
    {"bd": BD1, "cidr": "2001:db8:1::/64"},
    {"bd": BD10, "cidr": "192.168.10.0/24"},
]


def _graph_plan(attached=ATTACHED, prefixes=PREFIXES, vlans=VLANS, subnets=SUBNETS, clients=CLIENTS):
    rows = seg.segments(
        vlans, subnets, clients, seg.cabled_ports(CABLES), attached=attached, prefixes=prefixes
    )
    return {s["bd"]: s for s in rows}


def test_an_untagged_lan_takes_its_gateway_from_the_cable_attachment():
    """The router's eth0 is attached to VLAN 1 by its cable to the switch's
    native VLAN: the gateway rows carry `basis: cable`, one per address, and
    the prefixes come from the graph, not from the clients."""
    default = _graph_plan()[BD1]
    assert [(g["dev"], g["iface"], g["ip"], g["cidr"], g["af"], g["basis"]) for g in default["gateways"]] == [
        ("gw-01", "eth0", "192.168.2.1", "192.168.2.0/24", 4, "cable"),
        ("gw-01", "eth0", "2001:db8:1::1", "2001:db8:1::/64", 6, "cable"),
    ]
    assert (default["cidrs"], default["cidr_basis"]) == (["192.168.2.0/24", "2001:db8:1::/64"], "gateway")
    assert set(default["gateways"][0]) == {
        "dev",
        "iface",
        "ip",
        "cidr",
        "af",
        "vrf",
        "domain",
        "fhrp",
        "routes",
        "basis",
    }


def test_the_edge_basis_wins_over_the_svi_join_and_the_interface_is_listed_once():
    """eth0.10 is the SVI of the VLAN 10 group and attached by the graph as a
    subinterface: one gateway row, with the edge's basis."""
    office = _graph_plan()[BD10]
    assert [(g["iface"], g["ip"], g["basis"]) for g in office["gateways"]] == [
        ("eth0.10", "192.168.10.1", "subif")
    ]


def test_an_svi_the_graph_does_not_attach_joins_by_its_vlan():
    office = _graph_plan(attached=ATTACHED[:2])[BD10]
    assert [(g["iface"], g["ip"], g["basis"]) for g in office["gateways"]] == [
        ("eth0.10", "192.168.10.1", "svi")
    ]


def test_the_prefixes_in_the_bridge_domain_join_the_gateway_prefixes_ipv4_first_in_address_order():
    prefixes = [
        *PREFIXES,
        {"bd": BD10, "cidr": "2001:db8:10::/64"},
        {"bd": BD10, "cidr": "10.0.10.0/24"},
        {"bd": BD10, "cidr": "9.0.0.0/8"},
    ]
    office = _graph_plan(prefixes=prefixes)[BD10]
    assert office["cidrs"] == ["9.0.0.0/8", "10.0.10.0/24", "192.168.10.0/24", "2001:db8:10::/64"]
    assert office["cidr_basis"] == "gateway"


def test_a_segment_with_prefixes_and_no_gateway_takes_its_cidrs_from_the_graph():
    bd = "uni/tn-prod/BD-web"
    clients = [_client("ep:web", "leaf-101", bd=bd, cidrs=["10.1.1.0/24"])]
    [web] = seg.segments([], [], clients, set(), prefixes=[{"bd": bd, "cidr": "10.1.1.0/24"}])
    assert (web["cidrs"], web["cidr_basis"], web["gateways"]) == (["10.1.1.0/24"], "gateway", [])


def test_an_attached_interface_with_no_address_is_a_gateway_without_one():
    [vlan7] = seg.segments(
        [], [], [], set(), attached=[_attached("gw-01", "eth2.7", "bd:vlan:fab0:7", "subif", vid=7)]
    )
    assert (vlan7["vid"], [(g["iface"], g["ip"], g["basis"]) for g in vlan7["gateways"]]) == (
        7,
        [("eth2.7", None, "subif")],
    )
    assert (vlan7["cidrs"], vlan7["cidr_basis"]) == ([], None)


def test_an_attached_interface_is_never_a_gateway_of_another_segment_by_the_prefix():
    """VLAN 20 has no gateway, and its client sits in the prefix of eth0, which
    the graph attaches to VLAN 1: the fallback does not claim it."""
    bd20 = "bd:vlan:fab0:20"
    clients = [*CLIENTS, _client("ep:odd", "sw-01", port="Port 21", bd=bd20, cidrs=["192.168.2.0/24"])]
    odd = _graph_plan(clients=clients)[bd20]
    assert odd["gateways"] == []
    assert (odd["cidrs"], odd["cidr_basis"]) == (["192.168.2.0/24"], "clients")


def test_the_prefix_fallback_serves_a_segment_with_no_gateway_in_a_graph_with_attachments():
    """VLAN 1 has no attachment in this snapshot."""
    default = _graph_plan(attached=ATTACHED[2:], prefixes=PREFIXES[2:])[BD1]
    assert [(g["iface"], g["ip"], g["basis"]) for g in default["gateways"]] == [
        ("eth0", "192.168.2.1", "cidr"),
        ("eth0", "2001:db8:1::1", "cidr"),
    ]
    assert default["cidr_basis"] == "clients"


def test_a_bridge_domain_only_an_attachment_names_is_a_segment_with_its_vid_and_name():
    bd = "bd:vlan:fab0:99"
    row = _attached("gw-01", "eth3", bd, "cable", "10.9.9.1", "10.9.9.0/24", vid=99, segment="Lab")
    [lab] = [s for s in seg.segments([], [], [], set(), attached=[row]) if s["bd"] == bd]
    assert (lab["vid"], lab["name"], lab["cidrs"]) == (99, "Lab", ["10.9.9.0/24"])


def test_the_segments_with_attachments_are_the_same_for_any_row_order():
    first = seg.segments(
        VLANS, SUBNETS, CLIENTS, seg.cabled_ports(CABLES), attached=ATTACHED, prefixes=PREFIXES
    )
    rng = random.Random(11)
    for _ in range(5):
        attached = [*ATTACHED, ATTACHED[0]]
        prefixes = list(PREFIXES)
        rng.shuffle(attached)
        rng.shuffle(prefixes)
        got = seg.segments(
            VLANS, SUBNETS, CLIENTS, seg.cabled_ports(CABLES), attached=attached, prefixes=prefixes
        )
        assert got == first


def test_a_gateway_row_states_whether_the_graph_routes_for_it():
    vlans = [_vlan("sw-07", 20, svi="Vlan20", bd=BD10)]
    rows = [
        {**_addr("sw-07", "Vlan20", "10.20.7.1", "10.20.7.0/24"), "routes": False},
        {**_addr("sw-08", "Vlan20", "10.20.8.1", "10.20.8.0/24"), "routes": True},
    ]
    [plain] = seg.segments(vlans, rows, [], set())
    assert [(g["dev"], g["routes"]) for g in plain["gateways"]] == [("sw-07", False)]
    attached = [{**rows[1], "bd": BD1, "basis": "svi"}]
    [routed] = seg.segments([], [], [], set(), attached=attached)
    assert [(g["dev"], g["routes"]) for g in routed["gateways"]] == [("sw-08", True)]
    # a row that does not say, or an interface with no address, leaves it open
    [bare] = seg.segments(vlans, [], [], set())
    assert [g["routes"] for g in bare["gateways"]] == [None]


def test_the_topology_reads_state_gateway_for_beside_each_address():
    from hst.app.routes import topology

    for query in (topology._SUBNETS, topology._ATTACHED):
        assert "MATCH (i)-[g:GATEWAY_FOR]->(pfx) WHERE g._retired_at IS NULL } AS routes" in query


# --- the prefix fallback stays at the segment's site and in one routing domain


def _site_b_and_guest_vrf():
    """VLAN 1's client sits in 192.168.2.0/24, as does eth0 of gw-01 at site
    a; rtr-b at site b and the guest VRF of rtr-a hold the same prefix."""
    subnets = [
        *SUBNETS,
        _addr("rtr-b", "Gi0/1", "192.168.2.1", "192.168.2.0/24", domain="site-b"),
        {
            **_addr("rtr-a", "Gi0/2.99", "192.168.2.254", "192.168.2.0/24", domain="site-a:guest"),
            "vrf": "guest",
        },
    ]
    sites = {"gw-01": "a", "sw-01": "a", "ap-01": "a", "rtr-a": "a", "rtr-b": "b"}
    return subnets, sites


def test_the_prefix_fallback_takes_no_gateway_from_another_site():
    """rtr-b holds the prefix at site b, where none of the segment's devices is."""
    subnets, sites = _site_b_and_guest_vrf()
    subnets = [s for s in subnets if s["dev"] != "rtr-a"]
    default = {
        s["bd"]: s for s in seg.segments(VLANS, subnets, CLIENTS, seg.cabled_ports(CABLES), sites=sites)
    }[BD1]
    assert [(g["dev"], g["iface"]) for g in default["gateways"]] == [("gw-01", "eth0"), ("gw-01", "eth0")]


def test_the_prefix_fallback_takes_no_gateway_when_the_prefix_is_in_two_routing_domains():
    """At the segment's own site the prefix is held in the default routing domain and in the guest VRF."""
    subnets, sites = _site_b_and_guest_vrf()
    default = {
        s["bd"]: s for s in seg.segments(VLANS, subnets, CLIENTS, seg.cabled_ports(CABLES), sites=sites)
    }[BD1]
    assert default["gateways"] == []
    assert (default["cidrs"], default["cidr_basis"]) == (["192.168.2.0/24"], "clients")


def test_an_interface_the_prefix_fallback_takes_is_no_other_segments_gateway():
    """Two segments with no gateway whose clients share a prefix: the first
    in bridge-domain order takes the interface, the other does not draw it
    too."""
    bd20 = "bd:vlan:fab0:20"
    clients = [*CLIENTS, _client("ep:odd", "sw-01", port="Port 21", bd=bd20, cidrs=["192.168.2.0/24"])]
    plan = {s["bd"]: s for s in seg.segments(VLANS, SUBNETS, clients, seg.cabled_ports(CABLES))}
    assert [g["iface"] for g in plan[BD1]["gateways"]] == ["eth0", "eth0"]
    assert plan[bd20]["gateways"] == []


def _two_sites():
    """VLAN 10 at A and at B, one bridge domain on the default fabric, each site its own prefix."""
    vlans = [
        _vlan("a-gw", 10, ports=["eth0"], svi="Vlan10", bd=BD10, name="Users"),
        _vlan("a-sw", 10, ports=["Port 1"], native=["Port 1"], bd=BD10, name="Users"),
        _vlan("b-gw", 10, ports=["eth0"], svi="Vlan10", bd=BD10, name="Users"),
    ]
    subnets = [
        _addr("a-gw", "Vlan10", "10.1.10.1", "10.1.10.0/24"),
        _addr("b-gw", "Vlan10", "10.2.10.1", "10.2.10.0/24"),
    ]
    clients = [
        _client("ep-a", "a-sw", port="Port 1", bd=BD10, cidrs=["10.1.10.0/24"]),
        _client("ep-b", "b-gw", bd=BD10, cidrs=["10.2.10.0/24"]),
    ]
    # the bridge domain names the prefixes of every site
    prefixes = [{"bd": BD10, "cidr": "10.1.10.0/24"}, {"bd": BD10, "cidr": "10.2.10.0/24"}]
    sites = {"a-gw": "A", "a-sw": "A", "b-gw": "B"}
    return vlans, subnets, clients, prefixes, sites


def test_a_drawing_of_two_sites_keeps_one_segment_per_site_under_one_bridge_domain():
    """With no L2 fabric declared, VLAN 10 at A and at B is one bridge domain."""
    vlans, subnets, clients, prefixes, sites = _two_sites()
    out = seg.segments(vlans, subnets, clients, set(), prefixes=prefixes, sites=sites)
    assert [(s["bd"], s["site"]) for s in out] == [(BD10, "A"), (BD10, "B")]
    a, b = out
    assert (a["cidrs"], b["cidrs"]) == (["10.1.10.0/24"], ["10.2.10.0/24"])
    assert [c["dev"] for c in a["carriers"]] == ["a-gw", "a-sw"] and [c["dev"] for c in b["carriers"]] == [
        "b-gw"
    ]
    assert [g["dev"] for g in a["gateways"]] == ["a-gw"] and [g["dev"] for g in b["gateways"]] == ["b-gw"]
    assert (a["clients"], b["clients"]) == (1, 1)


def test_a_drawing_of_one_site_keeps_one_segment_with_no_site():
    vlans, subnets, clients, prefixes, sites = _two_sites()
    only = dict.fromkeys(sites, "A")
    (one,) = seg.segments(vlans, subnets, clients, set(), prefixes=prefixes, sites=only)
    assert one["site"] is None
    assert one["cidrs"] == ["10.1.10.0/24", "10.2.10.0/24"]
