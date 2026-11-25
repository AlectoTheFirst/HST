"""A connected ORIGINATES prefix, or a BGP aggregate, that the device's
observed RIB does not hold is not a route the device forwards on."""

from __future__ import annotations

from tests.test_path_trace import GW, _FakeRib, _route, _src_row, _store_row, graph  # noqa: F401

from hst import path
from hst.path.addrsets import _intervals
from hst.path.gates.routing import _route_partition


def _origin(cidr):
    return {**_route(cidr, kind="ORIGINATES"), "rib": None, "next_hop_vrf": None}


def _aggregate(cidr):
    return {**_route(cidr, kind="AGGREGATE", discard="blackhole"), "rib": None, "next_hop_vrf": None}


def _row(prefix, protocol, interface=None, next_hop=None, discard=None):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "interface": interface,
        "protocol": protocol,
        "discard": discard,
        "metric": 0,
    }


def _store(rows):
    """`(lpm, overlapping)` over a list of store rows, by real prefix match."""
    import ipaddress

    def lpm(probe):
        addr = ipaddress.ip_address(probe)
        hits = [r for r in rows if addr in ipaddress.ip_network(r["prefix"])]
        if not hits:
            return []
        best = max(ipaddress.ip_network(r["prefix"]).prefixlen for r in hits)
        return [r for r in hits if ipaddress.ip_network(r["prefix"]).prefixlen == best]

    def overlapping(lo, hi, minlen, af):
        # the side store's encoding: 16 bytes, an IPv4 address v4-mapped
        lo, hi = (
            int.from_bytes(v, "big") & (2**32 - 1 if af == 4 else 2**128 - 1) if isinstance(v, bytes) else v
            for v in (lo, hi)
        )
        out = []
        for r in rows:
            net = ipaddress.ip_network(r["prefix"])
            if (
                net.version == af
                and net.prefixlen > minlen
                and int(net.network_address) <= hi
                and int(net.broadcast_address) >= lo
            ):
                out.append(r)
        return out

    return lpm, overlapping


_DEFAULT = _row("0.0.0.0/0", "static", interface="pppoe0")
# the connected row of an up LAN: the store's evidence that its writer
# records connected routes for the table at all
_UP_LAN = _row("192.168.10.0/24", "connected", interface="eth1.10")


def test_a_connected_prefix_the_observed_rib_does_not_hold_is_unconfirmed():
    origin = _origin("192.168.50.0/24")
    routes = [origin, _origin("192.168.10.0/24")]
    parts = _route_partition(
        routes, _intervals(["192.168.50.20"]), _store([_DEFAULT, _UP_LAN]), [], observed=True
    )
    assert len(parts) == 1
    winners = parts[0][1]
    assert [w["kind"] for w in winners] == ["ORIGINATES"]
    assert winners[0]["unconfirmed"] == "selects 0.0.0.0/0 via pppoe0"


def test_a_store_with_no_connected_row_at_all_keeps_every_connected_prefix_decided():
    """A RIB file whose writer records no connected rows says nothing about any connected prefix."""
    routes = [_origin("192.168.50.0/24"), _origin("192.168.10.0/24")]
    for rows in (
        [_DEFAULT],
        [_DEFAULT, _row("192.168.50.0/24", "ospf", interface="eth2", next_hop="10.0.0.2")],
    ):
        for dst in ("192.168.50.20", "192.168.10.7"):
            notes: list[str] = []
            parts = _route_partition(routes, _intervals([dst]), _store(rows), notes, observed=True)
            winners = parts[0][1]
            assert "ORIGINATES" in [w["kind"] for w in winners], (dst, rows)
            assert not [w for w in winners if w.get("unconfirmed")], (dst, rows)
            assert notes == [], (dst, rows)


def test_a_connected_prefix_the_rib_holds_by_a_next_hop_loses_the_tie():
    origin = _origin("192.168.50.0/24")
    notes: list[str] = []
    store = _store([_row("192.168.50.0/24", "ospf", interface="eth2", next_hop="10.0.0.2"), _UP_LAN])
    routes = [origin, _origin("192.168.10.0/24")]
    parts = _route_partition(routes, _intervals(["192.168.50.20"]), store, notes, observed=True)
    winners = parts[0][1]
    assert [(w["kind"], w["next_hop"]) for w in winners] == [("RIB", "10.0.0.2")]
    assert any("192.168.50.0/24: the connected prefix" in n and "not used" in n for n in notes), notes


def test_a_connected_prefix_is_authoritative_without_an_observed_rib():
    for lookup, observed in ((None, False), (_store([_DEFAULT]), False)):
        origin = _origin("192.168.50.0/24")
        parts = _route_partition([origin], _intervals(["192.168.50.20"]), lookup, [], observed=observed)
        winners = parts[0][1]
        assert [w["kind"] for w in winners] == ["ORIGINATES"]
        assert not winners[0].get("unconfirmed")


def test_a_vyos_table_with_every_interface_up_answers_from_each_confirmed_route():
    """The owner's router: VLAN LANs connected, a PPPoE default, a BGP
    route via a peer, all interfaces up so FRR lists each connected row."""
    routes = [
        _origin("192.168.10.0/24"),
        _origin("192.168.20.0/24"),
        _origin("192.0.2.0/30"),
        {**_route("10.100.0.0/16", next_hop="192.0.2.2", kind="LEARNED_ROUTE"), "rib": None},
    ]
    store = _store(
        [
            _DEFAULT,
            _row("192.168.10.0/24", "connected", interface="eth1.10"),
            _row("192.168.20.0/24", "connected", interface="eth1.20"),
            _row("192.0.2.0/30", "connected", interface="eth2"),
            _row("10.100.0.0/16", "bgp", interface="eth2", next_hop="192.0.2.2"),
        ]
    )
    expect = {
        "192.168.10.7": ("192.168.10.0/24", "ORIGINATES"),
        "192.168.20.7": ("192.168.20.0/24", "ORIGINATES"),
        "192.0.2.2": ("192.0.2.0/30", "ORIGINATES"),
        "10.100.3.3": ("10.100.0.0/16", "LEARNED_ROUTE"),
        "8.8.8.8": ("0.0.0.0/0", "RIB"),
    }
    for dst, want in expect.items():
        notes: list[str] = []
        parts = _route_partition(routes, _intervals([dst]), store, notes, observed=True)
        winners = parts[0][1]
        assert [(w["cidr"], w["kind"]) for w in winners] == [want], dst
        assert not [w for w in winners if w.get("unconfirmed")], dst
        assert notes == [], dst


def test_an_aggregate_the_observed_rib_does_not_hold_is_unconfirmed():
    """The aggregate is not originated (no contributing route), the RIB
    selects the default route; the blackhole leg must not read as settled."""
    parts = _route_partition(
        [_aggregate("10.20.0.0/16")], _intervals(["10.20.5.5"]), _store([_DEFAULT]), [], observed=True
    )
    winners = parts[0][1]
    assert [w["kind"] for w in winners] == ["AGGREGATE"]
    assert winners[0]["unconfirmed"] == "selects 0.0.0.0/0 via pppoe0"


def test_an_aggregate_with_a_contributing_route_in_the_rib_is_not_marked():
    """A contributing route inside the aggregate means the device installs it."""
    store = _store([_DEFAULT, _row("10.20.7.0/24", "bgp", interface="eth2", next_hop="192.0.2.2")])
    parts = _route_partition(
        [_aggregate("10.20.0.0/16")], _intervals(["10.20.5.5"]), store, [], observed=True
    )
    winners = parts[0][1]
    assert [w["kind"] for w in winners] == ["AGGREGATE"]
    assert not winners[0].get("unconfirmed")


def test_an_aggregate_the_rib_holds_as_a_blackhole_is_confirmed():
    aggregate = _aggregate("10.20.0.0/16")
    store = _store([_DEFAULT, _row("10.20.0.0/16", "bgp", discard="blackhole")])
    parts = _route_partition([aggregate], _intervals(["10.20.5.5"]), store, [], observed=True)
    winners = parts[0][1]
    assert [w["kind"] for w in winners] == ["AGGREGATE"]
    assert not winners[0].get("unconfirmed")


def test_the_trace_marks_an_unheld_aggregate_leg_not_confirmed(graph):  # noqa: F811
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.20.0.0/16", kind="AGGREGATE", discard="blackhole")]}
    fake_rib = _FakeRib(lpm_rows=[_store_row("0.0.0.0/0", "192.0.2.2", interface="eth3")])

    result = path.trace(None, "10.0.0.5", "10.20.5.5", gateways=[GW], rib=fake_rib)

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["cidr"] == "10.20.0.0/16" and leg["indeterminate"] is True
    assert any("the RIB selects 0.0.0.0/0 via 192.0.2.2" in w for w in result["warnings"])


def test_the_trace_marks_an_unheld_connected_leg_not_confirmed(graph):  # noqa: F811
    """The LAN interface is down: the graph keeps its ORIGINATES /24, the RIB
    selects the default route. The leg on the /24 is not confirmed."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("192.168.50.0/24", kind="ORIGINATES"),
            _route("192.168.10.0/24", kind="ORIGINATES"),
            _route("0.0.0.0/0", next_hop="192.0.2.2"),
        ]
    }
    fake_rib = _FakeRib(
        lpm_rows=[_store_row("0.0.0.0/0", "192.0.2.2", interface="eth3")],
        overlapping_rows=[_store_row("192.168.10.0/24", None, interface="eth1.10", protocol="connected")],
    )

    result = path.trace(None, "10.0.0.5", "192.168.50.20", gateways=[GW], rib=fake_rib)

    legs = [leg for leg in result["legs"] if leg["cidr"] == "192.168.50.0/24"]
    assert legs and all(leg["indeterminate"] is True for leg in legs), result["legs"]
    assert any("the RIB selects 0.0.0.0/0 via 192.0.2.2" in w for w in result["warnings"])


# --- a table mirrored from the RIB into the graph, with no side store ---------------------


def _mirror_default():
    return {**_route("0.0.0.0/0", egress="pppoe0", kind="LEARNED_ROUTE"), "rib": None}


def test_a_mirrored_table_marks_a_static_it_does_not_confirm():
    """The static's next hop is not reachable, so FRR did not install it and
    the collector folded no RIB row onto it; the mirror selects the default."""
    static = {**_route("10.50.0.0/24", next_hop="192.168.9.1"), "rib": None}
    routes = [static, _mirror_default(), _origin("192.168.10.0/24")]
    parts = _route_partition(routes, _intervals(["10.50.0.5"]), None, [], mirrored=True)
    winners = parts[0][1]
    assert [(w["cidr"], w["kind"]) for w in winners] == [("10.50.0.0/24", "STATIC_ROUTE")]
    assert winners[0]["unconfirmed"] == "selects 0.0.0.0/0 via pppoe0"


def test_a_mirrored_table_keeps_confirmed_statics_connected_and_discards_unmarked():
    routes = [
        {**_route("10.60.0.0/16", next_hop="192.168.1.2", egress="eth1"), "rib": True},
        {**_route("0.0.0.0/0", egress="wg0"), "rib": True},
        {**_route("10.70.0.0/16", discard="blackhole"), "rib": None},
        _origin("192.168.10.0/24"),
        _aggregate("10.80.0.0/16"),
        _mirror_default(),
    ]
    for dst in ("10.60.1.1", "8.8.8.8", "10.70.1.1", "192.168.10.9", "10.80.1.1"):
        parts = _route_partition(routes, _intervals([dst]), None, [], mirrored=True)
        assert parts[0][1], dst
        assert not [w for w in parts[0][1] if w.get("unconfirmed")], dst


def test_without_the_mirror_flag_an_unconfirmed_static_is_not_marked():
    static = {**_route("10.50.0.0/24", next_hop="192.168.9.1"), "rib": None}
    parts = _route_partition([static, _mirror_default()], _intervals(["10.50.0.5"]), None, [])
    assert not parts[0][1][0].get("unconfirmed")


def test_the_store_answer_takes_precedence_over_the_mirror():
    static = {**_route("10.50.0.0/24", next_hop="192.168.9.1"), "rib": None}
    store = _store([_row("10.50.0.0/24", "static", interface="eth1", next_hop="192.168.9.1"), _DEFAULT])
    parts = _route_partition([static], _intervals(["10.50.0.5"]), store, [], observed=True, mirrored=True)
    assert not parts[0][1][0].get("unconfirmed")
