# ruff: noqa: F811

import importlib

import pytest
from tests.test_path_nat import _dnat_row, _nat_row
from tests.test_path_reply import _stateful_zoned_router
from tests.test_path_trace import (  # noqa: F401
    GW,
    _route,
    _src_row,
    graph,
)

from hst import path
from hst.path.addrsets import _intervals
from hst.results.trace import leg_result

tracemod = importlib.import_module("hst.path.trace")

UPLINK = getattr(tracemod, "_EGRESS_UPLINK_QUERY", None)


def _uplinks(graph, rows):
    read_one = graph.read_one

    def answer(query, **params):
        if query == UPLINK:
            return rows.get(params["u"])
        return read_one(query, **params)

    graph.read_one = answer


def test_a_next_hop_beyond_a_collected_wan_link_is_the_estates_exit(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1")]}
    _uplinks(graph, {"if:eth0": {"default_origin": None, "link_uid": "wan:r1:eth0", "link_name": "DIA"}})

    result = path.trace(None, "10.0.0.5", "198.51.100.7", gateways=[GW])

    leg = result["legs"][0]
    assert leg["boundary"] is True and not leg["indeterminate"]
    assert not any("not held by any interface" in w for w in result["warnings"])
    assert any("beyond the collected uplink" in n and "203.0.113.1" in n for n in result["notes"])


def test_the_reply_of_an_exit_starts_on_the_uplink_interface(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1"),
            _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        ]
    }
    _uplinks(graph, {"if:eth0": {"default_origin": None, "link_uid": "wan:r1:eth0", "link_name": "DIA"}})

    result = path.trace(None, "10.0.0.5", "198.51.100.7", gateways=[GW], reply=True)

    reply = result["reply"]
    assert not reply["verdict"].startswith("reply not derived"), reply["verdict"]
    stations = [(h["stage"], h["uid"], h["note"]) for h in reply["hops"][:2]]
    assert stations == [
        ("SRC_ENDPOINT", "wan:r1:eth0", "reply origin: 198.51.100.7, outside the twin"),
        ("INGRESS_IF", "if:eth0", "reply ingress"),
    ]
    assert reply["legs"][0]["egress"] == "eth1"


@pytest.mark.parametrize(
    ("default", "src", "dst", "next_hop"),
    [
        ("0.0.0.0/0", "10.0.0.5", "198.51.100.7", "203.0.113.1"),
        ("::/0", "fd00::5", "2001:db8:ff00::7", "2001:db8:18::1"),
    ],
)
def test_a_default_out_of_an_interface_the_access_client_serves_is_an_exit(
    graph, default, src, dst, next_hop
):
    graph.sources = [_src_row(ip=src)]
    graph.routes = {"vrf:main": [_route(default, egress="eth0", next_hop=next_hop)]}
    _uplinks(graph, {"if:eth0": {"default_origin": "dhcp", "link_uid": None, "link_name": None}})
    gw = {**GW, "cidr": "fd00::/64"} if ":" in src else GW

    result = path.trace(None, src, dst, gateways=[gw])

    assert not result["legs"][0]["indeterminate"] and result["legs"][0]["boundary"] is True


def _unmarked_boundary(result):
    leg = result["forward"]["legs"][0]
    assert leg["boundary"] is True and not leg["indeterminate"] and "indeterminate_reason" not in leg
    assert any("not held by any interface" in w for w in result["forward"]["warnings"])
    assert not any("beyond the collected uplink" in n for n in result["forward"]["notes"])
    assert leg_result(leg).answer == "true"
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"


def test_an_edge_with_no_wan_link_keeps_its_boundary_answer(graph):
    """The IOS-XE / NX-OS / Check Point shape: `ip route 0.0.0.0 0.0.0.0 <ISP gateway>` out of
    an interface no collector marks as an uplink (no WanLink, no access-client default)."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="Gi0/0/0", next_hop="203.0.113.1"),
            _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        ]
    }

    result = path.trace(None, "10.0.0.5", "198.51.100.7", port=443, proto="tcp", gateways=[GW], reply=True)

    _unmarked_boundary(result)
    assert result["forward"]["legs"][0]["verdict"] == "egress via Gi0/0/0"


def test_a_specific_route_out_of_the_access_interface_with_no_wan_link_keeps_its_boundary_answer(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("198.51.100.0/24", egress="eth0", next_hop="203.0.113.1")]}
    _uplinks(graph, {"if:eth0": {"default_origin": "dhcp", "link_uid": None, "link_name": None}})

    _unmarked_boundary(path.trace(None, "10.0.0.5", "198.51.100.7", gateways=[GW], reply=True))


def test_a_default_by_another_interface_than_the_wan_link_keeps_its_boundary_answer(graph):
    """A LAN-side next hop, on a device whose WAN link is on another interface: the WAN link
    drawn for a default route is not this route's exit."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth2", next_hop="10.0.2.254")]}
    _uplinks(graph, {"if:eth0": {"default_origin": None, "link_uid": "wan:r1:eth0", "link_name": "DIA"}})

    _unmarked_boundary(path.trace(None, "10.0.0.5", "198.51.100.7", gateways=[GW], reply=True))


# --- no destination NAT rule on a recorded reply -----------------------------------------------


def _port_forward(graph):
    """r1 leaves for the internet by eth0 (an interface-only default, the
    PPPoE shape) and forwards tcp/443 arriving on eth0 to 10.0.0.20: the reply
    of a LAN host's internet flow enters on eth0."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0"),
            _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        ]
    }


def test_a_reply_is_not_matched_against_a_destination_nat_rule(graph):
    _port_forward(graph)
    # a port forward of any destination arriving on eth0 to tcp/443: the reply's
    # own destination port is not stated, so a rule walk reads it as a possible match
    graph.nat = [
        _dnat_row(
            uid="nat:dnat:10",
            in_if="eth0",
            orig_dst_raw=None,
            orig_dst_addrs=[],
            orig_dst_port="443",
            protocol="tcp",
            translation="10.0.0.20",
            xlate_dst_addrs=["10.0.0.20"],
        )
    ]

    result = path.trace(None, "10.0.0.5", "198.51.100.7", port=443, proto="tcp", gateways=[GW], reply=True)

    reply = result["reply"]
    assert not any("dNAT" in w for w in reply["warnings"]), reply["warnings"]
    assert not [h for h in reply["hops"] if h["uid"] == "nat:dnat:10"]
    assert reply["legs"][0]["egress"] == "eth1"


def test_a_destination_nat_rule_still_applies_where_the_forward_crossing_is_not_recorded(graph):
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth1", kind="ORIGINATES")]}
    graph.nat = [
        _dnat_row(
            uid="nat:dnat:10",
            in_if="eth2",
            orig_dst_raw=None,
            orig_dst_addrs=[],
            translation="10.0.0.20",
            xlate_dst_addrs=["10.0.0.20"],
        )
    ]
    terminal = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth2", "if_name": "eth2"}

    result = tracemod._walk_reply_leg(
        None,
        {},
        terminal,
        ["dev:r1"],
        {},
        _intervals(["10.0.0.5"]),
        _intervals(["10.0.0.99"]),
        None,
        max_hops=8,
    )

    assert [h["uid"] for h in result["hops"] if h["stage"] == "DNAT"] == ["nat:dnat:10"]


# --- a reply leg with no local egress -----------------------------------------------------------


def test_a_reply_leg_with_no_local_egress_is_judged_as_a_reply(graph, monkeypatch):
    """The return pair GUEST-LAN drops every new flow; the forward lan->guest
    leg through r1 was a confirmed permit, so the reply leg, routed by a next
    hop with no egress interface resolved, is admitted from session state."""
    _stateful_zoned_router(graph, monkeypatch)
    gw = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth1.40", "if_name": "eth1.40"}
    grp = {"sources": _intervals(["10.0.40.9"]), "table_uid": "vrf:main", "table_name": "main", "nat": None}
    route = {"cidr": "10.0.0.0/24", "next_hop": "10.0.40.254", "egress_uid": None, "egress_name": None}
    trail = path._Trail()
    trail.device_gate_state["dev:r1"] = {
        "policy": ["established=accept", "related=accept"],
        "permit": True,
        "credits": ["rb:lan-guest"],
    }
    leg = {"lane": 0, "blocked": False, "indeterminate": False}

    denied = tracemod._remote_zone_stage(
        None,
        trail,
        leg,
        gw,
        grp,
        route,
        _intervals(["10.0.0.5"]),
        None,
        None,
        "10.0.40.9",
        "if:eth1",
        False,
        conn_state="established",
    )

    assert denied is False and not leg["blocked"]
    assert leg["firewall"].startswith("admitted from session state")
    # a reply never writes the forward crossing's reading
    assert "gate_state" not in leg


# --- the carrier source NAT stops at an exclude rule ------------------------------------------


def test_the_carrier_source_nat_stops_at_an_exclude_rule():
    rows = [
        _nat_row(
            uid="nat:10",
            out_if="eth0",
            orig_dst_raw="198.51.100.7",
            orig_dst_addrs=["198.51.100.7"],
            exclude=True,
        ),
        _nat_row(uid="nat:100", pos=100, out_if="eth0", translation="masquerade"),
    ]
    trail, leg, carrier = path._Trail(), {"indeterminate": False}, {}

    tracemod._carrier_snat(
        trail,
        leg,
        carrier,
        rows,
        "eth0",
        "203.0.113.2",
        _intervals(["203.0.113.2"]),
        _intervals(["198.51.100.7"]),
        51820,
        "udp",
        "wg0",
    )

    assert "snat" not in carrier and not [h for h in trail.hops if h["stage"] == "CARRIER_SNAT"]
    assert not leg["indeterminate"]


def test_an_exclude_rule_that_does_not_match_leaves_the_carrier_masquerade():
    rows = [
        _nat_row(
            uid="nat:10", out_if="eth0", orig_dst_raw="192.0.2.9", orig_dst_addrs=["192.0.2.9"], exclude=True
        ),
        _nat_row(uid="nat:100", pos=100, out_if="eth0", translation="masquerade"),
    ]
    trail, leg, carrier = path._Trail(), {"indeterminate": False}, {}

    tracemod._carrier_snat(
        trail,
        leg,
        carrier,
        rows,
        "eth0",
        "203.0.113.2",
        _intervals(["203.0.113.2"]),
        _intervals(["198.51.100.7"]),
        51820,
        "udp",
        "wg0",
    )

    assert carrier["snat"] == "203.0.113.2"
    assert [h["uid"] for h in trail.hops if h["stage"] == "CARRIER_SNAT"] == ["nat:100"]


# --- a reply that stops early is not asymmetric routing ---------------------------------------

R2_TERMINAL = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth5", "if_name": "r2-eth5"}


def test_a_reply_blocked_on_its_first_device_is_incomplete_not_asymmetric(graph):
    """The forward flow crossed r1 then r2; r2 discards the reply. The reply
    did not take another path, it stopped: its devices so far ([r2]) are the
    forward path reversed up to where it stopped."""
    graph.default_tables = {"if:r2-eth5": {"uid": "vrf:r2"}}
    graph.routes = {"vrf:r2": [_route("10.0.0.0/24", discard="blackhole")]}

    result = tracemod._walk_reply_leg(
        None,
        {},
        R2_TERMINAL,
        ["dev:r1", "dev:r2"],
        {"dev:r1": {"policy": None, "permit": True}},
        _intervals(["10.0.0.5"]),
        _intervals(["10.99.0.7"]),
        None,
        max_hops=8,
    )

    assert result["legs"][0]["blocked"] is True
    assert result["asymmetric"] is False
    notes = " ".join(result["comparison_notes"])
    assert "asymmetric routing" not in notes and "does not cross dev:r1" not in notes
    assert "stops on dev:r2" in notes


def test_a_reply_that_leaves_by_another_device_is_still_asymmetric(graph):
    graph.default_tables = {"if:r2-eth5": {"uid": "vrf:r2"}}
    graph.routes = {"vrf:r2": [_route("10.0.0.0/24", egress="r2-eth9", kind="ORIGINATES")]}

    result = tracemod._walk_reply_leg(
        None,
        {},
        R2_TERMINAL,
        ["dev:r1", "dev:r2"],
        {},
        _intervals(["10.0.0.5"]),
        _intervals(["10.99.0.7"]),
        None,
        max_hops=8,
    )

    assert result["asymmetric"] is True


def test_an_undecided_reply_that_went_home_another_way_is_still_asymmetric(graph):
    """r2's route home leaves by r2-eth9 and is derived (undecided): the reply reached its
    end another way, it did not stop on r2."""
    graph.default_tables = {"if:r2-eth5": {"uid": "vrf:r2"}}
    graph.routes = {"vrf:r2": [_route("10.0.0.0/24", egress="r2-eth9", derived=True)]}

    result = tracemod._walk_reply_leg(
        None,
        {},
        R2_TERMINAL,
        ["dev:r1", "dev:r2"],
        {"dev:r1": {"policy": None, "permit": True}},
        _intervals(["10.0.0.5"]),
        _intervals(["10.99.0.7"]),
        None,
        max_hops=8,
    )

    assert result["legs"][0]["indeterminate"] is True
    assert result["asymmetric"] is True
    notes = " ".join(result["comparison_notes"])
    assert "asymmetric routing" in notes and "does not cross dev:r1" in notes


# --- the host half of a split set -----------------------------------------------------------


def test_the_host_half_of_a_split_set_reads_as_the_hosts_alone(graph):
    from tests.test_path_trace import GW_GUEST, GW_LAN, _zoned_router

    _zoned_router(graph)
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.gates = [
        {"uid": "rb:lan-guest", "name": "LAN-GUEST", "kind": "FwRulebase"},
        {"uid": "rb:guest-lan", "name": "GUEST-LAN", "kind": "FwRulebase"},
    ]
    graph.dev_addrs = {
        "dev:r1": [{"ip": "10.0.0.1", "ip_uid": "ip:10.0.0.1", "if_uid": "if:eth1", "if_name": "eth1"}]
    }

    (alone,) = path.trace(None, "10.0.0.5", "10.0.0.2/31", port=22, proto="tcp", gateways=[GW_LAN, GW_GUEST])[
        "legs"
    ]
    split = path.trace(None, "10.0.0.5", "10.0.0.0/30", port=22, proto="tcp", gateways=[GW_LAN, GW_GUEST])
    hosts, own = split["legs"]

    assert own["router_local"] and own["dst_label"] == "10.0.0.1"
    assert not alone["indeterminate"]
    assert {k: v for k, v in hosts.items() if k != "dst_label"} == {
        k: v for k, v in alone.items() if k != "dst_label"
    }
    assert len(split["warnings"]) == len(set(split["warnings"]))


# --- the WAN link a default route leaves by -------------------------------------------------


def _oslo_two_links():
    """The Oslo router with a second WanLink, on eth1.20, whose uid sorts before the
    eth0 link's: the device's first link by uid is not the one a route leaves by."""
    from pathlib import Path

    from hst.core.fixtures import load_fixture
    from hst.core.model import NodeRecord, RelRecord

    estate = load_fixture(Path(__file__).resolve().parent.parent / "fixtures/demo-enterprise/estate-v3.yaml")
    dev, link = "dev:osl01-vyos-01", "wan:osl01-vyos-01:aaa"
    estate.nodes.append(NodeRecord(label="WanLink", uid=link, props={"kind": "dia", "name": "OTHER"}))
    estate.rels += [
        RelRecord(type="HAS_LINK", start_label="Device", start_uid=dev, end_label="WanLink", end_uid=link),
        RelRecord(
            type="ON",
            start_label="WanLink",
            start_uid=link,
            end_label="Interface",
            end_uid=f"{dev}/if/eth1.20",
        ),
    ]
    return estate


def _links(result):
    return [h["label"] for h in result["hops"] if h["kind"] == "WanLink"]


def test_a_default_route_draws_the_wan_link_on_its_own_egress():
    from tests.support.demo_trace_graph import TraceGraph

    estate = _oslo_two_links()
    for src, dst in (("10.18.10.21", "192.0.2.180"), ("fd00:18:10::21", "2001:db8:ff00::180")):
        graph = TraceGraph(estate)
        result = path.trace(graph, src, dst, port=443, proto="tcp", reply=True)
        assert graph.refused == []
        assert _links(result["forward"]) == ["WAN Fibrenta DIA"]
        # the reply starts on that link, not on the other one
        assert result["reply"]["hops"][0]["label"] == "WAN Fibrenta DIA"


def test_a_tunnel_tables_default_draws_no_wan_link_of_its_own():
    """The policy-routed host's default in table 100 leaves by wg0, which no WanLink is
    ON: no WAN hop is drawn for it."""
    from tests.support.demo_trace_graph import TraceGraph

    graph = TraceGraph(_oslo_two_links())
    result = path.trace(graph, "10.18.10.50", "192.0.2.180", port=443, proto="tcp")

    assert graph.refused == []
    assert result["legs"][0]["egress"] == "wg0"
    assert _links(result) == []


# --- a late L2 mark never opens a decided false -----------------------------------------------


def _drop_all(graph):
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    from tests.test_path_trace import _rule

    graph.rules = [_rule(pos=1, action="drop")]


def _mismatch_chain(graph):
    from tests.test_path_trace import _script_l2_trunk

    graph.iface_segments[GW["if_uid"]] = ["bd:vlan:fab0:10"]
    port = {"is_port": True, "lag": None}
    _script_l2_trunk(
        graph,
        chain=[
            {**port, "uid": "port:sw1-p24", "label": "Port 24", "dev": "sw1", "bds": ["bd:vlan:fab0:10"]},
            {"uid": "dev:sw2", "is_port": False, "label": "sw2", "dev": None, "lag": None, "bds": []},
            {**port, "uid": "port:sw2-p1", "label": "Uplink", "dev": "sw2", "bds": ["bd:vlan:fab0:99"]},
        ],
    )


def test_a_blocked_leg_with_an_l2_jump_stays_a_decided_block(graph):
    from tests.test_path_trace import _l2_source

    graph.sources = [_l2_source()]
    _drop_all(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    leg = result["legs"][0]
    assert any("drawn as a jump" in w for w in result["warnings"])
    assert leg["blocked"] and not leg["indeterminate"] and leg["boundary"] is True
    assert leg_result(leg).answer == "false"


def test_a_no_route_leg_with_an_l2_jump_stays_no_route(graph):
    from tests.test_path_trace import _l2_source

    graph.sources = [_l2_source()]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    leg = result["legs"][0]
    assert leg["verdict"] == "no route found" and not leg["indeterminate"]
    assert leg_result(leg).answer == "false"


def test_a_blocked_leg_with_a_source_side_mismatch_stays_undecided(graph):
    from tests.test_path_trace import _l2_source

    graph.sources = [_l2_source()]
    _mismatch_chain(graph)
    _drop_all(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    leg = result["legs"][0]
    assert any("bd:vlan:fab0:99" in w for w in result["warnings"])
    assert leg["blocked"] and leg["indeterminate"] is True
    assert leg_result(leg).answer == "open"
    assert not [k for k in leg if k.startswith("_")]


def test_a_no_route_leg_with_a_source_side_mismatch_stays_undecided(graph):
    """The table a route is looked up in is the ingress interface's: a contradicted
    ingress leaves "no route" unsound too."""
    from tests.test_path_trace import _l2_source

    graph.sources = [_l2_source()]
    _mismatch_chain(graph)

    leg = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])["legs"][0]

    assert leg["verdict"] == "no route found" and leg["indeterminate"] is True


def test_a_blocked_leg_with_a_destination_side_mismatch_stays_a_decided_block(graph):
    """The iot_lan shape of the live router: blocked by the zone rule set, and the egress
    interface's L2 stretch to the destination carries another bridge domain. That mark
    comes after the forwarding decision: the block is sound, the warning stays."""
    from tests.test_path_trace import GW_GUEST, GW_LAN, _l2_dst, _zoned_router

    _zoned_router(graph)
    graph.sources = [_src_row(ip="10.0.40.9")]
    graph.sources_by_ip["10.0.0.77"] = [_l2_dst()]
    graph.iface_segments[GW_LAN["if_uid"]] = ["bd:vlan:fab0:10"]
    port = {"is_port": True, "lag": None}
    graph.l2_chains[(GW_LAN["if_uid"], "dev:sw2")] = {
        "chain": [
            {**port, "uid": "port:sw2-p2", "label": "Uplink2", "dev": "sw2", "bds": ["bd:vlan:fab0:99"]}
        ]
    }

    result = path.trace(None, "10.0.40.9", "10.0.0.77", port=443, proto="tcp", gateways=[GW_GUEST, GW_LAN])

    leg = result["legs"][0]
    assert any("Uplink2" in w and "bd:vlan:fab0:99" in w for w in result["warnings"]), result["warnings"]
    assert leg["blocked"] and not leg["indeterminate"] and not result["indeterminate"]
    assert leg_result(leg).answer == "false"


def test_a_permitted_leg_with_a_vlan_mismatch_stays_undecided(graph):
    from tests.test_path_trace import _l2_source

    graph.sources = [_l2_source()]
    _mismatch_chain(graph)
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    leg = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])["legs"][0]

    assert not leg["blocked"] and leg["indeterminate"] is True


# --- routes that keep their boundary answer ----------------------------------------------------


def test_a_specific_route_by_a_wan_link_keeps_its_boundary_answer(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("198.51.100.0/24", egress="eth0", next_hop="203.0.113.1")]}
    _uplinks(
        graph,
        {
            "if:eth0": {
                "default_origin": None,
                "link_uid": "wan:r1:eth0",
                "link_name": "DIA",
                "link_kind": "dia",
            }
        },
    )

    _unmarked_boundary(path.trace(None, "10.0.0.5", "198.51.100.7", gateways=[GW], reply=True))


def test_a_default_by_an_mpls_link_keeps_its_boundary_answer(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1")]}
    _uplinks(
        graph,
        {
            "if:eth0": {
                "default_origin": None,
                "link_uid": "wan:r1:eth0",
                "link_name": "MPLS",
                "link_kind": "mpls",
            }
        },
    )

    _unmarked_boundary(path.trace(None, "10.0.0.5", "198.51.100.7", gateways=[GW], reply=True))


def test_an_ipv6_default_out_of_an_ipv4_access_client_interface_keeps_its_boundary_answer(graph):
    graph.sources = [_src_row(ip="fd00::5")]
    graph.routes = {"vrf:main": [_route("::/0", egress="eth0", next_hop="2001:db8:18::1")]}
    _uplinks(graph, {"if:eth0": {"default_origin": "dhcp", "link_uid": None, "link_name": None}})

    _unmarked_boundary(
        path.trace(None, "fd00::5", "2001:db8:ff00::7", gateways=[{**GW, "cidr": "fd00::/64"}], reply=True)
    )


# --- the reply reads the final state of the forward leg ----------------------------------------


def test_a_reply_is_not_admitted_on_a_forward_leg_that_ended_undecided(graph, monkeypatch):
    """r1's forward reading was a confirmed permit, but the forward leg ended undecided (a
    gate the walk did not evaluate): the reply leg is not admitted from session state."""
    _stateful_zoned_router(graph, monkeypatch)
    gw = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth1.40", "if_name": "eth1.40"}
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth1", kind="ORIGINATES")]}
    state = {"policy": ["established=accept", "related=accept"], "permit": True, "credits": ["rb:lan-guest"]}
    forward_leg = {"indeterminate": True, "indeterminate_reason": "1 gate(s) not evaluated"}

    result = tracemod._walk_reply_leg(
        None,
        forward_leg,
        {**gw, "if_name": "eth1.40"},
        ["dev:r1"],
        {"dev:r1": state},
        _intervals(["10.0.0.5"]),
        _intervals(["10.0.40.9"]),
        None,
        max_hops=8,
    )

    leg = result["legs"][0]
    assert not leg["firewall"].startswith("admitted from session state"), leg["firewall"]
    assert leg["indeterminate"] is True and not leg["blocked"]
    assert result["indeterminate"] is True


def test_a_reply_on_a_confirmed_forward_leg_is_admitted(graph, monkeypatch):
    _stateful_zoned_router(graph, monkeypatch)
    gw = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth1.40", "if_name": "eth1.40"}
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth1", kind="ORIGINATES")]}
    state = {"policy": ["established=accept", "related=accept"], "permit": True, "credits": ["rb:lan-guest"]}

    result = tracemod._walk_reply_leg(
        None,
        {"indeterminate": False},
        gw,
        ["dev:r1"],
        {"dev:r1": state},
        _intervals(["10.0.0.5"]),
        _intervals(["10.0.40.9"]),
        None,
        max_hops=8,
    )

    assert result["legs"][0]["firewall"].startswith("admitted from session state")


def test_a_blocked_leg_with_an_l2_jump_is_not_held_to_the_destination_context(graph):
    from tests.test_path_trace import _l2_source

    graph.sources = [_l2_source()]
    _drop_all(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.0/24", gateways=[GW], dst_context="vrf:elsewhere")

    leg = result["legs"][0]
    assert leg["blocked"] and not leg["indeterminate"]
    assert not any("requested destination context" in w for w in result["warnings"])
