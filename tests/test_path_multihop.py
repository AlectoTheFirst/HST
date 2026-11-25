"""The engine follows next-hops through every router the twin knows."""

# ruff: noqa: F811

from tests.test_path_nat import _nat_row
from tests.test_path_trace import GW, FakeGraph, _route, _rule, _src_row, graph  # noqa: F401

from hst import path

R2_IF = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth0", "if_name": "r2-eth0"}


def _two_routers(graph):
    """r1 (the gateway) reaches 10.99.0.0/24 via r2 at 10.0.12.2; r2 serves it
    on a connected interface. Route tables are split per ingress interface."""
    graph.sources = [_src_row()]
    graph.default_tables = {
        GW["if_uid"]: {"uid": "vrf:r1"},
        R2_IF["if_uid"]: {"uid": "vrf:r2"},
    }
    graph.routes = {
        "vrf:r1": [_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2")],
        "vrf:r2": [_route("10.99.0.0/24", egress="r2-eth5")],
    }
    graph.next_hop_devs = {"10.0.12.2": R2_IF}
    # both tables are recorded global tables, so a single owner in r2's table
    # is an ordinary hop (`_single_owner_scope`)
    graph.contexts = {
        "vrf:r1": {"name": "default", "is_global": True},
        "vrf:r2": {"name": "default", "is_global": True},
    }


def test_the_trace_walks_through_the_next_hop_router(graph):
    _two_routers(graph)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["verdict"] == "egress via r2-eth5"
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "r2") in kinds
    assert ("Interface", "r2-eth5") in kinds
    # the verdict names r2's winning route, not r1's hand-off
    assert "next-hop" not in result["verdict"]


def test_a_routing_loop_is_named_not_followed(graph):
    _two_routers(graph)
    # r2 routes the destination back to r1
    graph.routes["vrf:r2"] = [_route("10.99.0.0/24", egress="r2-eth0", next_hop="10.0.12.1")]
    graph.next_hop_devs["10.0.12.1"] = {
        "dev_uid": "dev:r1",
        "dev_name": "r1",
        "if_uid": "if:eth0",
        "if_name": "eth0",
    }
    # both of r1's interfaces are in its one table, so the return is a loop
    graph.default_tables["if:eth0"] = {"uid": "vrf:r1"}
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    assert any("routing loop" in n for n in result["notes"])


def test_a_return_to_the_same_device_in_another_vrf_is_not_a_loop(graph):
    graph.sources = [_src_row()]
    graph.default_tables = {
        GW["if_uid"]: {"uid": "vrf:r1-A"},
        "if:fw-a": {"uid": "vrf:fw"},
        "if:b-fw": {"uid": "vrf:r1-B"},
    }
    graph.routes = {
        "vrf:r1-A": [_route("10.99.0.0/24", egress="a-fw", next_hop="10.0.1.2")],
        "vrf:fw": [_route("10.99.0.0/24", egress="fw-b", next_hop="10.0.2.1")],
        "vrf:r1-B": [_route("10.99.0.0/24", egress="b-lan", kind="ORIGINATES")],
    }
    graph.next_hop_devs = {
        "10.0.1.2": {"dev_uid": "dev:fw", "dev_name": "fw", "if_uid": "if:fw-a", "if_name": "fw-a"},
        "10.0.2.1": {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:b-fw", "if_name": "b-fw"},
    }

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert not any("routing loop" in w for w in result["warnings"])
    assert not result["indeterminate"]
    assert result["legs"][0]["verdict"] == "egress via b-lan"


def test_a_return_to_the_same_vrf_through_a_firewall_is_a_loop(graph):
    """The same layout with the firewall routing back into VRF A."""
    graph.sources = [_src_row()]
    graph.default_tables = {
        GW["if_uid"]: {"uid": "vrf:r1-A"},
        "if:fw-a": {"uid": "vrf:fw"},
        "if:a-fw": {"uid": "vrf:r1-A"},
    }
    graph.routes = {
        "vrf:r1-A": [_route("10.99.0.0/24", egress="a-fw", next_hop="10.0.1.2")],
        "vrf:fw": [_route("10.99.0.0/24", egress="fw-a", next_hop="10.0.1.1")],
    }
    graph.next_hop_devs = {
        "10.0.1.2": {"dev_uid": "dev:fw", "dev_name": "fw", "if_uid": "if:fw-a", "if_name": "fw-a"},
        "10.0.1.1": {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:a-fw", "if_name": "a-fw"},
    }

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert result["indeterminate"]
    assert any("returns to r1: routing loop" in w for w in result["warnings"])


def test_snat_on_the_first_router_feeds_the_second(graph):
    _two_routers(graph)
    graph.nat_by_dev = {
        "dev:r1": [
            _nat_row(
                translation="10.0.12.1",
                xlate_src_addrs=["10.0.12.1"],
                out_if="eth0",
            )
        ],
        "dev:r2": [],
    }
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    leg = result["legs"][0]
    assert leg["verdict"] == "egress via r2-eth5"
    assert leg["snat"] == [{"sources": ["10.0.0.5/32"], "to": "10.0.12.1", "rule_uid": "nat:r10"}]


def test_a_masquerade_with_no_collected_address_does_not_claim_a_source_on_r2(graph):
    """r1 masquerades via an interface whose address was not collected."""
    _two_routers(graph)
    graph.nat_by_dev = {
        "dev:r1": [_nat_row(translation="masquerade", out_if="eth0")],
        "dev:r2": [],
    }
    graph.rb = {
        "rb_uid": "rb:fwd",
        "rb_name": "ipv4-forward",
        "vendor": "vyos",
        "default_action": "drop",
        "approximate": False,
    }
    graph.rules = [_rule(uid="fw:10", pos=10, src_any=False, src_cidrs=["10.0.0.0/24"])]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert result["indeterminate"] and leg["indeterminate"]
    assert any("whose address was not collected" in w for w in result["warnings"])
    assert "matches part of the range only" in leg["firewall"]


def test_a_drop_downstream_of_an_unknown_masquerade_source_blocks_and_stays_undecided(graph):
    """A partial match keeps a deny a deny."""
    _two_routers(graph)
    graph.nat_by_dev = {
        "dev:r1": [_nat_row(translation="masquerade", out_if="eth0")],
        "dev:r2": [],
    }
    graph.rb = {
        "rb_uid": "rb:fwd",
        "rb_name": "ipv4-forward",
        "vendor": "vyos",
        "default_action": "accept",
        "approximate": False,
    }
    # scoped to a source r1 itself never carries, so only the leg downstream of
    # the masquerade can match it
    graph.rules = [_rule(uid="fw:20", pos=20, action="drop", src_any=False, src_cidrs=["203.0.113.0/24"])]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] and leg["indeterminate"]
    assert "drop by rule 20" in leg["firewall"]
    assert "matches part of the range only" in leg["firewall"]
    assert any("whose address was not collected" in w for w in result["warnings"])


def test_dnat_on_the_second_router_lands_on_the_final_leg(graph):
    _two_routers(graph)
    graph.routes["vrf:r1"] = [_route("203.0.113.0/24", egress="eth0", next_hop="10.0.12.2")]
    graph.routes["vrf:r2"] = [_route("10.99.0.0/24", egress="r2-eth5")]
    graph.nat_by_dev = {
        "dev:r1": [],
        "dev:r2": [
            _nat_row(
                rb_uid="rb:r2dnat",
                rb_name="nat-destination",
                uid="r2:dnat:1",
                kind="dnat",
                orig_dst_raw="203.0.113.10",
                orig_dst_addrs=["203.0.113.10"],
                translation="10.99.0.7",
                xlate_dst_addrs=["10.99.0.7"],
            )
        ],
    }
    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])
    leg = result["legs"][0]
    assert leg["dnat"][0]["to"] == ["10.99.0.7/32"]
    assert leg["verdict"] == "egress via r2-eth5"


def test_a_double_dnat_keeps_both_translations_on_the_leg(graph):
    """The leg records both translations, upstream first."""
    _two_routers(graph)
    graph.routes["vrf:r1"] = [_route("10.50.0.0/24", egress="eth0", next_hop="10.0.12.2")]
    graph.routes["vrf:r2"] = [_route("10.99.0.0/24", egress="r2-eth5")]
    graph.nat_by_dev = {
        "dev:r1": [
            _nat_row(
                rb_uid="rb:r1dnat",
                rb_name="r1-nat-destination",
                uid="r1:dnat:1",
                kind="dnat",
                orig_dst_raw="203.0.113.10",
                orig_dst_addrs=["203.0.113.10"],
                translation="10.50.0.7",
                xlate_dst_addrs=["10.50.0.7"],
            )
        ],
        "dev:r2": [
            _nat_row(
                rb_uid="rb:r2dnat",
                rb_name="r2-nat-destination",
                uid="r2:dnat:1",
                kind="dnat",
                orig_dst_raw="10.50.0.7",
                orig_dst_addrs=["10.50.0.7"],
                translation="10.99.0.7",
                xlate_dst_addrs=["10.99.0.7"],
            )
        ],
    }
    # both boxes are Check Point gateways, so each one's policy is evaluated on
    # the destination as it arrived at that box
    graph.rb = {
        "rb_uid": "rb:cp",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "accept",
        "approximate": False,
    }
    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])

    leg = result["legs"][0]
    assert leg["dnat"] == [
        {"to": ["10.50.0.7/32"], "port": None, "rule_uid": "r1:dnat:1", "filter_view": "original"},
        {"to": ["10.99.0.7/32"], "port": None, "rule_uid": "r2:dnat:1", "filter_view": "original"},
    ]
    # The leg-level key is the view of the device that decided this leg.
    assert leg["filter_view"] == "original"
    assert leg["verdict"] == "egress via r2-eth5"


def test_a_double_dnat_pins_the_duplicate_notes_on_the_queried_address(graph):
    """The queried address, 203.0.113.10, exists twice in the landing context."""
    _two_routers(graph)
    graph.routes["vrf:r1"] = [_route("10.50.0.0/24", egress="eth0", next_hop="10.0.12.2")]
    graph.routes["vrf:r2"] = [_route("10.99.0.0/24", egress="r2-eth5", kind="ORIGINATES")]
    graph.nat_by_dev = {
        "dev:r1": [
            _nat_row(
                rb_uid="rb:r1dnat",
                rb_name="r1-nat-destination",
                uid="r1:dnat:1",
                kind="dnat",
                orig_dst_raw="203.0.113.10",
                orig_dst_addrs=["203.0.113.10"],
                translation="10.50.0.7",
                xlate_dst_addrs=["10.50.0.7"],
            )
        ],
        "dev:r2": [
            _nat_row(
                rb_uid="rb:r2dnat",
                rb_name="r2-nat-destination",
                uid="r2:dnat:1",
                kind="dnat",
                orig_dst_raw="10.50.0.7",
                orig_dst_addrs=["10.50.0.7"],
                translation="10.99.0.7",
                xlate_dst_addrs=["10.99.0.7"],
            )
        ],
    }
    graph.sources_by_ip["10.99.0.7"] = [_src_row(ip="10.99.0.7") | {"ep_uid": "ep:web", "ep_name": "web-1"}]
    graph.sources_by_ip["203.0.113.10"] = [
        _src_row(ip="203.0.113.10"),
        _src_row(dom="lab", ip="203.0.113.10"),
    ]
    graph.dst_instances["203.0.113.10"] = [
        {"uid": "ip:home:203.0.113.10", "anchor": None, "l3dom": "home"},
        {"uid": "ip:lab:203.0.113.10", "anchor": None, "l3dom": "lab"},
    ]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW])

    dupes = [n for n in result["notes"] if "also exists" in n]
    # the instance this lane landed on is not reported as another one
    assert not any("also exists in home" in n for n in dupes)
    # a different instance is reported
    assert any("also exists in lab" in n for n in dupes)


# The same transit address is owned in a second, isolated forwarding context.
RX_IF = {
    "dev_uid": "dev:a-rx",
    "dev_name": "rx",
    "if_uid": "if:rx-e0",
    "if_name": "rx-e0",
    "anchor": "vrf:rx",
    "l3dom": "lab",
}


def _duplicate_next_hop(graph):
    _two_routers(graph)
    graph.next_hop_devs["10.0.12.2"] = [
        RX_IF,
        {**R2_IF, "anchor": "vrf:r2", "l3dom": "home"},
    ]


def test_a_duplicate_next_hop_resolves_through_the_shared_routing_domain(graph):
    """r1's table and r2's context are members of one RoutingDomain; the trace
    must walk r2, not the other estate's router that sorts first."""
    _duplicate_next_hop(graph)
    graph.domain_mates = {"vrf:r1": ["vrf:r2"]}
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    leg = result["legs"][0]
    assert leg["verdict"] == "egress via r2-eth5"
    assert not leg["indeterminate"]
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "r2") in kinds
    assert ("Device", "rx") not in kinds


def test_a_duplicate_next_hop_with_no_tie_to_the_trace_fails_closed(graph):
    _duplicate_next_hop(graph)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    assert any("next hop 10.0.12.2 is owned in 2 forwarding contexts" in w for w in result["warnings"])
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "rx") not in kinds
    assert ("Device", "r2") not in kinds


def test_a_duplicate_next_hop_with_unanchored_rows_narrows_by_l3dom(graph):
    """Owner rows with no anchor carry only l3dom scope strings."""
    _two_routers(graph)
    graph.next_hop_devs["10.0.12.2"] = [
        {**RX_IF, "anchor": None},
        {**R2_IF, "anchor": None, "l3dom": "home"},
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"


FWB_IF = {
    "dev_uid": "dev:fw-b",
    "dev_name": "fw-b",
    "if_uid": "if:fwb-in",
    "if_name": "fwb-in",
    "anchor": "vrf:fw-b:B",
    "l3dom": "site1:B",
}


def _single_foreign_owner(graph, here=("A", False), there=("B", False)):
    """r1's table routes 10.9.0.0/16 via 192.168.5.2, and the only interface
    in the graph holding that address is fw-b's, in another context."""
    graph.sources = [_src_row()]
    graph.default_tables = {GW["if_uid"]: {"uid": "vrf:r1:A"}, "if:fwb-in": {"uid": "vrf:fw-b:B"}}
    graph.routes = {
        "vrf:r1:A": [_route("10.9.0.0/16", egress="eth0", next_hop="192.168.5.2")],
        "vrf:fw-b:B": [_route("10.9.0.0/16", egress="fwb-out", kind="ORIGINATES")],
    }
    graph.next_hop_devs = {"192.168.5.2": FWB_IF}
    graph.contexts = {
        "vrf:r1:A": {"name": here[0], "is_global": here[1]},
        "vrf:fw-b:B": {"name": there[0], "is_global": there[1]},
    }


def test_a_single_owner_in_an_unrelated_vrf_stops_the_trace(graph):
    """The VRF A neighbour is not collected."""
    _single_foreign_owner(graph)

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    leg = result["legs"][0]
    assert result["indeterminate"] and leg["indeterminate"]
    assert leg["verdict"] != "egress via fwb-out"
    assert not [h for h in result["hops"] if h["uid"] == "dev:fw-b"]
    assert any("held only by fw-b in VRF B, which is not VRF A" in w for w in result["warnings"])


def test_a_single_owner_in_a_vrf_of_the_same_routing_domain_is_followed(graph):
    _single_foreign_owner(graph)
    graph.domain_mates = {"vrf:r1:A": ["vrf:fw-b:B"]}

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via fwb-out"
    assert not result["indeterminate"]


def test_a_single_owner_in_a_vrf_holding_the_same_resolved_domain_is_followed(graph):
    """A collector that declares no RoutingDomain stamps the routing domain on every address and prefix."""
    _single_foreign_owner(graph)
    graph.contexts["vrf:r1:A"]["l3doms"] = ["corp"]
    graph.contexts["vrf:fw-b:B"]["l3doms"] = ["corp"]

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via fwb-out"
    assert not result["indeterminate"]


def test_a_single_owner_in_a_vrf_of_another_resolved_domain_stops(graph):
    _single_foreign_owner(graph)
    graph.contexts["vrf:r1:A"]["l3doms"] = ["corp"]
    graph.contexts["vrf:fw-b:B"]["l3doms"] = ["guest"]

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["indeterminate"] and result["legs"][0]["verdict"] != "egress via fwb-out"


def test_a_single_owner_in_the_exporting_vrf_of_a_leaked_route_is_followed(graph):
    """The route in VRF A is leaked from r1's VRF B; fw-b holds the next hop
    in VRF B too, so the owner is in the table the next hop resolves in."""
    _single_foreign_owner(graph)
    graph.routes["vrf:r1:A"] = [
        {**_route("10.9.0.0/16", egress="eth0", next_hop="192.168.5.2"), "next_hop_vrf": "vrf:r1:B"}
    ]
    graph.contexts["vrf:r1:B"] = {"name": "B", "is_global": False}

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via fwb-out"
    assert not result["indeterminate"]
    assert not [w for w in result["warnings"] if "held only by" in w]


def test_a_single_owner_outside_the_exporting_vrf_of_a_leaked_route_stops_the_trace(graph):
    """The route in VRF A is leaked from VRF LEAK."""
    _single_foreign_owner(graph)
    graph.routes["vrf:r1:A"] = [
        {**_route("10.9.0.0/16", egress="eth0", next_hop="192.168.5.2"), "next_hop_vrf": "vrf:r1:LEAK"}
    ]
    graph.contexts["vrf:r1:LEAK"] = {"name": "LEAK", "is_global": False}

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["indeterminate"] and result["legs"][0]["indeterminate"]
    assert result["legs"][0]["verdict"] != "egress via fwb-out"
    assert not [h for h in result["hops"] if h["uid"] == "dev:fw-b"]
    assert any(
        "held only by fw-b in VRF B, which is not the VRF LEAK the route is leaked from" in w
        for w in result["warnings"]
    )


def test_a_single_owner_under_an_unrecorded_anchor_is_followed_but_undecided(graph):
    """Manual, Nautobot and APIC addressing anchor an address to a source
    scope, not a VrfInstance: nothing shows the owner shares the route's
    routing domain, so the hop is drawn and the leg is not confirmed."""
    _single_foreign_owner(graph)
    graph.next_hop_devs = {"192.168.5.2": {**FWB_IF, "anchor": "src:nautobot"}}
    graph.default_tables["if:fwb-in"] = {"uid": "vrf:fw-b:B"}

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    leg = result["legs"][0]
    assert result["indeterminate"] and leg["indeterminate"]
    assert any(
        "held only by fw-b under src:nautobot" in w
        and "src:nautobot is not a recorded forwarding context" in w
        for w in result["warnings"]
    )


def test_a_single_owner_in_another_sites_global_table_is_followed(graph):
    """Global tables of two sites share no declared domain (the scope is the
    site), and the hop between them is an ordinary one."""
    _single_foreign_owner(graph, here=("default", True), there=("main", True))

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via fwb-out"
    assert not result["indeterminate"]


def test_a_single_owner_in_a_same_named_vrf_under_strict_grouping_is_followed(graph):
    """Strict grouping gives each device's VRF its own domain, so a VRF handed
    from device to device shares none; the same VRF name is the evidence."""
    _single_foreign_owner(graph, here=("A", False), there=("A", False))

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via fwb-out"
    assert not result["indeterminate"]


def test_a_single_owner_in_a_global_table_from_a_vrf_is_followed_but_undecided(graph):
    _single_foreign_owner(graph, here=("A", False), there=("default", True))

    result = path.trace(None, "10.0.0.5", "10.9.1.1", gateways=[GW])

    leg = result["legs"][0]
    assert leg["verdict"] == "egress via fwb-out"
    assert result["indeterminate"] and leg["indeterminate"]
    assert any(
        "held only by fw-b in table default, while the route is in table A" in w for w in result["warnings"]
    )


def test_an_fhrp_pair_owning_the_next_hop_in_one_context_is_not_ambiguous(graph):
    """The lowest device uid answers."""
    _two_routers(graph)
    # r2b routes in the context it shares with r2, so both owners answer alike
    graph.default_tables["if:r2b-e0"] = {"uid": "vrf:r2"}
    graph.next_hop_devs["10.0.12.2"] = [
        {**R2_IF, "anchor": "vrf:r2"},
        {
            "dev_uid": "dev:zz-r2b",
            "dev_name": "r2b",
            "if_uid": "if:r2b-e0",
            "if_name": "r2b-e0",
            "anchor": "vrf:r2",
        },
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result.get("indeterminate")
    # the tie is named the way _pick_gateway names its own
    assert any("2 interfaces hold next hop 10.0.12.2" in n for n in result["notes"])
    assert any("traced via r2 r2-eth0 (lowest uid)" in n for n in result["notes"])


def test_the_domain_mates_query_counts_only_declared_membership():
    """Rung 2 does not use rt-component MEMBER_OF edges for a next-hop pick."""
    assert "coalesce(m1.basis, 'declared') = 'declared'" in path._NEXT_HOP_DOMAIN_QUERY
    assert "coalesce(m2.basis, 'declared') = 'declared'" in path._NEXT_HOP_DOMAIN_QUERY


def test_the_domain_mates_query_reads_realizes_l3domain_ties():
    q = path._NEXT_HOP_DOMAIN_QUERY
    assert "UNION" in q
    assert "REALIZES]->(ld:L3Domain)" in q


def test_a_duplicate_next_hop_under_an_anchored_gateway_narrows_unanchored_rows_by_l3dom(graph):
    """Rung 3 compares a vrf uid against l3dom strings and does not match."""
    _two_routers(graph)
    graph.next_hop_devs["10.0.12.2"] = [
        {**RX_IF, "anchor": None},
        {**R2_IF, "anchor": None, "l3dom": "home"},
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[{**GW, "anchor": "vrf:r1"}])
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result.get("indeterminate")


def test_mixed_anchored_and_unanchored_owners_fail_closed(graph):
    """A row with no anchor is invisible to rung 2."""
    _two_routers(graph)
    graph.next_hop_devs["10.0.12.2"] = [
        {**RX_IF, "anchor": None, "l3dom": "home"},
        {**R2_IF, "anchor": "vrf:r2", "l3dom": "home"},
    ]
    graph.domain_mates = {"vrf:r1": ["vrf:r2"]}
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    assert any("anchored rows with unanchored rows" in w for w in result["warnings"])


def test_a_rung_two_tie_names_the_estate_duplicate_not_a_missing_tie(graph):
    """Both owners share a RoutingDomain with the trace's table."""
    _two_routers(graph)
    graph.next_hop_devs["10.0.12.2"] = [
        {**RX_IF, "anchor": "vrf:rx", "l3dom": "prod"},
        {**R2_IF, "anchor": "vrf:r2", "l3dom": "prod"},
    ]
    graph.domain_mates = {"vrf:r1": ["vrf:rx", "vrf:r2"]}
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    w = next(w for w in result["warnings"] if "next hop 10.0.12.2" in w)
    assert "owned in 2 forwarding contexts (prod, prod;" in w
    assert "duplicated inside the estate" in w
    assert "nothing ties" not in w


def test_a_cross_context_hop_rescopes_the_delivery_leg(graph):
    """Delivery is scoped by the context the trace entered."""
    _duplicate_next_hop(graph)
    graph.domain_mates = {"vrf:r1": ["vrf:r2"]}
    graph.routes["vrf:r2"] = [_route("10.99.0.0/24", egress="r2-eth5", kind="ORIGINATES")]
    graph.sources_by_ip["10.99.0.7"] = [
        {
            **_src_row(dom="r2net", ip="10.99.0.7"),
            "anchor": "vrf:r2",
            "ep_uid": "ep:srv7",
            "ep_name": "srv7",
        }
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    leg = result["legs"][0]
    assert leg.get("delivered")
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Endpoint", "srv7") in kinds


def test_a_cross_scope_hop_carries_the_entered_scope_to_later_rungs(graph):
    """Hop 1 lands on a single owner in another scope (a leaked next hop needs
    no ladder); a later duplicate next hop must narrow by the scope the trace
    entered, not by the first hop's."""
    graph.sources = [_src_row()]
    graph.default_tables = {
        GW["if_uid"]: {"uid": "vrf:r1"},
        "if:sb-e0": {"uid": "vrf:sb"},
        "if:sb2-e0": {"uid": "vrf:sb2"},
    }
    graph.routes = {
        "vrf:r1": [_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2")],
        "vrf:sb": [_route("10.99.0.0/24", egress="sb-e1", next_hop="10.0.13.9")],
        "vrf:sb2": [_route("10.99.0.0/24", egress="sb2-eth5")],
    }
    graph.next_hop_devs = {
        "10.0.12.2": {
            "dev_uid": "dev:sb",
            "dev_name": "sb",
            "if_uid": "if:sb-e0",
            "if_name": "sb-e0",
            "l3dom": "site-b",
        },
        "10.0.13.9": [
            # sorts first and matches the original gateway's scope
            {
                "dev_uid": "dev:aa-home",
                "dev_name": "aa-home",
                "if_uid": "if:aa-e0",
                "if_name": "aa-e0",
                "l3dom": "home",
            },
            {
                "dev_uid": "dev:sb2",
                "dev_name": "sb2",
                "if_uid": "if:sb2-e0",
                "if_name": "sb2-e0",
                "l3dom": "site-b",
            },
        ],
    }
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "sb2") in kinds
    assert ("Device", "aa-home") not in kinds
    assert result["legs"][0]["verdict"] == "egress via sb2-eth5"


def test_a_leaked_route_scopes_the_next_hop_pick_to_the_exporting_context(graph):
    """The route carries collected provenance (next_hop_vrf)."""
    _two_routers(graph)
    graph.default_tables["if:rx-e0"] = {"uid": "vrf:rx"}
    graph.routes["vrf:r1"] = [
        {**_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"), "next_hop_vrf": "vrf:rx"}
    ]
    graph.routes["vrf:rx"] = [_route("10.99.0.0/24", egress="rx-eth5")]
    graph.next_hop_devs["10.0.12.2"] = [
        RX_IF,  # anchor vrf:rx, the exporting context's owner
        {**R2_IF, "anchor": "vrf:r1", "l3dom": "home"},  # the importing table's own owner
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "rx") in kinds
    assert result["legs"][0]["verdict"] == "egress via rx-eth5"


def test_an_fhrp_pair_scripted_out_of_uid_order_answers_by_lowest_uid(graph):
    _two_routers(graph)
    graph.default_tables["if:r2b-e0"] = {"uid": "vrf:r2"}
    graph.next_hop_devs["10.0.12.2"] = [
        {
            "dev_uid": "dev:zz-r2b",
            "dev_name": "r2b",
            "if_uid": "if:r2b-e0",
            "if_name": "r2b-e0",
            "anchor": "vrf:r2",
        },
        {**R2_IF, "anchor": "vrf:r2"},
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result.get("indeterminate")
    assert any("2 interfaces hold next hop 10.0.12.2" in n for n in result["notes"])


def test_nat_rulebases_of_every_traversed_device_count_as_evaluated(graph):
    _two_routers(graph)
    graph.nat_by_dev = {
        "dev:r1": [_nat_row(translation="masquerade", out_if="eth0")],
        "dev:r2": [
            _nat_row(
                rb_uid="rb:r2nat",
                rb_name="r2-nat",
                uid="r2:n1",
                kind="snat",
                translation="masquerade",
                out_if="wan9",
            )
        ],
    }
    graph.gates = [
        {"uid": "rb:nat", "name": "nat-source", "kind": "FwRulebase"},
        {"uid": "rb:r2nat", "name": "r2-nat", "kind": "FwRulebase"},
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert "gate(s) not evaluated" not in result["verdict"]


def test_a_block_on_the_first_router_ends_the_lane_on_the_destination(graph):
    """The lane ends on the destination endpoint, drawn past the gate."""
    _two_routers(graph)
    graph.sources_by_ip["10.99.0.7"] = [
        _src_row(dom="home", ip="10.99.0.7") | {"anchor": "home", "ep_uid": "ep:srv", "ep_name": "srv-1"}
    ]
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    graph.rules = [_rule(uid="cp:deny", pos=7, action="drop")]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by Standard rule 7"
    assert leg.get("delivered") is not True

    hops = [(h["uid"], h["kind"], h["label"]) for h in result["hops"]]
    assert hops[-1] == ("ep:srv", "Endpoint", "srv-1")
    assert ("dev:r2", "Device", "r2") not in hops
    assert not [h for h in result["hops"] if h["uid"].startswith("if:r2-")]
    assert not [h for h in result["hops"] if h["label"] == "r2-eth5"]
    # one firewall evaluation, r1's: the same scripted rulebase governs r2 in
    # this fake graph, so a second note would mean the trace descended
    assert len([n for n in result["notes"] if "Standard" in n]) == 1

    by_uid = {h["uid"]: h for h in result["hops"]}
    assert by_uid["ep:srv"]["rank"] > by_uid["rb:1"]["rank"]
    assert by_uid["ep:srv"]["lane"] == leg["lane"]
    assert by_uid["ep:srv"]["stage"] == "DST_ENDPOINT"


# --- next-hop adjacency and the hop cap ---------------------------------------------------


def test_a_non_adjacent_next_hop_is_indeterminate_not_a_free_hop(graph):
    """The next-hop address is not on any prefix r1 is connected to."""
    _two_routers(graph)
    # r1's own connected prefix; the next hop 10.0.12.2 is outside it
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"),
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"] and result["indeterminate"]
    assert any("of r1 in table default covers next hop 10.0.12.2" in w for w in result["warnings"])
    assert any("transit device(s) between here and r2" in w for w in result["warnings"])
    hops = [(h["uid"], h["kind"]) for h in result["hops"]]
    assert ("dev:r2", "Device") not in hops
    assert ("if:r2-eth0", "Interface") not in hops
    # the leg ends on r1's own egress
    assert leg["verdict"] == "egress via eth0"


def test_a_next_hop_on_a_connected_prefix_traces_through(graph):
    _two_routers(graph)
    graph.routes["vrf:r1"] = [
        _route("10.0.12.0/30", egress="eth0", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"),
    ]
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result.get("indeterminate")


def test_a_table_with_no_connected_prefix_cannot_disprove_adjacency(graph):
    """The hop is drawn with a note."""
    _two_routers(graph)  # vrf:r1 carries the static route only
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result.get("indeterminate")
    assert not result["legs"][0]["indeterminate"]
    assert result["warnings"] == []
    assert any(
        "table default records nothing of the address family of next hop "
        "10.0.12.2, so the hop to r2 was drawn without checking adjacency" in n
        for n in result["notes"]
    )


def test_a_leaked_route_judges_adjacency_in_the_exporting_table(graph):
    """The route into vrf:r1 was leaked from vrf:rx."""
    _two_routers(graph)
    graph.default_tables["if:rx-e0"] = {"uid": "vrf:rx"}
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        {**_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"), "next_hop_vrf": "vrf:rx"},
    ]
    graph.routes["vrf:rx"] = [
        _route("10.0.12.0/30", egress="rx-e0", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="rx-eth5"),
    ]
    graph.next_hop_devs["10.0.12.2"] = [RX_IF]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via rx-eth5"
    assert not result["legs"][0]["indeterminate"]
    assert not result["indeterminate"]
    assert not [w for w in result["warnings"] if "covers next hop" in w]
    assert ("Device", "rx") in [(h["kind"], h["label"]) for h in result["hops"]]


def test_a_leaked_next_hop_on_an_own_address_of_the_exporting_table_is_adjacent(graph):
    """An interface address that the exporting table records is adjacency evidence."""
    _two_routers(graph)
    graph.default_tables["if:rx-e0"] = {"uid": "vrf:rx"}
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        {**_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"), "next_hop_vrf": "vrf:rx"},
    ]
    graph.routes["vrf:rx"] = [
        _route("192.168.7.0/24", egress="rx-e0", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="rx-eth5"),
    ]
    graph.dev_addrs = {
        "dev:r1": [
            {
                "ip": "10.0.12.2",
                "ip_uid": "ip:lab:10.0.12.2",
                "if_uid": "if:rx-e0",
                "if_name": "rx-e0",
            }
        ]
    }
    graph.next_hop_devs["10.0.12.2"] = [RX_IF]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via rx-eth5"
    assert not result["indeterminate"]
    assert not [w for w in result["warnings"] if "covers next hop" in w]


def test_a_host_route_evidences_adjacency_for_an_ordinary_route_too(graph):
    """The platform records the directly attached WAN peer as a /32 only."""
    _two_routers(graph)
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        _route("10.0.12.2/32", egress="eth0"),
        _route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"),
    ]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result["indeterminate"]
    assert not [w for w in result["warnings"] if "covers next hop" in w]


def test_an_own_address_evidences_adjacency_for_an_ordinary_route_too(graph):
    """The next hop is an address of this device in the table being routed on."""
    _two_routers(graph)
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"),
    ]
    graph.dev_addrs = {
        "dev:r1": [{"ip": "10.0.12.2", "ip_uid": "ip:lab:10.0.12.2", "if_uid": "if:eth0", "if_name": "eth0"}]
    }

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert not result["indeterminate"]
    assert not [w for w in result["warnings"] if "covers next hop" in w]


def test_the_unevidenced_adjacency_note_names_the_exporting_table_by_name(graph):
    _two_routers(graph)
    graph.default_tables["if:rx-e0"] = {"uid": "vrf:rx"}
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        {**_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"), "next_hop_vrf": "vrf:rx"},
    ]
    graph.routes["vrf:rx"] = [_route("10.99.0.0/24", egress="rx-eth5")]
    graph.next_hop_devs["10.0.12.2"] = [RX_IF]

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert any("table default records nothing of the address family" in n for n in result["notes"])
    assert not [n for n in result["notes"] if "table vrf:rx records" in n]


def _router_chain(graph, routers):
    """A chain of `routers` devices: r1 is the gateway, each hands the flow to
    the next, and the last serves 10.99.0.0/24 on a connected interface."""
    graph.sources = [_src_row()]
    graph.default_tables = {GW["if_uid"]: {"uid": "vrf:r1"}}
    graph.routes = {}
    graph.next_hop_devs = {}
    for i in range(1, routers + 1):
        if i == routers:
            graph.routes[f"vrf:r{i}"] = [_route("10.99.0.0/24", egress=f"r{i}-eth5")]
            continue
        graph.routes[f"vrf:r{i}"] = [_route("10.99.0.0/24", egress=f"r{i}-out", next_hop=f"10.{i}.0.2")]
        graph.next_hop_devs[f"10.{i}.0.2"] = {
            "dev_uid": f"dev:r{i + 1:02d}",
            "dev_name": f"r{i + 1}",
            "if_uid": f"if:r{i + 1}-in",
            "if_name": f"r{i + 1}-in",
        }
        graph.default_tables[f"if:r{i + 1}-in"] = {"uid": f"vrf:r{i + 1}"}


def test_the_hop_cap_is_read_from_settings(graph, monkeypatch):
    monkeypatch.setenv("MAX_L3_HOPS", "3")
    _router_chain(graph, 6)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    assert any("path exceeds 3 L3 hops; trace stopped at r4" in w for w in result["warnings"])
    assert not [h for h in result["hops"] if h["uid"] == "dev:r05"]


def test_an_explicit_hop_cap_overrides_the_setting(graph):
    _router_chain(graph, 6)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], max_hops=2)
    assert result["indeterminate"]
    assert any("path exceeds 2 L3 hops; trace stopped at r3" in w for w in result["warnings"])


def test_an_enterprise_depth_chain_is_not_stopped_by_the_default_cap(graph):
    _router_chain(graph, 32)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via r32-eth5"
    assert not result.get("indeterminate")
    assert not [w for w in result["warnings"] if "L3 hops" in w]


def test_both_routers_draw_their_own_route_decision_for_a_shared_prefix(graph):
    """A Prefix node is shared by every device in one routing domain."""
    _two_routers(graph)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    ranks = sorted(h["rank"] for h in result["hops"] if h["uid"] == "pfx:10.99.0.0/24")
    assert len(ranks) == 2
    assert ranks[0] < ranks[1]
    # r1's own device hop ranks before its route match, r2's after it
    dev_ranks = {h["uid"]: h["rank"] for h in result["hops"] if h["kind"] == "Device"}
    assert dev_ranks["dev:r1"] < ranks[0] < dev_ranks["dev:r2"] < ranks[1]


def _prefix_destination(graph):
    """r2 serves 10.99.0.0/24 on a connected interface in its table vrf:r2."""
    _two_routers(graph)
    graph.routes["vrf:r2"] = [_route("10.99.0.0/24", egress="r2-eth5", kind="ORIGINATES")]


def test_a_prefix_destination_delivered_in_the_requested_context_is_settled(graph):
    _prefix_destination(graph)

    result = path.trace(None, "10.0.0.5", "10.99.0.0/24", gateways=[GW], dst_context="vrf:r2")

    assert not result["indeterminate"]
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert all("_local_net" not in leg for leg in result["legs"])


def test_a_prefix_destination_delivered_in_another_context_is_undecided(graph):
    """The destination site shares a templated LAN with a third site."""
    _prefix_destination(graph)

    result = path.trace(None, "10.0.0.5", "10.99.0.0/24", gateways=[GW], dst_context="vrf:site-b")

    leg = result["legs"][0]
    assert result["indeterminate"] and leg["indeterminate"]
    assert leg["verdict"] == "egress via r2-eth5"  # forwarding is not steered
    assert leg["indeterminate_reason"] == (
        "the path to 10.99.0.0/24 is delivered in context vrf:r2, "
        "not in the requested destination context vrf:site-b"
    )


def test_a_prefix_destination_that_leaves_the_twin_outside_the_requested_context_is_undecided(graph):
    _two_routers(graph)  # r2's route has no next hop in the graph: the path leaves the twin at r2

    result = path.trace(None, "10.0.0.5", "10.99.0.0/24", gateways=[GW], dst_context="vrf:site-b")

    assert result["indeterminate"]
    assert any("leaves the twin in context vrf:r2, not in the requested" in w for w in result["warnings"])
