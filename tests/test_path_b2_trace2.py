"""Trace cases: dst_context, merged starts, wide network sources, late checks and the transport walk."""

import copy
import importlib

import pytest
from tests.test_path_multihop import _prefix_destination, _two_routers
from tests.test_path_sdwan import PE1, PE2_LO, TransportGraph, _l3vpn
from tests.test_path_trace import GW, FakeGraph, _route, _src_row

from hst import path
from hst.results.trace import project_trace

tracemod = importlib.import_module("hst.path.trace")


@pytest.fixture()
def graph(monkeypatch):
    g = FakeGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


@pytest.fixture()
def tgraph(monkeypatch):
    g = TransportGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


def _answer(result):
    return project_trace(copy.deepcopy(result))["result"]["answer"]


def _no_internal_keys(result):
    for leg in result["legs"]:
        assert not [k for k in leg if k.startswith("_")], leg


# --- a switched leg is held to dst_context -------------------------------------------------------


def test_a_switched_leg_outside_the_requested_destination_context_is_undecided(graph):
    graph.sources = [_src_row()]

    result = path.trace(None, "10.0.0.5", "10.0.0.128/25", gateways=[GW], dst_context="vrf:site-b")

    leg = result["legs"][0]
    assert leg["verdict"] == "switched in 10.0.0.0/24"  # forwarding is not steered
    assert result["indeterminate"] and leg["indeterminate"]
    assert leg["indeterminate_reason"] == (
        "the path to 10.0.0.128/25 is delivered in context home, "
        "not in the requested destination context vrf:site-b"
    )
    assert _answer(result) == "open"
    _no_internal_keys(result)


def test_a_switched_leg_in_the_requested_destination_context_stays_decided(graph):
    graph.sources = [_src_row()]
    without = path.trace(None, "10.0.0.5", "10.0.0.128/25", gateways=[GW])

    result = path.trace(None, "10.0.0.5", "10.0.0.128/25", gateways=[GW], dst_context="home")

    assert result == without
    assert not result["indeterminate"]
    _no_internal_keys(result)


# --- a single-address destination is held to dst_context --------------------------------------------


def _host_known_in_site_b(graph):
    """r2 delivers 10.99.0.7 on its connected 10.99.0.0/24 (table vrf:r2); the
    twin holds an instance of 10.99.0.7 only in vrf:site-b."""
    _prefix_destination(graph)
    graph.dst_instances["10.99.0.7"] = [
        {"uid": "ip:site-b:10.99.0.7", "anchor": "vrf:site-b", "l3dom": "site-b"}
    ]


def test_a_host_delivered_outside_the_requested_destination_context_is_undecided(graph):
    _host_known_in_site_b(graph)

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], dst_context="vrf:site-b")

    leg = result["legs"][0]
    assert leg["verdict"] == "egress via r2-eth5"
    assert result["indeterminate"] and leg["indeterminate"]
    assert leg["indeterminate_reason"] == (
        "the path to 10.99.0.7 is delivered in context vrf:r2, "
        "not in the requested destination context vrf:site-b"
    )
    assert _answer(result) == "open"
    # the walk's prose names it too
    assert result["verdict"].endswith(f"; INDETERMINATE, {leg['indeterminate_reason']}")


def test_a_host_delivered_in_the_requested_table_stays_decided(graph):
    """The instance is anchored elsewhere, but the delivering leg's own table is
    the requested context: the same answer as with no dst_context at all."""
    _host_known_in_site_b(graph)
    without = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], dst_context="vrf:r2")

    assert not result["indeterminate"]
    assert result["legs"] == without["legs"] and result["verdict"] == without["verdict"]
    assert _answer(result) == "true"


def _reached_endpoint(graph):
    """r1 delivers 10.7.0.9 on its connected 10.7.0.0/24 (table vrf:main), and
    the endpoint row anchors the address on its segment 'home'."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.7.0.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.sources_by_ip["10.7.0.9"] = [
        _src_row(ip="10.7.0.9")
        | {
            "anchor": "home",
            "ep_uid": "ep:cam",
            "ep_name": "cam-1",
            "att_uid": "dev:ap1",
            "att_is_port": False,
        }
    ]
    graph.dst_instances["10.7.0.9"] = [
        {"uid": "ip:home:10.7.0.9", "anchor": "home", "l3dom": "home"},
        {"uid": "ip:guest:10.7.0.9", "anchor": "guest", "l3dom": "guest"},
    ]


@pytest.mark.parametrize("context", ["home", "vrf:main"])
def test_a_host_reached_in_the_requested_context_reads_as_without_it(graph, context):
    """Requested by the instance's own anchor (a segment) or by the delivering
    table: either one holds the reached instance."""
    _reached_endpoint(graph)
    without = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW])

    result = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW], dst_context=context)

    assert result["legs"][0]["delivered"] is True
    assert result["legs"] == without["legs"]
    assert result["warnings"] == without["warnings"] and result["verdict"] == without["verdict"]
    assert result["indeterminate"] == without["indeterminate"]


def test_a_host_reached_in_another_context_is_undecided(graph):
    _reached_endpoint(graph)

    result = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW], dst_context="guest")

    leg = result["legs"][0]
    assert result["indeterminate"] and leg["indeterminate"]
    assert (
        "the path to 10.7.0.9 is delivered in context vrf:main, "
        "not in the requested destination context guest" in result["warnings"]
    )
    assert (
        "reached the instance in home; the requested context guest is not reachable from this source"
        in (result["notes"])
    )


# --- a merge holds every start ---------------------------------------------------------------------


def test_a_merge_with_an_interpretation_that_has_no_gateway_is_not_decided(graph):
    _two_routers(graph)
    graph.sources = [_src_row("home"), _src_row("dev")]
    gw_dev = {**GW, "cidr": "10.5.0.0/24", "l3dom": "dev", "if_uid": "if:dev1", "dev_uid": "dev:r7"}

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW, gw_dev])

    assert result["indeterminate"] is True
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"  # the traced part is unchanged
    assert any(
        w.startswith("[dev] not traced: no gateway found for the source prefix") for w in result["warnings"]
    )
    assert _answer(result) == "open"


def test_a_merge_of_traced_interpretations_stays_decided(graph):
    _two_routers(graph)
    graph.sources = [_src_row("home"), _src_row("dev")]
    gw_dev = {**GW, "l3dom": "dev"}

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW, gw_dev])

    assert len(result["legs"]) == 2
    assert result["indeterminate"] is False and result["warnings"] == []
    assert _answer(result) == "true"


def test_interpretations_past_the_cap_leave_the_answer_open(graph):
    graph.sources = [_src_row(dom=f"dom{i}", ip="10.0.0.5") | {"anchor": f"anchor{i}"} for i in range(10)]
    gws = [
        {**GW, "anchor": f"anchor{i}", "l3dom": f"dom{i}", "dev_uid": f"dev:r{i}", "if_uid": f"if:r{i}"}
        for i in range(10)
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    assert len({leg["interpretation"]["anchor"] for leg in result["legs"]}) == 8
    assert result["indeterminate"] is True
    assert result["warnings"] == [
        "not traced: 2 more interpretations exist (anchors: anchor8, anchor9); narrow with src_context"
    ]
    assert _answer(result) == "open"


# --- a network source wider than its gateway prefix --------------------------------------------------


def test_a_source_wider_than_its_gateway_prefix_is_not_decided(graph):
    _two_routers(graph)
    gw9 = {**GW, "cidr": "10.0.1.0/24", "if_uid": "if:r9-eth1", "if_name": "r9-eth1", "dev_uid": "dev:r9"}

    result = path.trace(None, "10.0.0.0/16", "10.99.0.7", gateways=[GW, gw9])

    leg = result["legs"][0]
    assert leg["sources"] == ["10.0.0.0/16"]
    assert result["indeterminate"] and leg["indeterminate"]
    assert leg["indeterminate_reason"] == (
        "10.0.1.0/24 +7 more (65280 addresses) of the source is outside 10.0.0.0/24 "
        "and was not traced (different gateway)"
    )
    assert "INDETERMINATE" in result["verdict"]
    assert _answer(result) == "open"


def test_a_source_inside_its_gateway_prefix_stays_decided(graph):
    _two_routers(graph)

    result = path.trace(None, "10.0.0.0/25", "10.99.0.7", gateways=[GW])

    assert not result["indeterminate"]
    assert not any("outside" in w for w in result["warnings"])


# --- a late check names itself in the walk's prose --------------------------------------------------


def test_an_undecided_aci_contract_names_itself_in_the_verdict(graph):
    """Only the source is an ACI endpoint: the contract cannot be decided."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.aci_ends = [{"ip": "10.0.0.5", "epg_uid": "epg:web", "epg_name": "web"}]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"] and result["legs"][0]["indeterminate"]
    assert " · INDETERMINATE by ACI (" in result["verdict"]


# --- an interface route in the transport walk --------------------------------------------------------


def _non_adjacent_next_hop(graph, extra):
    _two_routers(graph)
    graph.local_vrf = {"vrf_uid": "vrf:r1", "vrf_name": "default"}
    graph.routes["vrf:r1"] = [
        _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"),
        *extra,
    ]


def test_an_interface_default_route_does_not_make_a_next_hop_adjacent(graph):
    _non_adjacent_next_hop(graph, [_route("0.0.0.0/0", egress="pppoe0")])

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"] and result["indeterminate"]
    assert "transit device(s) between here and r2 are not represented" in leg["indeterminate_reason"]
    assert any(
        "by 0.0.0.0/0 out of pppoe0 with no next hop; the transport path is not traced" in w
        for w in result["warnings"]
    )
    assert [h["label"] for h in result["hops"] if h["kind"] == "Device"] == ["r1"]


def test_an_interface_host_route_to_the_next_hop_keeps_it_adjacent(graph):
    """A PPP peer's host route out of the interface is on the link, as
    `_host_prefixes` reads it."""
    _non_adjacent_next_hop(graph, [_route("10.0.12.2/32", egress="ppp0")])

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not result["indeterminate"]


def test_a_connected_side_store_route_keeps_the_next_hop_on_the_link():
    assert tracemod._on_link_route({"kind": "RIB", "cidr": "10.0.12.0/24", "protocol": "connected"})
    assert not tracemod._on_link_route({"kind": "RIB", "cidr": "0.0.0.0/0", "protocol": "static"})
    assert not tracemod._on_link_route({"kind": "STATIC_ROUTE", "cidr": "0.0.0.0/0"})


# --- the far PE's table of the routing domain -------------------------------------------------------


def _decided_l3vpn(graph):
    """`_l3vpn` with the customer table recorded and sharing a routing domain
    with pe2's global table, so the hop to pe2's loopback is decided."""
    _l3vpn(graph)
    graph.contexts["vrf:pe1-cust"] = {"name": "cust", "is_global": False}
    graph.domain_mates = {"vrf:pe1-cust": ["vrf:pe2-global"]}


class _TwoTablesGraph(TransportGraph):
    def read_one(self, query, **params):
        if "count(DISTINCT v.uid) AS tables" in query:
            return {"tables": 2, "names": ["cust", "cust-b"]}
        return super().read_one(query, **params)


def test_a_vpn_route_with_one_table_of_its_domain_on_the_far_pe_stays_decided(tgraph):
    _decided_l3vpn(tgraph)

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert result["legs"][0]["verdict"] == "egress via Gi0/0/0/2"
    assert not result["indeterminate"]
    assert any("Gi0/0/0/2 of that table stands in for the arrival interface" in n for n in result["notes"])


def test_a_far_pe_with_two_tables_of_the_routing_domain_is_not_decided(monkeypatch):
    g = _TwoTablesGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    _decided_l3vpn(g)

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    leg = result["legs"][0]
    assert leg["verdict"] == "egress via Gi0/0/0/2"
    assert leg["indeterminate"] and result["indeterminate"]
    assert leg["indeterminate_reason"] == (
        "10.1.1.5: pe2 holds 2 tables of the routing domain of default (cust, cust-b); "
        "which one the VPN label selects is not collected"
    )


def test_a_vpn_route_with_no_table_of_its_domain_on_the_far_pe_is_not_decided(tgraph):
    _decided_l3vpn(tgraph)
    tgraph.mate_if = {}

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert result["indeterminate"] and result["legs"][0]["indeterminate"]
    assert any(
        "pe2 holds no table of the routing domain of default; "
        "the table the VPN label selects there is not known" in w
        for w in result["warnings"]
    )


# --- the Oslo switched leg: the same-port exemption is per leg -------------------------------------


def test_a_switched_leg_between_two_ports_of_a_routed_device_keeps_its_gates(graph):
    """Hosts on two ports of the gateway device: the frame crosses it, so its
    gates stay on the path (the same-port exemption does not apply)."""
    graph.sources = [
        _src_row()
        | {
            "ep_uid": "ep:a",
            "att_uid": "port:r1-p1",
            "att_is_port": True,
            "sw_uid": "dev:r1",
            "sw_name": "r1",
        }
    ]
    graph.sources_by_ip["10.0.0.9"] = [
        _src_row(ip="10.0.0.9")
        | {
            "ep_uid": "ep:b",
            "att_uid": "port:r1-p2",
            "att_is_port": True,
            "sw_uid": "dev:r1",
            "sw_name": "r1",
        }
    ]
    graph.gates = [{"uid": "rb:r1", "name": "r1-acl", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.0.9", gateways=[GW])

    assert result["legs"][0]["verdict"] == "switched in 10.0.0.0/24"
    assert result["indeterminate"]
    assert "FwRulebase r1-acl: on path, not evaluated" in result["warnings"]
    _no_internal_keys(result)


def test_a_switched_leg_between_two_hosts_on_one_port_does_not_cross_that_device(graph):
    graph.sources = [
        _src_row()
        | {
            "ep_uid": "ep:a",
            "att_uid": "port:r1-p1",
            "att_is_port": True,
            "sw_uid": "dev:r1",
            "sw_name": "r1",
            "seg_uid": "bd:10",
        }
    ]
    graph.sources_by_ip["10.0.0.9"] = [
        _src_row(ip="10.0.0.9")
        | {
            "ep_uid": "ep:b",
            "att_uid": "port:r1-p1",
            "att_is_port": True,
            "sw_uid": "dev:r1",
            "sw_name": "r1",
            "seg_uid": "bd:10",
        }
    ]
    graph.gates = [{"uid": "rb:r1", "name": "r1-acl", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.0.9", gateways=[GW])

    assert result["legs"][0]["verdict"] == "switched in 10.0.0.0/24"
    assert not result["indeterminate"] and result["warnings"] == []
    _no_internal_keys(result)


def test_a_vpn_route_between_two_pes_on_one_link_continues_in_the_far_table(tgraph):
    _decided_l3vpn(tgraph)
    tgraph.routes["vrf:pe1-global"] = [_route("10.255.0.2/32", egress="Hu0/0/0/1", next_hop="10.0.12.2")]
    tgraph.next_hop_devs["10.0.12.2"] = {**PE2_LO, "if_uid": "if:pe2-core", "if_name": "Hu0/0/0/0"}

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    leg = result["legs"][0]
    assert leg["verdict"] == "egress via Gi0/0/0/2"
    assert not result["indeterminate"]
    assert any("continues in table cust, the same routing domain as" in n for n in result["notes"])


def test_a_route_leaked_to_the_global_table_continues_there_without_a_domain_table(tgraph):
    _decided_l3vpn(tgraph)
    tgraph.mate_if = {}
    tgraph.routes["vrf:pe1-cust"][1] = {
        **_route("10.99.0.0/24", next_hop="10.255.0.2", kind="LEARNED_ROUTE"),
        "next_hop_vrf": "vrf:pe1-global",
    }
    tgraph.routes["vrf:pe2-global"] = [_route("10.99.0.0/24", egress="Gi0/0/0/9")]

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert not any("routing domain of" in w for w in result["warnings"])


def _far_ce_pbr(tgraph):
    """A PBR policy on pe2's CE-facing interface that sends the destination to
    the table `steer`."""
    _decided_l3vpn(tgraph)
    tgraph.pbr_by_if["if:pe2-cust"] = [
        {
            "pol_uid": "pol:pe2",
            "pol_name": "from-ce",
            "rule_uid": "rule:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": ["10.99.0.0/24"],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": "vrf:pe2-steer",
            "table_name": "steer",
        }
    ]
    tgraph.pbr_by_dev = {"dev:pe2": [{"pol_uid": "pol:pe2", "if_uid": "if:pe2-cust"}]}
    tgraph.routes["vrf:pe2-steer"] = [_route("0.0.0.0/0", egress="Gi0/0/0/7")]


def test_a_pbr_policy_on_the_far_pes_ce_interface_does_not_claim_traffic_from_the_core(tgraph):
    _far_ce_pbr(tgraph)

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert result["legs"][0]["verdict"] == "egress via Gi0/0/0/2"
    assert not result["indeterminate"]


def test_a_pbr_policy_on_the_far_pes_ce_interface_is_credited_as_ruled_out_by_interface(tgraph):
    _far_ce_pbr(tgraph)

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert result["legs"][0]["pbr_uids"] == ["pol:pe2"]
    assert not any("PbrPolicy" in w for w in result["warnings"])


def test_a_pbr_policy_claims_the_flow_on_the_interface_it_arrives_on(tgraph):
    """pe2 is the first hop here, so the flow arrives on the CE-facing interface."""
    _far_ce_pbr(tgraph)
    tgraph.sources = [_src_row(dom="cust", ip="10.2.2.5")]
    pe2 = {
        **PE1,
        "cidr": "10.2.2.0/24",
        "if_uid": "if:pe2-cust",
        "if_name": "Gi0/0/0/2",
        "dev_uid": "dev:pe2",
    }

    result = path.trace(None, "10.2.2.5", "10.99.0.7", port=443, proto="tcp", gateways=[pe2])

    assert result["legs"][0]["verdict"] == "egress via Gi0/0/0/7"


def test_two_hosts_on_one_trunk_port_in_two_segments_keep_the_devices_gates(graph):
    """One port, one subnet, two VLANs: the frame crosses the device's bridge
    between the two segments, so its gates stay on the path."""
    row = {"att_uid": "port:r1-p1", "att_is_port": True, "sw_uid": "dev:r1", "sw_name": "r1"}
    graph.sources = [_src_row() | row | {"ep_uid": "ep:a", "seg_uid": "bd:10"}]
    graph.sources_by_ip["10.0.0.9"] = [_src_row(ip="10.0.0.9") | row | {"ep_uid": "ep:b", "seg_uid": "bd:20"}]
    graph.gates = [{"uid": "rb:r1", "name": "r1-acl", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.0.9", gateways=[GW])

    assert result["legs"][0]["verdict"] == "switched in 10.0.0.0/24"
    assert result["indeterminate"]
    assert "FwRulebase r1-acl: on path, not evaluated" in result["warnings"]
    _no_internal_keys(result)
