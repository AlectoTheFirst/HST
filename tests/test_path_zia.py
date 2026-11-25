"""The ZIA forwarding stage at the ZIA boundary (path/gates/zia.py): the pure
first-match walk, and the trace that draws it."""

# ruff: noqa: F811
from __future__ import annotations

import importlib

from tests.test_path_nat import _tunnel
from tests.test_path_trace import GW, _route, _src_row, graph  # noqa: F401

from hst import path
from hst.path.addrsets import _intervals
from hst.path.gates import zia

# the package exports a `trace` function under the module's own name
trace = importlib.import_module("hst.path.trace")

LOC = {"uid": "zia:acme:loc:1001", "name": "hq", "groups": ["zia:acme:locgrp:1"], "sublocations": []}
SRC = _intervals(["10.0.0.5"])
DST = _intervals(["8.8.8.8"])


def _rule(uid: str, order: int | None = 1, method: str = "direct", **over) -> dict:
    return {
        "uid": uid,
        "name": uid.rsplit(":", 1)[-1],
        "order": order,
        "method": method,
        "enabled": True,
        "location_ids": [],
        "location_group_ids": [],
        "src_ips": [],
        "dest_addresses": [],
        "other_criteria": [],
        "targets": [],
        **over,
    }


def test_a_rule_for_every_location_matches():
    decision = zia.forwarding_decision(LOC, [_rule("r1")], SRC, DST)
    assert decision.rule["uid"] == "r1"


def test_scope_through_the_location_and_through_a_group():
    by_loc = _rule("r1", location_ids=["1001"], targets=["zia:acme:loc:1001"])
    by_group = _rule("r2", location_group_ids=["1"], targets=["zia:acme:locgrp:1"])
    other = _rule("r0", order=1, location_ids=["9"], targets=["zia:acme:loc:9"])
    assert zia.forwarding_decision(LOC, [other, {**by_loc, "order": 2}], SRC, DST).rule["uid"] == "r1"
    assert zia.forwarding_decision(LOC, [other, {**by_group, "order": 2}], SRC, DST).rule["uid"] == "r2"


def test_a_parent_only_rule_for_a_sublocation_flow_is_undecided():
    location = {
        **LOC,
        "sublocations": [
            {"uid": "zia:acme:loc:1003", "name": "guest", "address_ranges": ["10.0.0.0/24"], "groups": []}
        ],
    }
    rule = _rule("r1", location_ids=["1001"], targets=["zia:acme:loc:1001"])
    decision = zia.forwarding_decision(location, [rule], SRC, DST)
    assert decision.rule is None and decision.undecided["uid"] == "r1"
    assert "parent location" in decision.reason


def test_an_uncollected_named_id_is_undecided():
    rule = _rule("r1", location_ids=["1001", "4242"], targets=["zia:acme:loc:9"])
    decision = zia.forwarding_decision(LOC, [rule], SRC, DST)
    assert decision.undecided["uid"] == "r1" and "did not collect" in decision.reason


def test_the_source_criterion_inside_outside_and_partial():
    assert zia.forwarding_decision(LOC, [_rule("r1", src_ips=["10.0.0.0/24"])], SRC, DST).rule["uid"] == "r1"
    assert zia.forwarding_decision(LOC, [_rule("r1", src_ips=["10.9.0.0/24"])], SRC, DST).rule is None
    wide = _intervals(["10.0.0.0/23"])
    partial = zia.forwarding_decision(LOC, [_rule("r1", src_ips=["10.0.0.0/24"])], wide, DST)
    assert partial.undecided["uid"] == "r1" and "part of the flow" in partial.reason


def test_an_fqdn_destination_is_undecided():
    decision = zia.forwarding_decision(LOC, [_rule("r1", dest_addresses=["www.example.com"])], SRC, DST)
    assert decision.undecided["uid"] == "r1" and "www.example.com" in decision.reason


def test_other_criteria_are_undecided():
    decision = zia.forwarding_decision(LOC, [_rule("r1", other_criteria=["dest_countries"])], SRC, DST)
    assert decision.undecided["uid"] == "r1" and "dest_countries" in decision.reason


def test_a_disabled_rule_is_skipped_and_an_order_below_one_comes_last():
    rules = [_rule("r0", order=0), _rule("r1", order=2, enabled=False), _rule("r2", order=3)]
    assert zia.forwarding_decision(LOC, rules, SRC, DST).rule["uid"] == "r2"
    assert zia.forwarding_decision(LOC, [_rule("r0", order=0)], SRC, DST).rule["uid"] == "r0"


def test_drop_is_decided_and_no_rule_matches():
    assert zia.forwarding_decision(LOC, [_rule("r1", method="drop")], SRC, DST).rule["method"] == "drop"
    none = zia.forwarding_decision(LOC, [_rule("r1", src_ips=["10.9.0.0/24"])], SRC, DST)
    assert (none.rule, none.undecided) == (None, None)


def _zia_graph(graph, rules: list[dict], location: dict | None = LOC):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="wg0")]}
    _tunnel(
        graph, endpoint=None, far_ip=None, far_uid="zia:acme:dc:fra4", far_name="fra4", far_kind="ZscalerDc"
    )
    graph.tunnel = {"uid": "zia:acme:gre:5001", "name": "zia-gre", "encap": "gre"}
    read, read_one = graph.read, graph.read_one

    def answer(query, **params):
        if query is zia._TENANT_RULES_QUERY:
            return rules
        return read(query, **params)

    def answer_one(query, **params):
        if query is zia._TUNNEL_LOCATION_QUERY:
            return location
        return read_one(query, **params)

    graph.read, graph.read_one = answer, answer_one


def test_a_drop_rule_blocks_the_leg_at_decap(graph):
    _zia_graph(graph, [_rule("zia:acme:fwdrule:9", method="drop")])
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["blocked"] and leg["blocking_uid"] == "zia:acme:fwdrule:9"
    assert leg["verdict"] == "BLOCKED by ZIA forwarding rule 9"
    assert [h["stage"] for h in result["hops"] if h["kind"] == "ZiaForwardingRule"] == ["DECAP"]


def test_a_direct_rule_draws_the_rule_and_keeps_the_boundary(graph):
    _zia_graph(graph, [_rule("zia:acme:fwdrule:1", method="direct")])
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["boundary"] and not leg["blocked"]
    assert "zia:acme:fwdrule:1" in leg["fw_uids"]
    assert any(
        h["note"].startswith("direct by ZIA forwarding rule 1")
        for h in result["hops"]
        if h["kind"] == "ZiaForwardingRule"
    )


def test_no_location_leaves_the_hops_unchanged(graph):
    _zia_graph(graph, [_rule("zia:acme:fwdrule:1")], location=None)
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert not [h for h in result["hops"] if h["kind"] == "ZiaForwardingRule"]
    assert result["legs"][0]["boundary"]


def test_a_zia_ipsec_tunnel_draws_the_location_boundary_and_no_warning(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gre1")]}
    graph.tunnel = None
    graph.iface_addrs = {"if:gre1": "198.51.100.20"}
    graph.iface_kinds = {"if:gre1": "tunnel"}
    graph.tunnel_by_source_ip = {
        "198.51.100.20": {"uid": "zia:acme:ipsec:7001", "name": "zia-ipsec", "encap": "ipsec"}
    }
    graph.tunnel_props = {
        "endpoint": None,
        "endpoint_port": None,
        "carrier_proto": None,
        "local_address": None,
        "encap": "ipsec",
    }
    read_one = graph.read_one

    def answer_one(query, **params):
        if query is zia._TUNNEL_LOCATION_QUERY:
            return LOC
        return read_one(query, **params)

    graph.read_one = answer_one
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert not any("peer endpoint not collected" in w for w in result["warnings"])
    assert [h["kind"] for h in result["hops"] if h["uid"] == LOC["uid"]] == ["ZiaLocation"]
    assert result["legs"][0]["boundary"]


def _carried_graph(graph, rules: list[dict], rows: list[dict]):
    """A router whose tunnel interface gre1 ends its own GRE tunnel toward a
    ZIA VIP; `rows` is what the egress tunnel lookup returns for gre1."""
    _zia_graph(graph, rules)
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gre1")]}
    graph.tunnel = None
    read = graph.read

    def answer(query, **params):
        if query is trace._EGRESS_TUNNEL_QUERY:
            return rows if params.get("u") == "if:gre1" else []
        return read(query, **params)

    graph.read = answer


ROUTER_GRE = {"uid": "tun:gre:198.51.100.20~104.129.194.38", "name": "Tunnel1", "encap": "gre"}
ZIA_GRE = {"uid": "zia:acme:gre:5001", "name": "zia-gre", "encap": "gre"}


def _row(tun: dict, binding: str, via: str | None = None) -> dict:
    return {**tun, "allowed_ips": None, "binding": binding, "via": via}


def test_a_router_tunnel_that_sources_a_zia_tunnel_draws_zia_for_its_egress(graph):
    """The router's GRE tunnel interface holds the ZIA inside range,
    and its own Tunnel's local address is the ZIA tunnel's source address."""
    rows = [_row(ROUTER_GRE, "endpoint"), _row(ZIA_GRE, "carried", via=ROUTER_GRE["uid"])]
    _carried_graph(graph, [_rule("zia:acme:fwdrule:9", method="drop")], rows)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] and leg["verdict"] == "BLOCKED by ZIA forwarding rule 9"
    assert [h["uid"] for h in result["hops"] if h["stage"] == "ENCAP"] == [ZIA_GRE["uid"]]
    assert not leg["indeterminate"]
    assert any(
        "rides ZIA tunnel zia-gre through the router's own tunnel Tunnel1" in n for n in result["notes"]
    )


def test_a_router_tunnel_that_sources_no_zia_tunnel_stays_its_own(graph):
    """Without a carried row the router's own tunnel is the one drawn."""
    _carried_graph(graph, [_rule("zia:acme:fwdrule:9", method="drop")], [_row(ROUTER_GRE, "endpoint")])

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert [h["uid"] for h in result["hops"] if h["stage"] == "ENCAP"] == [ROUTER_GRE["uid"]]
    assert not any("rides ZIA tunnel" in n for n in result["notes"])


def test_the_egress_tunnel_query_joins_the_router_tunnel_to_the_zia_tunnel():
    """The carried branch: the router's own Tunnel on the egress interface,
    its local address against the ZIA tunnel's source_ip, the same
    encapsulation, and its far end one of the ZIA tunnel's VIPs where ZIA
    names any."""
    branch = trace._EGRESS_TUNNEL_QUERY.split("UNION")[2]
    assert "MATCH (rt:Tunnel:Obj)-[e:ENDPOINT]->(eif:Interface {uid: $u})" in branch
    assert "MATCH (t:Tunnel:Obj {source_ip: rt.local_address, collection_ts: $snap})" in branch
    assert "t.encap = rt.encap" in branch
    assert "v1.vip = rt.endpoint" in branch
    assert "RETURN t, 'carried' AS binding, rt.uid AS via" in branch
