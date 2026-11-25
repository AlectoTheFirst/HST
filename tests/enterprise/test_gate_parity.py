import importlib
import os
from types import MappingProxyType

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.gates import (
    expand_aci_contracts,
    expand_device_gates,
    expand_zpa_broker,
    merge_choice_assignments,
)
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import ChoiceAssignment, ModelInput, StateKey
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager, header, initial_relation

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")

MANIFEST = "a" * 64


def inventory(nodes, relations):
    catalog = {node.uid: node for node in nodes}
    outgoing, incoming, labels = {}, {}, {}
    for node in nodes:
        for label in node.labels:
            labels.setdefault(label, []).append(node.uid)
    for relation in relations:
        outgoing.setdefault((relation.start, relation.kind), []).append(relation)
        incoming.setdefault((relation.end, relation.kind), []).append(relation)
    return GraphInventory(
        MANIFEST,
        "b" * 64,
        MappingProxyType(catalog),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


def node(uid, labels, **props):
    return GraphNode(uid, frozenset(labels), MappingProxyType({"uid": uid, **props}))


def rel(uid, kind, start, end):
    return GraphRelation(uid, kind, start, end, MappingProxyType({}))


def context():
    return ExecutionContext("estate", "graph", "domain", "dev", "vrf", 4)


def test_graph_nat_dnat_and_snat_compile_as_ordered_exact_relations():
    graph = inventory(
        [
            node("dev", ["Device"]),
            node("rb", ["FwRulebase"], kind="nat"),
            node("dnat", ["NatRule"], kind="dnat", position=1, enabled=True),
            node("snat", ["NatRule"], kind="snat", position=2, enabled=True),
            node("public", ["IpAddress"], ip="203.0.113.10"),
            node("private", ["IpAddress"], ip="10.0.0.10"),
            node("inside", ["Prefix"], cidr="10.0.0.0/24"),
            node("outside", ["IpAddress"], ip="192.0.2.10"),
        ],
        [
            rel("1", "ENFORCES", "dev", "rb"),
            rel("2", "HAS_RULE", "rb", "dnat"),
            rel("3", "ORIG_DST", "dnat", "public"),
            rel("4", "XLATE_DST", "dnat", "private"),
            rel("5", "HAS_RULE", "rb", "snat"),
            rel("6", "ORIG_SRC", "snat", "inside"),
            rel("7", "XLATE_SRC", "snat", "outside"),
        ],
    )
    ctx = context()
    done = StateKey("delivery", ctx)
    expansion = expand_device_gates(graph, ctx, "dev", None, None, done)
    assert expansion.entry.stage == "dnat"
    assert {item.key.stage for item in expansion.nodes} >= {"dnat", "snat"}
    model_input = ModelInput(MANIFEST, (*expansion.nodes,), (), (ChoiceAssignment("only"),), True)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        model = compile_model(model_input, manager, frozenset(manager.schema.field_names))
        by_stage = {item.key.stage: item for item in model.nodes}
        flow = initial_relation(
            header(manager, {"source_address": "10.0.0.5", "destination_address": "203.0.113.10"})
        )
        after_dnat = by_stage["dnat"].edges[0].relation.image(flow)
        after_snat = by_stage["snat"].edges[0].relation.image(after_dnat)
        assert {r["destination_address"] for r in after_snat.render(["destination_address"]).rows} == {
            int.from_bytes(bytes((10, 0, 0, 10)), "big")
        }
        assert {r["source_address"] for r in after_snat.render(["source_address"]).rows} == {
            int.from_bytes(bytes((192, 0, 2, 10)), "big")
        }
        assert {
            r["destination_address"] for r in after_snat.render(["destination_address"], bank="original").rows
        } == {int.from_bytes(bytes((203, 0, 113, 10)), "big")}


def test_unknown_nat_pool_is_an_explicit_terminal_not_fallthrough():
    graph = inventory(
        [
            node("dev", ["Device"]),
            node("rb", ["FwRulebase"], kind="nat"),
            node("n", ["NatRule"], kind="snat", enabled=True, translation="pool"),
        ],
        [rel("1", "ENFORCES", "dev", "rb"), rel("2", "HAS_RULE", "rb", "n")],
    )
    expansion = expand_device_gates(graph, context(), "dev", None, None, StateKey("done", context()))
    assert "NAT_POOL_ALLOCATION_UNKNOWN" in expansion.gaps
    assert any(item.terminal == "unknown" for item in expansion.nodes)


def test_load_balancer_members_are_correlated_choices_and_unknown_health_survives():
    graph = inventory(
        [
            node("dev", ["Device"]),
            node("vs", ["VirtualService"], proto="tcp", port=443),
            node("vip", ["IpAddress"], ip="198.51.100.10"),
            node("pool", ["Pool"]),
            node("m1", ["PoolMember"], state="up", port=8443),
            node("m2", ["PoolMember"], state="starting"),
            node("ip1", ["IpAddress"], ip="10.0.0.1"),
            node("ip2", ["IpAddress"], ip="10.0.0.2"),
        ],
        [
            rel("1", "ON", "vs", "dev"),
            rel("2", "VIP", "vs", "vip"),
            rel("3", "USES", "vs", "pool"),
            rel("4", "HAS_MEMBER", "pool", "m1"),
            rel("5", "HAS_MEMBER", "pool", "m2"),
            rel("6", "TARGETS", "m1", "ip1"),
            rel("7", "TARGETS", "m2", "ip2"),
        ],
    )
    expansion = expand_device_gates(graph, context(), "dev", None, None, StateKey("done", context()))
    assert "LOAD_BALANCER_MEMBER_HEALTH_UNKNOWN" in expansion.gaps
    assert any(dict(choice.bindings).keys() == {"lb:graph:domain:vs"} for choice in expansion.choices)
    assert any(item.terminal == "unknown" for item in expansion.nodes)


def test_choice_products_never_recombine_incompatible_scopes():
    routing = (ChoiceAssignment("r1", (("ecmp", "a"),)), ChoiceAssignment("r2", (("ecmp", "b"),)))
    gates = (ChoiceAssignment("g1", (("lb", "x"),)), ChoiceAssignment("g2", (("lb", "y"),)))
    merged = merge_choice_assignments(routing, gates)
    assert len(merged) == 4
    assert all({scope for scope, _ in item.bindings} == {"ecmp", "lb"} for item in merged)


def test_pbr_redirect_uses_qualified_routing_target():
    graph = inventory(
        [
            node("dev", ["Device"]),
            node("in", ["Interface"]),
            node("policy", ["PbrPolicy"]),
            node("rule", ["PbrRule"], position=1),
            node("alternate", ["VrfInstance"]),
        ],
        [
            rel("1", "ENFORCES", "in", "policy"),
            rel("2", "HAS_RULE", "policy", "rule"),
            rel("3", "REDIRECTS_VIA", "rule", "alternate"),
        ],
    )
    target = StateKey("routing:alternate:ingress:in", context())
    expansion = expand_device_gates(
        graph,
        context(),
        "dev",
        "in",
        None,
        StateKey("routing:default", context()),
        phases=("pbr",),
        routing_targets={"alternate": target},
    )
    assert any(edge.target == target for item in expansion.nodes for edge in item.edges)


def test_zpa_broker_uses_identity_policy_and_healthy_connector_address():
    graph = inventory(
        [
            node("id", ["IdentityGroup"]),
            node("seg", ["ZpaAppSegment"], tcp_port_ranges=("443", "443")),
            node("dest", ["IpAddress"], ip="10.1.0.5"),
            node("rule", ["ZpaAccessRule"], position=1, action="ALLOW", applies_to_all_identities=False),
            node("sg", ["ZpaServerGroup"]),
            node("cg", ["ZpaAppConnectorGroup"]),
            node("conn", ["ZpaAppConnector"], health="UP"),
            node("host", ["Vm"]),
            node("nic", ["Vnic"]),
            node("cip", ["IpAddress"], ip="192.0.2.10"),
        ],
        [
            rel("1", "RESOLVES_TO", "seg", "dest"),
            rel("2", "FOR", "rule", "seg"),
            rel("3", "GRANTS", "rule", "id"),
            rel("4", "SERVED_BY", "seg", "sg"),
            rel("5", "USES", "sg", "cg"),
            rel("6", "HAS", "cg", "conn"),
            rel("7", "RUNS_ON", "conn", "host"),
            rel("8", "OF", "nic", "host"),
            rel("9", "HAS_IP", "nic", "cip"),
        ],
    )
    expansion = expand_zpa_broker(graph, context(), "id", "seg", StateKey("routing:connector", context()))
    assert expansion.complete
    assert expansion.entry.stage == "proxy"
    edge = next(edge for item in expansion.nodes for edge in item.edges)
    assert dict(edge.rewrites)["source_address"] == int.from_bytes(bytes((192, 0, 2, 10)), "big")
    assert expansion.choices[0].bindings[0][0] == "zpa:graph:seg"


def test_zpa_broker_skips_a_disabled_connector_whatever_its_health():
    graph = inventory(
        [
            node("id", ["IdentityGroup"]),
            node("seg", ["ZpaAppSegment"], tcp_port_ranges=("443", "443")),
            node("dest", ["IpAddress"], ip="10.1.0.5"),
            node("rule", ["ZpaAccessRule"], position=1, action="ALLOW", applies_to_all_identities=False),
            node("sg", ["ZpaServerGroup"]),
            node("cg", ["ZpaAppConnectorGroup"]),
            node("conn", ["ZpaAppConnector"], health="up", enabled=False),
            node("host", ["Vm"]),
            node("nic", ["Vnic"]),
            node("cip", ["IpAddress"], ip="192.0.2.10"),
        ],
        [
            rel("1", "RESOLVES_TO", "seg", "dest"),
            rel("2", "FOR", "rule", "seg"),
            rel("3", "GRANTS", "rule", "id"),
            rel("4", "SERVED_BY", "seg", "sg"),
            rel("5", "USES", "sg", "cg"),
            rel("6", "HAS", "cg", "conn"),
            rel("7", "RUNS_ON", "conn", "host"),
            rel("8", "OF", "nic", "host"),
            rel("9", "HAS_IP", "nic", "cip"),
        ],
    )
    expansion = expand_zpa_broker(graph, context(), "id", "seg", StateKey("routing:connector", context()))
    # every connector is disabled: one deny verdict, as path/gates/zpa.py gives
    assert expansion.complete
    assert any(node.terminal == "deny" for node in expansion.nodes)
    assert not expansion.gaps


def test_aci_contract_without_collected_filter_is_unknown_not_permit():
    graph = inventory(
        [
            node("s", ["Endpoint"]),
            node("d", ["Endpoint"]),
            node("sip", ["IpAddress"], ip="10.0.0.1"),
            node("dip", ["IpAddress"], ip="10.0.0.2"),
            node("se", ["Epg"]),
            node("de", ["Epg"]),
            node("contract", ["Contract"]),
            # both EPGs in a bridge domain of the entry VRF, so the flow is a
            # fabric flow the contract decides (the gate scopes endpoints by VRF)
            node("bd", ["BridgeDomain"]),
            node("vrf", ["VrfInstance"]),
        ],
        [
            rel("1", "HAS_IP", "s", "sip"),
            rel("2", "HAS_IP", "d", "dip"),
            rel("3", "IN_EPG", "s", "se"),
            rel("4", "IN_EPG", "d", "de"),
            rel("5", "CONSUMES", "se", "contract"),
            rel("6", "PROVIDES", "de", "contract"),
            rel("7", "IN_BD", "se", "bd"),
            rel("8", "IN_BD", "de", "bd"),
            rel("9", "IN_VRF", "bd", "vrf"),
        ],
    )
    expansion = expand_aci_contracts(graph, context(), StateKey("routing", context()))
    assert not expansion.complete
    assert "ACI_CONTRACT_FILTER_UNKNOWN" in expansion.gaps
    assert any(item.terminal == "unknown" for item in expansion.nodes)
