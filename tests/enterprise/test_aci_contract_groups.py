"""The ACI contract gate grows with EPGs, not with endpoint pairs, and keeps its packet sets."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from types import MappingProxyType

import pytest
from tests.support.batch_inventory import inventory as batch_inventory

from hst.analysis_model import gates
from hst.analysis_model.compile import compile_model
from hst.analysis_model.gates import expand_aci_contracts
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import ChoiceAssignment, EdgeSpec, ModelInput, NodeSpec, StateKey
from hst.core.aci_filter import vrf_enforcement
from hst.core.fixtures import load_fixture
from hst.policy.ir import AllOf, AnyOf, Atom, ExecutionContext, Not

DEMO = Path(__file__).parents[2] / "fixtures" / "demo-enterprise" / "estate-v3.yaml"
MANIFEST = "a" * 64


def inventory(nodes, relations):
    outgoing, incoming, labels = {}, {}, {}
    for item in nodes:
        for label in item.labels:
            labels.setdefault(label, []).append(item.uid)
    for relation in relations:
        outgoing.setdefault((relation.start, relation.kind), []).append(relation)
        incoming.setdefault((relation.end, relation.kind), []).append(relation)
    return GraphInventory(
        MANIFEST,
        "b" * 64,
        MappingProxyType({item.uid: item for item in nodes}),
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


def _context():
    return ExecutionContext("estate", "graph", "domain", "dev", "vrf", 4)


def test_the_demo_estate_contract_gate_has_one_group_per_epg_pair_with_a_contract():
    # the gate scopes its endpoints to the VRF the request enters in, so
    # the request enters in the dc1 fabric VRF; in a VRF outside every fabric
    # the gate has no source endpoint and no EPG pair to group.
    graph = batch_inventory(load_fixture(DEMO))
    vrf = "vrf:aci:fab-dc1:tn-PROD:CTX1"
    context = ExecutionContext("estate", "graph", "domain", "dev", vrf, 4)
    downstream = StateKey("routing", context)
    expansion = expand_aci_contracts(graph, context, downstream)
    # the gate of the entry VRF is the entry, and the gate of the dc2 fabric follows it
    (gate,) = [item for item in expansion.nodes if item.key == expansion.entry]
    targets = {edge.target for edge in gate.edges}
    epgs = {
        epgs[0].uid
        for uid in graph.labels["Endpoint"]
        if graph.targets(uid, "HAS_IP")
        and (epgs := graph.targets(uid, "IN_EPG"))
        and gates._aci_epg_vrf(graph, epgs[0].uid)[0] == vrf
    }
    assert epgs
    external = {uid for uid in graph.labels["ExtEpg"] if vrf in gates._aci_external_vrfs(graph, uid)}
    assert external
    contracted = {
        (source, destination)
        for source in epgs
        for destination in epgs | external
        if source != destination
        and {item.uid for item in graph.targets(source, "CONSUMES")}
        & {item.uid for item in graph.targets(destination, "PROVIDES")}
    }
    endpoints = len(graph.labels["Endpoint"])
    # One intra edge and at most one deny edge per EPG, two edges per contracted
    # pair of an EPG and an EPG or an external EPG, and the reverse-contract,
    # the non-endpoint and the one-endpoint edge.
    assert len(gate.edges) <= 2 * len(epgs) + 2 * len(contracted) + 3
    assert len(targets) <= 2 * len(epgs) + len(contracted) + 3
    assert any(edge.uid.startswith("aci:permit:") for edge in gate.edges)
    assert len(gate.edges) < endpoints
    assert endpoints**2 > 50 * len(gate.edges)


def _per_endpoint_pair(graph, context, downstream):
    """The ungrouped expansion: one edge set per endpoint pair.

    It decides each pair by the governing VRF's enforcement mode as the gate
    does, and a flow with only one endpoint is unknown. The
    endpoints are scoped to the VRF the request enters in. A source endpoint
    is one of that VRF (or of an EPG whose VRF does not resolve); a
    destination endpoint is also one of a VRF on the same fabric, less the
    addresses the entry VRF holds. An address endpoints of two EPGs hold on
    one side is unknown, not decided once for each EPG."""
    key = StateKey(f"gate:aci:{context.vrf}", context, "aci-contract")
    edges, terminals = [], []

    def fabrics(vrf):
        return {
            fabric.uid
            for interface in graph.sources(vrf, "IN_VRF")
            if "Interface" in interface.labels
            for device in graph.targets(interface.uid, "ON")
            for fabric in graph.targets(device.uid, "MEMBER_OF")
        }

    def ranges(field, addresses):
        return AnyOf(tuple(Atom(field, "range", *value) for value in addresses))

    endpoints = []
    for uid in graph.labels.get("Endpoint", ()):
        addresses = [
            item
            for target in graph.targets(uid, "HAS_IP")
            for item in gates._node_intervals(target, context.address_family)
        ]
        epgs = graph.targets(uid, "IN_EPG")
        if addresses and epgs:
            endpoints.append((uid, addresses, epgs[0].uid, gates._aci_epg_vrf(graph, epgs[0].uid)[0]))
    owned = [
        address for _uid, addresses, _epg, vrf in endpoints if vrf == context.vrf for address in addresses
    ]
    sources, destinations = [], []
    for uid, addresses, epg, vrf in endpoints:
        if vrf in (context.vrf, None):
            sources.append((uid, ranges("source_address", addresses), epg))
            destinations.append((uid, ranges("destination_address", addresses), epg))
        elif fabrics(vrf) & fabrics(context.vrf):
            held = ranges("destination_address", owned)
            destinations.append((uid, AllOf((ranges("destination_address", addresses), Not(held))), epg))

    def held_twice(side):
        return AnyOf(
            tuple(
                AllOf((first, second))
                for index, (_uid, first, epg) in enumerate(side)
                for _other, second, other_epg in side[index + 1 :]
                if epg != other_epg
            )
        )

    ambiguous_sources, ambiguous_destinations = held_twice(sources), held_twice(destinations)
    placed_sources = [predicate for _uid, predicate, _epg in sources]
    placed_destinations = [predicate for _uid, predicate, _epg in destinations]
    for source, source_predicate, source_epg in sources:
        for destination, destination_predicate, destination_epg in destinations:
            pair = AllOf(
                (
                    source_predicate,
                    Not(ambiguous_sources),
                    destination_predicate,
                    Not(ambiguous_destinations),
                )
            )
            label = f"{source}:{destination}"
            contracts = {item.uid for item in graph.targets(source_epg, "CONSUMES")} & {
                item.uid for item in graph.targets(destination_epg, "PROVIDES")
            }
            (source_vrf, pref), (destination_vrf, _pref) = (
                gates._aci_epg_vrf(graph, source_epg),
                gates._aci_epg_vrf(graph, destination_epg),
            )
            enforcement = vrf_enforcement(source_vrf, destination_vrf, pref)
            undecided = StateKey(f"ref:enforcement-unknown:{label}", context)
            # a contract in the reverse orientation (the source EPG provides,
            # the destination EPG consumes) makes the enforced VRF's deny undecided
            reverse = {item.uid for item in graph.targets(source_epg, "PROVIDES")} & {
                item.uid for item in graph.targets(destination_epg, "CONSUMES")
            }
            reversed_target = StateKey(f"ref:reverse-contract:{label}", context)
            if source_epg == destination_epg:
                target = StateKey(f"ref:intra:{label}", context)
                terminals.append(NodeSpec(target, terminal="unknown", complete=False))
                edges.append(EdgeSpec(f"intra:{label}", target, pair))
            elif enforcement == "unenforced":
                edges.append(EdgeSpec(f"unenforced:{label}", downstream, pair))
            elif contracts:
                af = context.address_family
                filters = [gates._aci_contract_filter(graph, uid, af) for uid in sorted(contracts)]
                if filters and all(item is not None for item in filters):
                    allowed = AnyOf(tuple(item for item in filters if item is not None))
                    edges.append(EdgeSpec(f"permit:{label}", downstream, AllOf((pair, allowed))))
                    if enforcement == "enforced" and reverse:
                        target = reversed_target
                        terminals.append(NodeSpec(target, terminal="unknown", complete=False))
                    elif enforcement == "enforced":
                        target = StateKey(f"ref:filter-deny:{label}", context)
                        terminals.append(NodeSpec(target, terminal="deny"))
                    else:
                        target = undecided
                        terminals.append(NodeSpec(target, terminal="unknown", complete=False))
                    edges.append(EdgeSpec(f"filter-deny:{label}", target, AllOf((pair, Not(allowed)))))
                    continue
                target = StateKey(f"ref:unknown:{label}", context)
                terminals.append(NodeSpec(target, terminal="unknown", complete=False))
                edges.append(EdgeSpec(f"unknown:{label}", target, pair))
            elif enforcement == "enforced" and reverse:
                terminals.append(NodeSpec(reversed_target, terminal="unknown", complete=False))
                edges.append(EdgeSpec(f"reverse-contract:{label}", reversed_target, pair))
            elif enforcement == "enforced":
                target = StateKey(f"ref:deny:{label}", context)
                terminals.append(NodeSpec(target, terminal="deny"))
                edges.append(EdgeSpec(f"deny:{label}", target, pair))
            else:
                terminals.append(NodeSpec(undecided, terminal="unknown", complete=False))
                edges.append(EdgeSpec(f"enforcement-unknown:{label}", undecided, pair))
    any_source, any_destination = AnyOf(tuple(placed_sources)), AnyOf(tuple(placed_destinations))
    target = StateKey("ref:ambiguous", context)
    terminals.append(NodeSpec(target, terminal="unknown", complete=False))
    ambiguous = AnyOf((ambiguous_sources, ambiguous_destinations))
    edges.append(EdgeSpec("ambiguous", target, AllOf((any_source, any_destination, ambiguous))))
    edges.append(EdgeSpec("non-endpoint", downstream, AllOf((Not(any_source), Not(any_destination)))))
    target = StateKey("ref:one-endpoint", context)
    terminals.append(NodeSpec(target, terminal="unknown", complete=False))
    one_end = AnyOf((AllOf((any_source, Not(any_destination))), AllOf((Not(any_source), any_destination))))
    edges.append(EdgeSpec("one-endpoint", target, one_end))
    return key, (*terminals, NodeSpec(key, tuple(edges)))


def _outcomes(manager, entry, nodes, downstream):
    """The union of the gate's edge guards for each outcome its targets end in."""
    source = ModelInput(
        MANIFEST,
        tuple({item.key: item for item in (*nodes, NodeSpec(downstream, terminal="permit"))}.values()),
        (),
        (ChoiceAssignment("only"),),
        True,
    )
    model = compile_model(source, manager, frozenset(manager.schema.field_names))
    by_key = {item.key: item for item in model.nodes}
    terminal = {item.key: item.terminal for item in source.nodes}
    result = {}
    for edge in by_key[entry].edges:
        outcome = terminal[edge.target]
        result[outcome] = result[outcome].union(edge.guard) if outcome in result else edge.guard
    return result


def test_grouping_by_epg_keeps_the_packet_set_of_every_outcome():
    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")
    from hst.symbolic import HeaderSchema, SymbolicManager

    graph = inventory(
        [
            node("web1", ["Endpoint"]),
            node("web2", ["Endpoint"]),
            node("app1", ["Endpoint"]),
            node("db1", ["Endpoint"]),
            node("shared", ["Endpoint"]),
            node("unplaced", ["Endpoint"]),
            node("bare", ["Endpoint"]),
            node("ip-web1", ["IpAddress"], ip="10.0.1.1"),
            node("ip-web2", ["IpAddress"], ip="10.0.1.2"),
            node("ip-app1", ["IpAddress"], ip="10.0.2.1"),
            node("ip-db1", ["IpAddress"], ip="10.0.3.0/30"),
            node("ip-unplaced", ["IpAddress"], ip="10.0.9.9"),
            node("web", ["Epg"]),
            node("app", ["Epg"]),
            node("db", ["Epg"]),
            node("web-to-app", ["Contract"]),
            node("subject", ["ContractSubject"]),
            node("filter", ["AciFilter"]),
            node(
                "entry",
                ["FilterEntry"],
                proto="tcp",
                ether_type="ip",
                s_from_port="unspecified",
                s_to_port="unspecified",
                d_from_port=8080,
                d_to_port=8080,
                # written on every vzEntry by apic.py
                tcp_rules="unspecified",
                apply_to_frag="no",
            ),
            node("app-to-db", ["Contract"]),
            # an EPG in another VRF: its pairs have no known enforcement mode
            node("other1", ["Endpoint"]),
            node("ip-other1", ["IpAddress"], ip="10.0.4.1"),
            node("other", ["Epg"]),
            node("bd", ["BridgeDomain"]),
            node("bd-other", ["BridgeDomain"]),
            node("vrf", ["Vrf"], pc_enf_pref="enforced", contract_bypass=""),
            node("vrf-other", ["Vrf"], pc_enf_pref="enforced", contract_bypass=""),
            # both VRFs are on one fabric, so the other VRF's endpoint
            # is a destination of a request that enters in "vrf"
            node("fabric", ["Fabric"]),
            node("leaf", ["Device"]),
            node("leaf-if", ["Interface"]),
            node("leaf-if-other", ["Interface"]),
            # an app endpoint whose address no other EPG holds, so the app EPG
            # keeps a decided pair with db
            node("app2", ["Endpoint"]),
            node("ip-app2", ["IpAddress"], ip="10.0.2.2"),
        ],
        [
            rel("1", "HAS_IP", "web1", "ip-web1"),
            rel("2", "HAS_IP", "web2", "ip-web2"),
            rel("3", "HAS_IP", "app1", "ip-app1"),
            rel("4", "HAS_IP", "db1", "ip-db1"),
            # an address held by endpoints of two EPGs is unknown
            rel("5", "HAS_IP", "shared", "ip-app1"),
            rel("6", "HAS_IP", "unplaced", "ip-unplaced"),
            rel("7", "IN_EPG", "web1", "web"),
            rel("8", "IN_EPG", "web2", "web"),
            rel("9", "IN_EPG", "app1", "app"),
            rel("10", "IN_EPG", "db1", "db"),
            rel("11", "IN_EPG", "shared", "db"),
            rel("12", "IN_EPG", "bare", "db"),
            rel("13", "CONSUMES", "web", "web-to-app"),
            rel("14", "PROVIDES", "app", "web-to-app"),
            rel("15", "HAS", "web-to-app", "subject"),
            rel("16", "USES_FILTER", "subject", "filter"),
            rel("17", "HAS", "filter", "entry"),
            rel("18", "CONSUMES", "app", "app-to-db"),
            rel("19", "PROVIDES", "db", "app-to-db"),
            rel("20", "HAS_IP", "other1", "ip-other1"),
            rel("21", "IN_EPG", "other1", "other"),
            rel("22", "IN_BD", "web", "bd"),
            rel("23", "IN_BD", "app", "bd"),
            rel("24", "IN_BD", "db", "bd"),
            rel("25", "IN_VRF", "bd", "vrf"),
            rel("26", "IN_BD", "other", "bd-other"),
            rel("27", "IN_VRF", "bd-other", "vrf-other"),
            rel("28", "MEMBER_OF", "leaf", "fabric"),
            rel("29", "ON", "leaf-if", "leaf"),
            rel("30", "ON", "leaf-if-other", "leaf"),
            rel("31", "IN_VRF", "leaf-if", "vrf"),
            rel("32", "IN_VRF", "leaf-if-other", "vrf-other"),
            rel("33", "HAS_IP", "app2", "ip-app2"),
            rel("34", "IN_EPG", "app2", "app"),
        ],
    )
    context = _context()
    downstream = StateKey("routing", context)
    grouped = expand_aci_contracts(graph, context, downstream)
    assert set(grouped.gaps) == {
        "ACI_CONTRACT_FILTER_UNKNOWN",
        "ACI_ENDPOINT_IDENTITY_UNKNOWN",
        "ACI_INTRA_EPG_ISOLATION_UNKNOWN",
        "ACI_ONE_ENDPOINT_UNKNOWN",
        "ACI_REVERSE_CONTRACT_UNEVALUATED",
        "ACI_VRF_ENFORCEMENT_UNKNOWN",
    }
    reference_entry, reference_nodes = _per_endpoint_pair(graph, context, downstream)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        expected = _outcomes(manager, reference_entry, reference_nodes, downstream)
        actual = _outcomes(manager, grouped.entry, grouped.nodes, downstream)
        assert set(actual) == set(expected) == {"permit", "deny", "unknown"}
        for outcome, packets in expected.items():
            assert actual[outcome].equivalent(packets), outcome
