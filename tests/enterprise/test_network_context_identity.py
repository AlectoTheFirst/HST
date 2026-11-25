"""Routing states of contexts without one owning device, and the access
rulebases a device state binds.

An ACI fabric VRF spans its leaves and a PBR redirect table has no interface
of its own. Their states name the device of the ingress interface; a state
whose device is not known is an unknown terminal that names the context, not
an exception that fails the whole model. A NAT rulebase is never an access
layer, and a zone-pair rulebase is bound only for the zones the flow uses.
"""

from __future__ import annotations

import importlib
import ipaddress
import os
from types import MappingProxyType

import pytest

from hst.analysis_model.gates import expand_aci_contracts
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import StateKey
from hst.analysis_model.network import (
    _bindings,
    _egress_scoped,
    normalize_network,
    normalize_reply_network,
)
from hst.impact.evaluate import Interface, Member, Network, RequestSet, Service, member
from hst.policy.ir import AllOf, Atom, Constant, ExecutionContext, Predicate, Unknown
from hst.simul.rib import RibInput

MANIFEST = "a" * 64


class _Gates:
    def with_changes(self, _changes):
        return self


def _ivals(text: str):
    network = ipaddress.ip_network(text)
    return ((network.version, int(network.network_address), int(network.broadcast_address)),)


def _node(uid: str, labels: list[str], **props) -> GraphNode:
    return GraphNode(uid, frozenset(labels), MappingProxyType({"uid": uid, **props}))


def _graph(nodes: list[GraphNode] = (), relations: list[tuple[str, str, str]] = ()) -> GraphInventory:  # type: ignore[assignment]
    outgoing: dict[tuple[str, str], list[GraphRelation]] = {}
    incoming: dict[tuple[str, str], list[GraphRelation]] = {}
    labels: dict[str, list[str]] = {}
    for item in nodes:
        for label in item.labels:
            labels.setdefault(label, []).append(item.uid)
    for index, (kind, start, end) in enumerate(relations):
        relation = GraphRelation(f"r{index}", kind, start, end, MappingProxyType({}))
        outgoing.setdefault((start, kind), []).append(relation)
        incoming.setdefault((end, kind), []).append(relation)
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


def _fabric() -> Network:
    """A router r1 in context c1 sends 203.0.113.0/24 to a fabric VRF `fab`
    that spans leaves l1 and l2: it enters the fabric on l1 and leaves by the
    server subnet's gateway on l2. `redirect` is a PBR table with no device."""
    return Network(
        RibInput(
            contexts=[
                {"uid": "c1", "device_uid": "r1", "platform": "nxos"},
                {"uid": "fab", "device_uid": None, "device_uids": ["l1", "l2"], "platform": "apic"},
                {"uid": "redirect", "device_uid": None, "device_uids": [], "platform": None},
            ],
            connected=[
                {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "lan"},
                {"context_uid": "c1", "prefix": "192.0.2.0/30", "interface": "wan"},
                {"context_uid": "fab", "prefix": "192.0.2.0/30", "interface": "uplink"},
                {"context_uid": "fab", "prefix": "203.0.113.0/24", "interface": "servers"},
            ],
            static=[
                {"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"},
                # the redirect table's host route resolves its next hop, as the demo estate's does
                {"context_uid": "redirect", "prefix": "192.0.2.1/32"},
                {"context_uid": "redirect", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.1"},
            ],
        ),
        (
            Interface("r1", "if:r1:lan", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
            Interface("r1", "if:r1:wan", "wan", "c1", ("192.0.2.0/30",), ("192.0.2.1",)),
            Interface("l1", "if:l1:uplink", "uplink", "fab", ("192.0.2.0/30",), ("192.0.2.2",)),
            Interface("l2", "if:l2:servers", "servers", "fab", ("203.0.113.0/24",), ("203.0.113.1",)),
        ),
        _Gates(),
    )


def _request(source: str, destination: str, *, source_context: str | None = None) -> RequestSet:
    return RequestSet(
        "flow",
        _ivals(source),
        "server",
        (Member("server", _ivals(destination)),),
        member("server"),
        Service(frozenset({6}), ((4, 443, 443),)),
        source_context=source_context,
    )


def test_a_fabric_vrf_state_names_the_device_its_ingress_interface_is_on():
    request = _request("10.0.0.10/32", "203.0.113.10/32", source_context="c1")
    model = normalize_network(_fabric(), _graph(), request, request.members[0], "estate")

    states = {node.key.location: node for node in model.nodes}
    entered = states["routing:fab:ingress:if:l1:uplink"]
    assert entered.key.context.firewall_instance == "l1"
    assert entered.key.context.vrf == "fab"
    assert entered.terminal is None and entered.edges
    # the fabric delivers by the gateway on l2; the reply binding names that interface
    delivery = next(node for node in model.nodes if node.key.location == "delivery:fab:203.0.113.0/24")
    assert delivery.key.binding_scope == ("reply-ingress:if:l2:servers",)


def test_a_state_whose_device_is_unknown_is_a_named_unknown_terminal_not_an_exception():
    # The source context `redirect` has no owning device and no interface, so
    # neither the context nor an ingress names the device of its state.
    request = _request("198.51.100.10/32", "203.0.113.10/32", source_context="redirect")
    model = normalize_network(_fabric(), _graph(), request, request.members[0], "estate")

    (entry,) = model.entries
    assert entry.key.location == "terminal:context-device-unknown:redirect:ingress:none"
    assert entry.key.context.vrf == "redirect"
    assert entry.key.context.firewall_instance == "unknown"
    node = next(item for item in model.nodes if item.key == entry.key)
    assert node.terminal == "unknown" and node.complete is False


def test_sources_in_a_fabric_vrf_enter_by_the_interface_that_holds_them():
    request = _request("203.0.113.20/32", "192.0.2.1/32")
    model = normalize_network(_fabric(), _graph(), request, request.members[0], "estate")

    (entry,) = model.entries
    assert entry.key.location == "routing:fab:ingress:if:l2:servers"
    assert entry.key.context.firewall_instance == "l2"


def test_a_redirect_table_without_a_device_is_consulted_on_the_redirecting_device():
    graph = _graph(
        [
            _node("if:l1:uplink", ["Interface"], name="uplink"),
            _node("pbr", ["PbrPolicy"]),
            _node("pbr-rule", ["FwRule"], position=1),
            _node("redirect", ["VrfInstance"], name="redirect"),
        ],
        [
            ("ENFORCES", "if:l1:uplink", "pbr"),
            ("HAS_RULE", "pbr", "pbr-rule"),
            ("REDIRECTS_VIA", "pbr-rule", "redirect"),
        ],
    )
    request = _request("10.0.0.10/32", "203.0.113.10/32", source_context="c1")
    model = normalize_network(_fabric(), graph, request, request.members[0], "estate", _all_routes=True)

    states = {node.key.location: node for node in model.nodes}
    redirected = states["routing:redirect:ingress:if:l1:uplink"]
    assert redirected.key.context.firewall_instance == "l1"
    assert redirected.terminal is None
    # the table entered without an ingress has no device to name
    assert states["terminal:context-device-unknown:redirect:ingress:none"].terminal == "unknown"


def test_the_entry_attaches_sources_without_restating_the_service():
    request = _request("10.0.0.10/32", "203.0.113.10/32", source_context="c1")
    model = normalize_network(_fabric(), _graph(), request, request.members[0], "estate")

    def fields(predicate: Predicate) -> set[str]:
        if isinstance(predicate, Atom):
            return {predicate.field}
        return {field for term in getattr(predicate, "terms", ()) for field in fields(term)}

    (entry,) = model.entries
    assert fields(entry.predicate) == {"source_address", "destination_address"}


def test_a_reply_enters_the_delivery_context_by_the_interface_the_request_left_by():
    request = _request("10.0.0.10/32", "203.0.113.10/32", source_context="c1")
    network = _fabric()
    forward = normalize_network(network, _graph(), request, request.members[0], "estate")
    deliveries = tuple(
        node.key
        for node in forward.nodes
        if node.terminal == "permit" and node.key.location.startswith("delivery:")
    )
    assert deliveries

    reply = normalize_reply_network(network, _graph(), request, request.members[0], "estate", deliveries)

    (entry,) = reply.entries
    assert entry.key.location == "routing:fab:ingress:if:l2:servers"
    assert entry.key.context.firewall_instance == "l2"


def _context(device: str = "fw") -> ExecutionContext:
    return ExecutionContext("estate", "graph", "graph", device, "vrf", 4)


def test_a_nat_rulebase_is_not_bound_as_an_access_layer():
    graph = _graph(
        [
            _node("fw", ["Device"], role="firewall"),
            _node("access", ["FwRulebase"], kind="access", default_action="drop"),
            _node("nat", ["FwRulebase"], kind="nat"),
            _node("snat", ["NatRule"], kind="snat", out_if="port3"),
        ],
        [("ENFORCES", "fw", "access"), ("ENFORCES", "fw", "nat"), ("HAS_RULE", "nat", "snat")],
    )
    rulebases, installation = _bindings(graph, _context(), None, None, 4)

    assert rulebases == ("access",)
    assert installation == Unknown("INSTALLATION_UNKNOWN", "fw")


def _zone_pairs() -> GraphInventory:
    nodes = [
        _node("fgt", ["Device"], role="firewall"),
        _node("if:port1", ["Interface"], name="port1"),
        _node("if:port2", ["Interface"], name="port2"),
        _node("if:port3", ["Interface"], name="port3"),
        _node("zone:corp", ["Zone"], name="corp"),
        _node("zone:guest", ["Zone"], name="guest"),
        _node("zone:wan", ["Zone"], name="wan"),
    ]
    relations = [
        ("CONTAINS", "zone:corp", "if:port1"),
        ("CONTAINS", "zone:guest", "if:port2"),
        ("CONTAINS", "zone:wan", "if:port3"),
    ]
    for name, source, destination in (("corp-wan", "corp", "wan"), ("guest-wan", "guest", "wan")):
        nodes.append(
            _node(name, ["FwRulebase"], kind="access", default_action="drop", match_context="zone-pair")
        )
        relations += [
            ("ENFORCES", "fgt", name),
            ("FROM_ZONE", name, f"zone:{source}"),
            ("TO_ZONE", name, f"zone:{destination}"),
        ]
    return _graph(nodes, relations)


def test_a_zone_pair_rulebase_is_bound_only_for_the_zones_the_flow_uses():
    graph = _zone_pairs()
    context = _context("fgt")

    assert _bindings(graph, context, "if:port1", "if:port3", 4)[0] == ("corp-wan",)
    assert _bindings(graph, context, "if:port2", "if:port3", 4)[0] == ("guest-wan",)
    # no rulebase receives corp to guest: the destination zone's default applies, as in the tracer
    assert _bindings(graph, context, "if:port1", "if:port2", 4)[0] == ("zone:guest",)
    # an unnamed egress leaves the destination zone open: bound, with the gap named
    rulebases, installation = _bindings(graph, context, "if:port1", None, 4)
    assert rulebases == ("corp-wan",)
    assert installation == AllOf(
        (Unknown("INSTALLATION_UNKNOWN", "fgt"), Unknown("RULEBASE_SCOPE_UNKNOWN", "corp-wan"))
    )
    # its destination zone names the egress, so the policy is applied per FIB edge
    assert _egress_scoped(graph, context, "if:port1", 4) is True


def test_installation_evidence_binds_exactly():
    graph = _zone_pairs()
    relations = dict(graph.incoming)
    exact = MappingProxyType(
        {
            "installed": True,
            "coverage": "complete",
            "installed_revision": "r1",
            "context_uid": "vrf",
            "ingress_interface_uid": "*",
            "egress_interface_uid": "*",
            "address_family": 4,
        }
    )
    relations["corp-wan", "ENFORCES"] = (GraphRelation("installed", "ENFORCES", "fgt", "corp-wan", exact),)
    installed = GraphInventory(
        graph.manifest_digest,
        graph.fingerprint,
        graph.nodes,
        graph.labels,
        graph.outgoing,
        MappingProxyType(relations),
        True,
        (),
        0,
    )
    assert _bindings(installed, _context("fgt"), "if:port1", "if:port3", 4) == (("corp-wan",), Constant(True))


def test_the_aci_gate_state_is_complete_and_leaves_unknown_to_the_intra_epg_pairs():
    graph = _graph(
        [
            _node("web", ["Endpoint"]),
            _node("db", ["Endpoint"]),
            _node("ip-web", ["IpAddress"], ip="10.0.1.1"),
            _node("ip-db", ["IpAddress"], ip="10.0.2.1"),
            _node("epg-web", ["Epg"]),
            _node("epg-db", ["Epg"]),
            _node("bd", ["BridgeDomain"]),
            _node("vrf", ["Vrf"], pc_enf_pref="enforced", contract_bypass=""),
        ],
        [
            ("HAS_IP", "web", "ip-web"),
            ("HAS_IP", "db", "ip-db"),
            ("IN_EPG", "web", "epg-web"),
            ("IN_EPG", "db", "epg-db"),
            ("IN_BD", "epg-web", "bd"),
            ("IN_BD", "epg-db", "bd"),
            ("IN_VRF", "bd", "vrf"),
        ],
    )
    context = _context()
    expansion = expand_aci_contracts(graph, context, StateKey("routing", context))

    # a flow with only one ACI endpoint is unknown as well
    assert expansion.gaps == ("ACI_INTRA_EPG_ISOLATION_UNKNOWN", "ACI_ONE_ENDPOINT_UNKNOWN")
    gate = next(node for node in expansion.nodes if node.key == expansion.entry)
    assert gate.complete is True
    unknown = {node.key for node in expansion.nodes if node.terminal == "unknown"}
    intra = {edge.target for edge in gate.edges if edge.uid.startswith("aci:intra:")}
    one_end = {edge.target for edge in gate.edges if edge.uid == "aci:one-endpoint"}
    assert len(intra) == 2 and len(one_end) == 1
    assert intra | one_end == unknown


def _native():
    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


def test_a_given_source_context_attaches_every_source_of_a_port_request():
    _native()
    from hst.analysis_model.compile import compile_model
    from hst.assessment.symbolic_evaluation import member_packets
    from hst.impact.symbolic_walk import walk
    from hst.symbolic import HeaderSchema, SymbolicManager

    request = _request("10.0.0.10/32", "203.0.113.10/32", source_context="c1")
    source = normalize_network(_fabric(), _graph(), request, request.members[0], "estate")
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = member_packets(manager, request, request.members[0])
        # a stated nonzero port holds the fragment offset at 0, so it is stated knowledge
        assert "fragment_offset" in packets.known_fields
        model = compile_model(source, manager, packets.known_fields)
        result = walk(model, packets, request_id="flow")

    assert "SOURCE_ATTACHMENT_UNKNOWN" not in result.gap_refs
