"""`normalize_network` reads the RIB of the current Network."""

from dataclasses import replace
from types import MappingProxyType

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import ChoiceAssignment, EdgeSpec, NodeSpec, StateKey
from hst.analysis_model.network import (
    _bindings,
    _choice_catalog,
    _tunnel_targets,
    normalize_network,
    normalize_request_network,
)
from hst.analysis_model.overlay import _rebuild
from hst.impact.evaluate import Interface, Member, Network, RequestSet, member
from hst.policy.ir import AllOf, Constant, ExecutionContext, Not, Unknown
from hst.simul.rib import RibInput


class _Gates:
    def with_changes(self, _changes):
        return self


def _ivals(text):
    import ipaddress

    address = ipaddress.ip_address(text)
    return ((address.version, int(address), int(address)),)


def _graph():
    return GraphInventory(
        "a" * 64,
        "fingerprint",
        MappingProxyType({}),
        MappingProxyType({}),
        MappingProxyType({}),
        MappingProxyType({}),
        True,
        (),
        0,
    )


def _contexts_graph(**contexts):
    """Each context a recorded VrfInstance: True a global table, a string a
    non-global VRF of that name, None a VRF whose kind was not recorded."""
    nodes = {}
    for uid, kind in contexts.items():
        props = (
            {"is_global": True}
            if kind is True
            else {}
            if kind is None
            else {"is_global": False, "name": kind}
        )
        nodes[uid] = GraphNode(uid, frozenset({"VrfInstance"}), MappingProxyType(props))
    return _rebuild(_graph(), nodes, [])


def _network():
    return Network(
        RibInput(
            contexts=[
                {"uid": "c1", "device_uid": "r1", "platform": "nxos"},
                {"uid": "c2", "device_uid": "r2", "platform": "nxos"},
            ],
            connected=[
                {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "lan"},
                {"context_uid": "c1", "prefix": "192.0.2.0/24", "interface": "wan"},
                {"context_uid": "c2", "prefix": "203.0.113.0/24", "interface": "lan"},
            ],
            static=[
                {"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"},
            ],
        ),
        (
            Interface("r1", "if:r1:lan", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
            Interface("r1", "if:r1:wan", "wan", "c1", ("192.0.2.0/24",), ("192.0.2.1",)),
            Interface("r2", "if:r2:lan", "lan", "c2", ("203.0.113.0/24",), ("192.0.2.2",)),
        ),
        _Gates(),
    )


def test_graph_backed_adapter_follows_existing_rib_next_hop_and_delivery():
    request = RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    model = normalize_request_network(_network(), _contexts_graph(c1=True, c2=True), request, "estate")[
        "server"
    ]

    routing = {node.key.location: node for node in model.nodes if node.key.location.startswith("routing:")}
    c1 = next(node for location, node in routing.items() if location.startswith("routing:c1:"))
    assert any(edge.target.location.startswith("routing:c2:") for edge in c1.edges)
    assert any(node.key.location.startswith("delivery:c2:203.0.113.0/24") for node in model.nodes)
    assert model.entries[0].key.location == "routing:c1:ingress:if:r1:lan"
    assert model.choices_complete is True


def test_every_member_uses_the_same_routing_choice_catalog():
    request = RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "servers",
        (Member("one", _ivals("203.0.113.10")), Member("two", _ivals("203.0.113.11"))),
        member("one"),
        source_context="c1",
    )
    models = normalize_request_network(_network(), _graph(), request, "estate")

    assert models["one"].choices == models["two"].choices
    assert models["one"].entries[0].predicate != models["two"].entries[0].predicate


def test_unrelated_ecmp_groups_are_outside_request_scope_and_choice_growth_is_bounded():
    rows = [
        {"context_uid": f"unused:{group}", "prefix": f"10.{group}.0.0/16"}
        for group in range(11)
        for _alternative in range(2)
    ]
    choices, alternatives, complete = _choice_catalog(rows, maximum=1024)

    assert complete is False
    assert alternatives == {}
    assert choices[0].uid == "routing:resource-cutoff"


def test_empty_or_incomplete_rib_becomes_unknown_entry_not_a_denial():
    network = Network(
        RibInput(contexts=[{"uid": "c1", "device_uid": "r1", "platform": "nxos"}]),
        (Interface("r1", "if:r1:lan", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),),
        _Gates(),
    )
    request = RequestSet(
        "unknown",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    model = normalize_request_network(network, _graph(), request, "estate")["server"]

    assert model.nodes[0].terminal == "unknown"
    assert model.nodes[0].complete is False


def test_lpm_discard_edge_excludes_the_more_specific_prefix_from_permit_route():
    network = _network()
    network.routes.rib.extend(
        [
            {"context_uid": "c1", "af": 4, "prefix": "198.51.0.0/16", "interface": "wan"},
            {"context_uid": "c1", "af": 4, "prefix": "198.51.2.0/24", "discard": True},
        ]
    )
    request = RequestSet(
        "lpm",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("198.51.2.1")),),
        member("server"),
        source_context="c1",
    )
    model = normalize_network(network, _graph(), request, request.members[0], "estate")
    route = next(node for node in model.nodes if node.key.location == "routing:c1:ingress:none")

    assert len(route.edges) == 2
    assert any(edge.target.location.startswith("terminal:discard") for edge in route.edges)
    assert any(
        isinstance(edge.predicate, AllOf) and isinstance(edge.predicate.terms[1], Not) for edge in route.edges
    )


def test_unresolved_next_hop_is_not_promoted_to_delivery():
    network = _network()
    network.routing.static[0]["next_hop"] = "192.0.2.254"
    request = RequestSet(
        "unknown-hop",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    model = normalize_network(network, _graph(), request, request.members[0], "estate")

    assert any(node.key.location.startswith("terminal:unknown-hop:c1:203.0.113.0/24") for node in model.nodes)


def test_proven_carrier_route_and_reciprocal_peer_link_remote_overlay():
    def n(uid, labels, **props):
        return GraphNode(uid, frozenset(labels), MappingProxyType(props))

    def r(uid, kind, start, end):
        return GraphRelation(uid, kind, start, end, MappingProxyType({}))

    nodes = {
        item.uid: item
        for item in (
            n("r1", {"Device"}),
            n("r2", {"Device"}),
            n("overlay1", {"Interface"}),
            n("overlay2", {"Interface"}),
            n("remote-wan", {"Interface"}),
            n("far", {"IpAddress"}, ip="198.51.100.2"),
            n("local", {"IpAddress"}, ip="198.51.100.1"),
            n(
                "t1",
                {"Tunnel"},
                state="up",
                local_address="198.51.100.1",
                encap="wireguard",
                carrier_proto="udp",
            ),
            n(
                "t2",
                {"Tunnel"},
                state="up",
                local_address="198.51.100.2",
                encap="wireguard",
                carrier_proto="udp",
            ),
        )
    }
    relations = [
        r("o1", "ON", "overlay1", "r1"),
        r("o2", "ON", "overlay2", "r2"),
        r("rw", "ON", "remote-wan", "r2"),
        r("far-ip", "HAS_IP", "remote-wan", "far"),
        r("e1", "ENDPOINT", "t1", "overlay1"),
        r("e2", "ENDPOINT", "t2", "overlay2"),
        r("f1", "TERMINATES_ON", "t1", "far"),
        r("f2", "TERMINATES_ON", "t2", "local"),
    ]
    graph = _rebuild(_graph(), nodes, relations)
    network = Network(
        RibInput(contexts=[]),
        (
            Interface("r1", "wan1", "wan", "underlay1", (), ("198.51.100.1",)),
            Interface("r2", "overlay2", "overlay2", "overlay-context", (), ()),
        ),
        _Gates(),
    )
    target = StateKey(
        "routing:overlay-context:ingress:overlay2",
        ExecutionContext("estate", "authority", "domain", "r2", "overlay-context", 4),
    )
    result = _tunnel_targets(
        graph,
        network,
        [{"context_uid": "underlay1", "prefix": "198.51.100.0/24", "interface": "wan"}],
        {("overlay-context", "overlay2"): target},
    )

    assert result == {"t1": target}


def test_source_population_is_partitioned_by_attachment_with_unknown_remainder():
    network = replace(
        _network(),
        interfaces=(
            *_network().interfaces,
            Interface("r2", "if:r2:source", "source", "c2", ("10.0.1.0/24",), ("10.0.1.1",)),
        ),
    )
    source_low = _ivals("10.0.0.10")[0]
    source_high = _ivals("10.0.2.10")[0]
    request = RequestSet(
        "population",
        ((4, source_low[1], source_high[1]),),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
    )
    model = normalize_network(network, _graph(), request, request.members[0], "estate")

    assert {entry.key.location for entry in model.entries} == {
        "routing:c1:ingress:if:r1:lan",
        "routing:c2:ingress:if:r2:source",
        "routing:source-attachment:unknown",
    }


def _two_attachments(**fields):
    """A source population attached in c1 and in c2."""
    network = replace(
        _network(),
        interfaces=(
            *_network().interfaces,
            Interface("r2", "if:r2:source", "source", "c2", ("10.0.1.0/24",), ("10.0.1.1",)),
        ),
    )
    request = RequestSet(
        "population",
        ((4, _ivals("10.0.0.10")[0][1], _ivals("10.0.1.10")[0][1]),),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        **fields,
    )
    return network, request


def test_two_attachments_keep_the_sdwan_boundary_of_the_routing_states():
    boundary = GraphNode("vco:boundary", frozenset({"ForwardingBoundary"}), MappingProxyType({}))
    device = GraphNode("r1", frozenset({"Device"}), MappingProxyType({}))
    graph = _rebuild(
        _graph(),
        {boundary.uid: boundary, device.uid: device},
        [GraphRelation("boundary-binding", "HAS_BOUNDARY", device.uid, boundary.uid, MappingProxyType({}))],
    )
    network, request = _two_attachments()
    model = normalize_network(network, graph, request, request.members[0], "estate")

    assert len(model.entries) == 3
    c1 = next(node for node in model.nodes if node.key.location == "routing:c1:ingress:if:r1:lan")
    assert [edge.uid for edge in c1.edges] == ["sdwan:opaque"]
    assert not any(node.terminal == "permit" and ":c1:" in node.key.location for node in model.nodes)


def test_two_attachments_take_the_mtu_requirement():
    from hst.impact.evaluate import MtuRequirement

    network, request = _two_attachments(mtu=MtuRequirement(mode="unfragmented", ip_packet_bytes=1500))
    model = normalize_network(network, _graph(), request, request.members[0], "estate")

    assert any(node.key.location.startswith("mtu-delivery:") for node in model.nodes)
    assert not any(
        node.terminal == "permit" and not node.key.location.startswith("mtu-delivery:")
        for node in model.nodes
    )


def test_two_attachments_enter_the_aci_gate_each_and_the_remainder_does_not(monkeypatch):
    from hst.analysis_model import network as adapter
    from hst.analysis_model.gates import GateExpansion

    def aci(_graph, context, downstream, *, sources, destinations):
        key = StateKey(f"gate:aci:{downstream.location}", context, "aci")
        return GateExpansion(key, (NodeSpec(key, (EdgeSpec("aci:continue", downstream),)),), (), True)

    monkeypatch.setattr(adapter, "expand_aci_contracts", aci)
    network, request = _two_attachments()
    model = normalize_network(network, _graph(), request, request.members[0], "estate")

    assert {entry.key.location for entry in model.entries} == {
        "gate:aci:routing:c1:ingress:if:r1:lan",
        "gate:aci:routing:c2:ingress:if:r2:source",
        "routing:source-attachment:unknown",
    }


def test_two_attachments_enter_the_zpa_broker_each_and_join_its_choices_once(monkeypatch):
    from hst.analysis_model import network as adapter
    from hst.analysis_model.gates import GateExpansion

    offered = tuple(ChoiceAssignment(f"zpa:s:c{index}", (("zpa:s", f"c{index}"),)) for index in range(3))

    def zpa(_graph, context, _identity, _segment, downstream):
        key = StateKey(f"gate:zpa:{downstream.location}", context, "proxy")
        edges = tuple(EdgeSpec(f"zpa:{c.uid}", downstream, choices=c.bindings) for c in offered)
        return GateExpansion(key, (NodeSpec(key, edges),), offered, True)

    monkeypatch.setattr(adapter, "expand_zpa_broker", zpa)
    network, request = _two_attachments(identity_uid="identity", segment_uid="segment")
    model = normalize_network(network, _graph(), request, request.members[0], "estate")

    assert {entry.key.location for entry in model.entries} == {
        "gate:zpa:routing:c1:ingress:if:r1:lan",
        "gate:zpa:routing:c2:ingress:if:r2:source",
        "routing:source-attachment:unknown",
    }
    assert sorted(dict(choice.bindings)["zpa:s"] for choice in model.choices) == ["c0", "c1", "c2"]
    assert model.choices_complete is True


def test_installation_bindings_are_context_revision_and_order_scoped():
    nodes = {
        "rb": GraphNode(
            "rb",
            frozenset({"FwRulebase"}),
            MappingProxyType({"vendor": "checkpoint", "configured_revision": "rev-2"}),
        ),
        "vs1": GraphNode("vs1", frozenset({"FirewallInstance"}), MappingProxyType({})),
        "vs2": GraphNode("vs2", frozenset({"FirewallInstance"}), MappingProxyType({})),
    }
    base_props = {
        "installed": True,
        "coverage": "complete",
        "context_uid": "vrf1",
        "ingress_interface_uid": None,
        "egress_interface_uid": None,
        "address_family": 4,
    }
    relations = [
        GraphRelation(
            "wrong-vs",
            "ENFORCES",
            "vs2",
            "rb",
            MappingProxyType({**base_props, "installed_revision": "rev-2"}),
        ),
        GraphRelation(
            "stale",
            "ENFORCES",
            "vs1",
            "rb",
            MappingProxyType({**base_props, "installed_revision": "rev-1"}),
        ),
        GraphRelation(
            "current",
            "ENFORCES",
            "vs1",
            "rb",
            MappingProxyType({**base_props, "installed_revision": "rev-2"}),
        ),
    ]
    graph = _rebuild(_graph(), nodes, relations)
    context = ExecutionContext("estate", "manager", "domain", "vs1", "vrf1", 4)
    cross_instance, cross_installation = _bindings(
        _rebuild(_graph(), nodes, [relations[0]]), context, None, None, 4
    )
    assert cross_instance == ()
    assert isinstance(cross_installation, Unknown)
    rulebases, installation = _bindings(graph, context, None, None, 4)
    assert rulebases == ("rb",)
    assert isinstance(installation, Unknown)

    current_only = _rebuild(_graph(), nodes, [relations[2], relations[0]])
    reversed_rows = _rebuild(_graph(), nodes, [relations[0], relations[2]])
    assert _bindings(current_only, context, None, None, 4) == (
        ("rb",),
        Constant(True),
    )
    assert _bindings(reversed_rows, context, None, None, 4) == (
        ("rb",),
        Constant(True),
    )


def _duplicated_next_hop(leak: str | None = None):
    """A route in c1 toward 203.0.113.0/24 via 192.0.2.2, an address r2 holds
    in c2 and r3 in c3, leaked from `leak` when given."""
    contexts = [{"uid": c, "device_uid": f"r{c[1]}", "platform": "nxos"} for c in ("c1", "c2", "c3")]
    connected = [
        {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "lan"},
        *({"context_uid": c, "prefix": "192.0.2.0/24", "interface": "wan"} for c in ("c1", "c2", "c3")),
        *({"context_uid": c, "prefix": "203.0.113.0/24", "interface": "lan"} for c in ("c2", "c3")),
    ]
    interfaces = [
        Interface("r1", "if:r1:lan", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
        Interface("r1", "if:r1:wan", "wan", "c1", ("192.0.2.0/24",), ("192.0.2.1",)),
    ]
    for c in ("c2", "c3"):
        device = f"r{c[1]}"
        interfaces += [
            Interface(device, f"if:{device}:wan", "wan", c, ("192.0.2.0/24",), ("192.0.2.2",)),
            Interface(device, f"if:{device}:lan", "lan", c, ("203.0.113.0/24",), ("203.0.113.1",)),
        ]
    static = {"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"}
    if leak:
        static["next_hop_context_uid"] = leak
    network = Network(
        RibInput(contexts=contexts, connected=connected, static=[static]), tuple(interfaces), _Gates()
    )
    request = RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    return network, request


def _domain_graph(basis: str):
    nodes = {
        "rd": GraphNode("rd", frozenset({"RoutingDomain"}), MappingProxyType({})),
        **{c: GraphNode(c, frozenset({"VrfInstance"}), MappingProxyType({})) for c in ("c1", "c3")},
    }
    relations = [
        GraphRelation(f"member:{c}", "MEMBER_OF", c, "rd", MappingProxyType({"basis": basis}))
        for c in ("c1", "c3")
    ]
    return _rebuild(_graph(), nodes, relations)


def _fib_targets(model):
    c1 = next(node for node in model.nodes if node.key.location == "routing:c1:ingress:none")
    return {edge.target.location for edge in c1.edges if edge.uid.startswith("fib:c1:203.0.113.0/24")}


def test_a_duplicated_next_hop_resolves_in_the_leaked_table():
    network, request = _duplicated_next_hop(leak="c2")
    model = normalize_network(network, _graph(), request, request.members[0], "estate")

    assert _fib_targets(model) == {"routing:c2:ingress:if:r2:wan"}


def test_a_duplicated_next_hop_resolves_in_a_vrf_of_the_same_declared_routing_domain():
    network, request = _duplicated_next_hop()
    model = normalize_network(network, _domain_graph("declared"), request, request.members[0], "estate")

    assert _fib_targets(model) == {"routing:c3:ingress:if:r3:wan"}


def test_a_duplicated_next_hop_with_no_declared_evidence_is_undecided():
    network, request = _duplicated_next_hop()
    for graph in (_graph(), _domain_graph("rt-component")):
        model = normalize_network(network, graph, request, request.members[0], "estate")

        assert _fib_targets(model) == {"terminal:next-hop-owner-ambiguous:c1:203.0.113.0/24"}


def _single_owner(leak: str | None = None):
    """`_duplicated_next_hop` with only r3 in c3 holding 192.0.2.2."""
    network, request = _duplicated_next_hop(leak=leak)
    interfaces = tuple(item for item in network.interfaces if item.context_uid != "c2")
    return replace(network, interfaces=interfaces), request


def test_a_single_next_hop_owner_in_a_vrf_of_another_name_is_not_followed():
    for leak in (None, "c2"):
        network, request = _single_owner(leak)
        graph = _contexts_graph(c1="BLUE", c2="BLUE", c3="RED")
        model = normalize_network(network, graph, request, request.members[0], "estate")

        assert _fib_targets(model) == {"terminal:next-hop-owner-foreign-context:c1:203.0.113.0/24"}


def test_a_single_next_hop_owner_with_shared_evidence_is_followed():
    network, request = _single_owner()
    for graph in (
        _contexts_graph(c1=True, c3=True),
        _contexts_graph(c1="BLUE", c3="BLUE"),
        _domain_graph("declared"),
    ):
        model = normalize_network(network, graph, request, request.members[0], "estate")

        assert _fib_targets(model) == {"routing:c3:ingress:if:r3:wan"}


def test_a_single_next_hop_owner_without_shared_evidence_is_followed_undecided():
    network, request = _single_owner()
    for graph in (_contexts_graph(c1=True, c3="RED"), _contexts_graph(c1=None, c3="RED"), _graph()):
        model = normalize_network(network, graph, request, request.members[0], "estate")

        (target,) = _fib_targets(model)
        assert target.startswith("next-hop-owner-unshared-context:c1:203.0.113.0/24")
        note = next(node for node in model.nodes if node.key.location == target)
        assert note.complete is False
        assert {edge.target.location for edge in note.edges} == {"routing:c3:ingress:if:r3:wan"}
