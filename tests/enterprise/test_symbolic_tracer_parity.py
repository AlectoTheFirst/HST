"""The symbolic model discovers, binds and translates as the hop tracer does,
and keeps load-balancer choices within the joint-choice limit."""

import ipaddress
from types import MappingProxyType

from hst.analysis_model.gates import _load_balancer_edges
from hst.analysis_model.graph import GraphNode, GraphRelation
from hst.analysis_model.model import ChoiceAssignment, StateKey
from hst.analysis_model.network import (
    MAX_JOINT_CHOICES,
    _access_policy,
    _bindings,
    _relevant_rows,
    normalize_network,
)
from hst.analysis_model.overlay import _rebuild
from hst.analysis_model.session_walk import _reply_assignments
from hst.impact.evaluate import Interface, Member, Network, RequestSet, member
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Not, Unknown
from hst.policy.nat import normalize_nat_rules
from hst.simul.rib import RibInput

from .test_network_compile import _Gates, _graph, _ivals


def _range(text):
    network = ipaddress.ip_network(text)
    return ((network.version, int(network.network_address), int(network.broadcast_address)),)


def _node(uid, label, **props):
    return GraphNode(uid, frozenset({label}), MappingProxyType(props))


def _rel(kind, start, end, **props):
    return GraphRelation(f"{kind}:{start}:{end}", kind, start, end, MappingProxyType(props))


def _holds(predicate, packet):
    """Three-valued truth of a predicate on one concrete packet; None when an
    Unknown term decides it."""
    if isinstance(predicate, Constant):
        return predicate.value
    if isinstance(predicate, Unknown):
        return None
    if isinstance(predicate, Atom):
        value = packet[predicate.field]
        if predicate.operation == "eq":
            return value == predicate.value
        return predicate.value <= value <= predicate.other
    if isinstance(predicate, Not):
        inner = _holds(predicate.term, packet)
        return None if inner is None else not inner
    values = [_holds(term, packet) for term in predicate.terms]
    if isinstance(predicate, AllOf):
        return False if False in values else None if None in values else True
    assert isinstance(predicate, AnyOf)
    return True if True in values else None if None in values else False


def _packet(source, destination, protocol=6, source_port=40000, destination_port=443):
    return {
        "source_address": int(ipaddress.ip_address(source)),
        "destination_address": int(ipaddress.ip_address(destination)),
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
    }


# --- FIB discovery by interval overlap ----------------------------------------


def _summary_network():
    return Network(
        RibInput(
            contexts=[{"uid": "c1", "device_uid": "r1", "platform": "nxos"}],
            connected=[{"context_uid": "c1", "prefix": "10.9.0.0/24", "interface": "lan"}],
        ),
        (Interface("r1", "if:r1:lan", "lan", "c1", ("10.9.0.0/24",), ("10.9.0.1",)),),
        _Gates(),
    )


def test_discovery_selects_more_specific_routes_inside_a_member_range():
    rows = [
        {"context_uid": "c1", "prefix": "10.0.0.0/16", "next_hop": "192.0.2.1"},
        {"context_uid": "c1", "prefix": "10.0.5.0/24", "next_hop": "192.0.2.9"},
        {"context_uid": "c1", "prefix": "10.2.1.0/24", "next_hop": "192.0.2.5"},
        {"context_uid": "c1", "prefix": "172.16.0.0/12", "next_hop": "192.0.2.7"},
    ]
    request = RequestSet(
        "summary",
        _ivals("10.9.0.10"),
        "range",
        (Member("range", _range("10.0.0.0/16") + _range("10.2.0.0/23")),),
        member("range"),
        source_context="c1",
    )
    selected = {row["prefix"] for row in _relevant_rows(_summary_network(), request, rows)}

    assert selected == {"10.0.0.0/16", "10.0.5.0/24", "10.2.1.0/24"}


def test_discovery_starts_in_every_context_a_source_range_attaches_to():
    network = Network(
        RibInput(
            contexts=[
                {"uid": "a", "device_uid": "r1", "platform": "nxos"},
                {"uid": "b", "device_uid": "r2", "platform": "nxos"},
            ],
        ),
        (
            Interface("r1", "if:r1:lan", "lan", "a", ("10.1.0.0/24",), ("10.1.0.1",)),
            Interface("r2", "if:r2:lan", "lan", "b", ("10.1.1.0/24",), ("10.1.1.1",)),
        ),
        _Gates(),
    )
    rows = [
        {"context_uid": "a", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.1"},
        {"context_uid": "b", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"},
    ]
    request = RequestSet(
        "sources",
        _range("10.1.0.0/23"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
    )
    selected = {row["context_uid"] for row in _relevant_rows(network, request, rows)}

    assert selected == {"a", "b"}


def test_ipv6_discovery_does_not_read_a_low_address_as_ipv4():
    network = Network(
        RibInput(contexts=[{"uid": "c6", "device_uid": "r1", "platform": "nxos"}]),
        (Interface("r1", "if:r1:lan", "lan", "c6", ("2001:db8:1::/64",), ("2001:db8:1::1",)),),
        _Gates(),
    )
    rows = [{"context_uid": "c6", "prefix": "2001:db8:ff::/48", "next_hop": "2001:db8:1::2"}]
    request = RequestSet(
        "v6",
        _ivals("2001:db8:1::10"),
        "any",
        (Member("any", _range("::/0")),),
        member("any"),
        source_context="c6",
    )

    assert [row["prefix"] for row in _relevant_rows(network, request, rows)] == ["2001:db8:ff::/48"]


# --- zone-pair rulebases and VyOS chains --------------------------------------


def _vyos_graph(*, chains, pair_af=None, lan_zone=None):
    nodes = {
        "dev:r1": _node("dev:r1", "Device", role="router", platform="vyos"),
        "if:lan": _node("if:lan", "Interface", name="eth1"),
        "if:guest": _node("if:guest", "Interface", name="eth2"),
        # each zone states its default-action, as the VyOS collector writes it
        "zone:LAN": _node(
            "zone:LAN", "Zone", name="LAN", **({"default_action": "drop"} if lan_zone is None else lan_zone)
        ),
        "zone:GUEST": _node("zone:GUEST", "Zone", name="GUEST", default_action="drop"),
        "rb:LAN-GUEST": _node(
            "rb:LAN-GUEST",
            "FwRulebase",
            vendor="vyos",
            name="LAN-GUEST",
            match_context="zone-pair",
            default_action="drop",
            **({"af": pair_af} if pair_af else {}),
        ),
    }
    relations = [
        _rel("ON", "if:lan", "dev:r1"),
        _rel("ON", "if:guest", "dev:r1"),
        _rel("CONTAINS", "zone:LAN", "if:lan"),
        _rel("CONTAINS", "zone:GUEST", "if:guest"),
        _rel("FROM_ZONE", "rb:LAN-GUEST", "zone:LAN"),
        _rel("TO_ZONE", "rb:LAN-GUEST", "zone:GUEST"),
    ]
    if chains:
        for uid, chain, af in (
            ("rb:ipv4-forward", "forward", 4),
            ("rb:ipv4-input", "input", 4),
            ("rb:ipv6-forward", "forward", 6),
        ):
            nodes[uid] = _node(uid, "FwRulebase", vendor="vyos", chain=chain, af=af, default_action="drop")
            relations.append(_rel("ENFORCES", "dev:r1", uid))
    return _rebuild(_graph(), nodes, relations)


def test_zone_only_router_binds_its_zone_policy_and_cannot_prove_a_permit():
    graph = _vyos_graph(chains=False)
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    rulebases, installation = _bindings(graph, context, "if:lan", "if:guest", 4)
    assert rulebases == ("rb:LAN-GUEST",)
    assert isinstance(installation, Unknown)
    assert _access_policy(graph, context, "dev:r1", "if:lan", "if:guest", 4, "new") is not None


def _layers(policy):
    return [(layer.uid, layer.rules, layer.default) for layer in policy.layers]


def test_unbound_zone_pair_takes_the_destination_zone_default():
    graph = _vyos_graph(chains=False)
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    rulebases, installation = _bindings(graph, context, "if:guest", "if:lan", 4)
    assert rulebases == ("zone:LAN",)
    assert isinstance(installation, Unknown)
    policy = _access_policy(graph, context, "dev:r1", "if:guest", "if:lan", 4, "new")
    assert _layers(policy) == [("zone:LAN", (), "deny")]


def test_unrecorded_zone_default_is_unknown_not_a_drop():
    graph = _vyos_graph(chains=False, lan_zone={"default_action_unknown": True})
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    policy = _access_policy(graph, context, "dev:r1", "if:guest", "if:lan", 4, "new")
    assert _layers(policy) == [("zone:LAN", (), "unknown")]


def test_a_zone_stating_neither_default_nor_marker_is_unknown_not_a_drop():
    graph = _vyos_graph(chains=False, lan_zone={})
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    policy = _access_policy(graph, context, "dev:r1", "if:guest", "if:lan", 4, "new")
    assert _layers(policy) == [("zone:LAN", (), "unknown")]


def test_pair_ruleset_of_the_other_family_falls_to_the_zone_default():
    graph = _vyos_graph(chains=False, pair_af=6)
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    policy = _access_policy(graph, context, "dev:r1", "if:lan", "if:guest", 4, "new")
    assert _layers(policy) == [("zone:GUEST", (), "deny")]


def test_zoned_ingress_with_an_unknown_egress_cannot_be_open():
    graph = _vyos_graph(chains=False)
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    policy = _access_policy(graph, context, "dev:r1", "if:guest", None, 4, "new")
    assert policy is not None
    assert [layer.default for layer in policy.layers] == ["unknown"]


def test_transit_flow_skips_device_chains_and_other_family_rulesets():
    graph = _vyos_graph(chains=True)
    context = ExecutionContext("estate", "dev:r1", "domain", "dev:r1", "c1", 4)

    rulebases, _installation = _bindings(graph, context, "if:lan", "if:guest", 4)
    assert rulebases == ("rb:LAN-GUEST", "rb:ipv4-forward")


_INSTALLED = {
    "installed": True,
    "coverage": "complete",
    "installed_revision": "r1",
    "configured_revision": "r1",
}


def _zone_router(*, lan_zone=None, forward=None, input_drop=False):
    """One VyOS router: eth1 and eth3 in zone LAN, eth2 in zone GUEST, both
    zones default drop with installation evidence, no zone-pair ruleset;
    `forward` adds an installed ipv4 forward chain with that default."""
    nodes = {
        "dev:r1": _node("dev:r1", "Device", role="router", platform="vyos"),
        "if:lan": _node("if:lan", "Interface", name="eth1"),
        "if:guest": _node("if:guest", "Interface", name="eth2"),
        "if:lan2": _node("if:lan2", "Interface", name="eth3"),
        "zone:LAN": _node(
            "zone:LAN", "Zone", name="LAN", default_action="drop", **_INSTALLED, **(lan_zone or {})
        ),
        "zone:GUEST": _node("zone:GUEST", "Zone", name="GUEST", default_action="drop", **_INSTALLED),
    }
    relations = [
        _rel("ON", "if:lan", "dev:r1"),
        _rel("ON", "if:guest", "dev:r1"),
        _rel("ON", "if:lan2", "dev:r1"),
        _rel("CONTAINS", "zone:LAN", "if:lan"),
        _rel("CONTAINS", "zone:LAN", "if:lan2"),
        _rel("CONTAINS", "zone:GUEST", "if:guest"),
    ]
    chains = [("rb:ipv4-forward", "forward", forward)] if forward else []
    if input_drop:
        chains.append(("rb:ipv4-input", "input", "drop"))
    for uid, chain, default in chains:
        nodes[uid] = _node(uid, "FwRulebase", vendor="vyos", chain=chain, af=4, default_action=default)
        relations.append(
            _rel(
                "ENFORCES",
                "dev:r1",
                uid,
                installed=True,
                coverage="complete",
                installed_revision="r1",
                context_uid="*",
                ingress_interface_uid="*",
                egress_interface_uid="*",
                address_family=4,
            )
        )
    return _rebuild(_graph(), nodes, relations)


def _zone_network():
    return Network(
        RibInput(
            contexts=[{"uid": "c1", "device_uid": "dev:r1", "platform": "vyos"}],
            connected=[
                {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "eth1"},
                {"context_uid": "c1", "prefix": "10.0.9.0/24", "interface": "eth2"},
                {"context_uid": "c1", "prefix": "10.0.5.0/24", "interface": "eth3"},
            ],
        ),
        (
            Interface("dev:r1", "if:lan", "eth1", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
            Interface("dev:r1", "if:guest", "eth2", "c1", ("10.0.9.0/24",), ("10.0.9.1",)),
            Interface("dev:r1", "if:lan2", "eth3", "c1", ("10.0.5.0/24",), ("10.0.5.1",)),
        ),
        _Gates(),
    )


def _model(graph, source, destination, network=None):
    request = RequestSet("flow", _ivals(source), "dst", (Member("dst", _ivals(destination)),), member("dst"))
    return normalize_network(network or _zone_network(), graph, request, request.members[0], "estate")


def _path_policies(model, prefix):
    """The policies on the chain of single-edge nodes behind the entry's FIB
    edge for `prefix`, and the location the chain ends at."""
    by_key = {node.key: node for node in model.nodes}
    entry = by_key[model.entries[0].key]
    (edge,) = [edge for edge in entry.edges if f":{prefix}:" in edge.uid]
    layers, node = [], by_key[edge.target]
    while True:
        if node.policy is not None:
            layers.extend((layer.uid, layer.default) for layer in node.policy.layers)
        if not node.edges:
            return entry, layers, node.key.location
        node = by_key[node.edges[0].target]


def test_source_at_its_own_zoned_gateway_takes_the_destination_zone_default():
    """A source attached to a router with an owning device enters by
    the interface serving its prefix, so an unbound zone pair takes the
    destination zone's default-action as the tracer decides it."""
    for forward in (None, "accept"):
        model = _model(_zone_router(forward=forward), "10.0.0.10", "10.0.9.10")

        entry, layers, end = _path_policies(model, "10.0.9.0/24")
        assert entry.key.location == "routing:c1:ingress:if:lan"
        assert ("zone:GUEST", "deny") in layers
        assert end == "delivery:c1:10.0.9.0/24"


def test_zoned_router_with_an_unknown_ingress_is_unknown_not_open():
    """With the ingress unknown, no zone default can be chosen, so a
    zoned router's policy carries an unknown layer beside its chains."""
    graph = _zone_router(forward="accept")
    context = ExecutionContext("estate", "graph", "graph", "dev:r1", "c1", 4)

    policy = _access_policy(graph, context, "dev:r1", None, "if:guest", 4, "new")
    assert _layers(policy) == [
        ("rb:ipv4-forward", (), "permit"),
        ("zone-ingress-unknown:dev:r1", (), "unknown"),
    ]


def test_intra_zone_filtering_decides_a_flow_inside_one_zone():
    """Two interfaces of one zone that no (Z, Z) ruleset binds take the
    zone's intra-zone filtering, as `_intra_zone_verdict` reads it."""
    context = ExecutionContext("estate", "graph", "graph", "dev:r1", "c1", 4)
    cases = (
        ({"intra_zone_filtering": True, "intra_zone_action": "drop"}, "deny"),
        ({"intra_zone_filtering": True, "intra_zone_action": "accept"}, "permit"),
        # the documented default of a zone without intra-zone-filtering
        ({"intra_zone_filtering": False, "intra_zone_action": None}, "permit"),
        # filtered by a ruleset of the other family only
        ({"intra_zone_filtering": True, "intra_zone_action": None}, "unknown"),
    )
    for lan_zone, verdict in cases:
        graph = _zone_router(lan_zone=lan_zone, forward="accept")
        rulebases, installation = _bindings(graph, context, "if:lan", "if:lan2", 4)
        assert rulebases == ("rb:ipv4-forward", "zone:LAN#intra")
        assert installation == Constant(True)
        policy = _access_policy(graph, context, "dev:r1", "if:lan", "if:lan2", 4, "new")
        assert _layers(policy)[-1] == ("zone:LAN#intra", (), verdict)

    _entry, layers, _end = _path_policies(
        _model(_zone_router(lan_zone=cases[0][0], forward="accept"), "10.0.0.10", "10.0.5.10"), "10.0.5.0/24"
    )
    assert ("zone:LAN#intra", "deny") in layers


def test_a_zone_without_the_intra_zone_marker_binds_no_rulebase():
    graph = _zone_router()
    context = ExecutionContext("estate", "graph", "graph", "dev:r1", "c1", 4)

    assert _bindings(graph, context, "if:lan", "if:lan2", 4)[0] == ()


def test_a_destination_the_router_holds_is_unknown_not_a_forward_permit():
    """A packet to the router's own address is judged by its input
    chain, which the model does not read: it is an unknown terminal, and the
    forward chain judges only the forwarded packets."""
    graph = _zone_router(forward="accept", input_drop=True)
    network = Network(
        RibInput(
            contexts=[{"uid": "c1", "device_uid": "dev:r1", "platform": "vyos"}],
            connected=[
                {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "eth1"},
                {"context_uid": "c1", "prefix": "10.0.9.0/24", "interface": "eth2"},
            ],
        ),
        (
            Interface("dev:r1", "if:x1", "eth1", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
            Interface("dev:r1", "if:x2", "eth2", "c1", ("10.0.9.0/24",), ("10.0.9.1/24",)),
        ),
        _Gates(),
    )
    model = _model(graph, "10.0.0.10", "10.0.9.1", network)
    by_key = {node.key: node for node in model.nodes}
    entry = by_key[model.entries[0].key]

    assert entry.policy is None
    (local,) = [edge for edge in entry.edges if edge.uid == "local:c1"]
    assert _holds(local.predicate, _packet("10.0.0.10", "10.0.9.1"))
    assert by_key[local.target].terminal == "unknown"
    (fib,) = [edge for edge in entry.edges if edge.uid.startswith("fib:")]
    assert _holds(fib.predicate, _packet("10.0.0.10", "10.0.9.1")) is False
    assert _holds(fib.predicate, _packet("10.0.0.10", "10.0.9.7"))
    forward = by_key[fib.target]
    assert [layer.uid for layer in forward.policy.layers] == ["rb:ipv4-forward"]


def test_discovery_routes_the_destination_a_dnat_rule_translates_to():
    graph = _rebuild(
        _graph(),
        {
            "r1": _node("r1", "Device"),
            "rb:nat": _node("rb:nat", "FwRulebase", kind="nat", vendor="vyos", name="nat"),
            "rule": _node(
                "rule",
                "NatRule",
                position=10,
                kind="dnat",
                orig_dst="203.0.113.10",
                translation="192.168.1.10",
            ),
        },
        [_rel("ENFORCES", "r1", "rb:nat"), _rel("HAS_RULE", "rb:nat", "rule")],
    )
    network = Network(
        RibInput(
            contexts=[
                {"uid": "c1", "device_uid": "r1", "platform": "vyos"},
                {"uid": "c2", "device_uid": "r2", "platform": "vyos"},
            ],
            connected=[
                {"context_uid": "c1", "prefix": "192.168.1.0/24", "interface": "lan"},
                {"context_uid": "c1", "prefix": "198.51.100.0/30", "interface": "wan"},
                {"context_uid": "c2", "prefix": "198.51.100.0/30", "interface": "down"},
                {"context_uid": "c2", "prefix": "10.0.0.0/24", "interface": "users"},
            ],
            static=[
                {"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "198.51.100.2"},
                {"context_uid": "c2", "prefix": "203.0.113.0/24", "next_hop": "198.51.100.1"},
            ],
        ),
        (
            Interface("r1", "if:r1:lan", "lan", "c1", ("192.168.1.0/24",), ("192.168.1.1",)),
            Interface("r1", "if:r1:wan", "wan", "c1", ("198.51.100.0/30",), ("198.51.100.1",)),
            Interface("r2", "if:r2:down", "down", "c2", ("198.51.100.0/30",), ("198.51.100.2",)),
            Interface("r2", "if:r2:users", "users", "c2", ("10.0.0.0/24",), ("10.0.0.1",)),
        ),
        _Gates(),
    )
    model = _model(graph, "10.0.0.10", "203.0.113.10", network)
    by_key = {node.key.location: node for node in model.nodes}
    routing = by_key["routing:c1:ingress:if:r1:wan"]
    translated = _packet("10.0.0.10", "192.168.1.10")

    (edge,) = [edge for edge in routing.edges if _holds(edge.predicate, translated)]
    assert edge.target.location == "delivery:c1:192.168.1.0/24"


# --- NAT rules read through the tracer's rule builder -------------------------


def _nat_graph(rule_props, relations=(), extra=()):
    nodes = {
        "dev:r1": _node("dev:r1", "Device"),
        "rb:nat": _node("rb:nat", "FwRulebase", kind="nat", vendor="vyos", name="nat"),
        "rule": _node("rule", "NatRule", position=10, **rule_props),
        **{node.uid: node for node in extra},
    }
    return _rebuild(
        _graph(),
        nodes,
        [_rel("ENFORCES", "dev:r1", "rb:nat"), _rel("HAS_RULE", "rb:nat", "rule"), *relations],
    )


def _specs(graph):
    specs = normalize_nat_rules(
        graph, "dev:r1", ingress_interface_uid=None, egress_interface_uid=None, address_family=4
    )
    return {spec.stage: spec for spec in specs}


def test_dnat_rule_matches_its_original_source_too():
    specs = _specs(
        _nat_graph(
            {
                "kind": "dnat",
                "orig_src": "10.0.0.0/8",
                "orig_dst": "203.0.113.10",
                "translation": "192.168.1.10",
            }
        )
    )
    dnat = specs["dnat"]

    assert _holds(dnat.predicate, _packet("172.16.0.5", "203.0.113.10")) is False
    assert _holds(dnat.predicate, _packet("10.1.1.1", "203.0.113.10")) is True
    assert dnat.rewrites == (("destination_address", int(ipaddress.ip_address("192.168.1.10"))),)
    assert "snat" not in specs


def test_unresolved_original_object_claims_its_packets_as_unknown():
    fqdn = _node("obj:fqdn", "FqdnObject", fqdn="www.example.com")
    specs = _specs(
        _nat_graph(
            {"kind": "dnat", "translation": "192.168.1.10"},
            [_rel("ORIG_DST", "rule", "obj:fqdn")],
            [fqdn],
        )
    )
    dnat = specs["dnat"]

    assert dnat.gap_code == "NAT_MATCH_OBJECT_UNRESOLVED"
    assert dnat.rewrites == ()
    assert _holds(dnat.predicate, _packet("10.1.1.1", "8.8.8.8")) is None


def test_protocol_and_port_list_constrain_the_rule():
    specs = _specs(
        _nat_graph(
            {
                "kind": "dnat",
                "orig_dst": "203.0.113.10",
                "orig_dst_port": "80,443",
                "protocol": "tcp_udp",
                "translation": "192.168.1.10",
            }
        )
    )
    predicate = specs["dnat"].predicate

    assert _holds(predicate, _packet("10.1.1.1", "203.0.113.10", destination_port=22)) is False
    assert _holds(predicate, _packet("10.1.1.1", "203.0.113.10", destination_port=443)) is True
    assert _holds(predicate, _packet("10.1.1.1", "203.0.113.10", protocol=47, destination_port=443)) is False


def test_unreadable_port_spec_is_unknown_not_an_error():
    specs = _specs(
        _nat_graph(
            {
                "kind": "dnat",
                "orig_dst": "203.0.113.10",
                "orig_dst_port": "443-80",
                "translation": "192.168.1.10",
            }
        )
    )

    assert specs["dnat"].gap_code == "NAT_SERVICE_UNKNOWN"


def test_static_rule_translates_in_both_directions():
    public, real = int(ipaddress.ip_address("203.0.113.10")), int(ipaddress.ip_address("192.168.1.10"))
    specs = _specs(_nat_graph({"kind": "static", "orig_dst": "203.0.113.10", "translation": "192.168.1.10"}))

    inbound, outbound = specs["dnat"], specs["snat"]
    assert _holds(inbound.predicate, _packet("8.8.8.8", "203.0.113.10")) is True
    assert inbound.rewrites == (("destination_address", real),)
    assert _holds(outbound.predicate, _packet("192.168.1.10", "8.8.8.8")) is True
    assert _holds(outbound.predicate, _packet("10.1.1.1", "8.8.8.8")) is False
    assert outbound.rewrites == (("source_address", public),)


def test_static_port_mapping_matches_and_rewrites_the_source_port_outbound():
    real, public = "10.0.0.5", "203.0.113.5"
    nodes = (_node("ip:real", "IpAddress", ip=real), _node("ip:public", "IpAddress", ip=public))
    specs = _specs(
        _nat_graph(
            {"static": True, "protocol": "tcp", "orig_port": "80", "translation_port": "8080"},
            [_rel("ORIG_SRC", "rule", "ip:real"), _rel("XLATE_SRC", "rule", "ip:public")],
            nodes,
        )
    )
    outbound = specs["snat"]

    assert _holds(outbound.predicate, _packet(real, "8.8.8.8", source_port=5555)) is False
    assert _holds(outbound.predicate, _packet(real, "8.8.8.8", source_port=80)) is True
    assert outbound.rewrites == (
        ("source_address", int(ipaddress.ip_address(public))),
        ("source_port", 8080),
    )
    inbound = specs["dnat"]
    assert _holds(inbound.predicate, _packet("8.8.8.8", public, destination_port=8080)) is True
    assert inbound.rewrites == (
        ("destination_address", int(ipaddress.ip_address(real))),
        ("destination_port", 80),
    )


# --- load-balancer choices stay within the limit ------------------------------


def _lb_nodes(device, services, members):
    nodes = {device: _node(device, "Device", role="load-balancer")}
    relations = []
    for index in range(services):
        service, pool, vip = f"vs:{index}", f"pool:{index}", f"ip:vip:{index}"
        nodes[service] = _node(service, "VirtualService", proto="tcp", port=443)
        nodes[pool] = _node(pool, "Pool", coverage="complete")
        nodes[vip] = _node(vip, "IpAddress", ip=f"10.50.0.{index + 10}")
        relations += [_rel("ON", service, device), _rel("USES", service, pool), _rel("VIP", service, vip)]
        for number in range(members):
            node, address = f"m:{index}:{number}", f"ip:m:{index}:{number}"
            nodes[node] = _node(node, "PoolMember", state="up")
            nodes[address] = _node(address, "IpAddress", ip=f"10.60.{index}.{number + 1}")
            relations += [_rel("HAS_MEMBER", pool, node), _rel("TARGETS", node, address)]
    return nodes, relations


def test_load_balancer_choices_stay_within_the_limit_and_every_vip_keeps_its_claim():
    nodes, relations = _lb_nodes("lb1", 6, 4)
    graph = _rebuild(_graph(), nodes, relations)
    context = ExecutionContext("estate", "lb1", "domain", "lb1", "c3", 4)
    reroute = StateKey("routing:c3:ingress:none", context)

    edges, terminals, choices, gaps = _load_balancer_edges(
        graph, context, "lb1", reroute, (), MAX_JOINT_CHOICES
    )

    assert 0 < len(choices) <= MAX_JOINT_CHOICES
    assert "LOAD_BALANCER_CHOICE_CUTOFF" in gaps
    cut = [edge for edge in edges if edge.uid.endswith(":choice-cutoff")]
    assert cut and all(not edge.choices for edge in cut)
    claimed = {
        edge.uid.split(":")[0] + ":" + edge.uid.split(":")[1] for edge in edges if edge.uid.startswith("vs:")
    }
    assert claimed == {f"vs:{index}" for index in range(6)}
    assert any(edge.uid == "load-balancer:fallthrough" for edge in edges)
    assert any(node.terminal == "unknown" and not node.complete for node in terminals)

    # a scope the caller already binds adds no choices
    again = _load_balancer_edges(graph, context, "lb1", reroute, choices, MAX_JOINT_CHOICES)
    assert again[2] == ()


def test_load_balancer_elsewhere_in_the_estate_keeps_the_reply_model_decided():
    network = Network(
        RibInput(
            contexts=[
                {"uid": "c1", "device_uid": "r1", "platform": "nxos"},
                {"uid": "c2", "device_uid": "r2", "platform": "nxos"},
                {"uid": "c3", "device_uid": "lb1", "platform": "netscaler"},
            ],
            connected=[
                {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "lan"},
                {"context_uid": "c1", "prefix": "192.0.2.0/24", "interface": "wan"},
                {"context_uid": "c2", "prefix": "203.0.113.0/24", "interface": "lan"},
                {"context_uid": "c3", "prefix": "10.50.0.0/24", "interface": "vip"},
            ],
            static=[{"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"}],
        ),
        (
            Interface("r1", "if:r1:lan", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
            Interface("r1", "if:r1:wan", "wan", "c1", ("192.0.2.0/24",), ("192.0.2.1",)),
            Interface("r2", "if:r2:lan", "lan", "c2", ("203.0.113.0/24",), ("192.0.2.2",)),
            Interface("lb1", "if:lb1:vip", "vip", "c3", ("10.50.0.0/24",), ("10.50.0.1",)),
        ),
        _Gates(),
    )
    nodes, relations = _lb_nodes("lb1", 6, 4)
    graph = _rebuild(_graph(), nodes, relations)
    request = RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )

    model = normalize_network(network, graph, request, request.members[0], "estate", _all_routes=True)

    assert model.choices_complete is True
    assert len(model.choices) <= MAX_JOINT_CHOICES
    assert not any(node.key.location.startswith("terminal:choice-cutoff:") for node in model.nodes)


def test_reply_takes_every_choice_the_forward_choice_leaves_open():
    forward = ChoiceAssignment("routing:only")
    reply = (
        ChoiceAssignment("lb:a", (("lb:estate:domain:vs:0", "member:a"),)),
        ChoiceAssignment("lb:b", (("lb:estate:domain:vs:0", "member:b"),)),
    )

    class _Model:
        choices = reply

    assert _reply_assignments(_Model(), forward) == reply
