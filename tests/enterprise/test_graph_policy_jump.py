"""A VyOS jump rule in the graph policy normalization calls its target ruleset's
layer, the way the firewall gate reads the target's rules in its place."""

from __future__ import annotations

import ipaddress
import os
from types import MappingProxyType

import pytest

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Not, Ref, Unknown

CONTEXT = ExecutionContext("estate", "authority", "domain", "fw", "vrf", 4)
ANY = {"src_any": True, "dst_any": True}


def _graph(rulebases: dict[str, dict], rules: dict[str, tuple[str, dict, str | None]]) -> GraphInventory:
    """`rules` maps a rule uid to its rulebase, its props and the cidr of its
    destination object (None for any destination)."""
    nodes: dict[str, GraphNode] = {
        uid: GraphNode(uid, frozenset({"FwRulebase"}), MappingProxyType({"vendor": "vyos", **props}))
        for uid, props in rulebases.items()
    }
    outgoing: dict = {}
    incoming: dict = {}

    def relate(kind: str, start: str, end: str) -> None:
        rel = GraphRelation(f"{kind}:{start}:{end}", kind, start, end, MappingProxyType({}))
        outgoing[(start, kind)] = (*outgoing.get((start, kind), ()), rel)
        incoming[(end, kind)] = (*incoming.get((end, kind), ()), rel)

    for uid, (base, props, cidr) in rules.items():
        nodes[uid] = GraphNode(
            uid,
            frozenset({"FwRule"}),
            MappingProxyType({"enabled": True, "jump_target": "", **ANY, **props, "dst_any": cidr is None}),
        )
        relate("HAS_RULE", base, uid)
        if cidr is not None:
            obj = f"{uid}:dst"
            nodes[obj] = GraphNode(obj, frozenset({"Address"}), MappingProxyType({"cidr": cidr}))
            relate("DST", uid, obj)
    labels: dict = {}
    for uid, node in nodes.items():
        for label in node.labels:
            labels[label] = (*labels.get(label, ()), uid)
    return GraphInventory(
        "a" * 64,
        "fingerprint",
        MappingProxyType(nodes),
        MappingProxyType(labels),
        MappingProxyType(outgoing),
        MappingProxyType(incoming),
        True,
        (),
        0,
    )


def _holds(predicate, packet, objects):
    """Kleene truth of `predicate` for one packet: None is unknown."""
    if isinstance(predicate, Constant):
        return predicate.value
    if isinstance(predicate, Unknown):
        return None
    if isinstance(predicate, Atom):
        value = packet[predicate.field]
        if predicate.operation == "eq":
            return value == predicate.value
        if predicate.operation == "range":
            return predicate.value <= value <= predicate.other
        return value & predicate.other == predicate.value & predicate.other
    if isinstance(predicate, Ref):
        return _holds(objects[predicate.key].predicate, packet, objects)
    if isinstance(predicate, Not):
        inner = _holds(predicate.term, packet, objects)
        return None if inner is None else not inner
    values = [_holds(term, packet, objects) for term in predicate.terms]
    if isinstance(predicate, AllOf):
        return False if False in values else None if None in values else True
    assert isinstance(predicate, AnyOf)
    return True if True in values else None if None in values else False


def _layer(uid, packet, layers, objects, stack=()):
    """The action of layer `uid` for `packet`, with the compiler's call
    semantics (policy/compile.py `_block`)."""
    if uid not in layers or uid in stack:
        return "unknown"
    for rule in layers[uid].rules:
        matched = _holds(rule.predicate, packet, objects) if rule.enabled else False
        if matched is False:
            continue
        action = rule.action
        if action == "call":
            action = _layer(rule.called_layer, packet, layers, objects, (*stack, uid))
            if action == "return":
                if matched is None:
                    return "unknown"
                continue
        return "unknown" if matched is None else action
    return layers[uid].default


def _decide(graph, dst, ingress="eth0", ordered=("fwd",)):
    policy = GraphPolicyNormalizer(graph, CONTEXT).policy(
        ordered, installation=Constant(True), ingress=ingress
    )
    layers = {layer.uid: layer for layer in policy.layers}
    objects = {obj.key: obj for obj in policy.objects}
    packet = {"destination_address": int(ipaddress.ip_address(dst))}
    results = {_layer(uid, packet, layers, objects) for uid in policy.ordered_layers}
    return "deny" if "deny" in results else "unknown" if results - {"permit"} else "permit"


def _jumping(named: dict, named_rules: dict | None = None, **extra) -> GraphInventory:
    return _graph(
        {"fwd": {"chain": "forward", "default_action": "accept"}, "named": named, **extra.pop("bases", {})},
        {
            "fwd:10": (
                "fwd",
                {"position": 10, "action": "jump", "jump_target": "named", "in_interface": "eth0"},
                None,
            ),
            "fwd:20": ("fwd", {"position": 20, "action": "drop"}, "10.2.0.0/16"),
            **(
                named_rules
                if named_rules is not None
                else {"named:10": ("named", {"position": 10, "action": "accept"}, "10.0.0.0/24")}
            ),
            **extra,
        },
    )


def test_a_jump_rule_calls_the_target_layer_outside_the_ordered_layers():
    graph = _jumping({"default_action": "drop"})
    policy = GraphPolicyNormalizer(graph, CONTEXT).policy(
        ("fwd",), installation=Constant(True), ingress="eth0"
    )

    assert policy.ordered_layers == ("fwd",)
    jump = policy.layers[0].rules[0]
    assert (jump.action, jump.called_layer) == ("call", "named")
    # the target is evaluated, not reported as a field nothing reads
    assert not any(
        isinstance(term, Unknown) and term.code == "GRAPH_RULE_UNSUPPORTED_FIELD"
        for term in jump.predicate.terms
    )
    assert {layer.uid for layer in policy.layers} == {"fwd", "named"}


def test_the_target_rule_or_default_decides_a_flow_the_jump_hands_over():
    graph = _jumping({"default_action": "drop"})

    assert _decide(graph, "10.0.0.5") == "permit"
    assert _decide(graph, "10.9.0.5") == "deny"
    # a flow the jump rule does not match never sees the target
    assert _decide(graph, "10.9.0.5", ingress="eth1") == "permit"


def test_a_target_default_of_return_continues_after_the_jump():
    graph = _jumping({"default_action": "return"})

    assert _decide(graph, "10.9.0.5") == "permit"
    assert _decide(graph, "10.2.0.5") == "deny"


def test_a_return_rule_in_the_target_continues_after_the_jump_for_its_flows():
    graph = _jumping(
        {"default_action": "accept"},
        {
            "named:5": ("named", {"position": 5, "action": "return"}, "10.2.0.0/16"),
            "named:10": ("named", {"position": 10, "action": "accept"}, None),
        },
    )

    assert _decide(graph, "10.2.0.5") == "deny"
    assert _decide(graph, "10.9.0.5") == "permit"


def test_a_target_default_jump_is_followed():
    graph = _jumping(
        {"default_action": "jump", "default_jump_target": "deeper"},
        bases={"deeper": {"default_action": "drop"}},
        **{"deeper:10": ("deeper", {"position": 10, "action": "accept"}, "10.3.0.0/16")},
    )

    assert _decide(graph, "10.0.0.5") == "permit"
    assert _decide(graph, "10.3.0.5") == "permit"
    assert _decide(graph, "10.9.0.5") == "deny"


def test_a_continue_rule_decides_nothing():
    graph = _jumping(
        {"default_action": "drop"},
        {
            "named:5": ("named", {"position": 5, "action": "continue"}, None),
            "named:10": ("named", {"position": 10, "action": "accept"}, "10.0.0.0/24"),
        },
    )

    assert _decide(graph, "10.0.0.5") == "permit"
    assert _decide(graph, "10.9.0.5") == "deny"


def test_an_unrecorded_default_a_missing_target_and_a_loop_are_undecided():
    assert _decide(_jumping({"default_action_unknown": True}), "10.9.0.5") == "unknown"
    assert _decide(_jumping({"default_action_unknown": True}), "10.0.0.5") == "permit"

    missing = _graph(
        {"fwd": {"chain": "forward", "default_action": "accept"}},
        {"fwd:10": ("fwd", {"position": 10, "action": "jump", "jump_target": "absent"}, None)},
    )
    assert _decide(missing, "10.0.0.5") == "unknown"

    loop = _jumping(
        {"default_action": "drop"},
        {"named:10": ("named", {"position": 10, "action": "jump", "jump_target": "named"}, None)},
    )
    assert _decide(loop, "10.0.0.5") == "unknown"

    untargeted = _graph(
        {"fwd": {"chain": "forward", "default_action": "accept"}},
        {"fwd:10": ("fwd", {"position": 10, "action": "jump"}, None)},
    )
    assert _decide(untargeted, "10.0.0.5") == "unknown"


@pytest.fixture
def manager():
    from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager

    try:
        native = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with native:
        yield native


def test_the_compiled_policy_decides_through_the_jump(manager):
    from hst.policy.compile import PolicyCompiler
    from hst.symbolic import header

    graph = _jumping({"default_action": "drop"})
    policy = GraphPolicyNormalizer(graph, CONTEXT).policy(
        ("fwd",), installation=Constant(True), ingress="eth0"
    )
    fields = manager.schema.field_names
    for dst, permitted in (("10.0.0.5", True), ("10.9.0.5", False)):
        request = header(
            manager, {"destination_address": int(ipaddress.ip_address(dst))}, explicitly_all=fields
        )
        result = PolicyCompiler(manager, CONTEXT, request.known_fields).compile(policy).evaluate(request)
        assert result.bounds.lower.equivalent(result.bounds.upper)
        assert result.bounds.lower.is_empty() is not permitted
