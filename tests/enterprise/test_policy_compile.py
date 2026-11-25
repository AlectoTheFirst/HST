"""Policy compilation checked against a separate concrete control-flow evaluator."""

from __future__ import annotations

import os
from dataclasses import replace
from itertools import product

import pytest

from hst.policy.compile import PolicyCompiler
from hst.policy.ir import (
    AllOf,
    AnyOf,
    Atom,
    Constant,
    ExecutionContext,
    Layer,
    Not,
    ObjectDefinition,
    ObjectKey,
    Policy,
    Ref,
    Rule,
    Unknown,
)
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager, header


@pytest.fixture
def manager():
    try:
        native = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with native:
        yield native
    assert len(native._bdd) == 0


CONTEXT = ExecutionContext("estate", "manager", "domain", "gateway/vs/7", "vrf", 4)


def policy(*layers, ordered=None, objects=(), **kwargs):
    return Policy(
        "package",
        "r1",
        CONTEXT,
        layers,
        ordered or (layers[0].uid,),
        objects,
        installation=Constant(True),
        **kwargs,
    )


def setup(manager, *, stated=True):
    request = header(
        manager,
        {"protocol": 6, "fragment_offset": 0, "dscp": (0, 3), "ecn": (0, 3)},
        explicitly_all=manager.schema.field_names if stated else (),
    )
    return request, PolicyCompiler(manager, CONTEXT, request.known_fields)


def values(packets, field="dscp"):
    result = packets.render([field], limit=256)
    assert not result.truncated
    return {row[field] for row in result.rows}


def concrete_predicate(predicate, packet, objects, unknowns):
    if isinstance(predicate, Constant):
        return predicate.value
    if isinstance(predicate, Unknown):
        return unknowns[predicate.subject]
    if isinstance(predicate, Atom):
        value = packet[predicate.field]
        if predicate.operation == "eq":
            return value == predicate.value
        if predicate.operation == "range":
            return predicate.value <= value <= predicate.other
        return value & predicate.other == predicate.value & predicate.other
    if isinstance(predicate, AllOf):
        return all(concrete_predicate(term, packet, objects, unknowns) for term in predicate.terms)
    if isinstance(predicate, AnyOf):
        return any(concrete_predicate(term, packet, objects, unknowns) for term in predicate.terms)
    if isinstance(predicate, Not):
        return not concrete_predicate(predicate.term, packet, objects, unknowns)
    if isinstance(predicate, Ref):
        return concrete_predicate(objects[predicate.key].predicate, packet, objects, unknowns)
    raise AssertionError(predicate)


def concrete_layer(uid, packet, layers, objects, unknowns):
    layer = layers[uid]
    for rule in layer.rules:
        if not rule.enabled or (
            rule.install_targets and CONTEXT.firewall_instance not in rule.install_targets
        ):
            continue
        if not concrete_predicate(rule.predicate, packet, objects, unknowns):
            continue
        action = rule.action
        if action == "call":
            action = concrete_layer(rule.called_layer, packet, layers, objects, unknowns)
            if action == "return":
                continue
        return action
    return layer.default


def test_exact_nested_inline_and_ordered_layers_match_concrete_oracle(manager):
    request, compiler = setup(manager)
    group = ObjectKey("manager", "domain", "services")
    obj = ObjectDefinition(group, "1", AnyOf((Atom("dscp", "eq", 1), Atom("ecn", "mask", 1, 1))))
    inner = Layer(
        "inner", (Rule("inner-deny", AllOf((Ref(group), Not(Atom("dscp", "eq", 3)))), "deny"),), "return"
    )
    nested = Layer(
        "nested",
        (
            Rule("call-inner", Constant(True), "call", called_layer="inner"),
            Rule("special", Atom("dscp", "eq", 3), "permit"),
        ),
        "return",
    )
    first = Layer(
        "first",
        (
            Rule("call", Constant(True), "call", called_layer="nested"),
            Rule("permit", Atom("ecn", "eq", 0), "permit"),
        ),
        "deny",
    )
    second = Layer("second", (Rule("later-deny", Atom("ecn", "eq", 2), "deny"),), "permit")
    source = policy(first, second, nested, inner, ordered=("first", "second"), objects=(obj,))
    result = compiler.compile(source).evaluate(request)
    expected = set()
    for dscp, ecn in product(range(4), repeat=2):
        packet = {"dscp": dscp, "ecn": ecn}
        if all(
            concrete_layer(uid, packet, {layer.uid: layer for layer in source.layers}, {group: obj}, {})
            == "permit"
            for uid in source.ordered_layers
        ):
            expected.add((dscp, ecn))
    rows = result.bounds.lower.render(["dscp", "ecn"], limit=16)
    assert {(row["dscp"], row["ecn"]) for row in rows.rows} == expected
    assert result.bounds.lower.equivalent(result.bounds.upper)
    assert not result.gaps


@pytest.mark.parametrize("actions", tuple(product(("permit", "deny"), repeat=3)))
def test_unknown_predicates_bound_all_concrete_completions(manager, actions):
    request, compiler = setup(manager)
    rules = (
        Rule("first", AllOf((Atom("dscp", "range", 0, 1), Unknown("APPLICATION", "x"))), actions[0]),
        Rule("second", Unknown("IDENTITY", "y"), actions[1]),
    )
    layer = Layer("root", rules, actions[2])
    result = compiler.compile(policy(layer)).evaluate(request)
    worlds = []
    for x, y in product((False, True), repeat=2):
        worlds.append(
            {
                value
                for value in range(4)
                if concrete_layer("root", {"dscp": value}, {"root": layer}, {}, {"x": x, "y": y}) == "permit"
            }
        )
    assert values(result.bounds.lower) == set.intersection(*worlds)
    assert values(result.bounds.upper) == set.union(*worlds)
    if len(set(actions)) == 1:
        assert not result.gaps


def test_missing_cyclic_and_partial_objects_preserve_known_members(manager):
    request, compiler = setup(manager)
    a, b = ObjectKey("manager", "domain", "a"), ObjectKey("manager", "domain", "b")
    root = Layer("root", (Rule("permit", Ref(a), "permit"),), "deny")
    complete = ObjectDefinition(a, "1", AnyOf((Atom("dscp", "eq", 1), Ref(b))))
    result = compiler.compile(policy(root, objects=(complete,))).evaluate(request)
    assert values(result.bounds.lower) == {1}
    assert values(result.bounds.upper) == set(range(4))
    assert {gap.reason.code for gap in result.gaps} == {"OBJECT_MISSING"}
    cycle = ObjectDefinition(b, "1", Ref(a))
    result = compiler.compile(policy(root, objects=(complete, cycle))).evaluate(request)
    assert values(result.bounds.lower) == {1}
    assert values(result.bounds.upper) == set(range(4))
    assert {gap.reason.code for gap in result.gaps} == {"OBJECT_CYCLE"}
    partial = ObjectDefinition(a, "2", Atom("dscp", "eq", 2), complete=False)
    result = compiler.compile(policy(root, objects=(partial,))).evaluate(request)
    assert values(result.bounds.lower) == {2}
    assert values(result.bounds.upper) == set(range(4))


def test_missing_object_addition_and_object_only_edit_invalidate_blocks(manager):
    request, compiler = setup(manager)
    key = ObjectKey("manager", "domain", "target")
    rules = tuple(
        Rule(f"r-{index}", Ref(key) if index == 260 else Constant(False), "permit") for index in range(1024)
    )
    root = Layer("root", rules, "deny")
    original = policy(root)
    initial = compiler.compile(original)
    assert initial.stats.compiled_blocks == 4
    again = compiler.compile(original)
    assert again.stats.compiled_blocks == 0
    assert again.stats.reused_blocks == 4
    assert again.stats.recomposed_nodes == 0
    added = replace(original, objects=(ObjectDefinition(key, "1", Atom("dscp", "eq", 1)),))
    compiled = compiler.compile(added)
    assert compiled.stats.compiled_blocks == 1
    assert compiled.stats.reused_blocks == 3
    assert compiled.stats.recomposed_nodes == 2
    assert values(compiled.evaluate(request).bounds.lower) == {1}
    edited = replace(added, objects=(ObjectDefinition(key, "2", Atom("dscp", "eq", 2)),))
    incremental = compiler.compile(edited)
    cold = PolicyCompiler(manager, CONTEXT, request.known_fields).compile(edited)
    assert incremental.bounds.lower.equivalent(cold.bounds.lower)
    assert incremental.bounds.upper.equivalent(cold.bounds.upper)
    assert incremental.stats.compiled_blocks == 1
    assert values(compiled.evaluate(request).bounds.lower) == {1}
    assert values(incremental.evaluate(request).bounds.lower) == {2}


def test_disabled_install_target_order_and_inline_child_edits(manager):
    request, compiler = setup(manager)
    deny = Rule("deny", Constant(True), "deny", enabled=False)
    root = Layer("root", (deny, Rule("call", Constant(True), "call", called_layer="child")), "deny")
    child = Layer("child", (Rule("p", Atom("dscp", "eq", 1), "permit"),), "return")
    source = policy(root, child)
    assert values(compiler.compile(source).evaluate(request).bounds.lower) == {1}
    child2 = replace(child, rules=(replace(child.rules[0], predicate=Atom("dscp", "eq", 2)),))
    changed = compiler.compile(replace(source, layers=(root, child2)))
    assert values(changed.evaluate(request).bounds.lower) == {2}
    assert changed.stats.compiled_blocks == 2
    enabled = replace(root, rules=(replace(deny, enabled=True), root.rules[1]))
    assert (
        compiler.compile(replace(source, layers=(enabled, child))).evaluate(request).bounds.upper.is_empty()
    )
    other_target = replace(
        enabled, rules=(replace(enabled.rules[0], install_targets=("other/vs",)), root.rules[1])
    )
    assert values(
        compiler.compile(replace(source, layers=(other_target, child))).evaluate(request).bounds.lower
    ) == {1}
    moved = replace(enabled, rules=tuple(reversed(enabled.rules)))
    assert values(
        compiler.compile(replace(source, layers=(moved, child))).evaluate(request).bounds.lower
    ) == {1}


def test_unstated_fields_never_become_stated_and_header_padding_is_not_port_evidence(manager):
    request = header(manager, {"protocol": 6, "fragment_offset": 0})
    compiler = PolicyCompiler(manager, CONTEXT, request.known_fields)
    source = policy(Layer("root", (Rule("zero", Atom("destination_port", "eq", 0), "permit"),), "deny"))
    result = compiler.compile(source).evaluate(request)
    assert result.bounds.lower.is_empty()
    assert result.bounds.upper.equivalent(request)
    assert result.bounds.upper.known_fields == request.known_fields
    assert {gap.reason.subject for gap in result.gaps} == {"destination_port"}
    for query in (
        header(manager, {"protocol": 47, "fragment_offset": 0}, explicitly_all=manager.schema.field_names),
        header(manager, {"protocol": 6, "fragment_offset": 1}, explicitly_all=manager.schema.field_names),
    ):
        result = PolicyCompiler(manager, CONTEXT, query.known_fields).compile(source).evaluate(query)
        assert result.bounds.upper.is_empty()


def test_installation_unknown_context_mismatch_and_cycle_are_explicit(manager):
    request, compiler = setup(manager)
    root = Layer("root", (), "permit")
    source = policy(root)
    unknown_install = replace(source, installation=Unknown("INSTALLATION_UNKNOWN", "package"))
    result = compiler.compile(unknown_install).evaluate(request)
    assert result.bounds.lower.is_empty()
    assert result.bounds.upper.equivalent(request)
    with pytest.raises(ValueError, match="context"):
        compiler.compile(replace(source, context=replace(CONTEXT, firewall_instance="gateway/vs/8")))
    with pytest.raises(ValueError, match="knowledge"):
        compiler.compile(source).evaluate(request.with_knowledge(()))
    cyclic = Layer("root", (Rule("cycle", Constant(True), "call", called_layer="root"),), "deny")
    result = compiler.compile(policy(cyclic)).evaluate(request)
    assert result.bounds.lower.is_empty()
    assert result.bounds.upper.equivalent(request)
    assert "LAYER_CALL_CYCLE" in {gap.reason.code for gap in result.gaps}


def test_rule_attribution_is_separate_from_identical_action_proof(manager):
    request, compiler = setup(manager)
    source = policy(
        Layer(
            "root",
            (Rule("maybe", Unknown("APP", "application"), "permit"), Rule("later", Constant(True), "permit")),
            "deny",
        )
    )
    compiled = compiler.compile(source)
    assert compiled.evaluate(request).bounds.lower.equivalent(request)
    attribution = compiled.explain_rule("root", "later")
    assert attribution.bounds.lower.is_empty()
    assert attribution.bounds.upper.intersect(request).equivalent(request)


def test_invalid_ir_and_unsupported_field(manager):
    with pytest.raises(ValueError):
        Atom("dscp", "range", 4, 2)
    with pytest.raises(ValueError):
        Rule("call", Constant(True), "call")
    request, compiler = setup(manager)
    source = policy(Layer("root", (Rule("opaque", Atom("unknown_vendor_field", "eq", 1), "permit"),), "deny"))
    result = compiler.compile(source).evaluate(request)
    assert result.bounds.lower.is_empty()
    assert result.bounds.upper.equivalent(request)
    assert {gap.reason.code for gap in result.gaps} == {"UNSUPPORTED_FIELD"}


def test_shared_group_dependencies_stay_compact_and_transitive_edits_invalidate(manager):
    request, compiler = setup(manager)
    leaf = ObjectKey("manager", "domain", "leaf")
    shared = ObjectKey("manager", "domain", "shared")
    members = tuple(ObjectKey("manager", "domain", f"member-{index}") for index in range(100))
    definitions = (
        ObjectDefinition(leaf, "1", Atom("dscp", "eq", 1)),
        *(ObjectDefinition(key, "1", Ref(leaf)) for key in members),
        ObjectDefinition(shared, "1", AnyOf(tuple(Ref(key) for key in members))),
    )
    rules = tuple(Rule(f"use-{index}", Ref(shared), "permit") for index in range(512))
    source = policy(Layer("root", rules, "deny"), objects=definitions)
    first = compiler.compile(source)
    assert first.stats.compiled_objects == 102
    assert values(first.evaluate(request).bounds.lower) == {1}
    assert compiler.predicates.compile(Ref(shared)).dependencies == frozenset({shared})
    assert all(block.dependencies == frozenset({shared}) for block in compiler._blocks.values())
    changed = (replace(definitions[0], predicate=Atom("dscp", "eq", 2)), *definitions[1:])
    second = compiler.compile(replace(source, objects=changed))
    assert second.stats.compiled_blocks == 2
    assert values(second.evaluate(request).bounds.lower) == {2}
    assert values(first.evaluate(request).bounds.lower) == {1}


def test_compiled_lower_upper_roots_replay_in_a_fresh_manager(manager):
    from hst.policy.bounds import Bounds
    from hst.symbolic.artifacts import decode_packet_sets, encode_packet_sets

    request, compiler = setup(manager)
    source = policy(
        Layer(
            "root",
            (
                Rule("known", Atom("dscp", "eq", 1), "permit"),
                Rule("uncertain", AllOf((Atom("dscp", "range", 0, 2), Unknown("APP", "app"))), "permit"),
            ),
            "deny",
        )
    )
    bounds = compiler.compile(source).evaluate(request).bounds
    encoded = encode_packet_sets({"universe": bounds.universe, "lower": bounds.lower, "upper": bounds.upper})
    with SymbolicManager(HeaderSchema.ipv4()) as replay_manager:
        roots = decode_packet_sets(encoded, replay_manager)
        replayed = Bounds(roots["universe"], roots["lower"], roots["upper"])
        assert values(replayed.lower) == {1}
        assert values(replayed.upper) == {0, 1, 2}
        assert replayed.universe.known_fields == request.known_fields
