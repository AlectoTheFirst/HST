from dataclasses import replace
from datetime import UTC, datetime

from hst.analysis_model.dependencies import AbsenceSelector, DependencyIndex, QualifiedRef
from hst.analysis_model.evidence import EvidenceEvaluation, EvidencePolicy
from hst.analysis_model.graph import GraphInventory
from hst.analysis_model.incremental import plan_incremental, plan_model_incremental
from hst.analysis_model.model import (
    ChoiceAssignment,
    EdgeSpec,
    EntrySpec,
    ModelInput,
    NodeSpec,
    StateKey,
)
from hst.assessment.symbolic_evaluation import SymbolicEvaluation
from hst.impact.symbolic_walk import walk
from hst.policy.ir import (
    Atom,
    Constant,
    ExecutionContext,
    Layer,
    ObjectDefinition,
    ObjectKey,
    Policy,
    Ref,
    Rule,
)
from hst.symbolic import HeaderSchema, SymbolicManager, header

from .test_assessment_symbolic_bridge import native as native


def ref(kind, uid):
    return QualifiedRef(kind, "estate/domain", uid)


def _equivalent(left, right, manager, request_id):
    packets = header(manager, {}, explicitly_all=manager.schema.field_names)
    incremental = walk(left, packets, request_id=f"{request_id}-incremental")
    cold = walk(right, packets, request_id=f"{request_id}-cold")
    assert incremental.bounds.lower.equivalent(cold.bounds.lower)
    assert incremental.bounds.upper.equivalent(cold.bounds.upper)


def test_policy_edit_reuses_independent_routing_and_closes_transitively():
    route, rule, path, untouched = (
        ref("route", "r1"),
        ref("rule", "p1"),
        ref("path", "x"),
        ref("route", "r2"),
    )
    index = DependencyIndex()
    index.add(path, [rule])
    index.add(rule, [route])
    plan = plan_incremental(current=index, changed=[rule], universe=[route, rule, path, untouched])
    assert plan.affected == {rule, path}
    assert plan.routing == set()
    assert untouched in plan.reused
    assert plan.counters["policy_recomputed"] == 2


def test_old_dependencies_and_negative_selectors_invalidate_new_absences():
    old, current = DependencyIndex(), DependencyIndex()
    route, path, new_default = ref("route", "old"), ref("path", "x"), ref("route", "default")
    old.add(path, [route])
    old.record_absence(path, AbsenceSelector("route", "estate/domain", "default"))
    plan = plan_incremental(
        current=current, previous=old, changed=[new_default], universe=[route, path, new_default]
    )
    assert path in plan.affected


def test_incomplete_capture_forces_broad_rebuild():
    refs = [ref("route", "r"), ref("rule", "p")]
    plan = plan_incremental(current=DependencyIndex(), changed=[], universe=refs, complete=False)
    assert plan.broad_rebuild and plan.affected == set(refs) and not plan.reused


def test_production_compiler_reuses_only_dependency_unaffected_nodes(native):
    context = ExecutionContext("estate", "authority", "domain", "firewall", "vrf", 4)
    a = StateKey("a", context)
    b = StateKey("b", context)
    independent = StateKey("independent", context)
    initial = ModelInput(
        "a" * 64,
        (
            NodeSpec(a, edges=(EdgeSpec("to-b", b, Constant(True)),)),
            NodeSpec(independent, terminal="permit"),
        ),
        (EntrySpec(a),),
        (ChoiceAssignment("only"),),
        True,
    )
    added = ModelInput(
        "a" * 64,
        (*initial.nodes, NodeSpec(b, terminal="permit")),
        initial.entries,
        initial.choices,
        True,
    )
    graph = GraphInventory("a" * 64, "graph", {}, {}, {}, {}, True, (), 0)
    evaluation = SymbolicEvaluation(graph, "estate")
    try:
        first = evaluation._compile_uncached(initial, native, native.schema.field_names)
        second = evaluation._compile_uncached(added, native, native.schema.field_names)
        cold = SymbolicEvaluation(graph, "estate")
        try:
            expected = cold._compile_uncached(added, native, native.schema.field_names)
        finally:
            cold.close()
        first_nodes = {node.key: node for node in first.nodes}
        second_nodes = {node.key: node for node in second.nodes}
        assert second.fingerprint == expected.fingerprint
        _equivalent(second, expected, native, "add")
        assert second_nodes[independent] is first_nodes[independent]
        assert second_nodes[a] is not first_nodes[a]
        assert evaluation._policy_metrics["incremental_nodes_reused"] == 1

        removed = evaluation._compile_uncached(initial, native, native.schema.field_names)
        cold_removed = SymbolicEvaluation(graph, "estate")
        try:
            expected_removed = cold_removed._compile_uncached(initial, native, native.schema.field_names)
        finally:
            cold_removed.close()
        _equivalent(removed, expected_removed, native, "remove")
        removed_nodes = {node.key: node for node in removed.nodes}
        assert removed_nodes[independent] is second_nodes[independent]
        assert removed_nodes[a] is not second_nodes[a]
    finally:
        evaluation.close()


def test_policy_order_default_object_and_evidence_changes_invalidate_node(native):
    context = ExecutionContext("estate", "authority", "domain", "firewall", "vrf", 4)
    key = StateKey("filter", context)
    object_key = ObjectKey("authority", "domain", "object")
    obj = ObjectDefinition(object_key, "one", Atom("protocol", "eq", 6))
    rules = (
        Rule("first", Ref(object_key), "permit"),
        Rule("second", Constant(True), "deny"),
    )

    def source(policy, evidence=None):
        return ModelInput(
            "a" * 64,
            (NodeSpec(key, terminal="permit", policy=policy),),
            (EntrySpec(key),),
            (ChoiceAssignment("only"),),
            True,
            evidence=evidence,
        )

    def policy(*, ordered_rules=rules, default="deny", objects=(obj,)):
        layer = Layer("layer", ordered_rules, default)
        return Policy(
            "policy",
            "revision",
            context,
            (layer,),
            (layer.uid,),
            objects,
            Constant(True),
            manifest_digest="a" * 64,
        )

    baseline = source(policy())
    state, _ = plan_model_incremental(baseline, None)
    variants = (
        source(policy(ordered_rules=tuple(reversed(rules)))),
        source(policy(default="permit")),
        source(policy(objects=(replace(obj, predicate=Atom("protocol", "eq", 17)),))),
        source(
            policy(),
            EvidenceEvaluation(datetime(2026, 1, 1, tzinfo=UTC), EvidencePolicy(), (), ()),
        ),
    )
    for variant in variants:
        _, plan = plan_model_incremental(variant, state)
        assert not plan.reused
    graph = GraphInventory("a" * 64, "graph", {}, {}, {}, {}, True, (), 0)
    warm = SymbolicEvaluation(graph, "estate")
    try:
        warm._compile_uncached(baseline, native, native.schema.field_names)
        for index, variant in enumerate(variants):
            incremental = warm._compile_uncached(variant, native, native.schema.field_names)
            cold = SymbolicEvaluation(graph, "estate")
            try:
                expected = cold._compile_uncached(variant, native, native.schema.field_names)
            finally:
                cold.close()
            _equivalent(incremental, expected, native, f"policy-{index}")
    finally:
        warm.close()


def test_compiled_model_cache_never_crosses_manager_ownership(native):
    context = ExecutionContext("estate", "authority", "domain", "firewall", "vrf", 4)
    key = StateKey("terminal", context)
    source = ModelInput(
        "a" * 64,
        (NodeSpec(key, terminal="permit"),),
        (EntrySpec(key),),
        (ChoiceAssignment("only"),),
        True,
    )
    graph = GraphInventory("a" * 64, "graph", {}, {}, {}, {}, True, (), 0)
    evaluation = SymbolicEvaluation(graph, "estate")
    try:
        first = evaluation.compile(source, native, native.schema.field_names)
        with SymbolicManager(HeaderSchema.ipv4()) as other:
            second = evaluation.compile(source, other, other.schema.field_names)
            assert second is not first
            assert second.universe.manager is other
    finally:
        evaluation.close()
