"""Small deterministic checks for the synthetic policy-scale generator."""

from __future__ import annotations

import importlib
import os
from itertools import pairwise

import pytest

from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager

runner = importlib.import_module("tools.benchmark_policy_compiler")


def test_fixture_freezes_seed_counts_and_scope() -> None:
    fixture = runner.load_fixture()
    assert fixture["seed"] == 1209
    assert fixture["seeds"] == [1209, 1210, 1211, 1212, 1213]
    assert fixture["rule_counts"] == [1000, 5000, 20000, 50000, 100000]
    assert fixture["default_rule_counts"] == [1000]
    assert "not whole-enterprise qualification" in fixture["purpose"]


def test_generator_is_deterministic_and_has_real_cardinality() -> None:
    first, first_meta = runner.generate_policy(64, seed=1209)
    second, second_meta = runner.generate_policy(64, seed=1209)
    assert first == second
    assert first_meta == second_meta
    assert first_meta["layer_counts"]["enabled_rules"] == 64
    assert first_meta["object_counts"]["rule_objects"] == 64
    assert first_meta["object_counts"]["membership_edges"] > 0
    assert len({rule.uid for layer in first.layers for rule in layer.rules}) == 64
    regular_count = 64 - 2 * runner.INLINE_LAYER_COUNT
    predicate_inputs = {
        (
            first_meta["source_ranges"][index],
            first_meta["destination_ranges"][index],
            first_meta["service_protocols"][index],
            first_meta["service_ports"][index],
        )
        for index in range(regular_count)
    }
    assert len(predicate_inputs) == regular_count


def test_generated_address_ranges_overlap_and_shared_groups_are_referenced() -> None:
    policy, metadata = runner.generate_policy(128, seed=1213)
    ranges = metadata["source_ranges"][1:]
    assert any(left[0] <= right[1] and right[0] <= left[1] for left, right in pairwise(ranges))
    roots = set(metadata["group_roots"])
    refs = {
        term.key
        for layer in policy.layers
        for rule in layer.rules
        for term in getattr(rule.predicate, "terms", ())
        if isinstance(term, runner.Ref)
    }
    assert roots & refs
    assert len(roots) < sum(1 for layer in policy.layers for rule in layer.rules if rule.action != "call")


def test_output_schema_is_deterministic_without_native_backend() -> None:
    fixture = runner.load_fixture()
    assert {
        "format_version",
        "kind",
        "purpose",
        "seed",
        "seeds",
        "rule_counts",
        "context",
        "workload",
    } <= fixture.keys()
    assert fixture["workload"]["overlapping_address_ranges"] is True
    assert fixture["workload"]["shared_group_references"] is True


@pytest.fixture
def native_manager():
    try:
        manager = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native symbolic backend missing")
    with manager:
        yield manager
    assert len(manager._bdd) == 0


def test_native_edit_probes_are_observable_and_semantically_equal(native_manager) -> None:
    policy, metadata = runner.generate_policy(64, seed=1209)
    query = runner._query(native_manager, metadata, 0, source=100)
    compiler = runner.PolicyCompiler(native_manager, policy.context, query.known_fields)
    original = compiler.compile(policy)
    rule_edit = runner._edit_policy_rule(policy)
    incremental_rule = compiler.compile(rule_edit)
    cold_rule = runner.PolicyCompiler(native_manager, policy.context, query.known_fields).compile(rule_edit)
    assert runner._semantic_equal(incremental_rule, cold_rule)
    assert runner._outcome(original, query) != runner._outcome(incremental_rule, query)

    object_compiler = runner.PolicyCompiler(native_manager, policy.context, query.known_fields)
    object_compiler.compile(policy)
    object_edit = runner._edit_policy_object(policy, metadata)
    object_query = runner._query(native_manager, metadata, 4, source=runner.MAX_IPV4 - 100)
    before = runner._outcome(object_compiler.compile(policy), object_query)
    after = object_compiler.compile(object_edit)
    cold_after = runner.PolicyCompiler(native_manager, policy.context, query.known_fields).compile(
        object_edit
    )
    assert runner._semantic_equal(after, cold_after)
    assert before != runner._outcome(after, object_query)
    assert after.stats.compiled_blocks >= 1
