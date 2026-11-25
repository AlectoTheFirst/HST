"""Exercise policy quantifiers on real CUDD sets, without enumerating addresses."""

from __future__ import annotations

import importlib
import os

import pytest

from hst.policy.bounds import Bounds, TerminalRule, at_least, choices, first_match, for_all_requested_flows
from hst.symbolic import HeaderSchema, SymbolicManager, any_of, header

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for backend qualification")


@pytest.fixture
def manager():
    with SymbolicManager(HeaderSchema.ipv6()) as native:
        yield native


def test_universal_flows_count_clients_and_keep_partial_clients_unknown(manager):
    from hst.symbolic import prefix

    clients = prefix(manager, "source_address", "2001:db8::/64")
    query = clients.intersect(header(manager, {"protocol": 6, "destination_port": [80, 443]}))
    port80 = query.intersect(header(manager, {"destination_port": 80}))
    population = query.project(["source_address"])

    def project(packets):
        return packets.project(["source_address"])

    partial = for_all_requested_flows(Bounds(query, port80, query), population, project)
    assert partial.lower.is_empty()
    assert partial.upper.cardinality(["source_address"]) == 2**64
    blocked443 = for_all_requested_flows(Bounds(query, port80, port80), population, project)
    assert blocked443.upper.is_empty()
    all_permitted = for_all_requested_flows(Bounds.terminal(query, "permit"), population, project)
    assert all_permitted.lower.cardinality(["source_address"]) == 2**64


def test_ordered_unknown_predicate_preserves_identical_outcome_proof(manager):
    query = header(manager, {"protocol": 6, "destination_port": [80, 443]})
    unknown = Bounds.terminal(query, "unknown")
    permit = first_match(query, [TerminalRule(unknown, "permit")], default="permit")
    assert permit.lower.equivalent(query)
    ambiguous = first_match(query, [TerminalRule(unknown, "deny")], default="permit")
    assert ambiguous.lower.is_empty()
    assert ambiguous.upper.equivalent(query)


def test_forwarding_quantifier_is_distinct_from_evidence_uncertainty(manager):
    query = header(manager, {"protocol": 6, "destination_port": [80, 443]})
    branch_a = query.intersect(any_of(manager, "destination_port", [80]))
    branch_b = query.intersect(any_of(manager, "destination_port", [443]))
    branches = [Bounds(query, branch, branch) for branch in (branch_a, branch_b)]
    assert choices(query, branches, mode="possible").lower.equivalent(query)
    assert choices(query, branches, mode="guaranteed").upper.is_empty()
    unknown_choice = choices(query, branches, mode="unspecified")
    assert unknown_choice.lower.is_empty()
    assert unknown_choice.upper.equivalent(query)
    assert at_least(query, branches, 1).lower.equivalent(query)
    assert at_least(query, branches, 2).upper.is_empty()


def test_bounds_reject_cross_manager_sets(manager):
    with SymbolicManager(HeaderSchema.ipv6()) as other:
        from hst.symbolic import ManagerMismatchError

        with pytest.raises(ManagerMismatchError):
            Bounds(manager.universe(), other.empty(), manager.universe())
