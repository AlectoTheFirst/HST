"""Independent finite execution checks for the normalized relational worklist."""

from __future__ import annotations

import os
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from hst.analysis_model.compile import RouteSpec, compile_model, fib_edges
from hst.analysis_model.evidence import (
    CaptureOutcome,
    ClockQuality,
    EvidencePolicy,
    EvidenceWindow,
    evaluate_evidence,
)
from hst.analysis_model.model import (
    ChoiceAssignment,
    EdgeSpec,
    EntrySpec,
    EvidenceRef,
    ModelInput,
    NodeSpec,
    RangeRewriteSpec,
    StateKey,
    semantic_fingerprint,
)
from hst.impact.symbolic_answer import compound_members
from hst.impact.symbolic_walk import WalkLimits, walk
from hst.policy.ir import Atom, Constant, ExecutionContext, Layer, Policy, Rule, Unknown
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager
from hst.symbolic.predicates import header

MANIFEST = "a" * 64
CONTEXT = ExecutionContext("estate", "manager", "domain", "vs/1", "vrf", 4)
ONLY = (ChoiceAssignment("one"),)


def key(name: str) -> StateKey:
    return StateKey(name, CONTEXT)


@pytest.fixture
def manager():
    try:
        manager = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with manager:
        yield manager
    assert len(manager._bdd) == 0


def query(manager):
    return header(
        manager,
        {
            "protocol": 17,
            "source_address": 10,
            "destination_address": 20,
            "source_port": 123,
            "destination_port": 443,
            "fragment_offset": 0,
        },
        explicitly_all=manager.schema.field_names,
    )


def model(manager, nodes, *, entries=None, assignments=ONLY, complete=True, known=None):
    source = ModelInput(
        MANIFEST,
        tuple(nodes),
        tuple(entries) if entries is not None else (EntrySpec(key("a")),),
        assignments,
        complete,
    )
    return compile_model(source, manager, manager.schema.field_names if known is None else known)


def ecn_values(packets):
    return {
        value
        for value in range(4)
        if not packets.intersect(header(packets.manager, {"ecn": value}, bank="original")).is_empty()
    }


@pytest.mark.parametrize("seed", range(12))
def test_worklist_matches_independent_finite_forwarding_oracle(manager, seed):
    rng = random.Random(seed)
    table = {(node, ecn): (rng.randrange(5), rng.randrange(4)) for node in range(3) for ecn in range(4)}
    nodes = []
    for node in range(3):
        edges = tuple(
            EdgeSpec(
                str(ecn),
                key(str(table[node, ecn][0])),
                Atom("ecn", "eq", ecn),
                (("ecn", table[node, ecn][1]),),
            )
            for ecn in range(4)
        )
        nodes.append(NodeSpec(key(str(node)), edges))
    nodes.extend((NodeSpec(key("3"), terminal="permit"), NodeSpec(key("4"), terminal="deny")))
    compiled = model(manager, nodes, entries=(EntrySpec(key("0")),))
    result = walk(compiled, query(manager), request_id="finite")
    expected, loops = set(), set()
    for original in range(4):
        node, value, seen = 0, original, set()
        while node < 3 and (node, value) not in seen:
            seen.add((node, value))
            node, value = table[node, value]
        if node == 3:
            expected.add(original)
        elif node < 3:
            loops.add(original)
    assert ecn_values(result.bounds.lower) == ecn_values(result.bounds.upper) == expected
    assert ecn_values(dict(result.by_choice[0].outcomes)["loop"]) == loops
    assert result.complete and result.database_reads == 0


def test_diamond_merge_is_not_a_loop_and_infinite_alternative_prevents_proof(manager):
    nodes = [
        NodeSpec(key("a"), (EdgeSpec("left", key("b")), EdgeSpec("right", key("c")))),
        NodeSpec(key("b"), (EdgeSpec("end", key("d")),)),
        NodeSpec(key("c"), (EdgeSpec("end", key("d")),)),
        NodeSpec(key("d"), terminal="permit"),
    ]
    result = walk(model(manager, nodes), query(manager), request_id="diamond")
    assert ecn_values(result.bounds.lower) == set(range(4))
    assert dict(result.by_choice[0].outcomes)["loop"].is_empty()
    nodes[1] = NodeSpec(key("b"), (EdgeSpec("loop", key("b")), EdgeSpec("exit", key("d"))))
    result = walk(model(manager, nodes), query(manager), request_id="infinite")
    assert result.bounds.lower.is_empty()
    assert ecn_values(result.bounds.upper) == set(range(4))
    assert ecn_values(dict(result.by_choice[0].outcomes)["loop"]) == set(range(4))


def test_forwarding_choices_and_compound_members_retain_joint_assignment(manager):
    assignments = (
        ChoiceAssignment("left", (("ecmp", "left"),)),
        ChoiceAssignment("right", (("ecmp", "right"),)),
    )

    def member(reverse=False):
        nodes = (
            NodeSpec(
                key("a"),
                (
                    EdgeSpec("left", key("yes" if not reverse else "no"), choices=(("ecmp", "left"),)),
                    EdgeSpec("right", key("no" if not reverse else "yes"), choices=(("ecmp", "right"),)),
                ),
            ),
            NodeSpec(key("yes"), terminal="permit"),
            NodeSpec(key("no"), terminal="deny"),
        )
        return model(manager, nodes, assignments=assignments)

    request = query(manager)
    possible = walk(member(), request, request_id="shared", mode="possible")
    guaranteed = walk(member(), request, request_id="shared", mode="guaranteed")
    unspecified = walk(member(), request, request_id="shared")
    assert ecn_values(possible.bounds.lower) == set(range(4))
    assert guaranteed.bounds.upper.is_empty()
    assert unspecified.bounds.lower.is_empty() and ecn_values(unspecified.bounds.upper) == set(range(4))
    other = walk(member(True), request, request_id="shared", mode="possible")
    assert ecn_values(other.bounds.lower) == set(range(4))
    assert compound_members((possible, other), count=2, mode="possible").upper.is_empty()
    assert ecn_values(compound_members((possible, other), count=1, mode="guaranteed").lower) == set(range(4))
    with pytest.raises(ValueError, match="identity"):
        compound_members((possible, replace(other, request_id="different")), count=1)


def test_compiled_policy_unknowns_missing_nodes_and_attachments(manager):
    policy = Policy(
        "p",
        "1",
        CONTEXT,
        (Layer("l", (Rule("r", Unknown("MISSING_OBJECT", "x"), "permit"),), "deny"),),
        ("l",),
        installation=Constant(True),
        manifest_digest=MANIFEST,
    )
    nodes = (NodeSpec(key("a"), terminal="permit", policy=policy),)
    result = walk(model(manager, nodes), query(manager), request_id="policy")
    assert result.bounds.lower.is_empty() and ecn_values(result.bounds.upper) == set(range(4))
    assert "MISSING_OBJECT" in result.gap_refs
    missing = walk(
        model(manager, (NodeSpec(key("a"), (EdgeSpec("lost", key("absent")),)),)),
        query(manager),
        request_id="missing",
    )
    assert missing.bounds.lower.is_empty() and ecn_values(missing.bounds.upper) == set(range(4))
    assert "MODEL_NODE_MISSING" in missing.gap_refs
    no_attachment = walk(model(manager, nodes, entries=()), query(manager), request_id="none")
    assert no_attachment.bounds.lower.is_empty() and "SOURCE_ATTACHMENT_UNKNOWN" in no_attachment.gap_refs


@pytest.mark.parametrize(
    "limit,code",
    [(WalkLimits(max_states=1), "ANALYSIS_STATE_LIMIT"), (WalkLimits(max_steps=1), "ANALYSIS_STEP_LIMIT")],
)
def test_limit_is_unknown_not_loop_or_denial(manager, limit, code):
    compiled = model(
        manager, (NodeSpec(key("a"), (EdgeSpec("b", key("b")),)), NodeSpec(key("b"), terminal="permit"))
    )
    result = walk(compiled, query(manager), request_id="limit", limits=limit)
    assert not result.complete and result.bounds.lower.is_empty()
    assert ecn_values(result.bounds.upper) == set(range(4))
    assert code in result.gap_refs
    cancelled = walk(compiled, query(manager), request_id="cancel", cancelled=lambda: True)
    assert not cancelled.complete and "ANALYSIS_CANCELLED" in cancelled.gap_refs


def test_original_identity_survives_many_to_one_rewrite(manager):
    nodes = (
        NodeSpec(key("a"), (EdgeSpec("nat", key("b"), rewrites=(("ecn", 0),)),)),
        NodeSpec(key("b"), (EdgeSpec("permit", key("yes"), Atom("ecn", "eq", 0)),)),
        NodeSpec(key("yes"), terminal="permit"),
    )
    result = walk(model(manager, nodes), query(manager), request_id="nat")
    assert ecn_values(result.bounds.lower) == ecn_values(result.bounds.upper) == set(range(4))


def test_symbolic_fib_longest_prefix_and_no_route(manager):
    edges = fib_edges(
        (RouteSpec("default", "0.0.0.0/0", key("no")), RouteSpec("specific", "0.0.0.0/24", key("yes"))),
        address_family=4,
    )
    compiled = model(
        manager,
        (
            NodeSpec(key("a"), edges),
            NodeSpec(key("yes"), terminal="permit"),
            NodeSpec(key("no"), terminal="deny"),
        ),
    )
    request = query(manager)
    assert ecn_values(walk(compiled, request, request_id="fib").bounds.lower) == set(range(4))
    empty_fib = model(manager, (NodeSpec(key("a")),))
    result = walk(empty_fib, request, request_id="none")
    assert result.bounds.upper.is_empty()
    assert ecn_values(dict(result.by_choice[0].outcomes)["no_route"]) == set(range(4))
    incomplete_fib = model(manager, (NodeSpec(key("a"), complete=False),))
    assert ecn_values(walk(incomplete_fib, request, request_id="partial").bounds.upper) == set(range(4))


def test_pinning_fingerprints_and_context_isolation(manager):
    nodes = (NodeSpec(key("a"), (EdgeSpec("end", key("b")),)), NodeSpec(key("b"), terminal="permit"))
    source = ModelInput(MANIFEST, nodes, (EntrySpec(key("a")),), ONLY, True)
    assert semantic_fingerprint(source) == semantic_fingerprint(replace(source, nodes=tuple(reversed(nodes))))
    assert semantic_fingerprint(source) != semantic_fingerprint(replace(source, manifest_digest="b" * 64))
    known = frozenset(manager.schema.field_names)
    assert (
        compile_model(source, manager, known).fingerprint
        != compile_model(source, manager, known - {"source_port"}).fingerprint
    )
    other_vs = replace(key("b"), context=replace(CONTEXT, firewall_instance="vs/2"))
    changed = replace(nodes[0], edges=(EdgeSpec("end", other_vs),))
    result = walk(model(manager, (changed, nodes[1])), query(manager), request_id="scope")
    assert result.bounds.lower.is_empty() and "MODEL_NODE_MISSING" in result.gap_refs
    incomplete = walk(model(manager, nodes, complete=False), query(manager), request_id="choices")
    assert incomplete.bounds.lower.is_empty() and "FORWARDING_CHOICES_INCOMPLETE" in incomplete.gap_refs


def test_unstated_fields_cannot_be_promoted_by_model_or_rewrites(manager):
    request = header(manager, {"ecn": 0})
    compiled = model(
        manager,
        (
            NodeSpec(key("a"), (EdgeSpec("dport", key("yes"), Atom("destination_port", "eq", 443)),)),
            NodeSpec(key("yes"), terminal="permit"),
        ),
        known=request.known_fields,
    )
    result = walk(compiled, request, request_id="unstated")
    assert result.bounds.lower.is_empty() and not result.bounds.upper.is_empty()
    with pytest.raises(ValueError, match="knowledge"):
        walk(compiled, query(manager), request_id="mismatch")


def test_deep_acyclic_graph_uses_dependency_worklist_within_budget(manager):
    nodes = [NodeSpec(key(str(i)), (EdgeSpec("next", key(str(i + 1))),)) for i in range(100)]
    nodes.append(NodeSpec(key("100"), terminal="permit"))
    compiled = model(manager, nodes, entries=(EntrySpec(key("0")),))
    result = walk(compiled, query(manager), request_id="chain", limits=WalkLimits(max_steps=500))
    assert result.complete and ecn_values(result.bounds.lower) == set(range(4))


def test_offset_translation_is_executable_in_model(manager):
    edge = EdgeSpec("range", key("b"), ranges=(RangeRewriteSpec("source_address", 0, 2**24 - 1, 2**24),))
    nodes = (
        NodeSpec(key("a"), (edge,)),
        NodeSpec(key("b"), (EdgeSpec("check", key("yes"), Atom("source_address", "eq", 2**24 + 10)),)),
        NodeSpec(key("yes"), terminal="permit"),
    )
    result = walk(model(manager, nodes), query(manager), request_id="range")
    assert ecn_values(result.bounds.lower) == set(range(4))
    assert result.bounds.lower.cardinality(("source_address",), bank="original") == 1


def test_fib_exclusions_are_local_and_ecmp_requires_joint_choices(manager):
    routes = tuple(RouteSpec(str(i), f"10.{i}.0.0/16", key("yes")) for i in range(200))
    edges = fib_edges((RouteSpec("parent", "10.0.0.0/8", key("no")), *routes), address_family=4)
    # Disjoint peers do not copy all preceding prefixes into every guard.
    assert sum(len(edge.predicate.terms[1].term.terms) for edge in edges) == 200
    with pytest.raises(ValueError, match="joint choices"):
        fib_edges(
            (RouteSpec("one", "0.0.0.0/0", key("one")), RouteSpec("two", "0.0.0.0/0", key("two"))),
            address_family=4,
        )
    with pytest.raises(ValueError, match="boolean"):
        NodeSpec(key("a"), complete="false")


def test_gap_scopes_retain_original_request_subset_and_no_database_reads(manager, monkeypatch):
    def unexpected_read(*args, **kwargs):
        pytest.fail("symbolic traversal performed a live database read")

    monkeypatch.setattr("hst.path._read", unexpected_read)
    monkeypatch.setattr("hst.path._read_one", unexpected_read)
    monkeypatch.setattr("neo4j.GraphDatabase.driver", unexpected_read)
    nodes = (
        NodeSpec(
            key("a"),
            (
                EdgeSpec("known", key("yes"), Atom("ecn", "range", 1, 3)),
                EdgeSpec("gap", key("missing"), Atom("ecn", "eq", 0)),
            ),
        ),
        NodeSpec(key("yes"), terminal="permit"),
    )
    result = walk(model(manager, nodes), query(manager), request_id="scoped")
    assert ecn_values(result.bounds.lower) == {1, 2, 3}
    assert result.scoped_gaps
    assert all(ecn_values(gap.packets) == {0} for gap in result.scoped_gaps)
    assert any(gap.code == "MODEL_NODE_MISSING" and gap.state == key("missing") for gap in result.scoped_gaps)


def test_temporal_evidence_is_bound_to_nodes_and_saved_analysis_time(manager):
    observed = datetime(2026, 9, 12, 12, tzinfo=UTC)
    window = EvidenceWindow(
        "router-a",
        "collector",
        "rib",
        observed,
        observed,
        observed,
        CaptureOutcome.COMPLETE,
        ClockQuality.TRUSTED,
        4,
        "vrf",
    )
    reference = EvidenceRef("collector", "router-a", "rib", 4, "vrf")
    node = NodeSpec(key("a"), terminal="permit", evidence=(reference,))
    saved = evaluate_evidence((window,), EvidencePolicy(), analysis_time=observed + timedelta(minutes=5))
    source = ModelInput(MANIFEST, (node,), (EntrySpec(key("a")),), ONLY, True, evidence=saved)

    def result(input_model):
        return walk(
            compile_model(input_model, manager, frozenset(manager.schema.field_names)),
            query(manager),
            request_id="evidence",
        )

    assert ecn_values(result(source).bounds.lower) == set(range(4))
    later = replace(saved, analysis_time=observed + timedelta(hours=2), gaps=())
    stale = result(replace(source, manifest_digest="b" * 64, evidence=later))
    assert stale.bounds.lower.is_empty() and "stale-evidence" in stale.gap_refs
    assert ecn_values(stale.bounds.upper) == set(range(4))
    assert ecn_values(result(source).bounds.lower) == set(range(4))
    missing = result(replace(source, evidence=None))
    assert "EVIDENCE_NOT_COLLECTED" in missing.gap_refs and missing.bounds.lower.is_empty()
