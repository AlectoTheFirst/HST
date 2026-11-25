from dataclasses import replace
from itertools import combinations, product

import pytest
from tests.test_impact_evaluate import (
    CLIENTS,
    R1,
    A,
    B,
    _changes,
    _firewall,
    _interfaces,
    _network,
    _request,
    _routing,
    _static,
    ev,
)
from tests.test_impact_evaluate import graph as graph
from tests.test_impact_sessions import network as session_network
from tests.test_impact_sessions import request as session_request
from tests.test_path_trace import _rule

from hst.assessment.regression import analyze_regression, semantic_firewall_diff
from hst.assessment.repair import generate_firewall_candidates, search_repairs
from hst.assessment.resilience import apply_failures, expand_domains, search_resilience
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits, enumerate_subsets
from hst.simul.fw_overlay import Catalog, ChangeSet, parse_intents


def test_minimality_matches_every_binary_nonmonotone_three_edit_universe():
    ids = ("a", "b", "c")
    subsets = [group for size in range(4) for group in combinations(ids, size)]
    for outcomes in product((HOLDS, FAILS), repeat=len(subsets)):
        truth = dict(zip(subsets, outcomes, strict=True))
        result = enumerate_subsets(ids, truth.__getitem__, SearchLimits(max_combination_size=3))
        assert result["search_complete"]
        for finding in result["findings"]:
            group = tuple(finding["candidates"])
            proper = [s for s in subsets if set(s) < set(group)]
            immediate = [s for s in proper if len(s) == len(group) - 1]
            smaller = [s for s in subsets if len(s) < len(group)]
            assert finding["minimality"] == {
                "verified": True,
                "one_minimal": all(truth[s] == FAILS for s in immediate),
                "inclusion_minimal": all(truth[s] == FAILS for s in proper),
                "minimum_cardinality": all(truth[s] == FAILS for s in smaller),
            }


def test_unknown_and_nonmonotonicity_prevent_overclaiming():
    def oracle(group):
        return HOLDS if len(group) in {1, 3} else FAILS

    result = enumerate_subsets(["a", "b", "c"], oracle, SearchLimits(max_combination_size=3))
    final = result["findings"][-1]["minimality"]
    assert final["one_minimal"] and not final["inclusion_minimal"]
    uncertain = enumerate_subsets(["a"], lambda group: HOLDS if group else UNKNOWN)
    assert not uncertain["findings"][0]["minimality"]["one_minimal"]
    assert not uncertain["findings"][0]["minimality"]["minimum_cardinality"]


@pytest.mark.parametrize(
    ("limits", "reason"),
    [
        (SearchLimits(max_candidates=1), "candidate-limit"),
        (SearchLimits(max_evaluations=1), "evaluation-limit"),
        (SearchLimits(max_combination_size=1), "combination-limit"),
    ],
)
def test_caps_are_explicit(limits, reason):
    result = enumerate_subsets(["a", "b"], lambda _: FAILS, limits)
    assert result["stop_reason"] == reason
    assert not result["search_complete"]


def test_cancel_does_not_evaluate_or_claim_baseline():
    def forbidden(_):
        raise AssertionError("cancelled oracle must not run")

    result = enumerate_subsets(["a"], forbidden, cancelled=lambda: True)
    assert result["stop_reason"] == "cancelled"
    assert not result["findings"] and result["evaluated"] == 0


def test_regression_reverts_interacting_rule_edits_without_mutating_catalogs():
    before = {"rb": [_rule(uid="a", pos=1), _rule(uid="b", pos=2)]}
    after = {"rb": [_rule(uid="a", pos=1, action="drop"), _rule(uid="b", pos=2, action="drop")]}
    delta = semantic_firewall_diff(before, after, complete_rulebases=["rb"])

    def oracle(intents):
        overlay = ChangeSet(parse_intents(intents, Catalog()))
        rows = overlay._rewrite_fw_rules("rb", after["rb"])
        return HOLDS if all(row["action"] == "accept" for row in rows) else FAILS

    result = analyze_regression(delta, oracle, before_verdict=HOLDS, after_verdict=FAILS)
    assert result["confirmed_modeled_regression"]
    assert len(result["findings"]) == 1
    assert len(result["findings"][0]["candidates"]) == 2
    assert result["findings"][0]["minimality"]["minimum_cardinality"]
    assert all(row["action"] == "drop" for row in after["rb"])


def test_incomplete_deletion_and_opaque_service_are_excluded():
    before = {"rb": [_rule()]}
    after = {"rb": []}
    delta = semantic_firewall_diff(before, after, complete_rulebases=[])
    assert not delta["edits"] and "completeness" in delta["excluded"][0]["reason"]
    after = {"rb": [_rule(svc_any=False, protos=["tcp", "udp"], ports=["443", "53"])]}
    delta = semantic_firewall_diff(before, after, complete_rulebases=["rb"])
    assert not delta["edits"] and "service union" in delta["excluded"][0]["reason"]


def test_rule_position_reversal_uses_remove_add():
    before = {"rb": [_rule(uid="a", pos=1), _rule(uid="b", pos=2, action="drop")]}
    after = {"rb": [_rule(uid="b", pos=2, action="drop"), _rule(uid="a", pos=3)]}
    delta = semantic_firewall_diff(before, after, complete_rulebases=["rb"])
    intents = delta["edits"][0]["reverse_intents"]
    assert [i["kind"] for i in intents] == ["fw_rule.remove", "fw_rule.add"]
    overlay = ChangeSet(parse_intents(intents, Catalog()))
    assert [r["uid"] for r in overlay._rewrite_fw_rules("rb", after["rb"])] == ["a", "b"]


SCOPE = {
    "source": ["10.0.0.0/24"],
    "destination": ["203.0.113.10/32"],
    "protocols": ["tcp"],
    "ports": ["443"],
}


def test_generator_scope_and_cap():
    generated = generate_firewall_candidates({"rb": [_rule()]}, {"rb": "d"}, SCOPE, max_candidates=2)
    assert len(generated["candidates"]) == 2 and generated["generation_truncated"]
    assert not generated["universe_complete"]
    for candidate in generated["candidates"]:
        parse_intents(candidate["intents"], Catalog())
    with pytest.raises(ValueError, match="existing rulebases"):
        generate_firewall_candidates({"rb": []}, {"other": "d"}, SCOPE)


def test_repair_unknown_protection_is_never_verified_and_blocks_minimum_cost():
    generated = {
        "candidates": [
            {
                "id": uid,
                "device": "d",
                "intents": [{"kind": "fw_rule.add", "params": {"rulebase": "rb", "uid": uid}}],
            }
            for uid in ("a", "b")
        ],
        "allowed_targets": {"rb": "d"},
        "allowed_kinds": ["fw_rule.add"],
        "universe_complete": True,
        "excluded": [],
        "generator_version": "fixture",
    }

    def oracle(intents):
        ids = [i["params"]["uid"] for i in intents]
        return {
            "desired": HOLDS if ids else FAILS,
            "protected": {"isolation": UNKNOWN if ids == ["a"] else HOLDS},
            "newly_permitted_scope": 1 if ids == ["a"] else 2,
        }

    result = search_repairs(generated, oracle)
    assert all(p["candidates"] != ["a"] for p in result["findings"])
    assert not result["findings"][0]["minimum_cost"]
    assert result["unknown"] == 1


def static_network():
    routing = _routing()
    return _network(
        replace(
            routing,
            bgp=None,
            observed_paths=(),
            direction_status={},
            fixed_external_sessions=frozenset(),
            static=[
                _static("203.0.113.0/24", "10.0.1.2"),
                {**_static("203.0.113.0/24", "10.0.2.2"), "admin": 10},
            ],
        )
    )


def test_real_static_device_failure_recomputes_backup_and_shared_domain(graph):
    network = static_network()
    request = _request()
    assert ev.answer(network, request).lower == CLIENTS
    after = apply_failures(network, [{"kind": "device", "uid": A}])
    assert ev.answer(after, request).lower == CLIENTS
    assert after.routes is not network.routes
    assert len(network.routing.static) == 2
    targets = [{"id": "a", "kind": "device", "uid": A}, {"id": "b", "kind": "device", "uid": B}]
    domains = [{"id": "power", "members": ["a", "b"], "evidence_status": "declared"}]

    def oracle(effects):
        answer = ev.answer(apply_failures(network, effects), request)
        return HOLDS if answer.lower == CLIENTS else FAILS if not answer.upper else UNKNOWN

    result = search_resilience(targets, domains, oracle)
    singleton = next(f for f in result["findings"] if f["candidates"] == ["power"])
    assert singleton["minimality"]["minimum_cardinality"]
    assert not result["domain_coverage_established"]
    assert not result["survives_all_single_failures"]


def test_real_failed_ingress_is_denied_before_firewall_or_nat(graph):
    network = static_network()
    _firewall(graph, R1, "rb", [_rule()])
    for effect in ({"kind": "device", "uid": R1}, {"kind": "interface", "uid": _interfaces()[0].uid}):
        answer = ev.answer(apply_failures(network, [effect]), _request())
        assert not answer.upper


def test_dynamic_failure_recomputes_the_supported_model(graph):
    network = _network()
    changed = apply_failures(network, [{"kind": "device", "uid": A}])
    assert ev.answer(changed, _request()).lower == CLIENTS
    assert changed.routing is not network.routing


@pytest.mark.parametrize(
    "effect",
    [
        {"kind": "tunnel", "uid": "t1", "interfaces": ["wg1", "wg2"]},
        {"kind": "link", "uid": "underlay", "interfaces": ["wan1", "wan2"]},
        {"kind": "device", "uid": "r2"},
    ],
)
def test_real_tunnel_failure_suppresses_inner_and_carrier_session(effect):
    network = session_network(tunnel=True)
    request = session_request()
    assert ev.answer(network, request).lower == request.sources
    failed = apply_failures(network, [effect])
    assert not ev.answer(failed, request).upper
    assert ev.answer(network, request).lower == request.sources


def test_failed_stateful_nat_device_cannot_reuse_session_state():
    network = session_network(snat=True, stateful=True, deny_reply=True)
    request = session_request()
    assert ev.answer(network, request).lower == request.sources
    failed = apply_failures(network, [{"kind": "device", "uid": "r1"}])
    assert not ev.answer(failed, request).upper


def test_overlap_canonicalization_and_cycle_validation():
    targets = [{"id": "a", "kind": "device", "uid": "dev:a"}]
    domains = [
        {"id": "x", "members": ["a"], "evidence_status": "observed"},
        {"id": "y", "members": ["x", "a"], "evidence_status": "observed"},
    ]
    result = search_resilience(targets, domains, lambda effects: FAILS if effects else HOLDS)
    assert result["unique_physical_scenarios"] == 2
    assert not result["domain_coverage_established"]
    assert len(expand_domains(targets, domains)["y"]["effects"]) == 1
    with pytest.raises(ValueError, match="cyclic"):
        expand_domains(targets, [{"id": "x", "members": ["y"]}, {"id": "y", "members": ["x"]}])


def test_real_two_firewall_repair_preserves_protection(graph):
    network = static_network()
    _firewall(graph, R1, "rb:r", [_rule(uid="r", action="drop")])
    _firewall(graph, A, "rb:a", [_rule(uid="a", action="drop")])
    generated = generate_firewall_candidates(
        {"rb:r": graph.rules_by_rb["rb:r"], "rb:a": graph.rules_by_rb["rb:a"]},
        {"rb:r": R1, "rb:a": A},
        SCOPE,
        ["fw_rule.modify"],
    )

    def oracle(intents):
        outcome = ev.answer(ev.apply(network, _changes(*intents)), _request())
        return {
            "desired": HOLDS if outcome.lower == CLIENTS else FAILS if not outcome.upper else UNKNOWN,
            "protected": {},
        }

    result = search_repairs(generated, oracle)
    assert len(result["findings"]) == 1
    assert len(result["findings"][0]["intents"]) == 2
    assert result["findings"][0]["protected_count"] == 0
    assert graph.rules_by_rb["rb:r"][0]["action"] == "drop"
