"""Whole-flow costs, cost-ordered finite truth tables and multi-family inversion."""

from itertools import product
from types import SimpleNamespace

import pytest
from tests.test_impact_evaluate import (
    R1,
    VRF_A,
    VRF_B,
    VRF_R1,
    A,
    B,
    _firewall,
    _network,
    _request,
    _routing,
    _static,
    ev,
)
from tests.test_impact_evaluate import graph as graph
from tests.test_path_nat import _dnat_row
from tests.test_path_trace import _rule

from hst import path
from hst.assessment.adapters import _PolicyEdits, apply_model_edits, model_changes
from hst.assessment.cost import ScopeCostOracle, cardinality, permitted_scope_cost, scope_requests
from hst.assessment.regression import analyze_model_regression
from hst.assessment.repair import search_repairs
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits
from hst.assessment.semantic import read_snapshot_inputs, semantic_change_stream
from hst.core.manifest import DeviceEntry, FileEntry, file_facts
from hst.core.model import SectionOutcome
from hst.path.state import FlowRegion


def answer_bounds(request, lower, upper, duplicate=False):
    members = {"app": ev.MemberAnswer("app", upper, lower, upper, ())}
    if duplicate:
        members["alias"] = ev.MemberAnswer("alias", upper, lower, upper, ())
    return ev.Answer(request, "possible", (), (), members)


def test_full_cost_counts_all_five_dimensions_and_unions_overlapping_members():
    scope = {
        "source": ["10.0.0.0/31"],
        "destination": ["203.0.113.0/31"],
        "protocols": ["tcp", "udp"],
        "ports": ["443-444"],
        "source_ports": ["1000-1002"],
    }
    request = scope_requests(_request(), scope)[0]
    region = request.member_region(request.members[0])
    assert cardinality(region.union(region)) == 2 * 2 * 2 * 2 * 3
    before = answer_bounds(request, FlowRegion(), FlowRegion())
    after = answer_bounds(request, region, region, duplicate=True)
    cost = permitted_scope_cost([before], [after], region)
    assert cost["exact"] and cost["value"] == 48
    uncertain = permitted_scope_cost([answer_bounds(request, FlowRegion(), region)], [after], region)
    assert uncertain["lower"] == 0 and uncertain["upper"] == 48 and not uncertain["exact"]


def test_cost_ipv6_counts_without_float_and_separates_address_families():
    scope = {
        "source": ["::/0"],
        "destination": ["2001:db8::1"],
        "protocols": ["tcp"],
        "ports": ["443"],
        "source_ports": ["1"],
    }
    request = scope_requests(_request(), scope)[0]
    assert cardinality(request.member_region(request.members[0])) == 2**128
    scope["source"].append("10.0.0.1")
    with pytest.raises(ValueError, match="families"):
        scope_requests(_request(), scope)


def fixture_candidates():
    return {
        "candidates": [
            {
                "id": name,
                "device": "d" if name in "ab" else "e",
                "intents": [
                    {
                        "kind": "fw_rule.modify",
                        "params": {"rulebase": "rb" if name in "ab" else "rc", "rule": name},
                    }
                ],
            }
            for name in "abc"
        ],
        "allowed_targets": {"rb": "d", "rc": "e"},
        "allowed_kinds": ["fw_rule.modify"],
        "universe_complete": True,
        "excluded": [],
        "generator_version": "fixture",
    }


def test_cost_order_finds_nonmonotone_cheap_combination_before_expensive_parent():
    seen = []

    def key(intents):
        return "".join(i["params"]["rule"] for i in intents)

    values = {"": 0, "a": 100, "b": 50, "c": 1, "ab": 0, "ac": 20, "bc": 20, "abc": 0}

    def oracle(intents):
        seen.append(key(intents))
        return {"desired": HOLDS if intents else FAILS, "protected": {"isolated": HOLDS}}

    result = search_repairs(
        fixture_candidates(),
        oracle,
        SearchLimits(max_combination_size=3),
        cost_oracle=lambda intents: {"lower": values[key(intents)], "upper": values[key(intents)]},
        cost_order=["newly_permitted_scope", "devices", "rule_edits"],
    )
    assert result["search_complete"]
    assert seen.index("ab") < seen.index("a")
    costs = [t["evaluation"]["cost"] for t in result["trials"]]
    assert costs == sorted(costs)
    assert result["findings"][0]["candidates"] == ["a", "b"]
    assert result["findings"][0]["minimum_cost"]


def test_every_small_truth_table_unknown_never_establishes_infeasibility_or_minimum():
    generated = fixture_candidates()
    generated["candidates"] = generated["candidates"][:2]
    for outcomes in product((HOLDS, FAILS, UNKNOWN), repeat=4):
        groups = {(): outcomes[0], ("a",): outcomes[1], ("b",): outcomes[2], ("a", "b"): outcomes[3]}

        def oracle(intents, groups=groups):
            return {"desired": groups[tuple(i["params"]["rule"] for i in intents)], "protected": {}}

        result = search_repairs(
            generated, oracle, cost_oracle=lambda intents: {"lower": len(intents), "upper": len(intents)}
        )
        assert result["search_complete"]
        assert result["proved_infeasible"] == all(v == FAILS for v in groups.values())
        for finding in result["findings"]:
            subset = tuple(finding["candidates"])
            cheaper = [
                g for g in groups if (bool(g), len(g), len(g)) < (bool(subset), len(subset), len(subset))
            ]
            assert finding["minimum_cost"] == all(groups[g] == FAILS for g in cheaper)


def test_unknown_lower_cost_and_truncation_block_minimum_claims():
    generated = fixture_candidates()
    result = search_repairs(
        generated,
        lambda i: {"desired": HOLDS if i else FAILS, "protected": {}},
        SearchLimits(max_combination_size=3),
        cost_oracle=lambda i: {"lower": 0, "upper": None} if len(i) == 1 else {"lower": 2, "upper": 2},
    )
    assert not any(f["minimum_cost"] for f in result["findings"])
    bounded = search_repairs(
        generated,
        lambda i: {"desired": HOLDS, "protected": {}},
        SearchLimits(max_evaluations=1),
        cost_oracle=lambda i: {"lower": 0, "upper": 0},
    )
    assert not bounded["search_complete"] and bounded["stop_reason"] == "evaluation-limit"
    assert not bounded["proved_infeasible"]


def test_static_model_reversal_and_forward_replay_recompute_real_forwarding(graph):
    before = _network(_routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.1.2")]))
    after = _network(_routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")]))
    _firewall(graph, B, "rb:b", [_rule(action="drop")])
    diff = model_changes(
        before, after, {}, {}, complete_fw=[], complete_nat=[], complete_contexts=[VRF_R1, VRF_A, VRF_B]
    )
    assert [e["family"] for e in diff["edits"]] == ["static"]

    def state(net):
        result = ev.answer(net, _request())
        return HOLDS if result.lower else FAILS if not result.upper else UNKNOWN

    assert state(before) == HOLDS and state(after) == FAILS
    result = analyze_model_regression(
        diff,
        lambda edits: state(apply_model_edits(after, edits)),
        before_verdict=HOLDS,
        after_verdict=FAILS,
        forward_oracle=lambda edits: state(apply_model_edits(before, edits, direction="forward")),
    )
    assert result["findings"][0]["forward_replay"]["reproduces_failure"]
    assert before.routing.static[0]["next_hop"] == "10.0.1.2"
    with pytest.raises(ValueError, match="precondition"):
        apply_model_edits(before, diff["edits"])


def test_firewall_and_nat_exact_row_preconditions_and_order(graph):
    net = _network(_routing(bgp=False))
    fw_before, fw_after = [_rule(uid="one", pos=1)], [_rule(uid="one", pos=2, action="drop")]
    nat_before, nat_after = [_dnat_row()], [_dnat_row(translation="10.0.0.88", xlate_dst_addrs=["10.0.0.88"])]
    diff = model_changes(
        net,
        net,
        {"firewall": {"rb": fw_before}, "nat": {R1: nat_before}},
        {"firewall": {"rb": fw_after}, "nat": {R1: nat_after}},
        complete_fw=["rb"],
        complete_nat=[R1],
        complete_contexts=[],
    )
    assert {e["family"] for e in diff["edits"]} == {"firewall", "nat"}
    hook = _PolicyEdits(diff["edits"], "reverse")
    from hst.path.gates.firewall import _RULEBASE_RULES
    from hst.path.gates.nat import _NAT_RULES_QUERY_STRICT

    assert hook.rewrite(_NAT_RULES_QUERY_STRICT, {"dev": R1}, nat_after) == nat_before
    assert hook.rewrite(_RULEBASE_RULES, {"rb": "rb"}, fw_after) == fw_before
    with pytest.raises(ValueError, match="precondition"):
        hook.rewrite(_NAT_RULES_QUERY_STRICT, {"dev": R1}, nat_before)


def test_scope_cost_oracle_actual_policy_counts_destination_and_ports(graph):
    baseline = _network(_routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.1.2")]))
    _firewall(graph, A, "rb:a", [_rule(uid="deny", action="drop")])
    from tests.test_impact_evaluate import _changes

    changed = ev.apply(
        baseline, _changes({"kind": "fw_rule.remove", "params": {"rulebase": "rb:a", "rule": "deny"}})
    )
    scope = {
        "source": ["10.0.0.0/31"],
        "destination": ["203.0.113.10/31"],
        "protocols": ["tcp"],
        "ports": ["443-444"],
        "source_ports": ["1234"],
    }
    result = ScopeCostOracle(baseline, _request(), scope)(changed)
    assert result["exact"] and result["value"] == 8


def snapshot(cts, files=(), status="ok"):
    device = DeviceEntry(
        source="s",
        host="r1",
        outcome="collected" if status == "ok" else "failed",
        expected_sections=["config"],
        sections={"config": SectionOutcome(status=status)},
    )
    return SimpleNamespace(cts=cts, manifest=SimpleNamespace(devices=[device], files=files))


def test_semantic_reader_is_uncapped_and_includes_side_observations(tmp_path, monkeypatch):
    import pyarrow as pa
    import pyarrow.parquet as pq

    target = tmp_path / "rib.parquet"
    pq.write_table(pa.Table.from_pylist([{"prefix": "10.1.0.0/16", "protocol": "bgp"}]), target)
    sha, size = file_facts(target)
    entry = FileEntry(
        kind="sidestore",
        path=target.name,
        sha256=sha,
        bytes=size,
        source="s",
        host="r1",
        run_id="run",
        table="rib",
    )
    nodes = [
        {
            "uid": str(i),
            "labels": ["Obj", "Interface"],
            "props": {"_sources": ["s"], "_scope": "ios:r1", "name": str(i)},
        }
        for i in range(1250)
    ]

    def read(session, query, **params):
        return [] if "type(r)" in query else nodes[params["offset"] : params["offset"] + params["limit"]]

    monkeypatch.setattr(path, "_read", read)
    settings = SimpleNamespace(hst_data_dir=tmp_path)
    before = read_snapshot_inputs(None, snapshot("1", [entry]), settings)
    nodes[1200]["props"]["name"] = "changed"
    after = read_snapshot_inputs(None, snapshot("2", [entry]), settings)
    diff = semantic_change_stream(before, after)
    assert before["complete"] and before["record_count"] == 1252
    assert diff["counts"]["configuration"] == 1
    assert diff["changes"][0]["key"] == "node:1200"
    bounded = read_snapshot_inputs(None, snapshot("3", [entry]), settings, max_records=100)
    assert not bounded["complete"] and bounded["stop_reason"] == "record-limit"
    missing = read_snapshot_inputs(
        None, snapshot("4", [entry.model_copy(update={"path": "missing"})]), settings
    )
    assert not missing["evidence_complete"]
    failed = semantic_change_stream(before, missing)
    assert failed["counts"]["collection-failure"] >= 1


def test_partition_generator_uses_policy_boundaries_without_widening_scope():
    from hst.assessment.partitions import policy_partitions
    from hst.path.addrsets import _intervals, _ports, _protoset

    scope = {
        "source": ["10.0.0.0/24"],
        "destination": ["203.0.113.0/24"],
        "protocols": ["tcp", "udp"],
        "ports": ["1-100"],
    }
    rows = [_rule(src_any=False, src_cidrs=["10.0.0.0/25"], svc_any=False, protos=["tcp"], ports=["50"])]
    parts = policy_partitions(scope, rows)
    assert len(parts["source"]) == 2 and parts["ports"] == ["1-49", "50", "51-100"]
    assert _intervals(parts["source"]) == _intervals(scope["source"])
    assert _ports(parts["ports"]) == _ports(scope["ports"])
    assert _protoset(parts["protocols"]) == _protoset(scope["protocols"])


def test_forward_replay_respects_same_algorithm_budget():
    edits = {"edits": [{"id": "one"}], "excluded": [], "universe_complete": True}
    calls = []
    result = analyze_model_regression(
        edits,
        lambda selected: HOLDS if selected else FAILS,
        SearchLimits(max_evaluations=2),
        before_verdict=HOLDS,
        after_verdict=FAILS,
        forward_oracle=lambda selected: calls.append(selected) or FAILS,
    )
    assert not calls and result["evaluated"] == 2
    assert result["findings"][0]["forward_replay"]["verdict"] == UNKNOWN
    assert result["findings"][0]["forward_replay"]["evaluation"]["reason"] == "evaluation-limit"
