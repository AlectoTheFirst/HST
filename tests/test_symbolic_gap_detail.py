"""A gap row of a symbolic result names what is missing, next to its code (`gap_detail`)."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.enterprise import test_network_compile as nc
from tests.test_symbolic_routing_scope import _oslo_mirrored

from hst.analysis_model.compile import AnalysisModel, CompiledNode, with_estate_exits
from hst.analysis_model.evidence import EvidencePolicy, EvidenceWindow, evaluate_evidence
from hst.analysis_model.model import ChoiceAssignment, ModelInput, NodeSpec, StateKey, semantic_fingerprint
from hst.analysis_model.network import normalize_network
from hst.assessment import package, symbolic_results
from hst.impact.evaluate import Member, RequestSet, member
from hst.impact.symbolic_walk import TerminalReach, WalkGap
from hst.policy.ir import ExecutionContext
from hst.results.words import FORBIDDEN_WORDS, _contains_word

DEVICE, VRF = "dev:core1", "vrf:dev:core1:default"
STATE = StateKey(
    f"routing:{VRF}:ingress:{DEVICE}/if/eth0", ExecutionContext("default", "graph", "graph", DEVICE, VRF, 4)
)
ONLY = ChoiceAssignment("only")


def _vocabulary(text: str) -> None:
    assert not [word for word in FORBIDDEN_WORDS if _contains_word(text.lower(), word)], text


# --- the model ----------------------------------------------------------------------------


def test_a_model_with_no_reason_keeps_its_fingerprint():
    request = RequestSet(
        "web",
        nc._ivals("10.0.0.10"),
        "server",
        (Member("server", nc._ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    model = normalize_network(nc._network(), nc._graph(), request, request.members[0], "estate")
    assert not any(node.incomplete_reasons for node in model.nodes)
    assert semantic_fingerprint(model) == "0016eefc287160cd967b59984af8ed7c6ea24d692f04c2d93c61d7b2d9b6eb59"


@pytest.mark.parametrize(("destination", "reasons"), [("192.0.2.180", 0), ("192.0.2.10", 1)])
def test_the_routing_state_carries_the_reason_of_its_gap(destination, reasons):
    from tests.test_symbolic_masquerade import MAIN, _estate, _inventory, oslo_request

    request = oslo_request(destination=destination)
    model = normalize_network(_oslo_mirrored(), _inventory(_estate(1)), request, request.members[0], "estate")
    states = [node for node in model.nodes if node.key.location.startswith(f"routing:{MAIN}:")]
    for node in states:
        assert len(node.incomplete_reasons) == reasons
        assert node.complete is (reasons == 0)
        if reasons:
            assert "192.0.2.0/25 via 10.18.99.1" in node.incomplete_reasons[0]


def test_only_an_incomplete_node_has_a_reason():
    with pytest.raises(ValueError):
        NodeSpec(STATE, terminal="unknown", incomplete_reasons=("x",))


def test_a_reason_changes_the_fingerprint_and_its_absence_does_not():
    plain = ModelInput("a" * 64, (NodeSpec(STATE, terminal="unknown", complete=False),), (), (ONLY,), True)
    reasoned = replace(plain, nodes=(replace(plain.nodes[0], incomplete_reasons=("why",)),))
    assert semantic_fingerprint(reasoned) != semantic_fingerprint(plain)


def test_a_stored_compiled_model_takes_its_reasons_from_its_source():
    """A stored compiled model holds no reason (its codec writes none); the
    source it is keyed by does, and `with_estate_exits` puts it back."""
    stored = AnalysisModel(
        "a" * 64,
        "fp",
        None,
        (CompiledNode(STATE, (), (), False, ("MODEL_SCOPE_INCOMPLETE",)),),
        (),
        (ONLY,),
        True,  # type: ignore[arg-type]
    )
    source = ModelInput(
        "a" * 64,
        (NodeSpec(STATE, terminal="unknown", complete=False, incomplete_reasons=("why",)),),
        (),
        (ONLY,),
        True,
    )
    assert with_estate_exits(stored, source).nodes[0].incomplete_reasons == ("why",)
    plain = replace(source, nodes=(replace(source.nodes[0], incomplete_reasons=()),))
    assert with_estate_exits(stored, plain) is stored


# --- the evidence row ---------------------------------------------------------------------


def _answer(gaps, evidence=None):
    choice = SimpleNamespace(
        assignment=ONLY,
        terminal_reaches=(TerminalReach(STATE, "unknown", None),),
        scoped_gaps=tuple(gaps),  # type: ignore[arg-type]
    )
    result = SimpleNamespace(
        by_choice=(choice,), manifest_digest="a" * 64, model_fingerprint="fp", request_id="r"
    )
    return SimpleNamespace(members={"app": result}, evidence=evidence)


def _rows(gaps, evidence=None):
    rows = symbolic_results._evidence(_answer(gaps, evidence), _answer(gaps, evidence))["items"]  # type: ignore[arg-type]
    json.dumps(rows)
    return [row for row in rows if row["side"] == "before" and row["kind"] == "gap"]


REASONS = (
    "baseline routing is not calibrated: computed static route 192.0.2.0/25 via 10.18.99.1; "
    "the device holds no route for it",
    "baseline forwarding coverage for vrf:dev:core1:default is partial",
)


def test_the_scope_row_names_each_reason_next_to_its_code():
    (row,) = _rows([WalkGap("MODEL_SCOPE_INCOMPLETE", None, ONLY, STATE, reasons=REASONS)])  # type: ignore[arg-type]
    assert row["gap_code"] == "MODEL_SCOPE_INCOMPLETE"
    assert row["gap_detail"] == (
        "the routing of vrf:dev:core1:default (IPv4) on dev:core1 is not decided for this flow: "
        "baseline forwarding coverage for vrf:dev:core1:default is partial; "
        "baseline routing is not calibrated: computed static route 192.0.2.0/25 via 10.18.99.1; "
        "the device has no route for it"
    )
    _vocabulary(row["gap_detail"])
    # the answer of the row is the one it had
    assert row["missing"] == ["MODEL_SCOPE_INCOMPLETE"]
    assert row["steps"][0]["detail"] == "MODEL_SCOPE_INCOMPLETE"


def test_more_than_five_reasons_end_with_the_count_of_the_rest():
    reasons = tuple(f"reason {index}" for index in range(8))
    (row,) = _rows([WalkGap("MODEL_SCOPE_INCOMPLETE", None, ONLY, STATE, reasons=reasons)])  # type: ignore[arg-type]
    assert row["gap_detail"].endswith(": reason 0; reason 1; reason 2; reason 3; reason 4; and 3 more")


def test_a_row_with_nothing_to_name_has_no_detail():
    rows = _rows(
        [
            WalkGap("MODEL_SCOPE_INCOMPLETE", None, ONLY, STATE),
            WalkGap("MODEL_OUTCOME_UNKNOWN", None, ONLY, STATE),
        ]  # type: ignore[arg-type]
    )
    assert not any("gap_detail" in row for row in rows)


def _live_windows(**overrides):
    """The owner's router as the saved live rows show it: a device run with a
    fetch start and no finish, and no clock declaration."""
    start = datetime(2026, 11, 14, 10, 50, 50, tzinfo=UTC)
    return [
        EvidenceWindow(
            DEVICE,
            "vyos-core1",
            section,
            capture_start=start,
            capture_end=None,
            observation_time=start,
            outcome="complete",
            **overrides,
        )
        for section in ("version", "routes", "interfaces", "nat", "access", "routes6", "zones")
    ]


def _live_evidence(**overrides):
    return evaluate_evidence(
        _live_windows(**overrides),
        EvidencePolicy(),
        analysis_time=datetime(2026, 11, 14, 10, 53, 38, tzinfo=UTC),
    )


def test_the_clock_row_names_the_device_and_the_missing_declaration():
    (row,) = _rows([WalkGap("clock-quality-uncertain", None, ONLY, STATE)], _live_evidence())  # type: ignore[arg-type]
    assert row["gap_detail"] == (
        "dev:core1 (collected by vyos-core1): the collection clock is not declared trusted "
        "(clock quality unknown, no clock source, no clock assumption); declare it with "
        "COLLECTOR_CLOCK_QUALITY=trusted and COLLECTOR_CLOCK_ASSUMPTION, or record the device clock, "
        "for the sections access, interfaces, nat, routes, routes6, and 2 more"
    )
    _vocabulary(row["gap_detail"])


def test_the_window_row_names_the_missing_fetch_finish_time():
    (row,) = _rows([WalkGap("legacy-metadata-missing", None, ONLY, STATE)], _live_evidence())  # type: ignore[arg-type]
    assert row["gap_detail"].startswith(
        "dev:core1 (collected by vyos-core1): the fetch finish time of the collection is not recorded, "
        "for the sections access, interfaces"
    )
    _vocabulary(row["gap_detail"])


def test_an_evidence_gap_of_another_device_is_not_named():
    other = replace(STATE, context=replace(STATE.context, firewall_instance="dev:other"))
    (row,) = _rows([WalkGap("clock-quality-uncertain", None, ONLY, other)], _live_evidence())  # type: ignore[arg-type]
    assert "gap_detail" not in row


def test_a_trusted_clock_with_a_full_window_has_no_such_gap():
    evidence = evaluate_evidence(
        [
            replace(window, capture_end=window.capture_start + timedelta(seconds=2))  # type: ignore[operator]
            for window in _live_windows(clock_quality="trusted")
        ],
        EvidencePolicy(),
        analysis_time=datetime(2026, 11, 14, 10, 53, 38, tzinfo=UTC),
    )
    assert not {gap.code.value for gap in evidence.gaps} & {
        "clock-quality-uncertain",
        "legacy-metadata-missing",
    }


def test_a_row_stored_without_the_detail_replays_as_the_same_answer():
    stored = {"gap_code": "MODEL_SCOPE_INCOMPLETE", "missing": ["MODEL_SCOPE_INCOMPLETE"]}
    replayed = {**stored, "gap_detail": "the routing of x is not decided for this flow: y"}
    assert package._align(stored, replayed) == (stored, stored)
