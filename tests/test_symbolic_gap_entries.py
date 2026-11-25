"""`symbolic_results.gap_entries` holds the device and the context of each gap."""

from __future__ import annotations

from types import SimpleNamespace

from hst.analysis_model.model import ChoiceAssignment, StateKey
from hst.assessment.symbolic_results import gap_entries
from hst.impact.symbolic_walk import WalkGap
from hst.policy.ir import ExecutionContext


def _state(location, device, vrf):
    return StateKey(location, ExecutionContext("estate", "graph", "graph", device, vrf, 4))


def _answer(choices_by_member, gaps):
    members = {
        name: SimpleNamespace(
            by_choice=tuple(SimpleNamespace(scoped_gaps=tuple(scoped)) for scoped in choices),
            scoped_gaps=(),
        )
        for name, choices in choices_by_member.items()
    }
    return SimpleNamespace(members=members, gaps=tuple(gaps))


def test_each_gap_names_the_device_and_context_it_was_found_at():
    leaf = _state("routing:vrf:leaf:ingress:none", "dev:leaf101", "vrf:leaf")
    core = _state("gate:fw:core", "dev:core1", "vrf:core")
    answer = _answer(
        {
            "app": [
                [WalkGap("MODEL_SCOPE_INCOMPLETE", None, ChoiceAssignment("routing:only"), leaf)],
                [
                    WalkGap("MODEL_SCOPE_INCOMPLETE", None, ChoiceAssignment("routing:a"), leaf),
                    WalkGap("EVIDENCE_NOT_COLLECTED", None, ChoiceAssignment("routing:a"), core),
                ],
            ]
        },
        ["EVIDENCE_NOT_COLLECTED", "MODEL_SCOPE_INCOMPLETE"],
    )
    entries = gap_entries(answer)
    # one entry per code, device and context, whatever the number of choices that saw it
    assert [(e["code"], e["subject"], e["context_uid"]) for e in entries] == [
        ("EVIDENCE_NOT_COLLECTED", "dev:core1", "vrf:core"),
        ("MODEL_SCOPE_INCOMPLETE", "dev:leaf101", "vrf:leaf"),
    ]
    assert entries[1]["detail"] == "MODEL_SCOPE_INCOMPLETE at routing:vrf:leaf:ingress:none"
    assert all(e["kind"] == e["code"] and e["scope"] == "symbolic-set" for e in entries)


def test_a_code_with_no_state_and_an_aggregation_code_have_no_subject():
    unknown_device = _state("terminal:context-device-unknown:vrf:x:ingress:none", "unknown", "vrf:x")
    answer = _answer(
        {
            "app": [
                [
                    WalkGap("SOURCE_ATTACHMENT_UNKNOWN", None, ChoiceAssignment("routing:only")),
                    WalkGap("MODEL_OUTCOME_UNKNOWN", None, ChoiceAssignment("routing:only"), unknown_device),
                ]
            ]
        },
        ["FORWARDING_CHOICES_INCOMPLETE", "MODEL_OUTCOME_UNKNOWN", "SOURCE_ATTACHMENT_UNKNOWN"],
    )
    entries = {e["code"]: e for e in gap_entries(answer)}
    assert set(entries) == {
        "FORWARDING_CHOICES_INCOMPLETE",
        "MODEL_OUTCOME_UNKNOWN",
        "SOURCE_ATTACHMENT_UNKNOWN",
    }
    assert entries["SOURCE_ATTACHMENT_UNKNOWN"]["subject"] is None
    assert entries["FORWARDING_CHOICES_INCOMPLETE"] == {
        "kind": "FORWARDING_CHOICES_INCOMPLETE",
        "code": "FORWARDING_CHOICES_INCOMPLETE",
        "subject": None,
        "context_uid": None,
        "detail": "FORWARDING_CHOICES_INCOMPLETE",
        "scope": "symbolic-set",
    }
    assert entries["MODEL_OUTCOME_UNKNOWN"]["subject"] is None
    assert entries["MODEL_OUTCOME_UNKNOWN"]["context_uid"] == "vrf:x"


def test_result_level_scoped_gaps_are_read_when_no_choice_carries_them():
    core = _state("gate:fw:core", "dev:core1", "vrf:core")
    member = SimpleNamespace(by_choice=(), scoped_gaps=(WalkGap("EVIDENCE_NOT_COLLECTED", None, None, core),))
    answer = SimpleNamespace(members={"app": member}, gaps=("EVIDENCE_NOT_COLLECTED",))
    assert [e["subject"] for e in gap_entries(answer)] == ["dev:core1"]
