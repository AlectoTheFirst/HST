import importlib
import os

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.model import ChoiceAssignment, EdgeSpec, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.analysis_model.session_walk import session_walk
from hst.policy.ir import AllOf, Atom, Constant, ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager, header

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")

MANIFEST = "a" * 64


def key(name):
    return StateKey(name, ExecutionContext("e", "a", "d", "fw", "v", 4))


def compiled(manager, source, destination):
    start, end = key(f"{source}:start"), key(f"{source}:end")
    predicate = AllOf((Atom("source_address", "eq", source), Atom("destination_address", "eq", destination)))
    model = ModelInput(
        MANIFEST,
        (NodeSpec(start, (EdgeSpec("deliver", end),)), NodeSpec(end, terminal="permit")),
        (EntrySpec(start, predicate),),
        (ChoiceAssignment("only"),),
        True,
    )
    return compile_model(model, manager, frozenset({"source_address", "destination_address"}))


def test_round_trip_retains_forward_original_identity_and_reverses_current_headers():
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        forward = compiled(manager, 1, 2)
        reply = compiled(manager, 2, 1)
        request = header(manager, {"source_address": 1, "destination_address": 2})
        result = session_walk(forward, reply, request, request_id="request")
        assert result.reply.bounds.lower.equivalent(request.rename(from_bank="current", to_bank="original"))
        assert result.forward.by_choice[0].terminal_reaches


def test_proven_forward_path_creates_plain_reply_session_state():
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        model = compiled(manager, 1, 2)
        request = header(manager, {"source_address": 1, "destination_address": 2})
        reply = compiled(manager, 2, 1)
        result = session_walk(model, reply, request, request_id="request", requires_state=True)
        assert result.reply.bounds.lower.equivalent(request.rename(from_bank="current", to_bank="original"))


def test_reply_bounds_preserve_forward_permit_unknown_and_deny_partition():
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        permit, unknown, deny = key("permit"), key("unknown"), key("deny")
        forward = compile_model(
            ModelInput(
                MANIFEST,
                (
                    NodeSpec(permit, terminal="permit"),
                    NodeSpec(unknown, terminal="unknown", complete=False),
                    NodeSpec(deny, terminal="deny"),
                ),
                (
                    EntrySpec(permit, Atom("source_address", "eq", 1)),
                    EntrySpec(unknown, Atom("source_address", "eq", 2)),
                    EntrySpec(deny, Atom("source_address", "eq", 3)),
                ),
                (ChoiceAssignment("only"),),
                True,
            ),
            manager,
            frozenset({"source_address", "destination_address"}),
        )
        reply_start, reply_end = key("reply:start"), key("reply:end")
        reply = compile_model(
            ModelInput(
                MANIFEST,
                (
                    NodeSpec(reply_start, (EdgeSpec("reply", reply_end, Constant(True)),)),
                    NodeSpec(reply_end, terminal="permit"),
                ),
                (EntrySpec(reply_start, Constant(True)),),
                (ChoiceAssignment("only"),),
                True,
            ),
            manager,
            frozenset({"source_address", "destination_address"}),
        )
        request = header(manager, {"source_address": (1, 3), "destination_address": 9})
        result = session_walk(forward, reply, request, request_id="mixed")
        expected_lower = header(manager, {"source_address": 1, "destination_address": 9}).rename(
            from_bank="current", to_bank="original"
        )
        expected_upper = header(manager, {"source_address": (1, 2), "destination_address": 9}).rename(
            from_bank="current", to_bank="original"
        )
        assert result.reply.bounds.lower.equivalent(expected_lower)
        assert result.reply.bounds.upper.equivalent(expected_upper)


def test_a_forward_part_that_is_not_decided_names_its_own_causes_on_the_round_trip():
    from types import SimpleNamespace

    from hst.assessment.symbolic_results import gap_entries

    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        routing, delivery = key("routing"), key("delivery")
        forward = compile_model(
            ModelInput(
                MANIFEST,
                (
                    NodeSpec(routing, (EdgeSpec("deliver", delivery),), complete=False),
                    NodeSpec(delivery, terminal="permit"),
                ),
                (EntrySpec(routing, Constant(True)),),
                (ChoiceAssignment("only"),),
                True,
            ),
            manager,
            frozenset({"source_address", "destination_address"}),
        )
        reply = compiled(manager, 2, 1)
        request = header(manager, {"source_address": 1, "destination_address": 2})
        result = session_walk(forward, reply, request, request_id="request")
        choice = result.reply.by_choice[0]
        assert choice.bounds.lower.is_empty()
        assert choice.bounds.upper.equivalent(request.rename(from_bank="current", to_bank="original"))
        assert choice.complete is False
        # the forward part's own causes ride beside FORWARD_NOT_PROVEN, at their states
        assert {"FORWARD_NOT_PROVEN", "MODEL_SCOPE_INCOMPLETE", "MODEL_OUTCOME_UNKNOWN"} <= set(
            choice.gap_refs
        )
        assert choice.scoped_gaps[0].code == "FORWARD_NOT_PROVEN"
        assert choice.scoped_gaps[1:] == result.forward.by_choice[0].scoped_gaps
        assert ("MODEL_SCOPE_INCOMPLETE", routing) in {(gap.code, gap.state) for gap in choice.scoped_gaps}
        entries = gap_entries(
            SimpleNamespace(members={"destination": result.reply}, gaps=result.reply.gap_refs)
        )
        assert {
            "kind": "MODEL_SCOPE_INCOMPLETE",
            "code": "MODEL_SCOPE_INCOMPLETE",
            "subject": "fw",
            "context_uid": "v",
            "detail": "MODEL_SCOPE_INCOMPLETE at routing",
            "scope": "symbolic-set",
        } in entries
        assert any(entry["code"] == "FORWARD_NOT_PROVEN" for entry in entries)
