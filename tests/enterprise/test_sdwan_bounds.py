from __future__ import annotations

from hst.analysis_model.model import ChoiceAssignment, StateKey
from hst.policy.ir import Constant, ExecutionContext
from hst.policy.sdwan import (
    CROSS_BOUNDARY_MTU,
    CROSS_BOUNDARY_NAT,
    CROSS_BOUNDARY_SESSION,
    INCOMPLETE,
    OPAQUE_SELECTION,
    ForwardingAlternative,
    ForwardingBoundary,
    boundary_from_configuration,
    effective_settings,
    evaluate_boundary,
    unknown_alternative,
)

CONTEXT = ExecutionContext("estate", "vco", "ent-1", "edge-1", "segment-1", 4)


def _alternative(uid: str, admitted: bool) -> ForwardingAlternative:
    return ForwardingAlternative(
        uid=uid,
        predicate=Constant(admitted),
        target=StateKey(f"target:{uid}", CONTEXT),
        choices=(ChoiceAssignment(uid, (("sdwan-path", uid),)),),
        complete=True,
        evidence=(f"pathStats:{uid}",),
    )


def test_known_possible_path_does_not_establish_guaranteed_success() -> None:
    boundary = ForwardingBoundary(
        "b", "edge-1", "segment-1", (_alternative("dia", True),), False, ("business-policy:r1",)
    )
    result = evaluate_boundary(boundary)
    assert result.possible is True
    assert result.guaranteed is False
    assert result.gap_codes == (INCOMPLETE,)


def test_caller_complete_assumption_is_conditional_and_can_bound_alternatives() -> None:
    boundary = ForwardingBoundary(
        "b", "edge-1", "segment-1", (_alternative("dia", True), _alternative("hub", False)), False, ("r1",)
    )
    result = evaluate_boundary(boundary, allowed_uids=frozenset({"dia"}), assumption_complete=True)
    assert result.possible is result.guaranteed is result.conditional is True


def test_deleting_observed_path_does_not_prove_hidden_paths_absent() -> None:
    boundary = ForwardingBoundary("b", "edge-1", "segment-1", (), False, ("pathStats:empty",))
    result = evaluate_boundary(boundary)
    assert result.possible is True
    assert result.guaranteed is False
    assert INCOMPLETE in result.gap_codes


def test_edge_override_recursively_wins_without_erasing_profile_siblings() -> None:
    assert effective_settings(
        {"policy": {"voice": "hub", "bulk": "dia"}}, {"policy": {"voice": "direct"}}
    ) == {"policy": {"voice": "direct", "bulk": "dia"}}


def test_a_configured_boundary_is_incomplete_and_keeps_the_cross_boundary_gaps() -> None:
    """The collector reads no path statistics, so a configured alternative is
    never an observation and the candidate set is never complete."""
    alternative = unknown_alternative(
        "vco:ent-1:e1:s1:path:hub-1",
        StateKey("sdwan-path:hub-1", CONTEXT, "sdwan-boundary"),
        (ChoiceAssignment("vco:ent-1:e1:s1:path:hub-1", (("sdwan:e1:s1", "hub-1"),)),),
        subject="vco:ent-1:e1:s1:path:hub-1",
        evidence=("controlPlane:vpnHubs",),
    )
    boundary = boundary_from_configuration(
        uid="vco:ent-1:e1:s1:boundary",
        edge_uid="e1",
        segment_uid="s1",
        alternatives=(alternative,),
        selector_evidence=("business-policy:r1", "selector:dynamic-steering"),
    )
    assert boundary.alternatives[0].gap_code == OPAQUE_SELECTION
    assert boundary.alternatives[0].observed_at_ms is None
    assert boundary.candidate_set_complete is False
    assert boundary.unsupported_predicates == (
        CROSS_BOUNDARY_NAT,
        CROSS_BOUNDARY_SESSION,
        CROSS_BOUNDARY_MTU,
    )
    result = evaluate_boundary(boundary)
    assert result.possible is True
    assert result.guaranteed is False
    assert INCOMPLETE in result.gap_codes
