"""VeloCloud forwarding boundaries and their evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from hst.analysis_model.model import ChoiceAssignment, StateKey
from hst.policy.ir import Constant, Predicate, Unknown

INCOMPLETE = "SDWAN_FORWARDING_ALTERNATIVES_INCOMPLETE"
OPAQUE_SELECTION = "SDWAN_DYNAMIC_STEERING_OPAQUE"
UNSUPPORTED_PREDICATE = "SDWAN_APPLICATION_PREDICATE_UNSUPPORTED"
CROSS_BOUNDARY_NAT = "SDWAN_CROSS_BOUNDARY_NAT_UNKNOWN"
CROSS_BOUNDARY_SESSION = "SDWAN_CROSS_BOUNDARY_SESSION_UNKNOWN"
CROSS_BOUNDARY_MTU = "SDWAN_CROSS_BOUNDARY_MTU_UNKNOWN"


@dataclass(frozen=True, slots=True)
class ForwardingAlternative:
    uid: str
    predicate: Predicate
    target: StateKey
    choices: tuple[ChoiceAssignment, ...]
    complete: bool
    gap_code: str | None = None
    observed_at_ms: int | None = None
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.uid:
            raise ValueError("SD-WAN alternative UID is required")
        object.__setattr__(self, "choices", tuple(self.choices))
        object.__setattr__(self, "evidence", tuple(self.evidence))


@dataclass(frozen=True, slots=True)
class ForwardingBoundary:
    uid: str
    edge_uid: str
    segment_uid: str
    alternatives: tuple[ForwardingAlternative, ...]
    candidate_set_complete: bool
    selector_evidence: tuple[str, ...]
    unsupported_predicates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "alternatives", tuple(self.alternatives))
        object.__setattr__(self, "selector_evidence", tuple(self.selector_evidence))
        object.__setattr__(self, "unsupported_predicates", tuple(self.unsupported_predicates))


@dataclass(frozen=True, slots=True)
class BoundaryEvaluation:
    possible: bool
    guaranteed: bool
    conditional: bool
    gap_codes: tuple[str, ...]


def evaluate_boundary(
    boundary: ForwardingBoundary,
    *,
    allowed_uids: frozenset[str] | None = None,
    assumption_complete: bool = False,
) -> BoundaryEvaluation:
    """Evaluate the alternatives of a boundary.

    An alternative whose predicate is not a Constant is undecided.
    """
    selected = [a for a in boundary.alternatives if allowed_uids is None or a.uid in allowed_uids]
    statuses: list[bool | None] = []
    gaps: set[str] = set()
    for alternative in selected:
        if isinstance(alternative.predicate, Constant):
            statuses.append(alternative.predicate.value)
        else:
            statuses.append(None)
            gaps.add(alternative.gap_code or OPAQUE_SELECTION)
        if alternative.gap_code:
            gaps.add(alternative.gap_code)
    complete = boundary.candidate_set_complete or (allowed_uids is not None and assumption_complete)
    if not complete:
        statuses.append(None)
        gaps.add(INCOMPLETE)
    if boundary.unsupported_predicates:
        gaps.add(UNSUPPORTED_PREDICATE)
    possible = any(value is True for value in statuses) or any(value is None for value in statuses)
    guaranteed = bool(statuses) and all(value is True for value in statuses)
    return BoundaryEvaluation(possible, guaranteed, allowed_uids is not None, tuple(sorted(gaps)))


def unknown_alternative(
    uid: str,
    target: StateKey,
    choices: tuple[ChoiceAssignment, ...],
    *,
    subject: str,
    evidence: tuple[str, ...] = (),
) -> ForwardingAlternative:
    return ForwardingAlternative(
        uid,
        Unknown(OPAQUE_SELECTION, subject, evidence),
        target,
        choices,
        False,
        OPAQUE_SELECTION,
        evidence=evidence,
    )


def effective_settings(profile: dict, edge_override: dict) -> dict:
    """Apply the APIv2 inheritance. A key of the Edge override replaces the key of the profile, recursively
    for a dict value."""
    result = dict(profile)
    for key, value in edge_override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = effective_settings(result[key], value)
        else:
            result[key] = value
    return result


def boundary_from_configuration(
    *,
    uid: str,
    edge_uid: str,
    segment_uid: str,
    alternatives: tuple[ForwardingAlternative, ...],
    selector_evidence: tuple[str, ...],
) -> ForwardingBoundary:
    """A boundary built from configuration.

    The collector reads no path statistics. The candidate set is marked
    incomplete, and the 3 cross-boundary predicates are marked unsupported.
    """
    return ForwardingBoundary(
        uid,
        edge_uid,
        segment_uid,
        alternatives,
        False,
        selector_evidence,
        (CROSS_BOUNDARY_NAT, CROSS_BOUNDARY_SESSION, CROSS_BOUNDARY_MTU),
    )
