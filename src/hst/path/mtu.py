"""Pure MTU evaluation of directed crossings, independent of rendered hops.

A known rejection ceiling proves a local deficit. An acceptance lower bound
proves support up to that bound and proves nothing above it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from itertools import islice, product
from math import prod

from hst.core.mtu import (
    MtuConstraint,
    MtuCoverage,
    MtuFinding,
    MtuGapCode,
    MtuRequest,
    MtuResult,
    MtuStage,
    MtuUncoveredCode,
    mtu_fingerprint,
)
from hst.path.mtu_feedback import qualify_packet_result, request_for_connection


def _minimum(values: Sequence[int | None]) -> int | None:
    known = [v for v in values if v is not None]
    return min(known) if known else None


def _uncovered_code(stage: MtuStage) -> MtuUncoveredCode | None:
    """The uncovered code of a source, destination or boundary stage, or None for another stage."""
    if stage.enforcement == "source":
        return "source-endpoint"
    if stage.enforcement == "destination":
        return "destination-endpoint"
    subject = stage.egress_subject_uid or stage.ingress_subject_uid
    if subject is None and stage.enforcement == "unknown":
        # A boundary() stage has no subject and enforcement "unknown".
        return "path-beyond-twin"
    return None


def constraint_budget(constraint: MtuConstraint, stage: MtuStage) -> tuple[int | None, list[MtuGapCode]]:
    """Convert a local carrier limit to the connection's original-IP coordinates.

    context.af is the original packet family. The constraint family is the
    carrier family of the active tunnel stack. Outer MAC/tags are removed once.
    """
    from .mtu_encap import carrier_af, carrier_tag_depth, inner_budget

    gaps = list(constraint.gaps)
    af, encap_gaps = carrier_af(stage.encapsulation, original_af=stage.context.af)
    if encap_gaps:
        return None, sorted({*gaps, *encap_gaps})
    if (
        constraint.direction not in {stage.context.direction, "both"}
        or (constraint.af is not None and constraint.af != af)
        or (constraint.traffic_class is not None and constraint.traffic_class != stage.context.traffic_class)
    ):
        return None, sorted({*gaps, "MTU_SEMANTICS_UNKNOWN"})
    if constraint.value_bytes is None or constraint.bound_kind == "unknown":
        return None, sorted({*gaps, "MTU_SEMANTICS_UNKNOWN"})
    value = constraint.value_bytes
    coordinate = "ip"
    if constraint.metric == "l2_max_frame_bytes":
        tags, tag_gaps = carrier_tag_depth(stage.encapsulation)
        if tag_gaps:
            return None, sorted({*gaps, *tag_gaps})
        # The evidence states the tag depth it was normalized for. A crossing
        # with an unknown depth uses the stated depth. A known mismatch gives
        # MTU_SEMANTICS_UNKNOWN.
        depth = stage.context.tag_depth if stage.context.tag_depth is not None else constraint.tag_depth
        if depth is None or (tags is not None and tags != depth):
            return None, sorted({*gaps, "MTU_SEMANTICS_UNKNOWN"})
        if constraint.tag_depth is not None and constraint.tag_depth != depth:
            return None, sorted({*gaps, "MTU_SEMANTICS_UNKNOWN"})
        # An observation with tag_depth set holds the allowance for that depth.
        # A generic observation holds the allowance for one tag, and each further
        # tag gets that allowance credited back.
        credit = 0
        if (
            constraint.tag_depth is None
            and constraint.tag_accounting == "extra_allowance"
            and constraint.tag_allowance_bytes is not None
        ):
            credit = constraint.tag_allowance_bytes * max(depth - 1, 0)
        value = max(0, value - 14 - 4 * depth + credit)
        coordinate = "ethernet_payload"
    elif constraint.metric == "l2_payload_mtu_bytes":
        # Encapsulated payload shims (MPLS/PPPoE/MACsec) stay in the size budget.
        coordinate = "ethernet_payload"
    elif constraint.metric != f"ipv{af}_mtu_bytes":
        return None, sorted({*gaps, "MTU_SEMANTICS_UNKNOWN"})
    if stage.encapsulation:
        budget, missing = inner_budget(
            value,
            stage.encapsulation,
            original_af=stage.context.af,
            coordinate="ethernet_payload" if coordinate == "ethernet_payload" else "ip",
        )
        return budget, sorted({*gaps, *missing})
    return value, gaps


def _gap_finding(code: str, stage: MtuStage) -> MtuFinding:
    return MtuFinding.model_validate(
        {
            "code": code,
            "severity": "gap",
            "detail": code.removeprefix("MTU_").replace("_", " ").lower(),
            "subject_uids": sorted(
                {
                    u
                    for u in (
                        stage.ingress_subject_uid,
                        stage.egress_subject_uid,
                        stage.peer_subject_uid,
                    )
                    if u
                }
            ),
            "stage_ids": [stage.stage_id],
            "af": stage.context.af,
            "direction": stage.direction,
        }
    )


def _entry_deficit_detail(constraint: MtuConstraint) -> str:
    if constraint.enforcement_key == "imported-interface":
        return (
            "Requested complete IP packet exceeds the declared entry ceiling for this "
            "endpoint; it is dropped in every DF state."
        )
    if constraint.enforcement == "l2":
        return (
            "Requested complete IP packet exceeds the entry frame size limit; "
            "the interface drops it in every DF state."
        )
    return (
        "Requested complete IP packet exceeds the entry interface MTU; "
        "the interface drops it in every DF state."
    )


def evaluate_stage(stage: MtuStage, request: MtuRequest) -> MtuResult:
    """Evaluate one actual constraint point, retaining missing evidence."""
    request.validate_af(stage.context.af)
    result = MtuResult(
        mode=request.mode,
        af=stage.context.af,
        direction=stage.direction,
        connection_id=stage.connection_id,
        requested_bytes=request.ip_packet_bytes,
        stages=[stage],
        coverage=stage.coverage.model_copy(deep=True),
    )
    if request.mode == "off":
        return result
    if stage.applicability == "not_applicable":
        result.outcome = "not_assessed" if request.mode == "inventory" else "pass"
        return result
    gaps = set(stage.coverage.gaps)
    ceilings: list[int] = []
    support: list[int] = []
    findings: list[MtuFinding] = []
    deficit_enforcements: set[str] = set()
    for constraint in stage.constraints:
        budget, missing = constraint_budget(constraint, stage)
        gaps.update(missing)
        result.evidence_quality.extend(constraint.evidence_quality)
        if budget is None:
            continue
        support.append(budget)
        if constraint.bound_kind == "ceiling":
            ceilings.append(budget)
        if (
            request.ip_packet_bytes is not None
            and constraint.bound_kind == "ceiling"
            and request.ip_packet_bytes > budget
        ):
            deficit_enforcements.add(constraint.enforcement)
            findings.append(
                MtuFinding(
                    code="MTU_CAPACITY_DEFICIT",
                    severity="failure",
                    detail=_entry_deficit_detail(constraint)
                    if stage.context.direction == "rx"
                    else ("Requested complete IP packet exceeds this stage's normalized budget."),
                    subject_uids=[constraint.subject_uid],
                    stage_ids=[stage.stage_id],
                    evidence_uids=constraint.evidence_uids,
                    af=stage.context.af,
                    direction=stage.direction,
                    required_bytes=request.ip_packet_bytes,
                    # observed_bytes is the raw limit and is positive. The budget can be 0.
                    observed_bytes=constraint.value_bytes,
                    deficit_bytes=request.ip_packet_bytes - budget,
                )
            )
    if not stage.constraints:
        gaps.add("MTU_NOT_CAPTURED")
    if stage.applicability == "unknown":
        gaps.add("MTU_PATH_COVERAGE_INCOMPLETE")
    if stage.selection in {"possible", "unknown"}:
        gaps.add("MTU_PATH_COVERAGE_INCOMPLETE")
    result.known_ceiling_bytes = _minimum(ceilings)
    complete = (
        stage.coverage.complete
        and stage.coverage.constraints_complete
        and stage.coverage.candidate_set_complete
        and not stage.coverage.truncated
        and not gaps
        and bool(support)
    )
    result.coverage.complete = complete
    result.coverage.constraints_complete = stage.coverage.constraints_complete and not gaps
    result.coverage.gaps = sorted(gaps)
    if complete:
        result.guaranteed_bytes = min(support)
    result.evidence_quality = sorted(set(result.evidence_quality))
    result.unresolved_subjects = sorted(set(stage.coverage.unresolved_subjects))
    if gaps and not result.unresolved_subjects:
        result.unresolved_subjects = sorted(
            {
                u
                for u in (
                    stage.ingress_subject_uid,
                    stage.egress_subject_uid,
                    stage.peer_subject_uid,
                )
                if u
            }
        )
    result.findings = findings + [_gap_finding(g, stage) for g in sorted(gaps)]
    if result.known_ceiling_bytes is not None:
        result.bottleneck_stage_ids = [stage.stage_id]
    if request.mode == "inventory":
        result.outcome = "not_assessed"
    elif findings:
        # A deficit on a possible or unknown stage is a risk.
        if stage.selection in {"possible", "unknown"} or stage.applicability == "unknown":
            result.outcome = "unknown"
            for finding in findings:
                finding.severity = "risk"
        elif (
            request.mode == "packet"
            and stage.enforcement == "l3"
            and stage.context.af == 4
            and stage.context.direction != "rx"
        ):
            if request.ipv4_df is False:
                result.outcome = "fragmentation_required"
                result.coverage.gaps = sorted({*result.coverage.gaps, "MTU_FRAGMENTATION_UNMODELED"})
            elif request.ipv4_df is None:
                result.outcome = "conditional"
            else:
                result.outcome = "fail"
        else:
            result.outcome = "fail"
    elif (
        complete
        and request.ip_packet_bytes is not None
        and result.guaranteed_bytes is not None
        and request.ip_packet_bytes <= result.guaranteed_bytes
    ):
        result.outcome = "pass"
    else:
        result.outcome = "unknown"
    result = qualify_packet_result(result, stage, request, deficit_enforcements=deficit_enforcements)
    result.fingerprint = mtu_fingerprint(stage.model_dump(), request.model_dump())
    return result


def _merge_path(stages: Sequence[MtuStage], request: MtuRequest) -> MtuResult:
    # A trunk exit stage (tx, outside every candidate set) whose packet-mode outcome
    # is fragmentation_required or conditional caps the packet size of every later
    # stage at its known ceiling. Stages are ordered by depth, and within one depth
    # entry (rx) before exit (tx).
    order = sorted(
        range(len(stages)),
        key=lambda i: (stages[i].depth, 0 if stages[i].context.direction == "rx" else 1),
    )
    effective_bytes = request.ip_packet_bytes
    threaded_requests: dict[int, MtuRequest] = {}
    for i in order:
        stage = stages[i]
        stage_request = request
        if (
            request.mode == "packet"
            and effective_bytes is not None
            and effective_bytes != request.ip_packet_bytes
        ):
            stage_request = request.model_copy(update={"ip_packet_bytes": effective_bytes})
        threaded_requests[i] = stage_request
        if stage.candidate_id is not None or stage.context.direction == "rx":
            continue
        part = evaluate_stage(stage, stage_request)
        if (
            request.mode == "packet"
            and part.outcome in {"fragmentation_required", "conditional"}
            and part.known_ceiling_bytes is not None
        ):
            floor = effective_bytes or part.known_ceiling_bytes
            effective_bytes = max(1, min(floor, part.known_ceiling_bytes))
    parts = [evaluate_stage(stage, threaded_requests.get(i, request)) for i, stage in enumerate(stages)]
    first = stages[0] if stages else None
    applicable = [p for p in parts if p.stages[0].applicability != "not_applicable"]
    complete = bool(applicable) and all(p.coverage.complete for p in applicable)
    ceiling = _minimum([p.known_ceiling_bytes for p in applicable])
    coverage = MtuCoverage(
        complete=complete,
        constraints_complete=bool(applicable) and all(p.coverage.constraints_complete for p in applicable),
        candidate_set_complete=bool(applicable)
        and all(p.coverage.candidate_set_complete for p in applicable),
        exact_path_known=bool(applicable) and all(p.coverage.exact_path_known for p in applicable),
        truncated=any(p.coverage.truncated for p in applicable),
        gaps=sorted({g for p in applicable for g in p.coverage.gaps}),
        unresolved_subjects=sorted({u for p in applicable for u in p.unresolved_subjects}),
    )
    if not applicable and request.mode != "off":
        coverage.gaps = ["MTU_PATH_COVERAGE_INCOMPLETE"]
    outcomes = {p.outcome for p in applicable}
    outcome = "unknown"
    if request.mode in {"off", "inventory"}:
        outcome = "not_assessed"
    elif "fail" in outcomes:
        outcome = "fail"
    elif "fragmentation_required" in outcomes:
        outcome = "fragmentation_required"
    elif "conditional" in outcomes:
        outcome = "conditional"
    elif complete and outcomes == {"pass"}:
        outcome = "pass"
    if request.mode in {"packet", "unfragmented"} and outcome == "unknown":
        # "fits_known_limits" means every stage outside source, destination and
        # boundary is resolved and fits.
        has_deficit = any(f.code == "MTU_CAPACITY_DEFICIT" for p in applicable for f in p.findings)
        core = [p for p in applicable if p.stages[0].enforcement not in {"source", "destination", "unknown"}]
        # An empty core (only source, destination and boundary stages) is not
        # established.
        core_established = bool(core) and all(
            "MTU_PATH_COVERAGE_INCOMPLETE" not in p.stages[0].coverage.gaps
            and p.stages[0].coverage.constraints_complete
            and p.stages[0].selection in {"selected", "eligible"}
            for p in core
        )
        uncovered: set[MtuUncoveredCode] = set()
        endpoints_account_for_every_gap = True
        for p in applicable:
            if not p.coverage.gaps:
                continue
            code = _uncovered_code(p.stages[0])
            if code is None:
                endpoints_account_for_every_gap = False
                break
            uncovered.add(code)
        if not has_deficit and core_established and endpoints_account_for_every_gap and uncovered:
            outcome = "fits_known_limits"
            coverage.uncovered = sorted(uncovered)
    return MtuResult.model_validate(
        {
            "mode": request.mode,
            "af": first.context.af if first else None,
            "direction": first.direction if first else "forward",
            "connection_id": first.connection_id if first else "original",
            "requested_bytes": request.ip_packet_bytes,
            "outcome": outcome,
            "known_ceiling_bytes": ceiling,
            "guaranteed_bytes": _minimum([p.guaranteed_bytes for p in applicable]) if complete else None,
            "coverage": coverage,
            "stages": list(stages),
            "evidence_quality": sorted({q for p in applicable for q in p.evidence_quality}),
            "findings": [f for p in applicable for f in p.findings],
            "feedback": [f for p in applicable for f in p.feedback],
            "unresolved_subjects": coverage.unresolved_subjects,
            "bottleneck_stage_ids": sorted(
                {s for p in applicable if p.known_ceiling_bytes == ceiling for s in p.bottleneck_stage_ids}
            ),
            "fingerprint": mtu_fingerprint(request.model_dump(), [s.model_dump() for s in stages]),
        }
    )


def _merge_lanes(results: list[MtuResult], request: MtuRequest) -> list[MtuResult]:
    """Fold the lanes of one connection into one result per connection.

    Each lane is judged as its own path. Differing known outcomes give
    "conditional". A lane left "unknown" makes the connection "unknown". The
    connection ceiling is the largest lane ceiling.
    """
    known_outcomes = {"pass", "fail", "fragmentation_required", "conditional", "fits_known_limits"}
    by_connection: dict[tuple[str, str], list[MtuResult]] = defaultdict(list)
    for result in results:
        by_connection[(result.connection_id, result.direction)].append(result)
    merged: list[MtuResult] = []
    for key in sorted(by_connection):
        lanes = by_connection[key]
        if len(lanes) == 1:
            merged.append(lanes[0])
            continue
        outcomes = {lane.outcome for lane in lanes}
        if request.mode in {"off", "inventory"}:
            outcome = "not_assessed"
        elif outcomes <= known_outcomes:
            # "pass" with "fits_known_limits" gives "fits_known_limits". Any
            # other mix of known outcomes gives "conditional".
            if outcomes == {"pass"}:
                outcome = "pass"
            elif outcomes <= {"pass", "fits_known_limits"}:
                outcome = "fits_known_limits"
            elif len(outcomes) == 1:
                outcome = outcomes.copy().pop()
            else:
                outcome = "conditional"
        else:
            outcome = "unknown"
        ceilings = [lane.known_ceiling_bytes for lane in lanes if lane.known_ceiling_bytes is not None]
        guarantees = [lane.guaranteed_bytes for lane in lanes if lane.guaranteed_bytes is not None]
        complete = all(lane.coverage.complete for lane in lanes)
        unique_findings = {f.model_dump_json(): f for lane in lanes for f in lane.findings}
        findings = [unique_findings[k] for k in sorted(unique_findings)]
        if outcome in {"conditional", "unknown"}:
            # A deficit on one lane is a risk for the connection.
            findings = [
                f.model_copy(update={"severity": "risk"}) if f.code == "MTU_CAPACITY_DEFICIT" else f
                for f in findings
            ]
        connection = MtuResult.model_validate(
            {
                "mode": request.mode,
                "af": lanes[0].af,
                "direction": lanes[0].direction,
                "connection_id": lanes[0].connection_id,
                "requested_bytes": lanes[0].requested_bytes,
                "outcome": outcome,
                "known_ceiling_bytes": max(ceilings) if ceilings else None,
                "guaranteed_bytes": min(guarantees) if complete and len(guarantees) == len(lanes) else None,
                "coverage": {
                    "complete": complete,
                    "constraints_complete": all(lane.coverage.constraints_complete for lane in lanes),
                    "candidate_set_complete": all(lane.coverage.candidate_set_complete for lane in lanes),
                    "exact_path_known": False,
                    "truncated": any(lane.coverage.truncated for lane in lanes),
                    "gaps": sorted({g for lane in lanes for g in lane.coverage.gaps}),
                    "unresolved_subjects": sorted(
                        {u for lane in lanes for u in lane.coverage.unresolved_subjects}
                    ),
                    "uncovered": sorted({u for lane in lanes for u in lane.coverage.uncovered}),
                },
                "evidence_quality": sorted({q for lane in lanes for q in lane.evidence_quality}),
                "bottleneck_stage_ids": sorted(
                    {
                        s
                        for lane in lanes
                        if ceilings and lane.known_ceiling_bytes == min(ceilings)
                        for s in lane.bottleneck_stage_ids
                    }
                ),
                "findings": findings,
                "unresolved_subjects": sorted({u for lane in lanes for u in lane.unresolved_subjects}),
                "lanes": lanes,
                "feedback": [f for lane in lanes for f in lane.feedback],
                "fingerprint": mtu_fingerprint(request.model_dump(), [lane.fingerprint for lane in lanes]),
            }
        )
        merged.append(connection)
    return merged


def evaluate_stages(stages: Sequence[MtuStage], request: MtuRequest) -> MtuResult:
    """Evaluate directed connection legs and independent alternative sets.

    Serial LAGs produce a bounded Cartesian product of their members. A
    truncated candidate expansion gives no all-candidate guarantee.
    """
    groups: dict[tuple[str, str, str, int], list[MtuStage]] = defaultdict(list)
    for stage in stages:
        groups[(stage.connection_id, stage.direction, stage.lane, stage.context.af)].append(stage)
    if not groups:
        return _merge_path([], request)
    results: list[MtuResult] = []
    for key in sorted(groups):
        members = groups[key]
        leg_request, length_gaps = request_for_connection(
            request,
            direction=members[0].direction,
            connection_reset=any(s.connection_reset for s in members),
        )
        # A connection with no stated packet size is evaluated in inventory mode.
        eval_request = leg_request or MtuRequest(mode="inventory", traffic_class=request.traffic_class)
        candidate_sets: dict[str, set[str]] = defaultdict(set)
        for stage in members:
            if stage.candidate_id is not None:
                candidate_sets[stage.candidate_set_id or "legacy"].add(stage.candidate_id)
        summary = _merge_path(members, eval_request)
        if candidate_sets:
            set_ids = sorted(candidate_sets)
            choices = [sorted(candidate_sets[set_id]) for set_id in set_ids]
            truncated = prod(len(values) for values in choices) > 128
            parts = []
            for combination in islice(product(*choices), 128):
                selected = dict(zip(set_ids, combination, strict=True))
                parts.append(
                    _merge_path(
                        [
                            stage
                            for stage in members
                            if stage.candidate_id is None
                            or selected[stage.candidate_set_id or "legacy"] == stage.candidate_id
                        ],
                        eval_request,
                    )
                )
            summary.candidates = parts
            # Stages outside every candidate set bound each alternative. Their
            # ceiling and a deficit proven on them hold for an incomplete set.
            common = _merge_path([s for s in members if s.candidate_id is None], eval_request)
            if truncated:
                summary.coverage.truncated = True
                summary.coverage.complete = False
                summary.coverage.candidate_set_complete = False
                summary.coverage.gaps = sorted({*summary.coverage.gaps, "MTU_PATH_COVERAGE_INCOMPLETE"})
                summary.guaranteed_bytes = None
            # The upper bound is the maximum of the candidate ceilings when the
            # candidate set is complete and every candidate has a ceiling.
            # Otherwise it is the ceiling of the stages outside every candidate set.
            if summary.coverage.candidate_set_complete and all(
                p.known_ceiling_bytes is not None for p in parts
            ):
                summary.known_ceiling_bytes = max(
                    p.known_ceiling_bytes for p in parts if p.known_ceiling_bytes is not None
                )
            else:
                summary.known_ceiling_bytes = common.known_ceiling_bytes
                summary.bottleneck_stage_ids = list(common.bottleneck_stage_ids)
            outcomes = {p.outcome for p in parts}
            if not summary.coverage.candidate_set_complete and request.mode not in {"off", "inventory"}:
                summary.outcome = "fail" if common.outcome == "fail" else "unknown"
            elif len(outcomes) > 1 and request.mode not in {"off", "inventory"}:
                summary.outcome = "conditional" if "pass" in outcomes else "unknown"
        if length_gaps:
            summary.mode = request.mode
            summary.outcome = "unknown"
            summary.requested_bytes = None
            summary.coverage.complete = False
            summary.coverage.gaps = sorted({*summary.coverage.gaps, *length_gaps})
            summary.findings.extend(_gap_finding(gap, members[0]) for gap in length_gaps)
            for candidate in summary.candidates:
                candidate.mode = request.mode
                candidate.outcome = "unknown"
                candidate.requested_bytes = None
                candidate.coverage.complete = False
                candidate.coverage.gaps = sorted({*candidate.coverage.gaps, *length_gaps})
        summary.lane = key[2]
        summary.fingerprint = mtu_fingerprint(request.model_dump(), [stage.model_dump() for stage in members])
        results.append(summary)
    results = _merge_lanes(results, request)
    if len(results) == 1:
        return results[0]
    outcomes = {result.outcome for result in results}
    combined = "unknown"
    if request.mode in {"off", "inventory"}:
        combined = "not_assessed"
    elif "fail" in outcomes:
        combined = "fail"
    elif outcomes == {"pass"}:
        combined = "pass"
    elif outcomes <= {"pass", "fits_known_limits"}:
        combined = "fits_known_limits"
    # Distinct connections or regions have no single PMTU.
    return MtuResult.model_validate(
        {
            "mode": request.mode,
            "outcome": combined,
            "connections": results,
            "feedback": [feedback for result in results for feedback in result.feedback],
            "fingerprint": mtu_fingerprint(request.model_dump(), [r.fingerprint for r in results]),
        }
    )
