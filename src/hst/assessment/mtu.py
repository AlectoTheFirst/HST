"""The MTU audit rules of the API and the saved assessments."""

from __future__ import annotations

from collections.abc import Sequence

from hst.core.mtu import MtuConstraint, MtuFinding, MtuRequest, MtuResolution, MtuStage
from hst.path.mtu import evaluate_stages


def _coordinate(c: MtuConstraint) -> tuple:
    return c.metric, c.af, c.direction, c.bound_kind, c.traffic_class, c.tag_depth


def audit_neighbors(left: MtuResolution, right: MtuResolution) -> list[MtuFinding]:
    """Return the findings of both resolutions and the differences between them.

    A difference is a pair of ceiling constraints of the same coordinate with
    different values and without gaps. Its severity is `info`.
    """
    findings = [*_resolution_findings(left), *_resolution_findings(right)]
    for a in left.constraints:
        for b in right.constraints:
            if (
                _coordinate(a) != _coordinate(b)
                or a.value_bytes is None
                or b.value_bytes is None
                or a.value_bytes == b.value_bytes
                or a.gaps
                or b.gaps
                or a.bound_kind != "ceiling"
            ):
                continue
            findings.append(
                MtuFinding(
                    code="MTU_NORMALIZED_DIFFERENCE",
                    severity="info",
                    detail="Neighboring interfaces report different limits in the same byte coordinate.",
                    subject_uids=sorted({a.subject_uid, b.subject_uid}),
                    evidence_uids=sorted(set(a.evidence_uids + b.evidence_uids)),
                    af=a.af,
                    observed_bytes=a.value_bytes,
                    required_bytes=b.value_bytes,
                )
            )
    return _deduplicate(findings)


def audit_adjacency(left: MtuResolution, right: MtuResolution) -> list[MtuFinding]:
    """Return the findings of `audit_neighbors`, with each difference as the risk
    `MTU_ADJACENCY_DISCREPANCY`."""
    findings = audit_neighbors(left, right)
    for finding in findings:
        if finding.code == "MTU_NORMALIZED_DIFFERENCE":
            finding.code = "MTU_ADJACENCY_DISCREPANCY"
            finding.severity = "risk"
            finding.detail = (
                "Neighbor protocol MTUs differ; check protocol database exchange and observed session state."
            )
    return findings


def audit_members(members: Sequence[tuple[str, bool | None, MtuResolution]]) -> list[MtuFinding]:
    findings: list[MtuFinding] = []
    for index, (uid, active, resolution) in enumerate(members):
        for other_uid, other_active, other in members[index + 1 :]:
            for difference in audit_neighbors(resolution, other):
                if difference.code != "MTU_NORMALIZED_DIFFERENCE":
                    continue
                current = active is True and other_active is True
                difference.code = "MTU_LAG_INCONSISTENCY"
                difference.severity = "risk"
                difference.detail = (
                    "Active aggregate members have different MTU limits."
                    if current
                    else "Aggregate member MTU readiness differs; active eligibility is not established."
                )
                difference.subject_uids = sorted({uid, other_uid})
                difference.scope = "active_members" if current else "member_readiness"
                findings.append(difference)
    return _deduplicate(findings)


def audit_stages(stages: Sequence[MtuStage], request: MtuRequest) -> list[MtuFinding]:
    result = evaluate_stages(stages, request)
    findings = list(result.findings)
    pending = list(result.connections)
    while pending:
        child = pending.pop()
        findings.extend(child.findings)
        pending.extend(child.connections)
    return _deduplicate(findings)


def _deduplicate(findings: Sequence[MtuFinding]) -> list[MtuFinding]:
    unique = {f.model_dump_json(): f for f in findings}
    return [unique[key] for key in sorted(unique)]


def _resolution_findings(resolution: MtuResolution) -> list[MtuFinding]:
    findings = list(resolution.findings)
    for code in resolution.gaps:
        findings.append(
            MtuFinding(
                code=code,
                severity="gap",
                detail="MTU source evidence is incomplete for this comparison.",
                subject_uids=sorted({o.subject_uid for o in resolution.observations}),
                evidence_uids=sorted({o.uid for o in resolution.observations}),
            )
        )
    return findings
