"""Bounded read-only audits over explicit snapshot topology and MTU evidence."""

from __future__ import annotations

import base64
import json
from itertools import pairwise
from typing import Any, Literal

from hst.assessment.mtu import audit_neighbors
from hst.core.mtu import MtuContext, MtuFinding, MtuModel, MtuResolution
from hst.core.mtu_read import read_mtu, resolve_constraints

AuditScope = Literal["link", "bridge-domain", "fabric"]

# Every node and relationship in each traversed path is snapshot guarded.
_PATTERNS = {
    "link": (
        "MATCH p=(a:Obj)-[:CONNECTED_TO]-(b:Obj) WHERE a.uid < b.uid "
        "AND ($subject IS NULL OR a.uid=$subject OR b.uid=$subject)"
    ),
    "bridge-domain": (
        "MATCH p=(a:Obj)-[:CARRIES]->(:VlanInstance)-[:REALIZES]->(b:BridgeDomain) WHERE b.uid=$subject"
    ),
    "fabric": "MATCH p=(a:Obj)-[:ON]->(:Device)-[:MEMBER_OF]->(b:Fabric) WHERE b.uid=$subject",
}


class MtuAuditItem(MtuModel):
    subject_uid: str
    peer_uid: str
    resolutions: list[MtuResolution]
    findings: list[MtuFinding]


class MtuAuditPage(MtuModel):
    snapshot: int
    scope: AuditScope
    subject_uid: str | None
    items: list[MtuAuditItem]
    findings: list[MtuFinding]
    next_cursor: str | None = None
    truncated: bool = False
    coverage_complete: bool = False
    gaps: list[str]
    query_count: int


def audit_mtu(
    session: Any,
    *,
    scope: AuditScope = "link",
    subject_uid: str | None = None,
    af: Literal[4, 6] = 4,
    limit: int = 50,
    cursor: str | None = None,
) -> MtuAuditPage:
    """Keyset pagination binds snapshot, scope, subject and AF into each cursor."""
    cts = getattr(session, "cts", None)
    if type(cts) is not int:
        raise ValueError("MTU audit requires a pinned snapshot")
    if scope not in _PATTERNS or type(limit) is not int or not 1 <= limit <= 200 or af not in (4, 6):
        raise ValueError("invalid MTU audit scope, family or page limit (1..200)")
    if scope != "link" and not subject_uid:
        raise ValueError("bridge-domain/fabric audits require subject_uid")
    after_a, after_b = "", ""
    binding = [cts, scope, subject_uid, af]
    if cursor:
        try:
            if len(cursor) > 4096:
                raise ValueError("cursor too large")
            data = json.loads(base64.urlsafe_b64decode(cursor))
            if data[:4] != binding or len(data) != 6 or not all(isinstance(x, str) for x in data[4:]):
                raise ValueError("cursor binding")
            after_a, after_b = data[4:]
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ValueError("MTU cursor does not match snapshot/scope/subject/AF") from exc
    from hst import path

    query = (
        _PATTERNS[scope]
        + """
AND all(n IN nodes(p) WHERE n.collection_ts=$snap AND NOT n:Retired AND n._retired_at IS NULL)
AND all(r IN relationships(p) WHERE r.collection_ts=$snap AND r._retired_at IS NULL)
AND (a.uid > $after_a OR (a.uid=$after_a AND b.uid>$after_b))
RETURN DISTINCT a.uid AS subject_uid, b.uid AS peer_uid
ORDER BY subject_uid, peer_uid LIMIT $row_limit
"""
    )
    rows = path._read(
        session, query, subject=subject_uid, after_a=after_a, after_b=after_b, row_limit=limit + 1
    )
    more = len(rows) > limit
    rows = rows[:limit]
    evidence = read_mtu(
        session,
        {str(row[k]) for row in rows for k in ("subject_uid", "peer_uid")},
        max_subjects=400,
        max_observations=4000,
    )
    items = []
    for row in rows:
        a, b = row["subject_uid"], row["peer_uid"]
        resolutions = [
            resolve_constraints(evidence.by_subject.get(uid, []), MtuContext(af=af)) for uid in (a, b)
        ]
        findings = (
            audit_neighbors(*resolutions)
            if scope == "link"
            else [f for resolution in resolutions for f in resolution.findings]
        )
        for uid, resolution in zip((a, b), resolutions, strict=True):
            for gap in resolution.gaps:
                findings.append(
                    MtuFinding(
                        code=gap,
                        severity="gap",
                        subject_uids=[uid],
                        detail="MTU evidence is incomplete for this audit subject.",
                    )
                )
        unique = {f.model_dump_json(): f for f in findings}
        items.append(
            MtuAuditItem(
                subject_uid=a,
                peer_uid=b,
                resolutions=resolutions,
                findings=[unique[k] for k in sorted(unique)],
            )
        )
    page_findings: list[MtuFinding] = []
    if scope != "link":
        # Only adjacent members of this page are compared.
        for left, right in pairwise(items):
            for finding in audit_neighbors(left.resolutions[0], right.resolutions[0]):
                if finding.code == "MTU_NORMALIZED_DIFFERENCE":
                    finding.detail = "Recorded members of this scope have different comparable MTU limits."
                    finding.scope = "page_members"
                    page_findings.append(finding)
    token = None
    if more and rows:
        token = base64.urlsafe_b64encode(
            json.dumps(
                [*binding, rows[-1]["subject_uid"], rows[-1]["peer_uid"]], separators=(",", ":")
            ).encode()
        ).decode()
    gaps = {*evidence.gaps, "MTU_PATH_COVERAGE_INCOMPLETE"}
    if scope != "link":
        gaps.add("MTU_POLICY_UNRESOLVED")
    return MtuAuditPage(
        snapshot=cts,
        scope=scope,
        subject_uid=subject_uid,
        items=items,
        findings=page_findings,
        next_cursor=token,
        truncated=more or evidence.truncated,
        gaps=sorted(gaps),
        query_count=1 + evidence.query_count,
    )
