"""Render one page of a stored result artifact inside an analysis child."""

from __future__ import annotations

import json
from typing import Any, Literal, cast

from hst.app import crypto
from hst.assessment.result_artifacts import MAX_ARTIFACT_BYTES, ResultArtifactStore
from hst.assessment.symbolic_provenance import page_observations
from hst.assessment.symbolic_results import address_bucket
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.artifacts import ArtifactLimits, decode_packet_sets

BUCKETS = frozenset(
    {
        "evidence",
        "decided_change.loss",
        "decided_change.gain",
        "open_change.loss",
        "open_change.gain",
        "open.before",
        "open.after",
        "passes.before",
        "passes.after",
        "fails.before",
        "fails.after",
        "triage.decided_loss",
        "triage.passes_then_open",
        "triage.open_then_fails",
        "triage.open_throughout",
        "triage.decided_gain",
        "triage.open_then_passes",
        "triage.fails_then_open",
    }
)


def execute_page(settings: Any, inputs: dict) -> dict:
    bucket, offset, limit = inputs["bucket"], inputs["offset"], inputs["limit"]
    if (
        bucket not in BUCKETS
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= 1000
    ):
        raise ValueError("invalid exact-result page")
    reference = inputs["artifact_ref"]
    allowed = {(ref["estate"], ref["manifest_sha256"]) for ref in inputs["snapshot_refs"]}
    if (reference["estate"], reference["manifest_sha256"]) not in allowed:
        raise ValueError("exact result crosses the saved snapshot scope")
    store = ResultArtifactStore(settings.hst_data_dir, crypto.dek(settings))
    if bucket == "evidence":
        evidence = store.load_evidence(reference)
        if not evidence:
            raise ValueError("This result has no retained complete proof index")
        items = evidence["items"]
        end = min(offset + limit, len(items))
        return {
            "bucket": bucket,
            "artifact_sha256": reference["artifact_sha256"],
            "count": len(items),
            "items": items[offset:end],
            "observations": page_observations(evidence, items[offset:end]),
            "offset": offset,
            "next_offset": end if end < len(items) else None,
            "truncated": offset > 0 or end < len(items),
        }
    artifact = store.load(reference)
    family = json.loads(artifact)["family"]
    if type(family) is not int or family not in (4, 6):
        raise ValueError("invalid result address family")
    with SymbolicManager(HeaderSchema(cast(Literal[4, 6], family))) as manager:
        roots = decode_packet_sets(
            artifact,
            manager,
            limits=ArtifactLimits(max_bytes=MAX_ARTIFACT_BYTES, max_nodes=1_000_000, max_roots=200_000),
        )
        lb, ub = roots["before/lower"], roots["before/upper"]
        la, ua = roots["after/lower"], roots["after/upper"]
        unknown_before, unknown_after = ub.subtract(lb), ua.subtract(la)
        values = {
            "decided_change.loss": lb.subtract(ua),
            "decided_change.gain": la.subtract(ub),
            "open_change.loss": ub.subtract(la),
            "open_change.gain": ua.subtract(lb),
            "open.before": unknown_before,
            "open.after": unknown_after,
            "passes.before": lb,
            "passes.after": la,
            "fails.before": roots["population"].subtract(ub),
            "fails.after": roots["population"].subtract(ua),
            "triage.decided_loss": lb.subtract(ua),
            "triage.passes_then_open": lb.intersect(unknown_after),
            "triage.open_then_fails": unknown_before.subtract(ua),
            "triage.open_throughout": unknown_before.intersect(unknown_after),
            "triage.decided_gain": la.subtract(ub),
            "triage.open_then_passes": unknown_before.intersect(la),
            "triage.fails_then_open": unknown_after.subtract(ub),
        }
        return {
            "bucket": bucket,
            "artifact_sha256": reference["artifact_sha256"],
            **address_bucket(values[bucket], offset=offset, limit=limit),
        }
