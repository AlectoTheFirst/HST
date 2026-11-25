"""Context-scoped observation references for retained symbolic proofs."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from typing import Any

from hst.analysis_model.evidence import EvidenceEvaluation
from hst.analysis_model.model import StateKey


class ObservationIndex:
    """Index immutable observations once. The index infers no device join and no
    revision join.
    """

    def __init__(self, evidence: EvidenceEvaluation | None):
        self.records: dict[str, dict[str, Any]] = {}
        self.by_context: dict[tuple[str, int | None, str], list[str]] = defaultdict(list)
        if evidence is None:
            return
        for window in evidence.windows:
            record = asdict(window)
            for key in ("capture_start", "capture_end", "observation_time"):
                value = record[key]
                record[key] = value.isoformat() if isinstance(value, datetime) else None
            record["outcome"] = window.outcome.value
            record["clock_quality"] = window.clock_quality.value
            record["analysis_time"] = evidence.analysis_time.isoformat()
            record["producer_ids"] = list(window.producer_ids)
            record["revision"]["producer_ids"] = list(window.revision.producer_ids)
            # Evidence policy is part of the interpretation of the observation.
            record["policy"] = {
                "max_age_s": evidence.policy.max_age_s,
                "max_skew_s": evidence.policy.max_skew_s,
                "consistency_mode": evidence.policy.consistency_mode.value,
                "stable_window_assumption": evidence.policy.stable_window_assumption,
            }
            payload = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
            identity = hashlib.sha256(payload.encode()).hexdigest()
            self.records[identity] = record
            self.by_context[(window.subject, window.address_family, window.vrf)].append(identity)

    def references(self, state: StateKey | None) -> tuple[str, ...]:
        if state is None:
            return ()
        context = state.context
        return tuple(
            sorted(
                {
                    identity
                    for family in (None, context.address_family)
                    for vrf in ("", context.vrf)
                    for identity in self.by_context.get((context.firewall_instance, family, vrf), ())
                }
            )
        )


def page_observations(evidence: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    """Return only the observations referenced by this page of proof records."""
    catalog = evidence.get("observations", {})
    references = {reference for item in items for reference in item.get("observation_refs", ())}
    if not references <= catalog.keys():
        raise ValueError("retained proof references missing observation provenance")
    return {reference: catalog[reference] for reference in sorted(references)}
