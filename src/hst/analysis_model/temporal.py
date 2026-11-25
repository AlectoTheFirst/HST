"""Translate one pinned manifest into explicit compiled-evidence windows."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .evidence import (
    CaptureOutcome,
    ClockQuality,
    EvidenceEvaluation,
    EvidencePolicy,
    EvidenceWindow,
    RevisionEvidence,
    evaluate_evidence,
)
from .model import EvidenceRef

if TYPE_CHECKING:
    from .graph import GraphInventory


def manifest_evidence(
    snapshot: Any,
    *,
    analysis_time: datetime,
    policy: EvidencePolicy,
    graph: GraphInventory | None = None,
) -> EvidenceEvaluation:
    """Use only recorded collector windows. Absent clocks and revisions stay unknown."""
    if snapshot.manifest is None:
        raise ValueError("temporal evidence requires a pinned manifest")
    windows: list[EvidenceWindow] = []
    revisions = _installed_revisions(graph)
    for device in snapshot.manifest.devices:
        start = _time(device.fetch_started_ms)
        end = _time(device.fetch_finished_ms)
        # A device clock is evidence only when a collector captured it.
        declared_quality = ClockQuality(getattr(device, "clock_quality", "unknown"))
        collector_clock = getattr(device, "clock_source", "") == "collector-fetch-window" and bool(
            getattr(device, "clock_assumption", "")
        )
        verified = _time(getattr(device, "verified_ms", None))
        observed: datetime | None
        if verified is not None:
            # A later fetch that found a carried device unchanged observed the
            # device again on the collector host clock. A carried device that no
            # run fetched again keeps its original window.
            start = _time(getattr(device, "verified_started_ms", None)) or verified
            end = observed = verified
            clock_quality = declared_quality if collector_clock else ClockQuality.UNKNOWN
        elif collector_clock:
            observed = end or start
            clock_quality = declared_quality if observed is not None else ClockQuality.UNKNOWN
        else:
            source_observed = _time(device.source_clock_ms)
            observed = source_observed or end or start
            clock_quality = declared_quality if source_observed is not None else ClockQuality.UNKNOWN
        subjects = tuple(device.device_uids) or (device.host or f"{device.source}:unqualified",)
        for section, outcome in device.sections.items():
            status = str(outcome.status)
            capture = (
                CaptureOutcome.COMPLETE
                if status in {"ok", "empty", "complete", "complete-empty", "unchanged"}
                else CaptureOutcome.PARTIAL
                if status == "partial"
                else CaptureOutcome.MISSING
                if status in {"unknown", "not-captured", "unsupported"}
                else CaptureOutcome.FAILED
            )
            for subject in subjects:
                candidates = revisions.get(subject, ()) if section == "installation" else ()
                if not candidates:
                    candidates = (("", RevisionEvidence(), False),)
                for scope, revision, required in candidates:
                    windows.append(
                        EvidenceWindow(
                            subject=subject,
                            source=device.source,
                            section=section,
                            capture_start=start,
                            capture_end=end,
                            observation_time=observed,
                            outcome=capture,
                            clock_quality=clock_quality,
                            revision=revision,
                            revision_required=required,
                            revision_scope=scope,
                            producer_ids=(device.effective_run,) if device.effective_run else (),
                            clock_source=getattr(device, "clock_source", ""),
                            clock_assumption=getattr(device, "clock_assumption", ""),
                        )
                    )
    return evaluate_evidence(tuple(windows), policy, analysis_time=analysis_time)


def refs_for_context(
    evidence: EvidenceEvaluation, device_uid: str, sections: frozenset[str]
) -> tuple[EvidenceRef, ...]:
    """Return the evidence refs of the windows of `device_uid` in `sections`."""
    return tuple(
        sorted(
            {
                EvidenceRef(window.source, window.subject, window.section, window.address_family, window.vrf)
                for window in evidence.windows
                if window.subject == device_uid and window.section in sections
            },
            key=lambda ref: (ref.source, ref.subject, ref.section, ref.address_family or 0, ref.vrf),
        )
    )


def _time(value: Any) -> datetime | None:
    return datetime.fromtimestamp(value / 1000, UTC) if isinstance(value, int) else None


def _installed_revisions(
    graph: GraphInventory | None,
) -> dict[str, tuple[tuple[str, RevisionEvidence, bool], ...]]:
    """Join only observed installation relations to their configured rulebases."""
    if graph is None:
        return {}
    observed: dict[str, list[tuple[str, RevisionEvidence, bool]]] = {}
    for rulebase_uid in graph.labels.get("FwRulebase", ()):
        rulebase = graph.nodes.get(rulebase_uid)
        if rulebase is None:
            continue
        configured = rulebase.props.get("configured_revision")
        for relation in graph.incoming.get((rulebase_uid, "ENFORCES"), ()):
            if relation.props.get("installed") is not True:
                continue
            installed = relation.props.get("installed_revision")
            if configured is not None and not isinstance(configured, str):
                continue
            if installed is not None and not isinstance(installed, str):
                continue
            observed.setdefault(relation.start, []).append(
                (
                    rulebase_uid,
                    RevisionEvidence(
                        configured_revision=configured or "",
                        installed_revision=installed or "",
                        producer_ids=(str(relation.props["observation_uid"]),)
                        if relation.props.get("observation_uid")
                        else (),
                    ),
                    True,
                )
            )
    return {device: tuple(sorted(items, key=lambda item: item[0])) for device, items in observed.items()}
