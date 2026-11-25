"""Scope-specific post-deployment observation coverage, independent of verdicts."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def observation_coverage(
    record: Any,
    dependencies: list[dict],
    deployed_at: str,
    freshness_s: int | None = None,
    *,
    as_of: str | datetime | None = None,
) -> dict:
    deployment = datetime.fromisoformat(deployed_at)
    if deployment.tzinfo is None:
        raise ValueError("deployment time requires a timezone")
    threshold = deployment.timestamp() * 1000
    observed_at = as_of if as_of is not None else getattr(record, "published", None)
    if observed_at is None:
        return {
            "qualifies": False,
            "missing": [{"reasons": ["publication-time-unavailable"]}],
            "observations": [],
            "scope": "unknown",
            "deployed_at": deployed_at,
            "snapshot": str(record.snapshot_key)
            if getattr(record, "snapshot_key", None) is not None
            else None,
        }
    observed_at = datetime.fromisoformat(observed_at) if isinstance(observed_at, str) else observed_at
    if observed_at.tzinfo is None:
        raise ValueError("observation comparison time requires a timezone")
    required = [dep for dep in dependencies if dep.get("kind") not in {"requirement", "assumptions"}]
    global_scope = not required or any(
        dep.get("kind") == "estate" or not dep.get("scope_complete", True) for dep in required
    )
    missing: list[dict] = []
    observations: list[dict] = []
    matched: set[int] = set()
    for device in record.devices:
        selected = [
            (index, dep)
            for index, dep in enumerate(required)
            if (not dep.get("source") or dep["source"] == device.source)
            and (not dep.get("host") or dep["host"] == device.host)
            and (not dep.get("device") or dep["device"] in {*device.device_uids, device.host})
        ]
        if not global_scope and not selected:
            continue
        matched.update(index for index, _ in selected)
        scopes = [dep for _, dep in selected]
        sections = {dep["section"] for dep in scopes if dep.get("section")}
        tables = {dep["table"] for dep in scopes if dep.get("table")}
        whole_device = global_scope or not (sections or tables)
        if whole_device:
            sections = set(device.expected_sections)
            tables = set(device.tables)
        facts = {
            "source": device.source,
            "host": device.host,
            "device_uids": list(device.device_uids),
            "sections": sorted(sections),
            "tables": sorted(tables),
        }
        reasons: list[str] = []
        if device.carried or device.outcome in {"failed", "carried"}:
            reasons.append("carried-or-failed-collection")
        if whole_device and (device.outcome not in {"collected", "unchanged"} or not sections):
            reasons.append("incomplete-device-scope")
        observed = [device.fetch_started_ms]
        for section in sections:
            outcome = device.sections.get(section)
            if outcome is None or outcome.status not in {"ok", "empty"}:
                reasons.append(f"incomplete-section:{section}")
            for key, outcome in device.sections.items():
                if key.startswith(f"{section}_table_") and outcome.status not in {"ok", "empty"}:
                    reasons.append(f"incomplete-section:{key}")
        for table in tables:
            outcome = device.tables.get(table)
            if outcome is None or outcome.status not in {"complete", "complete-empty", "unchanged"}:
                reasons.append(f"incomplete-table:{table}")
            observed.append(outcome.observed_ms if outcome else None)
        if any(value is None or value < threshold for value in observed):
            reasons.append("observation-before-deployment-or-unknown")
        if freshness_s is not None and any(
            value is not None and observed_at.timestamp() * 1000 >= value + freshness_s * 1000
            for value in observed
        ):
            reasons.append("observation-expired")
        if reasons:
            missing.append({**facts, "reasons": sorted(set(reasons))})
        else:
            observations.append({**facts, "observed_ms": min(observed)})
    if not global_scope:
        for index, dependency in enumerate(required):
            if index not in matched:
                missing.append({"dependency": dependency, "reasons": ["required-scope-not-observed"]})
    if not record.devices or (not observations and not missing):
        missing.append({"reasons": ["no-required-observations"]})
    return {
        "qualifies": not missing and bool(observations),
        "missing": missing,
        "observations": observations,
        "scope": "estate" if global_scope else "recorded-dependencies",
        "deployed_at": deployed_at,
        "snapshot": str(record.snapshot_key) if getattr(record, "snapshot_key", None) is not None else None,
    }
