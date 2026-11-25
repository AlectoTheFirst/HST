"""Read-only enterprise schema and artifact upgrade planning."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

TARGET_REVISION = "0025"
ADDITIVE_REVISIONS = ("0024", "0025")


def migration_dry_run(
    *,
    current_revision: str,
    runtime: Mapping[str, str],
    cache_bindings: Sequence[Mapping[str, Any]] = (),
    saved_results: Sequence[Mapping[str, Any]] = (),
    database_read_only: bool = False,
    artifact_store_read_only: bool = False,
    offline_runtime_ready: bool = False,
) -> dict[str, Any]:
    """Return an upgrade report without connecting to or changing any service."""
    if current_revision not in {"0023", *ADDITIVE_REVISIONS}:
        raise ValueError("enterprise upgrade planning requires schema revision 0023, 0024 or 0025")
    pending = tuple(revision for revision in ADDITIVE_REVISIONS if revision > current_revision)
    schema_actions = []
    if "0024" in pending:
        schema_actions.append("create analysis_cache_artifacts")
    if "0025" in pending:
        schema_actions.append("create analysis_cache_leases")

    required = {
        name: str(runtime.get(name) or "")
        for name in (
            "semantic_version",
            "header_schema",
            "ordering_version",
            "backend",
            "backend_version",
            "build_identity",
        )
    }
    if any(not value for value in required.values()):
        raise ValueError("runtime identity is incomplete")
    cache = []
    for binding in cache_bindings:
        mismatches = tuple(
            name for name, expected in required.items() if str(binding.get(name) or "") != expected
        )
        cache.append(
            {
                "key": str(binding.get("key") or ""),
                "action": "invalidate" if mismatches else "retain",
                "reasons": mismatches,
            }
        )

    results = []
    for reference in saved_results:
        engine = str(reference.get("engine") or reference.get("mode") or "")
        version = str(reference.get("engine_version") or "")
        requires_v2 = engine in {"symbolic-v2", "compiled", "dd.cudd"}
        legacy_v1 = engine in {"legacy-v1", "v1"}
        results.append(
            {
                "identity": str(reference.get("identity") or ""),
                "action": "preserve",
                "runtime_requirement": (
                    {"engine": engine or "symbolic-v2", "version": version or "recorded"}
                    if requires_v2
                    else {"engine": engine or "unknown-recorded", "version": version or "recorded"}
                ),
                "downgrade": "readable-by-v1" if legacy_v1 else "preserve-unreadable",
            }
        )

    return {
        "schema": {
            "current": current_revision,
            "target": TARGET_REVISION,
            "pending": pending,
            "additive": True,
            "actions": tuple(schema_actions),
            "can_apply": not database_read_only,
        },
        "cache": {
            "entries": tuple(cache),
            "rebuild_from_pinned_evidence": any(item["action"] == "invalidate" for item in cache),
            "writable": not artifact_store_read_only,
        },
        "saved_results": {
            "entries": tuple(results),
            "mutated": False,
            "preserved": len(results),
        },
        "runtime": {
            **required,
            "offline_ready": offline_runtime_ready,
            "read_only_serving": current_revision == TARGET_REVISION,
        },
    }
