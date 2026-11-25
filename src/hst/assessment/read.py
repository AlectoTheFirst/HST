"""The read of saved assessments for the agent tool and the MCP tool."""

from __future__ import annotations

import json
from typing import Any

from hst.app.store.pg import PgStore
from hst.app.tables import MAX_RESULT_BYTES
from hst.assessment.store import _same_definition, clears_freshness


async def read_saved(
    settings: Any,
    run_id: str | None = None,
    limit: int = 20,
    *,
    store: Any = None,
    snapshot_refs: bool = False,
) -> dict:
    """Saved assessments with their recent runs, or one recorded run.

    `store` is the app store when the caller has one. It is used as given and
    stays open. Without it the function opens a `PgStore` from `settings` and
    disposes of it before returning. With `snapshot_refs`, each listed run also
    has the snapshot references it was computed from.
    """
    if not 1 <= limit <= 100:
        raise ValueError("Assessment list limit must be between 1 and 100.")
    owned = store is None
    if store is None:
        store = PgStore(settings.postgres_dsn, settings.postgres_ca_file)
    try:
        if run_id is None:
            records = await store.list_assessments(limit)
            return {
                "assessments": [
                    {
                        "id": r.id,
                        "revision": r.revision,
                        "title": r.title,
                        "purpose": r.purpose,
                        "freshness": await store.get_assessment_freshness(r.id),
                        "runs": [
                            {
                                "id": run.id,
                                "kind": run.kind,
                                "state": run.state,
                                "assessment_revision": run.assessment_revision,
                                **({"snapshot_refs": run.snapshot_refs} if snapshot_refs else {}),
                            }
                            for run in await store.list_analysis_runs(r.id, limit=5)
                        ],
                    }
                    for r in records
                ],
                "limit": limit,
            }
        run = await store.get_analysis_run(run_id)
        if run is None:
            return {"error": "Assessment run not found."}
        record = run.as_dict()
        for field in ("lease_token", "claimed_by", "checkpoint"):
            record.pop(field, None)
        freshness = await store.get_assessment_freshness(run.assessment_id)
        newest = await store.get_assessment(run.assessment_id)
        if newest is not None and not clears_freshness(run.kind, newest.definition):
            # A verify run, or a search run of a change assessment, answers
            # another question than the question that freshness tracks.
            freshness = {**freshness, "run_is_freshness_basis": False}
        elif freshness.get("state") == "current" and freshness.get("run_id") != run.id:
            current_run = (
                await store.get_analysis_run(freshness["run_id"]) if freshness.get("run_id") else None
            )
            stated = await store.get_assessment(run.assessment_id, run.assessment_revision)
            if (
                current_run is None
                or newest is None
                or stated is None
                or not _same_definition(stated.definition, newest.definition)
                or run.snapshot_refs[:1] != current_run.snapshot_refs[:1]
                or run.engine_version != current_run.engine_version
            ):
                # The state is `superseded` when the current run was created after
                # this run, and `not-current` otherwise.
                older = current_run is not None and run.created_at < current_run.created_at
                state = "superseded" if older else "not-current"
                freshness = {**freshness, "state": state, "causes": ["another-run-is-current"]}
        result = {"run": record, "freshness": freshness}
        if len(json.dumps(result).encode()) > MAX_RESULT_BYTES:
            return {
                "error": "Result exceeds the tool byte limit; use the assessment export.",
                "run_id": run.id,
            }
        return result
    finally:
        if owned:
            await store.dispose()
