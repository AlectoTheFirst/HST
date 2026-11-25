"""The operations tool `ops_list_collection_runs`.

`ops_list_collection_runs` lists the newest collection runs and the queued or
running `collect.run` jobs, in the shape of `GET /api/runs`. Each run is
written by the row serializer of that route, and `pending_runs` lists the jobs
as that route does. The tool also returns the `snapshot_key` of each run, which
is the run id that it published, and whether that run is the selected
snapshot. The tool needs `runs.manage`, the gate of `/api/runs`. Local stdio
offers it only when the app store is configured.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hst.app.ai.registry import ToolContext, ToolRegistry
from hst.core import db as dbmod
from hst.results.words import record
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    PageOut,
    catalogue_spec,
    jsonable,
    whole_result,
)
from hst.twin_tools.stores import read_store, require


class OpsListCollectionRunsInput(selectors.ToolInput):
    """The newest collection runs and the pending ones."""

    source: str | None = Field(
        default=None, max_length=200, description="Only runs of this source, applied after the read."
    )
    status: str | None = Field(
        default=None,
        max_length=32,
        description="Only runs with this status (running, ok, error, cancelled), applied after the read.",
    )
    limit: selectors.Limit = selectors.DEFAULT_LIMIT


class OpsListCollectionRunsResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    runs: list[dict[str, Any]]
    pending_runs: list[dict[str, Any]] = Field(
        description="every queued or running collect.run job, as GET /api/runs lists it"
    )


async def _history(
    ctx: ToolContext, store: Any, limit: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The run rows and pending jobs of `GET /api/runs`, each run with its
    `snapshot_key`."""
    import asyncio

    from hst.app.routes.jobs import job_json
    from hst.app.routes.runs import _json
    from hst.core.collection_progress import read_progress
    from hst.worker import collect as collect_worker

    require(store, "list_runs", "collection runs")
    rows = []
    for run in await store.list_runs(limit=limit):
        row = {**_json(run), "snapshot_key": run.snapshot_key}
        if run.status == "running":
            progress = await asyncio.to_thread(
                read_progress,
                ctx.settings,
                source=None if run.source == "cycle" else run.source,
                since_ms=int(run.started_at.timestamp() * 1000),
            )
            if progress:
                row["progress"] = progress
        rows.append(row)
    pending = [job_json(job) for job in await store.pending_jobs(collect_worker.RUN_KIND)]
    return rows, pending


def ops_list_collection_runs(ctx: ToolContext, params: OpsListCollectionRunsInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "ops_list_collection_runs", params, session)

        async def work(store: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            return await _history(ctx, store, params.limit)

        rows, pending = read_store(ctx, work)
        selected = call.snapshot.snapshot_id
        stored = ItemEvidence.of(record("stored"), basis="stored").model_dump(mode="json")
        runs = [
            {
                **row,
                "snapshot_matches": None if row["snapshot_key"] is None else row["snapshot_key"] == selected,
                "evidence": stored,
            }
            for row in jsonable(rows)
            if (params.source is None or row["source"] == params.source)
            and (params.status is None or row["status"] == params.status)
        ]
        truncated = len(rows) >= params.limit
        unknowns = (
            [f"the read stopped at the newest {params.limit} runs; the filters applied to those"]
            if truncated and (params.source is not None or params.status is not None)
            else []
        )
        return call.finish(
            session,
            result={"runs": runs, "pending_runs": jsonable(pending)},
            evidence=Evidence(
                result=whole_result((r["evidence"]["result"] for r in runs), unknowns=unknowns),
                unknowns=unknowns,
            ),
            page=PageOut(truncated=truncated, total=None if truncated else len(runs), limit=params.limit),
            engine_function="hst.app.store.Store.list_runs",
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="ops_list_collection_runs",
            description=(
                "List the newest collection runs, newest first, as GET /api/runs does: id, source, "
                "status, start and finish times, detail (the failure text of a failed run), who "
                "triggered it, and progress while running. snapshot_key is the run id a run published, "
                "and snapshot_matches says whether that is the selected snapshot. source and status "
                "filter the runs read. pending_runs lists every queued or running collect.run job. Needs "
                "runs.manage."
            ),
            input_model=OpsListCollectionRunsInput,
            result_model=OpsListCollectionRunsResult,
            run=ops_list_collection_runs,
            permission="runs.manage",
        )
    )
