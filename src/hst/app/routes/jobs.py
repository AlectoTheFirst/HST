"""GET /api/jobs lists the jobs of the maintenance queue with their times and details."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from hst.app.auth import require_permission
from hst.app.store import Job
from hst.core.collection_progress import read_progress
from hst.worker.collect import RUN_KIND

router = APIRouter(dependencies=[Depends(require_permission("runs.manage"))])


def job_json(job: Job) -> dict[str, Any]:
    """One job as GET /api/jobs lists it, and as GET /api/runs lists the
    pending `collect.run` jobs."""
    # Duration in seconds.
    duration = None
    if job.started_at is not None and job.finished_at is not None:
        duration = (job.finished_at - job.started_at).total_seconds()
    return {
        "id": job.id,
        "kind": job.kind,
        # Null for a maintenance job.
        "source": job.source,
        "device": job.device,
        "state": job.state,
        "attempt": job.attempt,
        "max_attempts": job.max_attempts,
        "enqueued_at": job.enqueued_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "not_before": job.not_before.isoformat(),
        "duration_s": duration,
        "detail": job.detail or "",
        "triggered_by": job.triggered_by,
    }


@router.get("/jobs")
async def history(request: Request, limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    store = request.app.state.store
    jobs = await store.list_jobs(limit=limit)
    rows = []
    for job in jobs:
        row = job_json(job)
        # The progress of a running collect.run job is on the row of its run in
        # GET /api/runs.
        if job.state == "running" and job.source and job.started_at is not None and job.kind != RUN_KIND:
            progress = await asyncio.to_thread(
                read_progress,
                request.app.state.settings,
                source=job.source,
                since_ms=int(job.started_at.timestamp() * 1000),
            )
            if progress:
                row["progress"] = progress
        rows.append(row)
    return {"jobs": rows, "depth": await store.job_depth()}
