"""The routes that trigger collector and reasoner runs, read their history and purge the graph."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel

from hst.app import crypto, demo_estate, evidence_exports, runs_exec
from hst.app.auth import current_user, require_permission
from hst.app.routes.jobs import job_json
from hst.app.store import Run, Store, User, live_run
from hst.core import Settings, rawstore
from hst.core import db as dbmod
from hst.core.collection_progress import read_progress
from hst.worker import collect as collect_worker

router = APIRouter(dependencies=[Depends(require_permission("runs.manage"))])
_session = dbmod.session  # Tests replace this name.


class RunBody(BaseModel):
    source: str


def _json(r: Run) -> dict:
    return {
        "id": r.id,
        "source": r.source,
        "status": r.status,
        "started_at": r.started_at.isoformat(),
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "detail": r.detail,
        # The field is null for a cron run and a reasoner run.
        "triggered_by": r.triggered_by,
    }


async def _enqueue(store: Store, settings: Settings, source: str, user: User) -> dict:
    """With RUN_EXECUTION=queue, enqueue a `collect.run` job for the run. The run
    row appears when an executor claims the job and starts it."""
    if source == runs_exec.DEVICE_RUN and not await asyncio.to_thread(rawstore.parked, settings.raw_dir):
        raise HTTPException(409, detail="no payloads are parked for a device run")
    if await live_run(store, source) is not None:
        raise HTTPException(409, detail=f"{source} is already running")
    job = await collect_worker.enqueue_run(store, source, user.id)
    if job is None:
        pending = next(
            (j for j in await store.pending_jobs(collect_worker.RUN_KIND) if j.source == source),
            None,
        )
        if pending is None:
            raise HTTPException(409, detail=f"{source} is already queued")
        if pending.state == "queued":
            raise HTTPException(409, detail=f"{source} is already queued (job {pending.id})")
        raise HTTPException(409, detail=f"job {pending.id} for {source} is running")
    return {
        "job_id": job.id,
        "kind": job.kind,
        "source": job.source,
        "status": "queued",
        "enqueued_at": job.enqueued_at.isoformat(),
    }


@router.post("/runs", status_code=202)
async def trigger(request: Request, body: RunBody, user: User = Depends(current_user)) -> dict:
    """Start a run of one source, a cycle, the reasoner or a device run. On a demo instance
    (HST_DEMO_FIXTURES) the source `demo` starts the demo estate load and needs the admin role.

    With RUN_EXECUTION=inline (the default) the run starts in this process and
    the answer is its row. With RUN_EXECUTION=queue the answer is the queued
    `collect.run` job (`job_id`, `kind`, `source`, `status` "queued",
    `enqueued_at`), and the run starts in the process that claims it."""
    store = request.app.state.store
    settings = request.app.state.settings
    if runs_exec.is_demo(settings, body.source):
        if not demo_estate.allowed(user.role):
            raise HTTPException(403, detail="loading the demo estate needs the admin role")
    elif body.source not in runs_exec.PSEUDO_SOURCES:
        row = await store.get_source(body.source)
        if row is None:
            valid = await runs_exec.valid_sources(store)
            raise HTTPException(400, detail=f"unknown source {body.source!r} (try: {', '.join(valid)})")
        if not row.enabled:
            raise HTTPException(409, detail=f"{body.source} is disabled")
    if settings.run_execution == "queue":
        return await _enqueue(store, settings, body.source, user)
    run = await runs_exec.launch(store, settings, body.source, user.id)
    if run is None:
        raise HTTPException(409, detail=f"{body.source} is already running")
    return _json(run)


class CancelBody(BaseModel):
    """`source` names one source of a cycle or a refresh to stop. An absent `source` stops the run."""

    source: str | None = None


@router.post("/runs/{run_id}/cancel")
async def cancel(
    request: Request,
    response: Response,
    run_id: int,
    user: User = Depends(current_user),
    body: CancelBody | None = None,
) -> dict:
    """Stop a running run, or one source of it.

    Without `source`, the builder ends before the load of its next device or at
    its next phase boundary. A load in flight ends between its stages or between
    the row groups of its side tables. A collector ends at its next request or
    command. Nothing that the run wrote is published, and the row finishes as
    `cancelled`.

    With `source`, the collectors of that source end at their next request or
    command. Its devices that are not loaded yet carry forward from the previous
    cycle, and the rest of the run finishes and publishes. The run row is not
    cancelled. A source refresh collects one source. A cancel of that source
    ends the refresh with nothing published, and the row finishes as `cancelled`.
    A device run is cancelled only as a whole.

    The answer is 200 with status `cancelled` when this process executes the run.
    It is 202 with status `cancelling` when another process executes it (`hst
    worker`, another replica, `hst cycle`). A request file is then written, and
    that process takes it. It is 404 when no running row has this id, when the
    row reads running with no process executing it (the row is then closed as
    orphaned), or when the run is not collecting that source. It is 409 when this
    process executes the run and the run is built. A run is built when the pointer
    names it or its builder has returned, and it finishes as built. It is 503 when
    the request file cannot be written."""
    source = body.source if body else None
    try:
        answer = await runs_exec.request_cancel(
            request.app.state.store, request.app.state.settings, run_id, by=user.username, source=source
        )
    except OSError as exc:
        raise HTTPException(
            503, detail=f"the cancel request for run {run_id} could not be written: {exc.strerror or exc}"
        ) from exc
    if answer == "built":
        raise HTTPException(409, detail=f"run {run_id} has finished building and can no longer be cancelled")
    if answer == "not_running" and not source:
        raise HTTPException(404, detail=f"run {run_id} is not running on this instance")
    if answer in ("not_running", "not_collecting_here"):
        raise HTTPException(404, detail=f"run {run_id} is not collecting {source} on this instance")
    if answer == "not_collecting":
        raise HTTPException(404, detail=f"run {run_id} is not collecting {source}")
    status = runs_exec.CANCELLED
    if answer == "requested":
        response.status_code = 202
        status = "cancelling"
    if source:
        return {"id": run_id, "source": source, "status": status}
    return {"id": run_id, "status": status}


@router.get("/runs")
async def history(request: Request, limit: int = Query(50, ge=1, le=200)) -> dict:
    """The sources that a run can be triggered for, the newest `limit` runs, and
    `pending_runs`. `pending_runs` holds every `collect.run` job that is queued
    or running, as GET /api/jobs lists a job. A queued run has no row until an
    executor claims its job. `limit` does not apply to `pending_runs`."""
    store = request.app.state.store
    runs = await store.list_runs(limit=limit)
    rows = []
    for run in runs:
        row = _json(run)
        if run.status == "running":
            progress = await asyncio.to_thread(
                read_progress,
                request.app.state.settings,
                source=None if run.source == "cycle" else run.source,
                since_ms=int(run.started_at.timestamp() * 1000),
            )
            if progress:
                row["progress"] = progress
        rows.append(row)
    return {
        "sources": await runs_exec.valid_sources(store),
        # On a demo instance the Runs page offers the demo estate load (app/demo_estate.py).
        "demo": demo_estate.folder(request.app.state.settings) is not None,
        "runs": rows,
        "pending_runs": [job_json(job) for job in await store.pending_jobs(collect_worker.RUN_KIND)],
    }


@router.get("/runs/http-traces")
async def http_traces(request: Request) -> dict:
    """The sealed HTTP exchange traces on disk (collectors/http_trace.py), newest
    first. A trace exists for a fetch whose source `HST_HTTP_TRACE` named."""
    settings = request.app.state.settings
    found = await asyncio.to_thread(rawstore.traces, settings.raw_dir)
    return {
        "enabled": settings.hst_http_trace,
        "traces": [
            {
                "source": t.source,
                "host": t.host,
                "run_id": t.run_id,
                "fetch_ts_ms": t.fetch_ts_ms,
                "size": t.size,
            }
            for t in found
        ],
    }


@router.get("/runs/http-traces/{run_id}")
async def http_trace(
    request: Request, run_id: str, source: str, host: str = "", user: User = Depends(current_user)
) -> Response:
    """One trace, decrypted, as JSON lines. `source` and `host` are the path
    segments from the listing. The file path needs them beside the run id."""
    settings = request.app.state.settings
    raw_dir = settings.raw_dir.resolve()
    path = (raw_dir / source / host / f"{run_id}{rawstore.TRACE_SUFFIX}").resolve()
    if not path.is_relative_to(raw_dir) or not path.is_file():
        raise HTTPException(404, detail="no such trace")
    # The trace is redacted. A failed record does not stop the download.
    await evidence_exports.record(
        request, user, kind="http_trace", raw_mode=None, source=source, host=host, run_id=run_id, payloads=1
    )
    body = await asyncio.to_thread(rawstore.read_trace, path, crypto.dek(settings))
    return Response(
        content=body,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{run_id}.http.jsonl"'},
    )


@router.post("/graph/purge", dependencies=[Depends(require_permission("graph.purge"))])
async def purge_graph(request: Request) -> dict:
    """Delete every node and relationship in the twin graph.

    The schema (constraints and indexes) and the Postgres data (users, sources,
    run history) stay. The parquet side store is not touched. The next
    collection has no parent run, and the HST map timeline starts again at it.
    The route holds the cycle lock for the delete. It refuses while a
    collection is running or while another holder has the lock.
    """
    store = request.app.state.store
    settings = request.app.state.settings

    def wipe() -> int:
        with _session(settings) as s:
            row = s.run("MATCH (n) RETURN count(n) AS c").single()
            count = int(row["c"]) if row else 0
            # IN TRANSACTIONS requires the auto-commit transaction that session.run opens.
            s.run("MATCH (n) CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS")
            return count

    # A builder takes the cycle lock after it claims its run row. A run that
    # starts after the check of the running rows waits for the delete.
    async with store.try_cycle_lock() as locked:
        running = await store.running_runs()
        if running and await store.reconcile_orphaned_runs(datetime.now(UTC)):
            # A row that no process holds a claim on is not a collection (`live_run`).
            running = await store.running_runs()
        if running:
            raise HTTPException(
                409, detail=f"a collection is running: run {running[0].id} ({running[0].source})"
            )
        if not locked:
            raise HTTPException(409, detail="a collection or a prune holds the cycle lock")
        deleted = await asyncio.to_thread(wipe)
    return {"deleted_nodes": deleted}
