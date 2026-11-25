"""The collection job bodies."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime

from hst.app import demo_estate, runs_exec
from hst.app.store import Job, Run, Store, User
from hst.core import rawstore
from hst.worker import queue
from hst.worker.maintenance import Context

KIND = "collect.cycle"
FETCH_KIND = "collect.fetch"
RUN_KIND = "collect.run"
# The `triggered_by` of a queued run is this prefix and the id of the account
# that triggered the run.
RUN_TRIGGER = "runs:"
# A queued run is claimed ahead of the maintenance jobs and the per-device
# fetch jobs. They have priority 0.
RUN_PRIORITY = 1


async def _manager(store: Store, user_id: int) -> User | None:
    """The account, when it still exists, is enabled and holds runs.manage."""
    from hst.app.permissions import permissions_for

    actor = await store.get_user(user_id)
    if actor is None or actor.disabled or "runs.manage" not in permissions_for(actor.role):
        return None
    return actor


def _run_detail(run: Run) -> str:
    head = (run.detail or "").split(" · ", 1)[0]
    return f"run {run.id} {run.status}" + (f": {head}" if head and head != run.status else "")


def _outcome(run: Run) -> str:
    """The detail of a job whose run has ended, from the run's row."""
    if run.status == "running":
        # The run ended and its row was not finished. `launch` writes the row
        # when the run ends. That write failed, and `launch` logged the error.
        # The row keeps the status 'running' until the orphaned-run sweep
        # closes it. The next trigger or cancel of the source runs that sweep.
        return f"run {run.id} ended, and its outcome was not recorded"
    return _run_detail(run)


async def collect_cycle_body(ctx: Context, job: Job) -> str:
    run = await runs_exec.run_blocking(ctx.store, ctx.settings, "cycle")
    if run is None:
        return "skipped: a run already holds the cycle claim"
    return _outcome(run)


async def collect_fetch_body(ctx: Context, job: Job) -> str:
    if (
        job.triggered_by.startswith("assessment:")
        and await _manager(ctx.store, int(job.triggered_by.split(":", 1)[1])) is None
    ):
        return "skipped: collection authorization is no longer valid"
    if not job.source:
        return "skipped: job has no source"
    return await runs_exec.run_device_fetch(ctx.store, ctx.settings, job.source, job.device or "")


async def enqueue_run(store: Store, source: str, user_id: int, *, now: datetime | None = None) -> Job | None:
    """Queue one run of `source` for the account `user_id`. The result is None
    when a `collect.run` job for that source is already queued or running."""
    return await queue.enqueue(
        store,
        RUN_KIND,
        source=source,
        priority=RUN_PRIORITY,
        max_attempts=1,
        triggered_by=f"{RUN_TRIGGER}{user_id}",
        now=now,
    )


async def collect_run_body(ctx: Context, job: Job) -> str:
    """Execute one queued run and report its outcome.

    The checks of the route run again at claim time. A run that finishes with
    status error does not fail the job.

    When the body is cancelled, the run is cancelled with it, unless it is
    already built and only records its outcome (`runs_exec.wait_for_run`).
    The job is finished with the run's outcome before the cancellation goes on.
    """
    run: Run | None = None
    try:
        user_id = job.triggered_by.removeprefix(RUN_TRIGGER)
        named = user_id != job.triggered_by and user_id.isdecimal()
        actor = await _manager(ctx.store, int(user_id)) if named else None
        if actor is None:
            return "skipped: collection authorization is no longer valid"
        source = job.source
        if not source:
            return "skipped: job has no source"
        if runs_exec.is_demo(ctx.settings, source):
            if not demo_estate.allowed(actor.role):
                return "skipped: loading the demo estate needs the admin role"
        elif source not in runs_exec.PSEUDO_SOURCES:
            row = await ctx.store.get_source(source)
            if row is None:
                return f"skipped: source {source} no longer exists"
            if not row.enabled:
                return f"skipped: {source} is disabled"
        if source == runs_exec.DEVICE_RUN and not await asyncio.to_thread(
            rawstore.parked, ctx.settings.raw_dir
        ):
            return "skipped: no payloads are parked for a device run"
        run = await runs_exec.launch(ctx.store, ctx.settings, source, actor.id)
        if run is None:
            return f"skipped: {source} is already running"
        return _outcome(await runs_exec.wait_for_run(ctx.store, run))
    except asyncio.CancelledError:
        detail = "skipped: the executor stopped before the run started"
        if run is not None:
            detail = _run_detail(run)
            with contextlib.suppress(Exception):
                detail = _run_detail(await runs_exec.finished_row(ctx.store, run))
        with contextlib.suppress(Exception):
            await queue.finish(ctx.store, job, ok=True, detail=detail)
        raise
