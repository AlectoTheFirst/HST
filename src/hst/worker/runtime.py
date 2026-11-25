"""`hst worker` runs the scheduler and the job executor in a process of their own.

The API process runs both loops in its lifespan (app/main.py) while
SCHEDULER_ENABLED is true. This module runs the same two loops without the HTTP
server. Every job then executes under the memory limit of this process. The
jobs are maintenance, scheduled cycles, per-device fetches, device runs, and
the runs and debug re-parses that the API queues for an operator
(RUN_EXECUTION=queue, worker/collect.py `collect.run`, app/debug_reparse.py
`debug.reparse`).

This module imports no FastAPI module. The store, the inventory startup and
the debug re-parse are imported inside the functions that use them.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from hst.core import Settings
from hst.worker import collect, maintenance
from hst.worker.executor import Executor
from hst.worker.maintenance import JobBody
from hst.worker.scheduler import SYSTEM_SCHEDULES, Schedule, Scheduler

log = logging.getLogger(__name__)

# How long first contact with Postgres is retried before the process gives up.
STARTUP_DEADLINE_S = 90

# How long the worker waits before it enters the scheduler loop again after an
# error ended it. The executor keeps claiming in the meantime.
SCHEDULER_RESTART_S = 30.0


async def open_store(settings: Settings) -> Any:
    """Run the migrations when `hst_run_migrations` is set, open the store,
    close the orphaned runs and purge the expired sessions and login states.

    A failed attempt is retried until `STARTUP_DEADLINE_S` has passed.
    """
    from hst.app.security import idle_after
    from hst.app.store.pg import PgStore, upgrade_to_head

    deadline = time.monotonic() + STARTUP_DEADLINE_S
    store = None
    while True:
        try:
            if settings.hst_run_migrations:
                await asyncio.to_thread(upgrade_to_head, settings.postgres_dsn, settings.postgres_ca_file)
            store = PgStore(settings.postgres_dsn, settings.postgres_ca_file)
            # `reconcile_orphaned_runs` try-locks the run claim of each stranded source.
            now = datetime.now(UTC)
            await store.reconcile_orphaned_runs(now)
            await store.purge_expired_sessions(now, idle_after(settings))
            await store.purge_expired_auth_state(now)
            return store
        except Exception as exc:
            if store is not None:
                await store.dispose()
                store = None
            if time.monotonic() >= deadline:
                raise
            log.warning("postgres not ready (%s: %s); retrying", type(exc).__name__, exc)
            await asyncio.sleep(2)


def bodies() -> dict[str, JobBody]:
    """The body of every job kind that an executor runs. The kinds are the
    maintenance kinds, the 3 collection kinds and the debug re-parse."""
    from hst.app import debug_reparse

    registry = dict(maintenance.BODIES)
    # The collect bodies are registered whether or not a cadence is configured.
    registry[collect.KIND] = collect.collect_cycle_body
    registry[collect.FETCH_KIND] = collect.collect_fetch_body
    registry[collect.RUN_KIND] = collect.collect_run_body
    # The API queues a re-parse with RUN_EXECUTION=queue (app/debug_reparse.py).
    registry[debug_reparse.KIND] = debug_reparse.reparse_body
    return registry


def build_loops(store: Any, settings: Settings) -> tuple[Scheduler, Executor]:
    """The scheduler and the executor, as the API and `hst worker` both run them."""
    from hst.app import debug_reparse

    # The cycle schedule exists only when a cadence is configured
    # (COLLECT_INTERVAL_S > 0).
    schedules = list(SYSTEM_SCHEDULES)
    if settings.collect_interval_s > 0:
        schedules.append(Schedule(collect.KIND, float(settings.collect_interval_s)))
    # Fan-out enqueues nothing until a group config sets interval_s.
    scheduler = Scheduler(store, settings, schedules=schedules, collect_fanout=True)
    executor = Executor(
        store,
        settings,
        bodies=bodies(),
        concurrency=settings.collect_worker_concurrency,
        kind_limits={debug_reparse.KIND: debug_reparse.MAX_CHILDREN},
    )
    return scheduler, executor


async def keep_scheduling(
    scheduler: Scheduler,
    *,
    restart_s: float = SCHEDULER_RESTART_S,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Run the scheduler loop, and enter it again after an error ends it.

    The scheduler survives a failed tick on its own, but an error while it
    stands by or takes leadership (Postgres gone) ends its loop.
    """
    while True:
        try:
            await scheduler.run()
        except Exception as exc:
            log.warning(
                "scheduler stopped (%s: %s); starting it again in %.0f s",
                type(exc).__name__,
                exc,
                restart_s,
            )
            await sleep(restart_s)
        else:
            return


async def _unless_stopped(work: Awaitable[Any], stop: asyncio.Event) -> tuple[bool, Any]:
    """(True, what `work` returned), or (False, None) when `stop` is set first,
    in which case `work` is cancelled. A stop during the startup ends the
    process at once."""
    running = asyncio.ensure_future(work)
    stopping = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait({running, stopping}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stopping.cancel()
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
    if running.cancelled():
        return False, None
    return True, running.result()


async def _open_unless_stopped(settings: Settings, stop: asyncio.Event) -> Any | None:
    """`open_store`, or None when `stop` is set first. A stop during the startup
    retries ends the process at once."""
    _opened, store = await _unless_stopped(open_store(settings), stop)
    return store


async def run(settings: Settings, *, stop: asyncio.Event, store: Any = None) -> None:
    """Run the scheduler and the executor until `stop` is set.

    The call opens the store unless one is given, and disposes only a store
    that it opened. The inventory startup runs first and registers the
    observation service before any job can publish. A stop during the opening
    of the store or during the inventory startup returns before any loop
    starts. A loop that ends on its own ends this call with its exception, or
    with a RuntimeError when it has none. On return the loops are cancelled.
    The executor cancels the jobs that it runs, and each run that it executes
    finishes its row as cancelled.
    """
    owns_store = store is None
    if store is None:
        store = await _open_unless_stopped(settings, stop)
        if store is None:
            return
    loops: list[asyncio.Task[None]] = []
    try:
        from hst.app.inventory.startup import start_for

        started, _ = await _unless_stopped(start_for(store, settings), stop)
        if not started or stop.is_set():
            return
        scheduler, executor = build_loops(store, settings)
        loops = [
            asyncio.create_task(keep_scheduling(scheduler), name="scheduler"),
            asyncio.create_task(executor.run(), name="executor"),
        ]
        stopping = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait({stopping, *loops}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            stopping.cancel()
        for task in loops:
            if task in done:
                error = task.exception()
                if error is not None:
                    raise error
                raise RuntimeError(f"the {task.get_name()} loop ended")
    finally:
        for task in loops:
            task.cancel()
        if loops:
            await asyncio.gather(*loops, return_exceptions=True)
        if owns_store:
            await store.dispose()


def main(settings: Settings) -> None:
    """Run until SIGTERM or SIGINT, then stop the loops and return."""

    async def _main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stop.set)
        await run(settings, stop=stop)

    asyncio.run(_main())
