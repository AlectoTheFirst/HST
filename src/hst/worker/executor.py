"""The embedded executor claims jobs, runs them and reports their outcomes."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from hst.app.store import Job, Store
from hst.core import Settings
from hst.worker import queue
from hst.worker.maintenance import BODIES, Context, JobBody

log = logging.getLogger(__name__)

CONCURRENCY = 2

# How often the loop wakes to claim, heartbeat and reap.
POLL_S = 5.0

# The detail of a job whose body returns an empty text.
NO_DETAIL = "done"


def worker_id() -> str:
    """A name for this executor, for the `claimed_by` column."""
    return f"{os.uname().nodename}/{uuid.uuid4().hex[:8]}"


async def _outlast(future: asyncio.Future[Any]) -> None:
    """Wait until `future` is done, and clear each cancellation of the caller
    that arrives in the meantime."""
    current = asyncio.current_task()
    while not future.done():
        try:
            await asyncio.wait({future})
        except asyncio.CancelledError:
            if current is not None:
                current.uncancel()


class Executor:
    """The executor claims and runs jobs. A test passes `clock` and `sleep` to
    drive it.

    `kind_limits` maps a kind to the maximum count of its jobs that run in this
    executor at once."""

    def __init__(
        self,
        store: Store,
        settings: Settings,
        *,
        bodies: dict[str, JobBody] | None = None,
        name: str | None = None,
        concurrency: int = CONCURRENCY,
        kind_limits: Mapping[str, int] | None = None,
        poll_s: float = POLL_S,
        lease: timedelta = queue.LEASE,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        self._bodies = BODIES if bodies is None else bodies
        self._name = name or worker_id()
        self._concurrency = concurrency
        self._kind_limits = dict(kind_limits or {})
        self._poll_s = poll_s
        self._lease = lease
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sleep = sleep or asyncio.sleep
        self._running: dict[int, asyncio.Task[None]] = {}
        # The kind of every job in `_running`, for `kind_limits`.
        self._kinds: dict[int, str] = {}
        # The jobs that this executor cancelled after it lost their lease. A
        # job stays in `_running` until its task ends and `_harvest` removes
        # it. `_cancel_lost` skips a job in this set.
        self._losing: set[int] = set()

    @property
    def name(self) -> str:
        return self._name

    async def _execute(self, job: Job) -> None:
        """Run the body of one job and record the outcome. An exception of the
        body becomes the detail of a failed attempt. A cancellation is raised."""
        ctx = Context(store=self._store, settings=self._settings)
        body = self._bodies.get(job.kind)
        if body is None:
            log.warning("job %s has kind %r, which this executor cannot run", job.id, job.kind)
            await self._store.finish_job(
                job.id,
                "error",
                f"no executor registered for kind {job.kind!r}",
                self._clock(),
            )
            return
        try:
            detail = await body(ctx, job)
        except asyncio.CancelledError:
            # The row stays running until reap requeues it.
            raise
        except Exception as exc:
            # The detail holds no traceback.
            detail = f"{type(exc).__name__}: {exc}"
            log.warning("job %s (%s) failed: %s", job.id, job.kind, detail, exc_info=exc)
            await self._finish(job, ok=False, detail=detail)
            return
        await self._finish(job, ok=True, detail=detail or NO_DETAIL)

    async def _finish(self, job: Job, *, ok: bool, detail: str) -> None:
        try:
            await queue.finish(self._store, job, ok=ok, detail=detail, now=self._clock())
        except Exception:
            log.exception("job %s (%s): the end state could not be written", job.id, job.kind)

    def _harvest(self) -> None:
        for job_id, task in list(self._running.items()):
            if task.done():
                del self._running[job_id]
                self._kinds.pop(job_id, None)
                self._losing.discard(job_id)

    def _start(self, claimed: list[Job]) -> None:
        loop = asyncio.get_running_loop()
        for job in claimed:
            self._kinds[job.id] = job.kind
            self._running[job.id] = loop.create_task(self._execute(job))

    async def _claim(self, batch: int, now: datetime, skip_kinds: list[str]) -> list[Job]:
        """Claim up to `batch` jobs, none of a kind in `skip_kinds`, and start
        the work for each.

        The claim is shielded. When a cancellation arrives during the claim,
        `_claim` waits for the claim to end, starts every claimed job and
        yields to the event loop once. Each body has then started when `run`
        cancels it. `_claim` then raises the cancellation."""
        claiming = asyncio.ensure_future(
            queue.claim(self._store, self._name, batch, now=now, lease=self._lease, skip_kinds=skip_kinds)
        )
        try:
            claimed = await asyncio.shield(claiming)
        except asyncio.CancelledError:
            await _outlast(claiming)
            if not claiming.cancelled() and claiming.exception() is None:
                self._start(claiming.result())
                await _outlast(asyncio.ensure_future(asyncio.sleep(0)))
            raise
        self._start(claimed)
        return claimed

    def _cancel_lost(self, extended: list[int]) -> None:
        """Stop the work for every job this executor no longer holds."""
        held = set(extended)
        for job_id, task in self._running.items():
            if job_id in held or job_id in self._losing or task.done():
                continue
            log.warning("job %s: the lease could not be extended; cancelling the work for it", job_id)
            self._losing.add(job_id)
            task.cancel()

    async def poll(self) -> list[Job]:
        """Run one pass of reap, heartbeat, claim and start. The result is the
        list of claimed jobs."""
        self._harvest()
        now = self._clock()
        await queue.reap(self._store, now)
        if self._running:
            extended = await queue.heartbeat(
                self._store, list(self._running), self._name, now=now, lease=self._lease
            )
            self._cancel_lost(extended)
        free = self._concurrency - len(self._running)
        claimed: list[Job] = []
        while free > 0:
            running = Counter(self._kinds.values())
            full = sorted(kind for kind, most in self._kind_limits.items() if running[kind] >= most)
            # While a limited kind is below its limit, each claim takes one
            # job. A larger claim could take more jobs of that kind than the
            # limit allows.
            batch = free if len(full) == len(self._kind_limits) else 1
            got = await self._claim(batch, now, full)
            claimed += got
            free -= len(got)
            if len(got) < batch:
                break
        return claimed

    async def drain(self) -> None:
        """Wait until every running job has ended. Tests call it."""
        while self._running:
            await asyncio.gather(*self._running.values(), return_exceptions=True)
            self._harvest()

    async def run(self) -> None:
        """Poll until cancelled."""
        log.info("executor %s started (concurrency %d)", self._name, self._concurrency)
        try:
            while True:
                try:
                    await self.poll()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning(
                        "executor poll failed (%s: %s); retrying next poll",
                        type(exc).__name__,
                        exc,
                    )
                await self._sleep(self._poll_s)
        finally:
            # Reap requeues each cancelled job on the next start.
            for task in self._running.values():
                task.cancel()
            if self._running:
                await asyncio.gather(*self._running.values(), return_exceptions=True)
            self._running.clear()
            self._kinds.clear()
            self._losing.clear()
