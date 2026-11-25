"""The executor: claim, run, report, and survive."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.fakes import FakeStore

from hst.core import Settings
from hst.worker import queue
from hst.worker.executor import Executor

# A job queued at NOW is due to an executor running on the real clock.
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def _queue(store, kind="work", *, max_attempts=3, at=NOW):
    return await store.enqueue_job(
        kind,
        not_before=at,
        max_attempts=max_attempts,
        triggered_by="scheduler",
        now=at,
    )


def _executor(store, bodies, **kwargs) -> Executor:
    return Executor(store, _settings(), bodies=bodies, name="worker-under-test", **kwargs)


async def test_a_job_body_runs_and_its_answer_lands_on_the_row():
    store = FakeStore()
    job = await _queue(store)
    seen = []

    async def body(ctx, j):
        seen.append((ctx.store is store, j.id, j.attempt))
        return "deleted 3 things"

    ex = _executor(store, {"work": body})
    await ex.poll()
    await ex.drain()

    assert seen == [(True, job.id, 1)]
    row = store.jobs[job.id]
    assert (row.state, row.detail) == ("ok", "deleted 3 things")
    assert row.finished_at is not None and row.claimed_by is None


async def test_a_body_that_says_nothing_records_something():
    store = FakeStore()
    job = await _queue(store)

    async def body(ctx, j):
        return ""

    ex = _executor(store, {"work": body})
    await ex.poll()
    await ex.drain()
    assert store.jobs[job.id].detail == "done"


async def test_a_failing_body_records_the_exception_and_the_executor_survives():
    store = FakeStore()
    await _queue(store, "boom", max_attempts=1)
    await _queue(store, "fine", max_attempts=1)
    ran = []

    async def boom(ctx, j):
        raise RuntimeError("twin unreachable")

    async def fine(ctx, j):
        ran.append(j.kind)
        return "ok"

    ex = _executor(store, {"boom": boom, "fine": fine}, concurrency=2)
    await ex.poll()
    await ex.drain()

    failed = next(j for j in store.jobs.values() if j.kind == "boom")
    # max_attempts of 1 does not retry
    assert failed.state == "error"
    assert failed.detail == "RuntimeError: twin unreachable"
    assert failed.finished_at is not None
    assert ran == ["fine"]  # the other job on the same poll was unaffected

    # and the loop keeps claiming afterwards
    await _queue(store, "fine2", max_attempts=1)
    ex2 = _executor(store, {"fine2": fine})
    await ex2.poll()
    await ex2.drain()
    assert ran == ["fine", "fine2"]


async def test_a_failing_body_with_attempts_left_is_requeued_with_backoff(monkeypatch):
    monkeypatch.setattr(queue, "BACKOFF_BASE_S", 60.0)
    store = FakeStore()
    job = await _queue(store, "boom", max_attempts=3)

    async def boom(ctx, j):
        raise ValueError("transient")

    ex = _executor(store, {"boom": boom}, clock=lambda: NOW)
    await ex.poll()
    await ex.drain()

    row = store.jobs[job.id]
    assert (row.state, row.attempt, row.detail) == ("queued", 1, "ValueError: transient")
    assert row.finished_at is None
    assert row.not_before == NOW + timedelta(seconds=60)


async def test_a_body_that_keeps_failing_reaches_a_dead_row(monkeypatch):
    monkeypatch.setattr(queue, "BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(queue, "BACKOFF_CAP_S", 0.0)
    store = FakeStore()
    job = await _queue(store, "boom", max_attempts=3)
    attempts = 0

    async def boom(ctx, j):
        nonlocal attempts
        attempts += 1
        raise ValueError("still broken")

    ex = _executor(store, {"boom": boom})
    for _ in range(4):
        await ex.poll()
        await ex.drain()

    row = store.jobs[job.id]
    assert attempts == 3
    assert (row.state, row.attempt) == ("dead", 3)
    assert row.detail == "ValueError: still broken"


async def test_a_kind_with_no_registered_body_is_recorded_not_retried():
    store = FakeStore()
    job = await _queue(store, "unknown.kind", max_attempts=4)

    ex = _executor(store, {})
    await ex.poll()
    await ex.drain()

    row = store.jobs[job.id]
    assert row.state == "error"
    assert row.finished_at is not None
    assert "no executor registered" in row.detail


async def test_concurrency_is_bounded():
    store = FakeStore()
    for i in range(5):
        await _queue(store, f"work{i}")
    gate = asyncio.Event()
    live = 0
    peak = 0

    async def body(ctx, j):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await gate.wait()
        live -= 1
        return "ok"

    ex = _executor(store, {f"work{i}": body for i in range(5)}, concurrency=2)
    claimed = await ex.poll()
    assert len(claimed) == 2
    await asyncio.sleep(0)  # let the two bodies reach their gate
    assert peak == 2
    # a second poll while both are still running claims nothing more
    assert await ex.poll() == []
    gate.set()
    await ex.drain()
    assert len(await ex.poll()) == 2


async def test_running_jobs_are_heartbeated_while_they_work():
    store = FakeStore()
    job = await _queue(store)
    gate = asyncio.Event()

    async def body(ctx, j):
        await gate.wait()
        return "ok"

    clock = {"at": NOW}
    ex = _executor(store, {"work": body}, clock=lambda: clock["at"], lease=timedelta(minutes=5))
    await ex.poll()
    first_lease = store.jobs[job.id].lease_expires_at

    clock["at"] = NOW + timedelta(minutes=4)
    await ex.poll()
    assert store.jobs[job.id].lease_expires_at > first_lease
    assert store.jobs[job.id].state == "running"  # not reaped

    gate.set()
    await ex.drain()


async def test_a_job_whose_heartbeat_is_refused_is_cancelled_not_finished():
    store = FakeStore()
    job = await _queue(store)
    started = asyncio.Event()
    cancelled: list[int] = []

    async def body(ctx, j):
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(j.id)
            raise
        return "finished after all"

    clock = {"at": NOW}
    ex = _executor(store, {"work": body}, clock=lambda: clock["at"], lease=timedelta(minutes=5))
    await ex.poll()
    await started.wait()

    # this executor stalls past its lease: the job is reaped and worker-b takes
    # the attempt that replaces it
    clock["at"] = NOW + timedelta(minutes=6)
    assert await store.reap_jobs(clock["at"]) == 1
    await store.claim_jobs("worker-b", 1, clock["at"], timedelta(minutes=5))

    clock["at"] = NOW + timedelta(minutes=7)
    await ex.poll()
    await ex.drain()

    assert cancelled == [job.id]
    row = store.jobs[job.id]
    assert (row.state, row.claimed_by, row.attempt) == ("running", "worker-b", 2)
    assert row.finished_at is None and row.detail != "finished after all"


async def test_a_poll_reaps_a_predecessors_abandoned_claim():
    store = FakeStore()
    job = await _queue(store, "work", max_attempts=3)
    await store.claim_jobs("worker-that-died", 1, NOW, timedelta(minutes=5))
    ran = []

    async def body(ctx, j):
        ran.append(j.attempt)
        return "ok"

    ex = _executor(store, {"work": body}, clock=lambda: NOW + timedelta(minutes=6))
    await ex.poll()
    await ex.drain()

    assert ran == [2]  # the abandoned attempt counted
    assert store.jobs[job.id].state == "ok"


async def test_a_poll_that_fails_does_not_end_the_loop():
    class BrokenStore(FakeStore):
        def __init__(self):
            super().__init__()
            self.polls = 0

        async def claim_jobs(self, *a, **kw):
            self.polls += 1
            if self.polls <= 2:
                raise RuntimeError("connection reset")
            return await super().claim_jobs(*a, **kw)

    store = BrokenStore()
    job = await _queue(store)
    sleeps = 0

    async def sleep(seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 4:
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    async def body(ctx, j):
        return "ok"

    ex = _executor(store, {"work": body}, poll_s=0.0, sleep=sleep)
    with pytest.raises(asyncio.CancelledError):
        await ex.run()
    assert store.polls >= 3
    assert store.jobs[job.id].state == "ok"


async def test_shutdown_cancels_in_flight_work():
    store = FakeStore()
    job = await _queue(store)
    started = asyncio.Event()

    async def body(ctx, j):
        started.set()
        await asyncio.sleep(3600)
        return "never"

    ex = _executor(store, {"work": body}, poll_s=3600.0)
    task = asyncio.get_running_loop().create_task(ex.run())
    await asyncio.wait_for(started.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert store.jobs[job.id].state == "running"
    assert await store.reap_jobs(datetime.now(UTC) + timedelta(hours=1)) == 1
