"""What an executor claims: no more of a limited kind than its limit, and
every job a claim takes gets its body, even when the executor is stopped
while the claim runs. And what `hst worker` does when it is stopped during
its inventory startup."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.app.fakes import FakeStore

from hst.app.crypto import generate_key
from hst.core import Settings
from hst.worker import queue, runtime
from hst.worker.executor import Executor

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **overrides)


async def _queue(store: FakeStore, kind: str, *, priority: int = 0, max_attempts: int = 1) -> Any:
    job = await store.enqueue_job(
        kind, priority=priority, not_before=NOW, max_attempts=max_attempts, triggered_by="test", now=NOW
    )
    assert job is not None
    return job


# --- kind limits ------------------------------------------------------------------------


async def test_a_limited_kind_is_claimed_up_to_its_limit_and_the_rest_waits_queued() -> None:
    store = FakeStore()
    # distinct sources, so the one-pending-per-kind rule does not shed any
    reparses = [
        await store.enqueue_job(
            "debug.reparse",
            source=f"s{i}",
            priority=1,
            not_before=NOW,
            max_attempts=1,
            triggered_by="t",
            now=NOW,
        )
        for i in range(3)
    ]
    sweep = await _queue(store, "maintenance.sweep")
    gates = {job.id: asyncio.Event() for job in [*reparses, sweep]}
    started: list[int] = []

    async def body(ctx: Any, job: Any) -> str:
        started.append(job.id)
        await gates[job.id].wait()
        return "done"

    ex = Executor(
        store,
        _settings(),
        bodies={"debug.reparse": body, "maintenance.sweep": body},
        name="worker-under-test",
        concurrency=3,
        kind_limits={"debug.reparse": 1},
    )

    first = await ex.poll()
    assert [job.id for job in first] == [reparses[0].id, sweep.id]
    assert [store.jobs[job.id].state for job in reparses[1:]] == ["queued", "queued"]
    # a free slot, and the limited kind at its limit: nothing is claimed
    assert await ex.poll() == []

    gates[reparses[0].id].set()
    for _ in range(100):
        if store.jobs[reparses[0].id].state == "ok":
            break
        await asyncio.sleep(0)
    second = await ex.poll()
    assert [job.id for job in second] == [reparses[1].id]
    assert store.jobs[reparses[2].id].state == "queued"

    for gate in gates.values():
        gate.set()
    await ex.drain()


async def test_without_limits_one_claim_takes_every_free_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    store = FakeStore()
    for index in range(4):
        await store.enqueue_job(
            "work", source=f"s{index}", not_before=NOW, max_attempts=1, triggered_by="t", now=NOW
        )
    batches: list[int] = []
    real = queue.claim

    async def counting(store: Any, worker_id: str, batch: int = 1, **kwargs: Any) -> Any:
        batches.append(batch)
        return await real(store, worker_id, batch, **kwargs)

    monkeypatch.setattr(queue, "claim", counting)

    async def body(ctx: Any, job: Any) -> str:
        return "done"

    ex = Executor(store, _settings(), bodies={"work": body}, name="worker-under-test", concurrency=3)
    assert len(await ex.poll()) == 3
    assert batches == [3]
    await ex.drain()


# --- a stop during a claim --------------------------------------------------------------


class _SlowClaims(FakeStore):
    """A store whose claim waits for `release` once it has been entered."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def claim_jobs(self, worker_id: str, batch: int, now: datetime, lease: Any, **kwargs: Any) -> Any:
        self.entered.set()
        await self.release.wait()
        return await super().claim_jobs(worker_id, batch, now, lease, **kwargs)


async def test_a_job_claimed_while_the_executor_stops_gets_its_body_and_is_finished_by_it() -> None:
    store = _SlowClaims()
    job = await _queue(store, "collect.run")
    started: list[int] = []

    async def body(ctx: Any, j: Any) -> str:
        started.append(j.id)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await queue.finish(ctx.store, j, ok=True, detail="stopped before the run started")
            raise
        return "never"

    ex = Executor(store, _settings(), bodies={"collect.run": body}, name="worker-under-test")
    loop = asyncio.create_task(ex.run())
    await asyncio.wait_for(store.entered.wait(), 10)
    loop.cancel()
    await asyncio.sleep(0)
    store.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(loop, 10)

    assert started == [job.id]
    row = store.jobs[job.id]
    assert (row.state, row.detail) == ("ok", "stopped before the run started")


async def test_a_claim_that_fails_while_the_executor_stops_ends_the_stop_alone() -> None:
    store = _SlowClaims()

    async def failing(*args: Any, **kwargs: Any) -> Any:
        store.entered.set()
        await store.release.wait()
        raise ConnectionError("postgres gone")

    store.claim_jobs = failing  # type: ignore[method-assign]
    ex = Executor(store, _settings(), bodies={}, name="worker-under-test")
    loop = asyncio.create_task(ex.run())
    await asyncio.wait_for(store.entered.wait(), 10)
    loop.cancel()
    await asyncio.sleep(0)
    store.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(loop, 10)
    assert ex._running == {}


# --- a stop during the worker's startup ------------------------------------------------


@pytest.fixture
def settings(tmp_path: Any) -> Settings:
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)


async def test_a_stop_during_the_inventory_startup_returns_before_any_loop_starts(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hst.app.inventory import startup

    entered = asyncio.Event()
    abandoned: list[bool] = []
    built: list[bool] = []

    async def slow_start(store: Any, settings: Any) -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            abandoned.append(True)

    def build_loops(store: Any, settings: Any) -> Any:
        built.append(True)
        raise AssertionError("the loops were built after the stop")

    monkeypatch.setattr(startup, "start_for", slow_start)
    monkeypatch.setattr(runtime, "build_loops", build_loops)
    stop = asyncio.Event()
    task = asyncio.create_task(runtime.run(settings, stop=stop, store=FakeStore()))
    await asyncio.wait_for(entered.wait(), 10)
    stop.set()

    assert await asyncio.wait_for(task, 10) is None
    assert abandoned == [True]
    assert built == []


async def test_a_stop_set_as_the_inventory_startup_ends_starts_no_loop(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hst.app.inventory import startup

    stop = asyncio.Event()
    built: list[bool] = []

    async def start_then_stop(store: Any, settings: Any) -> None:
        stop.set()

    def build_loops(store: Any, settings: Any) -> Any:
        built.append(True)
        raise AssertionError("the loops were built after the stop")

    monkeypatch.setattr(startup, "start_for", start_then_stop)
    monkeypatch.setattr(runtime, "build_loops", build_loops)

    assert await asyncio.wait_for(runtime.run(settings, stop=stop, store=FakeStore()), 10) is None
    assert built == []
