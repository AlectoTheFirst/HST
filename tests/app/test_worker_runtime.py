"""`hst worker`'s runtime: the job registry, the two loops, startup and stop."""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import threading

import pytest
from tests.app.fakes import FakeStore
from tests.app.inventory_rig import fake_rig

import hst.app.runs_exec as runs_exec
from hst.app import debug_reparse
from hst.app.crypto import generate_key
from hst.app.inventory import collection
from hst.app.security import hash_password
from hst.core import Settings
from hst.worker import collect, maintenance, queue, runtime


@pytest.fixture(autouse=True)
def _own_run_registry(monkeypatch):
    # The run registry is process-wide and FakeStore run ids start at 1 in every
    # test, so each test gets a registry of its own.
    monkeypatch.setattr(runs_exec, "_RUNS", {})


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)


async def _wait_for(predicate, give_up_after: float = 10.0) -> bool:
    # a polling budget, not a cancellation deadline
    for _ in range(int(give_up_after / 0.01)):
        if await predicate():
            return True
        await asyncio.sleep(0.01)
    return False


def test_bodies_add_the_collection_kinds_and_the_debug_reparse_and_leave_the_registries_alone():
    bodies = runtime.bodies()
    assert set(bodies) == set(maintenance.BODIES) | {
        collect.KIND,
        collect.FETCH_KIND,
        collect.RUN_KIND,
        debug_reparse.KIND,
    }
    assert bodies[collect.RUN_KIND] is collect.collect_run_body
    assert bodies[debug_reparse.KIND] is debug_reparse.reparse_body
    assert collect.RUN_KIND not in maintenance.BODIES
    assert debug_reparse.KIND not in maintenance.BODIES
    assert collect.RUN_KIND in queue.LEASE_BACKOFF_KINDS


def test_build_loops_schedules_the_cycle_only_with_a_cadence(tmp_path):
    manual = Settings(_env_file=None, hst_data_dir=tmp_path, collect_worker_concurrency=3)
    scheduler, executor = runtime.build_loops(FakeStore(), manual)
    assert collect.KIND not in scheduler.kinds()
    assert executor._concurrency == 3
    assert executor._kind_limits == {debug_reparse.KIND: debug_reparse.MAX_CHILDREN}

    timed = Settings(_env_file=None, hst_data_dir=tmp_path, collect_interval_s=600)
    scheduler, _ = runtime.build_loops(FakeStore(), timed)
    assert collect.KIND in scheduler.kinds()


async def test_run_executes_queued_jobs_until_stopped_and_keeps_a_given_store(settings):
    store = FakeStore()
    disposed = []

    async def dispose():
        disposed.append(True)

    store.dispose = dispose
    # a queued run for an account that does not exist: the collect.run body
    # answers without starting anything
    job = await collect.enqueue_run(store, "reasoner", 999)
    assert job is not None
    stop = asyncio.Event()
    task = asyncio.create_task(runtime.run(settings, stop=stop, store=store))

    async def finished():
        return store.jobs[job.id].state == "ok"

    assert await _wait_for(finished), "the queued job was never run"
    assert store.jobs[job.id].detail == "skipped: collection authorization is no longer valid"
    stop.set()
    await asyncio.wait_for(task, 10)
    assert disposed == []


async def test_a_stop_during_the_startup_retries_returns_at_once(settings, monkeypatch):
    opening = asyncio.Event()
    abandoned = []

    async def never_ready(settings):
        opening.set()
        try:
            await asyncio.Event().wait()
        finally:
            abandoned.append(True)

    monkeypatch.setattr(runtime, "open_store", never_ready)
    stop = asyncio.Event()
    task = asyncio.create_task(runtime.run(settings, stop=stop))
    await asyncio.wait_for(opening.wait(), 10)
    stop.set()
    assert await asyncio.wait_for(task, 10) is None
    assert abandoned == [True]


async def test_the_scheduler_loop_is_entered_again_after_an_error(caplog):
    slept: list[float] = []

    async def sleep(seconds):
        slept.append(seconds)

    class Flaky:
        runs = 0

        async def run(self):
            self.runs += 1
            if self.runs == 1:
                raise ConnectionError("postgres went away")

    flaky = Flaky()
    with caplog.at_level(logging.WARNING, logger="hst.worker.runtime"):
        await runtime.keep_scheduling(flaky, restart_s=30.0, sleep=sleep)
    assert flaky.runs == 2
    assert slept == [30.0]
    assert "scheduler stopped (ConnectionError: postgres went away)" in caplog.text


class _Idle:
    async def run(self):
        await asyncio.Event().wait()


async def test_a_loop_that_fails_ends_run_with_its_error(settings, monkeypatch):
    class Failing:
        async def run(self):
            raise RuntimeError("executor broke")

    monkeypatch.setattr(runtime, "build_loops", lambda store, settings: (_Idle(), Failing()))
    with pytest.raises(RuntimeError, match="executor broke"):
        await asyncio.wait_for(runtime.run(settings, stop=asyncio.Event(), store=FakeStore()), 10)


async def test_a_loop_that_returns_ends_run(settings, monkeypatch):
    class Returning:
        async def run(self):
            return None

    monkeypatch.setattr(runtime, "build_loops", lambda store, settings: (_Idle(), Returning()))
    with pytest.raises(RuntimeError, match="the executor loop ended"):
        await asyncio.wait_for(runtime.run(settings, stop=asyncio.Event(), store=FakeStore()), 10)


async def test_a_stop_while_a_queued_run_executes_finishes_it_as_cancelled(settings, monkeypatch):
    store = FakeStore()
    await store.create_source("unifi", "unifi", {}, b"")
    otto = await store.create_user("otto", hash_password("correct-horse-9"), "operator")
    entered = threading.Event()

    async def fake_prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    def blocking(settings, prepared, name, assigned=None, *, stop=None, **kw):
        entered.set()
        assert stop is not None and stop.wait(10), "the stop flag was never raised"
        raise RuntimeError("stopped at a phase boundary")

    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)
    monkeypatch.setattr(runs_exec, "execute_refresh", blocking)
    job = await collect.enqueue_run(store, "unifi", otto.id)
    assert job is not None
    stop = asyncio.Event()
    task = asyncio.create_task(runtime.run(settings, stop=stop, store=store))
    assert await asyncio.to_thread(entered.wait, 10), "the run never started"

    stop.set()
    await asyncio.wait_for(task, 30)
    (run,) = await store.list_runs()
    assert (run.status, run.triggered_by) == (runs_exec.CANCELLED, otto.id)
    assert (store.jobs[job.id].state, store.jobs[job.id].detail) == ("ok", f"run {run.id} cancelled")


async def test_start_for_registers_the_observation_service(monkeypatch):
    rig = fake_rig()
    asked = []

    class Reader:
        def __init__(self, settings):
            asked.append(settings)

        async def current_snapshot(self):
            return None

    monkeypatch.setattr("hst.app.inventory.routing.Neo4jGraphReader", Reader)
    from hst.app.inventory.startup import start_for

    try:
        await start_for(rig.store, rig.ctx.settings, lambda: rig.ctx)
        context = await collection.execution_context(rig.store)
        assert context.activated  # an empty installation is activated on first start
        assert collection.observation_service(context).ctx is rig.ctx
        assert asked == [rig.ctx.settings]
    finally:
        collection.set_observation_service(None)


def test_the_worker_runtime_imports_no_fastapi():
    probe = "import sys, hst.worker.runtime; print('fastapi' in sys.modules)"
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "False"
