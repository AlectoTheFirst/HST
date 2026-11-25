"""Real spawned children prove CPU isolation, bounded supervision and cancellation."""

from __future__ import annotations

import asyncio
import os
import time
from types import SimpleNamespace

from hst.assessment.jobs import AnalysisWorker
from hst.assessment.store import MemoryAssessmentStore


def succeeds(settings, inputs, *, progress, cancelled):
    progress({"evaluated": 2})
    return {"pid": os.getpid(), "verdict": "not-established", "dependencies": [{"source": "edge"}]}


def cooperates(settings, inputs, *, progress, cancelled):
    progress({"evaluated": 1})
    while not cancelled():
        time.sleep(0.01)
    return {"findings": [{"candidate": "verified-before-cancel"}], "search_complete": False}


def hangs(settings, inputs, *, progress, cancelled):
    progress({"evaluated": 1})
    while True:
        time.sleep(0.01)


def raises_sensitive_error(settings, inputs, *, progress, cancelled):
    raise RuntimeError("postgresql://private-user:do-not-expose@private-db")


async def fixture_run(store=None):
    store = store or MemoryAssessmentStore()
    saved = await store.create_assessment(title="fixture", purpose="evaluation", definition={}, created_by=1)
    run = await store.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=1,
        kind="evaluate",
        inputs={},
        snapshot_refs=[{"snapshot": "100"}],
        engine_version="fixture",
        created_by=1,
    )
    return store, run


def worker(store, execute, timeout=5):
    settings = SimpleNamespace(analysis_memory_mb=1024, analysis_timeout_s=timeout, analysis_poll_s=0.02)
    return AnalysisWorker(store, settings, execute=execute, poll_s=0.02, lease_seconds=3)


async def wait_progress(store, run_id):
    for _ in range(250):
        if (await store.get_analysis_run(run_id)).progress:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("analysis did not report progress within 5 seconds")


async def test_child_process_finishes_exact_result_and_persists_progress():
    store, run = await fixture_run()
    executor = worker(store, succeeds)
    assert await executor.run_once()
    assert not await executor.run_once()
    finished = await store.get_analysis_run(run.id)
    assert finished.state == "completed"
    assert finished.result["pid"] != os.getpid()
    assert finished.result["verdict"] == "not-established"
    assert finished.dependencies == [{"source": "edge"}]
    assert finished.progress == {"evaluated": 2}
    assert finished.result["execution"]["deadline_seconds"] == 5


async def test_cancellation_stops_child_and_preserves_verified_partial_findings():
    store, run = await fixture_run()
    task = asyncio.create_task(worker(store, cooperates).run_once())
    await wait_progress(store, run.id)
    await store.cancel_analysis(run.id)
    await asyncio.wait_for(task, 3)
    finished = await store.get_analysis_run(run.id)
    assert finished.state == "cancelled"
    assert finished.result["search_complete"] is False
    assert finished.result["stop_reason"] == "cancelled"
    assert finished.result["findings"] == [{"candidate": "verified-before-cancel"}]


async def test_absolute_deadline_terminates_noncooperative_child_and_keeps_loop_responsive():
    store, run = await fixture_run()
    ticks = 0

    async def tick():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    ticker = asyncio.create_task(tick())
    try:
        await asyncio.wait_for(worker(store, hangs, timeout=0.2).run_once(), 3)
    finally:
        ticker.cancel()
        await asyncio.gather(ticker, return_exceptions=True)
    finished = await store.get_analysis_run(run.id)
    assert finished.state == "failed"
    assert finished.result["stop_reason"] == "time-limit"
    assert ticks >= 5


async def test_child_exception_text_cannot_reach_saved_result():
    store, run = await fixture_run()
    await worker(store, raises_sensitive_error).run_once()
    finished = await store.get_analysis_run(run.id)
    assert finished.state == "failed"
    assert "do-not-expose" not in str(finished.as_dict())
    assert "private-db" not in str(finished.as_dict())
    assert finished.result["stop_reason"] == "execution-failed"
    runtime_exception = finished.result.get("runtime_exception")
    assert runtime_exception is not None
    assert runtime_exception["kind"] == "RuntimeError"
    assert runtime_exception["file"] == "test_assessment_jobs.py"
    assert runtime_exception["function"] == "raises_sensitive_error"
    assert isinstance(runtime_exception["line"], int)
    assert runtime_exception["line"] > 30


async def test_shutdown_kills_child_and_leaves_lease_for_restart():
    store, run = await fixture_run()
    executor = worker(store, hangs)
    task = asyncio.create_task(executor.run_once())
    await wait_progress(store, run.id)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    current = await store.get_analysis_run(run.id)
    assert current.state == "running"
    assert current.result is None


async def test_lost_lease_stops_work_without_writing_completion():
    class FencedStore(MemoryAssessmentStore):
        lost = False
        completion_calls = 0

        async def heartbeat_analysis(self, *args, **kwargs):
            return False if self.lost else await super().heartbeat_analysis(*args, **kwargs)

        async def finish_analysis(self, *args, **kwargs):
            self.completion_calls += 1
            return await super().finish_analysis(*args, **kwargs)

    store, run = await fixture_run(FencedStore())
    task = asyncio.create_task(worker(store, hangs).run_once())
    await wait_progress(store, run.id)
    store.lost = True
    await asyncio.wait_for(task, 3)
    assert store.completion_calls == 0
    assert (await store.get_analysis_run(run.id)).result is None
