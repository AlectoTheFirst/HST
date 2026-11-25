"""Queued runs: RUN_EXECUTION=queue turns POST /api/runs into a `collect.run` job,
and the job body executes the run in whichever process claims it."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.core import Settings
from hst.core.collection_progress import CollectionProgress
from hst.worker import collect, queue, runtime
from hst.worker.executor import Executor


@pytest.fixture(autouse=True)
def _own_run_registry(monkeypatch):
    # The run registry is process-wide and FakeStore run ids start at 1 in every
    # test, so each test gets a registry of its own.
    monkeypatch.setattr(runs_exec, "_RUNS", {})


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        hst_secret_key=generate_key(),
        hst_data_dir=tmp_path,
        run_execution="queue",
    )


@pytest.fixture
async def with_sources(seeded):
    await seeded.create_source("unifi", "unifi", {}, b"")
    await seeded.create_source("vyos", "vyos", {}, b"")
    await seeded.create_source("paused", "manual", {"devices": ""}, b"", enabled=False)
    return seeded


@pytest.fixture
async def queued(with_sources, settings):
    app = create_app(settings=settings, store=with_sources)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "otto")
        yield client


def _stub_prepare(monkeypatch) -> None:
    async def fake_prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)


def _blocking_refresh(monkeypatch) -> threading.Event:
    """A refresh that blocks until its stop flag is raised; returns the event
    set once the builder thread is running."""
    entered = threading.Event()

    def blocking(settings, prepared, name, assigned=None, *, stop=None, **kw):
        entered.set()
        assert stop is not None and stop.wait(10), "the stop flag was never raised"
        raise RuntimeError("stopped at a phase boundary")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", blocking)
    return entered


async def _user_id(store, username: str) -> int:
    user = await store.get_user_by_username(username)
    assert user is not None
    return user.id


def _executor(store, settings) -> Executor:
    return Executor(store, settings, bodies=runtime.bodies(), name="worker-under-test")


async def test_a_queued_trigger_answers_with_the_job_and_starts_no_run(queued, with_sources):
    r = await queued.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 202
    body = r.json()
    assert set(body) == {"job_id", "kind", "source", "status", "enqueued_at"}
    assert (body["kind"], body["source"], body["status"]) == ("collect.run", "unifi", "queued")
    job = with_sources.jobs[body["job_id"]]
    assert (job.kind, job.state, job.priority, job.max_attempts) == ("collect.run", "queued", 1, 1)
    assert job.triggered_by == f"runs:{await _user_id(with_sources, 'otto')}"
    assert await with_sources.list_runs() == []
    assert runs_exec._RUNS == {}


async def test_a_second_trigger_names_the_queued_job(queued):
    first = (await queued.post("/api/runs", json={"source": "unifi"})).json()
    r = await queued.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 409
    assert r.json()["error"] == f"unifi is already queued (job {first['job_id']})"
    # another source is its own slot
    assert (await queued.post("/api/runs", json={"source": "vyos"})).status_code == 202


async def test_a_claimed_job_with_no_run_row_yet_is_reported_as_running(queued, with_sources):
    job_id = (await queued.post("/api/runs", json={"source": "unifi"})).json()["job_id"]
    (claimed,) = await queue.claim(with_sources, "worker-a")
    assert claimed.id == job_id
    r = await queued.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 409
    assert r.json()["error"] == f"job {job_id} for unifi is running"


async def test_a_running_row_refuses_the_trigger_as_inline_does(queued, with_sources):
    await with_sources.start_run("unifi", datetime.now(UTC))
    r = await queued.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 409
    assert r.json()["error"] == "unifi is already running"
    assert with_sources.jobs == {}


async def test_a_device_run_with_nothing_parked_is_refused(queued, with_sources):
    r = await queued.post("/api/runs", json={"source": "device-run"})
    assert r.status_code == 409
    assert r.json()["error"] == "no payloads are parked for a device run"
    assert with_sources.jobs == {}


async def test_unknown_and_disabled_sources_answer_as_they_do_inline(queued, with_sources):
    r = await queued.post("/api/runs", json={"source": "cisco"})
    assert r.status_code == 400 and "unifi" in r.json()["error"]
    r = await queued.post("/api/runs", json={"source": "paused"})
    assert r.status_code == 409 and r.json()["error"] == "paused is disabled"
    assert with_sources.jobs == {}


async def test_the_executor_runs_the_queued_run_for_the_account_that_asked(
    queued, with_sources, settings, monkeypatch
):
    _stub_prepare(monkeypatch)
    monkeypatch.setattr(
        runs_exec,
        "execute_refresh",
        lambda settings, prepared, name, assigned=None, **kw: runs_exec.RunOutcome(f"{name} done", [], 7000),
    )
    job_id = (await queued.post("/api/runs", json={"source": "unifi"})).json()["job_id"]
    executor = _executor(with_sources, settings)
    await executor.poll()
    await executor.drain()

    (run,) = await with_sources.list_runs()
    assert (run.source, run.status, run.detail) == ("unifi", "ok", "unifi done")
    assert run.triggered_by == await _user_id(with_sources, "otto")
    job = with_sources.jobs[job_id]
    assert job.state == "ok"
    assert job.detail == f"run {run.id} ok: unifi done"


async def test_a_disabled_account_or_source_skips_the_job_and_starts_no_run(with_sources, settings):
    otto = await _user_id(with_sources, "otto")
    executor = _executor(with_sources, settings)
    await with_sources.update_source("vyos", enabled=False)
    paused = await collect.enqueue_run(with_sources, "vyos", otto)
    gone = await collect.enqueue_run(with_sources, "ghost", otto)
    assert paused is not None and gone is not None
    await executor.poll()
    await executor.drain()
    assert with_sources.jobs[paused.id].detail == "skipped: vyos is disabled"
    assert with_sources.jobs[gone.id].detail == "skipped: source ghost no longer exists"

    await with_sources.update_user(otto, disabled=True)
    refused = await collect.enqueue_run(with_sources, "reasoner", otto)
    assert refused is not None
    await executor.poll()
    await executor.drain()
    job = with_sources.jobs[refused.id]
    assert (job.state, job.detail) == ("ok", "skipped: collection authorization is no longer valid")
    assert await with_sources.list_runs() == []


async def test_stopping_the_executor_cancels_the_run_and_finishes_its_job(
    queued, with_sources, settings, monkeypatch
):
    entered = _blocking_refresh(monkeypatch)
    job_id = (await queued.post("/api/runs", json={"source": "unifi"})).json()["job_id"]
    loop_task = asyncio.create_task(_executor(with_sources, settings).run())
    assert await asyncio.to_thread(entered.wait, 10), "the run never started"

    loop_task.cancel()
    await asyncio.gather(loop_task, return_exceptions=True)

    (run,) = await with_sources.list_runs()
    assert run.status == runs_exec.CANCELLED
    job = with_sources.jobs[job_id]
    assert (job.state, job.detail) == ("ok", f"run {run.id} cancelled")
    assert job.claimed_by is None
    # the source's pending slot is free at once, not after the lease lapses
    assert (await queued.post("/api/runs", json={"source": "unifi"})).status_code == 202


async def test_a_killed_worker_leaves_a_dead_job_and_an_orphaned_run(with_sources):
    otto = await _user_id(with_sources, "otto")
    start = datetime.now(UTC)
    job = await collect.enqueue_run(with_sources, "unifi", otto, now=start)
    assert job is not None
    (claimed,) = await queue.claim(with_sources, "worker-a", now=start)
    run = await with_sources.start_run("unifi", start, otto)
    assert run is not None
    with_sources.crash()  # the process died: its claim went with its connection

    await queue.reap(with_sources, start + queue.LEASE + timedelta(seconds=1))
    assert with_sources.jobs[claimed.id].state == "dead"  # one attempt, never requeued
    await with_sources.reconcile_orphaned_runs(start + queue.LEASE)
    (row,) = await with_sources.list_runs()
    assert (row.status, row.detail) == ("error", "orphaned by crash")


async def test_wait_for_run_and_run_blocking_wait_for_their_own_run_only(settings, monkeypatch):
    store = FakeStore()
    await store.create_source("unifi", "unifi", {}, b"")
    entered = _blocking_refresh(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_source", lambda settings, source, row: ("derived", None))

    held = await runs_exec.launch(store, settings, "unifi")
    assert held is not None
    assert await asyncio.to_thread(entered.wait, 10)

    quick = await runs_exec.launch(store, settings, "reasoner")
    assert quick is not None
    finished = await asyncio.wait_for(runs_exec.wait_for_run(store, quick), 10)
    assert (finished.id, finished.status) == (quick.id, "ok")
    blocking = await asyncio.wait_for(runs_exec.run_blocking(store, settings, "reasoner"), 10)
    assert blocking is not None and blocking.status == "ok" and blocking.id != quick.id
    assert held.id in runs_exec._RUNS, "the other run was waited for or cancelled"

    runs_exec.cancel_run(held.id, by="test")
    final = await asyncio.wait_for(runs_exec.wait_for_run(store, held), 10)
    assert final.status == runs_exec.CANCELLED


async def test_the_job_listing_draws_no_progress_on_a_running_queued_run(queued, with_sources, settings):
    otto = await _user_id(with_sources, "otto")
    before = datetime.now(UTC) - timedelta(minutes=1)
    run_job = await collect.enqueue_run(with_sources, "unifi", otto, now=before)
    fetch_job = await queue.enqueue(
        with_sources, collect.FETCH_KIND, source="unifi", device="r1", triggered_by="scheduler", now=before
    )
    assert run_job is not None and fetch_job is not None
    assert len(await queue.claim(with_sources, "worker-a", 2, now=before)) == 2
    CollectionProgress(settings, "unifi").phase("Fetching devices", total=3)

    rows = {row["id"]: row for row in (await queued.get("/api/jobs")).json()["jobs"]}
    assert rows[run_job.id]["state"] == "running" and "progress" not in rows[run_job.id]
    assert rows[fetch_job.id]["progress"][0]["source"] == "unifi"
