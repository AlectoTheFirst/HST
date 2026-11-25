"""A 'running' row with no run behind it, and the queued run's job around it.

A run row can read 'running' with no process executing it while every process
stays up: the process that ran it was killed (a cron `hst cycle`), or the
run ended and `finish_run` failed after its claim was released. Inline, the
next trigger's `start_run` takes the free claim and closes the row. The queued
trigger, the cancel route and the graph purge run the orphaned-run sweep
before they refuse on a running row, so such a row neither blocks a queued
trigger or a purge nor takes a cancel request no process would act on. The
sweep spares every claim a process holds.

The `collect.run` body reports such a row as an outcome that was not
recorded, and its cancellation path survives a failed read of the row.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.app.store import Run, live_run
from hst.core import Settings, run_cancel
from hst.worker import collect, runtime
from hst.worker.executor import Executor


@pytest.fixture(autouse=True)
def _own_run_registry(monkeypatch):
    # process-wide, and FakeStore run ids start at 1 in every test
    monkeypatch.setattr(runs_exec, "_RUNS", {})


def _settings(tmp_path, mode: str) -> Settings:
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path, run_execution=mode)


def _requests(settings: Settings) -> list:
    directory = settings.hst_data_dir / run_cancel.DIRECTORY
    return sorted(directory.glob("*.json")) if directory.exists() else []


async def _orphan(store: FakeStore, source: str = "unifi") -> Run:
    """A row that reads 'running' with no claim behind it."""
    run = await store.start_run(source, datetime.now(UTC) - timedelta(minutes=30))
    assert run is not None
    store.crash()
    return run


@pytest.fixture
async def unifi(seeded):
    await seeded.create_source("unifi", "unifi", {}, b"")
    return seeded


def _stub_prepare(monkeypatch) -> None:
    async def fake_prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)


async def _client(store, settings):
    app = create_app(settings=settings, store=store)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    )
    await login(client, "ada")
    return client


# --- the store helper --------------------------------------------------------------


async def test_live_run_closes_an_orphaned_row_and_finds_no_run():
    """`live_run` is the check every refusal on a run in flight reads, so a
    row with no claim behind it refuses nothing."""
    store = FakeStore()
    stale = await _orphan(store)

    assert await live_run(store, "unifi") is None
    row = await store.get_run(stale.id)
    assert (row.status, row.detail) == ("error", "orphaned by crash")


async def test_live_run_finds_a_run_a_process_executes():
    store = FakeStore()
    run = await store.start_run("unifi", datetime.now(UTC))

    assert await live_run(store, "unifi") == run
    assert (await store.get_run(run.id)).status == "running"


# --- the routes --------------------------------------------------------------------


async def test_a_queued_trigger_closes_an_orphaned_row_and_queues_the_run(unifi, tmp_path):
    stale = await _orphan(unifi)
    client = await _client(unifi, _settings(tmp_path, "queue"))
    try:
        r = await client.post("/api/runs", json={"source": "unifi"})
    finally:
        await client.aclose()

    assert r.status_code == 202, r.json()
    assert r.json()["kind"] == collect.RUN_KIND
    row = await unifi.get_run(stale.id)
    assert (row.status, row.detail) == ("error", "orphaned by crash")


async def test_a_queued_trigger_refuses_a_run_a_process_executes(unifi, tmp_path):
    await unifi.start_run("unifi", datetime.now(UTC))  # its claim is held
    client = await _client(unifi, _settings(tmp_path, "queue"))
    try:
        r = await client.post("/api/runs", json={"source": "unifi"})
    finally:
        await client.aclose()

    assert r.status_code == 409
    assert r.json()["error"] == "unifi is already running"
    assert unifi.jobs == {}


@pytest.mark.parametrize("mode", ["inline", "queue"])
async def test_a_cancel_of_an_orphaned_row_is_not_running_and_writes_no_request(unifi, tmp_path, mode):
    stale = await _orphan(unifi)
    settings = _settings(tmp_path, mode)
    client = await _client(unifi, settings)
    try:
        r = await client.post(f"/api/runs/{stale.id}/cancel")
    finally:
        await client.aclose()

    assert r.status_code == 404
    assert r.json()["error"] == f"run {stale.id} is not running on this instance"
    assert _requests(settings) == []
    row = await unifi.get_run(stale.id)
    assert (row.status, row.detail) == ("error", "orphaned by crash")


async def test_a_cancel_finds_a_remote_run_however_many_runs_came_after_it(unifi, tmp_path):
    """The run is read by its id, not from a window of the newest rows."""
    remote = await unifi.start_run("unifi", datetime.now(UTC) - timedelta(hours=1))
    assert remote is not None
    for _ in range(250):
        later = await unifi.start_run("reasoner", datetime.now(UTC))
        await unifi.finish_run(later.id, "error", datetime.now(UTC), "refused")
    settings = _settings(tmp_path, "queue")
    client = await _client(unifi, settings)
    try:
        r = await client.post(f"/api/runs/{remote.id}/cancel")
    finally:
        await client.aclose()

    assert r.status_code == 202
    (path,) = _requests(settings)
    assert json.loads(path.read_text())["run_id"] == remote.id


async def test_the_purge_is_not_refused_by_an_orphaned_row(unifi, tmp_path, monkeypatch):
    import hst.app.routes.runs as runs_routes

    class _Graph:
        def __init__(self) -> None:
            self.queries: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, *a) -> bool:
            return False

        def run(self, query, **params):
            self.queries.append(query)
            return SimpleNamespace(single=lambda: {"c": 3})

    graph = _Graph()
    monkeypatch.setattr(runs_routes, "_session", lambda settings: graph)
    stale = await _orphan(unifi)
    client = await _client(unifi, _settings(tmp_path, "inline"))
    try:
        r = await client.post("/api/graph/purge")
        live = await unifi.start_run("unifi", datetime.now(UTC))
        refused = await client.post("/api/graph/purge")
    finally:
        await client.aclose()

    assert r.status_code == 200 and r.json() == {"deleted_nodes": 3}
    assert (await unifi.get_run(stale.id)).status == "error"
    assert refused.status_code == 409
    assert refused.json()["error"] == f"a collection is running: run {live.id} (unifi)"


# --- the collect.run body ----------------------------------------------------------


async def test_a_run_whose_row_was_not_finished_is_reported_so_and_heals_on_the_next_trigger(
    unifi, tmp_path, monkeypatch
):
    _stub_prepare(monkeypatch)
    monkeypatch.setattr(
        runs_exec, "execute_refresh", lambda *a, **kw: runs_exec.RunOutcome("refreshed", [], None)
    )
    real = FakeStore.finish_run
    calls = {"n": 0}

    async def flaky(self, run_id, status, finished_at, detail, snapshot_key=None):
        calls["n"] += 1
        if calls["n"] == 1:
            self._claims.discard(self.runs[run_id].source)  # PgStore releases it in its finally
            raise ConnectionError("server closed the connection unexpectedly")
        return await real(self, run_id, status, finished_at, detail, snapshot_key)

    monkeypatch.setattr(FakeStore, "finish_run", flaky)
    settings = _settings(tmp_path, "queue")
    otto = await unifi.get_user_by_username("otto")
    job = await collect.enqueue_run(unifi, "unifi", otto.id)
    assert job is not None
    executor = Executor(unifi, settings, bodies=runtime.bodies(), name="worker-under-test")
    await executor.poll()
    await executor.drain()

    (run,) = await unifi.list_runs()
    assert run.status == "running"
    assert unifi.jobs[job.id].detail == f"run {run.id} ended, and its outcome was not recorded"

    client = await _client(unifi, settings)
    try:
        r = await client.post("/api/runs", json={"source": "unifi"})
    finally:
        await client.aclose()
    assert r.status_code == 202
    row = await unifi.get_run(run.id)
    assert (row.status, row.detail) == ("error", "orphaned by crash")


async def test_a_cancelled_body_whose_row_read_fails_ends_cancelled(unifi, monkeypatch):
    started = Run(7, "unifi", "running", datetime.now(UTC), None, "")
    entered = asyncio.Event()

    async def launch(store, settings, source, triggered_by=None):
        return started

    async def wait_for_run(store, run):
        entered.set()
        await asyncio.sleep(3600)

    async def finished_row(store, run):
        raise ConnectionError("postgres gone")

    monkeypatch.setattr(runs_exec, "launch", launch)
    monkeypatch.setattr(runs_exec, "wait_for_run", wait_for_run)
    monkeypatch.setattr(runs_exec, "finished_row", finished_row)
    otto = await unifi.get_user_by_username("otto")
    job = await collect.enqueue_run(unifi, "unifi", otto.id)
    (claimed,) = await unifi.claim_jobs("worker-a", 1, datetime.now(UTC), timedelta(minutes=5))
    ctx = SimpleNamespace(store=unifi, settings=Settings(_env_file=None))

    body = asyncio.create_task(collect.collect_run_body(ctx, claimed))
    await asyncio.wait_for(entered.wait(), 30)
    body.cancel()
    with pytest.raises(asyncio.CancelledError):
        await body

    assert (unifi.jobs[job.id].state, unifi.jobs[job.id].detail) == ("ok", "run 7 running")


async def test_the_cycle_body_reports_a_row_that_was_not_finished(monkeypatch):
    async def run_blocking(store, settings, source, triggered_by=None):
        return Run(9, "cycle", "running", datetime.now(UTC), None, "")

    monkeypatch.setattr(runs_exec, "run_blocking", run_blocking)
    ctx = SimpleNamespace(store=FakeStore(), settings=Settings(_env_file=None))

    assert await collect.collect_cycle_body(ctx, None) == "run 9 ended, and its outcome was not recorded"


async def test_the_finished_row_is_read_however_many_runs_came_after_it():
    store = FakeStore()
    first = await store.start_run("unifi", datetime.now(UTC))
    await store.finish_run(first.id, "ok", datetime.now(UTC), "done")
    for _ in range(60):
        later = await store.start_run("reasoner", datetime.now(UTC))
        await store.finish_run(later.id, "error", datetime.now(UTC), "refused")

    row = await runs_exec.finished_row(store, first)

    assert (row.id, row.status, row.detail) == (first.id, "ok", "done")
