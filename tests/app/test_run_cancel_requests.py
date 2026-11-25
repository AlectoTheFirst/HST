"""Cancel across processes: request files under HST_DATA_DIR/run-cancel, the
watcher each executing run polls them with, and the route that writes them."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.core import Settings, run_cancel
from hst.core.collection_progress import CollectionProgress
from hst.worker import collect, runtime
from hst.worker.executor import Executor

STARTED = datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _own_run_registry(monkeypatch):
    # The run registry is process-wide and FakeStore run ids start at 1 in every
    # test, so each test gets a registry of its own.
    monkeypatch.setattr(runs_exec, "_RUNS", {})


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)


def _requests(settings) -> list:
    directory = settings.hst_data_dir / run_cancel.DIRECTORY
    return sorted(directory.glob("*.json")) if directory.exists() else []


# --- the request files -------------------------------------------------------------


def test_a_request_is_taken_once_by_its_own_run(settings):
    path = run_cancel.request(settings, 123, STARTED, by="otto", source=None)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(path.read_text())["run_started_at"] == STARTED.isoformat()
    # run 12 is not run 123
    assert run_cancel.take(settings, 12, STARTED) == []
    (taken,) = run_cancel.take(settings, 123, STARTED)
    assert (taken.run_id, taken.run_started_at, taken.source, taken.by) == (123, STARTED, None, "otto")
    assert not path.exists()
    assert run_cancel.take(settings, 123, STARTED) == []


def test_a_request_for_another_start_time_is_left_alone(settings):
    path = run_cancel.request(settings, 5, STARTED, by="otto", source="nxos-edge")
    assert run_cancel.take(settings, 5, STARTED + timedelta(seconds=1)) == []
    assert path.exists()


def test_an_unreadable_request_is_removed(settings, caplog):
    directory = settings.hst_data_dir / run_cancel.DIRECTORY
    directory.mkdir(parents=True)
    corrupt = directory / "7-0123abcd.json"
    corrupt.write_text("{not json")
    wrong_shape = directory / "7-4567abcd.json"
    wrong_shape.write_text(json.dumps({"run_id": 7}))
    with caplog.at_level(logging.WARNING, logger="hst.core.run_cancel"):
        assert run_cancel.take(settings, 7, STARTED) == []
    assert not corrupt.exists() and not wrong_shape.exists()
    assert "7-0123abcd.json" in caplog.text


def test_requests_older_than_an_hour_are_swept_by_the_next_request(settings):
    old = run_cancel.request(settings, 1, STARTED, by="otto", source=None)
    stale = time.time() - run_cancel.MAX_AGE_S - 60
    os.utime(old, (stale, stale))
    fresh = run_cancel.request(settings, 2, STARTED, by="otto", source=None)
    assert not old.exists()
    assert fresh.exists()


def test_take_creates_no_directory(settings):
    assert run_cancel.take(settings, 1, STARTED) == []
    assert not (settings.hst_data_dir / run_cancel.DIRECTORY).exists()


# --- the watcher --------------------------------------------------------------------


@pytest.fixture
def fast_poll(monkeypatch):
    monkeypatch.setattr(runs_exec, "CANCEL_POLL_S", 0.01)


def _stub_prepare(monkeypatch) -> None:
    async def fake_prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)


def _blocking_refresh(monkeypatch, sources: tuple[str, ...] = ()) -> tuple[threading.Event, dict]:
    """A refresh that registers `sources` on its stop flag and blocks until the
    run's own flag is raised."""
    entered = threading.Event()
    flags: dict[str, threading.Event] = {}

    def blocking(settings, prepared, name, assigned=None, *, stop=None, **kw):
        assert isinstance(stop, runs_exec.RunStop)
        for source in sources:
            flags[source] = stop.for_source(source)
        entered.set()
        assert stop.wait(10), "the stop flag was never raised"
        raise RuntimeError("stopped at a phase boundary")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", blocking)
    return entered, flags


async def _store() -> FakeStore:
    store = FakeStore()
    await store.create_source("unifi", "unifi", {}, b"")
    return store


async def _started(store, settings, monkeypatch, sources: tuple[str, ...] = ()):
    entered, flags = _blocking_refresh(monkeypatch, sources)
    run = await runs_exec.launch(store, settings, "unifi")
    assert run is not None
    assert await asyncio.to_thread(entered.wait, 10), "the run never started"
    return run, flags


async def test_a_whole_run_request_cancels_the_run_in_the_process_executing_it(
    settings, fast_poll, monkeypatch
):
    store = await _store()
    run, _ = await _started(store, settings, monkeypatch)
    run_cancel.request(settings, run.id, run.started_at, by="ada", source=None)
    finished = await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)
    assert finished.status == runs_exec.CANCELLED
    assert "ada" in finished.detail
    assert _requests(settings) == []


async def test_a_request_bound_to_another_start_time_is_ignored(settings, fast_poll, monkeypatch):
    store = await _store()
    run, _ = await _started(store, settings, monkeypatch)
    stray = run_cancel.request(settings, run.id, run.started_at + timedelta(seconds=1), by="ada", source=None)
    await asyncio.sleep(0.2)
    assert run.id in runs_exec._RUNS
    assert stray.exists()
    runs_exec.cancel_run(run.id, by="test")
    await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)


async def test_a_source_request_raises_that_source_flag_only(settings, fast_poll, monkeypatch):
    store = await _store()
    run, flags = await _started(store, settings, monkeypatch, sources=("nxos-edge", "vco"))
    run_cancel.request(settings, run.id, run.started_at, by="ada", source="nxos-edge")
    assert await asyncio.to_thread(flags["nxos-edge"].wait, 10), "the source's flag was never raised"
    assert not flags["vco"].is_set(), "the other source was stopped too"
    assert run.id in runs_exec._RUNS
    runs_exec.cancel_run(run.id, by="test")
    await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)


async def test_two_whole_run_requests_cancel_the_run_once(settings, fast_poll, monkeypatch):
    store = await _store()
    run, _ = await _started(store, settings, monkeypatch)
    calls = []
    real = runs_exec.cancel_run

    def counting(run_id, by="operator", source=None):
        calls.append((run_id, by, source))
        return real(run_id, by=by, source=source)

    monkeypatch.setattr(runs_exec, "cancel_run", counting)
    run_cancel.request(settings, run.id, run.started_at, by="ada", source=None)
    run_cancel.request(settings, run.id, run.started_at, by="otto", source=None)
    finished = await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)
    assert finished.status == runs_exec.CANCELLED
    assert len(calls) == 1


async def test_the_watcher_ends_with_its_run(settings, monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(runs_exec, "execute_source", lambda settings, source, row: ("derived", None))
    before = set(runs_exec._WATCHERS)
    run = await runs_exec.launch(store, settings, "reasoner")
    assert run is not None
    (watcher,) = set(runs_exec._WATCHERS) - before
    await runs_exec.wait_for_run(store, run)
    for _ in range(5):
        if watcher.done() and watcher not in runs_exec._WATCHERS:
            break
        await asyncio.sleep(0)
    assert watcher.cancelled()
    assert watcher not in runs_exec._WATCHERS


# --- a second cancellation while the run drains -------------------------------------


def _slow_to_stop(monkeypatch) -> tuple[threading.Event, threading.Event, threading.Event]:
    """A refresh whose phase in flight outlasts its stop flag. Returns
    (entered, stopping, release): `stopping` is set once the flag is raised,
    and the builder thread returns only when `release` is set."""
    entered, stopping, release = threading.Event(), threading.Event(), threading.Event()

    def slow(settings, prepared, name, assigned=None, *, stop=None, **kw):
        entered.set()
        assert stop is not None and stop.wait(10), "the stop flag was never raised"
        stopping.set()
        assert release.wait(10), "the builder thread was never released"
        raise RuntimeError("stopped at a phase boundary")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", slow)
    return entered, stopping, release


async def test_a_second_cancel_keeps_the_lock_until_the_builder_thread_returns(settings, monkeypatch):
    store = await _store()
    entered, stopping, release = _slow_to_stop(monkeypatch)
    try:
        run = await runs_exec.launch(store, settings, "unifi")
        assert run is not None
        assert await asyncio.to_thread(entered.wait, 10), "the run never started"
        assert runs_exec.cancel_run(run.id, by="ada")
        assert await asyncio.to_thread(stopping.wait, 10)
        assert runs_exec.cancel_run(run.id, by="otto")
        await asyncio.sleep(0.05)
        assert store._cycle_lock.locked(), "the cycle lock was released while the builder thread ran"
        assert run.id in runs_exec._RUNS
    finally:
        release.set()
    finished = await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)
    assert (finished.status, finished.detail) == (runs_exec.CANCELLED, "cancelled by ada")
    assert not store._cycle_lock.locked()


async def test_a_wait_cancelled_twice_cancels_its_run_once_and_waits_for_it(settings, monkeypatch):
    store = await _store()
    entered, stopping, release = _slow_to_stop(monkeypatch)
    try:
        run = await runs_exec.launch(store, settings, "unifi")
        assert run is not None
        assert await asyncio.to_thread(entered.wait, 10), "the run never started"
        waiter = asyncio.create_task(runs_exec.wait_for_run(store, run))
        await asyncio.sleep(0)
        waiter.cancel()  # a lost lease
        assert await asyncio.to_thread(stopping.wait, 10), "the run was never cancelled"
        waiter.cancel()  # then the executor stopping
        await asyncio.sleep(0.05)
        assert not waiter.done(), "the wait ended while the run was still draining"
        assert store._cycle_lock.locked()
    finally:
        release.set()
    await asyncio.wait({waiter}, timeout=10)
    assert waiter.cancelled()
    (row,) = await store.list_runs()
    assert (row.status, row.detail) == (runs_exec.CANCELLED, "cancelled")


async def test_an_executor_stop_after_a_cancel_request_waits_out_the_drain(
    seeded, settings, fast_poll, monkeypatch
):
    await seeded.create_source("unifi", "unifi", {}, b"")
    otto = await seeded.get_user_by_username("otto")
    assert otto is not None
    job = await collect.enqueue_run(seeded, "unifi", otto.id)
    assert job is not None
    entered, stopping, release = _slow_to_stop(monkeypatch)
    executor = Executor(seeded, settings, bodies=runtime.bodies(), name="worker-under-test")
    loop_task = asyncio.create_task(executor.run())
    try:
        assert await asyncio.to_thread(entered.wait, 10), "the run never started"
        (run,) = await seeded.list_runs()
        run_cancel.request(settings, run.id, run.started_at, by="ada", source=None)
        assert await asyncio.to_thread(stopping.wait, 10), "the request was never taken"
        loop_task.cancel()
        await asyncio.sleep(0.05)
        assert not loop_task.done(), "the executor stopped while the run was still draining"
        assert seeded._cycle_lock.locked(), "the cycle lock was released while the builder thread ran"
    finally:
        release.set()
    await asyncio.wait({loop_task}, timeout=10)
    assert loop_task.done()
    (row,) = await seeded.list_runs()
    assert (row.status, row.detail) == (runs_exec.CANCELLED, "cancelled by ada")
    assert seeded.jobs[job.id].detail == f"run {row.id} cancelled: cancelled by ada"


# --- the route ----------------------------------------------------------------------


@pytest.fixture
async def remote(seeded, settings):
    """A client, and a running row this process is not executing: the run
    executes in another process."""
    await seeded.create_source("unifi", "unifi", {}, b"")
    run = await seeded.start_run("unifi", datetime.now(UTC) - timedelta(minutes=1))
    app = create_app(settings=settings, store=seeded)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "otto")
        yield client, run


async def test_a_remote_run_gets_a_request_file_and_a_202(remote, settings):
    client, run = remote
    r = await client.post(f"/api/runs/{run.id}/cancel")
    assert r.status_code == 202
    assert r.json() == {"id": run.id, "status": "cancelling"}
    (path,) = _requests(settings)
    body = json.loads(path.read_text())
    assert body["run_started_at"] == run.started_at.isoformat()
    assert (body["run_id"], body["source"], body["by"]) == (run.id, None, "otto")


async def test_a_remote_source_with_no_progress_is_not_collecting(remote, settings):
    client, run = remote
    r = await client.post(f"/api/runs/{run.id}/cancel", json={"source": "nxos-edge"})
    assert r.status_code == 404
    assert r.json()["error"] == f"run {run.id} is not collecting nxos-edge"
    assert _requests(settings) == []


async def test_a_remote_source_with_progress_since_the_run_started_gets_a_request(remote, settings):
    client, run = remote
    CollectionProgress(settings, "nxos-edge").phase("Fetching devices", total=4)
    r = await client.post(f"/api/runs/{run.id}/cancel", json={"source": "nxos-edge"})
    assert r.status_code == 202
    assert r.json() == {"id": run.id, "source": "nxos-edge", "status": "cancelling"}
    (path,) = _requests(settings)
    assert json.loads(path.read_text())["source"] == "nxos-edge"


async def test_the_run_own_source_needs_no_progress_record(remote, settings):
    client, run = remote
    r = await client.post(f"/api/runs/{run.id}/cancel", json={"source": "unifi"})
    assert r.status_code == 202
    assert len(_requests(settings)) == 1


async def test_a_finished_row_is_not_running(remote, seeded, settings):
    client, run = remote
    await seeded.finish_run(run.id, "ok", datetime.now(UTC), "done")
    r = await client.post(f"/api/runs/{run.id}/cancel")
    assert r.status_code == 404
    assert r.json()["error"] == f"run {run.id} is not running on this instance"
    assert _requests(settings) == []


async def test_an_unwritable_request_directory_is_a_503(remote, settings):
    client, run = remote
    # a file where the directory belongs: the request cannot be written
    (settings.hst_data_dir / run_cancel.DIRECTORY).write_text("")
    r = await client.post(f"/api/runs/{run.id}/cancel")
    assert r.status_code == 503
    assert r.json()["error"].startswith(f"the cancel request for run {run.id} could not be written: ")
