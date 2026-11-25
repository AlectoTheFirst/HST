"""A re-parse in isolation (app/debug_reparse.py): the limits on its child, and
the `debug.reparse` job that carries it to the worker with RUN_EXECUTION=queue."""

from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import os
import threading
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.fakes import FakeStore
from tests.test_iosxe import RAW

from hst.app import debug_reparse
from hst.app.crypto import dek
from hst.app.security import hash_password
from hst.core import debug_capture, rawstore
from hst.worker import maintenance, queue, runtime
from hst.worker.executor import Executor
from hst.worker.maintenance import Context

RUN_ID = "1790000000000-abcdef12"


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
async def edge(app, seeded, tmp_path):
    app.state.settings.hst_data_dir = tmp_path
    await seeded.create_source("edge", "iosxe", {}, b"")
    return app.state.settings


def _write(settings, run_id=RUN_ID):
    return rawstore.write(settings.raw_dir, "edge", run_id, RAW, host="r1", key=dek(settings))


async def _payload(client) -> dict[str, Any]:
    [payload] = (await client.get("/api/debug-capture/payloads", params={"source": "edge"})).json()[
        "payloads"
    ]
    return payload


# --- the child's limits -------------------------------------------------------------


class _Connection:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    def close(self) -> None:
        pass


def test_the_address_space_is_limited_before_the_payload_is_read(app, tmp_path, monkeypatch):
    settings = app.state.settings
    settings.hst_data_dir = tmp_path
    _write(settings)
    order: list[str] = []
    read = rawstore.read
    monkeypatch.setattr(debug_reparse.faulthandler, "enable", lambda **kw: None)
    monkeypatch.setattr(
        debug_reparse, "_limit_address_space", lambda memory_mb: order.append(f"limit {memory_mb}")
    )
    monkeypatch.setattr(
        debug_reparse.rawstore, "read", lambda path, key: order.append("read") or read(path, key)
    )
    connection = _Connection()
    debug_reparse._child(settings, "iosxe", "edge", "r1", RUN_ID, connection, 64)  # type: ignore[arg-type]
    assert order == ["limit 64", "read"]
    assert [m["state"] for m in connection.sent] == ["ok"]


def test_a_child_that_runs_out_of_its_budget_reports_the_budget(app, tmp_path, monkeypatch):
    settings = app.state.settings
    settings.hst_data_dir = tmp_path
    _write(settings)
    monkeypatch.setattr(debug_reparse.faulthandler, "enable", lambda **kw: None)
    monkeypatch.setattr(debug_reparse, "_limit_address_space", lambda memory_mb: None)

    def exhausted(path, key):
        raise MemoryError

    monkeypatch.setattr(debug_reparse.rawstore, "read", exhausted)
    connection = _Connection()
    debug_reparse._child(settings, "iosxe", "edge", "r1", RUN_ID, connection, 64)  # type: ignore[arg-type]
    assert connection.sent == [
        {"state": "memory", "error": "reading and parsing the payload needed more than 64 MiB"}
    ]


async def test_a_process_runs_one_child_at_a_time(app, monkeypatch):
    running = 0
    most = 0
    entered = threading.Event()
    release = threading.Event()

    def child(settings, collector_type, source, host, run_id, *, stop=None):
        nonlocal running, most
        running += 1
        most = max(most, running)
        entered.set()
        release.wait(5)
        running -= 1
        return {"state": "ok", "run_id": run_id}

    monkeypatch.setattr(debug_reparse, "run_isolated", child)
    tasks = [
        asyncio.create_task(debug_reparse._reparse(app.state.settings, "iosxe", "edge", "r1", f"{n}-abcdef"))
        for n in range(3)
    ]
    assert await asyncio.to_thread(entered.wait, 5)
    # time for the other two to start, were they not held back
    await asyncio.sleep(0.2)
    release.set()
    results = await asyncio.gather(*tasks)
    assert [r["run_id"] for r in results] == ["0-abcdef", "1-abcdef", "2-abcdef"]
    assert most == debug_reparse.MAX_CHILDREN == 1


async def test_a_cancelled_reparse_stops_its_child_first(app, monkeypatch):
    entered = threading.Event()
    stopped = threading.Event()

    def child(settings, collector_type, source, host, run_id, *, stop=None):
        assert stop is not None
        entered.set()
        stop.wait(5)
        stopped.set()
        return {"state": "error", "error": debug_reparse._STOPPED}

    monkeypatch.setattr(debug_reparse, "run_isolated", child)
    task = asyncio.create_task(debug_reparse._reparse(app.state.settings, "iosxe", "edge", "r1", RUN_ID))
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.is_set()


class _Process:
    pid = 4_000_000
    exitcode: int | None = None

    def __init__(self, **kwargs: Any) -> None:
        self.killed = False

    def start(self) -> None:
        pass

    def is_alive(self) -> bool:
        return not self.killed

    def kill(self) -> None:
        self.killed = True
        self.exitcode = -9

    def join(self, timeout: float | None = None) -> None:
        pass


class _Receiver:
    def poll(self, timeout: float) -> bool:
        return False

    def close(self) -> None:
        pass


class _Context:
    def __init__(self) -> None:
        self.processes: list[_Process] = []

    def Pipe(self, duplex: bool) -> tuple[_Receiver, _Receiver]:
        return _Receiver(), _Receiver()

    def Process(self, **kwargs: Any) -> _Process:
        process = _Process(**kwargs)
        self.processes.append(process)
        return process


def test_a_stopped_wait_kills_the_child_and_says_so(app, monkeypatch):
    context = _Context()
    monkeypatch.setattr(debug_reparse.multiprocessing, "get_context", lambda method: context)
    stop = threading.Event()
    stop.set()
    result = debug_reparse.run_isolated(app.state.settings, "iosxe", "edge", "r1", RUN_ID, stop=stop)
    [process] = context.processes
    assert process.killed
    assert result["state"] == "error" and result["error"] == debug_reparse._STOPPED
    assert result["exit_code"] == -9


# --- the queued re-parse ------------------------------------------------------------


async def test_a_queued_reparse_is_a_job_the_executor_runs(client, edge, seeded):
    edge.run_execution = "queue"
    _write(edge)
    await login(client, "otto")
    otto = await seeded.get_user_by_username("otto")
    r = await client.post(
        "/api/debug-capture/reparse", json={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert r.status_code == 202 and r.json()["state"] == "running"
    job = await seeded.get_job(r.json()["job_id"])
    assert job.kind == debug_reparse.KIND and job.state == "queued"
    assert (job.source, job.device) == (None, f"edge/r1/{RUN_ID}")
    assert job.max_attempts == 1 and job.triggered_by == f"debug:{otto.id}"
    # nothing ran in this process, and the listing reads the job
    assert debug_reparse._TASKS == {}
    assert (await _payload(client))["reparse"] == {"state": "running"}
    again = await client.post(
        "/api/debug-capture/reparse", json={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert again.status_code == 409

    executor = Executor(seeded, edge, bodies=runtime.bodies())
    assert [j.id for j in await executor.poll()] == [job.id]
    await executor.drain()
    finished = await seeded.get_job(job.id)
    assert finished.state == "ok" and finished.detail == "re-parse ok"
    shown = (await _payload(client))["reparse"]
    assert shown["state"] == "ok" and "job_id" not in shown

    bundle = await client.get(
        "/api/debug-capture/bundle", params={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert bundle.status_code == 200 and bundle.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as z:
        prefix = f"captures/edge/r1/{RUN_ID}/"
        result = json.loads(z.read(prefix + "reparse.json"))
        records = z.read(prefix + "reparse-debug.jsonl").decode()
    assert result["state"] == "ok" and result["job_id"] == job.id and result["report"]["sections"]
    assert '"step": "iosxe.parse"' in records


async def _queued(store: FakeStore, settings, user: str = "otto") -> Any:
    account = await store.get_user_by_username(user)
    job = await debug_reparse.enqueue(store, settings, "edge", "r1", RUN_ID, account.id)
    [claimed] = await queue.claim(store, "test-worker")
    assert claimed.id == job.id
    return claimed


def _stored(settings) -> dict[str, Any] | None:
    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", RUN_ID)
    return debug_capture.read_reparse(raw_path, dek(settings))


async def test_a_job_that_ended_without_a_result_reads_as_killed(edge, seeded):
    _write(edge)
    job = await _queued(seeded, edge)
    stored = debug_reparse.state(edge, "edge", "r1", RUN_ID)
    assert stored is not None and stored["job_id"] == job.id
    assert await debug_reparse.resolve(seeded, stored) == {"state": "running"}
    await seeded.reap_jobs(datetime(2100, 1, 1, tzinfo=UTC))
    assert await debug_reparse.resolve(seeded, stored) == {
        "state": "killed",
        "error": f"the re-parse job {job.id} ended dead and left no result: "
        "lease expired: the executor holding this job stopped reporting",
    }
    del seeded.jobs[job.id]
    assert await debug_reparse.resolve(seeded, stored) == {
        "state": "killed",
        "error": f"the re-parse job {job.id} is no longer recorded and left no result",
    }


async def test_a_reparse_that_runs_here_or_has_a_result_lists_no_job_id(seeded):
    assert await debug_reparse.resolve(seeded, {"state": "running"}) == {"state": "running"}
    stored = {"state": "timeout", "error": "e", "started_ms": 1, "finished_ms": 2, "exit_code": -6}
    shown = await debug_reparse.resolve(seeded, {**stored, "peak_rss_kb": None, "job_id": None})
    assert shown == {**stored, "peak_rss_kb": None}
    assert await debug_reparse.resolve(seeded, None) is None


async def test_a_job_whose_account_lost_the_permission_seals_the_refusal(edge, seeded):
    _write(edge)
    await seeded.create_user("olly", hash_password(PASSWORD), "operator")
    job = await _queued(seeded, edge, "olly")
    olly = await seeded.get_user_by_username("olly")
    await seeded.update_user(olly.id, role="viewer")
    detail = await debug_reparse.reparse_body(Context(store=seeded, settings=edge), job)
    refusal = "the account that asked for the re-parse no longer holds runs.manage"
    assert detail == f"skipped: {refusal}"
    assert _stored(edge) == {"state": "error", "error": refusal, "job_id": job.id}


async def test_a_job_whose_payload_left_the_store_takes_its_result_file_with_it(edge, seeded):
    raw_path = _write(edge)
    job = await _queued(seeded, edge)
    raw_path.unlink()
    detail = await debug_reparse.reparse_body(Context(store=seeded, settings=edge), job)
    assert detail == "skipped: the payload is no longer in the raw store"
    assert not rawstore.sibling(raw_path, rawstore.REPARSE_RESULT_SUFFIX).exists()


def _pruned_meanwhile(raw_path):
    """A `_reparse` during which the retention sweep removes the payload, and
    after which the child writes its records and stack once more."""

    async def reparse(*args: Any) -> dict[str, Any]:
        maintenance._unlink_raw(raw_path)
        for path in debug_reparse._files(raw_path)[:2]:
            path.write_bytes(b"written after the sweep")
        return {"state": "ok"}

    return reparse


async def test_a_job_whose_payload_is_pruned_while_its_child_runs_leaves_no_reparse_file(
    edge, seeded, monkeypatch
):
    raw_path = _write(edge)
    job = await _queued(seeded, edge)
    monkeypatch.setattr(debug_reparse, "_reparse", _pruned_meanwhile(raw_path))
    detail = await debug_reparse.reparse_body(Context(store=seeded, settings=edge), job)
    assert detail == "re-parse ok"
    assert not raw_path.exists()
    assert [path.name for path in debug_reparse._files(raw_path) if path.exists()] == []


async def test_a_reparse_here_of_a_payload_pruned_while_its_child_runs_leaves_no_reparse_file(
    edge, monkeypatch
):
    raw_path = _write(edge)
    monkeypatch.setattr(debug_reparse, "_reparse", _pruned_meanwhile(raw_path))
    assert debug_reparse.start(edge, "iosxe", "edge", "r1", RUN_ID)
    await debug_reparse._TASKS[debug_capture.capture_id("edge", "r1", RUN_ID)]
    assert not raw_path.exists()
    assert [path.name for path in debug_reparse._files(raw_path) if path.exists()] == []


# --- the result file ----------------------------------------------------------------


def test_a_result_that_cannot_be_put_in_place_leaves_the_one_before_it(edge, monkeypatch):
    raw_path = _write(edge)
    key = dek(edge)
    debug_capture.write_reparse(raw_path, {"state": "ok"}, key)

    def refused(self: Path, target: Any) -> Path:
        raise OSError("refused")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "replace", refused)
        with pytest.raises(OSError, match="refused"):
            debug_capture.write_reparse(raw_path, {"state": "error"}, key)
    assert _stored(edge) == {"state": "ok"}
    assert not [path.name for path in raw_path.parent.iterdir() if path.name.endswith(".tmp")]


def test_a_result_a_killed_process_left_unwritten_goes_with_the_raw_stores_tmp_files(edge, monkeypatch):
    raw_path = _write(edge)
    opened: list[Path] = []
    real_open = os.open

    def recording(path: Any, flags: int, mode: int = 0o777) -> int:
        opened.append(Path(path))
        return real_open(path, flags, mode)

    with monkeypatch.context() as patched:
        patched.setattr(os, "open", recording)
        debug_capture.write_reparse(raw_path, {"state": "ok"}, dek(edge))
    [tmp] = opened
    assert tmp.parent == raw_path.parent and not tmp.exists()
    # what a process killed before the rename leaves
    tmp.write_bytes(b"sealed in part")
    now = datetime.now(UTC)
    stale = (now - maintenance.RAW_TMP_MIN_AGE - timedelta(minutes=5)).timestamp()
    os.utime(tmp, (stale, stale))
    assert maintenance.sweep_raw_tmp(edge.raw_dir, now) == [tmp]
    assert _stored(edge) == {"state": "ok"}


async def test_a_cancelled_job_seals_a_stopped_result_and_finishes(edge, seeded, monkeypatch):
    _write(edge)
    job = await _queued(seeded, edge)
    started = asyncio.Event()

    async def forever(*args: Any) -> dict[str, Any]:
        started.set()
        await asyncio.Event().wait()
        raise AssertionError("never reached")

    monkeypatch.setattr(debug_reparse, "_reparse", forever)
    task = asyncio.create_task(debug_reparse.reparse_body(Context(store=seeded, settings=edge), job))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert _stored(edge) == {"state": "error", "error": debug_reparse._STOPPED, "job_id": job.id}
    finished = await seeded.get_job(job.id)
    assert finished.state == "ok" and finished.detail == f"re-parse error: {debug_reparse._STOPPED}"


def test_the_executor_runs_debug_reparse_jobs():
    assert runtime.bodies()[debug_reparse.KIND] is debug_reparse.reparse_body


def _job_template() -> Any:
    from hst.app.store import Job

    now = datetime(2026, 9, 27, tzinfo=UTC)
    return Job(
        id=1,
        kind=debug_reparse.KIND,
        source=None,
        device=None,
        state="running",
        priority=1,
        attempt=1,
        max_attempts=1,
        not_before=now,
        lease_expires_at=None,
        claimed_by="w",
        enqueued_at=now,
        started_at=now,
        finished_at=None,
        detail=None,
        triggered_by="debug:1",
    )


def test_a_job_device_reads_back_as_the_payload():
    job = dataclasses.replace(_job_template(), device=debug_reparse.job_device("edge", "", RUN_ID))
    assert debug_reparse._payload_of(job) == ("edge", "", RUN_ID)
    for device in (None, "edge/r1", "edge/r1/not-a-run-id", f"/r1/{RUN_ID}", f"edge/a/b/{RUN_ID}"):
        assert debug_reparse._payload_of(dataclasses.replace(job, device=device)) is None
