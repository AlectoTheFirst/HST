"""The detail of a `maintenance.build_device_run` job whose run ended with
its row still reading running, because the write that finishes the row
failed: the same words a queued run's job uses for that case
(worker/collect.py `_outcome`), not the row's own 'running'."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from tests.app.fakes import FakeStore

from hst.app import runs_exec
from hst.core import Settings
from hst.worker import maintenance
from hst.worker.maintenance import Context


async def _body(monkeypatch, run) -> str:
    async def run_blocking(store, settings, source):
        assert source == runs_exec.DEVICE_RUN
        return run

    monkeypatch.setattr(runs_exec, "run_blocking", run_blocking)
    ctx = Context(store=FakeStore(), settings=Settings(_env_file=None))
    return await maintenance._build_device_run_body(ctx, None)  # type: ignore[arg-type]


async def test_a_run_whose_row_was_not_finished_says_so(monkeypatch):
    store = FakeStore()
    run = await store.start_run(runs_exec.DEVICE_RUN, datetime.now(UTC))
    assert run is not None and run.status == "running"
    assert await _body(monkeypatch, run) == f"run {run.id} ended, and its outcome was not recorded"


async def test_a_finished_run_reads_its_status_and_the_head_of_its_detail(monkeypatch):
    store = FakeStore()
    run = await store.start_run(runs_exec.DEVICE_RUN, datetime.now(UTC))
    assert run is not None
    finished = replace(run, status="ok", detail="3 device(s) · 1 carried")
    assert await _body(monkeypatch, finished) == f"run {run.id} ok: 3 device(s)"
    assert await _body(monkeypatch, None) == "skipped: a run already holds the cycle claim"
