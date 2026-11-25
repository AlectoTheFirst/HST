"""A source cancel that reaches a run before the run has handed its
collectors their stop flags, as a cycle waiting for the cycle lock has not,
is kept until the run is armed and then applied (`runs_exec._watch_cancel_requests`,
`RunStop.armed`); once armed, a source without a flag is one the run is not
collecting. And the 404 a source cancel of a run that is not running gets."""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.core import Settings, run_cancel


@pytest.fixture(autouse=True)
def _own_run_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs_exec, "_RUNS", {})
    monkeypatch.setattr(runs_exec, "CANCEL_POLL_S", 0.01)


@pytest.fixture
def settings(tmp_path: Any) -> Settings:
    return Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)


def _requests(settings: Settings) -> list[Any]:
    directory = settings.hst_data_dir / run_cancel.DIRECTORY
    return sorted(directory.glob("*.json")) if directory.exists() else []


class _Refresh:
    """A refresh of `unifi` that waits for `arm` before it hands out its stop
    flags, then waits for its source's flag and ends."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.arm = threading.Event()
        self.armed = threading.Event()
        self.flag_seen = threading.Event()

    def __call__(
        self, settings: Any, prepared: Any, name: str, assigned: Any = None, *, stop: Any = None, **kw: Any
    ):
        assert isinstance(stop, runs_exec.RunStop)
        self.entered.set()
        assert self.arm.wait(10), "the test never armed the run"
        runs_exec._arm_stop([p for p in prepared if p.row.name == name], stop)
        self.armed.set()
        if stop.sources[name].wait(10):
            self.flag_seen.set()
        raise RuntimeError("stopped at a phase boundary")


async def _launched(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> tuple[FakeStore, Any, _Refresh]:
    store = FakeStore()
    await store.create_source("unifi", "unifi", {}, b"")

    async def fake_prepare(store: Any, settings: Any) -> Any:
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    refresh = _Refresh()
    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)
    monkeypatch.setattr(runs_exec, "execute_refresh", refresh)
    run = await runs_exec.launch(store, settings, "unifi")
    assert run is not None
    assert await asyncio.to_thread(refresh.entered.wait, 10), "the run never started"
    return store, run, refresh


async def _polled(settings: Settings) -> None:
    for _ in range(500):
        if not _requests(settings):
            break
        await asyncio.sleep(0.01)
    assert _requests(settings) == [], "the watcher never took the request"
    await asyncio.sleep(0.05)


async def test_a_source_request_taken_before_the_run_is_armed_is_applied_once_it_is(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    store, run, refresh = await _launched(monkeypatch, settings)
    stop = runs_exec._RUNS[run.id][1]
    run_cancel.request(settings, run.id, run.started_at, by="ada", source="unifi")

    await _polled(settings)
    assert not stop.armed
    assert "unifi" not in stop.sources

    refresh.arm.set()
    assert await asyncio.to_thread(refresh.flag_seen.wait, 10), "the kept request was never applied"
    await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)


async def test_once_armed_a_request_for_a_source_the_run_does_not_collect_is_dropped(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    store, run, refresh = await _launched(monkeypatch, settings)
    stop = runs_exec._RUNS[run.id][1]
    run_cancel.request(settings, run.id, run.started_at, by="ada", source="vco")
    refresh.arm.set()
    assert await asyncio.to_thread(refresh.armed.wait, 10)

    with caplog.at_level(logging.INFO, logger=runs_exec.logger.name):
        await _polled(settings)
        for _ in range(500):
            if "which this run is not collecting" in caplog.text:
                break
            await asyncio.sleep(0.01)

    assert "the cancel request of ada names vco, which this run is not collecting" in caplog.text
    assert "vco" not in stop.sources
    runs_exec.cancel_run(run.id, by="test")
    await asyncio.wait_for(runs_exec.wait_for_run(store, run), 10)


def test_a_run_is_armed_once_every_flag_is_handed_out() -> None:
    stop = runs_exec.RunStop()
    assert not stop.armed
    runs_exec._arm_stop([], stop)
    assert stop.armed
    device_run = runs_exec.RunStop()
    runs_exec._arm_stop([], device_run, per_source=False)
    assert device_run.armed and device_run.sources == {}


# --- the route --------------------------------------------------------------------------


async def test_a_source_cancel_of_a_finished_run_says_the_run_is_not_collecting_it(
    seeded: FakeStore, settings: Settings
) -> None:
    await seeded.create_source("unifi", "unifi", {}, b"")
    run = await seeded.start_run("unifi", datetime.now(UTC) - timedelta(minutes=1))
    assert run is not None
    await seeded.finish_run(run.id, "ok", datetime.now(UTC), "done")
    app = create_app(settings=settings, store=seeded)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "otto")
        by_source = await client.post(f"/api/runs/{run.id}/cancel", json={"source": "unifi"})
        whole = await client.post(f"/api/runs/{run.id}/cancel")

    assert by_source.status_code == 404
    assert by_source.json()["error"] == f"run {run.id} is not collecting unifi on this instance"
    assert whole.status_code == 404
    assert whole.json()["error"] == f"run {run.id} is not running on this instance"
    assert _requests(settings) == []
