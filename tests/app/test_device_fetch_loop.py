"""Per-device collection work stays off the caller's event loop."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app.fakes import FakeStore

from hst.app import runs_exec
from hst.app.store import DeviceSpec
from hst.core import Settings

PAYLOAD = {"config": "x"}


class _AsyncDevice:
    """A collector on the async lane. `hold` blocks the loop its fetch runs on
    until the event is set; `park` suspends the
    fetch until it is cancelled."""

    VOLATILE_RAW_KEYS = ()

    def __init__(self, *, hold: threading.Event | None = None, park: bool = False) -> None:
        self.config = SimpleNamespace(transport="asyncssh")
        self.observed_host_key = ""
        self.observed_jump_key = ""
        self.hold = hold
        self.park = park
        self.thread: str | None = None
        self.started = threading.Event()
        self.cancelled = threading.Event()
        self.held: bool | None = None

    async def afetch(self) -> dict[str, str]:
        self.thread = threading.current_thread().name
        self.started.set()
        if self.hold is not None:
            self.held = self.hold.wait(10)
        if self.park:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
        return PAYLOAD


@pytest.fixture
async def fetching(monkeypatch, tmp_path):
    """A FakeStore with one fleet device, and the pipeline's seams patched:
    secrets resolve to nothing, the collector is the one the test sets, and
    parking records the payload."""
    store = FakeStore()
    await store.create_source("grp", "vyos", {}, b"")
    await store.replace_devices("grp", [DeviceSpec(host="r1")])
    built: dict[str, Any] = {}
    parked: list[Any] = []

    monkeypatch.setattr(runs_exec, "crypto", SimpleNamespace(dek=lambda s: b""))
    monkeypatch.setattr(runs_exec, "FernetResolver", lambda key: SimpleNamespace(resolve=lambda row: {}))
    monkeypatch.setattr(
        runs_exec.sources_glue, "build_device_collector", lambda row, d, s, **kw: built["collector"]
    )

    def park(collector, raw, *, source_name=None, **kw):
        parked.append(raw)
        return tmp_path / "1780000000000-abcd1234.json.gz.enc"

    monkeypatch.setattr(runs_exec.coll, "park", park)
    return SimpleNamespace(store=store, settings=Settings(_env_file=None), built=built, parked=parked)


async def test_an_async_fetch_runs_on_the_fetch_loop_while_the_callers_loop_goes_on(fetching):
    hold = threading.Event()
    device = fetching.built["collector"] = _AsyncDevice(hold=hold)

    task = asyncio.create_task(runs_exec.run_device_fetch(fetching.store, fetching.settings, "grp", "r1"))
    # the fetch blocks its loop until `hold` is set; this one has to keep running to set it
    assert await asyncio.to_thread(device.started.wait, 30), "the fetch never started"
    await asyncio.sleep(0)
    hold.set()
    detail = await asyncio.wait_for(task, 30)

    assert device.held is True, "the fetch held the caller's loop"
    assert device.thread == "device-fetch"
    assert "parked" in detail and fetching.parked == [PAYLOAD]


async def test_cancelling_the_job_cancels_the_fetch_on_the_fetch_loop(fetching):
    device = fetching.built["collector"] = _AsyncDevice(park=True)

    task = asyncio.create_task(runs_exec.run_device_fetch(fetching.store, fetching.settings, "grp", "r1"))
    assert await asyncio.to_thread(device.started.wait, 30), "the fetch never started"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert await asyncio.to_thread(device.cancelled.wait, 30), "the fetch went on after its job was cancelled"
    assert fetching.parked == []


def test_the_fetch_loop_is_shared_and_replaced_once_its_thread_has_ended():
    first = runs_exec._fetch_loop()
    assert runs_exec._fetch_loop() is first

    held = runs_exec._FETCH_LOOP
    assert held is not None
    loop, thread = held
    loop.call_soon_threadsafe(loop.stop)
    thread.join(30)
    assert not thread.is_alive()
    loop.close()

    second = runs_exec._fetch_loop()
    assert second is not first

    async def answer() -> str:
        return threading.current_thread().name

    assert asyncio.run_coroutine_threadsafe(answer(), second).result(30) == "device-fetch"


async def test_a_device_run_launch_walks_the_raw_store_off_the_loop(monkeypatch, tmp_path):
    """Both checks for parked payloads: the one before anything is prepared,
    and the one under the cycle lock that decides whether the run starts."""
    store = FakeStore()
    walks: list[int] = []
    answers = [["a parked payload"], []]

    def parked(raw_dir):
        walks.append(threading.get_ident())
        return answers.pop(0)

    async def prepare(store, settings):
        return [], {}

    async def capture(store, prepared=None):
        return runs_exec.ExecutionCapture()

    monkeypatch.setattr(runs_exec.rawstore, "parked", parked)
    monkeypatch.setattr(runs_exec, "_prepare_all", prepare)
    monkeypatch.setattr(runs_exec, "capture_execution", capture)

    run = await runs_exec.launch(store, Settings(_env_file=None, hst_data_dir=tmp_path), runs_exec.DEVICE_RUN)

    assert run is None and await store.list_runs() == []
    assert len(walks) == 2
    assert threading.get_ident() not in walks
