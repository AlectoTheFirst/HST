"""A stopped run ends at its next device, and its cycle lock outlives its thread."""

from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.app.fakes import FakeStore
from tests.app.test_device_run import _Cycle as _DeviceRunCycle
from tests.app.test_device_run import _park, _prepared
from tests.app.test_device_run import _Rt as _DeviceRunRt
from tests.app.test_device_run import _Session as _DeviceRunSession
from tests.app.test_device_run import _settings as _device_run_settings
from tests.app.test_runs_exec_fleet import NEW, PREV, _Coll, _Cycle, _fleet, _Rt, _Rules, _Session, _settings

from hst.app import runs_exec
from hst.collectors.base import CollectionStopped
from hst.core import rawstore
from hst.core.model import RunManifest

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


# --- the reason a stopped builder ends with -------------------------------------------


def test_a_run_stopped_with_its_lock_held_says_so():
    stop = runs_exec.RunStop()
    stop.set()
    with pytest.raises(RuntimeError) as raised:
        runs_exec._stopped(stop)
    assert str(raised.value) == runs_exec.RUN_STOPPED


def test_a_lost_lock_is_named_as_such():
    stop = runs_exec.RunStop()
    stop.lose()
    assert stop.is_set() and stop.lost
    with pytest.raises(RuntimeError) as raised:
        runs_exec._stopped(stop)
    assert str(raised.value) == runs_exec.LOCK_LOST


def test_a_plain_event_carries_no_cause_and_reads_as_a_lost_lock():
    stop = threading.Event()
    stop.set()
    with pytest.raises(RuntimeError) as raised:
        runs_exec._stopped(stop)
    assert str(raised.value) == runs_exec.LOCK_LOST


def test_losing_the_lock_stops_every_source():
    stop = runs_exec.RunStop()
    edge = stop.for_source("edge")
    stop.lose()
    assert edge.is_set()


# --- before each device's load --------------------------------------------------------


class _StoppingColl(_Coll):
    """`coll.execute` that stops the run while it loads `stop_at`."""

    def __init__(self, stop: threading.Event, stop_at: str) -> None:
        super().__init__(set())
        self.stop = stop
        self.stop_at = stop_at

    def execute(self, collector, s, *, collection_ts, source_name, on_write=None) -> RunManifest:
        manifest = super().execute(collector, s, collection_ts=collection_ts, source_name=source_name)
        if collector.host == self.stop_at:
            self.stop.set()
        return manifest


class _Loser:
    """Stands where `_StoppingColl` expects a flag, and loses the lock."""

    def __init__(self, stop: runs_exec.RunStop) -> None:
        self._stop = stop

    def set(self) -> None:
        self._stop.lose()


@pytest.fixture
def stopping(monkeypatch):
    def build(stop: threading.Event, stop_at: str) -> tuple[_Cycle, _StoppingColl]:
        cycle = _Cycle(PREV)
        coll = _StoppingColl(stop, stop_at)
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "coll", coll)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        return cycle, coll

    return build


def test_a_cycle_stopped_during_a_load_loads_no_further_device(stopping):
    stop = runs_exec.RunStop()
    cycle, coll = stopping(stop, "r2")

    with pytest.raises(RuntimeError) as raised:
        runs_exec.execute_cycle(
            _settings(), [_fleet("edge", "r1", "r2", "r3"), _fleet("core", "r9")], {"edge", "core"}, stop=stop
        )

    assert str(raised.value) == runs_exec.RUN_STOPPED
    assert coll.ran == ["r1", "r2"]
    assert cycle.pointer == PREV and cycle.meta is None  # nothing published


def test_a_refresh_stopped_during_a_load_loads_no_further_device(stopping):
    stop = runs_exec.RunStop()
    cycle, coll = stopping(stop, "r1")

    with pytest.raises(RuntimeError) as raised:
        runs_exec.execute_refresh(_settings(), [_fleet("edge", "r1", "r2")], "edge", stop=stop)

    assert str(raised.value) == runs_exec.RUN_STOPPED
    assert coll.ran == ["r1"]
    assert cycle.pointer == PREV and cycle.meta is None


def test_a_cycle_whose_lock_is_lost_during_a_load_says_the_lock_was_lost(stopping):
    stop = runs_exec.RunStop()
    cycle, coll = stopping(stop, "r1")
    coll.stop = _Loser(stop)

    with pytest.raises(RuntimeError) as raised:
        runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1", "r2")], {"edge"}, stop=stop)

    assert str(raised.value) == runs_exec.LOCK_LOST
    assert coll.ran == ["r1"]
    assert cycle.pointer == PREV and cycle.meta is None


# --- a stop that cuts the last load short ----------------------------------------------


class _CuttingColl(_Coll):
    """`coll.execute` whose load of `at` ends the way a collector's
    `check_stop` ends it once `stop` is raised: the flag goes up (or the lock
    is lost, with `lose`) and the load raises `CollectionStopped`."""

    def __init__(self, stop: runs_exec.RunStop, at: str, *, lose: bool = False) -> None:
        super().__init__(set())
        self._stop = stop
        self._at = at
        self._lose = lose

    def execute(self, collector, s, *, collection_ts, source_name, on_write=None) -> RunManifest:
        if collector.host == self._at:
            if self._lose:
                self._stop.lose()
            else:
                self._stop.set()
            raise CollectionStopped("collection cancelled")
        return super().execute(collector, s, collection_ts=collection_ts, source_name=source_name)


@pytest.fixture
def cutting(monkeypatch):
    def build(stop: runs_exec.RunStop, at: str, *, lose: bool = False) -> tuple[_Cycle, _CuttingColl]:
        cycle = _Cycle(PREV)
        coll = _CuttingColl(stop, at, lose=lose)
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "coll", coll)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        return cycle, coll

    return build


@pytest.mark.parametrize("lose", [False, True], ids=["stopped", "lock-lost"])
def test_a_single_device_press_cut_short_by_a_stop_ends_with_the_stop_reason(cutting, lose):
    """The only device of the press fails with `CollectionStopped` and no
    device after it reads the flag. The run ends with the stop's own reason,
    not as a press whose one device failed."""
    stop = runs_exec.RunStop()
    cycle, _ = cutting(stop, "r1", lose=lose)

    with pytest.raises(RuntimeError) as raised:
        runs_exec.execute_refresh(_settings(), [_fleet("edge", "r1")], "edge", stop=stop)

    assert str(raised.value) == (runs_exec.LOCK_LOST if lose else runs_exec.RUN_STOPPED)
    assert cycle.pointer == PREV and cycle.meta is None


def test_a_cycle_whose_last_load_is_cut_short_ends_with_the_stop_reason(cutting):
    stop = runs_exec.RunStop()
    cycle, coll = cutting(stop, "r2", lose=True)

    with pytest.raises(RuntimeError) as raised:
        runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1", "r2")], {"edge"}, stop=stop)

    assert str(raised.value) == runs_exec.LOCK_LOST
    assert coll.ran == ["r1"]
    assert cycle.pointer == PREV and cycle.meta is None


# --- one source stopped alone while its devices load ------------------------------------


class _SourceCancellingColl(_Coll):
    """`coll.execute` that cancels source `source` alone once `at` has loaded,
    or, with `cut`, while `at` loads: that load then ends as a collector's
    `check_stop` ends it."""

    def __init__(self, stop: runs_exec.RunStop, source: str, at: str, *, cut: bool = False) -> None:
        super().__init__(set())
        self._stop = stop
        self._source = source
        self._at = at
        self._cut = cut

    def execute(self, collector, s, *, collection_ts, source_name, on_write=None) -> RunManifest:
        if self._cut and collector.host == self._at:
            self._stop.cancel_source(self._source)
            raise CollectionStopped("collection cancelled")
        manifest = super().execute(collector, s, collection_ts=collection_ts, source_name=source_name)
        if collector.host == self._at:
            self._stop.cancel_source(self._source)
        return manifest


@pytest.mark.parametrize("cut", [False, True], ids=["after-a-load", "during-a-load"])
def test_a_source_stopped_alone_during_its_loads_keeps_what_landed_and_carries_the_rest(monkeypatch, cut):
    """The device loaded before the cancel answered for itself; the one the
    cancel cut short and the ones after it carry under `cancelled`, none of
    them reads as a failed device, and the rest of the cycle publishes."""
    stop = runs_exec.RunStop()
    cycle = _Cycle(PREV)
    coll = _SourceCancellingColl(stop, "edge", "r2" if cut else "r1", cut=cut)
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec, "coll", coll)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
    outs: list[runs_exec.DeviceOutcome] = []

    summary, _, key, _ = runs_exec.execute_cycle(
        _settings(),
        [_fleet("edge", "r1", "r2", "r3"), _fleet("core", "r9")],
        {"edge", "core"},
        outcomes=outs,
        stop=stop,
    )

    assert coll.ran == ["r1", "r9"]
    assert cycle.meta["statuses"] == {"edge": "cancelled", "core": "fresh"}
    assert cycle.scopes == {"vyos:r2": "cancelled", "vyos:r3": "cancelled"}
    assert cycle.collected == {"vyos:r1", "vyos:r9"}
    assert "edge: cancelled by operator; 2 of its devices are carried forward" in summary
    assert [(o.host, o.ok) for o in outs] == [("r1", True), ("r9", True)]
    assert cycle.meta["degraded"] is True
    assert key == NEW and cycle.pointer == NEW


@pytest.fixture
def device_rig(monkeypatch, tmp_path):
    settings = _device_run_settings(tmp_path)
    cycle = _DeviceRunCycle(PREV)
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _DeviceRunRt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _DeviceRunSession())
    return settings, cycle


def test_a_device_run_stopped_during_a_load_applies_no_further_payload(device_rig, monkeypatch):
    settings, cycle = device_rig
    edge = _prepared(settings, "edge", "r1", "r2", "r3")
    for host in ("r1", "r2", "r3"):
        _park(edge, host)
    stop = runs_exec.RunStop()
    joined: list[str] = []
    real = runs_exec._join_payload

    def join(s, settings, collector, source_name, payload, cts, on_write=None, **kw: Any):
        joined.append(payload.host)
        manifest = real(s, settings, collector, source_name, payload, cts, on_write, **kw)
        stop.set()
        return manifest

    monkeypatch.setattr(runs_exec, "_join_payload", join)

    with pytest.raises(RuntimeError) as raised:
        runs_exec.build_device_run(settings, [edge], stop=stop)

    assert str(raised.value) == runs_exec.RUN_STOPPED
    assert len(joined) == 1
    assert cycle.pointer == PREV and cycle.meta is None
    # nothing settles for a run that did not publish: the window stays parked
    assert len(rawstore.parked(settings.raw_dir)) == 3


@pytest.mark.parametrize("lose", [False, True], ids=["stopped", "lock-lost"])
def test_a_device_run_whose_only_load_is_cut_short_ends_with_the_stop_reason(device_rig, monkeypatch, lose):
    settings, cycle = device_rig
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")
    stop = runs_exec.RunStop()

    def join(s, settings, collector, source_name, payload, cts, on_write=None, **kw: Any):
        if lose:
            stop.lose()
        else:
            stop.set()
        raise CollectionStopped("collection cancelled")

    monkeypatch.setattr(runs_exec, "_join_payload", join)

    with pytest.raises(RuntimeError) as raised:
        runs_exec.build_device_run(settings, [edge], stop=stop)

    assert str(raised.value) == (runs_exec.LOCK_LOST if lose else runs_exec.RUN_STOPPED)
    assert cycle.pointer == PREV and cycle.meta is None
    assert len(rawstore.parked(settings.raw_dir)) == 1


def test_a_device_run_hands_each_collector_the_run_flag_and_no_source_flag(device_rig):
    """What a collector polls between the stages of a load
    (`Collector.check_stop`) is the run's own flag: a device run is stopped
    only as a whole, so it has no source flags a cancel could raise."""
    settings, _ = device_rig
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")
    stop = runs_exec.RunStop()

    runs_exec.build_device_run(settings, [edge], stop=stop)

    (unit,) = edge.units
    assert unit.collector.stop is stop
    assert stop.sources == {}


def test_a_source_cancel_of_a_device_run_answers_that_it_is_not_collecting_it(device_rig, monkeypatch):
    settings, cycle = device_rig
    edge = _prepared(settings, "edge", "r1", "r2", "r3")
    for host in ("r1", "r2", "r3"):
        _park(edge, host)
    stop = runs_exec.RunStop()
    monkeypatch.setattr(runs_exec, "_RUNS", {42: (None, stop)})
    answers: list[bool] = []
    joined: list[str] = []
    real = runs_exec._join_payload

    def join(s, settings, collector, source_name, payload, cts, on_write=None, **kw: Any):
        joined.append(payload.host)
        manifest = real(s, settings, collector, source_name, payload, cts, on_write, **kw)
        if len(joined) == 1:
            answers.append(runs_exec.cancel_run(42, source="edge"))
        return manifest

    monkeypatch.setattr(runs_exec, "_join_payload", join)

    _, _, key, _ = runs_exec.build_device_run(settings, [edge], stop=stop)

    assert answers == [False]
    assert not stop.is_set()
    assert joined == ["r1", "r2", "r3"]
    assert key is not None and cycle.pointer == key
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert rawstore.parked(settings.raw_dir) == []


# --- the lock outlives the thread -----------------------------------------------------


async def test_the_lock_is_held_past_the_drain_timeout_until_the_thread_returns(monkeypatch, caplog):
    monkeypatch.setattr(runs_exec, "DRAIN_TIMEOUT_S", 0.05)
    store = FakeStore()
    started, release = threading.Event(), threading.Event()
    stop = runs_exec.RunStop()

    def stuck() -> runs_exec.RunOutcome:
        started.set()
        # a call that does not return when the stop flag is raised
        assert release.wait(30), "the builder thread was never released"
        return runs_exec.RunOutcome("late", [], None)

    async def holder() -> None:
        async with store.cycle_lock(on_lost=stop.lose):
            await runs_exec._drained(stop, stuck)

    task = asyncio.ensure_future(holder())
    try:
        assert await asyncio.to_thread(started.wait, 30), "the builder thread never started"
        with caplog.at_level(logging.ERROR, logger=runs_exec.logger.name):
            task.cancel()
            for _ in range(3000):
                if any("has not stopped" in r.getMessage() for r in caplog.records):
                    break
                await asyncio.sleep(0.01)
            assert any("the cycle lock stays held until it returns" in r.getMessage() for r in caplog.records)
        assert stop.is_set()
        assert not task.done()
        assert store._cycle_lock.locked(), "the lock was released while the builder thread ran"
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not store._cycle_lock.locked()


def test_a_loop_that_cancels_every_task_on_its_way_out_keeps_the_lock_until_the_thread_returns():
    """`asyncio.run` cancels every task left when its coroutine returns, which
    is how a process ends its loop. The builder thread is not a task: the lock
    it runs under is released after the thread returns, not when the loop
    cancels the wait for it.

    The thread gives the lock half a second to be released under it after its
    stop flag is raised; a release in that time is the defect, and the order
    of the two events records it."""
    order: list[str] = []
    started, released = threading.Event(), threading.Event()
    stop = runs_exec.RunStop()

    def builder() -> runs_exec.RunOutcome:
        started.set()
        assert stop.wait(30), "the stop flag was never raised"
        released.wait(0.5)
        order.append("thread returned")
        return runs_exec.RunOutcome("stopped", [], None)

    @asynccontextmanager
    async def lock():
        try:
            yield
        finally:
            order.append("lock released")
            released.set()

    async def holder() -> None:
        async with lock():
            await runs_exec._drained(stop, builder)

    tasks: set[asyncio.Task[None]] = set()

    async def main() -> None:
        tasks.add(asyncio.get_running_loop().create_task(holder()))
        assert await asyncio.to_thread(started.wait, 30), "the builder thread never started"
        # returning here leaves `holder` waiting; asyncio.run cancels it

    asyncio.run(main())

    assert order == ["thread returned", "lock released"]
