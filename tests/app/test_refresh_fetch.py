"""A refresh fetches its devices the way a cycle does.

`launch` runs a press of one source, and the cold-start cycle a press falls
through to on an empty graph, with `concurrent=True`: the devices are fetched
through the cycle's `_FetchBuffer`, `collect_fetch_buffer` at a time, while the
loads stay serial behind them. A press loads every device it fetches, so what
the run holds is what the inline path, each device fetched inside its load,
gives it.

Only the pressed source can be cancelled alone, and a press whose source is
cancelled alone publishes nothing.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.app.fakes import FakeStore
from tests.app.test_runs_exec_fleet import _Cycle, _device, _Rt, _Rules, _Session, _source

from hst.app import runs_exec
from hst.app.crypto import generate_key
from hst.app.store import DeviceSpec
from hst.collectors.base import CollectionStopped
from hst.core import Settings, rawstore
from hst.core.model import RunManifest

PREV = 1_000
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


class _Device:
    """A device on the thread lane. With a `barrier` its fetch returns only
    once every fetch sharing the barrier has started, which a serial fetch
    never reaches."""

    def __init__(self, host: str, barrier: threading.Barrier | None = None, bad: bool = False) -> None:
        self.host = host
        self.scope = f"vyos:{host}"
        self.barrier = barrier
        self.bad = bad
        self.fetches = 0

    def fetch(self) -> dict[str, str]:
        self.fetches += 1
        if self.barrier is not None:
            self.barrier.wait()
        if self.bad:
            raise RuntimeError(f"{self.host} unreachable")
        return {"host": self.host, "config": f"hostname {self.host}"}


class _Coll:
    """`coll` as far as a refresh reaches it. `execute` fetches inline when it
    is handed no payload, as the real one does, and records what it loaded."""

    def __init__(self) -> None:
        self.loaded: list[tuple[str, dict[str, str]]] = []

    def raw_sha(self, collector: _Device, raw: dict[str, str]) -> str:
        return f"sha-{raw['host']}"

    def obs_sha(self, collector: _Device, raw: dict[str, str]) -> str:
        return ""

    def execute(
        self,
        collector: _Device,
        s: Any,
        *,
        collection_ts: int,
        source_name: str,
        raw: dict[str, str] | None = None,
        on_write: Any = None,
        fetch_window: tuple[int, int] | None = None,
    ) -> RunManifest:
        if raw is None:
            raw = collector.fetch()
        self.loaded.append((collector.host, raw))
        return RunManifest(
            run_id=f"{source_name}-{collector.host}", source=source_name, scope=collector.scope
        )


@pytest.fixture
def rig(monkeypatch, tmp_path):
    key = generate_key()
    built: list[int] = []

    def build(*, pointer: int | None = PREV) -> tuple[Settings, _Cycle, _Coll]:
        # a data directory per build, so two runs in one test publish apart
        built.append(len(built))
        settings = Settings(
            _env_file=None,
            hst_secret_key=key,
            hst_data_dir=tmp_path / f"data{built[-1]}",
            collect_thread_workers=4,
            collect_fetch_buffer=8,
        )
        cycle, coll = _Cycle(pointer), _Coll()
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "coll", coll)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        return settings, cycle, coll

    return build


def _fleet(name: str, *devices: _Device) -> runs_exec.PreparedSource:
    units = [runs_exec.PreparedDevice(_device(name, d.host), d, None) for d in devices]
    return runs_exec.PreparedSource(_source(name), units)


def test_a_concurrent_refresh_fetches_its_devices_at_the_same_time(rig):
    settings, cycle, coll = rig()
    barrier = threading.Barrier(3, timeout=30)
    fleet = _fleet("edge", *(_Device(h, barrier) for h in ("r1", "r2", "r3")))

    runs_exec.execute_refresh(settings, [fleet], "edge", concurrent=True)

    assert not barrier.broken
    assert [host for host, _ in coll.loaded] == ["r1", "r2", "r3"]  # the loads stay in order
    assert cycle.meta["statuses"] == {"edge": "fresh"}


def test_a_concurrent_refresh_publishes_what_the_inline_one_does(rig):
    def press(concurrent: bool) -> dict[str, Any]:
        settings, cycle, coll = rig()
        edge = _fleet("edge", _Device("r1"), _Device("r2", bad=True), _Device("r3"))
        other = _fleet("core", _Device("c1"))
        outs: list[runs_exec.DeviceOutcome] = []
        summary, ran, key, _ = runs_exec.execute_refresh(
            settings, [edge, other], "edge", outcomes=outs, concurrent=concurrent
        )
        return {
            "summary": summary,
            "key": key,
            "ran": [(row.name, d.host) for row, d, _ in ran],
            "meta": {k: v for k, v in cycle.meta.items() if k != "manifest_digest"},
            "carried": cycle.carried,
            "scopes": cycle.scopes,
            "collected": cycle.collected,
            "loaded": coll.loaded,
            "fetched": [d.fetches for p in (edge, other) for d in (u.collector for u in p.units)],
            "outcomes": [
                (o.source, o.host, o.ok, o.skipped, o.observations_only, o.full, o.error, o.tables)
                for o in outs
            ],
            "hashes": [(o.host, o.raw_sha) for o in outs],
        }

    inline, concurrent = press(False), press(True)

    for field in ("summary", "key", "ran", "meta", "carried", "scopes", "collected", "loaded", "fetched"):
        assert concurrent[field] == inline[field], field
    assert concurrent["outcomes"] == inline["outcomes"]
    assert inline["meta"]["statuses"] == {"edge": "partial", "core": "carried"}
    assert "edge/r2: RuntimeError: r2 unreachable" in inline["summary"]
    assert inline["hashes"] == [("r1", None), ("r2", None), ("r3", None)]
    assert concurrent["hashes"] == [("r1", "sha-r1"), ("r2", None), ("r3", "sha-r3")]


def test_the_cold_start_cycle_of_a_concurrent_refresh_fetches_concurrently(rig):
    """With no pointer a press runs one full cycle; it fetches every source's
    devices together, and none of them skips."""
    settings, cycle, coll = rig(pointer=None)
    barrier = threading.Barrier(3, timeout=30)
    edge = _fleet("edge", _Device("r1", barrier), _Device("r2", barrier))
    other = _fleet("core", _Device("c1", barrier))

    runs_exec.execute_refresh(settings, [edge, other], "edge", concurrent=True)

    assert not barrier.broken
    assert sorted(host for host, _ in coll.loaded) == ["c1", "r1", "r2"]
    assert cycle.meta["kind"] == "full"


def test_a_concurrent_refresh_removes_the_spill_files_an_earlier_run_left(rig):
    settings, _, _ = rig()
    stale = settings.raw_dir / rawstore.SPILL_DIR / f"1600000000000-bbbbbbbb{rawstore.SPILL_SUFFIX}"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"a payload a killed run sealed")

    runs_exec.execute_refresh(settings, [_fleet("edge", _Device("r1"))], "edge", concurrent=True)

    assert not stale.exists()


def test_a_press_whose_source_is_stopped_before_its_loads_publishes_nothing(rig):
    settings, cycle, coll = rig()
    fleet = _fleet("edge", _Device("r1"), _Device("r2"))
    stop = runs_exec.RunStop()
    stop.for_source("edge")
    stop.cancel_source("edge")

    with pytest.raises(RuntimeError, match="edge: cancelled by operator; nothing was published"):
        runs_exec.execute_refresh(settings, [fleet], "edge", stop=stop, concurrent=True)

    assert cycle.pointer == PREV and cycle.meta is None
    assert coll.loaded == []
    assert [u.collector.fetches for u in fleet.units] == [0, 0]


@pytest.mark.parametrize("concurrent", [False, True], ids=["inline", "concurrent"])
def test_a_press_whose_source_is_stopped_during_its_loads_publishes_nothing(rig, monkeypatch, concurrent):
    settings, cycle, coll = rig()
    fleet = _fleet("edge", _Device("r1"), _Device("r2"))
    stop = runs_exec.RunStop()
    load = coll.execute

    def execute(collector, s, **kw: Any) -> RunManifest:
        manifest = load(collector, s, **kw)
        stop.cancel_source("edge")
        return manifest

    monkeypatch.setattr(coll, "execute", execute)

    with pytest.raises(RuntimeError, match="edge: cancelled by operator; nothing was published"):
        runs_exec.execute_refresh(settings, [fleet], "edge", stop=stop, concurrent=concurrent)

    assert cycle.pointer == PREV and cycle.meta is None
    assert [host for host, _ in coll.loaded] == ["r1"]  # no device loads after the cancel


def test_a_press_gives_only_its_own_source_a_flag(rig):
    """Every other source is carried, so a cancel of one of them alone is
    answered as a source the run is not collecting."""
    settings, _, _ = rig()
    stop = runs_exec.RunStop()

    runs_exec.execute_refresh(
        settings, [_fleet("edge", _Device("r1")), _fleet("core", _Device("c1"))], "edge", stop=stop
    )

    assert set(stop.sources) == {"edge"}
    assert stop.cancel_source("core") is False


def test_the_cold_start_cycle_of_a_press_gives_every_source_a_flag(rig):
    settings, _, _ = rig(pointer=None)
    stop = runs_exec.RunStop()

    runs_exec.execute_refresh(
        settings, [_fleet("edge", _Device("r1")), _fleet("core", _Device("c1"))], "edge", stop=stop
    )

    assert set(stop.sources) == {"edge", "core"}


async def test_launch_presses_concurrently_and_records_what_each_device_did(tmp_path, monkeypatch):
    """A refresh's device outcomes carry the payload hashes a cycle's carry,
    and go to `device_status` as a cycle's do."""
    store = FakeStore()
    await store.create_source("edge", "vyos", {}, b"")
    await store.replace_devices("edge", [DeviceSpec("r1"), DeviceSpec("r2")])
    settings = Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)
    seen: dict[str, Any] = {}

    async def prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    def refresh(settings, prepared, name, assigned=None, *, outcomes=None, concurrent=False, **kw):
        seen["concurrent"] = concurrent
        outcomes.append(runs_exec.DeviceOutcome(name, "r1", True, raw_sha="sha-r1", obs_sha="", full=True))
        outcomes.append(runs_exec.DeviceOutcome(name, "r2", False, error="r2 unreachable"))
        return runs_exec.RunOutcome(f"refresh {name}", [], 7000)

    monkeypatch.setattr(runs_exec, "_prepare_all", prepare)
    monkeypatch.setattr(runs_exec, "execute_refresh", refresh)
    monkeypatch.setattr(runs_exec, "_RUNS", {})

    run = await runs_exec.launch(store, settings, "edge")
    assert run is not None
    finished = await asyncio.wait_for(runs_exec.wait_for_run(store, run), 30)

    assert finished.status == "ok"
    assert seen["concurrent"] is True
    status = {st.host: st for st in await store.list_device_status("edge")}
    assert status["r1"].last_raw_sha == "sha-r1" and status["r1"].last_full_at is not None
    assert status["r2"].consecutive_failures == 1 and status["r2"].last_error == "r2 unreachable"


def test_a_device_whose_fetch_the_cancel_of_its_source_ended_carries_as_cancelled(rig):
    """The cancel of one source lands while a fetch window is in flight, and
    ends the fetch of the device the loader asked for (`check_stop`). That
    device carries under `cancelled`, as the devices after it do, and is not
    recorded as a failed device; the rest of the cycle publishes."""
    settings, cycle, coll = rig()
    stop = runs_exec.RunStop()

    class _Cut(_Device):
        def fetch(self) -> dict[str, str]:
            self.fetches += 1
            stop.cancel_source("edge")
            raise CollectionStopped("collection cancelled")

    edge = _fleet("edge", _Cut("r1"), _Device("r2"))
    core = _fleet("core", _Device("c1"))
    outs: list[runs_exec.DeviceOutcome] = []

    summary, _, key, _ = runs_exec.execute_cycle(
        settings, [edge, core], {"edge", "core"}, prior={}, outcomes=outs, stop=stop
    )

    assert [(o.source, o.host, o.ok) for o in outs] == [("core", "c1", True)]
    assert cycle.meta["statuses"] == {"edge": "cancelled", "core": "fresh"}
    assert cycle.scopes == {"vyos:r1": "cancelled", "vyos:r2": "cancelled"}
    assert [host for host, _ in coll.loaded] == ["c1"]
    assert "edge: cancelled by operator; 2 of its devices are carried forward" in summary
    assert key is not None and cycle.pointer == key
