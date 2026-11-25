from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
import time
import weakref
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app.test_runs_exec_fleet import _Cycle, _device, _recent, _Rt, _Rules, _Session, _source, _status
from tests.test_collector_execute import FakeSession

from hst.app import runs_exec
from hst.app.crypto import dek, generate_key
from hst.collectors import base as collectors_base
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, rawstore
from hst.core.labels import CycleIdentityCollision
from hst.core.model import RunManifest

MIB = 1 << 20
PREV, NEW = 1_000, 2_000


class _Raw(dict):
    """A payload a weak reference can watch."""


def _big(host: str) -> _Raw:
    """A payload of about 1.25 MiB, above a 1 MiB threshold, the same for the
    same host on every call."""
    return _Raw(
        {"show running-config": f"hostname {host}\n" + "!\n" * (5 * MIB // 8), "show arp": f"arp {host}"}
    )


def _small(host: str) -> _Raw:
    return _Raw({"show running-config": f"hostname {host}\n", "show arp": f"arp {host}"})


class _Cfg(SourceConfig):
    host: str = ""
    transport: str = ""


class _Device(Collector):
    """A real collector around a payload builder: on the async lane when its
    transport is asyncssh, on the thread lane otherwise. `fetched` records the
    hosts whose fetch started, in order."""

    name = "fake"
    ConfigModel = _Cfg
    OBSERVATION_RAW_KEYS = ("show arp",)

    def __init__(self, settings: Settings, host: str, make: Any, *, transport: str = "asyncssh") -> None:
        super().__init__(_Cfg(host=host, source_name="edge", transport=transport), settings)
        self.host = host
        self.scope = f"fake:{host}"
        self._make = make
        self.fetched: list[str] = []

    def fetch(self) -> Any:
        self.fetched.append(self.host)
        return self._make(self.host)

    async def afetch(self) -> Any:
        await asyncio.sleep(0)
        return self.fetch()

    def normalize(self, raw: Any):
        b = GraphBuilder()
        b.node("Device", f"dev:{self.host}", hostname=self.host, role="router")
        return b.batch("edge", self.scope)

    def probe(self) -> str:
        return "ok"


def _settings(tmp_path: Path, **kw: Any) -> Settings:
    """Settings over a data directory whose data key already exists. Seals
    run on concurrent threads, and the first use of a data directory
    creates its key (`crypto.dek`): a thread that finds the key file created
    but not yet written cannot read it."""
    values: dict[str, Any] = {
        "_env_file": None,
        "hst_data_dir": tmp_path / "data",
        "hst_secret_key": generate_key(),
        "collect_spill_mb": 1,
        **kw,
    }
    settings = Settings(**values)
    dek(settings)
    return settings


def _unit(settings: Settings, host: str, make: Any = _big, *, transport: str = "asyncssh") -> tuple[str, Any]:
    collector = _Device(settings, host, make, transport=transport)
    return "edge", runs_exec.PreparedDevice(_device("edge", host), collector, None)


def _spill_files(settings: Settings) -> list[Path]:
    spill_dir = settings.raw_dir / rawstore.SPILL_DIR
    return sorted(spill_dir.iterdir()) if spill_dir.is_dir() else []


def _round_trip(payload: Any) -> Any:
    return json.loads(json.dumps(payload, default=str))


# --- _held_bytes ---------------------------------------------------------------------------


def test_held_bytes_is_the_getsizeof_sum_and_stops_at_its_bound():
    payload = {f"k{i}": "y" * 100_000 for i in range(100)}
    full = sys.getsizeof(payload) + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in payload.items())

    assert runs_exec._held_bytes(payload, 1 << 40) == full
    early = runs_exec._held_bytes(payload, 5000)
    assert 5000 <= early < full // 50


def test_held_bytes_counts_a_shared_container_once():
    shared = ["a" * 100, ("b" * 50,)]
    payload = {"x": shared, "y": shared}
    expected = (
        sys.getsizeof(payload)
        + sys.getsizeof("x")
        + sys.getsizeof("y")
        + sys.getsizeof(shared)
        + sys.getsizeof(shared[0])
        + sys.getsizeof(shared[1])
        + sys.getsizeof(shared[1][0])
    )

    assert runs_exec._held_bytes(payload, 1 << 40) == expected


def test_held_bytes_walks_a_dict_subclass():
    assert runs_exec._held_bytes(_Raw(config="z" * 5000), 1 << 40) > 5000


# --- what spills -----------------------------------------------------------------------------


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"], ids=["async-lane", "thread-lane"])
def test_a_payload_at_the_threshold_is_sealed_and_its_hashes_are_the_payloads(tmp_path, transport):
    settings = _settings(tmp_path)
    name, unit = _unit(settings, "r1", transport=transport)
    assert runs_exec._wants_loop(unit.collector) == (transport == "asyncssh")

    f = runs_exec._fetch_phase(settings, [(name, unit)], {}, False)[id(unit)]

    assert not f.error
    assert f.raw is None
    assert f.spilled is not None and f.spilled.path.is_file()
    assert (f.spilled.source, f.spilled.host, f.spilled.fetch_ts_ms) == ("edge", "r1", f.fetch_started_ms)
    payload = _big("r1")
    assert f.sha == runs_exec.coll.raw_sha(unit.collector, payload)
    assert f.obs == runs_exec.coll.obs_sha(unit.collector, payload)
    assert rawstore.read(f.spilled.path, dek(settings)) == _round_trip(payload)
    assert runs_exec._payload_kw(f) == {"sealed": f.spilled}


def test_nothing_spills_below_the_threshold_when_off_or_when_skipped(tmp_path):
    settings = _settings(tmp_path)
    small = _unit(settings, "small", _small)
    big = _unit(settings, "big")
    skip = _unit(settings, "skip")
    sha = runs_exec.coll.raw_sha(skip[1].collector, _big("skip"))
    obs = runs_exec.coll.obs_sha(skip[1].collector, _big("skip"))
    prior = {("edge", "skip"): _status("edge", "skip", sha, _recent(), obs=obs)}

    results = runs_exec._fetch_phase(settings, [small, skip], prior, True)
    off = runs_exec._fetch_phase(settings.model_copy(update={"collect_spill_mb": 0}), [big], {}, False)

    assert results[id(small[1])].raw == _small("small") and results[id(small[1])].spilled is None
    assert results[id(skip[1])].skipped
    assert results[id(skip[1])].raw is None and results[id(skip[1])].spilled is None
    assert off[id(big[1])].raw == _big("big") and off[id(big[1])].spilled is None
    assert runs_exec._payload_kw(off[id(big[1])]) == {"raw": off[id(big[1])].raw}
    assert not (settings.raw_dir / rawstore.SPILL_DIR).exists()


def test_a_spill_is_sealed_at_the_raw_compress_level(tmp_path, monkeypatch):
    settings = _settings(tmp_path, raw_compress_level=3)
    levels: list[int | None] = []
    real = rawstore.spill

    def recording(*args: Any, level: int | None = None, **kw: Any) -> rawstore.Spilled:
        levels.append(level)
        return real(*args, level=level, **kw)

    monkeypatch.setattr(rawstore, "spill", recording)

    runs_exec._fetch_phase(settings, [_unit(settings, "r1")], {}, False)

    assert levels == [3]


def test_a_spill_that_fails_keeps_the_payload_in_memory(tmp_path, monkeypatch, caplog):
    settings = _settings(tmp_path)

    def failing(*args: Any, **kw: Any) -> rawstore.Spilled:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(runs_exec.coll, "spill", failing)
    name, unit = _unit(settings, "r1")

    with caplog.at_level(logging.WARNING, logger=runs_exec.logger.name):
        f = runs_exec._fetch_phase(settings, [(name, unit)], {}, False)[id(unit)]

    assert f.spilled is None and f.raw == _big("r1")
    assert runs_exec._payload_kw(f) == {"raw": f.raw}
    assert any(
        "raw spill of edge/r1 failed; the payload is held in memory until its load" in r.getMessage()
        for r in caplog.records
    )


# --- the async lane's bound and its pool ----------------------------------------------------


def test_the_async_lane_holds_at_most_concurrency_plus_one_payloads(tmp_path, monkeypatch):
    """Thirty devices, two SSH slots, and the first seal held on the only
    post-fetch thread. Three fetches start, and no fourth until the seal is
    let go; at no point are more than three payloads alive."""
    settings = _settings(tmp_path, collect_max_concurrency=2, collect_thread_workers=1)
    release = threading.Event()
    watched: list[weakref.ref] = []
    state = SimpleNamespace(peak=0, at_release=None)
    real = runs_exec.coll.spill

    def watching(host: str) -> _Raw:
        state.peak = max(state.peak, sum(1 for ref in watched if ref() is not None) + 1)
        payload = _big(host)
        watched.append(weakref.ref(payload))
        return payload

    units = [_unit(settings, f"r{i:02d}", watching) for i in range(30)]

    def started() -> int:
        return sum(len(unit.collector.fetched) for _, unit in units)

    def held(*args: Any, **kw: Any) -> rawstore.Spilled:
        assert release.wait(timeout=30), "the seal was never let go"
        return real(*args, **kw)

    def let_go() -> None:
        deadline = time.monotonic() + 20
        while started() < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.3)  # time for a fourth fetch to start, were it admitted
        state.at_release = started()
        release.set()

    monkeypatch.setattr(runs_exec.coll, "spill", held)
    releaser = threading.Thread(target=let_go)
    releaser.start()
    try:
        results = runs_exec._fetch_phase(settings, units, {}, False)
    finally:
        release.set()
        releaser.join()

    assert state.at_release == 3
    assert state.peak <= 3
    assert all(f.spilled is not None and f.raw is None for f in results.values())
    assert len(_spill_files(settings)) == 30


def test_a_thread_lane_fetch_holding_every_fetch_thread_does_not_hold_async_hashing(tmp_path, monkeypatch):
    settings = _settings(tmp_path, collect_thread_workers=1)
    sealed_all = threading.Event()
    seen = SimpleNamespace(waited=None)
    count: list[str] = []
    real = runs_exec.coll.spill

    def recording(collector: Any, raw: Any, **kw: Any) -> rawstore.Spilled:
        spilled = real(collector, raw, **kw)
        count.append(collector.host)
        if len(count) == 3:
            sealed_all.set()
        return spilled

    def blocking(host: str) -> _Raw:
        seen.waited = sealed_all.wait(timeout=20)
        return _small(host)

    monkeypatch.setattr(runs_exec.coll, "spill", recording)
    units = [_unit(settings, "legacy", blocking, transport="paramiko")]
    units += [_unit(settings, f"a{i}") for i in range(3)]

    results = runs_exec._fetch_phase(settings, units, {}, False)

    assert seen.waited is True
    assert sorted(count) == ["a0", "a1", "a2"]
    assert all(not f.error for f in results.values())


def test_a_traced_thread_lane_spill_seals_its_trace_beside_the_adopted_file(tmp_path):
    settings = _settings(tmp_path, hst_http_trace="*")
    name, unit = _unit(settings, "r1", transport="paramiko")
    f = runs_exec._fetch_phase(settings, [(name, unit)], {}, False)[id(unit)]
    assert f.spilled is not None and f.trace is not None
    spool = f.trace.spool_path
    assert spool.exists()

    runs_exec.coll.execute(
        unit.collector,
        FakeSession(),
        collection_ts=NEW,
        source_name=name,
        **runs_exec._payload_kw(f),
        fetch_window=(f.fetch_started_ms, f.fetch_finished_ms),
        **runs_exec._trace_kw(f.trace),
    )

    assert f.spilled.final.is_file()
    assert rawstore.trace_path(f.spilled.final).is_file()
    assert not spool.exists()
    assert _spill_files(settings) == []


# --- what releases a spill -------------------------------------------------------------------


def _buffer(settings: Settings, hosts: list[str]) -> tuple[runs_exec._FetchBuffer, list[tuple[str, Any]]]:
    units = [_unit(settings, h) for h in hosts]
    return runs_exec._FetchBuffer(settings, units, {}, False), units


def test_discard_and_close_remove_the_spill_files_the_buffer_holds(tmp_path):
    settings = _settings(tmp_path)
    buffer, units = _buffer(settings, ["r0", "r1", "r2"])
    taken = buffer.get(id(units[0][1]))
    assert taken is not None and taken.spilled is not None
    held = [buffer._held[id(unit)].spilled for _, unit in units[1:]]
    assert all(s is not None and s.path.is_file() for s in held)

    buffer.discard(id(units[1][1]))
    assert not held[0].path.exists() and held[1].path.is_file()

    buffer.close()
    buffer.close()
    assert not held[1].path.exists()
    assert len(buffer) == 0
    # the result the loader took is its load's to adopt, not the buffer's
    assert taken.spilled.path.is_file()


def test_close_removes_every_spill_when_a_trace_cannot_be_discarded(tmp_path, caplog):
    class _Stuck:
        def discard(self) -> None:
            raise OSError(5, "Input/output error")

    settings = _settings(tmp_path)
    buffer, units = _buffer(settings, ["r0", "r1", "r2"])
    buffer.get(id(units[0][1]))
    first, second = (buffer._held[id(unit)] for _, unit in units[1:])
    first.trace = _Stuck()

    with caplog.at_level(logging.WARNING, logger=runs_exec.logger.name):
        buffer.close()

    assert not first.spilled.path.exists() and not second.spilled.path.exists()
    assert any("could not discard the http trace" in r.getMessage() for r in caplog.records)


def test_a_fetch_phase_that_raises_removes_the_spills_it_made(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    good_sealed = threading.Event()
    real_spill = runs_exec.coll.spill
    real_sha = runs_exec.coll.raw_sha

    def recording(*args: Any, **kw: Any) -> rawstore.Spilled:
        spilled = real_spill(*args, **kw)
        good_sealed.set()
        return spilled

    def failing(collector: Any, raw: Any) -> str:
        if collector.host == "bad":
            assert good_sealed.wait(timeout=20)
            raise RuntimeError("hash failed")
        return real_sha(collector, raw)

    monkeypatch.setattr(runs_exec.coll, "spill", recording)
    monkeypatch.setattr(runs_exec.coll, "raw_sha", failing)

    with pytest.raises(ExceptionGroup):
        runs_exec._fetch_phase(settings, [_unit(settings, "good"), _unit(settings, "bad")], {}, False)

    assert good_sealed.is_set()
    assert _spill_files(settings) == []


# --- a whole cycle ---------------------------------------------------------------------------


@pytest.fixture
def cycle_rig(monkeypatch):
    monkeypatch.setattr(runs_exec, "cycle", _Cycle(PREV))
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
    loads: list[SimpleNamespace] = []
    fail: set[str] = set()

    def load_payload(
        collector, session, raw, *, collection_ts, run_id, ts_ms, source_name=None, on_write=None
    ):
        loads.append(
            SimpleNamespace(kind="full", host=collector.host, raw=raw, run_id=run_id, cts=collection_ts)
        )
        if collector.host in fail:
            raise CycleIdentityCollision(f"uid dev:{collector.host} declared twice")
        return RunManifest(run_id=run_id, source=source_name or "", scope=collector.scope, finished_ms=ts_ms)

    def load_observations(collector, raw, *, collection_ts, run_id, ts_ms, source_name=None, on_write=None):
        loads.append(
            SimpleNamespace(
                kind="observations", host=collector.host, raw=raw, run_id=run_id, cts=collection_ts
            )
        )
        return RunManifest(run_id=run_id, source=source_name or "", scope=collector.scope, finished_ms=ts_ms)

    monkeypatch.setattr(collectors_base, "load_payload", load_payload)
    monkeypatch.setattr(collectors_base, "load_observations", load_observations)
    return SimpleNamespace(loads=loads, fail=fail)


def _fleet(units: list[tuple[str, Any]]) -> runs_exec.PreparedSource:
    return runs_exec.PreparedSource(_source("edge"), [unit for _, unit in units])


def _joined(path: Path) -> Any:
    return json.loads(rawstore.sibling(path, rawstore.META_SUFFIX).read_text())["snapshot_ts"]


def test_a_cycle_loads_a_spilled_payload_from_its_raw_file(tmp_path, cycle_rig):
    settings = _settings(tmp_path)
    units = [_unit(settings, "r1"), _unit(settings, "r2", _small)]
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_cycle(settings, [_fleet(units)], {"edge"}, None, {}, outs)

    by_host = {load.host: load for load in cycle_rig.loads}
    assert sorted(by_host) == ["r1", "r2"]
    big = by_host["r1"]
    assert big.kind == "full" and big.cts == NEW
    assert big.raw == _round_trip(_big("r1"))
    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", big.run_id)
    assert raw_path.is_file() and _joined(raw_path) == NEW
    assert big.run_id.split("-")[0] == str(next(o for o in outs if o.host == "r1").fetch_started_ms)
    outcome = {o.host: o for o in outs}
    assert outcome["r1"].ok and outcome["r1"].raw_sha == runs_exec.coll.raw_sha(
        units[0][1].collector, _big("r1")
    )
    assert by_host["r2"].raw == _small("r2")
    assert _spill_files(settings) == []


def test_a_cycle_publishes_a_spilled_observation_only_payload(tmp_path, cycle_rig):
    settings = _settings(tmp_path)
    name, unit = _unit(settings, "r1")
    sha = runs_exec.coll.raw_sha(unit.collector, _big("r1"))
    prior = {("edge", "r1"): _status("edge", "r1", sha, _recent(), obs="OLD-ARP")}
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_cycle(settings, [_fleet([(name, unit)])], {"edge"}, None, prior, outs)

    (load,) = cycle_rig.loads
    assert load.kind == "observations"
    assert load.raw == _round_trip(_big("r1"))
    assert _joined(rawstore.raw_path_of(settings.raw_dir, "edge", "r1", load.run_id)) == NEW
    (out,) = outs
    assert out.observations_only and out.raw_sha == sha
    assert _spill_files(settings) == []


def test_a_cycle_removes_the_spill_files_an_earlier_cycle_left(tmp_path, cycle_rig, caplog):
    settings = _settings(tmp_path)
    stale = settings.raw_dir / rawstore.SPILL_DIR / f"1600000000000-bbbbbbbb{rawstore.SPILL_SUFFIX}"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"a payload a killed cycle sealed")

    with caplog.at_level(logging.INFO, logger=runs_exec.logger.name):
        runs_exec.execute_cycle(settings, [_fleet([_unit(settings, "r1", _small)])], {"edge"}, None, {}, [])

    assert not stale.exists()
    assert any(
        "removed 1 spill file(s) of an earlier run from the raw store" in r.getMessage()
        for r in caplog.records
    )


def test_two_devices_that_draw_one_run_id_each_load_their_own_payload(tmp_path, cycle_rig, monkeypatch):
    settings = _settings(tmp_path)
    run_id = "1700000000000-aaaaaaaa"
    monkeypatch.setattr(collectors_base, "new_run_id", lambda fetch_ts_ms=None: run_id)
    units = [_unit(settings, "r1"), _unit(settings, "r2")]
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_cycle(settings, [_fleet(units)], {"edge"}, None, {}, outs)

    by_host = {load.host: load for load in cycle_rig.loads}
    assert sorted(by_host) == ["r1", "r2"]
    for host in ("r1", "r2"):
        assert by_host[host].run_id == run_id
        assert by_host[host].raw == _round_trip(_big(host))
        raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", host, run_id)
        assert rawstore.read(raw_path, dek(settings)) == _round_trip(_big(host))
    assert all(o.ok for o in outs)
    assert _spill_files(settings) == []


def _failing_evidence(monkeypatch, host: str) -> None:
    """`RunEvidence.on_write_for` raising for one host: the load of that
    device fails after the loop took its result and before `execute` or
    `execute_observations` runs, so its spill file is never moved."""
    real = runs_exec.RunEvidence.on_write_for

    def on_write_for(self: runs_exec.RunEvidence, collector: Any) -> Any:
        if getattr(collector, "host", None) == host:
            raise RuntimeError("evidence unavailable")
        return real(self, collector)

    monkeypatch.setattr(runs_exec.RunEvidence, "on_write_for", on_write_for)


def test_a_spilled_load_that_fails_before_its_file_is_moved_removes_it(tmp_path, cycle_rig, monkeypatch):
    settings = _settings(tmp_path)
    _failing_evidence(monkeypatch, "r1")
    units = [_unit(settings, f"r{i}") for i in range(3)]
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_cycle(settings, [_fleet(units)], {"edge"}, None, {}, outs)

    assert {o.host: o.ok for o in outs} == {"r0": True, "r1": False, "r2": True}
    assert sorted(load.host for load in cycle_rig.loads) == ["r0", "r2"]
    assert not (settings.raw_dir / "edge" / "r1").exists()
    assert _spill_files(settings) == []


def test_a_spilled_observation_only_publication_that_fails_first_removes_it(tmp_path, cycle_rig, monkeypatch):
    settings = _settings(tmp_path)
    _failing_evidence(monkeypatch, "r1")
    name, unit = _unit(settings, "r1")
    sha = runs_exec.coll.raw_sha(unit.collector, _big("r1"))
    prior = {("edge", "r1"): _status("edge", "r1", sha, _recent(), obs="OLD-ARP")}
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_cycle(settings, [_fleet([(name, unit)])], {"edge"}, None, prior, outs)

    (out,) = outs
    assert not out.ok and not out.observations_only and out.error == "RuntimeError: evidence unavailable"
    assert cycle_rig.loads == []
    assert not (settings.raw_dir / "edge" / "r1").exists()
    assert _spill_files(settings) == []


class _Abort(BaseException):
    """Neither an Exception nor a CycleIdentityCollision: nothing in the loop
    handles it."""


def test_a_base_exception_before_a_spill_is_moved_leaves_no_spill_behind(tmp_path, cycle_rig, monkeypatch):
    """The first load raises before it moves its spill file, while the rest
    of the window is held: the loop's finally removes the file of the result
    it took, and the buffer's close the files of the rest."""
    settings = _settings(tmp_path)
    units = [_unit(settings, f"r{i}") for i in range(4)]

    def aborting(*args: Any, **kw: Any) -> RunManifest:
        raise _Abort

    monkeypatch.setattr(runs_exec.coll, "execute", aborting)

    with pytest.raises(_Abort):
        runs_exec.execute_cycle(settings, [_fleet(units)], {"edge"}, None, {}, [])

    assert all(len(unit.collector.fetched) == 1 for _, unit in units), "one window held all four"
    assert cycle_rig.loads == []
    assert _spill_files(settings) == []


def test_a_cycle_that_fails_on_a_uid_collision_leaves_no_spill_behind(tmp_path, cycle_rig):
    """The first device's load fails the run after its spill file was moved
    to its raw path, while the rest of its window is held as spill files: the
    buffer's close removes those, and the device that was loaded keeps its
    joined raw file."""
    settings = _settings(tmp_path)
    units = [_unit(settings, f"r{i}") for i in range(4)]
    cycle_rig.fail.add("r0")

    with pytest.raises(CycleIdentityCollision):
        runs_exec.execute_cycle(settings, [_fleet(units)], {"edge"}, None, {}, [])

    (load,) = cycle_rig.loads
    assert load.host == "r0"
    assert _joined(rawstore.raw_path_of(settings.raw_dir, "edge", "r0", load.run_id)) == NEW
    assert all(len(unit.collector.fetched) == 1 for _, unit in units), "one window held all four"
    assert _spill_files(settings) == []
