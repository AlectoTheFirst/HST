"""What the fetch hand-off releases while the load loop runs.

`_FetchBuffer` bounds a cycle's payloads to one window, and three places can
hold a payload past its last reader: the buffer, for a unit of a source an
operator stopped, which the loop never asks for; the loop variable, which
binds the previous device's result while the next ask fetches a whole window;
and the async fetch lane, if it hashes a payload while holding an SSH slot.
The buffer drops a discarded unit's payload and never fetches it, the loop
unbinds its result before the next ask, and the lane hashes after it gives
the slot back. These are the tests of all three.
"""

from __future__ import annotations

import asyncio
import gc
import threading
import types
import weakref
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app.test_runs_exec_fleet import (
    _CollWithFetch,
    _Cycle,
    _FetchingCollector,
    _Rt,
    _Rules,
    _Session,
    _settings,
    _source,
)

from hst.app import runs_exec
from hst.app.store import Device
from hst.core import Settings

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)


class _Counted:
    VOLATILE_RAW_KEYS = ()

    def __init__(self, host: str, fetched: list[str]) -> None:
        self.config = SimpleNamespace(transport="asyncssh")
        self.host = host
        self.scope = f"fake:{host}"
        self._fetched = fetched

    async def afetch(self) -> dict[str, str]:
        self._fetched.append(self.host)
        return {"host": self.host, "config": "x" * 128}


def _device(source: str, host: str) -> Device:
    return Device(1, source, host, None, True, "", NOW, NOW)


def _units(count: int, fetched: list[str]) -> list[tuple[str, Any]]:
    hosts = [f"r{i:03d}" for i in range(count)]
    return [("edge", runs_exec.PreparedDevice(_device("edge", h), _Counted(h, fetched), None)) for h in hosts]


def _buffer(size: int, units: list[tuple[str, Any]]) -> runs_exec._FetchBuffer:
    settings = Settings(_env_file=None, collect_fetch_buffer=size, collect_max_concurrency=4)
    return runs_exec._FetchBuffer(settings, units, {}, False)


def _windows(monkeypatch) -> list[list[str]]:
    """The hosts of every window the buffer fetches, in order."""
    seen: list[list[str]] = []
    real = runs_exec._fetch_phase

    def recording(settings, units, prior, allow_skip, progress=None):
        seen.append([unit.collector.host for _, unit in units])
        return real(settings, units, prior, allow_skip, progress)

    monkeypatch.setattr(runs_exec, "_fetch_phase", recording)
    return seen


# --- _FetchBuffer.discard ------------------------------------------------------------


def test_discard_drops_a_payload_the_buffer_already_holds():
    fetched: list[str] = []
    units = _units(6, fetched)
    buffer = _buffer(4, units)

    first = buffer.get(id(units[0][1]))
    assert first is not None and first.raw["host"] == "r000"
    assert len(buffer) == 3, "the rest of the first window waits in the buffer"

    buffer.discard(id(units[2][1]))

    assert len(buffer) == 2
    assert id(units[2][1]) not in list(buffer)
    assert buffer.get(id(units[1][1])).raw["host"] == "r001"
    assert buffer.get(id(units[3][1])).raw["host"] == "r003"


def test_discard_ends_the_http_trace_of_a_payload_it_drops():
    """A dropped payload is never sealed, so nothing else would end its trace."""

    class _Trace:
        discarded = 0

        def discard(self) -> None:
            self.discarded += 1

    fetched: list[str] = []
    units = _units(3, fetched)
    buffer = _buffer(3, units)
    buffer.get(id(units[0][1]))
    held = buffer._held[id(units[1][1])]
    held.trace = trace = _Trace()

    buffer.discard(id(units[1][1]))
    buffer.discard(id(units[1][1]))

    assert trace.discarded == 1


def test_a_discarded_unit_of_a_later_window_is_never_fetched(monkeypatch):
    fetched: list[str] = []
    units = _units(10, fetched)
    buffer = _buffer(3, units)
    windows = _windows(monkeypatch)

    assert buffer.get(id(units[0][1])) is not None
    for _, unit in units[4:6]:
        buffer.discard(id(unit))
    for _, unit in units[1:]:
        if unit.collector.host in ("r004", "r005"):
            continue
        got = buffer.get(id(unit))
        assert got is not None and got.raw["host"] == unit.collector.host

    assert len(fetched) == 8
    assert "r004" not in fetched and "r005" not in fetched
    # a window leaves the discarded units out and fills itself from the next ones
    assert windows == [["r000", "r001", "r002"], ["r003", "r006", "r007"], ["r008", "r009"]]
    assert len(buffer) == 0


def test_get_of_a_discarded_unit_answers_none_and_fetches_nothing(monkeypatch):
    fetched: list[str] = []
    units = _units(8, fetched)
    buffer = _buffer(3, units)
    windows = _windows(monkeypatch)

    buffer.get(id(units[0][1]))
    held, later = id(units[1][1]), id(units[5][1])
    buffer.discard(held)  # already fetched and held
    buffer.discard(later)  # in a window not fetched yet

    assert buffer.get(held) is None
    assert buffer.get(later) is None
    with pytest.raises(KeyError):
        buffer[later]
    assert len(windows) == 1, "asking for a discarded unit fetches no window"
    assert fetched == ["r000", "r001", "r002"]


def test_windows_hold_at_most_collect_fetch_buffer_units(monkeypatch):
    fetched: list[str] = []
    units = _units(23, fetched)
    buffer = _buffer(4, units)
    windows = _windows(monkeypatch)
    dropped = {3, 7, 8, 9, 10, 15, 22}
    for index in dropped:
        buffer.discard(id(units[index][1]))

    for index, (_, unit) in enumerate(units):
        if index in dropped:
            continue
        assert buffer.get(id(unit)) is not None
        assert len(buffer) <= 4

    # sixteen units left to fetch, in full windows: skipping a discarded
    # unit neither shrinks a window nor lets one grow past the bound
    assert [len(w) for w in windows] == [4, 4, 4, 4]
    assert fetched == [f"r{i:03d}" for i in range(23) if i not in dropped]


def test_discard_on_the_hand_off_a_refresh_passes():
    """A refresh hands the loop a plain dict. Discarding pops the entry when
    there is one; a mapping the loop cannot write is left as it is."""
    plain: dict[int, runs_exec._Fetched] = {1: runs_exec._Fetched({"x": 1}), 2: runs_exec._Fetched()}
    runs_exec._discard_fetched(plain, 1)
    runs_exec._discard_fetched(plain, 3)
    assert list(plain) == [2]

    frozen = types.MappingProxyType({1: runs_exec._Fetched()})
    runs_exec._discard_fetched(frozen, 1)
    assert list(frozen) == [1]


# --- _collect_sources ------------------------------------------------------------------


class _Raw(dict):
    """A payload a weak reference can watch."""


class _WatchedCollector(_FetchingCollector):
    """`_FetchingCollector`, fetched on the thread lane, whose payload can be
    watched and whose fetches are counted per host."""

    def __init__(self, host: str, fetches: list[str]) -> None:
        super().__init__(host, sha=f"SHA-{host}")
        self._fetches = fetches

    def fetch(self) -> _Raw:
        self._fetches.append(self.host)
        return _Raw(super().fetch())


@pytest.fixture
def cycle_rig(monkeypatch):
    """The fakes `rig2` in test_runs_exec_fleet.py installs, and a spy on the
    buffer the cycle builds: every unit id the loop discards, and, each time
    the loop asks for a unit, whether the payload of the unit it asked for
    before is still alive."""
    cycle = _Cycle(1_000)
    coll = _CollWithFetch(set())
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec, "coll", coll)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())

    spy = SimpleNamespace(discarded=[], asked=[], alive_at_next_ask=[], previous=None)

    class _SpyBuffer(runs_exec._FetchBuffer):
        def discard(self, key: int) -> None:
            spy.discarded.append(key)
            super().discard(key)

        def __getitem__(self, key: int) -> runs_exec._Fetched:
            if spy.previous is not None:
                gc.collect()
                spy.alive_at_next_ask.append(spy.previous() is not None)
            spy.asked.append(key)
            fetched = super().__getitem__(key)
            spy.previous = weakref.ref(fetched.raw) if isinstance(fetched.raw, _Raw) else None
            return fetched

    monkeypatch.setattr(runs_exec, "_FetchBuffer", _SpyBuffer)
    return cycle, coll, spy


def _fleet(name: str, collectors: list[_WatchedCollector]) -> runs_exec.PreparedSource:
    units = [runs_exec.PreparedDevice(_device(name, c.host), c, None) for c in collectors]
    return runs_exec.PreparedSource(_source(name), units)


def test_a_cancelled_sources_units_are_discarded_and_never_fetched(cycle_rig):
    cycle, coll, spy = cycle_rig
    fetches: list[str] = []
    edge = _fleet("edge", [_WatchedCollector(h, fetches) for h in ("e1", "e2", "e3")])
    core = _fleet("core", [_WatchedCollector(h, fetches) for h in ("c1", "c2")])
    stop = runs_exec.RunStop()
    stop.for_source("edge")
    stop.for_source("core")
    stop.cancel_source("edge")

    runs_exec.execute_cycle(_settings(), [edge, core], {"edge", "core"}, stop=stop, prior={})

    assert spy.discarded == [id(u) for u in edge.units]
    assert sorted(fetches) == ["c1", "c2"], "a stopped source is not fetched for nobody"
    assert coll.ran == ["c1", "c2"]
    assert cycle.meta["statuses"] == {"edge": "cancelled", "core": "fresh"}


def test_a_cancelled_source_after_a_fetched_window_drops_what_it_held(cycle_rig):
    """The stopped source's units were fetched in the window the source
    before it opened. Its payloads go as the loop passes the source, not when
    the run ends."""
    _, coll, spy = cycle_rig
    fetches: list[str] = []
    core = _fleet("core", [_WatchedCollector("c1", fetches)])
    edge = _fleet("edge", [_WatchedCollector(h, fetches) for h in ("e1", "e2")])
    stop = runs_exec.RunStop()
    stop.for_source("core")
    stop.for_source("edge")
    stop.cancel_source("edge")

    runs_exec.execute_cycle(_settings(), [core, edge], {"core", "edge"}, stop=stop, prior={})

    assert sorted(fetches) == ["c1", "e1", "e2"], "one window held all three"
    assert spy.discarded == [id(u) for u in edge.units]
    assert coll.ran == ["c1"]


def test_the_previous_units_payload_is_gone_when_the_loop_asks_for_the_next(cycle_rig):
    _, coll, spy = cycle_rig
    fetches: list[str] = []
    hosts = [f"r{i}" for i in range(7)]
    edge = _fleet("edge", [_WatchedCollector(h, fetches) for h in hosts])
    settings = _settings().model_copy(update={"collect_fetch_buffer": 2})

    runs_exec.execute_cycle(settings, [edge], {"edge"}, prior={})

    assert coll.ran == hosts
    assert len(spy.asked) == 7
    assert spy.alive_at_next_ask == [False] * 6


# --- the async lane --------------------------------------------------------------------


def test_hashing_a_payload_does_not_hold_the_ssh_slot(monkeypatch):
    events: list[str] = []
    second_started = threading.Event()

    class _Ordered:
        VOLATILE_RAW_KEYS = ()

        def __init__(self, host: str) -> None:
            self.config = SimpleNamespace(transport="asyncssh")
            self.host = host
            self.scope = f"fake:{host}"

        async def afetch(self) -> dict[str, str]:
            events.append(f"fetch {self.host}")
            if self.host == "r001":
                second_started.set()
            await asyncio.sleep(0)
            return {"host": self.host}

    real_sha = runs_exec.coll.raw_sha

    def held_sha(collector: Any, raw: Any) -> str:
        if raw["host"] == "r000":
            events.append("hash r000 start")
            assert second_started.wait(timeout=10), "the second fetch waited for the first hash"
            events.append("hash r000 end")
        return real_sha(collector, raw)

    monkeypatch.setattr(runs_exec.coll, "raw_sha", held_sha)
    settings = Settings(
        _env_file=None, collect_max_concurrency=1, collect_thread_workers=2, collect_fetch_buffer=4
    )
    units = [
        ("edge", runs_exec.PreparedDevice(_device("edge", h), _Ordered(h), None)) for h in ("r000", "r001")
    ]

    results = runs_exec._fetch_phase(settings, units, {}, False)

    assert all(not f.error for f in results.values())
    assert events.index("fetch r001") < events.index("hash r000 end")
