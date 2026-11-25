from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from hst.app import runs_exec
from hst.app.store import Device
from hst.core import Settings

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


class _Gated:
    """A fake device on the async lane. Its fetch waits on one Event, so every
    fetch of the fleet becomes ready at the same moment and what the phase
    holds afterwards is decided by the queue and the semaphore alone. `live`
    holds the payloads the phase has produced and not yet handed on."""

    VOLATILE_RAW_KEYS = ()

    def __init__(self, host: str, gate: asyncio.Event, live: set[str]) -> None:
        self.config = SimpleNamespace(transport="asyncssh")
        self.host = host
        self.scope = f"fake:{host}"
        self._gate = gate
        self._live = live

    async def afetch(self) -> dict[str, str]:
        await self._gate.wait()
        self._live.add(self.host)
        return {"host": self.host, "config": "x" * 128}


def _units(count: int, gate: asyncio.Event, live: set[str]) -> list[tuple[str, Any]]:
    out = []
    for i in range(count):
        host = f"r{i:03d}"
        device = Device(i, "edge", host, None, True, "", NOW, NOW)
        out.append(("edge", runs_exec.PreparedDevice(device, _Gated(host, gate, live), None)))
    return out


async def test_the_fetch_phase_hands_payloads_on_instead_of_accumulating_them():
    gate = asyncio.Event()
    live: set[str] = set()
    settings = Settings(
        _env_file=None, collect_fetch_buffer=3, collect_max_concurrency=8, collect_thread_workers=4
    )
    units = _units(60, gate, live)
    consumed: list[int] = []

    async def sink(key: int, fetched: runs_exec._Fetched) -> None:
        consumed.append(key)
        live.discard(fetched.raw["host"])
        await asyncio.sleep(0)  # the serial loader: one payload at a time

    task = asyncio.ensure_future(runs_exec._fetch_phase_async(settings, units, {}, False, sink))
    await asyncio.sleep(0)
    assert live == set(), "every fake collector is blocked on the Event: nothing is fetched yet"

    gate.set()
    peak = 0
    while not task.done():
        peak = max(peak, len(live))
        await asyncio.sleep(0)
    results = await task

    assert len(consumed) == len(units)
    assert results == {}, "a consumer was given every result, so the phase kept none"
    assert peak <= settings.collect_fetch_buffer
    assert peak > 0, "the fleet was fetched, not skipped"

    gate2, live2 = asyncio.Event(), set()
    gate2.set()
    unbounded = await runs_exec._fetch_phase_async(settings, _units(60, gate2, live2), {}, False)
    assert len(unbounded) == 60 and len(live2) == 60


async def test_the_fetch_phase_reports_every_unit_through_its_consumer():
    """The queue changes what is held, not what is fetched: every unit reaches
    the consumer exactly once, with the payload its own fetch returned."""
    gate = asyncio.Event()
    gate.set()
    settings = Settings(_env_file=None, collect_fetch_buffer=2, collect_max_concurrency=4)
    units = _units(9, gate, set())
    seen: dict[int, str] = {}

    def sink(key: int, fetched: runs_exec._Fetched) -> None:
        assert key not in seen
        seen[key] = fetched.raw["host"]

    await runs_exec._fetch_phase_async(settings, units, {}, False, sink)

    assert seen == {id(unit): unit.collector.host for _, unit in units}


def test_the_buffer_holds_at_most_collect_fetch_buffer_payloads():
    """`_FetchBuffer` is what the serial load loop reads. It fetches the next
    window when the loop asks for a unit it does not hold, and drops each
    payload as the loop takes it, so a run of any size holds at most
    `collect_fetch_buffer` payloads at once."""
    gate = asyncio.Event()
    gate.set()
    settings = Settings(_env_file=None, collect_fetch_buffer=4, collect_max_concurrency=4)
    units = _units(30, gate, set())
    buffer = runs_exec._FetchBuffer(settings, units, {}, False)

    hosts = []
    for _, unit in units:  # the order `_collect_sources` asks in
        assert len(buffer) <= settings.collect_fetch_buffer
        fetched = buffer.get(id(unit))
        assert fetched is not None and not fetched.error
        hosts.append(fetched.raw["host"])
        assert len(buffer) <= settings.collect_fetch_buffer

    assert hosts == [unit.collector.host for _, unit in units]
    assert len(buffer) == 0, "the last window's payloads are released as they are read"
    assert buffer.get(id(units[0][1])) is None, "a payload the loop has taken is not held twice"
