"""Crash injection: a kill during a paused graph write."""

from __future__ import annotations

import asyncio
import threading

import pytest
from tests.app.fakes import FakeStore

from hst.app.runs_exec import RunOutcome, _drained


async def test_a_cancelled_run_holds_the_cycle_lock_until_its_builder_thread_stops():
    store = FakeStore()
    started = threading.Event()
    finished = threading.Event()
    stop = threading.Event()

    def builder() -> RunOutcome:
        started.set()
        # "paused": blocked mid-write, as a real builder is between phases
        # (app/runs_exec.py `_stopped`), until told to stop
        stop.wait(5)
        finished.set()
        return RunOutcome("stopped early", [], None)

    async def holder() -> None:
        async with store.cycle_lock(on_lost=stop.set):
            await _drained(stop, builder)

    holder_task = asyncio.ensure_future(holder())
    for _ in range(200):
        if started.is_set():
            break
        await asyncio.sleep(0.01)
    assert started.is_set(), "the builder thread never started"

    peer_got_it = asyncio.Event()

    async def peer() -> None:
        async with store.cycle_lock():
            peer_got_it.set()

    peer_task = asyncio.ensure_future(peer())
    await asyncio.sleep(0)
    assert not peer_got_it.is_set(), "a peer must not acquire the lock while the builder still holds it"

    holder_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await holder_task

    assert finished.is_set()
    assert stop.is_set()

    await asyncio.wait_for(peer_task, 5)
    assert peer_got_it.is_set()
