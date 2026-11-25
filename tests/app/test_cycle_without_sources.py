"""A cycle with no enabled source publishes no run."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from typing import Any

import pytest
from tests.app.conftest import login

import hst.app.runs_exec as runs_exec
from hst.core import Settings


@pytest.fixture
def builds(monkeypatch) -> list[set[str]]:
    """The cycles that were built, by their fresh sources. The graph is out of reach: a cycle that
    opened a session, and so could move the pointer, fails its run."""
    built: list[set[str]] = []

    def execute_cycle(settings, prepared, fresh, assigned=None, prior=None, outcomes=None, **kw):
        built.append(set(fresh))
        return runs_exec.RunOutcome("cycle 7000: 1 nodes, 0 rels", [], 7000)

    @contextmanager
    def no_graph(*args: Any, **kwargs: Any):
        raise AssertionError("a cycle with no enabled source opened a graph session")
        yield

    monkeypatch.setattr(runs_exec, "execute_cycle", execute_cycle)
    monkeypatch.setattr(runs_exec.dbmod, "session", no_graph)
    return built


async def _wait_done(store, run_id: int) -> Any:
    for _ in range(300):
        run = next(r for r in await store.list_runs() if r.id == run_id)
        if run.status != "running":
            return run
        await asyncio.sleep(0.01)
    raise AssertionError("run never finished")


async def test_a_cycle_with_no_sources_publishes_nothing_and_says_so(client, seeded, builds):
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "cycle"})
    assert r.status_code == 202
    run = await _wait_done(seeded, r.json()["id"])

    assert (run.source, run.status) == ("cycle", "ok")
    assert run.detail == "no sources are configured; nothing was collected and no run was published"
    assert run.snapshot_key is None
    assert builds == []
    listing = (await client.get("/api/runs")).json()
    assert listing["runs"][0]["detail"] == runs_exec.NO_SOURCES


async def test_a_cycle_with_only_disabled_sources_publishes_nothing(seeded, builds):
    await seeded.create_source("paused", "manual", {"devices": ""}, b"", enabled=False)
    run = await runs_exec.run_blocking(seeded, Settings(_env_file=None), "cycle")

    assert run is not None
    assert (run.status, run.detail) == ("ok", runs_exec.NO_ENABLED_SOURCES)
    assert run.snapshot_key is None
    assert builds == []


async def test_a_cycle_with_an_enabled_source_builds_and_publishes(seeded, builds, monkeypatch):
    await seeded.create_source("vyos", "vyos", {}, b"")
    await seeded.create_source("paused", "manual", {"devices": ""}, b"", enabled=False)

    async def fake_prepare(store, settings):
        rows = await store.list_sources()
        return [runs_exec.PreparedSource(r, []) for r in rows], {}

    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)
    run = await runs_exec.run_blocking(seeded, Settings(_env_file=None), "cycle")

    assert run is not None
    assert (run.status, run.detail, run.snapshot_key) == ("ok", "cycle 7000: 1 nodes, 0 rels", "7000")
    assert builds == [{"vyos", "paused"}]
