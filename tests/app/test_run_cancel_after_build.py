"""A cancel that lands once a run is built does not undo its bookkeeping.

The pointer moves in the builder thread (`_finalize_cycle`), and from then on
the run is published: the device statuses the next run's skip decisions
compare against, the host-key pins and the inventory publication have to be
recorded for it, and the row has to name it. A cancel that arrives after the
builder's last stop check is either refused (`RunStop.built`: `cancel_run`,
`wait_for_run`, the cancel route's 409) or, when it reached the task before
the builder returned, consumed by `_drained`, which returns the run the
builder published. Any other cancellation of the task, a process on its way
out, does not cut the recording short (`_settled`).

A refresh whose one source is cancelled alone publishes nothing and finishes
as `cancelled` (`RunCancelled`), as the cancel route answered.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime

from tests.app.conftest import login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.core import Settings

KEY = 7000


async def _store() -> FakeStore:
    store = FakeStore()
    await store.create_source("unifi", "unifi", {}, b"")
    return store


def _stub_prepare(monkeypatch) -> None:
    async def prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    monkeypatch.setattr(runs_exec, "_prepare_all", prepare)


def _outcomes(count: int) -> list[runs_exec.DeviceOutcome]:
    return [
        runs_exec.DeviceOutcome("unifi", f"h{i}", True, raw_sha=f"r{i}", graph_sha=f"g{i}", full=True)
        for i in range(count)
    ]


async def _finished(store: FakeStore, run_id: int):
    for _ in range(1000):
        run = await store.get_run(run_id)
        if run is not None and run.status != "running":
            return run
        await asyncio.sleep(0.01)
    raise AssertionError("the run never finished")


def _slow_statuses(store: FakeStore, entered: asyncio.Event) -> None:
    """Each status write waits a little, so a cancel can land between two."""
    real = store.upsert_device_status

    async def slow(*args, **kwargs):
        entered.set()
        await asyncio.sleep(0.05)
        return await real(*args, **kwargs)

    store.upsert_device_status = slow  # type: ignore[method-assign]


def _publishing_cycle(monkeypatch, count: int) -> None:
    """A cycle builder that publishes `KEY` the way `_finalize_cycle` does:
    the pointer moves, and the run's stop flag records that it is built."""

    def builder(settings, prepared, fresh, assigned, prior, outs, *, stop=None, **kw):
        outs.extend(_outcomes(count))
        if isinstance(stop, runs_exec.RunStop):
            stop.built = True
        return runs_exec.RunOutcome(f"cycle {KEY}", [], KEY)

    monkeypatch.setattr(runs_exec, "execute_cycle", builder)


async def test_a_cancel_after_the_run_is_built_is_refused_and_every_status_is_recorded(monkeypatch):
    store = await _store()
    _stub_prepare(monkeypatch)
    _publishing_cycle(monkeypatch, 5)
    entered = asyncio.Event()
    _slow_statuses(store, entered)

    run = await runs_exec.launch(store, Settings(_env_file=None), "cycle")
    assert run is not None
    await asyncio.wait_for(entered.wait(), 10)

    assert runs_exec.cancel_run(run.id, by="otto") is False
    assert await runs_exec.request_cancel(store, Settings(_env_file=None), run.id, by="otto") == "built"

    row = await _finished(store, run.id)
    assert (row.status, row.detail, row.snapshot_key) == ("ok", f"cycle {KEY}", str(KEY))
    assert len(await store.list_device_status()) == 5


async def test_a_task_cancelled_while_a_built_run_records_its_statuses_records_them_all(monkeypatch):
    """What a process on its way out does: it cancels the task itself, past
    `cancel_run`."""
    store = await _store()
    _stub_prepare(monkeypatch)
    _publishing_cycle(monkeypatch, 5)
    entered = asyncio.Event()
    _slow_statuses(store, entered)

    run = await runs_exec.launch(store, Settings(_env_file=None), "cycle")
    assert run is not None
    task, _ = runs_exec._RUNS[run.id]
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel("the process is stopping")
    task.cancel("and again")

    row = await _finished(store, run.id)
    assert (row.status, row.snapshot_key) == ("ok", str(KEY))
    assert {st.host for st in await store.list_device_status()} == {f"h{i}" for i in range(5)}
    assert not store._cycle_lock.locked()


async def test_a_cancel_the_builder_did_not_see_before_it_published_keeps_the_published_run(monkeypatch):
    """The cancel reaches the task while the builder is past its last stop
    check: the row records the run it published, with its statuses, and says
    that the cancel came too late."""
    store = await _store()
    _stub_prepare(monkeypatch)
    started, go = threading.Event(), threading.Event()

    def builder(settings, prepared, fresh, assigned, prior, outs, *, stop=None, **kw):
        started.set()
        # past the last stop check: the pointer is being set
        assert go.wait(10), "the builder was never released"
        outs.extend(_outcomes(2))
        return runs_exec.RunOutcome(f"cycle {KEY}", [], KEY)

    monkeypatch.setattr(runs_exec, "execute_cycle", builder)
    run = await runs_exec.launch(store, Settings(_env_file=None), "cycle")
    assert run is not None
    assert await asyncio.to_thread(started.wait, 10)

    assert runs_exec.cancel_run(run.id, by="otto") is True
    go.set()

    row = await _finished(store, run.id)
    assert (row.status, row.snapshot_key) == ("ok", str(KEY))
    assert row.detail == f"cycle {KEY} · {runs_exec.LATE_CANCEL} (cancelled by otto)"
    assert {st.host for st in await store.list_device_status()} == {"h0", "h1"}


async def test_a_cancelled_builder_that_published_nothing_leaves_the_run_cancelled(monkeypatch):
    store = await _store()
    _stub_prepare(monkeypatch)
    started, go = threading.Event(), threading.Event()

    def builder(settings, prepared, name, assigned=None, *, stop=None, outcomes=None, **kw):
        started.set()
        assert go.wait(10), "the builder was never released"
        return runs_exec.RunOutcome("skipped", [], None)

    monkeypatch.setattr(runs_exec, "execute_refresh", builder)
    run = await runs_exec.launch(store, Settings(_env_file=None), "unifi")
    assert run is not None
    assert await asyncio.to_thread(started.wait, 10)

    assert runs_exec.cancel_run(run.id, by="otto") is True
    go.set()

    row = await _finished(store, run.id)
    assert (row.status, row.detail, row.snapshot_key) == (runs_exec.CANCELLED, "cancelled by otto", None)


async def test_the_cancel_route_answers_409_for_a_built_run(client, seeded, monkeypatch):
    await seeded.create_source("unifi", "unifi", {}, b"")
    _stub_prepare(monkeypatch)
    _publishing_cycle(monkeypatch, 3)
    entered = asyncio.Event()
    _slow_statuses(seeded, entered)
    await login(client, "otto")

    run = await runs_exec.launch(seeded, Settings(_env_file=None), "cycle")
    assert run is not None
    await asyncio.wait_for(entered.wait(), 10)
    r = await client.post(f"/api/runs/{run.id}/cancel")

    assert r.status_code == 409
    assert r.json()["error"] == f"run {run.id} has finished building and can no longer be cancelled"
    assert (await _finished(seeded, run.id)).status == "ok"


async def test_a_status_that_cannot_be_written_clears_the_device_digests(monkeypatch):
    store = await _store()
    now = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
    await store.upsert_device_status(
        "unifi", "h0", now=now, ok=True, raw_sha="r-old", graph_sha="g-old", full=True
    )
    real = store.upsert_device_status

    async def failing(source, host, **kwargs):
        if host == "h0":
            raise RuntimeError("connection reset")
        return await real(source, host, **kwargs)

    store.upsert_device_status = failing  # type: ignore[method-assign]

    await runs_exec._record_outcomes(store, _outcomes(2))

    status = {st.host: st for st in await store.list_device_status()}
    assert (status["h0"].last_raw_sha, status["h0"].last_graph_sha) == ("", "")
    assert (status["h1"].last_raw_sha, status["h1"].last_graph_sha) == ("r1", "g1")


async def test_a_refresh_whose_source_is_cancelled_alone_finishes_as_cancelled(monkeypatch):
    store = await _store()
    _stub_prepare(monkeypatch)
    armed = threading.Event()

    def builder(settings, prepared, name, assigned=None, *, stop=None, **kw):
        flag = stop.for_source(name)
        stop.armed = True
        armed.set()
        assert flag.wait(10), "the source's flag was never raised"
        raise runs_exec.RunCancelled(f"{name}: cancelled by operator; nothing was published")

    monkeypatch.setattr(runs_exec, "execute_refresh", builder)
    run = await runs_exec.launch(store, Settings(_env_file=None), "unifi")
    assert run is not None
    assert await asyncio.to_thread(armed.wait, 10)

    assert runs_exec.cancel_run(run.id, by="otto", source="unifi") is True

    row = await _finished(store, run.id)
    assert (row.status, row.detail, row.snapshot_key) == (
        runs_exec.CANCELLED,
        "unifi: cancelled by operator; nothing was published",
        None,
    )


def test_a_run_cancelled_is_a_runtime_error():
    assert issubclass(runs_exec.RunCancelled, RuntimeError)
