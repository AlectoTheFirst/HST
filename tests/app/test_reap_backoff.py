"""Lapsed claims of memory-heavy collection kinds are requeued on the backoff curve."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from tests.app.fakes import FakeStore

from hst.core import Settings
from hst.worker import collect, maintenance, queue
from hst.worker.executor import Executor

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
LEASE = timedelta(minutes=5)
LAPSED = NOW + timedelta(minutes=6)
DETAIL = "lease expired: the executor holding this job stopped reporting"


async def _queue(store, kind, *, max_attempts=4, at=NOW):
    return await store.enqueue_job(
        kind,
        not_before=at,
        max_attempts=max_attempts,
        triggered_by="scheduler",
        now=at,
    )


async def _abandon(store, at=NOW):
    """Claim everything due for a worker that then stops heartbeating."""
    return await store.claim_jobs("worker-that-died", 10, at, LEASE)


def test_the_backoff_kinds_are_the_kinds_as_enqueued():
    assert set(queue.LEASE_BACKOFF_KINDS) == {
        collect.KIND,
        collect.FETCH_KIND,
        collect.RUN_KIND,
        maintenance.BUILD_DEVICE_RUN,
    }
    assert len(queue.LEASE_BACKOFF_KINDS) == 4


@pytest.mark.parametrize("kind", queue.LEASE_BACKOFF_KINDS)
async def test_a_lapsed_claim_of_a_backoff_kind_waits_the_first_backoff(kind):
    store = FakeStore()
    job = await _queue(store, kind)
    await _abandon(store)

    assert await queue.reap(store, LAPSED) == 1

    row = store.jobs[job.id]
    assert (row.state, row.claimed_by, row.lease_expires_at, row.finished_at) == ("queued", None, None, None)
    assert row.attempt == 1
    assert row.not_before == LAPSED + queue.backoff(1)
    assert row.not_before == LAPSED + timedelta(seconds=queue.BACKOFF_BASE_S)
    assert row.detail == DETAIL


async def test_a_lapsed_claim_of_any_other_kind_is_due_at_once():
    store = FakeStore()
    job = await _queue(store, "maintenance.prune_graph")
    await _abandon(store)

    assert await queue.reap(store, LAPSED) == 1

    row = store.jobs[job.id]
    assert (row.state, row.not_before, row.detail) == ("queued", LAPSED, DETAIL)


async def test_each_lapse_follows_the_same_curve_as_a_failed_attempt():
    store = FakeStore()
    job = await _queue(store, collect.KIND, max_attempts=8)
    at = NOW
    delays = []
    for attempt in range(1, 8):
        (claimed,) = await store.claim_jobs("worker-that-died", 1, at, LEASE)
        assert claimed.attempt == attempt
        at = at + LEASE + timedelta(seconds=1)
        assert await queue.reap(store, at) == 1
        row = store.jobs[job.id]
        assert row.not_before == at + queue.backoff(attempt)
        delays.append((row.not_before - at).total_seconds())
        at = row.not_before
    assert delays == [60.0, 120.0, 240.0, 480.0, 960.0, 1800.0, 1800.0]


async def test_a_lapsed_backoff_kind_with_no_attempts_left_is_dead():
    store = FakeStore()
    job = await _queue(store, collect.KIND, max_attempts=1)
    await _abandon(store)

    assert await queue.reap(store, LAPSED) == 1

    row = store.jobs[job.id]
    assert (row.state, row.finished_at, row.detail) == ("dead", LAPSED, DETAIL)
    assert row.not_before == NOW  # left as it was, not pushed out


async def test_reap_reads_the_queue_backoff_settings_when_it_runs(monkeypatch):
    monkeypatch.setattr(queue, "BACKOFF_BASE_S", 10.0)
    monkeypatch.setattr(queue, "BACKOFF_CAP_S", 15.0)
    store = FakeStore()
    job = await _queue(store, collect.FETCH_KIND)

    await _abandon(store)
    await queue.reap(store, LAPSED)
    assert store.jobs[job.id].not_before == LAPSED + timedelta(seconds=10)

    later = LAPSED + timedelta(seconds=10)
    await _abandon(store, later)
    await queue.reap(store, later + LEASE)
    assert store.jobs[job.id].not_before == later + LEASE + timedelta(seconds=15)  # 20 s, capped


async def test_the_store_requeues_at_once_when_no_kinds_are_named():
    """The store's defaults name no kinds; the policy is queue.reap's to pass."""
    store = FakeStore()
    job = await _queue(store, collect.KIND)
    await _abandon(store)

    assert await store.reap_jobs(LAPSED) == 1
    assert store.jobs[job.id].not_before == LAPSED


async def test_an_executor_poll_does_not_rerun_a_reaped_collection_in_the_same_pass():
    store = FakeStore()
    cycle = await _queue(store, collect.KIND)
    sweep = await _queue(store, "maintenance.prune_graph")
    await _abandon(store)
    ran: list[tuple[str, int]] = []

    async def body(ctx, job):
        ran.append((job.kind, job.attempt))
        return "ok"

    clock = {"at": LAPSED}
    ex = Executor(
        store,
        Settings(_env_file=None),
        bodies={collect.KIND: body, "maintenance.prune_graph": body},
        name="worker-under-test",
        concurrency=2,
        clock=lambda: clock["at"],
    )

    claimed = await ex.poll()
    await ex.drain()
    assert [j.id for j in claimed] == [sweep.id]
    assert ran == [("maintenance.prune_graph", 2)]
    row = store.jobs[cycle.id]
    assert (row.state, row.not_before) == ("queued", LAPSED + queue.backoff(1))

    clock["at"] = LAPSED + queue.backoff(1) - timedelta(seconds=1)
    assert await ex.poll() == []

    clock["at"] = LAPSED + queue.backoff(1)
    claimed = await ex.poll()
    await ex.drain()
    assert [j.id for j in claimed] == [cycle.id]
    assert ran == [("maintenance.prune_graph", 2), (collect.KIND, 2)]
    assert store.jobs[cycle.id].state == "ok"
