"""`reap_jobs` backoff, held to the same answer by `FakeStore` and `PgStore`.

PgStore computes each row's delay inside its one UPDATE; FakeStore computes it
in Python. Parametrized over both backends in the manner of
`test_store_contract.py`: the `pg` leg carries the `pg` marker and skips without
`HST_TEST_PG_DSN`.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.fakes import FakeStore

from hst.app.store.pg import PgStore, metadata, upgrade_to_head

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
LEASE = timedelta(minutes=5)
LAPSED = NOW + timedelta(minutes=6)
DSN = os.environ.get("HST_TEST_PG_DSN")
DETAIL = "lease expired: the executor holding this job stopped reporting"
BACKOFF = {
    "backoff_kinds": ("collect.cycle", "collect.fetch"),
    "backoff_base_s": 60.0,
    "backoff_cap_s": 1800.0,
}

BACKENDS = [
    pytest.param("fake", id="fake"),
    pytest.param(
        "pg",
        id="pg",
        marks=[pytest.mark.pg, pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")],
    ),
]


@pytest.fixture(params=BACKENDS)
async def store(request):
    if request.param == "fake":
        yield FakeStore()
        return

    from sqlalchemy.ext.asyncio import create_async_engine

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:  # clean slate per test
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    st = PgStore(DSN)
    yield st
    await st.dispose()


async def _queue(store, kind, *, max_attempts=4, at=NOW):
    return await store.enqueue_job(
        kind,
        not_before=at,
        max_attempts=max_attempts,
        triggered_by="scheduler",
        now=at,
    )


async def _row(store, job_id):
    return next(j for j in await store.list_jobs() if j.id == job_id)


async def test_a_backoff_kind_is_requeued_after_the_base_delay_and_others_at_once(store):
    """One reap, one statement, both answers."""
    cycle = await _queue(store, "collect.cycle")
    sweep = await _queue(store, "maintenance.prune_graph")
    await store.claim_jobs("worker-gone", 2, NOW, LEASE)

    assert await store.reap_jobs(LAPSED, **BACKOFF) == 2

    backed_off = await _row(store, cycle.id)
    assert (backed_off.state, backed_off.attempt) == ("queued", 1)
    assert backed_off.not_before == LAPSED + timedelta(seconds=60)
    assert (backed_off.claimed_by, backed_off.lease_expires_at, backed_off.finished_at) == (None, None, None)
    assert backed_off.detail == DETAIL

    at_once = await _row(store, sweep.id)
    assert (at_once.state, at_once.not_before, at_once.detail) == ("queued", LAPSED, DETAIL)


async def test_the_delay_doubles_per_attempt_up_to_the_cap(store):
    """Fractional seconds included: 1.5 s, 3 s, then the 5 s cap over 6 s."""
    job = await _queue(store, "collect.fetch", max_attempts=5)
    curve = {"backoff_kinds": ["collect.fetch"], "backoff_base_s": 1.5, "backoff_cap_s": 5.0}
    at = NOW
    delays = []
    for attempt in (1, 2, 3):
        (claimed,) = await store.claim_jobs("worker-gone", 1, at, LEASE)
        assert claimed.attempt == attempt
        at = at + LEASE
        assert await store.reap_jobs(at, **curve) == 1
        row = await _row(store, job.id)
        delays.append(row.not_before - at)
        at = row.not_before
    assert delays == [timedelta(seconds=1.5), timedelta(seconds=3), timedelta(seconds=5)]


async def test_a_backed_off_row_is_not_claimed_before_it_is_due(store):
    job = await _queue(store, "collect.cycle")
    await store.claim_jobs("worker-gone", 1, NOW, LEASE)
    await store.reap_jobs(LAPSED, **BACKOFF)

    assert await store.claim_jobs("worker-b", 1, LAPSED, LEASE) == []
    assert await store.claim_jobs("worker-b", 1, LAPSED + timedelta(seconds=59), LEASE) == []
    (retaken,) = await store.claim_jobs("worker-b", 1, LAPSED + timedelta(seconds=60), LEASE)
    assert (retaken.id, retaken.attempt) == (job.id, 2)


async def test_a_backoff_kind_with_no_attempts_left_is_dead(store):
    job = await _queue(store, "collect.cycle", max_attempts=1)
    await store.claim_jobs("worker-gone", 1, NOW, LEASE)

    assert await store.reap_jobs(LAPSED, **BACKOFF) == 1

    row = await _row(store, job.id)
    assert (row.state, row.finished_at, row.not_before, row.detail) == ("dead", LAPSED, NOW, DETAIL)
    assert (row.claimed_by, row.lease_expires_at) == (None, None)


async def test_no_backoff_kinds_means_every_kind_is_due_at_once(store):
    job = await _queue(store, "collect.cycle")
    await store.claim_jobs("worker-gone", 1, NOW, LEASE)

    assert await store.reap_jobs(LAPSED) == 1
    assert (await _row(store, job.id)).not_before == LAPSED


async def test_a_live_lease_is_left_alone_whatever_its_kind(store):
    job = await _queue(store, "collect.cycle")
    await store.claim_jobs("worker-a", 1, NOW, LEASE)

    assert await store.reap_jobs(NOW + timedelta(minutes=1), **BACKOFF) == 0
    row = await _row(store, job.id)
    assert (row.state, row.claimed_by, row.not_before) == ("running", "worker-a", NOW)
