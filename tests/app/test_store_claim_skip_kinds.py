"""`claim_jobs(skip_kinds=...)`, held to the same answer by `FakeStore` and
`PgStore`: a queued job of a skipped kind is left queued for a later claim,
and the claim takes the next job of another kind in its place. Parametrized
over both backends in the manner of `test_store_reap_backoff_contract.py`:
the `pg` leg carries the `pg` marker and skips without `HST_TEST_PG_DSN`.
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
DSN = os.environ.get("HST_TEST_PG_DSN")

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


async def _queue(store, kind, source, *, priority=0):
    job = await store.enqueue_job(
        kind,
        source=source,
        priority=priority,
        not_before=NOW,
        max_attempts=1,
        triggered_by="test",
        now=NOW,
    )
    assert job is not None
    return job


async def test_a_skipped_kind_stays_queued_and_the_next_kind_is_claimed_in_its_place(store):
    reparse = await _queue(store, "debug.reparse", "edge", priority=1)
    sweep = await _queue(store, "maintenance.sweep", "edge")

    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, LEASE, skip_kinds=["debug.reparse"])
    assert claimed.id == sweep.id
    assert await store.claim_jobs("worker-a", 1, NOW, LEASE, skip_kinds=["debug.reparse"]) == []

    (taken,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)
    assert (taken.id, taken.state, taken.attempt) == (reparse.id, "running", 1)


async def test_an_empty_skip_list_claims_every_kind(store):
    first = await _queue(store, "debug.reparse", "edge", priority=1)
    second = await _queue(store, "maintenance.sweep", "edge")

    claimed = await store.claim_jobs("worker-a", 5, NOW, LEASE, skip_kinds=())
    # an UPDATE ... RETURNING has no row order
    assert sorted(job.id for job in claimed) == sorted([first.id, second.id])
