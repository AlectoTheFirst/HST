"""Crash injection: a lost job-finish acknowledgement
(worker/queue.py `finish`). The store commits the outcome, and the
process dies before the worker learns that the call landed, so the worker
reports the same outcome again. With the fencing on `claimed_by` and
`attempt` (worker/queue.py `finish`, app/store/pg.py `finish_job`) the retry
is a no-op: the job finishes once, on the first call's terms.

Uses the `store` fixture from tests/app/test_store_contract.py, which
parametrizes over `FakeStore` and a real `PgStore` (the `pg` leg carries the
`pg` marker and skips without `HST_TEST_PG_DSN`).
"""

# ruff: noqa: F811 -- the imported `store` fixture is shadowed by design in the test signature

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from tests.app.test_store_contract import store  # noqa: F401  (fake + pg backends)
from tests.crash.injectors import SimulatedCrash, crash_after

from hst.worker import queue

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
LEASE = timedelta(minutes=5)


async def test_a_lost_finish_acknowledgement_is_retried_and_finishes_the_job_exactly_once(store):
    job = await store.enqueue_job(
        "maintenance.crash-ack",
        not_before=NOW,
        max_attempts=3,
        triggered_by="scheduler",
        now=NOW,
    )
    assert job is not None
    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)

    with pytest.MonkeyPatch.context() as mp:
        crash_after(mp, queue, "finish")
        with pytest.raises(SimulatedCrash):
            await queue.finish(store, claimed, True, "done", now=NOW)

    retry = await queue.finish(store, claimed, True, "done, retried", now=NOW + timedelta(seconds=5))
    assert retry is None  # the attempt it named is already finished: a no-op

    (row,) = await store.list_jobs(limit=1)
    assert row.id == claimed.id
    assert row.state == "ok"
    assert row.finished_at == NOW  # the retry's write never landed
    assert row.detail == "done"  # not "done, retried"
