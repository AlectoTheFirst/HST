"""GET /api/jobs: the maintenance queue's history, for whoever manages runs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from tests.app.conftest import login

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


async def _finished(store, kind, state, detail, *, seconds=7, max_attempts=3):
    await store.enqueue_job(
        kind,
        not_before=NOW,
        max_attempts=max_attempts,
        triggered_by="scheduler",
        now=NOW,
    )
    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, timedelta(minutes=5))
    return await store.finish_job(claimed.id, state, detail, NOW + timedelta(seconds=seconds))


async def test_jobs_are_operator_and_above(client):
    await login(client, "vera")
    assert (await client.get("/api/jobs")).status_code == 403
    await login(client, "otto")
    assert (await client.get("/api/jobs")).status_code == 200


async def test_the_history_reads_newest_first_with_what_each_job_did(client, store):
    await _finished(store, "maintenance.purge_sessions", "ok", "deleted 3 expired session(s)")
    await _finished(store, "maintenance.prune_graph", "dead", "RuntimeError: twin unreachable")
    await store.enqueue_job(
        "maintenance.purge_login_events",
        not_before=NOW,
        max_attempts=3,
        triggered_by="scheduler",
        now=NOW,
    )

    await login(client, "otto")
    body = (await client.get("/api/jobs")).json()

    kinds = [j["kind"] for j in body["jobs"]]
    assert kinds == [
        "maintenance.purge_login_events",
        "maintenance.prune_graph",
        "maintenance.purge_sessions",
    ]

    pruned = body["jobs"][1]
    assert pruned["state"] == "dead"
    assert pruned["detail"] == "RuntimeError: twin unreachable"
    assert pruned["attempt"] == 1 and pruned["max_attempts"] == 3
    assert pruned["duration_s"] == 7.0
    assert pruned["triggered_by"] == "scheduler"
    assert (pruned["source"], pruned["device"]) == (None, None)

    queued = body["jobs"][0]
    assert queued["state"] == "queued"
    assert (queued["started_at"], queued["finished_at"], queued["duration_s"]) == (None, None, None)
    assert queued["detail"] == ""


async def test_the_history_reports_the_depth_by_state(client, store):
    await _finished(store, "maintenance.purge_sessions", "ok", "done")
    await store.enqueue_job(
        "maintenance.prune_graph", not_before=NOW, max_attempts=3, triggered_by="scheduler", now=NOW
    )

    await login(client, "otto")
    body = (await client.get("/api/jobs")).json()
    assert body["depth"] == {"ok": 1, "queued": 1}


async def test_the_history_is_bounded(client, store):
    for i in range(5):
        await _finished(store, f"maintenance.k{i}", "ok", "done")

    await login(client, "otto")
    assert len((await client.get("/api/jobs?limit=2")).json()["jobs"]) == 2


@pytest.mark.parametrize("limit", ["0", "201", "many"])
async def test_an_out_of_range_limit_is_refused(client, limit):
    await login(client, "otto")
    assert (await client.get(f"/api/jobs?limit={limit}")).status_code == 422
