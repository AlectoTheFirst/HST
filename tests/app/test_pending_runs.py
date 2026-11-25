"""Queued runs are found by kind and state, not in a window of the newest jobs.

With RUN_EXECUTION=queue a trigger leaves a `collect.run` job and no run row
until an executor claims it. A per-device fan-out enqueues one `collect.fetch`
job per due device, which fills the newest job rows. The 409 of a second
trigger and the Runs page's queued state read the pending job by kind and
state (`Store.pending_jobs`), so the fan-out does not hide it, and GET
/api/runs lists the result as `pending_runs`.

The store half runs against both backends, in the manner of
`test_store_contract.py`: the `pg` leg carries the `pg` marker and skips
without `HST_TEST_PG_DSN`.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.app.store.pg import PgStore, metadata, upgrade_to_head
from hst.core import Settings
from hst.worker import collect, queue

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
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
async def backend(request):
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


async def _queue(store, kind, source=None, device=None, at=NOW):
    job = await store.enqueue_job(
        kind, source=source, device=device, not_before=at, max_attempts=1, triggered_by="scheduler", now=at
    )
    assert job is not None
    return job


# --- the store ---------------------------------------------------------------------


async def test_pending_jobs_are_the_queued_and_running_jobs_of_one_kind_oldest_first(backend):
    running = await _queue(backend, collect.RUN_KIND, "unifi")
    (claimed,) = await backend.claim_jobs("worker-a", 1, NOW, LEASE)
    assert claimed.id == running.id
    finished = await _queue(backend, collect.RUN_KIND, "vyos")
    (claimed,) = await backend.claim_jobs("worker-a", 1, NOW, LEASE)
    await backend.finish_job(claimed.id, "ok", "run 1 ok", NOW, claimed_by="worker-a", attempt=1)
    queued = await _queue(backend, collect.RUN_KIND, "vyos")
    await _queue(backend, collect.FETCH_KIND, "unifi", "r1")

    pending = await backend.pending_jobs(collect.RUN_KIND)

    assert [(j.id, j.source, j.state) for j in pending] == [
        (running.id, "unifi", "running"),
        (queued.id, "vyos", "queued"),
    ]
    assert finished.id not in {j.id for j in pending}
    assert [j.kind for j in await backend.pending_jobs(collect.FETCH_KIND)] == [collect.FETCH_KIND]
    assert await backend.pending_jobs("maintenance.prune_graph") == []


async def test_pending_jobs_are_not_bounded_by_the_newest_jobs(backend):
    queued = await _queue(backend, collect.RUN_KIND, "unifi")
    for i in range(250):
        await _queue(backend, collect.FETCH_KIND, "unifi", f"r{i:03d}")

    assert queued.id not in {j.id for j in await backend.list_jobs(limit=200)}
    assert [j.id for j in await backend.pending_jobs(collect.RUN_KIND)] == [queued.id]


async def test_a_run_is_read_by_its_id_and_the_running_rows_oldest_first(backend):
    first = await backend.start_run("unifi", NOW)
    second = await backend.start_run("vyos", NOW + timedelta(seconds=1))
    assert first is not None and second is not None
    await backend.finish_run(first.id, "ok", NOW + timedelta(seconds=2), "done")
    third = await backend.start_run("cycle", NOW + timedelta(seconds=3))
    assert third is not None

    row = await backend.get_run(first.id)
    assert row is not None and (row.id, row.source, row.status, row.detail) == (
        first.id,
        "unifi",
        "ok",
        "done",
    )
    assert await backend.get_run(first.id + 1000) is None
    assert [r.id for r in await backend.running_runs()] == [second.id, third.id]

    await backend.finish_run(second.id, "ok", NOW, "")
    await backend.finish_run(third.id, "ok", NOW, "")
    assert await backend.running_runs() == []


# --- the routes --------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _own_run_registry(monkeypatch):
    monkeypatch.setattr(runs_exec, "_RUNS", {})


@pytest.fixture
async def queued(seeded, tmp_path):
    await seeded.create_source("unifi", "unifi", {}, b"")
    await seeded.create_source("vyos", "vyos", {}, b"")
    settings = Settings(
        _env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path, run_execution="queue"
    )
    app = create_app(settings=settings, store=seeded)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "otto")
        yield client


async def _fan_out(store, count: int) -> None:
    """A scheduler tick's per-device fan-out: one fetch job per due device."""
    for i in range(count):
        job = await queue.enqueue(
            store, collect.FETCH_KIND, source="vyos", device=f"r{i:03d}", triggered_by="scheduler"
        )
        assert job is not None


async def test_a_second_trigger_names_the_queued_job_after_a_fan_out(queued, seeded):
    first = (await queued.post("/api/runs", json={"source": "unifi"})).json()
    await _fan_out(seeded, 250)

    r = await queued.post("/api/runs", json={"source": "unifi"})

    assert r.status_code == 409
    assert r.json()["error"] == f"unifi is already queued (job {first['job_id']})"


async def test_the_run_listing_names_every_pending_run_past_the_job_window(queued, seeded):
    first = (await queued.post("/api/runs", json={"source": "unifi"})).json()
    second = (await queued.post("/api/runs", json={"source": "vyos"})).json()
    (claimed,) = await queue.claim(seeded, "worker-a")
    assert claimed.id == first["job_id"]
    await _fan_out(seeded, 60)

    jobs = (await queued.get("/api/jobs")).json()["jobs"]
    listing = (await queued.get("/api/runs")).json()

    assert first["job_id"] not in {j["id"] for j in jobs}, "the fan-out did not fill the job window"
    assert [(j["id"], j["kind"], j["source"], j["state"]) for j in listing["pending_runs"]] == [
        (first["job_id"], collect.RUN_KIND, "unifi", "running"),
        (second["job_id"], collect.RUN_KIND, "vyos", "queued"),
    ]
    # the same row a job listing gives
    assert set(listing["pending_runs"][0]) == set(jobs[0])


async def test_the_run_listing_names_no_pending_run_when_none_is_queued(queued):
    listing = (await queued.get("/api/runs")).json()
    assert listing["pending_runs"] == []
