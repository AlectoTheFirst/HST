"""Assessment storage invariants, without changing the application store fake."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

import hst.assessment.store as module
from hst.assessment.store import (
    AnalysisCapacityError,
    MemoryAssessmentStore,
    RevisionConflict,
)


@pytest.fixture
def store():
    return MemoryAssessmentStore()


async def assessment(store, **definition):
    return await store.create_assessment(
        title="Payments",
        purpose="evaluation",
        definition={"request": {"clients": ["client-a"]}, **definition},
        created_by=1,
    )


async def enqueue(store, saved, **kwargs):
    return await store.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=saved.revision,
        kind="evaluation",
        inputs={"request": saved.definition["request"]},
        snapshot_refs=[
            {
                "namespace": "fixture",
                "collection_ts": 100,
                "manifest_sha": "abc",
                "observation_floor_ms": int(datetime.fromisoformat(saved.created_at).timestamp() * 1000),
            }
        ],
        engine_version="fixture-engine-1",
        created_by=1,
        **kwargs,
    )


async def test_revisions_are_immutable_and_concurrent_edits_are_fenced(store):
    definition = {"request": {"clients": ["a"]}}
    original = await store.create_requirement(title="First", definition=definition, created_by=1)
    definition["request"]["clients"].append("caller-mutation")
    original.definition["request"]["clients"].append("returned-record-mutation")
    stored = await store.get_requirement(original.id, 1)
    assert stored.definition == {"request": {"clients": ["a"]}}
    attempts = await asyncio.gather(
        *(
            store.create_requirement(
                title=title, definition={}, created_by=1, requirement_id=original.id, expected_revision=1
            )
            for title in ("Second", "Racing second")
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(value, RevisionConflict) for value in attempts) == 1
    assert (await store.get_requirement(original.id, 1)).title == "First"
    assert (await store.get_requirement(original.id)).revision == 2
    assert len(await store.list_requirements()) == 1


async def test_assessment_revisions_preserve_ordered_intents_and_old_run(store):
    saved = await assessment(store, intents=[{"kind": "first"}, {"kind": "second"}])
    run = await enqueue(store, saved)
    newer = await store.create_assessment(
        title=saved.title,
        purpose=saved.purpose,
        definition={**saved.definition, "intents": []},
        created_by=1,
        assessment_id=saved.id,
        expected_revision=1,
    )
    assert newer.revision == 2
    assert (await store.get_assessment(saved.id, 1)).definition["intents"] == [
        {"kind": "first"},
        {"kind": "second"},
    ]
    assert (await store.get_analysis_run(run.id)).assessment_revision == 1
    assert (await store.get_assessment_freshness(saved.id))["state"] == "needs-reassessment"


async def test_exact_dedup_and_explicit_retry_keep_original_results(store):
    saved = await assessment(store)
    run = await enqueue(store, saved)
    assert (await enqueue(store, saved)).id == run.id
    lease = await store.claim_analysis("worker")
    assert await store.finish_analysis(lease.id, lease.lease_token, result={"verdict": "unknown"})
    assert not await store.finish_analysis(lease.id, lease.lease_token, result={"verdict": "success"})
    assert (await enqueue(store, saved)).id == run.id
    retry = await enqueue(store, saved, retry_of=run.id)
    assert retry.id != run.id
    assert retry.retry_of == run.id
    assert (await store.get_analysis_run(run.id)).result == {"verdict": "unknown"}
    assert len(await store.retained_snapshot_refs()) == 1


async def test_lease_recovery_fences_crashed_worker_and_preserves_checkpoint(store, monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    saved = await assessment(store)
    run = await enqueue(store, saved)
    first = await store.claim_analysis("first", lease_seconds=10)
    assert await store.heartbeat_analysis(
        run.id, first.lease_token, progress={"evaluated": 3}, checkpoint={"next": 4}, lease_seconds=10
    )
    assert await store.claim_analysis("second") is None
    now += timedelta(seconds=11)
    assert not await store.heartbeat_analysis(run.id, first.lease_token)
    recovered = await store.claim_analysis("second")
    assert recovered.id == run.id
    assert recovered.attempt == 2
    assert recovered.progress == {"evaluated": 3}
    assert recovered.checkpoint == {"next": 4}
    assert recovered.lease_token != first.lease_token
    assert not await store.finish_analysis(run.id, first.lease_token, result={})
    assert await store.finish_analysis(run.id, recovered.lease_token, result={"partial": False})


async def test_cancel_queued_and_running_cannot_complete_search(store):
    saved = await assessment(store)
    queued = await enqueue(store, saved)
    assert (await store.cancel_analysis(queued.id)).state == "cancelled"
    assert await store.claim_analysis("worker") is None
    run = await enqueue(store, saved, retry_of=queued.id)
    lease = await store.claim_analysis("worker")
    assert (await store.cancel_analysis(run.id)).cancel_requested
    assert not await store.heartbeat_analysis(run.id, lease.lease_token)
    assert await store.finish_analysis(run.id, lease.lease_token, result={"verified_sets": [["r1"]]})
    finished = await store.get_analysis_run(run.id)
    assert finished.state == "cancelled"
    assert finished.result["verified_sets"] == [["r1"]]
    assert finished.result["search_complete"] is False
    assert finished.result["stop_reason"] == "cancelled"
    assert (await store.cancel_analysis(run.id)).finished_at == finished.finished_at


async def test_actor_admission_is_atomic_and_bounded(store):
    saved = await assessment(store)
    results = await asyncio.gather(
        *(
            store.enqueue_analysis(
                assessment_id=saved.id,
                assessment_revision=1,
                kind="evaluation",
                inputs={"variant": index},
                snapshot_refs=[{"collection_ts": 100}],
                engine_version="1",
                created_by=1,
            )
            for index in range(12)
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, AnalysisCapacityError) for result in results) == 4
    assert len(await store.list_analysis_runs()) == 8


async def test_dependency_invalidation_includes_absent_selectors_and_deduplicates(store):
    saved = await assessment(store)
    run = await enqueue(store, saved)
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(
        run.id,
        lease.lease_token,
        result={"verdict": "proven"},
        dependencies=[
            {"source": "edge", "vrf": "blue", "section": "routes", "selector": "all-prefixes", "absent": True}
        ],
    )
    assert (await store.get_assessment_freshness(saved.id))["state"] == "current"
    assert (
        await store.invalidate_assessments(
            "other", {"collection_ts": 101}, [{"source": "core", "vrf": "blue", "section": "routes"}]
        )
        == []
    )
    assert await store.invalidate_assessments(
        "new-route",
        {"collection_ts": 102},
        [{"source": "edge", "vrf": "blue", "section": "routes", "uid": "new-prefix"}],
    ) == [saved.id]
    assert await store.invalidate_assessments("new-route", {"collection_ts": 102}, []) == []
    fresh = await store.get_assessment_freshness(saved.id)
    assert fresh["causes"] == ["published-evidence"]
    assert (await store.get_analysis_run(run.id)).result == {"verdict": "proven"}


async def test_late_completion_does_not_clear_publication_or_revision_invalidation(store, monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    saved = await assessment(store)
    baseline = await enqueue(store, saved)
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(baseline.id, lease.lease_token, result={})
    retry = await enqueue(store, saved, retry_of=baseline.id)
    lease = await store.claim_analysis("worker")
    now += timedelta(seconds=1)
    await store.invalidate_assessments("published", {"collection_ts": 101}, [])
    await store.finish_analysis(retry.id, lease.lease_token, result={})
    assert (await store.get_assessment_freshness(saved.id))["state"] == "needs-reassessment"


async def test_engine_and_freshness_expiry_are_separate_from_historical_result(store, monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    saved = await assessment(store, freshness_s=5)
    run = await enqueue(store, saved)
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(run.id, lease.lease_token, result={"verdict": "unknown"})
    now += timedelta(seconds=6)
    assert (await store.get_assessment_freshness(saved.id))["causes"] == ["freshness-expired"]
    assert await store.invalidate_assessments("upgrade", {}, [{"source": "unrelated"}], "engine-2") == [
        saved.id
    ]
    assert (await store.get_assessment_freshness(saved.id))["causes"] == ["engine-version"]
    assert (await store.get_analysis_run(run.id)).state == "completed"


async def test_invalid_inputs_roll_back_and_documents_are_bounded(store):
    with pytest.raises(ValueError, match="title"):
        await store.create_requirement(title="", definition={}, created_by=1)
    with pytest.raises(ValueError):
        await store.create_requirement(title="invalid", definition={"n": float("nan")}, created_by=1)
    with pytest.raises(ValueError, match="8 MiB"):
        await store.create_requirement(
            title="large", definition={"n": "x" * module.MAX_DOCUMENT_BYTES}, created_by=1
        )
    assert await store.list_requirements() == []
    saved = await assessment(store)
    with pytest.raises(ValueError, match="revision"):
        await store.enqueue_analysis(
            assessment_id=saved.id,
            assessment_revision=2,
            kind="evaluation",
            inputs={},
            snapshot_refs=[{"collection_ts": 100}],
            engine_version="1",
            created_by=1,
        )
    assert await store.list_analysis_runs() == []


async def test_memory_store_cooperates_with_existing_fake():
    from tests.app.fakes import FakeStore

    class AssessmentFake(MemoryAssessmentStore, FakeStore):
        pass

    store = AssessmentFake()
    assert await store.list_users() == []
    saved = await assessment(store)
    assert await store.get_assessment(saved.id) == saved


async def test_first_inflight_run_and_later_historical_retry_remain_stale(store, monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    saved = await assessment(store)
    original = await enqueue(store, saved)
    lease = await store.claim_analysis("worker")
    now += timedelta(seconds=1)
    assert await store.invalidate_assessments("new-evidence", {"collection_ts": 101}, []) == [saved.id]
    await store.finish_analysis(original.id, lease.lease_token, result={})
    now += timedelta(seconds=1)
    replay = await enqueue(store, saved, retry_of=original.id)
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(replay.id, lease.lease_token, result={})
    assert (await store.get_assessment_freshness(saved.id))["state"] == "needs-reassessment"
    current = await store.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=1,
        kind="evaluation",
        inputs={"request": saved.definition["request"]},
        snapshot_refs=[{"collection_ts": 101}],
        engine_version="fixture-engine-1",
        created_by=1,
    )
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(current.id, lease.lease_token, result={})
    assert (await store.get_assessment_freshness(saved.id))["state"] == "current"


async def test_unpinned_snapshots_and_oversize_results_are_rejected_atomically(store):
    saved = await assessment(store)
    for ref in ({}, {"snapshot": "latest"}, {"snapshot": ""}):
        with pytest.raises(ValueError, match="pinned"):
            await store.enqueue_analysis(
                assessment_id=saved.id,
                assessment_revision=1,
                kind="evaluation",
                inputs={},
                snapshot_refs=[ref],
                engine_version="1",
                created_by=1,
            )
    run = await enqueue(store, saved)
    lease = await store.claim_analysis("worker")
    with pytest.raises(ValueError, match="8 MiB"):
        await store.finish_analysis(
            run.id, lease.lease_token, result={"huge": "x" * module.MAX_DOCUMENT_BYTES}
        )
    still_running = await store.get_analysis_run(run.id)
    assert still_running.state == "running"
    assert still_running.result is None
    assert await store.finish_analysis(run.id, lease.lease_token, result={"verdict": "unknown"})


async def test_expired_workers_exhaust_three_attempts_and_cancelled_leases_are_reaped(store, monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    saved = await assessment(store)
    run = await enqueue(store, saved)
    for attempt in range(1, 4):
        lease = await store.claim_analysis("crashing-worker", lease_seconds=1)
        assert lease.attempt == attempt
        now += timedelta(seconds=2)
    assert await store.claim_analysis("fourth-worker") is None
    assert (await store.get_analysis_run(run.id)).state == "failed"
    retry = await enqueue(store, saved, retry_of=run.id)
    await store.claim_analysis("abandoned-worker", lease_seconds=1)
    await store.cancel_analysis(retry.id)
    now += timedelta(seconds=2)
    assert await store.claim_analysis("next-worker") is None
    assert (await store.get_analysis_run(retry.id)).state == "cancelled"
