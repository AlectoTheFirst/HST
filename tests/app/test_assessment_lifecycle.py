"""Published evidence closes gaps."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from hst.assessment import lifecycle
from hst.assessment.store import MemoryAssessmentStore
from hst.core.manifest import DeviceEntry
from hst.core.model import SectionOutcome, TableOutcome


class Store(MemoryAssessmentStore):
    def __init__(self):
        super().__init__()
        self.jobs = {}
        self.role = "operator"

    async def get_user(self, user_id):
        return SimpleNamespace(id=user_id, role=self.role, disabled=False)

    @asynccontextmanager
    async def cycle_lock(self):
        yield


def reference(snapshot="100", age=0):
    return {
        "snapshot": snapshot,
        "manifest_sha256": "fixture-" + snapshot,
        "estate": "fixture",
        "observation_floor_ms": int((datetime.now(UTC) - timedelta(seconds=age)).timestamp() * 1000),
    }


@pytest.fixture
def publication(monkeypatch):
    state = {"ref": reference(), "devices": []}
    monkeypatch.setattr(
        lifecycle, "_publication", lambda settings: (state["ref"], SimpleNamespace(devices=state["devices"]))
    )
    monkeypatch.setattr(lifecycle.service, "snapshot_reference", lambda settings, value=None: state["ref"])
    monkeypatch.setattr(lifecycle.service, "engine_version", lambda settings: "engine")
    return state


async def assessment(store, **overrides):
    return await store.create_assessment(
        title="Service",
        purpose="evaluation",
        created_by=1,
        definition={"request": {"name": "fixture"}, "freshness_s": 3600, **overrides},
    )


async def complete(store, saved, ref, kind="evaluate", result=None):
    run = await store.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=saved.revision,
        kind=kind,
        inputs={},
        snapshot_refs=[ref],
        engine_version="engine",
        created_by=1,
    )
    lease = await store.claim_analysis("fixture")
    assert lease.id == run.id
    await store.finish_analysis(run.id, lease.lease_token, result=result or {"verdict": "not-established"})
    return run


async def test_committed_publication_invalidates_without_queueing(publication):
    store = Store()
    saved = await assessment(store)
    original = await complete(store, saved, reference("99"))
    first = await lifecycle.reconcile_once(store, None)
    assert first["invalidated"] == 1
    assert first["queued"] == 0
    assert (await store.get_assessment_freshness(saved.id))["state"] == "needs-reassessment"
    # A later poll against the same publication queues nothing either: the
    # operator starts the new evaluation, never the watcher.
    publication["ref"] = reference("101")
    assert (await lifecycle.reconcile_once(store, None))["queued"] == 0
    assert len(await store.list_analysis_runs(saved.id)) == 1
    assert (await store.get_analysis_run(original.id)).result == {"verdict": "not-established"}


async def test_cursor_scan_covers_every_assessment_beyond_ui_page_size(publication):
    store = Store()
    for index in range(205):
        await store.create_assessment(title=str(index), purpose="evaluation", created_by=1, definition={})
    assert (await lifecycle.reconcile_once(store, None))["assessments"] == 205


async def test_old_evidence_remains_expired_when_the_same_snapshot_is_recomputed(publication):
    store = Store()
    publication["ref"] = reference(age=7200)
    saved = await assessment(store)
    await complete(store, saved, publication["ref"])
    fresh = await store.get_assessment_freshness(saved.id)
    assert fresh["causes"] == ["freshness-expired"]
    assert (await lifecycle.reconcile_once(store, None))["queued"] == 0
    assert len(await store.list_analysis_runs(saved.id)) == 1


async def action_fixture(store):
    saved = await assessment(store)
    original = await complete(store, saved, reference("99"), kind="troubleshoot", result={"gaps": []})
    requested = datetime.now(UTC) - timedelta(seconds=10)
    action = {
        "id": "action1",
        "source": "vyos",
        "host": "edge",
        "section": "routes",
        "recipe_id": "vyos.rib.ipv4",
        "recipe_ids": ["vyos.rib.ipv4"],
        "sections": ["routes"],
        "requested_at": requested.isoformat(),
        "requested_by": 1,
        "run_id": original.id,
        "job_id": 1,
        "state": "queued",
    }
    saved = await store.create_assessment(
        title=saved.title,
        purpose=saved.purpose,
        created_by=1,
        assessment_id=saved.id,
        expected_revision=saved.revision,
        definition={**saved.definition, "collection_actions": [action]},
    )
    store.jobs[1] = SimpleNamespace(id=1, state="ok", source="vyos", device="edge")
    return saved, action


def device(
    action,
    *,
    age=0,
    source="vyos",
    host="edge",
    outcome="collected",
    carried=False,
    section_status="ok",
    table_status="complete",
):
    observed = int((datetime.now(UTC) - timedelta(seconds=age)).timestamp() * 1000)
    return DeviceEntry(
        source=source,
        host=host,
        outcome=outcome,
        carried=carried,
        fetch_started_ms=observed,
        sections={"routes": SectionOutcome(status=section_status)},
        tables={"rib": TableOutcome(status=table_status, observed_ms=observed)},
    )


async def test_fetch_completion_waits_for_exact_new_published_evidence_then_reevaluates(publication):
    store = Store()
    saved, action = await action_fixture(store)
    publication["devices"] = [device(action, age=60)]
    await lifecycle.reconcile_once(store, None)
    pending = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    assert pending["state"] == "awaiting_publication"
    assert "reevaluation_run_id" not in pending
    publication["ref"] = reference("101")
    publication["devices"] = [device(action)]
    assert (await lifecycle.reconcile_once(store, None))["queued"] == 1
    pending = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    followup = await store.get_analysis_run(pending["reevaluation_run_id"])
    assert followup.kind == "troubleshoot"
    assert followup.snapshot_refs == [publication["ref"]]
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(followup.id, lease.lease_token, result={"gaps": []})
    await lifecycle.reconcile_once(store, None)
    done = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    assert done["state"] == "reevaluated"
    assert done["gap_closed"] is True
    assert (await store.get_assessment_freshness(saved.id))["state"] == "current"


@pytest.mark.parametrize("override", [{"host": "other"}, {"source": "other"}, {"carried": True}])
async def test_wrong_device_or_carried_publication_never_closes_gap(publication, override):
    store = Store()
    saved, action = await action_fixture(store)
    publication["devices"] = [device(action, **override)]
    await lifecycle.reconcile_once(store, None)
    result = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    assert result["state"] == "awaiting_publication"
    assert "reevaluation_run_id" not in result


@pytest.mark.parametrize(
    "override", [{"outcome": "partial"}, {"section_status": "failed"}, {"table_status": "failed"}]
)
async def test_partial_or_unpublished_section_is_failed_not_closed(publication, override):
    store = Store()
    saved, action = await action_fixture(store)
    publication["devices"] = [device(action, **override)]
    await lifecycle.reconcile_once(store, None)
    result = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    assert result["state"] == "failed"
    assert "gap_closed" not in result


async def test_revoked_collection_requester_cannot_continue_action(publication):
    store = Store()
    saved, action = await action_fixture(store)
    publication["devices"] = [device(action)]
    store.role = "viewer"
    await lifecycle.reconcile_once(store, None)
    result = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    assert result["state"] == "failed"
    assert "authorization" in result["reason"]
    assert "reevaluation_run_id" not in result


async def test_reevaluation_can_leave_original_gap_open(publication):
    store = Store()
    saved, action = await action_fixture(store)
    publication["devices"] = [device(action)]
    await lifecycle.reconcile_once(store, None)
    pending = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(
        lease.id,
        lease.lease_token,
        result={
            "gaps": [
                {"source": "vyos", "host": "edge", "recipe_id": "vyos.rib.ipv4", "dimension": "ipv4-rib"}
            ]
        },
    )
    await lifecycle.reconcile_once(store, None)
    done = (await store.get_assessment(saved.id)).definition["collection_actions"][0]
    assert done["state"] == "reevaluated"
    assert done["gap_closed"] is False
    assert done["reevaluation_run_id"] == pending["reevaluation_run_id"]


async def test_new_requirement_revision_marks_stale_without_rebinding_saved_inputs(publication):
    store = Store()
    requirement = await store.create_requirement(
        title="Requirement", definition={"request": "original"}, created_by=1
    )
    saved = await assessment(store, requirement_id=requirement.id, requirement_revision=1)
    run = await complete(store, saved, publication["ref"])
    await store.create_requirement(
        title="Requirement",
        definition={"request": "different"},
        created_by=1,
        requirement_id=requirement.id,
        expected_revision=1,
    )
    assert "requirement-revision" in (await store.get_assessment_freshness(saved.id))["causes"]
    assert (await lifecycle.reconcile_once(store, None))["queued"] == 0
    assert (await store.get_assessment(saved.id)).definition == saved.definition
    assert (await store.get_analysis_run(run.id)).inputs == run.inputs
    assert len(await store.list_analysis_runs(saved.id)) == 1
