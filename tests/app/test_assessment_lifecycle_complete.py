"""Lifecycle contracts: immutable proposals, release policy and scoped reads."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import hst.assessment.store as storage
from hst.assessment.dependencies import DependencyRecorder, manifest_changes
from hst.assessment.proposals import save_proposal
from hst.assessment.store import MemoryAssessmentStore, RevisionConflict
from hst.assessment.verification import observation_coverage
from hst.core.manifest import DeviceEntry, SnapshotManifest, SourceEntry
from hst.core.model import SectionOutcome, TableOutcome
from hst.results.project import condition_result, project_engine


async def saved_run(store, *, kind="evaluate", result=None):
    saved = await store.create_assessment(title="fixture", purpose="evaluation", definition={}, created_by=1)
    run = await store.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=1,
        kind=kind,
        inputs={"definition": {"request": "complete-region"}, "analysis": {"protected": []}},
        snapshot_refs=[{"snapshot": "100"}],
        engine_version="fixture",
        created_by=1,
    )
    if result is not None:
        claim = await store.claim_analysis("worker")
        await store.finish_analysis(run.id, claim.lease_token, result=result)
    return saved, await store.get_analysis_run(run.id)


async def test_release_policy_is_explicit_audited_and_active_work_always_pins():
    store = MemoryAssessmentStore()
    saved, run = await saved_run(store)
    with pytest.raises(ValueError, match="reason"):
        await store.set_assessment_retention(saved.id, actor=1, reason="", release=True)
    policy = await store.set_assessment_retention(
        saved.id, actor=1, reason="Retention approved", release=True
    )
    assert policy["actor"] == 1 and policy["revision"] == 1
    assert (await store.get_assessment_retention(saved.id))["state"] == "active-work-protected"
    assert await store.retained_snapshot_refs() == run.snapshot_refs
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(run.id, lease.lease_token, result={"verdict": "holds"})
    assert (await store.get_assessment_retention(saved.id))["state"] == "released"
    assert await store.retained_snapshot_refs() == []
    assert (await store.get_analysis_run(run.id)).result == {"verdict": "holds"}
    restored = await store.set_assessment_retention(saved.id, actor=2, reason="Extend audit retention")
    assert restored["revision"] == 2
    assert await store.retained_snapshot_refs() == run.snapshot_refs


async def test_retention_deadline_expiry_never_changes_recorded_verdict(monkeypatch):
    now = datetime(2026, 9, 8, tzinfo=UTC)
    monkeypatch.setattr(storage, "utcnow", lambda: now)
    store = MemoryAssessmentStore()
    saved, run = await saved_run(store, result={"verdict": "not-established"})
    await store.set_assessment_retention(
        saved.id, actor=1, reason="Ten second fixture", retain_until=(now + timedelta(seconds=10)).isoformat()
    )
    assert await store.retained_snapshot_refs()
    now += timedelta(seconds=11)
    assert await store.retained_snapshot_refs() == []
    assert (await store.get_analysis_run(run.id)).result == run.result


async def test_verified_proposal_preserves_exact_source_and_editing_requires_new_evaluation():
    store = MemoryAssessmentStore()
    # a stored repair finding, written in the result vocabulary
    candidate = project_engine(
        {
            "verified": True,
            "verdict": "holds",
            "desired": "holds",
            "protected": {"isolation": "holds"},
            "intents": [
                {"kind": "fw_rule.add", "params": {"position": 1}},
                {"kind": "fw_rule.remove", "params": {"rule": "old"}},
            ],
            "candidates": ["a", "b"],
        }
    )
    _saved, run = await saved_run(store, kind="repair", result={"findings": [candidate]})
    proposal = await save_proposal(store, run.id, finding_index=0, title="Verified repair", actor=1)
    assert proposal.definition["verification_state"] == "verified"
    assert proposal.definition["source_run_id"] == run.id
    assert proposal.definition["intents"] == candidate["intents"]
    revised = await store.create_change_revision(
        title="Edited repair",
        created_by=1,
        change_id=proposal.id,
        expected_revision=1,
        definition={**proposal.definition, "intents": list(reversed(candidate["intents"]))},
    )
    assert revised.revision == 2
    assert revised.definition["verification_state"] == "needs-evaluation"
    assert revised.definition["verified_result"] is None
    assert (await store.get_change_revision(proposal.id, 1)).definition["verification_state"] == "verified"
    with pytest.raises(RevisionConflict):
        await store.create_change_revision(
            title="Racing edit",
            created_by=1,
            change_id=proposal.id,
            expected_revision=1,
            definition={"intents": []},
        )
    assert [revision.revision for revision in await store.list_change_revisions(proposal.id)] == [2, 1]


async def test_unknown_protected_requirement_cannot_be_saved_as_verified_proposal():
    store = MemoryAssessmentStore()
    _saved, run = await saved_run(
        store,
        kind="repair",
        result={
            "findings": [
                {
                    "verified": True,
                    "result": condition_result("holds").model_dump(mode="json"),
                    "desired": condition_result("holds").model_dump(mode="json"),
                    "protected": {"isolation": condition_result("not-established").model_dump(mode="json")},
                    "intents": [],
                }
            ]
        },
    )
    with pytest.raises(ValueError, match="verifies the desired requirement and every protection"):
        await save_proposal(store, run.id, finding_index=0, title="No proof", actor=1)


class Result:
    def __init__(self, rows):
        self.rows = rows

    def data(self):
        return self.rows

    def single(self):
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


class Session:
    def run(self, query, **params):
        return Result([] if params.get("uid") == "absent" else [{"uid": "rule", "action": "drop"}])

    def execute_read(self, callback):
        return callback(self)


def test_read_boundary_records_absence_selectors_objects_and_safe_estate_fallback():
    recorder = DependencyRecorder("estate", "100")
    session = recorder.session(Session())
    assert (
        session.execute_read(lambda tx: tx.run("MATCH (n) WHERE n.uid=$uid RETURN n", uid="absent").data())
        == []
    )
    session.run("MATCH (n) RETURN n", uid="rule").single()
    refs = recorder.references()
    assert any(ref.get("absence") and ref["selector"] == {"uid": "absent"} for ref in refs)
    assert any(
        ref["kind"] == "graph-object" and ref["uid"] == "rule" and "action" in ref["properties"]
        for ref in refs
    )
    assert any(ref["kind"] == "estate" for ref in refs)
    assert not recorder.complete


def test_side_read_records_vrf_selectors_observation_time_and_empty_result():
    class Reader:
        def routes(self, device_uid, vrf):
            return []

    recorder = DependencyRecorder("estate", "100")
    reader = recorder.reader(Reader(), source="edge", section="routes", observed_ms=1000)
    assert reader.routes("device", "blue") == []
    reference = recorder.references()[0]
    assert reference["absence"] and reference["vrf"] == "blue"
    assert reference["device"] == "device" and reference["observed_ms"] == 1000
    assert recorder.complete


def test_dependency_overflow_preserves_safe_scope_without_failing_evaluation():
    recorder = DependencyRecorder("estate", "100", max_references=1)
    recorder.record("section", source="a", section="rules")
    recorder.record("section", source="b", section="rules")
    assert recorder.truncated
    assert recorder.references()[-1]["kind"] == "estate"
    assert recorder.references()[-1]["reason"] == "dependency-cap"


def record(devices):
    return SnapshotManifest(
        snapshot_key=100,
        kind="full",
        opened="2026-09-08T10:00:00+00:00",
        published="2026-09-08T10:01:00+00:00",
        estate="estate",
        devices=devices,
        sources=[SourceEntry(name="s", type="vyos", status="ok", config_sha256="same")],
    )


def device(host="required", **kwargs):
    return DeviceEntry(
        source="s",
        host=host,
        outcome="collected",
        raw_sha256="same",
        fetch_started_ms=int(datetime(2026, 9, 8, 10, 0, tzinfo=UTC).timestamp() * 1000),
        device_uids=[host],
        expected_sections=["rules"],
        sections={"rules": SectionOutcome(status="ok")},
        **kwargs,
    )


def test_scoped_verification_ignores_unrelated_failed_device_and_is_time_deterministic():
    required = device()
    unrelated = device("unrelated").model_copy(update={"outcome": "failed", "fetch_started_ms": None})
    manifest = record([required, unrelated])
    deps = [
        {"kind": "observation", "scope_complete": True, "source": "s", "host": "required", "section": "rules"}
    ]
    first = observation_coverage(manifest, deps, "2026-09-08T09:59:00+00:00", 120)
    assert first["qualifies"] and len(first["observations"]) == 1
    assert first == observation_coverage(manifest, deps, "2026-09-08T09:59:00+00:00", 120)
    assert not observation_coverage(manifest, [{"kind": "estate"}], "2026-09-08T09:59:00+00:00", 120)[
        "qualifies"
    ]


def test_scoped_old_side_observation_and_missing_metadata_are_not_verification():
    old = device(tables={"rib": TableOutcome(status="unchanged", observed_ms=1)})
    deps = [
        {"kind": "observation", "source": "s", "host": "required", "table": "rib", "scope_complete": True}
    ]
    assert not observation_coverage(record([old]), deps, "2026-09-08T09:59:00+00:00")["qualifies"]
    legacy = SimpleNamespace(devices=[old])
    report = observation_coverage(legacy, deps, "2026-09-08T09:59:00+00:00")
    assert report["snapshot"] is None
    assert report["missing"][0]["reasons"] == ["publication-time-unavailable"]


def test_manifest_changes_include_new_removed_and_changed_host_scopes():
    previous = record([device("removed"), device("kept"), device("untouched")])
    following = record(
        [device("added"), device("kept").model_copy(update={"raw_sha256": "new"}), device("untouched")]
    )
    scopes = manifest_changes(previous, following)
    assert {scope["host"] for scope in scopes} == {"removed", "added", "kept"}
    assert manifest_changes(None, following)[0]["kind"] == "estate"


async def test_scoped_publication_preserves_unrelated_reads_but_missed_delta_falls_back():
    store = MemoryAssessmentStore()
    saved, run = await saved_run(store)
    lease = await store.claim_analysis("worker")
    await store.finish_analysis(
        run.id,
        lease.lease_token,
        result={"verdict": "holds"},
        dependencies=[
            {"kind": "observation", "source": "router-a", "section": "routes", "scope_complete": True},
        ],
    )
    assert (
        await store.invalidate_assessments(
            "event-101",
            {"snapshot": "101"},
            [
                {"source": "router-b", "section": "routes", "from_snapshot": "100"},
            ],
        )
        == []
    )
    # A watcher restart skipped 101.
    assert await store.invalidate_assessments(
        "event-102",
        {"snapshot": "102"},
        [
            {"source": "router-b", "section": "routes", "from_snapshot": "101"},
        ],
    ) == [saved.id]


def test_policy_collection_followup_requires_requested_section_without_unrelated_rib():
    from hst.assessment.lifecycle import _observation, _same_gap

    now = datetime.now(UTC)
    action = {
        "source": "controller",
        "host": "",
        "sections": ["policy"],
        "tables": [],
        "requested_at": (now - timedelta(seconds=5)).isoformat(),
        "recipe_ids": ["unifi.policy"],
        "gap_ids": ["policy-gap"],
    }
    device = DeviceEntry(
        source="controller",
        host="",
        outcome="collected",
        fetch_started_ms=int(now.timestamp() * 1000),
        sections={"policy": SectionOutcome(status="ok")},
    )
    assert _observation(action, SimpleNamespace(devices=[device]), 3600)[0] == "ready"
    assert _same_gap(action, {"id": "policy-gap", "code": "policy-unobserved"})
    assert not _same_gap(action, {"id": "different", "code": "routing-observation-missing"})
    routing = {**action, "tables": ["rib"]}
    assert _observation(routing, SimpleNamespace(devices=[device]), 3600)[0] == "failed"
