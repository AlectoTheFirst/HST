"""Proposal lineage and explicit retention policy through authenticated HTTP."""

from datetime import UTC, datetime, timedelta

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.app.test_assessment_lifecycle_complete import saved_run

from hst.assessment.store import MemoryAssessmentStore
from hst.results.project import project_engine


class AssessmentFake(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return AssessmentFake()


async def proposal_fixture(store):
    # a stored repair finding, written in the result vocabulary
    finding = project_engine(
        {
            "verified": True,
            "verdict": "holds",
            "desired": "holds",
            "protected": {"isolation": "holds"},
            "intents": [{"kind": "fw_rule.remove", "params": {"rule": "obsolete"}}],
            "preconditions": [{"rule": "obsolete", "exists": True}],
        }
    )
    return await saved_run(store, kind="repair", result={"findings": [finding]})


async def test_save_reopen_revise_exact_proposal_and_conflict(client, store):
    saved, run = await proposal_fixture(store)
    await login(client, "otto")
    url = f"/api/assessments/{saved.id}/runs/{run.id}/proposals"
    response = await client.post(url, json={"finding_index": 0, "title": "Remove obsolete rule"})
    assert response.status_code == 201, response.text
    proposal = response.json()
    assert proposal["definition"]["verification_state"] == "verified"
    assert proposal["definition"]["source_run_id"] == run.id
    detail = (await client.get(f"/api/assessments/{saved.id}")).json()
    assert detail["proposals"] == [proposal]
    path = f"/api/change-revisions/{proposal['id']}"
    response = await client.patch(path, json={"title": "Edited", "intents": [], "expected_revision": 1})
    assert response.status_code == 200, response.text
    revised = response.json()
    assert revised["revision"] == 2
    assert revised["definition"]["verification_state"] == "needs-evaluation"
    assert revised["definition"]["verified_result"] is None
    assert revised["definition"]["protected"] == proposal["definition"]["protected"]
    assert (await client.get(path, params={"revision": 1})).json() == proposal
    assert len((await client.get(path + "/revisions")).json()["revisions"]) == 2
    assert (
        await client.patch(path, json={"title": "Race", "intents": [], "expected_revision": 1})
    ).status_code == 409
    assert (await client.get(f"/api/assessments/{saved.id}")).json()["proposals"] == [revised]
    assert (
        await client.post(url.replace(saved.id, "wrong"), json={"finding_index": 0, "title": "Bad"})
    ).status_code == 404


async def test_proposal_mutation_requires_operator_and_verified_finding(client, store):
    saved, run = await saved_run(store, kind="repair", result={"findings": [{"verified": False}]})
    path = f"/api/assessments/{saved.id}/runs/{run.id}/proposals"
    await login(client, "vera")
    assert (await client.post(path, json={"finding_index": 0, "title": "Bad"})).status_code == 403
    await login(client, "otto")
    assert (await client.post(path, json={"finding_index": 0, "title": "Bad"})).status_code == 422


async def test_retention_admin_actor_deadline_and_ongoing_run_protection(client, store):
    saved, run = await saved_run(store)
    path = f"/api/assessments/{saved.id}/retention"
    await login(client, "otto")
    assert (
        await client.put(path, json={"reason": "Operator cannot release", "release": True})
    ).status_code == 403
    await login(client, "ada")
    response = await client.put(path, json={"reason": "Retention approved", "release": True})
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "active-work-protected"
    assert response.json()["policy"]["actor"] == (await store.get_user_by_username("ada")).id
    assert await store.retained_snapshot_refs() == run.snapshot_refs
    deadline = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    response = await client.put(path, json={"reason": "Keep through audit", "retain_until": deadline})
    assert response.json()["policy"]["retain_until"] == deadline
    assert response.json()["policy"]["revision"] == 2
    assert (
        await client.put(path, json={"reason": "Ambiguous", "retain_until": deadline, "release": True})
    ).status_code == 422
    assert (
        await client.put(path, json={"reason": "No timezone", "retain_until": "2026-10-01"})
    ).status_code == 422
    assert (await client.put(path, json={"reason": "Spoof actor", "actor": 999})).status_code == 422


async def test_replay_availability_belongs_to_exact_run_and_includes_policy(client, store, monkeypatch):
    from hst.app.routes import assessments

    saved, run = await saved_run(store, result={"verdict": "holds"})
    monkeypatch.setattr(
        assessments.packages, "replay_status", lambda settings, run: {"available": True, "bytes": 123}
    )
    await login(client, "vera")
    path = f"/api/assessments/{saved.id}/runs/{run.id}/replay-status"
    response = await client.get(path)
    assert response.status_code == 200
    assert response.json()["bytes"] == 123
    assert response.json()["retention"]["state"] == "retained"
    assert (await client.get(path.replace(saved.id, "wrong"))).status_code == 404


async def test_replay_availability_answers_503_while_the_cycle_lock_stays_held(client, store, monkeypatch):
    from hst.app.routes import assessments

    saved, run = await saved_run(store, result={"verdict": "holds"})
    read: list[str] = []
    monkeypatch.setattr(
        assessments.packages, "replay_status", lambda settings, run: read.append(run.id) or {}
    )
    monkeypatch.setattr(assessments, "STATUS_LOCK_WAIT_S", 0.01)
    await login(client, "vera")
    async with store.cycle_lock():
        response = await client.get(f"/api/assessments/{saved.id}/runs/{run.id}/replay-status")
    assert response.status_code == 503
    assert response.json()["error"] == assessments.CYCLE_LOCK_BUSY
    assert read == []


async def test_a_retention_write_answers_503_while_the_cycle_lock_stays_held(client, store, monkeypatch):
    from hst.app.routes import assessments

    saved, _run = await saved_run(store, result={"verdict": "holds"})
    monkeypatch.setattr(assessments, "CYCLE_LOCK_WAIT_S", 0.01)
    await login(client, "ada")
    path = f"/api/assessments/{saved.id}/retention"
    before = (await client.get(path)).json()
    async with store.cycle_lock():
        response = await client.put(path, json={"reason": "Audit hold"})
    assert response.status_code == 503
    assert (await client.get(path)).json() == before


async def test_change_reference_is_exact_and_staleness_never_rebinds_inputs(store):
    from hst.app.routes.assessments import _requirement_reference
    from hst.assessment.models import Definition

    _saved, run = await proposal_fixture(store)
    from hst.assessment.proposals import save_proposal

    proposal = await save_proposal(store, run.id, finding_index=0, title="Original", actor=1)
    definition = {"intents": proposal.definition["intents"], "change_id": proposal.id, "change_revision": 1}
    await _requirement_reference(store, definition)
    with pytest.raises(ValueError, match="intents"):
        await _requirement_reference(store, {**definition, "intents": []})
    with pytest.raises(ValueError, match="both its ID and revision"):
        Definition(requirement="requirement:fixture", change_id=proposal.id)
    assessment = await store.create_assessment(
        title="Linked", purpose="evaluation", definition=definition, created_by=1
    )
    await store.create_change_revision(
        title="Edited", definition={"intents": []}, created_by=1, change_id=proposal.id, expected_revision=1
    )
    freshness = await store.get_assessment_freshness(assessment.id)
    assert "change-revision" in freshness["causes"]
    assert (await store.get_assessment(assessment.id)).definition == definition


async def test_linked_analysis_cannot_omit_or_weaken_protected_requirements(store, monkeypatch):
    from hst.app.routes import assessments
    from hst.assessment.models import Analyze

    request = {
        "name": "app",
        "destination": "app",
        "sources": ["10.0.0.1"],
        "members": [{"name": "app", "addresses": ["203.0.113.10"]}],
        "condition": {"kind": "member", "member": "app"},
    }
    protected = {"name": "isolation", "request": request, "desired": "isolated"}
    proposal = await store.create_change_revision(
        title="Protected change",
        definition={"intents": [], "protected": [protected]},
        created_by=1,
    )
    saved = await store.create_assessment(
        title="Linked",
        purpose="evaluation",
        created_by=1,
        definition={
            "request": request,
            "intents": [],
            "change_id": proposal.id,
            "change_revision": proposal.revision,
        },
    )
    monkeypatch.setattr(
        assessments.service, "snapshot_reference", lambda settings, value=None: {"snapshot": "100"}
    )
    monkeypatch.setattr(assessments.service, "engine_version", lambda settings: "fixture")
    run = await assessments.submit(store, None, saved, Analyze(), 1)
    assert run.inputs["analysis"]["protected"][0]["desired"] == "isolated"
    with pytest.raises(ValueError, match="cannot be weakened"):
        await assessments.submit(
            store, None, saved, Analyze(protected=[{**protected, "desired": "holds"}]), 1
        )
