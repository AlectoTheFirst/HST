"""Assessment freshness: which runs clear it, which run a read pairs it with,
which troubleshoot run the library's evidence portfolio takes, and the time a
verification is submitted at."""

from datetime import UTC, datetime

from tests.app.conftest import login
from tests.app.test_assessments_api import create, finish
from tests.app.test_assessments_api import references as references
from tests.app.test_assessments_api import store as store
from tests.app.test_impact_api import REQUEST

from hst.assessment.read import read_saved
from hst.assessment.store import MemoryAssessmentStore

REQ_A = {"name": "A", "destination": "a", "sources": ["10.0.0.1"]}
REQ_B = {"name": "B", "destination": "b", "sources": ["10.9.9.9"]}
REF = {
    "snapshot": "100",
    "manifest_sha256": "a" * 64,
    "estate": "default",
    "observation_floor_ms": 4102444800000,
}


async def _run(memory, saved, revision, kind, inputs, result=None, ref=REF):
    run = await memory.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=revision,
        kind=kind,
        inputs=inputs,
        snapshot_refs=[ref],
        engine_version="e1",
        created_by=1,
        limits={},
    )
    claimed = await memory.claim_analysis("w")
    assert claimed.id == run.id
    await memory.finish_analysis(claimed.id, claimed.lease_token, result=result or {}, state="completed")
    return run


async def _revise(memory, saved, revision, **definition):
    return await memory.create_assessment(
        title="t",
        purpose="evaluation",
        created_by=1,
        assessment_id=saved.id,
        expected_revision=revision,
        definition={"intents": [], "freshness_s": 3600, "deployments": [], **definition},
    )


async def _state(memory, saved):
    return (await memory.get_assessment_freshness(saved.id))["state"]


async def test_a_verify_run_of_the_deployed_definition_does_not_clear_a_revised_request():
    memory = MemoryAssessmentStore()
    first = await memory.create_assessment(
        title="t",
        purpose="evaluation",
        created_by=1,
        definition={"request": REQ_A, "intents": [{"kind": "fw_rule.add"}], "freshness_s": 3600},
    )
    await _run(memory, first, 1, "evaluate", {"definition": first.definition})
    assert await _state(memory, first) == "current"
    deployment = {"reference": "CHG-1", "deployed_at": "2026-11-01T00:00:00+00:00", "assessment_revision": 1}
    await _revise(memory, first, 1, request=REQ_B, deployments=[deployment])
    assert await _state(memory, first) == "needs-reassessment"
    await _run(memory, first, 2, "verify", {"definition": first.definition, "prediction": {}})
    assert await _state(memory, first) == "needs-reassessment"


async def test_runs_that_evaluate_no_intents_do_not_clear_the_flag_and_an_evaluation_does():
    memory = MemoryAssessmentStore()
    first = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition={"request": REQ_A, "intents": []}
    )
    second = await _revise(memory, first, 1, request=REQ_A, intents=[{"kind": "fw_rule.add"}])
    assert await _state(memory, first) == "needs-reassessment"
    for kind in ("regression", "repair", "resilience"):
        await _run(memory, first, 2, kind, {"definition": second.definition, "kind": kind})
        assert await _state(memory, first) == "needs-reassessment", kind
    await _run(memory, first, 2, "troubleshoot", {"definition": second.definition})
    assert await _state(memory, first) == "current"


async def test_a_run_read_by_id_is_superseded_when_another_run_made_the_assessment_current():
    memory = MemoryAssessmentStore()
    saved = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition={"request": REQ_A, "intents": []}
    )
    old = await _run(memory, saved, 1, "evaluate", {"definition": saved.definition, "n": 1})
    newer = {**REF, "snapshot": "200", "manifest_sha256": "b" * 64}
    new = await _run(memory, saved, 1, "evaluate", {"definition": saved.definition, "n": 2}, ref=newer)
    read_old = await read_saved(None, old.id, store=memory)
    assert read_old["freshness"]["state"] == "superseded"
    assert read_old["freshness"]["run_id"] == new.id
    assert (await read_saved(None, new.id, store=memory))["freshness"]["state"] == "current"


async def test_a_run_of_a_revised_request_on_the_same_snapshot_is_superseded():
    memory = MemoryAssessmentStore()
    first = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition={"request": REQ_A, "intents": []}
    )
    old = await _run(memory, first, 1, "evaluate", {"definition": first.definition})
    second = await _revise(memory, first, 1, request=REQ_B)
    await _run(memory, first, 2, "evaluate", {"definition": second.definition})
    assert (await read_saved(None, old.id, store=memory))["freshness"]["state"] == "superseded"


async def test_a_run_on_the_inputs_of_the_current_run_reads_current_and_a_verify_run_keeps_it():
    memory = MemoryAssessmentStore()
    saved = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition={"request": REQ_A, "intents": []}
    )
    evaluation = await _run(memory, saved, 1, "evaluate", {"definition": saved.definition})
    search = await _run(memory, saved, 1, "resilience", {"definition": saved.definition})
    verify = await _run(memory, saved, 1, "verify", {"definition": saved.definition, "prediction": {}})
    fresh = await memory.get_assessment_freshness(saved.id)
    assert fresh["state"] == "current" and fresh["run_id"] == search.id
    # the evaluation states the same inputs as the current run; a verify run
    # answers another question: the assessment freshness is returned as it is
    assert (await read_saved(None, evaluation.id, store=memory))["freshness"]["state"] == "current"
    read_verify = (await read_saved(None, verify.id, store=memory))["freshness"]
    assert read_verify == {**fresh, "run_is_freshness_basis": False}


async def test_a_search_run_of_a_definition_without_intents_clears_the_flag():
    memory = MemoryAssessmentStore()
    first = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition={"request": REQ_A, "intents": []}
    )
    second = await _revise(memory, first, 1, request=REQ_B)
    assert await _state(memory, first) == "needs-reassessment"
    await _run(memory, first, 2, "resilience", {"definition": second.definition})
    assert await _state(memory, first) == "current"


async def test_the_evidence_portfolio_ignores_troubleshoot_runs_of_a_revised_request(client, store):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "troubleshoot"})
    action = {
        "id": "old-action",
        "source": "edge",
        "host": "r1",
        "recipe_id": "vyos.rib.ipv4",
        "section": "routes",
    }
    await finish(store, {"actions": [action]})

    async def portfolio():
        body = (await client.get("/api/assessments?include_evidence=true")).json()
        return body["evidence_portfolio"]["assessments"]

    assert await portfolio() == [item["id"]]
    # a deployment is recorded as a new revision of the same definition
    deploy = await client.post(
        f"/api/assessments/{item['id']}/deployments",
        json={"reference": "CHG-1", "deployed_at": "2026-01-01T10:00:00+00:00", "assessment_revision": 1},
    )
    assert deploy.status_code == 201, deploy.text
    assert await portfolio() == [item["id"]]
    current = (await client.get(f"/api/assessments/{item['id']}")).json()["assessment"]
    revised = await client.patch(
        f"/api/assessments/{item['id']}",
        json={
            "title": "Checkout",
            "expected_revision": current["revision"],
            "definition": {**current["definition"], "request": {**REQUEST, "name": "other"}},
        },
    )
    assert revised.status_code == 200, revised.text
    assert await portfolio() == []


async def test_verify_records_its_submission_time(client, store):
    await login(client, "otto")
    item = await create(client, snapshot="1000")
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    await finish(store, {"outcomes": {"after": {"verdict": "holds"}}})
    deploy = await client.post(
        f"/api/assessments/{item['id']}/deployments",
        json={"reference": "CHG-1", "deployed_at": "2026-01-01T10:00:00+00:00", "assessment_revision": 1},
    )
    assert deploy.status_code == 201, deploy.text
    before = datetime.now(UTC)
    result = await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "verify"})
    assert result.status_code == 202, result.text
    submitted = datetime.fromisoformat(result.json()["inputs"]["submitted_at"])
    assert before <= submitted <= datetime.now(UTC)


MIXED = {**REQUEST, "sources": ["192.168.10.0/24", "LAN"]}


async def test_submit_refuses_a_saved_request_with_an_unreadable_address_and_names_it(client, store):
    await login(client, "otto")
    saved = await store.create_assessment(
        title="Legacy",
        purpose="evaluation",
        created_by=1,
        definition={"request": MIXED, "mode": "possible", "intents": [], "deployments": []},
    )
    response = await client.post(f"/api/assessments/{saved.id}/analyses", json={"kind": "evaluate"})
    assert response.status_code == 400, response.text
    assert "LAN" in response.text
    assert await store.list_analysis_runs(saved.id) == []


async def test_a_queued_run_of_an_unreadable_request_fails_with_the_named_cause():
    from types import SimpleNamespace

    from hst.assessment import service
    from hst.assessment.jobs import AnalysisWorker
    from hst.assessment.models import Analyze

    memory = MemoryAssessmentStore()
    definition = {"request": MIXED, "mode": "possible", "intents": []}
    saved = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition=definition
    )
    analysis = Analyze(kind="evaluate").model_dump(mode="json")
    run = await memory.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=1,
        kind="evaluate",
        inputs={"definition": definition, "analysis": analysis, "snapshot_refs": [REF]},
        snapshot_refs=[REF],
        engine_version="e1",
        created_by=1,
        limits=analysis["limits"],
    )
    settings = SimpleNamespace(analysis_memory_mb=1024, analysis_timeout_s=30, analysis_poll_s=0.02)
    worker = AnalysisWorker(memory, settings, execute=service.execute, poll_s=0.02, lease_seconds=30)
    assert await worker.run_once()
    finished = await memory.get_analysis_run(run.id)
    assert finished.state == "failed"
    assert finished.result["stop_reason"] == "invalid-definition"
    assert "LAN" in finished.error
    assert await _state(memory, saved) != "current"


async def _clocked(monkeypatch):
    import hst.assessment.store as module

    ticks = iter(range(10_000))
    start = datetime(2026, 11, 13, tzinfo=UTC)
    from datetime import timedelta

    monkeypatch.setattr(module, "utcnow", lambda: start + timedelta(seconds=next(ticks)))


async def test_an_older_run_is_superseded_and_a_newer_one_is_not_current(monkeypatch):
    await _clocked(monkeypatch)
    memory = MemoryAssessmentStore()
    first = await memory.create_assessment(
        title="t", purpose="evaluation", created_by=1, definition={"request": REQ_A, "intents": []}
    )
    old = await _run(memory, first, 1, "evaluate", {"definition": first.definition})
    second = await _revise(memory, first, 1, request=REQ_A, intents=[{"kind": "fw_rule.add"}])
    current = await _run(memory, first, 2, "evaluate", {"definition": second.definition})
    newer = await _run(memory, first, 2, "regression", {"definition": second.definition})
    queued = await memory.enqueue_analysis(
        assessment_id=first.id,
        assessment_revision=2,
        kind="evaluate",
        inputs={"definition": second.definition, "n": 3},
        snapshot_refs=[{**REF, "snapshot": "300"}],
        engine_version="e1",
        created_by=1,
        limits={},
    )
    fresh = await memory.get_assessment_freshness(first.id)
    assert fresh["state"] == "current" and fresh["run_id"] == current.id
    read_old = (await read_saved(None, old.id, store=memory))["freshness"]
    assert read_old["state"] == "superseded" and "run_is_freshness_basis" not in read_old
    assert (await read_saved(None, queued.id, store=memory))["freshness"]["state"] == "not-current"
    # a regression of a change assessment cannot set freshness: not relabelled
    read_newer = (await read_saved(None, newer.id, store=memory))["freshness"]
    assert read_newer == {**fresh, "run_is_freshness_basis": False}


async def test_an_earlier_search_run_of_a_change_assessment_is_not_superseded(monkeypatch):
    await _clocked(monkeypatch)
    memory = MemoryAssessmentStore()
    saved = await memory.create_assessment(
        title="t",
        purpose="evaluation",
        created_by=1,
        definition={"request": REQ_A, "intents": [{"kind": "fw_rule.add"}]},
    )
    search = await _run(memory, saved, 1, "resilience", {"definition": saved.definition})
    await _run(memory, saved, 1, "evaluate", {"definition": saved.definition})
    read = (await read_saved(None, search.id, store=memory))["freshness"]
    assert read["state"] == "current" and read["run_is_freshness_basis"] is False


def missing_requirement(settings, inputs, *, progress, cancelled):
    from fastapi import HTTPException

    raise HTTPException(404, detail="no service requirement req:x in this snapshot")


async def test_a_requirement_missing_from_the_snapshot_is_input_unavailable_with_its_text():
    from types import SimpleNamespace

    from hst.assessment.jobs import AnalysisWorker

    memory = MemoryAssessmentStore()
    saved = await memory.create_assessment(title="t", purpose="evaluation", created_by=1, definition={})
    run = await memory.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=1,
        kind="evaluate",
        inputs={},
        snapshot_refs=[REF],
        engine_version="e1",
        created_by=1,
    )
    settings = SimpleNamespace(analysis_memory_mb=1024, analysis_timeout_s=30, analysis_poll_s=0.02)
    worker = AnalysisWorker(memory, settings, execute=missing_requirement, poll_s=0.02, lease_seconds=30)
    assert await worker.run_once()
    finished = await memory.get_analysis_run(run.id)
    assert finished.state == "failed"
    assert finished.result["stop_reason"] == "input-unavailable"
    assert "req:x" in finished.error


async def test_submit_does_not_reparse_a_population_artifact(client, store, monkeypatch):
    from hst.app.routes import assessments as routes

    await login(client, "otto")
    item = await create(client)
    stored = await store.get_assessment(item["id"])
    request = {
        **stored.definition["request"],
        "population": {"kind": "fixture"},
        "population_artifact": {"id": "artifact"},
        "population_complete": True,
        "population_scope": "fixture",
    }
    saved = await store.create_assessment(
        title="Population",
        purpose="evaluation",
        created_by=1,
        definition={**stored.definition, "request": request},
    )
    parsed = []
    original = routes.ev._request_from_body
    monkeypatch.setattr(routes.ev, "_request_from_body", lambda body: parsed.append(body) or original(body))
    response = await client.post(f"/api/assessments/{saved.id}/analyses", json={"kind": "evaluate"})
    assert response.status_code == 202, response.text
    assert parsed == []
