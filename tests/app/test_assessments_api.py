"""Assessment contracts: authorization, immutable inputs, exact exports and pinning."""

import json
from datetime import UTC, datetime

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.app.test_impact_api import REQUEST

from hst.app.routes import assessments as routes
from hst.assessment.store import MemoryAssessmentStore, input_digest


class AssessmentFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return AssessmentFakeStore()


@pytest.fixture(autouse=True)
def references(monkeypatch):
    def reference(settings, value=None):
        return {"snapshot": value or "2000", "manifest_sha256": f"digest-{value or '2000'}", "estate": "test"}

    monkeypatch.setattr(routes.service, "snapshot_reference", reference)
    monkeypatch.setattr(routes.service, "engine_version", lambda settings: "engine-test")


async def create(client, **definition):
    response = await client.post(
        "/api/assessments",
        json={"title": "Checkout", "definition": {"request": REQUEST, "mode": "possible", **definition}},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def finish(store, result):
    run = await store.claim_analysis("test")
    assert run is not None
    assert await store.finish_analysis(run.id, run.lease_token, result=result)
    return run


async def test_anonymous_and_viewer_cannot_submit(client):
    assert (await client.get("/api/assessments")).status_code == 401
    await login(client, "vera")
    assert (await client.get("/api/assessments")).status_code == 200
    assert (
        await client.post("/api/assessments", json={"title": "Blocked", "definition": {"request": REQUEST}})
    ).status_code == 403


async def test_save_revise_and_reopen_immutable_definition(client):
    await login(client, "otto")
    item = await create(client)
    edited = {
        "title": "Checkout revised",
        "expected_revision": 1,
        "definition": {**item["definition"], "mode": "guaranteed"},
    }
    response = await client.patch(f"/api/assessments/{item['id']}", json=edited)
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == 2
    old = (await client.get(f"/api/assessments/{item['id']}?revision=1")).json()
    assert old["assessment"]["definition"]["mode"] == "possible"
    assert (await client.patch(f"/api/assessments/{item['id']}", json=edited)).status_code == 409


async def test_job_resolves_snapshot_and_hides_lease(client, store):
    await login(client, "otto")
    item = await create(client)
    response = await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    assert response.status_code == 202, response.text
    run = response.json()
    assert run["inputs"]["definition"]["request"] == item["definition"]["request"]
    assert run["snapshot_refs"][0]["snapshot"] == "2000"
    claimed = await store.claim_analysis("worker")
    fetched = (await client.get(f"/api/analysis-jobs/{claimed.id}")).json()
    assert fetched["state"] == "running"
    assert "lease_token" not in fetched
    assert "claimed_by" not in fetched
    assert (await client.post(f"/api/analysis-jobs/{claimed.id}/cancel")).json()["cancel_requested"]


async def test_an_analysis_answers_503_and_queues_no_run_while_the_cycle_lock_stays_held(
    client, store, monkeypatch
):
    monkeypatch.setattr(routes, "CYCLE_LOCK_WAIT_S", 0.01)
    await login(client, "otto")
    item = await create(client)
    async with store.cycle_lock():
        response = await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    assert response.status_code == 503
    assert response.json()["error"] == routes.CYCLE_LOCK_BUSY
    assert await store.claim_analysis("worker") is None


async def test_export_exact_result_does_not_rerun_latest(client, store, monkeypatch):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    run = await finish(store, {"outcomes": {"after": {"verdict": "holds"}}, "snapshot": "2000"})

    def no_latest(*args, **kwargs):
        raise AssertionError("export must not query latest")

    monkeypatch.setattr(routes.service, "snapshot_reference", no_latest)
    response = await client.get(f"/api/assessments/{item['id']}/runs/{run.id}/export")
    assert response.status_code == 200
    package = json.loads(response.content)
    digest = package.pop("sha256")
    assert digest == input_digest(package)
    assert package["run"]["result"]["snapshot"] == "2000"
    assert "lease_token" not in package["run"]


async def test_analysis_contracts_reject_incomplete_searches(client):
    await login(client, "otto")
    item = await create(client)
    url = f"/api/assessments/{item['id']}/analyses"
    for body in (
        {"kind": "regression"},
        {"kind": "repair"},
        {"kind": "resilience"},
        {"kind": "evaluate", "limits": {"max_evaluations": 10001}},
        {"kind": "unknown"},
    ):
        assert (await client.post(url, json=body)).status_code == 422


async def test_verify_uses_deployed_revision_and_post_deployment_snapshot(client, store):
    await login(client, "otto")
    item = await create(client, snapshot="1000")
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    await finish(store, {"outcomes": {"after": {"verdict": "holds"}}})
    deploy = await client.post(
        f"/api/assessments/{item['id']}/deployments",
        json={"reference": "CHG-1", "deployed_at": "2026-01-01T10:00:00+00:00", "assessment_revision": 1},
    )
    assert deploy.status_code == 201, deploy.text
    result = await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "verify"})
    assert result.status_code == 202, result.text
    inputs = result.json()["inputs"]
    assert inputs["definition"] == item["definition"]
    assert inputs["snapshot_refs"][0]["snapshot"] == "2000"
    assert inputs["deployment"]["assessment_revision"] == 1


async def test_collection_uses_stored_recipe_and_checks_source(client, store):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "troubleshoot"})
    action = {
        "id": "rib",
        "recipe_id": "nxos.rib.ipv4",
        "source": "edge",
        "host": "switch",
        "section": "rib",
        "state": "available",
        "commands": ["show ip route vrf all | json"],
    }
    run = await finish(store, {"actions": [action]})
    url = f"/api/assessments/{item['id']}/collection-actions"
    assert (await client.post(url, json={"run_id": run.id, "action_ids": ["invented"]})).status_code == 422
    await store.create_source("edge", "nxos", {"host": "switch"}, b"encrypted", enabled=False)
    assert (await client.post(url, json={"run_id": run.id, "action_ids": ["rib"]})).status_code == 422


async def test_verification_requires_prediction_and_timezone(client):
    await login(client, "otto")
    item = await create(client)
    response = await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "verify"})
    assert response.status_code == 422


async def test_saved_requirement_revision_and_reference_integrity(client):
    await login(client, "otto")
    response = await client.post(
        "/api/requirements", json={"title": "Checkout", "definition": {"request": REQUEST}}
    )
    assert response.status_code == 200, response.text
    requirement = response.json()
    item = await create(client, requirement_id=requirement["id"], requirement_revision=1)
    updated = await client.patch(
        f"/api/requirements/{requirement['id']}",
        json={"title": "Renamed", "expected_revision": 1, "definition": {"request": REQUEST}},
    )
    assert updated.status_code == 200
    old = await client.get(f"/api/requirements/{requirement['id']}?revision=1")
    assert old.json()["title"] == "Checkout"
    assert item["definition"]["requirement_revision"] == 1
    response = await client.post(
        "/api/assessments",
        json={
            "title": "Invalid",
            "definition": {
                "request": {**REQUEST, "sources": ["192.0.2.1/32"]},
                "requirement_id": requirement["id"],
                "requirement_revision": 1,
            },
        },
    )
    assert response.status_code == 422


async def test_portable_export_permission_and_private_temporary_cleanup(client, store, monkeypatch):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    run = await finish(store, {"snapshot": "2000"})
    paths = []

    def build(settings, recorded, destination):
        assert recorded.id == run.id
        assert not destination.exists()
        destination.write_bytes(b"archive")
        paths.append(destination)

    monkeypatch.setattr(routes.packages, "build_portable", build)
    url = f"/api/assessments/{item['id']}/runs/{run.id}/export?portable=true"
    response = await client.get(url)
    assert response.status_code == 200
    assert response.content == b"archive"
    assert not paths[0].exists()
    await login(client, "vera")
    assert (await client.get(url)).status_code == 403
    assert len(paths) == 1


async def test_collection_prevalidates_all_targets_and_records_before_queue(client, store, monkeypatch):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "troubleshoot"})
    actions = [
        {
            "id": name,
            "recipe_id": "nxos.rib.ipv4",
            "source": name,
            "host": "switch",
            "section": "rib",
            "state": "available",
        }
        for name in ("one", "two")
    ]
    run = await finish(store, {"actions": actions})
    await store.create_source("one", "nxos", {"host": "switch"}, b"encrypted", enabled=True)
    queued = []

    async def enqueue(*args, **kwargs):
        record = await store.get_assessment(item["id"])
        assert any(a["source"] == kwargs["source"] for a in record.definition["collection_actions"])
        queued.append(kwargs)
        return None

    monkeypatch.setattr(store, "enqueue_job", enqueue)
    url = f"/api/assessments/{item['id']}/collection-actions"
    response = await client.post(url, json={"run_id": run.id, "action_ids": ["one", "two"]})
    assert response.status_code == 422
    assert not queued
    response = await client.post(url, json={"run_id": run.id, "action_ids": ["one"]})
    assert response.status_code == 200, response.text
    assert len(queued) == 1
    assert response.json()["actions"][0]["state"] == "awaiting_publication"
    response = await client.post(
        f"/api/assessments/{item['id']}/deployments",
        json={
            "reference": "CHG-2",
            "assessment_revision": 1,
            "deployed_at": datetime.now(UTC).replace(tzinfo=None).isoformat(),
        },
    )
    assert response.status_code == 422


async def test_the_exact_run_export_is_a_json_attachment_named_after_the_run(client, store):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    run = await finish(store, {"snapshot": "2000"})

    response = await client.get(f"/api/assessments/{item['id']}/runs/{run.id}/export")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == f'attachment; filename="assessment-{run.id}.json"'
    assert json.loads(response.content)["run"]["id"] == run.id


async def test_a_retry_of_a_failed_run_queues_a_new_run_and_keeps_the_failed_one(client, store):
    await login(client, "otto")
    item = await create(client)
    await client.post(f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate"})
    claimed = await store.claim_analysis("test")
    assert await store.finish_analysis(
        claimed.id, claimed.lease_token, result={"stop_reason": "execution-failed"}, state="failed"
    )

    response = await client.post(
        f"/api/assessments/{item['id']}/analyses", json={"kind": "evaluate", "retry_of": claimed.id}
    )

    assert response.status_code == 202, response.text
    retry = await store.get_analysis_run(response.json()["id"])
    assert retry.id != claimed.id
    assert retry.retry_of == claimed.id
    assert retry.state == "queued"
    failed = await store.get_analysis_run(claimed.id)
    assert failed.state == "failed"
    assert failed.result == {"stop_reason": "execution-failed"}
