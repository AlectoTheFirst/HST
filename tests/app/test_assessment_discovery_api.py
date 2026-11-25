"""Discovery is graph-read-only and suggestions retain exact assessment lineage."""

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.app.test_assessment_lifecycle_complete import saved_run

from hst.app.routes import assessment_discovery
from hst.assessment.store import MemoryAssessmentStore


class AssessmentFake(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return AssessmentFake()


async def test_discovery_requires_login_and_explicit_snapshot(client, monkeypatch):
    calls = []

    def search(settings, snapshot, kind, q, uid, **kwargs):
        calls.append((snapshot, kind, q, uid, kwargs))
        return {"snapshot": snapshot, "items": [], "truncated": False}

    monkeypatch.setattr(assessment_discovery, "search_options", search)
    assert (await client.get("/api/assessment-options?snapshot=100")).status_code == 401
    await login(client, "vera")
    assert (await client.get("/api/assessment-options")).status_code == 422
    response = await client.get(
        "/api/assessment-options",
        params={"snapshot": "100", "kind": "link,tunnel", "q": "Frankfurt", "uid": "link:frankfurt"},
    )
    assert response.status_code == 200, response.text
    assert calls == [("100", "link,tunnel", "Frankfurt", "link:frankfurt", {"dependencies": [], "limit": 50})]


async def test_suggestions_use_completed_matching_snapshot_only(client, store, monkeypatch):
    deps = [{"kind": "graph-object", "uid": "device:frankfurt", "snapshot": "100"}]
    saved, _run = await saved_run(store, result={"dependencies": deps})
    await store.enqueue_analysis(
        assessment_id=saved.id,
        assessment_revision=1,
        kind="resilience",
        inputs={},
        snapshot_refs=[{"snapshot": "200"}],
        engine_version="fixture",
        created_by=1,
    )
    calls = []

    def search(settings, snapshot, kind, q, uid, **kwargs):
        calls.append(kwargs["dependencies"])
        return {"snapshot": snapshot, "items": [], "truncated": False}

    monkeypatch.setattr(assessment_discovery, "search_options", search)
    await login(client, "vera")
    response = await client.get(
        "/api/assessment-options", params={"snapshot": "100", "assessment_id": saved.id}
    )
    assert response.status_code == 200, response.text
    assert calls == [deps]
    assert "100 most recent" in response.json()["suggestion_scope"]
    response = await client.get(
        "/api/assessment-options", params={"snapshot": "200", "assessment_id": saved.id}
    )
    assert response.status_code == 200
    assert calls[-1] == []
    response = await client.get(
        "/api/assessment-options", params={"snapshot": "100", "assessment_id": "missing"}
    )
    assert response.status_code == 404


async def test_invalid_discovery_scope_reports_validation_error(client, monkeypatch):
    def search(*args, **kwargs):
        raise ValueError("Select a published snapshot before choosing assessment objects.")

    monkeypatch.setattr(assessment_discovery, "search_options", search)
    await login(client, "vera")
    response = await client.get("/api/assessment-options?snapshot=latest")
    assert response.status_code == 422
    assert "published snapshot" in response.json()["error"]
    assert (await client.get("/api/assessment-options?snapshot=100&limit=101")).status_code == 422
