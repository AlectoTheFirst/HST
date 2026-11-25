"""Engine admission of a connection session through the real submission path:
connections past the per-actor bound are omitted as partial coverage, and a
later run submits them."""

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.routes import analysis_sessions
from hst.app.routes import assessments as assessment_routes
from hst.assessment.store import MAX_PENDING_PER_ACTOR, MemoryAssessmentStore

SNAPSHOT = {"snapshot": "100", "manifest_sha256": "digest-100", "estate": "test"}


class SessionFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return SessionFakeStore()


@pytest.fixture(autouse=True)
def references(monkeypatch):
    def reference(settings, value=None):
        return {"snapshot": value or "100", "manifest_sha256": f"digest-{value or '100'}", "estate": "test"}

    monkeypatch.setattr(assessment_routes.service, "snapshot_reference", reference)
    monkeypatch.setattr(assessment_routes.service, "engine_version", lambda settings: "engine-test")
    monkeypatch.setattr(analysis_sessions, "_pin", lambda settings, stated: stated.model_dump(mode="json"))


def _connection(index: int) -> dict:
    # distinct destinations, so no two connections share an input digest
    request = {
        "name": f"Item {index}",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": [f"192.0.2.{index + 1}"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }
    return {"id": f"item-{index}", "name": f"Item {index}", "source": {"kind": "inline", "request": request}}


async def test_a_session_past_the_bound_queues_what_fits_and_runs_the_rest_later(client, store):
    await login(client, "otto")
    count = MAX_PENDING_PER_ACTOR + 1
    created = await client.post(
        "/api/analysis-sessions",
        json={
            "title": "Large batch",
            "input": {
                "kind": "connection",
                "snapshot": SNAPSHOT,
                "connections": [_connection(i) for i in range(count)],
            },
        },
    )
    assert created.status_code == 201, created.text
    session = created.json()

    first = await client.post(
        f"/api/analysis-sessions/{session['id']}/runs",
        json={"session_revision": 1, "input_digest": session["input_digest"]},
    )
    assert first.status_code == 202, first.text
    body = first.json()
    assert len(body["definition"]["runs"]) == MAX_PENDING_PER_ACTOR
    assert body["results"]["admission"]["omitted"] == [f"item-{MAX_PENDING_PER_ACTOR}"]
    queued = [run for run in await store.list_analysis_runs() if run.state == "queued"]
    assert len(queued) == MAX_PENDING_PER_ACTOR

    # one run finishes, which frees one slot
    claimed = await store.claim_analysis("test")
    assert await store.finish_analysis(claimed.id, claimed.lease_token, result={"complete": True})

    second = await client.post(
        f"/api/analysis-sessions/{session['id']}/runs",
        json={"session_revision": 2, "input_digest": session["input_digest"]},
    )
    assert second.status_code == 202, second.text
    body = second.json()
    assert [run["item_id"] for run in body["definition"]["runs"]] == [f"item-{i}" for i in range(count)]
    assert "admission" not in body["results"]
    assert len(await store.list_analysis_runs()) == count
