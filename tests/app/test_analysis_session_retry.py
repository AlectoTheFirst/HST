"""A connection session whose child run failed or was cancelled runs again for
those children only."""

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.routes import analysis_sessions
from hst.app.routes import assessments as assessment_routes
from hst.assessment.store import MemoryAssessmentStore

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
    request = {
        "name": f"Item {index}",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": [f"192.0.2.{index + 1}"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }
    return {"id": f"item-{index}", "name": f"Item {index}", "source": {"kind": "inline", "request": request}}


async def _session(client, count: int) -> dict:
    created = await client.post(
        "/api/analysis-sessions",
        json={
            "title": "Retry",
            "input": {
                "kind": "connection",
                "snapshot": SNAPSHOT,
                "connections": [_connection(i) for i in range(count)],
            },
        },
    )
    assert created.status_code == 201, created.text
    return created.json()


async def _run(client, session: dict, revision: int):
    return await client.post(
        f"/api/analysis-sessions/{session['id']}/runs",
        json={"session_revision": revision, "input_digest": session["input_digest"]},
    )


async def _finish(store, outcomes: dict[str, str]) -> None:
    while (claimed := await store.claim_analysis("test")) is not None:
        state = outcomes[claimed.id]
        assert await store.finish_analysis(
            claimed.id,
            claimed.lease_token,
            result={"complete": True} if state == "completed" else {},
            state=state,
            error=None if state == "completed" else "engine error",
        )


@pytest.mark.parametrize("ending", ["failed", "cancelled"])
async def test_a_failed_or_cancelled_child_runs_again_and_completed_runs_are_kept(client, store, ending):
    await login(client, "otto")
    session = await _session(client, 3)
    first = await _run(client, session, 1)
    assert first.status_code == 202, first.text
    run_of = {run["item_id"]: run["id"] for run in first.json()["definition"]["runs"]}
    if ending == "cancelled":
        assert await store.cancel_analysis(run_of["item-2"]) is not None
        await _finish(store, {run_of["item-0"]: "completed", run_of["item-1"]: "completed"})
    else:
        await _finish(
            store, {run_of["item-0"]: "completed", run_of["item-1"]: "completed", run_of["item-2"]: "failed"}
        )

    second = await _run(client, session, 2)
    assert second.status_code == 202, second.text
    runs = {run["item_id"]: run["id"] for run in second.json()["definition"]["runs"]}
    assert runs["item-0"] == run_of["item-0"] and runs["item-1"] == run_of["item-1"]
    assert runs["item-2"] != run_of["item-2"]
    queued = [run for run in await store.list_analysis_runs() if run.state == "queued"]
    assert [run.id for run in queued] == [runs["item-2"]]
    # the failed or cancelled run stays recorded
    assert (await store.get_analysis_run(run_of["item-2"])).state == ending


async def test_a_session_whose_children_all_completed_is_not_run_again(client, store):
    await login(client, "otto")
    session = await _session(client, 2)
    first = await _run(client, session, 1)
    assert first.status_code == 202, first.text
    run_of = {run["item_id"]: run["id"] for run in first.json()["definition"]["runs"]}
    await _finish(store, dict.fromkeys(run_of.values(), "completed"))

    again = await _run(client, session, 2)
    assert again.status_code == 422, again.text
    assert "already been executed" in again.text
    assert len(await store.list_analysis_runs()) == 2
