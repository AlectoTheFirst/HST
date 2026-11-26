"""WP-07 "Done when" criteria of the Business Applications plan: saving a chat
simulation makes no engine call, and a cancelled or failed simulation run
leaves the run and the export of another session unchanged."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app import fw_overlay_read
from hst.app.routes import analysis_sessions
from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore

SNAPSHOT = {"snapshot": "100", "manifest_sha256": "abc", "estate": "test", "observation_floor_ms": None}
CHANGES = [{"kind": "route.add", "params": {"prefix": "192.0.2.0/24"}}]
FLOWS = [{"src": "10.0.0.1", "dst": "192.0.2.1", "proto": "tcp", "port": 443}]


class SessionFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return SessionFakeStore()


@pytest.fixture(autouse=True)
def pinned(monkeypatch):
    monkeypatch.setattr(analysis_sessions, "_pin", lambda settings, stated: stated.model_dump(mode="json"))
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, run=None: dict(SNAPSHOT))


@pytest.fixture
def engine_calls(monkeypatch):
    """Each call of the simulation engines, by name."""
    calls: list[str] = []

    def simulate(settings, value, source_kinds, requests):
        calls.append("_simulate")
        return {
            "snapshot": value.snapshot.model_dump(mode="json"),
            "simulation": {
                "flows": [{"flow": FLOWS[0], "before": {"result": "a"}, "after": {"result": "b"}}]
            },
            "protected": [],
        }

    def simulate_change(*args, **kwargs):
        calls.append("simulate_change")
        raise AssertionError("the overlay engine ran")

    monkeypatch.setattr(analysis_sessions, "_simulate", simulate)
    monkeypatch.setattr(fw_overlay_read, "simulate_change", simulate_change)
    return calls


def _run_records(store) -> list[dict]:
    return [doc for key, doc in store._assessment_records.items() if key[0] == "run"]


async def _chat_step(store, username: str):
    user_id = (await store.get_user_by_username(username)).id
    now = datetime.now(UTC)
    conversation = await store.create_conversation(user_id, "changesim", now)
    reply = await store.start_turn(
        user_id, conversation.id, "what if", None, now, per_user_cap=2, global_cap=16
    )
    assert await store.claim_turn(reply.id, "seed", 60, now)
    step = await store.append_step(
        reply.id,
        "change_simulate",
        1,
        {"intents": CHANGES, "flows": FLOWS},
        False,
        '{"flow_count": 1, "results_changed": 1}',
        now,
        5,
        provenance={
            "snapshot": "100",
            "degraded": False,
            "manifest_sha256": "abc",
            "engine": None,
            "queries": [],
        },
    )
    assert await store.finish_turn(reply.id, "seed", "done", now, content="the answer")
    return step


async def test_saving_a_chat_simulation_calls_no_engine_and_queues_no_run(client, store, engine_calls):
    await login(client, "otto")
    step = await _chat_step(store, "otto")

    first = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert first.status_code == 201, first.text
    again = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert again.status_code == 200, again.text

    assert engine_calls == []
    assert _run_records(store) == []
    assert await store.claim_analysis("wp07-test") is None
    saved = first.json()
    assert saved["revision"] == 1
    assert saved["definition"]["runs"] == []
    assert saved["definition"]["input"]["changes"] == CHANGES
    assert saved["results"]["review"]["origin"]["step_id"] == step.id
    assert "simulation" not in saved["results"]
    assert again.json()["id"] == saved["id"]
    assert again.json()["definition"]["runs"] == []


async def _queued_session(client, title: str) -> dict:
    created = await client.post(
        "/api/analysis-sessions",
        json={
            "title": title,
            "input": {
                "kind": "simulation",
                "snapshot": SNAPSHOT,
                "changes": CHANGES,
                "scope": {"flows": FLOWS, "sites": []},
                "bounds": {"max_flows": 50, "max_seconds": 30},
                "protected": [],
            },
        },
    )
    assert created.status_code == 201, created.text
    executed = await client.post(
        f"/api/analysis-sessions/{created.json()['id']}/runs",
        json={"session_revision": 1, "input_digest": created.json()["input_digest"]},
    )
    assert executed.status_code == 202, executed.text
    return executed.json()


async def _read(client, session_id: str) -> tuple[dict, bytes]:
    read = await client.get(f"/api/analysis-sessions/{session_id}")
    assert read.status_code == 200, read.text
    exported = await client.get(f"/api/analysis-sessions/{session_id}/export")
    assert exported.status_code == 200, exported.text
    return read.json(), exported.content


async def test_a_cancelled_and_a_failed_simulation_leave_another_session_run_unchanged(
    client, store, engine_calls
):
    await login(client, "otto")
    completed = await _queued_session(client, "Completed change")
    claimed = await store.claim_analysis("wp07-test")
    assert claimed is not None
    result = assessment_service.execute(None, claimed.inputs)
    assert await store.finish_analysis(claimed.id, claimed.lease_token, result=result)
    before, before_export = await _read(client, completed["id"])
    assert before["definition"]["runs"][0]["execution"] == "completed"
    assert before["results"]["simulation"]["flows"][0]["after"] == {"result": "b"}

    cancelled = await _queued_session(client, "Cancelled change")
    failed = await _queued_session(client, "Failed change")
    cancelled_run = cancelled["definition"]["runs"][0]["id"]
    answer = await client.post(f"/api/analysis-jobs/{cancelled_run}/cancel")
    assert answer.status_code == 200, answer.text
    assert answer.json()["state"] == "cancelled"
    claimed = await store.claim_analysis("wp07-test")
    assert claimed is not None and claimed.id == failed["definition"]["runs"][0]["id"]
    assert await store.finish_analysis(
        claimed.id,
        claimed.lease_token,
        state="failed",
        result={"search_complete": False, "stop_reason": "execution-failed"},
        error="Analysis execution failed.",
    )

    after, after_export = await _read(client, completed["id"])
    assert after == before
    assert after_export == before_export
    assert (await _read(client, cancelled["id"]))[0]["definition"]["runs"][0]["execution"] == "cancelled"
    failed_read = (await _read(client, failed["id"]))[0]
    assert failed_read["definition"]["runs"][0]["execution"] == "failed"
    assert "simulation" not in failed_read["results"]
    assert engine_calls == ["_simulate"]
