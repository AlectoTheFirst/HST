"""Optional drafting shares AI permissions and never exposes executable tools."""

import asyncio
import json
from datetime import UTC, datetime

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.agent.base import AgentAnswer
from hst.app.ai import prompt
from hst.app.routes import ai
from hst.assessment import discovery
from hst.assessment.assistant import SYSTEM
from hst.assessment.store import MemoryAssessmentStore


class AssessmentFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return AssessmentFakeStore()


async def configure(client):
    await login(client, "ada")
    response = await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "configured-model",
            "credentials": {"api_key": "server-secret"},
        },
    )
    assert response.status_code == 200


async def completed(client, job_id):
    for _ in range(200):
        response = await client.get(f"/api/assessment-assistant/drafts/{job_id}")
        assert response.status_code == 200
        if response.json()["status"] != "running":
            return response.json()
        await asyncio.sleep(0.01)
    raise AssertionError("Draft did not finish")


async def test_disabled_ai_has_manual_fallback(client):
    await login(client, "otto")
    response = await client.post(
        "/api/assessment-assistant/drafts", json={"snapshot": "1000", "question": "Help"}
    )
    assert response.status_code == 503
    assert "guided form" in response.text


async def test_provider_gets_no_tools_and_selections_resolve_at_exact_snapshot(client, monkeypatch):
    captured = {}

    class Adapter:
        def ask(self, question, **kwargs):
            captured.update(kwargs)
            return AgentAnswer(
                answer=json.dumps(
                    {
                        "title": "Continuity",
                        "kind": "resilience",
                        "searches": [{"kind": "link", "query": "Frankfurt"}],
                    }
                )
            )

    monkeypatch.setattr(ai.agent_base, "build", lambda *args: Adapter())
    snapshots = []

    def search(settings, snapshot, **kwargs):
        snapshots.append(snapshot)
        return {"snapshot": snapshot, "items": [], "truncated": False}

    monkeypatch.setattr(discovery, "search_options", search)
    await configure(client)
    response = await client.post(
        "/api/assessment-assistant/drafts",
        json={"snapshot": "1000", "question": "Can we survive losing Frankfurt?"},
    )
    assert response.status_code == 202
    result = await completed(client, response.json()["job_id"])
    assert result["status"] == "done"
    assert captured["tools"] == []
    assert captured["model"] == "configured-model"
    assert snapshots == ["1000", "1000"]
    assert not result["ready"]
    assert "server-secret" not in json.dumps(result)


@pytest.mark.parametrize("mode", ["append", "replace"])
async def test_the_draft_prompt_is_the_structured_base_and_system_without_site_instructions(
    client, monkeypatch, mode
):
    captured = {}

    class Adapter:
        def ask(self, question, **kwargs):
            captured.update(kwargs)
            return AgentAnswer(
                answer=json.dumps({"title": "Continuity", "kind": "resilience", "searches": []})
            )

    monkeypatch.setattr(ai.agent_base, "build", lambda *args: Adapter())
    monkeypatch.setattr(
        discovery,
        "search_options",
        lambda settings, snapshot, **kwargs: {"snapshot": snapshot, "items": [], "truncated": False},
    )
    await configure(client)
    saved = await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "configured-model",
            "system_prompt": "SITE-INSTRUCTION-MARKER",
            "prompt_mode": mode,
        },
    )
    assert saved.json()["prompt_mode"] == mode
    response = await client.post(
        "/api/assessment-assistant/drafts",
        json={"snapshot": "1000", "question": "Can we survive losing Frankfurt?"},
    )
    assert response.status_code == 202
    assert (await completed(client, response.json()["job_id"]))["status"] == "done"
    assert SYSTEM in captured["system"]
    assert captured["system"] == prompt.BASE_STRUCTURED + "\n\n" + SYSTEM
    assert "SITE-INSTRUCTION-MARKER" not in captured["system"]


async def test_symptom_interpretation_routes_concrete_clues_to_pinned_discovery(client, monkeypatch):
    captured = []

    class Adapter:
        def ask(self, question, **kwargs):
            assert kwargs["tools"] == []
            return AgentAnswer(
                answer=json.dumps(
                    {
                        "title": "Page unavailable",
                        "kind": "troubleshoot",
                        "searches": [
                            {"kind": "service", "destination": "https://shop.example", "location": "Berlin"}
                        ],
                        "questions": ["Which client network are you using?"],
                    }
                )
            )

    monkeypatch.setattr(ai.agent_base, "build", lambda *args: Adapter())

    def search(settings, snapshot, **kwargs):
        captured.append((snapshot, kwargs))
        return {"snapshot": snapshot, "items": [], "questions": ["No DNS observation in this snapshot."]}

    monkeypatch.setattr(discovery, "search_options", search)
    await configure(client)
    response = await client.post(
        "/api/assessment-assistant/drafts",
        json={
            "snapshot": "1000",
            "question": "The page fails from Berlin. https://shop.example",
        },
    )
    result = await completed(client, response.json()["job_id"])
    assert captured == [
        (
            "1000",
            {
                "kind": "service",
                "q": "",
                "limit": 30,
                "destination": "https://shop.example",
                "location": "Berlin",
            },
        )
    ]
    assert not result["ready"]
    assert "No DNS observation in this snapshot." in result["questions"]
    assert result["clues"][0]["location"] == "Berlin"


async def test_saved_selection_reloads_its_immutable_revision_not_the_new_latest(client, store, monkeypatch):
    from tests.test_assessment_assistant import REQUEST

    from hst.assessment.models import Definition

    definition = Definition.model_validate({"request": REQUEST}).model_dump(mode="json")
    first = await store.create_requirement(title="Original service", definition=definition, created_by=None)
    await store.create_requirement(
        title="New latest",
        definition=definition,
        created_by=None,
        requirement_id=first.id,
        expected_revision=1,
    )

    class Adapter:
        def ask(self, *args, **kwargs):
            raise AssertionError("An explicit selection reuses its reviewed plan.")

    monkeypatch.setattr(ai.agent_base, "build", lambda *args: Adapter())
    revisions = []

    def search(settings, snapshot, **kwargs):
        saved = kwargs["saved_requirements"]
        revisions.extend(value["revision"] for value in saved)
        return {
            "snapshot": snapshot,
            "items": [
                {
                    "kind": "service",
                    "origin": "saved",
                    "uid": value["id"],
                    "name": value["title"],
                    "requirement_id": value["id"],
                    "requirement_revision": value["revision"],
                    "definition": value["definition"]["request"],
                    "selectable": True,
                }
                for value in saved
            ],
        }

    monkeypatch.setattr(discovery, "search_options", search)
    await configure(client)
    response = await client.post(
        "/api/assessment-assistant/drafts",
        json={
            "snapshot": "1000",
            "question": "Check it",
            "plan": {"title": "Check", "kind": "evaluate"},
            "selections": [
                {"kind": "service", "origin": "saved", "uid": first.id, "requirement_revision": 1}
            ],
        },
    )
    result = await completed(client, response.json()["job_id"])
    assert result["ready"] and revisions == [1, 1]
    assert result["definition"]["request"] == definition["request"]
    assert result["definition"]["requirement_revision"] == 1


async def test_foreign_job_is_private(client, monkeypatch):
    class Adapter:
        def ask(self, *args, **kwargs):
            return AgentAnswer(answer='{"title":"Test","kind":"evaluate"}')

    monkeypatch.setattr(ai.agent_base, "build", lambda *args: Adapter())
    monkeypatch.setattr(
        discovery, "search_options", lambda settings, snapshot, **kw: {"snapshot": snapshot, "items": []}
    )
    await configure(client)
    response = await client.post(
        "/api/assessment-assistant/drafts", json={"snapshot": "1000", "question": "Test"}
    )
    job_id = response.json()["job_id"]
    await completed(client, job_id)
    await login(client, "otto")
    assert (await client.get(f"/api/assessment-assistant/drafts/{job_id}")).status_code == 404


async def test_bad_provider_payload_degrades_without_guessing(client, monkeypatch):
    class Adapter:
        def ask(self, *args, **kwargs):
            return AgentAnswer(answer='{"title":"Test","kind":"repair","targets":["invented"]}')

    monkeypatch.setattr(ai.agent_base, "build", lambda *args: Adapter())
    await configure(client)
    response = await client.post(
        "/api/assessment-assistant/drafts", json={"snapshot": "1000", "question": "Test"}
    )
    result = await completed(client, response.json()["job_id"])
    assert result["status"] == "error"
    assert "guided form" in result["detail"]
    assert "invented" not in json.dumps(result)


async def test_a_draft_that_fails_to_start_gives_its_slot_back(client, store, monkeypatch):
    def broken(*args):
        raise RuntimeError("the trust store could not be read")

    monkeypatch.setattr(ai.agent_base, "build", broken)
    await configure(client)
    with pytest.raises(RuntimeError):
        await client.post("/api/assessment-assistant/drafts", json={"snapshot": "1000", "question": "Test"})

    [draft] = [m for m in store.ai_messages.values() if m.role == "assistant"]
    assert (draft.status, draft.error, draft.lease_expires_at) == ("error", "the ask could not start", None)


async def test_unpinned_snapshot_rejected_before_provider(client):
    await login(client, "otto")
    response = await client.post(
        "/api/assessment-assistant/drafts", json={"snapshot": "latest", "question": "Test"}
    )
    assert response.status_code == 400


async def test_job_routes_reject_other_workflow_payloads(client, app):
    await login(client, "ada")
    store = app.state.store
    user = await store.get_user_by_username("ada")
    now = datetime.now(UTC)
    turns = {}
    for surface, payload in (("drawer", {"answer": "Text"}), ("assessment_draft", {"ready": False})):
        reply = await store.start_turn(
            user.id, None, "q", None, now, per_user_cap=2, global_cap=16, surface=surface
        )
        assert await store.claim_turn(reply.id, "test", 60, now)
        assert await store.finish_turn(reply.id, "test", "done", now, envelope={"payload": payload})
        turns[surface] = reply.id
    ordinary, draft = turns["drawer"], turns["assessment_draft"]
    assert (await client.get(f"/api/assessment-assistant/drafts/{ordinary}")).status_code == 404
    assert (await client.get(f"/api/agent/ask/{draft}")).status_code == 404
    assert (await client.get(f"/api/assessment-assistant/drafts/{draft}")).json() == {
        "status": "done",
        "ready": False,
    }
    assert (await client.get(f"/api/agent/ask/{ordinary}")).json() == {"status": "done", "answer": "Text"}
