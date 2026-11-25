"""The handoffs from a stored AI step.

The snapshot reference of a run is stubbed: run 1759 has an evidence manifest
and every other run has none. No test opens a Neo4j session.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore

NOW = datetime(2026, 9, 1, tzinfo=UTC)
MANIFEST = "ab" * 32
REFERENCE = {"snapshot": "1759", "manifest_sha256": MANIFEST, "estate": "test", "observation_floor_ms": None}
INTENTS = [
    {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:core1:LAN",
            "position": 10,
            "action": "drop",
            "destination": ["10.0.0.10"],
        },
    }
]
FLOWS = [{"src": "192.168.2.35", "dst": "10.0.0.10", "port": 443, "proto": "tcp"}]
SIMULATION_ARGS = {"intents": INTENTS, "flows": FLOWS, "sites": ["fra1"], "depth": 2, "snapshot": "latest"}
REQUEST = {
    "name": "web",
    "destination": "10.0.0.10",
    "sources": ["10.1.0.0/24"],
    "members": [{"name": "web", "addresses": ["10.0.0.10"]}],
    "condition": {"kind": "every", "parts": [{"kind": "member", "member": "web"}]},
}


class SessionFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return SessionFakeStore()


@pytest.fixture(autouse=True)
def references(monkeypatch):
    def reference(settings, value=None):
        if value != "1759":
            raise ValueError("A published snapshot with an evidence manifest is required.")
        return dict(REFERENCE)

    monkeypatch.setattr(assessment_service, "snapshot_reference", reference)


async def _step(
    store,
    username: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    run: str | None = "1759",
    manifest: str = MANIFEST,
    is_error: bool = False,
    result: str = "{}",
):
    """One finished drawer turn of `username` with one step."""
    user_id = (await store.get_user_by_username(username)).id
    conversation = await store.create_conversation(user_id, "drawer", NOW)
    reply = await store.start_turn(
        user_id, conversation.id, "what if", None, NOW, per_user_cap=2, global_cap=16
    )
    assert await store.claim_turn(reply.id, "seed", 60, NOW)
    provenance = {
        "snapshot": run,
        "degraded": False,
        "manifest_sha256": manifest,
        "engine": "fw_overlay",
        "queries": [],
    }
    step = await store.append_step(
        reply.id, tool, 1, arguments, is_error, result, NOW, 5, provenance=provenance if run else None
    )
    assert await store.finish_turn(reply.id, "seed", "done", NOW, content="the answer")
    return step


def _session_links(store) -> list[Any]:
    return [link for link in store.ai_links if link.kind == "analysis_session"]


# --- H1: POST /api/ai/steps/{id}/analysis-session ------------------------------------------


async def test_the_session_is_built_from_the_stored_step_and_the_body_is_ignored(client, store):
    await login(client, "otto")
    step = await _step(store, "otto", "change_simulate", SIMULATION_ARGS)

    echoed = {
        "title": "forged",
        "input": {"kind": "simulation", "snapshot": {"snapshot": "1760"}, "changes": []},
        "snapshot": "1760",
        "intents": [{"kind": "route.remove", "params": {}}],
        "review": {"origin": {"step_id": "forged"}},
    }
    r = await client.post(f"/api/ai/steps/{step.id}/analysis-session", json=echoed)
    assert r.status_code == 201, r.text
    saved = r.json()

    assert saved["title"] == "Simulation from chat step s1"
    assert saved["revision"] == 1
    value = saved["definition"]["input"]
    assert value["kind"] == "simulation"
    assert value["snapshot"] == REFERENCE
    assert value["changes"] == INTENTS
    assert value["scope"] == {"flows": FLOWS, "sites": ["fra1"]}
    assert value["bounds"]["depth"] == 2
    assert value["protected"] == []
    assert saved["definition"]["runs"] == []


async def test_the_saved_session_points_back_to_the_step_and_is_linked(client, store):
    await login(client, "otto")
    step = await _step(store, "otto", "change_simulate", {"intents": INTENTS})

    r = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert r.status_code == 201, r.text
    saved = r.json()
    origin = {
        "conversation_id": step.conversation_id,
        "message_id": step.message_id,
        "step_id": step.id,
        "step": "s1",
    }
    assert saved["results"]["review"]["origin"] == origin
    assert saved["definition"]["input"]["scope"] is None
    stored = await store.get_analysis_session(saved["id"])
    assert stored is not None and stored.results["review"]["origin"] == origin

    [link] = _session_links(store)
    assert (link.conversation_id, link.ref_id, link.ref_revision, link.direction) == (
        step.conversation_id,
        saved["id"],
        1,
        "to",
    )
    assert (link.message_id, link.step_id) == (step.message_id, step.id)

    detail = (await client.get(f"/api/ai/conversations/{step.conversation_id}")).json()
    assert [(item["kind"], item["ref_id"], item["step_id"]) for item in detail["links"]] == [
        ("analysis_session", saved["id"], step.id)
    ]


async def test_a_run_without_a_manifest_is_refused(client, store):
    await login(client, "otto")
    step = await _step(store, "otto", "change_simulate", SIMULATION_ARGS, run="1760")

    r = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert r.status_code == 422
    assert "evidence manifest" in r.json()["error"]
    assert await store.list_analysis_sessions() == []
    assert _session_links(store) == []


@pytest.mark.parametrize(
    ("tool", "options", "reason"),
    [
        ("impact_evaluate_service", {}, "not a change simulation"),
        ("change_simulate", {"is_error": True}, "ended with an error"),
        ("change_simulate", {"run": None}, "records no run"),
        ("change_simulate", {"manifest": "cd" * 32}, "differs from the step's"),
    ],
)
async def test_a_step_that_is_not_a_saved_simulation_is_refused(client, store, tool, options, reason):
    await login(client, "otto")
    step = await _step(store, "otto", tool, SIMULATION_ARGS, **options)

    r = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert r.status_code == 422
    assert reason in r.json()["error"]
    assert await store.list_analysis_sessions() == []


async def test_a_step_saved_before_returns_its_linked_session(client, store):
    await login(client, "otto")
    step = await _step(store, "otto", "change_simulate", SIMULATION_ARGS)

    first = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert first.status_code == 201, first.text
    again = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert again.status_code == 200, again.text

    assert again.json()["id"] == first.json()["id"]
    assert again.json()["revision"] == 1
    assert len(await store.list_analysis_sessions()) == 1
    assert len(_session_links(store)) == 1


async def test_a_step_without_intents_is_refused_before_anything_is_saved(client, store):
    await login(client, "otto")
    step = await _step(store, "otto", "change_simulate", {"flows": FLOWS})

    r = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert r.status_code == 422
    assert "does not form a simulation input" in r.json()["error"]
    assert await store.list_analysis_sessions() == []


async def test_a_viewer_is_refused_and_a_step_of_another_user_is_missing(client, store):
    step = await _step(store, "otto", "change_simulate", SIMULATION_ARGS)

    await login(client, "vera")
    assert (await client.post(f"/api/ai/steps/{step.id}/analysis-session")).status_code == 403
    await login(client, "ada")
    assert (await client.post(f"/api/ai/steps/{step.id}/analysis-session")).status_code == 404
    assert (await client.post("/api/ai/steps/not-a-uuid/analysis-session")).status_code == 404
    assert await store.list_analysis_sessions() == []


# --- H1b: GET /api/ai/steps/{id}/assessment-draft ------------------------------------------


async def test_the_draft_of_a_request_step_has_the_service_draft_shape(client, store):
    await login(client, "vera")
    arguments = {"form": "request", "request": REQUEST, "intents": INTENTS, "mode": "guaranteed"}
    step = await _step(store, "vera", "impact_evaluate_service", arguments)

    r = await client.get(f"/api/ai/steps/{step.id}/assessment-draft")
    assert r.status_code == 200, r.text
    # `serviceDraft` (web/src/assessments/context.ts): the request over the
    # editor's empty request, with the condition kinds the editor uses
    assert r.json() == {
        "title": "web",
        "kind": "troubleshoot",
        "definition": {
            "intents": INTENTS,
            "snapshot": "1759",
            "mode": "guaranteed",
            "freshness_s": 86400,
            "request": {
                **REQUEST,
                "condition": {"kind": "and", "parts": [{"kind": "member", "member": "web"}]},
                "success": "forward",
            },
        },
    }


async def test_the_draft_of_a_requirement_step_names_the_requirement(client, store):
    await login(client, "vera")
    result = json.dumps({"snapshot": {"id": "1759"}, "result": {"request": {"name": "web service"}}})
    arguments = {"form": "requirement", "requirement": "req:web"}
    step = await _step(store, "vera", "impact_evaluate_service", arguments, result=result)

    expected = {
        "title": "web service",
        "kind": "troubleshoot",
        "definition": {
            "intents": [],
            "snapshot": "1759",
            "mode": "possible",
            "freshness_s": 86400,
            "requirement": "req:web",
        },
    }
    assert (await client.get(f"/api/ai/steps/{step.id}/assessment-draft")).json() == expected

    # after compaction the result is gone, and the title is the requirement uid
    assert await store.compact_steps(NOW + timedelta(days=1), NOW + timedelta(days=1)) == 1
    compacted = (await client.get(f"/api/ai/steps/{step.id}/assessment-draft")).json()
    assert compacted == {**expected, "title": "req:web"}


@pytest.mark.parametrize(
    ("tool", "arguments", "options", "reason"),
    [
        ("change_simulate", SIMULATION_ARGS, {}, "not a service evaluation"),
        (
            "impact_evaluate_service",
            {"form": "application_connection", "application_connection": {"connection_id": "c1"}},
            {},
            "names no requirement and no request set",
        ),
        (
            "impact_evaluate_service",
            {"form": "request", "request": {**REQUEST, "members": []}},
            {},
            "is not complete",
        ),
        ("impact_evaluate_service", {"form": "request", "request": REQUEST}, {"run": None}, "records no run"),
        (
            "impact_evaluate_service",
            {"form": "request", "request": REQUEST},
            {"is_error": True},
            "ended with an error",
        ),
    ],
)
async def test_a_step_without_a_draft_is_refused(client, store, tool, arguments, options, reason):
    await login(client, "vera")
    step = await _step(store, "vera", tool, arguments, **options)

    r = await client.get(f"/api/ai/steps/{step.id}/assessment-draft")
    assert r.status_code == 422
    assert reason in r.json()["error"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"sources": [], "population": {"kind": "site", "site": "fra1"}}, "no client address or prefix"),
        ({"members": [{"name": " ", "addresses": ["10.0.0.10"]}]}, "a destination member has no name"),
        (
            {
                "members": [
                    {"name": "web", "addresses": ["10.0.0.10"]},
                    {"name": "web", "addresses": ["10.0.0.11"]},
                ]
            },
            "names are not unique",
        ),
        ({"condition": {"kind": "member", "member": "db"}}, "success condition"),
        ({"condition": {"kind": "every", "parts": []}}, "success condition"),
        (
            {"condition": {"kind": "n-of-m", "n": 2, "parts": [{"kind": "member", "member": "web"}]}},
            "success condition",
        ),
        (
            {
                "sources": ["2001:db8::/64"],
                "mtu": {"mode": "packet", "ip_packet_bytes": 1500, "ipv4_df": True},
            },
            "IPv4 DF is invalid for IPv6",
        ),
        ({"mtu": {"mode": "packet", "ip_packet_bytes": 70000}}, "IPv4 packet length"),
    ],
)
async def test_a_request_set_the_assessment_editor_refuses_has_no_draft(client, store, change, reason):
    await login(client, "vera")
    arguments = {"form": "request", "request": {**REQUEST, **change}}
    step = await _step(store, "vera", "impact_evaluate_service", arguments)

    r = await client.get(f"/api/ai/steps/{step.id}/assessment-draft")
    assert r.status_code == 422, r.text
    assert "is not complete" in r.json()["error"]
    assert reason in r.json()["error"]


async def test_the_draft_of_another_users_step_is_missing(client, store):
    step = await _step(store, "otto", "impact_evaluate_service", {"form": "request", "request": REQUEST})
    await login(client, "vera")
    assert (await client.get(f"/api/ai/steps/{step.id}/assessment-draft")).status_code == 404
