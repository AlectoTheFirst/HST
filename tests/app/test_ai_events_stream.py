"""GET /api/ai/messages/{id}/events: a turn as server-sent events read from
the stored rows.

Two apps on one FakeStore stand for two app processes that share Postgres.
The per-turn graph pin is stubbed, so no test opens a Neo4j session.
"""

from __future__ import annotations

import asyncio
import json
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from tests.app.conftest import login
from tests.app.test_ai_api import _configure

from hst.app.agent import base as agent_base
from hst.app.agent import tools as tools_mod
from hst.app.main import create_app
from hst.app.routes import ai as ai_routes
from hst.app.routes import ai_conversations as conv_routes

NOW = datetime(2026, 9, 1, tzinfo=UTC)
TRACE_RESULT = json.dumps({"status": "complete", "paths": []})


@pytest.fixture(autouse=True)
def _unpinned(monkeypatch):
    async def unpinned(settings, requested):
        return None

    monkeypatch.setattr(ai_routes, "_pin_turn", unpinned)


@pytest.fixture(autouse=True)
def _fast_reads(monkeypatch):
    monkeypatch.setattr(conv_routes, "EVENTS_POLL_S", 0.01)


@asynccontextmanager
async def _peer_client(app, store):
    """A client of a second app process on the same store and settings."""
    peer = create_app(settings=app.state.settings, store=store)
    transport = httpx.ASGITransport(app=peer)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        yield c


def _events(body: str) -> list[dict[str, Any]]:
    """The events of an event stream body; comment lines are skipped."""
    events = []
    for block in body.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if line and not line.startswith(":"))
        if fields:
            events.append(
                {"event": fields.get("event"), "id": fields.get("id"), "data": json.loads(fields["data"])}
            )
    return events


def _kinds(events: list[dict[str, Any]]) -> list[tuple[str | None, str | None]]:
    return [(e["event"], e["id"]) for e in events]


async def _conversation(client, store, username):
    await login(client, username)
    r = await client.post("/api/ai/conversations", json={"surface": "drawer"})
    assert r.status_code == 201, r.text
    user = await store.get_user_by_username(username)
    return user.id, r.json()["id"]


async def _running_turn(store, user_id, conversation_id):
    """A turn claimed by a process other than the app under test."""
    reply = await store.start_turn(user_id, conversation_id, "q", None, NOW, per_user_cap=2, global_cap=16)
    assert await store.claim_turn(reply.id, "peer", 60, NOW)
    return reply.id


async def _finished_turn(store, user_id, conversation_id):
    """A finished turn with two steps, labelled 1 and 2."""
    message_id = await _running_turn(store, user_id, conversation_id)
    for tool in ("resolve_address", "trace_path"):
        await store.append_step(message_id, tool, 1, {"src": "10.0.0.1"}, False, TRACE_RESULT, NOW, 5)
    assert await store.finish_turn(message_id, "peer", "done", NOW, content="the answer")
    return message_id


async def test_a_finished_turn_streams_its_steps_then_the_poll_answer(client, seeded):
    user_id, conversation_id = await _conversation(client, seeded, "vera")
    message_id = await _finished_turn(seeded, user_id, conversation_id)

    r = await client.get(f"/api/ai/messages/{message_id}/events")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/event-stream")
    events = _events(r.text)

    assert _kinds(events) == [("step", "1"), ("step", "2"), ("turn", None)]
    poll = (await client.get(f"/api/ai/messages/{message_id}")).json()
    assert [e["data"] for e in events[:2]] == poll["steps"]
    assert events[-1]["data"] == poll
    assert (poll["status"], poll["answer"]) == ("done", "the answer")


async def test_a_reconnect_resumes_after_the_last_event_id(client, seeded):
    user_id, conversation_id = await _conversation(client, seeded, "vera")
    message_id = await _finished_turn(seeded, user_id, conversation_id)
    url = f"/api/ai/messages/{message_id}/events"

    resumed = _events((await client.get(url, headers={"Last-Event-ID": "1"})).text)
    assert _kinds(resumed) == [("step", "2"), ("turn", None)]
    assert resumed[0]["data"]["name"] == "trace_path"
    # after the last step only the end of the turn is left
    assert _kinds(_events((await client.get(url, headers={"Last-Event-ID": "2"})).text)) == [("turn", None)]
    # an id that is not a step label replays the turn from its start
    assert len(_events((await client.get(url, headers={"Last-Event-ID": "x"})).text)) == 3


async def test_the_stream_sends_each_step_as_it_is_stored(client, seeded):
    user_id, conversation_id = await _conversation(client, seeded, "vera")
    message_id = await _running_turn(seeded, user_id, conversation_id)
    turn = await seeded.get_turn(user_id, message_id)
    events = conv_routes.turn_events(seeded, user_id, turn)

    await seeded.append_step(message_id, "trace_path", 1, {"src": "10.0.0.1"}, False, TRACE_RESULT, NOW, 5)
    first = await asyncio.wait_for(anext(events), 5)
    assert (first.event, first.id, first.data["name"]) == ("step", "1", "trace_path")
    assert (await seeded.get_message(user_id, message_id)).status == "running"

    assert await seeded.finish_turn(message_id, "peer", "done", NOW, content="the answer")
    last = await asyncio.wait_for(anext(events), 5)
    assert (last.event, last.id, last.data["status"], last.data["answer"]) == (
        "turn",
        None,
        "done",
        "the answer",
    )
    with pytest.raises(StopAsyncIteration):
        await anext(events)


async def test_a_turn_running_on_another_process_streams(app, client, seeded, monkeypatch):
    release = threading.Event()

    class _OneStep:
        def ask(self, question, *, on_step, **kwargs):
            step = tools_mod.ToolCall(
                name="trace_path",
                arguments={"src": "10.0.0.1"},
                result=tools_mod.frame_untrusted(TRACE_RESULT),
            )
            on_step(step)
            release.wait(timeout=30)
            return agent_base.AgentAnswer(answer="the answer", steps=[step])

    await _configure(client, monkeypatch, _OneStep())
    r = await client.post("/api/ai/conversations", json={"surface": "drawer"})
    r = await client.post(f"/api/ai/conversations/{r.json()['id']}/messages", json={"question": "q"})
    assert r.status_code == 202, r.text
    message_id = r.json()["message_id"]

    reads = 0
    get_turn_progress = seeded.get_turn_progress

    async def counted(*args, **kwargs):
        nonlocal reads
        reads += 1
        return await get_turn_progress(*args, **kwargs)

    monkeypatch.setattr(seeded, "get_turn_progress", counted)
    try:
        async with _peer_client(app, seeded) as client_b:
            await login(client_b, "ada")
            stream = asyncio.create_task(client_b.get(f"/api/ai/messages/{message_id}/events"))
            for _ in range(500):
                if reads >= 3 and seeded.ai_steps:
                    break
                await asyncio.sleep(0.01)
            # the stream is open on the second app while the first runs the turn
            assert not stream.done()
            release.set()
            response = await asyncio.wait_for(stream, 10)
    finally:
        release.set()
        for task in list(getattr(app.state, "ask_tasks", ())):
            await task

    assert response.status_code == 200, response.text
    events = _events(response.text)
    assert _kinds(events) == [("step", "1"), ("turn", None)]
    assert events[0]["data"]["name"] == "trace_path"
    assert (events[-1]["data"]["status"], events[-1]["data"]["answer"]) == ("done", "the answer")


async def test_a_running_turn_is_read_as_its_status_and_its_new_steps(client, seeded, monkeypatch):
    user_id, conversation_id = await _conversation(client, seeded, "vera")
    message_id = await _running_turn(seeded, user_id, conversation_id)
    turn = await seeded.get_turn(user_id, message_id)
    reads: list[int] = []
    get_turn_progress = seeded.get_turn_progress

    async def recorded(user, message, after):
        reads.append(after)
        return await get_turn_progress(user, message, after)

    monkeypatch.setattr(seeded, "get_turn_progress", recorded)
    events = conv_routes.turn_events(seeded, user_id, turn)

    await seeded.append_step(message_id, "trace_path", 1, {"src": "10.0.0.1"}, False, TRACE_RESULT, NOW, 5)
    assert (await asyncio.wait_for(anext(events), 5)).id == "1"
    await seeded.append_step(message_id, "trace_path", 1, {"src": "10.0.0.2"}, False, TRACE_RESULT, NOW, 5)
    assert (await asyncio.wait_for(anext(events), 5)).id == "2"
    assert await seeded.finish_turn(message_id, "peer", "done", NOW, content="the answer")
    last = await asyncio.wait_for(anext(events), 5)

    assert (last.event, [s["step"] for s in last.data["steps"]]) == ("turn", ["s1", "s2"])
    # each read asks only for the steps after the last one sent
    assert reads[0] == 0
    assert reads[-1] == 2
    assert set(reads) <= {0, 1, 2}


async def test_the_stream_closes_after_a_logout(client, seeded, monkeypatch):
    monkeypatch.setattr(conv_routes, "EVENTS_SESSION_CHECK_S", 0.0)
    user_id, conversation_id = await _conversation(client, seeded, "vera")
    message_id = await _running_turn(seeded, user_id, conversation_id)

    stream = asyncio.create_task(client.get(f"/api/ai/messages/{message_id}/events"))
    await asyncio.sleep(0.05)
    assert not stream.done()
    assert (await client.post("/api/logout")).status_code == 204
    response = await asyncio.wait_for(stream, 5)

    assert response.status_code == 200
    assert _events(response.text) == []
    assert (await seeded.get_message(user_id, message_id)).status == "running"


async def test_the_stream_answers_only_the_owner_of_an_answer(client, seeded):
    user_id, conversation_id = await _conversation(client, seeded, "vera")
    message_id = await _finished_turn(seeded, user_id, conversation_id)
    question = (await seeded.get_conversation(user_id, conversation_id)).messages[0]

    assert (await client.get(f"/api/ai/messages/{question.id}/events")).status_code == 404
    await login(client, "otto")
    assert (await client.get(f"/api/ai/messages/{message_id}/events")).status_code == 404
