"""Durable turns behind POST /api/agent/ask and the assessment drafts.

Two apps on one FakeStore stand for two app processes that share Postgres.
The per-turn graph pin is stubbed, so no test opens a Neo4j session.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.app.test_ai_api import _configure

from hst.app.agent import base as agent_base
from hst.app.agent.budget import INCOMPLETE_ANSWER
from hst.app.agent.tools import Tool, ToolCall
from hst.app.ai import turns
from hst.app.main import create_app
from hst.app.routes import ai as ai_routes
from hst.core import Settings

ASK_KEYS = ["status", "answer", "declined", "steps", "context", "page_context", "snapshot", "prompt_hash"]


@pytest.fixture(autouse=True)
def _unpinned(monkeypatch):
    async def unpinned(settings, requested):
        return None

    monkeypatch.setattr(ai_routes, "_pin_turn", unpinned)


@asynccontextmanager
async def _client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        yield c


def _peer(app, store):
    """A second app process on the same store and settings."""
    return create_app(settings=app.state.settings, store=store)


async def _poll(client, job_id):
    r = await client.get(f"/api/agent/ask/{job_id}")
    assert r.status_code == 200, r.text
    return r.json()


async def _until_finished(client, job_id):
    for _ in range(500):
        result = await _poll(client, job_id)
        if result["status"] != "running":
            return result
        await asyncio.sleep(0.01)
    raise AssertionError("the turn never finished")


async def _drain(*apps):
    for app in apps:
        for task in list(getattr(app.state, "ask_tasks", ())):
            await task


class _Blocking:
    """Answers "ok" once `release` is set."""

    def __init__(self) -> None:
        self.release = threading.Event()

    def ask(self, question, **kwargs):
        self.release.wait(timeout=30)
        return agent_base.AgentAnswer(answer="ok")


async def _start(store, username, surface="drawer", at=None):
    user = await store.get_user_by_username(username)
    return await store.start_turn(
        user.id,
        None,
        "q",
        None,
        at or datetime.now(UTC),
        per_user_cap=ai_routes.MAX_ASKS_PER_USER,
        global_cap=ai_routes.MAX_QUEUED_ASKS,
        surface=surface,
    )


async def test_two_apps_on_one_store_enforce_the_per_user_cap_together(app, client, seeded, monkeypatch):
    adapter = _Blocking()
    await _configure(client, monkeypatch, adapter)
    other = _peer(app, seeded)
    try:
        async with _client(other) as client_b:
            await login(client, "vera")
            await login(client_b, "vera")
            assert (await client.post("/api/agent/ask", json={"question": "q"})).status_code == 202
            assert (await client_b.post("/api/agent/ask", json={"question": "q"})).status_code == 202
            for c in (client, client_b):
                r = await c.post("/api/agent/ask", json={"question": "q"})
                assert r.status_code == 429
                assert "too many questions of this user in progress" in r.json()["error"]
            await login(client_b, "otto")
            assert (await client_b.post("/api/agent/ask", json={"question": "q"})).status_code == 202
    finally:
        adapter.release.set()
        await _drain(app, other)


async def test_a_turn_is_polled_to_completion_on_another_app_and_after_a_restart(
    app, client, seeded, monkeypatch
):
    adapter = _Blocking()
    await _configure(client, monkeypatch, adapter)
    r = await client.post("/api/agent/ask", json={"question": "q"})
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    try:
        async with _client(_peer(app, seeded)) as client_b:
            await login(client_b, "ada")
            assert await _poll(client_b, job_id) == {"status": "running"}
            adapter.release.set()
            result = await _until_finished(client_b, job_id)
    finally:
        adapter.release.set()
        await _drain(app)

    assert list(result) == ASK_KEYS
    assert result["status"] == "done"
    assert result["answer"] == "ok"
    # a new app on the same store, as after a restart, answers the same poll
    async with _client(_peer(app, seeded)) as restarted:
        await login(restarted, "ada")
        assert await _poll(restarted, job_id) == result


async def test_a_poll_answers_only_the_owner_and_the_turns_own_surface(client, seeded):
    ask = await _start(seeded, "ada")
    draft = await _start(seeded, "ada", surface="assessment_draft")
    ada = await seeded.get_user_by_username("ada")
    question = (await seeded.get_conversation(ada.id, ask.conversation_id)).messages[0]

    await login(client, "ada")
    assert (await client.get(f"/api/agent/ask/{ask.id}")).json() == {"status": "running"}
    assert (await client.get(f"/api/assessment-assistant/drafts/{draft.id}")).json() == {"status": "running"}
    assert (await client.get(f"/api/agent/ask/{draft.id}")).status_code == 404
    assert (await client.get(f"/api/assessment-assistant/drafts/{ask.id}")).status_code == 404
    assert (await client.get(f"/api/agent/ask/{question.id}")).status_code == 404

    await login(client, "otto")
    assert (await client.get(f"/api/agent/ask/{ask.id}")).status_code == 404
    assert (await client.get(f"/api/assessment-assistant/drafts/{draft.id}")).status_code == 404


async def test_steps_are_stored_before_the_turn_finishes(app, client, seeded, monkeypatch):
    tool = Tool("count", "", {}, "graph.read", lambda **kwargs: "counted")
    stepped = threading.Event()
    release = threading.Event()

    class _Adapter:
        def ask(self, question, *, budget, on_step, **kwargs):
            step = budget.invoke([tool], "count", {"n": 1})
            on_step(step)
            stepped.set()
            release.wait(timeout=30)
            return agent_base.AgentAnswer(answer="ok", steps=[step])

    await _configure(client, monkeypatch, _Adapter())
    ada = await seeded.get_user_by_username("ada")
    job_id = (await client.post("/api/agent/ask", json={"question": "q"})).json()["job_id"]
    try:
        assert await asyncio.to_thread(stepped.wait, 5)
        for _ in range(200):
            if seeded.ai_steps:
                break
            await asyncio.sleep(0.01)
        [step] = seeded.ai_steps.values()
        assert (step.message_id, step.label, step.tool) == (job_id, 1, "count")
        assert (step.arguments, step.is_error, step.result) == ({"n": 1}, False, "counted")
        assert (await seeded.get_message(ada.id, job_id)).status == "running"
    finally:
        release.set()
        await _drain(app)

    result = await _poll(client, job_id)
    assert result["steps"] == [
        {"name": "count", "arguments": {"n": 1}, "is_error": False, "result": "counted"}
    ]
    # the audit row of the step carries the ai_steps id
    [event] = [e for e in await seeded.list_ai_events() if e.event == "tool.call"]
    assert event.step_id == step.id


async def test_the_cancel_flag_stops_the_next_tool_call(app, client, seeded, monkeypatch):
    runs: list[dict] = []
    tool = Tool("count", "", {}, "graph.read", lambda **kwargs: runs.append(kwargs) or "counted")
    first = threading.Event()
    proceed = threading.Event()
    stopped: list[bool] = []

    class _Adapter:
        def ask(self, question, *, budget, on_step, **kwargs):
            on_step(budget.invoke([tool], "count", {}))
            first.set()
            proceed.wait(timeout=30)
            try:
                budget.invoke([tool], "count", {})
            except TimeoutError:
                stopped.append(True)
                raise
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    ada = await seeded.get_user_by_username("ada")
    job_id = (await client.post("/api/agent/ask", json={"question": "q"})).json()["job_id"]
    try:
        assert await asyncio.to_thread(first.wait, 5)
        assert await seeded.request_cancel(ada.id, job_id)
    finally:
        proceed.set()
        await _drain(app)

    assert len(runs) == 1
    assert stopped == [True]
    assert await _poll(client, job_id) == {"status": "error", "detail": ai_routes.CANCELLED_DETAIL}
    assert (await seeded.get_message(ada.id, job_id)).status == "cancelled"


async def test_a_failure_to_start_the_context_reads_finishes_the_turn(app, client, seeded, monkeypatch):
    def broken(request, question, ctx):
        raise RuntimeError("no worker thread")

    class _Adapter:
        def ask(self, question, **kwargs):
            return agent_base.AgentAnswer(answer="ok")

    monkeypatch.setattr(ai_routes, "_start_context", broken)
    await _configure(client, monkeypatch, _Adapter())
    ada = await seeded.get_user_by_username("ada")
    r = await client.post("/api/agent/ask", json={"question": "q", "include_context": True})
    job_id = r.json()["job_id"]
    result = await _until_finished(client, job_id)
    await _drain(app)

    assert result == {"status": "error", "detail": f"the ask failed (ask {job_id}); see the server log"}
    assert (await seeded.get_message(ada.id, job_id)).status == "error"


async def test_an_ask_abandoned_at_its_deadline_keeps_the_tokens_it_spent(
    app, client, seeded, monkeypatch, caplog
):
    class _Adapter:
        def ask(self, question, *, budget, **kwargs):
            # one provider round and one tool step, then a stall past the deadline
            budget.usage.add(120, 30)
            budget.rounds.append(40)
            budget.steps.append(ToolCall("count", {}, "counted"))
            time.sleep(0.5)
            return agent_base.AgentAnswer(answer="too late")

    caplog.set_level(logging.INFO, logger="hst.ai")
    monkeypatch.setattr(ai_routes, "ASK_DEADLINE_S", 0.05)
    await _configure(client, monkeypatch, _Adapter())
    ada = await seeded.get_user_by_username("ada")
    job_id = (await client.post("/api/agent/ask", json={"question": "q"})).json()["job_id"]
    result = await _until_finished(client, job_id)
    await _drain(app)

    assert (result["status"], result["answer"]) == ("done", INCOMPLETE_ANSWER)
    stored = await seeded.get_message(ada.id, job_id)
    assert stored.usage == {"input_tokens": 120, "output_tokens": 30, "rounds": [40]}
    assert f"ask {job_id} answered after 1 provider rounds" in caplog.text


async def test_a_turn_whose_lease_lapses_is_reported_interrupted(app, client, seeded, monkeypatch):
    """The accepting process stops renewing the lease, as a dead process
    would. The sweep marks the turn, and a peer app reports it interrupted,
    also after the stalled turn returns."""
    monkeypatch.setattr(turns, "LEASE_S", 0.05)
    monkeypatch.setattr(turns, "HEARTBEAT_S", 30.0)
    adapter = _Blocking()
    await _configure(client, monkeypatch, adapter)
    job_id = (await client.post("/api/agent/ask", json={"question": "q"})).json()["job_id"]
    try:
        await asyncio.sleep(0.1)
        assert await seeded.expire_stale_turns(datetime.now(UTC)) == 1
        async with _client(_peer(app, seeded)) as client_b:
            await login(client_b, "ada")
            result = await _poll(client_b, job_id)
    finally:
        adapter.release.set()
        await _drain(app)

    assert result == {"status": "error", "detail": ai_routes.INTERRUPTED_DETAIL}
    assert "interrupted" in result["detail"]
    assert await _poll(client, job_id) == result


async def test_a_turn_never_claimed_is_interrupted_after_the_grace_period(client, seeded):
    then = datetime.now(UTC) - timedelta(seconds=turns.PENDING_GRACE_S + 1)
    reply = await _start(seeded, "ada", at=then)
    assert await seeded.expire_stale_turns(datetime.now(UTC), turns.PENDING_GRACE_S) == 1
    await login(client, "ada")
    assert await _poll(client, reply.id) == {"status": "error", "detail": ai_routes.INTERRUPTED_DETAIL}


async def test_a_turn_waiting_on_the_gate_keeps_its_lease(app, client, seeded, monkeypatch):
    """With a 0.3 s lease, the turn waits on the gate for 4 lease lengths."""
    monkeypatch.setattr(turns, "LEASE_S", 0.3)
    monkeypatch.setattr(turns, "HEARTBEAT_S", 0.03)
    gate = asyncio.Semaphore(1)
    monkeypatch.setattr(ai_routes, "_ask_gate", gate)

    class _Adapter:
        def ask(self, question, **kwargs):
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    await gate.acquire()
    try:
        job_id = (await client.post("/api/agent/ask", json={"question": "q"})).json()["job_id"]
        loop = asyncio.get_running_loop()
        waited_until = loop.time() + 4 * turns.LEASE_S
        while loop.time() < waited_until:
            assert await seeded.expire_stale_turns(datetime.now(UTC)) == 0
            await asyncio.sleep(0.02)
        assert await _poll(client, job_id) == {"status": "running"}
    finally:
        gate.release()
    result = await _until_finished(client, job_id)
    await _drain(app)
    assert (result["status"], result["answer"]) == ("done", "ok")


async def test_the_global_cap_counts_the_active_turns_of_every_user(client, seeded, monkeypatch):
    await _configure(client, monkeypatch, _Blocking())
    for n in range(ai_routes.MAX_QUEUED_ASKS):
        await seeded.create_user(f"other-{n}", "h", "viewer")
        await _start(seeded, f"other-{n}", surface="drawer" if n % 2 else "assessment_draft")

    r = await client.post("/api/agent/ask", json={"question": "q"})
    assert r.status_code == 429
    assert "busy" in r.json()["error"]
    r = await client.post("/api/assessment-assistant/drafts", json={"snapshot": "1000", "question": "q"})
    assert r.status_code == 429
    assert "busy" in r.json()["error"]


async def test_the_sweeper_runs_with_the_scheduler_disabled(monkeypatch):
    monkeypatch.setattr(turns, "SWEEP_INTERVAL_S", 0.01)
    store = FakeStore()
    await store.create_user("ada", "h", "admin")
    then = datetime.now(UTC) - timedelta(minutes=5)
    reply = await _start(store, "ada", at=then)
    ada = await store.get_user_by_username("ada")

    app = create_app(settings=Settings(_env_file=None, scheduler_enabled=False), store=store)
    async with app.router.lifespan_context(app):
        assert app.state.worker_tasks == []
        assert app.state.turn_sweeper is not None
        for _ in range(300):
            if (await store.get_message(ada.id, reply.id)).status == "interrupted":
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("the sweeper never marked the stale turn")
    assert app.state.turn_sweeper.done()
