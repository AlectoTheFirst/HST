"""The conversation routes and the server-built history window.

The per-turn graph pin is stubbed, so no test opens a Neo4j session. The
provider is a stub adapter that records what it receives.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from tests.app.conftest import login
from tests.app.test_ai_api import _configure

from hst.app.agent import base as agent_base
from hst.app.agent import tools as tools_mod
from hst.app.ai import history
from hst.app.routes import ai as ai_routes
from hst.app.routes import ai_conversations as conv_routes
from hst.app.store import AiConversation, AiMessage, AiStep
from hst.core import snapshot as snapshot_mod
from hst.results.project import condition_result
from hst.results.words import from_engine, record

NOW = datetime(2026, 9, 1, tzinfo=UTC)
TRACE_RESULT = json.dumps(
    {"status": "complete", "snapshot": "1759", "paths": [{"hostname": "fw1"}, {"hostname": "fw2"}]}
)
STEP_LINE = re.compile(r"^\[s\d+\] [a-z_]+\(.*\) -> .+$")


@pytest.fixture(autouse=True)
def _unpinned(monkeypatch):
    async def unpinned(settings, requested):
        return None

    monkeypatch.setattr(ai_routes, "_pin_turn", unpinned)


class _Recorder:
    """Answers every call and records its keyword arguments. A call with no
    tools is the summary update."""

    def __init__(self, summary="the summary", on_turn=None):
        self.calls = []
        self.summary = summary
        self.on_turn = on_turn

    def ask(self, question, **kwargs):
        self.calls.append({"question": question, **kwargs})
        if not kwargs["tools"]:
            return agent_base.AgentAnswer(answer=self.summary)
        steps = self.on_turn(kwargs["on_step"]) if self.on_turn is not None else []
        return agent_base.AgentAnswer(answer="the answer", steps=steps)

    def turn_calls(self):
        return [c for c in self.calls if c["tools"]]


async def _user_id(store, username):
    return (await store.get_user_by_username(username)).id


async def _seed_turns(store, user_id, conversation_id, count, *, at=NOW):
    """`count` finished turns, each with one trace_path step."""
    for i in range(1, count + 1):
        reply = await store.start_turn(
            user_id, conversation_id, f"question {i}", None, at, per_user_cap=2, global_cap=16
        )
        assert await store.claim_turn(reply.id, "seed", 60, at)
        await store.append_step(reply.id, "trace_path", 1, {"src": "10.0.0.1"}, False, TRACE_RESULT, at, 5)
        assert await store.finish_turn(reply.id, "seed", "done", at, content=f"answer {i}")


async def _until_finished(client, message_id):
    for _ in range(500):
        r = await client.get(f"/api/ai/messages/{message_id}")
        assert r.status_code == 200, r.text
        if r.json()["status"] != "running":
            return r.json()
        await asyncio.sleep(0.01)
    raise AssertionError("the turn never finished")


async def _drain(app):
    for task in list(getattr(app.state, "ask_tasks", ())):
        await task


async def _create(client, **body):
    r = await client.post("/api/ai/conversations", json={"surface": "drawer", **body})
    assert r.status_code == 201, r.text
    return r.json()


async def test_a_conversation_is_created_listed_read_and_deleted_with_its_rows(app, client, seeded):
    await login(client, "vera")
    context = {
        "version": 1,
        "route": {"pathname": "/assessments"},
        "assessment": {"assessment_id": "a-1", "revision": 2, "run_id": "r-9"},
    }
    created = await _create(client, title="paths", context=context, pin="1759")
    assert (created["title"], created["pin"], created["pin_mode"]) == ("paths", "1759", "pinned")

    listed = (
        await client.get("/api/ai/conversations", params={"link_kind": "assessment", "link_id": "a-1"})
    ).json()
    assert [c["id"] for c in listed["conversations"]] == [created["id"]]
    assert (await client.get("/api/ai/conversations", params={"surface": "changesim"})).json() == {
        "conversations": []
    }

    user_id = await _user_id(seeded, "vera")
    await _seed_turns(seeded, user_id, created["id"], 1)
    detail = (await client.get(f"/api/ai/conversations/{created['id']}")).json()
    assert [m["role"] for m in detail["messages"]] == ["user", "assistant"]
    step = detail["messages"][1]["steps"][0]
    assert (step["step"], step["tool"], step["compacted"]) == ("s1", "trace_path", False)
    assert "result" not in step
    assert {(link["kind"], link["ref_id"]) for link in detail["links"]} == {
        ("assessment", "a-1"),
        ("assessment_run", "r-9"),
    }

    r = await client.delete(f"/api/ai/conversations/{created['id']}")
    assert r.status_code == 204
    assert (await client.get(f"/api/ai/conversations/{created['id']}")).status_code == 404
    assert (await client.get(f"/api/ai/steps/{step['id']}")).status_code == 404
    assert not [m for m in seeded.ai_messages.values() if m.conversation_id == created["id"]]
    assert not [s for s in seeded.ai_steps.values() if s.conversation_id == created["id"]]
    assert not [link for link in seeded.ai_links if link.conversation_id == created["id"]]
    event = seeded.ai_events[-1]
    assert (event.event, event.user_id, event.conversation_id) == (
        "conversation.delete",
        user_id,
        created["id"],
    )


async def test_the_list_titles_an_untitled_conversation_by_its_first_question(app, client, seeded):
    await login(client, "vera")
    untitled = await _create(client)
    titled = await _create(client, title="paths")
    await _seed_turns(seeded, await _user_id(seeded, "vera"), untitled["id"], 2)

    listed = {c["id"]: c for c in (await client.get("/api/ai/conversations")).json()["conversations"]}
    assert (listed[untitled["id"]]["title"], listed[untitled["id"]]["last_run"]) == ("question 1", None)
    assert listed[titled["id"]]["title"] == "paths"
    # the conversation read keeps the stored title
    assert (await client.get(f"/api/ai/conversations/{untitled['id']}")).json()["title"] == ""


async def test_a_foreign_id_answers_404_on_every_route(app, client, seeded):
    await login(client, "vera")
    created = await _create(client)
    await _seed_turns(seeded, await _user_id(seeded, "vera"), created["id"], 1)
    detail = (await client.get(f"/api/ai/conversations/{created['id']}")).json()
    message_id = detail["messages"][1]["id"]
    step_id = detail["messages"][1]["steps"][0]["id"]

    await login(client, "otto")
    cid = created["id"]
    assert (await client.get(f"/api/ai/conversations/{cid}")).status_code == 404
    assert (await client.delete(f"/api/ai/conversations/{cid}")).status_code == 404
    r = await client.post(f"/api/ai/conversations/{cid}/messages", json={"question": "q"})
    assert r.status_code == 404
    assert (await client.get(f"/api/ai/messages/{message_id}")).status_code == 404
    assert (await client.post(f"/api/ai/messages/{message_id}/cancel")).status_code == 404
    assert (await client.get(f"/api/ai/steps/{step_id}")).status_code == 404
    assert (await client.get("/api/ai/conversations")).json() == {"conversations": []}
    await login(client, "vera")
    assert (await client.get(f"/api/ai/conversations/{cid}")).status_code == 200


async def test_a_41_turn_conversation_sends_the_window_the_step_lines_and_the_summary(
    app, client, seeded, monkeypatch
):
    adapter = _Recorder(summary="turns 1 to 28 asked about fw1")
    await _configure(client, monkeypatch, adapter)
    created = await _create(client)
    await _seed_turns(seeded, await _user_id(seeded, "ada"), created["id"], 40)

    r = await client.post(f"/api/ai/conversations/{created['id']}/messages", json={"question": "question 41"})
    assert r.status_code == 202, r.text
    try:
        result = await _until_finished(client, r.json()["message_id"])
    finally:
        await _drain(app)
    assert (result["status"], result["answer"]) == ("done", "the answer")

    summary_call = next(c for c in adapter.calls if not c["tools"])
    assert "question 28" in summary_call["question"]
    assert "question 29" not in summary_call["question"]

    (turn,) = adapter.turn_calls()
    sent = turn["messages"]
    assert sent[-1] == {"role": "user", "content": "question 41"}
    assistants = [m["content"] for m in sent if m["role"] == "assistant"]
    assert len(assistants) == history.WINDOW_TURNS
    assert sent[0]["content"].startswith("<conversation_summary>")
    assert "turns 1 to 28 asked about fw1" in sent[0]["content"]
    assert sent[0]["content"].endswith("question 29")
    # the step lines are framed as data and quote the item names
    assert all(a.splitlines()[0] == '<tool_steps untrusted="true">' for a in assistants)
    first_line = assistants[0].splitlines()[1]
    assert first_line == (
        '[s29] trace_path(src=10.0.0.1) -> status=complete; snapshot=1759; paths=2; items: "fw1", "fw2"'
    )
    assert all(STEP_LINE.match(a.splitlines()[1]) for a in assistants)
    assert assistants[-1].endswith("answer 40")
    assert sum(len(m["content"]) for m in sent[:-1]) <= history.HISTORY_BUDGET_CHARS

    stored = await seeded.get_conversation(await _user_id(seeded, "ada"), created["id"])
    assert (stored.summary, stored.summary_through) == ("turns 1 to 28 asked about fw1", 56)
    event = next(e for e in seeded.ai_events if e.event == "summary.update")
    assert (event.outcome, event.conversation_id) == ("ok", created["id"])


async def test_a_conversation_at_500_messages_refuses_the_next_with_409(app, client, seeded, monkeypatch):
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client)
    assert conv_routes.MAX_CONVERSATION_MESSAGES == 500
    seeded.ai_conversations[created["id"]].message_count = 500

    r = await client.post(f"/api/ai/conversations/{created['id']}/messages", json={"question": "q"})
    assert r.status_code == 409
    assert "start a new conversation" in r.json()["error"]

    seeded.ai_conversations[created["id"]].message_count = 498
    r = await client.post(f"/api/ai/conversations/{created['id']}/messages", json={"question": "q"})
    assert r.status_code == 202
    await _drain(app)


async def test_a_message_takes_no_client_history(app, client, seeded, monkeypatch):
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client)
    body = {"question": "q", "history": [{"role": "user", "content": "x"}]}
    r = await client.post(f"/api/ai/conversations/{created['id']}/messages", json=body)
    assert r.status_code == 422


async def test_the_message_poll_has_the_agent_answer_shape_with_unframed_results(
    app, client, seeded, monkeypatch
):
    payload = json.dumps({"status": "complete", "paths": []})

    def one_step(on_step):
        step = tools_mod.ToolCall(
            name="trace_path", arguments={"src": "10.0.0.1"}, result=tools_mod.frame_untrusted(payload)
        )
        on_step(step)
        return [step]

    await _configure(client, monkeypatch, _Recorder(on_turn=one_step))
    created = await _create(client)
    r = await client.post(f"/api/ai/conversations/{created['id']}/messages", json={"question": "q"})
    assert r.status_code == 202
    try:
        result = await _until_finished(client, r.json()["message_id"])
    finally:
        await _drain(app)

    assert {"answer", "declined", "steps", "context", "snapshot"} <= set(result)
    assert (result["answer"], result["declined"], result["context"], result["snapshot"]) == (
        "the answer",
        False,
        None,
        None,
    )
    (step,) = result["steps"]
    assert {k: step[k] for k in ("name", "arguments", "is_error", "result")} == {
        "name": "trace_path",
        "arguments": {"src": "10.0.0.1"},
        "is_error": False,
        "result": payload,
    }
    stored = await seeded.get_step(await _user_id(seeded, "ada"), step["id"])
    assert stored.result_summary == "status=complete; paths=0"


async def test_a_step_is_read_in_full_and_as_its_summary_after_compaction(app, client, seeded):
    await login(client, "vera")
    created = await _create(client)
    user_id = await _user_id(seeded, "vera")
    reply = await seeded.start_turn(user_id, created["id"], "q", None, NOW, per_user_cap=2, global_cap=16)
    step = await seeded.append_step(
        reply.id, "trace_path", 1, {"src": "10.0.0.1"}, False, TRACE_RESULT, NOW, 5, result_summary="2 paths"
    )

    full = (await client.get(f"/api/ai/steps/{step.id}")).json()
    assert (full["result"], full["result_summary"], full["compacted"]) == (TRACE_RESULT, "2 paths", False)

    await seeded.compact_steps(NOW + timedelta(seconds=1), NOW + timedelta(seconds=1))
    compacted = (await client.get(f"/api/ai/steps/{step.id}")).json()
    assert (compacted["result"], compacted["result_summary"], compacted["compacted"]) == (
        None,
        "2 paths",
        True,
    )
    assert compacted["step"] == "s1"


async def test_cancel_sets_the_flag_on_the_owners_running_turn(app, client, seeded):
    await login(client, "vera")
    created = await _create(client)
    user_id = await _user_id(seeded, "vera")
    reply = await seeded.start_turn(user_id, created["id"], "q", None, NOW, per_user_cap=2, global_cap=16)

    r = await client.post(f"/api/ai/messages/{reply.id}/cancel")
    assert r.json() == {"cancel_requested": True}
    assert (await seeded.get_message(user_id, reply.id)).cancel_requested is True
    polled = (await client.get(f"/api/ai/messages/{reply.id}")).json()
    assert (polled["status"], polled["state"]) == ("running", "pending")


async def _post_and_wait(app, client, conversation_id, body):
    r = await client.post(f"/api/ai/conversations/{conversation_id}/messages", json=body)
    assert r.status_code == 202, r.text
    try:
        return await _until_finished(client, r.json()["message_id"])
    finally:
        await _drain(app)


async def test_the_page_context_is_stored_with_the_question_and_resolved_once_per_turn(
    app, client, seeded, monkeypatch
):
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client)
    context = {
        "version": 1,
        "route": {"pathname": "/", "pane_view": "trace"},
        "selection": [{"kind": "device", "uid": "dev:leaf101", "label": "leaf101"}],
    }

    result = await _post_and_wait(app, client, created["id"], {"question": "q", "context": context})

    assert result["status"] == "done"
    block = result["page_context"]
    # the turn is unpinned, so the graph check cannot run
    assert 'device dev:leaf101 "leaf101" [unverified]' in block
    assert result["context"] == {
        "page_context": context,
        "block": block,
        "snapshot": None,
    }
    detail = (await client.get(f"/api/ai/conversations/{created['id']}")).json()
    assert detail["messages"][0]["context"] == result["context"]
    (event,) = [e for e in seeded.ai_events if e.event == "context.resolve"]
    assert (event.outcome, event.message_id, event.conversation_id, event.surface) == (
        "ok",
        result["message_id"],
        created["id"],
        "drawer",
    )
    assert event.user_id == await _user_id(seeded, "ada")
    assert event.detail == {"selection": 1, "statuses": {"unverified": 1}}

    # a turn with no context stores none and records no event
    result = await _post_and_wait(app, client, created["id"], {"question": "q2"})
    assert (result["status"], result["context"], result["page_context"]) == ("done", None, None)
    assert len([e for e in seeded.ai_events if e.event == "context.resolve"]) == 1


async def test_a_turn_after_the_pointer_moved_reads_the_new_run_and_says_so(app, client, seeded, monkeypatch):
    pointer = iter([1000, 1000, 2000])
    requests = []

    async def pin(settings, requested):
        requests.append(requested)
        cts = int(requested.id) if requested is not None else next(pointer)
        return snapshot_mod.Snapshot(cts, settings)

    monkeypatch.setattr(ai_routes, "_pin_turn", pin)
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client)
    page = {"version": 1, "route": {"pathname": "/"}, "snapshot": {"id": "900", "origin": "pinned"}}

    results = [
        await _post_and_wait(app, client, created["id"], body)
        for body in (
            {"question": "first"},
            {"question": "second"},
            {"question": "third"},
            {"question": "fourth", "context": page},
        )
    ]

    assert [r["status"] for r in results] == ["done"] * 4
    assert [(r["snapshot"], r["snapshot_changed"]) for r in results] == [
        ("1000", False),
        ("1000", False),
        ("2000", True),
        # a run the page names is not a pointer move
        ("900", False),
    ]
    assert [r is None for r in requests] == [True, True, True, False]
    stored = await seeded.get_message(await _user_id(seeded, "ada"), results[2]["message_id"])
    assert stored.envelope["payload"]["snapshot_changed"] is True


async def test_a_pinned_conversation_never_reports_a_changed_run(app, client, seeded, monkeypatch):
    async def pin(settings, requested):
        return snapshot_mod.Snapshot(int(requested.id), settings)

    monkeypatch.setattr(ai_routes, "_pin_turn", pin)
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client, pin="1759")

    first = await _post_and_wait(app, client, created["id"], {"question": "first"})
    second = await _post_and_wait(app, client, created["id"], {"question": "second"})

    assert [(r["snapshot"], r["snapshot_changed"]) for r in (first, second)] == [
        ("1759", False),
        ("1759", False),
    ]


def test_a_step_line_names_the_label_the_tool_the_arguments_and_the_summary():
    step = AiStep(
        id="s",
        conversation_id="c",
        message_id="m",
        label=12,
        tool="simulate_policy_change",
        tool_version=1,
        arguments={"intents": [{}, {}], "snapshot": "1759", "reply": True},
        is_error=False,
        result=json.dumps({"snapshot": "1759", "flows": [], "evaluation": {"proven": 1, "possible": 2}}),
        result_sha256="",
        result_chars=0,
        started_at=NOW,
        elapsed_ms=1,
    )
    assert history.step_line(step) == (
        "[s12] simulate_policy_change(intents=2, snapshot=1759, reply=true)"
        " -> snapshot=1759; flows=0; evaluation.proven=1; evaluation.possible=2"
    )
    assert history.result_summary("trace_path", True, "ValueError: no such\ndevice") == (
        "error: ValueError: no such device"
    )
    assert history.result_summary("run_cypher", False, '{"columns": ["n"], "data": [[1], [2]]}') == (
        "columns=1; rows=2"
    )


# The results an envelope's evidence states, as JSON.
_FORWARDED = from_engine("hop-forwards", "holds").model_dump(mode="json")
_ALL_PATHS = from_engine("trace-forwards", "holds").model_dump(mode="json")
_PASSES = condition_result("holds").model_dump(mode="json")
_OPEN = condition_result("not-established").model_dump(mode="json")
_PER_ITEM = record("per-item").model_dump(mode="json")
_RECORDED = record("recorded").model_dump(mode="json")


def _catalogue_envelope(result: dict, *, evidence: dict, page_truncated: bool = False) -> str:
    """A catalogue envelope computed from run 1759, whose run is degraded."""
    return json.dumps(
        {
            "snapshot": {
                "id": "1759",
                "collection_ts": 1759,
                "selector": "latest",
                "manifest_sha256": None,
                "approximate": True,
                "run": {"snapshot": "1759", "degraded": True, "sources_failed": ["syslog"]},
            },
            "provenance": {"tool": "t", "tool_version": 1, "args_sha256": "0" * 64, "computed_at": "now"},
            "evidence": {"result": evidence, "unknowns": [], "gaps": [], "gaps_truncated": False},
            "page": {"next_cursor": "c" if page_truncated else None, "truncated": page_truncated},
            "result": result,
            "warnings": [],
        }
    )


def test_a_catalogue_step_line_reads_the_status_the_run_and_the_counts_from_the_envelope():
    legs = [
        {
            "leg": {"lane": 0, "detail": "egress via eth1"},
            "evidence": {"result": _FORWARDED, "basis": "derived"},
        },
        {"leg": {"lane": 0, "detail": "PERMITTED"}, "evidence": {"result": _FORWARDED, "basis": "derived"}},
    ]
    trace = {
        "detail": "PERMITTED",
        "hops": [{"lane": 0, "uid": "dev:sw1"}, {"lane": 0, "uid": "dev:fw1"}],
        "legs": legs,
        "legs_truncated": False,
    }
    step = AiStep(
        id="s",
        conversation_id="c",
        message_id="m",
        label=3,
        tool="reach_trace",
        tool_version=1,
        arguments={"mode": "path", "flow": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
        is_error=False,
        result=_catalogue_envelope(trace, evidence=_ALL_PATHS),
        result_sha256="",
        result_chars=0,
        started_at=NOW,
        elapsed_ms=1,
    )
    assert history.step_line(step) == (
        "[s3] reach_trace(mode=path, flow={...}) -> detail=PERMITTED; snapshot=1759; run.degraded=True;"
        ' evidence=forwarded, all candidate paths; hops=2; legs=2; forwarded=2; items: "dev:sw1", "dev:fw1"'
    )

    groups = {
        "mode": "groups",
        "status": "complete",
        "passes": {"count": 12, "offset": 0, "items": [{}], "truncated": True},
        "fails": {"count": 3, "truncated": True},
        "open": {"count": 0, "truncated": False},
    }
    assert history.result_summary(
        "reach_trace", False, _catalogue_envelope(groups, evidence=_PER_ITEM, page_truncated=True)
    ) == (
        "status=complete; mode=groups; snapshot=1759; run.degraded=True; evidence=each item states its own"
        " result; page.truncated; passes=12; fails=3; open=0"
    )
    # an evidence word that a bucket count already names is left to the bucket
    evidenced = {
        "mode": "groups",
        "status": "complete",
        "passes": {"count": 4000, "items": [{"evidence": {"result": _PASSES}}] * 2},
        "fails": {"count": 0, "items": []},
        "open": {"count": 0, "items": []},
        "explanations": {"count": 1, "items": [{"result": _OPEN}]},
    }
    assert history.result_summary("reach_trace", False, _catalogue_envelope(evidenced, evidence=_PASSES)) == (
        "status=complete; mode=groups; snapshot=1759; run.degraded=True; evidence=passes;"
        " passes=4000; fails=0; open=0; explanations=1; not decided=1"
    )

    rows = {"columns": ["n"], "data": [{"row": [1]}, {"row": [2]}], "truncated": True, "pinned": True}
    assert history.result_summary(
        "query_cypher", False, _catalogue_envelope(rows, evidence=_RECORDED, page_truncated=True)
    ) == (
        "snapshot=1759; run.degraded=True; evidence=recorded in the snapshot; truncated; page.truncated;"
        " columns=1; rows=2"
    )

    impact = {
        "subject": "device",
        "device_uid": "dev:sw1",
        "buckets": {"interfaces": {"count": 4, "items": []}, "tunnels": {"count": 0, "items": []}},
    }
    assert history.result_summary(
        "impact_assess", False, _catalogue_envelope(impact, evidence=_RECORDED)
    ) == (
        "snapshot=1759; run.degraded=True; evidence=recorded in the snapshot; buckets.interfaces=4;"
        " buckets.tunnels=0"
    )


def test_the_fold_stops_at_the_first_turn_that_has_not_ended():
    def message(seq: int, role: str, status: str = "done") -> AiMessage:
        return AiMessage(
            id=f"m{seq}", conversation_id="c", seq=seq, role=role, status=status, created_at=NOW, content="x"
        )

    messages = []
    for turn in range(1, history.WINDOW_TURNS + 5):
        # turn 2 is still running on another request
        messages += [
            message(2 * turn - 1, "user"),
            message(2 * turn, "assistant", "running" if turn == 2 else "done"),
        ]
    conversation = AiConversation(
        id="c", user_id=1, surface="drawer", created_at=NOW, last_message_at=NOW, messages=messages
    )

    window = history.window(conversation)
    assert len(window.turns) == history.WINDOW_TURNS
    assert [turn.question.seq for turn in window.fold] == [1]
    assert history.fold_request(None, window.fold)[1] == 2


async def test_a_cancel_during_the_summary_call_ends_the_turn_before_its_provider_call(
    app, client, seeded, monkeypatch
):
    class _CancelInSummary(_Recorder):
        def ask(self, question, **kwargs):
            if not kwargs["tools"]:
                for message in seeded.ai_messages.values():
                    if message.role == "assistant" and message.status in ("pending", "running"):
                        message.cancel_requested = True
            return super().ask(question, **kwargs)

    adapter = _CancelInSummary()
    await _configure(client, monkeypatch, adapter)
    created = await _create(client)
    await _seed_turns(seeded, await _user_id(seeded, "ada"), created["id"], 40)

    result = await _post_and_wait(app, client, created["id"], {"question": "question 41"})

    assert (result["status"], result["state"], result["detail"]) == (
        "error",
        "cancelled",
        ai_routes.CANCELLED_DETAIL,
    )
    assert [c for c in adapter.calls if not c["tools"]]
    assert adapter.turn_calls() == []


async def test_a_turn_pins_the_run_its_context_names_else_the_conversations_pin(
    app, client, seeded, monkeypatch
):
    requested = []

    async def pin(settings, ref):
        requested.append(ref)
        if ref.id == "1500":
            raise HTTPException(404, detail="unknown run: 1500")
        return snapshot_mod.Snapshot(int(ref.id), settings)

    monkeypatch.setattr(ai_routes, "_pin_turn", pin)
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client, pin="1759")
    page = {"version": 1, "route": {"pathname": "/"}, "snapshot": {"id": "900", "origin": "page-default"}}

    first = await _post_and_wait(app, client, created["id"], {"question": "first"})
    second = await _post_and_wait(app, client, created["id"], {"question": "second", "context": page})

    assert [(ref.id, ref.origin) for ref in requested] == [("1759", "pinned"), ("900", "page-default")]
    assert [r["snapshot"] for r in (first, second)] == ["1759", "900"]

    # a pin whose run has no retained graph refuses the turn
    unknown = await _create(client, pin="1500")
    r = await client.post(f"/api/ai/conversations/{unknown['id']}/messages", json={"question": "q"})
    assert r.status_code == 404
    assert "unknown run: 1500" in r.json()["error"]
    assert [ref.id for ref in requested] == ["1759", "900", "1500"]


async def test_a_context_whose_run_fails_the_check_records_a_rejected_resolution(
    app, client, seeded, monkeypatch
):
    async def pin(settings, ref):
        raise HTTPException(404, detail=f"unknown run: {ref.id}")

    monkeypatch.setattr(ai_routes, "_pin_turn", pin)
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client)
    page = {
        "version": 1,
        "route": {"pathname": "/"},
        "selection": [{"kind": "device", "uid": "dev:leaf101", "label": "leaf101"}],
        "snapshot": {"id": "900", "origin": "pinned"},
    }

    r = await client.post(
        f"/api/ai/conversations/{created['id']}/messages", json={"question": "q", "context": page}
    )

    assert r.status_code == 404
    [answer] = [
        m for m in seeded.ai_messages.values() if m.conversation_id == created["id"] and m.role == "assistant"
    ]
    (event,) = [e for e in seeded.ai_events if e.event == "context.resolve"]
    assert (event.outcome, event.message_id, event.conversation_id, event.snapshot) == (
        "rejected",
        answer.id,
        created["id"],
        "900",
    )
    assert event.detail == {"selection": 1, "status_code": 404}


async def test_a_provider_that_cannot_be_built_answers_502_and_leaves_no_rows(
    app, client, seeded, monkeypatch
):
    def unbuildable(*args, **kwargs):
        raise agent_base.AgentError("unknown provider: nope")

    await _configure(client, monkeypatch, _Recorder())
    monkeypatch.setattr(ai_routes.agent_base, "build", unbuildable)
    created = await _create(client)

    r = await client.post(f"/api/ai/conversations/{created['id']}/messages", json={"question": "q"})

    assert r.status_code == 502
    detail = (await client.get(f"/api/ai/conversations/{created['id']}")).json()
    assert (detail["message_count"], detail["messages"]) == (0, [])


async def test_a_failure_to_start_the_context_reads_finishes_the_conversation_turn(
    app, client, seeded, monkeypatch
):
    def broken(request, question, ctx):
        raise RuntimeError("no worker thread")

    monkeypatch.setattr(ai_routes, "_start_context", broken)
    await _configure(client, monkeypatch, _Recorder())
    created = await _create(client)

    result = await _post_and_wait(app, client, created["id"], {"question": "q", "include_context": True})

    assert (result["status"], result["state"]) == ("error", "error")
    assert result["detail"] == f"the ask failed (ask {result['message_id']}); see the server log"


async def test_a_drawer_turn_reads_the_open_application_draft_from_the_page_context(
    app, client, seeded, monkeypatch
):
    """The draft workspace's YAML and report reach the drawer's system text,
    checked against the caller's own generation."""
    adapter = _Recorder()
    await _configure(client, monkeypatch, adapter)
    generation = "6f1c2a4e-1b2c-4d5e-8f90-0a1b2c3d4e5f"
    record = {"id": generation, "created_by": await _user_id(seeded, "ada"), "snapshot": {"snapshot": "4000"}}

    async def get_application_generation(generation_id):
        return record if generation_id == generation else None

    # the fake store keeps no generations
    monkeypatch.setattr(seeded, "get_application_generation", get_application_generation, raising=False)
    created = await _create(client)
    note = "no address of the site B peer is recorded"
    yaml = f"groups:\n- id: peers\n  members:\n  - id: site-b\n    placeholder:\n      note: {note}\n"
    context = {
        "version": 1,
        "route": {"pathname": "/workspace", "pane_view": "applications", "section": "draft"},
        "application_draft": {
            "generation_id": generation,
            "status": "done",
            "run_id": "4000",
            "edited": True,
            "yaml": yaml,
            "members": [{"path": "groups.peers.members.site-b", "status": "unresolved", "note": note}],
        },
    }

    body = {"question": "why the note?", "context": context}
    result = await _post_and_wait(app, client, created["id"], body)

    assert result["status"] == "done"
    block = result["page_context"]
    head = f"application draft: generation {generation} [verified], run 4000 (recorded)"
    assert head + ", done, edited on the page" in block
    assert f'draft member groups.peers.members.site-b: unresolved, note "{note}"' in block
    assert "draft yaml: " + json.dumps(yaml) in block
    (turn,) = adapter.turn_calls()
    assert turn["system"].endswith("\n\n" + block)
    assert "Draft Business Application" in turn["system"]
    assert result["context"]["page_context"]["application_draft"]["yaml"] == yaml
