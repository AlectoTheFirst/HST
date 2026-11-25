"""Slow exploration must leave time for synthesis and stop after abandonment."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from tests.app.test_ai_api import (
    _ask_and_wait,
    _block,
    _configure,
    _db_seam,
    _FakeGraphSession,
    _openai_turn,
    _reach_trace_tool,
    _StubAnthropic,
    _StubOpenAI,
)

from hst.app.agent import budget as budget_mod
from hst.app.agent.anthropic_ import AnthropicAdapter
from hst.app.agent.base import AgentAnswer
from hst.app.agent.budget import INCOMPLETE_ANSWER, AskBudget
from hst.app.agent.openrouter import OpenRouterAdapter
from hst.app.agent.tools import Tool, dispatch
from hst.app.routes import ai as ai_routes
from hst.core import db as db_mod


@pytest.fixture
def clock(monkeypatch):
    now = SimpleNamespace(value=0.0)
    monkeypatch.setattr(budget_mod, "time", SimpleNamespace(monotonic=lambda: now.value))
    return now


def _tool(run):
    return Tool("probe", "test", {"type": "object"}, "graph.read", run)


def _adapter(monkeypatch, provider, *, final_failure=False):
    if provider == "openrouter":
        turn = _openai_turn(
            tool_calls=[SimpleNamespace(id="c1", function=SimpleNamespace(name="probe", arguments="{}"))]
        )
        stub = _StubOpenAI([turn, _openai_turn("Only the recorded subset was evaluated.")])
        adapter = OpenRouterAdapter({}, {})
    else:
        turn = SimpleNamespace(
            stop_reason="tool_use", content=[_block(type="tool_use", id="c1", name="probe", input={})]
        )
        stub = _StubAnthropic(
            [
                turn,
                SimpleNamespace(
                    stop_reason="end_turn",
                    content=[_block(type="text", text="Only the recorded subset was evaluated.")],
                ),
            ]
        )
        adapter = AnthropicAdapter(provider, {}, {})
    if final_failure:
        original = stub._create

        def create(**kwargs):
            if "tool_choice" in kwargs:
                raise TimeoutError("provider timed out")
            return original(**kwargs)

        if provider == "openrouter":
            stub.chat.completions.create = create
        else:
            stub.messages.create = create
            stub.beta.messages.create = create
    monkeypatch.setattr(adapter, "_client", lambda: stub)
    return adapter, stub


@pytest.mark.parametrize("provider", ["openrouter", "anthropic", "bedrock"])
@pytest.mark.parametrize("final_failure", [False, True])
def test_slow_exploration_preserves_evidence_and_reserves_a_final_answer(
    monkeypatch, clock, provider, final_failure
):
    adapter, stub = _adapter(monkeypatch, provider, final_failure=final_failure)
    budget = AskBudget(started=0.0)

    def run():
        clock.value = 215.0
        return '{"evaluated": "subset", "allowed": [443]}'

    answer = adapter.ask(
        "what traffic is allowed from non-RFC1918 to vlan 10",
        system="s",
        tools=[_tool(run)],
        model="m",
        effort="high",
        budget=budget,
    )
    assert len(answer.steps) == len(budget.steps) == 1
    assert "443" in answer.steps[0].result
    if final_failure:
        assert answer.answer == INCOMPLETE_ANSWER
    else:
        assert answer.answer == "Only the recorded subset was evaluated."
        assert len(stub.requests) == 2
        final = stub.requests[-1]
        assert final["tool_choice"] == ("none" if provider == "openrouter" else {"type": "none"})
        assert final["timeout"] == 80.0


def test_budget_skips_tools_reserved_for_final_answer_and_stops_after_cancellation(clock):
    budget = AskBudget(started=0.0)
    calls = []
    tools = [_tool(lambda: calls.append("ran") or "ok")]
    clock.value = 215.0
    assert budget.invoke(tools, "probe", {}).is_error
    assert calls == []
    budget.stopped.set()
    with pytest.raises(TimeoutError):
        budget.request_timeout(final=True)
    with pytest.raises(TimeoutError):
        budget.invoke(tools, "probe", {})
    assert calls == []


@pytest.mark.parametrize(
    ("port", "proto", "expected_port", "expected_proto"),
    [
        ("any", "any", "any", frozenset(range(256))),
        ("80,443", "tcp,udp", "80,443", ["tcp", "udp"]),
        ("1-1024", "tcp", "1-1024", "tcp"),
        (443, "tcp", 443, "tcp"),
        (None, "tcp", None, "tcp"),
    ],
)
def test_agent_trace_accepts_service_sets(monkeypatch, port, proto, expected_port, expected_proto):
    import hst.path as path_engine

    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda q: [], current=4000)))
    captured = {}

    def trace(session, src, dst, **kwargs):
        captured.update(kwargs)
        return {"verdict": "PARTIAL", "legs": []}

    monkeypatch.setattr(path_engine, "trace", trace)
    flow = {"src": "203.0.113.0/24", "dst": "10.10.0.0/24", "port": port, "proto": proto}
    call = dispatch([_reach_trace_tool()], "reach_trace", {"mode": "path", "flow": flow})
    assert call.is_error is False, call.result
    result = json.loads(call.ui_result)["result"]
    assert captured["port"] == expected_port
    assert captured["proto"] == expected_proto
    assert result["detail"] == "PARTIAL"


async def test_hard_deadline_preserves_completed_steps_and_stops_worker(client, monkeypatch):
    from threading import Event

    release = Event()
    finished = Event()
    budgets = []
    late_calls = []

    class Adapter:
        def ask(self, question, *, budget, **kwargs):
            budgets.append(budget)
            # Force one completed step even with the test's tiny deadline.
            budget.steps.append(budget_mod.dispatch([_tool(lambda: "evidence")], "probe", {}))
            try:
                release.wait(timeout=2)
                budget.invoke([_tool(lambda: late_calls.append("ran") or "late")], "probe", {})
            except TimeoutError:
                pass
            finally:
                finished.set()
            return AgentAnswer(answer="late")

    monkeypatch.setattr(ai_routes, "ASK_DEADLINE_S", 0.05)
    await _configure(client, monkeypatch, Adapter())
    try:
        result = await _ask_and_wait(client, {"question": "slow"})
        assert result["status"] == "done"
        assert result["answer"] == INCOMPLETE_ANSWER
        assert result["steps"][0]["result"] == "evidence"
        assert budgets[0].stopped.is_set()
    finally:
        release.set()
        # Let the worker finish without holding up the async event loop.
        import asyncio

        await asyncio.to_thread(finished.wait, 2)
    assert late_calls == []
