"""ModelClient, usage capture, the Anthropic error wrap, the audit sink and redaction.

No test here reaches a provider: the adapters run against stub clients that
mimic the Messages API, and the audit sink writes to the in-memory store.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from tests.app.fakes import FakeStore
from tests.app.test_ai_api import (
    _GUARDED_DEVICES,
    _ask_and_wait,
    _block,
    _configure,
    _db_seam,
    _FakeGraphSession,
    _StubAnthropic,
)

from hst.app.agent import base as agent_base
from hst.app.agent import registry
from hst.app.agent.anthropic_ import AnthropicAdapter
from hst.app.agent.base import AgentAnswer, AgentError
from hst.app.agent.budget import AskBudget
from hst.app.agent.tools import CypherAudit, Tool, ToolCall
from hst.app.ai.audit import AuditSink
from hst.app.ai.client import ModelClient, TurnRequest
from hst.app.ai.redact import redact, redact_exception

# --- usage capture and the Anthropic error wrap --------------------------------------


def _tool_turn(call_id: str, name: str = "probe", **extra):
    return SimpleNamespace(
        stop_reason="tool_use",
        content=[_block(type="tool_use", id=call_id, name=name, input={})],
        **extra,
    )


def _text_turn(text: str, **extra):
    return SimpleNamespace(stop_reason="end_turn", content=[_block(type="text", text=text)], **extra)


def _probe_tool() -> Tool:
    return Tool("probe", "test", {"type": "object", "properties": {}}, "graph.read", lambda: "ok")


def _anthropic(monkeypatch, stub, provider: str = "anthropic") -> AnthropicAdapter:
    adapter = AnthropicAdapter(provider, {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)
    return adapter


def test_the_anthropic_adapter_returns_token_usage_and_the_served_model(monkeypatch):
    stub = _StubAnthropic(
        [
            _tool_turn(
                "tu_1",
                model="claude-opus-5",
                usage=SimpleNamespace(input_tokens=1200, output_tokens=80),
            ),
            _text_turn(
                "done",
                model="claude-sonnet-5",
                usage=SimpleNamespace(input_tokens=1400, output_tokens=300),
            ),
        ]
    )
    answer = _anthropic(monkeypatch, stub).ask(
        "q", system="s", tools=[_probe_tool()], model="claude-opus-5", effort="high"
    )

    assert answer.answer == "done"
    assert (answer.usage.input_tokens, answer.usage.output_tokens) == (2600, 380)
    # a server-side fallback answers with another model; the last response names it
    assert answer.model_served == "claude-sonnet-5"
    assert answer.provider == "anthropic"
    assert answer.stop_reason == "end_turn"
    assert len(answer.rounds) == 2 and all(ms >= 0 for ms in answer.rounds)


def test_the_budget_holds_the_usage_and_the_rounds_the_adapter_collected(monkeypatch):
    stub = _StubAnthropic(
        [
            _tool_turn("tu_1", usage=SimpleNamespace(input_tokens=1200, output_tokens=80)),
            _text_turn("done", usage=SimpleNamespace(input_tokens=1400, output_tokens=300)),
        ]
    )
    budget = AskBudget()
    answer = _anthropic(monkeypatch, stub).ask(
        "q", system="s", tools=[_probe_tool()], model="claude-opus-5", effort="high", budget=budget
    )

    # the route reads these when the ask is abandoned before the adapter returns
    assert (budget.usage.input_tokens, budget.usage.output_tokens) == (2600, 380)
    assert budget.rounds == answer.rounds
    assert len(budget.rounds) == 2


def test_a_response_without_usage_leaves_the_totals_at_zero(monkeypatch):
    stub = _StubAnthropic([_text_turn("hi")])
    answer = _anthropic(monkeypatch, stub, "bedrock").ask(
        "q", system="s", tools=[], model="anthropic.claude-opus-5", effort="high"
    )
    assert (answer.usage.input_tokens, answer.usage.output_tokens) == (0, 0)
    assert answer.model_served is None
    assert answer.provider == "bedrock"


def test_an_anthropic_exception_on_a_non_final_request_is_an_agent_error(monkeypatch):
    class _Failing(_StubAnthropic):
        def _create(self, **kwargs):
            self.requests.append(kwargs)
            raise RuntimeError("upstream overloaded")

    stub = _Failing([])
    with pytest.raises(AgentError, match="provider call failed: upstream overloaded") as raised:
        _anthropic(monkeypatch, stub).ask("q", system="s", tools=[_probe_tool()], model="m", effort="high")
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert "tool_choice" not in stub.requests[0]


def test_the_anthropic_adapter_reports_each_tool_step_as_it_returns(monkeypatch):
    stub = _StubAnthropic([_tool_turn("tu_1"), _tool_turn("tu_2"), _text_turn("done")])
    seen: list[ToolCall] = []
    answer = _anthropic(monkeypatch, stub).ask(
        "q", system="s", tools=[_probe_tool()], model="m", effort="high", on_step=seen.append
    )
    assert [s.name for s in seen] == ["probe", "probe"]
    assert seen == answer.steps


def test_messages_replace_the_history_and_the_question(monkeypatch):
    stub = _StubAnthropic([_text_turn("done")])
    conversation = [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "answer"},
        {"role": "user", "content": "second"},
    ]
    _anthropic(monkeypatch, stub).ask(
        "ignored",
        system="s",
        tools=[],
        model="m",
        effort="high",
        history=[{"role": "user", "content": "ignored too"}],
        messages=conversation,
    )
    assert stub.requests[0]["messages"] == conversation


async def test_an_anthropic_provider_exception_reports_the_provider_call_failed(client, monkeypatch):
    class _Failing(_StubAnthropic):
        def _create(self, **kwargs):
            raise RuntimeError("upstream overloaded")

    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: _Failing([]))
    await _configure(client, monkeypatch, adapter)

    result = await _ask_and_wait(client, {"question": "hi"})

    assert result["status"] == "error"
    assert result["detail"].startswith("the provider call failed (ask ")
    assert "upstream overloaded" not in result["detail"]


# --- ModelClient ------------------------------------------------------------------


def _config(**changes):
    return {**registry.merged(None), "provider": "anthropic", "model": "claude-opus-5", **changes}


def test_available_needs_the_agent_turned_on_and_credentials():
    assert ModelClient(_config(enabled=True), {"api_key": "k"}).available()
    assert not ModelClient(_config(enabled=False), {"api_key": "k"}).available()
    assert not ModelClient(_config(enabled=True), {}).available()


async def test_from_store_reads_the_saved_settings_and_credentials(client, app, monkeypatch):
    await _configure(client, monkeypatch, object())

    model_client = await ModelClient.from_store(app.state.store, app.state.settings)

    assert model_client.available()
    assert (model_client.provider, model_client.model) == ("anthropic", "claude-opus-5")
    assert model_client.secrets == {"api_key": "sk-ant-x"}
    assert model_client.trust is not None and model_client.trust.verify


def test_run_asks_with_the_configured_model_and_names_the_provider(monkeypatch):
    seen: dict = {}

    class _Adapter:
        def ask(self, question, **kwargs):
            seen.update(question=question, **kwargs)
            return AgentAnswer(answer="ok")

    built: list[tuple] = []
    monkeypatch.setattr(agent_base, "build", lambda *args: built.append(args) or _Adapter())
    steps: list[ToolCall] = []
    model_client = ModelClient(_config(enabled=True, effort="medium"), {"api_key": "k"})

    answer = model_client.run(TurnRequest("q", system="s", on_step=steps.append))
    model_client.run(TurnRequest("again", system="s"))

    assert answer.provider == "anthropic"
    assert (seen["model"], seen["effort"], seen["system"]) == ("claude-opus-5", "medium", "s")
    assert seen["messages"] is None
    # one adapter per client
    assert len(built) == 1 and built[0][0] == "anthropic"


def test_run_propagates_an_unknown_provider_as_an_agent_error():
    model_client = ModelClient(_config(provider="nope"), {})
    with pytest.raises(AgentError, match="unknown provider"):
        model_client.run(TurnRequest("q", system="s"))


@pytest.mark.parametrize("provider", ["anthropic", "bedrock", "openrouter"])
def test_probe_calls_the_provider_probe(monkeypatch, provider):
    from hst.app.agent import anthropic_, openrouter

    calls: list[tuple] = []
    monkeypatch.setattr(anthropic_, "probe", lambda *args: calls.append(("anthropic", *args)))
    monkeypatch.setattr(openrouter, "probe", lambda *args: calls.append(("openrouter", *args)))
    options = {"aws_region": "eu-west-1"}

    ModelClient(_config(provider=provider, options=options), {"api_key": "k"}).probe()

    if provider == "openrouter":
        assert calls == [("openrouter", {"api_key": "k"}, options, "claude-opus-5", None)]
    else:
        assert calls == [("anthropic", provider, {"api_key": "k"}, options, "claude-opus-5", None)]


# --- the audit sink ---------------------------------------------------------------


async def _eventually(check) -> None:
    for _ in range(200):
        if check():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the condition never held")


async def test_one_tool_call_event_is_written_per_tool_call(client, app, monkeypatch):
    import hst.twin_tools.query as query_mod
    from hst.core import db as db_mod

    table = {"columns": ["n"], "data": [{"row": [1]}], "truncated": False}
    monkeypatch.setattr(query_mod, "run_readonly", lambda s, q, p, graph=False: table)
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))
    stub = _StubAnthropic(
        [
            SimpleNamespace(
                stop_reason="tool_use",
                content=[
                    _block(
                        type="tool_use", id="tu_1", name="query_cypher", input={"query": _GUARDED_DEVICES}
                    ),
                    _block(type="tool_use", id="tu_2", name="no_such_tool", input={}),
                ],
            ),
            _tool_turn("tu_3", name="query_cypher"),
            _text_turn("done"),
        ]
    )
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)
    await _configure(client, monkeypatch, adapter)

    result = await _ask_and_wait(client, {"question": "hi"})

    assert result["status"] == "done"
    ada = await app.state.store.get_user_by_username("ada")
    events = sorted(app.state.store.ai_events, key=lambda e: e.id)
    assert [(e.event, e.tool, e.outcome) for e in events] == [
        ("tool.call", "query_cypher", "ok"),
        ("tool.call", "no_such_tool", "error"),
        # query_cypher without its query argument
        ("tool.call", "query_cypher", "error"),
    ]
    assert {(e.user_id, e.origin, e.provider, e.model_requested) for e in events} == {
        (ada.id, "web", "anthropic", "claude-opus-5")
    }
    assert len({e.step_id for e in events}) == 3
    assert events[2].error_class == "TypeError"
    assert all(e.latency_ms is not None for e in events)
    # the Cypher row names the tool call that ran it
    cypher = app.state.store.cypher_events
    assert [(c.query, c.origin, c.ai_step_id) for c in cypher] == [
        (_GUARDED_DEVICES, "web", events[0].step_id)
    ]


async def test_the_sink_writes_as_each_call_returns():
    store = FakeStore()
    sink = AuditSink(store, user_id=7, provider="openrouter", model_requested="m", snapshot="3000")
    sink.cypher.append(CypherAudit("MATCH (n) RETURN n", "ok", 1, 20))

    await asyncio.to_thread(sink.on_step, ToolCall("run_cypher", {"query": "q"}, "{}", elapsed_ms=12))
    await _eventually(lambda: store.ai_events and store.cypher_events)

    [event] = store.ai_events
    assert (event.event, event.tool, event.outcome, event.latency_ms) == ("tool.call", "run_cypher", "ok", 12)
    assert (event.user_id, event.snapshot, event.provider) == (7, "3000", "openrouter")
    assert event.detail is None
    [row] = store.cypher_events
    assert (row.user_id, row.origin, row.ai_step_id, row.row_count) == (7, "web", event.step_id, 1)

    await sink.close()
    assert len(store.ai_events) == 1 and len(store.cypher_events) == 1


async def test_the_turn_end_flush_writes_cypher_rows_no_step_claimed():
    store = FakeStore()
    sink = AuditSink(store, user_id=7)
    sink.cypher.append(CypherAudit("RETURN 1", "rejected"))

    await sink.close()

    assert [(c.query, c.outcome, c.origin, c.ai_step_id) for c in store.cypher_events] == [
        ("RETURN 1", "rejected", "web", None)
    ]
    assert store.ai_events == []


async def test_rows_that_found_no_loop_are_written_by_the_turn_end_flush():
    store = FakeStore()
    sink = AuditSink(store, user_id=None)
    closed = asyncio.new_event_loop()
    closed.close()
    sink._loop = closed

    sink.on_step(ToolCall("trace_path", {}, "PermissionError: no", is_error=True))
    assert store.ai_events == []

    await sink.close()
    [event] = store.ai_events
    assert (event.outcome, event.error_class) == ("error", "PermissionError")


async def test_an_audit_write_failure_is_logged_and_does_not_raise(caplog):
    store = FakeStore()

    async def boom(event):
        raise RuntimeError("store is down")

    store.record_ai_event = boom
    sink = AuditSink(store, user_id=1)
    sink.on_step(ToolCall("trace_path", {}, "ok"))
    await sink.close()

    assert "failed to record an agent audit row (tool.call)" in caplog.text


# --- redaction --------------------------------------------------------------------

# Built at run time so the source holds no string a secret scanner reads as a key.
_ANTHROPIC_KEY = "sk-" + "ant-api03-" + "abc123" * 4
_OPENROUTER_KEY = "sk-" + "or-v1-" + "0f" * 16
_AWS_KEY_ID = "AKIA" + "ABCDEFGH" * 2
_AWS_TEMP_KEY_ID = "ASIA" + "QRSTUVWX" * 2


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"Error code: 401 - invalid x-api-key {_ANTHROPIC_KEY}", _ANTHROPIC_KEY),
        (f"OpenRouter rejected {_OPENROUTER_KEY}", _OPENROUTER_KEY),
        (f"The security token {_AWS_KEY_ID} is not valid", _AWS_KEY_ID),
        (f"temporary id {_AWS_TEMP_KEY_ID} expired", _AWS_TEMP_KEY_ID),
        ("POST https://svc:pw@gateway.example/v1/messages failed", "svc:pw"),
        ("GET https://gateway.example/v1/models?sig=abc&x=1 returned 403", "sig=abc"),
        ("headers {'Authorization': 'Bearer abc.def'}", "abc.def"),
        ("x-api-key: plain-value", "plain-value"),
    ],
)
def test_redact_removes_credentials(text, secret):
    cleaned = redact(text)
    assert secret not in cleaned
    assert "[redacted]" in cleaned


def test_redact_keeps_the_rest_of_the_text():
    text = "Connection error to https://api.anthropic.com/v1/messages (HTTP 529 overloaded_error)"
    assert redact(text) == text
    assert redact("POST https://u:p@host.example/v1?t=1 failed") == (
        "POST https://[redacted]@host.example/v1?[redacted] failed"
    )


def test_redact_exception_keeps_the_traceback_and_removes_credentials():
    try:
        try:
            raise ValueError(f"upstream rejected {_ANTHROPIC_KEY}")
        except ValueError as cause:
            raise AgentError("provider call failed") from cause
    except AgentError as exc:
        text = redact_exception(exc)

    assert _ANTHROPIC_KEY not in text
    assert "ValueError: upstream rejected [redacted]" in text
    assert text.startswith("Traceback")
    assert text.endswith("AgentError: provider call failed")


async def test_a_crashed_ask_logs_its_traceback_without_credentials(client, monkeypatch, caplog):
    class _Adapter:
        def ask(self, question, **kwargs):
            raise RuntimeError(f"gateway echoed x-api-key: {_ANTHROPIC_KEY}")

    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(client, {"question": "q"})

    assert result["status"] == "error"
    assert "crashed: Traceback" in caplog.text
    assert "RuntimeError: gateway echoed x-api-key: [redacted]" in caplog.text
    assert _ANTHROPIC_KEY not in caplog.text
