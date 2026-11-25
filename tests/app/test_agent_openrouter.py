"""OpenRouter adapter unit tests, client faked at the `_client` seam."""

from types import SimpleNamespace

import pytest

from hst.app.agent.base import AgentError
from hst.app.agent.openrouter import OpenRouterAdapter
from hst.app.agent.tools import Tool


def _tool(run=lambda **kw: "ok"):
    return Tool(
        name="probe",
        description="test tool",
        schema={"type": "object", "properties": {}},
        permission="graph.read",
        run=run,
    )


class _FakeClient:
    """Answers `chat.completions.create` from a scripted list, recording calls."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _adapter(client):
    a = OpenRouterAdapter({"api_key": "k"}, {})
    a._client = lambda: client
    return a


def _final(text="done"):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))])


def test_a_choicesless_response_becomes_a_readable_error():
    client = _FakeClient([SimpleNamespace(choices=None, error={"message": "upstream overloaded"})])
    with pytest.raises(AgentError, match="upstream overloaded"):
        _adapter(client).ask("q", system="s", tools=[_tool()], model="m", effort="medium")


def test_a_provider_exception_becomes_an_agent_error():
    client = _FakeClient([RuntimeError("boom")])
    with pytest.raises(AgentError, match="provider call failed: boom"):
        _adapter(client).ask("q", system="s", tools=[_tool()], model="m", effort="medium")


def test_tool_only_turns_replay_empty_content_not_null():
    call = SimpleNamespace(id="c1", function=SimpleNamespace(name="probe", arguments="{}"))
    tool_turn = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))]
    )
    client = _FakeClient([tool_turn, _final()])
    answer = _adapter(client).ask("q", system="s", tools=[_tool()], model="m", effort="medium")
    assert answer.answer == "done"
    assert len(answer.steps) == 1 and not answer.steps[0].is_error
    replayed = [m for m in client.calls[1]["messages"] if m.get("role") == "assistant"]
    assert replayed and replayed[0]["content"] == ""


def _usage(prompt, completion):
    return SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion)


def test_the_answer_carries_token_usage_and_the_served_model():
    call = SimpleNamespace(id="c1", function=SimpleNamespace(name="probe", arguments="{}"))
    tool_turn = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=None, tool_calls=[call]), finish_reason="tool_calls"
            )
        ],
        model="anthropic/claude-opus-5",
        usage=_usage(900, 40),
    )
    final = SimpleNamespace(
        choices=[
            SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=None), finish_reason="stop")
        ],
        model="anthropic/claude-opus-5-20260901",
        usage=_usage(1000, 120),
    )
    client = _FakeClient([tool_turn, final])
    answer = _adapter(client).ask(
        "q", system="s", tools=[_tool()], model="anthropic/claude-opus-5", effort="m"
    )

    assert answer.answer == "done"
    assert (answer.usage.input_tokens, answer.usage.output_tokens) == (1900, 160)
    assert answer.model_served == "anthropic/claude-opus-5-20260901"
    assert answer.provider == "openrouter"
    assert answer.stop_reason == "stop"
    assert len(answer.rounds) == 2


def test_a_content_filter_finish_is_reported_as_declined():
    filtered = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content="partial", tool_calls=None), finish_reason="content_filter"
            )
        ]
    )
    answer = _adapter(_FakeClient([filtered])).ask(
        "q", system="s", tools=[_tool()], model="m", effort="medium"
    )
    assert answer.declined is True
    assert answer.answer == "The model declined to answer this question."
    assert answer.stop_reason == "content_filter"


def test_each_tool_step_is_reported_as_it_returns_including_malformed_arguments():
    good = SimpleNamespace(id="c1", function=SimpleNamespace(name="probe", arguments="{}"))
    bad = SimpleNamespace(id="c2", function=SimpleNamespace(name="probe", arguments="{not json"))
    tool_turn = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[good, bad]))]
    )
    seen = []
    answer = _adapter(_FakeClient([tool_turn, _final()])).ask(
        "q", system="s", tools=[_tool()], model="m", effort="medium", on_step=seen.append
    )
    assert [s.is_error for s in seen] == [False, True]
    assert seen == answer.steps
