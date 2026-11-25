"""Adapter protocol, the shared answer shape, and the history seeding rule."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from hst.app.agent.budget import AskBudget
from hst.app.agent.tools import Tool, ToolCall
from hst.app.tls import Trust

# Upper bound on the tool rounds of one ask.
MAX_TURNS = 24


class AgentError(RuntimeError):
    """Provider-side failure shown to the operator verbatim."""


@dataclass
class Usage:
    """Tokens one ask spent, summed over its provider rounds."""

    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, input_tokens: Any, output_tokens: Any) -> None:
        # a stub or an upstream that reports no usage leaves the totals as they are
        if isinstance(input_tokens, int):
            self.input_tokens += input_tokens
        if isinstance(output_tokens, int):
            self.output_tokens += output_tokens


@dataclass
class AgentAnswer:
    answer: str
    steps: list[ToolCall] = field(default_factory=list)
    declined: bool = False
    usage: Usage = field(default_factory=Usage)
    # The model id of the last response. A server-side fallback can answer
    # with a model other than the requested model.
    model_served: str | None = None
    provider: str | None = None
    # the latency of each provider round in milliseconds, in order
    rounds: list[int] = field(default_factory=list)
    # the stop or finish reason of the last response
    stop_reason: str | None = None


# Called with each tool step as soon as the tool returns, on the adapter's thread.
StepCallback = Callable[[ToolCall], None]


def seed_history(history: Sequence[Mapping[str, str]], question: str) -> list[dict[str, Any]]:
    """Prior text turns plus the new question, normalized for the providers.

    The Anthropic Messages API requires the first message to be a user turn and
    rejects consecutive same-role messages.
    """
    seeded: list[dict[str, Any]] = []
    for turn in [*history, {"role": "user", "content": question}]:
        content = turn["content"].strip()
        if not content:
            continue
        if not seeded and turn["role"] != "user":
            continue
        if seeded and seeded[-1]["role"] == turn["role"]:
            seeded[-1]["content"] += "\n\n" + content
        else:
            seeded.append({"role": turn["role"], "content": content})
    return seeded


class AgentAdapter(Protocol):
    def ask(
        self,
        question: str,
        *,
        system: str,
        tools: list[Tool],
        model: str,
        effort: str,
        history: Sequence[Mapping[str, str]] = (),
        budget: AskBudget | None = None,
        on_step: StepCallback | None = None,
        messages: Sequence[Mapping[str, Any]] | None = None,
    ) -> AgentAnswer:
        """Answer `question`. `messages`, when given, is the whole seeded
        conversation ending with the question, and replaces `history`."""
        ...


def build(
    provider: str, credentials: dict[str, str], options: dict[str, Any], trust: Trust | None = None
) -> AgentAdapter:
    """Construct the adapter for a provider id.

    `trust` is the resolved TLS trust for this provider (app/tls.py). None
    selects the SDK defaults.
    """
    if provider in ("anthropic", "bedrock"):
        from hst.app.agent.anthropic_ import AnthropicAdapter

        return AnthropicAdapter(provider, credentials, options, trust)
    if provider == "openrouter":
        from hst.app.agent.openrouter import OpenRouterAdapter

        return OpenRouterAdapter(credentials, options, trust)
    raise AgentError(f"unknown provider: {provider}")
