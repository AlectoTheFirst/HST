"""OpenRouter adapter for OpenAI-compatible chat completions."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any

from hst.app.agent.base import MAX_TURNS, AgentAnswer, AgentError, StepCallback, seed_history
from hst.app.agent.budget import FINAL_INSTRUCTION, INCOMPLETE_ANSWER, AskBudget
from hst.app.agent.tools import Tool, ToolCall
from hst.app.ai.redact import redact_exception
from hst.app.ai.schema import provider_input_schema
from hst.app.tls import Trust

log = logging.getLogger("hst.ai")

BASE_URL = "https://openrouter.ai/api/v1"
MAX_TOKENS = 16000
# the finish reason an OpenAI-compatible upstream reports when its moderation
# stopped the answer
CONTENT_FILTER = "content_filter"
DECLINED = "The model declined to answer this question."


class OpenRouterAdapter:
    def __init__(
        self, credentials: dict[str, str], options: dict[str, Any], trust: Trust | None = None
    ) -> None:
        self.credentials = credentials
        self.options = options
        self.trust = trust or Trust()

    def _client(self) -> Any:
        try:
            import openai
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise AgentError("the `openai` package is not installed on the server") from exc
        from hst.app.agent.registry import validate_options

        try:
            validate_options("openrouter", self.options)
        except ValueError as exc:
            raise AgentError(str(exc)) from exc
        extra: dict[str, Any] = {}
        if not self.trust.is_default:
            extra["http_client"] = openai.DefaultHttpxClient(verify=self.trust.ssl_verify())
        return openai.OpenAI(
            api_key=self.credentials.get("api_key"),
            base_url=self.options.get("base_url") or BASE_URL,
            # The timeout bounds one round.
            timeout=90.0,
            max_retries=0,
            **extra,
        )

    def _complete(self, client: Any, **kwargs: Any) -> Any:
        """One provider round. Returns a response with `choices` or raises AgentError.

        OpenRouter reports upstream failures as HTTP 200 with an `error` object
        and no `choices`."""
        try:
            response = client.chat.completions.create(**kwargs)
        except AgentError:
            raise
        except Exception as exc:
            raise AgentError(f"provider call failed: {exc}") from exc
        _require_choices(response)
        return response

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
        budget = budget or AskBudget()
        client = self._client()
        usage = budget.usage
        rounds = budget.rounds
        served: dict[str, str | None] = {"model": None, "stop_reason": None}

        def answer(text: str, *, declined: bool = False) -> AgentAnswer:
            return AgentAnswer(
                answer=text,
                steps=steps,
                declined=declined,
                usage=usage,
                model_served=served["model"],
                provider="openrouter",
                rounds=rounds,
                stop_reason=served["stop_reason"],
            )

        def complete(**kwargs: Any) -> Any:
            started = time.monotonic()
            try:
                response = self._complete(client, **kwargs)
            finally:
                rounds.append(int((time.monotonic() - started) * 1000))
            reported = getattr(response, "usage", None)
            usage.add(getattr(reported, "prompt_tokens", None), getattr(reported, "completion_tokens", None))
            if isinstance(model_id := getattr(response, "model", None), str):
                served["model"] = model_id
            finish = getattr(response.choices[0], "finish_reason", None)
            served["stop_reason"] = finish if isinstance(finish, str) else None
            return response

        wire_tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": provider_input_schema(t.schema),
                },
            }
            for t in tools
        ]
        transcript: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            *([dict(m) for m in messages] if messages is not None else seed_history(history, question)),
        ]
        steps: list[ToolCall] = []

        for _ in range(MAX_TURNS):
            if not budget.exploring():
                break
            try:
                response = complete(
                    model=model,
                    max_tokens=MAX_TOKENS,
                    messages=transcript,
                    tools=wire_tools,
                    timeout=budget.request_timeout(),
                )
            except AgentError:
                if not steps or budget.exploring():
                    raise
                break
            choice = response.choices[0]
            if getattr(choice, "finish_reason", None) == CONTENT_FILTER:
                return answer(DECLINED, declined=True)
            message = choice.message
            calls = list(getattr(message, "tool_calls", None) or [])

            if not calls:
                return answer((message.content or "").strip())

            transcript.append(
                {
                    "role": "assistant",
                    # upstreams behind OpenRouter's translation return 400 on null content
                    "content": message.content or "",
                    "tool_calls": [
                        {
                            "id": c.id,
                            "type": "function",
                            "function": {"name": c.function.name, "arguments": c.function.arguments},
                        }
                        for c in calls
                    ],
                }
            )
            for call in calls:
                # arguments arrive as a JSON string
                try:
                    args = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError:
                    outcome = ToolCall(call.function.name, {}, "arguments were not valid JSON", is_error=True)
                else:
                    outcome = budget.invoke(tools, call.function.name, args)
                steps.append(outcome)
                if on_step is not None:
                    on_step(outcome)
                transcript.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": outcome.result,
                    }
                )

        transcript.append(
            {
                "role": "user",
                "content": FINAL_INSTRUCTION,
            }
        )
        try:
            response = complete(
                model=model,
                max_tokens=MAX_TOKENS,
                messages=transcript,
                tools=wire_tools,
                tool_choice="none",
                timeout=budget.request_timeout(final=True),
            )
        except (AgentError, TimeoutError) as exc:
            if not steps:
                raise
            log.warning(
                "agent final answer failed; preserving %d tool steps: %s", len(steps), redact_exception(exc)
            )
            return answer(INCOMPLETE_ANSWER)
        if getattr(response.choices[0], "finish_reason", None) == CONTENT_FILTER:
            return answer(DECLINED, declined=True)
        text = (response.choices[0].message.content or "").strip()
        return answer(text or "Gave up after too many tool calls without reaching an answer.")


def _require_choices(response: Any) -> None:
    """Raise AgentError for a reply without `choices`, with the message of its
    `error` object."""
    if getattr(response, "choices", None):
        return
    detail = getattr(response, "error", None)
    if isinstance(detail, Mapping):
        msg = detail.get("message")
    else:
        msg = getattr(detail, "message", None) or (str(detail) if detail else None)
    raise AgentError(f"the provider returned no answer: {msg or 'no error detail given'}")


def probe(
    credentials: dict[str, str], options: dict[str, Any], model: str, trust: Trust | None = None
) -> None:
    """One chat completion request. Raises AgentError for a reply without `choices`."""
    client = OpenRouterAdapter(credentials, options, trust)._client()
    reply = client.chat.completions.create(
        model=model,
        max_tokens=1,
        messages=[{"role": "user", "content": "ok"}],
    )
    _require_choices(reply)
