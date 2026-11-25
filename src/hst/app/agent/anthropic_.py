"""Anthropic Messages API adapter for Anthropic direct and AWS Bedrock."""

from __future__ import annotations

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

MAX_TOKENS = 16000
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicAdapter:
    def __init__(
        self,
        provider: str,
        credentials: dict[str, str],
        options: dict[str, Any],
        trust: Trust | None = None,
    ) -> None:
        self.provider = provider
        self.credentials = credentials
        self.options = options
        self.trust = trust or Trust()

    def _http_client(self, anthropic: Any) -> dict[str, Any]:
        """`http_client=` for the SDK when the trust settings are not the default."""
        if self.trust.is_default:
            return {}
        return {"http_client": anthropic.DefaultHttpxClient(verify=self.trust.ssl_verify())}

    def _client(self) -> Any:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise AgentError("the `anthropic` package is not installed on the server") from exc

        if self.provider == "bedrock":
            return self._bedrock_client(anthropic)
        return anthropic.Anthropic(
            api_key=self.credentials.get("api_key"),
            timeout=90.0,
            max_retries=0,
            **self._http_client(anthropic),
        )

    def _bedrock_client(self, anthropic: Any) -> Any:
        """Bedrock client for the auth mode that `registry.bedrock_auth_mode` picks.

        Region is the only required option. An option value that
        `registry.validate_options` or `registry.validate_endpoint` refuses
        raises AgentError.
        """
        from hst.app.agent.registry import bedrock_auth_mode, validate_endpoint, validate_options

        region = self.options.get("aws_region")
        mode = bedrock_auth_mode(self.credentials, self.options)
        if mode is None:
            raise AgentError("Bedrock needs a region")
        try:
            validate_options("bedrock", self.options)
            validate_endpoint("bedrock", self.credentials, self.options)
        except ValueError as exc:
            raise AgentError(str(exc)) from exc

        common: dict[str, Any] = {
            "aws_region": region,
            "timeout": 90.0,
            "max_retries": 0,
            **self._http_client(anthropic),
        }
        if self.options.get("base_url"):
            common["base_url"] = self.options["base_url"]

        if mode == "api_key":
            # a Bedrock API key is a bearer token
            return anthropic.AnthropicBedrock(
                **common,
                api_key=self.credentials["aws_bedrock_api_key"],
            )

        if mode == "assume":
            creds = self._assume_role(region)  # type: ignore[arg-type]
            return anthropic.AnthropicBedrock(
                **common,
                aws_access_key=creds["AccessKeyId"],
                aws_secret_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

        if mode == "keys":
            return anthropic.AnthropicBedrock(
                **common,
                aws_access_key=self.credentials["aws_access_key_id"],
                aws_secret_key=self.credentials["aws_secret_access_key"],
                aws_session_token=self.credentials.get("aws_session_token") or None,
            )

        # In the "ambient" mode the SDK resolves the credential chain of the host.
        return anthropic.AnthropicBedrock(**common)

    def _assume_role(self, region: str) -> dict[str, str]:
        """STS AssumeRole with the credentials of the form or of the host."""
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise AgentError("assuming a role needs `boto3`; install the `agent` extra") from exc

        kwargs: dict[str, Any] = {"region_name": region}
        if self.credentials.get("aws_access_key_id"):
            kwargs["aws_access_key_id"] = self.credentials["aws_access_key_id"]
            kwargs["aws_secret_access_key"] = self.credentials.get("aws_secret_access_key")
            if self.credentials.get("aws_session_token"):
                kwargs["aws_session_token"] = self.credentials["aws_session_token"]

        # boto3 takes a CA path or False.
        with self.trust.ca_file_path() as verify:
            if verify is not None:
                kwargs["verify"] = verify
            sts = boto3.client("sts", **kwargs)
            assumed = sts.assume_role(
                RoleArn=self.options["aws_role_arn"],
                RoleSessionName=self.options.get("aws_role_session_name") or "hst",
            )
        return assumed["Credentials"]

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
        wire_tools = [
            {"name": t.name, "description": t.description, "input_schema": provider_input_schema(t.schema)}
            for t in tools
        ]
        transcript: list[dict[str, Any]] = (
            [dict(m) for m in messages] if messages is not None else seed_history(history, question)
        )
        steps: list[ToolCall] = []
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
                provider=self.provider,
                rounds=rounds,
                stop_reason=served["stop_reason"],
            )

        def request(*, final: bool) -> Any:
            kwargs: dict[str, Any] = {
                "model": model,
                "max_tokens": MAX_TOKENS,
                "system": system,
                "messages": transcript,
                "tools": wire_tools,
                "output_config": {"effort": effort},
                "timeout": budget.request_timeout(final=final),
            }
            if final:
                # `tools` stays in the request for the tool_use blocks of the transcript.
                kwargs["tool_choice"] = {"type": "none"}
            # Bedrock rejects server-side fallbacks.
            if self.provider == "anthropic":
                kwargs["betas"] = [FALLBACK_BETA]
                kwargs["fallbacks"] = "default"
                create = client.beta.messages.create
            else:
                create = client.messages.create
            started = time.monotonic()
            try:
                response = create(**kwargs)
            except Exception as exc:
                raise AgentError(f"provider call failed: {exc}") from exc
            finally:
                rounds.append(int((time.monotonic() - started) * 1000))
            reported = getattr(response, "usage", None)
            usage.add(getattr(reported, "input_tokens", None), getattr(reported, "output_tokens", None))
            if isinstance(model_id := getattr(response, "model", None), str):
                served["model"] = model_id
            if isinstance(stop := getattr(response, "stop_reason", None), str):
                served["stop_reason"] = stop
            return response

        for _ in range(MAX_TURNS):
            if not budget.exploring():
                break
            try:
                response = request(final=False)
            except Exception:
                if not steps or budget.exploring():
                    raise
                break

            # A refusal has no content.
            if getattr(response, "stop_reason", None) == "refusal":
                detail = getattr(getattr(response, "stop_details", None), "explanation", "")
                return answer(detail or "The model declined to answer this question.", declined=True)

            blocks = list(response.content or [])
            calls = [b for b in blocks if getattr(b, "type", None) == "tool_use"]
            if not calls:
                text = "".join(b.text for b in blocks if getattr(b, "type", None) == "text")
                return answer(text.strip())

            # One user message holds the result of each tool call of the round.
            transcript.append({"role": "assistant", "content": blocks})
            results = []
            for call in calls:
                outcome = budget.invoke(tools, call.name, dict(call.input or {}))
                steps.append(outcome)
                if on_step is not None:
                    on_step(outcome)
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": call.id,
                        "content": outcome.result,
                        "is_error": outcome.is_error,
                    }
                )
            transcript.append({"role": "user", "content": results})

        # The Messages API coalesces consecutive user turns.
        transcript.append(
            {
                "role": "user",
                "content": FINAL_INSTRUCTION,
            }
        )
        try:
            response = request(final=True)
        except Exception as exc:
            if not steps:
                raise
            log.warning(
                "agent final answer failed; preserving %d tool steps: %s", len(steps), redact_exception(exc)
            )
            return answer(INCOMPLETE_ANSWER)
        if getattr(response, "stop_reason", None) == "refusal":
            detail = getattr(getattr(response, "stop_details", None), "explanation", "")
            return answer(detail or "The model declined to answer this question.", declined=True)
        text = "".join(b.text for b in (response.content or []) if getattr(b, "type", None) == "text")
        return answer(text.strip() or "Gave up after too many tool calls without reaching an answer.")


def probe(
    provider: str,
    credentials: dict[str, str],
    options: dict[str, Any],
    model: str,
    trust: Trust | None = None,
) -> None:
    """One Messages request. Raises AgentError for a reply that is not a message."""
    adapter = AnthropicAdapter(provider, credentials, options, trust)
    client = adapter._client()
    reply = client.messages.create(
        model=model,
        max_tokens=1,
        messages=[{"role": "user", "content": "ok"}],
    )
    if getattr(reply, "type", None) != "message":
        raise AgentError("the provider reply is not a message")
