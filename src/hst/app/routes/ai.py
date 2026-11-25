"""The provider settings (admin) and the ask endpoint (viewer+) of the Ask-AI agent."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from hst.app import crypto, tls
from hst.app.agent import base as agent_base
from hst.app.agent import context as agent_context
from hst.app.agent import registry
from hst.app.agent import tools as tools_mod
from hst.app.agent.budget import ASK_TIMEOUT_S, INCOMPLETE_ANSWER, AskBudget
from hst.app.agent.openrouter import BASE_URL as OPENROUTER_BASE_URL
from hst.app.ai import envelope as envelope_mod
from hst.app.ai import prompt as prompt_mod
from hst.app.ai import turns
from hst.app.ai.audit import AuditSink
from hst.app.ai.client import (
    MAX_ASKS_PER_USER,
    MAX_CONCURRENT_ASKS,
    MAX_QUEUED_ASKS,
    ModelClient,
    TurnRequest,
    _ask_gate,
    _load,
    decode_settings,
)
from hst.app.ai.context_resolver import ContextResolver, PageContext, SnapshotRef
from hst.app.ai.redact import redact, redact_exception
from hst.app.ai.registry import Principal, ToolContext
from hst.app.auth import current_user, require_permission
from hst.app.crypto import encrypt_secrets
from hst.app.permissions import permissions_for
from hst.app.store import AppSetting, TurnCapExceeded, User
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod

log = logging.getLogger("hst.ai")

# app/ai/client.py defines the ask queue and the settings read. This module
# exports their names.
__all__ = [
    "MAX_ASKS_PER_USER",
    "MAX_CONCURRENT_ASKS",
    "MAX_QUEUED_ASKS",
    "_ask_gate",
    "_load",
    "router",
]

router = APIRouter()
require_agent_ask = require_permission("agent.ask")  # B008 forbids this call in an argument default.

MAX_QUESTION_CHARS = 4000

# The maximum count of characters of one tool step result that the client receives.
MAX_STEP_RESULT_CHARS = 200_000

# These caps bound provider spend per request.
MAX_HISTORY_TURNS = 40
MAX_HISTORY_CHARS = 40_000

# The adapters reserve part of this deadline for their final answer.
ASK_DEADLINE_S = ASK_TIMEOUT_S
# The poll detail of an ask whose process stopped before it finished, and of
# one that was cancelled.
INTERRUPTED_DETAIL = "the ask was interrupted because the server process running it stopped; ask again"
CANCELLED_DETAIL = "the ask was cancelled before it finished"
# The 429 details, by the cap that refused the ask.
_CAP_DETAIL = {
    "user": "too many questions of this user in progress",
    "global": "the agent is busy; try again in a moment",
}
# After this count of seconds, the job reports the answer without the context.
CONTEXT_DEADLINE_S = 30.0
# The maximum length of each exception text in the `error` of a failed provider test.
MAX_PROBE_ERROR_CHARS = 2000
# The 400 detail of a save or a test that would send a stored credential to an
# endpoint other than the stored one. The credential names follow it.
OTHER_ENDPOINT_DETAIL = "credentials required for an endpoint other than the stored one: "
# The 400 detail of a save or a test that would send a stored credential under
# a TLS check weaker than the stored one. The credential names follow it.
WEAKER_TLS_DETAIL = "credentials required for a TLS check weaker than the stored one: "


class AiSettingsBody(BaseModel):
    enabled: bool
    provider: str
    model: str
    effort: str = "high"
    # The site instructions. In `replace` mode, the text is the whole prompt of
    # the conversational surfaces. A save without a mode stores `append`.
    system_prompt: str = ""
    prompt_mode: Literal["append", "replace"] = "append"
    # A null value deletes the stored secret. A blank string keeps it.
    credentials: dict[str, str | None] | None = None
    options: dict[str, str] | None = None


class AiTestBody(BaseModel):
    """Overrides for one probe."""

    provider: str | None = None
    model: str | None = None
    effort: str | None = None
    options: dict[str, str] | None = None
    # A blank or absent value falls back to the stored one. A null leaves the
    # stored one out of the probe.
    secrets: dict[str, str | None] | None = None


class HistoryTurn(BaseModel):
    """One prior text turn."""

    role: Literal["user", "assistant"]
    content: str


class AskBody(BaseModel):
    question: str
    # The prior turns of this conversation, oldest first. The client holds the history.
    history: list[HistoryTurn] = []
    # The change-simulation workspace asks for the entity context beside the answer.
    include_context: bool = False
    # The page that the question is asked from (strata/ai/page-context/v1). Each
    # reference in it is checked before the model reads it.
    context: PageContext | None = None


def _public(settings: dict[str, Any], secrets: dict[str, str], updated_at: Any = None) -> dict[str, Any]:
    return {
        "enabled": settings["enabled"],
        "provider": settings["provider"],
        "model": settings["model"],
        "effort": settings["effort"],
        "system_prompt": settings["site_instructions"],
        "prompt_mode": settings["prompt_mode"],
        "options": settings.get("options", {}),
        # Only the names of the stored credentials are returned.
        "stored_credentials": sorted(k for k, v in secrets.items() if v),
        "configured": registry.is_configured(settings, secrets),
        "updated_at": updated_at,
    }


def _endpoint(settings: Mapping[str, Any]) -> tuple[str, ...]:
    """The provider and the option values that select the host of its calls."""
    provider = str(settings["provider"])
    options = settings.get("options") or {}
    if provider == "openrouter":
        return (provider, options.get("base_url") or OPENROUTER_BASE_URL)
    if provider == "bedrock":
        return (provider, options.get("base_url") or "", options.get("aws_region") or "")
    return (provider,)


def _require_own_credentials(
    stored: Mapping[str, Any],
    settings: Mapping[str, Any],
    stored_secrets: Mapping[str, str],
    given: Mapping[str, str | None],
) -> None:
    """Raise a 400 when `given` leaves a stored credential of the provider in
    use, and `settings` select an endpoint other than the endpoint of `stored`
    or a TLS check weaker than the check of `stored`.

    `given` replaces a stored credential with a value and deletes it with a null.
    """
    if _endpoint(settings) != _endpoint(stored):
        detail = OTHER_ENDPOINT_DETAIL
    elif tls.weakens(stored.get("options") or {}, settings.get("options") or {}):
        detail = WEAKER_TLS_DETAIL
    else:
        return
    kept = [
        field.name
        for field in registry.BY_ID[settings["provider"]].credentials
        if stored_secrets.get(field.name) and given.get(field.name, "") == ""
    ]
    if kept:
        raise HTTPException(400, detail=detail + ", ".join(kept))


def _error_text(exc: BaseException) -> str:
    status = getattr(exc, "status_code", None)
    request_ = getattr(exc, "request", None)
    text = redact(f"{type(exc).__name__}: {exc}")[:MAX_PROBE_ERROR_CHARS]
    if status is None or request_ is None:
        return text
    origin = f"HTTP {status} from {request_.url.host}"
    # The SDKs hold a reply that is not JSON as text in `body`.
    body = getattr(exc, "body", None)
    if isinstance(body, dict | list):
        return f"{text} ({origin})"
    return f"{origin}: the reply is not JSON" if isinstance(body, str) and body else origin


@router.get("/settings/ai/providers", dependencies=[Depends(require_permission("settings.ai"))])
def get_providers() -> dict[str, Any]:
    return registry.descriptors()


@router.get("/settings/ai", dependencies=[Depends(require_permission("settings.ai"))])
async def get_ai_settings(request: Request) -> dict[str, Any]:
    settings, secrets, updated_at, unreadable = await _load(request)
    payload = _public(settings, secrets, updated_at)
    if unreadable:
        payload["secrets_unreadable"] = True
    return payload


@router.put("/settings/ai", dependencies=[Depends(require_permission("settings.ai"))])
async def put_ai_settings(request: Request, body: AiSettingsBody) -> dict[str, Any]:
    if body.provider not in registry.BY_ID:
        raise HTTPException(400, detail=f"unknown provider: {body.provider}")
    try:
        registry.validate_options(body.provider, body.options or {})
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc

    key = crypto.dek(request.app.state.settings)
    secrets: dict[str, str] = {}

    def change(row: AppSetting | None) -> tuple[dict, bytes]:
        stored, stored_secrets, _, unreadable = decode_settings(row, key)
        _require_own_credentials(
            stored,
            {"provider": body.provider, "options": body.options or {}},
            stored_secrets,
            body.credentials or {},
        )
        # A blank field keeps the stored value. A null deletes it.
        secrets.update(stored_secrets)
        for name, given in (body.credentials or {}).items():
            if given is None:
                secrets.pop(name, None)
            elif given:
                secrets[name] = given
        try:
            registry.validate_endpoint(body.provider, secrets, body.options or {})
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc)) from exc

        if unreadable:
            missing = [name for name in registry.required_credentials(body.provider) if not secrets.get(name)]
            if missing:
                raise HTTPException(
                    422,
                    detail="stored credentials cannot be decrypted; missing secret fields: "
                    + ", ".join(sorted(missing)),
                )
        return value, encrypt_secrets(key, secrets)

    value = {
        "enabled": body.enabled,
        "provider": body.provider,
        "model": body.model,
        "effort": body.effort,
        # registry.merged() resolves the default at read time
        "system_prompt": "" if registry._is_default_prompt(body.system_prompt) else body.system_prompt,
        "prompt_mode": body.prompt_mode,
        "options": body.options or {},
    }
    row = await request.app.state.store.modify_setting(registry.SETTINGS_KEY, change)
    return _public(registry.merged(value), secrets, row.updated_at)


@router.post("/settings/ai/test", dependencies=[Depends(require_permission("settings.ai"))])
async def test_ai_settings(request: Request, body: AiTestBody | None = None) -> dict[str, Any]:
    settings, secrets, _, _ = await _load(request)
    stored = dict(settings)
    if body is not None:
        if body.provider is not None:
            if body.provider not in registry.BY_ID:
                raise HTTPException(400, detail=f"unknown provider: {body.provider}")
            settings["provider"] = body.provider
        if body.model is not None:
            settings["model"] = body.model
        if body.effort is not None:
            settings["effort"] = body.effort
        if body.options is not None:
            # the probe sends the API key to the base_url
            try:
                registry.validate_options(settings["provider"], body.options)
            except ValueError as exc:
                raise HTTPException(400, detail=str(exc)) from exc
            settings["options"] = body.options
        _require_own_credentials(stored, settings, secrets, body.secrets or {})
        for name, given in (body.secrets or {}).items():
            if given is None:
                secrets.pop(name, None)
            elif given:
                secrets[name] = given
    try:
        registry.validate_endpoint(settings["provider"], secrets, settings.get("options") or {})
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    result = {"ok": False, "provider": settings["provider"], "model": settings["model"]}
    if not registry.is_configured(settings, secrets):
        if settings["provider"] == "bedrock":
            return {
                **result,
                "error": "an AWS region is required to test Bedrock",
            }
        missing = [n for n in registry.required_credentials(settings["provider"]) if not secrets.get(n)]
        return {**result, "error": f"missing credentials: {', '.join(missing)}"}
    trust = tls.resolve(request.app.state.settings, settings.get("options", {}))
    try:
        await asyncio.to_thread(_probe, settings, secrets, trust)
    except Exception as exc:
        log.warning("AI provider test failed (%s): %s", settings["provider"], redact_exception(exc))
        message = _error_text(exc)
        # The reason (TLS, DNS, proxy) of a transport failure is on the cause.
        cause = exc.__cause__ or exc.__context__
        if cause is not None and getattr(exc, "status_code", None) is None:
            message += f" ({_error_text(cause)})"
        return {**result, "error": message}
    return {**result, "ok": True}


@router.get("/settings/ai/events", dependencies=[Depends(require_permission("settings.ai"))])
async def list_ai_events(
    request: Request,
    limit: int = Query(200, ge=1, le=1000),
    days: int = Query(30, ge=1, le=366),
) -> dict[str, Any]:
    """The newest AI events, and the tokens per user per UTC day over the last
    `days` days, today included. An event has no question, answer, argument
    or result text."""
    store = request.app.state.store
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    events = await store.list_ai_events(limit=limit)
    usage = await store.ai_token_usage(today - timedelta(days=days - 1))
    names = {u.id: u.username for u in await store.list_users()}
    return {
        "events": [{**asdict(e), "at": e.at.isoformat(), "username": names.get(e.user_id)} for e in events],
        "daily_tokens": [
            {
                "day": u.day.isoformat(),
                "user_id": u.user_id,
                "username": names.get(u.user_id),
                "tokens_in": u.tokens_in,
                "tokens_out": u.tokens_out,
            }
            for u in usage
        ],
    }


def _probe(settings: dict[str, Any], secrets: dict[str, str], trust: tls.Trust) -> None:
    ModelClient(settings, secrets, trust).probe()


def _start_context(request: Request, question: str, ctx: ToolContext) -> asyncio.Task:
    """Begin reading the question's entity context on a worker thread.

    `ctx` is the context of the turn's tool calls. The reads pass the permission
    check of the model's tool calls and read the run that the turn is pinned to.
    A caller without `graph.read` gets an empty list.
    """
    task = asyncio.get_running_loop().create_task(asyncio.to_thread(agent_context.build, ctx, question))
    request.app.state.ask_tasks = getattr(request.app.state, "ask_tasks", set())
    request.app.state.ask_tasks.add(task)
    task.add_done_callback(request.app.state.ask_tasks.discard)
    return task


async def _collect_context(task: asyncio.Task | None) -> list[dict[str, Any]]:
    """The context reads' result, or an empty list."""
    if task is None:
        return []
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=CONTEXT_DEADLINE_S)
    except TimeoutError:
        log.warning("question context exceeded %.0fs; answering without it", CONTEXT_DEADLINE_S)
    except Exception:
        log.warning("question context could not be collected", exc_info=True)
    return []


class _UnknownRun(Exception):
    """The run a page context names has no retained graph."""


def _pin(settings: Any, cts: int | None) -> snapshotmod.Snapshot:
    with dbmod.session(settings, access_mode="READ") as session:
        if cts is not None:
            try:
                snapshotmod.require_retained(session, cts)
            except ValueError as exc:
                raise _UnknownRun(str(exc)) from exc
        return snapshotmod.resolve(session, settings, cts)


async def _pin_turn(settings: Any, requested: SnapshotRef | None) -> snapshotmod.Snapshot | None:
    """The snapshot that a tool call of one ask reads when the call names no run, resolved once per ask.

    A run the page context names must have a retained graph, or the ask
    answers 404 before a job starts. With no run named, the pointer is read
    once. When that read fails, the ask runs unpinned. Each tool call then
    resolves the pointer, as a call without a turn snapshot does.
    """
    cts = int(requested.id) if requested is not None else None
    try:
        return await asyncio.to_thread(_pin, settings, cts)
    except _UnknownRun as exc:
        raise HTTPException(404, detail=str(exc)) from exc
    except Exception as exc:
        if cts is not None:
            log.warning("the snapshot an ask names could not be checked", exc_info=True)
            raise HTTPException(
                503, detail=f"snapshot {cts} could not be checked; the graph did not answer"
            ) from exc
        log.warning("the cycle pointer could not be read; the ask runs unpinned", exc_info=True)
        return None


def _inventory_repository(app: Any) -> Any:
    # The import is deferred. Only an ask whose context names an inventory device reads the repository.
    from hst.app.inventory.observations import context_for

    return context_for(app).repo


async def _record_prompt(store: Any, assembled: prompt_mod.AssembledPrompt) -> None:
    """Store the system text under its hash in `ai_prompt_versions`. A failed
    write is logged and the ask goes on."""
    try:
        await store.put_prompt_version(assembled.static_hash, assembled.system, datetime.now(UTC))
    except Exception:
        log.warning("the prompt version could not be recorded", exc_info=True)


async def _render_page_context(
    request: Request, user: User, context: PageContext | None, snapshot: snapshotmod.Snapshot | None
) -> str | None:
    """The checked `<page_context>` block for the system prompt, or None when
    the ask has no context or the block could not be built."""
    if context is None:
        return None
    resolver = ContextResolver(
        request.app.state.settings,
        request.app.state.store,
        permissions_for(user.role),
        inventory=lambda: _inventory_repository(request.app),
        user_id=user.id,
    )
    try:
        return await resolver.render(context, snapshot)
    except Exception:
        log.warning("the page context could not be rendered", exc_info=True)
        return None


@router.post("/agent/ask")
async def ask(request: Request, body: AskBody, user: User = Depends(require_agent_ask)) -> JSONResponse:
    question = body.question.strip()
    if not question:
        raise HTTPException(400, detail="ask a question")
    if len(question) > MAX_QUESTION_CHARS:
        raise HTTPException(413, detail="question too long")
    if len(body.history) > MAX_HISTORY_TURNS or sum(len(t.content) for t in body.history) > MAX_HISTORY_CHARS:
        raise HTTPException(413, detail="conversation too long; start a new chat")

    app_settings = request.app.state.settings
    store = request.app.state.store
    client = await ModelClient.from_store(store, app_settings)
    if not client.enabled():
        raise HTTPException(503, detail="the agent is turned off")
    if not client.configured():
        raise HTTPException(503, detail="the agent has no provider credentials configured")

    # A map from source name to collector kind (`name` to `type` of
    # hst.app.store.Source). The collected-evidence check of interface.set_mtu in
    # change_simulate reads it (fw_overlay._validate_interface_set_mtu). `_sources`
    # on a Device holds the configured row name.
    source_kinds = {row.name: row.type for row in await store.list_sources()}
    # The caps are checked before the pin. A rejected ask reads no graph.
    # start_turn counts both caps under the per-user lock and inserts the rows.
    # The claim follows at once.
    try:
        runner = await turns.TurnRunner.start(
            store,
            user.id,
            question,
            owner=turns.owner(request.app),
            surface="drawer",
            per_user_cap=MAX_ASKS_PER_USER,
            global_cap=MAX_QUEUED_ASKS,
            tool_versions={spec.name: spec.version for spec in tools_mod.agent_registry().specs()},
        )
    except TurnCapExceeded as exc:
        raise HTTPException(429, detail=_CAP_DETAIL[exc.scope]) from exc
    try:
        turn_snapshot = await _pin_turn(
            app_settings, body.context.snapshot if body.context is not None else None
        )
        snapshot_id = turn_snapshot.snapshot_id if turn_snapshot is not None else None
        # The Cypher calls of the agent are written to the trail of POST /api/cypher.
        # Each tool call is written to ai_events when the call returns.
        audit = AuditSink(
            store,
            user_id=user.id,
            origin="web",
            provider=client.provider,
            model_requested=client.model,
            snapshot=snapshot_id,
        )
        # The tools are filtered by permission. A viewer is not offered query_cypher.
        principal = Principal.for_role(user.role, user_id=user.id)
        tool_context = ToolContext(
            settings=app_settings,
            principal=principal,
            surface="drawer",
            snapshot=turn_snapshot,
            source_kinds=source_kinds,
            cypher_log=audit.cypher,
            store=store,
            loop=asyncio.get_running_loop(),
        )
        available = tools_mod.offered_tools(tool_context)

        try:
            client.adapter()
        except agent_base.AgentError as exc:
            raise HTTPException(502, detail=str(exc)) from exc
    except BaseException:
        # a turn that does not start gives its slot back at once
        await runner.finish("error", error="the ask could not start")
        raise

    def on_step(step: tools_mod.ToolCall) -> None:
        # The ai_steps row and the audit rows of the step share one id.
        step_id = str(uuid.uuid4())
        audit.on_step(step, step_id=step_id)
        provenance = tools_mod.step_provenance(step, turn_snapshot)
        tools_mod.frame_step(step, runner.on_step(step, step_id, provenance), turn_snapshot, provenance)

    async def run() -> None:
        context_task: asyncio.Task | None = None
        status, result, error = "error", None, None
        answer: agent_base.AgentAnswer | None = None
        try:
            # The context read starts before the provider call and is collected after it.
            if body.include_context:
                context_task = _start_context(request, question, tool_context)
            page_context = await _render_page_context(request, user, body.context, turn_snapshot)
            assembled = prompt_mod.assemble(
                "drawer",
                prompt_mod.SiteInstructions.from_config(client.config),
                available,
                principal,
                page_context,
            )
            await _record_prompt(store, assembled)
            # adapter.ask blocks for up to MAX_TURNS provider round-trips plus
            # their tool calls against the sync Neo4j driver
            async with _ask_gate:
                budget = AskBudget(timeout=ASK_DEADLINE_S)
                runner.attach(budget)
                try:
                    answer = await asyncio.wait_for(
                        asyncio.to_thread(
                            client.run,
                            TurnRequest(
                                question,
                                system=assembled.text,
                                tools=available,
                                history=[t.model_dump() for t in body.history],
                                budget=budget,
                                on_step=on_step,
                            ),
                        ),
                        timeout=ASK_DEADLINE_S,
                    )
                except TimeoutError:
                    log.warning(
                        "ask %s timed out during %s (%d steps)", runner.id, budget.phase, len(budget.steps)
                    )
                    if not budget.steps or runner.cancelled:
                        raise
                    answer = incomplete_answer(budget, client.provider)
                finally:
                    budget.stopped.set()
        except TimeoutError:
            log.warning("ask %s exceeded %.0fs and was abandoned", runner.id, ASK_DEADLINE_S)
            error = f"the ask exceeded {ASK_DEADLINE_S:.0f} seconds and was abandoned"
        except agent_base.AgentError as exc:
            # The reason stays in the server log.
            log.warning(
                "ask %s failed: %s",
                runner.id,
                redact(str(exc)),
                extra={
                    "provider": client.provider,
                    "model_requested": client.model,
                    "outcome": "error",
                    "error_class": type(exc.__cause__ or exc).__name__,
                },
            )
            error = f"the provider call failed (ask {runner.id}); see the server log"
        except Exception as exc:
            log.error("ask %s crashed: %s", runner.id, redact_exception(exc))
            error = f"the ask failed (ask {runner.id}); see the server log"
        else:
            # The context is collected before the job is marked done.
            context = await _collect_context(context_task)
            log.info(
                "ask %s answered after %d provider rounds",
                runner.id,
                len(answer.rounds),
                extra={
                    "provider": answer.provider,
                    "model_requested": client.model,
                    "model_served": answer.model_served,
                    "tokens_in": answer.usage.input_tokens,
                    "tokens_out": answer.usage.output_tokens,
                    "outcome": "refused" if answer.declined else "ok",
                    "snapshot": snapshot_id,
                },
            )
            status = "done"
            result = {
                "answer": answer.answer,
                "declined": answer.declined,
                "steps": [
                    {
                        "name": s.name,
                        "arguments": s.arguments,
                        "is_error": s.is_error,
                        # The raw payload can be large. The UI shows it on demand.
                        "result": (s.ui_result if s.ui_result is not None else tools_mod.unframe(s.result))[
                            :MAX_STEP_RESULT_CHARS
                        ],
                    }
                    for s in answer.steps
                ],
                "context": context,
                "page_context": page_context,
                "snapshot": snapshot_id,
                "prompt_hash": assembled.static_hash,
            }
        finally:
            await audit.close()
        if runner.cancelled:
            status, result, error = "cancelled", None, CANCELLED_DETAIL
        envelope = None
        if result is not None and answer is not None:
            named = body.context is not None and body.context.snapshot is not None
            # The client holds the history of this route as text. A marker
            # cannot cite a step of an earlier turn.
            envelope = await envelope_mod.for_turn(
                runner,
                answer,
                snapshot=snapshot_id,
                origin="context" if named else "pointer",
                provider=client.provider,
                model_requested=client.model,
                prompt_hash=str(result["prompt_hash"]),
            )
        await runner.finish(
            status,
            content=answer.answer if result is not None and answer is not None else "",
            payload=result,
            envelope=envelope,
            error=error,
            snapshot_id=snapshot_id,
            provider=answer.provider if answer is not None else client.provider,
            model_requested=client.model,
            model_served=answer.model_served if answer is not None else None,
            usage=_usage(answer),
        )

    # The app's task set holds the task. asyncio holds only a weak reference to a task.
    job_task = asyncio.get_running_loop().create_task(run())
    request.app.state.ask_tasks = getattr(request.app.state, "ask_tasks", set())
    request.app.state.ask_tasks.add(job_task)
    job_task.add_done_callback(request.app.state.ask_tasks.discard)

    return JSONResponse({"job_id": runner.id}, status_code=202)


def incomplete_answer(budget: AskBudget, provider: str) -> agent_base.AgentAnswer:
    """The answer of a turn abandoned at its deadline after some tool steps.
    It holds the steps, the tokens and the provider rounds of the budget."""
    return agent_base.AgentAnswer(
        answer=INCOMPLETE_ANSWER,
        steps=list(budget.steps),
        usage=budget.usage,
        provider=provider,
        rounds=list(budget.rounds),
    )


def _usage(answer: agent_base.AgentAnswer | None) -> dict[str, Any] | None:
    """The `ai_messages.usage` of a finished turn."""
    if answer is None:
        return None
    return {
        "input_tokens": answer.usage.input_tokens,
        "output_tokens": answer.usage.output_tokens,
        "rounds": list(answer.rounds),
    }


@router.get("/agent/ask/{job_id}")
async def ask_status(job_id: str, request: Request, user: User = Depends(current_user)) -> dict[str, Any]:
    # a foreign turn, and a turn of another surface, answer like a missing one
    message = await request.app.state.store.get_message(user.id, job_id, surface="drawer")
    if message is None or message.role != "assistant":
        raise HTTPException(404, detail="no such ask")
    return turns.poll_result(message, INTERRUPTED_DETAIL)
