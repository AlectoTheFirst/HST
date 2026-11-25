"""Stored AI conversations and their turns.

A conversation belongs to the user who created it. Every route that names a
conversation, a message or a step answers 404 for an id of another user, as
for a missing one. A message starts a durable turn (`app/ai/turns.py`) that a
client polls through `GET /api/ai/messages/{id}` or follows as server-sent
events through `GET /api/ai/messages/{id}/events`. Both read the stored rows.
They work from any app process and after a restart.

The server builds the history that the provider receives (`app/ai/history.py`).
A message has no client history. A conversation takes at most
`MAX_CONVERSATION_MESSAGES` messages. The 40-turn and 40,000-character caps
of `POST /api/agent/ask` apply to that route only.

A turn of a conversation that follows the pointer reads the pointer once.
When that run differs from the run of the conversation's previous turn, the
poll result has `snapshot_changed: true`.

A finished answer stores its answer envelope (`app/ai/envelope.py`), which
the poll returns as `envelope`.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal, cast, get_args

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hst.app.agent import base as agent_base
from hst.app.agent import tools as tools_mod
from hst.app.agent.budget import AskBudget
from hst.app.ai import envelope as envelope_mod
from hst.app.ai import history, turns
from hst.app.ai import prompt as prompt_mod
from hst.app.ai.audit import AuditSink
from hst.app.ai.client import MAX_ASKS_PER_USER, MAX_QUEUED_ASKS, ModelClient, TurnRequest, _ask_gate
from hst.app.ai.context_resolver import PageContext, SnapshotRef, record_resolution
from hst.app.ai.redact import redact, redact_exception
from hst.app.ai.registry import Principal, Surface, ToolContext
from hst.app.auth import COOKIE, current_user, require_permission
from hst.app.routes import ai as ai_routes
from hst.app.store import (
    TURN_ACTIVE_STATES,
    AiConversation,
    AiEvent,
    AiMessage,
    AiStep,
    AiTurn,
    TurnCapExceeded,
    User,
    canonical_uuid,
)
from hst.core.snapshot import parse_snapshot_id

log = logging.getLogger("hst.ai")

router = APIRouter()
require_agent_ask = require_permission("agent.ask")  # B008 forbids this call in an argument default.

# A conversation holds at most this many messages, questions and answers
# together. A message that would pass it answers 409.
MAX_CONVERSATION_MESSAGES = 500
FULL_DETAIL = f"the conversation has reached {MAX_CONVERSATION_MESSAGES} messages; start a new conversation"
# The surfaces a client creates conversations on. The structured surfaces
# have their own routes.
ConversationSurface = Literal["drawer", "changesim", "assessment_qa"]
CONVERSATION_SURFACES: tuple[str, ...] = get_args(ConversationSurface)
# How often an event stream reads the rows of a running turn.
EVENTS_POLL_S = 0.5
# How often an open event stream checks the session again.
EVENTS_SESSION_CHECK_S = 5.0


class ConversationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    surface: ConversationSurface
    title: str = Field(default="", max_length=200)
    # The page that the conversation is opened from. Its references are stored as links.
    context: PageContext | None = None
    # A run id. Every turn of the conversation is pinned to it.
    pin: str | None = None

    @field_validator("pin")
    @classmethod
    def _run_id(cls, value: str | None) -> str | None:
        run = parse_snapshot_id(value)
        return None if run is None else str(run)


class MessageBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str
    context: PageContext | None = None
    include_context: bool = False


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _context_links(context: PageContext | None) -> list[tuple[str, str, int | None]]:
    """The `from` links of a conversation opened from `context`. Each object of
    the page context with a kind of `ai_links.kind` gives one link."""
    if context is None:
        return []
    links: list[tuple[str, str, int | None]] = []
    if context.snapshot is not None:
        links.append(("snapshot", context.snapshot.id, None))
    if context.simulation is not None:
        sim = context.simulation
        if sim.analysis_session_id:
            links.append(("analysis_session", sim.analysis_session_id, sim.analysis_session_revision))
        if sim.change_id is not None:
            links.append(("change", str(sim.change_id), None))
    if context.analysis_session is not None:
        links.append(("analysis_session", context.analysis_session.id, context.analysis_session.revision))
    if context.assessment is not None:
        a = context.assessment
        links.append(("assessment", a.assessment_id, a.revision))
        if a.run_id:
            links.append(("assessment_run", a.run_id, None))
        if a.finding_id:
            links.append(("finding", a.finding_id, None))
    if context.application is not None:
        links.append(("application", context.application.application_id, context.application.revision))
    return list(dict.fromkeys(links))


def _step_meta(step: AiStep) -> dict[str, Any]:
    return {
        "id": step.id,
        "step": f"s{step.label}",
        "tool": step.tool,
        "tool_version": step.tool_version,
        "arguments": step.arguments,
        "is_error": step.is_error,
        "result_chars": step.result_chars,
        "result_summary": step.result_summary,
        "compacted": step.result is None,
        "started_at": _iso(step.started_at),
        "elapsed_ms": step.elapsed_ms,
    }


def _message_json(message: AiMessage, steps: list[AiStep]) -> dict[str, Any]:
    return {
        "id": message.id,
        "seq": message.seq,
        "role": message.role,
        "status": message.status,
        "content": message.content,
        "context": message.context,
        "envelope": message.envelope,
        "error": message.error,
        "snapshot": message.snapshot_id,
        "created_at": _iso(message.created_at),
        "finished_at": _iso(message.finished_at),
        "steps": [_step_meta(s) for s in steps],
    }


def _conversation_json(conversation: AiConversation) -> dict[str, Any]:
    return {
        "id": conversation.id,
        "surface": conversation.surface,
        "title": conversation.title,
        "pin": conversation.snapshot_id,
        "pin_mode": conversation.pin_mode,
        "message_count": conversation.message_count,
        "created_at": _iso(conversation.created_at),
        "last_message_at": _iso(conversation.last_message_at),
    }


def _poll_status(message: AiMessage) -> tuple[str, str | None]:
    """The poll status in the vocabulary of the ask poll, and the detail of
    a turn that ended without an answer."""
    if message.status in TURN_ACTIVE_STATES:
        return "running", None
    if message.status == "done":
        return "done", None
    if message.status == "interrupted":
        return "error", ai_routes.INTERRUPTED_DETAIL
    if message.status == "cancelled":
        return "error", message.error or ai_routes.CANCELLED_DETAIL
    return "error", message.error


def _poll_step(step: AiStep) -> dict[str, Any]:
    """One step of the poll answer, with its result cut at
    MAX_STEP_RESULT_CHARS. After compaction the result is the summary."""
    return {
        "id": step.id,
        "step": f"s{step.label}",
        "name": step.tool,
        "arguments": step.arguments,
        "is_error": step.is_error,
        "result": (step.result if step.result is not None else step.result_summary or "")[
            : ai_routes.MAX_STEP_RESULT_CHARS
        ],
    }


def _turn_json(turn: AiTurn) -> dict[str, Any]:
    """The poll answer. It has the fields of `AgentAnswer` (web/src/api/types.ts),
    the turn's ids and states, and the answer envelope or None. `context` is the
    page context stored with the question."""
    message = turn.message
    payload = (message.envelope or {}).get("payload") or {}
    status, detail = _poll_status(message)
    result: dict[str, Any] = {
        "status": status,
        "state": message.status,
        "message_id": message.id,
        "conversation_id": message.conversation_id,
        "answer": message.content if status == "done" else "",
        "declined": bool(payload.get("declined", False)),
        "steps": [_poll_step(s) for s in turn.steps],
        "context": turn.question.context if turn.question is not None else None,
        "snapshot": message.snapshot_id,
        "snapshot_changed": bool(payload.get("snapshot_changed", False)),
        "context_entries": payload.get("context_entries", []),
        "page_context": payload.get("page_context"),
        "prompt_hash": payload.get("prompt_hash"),
        "envelope": envelope_mod.stored_answer(message.envelope),
    }
    if detail is not None:
        result["detail"] = detail
    return result


@router.post("/ai/conversations", status_code=201)
async def create_conversation(
    request: Request, body: ConversationBody, user: User = Depends(require_agent_ask)
) -> dict[str, Any]:
    store = request.app.state.store
    now = datetime.now(UTC)
    conversation = await store.create_conversation(
        user.id,
        body.surface,
        now,
        title=body.title.strip(),
        snapshot_id=body.pin,
        pin_mode="pinned" if body.pin is not None else "follow",
    )
    for kind, ref_id, revision in _context_links(body.context):
        await store.add_link(conversation.id, kind, ref_id, "from", now, ref_revision=revision)
    return _conversation_json(conversation)


@router.get("/ai/conversations")
async def list_conversations(
    request: Request,
    surface: str | None = Query(None, max_length=40),
    link_kind: str | None = Query(None, max_length=40),
    link_id: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(require_agent_ask),
) -> dict[str, Any]:
    rows = await request.app.state.store.list_conversations(
        user.id, surface=surface, link_kind=link_kind, link_id=link_id, limit=limit
    )
    # The title of a conversation without one is its first question. `last_run`
    # is the run of the newest answer that has a run.
    return {"conversations": [{**_conversation_json(c), "last_run": c.last_run} for c in rows]}


@router.get("/ai/conversations/{conversation_id}")
async def get_conversation(
    conversation_id: str, request: Request, user: User = Depends(current_user)
) -> dict[str, Any]:
    conversation = await request.app.state.store.get_conversation(user.id, conversation_id)
    if conversation is None:
        raise HTTPException(404, detail="no such conversation")
    steps: dict[str, list[AiStep]] = {}
    for step in conversation.steps:
        steps.setdefault(step.message_id, []).append(step)
    return {
        **_conversation_json(conversation),
        "messages": [_message_json(m, steps.get(m.id, [])) for m in conversation.messages],
        "links": [
            {
                "kind": link.kind,
                "ref_id": link.ref_id,
                "ref_revision": link.ref_revision,
                "direction": link.direction,
                "message_id": link.message_id,
                "step_id": link.step_id,
                "created_at": _iso(link.created_at),
            }
            for link in conversation.links
        ],
    }


@router.delete("/ai/conversations/{conversation_id}", status_code=204)
async def delete_conversation(
    conversation_id: str, request: Request, user: User = Depends(current_user)
) -> Response:
    store = request.app.state.store
    if not await store.delete_conversation(user.id, conversation_id):
        raise HTTPException(404, detail="no such conversation")
    try:
        await store.record_ai_event(
            AiEvent(
                at=datetime.now(UTC),
                origin="web",
                event="conversation.delete",
                outcome="ok",
                user_id=user.id,
                conversation_id=canonical_uuid(conversation_id),
            )
        )
    except Exception:
        log.warning("the conversation.delete event could not be recorded", exc_info=True)
    return Response(status_code=204)


def _requested_run(body: MessageBody, conversation: AiConversation) -> SnapshotRef | None:
    """The run that a turn is pinned to. The run of the page context comes first,
    then the pin of the conversation. With None, the turn reads the pointer."""
    if body.context is not None and body.context.snapshot is not None:
        return body.context.snapshot
    if conversation.pin_mode == "pinned" and conversation.snapshot_id:
        return SnapshotRef(id=conversation.snapshot_id, origin="pinned")
    return None


def _run_origin(body: MessageBody, conversation: AiConversation) -> envelope_mod.SnapshotOrigin:
    """The origin of the run of `_requested_run`, one of the page context, the
    conversation's pin and the pointer."""
    if body.context is not None and body.context.snapshot is not None:
        return "context"
    if conversation.pin_mode == "pinned" and conversation.snapshot_id:
        return "conversation"
    return "pointer"


def _previous_run(conversation: AiConversation) -> str | None:
    """The run of the latest turn of `conversation` that recorded one."""
    return next(
        (m.snapshot_id for m in reversed(conversation.messages) if m.role == "assistant" and m.snapshot_id),
        None,
    )


class _TurnStopped(Exception):
    """The turn was cancelled, or lost its lease, before its provider call."""


async def _record_rejected_context(
    store: Any,
    message_id: str,
    context: PageContext,
    refusal: HTTPException,
    *,
    user_id: int,
    conversation: AiConversation,
    snapshot: str | None,
) -> None:
    """Record the `context.resolve` event of a turn that the run check refused.
    The event has the outcome 'rejected', the run that the turn named and the
    HTTP status of the refusal. A failed write is logged."""
    try:
        await store.record_ai_event(
            AiEvent(
                at=datetime.now(UTC),
                origin="web",
                event="context.resolve",
                outcome="rejected",
                user_id=user_id,
                surface=conversation.surface,
                conversation_id=conversation.id,
                message_id=message_id,
                snapshot=snapshot,
                detail={"selection": len(context.selection), "status_code": refusal.status_code},
            )
        )
    except Exception:
        log.warning("the context.resolve event could not be recorded", exc_info=True)


@router.post("/ai/conversations/{conversation_id}/messages")
async def post_message(
    conversation_id: str, request: Request, body: MessageBody, user: User = Depends(require_agent_ask)
) -> JSONResponse:
    question = body.question.strip()
    if not question:
        raise HTTPException(400, detail="ask a question")
    if len(question) > ai_routes.MAX_QUESTION_CHARS:
        raise HTTPException(413, detail="question too long")

    app_settings = request.app.state.settings
    store = request.app.state.store
    conversation = await store.get_conversation(user.id, conversation_id)
    # a shim conversation and a draft conversation take no messages here
    if conversation is None or conversation.ephemeral or conversation.surface not in CONVERSATION_SURFACES:
        raise HTTPException(404, detail="no such conversation")
    if conversation.message_count + 2 > MAX_CONVERSATION_MESSAGES:
        raise HTTPException(409, detail=FULL_DETAIL)

    client = await ModelClient.from_store(store, app_settings)
    if not client.enabled():
        raise HTTPException(503, detail="the agent is turned off")
    if not client.configured():
        raise HTTPException(503, detail="the agent has no provider credentials configured")
    # The adapter is built before the turn starts. A provider that cannot be
    # built leaves no question and answer rows in the conversation.
    try:
        client.adapter()
    except agent_base.AgentError as exc:
        raise HTTPException(502, detail=str(exc)) from exc
    source_kinds = {row.name: row.type for row in await store.list_sources()}
    try:
        runner = await turns.TurnRunner.start(
            store,
            user.id,
            question,
            owner=turns.owner(request.app),
            surface=conversation.surface,
            conversation_id=conversation.id,
            per_user_cap=MAX_ASKS_PER_USER,
            global_cap=MAX_QUEUED_ASKS,
            tool_versions={spec.name: spec.version for spec in tools_mod.agent_registry().specs()},
        )
    except TurnCapExceeded as exc:
        raise HTTPException(429, detail=ai_routes._CAP_DETAIL[exc.scope]) from exc
    except LookupError as exc:
        raise HTTPException(404, detail="no such conversation") from exc

    try:
        requested = _requested_run(body, conversation)
        origin = _run_origin(body, conversation)
        try:
            turn_snapshot = await ai_routes._pin_turn(app_settings, requested)
        except HTTPException as exc:
            if body.context is not None:
                await _record_rejected_context(
                    store,
                    runner.id,
                    body.context,
                    exc,
                    user_id=user.id,
                    conversation=conversation,
                    snapshot=requested.id if requested is not None else None,
                )
            raise
        snapshot_id = turn_snapshot.snapshot_id if turn_snapshot is not None else None
        # The pointer moved since the previous turn. This turn reads the new run.
        previous = _previous_run(conversation)
        snapshot_changed = (
            requested is None and None not in (snapshot_id, previous) and snapshot_id != previous
        )
        audit = AuditSink(
            store,
            user_id=user.id,
            origin="web",
            surface=conversation.surface,
            provider=client.provider,
            model_requested=client.model,
            snapshot=snapshot_id,
        )
        principal = Principal.for_role(user.role, user_id=user.id)
        tool_context = ToolContext(
            settings=app_settings,
            principal=principal,
            surface=cast("Surface", conversation.surface),
            snapshot=turn_snapshot,
            source_kinds=source_kinds,
            cypher_log=audit.cypher,
            store=store,
            loop=asyncio.get_running_loop(),
        )
        available = tools_mod.offered_tools(tool_context)
    except BaseException:
        await runner.finish("error", error="the ask could not start")
        raise

    def on_step(step: tools_mod.ToolCall) -> None:
        step_id = str(uuid.uuid4())
        audit.on_step(step, step_id=step_id)
        provenance = tools_mod.step_provenance(step, turn_snapshot)
        tools_mod.frame_step(step, runner.on_step(step, step_id, provenance), turn_snapshot, provenance)

    async def run() -> None:
        context_task: asyncio.Task | None = None
        status, payload, error = "error", None, None
        answer: agent_base.AgentAnswer | None = None
        # The steps of the earlier turns that the model reads. A marker may cite them.
        earlier: list[AiStep] = []
        try:
            if body.include_context:
                context_task = ai_routes._start_context(request, question, tool_context)
            started = time.monotonic()
            page_context = await ai_routes._render_page_context(request, user, body.context, turn_snapshot)
            if body.context is not None:
                await record_resolution(
                    store,
                    runner.id,
                    body.context,
                    page_context,
                    user_id=user.id,
                    surface=conversation.surface,
                    conversation_id=conversation.id,
                    snapshot=snapshot_id,
                    latency_ms=int((time.monotonic() - started) * 1000),
                )
            assembled = prompt_mod.assemble(
                cast("prompt_mod.PromptSurface", conversation.surface),
                prompt_mod.SiteInstructions.from_config(client.config),
                available,
                principal,
                page_context,
            )
            await ai_routes._record_prompt(store, assembled)
            async with _ask_gate:
                window = history.window(conversation)
                earlier = [step for turn in window.turns for step in turn.steps]
                # The summary call can take SUMMARY_TIMEOUT_S before the budget
                # exists. A cancel is checked before and after it.
                if await runner.stop_requested():
                    raise _TurnStopped
                summary = await history.fold(
                    store, client, user.id, conversation, window.fold, message_id=runner.id
                )
                if await runner.stop_requested():
                    raise _TurnStopped
                budget = runner.attach(AskBudget(timeout=ai_routes.ASK_DEADLINE_S))
                try:
                    answer = await asyncio.wait_for(
                        asyncio.to_thread(
                            client.run,
                            TurnRequest(
                                question,
                                system=assembled.text,
                                tools=available,
                                messages=history.messages(window, question, summary),
                                budget=budget,
                                on_step=on_step,
                            ),
                        ),
                        timeout=ai_routes.ASK_DEADLINE_S,
                    )
                except TimeoutError:
                    if not budget.steps or runner.cancelled:
                        raise
                    answer = ai_routes.incomplete_answer(budget, client.provider)
                finally:
                    budget.stopped.set()
        except _TurnStopped:
            log.info("turn %s stopped before its provider call", runner.id)
        except TimeoutError:
            log.warning("turn %s exceeded %.0fs and was abandoned", runner.id, ai_routes.ASK_DEADLINE_S)
            error = f"the ask exceeded {ai_routes.ASK_DEADLINE_S:.0f} seconds and was abandoned"
        except agent_base.AgentError as exc:
            # The provider's text stays in the server log, as in routes/ai.py.
            log.warning(
                "turn %s failed: %s",
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
            log.error("turn %s crashed: %s", runner.id, redact_exception(exc))
            error = f"the ask failed (ask {runner.id}); see the server log"
        else:
            status = "done"
            payload = {
                "declined": answer.declined,
                "context_entries": await ai_routes._collect_context(context_task),
                "page_context": page_context,
                "snapshot": snapshot_id,
                "snapshot_changed": snapshot_changed,
                "prompt_hash": assembled.static_hash,
            }
        finally:
            await audit.close()
        if runner.cancelled:
            status, payload, error = "cancelled", None, ai_routes.CANCELLED_DETAIL
        envelope = None
        if payload is not None and answer is not None:
            envelope = await envelope_mod.for_turn(
                runner,
                answer,
                snapshot=snapshot_id,
                origin=origin,
                provider=client.provider,
                model_requested=client.model,
                prompt_hash=str(payload["prompt_hash"]),
                earlier=earlier,
            )
        await runner.finish(
            status,
            content=answer.answer if payload is not None and answer is not None else "",
            payload=payload,
            envelope=envelope,
            error=error,
            snapshot_id=snapshot_id,
            provider=answer.provider if answer is not None else client.provider,
            model_requested=client.model,
            model_served=answer.model_served if answer is not None else None,
            usage=ai_routes._usage(answer),
        )

    task = asyncio.get_running_loop().create_task(run())
    request.app.state.ask_tasks = getattr(request.app.state, "ask_tasks", set())
    request.app.state.ask_tasks.add(task)
    task.add_done_callback(request.app.state.ask_tasks.discard)
    return JSONResponse({"message_id": runner.id}, status_code=202)


@router.get("/ai/messages/{message_id}")
async def get_message(
    message_id: str, request: Request, user: User = Depends(current_user)
) -> dict[str, Any]:
    turn = await request.app.state.store.get_turn(user.id, message_id)
    if turn is None:
        raise HTTPException(404, detail="no such message")
    return _turn_json(turn)


def _last_label(last_event_id: str | None) -> int:
    """The step label of the last event a reconnecting client received, 0
    when it sent none."""
    value = (last_event_id or "").strip()
    return int(value) if value.isascii() and value.isdecimal() else 0


async def turn_events(
    store: Any,
    user_id: int,
    turn: AiTurn,
    after: int = 0,
    *,
    authorized: Callable[[], Awaitable[bool]] | None = None,
) -> AsyncIterator[ServerSentEvent]:
    """The events of one turn, read from its stored rows.

    Every step with a label above `after` is one `step` event whose id is the
    label and whose data is the step of the poll answer. When the turn has
    ended, one `turn` event holds the poll answer and the stream closes. The
    `turn` event has no id. The last event id stays the label of the last
    step. While the turn runs, its status and its new steps are read again
    every EVENTS_POLL_S. Another process can run the turn.
    The stream closes without a `turn` event when the conversation is
    deleted, or when `authorized`, awaited every EVENTS_SESSION_CHECK_S,
    answers False.
    """
    message_id = turn.message.id
    status, steps = turn.message.status, turn.steps
    # The full turn for the `turn` event. It is None after a progress read.
    whole: AiTurn | None = turn
    loop = asyncio.get_running_loop()
    checked = loop.time()
    while True:
        for step in steps:
            if step.label > after:
                after = step.label
                yield ServerSentEvent(event="step", id=str(step.label), data=_poll_step(step))
        if status not in TURN_ACTIVE_STATES:
            if whole is None:
                whole = await store.get_turn(user_id, message_id)
                if whole is None:
                    return
            yield ServerSentEvent(event="turn", data=_turn_json(whole))
            return
        await asyncio.sleep(EVENTS_POLL_S)
        if authorized is not None and loop.time() - checked >= EVENTS_SESSION_CHECK_S:
            if not await authorized():
                return
            checked = loop.time()
        progress = await store.get_turn_progress(user_id, message_id, after)
        if progress is None:
            return
        status, steps, whole = progress.status, progress.steps, None


async def _owned_turn(message_id: str, request: Request, user: User = Depends(current_user)) -> AiTurn:
    turn = await request.app.state.store.get_turn(user.id, message_id)
    if turn is None:
        raise HTTPException(404, detail="no such message")
    return turn


@router.get("/ai/messages/{message_id}/events", response_class=EventSourceResponse)
async def message_events(
    request: Request,
    turn: AiTurn = Depends(_owned_turn),
    user: User = Depends(current_user),
    last_event_id: str | None = Header(None, max_length=20),
) -> AsyncIterator[ServerSentEvent]:
    """The turn as server-sent events (`turn_events`). A reconnect that sends
    `Last-Event-ID` receives the steps after that label. The session is
    checked again while the stream is open, as each poll request checks it,
    and the stream closes after a logout, a session expiry or a disabled
    account."""

    async def authorized() -> bool:
        try:
            current = await current_user(request, request.cookies.get(COOKIE))
        except HTTPException:
            return False
        return current.id == user.id

    async for event in turn_events(
        request.app.state.store, user.id, turn, _last_label(last_event_id), authorized=authorized
    ):
        yield event


@router.post("/ai/messages/{message_id}/cancel")
async def cancel_message(
    message_id: str, request: Request, user: User = Depends(current_user)
) -> dict[str, Any]:
    store = request.app.state.store
    message = await store.get_message(user.id, message_id)
    if message is None or message.role != "assistant":
        raise HTTPException(404, detail="no such message")
    return {"cancel_requested": await store.request_cancel(user.id, message_id)}


@router.get("/ai/steps/{step_id}")
async def get_step(step_id: str, request: Request, user: User = Depends(current_user)) -> dict[str, Any]:
    """The full result of one step, or its summary once compaction removed it."""
    step = await request.app.state.store.get_step(user.id, step_id)
    if step is None:
        raise HTTPException(404, detail="no such step")
    return {
        **_step_meta(step),
        "message_id": step.message_id,
        "conversation_id": step.conversation_id,
        "result": step.result,
    }
