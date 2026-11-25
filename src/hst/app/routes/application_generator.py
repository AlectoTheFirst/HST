"""Business Application generation.

`POST /api/business-applications/generations` starts a generation from a
description at a pinned snapshot. With `application_id` and `base_revision`
it starts an edit of that saved revision. The description is the change, and
the model also receives the canonical export of the revision. The `source` of
the record names the base revision and its digest. A commit of the edit must
state both. `POST /api/ai/service-drafts` starts one
from user messages of the caller's stored conversation. A generation runs as
a durable turn (`app/ai/turns.py`) in a `service_generator` conversation. It
takes no site instructions and is offered the generator's tools, each bound
to the snapshot (`generator.generator_registry`).

The finished generation is stored as an `application-generation` record.
`GET /api/business-applications/generations/{id}` answers the record to its
owner only, and answers any other user as for a missing id. While the turn
runs, or when it failed, the same route answers the turn's poll result.

The result holds the post-processed YAML, the generation report and the
result of `POST /api/business-applications/validate` for that YAML at the
snapshot. Where that route answers 422, the result holds the message as an
error on `$`. The import preview is included only for a caller who holds
changes.write, and only such a caller's validation is recorded as an
`application-validation` record that a commit can name.

The routes are registered before the `{application_id}` routes, and
`generations` is a reserved application id.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from hst import path as pathmod
from hst.app.agent import base as agent_base
from hst.app.agent import tools as tools_mod
from hst.app.agent.budget import ASK_TIMEOUT_S, AskBudget
from hst.app.ai import turns
from hst.app.ai.audit import AuditSink
from hst.app.ai.client import MAX_ASKS_PER_USER, MAX_QUEUED_ASKS, ModelClient, TurnRequest, _ask_gate
from hst.app.ai.redact import redact
from hst.app.ai.registry import Principal, ToolContext
from hst.app.auth import require_permission
from hst.app.permissions import permissions_for
from hst.app.routes import ai as ai_routes
from hst.app.store import TurnCapExceeded, User, canonical_uuid
from hst.applications import generator
from hst.applications import service as application_service
from hst.applications.models import BusinessApplicationDefinition, Identifier, stored_definition
from hst.applications.validation import record_validation, validate_application
from hst.applications.yaml_format import normalized_document
from hst.assessment import service as assessment_service
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod

log = logging.getLogger("hst.ai")

router = APIRouter(dependencies=[Depends(require_permission("graph.read"))])
require_ask = require_permission("agent.ask")  # B008 forbids this call in an argument default.

MAX_DESCRIPTION_CHARS = 4000
MAX_SOURCE_MESSAGES = 20
# The maximum count of characters of the export that an edit sends to the model.
# It equals the bound of the model copy of a tool result (`MAX_RESULT_CHARS`).
MAX_EDIT_EXPORT_CHARS = 100_000
GENERATION_DEADLINE_S = ASK_TIMEOUT_S

UNAVAILABLE_DETAIL = "AI generation is unavailable: the agent is turned off or has no provider credentials"
INTERRUPTED_DETAIL = (
    "the generation was interrupted because the server process running it stopped; start it again"
)
CANCELLED_DETAIL = "the generation was cancelled before it finished"
DECLINED_DETAIL = "the model declined to write the application"
# The 429 details, by the cap that refused the generation.
_CAP_DETAIL = {
    "user": "too many AI requests of this user in progress",
    "global": "the agent is busy; try again in a moment",
}

SnapshotId = Annotated[str, Field(min_length=1, max_length=20)]
MessageId = Annotated[str, Field(min_length=1, max_length=64)]


class GenerationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=MAX_DESCRIPTION_CHARS)
    snapshot: SnapshotId
    # An edit names the saved application and the revision that it starts from.
    application_id: Identifier | None = None
    base_revision: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _edit_names_its_base(self) -> GenerationBody:
        if (self.application_id is None) != (self.base_revision is None):
            raise ValueError("an edit names both application_id and base_revision")
        return self


class ServiceDraftBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_id: str = Field(min_length=1, max_length=64)
    # the user messages that describe the application
    message_ids: list[MessageId] = Field(min_length=1, max_length=MAX_SOURCE_MESSAGES)
    snapshot: SnapshotId


def _run_id(value: str) -> int:
    """The run that a generation reads. A generation reads one pinned run and
    refuses the pointer."""
    try:
        cts = snapshotmod.parse_snapshot_id(value)
    except ValueError:
        cts = None
    if cts is None:
        raise HTTPException(400, detail="choose a pinned snapshot before generating")
    return cts


def _can_commit(user: User) -> bool:
    return "changes.write" in permissions_for(user.role)


@contextmanager
def _graph_facts(
    settings: Any, snap: snapshotmod.Snapshot, reference: dict
) -> Iterator[generator.SnapshotFacts]:
    """The post-processor's reads of the generation's run."""
    from hst.applications.generator_tools import GraphFacts

    with dbmod.session(settings, access_mode="READ") as session:
        yield GraphFacts(pathmod.pinned(session, snap), reference)


def _postprocess(
    settings: Any,
    snap: snapshotmod.Snapshot,
    reference: dict,
    answer: str,
    description: str,
    steps: Sequence[generator.Step],
    base: BusinessApplicationDefinition | None,
) -> generator.Draft:
    with _graph_facts(settings, snap, reference) as facts:
        return generator.postprocess(
            answer, description=description, steps=steps, facts=facts, snapshot=reference, base=base
        )


async def _validate(
    store: Any, settings: Any, draft: generator.Draft, reference: dict, can_commit: bool
) -> dict:
    """The `POST .../validate` result of the draft's YAML at the generation's
    snapshot, in replace mode, with the import preview only for a caller who
    may commit."""
    from hst.app.routes.business_applications import _resolve_graph

    async def resolve(definition: BusinessApplicationDefinition, revision: int) -> dict:
        return await asyncio.to_thread(
            _resolve_graph, settings, normalized_document(definition), revision, reference, [], []
        )

    try:
        return await validate_application(
            store,
            draft.yaml,
            mode="replace",
            snapshot=reference,
            resolve=resolve,
            application_id=draft.definition.id if draft.definition is not None else None,
            include_preview=can_commit and draft.definition is not None,
        )
    except ValueError as exc:
        return _failed_validation(reference, str(exc))


def _failed_validation(reference: dict, message: str) -> dict:
    """The validation result of a draft whose validation raised, such as a
    resolution over its address bound. The result has the error on `$`. The
    error blocks a save and the ready state. `POST .../validate` answers 422
    with the same message. The draft keeps its YAML and its report."""
    return {
        "errors": [{"path": "$", "message": message, "line": None, "column": None}],
        "warnings": [],
        "definition": None,
        "preview": None,
        "resolution": None,
        "flows": None,
        "blocking": ["$"],
        "snapshot": reference,
    }


def _generation_json(record: dict, can_commit: bool) -> dict[str, Any]:
    """The poll answer of a stored generation. The import preview and the
    validation digest are left out for a caller without changes.write."""
    validation = record.get("validation")
    if validation is not None and not can_commit:
        validation = {**validation, "preview": None}
    return {
        "status": "done",
        "generation_id": record["id"],
        "created_at": record.get("created_at"),
        "snapshot": record.get("snapshot"),
        "source": record.get("source"),
        "yaml": record.get("yaml"),
        "errors": record.get("errors") or [],
        "report": record.get("report"),
        "validation": validation,
        "validation_digest": record.get("validation_digest") if can_commit else None,
    }


class _Declined(Exception):
    """The provider declined the request."""


class _Stopped(Exception):
    """The turn was cancelled, or lost its lease, before its record was written."""


async def _start(
    request: Request,
    user: User,
    description: str,
    snapshot: str,
    source: dict[str, Any],
    *,
    question: str | None = None,
    base: BusinessApplicationDefinition | None = None,
) -> JSONResponse:
    """Start one generation and answer 202 with its id.

    `question` is the model's message, the description by default. `base` is
    the saved revision an edit starts from."""
    question = description if question is None else question
    cts = _run_id(snapshot)
    settings = request.app.state.settings
    store = request.app.state.store
    if not hasattr(store, "save_application_generation"):
        raise HTTPException(503, detail="Business Application storage is unavailable")
    client = await ModelClient.from_store(store, settings)
    if not client.available():
        raise HTTPException(503, detail=UNAVAILABLE_DETAIL)
    try:
        reference = await asyncio.to_thread(assessment_service.snapshot_reference, settings, str(cts))
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    snap = snapshotmod.Snapshot(int(reference["snapshot"]), settings)
    registry = generator.generator_registry(str(snap.cts))
    try:
        runner = await turns.TurnRunner.start(
            store,
            user.id,
            question,
            owner=turns.owner(request.app),
            surface="service_generator",
            per_user_cap=MAX_ASKS_PER_USER,
            global_cap=MAX_QUEUED_ASKS,
            tool_versions={spec.name: spec.version for spec in registry.specs()},
        )
    except TurnCapExceeded as exc:
        raise HTTPException(429, detail=_CAP_DETAIL[exc.scope]) from exc
    try:
        principal = Principal.for_role(user.role, user_id=user.id)
        audit = AuditSink(
            store,
            user_id=user.id,
            origin="web",
            surface="service_generator",
            provider=client.provider,
            model_requested=client.model,
            snapshot=snap.snapshot_id,
        )
        context = ToolContext(
            settings=settings,
            principal=principal,
            surface="service_generator",
            snapshot=snap,
            cypher_log=audit.cypher,
            store=store,
            loop=asyncio.get_running_loop(),
        )
        tools = tools_mod.offered_tools(context, registry)
        assembled = generator.system_prompt(principal, tools, edit=base is not None)
        try:
            client.adapter()
        except agent_base.AgentError as exc:
            raise HTTPException(502, detail=str(exc)) from exc
    except BaseException:
        # a generation that does not start gives its slot back at once
        await runner.finish("error", error="the generation could not start")
        raise
    can_commit = _can_commit(user)

    def on_step(step: tools_mod.ToolCall) -> None:
        # The ai_steps row and the audit rows of the step share one id.
        step_id = str(uuid.uuid4())
        audit.on_step(step, step_id=step_id)
        tools_mod.frame_step(step, runner.on_step(step, step_id), snap)

    async def finish(answer: agent_base.AgentAnswer) -> dict:
        steps = generator.steps_of(answer.steps)
        draft = await asyncio.to_thread(
            _postprocess, settings, snap, reference, answer.answer, description, steps, base
        )
        validation = await _validate(store, settings, draft, reference, can_commit)
        digest = await record_validation(store, validation) if can_commit else None
        report = generator.report(draft, generation_id=runner.id, snapshot=reference, validation=validation)
        record = generator.generation_record(
            generation_id=runner.id,
            created_by=user.id,
            created_at=datetime.now(UTC),
            snapshot=reference,
            source=source,
            description=description,
            provider=answer.provider or client.provider,
            model=answer.model_served or client.model,
            system_prompt_sha256=assembled.static_hash,
            steps=steps,
            draft=draft,
            report=report,
            validation=validation,
            validation_digest=digest,
        )
        if runner.cancelled or runner.lost:
            raise _Stopped
        return await store.save_application_generation(record)

    async def run() -> None:
        status, payload, error, content = "error", None, None, ""
        answer: agent_base.AgentAnswer | None = None
        try:
            async with _ask_gate:
                budget = runner.attach(AskBudget(timeout=GENERATION_DEADLINE_S))
                try:
                    answer = await asyncio.wait_for(
                        asyncio.to_thread(
                            client.run,
                            TurnRequest(
                                question,
                                system=assembled.system,
                                tools=tools,
                                budget=budget,
                                on_step=on_step,
                            ),
                        ),
                        timeout=GENERATION_DEADLINE_S,
                    )
                finally:
                    budget.stopped.set()
            if answer.declined:
                raise _Declined
            record = await finish(answer)
            status, payload, content = "done", {"generation_id": runner.id}, str(record["yaml"])
        except TimeoutError:
            log.warning("generation %s exceeded %.0fs and was abandoned", runner.id, GENERATION_DEADLINE_S)
            error = f"the generation exceeded {GENERATION_DEADLINE_S:.0f} seconds and was abandoned"
        except agent_base.AgentError as exc:
            # The provider SDK text describes the outbound path of the deployment.
            # It stays in the server log.
            log.warning("generation %s failed: %s", runner.id, redact(str(exc)))
            error = f"the provider call failed (generation {runner.id}); see the server log"
        except _Declined:
            error = DECLINED_DETAIL
        except _Stopped:
            error = CANCELLED_DETAIL
        except Exception:
            log.exception("generation %s crashed", runner.id)
            error = f"the generation failed (generation {runner.id}); see the server log"
        finally:
            await audit.close()
        if runner.cancelled:
            status, payload, error = "cancelled", None, CANCELLED_DETAIL
        await runner.finish(
            status,
            content=content,
            payload=payload,
            error=error,
            snapshot_id=snap.snapshot_id,
            provider=answer.provider if answer is not None else client.provider,
            model_requested=client.model,
            model_served=answer.model_served if answer is not None else None,
            usage=ai_routes._usage(answer),
        )

    task = asyncio.get_running_loop().create_task(run())
    request.app.state.ask_tasks = getattr(request.app.state, "ask_tasks", set())
    request.app.state.ask_tasks.add(task)
    task.add_done_callback(request.app.state.ask_tasks.discard)
    return JSONResponse({"generation_id": runner.id}, status_code=202)


@router.post("/business-applications/generations")
async def start_generation(
    body: GenerationBody, request: Request, user: User = Depends(require_ask)
) -> JSONResponse:
    """Generate a definition from a description at a pinned snapshot, or,
    with `application_id` and `base_revision`, edit that saved revision as the
    description asks. An edit starts only from the current revision. An older
    revision answers 409 before the model runs."""
    description = body.description.strip()
    if not description:
        raise HTTPException(400, detail="describe the application to generate")
    if body.application_id is None or body.base_revision is None:
        return await _start(request, user, description, body.snapshot, {"kind": "description"})
    store = request.app.state.store
    if not hasattr(store, "get_application"):
        raise HTTPException(503, detail="Business Application storage is unavailable")
    record = await store.get_application(body.application_id, body.base_revision)
    if record is None:
        raise HTTPException(404, detail="Business Application revision not found")
    current = await store.get_application(body.application_id)
    if current is not None and current.revision != record.revision:
        raise HTTPException(
            409,
            detail=(
                f"revision {record.revision} of {record.id} is not the current revision "
                f"{current.revision}; start the edit from the current revision"
            ),
        )
    export = application_service.export_revision(record)
    if len(export) > MAX_EDIT_EXPORT_CHARS:
        raise HTTPException(413, detail=f"the application export exceeds {MAX_EDIT_EXPORT_CHARS} characters")
    source = {
        "kind": "edit",
        "application_id": record.id,
        "base_revision": record.revision,
        "base_digest": record.digest,
    }
    question = generator.edit_question(
        description, export, application_id=record.id, revision=record.revision
    )
    base = stored_definition(record.definition)
    return await _start(request, user, description, body.snapshot, source, question=question, base=base)


@router.get("/business-applications/generations/{generation_id}")
async def get_generation(generation_id: str, request: Request, user: User = Depends(require_ask)) -> dict:
    """The stored record of the owner's generation, or the poll result of its
    turn. The id is a UUID in any text form. Any other id answers 404."""
    store = request.app.state.store
    canonical = canonical_uuid(generation_id)
    if canonical is None:
        raise HTTPException(404, detail="no such generation")
    record = None
    if hasattr(store, "get_application_generation"):
        record = await store.get_application_generation(canonical)
    if record is not None:
        if record.get("created_by") != user.id:
            raise HTTPException(404, detail="no such generation")
        return _generation_json(record, _can_commit(user))
    # a foreign turn, and a turn of another surface, answer like a missing one
    message = await store.get_message(user.id, canonical, surface="service_generator")
    if message is None or message.role != "assistant":
        raise HTTPException(404, detail="no such generation")
    return turns.poll_result(message, INTERRUPTED_DETAIL)


@router.post("/ai/service-drafts")
async def start_service_draft(
    body: ServiceDraftBody, request: Request, user: User = Depends(require_ask)
) -> JSONResponse:
    """Generate a definition from user messages of one of the caller's
    conversations, joined in conversation order."""
    store = request.app.state.store
    conversation_id = canonical_uuid(body.conversation_id)
    messages = []
    for message_id in dict.fromkeys(body.message_ids):
        message = await store.get_message(user.id, message_id) if conversation_id is not None else None
        if message is None or message.conversation_id != conversation_id or message.role != "user":
            raise HTTPException(404, detail=f"no user message {message_id} in the conversation")
        messages.append(message)
    description = "\n\n".join(
        m.content.strip() for m in sorted(messages, key=lambda m: m.seq) if m.content.strip()
    )
    if not description:
        raise HTTPException(400, detail="the messages hold no description")
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise HTTPException(413, detail=f"the description exceeds {MAX_DESCRIPTION_CHARS} characters")
    source = {
        "kind": "conversation",
        "conversation_id": conversation_id,
        "message_ids": [m.id for m in sorted(messages, key=lambda m: m.seq)],
    }
    return await _start(request, user, description, body.snapshot, source)
