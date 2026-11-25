"""Optional AI interpretation of an assessment question, with pinned, read-only discovery."""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from hst.app import tls
from hst.app.agent import base, registry
from hst.app.agent.budget import AskBudget
from hst.app.ai import client as ai_client
from hst.app.ai import prompt as prompt_mod
from hst.app.ai import turns
from hst.app.ai.redact import redact, redact_exception
from hst.app.ai.registry import Principal
from hst.app.auth import require_permission
from hst.app.store import TurnCapExceeded, User
from hst.assessment.assistant import DraftBody, parse_plan, prepare_draft

router = APIRouter(dependencies=[Depends(require_permission("graph.read"))])
require_ask = require_permission("agent.ask")
log = logging.getLogger("hst.assessment.assistant")

UNAVAILABLE_DETAIL = "AI assistance is unavailable. Continue with the guided form."
FAILED_DETAIL = "The draft could not be prepared. Refine the question or continue with the guided form."
INTERRUPTED_DETAIL = (
    "The draft was interrupted because the server process preparing it stopped. "
    "Try again or continue with the guided form."
)
CANCELLED_DETAIL = "The draft was cancelled. Continue with the guided form."
# The 429 details, by the cap that refused the draft.
_CAP_DETAIL = {
    "user": "An AI request of this user is in progress.",
    "global": "AI assistance is busy. Try again or continue with the guided form.",
}


@router.post("/assessment-assistant/drafts")
async def draft(request: Request, body: DraftBody, user: User = Depends(require_ask)) -> JSONResponse:
    if not body.question.strip():
        raise HTTPException(400, detail="Describe the question to investigate.")
    if body.snapshot.lower() in {"latest", "current", "head"}:
        raise HTTPException(400, detail="Choose a pinned snapshot before preparing a draft.")
    config, secrets, _, _ = await ai_client._load(request)
    if not config["enabled"] or not registry.is_configured(config, secrets):
        raise HTTPException(503, detail=UNAVAILABLE_DETAIL)
    # start_turn counts both caps under the per-user lock and inserts the rows.
    # The claim follows at once.
    try:
        runner = await turns.TurnRunner.start(
            request.app.state.store,
            user.id,
            body.question,
            owner=turns.owner(request.app),
            surface="assessment_draft",
            per_user_cap=ai_client.MAX_ASKS_PER_USER,
            global_cap=ai_client.MAX_QUEUED_ASKS,
        )
    except TurnCapExceeded as exc:
        raise HTTPException(429, detail=_CAP_DETAIL[exc.scope]) from exc
    try:
        options = config.get("options", {})
        try:
            adapter = base.build(
                config["provider"], secrets, options, tls.resolve(request.app.state.settings, options)
            )
        except base.AgentError as exc:
            log.warning("assessment assistant configuration failed: %s", redact(str(exc)))
            await runner.finish("error", error=UNAVAILABLE_DETAIL)
            raise HTTPException(502, detail=UNAVAILABLE_DETAIL) from exc
        # The draft surface takes no site instructions and is offered no tools.
        # Its answer is the JSON object that parse_plan reads.
        system = prompt_mod.assemble(
            "assessment_draft",
            prompt_mod.SiteInstructions.from_config(config),
            [],
            Principal.for_role(user.role, user_id=user.id),
        ).system
    except BaseException:
        # a draft that does not start gives its slot back at once
        await runner.finish("error", error="the ask could not start")
        raise

    async def run() -> None:
        budget = AskBudget(timeout=180)
        runner.attach(budget)
        state, result, error = "error", None, None
        try:
            async with ai_client._ask_gate:
                store = request.app.state.store
                saved = []
                if hasattr(store, "list_requirements"):
                    saved = [item.as_dict() for item in await store.list_requirements(limit=1000)]
                    # An explicitly selected revision stays selected when the
                    # library holds a newer revision.
                    for choice in body.selections:
                        if choice.kind == "service" and choice.origin == "saved":
                            saved = [item for item in saved if item["id"] != choice.uid]
                            if choice.requirement_revision is not None:
                                record = await store.get_requirement(choice.uid, choice.requirement_revision)
                                if record is not None:
                                    saved.insert(0, record.as_dict())

                def prepare() -> dict:
                    from hst.assessment.discovery import search_options

                    budget.check()
                    # A request with a plan skips the interpretation.
                    plan = body.plan
                    if plan is None:
                        answer = adapter.ask(
                            body.question,
                            system=system,
                            tools=[],
                            model=config["model"],
                            effort=config["effort"],
                            budget=budget,
                        )
                        if answer.declined:
                            raise ValueError("The assistant could not prepare this question.")
                        plan = parse_plan(answer.answer)
                    budget.check()
                    search = partial(search_options, request.app.state.settings, body.snapshot)
                    if saved:
                        search = partial(search, saved_requirements=saved)
                    return prepare_draft(body, plan, search)

                result = await asyncio.wait_for(asyncio.to_thread(prepare), timeout=180)
            state = "done"
        except Exception as exc:
            log.warning("assessment draft %s failed: %s", runner.id, redact_exception(exc))
            state, result, error = "error", None, FAILED_DETAIL
        finally:
            budget.stopped.set()
        if runner.cancelled:
            state, result, error = "cancelled", None, CANCELLED_DETAIL
        # the draft result is the envelope payload
        await runner.finish(
            state,
            payload=result,
            error=error,
            snapshot_id=body.snapshot,
            provider=config["provider"],
            model_requested=config["model"],
        )

    task = asyncio.create_task(run())
    request.app.state.ask_tasks = getattr(request.app.state, "ask_tasks", set())
    request.app.state.ask_tasks.add(task)
    task.add_done_callback(request.app.state.ask_tasks.discard)
    return JSONResponse({"job_id": runner.id}, status_code=202)


@router.get("/assessment-assistant/drafts/{job_id}")
async def status(job_id: str, request: Request, user: User = Depends(require_ask)) -> dict:
    # a foreign draft, and a turn of another surface, answer like a missing one
    message = await request.app.state.store.get_message(user.id, job_id, surface="assessment_draft")
    if message is None or message.role != "assistant":
        raise HTTPException(404, detail="No such draft.")
    return turns.poll_result(message, INTERRUPTED_DETAIL)
