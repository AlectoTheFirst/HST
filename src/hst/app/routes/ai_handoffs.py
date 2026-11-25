"""Handoffs from a stored AI step.

Each route names a step of the caller's conversations by id and answers 404
for a step of another user, as for a missing one. The server reads the tool,
the arguments and the run from the stored step (`app/ai/handoffs.py`) and
reads no request body.

`POST /api/ai/steps/{id}/analysis-session` saves a `change_simulate` step as
revision 1 of an analysis session of kind simulation, under
`changes.write`. The session is pinned to the snapshot reference of the run
that the step read. A run without an evidence manifest is refused. Its
`results.review.origin` names the step, and an `ai_links` row of kind
`analysis_session` links the step to the session. The session is saved
without a run. The analysis workspace runs the reviewed revision. A step
that already has such a link is not saved again. The route then answers 200
with the latest revision of the linked session. This route is the only path
from a chat to a durable simulation record.

`GET /api/ai/steps/{id}/assessment-draft` returns the assessment draft of an
`impact_evaluate_service` step in the shape `serviceDraft` builds in the web
client. The draft is not saved.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from hst.app.ai import handoffs
from hst.app.auth import current_user, require_permission
from hst.app.routes import analysis_sessions
from hst.app.store import AiStep, User
from hst.assessment import service as assessment_service

router = APIRouter()
require_changes_write = require_permission("changes.write")  # B008 forbids this call in an argument default.


async def _owned_step(request: Request, step_id: str, user: User) -> AiStep:
    step = await request.app.state.store.get_step(user.id, step_id)
    if step is None:
        raise HTTPException(404, detail="no such step")
    return step


async def _linked_session(store: Any, user: User, step: AiStep) -> str | None:
    """The id of the analysis session an earlier save of `step` created."""
    conversation = await store.get_conversation(user.id, step.conversation_id)
    links = conversation.links if conversation is not None else []
    return next(
        (
            link.ref_id
            for link in links
            if link.kind == "analysis_session" and link.direction == "to" and link.step_id == step.id
        ),
        None,
    )


@router.post("/ai/steps/{step_id}/analysis-session", status_code=201)
async def save_step_simulation(
    step_id: str, request: Request, response: Response, user: User = Depends(require_changes_write)
) -> dict[str, Any]:
    """Save a change simulation step as an analysis session, or return
    the session an earlier save of the step created."""
    step = await _owned_step(request, step_id, user)
    store = request.app.state.store
    settings = request.app.state.settings
    linked = await _linked_session(store, user, step)
    if linked is not None:
        response.status_code = 200
        return await analysis_sessions.get_session(linked, request, revision=None)
    with analysis_sessions.session_errors():
        run = handoffs.simulation_run(step)
        reference = await asyncio.to_thread(assessment_service.snapshot_reference, settings, run)
        body = analysis_sessions.CreateSession(
            title=handoffs.session_title(step),
            input=handoffs.simulation_input(step, reference),
            review=handoffs.review_origin(step),
        )
        saved = await analysis_sessions.save_session(store, settings, body, user.id)
    await store.add_link(
        step.conversation_id,
        "analysis_session",
        saved["id"],
        "to",
        datetime.now(UTC),
        message_id=step.message_id,
        step_id=step.id,
        ref_revision=saved["revision"],
    )
    return saved


@router.get("/ai/steps/{step_id}/assessment-draft")
async def step_assessment_draft(
    step_id: str, request: Request, user: User = Depends(current_user)
) -> dict[str, Any]:
    """The assessment draft of a service evaluation step."""
    step = await _owned_step(request, step_id, user)
    try:
        return handoffs.assessment_draft(step)
    except handoffs.HandoffError as exc:
        raise HTTPException(422, detail=str(exc)) from None
