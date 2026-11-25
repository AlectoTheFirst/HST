"""The routes that list, create, read, update and delete a change."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from hst.app import changes_delta
from hst.app.auth import current_user, require_permission
from hst.app.store import Change, ChangeIntent, User

router = APIRouter()

_STATUSES = ("draft", "simulated", "closed")


class IntentBody(BaseModel):
    kind: str
    params: dict[str, Any] = {}


class ChangeCreateBody(BaseModel):
    title: str
    description: str = ""
    snapshot_cts: int | None = None
    intents: list[IntentBody] = []


class ChangePatchBody(BaseModel):
    title: str | None = None
    description: str | None = None
    snapshot_cts: int | None = None
    status: str | None = None
    intents: list[IntentBody] | None = None


def _validate_intents(items: list[IntentBody]) -> list[tuple[str, dict]]:
    validated: list[tuple[str, dict]] = []
    for item in items:
        if item.kind not in changes_delta.INTENT_KINDS:
            raise HTTPException(
                422,
                detail=(
                    f"unknown intent kind {item.kind!r}; known kinds: "
                    f"{', '.join(sorted(changes_delta.INTENT_KINDS))}"
                ),
            )
        validated.append((item.kind, item.params))
    return validated


def _public_intent(intent: ChangeIntent) -> dict[str, Any]:
    return {
        "id": intent.id,
        "position": intent.position,
        "kind": intent.kind,
        "params": intent.params,
        # app/changes_delta.compute_route_delta predicts a row for a RIB-shaping kind only.
        "simulatable": intent.kind in changes_delta.RIB_SHAPING_KINDS,
    }


def _public(change: Change, intents: list[ChangeIntent]) -> dict[str, Any]:
    return {
        "id": change.id,
        "title": change.title,
        "description": change.description,
        "snapshot_cts": change.snapshot_cts,
        "status": change.status,
        "created_by": change.created_by,
        "created_at": change.created_at.isoformat(),
        "updated_at": change.updated_at.isoformat(),
        "intents": [_public_intent(i) for i in intents],
    }


@router.get("/changes", dependencies=[Depends(require_permission("graph.read"))])
async def list_changes(request: Request) -> dict[str, Any]:
    store = request.app.state.store
    rows = []
    for change in await store.list_changes():
        rows.append(_public(change, await store.list_change_intents(change.id)))
    return {"changes": rows}


@router.post("/changes", status_code=201, dependencies=[Depends(require_permission("changes.write"))])
async def create_change(
    request: Request, body: ChangeCreateBody, user: User = Depends(current_user)
) -> dict[str, Any]:
    intents = _validate_intents(body.intents)
    change, intent_rows = await request.app.state.store.create_change(
        title=body.title,
        description=body.description,
        snapshot_cts=body.snapshot_cts,
        created_by=user.id,
        intents=intents,
    )
    return _public(change, intent_rows)


@router.get("/changes/{change_id}", dependencies=[Depends(require_permission("graph.read"))])
async def get_change(request: Request, change_id: int) -> dict[str, Any]:
    store = request.app.state.store
    change = await store.get_change(change_id)
    if change is None:
        raise HTTPException(404, detail=f"no such change: {change_id}")
    return _public(change, await store.list_change_intents(change_id))


@router.patch("/changes/{change_id}", dependencies=[Depends(require_permission("changes.write"))])
async def update_change(request: Request, change_id: int, body: ChangePatchBody) -> dict[str, Any]:
    provided = body.model_dump(exclude_unset=True)
    if "status" in provided and provided["status"] not in _STATUSES:
        raise HTTPException(422, detail=f"status must be one of: {', '.join(_STATUSES)}")
    if "intents" in provided:
        # model_dump gives each IntentBody as a plain dict. _validate_intents
        # takes the IntentBody objects of the parsed body.
        provided["intents"] = _validate_intents(body.intents or [])
    result = await request.app.state.store.update_change(change_id, **provided)
    if result is None:
        raise HTTPException(404, detail=f"no such change: {change_id}")
    change, intent_rows = result
    return _public(change, intent_rows)


@router.delete(
    "/changes/{change_id}", status_code=204, dependencies=[Depends(require_permission("changes.write"))]
)
async def delete_change(request: Request, change_id: int) -> None:
    if not await request.app.state.store.delete_change(change_id):
        raise HTTPException(404, detail=f"no such change: {change_id}")
