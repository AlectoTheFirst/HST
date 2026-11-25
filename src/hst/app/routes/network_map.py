"""The network map's shared layouts and named views."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from hst.app.auth import current_user, require_permission
from hst.app.store import MapViewNameTaken, NetworkMapLayout, NetworkMapView, StaleMapRevision

router = APIRouter(prefix="/network-map")

# A scope is `site/<code>`. The code has the alphabet of a site code (CODE_RE in routes/sites.py).
SCOPE_RE = re.compile(r"^site/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_POSITIONS = 5000
MAX_STATE_BYTES = 16 * 1024
# The bound of a drawing coordinate, in the units of ELK.
MAX_COORD = 1e7


class Position(BaseModel):
    x: float = Field(ge=-MAX_COORD, le=MAX_COORD)
    y: float = Field(ge=-MAX_COORD, le=MAX_COORD)


class LayoutBody(BaseModel):
    positions: dict[str, Position]
    expected_revision: int = Field(ge=0)

    @field_validator("positions")
    @classmethod
    def _bounded(cls, value: dict[str, Position]) -> dict[str, Position]:
        if len(value) > MAX_POSITIONS:
            raise ValueError(f"at most {MAX_POSITIONS} positions")
        return value


class ViewBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    state: dict[str, Any]

    @field_validator("state")
    @classmethod
    def _small(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value)) > MAX_STATE_BYTES:
            raise ValueError(f"the view state is limited to {MAX_STATE_BYTES // 1024} KiB")
        return value


class ViewPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    state: dict[str, Any] | None = None
    expected_revision: int = Field(ge=1)

    @field_validator("state")
    @classmethod
    def _small(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(json.dumps(value)) > MAX_STATE_BYTES:
            raise ValueError(f"the view state is limited to {MAX_STATE_BYTES // 1024} KiB")
        return value


def _scope(scope: str) -> str:
    if not SCOPE_RE.match(scope):
        raise HTTPException(422, detail="scope must be site/<code>")
    return scope


def _layout(layout: NetworkMapLayout) -> dict[str, Any]:
    return {
        "scope": layout.scope,
        "positions": layout.positions,
        "revision": layout.revision,
        "updated_by": layout.updated_by,
        "updated_at": layout.updated_at.isoformat(),
    }


def _view(view: NetworkMapView) -> dict[str, Any]:
    return {
        "id": str(view.id),
        "name": view.name,
        "state": view.state,
        "owner_id": view.owner_id,
        "revision": view.revision,
        "created_at": view.created_at.isoformat(),
        "updated_at": view.updated_at.isoformat(),
    }


@router.get("/layouts/{scope:path}", dependencies=[Depends(require_permission("graph.read"))])
async def get_layout(request: Request, scope: str) -> dict[str, Any]:
    layout = await request.app.state.store.get_network_map_layout(_scope(scope))
    if layout is None:
        return {"scope": scope, "positions": {}, "revision": 0, "updated_by": None, "updated_at": None}
    return _layout(layout)


@router.put("/layouts/{scope:path}", dependencies=[Depends(require_permission("sites.write"))])
async def put_layout(
    request: Request, scope: str, body: LayoutBody, user: Annotated[Any, Depends(current_user)]
) -> dict[str, Any]:
    try:
        layout = await request.app.state.store.save_network_map_layout(
            _scope(scope),
            {uid: p.model_dump() for uid, p in sorted(body.positions.items())},
            expected_revision=body.expected_revision,
            user_id=user.id,
            now=datetime.now(UTC),
        )
    except StaleMapRevision as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    return _layout(layout)


@router.delete(
    "/layouts/{scope:path}", status_code=204, dependencies=[Depends(require_permission("sites.write"))]
)
async def delete_layout(request: Request, scope: str, expected_revision: int) -> Response:
    try:
        await request.app.state.store.delete_network_map_layout(
            _scope(scope), expected_revision=expected_revision
        )
    except StaleMapRevision as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    return Response(status_code=204)


@router.get("/views", dependencies=[Depends(require_permission("graph.read"))])
async def list_views(request: Request) -> dict[str, Any]:
    return {"views": [_view(v) for v in await request.app.state.store.list_network_map_views()]}


@router.post("/views", status_code=201, dependencies=[Depends(require_permission("sites.write"))])
async def create_view(
    request: Request, body: ViewBody, user: Annotated[Any, Depends(current_user)]
) -> dict[str, Any]:
    try:
        view = await request.app.state.store.create_network_map_view(
            body.name.strip(), body.state, owner_id=user.id, now=datetime.now(UTC)
        )
    except MapViewNameTaken as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    return _view(view)


@router.patch("/views/{view_id}", dependencies=[Depends(require_permission("sites.write"))])
async def update_view(request: Request, view_id: UUID, body: ViewPatch) -> dict[str, Any]:
    try:
        view = await request.app.state.store.update_network_map_view(
            view_id,
            expected_revision=body.expected_revision,
            now=datetime.now(UTC),
            name=body.name.strip() if body.name else None,
            state=body.state,
        )
    except (StaleMapRevision, MapViewNameTaken) as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    if view is None:
        raise HTTPException(404, detail="view not found")
    return _view(view)


@router.delete("/views/{view_id}", status_code=204, dependencies=[Depends(require_permission("sites.write"))])
async def delete_view(request: Request, view_id: UUID, expected_revision: int) -> Response:
    try:
        found = await request.app.state.store.delete_network_map_view(
            view_id, expected_revision=expected_revision
        )
    except StaleMapRevision as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    if not found:
        raise HTTPException(404, detail="view not found")
    return Response(status_code=204)
