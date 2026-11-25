"""Saved views, the personal filters over the device list."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request

from hst.app.auth import current_user, require_permission
from hst.app.inventory.contracts import (
    CollectionState,
    Lifecycle,
    PlacementState,
    SavedViewCreate,
    SavedViewPatch,
    SavedViewView,
    SortDirection,
    SortField,
    ViewFilter,
)
from hst.app.inventory.observations import context_for
from hst.app.inventory.repository import InventoryTx, NotFound
from hst.app.store import InventorySavedView, User

router = APIRouter()

_NAMESPACE = uuid.UUID("5d2b2a1e-4f66-4b1a-9c73-7a9d0f9f1e21")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def builtin_id(key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, f"inventory:view:{key}")


BUILTIN_VIEWS: dict[uuid.UUID, SavedViewView] = {
    builtin_id(key): SavedViewView(
        id=builtin_id(key),
        owner_id="",
        name=name,
        filter=view_filter,
        sort=SortField.NAME,
        direction=SortDirection.ASC,
        columns=[],
        revision=0,
        created_at=_EPOCH,
        updated_at=_EPOCH,
    )
    for key, name, view_filter in (
        ("all", "All devices", ViewFilter()),
        (
            "unplaced",
            "Unplaced",
            ViewFilter(placement_state=[PlacementState.UNPLACED, PlacementState.CONFLICT]),
        ),
        (
            "collection-issues",
            "Collection issues",
            ViewFilter(
                collection_state=[
                    CollectionState.FAILED,
                    CollectionState.PARTIAL,
                    CollectionState.STALE,
                    CollectionState.NEVER,
                ]
            ),
        ),
        ("archived", "Archived", ViewFilter(lifecycle=[Lifecycle.ARCHIVED])),
    )
}


def view_of(row: InventorySavedView) -> SavedViewView:
    return SavedViewView(
        id=row.id,
        owner_id=str(row.owner_id),
        name=row.name,
        filter=ViewFilter.model_validate({**row.filter, "version": row.filter_version}),
        sort=SortField(row.sort),
        direction=SortDirection(row.direction),
        columns=list(row.columns),
        revision=row.revision,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def resolve_view(tx: InventoryTx, view_id: uuid.UUID, owner_id: int) -> SavedViewView:
    """Return the built-in view or the view of the caller with `view_id`. Any other id is a 404."""
    builtin = BUILTIN_VIEWS.get(view_id)
    if builtin is not None:
        return builtin
    row = await tx.get_view(view_id, owner_id)
    if row is None:
        raise NotFound("view not found")
    return view_of(row)


def _filter_payload(view_filter: ViewFilter) -> dict[str, Any]:
    return view_filter.model_dump(mode="json", exclude={"version"})


@router.get("/views", dependencies=[Depends(require_permission("graph.read"))])
async def list_views(request: Request, user: User = Depends(current_user)) -> list[SavedViewView]:
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        rows = await tx.list_views(user.id)
    return [*BUILTIN_VIEWS.values(), *(view_of(r) for r in rows)]


@router.get("/views/{view_id}", dependencies=[Depends(require_permission("graph.read"))])
async def get_view(request: Request, view_id: uuid.UUID, user: User = Depends(current_user)) -> SavedViewView:
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        return await resolve_view(tx, view_id, user.id)


@router.post("/views", status_code=201, dependencies=[Depends(require_permission("graph.read"))])
async def create_view(
    request: Request, body: SavedViewCreate, user: User = Depends(current_user)
) -> SavedViewView:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        row = await tx.create_view(
            owner_id=user.id,
            name=body.name,
            filter=_filter_payload(body.filter),
            sort=body.sort.value,
            direction=body.direction.value,
            columns=body.columns,
            now=now,
            filter_version=body.filter.version,
        )
        await tx.append_event(
            entity_type="view",
            entity_id=str(row.id),
            actor_id=user.id,
            action="view.create",
            now=now,
            after={"name": row.name, "revision": row.revision},
        )
    return view_of(row)


@router.patch("/views/{view_id}", dependencies=[Depends(require_permission("graph.read"))])
async def update_view(
    request: Request, view_id: uuid.UUID, body: SavedViewPatch, user: User = Depends(current_user)
) -> SavedViewView:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        current = await tx.get_view(view_id, user.id)
        if current is None:
            raise NotFound("view not found")
        kwargs: dict[str, Any] = {}
        if body.name is not None:
            kwargs["name"] = body.name
        if body.filter is not None:
            kwargs["filter"] = _filter_payload(body.filter)
        if body.sort is not None:
            kwargs["sort"] = body.sort.value
        if body.direction is not None:
            kwargs["direction"] = body.direction.value
        if body.columns is not None:
            kwargs["columns"] = body.columns
        row = await tx.update_view(
            view_id, user.id, expected_revision=body.expected_revision, now=now, **kwargs
        )
        await tx.append_event(
            entity_type="view",
            entity_id=str(row.id),
            actor_id=user.id,
            action="view.update",
            now=now,
            before={"name": current.name, "revision": current.revision},
            after={"name": row.name, "revision": row.revision},
        )
    return view_of(row)


@router.delete("/views/{view_id}", status_code=204, dependencies=[Depends(require_permission("graph.read"))])
async def delete_view(
    request: Request,
    view_id: uuid.UUID,
    expected_revision: int | None = None,
    user: User = Depends(current_user),
) -> None:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        current = await tx.get_view(view_id, user.id)
        if current is None:
            raise NotFound("view not found")
        await tx.delete_view(view_id, user.id, expected_revision=expected_revision)
        await tx.append_event(
            entity_type="view",
            entity_id=str(view_id),
            actor_id=user.id,
            action="view.delete",
            now=now,
            before={"name": current.name, "revision": current.revision},
        )
