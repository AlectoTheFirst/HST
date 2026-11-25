"""Routes for routing inspection and routing groups."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from hst.app.auth import current_user, require_permission
from hst.app.inventory.contracts import (
    API_PREFIX,
    OPERATION_PERMISSIONS,
    ApplyRequest,
    ApplyResponse,
    DeviceRoutingQuery,
    DeviceRoutingResponse,
    ErrorCode,
    ErrorResponse,
    PreviewOperation,
    PreviewRequest,
    PreviewResponse,
    RoutingGroupCreate,
    RoutingGroupPatch,
    RoutingGroupView,
)
from hst.app.inventory.repository import InventoryError
from hst.app.inventory.routing import Actor, GraphReader, Neo4jGraphReader, RoutingService
from hst.app.permissions import permissions_for
from hst.app.store import User

router = APIRouter(prefix=API_PREFIX, tags=["inventory-routing"])
operations_router = APIRouter(prefix=API_PREFIX, tags=["inventory-routing"])

_GRAPH_STATE = "inventory_graph"
_READ = [Depends(require_permission("graph.read"))]
_WRITE = [Depends(require_permission("sources.write"))]
_MEMBERS = [Depends(require_permission(OPERATION_PERMISSIONS[PreviewOperation.EDIT_ROUTING_MEMBERS]))]
_USER = Depends(current_user)


def graph_reader(request: Request) -> GraphReader:
    reader = getattr(request.app.state, _GRAPH_STATE, None)
    if reader is None:
        reader = Neo4jGraphReader(request.app.state.settings)
        setattr(request.app.state, _GRAPH_STATE, reader)
    return reader


def service(request: Request) -> RoutingService:
    return RoutingService(request.app.state.store.inventory(), graph_reader(request))


def actor_of(user: User) -> Actor:
    return Actor(id=user.id, name=user.username, permissions=permissions_for(user.role))


def error_response(exc: InventoryError) -> JSONResponse:
    body = ErrorResponse(
        error=str(exc),
        code=exc.code,
        current_revision=exc.current_revision,
        references=list(exc.references),
    )
    return JSONResponse(status_code=exc.status, content=body.model_dump(mode="json"))


def _validation(exc: ValidationError) -> JSONResponse:
    body = ErrorResponse(
        error="invalid query parameters",
        code=ErrorCode.VALIDATION,
        detail={"errors": [dict(e, ctx=None) for e in exc.errors(include_url=False, include_context=False)]},
    )
    return JSONResponse(status_code=422, content=body.model_dump(mode="json"))


async def _inventory_error_handler(_request: Request, exc: Exception) -> Response:
    if isinstance(exc, InventoryError):
        return error_response(exc)
    raise exc


# --- device routing ---------------------------------------------------------------------


@router.get(
    "/devices/{device_id}/routing",
    response_model=DeviceRoutingResponse,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    dependencies=_READ,
)
async def get_device_routing(request: Request, device_id: uuid.UUID) -> Any:
    try:
        query = DeviceRoutingQuery.model_validate(dict(request.query_params))
    except ValidationError as exc:
        return _validation(exc)
    return await service(request).device_routing(device_id, query.snapshot_key)


# --- routing groups ---------------------------------------------------------------------


@router.get("/routing-groups", response_model=list[RoutingGroupView], dependencies=_READ)
async def list_routing_groups(request: Request) -> list[RoutingGroupView]:
    return await service(request).list_groups()


@router.get("/routing-groups/{group_id}", response_model=RoutingGroupView, dependencies=_READ)
async def get_routing_group(request: Request, group_id: uuid.UUID) -> RoutingGroupView:
    return await service(request).get_group(group_id)


@router.post("/routing-groups", response_model=RoutingGroupView, status_code=201, dependencies=_WRITE)
async def create_routing_group(
    request: Request, body: RoutingGroupCreate, user: User = _USER
) -> RoutingGroupView:
    return await service(request).create_group(body, actor_of(user))


@router.patch("/routing-groups/{group_id}", response_model=RoutingGroupView, dependencies=_WRITE)
async def patch_routing_group(
    request: Request, group_id: uuid.UUID, body: RoutingGroupPatch, user: User = _USER
) -> RoutingGroupView:
    return await service(request).patch_group(group_id, body, actor_of(user))


@router.delete("/routing-groups/{group_id}", status_code=204, dependencies=_WRITE)
async def delete_routing_group(
    request: Request, group_id: uuid.UUID, expected_revision: int = Query(ge=1), user: User = _USER
) -> Response:
    await service(request).delete_group(group_id, expected_revision, actor_of(user))
    return Response(status_code=204)


# --- edit_routing_members preview and apply ------------------------------------------------


@operations_router.post("/operations/preview", response_model=PreviewResponse, dependencies=_MEMBERS)
async def preview_operation(request: Request, body: PreviewRequest, user: User = _USER) -> PreviewResponse:
    if body.operation != PreviewOperation.EDIT_ROUTING_MEMBERS:
        raise InventoryError(f"{body.operation.value} is not served by the routing operations router")
    return await service(request).preview_members(body, actor_of(user))


@operations_router.post("/operations/apply", response_model=ApplyResponse, dependencies=_MEMBERS)
async def apply_operation(request: Request, body: ApplyRequest, user: User = _USER) -> ApplyResponse:
    return await service(request).apply_members(body, actor_of(user))


def register(app: FastAPI, graph: GraphReader | None = None, *, operations: bool = True) -> None:
    """Mount the routing routers on `app`.

    `graph` overrides the graph reader. With `operations=False` the function does not mount the
    preview and apply paths. The generic operations dispatcher serves them."""
    if graph is not None:
        setattr(app.state, _GRAPH_STATE, graph)
    app.add_exception_handler(InventoryError, _inventory_error_handler)
    app.include_router(router)
    if operations:
        app.include_router(operations_router)
