"""Application registration and the versioned inventory activation boundary."""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute

from hst.app.auth import current_user
from hst.app.inventory.collection import has_inventory
from hst.app.inventory.contracts import API_PREFIX, ROUTE_PERMISSIONS, ActivationState
from hst.app.inventory.startup import (  # noqa: F401 - re-exported
    SUPPORTED_RESOLVER,
    compatible,
    initialize_fresh,
    start_for,
)
from hst.app.permissions import permissions_for
from hst.app.store import User


async def require_inventory(request: Request, user: Annotated[User, Depends(current_user)]) -> None:
    path = request.scope["route"].path.removeprefix(API_PREFIX)
    normalized = re.sub(r"\{[^}]+\}", "{id}", path)
    permission = ROUTE_PERMISSIONS.get((request.method, normalized), "graph.read")
    if normalized == "/profiles/{id}/versions":
        permission = "sources.write"
    if permission not in permissions_for(user.role):
        raise HTTPException(403, detail=f"requires permission: {permission}")
    store = request.app.state.store
    if not has_inventory(store):
        raise HTTPException(503, detail="inventory storage is unavailable")
    async with store.inventory().transaction() as tx:
        state = await tx.get_state()
    if state.resolver_version > SUPPORTED_RESOLVER:
        raise HTTPException(503, detail="inventory requires a newer application version")
    if path != "/state" and (
        state.activation_state != ActivationState.ACTIVE.value or state.resolver_version != SUPPORTED_RESOLVER
    ):
        raise HTTPException(503, detail="inventory has not been initialized")


def register(app: FastAPI) -> None:
    from hst.app.inventory import connection_routes, inventory_routes, profile_routes, routing_routes

    connection_routes.install_error_handlers(app)
    app.add_exception_handler(inventory_routes.InventoryError, inventory_routes._handle_inventory_error)
    guarded = APIRouter(dependencies=[Depends(require_inventory)])
    guarded.include_router(connection_routes.router)
    guarded.include_router(profile_routes.router)
    for router in inventory_routes.ROUTERS:
        if router is inventory_routes.router:
            selected = APIRouter()
            selected.routes.extend(
                route
                for route in router.routes
                if isinstance(route, APIRoute) and not route.path.startswith("/operations/")
            )
            guarded.include_router(selected, prefix=API_PREFIX)
        else:
            guarded.include_router(router, prefix=API_PREFIX)
    guarded.include_router(routing_routes.router)
    app.include_router(guarded)


async def start(app: FastAPI) -> None:
    from hst.app.inventory.observations import context_for

    await start_for(app.state.store, app.state.settings, lambda: context_for(app))
