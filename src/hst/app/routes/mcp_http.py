"""The MCP HTTP transport at /api/mcp, and its on/off setting.

`/api/mcp` serves the MCP streamable HTTP transport in stateless mode with
JSON responses. Each POST has one JSON-RPC message and a personal access
token as `Authorization: Bearer <token>`. The session cookie is not read.
The checks run in this order:

1. The app settings row `mcp_http` must hold `enabled: true`. Otherwise the
   path answers 404, as an unknown route does. The row is absent by default.
2. The method must be POST. A stateless server keeps no stream for GET and
   no session for DELETE. Both answer 405.
3. The bearer token must name a stored token that has not expired and whose
   user is not disabled. Otherwise 401. Revoking a token deletes its row.
4. The token's user must hold `agent.ask`. Otherwise 403.

The request then runs on an MCP server built for the token principal. The
principal has the user's permissions, resolved from the role at this request,
and the token's scope. `tools/list` lists the tools that the user may call, and
each call checks the permission again in `ToolRegistry.invoke`. The 4 write
tools are listed only for a token with scope `read-write` whose user holds
`changes.write`. A `read` token that calls one gets `forbidden`. The tool
calls use the app store. Every tool call writes an `ai_events` row, and every
Cypher query a `cypher_events` row, with origin `mcp` and the token's user.

The `mcp` package is imported when a request is served. The app starts
without the `mcp` extra, and the transport then answers 503.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, FastAPI, Request
from pydantic import BaseModel
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from hst.app import security
from hst.app.ai.registry import Principal, TokenScope
from hst.app.auth import require_permission
from hst.app.permissions import permissions_for

if TYPE_CHECKING:
    from hst.app.store import Store

log = logging.getLogger("hst.ai")

PATH = "/api/mcp"
SETTINGS_KEY = "mcp_http"
# The `mcp` package logs the start and the end of every session manager at
# INFO, and each request runs its own manager.
SESSION_MANAGER_LOGGER = "mcp.server.streamable_http_manager"

router = APIRouter()


async def http_enabled(store: Store) -> bool:
    """Whether an admin enabled the transport. An absent row means disabled."""
    row = await store.get_setting(SETTINGS_KEY)
    return row is not None and bool(row.value.get("enabled", False))


class McpSettingsBody(BaseModel):
    mcp_http_enabled: bool


@router.get("/settings/mcp", dependencies=[Depends(require_permission("settings.ai"))])
async def get_mcp_settings(request: Request) -> dict[str, bool]:
    return {"mcp_http_enabled": await http_enabled(request.app.state.store)}


@router.put("/settings/mcp", dependencies=[Depends(require_permission("settings.ai"))])
async def put_mcp_settings(request: Request, body: McpSettingsBody) -> dict[str, bool]:
    await request.app.state.store.put_setting(SETTINGS_KEY, {"enabled": body.mcp_http_enabled}, b"")
    return {"mcp_http_enabled": body.mcp_http_enabled}


def _error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


_UNAUTHORIZED = {"WWW-Authenticate": 'Bearer realm="hst"'}


class McpHttpEndpoint:
    """The ASGI app behind `/api/mcp`. The module docstring lists the checks."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        store = request.app.state.store
        response = await self._refusal(request, store)
        if isinstance(response, JSONResponse):
            await response(scope, receive, send)
            return
        await serve(response, store, scope, receive, send)

    async def _refusal(self, request: Request, store: Any) -> JSONResponse | Principal:
        """The response that refuses the request, or the principal it runs for."""
        if not await http_enabled(store):
            return _error(404, "Not Found")
        if request.method != "POST":
            return _error(405, "the MCP HTTP transport is stateless and takes POST only", {"Allow": "POST"})
        token = security.bearer_token(request.headers.get("authorization"))
        if token is None:
            return _error(401, "a personal access token is required as a bearer token", _UNAUTHORIZED)
        found = await store.get_access_token_user(security.token_hash(token), datetime.now(UTC))
        if found is None or found[1].disabled:
            return _error(401, "the token is unknown, revoked or expired", _UNAUTHORIZED)
        access_token, user = found
        if "agent.ask" not in permissions_for(user.role):
            return _error(403, "requires permission: agent.ask")
        scope: TokenScope = "read-write" if access_token.scope == "read-write" else "read"
        return Principal.for_token(user_id=user.id, role=user.role, scope=scope)


async def serve(principal: Principal, store: Any, scope: Scope, receive: Receive, send: Send) -> None:
    """Answer one request on an MCP server built for `principal`.

    The server is built per request. No identity or session outlives the
    request. The build runs in a worker thread. Registering the tools takes
    tens of milliseconds. The audit rows of the request's tool calls are
    written before `serve` returns.
    """
    try:
        from mcp.server.transport_security import TransportSecuritySettings

        from hst.mcp_server import build_server
    except ImportError as exc:
        log.warning("the MCP HTTP transport needs the mcp extra: %s", exc)
        await _error(503, "the MCP HTTP transport needs the mcp package on the server")(scope, receive, send)
        return
    from hst.app.ai.audit import McpAudit

    audit = McpAudit(store, user_id=principal.user_id)
    try:
        # the tool calls reach the app store through this request's event loop
        server = await asyncio.to_thread(
            build_server, principal, audit=audit, store=store, loop=asyncio.get_running_loop()
        )
        # The bearer token is the credential. A browser does not send it without
        # a script. The Host and Origin checks against DNS rebinding are off.
        server.streamable_http_app(
            stateless_http=True,
            json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        manager = server.session_manager
        async with manager.run():
            await manager.handle_request(scope, receive, send)
    finally:
        await audit.close()


def install(app: FastAPI) -> None:
    """Route `/api/mcp` to the transport. The route is not in the OpenAPI schema.

    The session manager logger is set to WARNING. A request adds no INFO line
    for the start and the end of its manager to the app log.
    """
    logging.getLogger(SESSION_MANAGER_LOGGER).setLevel(logging.WARNING)
    # A Route whose endpoint is not a function passes the request to it as ASGI.
    app.router.routes.append(Route(PATH, McpHttpEndpoint(), include_in_schema=False))
