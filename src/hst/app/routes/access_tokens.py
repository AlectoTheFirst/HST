"""Personal access tokens, the bearer credential of the MCP HTTP transport.

Each user issues, lists and revokes their own tokens. Issuing needs
`agent.ask`, the permission that the transport checks on every request. Listing
and revoking need a session only. A user who lost `agent.ask` can revoke a token.
The token text is returned once, by the request that issues it. The store holds
only its SHA-256 hash.

The scope is chosen when a token is issued and defaults to `read`. No route
changes the scope of a token. A user who needs another scope issues a new
token and revokes the first one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from hst.app import security
from hst.app.ai.registry import TokenScope
from hst.app.auth import current_user, require_permission
from hst.app.routes import mcp_http
from hst.app.store import AccessToken, User

router = APIRouter()
require_agent_ask = require_permission("agent.ask")  # B008 forbids this call in an argument default.

# The maximum count of tokens of one user, expired tokens included. A revoked token is not counted.
MAX_TOKENS_PER_USER = 20
DEFAULT_LIFETIME_DAYS = 90
MAX_LIFETIME_DAYS = 90


class TokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100, pattern=r"\S")
    scope: TokenScope = "read"
    expires_in_days: int = Field(default=DEFAULT_LIFETIME_DAYS, ge=1, le=MAX_LIFETIME_DAYS)


def token_json(token: AccessToken, now: datetime) -> dict[str, Any]:
    return {
        "id": token.id,
        "name": token.name,
        "scope": token.scope,
        "created_at": token.created_at.isoformat(),
        "expires_at": token.expires_at.isoformat(),
        "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
        "expired": token.expires_at <= now,
    }


@router.get("/access-tokens")
async def list_tokens(request: Request, user: User = Depends(current_user)) -> dict[str, Any]:
    """The caller's tokens, newest first, and whether the MCP HTTP transport is enabled."""
    store = request.app.state.store
    now = datetime.now(UTC)
    tokens = await store.list_access_tokens(user.id)
    return {
        "tokens": [token_json(t, now) for t in tokens],
        "mcp_http_enabled": await mcp_http.http_enabled(store),
    }


@router.post("/access-tokens", status_code=201)
async def create_token(
    request: Request, body: TokenCreate, user: User = Depends(require_agent_ask)
) -> dict[str, Any]:
    """Issue a token. Only this response holds the token text."""
    store = request.app.state.store
    if len(await store.list_access_tokens(user.id)) >= MAX_TOKENS_PER_USER:
        raise HTTPException(
            409, detail=f"at most {MAX_TOKENS_PER_USER} tokens per user; revoke one to issue another"
        )
    token = security.new_session_token()
    now = datetime.now(UTC)
    row = await store.create_access_token(
        security.token_hash(token),
        user.id,
        body.name.strip(),
        body.scope,
        now + timedelta(days=body.expires_in_days),
        now,
    )
    return {**token_json(row, now), "token": token}


@router.delete("/access-tokens/{token_id}", status_code=204)
async def revoke_token(request: Request, token_id: int, user: User = Depends(current_user)) -> Response:
    """Revoke one of the caller's tokens. Another user's token id answers 404."""
    if not await request.app.state.store.delete_access_token(user.id, token_id):
        raise HTTPException(404, detail="no such token")
    return Response(status_code=204)
