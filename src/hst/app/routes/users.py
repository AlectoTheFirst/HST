"""Admin CRUD over accounts."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from hst.app.auth import require_permission
from hst.app.routes.access_tokens import token_json
from hst.app.routes.setup import MIN_PASSWORD_LENGTH
from hst.app.security import MAX_PASSWORD_LENGTH, hash_password
from hst.app.store import User

router = APIRouter()
USERNAME = r"^[a-z0-9_.-]{2,32}$"
require_users_manage = require_permission("users.manage")


class UserCreate(BaseModel):
    username: str = Field(pattern=USERNAME)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    role: Literal["viewer", "operator", "admin"]


class UserPatch(BaseModel):
    role: Literal["viewer", "operator", "admin"] | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    # 'mapped' alone clears a local override.
    role_source: Literal["local", "mapped"] | None = None


def _json(u: User, identities: list[str] | tuple[str, ...] = ()) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "disabled": u.disabled,
        "created_at": u.created_at.isoformat(),
        "role_source": u.role_source,
        "has_password": u.password_hash is not None,
        "identities": list(identities),
    }


async def _identities_by_user(store, user_ids: list[int]) -> dict[int, list[str]]:
    """Map each user id to the sorted names of its identity providers. An
    account without an identity has no entry."""
    idents = await store.list_identities_for_users(user_ids)
    if not idents:
        return {}
    providers = {p.id: p.name for p in await store.list_auth_providers()}
    grouped: dict[int, set[str]] = {}
    for i in idents:
        grouped.setdefault(i.user_id, set()).add(providers.get(i.provider_id, "?"))
    return {uid: sorted(names) for uid, names in grouped.items()}


@router.get("/users")
async def list_users(request: Request, admin: User = Depends(require_users_manage)) -> dict:
    store = request.app.state.store
    users = await store.list_users()
    by_user = await _identities_by_user(store, [u.id for u in users])
    return {"users": [_json(u, by_user.get(u.id, [])) for u in users]}


@router.post("/users", status_code=201)
async def create_user(
    request: Request, body: UserCreate, admin: User = Depends(require_users_manage)
) -> dict:
    try:
        password_hash = await asyncio.to_thread(hash_password, body.password)
        u = await request.app.state.store.create_user(body.username, password_hash, body.role)
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    # a new account has no identities
    return _json(u, [])


@router.patch("/users/{user_id}")
async def patch_user(
    request: Request, user_id: int, body: UserPatch, admin: User = Depends(require_users_manage)
) -> dict:
    if user_id == admin.id and (body.disabled is True or (body.role is not None and body.role != "admin")):
        raise HTTPException(400, detail="you cannot disable or demote yourself")
    store = request.app.state.store
    password_hash = await asyncio.to_thread(hash_password, body.password) if body.password else None
    role_source = "local" if body.role is not None else body.role_source
    u = await store.update_user(
        user_id,
        role=body.role,
        disabled=body.disabled,
        password_hash=password_hash,
        role_source=role_source,
    )
    if u is None:
        raise HTTPException(404, detail=f"no user {user_id}")
    identities = (await _identities_by_user(store, [u.id])).get(u.id, [])
    return _json(u, identities)


@router.delete("/users/{user_id}/sessions")
async def revoke_sessions(
    request: Request, user_id: int, admin: User = Depends(require_users_manage)
) -> dict:
    """Revoke the sessions and the personal access tokens of an account."""
    store = request.app.state.store
    if await store.get_user(user_id) is None:
        raise HTTPException(404, detail=f"no user {user_id}")
    sessions = await store.delete_user_sessions(user_id)
    return {"revoked": sessions, "revoked_tokens": await store.delete_user_access_tokens(user_id)}


@router.get("/users/{user_id}/access-tokens")
async def list_user_tokens(
    request: Request, user_id: int, admin: User = Depends(require_users_manage)
) -> dict[str, Any]:
    """List the personal access tokens of another account, newest first. The
    response holds no token text. The store holds only the hash of a token."""
    store = request.app.state.store
    if await store.get_user(user_id) is None:
        raise HTTPException(404, detail=f"no user {user_id}")
    now = datetime.now(UTC)
    return {"tokens": [token_json(t, now) for t in await store.list_access_tokens(user_id)]}


@router.delete("/users/{user_id}/access-tokens/{token_id}", status_code=204)
async def revoke_user_token(
    request: Request, user_id: int, token_id: int, admin: User = Depends(require_users_manage)
) -> Response:
    """Revoke one token of another account."""
    if not await request.app.state.store.delete_access_token(user_id, token_id):
        raise HTTPException(404, detail="no such token")
    return Response(status_code=204)
