"""The first-run setup creates the first admin account through the UI."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from hst.app import security

router = APIRouter()
log = logging.getLogger("hst.setup")

MIN_PASSWORD_LENGTH = 12


class SetupBody(BaseModel):
    username: str = Field(min_length=1, max_length=security.MAX_USERNAME_LENGTH)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=security.MAX_PASSWORD_LENGTH)


async def setup_required(store) -> bool:
    """True while the store holds no user of any role."""
    return not await store.list_users()


@router.get("/setup")
async def setup_status(request: Request) -> dict:
    """Report whether first-run setup is open."""
    required = await setup_required(request.app.state.store)
    return {"required": required, "min_password_length": MIN_PASSWORD_LENGTH}


@router.post("/setup", status_code=201)
async def create_first_admin(body: SetupBody, request: Request, response: Response) -> dict:
    """Create the first administrator and sign them in.

    The store serializes concurrent callers in `create_first_user`.
    """
    store = request.app.state.store
    if not await setup_required(store):
        raise HTTPException(409, detail="setup has already been completed")

    username = body.username.strip()
    if not username:
        raise HTTPException(422, detail="username cannot be blank")

    try:
        password_hash = await asyncio.to_thread(security.hash_password, body.password)
        user = await store.create_first_user(username, password_hash, "admin")
    except ValueError as exc:
        raise HTTPException(409, detail="setup has already been completed") from exc

    log.info("first-run setup completed: admin %r created", user.username)

    from hst.app.auth import issue_session

    await issue_session(request, response, user)
    return {"username": user.username, "role": user.role}
