"""Login, sessions, and the two dependencies every protected route uses."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import APIKeyCookie
from pydantic import BaseModel, Field

from hst.app import security, sso_flow
from hst.app.permissions import permissions_for
from hst.app.store import User

COOKIE = "hst_session"
_session_cookie = APIKeyCookie(
    name=COOKIE,
    scheme_name="SessionCookie",
    description="HttpOnly session cookie from the HST sign-in",
    auto_error=False,
)
_BURNER_HASH = security.hash_password("no-such-user")
TOO_MANY_ATTEMPTS = "too many attempts"
router = APIRouter()
log = logging.getLogger("hst.auth")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=security.MAX_USERNAME_LENGTH)
    password: str = Field(max_length=security.MAX_PASSWORD_LENGTH)


def _now() -> datetime:
    return datetime.now(UTC)


def source_address(request: Request) -> str:
    """The caller's address for the login-events audit trail, or "" when the
    request has no client.
    """
    return request.client.host if request.client else ""


async def record_login_event(
    store, *, username: str, user_id: int | None, provider: str, outcome: str, source: str
) -> None:
    """Record one login event. A write failure does not change the login outcome."""
    try:
        await store.record_login_event(
            username=username, user_id=user_id, provider=provider, outcome=outcome, source=source, at=_now()
        )
    except Exception:
        log.warning("failed to record login event (provider=%r outcome=%r)", provider, outcome, exc_info=True)


async def issue_session(
    request: Request, response: Response, user, *, provider_id: int | None = None
) -> None:
    """Create a session row and set the cookie.

    `provider_id` is the auth provider of an SSO login. The call raises
    `sso_flow.SsoLoginError` and sets no cookie when that provider no longer
    exists or is disabled.

    `secure` follows the request scheme. Behind a trusted proxy (HST_FORWARDED_ALLOW_IPS),
    uvicorn takes the scheme from X-Forwarded-Proto. COOKIE_SECURE=true forces `secure` on.
    """
    app = request.app
    store = app.state.store
    token = security.new_session_token()
    tok_hash = security.token_hash(token)
    ttl = timedelta(hours=app.state.settings.session_ttl_hours)
    now = _now()
    if provider_id is None:
        await store.create_session(tok_hash, user.id, now + ttl, now)
    elif not await store.create_provider_session(tok_hash, user.id, provider_id, now + ttl, now):
        raise sso_flow.SsoLoginError("the provider was deleted or disabled during the login")
    response.set_cookie(
        COOKIE,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https" or app.state.settings.cookie_secure,
    )


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response) -> dict:
    app = request.app
    store = app.state.store
    host = request.client.host if request.client else "?"
    source = source_address(request)
    # The attempt takes one unit in each of 3 buckets:
    #
    #  - (username, ip) is the strict one.
    #  - ip bounds one host walking a list of usernames.
    #  - username alone has a limit 10 times the strict one.
    #
    # Each key is a tuple that starts with the name of its bucket.
    #
    # No await stands between the start of the handler and `reserve`. A failed
    # attempt keeps its units. A successful login gives them back.
    limiter = app.state.limiter
    reservation = limiter.reserve(
        (
            (("user-ip", body.username, host), None),
            (("ip", host), None),
            (("user", body.username), limiter.limit * 10),
        )
    )
    if reservation.full is not None:
        # One row per bucket per window (`note_once`).
        if limiter.note_once(reservation.full):
            await record_login_event(
                store,
                username=body.username,
                user_id=None,
                provider="local",
                outcome="rate_limited",
                source=source,
            )
        raise HTTPException(429, detail=TOO_MANY_ATTEMPTS)
    # With local login off, `user` stays None and the request takes the
    # unknown-user path below.
    try:
        local_login_on = await sso_flow.local_login_enabled(store)
        user = await store.get_user_by_username(body.username) if local_login_on else None
    except BaseException:
        # No password was verified.
        limiter.release(reservation)
        raise
    # Unknown users and users with no password hash verify against a precomputed
    # burner hash.
    ok = await asyncio.to_thread(
        security.verify_password, (user.password_hash if user else None) or _BURNER_HASH, body.password
    )
    if not ok or user is None or user.disabled or not user.password_hash:
        # The 401 has the same body and timing in every case. Unknown user, wrong
        # password and null hash are recorded as "bad_credentials".
        if not local_login_on:
            outcome = "local_login_disabled"
        elif user is not None and user.disabled:
            outcome = "disabled"
        else:
            outcome = "bad_credentials"
        await record_login_event(
            store, username=body.username, user_id=None, provider="local", outcome=outcome, source=source
        )
        raise HTTPException(401, detail="invalid credentials")
    limiter.release(reservation)
    await issue_session(request, response, user)
    await record_login_event(
        store, username=user.username, user_id=user.id, provider="local", outcome="ok", source=source
    )
    return {"username": user.username, "role": user.role}


async def current_user(request: Request, token: Annotated[str | None, Depends(_session_cookie)]) -> User:
    user = None
    if token:
        # A session has 2 expiries. The absolute expiry is the one the cookie was
        # issued with. The idle expiry is measured from the last use of the
        # session. The store applies both and moves the last-use mark forward,
        # throttled, when it accepts the session.
        user = await request.app.state.store.get_session_user(
            security.token_hash(token), _now(), security.idle_after(request.app.state.settings)
        )
    if user is None or user.disabled:
        raise HTTPException(401, detail="not authenticated")
    return user


def require_permission(name: str):
    """A route dependency gating on a named permission.

    The user's role resolves to its permission set (app/permissions.py) on every
    call.
    """

    async def dep(user: User = Depends(current_user)) -> User:
        if name not in permissions_for(user.role):
            raise HTTPException(403, detail=f"requires permission: {name}")
        return user

    return dep


@router.post("/logout", status_code=204)
async def logout(request: Request) -> Response:
    """Delete the session row of the cookie, clear the cookie and answer 204.

    The call is idempotent and needs no valid session.
    """
    # The handler returns an explicit Response. A 204 has no body, and the
    # cookie deletion is a header on that response.
    response = Response(status_code=204)
    token = request.cookies.get(COOKIE)
    if token:
        await request.app.state.store.delete_session(security.token_hash(token))
    response.delete_cookie(COOKIE)
    return response


@router.get("/me")
async def me(user: User = Depends(current_user)) -> dict:
    return _me_payload(user)


# The palette names that theme.css of the SPA defines. web/src/shell/theme.ts holds the same set.
THEMES = frozenset({"light", "dark", "system", "dracula", "catppuccin", "tokyo-night", "nord"})


class MePatch(BaseModel):
    """The self-service fields. `theme` is validated against THEMES in the handler."""

    theme: str | None = None


@router.patch("/me")
async def patch_me(request: Request, body: MePatch, user: User = Depends(current_user)) -> dict:
    """Self-service preferences."""
    if body.theme not in THEMES:
        raise HTTPException(400, detail=f"theme must be one of {', '.join(sorted(THEMES))}")
    updated = await request.app.state.store.set_user_theme(user.id, body.theme)
    return _me_payload(updated or user)


def _me_payload(user: User) -> dict:
    return {
        "username": user.username,
        "role": user.role,
        "permissions": sorted(permissions_for(user.role)),
        "theme": user.theme,
    }
