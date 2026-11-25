"""Public SSO endpoints. They are the provider list of the login page and the
login and callback routes of each protocol."""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from hst.app import saml_flow, sso_flow
from hst.app.auth import TOO_MANY_ATTEMPTS, issue_session, record_login_event, source_address
from hst.app.security import Reservation

router = APIRouter(prefix="/auth")
log = logging.getLogger("hst.sso")

STATE_COOKIE = "hst_sso_state"
STATE_COOKIE_PATH = "/api/auth"
# The cookie holds the id of the pending AuthnRequest in the browser that
# started the SAML login. The cookie is SameSite=None for the cross-site POST
# of the IdP to the ACS. Its path is the ACS path of the provider.
SAML_REQUEST_COOKIE = "hst_saml_req"
LOGIN_START_LIMIT_FACTOR = 10


def _acs_path(name: str) -> str:
    return f"/api/auth/{name}/acs"


def _reserve(request: Request, bucket: str) -> Reservation:
    """Take one unit of the client address in `bucket`. Raises a 429 when the bucket is full.

    The limit is `LOGIN_START_LIMIT_FACTOR` times the login limit.
    """
    limiter = request.app.state.limiter
    host = request.client.host if request.client else "?"
    reservation: Reservation = limiter.reserve((((bucket, host), limiter.limit * LOGIN_START_LIMIT_FACTOR),))
    if reservation.full is not None:
        raise HTTPException(429, detail=TOO_MANY_ATTEMPTS)
    return reservation


def _external_url(request: Request, route: str, name: str) -> str:
    """Raises a 503 when the setting `public_url` is empty."""
    try:
        return sso_flow.external_url(request.app, route, name=name)
    except sso_flow.PublicUrlNotSet as exc:
        log.warning("%s %s refused: %s", request.method, request.url.path, exc)
        raise HTTPException(503, detail=str(exc)) from exc


def _saml_urls(request: Request, name: str) -> tuple[str, str]:
    """Return the entity id and the ACS URL of the provider `name`."""
    return _external_url(request, "saml_metadata", name), _external_url(request, "saml_acs", name)


@router.get("/providers")
async def list_providers(request: Request) -> dict:
    store = request.app.state.store
    providers = [p for p in await store.list_auth_providers() if p.enabled]
    return {
        "providers": [
            {"name": p.name, "kind": p.kind, "label": p.config.get("label") or p.name} for p in providers
        ],
        "local_login_enabled": await sso_flow.local_login_enabled(store),
    }


@router.get("/{name}/login")
async def start_login(name: str, request: Request) -> RedirectResponse:
    _reserve(request, "sso-start")
    store = request.app.state.store
    provider = await store.get_auth_provider(name)
    if provider is None or not provider.enabled:
        raise HTTPException(404, detail=f"no such provider: {name}")
    if provider.kind == "saml":
        return await _start_saml_login(provider, request, store)
    if provider.kind != "oidc":
        raise HTTPException(501, detail=f"{provider.kind} login is not supported")
    discovery = provider.config.get(sso_flow.DISCOVERY_KEY)
    if not discovery:
        log.warning("provider %r is enabled but has no cached discovery", name)
        raise HTTPException(404, detail=f"no such provider: {name}")
    redirect_uri = _external_url(request, "sso_callback", name)

    verifier = secrets.token_urlsafe(48)
    nonce = secrets.token_urlsafe(24)
    state_id = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    await store.create_auth_state(
        state_id,
        provider.id,
        sso_flow.STATE_KIND,
        {"nonce": nonce, "code_verifier": verifier},
        now + sso_flow.AUTH_STATE_TTL,
    )
    scope = provider.config.get("scope") or "openid profile email"
    url = sso_flow.build_authorization_url(
        discovery,
        client_id=provider.config.get("client_id", ""),
        redirect_uri=redirect_uri,
        state=state_id,
        nonce=nonce,
        code_challenge=sso_flow.pkce_challenge(verifier),
        scope=scope,
    )
    resp = RedirectResponse(url=url, status_code=302)
    resp.set_cookie(
        STATE_COOKIE,
        state_id,
        max_age=300,
        httponly=True,
        samesite="lax",
        path=STATE_COOKIE_PATH,
        secure=request.url.scheme == "https" or request.app.state.settings.cookie_secure,
    )
    return resp


@router.get("/{name}/callback", name="sso_callback")
async def callback(name: str, request: Request) -> RedirectResponse:
    """A successful login sets the session cookie through `issue_session` and
    redirects with 302 to "/". A failed login redirects with 302 to
    "/login?error=sso", and the URL holds no detail. The state cookie is
    cleared in both cases. An empty setting `public_url` gives 503.
    """
    store, settings = request.app.state.store, request.app.state.settings
    provider = await store.get_auth_provider(name)
    resp = RedirectResponse(url="/login?error=sso", status_code=302)
    source = source_address(request)
    if provider is None or not provider.enabled or provider.kind != "oidc":
        log.warning("sso callback for unknown, disabled, or non-oidc provider %r", name)
        await record_login_event(
            store, username="", user_id=None, provider=name, outcome="unknown_provider", source=source
        )
    else:
        redirect_uri = _external_url(request, "sso_callback", name)
        signed_in = RedirectResponse(url="/", status_code=302)
        try:
            user = await sso_flow.complete_oidc_login(
                store=store,
                settings=settings,
                provider=provider,
                request=request,
                state_cookie_value=request.cookies.get(STATE_COOKIE),
                redirect_uri=redirect_uri,
            )
            await issue_session(request, signed_in, user, provider_id=provider.id)
        except sso_flow.SsoLoginError as exc:
            log.warning("sso callback failed for provider %r: %s", name, exc)
            await record_login_event(
                store, username="", user_id=None, provider=name, outcome="failed", source=source
            )
        except Exception as exc:
            log.warning("sso callback failed for provider %r: %s: %s", name, type(exc).__name__, exc)
            await record_login_event(
                store, username="", user_id=None, provider=name, outcome="failed", source=source
            )
        else:
            resp = signed_in
            await record_login_event(
                store, username=user.username, user_id=user.id, provider=name, outcome="ok", source=source
            )
    resp.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
    return resp


# --- SAML ----------------------------------------------------------------------


async def _start_saml_login(provider, request: Request, store) -> RedirectResponse:
    """Start an SP-initiated login with a signed AuthnRequest in the redirect
    binding. The pending request id goes into the auth_state table with a
    5-minute expiry. The ACS accepts the response only from the browser that
    started the login.
    """
    if not saml_flow.saml_metadata_ok(provider.config):
        log.warning("provider %r is enabled but has no cached SAML metadata", provider.name)
        raise HTTPException(404, detail=f"no such provider: {provider.name}")

    entity_id, acs_url = _saml_urls(request, provider.name)
    try:
        redirect_url, request_id = await saml_flow.start_login(
            provider=provider, settings=request.app.state.settings, entity_id=entity_id, acs_url=acs_url
        )
    except sso_flow.SsoLoginError as exc:
        log.warning("could not start SAML login for provider %r: %s", provider.name, exc)
        raise HTTPException(404, detail=f"no such provider: {provider.name}") from exc

    now = datetime.now(UTC)
    await store.create_auth_state(
        request_id, provider.id, saml_flow.REQUEST_KIND, {}, now + sso_flow.AUTH_STATE_TTL
    )
    resp = RedirectResponse(url=redirect_url, status_code=302)
    resp.set_cookie(
        SAML_REQUEST_COOKIE,
        request_id,
        max_age=int(sso_flow.AUTH_STATE_TTL.total_seconds()),
        httponly=True,
        # A browser drops a SameSite=None cookie that is not Secure. A SAML
        # login needs HTTPS at the browser.
        samesite="none",
        path=_acs_path(provider.name),
        secure=request.url.scheme == "https" or request.app.state.settings.cookie_secure,
    )
    return resp


@router.post("/{name}/acs", name="saml_acs")
async def acs(name: str, request: Request) -> RedirectResponse:
    """The assertion consumer service receives a cross-site POST from the IdP.
    The csrf_guard of app/main.py exempts its exact path from the X-HST-CSRF
    check. A successful login sets the session cookie through `issue_session`
    and redirects with 302 to "/". A failed login redirects with 302 to
    "/login?error=sso", and the URL holds no detail. An empty setting
    `public_url` gives 503. A request without the `hst_saml_req` cookie fails
    before the form is read. A client address over its limit gets 429, and a
    successful login gives its unit back.
    """
    reservation = _reserve(request, "saml-acs")
    store, settings = request.app.state.store, request.app.state.settings
    provider = await store.get_auth_provider(name)
    resp = RedirectResponse(url="/login?error=sso", status_code=302)
    source = source_address(request)
    if provider is None or not provider.enabled or provider.kind != "saml":
        log.warning("SAML ACS for unknown, disabled, or non-saml provider %r", name)
        await record_login_event(
            store, username="", user_id=None, provider=name, outcome="unknown_provider", source=source
        )
        return resp

    entity_id, acs_url = _saml_urls(request, name)
    bound = request.cookies.get(SAML_REQUEST_COOKIE)
    if not bound:
        log.warning("SAML ACS for provider %r carried no %s cookie", name, SAML_REQUEST_COOKIE)
        await record_login_event(
            store, username="", user_id=None, provider=name, outcome="failed", source=source
        )
        return resp
    form = await request.form()
    saml_response_b64 = form.get("SAMLResponse")
    if not saml_response_b64 or not isinstance(saml_response_b64, str):
        log.warning("SAML ACS for provider %r carried no SAMLResponse field", name)
        await record_login_event(
            store, username="", user_id=None, provider=name, outcome="failed", source=source
        )
        return resp

    signed_in = RedirectResponse(url="/", status_code=302)
    try:
        user = await saml_flow.complete_saml_login(
            store=store,
            settings=settings,
            provider=provider,
            entity_id=entity_id,
            acs_url=acs_url,
            saml_response_b64=saml_response_b64,
            bound=bound,
        )
        await issue_session(request, signed_in, user, provider_id=provider.id)
    except sso_flow.SsoLoginError as exc:
        log.warning("SAML ACS failed for provider %r: %s", name, exc)
        await record_login_event(
            store, username="", user_id=None, provider=name, outcome="failed", source=source
        )
    except Exception as exc:
        log.warning("SAML ACS failed for provider %r: %s: %s", name, type(exc).__name__, exc)
        await record_login_event(
            store, username="", user_id=None, provider=name, outcome="failed", source=source
        )
    else:
        resp = signed_in
        request.app.state.limiter.release(reservation)
        await record_login_event(
            store, username=user.username, user_id=user.id, provider=name, outcome="ok", source=source
        )
    resp.delete_cookie(SAML_REQUEST_COOKIE, path=_acs_path(name))
    return resp


@router.get("/{name}/metadata", name="saml_metadata")
async def metadata(name: str, request: Request) -> Response:
    """Return the SP metadata XML for the setup of the IdP. It holds the entity
    id, the ACS URL and the SP certificate. The entity id is the URL of this
    route under the setting `public_url`.
    A client address over its limit gets 429.
    """
    _reserve(request, "saml-metadata")
    store = request.app.state.store
    provider = await store.get_auth_provider(name)
    if provider is None or not provider.enabled or provider.kind != "saml":
        raise HTTPException(404, detail=f"no such provider: {name}")
    sp_cert_pem = provider.config.get(saml_flow.SP_CERT_CONFIG_KEY, "")
    if not sp_cert_pem:
        log.warning("provider %r is enabled but has no SP certificate", name)
        raise HTTPException(404, detail=f"no such provider: {name}")
    entity_id, acs_url = _saml_urls(request, name)
    xml = await asyncio.to_thread(
        saml_flow.build_sp_metadata_xml, entity_id=entity_id, acs_url=acs_url, sp_cert_pem=sp_cert_pem
    )
    return Response(content=xml, media_type="application/xml")
