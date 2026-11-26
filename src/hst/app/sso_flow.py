"""OIDC discovery, PKCE, ID-token validation and the group-to-role resolution
at each SSO login."""

from __future__ import annotations

import logging
import re
import warnings
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx

from hst.app import crypto, egress, tls
from hst.app.crypto import SecretKeyError, decrypt_secrets
from hst.app.store import ROLES, GroupMapping, Identity, IdentityOwnerMissing, User
from hst.app.tls import Trust

# authlib.jose raises a DeprecationWarning at its first import.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from authlib.jose import jwt as _jwt
    from authlib.jose.errors import JoseError

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.applications import Starlette

    from hst.app.store import AuthProvider, Store
    from hst.core import Settings

log = logging.getLogger("hst.sso")

# app/routes/auth_settings.py strips the private config keys from responses.
DISCOVERY_KEY = "_discovery"
JWKS_KEY = "_jwks"

# The auth_state.kind of the row that holds the nonce and the PKCE verifier of
# a pending OIDC login.
STATE_KIND = "oidc"
AUTH_STATE_TTL = timedelta(minutes=5)
# The clock-drift tolerance for the exp and iat of the ID token is in seconds.
CLOCK_SKEW_S = 60

LOCAL_LOGIN_KEY = "auth.local_login_enabled"
# The config key of the group that each login of a provider must have.
REQUIRED_GROUP = "required_group"
DEFAULT_SCOPE = "openid profile email"

_USERNAME_JUNK = re.compile(r"[^a-z0-9_.-]+")


class SsoLoginError(Exception):
    """A reason an OIDC callback did not end in a session."""


class PublicUrlNotSet(Exception):
    """The setting `public_url` is empty."""


def external_url(app: Starlette, route: str, **path_params: str) -> str:
    """The URL of the named route under the setting `public_url`.

    Raises `PublicUrlNotSet` when the setting is empty.
    """
    public_url = app.state.settings.public_url
    if not public_url:
        raise PublicUrlNotSet("HST_PUBLIC_URL is not set")
    return public_url + str(app.url_path_for(route, **path_params))


async def warn_if_public_url_missing(store: Store, settings: Settings) -> None:
    """Log one warning when the setting `public_url` is empty and an auth provider is enabled."""
    if settings.public_url:
        return
    enabled = [p.name for p in await store.list_auth_providers() if p.enabled]
    if enabled:
        log.warning("HST_PUBLIC_URL is not set. The SSO routes of %s answer 503.", ", ".join(enabled))


class _JwksKeyMiss(Exception):
    """The `kid` of the ID token is not in the JWKS used to validate it.

    On this error the caller refetches discovery and retries once.
    """


# --- local-login toggle -----------------------------------------------------


async def local_login_enabled(store: Store) -> bool:
    """An absent setting means enabled."""
    row = await store.get_setting(LOCAL_LOGIN_KEY)
    if row is None:
        return True
    return bool(row.value.get("enabled", True))


# --- outbound HTTP, swappable for tests -------------------------------------


def _transport() -> httpx.AsyncBaseTransport | None:
    """The transport of `_client`. None selects the default transport of httpx."""
    return None


def _client(trust: Trust) -> httpx.AsyncClient:
    """An installed test transport ignores `trust`."""
    return httpx.AsyncClient(transport=_transport(), timeout=10.0, verify=trust.ssl_verify())


# --- discovery ---------------------------------------------------------------


async def discover(issuer: str, *, trust: Trust) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fetch the discovery document of `issuer` and its JWKS.

    A URL that fails the https check of app/egress.py raises ValueError.
    A discovery document with an `issuer` other than `issuer` raises ValueError.
    """
    egress.check_https_url(issuer, what="issuer")
    async with _client(trust) as client:
        resp = await client.get(issuer.rstrip("/") + "/.well-known/openid-configuration")
        resp.raise_for_status()
        doc: dict[str, Any] = resp.json()
        if doc.get("issuer") != issuer:
            raise ValueError(
                f"issuer {issuer!r} is not the issuer {doc.get('issuer')!r} of the discovery document"
            )
        for field_name in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"):
            url = doc.get(field_name)
            if url:
                egress.check_https_url(url, what=field_name)
        jwks_uri = doc["jwks_uri"]
        jwks_resp = await client.get(jwks_uri)
        jwks_resp.raise_for_status()
        jwks: dict[str, Any] = jwks_resp.json()
    return doc, jwks


async def refresh_discovery(config: dict[str, Any], *, trust: Trust) -> tuple[dict[str, Any], bool]:
    """Fetch discovery and JWKS for an OIDC provider config and cache them
    under the private config keys. Returns the config to store and whether
    the fetch succeeded.

    A scheme violation or an issuer mismatch raises ValueError. On any other
    failure, the returned config has no cache.
    """
    issuer = config.get("issuer") or ""
    try:
        doc, jwks = await discover(issuer, trust=trust)
    except ValueError:
        raise
    except Exception as exc:
        log.info("discovery fetch failed for issuer %r: %s: %s", issuer, type(exc).__name__, exc)
        stripped = {k: v for k, v in config.items() if k not in (DISCOVERY_KEY, JWKS_KEY)}
        return stripped, False
    new_config = dict(config)
    new_config[DISCOVERY_KEY] = doc
    new_config[JWKS_KEY] = jwks
    return new_config, True


def discovery_ok(config: dict[str, Any]) -> bool:
    return bool(config.get(DISCOVERY_KEY)) and bool(config.get(JWKS_KEY))


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    """The config without the keys that start with an underscore."""
    return {k: v for k, v in config.items() if not k.startswith("_")}


def validate_required_group(config: dict[str, Any]) -> None:
    """Raise ValueError unless `required_group` is absent or a string."""
    value = config.get(REQUIRED_GROUP)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"config.{REQUIRED_GROUP} must be a string")


def validate_oidc_config(config: dict[str, Any]) -> None:
    """Shape check of an OIDC config before a save runs discovery."""
    if not isinstance(config.get("issuer"), str) or not config["issuer"]:
        raise ValueError("config.issuer is required")
    if not isinstance(config.get("client_id"), str) or not config["client_id"]:
        raise ValueError("config.client_id is required")
    default_role = config.get("default_role", "viewer")
    allowed = (*ROLES, "none")
    if default_role not in allowed:
        raise ValueError(f"config.default_role must be one of {', '.join(allowed)}")
    validate_required_group(config)
    scope = config.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise ValueError("config.scope must be a string")
    if scope and "openid" not in scope.split():
        raise ValueError("config.scope must include openid")
    if config.get(tls.CA_BUNDLE):
        tls.validate_ca_bundle(config[tls.CA_BUNDLE], what=f"config.{tls.CA_BUNDLE}")


# --- authorization request ----------------------------------------------------


def pkce_challenge(verifier: str) -> str:
    digest = sha256(verifier.encode()).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode()


def build_authorization_url(
    discovery: dict[str, Any],
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    scope: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return discovery["authorization_endpoint"] + "?" + urlencode(params)


# --- token exchange, userinfo, ID token validation -----------------------------


async def _exchange_code(
    discovery: dict[str, Any],
    *,
    client_id: str,
    client_secret: str,
    code: str,
    verifier: str,
    redirect_uri: str,
    trust: Trust,
) -> dict[str, Any]:
    token_endpoint = discovery["token_endpoint"]
    methods = discovery.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
        "client_id": client_id,
    }
    kwargs: dict[str, Any] = {"data": data}
    if "client_secret_basic" in methods:
        kwargs["auth"] = httpx.BasicAuth(client_id, client_secret)
    else:
        data["client_secret"] = client_secret
    async with _client(trust) as client:
        resp = await client.post(token_endpoint, **kwargs)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
    return result


async def _fetch_userinfo(discovery: dict[str, Any], access_token: str, *, trust: Trust) -> dict[str, Any]:
    endpoint = discovery.get("userinfo_endpoint")
    if not endpoint or not access_token:
        return {}
    async with _client(trust) as client:
        resp = await client.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
    return result


def _validate_id_token(
    id_token: str, jwks: dict[str, Any], *, issuer: str, client_id: str, nonce: str
) -> dict[str, Any]:
    """Check the signature against the JWKS, then the issuer, the audience
    and the expiry with a leeway of `CLOCK_SKEW_S`, then the nonce.

    A `kid` that is not in the JWKS raises `_JwksKeyMiss`.
    """
    claims_options = {
        "iss": {"essential": True, "value": issuer},
        "aud": {"essential": True, "value": client_id},
        "exp": {"essential": True},
    }
    try:
        claims = _jwt.decode(id_token, jwks, claims_options=claims_options)
    except ValueError as exc:
        # authlib.jose raises a plain ValueError ("Invalid JSON Web Key Set")
        # when the kid of the token matches no key in the set.
        raise _JwksKeyMiss(str(exc)) from exc
    claims.validate(leeway=CLOCK_SKEW_S)
    if claims.get("nonce") != nonce:
        raise SsoLoginError("id token nonce does not match the login attempt")
    return dict(claims)


def _decode_with_refresh_on_miss(
    id_token: str, jwks: dict[str, Any], *, issuer: str, client_id: str, nonce: str
) -> dict[str, Any]:
    """Raises `SsoLoginError` for a JoseError from `_validate_id_token`."""
    try:
        return _validate_id_token(id_token, jwks, issuer=issuer, client_id=client_id, nonce=nonce)
    except JoseError as exc:
        raise SsoLoginError(f"id token invalid: {exc}") from exc


# --- username and role resolution ---------------------------------------------


def _base_username(preferred_username: str | None, email: str, subject: str) -> str:
    raw = (preferred_username or (email.split("@")[0] if email else "") or subject or "user").lower()
    cleaned = _USERNAME_JUNK.sub("-", raw).strip("-._")
    return cleaned[:28] or "user"


async def _unique_username(store: Store, base: str) -> str:
    candidate = base
    suffix = 2
    while await store.get_user_by_username(candidate):
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


def _resolve_role(
    mappings: list[GroupMapping], groups: set[str], default_role: str
) -> tuple[str | None, bool]:
    """(role, should_disable) for a 'mapped' account."""
    matches = [m.role for m in mappings if m.group_name in groups]
    if matches:
        return max(matches, key=ROLES.index), False
    if default_role == "none":
        return None, True
    return default_role, False


# --- shared provisioning, protocol-neutral -----------------------------------


async def provision_and_authorize(
    *,
    store: Store,
    provider: AuthProvider,
    subject: str,
    email: str,
    preferred_username: str | None,
    groups: set[str],
) -> tuple[User, Identity]:
    """Provisioning and role resolution of one login,
    for OIDC (`complete_oidc_login`) and SAML
    (`complete_saml_login` in app/saml_flow.py).

    Raises SsoLoginError if login is refused.
    """
    # The check runs before the account lookup. A login that it refuses
    # creates no account and changes no account.
    required_group = provider.config.get(REQUIRED_GROUP)
    if required_group and required_group not in groups:
        raise SsoLoginError(
            f"the groups of subject {subject!r} do not include the required group {required_group!r}"
        )

    identity = await store.get_identity(provider.id, subject)
    is_new = identity is None
    if identity is None:
        base = _base_username(preferred_username, email, subject)
        username = await _unique_username(store, base)
        # No identity links to an existing local account by email.
        try:
            user, identity = await store.create_user_with_identity(
                username, "viewer", provider.id, subject, email=email
            )
        except IdentityOwnerMissing as exc:
            raise SsoLoginError(f"provider {provider.name!r} was deleted during the login") from exc
        log.info("provisioned user %r from provider %r (sub=%r)", username, provider.name, subject)
    else:
        found = await store.get_user(identity.user_id)
        if found is None:
            raise SsoLoginError("identity refers to a missing user")
        user = found

    if is_new or user.role_source == "mapped":
        mappings = await store.list_group_mappings(provider.id)
        role, should_disable = _resolve_role(mappings, groups, provider.config.get("default_role", "viewer"))
        updated = await store.update_user(
            user.id,
            role=role or ("viewer" if is_new else None),
            disabled=True if should_disable else None,
            role_source="mapped",
        )
        if updated is not None:
            user = updated

    if user.disabled:
        raise SsoLoginError(f"account {user.username!r} is disabled")

    return user, identity


# --- the full callback ----------------------------------------------------------


async def complete_oidc_login(
    *,
    store: Store,
    settings: Settings,
    provider: AuthProvider,
    request: Request,
    state_cookie_value: str | None,
    redirect_uri: str,
) -> User:
    """Callback validation and provisioning of an OIDC login.
    Returns the user to sign in. Raises `SsoLoginError` for each rejection.

    `redirect_uri` is the value the authorization request sent.
    """
    if state_cookie_value is None:
        raise SsoLoginError("no state cookie on the callback request")
    idp_error = request.query_params.get("error")
    if idp_error:
        raise SsoLoginError(f"idp returned error: {idp_error}")
    if request.query_params.get("state") != state_cookie_value:
        raise SsoLoginError("state parameter does not match the state cookie")
    code = request.query_params.get("code")
    if not code:
        raise SsoLoginError("no authorization code in the callback")

    now = datetime.now(UTC)
    row = await store.consume_auth_state(state_cookie_value, STATE_KIND, provider.id, now)
    if row is None:
        raise SsoLoginError("no pending login of this provider has the state, or it expired or was used")

    config = provider.config
    discovery = config.get(DISCOVERY_KEY)
    jwks = config.get(JWKS_KEY)
    if not discovery or not jwks:
        raise SsoLoginError(f"provider {provider.name!r} has no cached discovery")

    client_id = config.get("client_id", "")
    key = crypto.dek(settings)
    try:
        provider_secrets = decrypt_secrets(key, provider.secrets) if provider.secrets else {}
    except SecretKeyError as exc:
        raise SsoLoginError(f"provider secret cannot be decrypted: {exc}") from exc
    client_secret = provider_secrets.get("client_secret", "")

    trust = tls.resolve(settings, config)
    try:
        token_response = await _exchange_code(
            discovery,
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            verifier=row.payload["code_verifier"],
            redirect_uri=redirect_uri,
            trust=trust,
        )
    except Exception as exc:
        raise SsoLoginError(f"token exchange failed: {type(exc).__name__}: {exc}") from exc

    id_token = token_response.get("id_token")
    if not id_token:
        raise SsoLoginError("token response carried no id_token")
    issuer = config.get("issuer", "")
    nonce = row.payload["nonce"]

    try:
        claims = _validate_id_token(id_token, jwks, issuer=issuer, client_id=client_id, nonce=nonce)
    except _JwksKeyMiss:
        try:
            refreshed_config, ok = await refresh_discovery(config, trust=trust)
        except ValueError as exc:
            raise SsoLoginError(f"discovery refresh refused: {exc}") from exc
        if not ok:
            raise SsoLoginError("id token key not found, and discovery refresh failed") from None
        await store.update_auth_provider(provider.name, config=refreshed_config)
        claims = _decode_with_refresh_on_miss(
            id_token, refreshed_config[JWKS_KEY], issuer=issuer, client_id=client_id, nonce=nonce
        )
    except JoseError as exc:
        raise SsoLoginError(f"id token invalid: {exc}") from exc

    subject = claims.get("sub")
    if not subject:
        raise SsoLoginError("id token carried no sub claim")

    groups_claim = config.get("groups_claim") or "groups"
    groups = claims.get(groups_claim)
    if groups is None:
        access_token = token_response.get("access_token")
        if access_token:
            try:
                userinfo = await _fetch_userinfo(discovery, access_token, trust=trust)
            except Exception as exc:
                log.info("userinfo fetch failed for provider %r: %s", provider.name, exc)
                userinfo = {}
            if userinfo and userinfo.get("sub") != subject:
                log.warning(
                    "the userinfo reply of provider %r is discarded. Its sub is %r and the id token has %r",
                    provider.name,
                    userinfo.get("sub"),
                    subject,
                )
                userinfo = {}
            groups = userinfo.get(groups_claim)
    group_set = set(groups) if isinstance(groups, list) else set()

    email = claims.get("email") or ""
    user, identity = await provision_and_authorize(
        store=store,
        provider=provider,
        subject=subject,
        email=email,
        preferred_username=claims.get("preferred_username"),
        groups=group_set,
    )
    await store.touch_last_login(identity.id, now)
    return user
