"""The admin auth settings for the local-login toggle, the identity providers,
their group mappings and the login events."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from hst.app import crypto, saml_flow, sso_flow, tls
from hst.app.auth import require_permission
from hst.app.crypto import encrypt_secrets
from hst.app.store import AuthProvider

router = APIRouter(prefix="/settings/auth")
require_settings_auth = require_permission("settings.auth")  # B008 forbids this call in an argument default.
require_users_manage = require_permission("users.manage")  # B008 forbids this call in an argument default.

NAME_PATTERN = r"^[a-z0-9-]{1,64}$"


class LocalLoginBody(BaseModel):
    local_login_enabled: bool


class ProviderCreate(BaseModel):
    name: str = Field(pattern=NAME_PATTERN)
    kind: Literal["oidc", "saml"]
    config: dict = {}
    secret: str | None = None


class ProviderPatch(BaseModel):
    config: dict | None = None
    secret: str | None = None
    enabled: bool | None = None


class MappingBody(BaseModel):
    group_name: str = Field(min_length=1, max_length=256)
    role: Literal["viewer", "operator", "admin"]


def _external_url(request: Request, route: str, name: str) -> str | None:
    """None when the setting `public_url` is empty."""
    try:
        return sso_flow.external_url(request.app, route, name=name)
    except sso_flow.PublicUrlNotSet:
        return None


def _provider_json(request: Request, row: AuthProvider) -> dict:
    """A SAML provider has `sp_entity_id` and `sp_acs_url`. An OIDC provider
    has `redirect_uri`. Each of the 3 URLs is null when the setting
    `public_url` is empty.
    """
    body: dict = {
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "enabled": row.enabled,
        "config": sso_flow.public_config(row.config),
        "has_secret": row.secrets is not None,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }
    if row.kind == "saml":
        body["sp_entity_id"] = _external_url(request, "saml_metadata", row.name)
        body["sp_acs_url"] = _external_url(request, "saml_acs", row.name)
    elif row.kind == "oidc":
        body["redirect_uri"] = _external_url(request, "sso_callback", row.name)
    return body


def _has_idp_data(kind: str, config: dict) -> bool:
    """True when the config holds the cached discovery (OIDC) or the cached
    IdP metadata (SAML)."""
    if kind == "oidc":
        return sso_flow.discovery_ok(config)
    if kind == "saml":
        return saml_flow.saml_metadata_ok(config)
    return False


def _is_login_path(provider: AuthProvider) -> bool:
    """True when a user can sign in through the provider."""
    return provider.enabled and _has_idp_data(provider.kind, provider.config)


async def _ensure_login_path_survives(request: Request, provider: AuthProvider, *, detail: str) -> None:
    """Raise a 409 with `detail` when local login is off and no provider other
    than `provider` is a login path (`_is_login_path`)."""
    store = request.app.state.store
    if await sso_flow.local_login_enabled(store):
        return
    if any(_is_login_path(p) for p in await store.list_auth_providers() if p.id != provider.id):
        return
    raise HTTPException(409, detail=detail)


_LAST_PROVIDER = "cannot disable the last enabled identity provider while local login is off"
OTHER_ISSUER_DETAIL = "client secret required for an issuer other than the stored one"
WEAKER_TLS_DETAIL = "client secret required for a TLS check weaker than the stored one"


def _require_own_client_secret(stored: dict, config: dict) -> None:
    if config.get("issuer") != stored.get("issuer"):
        raise HTTPException(400, detail=OTHER_ISSUER_DETAIL)
    if tls.weakens(stored, config):
        raise HTTPException(400, detail=WEAKER_TLS_DETAIL)


async def _validate_and_discover(request: Request, kind: str, config: dict) -> dict:
    """Validate the shape of a submitted config and, for OIDC and SAML, run
    discovery or metadata parsing.

    Either step raises ValueError for a missing required field, for a scheme
    violation in discovery or in the metadata fetch, or for an issuer mismatch
    in discovery. The caller turns the ValueError into a 4xx.
    """
    trust = tls.resolve(request.app.state.settings, config)
    if kind == "oidc":
        sso_flow.validate_oidc_config(config)
        new_config, _ok = await sso_flow.refresh_discovery(config, trust=trust)
        return new_config
    if kind == "saml":
        saml_flow.validate_saml_config(config)
        new_config, _ok = await saml_flow.refresh_saml_metadata(config, trust=trust)
        return new_config
    return config


@router.get("")
async def get_local_login(request: Request, admin=Depends(require_settings_auth)) -> dict:
    return {"local_login_enabled": await sso_flow.local_login_enabled(request.app.state.store)}


@router.put("")
async def put_local_login(
    request: Request, body: LocalLoginBody, admin=Depends(require_settings_auth)
) -> dict:
    store = request.app.state.store
    if not body.local_login_enabled:
        providers = await store.list_auth_providers()
        if not any(_is_login_path(p) for p in providers):
            raise HTTPException(
                409,
                detail="local login cannot be turned off: no enabled identity provider can sign a user in",
            )
        admins_with_password = [
            u for u in await store.list_users() if u.role == "admin" and not u.disabled and u.password_hash
        ]
        if not admins_with_password:
            raise HTTPException(
                409,
                detail="local login cannot be turned off: no enabled admin account with a "
                "password would remain",
            )
    await store.put_setting(sso_flow.LOCAL_LOGIN_KEY, {"enabled": body.local_login_enabled}, b"")
    return {"local_login_enabled": body.local_login_enabled}


@router.get("/providers")
async def list_providers(request: Request, admin=Depends(require_settings_auth)) -> list[dict]:
    rows = await request.app.state.store.list_auth_providers()
    return [_provider_json(request, r) for r in rows]


@router.post("/providers", status_code=201)
async def create_provider(
    request: Request, body: ProviderCreate, admin=Depends(require_settings_auth)
) -> dict:
    store, settings = request.app.state.store, request.app.state.settings
    try:
        config = await _validate_and_discover(request, body.kind, dict(body.config))
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    secrets_blob = None
    if body.kind == "saml":
        # The SP keypair is generated here only.
        sp_key_pem, sp_cert_pem = saml_flow.generate_sp_keypair()
        config[saml_flow.SP_CERT_CONFIG_KEY] = sp_cert_pem
        key = crypto.dek(settings)
        secrets_blob = encrypt_secrets(key, {saml_flow.SP_PRIVATE_KEY_SECRET: sp_key_pem})
    elif body.secret:
        key = crypto.dek(settings)
        secrets_blob = encrypt_secrets(key, {"client_secret": body.secret})
    try:
        row = await store.create_auth_provider(body.name, body.kind, config, secrets_blob, enabled=False)
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    return _provider_json(request, row)


@router.patch("/providers/{name}")
async def patch_provider(
    request: Request, name: str, body: ProviderPatch, admin=Depends(require_settings_auth)
) -> dict:
    store, settings = request.app.state.store, request.app.state.settings
    row = await store.get_auth_provider(name)
    if row is None:
        raise HTTPException(404, detail=f"no such provider: {name}")

    new_config = None
    if body.config is not None:
        try:
            new_config = await _validate_and_discover(request, row.kind, dict(body.config))
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        if row.kind == "oidc" and row.secrets is not None and not body.secret:
            _require_own_client_secret(row.config, new_config)
        if row.kind == "saml":
            # The stored SP certificate replaces the value of the config body.
            new_config[saml_flow.SP_CERT_CONFIG_KEY] = row.config.get(saml_flow.SP_CERT_CONFIG_KEY, "")

    secrets_blob = None
    if body.secret and row.kind == "oidc":
        key = crypto.dek(settings)
        secrets_blob = encrypt_secrets(key, {"client_secret": body.secret})
    # The SAML secret (the SP private key) is not sealed again on PATCH.

    config_after = new_config if new_config is not None else row.config
    enabled_after = row.enabled if body.enabled is None else body.enabled
    has_idp_data = _has_idp_data(row.kind, config_after)
    if body.enabled is True and not has_idp_data:
        if row.kind == "oidc":
            raise HTTPException(
                409,
                detail=f"{name} has no successful discovery yet; save it again once the issuer is reachable",
            )
        raise HTTPException(
            409,
            detail=f"{name} has no successfully parsed IdP metadata yet; save it again once "
            "the metadata is reachable and valid",
        )
    if _is_login_path(row) and not enabled_after:
        await _ensure_login_path_survives(request, row, detail=_LAST_PROVIDER)
    elif _is_login_path(row) and not has_idp_data:
        what = "discovery" if row.kind == "oidc" else "IdP metadata"
        await _ensure_login_path_survives(
            request,
            row,
            detail=f"the new config of {name} has no usable {what}, and {name} is the last "
            "identity provider while local login is off",
        )

    updated = await store.update_auth_provider(
        name, config=new_config, secrets=secrets_blob, enabled=body.enabled
    )
    if updated is None:
        raise HTTPException(404, detail=f"no such provider: {name}")
    return _provider_json(request, updated)


@router.delete("/providers/{name}", status_code=204)
async def delete_provider(request: Request, name: str, admin=Depends(require_settings_auth)) -> Response:
    store = request.app.state.store
    row = await store.get_auth_provider(name)
    if row is None:
        raise HTTPException(404, detail=f"no such provider: {name}")
    if _is_login_path(row):
        await _ensure_login_path_survives(request, row, detail=_LAST_PROVIDER)
    await store.delete_auth_provider(name)
    return Response(status_code=204)


@router.post("/providers/{name}/test")
async def test_provider(request: Request, name: str, admin=Depends(require_settings_auth)) -> dict:
    store = request.app.state.store
    row = await store.get_auth_provider(name)
    if row is None:
        raise HTTPException(404, detail=f"no such provider: {name}")
    trust = tls.resolve(request.app.state.settings, row.config)
    if row.kind == "saml":
        return await saml_flow.test_saml_metadata(row.config, trust=trust)
    if row.kind != "oidc":
        return {"ok": False, "detail": f"{row.kind} testing is not supported"}
    issuer = row.config.get("issuer", "")
    try:
        await sso_flow.discover(issuer, trust=trust)
    except ValueError as exc:
        return {"ok": False, "detail": str(exc)}
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "detail": "discovery and JWKS fetched"}


@router.get("/providers/{name}/mappings")
async def list_mappings(request: Request, name: str, admin=Depends(require_settings_auth)) -> list[dict]:
    store = request.app.state.store
    row = await store.get_auth_provider(name)
    if row is None:
        raise HTTPException(404, detail=f"no such provider: {name}")
    return [{"group_name": g.group_name, "role": g.role} for g in await store.list_group_mappings(row.id)]


@router.post("/providers/{name}/mappings", status_code=201)
async def put_mapping(
    request: Request, name: str, body: MappingBody, admin=Depends(require_settings_auth)
) -> dict:
    store = request.app.state.store
    row = await store.get_auth_provider(name)
    if row is None:
        raise HTTPException(404, detail=f"no such provider: {name}")
    g = await store.put_group_mapping(row.id, body.group_name, body.role)
    return {"group_name": g.group_name, "role": g.role}


@router.delete("/providers/{name}/mappings/{group_name}", status_code=204)
async def delete_mapping(
    request: Request, name: str, group_name: str, admin=Depends(require_settings_auth)
) -> Response:
    store = request.app.state.store
    row = await store.get_auth_provider(name)
    if row is None:
        raise HTTPException(404, detail=f"no such provider: {name}")
    if not await store.delete_group_mapping(row.id, group_name):
        raise HTTPException(404, detail=f"no such mapping: {group_name}")
    return Response(status_code=204)


@router.get("/events")
async def list_login_events(
    request: Request, limit: int = Query(200, ge=1, le=1000), admin=Depends(require_users_manage)
) -> list[dict]:
    rows = await request.app.state.store.list_login_events(limit=limit)
    return [
        {
            "at": r.at.isoformat(),
            "username": r.username,
            "user_id": r.user_id,
            "provider": r.provider,
            "outcome": r.outcome,
            "source": r.source,
        }
        for r in rows
    ]
