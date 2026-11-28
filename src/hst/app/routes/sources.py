"""Source registry CRUD. The routes store each secret encrypted and return no secret."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError, field_validator

from hst.app import crypto, runs_exec
from hst.app import sources as glue
from hst.app.auth import COOKIE, current_user, require_permission
from hst.app.crypto import SecretKeyError, decrypt_secrets, encrypt_secrets
from hst.app.store import Device, DeviceSpec, Source, live_run

router = APIRouter()
require_runs_manage = require_permission("runs.manage")
require_sources_write = require_permission("sources.write")


async def _inventory_service(request: Request):
    from hst.app.inventory.legacy import LegacyConnections, active
    from hst.app.inventory.observations import context_for

    if not await active(request.app.state.store):
        return None
    user = await current_user(request, token=request.cookies.get(COOKIE))
    return LegacyConnections(
        request.app.state.store,
        request.app.state.settings,
        actor_id=user.id,
        context=context_for(request.app),
    )


class SourceCreate(BaseModel):
    name: str = Field(pattern=glue.NAME_PATTERN)
    type: str
    config: dict = {}
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def not_reserved(cls, v: str) -> str:
        if v in ("reasoner", "snapshot"):
            raise ValueError(f"{v} is a reserved name")
        return v


class SourcePatch(BaseModel):
    config: dict | None = None
    enabled: bool | None = None


def _json(row: Source, key: str) -> dict:
    """A blob that no longer decrypts under `key` sets `secrets_unreadable`."""
    model_cls = glue.model_for(row.type)
    fields = glue.secret_fields(model_cls)
    try:
        stored = set(decrypt_secrets(key, row.secrets))
    except SecretKeyError:
        secrets, unreadable = dict.fromkeys(fields, False), True
    else:
        secrets, unreadable = {f: f in stored for f in fields}, False
    payload = {
        "name": row.name,
        "type": row.type,
        "kind": glue.kind_of(row.type),
        "config": row.config,
        "secrets": secrets,
        "enabled": row.enabled,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
    if unreadable:
        payload["secrets_unreadable"] = True
    return payload


async def _with_scope_warnings(request: Request, payload: dict, service) -> dict:
    """Add a `warnings` list to the API shape of the saved row when another
    controller row resolves to its routing scope (app/sources.py
    shared_routing_scope_warnings). The key is absent when there is none."""
    warnings = await glue.routing_scope_warnings(
        request.app.state.store,
        request.app.state.settings,
        payload["name"],
        read=service.read if service is not None else None,
    )
    if warnings:
        payload["warnings"] = warnings
    return payload


@router.get("/source-types", dependencies=[Depends(require_runs_manage)])
async def source_types() -> dict:
    return {"types": glue.source_types()}


@router.get("/sources", dependencies=[Depends(require_runs_manage)])
async def list_sources(request: Request) -> dict:
    # The DEK is resolved once, before any row blob is decrypted.
    key = crypto.dek(request.app.state.settings)
    rows = await request.app.state.store.list_sources()
    service = await _inventory_service(request)
    if service is not None:
        rows = [await service.read(row) for row in rows]
    return {"sources": [_json(r, key) for r in rows]}


@router.post("/sources", status_code=201, dependencies=[Depends(require_sources_write)])
async def create_source(request: Request, body: SourceCreate) -> dict:
    settings = request.app.state.settings
    service = await _inventory_service(request)
    if service is not None:
        row = await service.create(body.name, body.type, body.config, body.enabled)
        return await _with_scope_warnings(request, _json(row, crypto.dek(settings)), service)
    body.config.pop("source_name", None)
    try:
        config, secrets = glue.validate_source(body.type, body.config)
    except KeyError:
        raise HTTPException(400, detail=f"unknown source type {body.type!r}") from None
    except ValidationError as exc:
        raise HTTPException(422, detail=_first_error(exc)) from exc
    key = crypto.dek(settings)
    blob = encrypt_secrets(key, secrets)
    try:
        row = await request.app.state.store.create_source(body.name, body.type, config, blob, body.enabled)
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    return await _with_scope_warnings(request, _json(row, key), None)


@router.patch("/sources/{name}", dependencies=[Depends(require_sources_write)])
async def patch_source(request: Request, name: str, body: SourcePatch) -> dict:
    service = await _inventory_service(request)
    if service is not None:
        try:
            row = await service.patch(name, body.config, body.enabled)
        except glue.CredentialsRequired as exc:
            raise HTTPException(400, detail=str(exc)) from exc
        return await _with_scope_warnings(
            request, _json(row, crypto.dek(request.app.state.settings)), service
        )
    settings, store = request.app.state.settings, request.app.state.store
    # The DEK is resolved before merge_config or _json below decrypt a row blob.
    key = crypto.dek(settings)

    def change(row: Source) -> Source:
        if body.config is not None:
            try:
                row.config, row.secrets = glue.merge_config(row, body.config, key)
            except ValidationError as exc:
                raise HTTPException(422, detail=_first_error(exc)) from exc
            except glue.SecretsUnreadable as exc:
                raise HTTPException(422, detail=str(exc)) from exc
            except glue.CredentialsRequired as exc:
                raise HTTPException(400, detail=str(exc)) from exc
        if body.enabled is not None:
            row.enabled = body.enabled
        return row

    updated = await store.modify_source(name, change)
    if updated is None:
        raise HTTPException(404, detail=f"no source {name!r}")
    return await _with_scope_warnings(request, _json(updated, key), None)


@router.delete("/sources/{name}", dependencies=[Depends(require_sources_write)])
async def delete_source(request: Request, name: str) -> dict:
    service = await _inventory_service(request)
    if service is not None:
        await service.delete(name)
        return {"ok": True}
    store = request.app.state.store
    if await store.get_source(name) is None:
        raise HTTPException(404, detail=f"no source {name!r}")
    if await live_run(store, name):
        raise HTTPException(409, detail=f"{name} has a run in flight")
    await store.delete_source(name)
    return {"ok": True}


@router.post("/sources/{name}/test", dependencies=[Depends(require_runs_manage)])
async def test_source(request: Request, name: str) -> dict:
    service = await _inventory_service(request)
    if service is not None:
        return await service.probe(name)
    settings, store = request.app.state.settings, request.app.state.store
    row = await store.get_source(name)
    if row is None:
        raise HTTPException(404, detail=f"no source {name!r}")
    if not row.enabled:
        raise HTTPException(409, detail=f"{name} is disabled")
    # A broken KEK propagates to the app-level handler (500).
    key = crypto.dek(settings)
    try:
        secrets = decrypt_secrets(key, row.secrets)
    except SecretKeyError as exc:
        raise HTTPException(409, detail="stored credentials cannot be decrypted") from exc
    # A device group probes its first enabled device.
    device = None
    if glue.is_group(row.type):
        fleet = [d for d in await store.list_devices(row.name) if d.enabled]
        if fleet:
            device = fleet[0]
    sites = {site.code: site for site in await store.list_sites()}
    rows = {r.name: r for r in await store.list_sources()}
    try:
        if device is not None:
            collector = glue.build_device_collector(row, device, settings, sites=sites, sources=rows)
        else:
            collector = glue.build_collector(row, settings, sites=sites, sources=rows)
        detail = await asyncio.to_thread(collector.probe)
        await runs_exec.pin_host_key(store, row, collector, device)
        return {"ok": True, "detail": glue.redacted(detail, secrets)}
    except Exception as exc:
        detail = glue.redacted(f"{type(exc).__name__}: {exc}", secrets)
        return {"ok": False, "detail": detail}


def _first_error(exc: ValidationError) -> str:
    e = exc.errors()[0]
    loc = ".".join(str(p) for p in e["loc"])
    return f"invalid config: {loc}: {e['msg']}"


# --- device fleets -----------------------------


class DeviceIn(BaseModel):
    host: str = Field(min_length=1)
    port: int | None = None
    enabled: bool = True


class DevicesPut(BaseModel):
    devices: list[DeviceIn]


def _device_json(d: Device) -> dict:
    return {
        "host": d.host,
        "port": d.port,
        "enabled": d.enabled,
        "pinned": bool(d.host_key),
        "updated_at": d.updated_at.isoformat() if d.updated_at else None,
    }


async def _fleet_source(request: Request, name: str) -> Source:
    row = await request.app.state.store.get_source(name)
    if row is None:
        raise HTTPException(404, detail=f"no source {name!r}")
    if not glue.is_group(row.type):
        raise HTTPException(400, detail=f"source type {row.type!r} does not take a device list")
    return row


@router.get("/sources/{name}/devices", dependencies=[Depends(require_runs_manage)])
async def list_devices(request: Request, name: str) -> dict:
    """Each device holds its `device_status` row when one exists."""
    row = await _fleet_source(request, name)
    store = request.app.state.store
    rows = await store.list_devices(row.name)
    status = {s.host: s for s in await store.list_device_status(row.name)}
    return {"devices": [_device_json(d) | {"status": _status_json(status.get(d.host))} for d in rows]}


def _status_json(s) -> dict | None:
    if s is None:
        return None
    return {
        "last_attempt_at": s.last_attempt_at.isoformat() if s.last_attempt_at else None,
        "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
        "consecutive_failures": s.consecutive_failures,
        "last_error": s.last_error,
        "fetch_ms": s.fetch_ms,
        "load_ms": s.load_ms,
    }


@router.put("/sources/{name}/devices", dependencies=[Depends(require_sources_write)])
async def put_devices(request: Request, name: str, body: DevicesPut) -> dict:
    """Replace the fleet with the submitted list. A device is matched by host,
    and a device that the list omits is deleted. A kept row keeps its pinned
    host key. The config of each device is the config of the group with the
    address of the device on top. It is validated against the type with the
    stored secrets of the group when they decrypt. An unreadable blob skips
    that check, as in merge_config."""
    service = await _inventory_service(request)
    if service is not None:
        rows = await service.replace_devices(
            name, [DeviceSpec(d.host, port=d.port, enabled=d.enabled) for d in body.devices]
        )
        return {"devices": [_device_json(d) for d in rows]}
    settings, store = request.app.state.settings, request.app.state.store
    row = await _fleet_source(request, name)
    key = crypto.dek(settings)
    try:
        stored: dict | None = decrypt_secrets(key, row.secrets)
    except SecretKeyError:
        stored = None
    now = datetime.now(UTC)
    for spec in body.devices:
        if stored is not None:
            candidate = Device(0, row.name, spec.host, spec.port, spec.enabled, "", now, now)
            payload = glue.inject_secrets(glue.device_config(row, candidate), stored)
            try:
                glue.model_for(row.type)(**payload)
            except ValidationError as exc:
                raise HTTPException(422, detail=f"{spec.host}: {_first_error(exc)}") from exc
    try:
        rows = await store.replace_devices(
            row.name,
            [DeviceSpec(d.host, port=d.port, enabled=d.enabled) for d in body.devices],
        )
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return {"devices": [_device_json(d) for d in rows]}


@router.post("/sources/{name}/devices/{host}/test", dependencies=[Depends(require_runs_manage)])
async def test_device(request: Request, name: str, host: str) -> dict:
    """Probe one device of a fleet as `test_source` does, and pin its host key."""
    service = await _inventory_service(request)
    if service is not None:
        return await service.probe(name, host)
    settings, store = request.app.state.settings, request.app.state.store
    row = await _fleet_source(request, name)
    device = next((d for d in await store.list_devices(row.name) if d.host == host), None)
    if device is None:
        raise HTTPException(404, detail=f"no device {host!r} in {name!r}")
    key = crypto.dek(settings)
    try:
        secrets = decrypt_secrets(key, row.secrets)
    except SecretKeyError as exc:
        raise HTTPException(409, detail="stored credentials cannot be decrypted") from exc
    try:
        sites = {site.code: site for site in await store.list_sites()}
        rows = {r.name: r for r in await store.list_sources()}
        collector = glue.build_device_collector(row, device, settings, sites=sites, sources=rows)
        detail = await asyncio.to_thread(collector.probe)
        await runs_exec.pin_host_key(store, row, collector, device)
        return {"ok": True, "detail": glue.redacted(detail, secrets)}
    except Exception as exc:
        detail = glue.redacted(f"{type(exc).__name__}: {exc}", secrets)
        return {"ok": False, "detail": detail}


@router.get("/sources/{name}/effective", dependencies=[Depends(require_permission("graph.read"))])
async def effective_group(request: Request, name: str) -> dict:
    """Return the resolved non-secret normalization values per collection target and UID.

    The site comes from resolve_device_sites. A controller's device sits where
    a person placed it or where its reported location is bound. A target that
    no collection has seen gets the site of the group.
    """
    service = await _inventory_service(request)
    if service is not None:
        return await service.effective(name)
    store = request.app.state.store
    row = await store.get_source(name)
    if row is None:
        raise HTTPException(404, detail=f"no such group: {name}")
    devices = {d.host: d for d in await store.list_devices(name)}
    target_devices = await store.target_devices(name)
    mappings: dict[str, list[str]] = {}
    for mapping in target_devices:
        mappings.setdefault(mapping.host, []).append(mapping.device_uid)
    sites = {site.code: site for site in await store.list_sites()}
    locations = await store.list_reported_locations()
    placed = glue.resolve_device_sites(
        await store.device_sites(),
        target_devices,
        {row.name: row},
        {(loc.source, loc.location_id): loc.site for loc in locations if loc.site},
    )
    hosts = sorted(set(devices) | set(mappings)) or [""]
    result = []
    for host in hosts:
        device = devices.get(host)
        uids = sorted(mappings.get(host, []))
        target_uids: list[str | None] = []
        target_uids.extend(uids)
        if not target_uids:
            target_uids.append(None)
        for uid in target_uids:
            payload, origins = glue.resolve_normalization(
                row,
                request.app.state.settings,
                device=device,
                sites=sites,
            )
            site, site_origin = placed.get(uid or "", (None, ""))
            if uid is None:
                site = row.config.get("site_code") or None
                site_origin = "group" if site else ""
            result.append(
                {
                    "host": host,
                    "device_uids": [uid] if uid is not None else [],
                    "site": site,
                    "values": {
                        "routing_scope": payload["routing_scope"],
                        "l2fabric": payload["l2fabric"],
                    },
                    "origins": origins | {"site": site_origin},
                }
            )
    return {"devices": result}
