"""Connections, targets and the collection operations."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Protocol

import sqlalchemy as sa
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from hst import collectors as coll
from hst.app import crypto, runs_exec, source_egress
from hst.app import sources as glue
from hst.app.auth import require_permission
from hst.app.inventory import collection, credentials
from hst.app.inventory import field_metadata as _fm
from hst.app.inventory.contracts import (
    API_PREFIX,
    MAX_SELECTION,
    OPERATION_PERMISSIONS,
    REDACTED,
    ApplyRequest,
    ApplyResponse,
    ApplyResult,
    ApplyStatus,
    CollectionState,
    ConnectionCreate,
    ConnectionHealth,
    ConnectionKind,
    ConnectionListQuery,
    ConnectionPatch,
    ConnectionView,
    CredentialPatch,
    DeviceListQuery,
    EffectiveCollection,
    ErrorResponse,
    FieldCategory,
    Generation,
    ImpactItem,
    ImpactPage,
    PageQuery,
    PreviewMember,
    PreviewMemberKind,
    PreviewOperation,
    PreviewRequest,
    PreviewResponse,
    ProbeRequest,
    ProbeResult,
    ProfileAssignmentChange,
    ProfilePatch,
    ReplacementChange,
    Selection,
    TargetCreate,
    TargetKind,
    TargetPatch,
    TargetReplaceRequest,
    TargetReplaceResponse,
    TargetView,
    redact_by_key,
)
from hst.app.inventory.repository import (
    Conflict,
    InventoryChanged,
    InventoryError,
    InventoryTx,
    NotFound,
    StaleRevision,
)
from hst.app.inventory.tables import PREVIEW_TTL_S
from hst.app.permissions import permissions_for
from hst.app.store import (
    UNSET,
    CollectionProfile,
    CollectionProfileVersion,
    Device,
    DeviceFilters,
    DeviceSpec,
    DeviceStatus,
    InventoryDevice,
    InventoryState,
    InventoryTarget,
    OperationPreview,
    Source,
    SourceInventory,
    Store,
    User,
    live_run,
)
from hst.app.store.pg import device_status as device_status_table
from hst.app.store.pg import devices as devices_table
from hst.app.store.pg import jobs as jobs_table
from hst.app.store.pg import sources as sources_table
from hst.app.store.pg import target_devices as target_devices_table
from hst.core import Settings, uid

log = logging.getLogger(__name__)

router = APIRouter(prefix=API_PREFIX)
require_runs_manage = require_permission("runs.manage")
require_sources_write = require_permission("sources.write")
# The operation routes require `graph.read`. The handler checks the
# permission of each operation with `OPERATION_PERMISSIONS`.
require_graph_read = require_permission("graph.read")

# The stale threshold of a target is at least this number of seconds.
STALE_FLOOR_S = 300

RESERVED_NAMES = frozenset({"reasoner", "snapshot", "cycle", runs_exec.DEVICE_RUN, runs_exec.DEMO})


# --- errors -----------------------------------------------------------------------------------


class Validation(InventoryError):
    """A well-formed request that the inventory refuses. The response is 422 with the code `validation`."""


class CredentialsRequiredError(Validation):
    """A change of the endpoint or of the TLS check keeps a stored credential.
    `detail` lists the paths of its secrets under `credentials`."""

    def __init__(self, exc: source_egress.CredentialsRequired):
        super().__init__(str(exc))
        self.detail = {"credentials": exc.kept}


def error_response(exc: InventoryError) -> JSONResponse:
    body = ErrorResponse(
        error=str(exc),
        code=exc.code,
        current_revision=exc.current_revision,
        references=exc.references,
        detail=getattr(exc, "detail", None),
    )
    return JSONResponse(body.model_dump(mode="json"), status_code=exc.status)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(InventoryError)
    async def inventory_error(request: Request, exc: InventoryError) -> JSONResponse:
        return error_response(exc)


def register(app: FastAPI) -> None:
    """Mount the connection, target, operation, profile and credential routers
    and their error shaping."""
    from hst.app.inventory import profile_routes

    install_error_handlers(app)
    app.include_router(router)
    app.include_router(profile_routes.router)


# --- context -----------------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _store(request: Request) -> Store:
    store = request.app.state.store
    if not collection.has_inventory(store):
        raise Validation("inventory is not available on this store")
    return store


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _key(request: Request) -> str:
    return crypto.dek(_settings(request))


async def _generation(tx: InventoryTx) -> Generation:
    state = await tx.get_state()
    return Generation(
        snapshot_key=state.read_model_snapshot_key,
        intent_generation=state.intent_generation,
        inventory_sync_pending=state.inventory_sync_pending,
    )


def _first_error(exc: ValidationError) -> str:
    e = exc.errors()[0]
    loc = ".".join(str(p) for p in e["loc"])
    return f"invalid config: {loc}: {e['msg']}"


# --- execution records ----------------------------------------------------------------------------


# The count of the newest job rows that `active_lease` reads from a store
# without a transaction connection. The high water mark of the queue is 1000
# pending jobs by default.
_LEASE_SCAN_LIMIT = 10000


class ExecutionRecords:
    """The execution records a connection or target change must update
    in the same transaction as its inventory row."""

    def __init__(self, store: Store, tx: InventoryTx) -> None:
        self.store = store
        self.conn = tx.connection

    async def create_source(self, name: str, type_: str, config: dict, enabled: bool) -> Source:
        if self.conn is not None:
            now = _now()
            row = (
                await self.conn.execute(
                    sources_table.insert()
                    .values(
                        name=name,
                        type=type_,
                        config=config,
                        secrets=b"",
                        enabled=enabled,
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(sources_table)
                )
            ).one()
            return Source(
                row.id,
                row.name,
                row.type,
                dict(row.config),
                bytes(row.secrets or b""),
                row.enabled,
                row.created_at,
                row.updated_at,
            )
        try:
            return await self.store.create_source(name, type_, config, b"", enabled)
        except ValueError as exc:
            raise Conflict(str(exc)) from exc

    async def update_source(
        self, name: str, *, config: dict | None = None, enabled: bool | None = None
    ) -> None:
        if self.conn is not None:
            values: dict[str, Any] = {"updated_at": _now()}
            if config is not None:
                values["config"] = config
            if enabled is not None:
                values["enabled"] = enabled
            await self.conn.execute(
                sources_table.update().where(sources_table.c.name == name).values(**values)
            )
            return
        await self.store.update_source(name, config=config, enabled=enabled)

    async def delete_source(self, name: str) -> None:
        if self.conn is not None:
            await self.conn.execute(sources_table.delete().where(sources_table.c.name == name))
            return
        await self.store.delete_source(name)

    async def add_device(self, source: str, host: str, port: int | None, enabled: bool) -> Device:
        if self.conn is not None:
            now = _now()
            row = (
                await self.conn.execute(
                    devices_table.insert()
                    .values(
                        source=source,
                        host=host,
                        port=port,
                        enabled=enabled,
                        host_key="",
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(devices_table)
                )
            ).one()
            return Device(
                row.id,
                row.source,
                row.host,
                row.port,
                row.enabled,
                row.host_key,
                row.created_at,
                row.updated_at,
            )
        existing = await self.store.list_devices(source)
        specs = [DeviceSpec(d.host, port=d.port, enabled=d.enabled) for d in existing]
        specs.append(DeviceSpec(host, port=port, enabled=enabled))
        rows = await self.store.replace_devices(source, specs)
        return next(d for d in rows if d.host == host)

    async def set_device_enabled(self, source: str, host: str, enabled: bool) -> None:
        if self.conn is not None:
            await self.conn.execute(
                devices_table.update()
                .where(devices_table.c.source == source, devices_table.c.host == host)
                .values(enabled=enabled, updated_at=_now())
            )
            return
        existing = await self.store.list_devices(source)
        specs = [
            DeviceSpec(d.host, port=d.port, enabled=enabled if d.host == host else d.enabled)
            for d in existing
        ]
        await self.store.replace_devices(source, specs)

    async def clear_device_host_key(self, source: str, host: str) -> None:
        if self.conn is not None:
            await self.conn.execute(
                devices_table.update()
                .where(devices_table.c.source == source, devices_table.c.host == host)
                .values(host_key="", updated_at=_now())
            )
            return
        await self.store.clear_device_host_key(source, host)

    async def get_source(self, name: str, *, lock: bool = False) -> Source | None:
        """The source row as this transaction sees it, its own writes included.
        With `lock` the row is locked FOR NO KEY UPDATE until the transaction
        ends."""
        if self.conn is not None:
            query = sa.select(sources_table).where(sources_table.c.name == name)
            if lock:
                query = query.with_for_update(key_share=True)
            row = (await self.conn.execute(query)).first()
            if row is None:
                return None
            return Source(
                row.id,
                row.name,
                row.type,
                dict(row.config),
                bytes(row.secrets or b""),
                row.enabled,
                row.created_at,
                row.updated_at,
            )
        return await self.store.get_source(name)

    async def get_device(self, source: str, host: str) -> Device | None:
        if self.conn is not None:
            row = (
                await self.conn.execute(
                    sa.select(devices_table).where(
                        devices_table.c.source == source, devices_table.c.host == host
                    )
                )
            ).first()
            if row is None:
                return None
            return Device(
                row.id,
                row.source,
                row.host,
                row.port,
                row.enabled,
                row.host_key,
                row.created_at,
                row.updated_at,
            )
        return next((d for d in await self.store.list_devices(source) if d.host == host), None)

    async def list_devices(self, source: str) -> list[Device]:
        if self.conn is not None:
            rows = (
                await self.conn.execute(sa.select(devices_table).where(devices_table.c.source == source))
            ).all()
            return [
                Device(r.id, r.source, r.host, r.port, r.enabled, r.host_key, r.created_at, r.updated_at)
                for r in rows
            ]
        return await self.store.list_devices(source)

    async def remove_device(self, source: str, host: str) -> None:
        """Delete the fleet row of a host with its status and observation records.
        `replace_devices` deletes the same records for a host that leaves the fleet."""
        if self.conn is not None:
            await self.conn.execute(
                devices_table.delete().where(devices_table.c.source == source, devices_table.c.host == host)
            )
            await self.conn.execute(
                device_status_table.delete().where(
                    device_status_table.c.source == source, device_status_table.c.host == host
                )
            )
            await self.conn.execute(
                target_devices_table.delete().where(
                    target_devices_table.c.source == source, target_devices_table.c.host == host
                )
            )
            return
        existing = await self.store.list_devices(source)
        specs = [DeviceSpec(d.host, port=d.port, enabled=d.enabled) for d in existing if d.host != host]
        await self.store.replace_devices(source, specs)

    async def active_lease(self, source: str, host: str | None = None) -> int | None:
        """Return the id of a running job of `source`, or None. With `host`,
        the job is for that host or for the whole source."""
        if self.conn is not None:
            where = [jobs_table.c.state == "running", jobs_table.c.source == source]
            if host is not None:
                where.append(
                    sa.or_(
                        jobs_table.c.device.is_(None),
                        jobs_table.c.device == "",
                        jobs_table.c.device == host,
                    )
                )
            row = (await self.conn.execute(sa.select(jobs_table.c.id).where(*where).limit(1))).first()
            return int(row.id) if row is not None else None
        for job in await self.store.list_jobs(limit=_LEASE_SCAN_LIMIT):
            if job.state != "running" or job.source != source:
                continue
            if host is None or job.device in (None, "", host):
                return job.id
        return None


async def _refuse_in_flight(ctx: OperationContext, source: str, host: str | None = None) -> None:
    """Raise `Conflict` while `source` has a run in flight or a running
    collection job. With `host`, the job is for that host or for the whole source."""
    if await live_run(ctx.store, source):
        raise Conflict(f"{source} has a run in flight", references=[f"run:{source}"])
    job_id = await ExecutionRecords(ctx.store, ctx.tx).active_lease(source, host)
    if job_id is not None:
        label = f"{source}/{host}" if host else source
        raise Conflict(f"{label} has a collection job in flight", references=[f"job:{job_id}"])


# --- views --------------------------------------------------------------------------------------------


def _collection_state(
    statuses: Sequence[DeviceStatus | None], interval_s: int, cycle_interval_s: int, now: datetime
) -> CollectionState:
    """The state is `never` if no target has an attempt. It is `failed` if every
    attempted target fails and `partial` if a part of them fails. It is `manual`
    if no cadence is set. It is `stale` if a last success is missing or older than
    the threshold, and `current` otherwise."""
    present = [s for s in statuses if s is not None and s.last_attempt_at is not None]
    if not present:
        return CollectionState.NEVER
    failing = [s for s in present if s.consecutive_failures > 0]
    if failing and len(failing) == len(present):
        return CollectionState.FAILED
    if failing:
        return CollectionState.PARTIAL
    cadence = interval_s or cycle_interval_s
    if cadence <= 0:
        return CollectionState.MANUAL
    threshold = max(3 * cadence, STALE_FLOOR_S)
    for s in present:
        if s.last_success_at is None or (now - s.last_success_at).total_seconds() > threshold:
            return CollectionState.STALE
    return CollectionState.CURRENT


def _kind_of(row: Source) -> ConnectionKind:
    return ConnectionKind.DIRECT if glue.is_group(row.type) else ConnectionKind.CONTROLLER


def _target_kind(row: Source, device: Device | None) -> TargetKind:
    if device is not None:
        return TargetKind.DIRECT
    if glue.is_group(row.type):
        return TargetKind.IMPLICIT
    return TargetKind.CONTROLLER


def _connection_config(row: Source) -> dict[str, Any]:
    """Return the config paths of the connection and target categories, with
    each secret value replaced by `REDACTED`. The config of a collector type
    without field metadata is returned whole and redacted by key."""
    if row.type not in _fm.COLLECTORS:
        return redact_by_key(dict(row.config))
    keep = (FieldCategory.CONNECTION.value, FieldCategory.TARGET.value)
    flat = {
        path: value
        for path, value in collection.flatten(row.config).items()
        if collection.category_of(row.type, path) in keep
    }
    secret = _fm.secret_paths(row.type)
    for path in flat:
        if path in secret and flat[path] not in (None, ""):
            flat[path] = REDACTED
    return collection.unflatten(flat)


class _FleetIndex:
    """The reads that the views and previews of many targets share, made once
    per source for the life of one request."""

    def __init__(self, tx: InventoryTx, store: Store, *, many: bool = False) -> None:
        self._tx = tx
        self._many = many
        self._records = ExecutionRecords(store, tx)
        self._store = store
        self._mapped: dict[str, dict[str, list[uuid.UUID]]] = {}
        self._status: dict[str, dict[str, DeviceStatus]] = {}
        self._rows: dict[str, Source | None] = {}
        self._devices: dict[str, dict[str, Device]] = {}

    async def source(self, source_key: str) -> Source | None:
        if source_key not in self._rows:
            self._rows[source_key] = await self._records.get_source(source_key)
        return self._rows[source_key]

    async def status(self, source_key: str) -> dict[str, DeviceStatus]:
        """The source's device status rows, by host."""
        if source_key not in self._status:
            self._status[source_key] = {s.host: s for s in await self._store.list_device_status(source_key)}
        return self._status[source_key]

    async def device(self, source_key: str, host: str) -> Device | None:
        if not self._many:
            return await self._records.get_device(source_key, host)
        if source_key not in self._devices:
            self._devices[source_key] = {d.host: d for d in await self._records.list_devices(source_key)}
        return self._devices[source_key].get(host)

    async def _mapped_ids(self, source_key: str) -> dict[str, list[uuid.UUID]]:
        """The ids of the inventory devices whose graph uid is in a
        `target_devices` row of the source, by host."""
        if source_key not in self._mapped:
            mappings = await self._store.target_devices(source_key)
            found = await self._tx.get_devices_by_graph_uids(sorted({m.device_uid for m in mappings}))
            by_uid = {d.graph_uid: d.id for d in found}
            by_host: dict[str, dict[uuid.UUID, None]] = {}
            for mapping in mappings:
                if (device_id := by_uid.get(mapping.device_uid)) is not None:
                    by_host.setdefault(mapping.host, {}).setdefault(device_id)
            self._mapped[source_key] = {host: list(ids) for host, ids in by_host.items()}
        return self._mapped[source_key]

    async def device_ids(self, targets: Sequence[InventoryTarget]) -> dict[uuid.UUID, list[uuid.UUID]]:
        """The ids of the inventory devices of each target, from its observation
        rows and from the mapped devices of its host."""
        observed = await self._tx.list_observations_for_targets([t.id for t in targets])
        out: dict[uuid.UUID, list[uuid.UUID]] = {}
        for target in targets:
            ids = dict.fromkeys(o.device_id for o in observed.get(target.id, ()))
            for device_id in (await self._mapped_ids(target.source_key)).get(target.host, ()):
                ids.setdefault(device_id)
            out[target.id] = list(ids)
        return out


@dataclass
class _TargetContext:
    """The source row, the device row, the status and the observed device ids of one target view."""

    row: Source
    device: Device | None
    status: DeviceStatus | None
    device_ids: list[uuid.UUID] = field(default_factory=list)


async def _target_context(
    tx: InventoryTx,
    store: Store,
    target: InventoryTarget,
    index: _FleetIndex | None = None,
    device_ids: list[uuid.UUID] | None = None,
) -> _TargetContext | None:
    """A caller that builds the contexts of many targets passes `index` and
    `device_ids`. Without them, the function builds a `_FleetIndex` and reads
    the device ids of the target."""
    index = index or _FleetIndex(tx, store)
    row = await index.source(target.source_key)
    if row is None:
        return None
    device = None
    if target.legacy_device_id is not None or target.kind == TargetKind.DIRECT.value:
        device = await index.device(row.name, target.host)
    status = (await index.status(row.name)).get(target.host)
    if device_ids is None:
        device_ids = (await index.device_ids([target]))[target.id]
    return _TargetContext(row, device, status, device_ids)


def target_view(target: InventoryTarget, ctx: _TargetContext | None) -> TargetView:
    device = ctx.device if ctx else None
    status = ctx.status if ctx else None
    pinned = (
        bool(device.host_key)
        if device is not None
        else bool((ctx.row.config.get("host_key") if ctx else "") or "")
    )
    return TargetView(
        id=target.id,
        connection_id=str(target.source_id) if target.source_id is not None else target.source_key,
        source_key=target.source_key,
        host=target.host,
        port=device.port
        if device is not None
        else (ctx.row.config.get("port") if ctx and target.kind != TargetKind.DIRECT.value else None),
        kind=TargetKind(target.kind),
        enabled=target.enabled,
        host_key_pinned=pinned,
        endpoint_config=target.endpoint_config,
        profile_id=target.profile_id,
        onboarding_site_id=str(target.onboarding_site_id) if target.onboarding_site_id is not None else None,
        legacy_device_id=str(target.legacy_device_id) if target.legacy_device_id is not None else None,
        revision=target.revision,
        archived_at=target.archived_at,
        observed_device_ids=list(ctx.device_ids) if ctx else [],
        last_attempt_at=status.last_attempt_at if status else None,
        last_success_at=status.last_success_at if status else None,
        consecutive_failures=status.consecutive_failures if status else 0,
        last_error=status.last_error if status else "",
    )


async def _target_views(
    tx: InventoryTx, store: Store, targets: Sequence[InventoryTarget]
) -> list[TargetView]:
    index = _FleetIndex(tx, store, many=True)
    ids = await index.device_ids(targets)
    return [
        target_view(target, await _target_context(tx, store, target, index, ids[target.id]))
        for target in targets
    ]


async def connection_view(
    tx: InventoryTx, store: Store, settings: Settings, row: Source, inventory: SourceInventory | None
) -> ConnectionView:
    targets = [t for t in await tx.list_targets(row.id) if t.archived_at is None]
    index = _FleetIndex(tx, store)
    statuses = await index.status(row.name)
    observed = await index.device_ids(targets)
    now = _now()
    device_ids: set[uuid.UUID] = set()
    failing = 0
    last_success: datetime | None = None
    last_attempt: datetime | None = None
    per_target: list[DeviceStatus | None] = []
    for target in targets:
        st = statuses.get(target.host)
        per_target.append(st)
        if st is not None:
            if st.consecutive_failures > 0:
                failing += 1
            if st.last_success_at and (last_success is None or st.last_success_at > last_success):
                last_success = st.last_success_at
            if st.last_attempt_at and (last_attempt is None or st.last_attempt_at > last_attempt):
                last_attempt = st.last_attempt_at
        device_ids.update(observed[target.id])
    interval = await _connection_interval(tx, settings, row, inventory)
    health = ConnectionHealth(
        state=_collection_state(per_target, interval, settings.collect_interval_s, now),
        last_success_at=last_success,
        last_attempt_at=last_attempt,
        failing_targets=failing,
        target_count=len(targets),
        device_count=len(device_ids),
    )
    return ConnectionView(
        id=str(row.id),
        name=row.name,
        display_name=(inventory.display_name if inventory else "") or row.name,
        collector_type=row.type,
        kind=_kind_of(row),
        enabled=row.enabled,
        config=_connection_config(row),
        profile_id=inventory.default_profile_id if inventory else None,
        revision=inventory.inventory_revision if inventory else 1,
        frozen_normalization=inventory.frozen_normalization if inventory else None,
        health=health,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _connection_interval(
    tx: InventoryTx, settings: Settings, row: Source, inventory: SourceInventory | None
) -> int:
    """The cadence of the connection in seconds, or 0 if none is set. Under v2
    it is the `interval_s` of the default profile. Under v1 it is the
    `interval_s` of the source row config."""
    state = await tx.get_state()
    context = collection.context_from_state(state)
    if not context.v2:
        try:
            return int(row.config.get("interval_s") or 0)
        except (TypeError, ValueError):
            return 0
    if inventory is None or inventory.default_profile_id is None:
        return 0
    profile = await tx.get_profile(inventory.default_profile_id)
    if profile is None:
        return 0
    version = await tx.get_profile_version(profile.id, profile.current_revision)
    if version is None:
        return 0
    try:
        return int(version.settings.get("interval_s") or 0)
    except (TypeError, ValueError):
        return 0


# --- lookups ---------------------------------------------------------------------------------------------


async def _source_by_id(
    store: Store, tx: InventoryTx, connection_id: str
) -> tuple[Source, SourceInventory | None]:
    """Return the source row and its inventory record. `connection_id` is the
    integer source id as text or the name of the source."""
    inventory: SourceInventory | None = None
    if connection_id.isdigit():
        inventory = await tx.get_source_inventory(int(connection_id))
    if inventory is None:
        inventory = await tx.get_source_inventory_by_key(connection_id)
    name = inventory.name if inventory is not None else connection_id
    row = await store.get_source(name)
    if row is None or (connection_id.isdigit() and inventory is None and str(row.id) != connection_id):
        raise NotFound("connection not found")
    return row, inventory


async def _locked_source(records: ExecutionRecords, name: str) -> Source:
    """The source row `name`, locked FOR NO KEY UPDATE until the transaction ends."""
    row = await records.get_source(name, lock=True)
    if row is None:
        raise NotFound("connection not found")
    return row


async def _target_or_404(tx: InventoryTx, target_id: uuid.UUID) -> InventoryTarget:
    target = await tx.get_target(target_id)
    if target is None:
        raise NotFound("target not found")
    return target


def _check_profile_type(profile_type: str, row: Source) -> None:
    if profile_type != row.type:
        raise Validation(f"profile is for collector type {profile_type!r}, connection is {row.type!r}")


async def _profile_for(tx: InventoryTx, profile_id: uuid.UUID, row: Source):
    profile = await tx.get_profile(profile_id)
    if profile is None or profile.archived_at is not None:
        raise Validation("profile does not exist or is archived")
    _check_profile_type(profile.collector_type, row)
    return profile


async def _site_id(store: Store, site_id: str | None) -> int | None:
    if site_id is None:
        return None
    for site in await store.list_sites():
        if str(site.id) == site_id or site.code == site_id:
            return site.id
    raise Validation(f"site {site_id!r} does not exist")


def _validate_shape(
    row_type: str, config: Mapping[str, Any], settings: Mapping[str, Any], secret_paths: Sequence[str]
) -> None:
    """Validate the composed collector config against the ConfigModel with
    placeholder secrets."""
    if row_type not in coll.REGISTRY:
        raise Validation(f"unknown collector type {row_type!r}")
    payload = collection.unflatten({**collection.flatten(config), **collection.flatten(settings)})
    payload = glue.inject_secrets(payload, dict.fromkeys(secret_paths, "placeholder"))
    payload.pop("source_name", None)
    try:
        coll.REGISTRY[row_type].ConfigModel(**payload)
    except ValidationError as exc:
        raise Validation(_first_error(exc)) from exc


# --- connections ----------------------------------------------------------------------------------------


@router.get("/connections", response_model=list[ConnectionView])
async def list_connections(
    request: Request,
    query: Annotated[ConnectionListQuery, Query()],
    user: User = Depends(require_runs_manage),
) -> list[ConnectionView]:
    store, settings = _store(request), _settings(request)
    out: list[ConnectionView] = []
    async with store.inventory().transaction() as tx:
        inventories = {s.name: s for s in await tx.list_source_inventory()}
        for row in await store.list_sources():
            if query.collector_type and row.type != query.collector_type:
                continue
            if query.kind is not None and _kind_of(row) != query.kind:
                continue
            out.append(await connection_view(tx, store, settings, row, inventories.get(row.name)))
    return out


@router.get("/connections/{connection_id}", response_model=ConnectionView)
async def get_connection(
    request: Request, connection_id: str, user: User = Depends(require_runs_manage)
) -> ConnectionView:
    store, settings = _store(request), _settings(request)
    async with store.inventory().transaction() as tx:
        row, inventory = await _source_by_id(store, tx, connection_id)
        return await connection_view(tx, store, settings, row, inventory)


@router.post("/connections", status_code=201, response_model=ConnectionView)
async def create_connection(
    request: Request, body: ConnectionCreate, user: User = Depends(require_sources_write)
) -> ConnectionView:
    store, settings = _store(request), _settings(request)
    if body.name in RESERVED_NAMES:
        raise Validation(f"{body.name} is a reserved name")
    if body.collector_type not in coll.REGISTRY:
        raise Validation(f"unknown collector type {body.collector_type!r}")
    try:
        config = collection.validate_connection_config(body.collector_type, body.config)
    except collection.SettingsRejected as exc:
        raise Validation(str(exc)) from exc
    await _check_location_sites(store, body.collector_type, config)
    config.pop("source_name", None)
    now = _now()
    async with store.inventory().transaction() as tx:
        records = ExecutionRecords(store, tx)
        settings_map: dict[str, Any] = {}
        secret_paths: list[str] = []
        if body.profile_id is not None:
            profile = await tx.get_profile(body.profile_id)
            if profile is None or profile.archived_at is not None:
                raise Validation("profile does not exist or is archived")
            if profile.collector_type != body.collector_type:
                raise Validation(f"profile is for collector type {profile.collector_type!r}")
            version = await tx.get_profile_version(profile.id, profile.current_revision)
            if version is not None:
                settings_map = dict(version.settings)
                if version.credential_id is not None and version.credential_revision is not None:
                    cv = await tx.get_credential_version(version.credential_id, version.credential_revision)
                    secret_paths = list(cv.secret_paths) if cv else []
            _validate_shape(body.collector_type, config, settings_map, secret_paths)
        row = await records.create_source(body.name, body.collector_type, config, body.enabled)
        inventory = await tx.get_source_inventory(row.id)
        if inventory is None:
            inventory = await tx.get_source_inventory_by_key(row.name)
        if inventory is not None and (body.display_name or body.profile_id is not None):
            inventory = await tx.update_source_inventory(
                inventory.source_id,
                expected_revision=inventory.inventory_revision,
                now=now,
                display_name=body.display_name,
                default_profile_id=body.profile_id,
            )
        # A controller connection, or a direct connection with a host, gets
        # 1 target for its own endpoint.
        if not glue.is_group(body.collector_type) or config.get("host"):
            await tx.create_target(
                source_id=row.id,
                source_key=row.name,
                host=str(config.get("host") or ""),
                kind=_target_kind(row, None).value,
                now=now,
                enabled=body.enabled,
            )
        await tx.append_event(
            entity_type="connection",
            entity_id=str(row.id),
            actor_id=user.id,
            action="created",
            now=now,
            after={
                "name": row.name,
                "collector_type": row.type,
                "config": _connection_config(row),
                "enabled": body.enabled,
            },
            sensitive=True,
        )
    return await _committed_view(store, settings, row.id)


@dataclass
class Binding:
    """A profile, its current version and the secret paths of the credential version it pins."""

    profile: CollectionProfile
    version: CollectionProfileVersion
    secret_paths: list[str]


async def _binding(tx: InventoryTx, profile_id: uuid.UUID | None) -> Binding | None:
    """The binding of a profile that pins a credential with secrets, or None."""
    profile = await tx.get_profile(profile_id) if profile_id is not None else None
    if profile is None:
        return None
    version = await tx.get_profile_version(profile.id, profile.current_revision)
    if version is None or version.credential_id is None or version.credential_revision is None:
        return None
    cv = await tx.get_credential_version(version.credential_id, version.credential_revision)
    paths = sorted(cv.secret_paths) if cv is not None else []
    return Binding(profile, version, paths) if paths else None


def _kept(before: Binding | None, after: Binding | None) -> Binding | None:
    """`before` when `after` pins the same credential, None otherwise."""
    if before is None or after is None or before.version.credential_id != after.version.credential_id:
        return None
    return before


def _require_credentials(
    collector_type: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    kept: Binding | None,
    secrets: Mapping[str, str] | None,
) -> dict[str, str] | None:
    """Raise CredentialsRequiredError when `after` moves the endpoint or weakens the TLS
    check of `before`, and `secrets` lacks a secret of the kept binding. Return the
    validated `secrets` to bind, or None when the request has none."""
    paths = kept.secret_paths if kept is not None else []
    given = {path for path, value in (secrets or {}).items() if value}
    try:
        source_egress.require_secrets(collector_type, before, after, paths, given)
    except source_egress.CredentialsRequired as exc:
        raise CredentialsRequiredError(exc) from exc
    if not secrets:
        return None
    if kept is None:
        raise Validation("the secrets replace a stored credential, and the change keeps none")
    try:
        return credentials.validate_secret_map([collector_type], secrets)
    except credentials.SecretsRejected as exc:
        raise Validation(str(exc)) from exc


async def _rebind(
    tx: InventoryTx,
    key: str,
    binding: Binding,
    secrets: Mapping[str, str],
    *,
    label: str,
    assign: Any,
    actor_id: int | None,
    now: datetime,
    request_id: str | None = None,
) -> None:
    """Pin a new credential that holds `secrets` in place of the credential of the binding.

    A profile that 1 connection or 1 target follows gets a new revision. A shared profile
    stays as it is, and `assign` receives the id of a copy that pins the new credential."""
    suffix = uuid.uuid4().hex[:8]
    cred, cv = await tx.create_credential(
        display_name=f"{label} {suffix}",
        sealed=credentials.seal(key, secrets),
        secret_paths=sorted(secrets),
        actor_id=actor_id,
        now=now,
    )
    await tx.append_event(
        entity_type="credential",
        entity_id=str(cred.id),
        actor_id=actor_id,
        action="created",
        now=now,
        after={"display_name": cred.display_name, "secrets": credentials.redact_secret_names(secrets)},
        request_id=request_id,
        sensitive=True,
    )
    profile, settings_map = binding.profile, dict(binding.version.settings)
    refs = await tx.profile_references(profile.id)
    if len(refs.source_ids) + len(refs.target_ids) > 1:
        copy, _ = await tx.create_profile(
            display_name=f"{profile.display_name} {suffix}",
            collector_type=profile.collector_type,
            settings=settings_map,
            credential_id=cred.id,
            credential_revision=cv.revision,
            actor_id=actor_id,
            now=now,
        )
        await assign(copy.id)
        return
    await tx.add_profile_version(
        profile.id,
        expected_revision=profile.current_revision,
        settings=settings_map,
        credential_id=cred.id,
        credential_revision=cv.revision,
        actor_id=actor_id,
        now=now,
    )


def _assigner(tx: InventoryTx, row: Source, target: InventoryTarget | None, now: datetime) -> Any:
    """A callback that makes a profile the profile of `target`, or the default profile of
    the connection when `target` has no profile of its own."""

    async def assign(profile_id: uuid.UUID) -> None:
        if target is not None and target.profile_id is not None:
            fresh = await tx.get_target(target.id)
            revision = fresh.revision if fresh is not None else target.revision
            await tx.update_target(target.id, expected_revision=revision, now=now, profile_id=profile_id)
            return
        inventory = await tx.get_source_inventory(row.id)
        if inventory is None:
            raise NotFound("connection has no inventory record")
        await tx.update_source_inventory(
            row.id, expected_revision=inventory.inventory_revision, now=now, default_profile_id=profile_id
        )

    return assign


async def _committed_view(store: Store, settings: Settings, source_id: int) -> ConnectionView:
    """The saved connection's view, built in a new read transaction after the
    write commits."""
    async with store.inventory().transaction() as tx:
        row, inventory = await _source_by_id(store, tx, str(source_id))
        view = await connection_view(tx, store, settings, row, inventory)
    return await _with_scope_warnings(store, settings, view)


async def _with_scope_warnings(store: Store, settings: Settings, view: ConnectionView) -> ConnectionView:
    """Return the view with a warning if another controller connection resolves
    to its routing scope (app/sources.py shared_routing_scope_warnings). The
    function reads the rows after the save commits, each with its frozen
    normalization."""
    from hst.app.inventory.legacy import LegacyConnections

    warnings = await glue.routing_scope_warnings(
        store, settings, view.name, read=LegacyConnections(store, settings).read
    )
    return view.model_copy(update={"warnings": warnings}) if warnings else view


@router.patch("/connections/{connection_id}", response_model=ConnectionView)
async def patch_connection(
    request: Request, connection_id: str, body: ConnectionPatch, user: User = Depends(require_sources_write)
) -> ConnectionView:
    store, settings = _store(request), _settings(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        records = ExecutionRecords(store, tx)
        row, inventory = await _source_by_id(store, tx, connection_id)
        row = await _locked_source(records, row.name)
        if inventory is None:
            raise NotFound("connection has no inventory record")
        if body.expected_revision != inventory.inventory_revision:
            raise StaleRevision(
                f"connection is at revision {inventory.inventory_revision}, not {body.expected_revision}",
                current_revision=inventory.inventory_revision,
            )
        before = {
            "display_name": inventory.display_name,
            "profile_id": str(inventory.default_profile_id),
            "enabled": row.enabled,
        }
        new_config: dict | None = None
        if body.config is not None:
            try:
                overlay = collection.validate_connection_config(row.type, body.config)
            except collection.SettingsRejected as exc:
                raise Validation(str(exc)) from exc
            await _check_location_sites(store, row.type, overlay)
            # An identity field of the endpoint changes only through target replacement.
            identity = collection.identity_paths(
                row.type, FieldCategory.CONNECTION.value, FieldCategory.TARGET.value
            )
            current = collection.flatten(row.config)
            # A path that the stored config lacks and that the edit sends empty counts
            # as unchanged. The form sends "" for every field that it shows.
            changed = {
                p
                for p, v in collection.flatten(overlay).items()
                if current.get(p) != v and not (current.get(p) in (None, "") and v in (None, "", [], {}))
            }
            blocked = sorted(changed & identity)
            if blocked:
                raise Validation(
                    "identity-bearing fields change through target replacement, not a connection edit: "
                    + ", ".join(blocked)
                )
            new_config = glue._overlay(row.config, overlay)
            new_config.pop("source_name", None)
        endpoints: list[InventoryTarget | None] = [
            t
            for t in await tx.list_targets(row.id)
            if t.kind != TargetKind.DIRECT.value and t.archived_at is None
        ]
        after_default = None if body.clear_profile else (body.profile_id or inventory.default_profile_id)
        # A connection without a controller or implicit target checks its default profile.
        kept: list[tuple[Binding, InventoryTarget | None, dict[str, str]]] = []
        for endpoint in endpoints or [None]:
            own = endpoint.profile_id if endpoint is not None else None
            before_binding = await _binding(tx, own or inventory.default_profile_id)
            after_binding = await _binding(tx, own or after_default)
            binding = _kept(before_binding, after_binding)
            secrets = _require_credentials(
                row.type,
                row.config,
                new_config if new_config is not None else row.config,
                binding,
                body.secret_values(),
            )
            if (
                binding is not None
                and secrets is not None
                and all(b.profile.id != binding.profile.id for b, _, _ in kept)
            ):
                kept.append((binding, endpoint, secrets))
        if body.clear_jump_host_keys:
            base = new_config if new_config is not None else row.config
            if base.get(collection.JUMP_PINS):
                new_config = {k: v for k, v in base.items() if k != collection.JUMP_PINS}
        if body.profile_id is not None:
            await _profile_for(tx, body.profile_id, row)
        profile_arg: Any = UNSET
        if body.clear_profile:
            profile_arg = None
        elif body.profile_id is not None:
            profile_arg = body.profile_id
        inventory = await tx.update_source_inventory(
            inventory.source_id,
            expected_revision=inventory.inventory_revision,
            now=now,
            display_name=body.display_name if body.display_name is not None else UNSET,
            default_profile_id=profile_arg,
        )
        if new_config is not None or body.enabled is not None:
            await records.update_source(row.name, config=new_config, enabled=body.enabled)
            if body.enabled is not None:
                # The implicit or controller target gets the `enabled` value of the connection.
                for target in await tx.list_targets(row.id):
                    if target.kind != TargetKind.DIRECT.value and target.archived_at is None:
                        await tx.update_target(
                            target.id, expected_revision=target.revision, now=now, enabled=body.enabled
                        )
        for binding, endpoint, secrets in kept:
            await _rebind(
                tx,
                _key(request),
                binding,
                secrets,
                label=row.name,
                assign=_assigner(tx, row, endpoint, now),
                actor_id=user.id,
                now=now,
            )
        fresh = await records.get_source(row.name)
        row = fresh if fresh is not None else row
        await tx.append_event(
            entity_type="connection",
            entity_id=str(row.id),
            actor_id=user.id,
            action="updated",
            now=now,
            before=before,
            after={
                "display_name": inventory.display_name,
                "profile_id": str(inventory.default_profile_id),
                "enabled": row.enabled,
                "config": _connection_config(row) if new_config is not None else None,
            },
            sensitive=True,
        )
    return await _committed_view(store, settings, row.id)


@router.delete("/connections/{connection_id}")
async def delete_connection_direct(
    request: Request, connection_id: str, user: User = Depends(require_sources_write)
) -> JSONResponse:
    """Deletion needs a preview."""
    store = _store(request)
    async with store.inventory().transaction() as tx:
        await _source_by_id(store, tx, connection_id)
    raise Validation(
        "connection deletion requires a preview: POST /operations/preview with operation delete_connection"
    )


# --- targets -------------------------------------------------------------------------------------------


@router.get("/targets", response_model=list[TargetView])
async def list_targets(
    request: Request,
    connection_id: str | None = None,
    include_archived: bool = False,
    user: User = Depends(require_runs_manage),
) -> list[TargetView]:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        source_id: int | None = None
        if connection_id is not None:
            row, _ = await _source_by_id(store, tx, connection_id)
            source_id = row.id
        targets = await tx.list_targets(source_id, include_archived=include_archived)
        return await _target_views(tx, store, targets)


@router.get("/targets/{target_id}", response_model=TargetView)
async def get_target(
    request: Request, target_id: uuid.UUID, user: User = Depends(require_runs_manage)
) -> TargetView:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        target = await _target_or_404(tx, target_id)
        return target_view(target, await _target_context(tx, store, target))


@router.post("/targets", status_code=201, response_model=TargetView)
async def create_target(
    request: Request, body: TargetCreate, user: User = Depends(require_sources_write)
) -> TargetView:
    store = _store(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        records = ExecutionRecords(store, tx)
        row, _inventory = await _source_by_id(store, tx, body.connection_id)
        if not glue.is_group(row.type):
            raise Validation(
                "a controller connection has one target, its endpoint; "
                "add direct targets to a direct connection"
            )
        endpoint_config = _target_identity(row, body.endpoint_config)
        if body.profile_id is not None:
            await _profile_for(tx, body.profile_id, row)
        site_id = await _site_id(store, body.onboarding_site_id)
        if await tx.get_active_target(row.name, body.host) is not None:
            raise Conflict(
                f"an active target {body.host!r} exists on {row.name}",
                references=[f"target:{row.name}/{body.host}"],
            )
        if any(d.host == body.host for d in await store.list_devices(row.name)):
            raise Conflict(f"the fleet of {row.name} already carries {body.host!r}")
        # The first direct target of the fleet archives the implicit target.
        # The implicit host is not collected once device rows exist.
        for existing in await tx.list_targets(row.id):
            if existing.kind == TargetKind.IMPLICIT.value and existing.archived_at is None:
                await tx.retire_observations(existing.id, now)
                await tx.archive_target(existing.id, expected_revision=None, now=now)
        device = await records.add_device(row.name, body.host, body.port, body.enabled)
        target = await tx.create_target(
            source_id=row.id,
            source_key=row.name,
            host=body.host,
            kind=TargetKind.DIRECT.value,
            now=now,
            legacy_device_id=device.id,
            profile_id=body.profile_id,
            onboarding_site_id=site_id,
            enabled=body.enabled,
            **({"endpoint_config": endpoint_config} if endpoint_config else {}),
        )
        await tx.append_event(
            entity_type="target",
            entity_id=str(target.id),
            actor_id=user.id,
            action="created",
            now=now,
            after={
                "source_key": row.name,
                "host": body.host,
                "port": body.port,
                "enabled": body.enabled,
                "profile_id": str(body.profile_id) if body.profile_id else None,
            },
        )
        return target_view(target, await _target_context(tx, store, target))


@router.patch("/targets/{target_id}", response_model=TargetView)
async def patch_target(
    request: Request, target_id: uuid.UUID, body: TargetPatch, user: User = Depends(require_sources_write)
) -> TargetView:
    store = _store(request)
    now = _now()
    async with store.inventory().transaction() as tx:
        records = ExecutionRecords(store, tx)
        target = await _target_or_404(tx, target_id)
        if target.archived_at is not None:
            raise Conflict("target is archived")
        if body.expected_revision != target.revision:
            raise StaleRevision(
                f"target is at revision {target.revision}, not {body.expected_revision}",
                current_revision=target.revision,
            )
        row = await _locked_source(records, target.source_key)
        if body.profile_id is not None:
            await _profile_for(tx, body.profile_id, row)
        profile_arg: Any = UNSET
        if body.clear_profile:
            profile_arg = None
        elif body.profile_id is not None:
            profile_arg = body.profile_id
        site_arg: Any = UNSET
        if body.clear_onboarding_site:
            site_arg = None
        elif body.onboarding_site_id is not None:
            site_arg = await _site_id(store, body.onboarding_site_id)
        before = {
            "enabled": target.enabled,
            "profile_id": str(target.profile_id) if target.profile_id else None,
        }
        updated = await tx.update_target(
            target.id,
            expected_revision=target.revision,
            now=now,
            enabled=body.enabled if body.enabled is not None else UNSET,
            profile_id=profile_arg,
            onboarding_site_id=site_arg,
        )
        if body.enabled is not None and target.kind == TargetKind.DIRECT.value:
            await records.set_device_enabled(row.name, target.host, body.enabled)
        elif body.enabled is not None:
            await records.update_source(row.name, enabled=body.enabled)
        if body.clear_host_key:
            if target.kind == TargetKind.DIRECT.value:
                await records.clear_device_host_key(row.name, target.host)
            elif row.config.get("host_key"):
                await records.update_source(row.name, config={**row.config, "host_key": ""})
        await tx.append_event(
            entity_type="target",
            entity_id=str(target.id),
            actor_id=user.id,
            action="updated",
            now=now,
            before=before,
            after={
                "enabled": updated.enabled,
                "profile_id": str(updated.profile_id) if updated.profile_id else None,
                "host_key_cleared": body.clear_host_key,
            },
        )
        return target_view(updated, await _target_context(tx, store, updated))


@router.delete("/targets/{target_id}")
async def delete_target_direct(
    request: Request, target_id: uuid.UUID, user: User = Depends(require_sources_write)
) -> JSONResponse:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        await _target_or_404(tx, target_id)
    raise Validation(
        "target deletion requires a preview: POST /operations/preview with operation delete_target"
    )


# --- effective settings and probe -----------------------------------------------------------------------


async def _resolve_target(
    store: Store, settings: Settings, tx: InventoryTx, target: InventoryTarget, *, key: str | None
) -> tuple[collection.ResolvedCollection, Source, Device | None]:
    row = await store.get_source(target.source_key)
    if row is None:
        raise NotFound("connection not found")
    device = None
    if target.kind == TargetKind.DIRECT.value:
        device = next((d for d in await store.list_devices(row.name) if d.host == target.host), None)
    context = collection.context_from_state(await tx.get_state())
    resolver = collection.Resolver(tx, settings, context=context, key=key)
    sites = {site.code: site for site in await store.list_sites()}
    try:
        resolved = await resolver.resolve(
            row,
            device=device,
            host=target.host if device is None else None,
            with_secrets=key is not None,
            sites=sites,
        )
    except collection.RepairRequired as exc:
        raise Conflict(str(exc), references=[f"credential:{exc.credential_id}"]) from exc
    except collection.ResolutionError as exc:
        raise Validation(str(exc)) from exc
    if resolved.effective.target_id is None:
        resolved.effective = resolved.effective.model_copy(update={"target_id": target.id})
    return resolved, row, device


@router.get("/targets/{target_id}/effective", response_model=EffectiveCollection)
async def effective_settings(
    request: Request, target_id: uuid.UUID, user: User = Depends(require_runs_manage)
) -> EffectiveCollection:
    store, settings = _store(request), _settings(request)
    async with store.inventory().transaction() as tx:
        target = await _target_or_404(tx, target_id)
        resolved, _row, _device = await _resolve_target(store, settings, tx, target, key=None)
        return resolved.effective


@router.post("/targets/{target_id}/probe", response_model=ProbeResult)
async def probe_target(
    request: Request,
    target_id: uuid.UUID,
    body: ProbeRequest | None = None,
    user: User = Depends(require_runs_manage),
) -> ProbeResult:
    """Probe the target with the stored effective revision. A disabled target
    is probed like an enabled target."""
    store, settings = _store(request), _settings(request)
    key = _key(request)
    async with store.inventory().transaction() as tx:
        target = await _target_or_404(tx, target_id)
        try:
            resolved, row, device = await _resolve_target(store, settings, tx, target, key=key)
        except Conflict as exc:
            # A credential that needs repair gives a failed probe result.
            probe_effective, _r, _d = await _resolve_target(store, settings, tx, target, key=None)
            return ProbeResult(
                ok=False,
                message=str(exc),
                effective=probe_effective.effective,
                host_key_pinned=False,
                duration_ms=0,
            )
    rows = {r.name: r for r in await store.list_sources()}
    sites = {site.code: site for site in await store.list_sites()}
    secrets = resolved.secrets
    t0 = time.monotonic()
    try:
        if device is not None:
            collector = glue.build_device_collector(
                row, device, settings, sites=sites, sources=rows, effective=resolved
            )
        else:
            collector = glue.build_collector(row, settings, sites=sites, sources=rows, effective=resolved)
        detail = await asyncio.to_thread(collector.probe)
        await runs_exec.pin_host_key(store, row, collector, device)
        ok, message = True, glue.redacted(str(detail), secrets)
    except Exception as exc:
        ok, message = False, glue.redacted(f"{type(exc).__name__}: {exc}", secrets)
    duration = int((time.monotonic() - t0) * 1000)
    pinned = False
    if device is not None:
        fresh = next((d for d in await store.list_devices(row.name) if d.host == device.host), None)
        pinned = bool(fresh.host_key) if fresh else False
    else:
        fresh_row = await store.get_source(row.name)
        pinned = bool((fresh_row.config.get("host_key") if fresh_row else "") or "")
    return ProbeResult(
        ok=ok, message=message, effective=resolved.effective, host_key_pinned=pinned, duration_ms=duration
    )


# --- operations: preview and apply ------------------------------------------------------------------------


@dataclass
class OperationContext:
    store: Store
    settings: Settings
    key: str
    actor: User
    now: datetime
    tx: InventoryTx
    state: InventoryState


@dataclass
class PreviewPlan:
    """The result of the preview of an operation. It holds the members with
    their revisions, the impact rows to store, the redacted change, the counts,
    the warnings and a sealed secret draft if the change has secrets."""

    members: list[PreviewMember]
    impacts: list[tuple[str, str, dict]]
    changes: dict[str, Any]
    affected_devices: int
    affected_targets: int
    warnings: list[str] = field(default_factory=list)
    secret_draft: bytes | None = None
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApplyOutcome:
    results: list[ApplyResult]
    job_ids: list[int] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class OperationHandler(Protocol):
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan: ...

    async def apply(
        self, ctx: OperationContext, preview: OperationPreview, request_id: str
    ) -> ApplyOutcome: ...


OPERATIONS: dict[PreviewOperation, OperationHandler] = {}


def register_operation(operation: PreviewOperation, handler: OperationHandler) -> None:
    OPERATIONS[operation] = handler


def _member(kind: PreviewMemberKind, id_: str, revision: int, label: str) -> PreviewMember:
    return PreviewMember(kind=kind, id=id_, revision=revision, label=label)


def _member_ids(preview: OperationPreview, kind: PreviewMemberKind) -> list[tuple[str, int]]:
    return [(m["id"], int(m["revision"])) for m in preview.members if m.get("kind") == kind.value]


async def _selected_targets(
    ctx: OperationContext, selection: Selection
) -> tuple[list[InventoryTarget], list[str]]:
    """Return the targets of a selection and the warnings. An id of the
    selection is a target id or a device id. A device selects every active
    target that observes it. A warning lists each device that has no active
    target or that is observed through 2 or more connections. A filter
    selection selects devices."""
    warnings: list[str] = []
    targets: dict[uuid.UUID, InventoryTarget] = {}
    devices: list[InventoryDevice] = []
    if selection.ids is not None:
        for raw in selection.ids:
            try:
                id_ = uuid.UUID(raw)
            except ValueError as exc:
                raise Validation(f"{raw!r} is not a target or device id") from exc
            target = await ctx.tx.get_target(id_)
            if target is not None:
                if target.archived_at is not None:
                    raise Validation(f"target {id_} is archived")
                targets[target.id] = target
                continue
            device = await ctx.tx.get_device(id_)
            if device is None:
                raise NotFound(f"no target or device {id_}")
            devices.append(device)
    else:
        devices = await _filtered_devices(ctx, selection)
    for device in devices:
        observing = await ctx.tx.get_observations(device.id)
        found = []
        for obs in observing:
            target = await ctx.tx.get_target(obs.target_id)
            if target is not None and target.archived_at is None:
                found.append(target)
        if not found:
            warnings.append(f"device {device.hostname or device.graph_uid} has no active target")
            continue
        if len({t.source_key for t in found}) > 1:
            warnings.append(
                f"device {device.hostname or device.graph_uid} is observed through "
                f"{len(found)} connections; all its targets are selected, narrow to the intended ones"
            )
        for target in found:
            targets[target.id] = target
    if len(targets) > MAX_SELECTION:
        raise Validation(
            f"selection expands to {len(targets)} targets; the limit is {MAX_SELECTION}, narrow the selection"
        )
    return list(targets.values()), warnings


async def _filtered_devices(ctx: OperationContext, selection: Selection) -> list[InventoryDevice]:
    query = selection.filter
    if query is None:
        raise Validation("a filter selection is required")
    if selection.intent_generation != ctx.state.intent_generation:
        raise InventoryChanged("the inventory changed since the selection was made; refresh and select again")
    filters = await _device_filters(ctx.store, query)
    out: list[InventoryDevice] = []
    cursor: str | None = None
    while True:
        page = await ctx.tx.list_devices(
            filters, sort=query.sort, direction=query.direction, limit=200, cursor=cursor
        )
        out.extend(item.device for item in page.items)
        if len(out) > MAX_SELECTION:
            raise Validation(f"the filter selects more than {MAX_SELECTION} devices; narrow the selection")
        cursor = page.next_cursor
        if cursor is None:
            return out


async def _device_filters(store: Store, query: DeviceListQuery) -> DeviceFilters:
    site_ids: list[int] = []
    if query.site_id:
        sites = await store.list_sites()
        for wanted in query.site_id:
            match = next((s.id for s in sites if str(s.id) == wanted or s.code == wanted), None)
            if match is None:
                raise Validation(f"unknown site {wanted!r}")
            site_ids.append(match)
    source_ids: list[int] = []
    if query.connection_id:
        sources = await store.list_sources()
        for wanted in query.connection_id:
            match = next((s.id for s in sources if str(s.id) == wanted or s.name == wanted), None)
            if match is None:
                raise Validation(f"unknown connection {wanted!r}")
            source_ids.append(match)
    return DeviceFilters(
        q=query.q,
        site_ids=site_ids,
        source_ids=source_ids,
        platforms=list(query.platform),
        collection_states=[s.value for s in query.collection_state],
        placement_states=[s.value for s in query.placement_state],
        lifecycles=[s.value for s in query.lifecycle],
    )


async def _impact_rows_for_targets(
    ctx: OperationContext, targets: Sequence[InventoryTarget]
) -> tuple[list[tuple[str, str, dict]], set[uuid.UUID]]:
    """Return 1 impact row for each target and 1 for each device that the
    target observes, with the set of the device ids."""
    rows: list[tuple[str, str, dict]] = []
    device_ids: set[uuid.UUID] = set()
    observed = await _FleetIndex(ctx.tx, ctx.store).device_ids(targets)
    devices = {
        device.id: device
        for device in await ctx.tx.get_devices(list({i for ids in observed.values() for i in ids}))
    }
    for target in targets:
        ids = observed[target.id]
        rows.append(
            (
                PreviewMemberKind.TARGET.value,
                str(target.id),
                {
                    "connection_id": str(target.source_id)
                    if target.source_id is not None
                    else target.source_key,
                    "host": target.host,
                    "device_count": len(ids),
                },
            )
        )
        for device_id in ids:
            device_ids.add(device_id)
            device = devices.get(device_id)
            rows.append(
                (
                    PreviewMemberKind.DEVICE.value,
                    str(device_id),
                    {
                        "target_id": str(target.id),
                        "hostname": device.hostname if device else "",
                        "graph_uid": device.graph_uid if device else "",
                    },
                )
            )
    return rows, device_ids


async def _profile_targets(
    tx: InventoryTx, profile_id: uuid.UUID
) -> tuple[list[InventoryTarget], list[SourceInventory]]:
    """Return the active targets that use the profile and the connections whose
    default profile it is. A target uses the profile by assignment, or by the
    default of its connection if the target has no profile."""
    refs = await tx.profile_references(profile_id)
    targets: dict[uuid.UUID, InventoryTarget] = {}
    for t in await tx.get_targets(refs.target_ids):
        if t.archived_at is None:
            targets[t.id] = t
    connections: list[SourceInventory] = []
    for source_id in refs.source_ids:
        inventory = await tx.get_source_inventory(source_id)
        if inventory is None:
            continue
        connections.append(inventory)
        for t in await tx.list_targets(source_id):
            if t.archived_at is None and t.profile_id is None:
                targets[t.id] = t
    return list(targets.values()), connections


class AssignTargetProfile:
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan:
        if not isinstance(change, ProfileAssignmentChange):
            raise Validation("assign_target_profile needs a profile assignment change")
        targets, warnings = await _selected_targets(ctx, selection)
        if not targets:
            raise Validation("the selection names no target")
        profile = None
        if change.profile_id is not None:
            profile = await ctx.tx.get_profile(change.profile_id)
            if profile is None or profile.archived_at is not None:
                raise Validation("profile does not exist or is archived")
            for target in targets:
                row = await ctx.store.get_source(target.source_key)
                if row is not None:
                    _check_profile_type(profile.collector_type, row)
        members = [
            _member(
                PreviewMemberKind.TARGET,
                str(t.id),
                t.revision,
                f"{t.source_key}/{t.host}" if t.host else t.source_key,
            )
            for t in targets
        ]
        impacts, device_ids = await _impact_rows_for_targets(ctx, targets)
        return PreviewPlan(
            members=members,
            impacts=impacts,
            changes={
                "profile_id": str(change.profile_id) if change.profile_id else None,
                "profile_name": profile.display_name if profile else None,
            },
            affected_devices=len(device_ids),
            affected_targets=len(targets),
            warnings=warnings,
            summary={"targets": len(targets), "devices": len(device_ids)},
        )

    async def apply(self, ctx: OperationContext, preview: OperationPreview, request_id: str) -> ApplyOutcome:
        raw = preview.changes.get("profile_id")
        profile_id = uuid.UUID(raw) if raw else None
        if profile_id is not None:
            profile = await ctx.tx.get_profile(profile_id)
            if profile is None or profile.archived_at is not None:
                raise Conflict("profile no longer exists")
        results: list[ApplyResult] = []
        for id_, revision in _member_ids(preview, PreviewMemberKind.TARGET):
            target_id = uuid.UUID(id_)
            before = await ctx.tx.get_target(target_id)
            updated = await ctx.tx.update_target(
                target_id, expected_revision=revision, now=ctx.now, profile_id=profile_id
            )
            await ctx.tx.append_event(
                entity_type="target",
                entity_id=id_,
                actor_id=ctx.actor.id,
                action="profile_assigned",
                now=ctx.now,
                before={"profile_id": str(before.profile_id) if before and before.profile_id else None},
                after={"profile_id": str(profile_id) if profile_id else None},
                request_id=request_id,
            )
            results.append(ApplyResult(kind=PreviewMemberKind.TARGET, id=id_, revision=updated.revision))
        return ApplyOutcome(results)


class EditProfile:
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan:
        if not isinstance(change, ProfilePatch):
            raise Validation("edit_profile needs a profile patch")
        if selection.ids is None or len(selection.ids) != 1:
            raise Validation("edit_profile selects exactly one profile id")
        profile_id = _uuid_of(selection.ids[0], "profile")
        profile = await ctx.tx.get_profile(profile_id)
        if profile is None or profile.archived_at is not None:
            raise NotFound("profile not found")
        if change.expected_revision != profile.current_revision:
            raise StaleRevision(
                f"profile is at revision {profile.current_revision}, not {change.expected_revision}",
                current_revision=profile.current_revision,
            )
        version = await ctx.tx.get_profile_version(profile.id, profile.current_revision)
        settings_map = dict(version.settings) if version else {}
        if change.settings is not None:
            try:
                settings_map = collection.validate_profile_settings(profile.collector_type, change.settings)
            except collection.SettingsRejected as exc:
                raise Validation(str(exc)) from exc
        credential_id = version.credential_id if version else None
        if change.clear_credential:
            credential_id = None
        elif change.credential_id is not None:
            cred = await ctx.tx.get_credential(change.credential_id)
            if cred is None or cred.archived_at is not None:
                raise Validation("credential does not exist or is archived")
            credential_id = cred.id
        await _require_profile_credentials(
            ctx.tx, profile.collector_type, version, settings_map, credential_id
        )
        targets, connections = await _profile_targets(ctx.tx, profile.id)
        impacts, device_ids = await _impact_rows_for_targets(ctx, targets)
        for inventory in connections:
            impacts.append(
                (
                    PreviewMemberKind.CONNECTION.value,
                    str(inventory.source_id),
                    {"name": inventory.name, "display_name": inventory.display_name},
                )
            )
        changes = change.model_dump(mode="json", exclude_none=True)
        changes["settings"] = settings_map if change.settings is not None else None
        changes["credential_id"] = str(credential_id) if credential_id else None
        return PreviewPlan(
            members=[
                _member(
                    PreviewMemberKind.PROFILE, str(profile.id), profile.current_revision, profile.display_name
                )
            ],
            impacts=impacts,
            changes=changes,
            affected_devices=len(device_ids),
            affected_targets=len(targets),
            summary={"targets": len(targets), "connections": len(connections), "devices": len(device_ids)},
        )

    async def apply(self, ctx: OperationContext, preview: OperationPreview, request_id: str) -> ApplyOutcome:
        [(id_, revision)] = _member_ids(preview, PreviewMemberKind.PROFILE)
        profile_id = uuid.UUID(id_)
        changes = preview.changes
        result = await apply_profile_edit(
            ctx.tx,
            profile_id,
            expected_revision=revision,
            display_name=changes.get("display_name"),
            settings=changes.get("settings"),
            credential_id=uuid.UUID(changes["credential_id"]) if changes.get("credential_id") else None,
            clear_credential=changes.get("credential_id") is None and bool(changes.get("clear_credential")),
            actor_id=ctx.actor.id,
            now=ctx.now,
            request_id=request_id,
        )
        return ApplyOutcome([ApplyResult(kind=PreviewMemberKind.PROFILE, id=id_, revision=result)])


async def _require_profile_credentials(
    tx: InventoryTx,
    collector_type: str,
    current: CollectionProfileVersion | None,
    settings_map: Mapping[str, Any],
    credential_id: uuid.UUID | None,
) -> None:
    """Raise CredentialsRequiredError when `settings_map` moves the endpoint or weakens the
    TLS check of `current`, and the edit keeps the credential that `current` pins."""
    if current is None or current.credential_id is None or credential_id != current.credential_id:
        return
    cv = (
        await tx.get_credential_version(current.credential_id, current.credential_revision)
        if current.credential_revision is not None
        else None
    )
    paths = sorted(cv.secret_paths) if cv is not None else []
    try:
        source_egress.require_secrets(collector_type, current.settings, settings_map, paths, ())
    except source_egress.CredentialsRequired as exc:
        raise CredentialsRequiredError(exc) from exc


async def apply_profile_edit(
    tx: InventoryTx,
    profile_id: uuid.UUID,
    *,
    expected_revision: int,
    display_name: str | None,
    settings: Mapping[str, Any] | None,
    credential_id: uuid.UUID | None,
    clear_credential: bool,
    actor_id: int | None,
    now: datetime,
    request_id: str | None = None,
) -> int:
    """Rename the profile and, if the settings or the credential change, add an
    immutable revision that pins the current version of the credential. The
    direct PATCH and the `edit_profile` operation call this function. Return
    the current revision after the edit."""
    profile = await tx.get_profile(profile_id)
    if profile is None or profile.archived_at is not None:
        raise NotFound("profile not found")
    if expected_revision != profile.current_revision:
        raise StaleRevision(
            f"profile is at revision {profile.current_revision}, not {expected_revision}",
            current_revision=profile.current_revision,
        )
    current = await tx.get_profile_version(profile.id, profile.current_revision)
    revision = profile.current_revision
    if display_name is not None and display_name != profile.display_name:
        await tx.rename_profile(profile.id, display_name, expected_revision=revision, now=now)
    new_settings = (
        collection.validate_profile_settings(profile.collector_type, settings)
        if settings is not None
        else (dict(current.settings) if current else {})
    )
    if clear_credential:
        cred_id: uuid.UUID | None = None
    elif credential_id is not None:
        cred_id = credential_id
    else:
        cred_id = current.credential_id if current else None
    await _require_profile_credentials(tx, profile.collector_type, current, new_settings, cred_id)
    cred_rev: int | None = None
    if cred_id is not None:
        cred = await tx.get_credential(cred_id)
        if cred is None or cred.archived_at is not None:
            raise Validation("credential does not exist or is archived")
        cred_rev = cred.current_revision
    unchanged = (
        current is not None
        and new_settings == current.settings
        and cred_id == current.credential_id
        and cred_rev == current.credential_revision
    )
    if not unchanged:
        secret_paths: list[str] = []
        if cred_id is not None and cred_rev is not None:
            cv = await tx.get_credential_version(cred_id, cred_rev)
            secret_paths = list(cv.secret_paths) if cv else []
        _validate_profile_shape(profile.collector_type, new_settings, secret_paths)
        version = await tx.add_profile_version(
            profile.id,
            expected_revision=revision,
            settings=new_settings,
            credential_id=cred_id,
            credential_revision=cred_rev,
            actor_id=actor_id,
            now=now,
        )
        revision = version.revision
    await tx.append_event(
        entity_type="profile",
        entity_id=str(profile.id),
        actor_id=actor_id,
        action="updated",
        now=now,
        before={"revision": profile.current_revision, "display_name": profile.display_name},
        after={
            "revision": revision,
            "display_name": display_name or profile.display_name,
            "settings": new_settings if not unchanged else None,
        },
        request_id=request_id,
    )
    return revision


def _validate_profile_shape(
    collector_type: str, settings: Mapping[str, Any], secret_paths: Sequence[str]
) -> None:
    """Validate the settings of a profile revision against the ConfigModel with
    placeholder secrets. Raise `Validation` for an error under a field of the
    profile or credential category. An error under another field is ignored."""
    if collector_type not in coll.REGISTRY:
        raise Validation(f"unknown collector type {collector_type!r}")
    model = coll.REGISTRY[collector_type].ConfigModel
    payload = glue.inject_secrets(
        collection.unflatten(collection.flatten(settings)), dict.fromkeys(secret_paths, "placeholder")
    )
    owned = collection.paths_in_category(collector_type, FieldCategory.PROFILE.value) | (
        collection.paths_in_category(collector_type, FieldCategory.CREDENTIAL.value)
    )
    heads = {path.partition(".")[0] for path in owned}
    try:
        model(**payload)
    except ValidationError as exc:
        for e in exc.errors():
            loc = [str(part) for part in e["loc"]]
            if loc and loc[0] in heads:
                if e["type"] == "missing":
                    # Pydantic includes the selected union tag before the leaf.
                    candidates = {".".join(loc), ".".join(loc[:-2] + loc[-1:])}
                    for field in _fm.COLLECTORS[collector_type].fields:
                        if field.secret and field.path in candidates:
                            raise Validation(
                                f"the selected credential has no {field.label} ({field.path}); "
                                "the profile needs one credential with every required secret, "
                                "jump-host secrets included"
                            ) from exc
                raise Validation(f"invalid profile setting: {'.'.join(loc)}: {e['msg']}") from exc


class RotateCredential:
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan:
        if not isinstance(change, CredentialPatch):
            raise Validation("rotate_credential needs a credential patch")
        if selection.ids is None or len(selection.ids) != 1:
            raise Validation("rotate_credential selects exactly one credential id")
        credential_id = _uuid_of(selection.ids[0], "credential")
        cred = await ctx.tx.get_credential(credential_id)
        if cred is None or cred.archived_at is not None:
            raise NotFound("credential not found")
        if change.expected_revision != cred.current_revision:
            raise StaleRevision(
                f"credential is at revision {cred.current_revision}, not {change.expected_revision}",
                current_revision=cred.current_revision,
            )
        secrets = change.secret_values()
        profile_ids = await credentials.affected_profiles(ctx.tx, credential_id)
        profiles = [p for p in [await ctx.tx.get_profile(pid) for pid in profile_ids] if p is not None]
        draft: bytes | None = None
        secret_names: dict[str, str] = {}
        if secrets is not None:
            try:
                validated = credentials.validate_secret_map(credentials.collector_types_of(profiles), secrets)
            except credentials.SecretsRejected as exc:
                raise Validation(str(exc)) from exc
            draft = credentials.seal_draft(ctx.key, ctx.actor.id, validated, hint=str(credential_id))
            secret_names = credentials.redact_secret_names(validated)
        members = [
            _member(PreviewMemberKind.CREDENTIAL, str(cred.id), cred.current_revision, cred.display_name)
        ]
        impacts: list[tuple[str, str, dict]] = []
        all_targets: dict[uuid.UUID, InventoryTarget] = {}
        connections = 0
        for profile in profiles:
            members.append(
                _member(
                    PreviewMemberKind.PROFILE, str(profile.id), profile.current_revision, profile.display_name
                )
            )
            impacts.append(
                (
                    PreviewMemberKind.PROFILE.value,
                    str(profile.id),
                    {"display_name": profile.display_name, "revision": profile.current_revision},
                )
            )
            targets, conns = await _profile_targets(ctx.tx, profile.id)
            connections += len(conns)
            for inventory in conns:
                impacts.append(
                    (
                        PreviewMemberKind.CONNECTION.value,
                        str(inventory.source_id),
                        {"name": inventory.name, "profile_id": str(profile.id)},
                    )
                )
            for t in targets:
                all_targets[t.id] = t
        rows, device_ids = await _impact_rows_for_targets(ctx, list(all_targets.values()))
        impacts.extend(rows)
        return PreviewPlan(
            members=members,
            impacts=impacts,
            changes={"display_name": change.display_name, "secrets": secret_names or None},
            affected_devices=len(device_ids),
            affected_targets=len(all_targets),
            secret_draft=draft,
            summary={
                "profiles": len(profiles),
                "targets": len(all_targets),
                "connections": connections,
                "devices": len(device_ids),
            },
        )

    async def apply(self, ctx: OperationContext, preview: OperationPreview, request_id: str) -> ApplyOutcome:
        [(id_, revision)] = _member_ids(preview, PreviewMemberKind.CREDENTIAL)
        credential_id = uuid.UUID(id_)
        expected = {uuid.UUID(pid): rev for pid, rev in _member_ids(preview, PreviewMemberKind.PROFILE)}
        results: list[ApplyResult] = []
        display_name = preview.changes.get("display_name")
        cred = await ctx.tx.get_credential(credential_id)
        if cred is None:
            raise NotFound("credential not found")
        if display_name and display_name != cred.display_name:
            cred = await ctx.tx.rename_credential(
                credential_id, display_name, expected_revision=revision, now=ctx.now
            )
            await ctx.tx.append_event(
                entity_type="credential",
                entity_id=id_,
                actor_id=ctx.actor.id,
                action="renamed",
                now=ctx.now,
                after={"display_name": display_name},
                request_id=request_id,
            )
        current_revision = cred.current_revision
        if preview.secret_draft is not None:
            secrets = credentials.open_draft(ctx.key, ctx.actor.id, preview.secret_draft, hint=id_)
            version, repinned = await credentials.rotate(
                ctx.tx,
                ctx.key,
                credential_id,
                secrets,
                expected_revision=revision,
                actor_id=ctx.actor.id,
                now=ctx.now,
                request_id=request_id,
                profile_revisions=expected,
            )
            current_revision = version.revision
            for pv in repinned:
                results.append(
                    ApplyResult(kind=PreviewMemberKind.PROFILE, id=str(pv.profile_id), revision=pv.revision)
                )
        results.insert(0, ApplyResult(kind=PreviewMemberKind.CREDENTIAL, id=id_, revision=current_revision))
        return ApplyOutcome(results)


class DeleteConnection:
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan:
        if selection.ids is None or len(selection.ids) != 1:
            raise Validation("delete_connection selects exactly one connection id")
        row, inventory = await _source_by_id(ctx.store, ctx.tx, selection.ids[0])
        await _refuse_in_flight(ctx, row.name)
        targets = [t for t in await ctx.tx.list_targets(row.id) if t.archived_at is None]
        impacts, device_ids = await _impact_rows_for_targets(ctx, targets)
        revision = inventory.inventory_revision if inventory else 1
        return PreviewPlan(
            members=[_member(PreviewMemberKind.CONNECTION, str(row.id), revision, row.name)],
            impacts=impacts,
            changes={"delete": row.name},
            affected_devices=len(device_ids),
            affected_targets=len(targets),
            warnings=[
                "devices, placements and history are kept; observations through this connection are retired"
            ],
            summary={"targets": len(targets), "devices": len(device_ids)},
        )

    async def apply(self, ctx: OperationContext, preview: OperationPreview, request_id: str) -> ApplyOutcome:
        [(id_, revision)] = _member_ids(preview, PreviewMemberKind.CONNECTION)
        row, inventory = await _source_by_id(ctx.store, ctx.tx, id_)
        if inventory is not None and inventory.inventory_revision != revision:
            raise StaleRevision(
                f"connection is at revision {inventory.inventory_revision}, not {revision}",
                current_revision=inventory.inventory_revision,
            )
        await _refuse_in_flight(ctx, row.name)
        records = ExecutionRecords(ctx.store, ctx.tx)
        archived = await ctx.tx.archive_source_targets(row.id, ctx.now)
        for target in archived:
            await ctx.tx.retire_observations(target.id, ctx.now)
        await ctx.tx.clear_target_source(row.id, ctx.now)
        await records.delete_source(row.name)
        await ctx.tx.append_event(
            entity_type="connection",
            entity_id=id_,
            actor_id=ctx.actor.id,
            action="deleted",
            now=ctx.now,
            before={"name": row.name, "collector_type": row.type, "targets": len(archived)},
            request_id=request_id,
            sensitive=True,
        )
        return ApplyOutcome([ApplyResult(kind=PreviewMemberKind.CONNECTION, id=id_, revision=revision)])


class DeleteTarget:
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan:
        if selection.ids is None:
            raise Validation("delete_target selects explicit target ids")
        targets = []
        for raw in selection.ids:
            target = await ctx.tx.get_target(_uuid_of(raw, "target"))
            if target is None or target.archived_at is not None:
                raise NotFound(f"target {raw} not found")
            await _refuse_in_flight(ctx, target.source_key, target.host)
            targets.append(target)
        impacts, device_ids = await _impact_rows_for_targets(ctx, targets)
        return PreviewPlan(
            members=[
                _member(PreviewMemberKind.TARGET, str(t.id), t.revision, f"{t.source_key}/{t.host}")
                for t in targets
            ],
            impacts=impacts,
            changes={"delete": [str(t.id) for t in targets]},
            affected_devices=len(device_ids),
            affected_targets=len(targets),
            warnings=[
                "devices keep their inventory record and history; this target's observations are retired"
            ],
            summary={"targets": len(targets), "devices": len(device_ids)},
        )

    async def apply(self, ctx: OperationContext, preview: OperationPreview, request_id: str) -> ApplyOutcome:
        records = ExecutionRecords(ctx.store, ctx.tx)
        results: list[ApplyResult] = []
        for id_, revision in _member_ids(preview, PreviewMemberKind.TARGET):
            target = await ctx.tx.get_target(uuid.UUID(id_))
            if target is None:
                raise NotFound(f"target {id_} not found")
            await _refuse_in_flight(ctx, target.source_key, target.host)
            await ctx.tx.retire_observations(target.id, ctx.now)
            archived = await ctx.tx.archive_target(target.id, expected_revision=revision, now=ctx.now)
            if target.kind == TargetKind.DIRECT.value:
                await records.remove_device(target.source_key, target.host)
            await ctx.tx.append_event(
                entity_type="target",
                entity_id=id_,
                actor_id=ctx.actor.id,
                action="deleted",
                now=ctx.now,
                before={"source_key": target.source_key, "host": target.host},
                request_id=request_id,
            )
            results.append(ApplyResult(kind=PreviewMemberKind.TARGET, id=id_, revision=archived.revision))
        return ApplyOutcome(results)


class ReplaceTarget:
    async def preview(self, ctx: OperationContext, selection: Selection, change: Any) -> PreviewPlan:
        if not isinstance(change, ReplacementChange):
            raise Validation("replace_target needs a replacement change")
        if selection.ids is None or len(selection.ids) != 1:
            raise Validation("replace_target selects exactly one target id")
        target = await ctx.tx.get_target(_uuid_of(selection.ids[0], "target"))
        if target is None or target.archived_at is not None:
            raise NotFound("target not found")
        row = await ctx.store.get_source(target.source_key)
        if row is None:
            raise NotFound("connection not found")
        await _refuse_in_flight(ctx, row.name, target.host)
        endpoint = _validate_endpoint(row, target, change.endpoint_config)
        new_host = str(
            endpoint.get(
                "host",
                target.host if target.kind == TargetKind.DIRECT.value else row.config.get("host") or "",
            )
        )
        if (
            target.kind == TargetKind.DIRECT.value
            and new_host != target.host
            and (
                await ctx.tx.get_active_target(row.name, new_host) is not None
                or any(d.host == new_host for d in await ctx.store.list_devices(row.name))
            )
        ):
            raise Conflict(f"{row.name} already has a target {new_host!r}")
        draft: bytes | None = None
        secret_names: dict[str, str] = {}
        if target.kind != TargetKind.DIRECT.value:
            inventory = await ctx.tx.get_source_inventory(row.id)
            default = inventory.default_profile_id if inventory is not None else None
            secrets = _require_credentials(
                row.type,
                row.config,
                _replaced_config(row, endpoint),
                await _binding(ctx.tx, target.profile_id or default),
                change.secret_values(),
            )
            if secrets is not None:
                draft = credentials.seal_draft(ctx.key, ctx.actor.id, secrets, hint=str(target.id))
                secret_names = credentials.redact_secret_names(secrets)
        impacts, device_ids = await _impact_rows_for_targets(ctx, [target])
        return PreviewPlan(
            members=[
                _member(
                    PreviewMemberKind.TARGET,
                    str(target.id),
                    target.revision,
                    f"{target.source_key}/{target.host}" if target.host else target.source_key,
                )
            ],
            impacts=impacts,
            changes={
                "endpoint_config": redact_by_key(endpoint),
                "new_host": new_host,
                **({"secrets": secret_names} if secret_names else {}),
            },
            affected_devices=len(device_ids),
            affected_targets=1,
            warnings=_replacement_warnings(row, endpoint),
            secret_draft=draft,
            summary={"devices": len(device_ids)},
        )

    async def apply(self, ctx: OperationContext, preview: OperationPreview, request_id: str) -> ApplyOutcome:
        [(id_, revision)] = _member_ids(preview, PreviewMemberKind.TARGET)
        target = await ctx.tx.get_target(uuid.UUID(id_))
        if target is None or target.archived_at is not None:
            raise NotFound("target not found")
        records = ExecutionRecords(ctx.store, ctx.tx)
        row = await _locked_source(records, target.source_key)
        await _refuse_in_flight(ctx, row.name, target.host)
        endpoint = dict(preview.changes.get("endpoint_config") or {})
        await ctx.tx.retire_observations(target.id, ctx.now)
        await ctx.tx.archive_target(target.id, expected_revision=revision, now=ctx.now)
        if target.kind == TargetKind.DIRECT.value:
            new_host = str(endpoint.get("host", target.host))
            port = endpoint.get("port")
            old_device = next(
                (d for d in await ctx.store.list_devices(row.name) if d.host == target.host), None
            )
            if old_device is not None:
                await records.remove_device(row.name, target.host)
                if port is None:
                    port = old_device.port  # The new device keeps the port if the endpoint has none.
            device = await records.add_device(row.name, new_host, port, target.enabled)
            legacy_id: int | None = device.id
            new_config: dict | None = None
            identity = {k: v for k, v in endpoint.items() if k not in ("host", "port")}
            identity = _target_identity(row, glue._overlay(target.endpoint_config, identity))
        else:
            new_config = _replaced_config(row, endpoint)
            new_host = str(new_config.get("host") or "")
            legacy_id = None
        if new_config is not None:
            new_config.pop("source_name", None)
            await records.update_source(row.name, config=new_config)
        created = await ctx.tx.create_target(
            source_id=row.id,
            source_key=row.name,
            host=new_host,
            kind=target.kind,
            now=ctx.now,
            legacy_device_id=legacy_id,
            profile_id=target.profile_id,
            onboarding_site_id=target.onboarding_site_id,
            enabled=target.enabled,
            **({"endpoint_config": identity} if target.kind == TargetKind.DIRECT.value and identity else {}),
        )
        if preview.secret_draft is not None:
            secrets = credentials.open_draft(ctx.key, ctx.actor.id, preview.secret_draft, hint=id_)
            inventory = await ctx.tx.get_source_inventory(row.id)
            default = inventory.default_profile_id if inventory is not None else None
            binding = await _binding(ctx.tx, target.profile_id or default)
            if binding is None:
                raise Validation("the secrets replace a stored credential, and the change keeps none")
            await _rebind(
                ctx.tx,
                ctx.key,
                binding,
                secrets,
                label=row.name,
                assign=_assigner(ctx.tx, row, created, ctx.now),
                actor_id=ctx.actor.id,
                now=ctx.now,
                request_id=request_id,
            )
        await ctx.tx.append_event(
            entity_type="target",
            entity_id=id_,
            actor_id=ctx.actor.id,
            action="replaced",
            now=ctx.now,
            before={"host": target.host},
            after={
                "host": new_host,
                "replacement_id": str(created.id),
                "endpoint_config": redact_by_key(endpoint),
            },
            request_id=request_id,
            sensitive=True,
        )
        return ApplyOutcome(
            [
                ApplyResult(kind=PreviewMemberKind.TARGET, id=id_, revision=revision),
                ApplyResult(kind=PreviewMemberKind.TARGET, id=str(created.id), revision=created.revision),
            ],
            extra={"old_target_id": id_, "new_target_id": str(created.id)},
        )


async def _check_location_sites(store: Any, collector_type: str, config: Mapping[str, Any]) -> None:
    """A ZIA location_sites line holds the code of an inventory site. An Equinix
    ibx_sites line holds the code of an inventory site or a new code. A new code
    that folds onto the code of an inventory site, such as `FR5` for `fr5`, is
    refused."""
    field = {"zia": "location_sites", "equinix": "ibx_sites"}.get(collector_type)
    text = config.get(field) if field else None
    if not isinstance(text, str) or not text.strip():
        return
    from hst.collectors.util import parse_pairs
    from hst.core import uid as uidmod

    known = {site.code for site in await store.list_sites()}
    pairs = parse_pairs(text, field=str(field))
    if collector_type == "zia":
        unknown = [(key, code) for key, code in pairs.items() if code not in known]
        if unknown:
            lines = "; ".join(f"'{key}, {code}'" for key, code in unknown)
            raise Validation(f"location_sites: no site has the code of the line {lines}")
        return
    folded = [
        (key, code, clash)
        for key, code in pairs.items()
        if code not in known and (clash := uidmod.site_fold(code, known)) is not None
    ]
    if folded:
        lines = "; ".join(f"'{key}, {code}' (the site {clash!r})" for key, code, clash in folded)
        raise Validation(f"ibx_sites: the code of the line is the same site as another code: {lines}")


def _replaced_config(row: Source, endpoint: dict[str, Any]) -> dict:
    """The source config after the replacement of the endpoint of the connection. The
    endpoint fields overlay the source config, and the host key pin of the source is cleared."""
    config = glue._overlay(row.config, endpoint)
    if _has_host_key(row.type):
        config["host_key"] = ""
    return config


def _has_host_key(collector_type: str) -> bool:
    """Whether the collector type has a `host_key` field."""
    coll = _fm.COLLECTORS.get(collector_type)
    return coll is not None and any(f.path == "host_key" for f in coll.fields)


def _replacement_warnings(row: Source, endpoint: Mapping[str, Any]) -> list[str]:
    """The warnings of a replacement about the host key pin and the uid prefix."""
    warnings = []
    if _has_host_key(row.type):
        warnings.append(
            "the host key pin of the old endpoint is not transferred; the new endpoint pins on first contact"
        )
    new_tenant = endpoint.get("tenant")
    old_tenant = row.config.get("tenant")
    if row.type in ("zia", "zpa") and new_tenant and str(new_tenant) != str(old_tenant or ""):
        old, new = f"{row.type}:{uid.slug(str(old_tenant or ''))}", f"{row.type}:{uid.slug(str(new_tenant))}"
        warnings.append(f"the uid prefix of every node of this source changes from {old} to {new}")
    return warnings


def _target_identity(row: Source, values: Mapping[str, Any]) -> dict[str, Any]:
    flat = collection.flatten(values)
    bad = [
        path
        for path in flat
        if collection.category_of(row.type, path) != FieldCategory.TARGET.value
        or path in {"host", "port", "host_key"}
        or path in _fm.secret_paths(row.type)
    ]
    if bad:
        raise Validation("endpoint_config accepts only target identity overrides: " + ", ".join(sorted(bad)))
    return collection.unflatten(flat)


def _validate_endpoint(row: Source, target: InventoryTarget, endpoint: Mapping[str, Any]) -> dict[str, Any]:
    """Return the endpoint config of a replacement. A direct target accepts
    paths of the target category. The endpoint of a connection accepts paths
    of the connection and target categories. An empty config and `host_key`
    are refused."""
    flat = collection.flatten(endpoint)
    if not flat:
        raise Validation("endpoint_config is empty")
    if target.kind == TargetKind.DIRECT.value:
        allowed = {FieldCategory.TARGET.value}
    else:
        allowed = {FieldCategory.TARGET.value, FieldCategory.CONNECTION.value}
    bad = {
        p: (collection.category_of(row.type, p) or "unknown")
        for p in flat
        if collection.category_of(row.type, p) not in allowed
    }
    if "host_key" in flat:
        bad["host_key"] = "learned on first contact, never supplied"
    if bad:
        raise Validation(
            "endpoint_config may only carry address and identity fields; rejected: "
            + ", ".join(f"{p} ({c})" for p, c in sorted(bad.items()))
        )
    return collection.unflatten(flat)


def _uuid_of(raw: str, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise Validation(f"{raw!r} is not a {what} id") from exc


register_operation(PreviewOperation.ASSIGN_TARGET_PROFILE, AssignTargetProfile())
register_operation(PreviewOperation.EDIT_PROFILE, EditProfile())
register_operation(PreviewOperation.ROTATE_CREDENTIAL, RotateCredential())
register_operation(PreviewOperation.DELETE_CONNECTION, DeleteConnection())
register_operation(PreviewOperation.DELETE_TARGET, DeleteTarget())
register_operation(PreviewOperation.REPLACE_TARGET, ReplaceTarget())


def _require(user: User, permission: str) -> None:
    if permission not in permissions_for(user.role):
        raise HTTPException(403, detail=f"requires permission: {permission}")


async def _context(request: Request, user: User, tx: InventoryTx) -> OperationContext:
    return OperationContext(
        store=_store(request),
        settings=_settings(request),
        key=_key(request),
        actor=user,
        now=_now(),
        tx=tx,
        state=await tx.get_state(),
    )


@router.post("/operations/preview", response_model=PreviewResponse)
async def preview_operation(
    request: Request, body: PreviewRequest, user: User = Depends(require_graph_read)
) -> PreviewResponse:
    from hst.app.inventory import inventory_routes, routing_routes

    _require(user, OPERATION_PERMISSIONS[body.operation])
    if body.operation in inventory_routes.OPERATIONS:
        return await inventory_routes.preview_operation(request, body, user)
    if body.operation == PreviewOperation.EDIT_ROUTING_MEMBERS:
        return await routing_routes.service(request).preview_members(body, routing_routes.actor_of(user))
    handler = OPERATIONS.get(body.operation)
    if handler is None:
        raise Validation(f"operation {body.operation.value} is not available")
    store = _store(request)
    async with store.inventory().transaction() as tx:
        ctx = await _context(request, user, tx)
        plan = await handler.preview(ctx, body.selection, body.typed_change())
        preview = await tx.create_preview(
            actor_id=user.id,
            operation=body.operation.value,
            permissions=[OPERATION_PERMISSIONS[body.operation]],
            intent_generation=ctx.state.intent_generation,
            snapshot_key=ctx.state.read_model_snapshot_key,
            members=[m.model_dump(mode="json") for m in plan.members],
            changes=redact_by_key(plan.changes),
            impact={
                **plan.summary,
                "affected_devices": plan.affected_devices,
                "affected_targets": plan.affected_targets,
            },
            secret_draft=plan.secret_draft,
            now=ctx.now,
            ttl=timedelta(seconds=PREVIEW_TTL_S),
        )
        if plan.impacts:
            await tx.add_preview_impacts(preview.token, plan.impacts)
        generation = await _generation(tx)
    return PreviewResponse(
        token=preview.token,
        operation=body.operation,
        expires_at=preview.expires_at,
        generation=generation,
        members=plan.members,
        member_count=len(plan.members),
        affected_device_count=plan.affected_devices,
        affected_target_count=plan.affected_targets,
        changes=redact_by_key(plan.changes),
        warnings=plan.warnings,
    )


async def apply_preview(
    request: Request, user: User, token: uuid.UUID, idempotency_key: str
) -> tuple[ApplyResponse, ApplyOutcome | None]:
    """Apply a preview for POST /operations/apply and
    POST /targets/{id}/replace. Return the response and the outcome. The
    outcome is None for a stored result of an earlier apply and for an
    operation of `inventory_routes` or `routing_routes`."""
    store = _store(request)
    from hst.app.inventory import inventory_routes, routing_routes

    body = ApplyRequest(token=token, idempotency_key=idempotency_key)
    digest = inventory_routes.request_digest(body)
    async with store.inventory().transaction() as tx:
        stored = await tx.check_idempotency(user.id, idempotency_key, digest)
        if stored is not None:
            response = ApplyResponse.model_validate({**stored.response, "status": ApplyStatus.REUSED.value})
            _require(user, OPERATION_PERMISSIONS[response.operation])
            return response, None
        preview = await tx.get_preview(token, user.id, _now())
        operation = PreviewOperation(preview.operation)
        _require(user, OPERATION_PERMISSIONS[operation])
    if operation in inventory_routes.OPERATIONS:
        return await inventory_routes.apply_operation(request, body, user), None
    if operation == PreviewOperation.EDIT_ROUTING_MEMBERS:
        return await routing_routes.service(request).apply_members(body, routing_routes.actor_of(user)), None
    async with store.inventory().transaction() as tx:
        stored = await tx.check_idempotency(user.id, idempotency_key, digest)
        if stored is not None:
            return ApplyResponse.model_validate({**stored.response, "status": ApplyStatus.REUSED.value}), None
        preview = await tx.get_preview(token, user.id, _now())
        operation = PreviewOperation(preview.operation)
        _require(user, OPERATION_PERMISSIONS[operation])
        for permission in preview.permissions:
            _require(user, permission)
        handler = OPERATIONS.get(operation)
        if handler is None:
            raise Validation(f"operation {operation.value} is not available")
        ctx = await _context(request, user, tx)
        # `consume_preview` returns the sealed draft and clears it from the stored preview.
        consumed = await tx.consume_preview(token, user.id, ctx.now, result_id=None)
        outcome = await handler.apply(ctx, consumed, idempotency_key)
        await tx.bump_generation(ctx.now)
        generation = await _generation(tx)
        response = ApplyResponse(
            token=token,
            operation=operation,
            status=ApplyStatus.APPLIED,
            generation=generation,
            results=outcome.results,
            job_ids=outcome.job_ids,
        )
        await tx.record_operation_result(
            actor_id=user.id,
            idempotency_key=idempotency_key,
            request_digest=digest,
            status=200,
            response=response.model_dump(mode="json"),
            now=ctx.now,
        )
        return response, outcome


@router.post("/operations/apply", response_model=ApplyResponse)
async def apply_operation(
    request: Request, body: ApplyRequest, user: User = Depends(require_graph_read)
) -> ApplyResponse:
    response, _ = await apply_preview(request, user, body.token, body.idempotency_key)
    return response


@router.get("/operations/previews/{token}/impact", response_model=ImpactPage)
async def preview_impact(
    request: Request,
    token: uuid.UUID,
    page: Annotated[PageQuery, Query()],
    user: User = Depends(require_graph_read),
) -> ImpactPage:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        preview = await tx.get_preview(token, user.id, _now())
        for permission in preview.permissions:
            _require(user, permission)
        after = 0
        if page.cursor:
            try:
                after = int(page.cursor)
            except ValueError as exc:
                raise Validation("malformed cursor") from exc
        rows, total = await tx.page_preview_impacts(token, after_seq=after, limit=page.limit)
        generation = await _generation(tx)
    items = [ImpactItem(kind=PreviewMemberKind(r.kind), entity_id=r.entity_id, detail=r.detail) for r in rows]
    next_cursor = str(rows[-1].seq) if rows and rows[-1].seq < total else None
    return ImpactPage(items=items, next_cursor=next_cursor, total=total, generation=generation)


@router.post("/targets/{target_id}/replace", response_model=TargetReplaceResponse)
async def replace_target(
    request: Request,
    target_id: uuid.UUID,
    body: TargetReplaceRequest,
    user: User = Depends(require_sources_write),
) -> TargetReplaceResponse:
    store = _store(request)
    async with store.inventory().transaction() as tx:
        preview = await tx.get_preview(body.token, user.id, _now())
        if preview.operation != PreviewOperation.REPLACE_TARGET.value:
            raise Validation("the preview is not a replace_target preview")
        members = _member_ids(preview, PreviewMemberKind.TARGET)
        if not members or members[0][0] != str(target_id):
            raise Validation("the preview names another target")
    response, _ = await apply_preview(request, user, body.token, body.idempotency_key)
    ids = [r.id for r in response.results if r.kind == PreviewMemberKind.TARGET]
    if len(ids) < 2:
        raise Validation("the replacement produced no new target")
    async with store.inventory().transaction() as tx:
        old = await _target_or_404(tx, uuid.UUID(ids[0]))
        new = await _target_or_404(tx, uuid.UUID(ids[1]))
        return TargetReplaceResponse(
            old_target=target_view(old, await _target_context(tx, store, old)),
            new_target=target_view(new, await _target_context(tx, store, new)),
        )
