"""Devices and batch operations under /api/inventory."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from hst.app.auth import current_user, require_permission
from hst.app.inventory import events as eventsmod
from hst.app.inventory import placement as placementmod
from hst.app.inventory.contracts import (
    API_PREFIX,
    INVENTORY_WRITE,
    MAX_SELECTION,
    OPERATION_PERMISSIONS,
    ActivationState,
    ApplyRequest,
    ApplyResponse,
    ApplyResult,
    ApplyStatus,
    Authority,
    CollectionState,
    CollectRequest,
    CollectResponse,
    ContributingObservation,
    DeviceDetail,
    DeviceListQuery,
    DevicePage,
    DeviceSummary,
    ErrorCode,
    ErrorResponse,
    EventPage,
    Generation,
    ImpactItem,
    ImpactPage,
    InventoryStateView,
    JobRef,
    Lifecycle,
    LifecycleAction,
    LifecyclePatch,
    ObservationState,
    ObservationView,
    ObservingConnection,
    PageQuery,
    PlacementChange,
    PlacementMode,
    PlacementOrigin,
    PlacementPatch,
    PlacementResponse,
    PlacementState,
    PreviewMember,
    PreviewMemberKind,
    PreviewOperation,
    PreviewRequest,
    PreviewResponse,
    ProfileOrigin,
    RelatedEntity,
    Selection,
    SkippedTarget,
    SortField,
    TargetCollectionSummary,
    TargetKind,
)
from hst.app.inventory.observations import (
    DeviceClaims,
    InventoryContext,
    ObservationService,
    ReadModel,
    context_for,
)
from hst.app.inventory.repository import (
    InventoryChanged,
    InventoryError,
    InventoryTx,
    NotFound,
)
from hst.app.inventory.site_routes import parse_int_id, release_site
from hst.app.inventory.site_routes import router as sites_router
from hst.app.inventory.views import resolve_view
from hst.app.inventory.views import router as views_router
from hst.app.permissions import permissions_for
from hst.app.store import (
    DeviceFilters,
    DeviceListItem,
    InventoryDevice,
    InventoryState,
    ObservingTarget,
    OperationPreview,
    User,
)

log = logging.getLogger("hst.inventory")
router = APIRouter()

PREVIEW_TTL = timedelta(minutes=10)
FETCH_KIND = "collect.fetch"


class Forbidden(InventoryError):
    code = ErrorCode.FORBIDDEN
    status = 403


class ObservedStoreUnavailable(InventoryError):
    """The graph read failed. `detail` holds the cached facts and the age of their snapshot."""

    code = ErrorCode.OBSERVED_STORE_UNAVAILABLE
    status = 503

    def __init__(self, message: str, *, detail: dict[str, Any]):
        super().__init__(message)
        self.detail = detail


def error_response(exc: InventoryError) -> JSONResponse:
    body = ErrorResponse(
        error=str(exc),
        code=exc.code,
        current_revision=exc.current_revision,
        references=exc.references,
        detail=getattr(exc, "detail", None),
    )
    return JSONResponse(body.model_dump(mode="json"), status_code=exc.status)


def generation_of(state: InventoryState) -> Generation:
    return Generation(
        snapshot_key=state.read_model_snapshot_key,
        intent_generation=state.intent_generation,
        inventory_sync_pending=state.inventory_sync_pending,
    )


def snapshot_age_s(snapshot_key: str | None, now: datetime) -> float | None:
    """Return the age of the snapshot in seconds.

    A snapshot key is the `collection_ts` of the run in milliseconds. The result is None for a
    key that is not a number."""
    if not snapshot_key or not snapshot_key.isdigit():
        return None
    return max(0.0, now.timestamp() - int(snapshot_key) / 1000.0)


def permissions_of(user: User) -> frozenset[str]:
    return permissions_for(user.role)


def require(user: User, permission: str) -> None:
    if permission not in permissions_of(user):
        raise Forbidden(f"requires permission: {permission}")


# --- query parsing ------------------------------------------------------------------------

_LIST_FIELDS = frozenset(
    {"site_id", "connection_id", "platform", "collection_state", "placement_state", "lifecycle"}
)


def _validation_message(what: str, exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return f"invalid {what}"
    loc = ".".join(str(p) for p in errors[0].get("loc", ()))
    return f"invalid {what}: {loc}: {errors[0].get('msg', 'invalid')}"


def parse_list_query(request: Request) -> DeviceListQuery:
    """Parse the query of the device list.

    Repeated values of one field are alternatives. An unknown field or a malformed value gives
    a 422 with the validation code."""
    raw: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in _LIST_FIELDS:
            raw.setdefault(key, []).append(value)
        else:
            raw[key] = value
    try:
        return DeviceListQuery.model_validate(raw)
    except ValidationError as exc:
        raise InventoryError(_validation_message("filter", exc)) from exc


def parse_page_query(request: Request) -> PageQuery:
    try:
        return PageQuery.model_validate(dict(request.query_params))
    except ValidationError as exc:
        raise InventoryError(_validation_message("page query", exc)) from exc


def filters_of(query: DeviceListQuery) -> DeviceFilters:
    return DeviceFilters(
        q=query.q or None,
        site_ids=[parse_int_id(s, "site") for s in query.site_id],
        source_ids=[parse_int_id(c, "connection") for c in query.connection_id],
        platforms=list(query.platform),
        collection_states=[s.value for s in query.collection_state],
        placement_states=[s.value for s in query.placement_state],
        lifecycles=[s.value for s in query.lifecycle],
    )


async def apply_view(
    tx: InventoryTx, query: DeviceListQuery, owner_id: int, explicit: set[str]
) -> DeviceListQuery:
    """Merge the saved view of the query into the query.

    The view gives the filter, the sort and the direction that the request does not state."""
    if query.view_id is None:
        return query
    view = await resolve_view(tx, query.view_id, owner_id)
    merged = query.model_dump()
    for name, value in view.filter.model_dump(exclude={"version"}).items():
        if name not in explicit:
            merged[name] = value
    if "sort" not in explicit:
        merged["sort"] = view.sort
    if "direction" not in explicit:
        merged["direction"] = view.direction
    return DeviceListQuery.model_validate(merged)


# --- summaries --------------------------------------------------------------------------------


def observing_connection(o: ObservingTarget) -> ObservingConnection:
    return ObservingConnection(
        connection_id=str(o.source_id) if o.source_id is not None else "",
        source_key=o.source_key,
        display_name=o.display_name,
        target_id=o.target_id,
        target_host=o.host,
        observation_state=ObservationState(o.state),
        authority=Authority(o.authority),
        last_success_at=o.last_success_at,
    )


def summary_of(
    device: InventoryDevice, site_code: str | None, connections: Sequence[ObservingConnection]
) -> DeviceSummary:
    return DeviceSummary(
        id=device.id,
        graph_uid=device.graph_uid,
        hostname=device.hostname,
        platform=device.platform,
        management_address=device.management_address,
        lifecycle=Lifecycle(device.lifecycle),
        revision=device.revision,
        collection_state=CollectionState(device.collection_state),
        last_success_at=device.last_success_at,
        site_id=str(device.resolved_site_id) if device.resolved_site_id is not None else None,
        site_code=site_code,
        placement_state=PlacementState(device.placement_state),
        connections=list(connections),
        latest_snapshot_key=device.latest_snapshot_key,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
    )


def _site_code(site_codes: dict[int, str], device: InventoryDevice) -> str | None:
    return site_codes.get(device.resolved_site_id) if device.resolved_site_id is not None else None


def summary_of_item(item: DeviceListItem) -> DeviceSummary:
    return summary_of(item.device, item.site_code, [observing_connection(c) for c in item.connections])


def placement_response(resolved: placementmod.Resolved, site_codes: dict[int, str]) -> PlacementResponse:
    def code(site_id: int | None) -> str | None:
        return site_codes.get(site_id) if site_id is not None else None

    return PlacementResponse(
        mode=resolved.mode,
        desired_site_id=str(resolved.desired_site_id) if resolved.desired_site_id is not None else None,
        desired_site_code=code(resolved.desired_site_id),
        basis=resolved.basis,
        contributing=[
            ContributingObservation(
                target_id=c.target_id,
                connection_id=c.connection_id,
                location_id=c.location_handle,
                location_name=c.location_name,
                site_id=str(c.site_id) if c.site_id is not None else None,
                site_code=code(c.site_id),
                bound=c.site_id is not None,
                state=c.state,
                authority=c.authority,
            )
            for c in resolved.contributing
        ],
        conflict=resolved.conflict,
        stale=resolved.stale,
        published_site_id=str(resolved.published_site_id) if resolved.published_site_id is not None else None,
        published_site_code=code(resolved.published_site_id),
        published_snapshot_key=resolved.published_snapshot_key,
        desired_revision=resolved.desired_revision,
        applied_revision=resolved.applied_revision,
        pending=resolved.pending,
        origin=resolved.origin,
        actor_id=str(resolved.actor_id) if resolved.actor_id is not None else None,
        updated_at=resolved.updated_at,
    )


# --- devices ------------------------------------------------------------------------------------


@router.get("/devices", dependencies=[Depends(require_permission("graph.read"))])
async def list_devices(request: Request, user: User = Depends(current_user)) -> DevicePage:
    ctx = context_for(request.app)
    query = parse_list_query(request)
    explicit = {k for k, _ in request.query_params.multi_items()}
    async with ctx.repo.transaction() as tx:
        query = await apply_view(tx, query, user.id, explicit)
        page = await tx.list_devices(
            filters_of(query),
            sort=query.sort,
            direction=query.direction,
            limit=query.limit,
            cursor=query.cursor,
        )
    return DevicePage(
        items=[summary_of_item(i) for i in page.items],
        next_cursor=page.next_cursor,
        generation=generation_of(page.state),
    )


async def _device_or_404(tx: InventoryTx, device_id: uuid.UUID) -> InventoryDevice:
    device = await tx.get_device(device_id)
    if device is None:
        raise NotFound("device not found")
    return device


async def _collection_summaries(
    ctx: InventoryContext, tx: InventoryTx, claims: DeviceClaims
) -> list[TargetCollectionSummary]:
    sources = {s.name: s for s in await tx.list_source_inventory()}
    statuses: dict[tuple[str, str], Any] = {}
    for source_key in sorted({tg.source_key for tg in claims.targets.values()}):
        for st in await ctx.store.list_device_status(source_key):
            statuses[(st.source, st.host)] = st
    out = []
    for obs in claims.observations:
        target = claims.targets.get(obs.target_id)
        if target is None or obs.state == ObservationState.ABSENT.value:
            continue
        source = sources.get(target.source_key)
        profile_id = target.profile_id
        origin = ProfileOrigin.TARGET
        if profile_id is None and source is not None and source.default_profile_id is not None:
            profile_id, origin = source.default_profile_id, ProfileOrigin.CONNECTION
        if profile_id is None:
            origin = ProfileOrigin.NONE
        profile = await tx.get_profile(profile_id) if profile_id is not None else None
        status = statuses.get((target.source_key, target.host))
        out.append(
            TargetCollectionSummary(
                target_id=target.id,
                connection_id=str(target.source_id) if target.source_id is not None else "",
                enabled=target.enabled,
                profile_id=profile_id,
                profile_revision=profile.current_revision if profile else None,
                profile_origin=origin,
                last_attempt_at=status.last_attempt_at if status else None,
                last_success_at=status.last_success_at if status else None,
                consecutive_failures=status.consecutive_failures if status else 0,
                last_error=status.last_error if status else "",
            )
        )
    return out


@router.get("/devices/{device_id}", dependencies=[Depends(require_permission("graph.read"))])
async def get_device(
    request: Request, device_id: uuid.UUID, user: User = Depends(current_user)
) -> DeviceDetail:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        device = await _device_or_404(tx, device_id)
        state = await tx.get_state()
        site_rows = await ctx.site_rows(tx).list()
        site_codes = {s.id: s.code for s in site_rows}
        claims = await ReadModel(ctx).gather(tx, device, site_ids={s.code: s.id for s in site_rows})
        resolved = claims.resolve()
        sources = {s.source_id: s for s in await tx.list_source_inventory()}
        connections = []
        observations = []
        for obs in claims.observations:
            target = claims.targets.get(obs.target_id)
            if target is None:
                continue
            source = sources.get(target.source_id) if target.source_id is not None else None
            loc = claims.locations.get(obs.reported_location_handle) if obs.reported_location_handle else None
            observations.append(
                ObservationView(
                    target_id=target.id,
                    connection_id=str(target.source_id) if target.source_id is not None else "",
                    source_key=target.source_key,
                    host=target.host,
                    kind=TargetKind(target.kind),
                    reported_location_id=loc.handle if loc else None,
                    reported_location_name=loc.name if loc else "",
                    last_success_at=obs.last_success_at,
                    last_seen_snapshot_key=obs.last_seen_snapshot_key,
                    state=ObservationState(obs.state),
                    authority=Authority(obs.authority),
                    notes=obs.notes,
                )
            )
            if obs.state != ObservationState.ABSENT.value:
                connections.append(
                    ObservingConnection(
                        connection_id=str(target.source_id) if target.source_id is not None else "",
                        source_key=target.source_key,
                        display_name=source.display_name if source else "",
                        target_id=target.id,
                        target_host=target.host,
                        observation_state=ObservationState(obs.state),
                        authority=Authority(obs.authority),
                        last_success_at=obs.last_success_at,
                    )
                )
        collection = None
        if "runs.manage" in permissions_of(user):
            collection = await _collection_summaries(ctx, tx, claims)
    summary = summary_of(device, _site_code(site_codes, device), connections)
    placement = placement_response(resolved, site_codes)
    generation = generation_of(state)
    reader = ctx.graph_reader()
    try:
        related_rows = await asyncio.to_thread(
            reader.related, [device.graph_uid], state.read_model_snapshot_key
        )
    except Exception as exc:
        log.warning("graph read for device %s failed: %s", device.id, type(exc).__name__)
        raise ObservedStoreUnavailable(
            "observed store unavailable; showing cached facts",
            detail={
                "snapshot_key": state.read_model_snapshot_key,
                "snapshot_age_s": snapshot_age_s(state.read_model_snapshot_key, now),
                "summary": summary.model_dump(mode="json"),
                "placement": placement.model_dump(mode="json"),
                "observations": [o.model_dump(mode="json") for o in observations],
                "generation": generation.model_dump(mode="json"),
            },
        ) from exc
    related = [
        RelatedEntity(uid=r.uid, label=r.label, relation=r.relation, name=r.name)
        for r in related_rows.get(device.graph_uid, [])
    ]
    return DeviceDetail(
        summary=summary,
        placement=placement,
        observations=observations,
        related=related,
        collection=collection,
        generation=generation,
    )


@router.get("/devices/{device_id}/history", dependencies=[Depends(require_permission("graph.read"))])
async def device_history(
    request: Request, device_id: uuid.UUID, user: User = Depends(current_user)
) -> EventPage:
    ctx = context_for(request.app)
    query = parse_page_query(request)
    async with ctx.repo.transaction() as tx:
        await _device_or_404(tx, device_id)
        return await eventsmod.page_history(
            tx,
            ctx.store,
            entity_type="device",
            entity_id=str(device_id),
            query=query,
            permissions=permissions_of(user),
        )


async def _site_id_of(ctx: InventoryContext, tx: InventoryTx, site_id: str | None) -> int | None:
    if site_id is None:
        return None
    sid = parse_int_id(site_id, "site")
    if all(row.id != sid for row in await ctx.site_rows(tx).list()):
        raise NotFound("site not found")
    return sid


@router.patch("/devices/{device_id}/placement", dependencies=[Depends(require_permission("sites.write"))])
async def patch_placement(
    request: Request, device_id: uuid.UUID, body: PlacementPatch, user: User = Depends(current_user)
) -> PlacementResponse:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        device = await _device_or_404(tx, device_id)
        before = await tx.get_placement(device_id)
        site_id = await _site_id_of(ctx, tx, body.site_id)
        placement = await tx.set_placement(
            device_id,
            mode=body.mode,
            site_id=site_id,
            origin=PlacementOrigin.MANUAL.value,
            expected_revision=body.expected_revision,
            actor_id=user.id,
            now=now,
        )
        await tx.append_event(
            entity_type="device",
            entity_id=str(device_id),
            actor_id=user.id,
            action="placement.set",
            now=now,
            before=eventsmod.placement_payload(before),
            after=eventsmod.placement_payload(placement),
        )
        resolved = (await ReadModel(ctx).refresh(tx, [device.id], now, collection=False))[device.id]
        site_codes = {s.id: s.code for s in await ctx.site_rows(tx).list()}
    return placement_response(resolved, site_codes)


@router.patch("/devices/{device_id}/lifecycle", dependencies=[Depends(require_permission(INVENTORY_WRITE))])
async def patch_lifecycle(
    request: Request, device_id: uuid.UUID, body: LifecyclePatch, user: User = Depends(current_user)
) -> DeviceSummary:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        device = await _device_or_404(tx, device_id)
        updated = await _set_lifecycle(tx, device, body.action, body.expected_revision, user.id, now)
        site_codes = {s.id: s.code for s in await ctx.site_rows(tx).list()}
        connections = await _connections_of(tx, updated.id)
    return summary_of(updated, _site_code(site_codes, updated), connections)


async def _connections_of(tx: InventoryTx, device_id: uuid.UUID) -> list[ObservingConnection]:
    observations = [
        o for o in await tx.get_observations(device_id) if o.state != ObservationState.ABSENT.value
    ]
    targets = {tg.id: tg for tg in await tx.get_targets([o.target_id for o in observations])}
    sources = {s.source_id: s for s in await tx.list_source_inventory()}
    out = []
    for obs in observations:
        target = targets.get(obs.target_id)
        if target is None:
            continue
        source = sources.get(target.source_id) if target.source_id is not None else None
        out.append(
            ObservingConnection(
                connection_id=str(target.source_id) if target.source_id is not None else "",
                source_key=target.source_key,
                display_name=source.display_name if source else "",
                target_id=target.id,
                target_host=target.host,
                observation_state=ObservationState(obs.state),
                authority=Authority(obs.authority),
                last_success_at=obs.last_success_at,
            )
        )
    return out


async def _set_lifecycle(
    tx: InventoryTx,
    device: InventoryDevice,
    action: LifecycleAction,
    expected_revision: int,
    actor_id: int | None,
    now: datetime,
) -> InventoryDevice:
    """Set the lifecycle of the device.

    Archive sets `archived`. Unarchive sets `active` when the device has an observation that is
    not absent, and `missing` otherwise. Collection does not change."""
    if action == LifecycleAction.ARCHIVE:
        target = Lifecycle.ARCHIVED
    else:
        live = [o for o in await tx.get_observations(device.id) if o.state != ObservationState.ABSENT.value]
        target = Lifecycle.ACTIVE if live else Lifecycle.MISSING
    updated = await tx.set_lifecycle(device.id, target, expected_revision=expected_revision, now=now)
    await tx.append_event(
        entity_type="device",
        entity_id=str(device.id),
        actor_id=actor_id,
        action=f"lifecycle.{action.value}",
        now=now,
        before={"lifecycle": device.lifecycle, "revision": device.revision},
        after={"lifecycle": updated.lifecycle, "revision": updated.revision},
    )
    return updated


@router.post("/devices/{device_id}/collect", dependencies=[Depends(require_permission("runs.manage"))])
async def collect_device(
    request: Request, device_id: uuid.UUID, body: CollectRequest, user: User = Depends(current_user)
) -> CollectResponse:
    """Enqueue one fetch for each distinct eligible target of the device.

    The response lists a target as skipped when the target does not observe the device, is
    archived or disabled, has a disabled connection or is already queued."""
    from hst.worker import queue

    ctx = context_for(request.app)
    now = ctx.clock()
    jobs: list[JobRef] = []
    skipped: list[SkippedTarget] = []
    async with ctx.repo.transaction() as tx:
        await _device_or_404(tx, device_id)
        observed = {o.target_id: o for o in await tx.get_observations(device_id)}
        eligible = []
        for target_id in dict.fromkeys(body.target_ids):
            target = await tx.get_target(target_id)
            obs = observed.get(target_id)
            if target is None or obs is None or obs.state == ObservationState.ABSENT.value:
                skipped.append(
                    SkippedTarget(target_id=target_id, reason="target does not observe this device")
                )
                continue
            if target.archived_at is not None:
                skipped.append(SkippedTarget(target_id=target_id, reason="target archived"))
                continue
            if not target.enabled:
                skipped.append(SkippedTarget(target_id=target_id, reason="target disabled"))
                continue
            source = await ctx.store.get_source(target.source_key)
            if source is None or not source.enabled:
                skipped.append(SkippedTarget(target_id=target_id, reason="connection disabled"))
                continue
            eligible.append(target)
        for target in eligible:
            job = await queue.enqueue(
                ctx.store,
                FETCH_KIND,
                source=target.source_key,
                device=target.host or None,
                triggered_by=f"inventory:{user.id}",
                now=now,
            )
            if job is None:
                skipped.append(SkippedTarget(target_id=target.id, reason="already queued"))
                continue
            jobs.append(
                JobRef(job_id=job.id, target_id=target.id, source_key=target.source_key, host=target.host)
            )
        if jobs:
            await tx.append_event(
                entity_type="device",
                entity_id=str(device_id),
                actor_id=user.id,
                action="collect.requested",
                now=now,
                after={"targets": [str(j.target_id) for j in jobs], "jobs": [j.job_id for j in jobs]},
            )
    return CollectResponse(jobs=jobs, skipped=skipped)


@router.get("/state", dependencies=[Depends(require_permission("graph.read"))])
async def inventory_state(request: Request) -> InventoryStateView:
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        state = await tx.get_state()
    return InventoryStateView(
        resolver_version=state.resolver_version,
        schema_version=state.schema_version,
        backfill_version=state.backfill_version,
        activation_state=ActivationState(state.activation_state),
        read_model_snapshot_key=state.read_model_snapshot_key,
        intent_generation=state.intent_generation,
        inventory_sync_pending=state.inventory_sync_pending,
        updated_at=state.updated_at,
    )


# --- operations: preview and apply ------------------------------------------------------------


@dataclass
class Draft:
    """What a handler's preview produced, before it is stored."""

    members: list[PreviewMember]
    changes: dict[str, Any] = field(default_factory=dict)
    impact: dict[str, Any] = field(default_factory=dict)
    impact_rows: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    affected_device_count: int = 0
    affected_target_count: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class Applied:
    results: list[ApplyResult]
    job_ids: list[int] = field(default_factory=list)


class OperationHandler(Protocol):
    async def preview(
        self,
        ctx: InventoryContext,
        tx: InventoryTx,
        user: User,
        request: PreviewRequest,
        state: InventoryState,
    ) -> Draft: ...

    async def apply(
        self, ctx: InventoryContext, tx: InventoryTx, user: User, preview: OperationPreview, now: datetime
    ) -> Applied: ...


OPERATIONS: dict[PreviewOperation, OperationHandler] = {}


def register_operation(operation: PreviewOperation, handler: OperationHandler) -> None:
    OPERATIONS[operation] = handler


async def materialize_devices(
    tx: InventoryTx, selection: Selection, state: InventoryState, *, include_archived: bool
) -> list[InventoryDevice]:
    """Return the members of a device selection.

    The members are the explicit ids, or every device that the filter matches at the generation
    that the client saw. More than MAX_SELECTION members give a 422 that asks for a narrower
    selection."""
    if selection.ids is not None:
        ids = []
        for raw in selection.ids:
            try:
                ids.append(uuid.UUID(raw))
            except ValueError as exc:
                raise InventoryError(f"malformed device id {raw!r}") from exc
        found = {d.id: d for d in await tx.get_devices(ids)}
        missing = [str(i) for i in ids if i not in found]
        if missing:
            raise InventoryError("selection names devices that do not exist", references=missing)
        return [found[i] for i in ids]
    if selection.filter is None:
        raise InventoryError("selection needs ids or a filter")
    if (
        selection.intent_generation != state.intent_generation
        or selection.snapshot_key != state.read_model_snapshot_key
    ):
        raise InventoryChanged("inventory changed since the selection was made; refresh")
    filters = filters_of(selection.filter)
    if include_archived and not filters.lifecycles:
        filters.lifecycles = [m.value for m in Lifecycle]
    out: list[InventoryDevice] = []
    cursor = None
    while True:
        page = await tx.list_devices(
            filters,
            sort=selection.filter.sort,
            direction=selection.filter.direction,
            limit=200,
            cursor=cursor,
        )
        out.extend(item.device for item in page.items)
        if len(out) > MAX_SELECTION:
            raise InventoryError(f"selection exceeds {MAX_SELECTION} devices; narrow the selection")
        if page.next_cursor is None:
            return out
        cursor = page.next_cursor


def _label(device: InventoryDevice) -> str:
    return device.hostname or device.graph_uid


class PlaceDevices:
    async def preview(
        self,
        ctx: InventoryContext,
        tx: InventoryTx,
        user: User,
        request: PreviewRequest,
        state: InventoryState,
    ) -> Draft:
        change = request.typed_change()
        if not isinstance(change, PlacementChange):
            raise InventoryError("place_devices needs a placement change")
        site_id = await _site_id_of(ctx, tx, change.site_id)
        devices = await materialize_devices(tx, request.selection, state, include_archived=False)
        placements = {p.device_id: p for p in await tx.get_placements([d.id for d in devices])}
        members = []
        rows = []
        targets: set[uuid.UUID] = set()
        for device in devices:
            current = placements.get(device.id)
            members.append(
                PreviewMember(
                    kind=PreviewMemberKind.DEVICE,
                    id=str(device.id),
                    revision=current.revision if current else 0,
                    label=_label(device),
                )
            )
            observing = [o.target_id for o in await tx.get_observations(device.id) if o.state != "absent"]
            targets.update(observing)
            rows.append(
                (
                    PreviewMemberKind.DEVICE.value,
                    str(device.id),
                    {
                        "label": _label(device),
                        "current_mode": current.mode if current else PlacementMode.AUTO.value,
                        "current_site_id": current.site_id if current else None,
                        "targets": len(observing),
                    },
                )
            )
        changes = {"mode": change.mode.value, "site_id": site_id}
        return Draft(members, changes, {"devices": len(devices)}, rows, len(devices), len(targets))

    async def apply(
        self, ctx: InventoryContext, tx: InventoryTx, user: User, preview: OperationPreview, now: datetime
    ) -> Applied:
        mode = PlacementMode(preview.changes["mode"])
        site_id = preview.changes.get("site_id")
        if site_id is not None:
            await _site_id_of(ctx, tx, str(site_id))
        results = []
        for member in preview.members:
            device_id = uuid.UUID(member["id"])
            before = await tx.get_placement(device_id)
            placement = await tx.set_placement(
                device_id,
                mode=mode,
                site_id=int(site_id) if site_id is not None else None,
                origin=PlacementOrigin.MANUAL.value,
                expected_revision=int(member["revision"]),
                actor_id=user.id,
                now=now,
            )
            await tx.append_event(
                entity_type="device",
                entity_id=str(device_id),
                actor_id=user.id,
                action="placement.set",
                now=now,
                before=eventsmod.placement_payload(before),
                after=eventsmod.placement_payload(placement),
                request_id=str(preview.token),
            )
            results.append(
                ApplyResult(kind=PreviewMemberKind.DEVICE, id=str(device_id), revision=placement.revision)
            )
        await ReadModel(ctx).refresh(tx, [uuid.UUID(m["id"]) for m in preview.members], now, collection=False)
        return Applied(results)


class LifecycleOperation:
    def __init__(self, action: LifecycleAction) -> None:
        self.action = action

    async def preview(
        self,
        ctx: InventoryContext,
        tx: InventoryTx,
        user: User,
        request: PreviewRequest,
        state: InventoryState,
    ) -> Draft:
        devices = await materialize_devices(tx, request.selection, state, include_archived=True)
        wanted = Lifecycle.ARCHIVED if self.action == LifecycleAction.UNARCHIVE else None
        members = []
        rows = []
        warnings = []
        for device in devices:
            if wanted is not None and device.lifecycle != wanted.value:
                raise InventoryError(f"device {_label(device)} is not archived", references=[str(device.id)])
            if wanted is None and device.lifecycle == Lifecycle.ARCHIVED.value:
                raise InventoryError(
                    f"device {_label(device)} is already archived", references=[str(device.id)]
                )
            members.append(
                PreviewMember(
                    kind=PreviewMemberKind.DEVICE,
                    id=str(device.id),
                    revision=device.revision,
                    label=_label(device),
                )
            )
            rows.append(
                (
                    PreviewMemberKind.DEVICE.value,
                    str(device.id),
                    {"label": _label(device), "lifecycle": device.lifecycle},
                )
            )
        if self.action == LifecycleAction.ARCHIVE:
            warnings.append("archiving hides devices from the default view; collection is unchanged")
        return Draft(
            members, {"action": self.action.value}, {"devices": len(devices)}, rows, len(devices), 0, warnings
        )

    async def apply(
        self, ctx: InventoryContext, tx: InventoryTx, user: User, preview: OperationPreview, now: datetime
    ) -> Applied:
        results = []
        for member in preview.members:
            device = await _device_or_404(tx, uuid.UUID(member["id"]))
            updated = await _set_lifecycle(tx, device, self.action, int(member["revision"]), user.id, now)
            results.append(
                ApplyResult(kind=PreviewMemberKind.DEVICE, id=str(device.id), revision=updated.revision)
            )
        return Applied(results)


class DeleteSite:
    async def preview(
        self,
        ctx: InventoryContext,
        tx: InventoryTx,
        user: User,
        request: PreviewRequest,
        state: InventoryState,
    ) -> Draft:
        ids = request.selection.ids
        if ids is None or len(ids) != 1:
            raise InventoryError("delete_site takes exactly one site id")
        site_id = parse_int_id(ids[0], "site")
        rows = [r for r in await ctx.site_rows(tx).list() if r.id == site_id]
        if not rows:
            raise NotFound("site not found")
        site = rows[0]
        impact_rows: list[tuple[str, str, dict[str, Any]]] = []
        devices: list[InventoryDevice] = []
        cursor = None
        filters = DeviceFilters(site_ids=[site_id], lifecycles=[m.value for m in Lifecycle])
        while True:
            page = await tx.list_devices(filters, sort=SortField.NAME, limit=200, cursor=cursor)
            devices.extend(item.device for item in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        placements = {p.device_id: p for p in await tx.get_placements([d.id for d in devices])}
        for device in devices:
            current = placements.get(device.id)
            impact_rows.append(
                (
                    PreviewMemberKind.DEVICE.value,
                    str(device.id),
                    {
                        "label": _label(device),
                        "mode": current.mode if current else PlacementMode.AUTO.value,
                        "effect": "unplaced" if current and current.site_id == site_id else "recomputed",
                    },
                )
            )
        # The member kinds have no location value. The impact row of a location binding has
        # the kind `connection` and the location handle as its entity.
        locations = [loc for loc in await tx.list_locations() if loc.site == site.code]
        for loc in locations:
            impact_rows.append(
                (
                    PreviewMemberKind.CONNECTION.value,
                    str(loc.handle),
                    {
                        "location": True,
                        "source_key": loc.source,
                        "location_id": loc.location_id,
                        "effect": "unbound",
                    },
                )
            )
        targets = [
            tg for tg in await tx.list_targets(include_archived=True) if tg.onboarding_site_id == site_id
        ]
        for tg in targets:
            impact_rows.append(
                (
                    PreviewMemberKind.TARGET.value,
                    str(tg.id),
                    {"source_key": tg.source_key, "host": tg.host, "effect": "default cleared"},
                )
            )
        member = PreviewMember(
            kind=PreviewMemberKind.SITE, id=str(site.id), revision=site.revision, label=site.code
        )
        impact = {"devices": len(devices), "locations": len(locations), "onboarding_targets": len(targets)}
        return Draft(
            [member], {"site_id": site.id, "code": site.code}, impact, impact_rows, len(devices), len(targets)
        )

    async def apply(
        self, ctx: InventoryContext, tx: InventoryTx, user: User, preview: OperationPreview, now: datetime
    ) -> Applied:
        member = preview.members[0]
        site_id = int(member["id"])
        rows = [r for r in await ctx.site_rows(tx).list() if r.id == site_id]
        if not rows:
            raise NotFound("site not found")
        if rows[0].revision != int(member["revision"]):
            from hst.app.inventory.repository import StaleRevision

            raise StaleRevision(
                f"site is at revision {rows[0].revision}, not {member['revision']}",
                current_revision=rows[0].revision,
            )
        release = await release_site(ctx, tx, site_id, actor_id=user.id, now=now)
        results = [ApplyResult(kind=PreviewMemberKind.SITE, id=str(site_id), revision=release.site.revision)]
        for placement in await tx.get_placements(release.placements):
            results.append(
                ApplyResult(
                    kind=PreviewMemberKind.DEVICE, id=str(placement.device_id), revision=placement.revision
                )
            )
        return Applied(results)


register_operation(PreviewOperation.PLACE_DEVICES, PlaceDevices())
register_operation(PreviewOperation.ARCHIVE_DEVICES, LifecycleOperation(LifecycleAction.ARCHIVE))
register_operation(PreviewOperation.RESTORE_DEVICES, LifecycleOperation(LifecycleAction.UNARCHIVE))
register_operation(PreviewOperation.DELETE_SITE, DeleteSite())


def _handler(operation: PreviewOperation) -> OperationHandler:
    handler = OPERATIONS.get(operation)
    if handler is None:
        raise InventoryError(f"operation {operation.value} is not available")
    return handler


@router.post("/operations/preview")
async def preview_operation(
    request: Request, body: PreviewRequest, user: User = Depends(current_user)
) -> PreviewResponse:
    ctx = context_for(request.app)
    permission = OPERATION_PERMISSIONS[body.operation]
    require(user, permission)
    handler = _handler(body.operation)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        state = await tx.get_state()
        draft = await handler.preview(ctx, tx, user, body, state)
        if len(draft.members) > MAX_SELECTION:
            raise InventoryError(f"selection exceeds {MAX_SELECTION} members; narrow the selection")
        preview = await tx.create_preview(
            actor_id=user.id,
            operation=body.operation.value,
            permissions=[permission],
            intent_generation=state.intent_generation,
            snapshot_key=state.read_model_snapshot_key,
            members=[m.model_dump(mode="json") for m in draft.members],
            changes=draft.changes,
            impact=draft.impact,
            secret_draft=None,
            now=now,
            ttl=PREVIEW_TTL,
        )
        await tx.add_preview_impacts(preview.token, draft.impact_rows)
    return PreviewResponse(
        token=preview.token,
        operation=body.operation,
        expires_at=preview.expires_at,
        generation=generation_of(state),
        members=draft.members,
        member_count=len(draft.members),
        affected_device_count=draft.affected_device_count,
        affected_target_count=draft.affected_target_count,
        changes=preview.changes,
        warnings=draft.warnings,
    )


def request_digest(body: ApplyRequest) -> str:
    return hashlib.sha256(f"apply\0{body.token}".encode()).hexdigest()


async def apply_operation(
    request: Request,
    body: ApplyRequest,
    user: User,
    *,
    expect: tuple[PreviewOperation, str] | None = None,
) -> ApplyResponse:
    """Consume the preview and apply it in one transaction.

    The consumption locks the preview row. A second concurrent apply waits and then reads the
    preview as consumed. A stale revision rolls back the transaction. The response is recorded
    under the idempotency key and replayed to a retry."""
    ctx = context_for(request.app)
    now = ctx.clock()
    digest = request_digest(body)
    async with ctx.repo.transaction() as tx:
        stored = await tx.check_idempotency(user.id, body.idempotency_key, digest)
        if stored is not None:
            replay = ApplyResponse.model_validate(stored.response)
            return replay.model_copy(update={"status": ApplyStatus.REUSED})
        preview = await tx.consume_preview(body.token, user.id, now, result_id=None)
        operation = PreviewOperation(preview.operation)
        if expect is not None and (
            operation != expect[0] or all(m["id"] != expect[1] for m in preview.members)
        ):
            raise InventoryError("the preview does not cover this resource")
        permission = OPERATION_PERMISSIONS[operation]
        require(user, permission)
        if permission not in preview.permissions:
            raise Forbidden("the preview was made under a different permission")
        applied = await _handler(operation).apply(ctx, tx, user, preview, now)
        state = await tx.get_state()
        response = ApplyResponse(
            token=preview.token,
            operation=operation,
            status=ApplyStatus.APPLIED,
            generation=generation_of(state),
            results=applied.results,
            job_ids=applied.job_ids,
        )
        await tx.record_operation_result(
            actor_id=user.id,
            idempotency_key=body.idempotency_key,
            request_digest=digest,
            status=200,
            response=response.model_dump(mode="json"),
            now=now,
        )
    return response


@router.post("/operations/apply")
async def apply_route(
    request: Request, body: ApplyRequest, user: User = Depends(current_user)
) -> ApplyResponse:
    return await apply_operation(request, body, user)


@router.get("/operations/previews/{token}/impact")
async def preview_impact(
    request: Request, token: uuid.UUID, user: User = Depends(current_user)
) -> ImpactPage:
    ctx = context_for(request.app)
    query = parse_page_query(request)
    after = eventsmod.decode_cursor(query.cursor) or 0
    async with ctx.repo.transaction() as tx:
        preview = await tx.get_preview(token, user.id, ctx.clock())
        require(user, OPERATION_PERMISSIONS[PreviewOperation(preview.operation)])
        state = await tx.get_state()
        if preview.intent_generation != state.intent_generation:
            raise InventoryChanged("inventory changed since the preview was made; preview again")
        rows, total = await tx.page_preview_impacts(token, after_seq=after, limit=query.limit)
    return ImpactPage(
        items=[
            ImpactItem(kind=PreviewMemberKind(r.kind), entity_id=r.entity_id, detail=r.detail) for r in rows
        ],
        next_cursor=str(rows[-1].seq) if rows and rows[-1].seq < total else None,
        total=total,
        generation=generation_of(state),
    )


# --- registration -------------------------------------------------------------------------------

ROUTERS: tuple[APIRouter, ...] = (router, sites_router, views_router)


async def _handle_inventory_error(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, InventoryError):
        return error_response(exc)
    raise exc


def register(app: FastAPI, *, prefix: str = API_PREFIX, operations: bool = True) -> None:
    app.add_exception_handler(InventoryError, _handle_inventory_error)
    for r in ROUTERS:
        if r is router and not operations:
            selected = APIRouter()
            selected.routes.extend(
                route for route in r.routes if not getattr(route, "path", "").startswith("/operations/")
            )
            app.include_router(selected, prefix=prefix)
        else:
            app.include_router(r, prefix=prefix)


def service_for(app: FastAPI) -> ObservationService:
    return ObservationService(context_for(app))
