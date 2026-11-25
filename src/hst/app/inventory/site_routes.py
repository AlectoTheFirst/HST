"""Sites and reported locations under /api/inventory."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ValidationError

from hst.app.auth import current_user, require_permission
from hst.app.inventory.contracts import (
    ApplyRequest,
    ApplyResponse,
    BulkRowStatus,
    LocationBindingResult,
    LocationBindingRowResult,
    LocationBindings,
    LocationConnectionCount,
    LocationMatch,
    LocationPage,
    LocationPatch,
    LocationRow,
    LocationSearchQuery,
    LocationState,
    LocationStateCounts,
    LocationView,
    PreviewOperation,
    SiteCreate,
    SiteImport,
    SiteImportResult,
    SiteImportRowResult,
    SitePage,
    SitePatch,
    SiteSearchQuery,
    SiteSort,
    SiteView,
    SortDirection,
)
from hst.app.inventory.observations import InventoryContext, ReadModel, SiteRow, context_for
from hst.app.inventory.repository import InventoryError, InventoryTx, NotFound
from hst.app.inventory.site_params import SiteBlock
from hst.app.store import InventoryLocation, User
from hst.core import uid as uidmod

router = APIRouter()


def parse_int_id(value: str, what: str) -> int:
    """An integer id arrives as a string. A malformed id is a 422."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise InventoryError(f"malformed {what} id") from exc


def parse_query[Q: BaseModel](model: type[Q], request: Request) -> Q:
    """Validate the query parameters with `model`. An unknown or malformed query field is a 422."""
    try:
        return model.model_validate(dict(request.query_params))
    except ValidationError as exc:
        errors = exc.errors()
        if not errors:
            raise InventoryError("invalid query") from exc
        where = ".".join(str(p) for p in errors[0]["loc"])
        raise InventoryError(f"invalid query: {where}: {errors[0]['msg']}") from exc


def _norm(value: str) -> str:
    return "".join(ch for ch in value.casefold() if ch.isalnum())


class SiteMatcher:
    """Suggests a site for an unmapped location. The rules run in order, and the
    first rule that matches any site decides. One match is the suggestion. More
    than one match is ambiguous and suggests nothing. Codes and names compare with
    case and punctuation removed. "FRA-DC" matches the code "fra_dc"."""

    RULES = ("code", "name", "location_id", "code_in_name")

    def __init__(self, rows: list[SiteRow]) -> None:
        self._by_code: dict[str, list[SiteRow]] = {}
        self._by_name: dict[str, list[SiteRow]] = {}
        for row in rows:
            self._by_code.setdefault(_norm(row.code), []).append(row)
            if _norm(row.name):
                self._by_name.setdefault(_norm(row.name), []).append(row)

    def match(self, loc: InventoryLocation) -> tuple[SiteRow, str] | None:
        name = _norm(loc.name)
        tokens = {_norm(t) for t in re.split(r"[^0-9A-Za-z]+", loc.name) if len(t) >= 2}
        candidates = {
            "code": self._by_code.get(name, []) if name else [],
            "name": self._by_name.get(name, []) if name else [],
            "location_id": self._by_code.get(_norm(loc.location_id), []),
            "code_in_name": list({r.id: r for t in tokens for r in self._by_code.get(t, [])}.values()),
        }
        for rule in self.RULES:
            hits = candidates[rule]
            if len(hits) == 1:
                return hits[0], rule
            if hits:
                return None
        return None


# --- sites -----------------------------------------------------------------------------------


@dataclass
class SiteCounts:
    devices: dict[int, int]
    locations: dict[str, int]


async def site_counts(ctx: InventoryContext, tx: InventoryTx) -> SiteCounts:
    devices = await ctx.site_rows(tx).device_counts()
    locations = Counter(loc.site for loc in await tx.list_locations() if loc.site)
    return SiteCounts(devices, dict(locations))


def site_view(row: SiteRow, counts: SiteCounts) -> SiteView:
    return SiteView(
        id=str(row.id),
        code=row.code,
        name=row.name,
        location=row.location,
        lat=row.lat,
        lon=row.lon,
        site_group=row.site_group,
        blocks=None if row.blocks is None else [SiteBlock.model_validate(b) for b in row.blocks],
        revision=row.revision,
        device_count=counts.devices.get(row.id, 0),
        location_count=counts.locations.get(row.code, 0),
    )


async def site_row(ctx: InventoryContext, tx: InventoryTx, site_id: int) -> SiteRow:
    for row in await ctx.site_rows(tx).list():
        if row.id == site_id:
            return row
    raise NotFound("site not found")


@router.get("/sites", dependencies=[Depends(require_permission("graph.read"))])
async def list_sites(request: Request) -> list[SiteView]:
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        rows = await ctx.site_rows(tx).list()
        counts = await site_counts(ctx, tx)
    return [site_view(r, counts) for r in rows]


@router.get("/sites/search", dependencies=[Depends(require_permission("graph.read"))])
async def search_sites(request: Request) -> SitePage:
    """Sites matching `q` in code, name or location, sorted and paged."""
    query = parse_query(SiteSearchQuery, request)
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        rows = await ctx.site_rows(tx).list()
        counts = await site_counts(ctx, tx)
    views = [site_view(r, counts) for r in rows]
    if query.q:
        needle = query.q.casefold()
        views = [v for v in views if needle in f"{v.code}\n{v.name}\n{v.location}".casefold()]
    views.sort(key=lambda v: v.code)
    if query.sort == SiteSort.NAME:
        views.sort(key=lambda v: (v.name or v.code).casefold())
    elif query.sort == SiteSort.DEVICES:
        views.sort(key=lambda v: v.device_count)
    if query.direction == SortDirection.DESC:
        views.reverse()
    page = views[query.offset : query.offset + query.limit]
    return SitePage(items=page, total=len(views), offset=query.offset, limit=query.limit)


@router.get("/sites/{site_id}", dependencies=[Depends(require_permission("graph.read"))])
async def get_site(request: Request, site_id: str) -> SiteView:
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        row = await site_row(ctx, tx, parse_int_id(site_id, "site"))
        counts = await site_counts(ctx, tx)
    return site_view(row, counts)


@router.post("/sites", status_code=201, dependencies=[Depends(require_permission("sites.write"))])
async def create_site(request: Request, body: SiteCreate, user: User = Depends(current_user)) -> SiteView:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        row = await ctx.site_rows(tx).create(body.code, body.name, body.location, now=now, point=body.point())
        after: dict[str, Any] = {
            "code": row.code,
            "name": row.name,
            "location": row.location,
            "revision": row.revision,
        }
        if row.lat is not None:
            after.update(lat=row.lat, lon=row.lon)
        await tx.append_event(
            entity_type="site",
            entity_id=str(row.id),
            actor_id=user.id,
            action="site.create",
            now=now,
            after=after,
        )
    return site_view(row, SiteCounts({}, {}))


@router.post("/sites/import", dependencies=[Depends(require_permission("sites.write"))])
async def import_sites(
    request: Request, body: SiteImport, user: User = Depends(current_user)
) -> SiteImportResult:
    """Create the sites whose code is new and update the name and location of
    the others. Nothing is written when a row is refused or on a dry run."""
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        existing = {r.code: r for r in await ctx.site_rows(tx).list()}
        seen: set[str] = set()
        results: list[SiteImportRowResult] = []
        for index, item in enumerate(body.sites):
            current = existing.get(item.code)
            if item.code in seen:
                results.append(
                    SiteImportRowResult(
                        index=index,
                        code=item.code,
                        action="none",
                        status=BulkRowStatus.ERROR,
                        error="duplicate code in this import",
                    )
                )
                continue
            clash = uidmod.site_fold(item.code, [*existing, *seen])
            seen.add(item.code)
            if clash is not None:
                results.append(
                    SiteImportRowResult(
                        index=index,
                        code=item.code,
                        action="none",
                        status=BulkRowStatus.ERROR,
                        error=f"code folds onto {clash!r}: both are the site {uidmod.site(item.code)}",
                    )
                )
                continue
            if current is None:
                action, status = "create", BulkRowStatus.CHANGE
            elif (item.name is not None and item.name != current.name) or (
                item.location is not None and item.location != current.location
            ):
                action, status = "update", BulkRowStatus.CHANGE
            else:
                action, status = "none", BulkRowStatus.UNCHANGED
            results.append(
                SiteImportRowResult(index=index, code=item.code, action=action, status=status, error=None)
            )
        errors = sum(r.status == BulkRowStatus.ERROR for r in results)
        applied = not body.dry_run and errors == 0
        if applied:
            rows = ctx.site_rows(tx)
            for item, result in zip(body.sites, results, strict=True):
                if result.action == "create":
                    row = await rows.create(item.code, item.name or "", item.location or "", now=now)
                    await tx.append_event(
                        entity_type="site",
                        entity_id=str(row.id),
                        actor_id=user.id,
                        action="site.create",
                        now=now,
                        after={
                            "code": row.code,
                            "name": row.name,
                            "location": row.location,
                            "revision": row.revision,
                        },
                    )
                elif result.action == "update":
                    before = existing[item.code]
                    kwargs: dict[str, Any] = {}
                    if item.name is not None:
                        kwargs["name"] = item.name
                    if item.location is not None:
                        kwargs["location"] = item.location
                    row = await rows.update(before.id, expected_revision=before.revision, now=now, **kwargs)
                    await tx.append_event(
                        entity_type="site",
                        entity_id=str(row.id),
                        actor_id=user.id,
                        action="site.update",
                        now=now,
                        before={
                            "name": before.name,
                            "location": before.location,
                            "revision": before.revision,
                        },
                        after={"name": row.name, "location": row.location, "revision": row.revision},
                    )
    return SiteImportResult(
        applied=applied,
        created=sum(r.action == "create" for r in results),
        updated=sum(r.action == "update" for r in results),
        unchanged=sum(r.status == BulkRowStatus.UNCHANGED for r in results),
        errors=errors,
        rows=results,
    )


@router.patch("/sites/{site_id}", dependencies=[Depends(require_permission("sites.write"))])
async def update_site(
    request: Request, site_id: str, body: SitePatch, user: User = Depends(current_user)
) -> SiteView:
    ctx = context_for(request.app)
    now = ctx.clock()
    sid = parse_int_id(site_id, "site")
    async with ctx.repo.transaction() as tx:
        before = await site_row(ctx, tx, sid)
        kwargs: dict[str, Any] = {}
        if body.name is not None:
            kwargs["name"] = body.name
        if body.location is not None:
            kwargs["location"] = body.location
        if body.sets_point:
            kwargs["point"] = body.point()
        layout = body.map_params()
        kwargs.update(layout)
        row = await ctx.site_rows(tx).update(sid, expected_revision=body.expected_revision, now=now, **kwargs)
        before_event: dict[str, Any] = {
            "name": before.name,
            "location": before.location,
            "revision": before.revision,
        }
        after_event: dict[str, Any] = {"name": row.name, "location": row.location, "revision": row.revision}
        if body.sets_point:
            before_event.update(lat=before.lat, lon=before.lon)
            after_event.update(lat=row.lat, lon=row.lon)
        for key in layout:
            before_event[key] = getattr(before, key)
            after_event[key] = getattr(row, key)
        await tx.append_event(
            entity_type="site",
            entity_id=str(row.id),
            actor_id=user.id,
            action="site.update",
            now=now,
            before=before_event,
            after=after_event,
        )
        counts = await site_counts(ctx, tx)
    return site_view(row, counts)


@dataclass
class SiteRelease:
    """The records that the deletion of a site released."""

    site: SiteRow
    placements: list[uuid.UUID]
    locations: list[uuid.UUID]
    onboarding_targets: int
    refreshed: list[uuid.UUID]


async def release_site(
    ctx: InventoryContext, tx: InventoryTx, site_id: int, *, actor_id: int | None, now: datetime
) -> SiteRelease:
    """Delete the site and release its placements, locations and onboarding defaults in `tx`."""
    row = await site_row(ctx, tx, site_id)
    placements = await tx.release_site_placements(site_id, actor_id=actor_id, now=now)
    handles = await tx.unbind_site_locations(row.code, now)
    cleared = await tx.clear_onboarding_site(site_id, now)
    read_model = ReadModel(ctx)
    moved = await read_model.devices_at_locations(tx, handles)
    await ctx.site_rows(tx).delete(site_id)
    affected = sorted(set(placements) | set(moved), key=str)
    await read_model.refresh(tx, affected, now, collection=False)
    for device_id in placements:
        await tx.append_event(
            entity_type="device",
            entity_id=str(device_id),
            actor_id=actor_id,
            action="placement.released",
            now=now,
            before={"mode": "assigned", "site_id": site_id},
            after={"mode": "unplaced", "site_id": None},
        )
    await tx.append_event(
        entity_type="site",
        entity_id=str(site_id),
        actor_id=actor_id,
        action="site.delete",
        now=now,
        before={"code": row.code, "revision": row.revision},
        after={
            "placements_released": len(placements),
            "locations_unbound": len(handles),
            "onboarding_defaults_cleared": cleared,
        },
    )
    return SiteRelease(row, placements, handles, cleared, affected)


@router.delete("/sites/{site_id}", dependencies=[Depends(require_permission("sites.write"))])
async def delete_site(
    request: Request,
    site_id: str,
    token: uuid.UUID,
    idempotency_key: str = Query(min_length=1, max_length=128),
    user: User = Depends(current_user),
) -> ApplyResponse:
    """Apply a `delete_site` preview whose one member is this site. The token
    and the idempotency key are query parameters."""
    from hst.app.inventory.inventory_routes import apply_operation

    sid = parse_int_id(site_id, "site")
    body = ApplyRequest(token=token, idempotency_key=idempotency_key)
    return await apply_operation(request, body, user, expect=(PreviewOperation.DELETE_SITE, str(sid)))


# --- locations ---------------------------------------------------------------------------------


def location_view(
    loc: InventoryLocation,
    *,
    source_ids: dict[str, int],
    site_ids: dict[str, int],
    device_counts: dict[uuid.UUID, int],
) -> LocationView:
    source_id = source_ids.get(loc.source)
    return LocationView(
        id=loc.handle,
        connection_id=str(source_id) if source_id is not None else "",
        source_key=loc.source,
        location_id=loc.location_id,
        name=loc.name,
        site_id=str(site_ids[loc.site]) if loc.site and loc.site in site_ids else None,
        site_code=loc.site,
        revision=loc.revision,
        device_count=device_counts.get(loc.handle, 0),
    )


async def _location_context(
    ctx: InventoryContext, tx: InventoryTx
) -> tuple[dict[str, int], dict[str, int], dict[uuid.UUID, int]]:
    source_ids = {s.name: s.source_id for s in await tx.list_source_inventory()}
    site_ids = {s.code: s.id for s in await ctx.site_rows(tx).list()}
    counts = await ctx.aux(tx).location_device_counts()
    return source_ids, site_ids, counts


@router.get("/locations", dependencies=[Depends(require_permission("graph.read"))])
async def list_locations(request: Request, connection_id: str | None = None) -> list[LocationView]:
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        source = None
        if connection_id is not None:
            row = await tx.get_source_inventory(parse_int_id(connection_id, "connection"))
            if row is None:
                raise NotFound("connection not found")
            source = row.name
        rows = await tx.list_locations(source)
        source_ids, site_ids, counts = await _location_context(ctx, tx)
    return [location_view(r, source_ids=source_ids, site_ids=site_ids, device_counts=counts) for r in rows]


def _matches(loc: InventoryLocation, needle: str) -> bool:
    return needle in f"{loc.name}\n{loc.location_id}\n{loc.source}\n{loc.site or ''}".casefold()


@router.get("/locations/search", dependencies=[Depends(require_permission("graph.read"))])
async def search_locations(request: Request) -> LocationPage:
    """Locations filtered by text, connection, site and mapping state, with a
    suggested site on each unmapped row. The state counts apply every filter
    but the state, and the connection counts apply every filter but the
    connection."""
    query = parse_query(LocationSearchQuery, request)
    ctx = context_for(request.app)
    async with ctx.repo.transaction() as tx:
        source = None
        if query.connection_id is not None:
            row = await tx.get_source_inventory(parse_int_id(query.connection_id, "connection"))
            if row is None:
                raise NotFound("connection not found")
            source = row.name
        site_code = None
        if query.site_id is not None:
            site_code = (await site_row(ctx, tx, parse_int_id(query.site_id, "site"))).code
        locations = await tx.list_locations()
        site_rows = await ctx.site_rows(tx).list()
        source_ids, site_ids, counts = await _location_context(ctx, tx)
    matcher = SiteMatcher(site_rows)
    suggestions = {loc.handle: matcher.match(loc) for loc in locations if loc.site is None}
    if query.q:
        needle = query.q.casefold()
        locations = [loc for loc in locations if _matches(loc, needle)]
    if site_code is not None:
        locations = [loc for loc in locations if loc.site == site_code]
    per_source = Counter(loc.source for loc in locations)
    if source is not None:
        locations = [loc for loc in locations if loc.source == source]

    def state_of(loc: InventoryLocation) -> set[LocationState]:
        if loc.site is not None:
            return {LocationState.MAPPED}
        return (
            {LocationState.UNMAPPED, LocationState.SUGGESTED}
            if suggestions.get(loc.handle)
            else {LocationState.UNMAPPED}
        )

    states = Counter(state for loc in locations for state in state_of(loc))
    if query.state != LocationState.ALL:
        locations = [loc for loc in locations if query.state in state_of(loc)]
    locations.sort(
        key=lambda loc: (loc.name.casefold() or loc.location_id.casefold(), loc.source, loc.location_id)
    )
    page = locations[query.offset : query.offset + query.limit]
    items = []
    for loc in page:
        match = suggestions.get(loc.handle)
        items.append(
            LocationRow(
                location=location_view(loc, source_ids=source_ids, site_ids=site_ids, device_counts=counts),
                suggestion=LocationMatch(site_id=str(match[0].id), site_code=match[0].code, rule=match[1])
                if match
                else None,
            )
        )
    return LocationPage(
        items=items,
        total=len(locations),
        offset=query.offset,
        limit=query.limit,
        counts=LocationStateCounts(
            all=sum(per_source.values()) if source is None else per_source.get(source, 0),
            mapped=states[LocationState.MAPPED],
            unmapped=states[LocationState.UNMAPPED],
            suggested=states[LocationState.SUGGESTED],
        ),
        connections=[
            LocationConnectionCount(connection_id=str(source_ids.get(key, "")), source_key=key, count=n)
            for key, n in sorted(per_source.items())
        ],
    )


@router.post("/locations/bindings", dependencies=[Depends(require_permission("sites.write"))])
async def bind_locations(
    request: Request, body: LocationBindings, user: User = Depends(current_user)
) -> LocationBindingResult:
    """Map many locations in one transaction. A row is refused when its location
    or site does not exist, when it names a location twice, or when its expected
    revision is stale. Nothing is written when a row is refused or on a dry run.
    The devices at every changed location are recomputed once, after the writes."""
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        locations = await tx.list_locations()
        by_handle = {loc.handle: loc for loc in locations}
        by_key = {(loc.source, loc.location_id): loc for loc in locations}
        site_list = await ctx.site_rows(tx).list()
        site_by_id = {str(r.id): r for r in site_list}
        site_by_code = {r.code: r for r in site_list}
        seen: set[uuid.UUID] = set()
        rows: list[LocationBindingRowResult] = []
        planned: list[tuple[InventoryLocation, str | None]] = []
        for index, item in enumerate(body.bindings):
            error = None
            loc = None
            if item.id is not None:
                loc = by_handle.get(item.id)
                error = None if loc else "location not found"
            elif item.source_key and item.location_id:
                loc = by_key.get((item.source_key, item.location_id))
                error = None if loc else f"no location {item.location_id} on connection {item.source_key}"
            else:
                error = "a binding needs a location id, or a connection key and a vendor location id"
            code: str | None = None
            if error is None and item.site_id is not None and item.site_code is not None:
                error = "a binding takes a site id or a site code, and this one has both"
            elif error is None and item.site_id is not None:
                site = site_by_id.get(item.site_id)
                error = None if site else f"site {item.site_id} not found"
                code = site.code if site else None
            elif error is None and item.site_code:
                site = site_by_code.get(item.site_code)
                error = None if site else f"site code {item.site_code} not found"
                code = site.code if site else None
            if error is None and loc is not None and loc.handle in seen:
                error = "the location appears twice in this request"
            if error is None and loc is not None and item.expected_revision not in (None, loc.revision):
                error = f"the location changed; current revision {loc.revision}"
            if loc is not None:
                seen.add(loc.handle)
            if error is not None:
                status = BulkRowStatus.ERROR
            elif loc is not None and loc.site == code:
                status = BulkRowStatus.UNCHANGED
            else:
                status = BulkRowStatus.CHANGE
            if status == BulkRowStatus.CHANGE and loc is not None:
                planned.append((loc, code))
            rows.append(
                LocationBindingRowResult(
                    index=index,
                    id=loc.handle if loc else None,
                    source_key=loc.source if loc else item.source_key or "",
                    location_id=loc.location_id if loc else item.location_id or "",
                    name=loc.name if loc else "",
                    site_before=loc.site if loc else None,
                    site_after=code if error is None else None,
                    status=status,
                    error=error,
                )
            )
        errors = sum(r.status == BulkRowStatus.ERROR for r in rows)
        applied = not body.dry_run and errors == 0
        moved: list[uuid.UUID] = []
        if applied and planned:
            for loc, code in planned:
                row = await tx.bind_location(loc.handle, code, expected_revision=loc.revision, now=now)
                await tx.append_event(
                    entity_type="location",
                    entity_id=str(loc.handle),
                    actor_id=user.id,
                    action="location.bind",
                    now=now,
                    before={"site": loc.site, "revision": loc.revision},
                    after={"site": row.site, "revision": row.revision},
                )
            read_model = ReadModel(ctx)
            moved = await read_model.devices_at_locations(tx, [loc.handle for loc, _ in planned])
            await read_model.refresh(tx, moved, now, collection=False)
    return LocationBindingResult(
        applied=applied,
        changed=len(planned),
        unchanged=sum(r.status == BulkRowStatus.UNCHANGED for r in rows),
        errors=errors,
        devices_recomputed=len(moved),
        rows=rows,
    )


@router.patch("/locations/{handle}", dependencies=[Depends(require_permission("sites.write"))])
async def bind_location(
    request: Request, handle: uuid.UUID, body: LocationPatch, user: User = Depends(current_user)
) -> LocationView:
    ctx = context_for(request.app)
    now = ctx.clock()
    async with ctx.repo.transaction() as tx:
        before = await tx.get_location(handle)
        if before is None:
            raise NotFound("location not found")
        code: str | None = None
        if body.site_id is not None:
            site = await site_row(ctx, tx, parse_int_id(body.site_id, "site"))
            code = site.code
        row = await tx.bind_location(handle, code, expected_revision=body.expected_revision, now=now)
        moved = await ReadModel(ctx).devices_at_locations(tx, [handle])
        await ReadModel(ctx).refresh(tx, moved, now, collection=False)
        await tx.append_event(
            entity_type="location",
            entity_id=str(handle),
            actor_id=user.id,
            action="location.bind",
            now=now,
            before={"site": before.site, "revision": before.revision},
            after={"site": row.site, "revision": row.revision, "devices_recomputed": len(moved)},
        )
        source_ids, site_ids, counts = await _location_context(ctx, tx)
    return location_view(row, source_ids=source_ids, site_ids=site_ids, device_counts=counts)
