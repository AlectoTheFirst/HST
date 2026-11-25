"""The routes for sites, locations, device placement and the reachability between sites."""

from __future__ import annotations

import asyncio
import functools
import re
from collections import Counter
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, NamedTuple

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator, model_validator

from hst.app import sources as glue
from hst.app.auth import current_user, require_permission
from hst.app.inventory import collection as inventory_collection
from hst.app.inventory import events as inventory_events
from hst.app.inventory import site_routes as inventory_sites
from hst.app.inventory.contracts import PlacementMode
from hst.app.inventory.observations import ReadModel, context_for
from hst.app.inventory.repository import NotFound
from hst.app.permissions import permissions_for
from hst.app.routes.run_lease import aleased
from hst.app.store import DeviceFilters
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.core import uid as uidmod
from hst.results.trace import project_trace
from hst.results.words import Missing, from_engine

if TYPE_CHECKING:
    from hst.core.snapshot import Snapshot

router = APIRouter()

CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

MAX_PAIRS = 64


class SiteBody(BaseModel):
    code: str
    name: str = ""
    location: str = ""
    params: SiteParams | None = None

    @field_validator("code")
    @classmethod
    def _check_code(cls, v: str) -> str:
        if not CODE_RE.match(v):
            raise ValueError("code must be alphanumeric with . _ : - and no spaces")
        return v


class SitePatch(BaseModel):
    name: str | None = None
    location: str | None = None
    # A patch may set one coordinate. update_site checks the lat and lon pair
    # on the merged result.
    params: SiteParamsPatch | None = None


class SiteParamsPatch(BaseModel):
    """The parameters of a site, with one network default and the place on the map.

    `lat` and `lon` are set together or not at all.
    """

    routing_scope: str | None = None
    lat: float | None = None
    lon: float | None = None

    @field_validator("routing_scope")
    @classmethod
    def _identifier(cls, value: str | None) -> str | None:
        if value is not None and not CODE_RE.fullmatch(value):
            raise ValueError("must be a canonical identifier with . _ : - and no spaces")
        return value

    @field_validator("lat")
    @classmethod
    def _lat(cls, value: float | None) -> float | None:
        if value is not None and not -90 <= value <= 90:
            raise ValueError("lat must be within -90..90")
        return value

    @field_validator("lon")
    @classmethod
    def _lon(cls, value: float | None) -> float | None:
        if value is not None and not -180 <= value <= 180:
            raise ValueError("lon must be within -180..180")
        return value


class SiteParams(SiteParamsPatch):
    """The site parameters that are stored and that a create sends."""

    @model_validator(mode="after")
    def _coordinates(self) -> SiteParams:
        if (self.lat is None) != (self.lon is None):
            raise ValueError("lat and lon go together")
        return self


# These params shape collection. A change to them needs the permission for
# source edits. Any site editor may set the rest of SiteParams.
NETWORK_PARAMS = frozenset({"routing_scope"})


SiteBody.model_rebuild()
SitePatch.model_rebuild()


class AssignBody(BaseModel):
    device_uid: str
    # A null site removes the hand placement, and the device takes the site from its collector.
    site: str | None = None


class BindBody(BaseModel):
    # A null site unbinds the location, and its devices become unplaced.
    site: str | None = None


def _public(site: Any) -> dict[str, Any]:
    return {
        "code": site.code,
        "name": site.name,
        "location": site.location,
        "params": site.params,
        "device_count": site.device_count,
    }


async def _inventory_active(store: Any) -> bool:
    return (
        inventory_collection.has_inventory(store)
        and (await inventory_collection.execution_context(store)).activated
    )


def _reject_normalization_change(before: dict, after: dict, reference: str) -> None:
    from hst.app.inventory.legacy import NormalizationMigrated

    if any(before.get(key) != after.get(key) for key in NETWORK_PARAMS):
        raise NormalizationMigrated(
            "site routing normalization is frozen; use inventory placement for physical moves",
            references=[reference],
        )


async def _site_by_code(ctx: Any, tx: Any, code: str) -> Any:
    for row in await ctx.site_rows(tx).list():
        if row.code == code:
            return row
    raise NotFound(f"no such site: {code}")


async def _write_site_params(ctx: Any, tx: Any, row: Any, params: dict) -> None:
    if tx.connection is not None:
        from hst.app.store.pg import sites

        await tx.connection.execute(sites.update().where(sites.c.id == row.id).values(params=params))
    else:
        await ctx.store.update_site(row.code, name=row.name, location=row.location, params=params)


async def _locked_site_params(ctx: Any, tx: Any, row: Any) -> dict:
    """The params of the site `row`, with the row locked FOR NO KEY UPDATE until
    the transaction ends."""
    if tx.connection is not None:
        import sqlalchemy as sa

        from hst.app.store.pg import sites

        stored = (
            await tx.connection.execute(
                sa.select(sites.c.params).where(sites.c.id == row.id).with_for_update(key_share=True)
            )
        ).scalar()
        return dict(stored or {})
    legacy = await ctx.store.get_site(row.code)
    return dict(legacy.params or {}) if legacy else {}


async def _legacy_site_result(ctx: Any, tx: Any, row: Any, params: dict) -> dict[str, Any]:
    counts = await inventory_sites.site_counts(ctx, tx)
    return {
        "code": row.code,
        "name": row.name,
        "location": row.location,
        "params": params,
        "device_count": counts.devices.get(row.id, 0),
    }


async def _placements(store: Any, request: Request | None = None) -> dict[str, tuple[str, str]]:
    """Every collected device's site and what decided it."""
    if request is not None and await _inventory_active(store):
        ctx = context_for(request.app)
        resolved: dict[str, tuple[str, str]] = {}
        async with ctx.repo.transaction() as tx:
            cursor = None
            while True:
                page = await tx.list_devices(DeviceFilters(), limit=200, cursor=cursor)
                for item in page.items:
                    if item.site_code is not None:
                        placed = await tx.get_placement(item.device.id)
                        origin = "hand" if placed and placed.mode == "assigned" else "location"
                        resolved[item.device.graph_uid] = (item.site_code, origin)
                cursor = page.next_cursor
                if cursor is None:
                    return resolved
    locations = await store.list_reported_locations()
    return glue.resolve_device_sites(
        await store.device_sites(),
        await store.target_devices(),
        {row.name: row for row in await store.list_sources()},
        {(loc.source, loc.location_id): loc.site for loc in locations if loc.site},
    )


@router.get("/sites", dependencies=[Depends(require_permission("graph.read"))])
async def list_sites(request: Request) -> dict[str, Any]:
    """Every site, with what sits there and what a delete would release.

    `device_count` counts every device that the placement rule puts at the site.
    The other 3 counts are what a delete would clear.
    """
    store = request.app.state.store
    if await _inventory_active(store):
        ctx = context_for(request.app)
        async with ctx.repo.transaction() as tx:
            rows = await ctx.site_rows(tx).list()
            counts = await inventory_sites.site_counts(ctx, tx)
            legacy = {site.code: site for site in await store.list_sites()}
            placed: Counter[str] = Counter()
            cursor = None
            while True:
                page = await tx.list_devices(DeviceFilters(), limit=200, cursor=cursor)
                placements = {
                    p.device_id: p for p in await tx.get_placements([item.device.id for item in page.items])
                }
                for item in page.items:
                    placement = placements.get(item.device.id)
                    if item.site_code and placement and placement.mode == "assigned":
                        placed[item.site_code] += 1
                cursor = page.next_cursor
                if cursor is None:
                    break
            return {
                "sites": [
                    {
                        "code": row.code,
                        "name": row.name,
                        "location": row.location,
                        "params": legacy[row.code].params if row.code in legacy else {},
                        "device_count": counts.devices.get(row.id, 0),
                        "group_count": 0,
                        "location_count": counts.locations.get(row.code, 0),
                        "placed_count": placed[row.code],
                    }
                    for row in rows
                ]
            }
    rows = await store.list_sites()
    groups = Counter(
        row.config.get("site_code")
        for row in await store.list_sources()
        if glue.is_group(row.type) and row.config.get("site_code")
    )
    locations = Counter(loc.site for loc in await store.list_reported_locations() if loc.site)
    placed = Counter((await store.device_sites()).values())
    here = Counter(site for site, _origin in (await _placements(store, request)).values())
    return {
        "sites": [
            _public(s)
            | {
                "device_count": here.get(s.code, 0),
                "group_count": groups.get(s.code, 0),
                "location_count": locations.get(s.code, 0),
                "placed_count": placed.get(s.code, 0),
            }
            for s in rows
        ]
    }


async def site_codes(store: Any, ctx_of: Callable[[], Any]) -> set[str]:
    """The codes of every site, from the rows `create_site_row` writes to."""
    if await _inventory_active(store):
        ctx = ctx_of()
        async with ctx.repo.transaction() as tx:
            return {row.code for row in await ctx.site_rows(tx).list()}
    return {site.code for site in await store.list_sites()}


async def create_site_row(
    store: Any, ctx_of: Callable[[], Any], body: SiteBody, actor_id: int | None
) -> dict[str, Any]:
    """Create one site. With an active inventory, write the inventory site row and its event.
    Otherwise write the site row of the store. POST /api/sites and the demo estate load
    (app/demo_estate.py) create sites here. The store raises ValueError for a code that exists.

    The caller checks that the actor may set the network parameters `body` names."""
    # The params hold only the keys that the operator set. A later patch merges
    # over these keys.
    params = body.params.model_dump(exclude_unset=True) if body.params is not None else {}
    if await _inventory_active(store):
        _reject_normalization_change({}, params, f"site:{body.code}")
        ctx = ctx_of()
        now = ctx.clock()
        async with ctx.repo.transaction() as tx:
            row = await ctx.site_rows(tx).create(body.code, body.name, body.location, now=now)
            await _write_site_params(ctx, tx, row, params)
            await tx.append_event(
                entity_type="site",
                entity_id=str(row.id),
                actor_id=actor_id,
                action="site.create",
                now=now,
                after={"code": row.code, "params": params},
            )
            return await _legacy_site_result(ctx, tx, row, params)
    return _public(await store.create_site(body.code, body.name, body.location, params))


@router.post("/sites", status_code=201, dependencies=[Depends(require_permission("sites.write"))])
async def create_site(request: Request, body: SiteBody, user: Any = Depends(current_user)) -> dict[str, Any]:
    store = request.app.state.store
    ctx_of = functools.partial(context_for, request.app)
    if await _inventory_active(store):
        return await create_site_row(store, ctx_of, body, user.id)
    params = body.params.model_dump(exclude_unset=True) if body.params is not None else {}
    if any(params.get(key) is not None for key in NETWORK_PARAMS):
        _require_sources_write(user)
    try:
        return await create_site_row(store, ctx_of, body, user.id)
    except ValueError as exc:
        raise HTTPException(409, detail=str(exc)) from exc


@router.patch("/sites/{code}", dependencies=[Depends(require_permission("sites.write"))])
async def update_site(
    request: Request, code: str, body: SitePatch, user: Any = Depends(current_user)
) -> dict[str, Any]:
    store = request.app.state.store
    if await _inventory_active(store):
        ctx = context_for(request.app)
        now = ctx.clock()
        async with ctx.repo.transaction() as tx:
            current = await _site_by_code(ctx, tx, code)
            before_params = await _locked_site_params(ctx, tx, current)
            active_params = before_params
            if "params" in body.model_fields_set:
                active_params = (
                    {}
                    if body.params is None
                    else {**before_params, **body.params.model_dump(exclude_unset=True)}
                )
                _reject_normalization_change(before_params, active_params, f"site:{code}")
                try:
                    SiteParams(**active_params)
                except ValueError as exc:
                    raise HTTPException(422, detail=str(exc)) from exc
            kwargs = {
                key: value
                for key, value in (("name", body.name), ("location", body.location))
                if value is not None
            }
            row = await ctx.site_rows(tx).update(
                current.id, expected_revision=current.revision, now=now, **kwargs
            )
            await _write_site_params(ctx, tx, row, active_params)
            await tx.append_event(
                entity_type="site",
                entity_id=str(row.id),
                actor_id=user.id,
                action="site.update",
                now=now,
                before={"name": current.name, "location": current.location, "params": before_params},
                after={"name": row.name, "location": row.location, "params": active_params},
            )
            return await _legacy_site_result(ctx, tx, row, active_params)
    params: dict[str, Any] | None = None
    if "params" in body.model_fields_set:
        if body.params is None:
            # A null params clears every parameter, including the network default.
            _require_sources_write(user)
            params = {}
        else:
            # A field sent as null is cleared.
            supplied = body.params.model_dump(exclude_unset=True)
            if any(key in NETWORK_PARAMS for key in supplied):
                _require_sources_write(user)

            def merge(stored: dict) -> dict:
                merged = {**stored, **supplied}
                try:
                    SiteParams(**merged)
                except ValueError as exc:
                    raise HTTPException(422, detail=str(exc)) from exc
                return merged

            site = await store.update_site(code, name=body.name, location=body.location, change_params=merge)
            if site is None:
                raise HTTPException(404, detail=f"no such site: {code}")
            return _public(site)
    site = await store.update_site(code, name=body.name, location=body.location, params=params)
    if site is None:
        raise HTTPException(404, detail=f"no such site: {code}")
    return _public(site)


def _require_sources_write(user: Any) -> None:
    if "sources.write" not in permissions_for(user.role):
        raise HTTPException(403, detail="requires permission: sources.write")


@router.delete("/sites/{code}", dependencies=[Depends(require_permission("sites.write"))])
async def delete_site(request: Request, code: str, user: Any = Depends(current_user)) -> dict[str, Any]:
    """Delete the site and report what it released.

    The route never refuses. The groups of the site lose their site. The
    locations bound to the site become unbound. The devices placed at the site by
    hand lose that placement. All of them stay collectable and become unplaced.
    The graph keeps what the site published until the next run.
    """
    if await _inventory_active(request.app.state.store):
        ctx = context_for(request.app)
        async with ctx.repo.transaction() as tx:
            row = await _site_by_code(ctx, tx, code)
            locations = [loc for loc in await tx.list_locations() if loc.site == code]
            result = await inventory_sites.release_site(ctx, tx, row.id, actor_id=user.id, now=ctx.clock())
            devices = [await tx.get_device(device_id) for device_id in result.placements]
            return {
                "groups": [],
                "locations": [{"source": loc.source, "location_id": loc.location_id} for loc in locations],
                "devices": [d.graph_uid for d in devices if d is not None],
            }
    released = await request.app.state.store.delete_site(code)
    if released is None:
        raise HTTPException(404, detail=f"no such site: {code}")
    return {
        "groups": released.groups,
        "locations": [{"source": s, "location_id": i} for s, i in released.locations],
        "devices": released.devices,
    }


@router.get("/sites/{code}/devices", dependencies=[Depends(require_permission("graph.read"))])
async def site_devices(request: Request, code: str) -> dict[str, Any]:
    store = request.app.state.store
    if await store.get_site(code) is None:
        raise HTTPException(404, detail=f"no such site: {code}")
    # The list holds every device that the placement rule puts at the site.
    uids = sorted(uid for uid, (site, _origin) in (await _placements(store, request)).items() if site == code)
    return {"devices": await asyncio.to_thread(_device_details, request, uids)}


@router.get("/sites/devices", dependencies=[Depends(require_permission("graph.read"))])
async def all_devices(request: Request) -> dict[str, Any]:
    """Every collected device with its uid and where it sits.

    `site` comes from the rule in resolve_device_sites. `graph_site` is the site
    that the last run published.
    """
    store = request.app.state.store
    locations = await store.list_reported_locations()
    # An id such as "default" or "1" repeats across orchestrators.
    names = {(loc.source, loc.location_id): loc.name for loc in locations}
    mappings = await store.target_devices()
    source_of = {m.device_uid: (m.source, m.location_id) for m in mappings}
    rows_by_name = {row.name: row for row in await store.list_sources()}
    resolved = await _placements(store, request)
    rows = await asyncio.to_thread(_collected_devices, request)
    devices = []
    active_inventory = await _inventory_active(store)
    for r in rows:
        source, location_id = source_of.get(r["uid"], ("", ""))
        site, origin = resolved.get(r["uid"], (None, ""))
        row = rows_by_name.get(source)
        devices.append(
            {
                **r,
                "site": site,
                "hand_placed": origin == "hand",
                # Only a controller device that a collection has seen can be placed by hand.
                "can_place": active_inventory or (row is not None and not glue.is_group(row.type)),
                "source": source,
                "location_id": location_id,
                "location_name": names.get((source, location_id), ""),
            }
        )
    return {"devices": devices}


@router.get("/locations", dependencies=[Depends(require_permission("graph.read"))])
async def list_locations(request: Request) -> dict[str, Any]:
    """Every place an orchestrator named, and the site it is bound to.

    A location with no site is unplaced. Its devices have no LOCATED_IN edge
    until an operator binds the location or places each device by hand.
    """
    if await _inventory_active(request.app.state.store):
        ctx = context_for(request.app)
        async with ctx.repo.transaction() as tx:
            rows = await tx.list_locations()
            counts = await ctx.aux(tx).location_device_counts()
            return {
                "locations": [
                    {
                        "source": loc.source,
                        "location_id": loc.location_id,
                        "name": loc.name,
                        "site": loc.site,
                        "device_count": counts.get(loc.handle, 0),
                    }
                    for loc in rows
                ]
            }
    rows = await request.app.state.store.list_reported_locations()
    return {
        "locations": [
            {
                "source": loc.source,
                "location_id": loc.location_id,
                "name": loc.name,
                "site": loc.site,
                "device_count": loc.device_count,
            }
            for loc in rows
        ]
    }


@router.patch(
    "/locations/{source}/{location_id:path}",
    dependencies=[Depends(require_permission("sites.write"))],
)
async def bind_location(
    request: Request, source: str, location_id: str, body: BindBody, user: Any = Depends(current_user)
) -> dict[str, Any]:
    """Bind one reported location to a site, or clear it with a null site."""
    store = request.app.state.store
    if await _inventory_active(store):
        ctx = context_for(request.app)
        now = ctx.clock()
        async with ctx.repo.transaction() as tx:
            loc = next(
                (loc for loc in await tx.list_locations(source) if loc.location_id == location_id), None
            )
            if loc is None:
                raise NotFound(f"no location {location_id!r} on {source!r}")
            if body.site is not None:
                await _site_by_code(ctx, tx, body.site)
            changed = await tx.bind_location(loc.handle, body.site, expected_revision=loc.revision, now=now)
            moved = await ReadModel(ctx).devices_at_locations(tx, [loc.handle])
            await ReadModel(ctx).refresh(tx, moved, now, collection=False)
            await tx.append_event(
                entity_type="location",
                entity_id=str(loc.handle),
                actor_id=user.id,
                action="location.bind",
                now=now,
                before={"site": loc.site, "revision": loc.revision},
                after={"site": changed.site, "revision": changed.revision},
            )
        return {
            "source": source,
            "location_id": location_id,
            "site": body.site,
            "detail": "the binding appears in the graph at the next collection run",
        }
    try:
        found = await store.bind_location(source, location_id, body.site)
    except ValueError as exc:
        raise HTTPException(404, detail=str(exc)) from exc
    if not found:
        raise HTTPException(404, detail=f"no location {location_id!r} on {source!r}")
    return {
        "source": source,
        "location_id": location_id,
        "site": body.site,
        "detail": "the binding appears in the graph at the next collection run",
    }


def _collected_devices(request: Request) -> list[dict[str, Any]]:
    from hst.core import snapshot as snapshotmod

    settings = request.app.state.settings
    with dbmod.session(settings) as s:
        cts = snapshotmod.resolve(s, settings).cts
        snap = snapshotmod.snap_param(cts)
        return s.execute_read(
            lambda tx: [
                r.data()
                for r in tx.run(
                    "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap AND NOT d:Retired "
                    "OPTIONAL MATCH (d)-[:LOCATED_IN]->(site:Site) "
                    "RETURN d.uid AS uid, d.hostname AS hostname, d.platform AS platform, "
                    "       site.code AS graph_site ORDER BY d.hostname",
                    snap=snap,
                )
            ]
        )


@router.post("/sites/assign", dependencies=[Depends(require_permission("sites.write"))])
async def assign(request: Request, body: AssignBody, user: Any = Depends(current_user)) -> dict[str, Any]:
    """Place one controller device by hand. Postgres only.

    The placement overrules what the controller reports for the device.

    The route refuses a group device and a device that no collection has seen.

    Every run re-applies every placement onto the run it is building.
    """
    store = request.app.state.store
    if await _inventory_active(store):
        ctx = context_for(request.app)
        now = ctx.clock()
        async with ctx.repo.transaction() as tx:
            device = await tx.get_device_by_graph_uid(body.device_uid)
            if device is None:
                raise NotFound(f"no collected device {body.device_uid}")
            site = await _site_by_code(ctx, tx, body.site) if body.site is not None else None
            before = await tx.get_placement(device.id)
            changed = await tx.set_placement(
                device.id,
                mode=PlacementMode.ASSIGNED if site else PlacementMode.AUTO,
                site_id=site.id if site else None,
                origin="manual",
                expected_revision=before.revision if before else 0,
                actor_id=user.id,
                now=now,
            )
            await ReadModel(ctx).refresh(tx, [device.id], now, collection=False)
            await tx.append_event(
                entity_type="device",
                entity_id=str(device.id),
                actor_id=user.id,
                action="placement.set",
                now=now,
                before=inventory_events.placement_payload(before),
                after=inventory_events.placement_payload(changed),
            )
        return {
            "device_uid": body.device_uid,
            "site": body.site,
            "detail": "the placement appears in the graph at the next collection run",
        }
    mapping = next(
        (m for m in await store.target_devices() if m.device_uid == body.device_uid),
        None,
    )
    if mapping is None:
        raise HTTPException(404, detail=f"no collected device {body.device_uid}")
    row = await store.get_source(mapping.source)
    if row is not None and glue.is_group(row.type):
        raise HTTPException(
            409,
            detail=(
                f"{body.device_uid} is collected by the group {mapping.source}, which sits at one "
                "site; move the group, or put this device in its own group"
            ),
        )
    try:
        await store.assign_device(body.device_uid, body.site)
    except ValueError as exc:
        raise HTTPException(404, detail=str(exc)) from exc
    return {
        "device_uid": body.device_uid,
        "site": body.site,
        "detail": "the placement appears in the graph at the next collection run",
    }


def _device_details(request: Request, uids: list[str]) -> list[dict[str, Any]]:
    """The hostnames of a set of device uids."""
    if not uids:
        return []
    from hst.core import snapshot as snapshotmod

    settings = request.app.state.settings
    with dbmod.session(settings) as s:
        return device_details(s, snapshotmod.resolve(s, settings), uids)


def device_details(session: Any, snapshot: Snapshot, uids: list[str]) -> list[dict[str, Any]]:
    """Hostname and platform of each device uid in the run `snapshot` names, in
    the order of `uids`."""
    if not uids:
        return []

    snap = snapshotmod.snap_param(snapshot.cts)
    rows = session.execute_read(
        lambda tx: [
            r.data()
            for r in tx.run(
                "MATCH (d:Device:Obj) WHERE d.uid IN $uids AND d.collection_ts = $snap "
                "RETURN d.uid AS uid, d.hostname AS hostname, d.platform AS platform",
                uids=uids,
                snap=snap,
            )
        ]
    )
    found = {r["uid"]: r for r in rows}
    return [found.get(u, {"uid": u, "hostname": None, "platform": None}) for u in uids]


# --- reachability between locations -------------------------------------------


class SiteTraceBody(BaseModel):
    src_site: str
    dst_site: str
    port: int | None = None
    proto: str = "tcp"


@router.post("/sites/trace", dependencies=[Depends(require_permission("graph.read"))])
async def trace_sites(request: Request, body: SiteTraceBody) -> dict[str, Any]:
    """Report whether site A reaches site B, and by which paths.

    Every prefix pair up to MAX_PAIRS is traced. All traces read one run.
    """
    store = request.app.state.store
    for code in (body.src_site, body.dst_site):
        if await store.get_site(code) is None:
            raise HTTPException(404, detail=f"no such site: {code}")

    snap, src_prefixes, dst_prefixes = await asyncio.to_thread(
        _site_prefix_pair, request, body.src_site, body.dst_site
    )
    if not src_prefixes or not dst_prefixes:
        empty = body.src_site if not src_prefixes else body.dst_site
        return {
            "src_site": body.src_site,
            "dst_site": body.dst_site,
            "snapshot": snap.cts,
            "pairs": [],
            "truncated": False,
            "note": f"no prefixes found behind {empty}",
        }

    pairs = [(a, b) for a in src_prefixes for b in dst_prefixes]
    truncated = len(pairs) > MAX_PAIRS
    both = {p.cidr for p in src_prefixes} & {p.cidr for p in dst_prefixes}
    present = await asyncio.to_thread(_run_present, request, snap)
    async with aleased(request, [snap.cts]):
        results = await asyncio.to_thread(
            _trace_pairs, request, pairs[:MAX_PAIRS], body.port, body.proto, snap, both, present
        )
    return {
        "src_site": body.src_site,
        "dst_site": body.dst_site,
        "snapshot": snap.cts,
        "pairs": results,
        "truncated": truncated,
        "total_pairs": len(pairs),
    }


def _run_present(request: Request, snap: Snapshot | None) -> bool:
    """Whether the `:CycleRun` node of the run of `snap` exists. The route reads
    it before it takes the lease."""
    cts = getattr(snap, "cts", None)
    if cts is None:
        return False
    with dbmod.session(request.app.state.settings) as s:
        return cyclemod.run_present(s, cts)


def _refuse_pruned(session: Any, snap: Snapshot | None, present: bool) -> None:
    """Fail with a 409 when the run node that existed before the lease is gone.
    A prune deletes the `:CycleRun` node of a run before its objects."""
    cts = getattr(snap, "cts", None)
    if present and cts is not None and not cyclemod.run_present(session, cts):
        raise HTTPException(409, detail=f"run {cts} was pruned while it was read")


def _trace_pairs(
    request: Request,
    pairs: list[tuple[SitePrefix, SitePrefix]],
    port: int | None,
    proto: str,
    snap: Snapshot,
    both: set[str],
    present: bool = False,
) -> list[dict[str, Any]]:
    """One answer per pair, with every trace pinned to `snap`. A pair with a
    prefix that both sites hold is not traced. Its answer is `not-established`
    with the missing code `prefix-at-both-sites`. `present` is `_run_present` from
    before the lease. The run is checked against it before the first trace and
    after the last one."""
    from hst import path as path_engine
    from hst.core import ribsource

    results: list[dict[str, Any]] = []
    settings = request.app.state.settings
    with dbmod.session(settings) as raw:
        _refuse_pruned(raw, snap, present)
        # The traces and the RIB bound are pinned to the snapshot of the prefixes.
        session = path_engine.pinned(raw, snap)
        rib = ribsource.for_snapshot(snap)
        gateways = path_engine.load_gateways(session)
        for src, dst in pairs:
            if src.cidr in both or dst.cidr in both:
                shared = src.cidr if src.cidr in both else dst.cidr
                detail = f"{shared} is held at both sites; the pair is not traced"
                missing = [Missing(code="prefix-at-both-sites", subject=shared, detail=detail)]
                results.append(
                    {
                        "src": src.cidr,
                        "dst": dst.cidr,
                        "src_context": src.context,
                        "dst_context": dst.context,
                        "result": from_engine(
                            "trace-forwards", "not-established", missing=missing
                        ).model_dump(mode="json"),
                        "detail": detail,
                        "blocked": None,
                    }
                )
                continue
            traced = path_engine.trace(
                session,
                src.cidr,
                dst.cidr,
                port=port,
                proto=proto,
                gateways=gateways,
                rib=rib,
                src_context=src.context,
                dst_context=dst.context,
            )
            project_trace(traced)
            # `blocked` comes from the projected answer. A trace with no legs, a
            # no-route leg or an undecided leg has `blocked` False or None in its
            # legs. A pair that the tracer could not forward must not count as open.
            answer = (traced.get("result") or {}).get("answer")
            blocked = {"false": True, "true": False}.get(str(answer))
            results.append(
                {
                    "src": src.cidr,
                    "dst": dst.cidr,
                    "src_context": src.context,
                    "dst_context": dst.context,
                    "result": traced.get("result"),
                    "detail": traced.get("detail"),
                    "blocked": blocked,
                }
            )
        _refuse_pruned(raw, snap, present)
    return results


class SitePrefix(NamedTuple):
    """A connected prefix of a site with its cidr, its node uid and its addressing
    context. The context is the anchor that the tracer compares, as `_anchor_of`
    reads it."""

    cidr: str
    uid: str | None
    context: str | None


def _site_prefix_pair(
    request: Request, src_code: str, dst_code: str
) -> tuple[Snapshot, list[SitePrefix], list[SitePrefix]]:
    """The prefixes of two sites from one resolution of the pointer, and that run."""
    settings = request.app.state.settings
    with dbmod.session(settings) as s:
        snapshot = snapshotmod.resolve(s, settings)
        return snapshot, site_prefix_rows(s, snapshot, src_code), site_prefix_rows(s, snapshot, dst_code)


def site_prefixes(session: Any, snapshot: Snapshot, code: str) -> list[str]:
    """Connected prefixes of the devices located at site `code` in the run
    `snapshot` names, in prefix order."""
    return sorted({p.cidr for p in site_prefix_rows(session, snapshot, code)})


def site_prefix_rows(session: Any, snapshot: Snapshot, code: str) -> list[SitePrefix]:
    """The connected prefixes of the devices located at site `code` in the run
    `snapshot` names, one per prefix node, in cidr order. Two nodes of one cidr
    in two contexts are two prefixes."""

    snap = snapshotmod.snap_param(snapshot.cts)
    rows = session.execute_read(
        lambda tx: [
            r.data()
            for r in tx.run(
                "MATCH (d:Device:Obj)-[:LOCATED_IN]->(:Site {uid: $site}) "
                "WHERE d.collection_ts = $snap "
                "MATCH (i:Interface)-[:ON]->(d) "
                "MATCH (i)-[h:HAS_IP]->(ip:IpAddress)-[:IN]->(p:Prefix) "
                "WHERE NOT d:Retired AND NOT i:Retired AND NOT p:Retired "
                "  AND h._retired_at IS NULL AND p.kind = 'connected' "
                "RETURN DISTINCT p.cidr AS cidr, p.uid AS uid, coalesce(p.anchor, p.l3dom) AS context "
                "ORDER BY cidr, uid",
                # Every collector builds a Site uid through uid.site().
                site=uidmod.site(code),
                snap=snap,
            )
        ]
    )
    return [SitePrefix(r["cidr"], r.get("uid"), r.get("context")) for r in rows if r["cidr"]]
