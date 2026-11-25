"""Observations, publication and the inventory read model."""

from __future__ import annotations

import builtins
import logging
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from hst.app.inventory import placement as placementmod
from hst.app.inventory import tables as t
from hst.app.inventory.contracts import (
    Authority,
    CollectionState,
    Lifecycle,
    ObservationState,
    OutboxKind,
    OutboxState,
    PlacementMode,
    PlacementOrigin,
    PublicationState,
    SortField,
    redact_by_key,
)
from hst.app.inventory.repository import (
    Conflict,
    InventoryError,
    InventoryRepository,
    InventoryTx,
    NotFound,
    StaleRevision,
)
from hst.app.store import (
    UNSET,
    DeviceFilters,
    DeviceStatus,
    InventoryDevice,
    InventoryLocation,
    InventoryObservation,
    InventoryPlacement,
    InventoryPublication,
    InventoryTarget,
    PublicationApplyReport,
    SourceInventory,
    StagedObservation,
    StagedTarget,
    Store,
)
from hst.app.store.pg import sites
from hst.core import uid as uidmod
from hst.core.model import Batch, section_verdict

log = logging.getLogger("hst.inventory")

CONTEXT_UID_PREFIX = "firewall-instance:"
# The stale threshold is 3 intervals and at least 300 s.
STALE_FLOOR_S = 300
OUTBOX_LEASE = timedelta(minutes=5)
OUTBOX_RETRY = timedelta(seconds=30)
RECONCILE_MAX_ATTEMPTS = 20
# The origin stamped on the `auto` row a publication materializes for a device
# without one (ObservationService._ensure_placement_rows).
MATERIALIZED_ORIGIN = PlacementOrigin.MANUAL


def utcnow() -> datetime:
    return datetime.now(UTC)


def outbox_key(snapshot_key: str) -> str:
    return f"publication:{snapshot_key}"


# --- observed devices -----------------------------------------------------------------


@dataclass(frozen=True)
class ObservedDevice:
    """What one target reports about one graph device in one run."""

    graph_uid: str
    hostname: str = ""
    platform: str = ""
    management_address: str = ""
    # (location id, display name) as the collector reported it, or None.
    reported_location: tuple[str, str] | None = None
    warnings: tuple[str, ...] = ()

    def notes(self) -> dict[str, Any] | None:
        if not self.warnings:
            return None
        return {"warnings": [str(w) for w in self.warnings]}


def is_inventory_device_uid(uid: str) -> bool:
    """Return True for the uid of an inventory device.

    A context has the label Device too. The uid of a context has the prefix
    `firewall-instance:`."""
    return bool(uid) and not uid.startswith(CONTEXT_UID_PREFIX)


def observed_devices_from_batch(batch: Batch) -> list[ObservedDevice]:
    """Return the inventory devices of a normalized batch.

    Each device has its reported location and the batch warnings that hold its hostname or
    its uid."""
    from hst.collectors.base import REPORTED_LOCATION_NAME_PROP, REPORTED_LOCATION_PROP

    out: list[ObservedDevice] = []
    for node in batch.nodes:
        if node.label != "Device" or not is_inventory_device_uid(node.uid):
            continue
        props = node.props
        location = None
        if props.get(REPORTED_LOCATION_PROP):
            loc_id = str(props[REPORTED_LOCATION_PROP])
            location = (loc_id, str(props.get(REPORTED_LOCATION_NAME_PROP) or loc_id))
        hostname = str(props.get("hostname") or props.get("name") or "")
        warnings = tuple(w for w in batch.warnings if (hostname and hostname in w) or node.uid in w)
        out.append(
            ObservedDevice(
                graph_uid=node.uid,
                hostname=hostname,
                platform=str(props.get("platform") or ""),
                management_address=str(props.get("mgmt_ip") or props.get("management_address") or ""),
                reported_location=location,
                warnings=warnings,
            )
        )
    return sorted(out, key=lambda d: d.graph_uid)


def authority_of(batch: Batch, authoritative: Iterable[str] = ()) -> tuple[Authority, bool]:
    """Return (authority, succeeded).

    A batch without sections is complete. A degrading status on an authoritative section gives
    (partial, False)."""
    if not batch.sections:
        return Authority.COMPLETE, True
    verdict = section_verdict(batch.sections, authoritative)
    if verdict == "failed":
        return Authority.PARTIAL, False
    return (Authority.PARTIAL if verdict == "partial" else Authority.COMPLETE), True


def coerce_authority(value: Authority | str) -> tuple[Authority, bool]:
    """Accept the repository vocabulary and the collector verdict vocabulary."""
    if isinstance(value, Authority):
        return value, True
    text = str(value).lower()
    if text in ("complete", "ok"):
        return Authority.COMPLETE, True
    if text == "partial":
        return Authority.PARTIAL, True
    if text == "failed":
        return Authority.PARTIAL, False
    raise InventoryError(f"unknown authority {value!r}")


# --- site rows and auxiliary reads ------------------------------------------------------


@dataclass(frozen=True)
class SiteRow:
    id: int
    code: str
    name: str
    location: str
    revision: int
    # `params.lat` and `params.lon`, the site's point on the site map
    lat: float | None = None
    lon: float | None = None
    # `params.site_group` and `params.blocks`, as stored
    site_group: str | None = None
    blocks: list[dict[str, Any]] | None = None


class SiteRows(Protocol):
    """The rows of the `sites` table, read and written inside an inventory transaction."""

    async def list(self) -> list[SiteRow]: ...
    async def create(
        self, code: str, name: str, location: str, *, now: datetime, point: tuple[float, float] | None = None
    ) -> SiteRow: ...
    async def update(
        self,
        site_id: int,
        *,
        expected_revision: int,
        now: datetime,
        name: str | object = UNSET,
        location: str | object = UNSET,
        point: tuple[float, float] | object | None = UNSET,
        site_group: str | object | None = UNSET,
        blocks: builtins.list[dict[str, Any]] | object | None = UNSET,
    ) -> SiteRow: ...
    async def delete(self, site_id: int) -> None: ...
    async def device_counts(self) -> dict[int, int]: ...


class AuxReader(Protocol):
    """The reads that `InventoryTx` does not have.

    They are the publications in one state, the staged rows of one snapshot and the device
    count of each reported location."""

    async def list_publications(self, state: PublicationState) -> list[InventoryPublication]: ...
    async def staged_rows(self, snapshot_key: str) -> tuple[list[StagedTarget], list[StagedObservation]]: ...
    async def location_device_counts(self) -> dict[uuid.UUID, int]: ...


class PgSiteRows:
    def __init__(self, conn: AsyncConnection) -> None:
        self._c = conn

    _cols = (sites.c.id, sites.c.code, sites.c.name, sites.c.location, sites.c.revision, sites.c.params)

    @staticmethod
    def _row(r: sa.Row) -> SiteRow:
        params = r.params or {}
        lat, lon = params.get("lat"), params.get("lon")
        layout = {"site_group": params.get("site_group"), "blocks": params.get("blocks")}
        if lat is None or lon is None:
            return SiteRow(r.id, r.code, r.name, r.location, r.revision, **layout)
        return SiteRow(r.id, r.code, r.name, r.location, r.revision, float(lat), float(lon), **layout)

    async def list(self) -> list[SiteRow]:
        rows = (await self._c.execute(sa.select(*self._cols).order_by(sites.c.code))).all()
        return [self._row(r) for r in rows]

    async def create(
        self, code: str, name: str, location: str, *, now: datetime, point: tuple[float, float] | None = None
    ) -> SiteRow:
        params = {"lat": point[0], "lon": point[1]} if point else {}
        known = (await self._c.execute(sa.select(sites.c.code))).scalars().all()
        if clash := uidmod.site_fold(code, known):
            raise Conflict(f"site code {code!r} folds onto {clash!r}: both are the site {uidmod.site(code)}")
        try:
            async with self._c.begin_nested():
                row = (
                    await self._c.execute(
                        sites.insert()
                        .values(
                            code=code,
                            name=name,
                            location=location,
                            params=params,
                            created_at=now,
                            updated_at=now,
                        )
                        .returning(*self._cols)
                    )
                ).one()
        except IntegrityError as exc:
            raise Conflict(f"site code {code!r} is in use") from exc
        return self._row(row)

    async def update(
        self,
        site_id: int,
        *,
        expected_revision: int,
        now: datetime,
        name: str | object = UNSET,
        location: str | object = UNSET,
        point: tuple[float, float] | object | None = UNSET,
        site_group: str | object | None = UNSET,
        blocks: builtins.list[dict[str, Any]] | object | None = UNSET,
    ) -> SiteRow:
        current = (await self._c.execute(sa.select(*self._cols).where(sites.c.id == site_id))).first()
        if current is None:
            raise NotFound("site not found")
        if current.revision != expected_revision:
            raise StaleRevision(
                f"site is at revision {current.revision}, not {expected_revision}",
                current_revision=current.revision,
            )
        values: dict[str, Any] = {"revision": current.revision + 1, "updated_at": now}
        if name is not UNSET:
            values["name"] = name
        if location is not UNSET:
            values["location"] = location
        # The update keeps the params that it does not name.
        params = dict(current.params or {})
        if point is not UNSET:
            params = {k: v for k, v in params.items() if k not in ("lat", "lon")}
            if isinstance(point, tuple):
                params.update(lat=point[0], lon=point[1])
        # a cleared site group or block list is stored as null
        if site_group is not UNSET:
            params["site_group"] = site_group
        if blocks is not UNSET:
            params["blocks"] = blocks
        if any(arg is not UNSET for arg in (point, site_group, blocks)):
            values["params"] = params
        row = (
            await self._c.execute(
                sites.update()
                .where(sites.c.id == site_id, sites.c.revision == expected_revision)
                .values(**values)
                .returning(*self._cols)
            )
        ).one_or_none()
        if row is None:
            # The revision predicate above is the compare-and-swap.
            revision = (
                await self._c.execute(sa.select(sites.c.revision).where(sites.c.id == site_id))
            ).scalar_one_or_none()
            if revision is None:
                raise NotFound("site not found")
            raise StaleRevision(
                f"site is at revision {revision}, not {expected_revision}", current_revision=revision
            )
        return self._row(row)

    async def delete(self, site_id: int) -> None:
        await self._c.execute(sites.delete().where(sites.c.id == site_id))

    async def device_counts(self) -> dict[int, int]:
        d = t.inventory_devices.c
        rows = (
            await self._c.execute(
                sa.select(d.resolved_site_id, sa.func.count())
                .where(d.resolved_site_id.is_not(None), d.lifecycle != Lifecycle.ARCHIVED.value)
                .group_by(d.resolved_site_id)
            )
        ).all()
        return {int(r[0]): int(r[1]) for r in rows}


class PgAuxReader:
    def __init__(self, conn: AsyncConnection) -> None:
        self._c = conn

    async def list_publications(self, state: PublicationState) -> list[InventoryPublication]:
        p = t.inventory_publications
        rows = (
            await self._c.execute(
                p.select().where(p.c.state == state.value).order_by(p.c.created_at, p.c.snapshot_key)
            )
        ).all()
        return [
            InventoryPublication(
                r.snapshot_key,
                r.parent_snapshot_key,
                r.state,
                r.intent_generation,
                r.staged_changes or {},
                r.placement_revisions or {},
                r.created_at,
                r.published_at,
                r.applied_at,
            )
            for r in rows
        ]

    async def staged_rows(self, snapshot_key: str) -> tuple[list[StagedTarget], list[StagedObservation]]:
        st, so = t.inventory_staged_targets, t.inventory_staged_observations
        targets = [
            StagedTarget(r.snapshot_key, r.target_id, r.authority, r.succeeded, r.attempted_at)
            for r in (await self._c.execute(st.select().where(st.c.snapshot_key == snapshot_key))).all()
        ]
        rows = [
            StagedObservation(
                r.target_id,
                r.graph_uid,
                r.hostname,
                r.platform,
                r.management_address,
                r.reported_location_handle,
                r.notes,
            )
            for r in (
                await self._c.execute(
                    so.select()
                    .where(so.c.snapshot_key == snapshot_key)
                    .order_by(so.c.target_id, so.c.graph_uid)
                )
            ).all()
        ]
        return targets, rows

    async def location_device_counts(self) -> dict[uuid.UUID, int]:
        """Return the count of devices of each reported location, from the observations that
        are not absent."""
        o = t.inventory_observations.c
        rows = (
            await self._c.execute(
                sa.select(o.reported_location_handle, sa.func.count(sa.distinct(o.device_id)))
                .where(o.reported_location_handle.is_not(None), o.state != ObservationState.ABSENT.value)
                .group_by(o.reported_location_handle)
            )
        ).all()
        return {r[0]: int(r[1]) for r in rows}


SiteRowsFactory = Callable[[InventoryTx], SiteRows]
AuxReaderFactory = Callable[[InventoryTx], AuxReader]


def _conn(tx: InventoryTx) -> AsyncConnection:
    if tx.connection is None:
        raise RuntimeError("this read needs the transaction's database connection")
    return tx.connection


def pg_site_rows(tx: InventoryTx) -> SiteRows:
    return PgSiteRows(_conn(tx))


def pg_aux_reader(tx: InventoryTx) -> AuxReader:
    return PgAuxReader(_conn(tx))


# The staging path registers a reported location that is not registered yet.
LocationEnsurer = Callable[[InventoryTx, str, str, str, datetime], Any]


async def pg_ensure_location(
    tx: InventoryTx, source_key: str, location_id: str, name: str, now: datetime
) -> uuid.UUID:
    from sqlalchemy.dialects.postgresql import insert

    from hst.app.store.pg import reported_locations

    stmt = (
        insert(reported_locations)
        .values(source=source_key, location_id=location_id, name=name, site=None, updated_at=now)
        .on_conflict_do_update(
            index_elements=["source", "location_id"],
            set_={"name": sa.func.coalesce(sa.func.nullif(sa.literal(name), ""), reported_locations.c.name)},
        )
        .returning(reported_locations.c.handle)
    )
    return (await _conn(tx).execute(stmt)).scalar_one()


# --- graph reads -----------------------------------------------------------------------


@dataclass(frozen=True)
class RelatedEntityRow:
    uid: str
    label: str
    relation: str
    name: str


class GraphReader(Protocol):
    """The batched graph read of a device detail.

    It returns the relationships that the collectors wrote for a set of devices at the
    read-model snapshot."""

    def related(
        self, device_uids: Sequence[str], snapshot_key: str | None
    ) -> dict[str, list[RelatedEntityRow]]: ...


class Neo4jGraphReader:
    """RUNS_ON contexts and MEMBER_OF groups of the devices, read from the
    published snapshot the read model is at."""

    def __init__(self, settings: Any) -> None:
        self._settings = settings

    def related(
        self, device_uids: Sequence[str], snapshot_key: str | None
    ) -> dict[str, list[RelatedEntityRow]]:
        from hst.core import db as dbmod
        from hst.path import LIVE_SNAP

        if not device_uids:
            return {}
        from hst.core.labels import RESERVED_LABELS

        snap = int(snapshot_key) if snapshot_key and snapshot_key.isdigit() else LIVE_SNAP
        # The domain label is the label outside the reserved set.
        query = (
            "MATCH (d:Device:Obj) WHERE d.uid IN $uids AND d.collection_ts = $snap "
            "OPTIONAL MATCH (c)-[:RUNS_ON]->(d) WHERE c.collection_ts = $snap "
            "OPTIONAL MATCH (d)-[:MEMBER_OF]->(g) WHERE g.collection_ts = $snap "
            "RETURN d.uid AS uid, "
            "collect(DISTINCT {uid: c.uid, label: head([l IN labels(c) WHERE NOT l IN $reserved]), "
            "relation: 'RUNS_ON', name: coalesce(c.name, '')}) AS contexts, "
            "collect(DISTINCT {uid: g.uid, label: head([l IN labels(g) WHERE NOT l IN $reserved]), "
            "relation: 'MEMBER_OF', name: coalesce(g.name, '')}) AS groups"
        )
        reserved = sorted(RESERVED_LABELS)
        with dbmod.session(self._settings) as s:
            rows = s.execute_read(
                lambda tx: [
                    r.data() for r in tx.run(query, uids=list(device_uids), snap=snap, reserved=reserved)
                ]
            )
        out: dict[str, list[RelatedEntityRow]] = {}
        for r in rows:
            items = [
                RelatedEntityRow(
                    str(e["uid"]), str(e["label"] or ""), str(e["relation"]), str(e["name"] or "")
                )
                for e in [*r["contexts"], *r["groups"]]
                if e.get("uid")
            ]
            out[r["uid"]] = sorted(items, key=lambda e: (e.relation, e.uid))
        return out


# --- collection state ------------------------------------------------------------------


@dataclass(frozen=True)
class TargetEvidence:
    """One target's last attempt, for the collection state of a device."""

    attempted: bool
    ok: bool
    last_success_at: datetime | None
    # The seconds after the last success at which the evidence is stale. None means manual
    # collection without a deadline.
    stale_after_s: float | None


def stale_threshold(interval_s: int, cycle_interval_s: int) -> float | None:
    """Return the stale threshold in seconds.

    A target with an interval has max(3 * interval, 300 s). A target without an interval has
    max(3 * cycle interval, 300 s) when the cycle interval is above 0, and None otherwise."""
    if interval_s > 0:
        return float(max(3 * interval_s, STALE_FLOOR_S))
    if cycle_interval_s > 0:
        return float(max(3 * cycle_interval_s, STALE_FLOOR_S))
    return None


def collection_state(evidence: Sequence[TargetEvidence], now: datetime) -> CollectionState:
    attempted = [e for e in evidence if e.attempted]
    if not attempted:
        return CollectionState.NEVER
    ok = [e for e in attempted if e.ok]
    if not ok:
        return CollectionState.FAILED
    if len(ok) < len(attempted):
        return CollectionState.PARTIAL
    for e in ok:
        if e.stale_after_s is None or e.last_success_at is None:
            continue
        if (now - e.last_success_at).total_seconds() > e.stale_after_s:
            return CollectionState.STALE
    if all(e.stale_after_s is None for e in ok):
        return CollectionState.MANUAL
    return CollectionState.CURRENT


def target_evidence(status: DeviceStatus | None, stale_after_s: float | None) -> TargetEvidence:
    if status is None or status.last_attempt_at is None:
        return TargetEvidence(False, False, None, stale_after_s)
    ok = status.consecutive_failures == 0 and status.last_success_at is not None
    return TargetEvidence(True, ok, status.last_success_at, stale_after_s)


# --- context ---------------------------------------------------------------------------


@dataclass
class InventoryContext:
    """The store, the settings, the site-row accessor, the auxiliary reader, the location
    registrar, the graph reader and the clock of the services and the routes. Tests replace
    the last 5."""

    store: Store
    settings: Any
    site_rows: SiteRowsFactory = pg_site_rows
    aux: AuxReaderFactory = pg_aux_reader
    ensure_location: LocationEnsurer = pg_ensure_location
    graph: GraphReader | None = None
    clock: Callable[[], datetime] = utcnow

    @property
    def repo(self) -> InventoryRepository:
        return self.store.inventory()

    def graph_reader(self) -> GraphReader:
        if self.graph is None:
            self.graph = Neo4jGraphReader(self.settings)
        return self.graph

    @property
    def cycle_interval_s(self) -> int:
        return int(getattr(self.settings, "collect_interval_s", 0) or 0)


def context_for(app: Any) -> InventoryContext:
    """The app's inventory context, built once from app.state. A test sets
    `app.state.inventory_context` before the first request."""
    ctx = getattr(app.state, "inventory_context", None)
    if ctx is None:
        ctx = InventoryContext(app.state.store, app.state.settings)
        app.state.inventory_context = ctx
    return ctx


# --- read model -------------------------------------------------------------------------


@dataclass
class DeviceClaims:
    """Everything the resolver and the detail need about one device's
    observations."""

    device: InventoryDevice
    placement: InventoryPlacement | None
    observations: list[InventoryObservation]
    targets: Mapping[uuid.UUID, InventoryTarget]
    locations: Mapping[uuid.UUID, InventoryLocation]
    site_ids: Mapping[str, int]

    def claims(self) -> list[placementmod.Claim]:
        return [
            claim_of(obs, self.targets.get(obs.target_id), self.locations, self.site_ids)
            for obs in self.observations
        ]

    def intent(self) -> placementmod.Intent | None:
        return intent_of(self.placement)

    def resolve(self) -> placementmod.Resolved:
        return placementmod.resolve(self.intent(), self.claims())


def intent_of(p: InventoryPlacement | None) -> placementmod.Intent | None:
    if p is None:
        return None
    return placementmod.Intent(
        mode=PlacementMode(p.mode),
        site_id=p.site_id,
        origin=PlacementOrigin(p.origin),
        revision=p.revision,
        applied_revision=p.applied_revision,
        published_site_id=p.published_site_id,
        published_snapshot_key=p.published_snapshot_key,
        actor_id=p.actor_id,
        updated_at=p.updated_at,
    )


def claim_of(
    obs: InventoryObservation,
    target: InventoryTarget | None,
    locations: Mapping[uuid.UUID, InventoryLocation],
    site_ids: Mapping[str, int],
    *,
    state: ObservationState | None = None,
    handle: uuid.UUID | object | None = UNSET,
) -> placementmod.Claim:
    location_handle = obs.reported_location_handle if handle is UNSET else handle
    loc = locations.get(location_handle) if isinstance(location_handle, uuid.UUID) else None
    return placementmod.Claim(
        target_id=obs.target_id,
        connection_id=str(target.source_id) if target and target.source_id is not None else "",
        state=state or ObservationState(obs.state),
        authority=Authority(obs.authority),
        location_handle=loc.handle if loc else None,
        location_name=loc.name if loc else "",
        site_id=site_ids.get(loc.site) if loc and loc.site else None,
    )


class ReadModel:
    """Maintains the indexed summary columns of `inventory_devices` from the
    resolver and the collection-state rule, and gathers a device's claims for
    the detail. Every method runs inside the caller's transaction."""

    def __init__(self, ctx: InventoryContext) -> None:
        self.ctx = ctx

    async def site_ids(self, tx: InventoryTx) -> dict[str, int]:
        return {s.code: s.id for s in await self.ctx.site_rows(tx).list()}

    async def gather(
        self,
        tx: InventoryTx,
        device: InventoryDevice,
        *,
        site_ids: Mapping[str, int] | None = None,
        locations: Mapping[uuid.UUID, InventoryLocation] | None = None,
        targets: Mapping[uuid.UUID, InventoryTarget] | None = None,
        placement: InventoryPlacement | object | None = UNSET,
    ) -> DeviceClaims:
        observations = await tx.get_observations(device.id)
        if targets is None:
            targets = {tg.id: tg for tg in await tx.get_targets([o.target_id for o in observations])}
        if locations is None:
            found: dict[uuid.UUID, InventoryLocation] = {}
            for obs in observations:
                if obs.reported_location_handle and obs.reported_location_handle not in found:
                    loc = await tx.get_location(obs.reported_location_handle)
                    if loc is not None:
                        found[loc.handle] = loc
            locations = found
        row = await tx.get_placement(device.id) if placement is UNSET else placement
        return DeviceClaims(
            device,
            row if isinstance(row, InventoryPlacement) else None,
            observations,
            targets,
            locations,
            site_ids if site_ids is not None else await self.site_ids(tx),
        )

    async def stale_after(
        self,
        tx: InventoryTx,
        target: InventoryTarget,
        *,
        sources: Mapping[str, SourceInventory],
        legacy_intervals: Mapping[str, int],
        cache: dict[uuid.UUID, float | None],
    ) -> float | None:
        """Return the stale threshold of a target.

        The interval is that of the profile of the target, else that of the default profile of
        its connection, else the `interval_s` of the source config."""
        if target.id in cache:
            return cache[target.id]
        interval = 0
        source = sources.get(target.source_key)
        profile_id = target.profile_id or (source.default_profile_id if source else None)
        if profile_id is not None:
            profile = await tx.get_profile(profile_id)
            version = (
                await tx.get_profile_version(profile_id, profile.current_revision)
                if profile is not None
                else None
            )
            if version is not None:
                try:
                    interval = int(version.settings.get("interval_s") or 0)
                except (TypeError, ValueError):
                    interval = 0
        else:
            interval = legacy_intervals.get(target.source_key, 0)
        cache[target.id] = stale_threshold(interval, self.ctx.cycle_interval_s)
        return cache[target.id]

    async def _legacy_intervals(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for row in await self.ctx.store.list_sources():
            try:
                out[row.name] = int(row.config.get("interval_s") or 0)
            except (TypeError, ValueError):
                out[row.name] = 0
        return out

    async def _statuses(self) -> dict[tuple[str, str], DeviceStatus]:
        return {(s.source, s.host): s for s in await self.ctx.store.list_device_status()}

    async def _evidence(
        self,
        tx: InventoryTx,
        observing: Iterable[InventoryTarget],
        *,
        statuses: Mapping[tuple[str, str], DeviceStatus],
        sources: Mapping[str, SourceInventory],
        legacy: Mapping[str, int],
        cache: dict[uuid.UUID, float | None],
    ) -> tuple[CollectionState, datetime | None]:
        evidence = []
        latest: datetime | None = None
        for target in observing:
            deadline = await self.stale_after(
                tx, target, sources=sources, legacy_intervals=legacy, cache=cache
            )
            status = statuses.get((target.source_key, target.host))
            evidence.append(target_evidence(status, deadline))
            if status and status.last_success_at and (latest is None or status.last_success_at > latest):
                latest = status.last_success_at
        return collection_state(evidence, self.ctx.clock()), latest

    async def refresh(
        self,
        tx: InventoryTx,
        device_ids: Iterable[uuid.UUID],
        now: datetime,
        *,
        placement: bool = True,
        collection: bool = True,
    ) -> dict[uuid.UUID, placementmod.Resolved]:
        """Recompute the summary columns of the given devices.

        The sites, locations, targets, placements and statuses are read once for the batch. The
        observations are read per device."""
        ids = list(dict.fromkeys(device_ids))
        if not ids:
            return {}
        site_ids = await self.site_ids(tx)
        locations = {loc.handle: loc for loc in await tx.list_locations()}
        targets = {tg.id: tg for tg in await tx.list_targets(include_archived=True)}
        placements = {p.device_id: p for p in await tx.get_placements(ids)}
        statuses = await self._statuses() if collection else {}
        sources = {s.name: s for s in await tx.list_source_inventory()} if collection else {}
        legacy = await self._legacy_intervals() if collection else {}
        cache: dict[uuid.UUID, float | None] = {}
        resolved: dict[uuid.UUID, placementmod.Resolved] = {}
        for device in await tx.get_devices(ids):
            claims = await self.gather(
                tx,
                device,
                site_ids=site_ids,
                locations=locations,
                targets=targets,
                placement=placements.get(device.id),
            )
            values: dict[str, Any] = {}
            if placement:
                r = claims.resolve()
                resolved[device.id] = r
                values["resolved_site_id"] = r.desired_site_id
                values["placement_state"] = r.summary_state.value
            if collection:
                observing = [
                    targets[o.target_id]
                    for o in claims.observations
                    if o.state != ObservationState.ABSENT.value and o.target_id in targets
                ]
                state, latest = await self._evidence(
                    tx, observing, statuses=statuses, sources=sources, legacy=legacy, cache=cache
                )
                values["collection_state"] = state.value
                values["last_success_at"] = latest
            await tx.set_device_summary(device.id, now=now, **values)
        return resolved

    async def refresh_all_collection_states(self, tx: InventoryTx, now: datetime) -> int:
        """Recompute the collection state of every device and apply 2 lifecycle rules.

        An active device without an observation that is not absent becomes missing. That is
        the state of a device whose targets were archived with their source. A missing device
        with an observation that is not absent becomes active. The lifecycle writes are
        collected during the walk and applied after it."""
        statuses = await self._statuses()
        sources = {s.name: s for s in await tx.list_source_inventory()}
        legacy = await self._legacy_intervals()
        cache: dict[uuid.UUID, float | None] = {}
        by_key = {(tg.source_key, tg.host): tg for tg in await tx.list_targets(include_archived=True)}
        filters = DeviceFilters(lifecycles=[m.value for m in Lifecycle])
        cursor = None
        touched = 0
        lifecycle_moves: list[tuple[InventoryDevice, Lifecycle]] = []
        while True:
            page = await tx.list_devices(filters, sort=SortField.NAME, limit=200, cursor=cursor)
            for item in page.items:
                observing = [
                    by_key[(c.source_key, c.host)]
                    for c in item.connections
                    if (c.source_key, c.host) in by_key
                ]
                state, latest = await self._evidence(
                    tx, observing, statuses=statuses, sources=sources, legacy=legacy, cache=cache
                )
                if state.value != item.device.collection_state or latest != item.device.last_success_at:
                    await tx.set_device_summary(
                        item.device.id, now=now, collection_state=state.value, last_success_at=latest
                    )
                    touched += 1
                if item.device.lifecycle == Lifecycle.ACTIVE.value and not item.connections:
                    lifecycle_moves.append((item.device, Lifecycle.MISSING))
                elif item.device.lifecycle == Lifecycle.MISSING.value and item.connections:
                    lifecycle_moves.append((item.device, Lifecycle.ACTIVE))
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        for device, lifecycle in lifecycle_moves:
            await tx.set_lifecycle(device.id, lifecycle, expected_revision=device.revision, now=now)
            await tx.append_event(
                entity_type="device",
                entity_id=str(device.id),
                actor_id=None,
                action="device.missing" if lifecycle == Lifecycle.MISSING else "device.reappeared",
                now=now,
                before={"lifecycle": device.lifecycle},
                after={"lifecycle": lifecycle.value},
            )
            touched += 1
        return touched

    async def devices_at_locations(self, tx: InventoryTx, handles: Iterable[uuid.UUID]) -> list[uuid.UUID]:
        """Return the devices whose observations report one of the locations."""
        wanted = set(handles)
        if not wanted:
            return []
        by_source: dict[str, set[uuid.UUID]] = {}
        for loc in await tx.list_locations():
            if loc.handle in wanted:
                by_source.setdefault(loc.source, set()).add(loc.handle)
        out: set[uuid.UUID] = set()
        targets = await tx.list_targets(include_archived=True)
        for source_key, handles_of_source in by_source.items():
            for target in targets:
                if target.source_key != source_key:
                    continue
                for obs in await tx.list_observations(target.id):
                    if obs.reported_location_handle in handles_of_source:
                        out.add(obs.device_id)
        return sorted(out, key=str)


# --- publication ----------------------------------------------------------------------------


@dataclass(frozen=True)
class StageResult:
    snapshot_key: str
    target_id: uuid.UUID
    staged: int
    authority: Authority
    succeeded: bool


@dataclass(frozen=True)
class PlacementInput:
    """The placements that the caller writes into the new snapshot.

    `site_assignments` maps a graph uid to a site code, and None clears the edge.
    `placement_revisions` holds the captured revisions."""

    snapshot_key: str
    intent_generation: int
    site_assignments: dict[str, str | None]
    placement_revisions: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class PublishOutcome:
    snapshot_key: str
    state: PublicationState
    applied: PublicationApplyReport | None
    sync_pending: bool
    detail: str = ""


@dataclass
class ReconcileReport:
    applied: list[str] = field(default_factory=list)
    aborted: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    outbox_done: int = 0
    collection_states_touched: int = 0
    sync_pending: bool = False


@dataclass
class _Folded:
    """The claims of every device after this run's staged rows are folded
    over the current observations, and the devices
    the run sees for the first time with their onboarding decision."""

    existing: dict[uuid.UUID, list[placementmod.Claim]]
    new_devices: dict[str, list[placementmod.Claim]]
    new_onboarding: dict[str, placementmod.OnboardingDefault]


class ObservationService:
    """The idempotent observation service.

    An app has one instance. Each method opens its own transaction. `stage_observations` runs
    in the transaction of the caller."""

    def __init__(self, ctx: InventoryContext) -> None:
        self.ctx = ctx
        self.read_model = ReadModel(ctx)

    # --- staging ---------------------------------------------------------------------

    async def _target_for(
        self, tx: InventoryTx, target_key: tuple[str, str], now: datetime
    ) -> InventoryTarget:
        """Return the inventory target of an execution key.

        The first call for a key registers the target. The kind is `direct` with the id of the
        fleet row when a fleet row has the host, `implicit` for another host and `controller`
        without a host."""
        source_key, host = target_key
        existing = await tx.get_active_target(source_key, host)
        if existing is not None:
            return existing
        source = await tx.get_source_inventory_by_key(source_key)
        if source is None:
            raise NotFound(f"connection {source_key!r} not found")
        legacy_id = None
        kind = "controller" if not host else "implicit"
        if host:
            for row in await self.ctx.store.list_devices(source_key):
                if row.host == host:
                    legacy_id, kind = row.id, "direct"
                    break
        return await tx.create_target(
            source_id=source.source_id,
            source_key=source_key,
            host=host,
            kind=kind,
            now=now,
            legacy_device_id=legacy_id,
        )

    async def _location_handle(
        self,
        tx: InventoryTx,
        source_key: str,
        reported: tuple[str, str] | None,
        known: dict[str, uuid.UUID],
        now: datetime,
    ) -> uuid.UUID | None:
        if reported is None or not reported[0]:
            return None
        location_id, name = reported
        if location_id in known:
            return known[location_id]
        handle = await self.ctx.ensure_location(tx, source_key, location_id, name, now)
        known[location_id] = handle
        return handle

    async def stage_observations(
        self,
        txn: InventoryTx,
        snapshot_key: str,
        target_key: tuple[str, str],
        observations: Sequence[ObservedDevice],
        authority: Authority | str,
        *,
        succeeded: bool | None = None,
        attempted_at: datetime | None = None,
    ) -> StageResult:
        """Stage the observations that one target reported in the run `snapshot_key`.

        `authority` takes the repository vocabulary (`complete`, `partial`) or the collector
        verdict (`ok`, `partial`, `failed`). `failed` means that the target did not succeed,
        and its prior claims go stale. An observation without a uid or with a context uid
        stages nothing. The rows are keyed by (snapshot, target, uid), and a repeated staging
        of the same target is idempotent."""
        now = attempted_at or self.ctx.clock()
        auth, ok = coerce_authority(authority)
        if succeeded is not None:
            ok = succeeded
        if await txn.get_publication(snapshot_key) is None:
            state = await txn.get_state()
            await txn.stage_publication(
                snapshot_key, parent_snapshot_key=state.read_model_snapshot_key, now=now
            )
        target = await self._target_for(txn, target_key, now)
        await txn.stage_target(snapshot_key, target.id, authority=auth, succeeded=ok, attempted_at=now)
        known = {loc.location_id: loc.handle for loc in await txn.list_locations(target.source_key)}
        rows: list[StagedObservation] = []
        seen: set[str] = set()
        for obs in observations:
            if not ok or not is_inventory_device_uid(obs.graph_uid) or obs.graph_uid in seen:
                continue
            seen.add(obs.graph_uid)
            notes = obs.notes()
            rows.append(
                StagedObservation(
                    target_id=target.id,
                    graph_uid=obs.graph_uid,
                    hostname=obs.hostname,
                    platform=obs.platform,
                    management_address=obs.management_address,
                    reported_location_handle=await self._location_handle(
                        txn, target.source_key, obs.reported_location, known, now
                    ),
                    notes=redact_by_key(notes) if notes else None,
                )
            )
        staged = await txn.stage_observations(snapshot_key, rows)
        return StageResult(snapshot_key, target.id, staged, auth, ok)

    async def abort(self, snapshot_key: str) -> None:
        """Drop the staging rows of a run that does not publish. The current observations
        stay."""
        async with self.ctx.repo.transaction() as tx:
            pub = await tx.get_publication(snapshot_key)
            if pub is None or pub.state in (PublicationState.APPLIED.value, PublicationState.ABORTED.value):
                return
            await tx.abort_publication(snapshot_key, self.ctx.clock())

    # --- composition -----------------------------------------------------------------------

    async def _fold(
        self,
        tx: InventoryTx,
        snapshot_key: str,
        *,
        locations: Mapping[uuid.UUID, InventoryLocation],
        site_ids: Mapping[str, int],
        targets: Mapping[uuid.UUID, InventoryTarget],
    ) -> _Folded:
        """Fold the staged rows over the current observations.

        A complete successful target replaces its claims, and an empty result retires all of
        them. A partial target updates the claims that it reported and leaves the rest stale.
        A failed target leaves all of its claims stale. A device that no staged target
        observes keeps its current claims."""
        staged_targets, staged_rows = await self.ctx.aux(tx).staged_rows(snapshot_key)
        by_target: dict[uuid.UUID, list[StagedObservation]] = {}
        for r in staged_rows:
            by_target.setdefault(r.target_id, []).append(r)
        existing: dict[uuid.UUID, list[placementmod.Claim]] = {}
        new_devices: dict[str, list[placementmod.Claim]] = {}
        new_targets: dict[str, list[InventoryTarget]] = {}
        replaced: dict[uuid.UUID, set[uuid.UUID]] = {}
        for st in staged_targets:
            target = targets.get(st.target_id)
            seen: set[uuid.UUID] = set()
            if st.succeeded:
                for r in by_target.get(st.target_id, []):
                    device = await tx.get_device_by_graph_uid(r.graph_uid)
                    probe = InventoryObservation(
                        st.target_id,
                        device.id if device else uuid.UUID(int=0),
                        r.reported_location_handle,
                        st.attempted_at,
                        snapshot_key,
                        ObservationState.CURRENT.value,
                        st.authority,
                        r.notes,
                        st.attempted_at,
                    )
                    claim = claim_of(probe, target, locations, site_ids)
                    if device is None:
                        new_devices.setdefault(r.graph_uid, []).append(claim)
                        if target is not None:
                            new_targets.setdefault(r.graph_uid, []).append(target)
                    else:
                        existing.setdefault(device.id, []).append(claim)
                        seen.add(device.id)
            leftover = (
                ObservationState.ABSENT
                if st.succeeded and st.authority == Authority.COMPLETE.value
                else ObservationState.STALE
            )
            for obs in await tx.list_observations(st.target_id):
                replaced.setdefault(obs.device_id, set()).add(st.target_id)
                if obs.device_id in seen or obs.state == ObservationState.ABSENT.value:
                    continue
                existing.setdefault(obs.device_id, []).append(
                    claim_of(obs, target, locations, site_ids, state=leftover)
                )
        # Claims from targets that took no part in this run stay as they are.
        for device_id in list(existing):
            for obs in await tx.get_observations(device_id):
                if obs.target_id in replaced.get(device_id, set()):
                    continue
                existing[device_id].append(claim_of(obs, targets.get(obs.target_id), locations, site_ids))
        onboarding = {
            uid: placementmod.onboarding_default([tg.onboarding_site_id for tg in new_targets.get(uid, [])])
            for uid in new_devices
        }
        return _Folded(existing, new_devices, onboarding)

    async def compose_placements(self, snapshot_key: str) -> PlacementInput:
        """Return the placement input of the run. The caller calls it before finalization.

        The input is computed from the staged observations of the run, folded over the current
        observations, and from the intent read in the same transaction. The captured revisions
        are stored on the publication, and `publish` applies these revisions."""
        async with self.ctx.repo.transaction() as tx:
            pub = await tx.get_publication(snapshot_key)
            if pub is None:
                raise NotFound(f"publication {snapshot_key!r} is not staged")
            if pub.state != PublicationState.STAGED.value:
                raise Conflict(f"publication {snapshot_key!r} is {pub.state}")
            state = await tx.get_state()
            site_rows = await self.ctx.site_rows(tx).list()
            site_ids = {s.code: s.id for s in site_rows}
            site_codes = {s.id: s.code for s in site_rows}
            locations = {loc.handle: loc for loc in await tx.list_locations()}
            targets = {tg.id: tg for tg in await tx.list_targets(include_archived=True)}
            folded = await self._fold(
                tx, snapshot_key, locations=locations, site_ids=site_ids, targets=targets
            )
            assignments: dict[str, str | None] = {}
            revisions: dict[str, dict[str, Any]] = {}

            def capture(device: InventoryDevice, resolved: placementmod.Resolved) -> None:
                site = resolved.publish_site_id
                assignments[device.graph_uid] = site_codes.get(site) if site is not None else None
                revisions[str(device.id)] = {
                    "revision": resolved.desired_revision,
                    "site_id": site,
                    "mode": resolved.mode.value,
                }

            wanted = set(folded.existing)
            # A device with a pending placement gets a captured revision even when this run
            # did not observe it.
            wanted.update(await self._pending_placement_ids(tx))
            placements = {p.device_id: p for p in await tx.get_placements(list(wanted))}
            for device in await tx.get_devices(sorted(wanted, key=str)):
                claims = folded.existing.get(device.id)
                if claims is None:
                    gathered = await self.read_model.gather(
                        tx,
                        device,
                        site_ids=site_ids,
                        locations=locations,
                        targets=targets,
                        placement=placements.get(device.id),
                    )
                    claims = gathered.claims()
                capture(device, placementmod.resolve(intent_of(placements.get(device.id)), claims))
            for uid, claims in folded.new_devices.items():
                decision = folded.new_onboarding[uid]
                intent = None
                if decision.site_id is not None:
                    intent = placementmod.Intent(
                        PlacementMode.ASSIGNED, decision.site_id, PlacementOrigin.ONBOARDING, revision=1
                    )
                resolved = placementmod.resolve(intent, claims)
                site = resolved.publish_site_id
                assignments[uid] = site_codes.get(site) if site is not None else None
                # The key is `uid:<graph uid>` until the apply registers the device and moves
                # the entry to the device id. The repository skips a key that is not a UUID.
                revisions[f"uid:{uid}"] = {"revision": 0, "site_id": site, "mode": resolved.mode.value}
            await tx.set_placement_revisions(snapshot_key, revisions)
            return PlacementInput(snapshot_key, state.intent_generation, assignments, revisions)

    async def _pending_placement_ids(self, tx: InventoryTx) -> list[uuid.UUID]:
        """Return the devices whose `placement_state` is `pending`. The next publication has
        to cover the intent rows of these devices."""
        filters = DeviceFilters(placement_states=["pending"], lifecycles=[m.value for m in Lifecycle])
        out: list[uuid.UUID] = []
        cursor = None
        while True:
            page = await tx.list_devices(filters, sort=SortField.NAME, limit=200, cursor=cursor)
            out.extend(item.device.id for item in page.items)
            if page.next_cursor is None:
                return out
            cursor = page.next_cursor

    # --- publish and apply ---------------------------------------------------------------

    async def publish(self, snapshot_key: str) -> PublishOutcome:
        """Record that the snapshot is published in the graph, and then apply it to the read
        model. The 2 steps are separate transactions."""
        now = self.ctx.clock()
        async with self.ctx.repo.transaction() as tx:
            pub = await tx.get_publication(snapshot_key)
            if pub is None:
                raise NotFound(f"publication {snapshot_key!r} is not staged")
            if pub.state == PublicationState.STAGED.value:
                await tx.mark_published(snapshot_key, now)
            elif pub.state == PublicationState.APPLIED.value:
                return PublishOutcome(snapshot_key, PublicationState.APPLIED, None, False, "already applied")
            elif pub.state == PublicationState.ABORTED.value:
                raise Conflict(f"publication {snapshot_key!r} was aborted")
            await tx.enqueue_outbox(
                kind=OutboxKind.PUBLICATION_RECONCILE.value,
                dedup_key=outbox_key(snapshot_key),
                payload={"snapshot_key": snapshot_key},
                now=now,
                max_attempts=RECONCILE_MAX_ATTEMPTS,
            )
        outcome = await self._apply(snapshot_key)
        # The outbox item of this publication finishes here when the apply
        # went through, and is retried on its schedule when it did not.
        await self.retry(worker_id=f"publish:{snapshot_key}")
        return outcome

    async def _register_new_devices(
        self, tx: InventoryTx, pub: InventoryPublication, now: datetime
    ) -> list[uuid.UUID]:
        """Register the devices that this run sees for the first time and apply the one-time
        onboarding default.

        The function runs before the repository applies the publication. The revision of an
        onboarding placement is then among the captured revisions of the publication. An
        agreed default is published in this snapshot and reads as applied."""
        staged_targets, staged_rows = await self.ctx.aux(tx).staged_rows(pub.snapshot_key)
        succeeded = {st.target_id for st in staged_targets if st.succeeded}
        by_uid: dict[str, list[StagedObservation]] = {}
        for r in staged_rows:
            if r.target_id in succeeded:
                by_uid.setdefault(r.graph_uid, []).append(r)
        targets = {tg.id: tg for tg in await tx.get_targets(sorted(succeeded, key=str))}
        registered: list[uuid.UUID] = []
        revisions = dict(pub.placement_revisions)
        for uid in sorted(by_uid):
            if await tx.get_device_by_graph_uid(uid) is not None:
                continue
            first = by_uid[uid][0]
            device, created = await tx.register_device(
                uid,
                hostname=first.hostname,
                platform=first.platform,
                management_address=first.management_address,
                snapshot_key=pub.snapshot_key,
                now=now,
            )
            if not created:
                continue
            registered.append(device.id)
            captured = revisions.pop(f"uid:{uid}", {})
            decision = placementmod.onboarding_default(
                [targets[r.target_id].onboarding_site_id for r in by_uid[uid] if r.target_id in targets]
            )
            if decision.site_id is not None:
                placement = await tx.set_placement(
                    device.id,
                    mode=PlacementMode.ASSIGNED,
                    site_id=decision.site_id,
                    origin=PlacementOrigin.ONBOARDING.value,
                    expected_revision=0,
                    actor_id=None,
                    now=now,
                )
                revisions[str(device.id)] = {
                    "revision": placement.revision,
                    "site_id": decision.site_id,
                    "mode": PlacementMode.ASSIGNED.value,
                }
                await tx.append_event(
                    entity_type="device",
                    entity_id=str(device.id),
                    actor_id=None,
                    action="placement.onboarding",
                    now=now,
                    snapshot_key=pub.snapshot_key,
                    after={"mode": "assigned", "site_id": decision.site_id, "revision": placement.revision},
                )
            else:
                revisions[str(device.id)] = {
                    "revision": 0,
                    "site_id": captured.get("site_id"),
                    "mode": PlacementMode.AUTO.value,
                }
                if decision.conflict:
                    await tx.append_event(
                        entity_type="device",
                        entity_id=str(device.id),
                        actor_id=None,
                        action="placement.onboarding_conflict",
                        now=now,
                        snapshot_key=pub.snapshot_key,
                        after={"mode": "auto", "candidates": list(decision.candidates)},
                    )
        if revisions != pub.placement_revisions:
            await tx.set_placement_revisions(pub.snapshot_key, revisions)
        return registered

    async def _ensure_placement_rows(self, tx: InventoryTx, snapshot_key: str, now: datetime) -> None:
        """Give an `auto` placement row to each device that the composer captured at revision 0.

        Such a device has no placement row, and the repository records the applied side only on
        a row. The new row has revision 1, and that revision replaces the captured revision 0.
        The published site of an auto device is then recorded on the row. The `stale` and
        `pending` rules read it there."""
        pub = await tx.get_publication(snapshot_key)
        if pub is None:
            return
        revisions = dict(pub.placement_revisions)
        changed = False
        for key, captured in revisions.items():
            if int(captured.get("revision", 0)) != 0:
                continue
            try:
                device_id = uuid.UUID(key)
            except ValueError:
                continue
            if await tx.get_placement(device_id) is not None:
                continue
            row = await tx.set_placement(
                device_id,
                mode=PlacementMode.AUTO,
                site_id=None,
                origin=MATERIALIZED_ORIGIN.value,
                expected_revision=0,
                actor_id=None,
                now=now,
            )
            revisions[key] = {**captured, "revision": row.revision}
            changed = True
        if changed:
            await tx.set_placement_revisions(snapshot_key, revisions)

    async def _apply(self, snapshot_key: str) -> PublishOutcome:
        now = self.ctx.clock()
        try:
            async with self.ctx.repo.transaction() as tx:
                pub = await tx.get_publication(snapshot_key)
                if pub is None:
                    raise NotFound(f"publication {snapshot_key!r} not found")
                if pub.state == PublicationState.APPLIED.value:
                    return PublishOutcome(
                        snapshot_key, PublicationState.APPLIED, None, False, "already applied"
                    )
                if pub.state != PublicationState.PUBLISHED.value:
                    raise Conflict(f"publication {snapshot_key!r} is {pub.state}, not published")
                newest = await tx.latest_publication(PublicationState.APPLIED)
                if newest is not None and newest.created_at > pub.created_at:
                    await tx.abort_publication(snapshot_key, now)
                    return PublishOutcome(
                        snapshot_key,
                        PublicationState.ABORTED,
                        None,
                        False,
                        f"publication {newest.snapshot_key!r} is newer and already applied",
                    )
                staged_targets, _ = await self.ctx.aux(tx).staged_rows(snapshot_key)
                touched: set[uuid.UUID] = set()
                for st in staged_targets:
                    touched.update(o.device_id for o in await tx.list_observations(st.target_id))
                registered = await self._register_new_devices(tx, pub, now)
                await self._ensure_placement_rows(tx, snapshot_key, now)
                report = await tx.apply_publication(snapshot_key, now)
                report.registered_device_ids.extend(registered)
                touched.update(report.registered_device_ids)
                touched.update(report.reappeared_device_ids)
                touched.update(report.missing_device_ids)
                for key in (await tx.get_publication(snapshot_key) or pub).placement_revisions:
                    try:
                        touched.add(uuid.UUID(key))
                    except ValueError:
                        continue
                await self.read_model.refresh(tx, sorted(touched, key=str), now)
                await self._apply_events(tx, report, snapshot_key, now)
                return PublishOutcome(snapshot_key, PublicationState.APPLIED, report, False)
        except (NotFound, Conflict):
            raise
        except Exception as exc:
            log.error("inventory apply of %s failed: %s", snapshot_key, type(exc).__name__)
            await self._mark_sync_pending(snapshot_key)
            return PublishOutcome(snapshot_key, PublicationState.PUBLISHED, None, True, type(exc).__name__)

    async def _apply_events(
        self, tx: InventoryTx, report: PublicationApplyReport, snapshot_key: str, now: datetime
    ) -> None:
        for device_id in report.registered_device_ids:
            await tx.append_event(
                entity_type="device",
                entity_id=str(device_id),
                actor_id=None,
                action="device.registered",
                now=now,
                snapshot_key=snapshot_key,
            )
        for device_id in report.reappeared_device_ids:
            await tx.append_event(
                entity_type="device",
                entity_id=str(device_id),
                actor_id=None,
                action="device.reappeared",
                now=now,
                snapshot_key=snapshot_key,
                before={"lifecycle": "missing"},
                after={"lifecycle": "active"},
            )
        for device_id in report.missing_device_ids:
            await tx.append_event(
                entity_type="device",
                entity_id=str(device_id),
                actor_id=None,
                action="device.missing",
                now=now,
                snapshot_key=snapshot_key,
                before={"lifecycle": "active"},
                after={"lifecycle": "missing"},
            )
        await tx.append_event(
            entity_type="publication",
            entity_id=snapshot_key,
            actor_id=None,
            action="publication.applied",
            now=now,
            snapshot_key=snapshot_key,
            after={
                "registered": len(report.registered_device_ids),
                "reappeared": len(report.reappeared_device_ids),
                "missing": len(report.missing_device_ids),
                "observations": report.observations_written,
                "retired": report.observations_retired,
                "placements": report.placements_applied,
            },
        )

    async def _mark_sync_pending(self, snapshot_key: str) -> None:
        try:
            async with self.ctx.repo.transaction() as tx:
                now = self.ctx.clock()
                await tx.set_sync_pending(True, now)
                await tx.enqueue_outbox(
                    kind=OutboxKind.PUBLICATION_RECONCILE.value,
                    dedup_key=outbox_key(snapshot_key),
                    payload={"snapshot_key": snapshot_key},
                    now=now,
                    max_attempts=RECONCILE_MAX_ATTEMPTS,
                )
        except Exception as inner:  # pragma: no cover - the store itself is down
            log.error(
                "could not record inventory sync pending for %s: %s", snapshot_key, type(inner).__name__
            )

    # --- reconcile -------------------------------------------------------------------------

    async def reconcile(self, latest_snapshot_key: str | None) -> ReconcileReport:
        """Bring the read model up to the latest published snapshot.

        `latest_snapshot_key` is the key of the graph pointer. A staged publication with that
        key is marked published. The graph published it, and the process stopped before
        Postgres recorded it. Each published publication is then applied in creation order. A
        staged publication that is older than a published publication or than the newest
        applied one is aborted. The due outbox items run, and the collection states are
        refreshed."""
        report = ReconcileReport()
        now = self.ctx.clock()
        async with self.ctx.repo.transaction() as tx:
            await tx.reap_outbox(now)
            aux = self.ctx.aux(tx)
            if latest_snapshot_key:
                pub = await tx.get_publication(latest_snapshot_key)
                if pub is not None and pub.state == PublicationState.STAGED.value:
                    await tx.mark_published(latest_snapshot_key, now)
                    await tx.enqueue_outbox(
                        kind=OutboxKind.PUBLICATION_RECONCILE.value,
                        dedup_key=outbox_key(latest_snapshot_key),
                        payload={"snapshot_key": latest_snapshot_key},
                        now=now,
                        max_attempts=RECONCILE_MAX_ATTEMPTS,
                    )
            pending = await aux.list_publications(PublicationState.PUBLISHED)
            newest_applied = await tx.latest_publication(PublicationState.APPLIED)
            moved_past = [p.created_at for p in pending]
            if newest_applied is not None:
                moved_past.append(newest_applied.created_at)
            for p in await aux.list_publications(PublicationState.STAGED):
                if p.snapshot_key != latest_snapshot_key and any(p.created_at < at for at in moved_past):
                    await tx.abort_publication(p.snapshot_key, now)
                    report.aborted.append(p.snapshot_key)
        for pub in pending:
            outcome = await self._apply(pub.snapshot_key)
            if outcome.state == PublicationState.APPLIED:
                report.applied.append(pub.snapshot_key)
            elif outcome.state == PublicationState.ABORTED:
                report.aborted.append(pub.snapshot_key)
            else:
                report.failed.append(pub.snapshot_key)
                break
        report.outbox_done = await self.retry(worker_id="reconcile")
        async with self.ctx.repo.transaction() as tx:
            report.collection_states_touched = await self.read_model.refresh_all_collection_states(tx, now)
            state = await tx.get_state()
            if (
                state.inventory_sync_pending
                and not report.failed
                and not await self.ctx.aux(tx).list_publications(PublicationState.PUBLISHED)
            ):
                state = await tx.set_sync_pending(False, now)
            report.sync_pending = state.inventory_sync_pending
        return report

    async def retry(self, worker_id: str | None = None) -> int:
        """Run the due outbox items and return the count of finished items.

        A publication reconcile applies its snapshot. A snapshot that is already applied or
        aborted counts as done. A job enqueue goes to the queue."""
        from hst.worker import queue

        worker = worker_id or f"inventory-outbox:{uuid.uuid4().hex[:8]}"
        now = self.ctx.clock()
        async with self.ctx.repo.transaction() as tx:
            items = await tx.claim_outbox(worker, now=now, lease=OUTBOX_LEASE, batch=20)
        done = 0
        for item in items:
            ok, error = True, ""
            try:
                if item.kind == OutboxKind.PUBLICATION_RECONCILE.value:
                    outcome = await self._apply_for_outbox(str(item.payload.get("snapshot_key") or ""))
                    if outcome is not None and outcome.state == PublicationState.PUBLISHED:
                        ok, error = False, outcome.detail or "apply failed"
                elif item.kind == OutboxKind.JOB_ENQUEUE.value:
                    await queue.enqueue(
                        self.ctx.store,
                        str(item.payload["kind"]),
                        source=item.payload.get("source"),
                        device=item.payload.get("device"),
                        triggered_by=str(item.payload.get("triggered_by") or "inventory"),
                        now=now,
                    )
            except Exception as exc:
                ok, error = False, type(exc).__name__
            async with self.ctx.repo.transaction() as tx:
                finished = await tx.finish_outbox(
                    item.id,
                    ok=ok,
                    now=self.ctx.clock(),
                    claimed_by=worker,
                    error=error,
                    retry_at=None if ok else self.ctx.clock() + OUTBOX_RETRY,
                )
                if finished is not None and finished.state == OutboxState.DONE.value:
                    done += 1
        return done

    async def _apply_for_outbox(self, snapshot_key: str) -> PublishOutcome | None:
        async with self.ctx.repo.transaction() as tx:
            pub = await tx.get_publication(snapshot_key)
        if pub is None or pub.state in (PublicationState.APPLIED.value, PublicationState.ABORTED.value):
            return None
        if pub.state == PublicationState.STAGED.value:
            # The publication is not marked published. A reconcile with the latest key of
            # the graph marks it.
            return None
        outcome = await self._apply(snapshot_key)
        if outcome.state in (PublicationState.APPLIED, PublicationState.ABORTED):
            async with self.ctx.repo.transaction() as tx:
                state = await tx.get_state()
                if state.inventory_sync_pending and not await self.ctx.aux(tx).list_publications(
                    PublicationState.PUBLISHED
                ):
                    await tx.set_sync_pending(False, self.ctx.clock())
        return outcome
