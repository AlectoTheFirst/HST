"""Test rig for the inventory services and routes."""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from tests.app.inventory_fakes import FakeInventoryRepository, InventoryFakeStore

from hst.app.inventory import observations as obs
from hst.app.inventory.contracts import ObservationState, PublicationState
from hst.app.inventory.repository import Conflict, InventoryTx, NotFound, StaleRevision
from hst.app.store import UNSET, InventoryLocation, InventoryPublication, StagedObservation, StagedTarget
from hst.core import uid as uidmod

DSN = os.environ.get("HST_TEST_PG_DSN")
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)


class Clock:
    """A clock the test advances; every service call reads it."""

    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def tick(self, seconds: float = 1.0) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class FakeSiteRows:
    def __init__(self, tables: Any, store: InventoryFakeStore | None) -> None:
        self.t = tables
        self.store = store
        if not hasattr(tables, "site_meta"):
            tables.site_meta = {}
        if not hasattr(tables, "site_points"):
            tables.site_points = {}
        if not hasattr(tables, "site_params"):
            tables.site_params = {}

    def _row(self, site_id: int) -> obs.SiteRow:
        code = self.t.sites_rows[site_id]
        name, location, revision = self.t.site_meta.get(site_id, ("", "", 1))
        lat, lon = self.t.site_points.get(site_id, (None, None))
        params = self._params(site_id)
        return obs.SiteRow(
            site_id, code, name, location, revision, lat, lon, params.get("site_group"), params.get("blocks")
        )

    def _legacy(self, site_id: int) -> dict[str, Any] | None:
        # the site group and blocks live in the params column of the store row
        # when there is one
        if self.store is None:
            return None
        return self.store.sites_rows.get(self.t.sites_rows[site_id])

    def _params(self, site_id: int) -> dict[str, Any]:
        legacy = self._legacy(site_id)
        if legacy is not None:
            return legacy.get("params") or {}
        return self.t.site_params.get(site_id, {})

    def _set_params(self, site_id: int, changes: dict[str, Any]) -> None:
        params = {**self._params(site_id), **changes}
        legacy = self._legacy(site_id)
        if legacy is not None:
            legacy["params"] = params
        else:
            self.t.site_params[site_id] = params

    async def list(self) -> list[obs.SiteRow]:
        return sorted((self._row(i) for i in self.t.sites_rows), key=lambda r: r.code)

    async def create(
        self, code: str, name: str, location: str, *, now: datetime, point: tuple[float, float] | None = None
    ) -> obs.SiteRow:
        if code in self.t.sites_rows.values():
            raise Conflict(f"site code {code!r} is in use")
        if clash := uidmod.site_fold(code, self.t.sites_rows.values()):
            raise Conflict(f"site code {code!r} folds onto {clash!r}")
        site_id = max(self.t.sites_rows, default=0) + 1
        self.t.sites_rows[site_id] = code
        self.t.site_meta[site_id] = (name, location, 1)
        if point:
            self.t.site_points[site_id] = point
        if self.store is not None:
            params = {"lat": point[0], "lon": point[1]} if point else {}
            self.store.sites_rows[code] = {"name": name, "location": location, "params": params}
        return self._row(site_id)

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
        blocks: list[dict[str, Any]] | object | None = UNSET,
    ) -> obs.SiteRow:
        if site_id not in self.t.sites_rows:
            raise NotFound("site not found")
        current = self._row(site_id)
        if current.revision != expected_revision:
            raise StaleRevision(
                f"site is at revision {current.revision}, not {expected_revision}",
                current_revision=current.revision,
            )
        new_name = current.name if name is UNSET else str(name)
        new_location = current.location if location is UNSET else str(location)
        self.t.site_meta[site_id] = (new_name, new_location, current.revision + 1)
        if isinstance(point, tuple):
            self.t.site_points[site_id] = point
        elif point is None:
            self.t.site_points.pop(site_id, None)
        pairs = (("site_group", site_group), ("blocks", blocks))
        changes = {key: value for key, value in pairs if value is not UNSET}
        if changes:
            self._set_params(site_id, changes)
        return self._row(site_id)

    async def delete(self, site_id: int) -> None:
        code = self.t.sites_rows.pop(site_id, None)
        self.t.site_meta.pop(site_id, None)
        self.t.site_points.pop(site_id, None)
        self.t.site_params.pop(site_id, None)
        if self.store is not None and code is not None:
            self.store.sites_rows.pop(code, None)

    async def device_counts(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for d in self.t.devices.values():
            if d.resolved_site_id is not None and d.lifecycle != "archived":
                out[d.resolved_site_id] = out.get(d.resolved_site_id, 0) + 1
        return out


class FakeAuxReader:
    def __init__(self, tables: Any) -> None:
        self.t = tables

    async def list_publications(self, state: PublicationState) -> list[InventoryPublication]:
        rows = [p for p in self.t.publications.values() if p.state == state.value]
        return sorted(rows, key=lambda p: (p.created_at, p.snapshot_key))

    async def staged_rows(self, snapshot_key: str) -> tuple[list[StagedTarget], list[StagedObservation]]:
        targets = [st for (k, _), st in self.t.staged_targets.items() if k == snapshot_key]
        rows = [r for (k, _, _), r in sorted(self.t.staged_observations.items()) if k == snapshot_key]
        return targets, rows

    async def location_device_counts(self) -> dict[uuid.UUID, int]:
        seen: dict[uuid.UUID, set[uuid.UUID]] = {}
        for o in self.t.observations.values():
            if o.reported_location_handle is not None and o.state != ObservationState.ABSENT.value:
                seen.setdefault(o.reported_location_handle, set()).add(o.device_id)
        return {h: len(devices) for h, devices in seen.items()}


def fake_site_rows(store: InventoryFakeStore | None):
    def factory(tx: InventoryTx) -> FakeSiteRows:
        return FakeSiteRows(tx.t, store)  # type: ignore[attr-defined]

    return factory


def fake_aux(tx: InventoryTx) -> FakeAuxReader:
    return FakeAuxReader(tx.t)  # type: ignore[attr-defined]


async def fake_ensure_location(
    tx: InventoryTx, source_key: str, location_id: str, name: str, now: datetime
) -> uuid.UUID:
    tables = tx.t  # type: ignore[attr-defined]
    for loc in tables.locations_rows.values():
        if loc.source == source_key and loc.location_id == location_id:
            if name and loc.name != name:
                loc.name = name
            return loc.handle
    row = InventoryLocation(uuid.uuid4(), source_key, location_id, name, None, 1, now)
    tables.locations_rows[row.handle] = row
    return row.handle


class FakeGraph:
    """The graph reader of the detail: canned related entities, or an
    outage when `down` is set."""

    def __init__(self) -> None:
        self.related_by_uid: dict[str, list[obs.RelatedEntityRow]] = {}
        self.down = False
        self.calls: list[list[str]] = []

    def related(self, device_uids, snapshot_key):
        self.calls.append(list(device_uids))
        if self.down:
            raise ConnectionError("graph unavailable")
        return {uid: self.related_by_uid.get(uid, []) for uid in device_uids}


@dataclass
class Settings:
    """The two settings the inventory reads."""

    collect_interval_s: int = 0
    neo4j_uri: str = "bolt://127.0.0.1:1"


@dataclass
class Rig:
    store: Any
    ctx: obs.InventoryContext
    clock: Clock
    service: obs.ObservationService
    graph: FakeGraph | None = None
    fake: FakeInventoryRepository | None = None
    pg: bool = False
    source_ids: dict[str, int] = field(default_factory=dict)
    site_ids: dict[str, int] = field(default_factory=dict)

    @property
    def repo(self):
        return self.store.inventory()

    async def seed_source(
        self, name: str, type_: str = "vyos", *, enabled: bool = True, config: dict | None = None
    ) -> int:
        row = await self.store.create_source(name, type_, config or {}, b"", enabled=enabled)
        if self.fake is not None:
            self.fake.seed_source(row.id, name, type_, enabled=enabled)
        self.source_ids[name] = row.id
        return row.id

    async def seed_site(self, code: str, name: str = "") -> int:
        if self.fake is not None:
            async with self.repo.transaction() as tx:
                row = await self.ctx.site_rows(tx).create(code, name, "", now=self.clock())
            self.site_ids[code] = row.id
            return row.id
        site = await self.store.create_site(code, name, "")
        self.site_ids[code] = site.id
        return site.id

    async def seed_location(
        self, source: str, location_id: str, name: str = "", site: str | None = None
    ) -> uuid.UUID:
        if self.fake is not None:
            row = self.fake.seed_location(source, location_id, name, site)
            return row.handle
        await self.store.record_target_devices(
            source, "", [f"seed:{location_id}"], {f"seed:{location_id}": (location_id, name)}
        )
        if site is not None:
            await self.store.bind_location(source, location_id, site)
        async with self.repo.transaction() as tx:
            for loc in await tx.list_locations(source):
                if loc.location_id == location_id:
                    return loc.handle
        raise AssertionError("location not registered")

    async def target(
        self,
        source: str,
        host: str,
        *,
        kind: str = "direct",
        onboarding_site: str | None = None,
        enabled: bool = True,
    ):
        async with self.repo.transaction() as tx:
            existing = await tx.get_active_target(source, host)
            if existing is not None:
                return existing
            return await tx.create_target(
                source_id=self.source_ids[source],
                source_key=source,
                host=host,
                kind=kind,
                now=self.clock(),
                onboarding_site_id=self.site_ids[onboarding_site] if onboarding_site else None,
                enabled=enabled,
            )

    async def run(
        self,
        snapshot_key: str,
        reports: dict[tuple[str, str], tuple[str, list[obs.ObservedDevice]]],
        *,
        compose: bool = True,
        publish: bool = True,
    ) -> tuple[obs.PlacementInput | None, obs.PublishOutcome | None]:
        """One collection run: stage every target's report in one transaction,
        compose the placements, publish. `reports` maps target key to
        (authority, observed devices); authority `failed` stages nothing."""
        async with self.repo.transaction() as tx:
            for key, (authority, devices) in reports.items():
                await self.service.stage_observations(tx, snapshot_key, key, devices, authority)
        placement = await self.service.compose_placements(snapshot_key) if compose else None
        outcome = await self.service.publish(snapshot_key) if publish else None
        return placement, outcome

    async def device_by_uid(self, uid: str):
        async with self.repo.transaction() as tx:
            return await tx.get_device_by_graph_uid(uid)

    async def observations(self, uid: str):
        async with self.repo.transaction() as tx:
            device = await tx.get_device_by_graph_uid(uid)
            if device is None:
                return []
            return await tx.get_observations(device.id)

    async def placement(self, uid: str):
        async with self.repo.transaction() as tx:
            device = await tx.get_device_by_graph_uid(uid)
            return await tx.get_placement(device.id) if device else None

    async def resolved(self, uid: str):
        async with self.repo.transaction() as tx:
            device = await tx.get_device_by_graph_uid(uid)
            assert device is not None
            claims = await self.service.read_model.gather(tx, device)
            return claims.resolve()

    async def state(self):
        async with self.repo.transaction() as tx:
            return await tx.get_state()


async def seed_site(
    store: Any, code: str, name: str = "", location: str = "", params: dict[str, Any] | None = None
) -> int:
    """A site row through the inventory's site rows, on a FakeStore or a
    PgStore; `params` replaces the row's params. Returns the site id."""
    async with store.inventory().transaction() as tx:
        if tx.connection is None:
            rows: Any = FakeSiteRows(tx.t, store)  # type: ignore[attr-defined]
        else:
            rows = obs.pg_site_rows(tx)
        row = await rows.create(code, name, location, now=datetime.now(UTC))
        if params is not None:
            if tx.connection is None:
                store.sites_rows[code]["params"] = dict(params)
            else:
                from hst.app.store.pg import sites

                await tx.connection.execute(sites.update().where(sites.c.id == row.id).values(params=params))
    return row.id


def fake_rig(*, settings: Settings | None = None) -> Rig:
    store = InventoryFakeStore()
    clock = Clock()
    graph = FakeGraph()
    ctx = obs.InventoryContext(
        store,
        settings or Settings(),
        site_rows=fake_site_rows(store),
        aux=fake_aux,
        ensure_location=fake_ensure_location,
        graph=graph,
        clock=clock,
    )
    return Rig(store, ctx, clock, obs.ObservationService(ctx), graph=graph, fake=store.inventory())


async def reset_pg() -> Any:
    """A clean disposable database at the migration head, and a PgStore on it."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import PgStore, metadata, upgrade_to_head

    assert DSN
    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    return PgStore(DSN)


async def pg_rig(*, settings: Settings | None = None, graph: FakeGraph | None = None) -> Rig:
    store = await reset_pg()
    clock = Clock()
    ctx = obs.InventoryContext(store, settings or Settings(), graph=graph or FakeGraph(), clock=clock)
    return Rig(store, ctx, clock, obs.ObservationService(ctx), graph=graph or ctx.graph, pg=True)  # type: ignore[arg-type]


def device(
    uid: str, hostname: str = "", location: tuple[str, str] | None = None, **kw: Any
) -> obs.ObservedDevice:
    return obs.ObservedDevice(uid, hostname or uid.rsplit(":", 1)[-1], reported_location=location, **kw)
