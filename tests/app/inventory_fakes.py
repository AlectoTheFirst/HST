"""In-memory inventory repository with the semantics of PgInventoryTx."""

from __future__ import annotations

import copy
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from tests.app.fakes import FakeStore

from hst.app.inventory.contracts import (
    MAX_DERIVED_IMPACT,
    MAX_PAGE_LIMIT,
    ActivationState,
    Authority,
    CursorError,
    Lifecycle,
    ListCursor,
    ObservationState,
    OutboxState,
    PlacementMode,
    PublicationState,
    SortDirection,
    SortField,
    decode_cursor,
    encode_cursor,
    filter_digest,
    redact_by_key,
)
from hst.app.inventory.repository import (
    Conflict,
    IdempotencyConflict,
    InventoryChanged,
    InventoryError,
    NotFound,
    PreviewExpired,
    StaleRevision,
    redact_response,
)
from hst.app.store import (
    UNSET,
    CollectionCredential,
    CollectionCredentialVersion,
    CollectionProfile,
    CollectionProfileVersion,
    DeviceFilters,
    DeviceListItem,
    DevicePageResult,
    InventoryDevice,
    InventoryEvent,
    InventoryLocation,
    InventoryObservation,
    InventoryPlacement,
    InventoryPublication,
    InventoryRoutingGroup,
    InventoryRoutingMember,
    InventorySavedView,
    InventoryState,
    InventoryTarget,
    ObservingTarget,
    OperationPreview,
    OperationResult,
    OutboxItem,
    PreviewImpact,
    ProfileReferences,
    PublicationApplyReport,
    SourceInventory,
    StagedObservation,
    StagedTarget,
)


def _stale(expected: int, current: int, what: str) -> None:
    if expected != current:
        raise StaleRevision(f"{what} is at revision {current}, not {expected}", current_revision=current)


class _Tables:
    """Every table of the fake, copied wholesale per transaction."""

    def __init__(self) -> None:
        self.state = InventoryState(1, 1, 0, "inactive", None, 1, False, datetime.now(UTC))
        # the source, site and location rows that hold the inventory columns
        self.sources_rows: dict[int, SourceInventory] = {}
        self.sites_rows: dict[int, str] = {}  # id -> code
        self.locations_rows: dict[uuid.UUID, InventoryLocation] = {}
        self.targets: dict[uuid.UUID, InventoryTarget] = {}
        self.devices: dict[uuid.UUID, InventoryDevice] = {}
        self.observations: dict[tuple[uuid.UUID, uuid.UUID], InventoryObservation] = {}
        self.placements: dict[uuid.UUID, InventoryPlacement] = {}
        self.publications: dict[str, InventoryPublication] = {}
        self.staged_targets: dict[tuple[str, uuid.UUID], StagedTarget] = {}
        self.staged_observations: dict[tuple[str, uuid.UUID, str], StagedObservation] = {}
        self.credentials: dict[uuid.UUID, CollectionCredential] = {}
        self.credential_versions: dict[tuple[uuid.UUID, int], CollectionCredentialVersion] = {}
        self.profiles: dict[uuid.UUID, CollectionProfile] = {}
        self.profile_versions: dict[tuple[uuid.UUID, int], CollectionProfileVersion] = {}
        self.views: dict[uuid.UUID, InventorySavedView] = {}
        self.groups: dict[uuid.UUID, InventoryRoutingGroup] = {}
        self.members: dict[tuple[uuid.UUID, str], InventoryRoutingMember] = {}
        self.events: dict[int, InventoryEvent] = {}
        self._eid = 0
        self.previews: dict[uuid.UUID, OperationPreview] = {}
        self.impacts: dict[uuid.UUID, list[PreviewImpact]] = {}
        self.results: dict[tuple[int, str], OperationResult] = {}
        self.outbox: dict[int, OutboxItem] = {}
        self._oid = 0


class FakeInventoryTx:
    def __init__(self, tables: _Tables) -> None:
        self.t = tables

    @property
    def connection(self) -> None:
        return None

    # --- state ---------------------------------------------------------------------

    async def get_state(self) -> InventoryState:
        return replace(self.t.state)

    async def bump_generation(self, now: datetime) -> int:
        self.t.state.intent_generation += 1
        self.t.state.updated_at = now
        return self.t.state.intent_generation

    async def activate(
        self, *, resolver_version: int, schema_version: int, backfill_version: int, now: datetime
    ) -> InventoryState:
        st = self.t.state
        st.resolver_version, st.schema_version, st.backfill_version = (
            resolver_version,
            schema_version,
            backfill_version,
        )
        st.activation_state, st.updated_at = ActivationState.ACTIVE.value, now
        return replace(st)

    async def set_activation_state(self, state: ActivationState, now: datetime) -> InventoryState:
        self.t.state.activation_state, self.t.state.updated_at = state.value, now
        return replace(self.t.state)

    async def advance_read_model(self, snapshot_key: str, now: datetime) -> InventoryState:
        st = self.t.state
        st.read_model_snapshot_key, st.inventory_sync_pending, st.updated_at = snapshot_key, False, now
        return replace(st)

    async def set_sync_pending(self, pending: bool, now: datetime) -> InventoryState:
        self.t.state.inventory_sync_pending, self.t.state.updated_at = pending, now
        return replace(self.t.state)

    # --- sources -------------------------------------------------------------------

    async def get_source_inventory(self, source_id: int) -> SourceInventory | None:
        row = self.t.sources_rows.get(source_id)
        return replace(row) if row else None

    async def get_source_inventory_by_key(self, source_key: str) -> SourceInventory | None:
        for row in self.t.sources_rows.values():
            if row.name == source_key:
                return replace(row)
        return None

    async def list_source_inventory(self) -> list[SourceInventory]:
        return sorted((replace(r) for r in self.t.sources_rows.values()), key=lambda r: r.name)

    async def update_source_inventory(
        self,
        source_id: int,
        *,
        expected_revision: int,
        now: datetime,
        display_name: str | object = UNSET,
        default_profile_id: uuid.UUID | object | None = UNSET,
    ) -> SourceInventory:
        row = self.t.sources_rows.get(source_id)
        if row is None:
            raise NotFound("connection not found")
        _stale(expected_revision, row.inventory_revision, "connection")
        if default_profile_id not in (UNSET, None) and default_profile_id not in self.t.profiles:
            raise Conflict("profile does not exist")
        if display_name is not UNSET:
            row.display_name = display_name  # type: ignore[assignment]
        if default_profile_id is not UNSET:
            row.default_profile_id = default_profile_id  # type: ignore[assignment]
        row.inventory_revision += 1
        await self.bump_generation(now)
        return replace(row)

    async def set_frozen_normalization(
        self, source_id: int, value: dict | None, now: datetime
    ) -> SourceInventory:
        row = self.t.sources_rows.get(source_id)
        if row is None:
            raise NotFound("connection not found")
        row.frozen_normalization = copy.deepcopy(value)
        return replace(row)

    # --- targets -------------------------------------------------------------------

    async def create_target(
        self,
        *,
        source_id: int,
        source_key: str,
        host: str,
        kind: str,
        now: datetime,
        legacy_device_id: int | None = None,
        profile_id: uuid.UUID | None = None,
        onboarding_site_id: int | None = None,
        enabled: bool = True,
    ) -> InventoryTarget:
        if await self.get_active_target(source_key, host) is not None:
            raise Conflict(f"an active target for ({source_key!r}, {host!r}) exists")
        if profile_id is not None and profile_id not in self.t.profiles:
            raise Conflict("profile does not exist")
        if legacy_device_id is not None and any(
            x.legacy_device_id == legacy_device_id for x in self.t.targets.values()
        ):
            raise Conflict("legacy device already referenced")
        row = InventoryTarget(
            uuid.uuid4(),
            source_id,
            source_key,
            host,
            kind,
            legacy_device_id,
            profile_id,
            onboarding_site_id,
            enabled,
            1,
            None,
            now,
            now,
        )
        self.t.targets[row.id] = row
        await self.bump_generation(now)
        return replace(row)

    async def get_target(self, target_id: uuid.UUID) -> InventoryTarget | None:
        row = self.t.targets.get(target_id)
        return replace(row) if row else None

    async def get_targets(self, target_ids: Sequence[uuid.UUID]) -> list[InventoryTarget]:
        return [replace(self.t.targets[i]) for i in target_ids if i in self.t.targets]

    async def get_active_target(self, source_key: str, host: str) -> InventoryTarget | None:
        for row in self.t.targets.values():
            if row.source_key == source_key and row.host == host and row.archived_at is None:
                return replace(row)
        return None

    async def list_targets(
        self, source_id: int | None = None, *, include_archived: bool = False
    ) -> list[InventoryTarget]:
        rows = [
            replace(r)
            for r in self.t.targets.values()
            if (source_id is None or r.source_id == source_id) and (include_archived or r.archived_at is None)
        ]
        return sorted(rows, key=lambda r: (r.source_key, r.host))

    async def update_target(
        self,
        target_id: uuid.UUID,
        *,
        expected_revision: int,
        now: datetime,
        enabled: bool | object = UNSET,
        profile_id: uuid.UUID | object | None = UNSET,
        onboarding_site_id: int | object | None = UNSET,
        legacy_device_id: int | object | None = UNSET,
    ) -> InventoryTarget:
        row = self.t.targets.get(target_id)
        if row is None:
            raise NotFound("target not found")
        _stale(expected_revision, row.revision, "target")
        if profile_id is not UNSET and profile_id is not None and profile_id not in self.t.profiles:
            raise Conflict("target update references a record that does not exist")
        for key, value in (
            ("enabled", enabled),
            ("profile_id", profile_id),
            ("onboarding_site_id", onboarding_site_id),
            ("legacy_device_id", legacy_device_id),
        ):
            if value is not UNSET:
                setattr(row, key, value)
        row.revision += 1
        row.updated_at = now
        await self.bump_generation(now)
        return replace(row)

    async def archive_target(
        self, target_id: uuid.UUID, *, expected_revision: int | None, now: datetime
    ) -> InventoryTarget:
        row = self.t.targets.get(target_id)
        if row is None:
            raise NotFound("target not found")
        if expected_revision is not None:
            _stale(expected_revision, row.revision, "target")
        if row.archived_at is not None:
            return replace(row)
        row.archived_at, row.enabled, row.revision, row.updated_at = now, False, row.revision + 1, now
        await self.retire_observations(target_id, now)
        await self.bump_generation(now)
        return replace(row)

    async def archive_source_targets(self, source_id: int, now: datetime) -> list[InventoryTarget]:
        archived = [
            await self.archive_target(x.id, expected_revision=None, now=now)
            for x in await self.list_targets(source_id)
        ]
        await self.clear_target_source(source_id, now)
        return [replace(a, source_id=None) for a in archived]

    async def retire_observations(self, target_id: uuid.UUID, now: datetime) -> int:
        n = 0
        for obs in self.t.observations.values():
            if obs.target_id == target_id and obs.state != ObservationState.ABSENT.value:
                obs.state, obs.updated_at = ObservationState.ABSENT.value, now
                n += 1
        return n

    async def clear_target_source(self, source_id: int, now: datetime) -> int:
        n = 0
        for row in self.t.targets.values():
            if row.source_id == source_id:
                row.source_id, row.updated_at = None, now
                n += 1
        return n

    async def clear_onboarding_site(self, site_id: int, now: datetime) -> int:
        n = 0
        for row in self.t.targets.values():
            if row.onboarding_site_id == site_id:
                row.onboarding_site_id, row.updated_at = None, now
                n += 1
        return n

    # --- devices -------------------------------------------------------------------

    async def register_device(
        self,
        graph_uid: str,
        *,
        hostname: str,
        platform: str,
        management_address: str,
        snapshot_key: str | None,
        now: datetime,
    ) -> tuple[InventoryDevice, bool]:
        existing = next((d for d in self.t.devices.values() if d.graph_uid == graph_uid), None)
        if existing is None:
            row = InventoryDevice(
                uuid.uuid4(),
                graph_uid,
                now,
                now,
                snapshot_key,
                hostname,
                platform,
                management_address,
                "active",
                1,
                "never",
                None,
                None,
                "unplaced",
                now,
            )
            self.t.devices[row.id] = row
            return replace(row), True
        existing.last_seen, existing.latest_snapshot_key = now, snapshot_key
        existing.hostname, existing.platform, existing.management_address = (
            hostname,
            platform,
            management_address,
        )
        existing.updated_at = now
        if existing.lifecycle == Lifecycle.MISSING.value:
            existing.lifecycle = Lifecycle.ACTIVE.value
        return replace(existing), False

    async def get_device(self, device_id: uuid.UUID) -> InventoryDevice | None:
        row = self.t.devices.get(device_id)
        return replace(row) if row else None

    async def get_devices(self, device_ids: Sequence[uuid.UUID]) -> list[InventoryDevice]:
        return [replace(self.t.devices[i]) for i in device_ids if i in self.t.devices]

    async def get_device_by_graph_uid(self, graph_uid: str) -> InventoryDevice | None:
        row = next((d for d in self.t.devices.values() if d.graph_uid == graph_uid), None)
        return replace(row) if row else None

    async def get_devices_by_graph_uids(self, graph_uids: Sequence[str]) -> list[InventoryDevice]:
        wanted = set(graph_uids)
        return [replace(d) for d in self.t.devices.values() if d.graph_uid in wanted]

    async def set_lifecycle(
        self, device_id: uuid.UUID, lifecycle: Lifecycle, *, expected_revision: int, now: datetime
    ) -> InventoryDevice:
        row = self.t.devices.get(device_id)
        if row is None:
            raise NotFound("device not found")
        _stale(expected_revision, row.revision, "device")
        row.lifecycle, row.revision, row.updated_at = lifecycle.value, row.revision + 1, now
        await self.bump_generation(now)
        return replace(row)

    async def set_device_summary(
        self,
        device_id: uuid.UUID,
        *,
        now: datetime,
        collection_state: str | object = UNSET,
        last_success_at: datetime | object | None = UNSET,
        resolved_site_id: int | object | None = UNSET,
        placement_state: str | object = UNSET,
    ) -> InventoryDevice:
        row = self.t.devices.get(device_id)
        if row is None:
            raise NotFound("device not found")
        for key, value in (
            ("collection_state", collection_state),
            ("last_success_at", last_success_at),
            ("resolved_site_id", resolved_site_id),
            ("placement_state", placement_state),
        ):
            if value is not UNSET:
                setattr(row, key, value)
        row.updated_at = now
        return replace(row)

    def _observed_by_sources(self, source_ids: list[int]) -> set[uuid.UUID]:
        out = set()
        for obs in self.t.observations.values():
            tg = self.t.targets.get(obs.target_id)
            if tg and tg.source_id in source_ids and obs.state != ObservationState.ABSENT.value:
                out.add(obs.device_id)
        return out

    def _matches(self, d: InventoryDevice, f: DeviceFilters, observed: set[uuid.UUID] | None) -> bool:
        if f.lifecycles:
            if d.lifecycle not in f.lifecycles:
                return False
        elif d.lifecycle == Lifecycle.ARCHIVED.value:
            return False
        if f.q:
            q = f.q.lower()
            if (
                q not in d.hostname.lower()
                and q not in d.graph_uid.lower()
                and q not in d.management_address.lower()
            ):
                return False
        if f.site_ids and d.resolved_site_id not in f.site_ids:
            return False
        if f.platforms and d.platform not in f.platforms:
            return False
        if f.collection_states and d.collection_state not in f.collection_states:
            return False
        if f.placement_states and d.placement_state not in f.placement_states:
            return False
        return not (observed is not None and d.id not in observed)

    def _sort_value(self, d: InventoryDevice, sort: SortField) -> Any:
        if sort == SortField.NAME:
            return d.hostname.lower()
        if sort == SortField.PLATFORM:
            return d.platform
        if sort == SortField.SITE:
            return self.t.sites_rows.get(d.resolved_site_id or -1, "")
        if sort == SortField.COLLECTION_STATE:
            return d.collection_state
        return d.last_success_at or datetime(1, 1, 1, tzinfo=UTC)

    async def list_devices(
        self,
        filters: DeviceFilters,
        *,
        sort: SortField = SortField.NAME,
        direction: SortDirection = SortDirection.ASC,
        limit: int = 50,
        cursor: str | None = None,
    ) -> DevicePageResult:
        limit = max(1, min(int(limit), MAX_PAGE_LIMIT))
        state = await self.get_state()
        digest = filter_digest(filters.as_dict())
        observed = self._observed_by_sources(filters.source_ids) if filters.source_ids else None
        rows = [d for d in self.t.devices.values() if self._matches(d, filters, observed)]
        keyed = sorted(
            ((self._sort_value(d, sort), str(d.id), d) for d in rows),
            key=lambda x: (x[0], x[1]),
            reverse=direction == SortDirection.DESC,
        )
        if cursor is not None:
            try:
                pinned = decode_cursor(cursor)
            except CursorError as exc:
                raise InventoryError(str(exc)) from exc
            if (
                pinned.intent_generation != state.intent_generation
                or pinned.snapshot_key != state.read_model_snapshot_key
            ):
                raise InventoryChanged("inventory changed since this page was read; refresh")
            if pinned.sort != sort or pinned.direction != direction or pinned.filter_digest != digest:
                raise InventoryError("cursor does not match the requested sort or filters")
            last_value: Any = pinned.last_value
            if sort == SortField.LAST_SUCCESS and last_value is not None:
                last_value = datetime.fromisoformat(last_value)
            marker = (last_value, str(pinned.last_id))
            if direction == SortDirection.ASC:
                keyed = [k for k in keyed if (k[0], k[1]) > marker]
            else:
                keyed = [k for k in keyed if (k[0], k[1]) < marker]
        page = keyed[:limit]
        next_cursor = None
        if len(keyed) > limit and page:
            value, _, last = page[-1]
            next_cursor = encode_cursor(
                ListCursor(
                    snapshot_key=state.read_model_snapshot_key,
                    intent_generation=state.intent_generation,
                    sort=sort,
                    direction=direction,
                    filter_digest=digest,
                    last_value=value.isoformat() if isinstance(value, datetime) else value,
                    last_id=last.id,
                )
            )
        items = []
        for _, _, d in page:
            conns = []
            for obs in sorted(self.t.observations.values(), key=lambda o: str(o.target_id)):
                if obs.device_id != d.id or obs.state == ObservationState.ABSENT.value:
                    continue
                tg = self.t.targets[obs.target_id]
                src = self.t.sources_rows.get(tg.source_id) if tg.source_id is not None else None
                conns.append(
                    ObservingTarget(
                        tg.id,
                        tg.source_id,
                        tg.source_key,
                        src.display_name if src else "",
                        tg.host,
                        obs.state,
                        obs.authority,
                        obs.last_success_at,
                    )
                )
            conns.sort(key=lambda c: (c.source_key, c.host))
            items.append(DeviceListItem(replace(d), self.t.sites_rows.get(d.resolved_site_id or -1), conns))
        return DevicePageResult(items, next_cursor, state)

    # --- observations and publications -----------------------------------------------

    async def get_observations(self, device_id: uuid.UUID) -> list[InventoryObservation]:
        return sorted(
            (replace(o) for o in self.t.observations.values() if o.device_id == device_id),
            key=lambda o: str(o.target_id),
        )

    async def list_observations(self, target_id: uuid.UUID) -> list[InventoryObservation]:
        return sorted(
            (replace(o) for o in self.t.observations.values() if o.target_id == target_id),
            key=lambda o: str(o.device_id),
        )

    async def list_observations_for_targets(
        self, target_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, list[InventoryObservation]]:
        wanted = set(target_ids)
        out: dict[uuid.UUID, list[InventoryObservation]] = {}
        for o in sorted(self.t.observations.values(), key=lambda o: (str(o.target_id), str(o.device_id))):
            if o.target_id in wanted:
                out.setdefault(o.target_id, []).append(replace(o))
        return out

    async def upsert_observation(
        self,
        target_id: uuid.UUID,
        device_id: uuid.UUID,
        *,
        now: datetime,
        reported_location_handle: uuid.UUID | None = None,
        last_success_at: datetime | None = None,
        last_seen_snapshot_key: str | None = None,
        state: ObservationState = ObservationState.CURRENT,
        authority: Authority = Authority.COMPLETE,
        notes: dict | None = None,
    ) -> InventoryObservation:
        if target_id not in self.t.targets or device_id not in self.t.devices:
            raise NotFound("target or device not found")
        row = InventoryObservation(
            target_id,
            device_id,
            reported_location_handle,
            last_success_at,
            last_seen_snapshot_key,
            state.value,
            authority.value,
            copy.deepcopy(notes),
            now,
        )
        self.t.observations[(target_id, device_id)] = row
        return replace(row)

    async def stage_publication(
        self, snapshot_key: str, *, parent_snapshot_key: str | None, now: datetime
    ) -> InventoryPublication:
        if snapshot_key in self.t.publications:
            raise Conflict(f"publication {snapshot_key!r} already staged")
        row = InventoryPublication(
            snapshot_key,
            parent_snapshot_key,
            "staged",
            self.t.state.intent_generation,
            {},
            {},
            now,
            None,
            None,
        )
        self.t.publications[snapshot_key] = row
        return replace(row)

    async def stage_target(
        self,
        snapshot_key: str,
        target_id: uuid.UUID,
        *,
        authority: Authority,
        succeeded: bool,
        attempted_at: datetime,
    ) -> StagedTarget:
        if snapshot_key not in self.t.publications or target_id not in self.t.targets:
            raise NotFound("publication or target not found")
        row = StagedTarget(snapshot_key, target_id, authority.value, succeeded, attempted_at)
        self.t.staged_targets[(snapshot_key, target_id)] = row
        return replace(row)

    async def stage_observations(self, snapshot_key: str, rows: Sequence[StagedObservation]) -> int:
        if rows and snapshot_key not in self.t.publications:
            raise NotFound("publication or target not found")
        for r in rows:
            if r.target_id not in self.t.targets:
                raise NotFound("publication or target not found")
            self.t.staged_observations.setdefault((snapshot_key, r.target_id, r.graph_uid), replace(r))
        return len(rows)

    async def set_placement_revisions(
        self, snapshot_key: str, revisions: dict[str, dict]
    ) -> InventoryPublication:
        pub = self.t.publications.get(snapshot_key)
        if pub is None:
            raise NotFound("publication not found")
        pub.placement_revisions = copy.deepcopy(revisions)
        return replace(pub)

    def _transition(self, snapshot_key: str, allowed: tuple[str, ...], **values: Any) -> InventoryPublication:
        pub = self.t.publications.get(snapshot_key)
        if pub is None:
            raise NotFound("publication not found")
        if pub.state not in allowed:
            raise Conflict(f"publication {snapshot_key!r} is {pub.state}")
        for k, v in values.items():
            setattr(pub, k, v)
        return replace(pub)

    def _drop_staging(self, snapshot_key: str) -> None:
        for k in [k for k in self.t.staged_observations if k[0] == snapshot_key]:
            del self.t.staged_observations[k]
        for k in [k for k in self.t.staged_targets if k[0] == snapshot_key]:
            del self.t.staged_targets[k]

    async def mark_published(self, snapshot_key: str, now: datetime) -> InventoryPublication:
        return self._transition(snapshot_key, ("staged",), state="published", published_at=now)

    async def abort_publication(self, snapshot_key: str, now: datetime) -> InventoryPublication:
        pub = self._transition(snapshot_key, ("staged", "published"), state="aborted")
        self._drop_staging(snapshot_key)
        return pub

    async def apply_publication(self, snapshot_key: str, now: datetime) -> PublicationApplyReport:
        pub = self.t.publications.get(snapshot_key)
        if pub is None:
            raise NotFound("publication not found")
        if pub.state == PublicationState.APPLIED.value:
            raise Conflict(f"publication {snapshot_key!r} is already applied")
        if pub.state != PublicationState.PUBLISHED.value:
            raise Conflict(f"publication {snapshot_key!r} is {pub.state}, not published")
        newest = await self.latest_publication(PublicationState.APPLIED)
        if newest is not None and newest.created_at > pub.created_at:
            raise Conflict(f"publication {newest.snapshot_key!r} is newer and already applied")
        staged_targets = [st for (k, _), st in self.t.staged_targets.items() if k == snapshot_key]
        staged_rows = [r for (k, _, _), r in self.t.staged_observations.items() if k == snapshot_key]
        registered: list[uuid.UUID] = []
        reappeared: list[uuid.UUID] = []
        written = retired = 0
        touched: set[uuid.UUID] = set()
        for st in staged_targets:
            seen: set[uuid.UUID] = set()
            if st.succeeded:
                for r in [r for r in staged_rows if r.target_id == st.target_id]:
                    before = await self.get_device_by_graph_uid(r.graph_uid)
                    device, created = await self.register_device(
                        r.graph_uid,
                        hostname=r.hostname,
                        platform=r.platform,
                        management_address=r.management_address,
                        snapshot_key=snapshot_key,
                        now=now,
                    )
                    if created:
                        registered.append(device.id)
                    elif before is not None and before.lifecycle == Lifecycle.MISSING.value:
                        reappeared.append(device.id)
                    await self.upsert_observation(
                        st.target_id,
                        device.id,
                        now=now,
                        reported_location_handle=r.reported_location_handle,
                        last_success_at=st.attempted_at,
                        last_seen_snapshot_key=snapshot_key,
                        state=ObservationState.CURRENT,
                        authority=Authority(st.authority),
                        notes=r.notes,
                    )
                    seen.add(device.id)
                    touched.add(device.id)
                    written += 1
            leftover = (
                ObservationState.ABSENT
                if st.succeeded and st.authority == Authority.COMPLETE.value
                else ObservationState.STALE
            )
            for obs in self.t.observations.values():
                if obs.target_id != st.target_id or obs.device_id in seen or obs.state == "absent":
                    continue
                obs.state, obs.updated_at = leftover.value, now
                touched.add(obs.device_id)
                if leftover == ObservationState.ABSENT:
                    retired += 1
        missing: list[uuid.UUID] = []
        for device_id in sorted(touched, key=str):
            d = self.t.devices.get(device_id)
            if d is None or d.lifecycle == Lifecycle.ARCHIVED.value:
                continue
            live = [
                o for o in self.t.observations.values() if o.device_id == device_id and o.state != "absent"
            ]
            if not live and d.lifecycle != Lifecycle.MISSING.value:
                d.lifecycle, d.updated_at = Lifecycle.MISSING.value, now
                missing.append(device_id)
        applied = 0
        for key, captured in pub.placement_revisions.items():
            try:
                device_id = uuid.UUID(key)
            except ValueError:
                continue
            pl = self.t.placements.get(device_id)
            revision = int(captured.get("revision", 0))
            if pl is not None and pl.applied_revision <= revision:
                pl.applied_revision = revision
                pl.published_site_id = captured.get("site_id")
                pl.published_snapshot_key = snapshot_key
                applied += 1
        summary = {
            "targets": len(staged_targets),
            "staged_observations": len(staged_rows),
            "registered": len(registered),
            "reappeared": len(reappeared),
            "missing": len(missing),
            "retired": retired,
            "placements_applied": applied,
        }
        self._transition(
            snapshot_key, ("published",), state="applied", applied_at=now, staged_changes=summary
        )
        self._drop_staging(snapshot_key)
        await self.advance_read_model(snapshot_key, now)
        return PublicationApplyReport(
            snapshot_key, registered, reappeared, missing, written, retired, applied
        )

    async def get_publication(self, snapshot_key: str) -> InventoryPublication | None:
        pub = self.t.publications.get(snapshot_key)
        return replace(pub) if pub else None

    async def latest_publication(self, state: PublicationState | None = None) -> InventoryPublication | None:
        rows = [p for p in self.t.publications.values() if state is None or p.state == state.value]
        if not rows:
            return None
        return replace(max(rows, key=lambda p: p.created_at))

    # --- placements and locations --------------------------------------------------

    async def get_placement(self, device_id: uuid.UUID) -> InventoryPlacement | None:
        row = self.t.placements.get(device_id)
        return replace(row) if row else None

    async def get_placements(self, device_ids: Sequence[uuid.UUID]) -> list[InventoryPlacement]:
        return [replace(self.t.placements[i]) for i in device_ids if i in self.t.placements]

    async def set_placement(
        self,
        device_id: uuid.UUID,
        *,
        mode: PlacementMode,
        site_id: int | None,
        origin: str,
        expected_revision: int,
        actor_id: int | None,
        now: datetime,
    ) -> InventoryPlacement:
        if (mode == PlacementMode.ASSIGNED) != (site_id is not None):
            raise InventoryError("site_id is required exactly when mode is assigned")
        if site_id is not None and site_id not in self.t.sites_rows:
            raise NotFound("site not found")
        current = self.t.placements.get(device_id)
        if current is None:
            _stale(expected_revision, 0, "placement")
            if device_id not in self.t.devices:
                raise NotFound("device not found")
            row = InventoryPlacement(device_id, mode.value, site_id, origin, 1, actor_id, now)
            self.t.placements[device_id] = row
        else:
            _stale(expected_revision, current.revision, "placement")
            current.mode, current.site_id, current.origin = mode.value, site_id, origin
            current.revision, current.actor_id, current.updated_at = current.revision + 1, actor_id, now
            row = current
        await self.bump_generation(now)
        return replace(row)

    async def release_site_placements(
        self, site_id: int, *, actor_id: int | None, now: datetime
    ) -> list[uuid.UUID]:
        out = []
        for pl in self.t.placements.values():
            if pl.site_id == site_id:
                pl.mode, pl.site_id, pl.revision, pl.actor_id, pl.updated_at = (
                    "unplaced",
                    None,
                    pl.revision + 1,
                    actor_id,
                    now,
                )
                out.append(pl.device_id)
            if pl.published_site_id == site_id:
                pl.published_site_id = None
        if out:
            await self.bump_generation(now)
        return out

    async def get_location(self, handle: uuid.UUID) -> InventoryLocation | None:
        row = self.t.locations_rows.get(handle)
        return replace(row) if row else None

    async def list_locations(self, source: str | None = None) -> list[InventoryLocation]:
        rows = [replace(r) for r in self.t.locations_rows.values() if source is None or r.source == source]
        return sorted(rows, key=lambda r: (r.source, r.location_id))

    async def bind_location(
        self, handle: uuid.UUID, site: str | None, *, expected_revision: int, now: datetime
    ) -> InventoryLocation:
        row = self.t.locations_rows.get(handle)
        if row is None:
            raise NotFound("location not found")
        _stale(expected_revision, row.revision, "location")
        if site is not None and site not in self.t.sites_rows.values():
            raise NotFound("site not found")
        row.site, row.revision, row.updated_at = site, row.revision + 1, now
        await self.bump_generation(now)
        return replace(row)

    async def unbind_site_locations(self, site: str, now: datetime) -> list[uuid.UUID]:
        out = []
        for row in self.t.locations_rows.values():
            if row.site == site:
                row.site, row.revision, row.updated_at = None, row.revision + 1, now
                out.append(row.handle)
        if out:
            await self.bump_generation(now)
        return out

    # --- credentials and profiles -----------------------------------------------------

    async def create_credential(
        self,
        *,
        display_name: str,
        sealed: bytes,
        secret_paths: Sequence[str],
        actor_id: int | None,
        now: datetime,
    ) -> tuple[CollectionCredential, CollectionCredentialVersion]:
        if any(c.display_name == display_name for c in self.t.credentials.values()):
            raise Conflict(f"credential name {display_name!r} is in use")
        cred = CollectionCredential(uuid.uuid4(), display_name, 1, None, now, now)
        ver = CollectionCredentialVersion(cred.id, 1, bytes(sealed), sorted(secret_paths), now, actor_id)
        self.t.credentials[cred.id] = cred
        self.t.credential_versions[(cred.id, 1)] = ver
        return replace(cred), replace(ver)

    async def add_credential_version(
        self,
        credential_id: uuid.UUID,
        *,
        expected_revision: int,
        sealed: bytes,
        secret_paths: Sequence[str],
        actor_id: int | None,
        now: datetime,
    ) -> CollectionCredentialVersion:
        cred = self.t.credentials.get(credential_id)
        if cred is None:
            raise NotFound("credential not found")
        _stale(expected_revision, cred.current_revision, "credential")
        rev = cred.current_revision + 1
        ver = CollectionCredentialVersion(
            credential_id, rev, bytes(sealed), sorted(secret_paths), now, actor_id
        )
        self.t.credential_versions[(credential_id, rev)] = ver
        cred.current_revision, cred.updated_at = rev, now
        await self.bump_generation(now)
        return replace(ver)

    async def rename_credential(
        self, credential_id: uuid.UUID, display_name: str, *, expected_revision: int, now: datetime
    ) -> CollectionCredential:
        cred = self.t.credentials.get(credential_id)
        if cred is None:
            raise NotFound("credential not found")
        _stale(expected_revision, cred.current_revision, "credential")
        if any(c.display_name == display_name and c.id != credential_id for c in self.t.credentials.values()):
            raise Conflict(f"credential name {display_name!r} is in use")
        cred.display_name, cred.updated_at = display_name, now
        return replace(cred)

    async def get_credential(self, credential_id: uuid.UUID) -> CollectionCredential | None:
        row = self.t.credentials.get(credential_id)
        return replace(row) if row else None

    async def list_credentials(self, *, include_archived: bool = False) -> list[CollectionCredential]:
        rows = [replace(c) for c in self.t.credentials.values() if include_archived or c.archived_at is None]
        return sorted(rows, key=lambda c: c.display_name)

    async def get_credential_version(
        self, credential_id: uuid.UUID, revision: int
    ) -> CollectionCredentialVersion | None:
        row = self.t.credential_versions.get((credential_id, revision))
        return replace(row) if row else None

    async def profiles_pinning_credential(self, credential_id: uuid.UUID) -> list[uuid.UUID]:
        out = []
        for p in self.t.profiles.values():
            v = self.t.profile_versions.get((p.id, p.current_revision))
            if v and v.credential_id == credential_id and p.archived_at is None:
                out.append(p.id)
        return sorted(out, key=str)

    async def archive_credential(
        self, credential_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> CollectionCredential:
        cred = self.t.credentials.get(credential_id)
        if cred is None:
            raise NotFound("credential not found")
        _stale(expected_revision, cred.current_revision, "credential")
        users = await self.profiles_pinning_credential(credential_id)
        if users:
            raise Conflict("credential is pinned by profiles", references=[str(u) for u in users])
        cred.archived_at, cred.updated_at = now, now
        return replace(cred)

    def _check_pin(self, credential_id: uuid.UUID | None, credential_revision: int | None) -> None:
        if (credential_id is None) != (credential_revision is None):
            raise Conflict("credential version does not exist")
        if (
            credential_id is not None
            and (credential_id, credential_revision) not in self.t.credential_versions
        ):
            raise Conflict("credential version does not exist")

    async def create_profile(
        self,
        *,
        display_name: str,
        collector_type: str,
        settings: dict,
        credential_id: uuid.UUID | None,
        credential_revision: int | None,
        actor_id: int | None,
        now: datetime,
    ) -> tuple[CollectionProfile, CollectionProfileVersion]:
        if any(p.display_name == display_name for p in self.t.profiles.values()):
            raise Conflict(f"profile name {display_name!r} is in use")
        self._check_pin(credential_id, credential_revision)
        prof = CollectionProfile(uuid.uuid4(), display_name, collector_type, 1, None, now, now)
        ver = CollectionProfileVersion(
            prof.id, 1, copy.deepcopy(settings), credential_id, credential_revision, now, actor_id
        )
        self.t.profiles[prof.id] = prof
        self.t.profile_versions[(prof.id, 1)] = ver
        return replace(prof), replace(ver)

    async def add_profile_version(
        self,
        profile_id: uuid.UUID,
        *,
        expected_revision: int,
        settings: dict,
        credential_id: uuid.UUID | None,
        credential_revision: int | None,
        actor_id: int | None,
        now: datetime,
    ) -> CollectionProfileVersion:
        prof = self.t.profiles.get(profile_id)
        if prof is None:
            raise NotFound("profile not found")
        _stale(expected_revision, prof.current_revision, "profile")
        self._check_pin(credential_id, credential_revision)
        rev = prof.current_revision + 1
        ver = CollectionProfileVersion(
            profile_id, rev, copy.deepcopy(settings), credential_id, credential_revision, now, actor_id
        )
        self.t.profile_versions[(profile_id, rev)] = ver
        prof.current_revision, prof.updated_at = rev, now
        await self.bump_generation(now)
        return replace(ver)

    async def rename_profile(
        self, profile_id: uuid.UUID, display_name: str, *, expected_revision: int, now: datetime
    ) -> CollectionProfile:
        prof = self.t.profiles.get(profile_id)
        if prof is None:
            raise NotFound("profile not found")
        _stale(expected_revision, prof.current_revision, "profile")
        if any(p.display_name == display_name and p.id != profile_id for p in self.t.profiles.values()):
            raise Conflict(f"profile name {display_name!r} is in use")
        prof.display_name, prof.updated_at = display_name, now
        return replace(prof)

    async def get_profile(self, profile_id: uuid.UUID) -> CollectionProfile | None:
        row = self.t.profiles.get(profile_id)
        return replace(row) if row else None

    async def list_profiles(
        self, collector_type: str | None = None, *, include_archived: bool = False
    ) -> list[CollectionProfile]:
        rows = [
            replace(p)
            for p in self.t.profiles.values()
            if (collector_type is None or p.collector_type == collector_type)
            and (include_archived or p.archived_at is None)
        ]
        return sorted(rows, key=lambda p: p.display_name)

    async def get_profile_version(
        self, profile_id: uuid.UUID, revision: int
    ) -> CollectionProfileVersion | None:
        row = self.t.profile_versions.get((profile_id, revision))
        return replace(row) if row else None

    async def list_profile_versions(self, profile_id: uuid.UUID) -> list[CollectionProfileVersion]:
        return sorted(
            (replace(v) for (pid, _), v in self.t.profile_versions.items() if pid == profile_id),
            key=lambda v: v.revision,
        )

    async def profile_references(self, profile_id: uuid.UUID) -> ProfileReferences:
        targets = sorted(
            (x.id for x in self.t.targets.values() if x.profile_id == profile_id and x.archived_at is None),
            key=str,
        )
        srcs = sorted(s.source_id for s in self.t.sources_rows.values() if s.default_profile_id == profile_id)
        return ProfileReferences(targets, srcs)

    async def archive_profile(
        self, profile_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> CollectionProfile:
        prof = self.t.profiles.get(profile_id)
        if prof is None:
            raise NotFound("profile not found")
        _stale(expected_revision, prof.current_revision, "profile")
        refs = await self.profile_references(profile_id)
        if refs.target_ids or refs.source_ids:
            raise Conflict(
                "profile is in use",
                references=[f"target:{i}" for i in refs.target_ids]
                + [f"connection:{i}" for i in refs.source_ids],
            )
        prof.archived_at, prof.updated_at = now, now
        return replace(prof)

    # --- saved views ---------------------------------------------------------------

    async def create_view(
        self,
        *,
        owner_id: int,
        name: str,
        filter: dict,
        sort: str,
        direction: str,
        columns: Sequence[str],
        now: datetime,
        filter_version: int = 1,
    ) -> InventorySavedView:
        if any(v.owner_id == owner_id and v.name == name for v in self.t.views.values()):
            raise Conflict(f"a view named {name!r} exists")
        row = InventorySavedView(
            uuid.uuid4(),
            owner_id,
            name,
            filter_version,
            copy.deepcopy(filter),
            sort,
            direction,
            list(columns),
            1,
            now,
            now,
        )
        self.t.views[row.id] = row
        return replace(row)

    async def get_view(self, view_id: uuid.UUID, owner_id: int) -> InventorySavedView | None:
        row = self.t.views.get(view_id)
        return replace(row) if row and row.owner_id == owner_id else None

    async def list_views(self, owner_id: int) -> list[InventorySavedView]:
        return sorted(
            (replace(v) for v in self.t.views.values() if v.owner_id == owner_id), key=lambda v: v.name
        )

    async def update_view(
        self,
        view_id: uuid.UUID,
        owner_id: int,
        *,
        expected_revision: int,
        now: datetime,
        name: str | object = UNSET,
        filter: dict | object = UNSET,
        sort: str | object = UNSET,
        direction: str | object = UNSET,
        columns: Sequence[str] | object = UNSET,
    ) -> InventorySavedView:
        row = self.t.views.get(view_id)
        if row is None or row.owner_id != owner_id:
            raise NotFound("view not found")
        _stale(expected_revision, row.revision, "view")
        if name is not UNSET and any(
            v.owner_id == owner_id and v.name == name and v.id != view_id for v in self.t.views.values()
        ):
            raise Conflict("a view with that name exists")
        for key, value in (("name", name), ("filter", filter), ("sort", sort), ("direction", direction)):
            if value is not UNSET:
                setattr(row, key, copy.deepcopy(value))
        if columns is not UNSET:
            row.columns = list(columns)  # type: ignore[arg-type]
        row.revision, row.updated_at = row.revision + 1, now
        return replace(row)

    async def delete_view(
        self, view_id: uuid.UUID, owner_id: int, *, expected_revision: int | None = None
    ) -> bool:
        row = self.t.views.get(view_id)
        if row is None or row.owner_id != owner_id:
            return False
        if expected_revision is not None:
            _stale(expected_revision, row.revision, "view")
        del self.t.views[view_id]
        return True

    # --- routing groups -------------------------------------------------------------

    async def create_routing_group(
        self, *, display_name: str, description: str, now: datetime
    ) -> InventoryRoutingGroup:
        if any(g.display_name == display_name for g in self.t.groups.values()):
            raise Conflict(f"routing group {display_name!r} exists")
        row = InventoryRoutingGroup(uuid.uuid4(), display_name, description, 1, None, now, now)
        self.t.groups[row.id] = row
        await self.bump_generation(now)
        return replace(row)

    async def get_routing_group(self, group_id: uuid.UUID) -> InventoryRoutingGroup | None:
        row = self.t.groups.get(group_id)
        return replace(row) if row else None

    async def list_routing_groups(self, *, include_archived: bool = False) -> list[InventoryRoutingGroup]:
        rows = [replace(g) for g in self.t.groups.values() if include_archived or g.archived_at is None]
        return sorted(rows, key=lambda g: g.display_name)

    def _bump_group(
        self, group_id: uuid.UUID, expected_revision: int, now: datetime
    ) -> InventoryRoutingGroup:
        row = self.t.groups.get(group_id)
        if row is None:
            raise NotFound("routing group not found")
        _stale(expected_revision, row.revision, "routing group")
        row.revision, row.updated_at = row.revision + 1, now
        return row

    async def update_routing_group(
        self,
        group_id: uuid.UUID,
        *,
        expected_revision: int,
        now: datetime,
        display_name: str | object = UNSET,
        description: str | object = UNSET,
    ) -> InventoryRoutingGroup:
        if display_name is not UNSET and any(
            g.display_name == display_name and g.id != group_id for g in self.t.groups.values()
        ):
            raise Conflict("routing group name is in use")
        row = self._bump_group(group_id, expected_revision, now)
        if display_name is not UNSET:
            row.display_name = display_name  # type: ignore[assignment]
        if description is not UNSET:
            row.description = description  # type: ignore[assignment]
        await self.bump_generation(now)
        return replace(row)

    async def archive_routing_group(
        self, group_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> InventoryRoutingGroup:
        row = self._bump_group(group_id, expected_revision, now)
        row.archived_at = now
        await self.bump_generation(now)
        return replace(row)

    async def set_routing_members(
        self,
        group_id: uuid.UUID,
        *,
        expected_revision: int,
        add: Sequence[tuple[str, str]],
        remove: Sequence[str],
        actor_id: int | None,
        now: datetime,
    ) -> InventoryRoutingGroup:
        row = self._bump_group(group_id, expected_revision, now)
        for uid in remove:
            self.t.members.pop((group_id, uid), None)
        for uid, owner in add:
            self.t.members.setdefault(
                (group_id, uid), InventoryRoutingMember(group_id, uid, owner, now, actor_id)
            )
        await self.bump_generation(now)
        return replace(row)

    async def list_routing_members(self, group_id: uuid.UUID) -> list[InventoryRoutingMember]:
        return sorted(
            (replace(m) for (g, _), m in self.t.members.items() if g == group_id), key=lambda m: m.context_uid
        )

    async def groups_for_contexts(
        self, context_uids: Sequence[str]
    ) -> dict[str, list[InventoryRoutingGroup]]:
        out: dict[str, list[InventoryRoutingGroup]] = {}
        for (gid, uid), _ in sorted(self.t.members.items(), key=lambda kv: kv[0][1]):
            g = self.t.groups[gid]
            if uid in context_uids and g.archived_at is None:
                out.setdefault(uid, []).append(replace(g))
        for lst in out.values():
            lst.sort(key=lambda g: g.display_name)
        return out

    # --- previews and idempotent apply -------------------------------------------------

    async def create_preview(
        self,
        *,
        actor_id: int,
        operation: str,
        permissions: Sequence[str],
        intent_generation: int,
        snapshot_key: str | None,
        members: Sequence[dict],
        changes: dict,
        impact: dict,
        secret_draft: bytes | None,
        now: datetime,
        ttl: timedelta,
    ) -> OperationPreview:
        row = OperationPreview(
            uuid.uuid4(),
            actor_id,
            operation,
            list(permissions),
            intent_generation,
            snapshot_key,
            copy.deepcopy(list(members)),
            redact_by_key(changes),
            redact_by_key(impact),
            now,
            now + ttl,
            None,
            None,
            secret_draft,
        )
        self.t.previews[row.token] = row
        return replace(row, secret_draft=None)

    async def add_preview_impacts(self, token: uuid.UUID, rows: Sequence[tuple[str, str, dict]]) -> int:
        existing = self.t.impacts.setdefault(token, [])
        if len(existing) + len(rows) > MAX_DERIVED_IMPACT:
            raise InventoryError(f"derived impact exceeds {MAX_DERIVED_IMPACT} records; narrow the selection")
        base = len(existing)
        for i, (kind, entity_id, detail) in enumerate(rows):
            existing.append(PreviewImpact(token, base + i + 1, kind, entity_id, dict(detail)))
        return len(rows)

    async def page_preview_impacts(
        self, token: uuid.UUID, *, after_seq: int = 0, limit: int = 50
    ) -> tuple[list[PreviewImpact], int]:
        rows = self.t.impacts.get(token, [])
        page = [replace(r) for r in rows if r.seq > after_seq][: max(1, min(limit, MAX_PAGE_LIMIT))]
        return page, len(rows)

    def _preview_row(self, token: uuid.UUID, actor_id: int, now: datetime) -> OperationPreview:
        row = self.t.previews.get(token)
        if row is None or row.actor_id != actor_id:
            raise NotFound("preview not found")
        if row.consumed_at is not None:
            raise PreviewExpired("preview already applied")
        if row.expires_at <= now:
            raise PreviewExpired("preview expired")
        return row

    async def get_preview(self, token: uuid.UUID, actor_id: int, now: datetime) -> OperationPreview:
        return replace(self._preview_row(token, actor_id, now), secret_draft=None)

    async def consume_preview(
        self, token: uuid.UUID, actor_id: int, now: datetime, *, result_id: uuid.UUID | None
    ) -> OperationPreview:
        row = self._preview_row(token, actor_id, now)
        out = replace(row, consumed_at=now, result_id=result_id)
        row.consumed_at, row.result_id, row.secret_draft = now, result_id, None
        return out

    async def purge_expired_previews(self, now: datetime) -> int:
        gone = [k for k, p in self.t.previews.items() if p.expires_at <= now or p.consumed_at is not None]
        for k in gone:
            del self.t.previews[k]
            self.t.impacts.pop(k, None)
        return len(gone)

    async def check_idempotency(
        self, actor_id: int, idempotency_key: str, request_digest: str
    ) -> OperationResult | None:
        row = self.t.results.get((actor_id, idempotency_key))
        if row is None:
            return None
        if row.request_digest != request_digest:
            raise IdempotencyConflict("idempotency key reused with a different request")
        return replace(row)

    async def record_operation_result(
        self,
        *,
        actor_id: int,
        idempotency_key: str,
        request_digest: str,
        status: int,
        response: dict,
        now: datetime,
    ) -> OperationResult:
        existing = self.t.results.get((actor_id, idempotency_key))
        if existing is not None:
            if existing.request_digest == request_digest:
                return replace(existing)
            raise IdempotencyConflict("idempotency key already recorded")
        row = OperationResult(
            uuid.uuid4(), actor_id, idempotency_key, request_digest, status, redact_response(response), now
        )
        self.t.results[(actor_id, idempotency_key)] = row
        return replace(row)

    # --- events ---------------------------------------------------------------------

    async def append_event(
        self,
        *,
        entity_type: str,
        entity_id: str,
        actor_id: int | None,
        action: str,
        now: datetime,
        before: dict | None = None,
        after: dict | None = None,
        request_id: str | None = None,
        snapshot_key: str | None = None,
        sensitive: bool = False,
    ) -> InventoryEvent:
        self.t._eid += 1
        row = InventoryEvent(
            self.t._eid,
            entity_type,
            entity_id,
            actor_id,
            action,
            now,
            redact_by_key(copy.deepcopy(before)) if before is not None else None,
            redact_by_key(copy.deepcopy(after)) if after is not None else None,
            request_id,
            snapshot_key,
            sensitive,
        )
        self.t.events[row.id] = row
        return replace(row)

    async def page_events(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        before_id: int | None = None,
        limit: int = 50,
        include_sensitive: bool = True,
    ) -> tuple[list[InventoryEvent], int | None]:
        limit = max(1, min(limit, MAX_PAGE_LIMIT))
        rows = [
            replace(e)
            for e in sorted(self.t.events.values(), key=lambda e: -e.id)
            if (entity_type is None or e.entity_type == entity_type)
            and (entity_id is None or e.entity_id == entity_id)
            and (before_id is None or e.id < before_id)
            and (include_sensitive or not e.sensitive)
        ]
        page = rows[:limit]
        return page, (page[-1].id if len(rows) > limit and page else None)

    # --- outbox ---------------------------------------------------------------------

    async def enqueue_outbox(
        self, *, kind: str, dedup_key: str, payload: dict, now: datetime, max_attempts: int = 5
    ) -> OutboxItem | None:
        if any(o.dedup_key == dedup_key for o in self.t.outbox.values()):
            return None
        self.t._oid += 1
        row = OutboxItem(
            self.t._oid,
            dedup_key,
            kind,
            redact_by_key(payload),
            "pending",
            0,
            max_attempts,
            None,
            None,
            now,
            "",
            now,
            now,
        )
        self.t.outbox[row.id] = row
        return replace(row)

    async def claim_outbox(
        self, worker_id: str, *, now: datetime, lease: timedelta, batch: int = 10
    ) -> list[OutboxItem]:
        due = sorted(
            (o for o in self.t.outbox.values() if o.state == "pending" and o.next_attempt_at <= now),
            key=lambda o: (o.next_attempt_at, o.id),
        )[:batch]
        for o in due:
            o.state, o.attempt, o.claimed_by, o.lease_expires_at, o.updated_at = (
                "running",
                o.attempt + 1,
                worker_id,
                now + lease,
                now,
            )
        return [replace(o) for o in sorted(due, key=lambda o: o.id)]

    async def finish_outbox(
        self,
        item_id: int,
        *,
        ok: bool,
        now: datetime,
        claimed_by: str,
        error: str = "",
        retry_at: datetime | None = None,
    ) -> OutboxItem | None:
        o = self.t.outbox.get(item_id)
        if o is None or o.claimed_by != claimed_by or o.state != "running":
            return None
        if ok:
            o.state, o.last_error = "done", ""
        elif retry_at is not None and o.attempt < o.max_attempts:
            o.state, o.next_attempt_at, o.last_error = "pending", retry_at, error
        else:
            o.state, o.last_error = "failed", error
        o.lease_expires_at, o.claimed_by, o.updated_at = None, None, now
        return replace(o)

    async def reap_outbox(self, now: datetime) -> int:
        n = 0
        for o in self.t.outbox.values():
            if o.state == "running" and o.lease_expires_at is not None and o.lease_expires_at < now:
                o.state, o.lease_expires_at, o.claimed_by = "pending", None, None
                o.next_attempt_at, o.last_error, o.updated_at = now, "lease expired", now
                n += 1
        return n

    async def purge_outbox_done(self, before: datetime) -> int:
        gone = [k for k, o in self.t.outbox.items() if o.state == "done" and o.updated_at < before]
        for k in gone:
            del self.t.outbox[k]
        return len(gone)

    async def list_outbox(self, state: OutboxState | None = None) -> list[OutboxItem]:
        return [
            replace(o)
            for o in sorted(self.t.outbox.values(), key=lambda o: o.id)
            if state is None or o.state == state.value
        ]


class FakeInventoryRepository:
    """`InventoryRepository` in memory."""

    def __init__(self) -> None:
        self.tables = _Tables()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[FakeInventoryTx]:
        snapshot = copy.deepcopy(self.tables.__dict__)
        try:
            yield FakeInventoryTx(self.tables)
        except BaseException:
            self.tables.__dict__.clear()
            self.tables.__dict__.update(snapshot)
            raise

    # seeding helpers for tests
    def seed_source(
        self, source_id: int, name: str, type_: str = "vyos", *, enabled: bool = True
    ) -> SourceInventory:
        row = SourceInventory(source_id, name, type_, enabled, "", None, 1, None)
        self.tables.sources_rows[source_id] = row
        return row

    def seed_site(self, site_id: int, code: str) -> None:
        self.tables.sites_rows[site_id] = code

    def seed_location(
        self, source: str, location_id: str, name: str = "", site: str | None = None
    ) -> InventoryLocation:
        row = InventoryLocation(uuid.uuid4(), source, location_id, name, site, 1, datetime.now(UTC))
        self.tables.locations_rows[row.handle] = row
        return row


class InventoryFakeStore(FakeStore):
    """FakeStore plus `inventory()`, for app tests that need both."""

    def __init__(self) -> None:
        super().__init__()
        self._inventory = FakeInventoryRepository()

    def inventory(self) -> FakeInventoryRepository:
        return self._inventory
