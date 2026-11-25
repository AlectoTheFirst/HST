"""The inventory repository. It gives one transactional unit of work over the engine of the store."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from hst.app.inventory import tables as t
from hst.app.inventory.contracts import (
    MAX_DERIVED_IMPACT,
    MAX_PAGE_LIMIT,
    ActivationState,
    Authority,
    CursorError,
    ErrorCode,
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
from hst.app.store.pg import reported_locations, sites, sources

# The count of values of one IN list. asyncpg takes at most 32,767 bind parameters per statement.
_IN_CHUNK = 5000

# --- errors ------------------------------------------------------------------------


class InventoryError(Exception):
    """A refusal that the API maps to a stable error code. `status` is the HTTP status of the
    code in `ERROR_STATUS`."""

    code: ErrorCode = ErrorCode.VALIDATION
    status: int = 422

    def __init__(
        self, message: str, *, current_revision: int | None = None, references: list[str] | None = None
    ):
        super().__init__(message)
        self.current_revision = current_revision
        self.references = references or []


class StaleRevision(InventoryError):
    code = ErrorCode.STALE_REVISION
    status = 409


class NotFound(InventoryError):
    code = ErrorCode.NOT_FOUND
    status = 404


class InventoryChanged(InventoryError):
    code = ErrorCode.INVENTORY_CHANGED
    status = 409


class PreviewExpired(InventoryError):
    code = ErrorCode.PREVIEW_EXPIRED
    status = 409


class Conflict(InventoryError):
    """A write that collides with an existing record or that an existing reference forbids.

    Examples are a duplicate active target, a display name in use and the deletion of a profile
    in use. The status is 409 with the code `conflict`. `references` lists the records that
    block the write."""

    code = ErrorCode.CONFLICT
    status = 409


class IdempotencyConflict(Conflict):
    """The idempotency key was reused with a different request digest."""

    code = ErrorCode.IDEMPOTENCY_CONFLICT


# --- unit of work -------------------------------------------------------------------


class InventoryTx(Protocol):
    """The inventory operations of one transaction. The exit of the context manager commits.
    An exception rolls back the transaction."""

    @property
    def connection(self) -> AsyncConnection | None: ...

    # state
    async def get_state(self) -> InventoryState: ...
    async def bump_generation(self, now: datetime) -> int: ...
    async def activate(
        self, *, resolver_version: int, schema_version: int, backfill_version: int, now: datetime
    ) -> InventoryState: ...
    async def set_activation_state(self, state: ActivationState, now: datetime) -> InventoryState: ...
    async def advance_read_model(self, snapshot_key: str, now: datetime) -> InventoryState: ...
    async def set_sync_pending(self, pending: bool, now: datetime) -> InventoryState: ...

    # sources
    async def get_source_inventory(self, source_id: int) -> SourceInventory | None: ...
    async def get_source_inventory_by_key(self, source_key: str) -> SourceInventory | None: ...
    async def list_source_inventory(self) -> list[SourceInventory]: ...
    async def update_source_inventory(
        self,
        source_id: int,
        *,
        expected_revision: int,
        now: datetime,
        display_name: str | object = UNSET,
        default_profile_id: uuid.UUID | object | None = UNSET,
    ) -> SourceInventory: ...
    async def set_frozen_normalization(
        self, source_id: int, value: dict | None, now: datetime
    ) -> SourceInventory: ...

    # targets. `archive_*` archives a target and retires its observations.
    # `archive_source_targets` also clears the source FK and keeps `source_key`.
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
        endpoint_config: dict | None = None,
    ) -> InventoryTarget: ...
    async def get_target(self, target_id: uuid.UUID) -> InventoryTarget | None: ...
    async def get_targets(self, target_ids: Sequence[uuid.UUID]) -> list[InventoryTarget]: ...
    async def get_active_target(self, source_key: str, host: str) -> InventoryTarget | None: ...
    async def list_targets(
        self, source_id: int | None = None, *, include_archived: bool = False
    ) -> list[InventoryTarget]: ...
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
    ) -> InventoryTarget: ...
    async def archive_target(
        self, target_id: uuid.UUID, *, expected_revision: int | None, now: datetime
    ) -> InventoryTarget: ...
    async def archive_source_targets(self, source_id: int, now: datetime) -> list[InventoryTarget]: ...
    async def retire_observations(self, target_id: uuid.UUID, now: datetime) -> int: ...
    async def clear_target_source(self, source_id: int, now: datetime) -> int: ...
    async def clear_onboarding_site(self, site_id: int, now: datetime) -> int: ...

    # devices. `register_device` inserts on the first observation of a graph uid
    # and otherwise refreshes the observed summary (missing becomes active,
    # archived stays archived). `set_device_summary` writes read-model columns
    # without touching the revision or the intent generation.
    async def register_device(
        self,
        graph_uid: str,
        *,
        hostname: str,
        platform: str,
        management_address: str,
        snapshot_key: str | None,
        now: datetime,
    ) -> tuple[InventoryDevice, bool]: ...
    async def get_device(self, device_id: uuid.UUID) -> InventoryDevice | None: ...
    async def get_devices(self, device_ids: Sequence[uuid.UUID]) -> list[InventoryDevice]: ...
    async def get_device_by_graph_uid(self, graph_uid: str) -> InventoryDevice | None: ...
    async def get_devices_by_graph_uids(self, graph_uids: Sequence[str]) -> list[InventoryDevice]: ...
    async def set_lifecycle(
        self, device_id: uuid.UUID, lifecycle: Lifecycle, *, expected_revision: int, now: datetime
    ) -> InventoryDevice: ...
    async def set_device_summary(
        self,
        device_id: uuid.UUID,
        *,
        now: datetime,
        collection_state: str | object = UNSET,
        last_success_at: datetime | object | None = UNSET,
        resolved_site_id: int | object | None = UNSET,
        placement_state: str | object = UNSET,
    ) -> InventoryDevice: ...
    async def list_devices(
        self,
        filters: DeviceFilters,
        *,
        sort: SortField = SortField.NAME,
        direction: SortDirection = SortDirection.ASC,
        limit: int = 50,
        cursor: str | None = None,
    ) -> DevicePageResult: ...

    # observations and publications. The caller stages rows under a snapshot key and marks
    # the snapshot published. `apply_publication` then moves the staged facts into the read
    # model and advances the read-model key. The docstring of
    # `PgInventoryTx.apply_publication` has the replacement rules. A publication older than
    # the applied one is refused. `abort_publication` drops the staging rows.
    async def get_observations(self, device_id: uuid.UUID) -> list[InventoryObservation]: ...
    async def list_observations(self, target_id: uuid.UUID) -> list[InventoryObservation]: ...
    async def list_observations_for_targets(
        self, target_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, list[InventoryObservation]]: ...
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
    ) -> InventoryObservation: ...
    async def stage_publication(
        self, snapshot_key: str, *, parent_snapshot_key: str | None, now: datetime
    ) -> InventoryPublication: ...
    async def stage_target(
        self,
        snapshot_key: str,
        target_id: uuid.UUID,
        *,
        authority: Authority,
        succeeded: bool,
        attempted_at: datetime,
    ) -> StagedTarget: ...
    async def stage_observations(self, snapshot_key: str, rows: Sequence[StagedObservation]) -> int: ...
    async def set_placement_revisions(
        self, snapshot_key: str, revisions: dict[str, dict]
    ) -> InventoryPublication: ...
    async def mark_published(self, snapshot_key: str, now: datetime) -> InventoryPublication: ...
    async def abort_publication(self, snapshot_key: str, now: datetime) -> InventoryPublication: ...
    async def apply_publication(self, snapshot_key: str, now: datetime) -> PublicationApplyReport: ...
    async def get_publication(self, snapshot_key: str) -> InventoryPublication | None: ...
    async def latest_publication(
        self, state: PublicationState | None = None
    ) -> InventoryPublication | None: ...

    # placements and locations. A device without a placement row is at revision 0. The
    # first `set_placement` for it states expected_revision=0. Site deletion uses
    # `release_site_placements` and `unbind_site_locations`.
    async def get_placement(self, device_id: uuid.UUID) -> InventoryPlacement | None: ...
    async def get_placements(self, device_ids: Sequence[uuid.UUID]) -> list[InventoryPlacement]: ...
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
    ) -> InventoryPlacement: ...
    async def release_site_placements(
        self, site_id: int, *, actor_id: int | None, now: datetime
    ) -> list[uuid.UUID]: ...
    async def get_location(self, handle: uuid.UUID) -> InventoryLocation | None: ...
    async def list_locations(self, source: str | None = None) -> list[InventoryLocation]: ...
    async def bind_location(
        self, handle: uuid.UUID, site: str | None, *, expected_revision: int, now: datetime
    ) -> InventoryLocation: ...
    async def unbind_site_locations(self, site: str, now: datetime) -> list[uuid.UUID]: ...

    # credentials and profiles. Versions are insert-only. `sealed` is the ciphertext of
    # app/crypto.py `encrypt_secrets`, and the read methods return it as ciphertext. An
    # archive raises Conflict with `references` while references exist.
    async def create_credential(
        self,
        *,
        display_name: str,
        sealed: bytes,
        secret_paths: Sequence[str],
        actor_id: int | None,
        now: datetime,
    ) -> tuple[CollectionCredential, CollectionCredentialVersion]: ...
    async def add_credential_version(
        self,
        credential_id: uuid.UUID,
        *,
        expected_revision: int,
        sealed: bytes,
        secret_paths: Sequence[str],
        actor_id: int | None,
        now: datetime,
    ) -> CollectionCredentialVersion: ...
    async def rename_credential(
        self, credential_id: uuid.UUID, display_name: str, *, expected_revision: int, now: datetime
    ) -> CollectionCredential: ...
    async def get_credential(self, credential_id: uuid.UUID) -> CollectionCredential | None: ...
    async def list_credentials(self, *, include_archived: bool = False) -> list[CollectionCredential]: ...
    async def get_credential_version(
        self, credential_id: uuid.UUID, revision: int
    ) -> CollectionCredentialVersion | None: ...
    async def profiles_pinning_credential(self, credential_id: uuid.UUID) -> list[uuid.UUID]: ...
    async def archive_credential(
        self, credential_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> CollectionCredential: ...
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
    ) -> tuple[CollectionProfile, CollectionProfileVersion]: ...
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
    ) -> CollectionProfileVersion: ...
    async def rename_profile(
        self, profile_id: uuid.UUID, display_name: str, *, expected_revision: int, now: datetime
    ) -> CollectionProfile: ...
    async def get_profile(self, profile_id: uuid.UUID) -> CollectionProfile | None: ...
    async def list_profiles(
        self, collector_type: str | None = None, *, include_archived: bool = False
    ) -> list[CollectionProfile]: ...
    async def get_profile_version(
        self, profile_id: uuid.UUID, revision: int
    ) -> CollectionProfileVersion | None: ...
    async def list_profile_versions(self, profile_id: uuid.UUID) -> list[CollectionProfileVersion]: ...
    async def profile_references(self, profile_id: uuid.UUID) -> ProfileReferences: ...
    async def archive_profile(
        self, profile_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> CollectionProfile: ...

    # saved views
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
    ) -> InventorySavedView: ...
    async def get_view(self, view_id: uuid.UUID, owner_id: int) -> InventorySavedView | None: ...
    async def list_views(self, owner_id: int) -> list[InventorySavedView]: ...
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
    ) -> InventorySavedView: ...
    async def delete_view(
        self, view_id: uuid.UUID, owner_id: int, *, expected_revision: int | None = None
    ) -> bool: ...

    # routing groups
    async def create_routing_group(
        self, *, display_name: str, description: str, now: datetime
    ) -> InventoryRoutingGroup: ...
    async def get_routing_group(self, group_id: uuid.UUID) -> InventoryRoutingGroup | None: ...
    async def list_routing_groups(self, *, include_archived: bool = False) -> list[InventoryRoutingGroup]: ...
    async def update_routing_group(
        self,
        group_id: uuid.UUID,
        *,
        expected_revision: int,
        now: datetime,
        display_name: str | object = UNSET,
        description: str | object = UNSET,
    ) -> InventoryRoutingGroup: ...
    async def archive_routing_group(
        self, group_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> InventoryRoutingGroup: ...
    async def set_routing_members(
        self,
        group_id: uuid.UUID,
        *,
        expected_revision: int,
        add: Sequence[tuple[str, str]],
        remove: Sequence[str],
        actor_id: int | None,
        now: datetime,
    ) -> InventoryRoutingGroup: ...
    async def list_routing_members(self, group_id: uuid.UUID) -> list[InventoryRoutingMember]: ...
    async def groups_for_contexts(
        self, context_uids: Sequence[str]
    ) -> dict[str, list[InventoryRoutingGroup]]: ...

    # previews and idempotent apply. A preview is bound to its actor, and a read by another
    # actor raises NotFound. A preview expires after its ttl. `consume_preview` returns the
    # sealed draft one time and clears it. `check_idempotency` returns the stored result for
    # a repeated key and raises for a different digest.
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
    ) -> OperationPreview: ...
    async def add_preview_impacts(self, token: uuid.UUID, rows: Sequence[tuple[str, str, dict]]) -> int: ...
    async def page_preview_impacts(
        self, token: uuid.UUID, *, after_seq: int = 0, limit: int = 50
    ) -> tuple[list[PreviewImpact], int]: ...
    async def get_preview(self, token: uuid.UUID, actor_id: int, now: datetime) -> OperationPreview: ...
    async def consume_preview(
        self, token: uuid.UUID, actor_id: int, now: datetime, *, result_id: uuid.UUID | None
    ) -> OperationPreview: ...
    async def purge_expired_previews(self, now: datetime) -> int: ...
    async def check_idempotency(
        self, actor_id: int, idempotency_key: str, request_digest: str
    ) -> OperationResult | None: ...
    async def record_operation_result(
        self,
        *,
        actor_id: int,
        idempotency_key: str,
        request_digest: str,
        status: int,
        response: dict,
        now: datetime,
    ) -> OperationResult: ...

    # events
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
    ) -> InventoryEvent: ...
    async def page_events(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        before_id: int | None = None,
        limit: int = 50,
        include_sensitive: bool = True,
    ) -> tuple[list[InventoryEvent], int | None]: ...

    # outbox
    async def enqueue_outbox(
        self, *, kind: str, dedup_key: str, payload: dict, now: datetime, max_attempts: int = 5
    ) -> OutboxItem | None: ...
    async def claim_outbox(
        self, worker_id: str, *, now: datetime, lease: timedelta, batch: int = 10
    ) -> list[OutboxItem]: ...
    async def finish_outbox(
        self,
        item_id: int,
        *,
        ok: bool,
        now: datetime,
        claimed_by: str,
        error: str = "",
        retry_at: datetime | None = None,
    ) -> OutboxItem | None: ...
    async def reap_outbox(self, now: datetime) -> int: ...
    async def purge_outbox_done(self, before: datetime) -> int: ...
    async def list_outbox(self, state: OutboxState | None = None) -> list[OutboxItem]: ...


class InventoryRepository(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[InventoryTx]: ...


# --- helpers ------------------------------------------------------------------------


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _stale(expected: int, current: int, what: str) -> None:
    if expected != current:
        raise StaleRevision(f"{what} is at revision {current}, not {expected}", current_revision=current)


def redact_response(response: dict) -> dict:
    """Mask an apply response by key name before it is recorded.

    The masking is that of an event payload. The key `token` keeps its value when the value is
    a UUID. That token is the primary key of the previews table and is not secret material."""
    masked: dict = redact_by_key(response)
    token = response.get("token")
    if isinstance(token, uuid.UUID) or (isinstance(token, str) and _is_uuid(token)):
        masked["token"] = token
    return masked


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class _SortSpec:
    field: SortField
    # The sort expression over the join of `inventory_devices` and `sites` in `list_devices`.
    expr: Any
    # `encode` maps a Python value to a cursor value. `decode` maps a cursor value back.
    encode: Any
    decode: Any


def _sort_spec(sort: SortField) -> _SortSpec:
    d = t.inventory_devices.c
    if sort == SortField.NAME:
        return _SortSpec(sort, sa.func.lower(d.hostname), str, str)
    if sort == SortField.PLATFORM:
        return _SortSpec(sort, d.platform, str, str)
    if sort == SortField.SITE:
        return _SortSpec(sort, sa.func.coalesce(sites.c.code, ""), str, str)
    if sort == SortField.COLLECTION_STATE:
        return _SortSpec(sort, d.collection_state, str, str)
    # A NULL `last_success_at` (never collected) sorts as the oldest instant.
    epoch = datetime(1, 1, 1, tzinfo=UTC)
    return _SortSpec(
        sort,
        sa.func.coalesce(d.last_success_at, sa.literal(epoch)),
        lambda v: v.isoformat(),
        datetime.fromisoformat,
    )


# --- row mappers -----------------------------------------------------------------------


def _device(row: sa.Row) -> InventoryDevice:
    return InventoryDevice(
        row.id,
        row.graph_uid,
        row.first_seen,
        row.last_seen,
        row.latest_snapshot_key,
        row.hostname,
        row.platform,
        row.management_address,
        row.lifecycle,
        row.revision,
        row.collection_state,
        row.last_success_at,
        row.resolved_site_id,
        row.placement_state,
        row.updated_at,
    )


def _target(row: sa.Row) -> InventoryTarget:
    return InventoryTarget(
        row.id,
        row.source_id,
        row.source_key,
        row.host,
        row.kind,
        row.legacy_device_id,
        row.profile_id,
        row.onboarding_site_id,
        row.enabled,
        row.revision,
        row.archived_at,
        row.created_at,
        row.updated_at,
        row.endpoint_config,
    )


def _observation(row: sa.Row) -> InventoryObservation:
    return InventoryObservation(
        row.target_id,
        row.device_id,
        row.reported_location_handle,
        row.last_success_at,
        row.last_seen_snapshot_key,
        row.state,
        row.authority,
        row.notes,
        row.updated_at,
    )


def _placement(row: sa.Row) -> InventoryPlacement:
    return InventoryPlacement(
        row.device_id,
        row.mode,
        row.site_id,
        row.origin,
        row.revision,
        row.actor_id,
        row.updated_at,
        row.applied_revision,
        row.published_site_id,
        row.published_snapshot_key,
    )


def _source_inventory(row: sa.Row) -> SourceInventory:
    return SourceInventory(
        row.id,
        row.name,
        row.type,
        row.enabled,
        row.display_name,
        row.default_profile_id,
        row.inventory_revision,
        row.frozen_normalization,
    )


def _location(row: sa.Row) -> InventoryLocation:
    return InventoryLocation(
        row.handle, row.source, row.location_id, row.name, row.site, row.revision, row.updated_at
    )


def _credential(row: sa.Row) -> CollectionCredential:
    return CollectionCredential(
        row.id, row.display_name, row.current_revision, row.archived_at, row.created_at, row.updated_at
    )


def _credential_version(row: sa.Row) -> CollectionCredentialVersion:
    return CollectionCredentialVersion(
        row.credential_id,
        row.revision,
        bytes(row.sealed),
        list(row.secret_paths or []),
        row.created_at,
        row.actor_id,
    )


def _profile(row: sa.Row) -> CollectionProfile:
    return CollectionProfile(
        row.id,
        row.display_name,
        row.collector_type,
        row.current_revision,
        row.archived_at,
        row.created_at,
        row.updated_at,
    )


def _profile_version(row: sa.Row) -> CollectionProfileVersion:
    return CollectionProfileVersion(
        row.profile_id,
        row.revision,
        row.settings or {},
        row.credential_id,
        row.credential_revision,
        row.created_at,
        row.actor_id,
    )


def _event(row: sa.Row) -> InventoryEvent:
    return InventoryEvent(
        row.id,
        row.entity_type,
        row.entity_id,
        row.actor_id,
        row.action,
        row.at,
        row.before,
        row.after,
        row.request_id,
        row.snapshot_key,
        row.sensitive,
    )


def _view(row: sa.Row) -> InventorySavedView:
    return InventorySavedView(
        row.id,
        row.owner_id,
        row.name,
        row.filter_version,
        row.filter or {},
        row.sort,
        row.direction,
        list(row.columns or []),
        row.revision,
        row.created_at,
        row.updated_at,
    )


def _group(row: sa.Row) -> InventoryRoutingGroup:
    return InventoryRoutingGroup(
        row.id,
        row.display_name,
        row.description,
        row.revision,
        row.archived_at,
        row.created_at,
        row.updated_at,
    )


def _member(row: sa.Row) -> InventoryRoutingMember:
    return InventoryRoutingMember(row.group_id, row.context_uid, row.owner_uid, row.added_at, row.actor_id)


def _state(row: sa.Row) -> InventoryState:
    return InventoryState(
        row.resolver_version,
        row.schema_version,
        row.backfill_version,
        row.activation_state,
        row.read_model_snapshot_key,
        row.intent_generation,
        row.inventory_sync_pending,
        row.updated_at,
    )


def _publication(row: sa.Row) -> InventoryPublication:
    return InventoryPublication(
        row.snapshot_key,
        row.parent_snapshot_key,
        row.state,
        row.intent_generation,
        row.staged_changes or {},
        row.placement_revisions or {},
        row.created_at,
        row.published_at,
        row.applied_at,
    )


def _staged_target(row: sa.Row) -> StagedTarget:
    return StagedTarget(row.snapshot_key, row.target_id, row.authority, row.succeeded, row.attempted_at)


def _preview(row: sa.Row, *, with_draft: bool) -> OperationPreview:
    return OperationPreview(
        row.token,
        row.actor_id,
        row.operation,
        list(row.permissions or []),
        row.intent_generation,
        row.snapshot_key,
        list(row.members or []),
        row.changes or {},
        row.impact or {},
        row.created_at,
        row.expires_at,
        row.consumed_at,
        row.result_id,
        bytes(row.secret_draft) if with_draft and row.secret_draft is not None else None,
    )


def _impact(row: sa.Row) -> PreviewImpact:
    return PreviewImpact(row.token, row.seq, row.kind, row.entity_id, row.detail or {})


def _result(row: sa.Row) -> OperationResult:
    return OperationResult(
        row.id,
        row.actor_id,
        row.idempotency_key,
        row.request_digest,
        row.status,
        row.response or {},
        row.created_at,
    )


def _outbox(row: sa.Row) -> OutboxItem:
    return OutboxItem(
        row.id,
        row.dedup_key,
        row.kind,
        row.payload or {},
        row.state,
        row.attempt,
        row.max_attempts,
        row.lease_expires_at,
        row.claimed_by,
        row.next_attempt_at,
        row.last_error,
        row.created_at,
        row.updated_at,
    )


# --- Postgres implementation ------------------------------------------------------------


class PgInventoryTx:
    """`InventoryTx` over one `AsyncConnection` inside one transaction."""

    def __init__(self, conn: AsyncConnection) -> None:
        self._c = conn

    @property
    def connection(self) -> AsyncConnection:
        return self._c

    async def _guarded(self, stmt: Any, params: Any = None) -> Any:
        """Run one statement under a savepoint."""
        async with self._c.begin_nested():
            if params is None:
                return await self._c.execute(stmt)
            return await self._c.execute(stmt, params)

    async def _lock(self, table: sa.Table, where: Any) -> None:
        """Lock the row of `table` that matches `where` until the transaction
        ends. A second writer of the row waits in this call. The revision that
        it reads next is the committed one."""
        await self._c.execute(
            sa.select(sa.literal(1)).select_from(table).where(where).with_for_update(key_share=True)
        )

    # --- state ---------------------------------------------------------------------

    async def _ensure_state(self) -> None:
        from sqlalchemy.dialects.postgresql import insert

        stmt = insert(t.inventory_state).values(id=1, updated_at=datetime.now(UTC)).on_conflict_do_nothing()
        await self._c.execute(stmt)

    async def get_state(self) -> InventoryState:
        row = (await self._c.execute(t.inventory_state.select().where(t.inventory_state.c.id == 1))).first()
        if row is None:
            return InventoryState(
                1, 1, 0, ActivationState.INACTIVE.value, None, 1, False, datetime.fromtimestamp(0, UTC)
            )
        return _state(row)

    async def bump_generation(self, now: datetime) -> int:
        await self._ensure_state()
        gen = (
            await self._c.execute(
                t.inventory_state.update()
                .where(t.inventory_state.c.id == 1)
                .values(intent_generation=t.inventory_state.c.intent_generation + 1, updated_at=now)
                .returning(t.inventory_state.c.intent_generation)
            )
        ).scalar_one()
        return int(gen)

    async def _update_state(self, now: datetime, **values: Any) -> InventoryState:
        await self._ensure_state()
        row = (
            await self._c.execute(
                t.inventory_state.update()
                .where(t.inventory_state.c.id == 1)
                .values(updated_at=now, **values)
                .returning(t.inventory_state)
            )
        ).one()
        return _state(row)

    async def activate(
        self, *, resolver_version: int, schema_version: int, backfill_version: int, now: datetime
    ) -> InventoryState:
        return await self._update_state(
            now,
            resolver_version=resolver_version,
            schema_version=schema_version,
            backfill_version=backfill_version,
            activation_state=ActivationState.ACTIVE.value,
        )

    async def set_activation_state(self, state: ActivationState, now: datetime) -> InventoryState:
        return await self._update_state(now, activation_state=state.value)

    async def advance_read_model(self, snapshot_key: str, now: datetime) -> InventoryState:
        return await self._update_state(
            now, read_model_snapshot_key=snapshot_key, inventory_sync_pending=False
        )

    async def set_sync_pending(self, pending: bool, now: datetime) -> InventoryState:
        return await self._update_state(now, inventory_sync_pending=pending)

    # --- sources -------------------------------------------------------------------

    _source_cols = (
        sources.c.id,
        sources.c.name,
        sources.c.type,
        sources.c.enabled,
        sources.c.display_name,
        sources.c.default_profile_id,
        sources.c.inventory_revision,
        sources.c.frozen_normalization,
    )

    async def get_source_inventory(self, source_id: int) -> SourceInventory | None:
        row = (await self._c.execute(sa.select(*self._source_cols).where(sources.c.id == source_id))).first()
        return _source_inventory(row) if row else None

    async def get_source_inventory_by_key(self, source_key: str) -> SourceInventory | None:
        row = (
            await self._c.execute(sa.select(*self._source_cols).where(sources.c.name == source_key))
        ).first()
        return _source_inventory(row) if row else None

    async def list_source_inventory(self) -> list[SourceInventory]:
        rows = (await self._c.execute(sa.select(*self._source_cols).order_by(sources.c.name))).all()
        return [_source_inventory(r) for r in rows]

    async def update_source_inventory(
        self,
        source_id: int,
        *,
        expected_revision: int,
        now: datetime,
        display_name: str | object = UNSET,
        default_profile_id: uuid.UUID | object | None = UNSET,
    ) -> SourceInventory:
        await self._lock(sources, sources.c.id == source_id)
        current = await self.get_source_inventory(source_id)
        if current is None:
            raise NotFound("connection not found")
        _stale(expected_revision, current.inventory_revision, "connection")
        values: dict[str, Any] = {"inventory_revision": current.inventory_revision + 1, "updated_at": now}
        if display_name is not UNSET:
            values["display_name"] = display_name
        if default_profile_id is not UNSET:
            values["default_profile_id"] = default_profile_id
        try:
            await self._guarded(sources.update().where(sources.c.id == source_id).values(**values))
        except IntegrityError as exc:
            raise Conflict("profile does not exist") from exc
        await self.bump_generation(now)
        updated = await self.get_source_inventory(source_id)
        if updated is None:
            raise NotFound("connection not found")
        return updated

    async def set_frozen_normalization(
        self, source_id: int, value: dict | None, now: datetime
    ) -> SourceInventory:
        await self._c.execute(
            sources.update()
            .where(sources.c.id == source_id)
            .values(frozen_normalization=value, updated_at=now)
        )
        current = await self.get_source_inventory(source_id)
        if current is None:
            raise NotFound("connection not found")
        return current

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
        endpoint_config: dict | None = None,
    ) -> InventoryTarget:
        try:
            row = (
                await self._guarded(
                    t.inventory_targets.insert()
                    .values(
                        id=_uuid(),
                        source_id=source_id,
                        source_key=source_key,
                        host=host,
                        kind=kind,
                        legacy_device_id=legacy_device_id,
                        profile_id=profile_id,
                        onboarding_site_id=onboarding_site_id,
                        enabled=enabled,
                        endpoint_config=endpoint_config or {},
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(t.inventory_targets)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(
                f"an active target for ({source_key!r}, {host!r}) exists or a reference is invalid"
            ) from exc
        await self.bump_generation(now)
        return _target(row)

    async def get_target(self, target_id: uuid.UUID) -> InventoryTarget | None:
        row = (
            await self._c.execute(t.inventory_targets.select().where(t.inventory_targets.c.id == target_id))
        ).first()
        return _target(row) if row else None

    async def get_targets(self, target_ids: Sequence[uuid.UUID]) -> list[InventoryTarget]:
        if not target_ids:
            return []
        rows = (
            await self._c.execute(
                t.inventory_targets.select().where(t.inventory_targets.c.id.in_(list(target_ids)))
            )
        ).all()
        return [_target(r) for r in rows]

    async def get_active_target(self, source_key: str, host: str) -> InventoryTarget | None:
        row = (
            await self._c.execute(
                t.inventory_targets.select().where(
                    t.inventory_targets.c.source_key == source_key,
                    t.inventory_targets.c.host == host,
                    t.inventory_targets.c.archived_at.is_(None),
                )
            )
        ).first()
        return _target(row) if row else None

    async def list_targets(
        self, source_id: int | None = None, *, include_archived: bool = False
    ) -> list[InventoryTarget]:
        stmt = t.inventory_targets.select().order_by(
            t.inventory_targets.c.source_key, t.inventory_targets.c.host
        )
        if source_id is not None:
            stmt = stmt.where(t.inventory_targets.c.source_id == source_id)
        if not include_archived:
            stmt = stmt.where(t.inventory_targets.c.archived_at.is_(None))
        return [_target(r) for r in (await self._c.execute(stmt)).all()]

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
        await self._lock(t.inventory_targets, t.inventory_targets.c.id == target_id)
        current = await self.get_target(target_id)
        if current is None:
            raise NotFound("target not found")
        _stale(expected_revision, current.revision, "target")
        values: dict[str, Any] = {"revision": current.revision + 1, "updated_at": now}
        for key, value in (
            ("enabled", enabled),
            ("profile_id", profile_id),
            ("onboarding_site_id", onboarding_site_id),
            ("legacy_device_id", legacy_device_id),
        ):
            if value is not UNSET:
                values[key] = value
        try:
            row = (
                await self._guarded(
                    t.inventory_targets.update()
                    .where(t.inventory_targets.c.id == target_id)
                    .values(**values)
                    .returning(t.inventory_targets)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict("target update references a record that does not exist") from exc
        await self.bump_generation(now)
        return _target(row)

    async def archive_target(
        self, target_id: uuid.UUID, *, expected_revision: int | None, now: datetime
    ) -> InventoryTarget:
        await self._lock(t.inventory_targets, t.inventory_targets.c.id == target_id)
        current = await self.get_target(target_id)
        if current is None:
            raise NotFound("target not found")
        if expected_revision is not None:
            _stale(expected_revision, current.revision, "target")
        if current.archived_at is not None:
            return current
        row = (
            await self._c.execute(
                t.inventory_targets.update()
                .where(t.inventory_targets.c.id == target_id)
                .values(archived_at=now, enabled=False, revision=current.revision + 1, updated_at=now)
                .returning(t.inventory_targets)
            )
        ).one()
        await self.retire_observations(target_id, now)
        await self.bump_generation(now)
        return _target(row)

    async def archive_source_targets(self, source_id: int, now: datetime) -> list[InventoryTarget]:
        """Archive every active target of a source, for a source deletion.

        Each target is archived and its observations are retired. The source FK is cleared and
        `source_key` stays. Devices, placements and events do not change."""
        archived = []
        for target in await self.list_targets(source_id):
            archived.append(await self.archive_target(target.id, expected_revision=None, now=now))
        await self.clear_target_source(source_id, now)
        return [InventoryTarget(**{**a.__dict__, "source_id": None}) for a in archived]

    async def retire_observations(self, target_id: uuid.UUID, now: datetime) -> int:
        result = await self._c.execute(
            t.inventory_observations.update()
            .where(
                t.inventory_observations.c.target_id == target_id,
                t.inventory_observations.c.state != ObservationState.ABSENT.value,
            )
            .values(state=ObservationState.ABSENT.value, updated_at=now)
        )
        return int(result.rowcount or 0)

    async def clear_target_source(self, source_id: int, now: datetime) -> int:
        result = await self._c.execute(
            t.inventory_targets.update()
            .where(t.inventory_targets.c.source_id == source_id)
            .values(source_id=None, updated_at=now)
        )
        return int(result.rowcount or 0)

    async def clear_onboarding_site(self, site_id: int, now: datetime) -> int:
        result = await self._c.execute(
            t.inventory_targets.update()
            .where(t.inventory_targets.c.onboarding_site_id == site_id)
            .values(onboarding_site_id=None, updated_at=now)
        )
        return int(result.rowcount or 0)

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
        """Insert the device on its first observation. Otherwise refresh the observed summary.

        A missing device becomes active. An archived device stays archived, and its summary is
        refreshed."""
        existing = await self.get_device_by_graph_uid(graph_uid)
        if existing is None:
            row = (
                await self._c.execute(
                    t.inventory_devices.insert()
                    .values(
                        id=_uuid(),
                        graph_uid=graph_uid,
                        first_seen=now,
                        last_seen=now,
                        latest_snapshot_key=snapshot_key,
                        hostname=hostname,
                        platform=platform,
                        management_address=management_address,
                        updated_at=now,
                    )
                    .returning(t.inventory_devices)
                )
            ).one()
            return _device(row), True
        values: dict[str, Any] = {
            "last_seen": now,
            "latest_snapshot_key": snapshot_key,
            "hostname": hostname,
            "platform": platform,
            "management_address": management_address,
            "updated_at": now,
        }
        if existing.lifecycle == Lifecycle.MISSING.value:
            values["lifecycle"] = Lifecycle.ACTIVE.value
        row = (
            await self._c.execute(
                t.inventory_devices.update()
                .where(t.inventory_devices.c.id == existing.id)
                .values(**values)
                .returning(t.inventory_devices)
            )
        ).one()
        return _device(row), False

    async def get_device(self, device_id: uuid.UUID) -> InventoryDevice | None:
        row = (
            await self._c.execute(t.inventory_devices.select().where(t.inventory_devices.c.id == device_id))
        ).first()
        return _device(row) if row else None

    async def get_devices(self, device_ids: Sequence[uuid.UUID]) -> list[InventoryDevice]:
        out: list[InventoryDevice] = []
        for start in range(0, len(device_ids), _IN_CHUNK):
            rows = (
                await self._c.execute(
                    t.inventory_devices.select().where(
                        t.inventory_devices.c.id.in_(list(device_ids[start : start + _IN_CHUNK]))
                    )
                )
            ).all()
            out.extend(_device(r) for r in rows)
        return out

    async def get_devices_by_graph_uids(self, graph_uids: Sequence[str]) -> list[InventoryDevice]:
        out: list[InventoryDevice] = []
        for start in range(0, len(graph_uids), _IN_CHUNK):
            rows = (
                await self._c.execute(
                    t.inventory_devices.select().where(
                        t.inventory_devices.c.graph_uid.in_(list(graph_uids[start : start + _IN_CHUNK]))
                    )
                )
            ).all()
            out.extend(_device(r) for r in rows)
        return out

    async def get_device_by_graph_uid(self, graph_uid: str) -> InventoryDevice | None:
        row = (
            await self._c.execute(
                t.inventory_devices.select().where(t.inventory_devices.c.graph_uid == graph_uid)
            )
        ).first()
        return _device(row) if row else None

    async def set_lifecycle(
        self, device_id: uuid.UUID, lifecycle: Lifecycle, *, expected_revision: int, now: datetime
    ) -> InventoryDevice:
        await self._lock(t.inventory_devices, t.inventory_devices.c.id == device_id)
        current = await self.get_device(device_id)
        if current is None:
            raise NotFound("device not found")
        _stale(expected_revision, current.revision, "device")
        row = (
            await self._c.execute(
                t.inventory_devices.update()
                .where(t.inventory_devices.c.id == device_id)
                .values(lifecycle=lifecycle.value, revision=current.revision + 1, updated_at=now)
                .returning(t.inventory_devices)
            )
        ).one()
        await self.bump_generation(now)
        return _device(row)

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
        values: dict[str, Any] = {"updated_at": now}
        for key, value in (
            ("collection_state", collection_state),
            ("last_success_at", last_success_at),
            ("resolved_site_id", resolved_site_id),
            ("placement_state", placement_state),
        ):
            if value is not UNSET:
                values[key] = value
        row = (
            await self._c.execute(
                t.inventory_devices.update()
                .where(t.inventory_devices.c.id == device_id)
                .values(**values)
                .returning(t.inventory_devices)
            )
        ).first()
        if row is None:
            raise NotFound("device not found")
        return _device(row)

    def _device_where(self, filters: DeviceFilters) -> list[Any]:
        d = t.inventory_devices.c
        where: list[Any] = []
        if filters.lifecycles:
            where.append(d.lifecycle.in_(filters.lifecycles))
        else:
            where.append(d.lifecycle != Lifecycle.ARCHIVED.value)
        if filters.q:
            needle = f"%{filters.q.lower()}%"
            where.append(
                sa.or_(
                    sa.func.lower(d.hostname).like(needle),
                    sa.func.lower(d.graph_uid).like(needle),
                    sa.func.lower(d.management_address).like(needle),
                )
            )
        if filters.site_ids:
            where.append(d.resolved_site_id.in_(filters.site_ids))
        if filters.platforms:
            where.append(d.platform.in_(filters.platforms))
        if filters.collection_states:
            where.append(d.collection_state.in_(filters.collection_states))
        if filters.placement_states:
            where.append(d.placement_state.in_(filters.placement_states))
        if filters.source_ids:
            o, tg = t.inventory_observations.c, t.inventory_targets.c
            observed = (
                sa.select(o.device_id)
                .select_from(t.inventory_observations.join(t.inventory_targets, tg.id == o.target_id))
                .where(tg.source_id.in_(filters.source_ids), o.state != ObservationState.ABSENT.value)
            )
            where.append(d.id.in_(observed))
        return where

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
        spec = _sort_spec(sort)
        d = t.inventory_devices.c
        stmt = (
            sa.select(t.inventory_devices, sites.c.code.label("site_code"), spec.expr.label("sort_value"))
            .select_from(t.inventory_devices.outerjoin(sites, sites.c.id == d.resolved_site_id))
            .where(*self._device_where(filters))
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
            last_value = spec.decode(pinned.last_value) if pinned.last_value is not None else None
            key = sa.tuple_(spec.expr, d.id)
            marker = sa.tuple_(sa.literal(last_value), sa.literal(pinned.last_id))
            stmt = stmt.where(key > marker if direction == SortDirection.ASC else key < marker)
        if direction == SortDirection.ASC:
            stmt = stmt.order_by(spec.expr.asc(), d.id.asc())
        else:
            stmt = stmt.order_by(spec.expr.desc(), d.id.desc())
        rows = (await self._c.execute(stmt.limit(limit + 1))).all()
        page = rows[:limit]
        next_cursor = None
        if len(rows) > limit and page:
            last = page[-1]
            next_cursor = encode_cursor(
                ListCursor(
                    snapshot_key=state.read_model_snapshot_key,
                    intent_generation=state.intent_generation,
                    sort=sort,
                    direction=direction,
                    filter_digest=digest,
                    last_value=spec.encode(last.sort_value) if last.sort_value is not None else None,
                    last_id=last.id,
                )
            )
        connections = await self._observing(list({r.id for r in page}))
        items = [DeviceListItem(_device(r), r.site_code, connections.get(r.id, [])) for r in page]
        return DevicePageResult(items, next_cursor, state)

    async def _observing(self, device_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[ObservingTarget]]:
        """Return, in one query for the page, each observation that is not absent with its
        target and the display name of its connection."""
        if not device_ids:
            return {}
        o, tg = t.inventory_observations.c, t.inventory_targets.c
        stmt = (
            sa.select(
                o.device_id,
                tg.id.label("target_id"),
                tg.source_id,
                tg.source_key,
                sa.func.coalesce(sources.c.display_name, "").label("display_name"),
                tg.host,
                o.state,
                o.authority,
                o.last_success_at,
            )
            .select_from(
                t.inventory_observations.join(t.inventory_targets, tg.id == o.target_id).outerjoin(
                    sources, sources.c.id == tg.source_id
                )
            )
            .where(o.device_id.in_(device_ids), o.state != ObservationState.ABSENT.value)
            .order_by(tg.source_key, tg.host)
        )
        out: dict[uuid.UUID, list[ObservingTarget]] = {}
        for r in (await self._c.execute(stmt)).all():
            out.setdefault(r.device_id, []).append(
                ObservingTarget(
                    r.target_id,
                    r.source_id,
                    r.source_key,
                    r.display_name,
                    r.host,
                    r.state,
                    r.authority,
                    r.last_success_at,
                )
            )
        return out

    # --- observations and publications -----------------------------------------------

    async def get_observations(self, device_id: uuid.UUID) -> list[InventoryObservation]:
        rows = (
            await self._c.execute(
                t.inventory_observations.select()
                .where(t.inventory_observations.c.device_id == device_id)
                .order_by(t.inventory_observations.c.target_id)
            )
        ).all()
        return [_observation(r) for r in rows]

    async def list_observations(self, target_id: uuid.UUID) -> list[InventoryObservation]:
        rows = (
            await self._c.execute(
                t.inventory_observations.select()
                .where(t.inventory_observations.c.target_id == target_id)
                .order_by(t.inventory_observations.c.device_id)
            )
        ).all()
        return [_observation(r) for r in rows]

    async def list_observations_for_targets(
        self, target_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, list[InventoryObservation]]:
        """The observations of every target in `target_ids`, each list in `list_observations` order."""
        out: dict[uuid.UUID, list[InventoryObservation]] = {}
        for start in range(0, len(target_ids), _IN_CHUNK):
            rows = (
                await self._c.execute(
                    t.inventory_observations.select()
                    .where(
                        t.inventory_observations.c.target_id.in_(list(target_ids[start : start + _IN_CHUNK]))
                    )
                    .order_by(t.inventory_observations.c.target_id, t.inventory_observations.c.device_id)
                )
            ).all()
            for row in rows:
                out.setdefault(row.target_id, []).append(_observation(row))
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
        from sqlalchemy.dialects.postgresql import insert

        values = {
            "reported_location_handle": reported_location_handle,
            "last_success_at": last_success_at,
            "last_seen_snapshot_key": last_seen_snapshot_key,
            "state": state.value,
            "authority": authority.value,
            "notes": notes,
            "updated_at": now,
        }
        stmt = (
            insert(t.inventory_observations)
            .values(target_id=target_id, device_id=device_id, **values)
            .on_conflict_do_update(index_elements=["target_id", "device_id"], set_=values)
            .returning(t.inventory_observations)
        )
        try:
            row = (await self._guarded(stmt)).one()
        except IntegrityError as exc:
            raise NotFound("target or device not found") from exc
        return _observation(row)

    async def stage_publication(
        self, snapshot_key: str, *, parent_snapshot_key: str | None, now: datetime
    ) -> InventoryPublication:
        state = await self.get_state()
        try:
            row = (
                await self._guarded(
                    t.inventory_publications.insert()
                    .values(
                        snapshot_key=snapshot_key,
                        parent_snapshot_key=parent_snapshot_key,
                        intent_generation=state.intent_generation,
                        created_at=now,
                    )
                    .returning(t.inventory_publications)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"publication {snapshot_key!r} already staged") from exc
        return _publication(row)

    async def stage_target(
        self,
        snapshot_key: str,
        target_id: uuid.UUID,
        *,
        authority: Authority,
        succeeded: bool,
        attempted_at: datetime,
    ) -> StagedTarget:
        from sqlalchemy.dialects.postgresql import insert

        values = {"authority": authority.value, "succeeded": succeeded, "attempted_at": attempted_at}
        stmt = (
            insert(t.inventory_staged_targets)
            .values(snapshot_key=snapshot_key, target_id=target_id, **values)
            .on_conflict_do_update(index_elements=["snapshot_key", "target_id"], set_=values)
            .returning(t.inventory_staged_targets)
        )
        try:
            row = (await self._guarded(stmt)).one()
        except IntegrityError as exc:
            raise NotFound("publication or target not found") from exc
        return _staged_target(row)

    async def stage_observations(self, snapshot_key: str, rows: Sequence[StagedObservation]) -> int:
        from sqlalchemy.dialects.postgresql import insert

        if not rows:
            return 0
        payload = [
            {
                "snapshot_key": snapshot_key,
                "target_id": r.target_id,
                "graph_uid": r.graph_uid,
                "hostname": r.hostname,
                "platform": r.platform,
                "management_address": r.management_address,
                "reported_location_handle": r.reported_location_handle,
                "notes": r.notes,
            }
            for r in rows
        ]
        stmt = insert(t.inventory_staged_observations).on_conflict_do_nothing()
        try:
            await self._guarded(stmt, payload)
        except IntegrityError as exc:
            raise NotFound("publication or target not found") from exc
        return len(payload)

    async def set_placement_revisions(
        self, snapshot_key: str, revisions: dict[str, dict]
    ) -> InventoryPublication:
        row = (
            await self._c.execute(
                t.inventory_publications.update()
                .where(t.inventory_publications.c.snapshot_key == snapshot_key)
                .values(placement_revisions=revisions)
                .returning(t.inventory_publications)
            )
        ).first()
        if row is None:
            raise NotFound("publication not found")
        return _publication(row)

    async def _transition(
        self, snapshot_key: str, allowed: tuple[str, ...], **values: Any
    ) -> InventoryPublication:
        row = (
            await self._c.execute(
                t.inventory_publications.update()
                .where(
                    t.inventory_publications.c.snapshot_key == snapshot_key,
                    t.inventory_publications.c.state.in_(allowed),
                )
                .values(**values)
                .returning(t.inventory_publications)
            )
        ).first()
        if row is None:
            current = await self.get_publication(snapshot_key)
            if current is None:
                raise NotFound("publication not found")
            raise Conflict(f"publication {snapshot_key!r} is {current.state}")
        return _publication(row)

    async def mark_published(self, snapshot_key: str, now: datetime) -> InventoryPublication:
        return await self._transition(
            snapshot_key,
            (PublicationState.STAGED.value,),
            state=PublicationState.PUBLISHED.value,
            published_at=now,
        )

    async def abort_publication(self, snapshot_key: str, now: datetime) -> InventoryPublication:
        pub = await self._transition(
            snapshot_key,
            (PublicationState.STAGED.value, PublicationState.PUBLISHED.value),
            state=PublicationState.ABORTED.value,
        )
        await self._c.execute(
            t.inventory_staged_observations.delete().where(
                t.inventory_staged_observations.c.snapshot_key == snapshot_key
            )
        )
        await self._c.execute(
            t.inventory_staged_targets.delete().where(
                t.inventory_staged_targets.c.snapshot_key == snapshot_key
            )
        )
        return pub

    async def apply_publication(self, snapshot_key: str, now: datetime) -> PublicationApplyReport:
        """Move the staged facts of a published snapshot into the read model.

        A complete successful target replaces the membership and location claims of that
        target, and an empty result retires all of them. A partial target updates the devices
        that it reported and marks the rest of its claims stale. A failed target marks all of
        its claims stale. A device without an observation that is not absent becomes missing. A
        missing device that is seen again becomes active. An archived device keeps its
        lifecycle. Then the captured placement revisions are applied and the read-model key
        advances. A publication older than the applied one is refused."""
        pub = await self.get_publication(snapshot_key)
        if pub is None:
            raise NotFound("publication not found")
        if pub.state == PublicationState.APPLIED.value:
            raise Conflict(f"publication {snapshot_key!r} is already applied")
        if pub.state != PublicationState.PUBLISHED.value:
            raise Conflict(f"publication {snapshot_key!r} is {pub.state}, not published")
        newest = await self.latest_publication(PublicationState.APPLIED)
        if newest is not None and newest.created_at > pub.created_at:
            raise Conflict(f"publication {newest.snapshot_key!r} is newer and already applied")

        staged_targets = [
            _staged_target(r)
            for r in (
                await self._c.execute(
                    t.inventory_staged_targets.select().where(
                        t.inventory_staged_targets.c.snapshot_key == snapshot_key
                    )
                )
            ).all()
        ]
        staged_rows = (
            await self._c.execute(
                t.inventory_staged_observations.select().where(
                    t.inventory_staged_observations.c.snapshot_key == snapshot_key
                )
            )
        ).all()
        by_target: dict[uuid.UUID, list[sa.Row]] = {}
        for r in staged_rows:
            by_target.setdefault(r.target_id, []).append(r)

        registered: list[uuid.UUID] = []
        reappeared: list[uuid.UUID] = []
        written = 0
        retired = 0
        touched_devices: set[uuid.UUID] = set()
        for st in staged_targets:
            reported = by_target.get(st.target_id, [])
            seen: set[uuid.UUID] = set()
            if st.succeeded:
                for r in reported:
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
                    touched_devices.add(device.id)
                    written += 1
            # A claim that this target did not repeat becomes absent after a complete
            # result, and stale after a partial or failed result.
            leftover_state = (
                ObservationState.ABSENT
                if st.succeeded and st.authority == Authority.COMPLETE.value
                else ObservationState.STALE
            )
            for obs in await self.list_observations(st.target_id):
                if obs.device_id in seen or obs.state == ObservationState.ABSENT.value:
                    continue
                await self._c.execute(
                    t.inventory_observations.update()
                    .where(
                        t.inventory_observations.c.target_id == st.target_id,
                        t.inventory_observations.c.device_id == obs.device_id,
                    )
                    .values(state=leftover_state.value, updated_at=now)
                )
                touched_devices.add(obs.device_id)
                if leftover_state == ObservationState.ABSENT:
                    retired += 1

        missing: list[uuid.UUID] = []
        for device_id in sorted(touched_devices, key=str):
            touched = await self.get_device(device_id)
            if touched is None or touched.lifecycle == Lifecycle.ARCHIVED.value:
                continue
            live = [
                o for o in await self.get_observations(device_id) if o.state != ObservationState.ABSENT.value
            ]
            if not live and touched.lifecycle != Lifecycle.MISSING.value:
                await self._c.execute(
                    t.inventory_devices.update()
                    .where(t.inventory_devices.c.id == device_id)
                    .values(lifecycle=Lifecycle.MISSING.value, updated_at=now)
                )
                missing.append(device_id)

        placements_applied = 0
        for device_key, captured in pub.placement_revisions.items():
            try:
                device_id = uuid.UUID(device_key)
            except ValueError:
                continue
            revision = int(captured.get("revision", 0))
            site_id = captured.get("site_id")
            result = await self._c.execute(
                t.inventory_placements.update()
                .where(
                    t.inventory_placements.c.device_id == device_id,
                    t.inventory_placements.c.applied_revision <= revision,
                )
                .values(
                    applied_revision=revision,
                    published_site_id=site_id,
                    published_snapshot_key=snapshot_key,
                )
            )
            placements_applied += int(result.rowcount or 0)

        summary = {
            "targets": len(staged_targets),
            "staged_observations": len(staged_rows),
            "registered": len(registered),
            "reappeared": len(reappeared),
            "missing": len(missing),
            "retired": retired,
            "placements_applied": placements_applied,
        }
        await self._transition(
            snapshot_key,
            (PublicationState.PUBLISHED.value,),
            state=PublicationState.APPLIED.value,
            applied_at=now,
            staged_changes=summary,
        )
        await self._c.execute(
            t.inventory_staged_observations.delete().where(
                t.inventory_staged_observations.c.snapshot_key == snapshot_key
            )
        )
        await self._c.execute(
            t.inventory_staged_targets.delete().where(
                t.inventory_staged_targets.c.snapshot_key == snapshot_key
            )
        )
        await self.advance_read_model(snapshot_key, now)
        return PublicationApplyReport(
            snapshot_key, registered, reappeared, missing, written, retired, placements_applied
        )

    async def get_publication(self, snapshot_key: str) -> InventoryPublication | None:
        row = (
            await self._c.execute(
                t.inventory_publications.select().where(
                    t.inventory_publications.c.snapshot_key == snapshot_key
                )
            )
        ).first()
        return _publication(row) if row else None

    async def latest_publication(self, state: PublicationState | None = None) -> InventoryPublication | None:
        stmt = (
            t.inventory_publications.select().order_by(t.inventory_publications.c.created_at.desc()).limit(1)
        )
        if state is not None:
            stmt = stmt.where(t.inventory_publications.c.state == state.value)
        row = (await self._c.execute(stmt)).first()
        return _publication(row) if row else None

    # --- placements and locations --------------------------------------------------

    async def get_placement(self, device_id: uuid.UUID) -> InventoryPlacement | None:
        row = (
            await self._c.execute(
                t.inventory_placements.select().where(t.inventory_placements.c.device_id == device_id)
            )
        ).first()
        return _placement(row) if row else None

    async def get_placements(self, device_ids: Sequence[uuid.UUID]) -> list[InventoryPlacement]:
        if not device_ids:
            return []
        rows = (
            await self._c.execute(
                t.inventory_placements.select().where(
                    t.inventory_placements.c.device_id.in_(list(device_ids))
                )
            )
        ).all()
        return [_placement(r) for r in rows]

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
        # The device row is the lock of the placement. It exists when the placement has no row.
        await self._lock(t.inventory_devices, t.inventory_devices.c.id == device_id)
        current = await self.get_placement(device_id)
        try:
            if current is None:
                _stale(expected_revision, 0, "placement")
                if await self.get_device(device_id) is None:
                    raise NotFound("device not found")
                row = (
                    await self._guarded(
                        t.inventory_placements.insert()
                        .values(
                            device_id=device_id,
                            mode=mode.value,
                            site_id=site_id,
                            origin=origin,
                            revision=1,
                            actor_id=actor_id,
                            updated_at=now,
                        )
                        .returning(t.inventory_placements)
                    )
                ).one()
            else:
                _stale(expected_revision, current.revision, "placement")
                row = (
                    await self._guarded(
                        t.inventory_placements.update()
                        .where(t.inventory_placements.c.device_id == device_id)
                        .values(
                            mode=mode.value,
                            site_id=site_id,
                            origin=origin,
                            revision=current.revision + 1,
                            actor_id=actor_id,
                            updated_at=now,
                        )
                        .returning(t.inventory_placements)
                    )
                ).one()
        except IntegrityError as exc:
            raise NotFound("site not found") from exc
        await self.bump_generation(now)
        return _placement(row)

    async def release_site_placements(
        self, site_id: int, *, actor_id: int | None, now: datetime
    ) -> list[uuid.UUID]:
        """Set each assigned placement at the site to mode `unplaced`, with a new revision.
        A site deletion calls it."""
        rows = (
            await self._c.execute(
                t.inventory_placements.update()
                .where(t.inventory_placements.c.site_id == site_id)
                .values(
                    mode=PlacementMode.UNPLACED.value,
                    site_id=None,
                    revision=t.inventory_placements.c.revision + 1,
                    actor_id=actor_id,
                    updated_at=now,
                )
                .returning(t.inventory_placements.c.device_id)
            )
        ).all()
        await self._c.execute(
            t.inventory_placements.update()
            .where(t.inventory_placements.c.published_site_id == site_id)
            .values(published_site_id=None)
        )
        if rows:
            await self.bump_generation(now)
        return [r.device_id for r in rows]

    _location_cols = (
        reported_locations.c.handle,
        reported_locations.c.source,
        reported_locations.c.location_id,
        reported_locations.c.name,
        reported_locations.c.site,
        reported_locations.c.revision,
        reported_locations.c.updated_at,
    )

    async def get_location(self, handle: uuid.UUID) -> InventoryLocation | None:
        row = (
            await self._c.execute(
                sa.select(*self._location_cols).where(reported_locations.c.handle == handle)
            )
        ).first()
        return _location(row) if row else None

    async def list_locations(self, source: str | None = None) -> list[InventoryLocation]:
        stmt = sa.select(*self._location_cols).order_by(
            reported_locations.c.source, reported_locations.c.location_id
        )
        if source is not None:
            stmt = stmt.where(reported_locations.c.source == source)
        return [_location(r) for r in (await self._c.execute(stmt)).all()]

    async def bind_location(
        self, handle: uuid.UUID, site: str | None, *, expected_revision: int, now: datetime
    ) -> InventoryLocation:
        await self._lock(reported_locations, reported_locations.c.handle == handle)
        current = await self.get_location(handle)
        if current is None:
            raise NotFound("location not found")
        _stale(expected_revision, current.revision, "location")
        try:
            row = (
                await self._guarded(
                    reported_locations.update()
                    .where(reported_locations.c.handle == handle)
                    .values(site=site, revision=current.revision + 1, updated_at=now)
                    .returning(*self._location_cols)
                )
            ).one()
        except IntegrityError as exc:
            raise NotFound("site not found") from exc
        await self.bump_generation(now)
        return _location(row)

    async def unbind_site_locations(self, site: str, now: datetime) -> list[uuid.UUID]:
        rows = (
            await self._c.execute(
                reported_locations.update()
                .where(reported_locations.c.site == site)
                .values(site=None, revision=reported_locations.c.revision + 1, updated_at=now)
                .returning(reported_locations.c.handle)
            )
        ).all()
        if rows:
            await self.bump_generation(now)
        return [r.handle for r in rows]

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
        cid = _uuid()
        try:
            crow = (
                await self._guarded(
                    t.collection_credentials.insert()
                    .values(
                        id=cid, display_name=display_name, current_revision=1, created_at=now, updated_at=now
                    )
                    .returning(t.collection_credentials)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"credential name {display_name!r} is in use") from exc
        vrow = (
            await self._c.execute(
                t.collection_credential_versions.insert()
                .values(
                    credential_id=cid,
                    revision=1,
                    sealed=sealed,
                    secret_paths=sorted(secret_paths),
                    created_at=now,
                    actor_id=actor_id,
                )
                .returning(t.collection_credential_versions)
            )
        ).one()
        return _credential(crow), _credential_version(vrow)

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
        await self._lock(t.collection_credentials, t.collection_credentials.c.id == credential_id)
        current = await self.get_credential(credential_id)
        if current is None:
            raise NotFound("credential not found")
        _stale(expected_revision, current.current_revision, "credential")
        revision = current.current_revision + 1
        vrow = (
            await self._c.execute(
                t.collection_credential_versions.insert()
                .values(
                    credential_id=credential_id,
                    revision=revision,
                    sealed=sealed,
                    secret_paths=sorted(secret_paths),
                    created_at=now,
                    actor_id=actor_id,
                )
                .returning(t.collection_credential_versions)
            )
        ).one()
        await self._c.execute(
            t.collection_credentials.update()
            .where(t.collection_credentials.c.id == credential_id)
            .values(current_revision=revision, updated_at=now)
        )
        await self.bump_generation(now)
        return _credential_version(vrow)

    async def rename_credential(
        self, credential_id: uuid.UUID, display_name: str, *, expected_revision: int, now: datetime
    ) -> CollectionCredential:
        await self._lock(t.collection_credentials, t.collection_credentials.c.id == credential_id)
        current = await self.get_credential(credential_id)
        if current is None:
            raise NotFound("credential not found")
        _stale(expected_revision, current.current_revision, "credential")
        try:
            row = (
                await self._guarded(
                    t.collection_credentials.update()
                    .where(t.collection_credentials.c.id == credential_id)
                    .values(display_name=display_name, updated_at=now)
                    .returning(t.collection_credentials)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"credential name {display_name!r} is in use") from exc
        return _credential(row)

    async def get_credential(self, credential_id: uuid.UUID) -> CollectionCredential | None:
        row = (
            await self._c.execute(
                t.collection_credentials.select().where(t.collection_credentials.c.id == credential_id)
            )
        ).first()
        return _credential(row) if row else None

    async def list_credentials(self, *, include_archived: bool = False) -> list[CollectionCredential]:
        stmt = t.collection_credentials.select().order_by(t.collection_credentials.c.display_name)
        if not include_archived:
            stmt = stmt.where(t.collection_credentials.c.archived_at.is_(None))
        return [_credential(r) for r in (await self._c.execute(stmt)).all()]

    async def get_credential_version(
        self, credential_id: uuid.UUID, revision: int
    ) -> CollectionCredentialVersion | None:
        row = (
            await self._c.execute(
                t.collection_credential_versions.select().where(
                    t.collection_credential_versions.c.credential_id == credential_id,
                    t.collection_credential_versions.c.revision == revision,
                )
            )
        ).first()
        return _credential_version(row) if row else None

    async def profiles_pinning_credential(self, credential_id: uuid.UUID) -> list[uuid.UUID]:
        """Profiles whose current version pins any revision of the credential."""
        pv, p = t.collection_profile_versions.c, t.collection_profiles.c
        stmt = (
            sa.select(p.id)
            .select_from(
                t.collection_profiles.join(
                    t.collection_profile_versions,
                    sa.and_(pv.profile_id == p.id, pv.revision == p.current_revision),
                )
            )
            .where(pv.credential_id == credential_id, p.archived_at.is_(None))
            .order_by(p.id)
        )
        return [r.id for r in (await self._c.execute(stmt)).all()]

    async def archive_credential(
        self, credential_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> CollectionCredential:
        await self._lock(t.collection_credentials, t.collection_credentials.c.id == credential_id)
        current = await self.get_credential(credential_id)
        if current is None:
            raise NotFound("credential not found")
        _stale(expected_revision, current.current_revision, "credential")
        users = await self.profiles_pinning_credential(credential_id)
        if users:
            raise Conflict("credential is pinned by profiles", references=[str(u) for u in users])
        row = (
            await self._c.execute(
                t.collection_credentials.update()
                .where(t.collection_credentials.c.id == credential_id)
                .values(archived_at=now, updated_at=now)
                .returning(t.collection_credentials)
            )
        ).one()
        return _credential(row)

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
        pid = _uuid()
        try:
            prow = (
                await self._guarded(
                    t.collection_profiles.insert()
                    .values(
                        id=pid,
                        display_name=display_name,
                        collector_type=collector_type,
                        current_revision=1,
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(t.collection_profiles)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"profile name {display_name!r} is in use") from exc
        try:
            vrow = (
                await self._guarded(
                    t.collection_profile_versions.insert()
                    .values(
                        profile_id=pid,
                        revision=1,
                        settings=settings,
                        credential_id=credential_id,
                        credential_revision=credential_revision,
                        created_at=now,
                        actor_id=actor_id,
                    )
                    .returning(t.collection_profile_versions)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict("credential version does not exist") from exc
        return _profile(prow), _profile_version(vrow)

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
        await self._lock(t.collection_profiles, t.collection_profiles.c.id == profile_id)
        current = await self.get_profile(profile_id)
        if current is None:
            raise NotFound("profile not found")
        _stale(expected_revision, current.current_revision, "profile")
        revision = current.current_revision + 1
        try:
            vrow = (
                await self._guarded(
                    t.collection_profile_versions.insert()
                    .values(
                        profile_id=profile_id,
                        revision=revision,
                        settings=settings,
                        credential_id=credential_id,
                        credential_revision=credential_revision,
                        created_at=now,
                        actor_id=actor_id,
                    )
                    .returning(t.collection_profile_versions)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict("credential version does not exist") from exc
        await self._c.execute(
            t.collection_profiles.update()
            .where(t.collection_profiles.c.id == profile_id)
            .values(current_revision=revision, updated_at=now)
        )
        await self.bump_generation(now)
        return _profile_version(vrow)

    async def rename_profile(
        self, profile_id: uuid.UUID, display_name: str, *, expected_revision: int, now: datetime
    ) -> CollectionProfile:
        await self._lock(t.collection_profiles, t.collection_profiles.c.id == profile_id)
        current = await self.get_profile(profile_id)
        if current is None:
            raise NotFound("profile not found")
        _stale(expected_revision, current.current_revision, "profile")
        try:
            row = (
                await self._guarded(
                    t.collection_profiles.update()
                    .where(t.collection_profiles.c.id == profile_id)
                    .values(display_name=display_name, updated_at=now)
                    .returning(t.collection_profiles)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"profile name {display_name!r} is in use") from exc
        return _profile(row)

    async def get_profile(self, profile_id: uuid.UUID) -> CollectionProfile | None:
        row = (
            await self._c.execute(
                t.collection_profiles.select().where(t.collection_profiles.c.id == profile_id)
            )
        ).first()
        return _profile(row) if row else None

    async def list_profiles(
        self, collector_type: str | None = None, *, include_archived: bool = False
    ) -> list[CollectionProfile]:
        stmt = t.collection_profiles.select().order_by(t.collection_profiles.c.display_name)
        if collector_type is not None:
            stmt = stmt.where(t.collection_profiles.c.collector_type == collector_type)
        if not include_archived:
            stmt = stmt.where(t.collection_profiles.c.archived_at.is_(None))
        return [_profile(r) for r in (await self._c.execute(stmt)).all()]

    async def get_profile_version(
        self, profile_id: uuid.UUID, revision: int
    ) -> CollectionProfileVersion | None:
        row = (
            await self._c.execute(
                t.collection_profile_versions.select().where(
                    t.collection_profile_versions.c.profile_id == profile_id,
                    t.collection_profile_versions.c.revision == revision,
                )
            )
        ).first()
        return _profile_version(row) if row else None

    async def list_profile_versions(self, profile_id: uuid.UUID) -> list[CollectionProfileVersion]:
        rows = (
            await self._c.execute(
                t.collection_profile_versions.select()
                .where(t.collection_profile_versions.c.profile_id == profile_id)
                .order_by(t.collection_profile_versions.c.revision)
            )
        ).all()
        return [_profile_version(r) for r in rows]

    async def profile_references(self, profile_id: uuid.UUID) -> ProfileReferences:
        targets = (
            await self._c.execute(
                sa.select(t.inventory_targets.c.id)
                .where(
                    t.inventory_targets.c.profile_id == profile_id,
                    t.inventory_targets.c.archived_at.is_(None),
                )
                .order_by(t.inventory_targets.c.id)
            )
        ).all()
        srcs = (
            await self._c.execute(
                sa.select(sources.c.id)
                .where(sources.c.default_profile_id == profile_id)
                .order_by(sources.c.id)
            )
        ).all()
        return ProfileReferences([r.id for r in targets], [r.id for r in srcs])

    async def archive_profile(
        self, profile_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> CollectionProfile:
        await self._lock(t.collection_profiles, t.collection_profiles.c.id == profile_id)
        current = await self.get_profile(profile_id)
        if current is None:
            raise NotFound("profile not found")
        _stale(expected_revision, current.current_revision, "profile")
        refs = await self.profile_references(profile_id)
        if refs.target_ids or refs.source_ids:
            raise Conflict(
                "profile is in use",
                references=[f"target:{i}" for i in refs.target_ids]
                + [f"connection:{i}" for i in refs.source_ids],
            )
        row = (
            await self._c.execute(
                t.collection_profiles.update()
                .where(t.collection_profiles.c.id == profile_id)
                .values(archived_at=now, updated_at=now)
                .returning(t.collection_profiles)
            )
        ).one()
        return _profile(row)

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
        try:
            row = (
                await self._guarded(
                    t.inventory_saved_views.insert()
                    .values(
                        id=_uuid(),
                        owner_id=owner_id,
                        name=name,
                        filter_version=filter_version,
                        filter=filter,
                        sort=sort,
                        direction=direction,
                        columns=list(columns),
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(t.inventory_saved_views)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"a view named {name!r} exists") from exc
        return _view(row)

    async def get_view(self, view_id: uuid.UUID, owner_id: int) -> InventorySavedView | None:
        # A view of another owner reads as absent.
        row = (
            await self._c.execute(
                t.inventory_saved_views.select().where(
                    t.inventory_saved_views.c.id == view_id, t.inventory_saved_views.c.owner_id == owner_id
                )
            )
        ).first()
        return _view(row) if row else None

    async def list_views(self, owner_id: int) -> list[InventorySavedView]:
        rows = (
            await self._c.execute(
                t.inventory_saved_views.select()
                .where(t.inventory_saved_views.c.owner_id == owner_id)
                .order_by(t.inventory_saved_views.c.name)
            )
        ).all()
        return [_view(r) for r in rows]

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
        await self._lock(t.inventory_saved_views, t.inventory_saved_views.c.id == view_id)
        current = await self.get_view(view_id, owner_id)
        if current is None:
            raise NotFound("view not found")
        _stale(expected_revision, current.revision, "view")
        values: dict[str, Any] = {"revision": current.revision + 1, "updated_at": now}
        for key, value in (("name", name), ("filter", filter), ("sort", sort), ("direction", direction)):
            if value is not UNSET:
                values[key] = value
        if columns is not UNSET:
            values["columns"] = list(columns)  # type: ignore[arg-type]
        try:
            row = (
                await self._guarded(
                    t.inventory_saved_views.update()
                    .where(
                        t.inventory_saved_views.c.id == view_id,
                        t.inventory_saved_views.c.owner_id == owner_id,
                    )
                    .values(**values)
                    .returning(t.inventory_saved_views)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict("a view with that name exists") from exc
        return _view(row)

    async def delete_view(
        self, view_id: uuid.UUID, owner_id: int, *, expected_revision: int | None = None
    ) -> bool:
        """Delete the view and return True. Return False for an absent view or a view of
        another owner. A route passes the `expected_revision` of the client."""
        await self._lock(t.inventory_saved_views, t.inventory_saved_views.c.id == view_id)
        current = await self.get_view(view_id, owner_id)
        if current is None:
            return False
        if expected_revision is not None:
            _stale(expected_revision, current.revision, "view")
        result = await self._c.execute(
            t.inventory_saved_views.delete().where(
                t.inventory_saved_views.c.id == view_id,
                t.inventory_saved_views.c.owner_id == owner_id,
                t.inventory_saved_views.c.revision == current.revision,
            )
        )
        return bool(result.rowcount)

    # --- routing groups -------------------------------------------------------------

    async def create_routing_group(
        self, *, display_name: str, description: str, now: datetime
    ) -> InventoryRoutingGroup:
        try:
            row = (
                await self._guarded(
                    t.inventory_routing_groups.insert()
                    .values(
                        id=_uuid(),
                        display_name=display_name,
                        description=description,
                        created_at=now,
                        updated_at=now,
                    )
                    .returning(t.inventory_routing_groups)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict(f"routing group {display_name!r} exists") from exc
        await self.bump_generation(now)
        return _group(row)

    async def get_routing_group(self, group_id: uuid.UUID) -> InventoryRoutingGroup | None:
        row = (
            await self._c.execute(
                t.inventory_routing_groups.select().where(t.inventory_routing_groups.c.id == group_id)
            )
        ).first()
        return _group(row) if row else None

    async def list_routing_groups(self, *, include_archived: bool = False) -> list[InventoryRoutingGroup]:
        stmt = t.inventory_routing_groups.select().order_by(t.inventory_routing_groups.c.display_name)
        if not include_archived:
            stmt = stmt.where(t.inventory_routing_groups.c.archived_at.is_(None))
        return [_group(r) for r in (await self._c.execute(stmt)).all()]

    async def _bump_group(
        self, group_id: uuid.UUID, expected_revision: int, now: datetime, **values: Any
    ) -> sa.Row:
        await self._lock(t.inventory_routing_groups, t.inventory_routing_groups.c.id == group_id)
        current = await self.get_routing_group(group_id)
        if current is None:
            raise NotFound("routing group not found")
        _stale(expected_revision, current.revision, "routing group")
        try:
            row = (
                await self._guarded(
                    t.inventory_routing_groups.update()
                    .where(t.inventory_routing_groups.c.id == group_id)
                    .values(revision=current.revision + 1, updated_at=now, **values)
                    .returning(t.inventory_routing_groups)
                )
            ).one()
        except IntegrityError as exc:
            raise Conflict("routing group name is in use") from exc
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
        values: dict[str, Any] = {}
        if display_name is not UNSET:
            values["display_name"] = display_name
        if description is not UNSET:
            values["description"] = description
        row = await self._bump_group(group_id, expected_revision, now, **values)
        await self.bump_generation(now)
        return _group(row)

    async def archive_routing_group(
        self, group_id: uuid.UUID, *, expected_revision: int, now: datetime
    ) -> InventoryRoutingGroup:
        row = await self._bump_group(group_id, expected_revision, now, archived_at=now)
        await self.bump_generation(now)
        return _group(row)

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
        from sqlalchemy.dialects.postgresql import insert

        row = await self._bump_group(group_id, expected_revision, now)
        if remove:
            await self._c.execute(
                t.inventory_routing_members.delete().where(
                    t.inventory_routing_members.c.group_id == group_id,
                    t.inventory_routing_members.c.context_uid.in_(list(remove)),
                )
            )
        if add:
            await self._c.execute(
                insert(t.inventory_routing_members).on_conflict_do_nothing(),
                [
                    {
                        "group_id": group_id,
                        "context_uid": uid,
                        "owner_uid": owner,
                        "added_at": now,
                        "actor_id": actor_id,
                    }
                    for uid, owner in add
                ],
            )
        await self.bump_generation(now)
        return _group(row)

    async def list_routing_members(self, group_id: uuid.UUID) -> list[InventoryRoutingMember]:
        rows = (
            await self._c.execute(
                t.inventory_routing_members.select()
                .where(t.inventory_routing_members.c.group_id == group_id)
                .order_by(t.inventory_routing_members.c.context_uid)
            )
        ).all()
        return [_member(r) for r in rows]

    async def groups_for_contexts(
        self, context_uids: Sequence[str]
    ) -> dict[str, list[InventoryRoutingGroup]]:
        if not context_uids:
            return {}
        m, g = t.inventory_routing_members.c, t.inventory_routing_groups.c
        stmt = (
            sa.select(m.context_uid, t.inventory_routing_groups)
            .select_from(t.inventory_routing_members.join(t.inventory_routing_groups, g.id == m.group_id))
            .where(m.context_uid.in_(list(context_uids)), g.archived_at.is_(None))
            .order_by(m.context_uid, g.display_name)
        )
        out: dict[str, list[InventoryRoutingGroup]] = {}
        for r in (await self._c.execute(stmt)).all():
            out.setdefault(r.context_uid, []).append(_group(r))
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
        """Store a preview.

        `changes` and `impact` are masked by key name, like an event payload. The preview and
        impact responses show the stored values. New credential material is only in the sealed
        draft."""
        row = (
            await self._c.execute(
                t.inventory_operation_previews.insert()
                .values(
                    token=_uuid(),
                    actor_id=actor_id,
                    operation=operation,
                    permissions=list(permissions),
                    intent_generation=intent_generation,
                    snapshot_key=snapshot_key,
                    members=list(members),
                    changes=redact_by_key(changes),
                    impact=redact_by_key(impact),
                    secret_draft=secret_draft,
                    created_at=now,
                    expires_at=now + ttl,
                )
                .returning(t.inventory_operation_previews)
            )
        ).one()
        return _preview(row, with_draft=False)

    async def add_preview_impacts(self, token: uuid.UUID, rows: Sequence[tuple[str, str, dict]]) -> int:
        if not rows:
            return 0
        existing = (
            await self._c.execute(
                sa.select(sa.func.count())
                .select_from(t.inventory_preview_impacts)
                .where(t.inventory_preview_impacts.c.token == token)
            )
        ).scalar_one()
        if int(existing) + len(rows) > MAX_DERIVED_IMPACT:
            raise InventoryError(f"derived impact exceeds {MAX_DERIVED_IMPACT} records; narrow the selection")
        await self._c.execute(
            t.inventory_preview_impacts.insert(),
            [
                {
                    "token": token,
                    "seq": int(existing) + i + 1,
                    "kind": kind,
                    "entity_id": entity_id,
                    "detail": detail,
                }
                for i, (kind, entity_id, detail) in enumerate(rows)
            ],
        )
        return len(rows)

    async def page_preview_impacts(
        self, token: uuid.UUID, *, after_seq: int = 0, limit: int = 50
    ) -> tuple[list[PreviewImpact], int]:
        total = (
            await self._c.execute(
                sa.select(sa.func.count())
                .select_from(t.inventory_preview_impacts)
                .where(t.inventory_preview_impacts.c.token == token)
            )
        ).scalar_one()
        rows = (
            await self._c.execute(
                t.inventory_preview_impacts.select()
                .where(
                    t.inventory_preview_impacts.c.token == token,
                    t.inventory_preview_impacts.c.seq > after_seq,
                )
                .order_by(t.inventory_preview_impacts.c.seq)
                .limit(max(1, min(limit, MAX_PAGE_LIMIT)))
            )
        ).all()
        return [_impact(r) for r in rows], int(total)

    async def _preview_row(self, token: uuid.UUID, actor_id: int, now: datetime, *, lock: bool) -> sa.Row:
        stmt = t.inventory_operation_previews.select().where(t.inventory_operation_previews.c.token == token)
        if lock:
            stmt = stmt.with_for_update()
        row = (await self._c.execute(stmt)).first()
        # A token of another user reads as absent.
        if row is None or row.actor_id != actor_id:
            raise NotFound("preview not found")
        if row.consumed_at is not None:
            raise PreviewExpired("preview already applied")
        if row.expires_at <= now:
            raise PreviewExpired("preview expired")
        return row

    async def get_preview(self, token: uuid.UUID, actor_id: int, now: datetime) -> OperationPreview:
        return _preview(await self._preview_row(token, actor_id, now, lock=False), with_draft=False)

    async def consume_preview(
        self, token: uuid.UUID, actor_id: int, now: datetime, *, result_id: uuid.UUID | None
    ) -> OperationPreview:
        """Return the preview with its sealed draft, and clear the draft. A preview is
        consumed one time.

        The row is locked. A second concurrent apply waits and then finds the preview
        consumed."""
        row = await self._preview_row(token, actor_id, now, lock=True)
        preview = _preview(row, with_draft=True)
        await self._c.execute(
            t.inventory_operation_previews.update()
            .where(t.inventory_operation_previews.c.token == token)
            .values(consumed_at=now, secret_draft=None, result_id=result_id)
        )
        preview.consumed_at = now
        preview.result_id = result_id
        return preview

    async def purge_expired_previews(self, now: datetime) -> int:
        result = await self._c.execute(
            t.inventory_operation_previews.delete().where(
                sa.or_(
                    t.inventory_operation_previews.c.expires_at <= now,
                    t.inventory_operation_previews.c.consumed_at.is_not(None),
                )
            )
        )
        return int(result.rowcount or 0)

    async def check_idempotency(
        self, actor_id: int, idempotency_key: str, request_digest: str
    ) -> OperationResult | None:
        row = (
            await self._c.execute(
                t.inventory_operation_results.select().where(
                    t.inventory_operation_results.c.actor_id == actor_id,
                    t.inventory_operation_results.c.idempotency_key == idempotency_key,
                )
            )
        ).first()
        if row is None:
            return None
        if row.request_digest != request_digest:
            raise IdempotencyConflict("idempotency key reused with a different request")
        return _result(row)

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
        """Record the response of an operation under its idempotency key.

        The response is masked by key name before it is written. An idempotent retry gets the
        stored response."""
        try:
            row = (
                await self._guarded(
                    t.inventory_operation_results.insert()
                    .values(
                        id=_uuid(),
                        actor_id=actor_id,
                        idempotency_key=idempotency_key,
                        request_digest=request_digest,
                        status=status,
                        response=redact_response(response),
                        created_at=now,
                    )
                    .returning(t.inventory_operation_results)
                )
            ).one()
        except IntegrityError as exc:
            # 2 identical requests can both pass `check_idempotency` before one of them
            # commits. The second request gets the recorded result. A different digest under
            # the key is a conflict.
            existing = (
                await self._c.execute(
                    t.inventory_operation_results.select().where(
                        t.inventory_operation_results.c.actor_id == actor_id,
                        t.inventory_operation_results.c.idempotency_key == idempotency_key,
                    )
                )
            ).first()
            if existing is not None and existing.request_digest == request_digest:
                return _result(existing)
            raise IdempotencyConflict("idempotency key already recorded") from exc
        return _result(row)

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
        """Append one intent event. `redact_by_key` masks `before` and `after`."""
        row = (
            await self._c.execute(
                t.inventory_events.insert()
                .values(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    actor_id=actor_id,
                    action=action,
                    at=now,
                    before=redact_by_key(before) if before is not None else None,
                    after=redact_by_key(after) if after is not None else None,
                    request_id=request_id,
                    snapshot_key=snapshot_key,
                    sensitive=sensitive,
                )
                .returning(t.inventory_events)
            )
        ).one()
        return _event(row)

    async def page_events(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        before_id: int | None = None,
        limit: int = 50,
        include_sensitive: bool = True,
    ) -> tuple[list[InventoryEvent], int | None]:
        e = t.inventory_events.c
        limit = max(1, min(limit, MAX_PAGE_LIMIT))
        stmt = t.inventory_events.select().order_by(e.id.desc()).limit(limit + 1)
        if entity_type is not None:
            stmt = stmt.where(e.entity_type == entity_type)
        if entity_id is not None:
            stmt = stmt.where(e.entity_id == entity_id)
        if before_id is not None:
            stmt = stmt.where(e.id < before_id)
        if not include_sensitive:
            stmt = stmt.where(e.sensitive.is_(False))
        rows = (await self._c.execute(stmt)).all()
        page = [_event(r) for r in rows[:limit]]
        next_before = page[-1].id if len(rows) > limit and page else None
        return page, next_before

    # --- outbox ---------------------------------------------------------------------

    async def enqueue_outbox(
        self, *, kind: str, dedup_key: str, payload: dict, now: datetime, max_attempts: int = 5
    ) -> OutboxItem | None:
        from sqlalchemy.dialects.postgresql import insert

        # The payload is masked by key name.
        stmt = (
            insert(t.inventory_outbox)
            .values(
                dedup_key=dedup_key,
                kind=kind,
                payload=redact_by_key(payload),
                state=OutboxState.PENDING.value,
                max_attempts=max_attempts,
                next_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(index_elements=["dedup_key"])
            .returning(t.inventory_outbox)
        )
        row = (await self._c.execute(stmt)).first()
        return _outbox(row) if row else None

    async def claim_outbox(
        self, worker_id: str, *, now: datetime, lease: timedelta, batch: int = 10
    ) -> list[OutboxItem]:
        o = t.inventory_outbox.c
        due = (
            sa.select(o.id)
            .where(o.state == OutboxState.PENDING.value, o.next_attempt_at <= now)
            .order_by(o.next_attempt_at, o.id)
            .limit(batch)
            .with_for_update(skip_locked=True)
        )
        rows = (
            await self._c.execute(
                t.inventory_outbox.update()
                .where(o.id.in_(due))
                .values(
                    state=OutboxState.RUNNING.value,
                    attempt=o.attempt + 1,
                    claimed_by=worker_id,
                    lease_expires_at=now + lease,
                    updated_at=now,
                )
                .returning(t.inventory_outbox)
            )
        ).all()
        return sorted((_outbox(r) for r in rows), key=lambda i: i.id)

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
        o = t.inventory_outbox.c
        current = (
            await self._c.execute(
                t.inventory_outbox.select().where(
                    o.id == item_id, o.claimed_by == claimed_by, o.state == "running"
                )
            )
        ).first()
        if current is None:
            return None
        if ok:
            values: dict[str, Any] = {"state": OutboxState.DONE.value, "last_error": ""}
        elif retry_at is not None and current.attempt < current.max_attempts:
            values = {"state": OutboxState.PENDING.value, "next_attempt_at": retry_at, "last_error": error}
        else:
            values = {"state": OutboxState.FAILED.value, "last_error": error}
        row = (
            await self._c.execute(
                t.inventory_outbox.update()
                .where(o.id == item_id)
                .values(lease_expires_at=None, claimed_by=None, updated_at=now, **values)
                .returning(t.inventory_outbox)
            )
        ).one()
        return _outbox(row)

    async def reap_outbox(self, now: datetime) -> int:
        o = t.inventory_outbox.c
        result = await self._c.execute(
            t.inventory_outbox.update()
            .where(
                o.state == OutboxState.RUNNING.value,
                o.lease_expires_at.is_not(None),
                o.lease_expires_at < now,
            )
            .values(
                state=OutboxState.PENDING.value,
                lease_expires_at=None,
                claimed_by=None,
                next_attempt_at=now,
                last_error="lease expired",
                updated_at=now,
            )
        )
        return int(result.rowcount or 0)

    async def purge_outbox_done(self, before: datetime) -> int:
        o = t.inventory_outbox.c
        result = await self._c.execute(
            t.inventory_outbox.delete().where(o.state == OutboxState.DONE.value, o.updated_at < before)
        )
        return int(result.rowcount or 0)

    async def list_outbox(self, state: OutboxState | None = None) -> list[OutboxItem]:
        stmt = t.inventory_outbox.select().order_by(t.inventory_outbox.c.id)
        if state is not None:
            stmt = stmt.where(t.inventory_outbox.c.state == state.value)
        return [_outbox(r) for r in (await self._c.execute(stmt)).all()]


class PgInventoryRepository:
    """`InventoryRepository` over the engine of the store. `PgStore` passes its own engine."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[PgInventoryTx]:
        async with self._engine.begin() as conn:
            yield PgInventoryTx(conn)
