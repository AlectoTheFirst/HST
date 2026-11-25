"""Frozen request and response contracts for `/api/inventory`."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)

from hst.app.inventory import field_metadata as _fm
from hst.app.inventory.site_params import SiteBlock, SiteBlocks, SiteGroup
from hst.app.sources import NAME_PATTERN as CONNECTION_NAME_PATTERN

# web/src/api/inventory.ts mirrors this value as CONTRACT_VERSION.
CONTRACT_VERSION = 1
API_PREFIX = "/api/inventory"

# Permission for archive and restore.
INVENTORY_WRITE = "inventory.write"

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
MAX_SELECTION = 1000

# A site code matches routes/sites.py CODE_RE.
SITE_CODE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
MAX_DERIVED_IMPACT = 100_000
REDACTED = "***"


# --- vocabularies ---------------------------------------------------------------


class ErrorCode(StrEnum):
    INVENTORY_CHANGED = "inventory_changed"
    NORMALIZATION_MIGRATED = "normalization_migrated"
    STALE_REVISION = "stale_revision"
    PREVIEW_EXPIRED = "preview_expired"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    VALIDATION = "validation"
    OBSERVED_STORE_UNAVAILABLE = "observed_store_unavailable"
    # A write that collides with an existing record or that an existing reference
    # forbids (a duplicate active target, a display name in use, the delete of a
    # profile in use). `references` lists the records that block the write.
    CONFLICT = "conflict"
    # An idempotency key reused with a different request digest.
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"


# The HTTP status of each error code.
ERROR_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVENTORY_CHANGED: 409,
    ErrorCode.NORMALIZATION_MIGRATED: 409,
    ErrorCode.STALE_REVISION: 409,
    ErrorCode.PREVIEW_EXPIRED: 409,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.VALIDATION: 422,
    ErrorCode.OBSERVED_STORE_UNAVAILABLE: 503,
    ErrorCode.CONFLICT: 409,
    ErrorCode.IDEMPOTENCY_CONFLICT: 409,
}


class PreviewOperation(StrEnum):
    PLACE_DEVICES = "place_devices"
    ASSIGN_TARGET_PROFILE = "assign_target_profile"
    EDIT_PROFILE = "edit_profile"
    ROTATE_CREDENTIAL = "rotate_credential"
    DELETE_SITE = "delete_site"
    DELETE_CONNECTION = "delete_connection"
    DELETE_TARGET = "delete_target"
    REPLACE_TARGET = "replace_target"
    EDIT_ROUTING_MEMBERS = "edit_routing_members"
    ARCHIVE_DEVICES = "archive_devices"
    RESTORE_DEVICES = "restore_devices"


# The permission an apply of each operation rechecks.
OPERATION_PERMISSIONS: dict[PreviewOperation, str] = {
    PreviewOperation.PLACE_DEVICES: "sites.write",
    PreviewOperation.ASSIGN_TARGET_PROFILE: "sources.write",
    PreviewOperation.EDIT_PROFILE: "sources.write",
    PreviewOperation.ROTATE_CREDENTIAL: "sources.write",
    PreviewOperation.DELETE_SITE: "sites.write",
    PreviewOperation.DELETE_CONNECTION: "sources.write",
    PreviewOperation.DELETE_TARGET: "sources.write",
    PreviewOperation.REPLACE_TARGET: "sources.write",
    PreviewOperation.EDIT_ROUTING_MEMBERS: "sources.write",
    PreviewOperation.ARCHIVE_DEVICES: INVENTORY_WRITE,
    PreviewOperation.RESTORE_DEVICES: INVENTORY_WRITE,
}


class Lifecycle(StrEnum):
    ACTIVE = "active"
    MISSING = "missing"
    ARCHIVED = "archived"


class LifecycleAction(StrEnum):
    ARCHIVE = "archive"
    UNARCHIVE = "unarchive"


class TargetKind(StrEnum):
    DIRECT = "direct"
    CONTROLLER = "controller"
    IMPLICIT = "implicit"


class ConnectionKind(StrEnum):
    DIRECT = "direct"
    CONTROLLER = "controller"


class ObservationState(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    ABSENT = "absent"


class Authority(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class PlacementMode(StrEnum):
    AUTO = "auto"
    ASSIGNED = "assigned"
    UNPLACED = "unplaced"


class PlacementOrigin(StrEnum):
    MANUAL = "manual"
    MIGRATED = "migrated"
    ONBOARDING = "onboarding"


class PlacementState(StrEnum):
    """Resolved placement summary of a device plus `pending` for intent the
    last publication has not covered."""

    ASSIGNED = "assigned"
    AUTO = "auto"
    UNPLACED = "unplaced"
    CONFLICT = "conflict"
    STALE = "stale"
    PENDING = "pending"


class PlacementBasis(StrEnum):
    ASSIGNED = "assigned"
    BOUND_LOCATIONS = "bound_locations"
    ONBOARDING = "onboarding"
    NONE = "none"


class CollectionState(StrEnum):
    """`never` without an attempt, `failed` when every attempt failed and `partial`
    when a part of the attempts failed. `stale` when a last success is older than
    its stale threshold. `manual` when no target has a cadence. `current` otherwise."""

    CURRENT = "current"
    STALE = "stale"
    PARTIAL = "partial"
    FAILED = "failed"
    NEVER = "never"
    MANUAL = "manual"


class PublicationState(StrEnum):
    STAGED = "staged"
    PUBLISHED = "published"
    APPLIED = "applied"
    ABORTED = "aborted"


class OutboxKind(StrEnum):
    PUBLICATION_RECONCILE = "publication_reconcile"
    JOB_ENQUEUE = "job_enqueue"


class OutboxState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class ActivationState(StrEnum):
    INACTIVE = "inactive"
    BACKFILL_READY = "backfill_ready"
    ACTIVE = "active"


class FieldCategory(StrEnum):
    PROFILE = "profile"
    CREDENTIAL = "credential"
    CONNECTION = "connection"
    TARGET = "target"
    INTERNAL = "internal"
    LEGACY_NORMALIZATION = "legacy_normalization"


class IdentitySensitivity(StrEnum):
    NONE = "none"
    LABEL = "label"
    SCOPE = "scope"
    IDENTITY = "identity"


class SortField(StrEnum):
    NAME = "name"
    PLATFORM = "platform"
    SITE = "site"
    LAST_SUCCESS = "last_success"
    COLLECTION_STATE = "collection_state"


class SortDirection(StrEnum):
    ASC = "asc"
    DESC = "desc"


class RouteTargetDirection(StrEnum):
    IMPORT = "import"
    EXPORT = "export"


class ProfileOrigin(StrEnum):
    TARGET = "target"
    CONNECTION = "connection"
    NONE = "none"


class PreviewMemberKind(StrEnum):
    DEVICE = "device"
    TARGET = "target"
    CONNECTION = "connection"
    PROFILE = "profile"
    CREDENTIAL = "credential"
    SITE = "site"
    ROUTING_GROUP = "routing_group"


class ApplyStatus(StrEnum):
    APPLIED = "applied"
    REUSED = "reused"


# --- base classes ---------------------------------------------------------------


class Request(BaseModel):
    """The base of every request body. An unknown field is a 422."""

    model_config = ConfigDict(extra="forbid")


class Response(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- errors and generation ------------------------------------------------------


class ErrorResponse(Response):
    error: str
    code: ErrorCode
    # Set for stale_revision.
    current_revision: int | None = None
    # A refused delete sets the ids that still reference the record.
    references: list[str] = Field(default_factory=list)
    detail: dict[str, Any] | None = None


class Generation(Response):
    """The coherent read-model position a list or preview was computed at.
    It is returned for an empty result too."""

    snapshot_key: str | None
    intent_generation: int
    inventory_sync_pending: bool = False


# --- cursor ---------------------------------------------------------------------


class ListCursor(BaseModel):
    """An opaque list cursor holds the read-model position, the sort, the filter
    digest and the last key seen. A cursor from another generation is refused with
    `inventory_changed`."""

    model_config = ConfigDict(extra="forbid")

    snapshot_key: str | None
    intent_generation: int
    sort: SortField
    direction: SortDirection
    filter_digest: str
    last_value: str | None
    last_id: UUID


class CursorError(ValueError):
    """The cursor is not one this server issued."""


def encode_cursor(cursor: ListCursor) -> str:
    raw = json.dumps(cursor.model_dump(mode="json"), separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(text: str) -> ListCursor:
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode())
        return ListCursor.model_validate_json(raw)
    except (binascii.Error, ValueError, ValidationError) as exc:
        raise CursorError("malformed cursor") from exc


def filter_digest(filters: dict[str, Any]) -> str:
    """Stable digest of the validated filter set a cursor was issued for."""
    canonical = json.dumps(filters, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# --- devices --------------------------------------------------------------------


class DeviceListQuery(Request):
    """The query parameters of GET /devices. Repeated values of one field combine
    with OR. Fields combine with AND."""

    q: str | None = Field(default=None, max_length=200)
    site_id: list[str] = Field(default_factory=list)
    connection_id: list[str] = Field(default_factory=list)
    platform: list[str] = Field(default_factory=list)
    collection_state: list[CollectionState] = Field(default_factory=list)
    placement_state: list[PlacementState] = Field(default_factory=list)
    lifecycle: list[Lifecycle] = Field(default_factory=list)
    sort: SortField = SortField.NAME
    direction: SortDirection = SortDirection.ASC
    limit: int = Field(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT)
    cursor: str | None = None
    view_id: UUID | None = None

    def filter_fields(self) -> dict[str, Any]:
        """Return the filter fields that a cursor digest and a saved view cover."""
        return self.model_dump(
            mode="json",
            include={
                "q",
                "site_id",
                "connection_id",
                "platform",
                "collection_state",
                "placement_state",
                "lifecycle",
            },
        )


class ObservingConnection(Response):
    connection_id: str
    source_key: str
    display_name: str
    target_id: UUID
    target_host: str
    observation_state: ObservationState
    authority: Authority
    last_success_at: datetime | None


class DeviceSummary(Response):
    id: UUID
    graph_uid: str
    hostname: str
    platform: str
    management_address: str
    lifecycle: Lifecycle
    revision: int
    collection_state: CollectionState
    last_success_at: datetime | None
    site_id: str | None
    site_code: str | None
    placement_state: PlacementState
    connections: list[ObservingConnection] = Field(default_factory=list)
    latest_snapshot_key: str | None
    first_seen: datetime
    last_seen: datetime


class DevicePage(Response):
    items: list[DeviceSummary]
    next_cursor: str | None
    generation: Generation


class ContributingObservation(Response):
    target_id: UUID
    connection_id: str
    location_id: UUID | None
    location_name: str
    site_id: str | None
    site_code: str | None
    bound: bool
    state: ObservationState
    authority: Authority


class PlacementResponse(Response):
    """Desired and published placement side by side. `pending` is true when
    publication coverage of `desired_revision` is incomplete."""

    mode: PlacementMode
    desired_site_id: str | None
    desired_site_code: str | None
    basis: PlacementBasis
    contributing: list[ContributingObservation] = Field(default_factory=list)
    conflict: bool
    stale: bool
    published_site_id: str | None
    published_site_code: str | None
    published_snapshot_key: str | None
    desired_revision: int
    applied_revision: int
    pending: bool
    origin: PlacementOrigin
    actor_id: str | None
    updated_at: datetime | None


class ObservationView(Response):
    target_id: UUID
    connection_id: str
    source_key: str
    host: str
    kind: TargetKind
    reported_location_id: UUID | None
    reported_location_name: str
    last_success_at: datetime | None
    last_seen_snapshot_key: str | None
    state: ObservationState
    authority: Authority
    notes: dict[str, Any] | None = None


class RelatedEntity(Response):
    uid: str
    label: str
    relation: str
    name: str


class TargetCollectionSummary(Response):
    target_id: UUID
    connection_id: str
    enabled: bool
    profile_id: UUID | None
    profile_revision: int | None
    profile_origin: ProfileOrigin
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    consecutive_failures: int
    last_error: str


class DeviceDetail(Response):
    summary: DeviceSummary
    placement: PlacementResponse
    observations: list[ObservationView]
    related: list[RelatedEntity] = Field(default_factory=list)
    # None when the caller lacks runs.manage.
    collection: list[TargetCollectionSummary] | None
    generation: Generation


class RoutingGroupRef(Response):
    group_id: UUID
    display_name: str
    updated_at: datetime


class RouteTargetView(Response):
    value: str
    direction: RouteTargetDirection


class RoutingContextView(Response):
    authority: str | None = None
    instance_uid: str | None = None
    vsid: int | None = None
    enterprise_name: str | None = None
    derived_domains: list[str] = Field(default_factory=list)
    context_uid: str
    kind: str
    owner_uid: str
    identifier: str
    management_domain: str | None
    enterprise: str | None
    segment: str | None
    route_targets: list[RouteTargetView] = Field(default_factory=list)
    declared_domain: str | None
    membership_basis: str
    user_groups: list[RoutingGroupRef] = Field(default_factory=list)


class DeviceRoutingQuery(Request):
    """The query parameters of GET /devices/{id}/routing. An omitted `snapshot_key`
    selects the current read-model snapshot."""

    snapshot_key: str | None = None


class DeviceRoutingResponse(Response):
    device_id: UUID
    snapshot_key: str
    contexts: list[RoutingContextView]
    # Time of the newest user-annotation change.
    annotations_as_of: datetime | None


class EventView(Response):
    id: int
    entity_type: str
    entity_id: str
    actor_id: str | None
    actor_name: str | None
    action: str
    at: datetime
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    request_id: str | None
    snapshot_key: str | None


class PageQuery(Request):
    """Cursor and page size of GET /devices/{id}/history and
    GET /operations/previews/{token}/impact."""

    cursor: str | None = None
    limit: int = Field(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT)


class EventPage(Response):
    items: list[EventView]
    next_cursor: str | None


class PlacementPatch(Request):
    mode: PlacementMode
    site_id: str | None = None
    expected_revision: int = Field(ge=0)

    @model_validator(mode="after")
    def _site_iff_assigned(self) -> PlacementPatch:
        if (self.mode == PlacementMode.ASSIGNED) != (self.site_id is not None):
            raise ValueError("site_id is required exactly when mode is assigned")
        return self


class LifecyclePatch(Request):
    action: LifecycleAction
    expected_revision: int = Field(ge=1)


class CollectRequest(Request):
    target_ids: list[UUID] = Field(min_length=1, max_length=MAX_SELECTION)


class JobRef(Response):
    job_id: int
    target_id: UUID
    source_key: str
    host: str


class SkippedTarget(Response):
    target_id: UUID
    reason: str


class CollectResponse(Response):
    jobs: list[JobRef]
    skipped: list[SkippedTarget] = Field(default_factory=list)


# --- connections and targets ------------------------------------------------------


class ConnectionListQuery(Request):
    kind: ConnectionKind | None = None
    collector_type: str | None = None


class ConnectionHealth(Response):
    state: CollectionState
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    failing_targets: int
    target_count: int
    device_count: int


class ConnectionView(Response):
    id: str
    # The immutable execution key (`sources.name`).
    name: str
    display_name: str
    collector_type: str
    kind: ConnectionKind
    enabled: bool
    # The connection-category fields, with each secret replaced by "***".
    config: dict[str, Any]
    profile_id: UUID | None
    revision: int
    frozen_normalization: dict[str, Any] | None
    health: ConnectionHealth
    created_at: datetime
    updated_at: datetime
    # Set by a create or an edit when another controller connection resolves to this
    # connection's routing scope (app/sources.py shared_routing_scope_warnings).
    warnings: list[str] = Field(default_factory=list)


class ConnectionCreate(Request):
    name: str = Field(pattern=CONNECTION_NAME_PATTERN)
    display_name: str = Field(default="", max_length=200)
    collector_type: str
    config: dict[str, Any] = Field(default_factory=dict)
    profile_id: UUID | None = None
    # Controller onboarding saves a disabled draft first.
    enabled: bool = False


class ConnectionPatch(Request):
    display_name: str | None = Field(default=None, max_length=200)
    config: dict[str, Any] | None = None
    profile_id: UUID | None = None
    clear_profile: bool = False
    enabled: bool | None = None
    clear_jump_host_keys: bool = False
    expected_revision: int = Field(ge=1)


class TargetView(Response):
    id: UUID
    connection_id: str
    source_key: str
    host: str
    port: int | None
    kind: TargetKind
    enabled: bool
    host_key_pinned: bool
    profile_id: UUID | None
    endpoint_config: dict[str, Any] = Field(default_factory=dict)
    onboarding_site_id: str | None
    legacy_device_id: str | None
    revision: int
    archived_at: datetime | None
    observed_device_ids: list[UUID] = Field(default_factory=list)
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    consecutive_failures: int
    last_error: str


class TargetCreate(Request):
    connection_id: str
    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    enabled: bool = True
    profile_id: UUID | None = None
    endpoint_config: dict[str, Any] = Field(default_factory=dict)
    onboarding_site_id: str | None = None


class TargetPatch(Request):
    enabled: bool | None = None
    profile_id: UUID | None = None
    clear_profile: bool = False
    onboarding_site_id: str | None = None
    clear_onboarding_site: bool = False
    clear_host_key: bool = False
    expected_revision: int = Field(ge=1)


class EffectiveCollection(Response):
    """What a target collects with, without secrets."""

    source_key: str
    target_key: str
    target_id: UUID | None
    collector_type: str
    profile_id: UUID | None
    profile_revision: int | None
    credential_id: UUID | None
    credential_revision: int | None
    # The effective values by dotted path, with each secret replaced by "***".
    values: dict[str, Any]
    # The origin of each dotted path, for example `profile`, `connection`, `target` or `frozen`.
    origins: dict[str, str]
    frozen_normalization: dict[str, Any]
    resolver_version: int
    configuration_digest: str


class ProbeRequest(Request):
    """A probe uses the stored effective revision only."""


class ProbeResult(Response):
    ok: bool
    message: str
    effective: EffectiveCollection
    host_key_pinned: bool
    duration_ms: int


class TargetReplaceRequest(Request):
    token: UUID
    idempotency_key: str = Field(min_length=1, max_length=128)


class TargetReplaceResponse(Response):
    old_target: TargetView
    new_target: TargetView


# --- profiles and credentials --------------------------------------------------------


class ProfileUsage(Response):
    targets: int
    connections: int


class ProfileView(Response):
    id: UUID
    display_name: str
    collector_type: str
    current_revision: int
    archived_at: datetime | None
    credential_id: UUID | None
    credential_revision: int | None
    settings: dict[str, Any]
    usage: ProfileUsage
    created_at: datetime
    updated_at: datetime


class ProfileVersionView(Response):
    profile_id: UUID
    revision: int
    settings: dict[str, Any]
    credential_id: UUID | None
    credential_revision: int | None
    created_at: datetime
    actor_id: str | None


class ProfileCreate(Request):
    display_name: str = Field(min_length=1, max_length=200)
    collector_type: str
    settings: dict[str, Any] = Field(default_factory=dict)
    credential_id: UUID | None = None


class ProfilePatch(Request):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    settings: dict[str, Any] | None = None
    credential_id: UUID | None = None
    clear_credential: bool = False
    expected_revision: int = Field(ge=1)


class ImpactTarget(Response):
    target_id: UUID
    connection_id: str
    host: str
    device_ids: list[UUID] = Field(default_factory=list)


class ProfileImpact(Response):
    profile_id: UUID
    revision: int
    targets: list[ImpactTarget]
    connection_ids: list[str]
    device_ids: list[UUID]
    total_targets: int
    total_devices: int
    generation: Generation


class CredentialView(Response):
    id: UUID
    display_name: str
    current_revision: int
    # The dotted paths of the secrets in the current version.
    secret_paths: list[str]
    archived_at: datetime | None
    profiles_using: int
    created_at: datetime
    updated_at: datetime


class CredentialCreate(Request):
    display_name: str = Field(min_length=1, max_length=200)
    secrets: dict[str, SecretStr] = Field(min_length=1)

    def secret_values(self) -> dict[str, str]:
        return {k: v.get_secret_value() for k, v in self.secrets.items()}


class CredentialPatch(Request):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    # A map creates a new version that holds this complete map. Without a map the patch
    # changes the metadata only.
    secrets: dict[str, SecretStr] | None = None
    expected_revision: int = Field(ge=1)

    def secret_values(self) -> dict[str, str] | None:
        if self.secrets is None:
            return None
        return {k: v.get_secret_value() for k, v in self.secrets.items()}


# --- sites and locations -------------------------------------------------------------


class SiteView(Response):
    id: str
    code: str
    name: str
    location: str
    # The point of the site on the site map. `lat` and `lon` are both set or both null.
    lat: float | None = None
    lon: float | None = None
    # the `site_group` and `blocks` site params the map reads (hst/map/site_config.py)
    site_group: str | None = None
    blocks: list[SiteBlock] | None = None
    revision: int
    device_count: int
    location_count: int


def _whole_point(model: SiteCreate | SitePatch) -> None:
    """`lat` and `lon` are both sent or both absent, and both numbers or both null.
    Two numbers set the point of the site. On a patch, two nulls clear the point."""
    fields = model.model_fields_set
    if ("lat" in fields) != ("lon" in fields) or (model.lat is None) != (model.lon is None):
        raise ValueError("lat and lon go together")


class SiteCreate(Request):
    code: str = Field(pattern=SITE_CODE_PATTERN)
    name: str = Field(default="", max_length=200)
    location: str = Field(default="", max_length=200)
    lat: float | None = Field(default=None, ge=-90, le=90)
    lon: float | None = Field(default=None, ge=-180, le=180)

    @model_validator(mode="after")
    def _point_is_whole(self) -> SiteCreate:
        _whole_point(self)
        return self

    def point(self) -> tuple[float, float] | None:
        return (self.lat, self.lon) if self.lat is not None and self.lon is not None else None


class SitePatch(Request):
    name: str | None = Field(default=None, max_length=200)
    location: str | None = Field(default=None, max_length=200)
    # Two nulls clear the point. The point stays when both fields are absent.
    lat: float | None = Field(default=None, ge=-90, le=90)
    lon: float | None = Field(default=None, ge=-180, le=180)
    # An absent field keeps the stored value. A null or an empty value clears it.
    site_group: SiteGroup = None
    blocks: SiteBlocks = None
    expected_revision: int = Field(ge=1)

    @model_validator(mode="after")
    def _point_is_whole(self) -> SitePatch:
        _whole_point(self)
        return self

    @property
    def sets_point(self) -> bool:
        return "lat" in self.model_fields_set

    def point(self) -> tuple[float, float] | None:
        return (self.lat, self.lon) if self.lat is not None and self.lon is not None else None

    def map_params(self) -> dict[str, Any]:
        """The `site_group` and `blocks` this patch sends, in the shape `sites.params` stores."""
        dumped = self.model_dump(include={"site_group", "blocks"})
        return {key: value for key, value in dumped.items() if key in self.model_fields_set}


class LocationView(Response):
    id: UUID
    connection_id: str
    source_key: str
    location_id: str
    name: str
    site_id: str | None
    site_code: str | None
    revision: int
    device_count: int


class LocationPatch(Request):
    site_id: str | None
    expected_revision: int = Field(ge=1)


# --- site and location search and bulk writes ---------------------------------------
#
# Search pages the site and location lists with an offset.

MAX_BULK_ROWS = 5000


class SiteSort(StrEnum):
    CODE = "code"
    NAME = "name"
    DEVICES = "devices"


class LocationState(StrEnum):
    ALL = "all"
    MAPPED = "mapped"
    UNMAPPED = "unmapped"
    SUGGESTED = "suggested"


class BulkRowStatus(StrEnum):
    CHANGE = "change"
    UNCHANGED = "unchanged"
    ERROR = "error"


class SiteSearchQuery(Request):
    q: str | None = Field(default=None, max_length=200)
    sort: SiteSort = SiteSort.CODE
    direction: SortDirection = SortDirection.ASC
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT)


class SitePage(Response):
    items: list[SiteView]
    total: int
    offset: int
    limit: int


class SiteImportRow(Request):
    code: str = Field(pattern=SITE_CODE_PATTERN)
    name: str | None = Field(default=None, max_length=200)
    location: str | None = Field(default=None, max_length=200)


class SiteImport(Request):
    """Create or update sites by code. A name or location left out keeps the
    stored value. With `dry_run` nothing is written."""

    sites: list[SiteImportRow] = Field(min_length=1, max_length=MAX_BULK_ROWS)
    dry_run: bool = False


class SiteImportRowResult(Response):
    index: int
    code: str
    action: str
    status: BulkRowStatus
    error: str | None


class SiteImportResult(Response):
    applied: bool
    created: int
    updated: int
    unchanged: int
    errors: int
    rows: list[SiteImportRowResult]


class LocationSearchQuery(Request):
    q: str | None = Field(default=None, max_length=200)
    connection_id: str | None = None
    site_id: str | None = None
    state: LocationState = LocationState.ALL
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_SELECTION)


class LocationConnectionCount(Response):
    connection_id: str
    source_key: str
    count: int


class LocationStateCounts(Response):
    all: int
    mapped: int
    unmapped: int
    suggested: int


class LocationMatch(Response):
    """A site whose code or name matches an unmapped location, and the rule that matched."""

    site_id: str
    site_code: str
    rule: str


class LocationRow(Response):
    location: LocationView
    suggestion: LocationMatch | None


class LocationPage(Response):
    items: list[LocationRow]
    total: int
    offset: int
    limit: int
    counts: LocationStateCounts
    connections: list[LocationConnectionCount]


class LocationBinding(Request):
    """One location, by handle or by connection key and vendor location id, and
    the site it maps to by id or code. A binding without a site removes the mapping
    of the location. Without an expected revision the current revision is used. A
    CSV import has no expected revision."""

    id: UUID | None = None
    source_key: str | None = Field(default=None, max_length=64)
    location_id: str | None = Field(default=None, max_length=256)
    site_id: str | None = None
    site_code: str | None = Field(default=None, max_length=64)
    expected_revision: int | None = Field(default=None, ge=1)


class LocationBindings(Request):
    bindings: list[LocationBinding] = Field(min_length=1, max_length=MAX_BULK_ROWS)
    dry_run: bool = False


class LocationBindingRowResult(Response):
    index: int
    id: UUID | None
    source_key: str
    location_id: str
    name: str
    site_before: str | None
    site_after: str | None
    status: BulkRowStatus
    error: str | None


class LocationBindingResult(Response):
    applied: bool
    changed: int
    unchanged: int
    errors: int
    devices_recomputed: int
    rows: list[LocationBindingRowResult]


# --- saved views ------------------------------------------------------------------------


class ViewFilter(Request):
    version: int = 1
    q: str | None = Field(default=None, max_length=200)
    site_id: list[str] = Field(default_factory=list)
    connection_id: list[str] = Field(default_factory=list)
    platform: list[str] = Field(default_factory=list)
    collection_state: list[CollectionState] = Field(default_factory=list)
    placement_state: list[PlacementState] = Field(default_factory=list)
    lifecycle: list[Lifecycle] = Field(default_factory=list)


class SavedViewView(Response):
    id: UUID
    owner_id: str
    name: str
    filter: ViewFilter
    sort: SortField
    direction: SortDirection
    columns: list[str]
    revision: int
    created_at: datetime
    updated_at: datetime


class SavedViewCreate(Request):
    name: str = Field(min_length=1, max_length=100)
    filter: ViewFilter = Field(default_factory=ViewFilter)
    sort: SortField = SortField.NAME
    direction: SortDirection = SortDirection.ASC
    columns: list[str] = Field(default_factory=list, max_length=20)


class SavedViewPatch(Request):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    filter: ViewFilter | None = None
    sort: SortField | None = None
    direction: SortDirection | None = None
    columns: list[str] | None = Field(default=None, max_length=20)
    expected_revision: int = Field(ge=1)


# --- routing groups ----------------------------------------------------------------------


class RoutingMemberView(Response):
    context_uid: str
    owner_uid: str
    added_at: datetime
    actor_id: str | None
    # False when the uid is no longer in the published snapshot.
    present: bool


class RoutingGroupView(Response):
    """A routing group is an operator label on observed routing contexts. The
    routes and route targets in the published snapshot decide how traffic can
    flow between contexts. Group membership does not change that."""

    id: UUID
    display_name: str
    description: str
    revision: int
    archived_at: datetime | None
    members: list[RoutingMemberView] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class RoutingGroupCreate(Request):
    display_name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    context_uids: list[str] = Field(default_factory=list, max_length=MAX_SELECTION)


class RoutingGroupPatch(Request):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    expected_revision: int = Field(ge=1)


# --- operations: preview and apply ---------------------------------------------------------


class Selection(Request):
    """Either at most 1000 explicit ids, or the exact validated filter plus the
    generation it was seen at."""

    ids: list[str] | None = Field(default=None, max_length=MAX_SELECTION)
    filter: DeviceListQuery | None = None
    snapshot_key: str | None = None
    intent_generation: int | None = None

    @model_validator(mode="after")
    def _one_form(self) -> Selection:
        if (self.ids is None) == (self.filter is None):
            raise ValueError("selection needs exactly one of ids or filter")
        if self.filter is not None and self.intent_generation is None:
            raise ValueError("a filter selection needs intent_generation")
        if self.ids is not None and len(self.ids) != len(set(self.ids)):
            raise ValueError("selection ids must be distinct")
        return self


class PlacementChange(Request):
    mode: PlacementMode
    site_id: str | None = None

    @model_validator(mode="after")
    def _site_iff_assigned(self) -> PlacementChange:
        if (self.mode == PlacementMode.ASSIGNED) != (self.site_id is not None):
            raise ValueError("site_id is required exactly when mode is assigned")
        return self


class ProfileAssignmentChange(Request):
    # null resumes the connection profile.
    profile_id: UUID | None


class RoutingMembersChange(Request):
    group_id: UUID
    add_context_uids: list[str] = Field(default_factory=list, max_length=MAX_SELECTION)
    remove_context_uids: list[str] = Field(default_factory=list, max_length=MAX_SELECTION)

    @model_validator(mode="after")
    def _disjoint(self) -> RoutingMembersChange:
        if set(self.add_context_uids) & set(self.remove_context_uids):
            raise ValueError("a context uid cannot be both added and removed")
        return self


class ReplacementChange(Request):
    endpoint_config: dict[str, Any]


Change = (
    PlacementChange
    | ProfileAssignmentChange
    | RoutingMembersChange
    | ReplacementChange
    | ProfilePatch
    | CredentialPatch
)

# The change model of each operation. None marks an operation that takes no change.
OPERATION_CHANGE: dict[PreviewOperation, type[Request] | None] = {
    PreviewOperation.PLACE_DEVICES: PlacementChange,
    PreviewOperation.ASSIGN_TARGET_PROFILE: ProfileAssignmentChange,
    PreviewOperation.EDIT_PROFILE: ProfilePatch,
    PreviewOperation.ROTATE_CREDENTIAL: CredentialPatch,
    PreviewOperation.DELETE_SITE: None,
    PreviewOperation.DELETE_CONNECTION: None,
    PreviewOperation.DELETE_TARGET: None,
    PreviewOperation.REPLACE_TARGET: ReplacementChange,
    PreviewOperation.EDIT_ROUTING_MEMBERS: RoutingMembersChange,
    PreviewOperation.ARCHIVE_DEVICES: None,
    PreviewOperation.RESTORE_DEVICES: None,
}


class PreviewRequest(Request):
    operation: PreviewOperation
    selection: Selection
    change: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _change_matches_operation(self) -> PreviewRequest:
        shape = OPERATION_CHANGE[self.operation]
        if shape is None:
            if self.change:
                raise ValueError(f"{self.operation.value} takes no change")
            return self
        if self.change is None:
            raise ValueError(f"{self.operation.value} needs a change")
        shape.model_validate(self.change)
        return self

    def typed_change(self) -> Request | None:
        shape = OPERATION_CHANGE[self.operation]
        return None if shape is None else shape.model_validate(self.change or {})

    def redacted_change(self) -> dict[str, Any] | None:
        typed = self.typed_change()
        return None if typed is None else typed.model_dump(mode="json")


class PreviewMember(Response):
    kind: PreviewMemberKind
    id: str
    revision: int
    label: str


class PreviewResponse(Response):
    token: UUID
    operation: PreviewOperation
    expires_at: datetime
    generation: Generation
    members: list[PreviewMember]
    member_count: int
    affected_device_count: int
    affected_target_count: int
    # The change that the apply writes, with each secret replaced by "***".
    changes: dict[str, Any]
    warnings: list[str] = Field(default_factory=list)


class ApplyRequest(Request):
    token: UUID
    idempotency_key: str = Field(min_length=1, max_length=128)


class ApplyResult(Response):
    kind: PreviewMemberKind
    id: str
    revision: int


class ApplyResponse(Response):
    token: UUID
    operation: PreviewOperation
    status: ApplyStatus
    generation: Generation
    results: list[ApplyResult]
    job_ids: list[int] = Field(default_factory=list)


class ImpactItem(Response):
    kind: PreviewMemberKind
    entity_id: str
    detail: dict[str, Any] = Field(default_factory=dict)


class ImpactPage(Response):
    items: list[ImpactItem]
    next_cursor: str | None
    total: int
    generation: Generation


# --- field metadata ------------------------------------------------------------


class FieldMetadata(Response):
    path: str
    variant: str | None
    category: FieldCategory
    secret: bool
    identity_sensitivity: IdentitySensitivity
    profile_applicability: str
    label: str


class CollectorFieldMetadata(Response):
    collector_type: str
    kind: ConnectionKind
    fields: list[FieldMetadata]


def field_metadata_for(collector_type: str) -> CollectorFieldMetadata:
    coll = _fm.COLLECTORS[collector_type]
    kind = ConnectionKind.DIRECT if coll.kind == "group" else ConnectionKind.CONTROLLER
    return CollectorFieldMetadata(
        collector_type=coll.collector_type,
        kind=kind,
        fields=[FieldMetadata(**f._asdict()) for f in coll.fields],
    )


def all_field_metadata() -> list[CollectorFieldMetadata]:
    return [field_metadata_for(name) for name in sorted(_fm.COLLECTORS)]


# --- activation state ----------------------------------------------------------------


class InventoryStateView(Response):
    resolver_version: int
    schema_version: int
    backfill_version: int
    activation_state: ActivationState
    read_model_snapshot_key: str | None
    intent_generation: int
    inventory_sync_pending: bool
    updated_at: datetime


# --- redaction ----------------------------------------------------------------------------


def redact_paths(value: dict[str, Any], paths: frozenset[str] | set[str]) -> dict[str, Any]:
    """Return a copy of `value` with the value at each dotted secret path replaced
    by "***". An absent path stays absent. A None or empty value stays as it is."""
    out: dict[str, Any] = {}
    for key, item in value.items():
        if key in paths:
            out[key] = REDACTED if item not in (None, "") else item
            continue
        nested = {p.partition(".")[2] for p in paths if p.partition(".")[0] == key and "." in p}
        if nested and isinstance(item, dict):
            out[key] = redact_paths(item, nested)
        else:
            out[key] = item
    return out


def redact_config(collector_type: str, config: dict[str, Any]) -> dict[str, Any]:
    """Redact a collector config by that collector's classified secret paths."""
    return redact_paths(config, _fm.secret_paths(collector_type))


Redactable = dict[str, Any] | list[Any] | str | int | float | bool | None
_MASK_KEYS = frozenset({"password", "passphrase", "private_key", "key", "client_secret", "secret", "token"})


def redact_by_key(value: Any) -> Any:
    """Redact a payload that has no classification (an event payload or a preview).
    The value of each key in `_MASK_KEYS` is masked at every depth."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if k in _MASK_KEYS and v not in (None, "") else redact_by_key(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_by_key(v) for v in value]
    return value


PermissionName = Literal[
    "graph.read",
    "runs.manage",
    "sites.write",
    "sources.write",
    "inventory.write",
]

# The permission of each route, by method and path. A path is relative to
# API_PREFIX. `{id}` stands for any id segment.
ROUTE_PERMISSIONS: dict[tuple[str, str], PermissionName] = {
    ("GET", "/devices"): "graph.read",
    ("GET", "/devices/{id}"): "graph.read",
    ("GET", "/devices/{id}/routing"): "graph.read",
    ("GET", "/devices/{id}/history"): "graph.read",
    ("PATCH", "/devices/{id}/placement"): "sites.write",
    ("PATCH", "/devices/{id}/lifecycle"): "inventory.write",
    ("POST", "/devices/{id}/collect"): "runs.manage",
    ("GET", "/connections"): "runs.manage",
    ("GET", "/connections/{id}"): "runs.manage",
    ("POST", "/connections"): "sources.write",
    ("PATCH", "/connections/{id}"): "sources.write",
    ("DELETE", "/connections/{id}"): "sources.write",
    ("GET", "/targets"): "runs.manage",
    ("GET", "/targets/{id}"): "runs.manage",
    ("POST", "/targets"): "sources.write",
    ("PATCH", "/targets/{id}"): "sources.write",
    ("DELETE", "/targets/{id}"): "sources.write",
    ("GET", "/targets/{id}/effective"): "runs.manage",
    ("POST", "/targets/{id}/probe"): "runs.manage",
    ("POST", "/targets/{id}/replace"): "sources.write",
    ("GET", "/profiles"): "sources.write",
    ("GET", "/profiles/{id}"): "sources.write",
    ("POST", "/profiles"): "sources.write",
    ("PATCH", "/profiles/{id}"): "sources.write",
    ("DELETE", "/profiles/{id}"): "sources.write",
    ("GET", "/profiles/{id}/impact"): "sources.write",
    ("GET", "/credentials"): "sources.write",
    ("GET", "/credentials/{id}"): "sources.write",
    ("POST", "/credentials"): "sources.write",
    ("PATCH", "/credentials/{id}"): "sources.write",
    ("DELETE", "/credentials/{id}"): "sources.write",
    ("GET", "/sites"): "graph.read",
    ("GET", "/sites/search"): "graph.read",
    ("GET", "/sites/{id}"): "graph.read",
    ("POST", "/sites"): "sites.write",
    ("POST", "/sites/import"): "sites.write",
    ("PATCH", "/sites/{id}"): "sites.write",
    ("DELETE", "/sites/{id}"): "sites.write",
    ("GET", "/locations"): "graph.read",
    ("GET", "/locations/search"): "graph.read",
    ("POST", "/locations/bindings"): "sites.write",
    ("PATCH", "/locations/{id}"): "sites.write",
    ("GET", "/views"): "graph.read",
    ("GET", "/views/{id}"): "graph.read",
    ("POST", "/views"): "graph.read",
    ("PATCH", "/views/{id}"): "graph.read",
    ("DELETE", "/views/{id}"): "graph.read",
    ("GET", "/routing-groups"): "graph.read",
    ("GET", "/routing-groups/{id}"): "graph.read",
    ("POST", "/routing-groups"): "sources.write",
    ("PATCH", "/routing-groups/{id}"): "sources.write",
    ("DELETE", "/routing-groups/{id}"): "sources.write",
    ("GET", "/field-metadata"): "runs.manage",
    ("GET", "/state"): "graph.read",
}
