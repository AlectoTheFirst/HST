"""Inventory tables on the store's shared `metadata`."""

from __future__ import annotations

from enum import StrEnum

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from hst.app.inventory.contracts import (
    ActivationState,
    Authority,
    CollectionState,
    Lifecycle,
    ObservationState,
    OutboxKind,
    OutboxState,
    PlacementMode,
    PlacementOrigin,
    PlacementState,
    PreviewOperation,
    PublicationState,
    TargetKind,
)
from hst.app.store.pg import metadata, reported_locations, sites, sources


def _values(enum: type[StrEnum]) -> tuple[str, ...]:
    return tuple(member.value for member in enum)


LIFECYCLES = _values(Lifecycle)
TARGET_KINDS = _values(TargetKind)
OBSERVATION_STATES = _values(ObservationState)
AUTHORITIES = _values(Authority)
PLACEMENT_MODES = _values(PlacementMode)
PLACEMENT_ORIGINS = _values(PlacementOrigin)
PLACEMENT_STATES = _values(PlacementState)
COLLECTION_STATES = _values(CollectionState)
PUBLICATION_STATES = _values(PublicationState)
OUTBOX_KINDS = _values(OutboxKind)
OUTBOX_STATES = _values(OutboxState)
ACTIVATION_STATES = _values(ActivationState)
PREVIEW_OPERATIONS = _values(PreviewOperation)

# The lifetime of a preview token in seconds. The maintenance sweep purges expired rows.
PREVIEW_TTL_S = 600
# Done outbox rows are deleted after this many days.
OUTBOX_DONE_RETENTION_DAYS = 7


def _in(name: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{name} IN ({quoted})"


# --- additions to legacy tables ---------------------------------------------------

# An editable display name beside the immutable execution key `sources.name`.
# An empty value shows the key.
sources.append_column(sa.Column("display_name", sa.Text, nullable=False, server_default=""))
# The connection's default profile. A target with no explicit profile follows it.
sources.append_column(
    sa.Column(
        "default_profile_id",
        UUID(as_uuid=True),
        sa.ForeignKey("collection_profiles.id", ondelete="SET NULL", name="fk_sources_default_profile"),
        nullable=True,
    )
)
# The revision of the inventory fields of this row (display name, default
# profile). Only the inventory service increments it.
sources.append_column(sa.Column("inventory_revision", sa.Integer, nullable=False, server_default="1"))
# The effective legacy normalization frozen at migration, with exact values,
# origins and identity relevance. NULL until the migration has run for this row.
sources.append_column(sa.Column("frozen_normalization", JSONB, nullable=True))

sites.append_column(sa.Column("revision", sa.Integer, nullable=False, server_default="1"))

reported_locations.append_column(sa.Column("revision", sa.Integer, nullable=False, server_default="1"))
# The opaque handle of the (source, location_id) pair in a URL.
reported_locations.append_column(
    sa.Column(
        "handle",
        UUID(as_uuid=True),
        nullable=False,
        server_default=sa.text("gen_random_uuid()"),
    )
)
reported_locations.append_constraint(sa.UniqueConstraint("handle", name="uq_reported_locations_handle"))

# --- collection profiles and credentials ----------------------------------------

collection_credentials = sa.Table(
    "collection_credentials",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("display_name", sa.Text, nullable=False, unique=True),
    sa.Column("current_revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint("current_revision > 0", name="ck_collection_credentials_revision"),
)

# The rows are immutable. `sealed` is the secret map, encrypted under the data key
# as `sources.secrets` is (app/crypto.py). `secret_paths` lists the dotted paths of
# the map.
collection_credential_versions = sa.Table(
    "collection_credential_versions",
    metadata,
    sa.Column(
        "credential_id",
        UUID(as_uuid=True),
        sa.ForeignKey("collection_credentials.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("revision", sa.Integer, primary_key=True),
    sa.Column("sealed", sa.LargeBinary, nullable=False),
    sa.Column("secret_paths", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.CheckConstraint("revision > 0", name="ck_collection_credential_versions_revision"),
)

collection_profiles = sa.Table(
    "collection_profiles",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("display_name", sa.Text, nullable=False, unique=True),
    # The one collector type this profile is compatible with.
    sa.Column("collector_type", sa.Text, nullable=False),
    sa.Column("current_revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint("current_revision > 0", name="ck_collection_profiles_revision"),
    sa.Index("ix_collection_profiles_collector_type", "collector_type"),
)

# The rows are immutable. `settings` holds the validated non-secret settings of
# the profile category. The credential pin is a composite FK to a credential version.
collection_profile_versions = sa.Table(
    "collection_profile_versions",
    metadata,
    sa.Column(
        "profile_id",
        UUID(as_uuid=True),
        sa.ForeignKey("collection_profiles.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("revision", sa.Integer, primary_key=True),
    sa.Column("settings", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("credential_id", UUID(as_uuid=True), nullable=True),
    sa.Column("credential_revision", sa.Integer, nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.ForeignKeyConstraint(
        ["credential_id", "credential_revision"],
        ["collection_credential_versions.credential_id", "collection_credential_versions.revision"],
        name="fk_collection_profile_versions_credential_version",
        ondelete="RESTRICT",
    ),
    sa.CheckConstraint("revision > 0", name="ck_collection_profile_versions_revision"),
    sa.CheckConstraint(
        "(credential_id IS NULL) = (credential_revision IS NULL)",
        name="ck_collection_profile_versions_credential_pair",
    ),
    sa.Index("ix_collection_profile_versions_credential", "credential_id", "credential_revision"),
)

# --- inventory devices, targets, observations -----------------------------------

inventory_devices = sa.Table(
    "inventory_devices",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("graph_uid", sa.Text, nullable=False, unique=True),
    sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("latest_snapshot_key", sa.Text, nullable=True),
    # The observed summary of the device. Only a published snapshot writes it.
    sa.Column("hostname", sa.Text, nullable=False, server_default=""),
    sa.Column("platform", sa.Text, nullable=False, server_default=""),
    sa.Column("management_address", sa.Text, nullable=False, server_default=""),
    sa.Column("lifecycle", sa.Text, nullable=False, server_default="active"),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    # The read-model summaries for the list hold the resolved placement and the
    # collection state. Only the inventory service writes them. `resolved_site_id`
    # is the desired site of the placement resolver, or NULL when the device is
    # unplaced, in conflict or stale.
    sa.Column("collection_state", sa.Text, nullable=False, server_default="never"),
    sa.Column("last_success_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("resolved_site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True),
    sa.Column("placement_state", sa.Text, nullable=False, server_default="unplaced"),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint(_in("lifecycle", LIFECYCLES), name="ck_inventory_devices_lifecycle"),
    sa.CheckConstraint(
        _in("collection_state", COLLECTION_STATES), name="ck_inventory_devices_collection_state"
    ),
    sa.CheckConstraint(_in("placement_state", PLACEMENT_STATES), name="ck_inventory_devices_placement_state"),
    sa.CheckConstraint("revision > 0", name="ck_inventory_devices_revision"),
    # The search compares the lowercase of hostname, graph_uid and management
    # address. Each of the 3 columns has an index on that expression.
    sa.Index("ix_inventory_devices_hostname", sa.text("lower(hostname)")),
    sa.Index("ix_inventory_devices_graph_uid", sa.text("lower(graph_uid)")),
    sa.Index("ix_inventory_devices_management_address", sa.text("lower(management_address)")),
    sa.Index("ix_inventory_devices_platform", "platform"),
    sa.Index("ix_inventory_devices_site", "resolved_site_id"),
    sa.Index("ix_inventory_devices_lifecycle", "lifecycle"),
    sa.Index("ix_inventory_devices_collection_state", "collection_state"),
    sa.Index("ix_inventory_devices_placement_state", "placement_state"),
    sa.Index("ix_inventory_devices_last_success", "last_success_at"),
)

# A target identifies an execution record. The address and the pin stay in the
# execution record. `source_key` is the immutable `sources.name` text. It stays
# when `source_id` is set to NULL.
inventory_targets = sa.Table(
    "inventory_targets",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="SET NULL"), nullable=True),
    sa.Column("source_key", sa.Text, nullable=False),
    # The host key of the execution record. It is `devices.host` for a fleet row,
    # `config.host` for an implicit or controller target, and "" for a controller
    # without a host.
    sa.Column("host", sa.Text, nullable=False, server_default=""),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column(
        "legacy_device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    ),
    sa.Column(
        "profile_id",
        UUID(as_uuid=True),
        sa.ForeignKey("collection_profiles.id", ondelete="RESTRICT"),
        nullable=True,
    ),
    sa.Column(
        "onboarding_site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True
    ),
    # A copy of the enabled flag of the execution record.
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # The collector identity overrides. The address and the TOFU pin stay in the execution records.
    sa.Column("endpoint_config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.UniqueConstraint("legacy_device_id", name="uq_inventory_targets_legacy_device"),
    sa.CheckConstraint(_in("kind", TARGET_KINDS), name="ck_inventory_targets_kind"),
    sa.CheckConstraint("revision > 0", name="ck_inventory_targets_revision"),
    sa.Index(
        "uq_inventory_targets_active",
        "source_key",
        "host",
        unique=True,
        postgresql_where=sa.text("archived_at IS NULL"),
    ),
    sa.Index("ix_inventory_targets_source", "source_id"),
    sa.Index("ix_inventory_targets_profile", "profile_id"),
)

# One row per (target, device) that the target observes or observed last.
# `notes` holds redacted collector warnings.
inventory_observations = sa.Table(
    "inventory_observations",
    metadata,
    sa.Column(
        "target_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_targets.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column(
        "device_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_devices.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column(
        "reported_location_handle",
        UUID(as_uuid=True),
        sa.ForeignKey("reported_locations.handle", ondelete="SET NULL"),
        nullable=True,
    ),
    sa.Column("last_success_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("last_seen_snapshot_key", sa.Text, nullable=True),
    sa.Column("state", sa.Text, nullable=False, server_default="current"),
    sa.Column("authority", sa.Text, nullable=False, server_default="complete"),
    sa.Column("notes", JSONB, nullable=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint(_in("state", OBSERVATION_STATES), name="ck_inventory_observations_state"),
    sa.CheckConstraint(_in("authority", AUTHORITIES), name="ck_inventory_observations_authority"),
    sa.Index("ix_inventory_observations_device", "device_id"),
    sa.Index("ix_inventory_observations_location", "reported_location_handle"),
)

inventory_placements = sa.Table(
    "inventory_placements",
    metadata,
    sa.Column(
        "device_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_devices.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("mode", sa.Text, nullable=False, server_default="auto"),
    # The site deletion service sets assigned placements to unplaced before it
    # deletes the site row.
    sa.Column("site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="RESTRICT"), nullable=True),
    sa.Column("origin", sa.Text, nullable=False, server_default="manual"),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # The applied state holds the revision that the last publication applied, the
    # site that it published and the key of that snapshot. An `applied_revision`
    # of 0 marks a placement that was never published.
    sa.Column("applied_revision", sa.Integer, nullable=False, server_default="0"),
    sa.Column("published_site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True),
    sa.Column("published_snapshot_key", sa.Text, nullable=True),
    sa.CheckConstraint(_in("mode", PLACEMENT_MODES), name="ck_inventory_placements_mode"),
    sa.CheckConstraint(_in("origin", PLACEMENT_ORIGINS), name="ck_inventory_placements_origin"),
    sa.CheckConstraint(
        "(mode = 'assigned') = (site_id IS NOT NULL)", name="ck_inventory_placements_assigned_site"
    ),
    sa.CheckConstraint("revision > 0", name="ck_inventory_placements_revision"),
    sa.Index("ix_inventory_placements_site", "site_id"),
)

# --- publication staging --------------------------------------------------------

inventory_publications = sa.Table(
    "inventory_publications",
    metadata,
    sa.Column("snapshot_key", sa.Text, primary_key=True),
    sa.Column("parent_snapshot_key", sa.Text, nullable=True),
    sa.Column("state", sa.Text, nullable=False, server_default="staged"),
    sa.Column("intent_generation", sa.BigInteger, nullable=False),
    # A redacted summary of the staged changes, with counts per target and per state.
    sa.Column("staged_changes", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    # A map from device id to the placement revision that this publication applied.
    sa.Column("placement_revisions", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("published_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("applied_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.CheckConstraint(_in("state", PUBLICATION_STATES), name="ck_inventory_publications_state"),
    sa.Index("ix_inventory_publications_state", "state", "created_at"),
)

# One row per target that took part in a run. The apply replaces the membership of
# a target with a complete result and updates the membership of a target with a
# partial result.
inventory_staged_targets = sa.Table(
    "inventory_staged_targets",
    metadata,
    sa.Column(
        "snapshot_key",
        sa.Text,
        sa.ForeignKey("inventory_publications.snapshot_key", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column(
        "target_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_targets.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("authority", sa.Text, nullable=False, server_default="complete"),
    sa.Column("succeeded", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("attempted_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint(_in("authority", AUTHORITIES), name="ck_inventory_staged_targets_authority"),
)

# One row per (target, observed graph device) in a run, keyed by graph uid.
inventory_staged_observations = sa.Table(
    "inventory_staged_observations",
    metadata,
    sa.Column(
        "snapshot_key",
        sa.Text,
        sa.ForeignKey("inventory_publications.snapshot_key", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column(
        "target_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_targets.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    sa.Column("graph_uid", sa.Text, primary_key=True),
    sa.Column("hostname", sa.Text, nullable=False, server_default=""),
    sa.Column("platform", sa.Text, nullable=False, server_default=""),
    sa.Column("management_address", sa.Text, nullable=False, server_default=""),
    sa.Column(
        "reported_location_handle",
        UUID(as_uuid=True),
        sa.ForeignKey("reported_locations.handle", ondelete="SET NULL"),
        nullable=True,
    ),
    sa.Column("notes", JSONB, nullable=True),
    sa.Index("ix_inventory_staged_observations_uid", "graph_uid"),
)

# --- events, views, routing groups ----------------------------------------------

inventory_events = sa.Table(
    "inventory_events",
    metadata,
    sa.Column("id", sa.BigInteger, primary_key=True),
    sa.Column("entity_type", sa.Text, nullable=False),
    sa.Column("entity_id", sa.Text, nullable=False),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("action", sa.Text, nullable=False),
    sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("before", JSONB, nullable=True),
    sa.Column("after", JSONB, nullable=True),
    # The idempotency request id of the apply that produced this event, if any.
    sa.Column("request_id", sa.Text, nullable=True),
    sa.Column("snapshot_key", sa.Text, nullable=True),
    # Sensitive connection changes are omitted for viewers.
    sa.Column("sensitive", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Index("ix_inventory_events_entity", "entity_type", "entity_id", "id"),
    sa.Index("ix_inventory_events_at", "at"),
)

inventory_saved_views = sa.Table(
    "inventory_saved_views",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("filter_version", sa.Integer, nullable=False, server_default="1"),
    sa.Column("filter", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("sort", sa.Text, nullable=False, server_default="name"),
    sa.Column("direction", sa.Text, nullable=False, server_default="asc"),
    sa.Column("columns", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("owner_id", "name", name="uq_inventory_saved_views_owner_name"),
    sa.CheckConstraint("revision > 0", name="ck_inventory_saved_views_revision"),
)

inventory_routing_groups = sa.Table(
    "inventory_routing_groups",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("display_name", sa.Text, nullable=False, unique=True),
    sa.Column("description", sa.Text, nullable=False, server_default=""),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint("revision > 0", name="ck_inventory_routing_groups_revision"),
)

# A person adds each context uid. A uid that disappears from the graph stays as a
# missing reference.
inventory_routing_members = sa.Table(
    "inventory_routing_members",
    metadata,
    sa.Column(
        "group_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_routing_groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column("context_uid", sa.Text, primary_key=True),
    sa.Column("owner_uid", sa.Text, nullable=False, server_default=""),
    sa.Column("added_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Index("ix_inventory_routing_members_context", "context_uid"),
)

# --- activation state, previews, idempotency, outbox ----------------------------

# The table holds one row with id 1. `resolver_version` 1 is the legacy resolver.
# The last step of the migration command activates version 2. `intent_generation`
# increases on every intent write. List cursors and preview tokens are pinned to it.
inventory_state = sa.Table(
    "inventory_state",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("resolver_version", sa.Integer, nullable=False, server_default="1"),
    sa.Column("schema_version", sa.Integer, nullable=False, server_default="1"),
    sa.Column("backfill_version", sa.Integer, nullable=False, server_default="0"),
    sa.Column("activation_state", sa.Text, nullable=False, server_default="inactive"),
    sa.Column("read_model_snapshot_key", sa.Text, nullable=True),
    sa.Column("intent_generation", sa.BigInteger, nullable=False, server_default="1"),
    sa.Column("inventory_sync_pending", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint("id = 1", name="ck_inventory_state_singleton"),
    sa.CheckConstraint(_in("activation_state", ACTIVATION_STATES), name="ck_inventory_state_activation"),
)

# A reused key with another digest is a 409. `response` is the redacted
# response that a retry of the same apply returns.
inventory_operation_results = sa.Table(
    "inventory_operation_results",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column("idempotency_key", sa.Text, nullable=False),
    sa.Column("request_digest", sa.Text, nullable=False),
    sa.Column("status", sa.Integer, nullable=False),
    sa.Column("response", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("actor_id", "idempotency_key", name="uq_inventory_operation_results_key"),
)

# The token is the primary key and holds no secret. The secret draft of a preview
# with new credential material is sealed under the data key and stored only in
# `secret_draft` until the preview is consumed.
inventory_operation_previews = sa.Table(
    "inventory_operation_previews",
    metadata,
    sa.Column("token", UUID(as_uuid=True), primary_key=True),
    sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column("operation", sa.Text, nullable=False),
    sa.Column("permissions", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    sa.Column("intent_generation", sa.BigInteger, nullable=False),
    sa.Column("snapshot_key", sa.Text, nullable=True),
    # The selection as ids with their expected revisions. It is immutable.
    sa.Column("members", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    sa.Column("changes", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("impact", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("secret_draft", sa.LargeBinary, nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column(
        "result_id",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_operation_results.id", ondelete="SET NULL"),
        nullable=True,
    ),
    sa.CheckConstraint(_in("operation", PREVIEW_OPERATIONS), name="ck_inventory_operation_previews_op"),
    sa.Index("ix_inventory_operation_previews_expiry", "expires_at"),
)

# The derived impact rows of a preview. The impact endpoint pages them with exact
# totals. The repository bounds them to 100,000 rows per preview.
inventory_preview_impacts = sa.Table(
    "inventory_preview_impacts",
    metadata,
    sa.Column(
        "token",
        UUID(as_uuid=True),
        sa.ForeignKey("inventory_operation_previews.token", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column("seq", sa.Integer, primary_key=True),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("entity_id", sa.Text, nullable=False),
    sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
)

# The lease columns are on the row, as in `jobs`.
inventory_outbox = sa.Table(
    "inventory_outbox",
    metadata,
    sa.Column("id", sa.BigInteger, primary_key=True),
    sa.Column("dedup_key", sa.Text, nullable=False, unique=True),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("state", sa.Text, nullable=False, server_default="pending"),
    sa.Column("attempt", sa.Integer, nullable=False, server_default="0"),
    sa.Column("max_attempts", sa.Integer, nullable=False, server_default="5"),
    sa.Column("lease_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("claimed_by", sa.Text, nullable=True),
    sa.Column("next_attempt_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_error", sa.Text, nullable=False, server_default=""),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint(_in("kind", OUTBOX_KINDS), name="ck_inventory_outbox_kind"),
    sa.CheckConstraint(_in("state", OUTBOX_STATES), name="ck_inventory_outbox_state"),
    sa.Index("ix_inventory_outbox_ready", "state", "next_attempt_at"),
)

INVENTORY_TABLES: tuple[sa.Table, ...] = (
    collection_credentials,
    collection_credential_versions,
    collection_profiles,
    collection_profile_versions,
    inventory_devices,
    inventory_targets,
    inventory_observations,
    inventory_placements,
    inventory_publications,
    inventory_staged_targets,
    inventory_staged_observations,
    inventory_events,
    inventory_saved_views,
    inventory_routing_groups,
    inventory_routing_members,
    inventory_state,
    inventory_operation_results,
    inventory_operation_previews,
    inventory_preview_impacts,
    inventory_outbox,
)

# The (table, column) pairs that migration 0028 adds to legacy tables, in the order of the migration.
LEGACY_ADDITIONS: tuple[tuple[str, str], ...] = (
    ("sources", "display_name"),
    ("sources", "default_profile_id"),
    ("sources", "inventory_revision"),
    ("sources", "frozen_normalization"),
    ("sites", "revision"),
    ("reported_locations", "revision"),
    ("reported_locations", "handle"),
)
