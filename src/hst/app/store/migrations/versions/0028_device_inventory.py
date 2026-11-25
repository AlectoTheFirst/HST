"""Device inventory: intent, collection profiles, provenance.

Revision ID: 0028
Revises: 0027

The migration adds columns to 3 existing tables. `sources` gains a display
name, a default profile, an inventory revision and a frozen normalization.
`sites` and `reported_locations` gain an integer revision. `reported_locations`
gains a UUID handle, filled with gen_random_uuid(). Every other change is a new
table. The migration reads no row of an existing table and decrypts no secret.
A new deployment starts with an empty inventory.

`downgrade` drops what `upgrade` created, in reverse order of dependency. The
`inventory_state` row starts at resolver_version 1 with the activation state
`inactive`.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def _in(name: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{name} IN ({quoted})"


LIFECYCLES = ("active", "missing", "archived")
TARGET_KINDS = ("direct", "controller", "implicit")
OBSERVATION_STATES = ("current", "stale", "absent")
AUTHORITIES = ("complete", "partial")
PLACEMENT_MODES = ("auto", "assigned", "unplaced")
PLACEMENT_ORIGINS = ("manual", "migrated", "onboarding")
PLACEMENT_STATES = ("assigned", "auto", "unplaced", "conflict", "stale", "pending")
COLLECTION_STATES = ("current", "stale", "partial", "failed", "never", "manual")
PUBLICATION_STATES = ("staged", "published", "applied", "aborted")
OUTBOX_KINDS = ("publication_reconcile", "job_enqueue")
OUTBOX_STATES = ("pending", "running", "done", "failed")
ACTIVATION_STATES = ("inactive", "backfill_ready", "active")
PREVIEW_OPERATIONS = (
    "place_devices",
    "assign_target_profile",
    "edit_profile",
    "rotate_credential",
    "delete_site",
    "delete_connection",
    "delete_target",
    "replace_target",
    "edit_routing_members",
    "archive_devices",
    "restore_devices",
)

TS = sa.TIMESTAMP(timezone=True)


def _uuid() -> UUID:
    return UUID(as_uuid=True)


def upgrade() -> None:
    # --- profiles and credentials, referenced by sources and targets -------------
    op.create_table(
        "collection_credentials",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("display_name", sa.Text, nullable=False, unique=True),
        sa.Column("current_revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("archived_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("current_revision > 0", name="ck_collection_credentials_revision"),
    )
    op.create_table(
        "collection_credential_versions",
        sa.Column(
            "credential_id",
            _uuid(),
            sa.ForeignKey("collection_credentials.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("revision", sa.Integer, primary_key=True),
        sa.Column("sealed", sa.LargeBinary, nullable=False),
        sa.Column("secret_paths", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.CheckConstraint("revision > 0", name="ck_collection_credential_versions_revision"),
    )
    op.create_table(
        "collection_profiles",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("display_name", sa.Text, nullable=False, unique=True),
        sa.Column("collector_type", sa.Text, nullable=False),
        sa.Column("current_revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("archived_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("current_revision > 0", name="ck_collection_profiles_revision"),
    )
    op.create_index("ix_collection_profiles_collector_type", "collection_profiles", ["collector_type"])
    op.create_table(
        "collection_profile_versions",
        sa.Column(
            "profile_id",
            _uuid(),
            sa.ForeignKey("collection_profiles.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("revision", sa.Integer, primary_key=True),
        sa.Column("settings", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("credential_id", _uuid(), nullable=True),
        sa.Column("credential_revision", sa.Integer, nullable=True),
        sa.Column("created_at", TS, nullable=False),
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
    )
    op.create_index(
        "ix_collection_profile_versions_credential",
        "collection_profile_versions",
        ["credential_id", "credential_revision"],
    )

    # --- columns on existing tables -----------------------------------------------
    op.add_column("sources", sa.Column("display_name", sa.Text, nullable=False, server_default=""))
    op.add_column("sources", sa.Column("default_profile_id", _uuid(), nullable=True))
    op.create_foreign_key(
        "fk_sources_default_profile",
        "sources",
        "collection_profiles",
        ["default_profile_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("sources", sa.Column("inventory_revision", sa.Integer, nullable=False, server_default="1"))
    op.add_column("sources", sa.Column("frozen_normalization", JSONB, nullable=True))
    op.add_column("sites", sa.Column("revision", sa.Integer, nullable=False, server_default="1"))
    op.add_column("reported_locations", sa.Column("revision", sa.Integer, nullable=False, server_default="1"))
    # The server default fills every existing row in the statement that adds the
    # NOT NULL column. The unique constraint follows.
    op.add_column(
        "reported_locations",
        sa.Column("handle", _uuid(), nullable=False, server_default=sa.text("gen_random_uuid()")),
    )
    op.create_unique_constraint("uq_reported_locations_handle", "reported_locations", ["handle"])

    # --- devices, targets, observations, placements -------------------------------
    op.create_table(
        "inventory_devices",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("graph_uid", sa.Text, nullable=False, unique=True),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("latest_snapshot_key", sa.Text, nullable=True),
        sa.Column("hostname", sa.Text, nullable=False, server_default=""),
        sa.Column("platform", sa.Text, nullable=False, server_default=""),
        sa.Column("management_address", sa.Text, nullable=False, server_default=""),
        sa.Column("lifecycle", sa.Text, nullable=False, server_default="active"),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("collection_state", sa.Text, nullable=False, server_default="never"),
        sa.Column("last_success_at", TS, nullable=True),
        sa.Column(
            "resolved_site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("placement_state", sa.Text, nullable=False, server_default="unplaced"),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(_in("lifecycle", LIFECYCLES), name="ck_inventory_devices_lifecycle"),
        sa.CheckConstraint(
            _in("collection_state", COLLECTION_STATES), name="ck_inventory_devices_collection_state"
        ),
        sa.CheckConstraint(
            _in("placement_state", PLACEMENT_STATES), name="ck_inventory_devices_placement_state"
        ),
        sa.CheckConstraint("revision > 0", name="ck_inventory_devices_revision"),
    )
    op.create_index("ix_inventory_devices_hostname", "inventory_devices", [sa.text("lower(hostname)")])
    op.create_index("ix_inventory_devices_graph_uid", "inventory_devices", [sa.text("lower(graph_uid)")])
    op.create_index(
        "ix_inventory_devices_management_address", "inventory_devices", [sa.text("lower(management_address)")]
    )
    op.create_index("ix_inventory_devices_platform", "inventory_devices", ["platform"])
    op.create_index("ix_inventory_devices_site", "inventory_devices", ["resolved_site_id"])
    op.create_index("ix_inventory_devices_lifecycle", "inventory_devices", ["lifecycle"])
    op.create_index("ix_inventory_devices_collection_state", "inventory_devices", ["collection_state"])
    op.create_index("ix_inventory_devices_placement_state", "inventory_devices", ["placement_state"])
    op.create_index("ix_inventory_devices_last_success", "inventory_devices", ["last_success_at"])

    op.create_table(
        "inventory_targets",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("source_id", sa.Integer, sa.ForeignKey("sources.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_key", sa.Text, nullable=False),
        sa.Column("host", sa.Text, nullable=False, server_default=""),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column(
            "legacy_device_id", sa.Integer, sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column(
            "profile_id", _uuid(), sa.ForeignKey("collection_profiles.id", ondelete="RESTRICT"), nullable=True
        ),
        sa.Column(
            "onboarding_site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("archived_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.UniqueConstraint("legacy_device_id", name="uq_inventory_targets_legacy_device"),
        sa.CheckConstraint(_in("kind", TARGET_KINDS), name="ck_inventory_targets_kind"),
        sa.CheckConstraint("revision > 0", name="ck_inventory_targets_revision"),
    )
    op.create_index(
        "uq_inventory_targets_active",
        "inventory_targets",
        ["source_key", "host"],
        unique=True,
        postgresql_where=sa.text("archived_at IS NULL"),
    )
    op.create_index("ix_inventory_targets_source", "inventory_targets", ["source_id"])
    op.create_index("ix_inventory_targets_profile", "inventory_targets", ["profile_id"])

    op.create_table(
        "inventory_observations",
        sa.Column(
            "target_id", _uuid(), sa.ForeignKey("inventory_targets.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column(
            "device_id", _uuid(), sa.ForeignKey("inventory_devices.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column(
            "reported_location_handle",
            _uuid(),
            sa.ForeignKey("reported_locations.handle", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("last_success_at", TS, nullable=True),
        sa.Column("last_seen_snapshot_key", sa.Text, nullable=True),
        sa.Column("state", sa.Text, nullable=False, server_default="current"),
        sa.Column("authority", sa.Text, nullable=False, server_default="complete"),
        sa.Column("notes", JSONB, nullable=True),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(_in("state", OBSERVATION_STATES), name="ck_inventory_observations_state"),
        sa.CheckConstraint(_in("authority", AUTHORITIES), name="ck_inventory_observations_authority"),
    )
    op.create_index("ix_inventory_observations_device", "inventory_observations", ["device_id"])
    op.create_index(
        "ix_inventory_observations_location", "inventory_observations", ["reported_location_handle"]
    )

    op.create_table(
        "inventory_placements",
        sa.Column(
            "device_id", _uuid(), sa.ForeignKey("inventory_devices.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column("mode", sa.Text, nullable=False, server_default="auto"),
        sa.Column("site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("origin", sa.Text, nullable=False, server_default="manual"),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("applied_revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "published_site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("published_snapshot_key", sa.Text, nullable=True),
        sa.CheckConstraint(_in("mode", PLACEMENT_MODES), name="ck_inventory_placements_mode"),
        sa.CheckConstraint(_in("origin", PLACEMENT_ORIGINS), name="ck_inventory_placements_origin"),
        sa.CheckConstraint(
            "(mode = 'assigned') = (site_id IS NOT NULL)", name="ck_inventory_placements_assigned_site"
        ),
        sa.CheckConstraint("revision > 0", name="ck_inventory_placements_revision"),
    )
    op.create_index("ix_inventory_placements_site", "inventory_placements", ["site_id"])

    # --- publications and staging ---------------------------------------------------
    op.create_table(
        "inventory_publications",
        sa.Column("snapshot_key", sa.Text, primary_key=True),
        sa.Column("parent_snapshot_key", sa.Text, nullable=True),
        sa.Column("state", sa.Text, nullable=False, server_default="staged"),
        sa.Column("intent_generation", sa.BigInteger, nullable=False),
        sa.Column("staged_changes", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("placement_revisions", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("published_at", TS, nullable=True),
        sa.Column("applied_at", TS, nullable=True),
        sa.CheckConstraint(_in("state", PUBLICATION_STATES), name="ck_inventory_publications_state"),
    )
    op.create_index("ix_inventory_publications_state", "inventory_publications", ["state", "created_at"])
    op.create_table(
        "inventory_staged_targets",
        sa.Column(
            "snapshot_key",
            sa.Text,
            sa.ForeignKey("inventory_publications.snapshot_key", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "target_id", _uuid(), sa.ForeignKey("inventory_targets.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column("authority", sa.Text, nullable=False, server_default="complete"),
        sa.Column("succeeded", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("attempted_at", TS, nullable=False),
        sa.CheckConstraint(_in("authority", AUTHORITIES), name="ck_inventory_staged_targets_authority"),
    )
    op.create_table(
        "inventory_staged_observations",
        sa.Column(
            "snapshot_key",
            sa.Text,
            sa.ForeignKey("inventory_publications.snapshot_key", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "target_id", _uuid(), sa.ForeignKey("inventory_targets.id", ondelete="RESTRICT"), primary_key=True
        ),
        sa.Column("graph_uid", sa.Text, primary_key=True),
        sa.Column("hostname", sa.Text, nullable=False, server_default=""),
        sa.Column("platform", sa.Text, nullable=False, server_default=""),
        sa.Column("management_address", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "reported_location_handle",
            _uuid(),
            sa.ForeignKey("reported_locations.handle", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", JSONB, nullable=True),
    )
    op.create_index("ix_inventory_staged_observations_uid", "inventory_staged_observations", ["graph_uid"])

    # --- events, views, routing groups ------------------------------------------------
    op.create_table(
        "inventory_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("entity_id", sa.Text, nullable=False),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("at", TS, nullable=False),
        sa.Column("before", JSONB, nullable=True),
        sa.Column("after", JSONB, nullable=True),
        sa.Column("request_id", sa.Text, nullable=True),
        sa.Column("snapshot_key", sa.Text, nullable=True),
        sa.Column("sensitive", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_inventory_events_entity", "inventory_events", ["entity_type", "entity_id", "id"])
    op.create_index("ix_inventory_events_at", "inventory_events", ["at"])

    op.create_table(
        "inventory_saved_views",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("filter_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("filter", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("sort", sa.Text, nullable=False, server_default="name"),
        sa.Column("direction", sa.Text, nullable=False, server_default="asc"),
        sa.Column("columns", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.UniqueConstraint("owner_id", "name", name="uq_inventory_saved_views_owner_name"),
        sa.CheckConstraint("revision > 0", name="ck_inventory_saved_views_revision"),
    )

    op.create_table(
        "inventory_routing_groups",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("display_name", sa.Text, nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("archived_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("revision > 0", name="ck_inventory_routing_groups_revision"),
    )
    op.create_table(
        "inventory_routing_members",
        sa.Column(
            "group_id",
            _uuid(),
            sa.ForeignKey("inventory_routing_groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("context_uid", sa.Text, primary_key=True),
        sa.Column("owner_uid", sa.Text, nullable=False, server_default=""),
        sa.Column("added_at", TS, nullable=False),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_inventory_routing_members_context", "inventory_routing_members", ["context_uid"])

    # --- activation state, idempotency, previews, outbox ------------------------------
    op.create_table(
        "inventory_state",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("resolver_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("schema_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("backfill_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("activation_state", sa.Text, nullable=False, server_default="inactive"),
        sa.Column("read_model_snapshot_key", sa.Text, nullable=True),
        sa.Column("intent_generation", sa.BigInteger, nullable=False, server_default="1"),
        sa.Column("inventory_sync_pending", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("id = 1", name="ck_inventory_state_singleton"),
        sa.CheckConstraint(_in("activation_state", ACTIVATION_STATES), name="ck_inventory_state_activation"),
    )
    op.execute("INSERT INTO inventory_state (id, updated_at) VALUES (1, now())")

    op.create_table(
        "inventory_operation_results",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("idempotency_key", sa.Text, nullable=False),
        sa.Column("request_digest", sa.Text, nullable=False),
        sa.Column("status", sa.Integer, nullable=False),
        sa.Column("response", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("actor_id", "idempotency_key", name="uq_inventory_operation_results_key"),
    )
    op.create_table(
        "inventory_operation_previews",
        sa.Column("token", _uuid(), primary_key=True),
        sa.Column("actor_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("operation", sa.Text, nullable=False),
        sa.Column("permissions", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("intent_generation", sa.BigInteger, nullable=False),
        sa.Column("snapshot_key", sa.Text, nullable=True),
        sa.Column("members", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("changes", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("impact", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("secret_draft", sa.LargeBinary, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("consumed_at", TS, nullable=True),
        sa.Column(
            "result_id",
            _uuid(),
            sa.ForeignKey("inventory_operation_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint(_in("operation", PREVIEW_OPERATIONS), name="ck_inventory_operation_previews_op"),
    )
    op.create_index("ix_inventory_operation_previews_expiry", "inventory_operation_previews", ["expires_at"])
    op.create_table(
        "inventory_preview_impacts",
        sa.Column(
            "token",
            _uuid(),
            sa.ForeignKey("inventory_operation_previews.token", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("seq", sa.Integer, primary_key=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("entity_id", sa.Text, nullable=False),
        sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_table(
        "inventory_outbox",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("dedup_key", sa.Text, nullable=False, unique=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("state", sa.Text, nullable=False, server_default="pending"),
        sa.Column("attempt", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False, server_default="5"),
        sa.Column("lease_expires_at", TS, nullable=True),
        sa.Column("claimed_by", sa.Text, nullable=True),
        sa.Column("next_attempt_at", TS, nullable=False),
        sa.Column("last_error", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(_in("kind", OUTBOX_KINDS), name="ck_inventory_outbox_kind"),
        sa.CheckConstraint(_in("state", OUTBOX_STATES), name="ck_inventory_outbox_state"),
    )
    op.create_index("ix_inventory_outbox_ready", "inventory_outbox", ["state", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_inventory_outbox_ready", table_name="inventory_outbox")
    op.drop_table("inventory_outbox")
    op.drop_table("inventory_preview_impacts")
    op.drop_index("ix_inventory_operation_previews_expiry", table_name="inventory_operation_previews")
    op.drop_table("inventory_operation_previews")
    op.drop_table("inventory_operation_results")
    op.drop_table("inventory_state")
    op.drop_index("ix_inventory_routing_members_context", table_name="inventory_routing_members")
    op.drop_table("inventory_routing_members")
    op.drop_table("inventory_routing_groups")
    op.drop_table("inventory_saved_views")
    op.drop_index("ix_inventory_events_at", table_name="inventory_events")
    op.drop_index("ix_inventory_events_entity", table_name="inventory_events")
    op.drop_table("inventory_events")
    op.drop_index("ix_inventory_staged_observations_uid", table_name="inventory_staged_observations")
    op.drop_table("inventory_staged_observations")
    op.drop_table("inventory_staged_targets")
    op.drop_index("ix_inventory_publications_state", table_name="inventory_publications")
    op.drop_table("inventory_publications")
    op.drop_index("ix_inventory_placements_site", table_name="inventory_placements")
    op.drop_table("inventory_placements")
    op.drop_index("ix_inventory_observations_location", table_name="inventory_observations")
    op.drop_index("ix_inventory_observations_device", table_name="inventory_observations")
    op.drop_table("inventory_observations")
    op.drop_index("ix_inventory_targets_profile", table_name="inventory_targets")
    op.drop_index("ix_inventory_targets_source", table_name="inventory_targets")
    op.drop_index("uq_inventory_targets_active", table_name="inventory_targets")
    op.drop_table("inventory_targets")
    for name in (
        "ix_inventory_devices_last_success",
        "ix_inventory_devices_placement_state",
        "ix_inventory_devices_collection_state",
        "ix_inventory_devices_lifecycle",
        "ix_inventory_devices_site",
        "ix_inventory_devices_platform",
        "ix_inventory_devices_management_address",
        "ix_inventory_devices_graph_uid",
        "ix_inventory_devices_hostname",
    ):
        op.drop_index(name, table_name="inventory_devices")
    op.drop_table("inventory_devices")

    op.drop_constraint("uq_reported_locations_handle", "reported_locations", type_="unique")
    op.drop_column("reported_locations", "handle")
    op.drop_column("reported_locations", "revision")
    op.drop_column("sites", "revision")
    op.drop_column("sources", "frozen_normalization")
    op.drop_column("sources", "inventory_revision")
    op.drop_constraint("fk_sources_default_profile", "sources", type_="foreignkey")
    op.drop_column("sources", "default_profile_id")
    op.drop_column("sources", "display_name")

    op.drop_index("ix_collection_profile_versions_credential", table_name="collection_profile_versions")
    op.drop_table("collection_profile_versions")
    op.drop_index("ix_collection_profiles_collector_type", table_name="collection_profiles")
    op.drop_table("collection_profiles")
    op.drop_table("collection_credential_versions")
    op.drop_table("collection_credentials")
