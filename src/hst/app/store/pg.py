"""The PostgreSQL store, with SQLAlchemy async core and Alembic migrations."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import itertools
import logging
import ssl
from collections.abc import AsyncIterator, Callable, Collection, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID as UUID_T
from uuid import uuid4

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.dialects.postgresql import JSONB, UUID, insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from hst.app.geo_places import name_key
from hst.app.store import (
    LIST_TITLE_CHARS,
    SESSION_TOUCH_INTERVAL,
    SSO_TOKEN_LOGIN_MAX_AGE,
    TURN_ACTIVE_STATES,
    TURN_FINAL_STATES,
    UNSET,
    AccessToken,
    AiConversation,
    AiEvent,
    AiLink,
    AiMessage,
    AiStep,
    AiTokenUsage,
    AiTurn,
    AiTurnProgress,
    AppSetting,
    AuthProvider,
    AuthState,
    Change,
    ChangeIntent,
    CypherEvent,
    Device,
    DeviceIdentity,
    DeviceIdentityReport,
    DeviceSpec,
    DeviceStatus,
    EvidenceExport,
    GeoPlace,
    GeoPlaceSearch,
    GroupMapping,
    Identity,
    IdentityOwnerMissing,
    Job,
    LoginEvent,
    MapViewNameTaken,
    NetworkMapLayout,
    NetworkMapView,
    ReportedLocation,
    Run,
    Site,
    SiteRelease,
    Source,
    StaleMapRevision,
    TargetDevice,
    TurnCapExceeded,
    User,
    canonical_uuid,
    identity_report,
    step_digest,
)
from hst.assessment.store import AssessmentStoreMixin, AssessmentTransaction, bounded_json
from hst.core import uid as uidmod
from hst.core.identity import base_uid, identifier, legacy_uid, mint_for

if TYPE_CHECKING:
    from hst.app.inventory.repository import PgInventoryRepository

log = logging.getLogger(__name__)

metadata = sa.MetaData()

# A row holds one serialized, bounded document of the versioned schema. The API
# only inserts a revision row. A mutable queue or freshness row uses revision 1.
assessment_records = sa.Table(
    "assessment_records",
    metadata,
    sa.Column("kind", sa.Text, primary_key=True),
    sa.Column("id", sa.Text, primary_key=True),
    sa.Column("revision", sa.Integer, primary_key=True),
    sa.Column("document", JSONB, nullable=False),
    sa.CheckConstraint("revision > 0", name="assessment_positive_revision"),
)
analysis_cache_artifacts = sa.Table(
    "analysis_cache_artifacts",
    metadata,
    sa.Column("cache_key", sa.String(64), primary_key=True),
    sa.Column("artifact_sha256", sa.String(64), nullable=False),
    sa.Column("path", sa.Text, nullable=False),
    sa.Column("encrypted_bytes", sa.BigInteger, nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("accessed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("lease_count", sa.Integer, nullable=False, server_default="0"),
    sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("pinned", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.CheckConstraint("encrypted_bytes > 0", name="analysis_cache_positive_bytes"),
    sa.CheckConstraint("lease_count >= 0", name="analysis_cache_nonnegative_leases"),
)
analysis_cache_leases = sa.Table(
    "analysis_cache_leases",
    metadata,
    sa.Column("lease_token", sa.String(48), primary_key=True),
    sa.Column(
        "cache_key",
        sa.String(64),
        sa.ForeignKey("analysis_cache_artifacts.cache_key", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
)
sa.Index(
    "analysis_cache_lease_expiry",
    analysis_cache_leases.c.cache_key,
    analysis_cache_leases.c.expires_at,
)
sa.Index(
    "analysis_cache_lru",
    analysis_cache_artifacts.c.pinned,
    analysis_cache_artifacts.c.lease_count,
    analysis_cache_artifacts.c.accessed_at,
)
sa.Index("assessment_records_document", assessment_records.c.document, postgresql_using="gin")
sa.Index(
    "assessment_records_queue",
    assessment_records.c.kind,
    assessment_records.c.document["state"].astext,
    assessment_records.c.document["created_at"].astext,
)
# The transaction lock of the assessment operations. A transaction under it runs
# no simulation and no collection. The lock serializes admission, revision
# checks, digest deduplication and lease fencing across the app replicas.
ASSESSMENT_LOCK = 3_687_102_894_100_231


# A 64-bit constant, the same in every process that runs first-run setup against
# this database. It differs from MIGRATION_LOCK of env.py.
FIRST_USER_LOCK = 8_071_552_014_921_338

# The cycle lock is one lock for all sources. It is in the single-bigint keyspace
# of FIRST_USER_LOCK and has its own key.
CYCLE_LOCK = 5_512_907_446_318_205

# The sequence of the publication fence. `cycle_lock` draws one value per
# acquisition and yields it to the caller. The caller passes it to the graph,
# and the cycle pointer refuses a value below the value that it holds
# (core/cycle.py `set_pointer`). A holder whose lock connection dies keeps
# running on its worker thread while the next holder writes.
CYCLE_FENCE_SEQ = "cycle_fence_seq"

# The interval of the check of a lock connection, in seconds.
LOCK_PING_S = 5.0

# Run claims use the two-int advisory form (class, hashtext(source)), a keyspace
# disjoint from the single-bigint FIRST_USER_LOCK and MIGRATION_LOCK. The lock is
# session-scoped on a connection held for the whole run.
RUN_CLAIM_CLASS = 471_113

# The lock of the leader election of the scheduler. One process holds it while
# it schedules. It is in the single-bigint keyspace of FIRST_USER_LOCK and
# CYCLE_LOCK and has its own key. Postgres releases the lock of a dead leader
# when its connection closes.
SCHEDULER_LOCK = 6_204_881_357_009_744

# The per-user lock of `start_turn`, in the two-int advisory form (class, user
# id) with a class other than RUN_CLAIM_CLASS. It is transaction-scoped. The
# per-user count and the insert run under it in one transaction.
AI_TURN_LOCK_CLASS = 471_114

# The lock of `modify_setting`, in the two-int advisory form (class,
# hashtext(key)). It is transaction-scoped and serializes 2 writers of a key
# that has no row yet.
SETTING_LOCK_CLASS = 471_115

# The transaction-scoped lock of the mint in `resolve_device` and of the move in
# `rekey_device`. It is in the single-bigint keyspace of FIRST_USER_LOCK and
# CYCLE_LOCK and has its own key. The loads of one run are serial. The lock
# stops 2 processes that mint at one time from giving one uid to 2 devices. A
# uid has many rows, and no constraint refuses that.
DEVICE_IDENTITY_LOCK = 2_906_331_871_455_120

users = sa.Table(
    "users",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("username", sa.Text, nullable=False, unique=True),
    # NULL means "no password authentication" for SSO-provisioned accounts. The login
    # endpoint refuses password auth for these before touching the hasher
    # (app/auth.py).
    sa.Column("password_hash", sa.Text, nullable=True),
    sa.Column("role", sa.Text, nullable=False),
    sa.Column("disabled", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # 'local' is a role that an admin assigned. 'mapped' is a role from the group
    # mappings. An SSO login recomputes a 'mapped' role and keeps a 'local' role.
    sa.Column("role_source", sa.Text, nullable=False, server_default="local"),
    # NULL means "never chose a theme".
    sa.Column("theme", sa.Text, nullable=True),
)

sessions = sa.Table(
    "sessions",
    metadata,
    sa.Column("token_hash", sa.Text, primary_key=True),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # The time of the last use, for the idle expiry (0009). It is written at
    # issue, and a use writes it at most once per SESSION_TOUCH_INTERVAL.
    sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=False),
)

# The bearer credentials of the MCP HTTP transport (0034). The table stores the
# hash of a token, as for sessions. A token is deleted with its user, and
# revoking one deletes its row. `scope` is fixed at creation.
personal_access_tokens = sa.Table(
    "personal_access_tokens",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("token_hash", sa.Text, nullable=False),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("scope", sa.Text, nullable=False, server_default="read"),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # NULL until the token first authenticates. A use writes it at most once per
    # SESSION_TOUCH_INTERVAL, as for sessions.last_used_at.
    sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.UniqueConstraint("token_hash", name="uq_personal_access_tokens_token_hash"),
    sa.CheckConstraint("scope IN ('read', 'read-write')", name="ck_personal_access_tokens_scope"),
    sa.Index("ix_personal_access_tokens_user", "user_id"),
)

runs = sa.Table(
    "runs",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("source", sa.Text, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("detail", sa.Text, nullable=False, server_default=""),
    # The account that asked for the run. NULL for cron and the reasoner.
    sa.Column("triggered_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    # The snapshot that the run published. `finish_run` sets it (0015). It is
    # text, as the id that `/api/snapshots` reports. It is NULL for a run that
    # published nothing.
    sa.Column("snapshot_key", sa.Text, nullable=True),
    # The index allows at most one 'running' row per source, in addition to the
    # advisory-lock claim.
    sa.Index("one_running_per_source", "source", unique=True, postgresql_where=sa.text("status = 'running'")),
)

# COALESCE in `one_pending_per_kind` maps a NULL source or device to '' for the unique index.
jobs = sa.Table(
    "jobs",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("source", sa.Text, nullable=True),
    sa.Column("device", sa.Text, nullable=True),
    sa.Column("state", sa.Text, nullable=False, server_default="queued"),
    sa.Column("priority", sa.Integer, nullable=False, server_default="0"),
    sa.Column("attempt", sa.Integer, nullable=False, server_default="0"),
    sa.Column("max_attempts", sa.Integer, nullable=False, server_default="1"),
    sa.Column("not_before", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("lease_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("claimed_by", sa.Text, nullable=True),
    sa.Column("enqueued_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("detail", sa.Text, nullable=True),
    sa.Column("triggered_by", sa.Text, nullable=False, server_default=""),
    sa.Index(
        "one_pending_per_kind",
        "kind",
        sa.text("coalesce(source, '')"),
        sa.text("coalesce(device, '')"),
        unique=True,
        postgresql_where=sa.text("state IN ('queued', 'running')"),
    ),
    sa.Index("jobs_ready", "priority", "not_before", postgresql_where=sa.text("state = 'queued'")),
    sa.Index("ix_jobs_finished_at", "finished_at"),
)

sources = sa.Table(
    "sources",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("name", sa.Text, nullable=False, unique=True),
    sa.Column("type", sa.Text, nullable=False),
    sa.Column("config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("secrets", sa.LargeBinary, nullable=False, server_default=sa.text("''::bytea")),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)

devices = sa.Table(
    "devices",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column(
        "source",
        sa.Text,
        sa.ForeignKey("sources.name", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    ),
    sa.Column("host", sa.Text, nullable=False),
    sa.Column("port", sa.Integer, nullable=True),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
    sa.Column("host_key", sa.Text, nullable=False, server_default=""),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("source", "host", name="uq_devices_source_host"),
    # `alembic check` compares the name with 0012_devices.py.
    sa.Index("ix_devices_source", "source"),
)

device_status = sa.Table(
    "device_status",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column(
        "source",
        sa.Text,
        sa.ForeignKey("sources.name", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    ),
    sa.Column("host", sa.Text, nullable=False),
    sa.Column("last_raw_sha", sa.Text, nullable=False, server_default=""),
    sa.Column("last_obs_sha", sa.Text, nullable=False, server_default=""),
    sa.Column("last_attempt_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("last_success_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("last_full_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default="0"),
    sa.Column("last_error", sa.Text, nullable=False, server_default=""),
    sa.Column("fetch_ms", sa.Integer, nullable=True),
    sa.Column("normalize_ms", sa.Integer, nullable=True),
    sa.Column("load_ms", sa.Integer, nullable=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_graph_sha", sa.Text, nullable=False, server_default=""),
    sa.Column("last_graph_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("last_graph_fetch_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("last_verified_started_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("last_verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.UniqueConstraint("source", "host", name="uq_device_status_source_host"),
    # `alembic check` compares the name with 0013_device_status.py.
    sa.Index("ix_device_status_source", "source"),
)

changes = sa.Table(
    "changes",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("title", sa.Text, nullable=False),
    sa.Column("description", sa.Text, nullable=False, server_default=""),
    sa.Column("snapshot_cts", sa.BigInteger, nullable=True),
    sa.Column("status", sa.Text, nullable=False, server_default="draft"),
    sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # `alembic check` compares the name with 0014_changes.py.
    sa.CheckConstraint("status IN ('draft', 'simulated', 'closed')", name="ck_changes_status"),
)

change_intents = sa.Table(
    "change_intents",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("change_id", sa.Integer, sa.ForeignKey("changes.id", ondelete="CASCADE"), nullable=False),
    sa.Column("position", sa.Integer, nullable=False),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("params", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.UniqueConstraint("change_id", "position", name="uq_change_intents_change_position"),
    # `alembic check` compares the name with 0014_changes.py.
    sa.Index("ix_change_intents_change", "change_id"),
)

sites = sa.Table(
    "sites",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("code", sa.Text, nullable=False, unique=True),
    sa.Column("name", sa.Text, nullable=False, server_default=""),
    sa.Column("location", sa.Text, nullable=False, server_default=""),
    sa.Column("params", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)

site_members = sa.Table(
    "site_members",
    metadata,
    sa.Column("device_uid", sa.Text, primary_key=True),
    sa.Column("site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
    sa.Column("assigned_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # `alembic check` compares the name with 0004_sites.py.
    sa.Index("ix_site_members_site", "site_id"),
)

target_devices = sa.Table(
    "target_devices",
    metadata,
    sa.Column("source", sa.Text, sa.ForeignKey("sources.name", ondelete="CASCADE"), primary_key=True),
    sa.Column("host", sa.Text, primary_key=True),
    sa.Column("device_uid", sa.Text, primary_key=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # `location_id` is empty when the source reported no place for the device.
    sa.Column("location_id", sa.Text, nullable=False, server_default=""),
    sa.Index("ix_target_devices_uid", "device_uid"),
)

# The device identity registry (0035_device_identity.py). It holds one row per
# identifier, and one uid has many rows. The names and the index ops equal those
# of the revision.
device_identity = sa.Table(
    "device_identity",
    metadata,
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("value", sa.Text, nullable=False),
    sa.Column("uid", sa.Text, nullable=False),
    sa.Column("hostname", sa.Text, nullable=True),
    sa.Column("last_hostname", sa.Text, nullable=True),
    sa.Column("first_run_id", sa.BigInteger, nullable=True),
    sa.PrimaryKeyConstraint("kind", "value", name="pk_device_identity"),
    sa.CheckConstraint("kind IN ('serial', 'ref')", name="ck_device_identity_kind"),
    sa.Index("ix_device_identity_uid", "uid", postgresql_ops={"uid": "text_pattern_ops"}),
)

# The table holds one row with id 1. `rekey_device` increments its `generation`.
device_identity_meta = sa.Table(
    "device_identity_meta",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
    sa.Column("generation", sa.Integer, nullable=False, server_default="0"),
    sa.CheckConstraint("id = 1", name="ck_device_identity_meta_one_row"),
)

reported_locations = sa.Table(
    "reported_locations",
    metadata,
    sa.Column("source", sa.Text, sa.ForeignKey("sources.name", ondelete="CASCADE"), primary_key=True),
    sa.Column("location_id", sa.Text, primary_key=True),
    sa.Column("name", sa.Text, nullable=False, server_default=""),
    # The site that the operator bound. NULL means unplaced.
    sa.Column("site", sa.Text, sa.ForeignKey("sites.code", ondelete="RESTRICT")),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)

app_settings = sa.Table(
    "app_settings",
    metadata,
    sa.Column("key", sa.Text, primary_key=True),
    sa.Column("value", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("secrets", sa.LargeBinary, nullable=False, server_default=sa.text("''::bytea")),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)

auth_providers = sa.Table(
    "auth_providers",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    # The slug of the URLs /api/auth/{name}/...
    sa.Column("name", sa.Text, nullable=False, unique=True),
    sa.Column("kind", sa.Text, nullable=False),  # 'oidc' | 'saml'
    # The public config holds the issuer, the client_id, the IdP metadata and the attribute names.
    sa.Column("config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    # Sealed by app/crypto.py, as sources.secrets is. It holds the client_secret
    # (oidc) or the SP private key (saml).
    sa.Column("secrets", sa.LargeBinary, nullable=True),
    sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)

identities = sa.Table(
    "identities",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "provider_id", sa.Integer, sa.ForeignKey("auth_providers.id", ondelete="CASCADE"), nullable=False
    ),
    # The issuer-scoped 'sub' of OIDC or the NameID of SAML.
    sa.Column("subject", sa.Text, nullable=False),
    sa.Column("email", sa.Text, nullable=False, server_default=""),
    sa.Column("last_login_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.UniqueConstraint("provider_id", "subject", name="uq_identities_provider_subject"),
)

group_mappings = sa.Table(
    "group_mappings",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column(
        "provider_id", sa.Integer, sa.ForeignKey("auth_providers.id", ondelete="CASCADE"), nullable=False
    ),
    # Compared for equality with the value of the group claim.
    sa.Column("group_name", sa.Text, nullable=False),
    sa.Column("role", sa.Text, nullable=False),  # 'viewer' | 'operator' | 'admin'
    sa.UniqueConstraint("provider_id", "group_name", name="uq_group_mappings_provider_group"),
)

# The rows of the OIDC state, nonce and PKCE, of the SAML InResponseTo request
# ids and of the SAML assertion-replay cache.
auth_state = sa.Table(
    "auth_state",
    metadata,
    sa.Column("id", sa.Text, primary_key=True),
    sa.Column(
        "provider_id", sa.Integer, sa.ForeignKey("auth_providers.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


# No update statement is written against this table, and the only delete is the
# age-based purge the scheduled maintenance job runs.
login_events = sa.Table(
    "login_events",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("username", sa.Text, nullable=False),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("provider", sa.Text, nullable=False),  # 'local' or the provider slug
    sa.Column("outcome", sa.Text, nullable=False),  # short stable token, e.g. 'ok', 'bad_credentials'
    sa.Column("source", sa.Text, nullable=False, server_default=""),
    # The read (app/routes/auth_settings.py) orders by `at`.
    sa.Index("ix_login_events_at", "at"),
)


# One POST /api/cypher call, or one Cypher tool call by a model surface.
cypher_events = sa.Table(
    "cypher_events",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("query", sa.Text, nullable=False),
    sa.Column("outcome", sa.Text, nullable=False),
    sa.Column("row_count", sa.Integer, nullable=False, server_default="0"),
    sa.Column("byte_count", sa.Integer, nullable=False, server_default="0"),
    # web | mcp | rest
    sa.Column("origin", sa.Text, nullable=True),
    # The step id of the tool call when a model ran the query. It has no foreign
    # key, and the row stays when the step is deleted.
    sa.Column("ai_step_id", UUID(as_uuid=False), nullable=True),
    # The retention purge and the reads by recency use the index.
    sa.Index("ix_cypher_events_created_at", "created_at"),
)


# One row per download of decrypted evidence, which is a debug bundle or an HTTP
# trace (0036_evidence_exports.py). The rows are not purged.
evidence_exports = sa.Table(
    "evidence_exports",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("username", sa.Text, nullable=False),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("raw_mode", sa.Text, nullable=True),
    sa.Column("source", sa.Text, nullable=False),
    sa.Column("host", sa.Text, nullable=False, server_default=""),
    sa.Column("run_id", sa.Text, nullable=False),
    sa.Column("payloads", sa.Integer, nullable=False, server_default="1"),
    sa.Index("ix_evidence_exports_at", "at"),
)


# The network map's shared layouts and views (0037_network_map_layouts.py).
network_map_layouts = sa.Table(
    "network_map_layouts",
    metadata,
    sa.Column("scope", sa.Text, primary_key=True),
    sa.Column("positions", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("updated_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.CheckConstraint("revision > 0", name="ck_network_map_layouts_revision"),
)

network_map_views = sa.Table(
    "network_map_views",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("state", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("name", name="uq_network_map_views_name"),
    sa.CheckConstraint("revision > 0", name="ck_network_map_views_revision"),
)


# The graph runs that readers hold open (0038_run_leases.py). The table holds one
# row per run per lease, with an expiry. Graph retention keeps every run with an
# unexpired row. The lease of a reader that dies ends at the expiry.
run_leases = sa.Table(
    "run_leases",
    metadata,
    sa.Column("lease_token", sa.String(48), primary_key=True),
    sa.Column("snapshot_key", sa.BigInteger, nullable=False),
    sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Index("ix_run_leases_expiry", "expires_at"),
)

# The default duration of the lease of a reader on a run, in seconds.
RUN_LEASE_TTL_S = 600.0


# The AI audit trail (0032_ai_events.py). It holds metadata only, one row per
# turn event, provider round or tool call. The conversation tables hold the
# content under their own retention. The conversation, message and step ids have
# no foreign key, and an event stays when its conversation is purged.
ai_events = sa.Table(
    "ai_events",
    metadata,
    sa.Column("id", sa.BigInteger, primary_key=True),
    sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    sa.Column("origin", sa.Text, nullable=False),
    sa.Column("surface", sa.Text, nullable=True),
    sa.Column("event", sa.Text, nullable=False),
    sa.Column("conversation_id", UUID(as_uuid=False), nullable=True),
    sa.Column("message_id", UUID(as_uuid=False), nullable=True),
    sa.Column("step_id", UUID(as_uuid=False), nullable=True),
    sa.Column("provider", sa.Text, nullable=True),
    sa.Column("model_requested", sa.Text, nullable=True),
    sa.Column("model_served", sa.Text, nullable=True),
    sa.Column("prompt_hash", sa.Text, nullable=True),
    sa.Column("tool", sa.Text, nullable=True),
    sa.Column("tool_version", sa.Integer, nullable=True),
    sa.Column("snapshot", sa.Text, nullable=True),
    sa.Column("latency_ms", sa.Integer, nullable=True),
    sa.Column("tokens_in", sa.Integer, nullable=True),
    sa.Column("tokens_out", sa.Integer, nullable=True),
    sa.Column("outcome", sa.Text, nullable=False),
    sa.Column("error_class", sa.Text, nullable=True),
    sa.Column("detail", JSONB, nullable=True),
    sa.Index("ix_ai_events_at", "at"),
    sa.Index("ix_ai_events_user_at", "user_id", "at"),
)

# The static prompt text for each prompt hash, written once per hash.
ai_prompt_versions = sa.Table(
    "ai_prompt_versions",
    metadata,
    sa.Column("hash", sa.Text, primary_key=True),
    sa.Column("content", sa.Text, nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


# The conversation store (0033_ai_conversations.py). The names equal those of
# the revision. A conversation is deleted with its user. Messages, steps and
# links are deleted with their conversation.
ai_conversations = sa.Table(
    "ai_conversations",
    metadata,
    sa.Column("id", UUID(as_uuid=False), primary_key=True),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    sa.Column("surface", sa.Text, nullable=False),
    sa.Column("ephemeral", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("title", sa.Text, nullable=False, server_default=""),
    sa.Column("snapshot_id", sa.Text, nullable=True),
    sa.Column("pin_mode", sa.Text, nullable=False, server_default="follow"),
    sa.Column("summary", sa.Text, nullable=True),
    sa.Column("summary_through", sa.Integer, nullable=False, server_default="0"),
    sa.Column("message_count", sa.Integer, nullable=False, server_default="0"),
    # The last step label issued. `append_step` increments it.
    sa.Column("step_count", sa.Integer, nullable=False, server_default="0"),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_message_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Index("ix_ai_conversations_last", "last_message_at"),
)
sa.Index(
    "ix_ai_conversations_user_last",
    ai_conversations.c.user_id,
    ai_conversations.c.last_message_at.desc(),
)

ai_messages = sa.Table(
    "ai_messages",
    metadata,
    sa.Column("id", UUID(as_uuid=False), primary_key=True),
    sa.Column(
        "conversation_id",
        UUID(as_uuid=False),
        sa.ForeignKey("ai_conversations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("seq", sa.Integer, nullable=False),
    sa.Column("role", sa.Text, nullable=False),
    sa.Column("content", sa.Text, nullable=False, server_default=""),
    sa.Column("context", JSONB, nullable=True),
    sa.Column("envelope", JSONB, nullable=True),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("error", sa.Text, nullable=True),
    sa.Column("snapshot_id", sa.Text, nullable=True),
    sa.Column("provider", sa.Text, nullable=True),
    sa.Column("model_requested", sa.Text, nullable=True),
    sa.Column("model_served", sa.Text, nullable=True),
    sa.Column("prompt_hash", sa.Text, sa.ForeignKey("ai_prompt_versions.hash"), nullable=True),
    sa.Column("usage", JSONB, nullable=True),
    sa.Column("lease_owner", sa.Text, nullable=True),
    sa.Column("lease_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("cancel_requested", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.UniqueConstraint("conversation_id", "seq", name="uq_ai_messages_conversation_seq"),
    sa.Index("ix_ai_messages_active", "status", postgresql_where=sa.text("status IN ('pending', 'running')")),
)

ai_steps = sa.Table(
    "ai_steps",
    metadata,
    sa.Column("id", UUID(as_uuid=False), primary_key=True),
    sa.Column(
        "conversation_id",
        UUID(as_uuid=False),
        sa.ForeignKey("ai_conversations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column(
        "message_id", UUID(as_uuid=False), sa.ForeignKey("ai_messages.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("label", sa.Integer, nullable=False),
    sa.Column("tool", sa.Text, nullable=False),
    sa.Column("tool_version", sa.Integer, nullable=False),
    sa.Column("arguments", JSONB, nullable=False),
    sa.Column("is_error", sa.Boolean, nullable=False),
    sa.Column("result", sa.Text, nullable=True),
    sa.Column("result_sha256", sa.Text, nullable=False),
    sa.Column("result_chars", sa.Integer, nullable=False),
    sa.Column("result_summary", sa.Text, nullable=True),
    sa.Column("provenance", JSONB, nullable=True),
    sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("elapsed_ms", sa.Integer, nullable=False),
    sa.Column("compacted_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.UniqueConstraint("conversation_id", "label", name="uq_ai_steps_conversation_label"),
    sa.Index("ix_ai_steps_message", "message_id"),
)

# `ref_id` holds the id of a row in another table and has no foreign key.
ai_links = sa.Table(
    "ai_links",
    metadata,
    sa.Column("id", sa.BigInteger, primary_key=True),
    sa.Column(
        "conversation_id",
        UUID(as_uuid=False),
        sa.ForeignKey("ai_conversations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column(
        "message_id", UUID(as_uuid=False), sa.ForeignKey("ai_messages.id", ondelete="CASCADE"), nullable=True
    ),
    sa.Column(
        "step_id", UUID(as_uuid=False), sa.ForeignKey("ai_steps.id", ondelete="CASCADE"), nullable=True
    ),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("ref_id", sa.Text, nullable=False),
    sa.Column("ref_revision", sa.Integer, nullable=True),
    sa.Column("direction", sa.Text, nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Index("ix_ai_links_ref", "kind", "ref_id"),
)


# The offline place table behind the site address lookup (0030_geo_places.py).
# Index names and ops match the revision exactly.
geo_places = sa.Table(
    "geo_places",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("country_code", sa.Text, nullable=False),
    sa.Column("postal_code", sa.Text, nullable=False),
    sa.Column("name", sa.Text, nullable=False),
    sa.Column("admin1", sa.Text, nullable=False, server_default=""),
    sa.Column("admin2", sa.Text, nullable=False, server_default=""),
    sa.Column("lat", sa.Float, nullable=False),
    sa.Column("lon", sa.Float, nullable=False),
    sa.Column("name_key", sa.Text, nullable=False),
    sa.Index("ix_geo_places_name_key", "name_key", postgresql_ops={"name_key": "text_pattern_ops"}),
    sa.Index("ix_geo_places_postal_code", "postal_code", postgresql_ops={"postal_code": "text_pattern_ops"}),
)


def pg_ssl_engine_kwargs(ca_file: str) -> dict[str, Any]:
    """Return the TLS kwargs for every asyncpg engine of this module and of Alembic.

    A CA file gives one SSLContext with hostname checking on, passed through
    connect_args. An empty ca_file returns {}.
    """
    if not ca_file:
        return {}
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.check_hostname = True
    return {"connect_args": {"ssl": ctx}}


def upgrade_to_head(dsn: str, ca_file: str = "") -> None:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    # Alembic keeps the URL in a ConfigParser, which reads `%` as interpolation
    # syntax and raises on a single `%`. Each `%` of a percent-encoded password
    # (`%40` for an `@`) is doubled.
    cfg.set_main_option("sqlalchemy.url", dsn.replace("%", "%%"))
    cfg.attributes["postgres_ca_file"] = ca_file
    command.upgrade(cfg, "head")


def schema_is_current(dsn: str, ca_file: str = "") -> bool:
    """True when the database is at the newest revision.

    The Kubernetes deployment runs migrations in a Job and holds the app pods behind an
    init container that polls this.
    """
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", dsn.replace("%", "%%"))
    script = ScriptDirectory.from_config(cfg)
    heads = set(script.get_heads())

    # SQLAlchemy resolves a bare `postgresql://` to psycopg2, which is not installed.
    async def _current() -> set[str]:
        engine = create_async_engine(dsn, **pg_ssl_engine_kwargs(ca_file))
        try:
            async with engine.connect() as conn:
                return set(await conn.run_sync(lambda c: MigrationContext.configure(c).get_current_heads()))
        finally:
            await engine.dispose()

    current = asyncio.run(_current())
    return bool(heads) and current == heads


def _user(row: sa.Row) -> User:
    return User(
        row.id,
        row.username,
        row.password_hash,
        row.role,
        row.disabled,
        row.created_at,
        row.role_source,
        row.theme,
    )


def _run(row: sa.Row) -> Run:
    return Run(
        row.id,
        row.source,
        row.status,
        row.started_at,
        row.finished_at,
        row.detail,
        row.triggered_by,
        row.snapshot_key,
    )


def _job(row: sa.Row) -> Job:
    return Job(
        row.id,
        row.kind,
        row.source,
        row.device,
        row.state,
        row.priority,
        row.attempt,
        row.max_attempts,
        row.not_before,
        row.lease_expires_at,
        row.claimed_by,
        row.enqueued_at,
        row.started_at,
        row.finished_at,
        row.detail,
        row.triggered_by,
    )


def _change(row: sa.Row) -> Change:
    return Change(
        id=row["id"],
        title=row["title"],
        description=row["description"] or "",
        snapshot_cts=row["snapshot_cts"],
        status=row["status"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _change_intent(row: sa.Row) -> ChangeIntent:
    return ChangeIntent(
        id=row["id"],
        change_id=row["change_id"],
        position=row["position"],
        kind=row["kind"],
        params=row["params"] or {},
    )


def _site(row: sa.Row) -> Site:
    return Site(
        id=row["id"],
        code=row["code"],
        name=row["name"] or "",
        location=row["location"] or "",
        params=row["params"] or {},
        device_count=row["device_count"],
    )


def _access_token(row: sa.Row) -> AccessToken:
    return AccessToken(
        id=row.id,
        user_id=row.user_id,
        name=row.name,
        scope=row.scope,
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
    )


def _app_setting(row: sa.Row) -> AppSetting:
    return AppSetting(
        key=row["key"], value=row["value"] or {}, secrets=row["secrets"] or b"", updated_at=row["updated_at"]
    )


def _device(row: sa.Row) -> Device:
    return Device(
        id=row.id,
        source=row.source,
        host=row.host,
        port=row.port,
        enabled=row.enabled,
        host_key=row.host_key,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _check_columns(
    raw_sha: str | None,
    obs_sha: str | None,
    verified_started_at: datetime | None = None,
    verified_at: datetime | None = None,
    verified_raw_sha: str | None = None,
    verified_obs_sha: str | None = None,
) -> dict[str, object]:
    """Return the SET values of `last_verified_started_at` and
    `last_verified_at` for a write that can move the basis (`raw_sha`,
    `obs_sha`) and can offer a check. Every term reads the row as it is before
    the write, in the same statement.

    A check is recorded only when the basis of the row equals the hashes that
    the fetch compared (`verified_raw_sha`, `verified_obs_sha`), the write
    moves neither hash, the window ends at or after its start, and it ends
    after `last_graph_fetch_at`. A write that moves a hash clears the stored
    check. Any other write leaves the stored check. The result is empty when
    the write gives no hash and offers no check."""
    c = device_status.c
    moves = [
        *([c.last_raw_sha != raw_sha] if raw_sha is not None else []),
        *([c.last_obs_sha != obs_sha] if obs_sha is not None else []),
    ]
    moved = sa.or_(*moves) if moves else sa.false()
    offered = (
        verified_at is not None
        and verified_raw_sha is not None
        and verified_obs_sha is not None
        and (verified_started_at is None or verified_started_at <= verified_at)
    )
    if not offered:
        if not moves:
            return {}
        return {
            "last_verified_started_at": sa.case((moved, sa.null()), else_=c.last_verified_started_at),
            "last_verified_at": sa.case((moved, sa.null()), else_=c.last_verified_at),
        }
    stamp = sa.TIMESTAMP(timezone=True)
    take = sa.and_(
        sa.not_(moved),
        c.last_raw_sha == verified_raw_sha,
        c.last_obs_sha == verified_obs_sha,
        sa.or_(c.last_graph_fetch_at.is_(None), c.last_graph_fetch_at < sa.literal(verified_at, stamp)),
    )
    start = sa.literal(verified_started_at, stamp) if verified_started_at is not None else sa.null()
    return {
        "last_verified_started_at": sa.case(
            (take, start), (moved, sa.null()), else_=c.last_verified_started_at
        ),
        "last_verified_at": sa.case(
            (take, sa.literal(verified_at, stamp)), (moved, sa.null()), else_=c.last_verified_at
        ),
    }


def _device_status(row: sa.Row) -> DeviceStatus:
    return DeviceStatus(
        id=row.id,
        source=row.source,
        host=row.host,
        last_raw_sha=row.last_raw_sha,
        last_obs_sha=row.last_obs_sha,
        last_attempt_at=row.last_attempt_at,
        last_success_at=row.last_success_at,
        last_full_at=row.last_full_at,
        consecutive_failures=row.consecutive_failures,
        last_error=row.last_error,
        fetch_ms=row.fetch_ms,
        normalize_ms=row.normalize_ms,
        load_ms=row.load_ms,
        updated_at=row.updated_at,
        last_graph_sha=row.last_graph_sha,
        last_graph_at=row.last_graph_at,
        last_graph_fetch_at=row.last_graph_fetch_at,
        last_verified_started_at=row.last_verified_started_at,
        last_verified_at=row.last_verified_at,
    )


def _source(row: sa.Row) -> Source:
    return Source(
        row.id, row.name, row.type, row.config, row.secrets, row.enabled, row.created_at, row.updated_at
    )


def _auth_provider(row: sa.Row) -> AuthProvider:
    return AuthProvider(
        row.id, row.name, row.kind, row.config, row.secrets, row.enabled, row.created_at, row.updated_at
    )


def _identity(row: sa.Row) -> Identity:
    return Identity(row.id, row.user_id, row.provider_id, row.subject, row.email, row.last_login_at)


# The SQLSTATE of foreign_key_violation.
_FOREIGN_KEY_VIOLATION = "23503"


def _identity_insert_error(exc: IntegrityError, provider_id: int, subject: str) -> Exception | None:
    """The error of the store contract for a failed insert into `identities`.

    None when the insert failed on another constraint.
    """
    # `exc.orig` is the SQLAlchemy adapter error. Its `orig` is the asyncpg error.
    constraint = getattr(getattr(exc.orig, "orig", None), "constraint_name", None)
    if constraint == "uq_identities_provider_subject":
        return ValueError(f"identity ({provider_id}, {subject!r}) exists")
    if getattr(exc.orig, "sqlstate", None) == _FOREIGN_KEY_VIOLATION:
        return IdentityOwnerMissing(
            f"the user or the auth provider {provider_id} of the identity does not exist"
        )
    return None


def _group_mapping(row: sa.Row) -> GroupMapping:
    return GroupMapping(row.id, row.provider_id, row.group_name, row.role)


def _auth_state(row: sa.Row) -> AuthState:
    return AuthState(row.id, row.provider_id, row.kind, row.payload, row.expires_at)


def _login_event(row: sa.Row) -> LoginEvent:
    return LoginEvent(row.id, row.at, row.username, row.user_id, row.provider, row.outcome, row.source)


def _cypher_event(row: sa.Row) -> CypherEvent:
    return CypherEvent(
        row.id,
        row.created_at,
        row.user_id,
        row.query,
        row.outcome,
        row.row_count,
        row.byte_count,
        row.origin,
        row.ai_step_id,
    )


def _evidence_export(row: sa.Row) -> EvidenceExport:
    return EvidenceExport(
        row.id,
        row.at,
        row.user_id,
        row.username,
        row.kind,
        row.raw_mode,
        row.source,
        row.host,
        row.run_id,
        row.payloads,
    )


def _map_layout(row: sa.Row) -> NetworkMapLayout:
    return NetworkMapLayout(row.scope, dict(row.positions), row.revision, row.updated_by, row.updated_at)


def _map_view(row: sa.Row) -> NetworkMapView:
    return NetworkMapView(
        row.id, row.name, dict(row.state), row.owner_id, row.revision, row.created_at, row.updated_at
    )


_AI_EVENT_FIELDS = tuple(c.name for c in ai_events.columns if c.name != "id")


def _ai_event(row: sa.Row) -> AiEvent:
    return AiEvent(id=row.id, **{name: getattr(row, name) for name in _AI_EVENT_FIELDS})


# A conversation dataclass has one field per column, with the name of the column.
def _ai_conversation(row: sa.Row) -> AiConversation:
    return AiConversation(**{c.name: getattr(row, c.name) for c in ai_conversations.columns})


def _ai_message(row: sa.Row) -> AiMessage:
    return AiMessage(**{c.name: getattr(row, c.name) for c in ai_messages.columns})


def _ai_step(row: sa.Row) -> AiStep:
    return AiStep(**{c.name: getattr(row, c.name) for c in ai_steps.columns})


def _ai_link(row: sa.Row) -> AiLink:
    return AiLink(**{c.name: getattr(row, c.name) for c in ai_links.columns})


def _jsonb(value: dict[str, Any] | None) -> Any:
    """Return SQL NULL for None. A JSONB column stores a plain None as JSON null."""
    return sa.null() if value is None else value


def _effective_device_sites():
    """The site assignments of the operator, one row per assigned device uid.

    The site list, the member list and the uid-to-site map read this subquery.
    """
    return (
        sa.select(site_members.c.device_uid, sites.c.code.label("site"))
        .select_from(site_members.join(sites, sites.c.id == site_members.c.site_id))
        .subquery()
    )


class PgStore(AssessmentStoreMixin):
    def __init__(self, dsn: str, ca_file: str = "") -> None:
        ssl_kwargs = pg_ssl_engine_kwargs(ca_file)
        self._engine = create_async_engine(dsn, pool_pre_ping=True, **ssl_kwargs)
        # NullPool makes close() a real disconnect, which releases the session
        # advisory lock.
        self._claims_engine = create_async_engine(
            dsn, poolclass=NullPool, isolation_level="AUTOCOMMIT", **ssl_kwargs
        )
        self._claims: dict[int, AsyncConnection] = {}  # run id to its lock-holding connection
        self._inventory: PgInventoryRepository | None = None

    def inventory(self) -> PgInventoryRepository:
        """The inventory repository over this store's engine (app/inventory/
        repository.py)."""
        from hst.app.inventory.repository import PgInventoryRepository

        if self._inventory is None:
            self._inventory = PgInventoryRepository(self._engine)
        return self._inventory

    @asynccontextmanager
    async def _snapshot_read(self) -> AsyncIterator[AsyncConnection]:
        """A read-only REPEATABLE READ transaction. Every statement in it reads
        one snapshot of the database."""
        async with self._engine.connect() as c:
            await c.execution_options(isolation_level="REPEATABLE READ", postgresql_readonly=True)
            async with c.begin():
                yield c

    @asynccontextmanager
    async def assessment_transaction(self) -> AsyncIterator[AssessmentTransaction]:
        async with self._engine.begin() as conn:
            await conn.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": ASSESSMENT_LOCK})
            yield _PgAssessmentTransaction(conn)

    async def ping(self) -> bool:
        try:
            async with self._engine.connect() as c:
                await c.execute(sa.text("SELECT 1"))
            return True
        except Exception:
            # The caller gets False, and the log holds the exception.
            log.warning("postgres ping failed", exc_info=True)
            return False

    async def get_user_by_username(self, username: str) -> User | None:
        async with self._engine.connect() as c:
            row = (await c.execute(users.select().where(users.c.username == username))).first()
        return _user(row) if row else None

    async def get_user(self, user_id: int) -> User | None:
        async with self._engine.connect() as c:
            row = (await c.execute(users.select().where(users.c.id == user_id))).first()
        return _user(row) if row else None

    async def list_users(self) -> list[User]:
        async with self._engine.connect() as c:
            rows = (await c.execute(users.select().order_by(users.c.username))).all()
        return [_user(r) for r in rows]

    async def create_user(self, username: str, password_hash: str | None, role: str) -> User:
        try:
            async with self._engine.begin() as c:
                row = (
                    await c.execute(
                        users.insert()
                        .returning(users)
                        .values(
                            username=username,
                            password_hash=password_hash,
                            role=role,
                            created_at=datetime.now(UTC),
                        )
                    )
                ).first()
        except IntegrityError as exc:
            raise ValueError(f"username {username!r} exists") from exc
        return _user(row)

    async def create_first_user(self, username: str, password_hash: str, role: str) -> User:
        """Create the first account. Raises ValueError when an account exists.

        The advisory lock serializes concurrent setup calls.
        """
        async with self._engine.begin() as c:
            await c.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": FIRST_USER_LOCK})
            existing = (await c.execute(sa.select(sa.func.count()).select_from(users))).scalar_one()
            if existing:
                raise ValueError("an account already exists")
            row = (
                await c.execute(
                    users.insert()
                    .returning(users)
                    .values(
                        username=username,
                        password_hash=password_hash,
                        role=role,
                        created_at=datetime.now(UTC),
                    )
                )
            ).first()
        return _user(row)

    async def update_user(
        self,
        user_id: int,
        *,
        role: str | None = None,
        disabled: bool | None = None,
        password_hash: str | None = None,
        role_source: str | None = None,
    ) -> User | None:
        values = {
            k: v
            for k, v in (
                ("role", role),
                ("disabled", disabled),
                ("password_hash", password_hash),
                ("role_source", role_source),
            )
            if v is not None
        }
        if not values:
            return await self.get_user(user_id)
        async with self._engine.begin() as c:
            row = (
                await c.execute(users.update().where(users.c.id == user_id).values(**values).returning(users))
            ).first()
            # A password reset and a disable delete the sessions and the personal
            # access tokens of the account in this transaction.
            if row is not None and (password_hash is not None or disabled is True):
                await c.execute(sessions.delete().where(sessions.c.user_id == user_id))
                await c.execute(
                    personal_access_tokens.delete().where(personal_access_tokens.c.user_id == user_id)
                )
        return _user(row) if row else None

    async def set_user_theme(self, user_id: int, theme: str) -> User | None:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    users.update().where(users.c.id == user_id).values(theme=theme).returning(users)
                )
            ).first()
        return _user(row) if row else None

    async def create_session(
        self, tok_hash: str, user_id: int, expires_at: datetime, now: datetime | None = None
    ) -> None:
        async with self._engine.begin() as c:
            await c.execute(
                sessions.insert().values(
                    token_hash=tok_hash,
                    user_id=user_id,
                    expires_at=expires_at,
                    # The issue of a session counts as its first use for the idle expiry.
                    last_used_at=now or datetime.now(UTC),
                )
            )

    async def create_provider_session(
        self, tok_hash: str, user_id: int, provider_id: int, expires_at: datetime, now: datetime
    ) -> bool:
        async with self._engine.begin() as c:
            # The share lock waits for the row lock of `delete_auth_provider` and
            # of an `update_auth_provider` that disables the provider.
            enabled = (
                await c.execute(
                    sa.select(auth_providers.c.enabled)
                    .where(auth_providers.c.id == provider_id)
                    .with_for_update(read=True)
                )
            ).scalar_one_or_none()
            if not enabled:
                return False
            await c.execute(
                sessions.insert().values(
                    token_hash=tok_hash, user_id=user_id, expires_at=expires_at, last_used_at=now
                )
            )
        return True

    async def get_session_user(
        self, tok_hash: str, now: datetime, idle_after: timedelta | None = None
    ) -> User | None:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    sa.select(sessions.c.expires_at, sessions.c.last_used_at, users)
                    .join_from(sessions, users, sessions.c.user_id == users.c.id)
                    .where(sessions.c.token_hash == tok_hash)
                )
            ).first()
            if row is None:
                return None
            idle = idle_after is not None and row.last_used_at <= now - idle_after
            if row.expires_at <= now or idle:
                await c.execute(sessions.delete().where(sessions.c.token_hash == tok_hash))
                return None
            # The last use of a session of a disabled account does not move forward.
            if not row.disabled and row.last_used_at <= now - SESSION_TOUCH_INTERVAL:
                await c.execute(
                    sessions.update().where(sessions.c.token_hash == tok_hash).values(last_used_at=now)
                )
        return _user(row)

    async def delete_session(self, tok_hash: str) -> None:
        async with self._engine.begin() as c:
            await c.execute(sessions.delete().where(sessions.c.token_hash == tok_hash))

    async def delete_user_sessions(self, user_id: int) -> int:
        """Delete every session of the account and return the count."""
        async with self._engine.begin() as c:
            result = await c.execute(sessions.delete().where(sessions.c.user_id == user_id))
        return result.rowcount

    async def create_access_token(
        self, tok_hash: str, user_id: int, name: str, scope: str, expires_at: datetime, now: datetime
    ) -> AccessToken:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    personal_access_tokens.insert()
                    .returning(personal_access_tokens)
                    .values(
                        token_hash=tok_hash,
                        user_id=user_id,
                        name=name,
                        scope=scope,
                        created_at=now,
                        expires_at=expires_at,
                    )
                )
            ).first()
        return _access_token(row)  # type: ignore[arg-type]

    async def delete_user_access_tokens(self, user_id: int) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(
                personal_access_tokens.delete().where(personal_access_tokens.c.user_id == user_id)
            )
        return result.rowcount

    async def list_access_tokens(self, user_id: int) -> list[AccessToken]:
        async with self._engine.connect() as c:
            rows = (
                await c.execute(
                    personal_access_tokens.select()
                    .where(personal_access_tokens.c.user_id == user_id)
                    .order_by(personal_access_tokens.c.created_at.desc(), personal_access_tokens.c.id.desc())
                )
            ).all()
        return [_access_token(r) for r in rows]

    async def delete_access_token(self, user_id: int, token_id: int) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(
                personal_access_tokens.delete().where(
                    personal_access_tokens.c.id == token_id, personal_access_tokens.c.user_id == user_id
                )
            )
        return result.rowcount > 0

    async def get_access_token_user(self, tok_hash: str, now: datetime) -> tuple[AccessToken, User] | None:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    personal_access_tokens.select().where(personal_access_tokens.c.token_hash == tok_hash)
                )
            ).first()
            if row is None or row.expires_at <= now:
                return None
            token = _access_token(row)
            if token.last_used_at is None or token.last_used_at <= now - SESSION_TOUCH_INTERVAL:
                await c.execute(
                    personal_access_tokens.update()
                    .where(personal_access_tokens.c.id == token.id)
                    .values(last_used_at=now)
                )
                token.last_used_at = now
            user = (await c.execute(users.select().where(users.c.id == token.user_id))).first()
            # An SSO account is an account with a linked identity. Its token works
            # only while its newest SSO login is younger than SSO_TOKEN_LOGIN_MAX_AGE.
            linked, newest = (
                await c.execute(
                    sa.select(sa.func.count(), sa.func.max(identities.c.last_login_at)).where(
                        identities.c.user_id == token.user_id
                    )
                )
            ).one()
        if linked and (newest is None or newest <= now - SSO_TOKEN_LOGIN_MAX_AGE):
            return None
        return (token, _user(user)) if user is not None else None

    async def _try_claim(self, source: str) -> AsyncConnection | None:
        """Acquire the source's advisory lock on a fresh dedicated connection.

        Returns the lock-holding connection, or None when a live holder exists.
        The caller owns the connection, and its close releases the claim."""
        conn = await self._claims_engine.connect()
        try:
            got = (
                await conn.execute(
                    sa.text("SELECT pg_try_advisory_lock(:c, hashtext(:s))"),
                    {"c": RUN_CLAIM_CLASS, "s": source},
                )
            ).scalar()
        except BaseException:
            await conn.close()
            raise
        if not got:
            await conn.close()
            return None
        return conn

    async def start_run(
        self, source: str, started_at: datetime, triggered_by: int | None = None
    ) -> Run | None:
        claim = await self._try_claim(source)
        if claim is None:
            return None
        try:
            async with self._engine.begin() as c:
                await c.execute(
                    runs.update()
                    .where(runs.c.source == source, runs.c.status == "running")
                    .values(status="error", finished_at=started_at, detail="orphaned by crash")
                )
                row = (
                    await c.execute(
                        runs.insert()
                        .returning(runs)
                        .values(
                            source=source,
                            status="running",
                            started_at=started_at,
                            detail="",
                            triggered_by=triggered_by,
                        )
                    )
                ).first()
        except BaseException:
            await claim.close()
            raise
        run = _run(row)
        self._claims[run.id] = claim
        return run

    async def finish_run(
        self,
        run_id: int,
        status: str,
        finished_at: datetime,
        detail: str,
        snapshot_key: str | None = None,
    ) -> None:
        try:
            # The compare-and-set runs on the pooled engine. After a Postgres
            # restart the claim connection is dead, and the pooled engine records
            # the outcome unless a later claimant reconciled the row.
            async with self._engine.begin() as c:
                result = await c.execute(
                    runs.update()
                    .where(runs.c.id == run_id, runs.c.status == "running")
                    .values(
                        status=status,
                        finished_at=finished_at,
                        detail=detail,
                        snapshot_key=snapshot_key,
                    )
                )
            if result.rowcount == 0:
                log.warning(
                    "run %s finished as %r but was already reconciled by a later "
                    "claimant; not resurrecting it",
                    run_id,
                    status,
                )
        finally:
            claim = self._claims.pop(run_id, None)
            if claim is not None:
                # Postgres releases the lock of a dead connection.
                with contextlib.suppress(Exception):
                    await claim.close()

    async def list_runs(self, limit: int = 50) -> list[Run]:
        async with self._engine.connect() as c:
            rows = (await c.execute(runs.select().order_by(runs.c.id.desc()).limit(limit))).all()
        return [_run(r) for r in rows]

    async def get_run(self, run_id: int) -> Run | None:
        async with self._engine.connect() as c:
            row = (await c.execute(runs.select().where(runs.c.id == run_id))).first()
        return _run(row) if row else None

    async def reconcile_orphaned_runs(self, now: datetime) -> int:
        # An acquired claim of a stranded source means that its row is orphaned.
        async with self._engine.connect() as c:
            stranded = (
                (await c.execute(sa.select(runs.c.source).where(runs.c.status == "running").distinct()))
                .scalars()
                .all()
            )
        reaped = 0
        for source in stranded:
            claim = await self._try_claim(source)
            if claim is None:
                continue
            try:
                async with self._engine.begin() as c:
                    result = await c.execute(
                        runs.update()
                        .where(runs.c.source == source, runs.c.status == "running")
                        .values(status="error", finished_at=now, detail="orphaned by crash")
                    )
                reaped += result.rowcount
            finally:
                await claim.close()
        return reaped

    async def running_run(self, source: str) -> Run | None:
        async with self._engine.connect() as c:
            # The state predicate is the literal text of `one_running_per_source`,
            # as in `running_runs`.
            row = (
                await c.execute(
                    runs.select().where(runs.c.source == source, sa.text("status = 'running'")).limit(1)
                )
            ).first()
        return _run(row) if row else None

    async def running_runs(self) -> list[Run]:
        async with self._engine.connect() as c:
            # The predicate is the literal text of `one_running_per_source`. The
            # planner matches the partial index to a literal predicate under every plan.
            rows = (
                await c.execute(runs.select().where(sa.text("status = 'running'")).order_by(runs.c.id))
            ).all()
        return [_run(r) for r in rows]

    async def list_sources(self) -> list[Source]:
        async with self._engine.connect() as c:
            rows = (await c.execute(sources.select().order_by(sources.c.name))).all()
        return [_source(r) for r in rows]

    async def get_source(self, name: str) -> Source | None:
        async with self._engine.connect() as c:
            row = (await c.execute(sources.select().where(sources.c.name == name))).first()
        return _source(row) if row else None

    async def create_source(
        self, name: str, type_: str, config: dict, secrets: bytes, enabled: bool = True
    ) -> Source:
        now = datetime.now(UTC)
        try:
            async with self._engine.begin() as c:
                row = (
                    await c.execute(
                        sources.insert()
                        .returning(sources)
                        .values(
                            name=name,
                            type=type_,
                            config=config,
                            secrets=secrets,
                            enabled=enabled,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                ).first()
        except IntegrityError as exc:
            raise ValueError(f"source {name!r} exists") from exc
        return _source(row)

    async def update_source(
        self,
        name: str,
        *,
        config: dict | None = None,
        secrets: bytes | None = None,
        enabled: bool | None = None,
    ) -> Source | None:
        values = {
            k: v for k, v in (("config", config), ("secrets", secrets), ("enabled", enabled)) if v is not None
        }
        values["updated_at"] = datetime.now(UTC)
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    sources.update().where(sources.c.name == name).values(**values).returning(sources)
                )
            ).first()
        return _source(row) if row else None

    async def modify_source(self, name: str, change: Callable[[Source], Source | None]) -> Source | None:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    sources.select().where(sources.c.name == name).with_for_update(key_share=True)
                )
            ).first()
            if row is None:
                return None
            current = _source(row)
            new = change(copy.deepcopy(current))
            if new is None:
                return current
            row = (
                await c.execute(
                    sources.update()
                    .where(sources.c.id == current.id)
                    .values(
                        config=new.config,
                        secrets=new.secrets,
                        enabled=new.enabled,
                        updated_at=datetime.now(UTC),
                    )
                    .returning(sources)
                )
            ).first()
        return _source(row)

    async def delete_source(self, name: str) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(sources.delete().where(sources.c.name == name))
        return result.rowcount > 0

    async def list_devices(self, source: str | None = None) -> list[Device]:
        query = devices.select().order_by(devices.c.source, devices.c.host)
        if source is not None:
            query = query.where(devices.c.source == source)
        async with self._engine.connect() as c:
            rows = (await c.execute(query)).all()
        return [_device(r) for r in rows]

    async def replace_devices(self, source: str, specs: list[DeviceSpec]) -> list[Device]:
        hosts = [s.host for s in specs]
        if len(set(hosts)) != len(hosts):
            raise ValueError("duplicate host in device list")
        now = datetime.now(UTC)
        try:
            async with self._engine.begin() as c:
                if not specs:
                    # An empty `specs` inserts no row, and no foreign key checks the source.
                    exists = (
                        await c.execute(sa.select(sources.c.id).where(sources.c.name == source))
                    ).first()
                    if exists is None:
                        raise ValueError(f"no source {source!r}")
                if specs:
                    # The upsert is by (source, host). A conflict keeps `host_key`,
                    # `id` and `created_at`.
                    stmt = insert(devices).values(
                        [
                            {
                                "source": source,
                                "host": s.host,
                                "port": s.port,
                                "enabled": s.enabled,
                                "created_at": now,
                                "updated_at": now,
                            }
                            for s in specs
                        ]
                    )
                    await c.execute(
                        stmt.on_conflict_do_update(
                            constraint="uq_devices_source_host",
                            set_={
                                "port": stmt.excluded.port,
                                "enabled": stmt.excluded.enabled,
                                "updated_at": now,
                            },
                        )
                    )
                await c.execute(
                    devices.delete().where(devices.c.source == source, devices.c.host.notin_(hosts))
                )
                # The observations of a host that leaves the fleet are deleted.
                await c.execute(
                    target_devices.delete().where(
                        target_devices.c.source == source, target_devices.c.host.notin_(hosts)
                    )
                )
                await c.execute(
                    device_status.delete().where(
                        device_status.c.source == source, device_status.c.host.notin_(hosts)
                    )
                )
                rows = (
                    await c.execute(
                        devices.select().where(devices.c.source == source).order_by(devices.c.host)
                    )
                ).all()
        except IntegrityError as exc:
            # The foreign key checks that the source exists.
            raise ValueError(f"no source {source!r}") from exc
        return [_device(r) for r in rows]

    async def set_device_host_key(self, source: str, host: str, host_key: str) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(
                devices.update()
                .where(
                    devices.c.source == source,
                    devices.c.host == host,
                    devices.c.host_key == "",
                )
                .values(host_key=host_key, updated_at=datetime.now(UTC))
            )
        return result.rowcount > 0

    async def clear_device_host_key(self, source: str, host: str) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(
                devices.update()
                .where(
                    devices.c.source == source,
                    devices.c.host == host,
                    devices.c.host_key != "",
                )
                .values(host_key="", updated_at=datetime.now(UTC))
            )
        return result.rowcount > 0

    async def upsert_device_status(
        self,
        source: str,
        host: str,
        *,
        now: datetime,
        ok: bool,
        raw_sha: str | None = None,
        obs_sha: str | None = None,
        graph_sha: str | None = None,
        graph_fetch_at: datetime | None = None,
        full: bool = False,
        error: str = "",
        fetch_ms: int | None = None,
        normalize_ms: int | None = None,
        load_ms: int | None = None,
        verified_started_at: datetime | None = None,
        verified_at: datetime | None = None,
        verified_raw_sha: str | None = None,
        verified_obs_sha: str | None = None,
    ) -> DeviceStatus:
        # A full load wrote the batch of its digest. A digest without `full` was
        # compared, and its batch was not written.
        graph_written = full and graph_sha is not None
        # The fetch time of the payload of the digest.
        graph_fetched = graph_fetch_at if graph_sha is not None else None
        if ok:
            insert_values = {
                "source": source,
                "host": host,
                "last_attempt_at": now,
                "updated_at": now,
                "last_success_at": now,
                "last_full_at": now if full else None,
                "last_raw_sha": raw_sha if raw_sha is not None else "",
                "last_obs_sha": obs_sha if obs_sha is not None else "",
                "last_graph_sha": graph_sha if graph_sha is not None else "",
                "last_graph_at": now if graph_written else None,
                "last_graph_fetch_at": graph_fetched,
                "consecutive_failures": 0,
                "last_error": "",
                "fetch_ms": fetch_ms,
                "normalize_ms": normalize_ms,
                "load_ms": load_ms,
                # A new row has no basis that a fetch compared.
                "last_verified_started_at": None,
                "last_verified_at": None,
            }
            # None means "no new value".
            set_: dict[str, object] = {
                "last_attempt_at": now,
                "updated_at": now,
                "last_success_at": now,
                "consecutive_failures": 0,
                "last_error": "",
            }
            if raw_sha is not None:
                set_["last_raw_sha"] = raw_sha
            if obs_sha is not None:
                set_["last_obs_sha"] = obs_sha
            if graph_sha is not None:
                set_["last_graph_sha"] = graph_sha
            if full:
                set_["last_full_at"] = now
            if graph_written:
                set_["last_graph_at"] = now
            if graph_fetched is not None:
                set_["last_graph_fetch_at"] = graph_fetched
            if fetch_ms is not None:
                set_["fetch_ms"] = fetch_ms
            if normalize_ms is not None:
                set_["normalize_ms"] = normalize_ms
            if load_ms is not None:
                set_["load_ms"] = load_ms
            set_.update(
                _check_columns(
                    raw_sha,
                    obs_sha,
                    verified_started_at,
                    verified_at,
                    verified_raw_sha,
                    verified_obs_sha,
                )
            )
        else:
            # A failing call ignores the hashes, the timings and `full`, in the
            # insert and in the update. The stored raw hash and graph digest are
            # cleared.
            insert_values = {
                "source": source,
                "host": host,
                "last_attempt_at": now,
                "updated_at": now,
                "consecutive_failures": 1,
                "last_error": error,
            }
            set_ = {
                "last_attempt_at": now,
                "updated_at": now,
                # The update increments the stored column.
                # `excluded.consecutive_failures` is 1, the value of the incoming row.
                "consecutive_failures": device_status.c.consecutive_failures + 1,
                "last_error": error,
                "last_raw_sha": "",
                "last_graph_sha": "",
                "last_verified_started_at": None,
                "last_verified_at": None,
            }
        stmt = insert(device_status).values(**insert_values)
        stmt = stmt.on_conflict_do_update(constraint="uq_device_status_source_host", set_=set_)
        try:
            async with self._engine.begin() as c:
                await c.execute(stmt)
                row = (
                    await c.execute(
                        device_status.select().where(
                            device_status.c.source == source, device_status.c.host == host
                        )
                    )
                ).first()
        except IntegrityError as exc:
            raise ValueError(f"no source {source!r}") from exc
        return _device_status(row)

    async def record_device_graph(
        self,
        source: str,
        host: str,
        *,
        now: datetime,
        graph_sha: str,
        written: bool,
        fetch_at: datetime | None = None,
    ) -> bool:
        values: dict[str, object] = {"last_graph_sha": graph_sha, "updated_at": now}
        if not graph_sha:
            values["last_raw_sha"] = ""
            values["last_verified_started_at"] = None
            values["last_verified_at"] = None
        else:
            if written:
                values["last_graph_at"] = now
            if fetch_at is not None:
                values["last_graph_fetch_at"] = fetch_at
        async with self._engine.begin() as c:
            result = await c.execute(
                device_status.update()
                .where(device_status.c.source == source, device_status.c.host == host)
                .values(**values)
            )
        return result.rowcount > 0

    async def record_device_basis(
        self,
        source: str,
        host: str,
        *,
        now: datetime,
        raw_sha: str | None = None,
        obs_sha: str | None = None,
        full: bool = False,
    ) -> bool:
        values: dict[str, object] = {"updated_at": now, **_check_columns(raw_sha, obs_sha)}
        if raw_sha is not None:
            values["last_raw_sha"] = raw_sha
        if obs_sha is not None:
            values["last_obs_sha"] = obs_sha
        if full:
            values["last_full_at"] = now
        async with self._engine.begin() as c:
            result = await c.execute(
                device_status.update()
                .where(device_status.c.source == source, device_status.c.host == host)
                .values(**values)
            )
        return result.rowcount > 0

    async def list_device_status(self, source: str | None = None) -> list[DeviceStatus]:
        query = device_status.select().order_by(device_status.c.source, device_status.c.host)
        if source is not None:
            query = query.where(device_status.c.source == source)
        async with self._engine.connect() as c:
            rows = (await c.execute(query)).all()
        return [_device_status(r) for r in rows]

    async def purge_expired_sessions(self, now: datetime, idle_after: timedelta | None = None) -> int:
        dead = sessions.c.expires_at <= now
        if idle_after is not None:
            dead = sa.or_(dead, sessions.c.last_used_at <= now - idle_after)
        async with self._engine.begin() as c:
            result = await c.execute(sessions.delete().where(dead))
        return result.rowcount

    async def _watch_lock(
        self, conn: AsyncConnection, on_lost: Callable[[], None], lock: str, effect: str
    ) -> None:
        """Call `on_lost` when the lock connection stops answering.

        The loop runs one statement on the lock connection every LOCK_PING_S
        seconds. `lock` and `effect` are the name of the lock and the result of
        the loss in the log line.

        `on_lost` is called at most once. A caller that works on a worker thread
        sets a flag in `on_lost` and reads the flag on that thread.
        """
        while True:
            await asyncio.sleep(LOCK_PING_S)
            try:
                await conn.execute(sa.text("SELECT 1"))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "the %s lock connection stopped answering (%s: %s); %s",
                    lock,
                    type(exc).__name__,
                    exc,
                    effect,
                )
                on_lost()
                return

    @asynccontextmanager
    async def cycle_lock(self, on_lost: Callable[[], None] | None = None) -> AsyncIterator[int]:
        """Hold the cross-process cycle lock for the duration of the block.

        The lock has its own connection from the claims engine, as a run claim
        has. The call blocks, and a second trigger waits for the lock.

        Yields a fence, one value of `CYCLE_FENCE_SEQ` per acquisition, in the
        order of the acquisitions. The holder passes it to the cycle pointer,
        which refuses a fence below the one that it holds. A previous holder
        that writes after the loss of its lock does not publish over the run of
        the next holder.

        `on_lost` is called when the lock connection stops answering while the
        block runs. A caller that works on a worker thread passes a flag setter
        and checks the flag before the load of each device and between phases.
        A caller that stays on the event loop passes nothing.
        """
        conn = await self._claims_engine.connect()
        watch: asyncio.Task[None] | None = None
        try:
            await conn.execute(sa.text("SELECT pg_advisory_lock(:key)"), {"key": CYCLE_LOCK})
            fence = (await conn.execute(sa.text(f"SELECT nextval('{CYCLE_FENCE_SEQ}')"))).scalar_one()
            if on_lost is not None:
                watch = asyncio.create_task(
                    self._watch_lock(conn, on_lost, "cycle", "the run holding it will not publish")
                )
            yield int(fence)
        finally:
            if watch is not None:
                # A cancel during a statement raises a driver error or a cancellation.
                watch.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await watch
            # The close of the connection releases the lock.
            await conn.close()

    @asynccontextmanager
    async def try_cycle_lock(self) -> AsyncIterator[bool]:
        """Take the lock of `cycle_lock` without waiting.

        Yields True when the caller holds the lock. The connection is closed in
        both cases.
        """
        conn = await self._claims_engine.connect()
        try:
            got = (
                await conn.execute(sa.text("SELECT pg_try_advisory_lock(:key)"), {"key": CYCLE_LOCK})
            ).scalar()
            yield bool(got)
        finally:
            await conn.close()

    @asynccontextmanager
    async def lease_run(
        self, cts: int | Iterable[int], ttl_s: float = RUN_LEASE_TTL_S
    ) -> AsyncIterator[None]:
        """Hold a lease on the graph runs `cts` for the duration of the block.

        Retention (`worker/maintenance.py` `prune_graph`) keeps every run with
        an unexpired lease. The lease expires after `ttl_s` seconds. The call
        deletes the expired rows of all readers before it inserts.
        """
        keys = sorted({int(cts)} if isinstance(cts, int) else {int(k) for k in cts})
        now = datetime.now(UTC)
        rows = [
            {"lease_token": uuid4().hex, "snapshot_key": key, "expires_at": now + timedelta(seconds=ttl_s)}
            for key in keys
        ]
        async with self._engine.begin() as c:
            await c.execute(run_leases.delete().where(run_leases.c.expires_at <= now))
            if rows:
                await c.execute(run_leases.insert(), rows)
        try:
            yield
        finally:
            tokens = [row["lease_token"] for row in rows]
            if tokens:
                # The row of a failed release ends at its `expires_at`.
                with contextlib.suppress(Exception):
                    async with self._engine.begin() as c:
                        await c.execute(run_leases.delete().where(run_leases.c.lease_token.in_(tokens)))

    async def leased_runs(self) -> set[int]:
        """The run keys with an unexpired lease."""
        query = sa.select(run_leases.c.snapshot_key).where(run_leases.c.expires_at > datetime.now(UTC))
        async with self._engine.connect() as c:
            return {int(key) for key in (await c.execute(query.distinct())).scalars()}

    @asynccontextmanager
    async def try_scheduler_lock(self, on_lost: Callable[[], None] | None = None) -> AsyncIterator[bool]:
        """Try to take the lock of the leader election of the scheduler for the
        duration of the block.

        The lock has its own key and its own connection from the claims engine.
        The call does not block. Yields True when the caller holds the lock.

        `on_lost` is called when the lock connection of the leader stops answering
        while the block runs. Postgres releases the lock with the connection.
        """
        conn = await self._claims_engine.connect()
        watch: asyncio.Task[None] | None = None
        try:
            got = (
                await conn.execute(sa.text("SELECT pg_try_advisory_lock(:key)"), {"key": SCHEDULER_LOCK})
            ).scalar()
            if got and on_lost is not None:
                watch = asyncio.create_task(
                    self._watch_lock(conn, on_lost, "scheduler", "this process stops scheduling")
                )
            yield bool(got)
        finally:
            if watch is not None:
                watch.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await watch
            # A closed connection has released the lock.
            with contextlib.suppress(Exception):
                await conn.close()

    # --- job queue -----------------------------------------------------------

    async def enqueue_job(
        self,
        kind: str,
        *,
        source: str | None = None,
        device: str | None = None,
        priority: int = 0,
        not_before: datetime,
        max_attempts: int,
        triggered_by: str,
        now: datetime,
    ) -> Job | None:
        """Insert one job, or None when an identical one is already pending.

        The duplicate check is the `one_pending_per_kind` unique index alone.
        A violation of another constraint is raised.
        """
        try:
            async with self._engine.begin() as c:
                row = (
                    await c.execute(
                        jobs.insert()
                        .returning(jobs)
                        .values(
                            kind=kind,
                            source=source,
                            device=device,
                            state="queued",
                            priority=priority,
                            attempt=0,
                            max_attempts=max_attempts,
                            not_before=not_before,
                            enqueued_at=now,
                            triggered_by=triggered_by,
                        )
                    )
                ).first()
        except IntegrityError as exc:
            # `exc.orig` is the SQLAlchemy adapter error. Its `orig` is the asyncpg error.
            constraint = getattr(getattr(exc.orig, "orig", None), "constraint_name", None)
            if constraint != "one_pending_per_kind":
                raise
            return None
        return _job(row)

    async def claim_jobs(
        self,
        worker_id: str,
        batch: int,
        now: datetime,
        lease: timedelta,
        *,
        skip_kinds: Collection[str] = (),
    ) -> list[Job]:
        """Take up to `batch` due jobs for this worker in one statement. A job of
        a kind in `skip_kinds` is not taken.

        `FOR UPDATE SKIP LOCKED` skips a ready row that another transaction has
        locked.
        """
        if batch <= 0:
            return []
        selected = sa.select(jobs.c.id).where(jobs.c.state == "queued", jobs.c.not_before <= now)
        if skip_kinds:
            selected = selected.where(jobs.c.kind.not_in(sorted(skip_kinds)))
        ready = (
            selected.order_by(jobs.c.priority.desc(), jobs.c.not_before)
            .limit(batch)
            .with_for_update(skip_locked=True)
            .cte("ready")
        )
        async with self._engine.begin() as c:
            rows = (
                await c.execute(
                    jobs.update()
                    .where(jobs.c.id.in_(sa.select(ready.c.id)))
                    .values(
                        state="running",
                        attempt=jobs.c.attempt + 1,
                        claimed_by=worker_id,
                        started_at=now,
                        lease_expires_at=now + lease,
                    )
                    .returning(jobs)
                )
            ).all()
        return [_job(r) for r in rows]

    async def heartbeat_jobs(
        self, job_ids: list[int], worker_id: str, now: datetime, lease: timedelta
    ) -> list[int]:
        """Extend the lease of the jobs that this worker holds. Returns the ids extended.

        The update matches `claimed_by`. A worker whose job was reaped and
        claimed by another worker does not extend the claim of that worker.
        """
        if not job_ids:
            return []
        async with self._engine.begin() as c:
            rows = (
                await c.execute(
                    jobs.update()
                    .where(
                        jobs.c.id.in_(job_ids),
                        jobs.c.state == "running",
                        jobs.c.claimed_by == worker_id,
                    )
                    .values(lease_expires_at=now + lease)
                    .returning(jobs.c.id)
                )
            ).scalars()
        return [int(i) for i in rows]

    async def finish_job(
        self,
        job_id: int,
        state: str,
        detail: str,
        now: datetime,
        *,
        retry_at: datetime | None = None,
        claimed_by: str | None = None,
        attempt: int | None = None,
    ) -> Job | None:
        """Record the outcome of an attempt.

        With `retry_at`, the attempt failed and the next one is due at that
        time. The row returns to 'queued' with the failure text, and
        `finished_at` stays null. Without `retry_at`, `state` is terminal and
        `finished_at` is set. Both cases release the lease.

        The write is a compare-and-set on 'running', as in `finish_run`.
        `claimed_by` and `attempt` limit it to one attempt. Both come from the
        `Job` that the caller claimed (worker/queue.py `finish`). A caller that
        passes neither gets the state check alone.
        """
        values: dict[str, Any] = {"detail": detail, "claimed_by": None, "lease_expires_at": None}
        if retry_at is not None:
            values |= {"state": "queued", "not_before": retry_at, "finished_at": None}
        else:
            values |= {"state": state, "finished_at": now}
        owned = [jobs.c.id == job_id, jobs.c.state == "running"]
        if claimed_by is not None:
            owned.append(jobs.c.claimed_by == claimed_by)
        if attempt is not None:
            owned.append(jobs.c.attempt == attempt)
        async with self._engine.begin() as c:
            row = (await c.execute(jobs.update().where(*owned).values(**values).returning(jobs))).first()
        if row is None:
            log.warning(
                "job %s: ownership lost, so the outcome %r is not being recorded; "
                "the row belongs to another attempt or was already reaped",
                job_id,
                state,
            )
            return None
        return _job(row)

    async def reap_jobs(
        self,
        now: datetime,
        *,
        backoff_kinds: Collection[str] = (),
        backoff_base_s: float = 60.0,
        backoff_cap_s: float = 1800.0,
    ) -> int:
        """Requeue every claim whose lease has passed.

        An executor that was killed during a job leaves such a claim. A job
        that has used its attempts goes to 'dead'.

        A requeued job of a kind in `backoff_kinds` is due
        `min(backoff_cap_s, backoff_base_s * 2 ** max(0, attempt - 1))` seconds
        after `now`, as worker/queue.py `backoff` computes for a failed attempt.
        `attempt` was incremented when the lapsed claim was taken, and the first
        lapse waits `backoff_base_s`. A job of another kind is due at `now`. The
        one UPDATE computes the delay per row from `attempt` of the row.
        """
        exhausted = jobs.c.attempt >= jobs.c.max_attempts
        requeue_at: list[tuple[Any, Any]] = [(exhausted, jobs.c.not_before)]
        if backoff_kinds:
            # The double precision base selects power(double precision, double
            # precision). The integer exponent casts to double precision
            # implicitly, and least() and the product are double precision.
            delay_s = sa.func.least(
                sa.literal(backoff_cap_s, sa.Float),
                sa.literal(backoff_base_s, sa.Float)
                * sa.func.power(sa.literal(2.0, sa.Float), sa.func.greatest(jobs.c.attempt - 1, 0)),
            )
            # make_interval(years, months, weeks, days, hours, mins, secs) takes
            # the seconds as double precision. SQLAlchemy 2.1 deprecates the
            # product of an Interval and a number.
            backed_off = sa.literal(now, jobs.c.not_before.type) + sa.func.make_interval(
                0, 0, 0, 0, 0, 0, delay_s, type_=sa.Interval
            )
            requeue_at.append((jobs.c.kind.in_(list(backoff_kinds)), backed_off))
        async with self._engine.begin() as c:
            result = await c.execute(
                jobs.update()
                .where(jobs.c.state == "running", jobs.c.lease_expires_at <= now)
                .values(
                    state=sa.case((exhausted, "dead"), else_="queued"),
                    not_before=sa.case(*requeue_at, else_=now),
                    finished_at=sa.case((exhausted, now), else_=sa.null()),
                    detail="lease expired: the executor holding this job stopped reporting",
                    claimed_by=None,
                    lease_expires_at=None,
                )
            )
        return result.rowcount

    async def job_depth(self) -> dict[str, int]:
        async with self._engine.connect() as c:
            rows = (await c.execute(sa.select(jobs.c.state, sa.func.count()).group_by(jobs.c.state))).all()
        return dict(rows)  # type: ignore[arg-type]

    async def get_job(self, job_id: int) -> Job | None:
        async with self._engine.connect() as connection:
            row = (await connection.execute(jobs.select().where(jobs.c.id == job_id))).first()
        return _job(row) if row else None

    async def list_jobs(self, limit: int = 50) -> list[Job]:
        async with self._engine.connect() as c:
            rows = (await c.execute(jobs.select().order_by(jobs.c.id.desc()).limit(limit))).all()
        return [_job(r) for r in rows]

    async def pending_jobs(self, kind: str) -> list[Job]:
        """Return the jobs of `kind` that are queued or running, oldest first.

        The state predicate is the literal text of `one_pending_per_kind`. The
        planner matches a query to a partial index only when it can prove the
        index predicate from the query predicate, and a cached generic plan
        with bound states cannot. `kind` is the first column of that index,
        and the rows are read from the index.
        """
        async with self._engine.connect() as c:
            rows = (
                await c.execute(
                    jobs.select()
                    .where(jobs.c.kind == kind, sa.text("state IN ('queued', 'running')"))
                    .order_by(jobs.c.id)
                )
            ).all()
        return [_job(r) for r in rows]

    async def purge_jobs(self, before: datetime) -> int:
        """Delete the jobs that finished before `before`.

        The delete compares `finished_at`. A queued job and a running job stay.
        """
        async with self._engine.begin() as c:
            result = await c.execute(
                jobs.delete().where(jobs.c.finished_at.is_not(None), jobs.c.finished_at < before)
            )
        return result.rowcount

    # --- changes ----------------------

    async def list_changes(self) -> list[Change]:
        async with self._engine.connect() as c:
            rows = (await c.execute(changes.select().order_by(changes.c.id))).mappings().all()
        return [_change(r) for r in rows]

    async def get_change(self, change_id: int) -> Change | None:
        async with self._engine.connect() as c:
            row = (await c.execute(changes.select().where(changes.c.id == change_id))).mappings().first()
        return _change(row) if row else None

    async def list_change_intents(self, change_id: int) -> list[ChangeIntent]:
        async with self._engine.connect() as c:
            rows = (
                (
                    await c.execute(
                        change_intents.select()
                        .where(change_intents.c.change_id == change_id)
                        .order_by(change_intents.c.position)
                    )
                )
                .mappings()
                .all()
            )
        return [_change_intent(r) for r in rows]

    async def create_change(
        self,
        *,
        title: str,
        description: str,
        snapshot_cts: int | None,
        created_by: int | None,
        intents: list[tuple[str, dict]],
    ) -> tuple[Change, list[ChangeIntent]]:
        now = datetime.now(UTC)
        async with self._engine.begin() as c:
            row = (
                (
                    await c.execute(
                        changes.insert()
                        .returning(changes)
                        .values(
                            title=title,
                            description=description,
                            snapshot_cts=snapshot_cts,
                            status="draft",
                            created_by=created_by,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                )
                .mappings()
                .first()
            )
            intent_rows = await self._replace_intents(c, row["id"], intents)
        return _change(row), intent_rows

    async def update_change(
        self,
        change_id: int,
        *,
        title: str | object = UNSET,
        description: str | object = UNSET,
        snapshot_cts: int | object | None = UNSET,
        status: str | object = UNSET,
        intents: list[tuple[str, dict]] | object = UNSET,
    ) -> tuple[Change, list[ChangeIntent]] | None:
        values: dict[str, Any] = {"updated_at": datetime.now(UTC)}
        if title is not UNSET:
            values["title"] = title
        if description is not UNSET:
            values["description"] = description
        if snapshot_cts is not UNSET:
            values["snapshot_cts"] = snapshot_cts
        if status is not UNSET:
            values["status"] = status
        async with self._engine.begin() as c:
            row = (
                (
                    await c.execute(
                        changes.update().where(changes.c.id == change_id).returning(changes).values(**values)
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                return None
            if intents is not UNSET:
                intent_rows = await self._replace_intents(c, change_id, intents)
            else:
                fetched = (
                    (
                        await c.execute(
                            change_intents.select()
                            .where(change_intents.c.change_id == change_id)
                            .order_by(change_intents.c.position)
                        )
                    )
                    .mappings()
                    .all()
                )
                intent_rows = [_change_intent(r) for r in fetched]
        return _change(row), intent_rows

    async def _replace_intents(
        self, c: AsyncConnection, change_id: int, intents: list[tuple[str, dict]]
    ) -> list[ChangeIntent]:
        """Delete the intents of the change and insert `intents` in the
        transaction of the caller. The stored list is replaced as a whole."""
        await c.execute(change_intents.delete().where(change_intents.c.change_id == change_id))
        if not intents:
            return []
        stmt = change_intents.insert().values(
            [
                {"change_id": change_id, "position": i, "kind": kind, "params": params}
                for i, (kind, params) in enumerate(intents)
            ]
        )
        rows = (await c.execute(stmt.returning(change_intents))).mappings().all()
        return sorted((_change_intent(r) for r in rows), key=lambda r: r.position)

    async def delete_change(self, change_id: int) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(changes.delete().where(changes.c.id == change_id))
        return result.rowcount > 0

    # --- sites ---------------------------------------------------------------

    async def list_sites(self) -> list[Site]:
        effective = _effective_device_sites()
        counts = (
            sa.select(sites.c.id.label("site_id"), sa.func.count().label("n"))
            .select_from(effective.join(sites, sites.c.code == effective.c.site))
            .group_by(sites.c.id)
            .subquery()
        )
        q = (
            sa.select(sites, sa.func.coalesce(counts.c.n, 0).label("device_count"))
            .select_from(sites.outerjoin(counts, counts.c.site_id == sites.c.id))
            .order_by(sites.c.code)
        )
        async with self._engine.connect() as c:
            rows = (await c.execute(q)).mappings().all()
        return [_site(r) for r in rows]

    async def get_site(self, code: str) -> Site | None:
        return next((s for s in await self.list_sites() if s.code == code), None)

    async def create_site(self, code: str, name: str, location: str, params: dict | None = None) -> Site:
        now = datetime.now(UTC)
        async with self._engine.begin() as c:
            known = (await c.execute(sa.select(sites.c.code))).scalars().all()
            if clash := uidmod.site_fold(code, known):
                raise ValueError(f"site {code} folds onto {clash}: both are the site {uidmod.site(code)}")
            try:
                await c.execute(
                    sites.insert().values(
                        code=code,
                        name=name,
                        location=location,
                        params=params or {},
                        created_at=now,
                        updated_at=now,
                    )
                )
            except IntegrityError as exc:
                raise ValueError(f"site {code} already exists") from exc
        return await self.get_site(code)  # type: ignore[return-value]

    async def update_site(
        self,
        code: str,
        *,
        name: str | None = None,
        location: str | None = None,
        params: dict | None = None,
        change_params: Callable[[dict], dict] | None = None,
    ) -> Site | None:
        from hst.app.inventory.legacy import NormalizationMigrated
        from hst.app.inventory.observations import InventoryContext
        from hst.app.inventory.repository import PgInventoryTx

        now = datetime.now(UTC)
        async with self._engine.begin() as c:
            tx = PgInventoryTx(c)
            state = await tx.get_state()
            if state.activation_state == "active" and state.resolver_version == 2:
                ctx = InventoryContext(self, None)
                before = next((row for row in await ctx.site_rows(tx).list() if row.code == code), None)
                if before is None:
                    return None
                stored_params = (
                    await c.execute(
                        sa.select(sites.c.params)
                        .where(sites.c.id == before.id)
                        .with_for_update(key_share=True)
                    )
                ).scalar() or {}
                if change_params is not None:
                    params = change_params(dict(stored_params))
                if params is not None and any(
                    stored_params.get(key) != params.get(key)
                    for key in ("routing_scope", "l3dom", "l2fabric")
                ):
                    raise NormalizationMigrated(
                        "site routing normalization is frozen", references=[f"site:{code}"]
                    )
                changes = {
                    key: value for key, value in (("name", name), ("location", location)) if value is not None
                }
                row = await ctx.site_rows(tx).update(
                    before.id, expected_revision=before.revision, now=now, **changes
                )
                if params is not None:
                    await c.execute(sites.update().where(sites.c.id == row.id).values(params=params))
                await tx.append_event(
                    entity_type="site",
                    entity_id=str(row.id),
                    actor_id=None,
                    action="site.update",
                    now=now,
                    before={"name": before.name, "location": before.location, "revision": before.revision},
                    after={"name": row.name, "location": row.location, "revision": row.revision},
                )
                found = True
            else:
                values: dict[str, Any] = {"updated_at": now, "revision": sites.c.revision + 1}
                if name is not None:
                    values["name"] = name
                if location is not None:
                    values["location"] = location
                if change_params is not None:
                    stored = (
                        await c.execute(
                            sa.select(sites.c.params)
                            .where(sites.c.code == code)
                            .with_for_update(key_share=True)
                        )
                    ).first()
                    if stored is None:
                        return None
                    params = change_params(dict(stored.params or {}))
                if params is not None:
                    values["params"] = params
                result = await c.execute(sites.update().where(sites.c.code == code).values(**values))
                found = result.rowcount > 0
        return await self.get_site(code) if found else None

    async def delete_site(self, code: str) -> SiteRelease | None:
        """Delete the site and release the groups, the locations and the devices
        that reference it.

        The result holds what was released. A group of the site has no site, a
        location bound to the site is unbound, and a device placed at the site
        by hand has no placement.

        The graph keeps the placements of the site until the next run publishes.
        """
        from hst.app.inventory.observations import InventoryContext
        from hst.app.inventory.repository import PgInventoryTx
        from hst.app.inventory.site_routes import release_site

        async with self._engine.begin() as c:
            tx = PgInventoryTx(c)
            state = await tx.get_state()
            if state.activation_state == "active" and state.resolver_version == 2:
                ctx = InventoryContext(self, None)
                row = next((r for r in await ctx.site_rows(tx).list() if r.code == code), None)
                if row is None:
                    return None
                bound = [
                    (loc.source, loc.location_id) for loc in await tx.list_locations() if loc.site == code
                ]
                result = await release_site(ctx, tx, row.id, actor_id=None, now=datetime.now(UTC))
                devices = await tx.get_devices(result.placements)
                return SiteRelease([], bound, [d.graph_uid for d in devices])
            site_id = (await c.execute(sa.select(sites.c.id).where(sites.c.code == code))).scalar()
            if site_id is None:
                return None
            placed = list(
                (
                    await c.execute(
                        sa.select(site_members.c.device_uid).where(site_members.c.site_id == site_id)
                    )
                )
                .scalars()
                .all()
            )
            bound = [
                (r.source, r.location_id)
                for r in (
                    await c.execute(
                        sa.select(reported_locations.c.source, reported_locations.c.location_id).where(
                            reported_locations.c.site == code
                        )
                    )
                ).all()
            ]
            here = (
                await c.execute(
                    sa.select(sources.c.name, sources.c.config).where(
                        sources.c.config["site_code"].astext == code
                    )
                )
            ).all()
            for row in here:
                await c.execute(
                    sources.update()
                    .where(sources.c.name == row.name)
                    .values(config={**row.config, "site_code": ""}, updated_at=datetime.now(UTC))
                )
            # The unbind runs before the delete. reported_locations.site is ON
            # DELETE RESTRICT.
            await c.execute(
                reported_locations.update()
                .where(reported_locations.c.site == code)
                .values(site=None, revision=reported_locations.c.revision + 1, updated_at=datetime.now(UTC))
            )
            await c.execute(site_members.delete().where(site_members.c.site_id == site_id))
            await c.execute(sites.delete().where(sites.c.code == code))
        return SiteRelease([row.name for row in here], bound, placed)

    async def site_members(self, code: str) -> list[str]:
        effective = _effective_device_sites()
        q = sa.select(effective.c.device_uid).where(effective.c.site == code).order_by(effective.c.device_uid)
        async with self._engine.connect() as c:
            return [r[0] for r in (await c.execute(q)).all()]

    async def assign_device(self, device_uid: str, code: str | None) -> bool:
        """Assign a device to a site, or unassign it with `code=None`."""
        from hst.app.inventory import events
        from hst.app.inventory.contracts import PlacementMode
        from hst.app.inventory.observations import InventoryContext, ReadModel
        from hst.app.inventory.repository import PgInventoryTx

        async with self._engine.begin() as c:
            tx = PgInventoryTx(c)
            state = await tx.get_state()
            if state.activation_state == "active" and state.resolver_version == 2:
                ctx = InventoryContext(self, None)
                device = await tx.get_device_by_graph_uid(device_uid)
                if device is None:
                    raise ValueError(f"no collected device: {device_uid}")
                site = next((row for row in await ctx.site_rows(tx).list() if row.code == code), None)
                if code is not None and site is None:
                    raise ValueError(f"no such site: {code}")
                now = datetime.now(UTC)
                before = await tx.get_placement(device.id)
                changed = await tx.set_placement(
                    device.id,
                    mode=PlacementMode.ASSIGNED if site else PlacementMode.AUTO,
                    site_id=site.id if site else None,
                    origin="manual",
                    expected_revision=before.revision if before else 0,
                    actor_id=None,
                    now=now,
                )
                await ReadModel(ctx).refresh(tx, [device.id], now, collection=False)
                await tx.append_event(
                    entity_type="device",
                    entity_id=str(device.id),
                    actor_id=None,
                    action="placement.set",
                    now=now,
                    before=events.placement_payload(before),
                    after=events.placement_payload(changed),
                )
                return True
            if code is None:
                result = await c.execute(site_members.delete().where(site_members.c.device_uid == device_uid))
                return result.rowcount > 0
            row = (await c.execute(sa.select(sites.c.id).where(sites.c.code == code))).first()
            if not row:
                raise ValueError(f"no such site: {code}")
            stmt = insert(site_members).values(
                device_uid=device_uid, site_id=row[0], assigned_at=datetime.now(UTC)
            )
            # A reassignment updates the row of the device.
            stmt = stmt.on_conflict_do_update(
                index_elements=[site_members.c.device_uid],
                set_={"site_id": row[0], "assigned_at": datetime.now(UTC)},
            )
            await c.execute(stmt)
        return True

    async def device_sites(self) -> dict[str, str]:
        """Return the map of device uid to site code."""
        q = sa.select(_effective_device_sites())
        async with self._engine.connect() as c:
            return {r[0]: r[1] for r in (await c.execute(q)).all()}

    async def record_target_devices(
        self,
        source: str,
        host: str,
        device_uids: list[str],
        locations: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        """Replace the observed uid set of a target.

        `locations` maps a device uid to the (id, name) that its source reports
        for its place. The location rows are upserted. A location that the call
        does not report keeps its row and the binding of the operator.
        """
        now = datetime.now(UTC)
        unique = sorted(set(device_uids))
        places = locations or {}
        async with self._engine.begin() as c:
            await c.execute(
                target_devices.delete().where(
                    target_devices.c.source == source, target_devices.c.host == host
                )
            )
            if unique:
                await c.execute(
                    target_devices.insert(),
                    [
                        {
                            "source": source,
                            "host": host,
                            "device_uid": uid,
                            "updated_at": now,
                            "location_id": places.get(uid, ("", ""))[0],
                        }
                        for uid in unique
                    ],
                )
            # The loop builds one row per location id. 2 devices of one call can
            # report one place under 2 names during a rename. The last non-empty
            # name is stored.
            seen: dict[str, str] = {}
            for uid in unique:
                place = places.get(uid)
                if not place or not place[0]:
                    continue
                location_id, name = place
                if name or location_id not in seen:
                    seen[location_id] = name
            for location_id, name in sorted(seen.items()):
                stmt = insert(reported_locations).values(
                    source=source, location_id=location_id, name=name, site=None, updated_at=now
                )
                await c.execute(
                    stmt.on_conflict_do_update(
                        index_elements=[reported_locations.c.source, reported_locations.c.location_id],
                        set_={"name": name, "updated_at": now},
                    )
                )

    async def list_reported_locations(self, source: str | None = None) -> list[ReportedLocation]:
        counts = (
            sa.select(
                target_devices.c.source,
                target_devices.c.location_id,
                sa.func.count(sa.distinct(target_devices.c.device_uid)).label("n"),
            )
            .group_by(target_devices.c.source, target_devices.c.location_id)
            .subquery()
        )
        q = (
            sa.select(reported_locations, sa.func.coalesce(counts.c.n, 0).label("device_count"))
            .select_from(
                reported_locations.outerjoin(
                    counts,
                    sa.and_(
                        counts.c.source == reported_locations.c.source,
                        counts.c.location_id == reported_locations.c.location_id,
                    ),
                )
            )
            .order_by(reported_locations.c.source, reported_locations.c.location_id)
        )
        if source is not None:
            q = q.where(reported_locations.c.source == source)
        async with self._engine.connect() as c:
            rows = (await c.execute(q)).mappings().all()
        return [
            ReportedLocation(r["source"], r["location_id"], r["name"], r["site"], r["device_count"])
            for r in rows
        ]

    async def bind_location(self, source: str, location_id: str, site: str | None) -> bool:
        from hst.app.inventory.observations import InventoryContext, ReadModel
        from hst.app.inventory.repository import PgInventoryTx

        async with self._engine.begin() as c:
            tx = PgInventoryTx(c)
            state = await tx.get_state()
            if state.activation_state == "active" and state.resolver_version == 2:
                ctx = InventoryContext(self, None)
                loc = next(
                    (loc for loc in await tx.list_locations(source) if loc.location_id == location_id), None
                )
                if loc is None:
                    return False
                if site is not None and not any(row.code == site for row in await ctx.site_rows(tx).list()):
                    raise ValueError(f"no such site: {site}")
                now = datetime.now(UTC)
                changed = await tx.bind_location(loc.handle, site, expected_revision=loc.revision, now=now)
                read_model = ReadModel(ctx)
                moved = await read_model.devices_at_locations(tx, [loc.handle])
                await read_model.refresh(tx, moved, now, collection=False)
                await tx.append_event(
                    entity_type="location",
                    entity_id=str(loc.handle),
                    actor_id=None,
                    action="location.bind",
                    now=now,
                    before={"site": loc.site, "revision": loc.revision},
                    after={"site": changed.site, "revision": changed.revision},
                )
                return True
            if site is not None:
                found = (await c.execute(sa.select(sites.c.id).where(sites.c.code == site))).first()
                if not found:
                    raise ValueError(f"no such site: {site}")
            result = await c.execute(
                reported_locations.update()
                .where(
                    reported_locations.c.source == source,
                    reported_locations.c.location_id == location_id,
                )
                .values(site=site, revision=reported_locations.c.revision + 1, updated_at=datetime.now(UTC))
            )
        return result.rowcount > 0

    async def target_devices(self, source: str | None = None) -> list[TargetDevice]:
        q = target_devices.select().order_by(
            target_devices.c.source, target_devices.c.host, target_devices.c.device_uid
        )
        if source is not None:
            q = q.where(target_devices.c.source == source)
        async with self._engine.connect() as c:
            rows = (await c.execute(q)).mappings().all()
        return [TargetDevice(**dict(row)) for row in rows]

    async def resolve_device(self, kind: str, value: str, hostname: str | None, run_id: int | None) -> str:
        """Return the uid of the identifier `(kind, value)`. The first call for
        an identifier mints a uid (`core/identity.py mint`) that differs from
        the taken uids, and writes the row. A hostname sets `last_hostname` on
        every row of the uid, for the identity report."""
        key = identifier(kind, value)
        t = device_identity
        lookup = sa.select(t.c.uid).where(t.c.kind == kind, t.c.value == key)
        async with self._engine.begin() as c:
            found = (await c.execute(lookup)).scalar()
            if found is None:
                await c.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": DEVICE_IDENTITY_LOCK})
                # Another process can mint the uid while this transaction waits for the lock.
                found = (await c.execute(lookup)).scalar()
            if found is None:
                base = base_uid(hostname)
                candidates = sa.select(t.c.uid).where(
                    sa.or_(t.c.uid == base, t.c.uid.startswith(f"{base}-", autoescape=True))
                )
                taken = set((await c.execute(candidates)).scalars())
                found = mint_for(kind, key, hostname, taken)
                await c.execute(
                    t.insert().values(
                        kind=kind,
                        value=key,
                        uid=found,
                        hostname=hostname,
                        last_hostname=hostname,
                        first_run_id=run_id,
                    )
                )
                # `legacy_uid` is the uid that the identifier gives without the registry.
                # Its references move to the new uid, unless a device of the registry owns it.
                legacy = legacy_uid(kind, value)
                if (await c.execute(sa.select(t.c.uid).where(t.c.uid == legacy).limit(1))).first() is None:
                    await self._move_device_references(c, legacy, found)
            elif hostname:
                await c.execute(
                    t.update()
                    .where(t.c.uid == found, t.c.last_hostname.is_distinct_from(hostname))
                    .values(last_hostname=hostname)
                )
        return found

    async def bind_device(self, uid: str, kind: str, value: str, run_id: int | None) -> None:
        """Add the identifier `(kind, value)` to the existing `uid`. An
        identifier that the registry holds already keeps its uid."""
        key = identifier(kind, value)
        t = device_identity
        async with self._engine.begin() as c:
            if (await c.execute(sa.select(t.c.uid).where(t.c.uid == uid).limit(1))).first() is None:
                raise LookupError(f"no device has the uid {uid!r}")
            await c.execute(
                insert(t)
                .values(kind=kind, value=key, uid=uid, first_run_id=run_id)
                .on_conflict_do_nothing(index_elements=[t.c.kind, t.c.value])
            )

    async def rekey_device(self, old_uid: str, new_uid: str, *, merge: bool = False) -> int:
        """Move every identifier of `old_uid` to `new_uid` and increment the
        generation. The next run loads every device again and writes the new
        uid. The references to the uid outside the graph move with it
        (`_move_device_references`). `merge` moves the identifiers into a uid
        that another device has, for a replaced chassis. The references of
        that device stay. Returns the number of identifiers moved."""
        t = device_identity
        meta = device_identity_meta
        async with self._engine.begin() as c:
            await c.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": DEVICE_IDENTITY_LOCK})
            if (await c.execute(sa.select(t.c.uid).where(t.c.uid == old_uid).limit(1))).first() is None:
                raise LookupError(f"no device has the uid {old_uid!r}")
            if old_uid == new_uid:
                raise ValueError(f"the device has the uid {new_uid!r} already")
            owner = (await c.execute(sa.select(t.c.uid).where(t.c.uid == new_uid).limit(1))).first()
            taken = owner is not None
            if taken and not merge:
                raise ValueError(f"the uid {new_uid!r} is taken")
            if not taken and merge:
                raise LookupError(f"no device has the uid {new_uid!r} to merge into")
            moved = (await c.execute(t.update().where(t.c.uid == old_uid).values(uid=new_uid))).rowcount
            await self._move_device_references(c, old_uid, new_uid)
            stmt = insert(meta).values(id=1, generation=1)
            await c.execute(
                stmt.on_conflict_do_update(
                    index_elements=[meta.c.id], set_={"generation": meta.c.generation + 1}
                )
            )
        return moved

    async def _move_device_references(self, c: AsyncConnection, old_uid: str, new_uid: str) -> None:
        """Move the references to a device uid outside the graph to the new uid.
        They are the hand placement (`site_members`), the observed target
        devices and the inventory device (`inventory_devices.graph_uid`). The
        device keeps its site and its inventory history. A reference that the
        new uid has already stays. In that case the hand placement of the old
        uid is deleted."""
        from hst.app.inventory import tables as inv
        from hst.app.inventory.repository import PgInventoryTx

        now = datetime.now(UTC)
        placed = site_members.c.device_uid
        if (await c.execute(sa.select(placed).where(placed == new_uid))).first() is None:
            await c.execute(site_members.update().where(placed == old_uid).values(device_uid=new_uid))
        else:
            await c.execute(site_members.delete().where(placed == old_uid))
        seen = target_devices.c
        targets = (await c.execute(sa.select(seen.source, seen.host).where(seen.device_uid == old_uid))).all()
        for source, host in targets:
            same = (seen.source == source, seen.host == host)
            if (await c.execute(sa.select(seen.host).where(*same, seen.device_uid == new_uid))).first():
                continue
            await c.execute(
                target_devices.update().where(*same, seen.device_uid == old_uid).values(device_uid=new_uid)
            )
        devices = inv.inventory_devices
        if (await c.execute(sa.select(devices.c.id).where(devices.c.graph_uid == new_uid))).first():
            return
        device = (
            await c.execute(
                devices.update()
                .where(devices.c.graph_uid == old_uid)
                .values(graph_uid=new_uid, revision=devices.c.revision + 1, updated_at=now)
                .returning(devices.c.id)
            )
        ).first()
        if device is not None:
            await PgInventoryTx(c).append_event(
                entity_type="device",
                entity_id=str(device.id),
                actor_id=None,
                action="device.rekeyed",
                now=now,
                before={"graph_uid": old_uid},
                after={"graph_uid": new_uid},
            )

    async def identity_generation(self) -> int:
        meta = device_identity_meta
        async with self._engine.connect() as c:
            value = (await c.execute(sa.select(meta.c.generation).where(meta.c.id == 1))).scalar()
        return int(value or 0)

    async def device_identities(self) -> list[DeviceIdentity]:
        t = device_identity
        async with self._engine.connect() as c:
            rows = (await c.execute(t.select().order_by(t.c.uid, t.c.kind, t.c.value))).mappings().all()
        return [DeviceIdentity(**dict(row)) for row in rows]

    async def device_identity_report(self) -> list[DeviceIdentityReport]:
        return identity_report(await self.device_identities())

    async def get_setting(self, key: str) -> AppSetting | None:
        async with self._engine.connect() as c:
            row = (await c.execute(app_settings.select().where(app_settings.c.key == key))).mappings().first()
        return _app_setting(row) if row else None

    async def put_setting(self, key: str, value: dict, secrets: bytes) -> AppSetting:
        now = datetime.now(UTC)
        # The upsert creates the row or replaces its value and secrets.
        stmt = insert(app_settings).values(key=key, value=value, secrets=secrets, updated_at=now)
        stmt = stmt.on_conflict_do_update(
            index_elements=[app_settings.c.key], set_={"value": value, "secrets": secrets, "updated_at": now}
        )
        async with self._engine.begin() as c:
            await c.execute(stmt)
        return AppSetting(key=key, value=value, secrets=secrets, updated_at=now)

    async def modify_setting(
        self, key: str, change: Callable[[AppSetting | None], tuple[dict, bytes] | None]
    ) -> AppSetting | None:
        async with self._engine.begin() as c:
            await c.execute(
                sa.text("SELECT pg_advisory_xact_lock(:c, hashtext(:k))"), {"c": SETTING_LOCK_CLASS, "k": key}
            )
            row = (
                (
                    await c.execute(
                        app_settings.select().where(app_settings.c.key == key).with_for_update(key_share=True)
                    )
                )
                .mappings()
                .first()
            )
            current = _app_setting(row) if row else None
            result = change(copy.deepcopy(current))
            if result is None:
                return current
            value, secrets = result
            now = datetime.now(UTC)
            stmt = insert(app_settings).values(key=key, value=value, secrets=secrets, updated_at=now)
            await c.execute(
                stmt.on_conflict_do_update(
                    index_elements=[app_settings.c.key],
                    set_={"value": value, "secrets": secrets, "updated_at": now},
                )
            )
        return AppSetting(key=key, value=value, secrets=secrets, updated_at=now)

    # --- geo places (app/geo_places.py) ----------------------------------------

    async def replace_geo_places(self, places: Iterable[GeoPlace]) -> int:
        """Replace the whole place table in one transaction. The rows are
        written with COPY in batches of 50,000. A thread reads and parses each
        batch."""
        columns = ("country_code", "postal_code", "name", "admin1", "admin2", "lat", "lon", "name_key")
        rows = iter(places)

        def next_batch() -> list[tuple]:
            return [
                (
                    p.country_code,
                    p.postal_code or "",
                    p.name,
                    p.admin1,
                    p.admin2,
                    p.lat,
                    p.lon,
                    name_key(p.name),
                )
                for p in itertools.islice(rows, 50_000)
            ]

        count = 0
        async with self._engine.begin() as c:
            await c.execute(geo_places.delete())
            raw = (await c.get_raw_connection()).driver_connection
            while batch := await asyncio.to_thread(next_batch):
                await raw.copy_records_to_table("geo_places", records=batch, columns=columns)
                count += len(batch)
            await c.execute(sa.text("ANALYZE geo_places"))
        return count

    async def search_geo_places(self, name: str, postal: str, limit: int) -> GeoPlaceSearch:
        g = geo_places.c
        where = []
        # both prefixes hold only letters, digits, spaces and dashes (geo_places.parse_query)
        if name:
            where.append(g.name_key.like(name + "%"))
        if postal:
            where.append(g.postal_code.like(postal + "%"))
        exact = sa.case((g.name_key == name, 0), else_=1)
        if postal:
            query = (
                sa.select(g.country_code, g.postal_code, g.name, g.admin1, g.admin2, g.lat, g.lon)
                .where(*where)
                .order_by(g.postal_code, exact, g.name_key, g.country_code)
                .limit(limit)
            )
        else:
            query = (
                sa.select(
                    g.country_code,
                    sa.null().label("postal_code"),
                    g.name,
                    g.admin1,
                    g.admin2,
                    sa.func.avg(g.lat).label("lat"),
                    sa.func.avg(g.lon).label("lon"),
                )
                .where(*where)
                .group_by(g.country_code, g.name, g.name_key, g.admin1, g.admin2)
                .order_by(exact, sa.func.length(g.name_key), g.name_key, g.country_code, g.admin1)
                .limit(limit)
            )
        async with self._engine.connect() as c:
            rows = (await c.execute(query)).all() if where else []
            available = bool(rows) or bool(
                (await c.execute(sa.select(sa.exists().where(g.id.is_not(None))))).scalar()
            )
        return GeoPlaceSearch(
            items=[
                GeoPlace(
                    r.country_code, r.postal_code, r.name, r.admin1, r.admin2, float(r.lat), float(r.lon)
                )
                for r in rows
            ],
            available=available,
        )

    # --- auth providers -------------------------------------------------------

    async def list_auth_providers(self) -> list[AuthProvider]:
        async with self._engine.connect() as c:
            rows = (await c.execute(auth_providers.select().order_by(auth_providers.c.name))).all()
        return [_auth_provider(r) for r in rows]

    async def get_auth_provider(self, name: str) -> AuthProvider | None:
        async with self._engine.connect() as c:
            row = (await c.execute(auth_providers.select().where(auth_providers.c.name == name))).first()
        return _auth_provider(row) if row else None

    async def create_auth_provider(
        self, name: str, kind: str, config: dict, secrets: bytes | None, enabled: bool = False
    ) -> AuthProvider:
        now = datetime.now(UTC)
        try:
            async with self._engine.begin() as c:
                row = (
                    await c.execute(
                        auth_providers.insert()
                        .returning(auth_providers)
                        .values(
                            name=name,
                            kind=kind,
                            config=config,
                            secrets=secrets,
                            enabled=enabled,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                ).first()
        except IntegrityError as exc:
            raise ValueError(f"auth provider {name!r} exists") from exc
        return _auth_provider(row)

    async def update_auth_provider(
        self,
        name: str,
        *,
        config: dict | None = None,
        secrets: bytes | None = None,
        enabled: bool | None = None,
    ) -> AuthProvider | None:
        values = {
            k: v for k, v in (("config", config), ("secrets", secrets), ("enabled", enabled)) if v is not None
        }
        values["updated_at"] = datetime.now(UTC)
        async with self._engine.begin() as c:
            if enabled is False:
                # The row lock blocks the insert of an identity of the provider until the commit.
                locked = (
                    await c.execute(
                        sa.select(auth_providers.c.id, auth_providers.c.enabled)
                        .where(auth_providers.c.name == name)
                        .with_for_update()
                    )
                ).first()
                if locked is not None and locked.enabled:
                    await self._delete_provider_sessions_and_tokens(c, locked.id)
            row = (
                await c.execute(
                    auth_providers.update()
                    .where(auth_providers.c.name == name)
                    .values(**values)
                    .returning(auth_providers)
                )
            ).first()
        return _auth_provider(row) if row else None

    async def _delete_provider_sessions_and_tokens(self, c: AsyncConnection, provider_id: int) -> None:
        """Deletes the sessions and the personal access tokens of each user
        that has an identity at the provider."""
        members = sa.select(identities.c.user_id).where(identities.c.provider_id == provider_id)
        await c.execute(sessions.delete().where(sessions.c.user_id.in_(members)))
        await c.execute(personal_access_tokens.delete().where(personal_access_tokens.c.user_id.in_(members)))

    async def delete_auth_provider(self, name: str) -> bool:
        async with self._engine.begin() as c:
            # The row lock blocks the insert of an identity of the provider until the commit.
            provider_id = (
                await c.execute(
                    sa.select(auth_providers.c.id).where(auth_providers.c.name == name).with_for_update()
                )
            ).scalar_one_or_none()
            if provider_id is None:
                return False
            # The call reads the identities before the provider delete cascades to them.
            await self._delete_provider_sessions_and_tokens(c, provider_id)
            # The identities, group_mappings and auth_state rows of the provider cascade.
            await c.execute(auth_providers.delete().where(auth_providers.c.id == provider_id))
        return True

    # --- identities -------------------------------------------------------------

    async def get_identity(self, provider_id: int, subject: str) -> Identity | None:
        async with self._engine.connect() as c:
            row = (
                await c.execute(
                    identities.select().where(
                        identities.c.provider_id == provider_id, identities.c.subject == subject
                    )
                )
            ).first()
        return _identity(row) if row else None

    async def create_identity(
        self, user_id: int, provider_id: int, subject: str, email: str = ""
    ) -> Identity:
        try:
            async with self._engine.begin() as c:
                row = (
                    await c.execute(
                        identities.insert()
                        .returning(identities)
                        .values(user_id=user_id, provider_id=provider_id, subject=subject, email=email)
                    )
                ).first()
        except IntegrityError as exc:
            error = _identity_insert_error(exc, provider_id, subject)
            if error is None:
                raise
            raise error from exc
        return _identity(row)

    async def create_user_with_identity(
        self, username: str, role: str, provider_id: int, subject: str, email: str = ""
    ) -> tuple[User, Identity]:
        async with self._engine.begin() as c:
            try:
                user_row = (
                    await c.execute(
                        users.insert()
                        .returning(users)
                        .values(
                            username=username, password_hash=None, role=role, created_at=datetime.now(UTC)
                        )
                    )
                ).one()
            except IntegrityError as exc:
                raise ValueError(f"username {username!r} exists") from exc
            try:
                identity_row = (
                    await c.execute(
                        identities.insert()
                        .returning(identities)
                        .values(user_id=user_row.id, provider_id=provider_id, subject=subject, email=email)
                    )
                ).one()
            except IntegrityError as exc:
                error = _identity_insert_error(exc, provider_id, subject)
                if error is None:
                    raise
                raise error from exc
        return _user(user_row), _identity(identity_row)

    async def touch_last_login(self, identity_id: int, when: datetime) -> None:
        async with self._engine.begin() as c:
            await c.execute(
                identities.update().where(identities.c.id == identity_id).values(last_login_at=when)
            )

    async def list_identities_for_users(self, user_ids: list[int]) -> list[Identity]:
        """Return the identities of a set of users in one query."""
        if not user_ids:
            return []
        async with self._engine.connect() as c:
            rows = (await c.execute(identities.select().where(identities.c.user_id.in_(user_ids)))).all()
        return [_identity(r) for r in rows]

    # --- group mappings ----------------------------------------------------------

    async def list_group_mappings(self, provider_id: int) -> list[GroupMapping]:
        async with self._engine.connect() as c:
            rows = (
                await c.execute(
                    group_mappings.select()
                    .where(group_mappings.c.provider_id == provider_id)
                    .order_by(group_mappings.c.group_name)
                )
            ).all()
        return [_group_mapping(r) for r in rows]

    async def put_group_mapping(self, provider_id: int, group_name: str, role: str) -> GroupMapping:
        stmt = insert(group_mappings).values(provider_id=provider_id, group_name=group_name, role=role)
        stmt = stmt.on_conflict_do_update(
            index_elements=[group_mappings.c.provider_id, group_mappings.c.group_name],
            set_={"role": role},
        ).returning(group_mappings)
        async with self._engine.begin() as c:
            row = (await c.execute(stmt)).first()
        return _group_mapping(row)  # type: ignore[arg-type]

    async def delete_group_mapping(self, provider_id: int, group_name: str) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(
                group_mappings.delete().where(
                    group_mappings.c.provider_id == provider_id, group_mappings.c.group_name == group_name
                )
            )
        return result.rowcount > 0

    # --- auth state ----------------------------------------------------------------

    async def create_auth_state(
        self, id: str, provider_id: int, kind: str, payload: dict, expires_at: datetime
    ) -> AuthState:
        # `id` is the primary key. The SAML assertion-replay cache
        # (app/saml_flow.py) treats a duplicate insert as a replay.
        try:
            async with self._engine.begin() as c:
                await c.execute(
                    auth_state.insert().values(
                        id=id, provider_id=provider_id, kind=kind, payload=payload, expires_at=expires_at
                    )
                )
        except IntegrityError as exc:
            raise ValueError(f"auth_state {id!r} exists") from exc
        return AuthState(id, provider_id, kind, payload, expires_at)

    async def consume_auth_state(
        self, id: str, kind: str, provider_id: int, now: datetime
    ) -> AuthState | None:
        # One statement deletes and returns the row. An expired row stays for
        # purge_expired_auth_state.
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    auth_state.delete()
                    .where(
                        auth_state.c.id == id,
                        auth_state.c.kind == kind,
                        auth_state.c.provider_id == provider_id,
                        auth_state.c.expires_at > now,
                    )
                    .returning(auth_state)
                )
            ).first()
        return _auth_state(row) if row else None

    async def purge_expired_auth_state(self, now: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(auth_state.delete().where(auth_state.c.expires_at <= now))
        return result.rowcount

    # --- login events ----------------------------------------------------------------

    async def record_login_event(
        self, username: str, user_id: int | None, provider: str, outcome: str, source: str, at: datetime
    ) -> LoginEvent:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    login_events.insert()
                    .returning(login_events)
                    .values(
                        at=at,
                        username=username,
                        user_id=user_id,
                        provider=provider,
                        outcome=outcome,
                        source=source,
                    )
                )
            ).first()
        return _login_event(row)  # type: ignore[arg-type]

    async def list_login_events(self, limit: int = 200) -> list[LoginEvent]:
        async with self._engine.connect() as c:
            rows = (
                await c.execute(login_events.select().order_by(login_events.c.at.desc()).limit(limit))
            ).all()
        return [_login_event(r) for r in rows]

    async def purge_login_events(self, before: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(login_events.delete().where(login_events.c.at < before))
        return result.rowcount

    # --- cypher events ----------------------------------------------------------------

    async def record_cypher_event(
        self,
        user_id: int | None,
        query: str,
        outcome: str,
        row_count: int,
        byte_count: int,
        at: datetime,
        origin: str | None = None,
        ai_step_id: str | None = None,
    ) -> CypherEvent:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    cypher_events.insert()
                    .returning(cypher_events)
                    .values(
                        created_at=at,
                        user_id=user_id,
                        query=query,
                        outcome=outcome,
                        row_count=row_count,
                        byte_count=byte_count,
                        origin=origin,
                        ai_step_id=ai_step_id,
                    )
                )
            ).first()
        return _cypher_event(row)  # type: ignore[arg-type]

    async def list_cypher_events(self, limit: int = 200) -> list[CypherEvent]:
        async with self._engine.connect() as c:
            rows = (
                await c.execute(
                    cypher_events.select().order_by(cypher_events.c.created_at.desc()).limit(limit)
                )
            ).all()
        return [_cypher_event(r) for r in rows]

    async def purge_cypher_events(self, before: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(cypher_events.delete().where(cypher_events.c.created_at < before))
        return result.rowcount

    # --- evidence exports -------------------------------------------------------------

    async def record_evidence_export(
        self,
        *,
        user_id: int | None,
        username: str,
        kind: str,
        raw_mode: str | None,
        source: str,
        host: str,
        run_id: str,
        payloads: int,
        at: datetime,
    ) -> EvidenceExport:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    evidence_exports.insert()
                    .returning(evidence_exports)
                    .values(
                        at=at,
                        user_id=user_id,
                        username=username,
                        kind=kind,
                        raw_mode=raw_mode,
                        source=source,
                        host=host,
                        run_id=run_id,
                        payloads=payloads,
                    )
                )
            ).first()
        return _evidence_export(row)  # type: ignore[arg-type]

    async def list_evidence_exports(self, limit: int = 200) -> list[EvidenceExport]:
        async with self._engine.connect() as c:
            rows = (
                await c.execute(
                    evidence_exports.select()
                    .order_by(evidence_exports.c.at.desc(), evidence_exports.c.id.desc())
                    .limit(limit)
                )
            ).all()
        return [_evidence_export(r) for r in rows]

    # --- network map layouts and views ----------------------------------------------

    async def get_network_map_layout(self, scope: str) -> NetworkMapLayout | None:
        async with self._engine.connect() as c:
            row = (
                await c.execute(network_map_layouts.select().where(network_map_layouts.c.scope == scope))
            ).first()
        return _map_layout(row) if row else None

    async def save_network_map_layout(
        self, scope: str, positions: dict, *, expected_revision: int, user_id: int | None, now: datetime
    ) -> NetworkMapLayout:
        t = network_map_layouts
        async with self._engine.begin() as c:
            if expected_revision == 0:
                # A concurrent first save of the same scope conflicts on the primary key.
                row = (
                    await c.execute(
                        insert(t)
                        .values(
                            scope=scope, positions=positions, revision=1, updated_by=user_id, updated_at=now
                        )
                        .on_conflict_do_nothing(index_elements=["scope"])
                        .returning(t)
                    )
                ).first()
            else:
                row = (
                    await c.execute(
                        t.update()
                        .where(t.c.scope == scope, t.c.revision == expected_revision)
                        .values(
                            positions=positions, revision=t.c.revision + 1, updated_by=user_id, updated_at=now
                        )
                        .returning(t)
                    )
                ).first()
        if row is None:
            raise StaleMapRevision(f"the layout of {scope} was saved by someone else")
        return _map_layout(row)

    async def delete_network_map_layout(self, scope: str, *, expected_revision: int) -> bool:
        t = network_map_layouts
        async with self._engine.begin() as c:
            current = (await c.execute(sa.select(t.c.revision).where(t.c.scope == scope))).scalar()
            if current is None:
                return False
            if current != expected_revision:
                raise StaleMapRevision(f"the layout of {scope} was saved by someone else")
            await c.execute(t.delete().where(t.c.scope == scope, t.c.revision == expected_revision))
        return True

    async def list_network_map_views(self) -> list[NetworkMapView]:
        async with self._engine.connect() as c:
            rows = (await c.execute(network_map_views.select().order_by(network_map_views.c.name))).all()
        return [_map_view(r) for r in rows]

    async def create_network_map_view(
        self, name: str, state: dict, *, owner_id: int | None, now: datetime
    ) -> NetworkMapView:
        try:
            async with self._engine.begin() as c:
                row = (
                    await c.execute(
                        network_map_views.insert()
                        .values(
                            id=uuid4(),
                            name=name,
                            state=state,
                            owner_id=owner_id,
                            revision=1,
                            created_at=now,
                            updated_at=now,
                        )
                        .returning(network_map_views)
                    )
                ).one()
        except IntegrityError as exc:
            raise MapViewNameTaken(f"a view named {name!r} exists") from exc
        return _map_view(row)

    async def update_network_map_view(
        self,
        view_id: UUID_T,
        *,
        expected_revision: int,
        now: datetime,
        name: str | None = None,
        state: dict | None = None,
    ) -> NetworkMapView | None:
        t = network_map_views
        values: dict[str, Any] = {"revision": t.c.revision + 1, "updated_at": now}
        if name is not None:
            values["name"] = name
        if state is not None:
            values["state"] = state
        try:
            async with self._engine.begin() as c:
                current = (await c.execute(sa.select(t.c.revision).where(t.c.id == view_id))).scalar()
                if current is None:
                    return None
                if current != expected_revision:
                    raise StaleMapRevision("the view was saved by someone else")
                row = (
                    await c.execute(
                        t.update()
                        .where(t.c.id == view_id, t.c.revision == expected_revision)
                        .values(**values)
                        .returning(t)
                    )
                ).first()
        except IntegrityError as exc:
            raise MapViewNameTaken(f"a view named {name!r} exists") from exc
        if row is None:
            raise StaleMapRevision("the view was saved by someone else")
        return _map_view(row)

    async def delete_network_map_view(self, view_id: UUID_T, *, expected_revision: int) -> bool:
        t = network_map_views
        async with self._engine.begin() as c:
            current = (await c.execute(sa.select(t.c.revision).where(t.c.id == view_id))).scalar()
            if current is None:
                return False
            if current != expected_revision:
                raise StaleMapRevision("the view was saved by someone else")
            await c.execute(t.delete().where(t.c.id == view_id))
        return True

    # --- AI audit trail -------------------------------------------------------------

    async def record_ai_event(self, event: AiEvent) -> AiEvent:
        async with self._engine.begin() as c:
            row = (
                await c.execute(
                    ai_events.insert()
                    .returning(ai_events)
                    .values(
                        {
                            **{name: getattr(event, name) for name in _AI_EVENT_FIELDS},
                            "detail": _jsonb(event.detail),
                        }
                    )
                )
            ).first()
        return _ai_event(row)  # type: ignore[arg-type]

    async def list_ai_events(self, limit: int = 200) -> list[AiEvent]:
        async with self._engine.connect() as c:
            rows = (
                await c.execute(
                    ai_events.select().order_by(ai_events.c.at.desc(), ai_events.c.id.desc()).limit(limit)
                )
            ).all()
        return [_ai_event(r) for r in rows]

    async def purge_ai_events(self, before: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(ai_events.delete().where(ai_events.c.at < before))
        return result.rowcount

    async def ai_token_usage(self, since: datetime) -> list[AiTokenUsage]:
        # The zone is a literal. The grouped expression has no bind parameter, and
        # Postgres treats its copies in SELECT and GROUP BY as equal.
        day = sa.cast(sa.func.timezone(sa.literal_column("'UTC'"), ai_events.c.at), sa.Date)
        stmt = (
            sa.select(
                day.label("day"),
                ai_events.c.user_id,
                sa.func.coalesce(sa.func.sum(ai_events.c.tokens_in), 0).label("tokens_in"),
                sa.func.coalesce(sa.func.sum(ai_events.c.tokens_out), 0).label("tokens_out"),
            )
            .where(
                ai_events.c.at >= since,
                sa.or_(ai_events.c.tokens_in.is_not(None), ai_events.c.tokens_out.is_not(None)),
            )
            .group_by(day, ai_events.c.user_id)
            .order_by(day.desc(), ai_events.c.user_id.asc().nulls_last())
        )
        async with self._engine.connect() as c:
            rows = (await c.execute(stmt)).all()
        return [
            AiTokenUsage(
                day=r.day, user_id=r.user_id, tokens_in=int(r.tokens_in), tokens_out=int(r.tokens_out)
            )
            for r in rows
        ]

    async def put_prompt_version(self, prompt_hash: str, content: str, at: datetime) -> bool:
        async with self._engine.begin() as c:
            result = await c.execute(
                insert(ai_prompt_versions)
                .values(hash=prompt_hash, content=content, created_at=at)
                .on_conflict_do_nothing(index_elements=["hash"])
            )
        return result.rowcount == 1

    # --- AI conversations -----------------------------------------------------------

    @staticmethod
    async def _insert_conversation(
        c: AsyncConnection,
        user_id: int,
        surface: str,
        at: datetime,
        *,
        title: str = "",
        ephemeral: bool = False,
        snapshot_id: str | None = None,
        pin_mode: str = "follow",
    ) -> AiConversation:
        row = (
            await c.execute(
                ai_conversations.insert()
                .returning(ai_conversations)
                .values(
                    id=str(uuid4()),
                    user_id=user_id,
                    surface=surface,
                    ephemeral=ephemeral,
                    title=title,
                    snapshot_id=snapshot_id,
                    pin_mode=pin_mode,
                    created_at=at,
                    last_message_at=at,
                )
            )
        ).one()
        return _ai_conversation(row)

    async def create_conversation(
        self,
        user_id: int,
        surface: str,
        at: datetime,
        *,
        title: str = "",
        ephemeral: bool = False,
        snapshot_id: str | None = None,
        pin_mode: str = "follow",
    ) -> AiConversation:
        async with self._engine.begin() as c:
            return await self._insert_conversation(
                c,
                user_id,
                surface,
                at,
                title=title,
                ephemeral=ephemeral,
                snapshot_id=snapshot_id,
                pin_mode=pin_mode,
            )

    async def get_conversation(self, user_id: int, conversation_id: str) -> AiConversation | None:
        cid = canonical_uuid(conversation_id)
        if cid is None:
            return None
        # The reads use one snapshot. The steps agree with the step count and
        # with the message states of the conversation.
        async with self._snapshot_read() as c:
            row = (
                await c.execute(
                    ai_conversations.select().where(
                        ai_conversations.c.id == cid, ai_conversations.c.user_id == user_id
                    )
                )
            ).first()
            if row is None:
                return None
            conversation = _ai_conversation(row)
            messages = await c.execute(
                ai_messages.select().where(ai_messages.c.conversation_id == cid).order_by(ai_messages.c.seq)
            )
            steps = await c.execute(
                ai_steps.select().where(ai_steps.c.conversation_id == cid).order_by(ai_steps.c.label)
            )
            links = await c.execute(
                ai_links.select().where(ai_links.c.conversation_id == cid).order_by(ai_links.c.id)
            )
            conversation.messages = [_ai_message(r) for r in messages]
            conversation.steps = [_ai_step(r) for r in steps]
            conversation.links = [_ai_link(r) for r in links]
        return conversation

    async def list_conversations(
        self,
        user_id: int,
        *,
        surface: str | None = None,
        link_kind: str | None = None,
        link_id: str | None = None,
        limit: int = 50,
    ) -> list[AiConversation]:
        of_row = ai_messages.c.conversation_id == ai_conversations.c.id
        first_question = (
            sa.select(sa.func.left(ai_messages.c.content, LIST_TITLE_CHARS))
            .where(of_row, ai_messages.c.role == "user")
            .order_by(ai_messages.c.seq)
            .limit(1)
            .scalar_subquery()
        )
        last_run = (
            sa.select(ai_messages.c.snapshot_id)
            .where(of_row, ai_messages.c.role == "assistant", ai_messages.c.snapshot_id.is_not(None))
            .order_by(ai_messages.c.seq.desc())
            .limit(1)
            .scalar_subquery()
        )
        query = sa.select(
            ai_conversations, first_question.label("first_question"), last_run.label("last_run")
        ).where(ai_conversations.c.user_id == user_id, ai_conversations.c.ephemeral.is_(False))
        if surface is not None:
            query = query.where(ai_conversations.c.surface == surface)
        if link_kind is not None or link_id is not None:
            linked = [ai_links.c.conversation_id == ai_conversations.c.id]
            if link_kind is not None:
                linked.append(ai_links.c.kind == link_kind)
            if link_id is not None:
                linked.append(ai_links.c.ref_id == link_id)
            query = query.where(sa.exists().where(*linked))
        query = query.order_by(ai_conversations.c.last_message_at.desc(), ai_conversations.c.id).limit(limit)
        async with self._engine.connect() as c:
            rows = (await c.execute(query)).all()
        conversations = []
        for r in rows:
            conversation = _ai_conversation(r)
            conversation.title = conversation.title or r.first_question or ""
            conversation.last_run = r.last_run
            conversations.append(conversation)
        return conversations

    async def delete_conversation(self, user_id: int, conversation_id: str) -> bool:
        cid = canonical_uuid(conversation_id)
        if cid is None:
            return False
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_conversations.delete().where(
                    ai_conversations.c.id == cid, ai_conversations.c.user_id == user_id
                )
            )
        return result.rowcount == 1

    async def start_turn(
        self,
        user_id: int,
        conversation_id: str | None,
        question: str,
        context: dict[str, Any] | None,
        at: datetime,
        *,
        per_user_cap: int,
        global_cap: int,
        surface: str = "drawer",
    ) -> AiMessage | None:
        cid: str | None = None
        if conversation_id is not None:
            cid = canonical_uuid(conversation_id)
            if cid is None:
                return None
        active = ai_messages.c.status.in_(TURN_ACTIVE_STATES)
        async with self._engine.begin() as c:
            # The lock is held until the commit. A second start of the same user
            # counts after the rows of this start exist. Other users are not blocked.
            await c.execute(
                sa.text("SELECT pg_advisory_xact_lock(:c, :u)"), {"c": AI_TURN_LOCK_CLASS, "u": user_id}
            )
            if cid is not None:
                owned = await c.scalar(
                    sa.select(ai_conversations.c.id).where(
                        ai_conversations.c.id == cid, ai_conversations.c.user_id == user_id
                    )
                )
                if owned is None:
                    return None
            mine = await c.scalar(
                sa.select(sa.func.count())
                .select_from(
                    ai_messages.join(ai_conversations, ai_conversations.c.id == ai_messages.c.conversation_id)
                )
                .where(active, ai_conversations.c.user_id == user_id)
            )
            if (mine or 0) >= per_user_cap:
                raise TurnCapExceeded("user")
            # The count is not serialized across users. Concurrent starts of
            # different users can each pass it, and the total can exceed
            # global_cap by the number of such starts.
            total = await c.scalar(sa.select(sa.func.count()).select_from(ai_messages).where(active))
            if (total or 0) >= global_cap:
                raise TurnCapExceeded("global")
            if cid is None:
                cid = (await self._insert_conversation(c, user_id, surface, at, ephemeral=True)).id
            seq = await c.scalar(
                ai_conversations.update()
                .where(ai_conversations.c.id == cid, ai_conversations.c.user_id == user_id)
                .values(message_count=ai_conversations.c.message_count + 2, last_message_at=at)
                .returning(ai_conversations.c.message_count)
            )
            if seq is None:
                return None
            await c.execute(
                ai_messages.insert().values(
                    id=str(uuid4()),
                    conversation_id=cid,
                    seq=seq - 1,
                    role="user",
                    content=question,
                    context=_jsonb(context),
                    status="done",
                    created_at=at,
                    finished_at=at,
                )
            )
            row = (
                await c.execute(
                    ai_messages.insert()
                    .returning(ai_messages)
                    .values(
                        id=str(uuid4()),
                        conversation_id=cid,
                        seq=seq,
                        role="assistant",
                        status="pending",
                        created_at=at,
                    )
                )
            ).one()
        return _ai_message(row)

    async def claim_turn(self, message_id: str, owner: str, lease_s: float, now: datetime) -> bool:
        mid = canonical_uuid(message_id)
        if mid is None:
            return False
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_messages.update()
                .where(
                    ai_messages.c.id == mid,
                    ai_messages.c.role == "assistant",
                    ai_messages.c.status == "pending",
                )
                .values(
                    status="running", lease_owner=owner, lease_expires_at=now + timedelta(seconds=lease_s)
                )
            )
        return result.rowcount == 1

    async def heartbeat_turn(self, message_id: str, owner: str, lease_s: float, now: datetime) -> bool:
        mid = canonical_uuid(message_id)
        if mid is None:
            return False
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_messages.update()
                .where(
                    ai_messages.c.id == mid,
                    ai_messages.c.status == "running",
                    ai_messages.c.lease_owner == owner,
                )
                .values(lease_expires_at=now + timedelta(seconds=lease_s))
            )
        return result.rowcount == 1

    async def append_step(
        self,
        message_id: str,
        tool: str,
        tool_version: int,
        arguments: dict[str, Any],
        is_error: bool,
        result: str,
        started_at: datetime,
        elapsed_ms: int,
        *,
        result_summary: str | None = None,
        provenance: dict[str, Any] | None = None,
        step_id: str | None = None,
    ) -> AiStep:
        mid = canonical_uuid(message_id)
        if mid is None:
            raise KeyError(message_id)
        async with self._engine.begin() as c:
            # The UPDATE locks the conversation row until the commit. 2 appends
            # to one conversation take consecutive labels.
            row = (
                await c.execute(
                    ai_conversations.update()
                    .where(
                        ai_conversations.c.id
                        == sa.select(ai_messages.c.conversation_id)
                        .where(ai_messages.c.id == mid)
                        .scalar_subquery()
                    )
                    .values(step_count=ai_conversations.c.step_count + 1)
                    .returning(ai_conversations.c.id, ai_conversations.c.step_count)
                )
            ).first()
            if row is None:
                raise KeyError(message_id)
            step = (
                await c.execute(
                    ai_steps.insert()
                    .returning(ai_steps)
                    .values(
                        id=step_id or str(uuid4()),
                        conversation_id=row.id,
                        message_id=mid,
                        label=row.step_count,
                        tool=tool,
                        tool_version=tool_version,
                        arguments=arguments,
                        is_error=is_error,
                        result=result,
                        result_sha256=step_digest(result),
                        result_chars=len(result),
                        result_summary=result_summary,
                        provenance=_jsonb(provenance),
                        started_at=started_at,
                        elapsed_ms=elapsed_ms,
                    )
                )
            ).one()
        return _ai_step(step)

    async def finish_turn(
        self,
        message_id: str,
        owner: str,
        status: str,
        at: datetime,
        *,
        content: str = "",
        envelope: dict[str, Any] | None = None,
        error: str | None = None,
        snapshot_id: str | None = None,
        provider: str | None = None,
        model_requested: str | None = None,
        model_served: str | None = None,
        prompt_hash: str | None = None,
        usage: dict[str, Any] | None = None,
    ) -> bool:
        if status not in TURN_FINAL_STATES:
            raise ValueError(f"not a final turn status: {status!r}")
        mid = canonical_uuid(message_id)
        if mid is None:
            return False
        async with self._engine.begin() as c:
            cid = await c.scalar(
                ai_messages.update()
                .where(
                    ai_messages.c.id == mid,
                    ai_messages.c.status == "running",
                    ai_messages.c.lease_owner == owner,
                )
                .values(
                    status=status,
                    content=content,
                    envelope=_jsonb(envelope),
                    error=error,
                    snapshot_id=snapshot_id,
                    provider=provider,
                    model_requested=model_requested,
                    model_served=model_served,
                    prompt_hash=prompt_hash,
                    usage=_jsonb(usage),
                    lease_expires_at=None,
                    finished_at=at,
                )
                .returning(ai_messages.c.conversation_id)
            )
            if cid is None:
                return False
            await c.execute(
                ai_conversations.update()
                .where(ai_conversations.c.id == cid)
                .values(
                    last_message_at=sa.func.greatest(
                        ai_conversations.c.last_message_at,
                        sa.literal(at, ai_conversations.c.last_message_at.type),
                    )
                )
            )
        return True

    async def set_question_context(self, message_id: str, context: dict[str, Any]) -> bool:
        mid = canonical_uuid(message_id)
        if mid is None:
            return False
        async with self._engine.begin() as c:
            reply = (
                await c.execute(
                    sa.select(ai_messages.c.conversation_id, ai_messages.c.seq).where(
                        ai_messages.c.id == mid, ai_messages.c.role == "assistant"
                    )
                )
            ).first()
            if reply is None:
                return False
            result = await c.execute(
                ai_messages.update()
                .where(
                    ai_messages.c.conversation_id == reply.conversation_id,
                    ai_messages.c.seq == reply.seq - 1,
                    ai_messages.c.role == "user",
                )
                .values(context=_jsonb(context))
            )
        return result.rowcount == 1

    async def request_cancel(self, user_id: int, message_id: str) -> bool:
        mid = canonical_uuid(message_id)
        if mid is None:
            return False
        owned = sa.select(ai_conversations.c.id).where(ai_conversations.c.user_id == user_id)
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_messages.update()
                .where(
                    ai_messages.c.id == mid,
                    ai_messages.c.status.in_(TURN_ACTIVE_STATES),
                    ai_messages.c.conversation_id.in_(owned),
                )
                .values(cancel_requested=True)
            )
        return result.rowcount == 1

    async def get_message(
        self, user_id: int, message_id: str, *, surface: str | None = None
    ) -> AiMessage | None:
        mid = canonical_uuid(message_id)
        if mid is None:
            return None
        query = (
            sa.select(ai_messages)
            .join(ai_conversations, ai_conversations.c.id == ai_messages.c.conversation_id)
            .where(ai_messages.c.id == mid, ai_conversations.c.user_id == user_id)
        )
        if surface is not None:
            query = query.where(ai_conversations.c.surface == surface)
        async with self._engine.connect() as c:
            row = (await c.execute(query)).first()
        return None if row is None else _ai_message(row)

    async def get_turn(self, user_id: int, message_id: str) -> AiTurn | None:
        mid = canonical_uuid(message_id)
        if mid is None:
            return None
        async with self._engine.connect() as c:
            row = (
                await c.execute(
                    sa.select(ai_messages)
                    .join(ai_conversations, ai_conversations.c.id == ai_messages.c.conversation_id)
                    .where(
                        ai_messages.c.id == mid,
                        ai_messages.c.role == "assistant",
                        ai_conversations.c.user_id == user_id,
                    )
                )
            ).first()
            if row is None:
                return None
            message = _ai_message(row)
            question = (
                await c.execute(
                    ai_messages.select().where(
                        ai_messages.c.conversation_id == message.conversation_id,
                        ai_messages.c.seq == message.seq - 1,
                    )
                )
            ).first()
            steps = await c.execute(
                ai_steps.select().where(ai_steps.c.message_id == mid).order_by(ai_steps.c.label)
            )
            return AiTurn(
                message=message,
                question=None if question is None else _ai_message(question),
                steps=[_ai_step(r) for r in steps],
            )

    async def get_turn_progress(self, user_id: int, message_id: str, after: int) -> AiTurnProgress | None:
        mid = canonical_uuid(message_id)
        if mid is None:
            return None
        async with self._snapshot_read() as c:
            status = await c.scalar(
                sa.select(ai_messages.c.status)
                .join(ai_conversations, ai_conversations.c.id == ai_messages.c.conversation_id)
                .where(
                    ai_messages.c.id == mid,
                    ai_messages.c.role == "assistant",
                    ai_conversations.c.user_id == user_id,
                )
            )
            if status is None:
                return None
            steps = await c.execute(
                ai_steps.select()
                .where(ai_steps.c.message_id == mid, ai_steps.c.label > after)
                .order_by(ai_steps.c.label)
            )
            return AiTurnProgress(status=status, steps=[_ai_step(r) for r in steps])

    async def get_step(self, user_id: int, step_id: str) -> AiStep | None:
        sid = canonical_uuid(step_id)
        if sid is None:
            return None
        query = (
            sa.select(ai_steps)
            .join(ai_conversations, ai_conversations.c.id == ai_steps.c.conversation_id)
            .where(ai_steps.c.id == sid, ai_conversations.c.user_id == user_id)
        )
        async with self._engine.connect() as c:
            row = (await c.execute(query)).first()
        return None if row is None else _ai_step(row)

    async def set_summary(self, user_id: int, conversation_id: str, summary: str, through: int) -> bool:
        cid = canonical_uuid(conversation_id)
        if cid is None:
            return False
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_conversations.update()
                .where(
                    ai_conversations.c.id == cid,
                    ai_conversations.c.user_id == user_id,
                    ai_conversations.c.summary_through < through,
                )
                .values(summary=summary, summary_through=through)
            )
        return result.rowcount == 1

    async def expire_stale_turns(self, now: datetime, pending_grace_s: float = 60.0) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_messages.update()
                .where(
                    ai_messages.c.status.in_(TURN_ACTIVE_STATES),
                    sa.or_(
                        ai_messages.c.lease_expires_at <= now,
                        sa.and_(
                            ai_messages.c.status == "pending",
                            ai_messages.c.lease_expires_at.is_(None),
                            ai_messages.c.created_at <= now - timedelta(seconds=pending_grace_s),
                        ),
                    ),
                )
                .values(status="interrupted", lease_expires_at=None, finished_at=now)
            )
        return result.rowcount

    async def add_link(
        self,
        conversation_id: str,
        kind: str,
        ref_id: str,
        direction: str,
        at: datetime,
        *,
        message_id: str | None = None,
        step_id: str | None = None,
        ref_revision: int | None = None,
    ) -> AiLink | None:
        cid = canonical_uuid(conversation_id)
        mid = None if message_id is None else canonical_uuid(message_id)
        sid = None if step_id is None else canonical_uuid(step_id)
        if cid is None or (message_id is not None and mid is None) or (step_id is not None and sid is None):
            return None
        async with self._engine.begin() as c:
            # FOR KEY SHARE blocks a delete of the conversation, and of its
            # messages and steps, until the insert commits.
            checks = [
                sa.select(ai_conversations.c.id)
                .where(ai_conversations.c.id == cid)
                .with_for_update(key_share=True)
            ]
            if mid is not None:
                checks.append(
                    sa.select(ai_messages.c.id).where(
                        ai_messages.c.id == mid, ai_messages.c.conversation_id == cid
                    )
                )
            if sid is not None:
                checks.append(
                    sa.select(ai_steps.c.id).where(ai_steps.c.id == sid, ai_steps.c.conversation_id == cid)
                )
            for check in checks:
                if await c.scalar(check) is None:
                    return None
            row = (
                await c.execute(
                    ai_links.insert()
                    .returning(ai_links)
                    .values(
                        conversation_id=cid,
                        message_id=mid,
                        step_id=sid,
                        kind=kind,
                        ref_id=ref_id,
                        ref_revision=ref_revision,
                        direction=direction,
                        created_at=at,
                    )
                )
            ).one()
        return _ai_link(row)

    async def compact_steps(self, before: datetime, at: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_steps.update()
                .where(ai_steps.c.started_at < before, ai_steps.c.result.is_not(None))
                .values(result=None, compacted_at=at)
            )
        return result.rowcount

    async def purge_conversations(self, before: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_conversations.delete().where(ai_conversations.c.last_message_at < before)
            )
        return result.rowcount

    async def purge_ephemeral(self, before: datetime) -> int:
        async with self._engine.begin() as c:
            result = await c.execute(
                ai_conversations.delete().where(
                    ai_conversations.c.ephemeral.is_(True), ai_conversations.c.last_message_at < before
                )
            )
        return result.rowcount

    async def dispose(self) -> None:
        for claim in list(self._claims.values()):
            with contextlib.suppress(Exception):
                await claim.close()
        self._claims.clear()
        await self._claims_engine.dispose()
        await self._engine.dispose()


class _PgAssessmentTransaction:
    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection

    async def get(self, kind: str, identifier: str, revision: int | None = None) -> dict | None:
        table = assessment_records
        query = sa.select(table.c.document).where(table.c.kind == kind, table.c.id == identifier)
        if revision is not None:
            query = query.where(table.c.revision == revision)
        return (
            await self.connection.execute(query.order_by(table.c.revision.desc()).limit(1))
        ).scalar_one_or_none()

    async def list(
        self, kind: str, *, filters: dict | None = None, limit: int = 100, latest: bool = False
    ) -> list[dict]:
        table = assessment_records
        document = table.c.document
        query = sa.select(document).where(table.c.kind == kind)
        if latest:
            newest = (
                sa.select(table.c.id, sa.func.max(table.c.revision).label("revision"))
                .where(table.c.kind == kind)
                .group_by(table.c.id)
                .subquery()
            )
            query = query.join(
                newest, sa.and_(table.c.id == newest.c.id, table.c.revision == newest.c.revision)
            )
        for key, value in (filters or {}).items():
            if key == "after_id":
                query = query.where(table.c.id > value)
            elif key == "claimable_at":
                query = query.where(
                    sa.or_(
                        document["state"].astext == "queued",
                        sa.and_(
                            document["state"].astext == "running",
                            sa.cast(document["lease_expires_at"].astext, sa.TIMESTAMP(timezone=True))
                            <= datetime.fromisoformat(value),
                        ),
                    )
                )
            elif isinstance(value, list):
                query = query.where(document[key].astext.in_(value))
            elif value is None:
                query = query.where(document[key].astext.is_(None))
            else:
                query = query.where(document.contains({key: value}))
        created = document["created_at"].astext
        if "after_id" in (filters or {}):
            query = query.order_by(table.c.id)
        else:
            query = query.order_by(
                created.asc() if "claimable_at" in (filters or {}) else created.desc(), table.c.id
            )
        if limit:
            query = query.limit(limit)
        return list((await self.connection.execute(query)).scalars().all())

    async def put(self, kind: str, document: dict, *, replace: bool = False) -> None:
        document = bounded_json(document)
        statement = insert(assessment_records).values(
            kind=kind, id=document["id"], revision=document["revision"], document=document
        )
        if replace:
            statement = statement.on_conflict_do_update(
                index_elements=["kind", "id", "revision"], set_={"document": document}
            )
        await self.connection.execute(statement)


# The import adds the inventory tables (app/inventory/tables.py) to `metadata`
# after every other table exists. They reference `sources`, `sites`, `devices`,
# `users` and `reported_locations` and append columns to 3 of them. tables.py
# imports `metadata` from this module, which defines those names before the
# import.
from hst.app.inventory import tables as _inventory_tables  # noqa: E402, F401
