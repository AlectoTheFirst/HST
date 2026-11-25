"""Identity and run-history store. Production uses Postgres (pg.py), and the tests use an in-memory store.

The app exposes read-only Cypher over the twin graph, and any operator can read
what the graph holds. The store keeps credentials outside the graph.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Collection, Iterable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from hst.assessment.store import AssessmentStore
from hst.core.identity import plain_uid

if TYPE_CHECKING:
    from hst.app.inventory.repository import InventoryRepository

ROLES = ("viewer", "operator", "admin")

# `UNSET` marks an omitted keyword of a partial update. `None` is a value there
# (`Change.snapshot_cts` of an unpinned change).
UNSET = object()

# A lookup writes `sessions.last_used_at` when the stored value is at least this old.
SESSION_TOUCH_INTERVAL = timedelta(minutes=5)
# An SSO account's personal access token works only while the account's newest
# SSO login is at most this old. The account is disabled only at its next
# login.
SSO_TOKEN_LOGIN_MAX_AGE = timedelta(days=30)


@dataclass
class User:
    id: int
    username: str
    # NULL means no password authentication.
    password_hash: str | None
    role: str
    disabled: bool
    created_at: datetime
    # 'local' is a role that an admin assigned. 'mapped' is a role from the group
    # mappings. An SSO login recomputes a 'mapped' role and keeps a 'local' role.
    role_source: str = "local"
    # The UI palette preference. The UI follows the OS when it is None.
    theme: str | None = None


@dataclass
class Run:
    id: int
    source: str
    status: str  # running | ok | error
    started_at: datetime
    finished_at: datetime | None
    detail: str
    # The id of the account that asked for this run, or None for cron and the reasoner.
    triggered_by: int | None = None
    # The `collection_ts` of the snapshot that this run published, as a string.
    # It equals the id that `/api/snapshots` reports. It is None for a run that
    # published nothing.
    snapshot_key: str | None = None


@dataclass
class Job:
    """One unit of background work, queued in Postgres.

    `source` and `device` scope a per-device collection job and are None for a
    maintenance job.

    `state` is one of 'queued', 'running', 'ok', 'error', 'dead'. A failed
    attempt with retries left goes back to 'queued'. The backoff moves
    `not_before`, and `detail` holds the failure text. 'dead' is the terminal
    state after the last attempt. 'error' is the terminal state for a job with
    `max_attempts` of 1.

    An executor extends `lease_expires_at` while it works, and `reap_jobs`
    requeues a claim whose lease has passed.

    `detail` is text for an operator and can hold the text of an exception.
    GET /api/jobs requires `runs.manage`. A job body writes no credential to
    `detail`.

    `triggered_by` is free text for the origin. It is 'scheduler', or an origin
    and the id of the account that asked for the job ('runs:<id>',
    'debug:<id>', 'inventory:<id>', 'assessment:<id>'). It has no foreign key.
    """

    id: int
    kind: str
    source: str | None
    device: str | None
    state: str
    priority: int
    attempt: int
    max_attempts: int
    not_before: datetime
    lease_expires_at: datetime | None
    claimed_by: str | None
    enqueued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    detail: str | None
    triggered_by: str


JOB_STATES = ("queued", "running", "ok", "error", "dead")
# The states of the partial unique index `one_pending_per_kind`. An enqueue of
# the same (kind, source, device) collides with a job in one of them.
JOB_PENDING_STATES = ("queued", "running")


@dataclass
class AppSetting:
    """One JSON settings document plus its sealed credential blob.

    `secrets` is encrypted with app/crypto.py.
    """

    key: str
    value: dict
    secrets: bytes
    updated_at: datetime


@dataclass
class Site:
    """The geographic place where devices sit. `code` is free-form, for example
    `DEU-FRA-123123` or `hq`."""

    id: int
    code: str
    name: str
    location: str
    params: dict = field(default_factory=dict)
    device_count: int = 0


@dataclass(frozen=True)
class GeoPlace:
    """One place of the offline address lookup (app/geo_places.py). A search
    result without a postal code stands for every postal code of the place."""

    country_code: str
    postal_code: str | None
    name: str
    admin1: str
    admin2: str
    lat: float
    lon: float


@dataclass
class GeoPlaceSearch:
    items: list[GeoPlace]
    # False while no place file is loaded.
    available: bool


@dataclass
class TargetDevice:
    """A discovered graph uid observed through one collection target."""

    source: str
    host: str
    device_uid: str
    updated_at: datetime
    location_id: str = ""


@dataclass
class DeviceIdentity:
    """One identifier of the device identity registry.

    `kind` is `serial` or `ref`, and `value` is the identifier in its registry
    form (`core/identity.py identifier`). `hostname` is the hostname at the
    mint, and `last_hostname` is the hostname that the device reported last.
    A row that the registry bound to an existing uid, for example a stack
    member serial, has no hostname of its own.
    """

    uid: str
    kind: str
    value: str
    hostname: str | None
    last_hostname: str | None
    first_run_id: int | None


@dataclass
class DeviceIdentityReport:
    """One uid that differs from `dev:<short name>` of the hostname that its
    device reported last. The cases are a suffixed uid, a device renamed after
    the mint, and a uid that the rename command set. `identifiers` holds its
    (kind, value) pairs."""

    uid: str
    hostname: str | None
    last_hostname: str | None
    first_run_id: int | None
    identifiers: list[tuple[str, str]]


def identity_report(rows: Iterable[DeviceIdentity]) -> list[DeviceIdentityReport]:
    """Group the registry rows by uid and return the uids that differ from
    `dev:<short name of the hostname seen last>` (`core/identity.py
    plain_uid`). Both stores use this rule."""
    by_uid: dict[str, list[DeviceIdentity]] = {}
    for row in rows:
        by_uid.setdefault(row.uid, []).append(row)
    out: list[DeviceIdentityReport] = []
    for device_uid, group in sorted(by_uid.items()):
        group.sort(key=lambda r: (r.first_run_id is None, r.first_run_id or 0, r.kind, r.value))
        hostname = next((r.hostname for r in group if r.hostname), None)
        last = next((r.last_hostname for r in group if r.last_hostname), None) or hostname
        if device_uid == plain_uid(last):
            continue
        out.append(
            DeviceIdentityReport(
                uid=device_uid,
                hostname=hostname,
                last_hostname=last,
                first_run_id=min((r.first_run_id for r in group if r.first_run_id is not None), default=None),
                identifiers=[(r.kind, r.value) for r in group],
            )
        )
    return out


@dataclass
class ReportedLocation:
    """A place an orchestrator names in its own terms.

    `location_id` is the stable id of the source system.
    `name` is for display only. A null `site` means that the location is unplaced.
    """

    source: str
    location_id: str
    name: str
    site: str | None
    device_count: int = 0


@dataclass
class SiteRelease:
    """The groups, the bound locations and the hand-placed devices that a deleted
    site released. All of them are unplaced and still collectable. The graph
    holds the old placements until the next run.
    """

    groups: list[str]
    locations: list[tuple[str, str]]
    devices: list[str]


@dataclass
class Change:
    """A planned change. It holds a target snapshot, an ordered list of typed
    intents (see `ChangeIntent`) and a status.

    `status` is one of 'draft', 'simulated', 'closed'. `snapshot_cts` pins the
    baseline (a `collection_ts` from `/api/snapshots`), and None means the change
    is not pinned. A route-delta provider computes the predicted delta on demand.

    `created_by` is the account id, as in `Run.triggered_by`.
    """

    id: int
    title: str
    description: str
    snapshot_cts: int | None
    status: str
    created_by: int | None
    created_at: datetime
    updated_at: datetime


@dataclass
class ChangeIntent:
    """One typed operation of a change. `kind` is the name of an entry of the
    change intent catalog, and `params` is the payload of that entry.
    `position` is the order of display and evaluation. It is unique within a
    change.
    """

    id: int
    change_id: int
    position: int
    kind: str
    params: dict


@dataclass
class Source:
    id: int
    name: str
    type: str
    config: dict
    secrets: bytes
    enabled: bool
    created_at: datetime
    updated_at: datetime


@dataclass
class Device:
    """One device of a source's fleet.

    A device row holds an address and an enabled flag. The group row holds the
    credentials, the cadence, the jump host, the site and the routing scope. A
    source with no device rows collects `config.host`.

    `host_key` is the TOFU pin of the device. It is written only while it is
    empty, as `config.host_key` of a source is. `port` is None when the device
    uses the port of the group.
    """

    id: int
    source: str
    host: str
    port: int | None
    enabled: bool
    host_key: str
    created_at: datetime
    updated_at: datetime


@dataclass
class DeviceSpec:
    """The values that a caller gives for one device of a fleet.

    The store adds the id, the timestamps and the pinned `host_key`. A rewrite
    of the row keeps its `host_key`.
    """

    host: str
    port: int | None = None
    enabled: bool = True


@dataclass
class DeviceStatus:
    """The state of the last collection attempt for one (source, host).

    The row is updated in place. `host` is a plain string.

    `last_raw_sha` is the change key of the fetch. A successful fetch sets it,
    a skipped attempt keeps it and a failed attempt clears it. `last_full_at`
    is the time of the last full normalize and load. `last_success_at` also
    advances on a fetch that skipped the normalize and the load. The next ok
    upsert resets `consecutive_failures` and `last_error`.

    `last_obs_sha` is the second change key (`collectors/base.py obs_sha`). It
    is the hash of the observation half of the payload (the ARP and MAC
    tables, the RIB). `last_raw_sha` does not cover that half. A fetch whose
    `last_raw_sha` matches and whose `last_obs_sha` does not match writes the
    side tables of the device and leaves its graph. A device with an empty
    hash skips on `last_raw_sha` alone.

    `last_graph_sha` is the third key (`collectors/base.py graph_sha`). It is
    the digest of the batch that the last normalized payload of the device
    produced, bound as `last_raw_sha` is
    (`inventory.collection.fingerprint_for`). A payload whose `last_raw_sha`
    does not match is normalized. When its digest matches `last_graph_sha`,
    only the objects that another source or device also writes are written to
    the graph. `last_graph_at` is the time at which that batch was last
    written to the graph. A digest older than `collect_full_interval_s` is not
    compared. `last_graph_at` differs from `last_full_at` for a device
    collected by per-device jobs. The fetch of such a device stores the
    payload, and its device run writes the graph later. A failed attempt and a
    failed load of a device run clear the digest, as they clear
    `last_raw_sha`. A device without a digest loads in full once.

    `last_graph_fetch_at` is the fetch time of the payload whose batch was
    last compared with the graph, written or found unchanged. A device run
    applies a parked payload only when it was fetched after that time
    (app/runs_exec.py `build_device_run`). The objects of an unchanged batch
    come forward with the time of their last write. A failed attempt leaves
    `last_graph_fetch_at`. The device run also reads
    `cycle.scope_collected_at`, the time of the objects that a failed load
    wrote to the graph.

    `last_verified_started_at` and `last_verified_at` are the start and the
    end of the last fetch that found the device unchanged against the stored
    basis. Its configuration hash matched `last_raw_sha`, and its observation
    hash matched `last_obs_sha` or the collector declares no observations. The
    check covers what the 2 hashes cover. The volatile keys outside both
    hashes (`Collector.VOLATILE_RAW_KEYS`) feed no value of the graph or the
    side tables. A device run publishes the window as the time at which a
    carried device was last checked (app/runs_exec.py `build_device_run`).
    The writing statement records the check only while `last_raw_sha` and
    `last_obs_sha` equal the hashes that the fetch compared, and only when the
    window ends at or after its start and after `last_graph_fetch_at`. A
    failed attempt, a full park and a load that records a new basis clear the
    check. Null means that no fetch checked the device.
    """

    id: int
    source: str
    host: str
    last_raw_sha: str
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_full_at: datetime | None
    consecutive_failures: int
    last_error: str
    fetch_ms: int | None
    normalize_ms: int | None
    load_ms: int | None
    updated_at: datetime
    last_obs_sha: str = ""
    last_graph_sha: str = ""
    last_graph_at: datetime | None = None
    last_graph_fetch_at: datetime | None = None
    last_verified_started_at: datetime | None = None
    last_verified_at: datetime | None = None


@dataclass
class AuthProvider:
    """A configured external identity provider (OIDC or SAML).

    `secrets` is sealed as `Source.secrets` is. The store handles opaque bytes,
    and only app/crypto.py decrypts them. None means that the provider has no
    secret.
    """

    id: int
    name: str
    kind: str  # 'oidc' | 'saml'
    config: dict
    secrets: bytes | None
    enabled: bool
    created_at: datetime
    updated_at: datetime


@dataclass
class Identity:
    """One external account linked to one local user, at one provider.

    `subject` is the stable id at the provider, OIDC's `sub` or SAML's NameID. No
    identity is linked to an existing local account by email match.
    """

    id: int
    user_id: int
    provider_id: int
    subject: str
    email: str
    last_login_at: datetime | None


class IdentityOwnerMissing(LookupError):
    """The user or the auth provider of a new identity does not exist."""


@dataclass
class GroupMapping:
    """One rule from a group to a role for a provider. Every SSO login applies it."""

    id: int
    provider_id: int
    group_name: str
    role: str


@dataclass
class LoginEvent:
    """One authentication decision, local or SSO. No statement updates a row.
    The only delete is the
    age-based purge of the scheduled maintenance job (`purge_login_events`,
    LOGIN_EVENT_RETENTION_DAYS).

    `username` is the name as presented (local) or resolved or provisioned
    (SSO), and on a failure it can be the name of an account that does not exist.
    `user_id` is set only when the attempt authenticated as an account.
    `provider` is `'local'` or the provider slug. `outcome`
    is a short stable token (`'ok'`, `'bad_credentials'`, `'disabled'`,
    `'rate_limited'`, `'local_login_disabled'`, `'unknown_provider'`,
    `'failed'`).
    """

    id: int
    at: datetime
    username: str
    user_id: int | None
    provider: str
    outcome: str
    source: str = ""


@dataclass
class CypherEvent:
    """One POST /api/cypher call, or one Cypher tool call by a model surface.

    `user_id` is ON DELETE SET NULL, as `login_events.user_id` is.

    `query` is stored verbatim. `outcome` is a short stable
    token: 'ok', 'rejected' (the guard refused it), 'too_large' (over the
    query-size cap and not run), 'result_too_large' (bounded mid-stream),
    'error' (the server rejected the Cypher itself). `row_count` and
    `byte_count` describe what came back, and are 0 for anything but 'ok'.
    `origin` is the surface that ran the query ('web' for the in-app agent,
    'mcp', 'rest'), and `ai_step_id` the tool call's step id when a model ran
    it. Both are nullable.
    """

    id: int
    at: datetime
    user_id: int | None
    query: str
    outcome: str
    row_count: int = 0
    byte_count: int = 0
    origin: str | None = None
    ai_step_id: str | None = None


class StaleMapRevision(Exception):
    """A network map write stated a revision that differs from the revision of
    the row. The caller reads again before it writes."""


class MapViewNameTaken(Exception):
    """A network map view with that name exists."""


@dataclass
class NetworkMapLayout:
    """The positions that people moved in one drawn scope (`site/<code>`) of the
    network map (`network_map_layouts`). `positions` maps a device uid to
    {x, y} in drawing units."""

    scope: str
    positions: dict
    revision: int
    updated_by: int | None
    updated_at: datetime


@dataclass
class NetworkMapView:
    """A named view of the network map (`network_map_views`), shared by the team."""

    id: UUID
    name: str
    state: dict
    owner_id: int | None
    revision: int
    created_at: datetime
    updated_at: datetime


@dataclass
class EvidenceExport:
    """One download of decrypted evidence by an account (`evidence_exports`).

    `kind` is `payload_bundle`, `run_bundle` or `http_trace`. `raw_mode` is
    `redacted`, `full` or `none` for a bundle, and None for a trace. `run_id` is
    the raw-store run id for a payload bundle or a trace, and the runs-table id
    as decimal text for a run bundle. `payloads` is the number of stored
    payloads in the download. `user_id` is ON DELETE SET NULL, as
    `cypher_events.user_id` is, and the row keeps `username` after the account
    is removed.
    """

    id: int
    at: datetime
    user_id: int | None
    username: str
    kind: str
    raw_mode: str | None
    source: str
    host: str
    run_id: str
    payloads: int


@dataclass
class AccessToken:
    """One personal access token, the bearer credential of the MCP HTTP
    transport (`personal_access_tokens`).

    The store holds only the hash of the token, as for sessions. `scope` is
    `read` or `read-write`. It is set when the token is created, and no
    statement changes it. Revoking a token deletes its row, and a token is
    deleted with its user. `last_used_at` is None until the token first
    authenticates. It moves forward at most once per `SESSION_TOUCH_INTERVAL`.
    """

    id: int
    user_id: int
    name: str
    scope: str
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None


@dataclass
class AiEvent:
    """One metadata row of the AI audit trail (`ai_events`).

    `event` is one of `turn.start`, `provider.round`, `tool.call`, `turn.done`,
    `turn.error`, `turn.cancel`, `turn.interrupted`, `context.resolve`,
    `conversation.delete`, `summary.update` and `handoff`. `outcome` is one of
    `ok`, `error`, `refused`, `timeout`, `cancelled` and `rejected`. The row
    holds no question, answer, argument or result text. `detail` holds only
    redacted, bounded values. `user_id` is ON DELETE SET NULL, as
    `cypher_events.user_id` is. `id` is assigned by the store.
    """

    at: datetime
    origin: str
    event: str
    outcome: str
    user_id: int | None = None
    surface: str | None = None
    conversation_id: str | None = None
    message_id: str | None = None
    step_id: str | None = None
    provider: str | None = None
    model_requested: str | None = None
    model_served: str | None = None
    prompt_hash: str | None = None
    tool: str | None = None
    tool_version: int | None = None
    snapshot: str | None = None
    latency_ms: int | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    error_class: str | None = None
    detail: dict[str, Any] | None = None
    id: int = 0


@dataclass(frozen=True)
class AiTokenUsage:
    """The tokens one user's AI events recorded on one UTC day.

    The sums are over the `ai_events` rows that hold `tokens_in` or
    `tokens_out`. `user_id` is None for rows with no user, such as local MCP calls
    and rows of a deleted account.
    """

    day: date
    user_id: int | None
    tokens_in: int
    tokens_out: int


# The active states of an assistant message. `start_turn` counts these rows
# against its caps, and `expire_stale_turns` moves them to 'interrupted'.
TURN_ACTIVE_STATES = ("pending", "running")
# The states `finish_turn` may set.
TURN_FINAL_STATES = ("done", "error", "cancelled")
# `list_conversations` titles an untitled conversation with at most this many
# characters of its first question.
LIST_TITLE_CHARS = 200


class TurnCapExceeded(Exception):
    """`start_turn` refused a turn. `scope` is 'user' when the caller already
    has `per_user_cap` active turns, and 'global' when all users together have
    `global_cap`."""

    def __init__(self, scope: str) -> None:
        super().__init__(scope)
        self.scope = scope


def canonical_uuid(value: str) -> str | None:
    """`value` in the canonical UUID text form, or None when it is not a UUID.
    The conversation methods treat an id that is not a UUID as a missing one."""
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError):
        return None


def step_digest(result: str) -> str:
    """Return the SHA-256 of the UTF-8 text of a step result (`ai_steps.result_sha256`)."""
    return hashlib.sha256(result.encode()).hexdigest()


@dataclass
class AiMessage:
    """One row of `ai_messages`. A user row holds the question and its page
    context with status 'done'. An assistant row holds the answer, runs through
    'pending' and 'running', and ends in 'done', 'error', 'cancelled' or
    'interrupted'. Its id is the id a client polls."""

    id: str
    conversation_id: str
    seq: int
    role: str
    status: str
    created_at: datetime
    content: str = ""
    context: dict[str, Any] | None = None
    envelope: dict[str, Any] | None = None
    error: str | None = None
    snapshot_id: str | None = None
    provider: str | None = None
    model_requested: str | None = None
    model_served: str | None = None
    prompt_hash: str | None = None
    usage: dict[str, Any] | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    cancel_requested: bool = False
    finished_at: datetime | None = None


@dataclass
class AiStep:
    """One tool call of a turn (`ai_steps`). `label` is unique within the
    conversation and is cited as `s<label>`. `result` is the text the UI shows,
    and is None after `compact_steps` removed it. `result_sha256` and
    `result_chars` describe the stored text."""

    id: str
    conversation_id: str
    message_id: str
    label: int
    tool: str
    tool_version: int
    arguments: dict[str, Any]
    is_error: bool
    result: str | None
    result_sha256: str
    result_chars: int
    started_at: datetime
    elapsed_ms: int
    result_summary: str | None = None
    provenance: dict[str, Any] | None = None
    compacted_at: datetime | None = None


@dataclass
class AiLink:
    """A reference between a conversation and another object (`ai_links`).
    `direction` is 'from' when the chat was opened from the object and 'to'
    when the chat created the object or handed off to it. `ref_id` has no
    foreign key."""

    id: int
    conversation_id: str
    kind: str
    ref_id: str
    direction: str
    created_at: datetime
    message_id: str | None = None
    step_id: str | None = None
    ref_revision: int | None = None


@dataclass
class AiConversation:
    """One row of `ai_conversations`, owned by `user_id`. `step_count` is the
    last step label issued. `get_conversation` fills `messages` (by seq),
    `steps` (by label) and `links`, and `list_conversations` leaves them empty.
    `list_conversations` sets `title` of a conversation without a title to the
    start of its first question. It sets `last_run` to the run of the newest
    answer that has one."""

    id: str
    user_id: int
    surface: str
    created_at: datetime
    last_message_at: datetime
    ephemeral: bool = False
    title: str = ""
    snapshot_id: str | None = None
    pin_mode: str = "follow"
    summary: str | None = None
    summary_through: int = 0
    message_count: int = 0
    step_count: int = 0
    last_run: str | None = None
    messages: list[AiMessage] = field(default_factory=list)
    steps: list[AiStep] = field(default_factory=list)
    links: list[AiLink] = field(default_factory=list)


@dataclass
class AiTurn:
    """One assistant message with the user message it answers and its steps.
    `question` is the message one seq before `message`, None when that row is
    missing. `steps` are the message's steps by label. `get_turn` returns it."""

    message: AiMessage
    question: AiMessage | None = None
    steps: list[AiStep] = field(default_factory=list)


@dataclass
class AiTurnProgress:
    """The status of one assistant message and its steps with a label above a
    given value, read at one point in time. `get_turn_progress` returns it."""

    status: str
    steps: list[AiStep] = field(default_factory=list)


@dataclass
class AuthState:
    """A server-side one-time row for OIDC state, nonce and PKCE, SAML request
    ids and the SAML assertion-replay cache.

    `kind` is `oidc` for an OIDC login, `saml_request` for a pending SAML
    request and `saml_seen` for a used SAML assertion.
    """

    id: str
    provider_id: int
    kind: str
    payload: dict
    expires_at: datetime


# --- device inventory ------------
#
# The records of the inventory tables in app/inventory/tables.py. The repository
# (app/inventory/repository.py) is the only writer. It enforces revisions,
# immutability and redaction. The routes convert the records to the models of
# contracts.py. The field order is the column order of the table, and a row maps
# to its record by position.


@dataclass
class InventoryDevice:
    """One inventory device, the stable identity of a graph Device uid."""

    id: UUID
    graph_uid: str
    first_seen: datetime
    last_seen: datetime
    latest_snapshot_key: str | None
    hostname: str
    platform: str
    management_address: str
    lifecycle: str
    revision: int
    collection_state: str
    last_success_at: datetime | None
    resolved_site_id: int | None
    placement_state: str
    updated_at: datetime


@dataclass
class InventoryTarget:
    """A reference to one execution record. `source_key` stays when `source_id`
    is set to NULL. `host` is the exact host key of the legacy record."""

    id: UUID
    source_id: int | None
    source_key: str
    host: str
    kind: str
    legacy_device_id: int | None
    profile_id: UUID | None
    onboarding_site_id: int | None
    enabled: bool
    revision: int
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime

    endpoint_config: dict = field(default_factory=dict)


@dataclass
class InventoryObservation:
    target_id: UUID
    device_id: UUID
    reported_location_handle: UUID | None
    last_success_at: datetime | None
    last_seen_snapshot_key: str | None
    state: str
    authority: str
    notes: dict | None
    updated_at: datetime


@dataclass
class InventoryPlacement:
    """The placement intent of a device and the placement that the last publication applied."""

    device_id: UUID
    mode: str
    site_id: int | None
    origin: str
    revision: int
    actor_id: int | None
    updated_at: datetime
    applied_revision: int = 0
    published_site_id: int | None = None
    published_snapshot_key: str | None = None


@dataclass
class SourceInventory:
    """The inventory-facing columns of a `sources` row."""

    source_id: int
    name: str
    type: str
    enabled: bool
    display_name: str
    default_profile_id: UUID | None
    inventory_revision: int
    frozen_normalization: dict | None


@dataclass
class InventoryLocation:
    """A `reported_locations` row seen through its UUID handle."""

    handle: UUID
    source: str
    location_id: str
    name: str
    site: str | None
    revision: int
    updated_at: datetime


@dataclass
class CollectionCredential:
    id: UUID
    display_name: str
    current_revision: int
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass
class CollectionCredentialVersion:
    """An immutable version of a credential. `sealed` is ciphertext under the
    data key, and the repository has no method that decrypts it. `secret_paths`
    holds the paths of the stored secrets and no value."""

    credential_id: UUID
    revision: int
    sealed: bytes
    secret_paths: list[str]
    created_at: datetime
    actor_id: int | None


@dataclass
class CollectionProfile:
    id: UUID
    display_name: str
    collector_type: str
    current_revision: int
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass
class CollectionProfileVersion:
    """An immutable version of a profile. It holds the validated non-secret
    settings and the pinned credential version."""

    profile_id: UUID
    revision: int
    settings: dict
    credential_id: UUID | None
    credential_revision: int | None
    created_at: datetime
    actor_id: int | None


@dataclass
class ProfileReferences:
    """The targets and the sources that reference a profile. A refused delete returns them."""

    target_ids: list[UUID] = field(default_factory=list)
    source_ids: list[int] = field(default_factory=list)


@dataclass
class InventoryEvent:
    id: int
    entity_type: str
    entity_id: str
    actor_id: int | None
    action: str
    at: datetime
    before: dict | None
    after: dict | None
    request_id: str | None
    snapshot_key: str | None
    sensitive: bool = False


@dataclass
class InventorySavedView:
    id: UUID
    owner_id: int
    name: str
    filter_version: int
    filter: dict
    sort: str
    direction: str
    columns: list[str]
    revision: int
    created_at: datetime
    updated_at: datetime


@dataclass
class InventoryRoutingGroup:
    id: UUID
    display_name: str
    description: str
    revision: int
    archived_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass
class InventoryRoutingMember:
    group_id: UUID
    context_uid: str
    owner_uid: str
    added_at: datetime
    actor_id: int | None


@dataclass
class InventoryState:
    """The singleton activation row."""

    resolver_version: int
    schema_version: int
    backfill_version: int
    activation_state: str
    read_model_snapshot_key: str | None
    intent_generation: int
    inventory_sync_pending: bool
    updated_at: datetime


@dataclass
class InventoryPublication:
    snapshot_key: str
    parent_snapshot_key: str | None
    state: str
    intent_generation: int
    staged_changes: dict
    placement_revisions: dict
    created_at: datetime
    published_at: datetime | None
    applied_at: datetime | None


@dataclass
class StagedTarget:
    snapshot_key: str
    target_id: UUID
    authority: str
    succeeded: bool
    attempted_at: datetime


@dataclass
class StagedObservation:
    """One (target, graph device) fact of a run, before publication."""

    target_id: UUID
    graph_uid: str
    hostname: str = ""
    platform: str = ""
    management_address: str = ""
    reported_location_handle: UUID | None = None
    notes: dict | None = None


@dataclass
class PublicationApplyReport:
    """The changes that a publication applied to the read model."""

    snapshot_key: str
    registered_device_ids: list[UUID]
    reappeared_device_ids: list[UUID]
    missing_device_ids: list[UUID]
    observations_written: int
    observations_retired: int
    placements_applied: int


@dataclass
class OperationPreview:
    token: UUID
    actor_id: int
    operation: str
    permissions: list[str]
    intent_generation: int
    snapshot_key: str | None
    members: list[dict]
    changes: dict
    impact: dict
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    result_id: UUID | None
    # The sealed draft. Only the row that `consume_preview` returns holds it.
    secret_draft: bytes | None = None


@dataclass
class PreviewImpact:
    token: UUID
    seq: int
    kind: str
    entity_id: str
    detail: dict


@dataclass
class OperationResult:
    id: UUID
    actor_id: int
    idempotency_key: str
    request_digest: str
    status: int
    response: dict
    created_at: datetime


@dataclass
class OutboxItem:
    id: int
    dedup_key: str
    kind: str
    payload: dict
    state: str
    attempt: int
    max_attempts: int
    lease_expires_at: datetime | None
    claimed_by: str | None
    next_attempt_at: datetime
    last_error: str
    created_at: datetime
    updated_at: datetime


@dataclass
class DeviceListItem:
    """One row of the device list. It holds the device and its observing
    connections. One batched query reads the connections of a page."""

    device: InventoryDevice
    site_code: str | None
    connections: list[ObservingTarget]


@dataclass
class ObservingTarget:
    target_id: UUID
    source_id: int | None
    source_key: str
    display_name: str
    host: str
    state: str
    authority: str
    last_success_at: datetime | None


@dataclass
class DeviceFilters:
    """The validated list filters. An empty list means no restriction. An empty
    `lifecycles` hides archived devices."""

    q: str | None = None
    site_ids: list[int] = field(default_factory=list)
    source_ids: list[int] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    collection_states: list[str] = field(default_factory=list)
    placement_states: list[str] = field(default_factory=list)
    lifecycles: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "q": self.q,
            "site_ids": sorted(self.site_ids),
            "source_ids": sorted(self.source_ids),
            "platforms": sorted(self.platforms),
            "collection_states": sorted(self.collection_states),
            "placement_states": sorted(self.placement_states),
            "lifecycles": sorted(self.lifecycles),
        }


@dataclass
class DevicePageResult:
    items: list[DeviceListItem]
    next_cursor: str | None
    state: InventoryState


class Store(AssessmentStore, Protocol):
    async def ping(self) -> bool: ...
    async def get_user_by_username(self, username: str) -> User | None: ...
    async def get_user(self, user_id: int) -> User | None: ...
    async def list_users(self) -> list[User]: ...
    async def create_user(self, username: str, password_hash: str | None, role: str) -> User: ...
    async def create_first_user(self, username: str, password_hash: str, role: str) -> User: ...
    # A new `password_hash` and `disabled=True` delete the sessions and the
    # personal access tokens of the account.
    async def update_user(
        self,
        user_id: int,
        *,
        role: str | None = None,
        disabled: bool | None = None,
        password_hash: str | None = None,
        role_source: str | None = None,
    ) -> User | None: ...
    async def create_session(
        self, tok_hash: str, user_id: int, expires_at: datetime, now: datetime | None = None
    ) -> None: ...
    # `idle_after` is the idle expiry. A session whose last use is older than
    # `idle_after` does not authenticate, also before `expires_at`. None means
    # that only `expires_at` applies. The last use of a session of a disabled
    # account does not move forward.
    async def get_session_user(
        self, tok_hash: str, now: datetime, idle_after: timedelta | None = None
    ) -> User | None: ...
    # Creates the session of a login through the auth provider. Returns False and
    # creates no session when the provider does not exist or is disabled. The check and
    # the insert run in one transaction that holds a lock on the provider row.
    async def create_provider_session(
        self, tok_hash: str, user_id: int, provider_id: int, expires_at: datetime, now: datetime
    ) -> bool: ...
    async def delete_session(self, tok_hash: str) -> None: ...
    async def delete_user_sessions(self, user_id: int) -> int: ...
    # --- personal access tokens (the MCP HTTP transport) ------------------------------
    # Revokes every token of the user and returns how many. A password reset
    # (update_user) does the same in its own transaction.
    async def delete_user_access_tokens(self, user_id: int) -> int: ...
    async def create_access_token(
        self, tok_hash: str, user_id: int, name: str, scope: str, expires_at: datetime, now: datetime
    ) -> AccessToken: ...
    # The user's tokens, expired ones included, newest first.
    async def list_access_tokens(self, user_id: int) -> list[AccessToken]: ...
    # Revokes one of the user's tokens. False when the user has no token of that id.
    async def delete_access_token(self, user_id: int, token_id: int) -> bool: ...
    # The token of `tok_hash` and its user, or None when no token has the hash,
    # the token expired at or before `now`, or the user is an SSO account whose
    # newest SSO login is older than SSO_TOKEN_LOGIN_MAX_AGE. Moves
    # `last_used_at` forward, throttled to SESSION_TOUCH_INTERVAL as sessions are.
    async def get_access_token_user(
        self, tok_hash: str, now: datetime
    ) -> tuple[AccessToken, User] | None: ...
    async def start_run(
        self, source: str, started_at: datetime, triggered_by: int | None = None
    ) -> Run | None: ...
    async def finish_run(
        self,
        run_id: int,
        status: str,
        finished_at: datetime,
        detail: str,
        snapshot_key: str | None = None,
    ) -> None: ...
    async def list_runs(self, limit: int = 50) -> list[Run]: ...
    # One run by id, of any age. None when no row has this id.
    async def get_run(self, run_id: int) -> Run | None: ...
    async def list_sources(self) -> list[Source]: ...
    async def get_source(self, name: str) -> Source | None: ...
    async def create_source(
        self, name: str, type_: str, config: dict, secrets: bytes, enabled: bool = True
    ) -> Source: ...
    async def update_source(
        self,
        name: str,
        *,
        config: dict | None = None,
        secrets: bytes | None = None,
        enabled: bool | None = None,
    ) -> Source | None: ...
    # Locks the row, calls `change` with it and writes the config, the secrets
    # and the enabled flag of the row that `change` returns, in one transaction.
    # `change` runs under the row lock and does no I/O. It returns None to
    # write nothing. Returns the row after the write, or None when there is no
    # source `name`.
    async def modify_source(self, name: str, change: Callable[[Source], Source | None]) -> Source | None: ...
    async def delete_source(self, name: str) -> bool: ...
    # --- device fleets ---------------------
    # `source=None` lists every fleet, for the cycle's prepare step.
    async def list_devices(self, source: str | None = None) -> list[Device]: ...
    # Replaces the fleet with `specs`. A row is matched by (source, host), and a
    # row whose host is absent from `specs` is deleted. A kept row keeps its id,
    # created_at and host_key. Raises ValueError for an unknown source and for a
    # duplicate host within `specs`.
    async def replace_devices(self, source: str, specs: list[DeviceSpec]) -> list[Device]: ...
    # Writes the pin only while it is empty, as the pin of a source. Returns
    # False when the row is missing or already pinned.
    async def set_device_host_key(self, source: str, host: str, host_key: str) -> bool: ...
    # Clears the pin after a device replacement or an OS reinstall. The next
    # connection pins again. Returns False when the row is missing or not pinned.
    async def clear_device_host_key(self, source: str, host: str) -> bool: ...
    # Records the outcome of one collection attempt for (source, host) and
    # creates the row on the first call. last_attempt_at and updated_at advance
    # to `now` on every call. Raises ValueError for an unknown source.
    #
    # ok=True advances last_success_at, resets consecutive_failures to 0 and
    # clears last_error. A raw_sha, obs_sha, graph_sha or timing passed as None
    # leaves the stored value. full=True also advances last_full_at, and
    # last_graph_at when a graph_sha is given. graph_fetch_at, given with a
    # graph_sha, is the fetch time of the payload of that batch
    # (last_graph_fetch_at).
    #
    # ok=False increments consecutive_failures, sets last_error and clears
    # last_raw_sha and last_graph_sha. The next success of the device loads and
    # writes in full. A failing call ignores the hashes, the timings and `full`.
    #
    # `verified_at` and `verified_started_at`, on an ok call, are the window of a
    # fetch that found the device unchanged against `verified_raw_sha` and
    # `verified_obs_sha`. The window is recorded (last_verified_started_at,
    # last_verified_at) only when the stored last_raw_sha and last_obs_sha equal
    # them, the call moves neither hash, the window ends at or after its start,
    # and it ends after last_graph_fetch_at. A call that moves raw_sha or
    # obs_sha and every failing call clear both columns. Any other call leaves
    # them.
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
    ) -> DeviceStatus: ...
    # Records the result of a device run for the graph of (source, host).
    # `graph_sha` is the digest of the batch that its payload normalized to.
    # `fetch_at` is the fetch time of that payload (last_graph_fetch_at).
    # `written` advances last_graph_at. An empty `graph_sha` means that the load
    # failed. It clears last_graph_sha, last_raw_sha, last_verified_started_at
    # and last_verified_at, as a failed attempt does. The call changes only
    # those columns and updated_at. Returns False when there is no row to update.
    async def record_device_graph(
        self,
        source: str,
        host: str,
        *,
        now: datetime,
        graph_sha: str,
        written: bool,
        fetch_at: datetime | None = None,
    ) -> bool: ...
    # Records the skip basis of a payload that a device run loaded into the
    # graph. The basis is `raw_sha` (last_raw_sha), `obs_sha` (last_obs_sha) and,
    # with `full`, last_full_at = `now`. A hash passed as None leaves the stored
    # value. A hash that changes clears the last check. The attempt columns stay,
    # and updated_at advances. Returns False when there is no row to update.
    async def record_device_basis(
        self,
        source: str,
        host: str,
        *,
        now: datetime,
        raw_sha: str | None = None,
        obs_sha: str | None = None,
        full: bool = False,
    ) -> bool: ...
    # `source=None` lists every device's status, ordered by (source, host).
    async def list_device_status(self, source: str | None = None) -> list[DeviceStatus]: ...
    async def running_run(self, source: str) -> Run | None: ...
    # Every row with the status 'running', oldest first.
    async def running_runs(self) -> list[Run]: ...
    async def reconcile_orphaned_runs(self, now: datetime) -> int: ...
    async def purge_expired_sessions(self, now: datetime, idle_after: timedelta | None = None) -> int: ...
    # Excludes every other run in every process that shares the database while
    # the caller holds the lock. A "cycle" run and a "vyos" run are 2 sources of
    # the per-source run claim, and both move the cycle pointer. The call blocks.
    #
    # Yields a fence, a value that increases with every acquisition. The holder
    # passes it to the graph, and the cycle pointer refuses a write with a lower
    # fence (core/cycle.py `set_pointer`). `on_lost` is called when the lock is
    # lost while the block runs. A holder that works on a worker thread stops
    # that work in `on_lost`.
    def cycle_lock(self, on_lost: Callable[[], None] | None = None) -> AbstractAsyncContextManager[int]: ...
    # Takes the same lock without waiting. Yields True when the caller holds it
    # and False when another holder does. A run that an operator asked for does
    # not use it.
    def try_cycle_lock(self) -> AbstractAsyncContextManager[bool]: ...
    # Holds the lease of a reader on one or more graph runs. The scheduled graph
    # prune keeps every run with an unexpired lease. The lease ends with the
    # block, or after `ttl_s` seconds when the reader dies.
    def lease_run(
        self, cts: int | Iterable[int], ttl_s: float = 600.0
    ) -> AbstractAsyncContextManager[None]: ...
    # The run keys with an unexpired lease.
    async def leased_runs(self) -> set[int]: ...
    # The lock of the leader election of the scheduler. It has its own key in
    # the single-bigint advisory keyspace of CYCLE_LOCK. The lock is held while
    # the block runs, and a leader that dies releases it with its connection.
    # The call does not block. `on_lost` is called when the lock is lost while
    # the block runs.
    def try_scheduler_lock(
        self, on_lost: Callable[[], None] | None = None
    ) -> AbstractAsyncContextManager[bool]: ...
    # --- job queue (worker/queue.py holds the policy) -------------------------
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
    ) -> Job | None: ...
    # Claims at most `batch` due jobs for `worker_id` in one statement. A claimed
    # job is 'running', its attempt is incremented and its lease is now +
    # `lease`. 2 claimants do not get the same row (SELECT ... FOR UPDATE SKIP
    # LOCKED in Postgres). A queued job of a kind in `skip_kinds` is left for a
    # later claim.
    async def claim_jobs(
        self,
        worker_id: str,
        batch: int,
        now: datetime,
        lease: timedelta,
        *,
        skip_kinds: Collection[str] = (),
    ) -> list[Job]: ...
    # Returns the ids extended. The worker cancels the work of an id that did not come back.
    async def heartbeat_jobs(
        self, job_ids: list[int], worker_id: str, now: datetime, lease: timedelta
    ) -> list[int]: ...
    # With `retry_at`, the attempt failed and the next one is due at that time.
    # The row returns to 'queued', and `detail` holds the failure. Without
    # `retry_at`, `state` is terminal ('ok', 'error' or 'dead') and `finished_at`
    # is set. `claimed_by` and `attempt` limit the write to one attempt. A job
    # that was reaped and claimed again is 'running' under another attempt.
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
    ) -> Job | None: ...
    # A lapsed claim goes back to 'queued', or to 'dead' once its attempts are
    # used. A requeued row whose kind is in `backoff_kinds` is due at
    # `now + min(backoff_cap_s, backoff_base_s * 2 ** max(0, attempt - 1))`
    # seconds, as worker/queue.py `backoff` computes for a failed attempt. A row
    # of another kind is due at `now`. Returns the number of rows reaped.
    async def reap_jobs(
        self,
        now: datetime,
        *,
        backoff_kinds: Collection[str] = (),
        backoff_base_s: float = 60.0,
        backoff_cap_s: float = 1800.0,
    ) -> int: ...
    async def job_depth(self) -> dict[str, int]: ...
    async def get_job(self, job_id: int) -> Job | None: ...
    async def list_jobs(self, limit: int = 50) -> list[Job]: ...
    # Every job of `kind` in a pending state (`JOB_PENDING_STATES`), oldest
    # first. The `one_pending_per_kind` index holds at most one job per (kind,
    # source, device), and the Postgres query reads that index.
    async def pending_jobs(self, kind: str) -> list[Job]: ...
    async def purge_jobs(self, before: datetime) -> int: ...
    # --- changes -----------------------
    async def list_changes(self) -> list[Change]: ...
    async def get_change(self, change_id: int) -> Change | None: ...
    async def list_change_intents(self, change_id: int) -> list[ChangeIntent]: ...
    # `intents` is `[(kind, params), ...]` in the order to store them at.
    async def create_change(
        self,
        *,
        title: str,
        description: str,
        snapshot_cts: int | None,
        created_by: int | None,
        intents: list[tuple[str, dict]],
    ) -> tuple[Change, list[ChangeIntent]]: ...
    # Every keyword defaults to the sentinel `UNSET`. A keyword at `UNSET` keeps
    # the stored value. `snapshot_cts` accepts None. `intents` replaces the whole
    # stored list in the transaction of the update, and `[]` stores an empty
    # list. Returns None for an unknown change_id.
    async def update_change(
        self,
        change_id: int,
        *,
        title: str | object = UNSET,
        description: str | object = UNSET,
        snapshot_cts: int | object | None = UNSET,
        status: str | object = UNSET,
        intents: list[tuple[str, dict]] | object = UNSET,
    ) -> tuple[Change, list[ChangeIntent]] | None: ...
    async def delete_change(self, change_id: int) -> bool: ...
    async def list_sites(self) -> list[Site]: ...
    async def get_site(self, code: str) -> Site | None: ...
    async def create_site(self, code: str, name: str, location: str, params: dict | None = None) -> Site: ...
    # `change_params` maps the stored params to the params to write. It runs
    # under the row lock in the transaction of the write and does no I/O. It
    # takes precedence over `params`.
    async def update_site(
        self,
        code: str,
        *,
        name: str | None = None,
        location: str | None = None,
        params: dict | None = None,
        change_params: Callable[[dict], dict] | None = None,
    ) -> Site | None: ...
    # Deletes the site and returns its SiteRelease, or None when there is no
    # such site. It never refuses. See PgStore.delete_site.
    async def delete_site(self, code: str) -> SiteRelease | None: ...
    async def site_members(self, code: str) -> list[str]: ...
    async def assign_device(self, device_uid: str, code: str | None) -> bool: ...
    async def device_sites(self) -> dict[str, str]: ...
    async def record_target_devices(
        self, source: str, host: str, device_uids: list[str], locations: dict[str, tuple[str, str]]
    ) -> None: ...
    async def target_devices(self, source: str | None = None) -> list[TargetDevice]: ...
    # The device identity registry. `kind` is
    # `serial` or `ref`. `resolve_device` mints a uid the first time that it
    # sees an identifier. `rekey_device` raises LookupError for an unknown old
    # uid and ValueError for a taken new uid. With `merge` the new uid must be
    # taken, and LookupError is raised when it is not. Both forms move the hand
    # placement and the observed target devices of the old uid to the new one.
    async def resolve_device(
        self, kind: str, value: str, hostname: str | None, run_id: int | None
    ) -> str: ...
    async def bind_device(self, uid: str, kind: str, value: str, run_id: int | None) -> None: ...
    async def rekey_device(self, old_uid: str, new_uid: str, *, merge: bool = False) -> int: ...
    async def identity_generation(self) -> int: ...
    async def device_identities(self) -> list[DeviceIdentity]: ...
    async def device_identity_report(self) -> list[DeviceIdentityReport]: ...
    async def list_reported_locations(self, source: str | None = None) -> list[ReportedLocation]: ...
    async def bind_location(self, source: str, location_id: str, site: str | None) -> bool: ...
    async def replace_geo_places(self, places: Iterable[GeoPlace]) -> int: ...
    async def search_geo_places(self, name: str, postal: str, limit: int) -> GeoPlaceSearch: ...
    async def get_setting(self, key: str) -> AppSetting | None: ...
    async def put_setting(self, key: str, value: dict, secrets: bytes) -> AppSetting: ...
    # Locks the setting `key`, calls `change` with the stored row or None and
    # writes the value and the secrets that `change` returns, in one
    # transaction. `change` runs under the lock and does no I/O. It returns
    # None to write nothing. Returns the row after the write, or the stored row
    # when `change` returns None.
    async def modify_setting(
        self, key: str, change: Callable[[AppSetting | None], tuple[dict, bytes] | None]
    ) -> AppSetting | None: ...
    async def list_auth_providers(self) -> list[AuthProvider]: ...
    async def get_auth_provider(self, name: str) -> AuthProvider | None: ...
    async def create_auth_provider(
        self, name: str, kind: str, config: dict, secrets: bytes | None, enabled: bool = False
    ) -> AuthProvider: ...
    # An update that changes `enabled` from true to false deletes the sessions
    # and the personal access tokens of each user that has an identity at the
    # provider, in the transaction of the update. The identities and the user
    # accounts stay. None when no provider has the name.
    async def update_auth_provider(
        self,
        name: str,
        *,
        config: dict | None = None,
        secrets: bytes | None = None,
        enabled: bool | None = None,
    ) -> AuthProvider | None: ...
    # Deletes the provider, and the sessions and the personal access tokens of
    # each user that has an identity at the provider, in one transaction. The
    # user accounts stay. False when no provider has the name.
    async def delete_auth_provider(self, name: str) -> bool: ...
    async def get_identity(self, provider_id: int, subject: str) -> Identity | None: ...
    # Raises ValueError when the provider has an identity of the subject, and
    # IdentityOwnerMissing when the user or the provider does not exist.
    async def create_identity(
        self, user_id: int, provider_id: int, subject: str, email: str = ""
    ) -> Identity: ...
    # Creates an account without a password and its identity in one
    # transaction. Raises ValueError when the username is taken or the provider
    # has an identity of the subject, and IdentityOwnerMissing when the
    # provider does not exist. No account is created when the call raises.
    async def create_user_with_identity(
        self, username: str, role: str, provider_id: int, subject: str, email: str = ""
    ) -> tuple[User, Identity]: ...
    async def touch_last_login(self, identity_id: int, when: datetime) -> None: ...
    async def list_identities_for_users(self, user_ids: list[int]) -> list[Identity]: ...
    async def list_group_mappings(self, provider_id: int) -> list[GroupMapping]: ...
    async def put_group_mapping(self, provider_id: int, group_name: str, role: str) -> GroupMapping: ...
    async def delete_group_mapping(self, provider_id: int, group_name: str) -> bool: ...
    async def create_auth_state(
        self, id: str, provider_id: int, kind: str, payload: dict, expires_at: datetime
    ) -> AuthState: ...
    # Deletes and returns the unexpired row of that id, kind and provider. None,
    # and no delete, when no row matches all 3.
    async def consume_auth_state(
        self, id: str, kind: str, provider_id: int, now: datetime
    ) -> AuthState | None: ...
    async def purge_expired_auth_state(self, now: datetime) -> int: ...
    async def record_login_event(
        self, username: str, user_id: int | None, provider: str, outcome: str, source: str, at: datetime
    ) -> LoginEvent: ...
    async def list_login_events(self, limit: int = 200) -> list[LoginEvent]: ...
    async def purge_login_events(self, before: datetime) -> int: ...
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
    ) -> CypherEvent: ...
    async def list_cypher_events(self, limit: int = 200) -> list[CypherEvent]: ...
    async def purge_cypher_events(self, before: datetime) -> int: ...
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
    ) -> EvidenceExport: ...
    async def list_evidence_exports(self, limit: int = 200) -> list[EvidenceExport]: ...
    # --- network map layouts and views --------------
    async def get_network_map_layout(self, scope: str) -> NetworkMapLayout | None: ...
    # `expected_revision` 0 creates the row. Another value must equal the
    # revision of the row, else StaleMapRevision is raised.
    async def save_network_map_layout(
        self, scope: str, positions: dict, *, expected_revision: int, user_id: int | None, now: datetime
    ) -> NetworkMapLayout: ...
    # False when there is no row. Raises StaleMapRevision when the revision differs.
    async def delete_network_map_layout(self, scope: str, *, expected_revision: int) -> bool: ...
    async def list_network_map_views(self) -> list[NetworkMapView]: ...
    # Raises MapViewNameTaken.
    async def create_network_map_view(
        self, name: str, state: dict, *, owner_id: int | None, now: datetime
    ) -> NetworkMapView: ...
    # None when there is no such view. Raises StaleMapRevision or MapViewNameTaken.
    async def update_network_map_view(
        self,
        view_id: UUID,
        *,
        expected_revision: int,
        now: datetime,
        name: str | None = None,
        state: dict | None = None,
    ) -> NetworkMapView | None: ...
    async def delete_network_map_view(self, view_id: UUID, *, expected_revision: int) -> bool: ...
    # --- AI audit trail ---------------------------------------------------------------
    async def record_ai_event(self, event: AiEvent) -> AiEvent: ...
    async def list_ai_events(self, limit: int = 200) -> list[AiEvent]: ...
    async def purge_ai_events(self, before: datetime) -> int: ...
    # Token sums per UTC day and user over events at or after `since`, newest
    # day first, then by user id with no user last.
    async def ai_token_usage(self, since: datetime) -> list[AiTokenUsage]: ...
    # Stores the text of one prompt hash once. True when this call wrote the row.
    async def put_prompt_version(self, prompt_hash: str, content: str, at: datetime) -> bool: ...
    # --- AI conversations -------------------------------------------------------------
    # Every read and user action is scoped to the owner. The id of a conversation
    # of another user, or an id that is not a UUID, is treated as a missing id.
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
    ) -> AiConversation: ...
    async def get_conversation(self, user_id: int, conversation_id: str) -> AiConversation | None: ...
    # The owner's non-ephemeral conversations, most recent message first. With
    # `link_kind` and `link_id`, only conversations with such an `ai_links` row.
    # A conversation without a title gets the first LIST_TITLE_CHARS characters
    # of its first question as `title`. `last_run` is the run of its newest
    # answer that has one.
    async def list_conversations(
        self,
        user_id: int,
        *,
        surface: str | None = None,
        link_kind: str | None = None,
        link_id: str | None = None,
        limit: int = 50,
    ) -> list[AiConversation]: ...
    async def delete_conversation(self, user_id: int, conversation_id: str) -> bool: ...
    # Runs in one transaction under a per-user advisory lock. It counts the user's
    # active assistant rows against `per_user_cap`, then every active row
    # against `global_cap`, and raises TurnCapExceeded at either cap. It then
    # inserts the user message and a 'pending' assistant message and returns
    # the assistant message. With `conversation_id` None it first creates an
    # ephemeral conversation of `surface`. None when the conversation is not
    # the user's.
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
    ) -> AiMessage | None: ...
    # Moves a 'pending' assistant message to 'running' with a lease for
    # `owner`. False when the row is not pending.
    async def claim_turn(self, message_id: str, owner: str, lease_s: float, now: datetime) -> bool: ...
    # Extends the lease of a 'running' message `owner` holds. False when the
    # row is no longer running under that owner.
    async def heartbeat_turn(self, message_id: str, owner: str, lease_s: float, now: datetime) -> bool: ...
    # Stores one tool call of the message's turn under the conversation's next
    # step label. The digest and length of `result` are computed here. Raises
    # KeyError when the message does not exist.
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
    ) -> AiStep: ...
    # Ends a 'running' turn `owner` holds with one of TURN_FINAL_STATES, clears
    # `lease_expires_at` and keeps `lease_owner`. False when the row is not
    # running under that owner, for example after the sweeper marked it
    # 'interrupted'. A `prompt_hash` must already be in `ai_prompt_versions`.
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
    ) -> bool: ...
    # Stores `context` on the user message that assistant message `message_id`
    # answers. False when no such message exists.
    async def set_question_context(self, message_id: str, context: dict[str, Any]) -> bool: ...
    # Sets `cancel_requested` on the owner's active assistant message.
    async def request_cancel(self, user_id: int, message_id: str) -> bool: ...
    # One message of the user's conversations, without its steps. With
    # `surface`, None unless the conversation is of that surface.
    async def get_message(
        self, user_id: int, message_id: str, *, surface: str | None = None
    ) -> AiMessage | None: ...
    # One assistant message of the user's conversations with the user message
    # before it and its steps. None when the id is missing or foreign, or is
    # the id of a user message.
    async def get_turn(self, user_id: int, message_id: str) -> AiTurn | None: ...
    # The status of the same assistant message and its steps with a label
    # above `after`, by label, read in one snapshot. None when `get_turn`
    # returns None.
    async def get_turn_progress(self, user_id: int, message_id: str, after: int) -> AiTurnProgress | None: ...
    # One step of the user's conversations, with its result.
    async def get_step(self, user_id: int, step_id: str) -> AiStep | None: ...
    # Stores the rolling summary of the turns up to message seq `through`.
    # False when the conversation is not the user's, or its stored summary
    # already covers `through`.
    async def set_summary(self, user_id: int, conversation_id: str, summary: str, through: int) -> bool: ...
    # Marks as 'interrupted' every active row whose lease has passed, and every
    # 'pending' row with no lease created more than `pending_grace_s` before
    # `now`. Steps are kept. Returns the number of rows marked.
    async def expire_stale_turns(self, now: datetime, pending_grace_s: float = 60.0) -> int: ...
    # Stores one link of the conversation. None when an id is not a UUID, the
    # conversation does not exist, or the message or the step is not one of
    # that conversation.
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
    ) -> AiLink | None: ...
    # Sets `result` to NULL and `compacted_at` to `at` on steps started before
    # `before`. `result_sha256`, `result_chars` and `result_summary` stay.
    async def compact_steps(self, before: datetime, at: datetime) -> int: ...
    # Deletes conversations whose last message is older than `before`, with
    # their messages, steps and links.
    async def purge_conversations(self, before: datetime) -> int: ...
    # The same for ephemeral conversations only.
    async def purge_ephemeral(self, before: datetime) -> int: ...
    # --- device inventory (app/inventory/repository.py) ------------------------
    # The transactional repository on the same engine. Every inventory write
    # goes through `repository.transaction()`. The transaction exposes its
    # connection, and a service updates a legacy execution record through it.
    def inventory(self) -> InventoryRepository: ...
    async def dispose(self) -> None: ...


async def live_run(store: Store, source: str) -> Run | None:
    """Return the run of `source` that a process is executing, or None.

    A 'running' row whose claim no process holds has no run. The orphaned-run
    sweep (`reconcile_orphaned_runs`) runs when a 'running' row is found, and
    the row is read again when the sweep changed a row. The sweep takes a claim
    only where no process holds one.
    """
    run = await store.running_run(source)
    if run is not None and await store.reconcile_orphaned_runs(datetime.now(UTC)):
        run = await store.running_run(source)
    return run
