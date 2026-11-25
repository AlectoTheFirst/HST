"""In-memory Store: mirrors PgStore semantics so route tests need no Postgres."""

from __future__ import annotations

import asyncio
import copy
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

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
    AuthProvider,
    AuthState,
    Change,
    ChangeIntent,
    CypherEvent,
    Device,
    DeviceIdentity,
    DeviceStatus,
    EvidenceExport,
    GroupMapping,
    Identity,
    IdentityOwnerMissing,
    Job,
    LoginEvent,
    MapViewNameTaken,
    NetworkMapLayout,
    NetworkMapView,
    Run,
    SiteRelease,
    Source,
    StaleMapRevision,
    TurnCapExceeded,
    User,
    canonical_uuid,
    identity_report,
    step_digest,
)
from hst.core import uid as uidmod
from hst.core.identity import identifier, legacy_uid, mint_for


def _checked(
    row,
    existing,
    raw_sha,
    obs_sha,
    verified_started_at=None,
    verified_at=None,
    verified_raw_sha=None,
    verified_obs_sha=None,
):
    """`row` with the last check as PgStore writes it (`pg._check_columns`),
    every term read from `existing`, the row before the write."""
    moved = (raw_sha is not None and existing.last_raw_sha != raw_sha) or (
        obs_sha is not None and existing.last_obs_sha != obs_sha
    )
    offered = (
        verified_at is not None
        and verified_raw_sha is not None
        and verified_obs_sha is not None
        and (verified_started_at is None or verified_started_at <= verified_at)
    )
    if (
        offered
        and not moved
        and existing.last_raw_sha == verified_raw_sha
        and existing.last_obs_sha == verified_obs_sha
        and (existing.last_graph_fetch_at is None or existing.last_graph_fetch_at < verified_at)
    ):
        return replace(row, last_verified_started_at=verified_started_at, last_verified_at=verified_at)
    if moved:
        return replace(row, last_verified_started_at=None, last_verified_at=None)
    return replace(
        row,
        last_verified_started_at=existing.last_verified_started_at,
        last_verified_at=existing.last_verified_at,
    )


class FakeStore:
    def __init__(self) -> None:
        self.users: dict[int, User] = {}
        # token -> (user_id, expires_at, last_used_at)
        self.sessions: dict[str, tuple[int, datetime, datetime]] = {}
        # token hash -> AccessToken
        self.access_tokens: dict[str, AccessToken] = {}
        self._atid = 0
        self.runs: dict[int, Run] = {}
        self.sources: dict[str, Source] = {}
        # (source, host) -> Device; deleting a source cascades, as the FK does
        self.devices: dict[tuple[str, str], Device] = {}
        self._did = 0
        # (source, host) -> DeviceStatus; deleting a source cascades, as the FK does
        self.device_status: dict[tuple[str, str], DeviceStatus] = {}
        self._dsid = 0
        self.settings_rows: dict[str, object] = {}
        self.changes: dict[int, Change] = {}
        self._chid = 0
        self.change_intents: dict[int, ChangeIntent] = {}
        self._ciid = 0
        self.sites_rows: dict[str, dict] = {}
        self.members: dict[str, str] = {}
        self.target_uid_rows: dict[tuple[str, str], set[str]] = {}
        self.target_places: dict[tuple[str, str], dict[str, str]] = {}
        self.locations: dict[tuple[str, str], dict] = {}
        self.auth_providers: dict[int, AuthProvider] = {}
        self.identities: dict[int, Identity] = {}
        self.group_mappings: dict[int, GroupMapping] = {}
        self.auth_state: dict[str, AuthState] = {}
        self.login_events: list[LoginEvent] = []
        self.cypher_events: list[CypherEvent] = []
        self.evidence_exports: list[EvidenceExport] = []
        self.map_layouts: dict[str, NetworkMapLayout] = {}
        self.map_views: dict[uuid.UUID, NetworkMapView] = {}
        self._eeid = 0
        self.ai_events: list[AiEvent] = []
        self.prompt_versions: dict[str, tuple[str, datetime]] = {}
        self._aeid = 0
        # The conversation tables. Conversations are stored without their
        # children; deleting one removes its messages, steps and links, as the
        # foreign keys do.
        self.ai_conversations: dict[str, AiConversation] = {}
        self.ai_messages: dict[str, AiMessage] = {}
        self.ai_steps: dict[str, AiStep] = {}
        self.ai_links: list[AiLink] = []
        self._alid = 0
        self._cycle_lock = asyncio.Lock()
        self._run_leases: dict[str, tuple[int, datetime]] = {}
        # one value per acquisition of the cycle lock
        self._fence = 0
        # PgStore's SCHEDULER_LOCK: whoever holds it leads. A test simulates a
        # peer leader by taking it before the scheduler starts.
        self._scheduler_lock = asyncio.Lock()
        self.jobs: dict[int, Job] = {}
        self._jid = 0
        # sources with a live claim
        self._claims: set[str] = set()
        self._uid = self._rid = 0
        self._sid = 0
        self._pid = self._iid = self._gid = 0
        self._leid = self._ceid = 0
        # The device identity registry: (kind, value) -> its row, and the
        # generation that the rename increments.
        self.identity_rows: dict[tuple[str, str], DeviceIdentity] = {}
        self.identity_gen = 0

    def crash(self) -> None:
        self._claims.clear()

    async def ping(self) -> bool:
        return True

    async def get_user_by_username(self, username):
        return next((u for u in self.users.values() if u.username == username), None)

    async def get_user(self, user_id):
        return self.users.get(user_id)

    async def list_users(self):
        return sorted(self.users.values(), key=lambda u: u.username)

    async def create_user(self, username, password_hash, role):
        if await self.get_user_by_username(username):
            raise ValueError(f"username {username!r} exists")
        self._uid += 1
        u = User(self._uid, username, password_hash, role, False, datetime.now(UTC))
        self.users[u.id] = u
        return u

    async def create_first_user(self, username, password_hash, role):
        if self.users:
            raise ValueError("an account already exists")
        return await self.create_user(username, password_hash, role)

    async def update_user(self, user_id, *, role=None, disabled=None, password_hash=None, role_source=None):
        u = self.users.get(user_id)
        if u is None:
            return None
        if role is not None:
            u = replace(u, role=role)
        if disabled is not None:
            u = replace(u, disabled=disabled)
        if password_hash is not None:
            u = replace(u, password_hash=password_hash)
        if password_hash is not None or disabled is True:
            # a reset and a disable revoke the account's sessions and tokens, mirroring PgStore
            await self.delete_user_sessions(user_id)
            await self.delete_user_access_tokens(user_id)
        if role_source is not None:
            u = replace(u, role_source=role_source)
        self.users[user_id] = u
        return u

    async def set_user_theme(self, user_id, theme):
        u = self.users.get(user_id)
        if u is None:
            return None
        u = replace(u, theme=theme)
        self.users[user_id] = u
        return u

    async def create_session(self, tok_hash, user_id, expires_at, now=None):
        self.sessions[tok_hash] = (user_id, expires_at, now or datetime.now(UTC))

    async def create_provider_session(self, tok_hash, user_id, provider_id, expires_at, now):
        provider = self.auth_providers.get(provider_id)
        if provider is None or not provider.enabled:
            return False
        self.sessions[tok_hash] = (user_id, expires_at, now)
        return True

    async def get_session_user(self, tok_hash, now, idle_after=None):
        row = self.sessions.get(tok_hash)
        if row is None:
            return None
        user_id, expires_at, last_used_at = row
        if expires_at <= now or (idle_after is not None and last_used_at <= now - idle_after):
            del self.sessions[tok_hash]
            return None
        user = self.users.get(user_id)
        # throttled forward-write, mirroring PgStore: only past the interval,
        # and never for a disabled account
        if not (user is not None and user.disabled) and last_used_at <= now - SESSION_TOUCH_INTERVAL:
            self.sessions[tok_hash] = (user_id, expires_at, now)
        return user

    async def delete_session(self, tok_hash):
        self.sessions.pop(tok_hash, None)

    async def delete_user_sessions(self, user_id):
        doomed = [t for t, (uid, _, _) in self.sessions.items() if uid == user_id]
        for tok in doomed:
            del self.sessions[tok]
        return len(doomed)

    # --- personal access tokens, keyed by hash as PgStore's unique column is ---
    async def create_access_token(self, tok_hash, user_id, name, scope, expires_at, now):
        if tok_hash in self.access_tokens:
            raise ValueError("duplicate token hash")
        self._atid += 1
        token = AccessToken(self._atid, user_id, name, scope, now, expires_at)
        self.access_tokens[tok_hash] = token
        return replace(token)

    async def list_access_tokens(self, user_id):
        mine = [t for t in self.access_tokens.values() if t.user_id == user_id]
        return [replace(t) for t in sorted(mine, key=lambda t: (t.created_at, t.id), reverse=True)]

    async def delete_access_token(self, user_id, token_id):
        doomed = [h for h, t in self.access_tokens.items() if t.id == token_id and t.user_id == user_id]
        for tok_hash in doomed:
            del self.access_tokens[tok_hash]
        return bool(doomed)

    async def delete_user_access_tokens(self, user_id):
        doomed = [h for h, t in self.access_tokens.items() if t.user_id == user_id]
        for tok_hash in doomed:
            del self.access_tokens[tok_hash]
        return len(doomed)

    async def get_access_token_user(self, tok_hash, now):
        token = self.access_tokens.get(tok_hash)
        if token is None or token.expires_at <= now:
            return None
        if token.last_used_at is None or token.last_used_at <= now - SESSION_TOUCH_INTERVAL:
            token.last_used_at = now
        user = self.users.get(token.user_id)
        # an SSO account's token needs a recent SSO login, mirroring PgStore
        logins = [i.last_login_at for i in self.identities.values() if i.user_id == token.user_id]
        if logins and all(t is None or t <= now - SSO_TOKEN_LOGIN_MAX_AGE for t in logins):
            return None
        return (replace(token), user) if user is not None else None

    async def start_run(self, source, started_at, triggered_by=None):
        if source in self._claims:
            return None
        self._claims.add(source)
        # the claim was free, so a 'running' row of the source is orphaned
        for rid, r in list(self.runs.items()):
            if r.source == source and r.status == "running":
                self.runs[rid] = replace(
                    r, status="error", finished_at=started_at, detail="orphaned by crash"
                )
        self._rid += 1
        r = Run(self._rid, source, "running", started_at, None, "", triggered_by)
        self.runs[r.id] = r
        return r

    async def finish_run(self, run_id, status, finished_at, detail, snapshot_key=None):
        r = self.runs[run_id]
        # compare-and-set: a row reconciled by a later claimant is never resurrected
        if r.status == "running":
            self.runs[run_id] = replace(
                r,
                status=status,
                finished_at=finished_at,
                detail=detail,
                snapshot_key=snapshot_key,
            )
        self._claims.discard(r.source)

    async def list_runs(self, limit=50):
        return sorted(self.runs.values(), key=lambda r: r.id, reverse=True)[:limit]

    async def get_run(self, run_id):
        return self.runs.get(run_id)

    async def list_sources(self):
        return sorted(self.sources.values(), key=lambda s: s.name)

    async def get_source(self, name):
        return self.sources.get(name)

    async def create_source(self, name, type_, config, secrets, enabled=True):
        if name in self.sources:
            raise ValueError(f"source {name!r} exists")
        self._sid += 1
        now = datetime.now(UTC)
        s = Source(self._sid, name, type_, config, secrets, enabled, now, now)
        self.sources[name] = s
        return s

    async def update_source(self, name, *, config=None, secrets=None, enabled=None):
        s = self.sources.get(name)
        if s is None:
            return None
        if config is not None:
            s = replace(s, config=config)
        if secrets is not None:
            s = replace(s, secrets=secrets)
        if enabled is not None:
            s = replace(s, enabled=enabled)
        s = replace(s, updated_at=datetime.now(UTC))
        self.sources[name] = s
        return s

    async def modify_source(self, name, change):
        s = self.sources.get(name)
        if s is None:
            return None
        new = change(copy.deepcopy(s))
        if new is None:
            return s
        return await self.update_source(name, config=new.config, secrets=new.secrets, enabled=new.enabled)

    async def delete_source(self, name):
        for key in [k for k in self.devices if k[0] == name]:
            del self.devices[key]
        for key in [k for k in self.device_status if k[0] == name]:
            del self.device_status[key]
        return self.sources.pop(name, None) is not None

    async def list_devices(self, source=None):
        rows = [d for d in self.devices.values() if source is None or d.source == source]
        return sorted(rows, key=lambda d: (d.source, d.host))

    async def replace_devices(self, source, specs):
        if source not in self.sources:
            raise ValueError(f"no source {source!r}")
        hosts = [s.host for s in specs]
        if len(set(hosts)) != len(hosts):
            raise ValueError("duplicate host in device list")
        now = datetime.now(UTC)
        for key in [k for k in self.devices if k[0] == source and k[1] not in hosts]:
            del self.devices[key]
        # a host that leaves the fleet takes its observations with it, as PgStore does
        for table in (self.target_uid_rows, self.target_places, self.device_status):
            for key in [k for k in table if k[0] == source and k[1] not in hosts]:
                del table[key]
        for spec in specs:
            existing = self.devices.get((source, spec.host))
            if existing is None:
                self._did += 1
                self.devices[(source, spec.host)] = Device(
                    self._did,
                    source,
                    spec.host,
                    spec.port,
                    spec.enabled,
                    "",
                    now,
                    now,
                )
            else:
                # id, created_at and host_key survive, as PgStore's upsert keeps them
                self.devices[(source, spec.host)] = replace(
                    existing,
                    port=spec.port,
                    enabled=spec.enabled,
                    updated_at=now,
                )
        return await self.list_devices(source)

    async def set_device_host_key(self, source, host, host_key):
        d = self.devices.get((source, host))
        if d is None or d.host_key:
            return False
        self.devices[(source, host)] = replace(d, host_key=host_key, updated_at=datetime.now(UTC))
        return True

    async def clear_device_host_key(self, source, host):
        d = self.devices.get((source, host))
        if d is None or not d.host_key:
            return False
        self.devices[(source, host)] = replace(d, host_key="", updated_at=datetime.now(UTC))
        return True

    async def upsert_device_status(
        self,
        source,
        host,
        *,
        now,
        ok,
        raw_sha=None,
        obs_sha=None,
        graph_sha=None,
        graph_fetch_at=None,
        full=False,
        error="",
        fetch_ms=None,
        normalize_ms=None,
        load_ms=None,
        verified_started_at=None,
        verified_at=None,
        verified_raw_sha=None,
        verified_obs_sha=None,
    ):
        if source not in self.sources:
            raise ValueError(f"no source {source!r}")
        existing = self.device_status.get((source, host))
        first = existing is None
        if existing is None:
            self._dsid += 1
            existing = DeviceStatus(
                id=self._dsid,
                source=source,
                host=host,
                last_raw_sha="",
                last_obs_sha="",
                last_attempt_at=None,
                last_success_at=None,
                last_full_at=None,
                consecutive_failures=0,
                last_error="",
                fetch_ms=None,
                normalize_ms=None,
                load_ms=None,
                updated_at=now,
            )
        if ok:
            row = replace(
                existing,
                last_attempt_at=now,
                updated_at=now,
                last_success_at=now,
                last_full_at=now if full else existing.last_full_at,
                last_raw_sha=raw_sha if raw_sha is not None else existing.last_raw_sha,
                last_obs_sha=obs_sha if obs_sha is not None else existing.last_obs_sha,
                last_graph_sha=graph_sha if graph_sha is not None else existing.last_graph_sha,
                # the batch a full load digests was written
                last_graph_at=now if full and graph_sha is not None else existing.last_graph_at,
                last_graph_fetch_at=(
                    graph_fetch_at
                    if graph_sha is not None and graph_fetch_at is not None
                    else existing.last_graph_fetch_at
                ),
                consecutive_failures=0,
                last_error="",
                fetch_ms=fetch_ms if fetch_ms is not None else existing.fetch_ms,
                normalize_ms=normalize_ms if normalize_ms is not None else existing.normalize_ms,
                load_ms=load_ms if load_ms is not None else existing.load_ms,
            )
            # a check belongs to the basis it matched, as PgStore records it
            # (`pg._check_columns`); a first row holds no basis to compare
            if first:
                row = replace(row, last_verified_started_at=None, last_verified_at=None)
            else:
                row = _checked(
                    row,
                    existing,
                    raw_sha,
                    obs_sha,
                    verified_started_at,
                    verified_at,
                    verified_raw_sha,
                    verified_obs_sha,
                )
        else:
            # the hashes passed, timings and full are ignored on a failing
            # call; the stored raw hash and graph digest are cleared, as
            # PgStore clears them
            row = replace(
                existing,
                last_attempt_at=now,
                updated_at=now,
                consecutive_failures=existing.consecutive_failures + 1,
                last_error=error,
                last_raw_sha="",
                last_graph_sha="",
                last_verified_started_at=None,
                last_verified_at=None,
            )
        self.device_status[(source, host)] = row
        return row

    async def record_device_graph(self, source, host, *, now, graph_sha, written, fetch_at=None):
        existing = self.device_status.get((source, host))
        if existing is None:
            return False
        if not graph_sha:
            row = replace(
                existing,
                last_graph_sha="",
                last_raw_sha="",
                last_verified_started_at=None,
                last_verified_at=None,
                updated_at=now,
            )
        else:
            row = replace(
                existing,
                last_graph_sha=graph_sha,
                last_graph_at=now if written else existing.last_graph_at,
                last_graph_fetch_at=fetch_at if fetch_at is not None else existing.last_graph_fetch_at,
                updated_at=now,
            )
        self.device_status[(source, host)] = row
        return True

    async def record_device_basis(self, source, host, *, now, raw_sha=None, obs_sha=None, full=False):
        existing = self.device_status.get((source, host))
        if existing is None:
            return False
        row = replace(
            existing,
            last_raw_sha=raw_sha if raw_sha is not None else existing.last_raw_sha,
            last_obs_sha=obs_sha if obs_sha is not None else existing.last_obs_sha,
            last_full_at=now if full else existing.last_full_at,
            updated_at=now,
        )
        self.device_status[(source, host)] = _checked(row, existing, raw_sha, obs_sha)
        return True

    async def list_device_status(self, source=None):
        rows = [d for d in self.device_status.values() if source is None or d.source == source]
        return sorted(rows, key=lambda d: (d.source, d.host))

    async def running_run(self, source):
        return next((r for r in self.runs.values() if r.source == source and r.status == "running"), None)

    async def running_runs(self):
        return sorted((r for r in self.runs.values() if r.status == "running"), key=lambda r: r.id)

    async def reconcile_orphaned_runs(self, now):
        orphaned = [
            r.id for r in self.runs.values() if r.status == "running" and r.source not in self._claims
        ]
        for run_id in orphaned:
            r = self.runs[run_id]
            self.runs[run_id] = replace(r, status="error", finished_at=now, detail="orphaned by crash")
        return len(orphaned)

    async def purge_expired_sessions(self, now, idle_after=None):
        expired = [
            tok
            for tok, (_, expires_at, last_used_at) in self.sessions.items()
            if expires_at <= now or (idle_after is not None and last_used_at <= now - idle_after)
        ]
        for tok in expired:
            del self.sessions[tok]
        return len(expired)

    @asynccontextmanager
    async def cycle_lock(self, on_lost=None):
        async with self._cycle_lock:
            self._fence += 1
            yield self._fence

    @asynccontextmanager
    async def try_cycle_lock(self):
        # `locked()` then `acquire()` with no await between them is atomic on one
        # event loop, so this cannot hand out the lock twice.
        if self._cycle_lock.locked():
            yield False
            return
        async with self._cycle_lock:
            yield True

    @asynccontextmanager
    async def lease_run(self, cts, ttl_s: float = 600.0):
        keys = {int(cts)} if isinstance(cts, int) else {int(k) for k in cts}
        now = datetime.now(UTC)
        self._run_leases = {t: v for t, v in self._run_leases.items() if v[1] > now}
        tokens = []
        for key in sorted(keys):
            token = uuid4().hex
            self._run_leases[token] = (key, now + timedelta(seconds=ttl_s))
            tokens.append(token)
        try:
            yield
        finally:
            for token in tokens:
                self._run_leases.pop(token, None)

    async def leased_runs(self) -> set[int]:
        now = datetime.now(UTC)
        return {key for key, expires in self._run_leases.values() if expires > now}

    @asynccontextmanager
    async def try_scheduler_lock(self, on_lost=None):
        # `locked()` then `acquire()` with no await between them cannot hand
        # the lock out twice
        if self._scheduler_lock.locked():
            yield False
            return
        async with self._scheduler_lock:
            yield True

    # --- job queue ---
    @staticmethod
    def _scope(job) -> tuple[str, str, str]:
        """PgStore's (kind, coalesce(source,''), coalesce(device,'')) key."""
        return (job.kind, job.source or "", job.device or "")

    async def enqueue_job(
        self,
        kind,
        *,
        source=None,
        device=None,
        priority=0,
        not_before,
        max_attempts,
        triggered_by,
        now,
    ):
        scope = (kind, source or "", device or "")
        # mirrors the one_pending_per_kind partial unique index
        if any(self._scope(j) == scope and j.state in ("queued", "running") for j in self.jobs.values()):
            return None
        self._jid += 1
        job = Job(
            id=self._jid,
            kind=kind,
            source=source,
            device=device,
            state="queued",
            priority=priority,
            attempt=0,
            max_attempts=max_attempts,
            not_before=not_before,
            lease_expires_at=None,
            claimed_by=None,
            enqueued_at=now,
            started_at=None,
            finished_at=None,
            detail=None,
            triggered_by=triggered_by,
        )
        self.jobs[job.id] = job
        return job

    async def claim_jobs(self, worker_id, batch, now, lease, *, skip_kinds=()):
        if batch <= 0:
            return []
        # PgStore orders by priority DESC, not_before ASC over the ready set.
        # No await inside this method, so two concurrent claimants on one event
        # loop cannot interleave.
        ready = sorted(
            (
                j
                for j in self.jobs.values()
                if j.state == "queued" and j.not_before <= now and j.kind not in skip_kinds
            ),
            key=lambda j: (-j.priority, j.not_before, j.id),
        )[:batch]
        claimed = []
        for job in ready:
            job = replace(
                job,
                state="running",
                attempt=job.attempt + 1,
                claimed_by=worker_id,
                started_at=now,
                lease_expires_at=now + lease,
            )
            self.jobs[job.id] = job
            claimed.append(job)
        return claimed

    async def heartbeat_jobs(self, job_ids, worker_id, now, lease):
        extended = []
        for job_id in job_ids:
            job = self.jobs.get(job_id)
            if job is None or job.state != "running" or job.claimed_by != worker_id:
                continue
            self.jobs[job_id] = replace(job, lease_expires_at=now + lease)
            extended.append(job_id)
        return extended

    async def finish_job(self, job_id, state, detail, now, *, retry_at=None, claimed_by=None, attempt=None):
        job = self.jobs.get(job_id)
        # compare-and-set on 'running', mirroring PgStore: a reaped job is not
        # resurrected by a late answer from the executor that lost it, and
        # naming the attempt keeps a late answer off the attempt that replaced it
        if job is None or job.state != "running":
            return None
        if claimed_by is not None and job.claimed_by != claimed_by:
            return None
        if attempt is not None and job.attempt != attempt:
            return None
        if retry_at is not None:
            job = replace(
                job,
                state="queued",
                not_before=retry_at,
                finished_at=None,
                detail=detail,
                claimed_by=None,
                lease_expires_at=None,
            )
        else:
            job = replace(
                job,
                state=state,
                finished_at=now,
                detail=detail,
                claimed_by=None,
                lease_expires_at=None,
            )
        self.jobs[job_id] = job
        return job

    async def reap_jobs(self, now, *, backoff_kinds=(), backoff_base_s=60.0, backoff_cap_s=1800.0):
        reaped = 0
        for job_id, job in list(self.jobs.items()):
            if job.state != "running" or job.lease_expires_at is None or job.lease_expires_at > now:
                continue
            exhausted = job.attempt >= job.max_attempts
            # PgStore's CASE, branch for branch: exhausted keeps its not_before,
            # a backoff kind waits least(cap, base * power(2.0, greatest(attempt
            # - 1, 0))) seconds, anything else is due at `now`.
            if exhausted:
                not_before = job.not_before
            elif job.kind in backoff_kinds:
                delay_s = min(backoff_cap_s, backoff_base_s * 2.0 ** max(job.attempt - 1, 0))
                not_before = now + timedelta(seconds=1) * delay_s
            else:
                not_before = now
            self.jobs[job_id] = replace(
                job,
                state="dead" if exhausted else "queued",
                not_before=not_before,
                finished_at=now if exhausted else None,
                detail="lease expired: the executor holding this job stopped reporting",
                claimed_by=None,
                lease_expires_at=None,
            )
            reaped += 1
        return reaped

    async def job_depth(self):
        depth: dict[str, int] = {}
        for job in self.jobs.values():
            depth[job.state] = depth.get(job.state, 0) + 1
        return depth

    async def list_jobs(self, limit=50):
        return sorted(self.jobs.values(), key=lambda j: j.id, reverse=True)[:limit]

    async def get_job(self, job_id):
        job = self.jobs.get(job_id)
        return replace(job) if job is not None else None

    async def pending_jobs(self, kind):
        # PgStore reads these through the one_pending_per_kind predicate
        pending = (j for j in self.jobs.values() if j.kind == kind and j.state in ("queued", "running"))
        return sorted(pending, key=lambda j: j.id)

    async def purge_jobs(self, before):
        doomed = [j.id for j in self.jobs.values() if j.finished_at is not None and j.finished_at < before]
        for job_id in doomed:
            del self.jobs[job_id]
        return len(doomed)

    # --- changes ---
    def _replace_intents(self, change_id: int, intents: list[tuple[str, dict]]) -> None:
        for iid in [i for i, row in self.change_intents.items() if row.change_id == change_id]:
            del self.change_intents[iid]
        for position, (kind, params) in enumerate(intents):
            self._ciid += 1
            self.change_intents[self._ciid] = ChangeIntent(self._ciid, change_id, position, kind, params)

    async def list_changes(self):
        return sorted(self.changes.values(), key=lambda c: c.id)

    async def get_change(self, change_id):
        return self.changes.get(change_id)

    async def list_change_intents(self, change_id):
        return sorted(
            (row for row in self.change_intents.values() if row.change_id == change_id),
            key=lambda row: row.position,
        )

    async def create_change(self, *, title, description, snapshot_cts, created_by, intents):
        self._chid += 1
        now = datetime.now(UTC)
        change = Change(self._chid, title, description, snapshot_cts, "draft", created_by, now, now)
        self.changes[change.id] = change
        self._replace_intents(change.id, intents)
        return change, await self.list_change_intents(change.id)

    async def update_change(
        self, change_id, *, title=UNSET, description=UNSET, snapshot_cts=UNSET, status=UNSET, intents=UNSET
    ):
        change = self.changes.get(change_id)
        if change is None:
            return None
        change = replace(
            change,
            title=change.title if title is UNSET else title,
            description=change.description if description is UNSET else description,
            snapshot_cts=change.snapshot_cts if snapshot_cts is UNSET else snapshot_cts,
            status=change.status if status is UNSET else status,
            updated_at=datetime.now(UTC),
        )
        self.changes[change_id] = change
        if intents is not UNSET:
            self._replace_intents(change_id, intents)
        return change, await self.list_change_intents(change_id)

    async def delete_change(self, change_id):
        if change_id not in self.changes:
            return False
        del self.changes[change_id]
        for iid in [i for i, row in self.change_intents.items() if row.change_id == change_id]:
            del self.change_intents[iid]
        return True

    # --- sites ---
    async def list_sites(self):
        from hst.app.store import Site

        return [
            Site(
                id=i,
                code=c,
                name=v["name"],
                location=v["location"],
                params=v.get("params", {}),
                device_count=sum(1 for x in (await self.device_sites()).values() if x == c),
            )
            for i, (c, v) in enumerate(sorted(self.sites_rows.items()), start=1)
        ]

    async def get_site(self, code):
        return next((s for s in await self.list_sites() if s.code == code), None)

    async def create_site(self, code, name, location, params=None):
        if code in self.sites_rows:
            raise ValueError(f"site {code} already exists")
        if clash := uidmod.site_fold(code, self.sites_rows):
            raise ValueError(f"site {code} folds onto {clash}")
        self.sites_rows[code] = {"name": name, "location": location, "params": params or {}}
        return await self.get_site(code)

    async def update_site(self, code, *, name=None, location=None, params=None, change_params=None):
        row = self.sites_rows.get(code)
        if row is None:
            return None
        if change_params is not None:
            params = change_params(copy.deepcopy(row["params"] or {}))
        if name is not None:
            row["name"] = name
        if location is not None:
            row["location"] = location
        if params is not None:
            row["params"] = params
        return await self.get_site(code)

    async def delete_site(self, code):
        """Delete and release, the same order PgStore uses: read what named the
        site, clear every one of those references, then drop the row."""
        if code not in self.sites_rows:
            return None
        groups = sorted(name for name, row in self.sources.items() if row.config.get("site_code") == code)
        locations = sorted(key for key, row in self.locations.items() if row["site"] == code)
        placed = sorted(uid for uid, at in self.members.items() if at == code)
        for name in groups:
            row = self.sources[name]
            self.sources[name] = replace(row, config={**row.config, "site_code": ""})
        for key in locations:
            self.locations[key]["site"] = None
        for uid in placed:
            del self.members[uid]
        del self.sites_rows[code]
        return SiteRelease(groups, locations, placed)

    async def site_members(self, code):
        return sorted(d for d, c in (await self.device_sites()).items() if c == code)

    async def assign_device(self, device_uid, code):
        if code is None:
            return self.members.pop(device_uid, None) is not None
        if code not in self.sites_rows:
            raise ValueError(f"no such site: {code}")
        self.members[device_uid] = code
        return True

    async def device_sites(self):
        return dict(self.members)

    async def record_target_devices(self, source, host, device_uids, locations=None):
        self.target_uid_rows[(source, host)] = set(device_uids)
        places = locations or {}
        self.target_places[(source, host)] = {u: places[u][0] for u in device_uids if u in places}
        # one write per location, the last non-empty name wins
        seen: dict[str, str] = {}
        for uid in sorted(set(device_uids)):
            if uid not in places or not places[uid][0]:
                continue
            location_id, name = places[uid]
            if name or location_id not in seen:
                seen[location_id] = name
        for location_id, name in sorted(seen.items()):
            row = self.locations.setdefault((source, location_id), {"name": name, "site": None})
            row["name"] = name

    async def target_devices(self, source=None):
        from hst.app.store import TargetDevice

        now = datetime.now(UTC)
        return [
            TargetDevice(group, host, uid, now, self.target_places.get((group, host), {}).get(uid, ""))
            for (group, host), uids in sorted(self.target_uid_rows.items())
            if source is None or group == source
            for uid in sorted(uids)
        ]

    async def resolve_device(self, kind, value, hostname, run_id):
        key = (kind, identifier(kind, value))
        row = self.identity_rows.get(key)
        if row is None:
            minted = mint_for(kind, key[1], hostname, {r.uid for r in self.identity_rows.values()})
            self.identity_rows[key] = DeviceIdentity(minted, kind, key[1], hostname, hostname, run_id)
            legacy = legacy_uid(kind, value)
            if not any(r.uid == legacy for r in self.identity_rows.values()):
                self._move_device_references(legacy, minted)
            return minted
        if hostname:
            for other in self.identity_rows.values():
                if other.uid == row.uid:
                    other.last_hostname = hostname
        return row.uid

    async def bind_device(self, uid, kind, value, run_id):
        if not any(r.uid == uid for r in self.identity_rows.values()):
            raise LookupError(f"no device has the uid {uid!r}")
        key = (kind, identifier(kind, value))
        self.identity_rows.setdefault(key, DeviceIdentity(uid, kind, key[1], None, None, run_id))

    async def rekey_device(self, old_uid, new_uid, *, merge=False):
        rows = [r for r in self.identity_rows.values() if r.uid == old_uid]
        if not rows:
            raise LookupError(f"no device has the uid {old_uid!r}")
        if old_uid == new_uid:
            raise ValueError(f"the device has the uid {new_uid!r} already")
        taken = any(r.uid == new_uid for r in self.identity_rows.values())
        if taken and not merge:
            raise ValueError(f"the uid {new_uid!r} is taken")
        if not taken and merge:
            raise LookupError(f"no device has the uid {new_uid!r} to merge into")
        for row in rows:
            row.uid = new_uid
        self._move_device_references(old_uid, new_uid)
        self.identity_gen += 1
        return len(rows)

    def _move_device_references(self, old_uid, new_uid):
        """PgStore's move: the hand placement and the observed target devices
        follow the new uid, unless the new uid has its own already."""
        if new_uid in self.members:
            self.members.pop(old_uid, None)
        elif old_uid in self.members:
            self.members[new_uid] = self.members.pop(old_uid)
        for key, uids in self.target_uid_rows.items():
            if old_uid in uids and new_uid not in uids:
                uids.discard(old_uid)
                uids.add(new_uid)
                places = self.target_places.get(key, {})
                if old_uid in places:
                    places[new_uid] = places.pop(old_uid)

    async def identity_generation(self):
        return self.identity_gen

    async def device_identities(self):
        return sorted(
            (replace(r) for r in self.identity_rows.values()), key=lambda r: (r.uid, r.kind, r.value)
        )

    async def device_identity_report(self):
        return identity_report(await self.device_identities())

    async def list_reported_locations(self, source=None):
        from hst.app.store import ReportedLocation

        counts: dict[tuple[str, str], set] = {}
        for (group, host), uids in self.target_uid_rows.items():
            places = self.target_places.get((group, host), {})
            for uid in uids:
                location_id = places.get(uid, "")
                if location_id:
                    counts.setdefault((group, location_id), set()).add(uid)
        return [
            ReportedLocation(group, location_id, row["name"], row["site"], len(counts.get(key, ())))
            for key, row in sorted(self.locations.items())
            for group, location_id in [key]
            if source is None or group == source
        ]

    async def bind_location(self, source, location_id, site):
        if site is not None and site not in self.sites_rows:
            raise ValueError(f"no such site: {site}")
        row = self.locations.get((source, location_id))
        if row is None:
            return False
        row["site"] = site
        return True

    async def get_setting(self, key):
        return self.settings_rows.get(key)

    async def put_setting(self, key, value, secrets):
        from datetime import UTC, datetime

        from hst.app.store import AppSetting

        row = AppSetting(key=key, value=value, secrets=secrets, updated_at=datetime.now(UTC))
        self.settings_rows[key] = row
        return row

    async def modify_setting(self, key, change):
        current = self.settings_rows.get(key)
        result = change(copy.deepcopy(current))
        if result is None:
            return current
        return await self.put_setting(key, *result)

    # --- geo places: the same prefix rules as PgStore.search_geo_places ---
    async def replace_geo_places(self, places):
        self.geo_places = list(places)
        return len(self.geo_places)

    async def search_geo_places(self, name, postal, limit):
        from hst.app.geo_places import name_key
        from hst.app.store import GeoPlace, GeoPlaceSearch

        rows = getattr(self, "geo_places", [])
        hits = [
            p
            for p in rows
            if name_key(p.name).startswith(name)
            and (p.postal_code or "").startswith(postal)
            and (name or postal)
        ]
        if postal:
            hits.sort(
                key=lambda p: (p.postal_code, name_key(p.name) != name, name_key(p.name), p.country_code)
            )
            items = hits[:limit]
        else:
            groups: dict[tuple, list[GeoPlace]] = {}
            for p in hits:
                groups.setdefault((p.country_code, p.name, p.admin1, p.admin2), []).append(p)
            items = [
                GeoPlace(c, None, n, a1, a2, sum(p.lat for p in g) / len(g), sum(p.lon for p in g) / len(g))
                for (c, n, a1, a2), g in groups.items()
            ]
            items.sort(
                key=lambda p: (
                    name_key(p.name) != name,
                    len(name_key(p.name)),
                    name_key(p.name),
                    p.country_code,
                    p.admin1,
                )
            )
            items = items[:limit]
        return GeoPlaceSearch(items=items, available=bool(rows))

    # --- auth providers ---
    async def list_auth_providers(self):
        return sorted(self.auth_providers.values(), key=lambda p: p.name)

    async def get_auth_provider(self, name):
        return next((p for p in self.auth_providers.values() if p.name == name), None)

    async def create_auth_provider(self, name, kind, config, secrets, enabled=False):
        if await self.get_auth_provider(name):
            raise ValueError(f"auth provider {name!r} exists")
        self._pid += 1
        now = datetime.now(UTC)
        p = AuthProvider(self._pid, name, kind, config, secrets, enabled, now, now)
        self.auth_providers[p.id] = p
        return p

    async def update_auth_provider(self, name, *, config=None, secrets=None, enabled=None):
        p = await self.get_auth_provider(name)
        if p is None:
            return None
        if config is not None:
            p = replace(p, config=config)
        if secrets is not None:
            p = replace(p, secrets=secrets)
        if enabled is not None:
            if p.enabled and not enabled:
                await self._delete_provider_sessions_and_tokens(p.id)
            p = replace(p, enabled=enabled)
        p = replace(p, updated_at=datetime.now(UTC))
        self.auth_providers[p.id] = p
        return p

    async def _delete_provider_sessions_and_tokens(self, provider_id):
        for user_id in {i.user_id for i in self.identities.values() if i.provider_id == provider_id}:
            await self.delete_user_sessions(user_id)
            await self.delete_user_access_tokens(user_id)

    async def delete_auth_provider(self, name):
        p = await self.get_auth_provider(name)
        if p is None:
            return False
        del self.auth_providers[p.id]
        await self._delete_provider_sessions_and_tokens(p.id)
        # cascade: identities, group_mappings, auth_state for this provider
        for iid in [i for i, ident in self.identities.items() if ident.provider_id == p.id]:
            del self.identities[iid]
        for gid in [g for g, gm in self.group_mappings.items() if gm.provider_id == p.id]:
            del self.group_mappings[gid]
        for sid in [s for s, st in self.auth_state.items() if st.provider_id == p.id]:
            del self.auth_state[sid]
        return True

    # --- identities ---
    async def get_identity(self, provider_id, subject):
        return next(
            (i for i in self.identities.values() if i.provider_id == provider_id and i.subject == subject),
            None,
        )

    async def create_identity(self, user_id, provider_id, subject, email=""):
        if user_id not in self.users or provider_id not in self.auth_providers:
            raise IdentityOwnerMissing(
                f"the user or the auth provider {provider_id} of the identity does not exist"
            )
        if await self.get_identity(provider_id, subject):
            raise ValueError(f"identity ({provider_id}, {subject!r}) exists")
        self._iid += 1
        i = Identity(self._iid, user_id, provider_id, subject, email, None)
        self.identities[i.id] = i
        return i

    async def create_user_with_identity(self, username, role, provider_id, subject, email=""):
        if await self.get_user_by_username(username):
            raise ValueError(f"username {username!r} exists")
        if provider_id not in self.auth_providers:
            raise IdentityOwnerMissing(
                f"the user or the auth provider {provider_id} of the identity does not exist"
            )
        if await self.get_identity(provider_id, subject):
            raise ValueError(f"identity ({provider_id}, {subject!r}) exists")
        user = await self.create_user(username, None, role)
        return user, await self.create_identity(user.id, provider_id, subject, email)

    async def touch_last_login(self, identity_id, when):
        i = self.identities.get(identity_id)
        if i is not None:
            self.identities[identity_id] = replace(i, last_login_at=when)

    async def list_identities_for_users(self, user_ids):
        wanted = set(user_ids)
        return [i for i in self.identities.values() if i.user_id in wanted]

    # --- group mappings ---
    async def list_group_mappings(self, provider_id):
        return sorted(
            (g for g in self.group_mappings.values() if g.provider_id == provider_id),
            key=lambda g: g.group_name,
        )

    async def put_group_mapping(self, provider_id, group_name, role):
        existing = next(
            (
                g
                for g in self.group_mappings.values()
                if g.provider_id == provider_id and g.group_name == group_name
            ),
            None,
        )
        if existing is not None:
            g = replace(existing, role=role)
            self.group_mappings[g.id] = g
            return g
        self._gid += 1
        g = GroupMapping(self._gid, provider_id, group_name, role)
        self.group_mappings[g.id] = g
        return g

    async def delete_group_mapping(self, provider_id, group_name):
        existing = next(
            (
                g
                for g in self.group_mappings.values()
                if g.provider_id == provider_id and g.group_name == group_name
            ),
            None,
        )
        if existing is None:
            return False
        del self.group_mappings[existing.id]
        return True

    # --- auth state ---
    async def create_auth_state(self, id, provider_id, kind, payload, expires_at):
        # a second create_auth_state with the same `id` raises
        if id in self.auth_state:
            raise ValueError(f"auth_state {id!r} exists")
        s = AuthState(id, provider_id, kind, payload, expires_at)
        self.auth_state[id] = s
        return s

    async def consume_auth_state(self, id, kind, provider_id, now):
        s = self.auth_state.get(id)
        if s is None or s.kind != kind or s.provider_id != provider_id or s.expires_at <= now:
            return None
        del self.auth_state[id]
        return s

    async def purge_expired_auth_state(self, now):
        expired = [i for i, s in self.auth_state.items() if s.expires_at <= now]
        for i in expired:
            del self.auth_state[i]
        return len(expired)

    # --- login events ---
    async def record_login_event(self, username, user_id, provider, outcome, source, at):
        self._leid += 1
        e = LoginEvent(self._leid, at, username, user_id, provider, outcome, source)
        self.login_events.append(e)
        return e

    async def list_login_events(self, limit=200):
        # newest-first, with no secondary key
        return sorted(self.login_events, key=lambda e: e.at, reverse=True)[:limit]

    async def purge_login_events(self, before):
        keep = [e for e in self.login_events if e.at >= before]
        purged = len(self.login_events) - len(keep)
        self.login_events = keep
        return purged

    # --- cypher events ---
    async def record_cypher_event(
        self, user_id, query, outcome, row_count, byte_count, at, origin=None, ai_step_id=None
    ):
        self._ceid += 1
        e = CypherEvent(self._ceid, at, user_id, query, outcome, row_count, byte_count, origin, ai_step_id)
        self.cypher_events.append(e)
        return e

    async def list_cypher_events(self, limit=200):
        return sorted(self.cypher_events, key=lambda e: e.at, reverse=True)[:limit]

    async def purge_cypher_events(self, before):
        keep = [e for e in self.cypher_events if e.at >= before]
        purged = len(self.cypher_events) - len(keep)
        self.cypher_events = keep
        return purged

    # --- evidence exports ---
    async def record_evidence_export(
        self, *, user_id, username, kind, raw_mode, source, host, run_id, payloads, at
    ):
        self._eeid += 1
        e = EvidenceExport(self._eeid, at, user_id, username, kind, raw_mode, source, host, run_id, payloads)
        self.evidence_exports.append(e)
        return e

    async def list_evidence_exports(self, limit=200):
        return sorted(self.evidence_exports, key=lambda e: (e.at, e.id), reverse=True)[:limit]

    # --- network map layouts and views ---
    async def get_network_map_layout(self, scope):
        return self.map_layouts.get(scope)

    async def save_network_map_layout(self, scope, positions, *, expected_revision, user_id, now):
        current = self.map_layouts.get(scope)
        if (current.revision if current else 0) != expected_revision:
            raise StaleMapRevision(f"the layout of {scope} was saved by someone else")
        saved = NetworkMapLayout(scope, dict(positions), expected_revision + 1, user_id, now)
        self.map_layouts[scope] = saved
        return saved

    async def delete_network_map_layout(self, scope, *, expected_revision):
        current = self.map_layouts.get(scope)
        if current is None:
            return False
        if current.revision != expected_revision:
            raise StaleMapRevision(f"the layout of {scope} was saved by someone else")
        del self.map_layouts[scope]
        return True

    async def list_network_map_views(self):
        return sorted(self.map_views.values(), key=lambda v: v.name)

    async def create_network_map_view(self, name, state, *, owner_id, now):
        if any(v.name == name for v in self.map_views.values()):
            raise MapViewNameTaken(f"a view named {name!r} exists")
        view = NetworkMapView(uuid.uuid4(), name, dict(state), owner_id, 1, now, now)
        self.map_views[view.id] = view
        return view

    async def update_network_map_view(self, view_id, *, expected_revision, now, name=None, state=None):
        current = self.map_views.get(view_id)
        if current is None:
            return None
        if current.revision != expected_revision:
            raise StaleMapRevision("the view was saved by someone else")
        if name is not None and any(v.name == name and v.id != view_id for v in self.map_views.values()):
            raise MapViewNameTaken(f"a view named {name!r} exists")
        updated = replace(
            current,
            name=current.name if name is None else name,
            state=current.state if state is None else dict(state),
            revision=current.revision + 1,
            updated_at=now,
        )
        self.map_views[view_id] = updated
        return updated

    async def delete_network_map_view(self, view_id, *, expected_revision):
        current = self.map_views.get(view_id)
        if current is None:
            return False
        if current.revision != expected_revision:
            raise StaleMapRevision("the view was saved by someone else")
        del self.map_views[view_id]
        return True

    # --- AI audit trail ---
    async def record_ai_event(self, event):
        self._aeid += 1
        stored = replace(event, id=self._aeid)
        self.ai_events.append(stored)
        return stored

    async def list_ai_events(self, limit=200):
        return sorted(self.ai_events, key=lambda e: (e.at, e.id), reverse=True)[:limit]

    async def purge_ai_events(self, before):
        keep = [e for e in self.ai_events if e.at >= before]
        purged = len(self.ai_events) - len(keep)
        self.ai_events = keep
        return purged

    async def ai_token_usage(self, since):
        sums: dict[tuple, list[int]] = {}
        for e in self.ai_events:
            if e.at < since or (e.tokens_in is None and e.tokens_out is None):
                continue
            key = (e.at.astimezone(UTC).date(), e.user_id)
            total = sums.setdefault(key, [0, 0])
            total[0] += e.tokens_in or 0
            total[1] += e.tokens_out or 0
        order = sorted(sums, key=lambda k: (-k[0].toordinal(), k[1] is None, k[1] or 0))
        return [AiTokenUsage(day, user_id, *sums[(day, user_id)]) for day, user_id in order]

    async def put_prompt_version(self, prompt_hash, content, at):
        if prompt_hash in self.prompt_versions:
            return False
        self.prompt_versions[prompt_hash] = (content, at)
        return True

    # --- AI conversations ---
    def _owned(self, user_id, conversation_id):
        c = self.ai_conversations.get(canonical_uuid(conversation_id) or "")
        return c if c is not None and c.user_id == user_id else None

    def _message(self, message_id):
        return self.ai_messages.get(canonical_uuid(message_id) or "")

    def _drop_conversations(self, doomed):
        for cid in doomed:
            del self.ai_conversations[cid]
        self.ai_messages = {k: m for k, m in self.ai_messages.items() if m.conversation_id not in doomed}
        self.ai_steps = {k: st for k, st in self.ai_steps.items() if st.conversation_id not in doomed}
        self.ai_links = [link for link in self.ai_links if link.conversation_id not in doomed]
        return len(doomed)

    async def create_conversation(
        self, user_id, surface, at, *, title="", ephemeral=False, snapshot_id=None, pin_mode="follow"
    ):
        c = AiConversation(
            id=str(uuid4()),
            user_id=user_id,
            surface=surface,
            created_at=at,
            last_message_at=at,
            ephemeral=ephemeral,
            title=title,
            snapshot_id=snapshot_id,
            pin_mode=pin_mode,
        )
        self.ai_conversations[c.id] = c
        return replace(c)

    async def get_conversation(self, user_id, conversation_id):
        c = self._owned(user_id, conversation_id)
        if c is None:
            return None
        messages = [replace(m) for m in self.ai_messages.values() if m.conversation_id == c.id]
        steps = [replace(st) for st in self.ai_steps.values() if st.conversation_id == c.id]
        return replace(
            c,
            messages=sorted(messages, key=lambda m: m.seq),
            steps=sorted(steps, key=lambda st: st.label),
            links=[replace(link) for link in self.ai_links if link.conversation_id == c.id],
        )

    async def list_conversations(self, user_id, *, surface=None, link_kind=None, link_id=None, limit=50):
        def linked(cid):
            return any(
                link.conversation_id == cid
                and (link_kind is None or link.kind == link_kind)
                and (link_id is None or link.ref_id == link_id)
                for link in self.ai_links
            )

        rows = [
            c
            for c in self.ai_conversations.values()
            if c.user_id == user_id
            and not c.ephemeral
            and (surface is None or c.surface == surface)
            and ((link_kind is None and link_id is None) or linked(c.id))
        ]
        rows.sort(key=lambda c: c.id)
        rows.sort(key=lambda c: c.last_message_at, reverse=True)

        def listed(c):
            messages = sorted(
                (m for m in self.ai_messages.values() if m.conversation_id == c.id), key=lambda m: m.seq
            )
            questions = [m.content for m in messages if m.role == "user"]
            runs = [m.snapshot_id for m in messages if m.role == "assistant" and m.snapshot_id is not None]
            title = c.title or (questions[0][:LIST_TITLE_CHARS] if questions else "")
            return replace(c, title=title, last_run=runs[-1] if runs else None)

        return [listed(c) for c in rows[:limit]]

    async def delete_conversation(self, user_id, conversation_id):
        c = self._owned(user_id, conversation_id)
        if c is None:
            return False
        self._drop_conversations({c.id})
        return True

    async def start_turn(
        self, user_id, conversation_id, question, context, at, *, per_user_cap, global_cap, surface="drawer"
    ):
        # no await before the inserts, so the counts and the inserts are
        # atomic within the event loop, as the advisory lock makes them in Postgres
        c = None
        if conversation_id is not None:
            c = self._owned(user_id, conversation_id)
            if c is None:
                return None
        active = [m for m in self.ai_messages.values() if m.status in TURN_ACTIVE_STATES]
        if (
            sum(1 for m in active if self.ai_conversations[m.conversation_id].user_id == user_id)
            >= per_user_cap
        ):
            raise TurnCapExceeded("user")
        if len(active) >= global_cap:
            raise TurnCapExceeded("global")
        if c is None:
            c = AiConversation(
                id=str(uuid4()),
                user_id=user_id,
                surface=surface,
                created_at=at,
                last_message_at=at,
                ephemeral=True,
            )
            self.ai_conversations[c.id] = c
        c.message_count += 2
        c.last_message_at = at
        question_row = AiMessage(
            id=str(uuid4()),
            conversation_id=c.id,
            seq=c.message_count - 1,
            role="user",
            status="done",
            created_at=at,
            content=question,
            context=context,
            finished_at=at,
        )
        reply = AiMessage(
            id=str(uuid4()),
            conversation_id=c.id,
            seq=c.message_count,
            role="assistant",
            status="pending",
            created_at=at,
        )
        self.ai_messages[question_row.id] = question_row
        self.ai_messages[reply.id] = reply
        return replace(reply)

    async def claim_turn(self, message_id, owner, lease_s, now):
        m = self._message(message_id)
        if m is None or m.role != "assistant" or m.status != "pending":
            return False
        m.status = "running"
        m.lease_owner = owner
        m.lease_expires_at = now + timedelta(seconds=lease_s)
        return True

    async def heartbeat_turn(self, message_id, owner, lease_s, now):
        m = self._message(message_id)
        if m is None or m.status != "running" or m.lease_owner != owner:
            return False
        m.lease_expires_at = now + timedelta(seconds=lease_s)
        return True

    async def append_step(
        self,
        message_id,
        tool,
        tool_version,
        arguments,
        is_error,
        result,
        started_at,
        elapsed_ms,
        *,
        result_summary=None,
        provenance=None,
        step_id=None,
    ):
        m = self._message(message_id)
        if m is None:
            raise KeyError(message_id)
        c = self.ai_conversations[m.conversation_id]
        c.step_count += 1
        step = AiStep(
            id=step_id or str(uuid4()),
            conversation_id=c.id,
            message_id=m.id,
            label=c.step_count,
            tool=tool,
            tool_version=tool_version,
            arguments=arguments,
            is_error=is_error,
            result=result,
            result_sha256=step_digest(result),
            result_chars=len(result),
            started_at=started_at,
            elapsed_ms=elapsed_ms,
            result_summary=result_summary,
            provenance=provenance,
        )
        self.ai_steps[step.id] = step
        return replace(step)

    async def finish_turn(
        self,
        message_id,
        owner,
        status,
        at,
        *,
        content="",
        envelope=None,
        error=None,
        snapshot_id=None,
        provider=None,
        model_requested=None,
        model_served=None,
        prompt_hash=None,
        usage=None,
    ):
        if status not in TURN_FINAL_STATES:
            raise ValueError(f"not a final turn status: {status!r}")
        m = self._message(message_id)
        if m is None or m.status != "running" or m.lease_owner != owner:
            return False
        m.status = status
        m.content = content
        m.envelope = envelope
        m.error = error
        m.snapshot_id = snapshot_id
        m.provider = provider
        m.model_requested = model_requested
        m.model_served = model_served
        m.prompt_hash = prompt_hash
        m.usage = usage
        m.lease_expires_at = None
        m.finished_at = at
        c = self.ai_conversations[m.conversation_id]
        c.last_message_at = max(c.last_message_at, at)
        return True

    async def set_question_context(self, message_id, context):
        m = self._message(message_id)
        if m is None or m.role != "assistant":
            return False
        question = next(
            (
                q
                for q in self.ai_messages.values()
                if q.conversation_id == m.conversation_id and q.seq == m.seq - 1 and q.role == "user"
            ),
            None,
        )
        if question is None:
            return False
        question.context = context
        return True

    async def request_cancel(self, user_id, message_id):
        m = self._message(message_id)
        if m is None or m.status not in TURN_ACTIVE_STATES:
            return False
        if self.ai_conversations[m.conversation_id].user_id != user_id:
            return False
        m.cancel_requested = True
        return True

    async def get_message(self, user_id, message_id, *, surface=None):
        m = self._message(message_id)
        if m is None:
            return None
        c = self.ai_conversations[m.conversation_id]
        if c.user_id != user_id or (surface is not None and c.surface != surface):
            return None
        return replace(m)

    async def get_turn(self, user_id, message_id):
        m = await self.get_message(user_id, message_id)
        if m is None or m.role != "assistant":
            return None
        question = next(
            (
                replace(q)
                for q in self.ai_messages.values()
                if q.conversation_id == m.conversation_id and q.seq == m.seq - 1
            ),
            None,
        )
        steps = sorted(
            (replace(st) for st in self.ai_steps.values() if st.message_id == m.id), key=lambda st: st.label
        )
        return AiTurn(message=m, question=question, steps=steps)

    async def get_turn_progress(self, user_id, message_id, after):
        m = await self.get_message(user_id, message_id)
        if m is None or m.role != "assistant":
            return None
        steps = sorted(
            (replace(st) for st in self.ai_steps.values() if st.message_id == m.id and st.label > after),
            key=lambda st: st.label,
        )
        return AiTurnProgress(status=m.status, steps=steps)

    async def get_step(self, user_id, step_id):
        st = self.ai_steps.get(canonical_uuid(step_id) or "")
        if st is None or self.ai_conversations[st.conversation_id].user_id != user_id:
            return None
        return replace(st)

    async def set_summary(self, user_id, conversation_id, summary, through):
        c = self._owned(user_id, conversation_id)
        if c is None or c.summary_through >= through:
            return False
        c.summary = summary
        c.summary_through = through
        return True

    async def expire_stale_turns(self, now, pending_grace_s=60.0):
        marked = 0
        for m in self.ai_messages.values():
            if m.status not in TURN_ACTIVE_STATES:
                continue
            lapsed = m.lease_expires_at is not None and m.lease_expires_at <= now
            abandoned = (
                m.status == "pending"
                and m.lease_expires_at is None
                and m.created_at <= now - timedelta(seconds=pending_grace_s)
            )
            if lapsed or abandoned:
                m.status = "interrupted"
                m.lease_expires_at = None
                m.finished_at = now
                marked += 1
        return marked

    async def add_link(
        self,
        conversation_id,
        kind,
        ref_id,
        direction,
        at,
        *,
        message_id=None,
        step_id=None,
        ref_revision=None,
    ):
        c = self.ai_conversations.get(canonical_uuid(conversation_id) or "")
        if c is None:
            return None
        m = None if message_id is None else self._message(message_id)
        if message_id is not None and (m is None or m.conversation_id != c.id):
            return None
        st = None if step_id is None else self.ai_steps.get(canonical_uuid(step_id) or "")
        if step_id is not None and (st is None or st.conversation_id != c.id):
            return None
        self._alid += 1
        link = AiLink(
            id=self._alid,
            conversation_id=c.id,
            kind=kind,
            ref_id=ref_id,
            direction=direction,
            created_at=at,
            message_id=None if m is None else m.id,
            step_id=None if st is None else st.id,
            ref_revision=ref_revision,
        )
        self.ai_links.append(link)
        return replace(link)

    async def compact_steps(self, before, at):
        compacted = 0
        for st in self.ai_steps.values():
            if st.started_at < before and st.result is not None:
                st.result = None
                st.compacted_at = at
                compacted += 1
        return compacted

    async def purge_conversations(self, before):
        return self._drop_conversations(
            {c.id for c in self.ai_conversations.values() if c.last_message_at < before}
        )

    async def purge_ephemeral(self, before):
        return self._drop_conversations(
            {c.id for c in self.ai_conversations.values() if c.ephemeral and c.last_message_at < before}
        )

    async def dispose(self) -> None:
        return
