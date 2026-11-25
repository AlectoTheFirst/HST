"""The runtime settings come from .env and the environment. The defaults match .env.example."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .device_roles import DEFAULT_TIER_TOKENS, TIER_ROLES

DEFAULT_L2_FABRIC = "fab0"


# The default number of device and refresh runs that graph retention keeps
# beside the cycles.
KEEP_DEVICE_RUNS_DEFAULT = 48


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # .env is resolved against the working directory. These defaults apply when
    # hst runs from a directory without the .env file.
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "change-me"  # noqa: S105 - the value is a placeholder
    neo4j_database: str = "neo4j"
    # PEM CA bundle for verified bolt TLS. Empty leaves TLS to the URI scheme.
    neo4j_tls_ca_file: str = ""

    # Prune deletes the graph data of the cycle runs beyond the newest N. Prune
    # never deletes the current run of the pointer. app/retention.py replaces
    # this default with the value that an admin sets.
    cycle_keep_runs: int = 30
    # Device and refresh runs have their own count. Prune keeps the newest N of
    # them that are newer than the oldest kept cycle (core/cycle.py
    # `_partition`). Each device run is a full copy of the graph, built every
    # device_run_interval_s. 48 runs are 8 hours at the default interval.
    cycle_keep_device_runs: int = KEEP_DEVICE_RUNS_DEFAULT
    # The transaction timeout in seconds of the reads that the finalize
    # derivations (rt-imports, rt-domains, link-speed) make over the whole run.
    # When it is unset, the db.transaction.timeout of the server applies. The
    # CLI audits use 30 s.
    reasoner_read_timeout_s: float | None = Field(default=None, gt=0)

    # Each L2 fabric of a classic switched estate maps to its source names. An
    # empty map means one fabric. A source that is not listed is in the default
    # fabric. Example: L2_FABRICS='{"dmz": ["vyos-dmz", "unifi-dmz"]}'.
    l2_fabrics: dict[str, list[str]] = {}

    def l2fabric_of(self, source_name: str, explicit: str | None = None) -> str:
        if explicit:
            return explicit
        for fabric, members in (self.l2_fabrics or {}).items():
            if source_name in members:
                return fabric
        return DEFAULT_L2_FABRIC

    # The hostname naming standard of the estate maps each role code token to a
    # design tier (core/device_roles.py). The run sets Device.role and
    # Device.tier from it before the reasoner. It replaces only a role in
    # GENERIC_ROLES. The environment value replaces the whole map, e.g.
    # HOSTNAME_TIER_TOKENS='{"cr": "core", "as": "access"}'.
    hostname_tier_tokens: dict[str, str] = Field(default_factory=lambda: dict(DEFAULT_TIER_TOKENS))

    @model_validator(mode="after")
    def _tier_tokens_known(self) -> Settings:
        unknown = sorted(set(self.hostname_tier_tokens.values()) - set(TIER_ROLES))
        if unknown:
            raise ValueError(f"hostname_tier_tokens names unknown tiers: {unknown}")
        return self

    hst_data_dir: Path = Path("./data")

    # A RIB table with at most this many routes is written to the graph as
    # LEARNED_ROUTE edges and to the parquet side store. A larger table (a full
    # internet table) is written to the side store only. LPM on the side store
    # runs in DuckDB.
    rib_graph_max_routes: int = 1000

    # How many L3 hops a trace follows.
    max_l3_hops: int = 32

    # How many parallel regions one stage of a trace holds before the remainder
    # is reported as one undecided region.
    path_region_cap: int = 64

    # How many lanes one trace walks to the end. Every equal-cost route of a
    # fork is its own lane and walks every device below it again. A fabric W
    # wide and H devices deep has W to the power H lanes. The trace lists the
    # routes of a fork past the cap and reports their legs as indeterminate.
    path_lane_cap: int = 64

    # How many healthy members a load balancer pool fans out into before the
    # rest are reported as one undecided leg.
    lb_member_cap: int = 8

    analysis_enabled: bool = True
    analysis_engine: Literal["legacy-v1", "symbolic-v2"] = "legacy-v1"
    analysis_memory_mb: int = Field(default=1024, ge=256, le=16384)
    analysis_cache_mb: int = Field(default=10240, ge=64, le=1048576)
    analysis_result_mb: int = Field(default=10240, ge=64, le=1048576)
    analysis_timeout_s: float = Field(default=120, ge=1, le=600)
    analysis_poll_s: float = Field(default=1, ge=0.1, le=60)
    # The temporal evidence policy of a symbolic analysis
    # (analysis_model/evidence.py `EvidencePolicy`). An observation older than
    # max_age_s at publication is stale. The observations of one model that
    # span more than max_skew_s are skewed.
    analysis_evidence_max_age_s: int = Field(default=3_600, ge=0)
    analysis_evidence_max_skew_s: int = Field(default=300, ge=0)
    analysis_evidence_consistency_mode: Literal["bounded-window", "stable-window-assumption"] = (
        "bounded-window"
    )
    analysis_evidence_stable_window_assumption: str = ""

    # The pinning rule applies to model-authored Cypher (query_cypher on MCP and
    # in the agent). Each MATCH must bind $snap in a predicate on collection_ts.
    # A query without the binding reads every retained run.
    # "refuse" rejects such a query with the guard form. "warn" runs it, logs a
    # warning and returns the guidance with the rows. POST /api/cypher and the
    # query catalog do not apply the rule.
    hst_ai_cypher_pinning: Literal["refuse", "warn"] = "refuse"
    # The check of agent tool arguments against each tool's input model.
    # "warn" logs one hst.ai warning that names the tool and the failing
    # field paths, and runs the call. "enforce" returns the mismatch to the
    # model as the call's error and does not run the call.
    hst_ai_tool_validation: Literal["warn", "enforce"] = "enforce"

    # The application server (hst serve) stores identity in Postgres only.
    postgres_dsn: str = "postgresql+asyncpg://hst:change-me@localhost:5433/hst"
    # PEM CA bundle for verified Postgres TLS. Empty means no TLS.
    postgres_ca_file: str = ""
    session_ttl_hours: int = 168
    # A session that has not been used for this long stops authenticating.
    session_idle_timeout_hours: int = 8
    # The Secure flag of the session cookie follows the request scheme. Behind a
    # TLS terminator in HST_FORWARDED_ALLOW_IPS, X-Forwarded-Proto sets the
    # scheme. True sets the flag for a terminator that sends no forwarded headers.
    cookie_secure: bool = False
    login_rate_limit: int = 5
    login_rate_window_s: int = 60
    # Retention days for the audit tables LoginEvent and CypherEvent. 0 keeps everything.
    login_event_retention_days: int = 90
    cypher_event_retention_days: int = 180
    # Retention days of the AI tables (app/store/__init__.py AiConversation,
    # AiStep, AiEvent). The age of a conversation is the age of its last message.
    # An old step result is compacted to its digest and summary. 0 keeps everything.
    ai_conversation_retention_days: int = 90
    ai_step_result_days: int = 14
    ai_event_retention_days: int = 180
    # Days the scheduler keeps completed rows of the `jobs` table. 0 keeps everything.
    job_history_retention_days: int = 30
    # Whether `hst serve` runs the scheduler and the embedded executor. True
    # runs maintenance and scheduled collection inside the API process. The
    # scheduler elects one leader (app/store/pg.py SCHEDULER_LOCK).
    scheduler_enabled: bool = True
    # Where a run triggered through POST /api/runs executes. "inline" starts it
    # in the process that answered the request. "queue" enqueues a
    # `collect.run` job (worker/collect.py) and answers 202 with the job. The
    # process whose executor claims the job executes the run. With
    # SCHEDULER_ENABLED=false on every API process, that process is `hst worker`.
    run_execution: Literal["inline", "queue"] = "inline"
    # The scheduler enqueues a full cycle every this many seconds. 0 keeps
    # collection manual.
    collect_interval_s: int = 0
    # Concurrent device fetches within one cycle. asyncssh fetches are asyncio
    # tasks under a semaphore of this size.
    collect_max_concurrency: int = 8
    # The thread pool for the blocking fetches of SSH devices on the paramiko
    # transport and of the HTTP collectors.
    collect_thread_workers: int = 8
    # A device whose raw payload hash is unchanged skips normalize and load. A
    # device whose normalized batch has the digest of the batch on record writes
    # only the objects that it shares with other writers and the objects with an
    # anchor. A full load is forced at least this often.
    collect_full_interval_s: int = 900
    # When the job queue holds this many pending jobs, the scheduler skips the
    # per-device fan-out for that tick. The devices stay due for the next tick.
    collect_queue_high_water: int = 1000
    # A device that keeps failing doubles its own polling interval per
    # consecutive failure, up to this cap. The rest of its group keeps cadence.
    collect_backoff_cap_s: int = 900
    # The maintenance sweep folds the parked per-device payloads into one new run
    # this often.
    device_run_interval_s: int = 600
    # How many fetch results the collection engine holds between the concurrent
    # fetch phase and the serial load (app/runs_exec.py `_FetchBuffer`).
    collect_fetch_buffer: int = 64
    # The payload size, in MiB, at or above which the fetch phase seals a
    # fetched payload to a spill file under <raw_dir>/.spill as soon as it is
    # hashed, and the load reads it back from there (core/rawstore.py
    # `spill`). The compared size is the in-memory size of the payload, a
    # `sys.getsizeof` sum over its containers, keys and values. 0 holds every
    # payload in memory until its load.
    collect_spill_mb: int = Field(default=8, ge=0)
    # The largest answer, in MiB, that one SSH command may give (collectors/ssh.py
    # `_AnswerBudget`). The limit applies to asyncssh and paramiko sessions, on
    # an exec channel and on a shell. The read stops at the first piece that
    # passes the limit and closes the channel. The command fails with the limit
    # and the size read, and no part of the answer is kept. A failed optional
    # command is a failed section. A failed required command fails the device.
    # On a shell session the next command runs on a new shell of the same
    # connection. 0 reads every answer whole. One HTTP response body has the
    # same limit.
    collect_max_answer_mb: int = Field(default=1024, ge=0)
    # gzip level of the raw payload files (core/rawstore.py `write`), 1 to 9.
    raw_compress_level: int = Field(default=6, ge=1, le=9)
    # Rows per parquet row group in the side store (core/sidestore.py
    # `write_table`).
    sidestore_row_group_rows: int = 65_536
    # Concurrent job bodies in each executor.
    collect_worker_concurrency: int = 16
    # The clock declaration for the collector host of this deployment. The host
    # clock stamps every fetch window. "trusted" declares that the host clock is
    # synchronized to the analysis clock. "trusted" requires the assumption text.
    collector_clock_quality: Literal["unknown", "trusted"] = "unknown"
    collector_clock_assumption: str = ""

    @model_validator(mode="after")
    def _clock_assumption(self) -> Settings:
        if self.collector_clock_quality == "trusted" and not self.collector_clock_assumption.strip():
            raise ValueError("trusted collector clock requires a nonempty assumption")
        if self.collector_clock_quality == "unknown" and self.collector_clock_assumption:
            raise ValueError("collector clock assumption requires trusted quality")
        stable = self.analysis_evidence_consistency_mode == "stable-window-assumption"
        if stable and not self.analysis_evidence_stable_window_assumption.strip():
            raise ValueError("stable-window-assumption consistency requires a nonempty assumption")
        if not stable and self.analysis_evidence_stable_window_assumption:
            raise ValueError("a stable window assumption requires stable-window-assumption consistency")
        return self

    # Comma-separated IPs/CIDRs of proxies whose X-Forwarded-* headers are
    # trusted. Empty trusts none.
    forwarded_allow_ips: str = Field(default="", validation_alias="HST_FORWARDED_ALLOW_IPS")
    # The origin that users reach, e.g. https://hst.example.net. The SAML entity
    # ID, the ACS URL and the OIDC redirect URI are built from it
    # (app/sso_flow.py `external_url`). The SSO routes answer 503 while it is empty.
    public_url: str = Field(default="", validation_alias="HST_PUBLIC_URL")

    @field_validator("public_url")
    @classmethod
    def _public_url_is_an_origin(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        try:
            parts = urlsplit(value)
            parts.port  # noqa: B018 -- the property raises ValueError for a port that is not a number
        except ValueError as exc:
            raise ValueError(f"HST_PUBLIC_URL {value!r} is not a URL") from exc
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"HST_PUBLIC_URL {value!r} must start with http:// or https://")
        if not parts.hostname:
            raise ValueError(f"HST_PUBLIC_URL {value!r} has no host")
        if "@" in parts.netloc:
            raise ValueError(f"HST_PUBLIC_URL {value!r} must not have a user or a password")
        if parts.path not in ("", "/") or "?" in value or "#" in value:
            raise ValueError(f"HST_PUBLIC_URL {value!r} must not have a path, a query or a fragment")
        return f"{parts.scheme}://{parts.netloc}"

    # The largest request body, in MiB, that the app reads (app/body_limit.py).
    # A larger request gets 413. The largest body a route accepts is an
    # assessment document of 8 MiB (assessment/store.py `MAX_DOCUMENT_BYTES`).
    max_request_body_mb: int = Field(default=16, ge=1, validation_alias="HST_MAX_REQUEST_BODY_MB")

    # PEM paths for the TLS of `hst serve`. `serve` refuses to start with only one of cert and key.
    tls_cert_file: str = ""
    tls_key_file: str = ""
    tls_key_password_file: str = ""
    # Trust for the outbound HTTPS of the app (AI providers, OIDC discovery and
    # token exchange, SAML metadata). TLS_CA_BUNDLE is a PEM file path for the
    # CA of a TLS-intercepting proxy. TLS_VERIFY=false skips verification for
    # every such connection. A provider row can override each setting with its
    # tls_skip_verify or tls_ca_bundle (app/tls.py). Collectors use their
    # per-source TlsConfig and read neither setting.
    tls_verify: bool = True
    tls_ca_bundle: str = ""

    @model_validator(mode="after")
    def _ca_bundle_exists(self) -> Settings:
        if self.tls_ca_bundle and not Path(self.tls_ca_bundle).is_file():
            raise ValueError(f"tls_ca_bundle {self.tls_ca_bundle!r} is not a file")
        return self

    web_dist: Path = Path("web/dist")  # The built SPA is served when the directory exists.
    # The GeoNames postal code file the app loads into the place table at
    # start-up, once per file (app/geo_places.py `load_bundled`).
    geo_places_file: Path | None = None
    # The operator key seals source credentials and raw snapshots. It wraps the
    # data key at HST_DATA_DIR/dek.wrapped. The key is any value of at least 32
    # bytes. `hst secret-key` generates one. The file variant wins when both
    # are set.
    hst_secret_key: str = ""
    hst_secret_key_file: str = ""

    # The key signs the snapshot manifests (core/manifest.py). An empty key
    # leaves every manifest unsigned. The key is any value of at least 32 bytes.
    # The file variant wins when both are set.
    evidence_signing_key: str = ""
    evidence_signing_key_file: str = ""

    # The regulatory retention period in days for raw files, side-store files
    # and manifests. None turns the period tier off, and 0 is a period of 0
    # days. A file is deleted only when the graph-count tier and this period
    # both allow it.
    evidence_retention_days: int | None = None

    # The HST map tables.
    # `hst_history_days` unset keeps the delta tables, layout and bindings.
    # `hst_sim_ttl_s` is the idle time in seconds before a simulation directory is swept.
    # `hst_context_cap` is the number of contexts drawn per chassis before the "+N" tier.
    hst_history_days: int | None = None
    hst_compact_after_days: int = 90
    hst_tier_checkpoint_every: int = 30
    hst_sim_ttl_s: int = 86_400
    hst_context_cap: int = 16

    # The folder of the synthetic demo estate (fixtures/demo-enterprise, in the image
    # /usr/share/hst/demo-enterprise). When it is set, an admin can load it from the Runs page as
    # a `demo` run (app/demo_estate.py). When it is unset, the `demo` run source does not exist.
    hst_demo_fixtures: Path | None = None

    # deploy/Containerfile sets this to the git SHA in the image.
    hst_build_revision: str = "unknown"

    # The name of the estate that this deployment models. Every published
    # manifest holds it in `SnapshotManifest.estate`.
    estate_name: str = "default"

    # Root logger setup (core/logsetup.py). "json" writes one object per line.
    hst_log_level: str = "INFO"
    hst_log_format: Literal["text", "json"] = "text"
    # The sources with HTTP exchange tracing, as comma-separated source row
    # names, or `*` for every source. An empty value traces nothing. A traced
    # fetch records every request and response beside its raw file
    # (collectors/http_trace.py).
    hst_http_trace: str = ""

    def http_trace_enabled(self, source: str) -> bool:
        wanted = {name.strip() for name in self.hst_http_trace.split(",") if name.strip()}
        return "*" in wanted or source in wanted

    # Collection debug capture limits (core/debug_capture.py). A parse step that
    # runs longer than `hst_debug_stack_after_s` gets a stack dump of every thread.
    # The default of 20 s is below the liveness kill of the pod after 5 failed
    # probes 15 s apart. A re-parse runs in a child process under a wall-clock
    # limit and, on Linux, an address-space limit of the mapped size of the child
    # plus `hst_debug_reparse_memory_mb`.
    hst_debug_stack_after_s: float = 20.0
    hst_debug_capture_hours: int = 24
    hst_debug_reparse_memory_mb: int = 1024
    hst_debug_reparse_timeout_s: int = 120

    # Whether `hst serve` and `hst worker` apply Alembic migrations on start-up.
    #
    # With True, processes that start together all migrate, and pg_advisory_lock
    # in migrations/env.py serializes them.
    #
    # The Helm chart sets this false and runs migrations in a Job that must
    # succeed before any pod rolls.
    hst_run_migrations: bool = True

    @property
    def raw_dir(self) -> Path:
        return self.hst_data_dir / "raw"

    @property
    def sidestore_dir(self) -> Path:
        return self.hst_data_dir / "sidestore"

    @property
    def manifests_dir(self) -> Path:
        return self.hst_data_dir / "manifests"

    @property
    def graph_archives_dir(self) -> Path:
        return self.hst_data_dir / "graph-archives"
