"""Collector base and registry.

A collection fetches raw objects, writes the raw snapshot, normalizes the
objects into a Batch and loads the Batch with scope-based retirement. The raw
snapshot is the audit trail, and a collector does not transform the objects
during the fetch. A collector writes no derived edges and no facts of another
source.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator

from hst.app import crypto
from hst.core import Settings, debug_capture, jsonstream, rawstore, redaction
from hst.core.config import DEFAULT_L2_FABRIC
from hst.core.identity import DeviceResolver, MemoryResolver
from hst.core.loader import CHUNK, SessionLike, load
from hst.core.manifest import file_facts
from hst.core.model import (
    DEGRADING_SECTION_STATUSES,
    DEGRADING_TABLE_STATUSES,
    Batch,
    RunManifest,
    SectionOutcome,
    TableOutcome,
)

from . import http, http_trace, streams

# (path, sha256 of the bytes written, byte count), called once per file a
# collection writes.
OnWrite = Callable[[Path, str, int], None]

# `raw_sha` excludes this reserved key of a raw payload.
RAW_OUTCOMES_KEY = "_strata_outcomes"


class CollectionStopped(RuntimeError):
    """The run of this fetch or load was cancelled or lost its lock.

    `Collector.check_stop` raises it before the next request, command, load
    stage or side-table row group."""


# Device properties an orchestrator sets to say where its management plane
# puts the device.
REPORTED_LOCATION_PROP = "reported_location"
REPORTED_LOCATION_NAME_PROP = "reported_location_name"

logger = logging.getLogger(__name__)


class SourceConfig(BaseModel):
    site_code: str = "home"
    """The code of the Site where the devices are located (LOCATED_IN)."""

    routing_scope: str | None = Field(
        None,
        title="Routing scope",
        description="Sources with the same scope treat same-named VRFs as one "
        "network. Leave empty to use the site code.",
        validation_alias=AliasChoices("routing_scope", "l3dom"),
    )
    """Empty means the site_code."""

    interval_s: int = Field(
        default=0,  # mypy's dataclass_transform view needs `default` as a keyword
        title="Collection interval (seconds)",
        description="Collect this group's devices every this many seconds. "
        "0 leaves the group to full cycles only.",
    )
    """Per-group cadence for the per-device job path (worker/scheduler.py
    `fanout_collect`): every enabled device of this group gets one
    `collect.fetch` job each interval, with per-device failure backoff. 0 (the
    default) means no per-device jobs."""

    capture_bgp: Literal["all", "sessions", "none"] = Field(
        default="all",  # mypy's dataclass_transform view needs `default` as a keyword
        title="BGP observation capture",
        description="Which BGP observations to read from this source's devices: "
        "all (observed session state and the per-session path tables), sessions "
        "(observed session state only), or none.",
    )
    """What a collector of this source reads into the BGP side-store tables
    (`core/sidestore.py` `bgp_sessions` and `bgp_session_routes`). `sessions`
    keeps the session state and drops the per-peer path commands. `none` drops
    both. Whatever is not captured is recorded as a `not-captured` table outcome."""

    source_name: str = ""  # set by the platform from the row name
    l2fabric: str | None = Field(
        default=None,
        title="L2 fabric",
        description="Canonical bridging identity, or null to inherit.",
    )
    resolved_origins: dict[str, str] = Field(default_factory=dict, exclude=True)

    @field_validator("routing_scope", "l2fabric")
    @classmethod
    def _canonical_domain(cls, value: str | None) -> str | None:
        if value is not None and value != "" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", value):
            raise ValueError("must be a canonical identifier with . _ : - and no spaces")
        return value

    @property
    def effective_routing_scope(self) -> str:
        return self.routing_scope or self.site_code

    @property
    def effective_l2fabric(self) -> str:
        return self.l2fabric or DEFAULT_L2_FABRIC


class Collector(ABC):
    """One management plane. Subclasses set `name`, a ConfigModel, and implement
    fetch/normalize/probe. `scope` is derived from config in __init__."""

    name: str = ""  # e.g. "unifi"
    scope: str = ""  # retirement partition, e.g. "unifi:default"
    ConfigModel: ClassVar[type[SourceConfig]] = SourceConfig
    # True when this collector writes its own `CollectionProgress`.
    reports_progress: ClassVar[bool] = False

    @classmethod
    def link_sources(cls, payload: dict[str, Any], sources: Mapping[str, Any]) -> dict[str, Any]:
        """Write into `payload` what this source needs from the other configured
        source rows, before the config model is built (app/sources.py
        `build_collector`).

        `sources` maps a row name to the row. A row holds `type` and the
        non-secret `config`. A collector sees the configuration of another
        source only here. A source that names another source resolves that
        name here, as the site row fills in the normalization fields. The
        default links nothing and returns `payload` unchanged.
        """
        return payload

    def normalization_inputs(self) -> dict[str, Any] | None:
        """Data outside the payload and the configuration that decides what
        the payload normalizes to, for the change hash (`raw_sha`).

        A collector that resolves part of its identity from the data of another
        source returns that data here. A change in that data defeats the
        unchanged-payload skip, and the device is loaded again. The base
        returns the generation of the device identity registry. The rename
        command increments the generation. After a rename, every device loads
        again at the next run and writes the uid that the registry holds. A
        collector that adds its own inputs merges them with these.
        """
        return {"identity_generation": self.identity.identity_generation()}

    # A "group" collector has one credential domain and one device per target,
    # and its configuration holds a device list. An "orchestrator" collector
    # polls one API-style system for many devices and has no device list. Each
    # collector class declares its kind. Check Point and NetScaler both name a
    # `host` and are different kinds.
    KIND: ClassVar[Literal["group", "orchestrator"]]

    # The per-table `parser_version` of the snapshot manifest (core/model.py `TableOutcome`).
    PARSER_VERSION: ClassVar[str] = "1"

    # The semantic versions of the graph-producing enrichments that a collector
    # opts into. A version change defeats fetch-level skipping even when the
    # device payload is equal.
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {}

    # Command outcome keys that enter the content hash.
    NORMALIZATION_OUTCOME_KEYS: ClassVar[tuple[str, ...]] = ()
    NORMALIZATION_CONFIG_KEYS: ClassVar[tuple[str, ...]] = ()

    # Top-level raw keys excluded from the change hash (`raw_sha`). Their values
    # differ on every fetch while the device state stays the same, such as a
    # timestamp that a controller stamps into its export. A collector that
    # declares no key hashes its whole payload.
    #
    # A fetch whose `raw_sha` and `obs_sha` both match the record skips
    # normalize and the load (app/runs_exec.py). A key here must therefore feed
    # no node, relationship or property of the graph other than a
    # VOLATILE_GRAPH_PROPS one, or feed it only through another key that the
    # hash covers (the Cisco `_strata_dynamic_bgp` projection of the BGP
    # session summaries). What the key feeds in the side tables or in the
    # status of a section must also be declared as an observation key (below),
    # which `obs_sha` covers. A key that the graph reads stays in the hash,
    # however often it changes, an uptime line included. The batch digest
    # (`graph_sha`) skips the graph write of such a payload.
    VOLATILE_RAW_KEYS: ClassVar[tuple[str, ...]] = ()

    # Top-level raw keys that hold the current observations of the device.
    # A key here that is not volatile stays in `raw_sha` too.
    OBSERVATION_RAW_KEYS: ClassVar[tuple[str, ...]] = ()

    # The same two declarations for raw keys a fetch derives from what it
    # reads, such as one BGP path command per configured peer, which no fixed
    # tuple can list. A top-level key the pattern matches in full is treated
    # exactly as a key listed in VOLATILE_RAW_KEYS or OBSERVATION_RAW_KEYS.
    # None matches nothing. Both are read with `getattr`. A collector-shaped
    # object without them hashes as a collector that declares none.
    VOLATILE_RAW_KEY_PATTERN: ClassVar[re.Pattern[str] | None] = None
    OBSERVATION_RAW_KEY_PATTERN: ClassVar[re.Pattern[str] | None] = None

    # Graph properties, per node label or relationship type, whose values
    # differ on every fetch while the device stays the same, such as the poll
    # time that a controller stamps on its objects. The batch digest
    # (`graph_sha`) leaves them out. A change in them alone causes no graph
    # write. They are written whenever their object is written. Between two
    # writes, a carried object holds the values of the last write. The forced
    # full load (`Settings.collect_full_interval_s`) bounds the age of those
    # values. The mapping is read with `getattr`, as the raw-key declarations
    # are.
    VOLATILE_GRAPH_PROPS: ClassVar[dict[str, tuple[str, ...]]] = {}

    # Side-store tables this collector also mirrors into the graph, subject to
    # `Settings.rib_graph_max_routes`.
    GRAPH_MIRRORED_TABLES: ClassVar[tuple[str, ...]] = ()

    # Payload sections that the twin requires (core/model.py `section_verdict`).
    AUTHORITATIVE_SECTIONS: ClassVar[tuple[str, ...]] = ()

    # Maps a section name to the graph labels that only that section produces.
    # It is read when a device collects `partial`. The objects of the failed
    # optional section are carried forward from the parent run and stamped
    # `carried_reason` `section-failed`.
    #
    # A label that two sections write is not declared here.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {}

    # Every declared side-store table gets a `TableOutcome` on the run manifest.
    SIDE_TABLES: ClassVar[tuple[str, ...]] = ()

    # Maps a side-store table to the sections whose commands feed it. A table
    # with no rows is `complete-empty` only when every feeding section
    # answered. A feeding section that failed, was refused or did not parse
    # makes an empty table `failed`. A table with rows and a feeding section
    # that did not answer is `partial` (`_write_side_tables`). A table absent
    # from the map is judged on its rows alone.
    TABLE_SECTIONS: ClassVar[dict[str, tuple[str, ...]]] = {}

    def __init__(self, config: SourceConfig, settings: Settings):
        self.config = config
        self.settings = settings  # raw_dir for execute()
        # The device identity registry. Every Device uid that this collector
        # writes comes from it. The platform sets the Postgres registry on the
        # collectors of a run (app/runs_exec.py `_arm_identity`). The default
        # registry is in memory, and a collector built in a test resolves
        # without Postgres.
        self.identity: DeviceResolver = MemoryResolver()
        self.last_device_uids: list[str] | None = None
        # The stop flag of the run or of its source (`runs_exec.RunStop`). The
        # run builder sets it before a fetch (app/runs_exec.py `_arm_stop`). The
        # flag is raised when an operator cancels the run or the source, or when
        # the cycle lock is lost. A long fetch polls it through `check_stop`
        # between requests. A load reads it between its stages (`_check_stop`)
        # and between the row groups of each side table it writes. It is None
        # for a probe or a standalone fetch.
        self.stop: threading.Event | None = None
        self.last_device_facts: dict[str, dict[str, Any]] | None = None
        # Maps a device uid to the (location id, display name) that the source
        # system reports.
        self.last_device_locations: dict[str, tuple[str, str]] | None = None

    def check_stop(self) -> None:
        """Raise `CollectionStopped` once the run asked this fetch to stop. A
        collector that makes many requests calls it before each one."""
        if self.stop is not None and self.stop.is_set():
            raise CollectionStopped("collection cancelled")

    @abstractmethod
    def fetch(self) -> Any:
        """Pull raw objects from the management plane (no transformation)."""

    async def afetch(self) -> Any:
        return await asyncio.to_thread(self.fetch)

    @abstractmethod
    def normalize(self, raw: Any) -> Batch:
        """Convert a raw payload to a typed Batch. Only this method interprets vendor semantics."""

    @abstractmethod
    def probe(self) -> str:
        """Check connectivity with a login and a version fetch. A probe collects and loads nothing."""

    def side_tables(self, raw: Any) -> dict[str, Sequence[dict[str, Any]]]:
        """Return the high-churn rows (RIB, ARP or MAC style) per side-store
        table name. The rows are keyed to graph uids and are too many for the
        graph. The default returns no table."""
        return {}

    def table_outcomes(self, raw: Any) -> dict[str, TableOutcome]:
        """What this collector states about tables beyond the rows it produced.

        A table that the run did not request reads `not-captured`.

        The statements apply over the write outcomes (`_write_side_tables`).
        A table that this collector wrote rows for keeps the outcome of the
        write. The default states nothing.
        """
        return {}

    def table_feeds(self, raw: Any) -> Mapping[str, tuple[str, ...]]:
        """Map each table to the sections of this payload that feed it.

        The default returns `TABLE_SECTIONS`. A collector whose section names
        depend on the payload overrides it. VyOS reads one routing table per
        configured policy table."""
        return self.TABLE_SECTIONS

    def release_payload(self) -> None:
        """Drop whatever this collector cached about the payload it last read.

        `normalize`, `sections` and `side_tables` can share one parse of a
        payload through a per-instance cache. The cache holds the payload. The
        run keeps the collector of every unit until it publishes.
        `load_payload` and `load_observations` call this method when a load
        returns or raises. The default caches nothing and drops nothing.
        """
        return None


REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    kind = getattr(cls, "KIND", None)
    if kind not in ("group", "orchestrator"):
        raise TypeError(f"collector {cls.name!r} must set KIND to 'group' or 'orchestrator'")
    REGISTRY[cls.name] = cls
    return cls


def new_run_id(fetch_ts_ms: int | None = None) -> str:
    """The identity of one fetch: `<fetch_ts_ms>-<nonce>`."""
    ts = fetch_ts_ms if fetch_ts_ms is not None else int(time.time() * 1000)
    return f"{ts}-{uuid.uuid4().hex[:8]}"


def _key_matches(pattern: re.Pattern[str] | None, key: object) -> bool:
    """Whether `pattern` matches the top-level raw key `key` in full. A key
    that is not a str does not match, and a None pattern matches no key."""
    return pattern is not None and isinstance(key, str) and pattern.fullmatch(key) is not None


def raw_sha(collector: Collector, raw: Any) -> str:
    """Content hash of a fetch's payload, for fetch-level change detection.

    A hash equal to the record means that the graph inputs of the payload
    are already loaded. The batch digest (`graph_sha`) of the device would
    match too, and the payload need not be normalized. This holds because the
    graph reads no volatile key (`Collector.VOLATILE_RAW_KEYS`). After a
    mismatch, the payload is normalized and its batch digest decides.

    The hash covers the canonical JSON (sorted keys) of the payload without
    the VOLATILE_RAW_KEYS of the collector, the keys that its
    VOLATILE_RAW_KEY_PATTERN matches and the reserved outcomes key. It also
    covers the normalization context.

    The digest is that of `json.dumps(..., sort_keys=True, default=str,
    separators=(",", ":"))`, the text that every stored hash covers.
    `jsonstream.sha256_json` hashes the text while it encodes it. A payload
    with a command answer of hundreds of megabytes is not held a second time
    as JSON.
    """
    body = raw
    if isinstance(raw, dict):
        skip = {*collector.VOLATILE_RAW_KEYS, RAW_OUTCOMES_KEY}
        volatile = getattr(collector, "VOLATILE_RAW_KEY_PATTERN", None)
        body = {k: v for k, v in raw.items() if k not in skip and not _key_matches(volatile, k)}
    config = collector.config
    settings = getattr(collector, "settings", None)
    source_name = getattr(config, "source_name", "")
    configured_fabric = getattr(config, "l2fabric", None)
    context = {
        "site_code": getattr(config, "site_code", None),
        "routing_scope": getattr(config, "effective_routing_scope", None),
        "l2fabric": settings.l2fabric_of(source_name, configured_fabric)
        if settings is not None
        else configured_fabric,
        "resolver_version": "1",
    }
    versions = getattr(collector, "NORMALIZATION_VERSIONS", {})
    if versions:
        context["normalization_versions"] = dict(versions)
        context["parser_version"] = collector.PARSER_VERSION
    if hasattr(config, "capture_mtu"):
        context["capture_mtu"] = config.capture_mtu
    config_keys = getattr(collector, "NORMALIZATION_CONFIG_KEYS", ())
    if config_keys:
        context["normalization_config"] = {key: getattr(config, key) for key in sorted(config_keys)}
    inputs = getattr(collector, "normalization_inputs", None)
    if callable(inputs):
        extra = inputs()
        if extra:
            context["normalization_inputs"] = extra
    outcome_keys = getattr(collector, "NORMALIZATION_OUTCOME_KEYS", ())
    if outcome_keys and isinstance(raw, dict):
        outcomes = raw.get(RAW_OUTCOMES_KEY)
        if isinstance(outcomes, dict):
            context["normalization_outcomes"] = {k: outcomes.get(k) for k in sorted(outcome_keys)}
    return jsonstream.sha256_json(
        {"payload": body, "normalization_context": context},
        sort_keys=True,
        separators=(",", ":"),
        max_depth=2,
    )


def obs_sha(collector: Collector, raw: Any) -> str:
    """Content hash of a fetch's observations alone, for the observation-level
    change detection `raw_sha` cannot do.

    Canonical JSON (sorted keys) over exactly the collector's
    `OBSERVATION_RAW_KEYS` that the payload carries and the keys its
    `OBSERVATION_RAW_KEY_PATTERN` matches, and nothing else.

    The hash is the empty string for a collector that declares neither
    observation keys nor an observation pattern, and for a payload that is
    not a mapping.
    """
    keys: tuple[str, ...] = tuple(getattr(collector, "OBSERVATION_RAW_KEYS", ()))
    pattern = getattr(collector, "OBSERVATION_RAW_KEY_PATTERN", None)
    if not isinstance(raw, dict) or not (keys or pattern is not None):
        return ""
    body = {k: raw[k] for k in keys if k in raw}
    if pattern is not None:
        body.update((k, v) for k, v in raw.items() if _key_matches(pattern, k))
    return jsonstream.sha256_json(body, sort_keys=True, separators=(",", ":"), max_depth=1)


def graph_sha(collector: Collector, batch: Batch) -> str:
    """Content digest of a normalized batch. The change detection
    (app/runs_exec.py) compares it to decide whether the graph of a payload
    is written.

    The digest covers what the loader writes. It covers the source and the
    scope of the batch, the label, uid and properties of each node, and the
    type, ends, key and properties of each relationship, without the
    `VOLATILE_GRAPH_PROPS` of the collector. It is the sha256 of one line per
    item. A line is the text of `json.dumps(item, sort_keys=True,
    default=str, separators=(",", ":"))` and a newline. The first line is
    `{"scope": ..., "source": ...}`. Each node follows as `[label, uid,
    props]` in (label, uid) order. Each relationship follows as `[type, start
    label, start uid, end label, end uid, key, props]`, ordered by all fields
    except the properties. The order in which a collector built the batch
    does not change the digest. The order of a list inside a property changes
    it, because that order can be significant (the entries of a policy).

    The digest does not cover the sections and warnings of the batch or the
    stamps of the load (run id, times). The loader writes the sections and
    warnings into no graph object. The run records them from the batch
    whether or not the batch is written. The stamps differ on every write.

    The batch is hashed one item at a time. The batch of a large device is
    not held a second time as text.
    """
    volatile: Mapping[str, Sequence[str]] = getattr(collector, "VOLATILE_GRAPH_PROPS", None) or {}
    encode = json.JSONEncoder(sort_keys=True, default=str, separators=(",", ":")).encode
    digest = hashlib.sha256()

    def line(item: Any) -> None:
        digest.update(encode(item).encode())
        digest.update(b"\n")

    def props(name: str, values: dict[str, Any]) -> dict[str, Any]:
        drop = volatile.get(name)
        return {k: v for k, v in values.items() if k not in drop} if drop else values

    line({"scope": batch.scope, "source": batch.source})
    for n in sorted(batch.nodes, key=lambda n: (n.label, n.uid)):
        line([n.label, n.uid, props(n.label, n.props)])
    for r in sorted(
        batch.rels,
        key=lambda r: (r.rel_type, r.start_label, r.start_uid, r.end_label, r.end_uid, encode(r.key)),
    ):
        ends = [r.rel_type, r.start_label, r.start_uid, r.end_label, r.end_uid]
        line([*ends, r.key, props(r.rel_type, r.props)])
    return digest.hexdigest()


def _identity(collector: Collector, source_name: str | None) -> tuple[str, str]:
    """Return (source, host), the two path segments of the files of a payload.

    `source` is the name of the source row, for example `vyos1`. It can
    differ from the collector type name in the batch (`vyos`). Without
    `source_name`, it falls back to `collector.config.source_name`, which the
    platform sets when it builds a collector, and then to the collector type
    for a standalone or test collector without a source row. `host` is
    `collector.config.host` when the ConfigModel has one. The config of a
    per-device fleet collector holds the host of its device. A controller
    type has no host, and its files use the one-level layout without a host.
    """
    source = source_name or str(getattr(collector.config, "source_name", "") or "") or collector.name
    return source, str(getattr(collector.config, "host", "") or "")


def fetch_traced(
    collector: Collector, source_name: str | None = None
) -> tuple[Any, http_trace.HttpTrace | None]:
    """Run `collector.fetch()`, with an HTTP exchange trace when the settings
    enable one for this source (`Settings.http_trace_enabled`).

    The trace is active only during the fetch and in the thread that runs it.
    Every client that `collectors.http.client` builds in that time records
    into it. A fetch that raises discards its trace. After a fetch returns,
    the caller hands the trace to `execute`, `execute_observations` or
    `park`. They seal it beside the raw file once the run id exists.
    """
    settings = getattr(collector, "settings", None)
    source = source_name or _identity(collector, None)[0]
    with http.fetching(source, getattr(settings, "collect_max_answer_mb", None)):
        if settings is None or not settings.hst_http_trace or not settings.http_trace_enabled(source):
            return collector.fetch(), None
        trace = http_trace.HttpTrace(source, settings.raw_dir, redaction.secret_values(collector.config))
        try:
            with http_trace.activate(trace):
                raw = collector.fetch()
        except BaseException:
            trace.discard()
            raise
        return raw, trace


def _seal_trace(collector: Collector, trace: http_trace.HttpTrace | None, raw_path: Path) -> None:
    """Seal the trace of the fetch beside its raw file.

    The trace is debugging evidence about the collection. It is not reported
    to the run manifest and is no input to the graph or the side store. No
    replay reads it."""
    if trace is None:
        return
    path = trace.seal(raw_path, crypto.dek(collector.settings))
    logger.info("http trace: %d exchanges of %s sealed at %s", trace.exchanges, trace.source, path)


def _compress_level(collector: Collector) -> int | None:
    """The gzip level the raw file of this collector's payload is written at
    (`Settings.raw_compress_level`). The level is read with `getattr`. A
    settings object without the field (a test double) writes at the default
    level of the raw store."""
    level: int | None = getattr(collector.settings, "raw_compress_level", None)
    return level


def park(
    collector: Collector,
    raw: Any,
    *,
    source_name: str | None = None,
    fetch_ts_ms: int | None = None,
    on_write: OnWrite | None = None,
    kind: str = rawstore.KIND_FULL,
    trace: http_trace.HttpTrace | None = None,
    hashes: dict[str, str] | None = None,
    fetch_finished_ms: int | None = None,
) -> Path:
    """Write one fetched payload to the raw store without joining it to a run.

    Returns the path of the raw file. Its stem is the run id that
    `load_payload` later receives.

    `on_write` reports the written file. The per-device fetch path passes no
    `on_write`. A parked payload belongs to the run that later joins it, and
    the manifest of that run records the file (app/runs_exec.py
    `build_device_run`).

    `kind` sets how the device run applies the payload
    (`rawstore.mark_kind`). The default `full` means normalize, load and side
    tables. `observation` means side tables only.

    `fetch_finished_ms` is the end time of the fetch. It is kept in the
    sidecar beside the start time in the run id
    (`rawstore.read_park_finished`). It is kept only with a `fetch_ts_ms`.
    Without `fetch_ts_ms`, the run id holds the park time.
    """
    source, host = _identity(collector, source_name)
    run_id = new_run_id(fetch_ts_ms)
    path = rawstore.write(
        collector.settings.raw_dir,
        source,
        run_id,
        raw,
        host=host,
        key=crypto.dek(collector.settings),
        level=_compress_level(collector),
    )
    _seal_trace(collector, trace, path)
    rawstore.mark_kind(
        path,
        kind,
        {
            "site_code": collector.config.site_code,
            "routing_scope": collector.config.effective_routing_scope,
            "l2fabric": collector.settings.l2fabric_of(
                collector.config.source_name, collector.config.l2fabric
            ),
            "origins": collector.config.resolved_origins,
            "resolver_version": "1",
        },
        hashes,
        fetch_finished_ms=fetch_finished_ms if fetch_ts_ms is not None else None,
    )
    _report(on_write, path)
    return path


def spill(
    collector: Collector,
    raw: Any,
    *,
    source_name: str | None = None,
    fetch_ts_ms: int | None = None,
) -> rawstore.Spilled:
    """Seal one fetched payload to a spill file ahead of its load
    (`rawstore.spill`), under the run id and key `execute` would use.

    The fetch window of the cycle (app/runs_exec.py) keeps a large payload in
    a spill file until the serial load reaches it. The load hands the handle
    to `execute` or `execute_observations` as `sealed`. They move the file to
    its raw path. A spill file that the load never reaches is removed with
    `rawstore.drop_spill`. `fetch_ts_ms` is the start of the fetch. The run
    id is built from it, as from the start in the `fetch_window` of
    `execute`.
    """
    source, host = _identity(collector, source_name)
    return rawstore.spill(
        collector.settings.raw_dir,
        source,
        new_run_id(fetch_ts_ms),
        raw,
        host=host,
        key=crypto.dek(collector.settings),
        level=_compress_level(collector),
    )


def _adopt(sealed: rawstore.Spilled) -> Path:
    """Call `rawstore.adopt` for `execute` and `execute_observations`.

    A spill file that cannot be moved to its raw path is removed before the
    error propagates."""
    try:
        return rawstore.adopt(sealed)
    except BaseException:
        rawstore.drop_spill(sealed)
        raise


def _report(on_write: OnWrite | None, path: Path) -> None:
    if on_write is None:
        return
    sha, size = file_facts(path)
    on_write(path, sha, size)


def _release(collector: Collector) -> None:
    """End one load's hold on its payload (`Collector.release_payload`).

    Read with `getattr`, so a collector-shaped object without the method (a
    test double) loads with nothing released."""
    fn = getattr(collector, "release_payload", None)
    if callable(fn):
        fn()


def _check_stop(collector: Collector) -> None:
    """Call `Collector.check_stop` between two stages of a load.

    A stopped run ends the running load at its next stage. The method is read
    with `getattr`, as `_release` reads its method."""
    fn = getattr(collector, "check_stop", None)
    if callable(fn):
        fn()


@dataclass(frozen=True)
class GraphGate:
    """What a load compares its normalized batch against (`load_payload`).

    `matches` answers whether a batch digest (`graph_sha`) is the one on
    record for the device, bound as the record is. `parent_ts` is the run the
    run being built stands on, whose graph holds the device's objects as its
    batch last wrote them and from which the carry brings forward whatever a
    matching batch does not write.
    """

    matches: Callable[[str], bool]
    parent_ts: int


# Finds the nodes of an unchanged batch that are not the device's alone
# (`_shared_uids`). The load writes such a node even though the batch digest
# matches the record. Another source or device writes the same uid, for
# example a device uid that APIC and NX-OS both resolve from one serial, a
# broadcast domain that every switch of a fabric declares, a route target or
# a first-hop redundancy group. The carry never copies a node that another
# writer has already written in the run being built. The carry lays the
# assertions of the device over such a node only where the parent run records
# the device as one of its writers (core/cycle.py `_carry_contributions`).
# The load writes the properties of the device, its assertions and its entry
# in `_sources` exactly (core/loader.py `assertion_props`).
#
# A node is the device's alone when the parent run (`$prev`) holds it with
# the scope of this batch as its first writer, with no other source and with
# no relationship of another collector scope, and when no load of the run
# being built (`$cts`) has written it yet. A node that the parent run does
# not hold is written too, because the carry cannot copy it. The
# relationships of the reasoner, the derivations and the site assignments
# belong to no collector and do not count as a second writer.
SHARED_OBJECTS = """
UNWIND $uids AS uid
OPTIONAL MATCH (p:Obj {uid: uid, collection_ts: $prev})
OPTIONAL MATCH (n:Obj {uid: uid, collection_ts: $cts})
WITH uid, p, n
WHERE p IS NULL
   OR coalesce(p._scope, '') <> $scope
   OR any(s IN coalesce(p._sources, []) WHERE s <> $source)
   OR (n IS NOT NULL AND coalesce(n.carried, false) = false)
   OR EXISTS {
        MATCH (p)-[r]-()
        WHERE r._scope <> $scope AND r._scope <> 'reasoner'
          AND NOT any(prefix IN $derived WHERE r._scope STARTS WITH prefix)
      }
RETURN uid
"""

# The scope prefixes of what writes relationships without being a collector:
# core/reasoner.py (`derived:`), the site assignments (`app:sites`) and the
# run meta nodes (`meta:`). The rule reasoner's own scope is `reasoner`.
DERIVED_SCOPE_PREFIXES = ("derived:", "app:", "meta:")


def _shared_uids(session: SessionLike, batch: Batch, *, prev: int, cts: int) -> set[str]:
    """Return the uids of `batch` that `SHARED_OBJECTS` finds shared.

    The uids are read in chunks of the loader size (`CHUNK`). The query only
    reads. It runs in a write transaction, as the anchor check of the loader
    runs."""
    uids = sorted({n.uid for n in batch.nodes})
    params = {
        "prev": prev,
        "cts": cts,
        "scope": batch.scope,
        "source": batch.source,
        "derived": list(DERIVED_SCOPE_PREFIXES),
    }
    shared: set[str] = set()
    for i in range(0, len(uids), CHUNK):
        chunk = uids[i : i + CHUNK]
        rows = session.execute_write(
            lambda tx, chunk=chunk: tx.run(SHARED_OBJECTS, uids=chunk, **params).data()
        )
        shared.update(str(row["uid"]) for row in rows)
    return shared


def _shared_part(batch: Batch, shared: set[str]) -> Batch:
    """Return the part of an unchanged batch that its load writes.

    The part holds the nodes in `shared`, every node with an `anchor`
    property, and every relationship whose ends are both kept.

    An anchored node is written whether or not another writer shares it. The
    cycle-wide identity check (core/loader.py `_check_cycle_anchors`) then
    sees the anchors of the device in the run being built. A load that
    declares one of the uids under another anchor fails the run, whichever of
    the two loads comes first, as between two written batches. The check
    does not see a carried copy, and the carry would attach the relationships
    of the device to the object of the other load.

    A relationship with an end left out comes forward with that end, which
    the carry copies from the parent run (core/cycle.py `_READ_CARRY_RELS`).
    """
    shared = shared | {n.uid for n in batch.nodes if n.props.get("anchor") is not None}
    left = {n.uid for n in batch.nodes if n.uid not in shared}
    return batch.model_copy(
        update={
            "nodes": [n for n in batch.nodes if n.uid in shared],
            "rels": [r for r in batch.rels if r.start_uid not in left and r.end_uid not in left],
        }
    )


def load_payload(
    collector: Collector,
    session: SessionLike,
    raw: Any,
    *,
    collection_ts: int,
    run_id: str,
    ts_ms: int,
    source_name: str | None = None,
    on_write: OnWrite | None = None,
    graph_gate: GraphGate | None = None,
) -> RunManifest:
    """Normalize a payload already in the raw store and load it into `collection_ts`.

    `run_id` and `ts_ms` are the parked payload's own fetch identity and fetch
    time. The run key is the `snapshot_ts` column.

    `source_name` overrides `batch.source`.

    `on_write` is called once per side-store file that this load writes, for
    the file list of the manifest. The raw file is not reported here.
    `execute` or `park` wrote it before this call.

    The returned manifest holds a `TableOutcome` for every side-store table
    that the collector declares. The outcome exists whether the table wrote
    a file, wrote nothing because the device had no rows, or failed to
    write. The manifest also holds the digest of the normalized batch
    (`graph_sha`).

    When `graph_gate` is given, the load asks it whether that digest is the
    one on record for this device. On a match, the parent run
    (`GraphGate.parent_ts`) already holds what the load would write. The
    load then writes only the shared part of the batch (`_shared_part`). The
    shared part holds the nodes that another source or device also writes
    (`SHARED_OBJECTS`), the nodes with an anchor, and the relationships
    between those. The shared nodes get the merged state and assertions that
    a load of the whole batch would give them. The rest comes forward from
    the parent run through the carry, and the run marks the scope of the
    device `unchanged` (app/runs_exec.py). The manifest then has
    `graph_unchanged` set, the counters of the shared part, and the sections
    and warnings of the batch. The side tables are written as after a full
    load, because the payload is new.

    A stopped run ends the load at its next stage (`Collector.check_stop`).
    The stages start before normalize, before the graph write, before the
    side tables and before each row group of a side table.

    The per-payload caches of the collector are released when this function
    returns or raises (`Collector.release_payload`). No later phase of the
    run reads the parse of this payload again.
    """
    source, host = _identity(collector, source_name)
    try:
        with debug_capture.capture(
            getattr(collector, "settings", None),
            source=source,
            host=host,
            run_id=run_id,
            collector=collector.name,
            raw=raw,
        ):
            return _load_payload(
                collector,
                session,
                raw,
                source,
                host,
                collection_ts=collection_ts,
                run_id=run_id,
                ts_ms=ts_ms,
                source_name=source_name,
                on_write=on_write,
                graph_gate=graph_gate,
            )
    finally:
        _release(collector)


def _load_payload(
    collector: Collector,
    session: SessionLike,
    raw: Any,
    source: str,
    host: str,
    *,
    collection_ts: int,
    run_id: str,
    ts_ms: int,
    source_name: str | None,
    on_write: OnWrite | None,
    graph_gate: GraphGate | None,
) -> RunManifest:
    _check_stop(collector)
    with debug_capture.step("normalize"):
        batch = collector.normalize(raw)
    collector.last_device_uids = sorted({n.uid for n in batch.nodes if n.label == "Device"})
    collector.last_device_facts = {
        n.uid: {
            "hostname": str(n.props.get("hostname") or n.props.get("name") or ""),
            "platform": str(n.props.get("platform") or ""),
            "management_address": str(n.props.get("mgmt_ip") or n.props.get("management_address") or ""),
            "warnings": [
                w
                for w in batch.warnings
                if n.uid in w or (n.props.get("hostname") and str(n.props["hostname"]) in w)
            ],
        }
        for n in batch.nodes
        if n.label == "Device"
    }
    collector.last_device_locations = {
        n.uid: (
            str(n.props[REPORTED_LOCATION_PROP]),
            str(n.props.get(REPORTED_LOCATION_NAME_PROP) or n.props[REPORTED_LOCATION_PROP]),
        )
        for n in batch.nodes
        if n.label == "Device" and n.props.get(REPORTED_LOCATION_PROP)
    }
    if source_name:
        batch = batch.model_copy(update={"source": source_name})
    with debug_capture.step("graph_digest") as out:
        digest = graph_sha(collector, batch)
        unchanged = graph_gate is not None and graph_gate.matches(digest)
        out["unchanged"] = unchanged
    _check_stop(collector)
    if graph_gate is not None and unchanged:
        # The whole batch is checked as a load would check it. A batch that
        # this build refuses is refused whether or not it is written.
        batch.validate_registry()
        with debug_capture.step("shared_objects") as out:
            part = _shared_part(
                batch, _shared_uids(session, batch, prev=graph_gate.parent_ts, cts=collection_ts)
            )
            out.update(nodes=len(part.nodes), rels=len(part.rels))
        if part.nodes or part.rels:
            with debug_capture.step("load", nodes=len(part.nodes), rels=len(part.rels)):
                manifest = load(session, part, run_id=run_id, ts_ms=ts_ms, collection_ts=collection_ts)
        else:
            manifest = RunManifest(
                run_id=run_id,
                source=batch.source,
                scope=batch.scope,
                finished_ms=ts_ms,
                sections=batch.sections,
            )
        manifest.graph_unchanged = True
        del part
    else:
        with debug_capture.step("load", nodes=len(batch.nodes), rels=len(batch.rels)):
            manifest = load(session, batch, run_id=run_id, ts_ms=ts_ms, collection_ts=collection_ts)
    manifest.graph_sha = digest
    # the batch's own warnings, then the load's (core/loader.py rival_warnings)
    manifest.warnings = [*batch.warnings, *manifest.warnings]
    sections = dict(batch.sections)
    del batch
    _check_stop(collector)
    manifest.tables = _write_side_tables(
        collector,
        raw,
        source,
        host,
        run_id=run_id,
        collection_ts=collection_ts,
        on_write=on_write,
        sections=sections,
    )
    return manifest


def load_observations(
    collector: Collector,
    raw: Any,
    *,
    collection_ts: int,
    run_id: str,
    ts_ms: int,
    source_name: str | None = None,
    on_write: OnWrite | None = None,
) -> RunManifest:
    """Write one payload's side-store tables and nothing else.

    The returned manifest holds zero node and relationship counters, the
    section outcomes of `sections` (the Cisco families), and the table outcomes.

    `run_id` and `ts_ms` are the fetch identity and the fetch time of the
    payload, as in `load_payload`. `collection_ts` is the run that the tables
    join. The per-payload caches of the collector are released when this
    function returns or raises, as in `load_payload`. A stopped run ends it
    before the side tables or within one row group of the table being written
    (`Collector.check_stop`).
    """
    source, host = _identity(collector, source_name)
    manifest = RunManifest(
        run_id=run_id,
        source=source_name or source,
        scope=str(getattr(collector, "scope", "") or ""),
        finished_ms=ts_ms,
    )
    try:
        with debug_capture.capture(
            getattr(collector, "settings", None),
            source=source,
            host=host,
            run_id=run_id,
            collector=collector.name,
            raw=raw,
        ):
            # Read with `getattr`, as the parse report of offline.py reads it.
            # Only the collectors that parse a payload apart from normalizing
            # it define `sections`. `side_tables` reuses the parse that
            # `sections` runs.
            sections_fn = getattr(collector, "sections", None)
            if callable(sections_fn):
                with debug_capture.step("sections"):
                    manifest.sections = sections_fn(raw)
            _check_stop(collector)
            manifest.tables = _write_side_tables(
                collector,
                raw,
                source,
                host,
                run_id=run_id,
                collection_ts=collection_ts,
                on_write=on_write,
                sections=manifest.sections,
            )
    finally:
        _release(collector)
    return manifest


def execute_observations(
    collector: Collector,
    *,
    raw: Any = None,
    sealed: rawstore.Spilled | None = None,
    collection_ts: int,
    source_name: str | None = None,
    on_write: OnWrite | None = None,
    fetch_window: tuple[int, int] | None = None,
    trace: http_trace.HttpTrace | None = None,
) -> RunManifest:
    """Store an already-fetched payload and publish its observations alone.

    `sealed` is a payload the caller already sealed to a spill file (`spill`).
    """
    if (raw is None) == (sealed is None):
        raise TypeError("execute_observations takes exactly one of raw and sealed")
    if sealed is not None:
        started = sealed.fetch_ts_ms
        run_id = sealed.run_id
        raw_path = _adopt(sealed)
    else:
        started = fetch_window[0] if fetch_window is not None else int(time.time() * 1000)
        run_id = new_run_id(started)
        source, host = _identity(collector, source_name)
        raw_path = rawstore.write(
            collector.settings.raw_dir,
            source,
            run_id,
            raw,
            host=host,
            key=crypto.dek(collector.settings),
            level=_compress_level(collector),
        )
    _seal_trace(collector, trace, raw_path)
    rawstore.mark_joined(raw_path, snapshot_ts=collection_ts)
    _report(on_write, raw_path)
    if sealed is not None:
        raw = rawstore.read(raw_path, crypto.dek(collector.settings))
    return load_observations(
        collector,
        raw,
        collection_ts=collection_ts,
        run_id=run_id,
        ts_ms=started,
        source_name=source_name,
        on_write=on_write,
    )


def _write_side_tables(
    collector: Collector,
    raw: Any,
    source: str,
    host: str,
    *,
    run_id: str,
    collection_ts: int,
    on_write: OnWrite | None,
    sections: Mapping[str, SectionOutcome] | None = None,
) -> dict[str, TableOutcome]:
    """Write the side-store tables of the load and return the outcome of each.

    A side-store problem never fails a load that wrote the graph.

    Every table that the collector declares in `SIDE_TABLES` gets an outcome.
    A table that the collector produced rows for without declaring it gets
    one too. A table with no rows reads `complete-empty` and writes no file.

    The statements of `table_outcomes` fill in the rest. A table that this
    run did not capture reads `not-captured`. A table whose feature the
    device does not have reads `unsupported`. An observation recorded per
    session and direction joins the mapping under its own key.

    The feeding sections of a table (`Collector.table_feeds`) are judged from
    `sections`, the section outcomes of the payload. A table with no rows and
    no statement reads `failed` when a feeding section did not answer
    (failed, unauthorized or malformed). The command that would have produced
    the rows gave no answer. A table written with rows reads `partial` when a
    feeding section did not answer, or when the collector states it `failed`
    or `partial`. Its rows are true, and part of the table is missing.

    A row that the collector cannot build fails the load. The values that
    `side_tables` returns can be row views (`streams.MappedRows`) that build
    each row while the table is written. A parse failure then raises
    `streams.RowMappingError` in the middle of a write. This function raises
    its original exception, as when `side_tables` itself raises. The tables
    that this call already wrote are removed. A file is reported through
    `on_write` only after every table is written. A load that fails this way
    leaves no side-store file and reports none.

    A stopped run ends the write the same way. `sidestore.write_table` reads
    the stop flag of the collector (`Collector.check_stop`) before the rows
    of each row group. A lazy view builds its rows, and the BGP paths of a
    full-table device are parsed, while the table is written. This function
    raises the `CollectionStopped`, removes the tables that this call already
    wrote, and reports none.
    """
    with debug_capture.step("side_tables") as out:
        produced = collector.side_tables(raw)
        out["rows"] = {table: len(rows or []) for table, rows in produced.items()}
    with debug_capture.step("table_outcomes"):
        stated = collector.table_outcomes(raw)
    names = sorted({*collector.SIDE_TABLES, *produced})
    if not names and not stated:
        return {}
    unread = unread_table_feeds(collector, raw, sections or {})
    try:
        from hst.core import sidestore
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        logger.warning("[sidestore] skipped: %s", detail)
        failed = {
            table: TableOutcome(status="failed", detail=detail, row_count=len(produced.get(table) or []))
            for table in names
        }
        # A statement for a key outside `names` and a `not-captured` statement
        # stay as the collector stated them when the side store is missing.
        for name, outcome in stated.items():
            if name not in names or outcome.status == "not-captured":
                failed[name] = outcome
        return failed

    outcomes: dict[str, TableOutcome] = {}
    published: list[Path] = []
    failure: BaseException | None = None
    # Read with `getattr`, as `_check_stop` reads it.
    check = getattr(collector, "check_stop", None)
    with debug_capture.step("write_side_tables") as out:
        for table in names:
            rows = produced.get(table) or []
            if not rows:
                outcomes[table] = stated.get(table) or empty_table_outcome(unread.get(table))
                continue
            try:
                written = sidestore.write_table(
                    collector.settings.sidestore_dir,
                    table,
                    source,
                    host,
                    run_id,
                    rows,
                    snapshot_ts=collection_ts,
                    row_group_rows=collector.settings.sidestore_row_group_rows,
                    check=check if callable(check) else None,
                )
            except CollectionStopped as exc:
                # A stopped run fails the load.
                failure = exc
                break
            except streams.RowMappingError as exc:
                # A row parse failure fails the load (see the docstring).
                failure = exc.original
                break
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                logger.warning("[sidestore] skipped: %s", detail)
                outcomes[table] = TableOutcome(status="failed", detail=detail, row_count=len(rows))
                continue
            if written is None:  # write_table found no rows and created no file
                outcomes[table] = empty_table_outcome(unread.get(table))
                continue
            published.append(written)
            outcomes[table] = written_table_outcome(
                len(rows),
                _store_path(written, collector.settings.hst_data_dir),
                unread.get(table),
                stated.get(table),
            )
        if failure is not None:
            for path in published:
                with contextlib.suppress(OSError):
                    path.unlink()
            # The exception is raised outside the handler. It keeps the cause and
            # the context it was raised with and gains none. The traceback holds
            # this frame, and `finally` clears the frame's reference to the
            # exception.
            try:
                raise failure
            finally:
                failure = None
        out["outcomes"] = {table: outcome.status for table, outcome in outcomes.items()}
    for path in published:
        _report(on_write, path)
    # The finer-grained statements apply last, only to keys that the write
    # loop left free. A per-session direction outcome has no table of its own.
    for name, outcome in stated.items():
        outcomes.setdefault(name, outcome)
    return outcomes


def unread_table_feeds(
    collector: Collector, raw: Any, sections: Mapping[str, SectionOutcome]
) -> dict[str, str]:
    """Map each table with a feeding section (`Collector.table_feeds`) that
    did not answer to the text "section=status, ..." of those sections."""
    unread: dict[str, str] = {}
    # Read with `getattr`. A collector stand-in in a test need not derive
    # from `Collector`.
    feeds = getattr(collector, "table_feeds", None)
    for table, feeding in (feeds(raw) if callable(feeds) else {}).items():
        bad = [
            f"{name}={sections[name].status}"
            for name in feeding
            if name in sections and sections[name].status in DEGRADING_SECTION_STATUSES
        ]
        if bad:
            unread[table] = ", ".join(bad)
    return unread


def empty_table_outcome(unread: str | None) -> TableOutcome:
    """A table with no rows: `complete-empty` when every feeding section
    answered, `failed` naming the ones that did not."""
    if unread:
        return TableOutcome(status="failed", detail=f"feeding section did not answer: {unread}")
    return TableOutcome(status="complete-empty", row_count=0)


def written_table_outcome(
    rows: int, path: str, unread: str | None, stated: TableOutcome | None
) -> TableOutcome:
    """A table whose rows were written: `complete`, or `partial` when a feeding
    section did not answer or the collector states that part of it failed."""
    reasons = []
    if unread:
        reasons.append(f"feeding section did not answer: {unread}")
    if stated is not None and stated.status in DEGRADING_TABLE_STATUSES:
        reasons.append(stated.detail or f"stated {stated.status} by the collector")
    if reasons:
        return TableOutcome(status="partial", detail="; ".join(reasons), row_count=rows, path=path)
    return TableOutcome(status="complete", row_count=rows, path=path)


def _store_path(path: Path, base: Path) -> str:
    """Return a written file as a POSIX path relative to the data directory.

    A file outside the data directory (a caller with its own store
    directory) returns its own path. The snapshot manifest records the same
    path per file."""
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def execute(
    collector: Collector,
    session: SessionLike,
    *,
    collection_ts: int | None = None,
    source_name: str | None = None,
    raw: Any | None = None,
    on_write: OnWrite | None = None,
    fetch_window: tuple[int, int] | None = None,
    trace: http_trace.HttpTrace | None = None,
    sealed: rawstore.Spilled | None = None,
    graph_gate: GraphGate | None = None,
) -> RunManifest:
    """Fetch a payload, store it raw, normalize it and load it.

    `collection_ts` is the shared version key of the cycle. The cycle
    orchestration passes it, and a standalone call stamps its own. The run
    id is built from the fetch time alone (`new_run_id`). `collection_ts` is
    recorded as the `snapshot_ts` under which the raw file and its
    side-store rows are joined.

    `source_name` is the name of the source row (`_identity`). It overrides
    `batch.source`.

    `raw` is a payload already fetched by the caller. None keeps the fetch
    inline.

    `fetch_window` is (fetch start, fetch finish) in epoch milliseconds, for a
    caller that hands in a fetched `raw`. `new_run_id` and the `ts_ms` of the
    load are stamped from the fetch start. It is ignored when `raw` is None.
    A `raw` without a window is stamped with the current time.

    `sealed` is a fetched payload that the caller already sealed to a spill
    file (`spill`). It replaces `raw`. The file is moved to the raw path that
    `rawstore.write` would have written. Its trace is sealed, and the file is
    joined and reported as a written raw file is. The payload is read back
    from the file for the load. The run id and `ts_ms` are the ones the spill
    was sealed under, built from the same fetch start as `fetch_window`. A
    spill file that cannot be moved is removed before the error propagates.
    Passing both `raw` and `sealed` raises a TypeError.

    `on_write` is called once per file this collection writes (the raw file
    and each side-store table) for the snapshot manifest's file list.

    `graph_gate` is handed to `load_payload`, which writes only the shared
    part of a normalized batch whose digest is the one on record. The raw
    file is written and joined in both cases. `graph_gate` is passed on only
    when given. Without it, `load_payload` is called without the keyword.
    """
    if raw is not None and sealed is not None:
        raise TypeError("execute takes at most one of raw and sealed")
    if sealed is not None:
        ts = sealed.fetch_ts_ms
        cts = collection_ts if collection_ts is not None else ts
        run_id = sealed.run_id
        raw_path = _adopt(sealed)
    else:
        if raw is None:
            started = int(time.time() * 1000)
            raw, trace = fetch_traced(collector, source_name)
        elif fetch_window is not None:
            started = fetch_window[0]
        else:
            started = int(time.time() * 1000)
        ts = started
        cts = collection_ts if collection_ts is not None else ts
        run_id = new_run_id(ts)
        source, host = _identity(collector, source_name)
        # Sealed with the same key as source credentials (rawstore docstring).
        raw_path = rawstore.write(
            collector.settings.raw_dir,
            source,
            run_id,
            raw,
            host=host,
            key=crypto.dek(collector.settings),
            level=_compress_level(collector),
        )
    _seal_trace(collector, trace, raw_path)
    rawstore.mark_joined(raw_path, snapshot_ts=cts)
    _report(on_write, raw_path)
    if sealed is not None:
        raw = rawstore.read(raw_path, crypto.dek(collector.settings))
    gate = {"graph_gate": graph_gate} if graph_gate is not None else {}
    return load_payload(
        collector,
        session,
        raw,
        collection_ts=cts,
        run_id=run_id,
        ts_ms=ts,
        source_name=source_name,
        on_write=on_write,
        **gate,
    )
