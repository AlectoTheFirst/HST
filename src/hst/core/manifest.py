"""The snapshot manifest is the evidence record of one published run."""

from __future__ import annotations

import contextlib
import hashlib
import heapq
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from neo4j import Session
from pydantic import BaseModel, Field, SerializerFunctionWrapHandler, model_serializer

from hst import __version__

from . import diff
from .config import Settings
from .cycle import stream_rows
from .model import SectionOutcome, TableOutcome
from .ribsource import run_ts  # noqa: F401  (a re-export for the callers that parse a run id)

if TYPE_CHECKING:
    import pyarrow as pa

# Every field after version 1 has a default.
#
#   2            `FileEntry.carried` and the operator's site assignments.
#   3            the fetch window of a device (`fetch_started_ms`,
#                `fetch_finished_ms`), the clock of the source
#                (`source_clock_ms`) with `clock_quality`, `clock_source` and
#                `clock_assumption`, `ingested_ms` and `expected_sections`.
#                `observed_ms` and `parser_version` of each side-store table
#                entry. `schema_version` of each file entry
#                (`sidestore.SCHEMA_VERSIONS`).
#   4            the encrypted graph archive.
#   5            `stretch_observations` and `warnings`.
#   6            each device entry's `verified_started_ms` and `verified_ms`.
#   7            `site_blocks`. Only a run that stamps at least one device writes it
#                (`SITE_BLOCKS_SCHEMA_VERSION`).
SCHEMA_VERSION = 6
SITE_BLOCKS_SCHEMA_VERSION = 7
READABLE_SCHEMA_VERSIONS = (1, 2, 3, 4, 5, 6, 7)
SUFFIX = ".json"
SIG_SUFFIX = ".sig"

# A manifest whose chain index is a multiple of `CHECKPOINT_EVERY` holds a
# full-state checkpoint.
CHECKPOINT_EVERY = 24

# `redact_config` replaces the value of a config key whose lowercased name
# contains one of these parts. The match applies at every depth of the
# configuration. The key stays.
REDACTED_KEY_PARTS = (
    "auth",
    "bearer",
    "community",
    "cookie",
    "credential",
    "key",
    "otp",
    "pass",
    "preshared",
    "private",
    "psk",
    "secret",
    "session",
    "token",
)
REDACTED = "[redacted]"

_RAW_SUFFIX = ".json.gz.enc"
_META_SUFFIX = ".meta.json"
_PARQUET_SUFFIX = ".parquet"
_RUN_ID = re.compile(r"^(?P<ts>\d+)-(?P<nonce>[0-9a-fA-F]{6,})$")


# --- canonical form and digests ---------------------------------------------------------


# The encoder behind `canonical_json` holds no state between calls.
_CANONICAL = json.JSONEncoder(sort_keys=True, default=str, separators=(",", ":"))
# `_CANONICAL_PRESORTED` renders the same bytes for a mapping whose keys are in
# sorted order at every depth (`RowDigests`).
_CANONICAL_PRESORTED = json.JSONEncoder(sort_keys=False, default=str, separators=(",", ":"))


def canonical_json(obj: Any) -> bytes:
    """Return `obj` as canonical JSON bytes.

    The keys are sorted and the output has no whitespace. `str` renders a
    value that JSON cannot render.
    """
    return _CANONICAL.encode(obj).encode()


def digest_bytes(data: bytes) -> str:
    """Return the SHA-256 of `data` as lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def canonical_digest(obj: Any) -> str:
    """Return the SHA-256 of `canonical_json(obj)` as lowercase hex."""
    return digest_bytes(canonical_json(obj))


def file_facts(path: Path) -> tuple[str, int]:
    """Return the SHA-256 hex digest and the byte count of the file on disk."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while block := fh.read(1024 * 1024):
            h.update(block)
            size += len(block)
    return h.hexdigest(), size


def rows_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    """Return the SHA-256 over the rows in canonical order.

    Each row is reduced to the SHA-256 of its canonical JSON. The hashes are
    sorted and each hash is followed by a newline.
    """
    return _combine(digest_bytes(canonical_json(dict(row))) for row in rows)


def _combine(items: Iterable[str]) -> str:
    """SHA-256 over a sorted, newline-joined list of per-item digests."""
    with _Buckets() as buckets:
        for item in items:
            buckets.add(item)
        return buckets.digest()


# A bucket of `_Buckets` holds this many per-item digests before it spills to a
# temporary file.
DIGEST_BUCKET_ITEMS = 100_000


class _Buckets:
    """Combines per-item digests into `_combine`'s value in bounded buckets.

    `digest` consumes the runs and may be called once.
    """

    def __init__(self, bucket: int = DIGEST_BUCKET_ITEMS) -> None:
        self._bucket = max(1, bucket)
        self._held: list[str] = []
        self._runs: list[IO[str]] = []
        self.count = 0

    def add(self, item: str) -> None:
        self._held.append(item)
        self.count += 1
        if len(self._held) >= self._bucket:
            self._spill()

    def _spill(self) -> None:
        run: IO[str] = tempfile.TemporaryFile("w+", encoding="ascii", newline="\n")  # noqa: SIM115
        run.writelines(f"{item}\n" for item in sorted(self._held))
        run.seek(0)
        self._runs.append(run)
        self._held = []

    def digest(self) -> str:
        h = hashlib.sha256()
        self._held.sort()
        merged: Iterable[str] = self._held
        if self._runs:
            runs: list[Iterator[str]] = [(line.rstrip("\n") for line in run) for run in self._runs]
            merged = heapq.merge(*runs, self._held)
        for item in merged:
            h.update(item.encode())
            h.update(b"\n")
        return h.hexdigest()

    def close(self) -> None:
        for run in self._runs:
            with contextlib.suppress(OSError):
                run.close()
        self._runs = []
        self._held = []

    def __enter__(self) -> _Buckets:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# `RowDigests` converts this many rows to Python values at a time.
# `sidestore_row_facts` reads a file in batches of this size.
ROW_DIGEST_SLICE = 8192


def _renders_flat(data_type: pa.DataType) -> bool:
    """Whether every value of a column of `data_type` converts to a Python value
    that holds no mapping.

    A row of such columns with its keys in sorted order renders to the same
    bytes with `_CANONICAL_PRESORTED` and with `_CANONICAL`.
    """
    import pyarrow as pa

    if pa.types.is_dictionary(data_type):
        return _renders_flat(data_type.value_type)
    return not pa.types.is_nested(data_type) and not isinstance(data_type, pa.BaseExtensionType)


class RowDigests:
    """Compute the row count and the `rows_digest` of arrow record batches that
    are added one at a time.

    A row is the mapping that `RecordBatch.to_pylist` gives for it. The row is
    reduced to the SHA-256 of its canonical JSON as soon as it is built. The
    digests are combined in bounded buckets (`_Buckets`). The value equals the
    value of `rows_digest` over the same rows. At most `ROW_DIGEST_SLICE` rows
    are held as Python values at once.

    A batch whose columns all render flat (`_renders_flat`) and have distinct
    names is converted column by column, in sorted column order, and rendered
    with `_CANONICAL_PRESORTED`. The bytes equal those of `canonical_json`
    over the same row. Any other batch is converted with `to_pylist` and
    rendered with the sorting encoder.

    `digest` may be called once. `close` and the context manager release the
    temporary files of the buckets.
    """

    def __init__(self) -> None:
        self._buckets = _Buckets()

    @property
    def count(self) -> int:
        return self._buckets.count

    def add(self, batch: pa.RecordBatch) -> None:
        names = batch.schema.names
        ordered = sorted(names)
        flat = (
            bool(names)
            and len(set(names)) == len(names)
            and all(_renders_flat(field.type) for field in batch.schema)
        )
        buckets = self._buckets
        encode = _CANONICAL_PRESORTED.encode
        for start in range(0, batch.num_rows, ROW_DIGEST_SLICE):
            part = batch.slice(start, ROW_DIGEST_SLICE)
            if not flat:
                for row in part.to_pylist():
                    buckets.add(digest_bytes(canonical_json(row)))
                continue
            columns = [column.to_pylist() for column in part.select(ordered).columns]
            for values in zip(*columns, strict=True):
                row_json = encode(dict(zip(ordered, values, strict=True)))
                buckets.add(hashlib.sha256(row_json.encode()).hexdigest())

    def digest(self) -> str:
        return self._buckets.digest()

    def close(self) -> None:
        self._buckets.close()

    def __enter__(self) -> RowDigests:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def sidestore_row_facts(path: Path) -> tuple[int, str]:
    """Return the row count and the `rows_digest` of a side-store parquet file on disk."""
    import pyarrow.parquet as pq

    with RowDigests() as digests, pq.ParquetFile(path) as reader:
        for batch in reader.iter_batches(batch_size=ROW_DIGEST_SLICE):
            digests.add(batch)
        return digests.count, digests.digest()


def redact_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """A source configuration with every credential-bearing value replaced by
    `[redacted]`, at every depth.
    """
    out: dict[str, Any] = {}
    for key, value in config.items():
        name = str(key)
        if any(part in name.lower() for part in REDACTED_KEY_PARTS):
            out[name] = REDACTED
        elif isinstance(value, Mapping):
            out[name] = redact_config(value)
        elif isinstance(value, list):
            out[name] = [redact_config(v) if isinstance(v, Mapping) else v for v in value]
        else:
            out[name] = value
    return out


def source_config_digest(name: str, type_: str, enabled: bool, config: Mapping[str, Any]) -> str:
    """Return the digest of one source.

    The digest is the SHA-256 of the canonical JSON of the name, the type, the
    enabled flag and the redacted configuration of the source.
    """
    return canonical_digest(
        {"name": name, "type": type_, "enabled": enabled, "config": redact_config(config)}
    )


# --- the record -------------------------------------------------------------------------


class FileEntry(BaseModel):
    """One raw or side-store file written into this snapshot.

    `path` is relative to the data directory. `sha256` covers the bytes on
    disk. The side-store-only fields are null on a raw entry.

    `carried` is false for a file that this run wrote and true for a file that
    an earlier run wrote.
    """

    kind: str  # "raw" or "sidestore"
    path: str
    sha256: str
    bytes: int
    source: str
    host: str
    run_id: str
    table: str | None = None
    row_count: int | None = None
    rows_sha256: str | None = None
    cap: int | None = None
    truncated: bool | None = None
    graph_mirrored: bool | None = None
    carried: bool = False
    # The schema version of the side-store table at write time
    # (`sidestore.SCHEMA_VERSIONS`). The value is null on a raw entry and on a
    # side-store entry of a manifest before schema version 3.
    schema_version: int | None = None
    # The sorted `device_uid` values of the rows in the side-store file. The
    # value is null on a raw entry, on a table without the column and on an
    # entry recorded without it. `SidestoreFiles` returns an entry with a null
    # value for every device of its table.
    device_uids: list[str] | None = None


# The side-store tables that hold the BGP path observations and the BGP
# session observations (core/sidestore.py).
BGP_ROUTES_TABLE = "bgp_session_routes"
BGP_SESSIONS_TABLE = "bgp_sessions"
# The side-store table that holds the OSPF link-state database
# (core/sidestore.py).
OSPF_LSDB_TABLE = "ospf_lsdb"


def ospf_context_key(context_uid: str) -> str:
    """Return the `DeviceEntry.tables` key of the link-state database of one
    forwarding context. The format is `ospf_lsdb/<context_uid>`.
    """
    return f"{OSPF_LSDB_TABLE}/{context_uid}"


def ospf_context_outcomes(tables: Mapping[str, TableOutcome]) -> dict[str, TableOutcome]:
    """Return the outcome per context uid for the per-context entries of the
    table outcomes of one device. Any other key is skipped."""
    prefix = f"{OSPF_LSDB_TABLE}/"
    return {
        key[len(prefix) :]: outcome
        for key, outcome in tables.items()
        if key.startswith(prefix) and key != prefix
    }


def bgp_direction_key(session_uid: str, direction: str) -> str:
    """Return the `DeviceEntry.tables` key of one direction of one session.

    The format is `bgp_session_routes/<session_uid>/<direction>`. The
    direction is `received`, `accepted` or `advertised`.
    """
    return f"{BGP_ROUTES_TABLE}/{session_uid}/{direction}"


def bgp_direction_outcomes(tables: Mapping[str, TableOutcome]) -> dict[tuple[str, str], TableOutcome]:
    """Return the outcome per (session_uid, direction) for the per-session
    direction entries of the table outcomes of one device.
    """
    out: dict[tuple[str, str], TableOutcome] = {}
    prefix = f"{BGP_ROUTES_TABLE}/"
    for key, outcome in tables.items():
        if not key.startswith(prefix):
            continue
        body = key[len(prefix) :]
        if "/" not in body:
            continue
        session_uid, direction = body.rsplit("/", 1)
        if session_uid:
            out[(session_uid, direction)] = outcome
    return out


class DeviceEntry(BaseModel):
    """One device of the run.

    `outcome` is "collected", "partial", "unchanged", "failed" or "carried".
    A "partial" device was collected and did not answer for at least one
    section (`sections`). An "unchanged" device was fetched, its payload hash
    matched and its objects were carried. The source of a "carried" device did
    not run in this snapshot.
    `raw_sha256` is the fetch-level payload hash (`collectors/base.py
    raw_sha`).
    `effective_run` is the run whose payload provides the state of this device
    in this snapshot. It is resolved from the join sidecars of the raw store
    (`effective_runs`). It is null, with `carried` true, for a device with no
    payload in any run at or before this snapshot.

    `sections` holds the outcome of each section of the collection of the
    device. It is empty for a device that this run did not collect and for a
    collector that reports no per-section outcomes.

    `tables` holds the outcome of each side-store table that the collector of
    the device declares, `complete-empty` included.

    `tables` also holds the per-session, per-direction outcomes of the BGP
    session tables. `bgp_direction_key` builds the keys and
    `bgp_direction_outcomes` reads them. A direction that the platform cannot
    expose (a received table with no soft reconfiguration inbound) is recorded
    as `not-captured`.

    `fetch_started_ms` and `fetch_finished_ms` are the start and the end of
    the fetch. `fetch_ts_ms` is parsed from the run id. `ingested_ms` is the
    time at which this run loaded the payload. `source_clock_ms` is the clock
    of the device at capture. `clock_quality`, `clock_source` and
    `clock_assumption` hold the basis for trust in that clock or in the fetch
    window of the collector. `expected_sections` holds the sections that the
    collector declares (the `SECTIONS` keys of the Cisco families). For a
    collector without a declaration (VyOS) it holds the section names of the
    recorded outcomes. `sections` is checked against it.
    `tables[t].observed_ms` holds the fetch start and
    `tables[t].parser_version` holds the `PARSER_VERSION` of the collector.
    All are null or empty on a device entry of a manifest before schema
    version 3.

    `device_uids` is the exact set of `Device.uid` values that this source
    unit produced. A carried entry keeps the values of the preceding manifest.
    """

    source: str
    host: str
    outcome: str
    fetch_ts_ms: int | None = None
    fetch_started_ms: int | None = None
    fetch_finished_ms: int | None = None
    source_clock_ms: int | None = None
    clock_quality: Literal["unknown", "uncertain", "trusted"] = "unknown"
    clock_source: str = ""
    clock_assumption: str = ""
    # The fetch window of the latest run that fetched this device and found
    # its payload unchanged.
    verified_started_ms: int | None = None
    verified_ms: int | None = None
    ingested_ms: int | None = None
    raw_sha256: str | None = None
    error: str = ""
    effective_run: str | None = None
    carried: bool = False
    sections: dict[str, SectionOutcome] = Field(default_factory=dict)
    expected_sections: list[str] = Field(default_factory=list)
    tables: dict[str, TableOutcome] = Field(default_factory=dict)
    device_uids: list[str] = Field(default_factory=list)
    # The retirement partition of the device. A paused target has no collector
    # that can rebuild it.
    scope: str = ""
    # The snapshot key, as text, of the run whose load of this device failed
    # after the load began to write. The objects of the device are then a mix
    # of 2 configurations. The value is copied while the device keeps that
    # state and is cleared by the next full load that succeeds
    # (app/runs_exec.py `_device_entries`).
    mixed_since: str | None = None

    @model_serializer(mode="wrap")
    def _omit_unset_mark(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data = handler(self)
        if isinstance(data, dict) and data.get("mixed_since") is None:
            data.pop("mixed_since", None)
        return data


class SourceEntry(BaseModel):
    name: str
    type: str
    status: str
    config_sha256: str


class GraphDelta(BaseModel):
    """The digest of what this snapshot changed against the previous one.

    `sha256` is null on the first snapshot of a chain and when the diff could
    not be read. `note` holds the reason. `detail_truncated` is true when a
    bucket of `core/diff.py` holds more than `diff.DETAIL_CAP` entries. The
    digest then covers the full counts and the first `diff.DETAIL_CAP` entries
    of each bucket.
    """

    previous_snapshot: int | None = None
    sha256: str | None = None
    counts: dict[str, dict[str, int]] = Field(default_factory=dict)
    detail_truncated: bool = False
    note: str = ""


class Checkpoint(BaseModel):
    """A digest of the full open state at this snapshot, written every
    `CHECKPOINT_EVERY` manifests. `sha256` is null when the state could not be
    read. `note` holds the reason."""

    sha256: str | None = None
    nodes: int = 0
    rels: int = 0
    note: str = ""


class PreviousLink(BaseModel):
    """The link to the previous manifest of the chain.

    It holds the key of the previous published snapshot, the digest of its
    manifest file and its chain index. `SnapshotManifest.previous` is null on
    the first manifest.
    """

    snapshot_key: int
    sha256: str
    chain_index: int


class GraphArchiveEntry(BaseModel):
    """The immutable encrypted archive of this snapshot's finalized graph."""

    path: str
    sha256: str
    bytes: int
    snapshot_key: int
    format_version: int
    graph_schema_version: int
    chunks: int
    nodes: int
    rels: int
    # The normalization context holds no secret and serves diagnosis. The
    # archive is authoritative.
    normalization_context: dict[str, Any] = Field(default_factory=dict)
    normalization_context_sha256: str


class StretchObservation(BaseModel):
    """One VLAN id on one Equinix Fabric circuit, as read by the `vlan-stretch`
    check of the reasoner (`hst/reasoner/vlan_stretch.py`).

    `kind` is `stretched`, `translated`, `one-sided` or `port-based`. `vid` is
    the VLAN id at the A end and `vid_z` is the VLAN id at the Z end. The 2
    values differ on a translated pair. `tag_a` and `tag_z` are the tags of
    the circuit per side and are null on an untagged circuit. `observed_macs`
    is the count of MAC addresses in the `mac` table that corroborate the
    observation. It is null when the side store could not answer. The
    manifest holds these entries from schema version 5.
    """

    circuit: str
    kind: str
    vid: int
    vid_z: int
    tag_a: int | None = None
    tag_z: int | None = None
    port_a: str
    port_z: str
    device_a: str | None = None
    device_z: str | None = None
    site_a: str | None = None
    site_z: str | None = None
    observed_macs: int | None = None


class SnapshotManifest(BaseModel):
    """The evidence record of one published snapshot.

    The file `<manifests_dir>/<snapshot_key>.json` holds `canonical_json` of
    this model. The file `<snapshot_key>.sig` in the same directory holds the
    signature when a signer is configured.
    """

    schema_version: int = SCHEMA_VERSION
    snapshot_key: int
    kind: str
    parent: int | None = None
    opened: str
    published: str
    app_version: str = __version__
    build_revision: str = ""
    # The estate this snapshot was published for (`Settings.estate_name`).
    estate: str = "default"
    chain_index: int = 0
    previous: PreviousLink | None = None
    sources: list[SourceEntry] = Field(default_factory=list)
    devices: list[DeviceEntry] = Field(default_factory=list)
    files: list[FileEntry] = Field(default_factory=list)
    # The site assignments of the operator that this snapshot applied, as a
    # map of device uid to site code. A cleared assignment is absent.
    site_assignments: dict[str, str] = Field(default_factory=dict)
    # The named blocks of the operator that this snapshot stamped on its Device
    # nodes (`core/cycle.py apply_site_blocks`), as a map of device uid to
    # [block name, zone or null]. The field belongs to schema version 7. It is
    # empty on an earlier manifest and on a run with no block.
    site_blocks: dict[str, tuple[str, str | None]] = Field(default_factory=dict)
    # The value is null on a manifest before schema version 4.
    graph_archive: GraphArchiveEntry | None = None
    graph_delta: GraphDelta = Field(default_factory=GraphDelta)
    checkpoint: Checkpoint | None = None
    # `stretch_observations` holds the observations of the vlan-stretch check
    # of the reasoner in this run. `warnings` holds the warnings of the loads
    # and of the derivations of the run. Both fields belong to schema version
    # 5 and are empty on an earlier manifest. `stretch_observations` is empty
    # on an estate with no Fabric circuits.
    stretch_observations: list[StretchObservation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _omit_empty_site_blocks(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Drop the `site_blocks` key when the run stamped no device. The record then has the
        bytes and the digest of a version 6 manifest (`SITE_BLOCKS_SCHEMA_VERSION`)."""
        data = handler(self)
        if isinstance(data, dict) and not data.get("site_blocks"):
            data.pop("site_blocks", None)
        return data


class Signature(BaseModel):
    """The content of `<snapshot_key>.sig`."""

    algorithm: str
    key_id: str
    public_key: str
    digest: str
    signature: str


def iso(ts_ms: int) -> str:
    """Return milliseconds since the epoch as a UTC ISO-8601 string, in the
    format that `core/cycle.py` uses for a run key."""
    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC).isoformat(timespec="seconds")


def now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds")


# --- files of a run ---------------------------------------------------------------------


def _relative(path: Path, base: Path) -> str:
    """Return `path` as a POSIX string relative to `base`.

    A path outside `base` is returned as its own POSIX string. The replay
    cache and the fixture loader pass such a path.
    """
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _identity(path: Path, base: Path, depth: int) -> tuple[str, str, str]:
    """Return (source, host, run_id) from a store path.

    `depth` is the count of path segments before the source directory. It is 0
    for the raw store (`<source>/<host>/<run_id>`) and 1 for the side store,
    where the table name is the first segment. The path of a source without a
    host (a controller type) has no host segment, and the host is ''.
    """
    parts = path.resolve().relative_to(base.resolve()).parts
    body = parts[depth:]
    run_id = path.name.split(".", 1)[0]
    source = body[0] if body else ""
    host = body[1] if len(body) > 2 else ""
    return source, host, run_id


def file_entry(
    settings: Settings,
    path: Path,
    *,
    sha: str = "",
    size: int = -1,
    mirrored_tables: Sequence[str] = (),
) -> FileEntry:
    """Describe one written file for the manifest.

    `sha` and `size` are the digest and the byte count of the file when the
    writer computed them (`on_write` of `collectors/base.py` reports both).
    They are read from disk when the caller passes none. The row count and the
    row digest of a side-store file come from `sidestore.written_row_facts`
    when this process wrote the file and the file is unchanged on disk. They
    are read back from the file otherwise (`sidestore_row_facts`). Both
    sources give the same values.

    `mirrored_tables` holds the tables that the collector of this file also
    mirrors into the graph (`Collector.GRAPH_MIRRORED_TABLES`).
    `graph_mirrored` is true when the table is in `mirrored_tables` and the
    row count is at most `rib_graph_max_routes`.
    """
    if not sha or size < 0:
        sha, size = file_facts(path)
    if path.name.endswith(_PARQUET_SUFFIX) and _under(path, settings.sidestore_dir):
        from . import sidestore

        source, host, run_id = _identity(path, settings.sidestore_dir, 1)
        table = path.resolve().relative_to(settings.sidestore_dir.resolve()).parts[0]
        row_count, rows_sha = sidestore.written_row_facts(path) or sidestore_row_facts(path)
        devices = sidestore.written_devices(path)
        if devices is None:
            devices = sidestore.file_devices(path)
        cap = settings.rib_graph_max_routes
        mirrors = table in mirrored_tables
        return FileEntry(
            kind="sidestore",
            path=_relative(path, settings.hst_data_dir),
            sha256=sha,
            bytes=size,
            source=source,
            host=host,
            run_id=run_id,
            table=table,
            row_count=row_count,
            rows_sha256=rows_sha,
            cap=cap if mirrors else None,
            truncated=mirrors and row_count > cap,
            graph_mirrored=mirrors and row_count <= cap,
            schema_version=sidestore.SCHEMA_VERSIONS.get(table),
            device_uids=None if devices is None else list(devices),
        )
    source, host, run_id = _identity(path, settings.raw_dir, 0)
    return FileEntry(
        kind="raw",
        path=_relative(path, settings.hst_data_dir),
        sha256=sha,
        bytes=size,
        source=source,
        host=host,
        run_id=run_id,
    )


class SidestoreFiles:
    """The side-store files of a snapshot, by table and device.

    The index is built from the file entries of a manifest. An entry whose
    `FileEntry.device_uids` is null is returned for every device of its table.
    """

    def __init__(self, settings: Settings, files: Iterable[FileEntry]) -> None:
        self._by_device: dict[str, dict[str, set[Path]]] = {}
        self._unlisted: dict[str, set[Path]] = {}
        for entry in files:
            if entry.kind != "sidestore" or entry.table is None:
                continue
            path = settings.hst_data_dir / entry.path
            if entry.device_uids is None:
                self._unlisted.setdefault(entry.table, set()).add(path)
                continue
            by_device = self._by_device.setdefault(entry.table, {})
            for uid in entry.device_uids:
                by_device.setdefault(uid, set()).add(path)

    def files(self, table: str, device_uids: Iterable[str]) -> list[Path]:
        """The files of `table` that can hold rows of `device_uids`, in path order."""
        found = set(self._unlisted.get(table, ()))
        by_device = self._by_device.get(table, {})
        for uid in device_uids:
            found |= by_device.get(uid, set())
        return sorted(found)


def _under(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def effective_runs(
    raw_dir: Path, snapshot_key: int, wanted: Iterable[tuple[str, str]] | None = None
) -> dict[tuple[str, str], str]:
    """Return, per (source, host) directory name, the run whose payload provides
    the state of that device at `snapshot_key`.

    The run is the newest raw file whose join sidecar holds a `snapshot_ts` at
    or before the key. `core/ribsource.py _latest_run_id` makes the same
    selection for side-store files. The sidecars are read from the newest
    fetch to the oldest and the first match is returned.

    Both parts of a key are the slugged directory names.

    `wanted` holds the (source, host) directories to read. None reads all
    directories.
    """
    out: dict[tuple[str, str], str] = {}
    if not raw_dir.is_dir():
        return out
    if wanted is not None:
        for source, host in sorted(set(wanted)):
            leaf = raw_dir / source / host if host else raw_dir / source
            if leaf.is_dir() and (run_id := _newest_joined(leaf, snapshot_key)) is not None:
                out[(source, host)] = run_id
        return out
    for source_dir in sorted(p for p in raw_dir.iterdir() if p.is_dir()):
        leaves = [source_dir, *sorted(p for p in source_dir.iterdir() if p.is_dir())]
        for leaf in leaves:
            host = "" if leaf == source_dir else leaf.name
            run_id = _newest_joined(leaf, snapshot_key)
            if run_id is not None:
                out[(source_dir.name, host)] = run_id
    return out


def _newest_joined(directory: Path, snapshot_key: int) -> str | None:
    candidates = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.name.endswith(_RAW_SUFFIX):
                continue
            run_id = entry.name[: -len(_RAW_SUFFIX)]
            m = _RUN_ID.match(run_id)
            if m:
                candidates.append((int(m["ts"]), run_id))
    for _ts, run_id in sorted(candidates, reverse=True):
        sidecar = directory / (run_id + _META_SUFFIX)
        if not sidecar.is_file():
            continue  # The file is parked or was superseded before it joined a run.
        try:
            joined = json.loads(sidecar.read_text()).get("snapshot_ts")
        except (OSError, ValueError):
            continue
        if isinstance(joined, int) and joined <= snapshot_key:
            return run_id
    return None


# --- graph-derived digests --------------------------------------------------------------


def graph_delta(
    session: Session,
    previous: int | None,
    snapshot_key: int,
    observer: diff.Observer | None = None,
) -> GraphDelta:
    """Digest the delta from the previous published snapshot to this one.

    `core/diff.py diff_snapshots` sorts every bucket that it returns and the
    canonical form sorts every key. The digest is the same in every process.
    The digested body leaves out the 2 snapshot keys.

    `observer` receives every record of the comparison (`core/diff.py Observer`).
    """
    if previous is None:
        return GraphDelta(note="first snapshot of the chain: no previous snapshot to diff against")
    result = diff.diff_snapshots(session, previous, snapshot_key, observer=observer)
    body = {k: result[k] for k in ("counts", "nodes", "rels", "truncated")}
    return GraphDelta(
        previous_snapshot=previous,
        sha256=canonical_digest(body),
        counts=result["counts"],
        detail_truncated=bool(result["truncated"]),
    )


_CHECKPOINT_NODES = (
    "MATCH (n:Obj {collection_ts: $snap}) RETURN n.uid AS uid, labels(n) AS labels, properties(n) AS props"
)
_CHECKPOINT_RELS = (
    "MATCH (a:Obj {collection_ts: $snap})-[r]->(b:Obj) WHERE r.collection_ts = $snap "
    "RETURN type(r) AS t, a.uid AS start, b.uid AS end, properties(r) AS props"
)
# A checkpoint row leaves out these properties. core/diff.py leaves them out
# of a comparison.
_EXCLUDED_PROPS = ("collection_ts", "collected_at", "carried")


def _payload(props: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in props.items() if not k.startswith("_") and k not in _EXCLUDED_PROPS}


def checkpoint(session: Session, snapshot_key: int) -> Checkpoint:
    """Digest the full open state at `snapshot_key`.

    Each node gives one canonical JSON row (uid, sorted labels, payload
    props). Each relationship gives one row (type, both uids, payload props).
    Each row is reduced to its digest inside the read transaction as the
    driver streams it. The digests are sorted and combined in bounded buckets
    (`_Buckets`). The value equals the value of a full sort.

    The driver runs `read` again from the start after a failure that it
    retries. Each attempt digests into its own buckets and counts.
    """

    def read(tx: Any) -> tuple[_Buckets, dict[str, int]]:
        rows = _Buckets()
        counts = {"nodes": 0, "rels": 0}
        try:
            for row in stream_rows(tx, _CHECKPOINT_NODES, snap=snapshot_key):
                rows.add(
                    digest_bytes(
                        canonical_json(
                            {
                                "uid": row["uid"],
                                "labels": sorted(row["labels"]),
                                "props": _payload(row["props"]),
                            }
                        )
                    )
                )
                counts["nodes"] += 1
            for row in stream_rows(tx, _CHECKPOINT_RELS, snap=snapshot_key):
                rows.add(
                    digest_bytes(
                        canonical_json(
                            {
                                "type": row["t"],
                                "start": row["start"],
                                "end": row["end"],
                                "props": _payload(row["props"]),
                            }
                        )
                    )
                )
                counts["rels"] += 1
        except BaseException:
            rows.close()
            raise
        return rows, counts

    rows, counts = session.execute_read(read)
    with rows:
        return Checkpoint(sha256=rows.digest(), nodes=counts["nodes"], rels=counts["rels"])


# --- signing ----------------------------------------------------------------------------


class SignerError(Exception):
    pass


class Signer(Protocol):
    """Signs a manifest digest."""

    def sign(self, digest: bytes) -> tuple[bytes, str] | None:
        """(signature bytes, algorithm tag), or None to leave the manifest
        unsigned. `digest` is the manifest file's SHA-256, as raw bytes."""

    @property
    def key_id(self) -> str:
        """The id of the signing key."""

    @property
    def public_key(self) -> str:
        """The verifying key as hex."""


class AppKeySigner:
    """Sign the manifest digest with Ed25519.

    The key is derived from the evidence signing key of the operator
    (`evidence_signing_key` or `evidence_signing_key_file`). The file is used
    when both are set.
    """

    MIN_KEY_BYTES = 32

    def __init__(self, material: bytes) -> None:
        if len(material) < self.MIN_KEY_BYTES:
            raise SignerError(
                f"evidence signing key is {len(material)} bytes; at least {self.MIN_KEY_BYTES} are "
                "required (HST_EVIDENCE_SIGNING_KEY or HST_EVIDENCE_SIGNING_KEY_FILE; "
                "`hst secret-key` generates a suitable value). Unset both to leave manifests "
                "unsigned."
            )
        seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"hst", info=b"evidence-sign-v1").derive(
            material
        )
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self._public = self._private.public_key().public_bytes_raw()

    def sign(self, digest: bytes) -> tuple[bytes, str] | None:
        return self._private.sign(digest), "ed25519"

    @property
    def key_id(self) -> str:
        return key_id_of(self._public)

    @property
    def public_key(self) -> str:
        return self._public.hex()


def key_id_of(public: bytes) -> str:
    return digest_bytes(public)[:16]


def verify(signature: Signature, digest: bytes) -> bool:
    if signature.algorithm != "ed25519":
        return False
    if signature.digest != digest.hex():
        return False
    try:
        public = bytes.fromhex(signature.public_key)
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(signature.signature), digest)
    except (InvalidSignature, ValueError):
        return False
    return signature.key_id == key_id_of(public)


def signer_for(settings: Settings) -> Signer | None:
    """The configured signer, or None when no evidence signing key is set."""
    if settings.evidence_signing_key_file:
        try:
            material = Path(settings.evidence_signing_key_file).read_bytes().strip()
        except OSError as exc:
            raise SignerError(f"cannot read HST_EVIDENCE_SIGNING_KEY_FILE: {exc}") from exc
    elif settings.evidence_signing_key:
        material = settings.evidence_signing_key.strip().encode()
    else:
        return None
    return AppKeySigner(material)


# --- the store --------------------------------------------------------------------------


def path_for(settings: Settings, snapshot_key: int) -> Path:
    return settings.manifests_dir / f"{snapshot_key}{SUFFIX}"


def sig_path_for(settings: Settings, snapshot_key: int) -> Path:
    return settings.manifests_dir / f"{snapshot_key}{SIG_SUFFIX}"


def keys(settings: Settings) -> list[int]:
    """Every snapshot key with a manifest on disk, oldest first."""
    directory = settings.manifests_dir
    if not directory.is_dir():
        return []
    out = []
    for path in directory.iterdir():
        if path.name.endswith(SUFFIX) and path.stem.isdigit():
            out.append(int(path.stem))
    return sorted(out)


def previous_link(settings: Settings, snapshot_key: int) -> PreviousLink | None:
    """Return the chain link for a manifest that is about to be written.

    The link holds the key of the newest manifest older than `snapshot_key`,
    the digest of its file and its chain index. The return value is None on
    the first manifest of a chain.
    """
    older = [k for k in keys(settings) if k < snapshot_key]
    if not older:
        return None
    key = older[-1]
    path = path_for(settings, key)
    sha, _size = file_facts(path)
    return PreviousLink(snapshot_key=key, sha256=sha, chain_index=read(settings, key).chain_index)


def write(settings: Settings, manifest: SnapshotManifest, signer: Signer | None = None) -> str:
    """Write the manifest, and its signature when a signer is given. Returns
    the SHA-256 of the bytes written.

    The caller writes the manifest before it moves the pointer that publishes
    the run.
    """
    directory = settings.manifests_dir
    directory.mkdir(parents=True, exist_ok=True)
    body = canonical_json(manifest.model_dump(mode="json"))
    path = path_for(settings, manifest.snapshot_key)
    _atomic_write(path, body)
    sha = digest_bytes(body)
    if signer is not None:
        signed = signer.sign(bytes.fromhex(sha))
        if signed is not None:
            raw_sig, algorithm = signed
            signature = Signature(
                algorithm=algorithm,
                key_id=signer.key_id,
                public_key=signer.public_key,
                digest=sha,
                signature=raw_sig.hex(),
            )
            _atomic_write(
                sig_path_for(settings, manifest.snapshot_key),
                canonical_json(signature.model_dump(mode="json")),
            )
    return sha


def _atomic_write(path: Path, body: bytes) -> None:
    """Write `body` to a temporary file in the same directory and rename it to
    `path`. A reader sees the previous file or the complete new file."""
    tmp = path.with_name(path.name + ".tmp")
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:
        fh.write(body)
    tmp.replace(path)


def read(settings: Settings, snapshot_key: int) -> SnapshotManifest:
    """The manifest of one snapshot. Raises FileNotFoundError when the
    snapshot has no manifest file, and ValueError when the schema version of
    the file is not in `READABLE_SCHEMA_VERSIONS`.
    """
    record = SnapshotManifest.model_validate_json(path_for(settings, snapshot_key).read_bytes())
    if record.schema_version not in READABLE_SCHEMA_VERSIONS:
        raise ValueError(
            f"snapshot {snapshot_key}'s manifest is schema version {record.schema_version}; "
            f"this build reads {', '.join(str(v) for v in READABLE_SCHEMA_VERSIONS)}"
        )
    return record


def read_signature(settings: Settings, snapshot_key: int) -> Signature | None:
    """The signature beside a manifest, or None when the manifest was written
    with no signer configured."""
    path = sig_path_for(settings, snapshot_key)
    if not path.is_file():
        return None
    return Signature.model_validate_json(path.read_bytes())


def digest_of(settings: Settings, snapshot_key: int) -> str:
    """The digest of a written manifest, from its bytes on disk."""
    return file_facts(path_for(settings, snapshot_key))[0]


# --- assembly ---------------------------------------------------------------------------


def carried_entries(
    settings: Settings,
    parent: int | None,
    devices: Sequence[DeviceEntry],
    files: Sequence[FileEntry],
) -> list[FileEntry]:
    """Return the file entries of the earlier runs that provide the state of
    the carried devices of this snapshot.

    The entries are copied from the manifests that recorded them, with
    `carried` set to true. The walk starts at `parent` and follows the
    `parent` link of each manifest. It reads each manifest once and stops when
    every wanted run is found. A manifest that cannot be read ends the walk.
    """
    wanted = {d.effective_run for d in devices if d.carried and d.effective_run} - {f.run_id for f in files}
    copied: dict[str, FileEntry] = {}
    key = parent
    seen: set[int] = set()
    while key is not None and key not in seen and wanted:
        seen.add(key)
        try:
            held = read(settings, key)
        except (OSError, ValueError):
            break
        for entry in held.files:
            if entry.run_id in wanted and entry.path not in copied:
                copied[entry.path] = entry.model_copy(update={"carried": True})
        wanted -= {entry.run_id for entry in held.files}
        key = held.parent
    return sorted(copied.values(), key=lambda f: f.path)


def build(
    *,
    settings: Settings,
    snapshot_key: int,
    kind: str,
    parent: int | None,
    sources: list[SourceEntry],
    devices: list[DeviceEntry],
    files: list[FileEntry],
    delta: GraphDelta,
    checkpoint_of: Callable[[], Checkpoint] | None = None,
    site_assignments: Mapping[str, str] | None = None,
    graph_archive: GraphArchiveEntry | None = None,
    stretch_observations: Sequence[Mapping[str, Any]] | None = None,
    warnings: Sequence[str] | None = None,
    site_blocks: Mapping[str, tuple[str, str | None]] | None = None,
) -> SnapshotManifest:
    """Assemble the record for one publish, resolving the chain from disk.

    `checkpoint_of` is called only when the chain index of this manifest is a
    multiple of `CHECKPOINT_EVERY`.

    `site_assignments` holds the assignments that the run applied
    (`SnapshotManifest.site_assignments`). `site_blocks` holds the named blocks
    that the run stamped (`SnapshotManifest.site_blocks`).
    """
    previous = previous_link(settings, snapshot_key)
    chain_index = 0 if previous is None else previous.chain_index + 1
    point = None
    if checkpoint_of is not None and chain_index % CHECKPOINT_EVERY == 0:
        point = checkpoint_of()
    blocks = dict(sorted((site_blocks or {}).items()))
    return SnapshotManifest(
        schema_version=SITE_BLOCKS_SCHEMA_VERSION if blocks else SCHEMA_VERSION,
        snapshot_key=snapshot_key,
        kind=kind,
        parent=parent,
        opened=iso(snapshot_key),
        published=now_iso(),
        build_revision=settings.hst_build_revision,
        estate=settings.estate_name,
        chain_index=chain_index,
        previous=previous,
        sources=sorted(sources, key=lambda s: s.name),
        devices=sorted(devices, key=lambda d: (d.source, d.host)),
        files=sorted(files, key=lambda f: f.path),
        site_assignments=dict(sorted((site_assignments or {}).items())),
        site_blocks=blocks,
        graph_archive=graph_archive,
        graph_delta=delta,
        checkpoint=point,
        stretch_observations=[StretchObservation.model_validate(dict(o)) for o in stretch_observations or []],
        warnings=list(warnings or []),
    )
