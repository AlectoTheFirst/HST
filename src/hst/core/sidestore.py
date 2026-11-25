"""Parquet side store for high-churn tables (RIB, ARP and MAC rows) keyed to
graph uids and held outside the graph.

Requires the `sidestore` extra (duckdb + pyarrow).
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import re
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from itertools import islice
from pathlib import Path
from typing import Any, NamedTuple

from . import manifest as manifestmod
from .ipenc import addr_bytes, prefix_bounds  # noqa: F401  (a re-export for the writers)
from .uid import slug

try:
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
except ImportError as exc:  # pragma: no cover - exercised via importorskip in tests
    raise RuntimeError("side store needs pip install -e '.[sidestore]'") from exc

logger = logging.getLogger(__name__)

SUFFIX = ".parquet"
# `_publish` writes a table under this suffix before it renames the file to its
# final name. Every reader matches the exact `SUFFIX`. worker/maintenance.py
# `sweep_sidestore_tmp` removes a file that a killed process left under this suffix.
TMP_SUFFIX = SUFFIX + ".tmp"

# The empty catalog file a read-only DuckDB connection over the side store
# attaches to (`connect_reader`), in the side store's own directory.
QUERY_CATALOG = ".query-catalog.duckdb"
# The directory, in the side store's own directory, that holds one spill
# directory for each process reading the store (`spill_dir`).
QUERY_SPILL = ".query-spill"
# The memory limit in MiB, the thread count and the spill limit in MiB of the
# DuckDB database that a side-store reader opens (`connect_reader`). Every
# connection that one process holds open over one side store shares the database.
DUCKDB_MEMORY_LIMIT_MB = 512
DUCKDB_THREADS = 2
DUCKDB_TEMP_LIMIT_MB = 2048


# The schema of each table. Every column is nullable. The schema fixes the type
# of each column.
#
# Every table ends in `run_id` and `snapshot_ts`.
# A run id holds the fetch time of the run (`collectors.base.new_run_id`).
# `ribsource.run_ts` reads the fetch time from the id.
# `snapshot_ts` is the joined collection_ts of the run. A reader bounds a
# snapshot lookup against `snapshot_ts`.
SCHEMAS: dict[str, pa.Schema] = {
    "rib": pa.schema(
        [
            pa.field("device_uid", pa.string()),
            pa.field("vrf", pa.string()),
            pa.field("context_uid", pa.string()),
            pa.field("prefix", pa.string()),
            pa.field("next_hop", pa.string()),
            # The VrfInstance uid in which the next hop resolves, for a route
            # leaked from another routing context (routing.py `_rib_route`).
            # Null for a route that resolves in its own table.
            pa.field("next_hop_context_uid", pa.string()),
            pa.field("interface", pa.string()),
            pa.field("protocol", pa.string()),
            # "blackhole" or "reject" for a discard route that has no next hop
            # and no egress interface. Null for every other route.
            pa.field("discard", pa.string()),
            pa.field("metric", pa.int64()),
            # The prefix as a closed [lo, hi] interval in the `addr_bytes`
            # encoding, with its length and its family, for the longest-prefix match.
            pa.field("af", pa.int64()),
            pa.field("prefixlen", pa.int64()),
            pa.field("lo", pa.binary(16)),
            pa.field("hi", pa.binary(16)),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
    "mac": pa.schema(
        [
            pa.field("device_uid", pa.string()),
            pa.field("vlan", pa.int64()),
            pa.field("mac", pa.string()),
            pa.field("port_name", pa.string()),
            # The BridgeDomain uid the VLAN resolves to (`uid.bridge_domain(fabric,
            # vid)`). Null in a file without this column.
            pa.field("bridge_domain_uid", pa.string()),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
    "arp": pa.schema(
        [
            pa.field("device_uid", pa.string()),
            pa.field("vrf", pa.string()),
            # The VrfInstance uid that the `vrf` name of the row resolves to on
            # this device, as `context_uid` in `rib`. Null in a file without
            # this column.
            pa.field("context_uid", pa.string()),
            pa.field("ip", pa.string()),
            pa.field("mac", pa.string()),
            pa.field("interface_name", pa.string()),
            # The address family of `ip` (4 or 6). Null when `ip` cannot be
            # parsed, and in a file without this column.
            pa.field("af", pa.int64()),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
    # One row per LSA of the link-state database of one OSPF process.
    # Each header field of an LSA is a column. The body of each LSA type is in
    # typed columns that only that type fills.
    #
    #   router LSA        `links`
    #   network LSA       `attached_routers`, `mask`
    #   summary LSAs      `mask`, `metric`
    #   external / NSSA   `mask`, `metric`, `metric_type`, `forwarding_address`
    #
    # `lsa_type` is the protocol's name for the LSA ("router", "network",
    # "summary", "asbr-summary", "external", "nssa-external").
    "ospf_lsdb": pa.schema(
        [
            pa.field("device_uid", pa.string()),
            # The VrfInstance uid in which the process runs, as `context_uid`
            # in `rib`.
            pa.field("context_uid", pa.string()),
            # The process that owns the database, in the naming of the platform
            # (an NX-OS process tag, an IOS process id). A device can run more
            # than 1 process, and each process has its own database.
            pa.field("process", pa.string()),
            pa.field("area", pa.string()),
            pa.field("lsa_type", pa.string()),
            pa.field("lsid", pa.string()),
            pa.field("adv_router", pa.string()),
            # The unsigned value of the LSA sequence number, as an integer.
            # Platforms print it as hex ("0x80000005").
            pa.field("seq", pa.int64()),
            pa.field("age", pa.int64()),
            # The metric of the LSA, for the types that have one. Null on
            # router and network LSAs. `links` holds the metric of each link of
            # a router LSA.
            pa.field("metric", pa.int64()),
            # The body of a router LSA. Each entry is one link with the link
            # type ("point-to-point", "transit", "stub", "virtual"), the link id
            # and the link data that the protocol defines for that type, and
            # the metric of the link.
            pa.field(
                "links",
                pa.list_(
                    pa.struct(
                        [
                            pa.field("link_type", pa.string()),
                            pa.field("link_id", pa.string()),
                            pa.field("link_data", pa.string()),
                            pa.field("metric", pa.int64()),
                        ]
                    )
                ),
            ),
            # The body of a network LSA. It holds the router ids attached to
            # the transit segment.
            pa.field("attached_routers", pa.list_(pa.string())),
            # The network mask of the prefix that an LSA describes, as a dotted
            # quad. `lsid` and `mask` together give the prefix. Null on the
            # types that describe no prefix.
            pa.field("mask", pa.string()),
            # External and NSSA LSA body.
            pa.field("forwarding_address", pa.string()),
            pa.field("metric_type", pa.int64()),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
    # BGP path observations, one row per prefix and direction.
    #
    # Every column is a BGP concept every platform HST parses can express.
    "bgp_session_routes": pa.schema(
        [
            pa.field("device_uid", pa.string()),
            # The VrfInstance uid in which the session runs, as `context_uid`
            # in `rib`.
            pa.field("context_uid", pa.string()),
            # The BgpSession node uid (`uid.bgp_session`). A row joins on it to
            # the configured session in the graph.
            pa.field("session_uid", pa.string()),
            pa.field("peer_ip", pa.string()),
            # Address family (4 or 6) and sub-family (such as "unicast",
            # "multicast" or "evpn") the row was read under.
            pa.field("af", pa.int64()),
            pa.field("safi", pa.string()),
            # "received" (what the peer sent, before the import policy),
            # "accepted" (what the import policy admitted) or "advertised"
            # (what the export policy sent). A direction that the platform
            # cannot expose is a `not-captured` table outcome in the manifest.
            pa.field("direction", pa.string()),
            # Which RIB the row was read out of: "adj-rib-in", "loc-rib" or
            # "adj-rib-out".
            pa.field("rib_type", pa.string()),
            # Where the row sits relative to policy: "pre-import",
            # "post-import", "pre-export" or "post-export".
            pa.field("policy_stage", pa.string()),
            # The identity that the platform gives one path of a prefix. 2 paths
            # of one prefix from one peer are 2 rows.
            pa.field("path_id", pa.string()),
            # The prefix and its interval encoding, as in `rib`.
            pa.field("prefix", pa.string()),
            pa.field("prefixlen", pa.int64()),
            pa.field("lo", pa.binary(16)),
            pa.field("hi", pa.binary(16)),
            # The BGP next-hop attribute, and the VrfInstance uid in which it
            # resolves for a path whose next hop belongs to another routing
            # context, as `next_hop_context_uid` in `rib`. The uid is null when
            # the next hop resolves in the context of the session.
            pa.field("next_hop", pa.string()),
            pa.field("next_hop_context_uid", pa.string()),
            pa.field("as_path", pa.string()),
            pa.field("local_pref", pa.int64()),
            pa.field("med", pa.int64()),
            pa.field("origin", pa.string()),
            pa.field("communities", pa.string()),
            # Whether the device marked this path best. Null for a direction
            # without such a mark. A received table is read before the best-path
            # decision.
            pa.field("best", pa.bool_()),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
    # Observed session state, one row per session and address family.
    "bgp_sessions": pa.schema(
        [
            pa.field("device_uid", pa.string()),
            pa.field("context_uid", pa.string()),
            pa.field("session_uid", pa.string()),
            pa.field("peer_ip", pa.string()),
            pa.field("af", pa.int64()),
            pa.field("safi", pa.string()),
            # The device's own word for the session state, unmapped.
            pa.field("state", pa.string()),
            # The time since which the session is established, in epoch
            # milliseconds. Null on a platform that reports only a relative
            # last-flap duration.
            pa.field("established_since_ms", pa.int64()),
            pa.field("prefixes_received", pa.int64()),
            pa.field("prefixes_advertised", pa.int64()),
            # The negotiated capabilities as one string, in the device's own
            # words.
            pa.field("capabilities", pa.string()),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
    # The full Check Point API envelope of a rule, layer, package or policy
    # object (collectors/checkpoint.py `ENVELOPE_TABLE`). The node of `uid`
    # holds `envelope_sha` as `checkpoint_envelope_sha`. A reader takes a row
    # only when the envelope hashes to the digest that the node holds.
    "checkpoint_envelopes": pa.schema(
        [
            pa.field("uid", pa.string()),
            pa.field("label", pa.string()),
            pa.field("envelope_sha", pa.string()),
            pa.field("envelope", pa.string()),
            pa.field("run_id", pa.string()),
            pa.field("snapshot_ts", pa.int64()),
        ]
    ),
}

# The rows per parquet row group when a caller gives no count. The value equals
# the default of `Settings.sidestore_row_group_rows`, which the collection path
# passes (collectors/base.py `_write_side_tables`). The repair paths
# (core/replay.py, core/reconcile.py) hold no Settings and take this value.
DEFAULT_ROW_GROUP_ROWS = 65_536

# Per-table schema version, for the snapshot manifest's file list
# (core/manifest.py `FileEntry.schema_version`). It changes with the
# shape of the table's `SCHEMAS` entry. Version 1 is each table's first shape.
SCHEMA_VERSIONS: dict[str, int] = {
    "rib": 1,
    "mac": 1,
    "arp": 1,
    "ospf_lsdb": 1,
    "bgp_session_routes": 1,
    "bgp_sessions": 1,
    "checkpoint_envelopes": 1,
}

# The count of written files that `_written` keeps for `written_row_facts`.
WRITTEN_FACTS_KEEP = 1024


class _Written(NamedTuple):
    """The record that `write_table` keeps of one file it wrote. It holds the
    identity of the file on disk (`_file_identity`), the row count and the row
    digest."""

    identity: tuple[int, int, int, int]
    rows: int
    digest: str
    # the distinct `device_uid` values of the rows, None for a table without
    # the column
    devices: tuple[str, ...] | None


_written: OrderedDict[str, _Written] = OrderedDict()
_written_lock = threading.Lock()


def _file_identity(st: os.stat_result) -> tuple[int, int, int, int]:
    """Return the device, the inode, the size and the modification time in
    nanoseconds of a file. One of them changes when the file at a path is
    replaced or rewritten. A rename changes none of them."""
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


def _record_written(
    path: Path,
    identity: tuple[int, int, int, int],
    rows: int,
    digest: str,
    devices: tuple[str, ...] | None,
) -> None:
    key = os.fspath(path.resolve())
    with _written_lock:
        _written[key] = _Written(identity, rows, digest, devices)
        _written.move_to_end(key)
        while len(_written) > WRITTEN_FACTS_KEEP:
            _written.popitem(last=False)


def _written_entry(path: Path) -> _Written | None:
    try:
        resolved = path.resolve()
        identity = _file_identity(resolved.stat())
    except OSError:
        return None
    key = os.fspath(resolved)
    with _written_lock:
        entry = _written.get(key)
    if entry is None or entry.identity != identity:
        return None
    return entry


def written_row_facts(path: Path) -> tuple[int, str] | None:
    """Return (row count, row digest) of a side-store file that `write_table`
    wrote in this process. Return None when `write_table` did not write the
    file, or when the file at `path` was replaced, rewritten or removed after
    the write.

    The digest is `manifest.RowDigests` over the record batches as they were
    written. `manifest.sidestore_row_facts` reads the same value back from the
    file. Each call compares the identity of the file at `path` with the
    recorded identity. `_written` keeps the last `WRITTEN_FACTS_KEEP` files
    written.
    """
    entry = _written_entry(path)
    return None if entry is None else (entry.rows, entry.digest)


def written_devices(path: Path) -> tuple[str, ...] | None:
    """The devices (`device_uid` values) of the rows of a side-store file
    `write_table` wrote in this process, sorted, under the same conditions as
    `written_row_facts`. None when the file is not recorded, or when its table
    has no `device_uid` column."""
    entry = _written_entry(path)
    return None if entry is None else entry.devices


def file_devices(path: Path) -> tuple[str, ...] | None:
    """The distinct `device_uid` values of a side-store file, sorted, read from
    the `device_uid` column alone. None for a file without the column."""
    with pq.ParquetFile(path) as reader:
        if "device_uid" not in reader.schema_arrow.names:
            return None
        found: set[str] = set()
        for batch in reader.iter_batches(columns=["device_uid"]):
            found.update(_batch_devices(batch) or ())
        return tuple(sorted(found))


def _batch_devices(batch: pa.RecordBatch) -> set[str] | None:
    if "device_uid" not in batch.schema.names:
        return None
    return {str(uid) for uid in pc.unique(batch.column("device_uid")).to_pylist() if uid is not None}


class _BatchDigest:
    """The row facts of the batches one write hands to the parquet writer
    (`manifest.RowDigests`). A digest that cannot be completed is
    dropped."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rows = manifestmod.RowDigests()
        self.whole = True
        self.devices: set[str] | None = None

    def through(self, batches: Iterable[pa.RecordBatch]) -> Iterator[pa.RecordBatch]:
        for batch in batches:
            found = _batch_devices(batch)
            if found is not None:
                self.devices = (self.devices or set()) | found
            if self.whole:
                try:
                    self.rows.add(batch)
                except OSError as exc:
                    self._give_up(exc)
            yield batch

    def facts(self) -> tuple[int, str] | None:
        if not self.whole:
            return None
        try:
            return self.rows.count, self.rows.digest()
        except OSError as exc:
            self._give_up(exc)
            return None

    def _give_up(self, exc: OSError) -> None:
        self.whole = False
        logger.warning(
            "side store: the row digest of %s was not taken during its write (%s); "
            "it is read back from the file when it is asked for",
            self.path,
            exc,
        )


def write_table(
    base_dir: Path,
    table: str,
    source: str,
    host: str,
    run_id: str,
    rows: Iterable[Mapping[str, Any]],
    snapshot_ts: int,
    row_group_rows: int | None = None,
    check: Callable[[], None] | None = None,
) -> Path | None:
    """Write `rows` as parquet at <base_dir>/<table>/<source>/<host>/<run_id>.parquet.

    `source` is the source ROW name and `host` is the device host. Both are
    slugged for the filesystem (the module docstring of rawstore.py describes
    the matching raw-file layout). An empty `host` adds no directory level, as
    for a controller source without devices. Every row gets the columns
    `run_id` and `snapshot_ts`. `snapshot_ts` is the joined collection_ts of
    the run, and `RibSource` bounds a snapshot lookup against it. A refresh or
    a per-device job can create more than 1 run with one `snapshot_ts`. The
    fetch time in `run_id` orders such runs.

    `rows` is any iterable of row mappings, such as a list, a generator or a
    lazy view that builds each row as it is read. It is iterated once, in
    order. The function returns None and creates no directory when `rows`
    yields nothing. The first row group alone decides this, before `table` is
    checked. For rows that are not empty, `table` must be a known side-store
    table (`SCHEMAS`).

    The file appears under its final name once it is complete on disk
    (`_publish`). A reader that lists exact paths (`ribsource.for_snapshot`)
    or globs `*.parquet` (`query`, the approximate reader) does not open a
    half-written file. A write that fails leaves no file.

    `row_group_rows` is the count of rows in one parquet row group. None takes
    `DEFAULT_ROW_GROUP_ROWS`, the default of `Settings.sidestore_row_group_rows`.
    The rows are read, stamped and converted one row group at a time.

    An exception raised while `rows` is iterated propagates to the caller,
    and `_publish` removes the partly written temporary file first.

    `check`, when given, is called before the rows of each row group are
    read, the first one included. An exception that it raises propagates in
    the same way. A load passes the stop check of its collector
    (`Collector.check_stop` through collectors/base.py `_write_side_tables`).
    A stopped run ends the write of a large table within one row group.

    The row count and the row digest of the file are taken from each record
    batch as it is handed to the writer (`manifest.RowDigests`) and kept for
    `written_row_facts`. The digest converts at most
    `manifest.ROW_DIGEST_SLICE` rows of a batch to Python values at a time,
    after the stamped rows of the batch are released.
    """
    size = max(1, row_group_rows or DEFAULT_ROW_GROUP_ROWS)
    it = iter(rows)
    if check is not None:
        check()
    first = list(islice(it, size))
    if not first:
        return None
    schema = SCHEMAS.get(table)
    if schema is None:
        raise ValueError(f"unknown side-store table {table!r}; known tables: {sorted(SCHEMAS)}")
    source_dir = base_dir / table / slug(source)
    directory = source_dir / slug(host) if host else source_dir
    directory.mkdir(parents=True, exist_ok=True)
    _private_dirs(base_dir, base_dir / table, source_dir, directory)
    path = directory / f"{run_id}{SUFFIX}"
    batches = _row_groups(first, it, schema, run_id, snapshot_ts, size, check)
    # The generator holds the first row group. This frame drops its reference,
    # and the row group is released with its record batch.
    del first
    digest = _BatchDigest(path)
    try:
        identity = _publish(path, schema, digest.through(batches))
        facts = digest.facts()
    finally:
        digest.rows.close()
    if facts is not None:
        _record_written(
            path, identity, *facts, None if digest.devices is None else tuple(sorted(digest.devices))
        )
    return path


def _row_groups(
    first: list[Mapping[str, Any]],
    rest: Iterator[Mapping[str, Any]],
    schema: pa.Schema,
    run_id: str,
    snapshot_ts: int,
    size: int,
    check: Callable[[], None] | None = None,
) -> Iterator[pa.RecordBatch]:
    """Yield `first` and then the rows of `rest` as record batches of at most
    `size` rows, each row stamped with `run_id` and `snapshot_ts`.

    One batch is one row group in the written file. `first` is the first row
    group, which `write_table` has read. Each later group is read from `rest`
    after the previous batch is handed on and after `check`, when given, has
    returned. The chunk is released once its stamped copy is built, and the
    stamped copy is released once the batch is built. The Python rows of at
    most one row group are held at a time.
    """
    chunk = first
    del first
    while chunk:
        stamped = [{**row, "run_id": run_id, "snapshot_ts": snapshot_ts} for row in chunk]
        del chunk
        batch = pa.RecordBatch.from_pylist(stamped, schema=schema)
        del stamped
        yield batch
        del batch
        if check is not None:
            check()
        chunk = list(islice(rest, size))


def _publish(path: Path, schema: pa.Schema, batches: Iterable[pa.RecordBatch]) -> tuple[int, int, int, int]:
    """Write `batches` to `path` through a temporary name in the same directory,
    fsync the file, and move it into place with `Path.replace` (`os.replace`).
    After the rename the final name holds either the old file or the whole new
    file. Return the identity of the written file (`_file_identity`), taken
    from the temporary file once it is synced.

    Each batch is written as its own row group by a `pq.ParquetWriter` open on
    the temporary file. The writer is closed before the fsync.

    The temporary name is `<run_id>` + `TMP_SUFFIX`, which no reader matches.
    The manifest-driven reader opens the exact paths that a published manifest
    lists, and the glob readers match `*.parquet` only. A crash between the
    write and the rename leaves at most the temporary file, and
    worker/maintenance.py `sweep_sidestore_tmp` removes it once it is old
    enough. On a failure that this process sees, the temporary file is removed
    before the exception is raised again. The directory is synced after the
    rename to make the new name durable.
    """
    tmp = path.with_name(path.name[: -len(SUFFIX)] + TMP_SUFFIX)
    try:
        # ParquetWriter keeps the mode of the file.
        os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        with pq.ParquetWriter(tmp, schema) as writer:
            for batch in batches:
                writer.write_batch(batch)
        identity = _file_identity(_fsync(tmp))
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    with contextlib.suppress(OSError):
        _fsync(path.parent)
    return identity


def _private_dirs(*directories: Path) -> None:
    for d in directories:
        with contextlib.suppress(OSError):
            d.chmod(0o700)


def _fsync(target: Path) -> os.stat_result:
    """fsync `target` and return its status as of the sync."""
    fd = os.open(target, os.O_RDONLY)
    try:
        os.fsync(fd)
        return os.fstat(fd)
    finally:
        os.close(fd)


# `connect_reader` holds this lock while it opens and configures a connection
# over a side store. One thread of a process at a time creates the catalog and
# configures the shared database.
_reader_lock = threading.Lock()


def _sql_str(value: str) -> str:
    """`value` as a SQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def _sql_ident(name: str) -> str:
    """`name` as a quoted SQL identifier. DuckDB matches a quoted identifier
    without regard to case, as it does an unquoted one."""
    return '"' + name.replace('"', '""') + '"'


@functools.cache
def _process_token(pid: int) -> str:
    """A random name part that is fixed for the life of the process `pid`.
    2 processes over one store can have the same process id. The API and the
    worker run in separate containers, and each container numbers its
    processes from 1."""
    return secrets.token_hex(8)


def spill_dir(base_dir: Path) -> Path:
    """The directory to which the DuckDB database of this process over the side
    store at `base_dir` spills. The path is
    `<base_dir>/<QUERY_SPILL>/<pid>-<token>`, one directory for each process.

    `connect_reader` creates the directory and sets its modification time to
    the current time on every connection it opens. worker/maintenance.py
    `sweep_sidestore_spills` removes a directory that no connection has opened
    and nothing has written for `SIDESTORE_TMP_MIN_AGE`. A process killed
    while a query spilled leaves such a directory. DuckDB removes its own
    files from the directory after each query and when the database closes,
    and leaves the directory in place.
    """
    pid = os.getpid()
    return base_dir / QUERY_SPILL / f"{pid}-{_process_token(pid)}"


def _open_spill(base_dir: Path) -> Path | None:
    """`spill_dir(base_dir)`, created when missing and marked in use as of
    now, or None when it cannot be created, as on a store mounted read-only.
    The database then does not spill, and a query past the memory limit
    fails."""
    path = spill_dir(base_dir)
    try:
        path.parent.mkdir(exist_ok=True)
        path.mkdir(exist_ok=True)
        _private_dirs(path.parent, path)
        os.utime(path)
    except OSError as exc:
        logger.warning(
            "side store: the spill directory %s cannot be created (%s); "
            "a query that needs more than %d MiB fails",
            path,
            exc,
            DUCKDB_MEMORY_LIMIT_MB,
        )
        return None
    return path


def _create_catalog(duckdb: Any, catalog: Path, spill: Path | None) -> None:
    """Create the empty catalog file that `connect_reader` attaches to.

    DuckDB creates a database file by opening it read-write, under a lock
    that conflicts with the hold of every other process on the same file. A
    process that creates the catalog while another process opens it fails,
    and a process that opens it while another process creates it fails. The
    file is created in the spill directory of this process and hard-linked
    into place. A link that finds the catalog in place leaves the catalog
    unchanged. A process killed between the 2 steps leaves the new file in
    its spill directory, and the spill sweep removes it. On a file system
    without hard links the file is moved into place. With no spill directory
    the file is created in place."""
    if spill is None:
        duckdb.connect(str(catalog)).close()
        with contextlib.suppress(OSError):
            catalog.chmod(0o600)
        return
    new = spill / QUERY_CATALOG
    duckdb.connect(str(new)).close()
    with contextlib.suppress(OSError):
        new.chmod(0o600)
    try:
        os.link(new, catalog)
    except FileExistsError:
        pass
    except OSError:
        if not catalog.exists():
            new.replace(catalog)
    finally:
        with contextlib.suppress(OSError):
            new.unlink()


def _bound(con: Any, spill: str) -> None:
    """Apply `DUCKDB_MEMORY_LIMIT_MB`, `DUCKDB_THREADS` and
    `DUCKDB_TEMP_LIMIT_MB` to the database of `con`, while its configuration
    is still unlocked, with `spill` as the directory it spills to. An empty
    `spill` turns spilling off. The progress bar is off. DuckDB prints the
    progress bar to the stdout of the process for a query that runs longer
    than 2 seconds."""
    con.execute("SET enable_progress_bar=false")
    con.execute(f"SET memory_limit='{int(DUCKDB_MEMORY_LIMIT_MB)}MiB'")
    con.execute(f"SET threads={int(DUCKDB_THREADS)}")
    con.execute(f"SET temp_directory={_sql_str(spill)}")
    con.execute(f"SET max_temp_directory_size='{int(DUCKDB_TEMP_LIMIT_MB)}MiB'")


def connect_reader(base_dir: Path) -> Any:
    """A read-only DuckDB connection that can read files under `base_dir` and
    nothing else, bounded by `DUCKDB_MEMORY_LIMIT_MB`, `DUCKDB_THREADS` and
    `DUCKDB_TEMP_LIMIT_MB`, which spills to the `spill_dir` of this process.
    The caller closes it. Raises ImportError when DuckDB is not installed.

    DuckDB cannot launch an in-memory database read-only. The connection
    attaches read_only to an empty catalog file, `QUERY_CATALOG` in
    `base_dir`, which is created on first use (`_create_catalog`). A view
    that a caller creates must be TEMP, because the read-only catalog rejects
    CREATE. A TEMP view belongs to the connection. External file access is
    disabled except under `base_dir`, and the configuration is locked. No
    statement can read outside the store or change these settings.

    Every connection that one process holds open on one catalog file shares
    one DuckDB database. A database with a locked configuration refuses any
    further SET. The connection that finds the database unlocked configures
    it. A connection that finds it locked uses it as it is, provided external
    access is off. `allowed_directories` must be set while external access is
    still on. The views scan parquet lazily, and `base_dir` must stay allowed
    for a read to run.
    """
    import duckdb

    catalog = base_dir / QUERY_CATALOG
    with _reader_lock:
        spill = _open_spill(base_dir)
        if not catalog.exists():
            _create_catalog(duckdb, catalog, spill)
        con = duckdb.connect(str(catalog), read_only=True)
        try:
            locked = con.execute("SELECT current_setting('lock_configuration')").fetchone()
            if not (locked and locked[0]):
                _bound(con, "" if spill is None else spill.as_posix())
                con.execute(f"SET allowed_directories=[{_sql_str(base_dir.as_posix())}]")
                con.execute("SET enable_external_access=false")
                con.execute("SET lock_configuration=true")
            else:
                external = con.execute("SELECT current_setting('enable_external_access')").fetchone()
                if external is None or external[0]:
                    raise RuntimeError(f"the side-store catalog {catalog} is open with external access on")
        except BaseException:
            con.close()
            raise
    return con


# The directories of the store that hold no side-store table. The map writes
# the HST tiers under `hst/`, with their own schemas and a file for every device
# of every run.
_NOT_TABLES = frozenset({"hst"})


def _named_tables(base_dir: Path, sql: str) -> list[str]:
    """The table directories of `base_dir` that `sql` names, as a word or as a
    quoted identifier."""
    found = []
    for path in sorted(base_dir.iterdir()):
        name = path.name
        if not path.is_dir() or name.startswith(".") or name in _NOT_TABLES:
            continue
        if _sql_ident(name).lower() in sql.lower() or re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", sql, re.I
        ):
            found.append(name)
    return found


def query(
    base_dir: Path,
    sql: str,
    tables: Iterable[str] | None = None,
    files: Mapping[str, Sequence[Path]] | None = None,
) -> list[dict[str, Any]]:
    """Run `sql` over the side store. Each <base_dir>/<table>/ subdirectory of
    `tables` that holds a parquet file is registered as a view with the name
    of the table, over the union of its parquet files.

    `tables` is the tables that the statement reads. With no `tables`, a view
    is made for each table that the statement names. Registering a view reads
    the footer of every file under it, and the store holds a file for every
    device of every run it keeps. The HST tiers under `hst/` are not
    registered, and a dot directory is not taken as a table that the statement
    names.

    `files` gives, per table, the parquet files that its view reads in place
    of every file under the table directory. A table in `files` is registered
    even when `tables` leaves it out. A table in `files` with no file listed
    gets no view. Every file must lie under `base_dir`.

    3 layers enforce read-only access. The catalog is opened read_only, which
    blocks catalog writes but not COPY TO or ATTACH. The DuckDB parser must
    classify every statement as SELECT or EXPLAIN, which blocks COPY, ATTACH
    and INSTALL at parse time. External file access is disabled except under
    `base_dir` with the configuration locked, which blocks a read of a file
    outside the store and a change of these settings from SQL. `connect_reader`
    applies the first and the third layer, and bounds the memory, the threads
    and the spill space of the query.
    """
    try:
        import duckdb
    except ImportError as exc:
        raise RuntimeError("side store needs pip install -e '.[sidestore]'") from exc

    for stmt in duckdb.extract_statements(sql):
        if stmt.type not in (duckdb.StatementType.SELECT, duckdb.StatementType.EXPLAIN):
            raise ValueError(f"side-store queries are read-only; refusing {stmt.type.name}")

    if base_dir.is_dir():
        con = connect_reader(base_dir)
        try:
            wanted = (
                _named_tables(base_dir, sql)
                if tables is None
                else [t for t in tables if t not in _NOT_TABLES]
            )
            listed = {name: list(paths) for name, paths in (files or {}).items() if name not in _NOT_TABLES}
            wanted = [*wanted, *(name for name in listed if name not in wanted)]
            root = base_dir.resolve()
            for table_dir in sorted(base_dir / name for name in wanted if (base_dir / name).is_dir()):
                if table_dir.name in listed:
                    paths = sorted(set(listed[table_dir.name]))
                    if any(not p.resolve().is_relative_to(root) for p in paths):
                        raise ValueError(f"side-store files of {table_dir.name} lie outside the store")
                    if paths:
                        quoted = ", ".join(_sql_str(p.as_posix()) for p in paths)
                        con.execute(
                            f"CREATE TEMP VIEW {_sql_ident(table_dir.name)} AS "  # noqa: S608
                            f"SELECT * FROM read_parquet([{quoted}], union_by_name=true)"
                        )
                    continue
                # DuckDB resolves the glob when the view is created. A table
                # directory with no parquet file under it fails every
                # statement. A first write that failed leaves such a directory.
                # The table gets no view, and a query that names it fails as a
                # query that names a table never written. The same holds for
                # the spill directories (`QUERY_SPILL`).
                if next(table_dir.rglob(f"*{SUFFIX}"), None) is None:
                    continue
                # Both interpolated values are directory names read from disk.
                # DuckDB cannot bind an identifier or a glob path, and both
                # are quoted. With union_by_name, a file without a column of
                # its table gives NULL for that column.
                glob = _sql_str(f"{table_dir.as_posix()}/**/*{SUFFIX}")
                con.execute(
                    f"CREATE TEMP VIEW {_sql_ident(table_dir.name)} AS "  # noqa: S608
                    f"SELECT * FROM read_parquet({glob}, union_by_name=true)"
                )
            return _rows(con, sql)
        finally:
            con.close()
    # Without a store on disk no view is registered. The same file-access
    # settings and bounds apply. The in-memory database belongs to this
    # connection and does not spill. The DuckDB default spill directory of an
    # in-memory database is `.tmp` in the working directory.
    con = duckdb.connect()
    try:
        _bound(con, "")
        con.execute("SET enable_external_access=false")
        con.execute("SET lock_configuration=true")
        return _rows(con, sql)
    finally:
        con.close()


def query_files(base_dir: Path, sql: str, table: str, paths: Sequence[Path]) -> list[dict[str, Any]]:
    """Run `sql` over the one table `table`, read from `paths` alone. With no
    path, the result is an empty list and no statement runs."""
    if not paths:
        return []
    return query(base_dir, sql, [table], {table: paths})


def _rows(con: Any, sql: str) -> list[dict[str, Any]]:
    cur = con.execute(sql)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]
