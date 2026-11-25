"""The maintenance job bodies: sessions, auth state, audit rows, graph history."""

from __future__ import annotations

import asyncio
import json
import logging
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hst.app import retention, runs_exec
from hst.app.security import idle_after
from hst.app.store import Job, Store
from hst.collectors import http_trace
from hst.core import Settings
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import manifest as manifestmod
from hst.core import rawstore as rawstoremod
from hst.core.ribsource import run_ts

log = logging.getLogger(__name__)
_session = dbmod.session  # Tests replace `_session`, as in app/routes/snapshots.py.

PRUNE_GRAPH = "maintenance.prune_graph"
PRUNE_SIDESTORE = "maintenance.prune_sidestore"
PRUNE_RAWSTORE = "maintenance.prune_rawstore"
PRUNE_MANIFESTS = "maintenance.prune_manifests"
PURGE_LOGIN_EVENTS = "maintenance.purge_login_events"
PURGE_CYPHER_EVENTS = "maintenance.purge_cypher_events"
PURGE_SESSIONS = "maintenance.purge_sessions"
PURGE_JOB_HISTORY = "maintenance.purge_job_history"
PURGE_AI_CONVERSATIONS = "maintenance.purge_ai_conversations"
COMPACT_AI_STEPS = "maintenance.compact_ai_steps"
PURGE_AI_EPHEMERAL = "maintenance.purge_ai_ephemeral"
PURGE_AI_EVENTS = "maintenance.purge_ai_events"
BUILD_DEVICE_RUN = "maintenance.build_device_run"

# The side-store tables that a device fetch can write rows into
# (core/sidestore.py `SCHEMAS`). sidestore.py raises at import time when the
# `sidestore` extra is missing, and this module does not import it.
SIDESTORE_TABLES = (
    "rib",
    "mac",
    "arp",
    "ospf_lsdb",
    "bgp_session_routes",
    "bgp_sessions",
    "checkpoint_envelopes",
)
# `SIDESTORE_TMP_SUFFIX` is the suffix of the temporary file of a side-store
# write (core/sidestore.py `TMP_SUFFIX`). `SIDESTORE_SPILL_DIR` is the directory
# of the side store that holds the DuckDB spill directory of each reading
# process (`QUERY_SPILL`). `SIDESTORE_CATALOG` is the catalog file of the reader
# (`QUERY_CATALOG`). The default DuckDB spill directory is the name of the
# catalog plus ".tmp".
SIDESTORE_TMP_SUFFIX = ".parquet.tmp"
SIDESTORE_SPILL_DIR = ".query-spill"
SIDESTORE_CATALOG = ".query-catalog.duckdb"
# The prefix of the name of every spill file that DuckDB writes.
DUCKDB_SPILL_PREFIX = "duckdb_temp_"


@dataclass(frozen=True)
class Context:
    """The store and the settings of the deployment that a job body receives."""

    store: Store
    settings: Settings


# A body returns the line that goes into the job's `detail`.
JobBody = Callable[[Context, Job], Awaitable[str]]


async def _assessment_refs(store: Store) -> set[int]:
    """The run keys that retained assessments reference directly.

    The graph, side-store and raw sweeps keep these runs whole and read the
    files their manifests bind (`retention.plan`). A reference that holds no
    valid run key raises ValueError and stops the sweep.
    """
    reader = getattr(store, "retained_snapshot_refs", None)
    if reader is None:
        return set()
    refs = await reader()
    pins: set[int] = set()
    for ref in refs:
        identities = [
            ref[key] for key in ("snapshot", "collection_ts", "snapshot_key") if ref.get(key) is not None
        ]
        if not identities or any(type(value) not in {str, int} for value in identities):
            raise ValueError("Retained assessment has no valid snapshot identity; retention stopped.")
        try:
            normalized = {int(value) for value in identities}
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Retained assessment has an invalid snapshot identity; retention stopped."
            ) from exc
        if len(normalized) != 1 or min(normalized) < 0:
            raise ValueError("Retained assessment has conflicting snapshot identities; retention stopped.")
        pins.update(normalized)
    return pins


async def _leased_runs(store: Store) -> set[int]:
    """The run keys that readers hold open. A pinned trace leases the run that
    it reads. Prune keeps a leased run whole until the lease ends or expires."""
    reader = getattr(store, "leased_runs", None)
    if reader is None:
        return set()
    return {int(key) for key in await reader()}


async def _assessment_pins(store: Store, settings: Settings) -> set[int]:
    """The runs that `prune_manifests` must keep. They are the run of every
    retained assessment and the manifest chain behind that run.

    The chain is kept for the manifest sweep only. Each manifest links to the
    manifest before it (`previous`), and the chain is the evidence trail of a
    pinned run. Every other sweep keeps the files that a run reads
    (`_assessment_refs`).

    The walk ends at an ancestor whose manifest is missing, and logs it, when
    the manifest that links to the ancestor is past
    `evidence_retention_days`. The period sweep keeps the predecessor of every
    manifest inside the period. Any other missing manifest is a broken chain,
    and the walk raises FileNotFoundError. This applies to the manifest of a
    pinned run, to a manifest that a manifest inside the period links to, and
    to every manifest when the period sweep is off.
    """
    pins = await _assessment_refs(store)
    pending = list(pins)
    named_by: dict[int, manifestmod.SnapshotManifest] = {}
    while pending:
        current = pending.pop()
        try:
            record = await asyncio.to_thread(manifestmod.read, settings, current)
        except FileNotFoundError:
            if not _period_removed(settings, named_by.get(current)):
                raise
            log.info("manifest chain of a retained assessment ends at %s: that manifest is gone", current)
            continue
        if record.previous is not None and record.previous.snapshot_key not in pins:
            pins.add(record.previous.snapshot_key)
            named_by[record.previous.snapshot_key] = record
            pending.append(record.previous.snapshot_key)
    return pins


def _period_removed(settings: Settings, naming: manifestmod.SnapshotManifest | None) -> bool:
    """Whether `prune_manifests` can have removed the predecessor of `naming`.
    This is true when the period sweep is on and `naming` is past the period."""
    days = settings.evidence_retention_days
    if days is None or naming is None:
        return False
    try:
        opened = datetime.fromisoformat(naming.opened)
    except ValueError:
        return False
    return datetime.now(UTC) - opened > timedelta(days=days)


def _graph_keep(limits: retention.Retention) -> cyclemod.Keep:
    """The `cycle.Keep` of `limits`. The graph prune and the raw, side-store
    and manifest sweeps all use it."""
    return cyclemod.Keep(limits.cycle_keep_runs, limits.cycle_keep_device_runs)


async def prune_graph(settings: Settings, store: Store, keep: int | cyclemod.Keep) -> list[int] | None:
    """Delete graph data of the runs retention no longer keeps under `keep`, if the graph is free.

    This is the scheduled form of `hst prune`. The runs it keeps are the graph
    window (`cycle.retained_runs`), the runs assessments reference
    (`_assessment_refs`) and the runs readers hold open (`_leased_runs`).

    Each victim is deleted under its own hold of the cross-pod cycle lock,
    oldest first, and the lock is released between victims. The lock is taken
    with `try_cycle_lock`. The `:CycleRun` node of a run is deleted first and
    its objects after, relationships before nodes (`cycle.delete_run`).

    The result is the list of deleted runs, or None when a collection held the
    lock before anything was deleted and this turn was skipped. A collection
    that took the lock part way through ends the turn with the runs deleted by
    then. Failures propagate, and the executor records them.
    """

    deleted: list[int] = []
    while True:
        async with store.try_cycle_lock() as locked:
            if not locked:
                return sorted(deleted, reverse=True) if deleted else None
            leased = await _leased_runs(store)
            held = frozenset(await _assessment_refs(store) | leased)
            victims = await asyncio.to_thread(_prune_one_run, settings, keep, held, frozenset(leased))
        if not victims or set(victims) & set(deleted):
            return sorted(deleted, reverse=True)
        deleted.extend(victims)


def _prune_one_run(
    settings: Settings, keep: int | cyclemod.Keep, held: frozenset[int], leased: frozenset[int] = frozenset()
) -> list[int]:
    """Delete the oldest run that retention no longer keeps, and run the HST
    sweep of that turn. The HST sweep defers its file deletion while a reader
    leases a cold run. The caller holds the cycle lock and calls from a worker
    thread."""
    with _session(settings) as s:
        victims = cyclemod.prune(s, keep, held, max_victims=1)
        try:
            pointer = cyclemod.current_ts_or_none(s)
        except Exception:
            log.warning("HST sweep: the cycle pointer could not be read", exc_info=True)
            pointer = None
    _sweep_hst(settings, victims, pointer, leased)
    return victims


def _sweep_hst(
    settings: Settings, pruned: list[int], pointer: int | None, leased: frozenset[int] = frozenset()
) -> None:
    """The HST sweep, in the turn of the graph prune and under its lock.

    It reconciles the marker of the run of the pointer, marks the runs that
    the prune deleted as cold and applies the HST retention. A failure is
    logged. The graph prune of the turn has succeeded before the sweep starts.
    """
    try:
        from hst.map import project as hst_project
        from hst.map import sweep as hst_sweep
    except ImportError:
        return
    try:
        hst_project.reconcile(
            settings.sidestore_dir,
            settings.manifests_dir,
            pointer,
            lambda key: runs_exec._hst_marker_fallback(settings, key),
        )
        hst_sweep.sweep(
            settings.sidestore_dir,
            settings.manifests_dir,
            pruned,
            checkpoint_every=settings.hst_tier_checkpoint_every,
            history_days=settings.hst_history_days,
            leased=leased,
        )
    except Exception:
        log.exception("HST sweep failed after the graph prune")


async def _prune_graph_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    victims = await prune_graph(ctx.settings, ctx.store, _graph_keep(limits))
    if victims is None:
        log.info("graph prune skipped: a collection run holds the cycle lock")
        return "skipped: a collection run holds the cycle lock"
    beyond = (
        f"the newest {limits.cycle_keep_runs} cycle(s)"
        f" and {limits.cycle_keep_device_runs} device or refresh run(s)"
    )
    if not victims:
        return f"nothing to prune beyond {beyond}"
    log.info(
        "graph prune deleted %d run(s) beyond %s: %s",
        len(victims),
        beyond,
        ", ".join(str(v) for v in victims),
    )
    return f"deleted {len(victims)} run(s) beyond {beyond}"


def _file_snapshot_ts(path: Path) -> int | None:
    """The run that the rows of a side-store parquet file joined, read from
    the `snapshot_ts` column of the file.

    The result is None when the file cannot be read or when the column does
    not hold exactly one distinct non-null value.
    """
    try:
        import pyarrow.compute as pc
        import pyarrow.parquet as pq
    except ImportError:
        return None
    try:
        with pq.ParquetFile(path) as parquet:
            # `read` returns no column for a name that the file does not
            # have. The schema check handles a missing column.
            if "snapshot_ts" not in parquet.schema_arrow.names:
                return None
            column = parquet.read(columns=["snapshot_ts"]).column("snapshot_ts")
        values = {value for value in pc.unique(column).to_pylist() if value is not None}
        if len(values) != 1:
            return None
        return int(next(iter(values)))
    except Exception:
        return None


def _path_identity(path: Path, base: Path, depth: int) -> tuple[str, str, str]:
    """The (source, host, run_id) of a store path, in the form that `_identity`
    of core/manifest.py gives the `FileEntry` of the same file.

    `depth` is the count of path segments before the source directory. It is
    0 for the raw store (`<source>/<host>/<run_id>`) and 1 for the side store,
    where the table name is the first segment. A source without hosts (a
    controller type) has no host segment.
    """
    parts = path.resolve().relative_to(base.resolve()).parts
    body = parts[depth:]
    run_id = path.name.split(".", 1)[0]
    source = body[0] if body else ""
    host = body[1] if len(body) > 2 else ""
    return source, host, run_id


def _ms_to_dt(ts_ms: int) -> datetime:
    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC)


def _past_period(ts_ms: int, days: int, now: datetime) -> bool:
    """Whether a run id's own fetch timestamp (milliseconds since the epoch)
    is older than the regulatory period `days`."""
    return now - _ms_to_dt(ts_ms) > timedelta(days=days)


def _log_unmanifested(sweep: str, runs: list[int]) -> None:
    if runs:
        log.info(
            "%s prune: %d graph-retained run(s) have no manifest yet; their files are protected outright: %s",
            sweep,
            len(runs),
            ", ".join(str(c) for c in runs),
        )


async def prune_sidestore(
    settings: Settings,
    store: Store,
    keep: int | cyclemod.Keep,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
) -> list[Path] | None:
    """Delete the side-store parquet files of every table in `SIDESTORE_TABLES`
    that belong to a run that retention no longer keeps, that no manifest of
    a retained run needs, and that are past the regulatory period.

    A file is deleted only when both tiers allow it.

    The graph-count tier is `retention.Plan`. It keeps every run that
    `cycle.retained_runs` keeps at `keep`, the runs that assessments reference
    and the runs that readers hold open. This tier protects a file when the
    `snapshot_ts` column of the file holds one of those keys, or when the
    manifest of a kept run needs the file
    (`retention.manifest_protected_identities`). A kept run with no manifest
    protects every file stamped at or below its key. A file stamped above the
    newest kept run belongs to a run in flight and stays.

    The period tier is `settings.evidence_retention_days`. It is off when the
    setting is `None`, the default. When the setting has a value, a file that
    the graph-count tier does not protect is deleted only when it is also past
    the period (`_past_period`, against its `snapshot_ts`).

    The decision is read under the cross-pod cycle lock that `prune_graph`
    takes. A cycle in flight can write the run that the sweep would delete.
    The lock is taken with `try_cycle_lock` and released before the files are
    walked and deleted.

    2 kinds of leftover are removed before the lock is tried, each in a worker
    thread. A collection that holds the lock does not stop them.
    `sweep_sidestore_spills` removes the DuckDB spill directories and files
    that no reader has used for `SIDESTORE_TMP_MIN_AGE`. It lists the spill
    directories alone and runs on every turn. `sweep_sidestore_tmp` removes
    the temporary files of side-store writes that never finished and are older
    than `SIDESTORE_TMP_MIN_AGE`. It walks the whole store and runs at most
    once per `SIDESTORE_TMP_SWEEP_INTERVAL` in a process. Both removals are
    logged, and the result does not hold them. `now` is the time against which
    this turn measures ages and the throttle. It defaults to the current time.

    With `dry_run` the files that would be deleted are returned and none is
    deleted.

    The result is the list of deleted files, or None when a collection held
    the lock and this turn was skipped. A file whose run key cannot be read is
    left in place and logged. Failures propagate, and the executor records
    them.
    """

    if now is None:
        now = datetime.now(UTC)
    turn = now

    def decide(refs: set[int], leased: set[int]) -> retention.Plan:
        with _session(settings) as s:
            window = cyclemod.retained_runs(s, keep)
        return retention.plan(settings, window, refs, leased)

    def sweep(plan: retention.Plan) -> list[Path]:
        if not plan.kept:
            return []
        _log_unmanifested("sidestore", list(plan.unmanifested))
        days = settings.evidence_retention_days
        victims: list[Path] = []
        for table in SIDESTORE_TABLES:
            table_dir = settings.sidestore_dir / table
            if not table_dir.is_dir():
                continue
            # A parquet file is under <table>/<source>/<host>/.
            for path in sorted(table_dir.rglob("*.parquet")):
                ts = _file_snapshot_ts(path)
                if ts is None:
                    log.warning("sidestore prune: no readable run key in %s, leaving it", path)
                    continue
                if plan.keeps(ts, _path_identity(path, settings.sidestore_dir, 1)):
                    continue  # a kept run, a kept run's manifest, or a run in flight still needs it
                if days is not None and not _past_period(ts, days, turn):
                    continue  # The file is inside the regulatory period.
                if not dry_run:
                    path.unlink()
                victims.append(path)
        return victims

    if not dry_run:
        await _sweep_sidestore_spills(settings.sidestore_dir, turn)
        await _sweep_sidestore_tmp_throttled(settings.sidestore_dir, turn)
    async with store.try_cycle_lock() as locked:
        if not locked:
            return None
        plan = await asyncio.to_thread(decide, await _assessment_refs(store), await _leased_runs(store))
    return await asyncio.to_thread(sweep, plan)


async def _prune_sidestore_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    victims = await prune_sidestore(ctx.settings, ctx.store, _graph_keep(limits))
    if victims is None:
        log.info("sidestore prune skipped: a collection run holds the cycle lock")
        return "skipped: a collection run holds the cycle lock"
    if not victims:
        return f"nothing to prune beyond the newest {limits.cycle_keep_runs} cycle(s)"
    log.info(
        "sidestore prune deleted %d file(s) beyond the newest %d cycle(s): %s",
        len(victims),
        limits.cycle_keep_runs,
        ", ".join(p.name for p in victims),
    )
    return f"deleted {len(victims)} sidestore file(s) beyond the newest {limits.cycle_keep_runs} cycle(s)"


# The time for which the temporary file of a raw write must be unmodified
# before a sweep removes it. The standalone sweep runs without the cycle lock,
# and this age protects a write in flight. A temporary file exists only from
# one write call to the rename that follows it.
RAW_TMP_MIN_AGE = timedelta(hours=6)
# The least time between two standalone walks of the raw store for those files
# in one process (`prune_rawstore` with the period tier off).
RAW_TMP_SWEEP_INTERVAL = timedelta(hours=6)
_raw_tmp_swept_at: datetime | None = None
# The time for which a spill file (core/rawstore.py `spill`) must be
# unmodified before the prune removes it. A cycle or a source refresh removes
# every spill file that it made before it ends. The start of the next cycle or
# refresh removes the spill files that a killed one left. A spill file is in
# use from its fetch to its load, inside one fetch window of a cycle or a
# refresh.
RAW_SPILL_MIN_AGE = timedelta(hours=24)
# The time for which an HTTP trace spool (collectors/http_trace.py) must be
# unmodified before the raw-store prune removes it. A trace spools from the
# start of its fetch until the write of the fetched payload seals it. Both
# happen inside the cycle or the device job that fetched the payload. A
# process that is killed in between leaves the spool with the unsealed
# exchanges.
HTTP_TRACE_SPOOL_MIN_AGE = timedelta(hours=24)
# `SIDESTORE_TMP_MIN_AGE` is the time for which the temporary file of a
# side-store write (core/sidestore.py `_publish`) must be unmodified before a
# sweep removes it. `SIDESTORE_TMP_SWEEP_INTERVAL` is the least time between
# two walks of the side store for those files in one process. The sweep runs
# without the cycle lock, and the age protects a write in flight. A temporary
# file exists only from the start of one table write to the rename that ends
# it. The same age applies to the DuckDB spill directory of a reader
# (`sweep_sidestore_spills`). The process of the reader updates the
# modification time of the directory every time it opens a connection. The
# directory holds files only while a query runs.
SIDESTORE_TMP_MIN_AGE = timedelta(hours=6)
SIDESTORE_TMP_SWEEP_INTERVAL = timedelta(hours=6)
_sidestore_tmp_swept_at: datetime | None = None


def _sweep_tmp_file(path: Path, cutoff: datetime, store: str) -> bool:
    """Remove one temporary file of an unfinished write when it was last
    modified before `cutoff`, and return whether it was removed. A file that
    vanishes first (renamed by its writer, or removed by another sweep) is
    skipped. A file that cannot be removed is logged and left. `store` is the
    name of the store in the log."""
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if modified >= cutoff:
            return False
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("%s tmp sweep: could not remove %s, leaving it: %s", store, path, exc)
        return False
    return True


def _sweep_due(last: datetime | None, now: datetime, interval: timedelta) -> bool:
    """Whether a sweep that this process last ran at `last` runs again at
    `now`. It runs when it never ran, when `interval` or more has passed, or
    when `now` is earlier than `last`. `now` is earlier than `last` after the
    wall clock was stepped back."""
    return last is None or not timedelta(0) <= now - last < interval


def _log_raw_tmp_swept(count: int) -> None:
    if count:
        log.info("rawstore prune: removed %d temporary file(s) of unfinished raw writes", count)


def _hours(age: timedelta) -> str:
    """`age` in hours, as the log lines state it ("24 h")."""
    return f"{age.total_seconds() / 3600:g} h"


def _log_raw_spills_cleared(count: int) -> None:
    if count:
        log.info(
            "rawstore prune: removed %d spill file(s) last modified more than %s ago",
            count,
            _hours(RAW_SPILL_MIN_AGE),
        )


def sweep_raw_tmp(raw_dir: Path, now: datetime, older_than: timedelta = RAW_TMP_MIN_AGE) -> list[Path]:
    """Delete the temporary files of raw writes that never finished, and
    return them.

    `rawstore.write` writes a payload to `<run_id>` + `rawstore.TMP_SUFFIX`
    and renames it into place. It removes the temporary file when the write
    fails. `write_reparse` of core/debug_capture.py writes a re-parse result
    in the same way, to a name that ends in the same suffix. A process that is
    killed during a write leaves the temporary file. Only a file last modified
    more than `older_than` before `now` is deleted (`_sweep_tmp_file`). A
    write in flight keeps its file.
    """
    swept: list[Path] = []
    if not raw_dir.is_dir():
        return swept
    cutoff = now - older_than
    for path in sorted(raw_dir.rglob(f"*{rawstoremod.TMP_SUFFIX}")):
        if _sweep_tmp_file(path, cutoff, "rawstore"):
            swept.append(path)
    return swept


async def _sweep_raw_tmp_throttled(raw_dir: Path, now: datetime) -> None:
    """Run `sweep_raw_tmp` in a worker thread, unless this process already
    ran it less than `RAW_TMP_SWEEP_INTERVAL` before `now`. The time is
    recorded before the walk starts, with no await in between. Two turns in
    one process therefore do not walk at the same time. A `now` earlier than
    the recorded time, as after the wall clock was stepped back, sweeps at
    once.

    `rawstore.clear_spills` removes the spill files older than
    `RAW_SPILL_MIN_AGE` on the same turn. It lists `<raw_dir>/.spill` alone."""
    global _raw_tmp_swept_at
    if not _sweep_due(_raw_tmp_swept_at, now, RAW_TMP_SWEEP_INTERVAL):
        return
    _raw_tmp_swept_at = now
    swept = await asyncio.to_thread(sweep_raw_tmp, raw_dir, now)
    _log_raw_tmp_swept(len(swept))
    cleared = await asyncio.to_thread(
        rawstoremod.clear_spills, raw_dir, before=(now - RAW_SPILL_MIN_AGE).timestamp()
    )
    _log_raw_spills_cleared(len(cleared))


async def _sweep_http_trace_spools(raw_dir: Path, now: datetime) -> None:
    """Remove, in a worker thread, the HTTP trace spools in `raw_dir` last
    modified more than `HTTP_TRACE_SPOOL_MIN_AGE` before `now`
    (`http_trace.sweep_spools`). The sweep lists that one directory alone and
    runs on every turn."""
    removed = await asyncio.to_thread(
        http_trace.sweep_spools, raw_dir, before=(now - HTTP_TRACE_SPOOL_MIN_AGE).timestamp()
    )
    if removed:
        log.info(
            "rawstore prune: removed %d HTTP trace spool file(s) last modified more than %s ago",
            len(removed),
            _hours(HTTP_TRACE_SPOOL_MIN_AGE),
        )


def sweep_sidestore_tmp(
    sidestore_dir: Path, now: datetime, older_than: timedelta = SIDESTORE_TMP_MIN_AGE
) -> list[Path]:
    """Delete the temporary files of side-store writes that never finished,
    and return them.

    `sidestore.write_table` writes a table to `<run_id>` +
    `SIDESTORE_TMP_SUFFIX` and renames it into place. It removes the temporary
    file when the write fails. A process that is killed during a write leaves
    the temporary file. Only a file last modified more than `older_than`
    before `now` is deleted (`_sweep_tmp_file`). A write in flight keeps its
    file.
    """
    swept: list[Path] = []
    if not sidestore_dir.is_dir():
        return swept
    cutoff = now - older_than
    for path in sorted(sidestore_dir.rglob(f"*{SIDESTORE_TMP_SUFFIX}")):
        if _sweep_tmp_file(path, cutoff, "sidestore"):
            swept.append(path)
    return swept


async def _sweep_sidestore_tmp_throttled(sidestore_dir: Path, now: datetime) -> None:
    """Run `sweep_sidestore_tmp` in a worker thread, unless this process
    already ran it less than `SIDESTORE_TMP_SWEEP_INTERVAL` before `now`
    (`_sweep_due`). The time is recorded before the walk starts, with no
    await in between. Two turns in one process therefore do not walk at the
    same time."""
    global _sidestore_tmp_swept_at
    if not _sweep_due(_sidestore_tmp_swept_at, now, SIDESTORE_TMP_SWEEP_INTERVAL):
        return
    _sidestore_tmp_swept_at = now
    swept = await asyncio.to_thread(sweep_sidestore_tmp, sidestore_dir, now)
    if swept:
        log.info("sidestore prune: removed %d temporary file(s) of unfinished side-store writes", len(swept))


def _spill_entries(directory: Path) -> list[Path] | None:
    """The sorted entries of `directory`. The result is an empty list when the
    directory does not exist. The result is None, with a log line, when the
    directory cannot be listed."""
    try:
        return sorted(directory.iterdir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        log.warning("sidestore spill sweep: could not list %s, leaving it: %s", directory, exc)
        return None


def _sweep_spill_dir(spill: Path, before: float) -> bool:
    """Remove the spill directory of one process with its files, and return
    whether it was removed. The directory is removed only when the directory
    and every file in it were last modified before `before`, an epoch time in
    seconds. A path that is not a directory, and a directory with an entry
    that is not a regular file, are left. A path that cannot be read or
    removed is logged."""
    try:
        st = spill.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("sidestore spill sweep: could not read %s, leaving it: %s", spill, exc)
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_mtime >= before:
        return False
    entries = _spill_entries(spill)
    if entries is None:
        return False
    for path in entries:
        try:
            entry = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("sidestore spill sweep: could not read %s, leaving %s: %s", path, spill, exc)
            return False
        if not stat.S_ISREG(entry.st_mode) or entry.st_mtime >= before:
            return False
    try:
        for path in entries:
            path.unlink(missing_ok=True)
        spill.rmdir()
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("sidestore spill sweep: could not remove %s, leaving it: %s", spill, exc)
        return False
    return True


def sweep_sidestore_spills(
    sidestore_dir: Path, now: datetime, older_than: timedelta = SIDESTORE_TMP_MIN_AGE
) -> list[Path]:
    """Delete the DuckDB spill files that no side-store reader uses, and return
    the removed directories and files.

    Each process that reads the side store spills to its own directory under
    `SIDESTORE_SPILL_DIR` (core/sidestore.py `spill_dir`). The process sets the
    modification time of that directory to the current time every time it
    opens a connection. DuckDB removes its files from the directory after each
    query. A process that is killed while a query spills leaves its files
    there, up to `sidestore.DUCKDB_TEMP_LIMIT_MB`. Every process leaves the
    directory when it ends. A directory is removed with its files when the
    directory and every file in it were last modified more than `older_than`
    before `now`.

    A database that is opened on the catalog without its own spill directory
    spills to the DuckDB default, `<catalog>.tmp`. A spill file there that was
    last modified more than `older_than` before `now` is removed. DuckDB
    removes the directory when the database that created it closes.

    The sweep lists those directories alone. A path that vanishes first is
    skipped. A path that cannot be listed or removed is logged and left. The
    sweep raises no OSError.
    """
    cutoff = now - older_than
    removed: list[Path] = []
    for spill in _spill_entries(sidestore_dir / SIDESTORE_SPILL_DIR) or []:
        if _sweep_spill_dir(spill, cutoff.timestamp()):
            removed.append(spill)
    for path in _spill_entries(sidestore_dir / f"{SIDESTORE_CATALOG}.tmp") or []:
        if path.name.startswith(DUCKDB_SPILL_PREFIX) and _sweep_tmp_file(path, cutoff, "sidestore"):
            removed.append(path)
    return removed


async def _sweep_sidestore_spills(sidestore_dir: Path, now: datetime) -> None:
    """Run `sweep_sidestore_spills` in a worker thread. The sweep lists the
    spill directories alone and runs on every turn."""
    removed = await asyncio.to_thread(sweep_sidestore_spills, sidestore_dir, now)
    if removed:
        log.info(
            "sidestore prune: removed %d DuckDB spill path(s) no reader has used for more than %s",
            len(removed),
            _hours(SIDESTORE_TMP_MIN_AGE),
        )


def _unlink_raw(path: Path) -> None:
    """Delete a raw file, the HTTP trace of the fetch that produced it
    (core/rawstore.py `TRACE_SUFFIX`) and the debug capture files of its loads
    (`DEBUG_SUFFIXES`). The trace and the capture files have no retention tier
    of their own."""
    path.unlink()
    rawstoremod.trace_path(path).unlink(missing_ok=True)
    for suffix in rawstoremod.DEBUG_SUFFIXES:
        rawstoremod.sibling(path, suffix).unlink(missing_ok=True)


def _predates_manifests(settings: Settings, keys: set[int]) -> Callable[[int], bool]:
    """A test for whether a run with no manifest was published before manifests
    existed. A run whose manifest the period sweep removed fails it.

    The first manifest ever written links to no predecessor. When the oldest
    surviving manifest is that one, a run older than it predates manifests and
    its raw files are left alone (no-migration). Otherwise the manifests below
    the oldest survivor were removed by `prune_manifests`, and so was any one
    missing between survivors. With no manifest on disk at all every run predates them.
    """
    if not keys:
        return lambda run: True
    oldest = min(keys)
    try:
        first = manifestmod.read(settings, oldest).previous is None
    except (OSError, ValueError):
        # The oldest manifest is unreadable. It counts as the first manifest,
        # and the raw files of older runs are kept.
        first = True
    return lambda run: first and run < oldest


async def prune_rawstore(
    settings: Settings, store: Store, keep: int | cyclemod.Keep, *, now: datetime | None = None
) -> list[Path] | None:
    """Delete raw payload files whose regulatory period has passed and that no
    manifest of a retained run needs.

    This is the only sweep that deletes raw payloads. It is off while
    `settings.evidence_retention_days` is `None`, the default, and then keeps
    every raw payload. Raw payloads are DORA evidence.

    A raw file has no `snapshot_ts` column. Its `.meta.json` sidecar joins it
    to at most one run, once (`core/rawstore.py mark_joined`). The graph-count
    tier of a raw file is the membership of that run in `retained_runs`, plus
    the manifest-membership check
    (`retention.manifest_protected_identities`), through the `retention.Plan`
    that the side-store sweep reads. 3 kinds of file do not reach the period
    check and are kept:

    - A parked file has no `.meta.json` sidecar and belongs to no run.
    - A file joined a run that has no manifest on disk, and the run predates
      the manifests (`_predates_manifests`).
    - A file joined a run that is graph-retained, or the manifest of a
      retained run lists the file.

    A superseded payload (`core/rawstore.py mark_superseded`) joined no run,
    and no manifest lists it. Its period is measured against the fetch time
    in its run id (`core/ribsource.py run_ts`).

    The temporary files of raw writes that never finished are removed too,
    with the period tier on or off. They are logged, and the result does not
    hold them. With the tier off, `sweep_raw_tmp` removes them before the lock
    is tried, in a worker thread and at most once per `RAW_TMP_SWEEP_INTERVAL`
    in a process. With the tier on, the walk of the tier removes them, and the
    store is walked once per turn. In both cases only a file older than
    `RAW_TMP_MIN_AGE` is removed. The spill files that the fetch window of a
    cycle left behind (`core/rawstore.py` `spill`) are removed on the same
    turn when they are older than `RAW_SPILL_MIN_AGE`. The HTTP trace spools
    that a killed process left in the top directory of the store
    (collectors/http_trace.py) are removed on every turn, before the lock is
    tried, when they are older than `HTTP_TRACE_SPOOL_MIN_AGE`. `now` is the
    time against which this turn measures ages and the throttle. It defaults
    to the current time.

    The decision is read under the cross-pod cycle lock, as in
    `prune_sidestore`. A fetch in flight can write the file that the sweep
    would delete. The result is the list of deleted files, or None when a
    collection held the lock and this turn was skipped. Failures propagate,
    and the executor records them.
    """

    if now is None:
        now = datetime.now(UTC)
    raw_dir = settings.raw_dir
    tmp_cutoff = now - RAW_TMP_MIN_AGE

    def decide(refs: set[int], leased: set[int]) -> retention.Plan | None:
        if settings.evidence_retention_days is None or not raw_dir.is_dir():
            return None
        with _session(settings) as s:
            window = cyclemod.retained_runs(s, keep)
        return retention.plan(settings, window, refs, leased)

    def sweep(plan: retention.Plan) -> list[Path]:
        days = settings.evidence_retention_days
        if days is None:
            return []
        kept = plan.kept
        _log_unmanifested("rawstore", list(plan.unmanifested))
        manifest_keys = set(manifestmod.keys(settings))
        predates = _predates_manifests(settings, manifest_keys)
        victims: list[Path] = []
        swept = 0
        # The glob matches raw files and temporary files. The name of a
        # temporary file is the name of a raw file plus ".tmp"
        # (`rawstore.TMP_SUFFIX`).
        for path in sorted(raw_dir.rglob(f"*{rawstoremod.SUFFIX}*")):
            if path.name.endswith(rawstoremod.TMP_SUFFIX):
                if _sweep_tmp_file(path, tmp_cutoff, "rawstore"):
                    swept += 1
                continue
            if not path.name.endswith(rawstoremod.SUFFIX):
                continue
            sidecar = path.with_name(path.name[: -len(rawstoremod.SUFFIX)] + rawstoremod.META_SUFFIX)
            if not sidecar.is_file():
                continue  # A parked file belongs to no run.
            try:
                joined = json.loads(sidecar.read_text()).get("snapshot_ts")
            except (OSError, ValueError):
                log.warning("rawstore prune: unreadable sidecar for %s, leaving it", path)
                continue
            fetch_ts = run_ts(path.name[: -len(rawstoremod.SUFFIX)])
            if fetch_ts is None:
                log.warning("rawstore prune: no readable fetch time in %s, leaving it", path)
                continue
            if joined is None:
                # A superseded file joined no run. Only the period tier applies.
                if _past_period(fetch_ts, days, now):
                    _unlink_raw(path)
                    victims.append(path)
                continue
            if not kept:
                # The plan keeps no run. A joined file is left in place.
                continue
            if type(joined) is not int:
                log.warning("rawstore prune: the sidecar of %s names no run key, leaving it", path)
                continue
            if plan.keeps(joined, _path_identity(path, raw_dir, 0)):
                continue  # a kept run, a kept run's manifest, or a run in flight still needs it
            if joined not in manifest_keys and predates(joined):
                continue  # The run predates the manifests. Its files are kept.
            if _past_period(fetch_ts, days, now):
                _unlink_raw(path)
                victims.append(path)
        _log_raw_tmp_swept(swept)
        cleared = rawstoremod.clear_spills(raw_dir, before=(now - RAW_SPILL_MIN_AGE).timestamp())
        _log_raw_spills_cleared(len(cleared))
        return victims

    await _sweep_http_trace_spools(raw_dir, now)
    if settings.evidence_retention_days is None:
        await _sweep_raw_tmp_throttled(raw_dir, now)
    async with store.try_cycle_lock() as locked:
        if not locked:
            return None
        plan = await asyncio.to_thread(decide, await _assessment_refs(store), await _leased_runs(store))
    if plan is None:
        return []
    return await asyncio.to_thread(sweep, plan)


async def _prune_rawstore_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    victims = await prune_rawstore(ctx.settings, ctx.store, _graph_keep(limits))
    if victims is None:
        log.info("rawstore prune skipped: a collection run holds the cycle lock")
        return "skipped: a collection run holds the cycle lock"
    days = ctx.settings.evidence_retention_days
    if days is None:
        return "evidence_retention_days is unset: the period tier is off, keeping every raw file"
    if not victims:
        return f"nothing to prune past {days} day(s)"
    log.info(
        "rawstore prune deleted %d file(s) past %d day(s): %s",
        len(victims),
        days,
        ", ".join(p.name for p in victims),
    )
    return f"deleted {len(victims)} raw file(s) past {days} day(s)"


def _manifest_mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None


async def prune_manifests(
    settings: Settings, store: Store, keep: int | cyclemod.Keep | None = None
) -> list[int] | None:
    """Delete the manifest files whose regulatory period has passed, and keep
    the chain that a kept, newer manifest links back through.

    Only the period tier deletes a manifest. The manifest of a run that the
    graph keeps is not deleted (`cycle.retained_runs` at `keep`, by default
    the configured retention of the deployment, read under the lock). A run in
    the graph answers a trace from its manifest. Without a manifest its reads
    are approximate and its freshness is empty. The `previous` link of a
    manifest also keeps its target, and a manifest chain is walkable from any
    surviving manifest back to its nearest surviving ancestor. The newest
    manifest is kept at any age. A manifest past the period is kept when the
    newest manifest, or a manifest that is not past the period, links to it as
    `previous`. Only this sweep keeps the manifest chain behind a retained
    assessment (`_assessment_pins`). The manifest of a run that a reader holds
    open (`_leased_runs`) is kept until the lease ends, as in every other
    sweep.

    The age of a manifest that parses is measured from its `opened` timestamp.
    `retained_runs` and the raw and side-store sweeps date a run by the same
    moment, the snapshot key. The age of a manifest that does not parse is
    measured from the mtime of the file. A manifest that does not parse is
    checked against the period, and its `previous` link is not read.

    The sweep is off while `settings.evidence_retention_days` is `None`, as
    `prune_rawstore` is. It holds the cross-pod cycle lock. A run in flight
    writes the next manifest in the chain, and the lock keeps this sweep from
    reading the manifest directory during that write.

    The result is the list of snapshot keys whose manifest, signature and
    linked graph archive were deleted, or None when a collection held the lock
    and this turn was skipped. An archive is removed only when its victim
    manifest parses and the archive path is inside `graph_archives_dir`.
    Failures propagate, and the executor records them.
    """

    pins: set[int] = set()
    leased: set[int] = set()
    limits = (
        keep if keep is not None else cyclemod.Keep(settings.cycle_keep_runs, settings.cycle_keep_device_runs)
    )

    def run() -> list[int]:
        days = settings.evidence_retention_days
        if days is None:
            return []
        keys = manifestmod.keys(settings)
        if len(keys) <= 1:
            return []  # At most 1 manifest exists. The newest manifest is kept.
        with _session(settings) as s:
            in_graph = set(cyclemod.retained_runs(s, limits))
        newest = keys[-1]
        now = datetime.now(UTC)
        records: dict[int, manifestmod.SnapshotManifest] = {}
        for k in keys:
            try:
                records[k] = manifestmod.read(settings, k)
            except (OSError, ValueError):
                continue
        past_period: set[int] = set()
        for k in keys:
            if k == newest or k in pins or k in leased or k in in_graph:
                continue
            record = records.get(k)
            age_from = None
            if record is not None:
                try:
                    age_from = datetime.fromisoformat(record.opened)
                except ValueError:
                    age_from = None
            if age_from is None:
                age_from = _manifest_mtime(manifestmod.path_for(settings, k))
            if age_from is not None and now - age_from > timedelta(days=days):
                past_period.add(k)
        needed: set[int] = set()
        for k in keys:
            if k in past_period:
                continue
            record = records.get(k)
            if record is not None and record.previous is not None:
                needed.add(record.previous.snapshot_key)
        victims = sorted(k for k in past_period if k not in needed)
        for k in victims:
            # The archive reference is read before the manifest is removed. An
            # archive is deleted only with the manifest that owns it. An
            # archive without a readable manifest is left.
            record = records.get(k)
            archive_path: Path | None = None
            if record is not None and record.graph_archive is not None:
                resolved_archive = (settings.hst_data_dir / record.graph_archive.path).resolve()
                try:
                    resolved_archive.relative_to(settings.graph_archives_dir.resolve())
                except ValueError:
                    pass
                else:
                    archive_path = resolved_archive
            manifestmod.path_for(settings, k).unlink(missing_ok=True)
            manifestmod.sig_path_for(settings, k).unlink(missing_ok=True)
            if archive_path is not None:
                archive_path.unlink(missing_ok=True)
        return victims

    async with store.try_cycle_lock() as locked:
        if not locked:
            return None
        pins = await _assessment_pins(store, settings)
        leased = await _leased_runs(store)
        return await asyncio.to_thread(run)


async def _prune_manifests_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    victims = await prune_manifests(ctx.settings, ctx.store, _graph_keep(limits))
    if victims is None:
        log.info("manifest prune skipped: a collection run holds the cycle lock")
        return "skipped: a collection run holds the cycle lock"
    days = ctx.settings.evidence_retention_days
    if days is None:
        return "evidence_retention_days is unset: the period tier is off, keeping every manifest"
    if not victims:
        return f"nothing to prune past {days} day(s)"
    log.info("manifest prune deleted %d manifest(s) past %d day(s): %s", len(victims), days, victims)
    return f"deleted {len(victims)} manifest(s) past {days} day(s)"


async def _build_device_run_body(ctx: Context, job: Job) -> str:
    """Fold every raw payload that a `collect.fetch` job parked since the last
    device run into one new run.

    The body runs the pipeline of `runs_exec.launch` (the Run row, the
    cross-process cycle lock, site re-assignment, host-key pinning), as
    `collect_cycle_body` does for a scheduled cycle. `runs_exec.DEVICE_RUN` is
    the pseudo-source for which `launch` calls `build_device_run`.
    """
    run = await runs_exec.run_blocking(ctx.store, ctx.settings, runs_exec.DEVICE_RUN)
    if run is None:
        return "skipped: a run already holds the cycle claim"
    if run.status == "running":
        # The run ended and its row was not finished. `_outcome` in
        # worker/collect.py handles the same case.
        return f"run {run.id} ended, and its outcome was not recorded"
    head = (run.detail or "").split(" · ", 1)[0]
    return f"run {run.id} {run.status}" + (f": {head}" if head else "")


async def _inventory_housekeeping(ctx: Context, now: datetime) -> None:
    from hst.app.inventory import collection
    from hst.app.inventory.observations import InventoryContext, ObservationService

    if not collection.has_inventory(ctx.store):
        return
    async with ctx.store.inventory().transaction() as tx:
        await tx.purge_expired_previews(now)
        await tx.reap_outbox(now)
        await tx.purge_outbox_done(now - timedelta(days=7))
        active = (await tx.get_state()).activation_state == "active"
    if active:
        await ObservationService(InventoryContext(ctx.store, ctx.settings)).retry(worker_id="maintenance")


async def _purge_sessions_body(ctx: Context, job: Job) -> str:
    """Delete expired and idle sessions and the SSO login state that no login
    consumed.

    An expired session does not authenticate, and an abandoned OIDC state row
    cannot complete a login. The other purge of these rows runs at boot.
    """
    now = datetime.now(UTC)
    sessions = await ctx.store.purge_expired_sessions(now, idle_after(ctx.settings))
    states = await ctx.store.purge_expired_auth_state(now)
    await _inventory_housekeeping(ctx, now)
    return f"deleted {sessions} expired session(s) and {states} abandoned login attempt(s)"


async def _purge_login_events_body(ctx: Context, job: Job) -> str:
    """Delete the sign-in records that are older than the retention period.

    The records are evidence. Every failed login is a row, written by an
    unauthenticated caller.
    """
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.login_event_retention_days:
        return "retention is 0: keeping every sign-in record"
    before = datetime.now(UTC) - timedelta(days=limits.login_event_retention_days)
    deleted = await ctx.store.purge_login_events(before)
    return f"deleted {deleted} sign-in record(s) older than {limits.login_event_retention_days} day(s)"


async def _purge_cypher_events_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.cypher_event_retention_days:
        return "retention is 0: keeping every Cypher record"
    before = datetime.now(UTC) - timedelta(days=limits.cypher_event_retention_days)
    deleted = await ctx.store.purge_cypher_events(before)
    return f"deleted {deleted} Cypher record(s) older than {limits.cypher_event_retention_days} day(s)"


async def _purge_job_history_body(ctx: Context, job: Job) -> str:
    """Delete the completed job rows that are older than the retention period.

    A job row stays after success.
    """
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.job_history_retention_days:
        return "retention is 0: keeping every job record"
    before = datetime.now(UTC) - timedelta(days=limits.job_history_retention_days)
    deleted = await ctx.store.purge_jobs(before)
    return f"deleted {deleted} job record(s) older than {limits.job_history_retention_days} day(s)"


# The time for which a conversation that POST /api/agent/ask created is kept.
# No list shows such a conversation. The poll of its ask reads it.
AI_EPHEMERAL_HOURS = 24


async def _purge_ai_conversations_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.ai_conversation_retention_days:
        return "retention is 0: keeping every AI conversation"
    before = datetime.now(UTC) - timedelta(days=limits.ai_conversation_retention_days)
    deleted = await ctx.store.purge_conversations(before)
    return (
        f"deleted {deleted} AI conversation(s) with no message in "
        f"{limits.ai_conversation_retention_days} day(s)"
    )


async def _compact_ai_steps_body(ctx: Context, job: Job) -> str:
    """Compact the tool results that are older than the retention period. A
    compacted step keeps its digest, its character count and its summary."""
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.ai_step_result_days:
        return "retention is 0: keeping every AI tool result"
    now = datetime.now(UTC)
    compacted = await ctx.store.compact_steps(now - timedelta(days=limits.ai_step_result_days), now)
    return f"compacted {compacted} AI tool result(s) older than {limits.ai_step_result_days} day(s)"


async def _purge_ai_ephemeral_body(ctx: Context, job: Job) -> str:
    """Delete the ephemeral conversations that are older than
    AI_EPHEMERAL_HOURS. A conversation limit of 0 keeps every conversation,
    the ephemeral conversations included."""
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.ai_conversation_retention_days:
        return "retention is 0: keeping every AI conversation"
    deleted = await ctx.store.purge_ephemeral(datetime.now(UTC) - timedelta(hours=AI_EPHEMERAL_HOURS))
    return f"deleted {deleted} ephemeral AI conversation(s) older than {AI_EPHEMERAL_HOURS} h"


async def _purge_ai_events_body(ctx: Context, job: Job) -> str:
    limits = await retention.resolve(ctx.store, ctx.settings)
    if not limits.ai_event_retention_days:
        return "retention is 0: keeping every AI event"
    before = datetime.now(UTC) - timedelta(days=limits.ai_event_retention_days)
    deleted = await ctx.store.purge_ai_events(before)
    return f"deleted {deleted} AI event(s) older than {limits.ai_event_retention_days} day(s)"


BODIES: dict[str, JobBody] = {
    PRUNE_GRAPH: _prune_graph_body,
    PRUNE_SIDESTORE: _prune_sidestore_body,
    PRUNE_RAWSTORE: _prune_rawstore_body,
    PRUNE_MANIFESTS: _prune_manifests_body,
    PURGE_SESSIONS: _purge_sessions_body,
    PURGE_LOGIN_EVENTS: _purge_login_events_body,
    PURGE_CYPHER_EVENTS: _purge_cypher_events_body,
    PURGE_JOB_HISTORY: _purge_job_history_body,
    PURGE_AI_CONVERSATIONS: _purge_ai_conversations_body,
    COMPACT_AI_STEPS: _compact_ai_steps_body,
    PURGE_AI_EPHEMERAL: _purge_ai_ephemeral_body,
    PURGE_AI_EVENTS: _purge_ai_events_body,
    BUILD_DEVICE_RUN: _build_device_run_body,
}
