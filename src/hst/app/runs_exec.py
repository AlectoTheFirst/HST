"""Background execution of collection work, one job at a time.

Every collection trigger mints a new `collection_ts` and moves the pointer to
it. Nothing at the key of the previous run is touched. The 3 builders differ in
the sources that are fresh and in the kind of the run:

    execute_cycle     every enabled source (kind "full") or a subset
                      ("partial"), the trigger the scheduler and the UI use
    execute_refresh   one source pressed by an operator (kind "refresh")
    build_device_run  the payloads parked by per-device fetch jobs since the
                      last device run, folded in together (kind "device")

The 3 builders run the same sequence: fetch or re-read, load the fresh sources
under the new key, carry everything else forward from the parent run, the rule
reasoner, the two route-target derivations, re-apply the operator's site
assignments, write the `:CycleRun` meta node with `kind` and `parent`, and
move the pointer last.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import functools
import json
import logging
import sys
import threading
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, MutableMapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, cast

from neo4j import Session

from hst import collectors as coll
from hst import reasoner
from hst.app import crypto, demo_estate
from hst.app import sources as sources_glue
from hst.app.inventory import collection as inventory_collection
from hst.app.inventory.repository import InventoryTx
from hst.app.secrets import FernetResolver
from hst.app.store import Device, DeviceStatus, Run, Source, Store
from hst.collectors.base import CollectionStopped, Collector, GraphGate, fetch_traced
from hst.collectors.http_trace import HttpTrace
from hst.core import Settings, cycle, grapharchive, rawstore, redaction, run_cancel
from hst.core import db as dbmod
from hst.core import finalize as finalization
from hst.core import manifest as manifests
from hst.core import reasoner as rt_reasoner
from hst.core.collection_progress import CollectionProgress, read_progress
from hst.core.cycle import written_scopes
from hst.core.labels import CycleIdentityCollision
from hst.core.loader import collector_type
from hst.core.model import (
    DEGRADING_SECTION_STATUSES,
    DEGRADING_TABLE_STATUSES,
    Batch,
    RunManifest,
    SectionOutcome,
    TableOutcome,
    section_verdict,
    table_verdict,
)

if TYPE_CHECKING:
    from hst.map.project import Projection
    from hst.map.site_config import SiteConfig

logger = logging.getLogger(__name__)


class RunOutcome(NamedTuple):
    """What one collection produced.

    `detail` is the summary line of the run row. `ran` holds the device
    collectors that collected, for the first-contact host-key pin. `snapshot_key`
    is the `collection_ts` that the run published, or None when it published
    nothing. `status` is the status of the run row. It is "error" for a cycle
    in which a source failed and no source collected (`_cycle_status`).
    """

    detail: str
    ran: list[tuple[Source, Device | None, Collector]]
    snapshot_key: int | None
    status: str = "ok"


# Pseudo-sources run without a Source row. "cycle" collects every enabled
# source. "device-run" folds the parked per-device payloads into one run.
# "reasoner" is the standalone derivation trigger, which `execute_source` refuses.
DEVICE_RUN = "device-run"
PSEUDO_SOURCES = ("reasoner", "cycle", DEVICE_RUN)
# The demo estate load (app/demo_estate.py) is a run source only on an instance configured with
# HST_DEMO_FIXTURES. It is not listed with the pseudo-sources. On other instances the name is an
# ordinary source name. The Runs page offers the demo estate load on a card of its own.
DEMO = demo_estate.DEMO


def is_demo(settings: Settings, source: str) -> bool:
    """Whether `source` names the demo estate load on this instance."""
    return source == DEMO and demo_estate.folder(settings) is not None


# One run at a time per process. Across processes, `launch` holds the store's
# cycle lock (PgStore.cycle_lock) around the calls below.
_CYCLE_LOCK = threading.Lock()

# What a builder is told when the lock it was running under stopped being held.
LOCK_LOST = "the cycle lock was lost while this run was building; it was not published"
# What a builder is told when its run was stopped with the lock still held, by
# the cancel of an operator, a shutdown or a caller that stopped waiting. The run
# row records the cancellation.
RUN_STOPPED = "this run was stopped while it was building; it was not published"
# What the detail of a published run adds when a cancel arrived after the
# builder's last stop check (`_drained`).
LATE_CANCEL = "a cancel arrived after the run was published and did not apply"

# The status of a cancelled run row, and the `cycle.CARRY_REASONS` entry under
# which a source that an operator stopped carries its devices forward.
CANCELLED = "cancelled"

# How long a cancelled run waits for its builder thread before it logs that
# the thread has not stopped. The wait goes on until the thread returns.
DRAIN_TIMEOUT_S = 60.0
# How long past DRAIN_TIMEOUT_S a caller that cancelled a run waits for the
# run to finish its row (`wait_for_run`). The run goes on without it.
FINISH_MARGIN_S = 10.0

# Strong references to the builder futures.
_THREADS: set[asyncio.Future[Any]] = set()
# `_drained` waits on the futures of these threads. A future cannot be cancelled once it runs.
_BUILDERS = ThreadPoolExecutor(thread_name_prefix="run-builder")


class RunStop(threading.Event):
    """The stop flag of the run, and one flag per source under it.

    Each source has its own flag. The flag of the run raises every source flag.
    A builder that cannot act on the flag of a source hands its collectors the
    flag of the run (`_arm_stop`).

    `lost` tells a lost lock from the other stops (`lose`). The builder ends with
    the reason that applies (`_stopped`). `armed` is set once the builder has
    handed its collectors their flags (`_arm_stop`). Before that, a source
    without a flag can still be one that the run collects.

    `built` is set once the outcome of the run no longer depends on the flag.
    The builder sets it as the pointer moves to its run (`_finalize_cycle`), and
    `launch` sets it once the builder has returned. After that, only the
    bookkeeping of the run is left, and a cancel does not stop it (`cancel_run`,
    `wait_for_run`).
    """

    def __init__(self) -> None:
        super().__init__()
        self.sources: dict[str, threading.Event] = {}
        self.lost = False
        self.armed = False
        self.built = False

    def lose(self) -> None:
        """Mark the cycle lock as lost and set the flag. `cycle_lock` calls it as `on_lost`."""
        self.lost = True
        self.set()

    def for_source(self, name: str) -> threading.Event:
        """The flag of source `name`, created on the first call."""
        flag = self.sources.get(name)
        if flag is None:
            flag = self.sources[name] = threading.Event()
            if self.is_set():
                flag.set()
        return flag

    def set(self) -> None:
        super().set()
        for flag in self.sources.values():
            flag.set()

    def cancel_source(self, name: str) -> bool:
        """Stop one source. False when this run is not collecting it."""
        flag = self.sources.get(name)
        if flag is None:
            return False
        flag.set()
        return True

    def source_cancelled(self, name: str) -> bool:
        """Whether source `name` alone was stopped. False once the whole run is
        stopping."""
        if self.is_set():
            return False
        flag = self.sources.get(name)
        return flag is not None and flag.is_set()


class RunCancelled(RuntimeError):
    """The answer of a builder whose run ends with nothing published while the
    flag of the run stays down. This happens when the one source of a refresh is
    cancelled alone (`execute_refresh`). `launch` finishes the run as `cancelled`
    with this text as its detail, as it does for a run cancelled as a whole."""


def _source_stop(stop: threading.Event | None, name: str) -> threading.Event | None:
    return stop.for_source(name) if isinstance(stop, RunStop) else stop


def _source_cancelled(stop: threading.Event | None, name: str) -> bool:
    return isinstance(stop, RunStop) and stop.source_cancelled(name)


def _cut_by_cancel(exc: BaseException, stop: threading.Event | None, name: str) -> bool:
    """Whether a device's load ended because its source alone was cancelled
    (`Collector.check_stop`)."""
    return isinstance(exc, CollectionStopped) and _source_cancelled(stop, name)


def _arm_stop(
    prepared: list[PreparedSource], stop: threading.Event | None, *, per_source: bool = True
) -> None:
    """Hand each collector a stop flag. A fetch ends before its next request or
    command once the run is stopped.

    With `per_source`, each collector gets the flag of its source
    (`RunStop.for_source`). The flag of the run raises it, and a cancel of that
    source alone raises it too. Only a builder that acts on the cancel of a
    source arms its sources that way, because `cancel_run` reports a source with
    a flag as stopped. Without `per_source`, every collector gets the flag of the
    run and no source flag is created. A cancel of one source of the run then
    answers that the run is not collecting it.

    A `RunStop` is marked `armed` after every flag is handed out. A reader that
    sees the mark knows that a source without a flag is not one that this run
    collects."""
    for source in prepared:
        flag = _source_stop(stop, source.row.name) if per_source else stop
        for unit in source.units:
            # a seam test's stand-in collector has no slot for it
            if unit.collector is not None and hasattr(unit.collector, "stop"):
                unit.collector.stop = flag
    if isinstance(stop, RunStop):
        stop.armed = True


async def _arm_identity(store: Store, prepared: list[PreparedSource], run_id: int) -> None:
    """Hand each collector of the run the device identity registry of the
    store, bound to this run. Every Device uid that the run writes is resolved
    there. A uid that this run mints records the run id. `_prepare_all` builds the
    collectors before the run row exists."""
    collectors = [
        unit.collector
        for source in prepared
        for unit in source.units
        # a seam test's stand-in collector has no slot for it
        if unit.collector is not None and hasattr(unit.collector, "identity")
    ]
    if not collectors:
        return
    resolver = await sources_glue.StoreResolver.open(store, run_id)
    for collector in collectors:
        collector.identity = resolver


def _stopped(stop: threading.Event | None) -> None:
    """Raise when the run being built has been stopped. A run stops when its
    lock was lost, when it was cancelled or when its process shuts down.

    The builders call it before the load of each device, between phases and
    immediately before the switchover. The unwind of a stopped builder removes
    what it wrote (`_building`). Retention (`cycle.prune`) removes it when the
    unwind could not run.

    A plain `threading.Event` has no cause and raises LOCK_LOST. The direct
    callers of the builders pass a plain event to signal a lost lock.
    """
    if stop is not None and stop.is_set():
        raise RuntimeError(RUN_STOPPED if isinstance(stop, RunStop) and not stop.lost else LOCK_LOST)


def _remove_run_files(settings: Settings, cts: int) -> None:
    """Remove the evidence files that an unpublished run wrote under its key.
    These are the manifest and its signature, the graph archive and the HST map
    stage."""
    paths = (manifests.path_for(settings, cts), manifests.sig_path_for(settings, cts))
    for path in (*paths, grapharchive.path_for(settings, cts)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("run %s was not published and %s could not be removed", cts, path, exc_info=True)
    try:
        from hst.map import store as hst_store

        hst_store.discard_staged(settings.sidestore_dir, cts)
    except ImportError:
        pass  # without the sidestore extra no map stage was written


def _discard_unpublished(s: Session, settings: Settings, cts: int) -> None:
    """Remove what run `cts` wrote when the pointer does not name it. Never
    raises. When the pointer cannot be read the run is left as it is."""
    discard = getattr(cycle, "discard_run", None)
    if discard is None:  # a stub of the cycle module without it writes nothing to discard
        return
    try:
        if cycle.current_ts(s) == cts:
            return
    except Exception:
        logger.warning("run %s: the pointer could not be read, leaving the run in place", cts, exc_info=True)
        return
    try:
        discard(s, cts)
    except Exception:
        logger.warning(
            "run %s was not published and could not be discarded; retention removes it", cts, exc_info=True
        )
    _remove_run_files(settings, cts)


@contextlib.contextmanager
def _building(s: Session, settings: Settings, cts: int, kind: str, prev: int | None) -> Iterator[None]:
    """A run being built, recorded before its first write and discarded unless
    the pointer names it when the block ends.

    The `:CycleRun` node is written first (`cycle.begin_run`). Every way out of
    the block that leaves the pointer elsewhere removes the run's objects, its
    node and its evidence files.
    """
    begin = getattr(cycle, "begin_run", None)
    if begin is not None:  # a stub of the cycle module without it records nothing
        begin(s, cts, kind, prev)
    try:
        yield
    finally:
        _discard_unpublished(s, settings, cts)


async def _outwait(task: asyncio.Future[Any], bound_s: float | None) -> bool:
    """Wait up to `bound_s` seconds for `task`, whatever cancels the caller in
    the meantime. With `bound_s` None, wait until `task` is done. True when
    `task` is done.

    The caller is on its way out of a cancellation and waits for work that it
    must not leave behind. A further cancellation does not cut the wait short.
    Each further cancellation is absorbed and uncancelled. The cancel count of
    the caller stays at the one cancellation that it re-raises.
    """
    loop = asyncio.get_running_loop()
    deadline = None if bound_s is None else loop.time() + bound_s
    current = asyncio.current_task()
    while not task.done():
        left = None if deadline is None else deadline - loop.time()
        if left is not None and left <= 0:
            return False
        try:
            await asyncio.wait({task}, timeout=left)
        except asyncio.CancelledError:
            if current is not None:
                current.uncancel()
    return True


async def _drained(
    stop: threading.Event, fn: Callable[..., RunOutcome], /, *args: Any, **kwargs: Any
) -> RunOutcome:
    """Run a builder on a worker thread, and do not return while it still runs.

    The future is shielded and waited for on the cancellation path. The
    `cycle_lock` stays held until the thread is done.

    `stop` is set first. The thread stops at its next check: before the load of
    the next device, between the stages of the load in flight or the row groups
    of its side tables, or before the next command of a fetch. The wait has no
    bound. A thread still running after DRAIN_TIMEOUT_S is logged, and the lock
    stays held until it returns.

    A second cancellation during that wait does not shorten it.

    A builder that returns a published run (`RunOutcome.snapshot_key`) was past
    its last stop check when the cancel arrived, and the pointer names its run.
    Its outcome is returned in place of the cancellation, which is consumed. Its
    detail notes the late cancel (`LATE_CANCEL`). The caller then records the
    published run and the device statuses that the next run compares against. A
    builder that returns without publishing leaves the cancellation standing.
    """
    context = contextvars.copy_context()
    task = asyncio.wrap_future(_BUILDERS.submit(context.run, functools.partial(fn, *args, **kwargs)))
    _THREADS.add(task)
    task.add_done_callback(_THREADS.discard)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as exc:
        stop.set()
        if not await _outwait(task, DRAIN_TIMEOUT_S):
            logger.error(
                "the collection thread has not stopped %.0fs after the run was cancelled; "
                "the cycle lock stays held until it returns",
                DRAIN_TIMEOUT_S,
            )
            await _outwait(task, None)
        if not task.cancelled() and task.exception() is not None:
            logger.warning("the cancelled collection thread ended with: %s", task.exception())
        elif not task.cancelled() and task.result().snapshot_key is not None:
            outcome: RunOutcome = task.result()
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
            reason = str(exc)
            note = LATE_CANCEL + (f" ({reason})" if reason else "")
            logger.info(
                "the collection thread published %s before its cancel took effect", outcome.snapshot_key
            )
            return outcome._replace(detail=f"{outcome.detail} · {note}")
        raise


async def _settled(work: Coroutine[Any, Any, None]) -> None:
    """Run `work` to its end, whatever cancels the caller in the meantime,
    and raise what it raises.

    The work is what a run does once its builder has returned: the device
    statuses that the skip decisions of the next run compare against, the
    host-key pins and the inventory publication. A cancellation that arrives in
    the meantime is absorbed (`_outwait`).
    """
    inner = asyncio.ensure_future(work)
    await _outwait(inner, None)
    inner.result()


async def valid_sources(store: Store) -> list[str]:
    rows = await store.list_sources()
    return [*sorted(r.name for r in rows if r.enabled), *PSEUDO_SOURCES]


class PreparedDevice:
    """One buildable collector of a source's fleet.

    `device` is None for the implicit single-host source (a fleet-capable
    source with zero device rows, or a controller type with no fleet at all).
    `collector` is None when the build for this device failed. `error` then
    holds the reason, and the cycle records the device as failed without
    touching the rest of the fleet.
    """

    def __init__(
        self,
        device: Device | None,
        collector: Collector | None,
        error: str | None,
        effective: inventory_collection.ResolvedCollection | None = None,
    ) -> None:
        self.device = device
        self.collector = collector
        self.error = error
        # The resolution that this unit was built from under resolver v2 (profile,
        # credential and normalization revisions, configuration digest). None
        # under v1.
        self.effective = effective


class PreparedSource:
    """One configured source, resolved before the worker thread starts.

    `units` holds one PreparedDevice per enabled device of the fleet, or
    exactly one with `device=None` for the implicit single-host case. `error`
    is a group-level error (bad secrets, bad group config). With an error, the
    whole source is recorded as failed and the run goes on.
    """

    def __init__(
        self,
        row: Source,
        units: list[PreparedDevice],
        error: str | None = None,
        capture: ExecutionCapture | None = None,
        paused_hosts: set[str] | None = None,
    ) -> None:
        self.row = row
        self.units = units
        self.error = error
        # Paused targets retain ownership without constructing a collector or
        # entering the runnable unit index. Deleted targets are absent here.
        self.paused_hosts = paused_hosts or set()
        # Under resolver v2, the capture that every source of the run shares. It
        # is taken in the transaction that resolved the units. The placement
        # revisions that it lists belong to the same snapshot as the placement
        # generation of the units. None under v1.
        self.capture = capture


class DeviceOutcome:
    """One device's collection result, for the `device_status` table.

    The worker thread produces it and has no store. `launch` persists the list
    of a cycle or a refresh after the thread returns. The attempts of the
    devices of a device run were recorded when their payloads were fetched
    (`run_device_fetch`). The list of a device run records only the graph and
    the skip basis (`_record_graphs`).

    `skipped` means that the fetch succeeded, the payload hash matched, and
    normalize and load were skipped with the objects carried forward. A skip is
    a success.

    `observations_only` is the same fetch with a mismatched observation hash.
    The side tables of the device were written under this run, and its graph
    objects were carried. The outcome is a success unless a degrading
    authoritative section fails it, as it fails a full load. `full` stays false
    on both outcomes. The forced reload keeps its own cadence off
    `last_full_at`. A payload that was normalized and whose batch has the
    digest of the batch on record (`graph_sha`, `collectors/base.py
    load_payload`) is recorded the same way. Its raw file and side tables were
    written. Of its graph, only the part shared with other writers and the part
    with an anchor were written.

    `graph_sha` is the digest of the batch that the load normalized, bound as
    `fingerprint` is. `device_status.last_graph_sha` records it. It is None
    when nothing was normalized. `graph_fetch_ms` is the fetch time of the
    payload of that batch, read from its run id.
    `device_status.last_graph_fetch_at` records it.

    The outcome of a device run holds the skip basis of the payload that it
    loaded (`_record_graphs`, `record_device_basis`). `fingerprint` and
    `obs_sha` hold the basis when they describe what the run loaded, else None.
    `basis_full` is set when the payload was applied as a full one, which
    advances `last_full_at`. The fetch that parked the payload recorded only
    the attempt.

    `sections` holds what the load reported for each section of the payload.
    `authoritative` holds the sections without which the collector of this
    device cannot be read. `tables` holds the same for the side-store tables
    that the load was expected to write. Together they give `completeness`.

    `fetch_started_ms` and `fetch_finished_ms` are the timing of the concurrent
    fetch phase (`_Fetched`). They are null for a direct `coll.execute` call
    with no prefetched payload and for a device that never fetched.
    `ingested_ms` is the time this run loaded the payload, captured after
    `coll.execute` returns. It is null on `skipped` and on every outcome that
    never loaded. A failed outcome holds it when its load began, past the raw
    write or at the join of a full payload by a device run. Such a load can
    have written part of the device into the run beside the carried objects.
    The trace reads it as a failed load (path/gates/coverage.py).

    `verified` means that this fetch checked the device against the basis on
    record and found both hashes equal to the recorded ones. Both observation
    hashes are empty for a collector that declares no observations. A skip on
    the configuration hash alone (a row with no observation hash yet) is not a
    check. With the fetch window, `verified` gives the time a carried device
    was last checked (`_device_entries`). `checked_basis` is the
    (configuration, observation) hash pair that the check compared. The status
    row must still hold this pair for the check to be recorded there
    (`_record_outcomes`, `Store.upsert_device_status`)."""

    def __init__(
        self,
        source: str,
        host: str,
        ok: bool,
        *,
        raw_sha: str | None = None,
        obs_sha: str | None = None,
        skipped: bool = False,
        observations_only: bool = False,
        full: bool = False,
        error: str = "",
        fetch_ms: int | None = None,
        fetch_started_ms: int | None = None,
        fetch_finished_ms: int | None = None,
        ingested_ms: int | None = None,
        load_ms: int | None = None,
        sections: dict[str, SectionOutcome] | None = None,
        authoritative: tuple[str, ...] = (),
        tables: dict[str, TableOutcome] | None = None,
        fingerprint: str | None = None,
        graph_sha: str | None = None,
        graph_fetch_ms: int | None = None,
        basis_full: bool = False,
        verified: bool = False,
        checked_basis: tuple[str, str] | None = None,
    ) -> None:
        self.source = source
        self.host = host
        self.ok = ok
        self.raw_sha = raw_sha
        self.obs_sha = obs_sha
        self.graph_sha = graph_sha
        self.graph_fetch_ms = graph_fetch_ms
        # What `device_status.last_raw_sha` records: the raw hash itself under
        # v1, and under v2 the hash bound to the normalization revision and
        # placement generation (`collection.skip_fingerprint`). `raw_sha`
        # stays the payload's own digest for the manifest.
        self.fingerprint = fingerprint
        self.basis_full = basis_full
        self.skipped = skipped
        self.observations_only = observations_only
        self.verified = verified
        self.checked_basis = checked_basis
        self.full = full
        # The error is stored with the device and in the manifest.
        # `redaction.redact_text` removes the credentials of the shapes that it knows.
        # The sinks that hold the secret values of the source remove those values.
        self.error = redaction.redact_text(error)
        self.fetch_ms = fetch_ms
        self.fetch_started_ms = fetch_started_ms
        self.fetch_finished_ms = fetch_finished_ms
        self.ingested_ms = ingested_ms
        self.load_ms = load_ms
        self.sections = sections or {}
        self.authoritative = authoritative
        self.tables = tables or {}

    @property
    def completeness(self) -> str:
        """The completeness of the sections and tables of this device: ok, partial or failed."""
        return _completeness(self.sections, self.tables, self.authoritative)

    @property
    def status_sha(self) -> str | None:
        """The value the skip decision compares next time."""
        return self.fingerprint if self.fingerprint is not None else self.raw_sha


class RunEvidence:
    """What the run being built accumulates for its snapshot manifest
    (core/manifest.py).

    One instance per run. Every raw and side-store file a collector writes is
    reported here as it is written, with the digest of the bytes that landed
    on disk. `devices` collects the per-device outcomes the
    manifest records beside them.

    Not thread safe. Every write happens in the serial load loop
    (`_collect_sources`, `build_device_run`).
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.files: list[manifests.FileEntry] = []
        self.devices: list[DeviceOutcome] = []
        # The (source, host) of every device whose load committed a graph write
        # and then ended without an outcome, because its source was cancelled.
        # The objects of such a device mix that write with the carried objects,
        # as the objects of a failed load do.
        self.mixed_loads: set[tuple[str, str]] = set()
        # (source, host) -> (start, end) in epoch ms of the last fetch that
        # checked a device that this run carries without an outcome
        # (`DeviceStatus.last_verified_at`). It holds the per-device fetches
        # since the parent run (`_note_rechecks`).
        self.rechecked: dict[tuple[str, str], tuple[int | None, int]] = {}
        # What the loads could not settle from their payloads
        # (`RunManifest.warnings`), for the manifest's `warnings` beside the
        # reasoner's own (`_finalize_cycle`).
        self.warnings: list[str] = []
        # What the run was resolved under: the resolver version,
        # the intent generation captured before the build and the desired
        # placement revision per known device uid. `launch` fills it from the
        # inventory state. A direct caller leaves `LEGACY_CONTEXT`.
        self.capture = ExecutionCapture()

    def on_write_for(self, collector: Collector | None) -> Callable[[Path, str, int], None]:
        """The `on_write` callback for one collector's writes."""
        mirrored = tuple(getattr(collector, "GRAPH_MIRRORED_TABLES", ()))

        def record(path: Path, sha: str, size: int) -> None:
            self.files.append(
                manifests.file_entry(self.settings, path, sha=sha, size=size, mirrored_tables=mirrored)
            )

        return record

    def record_file(self, path: Path, collector: Collector | None = None) -> None:
        """Record a file that this run publishes and did not write in this
        pass. Such a file is the raw file of a payload parked by an earlier
        per-device fetch. The device run that joins it is the first run to use
        it. The file is hashed from disk."""
        mirrored = tuple(getattr(collector, "GRAPH_MIRRORED_TABLES", ()))
        self.files.append(manifests.file_entry(self.settings, path, mirrored_tables=mirrored))


class ExecutionCapture:
    """What a run captured about the inventory before it started: the resolver
    version, the placement (intent) generation and each known device's desired
    placement revision. The normalization context of the manifest records it,
    and every v2 skip fingerprint includes it."""

    def __init__(
        self,
        context: inventory_collection.ExecutionContext = inventory_collection.LEGACY_CONTEXT,
        placement_revisions: dict[str, int] | None = None,
    ) -> None:
        self.context = context
        self.placement_revisions: dict[str, int] = dict(placement_revisions or {})
        self.before_finalize: Callable[[int], Mapping[str, str | None]] | None = None
        # The named block (block name, zone) of each device uid, read from the
        # site parameters of the operator when the run started. The run stamps it
        # on its Device nodes (`core/cycle.py apply_site_blocks`). The map is empty
        # when the read failed. Then every stamp is cleared and none is written.
        # With None, which the direct callers and the seam tests pass, nothing is
        # stamped.
        self.site_blocks: dict[str, tuple[str, str | None]] | None = None
        # The run warning when the site parameters could not be read (`SITE_BLOCKS_UNREAD`).
        self.site_blocks_warning: str | None = None

    @property
    def resolver_version(self) -> int:
        return self.context.resolver_version

    @property
    def placement_generation(self) -> int:
        return self.context.placement_generation


def _status_host(unit: PreparedDevice) -> str:
    """The `device_status` key for this unit: the fleet row's host, the
    implicit `config.host`, or "" for a controller type with no host at all,
    where the controller itself is the one device of the source. Derived by
    `collection.unit_host`."""
    return inventory_collection.unit_host(unit.device, getattr(unit.collector, "config", None))


def _target_key(name: str, unit: PreparedDevice) -> inventory_collection.TargetKey:
    return inventory_collection.target_key(name, _status_host(unit))


def _parked_of(settings: Settings, source: str, host: str) -> list[rawstore.ParkedPayload] | None:
    """The payloads of (source, host) parked and not yet joined to a run
    (`rawstore.parked`), or None when the raw store cannot say."""
    key = inventory_collection.target_key(source, host).slugged
    try:
        return [p for p in rawstore.parked(settings.raw_dir, source) if (p.source, p.host) == key]
    except (OSError, ValueError):
        return None


def _parked_same(
    collector: Collector,
    parked: rawstore.ParkedPayload,
    fingerprint: str,
    obs: str,
    observations_only: bool,
) -> bool:
    """Whether `parked` already holds what this fetch would park. This holds
    when the hashes stored beside the park (`rawstore.read_park_hashes`) equal
    the skip fingerprint and the observation hash of this fetch, the park used
    the normalization context of the collector (`_parked_as_current`), and the
    park applies at least as much. A full payload covers an observation
    payload. An observation payload does not cover a full one. The payload
    itself is not read. A sidecar without hashes, or one that cannot be read,
    does not match."""
    if parked.kind == rawstore.KIND_OBSERVATION and not observations_only:
        return False
    stored = rawstore.read_park_hashes(parked.path)
    if not stored or stored.get("fingerprint") != fingerprint or stored.get("obs") != obs:
        return False
    return _parked_as_current(collector, parked)


def _ms(at: datetime | None) -> int:
    return int(at.timestamp() * 1000) if at is not None else 0


def _parked_targets(settings: Settings) -> frozenset[tuple[str, str]] | None:
    """The slugged (source, host) of every payload parked and not yet joined
    to a run (`rawstore.parked`), or None when the raw store cannot say."""
    try:
        return frozenset((p.source, p.host) for p in rawstore.parked(settings.raw_dir))
    except (OSError, ValueError):
        return None


class _GraphWrites:
    """A graph session that records whether a statement that changed the
    graph committed through it.

    It reads the update counters of the database. Every result that the work
    of a write transaction produced is consumed once the work returns, still
    inside the transaction. `ResultSummary.counters.contains_updates` is true
    when that statement created, deleted or set anything. `began` turns true
    only when such a transaction committed. A result that reports no summary
    (a stand-in session) counts as a write.
    """

    def __init__(self, session: Any) -> None:
        self._session = session
        self.began = False

    def execute_write(self, work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        changed = [False]

        def watched(tx: Any, *a: Any, **k: Any) -> Any:
            # A retried attempt starts over. Only the attempt that commits counts.
            results: list[Any] = []
            out = work(_WatchedTx(tx, results), *a, **k)
            changed[0] = any(_changed_graph(result) for result in results)
            return out

        result = self._session.execute_write(watched, *args, **kwargs)
        if changed[0]:
            self.began = True
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


def _changed_graph(result: Any) -> bool:
    """Whether the result of one statement reports a graph update. True when
    the result has no counters (no `consume`, or a summary without counters)."""
    consume = getattr(result, "consume", None)
    if consume is None:
        return True
    counters = getattr(consume(), "counters", None)
    return bool(getattr(counters, "contains_updates", True))


class _WatchedTx:
    """The transaction that `_GraphWrites` hands the work of a write. It runs
    every statement as given and keeps its result for the update counters."""

    def __init__(self, tx: Any, results: list[Any]) -> None:
        self._tx = tx
        self._results = results

    def run(self, query: Any, *args: Any, **kwargs: Any) -> Any:
        result = self._tx.run(query, *args, **kwargs)
        self._results.append(result)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tx, name)


def _trace_kw(trace: HttpTrace | None) -> dict[str, Any]:
    """The `trace=` keyword for a raw write, only when there is a trace."""
    return {"trace": trace} if trace is not None else {}


class _Fetched:
    """What the concurrent fetch phase learned about one unit.

    `fetch_started_ms` and `fetch_finished_ms` bracket the fetch itself, in
    epoch milliseconds. `coll.execute` takes them as `fetch_window`. They are
    null on every `_Fetched` built for a failure.

    `sha` and `obs` are the two content hashes of the payload (`coll.raw_sha`
    and `coll.obs_sha`). `skipped` means that both hashes matched the record,
    and nothing is written. `observations_only` means that the configuration
    matched and the observations did not. The side tables are then written and
    the graph is carried. The two flags are never both set. `raw` is the
    payload. It is null on a failure and on a skipped result, which nothing
    loads. `verified` is a skip that found both hashes equal to the recorded
    ones (`DeviceOutcome.verified`).

    `graph` is the digest of the batch of the device on record, for a result
    that goes to a load (`_recorded_graph`). The load normalizes the payload.
    When the batch has the same digest, the load writes only its shared part
    (`_graph_kw`). `graph` is empty when there is no digest to compare.

    `spilled` is set for a payload at or above COLLECT_SPILL_MB, which the
    fetch phase sealed to a spill file (`coll.spill`). `raw` is then null. The
    loader hands the spill file to `coll.execute` or
    `coll.execute_observations` as `sealed` (`_payload_kw`). A result that
    nothing loads has it removed (`_release_fetched`).
    """

    def __init__(
        self,
        raw: object = None,
        *,
        spilled: rawstore.Spilled | None = None,
        error: str = "",
        sha: str = "",
        obs: str = "",
        fetch_ms: int | None = None,
        fetch_started_ms: int | None = None,
        fetch_finished_ms: int | None = None,
        skipped: bool = False,
        observations_only: bool = False,
        fingerprint: str | None = None,
        trace: HttpTrace | None = None,
        graph: str = "",
        verified: bool = False,
    ) -> None:
        self.raw = raw
        self.spilled = spilled
        self.error = error
        self.graph = graph
        # The HTTP exchange trace of the fetch, when the source is traced
        # (collectors/http_trace.py). The write of this payload seals it beside the
        # raw file. It is discarded when the payload is skipped.
        self.trace = trace
        self.sha = sha
        self.obs = obs
        # the value the skip decision compared and the status row will hold
        self.fingerprint = fingerprint if fingerprint is not None else sha
        self.fetch_ms = fetch_ms
        self.fetch_started_ms = fetch_started_ms
        self.fetch_finished_ms = fetch_finished_ms
        self.skipped = skipped
        self.observations_only = observations_only
        self.verified = verified


def _recorded_graph(settings: Settings, status: DeviceStatus | None, now: float) -> str:
    """The digest of the batch of the device on record (`last_graph_sha`)
    that a load of its next payload compares against. It is "" when there is
    no row, when the row has no digest, or when the batch of the digest was
    last written `collect_full_interval_s` or longer ago. That batch is then
    written again, which is the forced full load of the graph."""
    if status is None or not status.last_graph_sha or status.last_graph_at is None:
        return ""
    if now - status.last_graph_at.timestamp() >= settings.collect_full_interval_s:
        return ""
    return status.last_graph_sha


def _graph_kw(unit: PreparedDevice, recorded: str, prev: int | None) -> dict[str, Any]:
    """The `graph_gate=` keyword for a load of `unit` into a run built on
    `prev`. The keyword is returned only when there is a digest on record to
    compare and a parent run to carry from. A load without the keyword writes
    its whole batch. The digest of the batch is bound as the record is
    (`inventory.collection.fingerprint_for`)."""
    if not recorded or prev is None:
        return {}
    effective = unit.effective

    def matches(digest: str) -> bool:
        return inventory_collection.fingerprint_for(effective, digest) == recorded

    return {"graph_gate": GraphGate(matches, prev)}


def _bound_graph(unit: PreparedDevice, manifest: RunManifest) -> str | None:
    """The digest `device_status.last_graph_sha` records for this load, bound
    as the record is. None for a load that normalized nothing."""
    if not manifest.graph_sha:
        return None
    return inventory_collection.fingerprint_for(unit.effective, manifest.graph_sha)


def _graph_fetch_ms(manifest: RunManifest) -> int | None:
    """The fetch time of the payload that a load normalized, read from the
    run id that it was stored under (`collectors/base.py new_run_id`). None for
    a load that normalized nothing. A parked payload holds the same time
    (`rawstore.parked`), so the two compare (`_last_observed`)."""
    if not manifest.graph_sha:
        return None
    return manifests.run_ts(manifest.run_id)


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _at_ms(ms: int | None) -> datetime | None:
    """An epoch-millisecond time as the aware datetime the store keeps, in
    whole milliseconds with no float in between, so `_ms_of` reads the same
    number back."""
    return None if ms is None else _EPOCH + timedelta(milliseconds=ms)


def _ms_of(at: datetime | None) -> int | None:
    """A stored time as epoch milliseconds. It is the inverse of `_at_ms`."""
    return None if at is None else (at - _EPOCH) // timedelta(milliseconds=1)


def _payload_kw(f: _Fetched) -> dict[str, Any]:
    """The payload keyword for `coll.execute` or `coll.execute_observations`:
    `sealed=` for a result held as a spill file, and `raw=` for one held in
    memory."""
    return {"sealed": f.spilled} if f.spilled is not None else {"raw": f.raw}


def _release_fetched(f: _Fetched) -> None:
    """Discard the spool of the HTTP trace and the spill file of a result that
    nothing will load. Never raises OSError."""
    if f.trace is not None:
        try:
            f.trace.discard()
        except OSError as exc:
            logger.warning("could not discard the http trace of a fetch result: %s", exc)
    if f.spilled is not None:
        rawstore.drop_spill(f.spilled)


def _held_bytes(payload: object, stop_at: int) -> int:
    """The memory `payload` holds, as a sum of `sys.getsizeof`: every dict
    with its keys, every list and tuple, and every other value, walking into
    the containers and counting each container once. The walk ends as soon as
    the sum reaches `stop_at`."""
    total = 0
    seen: set[int] = set()
    stack: list[object] = [payload]
    while stack and total < stop_at:
        value = stack.pop()
        if isinstance(value, dict):
            if id(value) in seen:
                continue
            seen.add(id(value))
            total += sys.getsizeof(value) + sum(sys.getsizeof(k) for k in value)
            stack.extend(value.values())
        elif isinstance(value, list | tuple):
            if id(value) in seen:
                continue
            seen.add(id(value))
            total += sys.getsizeof(value)
            stack.extend(value)
        else:
            total += sys.getsizeof(value, 0)
    return total


def _spill_large(
    name: str, unit: PreparedDevice, fetched: _Fetched, spill_at: int, made: list[rawstore.Spilled]
) -> None:
    """Seal the payload of `fetched` to a spill file when it holds `spill_at`
    bytes or more (`_held_bytes`), and keep the handle in its place.

    Every spill made is appended to `made`, which the fetch phase removes
    when it fails. A payload whose seal fails stays in memory until its load,
    and a warning is logged. The load then writes it as it writes any other
    payload.
    """
    collector = unit.collector
    if collector is None or fetched.raw is None or _held_bytes(fetched.raw, spill_at) < spill_at:
        return
    try:
        spilled = coll.spill(collector, fetched.raw, source_name=name, fetch_ts_ms=fetched.fetch_started_ms)
    except Exception as exc:
        label = name if unit.device is None else f"{name}/{unit.device.host}"
        logger.warning(
            "raw spill of %s failed; the payload is held in memory until its load: %s: %s",
            label,
            type(exc).__name__,
            exc,
        )
        return
    made.append(spilled)
    fetched.spilled = spilled
    fetched.raw = None


# The loop `run_device_fetch` runs its asyncssh fetches on, and the thread
# that runs it (`_fetch_loop`).
_FETCH_LOOP: tuple[asyncio.AbstractEventLoop, threading.Thread] | None = None
_FETCH_LOOP_LOCK = threading.Lock()


def _fetch_loop() -> asyncio.AbstractEventLoop:
    """The event loop that per-device fetches run on, started on first use.

    One loop, on a daemon thread of its own, serves every per-device fetch of
    the process. A loop whose thread is not alive, as
    in a forked process, is replaced.
    """
    global _FETCH_LOOP
    with _FETCH_LOOP_LOCK:
        if _FETCH_LOOP is not None and _FETCH_LOOP[1].is_alive():
            return _FETCH_LOOP[0]
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, name="device-fetch", daemon=True)
        thread.start()
        _FETCH_LOOP = (loop, thread)
        return loop


async def _afetch_apart(collector: Collector) -> Any:
    """Run `collector.afetch()` on the fetch loop (`_fetch_loop`) and await it
    from the loop of the caller. Cancelling the await cancels the fetch."""
    loop = _fetch_loop()
    return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(collector.afetch(), loop))


def _wants_loop(collector: Collector | None) -> bool:
    """Whether this collector fetches as an asyncio task. The collector must
    implement `afetch`, and the transport of its config must be asyncssh."""
    return callable(getattr(collector, "afetch", None)) and (
        getattr(getattr(collector, "config", None), "transport", "") == "asyncssh"
    )


def _fetch_phase(
    settings: Settings,
    units: list[tuple[str, PreparedDevice]],
    prior: Mapping[tuple[str, str], DeviceStatus],
    allow_skip: bool,
    progress: FleetProgress | None = None,
) -> dict[int, _Fetched]:
    """Fetch every unit concurrently. The caller loads the results serially
    afterwards, and the Neo4j session does not wait on a device.

    The phase has 2 lanes. asyncssh devices fetch as asyncio tasks under a
    `collect_max_concurrency` semaphore. Everything else (paramiko overrides,
    the HTTP collectors) runs on a thread pool bounded by
    `collect_thread_workers`, beside the loop.

    The skip decision is taken here, next to the hash. A device skips when its
    payload is unchanged, a prior full load is on record, and that load is
    newer than `collect_full_interval_s`. `allow_skip` is false on a cold
    start. Payload hashing for the async lane runs on a separate post-fetch
    pool of `collect_thread_workers` threads, outside the loop and the fetch
    pool.

    A device that qualifies for the skip is checked once more against its
    observation hash. `decide` reports a device with unchanged
    configuration and changed ARP, MAC or route tables as `observations_only`.

    A payload at or above COLLECT_SPILL_MB is sealed to a spill file once it
    is hashed (`_spill_large`), and its result holds the handle as `spilled`
    in place of `raw`. The caller adopts each such result, with `coll.execute`
    or `coll.execute_observations` and `sealed=`, or removes its file
    (`rawstore.drop_spill`). A phase that raises removes every spill that it
    made. With COLLECT_SPILL_MB=0, no result is spilled.

    Returns every unit's result at once.
    """
    if not units:
        return {}
    return asyncio.run(_fetch_phase_async(settings, units, prior, allow_skip, progress=progress))


async def _fetch_phase_async(
    settings: Settings,
    units: list[tuple[str, PreparedDevice]],
    prior: Mapping[tuple[str, str], DeviceStatus],
    allow_skip: bool,
    sink: Callable[[int, _Fetched], Awaitable[None] | None] | None = None,
    progress: FleetProgress | None = None,
) -> dict[int, _Fetched]:
    """Fetch `units` and hand each result on as it arrives.

    Every fetch, on either lane, puts its result on an
    `asyncio.Queue(maxsize=collect_fetch_buffer)` that one consumer drains. A
    fetch does not start until there is room for its payload. A phase with a
    `sink` (a consumer that loads or writes what it is handed) holds at most
    `collect_fetch_buffer` payloads at once.

    The consumer calls `sink` with one result at a time, in the order the
    fetches complete. `sink` can be a coroutine function, and its return value
    is awaited when it is awaitable. With no `sink`, the consumer collects the
    results and they are all returned.

    With COLLECT_SPILL_MB above 0, a result whose payload holds that many MiB
    or more is sealed to a spill file before it is handed on. The result holds
    the handle as `spilled` with `raw` null, and a sink receives it that way.
    The async lane then also takes one of `collect_max_concurrency` + 1
    admission permits before a fetch starts. It gives the permit back once the
    payload is hashed and, when large, sealed. At most that many async
    payloads at or above the threshold are in memory at once. A thread-lane
    payload is hashed and sealed on the thread that fetched it. The caller
    adopts or removes a result with `spilled`, as `_fetch_phase` describes.
    When the phase raises, it removes every spill file that it made.
    """
    now = time.time()
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(max(1, settings.collect_max_concurrency))
    spill_at = max(0, getattr(settings, "collect_spill_mb", 0)) << 20
    # every spill file this phase made, removed if the phase raises
    made: list[rawstore.Spilled] = []
    # The admission permit of the async lane. It is taken before a fetch and
    # held until the payload is hashed and, when large, sealed. The SSH slot
    # (`sem`) is given back after the fetch. Without this permit, only `room`
    # would bound the payloads that wait on the post-fetch pool.
    live = asyncio.Semaphore(max(1, settings.collect_max_concurrency) + 1) if spill_at else None
    # The devices with a payload that a per-device job parked and no device
    # run has loaded yet. The record is the basis of the last payload that a
    # run loaded, and the parked payload is newer. A matching hash does not
    # allow a skip of the load, because the device run would then apply the
    # parked payload over this one. Nothing skips when the parked index cannot
    # be read.
    pending = _parked_targets(settings) if allow_skip else frozenset()

    def decide(
        name: str,
        unit: PreparedDevice,
        raw: object,
        sha: str,
        obs: str,
        fetch_ms: int,
        fetch_started_ms: int,
        fetch_finished_ms: int,
    ) -> _Fetched:
        # The 2 hashes give 3 outcomes, decided in this order. The configuration
        # hash decides whether the payload has to be normalized. Only when it
        # does not, the observation hash decides whether anything has to be
        # written. A payload that is normalized holds the digest of the batch on
        # record. Its load writes only the shared part of the batch when the batch
        # has the same digest.
        unchanged = False
        compared = False
        recorded = ""
        fingerprint = inventory_collection.fingerprint_for(unit.effective, sha)
        if allow_skip:
            status = prior.get((name, _status_host(unit)))
            recorded = _recorded_graph(settings, status, now)
            unchanged = (
                status is not None
                and status.last_raw_sha == fingerprint
                and status.last_full_at is not None
                and now - status.last_full_at.timestamp() < settings.collect_full_interval_s
                and pending is not None
                and _target_key(name, unit).slugged not in pending
            )
            # An empty hash on either side leaves the skip standing.
            observations_only = (
                unchanged
                and status is not None
                and bool(obs)
                and bool(status.last_obs_sha)
                and status.last_obs_sha != obs
            )
            # The skip checked the observations only when their hash equals
            # the recorded one. Both hashes are empty for a collector that declares
            # no observations.
            compared = status is not None and status.last_obs_sha == obs
        else:
            observations_only = False
        skipped = unchanged and not observations_only
        # A skipped result is never loaded and does not hold its payload. The
        # result waits in the fetch window until the loader reaches it. The skip
        # branch reads only the hashes and the fetch times.
        return _Fetched(
            None if skipped else raw,
            sha=sha,
            obs=obs,
            fetch_ms=fetch_ms,
            fetch_started_ms=fetch_started_ms,
            fetch_finished_ms=fetch_finished_ms,
            skipped=skipped,
            observations_only=observations_only,
            fingerprint=fingerprint,
            graph="" if unchanged else recorded,
            verified=skipped and compared,
        )

    def fetch_blocking(entry: tuple[str, PreparedDevice]) -> tuple[int, _Fetched]:
        name, unit = entry
        collector = unit.collector
        if collector is None:  # the dispatch loop handles a unit without a collector
            return id(unit), _Fetched(error=unit.error or "collector not built")
        t0 = time.monotonic()
        started_ms = int(time.time() * 1000)
        try:
            raw, trace = fetch_traced(collector, name)
        except Exception as exc:
            return id(unit), _Fetched(error=f"{type(exc).__name__}: {exc}")
        finished_ms = int(time.time() * 1000)
        fetch_ms = int((time.monotonic() - t0) * 1000)
        fetched = decide(
            name,
            unit,
            raw,
            coll.raw_sha(collector, raw),
            coll.obs_sha(collector, raw),
            fetch_ms,
            started_ms,
            finished_ms,
        )
        del raw
        if spill_at and fetched.raw is not None:
            _spill_large(name, unit, fetched, spill_at, made)
        if trace is not None and fetched.skipped:
            trace.discard()  # nothing is written for a skipped payload
        else:
            fetched.trace = trace
        return id(unit), fetched

    workers = max(1, settings.collect_thread_workers)
    try:
        with (
            ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fetch") as pool,
            ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fetch-post") as post,
        ):

            async def fetch_task(name: str, unit: PreparedDevice) -> tuple[int, _Fetched]:
                collector = unit.collector
                if collector is None:  # the dispatch loop handles a unit without a collector
                    return id(unit), _Fetched(error=unit.error or "collector not built")
                async with live or contextlib.nullcontext():
                    async with sem:
                        t0 = time.monotonic()
                        started_ms = int(time.time() * 1000)
                        try:
                            raw = await collector.afetch()
                        except Exception as exc:
                            return id(unit), _Fetched(error=f"{type(exc).__name__}: {exc}")
                        finished_ms = int(time.time() * 1000)
                        fetch_ms = int((time.monotonic() - t0) * 1000)
                    # The slot bounds the SSH sessions open at once. Hashing
                    # opens no session, and the fetch of the next device starts
                    # while this payload hashes. The `room` permit of the phase
                    # still counts the payload. The `live` permit counts it
                    # until it is hashed and sealed.
                    sha = await loop.run_in_executor(post, coll.raw_sha, collector, raw)
                    obs = await loop.run_in_executor(post, coll.obs_sha, collector, raw)
                    fetched = decide(name, unit, raw, sha, obs, fetch_ms, started_ms, finished_ms)
                    del raw
                    if spill_at and fetched.raw is not None:
                        await loop.run_in_executor(post, _spill_large, name, unit, fetched, spill_at, made)
                    return id(unit), fetched

            async def fetch_threaded(entry: tuple[str, PreparedDevice]) -> tuple[int, _Fetched]:
                return await loop.run_in_executor(pool, fetch_blocking, entry)

            results: dict[int, _Fetched] = {}
            # A result holds only the unit id. The progress bar that it advances
            # belongs to the source of the unit.
            source_of = {id(unit): name for name, unit in units}
            buffered = max(1, settings.collect_fetch_buffer)
            queue: asyncio.Queue[tuple[int, _Fetched]] = asyncio.Queue(maxsize=buffered)
            # One permit per payload that the phase can hold. It is taken before a
            # fetch starts and given back only once the consumer has finished with
            # the result. The count of payloads in flight, on the queue and in the
            # hand of the consumer never passes `collect_fetch_buffer`. The bound of
            # the queue leaves out the fetches that have completed and not yet put
            # their result, and those fetches hold their payloads too.
            room = asyncio.Semaphore(buffered)

            async def deliver(key: int, fetched: _Fetched) -> None:
                if progress is not None:
                    progress.advance(source_of.get(key, ""))
                if sink is None:
                    results[key] = fetched
                    return
                waiting = sink(key, fetched)
                if waiting is not None:
                    await waiting

            async def hand_on(fetch: Coroutine[Any, Any, tuple[int, _Fetched]]) -> None:
                await room.acquire()
                try:
                    await queue.put(await fetch)
                except BaseException:
                    room.release()
                    raise

            async def consume(count: int) -> None:
                for _ in range(count):
                    key, fetched = await queue.get()
                    try:
                        await deliver(key, fetched)
                    finally:
                        room.release()

            fetches: list[Coroutine[Any, Any, tuple[int, _Fetched]]] = []
            for name, unit in units:
                if unit.collector is None:  # the caller filters these out
                    await deliver(id(unit), _Fetched(error=unit.error or "collector not built"))
                elif _wants_loop(unit.collector):
                    fetches.append(fetch_task(name, unit))
                else:
                    fetches.append(fetch_threaded((name, unit)))
            # One consumer runs beside the fetches, all in one task group. A fetch
            # that fails outright, or a sink that raises, cancels the rest.
            async with asyncio.TaskGroup() as group:
                group.create_task(consume(len(fetches)))
                for fetch in fetches:
                    group.create_task(hand_on(fetch))
            return results
    except BaseException:
        # Both pools have shut down and waited for their threads. Every spill
        # that a thread started is finished and listed.
        for spilled in made:
            rawstore.drop_spill(spilled)
        raise


class FleetProgress:
    """One progress record per source, for the run's whole fetch phase.

    A record covers every source whose collector reports nothing.

    The counts are devices answered out of devices asked, per source.
    `reports_progress` on the collector marks a source that keeps its own.
    """

    def __init__(self, settings: Settings, units: list[tuple[str, PreparedDevice]]) -> None:
        self._bars: dict[str, CollectionProgress] = {}
        self._done: dict[str, int] = {}
        totals: dict[str, int] = {}
        own: set[str] = set()
        for name, unit in units:
            totals[name] = totals.get(name, 0) + 1
            if getattr(unit.collector, "reports_progress", False):
                own.add(name)
        for name, total in totals.items():
            if name in own:
                continue
            bar = CollectionProgress(settings, name)
            bar.phase("Fetching devices", total)
            self._bars[name] = bar
            self._done[name] = 0

    def advance(self, name: str) -> None:
        bar = self._bars.get(name)
        if bar is None:
            return
        self._done[name] += 1
        bar.advance(self._done[name])

    def finish(self, name: str, success: bool = True) -> None:
        bar = self._bars.get(name)
        if bar is not None:
            bar.finish(success)

    def finish_all(self, success: bool = True) -> None:
        """Finish the bar of every source, when every source is done or the
        run is over."""
        for name in self._bars:
            self.finish(name, success)


class _FetchBuffer(Mapping[int, _Fetched]):
    """The fetch phase's hand-off to the serial load loop, bounded.

    The buffer fetches in windows of `collect_fetch_buffer` units and drops
    each payload as the loader takes it (`__getitem__` pops).

    A load releases the collector's per-payload caches when it ends
    (`Collector.release_payload`). A unit the loader will never ask for, one
    of a source an operator stopped, is dropped with `discard`.

    The window follows the order the loader asks in.

    A held result whose payload is at or above COLLECT_SPILL_MB is a sealed
    spill file (`_fetch_phase`). The window holds at most
    `collect_fetch_buffer` payloads below that size, and handles for the rest.
    Releasing such a result, by `discard` or `close`, removes its file. The
    load of a result that the loader takes adopts the file.

    Iteration and `len` cover the payloads buffered at the moment.

    `stop` is checked before each window. The check raises outside the per-unit
    `try`, so a lost lock ends the run.
    """

    def __init__(
        self,
        settings: Settings,
        units: list[tuple[str, PreparedDevice]],
        prior: Mapping[tuple[str, str], DeviceStatus],
        allow_skip: bool,
        stop: threading.Event | None = None,
        progress: FleetProgress | None = None,
    ) -> None:
        self._settings = settings
        self._units = units
        self._prior = prior
        self._allow_skip = allow_skip
        self._stop = stop
        self._progress = progress
        self._window = max(1, settings.collect_fetch_buffer)
        self._held: dict[int, _Fetched] = {}
        # The unit ids that the loader will not ask for. They are not fetched or held.
        self._discarded: set[int] = set()
        self._cursor = 0

    def discard(self, key: int) -> None:
        """Drop the unit that `key` names. A payload already held for it is
        released now, and a window not yet fetched leaves it out. Asking for
        it afterwards raises `KeyError`, as for a unit with no result. A held
        payload is never written to its raw file. Its HTTP trace is discarded
        with it, and a spill file that holds it is removed
        (`_release_fetched`)."""
        held = self._held.pop(key, None)
        if held is not None:
            _release_fetched(held)
        self._discarded.add(key)

    def close(self) -> None:
        """Release every result still held, as `discard` releases one, and
        fetch nothing more. The run calls it when its load loop ends, however
        it ends. Closing twice is a no-op."""
        held, self._held = self._held, {}
        self._cursor = len(self._units)
        for fetched in held.values():
            _release_fetched(fetched)

    def __getitem__(self, key: int) -> _Fetched:
        if key in self._discarded:
            raise KeyError(key)
        while key not in self._held and self._cursor < len(self._units):
            _stopped(self._stop)
            window = self._next_window()
            self._held.update(
                _fetch_phase(self._settings, window, self._prior, self._allow_skip, self._progress)
            )
        return self._held.pop(key)

    def _next_window(self) -> list[tuple[str, PreparedDevice]]:
        """The next at most `collect_fetch_buffer` units still to fetch, in
        the loader's order, with the cursor moved past every unit it read,
        the discarded ones included."""
        window: list[tuple[str, PreparedDevice]] = []
        while self._cursor < len(self._units) and len(window) < self._window:
            entry = self._units[self._cursor]
            self._cursor += 1
            if id(entry[1]) not in self._discarded:
                window.append(entry)
        return window

    def __iter__(self) -> Iterator[int]:
        return iter(self._held)

    def __len__(self) -> int:
        return len(self._held)


def _discard_fetched(fetched: Mapping[int, _Fetched], key: int) -> None:
    """Tell the fetch hand-off that the loader will not ask for unit `key`.

    A `_FetchBuffer` drops the unit's payload and skips its fetch
    (`_FetchBuffer.discard`). A plain mutable mapping, the empty one an inline
    cycle or refresh passes, drops the entry if there is one and releases it
    as the buffer does (`_release_fetched`). Any other mapping is left alone.
    It is read-only to the loader and holds nothing to release."""
    discard = getattr(fetched, "discard", None)
    if callable(discard):
        discard(key)
    elif isinstance(fetched, MutableMapping):
        dropped = fetched.pop(key, None)
        if dropped is not None:
            _release_fetched(dropped)


def _section_gaps(sections: Mapping[str, SectionOutcome]) -> str:
    """The sections of one device that did not come back, as `name=status`
    pairs in name order, for the run's detail line and the device's error."""
    return ", ".join(
        f"{n}={o.status}" for n, o in sorted(sections.items()) if o.status in DEGRADING_SECTION_STATUSES
    )


def _table_gaps(tables: Mapping[str, TableOutcome]) -> str:
    """The side-store tables of one device that the run holds no rows for, in
    the same `name=status` form. A table that came back empty
    (`complete-empty`) is not one of them."""
    return ", ".join(
        f"table {n}={o.status}" for n, o in sorted(tables.items()) if o.status in DEGRADING_TABLE_STATUSES
    )


def _unchanged_tables(collector: Collector | None) -> dict[str, TableOutcome]:
    """The table outcomes of a device whose fetch matched the previous payload.

    The previous run's file still holds the device's rows."""
    return {t: TableOutcome(status="unchanged") for t in getattr(collector, "SIDE_TABLES", ())}


def _observation_line(
    tables: Mapping[str, TableOutcome],
    sections: Mapping[str, SectionOutcome],
    completeness: str,
    unchanged: str = "configuration",
    shared: RunManifest | None = None,
) -> str:
    """One observation-only publication as a run-detail line.

    The line reports rows, per table in name order. A device whose verdict is
    not ok has the verdict and its gaps after them, in the form a full load's line uses.

    `unchanged` names what matched the record: the configuration, for a
    payload whose configuration hash matched at fetch time, or the graph, for
    a payload that was normalized and whose batch has the digest of the batch
    on record. `shared` is the manifest of such a load. Its counters count the
    objects that the load wrote because other writers share them
    (`collectors/base.py SHARED_OBJECTS`). The line states them when there are
    any.
    """
    written = ", ".join(f"{n}={o.row_count or 0}" for n, o in sorted(tables.items()))
    line = f"{unchanged} unchanged"
    if shared is not None and (shared.nodes_upserted or shared.rels_upserted):
        line += f", shared objects written: {shared.nodes_upserted} nodes, {shared.rels_upserted} rels"
    line = f"{line}, observations written: {written or 'none'}"
    if completeness != "ok":
        gaps = ", ".join(g for g in (_section_gaps(sections), _table_gaps(tables)) if g)
        line = f"{line} · {completeness}: {gaps}"
    return line


def _publish_observations(
    unit: PreparedDevice,
    name: str,
    cts: int,
    f: _Fetched,
    evidence: RunEvidence,
) -> RunManifest:
    """Write one observation-only payload's raw file and side tables into run
    `cts`, and return the manifest `coll.execute_observations` reports: the
    payload's section outcomes and its table outcomes.

    A failure fails the device, as it fails a full load of the same payload.
    The exception propagates to the caller.
    """
    collector = unit.collector
    if collector is None:  # the caller filters these out
        raise RuntimeError("collector not built")
    window = (
        (f.fetch_started_ms, f.fetch_finished_ms)
        if f.fetch_started_ms is not None and f.fetch_finished_ms is not None
        else None
    )
    try:
        return coll.execute_observations(
            collector,
            **_payload_kw(f),
            collection_ts=cts,
            source_name=name,
            on_write=evidence.on_write_for(collector),
            fetch_window=window,
            **_trace_kw(f.trace),
        )
    finally:
        # a no-op once the load moved the spill file to its raw path
        if f.spilled is not None:
            rawstore.drop_spill(f.spilled)


def _completeness(
    sections: Mapping[str, SectionOutcome],
    tables: Mapping[str, TableOutcome],
    authoritative: tuple[str, ...],
) -> str:
    """One device's collection verdict: ok, partial or failed.

    A degrading authoritative section fails the device. A side-store table
    that did not land never fails the device. The graph load has already
    committed by the time a table is written and is not rolled back. The
    device is then a partial collection. What landed is true, and this run
    does not hold the rows of that table."""
    verdict = section_verdict(sections, authoritative)
    if verdict == "ok" and table_verdict(tables) == "partial":
        return "partial"
    return verdict


class CarryScopes:
    """Which collector scopes a run can carry forward from its parent, and why.

    A scope is the retirement partition of one collector (core/loader.py). It
    is one device for a fleet source, `nxos:leaf1`, and one controller
    otherwise, `apic:fab1`. Every object that a load writes is stamped with
    it, which makes it the granularity at which absence has a meaning. A scope
    that collected in this run answered for itself. An object of that scope
    that the run does not hold is an object that the network no longer has. A
    scope that failed, did not run or skipped its load as unchanged proves
    nothing about absence, and its objects are gaps to fill.

    `collected` wins over `carry`, in either order. A scope that answered is
    never carried.

    `sections` holds the exception that a collected scope can still have. A
    `partial` device answered for itself, and its absent objects are removals,
    apart from the objects of a section that did not answer at all. `ran` records those
    labels beside the scope, and carry-forward brings them back, stamped
    `section-failed`.
    """

    def __init__(self) -> None:
        self.reasons: dict[str, str] = {}
        self.collected: set[str] = set()
        self.sections: dict[str, list[str]] = {}

    def ran(self, unit: PreparedDevice, sections: Mapping[str, SectionOutcome] | None = None) -> None:
        """Record that this unit collected. A `partial` device counts here
        too, because it connected and its load landed.

        `sections` holds what its load reported per section. The labels of
        every degrading section that the collector declares an exclusive
        label set for are recorded for the section-level carry. A device that
        lost one optional read keeps the objects of that read as last-known
        state. Every other absence of the same device still counts as a
        removal."""
        scope = _unit_scope(unit)
        if not scope:
            return
        self.collected.add(scope)
        self.reasons.pop(scope, None)
        labels = _failed_section_labels(unit.collector, sections or {})
        if labels:
            self.sections[scope] = labels

    def carry(self, unit: PreparedDevice, reason: str) -> None:
        """Record that this unit did not collect, for one of
        `cycle.CARRY_REASONS`. A unit with no collector cannot name its scope
        here. `_carry_phase` recovers its previous scope from the snapshot
        manifest."""
        scope = _unit_scope(unit)
        if scope and scope not in self.collected:
            self.reasons[scope] = reason


def _unit_scope(unit: PreparedDevice) -> str:
    """The retirement scope of one unit's collector, empty when the unit never
    got a collector and this run cannot name the scope it owns."""
    return str(getattr(unit.collector, "scope", "") or "")


def _failed_section_labels(collector: Collector | None, sections: Mapping[str, SectionOutcome]) -> list[str]:
    """The graph labels this device's failed optional sections own, sorted.

    One entry per label the collector declares as exclusively that section's
    (`Collector.SECTION_LABELS`) for every section whose status is degrading.
    A section the collector declares nothing for contributes nothing.

    Empty for a device with no failed section, a collector with no
    declarations, or a failed section whose data only merges properties onto
    another section's nodes.
    """
    declared = getattr(collector, "SECTION_LABELS", None) or {}
    labels: set[str] = set()
    for name, outcome in sections.items():
        if outcome.status in DEGRADING_SECTION_STATUSES:
            labels.update(declared.get(name, ()))
    return sorted(labels)


def _unasked(p: PreparedSource, statuses: Mapping[str, str]) -> bool:
    """Whether this run asked this source nothing at all.

    Either it was not in the fresh set, or it failed before its units were
    prepared (unreadable secrets, a group config that would not resolve, a
    fleet with nothing enabled in it). Both leave the run with no observation
    of any device of the source, including a device that is no longer one of
    its units. A device gone from the inventory of a source that ran is not carried.
    """
    return statuses.get(p.row.name) in ("carried", CANCELLED) or p.error is not None or not p.units


def _collect_sources(
    s: Session,
    prepared: list[PreparedSource],
    fresh: set[str],
    fetched: Mapping[int, _Fetched],
    cts: int,
    emit: Callable[[DeviceOutcome], None],
    evidence: RunEvidence,
    stop: threading.Event | None = None,
    prev: int | None = None,
) -> tuple[dict[str, str], list[str], list[tuple[Source, Device | None, Collector]], set[str], CarryScopes]:
    """Load every fresh source's units into cycle `cts`, unit by unit.

    Returns (per-source statuses, detail lines, the units that ran, the fresh
    sources whose unchanged devices skipped their loads and so need the
    absent-only carry, and the per-scope carry set). `evidence` collects every
    file the loads write, for the run's manifest.

    `fetched` maps unit id to what the fetch phase learned about that unit. A
    cycle given `prior`, and a refresh run with `concurrent`, pass a
    `_FetchBuffer`. The buffer fetches the next window as this loop asks for
    it and drops each payload once read. The loop asks for the result of a
    unit exactly once, in the order the buffer was given the units. The other
    callers pass an empty mapping, and each load fetches inline.

    `prev` is the run that `cts` is built on. A result that holds a digest on
    record (`_Fetched.graph`) is loaded with it to compare. A batch with the
    same digest writes only what it shares with other writers, and its other
    objects come forward from `prev` (`_graph_kw`). With `prev` None, nothing
    is compared.

    `stop` is checked before each unit, outside the per-unit `try` that turns
    an exception into the failure of one device. A stopped run ends before the
    load of its next device. A source cancelled alone while its devices
    load keeps the loads that landed and carries every other device under `cancelled`.
    """
    statuses: dict[str, str] = {}
    details: list[str] = []
    ran: list[tuple[Source, Device | None, Collector]] = []
    needs_carry: set[str] = set()
    scopes = CarryScopes()
    for p in prepared:
        name = p.row.name
        if not p.row.enabled or name not in fresh:
            statuses[name] = "carried"
            for unit in p.units:
                scopes.carry(unit, "not-run")
            continue
        if _source_cancelled(stop, name):
            # An operator stopped this source alone. Nothing it fetched is loaded.
            statuses[name] = CANCELLED
            details.append(f"{name}: cancelled by operator; its devices are carried forward")
            for unit in p.units:
                scopes.carry(unit, CANCELLED)
                _discard_fetched(fetched, id(unit))
            continue
        if p.error is not None or not p.units:
            statuses[name] = "failed"
            details.append(f"{name}: {p.error or 'no devices and no host'}")
            for unit in p.units:
                scopes.carry(unit, "failed")
            continue
        ok = bad = skipped = degraded = cancelled = 0
        for unit in p.units:
            _stopped(stop)
            if _source_cancelled(stop, name):
                # The source was stopped alone while its devices load. A
                # device loaded before the cancel keeps its load. This device
                # and every device after it carry, as the devices of a source
                # stopped before its first device do. None of them counts as
                # a failed device.
                cancelled += 1
                scopes.carry(unit, CANCELLED)
                _discard_fetched(fetched, id(unit))
                continue
            label = name if unit.device is None else f"{name}/{unit.device.host}"
            host = _status_host(unit)
            if unit.collector is None:
                bad += 1
                details.append(f"{label}: {unit.error}")
                emit(DeviceOutcome(name, host, False, error=unit.error or ""))
                continue
            # Unbind the result of the previous unit before asking for this
            # one. The ask can fetch a whole window, and that result still
            # holds its payload.
            f = None
            f = fetched.get(id(unit))
            if f is not None and f.error and _source_cancelled(stop, name):
                # The ask fetched a window, and the cancel of this source
                # ended the fetch of this unit (`Collector.check_stop`). The
                # unit carries as the devices after it do. It does not count
                # as a failed device.
                cancelled += 1
                scopes.carry(unit, CANCELLED)
                continue
            if f is not None and f.error:
                bad += 1
                scopes.carry(unit, "failed")
                details.append(f"{label}: {f.error}")
                emit(DeviceOutcome(name, host, False, error=f.error))
                continue
            if f is not None and f.skipped:
                # The fetch connected and both payload hashes matched.
                # Normalize and load are skipped, the objects are carried,
                # and the outcome is a success. The unit still reaches `ran`,
                # and its first-contact pin still lands.
                ok += 1
                skipped += 1
                scopes.carry(unit, "unchanged")
                details.append(f"{label}: unchanged, carried")
                ran.append((p.row, unit.device, unit.collector))
                emit(
                    DeviceOutcome(
                        name,
                        host,
                        True,
                        raw_sha=f.sha,
                        obs_sha=f.obs,
                        fingerprint=f.fingerprint,
                        skipped=True,
                        verified=f.verified,
                        checked_basis=(f.fingerprint, f.obs) if f.verified else None,
                        fetch_ms=f.fetch_ms,
                        fetch_started_ms=f.fetch_started_ms,
                        fetch_finished_ms=f.fetch_finished_ms,
                        tables=_unchanged_tables(unit.collector),
                    )
                )
                continue
            if f is not None and f.observations_only:
                # The side tables are written under this run, and the graph is
                # left to the carry.
                authoritative = tuple(getattr(unit.collector, "AUTHORITATIVE_SECTIONS", ()))
                try:
                    published = _publish_observations(unit, name, cts, f, evidence)
                except Exception as exc:
                    if f.trace is not None:
                        f.trace.discard()  # a no-op once the raw write sealed it
                    if _cut_by_cancel(exc, stop, name):
                        cancelled += 1
                        scopes.carry(unit, CANCELLED)
                        continue
                    bad += 1
                    scopes.carry(unit, "failed")
                    details.append(
                        f"{label}: configuration unchanged; observations not written: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    emit(DeviceOutcome(name, host, False, error=f"{type(exc).__name__}: {exc}"))
                    continue
                completeness = _completeness(published.sections, published.tables, authoritative)
                gaps = _section_gaps(published.sections)
                if completeness == "failed":
                    bad += 1
                    scopes.carry(unit, "failed")
                else:
                    ok += 1
                    skipped += 1
                    scopes.carry(unit, "unchanged")
                    ran.append((p.row, unit.device, unit.collector))
                if completeness == "partial":
                    degraded += 1
                details.append(
                    f"{label}: {_observation_line(published.tables, published.sections, completeness)}"
                )
                emit(
                    DeviceOutcome(
                        name,
                        host,
                        completeness != "failed",
                        raw_sha=f.sha,
                        obs_sha=f.obs,
                        fingerprint=f.fingerprint,
                        observations_only=True,
                        error="" if completeness != "failed" else f"sections not collected: {gaps}",
                        fetch_ms=f.fetch_ms,
                        fetch_started_ms=f.fetch_started_ms,
                        fetch_finished_ms=f.fetch_finished_ms,
                        sections=published.sections,
                        authoritative=authoritative,
                        tables=published.tables,
                    )
                )
                continue
            # whether this load committed a graph write before it ended
            ws = _GraphWrites(s)
            try:
                t0 = time.monotonic()
                on_write = evidence.on_write_for(unit.collector)
                if f is not None:
                    fetch_window = (
                        (f.fetch_started_ms, f.fetch_finished_ms)
                        if f.fetch_started_ms is not None and f.fetch_finished_ms is not None
                        else None
                    )
                    manifest = coll.execute(
                        unit.collector,
                        ws,
                        collection_ts=cts,
                        source_name=name,
                        **_payload_kw(f),
                        on_write=on_write,
                        fetch_window=fetch_window,
                        **_trace_kw(f.trace),
                        **_graph_kw(unit, f.graph, prev),
                    )
                else:
                    manifest = coll.execute(
                        unit.collector, ws, collection_ts=cts, source_name=name, on_write=on_write
                    )
                load_ms = int((time.monotonic() - t0) * 1000)
                ingested_ms = int(time.time() * 1000)
                # A degrading authoritative section fails the device, and a
                # degrading optional section makes it partial (core/model.py
                # `section_verdict`). A load whose batch has the digest of the
                # batch on record is an observation-only publication.
                kept = manifest.graph_unchanged
                authoritative = tuple(getattr(unit.collector, "AUTHORITATIVE_SECTIONS", ()))
                completeness = _completeness(manifest.sections, manifest.tables, authoritative)
                gaps = _section_gaps(manifest.sections)
                all_gaps = ", ".join(g for g in (gaps, _table_gaps(manifest.tables)) if g)
                if completeness == "failed":
                    bad += 1
                    # An authoritative section of this device did not come back.
                    scopes.carry(unit, "failed")
                elif kept:
                    ok += 1
                    skipped += 1
                    scopes.carry(unit, "unchanged")
                    ran.append((p.row, unit.device, unit.collector))
                else:
                    ok += 1
                    scopes.ran(unit, manifest.sections)
                    ran.append((p.row, unit.device, unit.collector))
                if completeness == "partial":
                    degraded += 1
                if kept:
                    line = _observation_line(
                        manifest.tables, manifest.sections, completeness, "graph", manifest
                    )
                else:
                    line = finalization.manifest_line(manifest)
                    if completeness != "ok":
                        line = f"{line} · {completeness}: {all_gaps}"
                details.append(f"{label}: {line}")
                _record_warnings(evidence, details, manifest)
                emit(
                    DeviceOutcome(
                        name,
                        host,
                        completeness != "failed",
                        raw_sha=f.sha if f is not None else None,
                        obs_sha=f.obs if f is not None else None,
                        fingerprint=f.fingerprint if f is not None else None,
                        observations_only=kept,
                        full=not kept,
                        graph_sha=_bound_graph(unit, manifest),
                        graph_fetch_ms=_graph_fetch_ms(manifest),
                        error="" if completeness != "failed" else f"sections not collected: {gaps}",
                        fetch_ms=f.fetch_ms if f is not None else None,
                        fetch_started_ms=f.fetch_started_ms if f is not None else None,
                        fetch_finished_ms=f.fetch_finished_ms if f is not None else None,
                        ingested_ms=ingested_ms,
                        load_ms=load_ms,
                        sections=manifest.sections,
                        authoritative=authoritative,
                        tables=manifest.tables,
                    )
                )
            except CycleIdentityCollision as exc:
                # Two devices of this run declared one uid as two objects
                # (core/loader.py `_check_cycle_anchors`). The run fails as
                # a whole, the way a failing reasoner fails it. A carry of
                # the rejected device would attach the edges of its previous
                # run to the node of the other device.
                raise CycleIdentityCollision(f"{label}: {exc}") from exc
            except Exception as exc:
                if f is not None and f.trace is not None:
                    f.trace.discard()  # a no-op once the write sealed it
                if _cut_by_cancel(exc, stop, name):
                    # The cancel of this source ended its load. The device
                    # carries as the devices after it do. A cancel after the
                    # load committed a write leaves that write beside the
                    # carried objects, and the device is marked as a failed
                    # load is.
                    cancelled += 1
                    scopes.carry(unit, CANCELLED)
                    if ws.began:
                        evidence.mixed_loads.add((name, host))
                    continue
                bad += 1
                scopes.carry(unit, "failed")
                details.append(f"{label}: {type(exc).__name__}: {exc}")
                # `ingested_ms` on the failed outcome records a graph write that
                # the load committed before it raised (path/gates/coverage.py).
                began = ws.began
                emit(
                    DeviceOutcome(
                        name,
                        host,
                        False,
                        error=f"{type(exc).__name__}: {exc}",
                        ingested_ms=int(time.time() * 1000) if began else None,
                    )
                )
            finally:
                # Remove a spill file that the load did not move to its raw
                # path, however the load ended. The call is a no-op once the
                # load moved it.
                if f is not None and f.spilled is not None:
                    rawstore.drop_spill(f.spilled)
        if cancelled:
            statuses[name] = CANCELLED
            details.append(f"{name}: cancelled by operator; {cancelled} of its devices are carried forward")
        elif bad:
            statuses[name] = "partial" if ok else "failed"
        else:
            statuses[name] = "partial" if degraded else "fresh"
        if skipped:
            needs_carry.add(name)
    return statuses, details, ran, needs_carry, scopes


def _record_warnings(evidence: RunEvidence, details: list[str], manifest: RunManifest) -> None:
    """Add the warnings of a load to the run detail and to the manifest. The
    warning text already names the device, and no label is added."""
    for warning in manifest.warnings:
        details.append(f"warning: {warning}")
        evidence.warnings.append(warning)


def _carry_phase(
    s: Session,
    prepared: list[PreparedSource],
    statuses: dict[str, str],
    needs_carry: set[str],
    details: list[str],
    prev: int | None,
    cts: int,
    scopes: CarryScopes,
    settings: Settings,
) -> list[str]:
    """Fill the gaps of the scopes that did not run or failed from the
    previous cycle.

    `scopes` decides which objects of the parent run come forward. A device
    that collected in this run answers for its own scope. An object of that
    scope that this run does not hold is a removal. The source names below
    cover the objects that no scope in this run can name
    (`cycle.carry_forward`).

    `scopes.sections` goes with the same call. A device that collected
    `partial` is in the carry set already, because a degrading section makes
    its source `partial` too. The section-level carry never needs a source
    that the scope-level carry did not name.

    Mutates `statuses` and `details` in place and returns the carried set."""
    # The absent-only carry also takes "partial" sources and the fresh sources
    # whose unchanged devices skipped their loads (`needs_carry`).
    if prev is not None:
        previous = _previous_devices(settings, prev)
        for p in prepared:
            hosts = dict.fromkeys(p.paused_hosts, "not-run")
            hosts.update({_status_host(u): "failed" for u in p.units if u.collector is None})
            if hosts:
                needs_carry.add(p.row.name)
            for host, reason in hosts.items():
                prior = previous.get((p.row.name, host))
                if prior is None:
                    continue
                owned = (
                    [prior.scope]
                    if prior.scope
                    else cycle.device_scopes(s, prev, prior.device_uids, p.row.name)
                )
                for scope in owned:
                    if scope not in scopes.collected:
                        scopes.reasons[scope] = reason
        _name_written_scopes(s, prev, prepared, previous, scopes)
        _name_renamed_scopes(prepared, previous, scopes)
    carried = sorted(
        {n for n, v in statuses.items() if v in ("carried", "failed", "partial", CANCELLED)} | needs_carry
    )
    if carried and prev is None:
        # On a cold start the not-run sources are recorded as failed.
        for name in list(statuses):
            if statuses[name] in ("carried", CANCELLED):
                statuses[name] = "failed"
        details.append(f"cold start: no previous run to carry {', '.join(carried)} from")
    if carried and prev is not None:
        # `_sources` on a node can hold the collector's TYPE name in place of
        # the source row's name (a row `vyos1` stamps `vyos`). Both are matched.
        # 'reasoner' is not in this set.
        carried_ids = sorted(
            {p.row.name for p in prepared if p.row.name in carried}
            | {p.row.type for p in prepared if p.row.name in carried}
        )
        # The sources whose objects can come forward on the source rule
        # alone, case 4 of `cycle._READ_CARRY_NODES`. A device dropped from
        # the inventory of a running source is a removal. Only a source that
        # this run asked nothing keeps its dropped devices.
        unasked = sorted(
            {p.row.name for p in prepared if p.row.name in carried and _unasked(p, statuses)}
            | {p.row.type for p in prepared if p.row.name in carried and _unasked(p, statuses)}
        )
        counts = cycle.carry_forward(
            s,
            prev,
            cts,
            carried_ids,
            scopes=scopes.reasons,
            collected=scopes.collected,
            unasked=unasked,
            section_labels=scopes.sections,
        )
        if counts["nodes"]:
            details.append(f"carried {counts['nodes']} nodes, {counts['rels']} rels from {prev}")
    return carried


# The collector types whose devices a parent run can hold under another
# scope than the one the collector names itself by (`_name_written_scopes`).
RESCOPED_TYPES = frozenset({"vyos"})


def _name_written_scopes(
    s: Session,
    prev: int,
    prepared: list[PreparedSource],
    previous: Mapping[tuple[str, str], manifests.DeviceEntry],
    scopes: CarryScopes,
) -> None:
    """Name, beside a unit that did not collect, the scope that its parent
    run holds the objects of the unit under, when that scope differs from the
    scope of the unit. The carry then brings the objects forward. Mutates
    `scopes.reasons`.

    A parent run can hold the objects of a unit under another scope. For
    example, a VyOS batch is stamped `vyos:<hostname>` where the run names the
    device `vyos:<host>`.

    Only a unit of one of RESCOPED_TYPES is looked up. The scope is read
    from the Device nodes of the unit in the parent run
    (`cycle.written_scopes`) and taken with the unit's reason only when it
    names the same collector type, did not collect, and is not the scope of
    any unit of this run or of any device the parent run's manifest records.
    """
    names = {p.row.name for p in prepared}
    units = [
        (entry.source, entry.scope, entry.device_uids)
        for entry in previous.values()
        if entry.source in names
        and entry.scope in scopes.reasons
        and collector_type(entry.scope) in RESCOPED_TYPES
    ]
    # `written_scopes` is imported by name. The seam tests replace `cycle`
    # whole, and the read uses the session that they stub.
    found = written_scopes(s, prev, units)
    if not found:
        return
    claimed = {entry.scope for entry in previous.values()} | {
        _unit_scope(u) for p in prepared for u in p.units
    }
    for scope, written in sorted(found.items()):
        for other in written:
            if (
                other in claimed
                or other in scopes.collected
                or other in scopes.reasons
                or collector_type(other) != collector_type(scope)
            ):
                continue
            scopes.reasons[other] = scopes.reasons[scope]


def _name_renamed_scopes(
    prepared: list[PreparedSource],
    previous: Mapping[tuple[str, str], manifests.DeviceEntry],
    scopes: CarryScopes,
) -> None:
    """Name, beside a unit that did not collect, the scope that the manifest
    of the parent run records for the same target, when the collector of the
    unit names another scope. The carry then brings the objects of the target
    forward. Mutates `scopes.reasons`.

    The parent scope is taken only when no other target of the parent
    manifest recorded it. A scope that collected, that already has a reason,
    or that is the scope of a unit of this run keeps its decision.
    """
    held = Counter(entry.scope for entry in previous.values() if entry.scope)
    current = {_unit_scope(u) for p in prepared for u in p.units}
    for p in prepared:
        for unit in p.units:
            reason = scopes.reasons.get(_unit_scope(unit))
            prior = previous.get((p.row.name, _status_host(unit)))
            if reason is None or prior is None or not prior.scope:
                continue
            old = prior.scope
            if held[old] > 1 or old in current or old in scopes.collected or old in scopes.reasons:
                continue
            scopes.reasons[old] = reason


def _note_rechecks(
    evidence: RunEvidence, prepared: list[PreparedSource], prior: Mapping[tuple[str, str], DeviceStatus]
) -> None:
    """Hand `_device_entries` the last check of every device this run has no
    outcome for (`RunEvidence.rechecked`).

    A device that the run carries can have been fetched since the parent run
    by a per-device job that found it unchanged against the basis on record.
    That fetch parks nothing and records only its window
    (`DeviceStatus.last_verified_at`). The window is the last check of the
    device. `_device_entries` publishes it when it is newer than what the
    entry of the parent records. `prior` holds the status rows that the run
    read under the cycle lock. A device whose load this run cut short after it
    wrote (`RunEvidence.mixed_loads`) holds a mix of that write and the objects
    of the parent, which no earlier check describes."""
    touched = {(o.source, o.host) for o in evidence.devices} | evidence.mixed_loads
    for prep in prepared:
        for unit in prep.units:
            key = (prep.row.name, _status_host(unit))
            row = prior.get(key)
            end = _ms_of(row.last_verified_at) if row is not None else None
            if key in touched or row is None or end is None:
                continue
            evidence.rechecked[key] = (_ms_of(row.last_verified_started_at), end)


def _previous_devices(settings: Settings, prev: int | None) -> dict[tuple[str, str], manifests.DeviceEntry]:
    if prev is None:
        return {}
    try:
        return {(d.source, d.host): d for d in manifests.read(settings, prev).devices}
    except (OSError, ValueError):
        # Publication independently validates the parent manifest chain.
        return {}


def _device_entries(
    settings: Settings,
    cts: int,
    prev: int | None,
    prepared: list[PreparedSource],
    statuses: dict[str, str],
    evidence: RunEvidence,
) -> list[manifests.DeviceEntry]:
    """One manifest entry per device of the run, collected or not.

    `effective_run` is the run whose payload provides the state of that
    device in this snapshot. For a device that this pass collected, it is the
    run that this pass wrote, taken from the file list. Otherwise it is the
    newest run at or before this snapshot that the join sidecars of the raw
    store record for the device. The file list comes first.

    `effective_run` is null with `carried` true for a device with no payload in
    any run at or before this snapshot. The fetch time comes from the run id,
    which is built from it (`collectors.base.new_run_id`).

    `fetch_started_ms`, `fetch_finished_ms` and `ingested_ms` come from the
    outcome the same way as `raw_sha256` and `error`. They are null for a
    device that this run has no outcome for. `expected_sections` and the
    `parser_version` of each table entry come from the collector of the unit.
    They hold what the collector declares, also for a device that did not run.

    `verified_started_ms` and `verified_ms` of a carried device are the window
    of the last fetch that checked it against the basis on record
    (`DeviceOutcome.verified`). That fetch is the fetch of this run or, for a
    device that this run has no outcome for, the check that a per-device fetch
    recorded (`RunEvidence.rechecked`). A check is published only when it ends
    after every time that the preceding entry records. It never dates the
    device earlier than its data. Otherwise the entry keeps the check of the
    preceding entry. The fetch window of the entry stays that of the fetch
    that its data came from.
    """
    previous_devices = _previous_devices(settings, prev)
    outcomes = {(o.source, o.host): o for o in evidence.devices}
    mixed_loads: set[tuple[str, str]] = getattr(evidence, "mixed_loads", set())
    rechecked: Mapping[tuple[str, str], tuple[int | None, int]] = getattr(evidence, "rechecked", {})
    fresh_runs = {(f.source, f.host): f.run_id for f in evidence.files if f.kind == "raw"}
    # only a device this run carried asks the raw store which run it stands on
    carried_keys = {
        inventory_collection.target_key(p.row.name, _status_host(unit)).slugged
        for p in prepared
        for unit in p.units
    } - {key for key, run_id in fresh_runs.items() if run_id}
    effective = manifests.effective_runs(settings.raw_dir, cts, carried_keys)
    entries: list[manifests.DeviceEntry] = []
    for p in prepared:
        for unit in p.units:
            host = _status_host(unit)
            outcome = outcomes.get((p.row.name, host))
            key = inventory_collection.target_key(p.row.name, host).slugged
            run_id = fresh_runs.get(key) or effective.get(key)
            prior = previous_devices.get((p.row.name, host))
            carried = key not in fresh_runs
            sections = outcome.sections if outcome is not None else {}
            if carried and not sections and prior is not None:
                sections = dict(prior.sections)
            fetch_started_ms = outcome.fetch_started_ms if outcome is not None else None
            parser_version = getattr(unit.collector, "PARSER_VERSION", None)
            tables = {
                name: table.model_copy(
                    update={"observed_ms": fetch_started_ms, "parser_version": parser_version}
                )
                # A skip that is no check did not compare what feeds the
                # tables. For VyOS, `neigh` feeds `arp`, and only the
                # observation hash covers it. The tables of such a skip are
                # not stamped as observed by this fetch and keep the stamps
                # of the preceding entry.
                for name, table in (
                    outcome.tables
                    if outcome is not None and (outcome.verified or not outcome.skipped)
                    else {}
                ).items()
            }
            if carried and not tables and prior is not None:
                tables = dict(prior.tables)
            captured_uids = getattr(unit.collector, "last_device_uids", None)
            if captured_uids is None:
                device_uids = list(prior.device_uids) if prior is not None else []
            else:
                device_uids = sorted(set(captured_uids))
            # The clock declaration is a host-level setting. The same collector
            # host clock stamps the fetch window of every source.
            declared_quality = cast(
                Literal["unknown", "uncertain", "trusted"],
                settings.collector_clock_quality,
            )
            declared_assumption = settings.collector_clock_assumption
            clock_source = "collector-fetch-window" if declared_quality == "trusted" else ""
            source_clock_ms = None
            if carried and prior is not None:
                declared_quality = prior.clock_quality
                declared_assumption = prior.clock_assumption
                clock_source = prior.clock_source
                source_clock_ms = prior.source_clock_ms
                fetch_started_ms = prior.fetch_started_ms
            # A fetch that found a carried device unchanged against the basis
            # on record observed the device again. The window of that fetch
            # gives the age and skew of the evidence. The fetch is the fetch of
            # this run or, for a device that this run has no outcome for, a
            # per-device fetch since the parent run. A device that no fetch
            # checked keeps the last verification.
            check: tuple[int | None, int] | None = None
            if outcome is not None:
                if outcome.verified and outcome.ok and outcome.fetch_finished_ms is not None:
                    check = (outcome.fetch_started_ms, outcome.fetch_finished_ms)
            elif prior is not None:
                check = rechecked.get((p.row.name, host))
            seen = (
                max(
                    (
                        t
                        for t in (prior.fetch_started_ms, prior.fetch_finished_ms, prior.verified_ms)
                        if t is not None
                    ),
                    default=None,
                )
                if prior is not None
                else None
            )
            verified = carried and check is not None and (seen is None or check[1] > seen)
            verified_started_ms, verified_ms = (
                check
                if verified and check is not None
                else (prior.verified_started_ms, prior.verified_ms)
                if carried and prior is not None
                else (None, None)
            )
            if verified:
                # the verification is stamped by this run's collector host clock
                declared_quality = cast(
                    Literal["unknown", "uncertain", "trusted"], settings.collector_clock_quality
                )
                declared_assumption = settings.collector_clock_assumption
                clock_source = "collector-fetch-window" if declared_quality == "trusted" else ""
            entries.append(
                manifests.DeviceEntry(
                    mixed_since=_mixed_since(
                        outcome, prior, cts, unit.collector, (p.row.name, host) in mixed_loads
                    ),
                    source=p.row.name,
                    host=host,
                    outcome=_device_outcome(outcome, statuses.get(p.row.name, "carried")),
                    fetch_ts_ms=manifests.run_ts(run_id) if run_id else None,
                    fetch_started_ms=fetch_started_ms,
                    fetch_finished_ms=(
                        prior.fetch_finished_ms
                        if carried and prior is not None
                        else outcome.fetch_finished_ms
                        if outcome is not None
                        else None
                    ),
                    source_clock_ms=source_clock_ms,
                    clock_quality=declared_quality,
                    clock_source=clock_source,
                    clock_assumption=declared_assumption,
                    verified_started_ms=verified_started_ms,
                    verified_ms=verified_ms,
                    ingested_ms=outcome.ingested_ms if outcome is not None else None,
                    raw_sha256=outcome.raw_sha if outcome is not None else None,
                    error=(
                        redaction.redact_known(
                            outcome.error, redaction.secret_values(getattr(unit.collector, "config", None))
                        )
                        if outcome is not None
                        else ""
                    ),
                    effective_run=run_id,
                    carried=carried,
                    sections=sections,
                    expected_sections=(
                        list(prior.expected_sections)
                        if carried and prior is not None
                        else _expected_sections(unit.collector, sections)
                    ),
                    tables=tables,
                    device_uids=device_uids,
                    scope=_unit_scope(unit) or (prior.scope if prior is not None else ""),
                )
            )
        represented = {_status_host(unit) for unit in p.units}
        for (source, host), prior in previous_devices.items():
            if source != p.row.name or host in represented:
                continue
            if host in p.paused_hosts or _unasked(p, statuses):
                entries.append(prior.model_copy(update={"outcome": "carried", "carried": True}))
    return entries


def _mixed_since(
    outcome: DeviceOutcome | None,
    prior: manifests.DeviceEntry | None,
    cts: int,
    collector: Collector | None = None,
    cut_after_write: bool = False,
) -> str | None:
    """The run whose failed load left the objects of this device a mix of
    two configurations, while the device still stands on that state.

    A failed load that committed a graph write (`ingested_ms` on the failed
    outcome), or a load that the cancel of its source cut after a write
    (`cut_after_write`), marks this run. A full payload that loaded with
    success clears the mark, whatever its side tables did, because it wrote
    the objects of the device whole. The one exception is a degrading section
    whose labels the collector declares (`Collector.SECTION_LABELS`). Those
    objects are carried from the parent run, which holds the mixed state, and
    the mark stays while such a section fails. A degrading policy section is
    also reported by its own gap. Every other case keeps the mark of the run
    before: no outcome, a failed fetch, or a skipped or observation-only fetch
    whose basis can predate the failed load."""
    if cut_after_write or (outcome is not None and not outcome.ok and outcome.ingested_ms is not None):
        return str(cts)
    if (
        outcome is not None
        and outcome.ok
        and outcome.full
        and not outcome.skipped
        and not outcome.observations_only
        and not _failed_section_labels(collector, outcome.sections)
    ):
        return None
    return prior.mixed_since if prior is not None else None


def _expected_sections(collector: Collector | None, sections: Mapping[str, SectionOutcome]) -> list[str]:
    """The sections that the collector of this device accounts for, sorted.
    These are its `SECTIONS` classvar (the Cisco families) when it declares
    one, and otherwise the section names that its outcomes recorded (VyOS,
    whose section names vary with the policy tables of the device). Empty for
    a device with no collector."""
    declared = getattr(collector, "SECTIONS", None)
    return sorted(declared) if declared else sorted(sections)


def _device_outcome(outcome: DeviceOutcome | None, source_status: str) -> str:
    """What one device did in this run. A device without an outcome was not
    collected in this run and stands on what the carry brought forward.

    "partial" is a collection. The device connected, the load landed, and at
    least one of its sections did not come back. An `unsupported` or `empty`
    section does not count. A box without the feature and a box with nothing
    in the table both answered.

    An observation-only publication reads `unchanged` too. In the manifest, an
    observation-only device contributes its raw file and a parquet per
    non-empty table. A skipped device contributes no file."""
    if outcome is None:
        return "carried" if source_status != "failed" else "failed"
    if not outcome.ok:
        return "failed"
    if outcome.skipped or outcome.observations_only:
        return "partial" if outcome.completeness == "partial" else "unchanged"
    return "partial" if outcome.completeness == "partial" else "collected"


def _graph_evidence(
    s: Session,
    settings: Settings,
    cts: int,
    prev: int | None,
    details: list[str],
    observer: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[manifests.GraphDelta, Callable[[], manifests.Checkpoint]]:
    """The two graph-derived digests of the manifest, and what to do when the
    graph cannot answer.

    Every other part of the manifest is evidence about files this process
    wrote, and a failure there fails the run. A failed read of these two
    records the digest as null with the reason beside it.

    The delta is computed here. The checkpoint comes back as a thunk, because
    only `manifest.build` knows whether this position in the chain
    checkpoints, and reading the full open state is expensive.
    """

    def delta() -> manifests.GraphDelta:
        try:
            return manifests.graph_delta(s, prev, cts, observer=observer)
        except Exception as exc:
            note = f"{type(exc).__name__}: {exc}"
            logger.warning("[manifest] graph delta for run %s not digested: %s", cts, note)
            details.append(f"manifest: graph delta not digested ({note})")
            return manifests.GraphDelta(previous_snapshot=prev, note=note)

    def checkpoint() -> manifests.Checkpoint:
        try:
            return manifests.checkpoint(s, cts)
        except Exception as exc:
            note = f"{type(exc).__name__}: {exc}"
            logger.warning("[manifest] checkpoint for run %s not digested: %s", cts, note)
            details.append(f"manifest: checkpoint not digested ({note})")
            return manifests.Checkpoint(note=note)

    return delta(), checkpoint


def _write_manifest(
    s: Session,
    settings: Settings,
    cts: int,
    prev: int | None,
    kind: str,
    statuses: dict[str, str],
    details: list[str],
    prepared: list[PreparedSource],
    evidence: RunEvidence,
    devices: list[manifests.DeviceEntry],
    carried_files: list[manifests.FileEntry],
    assigned_sites: Mapping[str, str | None] | None,
    findings: finalization.RunFindings | None = None,
    projection: Projection | None = None,
) -> str:
    """Build, sign and write the manifest of this snapshot and return its
    digest.

    Raises when the manifest cannot be written, and the run is not published.

    The file list holds what this run wrote plus the entries of the earlier
    runs that its carried devices stand on, copied from the parent chain
    (`manifest.carried_entries`). The manifest then names every file that the
    snapshot answers with. The site assignments that this run applied are
    recorded beside them. A rebuild can re-materialize them without the
    identity store.
    """
    sources = [
        manifests.SourceEntry(
            name=p.row.name,
            type=p.row.type,
            status=statuses.get(p.row.name, "carried"),
            config_sha256=manifests.source_config_digest(p.row.name, p.row.type, p.row.enabled, p.row.config),
        )
        for p in prepared
    ]
    delta, checkpoint = _graph_evidence(
        s, settings, cts, prev, details, projection.observe if projection is not None else None
    )
    if projection is not None:
        # the HST map tiers use this diff and stage their files before the pointer moves
        projection.prepare(s, complete=prev is None or delta.sha256 is not None)
    # The diagnostic values are non-secret.
    capture = evidence.capture
    normalization_context: dict[str, Any] = {
        "app_version": manifests.__version__,
        "build_revision": settings.hst_build_revision,
        "settings": {
            "estate_name": settings.estate_name,
            "l2_fabrics": settings.l2_fabrics,
            "rib_graph_max_routes": settings.rib_graph_max_routes,
        },
        # What the run was resolved under: the resolver version,
        # the intent generation captured before the build and the desired
        # placement revision of every device uid known when it started.
        "resolver_version": str(capture.resolver_version),
        "placement_generation": capture.placement_generation,
        "placement_revisions": dict(sorted(capture.placement_revisions.items())),
        "sources": {
            p.row.name: {
                "type": p.row.type,
                "config_sha256": manifests.source_config_digest(
                    p.row.name, p.row.type, p.row.enabled, p.row.config
                ),
                "devices": {_status_host(unit): _device_context(settings, p, unit) for unit in p.units},
            }
            for p in prepared
        },
    }
    if prev is not None:
        try:
            prior_archive = manifests.read(settings, prev).graph_archive
        except (OSError, ValueError):
            prior_archive = None
        prior_context = prior_archive.normalization_context if prior_archive is not None else {}
        prior_sources = prior_context.get("sources", {})
        for device_entry in devices:
            if not device_entry.carried:
                continue
            previous = prior_sources.get(device_entry.source, {}).get("devices", {}).get(device_entry.host)
            if previous is not None and device_entry.source in normalization_context["sources"]:
                normalization_context["sources"][device_entry.source]["devices"][device_entry.host] = previous
    archive = manifests.GraphArchiveEntry.model_validate(
        grapharchive.write(
            s,
            settings,
            cts,
            crypto.dek(settings),
            normalization_context=normalization_context,
        )
    )
    record = manifests.build(
        settings=settings,
        snapshot_key=cts,
        kind=kind,
        parent=prev,
        sources=sources,
        devices=devices,
        files=[*evidence.files, *carried_files],
        delta=delta,
        checkpoint_of=checkpoint,
        site_assignments={uid: code for uid, code in (assigned_sites or {}).items() if code},
        site_blocks=evidence.capture.site_blocks,
        graph_archive=archive,
        stretch_observations=findings.stretch_observations if findings is not None else None,
        warnings=findings.warnings if findings is not None else None,
    )
    return manifests.write(settings, record, manifests.signer_for(settings))


def _device_context(settings: Settings, p: PreparedSource, unit: PreparedDevice) -> dict[str, Any]:
    """The block of one device in the normalization context of the manifest.
    It holds the values that the collector was built with and, under resolver
    v2, the profile, credential and normalization revisions plus the
    configuration digest of the resolution that it was built from."""
    config = getattr(unit.collector, "config", None)
    block: dict[str, Any] = {
        "parser_version": getattr(unit.collector, "PARSER_VERSION", None),
        "effective": {
            "site": getattr(config, "site_code", None),
            "routing_scope": getattr(config, "effective_routing_scope", None),
            "l2fabric": getattr(config, "l2fabric", None) or settings.l2fabric_of(p.row.name),
        },
        "origins": getattr(config, "resolved_origins", {}),
        "resolver_version": sources_glue.RESOLVER_VERSION,
    }
    if unit.effective is not None:
        block.update(unit.effective.evidence())
        block["resolver_version"] = str(unit.effective.effective.resolver_version)
    return block


def _with_group_sites(
    assigned: Mapping[str, str | None] | None, prepared: list[PreparedSource]
) -> dict[str, str | None]:
    """`assigned` with the group sites of the uids that this cycle revealed.
    The group row of a prepared source fills each uid that `assigned` lacks or
    maps to None (`_effective_assignments`)."""
    sites = dict(assigned or {})
    for device_uid, site in _group_row_sites(prepared).items():
        if sites.get(device_uid) is None:
            sites[device_uid] = site
    return sites


def _group_row_sites(prepared: list[PreparedSource]) -> dict[str, str]:
    """Where a group's devices sit, read off the stored rows alone.

    `_effective_assignments` answers this for every uid `target_devices`
    already knows. A uid first seen in this cycle is placed from the rows the
    run was prepared from.

    Only groups are placed here, off the row. An empty site_code places the
    group nowhere.
    """
    sites: dict[str, str] = {}
    for prepared_source in prepared:
        if not sources_glue.is_group(prepared_source.row.type):
            continue
        site = prepared_source.row.config.get("site_code")
        if not site:
            continue
        for unit in prepared_source.units:
            for device_uid in getattr(unit.collector, "last_device_uids", None) or ():
                sites.setdefault(device_uid, site)
    return sites


def _finalize_cycle(
    s: Session,
    settings: Settings,
    cts: int,
    prev: int | None,
    statuses: dict[str, str],
    details: list[str],
    carried: list[str],
    assigned_sites: Mapping[str, str | None] | None,
    *,
    prepared: list[PreparedSource],
    evidence: RunEvidence,
    kind: str = "full",
    head: str = "cycle",
    fence: int | None = None,
    stop: threading.Event | None = None,
) -> str:
    """Derivations, the run meta node, and the switchover. Returns the summary.

    Shared by all three builders. The meta node records the kind of the run
    and its `parent`. `head` is the summary's leading word.

    The pointer moves last, after every write this run owns, the site
    assignments and the meta node included.

    The snapshot manifest is written between the totals of the meta node and
    that move. The meta node records its digest.
    """
    # The rule reasoner, the route-target derivations and the site assignments,
    # in that order (core/finalize.py). A site already in the map keeps authority.
    if evidence.capture.before_finalize is not None:
        effective_sites = dict(evidence.capture.before_finalize(cts))
    else:
        effective_sites = _with_group_sites(assigned_sites, prepared)
    site_blocks = evidence.capture.site_blocks
    # passed only when the run read them, like `parent`. The seam test stubs take only the rest.
    blocks_kw: dict[str, Any] = {} if site_blocks is None else {"site_blocks": site_blocks}
    # What the loads and the checks beside the rules found, for the manifest
    # below. The warnings of the loads come first, and the derivations add theirs.
    findings = finalization.RunFindings(warnings=list(evidence.warnings))
    if evidence.capture.site_blocks_warning:
        details.append(f"warning: {evidence.capture.site_blocks_warning}")
        findings.warnings.append(evidence.capture.site_blocks_warning)
    # The device entries and the files they stand on are known before the
    # derivations, and the derivations that read the side store open the files
    # of the devices they ask about (`manifest.SidestoreFiles`).
    devices = _device_entries(settings, cts, prev, prepared, statuses, evidence)
    carried_files = manifests.carried_entries(settings, prev, devices, evidence.files)
    details.extend(
        finalization.finalize_derivations(
            s,
            settings,
            cts,
            effective_sites,
            rules=reasoner,
            route_targets=rt_reasoner,
            cycle=cycle,
            findings=findings,
            parent=prev,
            sidestore_files=manifests.SidestoreFiles(settings, [*evidence.files, *carried_files]),
            **blocks_kw,
        )
    )
    # counted after the assignment, so the meta node's totals include the
    # LOCATED_IN edges it created
    totals = cycle.cycle_counts(s, cts)
    projection = _hst_projection(s, settings, cts, prev, kind)
    manifest_digest = _write_manifest(
        s,
        settings,
        cts,
        prev,
        kind,
        statuses,
        details,
        prepared,
        evidence,
        devices,
        carried_files,
        effective_sites,
        findings,
        projection,
    )
    cycle.write_cycle_meta(
        s,
        cts,
        statuses=statuses,
        carried_from=prev if carried else None,
        nodes=totals["nodes"],
        rels=totals["rels"],
        degraded=any(v in ("failed", "partial", CANCELLED) for v in statuses.values()),
        kind=kind,
        parent=prev,
        manifest_digest=manifest_digest,
    )
    # The switchover, and nothing after it.
    # `fence` covers a lock lost between this check and the write.
    _stopped(stop)
    if fence is None:
        # The blocking CLI path and the seam tests run without a lock and a fence.
        cycle.set_pointer(s, cts)
    else:
        cycle.set_pointer(s, cts, fence)
    if isinstance(stop, RunStop):
        # The pointer names the run. A cancel after this point has nothing to stop.
        stop.built = True
    if projection is not None:
        projection.publish()
    return f"{head} {cts}: {totals['nodes']} nodes, {totals['rels']} rels · " + "; ".join(details)


def _hst_marker_fallback(settings: Settings, key: int) -> dict[str, Any]:
    """The marker fields of a run whose projection never wrote one, from its manifest."""
    try:
        record = manifests.read(settings, key)
    except (OSError, ValueError):
        return {"kind": None, "parent": None, "published_ts": key}
    counts = record.graph_delta.counts.get("nodes", {})
    return {
        "kind": record.kind,
        "parent": record.parent,
        "published_ts": key,
        "counts": {k: int(counts.get(k, 0)) for k in ("added", "removed", "changed")},
    }


def _hst_projection(
    s: Session, settings: Settings, cts: int, prev: int | None, kind: str
) -> Projection | None:
    """The HST map projection of run `cts`, after the marker of `prev` is reconciled.

    None without the `sidestore` extra, which the map tables are written with.
    """
    try:
        from hst.map import project as hst_project
    except ImportError:
        return None
    hst_project.reconcile(
        settings.sidestore_dir, settings.manifests_dir, prev, lambda key: _hst_marker_fallback(settings, key)
    )
    return hst_project.Projection(
        settings.sidestore_dir,
        settings.manifests_dir,
        cts,
        prev,
        kind,
        checkpoint_every=settings.hst_tier_checkpoint_every,
    )


def _clear_spills(settings: Settings) -> None:
    """Remove the spill files an earlier run left in the raw store.

    Only a fetch window writes them, a cycle's or a refresh's, and both run
    under the cycle lock. The caller holds that lock, so a spill file present
    now belongs to an earlier run that has not adopted or removed it.
    `rawstore.clear_spills` logs what it cannot remove and never fails the
    run.
    """
    removed = rawstore.clear_spills(settings.raw_dir)
    if removed:
        logger.info("removed %d spill file(s) of an earlier run from the raw store", len(removed))


def execute_cycle(
    settings: Settings,
    prepared: list[PreparedSource],
    fresh: set[str],
    assigned_sites: Mapping[str, str | None] | None = None,
    prior: Mapping[tuple[str, str], DeviceStatus] | None = None,
    outcomes: list[DeviceOutcome] | None = None,
    *,
    fence: int | None = None,
    stop: threading.Event | None = None,
    capture: ExecutionCapture | None = None,
) -> RunOutcome:
    """Run one full cycle. Blocking, on a worker thread.

    The cycle runs the concurrent fetch phase, the fresh loads, the
    carry-forward for the rest, the rule reasoner, the route-target domain
    derivation (rt-domains), the re-applied operator site assignments, the
    cycle meta node and the pointer, in this order. The run is `full` when
    `fresh` names every prepared source and `partial` otherwise.

    `prior` turns the concurrent path on. Fetches run on the bounded pool. A
    device whose payload hash matches its `device_status` row skips normalize
    and load, and its objects are carried forward (`_fetch_phase`). A device
    whose payload is normalized and whose batch has the digest that its row
    records writes its raw file, its side tables and the objects that it
    shares with other writers. Its other objects are carried forward the same
    way (`_recorded_graph`). With None (direct callers and the seam tests that
    stub `coll.execute`), every fetch is inline and serial, with no skipping.
    `outcomes` collects one DeviceOutcome per attempted device for `launch` to
    persist.

    A failing collector fails only that device. A group with fresh and failed
    devices reads "partial". It joins the carry set, and the absent-only rule
    of carry_forward fills the gaps of the failed devices with `carried: true`
    copies. A cycle in which no source collected and a source failed publishes
    the carried objects, and its run reads "error" (`_cycle_status`). A failing
    reasoner (rule or route-target) fails the whole run, see
    `core/finalize.py finalize_derivations`. A `CycleIdentityCollision` across
    devices (core/loader.py `_check_cycle_anchors`) fails the whole run too.
    """

    evidence = RunEvidence(settings)
    if capture is not None:
        evidence.capture = capture
    _arm_stop(prepared, stop)

    def emit(outcome: DeviceOutcome) -> None:
        evidence.devices.append(outcome)
        if outcomes is not None:
            outcomes.append(outcome)

    with _CYCLE_LOCK, dbmod.session(settings) as s:
        prev = cycle.current_ts(s)
        cts = cycle.new_collection_ts()
        kind = "full" if all(p.row.name in fresh for p in prepared) else "partial"
        with _building(s, settings, cts, kind, prev):
            fetched: Mapping[int, _Fetched] = {}
            progress: FleetProgress | None = None
            if prior is not None:
                _clear_spills(settings)
                # The units are in the order that the load loop below asks for them.
                # Each window that the buffer fetches is the next stretch of the serial load.
                to_fetch = [
                    (p.row.name, u)
                    for p in prepared
                    if p.row.name in fresh and p.error is None
                    for u in p.units
                    if u.collector is not None
                ]
                progress = FleetProgress(settings, to_fetch)
                fetched = _FetchBuffer(settings, to_fetch, prior, prev is not None, stop, progress)
            _stopped(stop)
            try:
                statuses, details, ran, needs_carry, scopes = _collect_sources(
                    s, prepared, fresh, fetched, cts, emit, evidence, stop, prev
                )
            finally:
                # A result that the loop never took is not loaded now. Its spill
                # file is removed with it.
                if isinstance(fetched, _FetchBuffer):
                    fetched.close()
                # The fetch is over either way. A record left reading `collecting`
                # draws a bar for a fetch that ended, and the runs endpoint has no
                # way to tell that from one still running.
                if progress is not None:
                    progress.finish_all()
            _stopped(stop)
            if prior is not None:
                _note_rechecks(evidence, prepared, prior)
            carried = _carry_phase(s, prepared, statuses, needs_carry, details, prev, cts, scopes, settings)
            summary = _finalize_cycle(
                s,
                settings,
                cts,
                prev,
                statuses,
                details,
                carried,
                assigned_sites,
                prepared=prepared,
                evidence=evidence,
                kind=kind,
                fence=fence,
                stop=stop,
            )
            return RunOutcome(summary, ran, cts, _cycle_status(statuses))


def _cycle_status(statuses: Mapping[str, str]) -> str:
    """The run status of a cycle with these per-source statuses. A cycle in
    which a source failed and no source is "fresh" or "partial" is "error"."""
    values = set(statuses.values())
    if "failed" in values and not values & {"fresh", "partial"}:
        return "error"
    return "ok"


def execute_refresh(
    settings: Settings,
    prepared: list[PreparedSource],
    name: str,
    assigned_sites: Mapping[str, str | None] | None = None,
    *,
    fence: int | None = None,
    stop: threading.Event | None = None,
    capture: ExecutionCapture | None = None,
    outcomes: list[DeviceOutcome] | None = None,
    concurrent: bool = False,
) -> RunOutcome:
    """Re-collect one source into a new run. Blocking, on a worker thread.

    A press builds a run the way a partial cycle does. The pressed source is
    fresh under a new key, and every other source is carried forward from the
    run that the pointer names. Then come the derivations, the pointer and a
    `:CycleRun` with kind "refresh" and `parent` set to the run that it was
    built from. Nothing at the key of the parent is changed.

    A device group refreshes every enabled device of its fleet. When a device
    fails, the source reads "partial" and the objects of the failed devices
    are carried forward from the parent run. The run fails when every device
    fails.

    On an empty graph (no pointer, at the first run or right after a purge),
    there is nothing to carry from, and the press runs one full cycle.

    `concurrent` fetches the devices of the source the way a cycle does
    (`_FetchBuffer`), `collect_fetch_buffer` at a time, across the two fetch
    lanes, with the loads serial behind them. A press loads every device that
    it fetches, and no device is skipped as unchanged. The cold-start cycle
    fetches the same way. With False, the default for direct callers and the
    seam tests that stub `coll.execute`, each device is fetched inline in its
    load.

    Only the collectors of the pressed source get a source flag. Every other
    source is carried. A cancel of one of them alone stops nothing and answers
    that the run is not collecting it (`cancel_run`). The cold-start cycle
    arms every source that it collects (`execute_cycle`). A press whose source
    is cancelled alone before its loads end publishes nothing, because it is
    the one source that the run collects. The builder raises `RunCancelled`,
    which `launch` records as the cancellation of the run.
    """
    _arm_stop([p for p in prepared if p.row.name == name], stop)
    with _CYCLE_LOCK, dbmod.session(settings) as s:
        prev = cycle.current_ts(s)
        if prev is not None:
            mine = next((p for p in prepared if p.row.name == name), None)
            if mine is None or mine.error is not None or not mine.units:
                reason = mine.error or "no devices and no host" if mine else "source not prepared"
                raise RuntimeError(f"{name}: {reason}")
            cts = cycle.new_collection_ts()
            with _building(s, settings, cts, "refresh", prev):
                evidence = RunEvidence(settings)
                if capture is not None:
                    evidence.capture = capture

                def emit(outcome: DeviceOutcome) -> None:
                    evidence.devices.append(outcome)
                    if outcomes is not None:
                        outcomes.append(outcome)

                fetched: Mapping[int, _Fetched] = {}
                progress: FleetProgress | None = None
                if concurrent:
                    _clear_spills(settings)
                    to_fetch = [(name, u) for u in mine.units if u.collector is not None]
                    progress = FleetProgress(settings, to_fetch)
                    fetched = _FetchBuffer(settings, to_fetch, {}, False, stop, progress)
                try:
                    statuses, details, ran, needs_carry, scopes = _collect_sources(
                        s, prepared, {name}, fetched, cts, emit, evidence, stop, prev
                    )
                finally:
                    if isinstance(fetched, _FetchBuffer):
                        fetched.close()
                    if progress is not None:
                        progress.finish_all()
                # A stop of the whole run that cut the load of the last device
                # short left that device failed, with no device after it to check
                # the flag. The run ends with the reason of the stop.
                _stopped(stop)
                if statuses.get(name) == CANCELLED or _source_cancelled(stop, name):
                    # The source was stopped alone, before its first device or
                    # during its loads. It is the one source that this run
                    # collects, and nothing publishes. The check reads the flag as
                    # well as the status, for a cancel that landed after the check
                    # of the last device.
                    raise RunCancelled(f"{name}: cancelled by operator; nothing was published")
                if statuses.get(name) == "failed":
                    # Nothing of the pressed source landed. A published run that
                    # carried everything and collected nothing would read as a
                    # successful press.
                    raise RuntimeError("; ".join(details))
                carried = _carry_phase(
                    s, prepared, statuses, needs_carry, details, prev, cts, scopes, settings
                )
                summary = _finalize_cycle(
                    s,
                    settings,
                    cts,
                    prev,
                    statuses,
                    details,
                    carried,
                    assigned_sites,
                    prepared=prepared,
                    evidence=evidence,
                    kind="refresh",
                    head=f"refresh {name}",
                    fence=fence,
                    stop=stop,
                )
                return RunOutcome(summary, ran, cts)
    # Cold start. One full cycle creates the first complete snapshot, under the
    # same lock acquisition and the same fence. With no previous run, no device
    # can skip, and the concurrent fetch needs no device status.
    return execute_cycle(
        settings,
        prepared,
        {p.row.name for p in prepared},
        assigned_sites,
        {} if concurrent else None,
        outcomes=outcomes,
        fence=fence,
        stop=stop,
        capture=capture,
    )


def execute_demo(
    settings: Settings,
    runs: Sequence[Path],
    *,
    fence: int | None = None,
    stop: threading.Event | None = None,
    site_blocks: Mapping[str, tuple[str, str | None]] | None = None,
) -> RunOutcome:
    """Publish the run files of the demo estate in order. Blocking, on a worker thread.

    Each file is published as one run from empty, as `hst load-fixture --new-run` publishes it,
    with the map tables of the run (`fixture_runs.publish`).

    Every file is parsed before the first publish, and a file that does not parse publishes nothing.
    A stop before the first publish ends the run with nothing published. A stop after one keeps
    what is published and loads no further file, and the outcome names the last published run.

    `site_blocks` (device uid to block name and zone) is stamped on each run's Device nodes right
    after its load, before the derivations, the archive, the manifest and the pointer, with the
    statement a collection run uses (`cycle.apply_site_blocks`). With None, nothing is stamped.
    """
    from hst.app import fixture_runs
    from hst.core import loader as loadermod
    from hst.core.fixtures import load_fixture

    def stamped(s: Session, batch: Batch, **kwargs: Any) -> RunManifest:
        out = loadermod.load(s, batch, **kwargs)
        if site_blocks is not None:
            cycle.apply_site_blocks(s, site_blocks, kwargs["collection_ts"])
        return out

    batches = [(path, load_fixture(path)) for path in runs]
    published: list[tuple[Path, fixture_runs.FixtureRun]] = []
    with _CYCLE_LOCK:
        for path, batch in batches:
            if published and stop is not None and stop.is_set():
                break
            _stopped(stop)
            with dbmod.session(settings) as s:
                out = fixture_runs.publish(
                    s, settings, batch, path, new_run=True, fence=fence, loader=stamped
                )
            published.append((path, out))
    parts = [f"{path.stem} run {out.cts}" for path, out in published]
    detail = f"demo estate: {', '.join(parts)}"
    no_map = [
        (path.stem, out.map_failure or "no map projection") for path, out in published if not out.tiers_ready
    ]
    detail += f"; map tables written for {len(published) - len(no_map)} of {len(published)} runs"
    detail += "".join(f"; {stem}: map tables not written: {why}" for stem, why in no_map)
    left = [path.stem for path in runs[len(published) :]]
    if left:
        detail += f"; stopped before {', '.join(left)}"
    return RunOutcome(detail, [], published[-1][1].cts)


REASONER_REFUSAL = "the rule reasoner runs inside a collection run only; trigger a cycle or press a source"


def execute_source(settings: Settings, source: str, row: Source | None) -> tuple[str, Collector | None]:
    """The standalone reasoner trigger. Blocking, on a worker thread."""
    if source == "reasoner":
        raise RuntimeError(REASONER_REFUSAL)
    raise ValueError(f"execute_source only handles the reasoner; got {source!r}")


async def pin_host_key(store: Store, row: Source, collector, device: Device | None = None) -> None:
    """Record the host keys of the device and the bastion presented on first
    contact.

    The keys are written only into an empty pin. Once a key is pinned, the
    transport rejects a differing key. The pin is merged into the source row
    under the row lock of `Store.modify_source`. A write of the config by
    another writer is then kept.

    The pin of a fleet device lands on its own `devices.host_key` (the store
    enforces empty-only). The pin of the bastion stays on the source config in
    both cases, because the jump host belongs to the group and the whole fleet
    shares it. Under resolver v2 the row holds no jump host, because the jump
    host is a profile field and a revision is immutable. The key is then also
    kept by the address of the bastion in `config["jump_pins"]`, which the
    resolver lays over a profile that states none. A key that the profile
    states is never recorded.
    """
    observed = getattr(collector, "observed_host_key", "")
    jump_observed = getattr(collector, "observed_jump_key", "")
    if not observed and not jump_observed:
        return
    if device is not None and observed:
        await store.set_device_host_key(row.name, device.host, observed)
        observed = ""
    if not observed and not jump_observed:
        return
    bastion = getattr(getattr(collector, "config", None), "jump_host", None)

    def pin(fresh: Source) -> Source | None:
        config = fresh.config
        changed = False
        if observed and not config.get("host_key"):
            config["host_key"] = observed
            changed = True
        jump = config.get("jump_host")
        if jump_observed and isinstance(jump, dict) and not jump.get("host_key"):
            config["jump_host"] = {**jump, "host_key": jump_observed}
            changed = True
        if jump_observed and bastion is not None and not getattr(bastion, "host_key", ""):
            pin_key = inventory_collection.jump_pin_key(bastion.host, bastion.port)
            pins = config.get(inventory_collection.JUMP_PINS)
            if not isinstance(pins, dict) or not pins.get(pin_key):
                config[inventory_collection.JUMP_PINS] = {
                    **(pins if isinstance(pins, dict) else {}),
                    pin_key: jump_observed,
                }
                changed = True
        return fresh if changed else None

    # A row that was deleted during the run gets no pin.
    await store.modify_source(row.name, pin)


def _now() -> datetime:
    return datetime.now(UTC)


async def _record_outcomes(
    store: Store, outcomes: list[DeviceOutcome], secrets: Mapping[str, str] | None = None
) -> None:
    """Persist the per-device results of a cycle or a refresh to
    `device_status`, best-effort per row. `secrets` holds the credential
    values of the sources of the run. They are removed from the error text
    before it is logged or stored.

    A row that cannot be written would keep describing the objects of the
    device in the run before this one, and the skip decisions of the next run
    compare against it (`_recorded_graph`, `decide`). Its digest and raw hash
    are cleared (`_forget_device`). The next fetch of the device is then
    stored, and its next load writes.

    An outcome that checked the device against the basis on record
    (`DeviceOutcome.verified`) offers its fetch window as the last check of
    the row, with the hashes that it compared (`checked_basis`). The store
    records it only while the row still holds those hashes. A later device
    run publishes it for the device that it carries."""
    now = _now()
    for o in outcomes:
        o.error = sources_glue.redacted(o.error, dict(secrets or {}))
        if not o.ok:
            logger.error("collection failed for %s/%s: %s", o.source, o.host, o.error)
        checked = o.ok and o.verified and o.fetch_finished_ms is not None and o.checked_basis is not None
        try:
            await store.upsert_device_status(
                o.source,
                o.host,
                now=now,
                ok=o.ok,
                raw_sha=o.status_sha,
                obs_sha=o.obs_sha,
                graph_sha=o.graph_sha,
                graph_fetch_at=_at_ms(o.graph_fetch_ms),
                full=o.full,
                error=o.error,
                fetch_ms=o.fetch_ms,
                load_ms=o.load_ms,
                verified_started_at=_at_ms(o.fetch_started_ms) if checked else None,
                verified_at=_at_ms(o.fetch_finished_ms) if checked else None,
                verified_raw_sha=o.checked_basis[0] if checked and o.checked_basis else None,
                verified_obs_sha=o.checked_basis[1] if checked and o.checked_basis else None,
            )
        except Exception as exc:
            logger.warning("device_status for %s/%s not recorded: %s", o.source, o.host, exc)
            await _forget_device(store, o, now)


async def _record_graphs(store: Store, outcomes: list[DeviceOutcome]) -> None:
    """Persist what the loads of a device run established about the graph
    of each device (`record_device_graph`). That is the digest of the batch of
    an applied payload, the fetch time of that payload, and whether the batch
    was written. A load that failed clears the digest and the raw hash of the
    device. Its next fetch is then stored, and its next load writes. An
    observation payload normalized nothing to the digest. The writes are
    best-effort per row, as in `_record_outcomes`, and a digest that cannot be
    recorded is cleared the same way.

    A load that succeeded also records the skip basis of its payload
    (`record_device_basis`). The basis is recorded here, with the run
    published. The next fetch and the next cycle then skip against what the
    graph holds. A basis that cannot be recorded clears the raw hash and the
    digest. The next fetch of the device then parks, and its next load
    writes."""
    now = _now()
    for o in outcomes:
        if not (o.ok and o.graph_sha is None):
            digest = o.graph_sha if o.ok and o.graph_sha is not None else ""
            try:
                await store.record_device_graph(
                    o.source,
                    o.host,
                    now=now,
                    graph_sha=digest,
                    written=o.full,
                    fetch_at=_at_ms(o.graph_fetch_ms),
                )
            except Exception as exc:
                logger.warning("device_status graph for %s/%s not recorded: %s", o.source, o.host, exc)
                if digest:
                    await _forget_device(store, o, now)
                continue
        if not o.ok or (o.fingerprint is None and o.obs_sha is None and not o.basis_full):
            continue
        try:
            if not await store.record_device_basis(
                o.source, o.host, now=now, raw_sha=o.fingerprint, obs_sha=o.obs_sha, full=o.basis_full
            ):
                logger.warning(
                    "device_status basis for %s/%s not recorded: no device_status row; its next fetch "
                    "parks again and the device run after it records the basis",
                    o.source,
                    o.host,
                )
        except Exception as exc:
            logger.warning("device_status basis for %s/%s not recorded: %s", o.source, o.host, exc)
            await _forget_device(store, o, now)


async def _forget_device(store: Store, o: DeviceOutcome, now: datetime) -> None:
    """Clear the digest and the raw hash of a device whose status row could
    not be written. When that fails as well, the row is left as it is, and an
    error is logged."""
    try:
        await store.record_device_graph(o.source, o.host, now=now, graph_sha="", written=False)
    except Exception as exc:
        logger.error(
            "device_status for %s/%s still describes an earlier run; its next unchanged payload may "
            "skip its load: %s",
            o.source,
            o.host,
            exc,
        )


_UnitIndex = dict[tuple[str, str], tuple[PreparedSource, PreparedDevice]]


def _unit_index(prepared: list[PreparedSource]) -> _UnitIndex:
    """(slugged source, slugged host) -> the prepared unit that fetched it.

    A parked payload names its source and host by the slugged directory
    segments that `rawstore.write` put it under. The join back to a prepared
    unit slugs both sides.
    """
    index: _UnitIndex = {}
    for p in prepared:
        for unit in p.units:
            index[_target_key(p.row.name, unit).slugged] = (p, unit)
    return index


def _join_payload(
    s: Session,
    settings: Settings,
    collector: Collector,
    source_name: str,
    payload: rawstore.ParkedPayload,
    cts: int,
    on_write: Callable[[Path, str, int], None] | None = None,
    *,
    observations_only: bool = False,
    graph_gate: GraphGate | None = None,
    basis: dict[str, str] | None = None,
) -> RunManifest:
    """Re-read one parked payload and load it into run `cts`.

    The raw file is the only thing that survives a scheduler tick. The
    in-memory Batch of the fetch phase does not outlive the process. The
    device run decrypts and re-normalizes the payload here, the same way
    core/replay.py replays a raw file.

    The payload keeps its own fetch-time `run_id` and fetch time in the graph
    and in the side-store rows. Only `snapshot_ts` names the run that it
    joined.

    Nothing is settled here. `build_device_run` writes every join sidecar
    after the run has published. A run that raises in a derivation leaves its
    whole window parked for the next run to retry. The side-store rows that
    this load writes are the exception. The side-store sweep removes a
    parquet file stamped with a run that never published.

    `observations_only` (the park-time kind of the payload) writes its side
    tables and nothing else.

    `graph_gate` is handed to `coll.load_payload`, which normalizes the
    payload and writes only the shared part of the batch when the batch has
    the digest on record. It is passed on only when given.

    `basis`, when given, receives the two content hashes of the payload
    ("raw" from `coll.raw_sha` and "obs" from `coll.obs_sha`) of the bytes
    that this join read. The run records them as the skip basis once it has
    published (`_record_graphs`).
    """
    raw = rawstore.read(payload.path, crypto.dek(settings))
    if basis is not None:
        basis["raw"] = coll.raw_sha(collector, raw)
        basis["obs"] = coll.obs_sha(collector, raw)
    if observations_only:
        return coll.load_observations(
            collector,
            raw,
            collection_ts=cts,
            run_id=payload.run_id,
            ts_ms=payload.fetch_ts_ms,
            source_name=source_name,
            on_write=on_write,
        )
    if payload.normalization_context:
        context = payload.normalization_context
        collector.config = collector.config.model_copy(
            update={
                "site_code": context.get("site_code", collector.config.site_code),
                "routing_scope": context.get("routing_scope", collector.config.routing_scope),
                "l2fabric": context.get("l2fabric", collector.config.l2fabric),
                "resolved_origins": context.get("origins", collector.config.resolved_origins),
            }
        )
    gate = {"graph_gate": graph_gate} if graph_gate is not None else {}
    return coll.load_payload(
        collector,
        s,
        raw,
        collection_ts=cts,
        run_id=payload.run_id,
        ts_ms=payload.fetch_ts_ms,
        source_name=source_name,
        on_write=on_write,
        **gate,
    )


def _parked_as_current(collector: Collector, payload: rawstore.ParkedPayload) -> bool:
    """Whether the park-time normalization context that `_join_payload`
    applies (`collectors/base.py park`) equals the context of `collector`. Only
    then does a skip basis bound to the current resolution of the unit
    describe the load of this payload. A payload with no context, or a key
    that the context lacks, is joined under the context of the collector.
    Anything that cannot be compared counts as not current."""
    context = payload.normalization_context
    if not context:
        return True
    try:
        config = collector.config
        now = {
            "site_code": config.site_code,
            "routing_scope": config.effective_routing_scope,
            "l2fabric": collector.settings.l2fabric_of(config.source_name, config.l2fabric),
            "origins": config.resolved_origins,
        }
        # the join keeps the value of the collector for a key that the context lacks
        return all(k not in context or json.loads(json.dumps(now[k], default=str)) == context[k] for k in now)
    except (AttributeError, TypeError, ValueError):
        return False


def _window(
    payloads: list[rawstore.ParkedPayload],
) -> tuple[list[rawstore.ParkedPayload], dict[Path, list[rawstore.ParkedPayload]]]:
    """Split a device-run window into what to apply and what that supersedes.

    Returns the newest payload per device, oldest fetch first, and, keyed by
    the applied payload's path, the older payloads of the same device it wins
    against. The older ones are settled against the run this window publishes.
    """
    by_device: dict[tuple[str, str], list[rawstore.ParkedPayload]] = {}
    for payload in payloads:
        by_device.setdefault((payload.source, payload.host), []).append(payload)
    apply_: list[rawstore.ParkedPayload] = []
    superseded: dict[Path, list[rawstore.ParkedPayload]] = {}
    for group in by_device.values():
        group.sort(key=lambda p: p.fetch_ts_ms)
        apply_.append(group[-1])
        if len(group) > 1:
            superseded[group[-1].path] = group[:-1]
    apply_.sort(key=lambda p: p.fetch_ts_ms)
    return apply_, superseded


def _payload_label(payload: rawstore.ParkedPayload) -> str:
    """The source, host and run id of the payload. A controller payload has no host."""
    where = f"{payload.source}/{payload.host}" if payload.host else payload.source
    return f"{where} {payload.run_id}"


def _settle_joined(paths: list[Path], cts: int) -> None:
    """Record the run each payload joined, once the run has published.

    A sidecar that cannot be written is only logged, because the run that it
    names is already published. The payload stays parked. The next device run
    finds the run that it would have joined newer than its fetch and settles
    it as superseded.
    """
    for path in paths:
        try:
            rawstore.mark_joined(path, snapshot_ts=cts)
        except Exception:
            logger.exception("raw payload %s joined run %s but its sidecar was not written:", path, cts)


def _settle_superseded(payloads: list[rawstore.ParkedPayload], run_key: int) -> None:
    """Settle payloads no run will apply, against the run that superseded them.

    Best-effort, as `_settle_joined` is.
    """
    for payload in payloads:
        try:
            rawstore.mark_superseded(payload.path, superseded_by=run_key)
        except Exception:
            logger.exception(
                "raw payload %s was superseded by run %s but its sidecar was not written:",
                payload.path,
                run_key,
            )


def _collected_at(s: Session, prev: int, scopes: set[str]) -> dict[str, int | None]:
    """The newest `collected_at` run `prev` holds for each of `scopes`, read
    once for the whole window (`cycle.scopes_collected_at`). The function is
    read by name, as core/finalize.py reads the optional steps of the cycle
    module. A stub of the module that has only `scope_collected_at` is asked
    scope by scope."""
    batched = getattr(cycle, "scopes_collected_at", None)
    if batched is not None:
        found: dict[str, int] = batched(s, prev, scopes)
        return {scope: found.get(scope) for scope in scopes}
    return {scope: cycle.scope_collected_at(s, prev, scope) for scope in scopes}


def _last_observed(collected_at: int | None, status: DeviceStatus | None) -> int | None:
    """The time when the run that the device run builds on last observed a
    device, in epoch milliseconds like the fetch time of a parked payload.
    None when the run never observed the device.

    The result is the newer of two times. `collected_at` is the newest
    `collected_at` of the objects that the scope of the device owns in that
    run (`_collected_at`), which is the time a load last wrote them.
    `DeviceStatus.last_graph_fetch_at` is the fetch time of the payload whose
    batch the graph was last checked against. It is the later time once a
    cycle or a device run found the batch unchanged, because the objects of
    such a batch that come forward keep the time of their last write. The row
    describes the run that the pointer names, since every run records it
    before it releases the cycle lock.
    """
    times = [collected_at]
    if status is not None:
        times.append(_ms_of(status.last_graph_fetch_at))
    known = [t for t in times if t is not None]
    return max(known) if known else None


def build_device_run(
    settings: Settings,
    prepared: list[PreparedSource],
    assigned_sites: Mapping[str, str | None] | None = None,
    *,
    fence: int | None = None,
    stop: threading.Event | None = None,
    capture: ExecutionCapture | None = None,
    outcomes: list[DeviceOutcome] | None = None,
    prior: Mapping[tuple[str, str], DeviceStatus] | None = None,
) -> RunOutcome:
    """Fold every parked per-device payload into one new run. Blocking, on a
    worker thread.

    A device fetch parks its payload (`run_device_fetch`). Once per
    `device_run_interval_s`, everything parked since the last device run is
    re-read, loaded under one new key, and published as a `:CycleRun` with kind
    "device" and `parent` set to the run it was built from. Every device and
    source the window did not touch is carried forward.

    A payload whose source is not prepared (deleted or disabled between the
    fetch and now), or whose re-read or normalize raises, is left parked and
    named in the detail. The run still builds from the rest. Nothing is
    published when nothing is parked, and nothing is published before the first
    cycle has minted a run to carry from.

    A payload is only applied when it is newer than what the parent run already
    holds for that device (`_last_observed`). An older payload is settled as
    superseded and named in the detail, and its raw file is kept. Of 2 or more payloads
    of one device in one window, the newest is applied and the rest are
    superseded by the run it publishes. An observation payload that supersedes
    a full one is applied as a full payload.

    A window that applies nothing publishes nothing.

    `stop` is checked before the load of each payload, and each collector is
    handed the flag of the run. A device run is stopped only as a whole. It
    fetches nothing, and no source of it has requests to end. A payload cut
    short by the flag of its source would read as a failed device. The run
    creates no source flags. A cancel of one of its sources answers that the
    run is not collecting that source (`cancel_run`).

    `prior` holds the `device_status` row of each device. A full payload of a
    device whose row holds a digest of its batch (`_recorded_graph`) is
    normalized and loaded with that digest to compare. When its batch has the
    same digest, its side tables and the objects that it shares with other
    writers are written. Its other graph objects come forward from the parent
    run, as the objects of an observation payload do. The row also gives the
    time of the last graph check of the device for the comparison above. With
    None, the default for direct callers, nothing is compared.
    """
    _arm_stop(prepared, stop, per_source=False)
    prior = prior or {}
    now = time.time()
    with _CYCLE_LOCK, dbmod.session(settings) as s:
        prev = cycle.current_ts(s)
        if prev is None:
            return RunOutcome("skipped: no snapshot yet; a cycle must run first", [], None)
        payloads = rawstore.parked(settings.raw_dir)
        if not payloads:
            return RunOutcome("no device payloads parked since the last device run", [], None)
        cts = cycle.new_collection_ts()
        with _building(s, settings, cts, "device", prev):
            index = _unit_index(prepared)
            evidence = RunEvidence(settings)
            if capture is not None:
                evidence.capture = capture
            if outcomes is not None:
                evidence.devices = outcomes
            statuses: dict[str, str] = {p.row.name: "carried" for p in prepared}
            details: list[str] = []
            ran: list[tuple[Source, Device | None, Collector]] = []
            failed: set[str] = set()
            joined: set[str] = set()
            joined_paths: list[Path] = []
            stale: list[rawstore.ParkedPayload] = []
            # Every device of every prepared source starts as not-run.
            scopes = CarryScopes()
            for prep in prepared:
                for untouched in prep.units:
                    scopes.carry(untouched, "not-run")
            newest, superseded = _window(payloads)
            # the parent run's observation time of every device in the window, in
            # one read of the run
            window_scopes = {
                found[1].collector.scope
                for payload in newest
                if (found := index.get((payload.source, payload.host))) is not None
                and found[1].collector is not None
            }
            collected = _collected_at(s, prev, window_scopes)
            for payload in newest:
                _stopped(stop)
                # The label holds the run id with source/host. A window can hold
                # 2 or more payloads of one device.
                label = _payload_label(payload)
                found = index.get((payload.source, payload.host))
                if found is None or found[1].collector is None:
                    details.append(f"{label}: no enabled source or device for this payload; left parked")
                    continue
                source, unit = found
                collector = unit.collector
                if collector is None:  # the guard above already skipped this case
                    continue
                host = _status_host(unit)
                status = prior.get((source.row.name, host))
                observed = _last_observed(collected.get(collector.scope), status)
                if observed is not None and payload.fetch_ts_ms <= observed:
                    # the payloads it won against are older still
                    stale.append(payload)
                    stale.extend(superseded.get(payload.path, []))
                    details.append(
                        f"{label}: run {prev} holds a newer observation of this device "
                        f"({observed} vs {payload.fetch_ts_ms}); superseded, not applied"
                    )
                    continue
                observations_only = payload.kind == rawstore.KIND_OBSERVATION and not any(
                    older.kind != rawstore.KIND_OBSERVATION
                    and (observed is None or older.fetch_ts_ms > observed)
                    for older in superseded.get(payload.path, [])
                )
                recorded = "" if observations_only else _recorded_graph(settings, status, now)
                # read before the join, which sets the park-time context on the collector
                as_current = _parked_as_current(collector, payload)
                basis: dict[str, str] = {}
                ws = _GraphWrites(s)
                try:
                    manifest = _join_payload(
                        cast(Session, ws),
                        settings,
                        collector,
                        source.row.name,
                        payload,
                        cts,
                        evidence.on_write_for(collector),
                        observations_only=observations_only,
                        basis=basis,
                        **_graph_kw(unit, recorded, prev),
                    )
                    # The raw file is evidence of this run too. The fetch that
                    # parked it wrote it, and no writer here reports it.
                    evidence.record_file(payload.path, collector)
                except CycleIdentityCollision as exc:
                    # The same rule as in `_collect_sources`. A uid that folds
                    # two devices together fails the run.
                    raise CycleIdentityCollision(f"{label}: {exc}") from exc
                except Exception as exc:
                    failed.add(source.row.name)
                    scopes.carry(unit, "failed")
                    details.append(f"{label}: {type(exc).__name__}: {exc}; left parked")
                    # A load that committed a graph write before it raised left
                    # part of the objects of the device in this run. The carry
                    # fills only what it left absent. `ingested_ms` records
                    # that, as the failure path of the cycle records it
                    # (path/gates/coverage.py). A join that failed before any
                    # write (the raw read, normalize) carries the device whole.
                    evidence.devices.append(
                        DeviceOutcome(
                            source.row.name,
                            host,
                            False,
                            error=f"{type(exc).__name__}: {exc}",
                            ingested_ms=int(time.time() * 1000) if ws.began else None,
                        )
                    )
                    continue
                # The same rule as for the loads of a cycle. The payload
                # applied, and what it applied can still be less than the
                # whole device.
                #
                # An observation-kind payload, and a full payload whose batch
                # has the digest of the batch on record, wrote their side
                # tables and left the graph to the carry, except for the
                # objects of a kept batch that other writers share. The other
                # objects of the device come from the parent run and come
                # forward marked `unchanged`. The rows that a reader selects
                # by run belong to this run. A degrading authoritative
                # section fails such a device too, and its objects then carry
                # as the objects of a failed unit do.
                kept = observations_only or manifest.graph_unchanged
                authoritative = tuple(getattr(collector, "AUTHORITATIVE_SECTIONS", ()))
                completeness = _completeness(manifest.sections, manifest.tables, authoritative)
                gaps = _section_gaps(manifest.sections)
                all_gaps = ", ".join(g for g in (gaps, _table_gaps(manifest.tables)) if g)
                if completeness != "ok":
                    failed.add(source.row.name)
                if completeness == "failed":
                    scopes.carry(unit, "failed")
                elif kept:
                    scopes.carry(unit, "unchanged")
                else:
                    scopes.ran(unit, manifest.sections)
                # The skip basis this load establishes, recorded once the run
                # has published (`_record_graphs`). An observation payload
                # leaves the raw hash alone. A full payload normalized under a
                # context that is not the unit's own (placement moved since the
                # park) clears it.
                raw_basis: str | None = None
                if not observations_only and "raw" in basis:
                    raw_basis = (
                        inventory_collection.fingerprint_for(unit.effective, basis["raw"])
                        if as_current
                        else ""
                    )
                evidence.devices.append(
                    DeviceOutcome(
                        source.row.name,
                        host,
                        completeness != "failed",
                        obs_sha=basis.get("obs"),
                        fingerprint=raw_basis,
                        basis_full=bool(raw_basis),
                        observations_only=kept,
                        full=not kept,
                        graph_sha=_bound_graph(unit, manifest),
                        graph_fetch_ms=_graph_fetch_ms(manifest),
                        error="" if completeness != "failed" else f"sections not collected: {gaps}",
                        sections=manifest.sections,
                        authoritative=authoritative,
                        tables=manifest.tables,
                        # The parked file records when its fetch started (its run
                        # id), and its park sidecar when it finished.
                        fetch_started_ms=payload.fetch_ts_ms,
                        fetch_finished_ms=payload.fetch_finished_ms,
                        # The time this run loaded the payload into the graph, as
                        # the cycle records it. It is null for an observation payload.
                        ingested_ms=None if observations_only else int(time.time() * 1000),
                    )
                )
                joined.add(source.row.name)
                joined_paths.append(payload.path)
                if kept:
                    matched = "configuration" if observations_only else "graph"
                    line = _observation_line(
                        manifest.tables, manifest.sections, completeness, matched, manifest
                    )
                else:
                    line = finalization.manifest_line(manifest)
                    if completeness != "ok":
                        line = f"{line} · {completeness}: {all_gaps}"
                details.append(f"{label}: {line}")
                _record_warnings(evidence, details, manifest)
                for older in superseded.get(payload.path, []):
                    details.append(
                        f"{_payload_label(older)}: superseded by {payload.run_id} in this window; not applied"
                    )
                ran.append((source.row, unit.device, collector))
            _stopped(stop)
            if not joined:
                # The stale payloads still settle against the parent run.
                _settle_superseded(stale, prev)
                detail = "skipped: no parked payload this window could apply"
                if details:
                    detail += " · " + "; ".join(details)
                return RunOutcome(detail, [], None)
            # "fresh" names the sources this window collected from.
            for name in joined:
                statuses[name] = "partial" if name in failed else "fresh"
            for name in failed - joined:
                statuses[name] = "failed"
            _note_rechecks(evidence, prepared, prior)
            # Every source that contributed also needs the absent-only carry.
            carried = _carry_phase(s, prepared, statuses, joined, details, prev, cts, scopes, settings)
            summary = _finalize_cycle(
                s,
                settings,
                cts,
                prev,
                statuses,
                details,
                carried,
                assigned_sites,
                prepared=prepared,
                evidence=evidence,
                kind="device",
                head="device run",
                fence=fence,
                stop=stop,
            )
            # The payloads are settled only now, with the run published. A run that raised in a
            # derivation leaves every payload of its window parked, and the next
            # device run retries them.
            _settle_superseded(stale, prev)
            _settle_joined(joined_paths, cts)
            for path in joined_paths:
                _settle_superseded(superseded.get(path, []), cts)
            return RunOutcome(summary, ran, cts)


async def run_device_fetch(store: Store, settings: Settings, source: str, host: str) -> str:
    """One per-device collection, the whole pipeline of the `collect.fetch`
    job.

    The job builds the collector and fetches. The async transport fetches on
    the fetch loop of the process (`_fetch_loop`), and every other transport
    fetches on a thread. The job hashes twice. It skips when both hashes match
    the record and nothing of the device is parked. Otherwise it parks the
    payload, as an observation-only payload when only the observation hash
    moved. Then it records the attempt in `device_status` and the
    first-contact pin. The device run that loads the payload records the skip
    basis (`_record_graphs`).

    The payload is written to the raw store under a run id built from its own
    fetch time.

    A device failure is reported in the return detail and in `device_status`
    and is not raised."""
    row = await store.get_source(source)
    if row is None or not row.enabled:
        return f"skipped: source {source} is gone or disabled"
    context = await inventory_collection.execution_context(store)
    fleet = await store.list_devices(source)
    device = next((d for d in fleet if d.host == host), None)
    label = f"{source}/{host}" if device is not None else source
    if device is None and not host and sources_glue.is_group(row.type) and not row.config.get("host"):
        # The empty direct source. A group with no device row and no
        # implicit host has nothing to collect, and `_prepare_all`
        # already refuses it. A job for it is dropped here.
        return f"skipped: {source} has no enabled devices and no host"
    resolved: inventory_collection.ResolvedCollection | None = None
    if context.v2:
        # Resolver v2 uses the profile revision of the target, its pinned
        # credential version and the frozen normalization. The secrets of the
        # row are not read.
        try:
            async with store.inventory().transaction() as tx:
                resolver = inventory_collection.Resolver(
                    tx, settings, context=context, key=crypto.dek(settings)
                )
                resolved = await resolver.resolve(row, device=device, host=host, with_secrets=True)
        except inventory_collection.RepairRequired as exc:
            await _record_outcomes(store, [DeviceOutcome(source, host, False, error=str(exc))])
            return f"failed: {label}: {exc}"
        except inventory_collection.ResolutionError as exc:
            return f"failed: {label}: {exc}"
        except Exception as exc:
            return f"failed: {source}: {type(exc).__name__}: {exc}"
        secrets = dict(resolved.secrets)
        if not resolved.enabled:
            return f"skipped: {label}: {resolved.reason or 'disabled'}"
    else:
        try:
            secrets = FernetResolver(crypto.dek(settings)).resolve(row)
        except Exception as exc:
            # A group-level error. Bad secrets fail the source.
            return f"failed: {source}: {type(exc).__name__}: {exc}"

    async def fail(msg: str) -> str:
        await _record_outcomes(store, [DeviceOutcome(source, host, False, error=msg)], secrets)
        return sources_glue.redacted(f"failed: {label}: {msg}", secrets)

    if device is not None and not device.enabled:
        return f"skipped: {label} is disabled"
    sites = {site.code: site for site in await store.list_sites()}
    rows = {r.name: r for r in await store.list_sources()}
    # The fetch resolves no Device uid. The change hash reads the generation.
    identity = await sources_glue.StoreResolver.open(store)
    try:
        if device is not None:
            collector = sources_glue.build_device_collector(
                row, device, settings, sites=sites, sources=rows, effective=resolved, identity=identity
            )
        elif str(row.config.get("host") or "") == host:
            # The implicit single-host source. The device is the host of the config.
            collector = sources_glue.build_collector(
                row, settings, sites=sites, sources=rows, effective=resolved, identity=identity
            )
        else:
            return f"skipped: {source} has no device row {host!r} and no matching host"
    except Exception as exc:
        return await fail(f"{type(exc).__name__}: {exc}")

    t0 = time.monotonic()
    # The fetch window on the collector host clock, stamped as the fetch phase
    # of the cycle stamps it. It is the time the device was observed.
    fetch_started_ms = int(time.time() * 1000)
    trace: HttpTrace | None = None
    try:
        if _wants_loop(collector):
            raw = await _afetch_apart(collector)
        else:
            raw, trace = await asyncio.to_thread(fetch_traced, collector, source)
    except Exception as exc:
        return await fail(f"{type(exc).__name__}: {exc}")
    fetch_finished_ms = int(time.time() * 1000)
    fetch_ms = int((time.monotonic() - t0) * 1000)
    sha = await asyncio.to_thread(coll.raw_sha, collector, raw)
    obs = await asyncio.to_thread(coll.obs_sha, collector, raw)

    # The parked index is read before the status row. A payload that a device
    # run settled after this read has a park that cleared the raw hash (below),
    # unless that run has since recorded its basis.
    pending = await asyncio.to_thread(_parked_of, settings, source, host)
    prior = next((st for st in await store.list_device_status(source) if st.host == host), None)
    fingerprint = inventory_collection.fingerprint_for(resolved, sha)
    unchanged = (
        prior is not None
        and prior.last_raw_sha == fingerprint
        and prior.last_full_at is not None
        and time.time() - prior.last_full_at.timestamp() < settings.collect_full_interval_s
    )
    # The record is the basis of the last payload that a run loaded. A payload
    # of this device parked since then and not yet loaded is newer than the
    # record. A pending full payload forbids a skip on a match, because the
    # device run would apply that payload over a configuration that the device
    # has left again. A pending observation payload makes this fetch park its
    # own observations, which win over it in the window. An unreadable index
    # skips nothing.
    if pending is None or any(p.kind != rawstore.KIND_OBSERVATION for p in pending):
        unchanged = False
    # The same three-way decision as in the fetch phase of the cycle
    # (`_fetch_phase_async decide`). An unchanged configuration with changed
    # observations parks a payload that the device run applies as side tables only.
    observations_only = (
        unchanged
        and prior is not None
        and bool(obs)
        and ((bool(prior.last_obs_sha) and prior.last_obs_sha != obs) or bool(pending))
    )
    if unchanged and not observations_only:
        if trace is not None:
            trace.discard()  # nothing is parked
        # Record the attempt alone. The hashes matched the record, and writing
        # them back from outside the cycle lock could overwrite a basis that a
        # cycle or a device run recorded since this fetch read it. Also record
        # the check. The device was found equal to the basis on record in
        # everything that the hashes cover. Its observations count only when
        # their hash was compared or the collector declares none, as the cycle
        # counts it. The next device run publishes the check for the carried
        # device.
        await _record_outcomes(
            store,
            [
                DeviceOutcome(
                    source,
                    host,
                    True,
                    skipped=True,
                    verified=prior is not None and prior.last_obs_sha == obs,
                    checked_basis=(fingerprint, obs),
                    fetch_ms=fetch_ms,
                    fetch_started_ms=fetch_started_ms,
                    fetch_finished_ms=fetch_finished_ms,
                )
            ],
        )
        await pin_host_key(store, row, collector, device)
        return f"{label}: unchanged, not parked"

    # A payload identical to the newest parked payload of the device is not
    # parked again, as long as that payload is newer than the last load that the
    # record names. A cycle that loaded the device after the park left the parked
    # payload to be superseded by the window. A device back on that content has
    # to park anew.
    newest = max(pending, key=lambda p: p.fetch_ts_ms) if pending else None
    loaded_ms = max(_ms(prior.last_full_at), _ms(prior.last_graph_fetch_at)) if prior is not None else 0
    if (
        newest is not None
        and newest.fetch_ts_ms > loaded_ms
        and await asyncio.to_thread(_parked_same, collector, newest, fingerprint, obs, observations_only)
    ):
        if trace is not None:
            trace.discard()
        await _record_outcomes(store, [DeviceOutcome(source, host, True, skipped=True, fetch_ms=fetch_ms)])
        await pin_host_key(store, row, collector, device)
        return f"{label}: unchanged since {newest.path.name}, not parked again"

    try:
        # The kind is named only when it is not the default. An ordinary park
        # is a full payload. The trace is passed only when there is one. The
        # run id is built from the start of the fetch, as the spill of the
        # cycle builds it. `build_device_run` reads it back as the observation
        # time of the payload, which the park time would overstate. The end of
        # the fetch goes into the park sidecar, and the device run publishes
        # the whole window. The hashes go into the park sidecar for the
        # identical check above.
        park_kw: dict[str, Any] = {
            "source_name": source,
            "fetch_ts_ms": fetch_started_ms,
            "fetch_finished_ms": fetch_finished_ms,
            "hashes": {"fingerprint": fingerprint, "obs": obs},
            **_trace_kw(trace),
        }
        if observations_only:
            park_kw["kind"] = rawstore.KIND_OBSERVATION
        path = await asyncio.to_thread(lambda: coll.park(collector, raw, **park_kw))
    except Exception as exc:
        if trace is not None:
            trace.discard()
        return await fail(f"{type(exc).__name__}: {exc}")
    # Record the attempt and no basis. The skip basis (the two hashes and
    # `last_full_at`) describes what the graph holds. The graph holds this
    # payload only once a device run has loaded it. That run records the basis
    # (`_record_graphs`), as it records whether the graph was written. A basis
    # written here would let the next fetch or cycle skip against a payload
    # that no run has loaded. `load_ms` stays unset for the same reason.
    #
    # A full park clears the raw hash. An observation payload leaves it.
    await _record_outcomes(
        store,
        [
            DeviceOutcome(
                source,
                host,
                True,
                raw_sha=None if observations_only else "",
                observations_only=observations_only,
                fetch_ms=fetch_ms,
            )
        ],
    )
    await pin_host_key(store, row, collector, device)
    what = "parked observations" if observations_only else "parked"
    return sources_glue.redacted(f"{label}: {what} {path.name}", secrets)


_TASKS: set[asyncio.Task] = set()  # Strong references. asyncio keeps only weak ones.
# The runs that this process executes, by run id, with the task to cancel
# and the stop flag that its builder thread and collectors poll. A run on
# another pod is not here, and `cancel_run` answers False for it.
# `request_cancel` reaches it through a request file (core/run_cancel.py).
_RUNS: dict[int, tuple[asyncio.Task, RunStop]] = {}
# One watcher per run that this process executes. It polls for the cancel
# requests that another process writes for the run. The set holds strong
# references, as _TASKS does for the runs. A caller that waits on the runs
# in _TASKS never waits on these watchers.
_WATCHERS: set[asyncio.Task[None]] = set()
# How often a watcher looks for its run's cancel requests.
CANCEL_POLL_S = 2.0


def cancel_run(run_id: int, by: str = "operator", source: str | None = None) -> bool:
    """Stop a running run, or one source of it.

    With no `source`, raise the stop flag of the run and cancel the task that
    waits on it. The builder thread ends before the load of its next device or
    at its next phase boundary. A load in flight ends between its stages or
    before the next row group of the side table that it writes. A collector
    ends before its next request or command. `_drained` reclaims the thread,
    and the run row finishes as `cancelled`. Nothing that the run wrote is
    published, because every write of a run lands under its own collection_ts
    and the pointer never named it.

    With a `source`, raise the flag of that source alone. Its collectors end
    at their next request or command, its devices not loaded yet carry
    forward, and the rest of the cycle finishes and publishes. The run row is
    not cancelled, because the run collected everything that the operator
    left it. A refresh collects one source. A cancel of that source publishes
    nothing and finishes the row as `cancelled` (`execute_refresh`).

    Returns False in 3 cases. No run with this id executes in this process.
    The run executes and is not collecting that source, because a refresh
    collects only the source that it was pressed for and a device run is
    stopped only as a whole (`build_device_run`). The run is already built
    (`RunStop.built`), because the pointer names it or its builder has
    returned. Only its bookkeeping is then left, which runs to its end.
    """
    entry = _RUNS.get(run_id)
    if entry is None:
        return False
    task, stop = entry
    if stop.built:
        logger.info(
            "run %s: the cancel of %s arrived after the run was built; nothing is left to stop", run_id, by
        )
        return False
    if source is not None:
        if not stop.cancel_source(source):
            return False
        logger.info("run %s: source %s cancelled by %s", run_id, source, by)
        return True
    logger.info("run %s cancelled by %s", run_id, by)
    stop.set()
    task.cancel(f"cancelled by {by}")
    return True


def _built(run_id: int) -> bool:
    """Whether the run `run_id`, executing in this process, is already built
    (`RunStop.built`)."""
    entry = _RUNS.get(run_id)
    return entry is not None and entry[1].built


def _armed(run_id: int) -> bool:
    """Whether the run `run_id` has handed its collectors their stop flags
    (`RunStop.armed`). True for a run this process no longer executes, since
    nothing is left to wait for."""
    entry = _RUNS.get(run_id)
    return entry is None or entry[1].armed


async def _watch_cancel_requests(settings: Settings, run_id: int, started_at: datetime) -> None:
    """Act on the cancel requests other processes write for this run.

    Polls every CANCEL_POLL_S until cancelled, which `launch` does when the
    task of the run is done. A whole-run request cancels the run once. A
    source request raises the flag of that source. A source request that
    arrives before the run has handed its collectors their flags, as for a
    cycle that waits for the cycle lock, is kept and tried again at every
    poll. Only once the run is armed (`RunStop.armed`) does a source without a
    flag mean a source that the run is not collecting, and the request is then
    dropped. A failed poll is logged once and the polling goes on. A watcher
    never ends its run.
    """
    cancelled = warned = False
    waiting: dict[str, str] = {}
    while True:
        await asyncio.sleep(CANCEL_POLL_S)
        try:
            found = await asyncio.to_thread(run_cancel.take, settings, run_id, started_at)
            for req in found:
                if req.source is None:
                    if not cancelled:
                        cancelled = cancel_run(run_id, by=req.by)
                else:
                    waiting[req.source] = req.by
            for source, by in list(waiting.items()):
                # `armed` is read before the attempt. If the run was armed
                # then, every flag that the attempt looks for was handed out.
                armed = _armed(run_id)
                if cancel_run(run_id, by=by, source=source):
                    del waiting[source]
                elif armed:
                    del waiting[source]
                    logger.info(
                        "run %s: the cancel request of %s names %s, which this run is not collecting",
                        run_id,
                        by,
                        source,
                    )
        except Exception as exc:
            if not warned:
                warned = True
                logger.warning(
                    "run %s: its cancel requests could not be read (%s: %s)", run_id, type(exc).__name__, exc
                )


CancelAnswer = Literal[
    "cancelled", "requested", "not_running", "not_collecting", "not_collecting_here", "built"
]


async def request_cancel(
    store: Store, settings: Settings, run_id: int, *, by: str, source: str | None = None
) -> CancelAnswer:
    """Cancel a run, or one source of it, in whichever process executes it.

    A run that this process executes is cancelled at once (`cancel_run`).
    The answer is "cancelled", "not_collecting_here" when the run is not
    collecting `source`, or "built" when the run is already built and a cancel
    no longer changes it. A run executing elsewhere gets a request file
    (core/run_cancel.py), which its process takes within CANCEL_POLL_S. The
    answer is then "requested". The answer is "not_running" when no running
    row has this id, and when the row reads running with no run behind it,
    because its process is gone or it ended and its row could not be
    finished. The orphaned-run sweep closes such a row first, and no request
    is written that no process would take. The answer is "not_collecting"
    when `source` is neither the source of the run nor one with a progress
    record written since the run started. Raises OSError when the request
    cannot be written.
    """
    if run_id in _RUNS:
        if cancel_run(run_id, by=by, source=source):
            return "cancelled"
        return "built" if _built(run_id) else "not_collecting_here"
    row = await store.get_run(run_id)
    if row is None or row.status != "running":
        return "not_running"
    # The sweep takes a claim only where no process holds one. A live run
    # holds its claim from before its row is written until after it is
    # finished. The sweep closes nothing that still runs, here or elsewhere.
    if await store.reconcile_orphaned_runs(_now()):
        row = await store.get_run(run_id)
        if row is None or row.status != "running":
            return "not_running"
    if source is not None and source != row.source:
        progress = await asyncio.to_thread(
            read_progress, settings, source=source, since_ms=int(row.started_at.timestamp() * 1000)
        )
        if not progress:
            return "not_collecting"
    await asyncio.to_thread(run_cancel.request, settings, run_id, row.started_at, by=by, source=source)
    return "requested"


async def configured_secrets(store: Store, settings: Settings) -> list[str]:
    """The credential values the enabled sources are configured with, resolved
    as a run resolves them (`_prepare_all`). The last pass of a path that hands
    collected data to a reader removes them from what it hands over
    (`core/redaction.py redact_known`), whatever shape the data has."""
    _prepared, secrets = await _prepare_all(store, settings)
    return [value for value in secrets.values() if value]


async def _prepare_all(store: Store, settings: Settings) -> tuple[list[PreparedSource], dict[str, str]]:
    """Resolve enabled sources and retain disabled sources for carry-forward.
    Group-level failures (bad secrets, bad group config) become
    PreparedSource.error. The build failure of a single device becomes its
    PreparedDevice.error. One bad row fails one device and never the fleet or
    the run. The merged secrets dict feeds the redaction of the run detail.

    Under resolver v2 (`inventory_state`) every unit is resolved through
    `collection.Resolver` inside one repository transaction. The profile
    revision of the target, its credential version and the normalization are
    frozen here, once, for the whole run. In-flight jobs keep the
    configuration captured at start. A disabled inventory target is not a
    unit. An unreadable credential is a unit error that names the credential.
    A collector is never built with empty secrets."""
    context = await inventory_collection.execution_context(store)
    if context.v2:
        return await _prepare_all_v2(store, settings, context)
    prepared: list[PreparedSource] = []
    merged: dict[str, str] = {}
    fleets: dict[str, list[Device]] = {}
    sites = {site.code: site for site in await store.list_sites()}
    for d in await store.list_devices():
        fleets.setdefault(d.source, []).append(d)
    rows = await store.list_sources()
    # every row, enabled or not, because a source linked by name still holds its data
    by_name = {r.name: r for r in rows}
    for row in rows:
        if not row.enabled:
            prepared.append(PreparedSource(row, []))
            continue
        # Once-only backfill. Writes include these keys, with null for inherit.
        # A row without them has its effective values pinned before inheritance
        # applies.
        if "routing_scope" not in row.config or "l2fabric" not in row.config:

            def backfill(fresh: Source) -> Source | None:
                if "routing_scope" in fresh.config and "l2fabric" in fresh.config:
                    return None
                fresh.config.setdefault("routing_scope", sources_glue.backfill_routing_scope(fresh))
                fresh.config.setdefault("l2fabric", settings.l2fabric_of(fresh.name))
                return fresh

            updated = await store.modify_source(row.name, backfill)
            if updated is not None:
                row = updated
        try:
            merged.update(FernetResolver(crypto.dek(settings)).resolve(row))
        except Exception as exc:
            prepared.append(PreparedSource(row, [], f"{type(exc).__name__}: {exc}"))
            continue
        configured_fleet = fleets.get(row.name, [])
        fleet = [d for d in configured_fleet if d.enabled]
        if fleet:
            units = []
            for device in fleet:
                try:
                    collector = sources_glue.build_device_collector(
                        row, device, settings, sites=sites, sources=by_name
                    )
                    units.append(PreparedDevice(device, collector, None))
                except Exception as exc:
                    units.append(PreparedDevice(device, None, f"{type(exc).__name__}: {exc}"))
            prepared.append(
                PreparedSource(row, units, paused_hosts={d.host for d in configured_fleet if not d.enabled})
            )
        elif configured_fleet:
            prepared.append(PreparedSource(row, [], "no enabled devices"))
        elif sources_glue.is_group(row.type) and not row.config.get("host"):
            # A group whose whole fleet is disabled reads the same as a group
            # with no fleet. This source has nothing to collect.
            prepared.append(PreparedSource(row, [], "no enabled devices and no host"))
        else:
            try:
                # No site is chosen for an orchestrator. Its devices sit where
                # their reported locations are bound, which can be more than one
                # site. routing_scope and l2fabric resolve from the row and then
                # the application default.
                collector = sources_glue.build_collector(row, settings, sites=sites, sources=by_name)
                prepared.append(PreparedSource(row, [PreparedDevice(None, collector, None)]))
            except Exception as exc:
                prepared.append(PreparedSource(row, [], f"{type(exc).__name__}: {exc}"))
    return prepared, merged


async def _prepare_all_v2(
    store: Store, settings: Settings, context: inventory_collection.ExecutionContext
) -> tuple[list[PreparedSource], dict[str, str]]:
    """`_prepare_all` under resolver v2. The unit list has the same shape
    (fleet rows, else the implicit host, else the controller). The rest of the
    run does not know which resolver built its collectors."""
    prepared: list[PreparedSource] = []
    merged: dict[str, str] = {}
    fleets: dict[str, list[Device]] = {}
    sites = {site.code: site for site in await store.list_sites()}
    for d in await store.list_devices():
        fleets.setdefault(d.source, []).append(d)
    rows = await store.list_sources()
    by_name = {r.name: r for r in rows}
    key = crypto.dek(settings)
    async with store.inventory().transaction() as tx:
        resolver = inventory_collection.Resolver(tx, settings, context=context, key=key)

        ineligible: dict[str, str] = {}

        async def unit_for(row: Source, device: Device | None) -> PreparedDevice | None:
            """One resolved unit, or None for a target that the inventory has
            disabled. The reason of the resolver is kept for the source-level
            error."""
            try:
                resolved = await resolver.resolve(row, device=device, with_secrets=True, sites=sites)
            except inventory_collection.ResolutionError as exc:
                return PreparedDevice(device, None, str(exc))
            except Exception as exc:
                return PreparedDevice(device, None, f"{type(exc).__name__}: {exc}")
            if not resolved.enabled:
                ineligible[resolved.key.host] = resolved.reason or "disabled"
                return None
            merged.update(resolved.secrets)
            try:
                if device is not None:
                    collector = sources_glue.build_device_collector(
                        row, device, settings, sites=sites, sources=by_name, effective=resolved
                    )
                else:
                    collector = sources_glue.build_collector(
                        row, settings, sites=sites, sources=by_name, effective=resolved
                    )
            except Exception as exc:
                return PreparedDevice(device, None, f"{type(exc).__name__}: {exc}", resolved)
            return PreparedDevice(device, collector, None, resolved)

        for row in rows:
            if not row.enabled:
                prepared.append(PreparedSource(row, []))
                continue
            configured_fleet = fleets.get(row.name, [])
            fleet = [d for d in configured_fleet if d.enabled]
            ineligible.clear()
            if fleet:
                units = [u for u in [await unit_for(row, device) for device in fleet] if u is not None]
                if units:
                    prepared.append(PreparedSource(row, units))
                else:
                    # The inventory excluded every enabled device row. The
                    # error names the reasons of the inventory.
                    prepared.append(PreparedSource(row, [], _ineligible_detail(ineligible)))
            elif configured_fleet:
                prepared.append(PreparedSource(row, [], "no enabled devices"))
            elif sources_glue.is_group(row.type) and not row.config.get("host"):
                prepared.append(PreparedSource(row, [], "no enabled devices and no host"))
            else:
                unit = await unit_for(row, None)
                if unit is None:
                    prepared.append(PreparedSource(row, [], _ineligible_detail(ineligible)))
                elif unit.collector is None and unit.effective is None:
                    prepared.append(PreparedSource(row, [], unit.error))
                else:
                    prepared.append(PreparedSource(row, [unit]))
            prepared[-1].paused_hosts = {d.host for d in configured_fleet if not d.enabled} | {
                host
                for host, reason in ineligible.items()
                if reason in {"target disabled", "execution record disabled", "connection disabled"}
            }
        # The capture is read here, in the transaction that resolved the
        # units. A placement or intent write that lands after it cannot make
        # the placement revisions of the manifest disagree with the generation
        # of the units.
        capture = ExecutionCapture(context, await _placement_revisions(store, tx))
        for p in prepared:
            p.capture = capture
    return prepared, merged


def _ineligible_detail(reasons: Mapping[str, str]) -> str:
    """The source-level error for a fleet the inventory excluded entirely:
    each resolver reason with the number of targets it applied to."""
    if not reasons:
        return "no eligible targets in inventory"
    counts: dict[str, int] = {}
    for reason in reasons.values():
        counts[reason] = counts.get(reason, 0) + 1
    listed = ", ".join(f"{n} {reason}" for reason, n in sorted(counts.items()))
    return f"no eligible targets in inventory: {listed}"


async def _placement_revisions(store: Store, tx: InventoryTx) -> dict[str, int]:
    """The desired placement revision of every device uid the execution
    records know, as `tx` sees them. 0 for a device with no placement."""
    revisions: dict[str, int] = {}
    for uid in sorted({m.device_uid for m in await store.target_devices()}):
        device = await tx.get_device_by_graph_uid(uid)
        if device is None:
            continue
        placement = await tx.get_placement(device.id)
        revisions[uid] = placement.revision if placement is not None else 0
    return revisions


async def capture_execution(store: Store, prepared: list[PreparedSource] | None = None) -> ExecutionCapture:
    """What a run captures from the inventory before its build starts. That
    is the activation context (resolver version, intent generation) and the
    desired placement revision of every device uid that the execution records
    already know. Empty under v1 or without an inventory repository.

    A preparation under v2 holds the capture that it took in its own resolving
    transaction (`_prepare_all_v2`), and that capture is returned as is.
    Otherwise the context is taken from the prepared units when they hold one.
    The generation that the manifest records is then the generation that the
    units were resolved under, whatever intent write landed in between. The
    placement revisions are read afresh."""
    for p in prepared or ():
        if p.capture is not None:
            return p.capture
    context: inventory_collection.ExecutionContext | None = None
    for p in prepared or ():
        for unit in p.units:
            if unit.effective is not None:
                context = inventory_collection.ExecutionContext(
                    resolver_version=unit.effective.effective.resolver_version,
                    activated=True,
                    placement_generation=unit.effective.placement_generation,
                )
                break
        if context is not None:
            break
    if context is None:
        context = await inventory_collection.execution_context(store)
    if not context.activated or not inventory_collection.has_inventory(store):
        return ExecutionCapture(context)
    async with store.inventory().transaction() as tx:
        revisions = await _placement_revisions(store, tx)
    return ExecutionCapture(context, revisions)


async def _stage_results(
    store: Store,
    capture: ExecutionCapture,
    snapshot_key: int | None,
    prepared: list[PreparedSource],
    outcomes: list[DeviceOutcome],
    *,
    publish: bool = True,
) -> None:
    """The publication seam. It hands every target result of a published
    run to the observation service under the snapshot key of the run, then
    tells it that the pointer moved. Nothing is staged for a run that did not
    publish. A service failure is logged and does not fail the run."""
    if snapshot_key is None or not capture.context.activated or not inventory_collection.has_inventory(store):
        return
    from hst.app.inventory import observations as inventory_observations

    service = inventory_collection.observation_service(capture.context)
    by_key = {(o.source, o.host): o for o in outcomes}
    now = _now()
    try:
        async with store.inventory().transaction() as tx:
            if await tx.get_publication(str(snapshot_key)) is None:
                state = await tx.get_state()
                await tx.stage_publication(
                    str(snapshot_key), parent_snapshot_key=state.read_model_snapshot_key, now=now
                )
            for p in prepared:
                for unit in p.units:
                    key = _target_key(p.row.name, unit)
                    outcome = by_key.get((key.source, key.host))
                    if outcome is None:
                        continue
                    succeeded = outcome.ok
                    carried = outcome.skipped or outcome.observations_only
                    if succeeded and carried and getattr(unit.collector, "last_device_uids", None) is None:
                        # The device did not normalize in this run. It
                        # reports what the parent run holds, and the
                        # collector kept nothing to stage.
                        continue
                    authority = (
                        inventory_collection.authority_verdict(outcome.sections, outcome.authoritative)
                        if succeeded
                        else inventory_collection.Authority.PARTIAL
                    )
                    observed = inventory_collection.observed_devices(unit.collector) if succeeded else []
                    await service.stage_observations(
                        tx,
                        str(snapshot_key),
                        (key.source, key.host),
                        [
                            inventory_observations.ObservedDevice(
                                graph_uid=o.graph_uid,
                                hostname=o.hostname,
                                platform=o.platform,
                                management_address=o.management_address,
                                reported_location=(o.reported_location_id, o.reported_location_name)
                                if o.reported_location_id
                                else None,
                                warnings=tuple((o.notes or {}).get("warnings", ())),
                            )
                            for o in observed
                        ],
                        authority,
                        succeeded=succeeded,
                        attempted_at=now,
                    )
        if publish:
            await service.publish(str(snapshot_key))
    except Exception:
        if not publish:
            raise
        logger.exception("inventory observations for run %s were not staged:", snapshot_key)


async def _record_ran(
    store: Store,
    ran: list[tuple[Source, Device | None, Collector]],
    capture: ExecutionCapture,
    snapshot_key: int | None,
) -> None:
    """What a run records once its builder has returned, outside the cycle
    lock: the first-contact host-key pin of every device that connected, the
    devices each collector reported for its target, and the inventory
    publication of the run.

    The pointer already names the run. A store call that fails for one row is
    logged, and the other rows and the publication follow."""
    for ran_row, device, collector in ran:
        host = _status_host(PreparedDevice(device, collector, None))
        try:
            await pin_host_key(store, ran_row, collector, device)
        except Exception:
            logger.exception(
                "run %s: the host key of %s %s was not pinned:", snapshot_key, ran_row.name, host
            )
        if collector.last_device_uids is None:
            continue
        try:
            await store.record_target_devices(
                ran_row.name, host, collector.last_device_uids, collector.last_device_locations or {}
            )
        except Exception:
            logger.exception(
                "run %s: the devices of %s %s were not recorded:", snapshot_key, ran_row.name, host
            )
    await _publish_inventory(store, capture, snapshot_key)


async def _publish_inventory(store: Store, capture: ExecutionCapture, snapshot_key: int | None) -> None:
    if snapshot_key is None or not capture.context.activated:
        return
    try:
        await inventory_collection.observation_service(capture.context).publish(str(snapshot_key))
    except Exception:
        logger.exception("inventory publication %s awaits reconciliation", snapshot_key)


async def _effective_assignments(store: Store, prepared: list[PreparedSource]) -> dict[str, str | None]:
    """The UID-to-site intent map that the run materializes. It holds the
    site of each device that sits somewhere and None for each known device
    that does not.

    sources_glue.resolve_device_sites resolves it, as for the sites route.

    Every configured source takes part, also the sources that this run does
    not collect. A device run or a refresh carries the devices of the other
    sources forward, and a carried device must keep its LOCATED_IN edge. A
    prepared row stands in for the stored one, because it is the
    configuration that the run was built from.

    A device whose placement was removed (its location unbound, its hand
    placement cleared, the site of its group cleared) is named with None. A
    carried device keeps the site of its previous copy unless the run
    resolved it. A device left out of the map would keep the placement for
    good.
    """
    rows = {row.name: row for row in await store.list_sources()}
    rows.update({p.row.name: p.row for p in prepared})
    mappings = await store.target_devices()
    resolved = sources_glue.resolve_device_sites(
        await store.device_sites(),
        mappings,
        rows,
        {
            (loc.source, loc.location_id): loc.site
            for loc in await store.list_reported_locations()
            if loc.site
        },
    )
    out: dict[str, str | None] = {m.device_uid: None for m in mappings}
    out.update({uid: site for uid, (site, _origin) in resolved.items()})
    return out


async def _write_site_config(store: Store, settings: Settings) -> SiteConfig | None:
    """The site groups, the named blocks and the location countries the map projection of the run reads
    (hst/map/site_config.py). Returns the config read, None when the site parameters could not be
    read.

    A failure here leaves the file of the run before and never fails the run."""
    try:
        from hst.map import site_config
    except ImportError:
        return None
    try:
        sites = await store.list_sites()
        config = site_config.from_params(
            ((s.code, s.params or {}) for s in sites), locations={s.code: s.location for s in sites}
        )
    except Exception:
        logger.exception("the site parameters were not read: no device is stamped with a site block")
        return None
    try:
        await asyncio.to_thread(site_config.write, settings.sidestore_dir, config)
    except Exception:
        logger.exception("the map site config was not written")
    return config


# The run warning of a run whose read of the site parameters failed. Such a run stamps no device,
# and a device of zone `internet` reads as no edge of the estate in that run.
SITE_BLOCKS_UNREAD = (
    "site blocks: the site parameters could not be read; no device of this run is stamped with "
    "a site zone, so no device reads as an internet edge by its zone"
)


def _site_blocks(config: SiteConfig | None) -> dict[str, tuple[str, str | None]]:
    """Device uid to the name and zone of its named block, the stamp that a run writes on its
    Device nodes (`core/cycle.py apply_site_blocks`). The uids are the graph's `Device.uid`, as the
    map reads them (`map/tiers/fold.py`). The first block that names a uid wins
    (`site_config.from_params`). Empty when the site parameters could not be read, and the run then
    stamps no device."""
    if config is None:
        return {}
    return {uid: (block.name, block.zone) for uid, block in sorted(config.blocks.items())}


NO_SOURCES = "no sources are configured; nothing was collected and no run was published"
NO_ENABLED_SOURCES = "no source is enabled; nothing was collected and no run was published"


def _no_sources_detail(prepared: list[PreparedSource]) -> str:
    """The detail of a cycle with no enabled source, which publishes no run."""
    return NO_ENABLED_SOURCES if prepared else NO_SOURCES


async def _demo_applications(
    store: Store,
    settings: Settings,
    estate: demo_estate.DemoEstate,
    snapshot_key: int | None,
    actor_id: int | None,
    lines: list[str],
) -> None:
    """The applications of the demo estate imported and resolved at `snapshot_key`. The summary
    line is appended to `lines`."""
    if snapshot_key is None:
        lines.append("applications: not imported, no run was published")
        return
    lines.append(await demo_estate.import_applications(store, settings, estate.apps, snapshot_key, actor_id))


async def _abandon(store: Store, run: Run, exc: BaseException, secrets: dict[str, str]) -> None:
    """Finish the row of a claimed run that has no work task. `finish_run`
    releases the claim of the run."""
    if isinstance(exc, asyncio.CancelledError):
        status, detail = CANCELLED, str(exc) or "cancelled"
    else:
        status, detail = "error", f"{type(exc).__name__}: {exc}"
    try:
        await store.finish_run(run.id, status, _now(), sources_glue.redacted(detail, secrets))
    except Exception:
        logger.exception("finish_run failed for run %s (%s):", run.id, run.source)


async def launch(
    store: Store, settings: Settings, source: str, triggered_by: int | None = None
) -> Run | None:
    run: Run | None = None
    # `rawstore.parked` walks the raw store, so it runs off the loop
    if source == DEVICE_RUN and not await asyncio.to_thread(rawstore.parked, settings.raw_dir):
        return None
    demo = is_demo(settings, source)
    site_config = await _write_site_config(store, settings)
    if source == "reasoner" or demo:
        row: Source | None = None
        prepared: list[PreparedSource] = []
        secrets: dict[str, str] = {}
        fresh: set[str] = set()
    else:
        if source in ("cycle", DEVICE_RUN):
            row = None
        else:
            row = await store.get_source(source)
            if row is None:
                # deleted between the route's pre-check and here (race)
                return None
            if not row.enabled:
                # a paused source does not run
                return None
        prepared, secrets = await _prepare_all(store, settings)
        fresh = {p.row.name for p in prepared} if source == "cycle" else {source}
        if source == "cycle" and not any(p.row.enabled for p in prepared):
            # Nothing to collect. A run built now would hold no fresh source. With no source at all,
            # it would hold an empty graph that the pointer would name and every view would draw.
            run = await store.start_run(source, _now(), triggered_by)
            if run is None:
                return None
            await store.finish_run(run.id, "ok", _now(), _no_sources_detail(prepared))
            return run
        if row is not None:
            mine = next((p for p in prepared if p.row.name == source), None)
            if mine is not None and mine.error is not None:
                # The triggered source itself cannot run. The failure is recorded,
                # and no cycle starts that would carry everything and collect
                # nothing.
                run = await store.start_run(source, _now(), triggered_by)
                if run is None:
                    return None
                await store.finish_run(run.id, "error", _now(), mine.error)
                return run
    # Captured once, with the units resolved. Queued work resolves once
    # when claimed. The capture holds the resolver version and intent
    # generation that this run is built under, and the placement revisions
    # that it will publish.
    capture = await capture_execution(store, prepared)
    capture.site_blocks = _site_blocks(site_config)
    capture.site_blocks_warning = SITE_BLOCKS_UNREAD if site_config is None else None
    claimed: Run | None = None
    try:
        if source == DEVICE_RUN:
            # Decide no-work while holding the same estate-wide exclusion used by
            # builders, and claim the run before releasing it, so another device
            # builder cannot consume the checked window in between.
            async with store.cycle_lock():
                if not await asyncio.to_thread(rawstore.parked, settings.raw_dir):
                    return None
                claimed = await store.start_run(source, _now(), triggered_by)
        else:
            claimed = await store.start_run(source, _now(), triggered_by)
        if claimed is None:
            return None
        await _arm_identity(store, prepared, claimed.id)
    except BaseException as exc:
        if claimed is not None:
            await _abandon(store, claimed, exc, secrets)
        raise
    run = claimed

    # Set when the lock connection stops answering or an operator cancels the
    # run (`cancel_run`), and read from the builder thread before each device's
    # load and between phases, and by a collector between requests or
    # commands, between the stages of a load and before each row group of a
    # side table.
    stop = RunStop()

    async def work() -> None:
        snapshot_key: int | None = None
        if capture.context.activated:
            loop = asyncio.get_running_loop()

            async def prepare_publication(cts: int) -> Mapping[str, str | None]:
                await _stage_results(store, capture, cts, prepared, outs, publish=False)
                service = inventory_collection.observation_service(capture.context)
                placement = await service.compose_placements(str(cts))
                capture.context = replace(capture.context, placement_generation=placement.intent_generation)
                capture.placement_revisions = {
                    uid: int(value["revision"]) for uid, value in placement.placement_revisions.items()
                }
                return placement.site_assignments

            capture.before_finalize = lambda cts: asyncio.run_coroutine_threadsafe(
                prepare_publication(cts), loop
            ).result()
        try:
            status = "ok"
            if source == "reasoner":
                detail, _ = await asyncio.to_thread(execute_source, settings, source, row)
            elif demo:
                # The sites come first, because the map projection of each run reads them
                # (_write_site_config). The runs build under the cycle lock, as a cycle does. The
                # applications are resolved once the runs are published, at the last of them.
                root = demo_estate.folder(settings)
                if root is None:
                    raise RuntimeError("HST_DEMO_FIXTURES was unset while the run started")
                estate = await asyncio.to_thread(demo_estate.read, root)
                lines = [await demo_estate.seed_sites(store, settings, estate.sites, triggered_by)]
                # read after the seed, so the blocks of the sites it created are stamped
                demo_config = await _write_site_config(store, settings)
                blocks = _site_blocks(demo_config)
                if demo_config is None:
                    lines.append(f"warning: {SITE_BLOCKS_UNREAD}")
                async with store.cycle_lock(on_lost=stop.lose) as fence:
                    detail, ran, snapshot_key, status = await _drained(
                        stop, execute_demo, settings, estate.runs, fence=fence, stop=stop, site_blocks=blocks
                    )
                    stop.built = True
                await _settled(_demo_applications(store, settings, estate, snapshot_key, triggered_by, lines))
                detail = " · ".join([detail, *lines])
            elif source == "cycle":
                assigned = await _effective_assignments(store, prepared)
                outs: list[DeviceOutcome] = []
                # The lock is held across the whole collection, and a second
                # trigger waits for it. The pointer refuses a run built under an
                # older fence.
                #
                # The device statuses that the skip decisions compare are read,
                # and the statuses of this run are written, while the lock is
                # held. A run queued behind this one then decides against what
                # this one published. Once the builder has returned, the run is
                # built, and what is left runs to its end (`_settled`).
                async with store.cycle_lock(on_lost=stop.lose) as fence:
                    prior = {(st.source, st.host): st for st in await store.list_device_status()}
                    detail, ran, snapshot_key, status = await _drained(
                        stop,
                        execute_cycle,
                        settings,
                        prepared,
                        fresh,
                        assigned,
                        prior,
                        outs,
                        fence=fence,
                        stop=stop,
                        capture=capture,
                    )
                    stop.built = True
                    await _settled(_record_outcomes(store, outs, secrets))
                await _settled(_record_ran(store, ran, capture, snapshot_key))
            elif source == DEVICE_RUN:
                assigned = await _effective_assignments(store, prepared)
                outs = []
                # the statuses read and the digests written under the lock,
                # as a cycle's are
                async with store.cycle_lock(on_lost=stop.lose) as fence:
                    prior = {(st.source, st.host): st for st in await store.list_device_status()}
                    detail, ran, snapshot_key, status = await _drained(
                        stop,
                        build_device_run,
                        settings,
                        prepared,
                        assigned,
                        fence=fence,
                        stop=stop,
                        capture=capture,
                        outcomes=outs,
                        prior=prior,
                    )
                    stop.built = True
                    if snapshot_key is not None:
                        await _settled(_record_graphs(store, outs))
                await _settled(_record_ran(store, ran, capture, snapshot_key))
            else:
                # a source press builds its own run, kind "refresh", with every
                # other source carried forward
                assigned = await _effective_assignments(store, prepared)
                outs = []
                async with store.cycle_lock(on_lost=stop.lose) as fence:
                    detail, ran, snapshot_key, status = await _drained(
                        stop,
                        execute_refresh,
                        settings,
                        prepared,
                        source,
                        assigned,
                        fence=fence,
                        stop=stop,
                        capture=capture,
                        outcomes=outs,
                        concurrent=True,
                    )
                    stop.built = True
                    # Fetched as a cycle fetches. Each outcome holds the hashes of
                    # the payload and is recorded as the outcomes of a cycle are.
                    await _settled(_record_outcomes(store, outs, secrets))
                await _settled(_record_ran(store, ran, capture, snapshot_key))
        except asyncio.CancelledError as exc:
            # `cancel_run` stopped the run. `_drained` drained the builder
            # thread, and nothing that it wrote was published. The task goes
            # on to finish the row, and the cancellation is consumed here and
            # not re-raised. A run that the pointer already names keeps its
            # outcome. Only a process on its way out cancels the task once the
            # run is built, and the row still records what was published.
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
            if snapshot_key is None:
                status, detail = CANCELLED, str(exc) or "cancelled"
        except RunCancelled as exc:
            # The one source that a refresh collects was cancelled alone.
            # Nothing was published, and the row records the cancel of the operator.
            status, detail = CANCELLED, str(exc)
        except Exception as exc:
            status, detail = "error", f"{type(exc).__name__}: {exc}"
        detail = sources_glue.redacted(detail, secrets)
        try:
            await store.finish_run(
                run.id,
                status,
                _now(),
                detail,
                snapshot_key=str(snapshot_key) if snapshot_key is not None else None,
            )
        except Exception:
            # The claim is still released (finish_run closes it in its finally block).
            # The row reads 'running' until the next claim or boot sweep reconciles it.
            logger.exception("finish_run failed for run %s (%s):", run.id, source)

    task = asyncio.create_task(work())
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    _RUNS[run.id] = (task, stop)
    # The watcher ends when the run does.
    watcher = asyncio.create_task(_watch_cancel_requests(settings, run.id, run.started_at))
    _WATCHERS.add(watcher)
    watcher.add_done_callback(_WATCHERS.discard)

    def _forget(_task: asyncio.Task[None], run_id: int = run.id) -> None:
        _RUNS.pop(run_id, None)
        watcher.cancel()

    task.add_done_callback(_forget)
    return run


async def finished_row(store: Store, run: Run) -> Run:
    """The run's row as the store has it now, or `run` when it is not found."""
    return await store.get_run(run.id) or run


async def wait_for_run(store: Store, run: Run) -> Run:
    """Wait for a run that `launch` started in this process, and return its finished row.

    Only this run is waited for, and other runs in the process go on.
    Cancelling the wait cancels this run once. A run that is already stopping
    (a cancel request, a lost lock) is not cancelled again, because a second
    cancellation would cut its drain short and replace the outcome that the
    first one recorded. A run that is already built (`RunStop.built`) is not
    cancelled at all. The cancellation reaches the caller after the task of
    the run is done, or after DRAIN_TIMEOUT_S and FINISH_MARGIN_S have passed.
    A run that `launch` finished before returning (the triggered source could
    not run) has no task, and its row is returned as it is.
    """
    entry = _RUNS.get(run.id)
    if entry is not None:
        task, stop = entry
        try:
            await asyncio.wait({task})
        except asyncio.CancelledError as exc:
            if not stop.is_set() and not stop.built:
                stop.set()
                task.cancel(exc.args[0] if exc.args else None)
            await _outwait(task, DRAIN_TIMEOUT_S + FINISH_MARGIN_S)
            raise
    return await finished_row(store, run)


async def run_blocking(
    store: Store, settings: Settings, source: str, triggered_by: int | None = None
) -> Run | None:
    """Run `launch` without the background task. It starts the run, does the work and waits for it.

    It waits for its own run only (`wait_for_run`), and returns that run's finished
    row. A job body that calls it and is cancelled cancels that run and no other.

    Returns None when the source is unknown, disabled or already running, as
    `launch` does.
    """
    run = await launch(store, settings, source, triggered_by)
    if run is None:
        return None
    return await wait_for_run(store, run)
