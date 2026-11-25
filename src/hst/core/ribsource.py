"""Longest-prefix-match reader for the RIB side store. It answers the routing
lookups of the path engine (the longest-prefix match, and the overlapping-route
sweep that finds ECMP and backup routes) from RIBs held outside the graph.
sidestore.py writes the `rib` table and holds its schema.

When duckdb is not installed, or the side store has no `rib` data, every
lookup returns an empty result.

The reader selects its files in one of 2 modes. A reader bound to a published
snapshot (`for_snapshot`, with the `Snapshot` of the request and its manifest)
opens exactly the files that the manifest of the snapshot publishes, device by
device (`snapshot_evidence`). That list has no file of a run that failed after
it wrote its parquet file, and no file outside a published run. With no
manifest (a pin without a manifest, a fixture store, no pin at all), the reader
globs every file under `rib/` and picks, per device, the newest run at or
before the bound. That mode is `approximate`.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import threading
from collections.abc import Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .ipenc import addr_bytes
from .uid import slug

if TYPE_CHECKING:
    from .snapshot import Snapshot

_COLUMNS = "prefix, next_hop, next_hop_context_uid, interface, protocol, discard, metric, prefixlen, af"

# A run id is "<fetch_ts_ms>-<nonce>" (collectors/base.py:new_run_id). The
# pattern matches it at the start of the string or after a "-".
_RUN_TS = re.compile(r"(?:^|-)(\d+)-([0-9a-fA-F]{6,})$")


def run_ts(run_id: str) -> int | None:
    """The millisecond fetch timestamp in a run id, or None if the id does not
    parse. The stem of a side-store parquet file is a run id."""
    m = _RUN_TS.search(run_id)
    return int(m.group(1)) if m else None


# --- the evidence of a published snapshot for each device --------------------------------


@dataclass(frozen=True)
class DeviceEvidence:
    """The run, the outcome and the file of one device for one side-store
    table, from the manifest of the pinned snapshot. The table is `rib` for
    `RibSource`, or the table that a caller of `snapshot_evidence` passes.

    `source` and `host` are the slugged directory names of the store layout. A
    `DeviceEntry` holds the unslugged row name and host. A `FileEntry` and the
    files on disk hold the slugged names. `run_id` is the run that the device
    stands on in the snapshot. It is the run that collected the device, or
    `DeviceEntry.effective_run` for a carried or unchanged device.

    `outcome` is the `TableOutcome` status that the run recorded for the
    table. The statuses are `complete`, `complete-empty`, `unsupported`,
    `failed` and `partial`. The reader adds 3 values. `missing` means that the
    run recorded a file that is not on disk (retention, or a store moved away
    from its manifests). `unknown` means that the outcome of the run is
    recorded further back than `EVIDENCE_WALK_MAX` manifests. A copied file, if
    any, still selects its rows. None means that no manifest records an outcome
    for the device. `complete` selects a file, in `path`. `partial` selects a
    file when the run wrote one. Every other value selects no rows. `detail`
    holds the cause when the status does not show it.
    """

    source: str
    host: str
    run_id: str | None
    outcome: str | None
    path: Path | None = None
    detail: str = ""
    device_uids: tuple[str, ...] = ()


class _ManifestIndex:
    """The side-store files of one manifest by (table, run id), the run ids
    that it holds a file for, and the device entry that collected each run. The
    device entry is the first entry of the run that is not carried, in manifest
    order. `_Chain` keys the index on `id(record)`. `record` keeps the manifest
    alive for that time."""

    def __init__(self, record: Any) -> None:
        self.record = record
        self.run_ids: set[str | None] = set()
        # The run ids of the files that are not carried.
        self.own_runs: set[str | None] = set()
        self.files: dict[tuple[str, str | None], Any] = {}
        self.collected: dict[str | None, Any] = {}
        for f in record.files:
            self.run_ids.add(f.run_id)
            if not getattr(f, "carried", False):
                self.own_runs.add(f.run_id)
            if f.kind == "sidestore":
                self.files.setdefault((f.table, f.run_id), f)
        for d in record.devices:
            if not d.carried:
                self.collected.setdefault(d.effective_run, d)

    def table_file(self, run_id: str | None, table: str) -> Any:
        return self.files.get((table, run_id))


class _Chain:
    """The manifest chain from a snapshot back along `parent` links, each
    manifest read once. A missing or unreadable manifest ends the walk."""

    def __init__(self, settings: Any) -> None:
        self._settings = settings
        self._cache: dict[int, Any] = {}
        self._index: dict[int, _ManifestIndex] = {}

    def hold(self, key: int, record: Any) -> None:
        """Store a manifest that the caller has read as the manifest of `key`."""
        self._cache[key] = record

    def read(self, key: int) -> Any:
        if key not in self._cache:
            # The import is deferred. core/manifest.py imports `run_ts` from this module.
            from . import manifest as manifestmod

            try:
                self._cache[key] = manifestmod.read(self._settings, key)
            except (OSError, ValueError):
                self._cache[key] = None
        return self._cache[key]

    def index(self, record: Any) -> _ManifestIndex:
        """The `_ManifestIndex` of one manifest, built on the first call for that
        manifest."""
        found = self._index.get(id(record))
        if found is None:
            found = _ManifestIndex(record)
            self._index[id(record)] = found
        return found

    def walk(self, key: int | None) -> Iterator[Any]:
        seen: set[int] = set()
        while key is not None and key not in seen:
            seen.add(key)
            record = self.read(key)
            if record is None:
                return
            yield record
            key = record.parent


@dataclass
class SnapshotEvidence:
    """The side-store evidence of one published snapshot. `devices` holds the
    `DeviceEvidence` of each device of its manifest (`snapshot_evidence`).
    `chain` holds the manifests read so far. `RibSource.coverage` walks it to
    join a device with no file to its `device_uid`."""

    snapshot_key: int
    data_dir: Path
    devices: list[DeviceEvidence]
    chain: _Chain
    # The status that the pinned manifest records for the link-state database
    # of each context, by context uid (`manifest.ospf_context_key`). Only the
    # `ospf_lsdb` evidence holds it.
    contexts: dict[str, str] = field(default_factory=dict)
    _by_run: dict[str, DeviceEvidence] = field(init=False, default_factory=dict)
    _uid_files: dict[str, set[Path]] = field(init=False, default_factory=dict)
    _unlisted: set[Path] = field(init=False, default_factory=set)

    def __post_init__(self) -> None:
        for device in self.devices:
            if device.run_id is not None:
                self._by_run.setdefault(device.run_id, device)
            if device.path is None:
                continue
            if not device.device_uids:
                self._unlisted.add(device.path)
            for uid in device.device_uids:
                self._uid_files.setdefault(uid, set()).add(device.path)

    @property
    def files(self) -> list[Path]:
        """Every file the snapshot selects, each once, in path order."""
        return sorted({d.path for d in self.devices if d.path is not None})

    def by_run(self, run_id: str) -> DeviceEvidence | None:
        """The device standing on `run_id`, when the snapshot selects that run."""
        return self._by_run.get(run_id)

    def files_for(self, device_uids: Iterable[str]) -> list[Path]:
        """The files that can hold rows of `device_uids`, in path order. They are
        the files of the entries that record one of the uids, and the files of
        the entries that record no uid (a manifest without the field). A file
        of an entry with no uid can hold any device."""
        found = set(self._unlisted)
        for uid in device_uids:
            found |= self._uid_files.get(uid, set())
        return sorted(found)


def snapshot_evidence(
    settings: Any, cts: int | None, *, manifest: Any = None, table: str = "rib"
) -> SnapshotEvidence | None:
    """The side-store evidence of the snapshot pinned at `cts`. The result is
    None for no pin, for settings with no manifests directory (a fixture
    store), and for a key with no manifest file (a run without a manifest).

    The function reads the pinned manifest and resolves, for each device of
    the manifest, the run that answers for the device. A schema-version-2
    manifest holds the file entry of a carried device
    (`manifest.carried_entries`).

    `manifest` is the pinned manifest when the caller has read it.

    `table` is the side-store table of the evidence.
    """
    if cts is None:
        return None
    chain = _Chain(settings)
    if manifest is not None:
        chain.hold(cts, manifest)
        record: Any = manifest
    elif getattr(settings, "manifests_dir", None) is None:
        return None
    else:
        record = chain.read(cts)
    if record is None:
        return None
    # The import is deferred. core/manifest.py imports `run_ts` from this module.
    from . import manifest as manifestmod

    data_dir = Path(settings.hst_data_dir)
    store_dir = Path(settings.sidestore_dir)
    devices: list[DeviceEvidence] = []
    contexts: dict[str, str] = {}
    for entry in record.devices:
        evidence = _device_evidence(entry, record, chain, data_dir, store_dir, table)
        if evidence is not None:
            devices.append(evidence)
        if table == manifestmod.OSPF_LSDB_TABLE:
            for context_uid, outcome in manifestmod.ospf_context_outcomes(entry.tables).items():
                contexts[context_uid] = outcome.status
    return SnapshotEvidence(cts, data_dir, devices, chain, contexts)


def _device_evidence(
    entry: Any, record: Any, chain: _Chain, data_dir: Path, store_dir: Path, table: str = "rib"
) -> DeviceEvidence | None:
    """Resolve one `DeviceEntry` to the run and outcome that answer for it.

    A device that the run collected stands on its own outcome in
    `tables[table]` and on the file that the run published for it. A carried
    or unchanged device stands on the run in `effective_run`. The file is the
    entry of the pinned manifest for that run, where it has one. The outcome
    is read from the manifest whose device entry collected the run. When the
    pinned manifest holds the file and no manifest of the chain holds the
    outcome, the file answers. A device with no run yields None.
    """
    source, host = slug(entry.source), slug(entry.host)
    run_id = entry.effective_run
    uids = tuple(entry.device_uids)
    recorded = entry.tables.get(table)
    if recorded is not None and recorded.status != "unchanged":
        recorded_file = chain.index(record).table_file(run_id, table)
        return _resolve(
            source, host, run_id, recorded.status, recorded_file, data_dir, store_dir, table, uids
        )
    if run_id is None:
        return None
    pinned = chain.index(record).table_file(run_id, table)
    read = 0
    last: Any = None
    for held in islice(chain.walk(record.snapshot_key), EVIDENCE_WALK_MAX):
        read, last = read + 1, held
        held_index = chain.index(held)
        if run_id not in held_index.run_ids:
            continue
        collected = held_index.collected.get(run_id)
        if collected is None and (
            (held.snapshot_key == record.snapshot_key and pinned is not None)
            or run_id not in held_index.own_runs
        ):
            # The entry is a copy, in the pinned manifest or in a run that
            # carried the device. The walk continues to the manifest that
            # holds the outcome of the run.
            continue
        outcome = collected.tables.get(table) if collected is not None else None
        status = outcome.status if outcome is not None else None
        entry_for = pinned if pinned is not None else held_index.table_file(run_id, table)
        return _resolve(source, host, run_id, status, entry_for, data_dir, store_dir, table, uids)
    if read == EVIDENCE_WALK_MAX and last is not None and last.parent is not None:
        # The walk stopped at `EVIDENCE_WALK_MAX` before the end of the chain.
        # The outcome of the run is recorded further back and is `unknown`. A
        # copied file still answers with its rows.
        why = f"the outcome of run {run_id} is recorded beyond the {EVIDENCE_WALK_MAX} manifests read"
        if pinned is not None:
            found = _resolve(source, host, run_id, "complete", pinned, data_dir, store_dir, table, uids)
            return found if found.outcome != "complete" else replace(found, outcome="unknown", detail=why)
        return DeviceEvidence(source, host, run_id, "unknown", detail=why, device_uids=uids)
    if pinned is not None:
        return _resolve(source, host, run_id, None, pinned, data_dir, store_dir, table, uids)
    return DeviceEvidence(
        source, host, run_id, None, detail=f"no manifest in the chain holds run {run_id}", device_uids=uids
    )


def _resolve(
    source: str,
    host: str,
    run_id: str | None,
    status: str | None,
    entry: Any,
    data_dir: Path,
    store_dir: Path,
    table: str = "rib",
    uids: tuple[str, ...] = (),
) -> DeviceEvidence:
    """The evidence for a device that stands on `run_id`, from the status that
    the run recorded for `table` and the file entry that the run published for
    it. A file with no recorded status has the outcome `complete`. No status
    and no file selects no rows. A `partial` table with a file selects the file
    and keeps its status."""
    if status is None and entry is not None:
        status = "complete"
    if status == "partial" and entry is not None:
        found = _resolve(source, host, run_id, "complete", entry, data_dir, store_dir, table, uids)
        if found.outcome != "complete":
            return found
        return replace(found, outcome="partial")
    if status != "complete":
        return DeviceEvidence(source, host, run_id, status, device_uids=uids)
    if entry is None:
        return DeviceEvidence(
            source,
            host,
            run_id,
            "missing",
            detail=f"run {run_id} published no {table} file",
            device_uids=uids,
        )
    path = data_dir / entry.path
    if not _under(path, store_dir):
        return DeviceEvidence(
            source, host, run_id, "missing", detail=f"{entry.path} is outside the store", device_uids=uids
        )
    if not path.is_file():
        return DeviceEvidence(
            source, host, run_id, "missing", detail=f"{entry.path} is not on disk", device_uids=uids
        )
    return DeviceEvidence(source, host, run_id, "complete", path, device_uids=uids)


# The maximum count of manifests that `_device_evidence` reads, from the pinned
# manifest back, for the outcome of the run of a carried device. Beyond that
# count the outcome is `unknown`.
EVIDENCE_WALK_MAX = 32

# The maximum count of manifests that the join of a device with no recorded
# `device_uids` reads.
ORPHAN_WALK_MAX = 8

# The rank of an outcome when 2 source units list the same `Device.uid` (an
# inventory unit and the collector of the device). `recorded_orphans` keeps the
# outcome with the highest rank.
_OUTCOME_RANK = {"unsupported": 1, "complete-empty": 2, "missing": 3, "partial": 4, "failed": 5}


def recorded_orphans(
    devices: list[DeviceEvidence],
) -> tuple[dict[str, DeviceEvidence], list[DeviceEvidence]]:
    """The devices that the snapshot selects no file for, by the `device_uids`
    of their manifest entries, and the list of such devices whose entries
    record no uid (a manifest without the field). The reader joins the devices
    of the list through a bounded walk of the chain. A device with uids and no
    recorded outcome is left out."""
    index: dict[str, DeviceEvidence] = {}
    legacy: list[DeviceEvidence] = []
    for d in devices:
        if d.path is not None:
            continue
        if not d.device_uids:
            legacy.append(d)
            continue
        if d.outcome is None:
            continue
        for uid in d.device_uids:
            held = index.get(uid)
            if held is None or _OUTCOME_RANK.get(d.outcome, 0) > _OUTCOME_RANK.get(str(held.outcome), 0):
                index[uid] = d
    return index, legacy


def _under(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


# The count of rows that a reader fetches from DuckDB at a time (`RibSource._rows`).
FETCH_ROWS = 10_000


def _sql_str(value: str) -> str:
    """A SQL string literal. DuckDB binds no parameter into a file list."""
    return "'" + value.replace("'", "''") + "'"


def holds_parquet(directory: Path) -> bool:
    """Whether a side-store table directory holds a parquet file anywhere
    under it. DuckDB does not create a glob view over a directory without
    one."""
    return directory.is_dir() and next(directory.rglob("*.parquet"), None) is not None


def pick_run(snapshot_ts_by_run: dict[str, Any], as_of_ms: int | None) -> str | None:
    """The run a device answers from, among its runs and their snapshot_ts.

    With `as_of_ms`, only the runs with a snapshot_ts at or before it are
    candidates. A run with no snapshot_ts is then left out. The run with the
    newest snapshot_ts is picked. Among runs with the same snapshot_ts, the
    run with the latest fetch time in its id is picked. Every side-store
    reader that picks a run per device uses this rule.
    """
    run_ids = list(snapshot_ts_by_run)
    if as_of_ms is not None:
        run_ids = [
            rid for rid in run_ids if (snap := snapshot_ts_by_run[rid]) is not None and snap <= as_of_ms
        ]

    def _key(rid: str) -> tuple[int, int, int, str]:
        snap = snapshot_ts_by_run.get(rid)
        if snap is None:
            # A run with no snapshot_ts ranks below every run that has one.
            # The id string orders the runs with no snapshot_ts.
            return (0, 0, 0, rid)
        # Among runs with the same snapshot_ts, the run with the latest
        # fetch time in its id wins. A refresh or a per-device job can create
        # more than one run_id under one collection_ts. A run id that does
        # not parse ranks below the other runs with that snapshot_ts.
        fetch_ts = run_ts(rid)
        return (1, snap, fetch_ts if fetch_ts is not None else -1, rid)

    return max(run_ids, key=_key) if run_ids else None


@contextlib.contextmanager
def time_limit(con: Any, seconds: float | None) -> Iterator[None]:
    """Interrupt the statement that `con` runs inside the block once `seconds`
    have passed. DuckDB has no statement timeout. `interrupt` cancels the
    running statement, and the statement raises `duckdb.InterruptException`.
    The connection stays usable. There is no limit when `con` or `seconds` is
    None."""
    if con is None or seconds is None:
        yield
        return
    timer = threading.Timer(seconds, con.interrupt)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


# --- the reader -------------------------------------------------------------------------


class RibSource:
    """Read-only longest-prefix-match and overlap queries over the RIB
    side-store run of a device.

    The connection is the connection that sidestore.query() reads through
    (`sidestore.connect_reader`). It has a read_only catalog, external access
    locked to the store, and bounded memory, threads and spill. A TEMP view
    covers the parquet files. One connection is cached on the instance for
    every lpm()/overlapping() call.

    The view is built from the exact file list of a published snapshot when
    the instance has `evidence` (from `snapshot_evidence`), and from a glob of
    every file under `rib/` when it has none (`approximate`). In both modes the
    picked run id is cached per device_uid.
    """

    def __init__(
        self, base_dir: Path, *, as_of_ms: int | None = None, evidence: SnapshotEvidence | None = None
    ) -> None:
        # `as_of_ms` bounds the run selection for snapshot traces. Only runs
        # whose `snapshot_ts` column is at or before the bound are candidates.
        # None selects the newest run. `evidence` limits the files to the files
        # that the manifest of the pinned snapshot publishes.
        self._base_dir = Path(base_dir)
        self._as_of_ms = as_of_ms
        self._evidence = evidence
        self._con: Any = None
        self._unavailable = False
        self._has_view = False
        self._view_bound = False
        self._view_source = ""
        self._run_id_cache: dict[str, str | None] = {}
        self._orphans: dict[str, DeviceEvidence] | None = None

    def close(self) -> None:
        """Release the cached connection of the reader. A repeated close does nothing."""
        if self._con is not None:
            self._con.close()
            self._con = None
        self._has_view = False
        self._view_bound = False

    def _connect(self) -> Any:
        """The connection with the `rib` view bound. twin_tools/routing.py queries
        the view through it."""
        con = self._open()
        if con is not None:
            self._view()
        return con

    def _open(self) -> Any:
        """The connection, with the `rib` view declared but not bound."""
        if self._con is not None:
            return self._con
        if self._unavailable:
            return None

        rib_dir = self._base_dir / "rib"
        files = None if self._evidence is None else self._evidence.files
        present = holds_parquet(rib_dir) if files is None else self._base_dir.is_dir()
        if not present:
            self._unavailable = True
            return None

        try:
            # sidestore raises RuntimeError when pyarrow is not installed.
            from hst.core import sidestore
        except (ImportError, RuntimeError):
            self._unavailable = True
            return None
        try:
            # The connection is read-only, locked to base_dir and bounded in
            # memory, threads and spill. The view is TEMP. The read-only
            # catalog rejects CREATE.
            con = sidestore.connect_reader(self._base_dir)
        except ImportError:
            self._unavailable = True
            return None
        # With union_by_name, a file without the LPM columns has NULL in
        # those columns.
        if files is None:
            glob = _sql_str(f"{rib_dir.as_posix()}/**/*.parquet")
            source = f"read_parquet({glob}, union_by_name=true)"
        else:
            source = f"read_parquet([{', '.join(_sql_str(p.as_posix()) for p in files)}], union_by_name=true)"
        # The view is bound on its first use (`_view`). The binding reads the
        # footer of every file of the view. A lookup about a device whose
        # entry records its uids opens only the files of that device.
        if files is None or files:
            self._view_source = source
            self._has_view = True
        self._con = con
        return con

    def _view(self) -> str:
        """The name of the `rib` view over every selected file, bound on first use."""
        if self._has_view and not self._view_bound and self._con is not None:
            self._con.execute(f"CREATE TEMP VIEW rib AS SELECT * FROM {self._view_source}")  # noqa: S608
            self._view_bound = True
        return "rib"

    @property
    def available(self) -> bool:
        """Whether duckdb is importable and a store is present."""
        return self._open() is not None

    @property
    def approximate(self) -> bool:
        """Whether files are selected by age, with no published manifest.

        True for a pin with no manifest (a run without a manifest, a fixture
        store, no pin at all). The newest file at or before the bound then
        answers for each device. The run that wrote the file can be
        unpublished."""
        return self._evidence is None

    def has_rows(self, device_uid: str) -> bool:
        """Whether the store holds any run for this device within the bound."""
        con = self._open()
        return con is not None and self._latest_run_id(con, device_uid) is not None

    def coverage(self, device_uid: str) -> str | None:
        """The `DeviceEvidence.outcome` that the pinned snapshot recorded for the
        RIB table of the device. The values are `complete`, `complete-empty`,
        `failed`, `partial`, `missing` and `unknown` (the outcome of the run is
        recorded further back than `EVIDENCE_WALK_MAX` manifests). The result
        is None when no manifest records the device, and in approximate mode.
        """
        if self._evidence is None:
            return None
        con = self._open()
        if con is not None:
            run_id = self._latest_run_id(con, device_uid)
            if run_id is not None:
                selected = self._evidence.by_run(run_id)
                if selected is not None:
                    return selected.outcome
        found = self._orphans_by_device_uid().get(device_uid)
        return found.outcome if found is not None else None

    def _orphans_by_device_uid(self) -> dict[str, DeviceEvidence]:
        """The evidence by device_uid, for every device that the snapshot selects
        no file for. The manifest identifies a device by source and host. The
        rows identify it by `device_uid`. A device with no file in the snapshot
        is joined through the `device_uids` of its manifest entry. An entry
        that records none (a manifest without the field) is joined through the
        newest RIB file that its source and host published in the first
        `ORPHAN_WALK_MAX` manifests of the chain. Only the device uids of that
        file are read. The index is built once per instance, on the first
        lookup that finds no selected file."""
        if self._orphans is not None:
            return self._orphans
        evidence = self._evidence
        if evidence is None:
            self._orphans = {}
            return self._orphans
        index, legacy = recorded_orphans(evidence.devices)
        con = self._open() if legacy else None
        if con is not None:
            pending = {(d.source, d.host): d for d in legacy}
            for held in islice(evidence.chain.walk(evidence.snapshot_key), ORPHAN_WALK_MAX):
                if not pending:
                    break
                for f in held.files:
                    if f.kind != "sidestore" or f.table != "rib":
                        continue
                    device = pending.get((f.source, f.host))
                    if device is None:
                        continue
                    path = evidence.data_dir / f.path
                    if not _under(path, self._base_dir) or not path.is_file():
                        continue
                    for uid in self._device_uids(con, path):
                        index.setdefault(uid, device)
                    del pending[(f.source, f.host)]
        self._orphans = index
        return index

    def _device_uids(self, con: Any, path: Path) -> list[str]:
        rows = con.execute(
            f"SELECT DISTINCT device_uid FROM read_parquet({_sql_str(path.as_posix())})"  # noqa: S608
        ).fetchall()
        return [r[0] for r in rows if r[0] is not None]

    def _from(self, device_uids: Sequence[str]) -> str:
        """The relation that a query about `device_uids` reads. With evidence, the
        relation is the list of the files that can hold the rows of the devices
        (`files_for`). Without evidence, or when that list has every file of
        the evidence, the relation is the `rib` view."""
        if self._evidence is None or not self._has_view:
            return self._view()
        files = self._evidence.files_for(device_uids)
        if len(files) >= len(self._evidence.files):
            return self._view()
        if not files:
            return f"(SELECT * FROM {self._view()} WHERE false)"  # noqa: S608 - a fixed view name
        return f"read_parquet([{', '.join(_sql_str(p.as_posix()) for p in files)}], union_by_name=true)"

    def _latest_run_id(self, con: Any, device_uid: str) -> str | None:
        # The picked run is cached per device_uid for the life of the instance.
        if device_uid in self._run_id_cache:
            return self._run_id_cache[device_uid]
        if not self._has_view:
            # The pinned snapshot publishes no RIB file.
            self._run_id_cache[device_uid] = None
            return None

        # The run is selected by the `snapshot_ts` column, the joined
        # collection_ts of the run.
        rows = con.execute(
            f"SELECT run_id, max(snapshot_ts) FROM {self._from([device_uid])} "  # noqa: S608
            "WHERE device_uid = ? GROUP BY run_id",
            [device_uid],
        ).fetchall()
        picked = self._pick_run({r[0]: r[1] for r in rows if r[0] is not None})
        self._run_id_cache[device_uid] = picked
        return picked

    def _latest_run_ids(self, con: Any) -> dict[str, str]:
        """The run that each device of the view answers from, from one query.
        The result of each device is stored in the cache of `_latest_run_id`."""
        if not self._has_view:
            return {}
        self._view()
        rows = con.execute(
            "SELECT device_uid, run_id, max(snapshot_ts) FROM rib "
            "WHERE device_uid IS NOT NULL AND run_id IS NOT NULL GROUP BY device_uid, run_id"
        ).fetchall()
        by_device: dict[str, dict[str, Any]] = {}
        for device_uid, run_id, snapshot_ts in rows:
            by_device.setdefault(device_uid, {})[run_id] = snapshot_ts
        picked: dict[str, str] = {}
        for device_uid, snapshot_ts_by_run in by_device.items():
            run_id = self._pick_run(snapshot_ts_by_run)
            self._run_id_cache[device_uid] = run_id
            if run_id is not None:
                picked[device_uid] = run_id
        return picked

    def _pick_run(self, snapshot_ts_by_run: dict[str, Any]) -> str | None:
        """The run a device answers from, among its runs and their snapshot_ts
        (`pick_run`, bounded by this instance's `as_of_ms`)."""
        return pick_run(snapshot_ts_by_run, self._as_of_ms)

    def _rows(self, con: Any, sql: str, params: list) -> list[dict[str, Any]]:
        """The result as one dict per row, built `FETCH_ROWS` rows at a time."""
        cur = con.execute(sql, params)
        cols = [c[0] for c in cur.description]
        rows: list[dict[str, Any]] = []
        while batch := cur.fetchmany(FETCH_ROWS):
            rows.extend(dict(zip(cols, row, strict=True)) for row in batch)
        return rows

    def lpm(
        self, device_uid: str, context_uid: str | None, probe_ip: str, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        """The ECMP set of routes that match `probe_ip`. It is every row with the
        longest prefixlen among the routes of the latest run of the device and
        context that cover the address. The result is [] if no route covers
        it, the device has no rows, or the store is not queryable.

        `context_uid` is the uid of the owning VrfInstance. A row matches by
        its `context_uid`. A row whose `context_uid` is NULL matches by
        `legacy_vrf` against its `vrf` name column. Without `legacy_vrf`, SQL
        NULL is bound into that comparison, and no row matches by it.

        The rows are filtered to the address family of the probe. In the
        v4-mapped byte encoding, every v6 interval around ::ffff:0:0/96 covers
        every v4 address.
        """
        con = self._open()
        if con is None:
            return []
        run_id = self._latest_run_id(con, device_uid)
        if run_id is None:
            return []
        probe = addr_bytes(probe_ip)
        af = 6 if ":" in probe_ip else 4
        src = self._from([device_uid])
        return self._rows(
            con,
            f"SELECT {_COLUMNS} FROM {src} "  # noqa: S608
            "WHERE device_uid = ? AND (context_uid = ? OR (context_uid IS NULL AND vrf = ?)) "
            "AND run_id = ? AND af = ? "
            "AND lo IS NOT NULL AND lo <= ? AND ? <= hi "
            "AND prefixlen = ("
            f"  SELECT max(prefixlen) FROM {src} "
            "  WHERE device_uid = ? AND (context_uid = ? OR (context_uid IS NULL AND vrf = ?)) "
            "  AND run_id = ? AND af = ? "
            "  AND lo IS NOT NULL AND lo <= ? AND ? <= hi"
            ") "
            # equal-cost rows in one order on every read
            "ORDER BY prefix, next_hop, interface",
            [
                device_uid,
                context_uid,
                legacy_vrf,
                run_id,
                af,
                probe,
                probe,
                device_uid,
                context_uid,
                legacy_vrf,
                run_id,
                af,
                probe,
                probe,
            ],
        )

    def covering_lengths(
        self, tables: Sequence[tuple[str, str | None, str | None]], probe_ip: str
    ) -> dict[str, int]:
        """The prefixlen that `lpm` answers with for `probe_ip`, by context uid,
        for each (device uid, context uid, `legacy_vrf`) of `tables`. It is
        the longest prefixlen of the routes of the latest run of the device in
        that context that cover the address, with the context and family rules
        of `lpm`. A context with no covering route is absent. One statement
        reads every table (`trace.vrf_starts`)."""
        con = self._open()
        if con is None or not tables:
            return {}
        devices = sorted({device_uid for device_uid, _context, _vrf in tables})
        if any(d not in self._run_id_cache for d in devices):
            runs = self._latest_run_ids(con)
        else:
            runs = {d: r for d in devices if (r := self._run_id_cache[d]) is not None}
        devices = [d for d in devices if runs.get(d) is not None]
        if not devices:
            return {}
        probe = addr_bytes(probe_ip)
        af = 6 if ":" in probe_ip else 4
        rows = con.execute(
            f"SELECT device_uid, run_id, context_uid, vrf, max(prefixlen) FROM {self._from(devices)} "  # noqa: S608
            f"WHERE device_uid IN ({', '.join('?' for _ in devices)}) AND af = ? "
            "AND lo IS NOT NULL AND lo <= ? AND ? <= hi "
            "GROUP BY device_uid, run_id, context_uid, vrf",
            [*devices, af, probe, probe],
        ).fetchall()
        out: dict[str, int] = {}
        for device_uid, context_uid, legacy_vrf in tables:
            if context_uid is None:
                continue
            for dev, run_id, ctx, vrf, length in rows:
                if dev != device_uid or run_id != runs.get(device_uid) or length is None:
                    continue
                if ctx == context_uid or (ctx is None and legacy_vrf is not None and vrf == legacy_vrf):
                    out[context_uid] = max(out.get(context_uid, -1), int(length))
        return out

    def overlapping(
        self,
        device_uid: str,
        context_uid: str | None,
        lo: bytes,
        hi: bytes,
        min_prefixlen: int,
        af: int,
        *,
        legacy_vrf: str | None = None,
    ) -> list[dict[str, Any]]:
        """The rows of address family `af` from the latest run of the device and
        context whose [lo, hi] interval intersects the given [lo, hi] and whose
        prefixlen is greater than `min_prefixlen`. The result is [] under the
        same conditions as `lpm`.

        `context_uid` and `legacy_vrf` match as in `lpm`.
        """
        con = self._open()
        if con is None:
            return []
        run_id = self._latest_run_id(con, device_uid)
        if run_id is None:
            return []
        return self._rows(
            con,
            f"SELECT {_COLUMNS} FROM {self._from([device_uid])} "  # noqa: S608
            "WHERE device_uid = ? AND (context_uid = ? OR (context_uid IS NULL AND vrf = ?)) "
            "AND run_id = ? AND af = ? "
            "AND lo IS NOT NULL AND lo <= ? AND hi >= ? AND prefixlen > ? "
            "ORDER BY prefix, next_hop, interface",
            [device_uid, context_uid, legacy_vrf, run_id, af, hi, lo, min_prefixlen],
        )

    def routes(
        self, device_uid: str, context_uid: str | None, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        """Every row of the latest run of the device and context that has a next
        hop.

        `context_uid` and `legacy_vrf` match as in `lpm`. The result is []
        when the store is unavailable, the device is unknown, or no run is
        within the `as_of_ms` bound.
        """
        con = self._open()
        if con is None:
            return []
        run_id = self._latest_run_id(con, device_uid)
        if run_id is None:
            return []
        return self._rows(
            con,
            f"SELECT {_COLUMNS} FROM {self._from([device_uid])} "  # noqa: S608
            "WHERE device_uid = ? AND (context_uid = ? OR (context_uid IS NULL AND vrf = ?)) "
            "AND run_id = ? AND next_hop IS NOT NULL",
            [device_uid, context_uid, legacy_vrf, run_id],
        )

    def next_hop_context_consumers(
        self, context_uids: Collection[str]
    ) -> list[tuple[str, str | None, str | None]]:
        """(device_uid, context_uid, vrf) of every table that has a row with one
        of `context_uids` as its next-hop context, in the run that its device
        answers from. `vrf` is the VRF name column. It identifies the table of
        a row whose `context_uid` is NULL. The result is [] when the store
        is not queryable or `context_uids` is empty."""
        con = self._open()
        if con is None or not self._has_view or not context_uids:
            return []
        self._view()
        rows = con.execute(
            "SELECT DISTINCT device_uid, run_id, context_uid, vrf FROM rib "
            "WHERE device_uid IS NOT NULL AND list_contains(?, next_hop_context_uid)",
            [sorted({str(c) for c in context_uids})],
        ).fetchall()
        return sorted(
            {(r[0], r[2], r[3]) for r in rows if self._latest_run_id(con, r[0]) == r[1]},
            key=lambda t: tuple(str(x) for x in t),
        )

    def next_hop_values(self) -> set[str]:
        """The distinct next hops of the view, over every run in it, from one
        query. The caller tests them and reads the routes of the next hops that
        it keeps (`routes_matching`). `routes_matching` drops a next hop that
        only an older run holds."""
        con = self._open()
        if con is None or not self._has_view:
            return set()
        self._view()
        rows = con.execute("SELECT DISTINCT next_hop FROM rib WHERE next_hop IS NOT NULL").fetchall()
        return {r[0] for r in rows}

    def route_tables(self) -> set[tuple[str, str | None, str | None]]:
        """(device_uid, context_uid, vrf) of every table that holds a route with
        a prefix and a next hop in the run that its device answers from. `vrf`
        is the VRF name column. It identifies the table of a row whose
        `context_uid` is NULL."""
        con = self._open()
        if con is None or not self._has_view:
            return set()
        picked = self._latest_run_ids(con)
        self._view()
        rows = con.execute(
            "SELECT DISTINCT device_uid, run_id, context_uid, vrf FROM rib "
            "WHERE next_hop IS NOT NULL AND prefix IS NOT NULL"
        ).fetchall()
        return {(r[0], r[2], r[3]) for r in rows if picked.get(r[0]) == r[1]}

    def routes_matching(
        self, *, next_hops: Collection[str] | None = None, prefixes: Collection[str] | None = None
    ) -> list[tuple[str, str | None, str | None, dict[str, Any]]]:
        """The routes whose next hop is one of `next_hops` and whose prefix is
        one of `prefixes`, from the run that each device answers from
        (`_latest_run_ids`). A bound that is None is not applied. Each item is
        (device_uid, context_uid, vrf, row), and the row has the columns of a
        `routes` row. With no bound the result is every route with a next
        hop."""
        con = self._open()
        if (
            con is None
            or not self._has_view
            or not (next_hops is None or next_hops)
            or not (prefixes is None or prefixes)
        ):
            return []
        picked = self._latest_run_ids(con)
        where = "next_hop IS NOT NULL"
        params: list[Any] = []
        if next_hops is not None:
            where += " AND list_contains(?, next_hop)"
            params.append(list(next_hops))
        if prefixes is not None:
            where += " AND list_contains(?, prefix)"
            params.append(list(prefixes))
        self._view()
        cur = con.execute(
            f"SELECT device_uid, run_id, context_uid, vrf, {_COLUMNS} FROM rib WHERE {where}",  # noqa: S608
            params,
        )
        cols = [c[0] for c in cur.description][4:]
        out: list[tuple[str, str | None, str | None, dict[str, Any]]] = []
        while batch := cur.fetchmany(FETCH_ROWS):
            out.extend(
                (row[0], row[2], row[3], dict(zip(cols, row[4:], strict=True)))
                for row in batch
                if picked.get(row[0]) == row[1]
            )
        return out

    def route_page(
        self,
        device_uid: str,
        context_uid: str | None = None,
        *,
        legacy_vrf: str | None = None,
        address: str | None = None,
        prefix_text: str | None = None,
        protocol: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> RoutePage:
        """One page of the route table of a device, or of one of its contexts,
        from the run the snapshot selects for the device.

        Without `context_uid`, the rows of every context of the device are
        read, and each row holds its context. With it, rows match as in `lpm`.
        `address` keeps the routes of its family that cover it, longest prefix
        first. The first rows are the rows that `lpm` answers with. `longest`
        of a row is true when the row is at the longest covering prefix of its
        own table. The text filter and the protocol filter do not change
        `longest`. `prefix_text` keeps the prefixes that contain the text.
        `protocol` keeps one protocol ("" is a row with none). The protocol
        counts apply every filter except the protocol filter. The page is
        empty under the same conditions as `lpm`.
        """
        con = self._open()
        run_id = self._latest_run_id(con, device_uid) if con is not None else None
        if con is None or run_id is None:
            return RoutePage(total=0, rows=[], protocols=[], run_id=None)
        src = self._from([device_uid])
        where = ["device_uid = ?", "run_id = ?"]
        params: list[Any] = [device_uid, run_id]
        if context_uid is not None:
            where.append("(context_uid = ? OR (context_uid IS NULL AND vrf = ?))")
            params += [context_uid, legacy_vrf]
        if address:
            probe = addr_bytes(address)
            where.append("af = ? AND lo IS NOT NULL AND lo <= ? AND ? <= hi")
            params += [6 if ":" in address else 4, probe, probe]
        # the longest covering prefix of each routing table, before the text
        # and protocol filters
        best: dict[str, int] = {}
        if address:
            best = {
                str(r["ctx"]): int(r["best"])
                for r in self._rows(
                    con,
                    f"SELECT coalesce(context_uid, vrf, '') AS ctx, max(prefixlen) AS best FROM {src} "  # noqa: S608
                    f"WHERE {' AND '.join(where)} GROUP BY 1",
                    list(params),
                )
                if r["best"] is not None
            }
        if prefix_text:
            escaped = prefix_text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("prefix ILIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        facet_where = " AND ".join(where)
        protocols = self._rows(
            con,
            f"SELECT coalesce(protocol, '') AS protocol, count(*) AS count FROM {src} "  # noqa: S608
            f"WHERE {facet_where} GROUP BY 1 ORDER BY count DESC, protocol",
            params,
        )
        if protocol is not None:
            where.append("coalesce(protocol, '') = ?")
            params.append(protocol)
        clause = " AND ".join(where)
        total = con.execute(f"SELECT count(*) FROM {src} WHERE {clause}", params).fetchone()[0]  # noqa: S608
        # The order is total over every column of a row. Pages read with
        # different offsets share no row and skip no row. Rows of 2 contexts
        # with the same prefix and next hop tie without the tie keys. DuckDB
        # does not keep the order of tied rows from one query to the next.
        ties = (
            "coalesce(context_uid, vrf), vrf, context_uid, interface, protocol, discard, "
            "metric, next_hop_context_uid, prefix"
        )
        order = "prefixlen DESC, lo, next_hop" if address else "af, lo, prefixlen, next_hop"
        order = f"{order} NULLS LAST, {ties}"
        rows = self._rows(
            con,
            f"SELECT vrf, context_uid, {_COLUMNS} FROM {src} WHERE {clause} "  # noqa: S608
            f"ORDER BY {order} NULLS LAST LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        if address:
            for row in rows:
                ctx = str(row.get("context_uid") or row.get("vrf") or "")
                row["longest"] = row.get("prefixlen") is not None and best.get(ctx) == row["prefixlen"]
        return RoutePage(total=total, rows=rows, protocols=protocols, run_id=run_id)

    def search_routes(
        self, text: str, *, limit: int = 200, row_cap: int | None = None, timeout_s: float | None = None
    ) -> RoutePage:
        """The routes of every device that answer for `text`. Each device is read
        from the run that the snapshot selects for it.

        For an address, the result has the longest-prefix match of each routing
        table and the routes whose network is the address. For a prefix, the
        result has the routes for exactly that prefix. The other covering
        routes are left out. Rows are ordered longest prefix first, then by
        device. The page is empty when the store is not queryable or the text
        is neither an address nor a prefix.

        `row_cap` bounds the rows that each statement returns (longest prefix
        first). `timeout_s` bounds the time of the whole lookup before DuckDB
        interrupts it (`time_limit`). A search across every device sets both.
        """
        empty = RoutePage(total=0, rows=[], protocols=[], run_id=None)
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return empty
        con = self._open()
        with time_limit(con, timeout_s):
            return (
                self._search_routes(con, text, net, limit=limit, row_cap=row_cap)
                if con is not None
                else empty
            )

    def _search_routes(
        self,
        con: Any,
        text: str,
        net: ipaddress.IPv4Network | ipaddress.IPv6Network,
        *,
        limit: int,
        row_cap: int | None,
    ) -> RoutePage:
        picked = self._latest_run_ids(con)
        if not picked:
            return RoutePage(total=0, rows=[], protocols=[], run_id=None)
        keys = [f"{device}\x1f{run}" for device, run in picked.items()]
        marks = ",".join("?" * len(keys))
        current = f"device_uid || chr(31) || run_id IN ({marks})"
        columns = f"device_uid, vrf, context_uid, {_COLUMNS}"
        capped = "" if row_cap is None else f" ORDER BY prefixlen DESC, device_uid LIMIT {int(row_cap)}"
        if "/" in text:
            rows = self._rows(
                con,
                f"SELECT {columns} FROM rib WHERE {current} AND prefix = ?{capped}",  # noqa: S608
                [*keys, str(net)],
            )
        else:
            probe = addr_bytes(str(net.network_address))
            matches = self._rows(
                con,
                f"SELECT {columns} FROM ("  # noqa: S608
                "SELECT *, max(prefixlen) OVER (PARTITION BY device_uid, coalesce(context_uid, vrf)) AS best "
                f"FROM rib WHERE {current} AND af = ? AND lo IS NOT NULL AND lo <= ? AND ? <= hi"
                f") WHERE prefixlen = best{capped}",
                [*keys, net.version, probe, probe],
            )
            networks = self._rows(
                con,
                f"SELECT {columns} FROM rib WHERE {current} AND prefix LIKE ?{capped}",  # noqa: S608
                [*keys, f"{net.network_address}/%"],
            )
            seen: set[tuple[Any, ...]] = set()
            rows = []
            for row in [*matches, *networks]:
                key = (
                    row["device_uid"],
                    row["context_uid"],
                    row["vrf"],
                    row["prefix"],
                    row["next_hop"],
                    row["interface"],
                )
                if key not in seen:
                    seen.add(key)
                    rows.append(row)
        rows.sort(key=lambda r: (-(r["prefixlen"] or 0), r["device_uid"], r["context_uid"] or r["vrf"] or ""))
        return RoutePage(total=len(rows), rows=rows[:limit], protocols=[], run_id=None)


@dataclass
class RoutePage:
    """A page of routes (`RibSource.route_page`). It holds the rows, the count
    of all matching rows, the protocol counts and the run of the rows."""

    total: int
    rows: list[dict[str, Any]]
    protocols: list[dict[str, Any]]
    run_id: str | None


def for_snapshot(snapshot: Snapshot) -> RibSource:
    """The RibSource of every trace caller. It is bounded to the run of the
    pinned graph session of the caller. It reads exactly the files that the
    manifest of that run publishes (`snapshot_evidence`). When the run has no
    manifest, it reads the newest file at or before the bound (`approximate`).
    """
    record = snapshot.manifest
    evidence = (
        None
        if record is None
        else snapshot.evidence(
            "rib", lambda: snapshot_evidence(snapshot.settings, snapshot.cts, manifest=record)
        )
    )
    return RibSource(snapshot.settings.sidestore_dir, as_of_ms=snapshot.cts, evidence=evidence)
