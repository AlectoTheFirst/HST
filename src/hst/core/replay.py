"""Point-in-time reconstruction, by replaying raw snapshots."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from . import manifest as manifestmod
from . import rawstore
from .config import Settings
from .loader import load
from .model import RunManifest
from .rawstore import SUFFIX, read
from .uid import slug

# A run id has the form `<epoch_ms>-<nonce>`. `collectors.base.new_run_id`
# builds it. The raw store and the manifests read it. A run id has no collector
# name and no source segment. `list_snapshots` takes the source from the
# directory of the raw file.
RUN_ID = rawstore._RUN_ID


@dataclass(frozen=True)
class Snapshot:
    source: str
    host: str
    run_id: str
    ts_ms: int
    path: Path

    @property
    def taken_at(self) -> datetime:
        return datetime.fromtimestamp(self.ts_ms / 1000, UTC)


@dataclass
class RebuildReport:
    as_of_ms: int
    replayed: list[Snapshot] = field(default_factory=list)
    manifests: list[RunManifest] = field(default_factory=list)
    # The (source, host) pairs with no snapshot at or before `as_of_ms`. A label is
    # "source" for a source directory without hosts and "source/host" for a host
    # directory.
    missing: list[str] = field(default_factory=list)
    # (label, reason) for each snapshot that could not be replayed. The label has
    # the form of a `missing` entry.
    failed: list[tuple[str, str]] = field(default_factory=list)
    # The lines that the finalization stages of core/finalize.py reported. The
    # list is empty on a dry run and when nothing was replayed.
    derived: list[str] = field(default_factory=list)
    # The count of nodes removed from the target before replay. It is 0 on a dry run
    # and for an empty target.
    cleared: int = 0

    @property
    def ok(self) -> bool:
        return not self.missing and not self.failed


def parse_run_id(name: str) -> int | None:
    """The epoch milliseconds of a run id, or None if the id does not parse.
    `1784527461005-b3054969` gives 1784527461005.

    An id with a collector name or a source segment does not parse.
    """
    m = RUN_ID.match(name)
    return int(m["ts"]) if m else None


def list_snapshots(raw_dir: Path) -> dict[str, list[Snapshot]]:
    """Every readable snapshot, newest first, grouped by source directory.

    The source is the name of the directory that `rawstore.write` wrote under.
    The scan reads the files directly under each source directory and the files
    of each `<host>/` subdirectory. Each `Snapshot` holds the host of its
    directory. The host is "" for a file directly under the source directory (a
    controller-type source with no device concept) and the name of the
    subdirectory otherwise. The dict has one entry per source directory.
    """
    out: dict[str, list[Snapshot]] = {}
    if not raw_dir.is_dir():
        return out
    for source_dir in sorted(p for p in raw_dir.iterdir() if p.is_dir()):
        found: list[Snapshot] = []
        leaves = [(source_dir, "")] + [(p, p.name) for p in sorted(source_dir.iterdir()) if p.is_dir()]
        for leaf_dir, host in leaves:
            for path in sorted(leaf_dir.glob(f"*{SUFFIX}")):
                run_id = path.name[: -len(SUFFIX)]
                ts = parse_run_id(run_id)
                if ts is not None:
                    found.append(Snapshot(source_dir.name, host, run_id, ts, path))
        if found:
            out[source_dir.name] = sorted(found, key=lambda s: s.ts_ms, reverse=True)
    return out


def plan(raw_dir: Path, as_of_ms: int) -> tuple[list[Snapshot], list[str]]:
    """The newest snapshot per (source, host) at or before `as_of_ms`, and the
    (source, host) pairs with none.

    `list_snapshots` returns the snapshots of every host of a source directory
    in one list (the `<source>/<host>/<run_id>` layout). `plan` groups them by
    host. The snapshots of each host keep the newest-first order of
    `list_snapshots`. A source without hosts (controller type) is reported
    missing as its source name. A host of a per-device source with no eligible
    snapshot is reported as "<source>/<host>".

    Returns (selected, missing). Selected is ordered oldest-first.
    """
    selected: list[Snapshot] = []
    missing: list[str] = []
    for source, snaps in list_snapshots(raw_dir).items():
        by_host: dict[str, list[Snapshot]] = {}
        for snap in snaps:
            by_host.setdefault(snap.host, []).append(snap)
        for host, host_snaps in sorted(by_host.items()):
            eligible = [s for s in host_snaps if s.ts_ms <= as_of_ms]
            if eligible:
                selected.append(eligible[0])  # host_snaps is newest-first
            else:
                missing.append(source if not host else f"{source}/{host}")
    return sorted(selected, key=lambda s: s.ts_ms), sorted(missing)


def _publish(
    settings: Settings,
    target: Any,
    cts: int,
    *,
    reprocessed_from: int | None,
    manifests: list[RunManifest],
    ok: bool,
    exact_counts: tuple[int, int] | None = None,
    exact_record: manifestmod.SnapshotManifest | None = None,
) -> None:
    """Write the meta node of the rebuilt run, then move the pointer to it.

    A rebuilt target answers its run status from the meta node
    (`core/cycle.py run_status` reads it). The status shows the run that a
    repair target is pinned to and whether the reconstruction was complete. An
    exact archive restore uses `exact_record` to reproduce the source statuses,
    the parent, the kind, the degradation and the manifest digest of the
    collection. Its meta node has no reprocessing marker and no identity of the
    current build.

    A raw replay has no exact record. Its statuses are empty. Its meta node
    holds the version and the revision of the current build. `reprocessed_from`
    is the snapshot key of a manifest replay through the current normalizer and
    reasoners. `nodes` and `rels` count the records of the exact versioned
    archive or the load manifests of the raw replay.
    """
    from hst import __version__

    from . import cycle as cyclemod

    statuses = {} if exact_record is None else {source.name: source.status for source in exact_record.sources}
    cyclemod.write_cycle_meta(
        target,
        cts,
        statuses=statuses,
        carried_from=(
            exact_record.parent
            if exact_record is not None and any(device.carried for device in exact_record.devices)
            else None
        ),
        nodes=exact_counts[0] if exact_counts is not None else sum(m.nodes_upserted for m in manifests),
        rels=exact_counts[1] if exact_counts is not None else sum(m.rels_upserted for m in manifests),
        degraded=(
            not ok
            if exact_record is None
            else any(device.outcome in {"failed", "partial"} for device in exact_record.devices)
        ),
        kind="full" if exact_record is None else exact_record.kind,
        parent=None if exact_record is None else exact_record.parent,
        manifest_digest=(
            None if exact_record is None else manifestmod.digest_of(settings, exact_record.snapshot_key)
        ),
        reprocessed_from=reprocessed_from,
        app_version=__version__ if exact_record is None else None,
        build_revision=settings.hst_build_revision if exact_record is None else None,
    )
    cyclemod.set_pointer(target, cts)


# One batch per statement keeps a large scratch graph under the transaction memory
# ceiling.
_CLEAR_BATCH = "MATCH (n) WITH n LIMIT $batch DETACH DELETE n RETURN count(n) AS c"


def _clear_target(target: Any, batch: int = 10_000) -> int:
    """Delete every node (and its relationships) from the target, batched. Returns the
    total removed."""
    total = 0
    while True:
        rows = target.execute_write(lambda tx: tx.run(_CLEAR_BATCH, batch=batch).data())
        deleted = rows[0]["c"] if rows else 0
        total += deleted
        if deleted < batch:
            return total


def _release_payload(collector: Any) -> None:
    """Drop the per-payload caches of a collector that has finished one
    snapshot (`Collector.release_payload`). The method is read with `getattr`.
    An injected collector without the method releases nothing."""
    fn = getattr(collector, "release_payload", None)
    if callable(fn):
        fn()


def device_collector(collector: Any, host: str, *, slugged: bool = False) -> Any:
    """The collector that normalizes one device of a source, built from the
    collector of the source as the cycle builds it.

    The cycle builds the collector of a fleet device from the configuration of
    its group with the host, the port and the pinned host key of the device
    (`app/sources.py build_device_collector`). Normalization reads only the
    host of these 3 values. `device_collector` returns `collector` when its
    configuration has this host. Otherwise it returns a collector of the same
    class over the same configuration with `host` as the host. The new
    collector shares the device identity registry of the source
    (`Collector.identity`). The device resolves to the same uid with both
    collectors.

    The retirement scope of a collector, and the registry ref of a device that
    reports no serial, follow the host of its configuration (`collectors/cli_collector.py`
    `SshCliCollector.__init__`). A collector whose configuration has no host
    field is returned unchanged.

    `host` is the host of the device, as a manifest records it. With `slugged`,
    `host` is the name of the host directory of a raw file. `rawstore.write`
    builds that name with `uid.slug`, and the collector is built with it. A
    host that `uid.slug` changes (upper case, the colons of an IPv6 address)
    cannot be recovered from its directory. A caller that has the host of the
    device builds the collector from that host (`device_collector_for` of
    `rebuild`).
    """
    config = getattr(collector, "config", None)
    if not isinstance(config, BaseModel) or "host" not in type(config).model_fields:
        return collector
    own = str(getattr(config, "host", "") or "")
    if (slug(own) if slugged else own) == host:
        return collector
    built = type(collector)(config.model_copy(update={"host": host}), collector.settings)
    if hasattr(collector, "identity"):
        built.identity = collector.identity
    return built


def rebuild(
    settings: Settings,
    target: Any,
    as_of_ms: int,
    *,
    collector_for: Any,
    device_collector_for: Callable[[str, str], Any | None] | None = None,
    dry_run: bool = False,
) -> RebuildReport:
    """Replay into `target` (an open session on a scratch database).

    `collector_for(source)` returns the collector of that source, or None when that
    source is not configured.

    Every device of a fleet replays under its own scope, as the cycle loads it.
    `device_collector_for(source, host)`, when given, returns the collector of the
    configured device whose raw files are under that source directory and host
    directory, or None when no configured device has that host. Both names have the
    form that `rawstore.write` gives them. The collector is built as the cycle builds
    it (`app/sources.py build_device_collector`). When `device_collector_for` is not
    given or returns None, the snapshot is normalized by the collector of its source,
    built for the name of its host directory (`device_collector`). That name is the
    slugged host of the device.

    The target is wiped before replay. The caller guards the target (the CLI refuses
    the live twin via `same_endpoint`).

    Every load shares one `collection_ts` (= `as_of_ms`). The finalization of a normal
    run (`core/finalize.py`) runs over that key. `_publish` then writes the meta node
    of the run and moves the pointer to it. No site assignments are applied on this
    path.
    """
    from hst.app.crypto import dek

    selected, missing = plan(settings.raw_dir, as_of_ms)
    report = RebuildReport(as_of_ms=as_of_ms, missing=missing)
    key = dek(settings)

    if not dry_run:
        report.cleared = _clear_target(target)

    for snap in selected:
        collector = None
        try:
            label = snap.source if not snap.host else f"{snap.source}/{snap.host}"
            source_collector = collector_for(snap.source)
            if source_collector is None:
                report.failed.append((label, "no such source configured; cannot normalize"))
                continue
            try:
                if device_collector_for is not None:
                    collector = device_collector_for(snap.source, snap.host)
                if collector is None:
                    collector = device_collector(source_collector, snap.host, slugged=True)
                payload = read(snap.path, key)
                batch = collector.normalize(payload)
            except Exception as exc:
                report.failed.append((label, f"{type(exc).__name__}: {exc}"))
                continue
            report.replayed.append(snap)
            if dry_run:
                continue
            # The payload and its parse are released before the load.
            _release_payload(collector)
            payload = None
            report.manifests.append(
                load(target, batch, run_id=snap.run_id, ts_ms=snap.ts_ms, collection_ts=as_of_ms)
            )
        finally:
            # The collector of the snapshot can be the collector of its source. The
            # caller keeps that collector for the rest of the replay.
            _release_payload(collector)
            payload = batch = None
    if not dry_run and report.replayed:
        from . import finalize as finalizemod

        # The derived conclusions are stamped with the newest replayed timestamp.
        report.derived = finalizemod.finalize_derivations(
            target,
            settings,
            as_of_ms,
            {},
            ts_ms=max(s.ts_ms for s in report.replayed),
            sidestore_files=_snapshot_sidestore_files(settings, report.replayed),
        )
        _publish(
            settings,
            target,
            as_of_ms,
            reprocessed_from=None,
            manifests=report.manifests,
            ok=report.ok,
        )
    return report


# --- manifest-driven replay -------------------------------------------------------------


@dataclass(frozen=True)
class SourceLookup:
    """The collector of one source and the type, the enabled flag and the stored
    configuration of its row. A manifest-driven replay gives the source name and these
    3 row values to `manifest.source_config_digest`. `config` is the stored
    configuration of the row, before secret resolution."""

    collector: Any
    type: str
    enabled: bool
    config: Mapping[str, Any]


@dataclass
class ManifestRebuildReport:
    """The result of a manifest-driven replay."""

    snapshot_key: int
    replayed: list[manifestmod.DeviceEntry] = field(default_factory=list)
    manifests: list[RunManifest] = field(default_factory=list)
    # The devices of the manifest with no `effective_run`. They have no payload to replay.
    missing: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    # The lines that the finalization stages of core/finalize.py reported. The
    # list is empty on a dry run and when nothing was replayed.
    derived: list[str] = field(default_factory=list)
    # The sources replayed under the current configuration with a recorded digest
    # mismatch (--allow-config-drift). Each entry holds the source and both digests.
    drift: list[str] = field(default_factory=list)
    # One note for each kept side-store file that was missing or failed its digest
    # check. The note states whether the file was regenerated into the scratch
    # directory or left unresolved.
    side_table_notes: list[str] = field(default_factory=list)
    cleared: int = 0
    # True when the records of the encrypted graph archive were restored. False
    # when a manifest without a graph archive was reprocessed through the current
    # collector.
    exact: bool = False

    @property
    def ok(self) -> bool:
        return not self.missing and not self.failed


def rebuild_from_manifest(
    settings: Settings,
    target: Any,
    snapshot_key: int,
    *,
    source_for: Callable[[str], SourceLookup | None],
    allow_config_drift: bool = False,
    dry_run: bool = False,
    sidestore_scratch_dir: Path | None = None,
) -> ManifestRebuildReport:
    """Restore the snapshot of the manifest at `snapshot_key`.

    A manifest with a graph archive (schema 4 and later) restores the exact
    finalized normalized facts from the authenticated archive. The restore uses
    no collector, no settings lookup, no device overrides and no reasoners. A
    manifest without an archive follows the raw replay path below.

    A device carried in a version-1 manifest reports no raw file entry.

    The manifest is read with `core.manifest.read(settings, snapshot_key)`,
    which raises `FileNotFoundError` when there is none. Raw files with no
    manifest replay through the date-based path of `rebuild`.

    A device with a null `effective_run` (a device carried forward with no
    payload in any run at or before this snapshot) is reported under
    `missing`. For every other device the raw `FileEntry` with that run id is
    looked up.

    Before the devices of a source are normalized, the current configuration
    is digested with `manifest.source_config_digest`, as at publish time.
    `source_for` returns the type, the enabled flag and the stored
    configuration of the row with the collector of the source. The digest is
    compared to the recorded `config_sha256` of the manifest. On a mismatch the
    source and every device of the source get a `failed` entry. The entry of
    the source holds both digests. With `allow_config_drift` the devices replay
    under the current configuration and the drift is recorded in `drift`.

    Each device is normalized by the collector of its source, built for the
    host that the manifest records for the device (`device_collector`). Every
    device of a fleet loads under its own scope, as the cycle loaded it. A
    regenerated side table derives the same device uid as the load.

    The side-store rows of a device are read from the kept parquet file in
    place when the file is on disk and its digest matches the record of the
    manifest. When the file is missing or altered, the rows are regenerated
    from the same raw payload via `side_tables` of the collector and written
    into `sidestore_scratch_dir`. The primary side store is not written. A
    file that needs regeneration with no scratch directory is left unresolved
    and noted.

    The target is wiped before replay, as `rebuild` wipes it. Every load
    shares one `collection_ts` (= `snapshot_key`). The finalization of a normal
    run (`core/finalize.py`) runs over that key with the site assignments and
    the site blocks of the manifest. `_publish` then writes the meta node of
    the run with the snapshot as `reprocessed_from`, and moves the pointer.
    This path does not read the identity store.
    """
    from hst.app.crypto import dek

    record = manifestmod.read(settings, snapshot_key)
    report = ManifestRebuildReport(snapshot_key=snapshot_key)
    key = dek(settings)

    # A manifest of schema 4 and later has the archive of the finalized
    # normalized graph. The restore reads the archive alone.
    # `grapharchive.verify` checks the authentication, the counts and the digest
    # of the whole archive before the target is cleared.
    if record.graph_archive is not None:
        from . import grapharchive

        grapharchive.verify(settings, record.graph_archive, key)
        report.exact = True
        if dry_run:
            return report
        report.cleared = _clear_target(target)
        counts = grapharchive.restore(target, settings, record.graph_archive, key, snapshot_key)
        _publish(
            settings,
            target,
            snapshot_key,
            reprocessed_from=None,
            manifests=[],
            ok=True,
            exact_counts=counts,
            exact_record=record,
        )
        return report

    sources_by_name = {s.name: s for s in record.sources}
    raw_files_by_run = {f.run_id: f for f in record.files if f.kind == "raw"}
    sidestore_files_by_run: dict[str, list[manifestmod.FileEntry]] = {}
    for f in record.files:
        if f.kind == "sidestore":
            sidestore_files_by_run.setdefault(f.run_id, []).append(f)

    if not dry_run:
        report.cleared = _clear_target(target)

    lookups: dict[str, SourceLookup | None] = {}
    ok_sources: set[str] = set()
    for name, entry in sources_by_name.items():
        lookup = source_for(name)
        lookups[name] = lookup
        if lookup is None:
            continue
        today_digest = manifestmod.source_config_digest(name, lookup.type, lookup.enabled, lookup.config)
        if today_digest == entry.config_sha256:
            ok_sources.add(name)
            continue
        note = (
            f"{name}: manifest recorded configuration digest {entry.config_sha256}, "
            f"today's configuration digests {today_digest}"
        )
        if not allow_config_drift:
            report.failed.append((name, f"{note} -- rerun with allow_config_drift to replay anyway"))
            continue
        report.drift.append(f"{note} -- replayed under today's configuration (allow_config_drift)")
        ok_sources.add(name)

    for device in record.devices:
        collector = None
        try:
            label = device.source if not device.host else f"{device.source}/{device.host}"
            effective_run = device.effective_run
            if effective_run is None:
                report.missing.append(label)
                continue
            if device.source not in sources_by_name:
                report.failed.append((label, "source not named in this snapshot's manifest"))
                continue
            if device.source not in ok_sources:
                lookup = lookups.get(device.source)
                reason = (
                    "no such source configured; cannot normalize"
                    if lookup is None
                    else "source configuration drift; rerun with allow_config_drift"
                )
                report.failed.append((label, reason))
                continue
            raw_entry = raw_files_by_run.get(effective_run)
            if raw_entry is None:
                reason = f"no raw file entry for run {effective_run!r} in the manifest"
                report.failed.append((label, reason))
                continue
            lookup = lookups[device.source]
            if lookup is None:
                report.failed.append((label, "no such source configured; cannot normalize"))
                continue
            try:
                collector = device_collector(lookup.collector, device.host)
                payload = read(settings.hst_data_dir / raw_entry.path, key)
                batch = collector.normalize(payload)
            except Exception as exc:
                report.failed.append((label, f"{type(exc).__name__}: {exc}"))
                continue
            report.replayed.append(device)
            if dry_run:
                continue
            # The collector still holds the parse cache that `normalize` filled.
            # The regeneration of a side table reuses the parse of the payload.
            _replay_side_tables(
                settings,
                collector,
                payload,
                device,
                effective_run,
                sidestore_files_by_run,
                sidestore_scratch_dir,
                report,
            )
            # The payload and its parse are released before the load.
            _release_payload(collector)
            payload = None
            report.manifests.append(
                load(
                    target,
                    batch,
                    run_id=effective_run,
                    ts_ms=device.fetch_ts_ms or manifestmod.run_ts(effective_run) or snapshot_key,
                    collection_ts=snapshot_key,
                )
            )
        finally:
            # The collector of the device can be the collector of its source. The
            # lookup keeps that collector for the rest of the replay.
            _release_payload(collector)
            payload = batch = None
    if not dry_run and report.replayed:
        from . import finalize as finalizemod

        replayed_at = max(
            (d.fetch_ts_ms for d in report.replayed if d.fetch_ts_ms is not None),
            default=snapshot_key,
        )
        # The side-store files of the manifest. A file that is missing from the
        # store is left out. `_replay_side_tables` has reported it.
        on_disk = [
            f for f in record.files if f.kind != "sidestore" or (settings.hst_data_dir / f.path).is_file()
        ]
        report.derived = finalizemod.finalize_derivations(
            target,
            settings,
            snapshot_key,
            dict(record.site_assignments),
            ts_ms=replayed_at,
            sidestore_files=manifestmod.SidestoreFiles(settings, on_disk),
            # The named blocks that the run stamped. A manifest before schema 7 has none.
            site_blocks=dict(record.site_blocks),
        )
        _publish(
            settings,
            target,
            snapshot_key,
            reprocessed_from=snapshot_key,
            manifests=report.manifests,
            ok=report.ok,
        )
    return report


def _snapshot_sidestore_files(settings: Settings, snapshots: list[Snapshot]) -> manifestmod.SidestoreFiles:
    """The side-store files that the runs of the replayed raw snapshots wrote,
    found by their run ids. The derivations read only these files. A date-based
    rebuild has no manifest that lists them. The entries have no `device_uids`,
    and each file is read for every device of its table."""
    from . import sidestore

    base = settings.sidestore_dir
    entries: list[manifestmod.FileEntry] = []
    tables = sorted(
        d
        for d in (base.iterdir() if base.is_dir() else ())
        if d.is_dir() and not d.name.startswith(".") and d.name not in sidestore._NOT_TABLES
    )
    for snap in snapshots:
        for table in tables:
            directory = table / slug(snap.source)
            if snap.host:
                directory = directory / slug(snap.host)
            path = directory / f"{snap.run_id}{sidestore.SUFFIX}"
            if path.is_file():
                entries.append(
                    manifestmod.FileEntry(
                        kind="sidestore",
                        path=manifestmod._relative(path, settings.hst_data_dir),
                        sha256="",
                        bytes=-1,
                        source=snap.source,
                        host=snap.host,
                        run_id=snap.run_id,
                        table=table.name,
                    )
                )
    return manifestmod.SidestoreFiles(settings, entries)


def _replay_side_tables(
    settings: Settings,
    collector: Any,
    payload: Any,
    device: manifestmod.DeviceEntry,
    effective_run: str,
    sidestore_files_by_run: dict[str, list[manifestmod.FileEntry]],
    scratch_dir: Path | None,
    report: ManifestRebuildReport,
) -> None:
    """Verify or regenerate the side-store files of the replayed run of one
    device. The files are joined to the run by run id (see
    `rebuild_from_manifest`). `effective_run` is `device.effective_run` as a
    `str`. The caller has skipped a device with no effective run.

    `sidestore.write_table` writes a regenerated file under a temporary name
    and renames it into place, as it does for the primary store. An interrupted
    replay leaves no partly written parquet file under a final name in the
    scratch directory."""
    label = device.source if not device.host else f"{device.source}/{device.host}"
    for entry in sidestore_files_by_run.get(effective_run, []):
        table = entry.table
        if table is None:
            # `file_entry` sets `table` on every "sidestore" kind entry.
            report.side_table_notes.append(f"{label}: a sidestore file entry has no table name")
            continue
        path = settings.hst_data_dir / entry.path
        kept_ok = path.is_file()
        if kept_ok:
            sha, size = manifestmod.file_facts(path)
            kept_ok = (sha, size) == (entry.sha256, entry.bytes)
        if kept_ok:
            continue  # The file on disk matches the manifest and is read in place.
        if scratch_dir is None:
            report.side_table_notes.append(
                f"{label}: {table} is missing or altered and no scratch directory was given "
                "to regenerate it into"
            )
            continue
        rows = collector.side_tables(payload).get(table, [])
        if not rows:
            report.side_table_notes.append(
                f"{label}: {table} is missing or altered and side_tables produced no rows to "
                "regenerate it from"
            )
            continue
        try:
            from hst.core import sidestore
        except Exception as exc:
            report.side_table_notes.append(f"{label}: {table} could not be regenerated: {exc}")
            continue
        written = sidestore.write_table(
            scratch_dir,
            table,
            device.source,
            device.host,
            effective_run,
            rows,
            snapshot_ts=device.fetch_ts_ms or manifestmod.run_ts(effective_run) or 0,
        )
        # `write_table` digested the rows as it wrote them. That digest is
        # compared with the recorded digest, as in the side-store repair
        # (core/reconcile.py `repair_derived`).
        facts = None if written is None else sidestore.written_row_facts(written)
        if facts is None or entry.rows_sha256 is None:
            report.side_table_notes.append(f"{label}: {table} regenerated into {written}")
        elif facts[1] == entry.rows_sha256:
            report.side_table_notes.append(
                f"{label}: {table} regenerated into {written}, the recorded row digest matches"
            )
        else:
            report.side_table_notes.append(
                f"{label}: {table} regenerated into {written}, and the row digest differs "
                f"(manifest {entry.rows_sha256}, regenerated {facts[1]})"
            )
