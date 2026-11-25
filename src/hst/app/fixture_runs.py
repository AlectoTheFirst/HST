"""Publish a YAML fixture batch as one run: the load, the derivations, the graph archive, the
manifest, the cycle meta node, the pointer and the HST map tables of the run."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hst.core import Settings
from hst.core.loader import load
from hst.core.model import Batch, RunManifest


class FixtureExtendError(RuntimeError):
    """A load without `new_run` cannot extend the run published before it."""


@dataclass
class FixtureRun:
    """What one fixture load published. `marker` is the HST map marker of the run, or None without
    the `sidestore` extra. `map_failure` holds the reason why the map tiers were not written."""

    cts: int
    previous: int | None
    loaded: RunManifest
    derived: list[str] = field(default_factory=list)
    marker: dict[str, Any] | None = None
    map_failure: str | None = None

    @property
    def tiers_ready(self) -> bool:
        return bool(self.marker and self.marker.get("tiers_ready"))


def publish(
    s: Any,
    settings: Settings,
    batch: Batch,
    path: Path,
    *,
    new_run: bool,
    fence: int | None = None,
    loader: Callable[..., RunManifest] = load,
) -> FixtureRun:
    """Load `batch`, read from `path`, as a new run and publish it.

    Every call publishes a fresh immutable snapshot. Without `new_run`, the authenticated graph
    archive of the previous snapshot is verified and its graph is copied into the unpublished
    target first. The fixture adds to that copy. `new_run` starts from empty.

    The rule reasoner runs over the run this load builds. The HST map tables of the run are written
    with the projection a collection run uses. The parent of the projection is the run published
    before this load, also with `new_run`. A projection failure leaves the run without map tables
    and does not fail the load.

    `fence` is the cycle lock acquisition that the caller holds. With `fence`, the pointer does not
    move when a later acquisition has moved it (`cycle.set_pointer`). `loader` is
    `core.loader.load`.
    """
    from hst.app import crypto, runs_exec
    from hst.core import cycle as cyclemod
    from hst.core import finalize, grapharchive
    from hst.core import manifest as snapshot_manifest

    run_id = f"fixture-{path.stem}-{int(time.time())}"
    previous = cyclemod.current_ts(s)
    cts = cyclemod.new_collection_ts()
    if previous is not None and cts <= previous:
        cts = previous + 1
    with runs_exec._building(s, settings, cts, "full", None if new_run else previous):
        prior_record = None
        if previous is not None and not new_run:
            try:
                prior_record = snapshot_manifest.read(settings, previous)
            except (OSError, ValueError) as exc:
                raise FixtureExtendError(
                    f"cannot extend snapshot {previous}: its manifest is unavailable: {exc}"
                ) from None
            if prior_record.graph_archive is None:
                raise FixtureExtendError(
                    f"cannot extend snapshot {previous}: it has no authenticated graph archive; use --new-run"
                )
            key = crypto.dek(settings)
            grapharchive.verify(settings, prior_record.graph_archive, key)
            # The cycle copier keeps shared unversioned objects as singletons.
            cyclemod.carry_forward(s, previous, cts, [entry.name for entry in prior_record.sources])

        loaded = loader(s, batch, run_id=run_id, collection_ts=cts)
        # The fixture writes no side-store file. The derivations read the files
        # of the carried devices from the manifest of the previous run.
        derived = finalize.finalize_derivations(
            s,
            settings,
            cts,
            {},
            parent=previous if prior_record is not None else None,
            sidestore_files=snapshot_manifest.SidestoreFiles(
                settings,
                [
                    f
                    for f in (prior_record.files if prior_record is not None else [])
                    if f.kind != "sidestore" or (settings.hst_data_dir / f.path).is_file()
                ],
            ),
        )
        counts = cyclemod.cycle_counts(s, cts)
        archive_context = {
            "fixture": path.name,
            "source": batch.source,
            "parent_snapshot": previous if prior_record is not None else None,
        }
        archive = snapshot_manifest.GraphArchiveEntry.model_validate(
            grapharchive.write(s, settings, cts, crypto.dek(settings), normalization_context=archive_context)
        )
        prior_sources = list(prior_record.sources) if prior_record is not None else []
        sources = [
            *[
                entry.model_copy(update={"status": "carried"})
                for entry in prior_sources
                if entry.name != batch.source
            ],
            snapshot_manifest.SourceEntry(
                name=batch.source,
                type="fixture",
                status="fresh",
                config_sha256=snapshot_manifest.source_config_digest(
                    batch.source, "fixture", True, {"path": path.name}
                ),
            ),
        ]
        projection = runs_exec._hst_projection(s, settings, cts, previous, "full")
        delta = snapshot_manifest.graph_delta(
            s, previous, cts, projection.observe if projection is not None else None
        )
        if projection is not None:
            # the map tiers use this diff and stage their files before the pointer moves
            projection.prepare(s, complete=previous is None or delta.sha256 is not None)
        record = snapshot_manifest.build(
            settings=settings,
            snapshot_key=cts,
            kind="full",
            parent=previous if prior_record is not None else None,
            sources=sources,
            devices=[
                device.model_copy(update={"outcome": "carried", "carried": True})
                for device in (prior_record.devices if prior_record is not None else [])
            ],
            files=[
                entry.model_copy(update={"carried": True})
                for entry in (prior_record.files if prior_record is not None else [])
            ],
            delta=delta,
            checkpoint_of=lambda: snapshot_manifest.checkpoint(s, cts),
            site_assignments=prior_record.site_assignments if prior_record is not None else {},
            graph_archive=archive,
        )
        digest = snapshot_manifest.write(settings, record, snapshot_manifest.signer_for(settings))
        statuses = {entry.name: entry.status for entry in sources}
        cyclemod.write_cycle_meta(
            s,
            cts,
            statuses=statuses,
            carried_from=previous if prior_record is not None else None,
            nodes=counts["nodes"],
            rels=counts["rels"],
            degraded=False,
            parent=previous if prior_record is not None else None,
            manifest_digest=digest,
        )
        if fence is None:
            cyclemod.set_pointer(s, cts)
        else:
            cyclemod.set_pointer(s, cts, fence=fence)
        out = FixtureRun(cts=cts, previous=previous, loaded=loaded, derived=list(derived))
        if projection is not None:
            out.marker = projection.publish()
            if not out.tiers_ready:
                out.map_failure = str(projection.failed or "no tiers")
        return out
