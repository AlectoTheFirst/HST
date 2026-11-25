"""The run listing, date resolution, the A/B comparison and manifest replay."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from hst.app.auth import require_permission
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.core.diff import DiffTimeout, request_diff

router = APIRouter()
_session = dbmod.session  # Tests replace this name.


def _cts(value: str, name: str) -> int:
    if not value.isdigit():
        raise HTTPException(400, detail=f"{name} must be a run id from /api/snapshots")
    return int(value)


def _instant(value: str) -> datetime:
    """An ISO-8601 instant, read as UTC when it has no offset."""
    try:
        when = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            400,
            detail=(f"at must be an ISO-8601 instant, for example 2026-03-31T18:00:00Z; got {value!r}"),
        ) from None
    return when if when.tzinfo is not None else when.replace(tzinfo=UTC)


@router.get("/snapshots", dependencies=[Depends(require_permission("graph.read"))])
def list_snapshots(request: Request) -> dict:
    """The runs, newest first, and the state of the one the pointer names.

    `run` is the status of the current run with a freshness summary per device
    (`core/cycle.py run_status`). The summary holds the outcome of each device,
    the reason when its objects are carried, the time it was last observed and
    the age of each of its side-store tables. `run` is null before the first run
    is published.
    """
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = snapshotmod.resolve(s, settings)
        # `truncated` is true when older runs exist beyond the page.
        snapshots, truncated = cyclemod.list_cycles(s)
        return {
            "snapshots": snapshots,
            "truncated": truncated,
            "current": snap.cts,
            "run": cyclemod.run_status(s, snap),
        }


# The newest run at or before a bound. The caller caps `$bound` at the run of
# the pointer. A build can die after it writes the meta node and before it moves
# the pointer (the order in core/cycle.py). Such a run is not resolved.
_RESOLVE_AT = (
    "MATCH (c:CycleRun) WHERE c.cts <= $bound AND coalesce(c.state, 'built') <> 'building' "
    "RETURN c.cts AS cts, coalesce(c.kind, 'full') AS kind, c.created AS created "
    "ORDER BY c.cts DESC LIMIT 1"
)


def _observations(record: Any) -> list[dict]:
    """Per-device observation times of one snapshot, from its manifest.

    Each device has 4 distinct times (core/manifest.py `DeviceEntry`).
    `fetch_ts_ms` is parsed from the run id. `fetch_started_ms` and
    `fetch_finished_ms` are the start and the end of the fetch. `ingested_ms` is
    the time when the run loaded the payload. A time is null on a device that
    has no outcome in the run. All 4 times are null in a manifest of a schema
    version below 3. The rows are in the manifest order, by source and host.
    """
    if record is None:
        return []
    return [
        {
            "source": d.source,
            "host": d.host,
            "outcome": d.outcome,
            "effective_run": d.effective_run,
            "carried": d.carried,
            "fetch_ts_ms": d.fetch_ts_ms,
            "fetch_started_ms": d.fetch_started_ms,
            "fetch_finished_ms": d.fetch_finished_ms,
            "ingested_ms": d.ingested_ms,
        }
        for d in record.devices
    ]


@router.get("/snapshots/resolve", dependencies=[Depends(require_permission("graph.read"))])
def resolve_snapshot(request: Request, at: str) -> dict:
    """The committed snapshot that answers for one instant.

    The answer is the newest committed run at or before the instant.

    Resolution is by snapshot key, which is the time when the run opened.

    A run that the pointer has not moved to is not resolved. `approximate` is
    true when the resolved run has no manifest.
    """
    settings = request.app.state.settings
    when = _instant(at).astimezone(UTC)
    with _session(settings) as s:
        try:
            return resolve_at(s, settings, when)
        except (NoRunPublished, NoSnapshotAt) as exc:
            raise HTTPException(404, detail=str(exc)) from None


class NoRunPublished(LookupError):
    """No run is published."""


class NoSnapshotAt(LookupError):
    """No committed run was opened at or before the instant."""


def resolve_at(session: Any, settings: Any, when: datetime) -> dict:
    """The committed snapshot that answers for the UTC instant `when`, as
    `GET /api/snapshots/resolve` returns it.

    Raises `NoRunPublished` before the first published run, and `NoSnapshotAt`
    when no committed run was opened at or before `when`.
    """
    current = snapshotmod.resolve(session, settings)
    if current.cts is None:
        raise NoRunPublished("no run is published yet")
    bound = min(int(when.timestamp() * 1000), current.cts)
    rows = session.execute_read(lambda tx: tx.run(_RESOLVE_AT, bound=bound).data())
    if not rows:
        raise NoSnapshotAt(f"no committed snapshot at or before {when.isoformat()}")
    row = rows[0]
    snap = snapshotmod.resolve(session, settings, int(row["cts"]))
    record = snap.manifest
    return {
        "at": when.isoformat(),
        "snapshot": snap.snapshot_id,
        "kind": row["kind"],
        "opened": row["created"],
        "published": None if record is None else record.published,
        "approximate": snap.approximate,
        "devices": _observations(record),
    }


@router.get("/diff", dependencies=[Depends(require_permission("graph.read"))])
def get_diff(request: Request, a: str, b: str) -> dict:
    """What changed from run `a` to run `b`.

    A removal holds `last_seen`, `absence_detected` and the outcome of the device
    that owned the object, from the manifest of `b` (`core/diff.py`). The status
    of a removal is `unknown` when that device failed or was carried in `b`.
    """
    cts_a, cts_b = _cts(a, "a"), _cts(b, "b")
    settings = request.app.state.settings
    with _session(settings) as s:
        known = {
            r["cts"]
            for r in s.execute_read(
                lambda tx: tx.run(
                    "MATCH (c:CycleRun) WHERE c.cts IN [$a, $b] "
                    "AND coalesce(c.state, 'built') <> 'building' RETURN c.cts AS cts",
                    a=cts_a,
                    b=cts_b,
                ).data()
            )
        }
        missing = [str(v) for v in (cts_a, cts_b) if v not in known]
        if missing:
            raise HTTPException(404, detail=f"unknown run(s): {', '.join(missing)}")
        # The manifest of run `b` qualifies a removal. A run with no manifest
        # gives no device entries, and every removal stays unqualified.
        record = snapshotmod.resolve(s, settings, cts_b).manifest
        devices = [] if record is None else record.devices
        try:
            return request_diff(s, cts_a, cts_b, devices_b=devices)
        except DiffTimeout as exc:
            raise HTTPException(504, detail=str(exc)) from None


class RebuildBody(BaseModel):
    """The target and the options of a rebuild.

    `into` is a bolt URI.
    """

    into: str = ""
    allow_config_drift: bool = False
    dry_run: bool = False


@router.post("/snapshots/{key}/rebuild", dependencies=[Depends(require_permission("graph.purge"))])
async def rebuild_snapshot(request: Request, key: str, body: RebuildBody) -> dict:
    """Reconstruct one published snapshot from its manifest, into a scratch
    database (`core/replay.py rebuild_from_manifest`).

    The rebuild replays each device from the raw file of its `effective_run`.

    The target must be a scratch target in both stores. The graph target is refused
    when it has the port of the configured graph and a host that is equal to
    its host or resolves to one of its addresses (`core/db.py same_endpoint`).
    A target whose host does not resolve is refused. The call sends the Neo4j
    credentials to the target and deletes every node there. The driver of the
    target is closed when the call ends. A regenerated side-store file goes
    under `<data dir>/replay/<key>`.

    A source whose configuration digest differs from the manifest refuses its
    devices. `allow_config_drift` replays them and reports the drift. `ok` is
    false when a device of the snapshot could not be replayed.
    """
    from hst.app import sources as glue
    from hst.core import replay

    cts = _cts(key, "the snapshot key")
    settings = request.app.state.settings
    if not body.into:
        raise HTTPException(400, detail="into is required")
    if await asyncio.to_thread(dbmod.same_endpoint, body.into, settings.neo4j_uri):
        raise HTTPException(
            400,
            detail=(f"into is the configured graph ({body.into}); a rebuild needs a scratch database"),
        )
    if not await asyncio.to_thread(dbmod.resolves, body.into):
        raise HTTPException(400, detail=f"the host of into does not resolve ({body.into})")
    if not await asyncio.to_thread(dbmod.resolves, settings.neo4j_uri):
        raise HTTPException(
            503,
            detail="the host of the configured graph does not resolve, so into cannot be compared with it",
        )
    rows = {r.name: r for r in await request.app.state.store.list_sources()}
    sites = {site.code: site for site in await request.app.state.store.list_sites()}
    # The replay reads the registry and resolves the same uids as the cycle.
    registry = await glue.registry_snapshot(request.app.state.store)
    target = settings.model_copy(update={"neo4j_uri": body.into})
    scratch = settings.hst_data_dir / "replay" / str(cts)

    def source_for(name: str) -> Any:
        row = rows.get(name)
        if row is None:
            return None
        return replay.SourceLookup(
            collector=glue.build_collector(row, settings, sites=sites, sources=rows, identity=registry),
            type=row.type,
            enabled=row.enabled,
            config=row.config,
        )

    def go() -> Any:
        with _session(target) as s:
            return replay.rebuild_from_manifest(
                settings,
                s,
                cts,
                source_for=source_for,
                allow_config_drift=body.allow_config_drift,
                dry_run=body.dry_run,
                sidestore_scratch_dir=scratch,
            )

    try:
        report = await asyncio.to_thread(go)
    except FileNotFoundError:
        raise HTTPException(
            404,
            detail=(
                f"snapshot {cts} has no manifest; history from before manifests is rebuilt "
                "by date with the rebuild command"
            ),
        ) from None
    except ValueError as exc:
        # core/manifest.py `read` raises ValueError for a manifest that this build cannot read.
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await asyncio.to_thread(dbmod.close_driver, target)
    return {
        "snapshot": str(cts),
        "into": body.into,
        "dry_run": body.dry_run,
        "ok": report.ok,
        "cleared": report.cleared,
        "replayed": [d.source if not d.host else f"{d.source}/{d.host}" for d in report.replayed],
        "missing": report.missing,
        "failed": [{"device": name, "reason": why} for name, why in report.failed],
        "drift": report.drift,
        "side_tables": report.side_table_notes,
        "derived": report.derived,
        "nodes": sum(m.nodes_upserted for m in report.manifests),
        "rels": sum(m.rels_upserted for m in report.manifests),
    }
