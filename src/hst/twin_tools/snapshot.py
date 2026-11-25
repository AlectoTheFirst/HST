"""Snapshot tools: `snapshot_list`, `snapshot_resolve` and `snapshot_diff`.

Each tool reads the graph in a READ session, binds the run once through the
snapshot selector and answers with the envelope.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.results.words import FIXED_REASONS, Answer, decided, from_engine
from hst.results.words import record as completeness
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    jsonable,
    unknowns_missing,
    whole_result,
)

# --- snapshot_list -------------------------------------------------------------------------


class SnapshotListInput(selectors.PagedInput):
    """List the retained runs, newest first."""


class RunRow(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    ts_ms: int | None = None
    created: Any = None
    kind: str
    parent: str | int | None = None
    nodes: int | None = None
    rels: int | None = None
    degraded: bool | None = None
    sources_fresh: list[str] | None = None
    sources_carried: list[str] | None = None
    sources_failed: list[str] | None = None
    sources_partial: list[str] | None = None
    sources_cancelled: list[str] | None = None
    is_current: bool
    is_selected: bool


class SnapshotListResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    current: str | None = Field(description="the run the published pointer names")
    runs: list[RunRow]


def snapshot_list(ctx: ToolContext, params: SnapshotListInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "snapshot_list", params, session)
        if params.snapshot == selectors.LATEST and ctx.snapshot is None:
            pointer = call.snapshot.cts
        else:
            pointer = snapshotmod.resolve(session, ctx.settings).cts
        rows, more = cyclemod.list_cycles(session, limit=call.pager.limit, offset=call.pager.offset)
        current = None if pointer is None else str(pointer)
        runs = [
            {**row, "is_current": row["id"] == current, "is_selected": row["id"] == call.snapshot.snapshot_id}
            for row in jsonable(rows)
        ]
        page_rows, page = call.pager.take(runs, more=more)
        return call.finish(
            session,
            result={"current": current, "runs": page_rows},
            evidence=Evidence(result=completeness("recorded")),
            page=page,
            engine_function="hst.core.cycle.list_cycles",
            queries=[("fixed", "hst.core.cycle.LIST_CYCLES")],
        )


# --- snapshot_resolve ----------------------------------------------------------------------


class SnapshotResolveInput(selectors.PagedInput):
    """Resolve a snapshot selector, or an instant, to one run."""

    at: datetime | None = Field(
        default=None,
        description=(
            "An ISO-8601 instant, read as UTC when it carries no offset. Given, the answer is the "
            "newest committed run opened at or before it, and snapshot is ignored."
        ),
    )
    include_health: bool = Field(
        default=False, description="Add each device's section and side-store table outcomes to its row."
    )


class DeviceObservation(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str
    host: str
    outcome: str | None = None
    effective_run: str | int | None = None
    carried: bool | None = None
    fetch_ts_ms: int | None = None
    fetch_started_ms: int | None = None
    fetch_finished_ms: int | None = None
    ingested_ms: int | None = None
    sections: dict[str, str] | None = None
    tables: dict[str, str] | None = None


class SnapshotResolveResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    at: str | None = None
    snapshot: str | None
    kind: str | None = None
    opened: Any = None
    published: Any = None
    approximate: bool
    devices: list[DeviceObservation] = Field(
        description="per-device observation times from the run's manifest, one page"
    )


_RUN_META = """
MATCH (c:CycleRun {uid: $uid})
RETURN coalesce(c.kind, 'full') AS kind, c.created AS created"""


def snapshot_resolve(ctx: ToolContext, params: SnapshotResolveInput) -> str:
    from hst.app.routes import snapshots as snapshots_route

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        if params.at is not None:
            when = params.at if params.at.tzinfo is not None else params.at.replace(tzinfo=UTC)
            try:
                resolved = snapshots_route.resolve_at(session, ctx.settings, when.astimezone(UTC))
            except snapshots_route.NoRunPublished as exc:
                raise ToolError("snapshot_not_published", str(exc)) from None
            except snapshots_route.NoSnapshotAt as exc:
                raise ToolError("not_found", str(exc), field="at") from None
            snap = snapshotmod.resolve(session, ctx.settings, int(resolved["snapshot"]))
            call = Call.open(ctx, "snapshot_resolve", params, session, snapshot=snap)
        else:
            call = Call.open(ctx, "snapshot_resolve", params, session)
            snap = call.snapshot
            meta = [] if snap.cts is None else session.run(_RUN_META, uid=f"cycle:{snap.cts}").data()
            record = snap.manifest
            resolved = {
                "at": None,
                "snapshot": snap.snapshot_id,
                "kind": meta[0]["kind"] if meta else None,
                "opened": meta[0]["created"] if meta else None,
                "published": None if record is None else record.published,
                "approximate": snap.approximate,
                "devices": snapshots_route._observations(record),
            }
        devices = jsonable(resolved.pop("devices"))
        if params.include_health:
            health = snap.completeness()
            for device in devices:
                entry = health.get(f"{device['source']}/{device['host']}")
                device["sections"] = None if entry is None else entry.sections
                device["tables"] = None if entry is None else entry.tables
        page_devices, page = call.pager.take(devices[call.pager.offset :], total=len(devices))
        unknowns = []
        if snap.cts is not None and snap.approximate:
            unknowns.append("no manifest governs this run, so per-device observation times are not recorded")
        return call.finish(
            session,
            result={**jsonable(resolved), "devices": page_devices},
            evidence=Evidence(
                result=completeness("recorded", missing=unknowns_missing(unknowns)), unknowns=unknowns
            ),
            page=page,
            engine_function=(
                "hst.app.routes.snapshots.resolve_at"
                if params.at is not None
                else "hst.core.snapshot.resolve"
            ),
            queries=[
                ("fixed", "hst.app.routes.snapshots._RESOLVE_AT")
                if params.at is not None
                else ("fixed", "hst.twin_tools.snapshot._RUN_META")
            ],
        )


# --- snapshot_diff -------------------------------------------------------------------------

Bucket = Literal[
    "nodes.added", "nodes.removed", "nodes.changed", "rels.added", "rels.removed", "rels.changed"
]


class SnapshotDiffInput(selectors.PagedInput):
    """What changed from run `base` (side A) to the selected run (side B)."""

    base: str = Field(pattern=r"^[0-9]{1,19}$", description="The run id of side A, the older run.")
    bucket: Bucket | None = Field(
        default=None,
        description="The bucket whose records to page through. Omitted, only the counts come back.",
    )


class DiffCounts(BaseModel):
    model_config = ConfigDict(extra="allow")

    nodes: dict[str, int]
    rels: dict[str, int]


class DiffItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    removal: Literal["removed", "unknown"] | None = None
    evidence: ItemEvidence


class SnapshotDiffResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    base: str
    counts: DiffCounts
    bucket: str | None = None
    bucket_count: int | None = None
    bucket_truncated: bool = Field(
        default=False, description="true when the bucket holds more records than the 500 the comparison keeps"
    )
    items: list[DiffItem] = Field(default_factory=list)


def _diff_evidence(bucket: str, record: dict[str, Any]) -> tuple[str | None, ItemEvidence]:
    """The removal status and the evidence of one diff record.

    A node removal is proven when the owning device answered for its scope in
    side B. A node removal is not established when that device failed or was
    carried. A relationship removal has no owning device and is not
    established. Additions and changes are derived from the two records.
    """
    if bucket == "nodes.removed":
        status = record.get("status")
        if status == "unknown":
            open_on = [
                Missing(
                    code="owner-not-answered",
                    subject=str(record.get("device") or record.get("device_uid") or "") or None,
                    detail="the owning device failed or was carried in side B, so its scope was not re-read",
                )
            ]
            open_result = from_engine("object-exists", "not-established", missing=open_on)
            return "unknown", ItemEvidence.of(open_result, basis="derived")
        return "removed", ItemEvidence.of(from_engine("object-exists", "does-not-hold"), basis="derived")
    if bucket == "rels.removed":
        open_on = [Missing(code="owner-not-collected", detail=FIXED_REASONS["owner-not-collected"])]
        open_result = from_engine("object-exists", "not-established", missing=open_on)
        return None, ItemEvidence.of(open_result, basis="derived")
    answer: Answer = "added" if bucket.endswith(".added") else "changed"
    return None, ItemEvidence.of(decided("object-exists", answer), basis="derived")


def snapshot_diff(ctx: ToolContext, params: SnapshotDiffInput) -> str:
    from hst.core.diff import DETAIL_CAP, DiffTimeout, request_diff

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "snapshot_diff", params, session)
        side_b = call.snapshot
        if side_b.cts is None:
            raise ToolError("snapshot_not_published", "no run is published yet; name side B by its run id")
        # `bind` checks that the run `base` has a retained graph.
        selectors.bind(ctx, session, params.base, field="base")
        cts_a = int(params.base)
        record = side_b.manifest
        try:
            diff = request_diff(
                session, cts_a, side_b.cts, devices_b=[] if record is None else record.devices
            )
        except DiffTimeout as exc:
            raise ToolError("timeout", str(exc), retryable=True) from None
        result: dict[str, Any] = {
            "base": str(cts_a),
            "counts": diff["counts"],
            "bucket": params.bucket,
            "bucket_count": None,
            "bucket_truncated": False,
            "items": [],
        }
        unknowns: list[str] = []
        page = None
        whole = completeness("recorded")
        if params.bucket is not None:
            family, change = params.bucket.split(".")
            records = jsonable(diff[family][change])
            count = diff["counts"][family][change]
            items = []
            for row in records:
                removal, evidence = _diff_evidence(params.bucket, row)
                items.append({**row, "removal": removal, "evidence": evidence.model_dump(mode="json")})
            page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
            result.update(bucket_count=count, bucket_truncated=count > DETAIL_CAP, items=page_items)
            if count > DETAIL_CAP:
                unknowns.append(
                    f"the bucket holds {count} records; the comparison keeps the first {DETAIL_CAP} "
                    "in sort order, and the others are not listed"
                )
            whole = whole_result((item["evidence"]["result"] for item in page_items), unknowns=unknowns)
        return call.finish(
            session,
            result=result,
            evidence=Evidence(result=whole, unknowns=unknowns),
            page=page,
            engine="hst.core.diff",
            engine_function="hst.core.diff.diff_snapshots",
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="snapshot_list",
            description=(
                "List the retained collection runs, newest first, with each run's status: degraded, "
                "and which sources were fresh, carried, failed, partial or cancelled. is_current marks "
                "the run the published pointer names and is_selected the run the snapshot argument "
                "selected. Pass a run id from here as snapshot to any other tool."
            ),
            input_model=SnapshotListInput,
            result_model=SnapshotListResult,
            run=snapshot_list,
        )
    )
    registry.register(
        catalogue_spec(
            name="snapshot_resolve",
            description=(
                "Resolve a snapshot selector, or an instant given as at, to one committed run: its id, "
                "kind, when it was opened and published, and whether a manifest governs it. devices "
                "lists what the manifest records per device, one page at a time; include_health adds "
                "each device's section and side-store table outcomes."
            ),
            input_model=SnapshotResolveInput,
            result_model=SnapshotResolveResult,
            run=snapshot_resolve,
        )
    )
    registry.register(
        catalogue_spec(
            name="snapshot_diff",
            description=(
                "Compare run base (side A) with the selected run (side B): counts of nodes and "
                "relationships added, removed and changed, and one bucket's records a page at a time. "
                "Each bucket keeps its first 500 records; bucket_truncated says more exist. A node "
                "removal reads removed when the owning device answered for its scope in side B, and "
                "unknown when that device failed or was carried. Every call recomputes the comparison."
            ),
            input_model=SnapshotDiffInput,
            result_model=SnapshotDiffResult,
            run=snapshot_diff,
        )
    )
