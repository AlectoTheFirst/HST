"""The evidence tool `evidence_get_gaps`.

`evidence_get_gaps` lists what the selected run lacks to answer questions
about one subject:

- `device`: the outcome the snapshot recorded for the device's RIB, BGP route
  and OSPF tables (`RibSource.coverage`, `BgpSource.coverage`,
  `OspfSource.coverage`). A table that is not complete is a gap.
- `assessment_run`: the gaps and missing evidence a stored run recorded, and
  the collection actions of a stored troubleshooting result.
- `application_connection`: the resolution issues of one catalog connection at
  the selected run, computed and not saved.
- `service_requirement`: the gaps and missing evidence of the requirement's
  evaluation at the selected run with no change applied.

The tool lists collection actions and does not queue them.
`POST /api/assessments/{id}/collection-actions` queues a collection under
`runs.manage`.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.results.words import record as completeness
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    MAX_GAPS,
    Call,
    Evidence,
    Gap,
    catalogue_spec,
    http_error,
    jsonable,
    missing_of,
    to_gap,
)
from hst.twin_tools.stores import read_store, require

MAX_ACTIONS = 50
# Missing-evidence lines of one engine answer that become gaps.
MAX_MISSING = 100

_COMPLETE = ("complete", "complete-empty")


class _Subject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=512, description="The subject's id, as kind describes.")


class DeviceGapsSubject(_Subject):
    """A device, by uid or hostname."""

    kind: Literal["device"]


class RunGapsSubject(_Subject):
    """A stored assessment run, by run id."""

    kind: Literal["assessment_run"]


class ConnectionGapsSubject(_Subject):
    """A connection of a catalog application, by connection id."""

    kind: Literal["application_connection"]
    application_id: str = Field(min_length=1, max_length=200, description="The application id.")


class RequirementGapsSubject(_Subject):
    """A graph ServiceRequirement, by uid."""

    kind: Literal["service_requirement"]


Subject = Annotated[
    DeviceGapsSubject | RunGapsSubject | ConnectionGapsSubject | RequirementGapsSubject,
    Field(discriminator="kind", description="What the gaps are about."),
]


class EvidenceGetGapsInput(selectors.PagedInput):
    """The evidence gaps of one subject at the selected run."""

    subject: Subject


class EvidenceGetGapsResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    subject: dict[str, Any]
    tables: dict[str, str | None] = Field(
        default_factory=dict, description="device subject: the recorded outcome of each side-store table"
    )
    gaps: list[dict[str, Any]] = Field(description="one page of the gaps")
    gap_count: int
    collection_actions: list[dict[str, Any]] = Field(
        default_factory=list, description="read-only suggestions from a stored troubleshooting result"
    )


def missing_evidence_gaps(lines: Any, subject: str) -> list[Gap]:
    """The missing-evidence lines of an engine answer, one gap each."""
    return [
        Gap(code="missing-evidence", kind="unclassified", subject=subject, detail=str(line)[:1000])
        for line in list(lines or ())[:MAX_MISSING]
    ]


def _device(
    ctx: ToolContext, call: Call, session: Any, ref: str
) -> tuple[dict[str, Any], list[Gap], list[str]]:
    from hst.twin_tools.inventory import _resolve_device

    snap = call.snapshot
    try:
        uid = _resolve_device(pathmod.pinned(session, snap), ref)
    except ToolError as exc:
        exc.field = "subject"
        raise
    rib, bgp, ospf = ctx.readers.rib(snap), ctx.readers.bgp(snap), ctx.readers.ospf(snap)
    tables = {"rib": rib.coverage(uid), "bgp_routes": bgp.coverage(uid), "ospf_lsdb": ospf.coverage(uid)}
    unknowns = []
    if any(source.approximate for source in (rib, bgp, ospf)):
        unknowns.append(
            "no evidence manifest governs this run, so the side store records no table outcome; the "
            "tables read null"
        )
    gaps = [
        Gap(
            code=f"{table}-{outcome or 'not-recorded'}",
            kind="not-collected",
            dimension=table,
            subject=uid,
            detail=f"the snapshot recorded the device's {table} table as {outcome or 'not recorded'}",
        )
        for table, outcome in tables.items()
        if outcome not in _COMPLETE
    ]
    return {"kind": "device", "id": ref, "device_uid": uid, "tables": tables}, gaps, unknowns


def _assessment_run(
    ctx: ToolContext, call: Call, run_id: str
) -> tuple[dict[str, Any], list[Gap], list[str], list[dict[str, Any]]]:
    async def work(store: Any) -> Any:
        require(store, "get_analysis_run", "assessment runs")
        return await store.get_analysis_run(run_id)

    run = read_store(ctx, work)
    if run is None:
        raise ToolError("not_found", f"no assessment run {run_id!r}", field="subject")
    result = jsonable(run.result) if isinstance(run.result, dict) else {}
    gaps = [to_gap(g) for g in result.get("gaps") or () if isinstance(g, dict)]
    gaps += missing_evidence_gaps(result.get("missing_evidence"), run_id)
    if run.state != "completed":
        gaps.insert(
            0,
            Gap(
                code="run-not-completed",
                kind="unclassified",
                subject=run_id,
                detail=f"the run is {run.state}, so it records no complete result",
            ),
        )
    actions = [
        {
            "rank": index + 1,
            "recipe_id": action.get("recipe_id"),
            "target": f"{action.get('source')}/{action.get('host')}",
            "state": action.get("state"),
            "id": action.get("id"),
        }
        for index, action in enumerate(a for a in result.get("actions") or () if isinstance(a, dict))
    ][:MAX_ACTIONS]
    subject = {"kind": "assessment_run", "id": run_id, "assessment_id": run.assessment_id, "state": run.state}
    return subject, gaps, [], actions


def _application_connection(
    ctx: ToolContext, call: Call, session: Any, subject: ConnectionGapsSubject
) -> tuple[dict[str, Any], list[Gap], list[str]]:
    from hst.twin_tools.apps import published_reference, read_application, resolve_definition

    item = read_application(ctx, subject.application_id, None, field="subject")
    if not any(c.get("id") == subject.id for c in item.definition.get("connections", [])):
        raise ToolError(
            "not_found",
            f"no connection {subject.id!r} in application {item.id} revision {item.revision}",
            field="subject",
        )
    reference = published_reference(ctx, call.snapshot)
    resolved = resolve_definition(
        session, call.snapshot, reference, item, connection_ids=[subject.id], field="subject"
    )
    (connection,) = resolved["connections"]
    gaps = [
        to_gap({"code": issue.get("code"), "subject": issue.get("path"), "detail": issue.get("detail")})
        for issue in connection.get("issues") or ()
    ]
    described = {
        "kind": "application_connection",
        "id": subject.id,
        "application_id": item.id,
        "revision": item.revision,
        "readiness": connection.get("readiness"),
        "resolution_saved": False,
    }
    return described, gaps, ["the resolution is computed for this call and not saved"]


def _service_requirement(
    ctx: ToolContext, call: Call, session: Any, uid: str
) -> tuple[dict[str, Any], list[Gap], list[str]]:
    from fastapi import HTTPException

    from hst.assessment.direct import evaluate_request

    try:
        body = evaluate_request(
            ctx.settings,
            pathmod.pinned(session, call.snapshot),
            call.snapshot,
            intents=[],
            requirement=uid,
            request=None,
            mode="possible",
        )
    except HTTPException as exc:
        raise http_error(exc, field="subject") from None
    except ValueError as exc:
        raise ToolError("invalid_argument", str(exc), field="subject") from None
    body = jsonable(body)
    gaps = [to_gap(g) for g in body.get("gaps") or () if isinstance(g, dict)]
    gaps += missing_evidence_gaps(body.get("missing_evidence"), uid)
    return {"kind": "service_requirement", "id": uid}, gaps, []


def evidence_get_gaps(ctx: ToolContext, params: EvidenceGetGapsInput) -> str:
    subject = params.subject
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "evidence_get_gaps", params, session)
        tables: dict[str, str | None] = {}
        actions: list[dict[str, Any]] = []
        if subject.kind == "device":
            described, gaps, unknowns = _device(ctx, call, session, subject.id)
            tables = described.pop("tables")
            function = "hst.core.ribsource.RibSource.coverage"
        elif subject.kind == "assessment_run":
            described, gaps, unknowns, actions = _assessment_run(ctx, call, subject.id)
            function = "hst.assessment.store.AssessmentStore.get_analysis_run"
        elif isinstance(subject, ConnectionGapsSubject):
            described, gaps, unknowns = _application_connection(ctx, call, session, subject)
            function = "hst.applications.resolution.resolve_application"
        else:
            described, gaps, unknowns = _service_requirement(ctx, call, session, subject.id)
            function = "hst.assessment.direct.evaluate_request"
        distinct = list({gap.model_dump_json(): gap for gap in gaps}.values())
        items = [gap.model_dump(mode="json") for gap in distinct]
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        return call.finish(
            session,
            result={
                "subject": described,
                "tables": tables,
                "gaps": page_items,
                "gap_count": len(items),
                "collection_actions": actions,
            },
            evidence=Evidence(
                result=completeness("incomplete", missing=missing_of(gap.model_dump() for gap in distinct))
                if distinct
                else completeness("complete"),
                complete=not distinct,
                gaps=distinct[:MAX_GAPS],
                gaps_truncated=len(distinct) > MAX_GAPS,
                unknowns=unknowns[:MAX_MISSING],
            ),
            page=page,
            engine_function=function,
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="evidence_get_gaps",
            description=(
                "List the evidence gaps of one subject at the selected run. subject.kind: device gives "
                "the recorded outcome of the device's RIB, BGP route and OSPF tables, and a gap for each "
                "that is not complete; assessment_run gives the gaps and missing evidence a stored run "
                "recorded, with the collection actions of a troubleshooting result as read-only "
                "suggestions; application_connection (with application_id) gives the resolution issues of "
                "one catalog connection, computed and not saved; service_requirement gives the gaps of "
                "the requirement's evaluation with no change applied. The evidence result is incomplete, "
                "with each gap as what is missing, whenever a gap is present. Gaps page with the cursor."
            ),
            input_model=EvidenceGetGapsInput,
            result_model=EvidenceGetGapsResult,
            run=evidence_get_gaps,
        )
    )
