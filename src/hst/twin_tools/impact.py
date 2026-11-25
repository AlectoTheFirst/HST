"""The impact tools `impact_evaluate_service` and `impact_assess`.

`impact_evaluate_service` answers one service-impact question through
`evaluate_request`, the function of `POST /api/impact/evaluate`. The intent
cap and the engine choice are the cap and the choice of the route. The
three-valued answer of the engine is the result of the connection condition
before and after the change. The address buckets of the engine have the names
of the tool. `decided_change` and `open_change` hold what the change decidedly
or openly costs or adds. `open` holds the clients that the data does not
decide. `passes` and `fails` hold the clients that the condition is decided
for. The `application_connection` form resolves one connection of a catalog
application at the selected run, as `GET .../resolve` does, without saving
the result, and evaluates its compiled request. An unresolved connection is
not evaluated. Its answer is not established, with its resolution issues as
gaps.

`impact_assess` lists what depends on one device or one link, through the
bodies of `GET /api/impact` and `GET /api/impact/link`. The tool does not
evaluate whether a dependant fails without the subject. The answer is a list
of records, and its `missing` entries state the missing evaluation.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.results.project import condition_result, missing_from_gaps
from hst.results.words import QUANTIFIER_OF_MODE, record
from hst.results.words import Result as ResultOut
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    catalogue_spec,
    gap_list,
    http_error,
    jsonable,
    missing_of,
    unknowns_missing,
)
from hst.twin_tools.inventory import _resolve_device

# --- impact_evaluate_service ---------------------------------------------------------------


class _EvaluateInput(selectors.PagedInput):
    intents: list[selectors.Intent] = Field(
        default_factory=list,
        max_length=selectors.MAX_INTENTS,
        description=(
            "The change set, in the intent shape of the policy overlay. Empty asks what the run alone "
            "establishes."
        ),
    )
    mode: Literal["possible", "guaranteed"] = Field(
        default="possible",
        description=(
            "possible counts the condition as passing if one path or member works; guaranteed only if "
            "every path and member works."
        ),
    )


class RequirementForm(_EvaluateInput):
    """A declared ServiceRequirement."""

    form: Literal["requirement"]
    requirement: str = Field(min_length=1, max_length=512, description="The ServiceRequirement uid.")


class RequestForm(_EvaluateInput):
    """A request set stated inline."""

    form: Literal["request"]
    request: dict[str, Any] = Field(
        description=(
            "The request set: name, destination, sources (the client population), members (the "
            "destinations, each with name and addresses), condition, and optionally proto and port."
        )
    )


class ApplicationRevisionRef(BaseModel):
    """One revision of a catalog application."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=200, description="The application id.")
    revision: int = Field(ge=1, description="The application revision.")
    digest: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="The revision digest. When given, a revision with another digest is refused.",
    )


class ApplicationConnectionRef(BaseModel):
    """One connection of a catalog application, as the analysis sessions name it."""

    model_config = ConfigDict(extra="forbid")

    application: ApplicationRevisionRef
    service_id: str = Field(
        min_length=1, max_length=200, description="The service the connection is associated with."
    )
    connection_id: str = Field(min_length=1, max_length=200, description="The connection id.")


class ApplicationConnectionForm(_EvaluateInput):
    """One connection of a Business Application in the catalog."""

    form: Literal["application_connection"]
    application_connection: ApplicationConnectionRef


EvaluateForm = RequirementForm | RequestForm | ApplicationConnectionForm


class ImpactEvaluateServiceInput(RootModel[Annotated[EvaluateForm, Field(discriminator="form")]]):
    """form: requirement names a declared requirement; form: request states the request set
    inline; form: application_connection names one connection of a catalog application."""


class ImpactEvaluateServiceResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: str | None = None
    outcomes: dict[str, Any] | None = Field(
        default=None,
        description=(
            "before and after: the condition's result, with the clients for which it passes, fails or "
            "is not decided (passes, fails, open)"
        ),
    )
    decided_change: dict[str, Any] | None = Field(
        default=None, description="loss and gain: the clients the change decidedly costs or adds"
    )
    open_change: dict[str, Any] | None = Field(
        default=None,
        description="loss and gain: the clients the change can cost or add; contains decided_change",
    )
    open: dict[str, Any] | None = Field(
        default=None, description="before and after: the clients for which the condition is not decided"
    )
    passes: dict[str, Any] | None = Field(
        default=None, description="before and after: the clients for which the condition passes"
    )
    fails: dict[str, Any] | None = Field(
        default=None, description="before and after: the clients for which the condition fails"
    )
    missing_evidence: list[Any] | None = None
    evidence: dict[str, Any] | None = Field(
        default=None, description="the engine's evidence steps: count, truncated and one page of items"
    )


def _count(body: dict[str, Any], part: str, side: str) -> int:
    bucket = (body.get(part) or {}).get(side)
    if not isinstance(bucket, dict):
        return 0
    # A count past 2**53 is null, and `count_decimal` holds it.
    count = bucket.get("count")
    return int(count) if count is not None else int(bucket.get("count_decimal") or 0)


def whole_answer(body: dict[str, Any], mode: str | None) -> ResultOut:
    """The answer of the whole evaluation, which is the result of the side
    after the change.

    A body without outcomes answers from its buckets after the change. A
    failing client gives `does-not-hold`. Otherwise an open client gives
    `not-established`. Otherwise the answer is `holds`."""
    outcomes = body.get("outcomes") if isinstance(body.get("outcomes"), dict) else {}
    after = outcomes.get("after") if isinstance(outcomes, dict) else None
    result = after.get("result") if isinstance(after, dict) else None
    if isinstance(result, dict):
        return ResultOut.model_validate(result)
    quantifier = QUANTIFIER_OF_MODE.get(mode or "")
    value = (
        "does-not-hold"
        if _count(body, "fails", "after")
        else "not-established"
        if _count(body, "open", "after")
        else "holds"
    )
    return condition_result(
        value,
        quantifier=quantifier,
        missing=missing_from_gaps(g for g in body.get("gaps") or [] if isinstance(g, dict)),
        fallback="the evaluation after the change is open",
    )


def _application_request(
    ctx: ToolContext, session: Any, call: Call, ref: ApplicationConnectionRef
) -> tuple[dict[str, Any] | None, dict[str, Any], list[dict[str, Any]]]:
    """The compiled request of one catalog connection at the call's run, the
    `application_connection` block of the answer, and the resolution issues.
    The request is None when the connection is unresolved."""
    from hst.twin_tools.apps import published_reference, read_application, resolve_definition

    field = "application_connection"
    item = read_application(ctx, ref.application.id, ref.application.revision, field=field)
    if ref.application.digest is not None and ref.application.digest != item.digest:
        raise ToolError(
            "conflict",
            f"application {item.id} revision {item.revision} has digest {item.digest}; "
            "the digest given differs",
            field=field,
        )
    services = item.definition.get("services", [])
    service = next((s for s in services if s.get("id") == ref.service_id), None)
    if service is None or ref.connection_id not in service.get("connection_ids", []):
        raise ToolError(
            "not_found",
            f"connection {ref.connection_id} is not associated with service {ref.service_id} of "
            f"application {item.id} revision {item.revision}",
            field=field,
        )
    reference = published_reference(ctx, call.snapshot)
    resolved = resolve_definition(
        session, call.snapshot, reference, item, connection_ids=[ref.connection_id], field=field
    )
    (connection,) = resolved["connections"]
    issues = list(connection.get("issues") or [])
    ready = connection.get("readiness") == "ready" and connection.get("request") is not None
    block = {
        "application": {"id": item.id, "revision": item.revision, "digest": item.digest},
        "service_id": ref.service_id,
        "connection_id": ref.connection_id,
        "readiness": connection.get("readiness"),
        "request": connection.get("request"),
        "issues": issues,
        "resolution_digest": resolved["digest"],
        "resolution_saved": False,
    }
    return (connection["request"] if ready else None), block, issues


def impact_evaluate_service(
    ctx: ToolContext, params: RequirementForm | RequestForm | ApplicationConnectionForm
) -> str:
    from fastapi import HTTPException

    from hst.assessment.direct import evaluate_request

    field = (
        "requirement"
        if isinstance(params, RequirementForm)
        else "request"
        if isinstance(params, RequestForm)
        else "application_connection"
    )
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "impact_evaluate_service", params, session)
        request: dict[str, Any] | None = params.request if isinstance(params, RequestForm) else None
        extra: dict[str, Any] = {}
        if isinstance(params, ApplicationConnectionForm):
            from hst.twin_tools.apps import issue_gaps

            request, block, issues = _application_request(ctx, session, call, params.application_connection)
            extra["application_connection"] = block
            if request is None:
                gaps, gaps_truncated = issue_gaps(issues)
                return call.finish(
                    session,
                    result={"mode": params.mode, **extra},
                    evidence=Evidence(
                        result=condition_result(
                            "not-established",
                            quantifier=QUANTIFIER_OF_MODE.get(params.mode),
                            missing=missing_of(gap.model_dump() for gap in gaps),
                            fallback="the connection is unresolved at this run",
                        ),
                        gaps=gaps,
                        gaps_truncated=gaps_truncated,
                        unknowns=[
                            "the connection is unresolved at this run, so its request was not evaluated; "
                            "the gaps are the resolution issues"
                        ],
                    ),
                    engine_function="hst.applications.resolution.resolve_application",
                )
        try:
            body = evaluate_request(
                ctx.settings,
                pathmod.pinned(session, call.snapshot),
                call.snapshot,
                intents=[intent.model_dump(mode="json") for intent in params.intents],
                requirement=params.requirement if isinstance(params, RequirementForm) else None,
                request=request,
                mode=params.mode,
            )
        except HTTPException as exc:
            raise http_error(exc, field=field) from None
        except ValueError as exc:
            raise ToolError("invalid_argument", str(exc), field=field) from None
        body = jsonable(body)
        steps = body.get("evidence") if isinstance(body.get("evidence"), dict) else {}
        items = list(steps.get("items") or [])
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        result = {**body, "evidence": {**steps, "items": page_items}, **extra}
        answer = whole_answer(result, params.mode)
        gaps, gaps_truncated = gap_list(g for g in body.get("gaps") or [] if isinstance(g, dict))
        engine = getattr(ctx.settings, "analysis_engine", "legacy-v1") or "legacy-v1"
        return call.finish(
            session,
            result=result,
            evidence=Evidence(result=answer, gaps=gaps, gaps_truncated=gaps_truncated),
            page=page,
            engine=engine,
            engine_function="hst.assessment.direct.evaluate_pinned",
        )


# --- impact_assess -------------------------------------------------------------------------


class DeviceSubject(selectors.ToolInput):
    """What depends on one device."""

    subject: Literal["device"]
    device: selectors.DeviceRef


class LinkSubject(selectors.ToolInput):
    """What depends on one link, WAN circuit or tunnel."""

    subject: Literal["link"]
    link: str = Field(
        min_length=1,
        max_length=512,
        description="The uid of a WanLink, a cabled Port, a Tunnel, or an Equinix Fabric VirtualCircuit.",
    )


class ImpactAssessInput(RootModel[Annotated[DeviceSubject | LinkSubject, Field(discriminator="subject")]]):
    """subject: device assesses a device; subject: link assesses a link, circuit or tunnel."""


class ImpactAssessResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    subject: Literal["device", "link"]
    device_uid: str
    link_uid: str | None = None
    buckets: dict[str, dict[str, Any]] = Field(
        description="per bucket: the exact count, at most 500 items, and truncated"
    )


_DEVICE_BUCKETS = (
    "single_homed_prefixes",
    "single_homed_endpoints",
    "gateway_prefixes",
    "attached_endpoints",
    "redundancy_groups",
    "interfaces",
    "tunnels",
    "bgp_sessions",
    "fhrp_groups",
)
_LINK_BUCKETS = ("single_homed_prefixes", "single_homed_endpoints")


def impact_assess(ctx: ToolContext, params: DeviceSubject | LinkSubject) -> str:
    from fastapi import HTTPException

    from hst.app.routes import impact as impact_route

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "impact_assess", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        try:
            if isinstance(params, DeviceSubject):
                uid = _resolve_device(pinned, params.device)
                body = jsonable(impact_route.assess(pinned, uid))
                result: dict[str, Any] = {
                    "subject": "device",
                    "device_uid": uid,
                    "device": body["device"],
                    "buckets": {name: body[name] for name in _DEVICE_BUCKETS},
                }
                unknowns = [
                    "the buckets list what the run records as depending on the device; whether each "
                    "dependant fails without it is not evaluated"
                ]
                function = "hst.app.routes.impact.assess"
            else:
                body = jsonable(impact_route.assess_link(pinned, params.link))
                result = {
                    "subject": "link",
                    "device_uid": body["device"],
                    "link_uid": body["link"],
                    "circuit": body["circuit"],
                    "other_circuits": body["other_circuits"],
                    "parallel_circuits": body["parallel_circuits"],
                    "parallel_path": body["parallel_path"],
                    "not_parallel": body["not_parallel"],
                    "buckets": {name: body[name] for name in _LINK_BUCKETS},
                }
                unknowns = [
                    "the buckets list what the run records as single-homed to the link's device; whether "
                    "each dependant fails without the link is not evaluated, and no flow is traced again"
                ]
                if body["parallel_path"] == "not established":
                    unknowns.append(
                        "the device carries other circuits, and none is shown to be a second path "
                        "independent of this one (not_parallel gives the reason per circuit), so no "
                        "parallel path is established and the single-homed buckets are listed in full"
                    )
                function = "hst.app.routes.impact.assess_link"
        except HTTPException as exc:
            raise http_error(exc, field=params.subject) from None
        return call.finish(
            session,
            result=result,
            evidence=Evidence(
                result=record("recorded", missing=unknowns_missing(unknowns)), unknowns=unknowns
            ),
            engine_function=function,
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="impact_evaluate_service",
            description=(
                "Evaluate one application's success condition before and after a change set, over one "
                "run. form: requirement names a declared ServiceRequirement by uid; form: request states "
                "the request set inline; form: application_connection names one connection of a catalog "
                "application, which is resolved at the run without saving the resolution and needs a run "
                "with an evidence manifest; an unresolved connection is not evaluated, and its "
                "resolution issues are the gaps. intents is the change set, at most 50; empty asks what "
                "the run alone establishes. outcomes.before.result and outcomes.after.result answer "
                "whether the connection condition passes, fails or is not decided, with what is missing, "
                "under the mode: possible counts as passing if one path or member works, guaranteed only "
                "if every path and member works. decided_change is what the change decidedly costs or "
                "adds, open_change what it can cost or add and contains decided_change, open the clients "
                "the data does not decide, and passes and fails the clients the condition is decided "
                "for. The engine's evidence steps page with the cursor, each with its result; "
                "missing_evidence says what a not decided part would need."
            ),
            input_model=ImpactEvaluateServiceInput,
            result_model=ImpactEvaluateServiceResult,
            run=impact_evaluate_service,
        )
    )
    registry.register(
        catalogue_spec(
            name="impact_assess",
            description=(
                "List what the run records as depending on one subject. subject: device (a uid or "
                "hostname) returns buckets of single-homed and gateway prefixes, endpoints, redundancy "
                "groups, interfaces, tunnels, BGP sessions and FHRP groups. subject: link (a WanLink, "
                "cabled Port, Tunnel or VirtualCircuit uid) returns the link's device, its other "
                "circuits, and what is single-homed to that device when the link is its only circuit. "
                "Counts are exact and items are capped at 500 per bucket. Whether each dependant fails "
                "is not evaluated."
            ),
            input_model=ImpactAssessInput,
            result_model=ImpactAssessResult,
            run=impact_assess,
        )
    )
