"""The write tools.

`change_submit_simulation` saves a change simulation as an analysis session
and queues its run, through the service functions behind `POST
/api/analysis-sessions` and `POST /api/analysis-sessions/{id}/runs`.
`app_save_application` saves a revision of a Business Application
definition through `save_definition`, as `POST /api/business-applications`
and `PUT /api/business-applications/{id}` do. `assessment_submit_run` queues
an analysis of a saved assessment through the service function behind `POST
/api/assessments/{id}/analyses`, and `assessment_cancel_run` cancels a run as
`POST /api/analysis-jobs/{id}/cancel` does.

Each tool needs `changes.write`, the permission of those routes. The registry
offers the tools only on the `mcp` surface, to a personal access token with
scope `read-write` (`hst.app.ai.registry.refusal`). No confirmation step
precedes a write. The records have the user of the token as their author, and
the per-actor cap on unfinished analyses applies. A queued run is pinned to an
immutable snapshot reference. A run without an evidence manifest raises
`snapshot_not_published`.

Each tool answers with the envelope. The evidence of the answer is the record
`stored`. A write records a request. The queued run computes the result, and
`change_get_simulation` and `assessment_read` read it.

The module imports no web framework at import time. A tool body imports the
route module whose service function it calls.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError

from hst.app.ai.registry import (
    ToolContext,
    ToolError,
    ToolLimits,
    ToolRegistry,
    ToolSpec,
    invalid_argument,
)
from hst.core import db as dbmod
from hst.results.words import record as completeness
from hst.twin_tools import selectors
from hst.twin_tools.apps import published_reference
from hst.twin_tools.assessment import snapshot_matches
from hst.twin_tools.change import MAX_FLOWS, MAX_SITES, SimFlow
from hst.twin_tools.envelope import MCP_SURFACES, Call, Evidence, catalogue_spec, http_error, jsonable
from hst.twin_tools.stores import read_store, require

# The maximum count of protected requirements and the maximum routing
# follow-on depth of one simulation, as in `hst.analysis.contracts`.
MAX_PROTECTIONS = 50
MAX_SIMULATION_DEPTH = 64

# The `Analyze` fields that `options` sets. `kind`, `snapshot` and
# `before_snapshot` are arguments of their own.
OPTION_FIELDS = (
    "limits",
    "allowed_targets",
    "allowed_kinds",
    "protected",
    "targets",
    "domains",
    "scope",
    "cost_order",
)

# The time, from the start of the write, in which change_submit_simulation
# and assessment_submit_run wait for the cycle lock to queue a run. It ends 5 s
# before the app store bound (`ToolLimits.timeout_s`). When a collection cycle
# holds the lock for that time, the call answers `timeout` and reports the
# saved session or that no run was queued.
LOCK_DEADLINE_S = ToolLimits.timeout_s - 5.0

ExecutionState = Literal["queued", "running", "completed", "failed", "cancelled"]
AnalysisKind = Literal["evaluate", "troubleshoot", "regression", "repair", "resilience", "verify"]


def _actor(ctx: ToolContext) -> int:
    """The token user a write records as its author."""
    principal = ctx.principal
    if principal is None or principal.user_id is None:
        raise ToolError("forbidden", "a write tool runs only for a personal access token user")
    return principal.user_id


def _write_error(exc: Exception) -> ToolError | None:
    """The typed error of a failed write, or None for an error `read_store` maps.

    A stale revision is `conflict`, the per-actor cap is `limit_exceeded`, a
    route helper's `HTTPException` maps by its status, and any other
    `ValueError` or `TypeError` is `invalid_argument`.
    """
    from fastapi import HTTPException

    from hst.assessment.store import AnalysisCapacityError, RevisionConflict

    if isinstance(exc, HTTPException):
        return http_error(exc)
    if isinstance(exc, RevisionConflict):
        return ToolError("conflict", str(exc))
    if isinstance(exc, AnalysisCapacityError):
        return ToolError("limit_exceeded", str(exc), retryable=True)
    if isinstance(exc, ValueError | TypeError):
        return ToolError("invalid_argument", str(exc))
    return None


def _write[T](ctx: ToolContext, work: Callable[[Any], Awaitable[T]]) -> T:
    """The result of `work(store)` on the app store, with its errors typed."""

    async def typed(store: Any) -> T:
        try:
            return await work(store)
        except ToolError:
            raise
        except Exception as exc:
            error = _write_error(exc)
            if error is None:
                raise
            raise error from None

    return read_store(ctx, typed)


def _invalid(exc: ValidationError, name: str) -> ToolError:
    """The `invalid_argument` error for an argument whose content a stored
    model refused. Each failing path in the message starts with the name of
    the argument."""
    problems = "; ".join(
        f"{'.'.join([name, *(str(part) for part in error['loc'])])}: {error['msg']}" for error in exc.errors()
    )
    return ToolError("invalid_argument", f"invalid arguments: {problems}", field=name)


def write_spec(
    *,
    name: str,
    description: str,
    input_model: type[BaseModel],
    result_model: type[Any],
    run: Callable[[ToolContext, Any], str],
    destructive: bool,
    idempotent: bool,
) -> ToolSpec:
    """A catalogue spec of kind `write` that needs `changes.write`, offered on
    the `mcp` surface only. `destructive` and `idempotent` set its
    annotations."""
    spec = catalogue_spec(
        name=name,
        description=description,
        input_model=input_model,
        result_model=result_model,
        run=run,
        permission="changes.write",
    )
    return dataclasses.replace(
        spec, kind="write", surfaces=MCP_SURFACES, destructive=destructive, idempotent=idempotent
    )


# --- change_submit_simulation --------------------------------------------------------------


class RevisionRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=200)
    revision: int = Field(ge=1)
    digest: str | None = Field(default=None, min_length=1, max_length=128)


class SimulationScopeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flows: list[SimFlow] = Field(
        default_factory=list,
        max_length=MAX_FLOWS,
        description="The flows to trace before and after the change. Empty, flows are derived from it.",
    )
    sites: list[str] = Field(
        default_factory=list, max_length=MAX_SITES, description="Narrow the routing follow-on to these sites."
    )


class SimulationBoundsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    depth: int | None = Field(
        default=None,
        ge=1,
        le=MAX_SIMULATION_DEPTH,
        description="How many levels of route dependency the routing follow-on walks; omitted, one.",
    )
    max_flows: int = Field(default=50, ge=1, le=200, description="The most flows scope.flows may hold.")
    max_seconds: float = Field(default=30, gt=0, le=300, description="The run's time bound in seconds.")


class ProtectionInput(BaseModel):
    """One protected requirement the run evaluates before and after the change."""

    model_config = ConfigDict(extra="allow")

    kind: Literal["inline", "application_connection"] = Field(
        description=(
            "inline also takes name and request (name, destination, sources, members and condition). "
            "application_connection also takes reference (application {id, revision, digest}, "
            "service_id, connection_id) and resolved_scope_digest, the digest of a saved resolution of "
            "that application at the same snapshot."
        )
    )
    desired: Literal["holds", "isolated"] = Field(
        default="holds", description="Whether the requirement must keep holding or must stay isolated."
    )


class ChangeSubmitSimulationInput(selectors.ToolInput):
    """Save a change simulation as an analysis session and queue its run."""

    title: str = Field(min_length=1, max_length=200, description="The session title.")
    changes: list[selectors.Intent] = Field(
        min_length=1,
        max_length=selectors.MAX_INTENTS,
        description="The change set, in the intent shape change_simulate takes.",
    )
    change_revision: RevisionRef | None = Field(
        default=None, description="The saved change revision the changes come from, when there is one."
    )
    scope: SimulationScopeInput | None = None
    bounds: SimulationBoundsInput | None = None
    protected: list[ProtectionInput] = Field(default_factory=list, max_length=MAX_PROTECTIONS)


class ChangeSubmitSimulationResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    session_id: str
    session_revision: int
    run_id: str
    execution: ExecutionState
    snapshot_reference: dict[str, Any] = Field(
        description="the immutable snapshot reference the run is pinned to"
    )


def _unqueued(created: dict[str, Any], error: ToolError) -> ToolError:
    """`error` for a run that was not queued, with the saved session in the
    message. The error is not retryable. A retry saves another session."""
    return ToolError(
        error.code,
        f"analysis session {created['id']} is saved as revision {created['revision']}, and its run "
        f"was not queued: {error.message}",
        field=error.field,
    )


def change_submit_simulation(ctx: ToolContext, params: ChangeSubmitSimulationInput) -> str:
    from hst.analysis.contracts import SimulationAnalysisInput
    from hst.app.routes import analysis_sessions as sessions

    actor = _actor(ctx)
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "change_submit_simulation", params, session)
        reference = published_reference(ctx, call.snapshot)
        document: dict[str, Any] = {
            "snapshot": reference,
            **params.model_dump(mode="json", include={"changes", "change_revision", "scope", "protected"}),
        }
        if params.bounds is not None:
            document["bounds"] = params.bounds.model_dump(mode="json")
        try:
            value = SimulationAnalysisInput.model_validate(document)
        except ValidationError as exc:
            raise invalid_argument(exc) from None
        if value.scope is not None and len(value.scope.flows) > value.bounds.max_flows:
            raise ToolError(
                "invalid_argument",
                f"scope.flows holds {len(value.scope.flows)} flows, more than bounds.max_flows "
                f"({value.bounds.max_flows})",
                field="scope",
            )

        saved: list[dict[str, Any]] = []

        async def work(store: Any) -> dict[str, Any]:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + LOCK_DEADLINE_S
            require(store, "create_analysis_session", "analysis sessions")
            # This call refuses at the cap before a session is saved. Queueing
            # the run checks the cap again.
            await store.ensure_analysis_capacity(actor, 1)
            created = await sessions.save_session(
                store, ctx.settings, sessions.CreateSession(title=params.title, input=value), actor
            )
            saved.append(created)
            reviewed = sessions.ExecuteSession(
                session_revision=created["revision"], input_digest=created["input_digest"]
            )
            try:
                return await sessions.run_session(
                    store,
                    ctx.settings,
                    created["id"],
                    reviewed,
                    actor,
                    lock_wait_s=max(deadline - loop.time(), 0.0),
                )
            except sessions.CycleLockWait as exc:
                raise _unqueued(created, ToolError("timeout", str(exc))) from None
            except Exception as exc:
                error = _write_error(exc)
                if error is None:
                    raise
                raise _unqueued(created, error) from None

        try:
            executed = _write(ctx, work)
        except ToolError as error:
            # the app store failed, or its bound ended the call, after the session was saved
            if not saved or error.code not in ("timeout", "engine_unavailable") or not error.retryable:
                raise
            raise ToolError(
                error.code,
                f"analysis session {saved[0]['id']} is saved as revision {saved[0]['revision']}, and the "
                f"call could not confirm that its run was queued: {error.message}",
            ) from None
        run = executed["definition"]["runs"][0]
        return call.finish(
            session,
            result={
                "session_id": executed["id"],
                "session_revision": executed["revision"],
                "run_id": run["id"],
                "execution": run["execution"],
                "snapshot_reference": jsonable(reference),
            },
            evidence=Evidence(result=completeness("stored")),
            engine_function="hst.app.routes.analysis_sessions.run_session",
        )


# --- app_save_application ------------------------------------------------------------------


class AppSaveApplicationInput(selectors.ToolInput):
    """Save a revision of a Business Application definition."""

    definition: dict[str, Any] = Field(
        description=(
            "The complete definition in the Business Application schema, version 1 or 2: "
            "schema_version, kind BusinessApplication, id, name, groups, connections and services, as "
            "app_applications mode: get returns it. A placeholder member needs schema_version 2 and "
            "state draft. It replaces the stored definition, so an entity it leaves out is removed "
            "from the new revision."
        )
    )
    expected_revision: int = Field(
        default=0,
        ge=0,
        description=(
            "0 creates a new application. To update one, its newest revision number; another number "
            "is the error conflict."
        ),
    )


class AppSaveApplicationResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    revision: int
    digest: str
    unchanged: bool = Field(
        description="true when the definition equals the newest revision, which is returned and not repeated"
    )


def app_save_application(ctx: ToolContext, params: AppSaveApplicationInput) -> str:
    from hst.applications import service as application_service
    from hst.applications.models import BusinessApplicationDefinition

    actor = _actor(ctx)
    try:
        definition = BusinessApplicationDefinition.model_validate(params.definition)
    except ValidationError as exc:
        raise _invalid(exc, "definition") from None
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "app_save_application", params, session)

        async def work(store: Any) -> Any:
            require(store, "create_application_revision", "Business Applications")
            # The revision records the origin of a direct API save, as the routes do by default.
            origin = await application_service.revision_origin(store, "api")
            return await application_service.save_definition(
                store, definition, expected_revision=params.expected_revision, actor=actor, origin=origin
            )

        saved = _write(ctx, work)
        return call.finish(
            session,
            result={
                "id": saved.id,
                "name": saved.name,
                "revision": saved.revision,
                "digest": saved.digest,
                "created_at": saved.created_at,
                "unchanged": saved.revision == params.expected_revision,
            },
            evidence=Evidence(result=completeness("stored")),
            engine_function="hst.applications.service.save_definition",
        )


# --- assessment_submit_run -----------------------------------------------------------------

RunId = Annotated[str | None, Field(pattern=r"^[0-9]{1,19}$"), BeforeValidator(selectors._digits)]

# The snapshot selector of `assessment_submit_run`. It has no `latest` default.
SubmitSnapshot = Annotated[
    str | None,
    Field(
        pattern=selectors.SNAPSHOT_PATTERN,
        description=(
            "A run id, or 'latest' for the published pointer. Omitted, the run the assessment saved, "
            "or the published pointer when it saved none; verify always uses the pointer when omitted. "
            "The run must have an evidence manifest."
        ),
    ),
    BeforeValidator(selectors._digits),
]


class AssessmentSubmitRunInput(selectors.ToolInput):
    """Queue an analysis of a saved assessment."""

    snapshot: SubmitSnapshot = None  # type: ignore[assignment]
    assessment_id: str = Field(
        min_length=1,
        max_length=200,
        description="The assessment id, as assessment_read mode: list returns it.",
    )
    kind: AnalysisKind = Field(
        default="evaluate",
        description=(
            "evaluate, troubleshoot, regression (needs before_snapshot), repair (needs "
            "options.allowed_targets), resilience (needs options.targets) or verify (needs a recorded "
            "deployment)."
        ),
    )
    before_snapshot: RunId = Field(
        default=None, description="The run a regression compares against. It needs an evidence manifest."
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "The other analysis settings, as POST /api/assessments/{id}/analyses takes them: limits, "
            "allowed_targets, allowed_kinds, protected, targets, domains, scope and cost_order."
        ),
    )


class AssessmentSubmitRunResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    state: str
    assessment_id: str
    assessment_revision: int
    kind: str
    snapshot_refs: list[dict[str, Any]] = Field(description="the snapshot references the run is pinned to")


def _bind_published(
    ctx: ToolContext, session: Any, selector: str, *, field: str, source: str | None = None
) -> Any:
    """The run that `selector` selects, checked for a retained graph and an
    evidence manifest. `source` describes the origin of a selector that the
    caller did not send. An error message starts with `source`."""
    try:
        snap = selectors.bind(ctx, session, selector, field=field)
        published_reference(ctx, snap, field=field)
    except ToolError as exc:
        if source is None:
            raise
        raise ToolError(
            exc.code, f"{source}: {exc.message}", retryable=exc.retryable, field=exc.field
        ) from None
    return snap


def assessment_submit_run(ctx: ToolContext, params: AssessmentSubmitRunInput) -> str:
    from hst.app.routes import assessments as assessment_routes
    from hst.assessment.models import Analyze

    actor = _actor(ctx)
    unknown = sorted(set(params.options) - set(OPTION_FIELDS))
    if unknown:
        raise ToolError(
            "invalid_argument",
            f"options takes {', '.join(OPTION_FIELDS)}; {', '.join(unknown)} is not one of them",
            field="options",
        )
    if params.kind == "regression" and params.before_snapshot is None:
        raise ToolError("invalid_argument", "a regression needs before_snapshot", field="before_snapshot")
    with dbmod.session(ctx.settings, access_mode="READ") as session:

        async def read(store: Any) -> Any:
            require(store, "get_assessment", "assessments")
            return await store.get_assessment(params.assessment_id)

        item = read_store(ctx, read)
        if item is None:
            raise ToolError("not_found", f"no assessment {params.assessment_id!r}", field="assessment_id")
        # `submit` reads an omitted snapshot the same way
        saved = None if params.kind == "verify" else item.definition.get("snapshot")
        source: str | None = None
        if params.snapshot is not None:
            selector = params.snapshot
        elif saved:
            selector, source = str(saved), f"the assessment's saved snapshot {saved}"
        else:
            selector, source = selectors.LATEST, "the published pointer"
        snap = _bind_published(ctx, session, selector, field="snapshot", source=source)
        if params.before_snapshot is not None:
            _bind_published(ctx, session, params.before_snapshot, field="before_snapshot")
        try:
            body = Analyze.model_validate(
                {
                    **params.options,
                    "kind": params.kind,
                    # An omitted snapshot stays None. `submit` then uses the saved snapshot.
                    "snapshot": None if params.snapshot is None else snap.snapshot_id,
                    "before_snapshot": params.before_snapshot,
                }
            )
        except ValidationError as exc:
            raise _invalid(exc, "options") from None
        call = Call.open(
            ctx,
            "assessment_submit_run",
            params.model_copy(update={"snapshot": selector}),
            session,
            snapshot=snap,
        )

        waited: list[bool] = []

        async def work(store: Any) -> Any:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + LOCK_DEADLINE_S
            require(store, "enqueue_analysis", "assessment runs")
            try:
                return await assessment_routes.submit_analysis(
                    store,
                    ctx.settings,
                    params.assessment_id,
                    body,
                    actor,
                    lock_wait_s=max(deadline - loop.time(), 0.0),
                )
            except assessment_routes.CycleLockWait as exc:
                waited.append(True)
                raise ToolError("timeout", f"{exc}; no run was queued", retryable=True) from None

        try:
            run = _write(ctx, work)
        except ToolError as error:
            # the app store bound ended the call after the cycle lock was taken
            if error.code != "timeout" or not error.retryable or waited:
                raise
            raise ToolError(
                "timeout",
                f"the call could not confirm that a run of assessment {params.assessment_id} was queued: "
                f"{error.message}; read its newest runs with assessment_read, mode: list, before a retry",
            ) from None
        return call.finish(
            session,
            result={
                "run_id": run.id,
                "state": run.state,
                "assessment_id": run.assessment_id,
                "assessment_revision": run.assessment_revision,
                "kind": run.kind,
                "snapshot_refs": jsonable(run.snapshot_refs),
            },
            evidence=Evidence(result=completeness("stored")),
            engine_function="hst.app.routes.assessments.submit_analysis",
        )


# --- assessment_cancel_run -----------------------------------------------------------------


class AssessmentCancelRunInput(selectors.ToolInput):
    """Cancel a queued or running analysis run."""

    run_id: str = Field(
        min_length=1,
        max_length=200,
        description=(
            "The run id, as assessment_submit_run, change_submit_simulation or assessment_read returns it."
        ),
    )


class AssessmentCancelRunResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_id: str
    state: str
    cancel_requested: bool
    snapshot_matches: bool | None = Field(
        default=None, description="whether the selected snapshot is one the run is pinned to"
    )


def assessment_cancel_run(ctx: ToolContext, params: AssessmentCancelRunInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "assessment_cancel_run", params, session)

        async def work(store: Any) -> Any:
            require(store, "cancel_analysis", "assessment runs")
            return await store.cancel_analysis(params.run_id)

        run = _write(ctx, work)
        if run is None:
            raise ToolError("not_found", f"no analysis run {params.run_id!r}", field="run_id")
        return call.finish(
            session,
            result={
                "run_id": run.id,
                "state": run.state,
                "cancel_requested": run.cancel_requested,
                "assessment_id": run.assessment_id,
                "kind": run.kind,
                "snapshot_matches": snapshot_matches(run.snapshot_refs, call.snapshot.snapshot_id),
            },
            evidence=Evidence(result=completeness("stored")),
            engine_function="hst.assessment.store.AssessmentStoreMixin.cancel_analysis",
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        write_spec(
            name="change_submit_simulation",
            description=(
                "Save a change simulation as an analysis session and queue its run, as Save as simulation "
                "does in the change-simulation workspace. The run is pinned to the selected snapshot, "
                "which needs an evidence manifest. It traces scope.flows, or flows derived from the "
                "changes, before and after the change set, and evaluates each protected requirement. "
                "Returns the session and run ids; change_get_simulation reads the result once the run "
                "completes. At most 8 unfinished analyses per user. Needs changes.write and a token with "
                "scope read-write."
            ),
            input_model=ChangeSubmitSimulationInput,
            result_model=ChangeSubmitSimulationResult,
            run=change_submit_simulation,
            destructive=False,
            idempotent=False,
        )
    )
    registry.register(
        write_spec(
            name="app_save_application",
            description=(
                "Save a Business Application definition as a new revision in the catalog. "
                "expected_revision 0 creates the application; to update one, pass its newest revision "
                "number, and a stale number is the error conflict. Earlier revisions are kept. A "
                "definition equal to the newest revision adds none. Needs changes.write and a token with "
                "scope read-write."
            ),
            input_model=AppSaveApplicationInput,
            result_model=AppSaveApplicationResult,
            run=app_save_application,
            # The tool replaces the stored definition. An entity that the new
            # definition leaves out is removed.
            destructive=True,
            idempotent=False,
        )
    )
    registry.register(
        write_spec(
            name="assessment_submit_run",
            description=(
                "Queue an analysis run of a saved assessment. Without snapshot the run uses the snapshot "
                "the assessment saved, or the published pointer when it saved none; the run needs an "
                "evidence manifest. kind selects evaluate, troubleshoot, regression, repair, resilience "
                "or verify, and options carries the other analysis settings. Returns the run id and "
                "state; assessment_read mode: run reads the result once the run completes. At most 8 "
                "unfinished analyses per user. Needs changes.write and a token with scope read-write."
            ),
            input_model=AssessmentSubmitRunInput,
            result_model=AssessmentSubmitRunResult,
            run=assessment_submit_run,
            destructive=False,
            idempotent=False,
        )
    )
    registry.register(
        write_spec(
            name="assessment_cancel_run",
            description=(
                "Cancel an analysis run, an assessment run or a simulation run. A queued run is cancelled "
                "at once. A running run is asked to stop and ends cancelled when its worker next checks. "
                "A finished run is returned unchanged. Needs changes.write and a token with scope "
                "read-write."
            ),
            input_model=AssessmentCancelRunInput,
            result_model=AssessmentCancelRunResult,
            run=assessment_cancel_run,
            destructive=True,
            idempotent=True,
        )
    )
