"""The change simulation tools `change_simulate` and `change_get_simulation`.

`change_simulate` runs `simulate_change`, the engine of the change-simulation
workspace and its export, synchronously under `graph.read`, as the export
route does. The verdict of each flow after the change maps to the statement
that the rules permit the flow. A permitted flow is permitted, a blocked flow
is blocked by the deciding rule, and an indeterminate flow is not decided.
When no flows are given, the engine derives at most 8 flows from the change
set. Those flows are a sample, and the whole answer is then `per-item`.

`change_get_simulation` reads one durable simulation run of an analysis
session from the app store, one section at a time.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.results.trace import flow_side_result
from hst.results.words import Result, from_engine, record
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    gap_list,
    jsonable,
    missing_of,
    unknowns_missing,
    whole_result,
)

# `fw_overlay_read._MAX_WITHDRAWAL_DEPTH`, the deepest routing follow-on the engine walks.
MAX_DEPTH = 8
MAX_FLOWS = 50
MAX_SITES = 20


def flow_evidence(entry: dict[str, Any]) -> ItemEvidence:
    """The evidence of one simulated flow.

    It is the result of the flow after the change. A flow with a model error
    is not decided.
    """
    after = entry.get("after") or {}
    error = entry.get("model_error") if isinstance(entry.get("model_error"), dict) else None
    if error:
        missing = [Missing(code=str(error.get("kind")), detail=str(error.get("detail") or error.get("kind")))]
        return ItemEvidence.of(
            from_engine("rule-permits", "not-established", missing=missing), basis="derived"
        )
    stated = after.get("result")
    result = Result.model_validate(stated) if isinstance(stated, dict) else flow_side_result(after)
    return ItemEvidence.of(result, basis="derived")


def derived_unknowns(simulation: dict[str, Any]) -> list[str]:
    """The unknowns of the envelope when the engine derived the flows."""
    from hst.app.fw_overlay_read import _MAX_DERIVED_FLOWS

    unknowns = [
        f"no flows were given, so the flows were derived from the change set: at most {_MAX_DERIVED_FLOWS} "
        "derived flows, a sample of the traffic the change affects"
    ]
    untraced = int(simulation.get("flows_derived_not_traced") or 0)
    if untraced:
        unknowns.append(f"{untraced} more derived candidate flows were not traced")
    return unknowns


def flows_result(items: list[dict[str, Any]], unknowns: list[str], *, derived: bool) -> Result:
    """The answer over the flows.

    It is the one result that every flow states, or `per-item` when the flows
    differ. Derived flows are a sample of the traffic, and their whole answer
    is `per-item`."""
    if derived and items:
        return record("per-item", missing=unknowns_missing(unknowns))
    return whole_result((item["evidence"]["result"] for item in items), unknowns=unknowns)


def _with_evidence(flows: list[Any]) -> list[dict[str, Any]]:
    return [
        {**flow, "evidence": flow_evidence(flow).model_dump(mode="json")}
        for flow in flows
        if isinstance(flow, dict)
    ]


def _routing_gaps(simulation: dict[str, Any]) -> tuple[list[Any], bool]:
    prediction = simulation.get("routing_prediction") or {}
    entries = [*(prediction.get("gaps_before") or []), *(prediction.get("gaps_after") or [])]
    return gap_list(entry for entry in entries if isinstance(entry, dict))


# --- change_simulate -----------------------------------------------------------------------


class SimFlow(BaseModel):
    """One flow, as the change-simulation export and the analysis sessions take it."""

    model_config = ConfigDict(extra="forbid")

    src: str = Field(min_length=1, max_length=500)
    dst: str = Field(min_length=1, max_length=500)
    port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = Field(default=None, min_length=1, max_length=40)


class ChangeSimulateInput(selectors.ToolInput):
    """Trace flows before and after a firewall, NAT, zone, routing or MTU change."""

    intents: list[selectors.Intent] = Field(
        min_length=1,
        max_length=selectors.MAX_INTENTS,
        description=(
            "The change set: fw_rule, nat_rule, zone, bgp_session.shut, ospf and interface.set_mtu kinds."
        ),
    )
    flows: list[SimFlow] | None = Field(
        default=None,
        max_length=MAX_FLOWS,
        description="The flows to trace. Omitted or empty, at most 8 flows are derived from the change set.",
    )
    sites: list[Annotated[str, Field(max_length=64)]] | None = Field(
        default=None, max_length=MAX_SITES, description="Narrow the routing follow-on to these sites."
    )
    depth: int | None = Field(
        default=None,
        ge=1,
        le=MAX_DEPTH,
        description="How many levels of route dependency the routing follow-on walks; omitted, one.",
    )


class ChangeSimulateResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    flow_count: int
    flows: list[dict[str, Any]]
    flows_derived_count: int | None = None
    routing_prediction: dict[str, Any] | None = None
    model_errors: list[dict[str, Any]]


def change_simulate(ctx: ToolContext, params: ChangeSimulateInput) -> str:
    from hst.app import fw_overlay_read
    from hst.simul.fw_overlay import ProposalError

    flows = [flow.model_dump(mode="json", exclude_none=True) for flow in params.flows or ()]
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "change_simulate", params, session)
        snap = call.snapshot
        readers = ctx.readers
        try:
            body = fw_overlay_read.simulate_change(
                pathmod.pinned(session, snap),
                intents=[intent.model_dump(mode="json") for intent in params.intents],
                flows=flows or None,
                depth=params.depth,
                sites=params.sites or None,
                rib=readers.rib(snap),
                bgp=readers.bgp(snap),
                ospf=readers.ospf(snap),
                source_kinds=ctx.source_kinds,
            )
        except pathmod.NoRun as exc:
            raise ToolError("snapshot_not_published", str(exc)) from None
        except (ProposalError, ValueError) as exc:
            raise ToolError("invalid_argument", str(exc), field="intents") from None
        body = jsonable(body)
        body["flows"] = _with_evidence(body.get("flows") or [])
        derived = not flows
        unknowns = derived_unknowns(body) if derived else []
        gaps, gaps_truncated = _routing_gaps(body)
        return call.finish(
            session,
            result=body,
            evidence=Evidence(
                result=flows_result(body["flows"], unknowns, derived=derived),
                unknowns=unknowns,
                gaps=gaps,
                gaps_truncated=gaps_truncated,
            ),
            engine="hst.app.fw_overlay_read",
            engine_function="hst.app.fw_overlay_read.simulate_change",
        )


# --- change_get_simulation -----------------------------------------------------------------


class ChangeGetSimulationInput(selectors.PagedInput):
    """One durable simulation run of an analysis session."""

    session_id: str = Field(min_length=1, max_length=200, description="The analysis session id.")
    run_id: str = Field(min_length=1, max_length=200, description="The run id, from the session's runs.")
    section: Literal["summary", "flows", "protected", "routing"] = Field(
        default="summary",
        description=(
            "summary: states and counts; flows: the traced flows a page at a time; protected: the "
            "protected requirements a page at a time; routing: the routing follow-on and prediction."
        ),
    )


class ChangeGetSimulationResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    execution: str
    result: dict[str, Any] | None = Field(
        default=None, description="the run's answer; null until the run is completed"
    )
    coverage: str
    section: Literal["summary", "flows", "protected", "routing"]
    snapshot_matches: bool | None = Field(
        default=None, description="whether the run was computed from the selected snapshot"
    )
    items: list[dict[str, Any]]
    error: str | None = None


async def _read_run(ctx: ToolContext, session_id: str, run_id: str) -> Any:
    """The run `run_id` of analysis session `session_id`, from the app store.

    Without an app store on the context, a store is opened from the settings
    and disposed of before returning.
    """
    from hst.app.routes.analysis_sessions import stored_session

    store = ctx.store
    owned = store is None
    if store is None:
        from hst.app.store.pg import PgStore

        store = PgStore(ctx.settings.postgres_dsn, ctx.settings.postgres_ca_file)
    try:
        if not hasattr(store, "get_analysis_session"):
            raise ToolError("engine_unavailable", "the app store keeps no analysis sessions")
        record = await store.get_analysis_session(session_id)
        if record is None:
            raise ToolError("not_found", f"no analysis session {session_id!r}", field="session_id")
        definition = stored_session(record.definition)
        if not any(item.id == run_id for item in definition.runs):
            raise ToolError(
                "not_found", f"no run {run_id!r} in analysis session {session_id!r}", field="run_id"
            )
        run = await store.get_analysis_run(run_id)
        if run is None:
            raise ToolError("not_found", f"no analysis run {run_id!r}", field="run_id")
        return run
    finally:
        if owned:
            await store.dispose()


def _protected_evidence(entry: dict[str, Any]) -> ItemEvidence:
    """The evidence of a protected requirement, which is its result after the change."""
    body = entry.get("result") or {}
    after = (body.get("outcomes") or {}).get("after", {}).get("result")
    if isinstance(after, dict):
        return ItemEvidence.of(Result.model_validate(after), basis="computed")
    missing = missing_of(body.get("gaps") or ()) or [
        Missing(code="protection-not-decided", detail="the evaluation of the protected requirement is open")
    ]
    return ItemEvidence.of(
        from_engine("condition-holds", "not-established", missing=missing), basis="computed"
    )


def change_get_simulation(ctx: ToolContext, params: ChangeGetSimulationInput) -> str:
    from sqlalchemy.exc import SQLAlchemyError

    from hst.app.ai.redact import redact
    from hst.app.routes.analysis_sessions import _coverage, _result

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "change_get_simulation", params, session)
        try:
            run = ctx.call_async(_read_run(ctx, params.session_id, params.run_id))
        except TimeoutError:
            raise ToolError("timeout", "the app store did not answer in time", retryable=True) from None
        except (OSError, SQLAlchemyError) as exc:
            raise ToolError(
                "engine_unavailable",
                redact(f"the app store could not be read: {type(exc).__name__}: {exc}"),
                retryable=True,
            ) from None
        completed = run.state == "completed"
        document = jsonable(run.result or {})
        simulation = document.get("simulation") or {}
        refs = run.snapshot_refs or []
        recorded = str(refs[0].get("snapshot")) if refs and isinstance(refs[0], dict) else None
        matches = None if recorded is None else recorded == call.snapshot.snapshot_id
        result: dict[str, Any] = {
            "session_id": params.session_id,
            "run_id": params.run_id,
            "execution": run.state,
            "result": _result(run.result) if completed else None,
            "coverage": _coverage(run.result) if completed else "not_started",
            "section": params.section,
            "snapshot_refs": jsonable(refs),
            "snapshot_matches": matches,
            "error": run.error,
            "items": [],
        }
        unknowns = []
        if matches is False:
            unknowns.append(
                f"the run was computed from run {recorded}, and the selected snapshot is "
                f"{call.snapshot.snapshot_id}"
            )
        if not completed:
            unknowns.append(f"the run is {run.state}, so it records no complete result")
        page = None
        whole = record("stored", missing=unknowns_missing(unknowns))
        gaps, gaps_truncated = _routing_gaps(simulation)
        if params.section == "summary":
            result["summary"] = {
                key: value for key, value in simulation.items() if not isinstance(value, list | dict)
            }
            result["protected_count"] = len(document.get("protected") or [])
        elif params.section == "routing":
            result["routing"] = {
                "consequence": simulation.get("routing_consequence"),
                "prediction": simulation.get("routing_prediction"),
            }
        else:
            if params.section == "flows":
                items = _with_evidence(simulation.get("flows") or [])
                derived = "flows_derived_count" in simulation
                if derived:
                    unknowns += derived_unknowns(simulation)
                whole = flows_result(items, unknowns, derived=derived)
            else:
                items = [
                    {**entry, "evidence": _protected_evidence(entry).model_dump(mode="json")}
                    for entry in document.get("protected") or []
                    if isinstance(entry, dict)
                ]
                whole = whole_result((i["evidence"]["result"] for i in items), unknowns=unknowns)
            page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
            result["items"] = page_items
        return call.finish(
            session,
            result=result,
            evidence=Evidence(result=whole, unknowns=unknowns, gaps=gaps, gaps_truncated=gaps_truncated),
            page=page,
            engine_function="hst.assessment.store.AssessmentStoreMixin.get_analysis_session",
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="change_simulate",
            version=4,
            description=(
                "Simulate a planned firewall, NAT, zone, routing or MTU change synchronously: each flow "
                "is traced twice over the run, as recorded and with the change set applied, and the "
                "answer gives the result before and after the change, the rule that decides each, "
                "grouped path counts, and the routing follow-on. Each flow's evidence.result says "
                "whether the rules permit it after the change: permitted, blocked by the deciding rule, "
                "or not decided. Without flows, at most 8 derived flows are traced; they are a sample, "
                "so the whole answer is per-item then. Nothing is saved. A flow that crosses none of the "
                "changed devices is named in model_errors."
            ),
            input_model=ChangeSimulateInput,
            result_model=ChangeSimulateResult,
            run=change_simulate,
        )
    )
    registry.register(
        catalogue_spec(
            name="change_get_simulation",
            version=4,
            description=(
                "Read one durable simulation run of an analysis session: its execution state, result "
                "and coverage, and one section. summary gives the counts; flows pages through the traced "
                "flows with their evidence; protected pages through the protected requirements with "
                "their results; routing gives the routing follow-on and prediction. snapshot_matches "
                "says whether the run was computed from the selected snapshot."
            ),
            input_model=ChangeGetSimulationInput,
            result_model=ChangeGetSimulationResult,
            run=change_get_simulation,
        )
    )
