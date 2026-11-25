"""Analysis sessions over the assessment and simulation engines."""

from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack, contextmanager
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.analysis.contracts import (
    AnalysisInput,
    AnalysisRunSummary,
    AnalysisSession,
    ApplicationConnection,
    ApplicationProtection,
    ConnectionAnalysisInput,
    CoverageState,
    SimulationAnalysisInput,
    SnapshotReference,
)
from hst.app import fw_overlay_read
from hst.app.auth import current_user, require_permission
from hst.app.routes import assessments as assessment_routes
from hst.app.store import User
from hst.assessment import evaluation as ev
from hst.assessment import service as assessment_service
from hst.assessment.models import Analyze, Definition
from hst.assessment.store import (
    MAX_PENDING_PER_ACTOR,
    AnalysisCapacityError,
    RevisionConflict,
    input_digest,
)
from hst.core import bgpsource, db, ospfsource, ribsource
from hst.core import snapshot as snapshotmod
from hst.results.project import answer_of, condition_result, missing_from_lines
from hst.simul.fw_overlay import ProposalError

router = APIRouter()
READ = [Depends(require_permission("graph.read"))]
WRITE = [Depends(require_permission("changes.write"))]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateSession(ApiModel):
    title: str = Field(min_length=1, max_length=200)
    input: AnalysisInput
    review: dict[str, Any] = Field(default_factory=dict, max_length=100)


class ExecuteSession(ApiModel):
    session_revision: int = Field(
        ge=1, validation_alias=AliasChoices("session_revision", "expected_revision")
    )
    input_digest: str = Field(min_length=64, max_length=64)
    analysis: Analyze = Field(default_factory=Analyze)


def _store(request: Request) -> Any:
    return _session_store(request.app.state.store)


def _session_store(store: Any) -> Any:
    if not hasattr(store, "create_analysis_session"):
        raise HTTPException(503, "Analysis session storage is unavailable")
    return store


@contextmanager
def session_errors():
    """Raise the errors of saving or running a session as HTTP errors. A revision
    conflict is a 409, a full capacity a 429, a held cycle lock a 503, an exceeded
    time bound a 408 and an input that the engines refuse a 422."""
    try:
        yield
    except RevisionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except AnalysisCapacityError as exc:
        raise HTTPException(429, str(exc)) from exc
    except CycleLockWait as exc:
        raise HTTPException(503, assessment_routes.CYCLE_LOCK_BUSY) from exc
    except TimeoutError as exc:
        raise HTTPException(408, "Analysis execution exceeded its reviewed time bound") from exc
    except (ProposalError, ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc


async def _session(store: Any, identifier: str, revision: int | None = None) -> Any:
    item = await store.get_analysis_session(identifier, revision)
    if item is None:
        raise HTTPException(404, "Analysis session not found")
    return item


def stored_session(document: dict) -> AnalysisSession:
    """Read a session the store holds."""
    runs = document.get("runs")
    if isinstance(runs, list) and any(isinstance(run, dict) and "outcome" in run for run in runs):
        document = {
            **document,
            "runs": [
                {key: value for key, value in run.items() if key != "outcome"}
                if isinstance(run, dict) and "outcome" in run
                else run
                for run in runs
                if not older_run(run)
            ],
        }
    return AnalysisSession.model_validate(document)


def older_run(run: Any) -> bool:
    """A run summary with an `outcome` and no `result`."""
    return isinstance(run, dict) and run.get("outcome") is not None and run.get("result") is None


def _pin(settings: Any, stated: SnapshotReference) -> dict:
    actual = assessment_service.snapshot_reference(settings, stated.snapshot)
    for key in ("snapshot", "manifest_sha256", "estate"):
        if str(actual.get(key)) != str(getattr(stated, key)):
            raise ValueError("the Analysis snapshot reference no longer matches its pinned evidence")
    return actual


def _result(result: dict | None) -> dict | None:
    """The answer of the run. It is `outcomes.after.result` of its evaluation,
    or else the `result` of the whole run, or else a `not-established` result.
    None for a run without a result."""
    if not result:
        return None
    raw_outcomes = result.get("outcomes")
    outcomes: dict = raw_outcomes if isinstance(raw_outcomes, dict) else {}
    nested_after = outcomes.get("after")
    for answer in (
        nested_after.get("result") if isinstance(nested_after, dict) else None,
        result.get("result"),
    ):
        if answer_of(answer) is not None:
            return answer
    return condition_result(
        "not-established",
        missing=missing_from_lines(result.get("missing_evidence") or []),
        fallback="the run's result states no answer",
    ).model_dump(mode="json")


def _coverage(result: dict | None) -> CoverageState:
    if not result:
        return "partial"
    if (
        result.get("complete") is False
        or result.get("search_complete") is False
        or result.get("scoped_search_complete") is False
        or result.get("gaps")
        or result.get("unresolved")
    ):
        return "partial"
    # The coverage of a simulation run includes its protections. A protection
    # evaluated with missing evidence or gaps makes the coverage of the run partial.
    for protection in result.get("protected") or []:
        evaluated = protection.get("result") if isinstance(protection, dict) else None
        if isinstance(evaluated, dict) and (
            evaluated.get("missing_evidence") or _coverage(evaluated) == "partial"
        ):
            return "partial"
    return "complete"


async def _present(store: Any, record: Any) -> dict:
    definition = stored_session(record.definition)
    runs = []
    for summary in definition.runs:
        run = await store.get_analysis_run(summary.id)
        if run is None:
            runs.append(summary)
            continue
        runs.append(
            AnalysisRunSummary(
                id=run.id,
                item_id=summary.item_id,
                execution=run.state,
                result=_result(run.result) if run.state == "completed" else None,
                coverage=_coverage(run.result) if run.state == "completed" else "not_started",
                result_ref=f"analysis-run:{run.id}" if run.result is not None else None,
            )
        )
    current = definition.model_copy(update={"runs": runs})
    results = dict(record.results)
    if isinstance(definition.input, SimulationAnalysisInput) and runs:
        run = await store.get_analysis_run(runs[0].id)
        if run is not None and run.result is not None:
            results.update(run.result)
    return {
        **record.as_dict(),
        "results": results,
        "definition": current.model_dump(mode="json"),
        "input_digest": input_digest(definition.input.model_dump(mode="json")),
    }


async def _application_request(store: Any, source: ApplicationConnection, snapshot: dict) -> dict:
    reference = source.reference
    application = await store.get_application(reference.application.id, reference.application.revision)
    if application is None:
        raise ValueError("the selected Business Application revision is unavailable")
    if reference.application.digest and reference.application.digest != application.digest:
        raise ValueError("the selected Business Application digest does not match its revision")
    definition = application.definition
    services = {item["id"]: item for item in definition.get("services", [])}
    service = services.get(reference.service_id)
    if service is None or reference.connection_id not in service.get("connection_ids", []):
        raise ValueError("the connection is not explicitly associated with the selected service")
    resolved = await store.get_application_resolution(source.resolved_scope_digest)
    if resolved is None:
        raise ValueError("the selected resolved scope is unavailable; review Coverage again")
    if (
        resolved.get("application", {}).get("id") != application.id
        or resolved.get("application", {}).get("revision") != application.revision
        or resolved.get("snapshot") != snapshot
    ):
        raise ValueError("the resolved scope does not match the selected application revision and snapshot")
    connection = next(
        (item for item in resolved.get("connections", []) if item.get("id") == reference.connection_id),
        None,
    )
    if connection is None or connection.get("readiness") != "ready" or not connection.get("request"):
        raise ValueError("the selected application connection is unresolved")
    reviewed_request = ev.RequestBody.model_validate(connection["request"]).model_dump(
        mode="json", exclude_none=True
    )
    if reviewed_request != source.request.model_dump(mode="json", exclude_none=True):
        raise ValueError("the submitted request differs from the reviewed resolved scope")
    return reviewed_request


async def _connection_request(store: Any, source: Any, snapshot: dict) -> tuple[dict | None, str | None]:
    if source.kind == "application_connection":
        return await _application_request(store, source, snapshot), None
    if source.kind == "saved_requirement":
        saved = await store.get_requirement(source.requirement.id, source.requirement.revision)
        request = source.request.model_dump(mode="json", exclude_none=True)
        # POST /api/requirements stores the request with its null fields. Both
        # sides are compared in one normalized form.
        if (
            saved is None
            or not isinstance(saved.definition.get("request"), dict)
            or ev.RequestBody.model_validate(saved.definition["request"]).model_dump(
                mode="json", exclude_none=True
            )
            != request
        ):
            raise ValueError("the saved requirement request does not match its immutable revision")
        return request, None
    if source.kind == "inline":
        return source.request.model_dump(mode="json", exclude_none=True), None
    return None, source.requirement_uid


async def _execute_connections(
    store: Any,
    settings: Any,
    record: Any,
    definition: AnalysisSession,
    body: ExecuteSession,
    actor: int | None,
) -> Any:
    value = definition.input
    if not isinstance(value, ConnectionAnalysisInput):
        raise TypeError("connection execution requires a connection input")
    snapshot = await asyncio.to_thread(_pin, settings, value.snapshot)
    # A connection whose run is queued, running or completed keeps that run. A
    # connection with a failed or cancelled run, or with no run, is submitted.
    kept = []
    for summary in definition.runs:
        run = await store.get_analysis_run(summary.id)
        if run is not None and run.state in {"queued", "running", "completed"}:
            kept.append(summary)
    kept_items = {summary.item_id for summary in kept}
    pending = [selected for selected in value.connections if selected.id not in kept_items]
    if not pending:
        raise RevisionConflict("every connection of this session already has a run")
    prepared: list[tuple[Any, dict]] = []
    for selected in pending:
        inline, requirement = await _connection_request(store, selected.source, snapshot)
        raw = {
            "request": inline,
            "requirement": requirement,
            "intents": [change.model_dump(mode="json") for change in value.changes],
            "mode": value.mode,
            "snapshot": snapshot["snapshot"],
        }
        normalized = await asyncio.to_thread(
            assessment_routes._definition,
            settings,
            Definition.model_validate(raw),
        )
        prepared.append((selected, normalized))
    # Engine admission bounds unfinished analyses per actor. The connections
    # past that bound are not submitted and are reported as omitted. The
    # coverage of the session stays partial.
    capacity = await store.analysis_capacity(actor)
    if capacity < 1:
        raise AnalysisCapacityError(f"at most {MAX_PENDING_PER_ACTOR} unfinished analyses per actor")
    prepared, omitted = prepared[:capacity], [selected.id for selected, _ in prepared[capacity:]]
    admission = (
        {
            "omitted": omitted,
            "limit": MAX_PENDING_PER_ACTOR,
            "reason": f"at most {MAX_PENDING_PER_ACTOR} unfinished analyses per actor; "
            "run the session again once runs finish to submit the omitted connections",
        }
        if omitted
        else None
    )
    summaries = list(kept)
    bindings: dict[str, Any] = dict(record.results.get("bindings") or {})
    try:
        for selected, normalized in prepared:
            assessment = await store.create_assessment(
                title=selected.name,
                purpose="analysis-session",
                definition=normalized,
                created_by=actor,
            )
            bindings[selected.id] = {
                "assessment_id": assessment.id,
                "assessment_revision": assessment.revision,
            }
            run = await assessment_routes.submit(
                store,
                settings,
                assessment,
                body.analysis.model_copy(update={"snapshot": snapshot["snapshot"]}),
                actor,
            )
            summaries.append(
                AnalysisRunSummary(
                    id=run.id,
                    item_id=selected.id,
                    execution=run.state,
                    coverage="not_started",
                )
            )
            bindings[selected.id]["input_digest"] = run.input_digest
    except Exception:
        if bindings:
            partial = definition.model_copy(update={"revision": record.revision + 1, "runs": summaries})
            await store.create_analysis_session(
                title=record.title,
                definition=partial.model_dump(mode="json"),
                results={
                    **record.results,
                    "bindings": bindings,
                    "execution_error": {
                        "state": "partial",
                        "submitted": len(summaries),
                        "requested": len(prepared),
                    },
                },
                created_by=actor,
                session_id=record.id,
                expected_revision=record.revision,
            )
        raise
    revised = definition.model_copy(update={"revision": record.revision + 1, "runs": summaries})
    replaced = {"admission", "execution_error"}
    results = {key: item for key, item in record.results.items() if key not in replaced}
    if admission is not None:
        results["admission"] = admission
    return await store.create_analysis_session(
        title=record.title,
        definition=revised.model_dump(mode="json"),
        results={**results, "bindings": bindings},
        created_by=actor,
        session_id=record.id,
        expected_revision=record.revision,
    )


def _simulation_request(store_data: dict, protection: Any) -> dict:
    if isinstance(protection, ApplicationProtection):
        resolved = store_data[protection.resolved_scope_digest]
        connection = next(
            item for item in resolved["connections"] if item["id"] == protection.reference.connection_id
        )
        return connection["request"]
    return protection.request.model_dump(mode="json", exclude_none=True)


def _simulate(
    settings: Any, value: SimulationAnalysisInput, source_kinds: dict, requests: list[dict]
) -> dict:
    stated = value.snapshot
    with db.session(settings) as session:
        snap = snapshotmod.resolve(session, settings, int(stated.snapshot))
        if snap.cts is None:
            raise ValueError("the selected snapshot has no committed identity")
        pinned = pathmod.pinned(session, snap)
        flows = (
            [flow.model_dump(mode="json", exclude_none=True) for flow in value.scope.flows]
            if value.scope
            else None
        )
        simulation = fw_overlay_read.simulate_change(
            pinned,
            intents=[change.model_dump(mode="json") for change in value.changes],
            flows=flows or None,
            depth=value.bounds.depth,
            sites=value.scope.sites if value.scope and value.scope.sites else None,
            detail=True,
            rib=ribsource.for_snapshot(snap),
            bgp=bgpsource.for_snapshot(snap),
            ospf=ospfsource.for_snapshot(snap),
            source_kinds=source_kinds,
        )
        protected = []
        for protection, request_document in zip(value.protected, requests, strict=True):
            readers = (
                ribsource.for_snapshot(snap),
                bgpsource.for_snapshot(snap),
                ospfsource.for_snapshot(snap),
            )
            try:
                result = ev.evaluate_change(
                    pinned,
                    intents=[change.model_dump(mode="json") for change in value.changes],
                    request=ev._request_from_body(ev.RequestBody.model_validate(request_document)),
                    mode="possible",
                    rib_source=readers[0],
                    bgp_source=readers[1],
                    ospf_source=readers[2],
                    detail=True,
                )
            finally:
                for reader in readers:
                    reader.close()
            protected.append(
                {
                    "desired": protection.desired,
                    "reference": protection.model_dump(mode="json"),
                    "result": result,
                }
            )
    return {
        "snapshot": value.snapshot.model_dump(mode="json"),
        "simulation": simulation,
        "protected": protected,
    }


async def _execute_simulation(
    store: Any,
    settings: Any,
    record: Any,
    definition: AnalysisSession,
    actor: int | None,
) -> Any:
    value = definition.input
    if not isinstance(value, SimulationAnalysisInput):
        raise TypeError("simulation execution requires a simulation input")
    if value.scope and len(value.scope.flows) > value.bounds.max_flows:
        raise ValueError("the reviewed simulation scope exceeds its max_flows bound")
    snapshot = await asyncio.to_thread(_pin, settings, value.snapshot)
    resolved: dict[str, dict] = {}
    for protection in value.protected:
        if not isinstance(protection, ApplicationProtection):
            continue
        application = await store.get_application(
            protection.reference.application.id, protection.reference.application.revision
        )
        if application is None:
            raise ValueError("a protected Business Application revision is unavailable")
        if (
            protection.reference.application.digest
            and protection.reference.application.digest != application.digest
        ):
            raise ValueError("a protected Business Application digest does not match its revision")
        service = next(
            (
                item
                for item in application.definition.get("services", [])
                if item.get("id") == protection.reference.service_id
            ),
            None,
        )
        if service is None or protection.reference.connection_id not in service.get("connection_ids", []):
            raise ValueError("a protected connection is not explicitly associated with its service")
        item = await store.get_application_resolution(protection.resolved_scope_digest)
        if (
            item is None
            or item.get("snapshot") != snapshot
            or item.get("application", {}).get("id") != application.id
            or item.get("application", {}).get("revision") != application.revision
        ):
            raise ValueError("a protected application connection lacks its reviewed pinned resolution")
        if not any(
            connection.get("id") == protection.reference.connection_id
            and connection.get("readiness") == "ready"
            for connection in item.get("connections", [])
        ):
            raise ValueError("a protected application connection is unresolved")
        resolved[protection.resolved_scope_digest] = item
    requests = [_simulation_request(resolved, item) for item in value.protected]
    source_kinds = {row.name: row.type for row in await store.list_sources()}
    run = await store.enqueue_analysis(
        assessment_id=record.id,
        assessment_revision=record.revision,
        kind="simulation",
        inputs={
            "analysis_session_simulation": value.model_dump(mode="json"),
            "source_kinds": source_kinds,
            "protected_requests": requests,
        },
        snapshot_refs=[snapshot],
        engine_version=assessment_service.engine_version(settings),
        created_by=actor,
        limits={"max_seconds": value.bounds.max_seconds},
    )
    summary = AnalysisRunSummary(
        id=run.id,
        item_id="simulation",
        execution=run.state,
        coverage="not_started",
    )
    revised = definition.model_copy(update={"revision": record.revision + 1, "runs": [summary]})
    return await store.create_analysis_session(
        title=record.title,
        definition=revised.model_dump(mode="json"),
        results=record.results,
        created_by=actor,
        session_id=record.id,
        expected_revision=record.revision,
    )


async def save_session(store: Any, settings: Any, body: CreateSession, actor: int | None) -> dict:
    """Check the input's pinned snapshot and save revision 1 of a new session
    for `actor`. Returns the session as the routes present it."""
    await asyncio.to_thread(_pin, settings, body.input.snapshot)
    identifier = str(uuid4())
    definition = AnalysisSession(id=identifier, revision=1, title=body.title, input=body.input)
    store = _session_store(store)
    saved = await store.create_analysis_session(
        title=body.title,
        definition=definition.model_dump(mode="json"),
        results={"review": body.review} if body.review else {},
        created_by=actor,
        session_id=identifier,
    )
    return await _present(store, saved)


class CycleLockWait(TimeoutError):
    """The cycle lock stayed held for longer than the caller of `run_session`
    would wait. No run was queued."""


async def run_session(
    store: Any,
    settings: Any,
    session_id: str,
    body: ExecuteSession,
    actor: int | None,
    *,
    lock_wait_s: float | None = None,
) -> dict:
    """Queue the runs of the reviewed session revision for `actor`, under the
    cycle lock, and save the next revision that lists them. Returns the
    session as the routes present it.

    The revision and the input digest must be the ones reviewed, and a
    revision runs once. The per-actor cap on unfinished analyses applies.
    With `lock_wait_s`, the wait for the cycle lock ends after that many
    seconds with `CycleLockWait`. The work under the lock is not bounded.
    """
    store = _session_store(store)
    record = await _session(store, session_id)
    if record.revision != body.session_revision:
        raise RevisionConflict(
            f"expected revision {body.session_revision}, current revision {record.revision}"
        )
    definition = stored_session(record.definition)
    actual_digest = input_digest(definition.input.model_dump(mode="json"))
    if body.input_digest != actual_digest:
        raise RevisionConflict("reviewed Analysis input digest does not match the session revision")
    # A run that `stored_session` leaves out of the read counts as executed. A
    # revision runs again for the rest of its connections when not all were
    # submitted, after an omission at admission or a failed submission. A
    # connection revision with a failed or cancelled child run also runs again.
    # `_execute_connections` submits that connection again and keeps the other runs.
    unfinished = bool(
        (record.results or {}).get("admission") or (record.results or {}).get("execution_error")
    )
    if not unfinished and definition.input.kind == "connection":
        for summary in definition.runs:
            run = await store.get_analysis_run(summary.id)
            if run is not None and run.state in {"failed", "cancelled"}:
                unfinished = True
                break
    if (definition.runs or record.definition.get("runs")) and not unfinished:
        raise ValueError("this Analysis session revision has already been executed")
    async with AsyncExitStack() as held:
        try:
            async with asyncio.timeout(lock_wait_s):
                await held.enter_async_context(store.cycle_lock())
        except TimeoutError as exc:
            if lock_wait_s is None:
                raise
            raise CycleLockWait(
                f"the cycle lock stayed held for more than {lock_wait_s:.1f} seconds"
            ) from exc
        if definition.input.kind == "connection":
            saved = await _execute_connections(store, settings, record, definition, body, actor)
        else:
            saved = await _execute_simulation(store, settings, record, definition, actor)
    return await _present(store, saved)


@router.get("/analysis-snapshot", dependencies=READ)
async def analysis_snapshot(request: Request, snapshot: str) -> dict:
    with session_errors():
        return await asyncio.to_thread(
            assessment_service.snapshot_reference, request.app.state.settings, snapshot
        )


@router.get("/analysis-sessions", dependencies=READ)
async def list_sessions(request: Request, limit: int = Query(100, ge=1, le=1000)) -> dict:
    store = _store(request)
    return {"sessions": [await _present(store, item) for item in await store.list_analysis_sessions(limit)]}


@router.post("/analysis-sessions", dependencies=WRITE, status_code=201)
async def create_session(body: CreateSession, request: Request, user: User = Depends(current_user)) -> dict:
    with session_errors():
        return await save_session(request.app.state.store, request.app.state.settings, body, user.id)


@router.get("/analysis-sessions/{session_id}", dependencies=READ)
async def get_session(
    session_id: str, request: Request, revision: int | None = Query(default=None, ge=1)
) -> dict:
    return await _present(_store(request), await _session(_store(request), session_id, revision))


@router.get("/analysis-sessions/{session_id}/history", dependencies=READ)
async def session_history(session_id: str, request: Request, limit: int = Query(100, ge=1, le=1000)) -> dict:
    await _session(_store(request), session_id)
    with session_errors():
        # `stored_session` reads each revision, as the GET of one revision does.
        return {
            "revisions": [
                {**item.as_dict(), "definition": stored_session(item.definition).model_dump(mode="json")}
                for item in await _store(request).list_analysis_session_revisions(session_id, limit)
            ]
        }


@router.post("/analysis-sessions/{session_id}/runs", dependencies=WRITE, status_code=202)
@router.post("/analysis-sessions/{session_id}/execute", dependencies=WRITE, status_code=202)
async def execute_session(
    session_id: str,
    body: ExecuteSession,
    request: Request,
    user: User = Depends(current_user),
) -> dict:
    with session_errors():
        return await run_session(
            request.app.state.store,
            request.app.state.settings,
            session_id,
            body,
            user.id,
            lock_wait_s=assessment_routes.CYCLE_LOCK_WAIT_S,
        )


@router.get("/analysis-sessions/{session_id}/runs/{run_id}", dependencies=READ)
async def get_session_run(session_id: str, run_id: str, request: Request) -> dict:
    store = _store(request)
    record = await _session(store, session_id)
    definition = stored_session(record.definition)
    summary = next((item for item in definition.runs if item.id == run_id), None)
    if summary is None:
        raise HTTPException(404, "Analysis run not found in this session")
    run = await store.get_analysis_run(run_id)
    if run is None:
        raise HTTPException(404, "Analysis run not found")
    return {"summary": summary.model_dump(mode="json"), "run": _run_json(run)}


@router.get("/analysis-sessions/{session_id}/runs/{run_id}/export", dependencies=READ)
async def export_session_run(session_id: str, run_id: str, request: Request) -> Response:
    record = await _session(_store(request), session_id)
    payload = await get_session_run(session_id, run_id, request)
    content = json.dumps(
        {
            "session_id": session_id,
            "session_revision": record.revision,
            "input": stored_session(record.definition).input.model_dump(mode="json"),
            **payload,
        },
        sort_keys=True,
        indent=2,
    )
    return Response(
        content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="analysis-{session_id}-{run_id}.json"',
            "X-HST-Analysis-Revision": str(record.revision),
            "X-HST-Export-Mode": "exact-saved-run",
        },
    )


@router.get("/analysis-sessions/{session_id}/export", dependencies=READ)
async def export_session(
    session_id: str, request: Request, revision: int | None = Query(default=None, ge=1)
) -> Response:
    store = _store(request)
    record = await _session(store, session_id, revision)
    payload = await _present(store, record)
    run_results = {}
    definition = stored_session(record.definition)
    for summary in definition.runs:
        run = await store.get_analysis_run(summary.id)
        if run is not None:
            run_results[summary.id] = {
                "input_digest": run.input_digest,
                "inputs": run.inputs,
                "snapshot_refs": run.snapshot_refs,
                "engine_version": run.engine_version,
                "state": run.state,
                "result": run.result,
                "error": run.error,
            }
    content = json.dumps({**payload, "run_results": run_results}, sort_keys=True, indent=2)
    return Response(
        content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="analysis-{record.id}-r{record.revision}.json"',
            "X-HST-Analysis-Revision": str(record.revision),
            "X-HST-Export-Mode": "exact-saved-run",
        },
    )


def _run_json(run: Any) -> dict:
    value = run.as_dict()
    for field in ("lease_token", "claimed_by", "checkpoint"):
        value.pop(field, None)
    return value


def execute_simulation_job(
    settings: Any,
    inputs: dict,
    *,
    progress: Any = None,
    cancelled: Any = None,
) -> dict:
    """Execute a reviewed simulation inside the durable analysis worker."""
    if cancelled and cancelled():
        raise RuntimeError("simulation cancelled")
    value = SimulationAnalysisInput.model_validate(inputs["analysis_session_simulation"])
    if progress:
        progress({"phase": "simulation", "state": "running"})
    result = _simulate(
        settings,
        value,
        dict(inputs.get("source_kinds", {})),
        list(inputs.get("protected_requests", [])),
    )
    if progress:
        progress({"phase": "simulation", "state": "completed"})
    return result
