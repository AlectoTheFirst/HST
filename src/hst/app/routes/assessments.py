"""Saved requirements, immutable assessments and bounded analysis submissions."""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from starlette.background import BackgroundTask

from hst import path as pathmod
from hst.app.auth import current_user, require_permission
from hst.app.store import User
from hst.assessment import evaluation as ev
from hst.assessment import package as packages
from hst.assessment import proposals, service
from hst.assessment.lifecycle_models import RetentionPolicy, ReviseChange, SaveProposal
from hst.assessment.models import (
    Analyze,
    CollectionActions,
    CreateAssessment,
    Definition,
    Deployment,
    ReviseAssessment,
)
from hst.assessment.population_request import bind_pinned_request
from hst.assessment.request_document import request_document as _request_document
from hst.assessment.store import AnalysisCapacityError, RevisionConflict, _same_definition
from hst.core import db, snapshot
from hst.simul.intents import OVERLAY_KINDS, capabilities

router = APIRouter()
READ = [Depends(require_permission("graph.read"))]
WRITE = [Depends(require_permission("changes.write"))]


# A collection holds the cycle lock for its whole length. A request waits this
# long for the lock, and a status read waits `STATUS_LOCK_WAIT_S`.
CYCLE_LOCK_WAIT_S = 20.0
STATUS_LOCK_WAIT_S = 2.0
CYCLE_LOCK_BUSY = "A collection or a prune holds the cycle lock. The request made no change."


@asynccontextmanager
async def _cycle_lock(store: Any, wait_s: float | None = None) -> AsyncIterator[None]:
    """Hold the cycle lock for the block. A wait for the lock of more than
    `wait_s` seconds ends with a 503. The default is `CYCLE_LOCK_WAIT_S`."""
    async with AsyncExitStack() as held:
        try:
            async with asyncio.timeout(CYCLE_LOCK_WAIT_S if wait_s is None else wait_s):
                await held.enter_async_context(store.cycle_lock())
        except TimeoutError as exc:
            raise HTTPException(503, CYCLE_LOCK_BUSY) from exc
        yield


@contextmanager
def _errors():
    try:
        yield
    except CycleLockWait as exc:
        raise HTTPException(503, CYCLE_LOCK_BUSY) from exc
    except RevisionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except AnalysisCapacityError as exc:
        raise HTTPException(429, str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc


def _store(request: Request) -> Any:
    store = request.app.state.store
    if not hasattr(store, "create_assessment"):
        raise HTTPException(503, "Assessment storage is unavailable; apply the database migrations.")
    return store


async def _assessment(store: Any, identifier: str, revision: int | None = None) -> Any:
    item = await store.get_assessment(identifier, revision)
    if item is None:
        raise HTTPException(404, "Assessment not found.")
    return item


def _definition(settings: Any, body: Definition) -> dict:
    value = body.model_dump(mode="json")
    for intent in value["intents"]:
        if intent.get("kind") not in OVERLAY_KINDS:
            raise ValueError(f"Intent {intent.get('kind')} is not supported by the impact engine.")
    if body.requirement:
        ref = service.snapshot_reference(settings, body.snapshot)
        with db.session(settings) as session:
            snap = snapshot.resolve(session, settings, int(ref["snapshot"]))
            req = ev._request_from_requirement(pathmod.pinned(session, snap), body.requirement)
        value.update(
            request=_request_document(req),
            requirement=None,
            origin_requirement=body.requirement,
            origin_snapshot=ref["snapshot"],
            snapshot=ref["snapshot"],
        )
    elif value.get("request", {}).get("population") is not None:
        ref = service.snapshot_reference(settings, body.snapshot)
        with db.session(settings) as session:
            snap = snapshot.resolve(session, settings, int(ref["snapshot"]))
            value["request"] = bind_pinned_request(settings, session, snap, value["request"])
        value["snapshot"] = ref["snapshot"]
    return value


def _run_json(run: Any) -> dict:
    # The worker lease fields stay out of the response.
    value = run.as_dict()
    for field in ("lease_token", "claimed_by", "checkpoint"):
        value.pop(field, None)
    return value


async def _requirement_reference(store: Any, definition: dict) -> None:
    if definition.get("requirement_id"):
        requirement = await store.get_requirement(
            definition["requirement_id"], definition["requirement_revision"]
        )
        if requirement is None or requirement.definition["request"] != definition["request"]:
            raise ValueError("The saved request must match its referenced requirement revision.")
    if definition.get("change_id"):
        change = await store.get_change_revision(definition["change_id"], definition["change_revision"])
        if change is None or change.definition["intents"] != definition["intents"]:
            raise ValueError("The saved intents must match their referenced change revision.")


async def submit(store: Any, settings: Any, item: Any, body: Analyze, actor: int | None) -> Any:
    value = body.model_dump(mode="json")
    selected = body.snapshot if body.kind == "verify" else body.snapshot or item.definition.get("snapshot")
    reference = await asyncio.to_thread(service.snapshot_reference, settings, selected)
    refs = [reference]
    if body.before_snapshot:
        refs.append(await asyncio.to_thread(service.snapshot_reference, settings, body.before_snapshot))
        if refs[0]["estate"] != refs[1]["estate"]:
            raise ValueError("Regression snapshots must belong to the same estate.")
    inputs = {"definition": item.definition, "analysis": value, "snapshot_refs": refs}
    if body.kind == "verify":
        deployments = item.definition.get("deployments", [])
        if not deployments:
            raise ValueError("Record a deployment before verifying its prediction.")
        deployment = deployments[-1]
        runs = await store.list_analysis_runs(item.id, limit=1000)
        prediction = next(
            (
                r
                for r in runs
                if r.state == "completed"
                and r.kind in {"evaluate", "evaluation"}
                and r.assessment_revision == deployment["assessment_revision"]
            ),
            None,
        )
        if prediction is None or not prediction.result:
            raise ValueError("The deployed revision needs a completed evaluation before verification.")
        if prediction.engine_version != await asyncio.to_thread(service.engine_version, settings):
            raise ValueError("Verification requires the prediction's original engine build.")
        deployed_revision = await _assessment(store, item.id, deployment["assessment_revision"])
        for ref in prediction.snapshot_refs:
            if ref not in refs:
                refs.append(ref)
        inputs.update(
            deployment=deployment,
            prediction=prediction.result,
            definition=deployed_revision.definition,
            # The observation age is measured at submission.
            submitted_at=datetime.now(UTC).isoformat(),
        )
    linked = inputs["definition"]
    stated = linked.get("request")
    if isinstance(stated, dict) and stated.get("sources") and stated.get("population_artifact") is None:
        # A saved request the grammar cannot read is refused here with its
        # named specs.
        await asyncio.to_thread(ev._request_from_body, ev.RequestBody.model_validate(stated))
    if linked.get("change_id"):
        change = await store.get_change_revision(linked["change_id"], linked["change_revision"])
        if change is None or change.definition["intents"] != linked.get("intents"):
            raise ValueError("The immutable change reference is unavailable or inconsistent.")
        protections = {entry["name"]: entry for entry in value["protected"]}
        for entry in change.definition.get("protected", []):
            normalized = Analyze(protected=[entry]).model_dump(mode="json")["protected"][0]
            if normalized["name"] in protections and protections[normalized["name"]] != normalized:
                raise ValueError("A linked proposal's protected requirement cannot be weakened.")
            protections[normalized["name"]] = normalized
        value["protected"] = list(protections.values())
        if len(value["protected"]) > 50:
            raise ValueError("An analysis supports at most 50 protected requirements.")
    return await store.enqueue_analysis(
        assessment_id=item.id,
        assessment_revision=item.revision,
        kind=body.kind,
        inputs=inputs,
        snapshot_refs=refs,
        engine_version=await asyncio.to_thread(service.engine_version, settings),
        created_by=actor,
        limits=value["limits"],
        retry_of=body.retry_of,
    )


class CycleLockWait(TimeoutError):
    """The cycle lock stayed held for longer than the caller of
    `submit_analysis` would wait. No run was queued."""


async def submit_analysis(
    store: Any,
    settings: Any,
    identifier: str,
    body: Analyze,
    actor: int | None,
    *,
    lock_wait_s: float | None = None,
) -> Any:
    """Submit one analysis of the newest revision of assessment `identifier`
    for `actor`, and return the queued run.

    The snapshots are pinned and the run is queued under the cycle lock. A
    retention sweep cannot remove a pinned run in between. The per-actor cap
    on unfinished analyses applies. With `lock_wait_s`, the wait for the
    cycle lock ends after that many seconds with `CycleLockWait`. The work
    under the lock is not bounded.
    """
    item = await _assessment(store, identifier)
    # The cycle lock keeps retention sweeps out between the pin and the queue write.
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
        return await submit(store, settings, item, body, actor)


@router.get("/assessment-capabilities", dependencies=READ)
def catalog() -> dict:
    return {
        "intents": [asdict(c) for c in capabilities()],
        "schema_version": 1,
        "analysis_permission": "changes.write",
        "failure_model": "recomputed-routing-with-policy-and-service-realization",
        "failure_targets": ["device", "interface", "link", "tunnel", "overlapping-domain"],
        "failure_protocols": ["connected", "static", "ospf", "bgp", "redistribution", "route-leaking", "pbr"],
        "repair_family": "firewall-policy",
        "repair_cost_dimensions": ["devices", "newly_permitted_scope", "rule_edits"],
        "repair_cost_order": "caller-selected-lexicographic",
        "regression_family": "observed-configured-model-inputs",
        "regression_families": [
            "firewall",
            "nat",
            "interfaces",
            "contexts",
            "connected",
            "static",
            "pbr",
            "bgp.processes",
            "bgp.sessions",
            "bgp.policies",
            "bgp.local_routes",
            "ospf",
        ],
        "regression_excluded_derived_inputs": {
            "rt_pairs": "Requires inversion of recorded RT configuration."
        },
        "evidence_requirement": "Pinned ownership and completeness for each affected model input.",
    }


@router.get("/requirements", dependencies=READ)
async def requirements(request: Request, limit: int = Query(100, ge=1, le=1000)) -> dict:
    return {"requirements": [r.as_dict() for r in await _store(request).list_requirements(limit)]}


@router.post("/requirements", dependencies=WRITE)
async def create_requirement(
    request: Request, body: CreateAssessment, user: User = Depends(current_user)
) -> dict:
    with _errors():
        definition = await asyncio.to_thread(_definition, request.app.state.settings, body.definition)
        result = await _store(request).create_requirement(
            title=body.title, definition=definition, created_by=user.id
        )
        return result.as_dict()


@router.get("/requirements/{identifier}", dependencies=READ)
async def requirement_detail(
    request: Request, identifier: str, revision: int | None = Query(None, ge=1)
) -> dict:
    item = await _store(request).get_requirement(identifier, revision)
    if item is None:
        raise HTTPException(404, "Requirement not found.")
    return item.as_dict()


@router.patch("/requirements/{identifier}", dependencies=WRITE)
async def revise_requirement(
    request: Request, identifier: str, body: ReviseAssessment, user: User = Depends(current_user)
) -> dict:
    with _errors():
        definition = await asyncio.to_thread(_definition, request.app.state.settings, body.definition)
        item = await _store(request).create_requirement(
            title=body.title,
            definition=definition,
            created_by=user.id,
            requirement_id=identifier,
            expected_revision=body.expected_revision,
        )
        return item.as_dict()


@router.get("/assessments", dependencies=READ)
async def library(
    request: Request, limit: int = Query(100, ge=1, le=1000), include_evidence: bool = False
) -> dict:
    from hst.assessment.evidence import portfolio

    store = _store(request)
    items = await store.list_assessments(limit)
    records = [{**a.as_dict(), "freshness": await store.get_assessment_freshness(a.id)} for a in items]
    result: dict[str, Any] = {"assessments": records}
    if include_evidence:
        results = []
        for item in items:
            runs = await store.list_analysis_runs(item.id, limit=1000)
            # The evidence comes from a run of a revision whose definition equals
            # the newest definition.
            same: dict[int, bool] = {item.revision: True}
            run = None
            for candidate in runs:
                if candidate.kind != "troubleshoot" or candidate.state != "completed" or not candidate.result:
                    continue
                if candidate.assessment_revision not in same:
                    older = await store.get_assessment(item.id, candidate.assessment_revision)
                    same[candidate.assessment_revision] = older is not None and _same_definition(
                        older.definition, item.definition
                    )
                if same[candidate.assessment_revision]:
                    run = candidate
                    break
            if run is not None:
                actions = [
                    {
                        **action,
                        "origins": [
                            {
                                "assessment_id": item.id,
                                "run_id": run.id,
                                "action_id": action["id"],
                                "snapshot_refs": run.snapshot_refs,
                            }
                        ],
                    }
                    for action in run.result.get("actions", [])
                ]
                results.append(
                    (item.id, item.definition.get("priority", 1), {**run.result, "actions": actions})
                )
        result["evidence_portfolio"] = portfolio(results)
    return result


@router.post("/assessments", dependencies=WRITE, status_code=201)
async def create(request: Request, body: CreateAssessment, user: User = Depends(current_user)) -> dict:
    with _errors():
        definition = await asyncio.to_thread(_definition, request.app.state.settings, body.definition)
        await _requirement_reference(_store(request), definition)
        definition.update(deployments=[], collection_actions=[])
        item = await _store(request).create_assessment(
            title=body.title, purpose=body.purpose, definition=definition, created_by=user.id
        )
        return item.as_dict()


@router.get("/assessments/{identifier}", dependencies=READ)
async def detail(request: Request, identifier: str, revision: int | None = Query(None, ge=1)) -> dict:
    store = _store(request)
    item = await _assessment(store, identifier, revision)
    fresh = await store.get_assessment_freshness(identifier)
    return {
        "assessment": item.as_dict(),
        "runs": [_run_json(r) for r in await store.list_analysis_runs(identifier)],
        "freshness": {**fresh, "reasons": fresh.get("causes", [])},
        "proposals": [p.as_dict() for p in await store.list_assessment_proposals(identifier)],
    }


@router.patch("/assessments/{identifier}", dependencies=WRITE)
async def revise(
    request: Request, identifier: str, body: ReviseAssessment, user: User = Depends(current_user)
) -> dict:
    with _errors():
        definition = await asyncio.to_thread(_definition, request.app.state.settings, body.definition)
        store = _store(request)
        current = await _assessment(store, identifier)
        await _requirement_reference(store, definition)
        for field in ("deployments", "collection_actions"):
            definition[field] = current.definition.get(field, [])
        item = await _store(request).create_assessment(
            title=body.title,
            purpose=body.purpose,
            definition=definition,
            created_by=user.id,
            assessment_id=identifier,
            expected_revision=body.expected_revision,
        )
        return item.as_dict()


@router.post("/assessments/{identifier}/analyses", dependencies=WRITE, status_code=202)
@router.post("/assessments/{identifier}/evaluations", dependencies=WRITE, status_code=202)
async def analyze(
    request: Request, identifier: str, body: Analyze, user: User = Depends(current_user)
) -> dict:
    store = _store(request)
    with _errors():
        run = await submit_analysis(
            store, request.app.state.settings, identifier, body, user.id, lock_wait_s=CYCLE_LOCK_WAIT_S
        )
        return _run_json(run)


@router.get("/analysis-jobs/{identifier}", dependencies=READ)
async def job(request: Request, identifier: str) -> dict:
    run = await _store(request).get_analysis_run(identifier)
    if run is None:
        raise HTTPException(404, "Analysis job not found.")
    return _run_json(run)


@router.post("/analysis-jobs/{identifier}/cancel", dependencies=WRITE)
async def cancel(request: Request, identifier: str) -> dict:
    run = await _store(request).cancel_analysis(identifier)
    if run is None:
        raise HTTPException(404, "Analysis job not found.")
    return _run_json(run)


@router.post("/assessments/{identifier}/deployments", dependencies=WRITE, status_code=201)
async def deployed(
    request: Request, identifier: str, body: Deployment, user: User = Depends(current_user)
) -> dict:
    store = _store(request)
    with _errors():
        at = datetime.fromisoformat(body.deployed_at)
        if at.tzinfo is None or at > datetime.now(UTC):
            raise ValueError("Deployment time must include a timezone and must not be in the future.")
        item = await _assessment(store, identifier)
        await _assessment(store, identifier, body.assessment_revision)
        definition = {
            **item.definition,
            "deployments": [
                *item.definition.get("deployments", []),
                {**body.model_dump(), "recorded_by": user.id},
            ],
        }
        result = await store.create_assessment(
            title=item.title,
            purpose=item.purpose,
            definition=definition,
            created_by=user.id,
            assessment_id=item.id,
            expected_revision=item.revision,
        )
        return result.as_dict()


@router.post(
    "/assessments/{identifier}/collection-actions", dependencies=[Depends(require_permission("runs.manage"))]
)
async def collect(
    request: Request, identifier: str, body: CollectionActions, user: User = Depends(current_user)
) -> dict:
    store = _store(request)
    with _errors():
        item = await _assessment(store, identifier)
        run = await store.get_analysis_run(body.run_id)
        if run is None or run.assessment_id != identifier or run.kind != "troubleshoot" or not run.result:
            raise ValueError("Select actions from a completed troubleshooting result on this assessment.")
        available = {a["id"]: a for a in run.result.get("actions", []) if a["state"] == "available"}
        if not set(body.action_ids) <= set(available):
            raise ValueError("A selected action does not exist or is not executable.")
        actions = []
        now = datetime.now(UTC)
        # The whole selection is validated before any queue write.
        for identifier_ in dict.fromkeys(body.action_ids):
            action = available[identifier_]
            source = await store.get_source(action["source"])
            if source is None or not source.enabled:
                raise ValueError("A collection source no longer exists or is disabled.")
            recipes = action.get("recipe_ids") or [action.get("recipe_id", "")]
            if any(not recipe.startswith(f"{source.type}.") for recipe in recipes):
                raise ValueError("The source collector has changed since this recipe was recorded.")
            devices = await store.list_devices(source.name)
            device = next((d for d in devices if d.host == action["host"]), None)
            if (device is not None and not device.enabled) or (
                device is None and str(source.config.get("host") or "") != action["host"]
            ):
                raise ValueError("A collection target no longer exists or is disabled.")
            actions.append(
                {
                    **action,
                    "request_id": str(uuid4()),
                    "job_id": None,
                    "state": "requested",
                    "requested_at": now.isoformat(),
                    "requested_by": user.id,
                    "run_id": run.id,
                }
            )
        definition = {
            **item.definition,
            "collection_actions": [*item.definition.get("collection_actions", []), *actions],
        }
        if len(definition["collection_actions"]) > 200:
            raise ValueError("This assessment already has the maximum number of collection actions.")
        async with _cycle_lock(store):
            # The request is stored before collection is scheduled.
            saved = await store.create_assessment(
                title=item.title,
                purpose=item.purpose,
                definition=definition,
                created_by=user.id,
                assessment_id=item.id,
                expected_revision=item.revision,
            )
            for action in actions:
                try:
                    queued = await store.enqueue_job(
                        "collect.fetch",
                        source=action["source"],
                        device=action["host"],
                        priority=1,
                        not_before=now,
                        max_attempts=1,
                        triggered_by=f"assessment:{user.id}",
                        now=now,
                    )
                    action.update(
                        job_id=queued.id if queued else None,
                        state="queued" if queued else "awaiting_publication",
                        reason="Collection queued."
                        if queued
                        else "An equivalent collection is already pending.",
                    )
                except Exception:
                    action.update(state="failed", reason="The collection request could not be queued.")
            updates = {a["request_id"]: a for a in actions}
            for attempt in range(3):
                latest = await _assessment(store, item.id)
                merged = [
                    updates.get(a.get("request_id"), a)
                    for a in latest.definition.get("collection_actions", [])
                ]
                try:
                    saved = await store.create_assessment(
                        title=latest.title,
                        purpose=latest.purpose,
                        definition={**latest.definition, "collection_actions": merged},
                        created_by=user.id,
                        assessment_id=item.id,
                        expected_revision=latest.revision,
                    )
                    break
                except RevisionConflict:
                    if attempt == 2:
                        raise
        return {"actions": actions, "assessment_revision": saved.revision}


@router.get("/assessments/{identifier}/runs/{run_id}/export", dependencies=READ)
async def export(
    request: Request,
    identifier: str,
    run_id: str,
    portable: bool = False,
    user: User = Depends(current_user),
) -> Response:
    run = await _store(request).get_analysis_run(run_id)
    if run is None or run.assessment_id != identifier:
        raise HTTPException(404, "Assessment run not found.")
    if run.result is None:
        raise HTTPException(409, "The run has no recorded result to export.")
    if portable:
        await require_permission("changes.write")(user)
        temporary = tempfile.TemporaryDirectory(prefix="hst-assessment-")
        target = Path(temporary.name) / f"assessment-{run.id}.zip"
        try:
            with _errors():
                async with _cycle_lock(_store(request)):
                    await asyncio.to_thread(packages.build_portable, request.app.state.settings, run, target)
            return FileResponse(
                target,
                media_type="application/zip",
                filename=target.name,
                background=BackgroundTask(temporary.cleanup),
            )
        except BaseException:
            temporary.cleanup()
            raise
    with _errors():
        package = packages.export_document(run)
    return Response(
        json.dumps(package, sort_keys=True, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="assessment-{run.id}.json"'},
    )


@router.get("/assessments/{identifier}/runs/{run_id}/buckets", dependencies=READ)
async def result_bucket(
    request: Request,
    identifier: str,
    run_id: str,
    bucket: str = Query(max_length=64),
    offset: str = Query("0", pattern=r"^[0-9]{1,40}$"),
    limit: int = Query(250, ge=1, le=1000),
) -> dict:
    from hst.assessment.direct import run_isolated
    from hst.assessment.result_page import BUCKETS

    if bucket not in BUCKETS:
        raise HTTPException(400, "Unknown result bucket.")
    run = await _store(request).get_analysis_run(run_id)
    if run is None or run.assessment_id != identifier:
        raise HTTPException(404, "Assessment run not found.")
    reference = (run.result or {}).get("symbolic", {}).get("artifact_ref")
    if reference is None:
        raise HTTPException(409, "This run has no retained symbolic result artifact.")
    return await asyncio.to_thread(
        run_isolated,
        request.app.state.settings,
        {
            "analysis": {"kind": "symbolic-page"},
            "snapshot_refs": run.snapshot_refs,
            "artifact_ref": reference,
            "bucket": bucket,
            "offset": int(offset),
            "limit": limit,
        },
    )


@router.post("/assessments/{identifier}/runs/{run_id}/proposals", dependencies=WRITE, status_code=201)
async def save_verified_proposal(
    request: Request,
    identifier: str,
    run_id: str,
    body: SaveProposal,
    user: User = Depends(current_user),
) -> dict:
    store = _store(request)
    run = await store.get_analysis_run(run_id)
    if run is None or run.assessment_id != identifier:
        raise HTTPException(404, "Assessment run not found.")
    if body.change_id:
        previous = await store.get_change_revision(body.change_id)
        if previous is None or previous.definition.get("source_assessment_id") != identifier:
            raise HTTPException(404, "Proposal not found for this assessment.")
    with _errors():
        proposal = await proposals.save_proposal(store, run_id, actor=user.id, **body.model_dump())
    return proposal.as_dict()


@router.get("/change-revisions/{identifier}", dependencies=READ)
async def change_detail(request: Request, identifier: str, revision: int | None = Query(None, ge=1)) -> dict:
    item = await _store(request).get_change_revision(identifier, revision)
    if item is None:
        raise HTTPException(404, "Change revision not found.")
    return item.as_dict()


@router.get("/change-revisions/{identifier}/revisions", dependencies=READ)
async def change_history(request: Request, identifier: str, limit: int = Query(100, ge=1, le=1000)) -> dict:
    store = _store(request)
    if await store.get_change_revision(identifier) is None:
        raise HTTPException(404, "Change revision not found.")
    return {"revisions": [r.as_dict() for r in await store.list_change_revisions(identifier, limit)]}


@router.patch("/change-revisions/{identifier}", dependencies=WRITE)
async def revise_change(
    request: Request,
    identifier: str,
    body: ReviseChange,
    user: User = Depends(current_user),
) -> dict:
    store = _store(request)
    current = await store.get_change_revision(identifier)
    if current is None:
        raise HTTPException(404, "Change revision not found.")
    definition = {**current.definition, "intents": body.intents}
    if body.preconditions is not None:
        definition["preconditions"] = body.preconditions
    with _errors():
        if any(intent.get("kind") not in OVERLAY_KINDS for intent in body.intents):
            raise ValueError("A change contains an unsupported intent kind.")
        revised = await store.create_change_revision(
            title=body.title,
            definition=definition,
            created_by=user.id,
            change_id=identifier,
            expected_revision=body.expected_revision,
        )
    return revised.as_dict()


@router.get("/assessments/{identifier}/retention", dependencies=READ)
async def retention(request: Request, identifier: str) -> dict:
    store = _store(request)
    await _assessment(store, identifier)
    return await store.get_assessment_retention(identifier)


@router.put(
    "/assessments/{identifier}/retention", dependencies=[Depends(require_permission("settings.retention"))]
)
async def set_retention(
    request: Request,
    identifier: str,
    body: RetentionPolicy,
    user: User = Depends(current_user),
) -> dict:
    store = _store(request)
    await _assessment(store, identifier)
    with _errors():
        async with _cycle_lock(store):
            await store.set_assessment_retention(identifier, actor=user.id, **body.model_dump())
    return await store.get_assessment_retention(identifier)


@router.get("/assessments/{identifier}/runs/{run_id}/replay-status", dependencies=READ)
async def replay_availability(request: Request, identifier: str, run_id: str) -> dict:
    store = _store(request)
    run = await store.get_analysis_run(run_id)
    if run is None or run.assessment_id != identifier:
        raise HTTPException(404, "Assessment run not found.")
    if run.result is None:
        raise HTTPException(409, "The run has no recorded result to replay.")
    async with _cycle_lock(store, STATUS_LOCK_WAIT_S):
        status = await asyncio.to_thread(packages.replay_status, request.app.state.settings, run)
    return {**status, "retention": await store.get_assessment_retention(identifier)}
