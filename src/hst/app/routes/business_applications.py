"""Revisioned Business Application import, export and resolution API."""

from __future__ import annotations

import asyncio
import functools
import logging
from contextlib import contextmanager
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.app.auth import current_user, require_permission
from hst.app.permissions import permissions_for
from hst.app.store import User
from hst.applications import flows as application_flows
from hst.applications import inventory_graph
from hst.applications import review as application_review
from hst.applications import service as application_service
from hst.applications.models import (
    MAX_CONNECTIONS,
    MAX_SERVICES,
    BusinessApplicationDefinition,
    Identifier,
    RemovalSet,
    stored_definition,
    upgraded_document,
)
from hst.applications.resolution import GraphInventoryReader, resolve_application
from hst.applications.service import ImportMode
from hst.applications.validation import FlowNotEvaluated, record_validation, validate_application
from hst.applications.yaml_format import ApplicationFormatError, normalized_document
from hst.assessment import service as assessment_service
from hst.assessment.store import RevisionConflict
from hst.core import db
from hst.core import snapshot as snapshotmod

log = logging.getLogger(__name__)
router = APIRouter()
require_graph_read = require_permission("graph.read")  # B008 forbids this call in an argument default.
READ = [Depends(require_graph_read)]
WRITE = [Depends(require_permission("changes.write"))]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# The id of an application-generation record, and the digest of an
# application-validation record, as a commit body names them.
GenerationId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")]
RecordDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SaveApplication(ApiModel):
    definition: BusinessApplicationDefinition
    expected_revision: int = Field(default=0, ge=0)
    source: Literal["editor", "trace", "api"] = "api"
    generation_id: GenerationId | None = None
    validation_digest: RecordDigest | None = None


class ImportPreviewBody(ApiModel):
    yaml: str = Field(min_length=1)
    removals: RemovalSet = Field(default_factory=RemovalSet)
    mode: ImportMode = "merge"
    # A recorded validation of the same definition. Its resolution gives the
    # mapping issues of the inventory members.
    validation_digest: RecordDigest | None = None


class ImportCommitBody(ImportPreviewBody):
    base_revision: int = Field(ge=0)
    base_digest: str
    preview_digest: str = Field(min_length=64, max_length=64)
    generation_id: GenerationId | None = None


class ValidateBody(ApiModel):
    yaml: str = Field(min_length=1)
    snapshot: str = Field(min_length=1)
    mode: ImportMode = "merge"
    application_id: Identifier | None = None
    evaluate: bool = False
    record: bool = False


class ReviewBody(ApiModel):
    reason: str = Field(min_length=1, max_length=500)


class ResolveBody(ApiModel):
    snapshot: str = Field(min_length=1)
    revision: int | None = Field(default=None, ge=1)
    service_ids: list[str] = Field(default_factory=list, max_length=MAX_SERVICES)
    connection_ids: list[str] = Field(default_factory=list, max_length=MAX_CONNECTIONS)


def _store(request: Request) -> Any:
    store = request.app.state.store
    if not hasattr(store, "get_application"):
        raise HTTPException(503, "Business Application storage is unavailable")
    return store


@contextmanager
def _errors():
    try:
        yield
    except RevisionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ApplicationFormatError, ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc


def _served(item: Any) -> dict:
    """A stored revision as the routes serve it. The definition is in the current
    shape (`upgraded_document`). The digest is the stored digest."""
    return {**item.as_dict(), "definition": upgraded_document(item.definition)}


async def _application(store: Any, identifier: str, revision: int | None = None) -> Any:
    item = await store.get_application(identifier, revision)
    if item is None:
        raise HTTPException(404, "Business Application not found")
    return item


@router.post("/business-applications/import/preview", dependencies=WRITE)
async def preview_import(body: ImportPreviewBody, request: Request) -> dict:
    with _errors():
        return (
            await application_service.preview_import(
                _store(request), body.yaml, body.removals, body.mode, validation_digest=body.validation_digest
            )
        ).as_dict()


async def _resolve_at_commit(request: Request, saved: Any, origin: dict, base_revision: int) -> dict:
    """Resolve a saved revision at the snapshot of its validation and save the
    resolved scope. Coverage and Analysis use the saved scope.

    The resolution document names the revision number. The number exists only
    after the insert. A failed resolution leaves the revision saved. The response
    then has the error, and Coverage can resolve the revision again.

    A commit whose definition equals the newest revision inserts nothing and
    returns that revision, `base_revision`, with the origin it was saved with.
    Nothing is resolved then, and `resolution_digest` is null.
    """
    outcome: dict[str, str | None] = {"resolution_digest": None, "resolution_error": None}
    validation = origin["validation"]
    if validation is None or saved.revision == base_revision:
        return outcome
    settings = request.app.state.settings
    try:
        reference = await asyncio.to_thread(
            assessment_service.snapshot_reference, settings, validation["snapshot"]["snapshot"]
        )
        result = await asyncio.to_thread(
            _resolve_graph, settings, saved.definition, saved.revision, reference, [], []
        )
        await _store(request).save_application_resolution(result)
    except ValueError as exc:
        outcome["resolution_error"] = str(exc)
    except Exception:
        log.warning(
            "resolution of application %s revision %s failed after the commit",
            saved.id,
            saved.revision,
            exc_info=True,
        )
        outcome["resolution_error"] = "the saved revision could not be resolved at the validation snapshot"
    else:
        outcome["resolution_digest"] = result["digest"]
    return outcome


@router.post("/business-applications/import/commit", dependencies=WRITE, status_code=201)
async def commit_import(body: ImportCommitBody, request: Request, user: User = Depends(current_user)) -> dict:
    """Commit a reviewed import. With `validation_digest`, the revision records
    that validation and is resolved at its snapshot after the insert. A
    `generation_id` that names an edit needs the base revision and digest the
    edit started from. Any other base answers 409."""
    store = _store(request)
    with _errors():
        await application_service.check_edit_base(
            store, body.generation_id, base_revision=body.base_revision, base_digest=body.base_digest
        )
        origin = await application_service.revision_origin(
            store,
            "import",
            generation_id=body.generation_id,
            validation_digest=body.validation_digest,
            actor=user.id,
        )
        saved = await application_service.commit_import(
            store,
            body.yaml,
            body.removals,
            base_revision=body.base_revision,
            base_digest=body.base_digest,
            preview_digest=body.preview_digest,
            actor=user.id,
            mode=body.mode,
            origin=origin,
        )
    await _flag_stale_bindings(store, saved, body.base_revision)
    return {**saved.as_dict(), **await _resolve_at_commit(request, saved, origin, body.base_revision)}


async def _save(request: Request, body: SaveApplication, expected_revision: int, user: User) -> dict:
    """Save the body's definition onto `expected_revision`. A `generation_id`
    that names an edit needs `expected_revision` to be the revision the edit
    started from, as a commit does. Any other base answers 409."""
    store = _store(request)
    with _errors():
        base = (
            await store.get_application(body.definition.id, expected_revision) if expected_revision else None
        )
        await application_service.check_edit_base(
            store,
            body.generation_id,
            base_revision=expected_revision,
            base_digest=base.digest if base is not None else "",
        )
        origin = await application_service.revision_origin(
            store,
            body.source,
            generation_id=body.generation_id,
            validation_digest=body.validation_digest,
            actor=user.id,
        )
        saved = await application_service.save_definition(
            store, body.definition, expected_revision=expected_revision, actor=user.id, origin=origin
        )
    await _flag_stale_bindings(store, saved, expected_revision)
    return {**saved.as_dict(), **await _resolve_at_commit(request, saved, origin, expected_revision)}


async def _flag_stale_bindings(store: Any, saved: Any, base_revision: int) -> None:
    """Open the review flag of a new revision whose older revisions an
    Analysis session binds. A save equal to the newest revision returns
    `base_revision` and opens nothing."""
    if saved.revision != base_revision:
        await application_review.flag_stale_bindings(store, saved.id, saved.revision)


# Registered before the {application_id} routes, and `validate` is a reserved
# application id that no new revision can take.
@router.post("/business-applications/validate")
async def validate_import(
    body: ValidateBody, request: Request, user: User = Depends(require_graph_read)
) -> dict:
    """Validate YAML at a pinned snapshot.

    Stage 1 and 2 errors come back with their line and column and the call
    still answers 200. A snapshot that cannot be pinned, or a resolution that
    exceeds its address bound, answers 422 as POST .../resolve does. The import
    preview is included only for a caller who may commit it. With `evaluate`,
    each ready connection is evaluated in a child process before the call
    answers, and `flows` holds the verdicts.

    Without `record` nothing is written and `validation_digest` is null. With
    `record`, which needs changes.write, a result without stage 1 or 2 errors
    is stored as an application-validation record, with the stage 4 verdicts
    when `evaluate` ran them, and `validation_digest` names it for a commit.
    """
    if body.record and "changes.write" not in permissions_for(user.role):
        raise HTTPException(403, "requires permission: changes.write")
    settings = request.app.state.settings
    store = _store(request)
    with _errors():
        reference = await asyncio.to_thread(assessment_service.snapshot_reference, settings, body.snapshot)

        async def resolve(definition: BusinessApplicationDefinition, revision: int) -> dict:
            return await asyncio.to_thread(
                _resolve_graph, settings, normalized_document(definition), revision, reference, [], []
            )

        result = await validate_application(
            store,
            body.yaml,
            mode=body.mode,
            snapshot=reference,
            resolve=resolve,
            application_id=body.application_id,
            include_preview="changes.write" in permissions_for(user.role),
            evaluate=functools.partial(_evaluate_flow, settings, reference) if body.evaluate else None,
        )
        result["validation_digest"] = await record_validation(store, result) if body.record else None
        return result


def _evaluate_flow(settings: Any, reference: dict, request: dict) -> dict:
    """The evaluate result of one compiled connection request at the validation
    snapshot. The request is the question of an Analysis evaluate run with no
    change set. A child process answers it. A busy process slot and a refused
    evaluation raise `FlowNotEvaluated`."""
    from hst.assessment import direct

    try:
        with db.session(settings, access_mode="READ") as session:
            snap = snapshotmod.resolve(session, settings, int(reference["snapshot"]))
            return direct.evaluate_pinned(
                settings,
                pathmod.pinned(session, snap),
                snap,
                intents=[],
                requirement=None,
                request=request,
                mode="possible",
            )
    except direct.CapacityBusy as exc:
        raise FlowNotEvaluated("capacity-busy") from exc
    except HTTPException as exc:
        raise FlowNotEvaluated("evaluation-failed", str(exc.detail)) from exc


@router.get("/business-applications", dependencies=READ)
async def list_applications(request: Request, limit: int = Query(100, ge=1, le=1000)) -> dict:
    """The newest revision of each application. `review` is `open` when the
    application has an open review flag. `analyses` is the number of Analysis
    sessions that reference the application. `connections` is the number of
    connections of the newest revision."""
    store = _store(request)
    items = await store.list_applications(limit)
    flagged = await store.open_application_reviews([item.id for item in items])
    counts = await application_review.session_counts(store)
    return {
        "applications": [
            {
                **_served(item),
                "review": "open" if item.id in flagged else None,
                "analyses": counts[item.id],
                "connections": len(item.definition.get("connections") or []),
            }
            for item in items
        ]
    }


@router.post("/business-applications", dependencies=WRITE, status_code=201)
async def create_application(
    body: SaveApplication, request: Request, user: User = Depends(current_user)
) -> dict:
    if body.expected_revision != 0:
        raise HTTPException(422, "new applications require expected_revision 0")
    return await _save(request, body, 0, user)


@router.get("/business-applications/affected", dependencies=READ)
async def affected_applications(
    request: Request,
    inventory_uid: Annotated[list[str], Query(min_length=1, max_length=50)],
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    """A bounded lookup in the definitions. It reports the mapping coverage."""
    return await find_affected(_store(request), inventory_uid, limit)


async def find_affected(store: Any, inventory_uids: list[str], limit: int) -> dict:
    """The applications among the newest `limit` definitions whose members
    reference one of `inventory_uids` explicitly, with the scan's coverage."""
    wanted = set(inventory_uids)
    matches = []
    scanned = await store.list_applications(limit)
    for item in scanned:
        references = sorted(
            {
                member["inventory"]["uid"]
                for group in item.definition.get("groups", [])
                for member in group.get("members", [])
                if member.get("inventory", {}).get("uid") in wanted
            }
        )
        if references:
            matches.append(
                {
                    "application_id": item.id,
                    "revision": item.revision,
                    "digest": item.digest,
                    "name": item.name,
                    "matched_inventory_uids": references,
                }
            )
    return {
        "applications": matches,
        "coverage": {
            "definitions_scanned": len(scanned),
            "limit": limit,
            "complete": len(scanned) < limit,
            "meaning": "explicit inventory references only; absence is not proof of no impact",
        },
    }


@router.get("/business-applications/{application_id}", dependencies=READ)
async def get_application(
    application_id: str, request: Request, revision: int | None = Query(default=None, ge=1)
) -> dict:
    return {"application": _served(await _application(_store(request), application_id, revision))}


@router.put("/business-applications/{application_id}", dependencies=WRITE)
async def revise_application(
    application_id: str,
    body: SaveApplication,
    request: Request,
    user: User = Depends(current_user),
) -> dict:
    if body.definition.id != application_id:
        raise HTTPException(422, "application id cannot change")
    return await _save(request, body, body.expected_revision, user)


@router.get("/business-applications/{application_id}/history", dependencies=READ)
async def application_history(
    application_id: str, request: Request, limit: int = Query(100, ge=1, le=1000)
) -> dict:
    await _application(_store(request), application_id)
    return {
        "revisions": [
            _served(item) for item in await _store(request).list_application_revisions(application_id, limit)
        ]
    }


@router.get("/business-applications/{application_id}/analyses", dependencies=READ)
async def application_analyses(application_id: str, request: Request) -> dict:
    """The Analysis sessions that reference the application, newest first.
    `stale` is true when a bound revision is older than `current_revision`."""
    store = _store(request)
    item = await _application(store, application_id)
    return {"analyses": await application_review.analyses(store, item.id, item.revision)}


async def _review_documents(store: Any, reviews: list[Any]) -> list[dict]:
    """The `as_dict` of each review with `opened_by_name` and `closed_by_name`,
    the username of `opened_by` and `closed_by`, or None."""
    ids = {
        user_id
        for review in reviews
        for user_id in (review.opened_by, review.closed_by)
        if user_id is not None
    }
    names = {}
    for user_id in ids:
        user = await store.get_user(user_id)
        names[user_id] = user.username if user else None
    return [
        {
            **review.as_dict(),
            "opened_by_name": names.get(review.opened_by),
            "closed_by_name": names.get(review.closed_by),
        }
        for review in reviews
    ]


@router.get("/business-applications/{application_id}/review", dependencies=READ)
async def application_review_flags(
    application_id: str, request: Request, limit: int = Query(100, ge=1, le=1000)
) -> dict:
    """The open review flag of the application, and all its flags newest first."""
    store = _store(request)
    await _application(store, application_id)
    history = await store.list_application_reviews(application_id, limit)
    current = next((review for review in history if review.state == "open"), None)
    if current is None:
        current = (await store.open_application_reviews([application_id])).get(application_id)
    documents = await _review_documents(store, [current, *history] if current else history)
    return {
        "current": documents[0] if current else None,
        "history": documents[1:] if current else documents,
    }


@router.post("/business-applications/{application_id}/review", dependencies=WRITE, status_code=201)
async def open_review(
    application_id: str, body: ReviewBody, request: Request, user: User = Depends(current_user)
) -> dict:
    """Open a review flag by hand at the newest revision. The route answers 409
    when a flag is open."""
    store = _store(request)
    item = await _application(store, application_id)
    review = await store.open_application_review(
        item.id, reason=body.reason, revision=item.revision, opened_by=user.id
    )
    if review is None:
        raise HTTPException(409, "the application has an open review flag")
    return (await _review_documents(store, [review]))[0]


@router.post("/business-applications/{application_id}/review/close", dependencies=WRITE)
async def close_review(application_id: str, request: Request, user: User = Depends(current_user)) -> dict:
    """Close the open review flag. The route answers 409 when no flag is open."""
    store = _store(request)
    await _application(store, application_id)
    review = await store.close_application_review(application_id, closed_by=user.id)
    if review is None:
        raise HTTPException(409, "the application has no open review flag")
    return (await _review_documents(store, [review]))[0]


@router.get("/business-applications/{application_id}/export", dependencies=READ)
async def export_application(
    application_id: str, request: Request, revision: int | None = Query(default=None, ge=1)
) -> Response:
    item = await _application(_store(request), application_id, revision)
    content = application_service.export_revision(item)
    return Response(
        content,
        media_type="application/yaml",
        headers={
            "Content-Disposition": f'attachment; filename="{item.id}-r{item.revision}.yaml"',
            "X-HST-Application-Revision": str(item.revision),
            "X-HST-Application-Digest": item.digest,
        },
    )


def _resolve_graph(
    settings: Any,
    definition: dict,
    revision: int,
    reference: dict,
    services: list[str],
    connections: list[str],
) -> dict:
    """Resolve `definition` at the pinned run of `reference` in a READ session.
    The driver refuses any write."""
    with db.session(settings, access_mode="READ") as session:
        snap = snapshotmod.resolve(session, settings, int(reference["snapshot"]))
        if snap.cts is None:
            raise ValueError("the selected snapshot has no committed identity")
        return resolve_application(
            stored_definition(definition),
            revision=revision,
            snapshot=reference,
            reader=GraphInventoryReader(session, snap.cts),
            service_ids=services,
            connection_ids=connections,
        )


@router.post("/business-applications/{application_id}/resolve", dependencies=WRITE)
async def resolve_and_record_scope(application_id: str, body: ResolveBody, request: Request) -> dict:
    """Resolve a revision at a pinned snapshot and save the resolved scope that
    an Analysis session references."""
    item = await _application(_store(request), application_id, body.revision)
    with _errors():
        reference = await asyncio.to_thread(
            assessment_service.snapshot_reference, request.app.state.settings, body.snapshot
        )
        result = await asyncio.to_thread(
            _resolve_graph,
            request.app.state.settings,
            item.definition,
            item.revision,
            reference,
            body.service_ids,
            body.connection_ids,
        )
        await _store(request).save_application_resolution(result)
        return result


def _resolved_inventory(
    settings: Any, definition: dict, revision: int, reference: dict, connections: list[str]
) -> tuple[dict, list[dict]]:
    """Resolve `definition` at the pinned run of `reference` and read the
    inventory objects it bound, in one READ session. Nothing is saved."""
    with db.session(settings, access_mode="READ") as session:
        snap = snapshotmod.resolve(session, settings, int(reference["snapshot"]))
        if snap.cts is None:
            raise ValueError("the selected snapshot has no committed identity")
        resolution = resolve_application(
            stored_definition(definition),
            revision=revision,
            snapshot=reference,
            reader=GraphInventoryReader(session, snap.cts),
            service_ids=[],
            connection_ids=connections,
        )
        rows = inventory_graph.read_inventory(session, snap.cts, inventory_graph.inventory_uids(resolution))
        return resolution, rows


async def _at_run(
    request: Request, application_id: str, snapshot: str, revision: int | None, connections: list[str]
) -> tuple[Any, dict, dict, list[dict]]:
    """The revision, the pinned reference, the read-only resolution at that
    run and the inventory rows it bound."""
    item = await _application(_store(request), application_id, revision)
    settings = request.app.state.settings
    with _errors():
        reference = await asyncio.to_thread(assessment_service.snapshot_reference, settings, snapshot)
        resolution, rows = await asyncio.to_thread(
            _resolved_inventory, settings, item.definition, item.revision, reference, connections
        )
    return item, reference, resolution, rows


@router.get("/business-applications/{application_id}/graph", dependencies=READ)
async def application_graph(
    application_id: str,
    request: Request,
    snapshot: str = Query(min_length=1),
    revision: int | None = Query(default=None, ge=1),
) -> dict:
    """The revision with the inventory objects its members resolve to at the
    pinned run, as an Explore graph payload. The route saves nothing, needs
    graph.read only and runs no trace or evaluation."""
    item, reference, resolution, rows = await _at_run(request, application_id, snapshot, revision, [])
    uids = inventory_graph.inventory_uids(resolution)
    return {
        "application": {"id": item.id, "revision": item.revision, "digest": item.digest, "name": item.name},
        "snapshot": {key: reference.get(key) for key in ("snapshot", "manifest_sha256", "estate")},
        "resolution_digest": resolution["digest"],
        "issues": resolution["issues"],
        **inventory_graph.application_graph(
            item.definition, revision=item.revision, resolution=resolution, rows=rows
        ),
        "library_query": {"key": "application-inventory", "params": {"uids": ",".join(uids)}},
    }


@router.get("/business-applications/{application_id}/flows", dependencies=READ)
async def application_flow_overlay(
    application_id: str,
    request: Request,
    snapshot: str = Query(min_length=1),
    revision: int | None = Query(default=None, ge=1),
    connection_id: Annotated[list[str] | None, Query(max_length=MAX_CONNECTIONS)] = None,
) -> dict:
    """The flows of the revision for a map at the pinned run. Each connection
    has its state, its resolution issues and endpoints at that run, and the
    distinct paths of the stored evaluation chosen for it
    (`applications/flows.py`). The route runs no trace or evaluation. A
    connection without a stored evaluation is not evaluated."""
    connections = list(dict.fromkeys(connection_id or []))
    item, reference, resolution, rows = await _at_run(
        request, application_id, snapshot, revision, connections
    )
    wanted = connections or [connection["id"] for connection in item.definition.get("connections", [])]
    evaluations = await application_flows.find_evaluations(
        _store(request),
        item.id,
        snapshot=str(reference["snapshot"]),
        revision=item.revision,
        connection_ids=wanted,
    )
    return application_flows.overlay(
        application=item.as_dict(),
        definition=item.definition,
        reference=reference,
        resolution=resolution,
        anchors=inventory_graph.device_anchors(rows),
        evaluations=evaluations,
        connection_ids=connections,
    )
