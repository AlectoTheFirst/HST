"""The business application tools `app_applications` and `app_find_affected`.

The Postgres catalog is the application model. Both tools read the catalog.
The graph BusinessService and ServiceRequirement objects belong to a separate
model that no collector writes. The tools list them under `related`.

`app_applications` in `list` mode lists the newest revision of each
application. In `get` mode it reads one revision. With `resolve` it resolves
each declared connection against the selected run through
`resolve_application`, the function of `GET .../resolve`. The tool does not
write the resolution record. `app_find_affected` lists the applications
whose members name one of the given inventory objects, through the body of
`GET /api/business-applications/affected`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.results.words import from_engine, record
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    Gap,
    ItemEvidence,
    Missing,
    PageOut,
    catalogue_spec,
    gap_list,
    jsonable,
    unknowns_missing,
    whole_result,
)
from hst.twin_tools.stores import read_store, require

# Connections one resolved answer lists, and issues per connection.
MAX_CONNECTIONS = 200
MAX_ISSUES = 50
# Graph application-model objects one answer lists under `related`.
MAX_RELATED = 50

_RELATED_REASON = (
    "an object of the graph application model, which no collector writes; the catalog definition "
    "is the application model"
)

_RELATED_BY_NAME = """
MATCH (n:Obj)
WHERE (n:BusinessService OR n:ServiceRequirement) AND NOT n:Retired
  AND n.collection_ts = $snap
  AND toLower(coalesce(n.name, '')) = toLower($name)
RETURN n.uid AS uid, labels(n) AS labels, n.name AS name
ORDER BY uid LIMIT 50"""

_RELATED_BY_OBJECT = """
UNWIND $uids AS target
MATCH p = (app:Obj)-[:SRC|HAS|HAS_MEMBER|DEPENDS_ON|PART_OF*1..4]-(x:Obj {uid: target, collection_ts: $snap})
WHERE (app:BusinessService OR app:ServiceRequirement)
  AND all(n IN nodes(p) WHERE NOT n:Retired AND n.collection_ts = $snap)
  AND all(r IN relationships(p) WHERE r._retired_at IS NULL AND r.collection_ts = $snap)
RETURN DISTINCT app.uid AS uid, labels(app) AS labels, app.name AS name, target AS inventory_uid
ORDER BY uid, inventory_uid LIMIT 50"""


def _related(rows: list[dict[str, Any]], relation: str) -> list[dict[str, Any]]:
    out = []
    for row in rows[:MAX_RELATED]:
        label = next(
            (lb for lb in row.get("labels") or () if lb in ("BusinessService", "ServiceRequirement")), None
        )
        item = {
            "uid": row["uid"],
            "label": label,
            "name": row.get("name"),
            "relation": relation
            if row.get("inventory_uid") is None
            else f"{relation} {row['inventory_uid']}",
            "reason": _RELATED_REASON,
        }
        out.append(jsonable(item))
    return out


# --- shared by app_applications, app_find_affected and impact_evaluate_service -------------


def read_application(ctx: ToolContext, application_id: str, revision: int | None, *, field: str) -> Any:
    """One stored application revision, or `not_found` on `field`."""

    async def work(store: Any) -> Any:
        require(store, "get_application", "Business Applications")
        return await store.get_application(application_id, revision)

    item = read_store(ctx, work)
    if item is None:
        named = application_id if revision is None else f"{application_id} revision {revision}"
        raise ToolError("not_found", f"no Business Application {named} in the catalog", field=field)
    return item


def application_lookup(ctx: ToolContext) -> Callable[[str], Any]:
    """The newest stored revision of an application by id, or None, read from
    the app store of `ctx`. The `app_group` selector of the traffic resolver
    reads the catalog through it."""

    def lookup(application_id: str) -> Any:
        async def work(store: Any) -> Any:
            require(store, "get_application", "Business Applications")
            return await store.get_application(application_id, None)

        return read_store(ctx, work)

    return lookup


def published_reference(
    ctx: ToolContext, snap: snapshotmod.Snapshot, *, field: str = "snapshot"
) -> dict[str, Any]:
    """The snapshot reference a resolution records, as `GET .../resolve`
    builds it. A run without an evidence manifest is `snapshot_not_published`
    on `field`."""
    from hst.assessment import service as assessment_service

    if snap.cts is None:
        raise ToolError("snapshot_not_published", "no run is published", field=field)
    try:
        return assessment_service.snapshot_reference(ctx.settings, snap.snapshot_id)
    except ValueError as exc:
        raise ToolError("snapshot_not_published", str(exc), field=field) from None


def resolve_definition(
    session: Any,
    snap: snapshotmod.Snapshot,
    reference: dict[str, Any],
    item: Any,
    *,
    connection_ids: list[str] | None = None,
    field: str,
) -> dict[str, Any]:
    """The resolution of one stored revision at `snap`, computed and not saved."""
    from hst.applications.models import stored_definition
    from hst.applications.resolution import GraphInventoryReader, resolve_application

    if snap.cts is None:
        raise ToolError("snapshot_not_published", "no run is published", field="snapshot")
    try:
        return resolve_application(
            stored_definition(item.definition),
            revision=item.revision,
            snapshot=reference,
            reader=GraphInventoryReader(session, snap.cts),
            connection_ids=connection_ids,
        )
    except ValueError as exc:
        # Only the address bound of the resolver raises a message with "exceeds".
        if "exceeds" in str(exc):
            raise ToolError("limit_exceeded", str(exc), field=field) from None
        raise ToolError("invalid_argument", str(exc), field=field) from None


def connection_evidence(connection: dict[str, Any]) -> ItemEvidence:
    """A connection resolves when ready, and is unresolved with its issue
    codes otherwise."""
    if connection.get("readiness") == "ready":
        return ItemEvidence.of(from_engine("connection-resolves", "holds"), basis="derived")
    open_on = [
        Missing(code=str(issue.get("code")), subject=issue.get("path"), detail=issue.get("detail"))
        for issue in connection.get("issues") or ()
    ] or [Missing(code="not-ready", detail=str(connection.get("readiness") or "the connection is not ready"))]
    unresolved = from_engine("connection-resolves", "not-established", missing=open_on)
    return ItemEvidence.of(unresolved, basis="derived")


def issue_gaps(issues: list[dict[str, Any]]) -> tuple[list[Gap], bool]:
    """The resolution issues as envelope gaps. The subject of a gap is the path of the issue."""
    return gap_list(
        {"code": issue.get("code"), "subject": issue.get("path"), "detail": issue.get("detail")}
        for issue in issues
    )


# --- app_applications ----------------------------------------------------------------------


class ApplicationsListInput(selectors.ToolInput):
    """The newest revision of each application in the catalog."""

    mode: Literal["list"]
    name_contains: str | None = Field(
        default=None,
        max_length=200,
        description="Only applications whose name contains this text, compared without case.",
    )
    limit: selectors.Limit = selectors.DEFAULT_LIMIT


class ApplicationsGetInput(selectors.ToolInput):
    """One application revision, resolved at the selected run on request."""

    mode: Literal["get"]
    application_id: str = Field(min_length=1, max_length=200, description="The application id.")
    revision: int | None = Field(default=None, ge=1, description="Omitted, the newest revision.")
    resolve: bool = Field(
        default=False,
        description=(
            "Resolve each declared connection at the selected run and return its readiness, request "
            "and issues. Needs a run with an evidence manifest. The resolution is not saved."
        ),
    )


class AppApplicationsInput(
    RootModel[Annotated[ApplicationsListInput | ApplicationsGetInput, Field(discriminator="mode")]]
):
    """mode: list lists the catalog; mode: get reads one application."""


class AppApplicationsResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["list", "get"]
    items: list[dict[str, Any]] | None = None
    definition: dict[str, Any] | None = None
    connections: list[dict[str, Any]] | None = None
    related: list[dict[str, Any]] = Field(
        default_factory=list, description="graph application-model objects, reported as evidence only"
    )


def _summary(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "revision": item.revision,
        "digest": item.digest,
        "created_at": item.created_at,
        "created_by": item.created_by,
    }


def _list(ctx: ToolContext, params: ApplicationsListInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "app_applications", params, session)

        async def work(store: Any) -> list[Any]:
            require(store, "list_applications", "Business Applications")
            return list(await store.list_applications(params.limit))

        read = read_store(ctx, work)
        wanted = (params.name_contains or "").lower()
        stored = ItemEvidence.of(record("stored"), basis="stored").model_dump(mode="json")
        items = [{**_summary(item), "evidence": stored} for item in read if wanted in str(item.name).lower()]
        truncated = len(read) >= params.limit
        unknowns = (
            [f"the catalog read stopped at {params.limit} applications; the filter applied to those"]
            if truncated
            else []
        )
        return call.finish(
            session,
            result={"mode": "list", "items": items, "related": []},
            evidence=Evidence(
                result=whole_result((i["evidence"]["result"] for i in items), unknowns=unknowns),
                unknowns=unknowns,
            ),
            page=PageOut(truncated=truncated, total=None if truncated else len(items), limit=params.limit),
            engine_function="hst.assessment.store.AssessmentStore.list_applications",
        )


def _get(ctx: ToolContext, params: ApplicationsGetInput) -> str:
    from hst.applications.models import upgraded_document

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "app_applications", params, session)
        item = read_application(ctx, params.application_id, params.revision, field="application_id")
        snap = call.snapshot
        related = _related(
            pathmod._read(pathmod.pinned(session, snap), _RELATED_BY_NAME, name=str(item.name)), "name match"
        )
        result: dict[str, Any] = {
            **_summary(item),
            "mode": "get",
            "definition": jsonable(upgraded_document(item.definition)),
            "evidence": ItemEvidence.of(record("declared"), basis="declared").model_dump(mode="json"),
            "connections": None,
            "resolution": None,
            "related": related,
        }
        evidence = Evidence(result=record("declared"))
        queries = [("fixed", "hst.twin_tools.apps._RELATED_BY_NAME")]
        if params.resolve:
            reference = published_reference(ctx, snap)
            resolved = resolve_definition(session, snap, reference, item, field="application_id")
            connections = [
                {
                    "id": c["id"],
                    "service_id": c.get("service_id"),
                    "readiness": c.get("readiness"),
                    "request": c.get("request"),
                    "issues": list(c.get("issues") or [])[:MAX_ISSUES],
                    "issues_truncated": len(c.get("issues") or []) > MAX_ISSUES,
                    "evidence": connection_evidence(c).model_dump(mode="json"),
                }
                for c in resolved["connections"][:MAX_CONNECTIONS]
            ]
            result["connections"] = connections
            result["resolution"] = {
                "ready": resolved["ready"],
                "digest": resolved["digest"],
                "snapshot": resolved["snapshot"],
                "connection_count": len(resolved["connections"]),
                "connections_truncated": len(resolved["connections"]) > MAX_CONNECTIONS,
                "saved": False,
            }
            gaps, gaps_truncated = issue_gaps(resolved["issues"])
            evidence = Evidence(
                result=whole_result(c["evidence"]["result"] for c in connections),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=["the resolution is computed for this call and not saved"],
            )
        return call.finish(
            session,
            result=result,
            evidence=evidence,
            engine_function=(
                "hst.applications.resolution.resolve_application"
                if params.resolve
                else "hst.assessment.store.AssessmentStore.get_application"
            ),
            queries=queries,
        )


def app_applications(ctx: ToolContext, params: ApplicationsListInput | ApplicationsGetInput) -> str:
    if isinstance(params, ApplicationsListInput):
        return _list(ctx, params)
    return _get(ctx, params)


# --- app_find_affected ---------------------------------------------------------------------


class AppFindAffectedInput(selectors.ToolInput):
    """The applications whose definitions name one of the given inventory objects."""

    inventory_uids: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(
        min_length=1, max_length=50, description="Graph uids of inventory objects, at most 50."
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="The most application definitions scanned, as GET /api/business-applications/affected.",
    )


class AppFindAffectedResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    applications: list[dict[str, Any]]
    definitions_scanned: int
    complete: bool
    related: list[dict[str, Any]] = Field(
        default_factory=list, description="graph application-model objects, reported as evidence only"
    )


def app_find_affected(ctx: ToolContext, params: AppFindAffectedInput) -> str:
    import neo4j.exceptions

    from hst.app.routes.business_applications import find_affected

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "app_find_affected", params, session)

        async def work(store: Any) -> dict[str, Any]:
            require(store, "list_applications", "Business Applications")
            return await find_affected(store, list(params.inventory_uids), params.limit)

        body = jsonable(read_store(ctx, work))
        coverage = body["coverage"]
        stored = ItemEvidence.of(record("stored"), basis="stored").model_dump(mode="json")
        applications = [{**match, "evidence": stored} for match in body["applications"]]
        unknowns = [coverage["meaning"]]
        if not coverage["complete"]:
            unknowns.append(f"the scan stopped at {params.limit} definitions; raise limit to scan more")
        try:
            rows = pathmod._read(
                pathmod.pinned(session, call.snapshot), _RELATED_BY_OBJECT, uids=list(params.inventory_uids)
            )
        except (neo4j.exceptions.Neo4jError, neo4j.exceptions.DriverError) as exc:
            rows = []
            unknowns.append(
                "the graph application-model objects linked to these uids were not read "
                f"({type(exc).__name__}), so related is empty"
            )
        related = _related(rows, "linked to")
        return call.finish(
            session,
            result={
                "applications": applications,
                "definitions_scanned": coverage["definitions_scanned"],
                "limit": coverage["limit"],
                "complete": coverage["complete"],
                "related": related,
            },
            evidence=Evidence(
                result=record("declared" if applications else "empty", missing=unknowns_missing(unknowns)),
                complete=coverage["complete"],
                unknowns=unknowns,
                absence="not_recorded",
            ),
            engine_function="hst.app.routes.business_applications.find_affected",
            queries=[("fixed", "hst.twin_tools.apps._RELATED_BY_OBJECT")],
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="app_applications",
            description=(
                "Read the Business Application catalog, the application model. mode: list lists the "
                "newest revision of each application, filtered by name_contains, at most limit. mode: get "
                "reads one application's definition; with resolve: true each declared connection is "
                "resolved at the selected run and returned with its readiness, compiled request and "
                "issues. Resolution needs a run with an evidence manifest, and the tool does not save it. "
                "related lists graph BusinessService and ServiceRequirement objects of the same name as "
                "evidence; they are not applications."
            ),
            input_model=AppApplicationsInput,
            result_model=AppApplicationsResult,
            run=app_applications,
        )
    )
    registry.register(
        catalogue_spec(
            name="app_find_affected",
            description=(
                "List the Business Applications whose definitions name one of the given inventory uids "
                "as a member, with the revision and the matched uids. Only explicit inventory references "
                "count: an application absent from the answer can still depend on the object. complete "
                "says whether every definition was scanned. related lists graph "
                "BusinessService and ServiceRequirement objects linked to the uids, as evidence only."
            ),
            input_model=AppFindAffectedInput,
            result_model=AppFindAffectedResult,
            run=app_find_affected,
        )
    )
