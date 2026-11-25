"""Query tools: `query_catalog`, `query_run_named` and `query_cypher`.

`graph_schema` is the graph model and the Cypher conventions.
`query_run_named` runs a catalog query with its declared parameters and the
selected run bound as `$snap`, through `named_query` and `run_named`.
`query_cypher` runs read-only model-authored Cypher under the rules of
`POST /api/cypher` and the pinning rule of the model surfaces, through
`check_cypher` and `read_cypher`, and writes one audit entry per call.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.app.tables import (
    LATEST_REFUSAL,
    LATEST_TOKEN,
    MAX_QUERY_BYTES,
    QueryRejected,
    ResultTooLarge,
    audit_outcome,
    check_pinned,
    run_readonly,
)
from hst.core import db as dbmod
from hst.core.labels import LABELS, RELS
from hst.queries import catalog
from hst.results.words import record as completeness
from hst.twin_tools import selectors
from hst.twin_tools.envelope import Call, Evidence, PageOut, catalogue_spec, jsonable, unknowns_missing

SCHEMA_CONVENTIONS = (
    "Every node has a uid, e.g. dev:<name> (a device's short hostname, minted once and then kept), "
    "ip:<anchor>:<addr>, pfx:<anchor>:<cidr> (anchor = owning VrfInstance "
    "uid, an l2seg uid, or a source-scope string), l2seg:<site>:vlan<vid>.",
    "IPs and prefixes are always scoped by L3Domain; there is no globally unique IP.",
    "All nodes carry :Obj plus layer labels. Every collection run "
    "re-creates the graph under a shared collection_ts, and old runs stay "
    "in the database. Retention keeps 30 collection cycles by default, plus "
    "the device runs between them and the runs pinned by saved assessments. "
    "$snap is bound to the current run before the Cypher executes, and only "
    "a pattern anchored with $snap is pinned: give one node per connected "
    "pattern component :Obj and 'x.collection_ts = $snap', which seeks the "
    "run's index. An operator-invented Site carries no run, so pin a Site with "
    "'(s:Meta OR s.collection_ts = $snap)'. "
    "An unguarded MATCH reads every retained run and returns one copy of "
    "each object per run. A current-state read is "
    "'MATCH (d:Device:Obj) WHERE d.collection_ts = $snap RETURN d'. "
    "Relationships never cross runs, so one guarded anchor per connected "
    "pattern component is enough. query_cypher refuses the Latest label. "
    "No writer emits :Retired or _retired_at; a graph that holds them "
    "predates the cycle model.",
    "Loader bookkeeping properties: collection_ts (the run's version key), "
    "collected_at (true collection time), carried (true when a source did "
    "not run this cycle and the object was copied forward from the "
    "previous one), plus the _-prefixed _scope and _sources. Everything "
    "else is payload.",
    "Nodes that can permit/deny/rewrite traffic carry :Gate.",
    "Derived edges (reasoner conclusions, e.g. stitched cabling) have derived: true and a rule property.",
    "A full-text index 'obj_names' covers name, description and hostname: "
    "CALL db.index.fulltext.queryNodes('obj_names', $q).",
)


def graph_schema() -> dict[str, Any]:
    """The graph model: node labels (with layer and gate flag), relationship
    types, and the conventions needed to write correct Cypher against the twin."""
    return {
        "labels": {
            name: {"layers": list(spec.layers), "gate": spec.gate} for name, spec in sorted(LABELS.items())
        },
        "relationships": sorted(RELS),
        "conventions": list(SCHEMA_CONVENTIONS),
    }


# --- query_catalog -------------------------------------------------------------------------


class SchemaCatalogInput(selectors.ToolInput):
    """The graph model and the Cypher conventions."""

    mode: Literal["schema"]
    label: str | None = Field(
        default=None,
        max_length=64,
        description="Add the property keys that nodes of this label carry in the run.",
    )


class ListCatalogInput(selectors.ToolInput):
    """The named queries."""

    mode: Literal["list"]
    group: str | None = Field(
        default=None, max_length=64, description="Only the named queries of this group."
    )


class QueryCatalogInput(
    RootModel[Annotated[SchemaCatalogInput | ListCatalogInput, Field(discriminator="mode")]]
):
    """mode: schema returns the graph model; mode: list returns the named queries."""


class QueryCatalogResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["schema", "list"]
    labels: dict[str, Any] | None = None
    relationships: list[str] | None = None
    conventions: list[str] | None = None
    properties: list[dict[str, Any]] | None = None
    items: list[dict[str, Any]] | None = None


# `query_catalog` reads the property keys of at most this many nodes of one label.
PROPERTY_SAMPLE = 200


def _label_properties(settings: Any, snap: Any, label: str) -> tuple[int, list[dict[str, Any]]]:
    """The count of sampled nodes of `label`, and each property key with the
    count of sampled nodes that have it. `label` is a registered label."""
    table = run_readonly(
        settings,
        f"MATCH (n:`{label}`:Obj) WHERE n.collection_ts = $snap "
        f"WITH n LIMIT {PROPERTY_SAMPLE} WITH collect(n) AS nodes "
        "UNWIND nodes AS n UNWIND keys(n) AS key WITH size(nodes) AS sampled, key "
        "WHERE NOT key STARTS WITH '_' "
        "RETURN sampled, key, count(*) AS nodes ORDER BY nodes DESC, key",
        {"snap": snap},
        trusted=True,
    )
    rows = [dict(zip(table["columns"], item["row"], strict=True)) for item in table["data"]]
    sampled = rows[0]["sampled"] if rows else 0
    return sampled, [{"name": r["key"], "nodes": r["nodes"]} for r in rows]


def query_catalog(ctx: ToolContext, params: SchemaCatalogInput | ListCatalogInput) -> str:
    if isinstance(params, SchemaCatalogInput) and params.label is not None and params.label not in LABELS:
        raise ToolError("invalid_argument", f"unknown label {params.label!r}", field="label")
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "query_catalog", params, session)
        if isinstance(params, ListCatalogInput):
            items = [
                {
                    "key": entry["key"],
                    "group": entry.get("group"),
                    "title": entry.get("title"),
                    "description": entry.get("description", ""),
                    "params": entry.get("params", []),
                    "cypher": entry["cypher"],
                }
                for entry in catalog()
                if params.group is None or entry.get("group") == params.group
            ]
            return call.finish(
                session,
                result={"mode": "list", "items": items},
                evidence=Evidence(result=completeness("declared")),
                page=PageOut(truncated=False, total=len(items)),
                engine_function="hst.queries.catalog",
            )
        schema: dict[str, Any] = {"mode": "schema", **graph_schema()}
        queries: list[tuple[str, str]] = []
        if params.label is not None:
            schema["labels"] = {params.label: schema["labels"][params.label]}
            sampled, properties = _label_properties(
                ctx.settings, selectors.snap_binding(call.snapshot), params.label
            )
            schema["properties"] = properties
            schema["sampled_nodes"] = sampled
            queries.append(("fixed", "hst.twin_tools.query._label_properties"))
        return call.finish(
            session,
            result=schema,
            evidence=Evidence(result=completeness("recorded")),
            engine_function="hst.twin_tools.query.graph_schema",
            queries=queries,
        )


# --- query_run_named -----------------------------------------------------------------------


class RunNamedInput(selectors.ToolInput):
    """Run one named query of the catalog."""

    key: str = Field(max_length=64, description="The key of a named query, from query_catalog mode: list.")
    params: dict[str, Annotated[str, Field(max_length=200)]] = Field(
        default_factory=dict,
        max_length=5,
        description="Values of the query's declared params. Undeclared names are ignored.",
    )


class TableResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    columns: list[str]
    data: list[dict[str, Any]] = Field(description="one {row: [...]} object per row, in columns order")
    truncated: bool


class RunNamedResult(TableResult):
    key: str


def named_query(key: str, given: Mapping[str, Any]) -> dict[str, Any]:
    """The catalog entry of `key`, checked to have each declared param in `given`.

    An unknown key raises `not_found`. A required param that is missing from
    `given` or blank raises `invalid_argument`.
    """
    entry = next((q for q in catalog() if q["key"] == key), None)
    if entry is None:
        raise ToolError(
            "not_found", f"no named query {key!r}; query_catalog mode: list has the keys", field="key"
        )
    missing = [
        p["name"]
        for p in entry.get("params", [])
        if not p.get("optional") and not str(given.get(p["name"]) or "").strip()
    ]
    if missing:
        raise ToolError(
            "invalid_argument", f"missing params for {key!r}: {', '.join(missing)}", field="params"
        )
    return entry


def run_named(settings: Any, entry: Mapping[str, Any], bound: dict[str, Any]) -> dict[str, Any]:
    """Run the Cypher of a named query with `bound` as its parameters.

    The Cypher runs trusted. A `snap` in `bound` selects the run. Without a
    `snap`, `run_readonly` binds the run of the pointer. A result above the
    byte cap raises `limit_exceeded`.
    """
    try:
        return run_readonly(settings, entry["cypher"], bound, trusted=True)
    except ResultTooLarge as exc:
        raise ToolError("limit_exceeded", str(exc)) from None


def query_run_named(ctx: ToolContext, params: RunNamedInput) -> str:
    entry = named_query(params.key, params.params)
    declared = [p["name"] for p in entry.get("params", [])]
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "query_run_named", params, session)
        # An optional param that the caller leaves out is bound to "". The
        # device filter matches every device for "".
        bound: dict[str, Any] = {name: params.params.get(name, "") for name in declared}
        bound["snap"] = selectors.snap_binding(call.snapshot)
        table = run_named(ctx.settings, entry, bound)
        return call.finish(
            session,
            result={"key": params.key, **table},
            evidence=Evidence(result=completeness("recorded"), absence="not_recorded"),
            page=PageOut(truncated=bool(table["truncated"])),
            engine_function="hst.app.tables.run_readonly",
            queries=[("catalog", params.key)],
        )


# --- query_cypher --------------------------------------------------------------------------


class CypherInput(selectors.ToolInput):
    """Run read-only Cypher against one run."""

    query: str = Field(
        min_length=1,
        max_length=MAX_QUERY_BYTES,
        description="Read-only Cypher that pins each pattern to $snap.",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        max_length=50,
        description="Query parameters. $snap is bound from snapshot, so snap is not accepted here.",
    )


class CypherResult(TableResult):
    pinned: bool = Field(description="true when each pattern of the query is pinned to $snap")


def audit_cypher(ctx: ToolContext, text: str, outcome: str, rows: int = 0, size: int = 0) -> None:
    """Add one `cypher_events` entry to the log of the call. The surface writes the log."""
    if ctx.cypher_log is not None:
        from hst.app.agent.tools import CypherAudit

        ctx.cypher_log.append(CypherAudit(text, outcome, rows, size))


def check_cypher(ctx: ToolContext, query: str, params: Mapping[str, Any], pinning: str) -> str | None:
    """The checks model-authored Cypher passes before any read.

    The order is the 64 KiB cap, a `snap` among the params of the caller, the
    Latest label and the pinning rule `pinning`. A refusal is audited and
    raised as a `ToolError`. The result is the warning of the `warn` pinning
    rule, or None.
    """
    if len(query.encode()) > MAX_QUERY_BYTES:
        audit_cypher(ctx, query[:MAX_QUERY_BYTES], "too_large")
        raise ToolError(
            "limit_exceeded", f"query too large: the limit is {MAX_QUERY_BYTES // 1024} KiB", field="query"
        )
    if "snap" in params:
        audit_cypher(ctx, query, "rejected")
        raise ToolError(
            "invalid_argument",
            "snap is bound from the snapshot argument and cannot be passed",
            field="params",
        )
    if LATEST_TOKEN.search(query):
        audit_cypher(ctx, query, "rejected")
        raise ToolError("invalid_argument", LATEST_REFUSAL, field="query")
    try:
        return check_pinned(query, pinning)
    except QueryRejected as exc:
        audit_cypher(ctx, query, "rejected")
        raise ToolError("invalid_argument", str(exc), field="query") from None


def read_cypher(ctx: ToolContext, settings: Any, query: str, bound: dict[str, Any]) -> dict[str, Any]:
    """Run model-authored Cypher through `run_readonly`. `run_readonly` applies
    the guard of POST /api/cypher before the read.

    A `snap` in `bound` selects the run. Without a `snap`, `run_readonly`
    binds the run of the pointer. A failed read is audited. A query that the
    guard rejects and a Neo4j client error raise `invalid_argument`. A result
    above the byte cap raises `limit_exceeded`. Any other exception propagates.
    """
    import neo4j.exceptions

    try:
        return run_readonly(settings, query, bound)
    except QueryRejected as exc:
        audit_cypher(ctx, query, audit_outcome(exc))
        raise ToolError("invalid_argument", str(exc), field="query") from None
    except ResultTooLarge as exc:
        audit_cypher(ctx, query, audit_outcome(exc))
        raise ToolError("limit_exceeded", str(exc)) from None
    except neo4j.exceptions.ClientError as exc:
        audit_cypher(ctx, query, audit_outcome(exc))
        raise ToolError("invalid_argument", f"{type(exc).__name__}: {exc}", field="query") from None
    except Exception as exc:
        audit_cypher(ctx, query, audit_outcome(exc))
        raise


def query_cypher(ctx: ToolContext, params: CypherInput) -> str:
    query = params.query
    warning = check_cypher(
        ctx, query, params.params, getattr(ctx.settings, "hst_ai_cypher_pinning", "refuse")
    )
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "query_cypher", params, session)
        table = read_cypher(
            ctx, ctx.settings, query, {**params.params, "snap": selectors.snap_binding(call.snapshot)}
        )
        warnings = [] if warning is None else [warning]
        text = call.finish(
            session,
            result={**jsonable(table), "pinned": warning is None},
            evidence=Evidence(
                result=completeness("recorded", missing=unknowns_missing(warnings)), unknowns=warnings
            ),
            page=PageOut(truncated=bool(table["truncated"])),
            engine_function="hst.app.tables.run_readonly",
            queries=[("cypher", hashlib.sha256(query.encode()).hexdigest())],
            warnings=warnings,
        )
    audit_cypher(ctx, query, "ok", len(table.get("data", ())), len(json.dumps(table, default=str).encode()))
    return text


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="query_catalog",
            description=(
                "mode: schema returns the graph model (labels with layer and gate flag, relationship "
                "types) and the conventions for writing Cypher against the twin; label adds the property "
                "keys that nodes of that label carry in the run. mode: list returns the named queries, "
                "each with its key, group, title, declared params and Cypher."
            ),
            input_model=QueryCatalogInput,
            result_model=QueryCatalogResult,
            run=query_catalog,
        )
    )
    registry.register(
        catalogue_spec(
            name="query_run_named",
            description=(
                "Run one named query by key, with its declared params as strings, against the selected "
                "run. At most 500 rows and 15 s. A row missing from the result has no record in the "
                "run, which is not evidence that the object does not exist."
            ),
            input_model=RunNamedInput,
            result_model=RunNamedResult,
            run=query_run_named,
        )
    )
    registry.register(
        catalogue_spec(
            name="query_cypher",
            description=(
                "Run read-only Cypher against the selected run. $snap is bound to that run, and only a "
                "pattern anchored with it is pinned: guard one :Obj node per connected pattern component "
                "with x.collection_ts = $snap (a Site with (s:Meta OR s.collection_ts = $snap)) as an "
                "AND term of the WHERE of its MATCH. An unguarded MATCH reads every retained "
                "run. A query with a pattern that is not pinned is refused unless the operator set the "
                "pinning rule to warn. The Latest label is refused. At most 500 rows, 15 s and "
                "64 KiB of query text. Call query_catalog mode: schema first for the labels."
            ),
            input_model=CypherInput,
            result_model=CypherResult,
            run=query_cypher,
            permission="cypher.run",
        )
    )
