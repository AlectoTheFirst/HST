"""The envelope that every catalogue tool returns, and the error of a failed call.

A catalogue tool answers with one `Envelope`. It holds the run that the tool
read (`snapshot`), how the answer was computed (`provenance`), how certain the
answer is (`evidence`), where the page ends (`page`) and the `result` of the
tool. A failure is a `ToolError` (`hst.app.ai.registry`). The MCP envelope
profile returns it as an `isError` result whose structured content has the
`ToolErrorPayload` shape.

`Pager` assembles one page. It stops at `limit` items, or before the item
that takes the serialized items past 256 KiB, and then sets `truncated` and
`next_cursor`. `catalogue_spec` declares a tool once, with the envelope as
its output model.

An input model may list, in its `unavailable` map, mode or source values that
the tool recognises and does not serve in this release. Its published schema
leaves them out, and `refuse_unavailable` answers a call that sends one with
`mode_unavailable`.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, ValidationError, model_validator

from hst.app.ai.registry import (
    AGENT_SURFACES,
    Provenance,
    QueryRef,
    Surface,
    ToolContext,
    ToolError,
    ToolErrorCode,
    ToolLimits,
    ToolSpec,
    invalid_argument,
)
from hst.app.tables import MAX_RESULT_BYTES
from hst.core import cycle as cyclemod
from hst.core import snapshot as snapshotmod
from hst.results.words import Missing, record
from hst.results.words import Result as ResultOut
from hst.twin_tools import selectors

__all__ = [
    "PAGE_BUDGET_BYTES",
    "Bounds",
    "Call",
    "Envelope",
    "Evidence",
    "Gap",
    "ItemEvidence",
    "PageOut",
    "Pager",
    "ToolError",
    "ToolErrorPayload",
    "catalogue_spec",
    "missing_of",
]

# Page assembly stops adding items once the serialized items would exceed this.
PAGE_BUDGET_BYTES = 256 * 1024

# The page assembly bounds a result at 256 KiB, and `Call.finish` refuses an
# envelope past the 4 MiB hard cap. On MCP both copies of a result keep the
# whole envelope. On a conversational surface `ToolRegistry.invoke` cuts the
# model copy at `AGENT_MODEL_CHARS`. The whole-call deadline of a read tool is
# 60 s.
CATALOGUE_LIMITS = ToolLimits(timeout_s=60.0, max_model_chars=MAX_RESULT_BYTES, max_ui_chars=MAX_RESULT_BYTES)
# The surfaces that offer a read tool of the catalogue. A write tool is
# offered on MCP only.
MCP_SURFACES: frozenset[Surface] = frozenset({"mcp"})
CATALOGUE_SURFACES = MCP_SURFACES | AGENT_SURFACES

Basis = Literal["observed", "configured", "derived", "computed", "declared", "stored"]


class RunHealth(BaseModel):
    """The run's status as `cycle.run_status` reports it."""

    model_config = ConfigDict(extra="allow")

    snapshot: str | None = None
    created: Any = None
    degraded: bool = False
    sources_carried: list[str] = Field(default_factory=list)
    sources_failed: list[str] = Field(default_factory=list)
    sources_partial: list[str] = Field(default_factory=list)
    sources_cancelled: list[str] = Field(default_factory=list)
    freshness: dict[str, Any] = Field(default_factory=dict)


class SnapshotRef(BaseModel):
    """The run one answer was computed from."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = Field(description="null only when no run is published")
    collection_ts: int | None
    selector: str
    manifest_sha256: str | None = None
    approximate: bool = Field(description="true when no manifest governs the run")
    run: RunHealth | None


class QueryRefOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["fixed", "catalog", "cypher"]
    id: str = Field(description="a module constant, a catalog key, or the sha256 of the executed Cypher text")


class ProvenanceOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    tool_version: int = Field(ge=1)
    engine: str | None = None
    engine_function: str | None = Field(
        default=None, description="dotted path of the engine or store function"
    )
    queries: list[QueryRefOut] = Field(default_factory=list)
    args_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="sha256 of the arguments other than snapshot, cursor and limit",
    )
    actor: str | None = None
    computed_at: datetime


class ItemEvidence(BaseModel):
    """The certainty of one item, in the words of the statement it tests.

    `result` is the answer of `hst.results.words`. It holds the statement, the
    answer, its word, the quantifier and condition of the question, and what
    is missing when the answer is open. `basis` is the origin of the item."""

    model_config = ConfigDict(extra="forbid")

    result: ResultOut
    basis: Basis

    @classmethod
    def of(cls, result: ResultOut, *, basis: Basis) -> ItemEvidence:
        """The evidence of one item from its result."""
        return cls(result=result, basis=basis)


class Gap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    kind: Literal["unsupported", "not-collected", "not-modeled", "unclassified"]
    dimension: str | None = None
    subject: str | None = None
    detail: str | None = Field(default=None, max_length=1000)
    producer: dict[str, Any] | str | None = None
    recipe_id: str | None = None
    context_uid: str | None = None


class Bounds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relation: Literal["L⊆S⊆U⊆P"] = "L⊆S⊆U⊆P"
    mode: Literal["possible", "guaranteed"] | None = None
    universe_count: int | None = Field(default=None, ge=0)
    lower_count: int = Field(ge=0)
    upper_count: int = Field(ge=0)
    open_count: int | None = Field(default=None, ge=0)
    unit: Literal["flow-rectangles", "clients", "addresses", "members", "routes"] | None = None


class Evidence(BaseModel):
    """How certain the whole answer is.

    `result` is the answer of the whole call in the words of its statement
    (`hst.results.words`) when the call tests one. The answer of a trace is the
    answer of its last hop. The answer of a policy decision is the decision. The
    answer of an evaluation is the condition with its quantifier. A call that
    lists records states a record completeness. It is the completeness that its
    items share, `per-item` when they differ, and `empty` when the call lists
    none, with what is missing."""

    model_config = ConfigDict(extra="forbid")

    result: ResultOut
    bounds: Bounds | None = None
    coverage: Literal["complete", "complete-empty", "partial", "failed", "missing", "not-captured"] | None = (
        None
    )
    complete: bool | None = None
    unknowns: list[str] = Field(default_factory=list, max_length=100)
    gaps: list[Gap] = Field(default_factory=list, max_length=200)
    gaps_truncated: bool = False
    absence: Literal["not_recorded"] | None = Field(
        default=None,
        description=(
            "not_recorded: an object missing from the result has no record in this snapshot, "
            "which is not evidence that it does not exist"
        ),
    )


class PageOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    next_cursor: str | None = None
    truncated: bool = Field(
        description="true when more items exist than the page holds; next_cursor, when set, reads them"
    )
    total: int | None = Field(default=None, ge=0)
    limit: int | None = None


class Envelope[R](BaseModel):
    """The answer of one catalogue tool call."""

    model_config = ConfigDict(extra="forbid")

    snapshot: SnapshotRef
    provenance: ProvenanceOut
    evidence: Evidence
    page: PageOut
    result: R
    warnings: list[str] = Field(default_factory=list, max_length=50)


class ToolErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ToolErrorCode
    message: str = Field(max_length=2000)
    retryable: bool
    field: str | None = None
    candidates: list[dict[str, Any]] = Field(default_factory=list, max_length=10)
    detail: str | None = None


class ToolErrorPayload(BaseModel):
    """The structured content of an `isError` result: `ToolError.payload()`."""

    model_config = ConfigDict(extra="forbid")

    error: ToolErrorDetail


# --- evidence helpers ----------------------------------------------------------------------


def record_evidence(carried: bool | None) -> ItemEvidence:
    """The evidence of a graph record in the run. The record is observed by
    the collection of the run, or carried forward from an earlier run."""
    return ItemEvidence.of(
        record("carried" if carried else "observed"), basis="configured" if carried else "observed"
    )


def unknowns_missing(unknowns: Iterable[str]) -> list[Missing]:
    """The free-text unknowns of a call as `missing` entries, at most 50."""
    return [Missing(code="unknown", detail=str(line)[:1000]) for line in unknowns][:50]


# The parts of a result that make two items state the same answer.
_SAME_RESULT = {"kind", "statement", "answer", "word", "quantifier", "condition"}


def whole_result(
    results: Iterable[ResultOut | Mapping[str, Any]], *, unknowns: Iterable[str] = ()
) -> ResultOut:
    """The whole answer of a call that lists items.

    It is the one result that every item states, `per-item` when the items
    differ, and `empty` for no items. The unknowns of the call are the
    `missing` entries of a record completeness."""
    seen: dict[str, ResultOut] = {}
    for item in results:
        value = item if isinstance(item, ResultOut) else ResultOut.model_validate(item)
        key = value.model_dump_json(
            include={"kind", "statement", "answer", "word", "quantifier", "condition"}
        )
        seen.setdefault(key, value)
    missing = unknowns_missing(unknowns)
    if len(seen) == 1:
        (only,) = seen.values()
        if only.kind != "result" and missing:
            return only.model_copy(update={"missing": missing})
        return only
    return record("per-item" if seen else "empty", missing=missing)


def lookup_evidence(count: int, unknowns: Iterable[str] = ()) -> Evidence:
    """The envelope evidence of a record lookup.

    A result with records is `recorded`. An empty result is `empty`. The
    evidence has `absence` set to `not_recorded`.
    """
    listed = list(unknowns)
    return Evidence(
        result=record("recorded" if count else "empty", missing=unknowns_missing(listed)),
        unknowns=listed,
        absence="not_recorded",
    )


def jsonable(value: Any) -> Any:
    """`value` with every graph or temporal type turned into its string form."""
    return json.loads(json.dumps(value, default=str))


_HTTP_CODES: dict[int, ToolErrorCode] = {
    400: "invalid_argument",
    404: "not_found",
    408: "timeout",
    409: "conflict",
    422: "invalid_argument",
    429: "limit_exceeded",
    503: "engine_unavailable",
    504: "timeout",
}


def http_error(exc: Any, *, field: str | None = None) -> ToolError:
    """The `HTTPException` of a route helper as a `ToolError`. The status
    selects the code, and the detail is the message. A status outside
    `_HTTP_CODES` is `internal`."""
    status = int(getattr(exc, "status_code", 500))
    code = _HTTP_CODES.get(status, "internal")
    return ToolError(
        code,
        str(getattr(exc, "detail", exc)),
        retryable=status in (408, 429, 503, 504),
        field=field if code in ("invalid_argument", "not_found") else None,
    )


# Gaps one envelope lists before it sets `gaps_truncated`.
MAX_GAPS = 200

_GAP_KINDS = frozenset({"unsupported", "not-collected", "not-modeled", "unclassified"})
# Maps an engine kind to the envelope gap kind with the same meaning.
_ENGINE_GAP_KINDS = {"not-modeled-yet": "not-modeled", "not-observed": "not-collected"}


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def to_gap(entry: Mapping[str, Any]) -> Gap:
    """An engine's gap or model-error entry as an envelope `Gap`.

    `code` is the code of the entry, or its kind when it has no code. The
    envelope kind is the kind of the entry when it is one of the four gap
    kinds, the mapped kind of `_ENGINE_GAP_KINDS` for `not-modeled-yet` and
    `not-observed`, and `unclassified` otherwise. Keys outside the `Gap` shape
    are left out.
    """
    kind = str(entry.get("kind") or "")
    producer = entry.get("producer")
    detail = entry.get("detail")
    return Gap(
        code=str(entry.get("code") or kind or "unclassified"),
        kind=kind if kind in _GAP_KINDS else _ENGINE_GAP_KINDS.get(kind, "unclassified"),  # type: ignore[arg-type]
        dimension=_text(entry.get("dimension")),
        subject=_text(entry.get("subject")),
        detail=None if detail is None else str(detail)[:1000],
        producer=producer if isinstance(producer, dict | str) else None,
        recipe_id=_text(entry.get("recipe_id")),
        context_uid=_text(entry.get("context_uid")),
    )


def missing_of(entries: Iterable[Mapping[str, Any]]) -> list[Missing]:
    """The gap entries of an engine as the `missing` entries of an open result.

    Each entry holds the code, the subject and the detail. The list holds at
    most 50 entries, distinct by code and subject."""
    seen: dict[tuple[str, str | None], Missing] = {}
    for entry in entries:
        gap = to_gap(entry)
        key = (gap.code, gap.subject)
        if key not in seen:
            seen[key] = Missing(
                code=gap.code[:120],
                subject=None if gap.subject is None else gap.subject[:500],
                detail=None if gap.detail is None else gap.detail[:1000],
            )
    return list(seen.values())[:50]


def gap_list(entries: Iterable[Mapping[str, Any]]) -> tuple[list[Gap], bool]:
    """The distinct gaps of `entries`, at most `MAX_GAPS`, and whether more were left out."""
    seen: dict[str, Gap] = {}
    for entry in entries:
        gap = to_gap(entry)
        seen.setdefault(gap.model_dump_json(), gap)
    gaps = list(seen.values())
    return gaps[:MAX_GAPS], len(gaps) > MAX_GAPS


# --- values the tool does not serve --------------------------------------------------------

# Maps a field name to the values that the tool recognises and does not serve.
Unavailable = Mapping[str, tuple[str, ...]]


def unavailable_values(model: type[BaseModel]) -> Unavailable:
    """The `unavailable` map an input model declares, or an empty one."""
    return getattr(model, "unavailable", {})


def refuse_unavailable(cls: type[BaseModel], data: Any) -> Any:
    """Refuse a value the model names in `unavailable`, before any field check.

    The call answers `mode_unavailable` with the field. Every other value
    passes to the model's own validation.
    """
    if isinstance(data, Mapping):
        for field, values in unavailable_values(cls).items():
            value = data.get(field)
            if isinstance(value, str) and value in values:
                raise ToolError(
                    "mode_unavailable",
                    f"{field} {value!r} is not available in this release; the input schema lists "
                    "the values this server serves",
                    field=field,
                )
    return data


def unavailable_check() -> Any:
    """The before-validator of an input model with an `unavailable` map. The
    class body assigns it to a public name."""
    return model_validator(mode="before")(classmethod(refuse_unavailable))  # type: ignore[arg-type]


# --- paging --------------------------------------------------------------------------------


@dataclass
class Pager:
    """One page of one call. It holds the offset, the item limit, and the
    binding (tool, snapshot, digest) of every cursor that it writes."""

    tool: str
    snapshot_id: str | None
    digest: str
    offset: int
    limit: int

    @classmethod
    def open(cls, tool: str, snapshot_id: str | None, digest: str, cursor: str | None, limit: int) -> Pager:
        offset = 0 if cursor is None else selectors.decode_cursor(cursor, tool, snapshot_id, digest)
        return cls(tool=tool, snapshot_id=snapshot_id, digest=digest, offset=offset, limit=limit)

    def cursor_at(self, position: int) -> str:
        return selectors.encode_cursor(self.tool, self.snapshot_id, self.digest, position)

    def take(
        self,
        window: Sequence[Any],
        *,
        total: int | None = None,
        more: bool = False,
        budget: int = PAGE_BUDGET_BYTES,
    ) -> tuple[list[Any], PageOut]:
        """The page's items and its `PageOut`.

        `window` holds the items from `offset` on. `more` is True when items
        exist past the end of `window`. Items are added until `limit` is reached,
        or until the next item takes the serialized items past `budget` bytes.
        The first item is always added. When items remain, the page is
        `truncated` and `next_cursor` starts at the first item left out.
        """
        page: list[Any] = []
        size = 0
        for item in window:
            if len(page) >= self.limit:
                break
            item_size = len(json.dumps(item, default=str).encode()) + 1
            if page and size + item_size > budget:
                break
            page.append(item)
            size += item_size
        remaining = len(window) > len(page) or more
        return page, PageOut(
            next_cursor=self.cursor_at(self.offset + len(page)) if remaining else None,
            truncated=remaining,
            total=total,
            limit=self.limit,
        )


def unpaged(total: int | None = None) -> PageOut:
    """The page of a tool that answers in one page."""
    return PageOut(truncated=False, total=total)


# --- one call ------------------------------------------------------------------------------


@functools.cache
def tool_versions() -> Mapping[str, int]:
    """The catalogue version of every read and write tool, by name."""
    from hst.twin_tools import catalogue_registry, write_registry

    return {
        spec.name: spec.version
        for registry in (catalogue_registry(), write_registry())
        for spec in registry.specs()
    }


@dataclass
class Call:
    """One catalogue tool call. It holds the resolved run, the argument digest
    and the pager."""

    ctx: ToolContext
    spec_name: str
    version: int
    params: selectors.ToolInput
    snapshot: snapshotmod.Snapshot
    digest: str
    pager: Pager

    @classmethod
    def open(
        cls,
        ctx: ToolContext,
        tool: str,
        params: selectors.ToolInput,
        session: Any,
        *,
        snapshot: snapshotmod.Snapshot | None = None,
    ) -> Call:
        """Bind the run and read the cursor.

        `snapshot` is the run that the tool resolved. Without it, the
        `snapshot` argument is bound through `selectors.bind`.
        """
        snap = snapshot if snapshot is not None else selectors.bind(ctx, session, params.snapshot)
        digest = selectors.args_sha256(params)
        cursor: str | None = None
        limit = selectors.MAX_LIMIT
        if isinstance(params, selectors.PagedInput):
            cursor, limit = params.cursor, params.limit
        return cls(
            ctx=ctx,
            spec_name=tool,
            version=tool_versions()[tool],
            params=params,
            snapshot=snap,
            digest=digest,
            pager=Pager.open(tool, snap.snapshot_id, digest, cursor, limit),
        )

    def finish(
        self,
        session: Any,
        *,
        result: Any,
        evidence: Evidence,
        page: PageOut | None = None,
        engine: str | None = None,
        engine_function: str | None = None,
        queries: Iterable[tuple[str, str]] = (),
        warnings: Iterable[str] = (),
    ) -> str:
        """The envelope as JSON text.

        The method reads the status of the run and the digest of its manifest.
        An envelope larger than the 4 MiB hard cap raises `limit_exceeded`.
        """
        snap = self.snapshot
        principal = self.ctx.principal
        envelope: Envelope[Any] = Envelope(
            snapshot=SnapshotRef(
                id=snap.snapshot_id,
                collection_ts=snap.cts,
                selector=self.params.snapshot,
                manifest_sha256=_manifest_sha256(snap),
                approximate=snap.approximate,
                run=_run_health(cyclemod.run_status(session, snap)),
            ),
            provenance=ProvenanceOut(
                tool=self.spec_name,
                tool_version=self.version,
                engine=engine,
                engine_function=engine_function,
                queries=[QueryRefOut(kind=kind, id=ident) for kind, ident in queries],  # type: ignore[arg-type]
                args_sha256=self.digest,
                actor=None if principal is None or principal.user_id is None else str(principal.user_id),
                computed_at=datetime.now(UTC),
            ),
            evidence=evidence,
            page=page if page is not None else unpaged(),
            result=jsonable(result.model_dump(mode="json") if isinstance(result, BaseModel) else result),
            warnings=[w[:500] for w in warnings][:50],
        )
        text = envelope.model_dump_json()
        if len(text.encode()) > MAX_RESULT_BYTES:
            raise ToolError(
                "limit_exceeded",
                f"the answer exceeds {MAX_RESULT_BYTES // (1024 * 1024)} MiB; "
                "narrow the arguments or lower limit",
            )
        return text


def _run_health(status: dict[str, Any] | None) -> RunHealth | None:
    return None if status is None else RunHealth.model_validate(status)


def _manifest_sha256(snap: snapshotmod.Snapshot) -> str | None:
    if snap.cts is None or snap.manifest is None:
        return None
    from hst.core import manifest as manifestmod

    try:
        return manifestmod.digest_of(snap.settings, snap.cts)
    except (OSError, ValueError):
        return None


def envelope_provenance(ctx: ToolContext, arguments: Mapping[str, Any], result: str) -> Provenance:
    """The registry `Provenance` of one call, read from the envelope that the
    call returned."""
    try:
        envelope = json.loads(result)
        snapshot = envelope["snapshot"]
        provenance = envelope["provenance"]
    except (ValueError, KeyError, TypeError):
        return Provenance(
            snapshot=None, run=None, manifest_sha256=None, engine=None, queries=(), evidence_keys=()
        )
    return Provenance(
        snapshot=snapshot.get("id"),
        run=snapshot.get("run"),
        manifest_sha256=snapshot.get("manifest_sha256"),
        engine=provenance.get("engine"),
        queries=tuple(QueryRef(kind=q["kind"], id=q["id"]) for q in provenance.get("queries", [])),
        evidence_keys=(),
    )


# --- declaring a tool ----------------------------------------------------------------------


def is_union_input(model: type[BaseModel]) -> bool:
    """Whether `model` is a root model over a discriminated union of inputs."""
    return issubclass(model, RootModel)


def union_input_schema(model: type[BaseModel]) -> dict[str, Any]:
    """The published input schema of a tool whose input is a discriminated union.

    The root is an object. Its `properties` hold every field of every mode,
    and its `required` holds the discriminator. `oneOf` holds one branch per
    mode, each with its own `required` fields.
    """
    schema = model.model_json_schema()
    defs: dict[str, Any] = schema.get("$defs", {})
    discriminator = schema["discriminator"]["propertyName"]
    properties: dict[str, Any] = {}
    values: list[str] = []
    for branch in schema["oneOf"]:
        variant = defs[branch["$ref"].rsplit("/", 1)[-1]]
        for name, prop in variant["properties"].items():
            if name == discriminator:
                values.append(prop["const"])
            else:
                properties.setdefault(name, prop)
    properties = {
        discriminator: {
            "type": "string",
            "enum": values,
            "description": "Selects the mode. Each value has its own required fields (oneOf).",
        },
        **properties,
    }
    out: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "required": [discriminator],
        "oneOf": schema["oneOf"],
        "discriminator": schema["discriminator"],
        "$defs": defs,
    }
    if "description" in schema:
        out["description"] = schema["description"]
    return out


def validate_input(model: type[BaseModel], arguments: Mapping[str, Any]) -> BaseModel:
    """The arguments as the input model of one mode, or `invalid_argument`."""
    try:
        validated = model.model_validate(dict(arguments))
    except ValidationError as exc:
        raise invalid_argument(exc, union=is_union_input(model)) from None
    return validated.root if isinstance(validated, RootModel) else validated


def catalogue_spec(
    *,
    name: str,
    description: str,
    input_model: type[BaseModel],
    result_model: type[Any],
    run: Callable[[ToolContext, Any], str],
    permission: str = "graph.read",
    version: int = 3,
) -> ToolSpec:
    """A read tool of the catalogue.

    `version` is 3 for every tool. A tool with a changed body passes a higher
    version.

    The body receives the arguments validated into the input model of their
    mode. The output model is the envelope over `result_model`. The tool is
    offered on the `mcp` surface and on the conversational surfaces
    (`AGENT_SURFACES`). A union input publishes `union_input_schema`.
    Another input that declares `unavailable` values publishes its own JSON
    Schema, which leaves them out.
    """

    def body(ctx: ToolContext, arguments: dict[str, Any]) -> str:
        return run(ctx, validate_input(input_model, arguments))

    body.__name__ = body.__qualname__ = name
    wire_schema: dict[str, Any] | None = None
    if is_union_input(input_model):
        wire_schema = union_input_schema(input_model)
    elif unavailable_values(input_model):
        wire_schema = input_model.model_json_schema()
    return ToolSpec(
        name=name,
        version=version,
        description=description,
        input_model=input_model,
        permission=permission,
        kind="read",
        snapshot="graph",
        run=body,
        surfaces=CATALOGUE_SURFACES,
        limits=CATALOGUE_LIMITS,
        output_model=Envelope[result_model],  # type: ignore[valid-type]
        provenance=envelope_provenance,
        wire_schema=wire_schema,
        idempotent=True,
    )
