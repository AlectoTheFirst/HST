"""The tool registry of the model surfaces.

A `ToolSpec` declares a tool once. It holds the name, the description, the
input model, the permission that the tool needs, the surfaces that offer the
tool and the function that runs it. `ToolRegistry.offered` lists the specs
that a principal may use on one surface, in registration order.
`ToolRegistry.invoke` runs one call. It looks up the spec, re-checks the
permission, validates the arguments, runs the body, closes the side-store
readers and caps the result. The body binds the snapshot through the context.
`offered` and `invoke` both use `refusal`. A `write` spec runs only for a
personal access token with scope `read-write` on a surface that the spec
declares. Every spec needs its permission.

This module imports no web framework. A tool body that uses a route helper
imports it inside the function.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from pydantic import BaseModel, RootModel, ValidationError

from hst.app.agent.readers import ReaderPool
from hst.app.ai.schema import provider_input_schema
from hst.app.permissions import permissions_for

if TYPE_CHECKING:
    from hst.app.agent.tools import CypherAudit
    from hst.core.snapshot import Snapshot

log = logging.getLogger("hst.ai")

Kind = Literal["read", "compute", "write"]
SnapshotMode = Literal["none", "graph", "record"]
# The scope of a personal access token, chosen when the token is created.
TokenScope = Literal["read", "read-write"]
Surface = Literal[
    "drawer", "changesim", "assessment_qa", "assessment_draft", "service_generator", "mcp", "rest"
]
ValidationMode = Literal["warn", "enforce"]
# The conversational surfaces. They offer the read tools of the catalogue.
AGENT_SURFACES: frozenset[Surface] = frozenset({"drawer", "changesim", "assessment_qa"})
ToolErrorCode = Literal[
    "invalid_argument",
    "not_found",
    "ambiguous",
    "snapshot_not_found",
    "snapshot_not_published",
    "permission_denied",
    "forbidden",
    "limit_exceeded",
    "cursor_mismatch",
    "mode_unavailable",
    "engine_unavailable",
    "timeout",
    "conflict",
    "unknown_tool",
    "internal",
]

# The tool permissions that only read. Local stdio `hst mcp` holds these.
LOCAL_READ_PERMISSIONS = frozenset({"graph.read", "cypher.run"})

_T = TypeVar("_T")


@dataclass(frozen=True)
class Principal:
    """Who a tool call runs for. `permissions` is resolved on the server from the role.

    `scope` is the scope of the personal access token a call on the MCP HTTP
    transport authenticated with. It is None for every other principal.
    """

    user_id: int | None
    role: str
    permissions: frozenset[str]
    origin: Literal["web", "mcp", "rest"]
    scope: TokenScope | None = None

    @classmethod
    def for_role(
        cls, role: str, *, user_id: int | None = None, origin: Literal["web", "mcp", "rest"] = "web"
    ) -> Principal:
        return cls(user_id=user_id, role=role, permissions=frozenset(permissions_for(role)), origin=origin)

    @classmethod
    def for_token(cls, *, user_id: int, role: str, scope: TokenScope) -> Principal:
        """The principal of a call on the MCP HTTP transport. It holds the
        permissions of the role of the token user and the scope of the token."""
        return cls(
            user_id=user_id,
            role=role,
            permissions=frozenset(permissions_for(role)),
            origin="mcp",
            scope=scope,
        )

    @classmethod
    def local(cls, *, store: bool = False) -> Principal:
        """The principal of local stdio `hst mcp`.

        It has no user id, every read permission and no write permission.
        `runs.manage` is included only when the app store is configured.
        """
        permissions = (LOCAL_READ_PERMISSIONS | {"runs.manage"}) if store else LOCAL_READ_PERMISSIONS
        return cls(user_id=None, role="local", permissions=permissions, origin="mcp")


class ToolError(Exception):
    """A tool failure.

    A tool body raises it. `ToolRegistry.invoke` returns it as an error
    outcome whose `error` field is `payload()`. `detail` is a short text for
    the caller to act on, such as the tool that replaces a retired name.
    """

    def __init__(
        self,
        code: ToolErrorCode,
        message: str,
        *,
        retryable: bool = False,
        field: str | None = None,
        candidates: Sequence[Mapping[str, Any]] = (),
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.field = field
        self.candidates = [dict(item) for item in candidates[:10]]
        self.detail = detail

    def payload(self) -> dict[str, Any]:
        """The `{"error": {...}}` object. The message is cut at 2,000 characters."""
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message[:2000],
            "retryable": self.retryable,
        }
        if self.field is not None:
            error["field"] = self.field
        if self.candidates:
            error["candidates"] = self.candidates
        if self.detail is not None:
            error["detail"] = self.detail
        return {"error": error}


def invalid_argument(exc: ValidationError, *, union: bool = False) -> ToolError:
    """An `invalid_argument` error whose message lists each failing field.

    The location of an error in a union input starts with the mode. With
    `union` set, the mode is removed from the location, and `field` is the
    name of the argument.
    """
    errors = exc.errors()
    locations = [tuple(e["loc"])[1:] if union and len(e["loc"]) > 1 else tuple(e["loc"]) for e in errors]
    problems = "; ".join(
        f"{'.'.join(str(part) for part in loc) or '(arguments)'}: {error['msg']}"
        for loc, error in zip(locations, errors, strict=True)
    )
    first = locations[0] if locations else ()
    return ToolError(
        "invalid_argument", f"invalid arguments: {problems}", field=str(first[0]) if first else None
    )


@dataclass(frozen=True)
class ToolLimits:
    """Per-tool bounds.

    `invoke` cuts the model copy at `max_model_chars`, and at
    `AGENT_MODEL_CHARS` at most on a conversational surface (`model_chars`).
    It cuts the UI copy at `max_ui_chars`. The defaults are the caps of
    `dispatch` and of the ask route's step copy. `max_items` maps an argument
    name to the highest count of list items that the argument may hold.
    `execute` refuses a longer list in both validation modes. `timeout_s` is
    declared for the surfaces that apply it. Its default is the default wait
    of `ToolContext.call_async`.
    """

    timeout_s: float = 30.0
    max_model_chars: int = 100_000
    max_ui_chars: int = 200_000
    max_items: Mapping[str, int] = field(default_factory=dict)


# The most characters of one result or error text the model reads on a
# conversational surface. It equals `traffic.MAX_RESULT_CHARS`. A spec that
# declares a larger `max_model_chars` gets that bound on MCP only.
AGENT_MODEL_CHARS = 100_000


def model_chars(limits: ToolLimits, surface: Surface | None) -> int:
    """The bound of the model copy of one call. It is the `max_model_chars` of
    the spec, and at most `AGENT_MODEL_CHARS` on a conversational surface."""
    if surface in AGENT_SURFACES:
        return min(limits.max_model_chars, AGENT_MODEL_CHARS)
    return limits.max_model_chars


@dataclass(frozen=True)
class QueryRef:
    kind: Literal["fixed", "catalog", "cypher"]
    id: str


@dataclass(frozen=True)
class Provenance:
    snapshot: str | None
    run: dict[str, Any] | None
    manifest_sha256: str | None
    engine: str | None
    queries: tuple[QueryRef, ...]
    evidence_keys: tuple[str, ...]


@dataclass
class ToolContext:
    """What one tool call reads besides its arguments.

    `snapshot` is the run that the turn pinned. `bind_snapshot` resolves the
    run that one call reads. `readers` hands out side-store readers, and the
    registry closes them when the call ends. `principal` is the principal of
    the call. `ToolRegistry.invoke` refuses a call without a principal.
    `store` is the app store. A tool body uses it only through `call_async`.
    `loop` is the event loop that owns the store. Both are None where no app
    store exists.
    """

    settings: Any
    principal: Principal | None = None
    surface: Surface | None = None
    snapshot: Snapshot | None = None
    source_kinds: Mapping[str, str] | None = None
    cypher_log: list[CypherAudit] | None = None
    readers: ReaderPool = field(default_factory=ReaderPool)
    store: Any = None
    loop: asyncio.AbstractEventLoop | None = None

    def call_async(self, coro: Coroutine[Any, Any, _T], timeout_s: float = ToolLimits.timeout_s) -> _T:
        """Run `coro` to completion from a tool body and return its result.

        With `loop` set, the coroutine runs on that loop and the calling worker
        thread waits for it. That loop owns the connections of the app store.
        Without a loop the coroutine runs on a new event loop in this thread.
        After `timeout_s` seconds the coroutine is cancelled and `TimeoutError`
        is raised.
        """
        if self.loop is None:
            return asyncio.run(asyncio.wait_for(coro, timeout_s))
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return future.result(timeout_s)
        except TimeoutError:
            future.cancel()
            raise

    def bind_snapshot(self, session: Any, value: str | int | None) -> Snapshot:
        """The snapshot one call reads.

        A call that gives no run, or the run of the turn, reads the snapshot
        of the turn. A value that is not a run id, or another run with no
        retained graph, raises before any engine read. With no turn snapshot,
        an omitted value resolves the pointer.
        """
        from hst.core import snapshot as snapshotmod

        cts = snapshotmod.parse_snapshot_id(value)
        if self.snapshot is not None and (cts is None or cts == self.snapshot.cts):
            return self.snapshot
        if cts is not None:
            snapshotmod.require_retained(session, cts)
        return snapshotmod.resolve(session, self.settings, cts)


def snapshot_provenance(ctx: ToolContext, arguments: Mapping[str, Any], result: str) -> Provenance:
    """The run that a call read. It is the run of the `snapshot` argument, else
    the run of the turn."""
    named = arguments.get("snapshot")
    if named is not None and named != "":
        snapshot: str | None = str(named)
    else:
        snapshot = ctx.snapshot.snapshot_id if ctx.snapshot is not None else None
    return Provenance(
        snapshot=snapshot, run=None, manifest_sha256=None, engine=None, queries=(), evidence_keys=()
    )


def no_provenance(ctx: ToolContext, arguments: Mapping[str, Any], result: str) -> Provenance:
    return Provenance(
        snapshot=None, run=None, manifest_sha256=None, engine=None, queries=(), evidence_keys=()
    )


@dataclass(frozen=True)
class ToolSpec:
    """One tool, declared once for every surface.

    `run` takes the context and the argument dict and returns text, a dict or a
    pydantic model. It receives the arguments as `normalize_arguments` returns
    them. In warn mode, a call whose arguments fail `input_model` runs.
    `wire_schema` is the published input schema. Without `wire_schema`, the
    JSON Schema of the input model is published.
    """

    name: str
    version: int
    description: str
    input_model: type[BaseModel]
    permission: str
    kind: Kind
    snapshot: SnapshotMode
    run: Callable[[ToolContext, dict[str, Any]], Any]
    surfaces: frozenset[Surface]
    limits: ToolLimits = field(default_factory=ToolLimits)
    output_model: type[BaseModel] | None = None
    provenance: Callable[[ToolContext, Mapping[str, Any], str], Provenance] = snapshot_provenance
    wire_schema: dict[str, Any] | None = None
    role_notes: Mapping[str, str] = field(default_factory=dict)
    destructive: bool = False
    idempotent: bool = False

    def input_schema(self) -> dict[str, Any]:
        return self.wire_schema if self.wire_schema is not None else self.input_model.model_json_schema()


@dataclass
class ToolOutcome:
    """The result of one call. `model_text` is the capped, framed copy for the
    transcript. `ui_text` is the unframed copy for the step that the UI shows.
    `error` is the `ToolError` payload of an error outcome."""

    step_id: str
    label: int
    name: str
    version: int
    arguments: dict[str, Any]
    is_error: bool
    model_text: str
    ui_text: str
    provenance: Provenance | None
    started_at: datetime
    elapsed_ms: int
    error: dict[str, Any] | None = None


def to_anthropic(spec: ToolSpec) -> dict[str, Any]:
    """The Anthropic Messages tool definition."""
    return {
        "name": spec.name,
        "description": spec.description,
        "input_schema": provider_input_schema(spec.input_schema()),
    }


def to_openai(spec: ToolSpec) -> dict[str, Any]:
    """The OpenAI and OpenRouter function tool definition."""
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": provider_input_schema(spec.input_schema()),
        },
    }


def validation_mode(settings: Any) -> ValidationMode:
    mode = getattr(settings, "hst_ai_tool_validation", "warn")
    return "enforce" if mode == "enforce" else "warn"


# The validation errors that Python raises as `TypeError` when a function is
# called with a required argument missing or with an argument it does not take.
_SIGNATURE_ERRORS = frozenset({"missing", "extra_forbidden"})


class ArgumentRefusal(Exception):
    """A call that `execute` refuses before the body runs. The arguments fail
    the input model in enforce mode, or a list holds more items than its cap.

    `error` is the `TypeError` or `ValueError` whose text the model reads.
    `field` is the name of the first failing argument. `ToolRegistry.invoke`
    returns the refusal as an `invalid_argument` error outcome.
    """

    def __init__(self, error: TypeError | ValueError, field: str | None) -> None:
        super().__init__(str(error))
        self.error = error
        self.field = field


def check_arguments(
    spec: ToolSpec, arguments: Mapping[str, Any], mode: ValidationMode
) -> ArgumentRefusal | None:
    """Validate `arguments` against the spec's input model.

    In warn mode, a mismatch logs one `hst.ai` warning with the tool name and
    each failing field path, and the function returns None. In enforce mode
    the function returns the mismatch as an `ArgumentRefusal`. The error of
    the refusal is a `TypeError` for a missing required argument or for an
    argument that the tool does not take. It is a `ValueError` for any other
    mismatch.
    """
    try:
        spec.input_model.model_validate(arguments)
    except ValidationError as exc:
        errors = exc.errors()
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '(arguments)'}: {error['msg']}"
            for error in errors
        )
        if mode == "enforce":
            text = f"invalid arguments for {spec.name}: {problems}"
            field = invalid_argument(exc, union=issubclass(spec.input_model, RootModel)).field
            if any(len(error["loc"]) == 1 and error["type"] in _SIGNATURE_ERRORS for error in errors):
                return ArgumentRefusal(TypeError(text), field)
            return ArgumentRefusal(ValueError(text), field)
        log.warning("tool %s: arguments do not match the input model: %s", spec.name, problems)
    return None


# String arguments that a model often sends as a JSON number. `parse_snapshot_id`
# and `_parse_port` read both forms.
_NUMBER_AS_TEXT = frozenset({"snapshot", "port"})


def normalize_arguments(spec: ToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """The arguments that validation and the body receive.

    A null argument is dropped, and the body uses its default. A `snapshot`
    or `port` that the input model types as a string and that arrives as a
    non-negative integer becomes its decimal string. Every other argument is
    kept as sent.
    """
    fields = spec.input_model.model_fields
    normalized: dict[str, Any] = {}
    for key, value in arguments.items():
        if value is None:
            continue
        if (
            key in _NUMBER_AS_TEXT
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
            and key in fields
            and fields[key].annotation is str
        ):
            value = str(value)
        normalized[key] = value
    return normalized


def execute(spec: ToolSpec, ctx: ToolContext, arguments: dict[str, Any]) -> str:
    """Normalize and validate the arguments, apply the item caps, run and close
    the readers. Returns the result text or raises. Refused arguments raise
    `ArgumentRefusal`. `ToolRegistry.invoke` returns an exception of `execute`
    as an error outcome.
    """
    arguments = normalize_arguments(spec, arguments)
    problem = check_arguments(spec, arguments, validation_mode(ctx.settings))
    if problem is not None:
        raise problem
    for key, cap in spec.limits.max_items.items():
        value = arguments.get(key)
        if isinstance(value, list) and len(value) > cap:
            text = f"invalid arguments for {spec.name}: {key}: at most {cap} items, got {len(value)}"
            raise ArgumentRefusal(ValueError(text), key)
    try:
        result = spec.run(ctx, arguments)
    finally:
        ctx.readers.close()
    if isinstance(result, str):
        return result
    if isinstance(result, BaseModel):
        return result.model_dump_json()
    return json.dumps(result, default=str)


def writes_allowed(principal: Principal) -> bool:
    """Whether `principal` authenticated with a personal access token of scope
    `read-write` on the MCP HTTP transport. `refusal` checks the permissions
    of the user."""
    return principal.origin == "mcp" and principal.scope == "read-write" and principal.user_id is not None


def refusal(spec: ToolSpec, principal: Principal | None, surface: Surface | None) -> ToolError | None:
    """The error that refuses `principal` a call to `spec` on `surface`, or
    None when the call may run.

    A `write` spec runs only on a surface that it declares, for a principal
    whose token has scope `read-write`. Any other caller gets `forbidden`. A
    caller without the permission of the spec gets `permission_denied`.
    """
    if spec.kind == "write" and (
        principal is None or surface not in spec.surfaces or not writes_allowed(principal)
    ):
        return ToolError(
            "forbidden",
            f"{spec.name} is a write tool, and write tools run only for a personal access token "
            "with scope read-write on the MCP HTTP transport",
        )
    if principal is None or spec.permission not in principal.permissions:
        return ToolError("permission_denied", f"{spec.name} requires the {spec.permission} permission")
    return None


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"tool {spec.name} is already registered")
        self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def specs(self) -> list[ToolSpec]:
        """Every registered spec, in registration order."""
        return list(self._specs.values())

    def offered(self, principal: Principal, surface: Surface) -> list[ToolSpec]:
        """The specs `principal` may call on `surface`, in registration order.

        A `write` spec is offered only to a token principal with scope
        `read-write` whose user holds the spec's permission (`refusal`).
        """
        return [
            spec
            for spec in self._specs.values()
            if surface in spec.surfaces and refusal(spec, principal, surface) is None
        ]

    def invoke(self, ctx: ToolContext, name: str, raw_args: dict[str, Any], *, label: int = 0) -> ToolOutcome:
        """Run one call. A failure at any step returns an error outcome.

        The steps look up the spec, re-check the permission and the write
        gate (`refusal`), validate the arguments, run the body, close the
        readers, read the provenance, and cap and frame the result. The body
        binds the snapshot through `ctx.bind_snapshot`. Refused arguments give
        `invalid_argument`. A `ToolError` keeps its code. Any other exception
        gives `internal`. The model copy of a result or an error is cut at the
        bound of `model_chars` for `ctx.surface`.
        """
        from hst.app.agent.tools import _error_step, cap_model_copy, frame_untrusted

        started_at = datetime.now(UTC)
        clock = time.monotonic()
        spec = self._specs.get(name)
        limits = spec.limits if spec is not None else ToolLimits()
        model_limit = model_chars(limits, ctx.surface)

        def outcome(
            is_error: bool,
            model_text: str,
            ui_text: str,
            provenance: Provenance | None = None,
            payload: dict[str, Any] | None = None,
        ) -> ToolOutcome:
            return ToolOutcome(
                step_id=str(uuid.uuid4()),
                label=label,
                name=name,
                version=spec.version if spec is not None else 0,
                arguments=raw_args,
                is_error=is_error,
                model_text=model_text,
                ui_text=ui_text[: limits.max_ui_chars],
                provenance=provenance,
                started_at=started_at,
                elapsed_ms=int((time.monotonic() - clock) * 1000),
                error=payload,
            )

        def error(text: str, tool_error: ToolError) -> ToolOutcome:
            call = _error_step(name, raw_args, text, limit=model_limit)
            ui_text = call.ui_result if call.ui_result is not None else call.result
            return outcome(True, call.result, ui_text, payload=tool_error.payload())

        if spec is None:
            return error(f"No such tool: {name}", ToolError("not_found", f"No such tool: {name}"))
        refused = refusal(spec, ctx.principal, ctx.surface)
        if refused is not None:
            return error(f"PermissionError: {refused.message}", refused)
        try:
            result = execute(spec, ctx, raw_args)
            provenance = spec.provenance(ctx, raw_args, result)
            model_copy = cap_model_copy(result, limit=model_limit)
        except ArgumentRefusal as exc:
            text = f"{type(exc.error).__name__}: {exc.error}"
            return error(text, ToolError("invalid_argument", text, field=exc.field))
        except ToolError as exc:
            return error(f"ToolError: {exc}", exc)
        except Exception as exc:  # The model receives the error text.
            text = f"{type(exc).__name__}: {exc}"
            return error(text, ToolError("internal", text))
        return outcome(False, frame_untrusted(model_copy), result, provenance)
