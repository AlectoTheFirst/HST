"""Publish registry specs as MCP tools.

`register_mcp` adds one MCP tool per spec that the `mcp` surface offers the
principal, in registration order. Each function's signature is built from
the spec's `input_model`, and the call runs through `ToolRegistry.invoke`. An
error outcome, or arguments the input model refuses, becomes a
`CallToolResult` with `isError: true` whose structured content is the
`ToolError` payload. The tool has annotations from the kind of the spec, and
its output schema is the spec's `output_model` when it has one. A spec with a
wire schema publishes it. The schema of a union input lists the required
fields of each mode. The schema of an input with `unavailable` values leaves
those values out. The signature of the function accepts the unavailable values
and makes every other field optional. The input model checks the call. A call
that sends an unavailable value gets the `mode_unavailable` error, whatever
other arguments it sends.

A `write` spec that the principal is not offered is not published. A call
that names it gets the registry's refusal, `forbidden` or
`permission_denied`, as an `isError` result.

`retire_tools` answers a call to a retired tool name with `unknown_tool`,
and `detail` holds the tool that replaces it.

Every call is reported to an `McpAudit` when one is given.

This module imports neither the `mcp` package nor a web framework at import
time. It imports the `mcp` types when it publishes a tool.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Annotated, Any, Literal, get_args

from pydantic import BaseModel, Field, RootModel, ValidationError

from hst.app.ai.registry import (
    Principal,
    ToolContext,
    ToolError,
    ToolRegistry,
    ToolSpec,
    invalid_argument,
    refusal,
)
from hst.core import Settings

if TYPE_CHECKING:
    import asyncio

    from hst.app.ai.audit import McpAudit


def register_mcp(
    server: Any,
    registry: ToolRegistry,
    *,
    principal: Principal,
    audit: McpAudit | None = None,
    store: Any = None,
    loop: asyncio.AbstractEventLoop | None = None,
) -> None:
    """Add the registry's `mcp` specs that `principal` is offered to `server` as tools.

    `registry.offered` gives the specs. `ToolRegistry.invoke` checks the
    permission on every call. Each function is registered through the `tool()`
    decorator of the server. The decorator reads the tool name and the
    description from the function. The annotations, and the wire schema of the
    spec when it has one, are then set on the registered tool. A call to a
    `write` spec that was not published is answered with the refusal of the
    registry. `audit` receives every call. `store` is the app store that the
    tool calls use, on the event loop `loop`. Without `store`, a tool body that
    needs the store opens one from the settings.
    """
    for spec in registry.offered(principal, "mcp"):
        server.tool()(_envelope_function(spec, registry, principal, audit, store, loop))
        _publish_metadata(server, spec)
    refused: dict[str, ToolError] = {}
    for spec in registry.specs():
        if spec.kind != "write" or "mcp" not in spec.surfaces:
            continue
        reason = refusal(spec, principal, "mcp")
        if reason is not None:
            refused[spec.name] = reason
    _refuse_unpublished(server, refused, audit)


def retire_tools(server: Any, replacements: Mapping[str, str], audit: McpAudit | None = None) -> None:
    """Answer a call to a retired tool name with the error `unknown_tool`.

    `replacements` maps each retired name to the tool, and the mode when it
    has one, that replaces it. A retired name is not listed. A call to it
    gets the `ToolError` payload with `isError: true`, and `detail` holds the
    replacement. The call is reported to `audit`.
    """
    answers = {
        name: ToolError(
            "unknown_tool", f"unknown tool {name}; its replacement is {replacement}", detail=replacement
        )
        for name, replacement in replacements.items()
    }
    _refuse_unpublished(server, answers, audit, error_class="ToolError")


def _refuse_unpublished(
    server: Any,
    refused: dict[str, ToolError],
    audit: McpAudit | None,
    *,
    error_class: str = "PermissionError",
) -> None:
    """Answer a call to a tool named in `refused` with its `ToolError` payload
    and `isError: true`, before the server looks the tool up.

    MCPServer answers every `tools/call` through its `call_tool` method. The
    `call_tool` of this server instance is wrapped. A call with any other tool
    name passes to it unchanged. The refused call is reported to `audit`
    with `error_class` as the error class. A server with no `call_tool` is not
    changed.
    """
    if not refused:
        return
    call_tool = getattr(server, "call_tool", None)
    if call_tool is None:
        return
    from mcp.types import CallToolResult, TextContent

    async def guarded(name: str, arguments: dict[str, Any], context: Any = None) -> Any:
        reason = refused.get(name)
        if reason is None:
            return await call_tool(name, arguments, context)
        if audit is not None:
            audit.record(name, 0, [], f"{error_class}: {reason.message}")
        payload = reason.payload()
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
            is_error=True,
        )

    server.call_tool = guarded


def _annotations(spec: ToolSpec) -> Any:
    """The MCP tool annotations of `spec`. A read tool is read-only and
    closed-world. A write tool is closed-world and has the destructive and
    idempotent hints of the spec."""
    from mcp.types import ToolAnnotations

    if spec.kind == "write":
        return ToolAnnotations(
            read_only_hint=False,
            destructive_hint=spec.destructive,
            idempotent_hint=spec.idempotent,
            open_world_hint=False,
        )
    return ToolAnnotations(read_only_hint=True, open_world_hint=False)


def _publish_metadata(server: Any, spec: ToolSpec) -> None:
    """Set the annotations and the wire schema of the spec on the tool that
    `server` registered for it.

    `register_mcp` calls the `tool()` decorator without arguments. MCPServer
    builds the input schema of a tool from the function signature and takes no
    schema argument. The wire schema of the spec replaces that input schema on
    the registered tool. A server with no tool manager is not changed.
    """
    manager = getattr(server, "_tool_manager", None)
    tool = manager.get_tool(spec.name) if manager is not None else None
    if tool is None:
        return
    tool.annotations = _annotations(spec)
    if spec.wire_schema is not None:
        tool.parameters = spec.wire_schema


def _envelope_function(
    spec: ToolSpec,
    registry: ToolRegistry,
    principal: Principal,
    audit: McpAudit | None,
    store: Any = None,
    loop: asyncio.AbstractEventLoop | None = None,
) -> Callable[..., Any]:
    """The typed function `register_mcp` publishes for `spec`.

    Its signature has one keyword parameter per field of the spec's input
    model, or of every mode of a union input. It validates the arguments into
    that model, dumps them in JSON mode and runs the call through
    `registry.invoke` with a new `Settings()`, and with `store` and `loop` on
    the tool context. A success returns the result text framed by
    `frame_untrusted`, with the parsed object as structured content when the
    text is a JSON object. An error outcome, arguments that the model refuses,
    or a value that the model lists as unavailable, returns the `ToolError`
    payload with `isError: true`. With an `output_model`, the published output
    schema is the schema of that model.
    """
    from mcp.types import CallToolResult, TextContent

    union = issubclass(spec.input_model, RootModel)
    signature = _union_signature(spec.input_model) if union else _model_signature(spec.input_model)
    # These signatures give optional parameters the default None. `published`
    # drops the None values, and the input model applies its defaults and its
    # required fields to the arguments sent.
    loose = union or bool(_unavailable(spec.input_model))
    if spec.output_model is not None:
        signature = signature.replace(return_annotation=Annotated[CallToolResult, spec.output_model])

    def refused(payload: dict[str, Any]) -> Any:
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
            is_error=True,
        )

    def published(**kwargs: Any) -> Any:
        given = {k: v for k, v in kwargs.items() if v is not None} if loose else kwargs
        try:
            arguments = spec.input_model.model_validate(given).model_dump(mode="json")
        except (ValidationError, ToolError) as exc:
            invalid = exc if isinstance(exc, ToolError) else invalid_argument(exc, union=union)
            if audit is not None:
                audit.record(spec.name, 0, [], f"ToolError: {invalid.message}")
            return refused(invalid.payload())
        ctx = ToolContext(
            settings=Settings(), principal=principal, surface="mcp", cypher_log=[], store=store, loop=loop
        )
        outcome = registry.invoke(ctx, spec.name, arguments)
        if audit is not None:
            error = outcome.ui_text if outcome.is_error else None
            audit.record(spec.name, outcome.elapsed_ms, ctx.cypher_log or [], error)
        if outcome.is_error:
            return refused(outcome.error or ToolError("internal", outcome.ui_text).payload())
        # The text goes to the model of the client. It holds strings that devices
        # report (LLDP and CDP names, descriptions, DHCP hostnames). It is framed
        # as data, as in the in-app transcript. The structured content is the
        # plain JSON.
        from hst.app.agent.tools import frame_untrusted

        snapshot = outcome.provenance.snapshot if outcome.provenance is not None else None
        return CallToolResult(
            content=[
                TextContent(
                    type="text", text=frame_untrusted(outcome.ui_text, tool=spec.name, snapshot=snapshot)
                )
            ],
            structured_content=_json_object(outcome.ui_text),
        )

    return _publish(published, spec, signature)


def _publish(
    published: Callable[..., Any], spec: ToolSpec, signature: inspect.Signature
) -> Callable[..., Any]:
    """Give `published` the spec's name, description and signature."""
    published.__name__ = published.__qualname__ = spec.name
    published.__doc__ = spec.description
    published.__signature__ = signature  # type: ignore[attr-defined]
    published.__annotations__ = {
        param.name: param.annotation
        for param in signature.parameters.values()
        if param.annotation is not param.empty
    }
    if signature.return_annotation is not signature.empty:
        published.__annotations__["return"] = signature.return_annotation
    return published


def _unavailable(model: type[BaseModel]) -> dict[str, tuple[str, ...]]:
    """The values that `model` recognises and does not serve, by field name."""
    return dict(getattr(model, "unavailable", {}))


def _widened(annotation: Any, extra: tuple[str, ...]) -> Any:
    """A literal annotation that also admits `extra`. A call that sends one of
    them passes the server's argument check, and the input model answers it."""
    return Literal[(*get_args(annotation), *extra)] if extra else annotation


def _no_alias(model: type[BaseModel], name: str, info: Any) -> None:
    """Refuse a field with an alias. A parameter is named after its field, and
    the input model validates the call by field name."""
    if info.alias is not None or info.validation_alias is not None:
        raise ValueError(f"{model.__name__}.{name}: an MCP tool input field takes no alias")


def _model_signature(model: type[BaseModel]) -> inspect.Signature:
    """One keyword parameter per field of `model`.

    Each parameter is annotated with the type, the constraints and the schema
    text of the field. The published schema keeps them. A default stays on
    the parameter. A default factory stays on the annotation. Each call gets a
    new value from the factory. A literal field with unavailable values admits
    them. A field with an alias raises `ValueError`.

    A model with unavailable values publishes its wire schema. Its signature
    keeps the fields that have unavailable values as the model declares them.
    It makes every other field optional with a None default and no type. The
    input model is the only check of those fields. A call that sends an
    unavailable value and leaves out a field that the value does not use
    passes the argument check of the server, and the input model answers it.
    """
    unavailable = _unavailable(model)

    def parameter(name: str, info: Any) -> inspect.Parameter:
        _no_alias(model, name, info)
        if unavailable and name not in unavailable:
            return inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[Any, Field(description=info.description)],
                default=None,
            )
        annotation = _widened(info.annotation, unavailable.get(name, ()))
        factory = {"default_factory": info.default_factory} if info.default_factory is not None else {}
        default: Any = inspect.Parameter.empty if info.is_required() or factory else info.get_default()
        return inspect.Parameter(
            name,
            inspect.Parameter.KEYWORD_ONLY,
            annotation=Annotated[
                (
                    annotation,
                    *info.metadata,
                    Field(
                        **factory,
                        title=info.title,
                        description=info.description,
                        examples=info.examples,
                        json_schema_extra=info.json_schema_extra,
                        discriminator=info.discriminator,
                    ),
                )
            ],
            default=default,
        )

    return inspect.Signature([parameter(name, info) for name, info in model.model_fields.items()])


def _union_signature(model: type[BaseModel]) -> inspect.Signature:
    """One keyword parameter per field of every mode of a union input.

    The discriminator is required and typed with the literal of every mode,
    and of every mode that the model lists as unavailable. Every other
    parameter is optional, defaults to None and has no type. A field that one
    mode requires can be absent from another mode. The spec publishes the wire
    schema of the union. The input model is the only check of the arguments of
    the chosen mode. A field with an alias raises `ValueError`.
    """
    root = model.model_fields["root"]
    discriminator = str(root.discriminator)
    unavailable = _unavailable(model)
    variants = [
        variant
        for variant in get_args(root.annotation)
        if isinstance(variant, type) and issubclass(variant, BaseModel)
    ]
    values: list[Any] = []
    fields: dict[str, Any] = {}
    for variant in variants:
        for name, info in variant.model_fields.items():
            _no_alias(variant, name, info)
            if name == discriminator:
                values.extend(get_args(info.annotation))
            else:
                fields.setdefault(name, info)
    values.extend(unavailable.get(discriminator, ()))
    parameters = [
        inspect.Parameter(
            discriminator,
            inspect.Parameter.KEYWORD_ONLY,
            annotation=Annotated[Literal[tuple(values)], Field(description="Selects the mode.")],
        ),
        *(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[Any, Field(description=info.description)],
                default=None,
            )
            for name, info in fields.items()
        ),
    ]
    return inspect.Signature(parameters)


def _json_object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
