"""Provider-neutral tool plumbing for the model surfaces.

The conversational surfaces offer the read tools of the catalogue
(`hst.twin_tools`). `offered_tools` lists the tools that one principal may
call on one surface as `Tool` objects for the provider adapters. Each call
runs through `ToolRegistry.invoke`. `ToolRegistry.invoke` checks the
permission again, validates the arguments, and caps and frames the result.
Each adapter translates a `Tool` into its wire schema. The Anthropic schema is
`{name, description, input_schema}`. The OpenAI schema is `{type: "function",
function: {...}}`.

`dispatch` runs one call by name and returns a failure as a step that the
model can read. The framing helpers mark every result as device-collected data
for the model. `route_prediction` is the BGP route prediction of
`routing_predict_routes`.
"""

from __future__ import annotations

import functools
import html
import json
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from hst.app.agent.readers import ReaderPool
from hst.app.ai.registry import Provenance, ToolContext, ToolRegistry, snapshot_provenance
from hst.simul import intents as simul_intents

if TYPE_CHECKING:
    from hst.core.snapshot import Snapshot

log = logging.getLogger(__name__)


@dataclass
class Tool:
    """One tool as the provider adapters offer it.

    `invoke` runs one call and returns its step. `offered_tools` sets it. A
    tool without `invoke` runs through `run`. `run` takes the arguments as
    keywords and returns the result text. `dispatch` caps and frames that text.
    """

    name: str
    description: str
    schema: dict[str, Any]
    permission: str
    run: Callable[..., Any] | None = None
    invoke: Callable[[Any], ToolCall] | None = None

    def __post_init__(self) -> None:
        if self.run is None and self.invoke is None:
            raise ValueError(f"tool {self.name} needs run or invoke")


@dataclass
class CypherAudit:
    """One `query_cypher` tool call, buffered for the audit trail.

    The caller that started the ask (app/routes/ai.py) drains the buffer, also
    when the ask ends at its deadline.
    """

    query: str
    outcome: str
    row_count: int = 0
    byte_count: int = 0


@dataclass
class ToolCall:
    """One tool invocation and its outcome, surfaced to the UI as a step.

    `result` is the model copy, which the adapters append to the transcript.
    `ui_result` is the unframed and uncapped text of the result or of the
    error, for the step in the UI. It is None when the UI copy is `result`.
    `AskBudget.invoke` sets `elapsed_ms` to the duration of the call in
    milliseconds. Equality ignores `elapsed_ms`.
    """

    name: str
    arguments: dict[str, Any]
    result: str
    is_error: bool = False
    ui_result: str | None = None
    elapsed_ms: int | None = field(default=None, compare=False)


# The 2 queries match a device by hostname. `_match_devices` runs the exact match
# first and then the prefix match.
_DEVICE_EXACT_QUERY = """
MATCH (d:Device:Obj)
WHERE NOT d:Retired AND d.collection_ts = $snap
  AND toLower(d.hostname) = toLower($name)
RETURN d.uid AS uid, d.hostname AS hostname, d.role AS role, d.vendor AS vendor
ORDER BY d.uid LIMIT 11"""

_DEVICE_PREFIX_QUERY = """
MATCH (d:Device:Obj)
WHERE NOT d:Retired AND d.collection_ts = $snap
  AND toLower(d.hostname) STARTS WITH toLower($name)
RETURN d.uid AS uid, d.hostname AS hostname, d.role AS role, d.vendor AS vendor
ORDER BY d.uid LIMIT 11"""


# The gaps of every route prediction row, sent with every response.
MODEL_SCOPE = (
    "BGP-only propagation to a fixed point; no IGP cost unless supplied, no "
    "redistribution, no next-hop resolution, single best path, multipath out "
    "of scope"
)

_PREDICT_SHUT_KINDS = frozenset({"bgp_session.shut", "bgp_session.unshut"})
_PREDICT_STATIC_ROUTE_KINDS = frozenset({"static_route.add", "static_route.remove"})
# The route prediction accepts each kind of the intent catalog of the
# simulator (`hst.simul.intents`). It reports each kind in this set as not
# modeled. The engine does not rerun a policy against an edited RoutePolicy
# or PrefixListEntry.
_PREDICT_NOT_MODELED_KINDS = simul_intents.STORED_KINDS - _PREDICT_SHUT_KINDS - _PREDICT_STATIC_ROUTE_KINDS


def _apply_predict_intents(graph_input: Any, intents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Change `graph_input.sessions` and `graph_input.local_routes` for the
    intents that the route prediction applies. Return one model_errors entry
    for each intent that it does not apply.

    `bgp_session.shut` removes a session from `sessions`.
    `bgp_session.unshut` cancels an earlier `bgp_session.shut` of the session.
    `fw_overlay_read._bgp_prediction` withholds a session for a denied address
    in the same way. `static_route.add` and `static_route.remove` add or
    remove a locally originated row on each BGP RoutingProcess of the named
    VRF. The row has the shape that `read_simulation_input` builds from
    `ORIGINATES`.
    """
    errors: list[dict[str, Any]] = []
    withheld: set[str] = set()
    added_routes: list[dict[str, Any]] = []
    removed_routes: set[tuple[str, str]] = set()

    for intent in intents:
        kind = str(intent.get("kind"))
        params = intent.get("params") or {}

        if kind in _PREDICT_SHUT_KINDS:
            session_uid = params.get("session")
            if not session_uid:
                raise ValueError(f"{kind} needs a 'session' param naming the BgpSession uid")
            if kind == "bgp_session.shut":
                withheld.add(str(session_uid))
            else:
                withheld.discard(str(session_uid))
        elif kind in _PREDICT_STATIC_ROUTE_KINDS:
            context_uid, prefix = params.get("context_uid"), params.get("prefix")
            if not context_uid or not prefix:
                raise ValueError(f"{kind} needs 'context_uid' and 'prefix' params")
            owners = [p["uid"] for p in graph_input.processes if p.get("context_uid") == context_uid]
            if not owners:
                errors.append(
                    {
                        "kind": "static-route-context-not-in-scope",
                        "detail": (
                            f"{context_uid!r} has no BGP RoutingProcess in this prediction's "
                            f"scope, so {kind} could not be attributed to one"
                        ),
                        "subject": str(context_uid),
                    }
                )
                continue
            if kind == "static_route.add":
                added_routes += [
                    {
                        "process_uid": owner,
                        "prefix": str(prefix),
                        "origin_mechanism": "static",
                        "src_protocol": "static",
                    }
                    for owner in owners
                ]
            else:
                removed_routes |= {(owner, str(prefix)) for owner in owners}
        elif kind in _PREDICT_NOT_MODELED_KINDS:
            errors.append(
                {
                    "kind": "not-modeled-yet",
                    "detail": (
                        f"{kind} is not modeled by the route prediction; the intent is "
                        "accepted and has no effect on the prediction"
                    ),
                    "subject": kind,
                }
            )
        else:
            raise ValueError(f"the route prediction cannot apply intent kind {kind!r}")

    if withheld:
        graph_input.sessions = [s for s in graph_input.sessions if str(s.get("uid")) not in withheld]
    if removed_routes:
        graph_input.local_routes = [
            r
            for r in graph_input.local_routes
            if (str(r.get("process_uid")), str(r.get("prefix"))) not in removed_routes
        ]
    graph_input.local_routes = [*graph_input.local_routes, *added_routes]
    return errors


@functools.cache
def agent_registry() -> ToolRegistry:
    """The tool catalogue, built once. The conversational surfaces offer its
    read tools, and `frame_step` reads the provenance of a step from it."""
    from hst.twin_tools import catalogue_registry

    return catalogue_registry()


def offered_tools(ctx: ToolContext, registry: ToolRegistry | None = None) -> list[Tool]:
    """The tools `ctx.principal` may call on `ctx.surface`, in catalogue order.

    Each tool runs a call through `registry.invoke` with a copy of `ctx` that
    has its own reader pool. The model copy of the step is the framed result
    or the framed error. The UI copy is the unframed text. `registry` defaults
    to `agent_registry()`. The list is empty for a context without a principal
    or without a surface.
    """
    if registry is None:
        registry = agent_registry()
    if ctx.principal is None or ctx.surface is None:
        return []
    return [
        Tool(
            name=spec.name,
            description=spec.description,
            schema=spec.input_schema(),
            permission=spec.permission,
            invoke=_invoker(registry, ctx, spec.name),
        )
        for spec in registry.offered(ctx.principal, ctx.surface)
    ]


def _invoker(registry: ToolRegistry, ctx: ToolContext, name: str) -> Callable[[Any], ToolCall]:
    def invoke(arguments: Any) -> ToolCall:
        outcome = registry.invoke(replace(ctx, readers=ReaderPool()), name, arguments)
        # An error text can quote device-authored strings. The model copy of an
        # error has the frame of a result.
        model_copy = frame_untrusted(outcome.model_text) if outcome.is_error else outcome.model_text
        return ToolCall(name, arguments, model_copy, is_error=outcome.is_error, ui_result=outcome.ui_text)

    return invoke


def _match_devices(session: Any, name: str) -> list[dict[str, Any]]:
    from hst import path as path_engine

    exact = path_engine._read(session, _DEVICE_EXACT_QUERY, name=name)
    return exact or path_engine._read(session, _DEVICE_PREFIX_QUERY, name=name)


@dataclass
class RoutePrediction:
    """One BGP route prediction: the scope uid, its kind (`device` or `vrf`),
    the predicted `RouteDelta` with the intents applied, and, when asked for,
    the prediction without them."""

    scope: str
    scope_kind: str
    delta: Any
    baseline: Any = None


def route_prediction(
    pinned: Any, scope: str, intents: list[dict[str, Any]], *, baseline: bool = False
) -> RoutePrediction:
    """Predict the BGP routes of one device or VRF of the pinned run.

    `scope` is a VrfInstance uid, a device uid or a hostname. An ambiguous
    hostname raises ValueError with the candidates. A hostname that matches no
    device goes to the read unchanged, and the read reports
    no-bgp-process-in-scope. `intents` change the engine input before the
    engine runs (`_apply_predict_intents`). The model errors of the delta
    start with the errors of the read and then the errors of the intents. With
    `baseline`, the engine also runs on the input as read, before the intents
    apply.
    """
    from hst.app import simul_read
    from hst.simul import provider

    name = scope.strip()
    # A VrfInstance uid starts with "vrf:" and a device uid starts with "dev:"
    # (hst.core.uid). `_match_devices` resolves each other value as a hostname.
    if name.startswith("vrf:"):
        target, scope_kind = name, "vrf"
        graph_input = simul_read.read_simulation_input(pinned, vrf=name)
    else:
        target = name
        if not name.startswith("dev:"):
            matches = _match_devices(pinned, name)
            if len(matches) > 1:
                candidates = ", ".join(f"{m['uid']} ({m['hostname']})" for m in matches)
                raise ValueError(f"ambiguous device name {name!r}; matches: {candidates}")
            if matches:
                target = matches[0]["uid"]
            # Without a match the read runs with the name and reports no-bgp-process-in-scope.
        scope_kind = "device"
        graph_input = simul_read.read_simulation_input(pinned, device=target)

    def compute() -> Any:
        return provider.compute_route_delta(
            processes=graph_input.processes,
            sessions=graph_input.sessions,
            policies=graph_input.policies,
            local_routes=graph_input.local_routes,
            platform=graph_input.platform,
        )

    before = compute() if baseline else None
    if before is not None:
        # The baseline is marked on the input as read, before the intents change the input.
        simul_read.mark_not_established(before, graph_input)
    # The intents replace the lists of graph_input before the engine runs on it.
    intent_errors = _apply_predict_intents(graph_input, intents)
    delta = compute()
    delta.model_errors = graph_input.errors.as_dicts() + intent_errors + delta.model_errors
    # `mark_not_established` sets the reason on each row of a context with an
    # ambiguous policy name.
    simul_read.mark_not_established(delta, graph_input)
    return RoutePrediction(scope=target, scope_kind=scope_kind, delta=delta, baseline=before)


def dispatch(tools: list[Tool], name: str, arguments: dict[str, Any]) -> ToolCall:
    """Run a tool by name, converting failure into a result the model can read.

    A tool error is returned to the model as a step and is not raised.

    A tool with `invoke` returns its own step. For a tool run through `run`,
    the model copy of a result or an error is at most `MAX_RESULT_CHARS`
    characters before framing. The UI copy is the full text, which the ask
    route cuts at its own `MAX_STEP_RESULT_CHARS`.
    """
    tool = next((t for t in tools if t.name == name), None)
    if tool is None:
        return _framed_error(_error_step(name, arguments, f"No such tool: {name}"))
    invoke = getattr(tool, "invoke", None)
    if invoke is not None:
        return invoke(arguments)
    try:
        run = getattr(tool, "run", None)
        if run is None:
            raise ValueError(f"tool {name} has nothing to run")
        result = run(**arguments)
        model_copy = cap_model_copy(result)
    except Exception as exc:  # The model and the UI get the error as a step.
        return _framed_error(_error_step(name, arguments, f"{type(exc).__name__}: {exc}"))
    return ToolCall(name, arguments, frame_untrusted(model_copy), ui_result=result)


def _framed_error(call: ToolCall) -> ToolCall:
    """The error step with its model copy framed. An error text can quote
    device-authored strings, such as the hostnames of an ambiguous match."""
    ui_result = call.ui_result if call.ui_result is not None else call.result
    framed = frame_untrusted(call.result)
    return ToolCall(call.name, call.arguments, framed, is_error=True, ui_result=ui_result)


def _error_step(name: str, arguments: dict[str, Any], error: str, limit: int | None = None) -> ToolCall:
    """An error step whose model copy is at most `limit` characters, by default
    `MAX_RESULT_CHARS`.

    An error text can echo model input, such as a Cypher query in a database
    error. A cut text ends with a note, and the note counts toward the limit.
    """
    from hst.app.agent.traffic import MAX_RESULT_CHARS

    if limit is None:
        limit = MAX_RESULT_CHARS
    if len(error) <= limit:
        return ToolCall(name, arguments, error, is_error=True)
    note = f"\n[error text cut to {limit} characters]"
    model_copy = error[: limit - len(note)] + note
    return ToolCall(name, arguments, model_copy, is_error=True, ui_result=error)


def is_envelope(value: Any) -> bool:
    """True when `value` is the parsed envelope of a catalogue tool. An
    envelope is an object with `result` and with the objects `snapshot` and
    `provenance`."""
    return (
        isinstance(value, dict)
        and "result" in value
        and isinstance(value.get("snapshot"), dict)
        and isinstance(value.get("provenance"), dict)
    )


def cap_model_copy(result: str, limit: int | None = None) -> str:
    """Bound the copy of a tool result the model reads to `limit` characters.

    The limit defaults to `traffic.MAX_RESULT_CHARS`, the limit of
    `traffic.bounded_result`. A result that fits is returned as it is. A
    catalogue envelope is shortened by
    `_cap_envelope`. Another larger JSON object loses the trailing
    items of its largest top-level list until it fits, and gains
    `"output_truncated": true`. When emptying that list is not enough, the next
    largest list is emptied and shortened the same way. Every other field keeps
    the value the tool computed. A result with no list left to shorten raises
    ValueError, which `dispatch` reports as an error step.
    """
    from hst.app.agent.traffic import MAX_RESULT_CHARS

    if limit is None:
        limit = MAX_RESULT_CHARS
    if len(result) <= limit:
        return result
    try:
        body = json.loads(result)
    except ValueError:
        body = None
    if is_envelope(body):
        return _cap_envelope(body, limit)
    if isinstance(body, dict):
        body["output_truncated"] = True
        while lists := [key for key, value in body.items() if isinstance(value, list) and value]:
            largest = max(lists, key=lambda name: len(json.dumps(body[name])))
            items, body[largest] = body[largest], []
            size = len(json.dumps(body))
            if size > limit:
                continue
            # json.dumps writes a list as "[" + items joined by ", " + "]". Each
            # item after the first adds 2 characters for the separator.
            kept = 0
            for item in items:
                size += len(json.dumps(item)) + (2 if kept else 0)
                if size > limit:
                    break
                kept += 1
            body[largest] = items[:kept]
            return json.dumps(body)
    raise ValueError(
        f"the result exceeds the {limit}-character limit and has no list "
        "that can be shortened; narrow the request"
    )


def _compact(value: Any) -> str:
    """`value` as JSON text in the compact form an envelope is written in."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def _nested_lists(node: dict[str, Any], name: str) -> list[tuple[str, dict[str, Any], str]]:
    """Every list reachable from `node` through objects alone, as its dotted
    name, the object that holds it and its key. The items of a list are not
    searched."""
    found: list[tuple[str, dict[str, Any], str]] = []
    for key, value in node.items():
        path = f"{name}.{key}"
        if isinstance(value, list):
            found.append((path, node, key))
        elif isinstance(value, dict):
            found += _nested_lists(value, path)
    return found


def _cut_note(name: str, kept: int, total: int, limit: int, paged: bool) -> str:
    remedy = "narrow the request or lower limit" if paged else "narrow the request"
    return (
        f"{name} lists {kept} of {total} items in this copy, cut to fit {limit} characters; "
        f"{remedy} to read the rest"
    )


_CURSOR_NOTE = (
    "page.truncated is true because this copy leaves items of the page out; page.next_cursor continues "
    "after the whole page and does not return them"
)


def _cap_run_health(envelope: dict[str, Any], limit: int) -> None:
    """Shorten the run-health lists of `envelope` to at most `limit` characters.

    Health flags and identifiers stay.
    """
    run = envelope["snapshot"].get("run")
    if not isinstance(run, dict) or len(_compact(run)) <= limit:
        return
    lists = _nested_lists(run, "snapshot.run")
    while pending := [entry for entry in lists if entry[1][entry[2]]]:
        name, holder, key = max(pending, key=lambda entry: len(_compact(entry[1][entry[2]])))
        items, holder[key] = holder[key], []
        run["output_truncated"] = envelope["output_truncated"] = True
        if name == "snapshot.run.freshness.devices":
            holder["truncated"] = True
        size = len(_compact(run))
        kept = 0
        for item in items:
            size += len(_compact(item)) + (1 if kept else 0)
            if size > limit:
                break
            kept += 1
        holder[key] = items[:kept]
        envelope["warnings"].append(
            f"{name} lists {kept} of {len(items)} items in this model copy; "
            "run health details were shortened to leave room for the tool result. "
            "Omitted entries are not evidence of healthy or absent sources or devices."
        )
        if len(_compact(run)) <= limit:
            return


def _cap_envelope(envelope: dict[str, Any], limit: int) -> str:
    """A catalogue envelope shortened to at most `limit` characters.

    Large shared run-health lists first get at most a quarter of the budget.
    The lists inside `result` and `evidence`, at any depth of objects, are
    the ones shortened. The largest list loses trailing items until the text
    fits. When emptying it is not enough, the next largest list is emptied and
    shortened the same way. The envelope gains `"output_truncated": true`, and
    `warnings` gains one entry per shortened list that names the list and the
    items kept. A paged envelope also gets `page.truncated` set to true and a
    last warning that `page.next_cursor` continues after the whole page. The
    provenance, the rest of the page and every other field keep the values
    the tool computed. An envelope that does not fit with every such list
    empty raises ValueError.
    """
    if len(compacted := _compact(envelope)) <= limit:
        return compacted
    warnings = envelope.get("warnings")
    if not isinstance(warnings, list):
        warnings = envelope["warnings"] = []
    _cap_run_health(envelope, limit // 4)
    if len(compacted := _compact(envelope)) <= limit:
        return compacted
    lists: list[tuple[str, dict[str, Any], str]] = []
    result = envelope["result"]
    if isinstance(result, list):
        lists.append(("result", envelope, "result"))
    elif isinstance(result, dict):
        lists += _nested_lists(result, "result")
    evidence = envelope.get("evidence")
    if isinstance(evidence, dict):
        lists += _nested_lists(evidence, "evidence")
    # a paged tool states its page size, which the caller can lower
    page = envelope.get("page")
    paged = isinstance(page, dict) and page.get("limit") is not None
    envelope["output_truncated"] = True
    if paged and isinstance(page, dict):
        # the note is in place before any size is measured, and moves last at the end
        page["truncated"] = True
        warnings.append(_CURSOR_NOTE)
    while pending := [entry for entry in lists if entry[1][entry[2]]]:
        name, holder, key = max(pending, key=lambda entry: len(_compact(entry[1][entry[2]])))
        items, holder[key] = holder[key], []
        # The size is measured with the longest form of the note, which has
        # `len(items)` as the kept count.
        warnings.append(_cut_note(name, len(items), len(items), limit, paged))
        size = len(_compact(envelope))
        if size > limit:
            warnings[-1] = _cut_note(name, 0, len(items), limit, paged)
            continue
        # A compact list is "[" + items joined by "," + "]". Each item after the
        # first adds 1 character for the separator.
        kept = 0
        for item in items:
            size += len(_compact(item)) + (1 if kept else 0)
            if size > limit:
                break
            kept += 1
        holder[key] = items[:kept]
        warnings[-1] = _cut_note(name, kept, len(items), limit, paged)
        if paged:
            warnings.remove(_CURSOR_NOTE)
            warnings.append(_CURSOR_NOTE)
        return _compact(envelope)
    raise ValueError(
        f"the result exceeds the {limit}-character limit with every list of its result and "
        "evidence emptied; narrow the request"
    )


# The header that `frame_untrusted` writes. The attributes `step`, `tool` and
# `snapshot` are optional. An attribute value is HTML-escaped and holds no
# double quote.
_FRAME_OPEN = re.compile(
    r'<tool_result(?: step="s[0-9]+")?(?: tool="[^"]*")?(?: snapshot="[^"]*")? untrusted="true">\n'
)
_FRAME_CLOSE = "\n</tool_result>"
# The pattern matches `<`, a run of backslashes, then `/`. Escaping adds one
# backslash to the run and unescaping removes one. The escaped payload holds
# no `</`, and unescaping restores every text. A JSON parser reads `<\/` in a
# string as `</`.
_CLOSING = re.compile(r"<(\\*)/")
_ESCAPED_CLOSING = re.compile(r"<\\(\\*)/")
_RUN_ID = re.compile(r"[0-9]{1,19}")


def step_label(label: int) -> str:
    """The name of a step in a frame, a history line and a citation: `s<label>`."""
    return f"s{label}"


def unframe(result: str) -> str:
    """Strip the `frame_untrusted` envelope and undo its escaping. A text
    without the envelope is returned unchanged."""
    opened = _FRAME_OPEN.match(result)
    if opened is None or not result.endswith(_FRAME_CLOSE) or opened.end() > len(result) - len(_FRAME_CLOSE):
        return result
    payload = result[opened.end() : len(result) - len(_FRAME_CLOSE)]
    return _ESCAPED_CLOSING.sub(r"<\1/", payload)


def frame_untrusted(
    result: str, *, step: int | None = None, tool: str | None = None, snapshot: str | None = None
) -> str:
    """Mark a tool result or error as device-collected data.

    Every `</` in the payload is escaped. A payload cannot close the frame.
    The header is `<tool_result step="sN" tool="<name>" snapshot="<run>"
    untrusted="true">`, with each attribute that has no value left out.
    `unframe` returns the payload as given.
    """
    attributes = ""
    if step is not None:
        attributes += f' step="{step_label(step)}"'
    if tool is not None:
        attributes += f' tool="{html.escape(tool, quote=True)}"'
    if snapshot is not None:
        attributes += f' snapshot="{html.escape(snapshot, quote=True)}"'
    escaped = _CLOSING.sub(r"<\\\1/", result)
    return f'<tool_result{attributes} untrusted="true">\n{escaped}{_FRAME_CLOSE}'


def frame_step(
    step: ToolCall, label: int | None, turn_snapshot: Snapshot | None, provenance: Provenance | None = None
) -> None:
    """Frame the model copy of one step of a turn with its label, its tool and
    the run it read.

    The step callback calls `frame_step`. The adapters append `step.result`
    to the transcript after the callback returns. `label` is the
    `ai_steps.label` of the step, or None. The run is `provenance.snapshot`.
    Without `provenance`, `step_provenance` reads the provenance.
    `ui_result` keeps the unframed text.
    """
    text = unframe(step.result)
    if step.ui_result is None:
        step.ui_result = text
    if provenance is None:
        provenance = step_provenance(step, turn_snapshot, text)
    named = provenance.snapshot if provenance is not None else None
    step.result = frame_untrusted(
        text,
        step=label,
        tool=step.name,
        snapshot=named if named is not None and _RUN_ID.fullmatch(named) else None,
    )


def step_provenance(
    step: ToolCall, turn_snapshot: Snapshot | None, text: str | None = None
) -> Provenance | None:
    """The provenance of one step of a turn, or None.

    The provenance function of the tool spec reads the provenance of a result
    from the unframed model copy `text`. For a catalogue tool it is the run,
    the engine and the queries of the envelope. For an error step
    `snapshot_provenance` returns the run of the `snapshot` argument, or the
    run of the turn. `step_provenance` does not raise. It returns None for
    arguments that are not a JSON object, for an unknown tool and for a
    provenance function that raises.
    """
    spec = agent_registry().get(step.name)
    if spec is None or not isinstance(step.arguments, Mapping):
        return None
    provenance = snapshot_provenance if step.is_error else spec.provenance
    try:
        return provenance(
            ToolContext(settings=None, snapshot=turn_snapshot),
            step.arguments,
            unframe(step.result) if text is None else text,
        )
    except Exception:
        log.warning("could not read the provenance of tool %s", step.name, exc_info=True)
        return None
