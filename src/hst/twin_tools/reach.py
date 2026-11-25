"""Path tools: `reach_trace` and `reach_audit_mtu`.

`reach_trace` in `path` mode traces one flow with `path.trace`, the engine
behind `GET /api/path`, and passes the arguments that the route passes. A
protocol that the caller leaves out stays unstated. Each hop of the trace has
the result of the statement "the device forwards the flow at this hop". The
result is forwarded, blocked by the deciding rule, no route, or not decided
with the missing data. A hop that does not forward decides the whole answer.
Without such a hop, the first open hop leaves the whole answer not decided.

`reach_trace` in `groups` mode evaluates every flow between two selected
address populations in one calculation, through `traffic.query`, in its
guaranteed mode. The flows fall into three disjoint buckets: passes (the
lower bound), fails (outside the upper bound) and open (the data does not
decide them). Each explanation has its result. For a selector that needs a
choice, the answer is `needs_clarification` with the candidates. The buckets
page together with one cursor, or one bucket alone when `bucket` selects it.

`reach_audit_mtu` returns one page of `audit_mtu`, and passes that engine's
own cursor through unchanged as `page.next_cursor`.
"""

from __future__ import annotations

import time
from itertools import zip_longest
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst import path as pathmod
from hst.app.agent.traffic import AddressSelector
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.core.mtu import MtuRequest
from hst.core.mtu_audit_read import AuditScope
from hst.results.trace import leg_result, project_trace, walk_result
from hst.results.words import Result, from_engine, record
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    CATALOGUE_LIMITS,
    Bounds,
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
    unpaged,
)

# One part of a trace answer lists at most `MAX_LEGS` legs, `MAX_NOTES` notes
# and `MAX_NOTES` warnings.
MAX_LEGS = 64
MAX_NOTES = 100


PortSpec = Annotated[
    Annotated[str, Field(max_length=200)] | Annotated[int, Field(ge=0, le=65535)] | None,
    Field(
        description=(
            "The port grammar of GET /api/path: a number, a range such as 1-1024, a comma list such "
            "as 80,443, or any. Omitted, the port is not stated."
        )
    ),
]


# --- reach_trace ---------------------------------------------------------------------------


class TraceFlow(BaseModel):
    """One flow."""

    model_config = ConfigDict(extra="forbid")

    src: str = Field(
        min_length=1, max_length=500, description="The source: a host address, a prefix or a range."
    )
    dst: str = Field(
        min_length=1, max_length=500, description="The destination: a host address, a prefix or a range."
    )
    proto: str | None = Field(
        default=None,
        max_length=40,
        description=(
            "The protocol grammar of GET /api/path: a name, a number, tcp_udp, any, or a comma list. "
            "Omitted, the protocol is not stated, as GET /api/path without a protocol."
        ),
    )
    port: PortSpec = None
    src_port: PortSpec = None


class ReachPathInput(selectors.ToolInput):
    """Trace one flow through the topology of one run."""

    mode: Literal["path"] = Field(description="path traces one flow.")
    flow: TraceFlow
    src_context: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "A forwarding-context uid that narrows where the source is (inventory_resolve kind: context)."
        ),
    )
    dst_context: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "A forwarding-context uid the destination is expected in; checked after forwarding decides."
        ),
    )
    reply: bool = Field(default=False, description="Also trace the reply direction of each forward leg.")
    mtu: MtuRequest | None = Field(
        default=None, description="An MTU check of complete IP packets along the path."
    )


_SELECTOR_TEXT = (
    "An address population. kind addresses takes addresses (IPs, prefixes or ranges); rfc1918 and "
    "non-rfc1918 take nothing else; group takes value, a NetObject name or uid; vlan takes value, a VLAN "
    "number; bridge_domain, site and zone take value, a name or uid (a site also by its code); app_group "
    "takes value '<application id>/<group id>' of the Business Application catalog. exclude removes "
    "addresses, prefixes or ranges. context is a VrfInstance uid that narrows the population."
)


class ReachGroupsInput(selectors.PagedInput):
    """Every flow between two address populations of one run."""

    mode: Literal["groups"] = Field(description="groups evaluates every flow between two selectors.")
    source: AddressSelector = Field(description=_SELECTOR_TEXT)
    destination: AddressSelector = Field(description=_SELECTOR_TEXT)
    ports: str = Field(
        default="any",
        min_length=1,
        max_length=200,
        description="Destination ports: a number, a range, a comma list or any.",
    )
    protocols: str = Field(
        default="any",
        min_length=1,
        max_length=100,
        description="Protocol names or numbers as a comma list, or any.",
    )
    source_ports: str = Field(
        default="any",
        min_length=1,
        max_length=200,
        description="Source ports: a number, a range, a comma list or any.",
    )
    ingress_interface: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "An Interface uid the source traffic is assumed to arrive on, for sources with no recorded "
            "attachment. The answer states the assumption."
        ),
    )
    bucket: Literal["passes", "fails", "open"] | None = Field(
        default=None,
        description=(
            "Page only this bucket; the other buckets report their counts. Omitted, the three buckets "
            "and the explanations page together."
        ),
    )


class ReachTraceInput(RootModel[Annotated[ReachPathInput | ReachGroupsInput, Field(discriminator="mode")]]):
    """mode: path traces one flow; mode: groups evaluates every flow between two selectors."""


class ReachTraceResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    detail: Any = Field(default=None, description="path: the tracer's prose on the whole walk")
    result: dict[str, Any] | None = Field(
        default=None, description="path: the answer of the walk: whether the flow is forwarded"
    )
    legs: list[dict[str, Any]] | None = Field(
        default=None,
        description="path: each leg of the trace under leg, its prose as detail, with its evidence",
    )
    status: str | None = Field(
        default=None,
        description="groups: complete, partial, needs_clarification, open or empty",
    )
    passes: dict[str, Any] | None = Field(
        default=None,
        description=(
            "groups: flows that pass the forward condition, as a count, the rectangles of this page and "
            "truncated"
        ),
    )
    fails: dict[str, Any] | None = Field(
        default=None, description="groups: flows that fail the forward condition, in the same shape"
    )
    open: dict[str, Any] | None = Field(
        default=None, description="groups: flows the data does not decide, in the same shape"
    )
    explanations: dict[str, Any] | None = Field(
        default=None,
        description="groups: the rule and device explanations of the decisions, each with its result",
    )
    candidates: list[dict[str, Any]] | None = Field(
        default=None, description="groups: the choices a selector that needs clarification offers"
    )
    exits: list[str] | None = Field(
        default=None,
        description=(
            "path: one sentence per estate exit of a forwarded walk whose candidate paths end at the "
            "estate's edge (reach left_estate or split): the device, the interface, the next hop and "
            "the basis; the walk's left_estate has the same exits as objects. Absent when no walk "
            "has one"
        ),
    )


def _leg_evidence(leg: dict[str, Any]) -> ItemEvidence:
    """The evidence of the statement "the device forwards the flow at this
    hop" for one leg of the trace. The result is the one that `project_trace`
    wrote on the leg, or `leg_result(leg)` when the leg has none."""
    stated = leg.get("result")
    return ItemEvidence.of(
        Result.model_validate(stated) if isinstance(stated, dict) else leg_result(leg), basis="derived"
    )


def _wrap(part: dict[str, Any]) -> tuple[dict[str, Any], list[ItemEvidence], list[dict[str, Any]], bool]:
    """One trace answer with its legs wrapped as `{leg, evidence}`, the evidence
    of every leg, the legs in the same order, and the `indeterminate` flag of
    the answer."""
    legs = [leg for leg in part.get("legs") or [] if isinstance(leg, dict)]
    evidence = [_leg_evidence(leg) for leg in legs]
    out = {
        **part,
        "legs": [
            {"leg": leg, "evidence": ev.model_dump(mode="json")}
            for leg, ev in zip(legs[:MAX_LEGS], evidence, strict=False)
        ],
        "legs_truncated": len(legs) > MAX_LEGS,
    }
    for key in ("notes", "warnings"):
        values = part.get(key)
        if isinstance(values, list) and len(values) > MAX_NOTES:
            out[key] = values[:MAX_NOTES]
            out[f"{key}_truncated"] = True
    return out, evidence, legs, bool(part.get("indeterminate"))


def trace_result(
    body: dict[str, Any],
) -> tuple[dict[str, Any], list[ItemEvidence], list[dict[str, Any]], bool]:
    """The trace answer as the tool returns it, the evidence of every forward
    and reply leg with the legs in the same order, and whether any part is
    indeterminate.

    A plain answer wraps its own legs. A `reply` answer wraps the forward
    part and each reply part, whether `reply` is one part or a list of them.
    """
    if "forward" not in body:
        return _wrap(body)
    forward, evidence, legs, indeterminate = _wrap(body["forward"])
    out: dict[str, Any] = {**body, "forward": forward}
    replies = body.get("reply")
    parts = replies if isinstance(replies, list) else [replies] if isinstance(replies, dict) else []
    wrapped = []
    for part in parts:
        one, more, rows, flag = _wrap(part)
        wrapped.append(one)
        evidence += more
        legs += rows
        indeterminate = indeterminate or flag
    if isinstance(replies, list):
        out["reply"] = wrapped
    elif isinstance(replies, dict):
        out["reply"] = wrapped[0]
    return out, evidence, legs, indeterminate


def _exit_basis(exit_: dict[str, Any]) -> str:
    """The basis of one estate exit in plain words."""
    basis = exit_.get("basis")
    if basis == "wan-link":
        link = exit_.get("wan_link") or exit_.get("wan_link_uid")
        return f"a collected WAN link {link}" if link else "a collected WAN link"
    if basis == "access-client-default":
        return "the access client's default"
    if basis == "site-zone":
        block = exit_.get("site_block")
        zone = 'the operator\'s site zone "internet"'
        return f"{zone} of block {block}" if block else zone
    return f"basis {basis}"


def exit_sentences(result: dict[str, Any]) -> list[str]:
    """One sentence per estate exit of each walk of a trace answer whose
    `reach` is `left_estate` or `split`. A sentence holds the device, the
    interface, the next hop and the basis. A walk without `reach` adds no
    sentence."""
    walks: list[tuple[str, Any]]
    if "forward" in result:
        replies = result.get("reply")
        walks = [("forward", result.get("forward"))]
        if isinstance(replies, list):
            walks += [
                (f"reply for {part.get('src_label')}", part) for part in replies if isinstance(part, dict)
            ]
        elif isinstance(replies, dict):
            walks.append(("reply", replies))
    else:
        walks = [("the walk", result)]
    out: list[str] = []
    for which, walk in walks:
        if not isinstance(walk, dict) or walk.get("reach") not in ("left_estate", "split"):
            continue
        where = (
            "the last hop is outside the estate"
            if walk["reach"] == "left_estate"
            else "split by path; the last hop of some paths is outside the estate"
        )
        for exit_ in walk.get("left_estate") or ():
            if not isinstance(exit_, dict):
                continue
            device = exit_.get("device") or exit_.get("device_uid")
            interface = exit_.get("interface") or exit_.get("interface_uid")
            hop = exit_.get("next_hop")
            to = f"to next hop {hop}" if hop else "with no next hop"
            out.append(f"{which}: {where}: {device} {interface} {to} ({_exit_basis(exit_)})")
    return out


def _port(value: str | int | None) -> Any:
    from hst.app.routes.path import _parse_port

    return _parse_port(None if value is None else str(value))


def reach_trace(ctx: ToolContext, params: ReachPathInput | ReachGroupsInput) -> str:
    if isinstance(params, ReachGroupsInput):
        return _groups(ctx, params)
    return _path(ctx, params)


def _path(ctx: ToolContext, params: ReachPathInput) -> str:
    from hst.app.routes.path import _parse_proto
    from hst.path.gates.firewall import _as_portset

    flow = params.flow
    try:
        if params.mtu is not None and params.mtu.reply_ip_packet_bytes is not None and not params.reply:
            raise ValueError("mtu.reply_ip_packet_bytes requires reply=true")
        port, src_port = _port(flow.port), _port(flow.src_port)
        proto = _parse_proto(flow.proto)
        _as_portset(port)
        _as_portset(src_port)
    except ValueError as exc:
        raise ToolError("invalid_argument", str(exc), field="flow") from None
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "reach_trace", params, session)
        snap = call.snapshot
        # GET /api/path builds `reply` and `mtu` in the same way. `src_port` is
        # passed only when the caller states it.
        kwargs: dict[str, Any] = {}
        if params.reply:
            kwargs["reply"] = True
        if params.mtu is not None and params.mtu.mode != "off":
            kwargs["mtu"] = params.mtu
        if src_port is not None:
            kwargs["src_port"] = src_port
        try:
            body = pathmod.trace(
                pathmod.pinned(session, snap),
                flow.src,
                flow.dst,
                port=port,
                proto=proto,
                rib=ctx.readers.rib(snap),
                src_context=params.src_context,
                dst_context=params.dst_context,
                **kwargs,
            )
        except pathmod.NoRun as exc:
            raise ToolError("snapshot_not_published", str(exc)) from None
        except ValueError as exc:
            raise ToolError("invalid_argument", str(exc), field="flow") from None
        result, evidence, legs, indeterminate = trace_result(project_trace(jsonable(body)))
        answer = walk_result([item.result for item in evidence], legs, indeterminate)
        unknowns = []
        if answer.answer == "open" and evidence:
            unknowns.append("at least one leg is indeterminate: a gate on it could not be decided")
        if any(ev.result.word == "no route" for ev in evidence):
            unknowns.append(
                "at least one leg stops where its table records no route for the destination; "
                "a route the snapshot did not record would change that leg"
            )
        if result.get("boundary") or (result.get("forward") or {}).get("boundary"):
            unknowns.append(
                "at least one leg leaves the modeled estate; the path past that boundary is not evaluated"
            )
        exits = exit_sentences(result)
        if exits:
            result = {**result, "exits": exits}
        return call.finish(
            session,
            result=result,
            evidence=Evidence(result=answer, unknowns=unknowns),
            engine="hst.path",
            engine_function="hst.path.trace",
        )


# --- reach_trace groups --------------------------------------------------------------------

# The soft deadline of one groups calculation. After the deadline, the
# calculation answers the space that it has not evaluated as not_established.
GROUPS_DEADLINE_S = CATALOGUE_LIMITS.timeout_s - 15
# One answer lists at most this many candidates for the selectors that need a choice.
MAX_CANDIDATES = 32
MAX_UNKNOWN_CHARS = 500

# The evidence of each bucket of a groups answer. The statement is the forward
# condition under the quantifier `every`. A flow passes only if every path and
# member works.
_BUCKET_EVIDENCE = {
    "allowed": ItemEvidence.of(
        from_engine("condition-holds", "holds", quantifier="every", condition="forward"), basis="computed"
    ),
    "denied": ItemEvidence.of(
        from_engine("condition-holds", "does-not-hold", quantifier="every", condition="forward"),
        basis="computed",
    ),
    "not_established": ItemEvidence.of(
        from_engine(
            "condition-holds",
            "not-established",
            quantifier="every",
            condition="forward",
            missing=[
                Missing(
                    code="flows-not-decided",
                    detail="the explanations of this bucket and missing_evidence name the missing data",
                )
            ],
        ),
        basis="computed",
    ),
}

# The result key of each engine bucket. The engine bucket `evidence` holds the
# rule and device explanations of the decisions.
_RESULT_KEYS = {
    "allowed": "passes",
    "denied": "fails",
    "not_established": "open",
    "evidence": "explanations",
}
_ENGINE_BUCKET = {key: name for name, key in _RESULT_KEYS.items()}


def _explanation(item: Any) -> Any:
    """One explanation of the engine with its condition answer in place of
    the engine's `outcome`."""
    from hst.results.project import explanation_result

    if not isinstance(item, dict) or "outcome" not in item:
        return item
    result = explanation_result(item, quantifier="every", condition="forward")
    return {**{k: v for k, v in item.items() if k != "outcome"}, "result": result}


def _groups(ctx: ToolContext, params: ReachGroupsInput) -> str:
    from hst.app.agent import traffic
    from hst.twin_tools.apps import application_lookup

    started = time.monotonic()
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "reach_trace", params, session)
        snap = call.snapshot
        try:
            body = traffic.query(
                pathmod.pinned(session, snap),
                source=params.source.model_dump(),
                destination=params.destination.model_dump(),
                ports=params.ports,
                protocols=params.protocols,
                source_ports=params.source_ports,
                ingress_interface=params.ingress_interface,
                rib_source=ctx.readers.rib(snap),
                bgp_source=ctx.readers.bgp(snap),
                ospf_source=ctx.readers.ospf(snap),
                checkpoint=lambda: time.monotonic() - started < GROUPS_DEADLINE_S,
                applications=application_lookup(ctx),
                offset=call.pager.offset,
            )
        except ValueError as exc:
            raise ToolError("invalid_argument", str(exc)) from None
        result, evidence, page = _groups_result(call, params, jsonable(body))
        return call.finish(
            session,
            result=result,
            evidence=evidence,
            page=page,
            engine="hst.impact.evaluate",
            engine_function="hst.app.agent.traffic.query",
        )


def _unknowns(texts: Any) -> list[str]:
    return [str(text)[:MAX_UNKNOWN_CHARS] for text in texts][:100]


def _groups_result(
    call: Call, params: ReachGroupsInput, body: dict[str, Any]
) -> tuple[dict[str, Any], Evidence, PageOut]:
    """The groups answer, its evidence and its page.

    The listed buckets page together. Row i of a page holds the item at the
    same offset in each listed bucket. The cursor moves every listed bucket by
    the count of rows on the page."""
    from hst.app.agent.traffic import BUCKETS

    # The calculation returns the status `not_established` for an open answer.
    status = "open" if body.get("status") == "not_established" else body.get("status")
    result: dict[str, Any] = {
        "mode": "groups",
        "status": status,
        "scope": body.get("scope"),
        "plan": body.get("plan"),
        "coverage": body.get("coverage"),
    }
    if "allowed" not in body:
        if status == "needs_clarification":
            plan = body.get("plan") or {}
            result["candidates"] = [
                {"side": side, **candidate}
                for side in ("source", "destination")
                for candidate in (plan.get(side) or {}).get("candidates") or ()
            ][:MAX_CANDIDATES]
        if status == "empty":
            result["reason"] = body.get("reason")
            unknowns = _unknowns([body.get("reason") or ""])
            evidence = Evidence(result=record("empty", missing=unknowns_missing(unknowns)), unknowns=unknowns)
        else:
            result["missing_evidence"] = body.get("missing_evidence") or []
            unknowns = _unknowns(result["missing_evidence"])
            evidence = Evidence(
                result=from_engine(
                    "condition-holds",
                    "not-established",
                    quantifier="every",
                    condition="forward",
                    missing=unknowns_missing(unknowns)
                    or [
                        Missing(code="needs-clarification", detail="the selectors name more than one choice")
                    ],
                ),
                unknowns=unknowns,
            )
        return result, evidence, unpaged()
    offset = call.pager.offset
    listed: list[str] = list(BUCKETS) if params.bucket is None else [_ENGINE_BUCKET[params.bucket]]
    windows = [body[name]["items"] for name in listed]
    more = any(
        body[name]["count"] > offset + len(window) for name, window in zip(listed, windows, strict=True)
    )
    taken, page = call.pager.take(
        list(zip_longest(*windows)), total=max(body[name]["count"] for name in listed), more=more
    )
    for name in BUCKETS:
        count = body[name]["count"]
        bucket: dict[str, Any] = {"count": count}
        if name in listed:
            index = listed.index(name)
            items = [_explanation(row[index]) for row in taken if row[index] is not None]
            bucket.update(offset=offset, items=items, truncated=count > offset + len(items))
        else:
            bucket["truncated"] = count > 0
        if name in _BUCKET_EVIDENCE:
            bucket["evidence"] = _BUCKET_EVIDENCE[name].model_dump(mode="json")
        result[_RESULT_KEYS[name]] = bucket
    for key in ("missing_evidence", "assumptions", "family_scope"):
        if key in body:
            result[key] = body[key]
    counts = {name: body[name]["count"] for name in _BUCKET_EVIDENCE}
    gaps, gaps_truncated = gap_list([*(body.get("gaps") or ()), *(body.get("model_errors") or ())])
    # The answer over the whole population is `denied` when a flow fails, else
    # `not_established` when a flow is open, else `allowed`.
    whole = next((name for name in ("denied", "not_established", "allowed") if counts[name]), None)
    evidence = Evidence(
        result=_BUCKET_EVIDENCE[whole].result if whole is not None else record("empty"),
        bounds=Bounds(
            mode="guaranteed",
            unit="flow-rectangles",
            universe_count=sum(counts.values()),
            lower_count=counts["allowed"],
            upper_count=counts["allowed"] + counts["not_established"],
            open_count=counts["not_established"],
        ),
        complete=bool((body.get("coverage") or {}).get("entire_request_decided")),
        unknowns=_unknowns(
            [
                "the calculation covers the forward direction of each flow; the return path is not evaluated",
                *(body.get("assumptions") or ()),
                *(body.get("missing_evidence") or ()),
            ]
        ),
        gaps=gaps,
        gaps_truncated=gaps_truncated,
    )
    return result, evidence, page


# --- reach_audit_mtu -----------------------------------------------------------------------


class ReachAuditMtuInput(selectors.ToolInput):
    """One page of an MTU audit of links, a bridge domain or a fabric."""

    scope: AuditScope = Field(
        default="link", description="link audits cabled neighbors; bridge-domain and fabric audit members."
    )
    subject_uid: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "The exact uid of the link end, bridge domain or fabric. Required for bridge-domain and fabric."
        ),
    )
    af: Literal[4, 6] = Field(default=4, description="The address family whose MTU is audited.")
    cursor: str | None = Field(
        default=None,
        max_length=selectors.MAX_CURSOR_CHARS,
        description=(
            "page.next_cursor of the previous reach_audit_mtu call, unchanged. It is bound to the run, "
            "scope, subject and address family."
        ),
    )
    limit: int = Field(
        default=selectors.DEFAULT_LIMIT, ge=1, le=selectors.MAX_LIMIT, description="Items per page."
    )


class ReachAuditMtuResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    scope: str
    subject_uid: str | None = None
    items: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    coverage_complete: bool
    query_count: int


def reach_audit_mtu(ctx: ToolContext, params: ReachAuditMtuInput) -> str:
    from hst.core.mtu_audit_read import audit_mtu

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "reach_audit_mtu", params, session)
        if call.snapshot.cts is None:
            raise ToolError("snapshot_not_published", "no run is published yet; the MTU audit reads one run")
        try:
            page = audit_mtu(
                pathmod.pinned(session, call.snapshot),
                scope=params.scope,
                subject_uid=params.subject_uid,
                af=params.af,
                limit=params.limit,
                cursor=params.cursor,
            )
        except ValueError as exc:
            if params.cursor and "cursor" in str(exc):
                raise ToolError("cursor_mismatch", str(exc), field="cursor") from None
            field = "subject_uid" if "subject_uid" in str(exc) else None
            raise ToolError("invalid_argument", str(exc), field=field) from None
        data = page.model_dump(mode="json")
        result = {
            key: data[key]
            for key in ("scope", "subject_uid", "items", "findings", "coverage_complete", "query_count")
        }
        result["evidence_truncated"] = bool(page.truncated and page.next_cursor is None)
        return call.finish(
            session,
            result=result,
            evidence=Evidence(
                result=record("recorded"),
                complete=page.coverage_complete,
                unknowns=[
                    "an item without findings is not evidence that its MTU matches: the audit covers the "
                    "MTU evidence the run recorded"
                ],
                gaps=[Gap(code=code, kind="unclassified", dimension="mtu") for code in page.gaps],
            ),
            page=PageOut(
                next_cursor=page.next_cursor, truncated=page.next_cursor is not None, limit=params.limit
            ),
            engine="hst.core.mtu_audit_read",
            engine_function="hst.core.mtu_audit_read.audit_mtu",
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="reach_trace",
            version=4,
            description=(
                "mode: path traces one flow from source to destination through the run's topology, "
                "routing, firewall and NAT included, as GET /api/path does, and reports the result, "
                "every hop and each hop's leg with the rule or route that decided it. A protocol left out "
                "stays unstated. Each leg's evidence.result answers whether the device forwards the flow "
                "at that hop: forwarded, blocked by a rule, no route, discarded by route, blocked at a "
                "VIP, or not decided with what is missing. The answer's evidence.result says whether the "
                "flow is forwarded on all candidate paths, or at which hop it is blocked or not decided. "
                "A walk whose paths end at the estate's edge names each exit under exits. "
                "reply also traces the reply direction; mtu checks "
                "packet sizes along the path. This is a hypothetical path computed from an imported "
                "snapshot. mode: groups evaluates every flow between a source and a destination selector "
                "(addresses, rfc1918, non-rfc1918, group, vlan, bridge_domain, site, zone or app_group) "
                "in one calculation, over the ports and protocols given (any by default), and returns "
                "disjoint buckets, as flow rectangles with exact counts: passes holds the flows that "
                "pass the forward condition, fails the flows that fail it, and open the flows the "
                "data does not decide; a flow counts as passing only if every path and member "
                "works. Each explanation carries its result. A selector that needs a choice answers "
                "status needs_clarification with the candidates. The buckets page with "
                "the cursor; bucket pages one of them alone."
            ),
            input_model=ReachTraceInput,
            result_model=ReachTraceResult,
            run=reach_trace,
        )
    )
    registry.register(
        catalogue_spec(
            name="reach_audit_mtu",
            description=(
                "One page of an MTU audit over the run's recorded MTU evidence: scope link audits cabled "
                "neighbors, bridge-domain and fabric audit the members of one subject_uid. Each item "
                "lists the resolved MTU of both ends and the findings. Pass page.next_cursor to the "
                "next reach_audit_mtu call to read the next page. For a path, use reach_trace with mtu."
            ),
            input_model=ReachAuditMtuInput,
            result_model=ReachAuditMtuResult,
            run=reach_audit_mtu,
        )
    )
