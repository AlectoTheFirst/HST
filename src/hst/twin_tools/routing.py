"""Routing tools: `routing_routes`, `routing_bgp` and `routing_predict_routes`.
`routing_evaluate_policy` is defined in `route_policy.py` and registered here,
in catalogue order.

`routing_routes` reads the route table a device reported, from the side store,
through the body of `GET /api/explore/routes`. With `source: computed` it runs
the routing calculation (`hst.simul.rib.compute`) over the input
`read_rib_input` reads for the device, and `both` returns the two side by
side. `mode: search_prefix` finds one prefix across every device. It reads the
configured and learned route edges of the graph, the observed route tables
and the observed BGP paths. Each device is read from the run that the
snapshot selects for it. `routing_bgp` reads the configured BGP sessions of
the graph with the state the side store observed for each, or the BGP paths
the side store observed. `routing_predict_routes` runs the BGP propagation
engine through `route_prediction`.

An observed row is proven when the snapshot recorded the device's table as
complete, and possible otherwise. An empty observed answer establishes
nothing. A computed row is proven when the calculation validated it against
the observed table. A predicted row is possible at most. The prediction
engine models BGP alone.

The prefix search and the routing calculation run under the whole-call
deadline of a read tool. Past it the call answers `timeout`.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.core import ipenc
from hst.core import snapshot as snapshotmod
from hst.core.reasoner import RT_IMPORTED_ROUTES
from hst.queries import _VRF_DEVICE
from hst.results.words import record
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    CATALOGUE_LIMITS,
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    gap_list,
    http_error,
    jsonable,
    unknowns_missing,
    whole_result,
)
from hst.twin_tools.inventory import _resolve_device

# The table outcomes that `coverage` of the envelope accepts.
_COVERAGE = frozenset({"complete", "complete-empty", "partial", "failed", "missing", "not-captured"})

# One lookup reports at most this many covering routes.
LOOKUP_CAP = 50

ADMIN_UNKNOWN = (
    "the observed route table records no administrative distance, so admin is null on every observed row"
)

_CONTEXT_QUERY = f"""
MATCH (v:VrfInstance:Obj)
WHERE NOT v:Retired AND v.collection_ts = $snap
  AND (v.uid = $context OR toLower(v.name) = toLower($context))
WITH v, {_VRF_DEVICE} AS d
WHERE d.uid = $device
RETURN v.uid AS uid, v.name AS name
ORDER BY uid LIMIT 11"""


def _context_uid(pinned: Any, device_uid: str, context: str | None) -> str | None:
    """The uid of the VrfInstance of the device that `context` selects by uid
    or by name. The result is None when no context is given. A name that
    matches more than one context raises `ambiguous` with the candidates. A
    name that matches no context raises `not_found`."""
    if context is None:
        return None
    rows = pathmod._read(pinned, _CONTEXT_QUERY, device=device_uid, context=context.strip())
    if not rows:
        raise ToolError(
            "not_found", f"no context {context!r} on device {device_uid} in this snapshot", field="context"
        )
    if len(rows) > 1:
        raise ToolError(
            "ambiguous",
            f"{context!r} names more than one context on {device_uid}; pass one uid from candidates",
            field="context",
            candidates=[{"uid": r["uid"], "name": r["name"]} for r in rows[:10]],
        )
    return str(rows[0]["uid"])


def _coverage(value: Any) -> Any:
    return value if value in _COVERAGE else None


def _observed_evidence(coverage: str | None) -> ItemEvidence:
    """The evidence of an observed row. The result is `complete` for a
    complete table. For any other table outcome the result is `incomplete`,
    and `missing` holds the outcome."""
    if coverage == "complete":
        return ItemEvidence.of(record("complete"), basis="observed")
    short = [
        Missing(
            code=f"table-{coverage or 'not-recorded'}",
            detail=f"the table was recorded as {coverage or 'not recorded'}",
        )
    ]
    return ItemEvidence.of(record("incomplete", missing=short), basis="observed")


def _observed_unknowns(*, available: bool, approximate: bool, coverage: str | None, what: str) -> list[str]:
    unknowns = []
    if not available:
        unknowns.append(f"the side store holds no {what} for this run")
    elif approximate:
        unknowns.append(
            f"no manifest governs this run: the {what} files were chosen by age, and no table outcome "
            "is recorded"
        )
    elif coverage not in ("complete", "complete-empty"):
        unknowns.append(f"the snapshot recorded the device's {what} as {coverage or 'not recorded'}")
    return unknowns


def _observed(items: list[dict[str, Any]], unknowns: list[str]) -> Any:
    """The result of the whole answer for the listed rows (`whole_result`). The
    unknowns are the missing data of a record completeness."""
    return whole_result((item["evidence"]["result"] for item in items), unknowns=unknowns)


# --- routing_routes ------------------------------------------------------------------------

# The whole-call deadline of a prefix search and of a routing calculation. It
# equals the deadline of every catalogue read tool.
DEADLINE_S = CATALOGUE_LIMITS.timeout_s

# One prefix search reads at most this many rows from each source. A search
# that matches more rows raises `limit_exceeded`.
SEARCH_CAP = 10_000

COMPUTED_UNKNOWN = (
    "computed rows come from the routing calculation over the routes, link-state databases and BGP "
    "paths this snapshot recorded; a computed row is proven only when the calculation validated it "
    "against the device's observed route table"
)


def _context_field() -> Any:
    return Field(
        default=None,
        max_length=512,
        description=(
            "A VrfInstance uid, or a VRF name on the device. Omitted, every context of the device answers."
        ),
    )


class RouteLookupInput(selectors.ToolInput):
    """The routes of one device that cover an address, longest prefix first."""

    mode: Literal["lookup"]
    device: selectors.DeviceRef
    context: str | None = _context_field()
    address: str = Field(max_length=64, description="An IPv4 or IPv6 address.")
    source: Literal["observed", "computed", "both"] = Field(
        default="observed",
        description=(
            "observed reads the route table the device reported. computed runs the routing calculation "
            "for the device, one device per call. both returns the two side by side."
        ),
    )


class RouteTableInput(selectors.PagedInput):
    """One page of the route table of a device, or of one of its contexts."""

    mode: Literal["table"]
    device: selectors.DeviceRef
    context: str | None = _context_field()
    prefix_contains: str | None = Field(
        default=None, max_length=64, description="Only prefixes whose text contains this."
    )
    protocol: str | None = Field(
        default=None,
        max_length=32,
        description="Only routes of this protocol. An empty string selects routes that name none.",
    )
    source: Literal["observed", "computed"] = Field(
        default="observed",
        description=(
            "observed pages through the route table the device reported. computed pages through the "
            "table the routing calculation installs for the device."
        ),
    )


class PrefixSearchInput(selectors.PagedInput):
    """One prefix across every device, in the graph and in the observed tables."""

    mode: Literal["search_prefix"]
    prefix: selectors.Cidr
    match: Literal["exact", "longer", "shorter"] = Field(
        default="exact",
        description=(
            "exact: the prefix itself. longer: the prefix and every prefix inside it. shorter: the "
            "prefix and every prefix that covers it."
        ),
    )
    role: Literal["originated", "advertised", "learned", "installed", "any"] = Field(
        default="any",
        description=(
            "originated: the configured routes of a context in the graph (ORIGINATES and STATIC_ROUTE "
            "edges). learned: the learned routes of the graph (LEARNED_ROUTE edges) and the BGP paths a "
            "session received or accepted. installed: the route tables the devices reported. "
            "advertised: the BGP paths a session advertised."
        ),
    )


class RoutingRoutesInput(
    RootModel[Annotated[RouteLookupInput | RouteTableInput | PrefixSearchInput, Field(discriminator="mode")]]
):
    """mode: lookup lists the routes covering an address; mode: table pages through a route table;
    mode: search_prefix finds one prefix across every device."""


class RouteRow(BaseModel):
    model_config = ConfigDict(extra="allow")

    prefix: str | None = None
    admin: int | None = None
    evidence: ItemEvidence


class ComputedRoutes(BaseModel):
    """The rows the routing calculation installs for the device."""

    model_config = ConfigDict(extra="allow")

    contexts: list[str] = Field(description="the contexts of the device the rows cover")
    scope_contexts: int = Field(
        description=(
            "the forwarding contexts the calculation read, widened from the device through BGP peers, "
            "route targets and leaked next hops"
        )
    )
    rounds: int
    convergence: str | None = Field(description="settled when the calculation found a fixed point")
    approximate: bool = Field(description="true when no manifest selected the observed tables it read")
    total: int = Field(description="every computed row that matches, across pages")
    protocols: list[dict[str, Any]] | None = None
    routes: list[RouteRow]
    routes_truncated: bool = Field(
        default=False, description="lookup: more covering routes exist than the 50 listed"
    )


class PrefixRow(BaseModel):
    model_config = ConfigDict(extra="allow")

    device_uid: str | None
    context_uid: str | None = None
    prefix: str
    role: Literal["originated", "advertised", "learned", "installed"]
    source: Literal["graph", "rib", "bgp_session_routes"]
    evidence: ItemEvidence


class RoutingRoutesResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["lookup", "table", "search_prefix"]
    source: Literal["observed", "computed", "both"] | None = None
    device_uid: str | None = None
    context_uid: str | None = None
    address: str | None = None
    available: bool | None = Field(
        default=None, description="whether the side store holds the tables the answer reads for this run"
    )
    approximate: bool | None = None
    coverage: str | None = None
    run_id: str | None = Field(default=None, description="the side-store run the observed rows come from")
    total: int | None = Field(
        default=None, description="every observed row, or every search row, that matches, across pages"
    )
    protocols: list[dict[str, Any]] | None = None
    routes: list[RouteRow] | None = Field(default=None, description="the observed rows")
    routes_truncated: bool = Field(
        default=False, description="lookup: more covering routes exist than the 50 listed"
    )
    computed: ComputedRoutes | None = Field(default=None, description="source computed or both")
    prefix: str | None = None
    match: str | None = None
    role: str | None = None
    items: list[PrefixRow] | None = Field(default=None, description="search_prefix: one page of matches")


@dataclass
class _Part:
    """One source's share of a `routing_routes` answer."""

    fields: dict[str, Any]
    rows: list[dict[str, Any]]
    unknowns: list[str]
    gap_entries: list[dict[str, Any]] = field(default_factory=list)
    page: Any = None
    coverage: str | None = None


def routing_routes(ctx: ToolContext, params: RouteLookupInput | RouteTableInput | PrefixSearchInput) -> str:
    if isinstance(params, PrefixSearchInput):
        return _search_prefix(ctx, params)
    started = time.monotonic()
    address = None
    if isinstance(params, RouteLookupInput):
        try:
            address = str(ipaddress.ip_address(params.address.strip()))
        except ValueError as exc:
            raise ToolError(
                "invalid_argument", f"{params.address!r} is not an IP address: {exc}", field="address"
            ) from None
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "routing_routes", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = _resolve_device(pinned, params.device)
        context_uid = _context_uid(pinned, device_uid, params.context)
        result: dict[str, Any] = {
            "mode": params.mode,
            "source": params.source,
            "device_uid": device_uid,
            "context_uid": context_uid,
            "address": address,
        }
        parts: list[_Part] = []
        observed = None
        if params.source in ("observed", "both"):
            observed = _observed_part(ctx, call, params, device_uid, context_uid, address)
            parts.append(observed)
        if params.source in ("computed", "both"):
            snapshot = call.snapshot
            calculation = _within_deadline(
                lambda cancelled: _calculate(ctx.settings, snapshot, device_uid, context_uid, cancelled),
                started,
                "the routing calculation",
            )
            parts.append(_computed_part(call, params, calculation, device_uid, address))
        for part in parts:
            result.update(part.fields)
        gaps, gaps_truncated = gap_list(entry for part in parts for entry in part.gap_entries)
        coverage = None if observed is None else _coverage(observed.coverage)
        queries = [("fixed", "hst.twin_tools.routing._CONTEXT_QUERY")] if context_uid else []
        if params.source == "observed":
            engine, function = "hst.core.ribsource", "hst.core.ribsource.RibSource.route_page"
        else:
            engine, function = "hst.simul.rib", "hst.simul.rib.compute"
            queries.append(("fixed", "hst.app.simul_read.read_rib_input"))
        return call.finish(
            session,
            result=result,
            evidence=Evidence(
                result=_observed(
                    [row for part in parts for row in part.rows],
                    [unknown for part in parts for unknown in part.unknowns],
                ),
                coverage=coverage,
                complete=None if coverage is None else coverage in ("complete", "complete-empty"),
                unknowns=[unknown for part in parts for unknown in part.unknowns],
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                absence="not_recorded",
            ),
            page=next((part.page for part in parts if part.page is not None), None),
            engine=engine,
            engine_function=function,
            queries=queries,
        )


def _observed_part(
    ctx: ToolContext,
    call: Call,
    params: RouteLookupInput | RouteTableInput,
    device_uid: str,
    context_uid: str | None,
    address: str | None,
) -> _Part:
    """The rows the device reported, through the body of `GET /api/explore/routes`."""
    from fastapi import HTTPException

    from hst.app.routes import explore

    try:
        if isinstance(params, RouteLookupInput):
            body = explore.route_table(
                ctx.settings, call.snapshot, context_uid or device_uid, address=address, limit=LOOKUP_CAP
            )
        else:
            body = explore.route_table(
                ctx.settings,
                call.snapshot,
                context_uid or device_uid,
                prefix=params.prefix_contains,
                protocol=params.protocol,
                offset=call.pager.offset,
                limit=call.pager.limit,
            )
    except HTTPException as exc:
        raise http_error(exc, field="device") from None
    body = jsonable(body)
    coverage = _coverage(body["coverage"])
    evidence = _observed_evidence(coverage).model_dump(mode="json")
    rows = [{**row, "admin": None, "evidence": evidence} for row in body["items"]]
    fields: dict[str, Any] = {
        "device_uid": body["device_uid"],
        "context_uid": body["context_uid"],
        "available": body["available"],
        "approximate": body["approximate"],
        "coverage": body["coverage"],
        "run_id": body["run_id"],
        "total": body["total"],
    }
    page = None
    if isinstance(params, RouteLookupInput):
        longest = rows[0]["prefixlen"] if rows else None
        for row in rows:
            row["longest_match"] = row["prefixlen"] == longest
        fields.update(routes=rows, routes_truncated=body["total"] > len(rows))
    else:
        page_rows, page = call.pager.take(
            rows, total=body["total"], more=call.pager.offset + len(rows) < body["total"]
        )
        fields.update(protocols=body["protocols"], routes=page_rows)
    unknowns = [
        ADMIN_UNKNOWN,
        *_observed_unknowns(
            available=body["available"],
            approximate=body["approximate"],
            coverage=body["coverage"],
            what="route table",
        ),
    ]
    return _Part(
        fields=fields,
        rows=fields["routes"],
        unknowns=unknowns,
        page=page,
        coverage=body["coverage"],
    )


# --- the whole-call deadline ---------------------------------------------------------------


class _Cancelled(Exception):
    """Raised by abandoned work that sees its call passed the deadline."""


def _within_deadline[T](work: Callable[[threading.Event], T], started: float, what: str) -> T:
    """The result of `work`, run in a worker thread, or `timeout` once the call
    has run `DEADLINE_S` seconds since `started`.

    The worker is abandoned at the deadline and keeps running until its next
    check. `work` receives an event that is set then, and stops at that
    check. `work` opens and closes its own graph session and side-store
    readers. An error that `work` raises is raised here.
    """
    remaining = DEADLINE_S - (time.monotonic() - started)
    outcome: dict[str, Any] = {}
    done = threading.Event()
    cancelled = threading.Event()

    def target() -> None:
        try:
            outcome["result"] = work(cancelled)
        except BaseException as exc:  # The waiting call raises it. It is dropped after the deadline.
            outcome["error"] = exc
        finally:
            done.set()

    if remaining > 0:
        threading.Thread(target=target, name="hst-tool-deadline", daemon=True).start()
    if remaining <= 0 or not done.wait(remaining):
        cancelled.set()
        raise ToolError(
            "timeout",
            f"{what} did not finish within {DEADLINE_S:g} s, the deadline of one call; narrow the "
            "question and call again",
            retryable=True,
        )
    if "error" in outcome:
        raise outcome["error"]
    return outcome["result"]


# --- computed routes -----------------------------------------------------------------------


@dataclass
class _Calculation:
    """One routing calculation for one device and what it read."""

    contexts: list[str]
    unattributed: list[str]
    scope_contexts: int
    result: Any
    read_errors: list[dict[str, Any]]
    approximate: bool


def _interactive_budget() -> Any:
    """The round limits of one tool call."""
    from hst.simul import propagate, rib
    from hst.simul.convergence import ConvergenceBudget

    return ConvergenceBudget(
        outer_rounds=rib.MAX_ROUNDS,
        bgp_rounds=propagate.MAX_ROUNDS,
        resolution_passes=rib.MAX_RESOLUTION_PASSES,
    )


def _calculate(
    settings: Any,
    snapshot: snapshotmod.Snapshot,
    device_uid: str,
    context_uid: str | None,
    cancelled: threading.Event,
) -> _Calculation:
    """Read the calculation's input for the device, or for one of its contexts,
    and run it. The function runs in the worker thread of the deadline with
    its own graph session and side-store readers."""
    from hst.app import simul_read
    from hst.core import bgpsource, ospfsource, ribsource
    from hst.simul import rib
    from hst.simul.errors import ErrorSink

    readers: list[Any] = []
    try:
        rib_source = ribsource.for_snapshot(snapshot)
        readers.append(rib_source)
        bgp_source = bgpsource.for_snapshot(snapshot)
        readers.append(bgp_source)
        ospf_source = ospfsource.for_snapshot(snapshot)
        readers.append(ospf_source)
        with dbmod.session(settings, access_mode="READ") as session:
            graph = simul_read.read_rib_input(
                pathmod.pinned(session, snapshot),
                contexts=[context_uid] if context_uid else (),
                devices=() if context_uid else [device_uid],
                rib_source=rib_source,
                bgp_source=bgp_source,
                ospf_source=ospf_source,
            )
        approximate = rib_source.approximate
    finally:
        for reader in readers:
            reader.close()
    if cancelled.is_set():
        raise _Cancelled
    result = rib.compute(graph.input, ErrorSink(), budget=_interactive_budget())
    owner = {str(c["uid"]): c.get("device_uid") for c in graph.input.contexts}
    return _Calculation(
        contexts=list(graph.scopes),
        unattributed=[uid for uid in graph.scopes if owner.get(uid) != device_uid],
        scope_contexts=len(graph.input.contexts),
        result=result,
        read_errors=graph.errors.as_dicts(),
        approximate=approximate,
    )


def _computed_evidence(validation: str | None, history_dependent: bool, settled: bool) -> ItemEvidence:
    """The evidence of a computed row. The row is `validated` when the
    calculation validated it against the observed table. The row is `computed`
    when no observed table confirms it, and `history-dependent` when the
    arrival order decided it. The row is `mismatch` when the observed table
    holds another selection, and `unsettled` when the calculation did not
    settle."""
    from hst.simul import rib

    if not settled:
        short = [Missing(code="no-routing-fixed-point", detail="the routing calculation did not settle")]
        return ItemEvidence.of(record("unsettled", missing=short), basis="computed")
    if validation == rib.MISMATCH:
        short = [Missing(code="rib-route-mismatch", detail="the observed table holds another selection")]
        return ItemEvidence.of(record("mismatch", missing=short), basis="computed")
    if history_dependent:
        short = [Missing(code=rib.HISTORY_DEPENDENT, detail="the arrival order decided this selection")]
        return ItemEvidence.of(record("history-dependent", missing=short), basis="computed")
    if validation == rib.VALIDATED:
        return ItemEvidence.of(record("validated"), basis="computed")
    short = [Missing(code=rib.NOT_OBSERVED, detail="no observed table confirms this row")]
    return ItemEvidence.of(record("computed", missing=short), basis="computed")


def _computed_part(
    call: Call,
    params: RouteLookupInput | RouteTableInput,
    calculation: _Calculation,
    device_uid: str,
    address: str | None,
) -> _Part:
    """The rows of the calculation for the device. A lookup returns the
    covering routes, longest prefix first. A table read returns one page of
    the table."""
    from hst.simul import rib

    result = calculation.result
    status = result.convergence.get("status")
    settled = status == "settled"
    validation = {(str(v["context_uid"]), str(v["prefix"])): v for v in result.validation}
    history = {
        (str(g.get("context_uid")), str(g.get("prefix")))
        for g in result.gaps
        if g.get("kind") == rib.HISTORY_DEPENDENT and g.get("prefix")
    }

    def shaped(row: dict[str, Any]) -> dict[str, Any]:
        key = (str(row["context_uid"]), str(row["prefix"]))
        check = validation.get(key)
        verdict = None if check is None else check.get("status")
        return {
            **{name: row.get(name) for name in rib.ROW_KEYS},
            "validation": verdict,
            "validation_detail": None if check is None else check.get("detail"),
            "evidence": _computed_evidence(verdict, key in history, settled).model_dump(mode="json"),
        }

    fib = result.fib
    part: dict[str, Any] = {
        "contexts": calculation.contexts,
        "scope_contexts": calculation.scope_contexts,
        "rounds": result.rounds,
        "convergence": status,
        "approximate": calculation.approximate,
    }
    page = None
    if isinstance(params, RouteTableInput):
        table = [
            row
            for context in calculation.contexts
            for row in fib.table(context) or []
            if row.get("device_uid") == device_uid
        ]
        text = (params.prefix_contains or "").strip().lower()
        if text:
            table = [row for row in table if text in str(row["prefix"]).lower()]
        counts: dict[str, int] = {}
        for row in table:
            name = str(row.get("protocol") or "")
            counts[name] = counts.get(name, 0) + 1
        if params.protocol is not None:
            table = [row for row in table if str(row.get("protocol") or "") == params.protocol]
        offset, limit = call.pager.offset, call.pager.limit
        rows, page = call.pager.take(
            [shaped(row) for row in table[offset : offset + limit]],
            total=len(table),
            more=offset + limit < len(table),
        )
        part.update(
            total=len(table),
            protocols=[
                {"protocol": name, "count": count}
                for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ],
            routes=rows,
        )
    else:
        probe, family = ipenc.addr_bytes(str(address)), ipaddress.ip_address(str(address)).version
        rows = []
        for context in calculation.contexts:
            longest = {str(r["prefix"]) for r in fib.lpm(device_uid, context, str(address))}
            for row in fib.overlapping(device_uid, context, probe, probe, -1, family):
                rows.append({**shaped(row), "longest_match": str(row["prefix"]) in longest})
        rows.sort(key=lambda r: -int(r["prefixlen"]))
        part.update(total=len(rows), routes=rows[:LOOKUP_CAP], routes_truncated=len(rows) > LOOKUP_CAP)
    unknowns = [COMPUTED_UNKNOWN]
    if not settled:
        unknowns.append(
            f"the routing calculation ended as {status} after {result.rounds} rounds; its rows are the "
            "state of the last round and are not an answer"
        )
    if calculation.approximate:
        unknowns.append(
            "no manifest governs this run: the observed tables the calculation read were chosen by age"
        )
    if calculation.unattributed:
        unknowns.append(
            "the calculation attributes these contexts to no single device, so their rows are not listed: "
            + _listed(calculation.unattributed)
        )
    in_scope = set(calculation.contexts)
    entries = [g for g in result.gaps if not g.get("context_uid") or str(g["context_uid"]) in in_scope]
    entries.extend(
        e for e in [*calculation.read_errors, *result.model_errors] if e.get("kind") != "rib-route-mismatch"
    )
    return _Part(
        fields={"computed": jsonable(part)},
        rows=part["routes"],
        unknowns=unknowns,
        gap_entries=entries,
        page=page,
    )


def _listed(values: list[str], cap: int = 20) -> str:
    """At most `cap` values, comma separated, with the count of the rest."""
    text = ", ".join(values[:cap])
    return text if len(values) <= cap else f"{text} and {len(values) - cap} more"


# --- search_prefix -------------------------------------------------------------------------

# The graph holds no edges for the routes that a VRF receives over route
# targets. The second branch resolves these routes (core/reasoner.py
# `RT_IMPORTED_ROUTES`) and stops at `$limit` rows. The first branch skips
# rt-import edges.
_PREFIX_ROUTES_QUERY = f"""
CALL {{
  MATCH (v:VrfInstance:Obj)-[r:ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE]->(p:Prefix)
  WHERE NOT v:Retired AND NOT p:Retired AND r._retired_at IS NULL
    AND v.collection_ts = $snap
    AND type(r) IN $kinds
    AND coalesce(r.derived, '') <> 'rt-import'
    AND ($cidrs IS NULL OR p.cidr IN $cidrs)
    AND ($starts IS NULL OR any(s IN $starts WHERE toLower(p.cidr) STARTS WITH s))
  RETURN v, p, type(r) AS edge, coalesce(r.proto, r.protocol) AS protocol, r.next_hop AS next_hop,
         r.next_hop_vrf AS next_hop_context_uid, r.derived AS derived
  UNION ALL
  MATCH (p:Prefix:Obj)
  WHERE 'LEARNED_ROUTE' IN $kinds AND NOT p:Retired AND p.collection_ts = $snap
    AND ($cidrs IS NULL OR p.cidr IN $cidrs)
    AND ($starts IS NULL OR any(s IN $starts WHERE toLower(p.cidr) STARTS WITH s))
  {RT_IMPORTED_ROUTES}
  WITH v, p WHERE v:VrfInstance AND NOT v:Retired AND v.collection_ts = $snap
  WITH v, p LIMIT $limit
  RETURN v, p, 'LEARNED_ROUTE' AS edge, 'bgp' AS protocol, null AS next_hop,
         null AS next_hop_context_uid, 'rt-import' AS derived
}}
WITH v, p, edge, protocol, next_hop, next_hop_context_uid, derived, {_VRF_DEVICE} AS d
RETURN d.uid AS device_uid, v.uid AS context_uid, p.cidr AS prefix, edge, protocol, next_hop,
       next_hop_context_uid, derived
ORDER BY device_uid, context_uid, prefix
LIMIT $limit"""

# The graph edges and the BGP directions each role reads.
_GRAPH_EDGES = {"originated": ("ORIGINATES", "STATIC_ROUTE"), "learned": ("LEARNED_ROUTE",)}
_BGP_DIRECTIONS = {"learned": ("received", "accepted"), "advertised": ("advertised",)}
_ROLE_ORDER = {"originated": 0, "learned": 1, "installed": 2, "advertised": 3}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _too_broad() -> ToolError:
    return ToolError(
        "limit_exceeded",
        f"more than {SEARCH_CAP} routes match in one source; use a longer prefix, match exact, or one role",
    )


def _matching(text: Any, net: Network, match: str) -> str | None:
    """The normalized prefix of `text` when it matches `net` under `match`, else None."""
    try:
        other = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None
    if other.version != net.version:
        return None
    low, high = int(other.network_address), int(other.broadcast_address)
    net_low, net_high = int(net.network_address), int(net.broadcast_address)
    if match == "exact":
        found = (low, high) == (net_low, net_high)
    elif match == "longer":
        found = net_low <= low and high <= net_high
    else:
        found = low <= net_low and net_high <= high
    return str(other) if found else None


def _graph_filter(net: Network, match: str) -> tuple[list[str] | None, list[str] | None]:
    """The filter for the candidate `Prefix` nodes of the graph, as a list of
    cidr values or as a list of lower-case text prefixes of the cidr. Both are
    None when the read has no filter. `_matching` decides each candidate after
    the read."""
    if match == "exact":
        return [str(net)], None
    if match == "shorter":
        return [str(net.supernet(new_prefix=length)) for length in range(net.prefixlen + 1)], None
    if net.version == 4:
        octets = -(-net.prefixlen // 8)
        if not octets:
            return None, None
        blocks = [net] if net.prefixlen == 8 * octets else list(net.subnets(new_prefix=8 * octets))
        tail = "/" if octets == 4 else "."
        return None, [".".join(str(b.network_address).split(".")[:octets]) + tail for b in blocks]
    first = int(net.network_address) >> 112
    if net.prefixlen >= 16 and first:
        return None, [f"{first:x}:"]
    return None, None


def _graph_items(pinned: Any, net: Network, match: str, role: str) -> list[dict[str, Any]]:
    """The route edges of the graph whose prefix matches. A configured route
    has the role `originated`. A learned route has the role `learned`."""
    kinds = [kind for name, edges in _GRAPH_EDGES.items() if role in (name, "any") for kind in edges]
    cidrs, starts = _graph_filter(net, match)
    rows = pathmod._read(
        pinned, _PREFIX_ROUTES_QUERY, kinds=kinds, cidrs=cidrs, starts=starts, limit=SEARCH_CAP + 1
    )
    if len(rows) > SEARCH_CAP:
        raise _too_broad()
    items = []
    for row in jsonable(rows):
        prefix = _matching(row["prefix"], net, match)
        if prefix is None:
            continue
        edge = row["edge"]
        if edge not in kinds:
            continue
        learned = edge == "LEARNED_ROUTE"
        basis: Literal["derived", "observed", "configured"] = "configured"
        if learned:
            basis = "derived" if row.get("derived") else "observed"
        items.append(
            {
                "device_uid": row.get("device_uid"),
                "context_uid": row.get("context_uid"),
                "prefix": prefix,
                "role": "learned" if learned else "originated",
                "source": "graph",
                "edge": edge,
                "protocol": row.get("protocol") or ("static" if edge == "STATIC_ROUTE" else None),
                "next_hop": row.get("next_hop"),
                "next_hop_context_uid": row.get("next_hop_context_uid"),
                "evidence": ItemEvidence.of(record("recorded"), basis=basis).model_dump(mode="json"),
            }
        )
    return items


def _interval_clause(net: Network, match: str) -> tuple[str, list[Any]]:
    """The side-store predicate of `match` over the `lo`/`hi` interval columns."""
    low, high, _length, family = ipenc.prefix_bounds(str(net))
    if match == "exact":
        return "af = ? AND lo = ? AND hi = ?", [family, low, high]
    if match == "longer":
        return "af = ? AND lo IS NOT NULL AND lo >= ? AND hi <= ?", [family, low, high]
    return "af = ? AND lo IS NOT NULL AND lo <= ? AND hi >= ?", [family, low, high]


def _store_rows(
    con: Any,
    table: str,
    columns: str,
    where: str,
    params: list[Any],
    pick: Callable[[str], str | None],
    cancelled: threading.Event,
) -> list[dict[str, Any]]:
    """The matching rows of one side-store table, each device read from the run
    `pick` selects for it in this snapshot. The cap counts the rows of the
    selected (device, run) pairs only."""
    found = con.execute(f"SELECT DISTINCT device_uid FROM {table} WHERE {where}", params).fetchall()  # noqa: S608
    runs: dict[str, str] = {}
    for device in sorted(str(r[0]) for r in found if r[0] is not None):
        if cancelled.is_set():
            raise _Cancelled
        run = pick(device)
        if run is not None:
            runs[device] = run
    if not runs:
        return []
    cursor = con.execute(
        f"SELECT run_id, {columns} FROM {table} "  # noqa: S608
        f"JOIN (VALUES {', '.join('(?, ?)' for _ in runs)}) AS selected(selected_device, selected_run) "
        f"ON device_uid = selected_device AND run_id = selected_run WHERE {where} "
        "ORDER BY device_uid, context_uid, af, lo, prefixlen LIMIT ?",
        [*(value for pair in runs.items() for value in pair), *params, SEARCH_CAP + 1],
    )
    names = [c[0] for c in cursor.description]
    rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
    if len(rows) > SEARCH_CAP:
        raise _too_broad()
    return rows


@dataclass
class _Store:
    available: bool
    approximate: bool
    incomplete: list[str] = field(default_factory=list)
    recorded: list[str] = field(default_factory=list)
    published: bool = True

    def unknowns(self, what: str) -> list[str]:
        if not self.available:
            return [f"the side store holds no {what} for this run"]
        if self.approximate:
            return [
                f"no manifest governs this run: the {what} files were chosen by age, and no table outcome "
                "is recorded"
            ]
        notes: list[str] = []
        if not self.published:
            notes.append(f"the snapshot publishes no {what} file")
        if self.incomplete:
            devices = _listed(self.incomplete)
            notes.append(f"the snapshot did not record the {what} of these devices as complete: {devices}")
        if self.recorded:
            devices = _listed(self.recorded)
            notes.append(
                f"the snapshot holds no complete {what} for these devices, named by source/host, so they "
                f"answer no rows: {devices}"
            )
        return notes


def _incomplete(coverage: dict[str, str | None]) -> list[str]:
    return sorted(device for device, value in coverage.items() if value not in ("complete", "complete-empty"))


def _recorded_incomplete(devices: Iterable[Any]) -> list[str]:
    """The devices, as source/host, whose table outcome in the evidence of the
    snapshot is neither complete nor complete-empty. The snapshot selects no
    file for such a device, and the device has no rows in the answer."""
    return sorted(
        {f"{d.source}/{d.host}" for d in devices if d.outcome not in ("complete", "complete-empty")}
    )


def _rib_items(
    source: Any, net: Network, match: str, cancelled: threading.Event
) -> tuple[list[dict[str, Any]], _Store]:
    """The installed routes whose prefix matches, from the observed route tables."""
    from hst.core import ribsource

    con = source._connect()
    recorded = [] if source._evidence is None else _recorded_incomplete(source._evidence.devices)
    if con is None or not source._has_view:
        return [], _Store(con is not None, source.approximate, recorded=recorded, published=False)
    where, params = _interval_clause(net, match)
    rows = _store_rows(
        con,
        "rib",
        f"device_uid, vrf, context_uid, {ribsource._COLUMNS}",
        where,
        params,
        lambda device: source._latest_run_id(con, device),
        cancelled,
    )
    coverage = {device: source.coverage(device) for device in sorted({str(r["device_uid"]) for r in rows})}
    items = [
        {
            "device_uid": row["device_uid"],
            "context_uid": row.get("context_uid"),
            "vrf": row.get("vrf"),
            "prefix": row["prefix"],
            "role": "installed",
            "source": "rib",
            "protocol": row.get("protocol"),
            "next_hop": row.get("next_hop"),
            "next_hop_context_uid": row.get("next_hop_context_uid"),
            "interface": row.get("interface"),
            "metric": row.get("metric"),
            "discard": row.get("discard"),
            "run_id": row["run_id"],
            "evidence": _observed_evidence(coverage.get(str(row["device_uid"]))).model_dump(mode="json"),
        }
        for row in rows
    ]
    incomplete = [] if source.approximate else _incomplete(coverage)
    return items, _Store(True, source.approximate, incomplete, recorded)


def _bgp_items(
    source: Any, net: Network, match: str, role: str, cancelled: threading.Event
) -> tuple[list[dict[str, Any]], _Store]:
    """The BGP paths whose prefix matches. A received or accepted path has the
    role `learned`. An advertised path has the role `advertised`."""
    from hst.core import bgpsource

    con = source._connect()
    evidence = source._evidence
    recorded = [] if evidence is None else _recorded_incomplete(evidence.devices.get(bgpsource.ROUTES, []))
    if con is None or bgpsource.ROUTES not in source._views:
        return [], _Store(con is not None, source.approximate, recorded=recorded, published=False)
    directions = [d for name, values in _BGP_DIRECTIONS.items() if role in (name, "any") for d in values]
    where, params = _interval_clause(net, match)
    where = f"{where} AND direction IN ({', '.join('?' for _ in directions)})"
    rows = _store_rows(
        con,
        bgpsource.ROUTES,
        bgpsource._ROUTE_COLUMNS,
        where,
        [*params, *directions],
        lambda device: source._pick_run(con, bgpsource.ROUTES, "device_uid", device),
        cancelled,
    )
    coverage = {device: source.coverage(device) for device in sorted({str(r["device_uid"]) for r in rows})}
    status_of: dict[tuple[str, str], str | None] = {}
    items = []
    for row in rows:
        session_uid, direction = row.get("session_uid"), str(row.get("direction"))
        if session_uid is not None and (session_uid, direction) not in status_of:
            status_of[(session_uid, direction)] = source.direction_status(session_uid, direction)
        items.append(
            {
                **row,
                "role": "advertised" if direction == "advertised" else "learned",
                "source": "bgp_session_routes",
                "protocol": "bgp",
                "direction_status": status_of.get((str(session_uid), direction)),
                "evidence": _observed_evidence(coverage.get(str(row["device_uid"]))).model_dump(mode="json"),
            }
        )
    incomplete = [] if source.approximate else _incomplete(coverage)
    return items, _Store(True, source.approximate, incomplete, recorded)


@dataclass
class _Search:
    items: list[dict[str, Any]]
    stores: dict[str, dict[str, bool]]
    unknowns: list[str]
    graph_read: bool


def _search(
    settings: Any,
    snapshot: snapshotmod.Snapshot,
    net: Network,
    match: str,
    role: str,
    cancelled: threading.Event,
) -> _Search:
    """Every matching row of the graph and of the two side-store tables the
    role reads. The function runs in the worker thread of the deadline with
    its own graph session and side-store readers."""
    from hst.core import bgpsource, ribsource

    items: list[dict[str, Any]] = []
    graph_read = role in ("originated", "learned", "any")
    if graph_read:
        with dbmod.session(settings, access_mode="READ") as session:
            items.extend(_graph_items(pathmod.pinned(session, snapshot), net, match, role))
    stores: dict[str, dict[str, bool]] = {}
    unknowns: list[str] = []
    if role in ("installed", "any"):
        if cancelled.is_set():
            raise _Cancelled
        rib_reader = ribsource.for_snapshot(snapshot)
        try:
            found, store = _rib_items(rib_reader, net, match, cancelled)
        finally:
            rib_reader.close()
        items.extend(found)
        stores["rib"] = {"available": store.available, "approximate": store.approximate}
        unknowns.extend(store.unknowns("route table"))
    if role in ("learned", "advertised", "any"):
        if cancelled.is_set():
            raise _Cancelled
        bgp_reader = bgpsource.for_snapshot(snapshot)
        try:
            found, store = _bgp_items(bgp_reader, net, match, role, cancelled)
        finally:
            bgp_reader.close()
        items.extend(found)
        stores["bgp_session_routes"] = {"available": store.available, "approximate": store.approximate}
        unknowns.extend(store.unknowns("BGP path table"))
    return _Search(items=items, stores=stores, unknowns=unknowns, graph_read=graph_read)


def _prefix_key(text: Any) -> tuple[int, int, int]:
    try:
        net = ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return (9, 0, 0)
    return (net.version, int(net.network_address), net.prefixlen)


def _search_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(item.get("device_uid") or ""),
        str(item.get("context_uid") or ""),
        _prefix_key(item["prefix"]),
        _ROLE_ORDER[item["role"]],
        str(item.get("session_uid") or ""),
        str(item.get("direction") or ""),
        str(item.get("next_hop") or ""),
        item["source"],
    )


def _search_prefix(ctx: ToolContext, params: PrefixSearchInput) -> str:
    started = time.monotonic()
    try:
        net = ipaddress.ip_network(params.prefix.strip(), strict=False)
    except ValueError as exc:
        raise ToolError(
            "invalid_argument", f"{params.prefix!r} is not a prefix: {exc}", field="prefix"
        ) from None
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "routing_routes", params, session)
        snapshot = call.snapshot
        search = _within_deadline(
            lambda cancelled: _search(ctx.settings, snapshot, net, params.match, params.role, cancelled),
            started,
            "search_prefix",
        )
        items = sorted(jsonable(search.items), key=_search_key)
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        stores = search.stores
        return call.finish(
            session,
            result={
                "mode": "search_prefix",
                "prefix": str(net),
                "match": params.match,
                "role": params.role,
                "available": any(s["available"] for s in stores.values()) if stores else None,
                "approximate": any(s["approximate"] for s in stores.values()) if stores else None,
                "stores": stores,
                "total": len(items),
                "items": page_items,
            },
            evidence=Evidence(
                result=_observed(page_items, search.unknowns),
                unknowns=search.unknowns,
                absence="not_recorded",
            ),
            page=page,
            engine="hst.core.sidestore",
            queries=[("fixed", "hst.twin_tools.routing._PREFIX_ROUTES_QUERY")] if search.graph_read else [],
        )


# --- routing_bgp ---------------------------------------------------------------------------


class BgpSessionsInput(selectors.PagedInput):
    """Configured BGP sessions with their observed state."""

    mode: Literal["sessions"]
    device: str | None = Field(
        default=None, max_length=512, description="Only the sessions of this device, by uid or hostname."
    )
    vrf: str | None = Field(
        default=None, max_length=512, description="Only sessions in this VRF, by VrfInstance uid or name."
    )
    peer_ip: str | None = Field(
        default=None, max_length=64, description="Only sessions to this peer address."
    )
    peer_asn: int | None = Field(default=None, ge=0, description="Only sessions to this peer AS.")


class BgpPathsInput(selectors.PagedInput):
    """BGP paths one device observed."""

    mode: Literal["paths"]
    device: selectors.DeviceRef
    context: str | None = _context_field()
    session_uid: str | None = Field(
        default=None, max_length=512, description="Only the paths of this session."
    )
    prefix: str | None = Field(
        default=None, max_length=64, description="Only the paths of this prefix, as its exact text."
    )
    direction: Literal["received", "accepted", "advertised", "any"] = Field(
        default="any",
        description=(
            "received: what the peer sent before the import policy; accepted: what the import policy "
            "admitted; advertised: what the export policy sent."
        ),
    )


class RoutingBgpInput(RootModel[Annotated[BgpSessionsInput | BgpPathsInput, Field(discriminator="mode")]]):
    """mode: sessions lists configured sessions with observed state; mode: paths lists observed paths."""


class RoutingBgpResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["sessions", "paths"]
    device_uid: str | None = None
    context_uid: str | None = None
    available: bool
    approximate: bool
    coverage: str | None = None
    direction_status: dict[str, str | None] | None = Field(
        default=None, description="paths with session_uid: what the snapshot recorded per direction"
    )
    items: list[dict[str, Any]]


_SESSIONS_QUERY = f"""
MATCH (rp:RoutingProcess:Obj {{proto: 'bgp'}})-[h:HAS]->(s:BgpSession)
WHERE rp.collection_ts = $snap
  AND NOT rp:Retired AND NOT s:Retired AND h._retired_at IS NULL
  AND ($peer_ip IS NULL OR s.peer_ip = $peer_ip)
  AND ($peer_asn IS NULL OR s.peer_asn = $peer_asn)
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance) WHERE iv._retired_at IS NULL AND NOT v:Retired
WITH rp, s, v, {_VRF_DEVICE} AS d
WHERE ($device IS NULL OR d.uid = $device)
  AND ($vrf IS NULL OR v.uid = $vrf OR toLower(coalesce(v.name, 'default')) = toLower($vrf))
RETURN s.uid AS uid, d.uid AS device_uid, d.hostname AS device, v.uid AS vrf_uid,
       coalesce(v.name, 'default') AS vrf, coalesce(rp.asn, s.local_asn) AS local_asn,
       s.peer_asn AS peer_asn, s.peer_ip AS peer_ip, s.afi_safi AS afi_safi,
       s.state AS admin_state, s.description AS description,
       s.import_policy_name AS import_policy, s.export_policy_name AS export_policy,
       coalesce(s.carried, false) AS carried
ORDER BY device_uid, vrf, peer_ip, uid"""

_DIRECTIONS = ("received", "accepted", "advertised")


def _sessions(ctx: ToolContext, params: BgpSessionsInput) -> str:
    peer_ip = None
    if params.peer_ip is not None:
        try:
            peer_ip = str(ipaddress.ip_address(params.peer_ip.strip()))
        except ValueError as exc:
            raise ToolError(
                "invalid_argument", f"{params.peer_ip!r} is not an IP address: {exc}", field="peer_ip"
            ) from None
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "routing_bgp", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = None if params.device is None else _resolve_device(pinned, params.device)
        rows = jsonable(
            pathmod._read(
                pinned,
                _SESSIONS_QUERY,
                device=device_uid,
                vrf=params.vrf,
                peer_ip=peer_ip,
                peer_asn=params.peer_asn,
            )
        )
        page_rows, page = call.pager.take(rows[call.pager.offset :], total=len(rows))
        bgp = ctx.readers.bgp(call.snapshot)
        available, approximate = bgp.available, bgp.approximate
        items = []
        missing = 0
        for row in page_rows:
            state = bgp.session_state(row["uid"]) if available else None
            observed = None
            if state is not None:
                observed = {
                    key: state.get(key)
                    for key in (
                        "state",
                        "established_since_ms",
                        "prefixes_received",
                        "prefixes_advertised",
                        "af",
                        "safi",
                    )
                }
                evidence = ItemEvidence.of(record("observed"), basis="observed")
            else:
                missing += 1
                short = [
                    Missing(
                        code="session-state-not-captured",
                        subject=str(row.get("uid") or ""),
                        detail="the run captured no state for this session",
                    )
                ]
                evidence = ItemEvidence.of(record("state-not-captured", missing=short), basis="configured")
            items.append(
                {**row, "observed": jsonable(observed), "evidence": evidence.model_dump(mode="json")}
            )
        unknowns = []
        if missing:
            unknowns.append(
                f"observed is null for {missing} sessions on this page: their state was not captured, "
                "which is not evidence that they are down"
            )
        if approximate and available:
            unknowns.append("no manifest governs this run: the BGP state files were chosen by age")
        return call.finish(
            session,
            result={
                "mode": "sessions",
                "device_uid": device_uid,
                "available": available,
                "approximate": approximate,
                "items": items,
            },
            evidence=Evidence(
                result=_observed(items, unknowns),
                unknowns=unknowns,
                absence="not_recorded",
            ),
            page=page,
            engine="hst.core.bgpsource",
            engine_function="hst.core.bgpsource.BgpSource.session_state",
            queries=[("fixed", "hst.twin_tools.routing._SESSIONS_QUERY")],
        )


def _paths(ctx: ToolContext, params: BgpPathsInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "routing_bgp", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = _resolve_device(pinned, params.device)
        context_uid = _context_uid(pinned, device_uid, params.context)
        bgp = ctx.readers.bgp(call.snapshot)
        available, approximate = bgp.available, bgp.approximate
        rows = jsonable(
            bgp.paths(
                device_uid,
                context_uid,
                None if params.prefix is None else params.prefix.strip(),
                direction=None if params.direction == "any" else params.direction,
                session_uid=params.session_uid,
            )
        )
        coverage = _coverage(bgp.coverage(device_uid)) if available else None
        evidence = _observed_evidence(coverage).model_dump(mode="json")
        items = [{**row, "evidence": evidence} for row in rows]
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        directions = None
        if params.session_uid is not None:
            wanted = _DIRECTIONS if params.direction == "any" else (params.direction,)
            directions = {d: bgp.direction_status(params.session_uid, d) for d in wanted}
        unknowns = _observed_unknowns(
            available=available, approximate=approximate, coverage=coverage, what="BGP path table"
        )
        for direction, status in (directions or {}).items():
            if status == "not-captured":
                unknowns.append(
                    f"the {direction} direction of {params.session_uid} was not captured, so the "
                    "answer holds no rows of it"
                )
        return call.finish(
            session,
            result={
                "mode": "paths",
                "device_uid": device_uid,
                "context_uid": context_uid,
                "available": available,
                "approximate": approximate,
                "coverage": coverage,
                "direction_status": directions,
                "items": page_items,
            },
            evidence=Evidence(
                result=_observed(page_items, unknowns),
                coverage=coverage,
                complete=None if coverage is None else coverage in ("complete", "complete-empty"),
                unknowns=unknowns,
                absence="not_recorded",
            ),
            page=page,
            engine="hst.core.bgpsource",
            engine_function="hst.core.bgpsource.BgpSource.paths",
            queries=[("fixed", "hst.twin_tools.routing._CONTEXT_QUERY")] if context_uid else [],
        )


def routing_bgp(ctx: ToolContext, params: BgpSessionsInput | BgpPathsInput) -> str:
    if isinstance(params, BgpSessionsInput):
        return _sessions(ctx, params)
    return _paths(ctx, params)


# --- routing_predict_routes ----------------------------------------------------------------

# One VRF lists at most this many predicted rows, and at most this many rows
# in each of the added, removed and changed lists.
VRF_ROW_CAP = 500


class PredictRoutesInput(selectors.PagedInput):
    """Predicted BGP routes of one device or VRF, with a routing change applied."""

    scope: str = Field(
        min_length=1,
        max_length=512,
        description="A device uid (dev:...), a VrfInstance uid (vrf:...) or a hostname.",
    )
    intents: list[selectors.Intent] = Field(
        default_factory=list,
        max_length=selectors.MAX_INTENTS,
        description=(
            "The routing change. bgp_session.shut and bgp_session.unshut {session} withhold or restore "
            "a BgpSession by uid; static_route.add and static_route.remove {context_uid, prefix} add or "
            "remove a locally originated prefix. Every other kind is accepted and reported as a "
            "not-modeled gap with no effect on the prediction."
        ),
    )


class PredictedVrf(BaseModel):
    model_config = ConfigDict(extra="allow")

    context_uid: str
    row_count: int
    rows: list[dict[str, Any]]
    rows_truncated: bool
    added: list[dict[str, Any]] | None = None
    removed: list[dict[str, Any]] | None = None
    changed: list[dict[str, Any]] | None = None
    evidence: ItemEvidence


class PredictRoutesResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    scope: str
    scope_kind: Literal["device", "vrf"]
    vrf_count: int
    vrfs: list[PredictedVrf]
    model_scope: str
    model_errors: list[dict[str, Any]]


def _by_vrf(rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    """Predicted rows per context uid, keyed by prefix."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        out.setdefault(str(row.get("context_uid")), {})[str(row.get("prefix"))] = row
    return out


def _capped(key: str, rows: list[Any]) -> dict[str, Any]:
    return {key: rows[:VRF_ROW_CAP], f"{key}_count": len(rows), f"{key}_truncated": len(rows) > VRF_ROW_CAP}


def _vrf_entries(delta: Any, baseline: Any) -> list[dict[str, Any]]:
    after = _by_vrf(jsonable(delta.rib))
    before = _by_vrf(jsonable(baseline.rib)) if baseline is not None else None
    evidence = ItemEvidence.of(record("computed"), basis="computed").model_dump(mode="json")
    entries = []
    for uid in sorted(set(after) | set(before or {})):
        rows = [after.get(uid, {})[p] for p in sorted(after.get(uid, {}))]
        entry: dict[str, Any] = {
            "context_uid": uid,
            "row_count": len(rows),
            "rows": rows[:VRF_ROW_CAP],
            "rows_truncated": len(rows) > VRF_ROW_CAP,
            "evidence": evidence,
        }
        if before is None:
            entry.update(added=None, removed=None, changed=None)
        else:
            old, new = before.get(uid, {}), after.get(uid, {})
            entry.update(_capped("added", [new[p] for p in sorted(new.keys() - old.keys())]))
            entry.update(_capped("removed", [old[p] for p in sorted(old.keys() - new.keys())]))
            entry.update(
                _capped(
                    "changed",
                    [
                        {"prefix": p, "before": old[p], "after": new[p]}
                        for p in sorted(old.keys() & new.keys())
                        if old[p] != new[p]
                    ],
                )
            )
        entries.append(entry)
    return entries


def routing_predict_routes(ctx: ToolContext, params: PredictRoutesInput) -> str:
    from hst.app.agent.tools import MODEL_SCOPE, route_prediction
    from hst.simul.intents import STORED_KINDS

    unknown = sorted({i.kind for i in params.intents} - STORED_KINDS)
    if unknown:
        raise ToolError(
            "invalid_argument",
            f"unknown intent kinds: {', '.join(unknown)}; GET /api/assessment-capabilities lists the kinds",
            field="intents",
        )
    intents = [i.model_dump(mode="json") for i in params.intents]
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "routing_predict_routes", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        scope = params.scope.strip()
        if not scope.startswith("vrf:"):
            try:
                scope = _resolve_device(pinned, scope)
            except ToolError as exc:
                exc.field = "scope"
                raise
        try:
            prediction = route_prediction(pinned, scope, intents, baseline=bool(intents))
        except ValueError as exc:
            raise ToolError("invalid_argument", str(exc), field="intents") from None
        entries = _vrf_entries(prediction.delta, prediction.baseline)
        page_entries, page = call.pager.take(entries[call.pager.offset :], total=len(entries))
        model_errors = jsonable(prediction.delta.model_errors)
        gaps, gaps_truncated = gap_list(model_errors)
        predict_unknowns = [
            f"model scope: {MODEL_SCOPE}",
            "the graph records that a VRF originates a prefix and records no network statements "
            "or redistribution, so the advertised set may be larger than the router sends",
        ]
        return call.finish(
            session,
            result={
                "scope": prediction.scope,
                "scope_kind": prediction.scope_kind,
                "vrf_count": len(entries),
                "vrfs": page_entries,
                "model_scope": MODEL_SCOPE,
                "model_errors": model_errors,
            },
            evidence=Evidence(
                result=record(
                    "computed" if any(e["row_count"] for e in entries) else "empty",
                    missing=unknowns_missing(predict_unknowns),
                ),
                unknowns=predict_unknowns,
                gaps=gaps,
                gaps_truncated=gaps_truncated,
            ),
            page=page,
            engine="hst.simul.propagate",
            engine_function="hst.simul.provider.compute_route_delta",
            queries=[("fixed", "hst.app.simul_read.read_simulation_input")],
        )


def register(registry: ToolRegistry) -> None:
    from hst.twin_tools import route_policy

    registry.register(
        catalogue_spec(
            name="routing_routes",
            description=(
                "Read route tables. mode: lookup lists the routes of one device that cover an address, "
                "longest prefix first, at most 50; longest_match marks the rows longest-prefix match "
                "selects. mode: table pages through the table of the device or one of its contexts, "
                "filtered by prefix text or protocol, with per-protocol counts. source: observed reads "
                "the table the device reported into routes; a row is proven when the snapshot recorded "
                "the table as complete, and admin is null because the observed table records no "
                "administrative distance. source: computed runs the routing calculation for one device "
                "and returns its rows under computed, with admin, igp_cost and the BGP attributes; a "
                "computed row is proven when the calculation validated it against the observed table. "
                "source: both (lookup only) returns the two. mode: search_prefix finds a prefix (match "
                "exact, longer or shorter) across every device: the configured and learned route edges "
                "of the graph, the reported route tables, and the BGP paths each session received, "
                "accepted or advertised, ordered by device and context. The prefix search and the "
                "calculation answer timeout past the 60 s deadline of one call. An empty answer is not "
                "evidence that no route exists."
            ),
            input_model=RoutingRoutesInput,
            result_model=RoutingRoutesResult,
            run=routing_routes,
        )
    )
    registry.register(
        catalogue_spec(
            name="routing_bgp",
            description=(
                "mode: sessions lists configured BGP sessions, filtered by device, VRF, peer address or "
                "peer AS, each with the state the snapshot observed; observed null means the state was "
                "not captured and says nothing about whether the session is up. mode: paths lists the "
                "BGP paths one device observed, filtered by context, session, prefix and direction "
                "(received before import policy, accepted after it, advertised after export policy); "
                "with session_uid, direction_status says per direction whether it was captured."
            ),
            input_model=RoutingBgpInput,
            result_model=RoutingBgpResult,
            run=routing_bgp,
        )
    )
    registry.register(route_policy.spec())
    registry.register(
        catalogue_spec(
            name="routing_predict_routes",
            description=(
                "Predict the BGP routes of one device or VRF by propagating advertisements across the "
                "peerings the graph records, with the routing change in intents applied first. vrfs "
                "pages through the predicted tables, one VRF per item; with intents, each VRF also lists "
                "the routes the change adds, removes and changes. Every row is possible at most: the "
                "engine models BGP alone, with no IGP cost, redistribution or next-hop resolution. "
                "model_errors and the gaps state what limits the prediction; repeat them with an answer."
            ),
            input_model=PredictRoutesInput,
            result_model=PredictRoutesResult,
            run=routing_predict_routes,
        )
    )
