"""`routing_evaluate_policy` evaluates one candidate route against one route
policy of one device and reports the clause that decided it."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.app import simul_read
from hst.app.ai.registry import ToolContext, ToolError, ToolSpec
from hst.core import db as dbmod
from hst.queries import _VRF_DEVICE
from hst.results.words import decided, from_engine
from hst.simul import bestpath, matchlist, platforms, prefixlist
from hst.simul import compile as compilemod
from hst.simul import policy as policymod
from hst.simul.errors import ErrorSink
from hst.simul.route import DEFAULT_LOCAL_PREFERENCE, Route
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    gap_list,
    missing_of,
)
from hst.twin_tools.inventory import _resolve_device

# One answer lists at most this many clauses in `clauses`.
CLAUSE_CAP = 100

# The ErrorSink kinds that map to the gap kind `unsupported` of the envelope.
# Each kind reports a match term, a set line or a list line that the snapshot
# does not define or that the engine does not evaluate.
_UNSUPPORTED = frozenset(
    {
        "undefined-community-list",
        "undefined-as-path-list",
        "unsupported-match",
        "unsupported-set",
        "unsupported-policy",
        "unsupported-list-entry",
        "neighbor-filter-list-not-modeled",
    }
)
# An ErrorSink kind in this set means that the platform, or the policy that
# the engine keys by name, is uncertain.
_DOUBT = frozenset({"unknown-platform", "unresolved-platform-profile", "ambiguous-policy-name"})
_GAIA_KINDS = frozenset({"gaia-route-map", "gaia-chain"})

NAMED_UNKNOWN = (
    "policy_name runs the policy outside any BGP session: a construct that depends on the session type "
    "reads eBGP, and the peer AS is unknown"
)
NO_POLICY_UNKNOWN = (
    "the snapshot records no policy on this session in this direction; the outcome is the platform's "
    "rule for a session with none"
)

_SESSION_QUERY = f"""
MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj {{uid: $session_uid, collection_ts: $snap}})
WHERE h._retired_at IS NULL AND NOT rp:Retired AND NOT b:Retired
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance) WHERE iv._retired_at IS NULL AND NOT v:Retired
WITH rp, b, v, {_VRF_DEVICE} AS d
RETURN properties(b) AS props, properties(rp) AS process, v.uid AS context_uid,
       d.uid AS device_uid, d.platform AS platform, d.vendor AS vendor
LIMIT 1"""

_DEVICE_QUERY = """
MATCH (d:Device:Obj {uid: $device, collection_ts: $snap})
WHERE NOT d:Retired
RETURN d.platform AS platform, d.vendor AS vendor
LIMIT 1"""

# The policy with the name `$name` that the device defines, and the policies
# that its clauses reference, to the depth `simul_read._REFERENCE_DEPTH`. The
# uid of a route policy starts with the uid of its device (`uid.route_policy`).
# A Gaia policy is scoped to a context of the device.
_NAMED_POLICY_QUERY = f"""
MATCH (seed:RoutePolicy:Obj)
WHERE seed.name = $name AND NOT seed:Retired AND seed.collection_ts = $snap
  AND (seed.uid STARTS WITH $uid_prefix OR seed.context_uid IN $contexts)
MATCH (seed)-[ref:HAS_RULE|REFERENCES*0..{simul_read._REFERENCE_DEPTH}]->(pol:RoutePolicy)
WHERE all(r IN ref WHERE r._retired_at IS NULL) AND NOT pol:Retired
WITH DISTINCT pol
OPTIONAL MATCH (pol)-[hr:HAS_RULE]->(e)
WHERE hr._retired_at IS NULL AND NOT e:Retired
RETURN pol.uid AS uid, pol.name AS name, pol.kind AS kind,
       collect(properties(e)) AS entries
ORDER BY pol.uid"""


# --- input and result ----------------------------------------------------------------------


class CandidateRoute(BaseModel):
    """The route the policy is applied to. Attributes left out take the BGP defaults."""

    model_config = ConfigDict(extra="forbid")

    prefix: selectors.Cidr
    next_hop: str | None = Field(default=None, max_length=64, description="An IPv4 or IPv6 address.")
    as_path: str | None = Field(
        default=None, max_length=2000, description="AS numbers separated by spaces, the nearest AS first."
    )
    communities: list[Annotated[str, Field(max_length=64)]] = Field(
        default_factory=list, max_length=64, description="Communities as text, e.g. 65000:100."
    )
    local_pref: int | None = Field(default=None, ge=0, le=4294967295, description="Omitted, 100.")
    med: int | None = Field(default=None, ge=0, le=4294967295)
    origin: Literal["igp", "egp", "incomplete"] | None = Field(default=None, description="Omitted, igp.")


class EvaluatePolicyInput(selectors.ToolInput):
    """Apply a route policy of one device to a candidate route."""

    device: selectors.DeviceRef
    session_uid: str | None = Field(
        default=None,
        max_length=512,
        description="A BgpSession uid of the device: the policy it attaches in direction. Pass exactly "
        "one of session_uid and policy_name.",
    )
    policy_name: str | None = Field(
        default=None,
        max_length=200,
        description="The name of a route policy or prefix list the device defines. Pass exactly one "
        "of session_uid and policy_name.",
    )
    direction: Literal["import", "export"]
    route: CandidateRoute


class PolicyRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None
    kind: str | None
    uid: str | None
    attached: bool = Field(description="true when a session attaches the policy")
    defined: bool = Field(description="true when the snapshot holds the policy's definition")


class MatchedClause(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clause_seq: int | None = Field(description="the deciding clause; null for a prefix list")
    action: str | None
    prefix_list: str | None = Field(description="the prefix list whose line matched the route")
    entry_seq: int | None = Field(description="the sequence of that line")


class EvaluatePolicyResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    device_uid: str
    session_uid: str | None = None
    direction: Literal["import", "export"]
    platform: str
    route: dict[str, Any]
    policy: PolicyRef
    decision: Literal["accept", "reject", "no-policy", "undefined-policy", "not-evaluated"]
    outcome: Literal["accept", "reject"] | None = Field(
        description="what the route meets: the policy's decision, or the platform rule for no policy "
        "or an undefined one"
    )
    matched: MatchedClause | None
    clauses: list[dict[str, Any]] = Field(description="the clauses the attribution walk evaluated, in order")
    clauses_truncated: bool = False
    rewritten: dict[str, Any] | None = Field(
        description="the route the policy accepted, with what it changed"
    )
    evidence: ItemEvidence


# --- reading the policy --------------------------------------------------------------------


@dataclass
class _Target:
    """The policy one call evaluates and what the engine needs to run it."""

    name: str | None
    kind: str | None
    attached: bool
    platform: str
    rows: list[dict[str, Any]]
    session: dict[str, Any] | None = None
    unknowns: list[str] = field(default_factory=list)


def _reachable(rows: Sequence[dict[str, Any]], name: str | None) -> list[dict[str, Any]]:
    """The policies that `name` reaches through the lists that its clauses
    match and the policies that they call."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_name.setdefault(str(row["name"]), []).append(row)
    seen: set[str] = set()
    queue = [name] if name else []
    while queue:
        current = queue.pop()
        if current in seen or current not in by_name:
            continue
        seen.add(current)
        for row in by_name[current]:
            for entry in row["entries"]:
                for key in (
                    "match_prefix_lists",
                    "match_community_lists",
                    "match_as_path_lists",
                    "match_policies",
                    "set_comm_list_delete",
                    "calls_policy",
                    "policy_name",
                ):
                    queue.extend(compilemod._names(entry, key))
    return [row for row in rows if str(row["name"]) in seen]


def _policy_rows(
    raw: Sequence[Mapping[str, Any]], name: str | None, errors: ErrorSink
) -> list[dict[str, Any]]:
    """The reachable policies, one per name as the engine keys them. A name
    collision among them is reported."""
    names = ErrorSink()
    rows = simul_read._dedupe_policies([simul_read._policy_row(r) for r in raw], names)
    reachable = _reachable(rows, name)
    wanted = {str(row["name"]) for row in reachable}
    for error in names.errors:
        if error.subject in wanted:
            errors.report(error.kind, error.detail, error.subject)
    return reachable


def _session_target(
    pinned: Any, device_uid: str, session_uid: str, direction: str, errors: ErrorSink
) -> _Target:
    rows = pathmod._read(pinned, _SESSION_QUERY, session_uid=session_uid)
    if not rows or rows[0].get("device_uid") != device_uid:
        raise ToolError(
            "not_found",
            f"no BGP session {session_uid!r} of device {device_uid} in this snapshot",
            field="session_uid",
        )
    row = rows[0]
    props, process = dict(row.get("props") or {}), dict(row.get("process") or {})
    session = {**props, "uid": session_uid}
    if session.get("local_asn") is None and process.get("asn") is not None:
        session["local_asn"] = process["asn"]
    raw = simul_read._process_platform(process, [row.get("platform")], [row.get("vendor")])
    platform = platforms.normalize(raw, errors)
    prefix = "import" if direction == "in" else "export"
    name = session.get(f"{prefix}_policy_name")
    kind = session.get(f"{prefix}_policy_kind")
    raw_policies = pathmod._read(pinned, simul_read._POLICIES, sessions=[session_uid]) if name else []
    rows = _policy_rows(raw_policies, str(name) if name else None, errors)
    # `bestpath.apply_attached_policy` runs a prefix list that is attached
    # beside the route map first. The clauses of the route map do not have to
    # reference that prefix list.
    beside = session.get(f"{prefix}_prefix_list_name")
    if beside:
        held = {str(r["name"]) for r in rows}
        rows += [r for r in _policy_rows(raw_policies, str(beside), errors) if str(r["name"]) not in held]
    return _Target(
        name=str(name) if name else None,
        kind=str(kind).lower() if kind else None,
        attached=bool(name),
        platform=platform,
        rows=rows,
        session=session,
    )


def _named_target(pinned: Any, device_uid: str, name: str, errors: ErrorSink) -> _Target:
    device = pathmod._read(pinned, _DEVICE_QUERY, device=device_uid)
    first = device[0] if device else {}
    raw = simul_read._process_platform({}, [first.get("platform")], [first.get("vendor")])
    contexts = [str(r["uid"]) for r in pathmod._read(pinned, simul_read._CONTEXTS_OF_DEVICE, dev=device_uid)]
    raw_policies = pathmod._read(
        pinned, _NAMED_POLICY_QUERY, name=name, uid_prefix=f"rtpol:{device_uid}:", contexts=contexts
    )
    rows = _policy_rows(raw_policies, name, errors)
    kind = next((str(r["kind"]).lower() for r in rows if r["name"] == name), None)
    return _Target(
        name=name,
        kind=kind,
        attached=False,
        platform=platforms.normalize(raw, errors),
        rows=rows,
        unknowns=[NAMED_UNKNOWN],
    )


# --- the candidate route -------------------------------------------------------------------


def _route(given: CandidateRoute) -> Route:
    """The engine's `Route` for the candidate, or `invalid_argument` on `route`."""
    try:
        prefix = str(ipaddress.ip_network(given.prefix.strip(), strict=False))
        next_hop = None if given.next_hop is None else str(ipaddress.ip_address(given.next_hop.strip()))
    except ValueError as exc:
        raise ToolError("invalid_argument", f"route: {exc}", field="route") from None
    tokens = (given.as_path or "").split()
    if not all(token.isdigit() for token in tokens):
        raise ToolError(
            "invalid_argument", "route: as_path holds AS numbers separated by spaces", field="route"
        )
    return Route(
        prefix=prefix,
        next_hop=next_hop,
        as_path=tuple(int(token) for token in tokens),
        communities=frozenset(c.strip() for c in given.communities if c.strip()),
        local_pref=DEFAULT_LOCAL_PREFERENCE if given.local_pref is None else given.local_pref,
        med=given.med,
        origin=given.origin or "igp",
    )


_ATTRIBUTES = ("next_hop", "as_path", "local_pref", "med", "origin", "communities", "weight", "tag")


def _route_json(route: Route) -> dict[str, Any]:
    return {
        "prefix": route.prefix,
        "next_hop": route.next_hop,
        "as_path": " ".join(str(asn) for asn in route.as_path),
        "local_pref": route.local_pref,
        "med": route.med,
        "origin": route.origin,
        "communities": sorted(route.communities),
        "weight": route.weight,
        "tag": route.tag,
    }


def _rewritten(before: Route, after: Route | None) -> dict[str, Any] | None:
    if after is None:
        return None
    return {
        **_route_json(after),
        "changed": [name for name in _ATTRIBUTES if getattr(before, name) != getattr(after, name)],
    }


# --- clause attribution --------------------------------------------------------------------


@dataclass
class _Walk:
    """The clauses one route met, in evaluation order, and the one that decided."""

    clauses: list[dict[str, Any]] = field(default_factory=list)
    matched: dict[str, Any] | None = None
    followed: bool = True
    blocked: bool = False
    note: str | None = None


def _holds(
    entry: Mapping[str, Any],
    route: Route,
    lists: Mapping[str, Any],
    platform: str,
    name: str,
    match_lists: compilemod.MatchLists,
    policies: Mapping[str, policymod.Policy] | None = None,
) -> bool:
    """Whether the clause's match lines hold for the route, as the engine compiles them."""
    guard = compilemod._guard(entry, lists, platform, ErrorSink(), f"route-map {name}", name, match_lists)
    env = policymod.Environment(
        original_route=route,
        output_route=route,
        policies=dict(policies or {}),
        prefix_lists=dict(lists),
        errors=ErrorSink(),
    )
    return guard.evaluate(env).boolean_value


def _unsupported(
    entry: Mapping[str, Any], lists: Mapping[str, Any], match_lists: compilemod.MatchLists
) -> list[str]:
    """The clause's match terms the engine cannot evaluate: match lines the
    collector kept verbatim, community and AS-path lists the snapshot does not
    hold or that hold a line the engine does not evaluate, and prefix lists the
    snapshot does not define."""
    out = list(compilemod._names(entry, "match_unsupported"))
    for key, kind, table in (
        ("match_community_lists", "community-list", match_lists.community),
        ("match_as_path_lists", "as-path-list", match_lists.as_path),
    ):
        for n in compilemod._names(entry, key):
            if n not in table:
                out.append(f"{kind} {n}")
            else:
                out.extend(
                    f"{kind} {n} line {line.seq} ({line.match_type} {line.value!r})"
                    for line in table[n]
                    if not matchlist.line_supported(line, kind)
                )
    out.extend(
        f"prefix-list {n} (undefined)"
        for n in compilemod._names(entry, "match_prefix_lists")
        if n not in lists
    )
    return out


def _first_line(lines: Sequence[Mapping[str, Any]], prefix: str) -> Mapping[str, Any] | None:
    """The prefix-list line that decides for `prefix`. It is the first line in
    sequence order that matches."""
    for line in sorted(lines, key=lambda e: int(e["seq"])):
        if prefixlist._line_matches(line, prefix):
            return line
    return None


def _decided(entry: Mapping[str, Any], action: str, route: Route, lists: Mapping[str, Any]) -> dict[str, Any]:
    """The deciding clause, with the prefix list and line that made it match."""
    matched: dict[str, Any] = {
        "clause_seq": int(entry["seq"]),
        "action": action,
        "prefix_list": None,
        "entry_seq": None,
    }
    for name in compilemod._names(entry, "match_prefix_lists"):
        line = _first_line(lists.get(name) or (), route.prefix)
        if line is not None and str(line["action"]).lower() == "permit":
            matched.update(prefix_list=name, entry_seq=int(line["seq"]))
            break
    return matched


def _clause(entry: Mapping[str, Any], holds: bool, unsupported: list[str]) -> dict[str, Any]:
    return {
        "seq": int(entry["seq"]),
        "action": str(entry["action"]).lower() if entry.get("action") else None,
        "matches": holds,
        "unsupported": unsupported,
    }


def _route_map_clause(
    walk: _Walk,
    entry: Mapping[str, Any],
    seqs: Sequence[int],
    route: Route,
    lists: Any,
    platform: str,
    name: str,
    match_lists: compilemod.MatchLists,
) -> tuple[dict[str, Any], bool, int | None]:
    """Evaluate one route-map clause for the walk. The result is its record,
    whether its match lines hold, and its continue target
    (`compile._continue_target`)."""
    holds = _holds(entry, route, lists, platform, name, match_lists)
    unsupported = _unsupported(entry, lists, match_lists)
    walk.blocked = walk.blocked or bool(unsupported)
    record = _clause(entry, holds, unsupported)
    walk.clauses.append(record)
    target = compilemod._continue_target(entry, seqs, ErrorSink(), f"route-map {name}")
    if holds and entry.get("continues") and entry.get("continue_seq") is not None and target in (None, -1):
        # The continue target is invalid or has no clause. The platform applies
        # its own rule for that fault.
        walk.blocked = True
    return record, holds, target


def _walk_route_map(
    name: str,
    entries: Sequence[Mapping[str, Any]],
    route: Route,
    lists: Any,
    platform: str,
    match_lists: compilemod.MatchLists,
) -> _Walk:
    """An IOS-XE route map (`compile._compile_iosxe_route_map`). Clauses run in
    sequence order, and the first whose match lines hold decides, unless it is
    a permit clause that continues to a later clause. When no clause decides
    after a continue, the continuing clause's permit sets the outcome."""
    walk = _Walk()
    ordered = sorted(entries, key=lambda e: int(e["seq"]))
    seqs = [int(e["seq"]) for e in ordered]
    continued: tuple[Mapping[str, Any], str] | None = None
    index = 0
    while index < len(ordered):
        entry = ordered[index]
        record, holds, target = _route_map_clause(
            walk, entry, seqs, route, lists, platform, name, match_lists
        )
        if not holds:
            index += 1
            continue
        action = str(entry.get("action") or "permit").lower()
        if target not in (None, -1) and action == "permit":
            record["continues_to"] = target
            continued = (entry, action)
            index = seqs.index(int(target))
            continue
        walk.matched = _decided(entry, action, route, lists)
        return walk
    if continued is not None:
        walk.matched = _decided(continued[0], continued[1], route, lists)
    return walk


def _walk_nxos_route_map(
    name: str,
    entries: Sequence[Mapping[str, Any]],
    route: Route,
    lists: Any,
    platform: str,
    match_lists: compilemod.MatchLists,
) -> _Walk:
    """An NX-OS route map (`compile._compile_nxos_route_map`). Each continue
    target starts an interval that runs up to the next target. An interval
    evaluates its clauses in sequence order. A clause that holds returns its
    action from the interval, or deny when its continue target has no clause. A
    clause that holds and continues sets the local default action to its own
    action and calls the target's interval. The call's return value is
    dropped, and the calling interval goes on with its next clause. An interval
    whose clauses run out returns the local default action, which starts as
    reject. The first interval's return is the decision, and when it is the
    local default action, the continuing clause that set it decides."""
    walk = _Walk()
    ordered = sorted(entries, key=lambda e: int(e["seq"]))
    seqs = [int(e["seq"]) for e in ordered]
    starts = {
        target
        for entry in ordered
        if (target := compilemod._continue_target(entry, seqs, ErrorSink(), f"route-map {name}"))
        not in (None, -1)
    }
    intervals: list[list[Mapping[str, Any]]] = []
    for entry in ordered:
        if not intervals or int(entry["seq"]) in starts:
            intervals.append([])
        intervals[-1].append(entry)
    by_start = {int(interval[0]["seq"]): interval for interval in intervals}
    local_default: list[tuple[Mapping[str, Any], str] | None] = [None]

    def run(interval: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], str] | None:
        for entry in interval:
            record, holds, target = _route_map_clause(
                walk, entry, seqs, route, lists, platform, name, match_lists
            )
            if not holds:
                continue
            action = str(entry.get("action") or "permit").lower()
            if target == -1:
                return entry, "deny"
            if target is None:
                return entry, action
            record["continues_to"] = target
            local_default[0] = (entry, action)
            run(by_start[target])
        return local_default[0]

    decided = run(intervals[0])
    if decided is not None:
        walk.matched = _decided(decided[0], decided[1], route, lists)
    return walk


def _walk_rpl(
    name: str,
    entries: Sequence[Mapping[str, Any]],
    route: Route,
    lists: Any,
    platform: str,
    match_lists: compilemod.MatchLists,
    policies: Mapping[str, policymod.Policy],
) -> _Walk:
    """An RPL policy (`compile._compile_rpl`). Statements run in order.
    `continue_seq` chains the branches of one `if`/`elseif`/`else`. Of these
    branches only the first whose guard holds runs. The `else` branch runs
    when no guard holds. The nested entries of a branch (`parent_seq`) run
    inside the branch. The first statement that runs and has a disposition
    decides. The walk stops at a statement that calls another policy."""
    walk = _Walk()
    ordered = sorted(entries, key=lambda e: int(e["seq"]))
    seqs = {int(e["seq"]) for e in ordered}
    children: dict[int | None, list[Mapping[str, Any]]] = {}
    for entry in ordered:
        parent = compilemod._parent(entry)
        children.setdefault(parent if parent in seqs else None, []).append(entry)

    def body(entry: Mapping[str, Any]) -> bool:
        if entry.get("calls_policy"):
            walk.followed = False
            walk.note = (
                f"statement {entry['seq']} calls policy {entry['calls_policy']}; the clause attribution "
                "stops at the call"
            )
            return True
        if block(children.get(int(entry["seq"]), [])):
            return True
        action = str(entry.get("action") or "").lower()
        if action in ("permit", "deny"):
            walk.matched = _decided(entry, action, route, lists)
            return True
        return False

    def block(items: Sequence[Mapping[str, Any]]) -> bool:
        by_seq = {int(e["seq"]): e for e in items}
        consumed: set[int] = set()
        for entry in items:
            if int(entry["seq"]) in consumed:
                continue
            chain = [entry]
            consumed.add(int(entry["seq"]))
            current = entry
            while current.get("continues") and current.get("continue_seq") is not None:
                target = int(current["continue_seq"])
                if target not in by_seq or target in consumed or target <= int(current["seq"]):
                    break
                current = by_seq[target]
                chain.append(current)
                consumed.add(target)
            for branch in chain:
                guarded = compilemod._rpl_guarded(branch)
                holds = (
                    _holds(branch, route, lists, platform, name, match_lists, policies) if guarded else True
                )
                unsupported = _unsupported(branch, lists, match_lists) if guarded else []
                walk.blocked = walk.blocked or bool(unsupported)
                walk.clauses.append(_clause(branch, holds, unsupported))
                if not holds:
                    continue
                if body(branch):
                    return True
                break
        return False

    block(children.get(None, []))
    return walk


def _walk(
    target: _Target,
    route: Route,
    lists: Mapping[str, Any],
    policies: Mapping[str, policymod.Policy] | None = None,
) -> _Walk:
    """The attribution of the evaluated policy, by its kind."""
    match_lists = compilemod.match_lists(target.rows)
    row = next(
        (
            r
            for r in target.rows
            if r["name"] == target.name and str(r.get("kind") or "") not in compilemod.LIST_KINDS
        ),
        None,
    )
    if row is None:
        return _Walk()
    kind = str(row.get("kind") or "").lower()
    entries = list(row.get("entries") or [])
    if kind == "prefix-list":
        line = _first_line(lists.get(str(target.name)) or (), route.prefix)
        if line is None:
            return _Walk()
        return _Walk(
            matched={
                "clause_seq": None,
                "action": str(line["action"]).lower(),
                "prefix_list": target.name,
                "entry_seq": int(line["seq"]),
            }
        )
    if kind in _GAIA_KINDS:
        return _Walk(followed=False, note="Gaia route maps report no clause attribution")
    if not entries:
        return _Walk()
    if kind == "rpl" or str(entries[0].get("kind", "clause")).lower() == "statement":
        return _walk_rpl(
            str(target.name), entries, route, lists, target.platform, match_lists, policies or {}
        )
    if platforms.route_map_flavor(target.platform) == platforms.NXOS:
        return _walk_nxos_route_map(str(target.name), entries, route, lists, target.platform, match_lists)
    return _walk_route_map(str(target.name), entries, route, lists, target.platform, match_lists)


# --- evaluation ----------------------------------------------------------------------------


def _session_asns(session: Mapping[str, Any]) -> bool:
    try:
        int(session["local_asn"])
        int(session["peer_asn"])
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _gap_entries(errors: ErrorSink) -> list[dict[str, Any]]:
    """The ErrorSink entries in the shape that `gap_list` maps to `Gap`. The
    kind of the entry is the code. The kind of a term that the engine cannot
    evaluate is `unsupported`."""
    return [
        {
            **error,
            "code": error["kind"],
            "kind": "unsupported" if error["kind"] in _UNSUPPORTED else error["kind"],
        }
        for error in errors.as_dicts()
    ]


def routing_evaluate_policy(ctx: ToolContext, params: EvaluatePolicyInput) -> str:
    if (params.session_uid is None) == (params.policy_name is None):
        raise ToolError(
            "invalid_argument", "pass exactly one of session_uid or policy_name", field="session_uid"
        )
    route = _route(params.route)
    direction = "in" if params.direction == "import" else "out"
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "routing_evaluate_policy", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = _resolve_device(pinned, params.device)
        compiled_errors, run_errors = ErrorSink(), ErrorSink()
        if params.session_uid is not None:
            target = _session_target(
                pinned, device_uid, params.session_uid.strip(), direction, compiled_errors
            )
        else:
            target = _named_target(pinned, device_uid, str(params.policy_name).strip(), compiled_errors)
        policies, lists = compilemod.compile_policies(target.rows, target.platform, compiled_errors)
        name = target.name
        defined = name is not None and (
            name in policies or (name in lists and (not target.attached or target.kind == "prefix-list"))
        )
        after: Route | None = None
        unknowns = list(target.unknowns)
        if target.session is not None and not _session_asns(target.session):
            run_errors.report(
                "session-asn-not-recorded",
                f"session {params.session_uid} records no local or peer AS, so its session type is unknown",
                params.session_uid,
            )
            decision = "not-evaluated"
        elif target.session is not None:
            after = bestpath.apply_attached_policy(
                route,
                target.session,
                direction=direction,
                platform=target.platform,
                policies=policies,
                prefix_lists=lists,
                errors=run_errors,
            )
            if name is None:
                decision = "no-policy"
                unknowns.append(NO_POLICY_UNKNOWN)
            else:
                decision = ("accept" if after is not None else "reject") if defined else "undefined-policy"
        elif name in policies:
            after = bestpath._run_policy(
                str(name),
                route,
                direction=direction,
                policies=policies,
                prefix_lists=lists,
                errors=run_errors,
                stype=bestpath.EBGP,
                peer_as=None,
            )
            decision = "accept" if after is not None else "reject"
        elif name in lists:
            after = route if prefixlist.evaluate(lists[str(name)], route.prefix) else None
            decision = "accept" if after is not None else "reject"
        else:
            run_errors.report(
                "undefined-policy",
                f"device {device_uid} defines no route policy or prefix list {name!r} in this snapshot",
                name,
            )
            decision = "undefined-policy"
        walk = _walk(target, route, lists, policies) if decision in ("accept", "reject") else _Walk()
        outcome: Literal["accept", "reject"] | None = "accept" if after is not None else "reject"
        if decision == "not-evaluated" or (decision == "undefined-policy" and not target.attached):
            outcome = None
        matched = walk.matched
        if matched is not None and outcome is not None:
            agrees = (matched["action"] == "permit") == (outcome == "accept")
            if not agrees:
                matched = None
                unknowns.append(
                    "the clause the attribution walk ends at disagrees with the engine's decision, so "
                    "matched is left out"
                )
        if walk.note:
            unknowns.append(walk.note)
        doubt = any(e.kind in _DOUBT for e in compiled_errors.errors) or bool(run_errors.errors)
        entries = [*_gap_entries(compiled_errors), *_gap_entries(run_errors)]
        open_on = missing_of(entries) or (
            [
                Missing(
                    code="attribution-not-followed", detail=str(walk.note or "the clause walk did not follow")
                )
            ]
            if walk.blocked or not walk.followed
            else [Missing(code="decision-not-decided", detail="the policy decision is open")]
        )
        if decision in ("accept", "reject"):
            proven = not doubt and not walk.blocked and (walk.followed or not compiled_errors.errors)
            result = (
                from_engine("route-policy-accepts", "holds" if outcome == "accept" else "does-not-hold")
                if proven
                else from_engine("route-policy-accepts", "not-established", missing=open_on)
            )
        elif decision == "no-policy" and not doubt:
            result = decided("route-policy-accepts", "default")
        else:
            result = from_engine("route-policy-accepts", "not-established", missing=open_on)
        evidence = ItemEvidence.of(result, basis="computed")
        gaps, gaps_truncated = gap_list(entries)
        row = next((r for r in target.rows if r["name"] == name), None)
        uid = None if row is None else str(row["uid"])
        kind = target.kind if row is None else str(row["kind"]).lower()
        return call.finish(
            session,
            result={
                "device_uid": device_uid,
                "session_uid": params.session_uid,
                "direction": params.direction,
                "platform": target.platform,
                "route": _route_json(route),
                "policy": {
                    "name": name,
                    "kind": kind,
                    "uid": uid,
                    "attached": target.attached,
                    "defined": defined,
                },
                "decision": decision,
                "outcome": outcome,
                "matched": matched,
                "clauses": walk.clauses[:CLAUSE_CAP],
                "clauses_truncated": len(walk.clauses) > CLAUSE_CAP,
                "rewritten": _rewritten(route, after),
                "evidence": evidence.model_dump(mode="json"),
            },
            evidence=Evidence(
                result=evidence.result,
                unknowns=unknowns,
                gaps=gaps,
                gaps_truncated=gaps_truncated,
            ),
            engine="hst.simul.bestpath",
            engine_function=(
                "hst.simul.bestpath.apply_attached_policy"
                if params.session_uid is not None
                else "hst.simul.bestpath._run_policy"
            ),
            queries=[
                ("fixed", "hst.twin_tools.route_policy._SESSION_QUERY")
                if params.session_uid is not None
                else ("fixed", "hst.twin_tools.route_policy._NAMED_POLICY_QUERY")
            ],
        )


def spec() -> ToolSpec:
    return catalogue_spec(
        name="routing_evaluate_policy",
        description=(
            "Apply a route policy of one device to a candidate route. Name the policy with exactly one "
            "of session_uid (the policy that BGP session attaches in direction) and policy_name (a "
            "route map, RPL policy or prefix list the device defines). decision is accept or reject, "
            "no-policy when the session attaches none in that direction, undefined-policy when the "
            "named policy has no definition in the snapshot, or not-evaluated; outcome is what the "
            "route meets, including the platform's rule for no policy or an undefined one. matched "
            "names the clause that decided, with the prefix list and line that made it match, and "
            "clauses lists the clauses evaluated in order; rewritten is the accepted route with the "
            "attributes the policy changed. Every fault the engine reports is a gap. The decision is "
            "proven only when the policy is defined and every match term evaluated is one the engine "
            "supports."
        ),
        input_model=EvaluatePolicyInput,
        result_model=EvaluatePolicyResult,
        run=routing_evaluate_policy,
    )
