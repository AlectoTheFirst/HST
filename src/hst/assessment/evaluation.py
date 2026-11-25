"""Shared service request parsing, model loading and impact evaluation.

HTTP, analysis workers and tools use the same evaluation semantics.
"""

from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import replace
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field, model_validator

from hst import path as pathmod
from hst.app import fw_overlay_read, simul_read
from hst.core.diff import DETAIL_CAP
from hst.core.labels import DEPENDENCY_GROUP_KINDS
from hst.core.mtu import MtuRequest
from hst.core.mtu_read import read_mtu
from hst.impact.evaluate import (
    ANY_ONE,
    CAPACITY,
    EVERY,
    FAILS,
    HOLDS,
    MEMBER,
    MODES,
    N_OF_M,
    NOT_ESTABLISHED,
    POSSIBLE,
    Answer,
    Condition,
    Explanation,
    GraphGates,
    Impact,
    Interface,
    Member,
    MtuRequirement,
    Network,
    RequestSet,
    Service,
    every,
    member,
    n_of_m,
)
from hst.impact.evaluate import evaluate as evaluate_impact
from hst.path.addrsets import _intervals, _merge, _ports, _protoset, _subtract, _to_cidrs
from hst.path.trace import _exit_basis_words, _exit_key
from hst.simul.errors import ErrorSink
from hst.simul.fw_overlay import ChangeSet, ProposalError, parse_intents

# --- the declared success condition --------
#
# A ServiceRequirement holds the source population (SRC), the logical destination,
# the service and the root DependencyGroup of its success condition. The group
# tree below the root is read one level at a time.

_REQUIREMENT_QUERY = """
MATCH (sr:ServiceRequirement:Obj {uid: $req, collection_ts: $snap})
WHERE NOT sr:Retired
OPTIONAL MATCH (sr)-[s:SRC]->(src)
WHERE s._retired_at IS NULL AND NOT src:Retired
OPTIONAL MATCH (app:BusinessService)-[dep:DEPENDS_ON]->(sr)
WHERE dep._retired_at IS NULL AND NOT app:Retired
OPTIONAL MATCH (sr)-[h:HAS]->(root:DependencyGroup)
WHERE h._retired_at IS NULL AND NOT root:Retired
RETURN sr.uid AS uid, sr.name AS name, sr.destination AS destination,
       sr.proto AS proto, sr.dport AS dport, sr.sport AS sport,
       sr.success AS success, sr.source_context AS source_context,
       sr.source_device_uid AS source_device_uid,
       sr.identity_uid AS identity_uid, sr.segment_uid AS segment_uid, sr.mtu_json AS mtu_json,
       [x IN collect(DISTINCT coalesce(src.cidr, src.ip)) WHERE x IS NOT NULL] AS sources,
       [x IN collect(DISTINCT app.uid) WHERE x IS NOT NULL] AS applications,
       [x IN collect(DISTINCT root.uid) WHERE x IS NOT NULL] AS roots
ORDER BY sr.uid LIMIT 1"""

# The query reads one level of the group tree. It returns the groups named in
# $uids, each with its child groups and its member objects. A member is the object
# at the end of a DEPENDS_ON edge of a group. The uid of the member is its name in
# the answer. Its cidr, ip or vip is the address set that the evaluator walks to.
_GROUP_QUERY = """
MATCH (g:DependencyGroup:Obj)
WHERE NOT g:Retired AND g.collection_ts = $snap AND g.uid IN $uids
OPTIONAL MATCH (g)-[hm:HAS_MEMBER]->(sub:DependencyGroup)
WHERE hm._retired_at IS NULL AND NOT sub:Retired
OPTIONAL MATCH (g)-[dep:DEPENDS_ON]->(t)
WHERE dep._retired_at IS NULL AND NOT t:Retired
RETURN g.uid AS uid, g.kind AS kind, g.n AS n, g.name AS name,
       [x IN collect(DISTINCT sub.uid) WHERE x IS NOT NULL] AS groups,
       [x IN collect(DISTINCT {uid: t.uid, name: t.name,
            address: coalesce(t.cidr, t.ip, t.vip)}) WHERE x.uid IS NOT NULL] AS members
ORDER BY g.uid"""

# The query reads the interfaces of the network model. A row holds the device of
# an interface, its forwarding context, the prefixes it is a gateway for, its
# addresses and the L2 segments it is bound to. The segments include the segments
# that they extend, as the tracer's _IFACE_SEGMENT_QUERY reads them. A routed port
# has no segment. GATEWAY_FOR starts from the interface or from an FhrpGroup that
# the interface is a member of.
_NETWORK_INTERFACES_QUERY = """
MATCH (i:Interface:Obj)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
  AND i.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
OPTIONAL MATCH (i)-[m:MEMBER_OF*0..1]->(gw)-[gf:GATEWAY_FOR]->(p:Prefix)
WHERE gf._retired_at IS NULL AND NOT p:Retired AND NOT gw:Retired
  AND all(r IN m WHERE r._retired_at IS NULL)
OPTIONAL MATCH (i)-[hi:HAS_IP]->(ip:IpAddress)
WHERE hi._retired_at IS NULL AND NOT ip:Retired
WITH d, i, v,
     [x IN collect(DISTINCT p.cidr) WHERE x IS NOT NULL] AS prefixes,
     [x IN collect(DISTINCT ip.ip) WHERE x IS NOT NULL] AS addresses
RETURN d.uid AS device_uid, i.uid AS uid, i.name AS name, v.uid AS context_uid,
       prefixes, addresses,
       i.ipv4_default_origin AS default_origin, d.site_zone AS site_zone,
       COLLECT {
         MATCH (w:WanLink)-[won:ON]->(i)
         WHERE won._retired_at IS NULL AND NOT w:Retired
         WITH w ORDER BY w.uid
         RETURN toLower(coalesce(w.kind, ''))
       } AS link_kinds,
       COLLECT {
         MATCH (i)-[bt:BOUND_TO]->(vl:VlanInstance)-[rz:REALIZES]->(s0)
         WHERE (s0:BridgeDomain OR s0:L2Segment) AND bt._retired_at IS NULL AND rz._retired_at IS NULL
           AND NOT vl:Retired AND NOT s0:Retired
         OPTIONAL MATCH (s0)-[x:EXTENDS*..2]-(s1)
         WHERE (s1:BridgeDomain OR s1:L2Segment) AND NOT s1:Retired
           AND all(r IN x WHERE r._retired_at IS NULL)
         UNWIND [s0.uid, s1.uid] AS segment
         WITH DISTINCT segment WHERE segment IS NOT NULL
         RETURN segment
       } AS segments
ORDER BY d.uid, i.uid"""

# The query reads the routing-domain identities of each forwarding context.
# `Network.same_scope` uses them to decide whether 2 contexts are one routing
# domain, as the tracer's _NEXT_HOP_DOMAIN_QUERY and _NEXT_HOP_CONTEXTS_QUERY do.
# The identities are the RoutingDomains that the VRF declares, the L3Domains that
# the VRF realizes and the resolved domain (`l3dom`) of the addresses of its
# interfaces.
_CONTEXT_DOMAINS_QUERY = """
MATCH (v:VrfInstance:Obj)
WHERE NOT v:Retired AND v.collection_ts = $snap
RETURN v.uid AS uid,
       COLLECT {
         MATCH (v)-[m:MEMBER_OF]->(rd:RoutingDomain)
         WHERE m._retired_at IS NULL AND coalesce(m.basis, 'declared') = 'declared'
           AND NOT rd:Retired AND rd.collection_ts = $snap
         RETURN DISTINCT rd.uid
       } AS declared,
       COLLECT {
         MATCH (v)-[r:REALIZES]->(ld:L3Domain)
         WHERE r._retired_at IS NULL AND NOT ld:Retired AND ld.collection_ts = $snap
         RETURN DISTINCT ld.uid
       } AS realized,
       COLLECT {
         MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)
         WHERE iv._retired_at IS NULL AND h._retired_at IS NULL AND NOT i:Retired AND NOT ip:Retired
           AND ip.collection_ts = $snap AND ip.l3dom IS NOT NULL
         RETURN DISTINCT ip.l3dom
       } AS stamped
ORDER BY uid"""

# The depth bound of group nesting stops a cyclic declaration.
_MAX_GROUP_DEPTH = 16

# A request outside these bounds is a bad request.
MAX_INTENTS = 50
MAX_MEMBERS = 50
MAX_SOURCES = 50
# The evidence list has one explanation per part of the flow space of a member
# per side. EVIDENCE_CAP bounds the listed explanations. `count` is the complete count.
EVIDENCE_CAP = DETAIL_CAP
_DETAIL: ContextVar[bool] = ContextVar("assessment_detail", default=False)

_GROUP_KIND_TO_CONDITION = {
    "and": EVERY,
    "or": ANY_ONE,
    "threshold": N_OF_M,
    "capacity": CAPACITY,
}


# --- POST /api/impact/evaluate ---------------------------------------------


class ConditionBody(BaseModel):
    """One node of an inline success condition. A node is a member by name or a
    group over further conditions. `kind` is `member` or one of the
    DependencyGroup kinds (`and`, `or`, `threshold`, `capacity`). `n` is
    required for a threshold group."""

    kind: str
    member: str | None = None
    n: int | None = None
    parts: list[ConditionBody] = Field(default_factory=list)


class MemberBody(BaseModel):
    """One concrete destination the logical destination resolves to. A member
    with no service of its own uses the request set's."""

    name: str
    addresses: list[str] = Field(min_length=1, max_length=MAX_SOURCES)
    proto: str | None = None
    port: str | None = None
    source_port: str | None = None


class RequestBody(BaseModel):
    """A request set stated inline, for a condition that is not declared in the
    graph. `sources` is the client population. `members` are the destinations
    that the condition is written over."""

    name: str
    destination: str
    # The artifact and read budget bound the CIDRs of a population artifact.
    sources: list[str] = Field(default_factory=list, max_length=1_000_000)
    members: list[MemberBody] = Field(min_length=1, max_length=MAX_MEMBERS)
    condition: ConditionBody
    proto: str | None = None
    port: str | None = None
    source_port: str | None = None
    success: str = "forward"
    source_context: str | None = None
    source_device_uid: str | None = None
    identity_uid: str | None = None
    segment_uid: str | None = None
    ingress_interface_uid: str | None = None
    destination_context: str | None = None
    header_constraints: dict[str, list[tuple[int, int]]] = Field(default_factory=dict, max_length=7)
    mtu: MtuRequest | None = None
    # A selector is bound once at submission and retained with its materialized
    # artifact. Evaluation accepts only the resulting source list.
    population: dict[str, Any] | None = None
    population_artifact: dict[str, Any] | None = None
    population_complete: bool | None = None
    population_gaps: list[str] = Field(default_factory=list, max_length=100)
    population_scope: str | None = None

    @model_validator(mode="after")
    def population_shape(self) -> RequestBody:
        if self.population_artifact is None and len(self.sources) > MAX_SOURCES:
            raise ValueError("Literal request sources are limited to 50 entries.")
        if not self.sources and self.population is None:
            raise ValueError("A request needs literal sources or a population selector.")
        if self.population_artifact is not None and (self.population is None or not self.sources):
            raise ValueError("A population artifact requires its selector and materialized sources.")
        if self.population_artifact is not None and self.population_complete is None:
            raise ValueError("A population artifact requires its saved completeness evidence.")
        if self.population_artifact is not None and not self.population_scope:
            raise ValueError("A population artifact requires its saved qualified scope.")
        if self.sources and self.population is not None and self.population_artifact is None:
            raise ValueError("A request states a population selector or literal sources, not both.")
        return self


class EvaluateBody(BaseModel):
    """A change set and the request set to evaluate it against. Exactly one of
    `requirement` (a declared ServiceRequirement uid) and `request` (an inline
    request set) is given. With an empty change set, the answer states what
    the snapshot alone establishes."""

    intents: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_INTENTS)
    requirement: str | None = None
    request: RequestBody | None = None
    mode: str = POSSIBLE
    snapshot: str | None = None


ConditionBody.model_rebuild()


def _service_of(proto: Any, dport: Any, sport: Any) -> Service:
    """The service dimensions of a request. A dimension that the request does
    not state stays `None`."""
    try:
        # a protocol list is ORed, as `request_document` writes it ('6,17')
        protos = [p.strip() for p in str(proto).split(",")] if proto else []
        if proto and not all(protos):
            raise ValueError(f"empty entry in protocol list: {proto}")
        return Service(
            proto=_protoset(protos) if proto else None,
            dport=tuple(_ports(dport)) if dport else None,
            sport=tuple(_ports(sport)) if sport else None,
        )
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc


def _address_set(specs: Any, what: str) -> tuple[tuple[int, int, int], ...]:
    """An address set from CIDR, range or single-address specs. A spec the
    grammar cannot read is a bad request."""
    texts = [str(s).strip() for s in (specs or ()) if str(s).strip()]
    parsed: list[tuple[int, int, int]] = []
    unreadable: list[str] = []
    for text in texts:
        one = _intervals([text])
        parsed.extend(one)
        if not one:
            unreadable.append(text)
    if unreadable:
        raise HTTPException(
            400, detail=f"{what} names specs the address grammar cannot read: {unreadable[:20]}"
        )
    if not parsed:
        raise HTTPException(400, detail=f"{what} names no address the address grammar can read: {texts}")
    return tuple(_merge(parsed))


def _condition_from_body(body: ConditionBody) -> Condition:
    """An inline condition as the expression of the evaluator. `RequestSet`
    checks the member names of the condition against the request set.

    A group kind is accepted in 2 spellings. One is the DependencyGroup kind
    that a declaration uses. The other is the name that the evaluator uses and
    that the answer returns. A condition from an answer can be posted again
    unchanged.
    """
    kind = str(body.kind or "").strip().lower()
    if kind in ("member", MEMBER):
        if not body.member:
            raise HTTPException(400, detail="a member condition names the member it is about")
        return member(body.member)
    mapped = _GROUP_KIND_TO_CONDITION.get(kind)
    if mapped is None and kind in (EVERY, ANY_ONE, N_OF_M, CAPACITY):
        mapped = kind
    if mapped is None:
        raise HTTPException(
            400,
            detail=(
                f"condition kind {body.kind!r} is not one of member, "
                f"{', '.join(sorted(DEPENDENCY_GROUP_KINDS))}, or the evaluator's own "
                f"{EVERY}, {ANY_ONE}, {N_OF_M}, {CAPACITY}"
            ),
        )
    parts = tuple(_condition_from_body(part) for part in body.parts)
    if not parts:
        raise HTTPException(400, detail=f"a {kind} group needs at least one part")
    if mapped == N_OF_M:
        if body.n is None:
            raise HTTPException(400, detail="a threshold group states n, the number of parts it needs")
        return n_of_m(int(body.n), *parts)
    return Condition(mapped, parts=parts)


def _request_from_body(body: RequestBody) -> RequestSet:
    if not body.sources:
        raise HTTPException(
            422, detail="Bind the population selector to a pinned snapshot before evaluation."
        )
    members = tuple(
        Member(
            m.name,
            _address_set(m.addresses, f"member {m.name!r}"),
            _service_of(m.proto, m.port, m.source_port) if (m.proto or m.port or m.source_port) else None,
        )
        for m in body.members
    )
    try:
        return RequestSet(
            body.name,
            _address_set(body.sources, "sources"),
            body.destination,
            members,
            _condition_from_body(body.condition),
            _service_of(body.proto, body.port, body.source_port),
            success=body.success,
            source_context=body.source_context,
            source_device_uid=body.source_device_uid,
            identity_uid=body.identity_uid,
            segment_uid=body.segment_uid,
            ingress_interface_uid=body.ingress_interface_uid,
            destination_context=body.destination_context,
            header_constraints=tuple(
                (name, tuple(ranges)) for name, ranges in sorted(body.header_constraints.items())
            ),
            mtu=MtuRequirement.from_request(body.mtu) if body.mtu is not None else None,
        )
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc


def _group_tree(session: Any, roots: list[str]) -> dict[str, dict[str, Any]]:
    """Every DependencyGroup reachable from the roots, keyed by uid, read one
    level at a time to a depth of `_MAX_GROUP_DEPTH`. A group is read once."""
    groups: dict[str, dict[str, Any]] = {}
    frontier = sorted({str(u) for u in roots if u})
    for _ in range(_MAX_GROUP_DEPTH):
        pending = [uid for uid in frontier if uid not in groups]
        if not pending:
            break
        rows = pathmod._read(session, _GROUP_QUERY, uids=pending)
        for row in rows:
            groups[str(row["uid"])] = row
        frontier = sorted({str(g) for row in rows for g in (row["groups"] or ())})
    return groups


def _condition_from_graph(
    uid: str,
    groups: dict[str, dict[str, Any]],
    members: dict[str, Member],
    depth: int,
    seen: tuple[str, ...],
) -> Condition:
    """The declared condition rooted at one group, and the members it names.

    The walk fills `members`. A member is the object that a group points at.
    The uid of the object is the name of the member, and 2 groups that point at
    the same object name one member. A group that repeats on the path above it
    is a cyclic declaration and is refused.
    """
    row = groups.get(uid)
    if row is None:
        raise HTTPException(404, detail=f"no dependency group {uid} in this snapshot")
    if uid in seen:
        raise HTTPException(
            400, detail=f"dependency group {uid} is nested inside itself; the declaration is cyclic"
        )
    if depth > _MAX_GROUP_DEPTH:
        raise HTTPException(400, detail=f"the declared condition nests deeper than {_MAX_GROUP_DEPTH} groups")
    kind = str(row["kind"] or "").strip().lower()
    mapped = _GROUP_KIND_TO_CONDITION.get(kind)
    if mapped is None:
        raise HTTPException(
            400,
            detail=(
                f"dependency group {uid} has kind {row['kind']!r}, which is not one of "
                f"{', '.join(sorted(DEPENDENCY_GROUP_KINDS))}"
            ),
        )
    parts: list[Condition] = []
    for entry in sorted(row["members"] or (), key=lambda m: str(m.get("uid"))):
        name = str(entry["uid"])
        if not entry.get("address"):
            raise HTTPException(
                400,
                detail=(
                    f"dependency group {uid} names member {name}, which carries no address in this "
                    "snapshot; the evaluator has no flow space for it"
                ),
            )
        members.setdefault(name, Member(name, _address_set([entry["address"]], f"member {name}")))
        parts.append(member(name))
    for child in sorted(row["groups"] or ()):
        parts.append(_condition_from_graph(str(child), groups, members, depth + 1, (*seen, uid)))
    if not parts:
        raise HTTPException(400, detail=f"dependency group {uid} has no member and no nested group")
    if mapped == N_OF_M:
        if row["n"] is None:
            raise HTTPException(400, detail=f"threshold group {uid} states no n")
        n = int(row["n"])
        if not 1 <= n <= len(parts):
            raise HTTPException(400, detail=f"threshold group {uid} states n={n} over {len(parts)} parts")
        return n_of_m(n, *parts)
    return Condition(mapped, parts=tuple(parts))


def _request_from_requirement(session: Any, uid: str) -> RequestSet:
    """The request set a declared ServiceRequirement states."""
    row = pathmod._read_one(session, _REQUIREMENT_QUERY, req=uid)
    if row is None:
        raise HTTPException(404, detail=f"no service requirement {uid} in this snapshot")
    roots = sorted(str(r) for r in (row["roots"] or ()))
    if not roots:
        raise HTTPException(
            400, detail=f"service requirement {uid} declares no dependency group, so it states no condition"
        )
    groups = _group_tree(session, roots)
    members: dict[str, Member] = {}
    parts = [_condition_from_graph(root, groups, members, 1, ()) for root in roots]
    condition = parts[0] if len(parts) == 1 else every(*parts)
    try:
        return RequestSet(
            str(row["name"] or uid),
            _address_set(row["sources"], f"service requirement {uid} sources"),
            str(row["destination"] or row["name"] or uid),
            tuple(members[name] for name in sorted(members)),
            condition,
            _service_of(row["proto"], row["dport"], row["sport"]),
            success=str(row.get("success") or "forward"),
            source_context=row.get("source_context"),
            source_device_uid=row.get("source_device_uid"),
            identity_uid=row.get("identity_uid"),
            segment_uid=row.get("segment_uid"),
            mtu=MtuRequirement.from_request(MtuRequest.model_validate_json(row["mtu_json"]))
            if row.get("mtu_json") is not None
            else None,
        )
    except ValueError as exc:
        raise HTTPException(400, detail=f"service requirement {uid}: {exc}") from exc


def _model_interfaces(session: Any) -> tuple[Interface, ...]:
    """Every interface of the pinned run as the evaluator's network model."""
    return tuple(
        Interface(
            device_uid=str(row["device_uid"]),
            uid=str(row["uid"]),
            name=str(row["name"] or ""),
            context_uid=str(row["context_uid"]) if row["context_uid"] else None,
            prefixes=tuple(sorted(str(p) for p in (row["prefixes"] or ()))),
            addresses=tuple(sorted(str(a) for a in (row["addresses"] or ()))),
            segments=tuple(sorted(str(x) for x in (row["segments"] or ()))),
            # The kinds of the WAN links on the interface, in WanLink uid order. The
            # uplink rule of the tracer (`Network.estate_prefixes`) reads the first link.
            link_kinds=tuple(str(k) for k in (row.get("link_kinds") or ())),
            default_origin=row.get("default_origin"),
            site_zone=row.get("site_zone"),
        )
        for row in pathmod._read(session, _NETWORK_INTERFACES_QUERY)
    )


def _context_domains(session: Any) -> dict[str, frozenset[str]]:
    """The routing-domain identities of every forwarding context of the run
    (`Network.same_scope`). Each identity has its kind as a prefix. A declared
    domain and a resolved domain of the same name are 2 identities."""
    return {
        str(row["uid"]): frozenset(
            [f"declared:{x}" for x in row["declared"] or ()]
            + [f"l3domain:{x}" for x in row["realized"] or ()]
            + [f"resolved:{x}" for x in row["stamped"] or ()]
        )
        for row in pathmod._read(session, _CONTEXT_DOMAINS_QUERY)
    }


def _contexts_in_scope(interfaces: tuple[Interface, ...], request: RequestSet) -> list[str]:
    """All modeled forwarding contexts, including the contexts of transit and return paths.

    The compiler closes this set over interface-less policy tables and
    control-plane dependencies before it calculates a route.
    """
    return sorted({i.context_uid for i in interfaces if i.context_uid})


def _change_set(session: Any, intents: list[dict[str, Any]], errors: ErrorSink) -> ChangeSet:
    """The caller's change set, parsed against the snapshot's policy objects."""
    catalog = fw_overlay_read.read_catalog(session, intents)
    resolved, _derivations = fw_overlay_read._resolve_intent_rulebases(session, intents, catalog, errors)
    return ChangeSet(intents=parse_intents(resolved, catalog), catalog=catalog, errors=errors)


def _cidrs(ivals: Any) -> list[str]:
    """An address interval set as prefixes, in a fixed order."""
    return sorted(_to_cidrs(list(ivals)))


def _address_bucket(ivals: Any) -> dict[str, Any]:
    """One address set as a detail bucket. The bucket holds the complete count,
    the capped prefixes and the cap flag. `_bucket` gives a row list the same shape."""
    cidrs = _cidrs(ivals)
    return {
        "count": len(cidrs),
        "items": cidrs if _DETAIL.get() else cidrs[:DETAIL_CAP],
        "truncated": not _DETAIL.get() and len(cidrs) > DETAIL_CAP,
    }


# The parts of `Triage` that a report shows, in the order of the report.
_TRIAGE_PARTS = (
    "proven_loss",
    "worked_now_unknown",
    "unknown_now_broken",
    "unknown_throughout",
    "proven_gain",
    "unknown_now_works",
    "broken_now_unknown",
)


def _triage_body(triage: Any) -> dict[str, Any]:
    """Each disjoint part as its own address bucket."""
    return {part: _address_bucket(getattr(triage, part)) for part in _TRIAGE_PARTS}


def _triage_flags(triage: Any) -> dict[str, bool]:
    """Whether one member has anything in each disjoint part."""
    return {part: bool(getattr(triage, part)) for part in _TRIAGE_PARTS}


def _steps(explanation: Explanation) -> list[dict[str, Any]]:
    return [
        {
            "device_uid": step.device_uid,
            "stage": step.stage,
            "kind": step.kind,
            "detail": step.detail,
            "unknown": list(step.unknown),
            **({"evidence_gap": step.data["evidence_gap"]} if "evidence_gap" in step.data else {}),
            **({"mtu": step.data["mtu"]} if "mtu" in step.data else {}),
        }
        for step in explanation.steps
    ]


def _left_estate(explanation: Explanation) -> list[dict[str, Any]]:
    """The distinct `left_estate` markers of the steps of one part, in `_exit_key`
    order. The tracer sets the marker on the step where the walk leaves the
    model at the edge of the estate. The list is empty for a part without a marker."""
    found = {
        _exit_key(exit_): dict(exit_)
        for step in explanation.steps
        if isinstance(exit_ := step.data.get("left_estate"), dict)
    }
    return [found[key] for key in sorted(found)]


def _left_estate_note(exits: list[dict[str, Any]]) -> str:
    """The row's sentence for a part whose path ends at the estate's edge."""
    clauses = []
    for exit_ in exits:
        where = " ".join(
            str(p) for p in (exit_.get("device") or exit_.get("device_uid"), exit_.get("interface")) if p
        )
        hop = f"to next hop {exit_['next_hop']}" if exit_.get("next_hop") else "with no next hop"
        clauses.append(f"{where} {hop} ({_exit_basis_words(exit_)})")
    return "the last hop is outside the estate: " + "; ".join(clauses)


def _evidence(answer: Answer, side: str) -> list[dict[str, Any]]:
    """The explanation of every part of every member, as evidence entries. An
    entry holds the steps that decided the part and, for a part that is not
    established, the missing evidence. The entry of a part whose path ends at
    the edge of the estate also has `left_estate` and the sentence
    `left_estate_note`."""
    out: list[dict[str, Any]] = []
    for name in sorted(answer.members):
        for explanation in answer.members[name].explanations:
            exits = _left_estate(explanation)
            out.append(
                {
                    "side": side,
                    "member": name,
                    "outcome": explanation.outcome,
                    "steps": _steps(explanation),
                    "missing": list(explanation.missing),
                    **({"left_estate": exits, "left_estate_note": _left_estate_note(exits)} if exits else {}),
                    **(
                        {
                            "request_region": {
                                "src": _cidrs(explanation.request.src),
                                "dst": _cidrs(explanation.request.dst),
                                "proto": sorted(explanation.request.proto)
                                if explanation.request.proto is not None
                                else None,
                                "dport": explanation.request.dport,
                                "sport": explanation.request.sport,
                            }
                        }
                        if _DETAIL.get()
                        else {}
                    ),
                }
            )
    return out


def _member_rows(impact: Impact) -> list[dict[str, Any]]:
    """One row per member. A row holds whether the change moved the member in
    each of the 4 directions, and the outcome counts of its parts on each side."""
    rows: list[dict[str, Any]] = []
    for name in sorted(impact.members):
        mi = impact.members[name]
        rows.append(
            {
                "name": name,
                "proven_loss": bool(mi.proven_loss),
                "possible_loss": bool(mi.possible_loss),
                "proven_gain": bool(mi.proven_gain),
                "possible_gain": bool(mi.possible_gain),
                "triage": _triage_flags(mi.triage),
                "before": _outcome_counts(impact.before, name),
                "after": _outcome_counts(impact.after, name),
            }
        )
    return rows


def _outcome_counts(answer: Answer, name: str) -> dict[str, int]:
    counts = {HOLDS: 0, FAILS: 0, NOT_ESTABLISHED: 0}
    for explanation in answer.members[name].explanations:
        counts[explanation.outcome] = counts.get(explanation.outcome, 0) + 1
    return counts


def _condition_body(condition: Condition) -> dict[str, Any]:
    """The evaluated condition as a document. The same expression is evaluated
    on both sides."""
    body: dict[str, Any] = {"kind": condition.kind}
    if condition.member is not None:
        body["member"] = condition.member
    if condition.n is not None:
        body["n"] = condition.n
    if condition.parts:
        body["parts"] = [_condition_body(part) for part in condition.parts]
    return body


def _evaluate_change(
    session: Any,
    *,
    intents: list[dict[str, Any]],
    requirement: str | None = None,
    request: RequestSet | None = None,
    mode: str = POSSIBLE,
    rib_source: Any | None = None,
    bgp_source: Any | None = None,
    ospf_source: Any | None = None,
    network: Network | None = None,
) -> dict[str, Any]:
    """The three outcomes of one change set against one request set.

    The session must already be pinned (`path.pinned`). The model is read once.
    It holds the interfaces of the run, the input of the routing calculation
    for the modeled forwarding contexts, and the gates of the tracer over the
    same session. The change set reaches the routing calculation through
    `rib.apply_intents` and the gates through the overlay hook, both inside
    `hst.impact.evaluate`.

    The answer has 3 parts over the client population of the request set.

    - `proven` holds what the evidence proves the change costs (`loss`) or
      adds (`gain`). The loss is the lower bound before minus the upper bound
      after. The gain is the lower bound after minus the upper bound before.
    - `possible` holds what the evidence does not rule out. It contains
      `proven`.
    - `not_established` holds the clients whose outcome the evidence does not
      settle on each side. It is the upper bound minus the lower bound. It is
      a third outcome beside holds and does not hold.

    `evidence` has one entry per part of the flow space of each member per
    side. An entry holds the steps that decided the part and, for a part that
    is not established, the missing evidence.

    The optional side-store readers must be bound to the same snapshot as the
    pinned session. Without them the evaluation reads the graph only.
    """
    if mode not in MODES:
        raise HTTPException(400, detail=f"mode must be one of {', '.join(MODES)}")
    if requirement is not None and request is not None:
        raise HTTPException(
            400, detail="state a requirement (a ServiceRequirement uid) or an inline request set, not both"
        )
    if requirement is not None:
        evaluated = _request_from_requirement(session, requirement)
    elif request is not None:
        evaluated = request
    else:
        raise HTTPException(
            400, detail="state either a requirement (a ServiceRequirement uid) or an inline request set"
        )

    errors = ErrorSink()
    try:
        delta = _change_set(session, intents, errors)
    except ProposalError as exc:
        raise HTTPException(400, detail=str(exc)) from exc

    if network is None:
        network = load_network(
            session,
            evaluated,
            rib_source=rib_source,
            bgp_source=bgp_source,
            ospf_source=ospf_source,
            errors=errors,
        )
    contexts = _contexts_in_scope(network.interfaces, evaluated)

    impact = evaluate_impact(network, delta, evaluated, mode)
    if any(e.get("kind") == "zone-move-not-resolvable" for e in errors.as_dicts()):
        raise HTTPException(
            422,
            detail="a zone-membership change in this change set could not be resolved to a zone "
            "pair, so the after side cannot be evaluated",
        )
    before, after = impact.before, impact.after

    evidence = _evidence(before, "before") + _evidence(after, "after")
    missing = sorted({m for entry in evidence for m in entry["missing"]})
    return {
        **({"outcomes": {"before": outcome(before), "after": outcome(after)}} if _DETAIL.get() else {}),
        "mode": impact.mode,
        "assumptions": sorted(set(before.assumptions) | set(after.assumptions)),
        "request": {
            "name": evaluated.name,
            "destination": evaluated.destination,
            "sources": _address_bucket(evaluated.sources),
            "members": [{"name": m.name, "addresses": _cidrs(m.addresses)} for m in evaluated.members],
            "condition": _condition_body(evaluated.condition),
            "requirement": requirement,
            "success": evaluated.success,
            "source_context": evaluated.source_context,
            "source_device_uid": evaluated.source_device_uid,
            "identity_uid": evaluated.identity_uid,
            "segment_uid": evaluated.segment_uid,
            **({"mtu": evaluated.mtu.as_request().model_dump(mode="json")} if evaluated.mtu else {}),
        },
        "intents": [i.as_dict() for i in delta.intents],
        "contexts_in_scope": contexts,
        "proven": {
            "loss": _address_bucket(impact.proven_loss),
            "gain": _address_bucket(impact.proven_gain),
        },
        "possible": {
            "loss": _address_bucket(impact.possible_loss),
            "gain": _address_bucket(impact.possible_gain),
        },
        "not_established": {
            "before": _address_bucket(_subtract(list(before.upper), list(before.lower))),
            "after": _address_bucket(_subtract(list(after.upper), list(after.lower))),
        },
        # `triage` holds the same comparison as `proven` and `possible` in parts
        # that do not overlap. `proven.loss` is inside `possible.loss`.
        "triage": _triage_body(impact.triage),
        "condition_holds": {
            "before": _address_bucket(before.lower),
            "after": _address_bucket(after.lower),
        },
        # `condition_fails` is the source population minus the upper bound.
        # `condition_holds` (the lower bound), `not_established` (the upper bound
        # minus the lower bound) and `condition_fails` partition the sources.
        "condition_fails": {
            "before": _address_bucket(_subtract(list(evaluated.sources), list(before.upper))),
            "after": _address_bucket(_subtract(list(evaluated.sources), list(after.upper))),
        },
        "members": _member_rows(impact),
        "evidence": {
            "count": len(evidence),
            "items": evidence if _DETAIL.get() else evidence[:EVIDENCE_CAP],
            "truncated": not _DETAIL.get() and len(evidence) > EVIDENCE_CAP,
        },
        "missing_evidence": missing,
        "gaps": [dict(g) for g in after.gaps],
        "model_errors": errors.as_dicts() + [dict(e) for e in after.model_errors],
    }


def load_network(
    session: Any,
    request: RequestSet,
    *,
    rib_source: Any = None,
    bgp_source: Any = None,
    ospf_source: Any = None,
    errors: ErrorSink | None = None,
    checkpoint: Callable[[], bool | None] | None = None,
) -> Network:
    """Read the interfaces and the routing inputs once and return the `Network`.

    Each candidate change set is evaluated as its own overlay on this network.
    `checkpoint` returns False when the time of the caller is spent. The walk
    and the routing calculation then stop and report it (`Network.checkpoint`)."""
    interfaces = _model_interfaces(session)
    if request.mtu is not None and request.mtu.mode != "off":
        evidence = read_mtu(session, (interface.uid for interface in interfaces))
        interfaces = tuple(
            replace(
                interface,
                mtu_observations_json=tuple(
                    obs.model_dump_json() for obs in evidence.by_subject.get(interface.uid, ())
                ),
            )
            for interface in interfaces
        )
    graph_input = simul_read.read_rib_input(
        session,
        contexts=_contexts_in_scope(interfaces, request),
        rib_source=rib_source,
        bgp_source=bgp_source,
        ospf_source=ospf_source,
    )
    if errors is not None:
        for err in graph_input.errors.as_dicts():
            errors.report(str(err["kind"]), str(err["detail"]), err.get("subject"))
    return Network(
        graph_input.input,
        interfaces,
        GraphGates(session),
        checkpoint=checkpoint,
        context_domains=_context_domains(session),
    )


def outcome(answer: Answer) -> dict[str, Any]:
    """The verdict of the whole request, the `isolated` flag and the sources
    that hold, fail and are unknown, from the bounds of the answer."""
    sources = list(answer.request_set.sources)
    failed = _subtract(sources, list(answer.upper))
    unknown = _subtract(list(answer.upper), list(answer.lower))
    verdict = FAILS if failed else NOT_ESTABLISHED if unknown else HOLDS
    result = {
        "verdict": verdict,
        "isolated": not bool(answer.upper),
        "holds": _cidrs(answer.lower),
        "fails": _cidrs(failed),
        "unknown": _cidrs(unknown),
    }
    if answer.request_set.unpaired_sources:
        # The unpaired sources are the clients of an address family that no member
        # has. The answer leaves them out.
        result["unpaired"] = _cidrs(list(answer.request_set.unpaired_sources))
    return result


def evaluate_change(session: Any, *, detail: bool = False, **kwargs: Any) -> dict[str, Any]:
    """Evaluate with `_evaluate_change`. With `detail`, the result holds the
    complete lists and the `outcomes` of both sides."""
    token = _DETAIL.set(detail)
    try:
        return _evaluate_change(session, **kwargs)
    finally:
        _DETAIL.reset(token)
