"""The before-and-after impact evaluator.

The impact calculation takes a set of logical connection requests Q and a
network model N. Reach(N) is the requests of Q that satisfy their declared
success condition under N. For a change delta, with N1 = Apply(N0, delta), the
2 differences are

    Lost   = Reach(N0) minus Reach(N1)
    Gained = Reach(N1) minus Reach(N0)

A missing observation widens the answer into bounds:

    lower  is a subset of  Reach(actual)  is a subset of  upper

The lower set holds the requests that the evidence proves. The upper set holds
every request that the evidence does not rule out. The losses are

    proven loss   = lower(before) minus upper(after)
    possible loss = upper(before) minus lower(after)

The gains are defined in the same way. This module implements those
definitions over the symbolic flow state of `hst.path.state` and the routing
calculation of `hst.simul.rib`.

A request set (`RequestSet`) is a source population, a logical destination
resolved to named members (each an address set and a service) and a success
condition. The success condition is a composable expression (`every`,
`any_one`, `n_of_m`, nested to any depth) over the members. At the level of
the request set, a request is identified by its client. At the level of a
member, a request is a rectangle of the flow space of that member, in the terms
of the caller, also after a translation on the path.

`answer(N, Q, mode)` walks the flow region of every member through the
network. The walk starts at the interface that the source population is
attached to. Per device it passes the destination NAT stage, the addresses of
the device (a load balancer VIP or a flow that ends on the device), policy
routing, the longest-prefix match over the compiled FIB, the filter, the source
NAT stage and the next hop. The walk ends when the flow is forwarded onto the
segment that serves its destination. Every stage is a `Transition` over a
`FlowRegion`. The effect of a stage on each output decides the part of the
request that the output answers for.

  - A permit, a rewrite, a pass and a selection continue the walk.
  - A deny, a discard route and no route are proven failures.
  - An `indeterminate` effect, or an effect whose `unknown` holds a dimension
    that the decision could not read, ends the walk with `not-established`.
    The part stays in the upper set and does not enter the lower set.
  - A step that the model has nothing for is also `not-established`. Such
    steps are a source that no interface serves, a context that the routing
    calculation did not cover or whose inputs are incomplete, a next hop that
    no interface in the model holds, a policy-routing rule, and a route with
    an interface and no next hop. A missing transition does not remove a
    request from the upper set.

The request identity survives a translation. The walk maps every output back
onto the request. A dimension that no rewrite has touched is narrowed exactly
as the gate narrowed it. A rewritten dimension keeps the value of the request.
A later decision that splits a rewritten dimension (part of a translated pool
permitted, the rest denied) is `not-established` for the whole part. A changed
backend selection is the same request.

With an explicit independent-choice assumption, the 2 modes define how the
successors of a relation combine. A routing decision with more than one
equal-cost route, a load balancer with more than one member and a source
prefix served by more than one interface each produce more than one successor
state from one input. In `possible` mode a part of the request holds when some
successor proves it, and fails when every successor fails it. In `guaranteed`
mode a part holds when every successor proves it, and fails when any successor
fails it. A comparison holds the mode and the request set fixed on both sides.

By default choice correlations are unspecified. A mixture of successful and
failed successors is then unknown in both modes.

`apply(N0, delta)` is the change. The routing intents of a `ChangeSet` go
through `rib.apply_intents`, and the calculation runs again on the changed
input. The firewall, NAT and zone intents reach the gates through the `overlay`
hook that `path.session._read` offers the tracer.

The interfaces are ordered by device and uid, the attachments by prefix length,
the routes as the FIB sorts them and the successors in the order in which the
gate produced them. An order-sensitive routing selection supports no proof.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from functools import cached_property
from itertools import pairwise
from typing import Any, Protocol

import hst.path as pathmod
from hst.core.mtu import MtuContext, MtuCoverage, MtuObservation, MtuRequest, MtuStage
from hst.core.mtu_read import resolve_constraints
from hst.path.addrsets import _PROTO_NUM, _intersect, _intervals, _merge, _subtract
from hst.path.gates.aci_symbolic import AciTransition
from hst.path.gates.coverage import (
    CreditedTransition,
    ImpactStage,
    _effect_credits,
    stage_gate_credits,
    strict_gate_coverage,
)
from hst.path.gates.firewall import (
    _DEVICE_STATE_POLICY_QUERY,
    _RULEBASE_RULES,
    FirewallTransition,
    _device_rulebase_verdict,
    _read_device_filter_view,
    _region_of,
    _rule_intervals_status,
    _unknown_dims,
)
from hst.path.gates.lb import LbTransition, _vip_bindings
from hst.path.gates.local_zone import LocalZoneTransition
from hst.path.gates.nat import (
    NatTransition,
    _iface_nat_role,
    _nat_rows,
    _nat_stage_rules,
    nat_rulebase_credits,
)
from hst.path.gates.routing import RoutingTransition
from hst.path.gates.tunnel import TunnelLeg, carrier_legs
from hst.path.gates.zpa import ZpaTransition
from hst.path.mtu import evaluate_stage
from hst.path.mtu_feedback import request_for_connection
from hst.path.state import DIMS, Effect, FlowRegion, Ivals, Rect, Transition, port_spec, proto_spec
from hst.path.verdict import DENY, INDETERMINATE, classify_action
from hst.simul import certainty, rib
from hst.simul.errors import ErrorSink
from hst.simul.fw_overlay import ZONE_OF_INTERFACE, ZONE_PAIR_RULEBASES, ChangeSet
from hst.simul.proof import affected_contexts

from .gaps import gap_from_effect, gap_from_step

# outcomes and modes

# The 3 outcomes. `not-established` is an outcome of its own and does not count
# as a failure.
HOLDS = "holds"
FAILS = "does-not-hold"
NOT_ESTABLISHED = "not-established"
# A member, or a whole condition, that has no address in a client's address
# family. Such a client is left out of the question.
NOT_APPLICABLE = "not-applicable"

POSSIBLE = "possible"
GUARANTEED = "guaranteed"
MODES: tuple[str, ...] = (POSSIBLE, GUARANTEED)
# The assumption that every answer states about the choices of a network. Flows
# spread over equal-cost paths and load balancer members by a hash that the
# snapshot does not record. The traffic takes every alternative, and the mode
# quantifies over the alternatives. The device that owns an address is not such
# a choice. A mix of owners is missing data and stays not established.
SPREAD_ASSUMPTION = (
    "flows spread over the equal-cost paths and the load balancer members; the selection on each "
    "device and for each connection is independent"
)

# The maximum device visits of one source rectangle's walk, across all its branches.
MAX_WALK_VISITS = 256

# Routing model errors under which no routing decision of the run is an
# answer.
_UNSETTLED = frozenset({"no-routing-fixed-point", "no-rib-fixed-point"})
# The routing result's gaps that leave a context's decisions open (`Network.incomplete`).
_OPEN_GAPS = frozenset(
    {rib.HISTORY_DEPENDENT, rib.NOT_OBSERVED, certainty.UNIQUENESS, certainty.EXTERNAL_RESPONSE}
)
# The coverage values of a context with no collected routing table
# (`Network.unobserved`). `core.ribsource.DeviceEvidence` lists the values of a
# device. `app.simul_read` sets `ambiguous-device` for a context that spans devices.
_UNOBSERVED_COVERAGE = frozenset({None, "unsupported", "ambiguous-device"})
# The model error of a context that spans devices (`app.simul_read`).
_UNOBSERVED_ERROR = "context-observation-ambiguous"
# The mark `apply` leaves on an overlay whose routing is its observed
# baseline's (`Network._routing_as_observed`). `dataclasses.replace` never copies it.
_ROUTING_AS_OBSERVED = "_routing_as_observed_mark"

# The name of each protocol number that the point path compares. It is the
# first name that `addrsets._PROTO_NUM` lists for the number.
_PROTO_NAME: dict[int, str] = {}
for _name, _number in _PROTO_NUM.items():
    _PROTO_NAME.setdefault(_number, _name)


# the request set


@dataclass(frozen=True)
class Service:
    """The service dimensions of a request. A dimension is `None` where the
    request states nothing about it (as in `hst.path.state`)."""

    proto: frozenset[int] | None = None
    dport: Ivals | None = None
    sport: Ivals | None = None


@dataclass(frozen=True)
class Member:
    """One concrete destination the logical destination resolves to. A
    member with no service of its own uses the request set's."""

    name: str
    addresses: Ivals
    service: Service | None = None


MEMBER = "member"
EVERY = "every"
ANY_ONE = "any-one"
N_OF_M = "n-of-m"
# A capacity requirement, declared over the members whose headroom it is about.
# It evaluates to `not-established` for every client.
CAPACITY = "capacity"


@dataclass(frozen=True)
class Condition:
    """The success condition as plain data. A condition is a member by name or
    a group of conditions. A group holds when every part holds, when any one
    part holds or when at least `n` parts hold. A capacity group stays
    not-established. Groups nest to any depth. The graph labels
    `ServiceRequirement` and `DependencyGroup` hold a declared condition, and
    it evaluates to this expression."""

    kind: str
    member: str | None = None
    n: int | None = None
    parts: tuple[Condition, ...] = ()

    def names(self) -> frozenset[str]:
        """Every member the condition refers to."""
        if self.kind == MEMBER:
            return frozenset({self.member}) if self.member is not None else frozenset()
        out: frozenset[str] = frozenset()
        for part in self.parts:
            out = out | part.names()
        return out


def member(name: str) -> Condition:
    return Condition(MEMBER, member=name)


def every(*parts: Condition) -> Condition:
    return Condition(EVERY, parts=tuple(parts))


def any_one(*parts: Condition) -> Condition:
    return Condition(ANY_ONE, parts=tuple(parts))


def n_of_m(n: int, *parts: Condition) -> Condition:
    return Condition(N_OF_M, n=n, parts=tuple(parts))


def capacity(*parts: Condition) -> Condition:
    return Condition(CAPACITY, parts=tuple(parts))


def _families(ivals: Iterable[tuple[int, int, int]]) -> set[int]:
    return {iv[0] for iv in ivals}


def _applies(condition: Condition, families: Mapping[str, set[int]], family: int) -> bool:
    """Whether some member the condition names has an address in `family`."""
    if condition.kind == MEMBER:
        return family in families.get(str(condition.member), set())
    return any(_applies(part, families, family) for part in condition.parts)


def _check_condition(condition: Condition, names: set[str]) -> None:
    if condition.kind == MEMBER:
        if condition.member is None or condition.member not in names:
            raise ValueError(
                f"the success condition names member {condition.member!r}, which the request set lacks"
            )
        return
    if condition.kind not in (EVERY, ANY_ONE, N_OF_M, CAPACITY):
        raise ValueError(f"unknown condition kind {condition.kind!r}")
    if not condition.parts:
        raise ValueError(f"a {condition.kind} group needs at least one part")
    if condition.kind == N_OF_M and (condition.n is None or not 1 <= condition.n <= len(condition.parts)):
        raise ValueError(
            f"an n-of-m group over {len(condition.parts)} parts needs n between 1 and that count"
        )
    for part in condition.parts:
        _check_condition(part, names)


@dataclass(frozen=True)
class MtuRequirement:
    """Immutable request identity for saved and counterfactual evaluations."""

    mode: str = "off"
    ip_packet_bytes: int | None = None
    ipv4_df: bool | None = None
    reply_ip_packet_bytes: int | None = None
    traffic_class: str | None = None

    def __post_init__(self) -> None:
        self.as_request()

    @classmethod
    def from_request(cls, request: MtuRequest) -> MtuRequirement:
        return cls(**request.model_dump())

    def as_request(self) -> MtuRequest:
        return MtuRequest.model_validate(asdict(self))


def _mtu_projection_gap(subject: str | None = None) -> dict[str, Any]:
    return {
        "code": "MTU_PATH_COVERAGE_INCOMPLETE",
        "kind": "not-modeled",
        "dimension": "mtu",
        "subject": subject,
        "detail": "Assessment routing projects local IP egress limits; physical members, receive limits, "
        "endpoints, encapsulation and proxy packet sizes do not have complete MTU coverage.",
        "producer": {"stage": "mtu", "kind": "projection-incomplete"},
        "recipe_id": None,
    }


@dataclass(frozen=True)
class RequestSet:
    """A set of logical connection requests Q. It holds a source population, a
    logical destination (named, resolved to `members`), the service and the
    success condition over the members.

    Sources and members may each be dual-stack. A client is paired only with
    member addresses of its own family. `sources` keeps the clients whose
    family the condition applies to. `unpaired_sources` keeps the rest, and
    the answer leaves them out. At least one family must pair."""

    name: str
    sources: Ivals
    destination: str
    members: tuple[Member, ...]
    condition: Condition
    service: Service = Service()
    success: str = "forward"
    source_context: str | None = None
    identity_uid: str | None = None
    segment_uid: str | None = None
    source_device_uid: str | None = None
    # An external population enters at an explicitly declared ingress.
    ingress_interface_uid: str | None = None
    destination_context: str | None = None
    mtu: MtuRequirement | None = None
    header_constraints: tuple[tuple[str, tuple[tuple[int, int], ...]], ...] = ()
    unpaired_sources: Ivals = ()

    def __post_init__(self) -> None:
        widths = {
            "tcp_flags": 8,
            "icmp_type": 8,
            "icmp_code": 8,
            "dscp": 6,
            "ecn": 2,
            "fragment_offset": 13,
            "more_fragments": 1,
        }
        if len({name for name, _ in self.header_constraints}) != len(self.header_constraints):
            raise ValueError("duplicate header constraint")
        normalized = []
        for name, ranges in self.header_constraints:
            if name not in widths or not 1 <= len(ranges) <= 32:
                raise ValueError("unsupported or unbounded header constraint")
            if any(
                type(low) is not int or type(high) is not int or not 0 <= low <= high < 2 ** widths[name]
                for low, high in ranges
            ):
                raise ValueError("invalid header constraint range")
            normalized.append((name, tuple(sorted({tuple(pair) for pair in ranges}))))
        object.__setattr__(self, "header_constraints", tuple(sorted(normalized)))
        if self.ingress_interface_uid and (self.source_device_uid or self.segment_uid):
            raise ValueError("explicit ingress cannot also be device-originated or brokered")
        if self.success not in {"forward", "round-trip", "session"}:
            raise ValueError("success must be forward, round-trip or session")
        if self.segment_uid and not self.identity_uid:
            raise ValueError("brokered access requires an identity and a segment")
        if self.segment_uid and self.source_device_uid:
            raise ValueError("brokered access selects its originating device through the connector")
        if not self.sources:
            raise ValueError("a request set names at least one source address")
        if not self.members:
            raise ValueError("a request set resolves its destination to at least one member")
        names = [m.name for m in self.members]
        if len(set(names)) != len(names):
            raise ValueError("member names are unique within a request set")
        for m in self.members:
            if not m.addresses:
                raise ValueError(f"member {m.name!r} names at least one address")
            if self.success == "session":
                protocols = (m.service or self.service).proto
                if not protocols or not protocols <= {6, 17}:
                    raise ValueError("session success requires an explicit TCP or UDP service")
        _check_condition(self.condition, set(names))
        member_families = {m.name: _families(m.addresses) for m in self.members}
        sources = tuple(self.sources) + tuple(self.unpaired_sources)
        paired = {f for f in _families(sources) if _applies(self.condition, member_families, f)}
        if not paired:
            raise ValueError(
                "no source shares an address family with the members the condition names; "
                "an IPv4 host and an IPv6 host never connect directly"
            )
        object.__setattr__(self, "sources", tuple(iv for iv in sources if iv[0] in paired))
        object.__setattr__(self, "unpaired_sources", tuple(iv for iv in sources if iv[0] not in paired))
        if self.mtu is not None:
            request = self.mtu.as_request()
            if 4 in paired:
                request.validate_af(4)
            if 6 in paired:
                request.model_copy(update={"ipv4_df": None}).validate_af(6)

    def member_region(self, m: Member) -> FlowRegion:
        """The flow region of the requests of one member, from the source
        population to the addresses of the member over its service."""
        if self.header_constraints:
            raise ValueError("explicit packet header constraints require the symbolic analysis engine")
        service = m.service or self.service
        region = FlowRegion()
        for family in sorted(_families(self.sources) & _families(m.addresses)):
            region = region.union(
                FlowRegion.from_query(
                    [iv for iv in self.sources if iv[0] == family],
                    [iv for iv in m.addresses if iv[0] == family],
                    service.proto,
                    service.dport,
                    service.sport,
                )
            )
        return region


# the network model


@dataclass(frozen=True)
class Interface:
    """One interface with its device, its forwarding context, the connected
    prefixes it serves (GATEWAY_FOR in the graph) and the addresses it holds
    (HAS_IP). The source population enters the network on the interface that
    serves its prefix. A next hop is followed to the interface that holds it.
    A destination inside a served prefix is forwarded onto that segment."""

    device_uid: str
    uid: str
    name: str
    context_uid: str | None = None
    prefixes: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    mtu_observations_json: tuple[str, ...] = ()
    # The L2 segments that the interface is bound to (bridge domains and
    # layer-2 segments, with the segments that they extend). Empty for a routed
    # port.
    segments: tuple[str, ...] = ()
    # The facts that make the interface an edge by the rule of the tracer
    # (`path.trace._uplink_interface`). They are the kinds of the WAN links on
    # it, the default mark of the access client and the site zone of its device.
    link_kinds: tuple[str, ...] = ()
    default_origin: str | None = None
    site_zone: str | None = None


class Gates(Protocol):
    """The gate transitions of every device. `GraphGates` reads them from the
    pinned graph. Each factory returns a transition over `FlowRegion`. For a
    device with no stage of that kind, the transition passes the region
    unchanged. For a stage whose rules cannot be read, the transition is
    `indeterminate`."""

    def dnat(self, device_uid: str, in_if: Interface | None) -> Transition: ...

    def filter(self, device_uid: str, in_if: Interface | None, out_if: Interface | None) -> Transition: ...

    def snat(self, device_uid: str, in_if: Interface | None, out_if: Interface | None) -> Transition: ...

    def local_filter(self, device_uid: str, in_if: Interface | None) -> Transition: ...

    def load_balancer(self, device_uid: str, address: str) -> Transition | None: ...

    def with_changes(self, changes: ChangeSet) -> Gates: ...


class _OverlaySession:
    """A session whose reads return with a change set applied.
    `path.session._read` calls the `overlay` hook on every read. The overlay
    of a wrapped session that has one is applied first.

    This session installs the 2 lookups of a zone move (`ChangeSet.zone_of`
    and `pair_rows`). Under `_depth`, those 2 reads see the graph as
    collected, with only the inner overlay applied. The reads share the cache
    of the inner session.
    """

    def __init__(self, session: Any, changes: ChangeSet) -> None:
        self._session = session
        self._changes = changes
        self._inner = getattr(session, "overlay", None)
        self._depth = 0
        self._zone_cache: dict[str, str | None] = {}
        cts = getattr(session, "cts", None)
        if cts is not None:
            self.cts = cts
        self.snapshot = getattr(session, "snapshot", None)
        changes.zone_of = self._zone_of
        changes.pair_rows = self._pair_rows

    def execute_read(self, work: Any, /) -> Any:
        return self._session.execute_read(work)

    @property
    def _read_cache(self) -> dict[Any, Any] | None:
        """The read cache of the inner session. `path.session._read` stores raw
        rows below the overlay, and this session shares them with the session
        it wraps."""
        return getattr(self._session, "_read_cache", None)

    def overlay(self, query: str, params: dict[str, Any], rows: Any) -> Any:
        if self._inner is not None:
            rows = self._inner(query, params, rows)
        return rows if self._depth else self._changes.rewrite(query, params, rows)

    def _raw(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self._depth += 1
        try:
            return list(pathmod._read(self, query, **params))
        finally:
            self._depth -= 1

    def _zone_of(self, interface: str) -> str | None:
        if interface not in self._zone_cache:
            rows = self._raw(ZONE_OF_INTERFACE, iface=interface)
            self._zone_cache[interface] = str(rows[0]["uid"]) if rows else None
        return self._zone_cache[interface]

    def _pair_rows(self, src: str, dst: str) -> list[dict[str, Any]]:
        return self._raw(ZONE_PAIR_RULEBASES, src=src, dst=dst)


@dataclass(frozen=True)
class _LocalFilter:
    """Router-local chains and interface ACLs over all service dimensions.

    Each applicable rulebase partitions the surviving region. The input
    chain and ingress ACL must both admit the packet.
    """

    session: Any
    device_uid: str
    in_if: str
    out_if: str | None = None
    chain: str = "input"
    conn_state: str = "new"
    acl_only: bool = False
    # the interface-ACL binding this filter judges (`_device_rulebase_verdict`)
    acl_direction: str | None = None
    # the router-local read, where an interface ACL that records its chain
    # is not a candidate (`_device_rulebase_verdict` `local_acls`)
    local: bool = False
    considered: list[str] = field(default_factory=list, compare=False)

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        out: list[tuple[FlowRegion, Effect]] = []
        pending = list(region)
        pools = [] if self.acl_only else [(self.chain, False)]
        pools.append(("forward", True))
        for chain, acl_only in pools:
            admitted: list[Rect] = []
            for rect in pending:
                verdict = _device_rulebase_verdict(
                    self.session,
                    self.device_uid,
                    self.in_if,
                    self.out_if,
                    list(rect.src),
                    list(rect.dst),
                    port_spec(rect.dport),
                    # the protocol set of the rectangle (`proto_spec`)
                    proto_spec(rect.proto),
                    rect.af,
                    chain=chain,
                    considered=self.considered,
                    conn_state=self.conn_state,
                    src_port=port_spec(rect.sport),
                    only_interface_acls=acl_only,
                    strict_local=not acl_only and self.chain in {"input", "output"},
                    has_egress=self.out_if is not None,
                    acl_direction=self.acl_direction,
                    local_acls=acl_only and self.local,
                )
                if verdict is None:
                    admitted.append(rect)
                    continue
                for item in verdict if isinstance(verdict, list) else [verdict]:
                    self.considered.extend(_effect_credits(item))
                    outcome = classify_action(item.get("action"))
                    reason = item.get("indeterminate_reason")
                    if item.get("partial"):
                        outcome = INDETERMINATE
                        reason = "the access rule covers only part of the packet address region"
                    part = _region_of(rect, item)
                    if outcome not in (DENY, INDETERMINATE):
                        admitted.append(part)
                    else:
                        out.append(
                            (
                                FlowRegion.single(part),
                                Effect(
                                    outcome,
                                    "firewall",
                                    terminal=outcome == DENY,
                                    unknown=_unknown_dims(reason)
                                    if outcome == INDETERMINATE
                                    else frozenset(),
                                    reason=reason,
                                    data=item,
                                ),
                            )
                        )
            pending = admitted
        if not self.acl_only and pending:
            zone = LocalZoneTransition(
                self.session, self.device_uid, self.in_if, self.out_if, self.chain, self.conn_state
            )
            out.extend(zone.apply(FlowRegion(tuple(pending))))
            self.considered.extend(zone.considered)
        else:
            out.extend((FlowRegion.single(r), Effect("permit", "firewall")) for r in pending)
        return out


@dataclass(frozen=True)
class _AddressFilter:
    """Refine address predicates before accepting a scalar policy verdict.

    Re-evaluating each disjoint atom preserves first-match order, negation
    and independent rulebases. Opaque predicates keep their unknown result.
    """

    session: Any
    transition: Transition
    cap: int = 512

    @property
    def considered(self) -> list[str]:
        """The gate uids that the wrapped filter read or ruled out. An
        interface ACL that the filter stage handed to the egress stage stays
        credited through them."""
        return list(getattr(self.transition, "considered", ()))

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        pending = list(region)
        out: list[tuple[FlowRegion, Effect]] = []
        evaluated = 0
        while pending:
            rect = pending.pop(0)
            decided = self.transition.apply(FlowRegion.single(rect))
            rulebases = {
                str(effect.data["rb_uid"])
                for _part, effect in decided
                if effect.data.get("partial") and effect.data.get("rb_uid")
            }
            atoms = [rect]
            for uid in sorted(rulebases):
                for rule in pathmod._read(self.session, _RULEBASE_RULES, rb=uid):
                    for dim in ("src", "dst"):
                        boundary, _unparsed = _rule_intervals_status(
                            rule.get(f"{dim}_cidrs") or [],
                            rule.get(f"{dim}_ips") or [],
                            rule.get(f"{dim}_ranges") or [],
                        )
                        split: list[Rect] = []
                        for atom in atoms:
                            inside = tuple(_intersect(list(getattr(atom, dim)), boundary))
                            outside = tuple(_subtract(list(getattr(atom, dim)), boundary))
                            if inside and outside:
                                split.extend((atom.narrow(**{dim: inside}), atom.narrow(**{dim: outside})))
                            else:
                                split.append(atom)
                        atoms = split
                        if evaluated + len(pending) + len(atoms) > self.cap:
                            return [
                                (
                                    region,
                                    Effect(
                                        INDETERMINATE,
                                        "firewall",
                                        reason="the symbolic address partition exceeded its region budget",
                                    ),
                                )
                            ]
            evaluated += 1
            if len(atoms) > 1:
                pending.extend(atoms)
            else:
                out.extend(decided)
        return out


@dataclass(frozen=True)
class _StatePolicyFilter:
    """A recorded global state decision is applied before the rulesets. The interface ACLs
    are applied after a permit of the state policy."""

    session: Any
    device_uid: str
    conn_state: str
    fallback: Transition
    acls: Transition
    state_credits: list[str] = field(default_factory=list, compare=False)

    @property
    def considered(self) -> list[str]:
        return [
            *self.state_credits,
            *getattr(self.fallback, "considered", ()),
            *getattr(self.acls, "considered", ()),
        ]

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        rows = pathmod._read(
            self.session,
            _DEVICE_STATE_POLICY_QUERY.replace(
                "RETURN global_state_policy, state_policy_basis ORDER BY uid LIMIT 1",
                "RETURN uid, global_state_policy ORDER BY uid",
            ),
            dev=self.device_uid,
        )
        policies = {tuple(sorted(r.get("global_state_policy") or ())) for r in rows}
        if not policies or policies == {()}:
            return self.fallback.apply(region)
        if len(policies) != 1:
            return [
                (
                    region,
                    Effect(INDETERMINATE, "session", reason="conflicting recorded global state policies"),
                )
            ]
        entries = [str(p).partition("=") for p in next(iter(policies))]
        if any(not sep or not action for _state, sep, action in entries):
            return [
                (region, Effect(INDETERMINATE, "session", reason="unrecognized recorded global state policy"))
            ]
        actions = {classify_action(action) for state, _sep, action in entries if state == self.conn_state}
        if not actions:
            return self.fallback.apply(region)
        self.state_credits.extend(str(row["uid"]) for row in rows if row.get("uid"))
        if len(actions) != 1 or INDETERMINATE in actions:
            return [
                (region, Effect(INDETERMINATE, "session", reason=f"unknown {self.conn_state} state action"))
            ]
        if DENY in actions:
            return [
                (
                    region,
                    Effect(
                        DENY,
                        "session",
                        terminal=True,
                        reason=f"recorded {self.conn_state} state policy denies",
                    ),
                )
            ]
        return self.acls.apply(region)


@dataclass(frozen=True)
class _UnlocatedStateFilter:
    """The bounds of a reply that may or may not find synchronized connection state."""

    new: Transition
    established: Transition

    @property
    def considered(self) -> list[str]:
        return [*getattr(self.new, "considered", ()), *getattr(self.established, "considered", ())]

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        new, established = self.new.apply(region), self.established.apply(region)
        out = []
        covered = FlowRegion()
        for left, le in new:
            for right, re in established:
                overlap = left.intersect(right)
                if not overlap:
                    continue
                covered = covered.union(overlap)
                lk = "permit" if le.kind in {"pass", "permit"} else le.kind
                rk = "permit" if re.kind in {"pass", "permit"} else re.kind
                effect = le
                if lk != rk or le.unknown or re.unknown or lk == INDETERMINATE:
                    effect = Effect(
                        INDETERMINATE,
                        "session",
                        reason="the response reached a different state location; "
                        "state synchronization is not recorded and changes the policy result",
                    )
                out.append((overlap, effect))
        missing = region.subtract(covered)
        if missing:
            out.append(
                (missing, Effect(INDETERMINATE, "session", reason="state policy coverage is incomplete"))
            )
        return out


_DEVICE_NAME_QUERY = """
MATCH (d:Device {uid: $dev})
WHERE d:Obj AND d.collection_ts = $snap AND NOT d:Retired
RETURN d.hostname AS name ORDER BY d.uid LIMIT 1"""


@dataclass(frozen=True)
class GraphGates:
    """`Gates` over a pinned graph session. It uses the transitions of the
    tracer over the rows that the tracer reads. `with_changes` wraps the
    session in the overlay hook, through which a change set reaches every gate."""

    session: Any

    @cached_property
    def _aci(self) -> dict[str | None, AciTransition]:
        return {}

    def fabric(self, context_uid: str | None) -> Transition:
        if context_uid not in self._aci:
            self._aci[context_uid] = AciTransition(self.session, context_uid)
        return self._aci[context_uid]

    @cached_property
    def virtual_services(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            pathmod._read(
                self.session,
                """
MATCH (vs:VirtualService:Obj)-[v:VIP]->(ip:IpAddress), (vs)-[o:ON]->(target)
WHERE NOT vs:Retired AND NOT ip:Retired AND NOT target:Retired
  AND v._retired_at IS NULL AND o._retired_at IS NULL
  AND vs.collection_ts = $snap
  AND ip.collection_ts = $snap
MATCH (d:Device:Obj)
WHERE NOT d:Retired AND d.collection_ts = $snap
  AND (d = target OR EXISTS {
    MATCH (d)-[m:MEMBER_OF]->(target:RedundancyGroup) WHERE m._retired_at IS NULL
  })
RETURN DISTINCT d.uid AS device_uid, ip.ip AS ip, vs.uid AS uid
ORDER BY device_uid, ip, uid
""",
            )
        )

    def dnat(self, device_uid: str, in_if: Interface | None) -> Transition:
        ingress = in_if.uid if in_if else None
        rows = _nat_rows(self.session, device_uid, strict=True, in_if=ingress)
        role = _iface_nat_role(self.session, in_if.uid) if rows and in_if is not None else None
        return CreditedTransition(
            NatTransition(
                _nat_stage_rules(rows, "dnat", in_if.name if in_if else None, ingress_role=role),
                complete_service=True,
            ),
            self.nat_credits(device_uid, ingress),
        )

    def nat_credits(self, device_uid: str, in_if: str | None = None) -> frozenset[str]:
        return frozenset(
            uid
            for row in nat_rulebase_credits(self.session, device_uid, in_if)
            for uid in [row["rb_uid"], *(row.get("rule_uids") or ())]
        )

    def filter(self, device_uid: str, in_if: Interface | None, out_if: Interface | None) -> Transition:
        return self._filter(device_uid, in_if, out_if, "new")

    def _filter(
        self, device_uid: str, in_if: Interface | None, out_if: Interface | None, state: str
    ) -> Transition:
        ingress, egress = in_if.uid if in_if else "", out_if.uid if out_if else None
        # The inbound interface ACL is judged here, on the original packet
        # (`filter_view`). The outbound interface ACL is judged at `egress_acl`,
        # after source NAT.
        return _StatePolicyFilter(
            self.session,
            device_uid,
            state,
            FirewallTransition(
                self.session, device_uid, ingress, egress, conn_state=state, acl_direction="in"
            ),
            _LocalFilter(
                self.session,
                device_uid,
                ingress,
                egress,
                conn_state=state,
                acl_only=True,
                acl_direction="in",
            ),
        )

    def egress_acl(
        self, device_uid: str, in_if: Interface | None, out_if: Interface | None, conn_state: str = "new"
    ) -> Transition:
        """The outbound interface ACLs of `out_if`, judged after source NAT on
        the packet as it leaves (IOS-XE runs the outbound list after the
        inside-to-outside translation). Only lists bound outbound are
        candidates. `filter` reads a device-wide rulebase."""
        ingress, egress = in_if.uid if in_if else "", out_if.uid if out_if else None
        return FirewallTransition(
            self.session, device_uid, ingress, egress, conn_state=conn_state, acl_direction="out"
        )

    def filter_view(self, device_uid: str) -> tuple[str | None, str | None]:
        return _read_device_filter_view(self.session, device_uid)

    def coverage(
        self, b: _Branch, stage: ImpactStage, out_if: Interface | None, *, preflight: bool
    ) -> Transition:
        ingress, egress = b.in_if.uid if b.in_if else None, out_if.uid if out_if else None
        credits = stage_gate_credits(
            self.session, b.device_uid, stage, ingress, egress, b.rect.af, b.gate_credits
        )
        if not preflight and b.phase == "reply" and (b.device_uid, b.context_uid) in b.forward_devices:
            credits |= self.nat_credits(b.device_uid, ingress)
        return strict_gate_coverage(
            self.session,
            b.device_uid,
            stage=stage,
            in_interface_uid=ingress,
            out_interface_uid=egress,
            evaluated_ids=credits,
            composed_kinds={"FwRulebase", "PbrPolicy", "VirtualService", "NatRule"},
            preflight=preflight,
        )

    def snat(self, device_uid: str, in_if: Interface | None, out_if: Interface | None) -> Transition:
        ingress = in_if.uid if in_if else None
        rows = _nat_rows(self.session, device_uid, strict=True, in_if=ingress)
        ingress_role = _iface_nat_role(self.session, in_if.uid) if rows and in_if is not None else None
        egress_role = _iface_nat_role(self.session, out_if.uid) if rows and out_if is not None else None
        return CreditedTransition(
            NatTransition(
                _nat_stage_rules(
                    rows,
                    "snat",
                    out_if.name if out_if else None,
                    ingress_role=ingress_role,
                    egress_role=egress_role,
                ),
                complete_service=True,
            ),
            self.nat_credits(device_uid, ingress),
        )

    def local_filter(self, device_uid: str, in_if: Interface | None) -> Transition:
        return self._local_filter(device_uid, in_if, None, "input", False)

    def output_filter(
        self, device_uid: str, out_if: Interface | None, established: bool | None = False
    ) -> Transition:
        return self._local_filter(device_uid, None, out_if, "output", established)

    def local_reply_filter(
        self, device_uid: str, in_if: Interface | None, established: bool | None
    ) -> Transition:
        return self._local_filter(device_uid, in_if, None, "input", established)

    def _local_filter(
        self,
        device_uid: str,
        in_if: Interface | None,
        out_if: Interface | None,
        chain: str,
        established: bool | None,
    ) -> Transition:
        if established is None:
            return _UnlocatedStateFilter(
                self._local_filter(device_uid, in_if, out_if, chain, False),
                self._local_filter(device_uid, in_if, out_if, chain, True),
            )
        ingress, egress = in_if.uid if in_if else "", out_if.uid if out_if else None
        state = "established" if established else "new"
        return _StatePolicyFilter(
            self.session,
            device_uid,
            state,
            _LocalFilter(self.session, device_uid, ingress, egress, chain, state, local=True),
            _LocalFilter(self.session, device_uid, ingress, egress, chain, state, acl_only=True, local=True),
        )

    def load_balancer(self, device_uid: str, address: str) -> Transition | None:
        rows = _vip_bindings(self.session, address, device_uid)
        return (
            LbTransition(self.session, device_uid, rows, address, require_known_health=True) if rows else None
        )

    def broker(self, identity_uid: str, segment_uid: str) -> Transition:
        return ZpaTransition(self.session, identity_uid, segment_uid, all_connectors=True)

    def tunnels(self, out_if: Interface, inner: FlowRegion) -> tuple[TunnelLeg, ...]:
        return carrier_legs(self.session, out_if.uid, inner)

    def estate_exit(
        self, device_uid: str, context_uid: str | None, route: Mapping[str, Any], out_if: Interface
    ) -> dict[str, Any] | None:
        """The `left_estate` marker of the tracer for a route that leaves the
        model at `device_uid` by `out_if` (`path.trace.estate_exit`), or None.
        An SD-WAN edge in this context gives None."""
        from hst.path.gates.sdwan import read_boundary
        from hst.path.trace import estate_exit

        if read_boundary(self.session, device_uid, context_uid):
            return None
        named = pathmod._read_one(self.session, _DEVICE_NAME_QUERY, dev=device_uid)
        return estate_exit(
            self.session,
            device_uid=device_uid,
            device_name=named.get("name") if named else None,
            table_uid=context_uid,
            route=dict(route),
            egress_uid=out_if.uid,
            egress_name=out_if.name,
        )

    def reply_filter(
        self, device_uid: str, in_if: Interface | None, out_if: Interface | None, established: bool | None
    ) -> Transition:
        if established is None:
            return _UnlocatedStateFilter(
                self._filter(device_uid, in_if, out_if, "new"),
                self._filter(device_uid, in_if, out_if, "established"),
            )
        return self._filter(device_uid, in_if, out_if, "established" if established else "new")

    def with_changes(self, changes: ChangeSet) -> Gates:
        return GraphGates(_OverlaySession(self.session, changes))


@dataclass(frozen=True)
class _Pass:
    gate: str = "state"
    reason: str | None = None

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        return [(region, Effect("pass", self.gate, reason=self.reason))]


@dataclass(frozen=True)
class _TunnelChoices:
    legs: tuple[TunnelLeg, ...]

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        return [
            (
                leg.inner,
                Effect(
                    "select"
                    if leg.can_decapsulate
                    else ("deny" if leg.status in {"down", "denied"} else INDETERMINATE),
                    "tunnel",
                    terminal=leg.status in {"down", "denied"},
                    reason="; ".join(leg.evidence),
                    data={"leg": leg},
                ),
            )
            for leg in self.legs
        ]


@dataclass(frozen=True)
class _Rewrite:
    device_uid: str
    stage: str
    before: Rect
    after: Rect
    deterministic: frozenset[str] = frozenset()
    context_uid: str | None = None


def _reverse(rect: Rect) -> Rect:
    return Rect(rect.af, rect.dst, rect.src, rect.proto, rect.sport, rect.dport)


_REVERSE_DIM = {"src": "dst", "dst": "src", "sport": "dport", "dport": "sport", "proto": "proto"}


def _network(text: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def _address(text: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(text)))
    except ValueError:
        return None


def _address_order(text: str) -> tuple[int, int]:
    """A sort key for normalized addresses, the family first and then the
    numeric value. IPv4 and IPv6 addresses do not compare with each other."""
    address = ipaddress.ip_address(text)
    return address.version, int(address)


@dataclass(frozen=True)
class _ResultIndex:
    """The parts of a routing result `Network.incomplete` reads, by context."""

    unsettled: tuple[str, ...]
    gaps: Mapping[str, Sequence[Mapping[str, Any]]]


@dataclass(frozen=True)
class _Calibration:
    """The calibration of a baseline, by context. It holds the context rows,
    the unverified validation items with their prefixes, and the validated
    prefixes."""

    contexts: Mapping[str, Mapping[str, Any]]
    unverified: Mapping[str, Sequence[tuple[Mapping[str, Any], Any]]]
    validated: Mapping[str, Sequence[Any]]


@dataclass(frozen=True)
class _InterfaceIndex:
    """The interfaces of a network by the address they hold and the device
    they are on, built once for every overlay of the network.
    `ordered` is every held address as (family, number), sorted, for a range
    lookup."""

    by_address: Mapping[str, tuple[Interface, ...]]
    by_device: Mapping[str, tuple[Interface, ...]]
    ordered: tuple[tuple[int, int], ...]
    address_of: Mapping[tuple[int, int], str]

    @classmethod
    def build(cls, interfaces: Iterable[Interface]) -> _InterfaceIndex:
        by_address: dict[str, list[Interface]] = {}
        by_device: dict[str, list[Interface]] = {}
        for i in interfaces:
            by_device.setdefault(i.device_uid, []).append(i)
            for a in i.addresses:
                if (normalized := _address(a)) is not None:
                    held = by_address.setdefault(normalized, [])
                    if not held or held[-1] is not i:
                        held.append(i)
        address_of = {_address_order(a): a for a in by_address}
        return cls(
            {a: tuple(v) for a, v in by_address.items()},
            {d: tuple(v) for d, v in by_device.items()},
            tuple(sorted(address_of)),
            address_of,
        )

    def within(self, dst: Ivals) -> list[str]:
        """The held addresses inside a destination set."""
        found: list[str] = []
        for af, lo, hi in dst:
            first = bisect_left(self.ordered, (af, lo))
            last = bisect_right(self.ordered, (af, hi))
            found.extend(self.address_of[key] for key in self.ordered[first:last])
        return found


@dataclass(frozen=True)
class Network:
    """The network model N. It holds the routing input that the calculation
    reads, every interface with the prefixes it serves and the addresses it
    holds, and the gates. `changes` is the change set this network has applied
    (None for the baseline).

    The routing calculation runs once per network, on first use.
    """

    routing: rib.RibInput
    interfaces: tuple[Interface, ...]
    gates: Gates
    changes: ChangeSet | None = None
    max_hops: int = 32
    # Calibration belongs to the unmodified baseline.
    baseline: Network | None = field(default=None, repr=False, compare=False)
    checkpoint: Callable[[], bool | None] | None = field(default=None, repr=False, compare=False)
    # The preceding overlay network.
    routing_parent: Network | None = field(default=None, repr=False, compare=False)
    # The exact routing predicates that `apply` supplies. An empty tuple is a
    # policy-only overlay when the routing input equals the routing input of
    # the baseline. `rib.compute_incremental` treats every other empty dirty set
    # as a full rebuild.
    routing_dirty: tuple[rib.PrefixPredicate, ...] = field(default=(), repr=False, compare=False)
    # The routing-domain identities of each forwarding context (`same_scope`). None
    # when the network was built without reading them. A hop between 2 contexts
    # is then not followed.
    context_domains: Mapping[str, frozenset[str]] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.interfaces, key=lambda i: (i.device_uid, i.uid)))
        object.__setattr__(self, "interfaces", ordered)

    @cached_property
    def routes(self) -> rib.RibResult:
        if self.baseline is None:
            return rib.compute(self.routing, ErrorSink(), validate_observed=True, checkpoint=self.checkpoint)
        parent = self.routing_parent or self.baseline
        if parent is None:
            return rib.compute(self.routing, ErrorSink(), validate_observed=False, checkpoint=self.checkpoint)
        if self.routing == parent.routing:
            # A firewall/NAT/zone overlay changes no RIB input.
            return parent.routes
        components = self.routing_components
        if components is None:
            return rib.compute(self.routing, ErrorSink(), validate_observed=False, checkpoint=self.checkpoint)
        return components.result

    @cached_property
    def routing_components(self) -> rib.IncrementalRib | None:
        """The component artifact for counterfactual routing overlays, built on first use.

        The baseline runs the whole-input calculation. An unattributable
        diagnostic keeps the value ``None``, and every child then runs the
        whole-input calculation.
        """
        parent = self.routing_parent or self.baseline
        if parent is None:
            return rib.incremental_from_result(self.routing, self.routes)
        if self.routing == parent.routing:
            return parent.routing_components
        previous = parent.routing_components
        if previous is None:
            return None
        return rib.compute_incremental(
            self.routing,
            previous=previous,
            dirty=self.routing_dirty,
            validate_observed=False,
            checkpoint=self.checkpoint,
        )

    @cached_property
    def _incomplete_cache(
        self,
    ) -> dict[tuple[str, tuple[tuple[int, int, int], ...] | None], tuple[tuple[str, bool], ...]]:
        return {}

    @cached_property
    def _result_index(self) -> _ResultIndex:
        """What `incomplete` reads of this network's routing result, by context."""
        result = self.routes
        gaps: dict[str, list[Mapping[str, Any]]] = {}
        for gap in result.gaps:
            if gap.get("kind") in _OPEN_GAPS:
                gaps.setdefault(str(gap.get("context_uid")), []).append(gap)
        return _ResultIndex(
            tuple(str(e["detail"]) for e in result.model_errors if e.get("kind") in _UNSETTLED), gaps
        )

    @cached_property
    def _calibration(self) -> _Calibration:
        """The calibration of this network's routing against the observed one,
        by context. Only a baseline owns one."""
        contexts: dict[str, Mapping[str, Any]] = {}
        for context in self.routing.contexts:
            contexts.setdefault(context["uid"], context)
        unverified: dict[str, list[tuple[Mapping[str, Any], Any]]] = {}
        validated: dict[str, list[Any]] = {}
        for item in self.routes.validation:
            status, uid = item.get("status"), str(item.get("context_uid"))
            if status in {rib.MISMATCH, rib.NOT_OBSERVED}:
                unverified.setdefault(uid, []).append((item, _network(item.get("prefix"))))
            elif status == rib.VALIDATED:
                net = _network(item.get("prefix"))
                if net is not None:
                    validated.setdefault(uid, []).append(net)
        return _Calibration(contexts, unverified, validated)

    def incomplete(self, context_uid: str, destinations: Ivals | None = None) -> tuple[str, ...]:
        """The reasons why no routing decision of one context is an answer. The
        run did not settle, or an input of the context is not observed (a peer
        whose paths are not captured, a link-state database that is not
        complete). A peer whose routes are not collected leaves the context
        open only where the collected table of the context cannot answer for
        it (`_peer_supply_answered`). `unobserved` returns the reasons that the
        symbolic model does not end a routing state for.

        The answer is kept per context and destination set. The walk asks for
        it at every device of every branch."""
        return tuple(reason for reason, _unobserved in self._reasons(context_uid, destinations))

    def unobserved(self, context_uid: str, destinations: Ivals | None = None) -> tuple[str, ...]:
        """The reasons of `incomplete` that state only that no routing table of
        the context is collected. The context is on a platform with no table
        collector, on a device that the run manifest does not record, or it
        spans devices. The table of a family that the collector does not read
        is such a reason too. A collection that failed or is partial is no
        such reason. The computed routes of such a context are not
        contradicted. A destination with no computed route is not decided."""
        return tuple(reason for reason, unobserved in self._reasons(context_uid, destinations) if unobserved)

    def _reasons(self, context_uid: str, destinations: Ivals | None) -> tuple[tuple[str, bool], ...]:
        key = (context_uid, None if destinations is None else tuple(destinations))
        known = self._incomplete_cache.get(key)
        if known is None:
            known = self._incomplete_cache[key] = self._incomplete(context_uid, destinations)
        return known

    @property
    def _routing_as_observed(self) -> bool:
        """Whether the routing of this network is the observed state that the
        collected tables of the baseline calibrate. True for the baseline, and
        for an overlay that `apply` made with no routing intent on such a
        network. False for a network derived in any other way (a failure
        scenario, a model edit, a changed routing input), also when its
        routing rows are equal."""
        return self.baseline is None or self.__dict__.get(_ROUTING_AS_OBSERVED) is True

    def _peer_supply_answered(self, context_uid: str, destinations: Ivals | None) -> bool:
        """Whether the collected table of the context answers a
        `certainty.PEER_SUPPLY` gap for these destinations. Such a gap states
        that the routes a BGP peer sends are not observed. The table answers
        when it is complete for every family asked, the routing of this
        network is the observed state and the context is not superseded. The
        table then holds the routes that the peer sent and the router
        installed. The per-prefix calibration in `_incomplete` decides each
        prefix. A prefix that the table has and the computed table lacks stays
        open."""
        if not destinations or not self._routing_as_observed:
            return False
        owner = self.baseline if self.baseline is not None else self
        if (
            context_uid in self.routing.superseded_contexts
            or context_uid in owner.routing.superseded_contexts
        ):
            return False
        if owner.routing.rib_coverage.get(context_uid) not in {"complete", "complete-empty"}:
            return False
        observed_afs = owner._calibration.contexts.get(context_uid, {}).get("observed_rib_afs")
        if observed_afs is None:
            return False
        return {af for af, _lo, _hi in destinations} <= set(observed_afs)

    def _incomplete(self, context_uid: str, destinations: Ivals | None) -> tuple[tuple[str, bool], ...]:
        """Each reason of `incomplete`, with True for a reason of `unobserved`."""
        index = self._result_index
        out = [(reason, False) for reason in index.unsettled]
        answered = self._peer_supply_answered(context_uid, destinations)
        # The sessions with a PEER_SUPPLY gap in this context. The
        # `unpaired-bgp-session` error of such a session repeats the gap and is
        # left out below.
        peer_sessions = {
            str(gap.get("session_uid"))
            for gap in index.gaps.get(context_uid, ())
            if gap.get("cause") == certainty.PEER_SUPPLY and gap.get("session_uid")
        }
        # A selection that the arrival-order tie-break decided is no proof.
        # It widens only the prefixes that it decided.
        for gap in index.gaps.get(context_uid, ()):
            if answered and gap.get("cause") == certainty.PEER_SUPPLY and not gap.get("origin_context_uid"):
                # The collected table answers for a peer of this context
                # (`_peer_supply_answered`). A gap copied from an upstream
                # context still counts.
                continue
            scoped = gap.get("kind") == rib.HISTORY_DEPENDENT or gap.get("scope") == "prefix"
            prefix = _network(gap.get("prefix")) if scoped else None
            if (
                destinations is not None
                and prefix is not None
                and not _intersect(list(destinations), _intervals([str(prefix)]))
            ):
                continue
            out.append((str(gap.get("detail")), gap.get("model_error_kind") == _UNOBSERVED_ERROR))
        out.extend(
            (str(e["detail"]), e.get("kind") == _UNOBSERVED_ERROR)
            for e in self.proof_errors.get(context_uid, ())
            if not (e.get("kind") == "unpaired-bgp-session" and str(e.get("subject")) in peer_sessions)
        )
        owner = self.baseline if self.baseline is not None else self
        calibration = owner._calibration
        baseline_input = owner.routing
        context = calibration.contexts.get(context_uid, {})
        coverage = baseline_input.rib_coverage.get(context_uid)
        no_table = coverage in _UNOBSERVED_COVERAGE
        if "observed_rib_afs" in context:
            observed_afs = context["observed_rib_afs"]
            requested_afs = {af for af, _lo, _hi in destinations or ()}
            if observed_afs is None or requested_afs - set(observed_afs):
                # `unread_rib_afs` holds the families whose table read failed.
                unread = requested_afs & set(context.get("unread_rib_afs") or ())
                out.append(
                    (
                        "baseline forwarding observations do not cover the requested "
                        f"address family in {context_uid}",
                        (no_table or coverage in {"complete", "complete-empty"}) and not unread,
                    )
                )
        if context_uid in baseline_input.rib_coverage and coverage not in {"complete", "complete-empty"}:
            out.append(
                (f"baseline forwarding coverage for {context_uid} is {coverage or 'not observed'}", no_table)
            )
        for item, prefix in calibration.unverified.get(context_uid, ()):
            # A pure model has no observation contract.
            if item.get("status") == rib.NOT_OBSERVED and context_uid not in baseline_input.rib_coverage:
                continue
            if destinations is not None and prefix is not None:
                # The destinations a longer validated route wins by longest-prefix
                # match are outside the uncertainty of a shorter, uncalibrated
                # prefix.
                remaining = _intersect(list(destinations), _intervals([str(prefix)]))
                for other in calibration.validated.get(context_uid, ()):
                    if not remaining:
                        break
                    if other.version != prefix.version or other.prefixlen <= prefix.prefixlen:
                        continue
                    remaining = _subtract(remaining, _intervals([str(other)]))
                if not remaining:
                    continue
            out.append(
                (
                    f"baseline routing is not calibrated: {item.get('detail')}",
                    no_table and item.get("status") == rib.NOT_OBSERVED,
                )
            )
        return tuple(out)

    @cached_property
    def proof_errors(self) -> Mapping[str, Sequence[Mapping[str, Any]]]:
        # `_incomplete` checks the RIB discrepancies against the baseline and
        # the destination region.
        return affected_contexts(
            self.routing, [e for e in self.routes.model_errors if e.get("kind") != "rib-route-mismatch"]
        )

    def interface(self, device_uid: str, name: str | None) -> Interface | None:
        """One device's interface by name or uid."""
        if not name:
            return None
        for i in self.interface_index.by_device.get(device_uid, ()):
            if name in (i.name, i.uid):
                return i
        return None

    @cached_property
    def interface_index(self) -> _InterfaceIndex:
        return _InterfaceIndex.build(self.interfaces)

    @cached_property
    def estate_prefixes(self) -> Ivals:
        """Every address of the estate, both families, by the rule of the
        tracer (`hst.path.trace.estate_prefixes`). The addresses are the
        prefixes that an interface of the network serves, the prefix of every
        route of a collected context, and the address space that is not on the
        internet. The routes are the connected and static rows of the routing
        input, its observed RIB rows and the computed RIB, without the default
        routes. A destination in the estate that a device sends out by the
        edge of the estate is a route missing on that device. The property
        reads the rows that the network holds and does not read the graph. A
        prefix that an uplink interface serves (the transfer network of the
        provider, `uplinks`) is not part of the estate. An uplink interface is
        an edge by the rule of the tracer. A network whose routing input and
        interfaces equal those of the network it was derived from (a policy
        change, a failure scenario of the same rows) shares the answer of that
        network."""
        from hst.path.trace import estate_prefixes

        parent = self.routing_parent or self.baseline
        if parent is not None and parent.routing == self.routing and parent.interfaces == self.interfaces:
            return parent.estate_prefixes
        from hst.path.trace import _uplink_interface

        routing = self.routing
        rows = [
            row
            for table in (routing.connected, routing.static, *routing.observed_rib.values(), self.routes.rib)
            for row in table
        ]
        # The default routes of each device from every table of the device
        # (the contexts of its interfaces and its policy tables), for the
        # uplink decision of the tracer (`_uplink_interface`).
        devices = {str(c["uid"]): c.get("device_uid") for c in routing.contexts}
        by_name: dict[tuple[Any, Any], Interface] = {(i.context_uid, i.name): i for i in self.interfaces}
        defaults: dict[Any, list[dict[str, Any]]] = {}
        for row in rows:
            net = _network(row.get("prefix"))
            if net is not None and net.prefixlen == 0:
                device = row.get("device_uid") or devices.get(str(row.get("context_uid")))
                hop = row.get("next_hop")
                egress = by_name.get((row.get("context_uid"), row.get("interface")))
                defaults.setdefault(device, []).append(
                    {
                        "cidr": str(net),
                        "next_hop": hop,
                        "interface": row.get("interface"),
                        "held": self._next_hop_held(hop, egress),
                    }
                )
        # Per interface, for both families. When a default route leaves by an
        # interface, every prefix that the interface serves belongs to the provider.
        uplinks = [
            prefix
            for i in self.interfaces
            if i.prefixes
            and _uplink_interface(
                {
                    "cidrs": list(i.prefixes),
                    "if_name": i.name,
                    "link_kinds": list(i.link_kinds),
                    "default_origin": i.default_origin,
                    "site_zone": i.site_zone,
                    "defaults": defaults.get(i.device_uid, []),
                }
            )
            for prefix in i.prefixes
        ]
        return estate_prefixes(
            (p for i in self.interfaces for p in i.prefixes),
            routed=(row.get("prefix") for row in rows),
            uplinks=uplinks,
        )

    def _next_hop_held(self, hop: Any, egress: Interface | None) -> bool:
        """Whether a collected interface holds the next hop of a default route,
        as the uplink decision of the tracer reads it. A link-local next hop
        counts only on an interface on the same link, which shares a connected
        prefix that is not link-local with the egress of the route. Any other
        next hop counts on any interface."""
        if not hop:
            return False
        owners = self.owners(str(hop))
        address = _address(str(hop))
        local = address is not None and ipaddress.ip_address(address).is_link_local
        if not local:
            return bool(owners)
        if egress is None:
            return False

        def routed(item: Interface) -> set[str]:
            return {p for p in item.prefixes if (n := _network(p)) is not None and not n.is_link_local}

        return any(o.uid != egress.uid and routed(o) & routed(egress) for o in owners)

    def owners(self, ip: str | None) -> tuple[Interface, ...]:
        """Every interface holding an address."""
        wanted = _address(ip)
        if wanted is None:
            return ()
        return self.interface_index.by_address.get(wanted, ())

    def domains_of(self, context_uid: str | None) -> frozenset[str]:
        """The routing-domain identities of a forwarding context. They are the
        declared domains of its VRF and the resolved domains of its addresses.
        Empty when they were not read."""
        if context_uid is None or self.context_domains is None:
            return frozenset()
        return self.context_domains.get(context_uid, frozenset())

    def same_scope(self, left: str | None, right: str | None) -> bool | None:
        """Whether 2 forwarding contexts are in one routing domain. True for
        one context and for 2 contexts that share a domain identity. False
        when both have domains and share none. None when either has none
        recorded."""
        if left is not None and left == right:
            return True
        first, second = self.domains_of(left), self.domains_of(right)
        if not first or not second:
            return None
        return bool(first & second)

    def on_link(
        self, owner: Interface, address: str, out_if: Interface | None, context_uid: str | None
    ) -> bool | None:
        """Whether an interface that holds `address` is on the link through
        which the flow leaves. True when it shares a segment with the egress
        interface. True when it serves the address in a prefix that the egress
        interface also serves and is in the routing domain of the flow. False
        when it is not on the link, and it is then another instance of the
        address. None when the prefixes do not decide the link or its routing
        domain was not read. A routed port is bound to no segment, and its
        link is the prefix."""
        if out_if is not None and owner.segments and out_if.segments:
            return bool(set(owner.segments) & set(out_if.segments))
        if out_if is not None:
            wanted = tuple(_intervals([address]))
            if not owner.prefixes or not _covered(wanted, out_if.prefixes):
                return None
            if not _covered(wanted, owner.prefixes):
                return False
        return self.same_scope(owner.context_uid, context_uid)

    def own_addresses(self, device_uid: str, context_uid: str | None) -> tuple[str, ...]:
        """The addresses a device answers for itself in one context, in
        address order."""
        found: set[str] = set()
        for i in self.interface_index.by_device.get(device_uid, ()):
            if i.context_uid not in (None, context_uid):
                continue
            for a in i.addresses:
                normalized = _address(a)
                if normalized is not None:
                    found.add(normalized)
        for row in getattr(self.gates, "virtual_services", ()):
            if row["device_uid"] != device_uid or (address := _address(row["ip"])) is None:
                continue
            contexts = {i.context_uid for i in self.service_interfaces(address, device_uid)}
            if contexts == {context_uid}:
                found.add(address)
        return tuple(sorted(found, key=_address_order))

    def service_interfaces(self, address: str, device_uid: str | None = None) -> tuple[Interface, ...]:
        devices = {
            str(row["device_uid"])
            for row in getattr(self.gates, "virtual_services", ())
            if _address(row["ip"]) == _address(address)
            and (device_uid is None or row["device_uid"] == device_uid)
        }
        bound = tuple(i for device in sorted(devices) for i in self.interface_index.by_device.get(device, ()))
        same_segment = tuple(i for i in bound if _covered(tuple(_intervals([address])), i.prefixes))
        return same_segment or bound

    def attachments(self, af: int) -> list[tuple[str, tuple[Interface, ...]]]:
        """Every served prefix of one family with the interfaces that serve it,
        longest prefix first. The first prefix that covers an address is its
        longest match."""
        by_prefix: dict[str, list[Interface]] = {}
        for i in self.interfaces:
            for p in i.prefixes:
                net = _network(p)
                if net is not None and net.version == af:
                    by_prefix.setdefault(str(net), []).append(i)
        ordered = sorted(
            by_prefix,
            key=lambda p: (-ipaddress.ip_network(p).prefixlen, int(ipaddress.ip_network(p).network_address)),
        )
        return [(p, tuple(by_prefix[p])) for p in ordered]

    @cached_property
    def _advertised(self) -> Mapping[Any, frozenset[str]]:
        """The sessions the snapshot observed advertising each prefix."""
        found: dict[Any, set[str]] = {}
        for row in self.routing.observed_paths:
            if (net := _network(row.get("prefix"))) is not None:
                found.setdefault(net, set()).add(str(row.get("session_uid")))
        return {net: frozenset(uids) for net, uids in found.items()}

    def advertisements(self, context_uid: str | None, prefix: str) -> int | None:
        """The count of BGP sessions of one context that the snapshot observed
        advertising a prefix, without the shut sessions. It is the redundancy
        behind a selected BGP route. None when the context runs no BGP process
        in the input."""
        inp = self.routing
        if inp.bgp is None or context_uid is None:
            return None
        processes = {str(p.get("uid")) for p in inp.bgp.processes if str(p.get("context_uid")) == context_uid}
        if not processes:
            return None
        sessions = {
            str(s.get("uid"))
            for s in inp.bgp.sessions
            if str(s.get("process_uid")) in processes and str(s.get("state") or "").lower() != "shutdown"
        }
        wanted = _network(prefix)
        return len(sessions & self._advertised.get(wanted, frozenset()))


# the answer


@dataclass(frozen=True)
class Step:
    """One decision on the walk with its device, its stage and the action of the gate."""

    device_uid: str | None
    stage: str
    kind: str
    detail: str
    unknown: tuple[str, ...] = ()
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Explanation:
    """The explanation of the outcome of one part of the request of a member.
    It holds the steps that prove or fail the part and, for a
    `not-established` part, the missing evidence."""

    member: str
    request: Rect
    outcome: str
    steps: tuple[Step, ...]
    missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class MemberAnswer:
    """One member's bounds over its flow space, in the request's own terms."""

    name: str
    request: FlowRegion
    lower: FlowRegion
    upper: FlowRegion
    explanations: tuple[Explanation, ...]

    def explain(self, region: FlowRegion) -> tuple[Explanation, ...]:
        """The explanations that touch a region."""
        return tuple(e for e in self.explanations if FlowRegion.single(e.request).intersect(region))


@dataclass(frozen=True)
class Answer:
    """The result of `answer(N, Q)`. It holds the clients for which the success
    condition is proven (`lower`), the clients for which it is not ruled out
    (`upper`), the bounds per member, and the gaps and model errors of the
    routing calculation."""

    request_set: RequestSet
    mode: str
    lower: Ivals
    upper: Ivals
    members: Mapping[str, MemberAnswer]
    gaps: tuple[Mapping[str, Any], ...] = ()
    model_errors: tuple[Mapping[str, Any], ...] = ()
    assumptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Triage:
    """The disjoint parts of a change between two bounded answers.

    `proven_loss` and `possible_loss` overlap. The seven fields below do not
    overlap each other and together cover the same requests.
    """

    proven_loss: Any
    worked_now_unknown: Any
    unknown_now_broken: Any
    unknown_throughout: Any
    proven_gain: Any
    unknown_now_works: Any
    broken_now_unknown: Any


def _triage(
    lower_before: Any, upper_before: Any, lower_after: Any, upper_after: Any, *, meet: Any, less: Any
) -> Triage:
    """`Triage` over any set type with an intersection and a difference."""
    before_unknown = less(upper_before, lower_before)
    after_unknown = less(upper_after, lower_after)
    return Triage(
        proven_loss=less(lower_before, upper_after),
        worked_now_unknown=less(meet(lower_before, upper_after), lower_after),
        unknown_now_broken=less(before_unknown, upper_after),
        unknown_throughout=less(meet(before_unknown, upper_after), lower_after),
        proven_gain=less(lower_after, upper_before),
        unknown_now_works=less(meet(lower_after, upper_before), lower_before),
        broken_now_unknown=less(after_unknown, upper_before),
    )


def _region_triage(before: MemberAnswer, after: MemberAnswer) -> Triage:
    return _triage(
        before.lower,
        before.upper,
        after.lower,
        after.upper,
        meet=lambda a, b: a.intersect(b),
        less=lambda a, b: a.subtract(b),
    )


def _ivals_triage(before: Answer, after: Answer) -> Triage:
    return _triage(
        before.lower,
        before.upper,
        after.lower,
        after.upper,
        meet=lambda a, b: tuple(_intersect(list(a), list(b))),
        less=lambda a, b: tuple(_subtract(list(a), list(b))),
    )


@dataclass(frozen=True)
class MemberImpact:
    name: str
    proven_loss: FlowRegion
    possible_loss: FlowRegion
    proven_gain: FlowRegion
    possible_gain: FlowRegion
    # The disjoint reading of the same comparison (`Triage`).
    triage: Triage


@dataclass(frozen=True)
class Impact:
    """The 4 differences, over clients at the level of the request set and
    over flow regions per member, with the 2 answers that they were taken
    from.

    Proven loss is inside possible loss, and proven gain is inside possible
    gain. `triage` is the same comparison split into parts that do not
    overlap.
    """

    mode: str
    before: Answer
    after: Answer
    proven_loss: Ivals
    possible_loss: Ivals
    proven_gain: Ivals
    possible_gain: Ivals
    members: Mapping[str, MemberImpact]
    triage: Triage

    def explain(
        self, name: str, region: FlowRegion
    ) -> tuple[tuple[Explanation, ...], tuple[Explanation, ...]]:
        """The before and after explanations touching one member's region."""
        return self.before.members[name].explain(region), self.after.members[name].explain(region)


# the walk


@dataclass(frozen=True)
class _Branch:
    """One flow on its way through the network. `rect` is the flow as the
    network sees it now, `answers` the part of the request it answers for
    in the request's own terms, `rewritten` the dimensions a translation
    has changed between the two."""

    rect: Rect
    answers: Rect
    rewritten: frozenset[str]
    device_uid: str
    context_uid: str | None
    in_if: Interface | None
    hops: int
    visited: frozenset[tuple[Any, ...]]
    steps: tuple[Step, ...]
    phase: str = "forward"
    forward_devices: frozenset[tuple[str, str | None]] = frozenset()
    translations: tuple[_Rewrite, ...] = ()
    locally_originated: bool = False
    broker_origin: Rect | None = None
    undone: frozenset[tuple[int, str]] = frozenset()
    binding_error: str | None = None
    # Header relations since this device's ingress, used when its access
    # policy matches the pre-NAT packet. These are separate from the end-to-end
    # connection bindings that a reply must undo.
    ingress: _Branch | None = field(default=None, repr=False, compare=False)
    local_mappings: tuple[_Rewrite, ...] = ()
    gate_credits: frozenset[str] = frozenset()

    def step(
        self,
        stage: str,
        kind: str,
        detail: str,
        unknown: Iterable[str] = (),
        data: Mapping[str, Any] | None = None,
    ) -> _Branch:
        step = Step(self.device_uid or None, stage, kind, detail, tuple(sorted(unknown)), dict(data or {}))
        return replace(self, steps=(*self.steps, step))


@dataclass(frozen=True)
class _Result:
    """The three regions one walk partitions a request part into, and the
    explanation of every branch that ended."""

    proven: FlowRegion = field(default_factory=FlowRegion)
    failed: FlowRegion = field(default_factory=FlowRegion)
    unknown: FlowRegion = field(default_factory=FlowRegion)
    explanations: tuple[Explanation, ...] = ()


def _disjoint_union(a: FlowRegion, b: FlowRegion) -> FlowRegion:
    return a.union(b.subtract(a))


def _gather(results: Iterable[_Result]) -> _Result:
    """The combined result of disjoint parts."""
    proven, failed, unknown = FlowRegion(), FlowRegion(), FlowRegion()
    explanations: list[Explanation] = []
    for r in results:
        proven = _disjoint_union(proven, r.proven)
        failed = _disjoint_union(failed, r.failed)
        unknown = _disjoint_union(unknown, r.unknown)
        explanations.extend(r.explanations)
    return _Result(proven, failed, unknown, tuple(explanations))


def _choose(mode: str, answers: Rect, results: Sequence[_Result], *, subject: str | None = None) -> _Result:
    """The successors of one relation, combined under the mode. In `possible`
    mode a part is proven when some successor proves it and fails when every
    successor fails it. In `guaranteed` mode a part is proven when every
    successor proves it and fails when any successor fails it. A part that is
    neither proven nor failed is not established.

    `unspecified` is for alternatives that are a gap in the data, such as 2
    owners of one address. A part is proven when every alternative proves it
    and fails when every alternative fails it. A part that the alternatives
    decide differently is not established, and its explanation holds
    `subject`, the ambiguity. A part that an alternative left open keeps the
    explanation of that alternative."""
    whole = FlowRegion.single(answers)
    explanations = tuple(e for r in results for e in r.explanations)
    if not results:
        return _Result(unknown=whole, explanations=explanations)
    if mode == "unspecified":
        # Overapproximate every admissible joint selection. Both universal
        # and existential questions are true if every successor proves them,
        # false if every successor fails, and otherwise depend on correlations.
        proven, failed = whole, whole
        for r in results:
            proven = proven.intersect(r.proven)
            failed = failed.intersect(r.failed)
    elif mode == POSSIBLE:
        proven, failed = FlowRegion(), whole
        for r in results:
            proven = _disjoint_union(proven, r.proven)
            failed = failed.intersect(r.failed)
    else:
        proven, failed = whole, FlowRegion()
        for r in results:
            proven = proven.intersect(r.proven)
            failed = _disjoint_union(failed, r.failed)
    unknown = whole.subtract(proven).subtract(failed)
    if mode == "unspecified" and unknown and explanations:
        open_in_one = FlowRegion()
        for r in results:
            open_in_one = open_in_one.union(r.unknown)
        mixed = unknown.subtract(open_in_one)
        detail = (
            f"{subject}, and they decide the flow differently; which one handles it is not recorded"
            if subject
            else "the alternatives decide the flow differently; which one handles it is not recorded"
        )
        explanations += tuple(
            Explanation(
                explanations[0].member,
                rect,
                NOT_ESTABLISHED,
                (Step(None, "choice", "ambiguous", detail),),
                (detail,),
            )
            for rect in mixed
        )
    return _Result(proven, failed, unknown, explanations)


def _owner_names(items: Iterable[Any]) -> str:
    return ", ".join(sorted({f"{i.name} on {i.device_uid}" for i in items}))


def _failure_cause(result: _Result, part: FlowRegion) -> str:
    """The last step of the first failing explanation that covers `part`."""
    for e in result.explanations:
        if e.outcome == FAILS and e.steps and part.intersect(FlowRegion.single(e.request)):
            return f", {e.steps[-1].detail}"
    return ""


def _within(part: Any, whole: Any) -> bool:
    """Whether a stated dimension value covers no more than another."""
    if part is None or whole is None:
        return part is whole
    if isinstance(part, frozenset):
        return bool(part <= whole)
    return not _subtract(list(part), list(whole))


def _map_request(branch: _Branch, out: Rect, claim: Rect) -> tuple[Rect, frozenset[str], str | None]:
    """The part of the request that an output answers for. `claim` is the part
    of the rectangle of the branch that the gate took, in the terms of the
    branch. `out` is the output that the gate produced from that part. On a
    dimension that no rewrite has touched, the request narrows as the claim
    narrows. On a rewritten dimension the claim is pulled back through the
    translations (`_preimage`). A claim that cannot be pulled back is
    returned as the dimension that the mapping cannot follow. A dimension that
    `out` states differently from the claim is rewritten from this point on."""
    answers = branch.answers
    rewritten = set(branch.rewritten)
    partial: str | None = None
    for dim in DIMS:
        before, claimed, after = getattr(branch.rect, dim), getattr(claim, dim), getattr(out, dim)
        if claimed != before:
            answer_dim = _REVERSE_DIM[dim] if branch.phase == "reply" else dim
            value = claimed
            known = before is not None and _within(claimed, before)
            if known and dim in branch.rewritten:
                for index in reversed(range(len(branch.translations))):
                    if (index, answer_dim) in branch.undone:
                        continue
                    known, value = _preimage(branch.translations[index], answer_dim, value)
                    if not known:
                        break
            if not known:
                partial = partial or dim
            else:
                original = getattr(answers, answer_dim)
                if value is None or original is None:
                    partial = partial or dim
                else:
                    narrowed = (
                        value & original
                        if isinstance(value, frozenset)
                        else tuple(_intersect(list(value), list(original)))
                    )
                    answers = answers.narrow(**{answer_dim: narrowed})
        if after != claimed:
            rewritten.add(dim)
    return answers, frozenset(rewritten), partial


def _preimage(mapping: _Rewrite, dim: str, value: Any) -> tuple[bool, Any]:
    """Pull a predicate back only through an evidenced deterministic map.

    A whole translated image also pulls back to the whole input of an
    uncertain pool. A partial pool image does not identify its clients.
    """
    before, after = getattr(mapping.before, dim), getattr(mapping.after, dim)
    if before == after:
        return True, value
    if value == after:
        return True, before
    if (
        dim in mapping.deterministic
        and value is not None
        and before is not None
        and after is not None
        and not isinstance(before, frozenset)
        and len(before) == len(after) == 1
    ):
        baf, blo, bhi = before[0]
        aaf, alo, ahi = after[0]
        if baf == aaf and bhi - blo == ahi - alo:
            matched = _intersect(list(value), list(after))
            return True, tuple((af, lo + blo - alo, hi + blo - alo) for af, lo, hi in matched)
    return False, value


def _bare(rect: Rect) -> Rect:
    """The rectangle with no origin. The `rewrite` of a gate then records the
    part that it took as the origin of its output."""
    return replace(rect, origin=None)


def _claim_of(rect: Rect, out: Rect, effect: Effect) -> Rect:
    """The part of `rect` that one output answers for, before any rewrite. It
    is the pre-translation claim of a NAT part, the recorded origin of a
    rewrite, or the output where the gate only narrowed."""
    if effect.gate == "nat" and "sources" in effect.data:
        part = effect.data
        return rect.narrow(
            src=tuple(_merge(list(part["sources"]))),
            dst=tuple(_merge(list(part["dst"]))),
            proto=part.get("proto_subset"),
            dport=None if part.get("port_subset") is None else tuple(part["port_subset"]),
            sport=part.get("sport_subset", rect.sport),
        )
    if out.origin is not None:
        return out.origin
    return out


def _route_text(route: Mapping[str, Any]) -> str:
    cidr = route.get("cidr")
    if route.get("discard"):
        return f"{cidr} discarded ({route['discard']})"
    if route.get("next_hop"):
        return f"{cidr} via {route['next_hop']}"
    return f"{cidr} on {route.get('egress_name') or 'an unnamed interface'}"


def _detail(effect: Effect) -> str:
    """A line of prose for one effect, from the gate's own data."""
    data = effect.data
    suffix = f" ({effect.reason})" if effect.reason else ""
    if effect.gate == "routing":
        routes = list(data.get("routes") or ())
        if not routes:
            return "no route covers the destination"
        return "; ".join(_route_text(r) for r in routes)
    if effect.gate == "nat":
        rule = data.get("rule") or {}
        if rule:
            return f"{effect.kind} by NAT rule {rule.get('uid')}{suffix}"
        return f"no NAT rule claims the flow{suffix}"
    if effect.gate == "lb":
        vs = data.get("vs") or {}
        target = data.get("member") or {}
        at = f"VIP {data['vip']}" if data.get("vip") else "the virtual service"
        label = vs.get("name") or vs.get("uid") or at
        if target:
            return f"{label} relates the request to member {target.get('ip')}{suffix}"
        return f"{effect.kind} at {label}{suffix}"
    if effect.gate == "firewall":
        by = data.get("by")
        rule = data.get("rule_uid")
        rulebase = data.get("rb_uid")
        evidence = f" {rule}" if rule else ""
        if rulebase:
            evidence += f" in {rulebase}"
        return f"{effect.kind}{f' by {by}' if by else ''}{evidence}{suffix}"
    return f"{effect.kind}{suffix}"


def _covered(dst: Ivals, prefixes: Iterable[str]) -> bool:
    """Whether a destination set lies within the prefixes an interface serves."""
    specs = [p for p in prefixes if _network(p) is not None]
    if not specs:
        return False
    return not _subtract(list(dst), _intervals(specs))


class _Walk:
    """One member's requests through one network, in one mode."""

    def __init__(
        self,
        net: Network,
        mode: str,
        name: str,
        request: RequestSet | None = None,
        *,
        tunnel_stack: tuple[str, ...] = (),
        terminal_device: str | None = None,
        terminal_context: str | None = None,
    ) -> None:
        self.net = net
        self.mode = mode
        self.member = name
        self.request = request
        self.tunnel_stack = tunnel_stack
        self.terminal_device = terminal_device
        self.terminal_context = terminal_context
        self.visits = 0

    def run(self, region: FlowRegion) -> _Result:
        return _gather(self.enter(rect) for rect in region)

    # ending a branch

    def _end(
        self,
        b: _Branch,
        outcome: str,
        stage: str,
        kind: str,
        detail: str,
        *,
        unknown: Iterable[str] = (),
        missing: Iterable[str] = (),
        evidence_gap: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> _Result:
        gap = (
            evidence_gap
            or gap_from_step({"stage": stage, "kind": kind, "detail": detail, "device_uid": b.device_uid})
            if outcome == NOT_ESTABLISHED
            else None
        )
        data = {**(evidence or {}), **({"evidence_gap": gap} if gap else {})}
        b = b.step(stage, kind, detail, unknown, data or None)
        if (
            outcome == HOLDS
            and b.phase == "forward"
            and self.request is not None
            and self.request.destination_context is not None
            and b.context_uid != self.request.destination_context
        ):
            return self._not_established(
                b,
                "destination",
                "wrong-context",
                "delivery to the requested destination context is not established",
            )
        if (
            outcome == HOLDS
            and self.terminal_device is not None
            and (b.device_uid != self.terminal_device or b.context_uid != self.terminal_context)
        ):
            return self._not_established(
                b, "carrier", "wrong-endpoint", "the carrier did not reach the recorded tunnel endpoint"
            )
        if (
            outcome == HOLDS
            and b.phase == "reply"
            and b.broker_origin is not None
            and _within(b.rect.dst, b.broker_origin.src)
        ):
            connector_reply = _reverse(b.broker_origin)
            if any(
                getattr(connector_reply, d) is not None
                and not _within(getattr(b.rect, d), getattr(connector_reply, d))
                for d in DIMS
            ):
                return self._not_established(
                    b,
                    "broker",
                    "unmatched-response",
                    "the connector received a response outside this request's backend binding",
                )
            b = replace(b, rect=_reverse(b.answers)).step(
                "broker", "reply", "the connector response completes the same authenticated request"
            )
        region = FlowRegion.single(b.answers)
        explanation = Explanation(self.member, b.answers, outcome, b.steps, tuple(missing))
        if outcome == HOLDS:
            if b.phase == "forward" and self.request is not None and self.request.success != "forward":
                return self.reply(b, local=stage == "endpoint")
            if b.phase == "reply":
                pending = [
                    mapping
                    for index, mapping in enumerate(b.translations)
                    if any(
                        getattr(mapping.before, dim) != getattr(mapping.after, dim)
                        and (index, dim) not in b.undone
                        for dim in DIMS
                    )
                ]
                if pending:
                    return self._not_established(
                        b,
                        "session",
                        "state-location-unobserved",
                        "the response did not revisit the device and context owning every forward binding; "
                        "cross-device or cross-context state synchronization is not established",
                    )
                expected = _reverse(b.answers)
                wrong = [
                    d
                    for d in DIMS
                    if getattr(expected, d) is not None
                    and not _within(getattr(b.rect, d), getattr(expected, d))
                ]
                if wrong:
                    return self._not_established(
                        b,
                        "session",
                        "unrestored-tuple",
                        "the response did not restore the original request's " + ", ".join(wrong),
                    )
            if (
                self.request is not None
                and self.request.mtu is not None
                and self.request.mtu.mode in {"unfragmented", "packet"}
            ):
                return self._end(
                    b,
                    NOT_ESTABLISHED,
                    "mtu",
                    "projection-incomplete",
                    _mtu_projection_gap()["detail"],
                    evidence_gap=_mtu_projection_gap(b.device_uid),
                )
            return _Result(proven=region, explanations=(explanation,))
        if outcome == FAILS:
            return _Result(failed=region, explanations=(explanation,))
        return _Result(unknown=region, explanations=(explanation,))

    def _not_established(self, b: _Branch, stage: str, kind: str, detail: str, *missing: str) -> _Result:
        return self._end(b, NOT_ESTABLISHED, stage, kind, detail, missing=missing or (detail,))

    # one transition

    def _advance(self, b: _Branch, out: Rect, effect: Effect, stage: str) -> tuple[_Branch, _Result | None]:
        """The branch after one output of a transition, or the result that
        output ends it with."""
        answers, rewritten, partial = _map_request(b, out, _claim_of(b.rect, out, effect))
        nb = replace(
            b,
            rect=out,
            answers=answers,
            rewritten=rewritten,
            gate_credits=b.gate_credits | _effect_credits(effect.data),
        )
        detail = _detail(effect)
        if partial is not None:
            return nb, self._not_established(
                nb,
                stage,
                effect.kind,
                detail,
                f"the {stage} stage on {b.device_uid} decides on the translated {partial} of the flow; "
                "which requests each part answers for is not determined through the translation",
            )
        if effect.kind == INDETERMINATE or effect.unknown:
            dims = ", ".join(sorted(effect.unknown))
            why = effect.reason or (
                f"the decision could not read {dims}" if dims else "the decision is undetermined"
            )
            return nb, self._end(
                nb,
                NOT_ESTABLISHED,
                stage,
                effect.kind,
                detail,
                unknown=effect.unknown,
                missing=(f"{stage} on {b.device_uid}: {why}",),
                evidence_gap=gap_from_effect(effect, stage=stage, device=b.device_uid, context=b.context_uid),
                evidence=self._data(nb, effect),
            )
        if effect.terminal:
            return nb, self._end(nb, FAILS, stage, effect.kind, detail, evidence=self._data(nb, effect))
        if effect.kind in {"rewrite", "relate", "broker"}:
            claimed = _claim_of(b.rect, out, effect)
            if any(getattr(claimed, d) != getattr(out, d) for d in DIMS):
                mapping = _Rewrite(
                    b.device_uid,
                    stage,
                    claimed,
                    out,
                    frozenset(effect.data.get("mappings") or ()),
                    context_uid=b.context_uid,
                )
                nb = replace(
                    nb,
                    translations=(*nb.translations, mapping) if b.phase == "forward" else nb.translations,
                    local_mappings=(*nb.local_mappings, mapping),
                )
        return nb.step(stage, effect.kind, detail, effect.unknown, self._data(nb, effect)), None

    def _data(self, b: _Branch, effect: Effect) -> dict[str, Any]:
        if effect.gate != "routing" or effect.kind != "select":
            refs = []
            for key in ("rule", "rb", "rulebase", "connector", "member", "vs"):
                value = effect.data.get(key)
                if isinstance(value, dict) and value.get("uid"):
                    refs.append({"role": key, "uid": str(value["uid"])})
            for key in ("uid", "rule_uid", "rb_uid", "contract_uid", "blocking_uid", "connector_uid"):
                value = effect.data.get(key)
                if isinstance(value, str):
                    refs.append({"role": key, "uid": value})
            return {"evidence_refs": refs} if refs else {}
        routes = list(effect.data.get("routes") or ())
        data: dict[str, Any] = {"routes": len(routes)}
        if routes and all(r.get("protocol") == rib.BGP for r in routes):
            data["advertisements"] = self.net.advertisements(b.context_uid, str(routes[0].get("cidr")))
        return data

    def _relation(
        self,
        b: _Branch,
        transition: Transition,
        stage: str,
        then: Callable[[_Branch, Effect], _Result],
    ) -> _Result:
        """Apply a transition to the flow of the branch. Every output that
        answers for a distinct part of the request continues on its own. The
        outputs that answer for the same part are the successors of a relation
        and combine under the mode."""
        whole = FlowRegion.single(b.answers)
        covered, proven, failed = FlowRegion(), FlowRegion(), FlowRegion()
        may_hold, unproven = FlowRegion(), FlowRegion()
        explanations: list[Explanation] = []
        for region, effect in CreditedTransition(transition).apply(FlowRegion.single(_bare(b.rect))):
            for out in region:
                nb, ended = self._advance(b, out, effect, stage)
                domain = FlowRegion.single(nb.answers)
                result = ended if ended is not None else then(nb, effect)
                covered = _disjoint_union(covered, domain)
                proven = _disjoint_union(proven, result.proven)
                failed = _disjoint_union(failed, result.failed)
                may_hold = _disjoint_union(may_hold, domain.subtract(result.failed))
                unproven = _disjoint_union(unproven, domain.subtract(result.proven))
                explanations.extend(result.explanations)
        if not covered:
            return self._not_established(
                b, stage, "silent", f"the {stage} stage on {b.device_uid} produced no decision"
            )
        if self.mode == POSSIBLE:
            failed = covered.subtract(may_hold)
        else:
            proven = covered.subtract(unproven)
        silent = whole.subtract(covered)
        if silent:
            for rect in silent:
                explanations.append(
                    Explanation(
                        self.member,
                        rect,
                        NOT_ESTABLISHED,
                        b.steps,
                        (f"the {stage} transition did not cover this part of the request",),
                    )
                )
        return _Result(proven, failed, whole.subtract(proven).subtract(failed), tuple(explanations))

    def _split(self, b: _Branch, **dims: Any) -> tuple[_Branch, _Result | None]:
        """The branch narrowed on address dimensions by the walk itself."""
        out = b.rect.narrow(**dims)
        answers, rewritten, partial = _map_request(b, out, out)
        nb = replace(b, rect=out, answers=answers, rewritten=rewritten)
        if partial is None:
            return nb, None
        return nb, self._not_established(
            nb,
            "split",
            "translated",
            f"the walk on {b.device_uid} separates the flow on its translated {partial}; which requests "
            "each part answers for is not determined through the translation",
        )

    # the stages

    def enter(self, request: Rect) -> _Result:
        """Attach the source population to the interfaces that serve it."""
        start = _Branch(request, request, frozenset(), "", None, None, 0, frozenset(), ())
        self.visits = 0
        if self.net.checkpoint is not None and self.net.checkpoint() is False:
            return self._not_established(start, "budget", "exhausted", "evaluation time budget exhausted")
        if self.request is not None and self.request.segment_uid:
            broker = getattr(self.net.gates, "broker", None)
            if broker is None:
                return self._not_established(start, "broker", "missing", "no identity/broker evidence reader")
            return self._relation(
                start,
                broker(self.request.identity_uid, self.request.segment_uid),
                "broker",
                lambda b, _e: self.attach(replace(b, broker_origin=_bare(b.rect))),
            )
        return self.attach(start)

    def attach(self, start: _Branch) -> _Result:
        request = start.rect
        if self.request is not None and self.request.ingress_interface_uid:
            candidates = [
                i
                for i in self.net.interfaces
                if i.uid == self.request.ingress_interface_uid
                and (self.request.source_context is None or i.context_uid == self.request.source_context)
            ]
            if len(candidates) != 1:
                return self._not_established(
                    start,
                    "entry",
                    "missing-ingress",
                    "the declared ingress interface is not uniquely recorded",
                )
            ingress = candidates[0]
            return self.device(
                replace(
                    start,
                    device_uid=ingress.device_uid,
                    context_uid=ingress.context_uid,
                    in_if=ingress,
                    locally_originated=False,
                    steps=(
                        *start.steps,
                        Step(
                            ingress.device_uid,
                            "entry",
                            "declared-ingress",
                            f"request assumes arrival on {ingress.uid}",
                        ),
                    ),
                )
            )
        results: list[_Result] = []
        remaining = list(request.src)
        source_device = self.request.source_device_uid if self.request else None
        # Ordinary populations are attached clients. A router-owned source
        # address alone does not change the processing location to the local
        # output chain. A device-originated request states that location, and
        # a broker supplies its own location.
        addresses = (
            sorted({a for i in self.net.interfaces for a in i.addresses if _address(a) is not None})
            if source_device or start.broker_origin is not None
            else []
        )
        for address in addresses:
            own = _intersect(remaining, _intervals([address]))
            if not own:
                continue
            owners = tuple(
                i
                for i in self.net.owners(address)
                if (not source_device or i.device_uid == source_device)
                and (
                    self.request is None
                    or self.request.source_context is None
                    or i.context_uid == self.request.source_context
                )
            )
            if not owners:
                continue
            remaining = _subtract(remaining, own)
            b, ended = self._split(start, src=tuple(own))
            if ended is not None:
                results.append(ended)
                continue
            outcomes = [
                self.device(
                    replace(
                        b,
                        device_uid=i.device_uid,
                        context_uid=i.context_uid,
                        in_if=None,
                        locally_originated=True,
                    )
                )
                for i in owners
            ]
            subject = f"source {address} is owned by {_owner_names(owners)}"
            results.append(_choose("unspecified", b.answers, outcomes, subject=subject))
        if source_device:
            if remaining:
                b, ended = self._split(start, src=tuple(remaining))
                results.append(
                    ended
                    if ended is not None
                    else self._not_established(
                        b,
                        "entry",
                        "unowned",
                        f"device {source_device} has no observed source-address ownership "
                        "in the requested context",
                    )
                )
            return _gather(results)
        for prefix, interfaces in self.net.attachments(request.af):
            if self.request is not None and self.request.source_context:
                interfaces = tuple(i for i in interfaces if i.context_uid == self.request.source_context)
                if not interfaces:
                    continue
            part = _intersect(remaining, _intervals([prefix]))
            if not part:
                continue
            remaining = _subtract(remaining, part)
            b, ended = self._split(start, src=tuple(part))
            if ended is not None:
                results.append(ended)
                continue
            sub = b.rect
            local = _intersect(list(sub.dst), _intervals([prefix]))
            if local:
                switched, ended = self._split(b, dst=tuple(local))
                results.append(
                    ended
                    if ended is not None
                    else self.deliver(
                        replace(
                            switched,
                            context_uid=(
                                interfaces[0].context_uid
                                if len({i.context_uid for i in interfaces}) == 1
                                else None
                            ),
                        ).step("entry", "switched", f"source and destination share {prefix}"),
                        None,
                    )
                )
                rest = _subtract(list(sub.dst), local)
                if not rest:
                    continue
                b, ended = self._split(b, dst=tuple(rest))
                if ended is not None:
                    results.append(ended)
                    continue
                sub = b.rect
            successors = [
                self.device(
                    replace(
                        b,
                        device_uid=i.device_uid,
                        context_uid=i.context_uid,
                        in_if=i,
                        steps=(
                            *b.steps,
                            Step(i.device_uid, "entry", "attach", f"{prefix} is served by {i.name}"),
                        ),
                    )
                )
                for i in interfaces
            ]
            results.append(
                successors[0]
                if len(successors) == 1
                else _choose(
                    "unspecified",
                    b.answers,
                    successors,
                    subject=f"{prefix} is served by {_owner_names(interfaces)}",
                )
            )
        if remaining:
            b, ended = self._split(start, src=tuple(remaining))
            results.append(
                ended
                if ended is not None
                else self._not_established(
                    b,
                    "entry",
                    "unattached",
                    "no interface in the model serves the source addresses",
                )
            )
        return _gather(results)

    def device(self, b: _Branch) -> _Result:
        """The whole forwarding decision of one device for a flow that arrives
        on `b.in_if`. The stages are destination NAT, then the addresses of
        the device or the forwarding path."""
        if self.net.checkpoint is not None and self.net.checkpoint() is False:
            return self._not_established(b, "budget", "exhausted", "evaluation time budget exhausted")
        # The walk of one source rectangle stops after MAX_WALK_VISITS device visits.
        self.visits += 1
        if self.visits > MAX_WALK_VISITS:
            return self._not_established(
                b,
                "budget",
                "branch-budget",
                f"the branch budget of {MAX_WALK_VISITS} device visits for one source is exhausted",
            )
        key = (b.device_uid, b.context_uid, b.in_if.uid if b.in_if else None, _bare(b.rect), b.phase)
        if key in b.visited:
            return self._not_established(
                b,
                "device",
                "loop",
                f"the flow returns to {b.device_uid}; the forwarding loop is not followed",
            )
        if b.hops >= self.net.max_hops:
            return self._not_established(
                b, "device", "hop-limit", f"the walk exceeds {self.net.max_hops} devices at {b.device_uid}"
            )
        b = replace(
            b,
            visited=b.visited | {key},
            ingress=replace(b, ingress=None),
            local_mappings=(),
            gate_credits=frozenset(),
        )
        return self.guard(
            b, "local-output" if b.locally_originated else "forward", None, True, self.device_pipeline
        )

    def guard(
        self,
        b: _Branch,
        stage: ImpactStage,
        out_if: Interface | None,
        preflight: bool,
        then: Callable[[_Branch], _Result],
    ) -> _Result:
        factory = getattr(self.net.gates, "coverage", None)
        if factory is None:
            return then(b)
        return self._relation(
            b, factory(b, stage, out_if, preflight=preflight), "gate-coverage", lambda nb, _e: then(nb)
        )

    def device_pipeline(self, b: _Branch) -> _Result:
        if (
            b.phase == "reply"
            and b.translations
            and (b.device_uid, b.context_uid) not in b.forward_devices
            and any(
                getattr(mapping.before, dim) != getattr(mapping.after, dim) and (index, dim) not in b.undone
                for index, mapping in enumerate(b.translations)
                for dim in DIMS
            )
        ):
            return self._not_established(
                b,
                "session",
                "state-location-unobserved",
                "an asymmetric response has pending translation bindings on another device or context; "
                "their synchronization at this location is not recorded",
            )
        if b.locally_originated:
            return self.route(b)
        if b.phase == "reply" and (b.device_uid, b.context_uid) in b.forward_devices:
            b = self.undo(b, "snat")
            b = self.undo(b, "load-balancer", dimensions={"src", "sport"})
            if b.binding_error:
                return self._not_established(b, "session", "binding-mismatch", b.binding_error)
            return self.local_or_forward(b)
        return self._relation(
            b, self.net.gates.dnat(b.device_uid, b.in_if), "dnat", lambda nb, _e: self.local_or_forward(nb)
        )

    def local_or_forward(self, b: _Branch) -> _Result:
        own = self.net.own_addresses(b.device_uid, b.context_uid)
        local = _intersect(list(b.rect.dst), _intervals(list(own))) if own else []
        if not local:
            return self.forward(b)
        results: list[_Result] = []
        rest = _subtract(list(b.rect.dst), local)
        if rest:
            nb, ended = self._split(b, dst=tuple(rest))
            results.append(ended if ended is not None else self.forward(nb))
        for ip in own:
            part = _intersect(local, _intervals([ip]))
            if not part:
                continue
            nb, ended = self._split(b, dst=tuple(part))
            results.append(ended if ended is not None else self.local(nb, ip))
        return _gather(results)

    def local(self, b: _Branch, ip: str) -> _Result:
        """A flow addressed to the device. The stages are the input chain, then
        a load balancer VIP or the end of the flow on the device."""
        return self.guard(b, "local-input", None, True, lambda nb: self.local_input(nb, ip))

    def local_input(self, b: _Branch, ip: str) -> _Result:
        local_reply = getattr(self.net.gates, "local_reply_filter", None)
        filtering = (
            local_reply(b.device_uid, b.in_if, self.established(b))
            if b.phase == "reply" and local_reply is not None
            else self.net.gates.local_filter(b.device_uid, b.in_if)
        )
        return self._filter_relation(
            b,
            filtering,
            "input-filter",
            lambda nb, _e: self.guard(
                nb, "local-input", None, False, lambda checked: self.terminate(checked, ip)
            ),
        )

    def terminate(self, b: _Branch, ip: str) -> _Result:
        lb = self.net.gates.load_balancer(b.device_uid, ip)
        if lb is None:
            if b.phase == "forward":
                b = replace(b, forward_devices=b.forward_devices | {(b.device_uid, b.context_uid)})
            return self.fabric(
                b,
                lambda nb, _e: self._end(
                    nb, HOLDS, "endpoint", "router-local", f"ends on {b.device_uid}, its own address {ip}"
                ),
            )

        def related(nb: _Branch, effect: Effect) -> _Result:
            target = (effect.data.get("member") or {}).get("ip")
            if _address(target) == _address(ip):
                return self._not_established(
                    nb,
                    "load-balancer",
                    "loop",
                    f"pool member {target} is the VIP itself; the pool dispatches back into the same "
                    "virtual service",
                )
            return self.forward(replace(nb, hops=nb.hops + 1))

        return self._relation(b, lb, "load-balancer", related)

    def forward(self, b: _Branch) -> _Result:
        """The routing decision of the device. Policy routing on the ingress
        interface comes first, then the longest-prefix match over the compiled
        FIB."""
        if b.context_uid is None:
            return self._not_established(
                b,
                "route",
                "no-context",
                f"the ingress interface on {b.device_uid} is in no forwarding context",
            )
        fib = self.net.routes.fib
        if not fib.covers(b.context_uid):
            return self._not_established(
                b, "route", "not-computed", f"the routing calculation did not cover context {b.context_uid}"
            )
        missing = self.net.incomplete(b.context_uid, b.rect.dst)
        if missing:
            return self._not_established(
                b,
                "route",
                "incomplete",
                f"the routing inputs of context {b.context_uid} are incomplete; no route decision of it "
                "is an answer",
                *missing,
            )
        if b.in_if is None:
            return self.route(b)
        ingress_uid = b.in_if.uid
        default_context = b.context_uid
        policy_ids = frozenset(
            str(rule["pol_uid"])
            for binding in self.net.routing.pbr
            if binding.get("if_uid") == ingress_uid
            for rule in binding.get("rules") or ()
            if rule.get("pol_uid")
        )
        b = replace(b, gate_credits=b.gate_credits | policy_ids)
        results: list[_Result] = []
        for group in fib.partition(
            ingress_uid,
            list(b.rect.src),
            list(b.rect.dst),
            service=(b.rect.proto, b.rect.dport, b.rect.sport),
        ):
            nb, ended = self._split(
                b,
                src=tuple(_merge(list(group["sources"]))),
                dst=tuple(_merge(list(group["dst"]))),
                proto=group["proto_subset"],
                dport=group["port_subset"],
                sport=group["sport_subset"],
            )
            if ended is not None:
                results.append(ended)
            elif group.get("opaque"):
                results.append(
                    self._not_established(
                        nb,
                        "pbr",
                        "unknown-predicate",
                        str(group.get("opaque_reason") or "PBR predicate is unknown"),
                    )
                )
            elif group.get("rule_uid") is not None:
                target = group.get("table_uid")
                if not target or not fib.covers(target):
                    results.append(
                        self._not_established(
                            nb,
                            "pbr",
                            "missing-table",
                            f"PBR rule {group['rule_uid']} names an unmodeled table",
                        )
                    )
                else:
                    selected = replace(nb, context_uid=target).step(
                        "pbr", "select", f"PBR rule {group['rule_uid']} selects {target}"
                    )
                    gap = self.net.incomplete(target, selected.rect.dst)
                    if gap:
                        results.append(self._not_established(selected, "pbr", "incomplete", gap[0], *gap))
                    else:
                        results.append(self.policy_route(selected, default_context))
            else:
                results.append(self.route(nb))
        return _gather(results)

    def policy_route(self, b: _Branch, default_context: str) -> _Result:
        """Route in the selected PBR table. The fallback to `default_context`
        applies only to the part that the table does not route.

        A discard route is a route. A covered prefix of a sparse table stays
        routed when a first-address probe misses.
        """
        transition = RoutingTransition.from_fib(self.net.routes.fib, b.device_uid, b.context_uid)
        results: list[_Result] = []
        for region, effect in transition.apply(FlowRegion.single(_bare(b.rect))):
            for rect in region:
                if effect.kind == "no-route" and default_context != b.context_uid:
                    nb, ended = self._split(b, dst=rect.dst)
                    results.append(
                        ended
                        if ended is not None
                        else self.route(
                            replace(nb, context_uid=default_context).step(
                                "pbr", "fallback", f"no route in the selected table; use {default_context}"
                            )
                        )
                    )
                else:
                    nb, ended = self._advance(b, rect, effect, "route")
                    results.append(ended if ended is not None else self.selected(nb, effect))
        return _gather(results)

    def route(self, b: _Branch) -> _Result:
        if b.context_uid is None or not self.net.routes.fib.covers(b.context_uid):
            return self._not_established(
                b, "route", "not-computed", "the forwarding context was not computed"
            )
        gap = self.net.incomplete(b.context_uid, b.rect.dst)
        if gap:
            return self._not_established(b, "route", "incomplete", gap[0], *gap)
        routing = RoutingTransition.from_fib(self.net.routes.fib, b.device_uid, b.context_uid)
        return self._relation(b, routing, "route", self.selected)

    def selected(self, b: _Branch, effect: Effect) -> _Result:
        """The routes that one selection installs. Each route is a successor."""
        routes = [
            resolved
            for route in effect.data.get("routes") or ()
            for resolved in self.resolved_egresses(b, route)
        ]
        successors = [self.egress(b, r, k, len(routes)) for k, r in enumerate(routes)]
        return successors[0] if len(successors) == 1 else self._choose_paths(b, routes, successors)

    def _choose_paths(
        self, b: _Branch, routes: Sequence[Mapping[str, Any]], successors: Sequence[_Result]
    ) -> _Result:
        """Equal-cost routes, combined under the mode (`SPREAD_ASSUMPTION`).
        The traffic takes every path. The mode decides a part that the paths
        decide differently. Every explanation that covers such a part gets a
        `split` step before the steps of its path. The step lists each path
        with its outcome and the device whose hash selects. The explanations
        stay a partition of the request."""
        result = _choose(self.mode, b.answers, successors)
        decided_true, decided_false = FlowRegion(), FlowRegion()
        for s in successors:
            decided_true = decided_true.union(s.proven)
            decided_false = decided_false.union(s.failed)
        split = decided_true.intersect(decided_false)
        if not split:
            return result
        shared = len(b.steps)
        explanations = []
        for e in result.explanations:
            part = FlowRegion.single(e.request).intersect(split)
            if not part:
                explanations.append(e)
                continue
            paths = []
            for route, s in zip(routes, successors, strict=True):
                holds, fails = bool(part.intersect(s.proven)), bool(part.intersect(s.failed))
                if fails and not holds:
                    word = f"fails{_failure_cause(s, part)}"
                else:
                    word = "passes" if holds and not fails else "differs by flow"
                paths.append(f"via {_route_text(route)}: {word}")
            detail = (
                f"split by path at {b.device_uid}: {'; '.join(paths)}. Which path a flow takes depends "
                f"on the hash on {b.device_uid}"
            )
            marker = Step(b.device_uid, "route", "split", detail, data={"paths": len(routes)})
            explanations.append(replace(e, steps=(*e.steps[:shared], marker, *e.steps[shared:])))
        return _Result(result.proven, result.failed, result.unknown, tuple(explanations))

    def resolved_egresses(
        self,
        b: _Branch,
        route: Mapping[str, Any],
        seen: frozenset[tuple[str | None, str]] = frozenset(),
    ) -> list[Mapping[str, Any]]:
        """Resolve recursive next hops through the compiled FIB.

        The selected RIB row can lack its connected egress. Every recursive
        ECMP successor is kept, with its adjacent gateway as the next hop.
        """
        if route.get("egress_name") or route.get("discard") or not route.get("next_hop"):
            return [route]
        context = route.get("next_hop_vrf") or b.context_uid
        hop = str(route["next_hop"])
        key = (context, hop)
        if key in seen or len(seen) >= self.net.max_hops:
            return [{**route, "resolution_error": "recursive next-hop resolution did not settle"}]
        gaps = self.net.incomplete(context, tuple(_intervals([hop]))) if context is not None else ()
        if gaps:
            return [{**route, "resolution_error": "; ".join(gaps)}]
        through = self.net.routes.fib.lpm(b.device_uid, context, hop)
        if not through:
            return [{**route, "resolution_error": f"no compiled route resolves next hop {hop}"}]
        resolved: list[Mapping[str, Any]] = []
        for row in through:
            leg = {
                **route,
                "egress_name": row.get("interface"),
                "next_hop": row.get("next_hop") or hop,
                "next_hop_vrf": row.get("next_hop_context_uid") or context,
                "discard": row.get("discard"),
            }
            resolved.extend(self.resolved_egresses(b, leg, seen | {key}))
        return resolved

    def egress(self, b: _Branch, route: Mapping[str, Any], index: int, count: int) -> _Result:
        """The leg of one route out of the device. The stages are the filter,
        the source NAT stage, then the next hop or the segment onto which the
        flow is forwarded."""
        out_if = self.net.interface(b.device_uid, route.get("egress_name"))
        b = b.step(
            "route",
            "via",
            _route_text(route) + (f" (choice {index + 1} of {count})" if count > 1 else ""),
            data={"choice": index + 1, "of": count},
        )
        if route.get("discard"):
            return self._end(b, FAILS, "route", "discard", _route_text(route))
        if route.get("resolution_error"):
            return self._not_established(b, "route", "resolution-incomplete", str(route["resolution_error"]))
        if out_if is None:
            return self._not_established(
                b, "route", "egress-unmodeled", "the selected route has no modeled egress interface"
            )
        return self.guard(
            b,
            "local-output" if b.locally_originated else "forward",
            out_if,
            True,
            lambda nb: self.egress_filter(nb, route, out_if),
        )

    def egress_filter(self, b: _Branch, route: Mapping[str, Any], out_if: Interface) -> _Result:
        established = self.established(b)
        reply_filter = getattr(self.net.gates, "reply_filter", None)
        filtering = (
            reply_filter(b.device_uid, b.in_if, out_if, established)
            if b.phase == "reply" and reply_filter is not None
            else self.net.gates.filter(b.device_uid, b.in_if, out_if)
        )
        if b.locally_originated:
            output_filter = getattr(self.net.gates, "output_filter", None)
            if output_filter is None:
                return self._not_established(b, "output-filter", "missing", "the output chain is not modeled")
            filtering = (
                output_filter(b.device_uid, out_if, established=established)
                if isinstance(self.net.gates, GraphGates)
                else output_filter(b.device_uid, out_if)
            )
        return self._filter_relation(
            b,
            filtering,
            "reply-filter" if b.phase == "reply" else "filter",
            lambda nb, _e: self.post_filter(nb, route, out_if),
        )

    def established(self, b: _Branch) -> bool | None:
        if b.phase == "reply" and self.request is not None and self.request.success == "session":
            return True if (b.device_uid, b.context_uid) in b.forward_devices else None
        return False

    def _filter_relation(
        self, b: _Branch, transition: Transition, stage: str, then: Callable[[_Branch, Effect], _Result]
    ) -> _Result:
        """Evaluate a policy in its recorded header view, preserving correlations."""
        if isinstance(self.net.gates, GraphGates):
            transition = _AddressFilter(self.net.gates.session, transition)
        view_reader = getattr(self.net.gates, "filter_view", None)
        if not b.local_mappings or view_reader is None:
            return self._relation(b, transition, stage, then)
        view, reason = view_reader(b.device_uid)
        if view is None:
            return self._not_established(
                b, stage, "unknown-header-view", reason or "the filter's NAT ordering is unrecorded"
            )
        if view != "original":
            return self._relation(b, transition, stage, then)
        if b.ingress is None:
            return self._not_established(
                b, stage, "missing-ingress", "the original header view is unavailable"
            )
        values = {d: getattr(b.rect, d) for d in DIMS}
        for mapping in reversed(b.local_mappings):
            for dim in DIMS:
                known, values[dim] = _preimage(mapping, dim, values[dim])
                if not known:
                    return self._not_established(
                        b,
                        stage,
                        "uncorrelated-header-view",
                        f"the original {dim} cannot be identified after the local translation",
                    )
        original = replace(
            b,
            rect=b.rect.narrow(**values),
            translations=b.ingress.translations,
            rewritten=b.ingress.rewritten,
            undone=b.ingress.undone,
        ).step(stage, "original-header", "access policy matches the packet before this device's translations")

        def resume(filtered: _Branch, effect: Effect) -> _Result:
            packet = filtered.rect
            for mapping in b.local_mappings:
                values = {}
                for dim in DIMS:
                    before, after, value = (
                        getattr(mapping.before, dim),
                        getattr(mapping.after, dim),
                        getattr(packet, dim),
                    )
                    if before == after:
                        continue
                    inverse = replace(mapping, before=mapping.after, after=mapping.before)
                    known, projected = _preimage(inverse, dim, value)
                    # A constant rewrite applies to every surviving original
                    # subregion. The filtered branch keeps the request identity
                    # of its subregion, and the subregions share the wire value.
                    if (
                        not known
                        and after is not None
                        and (len(after) == 1 and (isinstance(after, frozenset) or after[0][1] == after[0][2]))
                    ):
                        known, projected = True, after
                    if not known:
                        return self._not_established(
                            filtered,
                            stage,
                            "uncorrelated-header-view",
                            f"the filtered {dim} cannot be mapped to the routed packet",
                        )
                    values[dim] = projected
                packet = packet.narrow(**values)
            return then(
                replace(
                    filtered, rect=packet, rewritten=b.rewritten, translations=b.translations, undone=b.undone
                ),
                effect,
            )

        return self._relation(original, transition, stage, resume)

    def post_filter(self, b: _Branch, route: Mapping[str, Any], out_if: Interface | None) -> _Result:
        if b.phase == "reply" and (b.device_uid, b.context_uid) in b.forward_devices:
            b = self.undo(b, "load-balancer", dimensions={"dst", "dport"})
            b = self.undo(b, "dnat")
            if b.binding_error:
                return self._not_established(b, "session", "binding-mismatch", b.binding_error)
            return self.leave(b, Effect("pass", "nat"), route, out_if)
        if b.phase == "forward":
            b = replace(b, forward_devices=b.forward_devices | {(b.device_uid, b.context_uid)})
        return self._relation(
            b,
            self.net.gates.snat(b.device_uid, b.in_if, out_if),
            "snat",
            lambda sb, effect: self.leave(sb, effect, route, out_if),
        )

    def undo(self, b: _Branch, stage: str, *, dimensions: set[str] | None = None) -> _Branch:
        """Undo only mappings created by this branch on this device."""
        for index in reversed(range(len(b.translations))):
            mapping = b.translations[index]
            if (
                mapping.device_uid != b.device_uid
                or mapping.context_uid != b.context_uid
                or mapping.stage != stage
            ):
                continue
            values = {}
            rewritten = set(b.rewritten)
            undone = set(b.undone)
            for dim in DIMS:
                if (index, dim) in undone or (dimensions is not None and dim not in dimensions):
                    continue
                before, after = getattr(mapping.before, dim), getattr(mapping.after, dim)
                if before == after:
                    continue
                opposite = _REVERSE_DIM[dim]
                known, value = _preimage(mapping, dim, getattr(b.rect, opposite))
                if not known:
                    return replace(b, binding_error=f"the response does not match the {stage} {dim} binding")
                undone.add((index, dim))
                earlier = any(
                    getattr(m.before, dim) != getattr(m.after, dim) and (j, dim) not in undone
                    for j, m in enumerate(b.translations[:index])
                )
                if not earlier:
                    original = getattr(b.answers, dim)
                    if value is not None and original is not None:
                        value = (
                            value & original
                            if isinstance(value, frozenset)
                            else tuple(_intersect(list(value), list(original)))
                        )
                    rewritten.discard(opposite)
                values[opposite] = value
            if not values:
                continue
            packet = b.rect.narrow(**values)
            local = _Rewrite(
                b.device_uid,
                "reply-" + stage,
                b.rect,
                packet,
                frozenset(_REVERSE_DIM[d] for d in mapping.deterministic),
                context_uid=b.context_uid,
            )
            b = replace(
                b,
                rect=packet,
                rewritten=frozenset(rewritten),
                undone=frozenset(undone),
                local_mappings=(*b.local_mappings, local),
            ).step("reply-nat", "inverse", f"undo the forward {stage} mapping on {b.device_uid}")
        return b

    def reply(self, b: _Branch, *, local: bool = False) -> _Result:
        """A correlated response is a new routing walk with reversed headers."""
        if not b.device_uid:
            # Both directions use the same modeled segment, with no routed gate.
            rb = replace(b, rect=_reverse(b.rect), phase="reply")
            return self.fabric(
                rb,
                lambda nb, _e: self._end(
                    nb, HOLDS, "session", "local-segment", "the response uses the same segment"
                ),
            )
        reply = replace(
            b,
            rect=_reverse(b.rect),
            rewritten=frozenset(_REVERSE_DIM[d] for d in b.rewritten),
            phase="reply",
            hops=0,
            visited=frozenset(),
            locally_originated=local,
        ).step("session", "reply", "evaluate the response with reversed addresses and ports")
        return self.device(reply)

    def leave(
        self, b: _Branch, effect: Effect, route: Mapping[str, Any], out_if: Interface | None
    ) -> _Result:
        return self.guard(
            b,
            "local-output" if b.locally_originated else "forward",
            out_if,
            False,
            lambda nb: self.transmit(nb, effect, route, out_if),
        )

    def mtu_egress(self, b: _Branch, out_if: Interface | None) -> tuple[_Branch, _Result | None]:
        """Evaluate the MTU of the local egress of a branch. Incomplete coverage does not certify
        delivery."""
        if self.request is None or self.request.mtu is None or self.request.mtu.mode == "off":
            return b, None
        original = self.request.mtu.as_request()
        reset = b.broker_origin is not None or any(s.stage == "load-balancer" for s in b.steps)
        request, gaps = request_for_connection(
            original, direction="reverse" if b.phase == "reply" else "forward", connection_reset=reset
        )
        # Carrier packets and proxy-originated connections have independent sizes.
        if request is not None and b.rect.af == 6 and request.ipv4_df is not None:
            # IPv4 DF belongs to the IPv4 part of a dual-stack request only.
            request = request.model_copy(update={"ipv4_df": None})
        if self.tunnel_stack or request is None or b.rect.af != b.answers.af:
            return b.step(
                "mtu",
                "packet-shape-unknown",
                "This connection's IP packet length is unknown.",
                data={"evidence_gap": _mtu_projection_gap(b.device_uid)},
            ), None
        observations = [
            MtuObservation.model_validate_json(raw)
            for raw in (out_if.mtu_observations_json if out_if else ())
        ]
        context = MtuContext(
            af=4 if b.rect.af == 4 else 6, enforcement="l3", traffic_class=request.traffic_class
        )
        resolved = resolve_constraints(observations, context)
        stage = MtuStage(
            stage_id=f"assessment:{b.phase}:{b.hops}:{out_if.uid if out_if else b.device_uid}",
            direction="reverse" if b.phase == "reply" else "forward",
            context=context,
            egress_subject_uid=out_if.uid if out_if else None,
            enforcement="l3",
            selection="selected",
            constraints=[c for c in resolved.constraints if c.enforcement == "l3"],
            coverage=MtuCoverage(gaps=sorted(set(resolved.gaps + gaps + ["MTU_PATH_COVERAGE_INCOMPLETE"]))),
        )
        result = evaluate_stage(stage, request)
        data = {"mtu": result.model_dump(mode="json")}
        b = b.step("mtu", "egress-limit", "Evaluate this routed egress's captured IP limits.", data=data)
        if result.outcome == "fail":
            return b, self._end(
                b,
                FAILS,
                "mtu",
                "packet-exceeds-limit",
                "The requested packet exceeds this branch's proven IP egress ceiling.",
                evidence=data,
            )
        return b, None

    def transmit(
        self, b: _Branch, effect: Effect, route: Mapping[str, Any], out_if: Interface | None
    ) -> _Result:
        rule = effect.data.get("rule") if effect.gate == "nat" else None
        if rule and rule.get("masquerade"):
            # The rectangle holds the untranslated source. The translated
            # address is the address of the egress interface, resolved here.
            addresses = sorted(
                {
                    a
                    for a in (out_if.addresses if out_if else ())
                    if (n := _address(a)) and ipaddress.ip_address(n).version == b.rect.af
                }
            )
            if not addresses:
                return self._not_established(
                    b,
                    "snat",
                    "masquerade",
                    f"NAT rule {rule.get('uid')} masquerades via {route.get('egress_name') or 'the egress'}, "
                    "whose address the model does not hold",
                )
            if len(addresses) != 1:
                return self._not_established(
                    b,
                    "snat",
                    "ambiguous-egress-address",
                    "the egress has more than one address and no recorded masquerade selection",
                )
            translated = b.rect.narrow(src=tuple(_intervals([addresses[0]])))
            b = replace(
                b,
                rect=translated,
                rewritten=b.rewritten | {"src"},
                translations=(
                    *b.translations,
                    _Rewrite(b.device_uid, "snat", b.rect, translated, context_uid=b.context_uid),
                ),
            ).step("snat", "masquerade", f"source rewritten to {addresses[0]}")
        egress_acl = getattr(self.net.gates, "egress_acl", None)
        if egress_acl is not None and out_if is not None and not b.locally_originated:
            # The outbound interface ACL reads the packet as it leaves, after
            # the source NAT of this device and a resolved masquerade.
            # Router-originated traffic does not cross an outbound list.
            established = b.phase == "reply" and self.established(b) is True
            transition: Transition = egress_acl(
                b.device_uid, b.in_if, out_if, "established" if established else "new"
            )
            if isinstance(self.net.gates, GraphGates):
                transition = _AddressFilter(self.net.gates.session, transition)
            return self._relation(
                b, transition, "egress-filter", lambda nb, _e: self.onward(nb, route, out_if)
            )
        return self.onward(b, route, out_if)

    def onward(self, b: _Branch, route: Mapping[str, Any], out_if: Interface | None) -> _Result:
        """The stages after the egress filter. They are a tunnel, the egress
        MTU check, then delivery on the segment or the next hop."""
        tunnels = getattr(self.net.gates, "tunnels", None)
        legs = tunnels(out_if, FlowRegion.single(_bare(b.rect))) if tunnels is not None and out_if else ()
        if legs:
            return self._relation(b, _TunnelChoices(legs), "tunnel", self.carrier)
        b, mtu_terminal = self.mtu_egress(b, out_if)
        if mtu_terminal is not None:
            return mtu_terminal
        next_hop = route.get("next_hop")
        if not next_hop:
            if route.get("protocol") == rib.CONNECTED or (
                out_if is not None and _covered(b.rect.dst, out_if.prefixes)
            ):
                return self.deliver(b, out_if)
            return self._leaves_model(
                b,
                route,
                out_if,
                "forwarding",
                "beyond-interface",
                f"the modeled network ends at {route.get('egress_name') or 'an interface'}: route "
                f"{route.get('cidr')} leaves through it with no next hop, and nothing beyond it "
                "(an internet breakout, a provider network) is modeled yet",
            )
        owners = self.net.owners(str(next_hop))
        if not owners:
            return self._leaves_model(
                b,
                route,
                out_if,
                "next-hop",
                "unowned",
                f"no interface in the model holds next hop {next_hop}",
            )
        # Only an interface on the link through which the route leaves takes
        # the flow. The same address in another routing scope is another instance.
        verdicts = [(o, self.net.on_link(o, str(next_hop), out_if, b.context_uid)) for o in owners]
        if all(verdict is False for _o, verdict in verdicts):
            return self._not_established(
                b,
                "next-hop",
                "other-scope",
                f"next hop {next_hop} is held only by {_owner_names(owners)}, which is not on the link "
                f"{out_if.name if out_if else b.context_uid} leaves through; the walk does not follow it",
            )
        if not any(verdict is True for _o, verdict in verdicts):
            return self._not_established(
                b,
                "next-hop",
                "scope-unread",
                f"whether {_owner_names(owners)} holding next hop {next_hop} is on the link and routing "
                "domain of the route was not read",
            )
        owners = tuple(o for o, verdict in verdicts if verdict is not False)
        if len({o.context_uid for o in owners}) > 1:
            return self._not_established(
                b,
                "next-hop",
                "duplicated",
                f"next hop {next_hop} is held in {len({o.context_uid for o in owners})} forwarding contexts; "
                "the walk does not pick one",
            )
        successors = [
            self.device(
                replace(
                    b,
                    device_uid=o.device_uid,
                    context_uid=o.context_uid,
                    in_if=o,
                    locally_originated=False,
                    hops=b.hops + 1,
                    steps=(
                        *b.steps,
                        Step(o.device_uid, "next-hop", "arrive", f"{next_hop} is held by {o.name}"),
                    ),
                )
            )
            for o in owners
        ]
        return (
            successors[0]
            if len(successors) == 1
            else _choose(
                "unspecified",
                b.answers,
                successors,
                subject=f"next hop {next_hop} is held by {_owner_names(owners)}",
            )
        )

    def _leaves_model(
        self,
        b: _Branch,
        route: Mapping[str, Any],
        out_if: Interface | None,
        stage: str,
        kind: str,
        detail: str,
    ) -> _Result:
        """A part whose path leaves the model at this device.

        The part is forwarded out of the estate and holds where the tracer
        reads the same route as the edge of the estate
        (`GraphGates.estate_exit`, for a collected WAN link that is not MPLS,
        the default of the access client, or site zone "internet"). Its step
        holds the `left_estate` marker of the tracer. A round trip starts its
        reply on the egress interface. A part whose destination lies inside
        the estate (`Network.estate_prefixes`) stays not established, with no
        marker. Every other end is not established."""
        estate_exit = getattr(self.net.gates, "estate_exit", None)
        if estate_exit is None or out_if is None:
            return self._not_established(b, stage, kind, detail)
        # The edge is read first. The prefixes of the estate are computed only
        # where a recognized edge is reached.
        exit_ = estate_exit(b.device_uid, b.context_uid, route, out_if)
        if exit_ is None or _intersect(list(b.rect.dst), list(self.net.estate_prefixes)):
            return self._not_established(b, stage, kind, detail)
        from hst.path.trace import _exit_words

        return self._end(
            replace(b, in_if=out_if),
            HOLDS,
            "forwarding",
            "left-estate",
            f"forwarded on {b.device_uid} {out_if.name}; {_exit_words(exit_)}",
            evidence={"left_estate": exit_},
        )

    def deliver(self, b: _Branch, out_if: Interface | None) -> _Result:
        return self.fabric(b, lambda nb, _e: self._deliver(nb, out_if))

    def fabric(self, b: _Branch, then: Callable[[_Branch, Effect], _Result]) -> _Result:
        factory = getattr(self.net.gates, "fabric", None)
        transition = factory(b.context_uid) if factory is not None else _Pass("aci")
        return self._relation(b, transition, "fabric", then)

    def _deliver(self, b: _Branch, out_if: Interface | None) -> _Result:
        """Delivery to a modeled router endpoint must cross its input gate.

        Only an interface on the link through which the flow leaves is that
        endpoint (`Network.on_link`). The same address held in another routing
        scope is another instance. The walk adds an `other-instance` step for
        it and leaves the part to the host on the segment, as the tracer does."""
        results: list[_Result] = []
        remaining = list(b.rect.dst)
        index = self.net.interface_index
        owned = {
            address
            for address in index.within(b.rect.dst)
            if any(i.device_uid != b.device_uid for i in index.by_address[address])
        }
        owned.update(
            address
            for row in getattr(self.net.gates, "virtual_services", ())
            if (address := _address(row["ip"])) is not None
            and ipaddress.ip_address(address).version == b.rect.af
        )
        elsewhere: list[str] = []
        for address in sorted(owned):
            part = _intersect(remaining, _intervals([address]))
            if not part:
                continue
            candidates = self.net.owners(address) or self.net.service_interfaces(address)
            verdicts = [(i, self.net.on_link(i, address, out_if, b.context_uid)) for i in candidates]
            if candidates and all(verdict is False for _i, verdict in verdicts):
                elsewhere.append(f"{address} is also held by {_owner_names(candidates)} outside this link")
                continue
            remaining = _subtract(remaining, part)
            nb, ended = self._split(b, dst=tuple(part))
            if ended is not None:
                results.append(ended)
                continue
            if candidates and not any(verdict is True for _i, verdict in verdicts):
                results.append(
                    self._not_established(
                        nb,
                        "endpoint",
                        "scope-unread",
                        f"whether {_owner_names(candidates)} holding {address} is on the link and routing "
                        "domain of the flow was not read",
                    )
                )
                continue
            owners = tuple(i for i, verdict in verdicts if verdict is not False) or candidates
            if len({i.context_uid for i in owners}) != 1:
                results.append(
                    self._not_established(nb, "endpoint", "ambiguous", "endpoint context is ambiguous")
                )
                continue
            outcomes = [
                self.device(
                    replace(
                        nb,
                        device_uid=i.device_uid,
                        context_uid=i.context_uid,
                        in_if=i,
                        locally_originated=False,
                        hops=nb.hops + 1,
                    )
                )
                for i in owners
            ]
            subject = f"{address} is owned by {_owner_names(owners)}"
            results.append(_choose("unspecified", nb.answers, outcomes, subject=subject))
        if remaining:
            nb, ended = self._split(b, dst=tuple(remaining))
            if ended is None:
                nb = replace(nb, in_if=out_if)
                for note in elsewhere:
                    nb = nb.step("endpoint", "other-instance", note)
            results.append(
                ended
                if ended is not None
                else self._end(
                    nb,
                    HOLDS,
                    "forwarding",
                    "forwarded",
                    f"forwarded on {b.device_uid} {out_if.name if out_if else 'the connected segment'}",
                )
            )
        return _gather(results)

    def carrier(self, b: _Branch, effect: Effect) -> _Result:
        """Route the separate outer header, then resume the recorded inner context."""
        leg = effect.data["leg"]
        if leg.tunnel_uid in self.tunnel_stack or len(self.tunnel_stack) >= self.net.max_hops:
            return self._not_established(
                b, "tunnel", "recursive-carrier", "the tunnel carrier recursively selects itself"
            )
        remote = self.net.interface(leg.remote_device_uid, leg.remote_interface_uid)
        if remote is None or leg.outer is None:
            return self._not_established(
                b, "tunnel", "missing-endpoint", "the decrypted ingress is not modeled"
            )
        walk = _Walk(
            self.net,
            self.mode,
            self.member,
            tunnel_stack=(*self.tunnel_stack, leg.tunnel_uid),
            terminal_device=leg.remote_device_uid,
            terminal_context=leg.remote_underlay_context_uid,
        )
        outcomes = _gather(
            walk.device(
                _Branch(
                    rect,
                    rect,
                    frozenset(),
                    leg.local_device_uid,
                    leg.local_underlay_context_uid,
                    None,
                    0,
                    frozenset(),
                    (),
                    locally_originated=True,
                )
            )
            for rect in leg.outer
        )
        b = replace(
            b,
            steps=(
                *b.steps,
                *(
                    replace(step, stage=f"carrier/{step.stage}")
                    for explanation in outcomes.explanations
                    for step in explanation.steps
                ),
            ),
        )
        if leg.outer.subtract(outcomes.proven):
            if not leg.outer.subtract(outcomes.failed):
                return self._end(
                    b, FAILS, "tunnel", "carrier-blocked", "the outer carrier cannot reach its endpoint"
                )
            return self._not_established(
                b,
                "tunnel",
                "carrier-unknown",
                "the outer carrier is not established",
                *(m for explanation in outcomes.explanations for m in explanation.missing),
            )
        b = replace(
            b,
            device_uid=remote.device_uid,
            context_uid=remote.context_uid,
            in_if=remote,
            locally_originated=False,
            hops=b.hops + 1,
        ).step(
            "tunnel", "decapsulate", f"{leg.peer_tunnel_uid} resumes the inner packet in {remote.context_uid}"
        )
        return self.device(b)


# the success condition over the source population


def _project(region: FlowRegion) -> list[tuple[int, int, int]]:
    """The source addresses a region covers."""
    return _merge([iv for r in region for iv in r.src])


def _inside(atom: tuple[int, int, int], ivals: Sequence[tuple[int, int, int]]) -> bool:
    af, lo, hi = atom
    return any(a == af and ilo <= lo and hi <= ihi for a, ilo, ihi in ivals)


def _atoms(
    sources: Sequence[tuple[int, int, int]], *sets: Sequence[tuple[int, int, int]]
) -> list[tuple[int, int, int]]:
    """The source population cut at every boundary of every set. Each atom
    lies wholly inside or wholly outside each set."""
    cuts: dict[int, set[int]] = {}
    for ivals in (sources, *sets):
        for af, lo, hi in ivals:
            cuts.setdefault(af, set()).update((lo, hi + 1))
    out: list[tuple[int, int, int]] = []
    for af in sorted(cuts):
        points = sorted(cuts[af])
        for lo, nxt in pairwise(points):
            atom = (af, lo, nxt - 1)
            if _inside(atom, sources):
                out.append(atom)
    return out


def _evaluate(condition: Condition, outcomes: Mapping[str, str]) -> str:
    """The condition over member outcomes, three-valued."""
    if condition.kind == MEMBER:
        return outcomes[str(condition.member)]
    if condition.kind == CAPACITY:
        if all(_evaluate(part, outcomes) == NOT_APPLICABLE for part in condition.parts):
            return NOT_APPLICABLE
        # A capacity requirement is not answered from connectivity evidence.
        return NOT_ESTABLISHED
    # A part with no address in the family of the client is not counted.
    results = [r for part in condition.parts if (r := _evaluate(part, outcomes)) != NOT_APPLICABLE]
    if not results:
        return NOT_APPLICABLE
    held = sum(1 for r in results if r == HOLDS)
    failed = sum(1 for r in results if r == FAILS)
    if condition.kind == EVERY:
        needed = len(results)
    elif condition.kind == ANY_ONE:
        needed = 1
    else:
        needed = int(condition.n or 0)
    if held >= needed:
        return HOLDS
    if len(results) - failed < needed:
        return FAILS
    return NOT_ESTABLISHED


def _population(request: RequestSet, members: Mapping[str, MemberAnswer]) -> tuple[Ivals, Ivals]:
    """The clients for which the condition holds and those for which it is
    not ruled out. A member holds for a client when every flow of the request
    of the member from that client is proven. A member is ruled out when some
    flow of it is proven to fail."""
    sources = list(request.sources)
    holds: dict[str, list[tuple[int, int, int]]] = {}
    open_: dict[str, list[tuple[int, int, int]]] = {}
    for name, ma in members.items():
        holds[name] = _subtract(sources, _project(ma.request.subtract(ma.lower)))
        open_[name] = _subtract(sources, _project(ma.request.subtract(ma.upper)))
    lower: list[tuple[int, int, int]] = []
    upper: list[tuple[int, int, int]] = []
    member_families = {m.name: _families(m.addresses) for m in request.members}
    for atom in _atoms(sources, *holds.values(), *open_.values()):
        outcomes = {
            name: NOT_APPLICABLE
            if atom[0] not in member_families[name]
            else HOLDS
            if _inside(atom, holds[name])
            else (NOT_ESTABLISHED if _inside(atom, open_[name]) else FAILS)
            for name in members
        }
        outcome = _evaluate(request.condition, outcomes)
        if outcome == HOLDS:
            lower.append(atom)
        if outcome != FAILS:
            upper.append(atom)
    return tuple(_merge(lower)), tuple(_merge(upper))


# the public surface


def _requested_addresses(request: RequestSet) -> Ivals:
    """Every address of the request, for the forward and the return path. They
    are the source population and the addresses of each member."""
    return tuple(request.sources) + tuple(iv for m in request.members for iv in m.addresses)


def _mismatch_prefix(error: Mapping[str, Any]) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The prefix a `rib-route-mismatch` names, from its `<context>/<prefix>` subject."""
    subject = str(error.get("subject") or "")
    parts = subject.rsplit("/", 2)
    if len(parts) != 3:
        return None
    return _network(f"{parts[1]}/{parts[2]}")


def scoped_model_errors(
    errors: Iterable[Mapping[str, Any]], request: RequestSet
) -> tuple[Mapping[str, Any], ...]:
    """The model errors that concern this request.

    A RIB discrepancy is reported per prefix of the observed table. A
    discrepancy on a prefix that holds no requested address (a link-local IPv6
    route, a peer loopback, an uplink point-to-point address) is left out. A
    discrepancy whose subject cannot be parsed is kept, and so is every other
    error kind.
    """
    requested = list(_requested_addresses(request))
    out: list[Mapping[str, Any]] = []
    for error in errors:
        if error.get("kind") == "rib-route-mismatch":
            prefix = _mismatch_prefix(error)
            if prefix is not None and not _intersect(requested, _intervals([str(prefix)])):
                continue
        out.append(dict(error))
    return tuple(out)


def answer(network: Network, request: RequestSet, mode: str = POSSIBLE) -> Answer:
    """The lower and upper sets of one request set under one network."""
    if mode not in MODES:
        raise ValueError(f"mode {mode!r} is not one of {', '.join(MODES)}")
    members: dict[str, MemberAnswer] = {}
    for m in request.members:
        region = request.member_region(m)
        result = _Walk(network, mode, m.name, request).run(region)
        members[m.name] = MemberAnswer(
            m.name, region, result.proven, region.subtract(result.failed), result.explanations
        )
    lower, upper = _population(request, members)
    routes = network.routes
    return Answer(
        request,
        mode,
        lower,
        upper,
        members,
        tuple(dict(g) for g in routes.gaps)
        + ((_mtu_projection_gap(),) if request.mtu is not None and request.mtu.mode != "off" else ()),
        scoped_model_errors(routes.model_errors, request),
        tuple(
            [
                f"external advertisements remain fixed on session {uid}"
                for uid in sorted(network.routing.fixed_external_sessions)
            ]
            + [SPREAD_ASSUMPTION]
            + (
                [f"traffic arrives on declared ingress interface {request.ingress_interface_uid}"]
                if request.ingress_interface_uid
                else []
            )
        ),
    )


def apply(network: Network, delta: ChangeSet, errors: ErrorSink | None = None) -> Network:
    """The network after a change set. The routing intents go through the
    routing engine, and every other intent goes through the overlay of the
    gates."""
    routing = [i.as_dict() for i in delta.intents if i.kind in rib.INTENT_KINDS]
    changed_routing = rib.apply_intents(network.routing, routing, errors)
    after = replace(
        network,
        routing=changed_routing,
        gates=network.gates.with_changes(delta),
        changes=delta,
        baseline=network.baseline or network,
        routing_parent=network,
        routing_dirty=_routing_dirty(network.routing, changed_routing, routing),
    )
    # An overlay holds the same interfaces and shares their index.
    after.__dict__["interface_index"] = network.interface_index
    if not routing and changed_routing is network.routing and network._routing_as_observed:
        # Without a routing intent the overlay routes as its observed baseline.
        after.__dict__[_ROUTING_AS_OBSERVED] = True
    return after


def _routing_dirty(
    before: rib.RibInput,
    after: rib.RibInput,
    intents: Sequence[Mapping[str, Any]],
) -> tuple[rib.PrefixPredicate, ...]:
    """Derive conservative dirty keys for supported routing intents.

    ``apply_intents`` records the semantic closure in
    ``superseded_contexts``. Every known prefix in that closure is kept. An
    empty context receives a context-level sentinel, which the worklist
    accepts for route additions or withdrawals with no old row.
    """
    if not intents:
        return ()
    contexts = after.superseded_contexts | before.superseded_contexts
    if not contexts:
        # An intent with no observed effect has no narrow ownership proof.
        # The incremental API treats this as a full rebuild.
        return ()
    dependencies = rib.RoutingDependencies(after)
    dirty: list[rib.PrefixPredicate] = []
    for context_uid in sorted(contexts):
        predicates = sorted(dependencies.prefixes.get(context_uid, ()))
        dirty.extend(predicates or [rib.PrefixPredicate(context_uid, "")])
    return tuple(sorted(set(dirty)))


def compare(before: Answer, after: Answer) -> Impact:
    """The four differences between two answers to the same question."""
    if before.request_set != after.request_set:
        raise ValueError(
            "a comparison evaluates the same request set, with its success condition, on both sides"
        )
    if before.mode != after.mode:
        raise ValueError("a comparison holds the mode fixed on both sides")
    members = {
        name: MemberImpact(
            name,
            proven_loss=b.lower.subtract(after.members[name].upper),
            possible_loss=b.upper.subtract(after.members[name].lower),
            proven_gain=after.members[name].lower.subtract(b.upper),
            possible_gain=after.members[name].upper.subtract(b.lower),
            triage=_region_triage(b, after.members[name]),
        )
        for name, b in before.members.items()
    }
    return Impact(
        before.mode,
        before,
        after,
        proven_loss=tuple(_subtract(list(before.lower), list(after.upper))),
        possible_loss=tuple(_subtract(list(before.upper), list(after.lower))),
        proven_gain=tuple(_subtract(list(after.lower), list(before.upper))),
        possible_gain=tuple(_subtract(list(after.upper), list(before.lower))),
        members=members,
        triage=_ivals_triage(before, after),
    )


def evaluate(network: Network, delta: ChangeSet, request: RequestSet, mode: str = POSSIBLE) -> Impact:
    """The impact of a change on one request set. The same request set and the
    same mode are evaluated before and after."""
    return compare(answer(network, request, mode), answer(apply(network, delta), request, mode))
