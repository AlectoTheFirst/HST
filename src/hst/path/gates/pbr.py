"""Policy-based routing as a first-match partition of the flow space over the
ingress interface's PBR rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import zip_longest
from typing import Any

import hst.path as _path

from ..addrsets import (
    _MATCH,
    _UNKNOWN,
    _combine_and,
    _combine_or,
    _intersect,
    _port_matches,
    _proto_matches,
    _rule_intervals_status,
    _size,
    _subtract,
)
from ..state import Effect, FlowRegion, Ivals
from . import _Trail
from .firewall import (
    _NO_ADDRESS_REASON,
    _NO_SERVICE_REASON,
    _OPAQUE_SVC_FALLBACK,
    _SRC_PORT_REASON,
    _UNREAD_STATE_REASON,
    _rule_on_sport_slice,
    _service_split,
    _sport_atoms,
    _undecided_service_reason,
)

# One flow's service rectangle on the region path. The tuple holds the
# protocol set, the destination-port intervals and the source-port intervals.
# A dimension that the query leaves unset is `None`.
_ServiceBox = tuple["frozenset[int] | None", "Ivals | None", "Ivals | None"]


# The rule rows of the PbrPolicy nodes `pol` the leading MATCH binds, one row per
# enabled rule in policy name and rule position order, and one row with a null
# rule uid for a policy that holds no rule the stage can evaluate. `_pbr_partition`
# reads them for an ingress interface, and `POLICY_RULES` for named policies.
_PBR_RULE_ROWS = """OPTIONAL MATCH (pol)-[hr:HAS_RULE]->(r:FwRule)
WHERE r.enabled AND NOT r:Retired AND hr._retired_at IS NULL
// The service side is aggregated BEFORE the address side is matched, the same
// shape `firewall.py`'s `_RULEBASE_RULES` uses:
// projecting `sv.proto`/`sv.ports` un-aggregated next to the address
// `collect()`s would make them grouping keys, so a rule with two SvcObjects
// would come back as two rows and be evaluated as two sequential rules
// (an AND over its services) instead of one rule whose members are ORed.
// `svc_protos[i]` and `svc_port_specs[i]` describe the SAME member at index i.
OPTIONAL MATCH (r)-[se:SVC]->(sv:SvcObject)
WHERE se._retired_at IS NULL AND NOT sv:Retired
WITH pol, r, collect(DISTINCT sv) AS svc_members
WITH pol, r, size(svc_members) AS svc_obj_count,
     [m IN svc_members | m.proto] AS svc_protos,
     [m IN svc_members | m.ports] AS svc_port_specs,
     any(m IN svc_members WHERE coalesce(m.opaque, false)) AS svc_opaque,
     [x IN [m IN svc_members | m.opaque_reason] WHERE x IS NOT NULL] AS svc_opaque_reasons,
     // a source port is a dimension of the RULE, not an unknown member of it:
     // the protocols and ports still decide a miss with confidence, and only a
     // rule they otherwise match is left undecided
     any(m IN svc_members WHERE coalesce(m.src_port, '') <> '') AS svc_src_port,
     // member i's own source-port spec, the same index as `svc_protos[i]`, so
     // a query stating a source-port range is decided against it per member
     [m IN svc_members | m.src_port] AS svc_src_ports
// Each address side is aggregated before the next is matched, and both before
// the redirect: a group carries the closure of its members as RESOLVES_TO, so
// matching them together read |src| x |dst| x |redirects| rows per rule.
OPTIONAL MATCH (r)-[:SRC]->(so:NetObject)
OPTIONAL MATCH (so)-[:RESOLVES_TO]->(st)
WITH pol, r, svc_obj_count, svc_protos, svc_port_specs, svc_opaque, svc_opaque_reasons, svc_src_port,
     svc_src_ports,
     collect(DISTINCT st.cidr) AS src_cidrs, collect(DISTINCT st.ip) AS src_ips,
     collect(DISTINCT so.ranges) AS src_ranges, collect(DISTINCT so.opaque_reason) AS src_opaque_reasons,
     count(DISTINCT so) AS src_obj_count
OPTIONAL MATCH (r)-[:DST]->(dobj:NetObject)
OPTIONAL MATCH (dobj)-[:RESOLVES_TO]->(dt)
WITH pol, r, svc_obj_count, svc_protos, svc_port_specs, svc_opaque, svc_opaque_reasons, svc_src_port,
     svc_src_ports, src_cidrs, src_ips, src_ranges, src_opaque_reasons, src_obj_count,
     collect(DISTINCT dt.cidr) AS dst_cidrs, collect(DISTINCT dt.ip) AS dst_ips,
     collect(DISTINCT dobj.ranges) AS dst_ranges, collect(DISTINCT dobj.opaque_reason) AS dst_opaque_reasons,
     count(DISTINCT dobj) AS dst_obj_count
OPTIONAL MATCH (r)-[:REDIRECTS_VIA]->(v:VrfInstance)
// `pol_af` is the address family the policy applies to (4 or 6), null for a
// policy collected before the property existed
RETURN DISTINCT pol.uid AS pol_uid, pol.name AS pol_name, pol.af AS pol_af, r.uid AS rule_uid,
       r.position AS pos, r.name AS rule_name,
       src_cidrs, src_ips,
       dst_cidrs, dst_ips,
       src_ranges, dst_ranges, src_obj_count, dst_obj_count,
       v.uid AS table_uid, v.name AS table_name,
       svc_obj_count, svc_protos, svc_port_specs, svc_opaque, svc_opaque_reasons, svc_src_port,
       svc_src_ports,
       coalesce(r.states_opaque, false) AS states_opaque, r.states_opaque_reason AS states_opaque_reason,
       coalesce(r.src_negate, false) AS src_negate, coalesce(r.dst_negate, false) AS dst_negate,
       [x IN src_opaque_reasons + dst_opaque_reasons WHERE x IS NOT NULL] AS addr_opaque_reasons
ORDER BY pol.name, pos"""

_INTERFACE_POLICY_RULES = (
    """
MATCH (ifc:Interface {uid: $if_uid})-[e:ENFORCES]->(pol:PbrPolicy)
WHERE ifc:Obj AND ifc.collection_ts = $snap
  AND NOT pol:Retired AND e._retired_at IS NULL AND pol.collection_ts = $snap
// OPTIONAL, so a policy the interface enforces still comes back as one row
// when it holds no rule the stage can evaluate (every rule disabled or
// retired, or no rule at all). Such a policy claims nothing, but the stage
// did read it, and a mandatory match dropped it from the result and left it
// uncredited as though it sat on another interface. The evaluation loop
// skips the rows whose rule uid is null.
"""
    + _PBR_RULE_ROWS
)

# The rule rows of the PbrPolicy nodes `$pol_uids` names, in the row shape
# `partition_rules` reads. The generator's `policy_route_sources` reads the
# policies that send traffic to a table with it.
POLICY_RULES = (
    """
MATCH (pol:PbrPolicy)
WHERE pol.uid IN $pol_uids AND NOT pol:Retired AND pol:Obj AND pol.collection_ts = $snap
"""
    + _PBR_RULE_ROWS
)


def _pbr_partition(
    session: Any,
    trail: _Trail,
    if_uid: str,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None = None,
    proto: str | None = None,
    considered: list[str] | None = None,
    *,
    service: _ServiceBox | None = None,
    memo: dict[str, Any] | None = None,
    arrives: bool = True,
) -> list[dict[str, Any]]:
    """PBR on the ingress interface, evaluated first-match over the flow set.

    Each group holds its part of `service` as `proto_subset`/`port_subset`/`sport_subset`.
    `port`/`proto` are the flow tuple after destination NAT.

    `considered` receives the uid of each PbrPolicy that the read returns, once, in read order.

    `memo`, when given, keeps the interface's policy rows and default table
    for the next call on the same interface. A device visit partitions each
    destination NAT part with the same rules.

    `arrives` is False when the flow does not arrive on `if_uid` and the
    interface only selects the table the flow is routed in
    (`trace._far_gateway`). No policy of the interface is read then, and the
    whole flow set is one group in that table.
    """
    if memo is not None and if_uid in memo:
        policies, default_uid = memo[if_uid]
    else:
        policies = _path._read(session, _INTERFACE_POLICY_RULES, if_uid=if_uid) if arrives else []
        default_uid = interface_table(session, trail, if_uid)
        if memo is not None:
            memo[if_uid] = (policies, default_uid)
    if considered is not None:
        for r in policies:
            if r["pol_uid"] and r["pol_uid"] not in considered:
                considered.append(r["pol_uid"])
    return partition_rules(
        policies,
        src_set,
        dst_set,
        default_uid,
        port=port,
        proto=proto,
        service=service,
        trail=trail,
    )


def partition_rules(
    policies: list[dict[str, Any]],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    default_uid: str | None,
    *,
    port: int | None = None,
    proto: str | None = None,
    service: _ServiceBox | None = None,
    trail: _Trail | None = None,
) -> list[dict[str, Any]]:
    region = service is not None
    box: _ServiceBox = service if service is not None else (None, None, None)
    flows: list[tuple[list[tuple[int, int, int]], list[tuple[int, int, int]], _ServiceBox]] = [
        (src_set, dst_set, box)
    ]
    groups: list[dict[str, Any]] = []

    def with_box(g: dict[str, Any], fbox: _ServiceBox) -> dict[str, Any]:
        if region:
            g["proto_subset"], g["port_subset"], g["sport_subset"] = fbox
        return g

    for r in policies:
        if not r.get("rule_uid"):
            # A policy with no evaluable rule claims no part of the flow set.
            continue
        if not flows:
            break
        rule_src, src_unparsed = _rule_intervals_status(
            r.get("src_cidrs") or [], r.get("src_ips") or [], r.get("src_ranges") or []
        )
        rule_dst, dst_unparsed = _rule_intervals_status(
            r.get("dst_cidrs") or [], r.get("dst_ips") or [], r.get("dst_ranges") or []
        )
        # The address families the rule can claim. A VyOS `policy route`
        # applies to IPv4 only and a `policy route6` to IPv6 only. A policy
        # that records its family (`pol_af`) claims nothing of the other
        # family, even with no address match.
        pol_af = r.get("pol_af")
        families = {pol_af} if pol_af in (4, 6) else {i[0] for i in (*rule_src, *rule_dst)}
        # A side that lists address objects of which none has an address
        # (an address group with no member, or addresses the gate cannot
        # parse) is not read as "any address". The router's set is empty, or
        # unknown.
        no_address = any(
            not ivals and (unparsed or (count or 0) > 0)
            for ivals, unparsed, count in (
                (rule_src, src_unparsed, r.get("src_obj_count")),
                (rule_dst, dst_unparsed, r.get("dst_obj_count")),
            )
        )
        # A clause the collector could not model (`states_opaque`), or an
        # address object it could not resolve, leaves the rule undecided for a
        # flow it otherwise claims.
        undecided = "; ".join(
            x
            for x in (
                r.get("states_opaque") and (r.get("states_opaque_reason") or _UNREAD_STATE_REASON),
                *(r.get("addr_opaque_reasons") or []),
                no_address and not r.get("addr_opaque_reasons") and _NO_ADDRESS_REASON,
            )
            if x
        )
        nxt: list[tuple[list[tuple[int, int, int]], list[tuple[int, int, int]], _ServiceBox]] = []
        for srcs, dsts, fbox in flows:
            # Protocol, port and source-port criteria, read with
            # the three-valued matcher of the firewall gate.
            if region:
                decided, remainder = _service_boxes(r, fbox)
            else:
                claims, opaque_reason = _service_state(r, port, proto)
                decided, remainder = ([(fbox, opaque_reason)], []) if claims else ([], [fbox])
            if not decided:
                nxt.append((srcs, dsts, fbox))
                continue
            # a negated side claims the part of the flow its addresses exclude
            claimed = (_subtract if r.get("src_negate") else _intersect)(srcs, rule_src) if rule_src else srcs
            dst_hit = (_subtract if r.get("dst_negate") else _intersect)(dsts, rule_dst) if rule_dst else dsts
            if families:
                claimed = [i for i in claimed if i[0] in families]
                dst_hit = [i for i in dst_hit if i[0] in families]
            if not claimed or not dst_hit:
                nxt.append((srcs, dsts, fbox))
                continue
            for cbox, reason in decided:
                groups.append(
                    with_box(
                        {
                            "sources": claimed,
                            "dst": dst_hit,
                            "dst_partial": bool(rule_dst) and _size(dst_hit) < _size(dsts),
                            "pol_uid": r.get("pol_uid"),
                            "pol_name": r.get("pol_name"),
                            "rule_uid": r["rule_uid"],
                            "pos": r.get("pos"),
                            "rule_name": r.get("rule_name"),
                            "table_uid": r.get("table_uid"),
                            "table_name": r.get("table_name") or "main",
                            "opaque": bool(reason or undecided),
                            "opaque_reason": reason or undecided or None,
                        },
                        cbox,
                    )
                )
                if groups[-1]["dst_partial"] and trail is not None:
                    trail.notes.append(
                        f"PBR rule {r['pos']} matches only part of the destination "
                        f"set; its lane answers for that part only"
                    )
            rest_src = _subtract(srcs, claimed)
            if rest_src:
                nxt.append((rest_src, dsts, fbox))
            rest_dst = _subtract(dsts, dst_hit)
            if rest_dst:
                nxt.append((claimed, rest_dst, fbox))
            for rbox in remainder:
                nxt.append((claimed, dst_hit, rbox))
        flows = nxt

    for srcs, dsts, fbox in flows:
        groups.append(
            with_box(
                {
                    "sources": srcs,
                    "dst": dsts,
                    "dst_partial": False,
                    "pol_uid": None,
                    "pol_name": None,
                    "rule_uid": None,
                    "pos": None,
                    "rule_name": None,
                    "table_uid": default_uid,
                    "table_name": "default",
                    "opaque": False,
                    "opaque_reason": None,
                },
                fbox,
            )
        )
    return groups


def _as_firewall_row(r: dict[str, Any]) -> dict[str, Any]:
    """A PBR rule row's service side in the column names `_service_split`
    reads."""
    return {
        "svc_any": False,
        "svc_negate": False,
        "action": None,
        "protos": r.get("svc_protos") or [],
        "ports": r.get("svc_port_specs") or [],
        "src_ports": r.get("svc_src_ports") or [],
        "svc_opaque": bool(r.get("svc_opaque")),
        "svc_opaque_reasons": r.get("svc_opaque_reasons") or [],
        "svc_src_port": bool(r.get("svc_src_port")),
        "svc_obj_count": r.get("svc_obj_count", 0),
    }


def _service_boxes(
    r: dict[str, Any], box: _ServiceBox
) -> tuple[list[tuple[_ServiceBox, str | None]], list[_ServiceBox]]:
    """`_service_state` over one service rectangle. The result is the parts
    that the rule claims, each with the reason the claim is not settled (None
    when it is settled), and the parts the rule's service misses.
    """
    protos, ports, sports = box
    frow = _as_firewall_row(r)
    atoms: list[list[tuple[int, int, int]] | None] = (
        [None] if sports is None else list(_sport_atoms([frow], sports))
    )
    decided: list[tuple[_ServiceBox, str | None]] = []
    remainder: list[_ServiceBox] = []
    for atom in atoms:
        sport_dim: Ivals | None = None if atom is None else tuple(atom)
        srow = frow if atom is None else _rule_on_sport_slice(frow, atom)
        if srow is None:
            remainder.append((protos, ports, sport_dim))
            continue
        for kind, _action, reason, rp, rq in _service_split(
            srow, protos, None if ports is None else list(ports), False
        ):
            cbox: _ServiceBox = (rp, None if rq is None else tuple(rq), sport_dim)
            if kind == "pending":
                remainder.append(cbox)
            else:
                decided.append((cbox, reason))
    return decided, remainder


def _service_state(r: dict[str, Any], port: int | None, proto: str | None) -> tuple[bool, str | None]:
    """Whether a PBR rule's service side lets it claim this flow, and why the
    claim is not settled when it is not.

    Returns (claims, reason). `claims` False is the one confident non-match.
    Every member is known and non-opaque, and no member covers this flow. The
    caller skips the rule and the flow continues to the next rule. A reason
    means the gate does not confirm the criteria.
    """
    reason = (
        "; ".join(dict.fromkeys(x for x in r.get("svc_opaque_reasons", []) or [] if x))
        or _OPAQUE_SVC_FALLBACK
    )
    svc_opaque = bool(r.get("svc_opaque"))
    svc_src_port = bool(r.get("svc_src_port"))
    # index i of the two lists is one member's own (proto, port) pair.
    pairs = [
        (p, q) for p, q in zip_longest(r.get("svc_protos") or [], r.get("svc_port_specs") or []) if p or q
    ]
    if r.get("svc_obj_count", 0) > 0 and not pairs:
        # The rule has a service object and no member has a protocol or a port.
        if svc_opaque:
            return True, reason
        return True, _SRC_PORT_REASON if svc_src_port else _NO_SERVICE_REASON
    state = _combine_or(
        *[_combine_and(_proto_matches([p] if p else [], proto), _port_matches(q, port)) for p, q in pairs]
        or [_MATCH]  # With no SVC edge the rule matches on its addresses alone.
    )
    if state == _MATCH:
        # A source-port scope leaves the match unconfirmed.
        return True, _SRC_PORT_REASON if svc_src_port else None
    if state == _UNKNOWN:
        return True, _undecided_service_reason(pairs, port, proto, svc_opaque, reason, svc_src_port)
    if svc_opaque:
        # An unmapped member can cover this flow.
        return True, reason
    return False, None


# The routing table that an interface's own IN_VRF edge points to.
_DEFAULT_TABLE_QUERY = """
MATCH (v:VrfInstance)<-[iv:IN_VRF]-(i:Interface {uid: $if_uid})
WHERE i:Obj AND i.collection_ts = $snap
  AND NOT v:Retired AND iv._retired_at IS NULL AND v.collection_ts = $snap
RETURN v.uid AS uid ORDER BY v.uid LIMIT 1"""


def _default_table_uid(session: Any, if_uid: str) -> str | None:
    """The VrfInstance that an interface's own IN_VRF edge points to, or None
    when the interface has no such edge.
    """
    row = _path._read_one(session, _DEFAULT_TABLE_QUERY, if_uid=if_uid)
    return row["uid"] if row else None


def interface_table(session: Any, trail: _Trail, if_uid: str) -> str | None:
    """`_default_table_uid`, read once per trace for each interface."""
    if if_uid not in trail.interface_tables:
        trail.interface_tables[if_uid] = _default_table_uid(session, if_uid)
    return trail.interface_tables[if_uid]


# Every PbrPolicy this device enforces from any interface, with the interface
# it is bound to.
_DEVICE_PBR_POLICIES = """
MATCH (dev:Device {uid: $dev})<-[:ON]-(i:Interface)-[e:ENFORCES]->(pol:PbrPolicy)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND NOT pol:Retired AND e._retired_at IS NULL AND pol.collection_ts = $snap
RETURN DISTINCT pol.uid AS pol_uid, i.uid AS if_uid
ORDER BY pol_uid"""


def _other_interface_pbr_policies(session: Any, dev_uid: str, if_uid: str | None) -> list[str]:
    """PbrPolicy of this device ruled out by interface, for the leg to credit.

    A policy bound to `if_uid` itself is not returned. With `if_uid` None the
    flow arrives on no interface of the device that the graph records, and
    every policy is returned.
    """
    return [
        r["pol_uid"]
        for r in _path._read(session, _DEVICE_PBR_POLICIES, dev=dev_uid)
        if r["pol_uid"] and r["if_uid"] != if_uid
    ]


# --- the PBR stage as a transition ----------------------------------------------------


@dataclass
class PbrTransition:
    """Policy-based routing over a `FlowRegion`. It selects the table the
    flow is routed in.

    Every rectangle goes through `_pbr_partition` with its own service
    rectangle. A rule scoped to a protocol, a destination port or a source
    port decides on the values of the rectangle and claims only the part it
    covers. Each group is returned as the rectangle narrowed to the part of
    that group, with a `select` effect whose `data` is the group dict (the
    table, the rule) that the trace reads. For a claim the gate could not
    settle, the effect holds the reason and the dimensions the gate could not
    read.
    """

    session: Any
    trail: _Trail
    if_uid: str
    considered: list[str] = field(default_factory=list)

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        from .firewall import _unknown_dims

        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            groups = _pbr_partition(
                self.session,
                self.trail,
                self.if_uid,
                list(rect.src),
                list(rect.dst),
                considered=self.considered,
                service=(rect.proto, rect.dport, rect.sport),
            )
            for g in groups:
                sub = rect.narrow(
                    src=tuple(g["sources"]),
                    dst=tuple(g["dst"]),
                    proto=g["proto_subset"],
                    dport=g["port_subset"],
                    sport=g["sport_subset"],
                )
                reason = g.get("opaque_reason")
                out.append(
                    (
                        FlowRegion.single(sub),
                        Effect("select", "pbr", unknown=_unknown_dims(reason), reason=reason, data=g),
                    )
                )
        return out
