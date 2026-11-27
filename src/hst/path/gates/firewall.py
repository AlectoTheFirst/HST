"""Firewall verdicts from zone-pair rulebases and device-wide access rulebases,
and the leg-application wrapper that turns a verdict into hops and notes.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import zip_longest
from typing import Any, cast

import hst.path as _path
from hst.core.config import Settings

from ..addrsets import (
    _MATCH,
    _UNKNOWN,
    _combine_and,
    _combine_or,
    _complement,
    _iface_name_matches,
    _intersect,
    _intervals,
    _merge,
    _port_matches,
    _ports,
    _proto_matches,
    _protoset,
    _rule_intervals_status,
    _service_regions,
    _size,
    _subtract,
)
from ..checkpoint_installation import candidates as installed_candidates
from ..state import Effect, FlowRegion, Ivals, Rect, port_spec, proto_spec
from ..verdict import DENY, INDETERMINATE, PERMIT, classify_action
from . import Stage, _Trail, forwarding_visit

logger = logging.getLogger(__name__)

_RULEBASE_RULES = """
MATCH (rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)
WHERE rb:Obj AND rb.collection_ts = $snap
  AND r.enabled AND NOT r:Retired AND hr._retired_at IS NULL
  AND r.collection_ts = $snap
// a service-column object that is not a SvcObject at all: a Check Point
// application-site a graph collected before checkpoint.py read the service
// column wrote as a NetObject. The SvcObject read below never sees it, and
// counted as no service the rule would match every port on its addresses,
// so it counts as a service member that is not modeled (svc_opaque below).
// Such a graph wrote an application inside a service group the same way, as
// a NetObject member of the SvcObject group, which the member read below
// never sees either; it counts as an unmodeled member too.
WITH r, [(r)-[sx:SVC]->(x) WHERE NOT x:SvcObject AND NOT x:Retired AND sx._retired_at IS NULL
         | coalesce(x.name, x.uid)]
        + COLLECT {
            MATCH p_fx = (r)-[:SVC]->(:SvcObject)<-[:MEMBER_OF*1..16]-(x)
            WHERE NOT x:SvcObject AND NOT x:Retired
              AND all(n IN nodes(p_fx) WHERE NOT n:Retired)
              AND all(rel IN relationships(p_fx) WHERE rel._retired_at IS NULL)
            RETURN coalesce(x.name, x.uid)
          } AS svc_foreign
OPTIONAL MATCH (r)-[:SVC]->(sv0:SvcObject)
// sv0 itself (0 hops), or -- when sv0 is a service-group, nested groups included --
// every member within a bounded depth. MEMBER_OF points member -> group, so the
// traversal runs from a member up to sv0. A member whose kind the collector could
// not map carries no proto or port at all, and one whose port spec it could not
// parse carries a port no comparison can satisfy; either way the member sets
// opaque=True and marks the union as not fully known (svc_opaque below).
// same retirement filters app/fw_overlay_read.py applies to a single-hop
// MEMBER_OF (mo._retired_at IS NULL AND NOT m:Retired), carried over every
// edge and every intermediate node of this bounded-depth traversal.
OPTIONAL MATCH p_svm = (svm:SvcObject)-[:MEMBER_OF*0..16]->(sv0)
WHERE all(n IN nodes(p_svm) WHERE NOT n:Retired)
  AND all(rel IN relationships(p_svm) WHERE rel._retired_at IS NULL)
// INVARIANT: the members are materialized ONCE here and every
// service column below is projected from that one list, so `protos[i]` and
// `ports[i]` describe the SAME member at every index i and `_first_match` can
// zip them into per-member pairs. Two independent
// `collect(DISTINCT svm.proto)` / `collect(DISTINCT svm.ports)` calls dedupe
// each column on its own, which crosses one member's protocol against another
// member's port: a rule for a service group of tcp/443 and udp/53 then matched
// tcp/53 as well. A null on one side of a pair means that dimension is
// unconstrained for that member (a VyOS port-group SvcObject carries ports and
// no proto); a member null on both -- the group's own node, an unmapped kind --
// constrains nothing and `_first_match` drops the whole pair. The service side
// is aggregated before the address side is matched so the two cross products
// never multiply into each other.
WITH r, count(DISTINCT sv0) + size(svc_foreign) AS svc_obj_count, collect(DISTINCT svm) AS svc_members,
     svc_foreign
WITH r, svc_obj_count,
     [m IN svc_members | m.proto] AS protos,
     [m IN svc_members | m.ports] AS ports,
     size(svc_foreign) > 0 OR any(m IN svc_members WHERE coalesce(m.opaque, false)) AS svc_opaque,
     [x IN [m IN svc_members | m.opaque_reason] WHERE x IS NOT NULL]
       + [x IN svc_foreign | 'service object ' + x + ' is not modeled as a protocol and port']
       AS svc_opaque_reasons,
     // whether any member is scoped to a source port. That is a dimension of
     // the rule, not an unknown member of it: the protocols and ports above
     // still decide a miss with confidence, and only a rule they otherwise
     // match is undecided.
     any(m IN svc_members WHERE coalesce(m.src_port, '') <> '') AS svc_src_port,
     // the same member's own source-port spec beside its protocol and port,
     // projected from the one member list so `src_ports[i]` is member i's:
     // a query that states a source-port range is decided against it slice
     // by slice (`_first_match_by_sport`), and a query that states none keeps
     // reading the rule as undecided through `svc_src_port` above.
     [m IN svc_members | m.src_port] AS src_ports
// The source side is aggregated before the destination side is matched, for
// the same reason: a group carries the closure of its members as RESOLVES_TO,
// and matching both sides before one aggregation read |src| x |dst| rows per
// rule, a million for a rule between two groups of a thousand.
OPTIONAL MATCH (r)-[:SRC]->(so:NetObject) OPTIONAL MATCH (so)-[:RESOLVES_TO]->(st)
WITH r, svc_obj_count, protos, ports, svc_opaque, svc_opaque_reasons, svc_src_port, src_ports,
     collect(DISTINCT st.cidr) AS src_cidrs, collect(DISTINCT st.ip) AS src_ips,
     collect(DISTINCT so.ranges) AS src_ranges, count(DISTINCT so) AS src_obj_count,
     any(x IN collect(DISTINCT so.opaque) WHERE x) AS src_opaque,
     [x IN collect(DISTINCT so.opaque_reason) WHERE x IS NOT NULL] AS src_opaque_reasons
OPTIONAL MATCH (r)-[:DST]->(do:NetObject) OPTIONAL MATCH (do)-[:RESOLVES_TO]->(dt)
RETURN r.uid AS uid, r.position AS pos, r.action AS action, r.name AS name,
       r.jump_target AS jump_target,
       r.out_interface AS out_if, r.in_interface AS in_if,
       r.out_interface_group AS out_if_group, r.in_interface_group AS in_if_group,
       coalesce(r.states, []) AS states,
       coalesce(r.states_opaque, false) AS states_opaque,
       r.states_opaque_reason AS states_opaque_reason,
       coalesce(r.unmodeled_fields, []) AS unmodeled_fields,
       coalesce(r.install_on, []) AS install_on,
       coalesce(r.install_on_unresolved, false) AS install_on_unresolved,
       coalesce(r.src_any, false) AS src_any, coalesce(r.dst_any, false) AS dst_any,
       coalesce(r.svc_any, false) AS svc_any,
       r.svc_any IS NOT NULL AS svc_any_stated,
       coalesce(r.src_negate, false) AS src_negate, coalesce(r.dst_negate, false) AS dst_negate,
       coalesce(r.svc_negate, false) AS svc_negate,
       src_cidrs, src_ips,
       collect(DISTINCT dt.cidr) AS dst_cidrs, collect(DISTINCT dt.ip) AS dst_ips,
       protos, ports, svc_opaque, svc_opaque_reasons, svc_src_port, src_ports,
       src_ranges, collect(DISTINCT do.ranges) AS dst_ranges,
       src_obj_count, count(DISTINCT do) AS dst_obj_count,
       svc_obj_count,
       src_opaque,
       any(x IN collect(DISTINCT do.opaque) WHERE x) AS dst_opaque,
       src_opaque_reasons,
       [x IN collect(DISTINCT do.opaque_reason) WHERE x IS NOT NULL] AS dst_opaque_reasons
ORDER BY pos"""


# Why a rule could not be decided, in the words the leg note prints.
_NO_ADDRESS_REASON = "referenced objects carry no address"
_EMPTY_SIDE_REASON = "this side is not Any and lists no address object"
_NO_SERVICE_REASON = "referenced services carry no protocol or port"
_UNPARSED_ADDRESS_REASON = "the addresses this rule lists could not be parsed"
_NO_PROTO_REASON = "the query carries no protocol, and this rule's service is scoped to one"
_NO_PORT_REASON = "the query carries no destination port, and this rule's service is scoped to one"
# A rule matching on a source port is a confident non-match when the protocol or
# the destination port misses.
_SRC_PORT_REASON = "the rule matches on a source port the flow does not carry"
_UNDECIDED_SERVICE_REASON = "this rule's service is scoped to more than the query states"
_UNKNOWN_DEFAULT_REASON = "the chain's default action is not recorded"
# a rulebase or zone whose collector wrote neither its default action nor the
# marker for an unrecorded one.
_UNSTATED_DEFAULT_REASON = "the collection states neither the default action nor that it is unrecorded"
# the subjects `_unstated_default` has logged
_UNSTATED_LOGGED: set[str] = set()
_UNSTATED_LOGGED_MAX = 4096
# a reply that no listed rule decided, on a device whose connection-state
# rules the collection does not report (a UniFi gateway's predefined
# established/related rules)
_UNREPORTED_STATE_RULES_REASON = (
    "the device's predefined connection-state rules are not reported by its controller, "
    "so whether they admit this reply is not known"
)
_IFACE_GROUP_REASON = "the rule's interface-group scope is not collected"
# a rule scoped to an interface on a side of the leg whose interface name did
# not resolve
_IFACE_UNRESOLVED_REASON = (
    "the rule is scoped to {side} interface {scope!r}; this leg's {side} interface name did not resolve"
)
_NEGATED_EMPTY_SERVICE_REASON = "this rule's service is negated and lists no service object"
# The rule records `svc_any` false and has no SVC edge (`svc_any_stated`).
_EMPTY_SERVICE_REASON = "the service side is not Any and lists no service object"
# a rule whose connection state clause the collector could not read
_UNREAD_STATE_REASON = "the rule's connection state clause could not be read"
# a rule with vendor fields its normalizer does not model (`unmodeled_fields`)
_UNMODELED_FIELDS_REASON = "the rule also matches on {fields}, which is not modeled"
# a Check Point rule whose install-on column could not be compared with the
# gateway judging the flow
_INSTALL_ON_REASON = "the rule's install-on column names a target that is not resolved to this gateway"
_REGION_CAP_REASON = (
    "the partition stopped at {cap} regions, the path_region_cap setting; "
    "narrow the port or protocol query for a full answer"
)
# an object marked opaque whose reason the collector did not record
_OPAQUE_FALLBACK = "an object on this side is not modeled as an address set"
_OPAQUE_SVC_FALLBACK = "a referenced service is not modeled as a protocol and port"


def _undecided_service_reason(
    pairs: list[tuple[Any, Any]],
    port: Any,
    proto: Any,
    svc_opaque: bool,
    svc_reason: str,
    svc_src_port: bool = False,
) -> str:
    """Why an undecided service side could not be read, in the leg note's words.

    `port` and `proto` are each a scalar flow value or a region's subset. The
    function reads only whether each is None.
    """
    reasons = []
    if proto is None and any(p for p, _ in pairs):
        reasons.append(_NO_PROTO_REASON)
    if port is None and any(q for _, q in pairs):
        reasons.append(_NO_PORT_REASON)
    if svc_src_port:
        reasons.append(_SRC_PORT_REASON)
    if svc_opaque:
        reasons.append(svc_reason)
    return "; ".join(dict.fromkeys(reasons)) or _UNDECIDED_SERVICE_REASON


def _firewall_verdict(
    session: Any,
    dev_uid: str,
    in_if: str,
    out_if: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | None,
    considered: list[str] | None = None,
    *,
    conn_state: str = "new",
    src_port: Any = None,
    acl_direction: str | None = None,
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """The firewall verdict for this flow, from either rulebase model.

    `acl_direction` is the interface-ACL binding this stage judges, or None
    for both. It is passed to `_device_rulebase_verdict`.

    `src_port` is the flow's source port when the caller states one. A stated
    `src_port` returns a list of regions.

    Rulebases reach a flow in two shapes:

      1. Zone pair: (:Interface)<-[:CONTAINS]-(:Zone) with the rulebase joined by
         FROM_ZONE/TO_ZONE.
      2. Device-enforced: (:Device)-[:ENFORCES]->(:FwRulebase {kind:'access'}).

    Returns None only when no rulebase governs the device.

    A device with a zone policy and a device-wide rulebase whose chain the
    graph records is governed by both. A chain-less device-wide rulebase
    beside a zone policy is not credited.

    A scalar `port` and `proto` return a single dict or None. A range returns
    a list of dicts, one per decided region.

    `considered` is extended with every other zone-bound rulebase of the
    device and with the device's input and output chains.
    """
    af = (dst_set or src_set)[0][0] if (dst_set or src_set) else 4
    zoned = _zone_pair_verdict(
        session, in_if, out_if, src_set, dst_set, port, proto, af, conn_state=conn_state, src_port=src_port
    )
    if considered is not None:
        # The flow's (ingress zone, egress zone) pair rules out every other zone-bound
        # rulebase of the device.
        src_zone, dst_zone = _zone_of(session, in_if), _zone_of(session, out_if)
        if src_zone and dst_zone:
            considered.extend(
                _other_zone_pair_rulebases(session, dev_uid, (src_zone["name"], dst_zone["name"]), af)
            )
        # A forwarded packet crosses the forward chain only. The device's input
        # and output chains are ruled out by chain. `_firewall_verdict_local`
        # rules out the forward chain in the same way.
        considered.extend(_other_chain_rulebases(session, dev_uid, "forward", in_if))
    device = _device_rulebase_verdict(
        session,
        dev_uid,
        in_if,
        out_if,
        src_set,
        dst_set,
        port,
        proto,
        af,
        considered=considered,
        require_chain=zoned is not None,
        conn_state=conn_state,
        src_port=src_port,
        acl_direction=acl_direction,
    )
    if zoned is None or device is None:
        return zoned if device is None else device
    return _both_rulebase_models(zoned, device, considered)


def _both_rulebase_models(
    zoned: dict[str, Any] | list[dict[str, Any]],
    device: dict[str, Any] | list[dict[str, Any]],
    considered: list[str] | None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """One verdict for a device whose zone policy and device-wide chain both
    govern this flow.

    The chain is the first candidate and decides a tie. Selection is a deny
    from either, then an undecided from either, then a permit that covers
    only part of the flow, else the first.

    Both rulebases are credited through `considered`. `models` holds both
    verdicts in device order.
    """
    if considered is not None:
        for v in (device, zoned):
            for region in v if isinstance(v, list) else [v]:
                if region.get("rb_uid") and region["rb_uid"] not in considered:
                    considered.append(region["rb_uid"])
    if isinstance(zoned, list) or isinstance(device, list):
        regions = _refine_regions(
            cast("list[dict[str, Any]]", device if isinstance(device, list) else [device]),
            cast("list[dict[str, Any]]", zoned if isinstance(zoned, list) else [zoned]),
        )
        return _cap_candidate_regions(
            _merge_candidate_regions_by_outcome(regions), Settings().path_region_cap
        )
    ordered = [device, zoned]
    decided = next(
        (r for wanted in (DENY, INDETERMINATE) for r in ordered if classify_action(r["action"]) == wanted),
        _permit_pick(ordered),
    )
    return {**decided, "models": ordered}


def _rb_af(row: dict[str, Any]) -> int | None:
    """The address family a rulebase judges, or None for both or unknown.

    Without `af` the uid convention (`fw:ipv6:<name>` / `fw:ipv6-<chain>`)
    decides.
    """
    if row.get("af"):
        return row["af"]
    return 6 if ":ipv6" in (row.get("rb_uid") or "") else None


_ZONE_OF_INTERFACE = """
MATCH (iin:Interface {uid: $in_if})<-[c:CONTAINS]-(z:Zone)
WHERE iin:Obj AND iin.collection_ts = $snap
  AND NOT z:Retired AND c._retired_at IS NULL AND z.collection_ts = $snap
RETURN z.name AS name, z.default_action AS default_action,
       z.default_action_unknown AS default_action_unknown,
       z.established_default_unknown AS established_default_unknown,
       z.intra_zone_filtering AS intra_zone_filtering, z.intra_zone_action AS intra_zone_action
ORDER BY z.name LIMIT 1"""


def _zone_of(session: Any, if_uid: str | None) -> dict[str, Any] | None:
    """The zone containing an interface (name and default action), or None."""
    if not if_uid:
        return None
    return _path._read_one(session, _ZONE_OF_INTERFACE, in_if=if_uid)


def _intra_zone_verdict(zone: dict[str, Any]) -> dict[str, Any] | None:
    """The verdict on traffic between two interfaces of one zone that no
    ruleset bound as the pair (Z, Z) decides for the flow's family, or None
    when the graph does not record the zone's intra-zone filtering.

    A zone that states no intra-zone filtering lets traffic within it pass.
    A zone that filters by a ruleset for the other address family only is
    undecided."""
    recorded = zone.get("intra_zone_filtering")
    if recorded is None:
        return None
    name = zone["name"]
    action, why, by = zone.get("intra_zone_action"), None, "intra-zone-filtering"
    if not action and not recorded:
        action, by = "accept", "intra-zone default"
    elif not action:
        action = INDETERMINATE
        why = f"zone {name} filters traffic within it by a ruleset for the other address family only"
    return {
        # a synthetic uid, as the unbound zone pair has
        "rb_uid": f"zone-pair:{name}->{name}#intra",
        "rb_name": f"{name} intra-zone policy",
        "zones": f"{name}→{name}",
        "rule_uid": None,
        "pos": None,
        "action": action,
        "rule_name": None,
        "by": by,
        "partial": False,
        "indeterminate_reason": why,
    }


def _unstated_default(subject: str) -> tuple[str, str]:
    """(INDETERMINATE, reason) for a fall-through onto a rulebase or zone that
    states neither `default_action` nor `default_action_unknown`.

    It is logged once per subject."""
    if subject not in _UNSTATED_LOGGED and len(_UNSTATED_LOGGED) < _UNSTATED_LOGGED_MAX:
        _UNSTATED_LOGGED.add(subject)
        logger.warning(
            "firewall gate: %s states neither default_action nor default_action_unknown; "
            "a flow no rule matches is read as undecided",
            subject,
        )
    return INDETERMINATE, _UNSTATED_DEFAULT_REASON


def _zone_default(default_action: Any, unknown: Any, subject: str = "a zone") -> tuple[str, str | None]:
    """(action, reason) for a fall-through onto a zone's own default-action.

    A zone without a recorded default-action is undecided.
    """
    if default_action:
        return default_action, None
    if unknown:
        return INDETERMINATE, _UNKNOWN_DEFAULT_REASON
    return _unstated_default(subject)


def _state_rules_unreported(holder: dict[str, Any] | None, conn_state: str, key: str) -> bool:
    """Whether a fall-through in `conn_state` meets connection-state rules the
    collection does not report.

    `key` is the marker the collector writes on the rulebase or zone
    (`established_default_unknown`). The result is False for a new flow. Those
    rules match only established and related traffic."""
    return conn_state in ("established", "related") and bool((holder or {}).get(key))


def _fallthrough(action: str, why: str | None, unreported: bool) -> tuple[str, str | None]:
    """A fall-through's (action, reason), made undecided for a reply on a
    device whose connection-state rules are not reported."""
    if unreported and classify_action(action) != PERMIT:
        return INDETERMINATE, _UNREPORTED_STATE_RULES_REASON
    return action, why


def state_policy_text(policy: list[str] | tuple[str, ...], basis: str | None) -> str:
    """The text a leg note uses for a device's state policy.

    The text is the recorded setting. For a vendor whose state handling is
    fixed (Check Point), the text names the setting as the vendor's fixed
    stateful behaviour."""
    if basis == "vendor-default":
        return f"{', '.join(policy)}, the vendor's fixed stateful behaviour, not a collected setting"
    return ", ".join(policy)


def _interface_names(session: Any, in_if: str, out_if: str | None) -> tuple[str | None, str | None]:
    names = _path._read(
        session,
        "MATCH (i:Interface) WHERE i.uid IN [$a, $b] AND i:Obj AND i.collection_ts = $snap "
        "RETURN i.uid AS uid, i.name AS name",
        a=in_if,
        b=out_if,
    )
    by_uid = {n["uid"]: n["name"] for n in names}
    return by_uid.get(in_if), by_uid.get(out_if)


# The zone model's rules have no `*_any` flags. The rules query coalesces them to false.
def _net_side(
    any_flag: bool,
    obj_count: int,
    opaque: bool,
    negate: bool,
    reasons: list[str],
    rule_ivals: list[tuple[int, int, int]],
    flow_set: list[tuple[int, int, int]],
) -> tuple[list[tuple[int, int, int]] | None, bool, str | None]:
    """(hit, gap, reason) for one NetObject side (SRC or DST).

    `obj_count` is 0 for a rule with no SRC (or DST) NetObject edge. A
    side with no objects, no inline addresses and no Any flag is undecided.

    When the side lists objects, the known, non-opaque members decide the
    match wherever they can.

    The complement of a negated side is taken over the flow's address
    families. A negated side that is also opaque is a confident non-match
    only when the known members cover the whole flow set."""
    if any_flag:
        return ([] if negate else flow_set), False, None
    flow_afs = {i[0] for i in flow_set}
    opaque_reason = "; ".join(dict.fromkeys(x for x in reasons if x)) or _OPAQUE_FALLBACK

    def against_complement() -> list[tuple[int, int, int]]:
        return _intersect(flow_set, _complement(rule_ivals, flow_afs))

    if obj_count <= 0:
        if not rule_ivals:
            return None, True, _EMPTY_SIDE_REASON
        return (against_complement() if negate else _intersect(flow_set, rule_ivals)), False, None
    known_hit = _intersect(flow_set, rule_ivals) if rule_ivals else []
    if known_hit:
        # the known, non-opaque members decide this side
        if not negate:
            return known_hit, False, None
        rest = against_complement()
        if not opaque or not rest:
            return rest, False, None
        return None, True, opaque_reason
    if opaque:
        return None, True, opaque_reason
    if not rule_ivals:
        return None, True, _NO_ADDRESS_REASON
    return (against_complement() if negate else []), False, None


def _unwrap_single(value: Any) -> Any:
    """A one-element list as the one value it holds."""
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def _states_a_range(port: Any, proto: Any) -> bool:
    """Whether a query's port or protocol states a range.

    The shape of the value decides it. The function parses nothing.
    """
    if isinstance(proto, frozenset | set) or (isinstance(proto, list) and len(proto) > 1):
        return True
    if isinstance(port, frozenset | set):
        return True
    if isinstance(port, list):
        return len(port) > 1
    if not isinstance(port, str):
        return False
    s = port.strip().lower()
    return "-" in s or "," in s or s == "any"


def _as_protoset(proto: Any) -> tuple[frozenset[int] | None, bool]:
    """The query's protocol as a concrete set, and whether it states a range.

    `None` and an empty list mean the query states nothing about protocol.

    A protocol name that is not in the protocol table raises ValueError.
    """
    if proto is None or proto == "" or (isinstance(proto, list | set | frozenset) and not proto):
        return None, False
    specs = [str(p) for p in proto] if isinstance(proto, list | set | frozenset) else [str(proto)]
    return _protoset(specs), _states_a_range(None, proto)


def _as_portset(port: Any) -> tuple[list[tuple[int, int, int]] | None, bool]:
    """The query's destination port as concrete intervals, and whether it
    states a range. `None`, an empty string and an empty list, set or
    frozenset state nothing about it.
    """
    if port is None or port == "" or (isinstance(port, list | set | frozenset) and not port):
        return None, False
    spec = list(port) if isinstance(port, set | frozenset) else port
    return _ports(spec), _states_a_range(port, None)


def _iface_scope(
    r: dict[str, Any], in_name: str | None, out_name: str | None, unresolved: frozenset[str]
) -> tuple[bool, str | None]:
    """(skip, reason) for a rule's interface-name scope on this leg.

    `skip` is a confident miss. `unresolved` names the sides ('in', 'out')
    whose interface name did not resolve. A scope on such a side gives a
    `reason` and no skip."""
    reasons = []
    for side, scope, name in (("out", r["out_if"], out_name), ("in", r["in_if"], in_name)):
        if not scope or _iface_name_matches(scope, name):
            continue
        if name is not None or side not in unresolved:
            return True, None
        reasons.append(
            _IFACE_UNRESOLVED_REASON.format(side="egress" if side == "out" else "ingress", scope=scope)
        )
    return False, "; ".join(reasons) or None


def _first_match(
    rules: list[dict[str, Any]],
    in_name: str | None,
    out_name: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | None,
    state_skips: list[dict[str, Any]] | None = None,
    *,
    conn_state: str = "new",
    unresolved: frozenset[str] = frozenset(),
) -> (
    tuple[dict[str, Any], list[tuple[int, int, int]], list[tuple[int, int, int]]]
    | list[_DecidedRegion]
    | None
):
    """The first rule that matches the flow, with the parts of the sets it hit.

    A scalar `port`/`proto` returns `(rule, src_hit, dst_hit) | None`. A
    range returns a list of `(rule, src_hit, dst_hit, proto_subset,
    port_subset)` entries, one per decided region. `rule` is None for a
    region no rule decided.

    `state_skips`, when given, receives one entry per rule that is skipped
    because it is scoped to a connection state the traced flow does not have.

    `conn_state` is the connection state this evaluation models.

    `unresolved` names the sides of the leg whose interface name did not
    resolve (`_iface_scope`). The default is no side.
    """
    port, proto = _unwrap_single(port), _unwrap_single(proto)
    if _states_a_range(port, proto):
        return _first_match_regions(
            rules,
            in_name,
            out_name,
            src_set,
            dst_set,
            _as_protoset(proto)[0],
            _as_portset(port)[0],
            state_skips,
            conn_state=conn_state,
            unresolved=unresolved,
        )
    return _first_match_point(
        rules,
        in_name,
        out_name,
        src_set,
        dst_set,
        cast("int | None", port),
        cast("str | None", proto),
        state_skips,
        conn_state=conn_state,
        unresolved=unresolved,
    )


def _first_match_point(
    rules: list[dict[str, Any]],
    in_name: str | None,
    out_name: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    state_skips: list[dict[str, Any]] | None = None,
    *,
    conn_state: str = "new",
    unresolved: frozenset[str] = frozenset(),
) -> tuple[dict[str, Any], list[tuple[int, int, int]], list[tuple[int, int, int]]] | None:
    """The point path of `_first_match`, which returns one verdict for one scalar flow."""
    skips = [] if state_skips is None else state_skips
    net_side = _net_side

    for r in rules:
        # The interface scope is a literal name, a trailing-'*' wildcard, a leading-'!'
        # negation, or both combined.
        skip, iface_unresolved = _iface_scope(r, in_name, out_name, unresolved)
        if skip:
            continue
        # A rule scoped to a state set that excludes the modeled state is skipped.
        states = r.get("states") or []
        if states and conn_state not in states:
            skips.append({"pos": r["pos"], "states": list(states)})
            continue
        # svc_negate is read before the svc_any guard. A negated Any excludes every flow.
        svc_negate = r.get("svc_negate", False)
        if r["svc_any"] and svc_negate:
            continue
        svc_undecided: str | None = None
        if not r["svc_any"]:
            # Index i of protos and of ports is one member's own (proto, port) pair.
            pairs = [(p, q) for p, q in zip_longest(r["protos"] or [], r["ports"] or []) if p or q]
            svc_opaque = r.get("svc_opaque", False)
            svc_src_port = r.get("svc_src_port", False)
            svc_reason = (
                "; ".join(dict.fromkeys(x for x in r.get("svc_opaque_reasons", []) or [] if x))
                or _OPAQUE_SVC_FALLBACK
            )
            if r.get("svc_obj_count", 0) > 0 and not pairs:
                # the rule names services and none contributes a protocol or a port
                if svc_opaque:
                    svc_undecided = svc_reason
                elif svc_src_port:
                    svc_undecided = _SRC_PORT_REASON
                else:
                    svc_undecided = _NO_SERVICE_REASON
            elif not pairs and not svc_negate and r.get("svc_any_stated"):
                svc_undecided = _EMPTY_SERVICE_REASON
            else:
                # The un-negated predicate over the known members is computed first.
                # Opacity is a property of the side and is decided before the negation.
                # Each member's own protocol goes with that member's own port, and the
                # pairs are ORed. A group of tcp/443 and udp/53 does not cover tcp/53.
                state = _combine_or(
                    *[
                        _combine_and(_proto_matches([p] if p else [], proto), _port_matches(q, port))
                        for p, q in pairs
                    ]
                    # A rule with no SVC edge and no recorded `svc_any` matches
                    # on its addresses alone.
                    or [_MATCH]
                )
                if state == _MATCH:
                    if svc_src_port:
                        # the complement of an undecided side is undecided
                        svc_undecided = _SRC_PORT_REASON
                    elif svc_negate and not pairs:
                        # The side is negated and lists no service object. The
                        # collection does not record what the rule excludes.
                        svc_undecided = _NEGATED_EMPTY_SERVICE_REASON
                    elif svc_negate:
                        continue  # the known members are exactly what the rule excludes
                elif state == _UNKNOWN:
                    svc_undecided = _undecided_service_reason(
                        pairs, port, proto, svc_opaque, svc_reason, svc_src_port
                    )
                elif svc_opaque:
                    svc_undecided = svc_reason
                elif not svc_negate:
                    continue
        # `src_any` is the vendor's explicit Any.
        rule_src, src_unparsed = _rule_intervals_status(r["src_cidrs"], r["src_ips"], r["src_ranges"])
        rule_dst, dst_unparsed = _rule_intervals_status(r["dst_cidrs"], r["dst_ips"], r["dst_ranges"])
        if src_unparsed or dst_unparsed:
            return (
                {**r, "action": INDETERMINATE, "indeterminate_reason": _UNPARSED_ADDRESS_REASON},
                src_set,
                dst_set,
            )
        src_hit, src_gap, src_why = net_side(
            r["src_any"],
            r.get("src_obj_count", 0),
            r.get("src_opaque", False),
            r.get("src_negate", False),
            r.get("src_opaque_reasons") or [],
            rule_src,
            src_set,
        )
        dst_hit, dst_gap, dst_why = net_side(
            r["dst_any"],
            r.get("dst_obj_count", 0),
            r.get("dst_opaque", False),
            r.get("dst_negate", False),
            r.get("dst_opaque_reasons") or [],
            rule_dst,
            dst_set,
        )
        # The addresses decide before an undecided service.
        if src_gap or dst_gap:
            # An undecided service is named ahead of the address gap.
            why = svc_undecided or "; ".join(dict.fromkeys(x for x in (src_why, dst_why) if x))
            return {**r, "action": INDETERMINATE, "indeterminate_reason": why}, src_set, dst_set
        if not src_hit or not dst_hit:
            continue
        if svc_undecided is not None:
            return (
                {**r, "action": INDETERMINATE, "indeterminate_reason": svc_undecided},
                src_set,
                dst_set,
            )
        scope_reason = _scope_reason(r)
        if scope_reason:
            # The scope is read after the addresses and the service.
            return (
                {
                    **r,
                    "action": INDETERMINATE,
                    "indeterminate_reason": scope_reason,
                },
                src_set,
                dst_set,
            )
        # The interface-group scope is read last.
        if r.get("out_if_group") or r.get("in_if_group") or iface_unresolved:
            return (
                {
                    **r,
                    "action": INDETERMINATE,
                    "indeterminate_reason": _IFACE_GROUP_REASON
                    if r.get("out_if_group") or r.get("in_if_group")
                    else iface_unresolved,
                },
                src_set,
                dst_set,
            )
        return r, src_hit, dst_hit
    return None


def _boxes_outside_claim(
    region_proto: frozenset[int] | None,
    region_port: list[tuple[int, int, int]] | None,
    claim_proto: frozenset[int],
    claim_port: list[tuple[int, int, int]],
) -> list[tuple[frozenset[int] | None, list[tuple[int, int, int]] | None]]:
    """A pending (proto, port) region with one claimed rectangle carved out.

    Returns up to two disjoint boxes covering everything the claim did not.
    A region dimension that is `None` stays `None` on the box that keeps it.
    """
    boxes: list[tuple[frozenset[int] | None, list[tuple[int, int, int]] | None]] = []
    proto_outside = frozenset() if region_proto is None else (region_proto - claim_proto)
    if proto_outside:
        boxes.append((proto_outside, region_port))
    port_outside = [] if region_port is None else _subtract(region_port, claim_port)
    if port_outside:
        box_proto = region_proto if region_proto is None else claim_proto
        boxes.append((box_proto, port_outside))
    return boxes


# One rectangle's outcome against one rule's service side, with `kind` "match",
# "undecided" or "pending".
_ServiceSplitEntry = tuple[
    str, str, "str | None", "frozenset[int] | None", "list[tuple[int, int, int]] | None"
]

# One undecided rectangle of the query: the protocols and the ports it covers.
_RegionBox = tuple["frozenset[int] | None", "list[tuple[int, int, int]] | None"]

# One decided region with the rule that decided it, the address parts it hit,
# and the rectangle itself. The rule is None for a region that no rule in the
# walk claimed. The caller answers such a region with its own default action.
_DecidedRegion = tuple[
    "dict[str, Any] | None",
    "list[tuple[int, int, int]]",
    "list[tuple[int, int, int]]",
    "frozenset[int] | None",
    "list[tuple[int, int, int]] | None",
]


def _service_split(
    r: dict[str, Any],
    proto_sub: frozenset[int] | None,
    port_sub: list[tuple[int, int, int]] | None,
    svc_negate: bool,
) -> list[_ServiceSplitEntry]:
    """One pending region partitioned by one rule's service side.

    The caller does not pass a rule whose `svc_any` is negated.
    """
    if r["svc_any"]:
        return [("match", r["action"], r.get("indeterminate_reason"), proto_sub, port_sub)]

    pairs = [(p, q) for p, q in zip_longest(r["protos"] or [], r["ports"] or []) if p or q]
    svc_opaque = r.get("svc_opaque", False)
    svc_src_port = r.get("svc_src_port", False)
    svc_reason = (
        "; ".join(dict.fromkeys(x for x in r.get("svc_opaque_reasons", []) or [] if x))
        or _OPAQUE_SVC_FALLBACK
    )
    if r.get("svc_obj_count", 0) > 0 and not pairs:
        reason = svc_reason if svc_opaque else (_SRC_PORT_REASON if svc_src_port else _NO_SERVICE_REASON)
        return [("undecided", INDETERMINATE, reason, proto_sub, port_sub)]
    if not pairs and svc_negate:
        # A negated side with no service object is undecided, as in the point
        # path.
        return [("undecided", INDETERMINATE, _NEGATED_EMPTY_SERVICE_REASON, proto_sub, port_sub)]
    if not pairs and r.get("svc_any_stated"):
        return [("undecided", INDETERMINATE, _EMPTY_SERVICE_REASON, proto_sub, port_sub)]
    if not pairs:
        # A rule with no SVC edge and no recorded `svc_any` matches on its
        # addresses alone.
        return [("match", r["action"], r.get("indeterminate_reason"), proto_sub, port_sub)]

    regions = _service_regions(pairs, proto_sub, port_sub)
    out: list[_ServiceSplitEntry] = []
    remaining: list[_RegionBox] = [(proto_sub, port_sub)]
    for crp, crq in regions.claimed:
        # Each member claims only the part of the rectangle the members before it left.
        still: list[_RegionBox] = []
        for rp, rq in remaining:
            mine_p, p_empty = _meet_proto(rp, crp)
            mine_q, q_empty = _meet_port(rq, crq)
            if p_empty or q_empty or mine_p is None or mine_q is None:
                still.append((rp, rq))
                continue
            # a dimension the query does not state keeps its `None`
            claim_p = rp if rp is None else mine_p
            claim_q = rq if rq is None else mine_q
            if svc_src_port:
                out.append(("undecided", INDETERMINATE, _SRC_PORT_REASON, claim_p, claim_q))
            elif svc_negate:
                # The known members are exactly what the rule excludes. The
                # rectangle goes on to the next rule as a pending rectangle.
                out.append(("pending", "", None, claim_p, claim_q))
            else:
                out.append(("match", r["action"], r.get("indeterminate_reason"), claim_p, claim_q))
            still.extend(_boxes_outside_claim(rp, rq, mine_p, mine_q))
        remaining = still

    if regions.unknown_dims:
        # A member is scoped to a dimension that this part of the query does
        # not state. Every remaining rectangle is undecided.
        reason = _undecided_service_reason(pairs, port_sub, proto_sub, svc_opaque, svc_reason, svc_src_port)
        out.extend(("undecided", INDETERMINATE, reason, rp, rq) for rp, rq in remaining)
        return out

    for rp, rq in remaining:
        if svc_opaque:
            out.append(("undecided", INDETERMINATE, svc_reason, rp, rq))
        elif svc_negate:
            out.append(("match", r["action"], r.get("indeterminate_reason"), rp, rq))
        else:
            out.append(("pending", "", None, rp, rq))
    return out


def _split_pending(
    r: dict[str, Any],
    pending: list[_RegionBox],
    svc_negate: bool,
) -> tuple[list[_ServiceSplitEntry], list[_RegionBox]]:
    """Every pending rectangle of one rule through `_service_split`, with the
    ones the rule's service misses separated from the ones it decides.

    The second return value is the missed rectangles for the next rule.
    """
    entries: list[_ServiceSplitEntry] = []
    carried: list[_RegionBox] = []
    for proto_sub, port_sub in pending:
        for entry in _service_split(r, proto_sub, port_sub, svc_negate):
            if entry[0] == "pending":
                carried.append((entry[3], entry[4]))
            else:
                entries.append(entry)
    return entries, carried


def _coalesce_regions(boxes: list[_RegionBox]) -> _RegionBox:
    """The union of the rectangles' protocols and of their port intervals, as
    one rectangle."""
    protos = [p for p, _ in boxes]
    ports = [q for _, q in boxes]
    proto = None if any(p is None for p in protos) else frozenset().union(*[p for p in protos if p])
    port = None if any(q is None for q in ports) else _merge([iv for q in ports if q for iv in q])
    return proto, port


def _cap_regions(
    decided: list[_DecidedRegion],
    pending: list[_RegionBox],
    cap: int,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
) -> bool:
    """Apply the budget on the number of regions in one walk.

    When the decided and pending regions number more than `cap`, the pending
    regions are coalesced into one indeterminate region. Returns whether the
    pending regions were coalesced.
    """
    if not pending or len(decided) + len(pending) <= cap:
        return False
    proto, port = _coalesce_regions(pending)
    decided.append(
        (
            {
                "uid": None,
                "pos": None,
                "name": None,
                "action": INDETERMINATE,
                "indeterminate_reason": _REGION_CAP_REASON.format(cap=cap),
            },
            src_set,
            dst_set,
            proto,
            port,
        )
    )
    pending.clear()
    return True


def _merge_by_outcome(decided: list[_DecidedRegion]) -> list[_DecidedRegion]:
    """Regions one rule decided the same way, folded into one.

    Two regions merge only when the rule, position, action, indeterminate
    reason, protocol set and address parts hit are the same.
    """
    out: list[_DecidedRegion] = []
    index: dict[tuple[Any, ...], int] = {}
    for r, src_hit, dst_hit, proto_sub, port_sub in decided:
        key = (
            None if r is None else r.get("uid"),
            None if r is None else r.get("pos"),
            None if r is None else r.get("action"),
            None if r is None else r.get("indeterminate_reason"),
            proto_sub,
            port_sub is None,
            tuple(src_hit),
            tuple(dst_hit),
        )
        at = index.get(key)
        if at is None:
            index[key] = len(out)
            out.append((r, src_hit, dst_hit, proto_sub, port_sub))
            continue
        prev = out[at]
        merged = None if port_sub is None else _merge(list(prev[4] or []) + list(port_sub))
        out[at] = (prev[0], prev[1], prev[2], prev[3], merged)
    return out


def _first_match_regions(
    rules: list[dict[str, Any]],
    in_name: str | None,
    out_name: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    proto_set: frozenset[int] | None,
    port_ivals: list[tuple[int, int, int]] | None,
    state_skips: list[dict[str, Any]] | None = None,
    *,
    conn_state: str = "new",
    unresolved: frozenset[str] = frozenset(),
) -> list[_DecidedRegion]:
    """The partition path of `_first_match`. It finds the rule that decides
    each part of a (proto, port) range, first match, rule by rule.

    Only the service side is partitioned.

    Returns one entry per decided region, and one entry with `rule=None` per
    region still unclaimed after the last rule.

    `path_region_cap` caps the number of regions in one walk.
    """
    skips = [] if state_skips is None else state_skips
    cap = Settings().path_region_cap
    pending: list[_RegionBox] = [(proto_set, port_ivals)]
    decided: list[_DecidedRegion] = []

    for r in rules:
        if not pending:
            break
        skip, iface_unresolved = _iface_scope(r, in_name, out_name, unresolved)
        if skip:
            continue
        states = r.get("states") or []
        if states and conn_state not in states:
            skips.append({"pos": r["pos"], "states": list(states)})
            continue
        svc_negate = r.get("svc_negate", False)
        if r["svc_any"] and svc_negate:
            continue

        rule_src, src_unparsed = _rule_intervals_status(r["src_cidrs"], r["src_ips"], r["src_ranges"])
        rule_dst, dst_unparsed = _rule_intervals_status(r["dst_cidrs"], r["dst_ips"], r["dst_ranges"])
        if src_unparsed or dst_unparsed:
            entries, pending = _split_pending(r, pending, svc_negate)
            decided.extend(
                (
                    {**r, "action": INDETERMINATE, "indeterminate_reason": _UNPARSED_ADDRESS_REASON},
                    src_set,
                    dst_set,
                    rp,
                    rq,
                )
                for _kind, _action, _reason, rp, rq in entries
            )
            if _cap_regions(decided, pending, cap, src_set, dst_set):
                break
            continue
        src_hit, src_gap, src_why = _net_side(
            r["src_any"],
            r.get("src_obj_count", 0),
            r.get("src_opaque", False),
            r.get("src_negate", False),
            r.get("src_opaque_reasons") or [],
            rule_src,
            src_set,
        )
        dst_hit, dst_gap, dst_why = _net_side(
            r["dst_any"],
            r.get("dst_obj_count", 0),
            r.get("dst_opaque", False),
            r.get("dst_negate", False),
            r.get("dst_opaque_reasons") or [],
            rule_dst,
            dst_set,
        )
        if src_gap or dst_gap:
            addr_why = "; ".join(dict.fromkeys(x for x in (src_why, dst_why) if x))
            entries, pending = _split_pending(r, pending, svc_negate)
            decided.extend(
                (
                    {
                        **r,
                        "action": INDETERMINATE,
                        "indeterminate_reason": reason if kind == "undecided" else addr_why,
                    },
                    src_set,
                    dst_set,
                    rp,
                    rq,
                )
                for kind, _action, reason, rp, rq in entries
            )
            if _cap_regions(decided, pending, cap, src_set, dst_set):
                break
            continue
        if not src_hit or not dst_hit:
            continue

        # an undecided service takes precedence over the rule-level scope reason
        addr_ok_reason = _scope_reason(r)
        if addr_ok_reason is None and (r.get("out_if_group") or r.get("in_if_group")):
            addr_ok_reason = _IFACE_GROUP_REASON
        if addr_ok_reason is None:
            addr_ok_reason = iface_unresolved

        entries, pending = _split_pending(r, pending, svc_negate)
        for kind, action, reason, rp, rq in entries:
            final_action = INDETERMINATE if (kind == "undecided" or addr_ok_reason) else action
            final_reason = reason if kind == "undecided" else addr_ok_reason
            decided.append(
                (
                    {**r, "action": final_action, "indeterminate_reason": final_reason},
                    src_hit,
                    dst_hit,
                    rp,
                    rq,
                )
            )
        if _cap_regions(decided, pending, cap, src_set, dst_set):
            break

    decided.extend((None, src_set, dst_set, p, q) for p, q in pending)
    return _merge_by_outcome(decided)


# A stated source-port range is cut into slices, and the (proto, port) walk runs
# once per slice.


def _sport_atoms(rules: list[dict[str, Any]], sport_ivals: Ivals) -> list[list[tuple[int, int, int]]]:
    """The slices of a stated source-port range that every readable member
    spec in `rules` decides whole.

    Each spec cuts every slice it straddles in two. No slice is left partly
    inside a spec. A spec that `_ports` cannot read cuts nothing, and its
    member is undecided on every slice. The slices are returned in ascending
    port order."""
    atoms: list[list[tuple[int, int, int]]] = [list(sport_ivals)]
    specs = sorted({str(s) for r in rules for s in (r.get("src_ports") or []) if s})
    for spec in specs:
        try:
            ivals = _ports(spec)
        except ValueError:
            continue
        nxt: list[list[tuple[int, int, int]]] = []
        for atom in atoms:
            inside, outside = _intersect(atom, ivals), _subtract(atom, ivals)
            if inside:
                nxt.append(inside)
            if outside:
                nxt.append(outside)
        atoms = nxt
    return sorted(atoms)


def _rule_on_sport_slice(r: dict[str, Any], sport_slice: list[tuple[int, int, int]]) -> dict[str, Any] | None:
    """One rule as it reads on one source-port slice.

    A rule not scoped to a source port reads as itself. A scoped rule whose
    per-member specs were not collected (`src_ports` absent or empty while
    `svc_src_port` is set) reads as itself too. Otherwise a member whose spec
    misses the slice is dropped. `None` means the rule's service misses the
    slice."""
    if not r.get("svc_src_port") or r.get("svc_any"):
        return r
    src_ports = r.get("src_ports") or []
    if not any(s for s in src_ports):
        return r
    kept: list[tuple[Any, Any]] = []
    unreadable = dropped = covered = False
    for p, q, s in zip_longest(r.get("protos") or [], r.get("ports") or [], src_ports):
        if not s:
            kept.append((p, q))
            continue
        try:
            ivals = _ports(str(s))
        except ValueError:
            kept.append((p, q))
            unreadable = True
            continue
        if _subtract(sport_slice, ivals):
            dropped = True
            continue
        kept.append((p, q))
        covered = True
    negate = bool(r.get("svc_negate"))
    real = covered or unreadable or any(p or q for p, q in kept)
    if dropped and not real and (not kept or not r.get("svc_opaque")):
        if not negate:
            return None
        return {**r, "svc_any": True, "svc_negate": False, "protos": [], "ports": [], "svc_src_port": False}
    out = {**r, "protos": [p for p, _ in kept], "ports": [q for _, q in kept], "svc_src_port": unreadable}
    if not any(p or q for p, q in kept) and not unreadable and not r.get("svc_opaque"):
        # The members left constrain nothing on this slice. The rule matches on
        # its addresses alone here. A negated rule excludes everything, and the
        # `svc_any and svc_negate` guard of the walk reads that case.
        out["svc_any"] = True
    return out


def _first_match_by_sport(
    rules: list[dict[str, Any]],
    in_name: str | None,
    out_name: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    proto_set: frozenset[int] | None,
    port_ivals: list[tuple[int, int, int]] | None,
    sport_ivals: Ivals | None,
    state_skips: list[dict[str, Any]] | None = None,
    *,
    conn_state: str = "new",
    unresolved: frozenset[str] = frozenset(),
) -> list[tuple[Ivals | None, list[_DecidedRegion]]]:
    """Run `_first_match_regions` once per source-port slice.

    Returns `(slice, decided regions)` pairs. The slice is None for a query
    that states no source port."""
    if sport_ivals is None:
        return [
            (
                None,
                _first_match_regions(
                    rules,
                    in_name,
                    out_name,
                    src_set,
                    dst_set,
                    proto_set,
                    port_ivals,
                    state_skips,
                    conn_state=conn_state,
                    unresolved=unresolved,
                ),
            )
        ]
    out: list[tuple[Ivals | None, list[_DecidedRegion]]] = []
    for atom in _sport_atoms(rules, sport_ivals):
        sliced = [rr for r in rules if (rr := _rule_on_sport_slice(r, atom)) is not None]
        skips: list[dict[str, Any]] = []
        decided = _first_match_regions(
            sliced,
            in_name,
            out_name,
            src_set,
            dst_set,
            proto_set,
            port_ivals,
            skips,
            conn_state=conn_state,
            unresolved=unresolved,
        )
        if state_skips is not None:
            state_skips.extend(s for s in skips if s not in state_skips)
        out.append((tuple(atom), decided))
    return out


def _sport_query(src_port: Any) -> tuple[Ivals | None, bool]:
    """The query's source port as intervals, and whether it was stated."""
    ivals, _ = _as_portset(_unwrap_single(src_port))
    return (None if ivals is None else tuple(ivals)), ivals is not None


def _zone_pair_verdict(
    session: Any,
    in_if: str,
    out_if: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | None,
    af: int,
    *,
    conn_state: str = "new",
    src_port: Any = None,
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """Zone-pair rulebase for this flow, evaluated first-match.

    Returns {rulebase, rule, action, ...}, or None when no zone pair governs
    it. A range or a stated `src_port` returns a list of such dicts, one per
    region.

    A pair binds up to one ruleset per address family (`firewall.name` and
    `ipv6-name` side by side). The flow's family selects the ruleset that judges it.
    A pair that binds no ruleset for this family falls through to the
    destination zone's default-action.
    """
    # the query is normalized only when it states a range
    sport_ivals, sport_stated = _sport_query(src_port)
    is_range = _states_a_range(_unwrap_single(port), _unwrap_single(proto)) or sport_stated
    proto_set = _as_protoset(_unwrap_single(proto))[0] if is_range else None
    port_ivals = _as_portset(_unwrap_single(port))[0] if is_range else None

    def regionize(d: dict[str, Any]) -> dict[str, Any] | list[dict[str, Any]]:
        if not is_range:
            return d
        whole = {**d, "proto_subset": proto_set, "port_subset": port_ivals}
        if sport_stated:
            whole["sport_subset"] = sport_ivals
        return [whole]

    rows = (
        _path._read(
            session,
            """
MATCH (iin:Interface:Obj {uid: $in_if, collection_ts: $snap})<-[ci:CONTAINS]-(src:Zone)
MATCH (iout:Interface:Obj {uid: $out_if, collection_ts: $snap})<-[co:CONTAINS]-(dst:Zone)
MATCH (rb:FwRulebase)-[fz:FROM_ZONE]->(src), (rb)-[tz:TO_ZONE]->(dst)
WHERE iin:Obj AND iin.collection_ts = $snap AND iout:Obj AND iout.collection_ts = $snap
  AND NOT rb:Retired AND NOT src:Retired AND NOT dst:Retired
  AND ci._retired_at IS NULL AND co._retired_at IS NULL
  AND fz._retired_at IS NULL AND tz._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN rb.uid AS rb_uid, rb.name AS rb_name, rb.af AS af, rb.default_action AS default_action,
       rb.default_action_unknown AS default_action_unknown,
       rb.global_state_policy AS global_state_policy, rb.state_policy_basis AS state_policy_basis,
       rb.established_default_unknown AS established_default_unknown,
       src.name AS src_zone, dst.name AS dst_zone, dst.default_action AS zone_default,
       dst.default_action_unknown AS zone_default_unknown,
       dst.established_default_unknown AS zone_established_default_unknown
ORDER BY rb.uid""",
            in_if=in_if,
            out_if=out_if,
        )
        if out_if
        else []
    )
    if not rows:
        # If no ruleset binds this pair, the destination zone's default-action applies.
        src_zone, dst_zone = _zone_of(session, in_if), _zone_of(session, out_if)
        if not src_zone or not dst_zone:
            return None
        if src_zone["name"] == dst_zone["name"]:
            # For two interfaces of one zone, the zone's intra-zone filtering decides.
            intra = _intra_zone_verdict(src_zone)
            return regionize(intra) if intra is not None else None
        # a synthetic uid, as the ECMP NextHop station has
        action, why = _fallthrough(
            *_zone_default(
                dst_zone.get("default_action"),
                dst_zone.get("default_action_unknown"),
                f"zone {dst_zone['name']}",
            ),
            _state_rules_unreported(dst_zone, conn_state, "established_default_unknown"),
        )
        return regionize(
            {
                "rb_uid": f"zone-pair:{src_zone['name']}->{dst_zone['name']}#unbound",
                "rb_name": f"{src_zone['name']}→{dst_zone['name']} zone policy (no ruleset bound)",
                "zones": f"{src_zone['name']}→{dst_zone['name']}",
                "rule_uid": None,
                "pos": None,
                "action": action,
                "rule_name": None,
                "by": "default-action",
                "partial": False,
                "indeterminate_reason": why,
            }
        )
    row = next((r for r in rows if _rb_af(r) == af), None) or next(
        (r for r in rows if _rb_af(r) is None), None
    )
    if row is None and rows[0]["src_zone"] == rows[0]["dst_zone"]:
        # an intra-zone ruleset for the other family only
        zone = _zone_of(session, in_if) or {"name": rows[0]["src_zone"]}
        return regionize(_intra_zone_verdict({**zone, "intra_zone_filtering": True}) or {})
    if row is None:
        # With no ruleset for this family, the zone default applies.
        other = rows[0]
        action, why = _fallthrough(
            *_zone_default(
                other["zone_default"], other.get("zone_default_unknown"), f"zone {other['dst_zone']}"
            ),
            _state_rules_unreported(other, conn_state, "zone_established_default_unknown"),
        )
        return regionize(
            {
                "rb_uid": None,
                "rb_name": f"{other['src_zone']}→{other['dst_zone']} zone policy",
                "zones": f"{other['src_zone']}→{other['dst_zone']}",
                "rule_uid": None,
                "pos": None,
                "action": action,
                "rule_name": None,
                "by": "default-action",
                "partial": False,
                "indeterminate_reason": why,
                "global_state_policy": other.get("global_state_policy"),
                "state_policy_basis": other.get("state_policy_basis"),
            }
        )
    in_name, out_name = _interface_names(session, in_if, out_if)
    # Both interfaces resolved to a zone. A name that did not resolve is unknown.
    unresolved = _unresolved_sides(in_if, in_name, out_name, chain="forward", has_egress=True)
    rules = _rule_rows(session, row["rb_uid"])
    state_skips: list[dict[str, Any]] = []

    def default_action_dict() -> dict[str, Any]:
        if row["default_action"] is None and row.get("default_action_unknown"):
            return {
                "rb_uid": row["rb_uid"],
                "rb_name": row["rb_name"],
                "zones": f"{row['src_zone']}→{row['dst_zone']}",
                "rule_uid": None,
                "pos": None,
                "action": INDETERMINATE,
                "rule_name": None,
                "by": "default-action",
                "partial": False,
                "indeterminate_reason": _UNKNOWN_DEFAULT_REASON,
                "state_skips": state_skips,
                "global_state_policy": row.get("global_state_policy"),
                "state_policy_basis": row.get("state_policy_basis"),
            }
        action, why = row["default_action"], None
        if not action:
            action, why = _unstated_default(f"rulebase {row['rb_uid']}")
        else:
            action, why = _fallthrough(
                action, why, _state_rules_unreported(row, conn_state, "established_default_unknown")
            )
        return {
            "rb_uid": row["rb_uid"],
            "rb_name": row["rb_name"],
            "zones": f"{row['src_zone']}→{row['dst_zone']}",
            "rule_uid": None,
            "pos": None,
            "action": action,
            "rule_name": None,
            "by": "default-action",
            "partial": False,
            "indeterminate_reason": why,
            "state_skips": state_skips,
            "global_state_policy": row.get("global_state_policy"),
            "state_policy_basis": row.get("state_policy_basis"),
        }

    def matched_dict(r: dict[str, Any], src_hit: Any, dst_hit: Any) -> dict[str, Any]:
        partial = (_size(src_hit) < _size(src_set)) or (_size(dst_hit) < _size(dst_set))
        return {
            "rb_uid": row["rb_uid"],
            "rb_name": row["rb_name"],
            "zones": f"{row['src_zone']}→{row['dst_zone']}",
            "rule_uid": r["uid"],
            "pos": r["pos"],
            "action": r["action"],
            "rule_name": r["name"],
            "by": "rule",
            "partial": partial,
            "indeterminate_reason": r.get("indeterminate_reason"),
            "state_skips": state_skips,
            "global_state_policy": row.get("global_state_policy"),
            "state_policy_basis": row.get("state_policy_basis"),
        }

    if not is_range:
        m = _first_match(
            rules,
            in_name,
            out_name,
            src_set,
            dst_set,
            port,
            proto,
            state_skips,
            conn_state=conn_state,
            unresolved=unresolved,
        )
        if m:
            point = cast("tuple[dict[str, Any], list[tuple[int, int, int]], list[tuple[int, int, int]]]", m)
            r, src_hit, dst_hit = point
            return matched_dict(r, src_hit, dst_hit)
        return default_action_dict()
    results: list[dict[str, Any]] = []
    for sport_sub, decided in _first_match_by_sport(
        rules,
        in_name,
        out_name,
        src_set,
        dst_set,
        proto_set,
        port_ivals,
        sport_ivals,
        state_skips,
        conn_state=conn_state,
        unresolved=unresolved,
    ):
        for decided_rule, src_hit, dst_hit, proto_sub, port_sub in decided:
            d = (
                matched_dict(decided_rule, src_hit, dst_hit)
                if decided_rule is not None
                else default_action_dict()
            )
            d.update(proto_subset=proto_sub, port_subset=port_sub)
            if sport_stated:
                d["sport_subset"] = sport_sub
            results.append(d)
    return results


_ACCESS_VENDOR_QUERY = """
MATCH (dev:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND NOT rb:Retired AND e._retired_at IS NULL AND coalesce(rb.kind, 'access') = 'access'
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.vendor AS vendor, rb.match_context AS match_context
UNION
// the RedundancyGroup-bound half of the FwRulebase binding patterns
// (core/labels.py): a cluster's rulebase enforced from the RedundancyGroup
// rather than from either member Device directly -- mini-dc.yaml's Check
// Point cluster is bound exactly this way -- was invisible to the
// Device-ENFORCES read above and so never governed a flow, whatever a
// Check Point rule on it said.
MATCH (dev:Device {uid: $dev})-[e2:MEMBER_OF]->(:RedundancyGroup)-[e3:ENFORCES]->(rb2:FwRulebase)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND NOT rb2:Retired AND e2._retired_at IS NULL AND e3._retired_at IS NULL
  AND coalesce(rb2.kind, 'access') = 'access'
  AND rb2.collection_ts = $snap
RETURN DISTINCT rb2.vendor AS vendor, rb2.match_context AS match_context
UNION
// the zone-bound half of the device's filter: `_zone_pair_verdict` reads
// exactly this shape (FROM_ZONE/TO_ZONE off a Zone the device's own
// interfaces sit in) rather than ENFORCES, so a zone-firewall gateway whose
// only policy is bound this way -- UniFi's 9.x zone model, VyOS's zone
// firewall -- was invisible to the ENFORCES-only read above and fell back to
// ungoverned, when its pipeline order is exactly as derivable as any other
// box's.
MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
MATCH (i)<-[c:CONTAINS]-(z:Zone)
MATCH (rb:FwRulebase)-[zr:FROM_ZONE|TO_ZONE]->(z)
WHERE d:Obj AND d.collection_ts = $snap
  AND NOT i:Retired AND o._retired_at IS NULL AND NOT z:Retired AND c._retired_at IS NULL
  AND NOT rb:Retired AND zr._retired_at IS NULL AND rb.collection_ts = $snap
RETURN DISTINCT rb.vendor AS vendor, rb.match_context AS match_context"""

# Where each collected vendor's device-wide access policy sits relative to that
# device's own destination NAT. 'original' is the packet as it arrived, before
# the destination was translated (the Check Point gateway). 'translated' is the
# netfilter forwarding path the Stage model documents. On that path the
# destination is rewritten in PREROUTING, and the filter sees the result.
#
# A vendor that is not in the map is not defaulted into either bucket. An
# interface ACL (`match_context` 'interface-acl') is not read from this map.
_FILTER_VIEW_BY_VENDOR = {
    "checkpoint": "original",
    "vyos": "translated",
    "ubiquiti": "translated",
    "cisco": "translated",
}

# the view of an inbound interface ACL, which is the packet as it arrived
_INTERFACE_ACL_VIEW = "original"
_INTERFACE_ACL = "interface-acl"

# the view of a device with no collected access rulebase
_UNGOVERNED_VIEW = "ungoverned"

_UNKNOWN_VENDOR_REASON = "the filter's address view for this vendor is not known"


def _read_device_filter_view(session: Any, dev_uid: str) -> tuple[str | None, str | None]:
    """The uncached read behind `_device_filter_view`."""
    rows = _path._read(session, _ACCESS_VENDOR_QUERY, dev=dev_uid)
    if not rows:
        return _UNGOVERNED_VIEW, None
    # An interface ACL is placed by its binding direction for every vendor. The
    # filter stage judges the inbound list on the original packet.
    acl_bound = any(r.get("match_context") == _INTERFACE_ACL for r in rows)
    rows = [r for r in rows if r.get("match_context") != _INTERFACE_ACL]
    if any(not r.get("vendor") for r in rows):
        return None, (f"an access rulebase on this device carries no vendor, so {_UNKNOWN_VENDOR_REASON}")
    vendors = [str(r["vendor"]).strip().lower() for r in rows]
    unknown = sorted({v for v in vendors if v not in _FILTER_VIEW_BY_VENDOR})
    if unknown:
        return None, (
            f"this device's access rulebase was collected with vendor "
            f"{', '.join(unknown)}, and {_UNKNOWN_VENDOR_REASON}"
        )
    views = {_FILTER_VIEW_BY_VENDOR[v] for v in vendors}
    if acl_bound:
        views.add(_INTERFACE_ACL_VIEW)
    if len(views) > 1:
        named = ", ".join(sorted({*vendors, *(["an interface ACL"] if acl_bound else [])}))
        return None, (
            f"this device's access rulebases were collected from {named}, whose filters "
            "do not agree on which destination they match"
        )
    return views.pop(), None


def _device_filter_view(session: Any, trail: _Trail, dev_uid: str) -> tuple[str | None, str | None]:
    """Which destination this device's access policy matches on, and why not.

    Returns (view, reason). The view is 'original' (the packet as it arrived,
    before destination NAT) or 'translated' (after it), derived from the
    collected vendor of the device's own access rulebases. The view is
    `_UNGOVERNED_VIEW` when no access rulebase is collected on the device, and
    the reason is None. The view is None when the collected data does not
    decide the order. Then `reason` names what is missing. That is an access
    rulebase with no vendor, a vendor with no entry in
    `_FILTER_VIEW_BY_VENDOR`, or rulebases from two vendors whose views
    disagree.

    The read is cached on the trail. Each device is read once per trace.
    """
    cached = trail.filter_views.get(dev_uid)
    if cached is None:
        cached = _read_device_filter_view(session, dev_uid)
        trail.filter_views[dev_uid] = cached
    return cached


def _acl_bindings(rb: dict[str, Any]) -> list[tuple[str, str]]:
    """The (interface name, direction) bindings of an interface-ACL candidate row:
    its PROTECTED_BY edges, and the bindings to an interface the device did not
    report, which the collector keeps on the rulebase as "<name> <direction>"."""
    pairs = [(str(name), str(bound)) for name, bound in rb.get("acl_bindings") or [] if name]
    for entry in rb.get("acl_unreported") or []:
        name, _sep, bound = str(entry).rpartition(" ")
        if name:
            pairs.append((name, bound))
    return pairs


def _legacy_acl_bindings(rules: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """The bindings of an interface ACL whose rulebase records no binding.

    Such an ACL is one rulebase per binding. Every rule of it names the bound
    interface in `in_interface` or `out_interface` (read as `in_if`/`out_if`)."""
    pairs = [(str(r["in_if"]), "in") for r in rules if r.get("in_if")]
    return pairs + [(str(r["out_if"]), "out") for r in rules if r.get("out_if")]


def _acl_views(rb: dict[str, Any], legacy_rules: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """An interface-ACL candidate as one view per direction it is bound in.

    An access list is one rulebase per device and name, bound to its
    interfaces by PROTECTED_BY edges that each hold a direction
    (`cisco_common.acl_stage`), plus the bindings to interfaces the device did
    not report (`_acl_bindings`). The inbound binding of one list is judged at
    the filter stage. The outbound binding is judged after source NAT. Each
    direction is a candidate of its own. `acl_direction` names the direction,
    and `acl_interfaces` lists the names of the interfaces bound that way. A
    list bound to nothing has no view and governs no hop.

    A rulebase with neither is read from `legacy_rules`, and its view is
    marked `acl_legacy`.
    """
    bindings = _acl_bindings(rb)
    legacy = not bindings and legacy_rules is not None
    if legacy:
        bindings = _legacy_acl_bindings(legacy_rules or [])
    views = []
    for direction in ("in", "out"):
        names = sorted({name for name, bound in bindings if bound == direction})
        if names:
            views.append({**rb, "acl_direction": direction, "acl_interfaces": names, "acl_legacy": legacy})
    return views


def _acl_governs_hop(
    direction: str,
    interfaces: list[str],
    in_name: str | None,
    out_name: str | None,
    *,
    has_egress: bool = True,
) -> str:
    """Whether one direction of an interface ACL is bound to an interface this hop uses.

    A Check Point layer and a VyOS forward chain are device-wide. Every flow
    through the box passes them. A Cisco access list governs only the
    interfaces it is bound to, each in one direction.

    A list bound on a side whose interface name did not resolve is undecided.

    `has_egress` is False for a hop with no egress side.

    Returns "governs" when a bound interface matches this hop's resolved
    interface name on that side, "excluded" when the hop uses none of them,
    and otherwise an indeterminate-reason string naming the unresolved
    interface.
    """
    if direction == "out" and not has_egress:
        return "excluded"
    actual = out_name if direction == "out" else in_name
    if any(_iface_name_matches(name, actual) for name in interfaces):
        return "governs"
    if actual is None:
        side = "egress" if direction == "out" else "ingress"
        bound = ", ".join(repr(name) for name in interfaces)
        plural = "s" if len(interfaces) > 1 else ""
        return (
            f"this list is bound to {side} interface{plural} {bound}, "
            f"and this leg's {side} interface name could not be resolved"
        )
    return "excluded"


def _meet_proto(p1: frozenset[int] | None, p2: frozenset[int] | None) -> tuple[frozenset[int] | None, bool]:
    """The common protocol subset of two independently partitioned regions,
    and whether it is empty. `None` on either side means that partition did
    not narrow the dimension."""
    if p1 is None:
        return p2, p2 is not None and not p2
    if p2 is None:
        return p1, not p1
    inter = p1 & p2
    return inter, not inter


def _meet_port(
    q1: list[tuple[int, int, int]] | None, q2: list[tuple[int, int, int]] | None
) -> tuple[list[tuple[int, int, int]] | None, bool]:
    """The common port intervals of two regions, and whether they are empty.

    `None` on either side means that partition did not narrow the dimension."""
    if q1 is None:
        return q2, q2 is not None and not q2
    if q2 is None:
        return q1, not q1
    inter = _intersect(q1, q2)
    return inter, not inter


def _permit_pick(results: list[dict[str, Any]]) -> dict[str, Any]:
    """The verdict to report when every candidate permits.

    It is the first candidate whose rule covers only part of the flow, else
    the first candidate.
    """
    return next((r for r in results if r.get("partial")), results[0])


def _pick_winner(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Which of two candidates' verdicts governs one combined region.

    A device passes every device-wide rulebase for its family. A deny from
    any one is the verdict, then an indeterminate from any one, else the
    first candidate that permits only part of the flow, else the first
    candidate.
    """
    for wanted in (DENY, INDETERMINATE):
        if classify_action(a["action"]) == wanted:
            return a
        if classify_action(b["action"]) == wanted:
            return b
    return _permit_pick([a, b])


def _refine_regions(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The common refinement of two candidates' region partitions, each
    already covering the whole query domain, with `_pick_winner` deciding
    which candidate's verdict governs each combined sub-region."""
    out: list[dict[str, Any]] = []
    for da in a:
        for db in b:
            proto, proto_empty = _meet_proto(da.get("proto_subset"), db.get("proto_subset"))
            if proto_empty:
                continue
            port, port_empty = _meet_port(da.get("port_subset"), db.get("port_subset"))
            if port_empty:
                continue
            combined = {**_pick_winner(da, db), "proto_subset": proto, "port_subset": port}
            if "sport_subset" in da or "sport_subset" in db:
                sport, sport_empty = _meet_port(da.get("sport_subset"), db.get("sport_subset"))
                if sport_empty:
                    continue
                combined["sport_subset"] = sport
            out.append(combined)
    return out


def _sport_key(d: dict[str, Any]) -> tuple[tuple[int, int, int], ...] | None:
    """A region's source-port slice as a hashable grouping key.

    The key is None for every region of a query that states no source port."""
    sport = d.get("sport_subset")
    return None if sport is None else tuple(sport)


def _merge_candidate_regions_by_outcome(combined: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Regions of the device-wide candidate fold with the same outcome, folded into one.

    Regions merge only when the rulebase, rule, position, action,
    indeterminate reason, protocol subset and partial flag are the same.
    """
    out: list[dict[str, Any]] = []
    index: dict[tuple[Any, ...], int] = {}
    for d in combined:
        key = (
            d.get("rb_uid"),
            d.get("rule_uid"),
            d.get("action"),
            d.get("indeterminate_reason"),
            d.get("proto_subset"),
            # Ports merge only within one source-port slice.
            _sport_key(d),
            # `pos` separates one target rule reached by two jumps. `partial`
            # separates the regions where a rule covers part of the flow from
            # the regions where it covers all of it.
            d.get("pos"),
            bool(d.get("partial")),
        )
        at = index.get(key)
        if at is None:
            index[key] = len(out)
            out.append(dict(d))
            continue
        prev = out[at]
        port_sub = d.get("port_subset")
        prev_port = prev.get("port_subset")
        prev["port_subset"] = None if port_sub is None else _merge(list(prev_port or []) + list(port_sub))
    return out


def _cap_candidate_regions(
    combined: list[dict[str, Any]], cap: int, reason_cap: int | None = None
) -> list[dict[str, Any]]:
    """The region budget applied to the device-wide candidate fold.

    When there are more than `cap` regions, the regions from position
    `cap - 1` on are coalesced into one indeterminate region. The reason
    names `reason_cap`, which defaults to `cap`.
    """
    if len(combined) <= cap:
        return combined
    keep, surplus = combined[: cap - 1], combined[cap - 1 :]
    proto, port = _coalesce_regions([(d.get("proto_subset"), d.get("port_subset")) for d in surplus])
    coalesced = {
        "rb_uid": None,
        "rb_name": None,
        "zones": None,
        "rule_uid": None,
        "pos": None,
        "action": INDETERMINATE,
        "rule_name": None,
        "by": "default-action",
        "partial": False,
        "approximate_binding": False,
        "indeterminate_reason": _REGION_CAP_REASON.format(cap=reason_cap if reason_cap is not None else cap),
        "state_skips": [],
        "global_state_policy": None,
        "proto_subset": proto,
        "port_subset": port,
    }
    if any("sport_subset" in d for d in surplus):
        # The source-port slices of the surplus are coalesced into one, as the
        # protocols and ports above are. The result is None where a slice is None.
        _, sport = _coalesce_regions([(None, d.get("sport_subset")) for d in surplus])
        coalesced["sport_subset"] = sport
    keep.append(coalesced)
    return keep


# The device-wide access rulebases of one chain.
#
# The branches are in a CALL subquery. An ORDER BY after the last RETURN of a
# bare UNION sorts only that branch. `_device_rulebase_verdict` reports `results[0]`
# when no candidate denies or is undecided.
#
# The third branch is keyed on the ingress interface, `$in_if`, and covers a
# Check Point VSX appliance. The Gaia collector owns the appliance Device and
# its interfaces, and records each interface's virtual system as
# (Interface)-[:IN_CONTEXT]->(FirewallInstance). The management collector owns
# the virtual system's own Device node. That node holds the management object
# uid as `cp_raw_uid`, and the package installation targets bind it with
# ENFORCES. The two nodes are joined by that uid. `_scope` guards the join,
# because a management object uid is unique only within one management server.
# `FirewallInstance.authority` is the management source's scope string. A read
# with no ingress interface binds `$in_if` to null, and the branch matches nothing.
_RULEBASE_CANDIDATES = """
CALL {
  MATCH (dev:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase:Obj)
  WHERE dev:Obj AND dev.collection_ts = $snap
    AND NOT rb:Retired AND e._retired_at IS NULL
    AND NOT EXISTS {
      MATCH (iin:Interface {uid: $in_if})-[cx:IN_CONTEXT]->(context)
      WHERE iin:Obj AND iin.collection_ts = $snap AND cx._retired_at IS NULL AND NOT context:Retired
    }
    AND coalesce(rb.kind, 'access') = 'access'
    AND (coalesce(rb.chain, 'forward') = $chain
         OR ($strict_local AND rb.chain IS NULL AND $chain IN ['input', 'output']))
    AND rb.collection_ts = $snap
    AND NOT EXISTS {
      MATCH (rb)-[z:FROM_ZONE|TO_ZONE]->(:Zone)
      WHERE z._retired_at IS NULL
    }
  RETURN rb, coalesce(e.approximate, false) AS approximate,
         head([(d:Device {uid: $dev})-[:ENFORCES]->(rb) | d.cp_raw_uid]) AS owner_raw_uid
  UNION
  // the RedundancyGroup-bound half of the FwRulebase binding patterns
  // (core/labels.py) -- a cluster's rulebase enforced from the RedundancyGroup
  // rather than from either member Device directly. Without this branch,
  // mini-dc.yaml's own Check Point cluster rulebase was a candidate for
  // nothing: `unevaluated_gates`' safeguard was the only thing that ever saw
  // it, and the real evaluator below never decided a permit or deny for it.
  MATCH (dev:Device {uid: $dev})-[e2:MEMBER_OF]->(:RedundancyGroup)-[e3:ENFORCES]->(rb:FwRulebase:Obj)
  WHERE dev:Obj AND dev.collection_ts = $snap
    AND NOT rb:Retired AND e2._retired_at IS NULL AND e3._retired_at IS NULL
    AND NOT EXISTS {
      MATCH (iin:Interface {uid: $in_if})-[cx:IN_CONTEXT]->(context)
      WHERE iin:Obj AND iin.collection_ts = $snap AND cx._retired_at IS NULL AND NOT context:Retired
    }
    AND coalesce(rb.kind, 'access') = 'access'
    AND (coalesce(rb.chain, 'forward') = $chain
         OR ($strict_local AND rb.chain IS NULL AND $chain IN ['input', 'output']))
    AND rb.collection_ts = $snap
    AND NOT EXISTS {
      MATCH (rb)-[z:FROM_ZONE|TO_ZONE]->(:Zone)
      WHERE z._retired_at IS NULL
    }
  RETURN rb, coalesce(e3.approximate, false) AS approximate,
         head([(:Device {uid: $dev})-[:MEMBER_OF]->(rg:RedundancyGroup)-[:ENFORCES]->(rb)
               | rg.cp_raw_uid]) AS owner_raw_uid
  UNION
  // the VSX context branch: the rulebase bound to the virtual system whose
  // context the ingress interface belongs to (see the note above)
  MATCH (iin:Interface {uid: $in_if})-[c:IN_CONTEXT]->(fi:FirewallInstance)
  WHERE iin:Obj AND iin.collection_ts = $snap AND c._retired_at IS NULL AND NOT fi:Retired
  MATCH (vs:Device:Obj {collection_ts: $snap})-[e5:ENFORCES]->(rb:FwRulebase)
  WHERE vs.cp_raw_uid = fi.gateway_object_uid AND vs._scope = fi.authority
    AND NOT vs:Retired AND NOT rb:Retired AND e5._retired_at IS NULL
    AND coalesce(rb.kind, 'access') = 'access'
    AND (coalesce(rb.chain, 'forward') = $chain
         OR ($strict_local AND rb.chain IS NULL AND $chain IN ['input', 'output']))
    AND rb.collection_ts = $snap
    AND NOT EXISTS {
      MATCH (rb)-[z:FROM_ZONE|TO_ZONE]->(:Zone)
      WHERE z._retired_at IS NULL
    }
  RETURN rb, true AS approximate, vs.cp_raw_uid AS owner_raw_uid
}
RETURN rb.uid AS rb_uid, rb.name AS rb_name, rb.vendor AS vendor, rb.af AS af,
       rb.default_action AS default_action, rb.default_action_unknown AS default_action_unknown,
       rb.global_state_policy AS global_state_policy, rb.state_policy_basis AS state_policy_basis,
       rb.established_default_unknown AS established_default_unknown,
       rb.match_context AS match_context, rb.chain AS chain, approximate,
       // the management object uid of the gateway the binding names, which a
       // Check Point rule's install-on column is compared with (`_installed_rules`)
       owner_raw_uid,
       // the interfaces an interface ACL is bound to, as [name, direction]
       // pairs; empty for every other rulebase
       [(bi:Interface)-[pb:PROTECTED_BY]->(rb) WHERE pb._retired_at IS NULL AND NOT bi:Retired
        | [bi.name, pb.direction]] AS acl_bindings,
       // the bindings to an interface the device did not report, "<name> <direction>"
       rb.unreported_bindings AS acl_unreported
ORDER BY rb_name"""


def _is_iface_acl(rb: dict[str, Any]) -> bool:
    """Whether a rulebase row is an interface ACL."""
    return rb.get("match_context") == _INTERFACE_ACL


@dataclass(frozen=True)
class _Rulebases:
    """The device-wide rulebase candidates of one hop, and its interface names."""

    candidates: list[dict[str, Any]]
    in_name: str | None
    out_name: str | None


def _load_rulebases(
    session: Any,
    dev_uid: str,
    in_if: str,
    out_if: str | None,
    af: int,
    chain: str,
    considered: list[str] | None,
    *,
    only_interface_acls: bool,
    require_chain: bool,
    strict_local: bool,
    local_acls: bool = False,
) -> _Rulebases | None:
    """The candidates `_device_rulebase_verdict` judges, or None when there are none.

    See `_device_rulebase_verdict` for which candidates are excluded and which
    are credited to `considered`.
    """
    candidates = _path._read(
        session,
        _RULEBASE_CANDIDATES,
        dev=dev_uid,
        in_if=in_if or None,
        chain=chain,
        strict_local=strict_local,
    )
    installed = installed_candidates(session, in_if, out_if, af, chain) if chain == "forward" else []
    if installed:
        observed = {row["rb_uid"]: row for row in installed}
        candidates = [observed.pop(row["rb_uid"], row) for row in candidates]
        candidates.extend(observed.values())
    if only_interface_acls:
        candidates = [rb for rb in candidates if _is_iface_acl(rb)]
    # Every interface-ACL candidate is credited before the address-family filter.
    if considered is not None:
        considered.extend(rb["rb_uid"] for rb in candidates if _is_iface_acl(rb))
    if local_acls:
        # The router-local read of the interface ACLs (`local_acls`) takes only
        # a list that records no chain. That is the IOS-XE and NX-OS shape, which
        # applies to forwarded and terminated packets alike. A list that records
        # its chain (a UniFi LAN_IN, in the forward chain) is read in that chain
        # only. It was credited above.
        candidates = [rb for rb in candidates if rb.get("chain") is None]
    if require_chain:
        # Beside a zone-pair verdict, a device-wide candidate needs a recorded chain.
        candidates = [rb for rb in candidates if rb.get("chain") or _is_iface_acl(rb)]
    if considered is not None:
        considered.extend(
            rb["rb_uid"] for rb in candidates if not _is_iface_acl(rb) and _rb_af(rb) not in (None, af)
        )
    candidates = [rb for rb in candidates if _rb_af(rb) in (None, af)]
    # An interface ACL is judged once per direction it is bound in. It was
    # credited once by its uid above.
    candidates = [
        view
        for rb in candidates
        for view in (_acl_views(rb, _legacy_rules(session, rb)) if _is_iface_acl(rb) else [rb])
    ]
    if not candidates:
        return None
    in_name, out_name = _interface_names(session, in_if, out_if)
    return _Rulebases(candidates, in_name, out_name)


def _legacy_rules(session: Any, rb: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The rules of an interface ACL that records no binding of its own, or
    None for one that records its bindings."""
    if _acl_bindings(rb):
        return None
    rules: list[dict[str, Any]] = _path._read(session, _RULEBASE_RULES, rb=rb["rb_uid"])
    return rules


def _scope_unknown(rb: dict[str, Any], chain: str, strict_local: bool) -> bool:
    """Whether `rb` is a chainless policy asked about router-local traffic in
    strict mode.

    The pipeline scope of such a policy is not modeled. Its rules are not read."""
    return strict_local and chain in {"input", "output"} and rb.get("chain") is None


def _load_rules(
    session: Any, candidates: list[dict[str, Any]], chain: str, strict_local: bool
) -> Iterator[tuple[dict[str, Any], list[dict[str, Any]] | None]]:
    """Each candidate with its rules, read one rulebase at a time and in
    candidate order. `ChangeSet.rewrite` matches the rules query text and its
    `rb` parameter. The read is not batched across rulebases. A candidate
    whose scope is unknown (`_scope_unknown`) has None.

    The rules are read lazily, when `_judge_rulebases` takes each candidate.
    A judgement that raises stops the reads at that candidate. The inbound
    and outbound views of one interface ACL (`_acl_views`) share one read."""
    read: dict[str, list[dict[str, Any]]] = {}
    for rb in candidates:
        if _scope_unknown(rb, chain, strict_local):
            yield rb, None
        else:
            if rb["rb_uid"] not in read:
                read[rb["rb_uid"]] = _rule_rows(session, rb["rb_uid"])
            yield rb, read[rb["rb_uid"]]


# The ruleset a VyOS jump names. A flow that its rules leave undecided goes to
# its own default action or to a further jump.
_JUMP_TARGET = """
MATCH (rb:FwRulebase {uid: $rb})
WHERE rb:Obj AND rb.collection_ts = $snap AND NOT rb:Retired
RETURN rb.uid AS rb_uid, rb.name AS rb_name, rb.default_action AS default_action,
       coalesce(rb.default_action_unknown, false) AS default_action_unknown,
       rb.default_jump_target AS default_jump_target"""

# How many rulesets deep jumps are followed. A jump loop or a deeper chain
# leaves the jump undecided.
_JUMP_DEPTH = 16

_JUMP_NO_TARGET_REASON = "the rule jumps to no named ruleset"
_JUMP_UNDEFINED_REASON = "the rule jumps to ruleset {target}, which is not collected"
_JUMP_LOOP_REASON = "the rule's jumps loop or nest deeper than {depth} rulesets"
_JUMP_RETURN_REASON = "rule {pos} of jumped ruleset {target} returns on a match, which is not modeled"
_JUMP_SCOPE_REASON = (
    "the jump rule and rule {pos} of ruleset {target} both match on {dims}, which is not modeled"
)
_JUMP_DEFAULT_REASON = "the default action of jumped ruleset {target} is not recorded"
_JUMP_DEFAULT_ACTION_REASON = "the default action {action} of jumped ruleset {target} is not modeled"

# The `_RULEBASE_RULES` columns of each dimension a rule matches on. A jumped
# rule takes the jump rule's columns of a dimension it does not match on
# itself (`_jump_scoped`), all of a dimension's columns together.
_JUMP_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "source addresses": (
        "src_any",
        "src_negate",
        "src_cidrs",
        "src_ips",
        "src_ranges",
        "src_obj_count",
        "src_opaque",
        "src_opaque_reasons",
    ),
    "destination addresses": (
        "dst_any",
        "dst_negate",
        "dst_cidrs",
        "dst_ips",
        "dst_ranges",
        "dst_obj_count",
        "dst_opaque",
        "dst_opaque_reasons",
    ),
    "service": (
        "svc_any",
        "svc_any_stated",
        "svc_negate",
        "protos",
        "ports",
        "svc_opaque",
        "svc_opaque_reasons",
        "svc_src_port",
        "src_ports",
        "svc_obj_count",
    ),
    "connection state": ("states",),
    "inbound interface": ("in_if", "in_if_group"),
    "outbound interface": ("out_if", "out_if_group"),
}


def _matches_on(r: dict[str, Any], dim: str) -> bool:
    """Whether rule row `r` narrows dimension `dim` of `_JUMP_DIMENSIONS`."""
    if dim in ("source addresses", "destination addresses"):
        side = "src" if dim == "source addresses" else "dst"
        return not r.get(f"{side}_any") or bool(r.get(f"{side}_negate"))
    if dim == "service":
        return bool(r.get("svc_obj_count")) or bool(r.get("svc_negate"))
    return any(r.get(k) for k in _JUMP_DIMENSIONS[dim])


def _undecided_row(r: dict[str, Any], reason: str) -> dict[str, Any]:
    """Row `r`, undecided for a flow its addresses and service match.

    `reason` is added beside any reason the row already has. The row is
    marked `states_opaque`, and `_scope_reason` reads the reason."""
    why = [r.get("states_opaque_reason") or _UNREAD_STATE_REASON] if r.get("states_opaque") else []
    return {
        **r,
        "jump_target": None,
        "states_opaque": True,
        "states_opaque_reason": "; ".join([*why, reason]),
    }


def _jump_scoped(j: dict[str, Any], t: dict[str, Any], target: str) -> dict[str, Any]:
    """Rule `t` of the ruleset that jump rule `j` names, as it reads in the
    place of `j`. It governs a flow only when `j` does too.

    On a dimension only `j` matches on, `t` takes the columns of `j`. On a
    dimension both match on, `t` keeps its own columns and is undecided for a
    flow it otherwise matches. The rule rows cannot express the intersection
    of two matches. The row keeps the uid of `t`, which is the rule that
    decides. The row takes the position of `j`, which is the place in the
    chain where it is evaluated."""
    row = dict(t)
    clashes = []
    for dim, keys in _JUMP_DIMENSIONS.items():
        if not _matches_on(j, dim):
            continue
        if not _matches_on(t, dim):
            row.update({k: j.get(k) for k in keys})
        elif any(j.get(k) != t.get(k) for k in keys):
            clashes.append(dim)
    row["pos"] = j["pos"]
    row["name"] = f"jump to {target}, rule {t['pos']}" + (f": {t['name']}" if t.get("name") else "")
    row["unmodeled_fields"] = list(
        dict.fromkeys([*(j.get("unmodeled_fields") or []), *(t.get("unmodeled_fields") or [])])
    )
    if j.get("states_opaque"):
        row = _undecided_row(row, j.get("states_opaque_reason") or _UNREAD_STATE_REASON)
    if clashes:
        row = _undecided_row(
            row, _JUMP_SCOPE_REASON.format(pos=t["pos"], target=target, dims=", ".join(clashes))
        )
    return row


def _expand_jumps(
    session: Any,
    rows: list[dict[str, Any]],
    chain: tuple[str, ...],
    query: str = _RULEBASE_RULES,
) -> list[dict[str, Any]]:
    """A rulebase's rule rows with each VyOS jump replaced by what it evaluates.

    `action jump` evaluates the named ruleset `jump_target` for the flows the
    jump rule matches. A rule there that accepts, drops or rejects decides the
    flow for the whole chain. A flow that no rule there matches takes that
    ruleset's default action. Each jump rule is replaced in place by the
    target's rules, scoped to the jump rule (`_jump_scoped`), and a catch-all
    for the target's default action. A `return` rule inside the target is
    undecided unless it matches every flow. `continue` is dropped.

    `chain` is the rulebases being expanded, outermost first. A jump to a
    rulebase in `chain` is a loop. `query` is the rules query the caller read
    `rows` with."""
    out: list[dict[str, Any]] = []
    for r in rows:
        action = str(r.get("action") or "").strip().lower()
        if action == "continue":
            continue
        if action != "jump":
            out.append(r)
        elif not r.get("jump_target"):
            out.append(_undecided_row(r, _JUMP_NO_TARGET_REASON))
        else:
            out.extend(_jumped(session, r, str(r["jump_target"]), chain, query))
    return out


def _jumped(
    session: Any, j: dict[str, Any], target: str, chain: tuple[str, ...], query: str
) -> list[dict[str, Any]]:
    """The rows jump rule `j` stands for (`_expand_jumps`)."""
    if target in chain or len(chain) >= _JUMP_DEPTH:
        return [_undecided_row(j, _JUMP_LOOP_REASON.format(depth=_JUMP_DEPTH))]
    rb = _path._read_one(session, _JUMP_TARGET, rb=target)
    if rb is None:
        return [_undecided_row(j, _JUMP_UNDEFINED_REASON.format(target=target))]
    name = str(rb.get("rb_name") or target)
    inner = _expand_jumps(session, _path._read(session, query, rb=target), (*chain, target), query)
    out: list[dict[str, Any]] = []
    for t in inner:
        if str(t.get("action") or "").strip().lower() == "return":
            if not any(_matches_on(t, dim) for dim in _JUMP_DIMENSIONS) and not _scope_reason(t):
                # Every flow that the jump rule passes returns here. The rest of
                # the target and its default action are not reached.
                return out
            out.append(
                _undecided_row(
                    _jump_scoped(j, t, name), _JUMP_RETURN_REASON.format(pos=t["pos"], target=name)
                )
            )
            continue
        out.append(_jump_scoped(j, t, name))
    default = str(rb.get("default_action") or "").strip().lower()
    fallthrough = {**j, "jump_target": None, "name": f"jump to {name}, default-action"}
    if default == "return":
        return out
    if default == "jump" and rb.get("default_jump_target"):
        return out + _jumped(session, fallthrough, str(rb["default_jump_target"]), (*chain, target), query)
    if not default:
        if rb.get("default_action_unknown"):
            return [*out, _undecided_row(fallthrough, _JUMP_DEFAULT_REASON.format(target=name))]
        # With no default and no marker, the row is undecided, as in `_default_action_result`.
        return [*out, _undecided_row(fallthrough, _unstated_default(f"rulebase {target}")[1])]
    if classify_action(default) == INDETERMINATE:
        return [
            *out,
            _undecided_row(fallthrough, _JUMP_DEFAULT_ACTION_REASON.format(action=default, target=name)),
        ]
    return [*out, {**fallthrough, "action": default}]


def _rule_rows(session: Any, rb_uid: str) -> list[dict[str, Any]]:
    """The rule rows of one rulebase as the gate evaluates them.

    The rows are read with `_RULEBASE_RULES`, and the jumps are expanded
    (`_expand_jumps`)."""
    rows: list[dict[str, Any]] = _path._read(session, _RULEBASE_RULES, rb=rb_uid)
    return _expand_jumps(session, rows, (rb_uid,))


def _rb_result(
    rb: dict[str, Any],
    action: str,
    rule: dict[str, Any] | None,
    partial: bool,
    state_skips: list[dict[str, Any]],
    reason: str | None = None,
) -> dict[str, Any]:
    """One rulebase's decision, in the shape every verdict caller reads."""
    return {
        "rb_uid": rb["rb_uid"],
        "rb_name": rb.get("rb_name"),
        # The UI slot of the zone pair holds the vendor. This model has no zone pair.
        "zones": rb.get("vendor") or "device",
        "rule_uid": rule["uid"] if rule else None,
        "pos": rule["pos"] if rule else None,
        # An inferred binding gives no confident answer.
        "action": INDETERMINATE if rb.get("approximate") else action,
        "rule_name": rule["name"] if rule else None,
        "by": "rule" if rule else "default-action",
        "partial": partial,
        "approximate_binding": bool(rb.get("approximate")),
        "indeterminate_reason": reason or (rule or {}).get("indeterminate_reason"),
        # the rules passed over because they are scoped to a connection
        # state the traced flow does not have, and the device-wide state
        # policy that decides those flows ahead of every ruleset
        "state_skips": state_skips,
        "global_state_policy": rb.get("global_state_policy"),
        "state_policy_basis": rb.get("state_policy_basis"),
    }


def _default_action_result(
    rb: dict[str, Any], state_skips: list[dict[str, Any]], conn_state: str = "new"
) -> dict[str, Any]:
    """The decision when no rule matched.

    A recorded default-action decides, such as a Check Point layer's implicit
    cleanup action or a chain default. A rulebase without a recorded
    default-action is undecided."""
    if not rb["default_action"]:
        reason = (
            _UNKNOWN_DEFAULT_REASON
            if rb.get("default_action_unknown")
            else _unstated_default(f"rulebase {rb['rb_uid']}")[1]
        )
        return _rb_result(rb, INDETERMINATE, None, False, state_skips, reason=reason)
    action, why = _fallthrough(
        rb["default_action"],
        None,
        _state_rules_unreported(rb, conn_state, "established_default_unknown"),
    )
    return _rb_result(rb, action, None, False, state_skips, reason=why)


@dataclass(frozen=True)
class _RbQuery:
    """The flow one `_judge_rulebases` call decides.

    The service dimensions are normalized only when the query states a range.
    """

    src_set: list[tuple[int, int, int]]
    dst_set: list[tuple[int, int, int]]
    port: Any
    proto: Any
    is_range: bool
    proto_set: frozenset[int] | None
    port_ivals: list[tuple[int, int, int]] | None
    sport_ivals: Ivals | None
    sport_stated: bool
    src_size: int
    dst_size: int

    def partial(self, src_hit: list[tuple[int, int, int]], dst_hit: list[tuple[int, int, int]]) -> bool:
        return (_size(src_hit) < self.src_size) or (_size(dst_hit) < self.dst_size)

    def whole_range(self, d: dict[str, Any]) -> dict[str, Any] | list[dict[str, Any]]:
        """A decision that did not read the protocol or the port.

        A range query reports it as one region that covers the whole query. A
        point query reports it as the bare dict."""
        if not self.is_range:
            return d
        whole = {**d, "proto_subset": self.proto_set, "port_subset": self.port_ivals}
        if self.sport_stated:
            whole["sport_subset"] = self.sport_ivals
        return [whole]


def _rb_query(
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: Any,
    proto: Any,
    src_port: Any,
) -> _RbQuery:
    """Normalize a query for `_judge_rulebases`.

    Raises ValueError for an unreadable ranged port or protocol."""
    sport_ivals, sport_stated = _sport_query(src_port)
    is_range = _states_a_range(_unwrap_single(port), _unwrap_single(proto)) or sport_stated
    return _RbQuery(
        src_set=src_set,
        dst_set=dst_set,
        port=port,
        proto=proto,
        is_range=is_range,
        proto_set=_as_protoset(_unwrap_single(proto))[0] if is_range else None,
        port_ivals=_as_portset(_unwrap_single(port))[0] if is_range else None,
        sport_ivals=sport_ivals,
        sport_stated=sport_stated,
        src_size=_size(src_set),
        dst_size=_size(dst_set),
    )


def _installed_rules(rules: list[dict[str, Any]], owner: str | None) -> list[dict[str, Any]]:
    """The rules of a rulebase that are installed on the gateway its binding
    names, `owner` being that gateway's management object uid.

    A Check Point rule's install-on column scopes it to some of the gateways
    its layer is bound to. A rule whose column names gateways and not this
    one is not installed here and is left out with confidence. One whose
    column names this gateway reads as a rule with no install-on scope. One
    whose column names an entry that resolves to no gateway (a gateway
    group), or that is judged for a binding with no gateway uid, cannot be
    placed either way. It is kept with its scope. `_scope_reason` makes it
    undecided once its addresses and service otherwise match.
    """
    out = []
    for r in rules:
        install_on = r.get("install_on") or []
        if not install_on and not r.get("install_on_unresolved"):
            out.append(r)
        elif owner is not None and owner in install_on:
            out.append({**r, "install_on": [], "install_on_unresolved": False})
        elif r.get("install_on_unresolved") or owner is None:
            out.append(r)
    return out


def _scope_reason(r: dict[str, Any]) -> str | None:
    """Why a rule that otherwise matches cannot be applied, when a scope of
    it that is not a match dimension is not known.

    The reasons are an unreadable connection state clause, vendor fields that
    are not modeled, and an install-on column that `_installed_rules` could
    not place.
    """
    if r.get("states_opaque"):
        return r.get("states_opaque_reason") or _UNREAD_STATE_REASON
    # the collector sets `states_opaque` beside a non-empty list
    if r.get("unmodeled_fields"):
        return _UNMODELED_FIELDS_REASON.format(fields=", ".join(map(str, r["unmodeled_fields"])))
    if r.get("install_on") or r.get("install_on_unresolved"):
        return _INSTALL_ON_REASON
    return None


def _judge_rulebase(
    rb: dict[str, Any],
    rules: list[dict[str, Any]] | None,
    names: _Rulebases,
    q: _RbQuery,
    *,
    has_egress: bool,
    conn_state: str,
    acl_direction: str | None,
    unresolved: frozenset[str] = frozenset(),
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """One candidate's decision, evaluated first-match by position.

    `unresolved` names the sides whose interface name did not resolve, as in
    `_first_match`."""
    if rules is None:
        vendor = str(rb.get("vendor") or "").strip().lower()
        if vendor == "checkpoint":
            reason = "Check Point implied rules and their placement were not collected for local traffic"
        else:
            reason = "a chainless access policy has no modeled router-local pipeline scope"
        unknown = {**_rb_result(rb, INDETERMINATE, None, False, [], reason), "by": "pipeline-scope"}
        return q.whole_range(unknown)
    in_name, out_name = names.in_name, names.out_name
    bound = rb.get("acl_direction")
    if _is_iface_acl(rb) and acl_direction is not None:
        if bound == "out" and acl_direction == "in" and out_name is not None:
            # A list bound outbound on a resolved egress is judged at the egress
            # stage, after source NAT, on the packet as it leaves.
            return None
        if bound == "in" and acl_direction == "out":
            return None
    state_skips: list[dict[str, Any]] = []
    if _is_iface_acl(rb):
        governs = (
            _acl_governs_hop(bound, rb.get("acl_interfaces") or [], in_name, out_name, has_egress=has_egress)
            if bound in ("in", "out")
            else "excluded"
        )
        if governs == "excluded":
            return None
        if not rb.get("acl_legacy"):
            # the binding this view judged, in the leg and verdict text
            on = (out_name if bound == "out" else in_name) if governs == "governs" else None
            on = on or ", ".join(rb.get("acl_interfaces") or [])
            rb = {**rb, "rb_name": f"{rb.get('rb_name')} ({bound} on {on})"}
        if governs != "governs":
            # the list is bound on the one side this leg's interface name
            # did not resolve
            return q.whole_range(_rb_result(rb, INDETERMINATE, None, False, state_skips, reason=governs))

    rules = _installed_rules(rules, rb.get("owner_raw_uid"))
    if not q.is_range:
        m = _first_match(
            rules,
            in_name,
            out_name,
            q.src_set,
            q.dst_set,
            q.port,
            q.proto,
            state_skips,
            conn_state=conn_state,
            unresolved=unresolved,
        )
        if m:
            point = cast("tuple[dict[str, Any], list[tuple[int, int, int]], list[tuple[int, int, int]]]", m)
            r, src_hit, dst_hit = point
            return _rb_result(rb, r["action"], r, q.partial(src_hit, dst_hit), state_skips)
        return _default_action_result(rb, state_skips, conn_state)
    out: list[dict[str, Any]] = []
    for sport_sub, decided in _first_match_by_sport(
        rules,
        in_name,
        out_name,
        q.src_set,
        q.dst_set,
        q.proto_set,
        q.port_ivals,
        q.sport_ivals,
        state_skips,
        conn_state=conn_state,
        unresolved=unresolved,
    ):
        for decided_rule, src_hit, dst_hit, proto_sub, port_sub in decided:
            if decided_rule is not None:
                d = _rb_result(
                    rb, decided_rule["action"], decided_rule, q.partial(src_hit, dst_hit), state_skips
                )
            else:
                d = _default_action_result(rb, state_skips, conn_state)
            d.update(proto_subset=proto_sub, port_subset=port_sub)
            if q.sport_stated:
                d["sport_subset"] = sport_sub
            out.append(d)
    return out


def _fold_point(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The verdict of candidates that the flow must all pass.

    A deny from any one is the verdict, then an undecided one, then a permit
    that covers only part of the flow, then the first candidate's answer."""
    if not results:
        return None
    for wanted in (DENY, INDETERMINATE):
        hit = next((r for r in results if classify_action(r["action"]) == wanted), None)
        if hit:
            return hit
    return _permit_pick(results)


def _fold_ranges(region_lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
    """The range counterpart of `_fold_point`.

    A deny from any candidate is the verdict of a region.
    """
    cap = Settings().path_region_cap
    combined: list[dict[str, Any]] | None = None
    for region_list in region_lists:
        combined = region_list if combined is None else _refine_regions(combined, region_list)
        combined = _cap_candidate_regions(_merge_candidate_regions_by_outcome(combined), cap)
    return combined or None


def _judge_rulebases(
    names: _Rulebases,
    judged: Iterable[tuple[dict[str, Any], list[dict[str, Any]] | None]],
    q: _RbQuery,
    *,
    has_egress: bool,
    conn_state: str,
    acl_direction: str | None,
    considered: list[str] | None = None,
    unresolved: frozenset[str] = frozenset(),
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """Judge every loaded candidate on one query and fold their decisions.

    `considered`, when given, is extended with every candidate that produced
    a decision. The flow must pass each of them. A candidate that permitted
    and did not decide the leg, such as a second Check Point ordered layer,
    is added too."""
    decisions = []
    for rb, rules in judged:
        d = _judge_rulebase(
            rb,
            rules,
            names,
            q,
            has_egress=has_egress,
            conn_state=conn_state,
            acl_direction=acl_direction,
            unresolved=unresolved,
        )
        if d is not None:
            decisions.append(d)
            if considered is not None and rb["rb_uid"] not in considered:
                considered.append(rb["rb_uid"])
    if not q.is_range:
        return _fold_point(cast("list[dict[str, Any]]", decisions))
    return _fold_ranges(cast("list[list[dict[str, Any]]]", decisions))


def _device_rulebase_verdict(
    session: Any,
    dev_uid: str,
    in_if: str,
    out_if: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    af: int,
    chain: str = "forward",
    considered: list[str] | None = None,
    *,
    only_interface_acls: bool = False,
    has_egress: bool = True,
    require_chain: bool = False,
    conn_state: str = "new",
    src_port: Any = None,
    strict_local: bool = False,
    acl_direction: str | None = None,
    local_acls: bool = False,
) -> dict[str, Any] | list[dict[str, Any]] | None:
    """Device-wide access rulebases, each evaluated first-match by position.

    `local_acls` marks the router-local read of the inbound interface ACLs
    (`_firewall_verdict_local`). An ACL that records its chain is not a
    candidate there. It filters only the chain it names.

    `acl_direction` names the interface-ACL binding this stage judges. It is
    'in' at the filter stage and 'out' at the egress stage after source NAT. An
    interface ACL bound the other way is not a candidate here. An outbound
    list on a leg whose egress name did not resolve stays a candidate at the
    filter stage. None, the default, judges both directions here.

    `src_port`, when stated, is read as `_zone_pair_verdict` reads it.

    The candidates have two shapes. They are the Check Point model (a policy
    ENFORCED on the gateway) and the VyOS filter chains
    (ipv4-forward/ipv6-forward). Rules have `src_any`/`dst_any`/`svc_any` for
    the wildcard case and SRC/DST/SVC edges to NetObject/SvcObject otherwise.
    The interval arithmetic is the one the zone path uses.

    A deny from any device-wide rulebase for the flow's address family is
    the verdict. These rulebases are not candidates:

    - zone-bound rulebases (FROM_ZONE/TO_ZONE)
    - input and output chains (`rb.chain`), which gate router-local traffic.
      Only the forward chain or a chain-less rulebase is device-wide.
    - the other family's chains
    - an interface ACL (`match_context` 'interface-acl') not bound to an
      interface this hop uses in the direction judged (`_acl_governs_hop`)

    `considered`, when given, is extended with the uid of every interface-ACL
    candidate the query returned, and with every device-wide candidate that
    its recorded family rules out or that is judged.

    `approximate` on the ENFORCES edge forces the action to indeterminate.

    A scalar `port` and `proto` return a single dict or None. A range returns
    a list of dicts.
    """
    rulebases = _load_rulebases(
        session,
        dev_uid,
        in_if,
        out_if,
        af,
        chain,
        considered,
        only_interface_acls=only_interface_acls,
        require_chain=require_chain,
        strict_local=strict_local,
        local_acls=local_acls,
    )
    if rulebases is None:
        return None
    # The query is parsed after the interface names are read and before the
    # rules are read.
    q = _rb_query(src_set, dst_set, port, proto, src_port)
    judged = _load_rules(session, rulebases.candidates, chain, strict_local)
    return _judge_rulebases(
        rulebases,
        judged,
        q,
        has_egress=has_egress,
        conn_state=conn_state,
        acl_direction=acl_direction,
        considered=considered,
        unresolved=_unresolved_sides(
            in_if, rulebases.in_name, rulebases.out_name, chain=chain, has_egress=has_egress
        ),
    )


def _unresolved_sides(
    in_if: str | None, in_name: str | None, out_name: str | None, *, chain: str, has_egress: bool
) -> frozenset[str]:
    """The sides of a hop that exist but whose interface name did not resolve
    (`_iface_scope`).

    The ingress is such a side when its uid was given and has no name. The
    egress is such a side when `has_egress` is true, the chain is not the
    input chain, and the egress name is not known. A missing egress uid also
    gives an unknown name. A packet that the device terminates in the input
    chain leaves by no interface."""
    sides = set()
    if in_if and in_name is None:
        sides.add("in")
    if has_egress and chain != "input" and out_name is None:
        sides.add("out")
    return frozenset(sides)


# The chains a device's access rulebases are recorded in. A packet the device
# terminates or emits crosses exactly one of them.
_DEVICE_CHAINS = """
MATCH (dev:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND NOT rb:Retired AND e._retired_at IS NULL AND coalesce(rb.kind, 'access') = 'access'
  AND rb.chain IS NOT NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.chain AS chain ORDER BY chain"""


def _other_chain_rulebases(session: Any, dev_uid: str, chain: str, in_if: str | None = None) -> list[str]:
    """The rulebases ruled out by their chain alone, for the leg to credit.

    `in_if` is the ingress interface uid, the key of the candidate query's VSX
    context branch. Without it that branch matches nothing.

    The candidate set is the one `_device_rulebase_verdict` evaluates. A
    zone-bound ruleset and a rulebase that recorded no chain stay
    uncredited.
    """
    chains = [
        r["chain"]
        for r in _path._read(session, _DEVICE_CHAINS, dev=dev_uid)
        if r.get("chain") in {"input", "output", "forward"} and r.get("chain") != chain
    ]
    uids: list[str] = []
    for other in chains:
        uids.extend(
            rb["rb_uid"]
            for rb in _path._read(
                session,
                _RULEBASE_CANDIDATES,
                dev=dev_uid,
                in_if=in_if or None,
                chain=other,
                strict_local=False,
            )
            if rb["rb_uid"]
            # The candidate query folds a missing chain into 'forward'. A
            # rulebase that recorded no chain is not ruled out by chain.
            and rb.get("chain") is not None
        )
    return uids


# Every zone-bound rulebase of a device. Such a rulebase has a FROM_ZONE or
# TO_ZONE zone that is CONTAINS-bound to one of the device's own interfaces.
# Zones are matched by node. `dst_unbound` marks a TO_ZONE zone with no
# CONTAINS edge.
_DEVICE_ZONE_RULEBASES = """
MATCH (dev:Device {uid: $dev})<-[:ON]-(:Interface)<-[c:CONTAINS]-(z:Zone)
WHERE dev:Obj AND dev.collection_ts = $snap AND NOT z:Retired AND c._retired_at IS NULL
WITH collect(DISTINCT z) AS device_zones
// the rulebases bound to one of the device's zones, found from the zones
// rather than by scanning every rulebase
UNWIND device_zones AS dz
MATCH (rb:FwRulebase)-[:FROM_ZONE|TO_ZONE]->(dz)
WITH DISTINCT rb, device_zones
MATCH (rb)-[fz:FROM_ZONE]->(src:Zone), (rb)-[tz:TO_ZONE]->(dst:Zone)
WHERE NOT rb:Retired AND NOT src:Retired AND NOT dst:Retired
  AND fz._retired_at IS NULL AND tz._retired_at IS NULL
  AND rb.collection_ts = $snap
  AND (src IN device_zones OR dst IN device_zones)
RETURN DISTINCT rb.uid AS rb_uid, rb.af AS af, src.name AS src_zone, dst.name AS dst_zone,
       NOT EXISTS {
         MATCH (dst)-[cc:CONTAINS]->(:Interface) WHERE cc._retired_at IS NULL
       } AS dst_unbound
ORDER BY rb_uid"""


def _other_zone_pair_rulebases(
    session: Any, dev_uid: str, pair: tuple[str, str] | None, af: int, *, any_family: bool = False
) -> list[str]:
    """The zone-bound rulebases ruled out by pair or family, for the leg to credit.

    `pair` is None when the ingress and egress interfaces did not resolve to
    two zones, and nothing is ruled out. A rulebase whose pair and address
    family both match is not credited here.

    `any_family` keeps every rulebase of the pair out, whatever its family.
    """
    if pair is None:
        return []
    uids: list[str] = []
    for r in _path._read(session, _DEVICE_ZONE_RULEBASES, dev=dev_uid):
        if not r["rb_uid"]:
            continue
        if (r["src_zone"], r["dst_zone"]) == pair and (any_family or _rb_af(r) == af):
            continue
        uids.append(r["rb_uid"])
    return uids


def _local_zone_name(session: Any, dev_uid: str, src_zone: str) -> str | None:
    """The name of this device's local (router) zone, or None if the zone
    model does not record exactly one.

    The local zone is a zone paired with `src_zone` as a TO_ZONE target that
    is itself bound to no interface (`dst_unbound`).
    """
    names = {
        r["dst_zone"]
        for r in _path._read(session, _DEVICE_ZONE_RULEBASES, dev=dev_uid)
        if r["src_zone"] == src_zone and r.get("dst_unbound")
    }
    return next(iter(names)) if len(names) == 1 else None


def _firewall_verdict_local(
    session: Any,
    dev_uid: str,
    out_if: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    *,
    chain: str = "output",
    in_if: str = "",
    considered: list[str] | None = None,
    conn_state: str = "new",
    self_sent: bool = False,
) -> dict[str, Any] | None:
    """The verdict for a packet the router itself terminates or emits.

    The two router-local directions share one rule pool. The output chain
    judges a packet the device sources (a carrier packet). The input chain
    judges a packet addressed to the device's own interface. The caller names
    the chain and the side it has. An emitted packet has an egress and no
    ingress. An accepted packet has an ingress and no egress.

    The forward zone pairs are not consulted. A zone pair binds an ingress to
    an egress, and router-local traffic crosses no such pair. A zone firewall
    that records a local zone judges a new connection by the pair between that
    zone and the zone of the interface (`_local_zone_verdict`). That pair is a
    third pool under the same precedence. `self_sent` (the source covers one
    of the device's own addresses) skips that pool. A packet the device sends
    to itself enters on the loopback, which no from-zone rule set governs.
    Its local-zone handling is not modelled, and the pair stays in the
    unevaluated-gate report.

    An inbound interface ACL that records no chain is a second pool for the
    input direction, evaluated against the ingress side only. A deny or an
    undecided verdict from any pool is the answer.

    `considered`, when given, is extended with the rulebases of the device's
    other chains and with the interface-ACL candidates the two reads looked
    at.
    """
    af = (dst_set or src_set)[0][0] if (dst_set or src_set) else 4
    # The zone policy between the local zone and the zone of the interface
    # (`_local_zone_verdict`). It is None where the device records no local zone.
    zone = (
        None
        if self_sent
        else _local_zone_verdict(
            session, dev_uid, chain, in_if, out_if, src_set, dst_set, port, proto, considered, conn_state
        )
    )
    if considered is not None:
        considered.extend(_other_chain_rulebases(session, dev_uid, chain, in_if))
        # Every (ingress zone, local zone) rulebase stays uncredited here.
        if in_if:
            src_zone = _zone_of(session, in_if)
            if src_zone:
                local_zone = _local_zone_name(session, dev_uid, src_zone["name"])
                if local_zone:
                    considered.extend(
                        _other_zone_pair_rulebases(
                            session, dev_uid, (src_zone["name"], local_zone), af, any_family=True
                        )
                    )
    _refuse_ranged_query(port, proto)
    fw = _point_verdict(
        _device_rulebase_verdict(
            session,
            dev_uid,
            in_if,
            out_if,
            src_set,
            dst_set,
            port,
            proto,
            af,
            chain=chain,
            considered=considered,
            conn_state=conn_state,
        ),
        port,
        proto,
    )
    if chain != "input":
        return _local_precedence([fw, zone])
    acl = _point_verdict(
        _device_rulebase_verdict(
            session,
            dev_uid,
            in_if,
            None,
            src_set,
            dst_set,
            port,
            proto,
            af,
            chain="forward",
            considered=considered,
            only_interface_acls=True,
            has_egress=False,
            conn_state=conn_state,
            local_acls=True,
        ),
        port,
        proto,
    )
    return _local_precedence([fw, acl, zone])


def _local_precedence(verdicts: list[dict[str, Any] | None]) -> dict[str, Any] | None:
    """One router-local verdict from the pools that judge the packet.

    A deny from any pool wins, then an undecided verdict from any pool, else a
    permit (`_permit_pick`). `_device_rulebase_verdict` applies the same
    precedence within one pool."""
    results = [r for r in verdicts if r is not None]
    for wanted in (DENY, INDETERMINATE):
        hit = next((r for r in results if classify_action(r["action"]) == wanted), None)
        if hit:
            return hit
    return _permit_pick(results) if results else None


_LOCAL_ZONE_MIXED_REASON = (
    "the local-zone policy decides the parts of the flow the query leaves open differently"
)
_LOCAL_ZONES_UNBOUND_REASON = "more than one zone of this device is bound to no interface"


def _local_zone_verdict(
    session: Any,
    dev_uid: str,
    chain: str,
    in_if: str | None,
    out_if: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    considered: list[str] | None,
    conn_state: str,
) -> dict[str, Any] | None:
    """The verdict of the zone policy between the device's local zone and the
    zone of the interface a router-local packet arrives on (`input`) or
    leaves by (`output`), for the packet's own family.

    The evaluation is the one of `LocalZoneTransition` (gates/local_zone.py),
    which the impact engine runs. The local zone is the zone that the
    collector marks `local_zone` and that the device owns. The pair's rule set
    for the family is walked first-match, with jumps, groups and states. A
    family with no rule set bound takes the local or egress zone's recorded
    default-action. What that read does not establish is undecided with its
    reason.

    The result is None where that read finds no local zone, and for a packet
    that is not a new connection.

    `considered` is extended with the rulebases the read evaluated or ruled
    out by pair or family (the transition's `considered`).
    """
    from .local_zone import LocalZoneTransition  # local_zone imports this module

    interface = in_if if chain == "input" else out_if
    if conn_state != "new" or chain not in ("input", "output") or not interface:
        return None
    _refuse_ranged_query(port, proto)
    try:
        proto_set = _as_protoset(_unwrap_single(proto))[0]
    except ValueError:
        # a protocol name outside the number table is read as not stated
        proto_set = None
    if bool(src_set) != bool(dst_set):
        # One side is not known, for example for a carrier whose source address
        # was not resolved. That side is read as the whole family. A rule scoped
        # to an address on that side is then undecided (partial).
        whole = _intervals(["::/0" if (src_set or dst_set)[0][0] == 6 else "0.0.0.0/0"])
        src_set, dst_set = src_set or whole, dst_set or whole
    region = FlowRegion.from_query(src_set, dst_set, proto_set, _as_portset(_unwrap_single(port))[0])
    if not region:
        return None
    transition = LocalZoneTransition(session, dev_uid, in_if or None, out_if or None, chain)
    effects = [effect for _part, effect in transition.apply(region)]
    if not effects or all(effect.kind == "pass" for effect in effects):
        return None
    zone_names = {z.get("zone_uid"): z.get("zone_name") for z in transition._owned_zones or []}
    unbound = {
        r["dst_zone"]
        for r in _path._read(session, _DEVICE_ZONE_RULEBASES, dev=dev_uid)
        if r.get("dst_unbound")
    }
    if considered is not None and len(unbound) <= 1:
        considered.extend(transition.considered)
    verdicts = [_local_zone_effect_verdict(effect, zone_names) for effect in effects]
    first = verdicts[0]
    if len(unbound) > 1:
        # The structural signature of the local zone (`_local_zone_name`) is
        # not unique. The marker alone does not settle which zone is the router.
        return {**first, "action": INDETERMINATE, "indeterminate_reason": _LOCAL_ZONES_UNBOUND_REASON}
    if any(v["action"] != first["action"] or v["rb_uid"] != first["rb_uid"] for v in verdicts[1:]):
        return {**first, "action": INDETERMINATE, "indeterminate_reason": _LOCAL_ZONE_MIXED_REASON}
    return first


def _local_zone_effect_verdict(effect: Effect, zone_names: dict[Any, Any]) -> dict[str, Any]:
    """A `LocalZoneTransition` effect in the verdict shape the router-local
    callers read.

    A zone default-action, or a read that stopped before a pair, has no
    rulebase. It gets a synthetic station uid, as the unbound zone pair of
    `_zone_pair_verdict` does. No gate answers to that uid."""
    data = effect.data
    src = zone_names.get(data.get("src_zone_uid")) or data.get("src_zone_uid") or "?"
    dst = zone_names.get(data.get("dst_zone_uid")) or data.get("dst_zone_uid") or "?"
    rb_uid = data.get("rb_uid") if isinstance(data.get("rb_uid"), str) else None
    if rb_uid:
        rb_name, by = data.get("rb_name") or rb_uid, "rule" if data.get("rule_uid") else "default-action"
    elif data.get("by") == "zone-default":
        rb_uid = f"zone-pair:{src}->{dst}#unbound"
        rb_name, by = f"{src}→{dst} zone policy (no ruleset bound)", "default-action"
    else:
        rb_uid, rb_name, by = "zone-pair:local#unresolved", "local-zone policy", "default-action"
    action = effect.kind if effect.kind in (PERMIT, DENY, INDETERMINATE) else INDETERMINATE
    recorded = data.get("recorded_action")
    if action != INDETERMINATE and recorded and classify_action(recorded) == action:
        # the word the collection recorded ("accept", "drop", "reject"), as
        # every other verdict names it
        action = str(recorded)
    return {
        "rb_uid": rb_uid,
        "rb_name": rb_name,
        "zones": f"{src}→{dst}",
        "rule_uid": data.get("rule_uid"),
        "pos": data.get("rule_pos"),
        "action": action,
        "rule_name": data.get("rule_name"),
        "by": by,
        "partial": bool(data.get("partial")),
        "indeterminate_reason": effect.reason if action == INDETERMINATE else None,
        "state_skips": data.get("state_skips") or [],
    }


_RANGED_QUERY_ERROR = "a ranged query (port {port!r}, protocol {proto!r}) is not supported on this path"


def _refuse_ranged_query(port: Any, proto: Any) -> None:
    """Refuse a ranged port or protocol where one verdict is expected."""
    if _states_a_range(_unwrap_single(port), _unwrap_single(proto)):
        raise ValueError(_RANGED_QUERY_ERROR.format(port=port, proto=proto))


def _point_verdict(
    verdict: dict[str, Any] | list[dict[str, Any]] | None, port: Any, proto: Any
) -> dict[str, Any] | None:
    """The single verdict a leg reads, with a ranged query refused by name.

    A list means the query stated a range.
    """
    if isinstance(verdict, list):
        raise ValueError(_RANGED_QUERY_ERROR.format(port=port, proto=proto))
    return verdict


def _partial_permit(leg: dict[str, Any], fw: dict[str, Any], outcome: str, by: str) -> str:
    """`outcome`, with a permit that covers only part of the flow read as
    undecided.

    The first rule that hits any part of a network-scoped query decides the
    point walk. A permit for part of the range does not decide the rest. A
    partial deny stays a deny.
    """
    if outcome == PERMIT and fw.get("partial"):
        leg["indeterminate"] = True
        leg.setdefault(
            "indeterminate_reason",
            f"{fw['rb_name']} {by} permits only part of the flow's address range",
        )
        return INDETERMINATE
    return outcome


def _apply_firewall(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    out_if: str | None,
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    via: str,
    *,
    conn_state: str = "new",
    acl_direction: str | None = None,
) -> str | None:
    """Evaluate the firewall for one leg and write its hops, notes and leg fields.

    Returns the classified outcome, or None when no rulebase governs the device.

    `acl_direction` is the interface-ACL binding this call judges
    (`_device_rulebase_verdict`). A local-egress leg passes 'in', because its
    egress stage reads the outbound list after source NAT
    (`_apply_egress_acl`). A leg with no egress stage of its own passes None
    and judges both directions here.

    `conn_state` is forwarded to `_firewall_verdict`. A reply walk passes
    'established'.

    Only a 'new' (forward) call records this device's own reading, onto
    `leg['gate_state']`. Each write replaces `leg['gate_state']` with a new
    dict.
    """
    considered: list[str] = []
    _refuse_ranged_query(port, proto)
    fw = _point_verdict(
        _firewall_verdict(
            session,
            gw["dev_uid"],
            gw["if_uid"],
            out_if,
            sources,
            dsts,
            port,
            proto,
            considered,
            conn_state=conn_state,
            acl_direction=acl_direction,
        ),
        port,
        proto,
    )
    # The device-wide rulebase of a single-model device is not added here.
    if considered:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *considered})
    if not fw:
        if gw.get("vsx_kind") in {"virtual-system", "bridge"}:
            leg["indeterminate"] = True
            leg["firewall"] = "VS policy not established"
            trail.warn(
                f"VS {gw.get('vsid', '?')}: no governing access policy was established for this context"
            )
            if conn_state == "new":
                leg["gate_state"] = {
                    **leg.get("gate_state", {}),
                    forwarding_visit(gw): {"policy": None, "permit": False},
                }
            return INDETERMINATE
        if conn_state == "new":
            # No rulebase governed this hop. The hop is recorded as a permit with no policy.
            leg["gate_state"] = {
                **leg.get("gate_state", {}),
                forwarding_visit(gw): {"policy": None, "permit": True},
            }
        return None
    # `models` is every rulebase model that governs this hop, in the order the
    # device crosses them.
    models = fw.get("models") or [fw]
    for model in models:
        trail.hop(
            model["rb_uid"],
            "FwRulebase",
            model["rb_name"],
            f"{model['zones']} · {model['action']} ({model['by']})",
            stage=Stage.FILTER_RB,
        )
        if model["rule_uid"]:
            trail.hop(
                model["rule_uid"],
                "FwRule",
                f"rule {model['pos']}" + (f" ({model['rule_name']})" if model["rule_name"] else ""),
                model["action"],
                stage=Stage.FILTER_RULE,
            )
    by = f"rule {fw['pos']}" if fw["pos"] is not None else "default-action"
    leg["firewall"] = f"{fw['rb_name']} ({fw['zones']}) {fw['action']} by {by}"
    also = [m for m in models if m["rb_uid"] != fw["rb_uid"]]
    if also:
        leg["firewall"] += " · also crossed " + "; ".join(
            f"{m['rb_name']} ({m['zones']}) {m['action']}"
            + (f" by rule {m['pos']}" if m["pos"] is not None else " by default-action")
            for m in also
        )
    leg["fw_uid"] = fw["rb_uid"]
    if fw.get("partial"):
        leg["firewall"] += " (matches part of the range only)"
        trail.warn(
            f"{src_label}: {fw['rb_name']} {by} covers only part of the flow; narrow the query for a verdict"
        )
    nh = leg.get("next_hop")
    via_label = f"{via} → {nh}" if nh and via and nh != via else (via or nh or "?")
    trail.notes.append(f"{src_label} via {via_label}: {leg['firewall']}")
    # A rule passed over for its connection state is a note.
    modeled = "an established connection (a reply)" if conn_state == "established" else "a new connection"
    for skip in fw.get("state_skips") or []:
        trail.notes.append(
            f"{src_label}: rule {skip['pos']} is scoped to connection state "
            f"{'/'.join(skip['states'])}; this trace models {modeled}, so the rule "
            "does not govern it and evaluation continued to the next rule"
        )
    policy = fw.get("global_state_policy")
    if policy and conn_state != "established":
        trail.notes.append(
            f"{src_label}: the device's global state policy "
            f"({state_policy_text(policy, fw.get('state_policy_basis'))}) decides "
            "established and related traffic ahead of every ruleset; this trace models a "
            "new flow, which is the case the rulesets judge"
        )
    outcome = classify_action(fw["action"])
    if outcome == DENY:
        leg["blocked"] = True
        leg["verdict"] = f"BLOCKED by {fw['rb_name']} {by}"
    elif outcome == INDETERMINATE:
        leg["indeterminate"] = True
        if fw.get("approximate_binding"):
            why = (
                f"which rulebase governs this device was inferred, not "
                f"read (installation targets are not collected), so "
                f"{by} is reported but its verdict is not trusted"
            )
        elif fw.get("indeterminate_reason"):
            why = f"{by} could not be decided: {fw['indeterminate_reason']}"
        else:
            why = f"{by} has action {fw['action']!r}, which this engine does not evaluate"
        trail.warn(f"{src_label}: {fw['rb_name']}: {why}. The flow is NOT confirmed permitted.")
    outcome = _partial_permit(leg, fw, outcome, by)
    if conn_state == "new":
        # `credits` are the rulebases this crossing evaluated or ruled out.
        leg["gate_state"] = {
            **leg.get("gate_state", {}),
            forwarding_visit(gw): {
                "policy": policy,
                "permit": outcome == PERMIT and not leg.get("indeterminate"),
                # a zone default verdict has no rulebase uid
                "credits": sorted({*considered, *(m["rb_uid"] for m in models if m.get("rb_uid"))}),
            },
        }
    return outcome


# The device's own state policy is stored on the rulebases it governs. A device
# with device-wide chains binds them by ENFORCES. A zone-based device (VyOS
# zone policy) binds its rulesets to Zones that contain its interfaces.
_DEVICE_STATE_POLICY_QUERY = """
CALL {
  MATCH (d:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase)
  WHERE NOT rb:Retired AND e._retired_at IS NULL AND d:Obj AND d.collection_ts = $snap
    AND rb.global_state_policy IS NOT NULL
  RETURN rb.uid AS uid, rb.global_state_policy AS global_state_policy,
         rb.state_policy_basis AS state_policy_basis
  UNION
  MATCH (dev:Device {uid: $dev})<-[:ON]-(:Interface)<-[c:CONTAINS]-(z:Zone)
  WHERE dev:Obj AND dev.collection_ts = $snap AND NOT z:Retired AND c._retired_at IS NULL
  WITH collect(DISTINCT z) AS device_zones
  UNWIND device_zones AS dz
  MATCH (rb:FwRulebase)-[:FROM_ZONE|TO_ZONE]->(dz)
  WITH DISTINCT rb, device_zones
  MATCH (rb)-[fz:FROM_ZONE]->(src:Zone), (rb)-[tz:TO_ZONE]->(dst:Zone)
  WHERE NOT rb:Retired AND fz._retired_at IS NULL AND tz._retired_at IS NULL
    AND rb.collection_ts = $snap
    AND (src IN device_zones OR dst IN device_zones)
    AND rb.global_state_policy IS NOT NULL
  RETURN rb.uid AS uid, rb.global_state_policy AS global_state_policy,
         rb.state_policy_basis AS state_policy_basis
}
RETURN global_state_policy, state_policy_basis ORDER BY uid LIMIT 1"""


def _device_state_policy(session: Any, dev_uid: str) -> list[str] | None:
    """This device's own recorded `global_state_policy`, or None when it was
    not collected.

    Any one governed rulebase naming it answers for the device. Check Point
    records its fixed stateful behaviour on every access layer, with
    `state_policy_basis` "vendor-default" (collectors/checkpoint.py
    VENDOR_STATE_POLICY)."""
    return _device_state(session, dev_uid)[0]


def _device_state(session: Any, dev_uid: str) -> tuple[list[str] | None, str | None]:
    """(policy, basis) of this device's recorded state policy
    (`_device_state_policy`)."""
    row = _path._read_one(session, _DEVICE_STATE_POLICY_QUERY, dev=dev_uid)
    if not row or not row.get("global_state_policy"):
        return None, None
    basis = row.get("state_policy_basis")
    return list(row["global_state_policy"]), basis if isinstance(basis, str) else None


def _established_action(policy: list[str]) -> str | None:
    """What a recorded state policy does with established traffic.

    The result is PERMIT, DENY, or INDETERMINATE when its established actions
    conflict or are not ones this engine knows. The result is None when the
    policy names no established action (`invalid=drop` alone, or an entry
    with no `=`). The device's rules then decide the reply. The policy is
    parsed per state, as `_StatePolicyFilter` in impact/evaluate.py parses
    the same field."""
    actions = set()
    for entry in policy:
        state, sep, action = str(entry).strip().lower().partition("=")
        if sep and state.strip() == "established":
            actions.add(classify_action(action))
    if not actions:
        return None
    return next(iter(actions)) if len(actions) == 1 else INDETERMINATE


def _apply_firewall_reply(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    out_if: str | None,
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    via: str,
    *,
    acl_direction: str | None = None,
) -> str | None:
    """The firewall gate for one reply leg.

    `acl_direction` is forwarded to the admission read and to the
    `_apply_firewall` fallback (see there).

    A device whose own `global_state_policy` accepts established traffic,
    crossed by a forward leg that was a confirmed permit
    (`trail.device_gate_state`, recorded by `_apply_firewall` during the
    forward walk), admits the reply from session state. No rule is
    evaluated, and a note names the policy. A policy that drops or rejects
    established traffic blocks the reply of a flow the forward walk crossed
    here, ahead of every ruleset. A policy whose established actions conflict
    or are unknown leaves the leg undecided. A policy that names no
    established action (`invalid=drop` alone) decides nothing about the reply.

    Every other case falls through to ordinary rule evaluation on the
    reply's own (reversed and translated) tuple, via `_apply_firewall`. A
    device the forward walk crossed is evaluated with
    `conn_state='established'`, and any other device with `conn_state='new'`.

    The admission gets a station at the rulebase bound to the zone pair the
    reply crosses (ingress zone of `gw['if_uid']`, egress zone of `out_if`).
    """
    # A chassis-wide policy is not evidence of this VS's session behavior.
    policy = None if gw.get("firewall_instance_uid") else _device_state_policy(session, gw["dev_uid"])
    forward_state = trail.device_gate_state.get(forwarding_visit(gw))
    # The policy governs this connection's return traffic only where the
    # forward walk crossed the device. Elsewhere the reply is a new connection.
    established = _established_action(policy) if policy and forward_state is not None else None
    if forward_state is not None and forward_state.get("local"):
        return _apply_local_reply(
            session, trail, leg, gw, out_if, sources, dsts, port, proto, src_label, policy, forward_state
        )
    named = ", ".join(policy or [])
    if established == PERMIT and forward_state and forward_state.get("unconfirmed"):
        # The forward crossing here permitted the flow, and the forward leg
        # ended undecided. If the flow was permitted, the state policy admits
        # this reply. A rule read does not decide the reply.
        dev = gw["dev_name"] or gw["dev_uid"]
        note = f"session state admission not established ({named})"
        leg["firewall"] = note
        leg["indeterminate"] = True
        text = state_policy_text(policy or [], _device_state(session, gw["dev_uid"])[1])
        trail.warn(
            f"{src_label}: the forward flow through {dev} is not a confirmed permit; if it is "
            f"permitted, {dev}'s global state policy ({text}) admits this reply. "
            "The flow is NOT confirmed permitted."
        )
        _state_policy_station(
            session,
            trail,
            leg,
            gw,
            out_if,
            sources,
            dsts,
            port,
            proto,
            note,
            forward_state,
            acl_direction=acl_direction,
        )
        return INDETERMINATE
    if established == PERMIT and forward_state and forward_state.get("permit"):
        dev = gw["dev_name"] or gw["dev_uid"]
        note = f"admitted from session state ({named})"
        leg["firewall"] = note
        text = state_policy_text(policy or [], _device_state(session, gw["dev_uid"])[1])
        trail.notes.append(
            f"{src_label}: {dev}'s global state policy ({text}) already covers "
            "this reply; the forward flow through here was a confirmed permit, so no rule is "
            "evaluated for the return"
        )
        _state_policy_station(
            session,
            trail,
            leg,
            gw,
            out_if,
            sources,
            dsts,
            port,
            proto,
            note,
            forward_state,
            acl_direction=acl_direction,
        )
        return PERMIT
    if established in (DENY, INDETERMINATE):
        dev = gw["dev_name"] or gw["dev_uid"]
        text = state_policy_text(policy or [], _device_state(session, gw["dev_uid"])[1])
        if established == DENY:
            note = f"blocked by session state policy ({named})"
            leg["firewall"] = note
            leg["blocked"] = True
            leg["verdict"] = f"BLOCKED by {dev}'s global state policy ({named})"
            trail.notes.append(
                f"{src_label}: {dev}'s global state policy ({text}) drops established traffic "
                "ahead of every ruleset, so this reply is blocked and no rule is evaluated for it"
            )
        else:
            note = f"session state policy undecided ({named})"
            leg["firewall"] = note
            leg["indeterminate"] = True
            trail.warn(
                f"{src_label}: {dev}'s global state policy ({text}) gives established traffic "
                "conflicting or unknown actions, so whether it admits this reply is not known. "
                "The flow is NOT confirmed permitted."
            )
        fw_uid = _state_policy_station(
            session,
            trail,
            leg,
            gw,
            out_if,
            sources,
            dsts,
            port,
            proto,
            note,
            forward_state,
            acl_direction=acl_direction,
        )
        if fw_uid:
            leg["fw_uid"] = fw_uid
        return established
    fallback_conn_state = "established" if forward_state is not None else "new"
    outcome = _apply_firewall(
        session,
        trail,
        leg,
        gw,
        out_if,
        sources,
        dsts,
        port,
        proto,
        src_label,
        via,
        conn_state=fallback_conn_state,
        acl_direction=acl_direction,
    )
    return outcome


def _apply_local_reply(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    out_if: str | None,
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    policy: list[str] | None,
    forward_state: dict[str, Any],
) -> str | None:
    """The firewall gate for the reply a device sends to a flow it terminated.

    The forward leg was router-local (`_router_local_filter` recorded the
    entry `local`). This reply is locally originated. The forward chain and
    the zone pair of the interface that holds the address do not judge it.
    The state policy decides it as it decides any reply. Otherwise the output
    chain decides it, on the reply's own tuple, as an established connection.
    A policy that accepts established traffic, after a forward leg that is
    not a confirmed permit, leaves the reply undecided. Where the state
    policy decides, the rulebases that the input crossing credited are
    credited here, as `_state_policy_station` does for a transit reply. An
    output-chain read credits only what it read or ruled out."""
    dev = gw["dev_name"] or gw["dev_uid"]
    established = _established_action(policy) if policy else None
    named = ", ".join(policy or [])
    if established is not None:
        # The state policy decides the reply ahead of every ruleset.
        credits = [
            *(forward_state.get("credits") or []),
            *_other_chain_rulebases(session, gw["dev_uid"], "output"),
            *_local_reply_zone_rulebases(session, gw["dev_uid"], out_if),
        ]
        if credits:
            leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *credits})
        text = state_policy_text(policy or [], _device_state(session, gw["dev_uid"])[1])
        if established == PERMIT and not forward_state.get("permit"):
            # The forward flow here is not a confirmed permit. A blocked forward
            # leg starts no reply. If the flow was permitted, the state policy
            # admits this reply.
            leg["firewall"] = f"session state admission not established ({named})"
            leg["indeterminate"] = True
            trail.warn(
                f"{src_label}: the forward flow to {dev} is not a confirmed permit; if it is permitted, "
                f"{dev}'s global state policy ({text}) admits the reply it sends. "
                "The flow is NOT confirmed permitted."
            )
            return INDETERMINATE
        if established == PERMIT:
            leg["firewall"] = f"admitted from session state ({named})"
            trail.notes.append(
                f"{src_label}: {dev} answers a connection its input chain accepted; its global state "
                f"policy ({text}) covers the reply it sends, so no output rule is evaluated"
            )
        elif established == DENY:
            leg["firewall"] = f"blocked by session state policy ({named})"
            leg["blocked"] = True
            leg["verdict"] = f"BLOCKED by {dev}'s global state policy ({named})"
            trail.notes.append(
                f"{src_label}: {dev}'s global state policy ({text}) drops established traffic "
                "ahead of every ruleset, so the reply it sends is blocked"
            )
        else:
            leg["firewall"] = f"session state policy undecided ({named})"
            leg["indeterminate"] = True
            trail.warn(
                f"{src_label}: {dev}'s global state policy ({text}) gives established traffic "
                "conflicting or unknown actions, so whether it lets this reply out is not known. "
                "The flow is NOT confirmed permitted."
            )
        return established
    considered: list[str] = []
    fw = _firewall_verdict_local(
        session,
        gw["dev_uid"],
        out_if,
        sources,
        dsts,
        port,
        proto,
        chain="output",
        considered=considered,
        conn_state="established",
    )
    if considered:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *considered})
    if not fw:
        return None
    by = f"rule {fw['pos']}" if fw["pos"] is not None else "default-action"
    trail.hop(
        fw["rb_uid"],
        "FwRulebase",
        fw["rb_name"],
        f"output · {fw['action']} ({fw['by']})",
        stage=Stage.FILTER_RB,
    )
    if fw["rule_uid"]:
        trail.hop(
            fw["rule_uid"],
            "FwRule",
            f"rule {fw['pos']}" + (f" ({fw['rule_name']})" if fw["rule_name"] else ""),
            fw["action"],
            stage=Stage.FILTER_RULE,
        )
    leg["firewall"] = f"{fw['rb_name']} (output) {fw['action']} by {by}"
    leg["fw_uid"] = fw["rb_uid"]
    leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), fw["rb_uid"]})
    trail.notes.append(f"{src_label} sent by {dev}: {leg['firewall']}")
    outcome = classify_action(fw["action"])
    if outcome == DENY:
        leg["blocked"] = True
        leg["verdict"] = f"BLOCKED by {fw['rb_name']} {by}"
    elif outcome == INDETERMINATE:
        leg["indeterminate"] = True
        why = fw.get("indeterminate_reason") or f"{by} has action {fw['action']!r}"
        trail.warn(
            f"{src_label}: {fw['rb_name']} output chain could not decide: {why}. "
            "The flow is NOT confirmed permitted."
        )
    return _partial_permit(leg, fw, outcome, by)


def _local_reply_zone_rulebases(session: Any, dev_uid: str, out_if: str | None) -> list[str]:
    """The zone-bound rulebases that a locally sent reply credits when the
    state policy decided it. `_state_policy_station` credits the rulebases of
    a transit reply in the same way.

    The reply crosses the pair (local zone, zone of `out_if`). The state
    policy decides it ahead of that pair's rule sets. Every other pair is
    ruled out by pair. Every zone-bound rulebase of the device is credited
    when the egress zone is known and exactly one zone has no interface (the
    local zone). Otherwise nothing is credited, and the unevaluated-gate
    safeguard reports the rulebases."""
    egress = _zone_of(session, out_if)
    if not egress:
        return []
    rows = _path._read(session, _DEVICE_ZONE_RULEBASES, dev=dev_uid)
    # The local zone is the one zone with no interface (the signature that
    # `_local_zone_name` uses). It is found from any pair toward it. The
    # reply's own pair (local zone, egress zone) does not show that binding.
    if len({r["dst_zone"] for r in rows if r.get("dst_unbound")}) != 1:
        return []
    return [r["rb_uid"] for r in rows if r["rb_uid"]]


def _state_policy_station(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    out_if: str | None,
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    note: str,
    forward_state: dict[str, Any] | None,
    *,
    acl_direction: str | None,
) -> str | None:
    """Station a reply the state policy decided at the rulebase that governs
    the pair the reply crosses (`_apply_firewall_reply`), and return that
    rulebase's uid, or None when no rulebase governs the hop.

    The state policy decides the reply ahead of every ruleset. The leg
    credits what a rule read of the reply's pair would credit (`considered`
    and the governing rulebases, as `_apply_firewall` does) together with what
    the forward crossing of this device credited (`forward_state['credits']`)."""
    considered: list[str] = []
    _refuse_ranged_query(port, proto)
    fw = _point_verdict(
        _firewall_verdict(
            session,
            gw["dev_uid"],
            gw["if_uid"],
            out_if,
            sources,
            dsts,
            port,
            proto,
            considered,
            conn_state="established",
            acl_direction=acl_direction,
        ),
        port,
        proto,
    )
    models = (fw.get("models") or [fw]) if fw else []
    credits = {
        *considered,
        *((forward_state or {}).get("credits") or []),
        *(m["rb_uid"] for m in models if m.get("rb_uid")),
    }
    if credits:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *credits})
    if not fw:
        return None
    for model in models:
        trail.hop(model["rb_uid"], "FwRulebase", model["rb_name"], note, stage=Stage.FILTER_RB)
    return str(fw["rb_uid"])


def _apply_egress_acl(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: Any,
    proto: Any,
    src_label: str,
    *,
    conn_state: str = "new",
    region: FlowRegion | None = None,
) -> str | None:
    """The outbound interface ACLs of a local egress, after source NAT.

    An IOS-XE outbound access list runs after the inside-to-outside
    translation and matches the packet as it leaves. `sources` is the
    translated source set that `_apply_snat` returned. `dsts` is the
    destination after this device's own destination NAT. Only interface ACLs
    bound outbound are candidates (`acl_direction='out'`). The inbound list
    was judged at the filter stage on the original packet. A device-wide
    rulebase is not read a second time. Returns the classified outcome, or
    None when no outbound list governs the egress.

    A region leg is judged rectangle by rectangle on its own service
    dimensions. The leg has one outcome, the fold of every decided part. A
    deny everywhere is a deny, and a permit everywhere is a permit. A mixture
    is undecided and named as such. A lane is not split at this stage.

    The hops are at `Stage.EGRESS_FILTER_RB`/`EGRESS_FILTER_RULE`, after the
    source NAT station and before the egress interface, where the list runs.
    The leg's `firewall` field keeps the filter stage's own verdict and names
    this verdict after it. `egress_firewall` holds this verdict alone.
    """
    considered: list[str] = []
    af = (dsts or sources)[0][0] if (dsts or sources) else 4
    queries: list[tuple[Any, Any, Any]] = (
        [
            (
                port_spec(r.dport),
                proto_spec(r.proto),
                port_spec(r.sport),
            )
            for r in region
        ]
        if region is not None and len(region)
        else [(port, proto, None)]
    )
    decided: list[dict[str, Any]] = []
    # The candidates and their rules depend only on the hop. They are read once
    # and shared by every rectangle.
    rulebases = _load_rulebases(
        session,
        gw["dev_uid"],
        gw["if_uid"],
        route.get("egress_uid"),
        af,
        "forward",
        considered,
        only_interface_acls=True,
        require_chain=False,
        strict_local=False,
    )
    if rulebases is not None:
        judged = list(_load_rules(session, rulebases.candidates, "forward", False))
        for q_port, q_proto, q_sport in queries:
            verdict = _judge_rulebases(
                rulebases,
                judged,
                _rb_query(sources, dsts, q_port, q_proto, q_sport),
                has_egress=True,
                conn_state=conn_state,
                acl_direction="out",
            )
            if verdict is not None:
                decided.extend(verdict if isinstance(verdict, list) else [verdict])
    if considered:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *considered})
    if not decided:
        return None
    outcomes = {classify_action(d["action"]) for d in decided}
    fw = next(
        (d for wanted in (DENY, INDETERMINATE) for d in decided if classify_action(d["action"]) == wanted),
        decided[0],
    )
    outcome = classify_action(fw["action"])
    reason = fw.get("indeterminate_reason")
    if len(outcomes) > 1:
        outcome = INDETERMINATE
        reason = "the outbound list decides this flow in parts; narrow the query for a verdict"
    elif fw.get("partial") or (outcome == PERMIT and any(d.get("partial") for d in decided)):
        # A permit is confirmed only when every decided part covers the whole
        # flow. A rectangle permitted in full beside a rectangle that an entry
        # covers in part is not a confirmed permit.
        outcome = INDETERMINATE
        reason = "the outbound rule covers only part of the flow's address region"
    trail.hop(
        fw["rb_uid"],
        "FwRulebase",
        fw["rb_name"],
        f"{fw['zones']} · {fw['action']} ({fw['by']})",
        stage=Stage.EGRESS_FILTER_RB,
    )
    if fw["rule_uid"]:
        trail.hop(
            fw["rule_uid"],
            "FwRule",
            f"rule {fw['pos']}" + (f" ({fw['rule_name']})" if fw["rule_name"] else ""),
            fw["action"],
            stage=Stage.EGRESS_FILTER_RULE,
        )
    by = f"rule {fw['pos']}" if fw["pos"] is not None else "default-action"
    text = f"{fw['rb_name']} ({fw['zones']}) {fw['action']} by {by}"
    leg["egress_firewall"] = text
    leg["firewall"] = f"{leg['firewall']} · then {text}" if leg.get("firewall") else text
    leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), fw["rb_uid"]})
    egress = route.get("egress_name") or "the egress"
    trail.notes.append(f"{src_label} leaving by {egress}: {text}")
    if outcome == DENY:
        leg["blocked"] = True
        leg["verdict"] = f"BLOCKED by {fw['rb_name']} {by}"
    elif outcome == INDETERMINATE:
        leg["indeterminate"] = True
        trail.warn(f"{src_label}: {text}" + (f", {reason}" if reason else ""))
    return outcome


# The filter stage as a transition.


def _unknown_dims(reason: str | None) -> frozenset[str]:
    """The dimensions an indeterminate reason names as unread by the query,
    in `state.Rect`'s own dimension names."""
    if not reason:
        return frozenset()
    out: set[str] = set()
    if _NO_PROTO_REASON in reason:
        out.add("proto")
    if _NO_PORT_REASON in reason:
        out.add("dport")
    if _SRC_PORT_REASON in reason:
        out.add("sport")
    return frozenset(out)


def _region_of(rect: Rect, d: dict[str, Any]) -> Rect:
    """The part of `rect` that one decided region dict answers for.

    The rectangle is narrowed to the region's own decided service dimensions.
    A dimension that the region did not narrow keeps the value of `rect`."""
    dims: dict[str, Any] = {}
    if "proto_subset" in d:
        dims["proto"] = d["proto_subset"]
    if "port_subset" in d:
        dims["dport"] = None if d["port_subset"] is None else tuple(d["port_subset"])
    if "sport_subset" in d:
        dims["sport"] = None if d["sport_subset"] is None else tuple(d["sport_subset"])
    return rect.narrow(**dims)


@dataclass
class FirewallTransition:
    """The firewall gate over a `FlowRegion`, as an ordered predicate.

    Every rectangle is judged by `_firewall_verdict` on the rectangle's own
    dimensions, converted to the specs that `_firewall_verdict` reads. Each
    decided region is returned as one `(FlowRegion, Effect)` pair.
    `Effect.data` holds the rulebase's own region dict, and `Effect.unknown`
    names the dimensions the verdict could not read. A device that no
    rulebase governs answers the rectangle unchanged with a `pass` effect.
    """

    session: Any
    dev_uid: str
    in_if: str
    out_if: str | None
    conn_state: str = "new"
    considered: list[str] = field(default_factory=list)
    # the interface-ACL binding this transition judges (`_device_rulebase_verdict`)
    acl_direction: str | None = None

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            proto: Any = proto_spec(rect.proto)
            fw = _firewall_verdict(
                self.session,
                self.dev_uid,
                self.in_if,
                self.out_if,
                list(rect.src),
                list(rect.dst),
                port_spec(rect.dport),
                proto,
                self.considered,
                conn_state=self.conn_state,
                src_port=port_spec(rect.sport),
                acl_direction=self.acl_direction,
            )
            if fw is None:
                out.append((FlowRegion.single(rect), Effect("pass", "firewall")))
                continue
            for d in fw if isinstance(fw, list) else [fw]:
                outcome = classify_action(d["action"])
                reason = d.get("indeterminate_reason")
                out.append(
                    (
                        FlowRegion.single(_region_of(rect, d)),
                        Effect(
                            outcome,
                            "firewall",
                            terminal=outcome == DENY,
                            unknown=_unknown_dims(reason) if outcome == INDETERMINATE else frozenset(),
                            reason=reason,
                            data=d,
                        ),
                    )
                )
        return out
