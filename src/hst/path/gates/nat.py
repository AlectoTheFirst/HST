"""Destination and source NAT, evaluated as a first-match partition of the
flow space over each stage's rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import hst.path as _path

from ..addrsets import (
    _ALL_PROTOS,
    _MATCH,
    _NO_MATCH,
    _PORT_FAMILY,
    _UNIVERSE,
    _UNKNOWN,
    _combine_and,
    _describe,
    _iface_name_matches,
    _int_or_none,
    _intersect,
    _intervals,
    _MatchState,
    _merge,
    _ports,
    _protoset,
    _service_regions,
    _size,
    _subtract,
    _to_cidrs,
)
from ..state import Effect, FlowRegion, port_spec
from . import Stage, _Trail

_NAT_RULES_QUERY_STRICT = """
CALL {
  MATCH (d:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  WHERE NOT d:Retired AND NOT rb:Retired
    AND NOT EXISTS {
      MATCH (ix:Interface {uid: $in_if})-[cx:IN_CONTEXT]->(context)
      WHERE ix:Obj AND ix.collection_ts = $snap AND cx._retired_at IS NULL AND NOT context:Retired
    }
    AND d:Obj AND d.collection_ts = $snap AND rb.collection_ts = $snap
    AND e._retired_at IS NULL AND e.collection_ts = $snap
  RETURN rb, coalesce(e.approximate, false) AS approximate, d.cp_raw_uid AS owner_raw_uid
  UNION
  MATCH (d:Device {uid: $dev})-[m:MEMBER_OF]->(rg:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  WHERE NOT d:Retired AND NOT rg:Retired AND NOT rb:Retired
    AND NOT EXISTS {
      MATCH (ix:Interface {uid: $in_if})-[cx:IN_CONTEXT]->(context)
      WHERE ix:Obj AND ix.collection_ts = $snap AND cx._retired_at IS NULL AND NOT context:Retired
    }
    AND d:Obj AND d.collection_ts = $snap AND rg.collection_ts = $snap AND rb.collection_ts = $snap
    AND m._retired_at IS NULL AND e._retired_at IS NULL
    AND m.collection_ts = $snap
    AND e.collection_ts = $snap
  RETURN rb, coalesce(e.approximate, false) AS approximate, rg.cp_raw_uid AS owner_raw_uid
  UNION
  // VSX policy targets are useful configuration, but not installation proof.
  MATCH (iin:Interface {uid: $in_if})-[c:IN_CONTEXT]->(fi:FirewallInstance)
  WHERE iin:Obj AND iin.collection_ts = $snap
    AND c._retired_at IS NULL AND NOT fi:Retired AND fi.collection_ts = $snap
  MATCH (vs:Device:Obj)-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  WHERE vs.cp_raw_uid = fi.gateway_object_uid AND vs._scope = fi.authority
    AND NOT vs:Retired AND NOT rb:Retired
    AND vs.collection_ts = $snap AND rb.collection_ts = $snap
    AND e._retired_at IS NULL AND e.collection_ts = $snap
  RETURN rb, true AS approximate, vs.cp_raw_uid AS owner_raw_uid
  UNION
  MATCH (i:Interface:Obj {uid: $in_if, collection_ts: $snap})-[c:IN_CONTEXT]->(fi:FirewallInstance)
        -[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  MATCH (i)-[v:IN_VRF]->(vrf:VrfInstance)
  WHERE i:Obj AND i.collection_ts = $snap
    AND NOT i:Retired AND NOT fi:Retired AND NOT rb:Retired AND NOT vrf:Retired
    AND c._retired_at IS NULL AND e._retired_at IS NULL AND v._retired_at IS NULL
    AND rb.collection_ts = $snap AND fi.collection_ts = $snap
    AND e.context_uid=vrf.uid
  RETURN rb, NOT coalesce(e.installed AND e.coverage IN ['complete','complete-empty']
    AND rb.configured_revision=e.installed_revision
    AND e.ingress_interface_uid IN ['*',$in_if] AND e.egress_interface_uid='*'
    AND e.address_family=$af,false) AS approximate, fi.gateway_object_uid AS owner_raw_uid
}
// the management object uids of the gateways the bindings name, which a
// Check Point rule's install-on column is compared with (`_nat_installed`)
WITH rb, min(CASE WHEN approximate THEN 1 ELSE 0 END) > 0 AS approximate,
     collect(DISTINCT owner_raw_uid) AS owners
MATCH (rb)-[hr:HAS_RULE]->(n:NatRule)
WHERE NOT n:Retired AND n.collection_ts = $snap
  AND hr._retired_at IS NULL AND hr.collection_ts = $snap
// Each column is aggregated before the next is matched: crossing the four
// columns before one aggregation read the product of their objects per rule.
// A column's addresses are the object's own v4 and v6 address, the
// RESOLVES_TO closure a group or network object carries (the firewall gate
// reads SRC and DST the same way) and an address range object's `ranges`,
// so a group does not read as an object with no address. An object the
// collector could not resolve in full (a group with a member that carries no
// address) makes its column opaque: its addresses are a part of what the
// column matches.
OPTIONAL MATCH (n)-[os:ORIG_SRC]->(ost)
WHERE os._retired_at IS NULL AND os.collection_ts = $snap
  AND NOT ost:Retired AND ost.collection_ts = $snap
WITH rb, approximate, owners, n,
     count(os) > 0 AS orig_src_present,
     [x IN collect(DISTINCT ost.cidr) + collect(DISTINCT ost.ip) + collect(DISTINCT ost.cidr6)
           + collect(DISTINCT ost.ip6)
           + reduce(acc = [], l IN collect(DISTINCT [(ost)-[ror:RESOLVES_TO]->(ort)
               WHERE ror._retired_at IS NULL AND NOT ort:Retired | coalesce(ort.cidr, ort.ip)]) | acc + l)
           + reduce(acc = [], l IN collect(DISTINCT ost.ranges) | acc + l)
      WHERE x IS NOT NULL] AS orig_src_addrs,
     any(x IN collect(DISTINCT ost.opaque) WHERE x) AS orig_src_opaque
OPTIONAL MATCH (n)-[od:ORIG_DST]->(odt)
WHERE od._retired_at IS NULL AND od.collection_ts = $snap
  AND NOT odt:Retired AND odt.collection_ts = $snap
WITH rb, approximate, owners, n, orig_src_present, orig_src_addrs, orig_src_opaque,
     count(od) > 0 AS orig_dst_present,
     [x IN collect(DISTINCT odt.cidr) + collect(DISTINCT odt.ip) + collect(DISTINCT odt.cidr6)
           + collect(DISTINCT odt.ip6)
           + reduce(acc = [], l IN collect(DISTINCT [(odt)-[rdr:RESOLVES_TO]->(drt)
               WHERE rdr._retired_at IS NULL AND NOT drt:Retired | coalesce(drt.cidr, drt.ip)]) | acc + l)
           + reduce(acc = [], l IN collect(DISTINCT odt.ranges) | acc + l)
      WHERE x IS NOT NULL] AS orig_dst_addrs,
     any(x IN collect(DISTINCT odt.opaque) WHERE x) AS orig_dst_opaque
OPTIONAL MATCH (n)-[xs:XLATE_SRC]->(xst)
WHERE xs._retired_at IS NULL AND xs.collection_ts = $snap
  AND NOT xst:Retired AND xst.collection_ts = $snap
WITH rb, approximate, owners, n, orig_src_present, orig_src_addrs, orig_src_opaque,
     orig_dst_present, orig_dst_addrs, orig_dst_opaque,
     count(xs) > 0 AS xlate_src_present,
     [x IN collect(DISTINCT xst.cidr) + collect(DISTINCT xst.ip) + collect(DISTINCT xst.cidr6)
           + collect(DISTINCT xst.ip6)
           + reduce(acc = [], l IN collect(DISTINCT [(xst)-[rxs:RESOLVES_TO]->(xsr)
               WHERE rxs._retired_at IS NULL AND NOT xsr:Retired | coalesce(xsr.cidr, xsr.ip)]) | acc + l)
           + reduce(acc = [], l IN collect(DISTINCT xst.ranges) | acc + l)
      WHERE x IS NOT NULL] AS xlate_src_addrs,
     any(x IN collect(DISTINCT xst.opaque) WHERE x) AS xlate_src_opaque
OPTIONAL MATCH (n)-[xd:XLATE_DST]->(xdt)
WHERE xd._retired_at IS NULL AND xd.collection_ts = $snap
  AND NOT xdt:Retired AND xdt.collection_ts = $snap
WITH rb, approximate, owners, n, orig_src_present, orig_src_addrs, orig_src_opaque,
     orig_dst_present, orig_dst_addrs, orig_dst_opaque,
     xlate_src_present, xlate_src_addrs, xlate_src_opaque,
     count(xd) > 0 AS xlate_dst_present,
     [x IN collect(DISTINCT xdt.cidr) + collect(DISTINCT xdt.ip) + collect(DISTINCT xdt.cidr6)
           + collect(DISTINCT xdt.ip6)
           + reduce(acc = [], l IN collect(DISTINCT [(xdt)-[rxd:RESOLVES_TO]->(xdr)
               WHERE rxd._retired_at IS NULL AND NOT xdr:Retired | coalesce(xdr.cidr, xdr.ip)]) | acc + l)
           + reduce(acc = [], l IN collect(DISTINCT xdt.ranges) | acc + l)
      WHERE x IS NOT NULL] AS xlate_dst_addrs,
     any(x IN collect(DISTINCT xdt.opaque) WHERE x) AS xlate_dst_opaque
RETURN rb.uid AS rb_uid, rb.name AS rb_name, approximate, owners,
       coalesce(n.install_on, []) AS install_on,
       coalesce(n.install_on_unresolved, false) AS install_on_unresolved,
       n.auto_generated AS auto_generated,
       orig_src_present, orig_dst_present,
       xlate_src_present, xlate_dst_present,
       n.uid AS uid, n.position AS pos, n.kind AS kind, n.method AS method,
       coalesce(n.enabled, true) AS enabled, coalesce(n.exclude, false) AS exclude,
       n.translation AS translation, n.translation_port AS translation_port,
       n.direction AS direction, coalesce(n.static, false) AS static_flag, n.af AS af,
       n.orig_src AS orig_src_raw, n.orig_dst AS orig_dst_raw,
       n.orig_src_port AS orig_src_port, n.orig_dst_port AS orig_dst_port,
       n.orig_port AS orig_port, n.xlate_port AS xlate_port,
       n.protocol AS protocol, n.in_if AS in_if, n.out_if AS out_if,
       n.orig_service AS orig_service, n.xlate_service AS xlate_service,
       n.service_unknown AS service_unknown,
       n.translation_interface AS translation_interface,
       coalesce(n.xlate_src_original, false) AS xlate_src_original,
       coalesce(n.xlate_dst_original, false) AS xlate_dst_original,
       coalesce(n.approximate, false) AS rule_approximate,
       n.approximate_reason AS approximate_reason,
       n.match_acl AS match_acl, n.match_route_map AS match_route_map,
       coalesce(n.overload, false) AS overload, n.pool AS pool,
       n.pool_start AS pool_start, n.pool_end AS pool_end,
       orig_src_addrs, orig_dst_addrs, xlate_src_addrs, xlate_dst_addrs,
       orig_src_opaque, orig_dst_opaque, xlate_src_opaque, xlate_dst_opaque
ORDER BY rb.uid, pos"""

# Point tracing and the graph proofs read the same run-pinned rules. Every
# anchor of the query seeks the obj_uid_cts or obj_cts index.
_NAT_RULES_QUERY = _NAT_RULES_QUERY_STRICT

_NAT_CREDITS_QUERY = """
CALL {
  MATCH (d:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  WHERE NOT d:Retired AND NOT rb:Retired
    AND NOT EXISTS {
      MATCH (ix:Interface {uid: $in_if})-[cx:IN_CONTEXT]->(context)
      WHERE ix:Obj AND ix.collection_ts = $snap AND cx._retired_at IS NULL AND NOT context:Retired
    }
    AND d:Obj AND d.collection_ts = $snap AND rb.collection_ts = $snap
    AND e._retired_at IS NULL AND e.collection_ts = $snap
  RETURN rb
  UNION
  MATCH (d:Device {uid: $dev})-[m:MEMBER_OF]->(rg:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  WHERE NOT d:Retired AND NOT rg:Retired AND NOT rb:Retired
    AND NOT EXISTS {
      MATCH (ix:Interface {uid: $in_if})-[cx:IN_CONTEXT]->(context)
      WHERE ix:Obj AND ix.collection_ts = $snap AND cx._retired_at IS NULL AND NOT context:Retired
    }
    AND d:Obj AND d.collection_ts = $snap AND rg.collection_ts = $snap AND rb.collection_ts = $snap
    AND m._retired_at IS NULL AND e._retired_at IS NULL
    AND m.collection_ts = $snap
    AND e.collection_ts = $snap
  RETURN rb
  UNION
  // the VSX context branch, as in the rules query above
  MATCH (iin:Interface {uid: $in_if})-[c:IN_CONTEXT]->(fi:FirewallInstance)
  WHERE iin:Obj AND iin.collection_ts = $snap
    AND c._retired_at IS NULL AND NOT fi:Retired AND fi.collection_ts = $snap
  MATCH (vs:Device:Obj)-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
  WHERE vs.cp_raw_uid = fi.gateway_object_uid AND vs._scope = fi.authority
    AND NOT vs:Retired AND NOT rb:Retired
    AND vs.collection_ts = $snap AND rb.collection_ts = $snap
    AND e._retired_at IS NULL AND e.collection_ts = $snap
  RETURN rb
}
WITH DISTINCT rb
OPTIONAL MATCH (rb)-[hr:HAS_RULE]->(rule:NatRule)
WHERE hr._retired_at IS NULL AND hr.collection_ts = $snap
  AND NOT rule:Retired AND rule.collection_ts = $snap
RETURN rb.uid AS rb_uid, [uid IN collect(DISTINCT rule.uid) WHERE uid IS NOT NULL] AS rule_uids
ORDER BY rb.uid
"""


_NAT_IFACE_ADDR_QUERY = """
MATCH (i:Interface {uid: $u})-[h:HAS_IP]->(ip:IpAddress)
WHERE h._retired_at IS NULL AND NOT ip:Retired AND i:Obj AND i.collection_ts = $snap
  AND NOT i:Retired AND ip.collection_ts = $snap
  AND (($af = 4 AND NOT ip.ip CONTAINS ':') OR ($af = 6 AND ip.ip CONTAINS ':'))
WITH collect(DISTINCT ip.ip) AS addresses
WHERE size(addresses) = 1
RETURN addresses[0] AS ip"""

_IFACE_ADDR_QUERY = """
MATCH (i:Interface {uid: $u})-[h:HAS_IP]->(ip:IpAddress)
WHERE h._retired_at IS NULL AND NOT ip:Retired AND i:Obj AND i.collection_ts = $snap
RETURN ip.ip AS ip ORDER BY ip.ip LIMIT 1"""

_IFACE_ROLE_QUERY = """
MATCH (i:Interface {uid: $u})
WHERE i:Obj AND i.collection_ts = $snap
RETURN i.nat_role AS nat_role"""


def _iface_nat_role(session: Any, uid: str | None) -> str | None:
    """The collected Cisco `ip nat inside|outside` role of one interface, or
    None when the role is not collected."""
    if not uid:
        return None
    row = _path._read_one(session, _IFACE_ROLE_QUERY, u=uid)
    return row.get("nat_role") if row else None


# --- NAT ---------------------------------------------------------------------------------


def _translate_set(
    claimed: list[tuple[int, int, int]],
    match: list[tuple[int, int, int]],
    xlate: list[tuple[int, int, int]],
) -> list[tuple[int, int, int]]:
    """Map the claimed part of `match` into `xlate`.

    When the rule's match and translation sets are the same size (static and
    NPT-style network mappings) each address maps by offset. A claimed
    sub-range maps to the sub-range at the same offset. Any other rule maps
    the whole claimed part onto the translation set.
    """
    from ..reply_nat import translate

    return translate(claimed, match, xlate)


def _readable_proto(spec: str) -> bool:
    """Whether `_protoset` resolves one protocol spec."""
    try:
        _protoset([spec])
    except ValueError:
        return False
    return True


def _nat_proto_member(specs: list[str]) -> str | None:
    """A NAT rule's whole protocol scope as the one member spec
    `_service_regions` reads.

    A NAT rule has one protocol scope. `_service_regions` resolves one spec
    string per member. A scope written as more than one spec is passed as
    the single spec of its union. The spec is 'any' for the full range,
    '!any' for the empty range, and the IANA numbers joined with `_`
    otherwise. `_protoset` resolves each of these specs to the same set. A
    list with a spec that `_protoset` cannot read is passed as that spec
    alone, and the member stays undecided on the protocol dimension.
    """
    specs = [s for s in specs if str(s).strip()]
    if len(specs) < 2:
        return specs[0] if specs else None
    try:
        resolved = _protoset(specs)
    except ValueError:
        return next(s for s in specs if not _readable_proto(s))
    if resolved is None or resolved == _ALL_PROTOS:
        return "any"
    if not resolved:
        return "!any"
    return "_".join(str(n) for n in sorted(resolved))


def _translate_port(
    r: dict[str, Any],
    port: int | None,
    ivals: list[tuple[int, int, int]] | None,
) -> tuple[int | None, list[tuple[int, int, int]] | None, bool, str | None]:
    """The ports of a claimed part after this rule's translation.

    Returns the part's scalar port, its port region, whether the rule
    rewrote the port, and the reason the rewrite is not decided (None when
    it is decided). The scalar is None when the region maps onto more than
    one port.

    `port_spec` is the range the rule matches on and `xlate_port_spec` the
    raw translation-port spec it rewrites to. 2 shapes are decidable. A
    translation to a single port is a many-to-one rewrite, and every matched
    port leaves on that one port. A translation to one range of the size of
    the matched range is a PAT pool, and the claimed ports map through it by
    offset via `_translate_set`.

    Any other pool is undecidable, and the result holds a reason.

    A rule with no port scope, a rule whose specs `_ports` cannot read, and
    a flow with no port region use the scalar `xlate_port` column.
    """
    spec, xlate_spec = r.get("port_spec"), r.get("xlate_port_spec")
    if spec and xlate_spec and ivals is not None:
        try:
            match_ivals, xlate_ivals = _ports(spec), _ports(xlate_spec)
        except ValueError:
            match_ivals = xlate_ivals = []
        if match_ivals and xlate_ivals:
            one_target = len(xlate_ivals) == 1 and _size(xlate_ivals) == 1
            same_size_pool = (
                len(xlate_ivals) == 1 and len(match_ivals) == 1 and _size(xlate_ivals) == _size(match_ivals)
            )
            if not one_target and not same_size_pool:
                reason = f"translation port pool {xlate_spec} does not map onto matched ports {spec}"
                return port, ivals, False, reason
            mapped = _translate_set(ivals, match_ivals, xlate_ivals)
            if mapped:
                lo, hi = mapped[0][1], mapped[0][2]
                scalar = lo if len(mapped) == 1 and lo == hi else None
                return scalar, mapped, True, None
    xlate_port = r.get("xlate_port")
    if xlate_port:
        rewritten = [(_PORT_FAMILY, xlate_port, xlate_port)] if ivals is not None else ivals
        return xlate_port, rewritten, True, None
    return port, ivals, False, None


_Region = tuple[frozenset[int] | None, list[tuple[int, int, int]] | None]
_Flow = tuple[
    list[tuple[int, int, int]],
    list[tuple[int, int, int]],
    frozenset[int] | None,
    list[tuple[int, int, int]] | None,
]


def _nat_part(
    r: dict[str, Any],
    claimed_src: list[tuple[int, int, int]],
    claimed_dst: list[tuple[int, int, int]],
    region: _Region,
    port: int | None,
    *,
    opaque: bool = False,
) -> dict[str, Any]:
    """One claimed part. It holds the addresses and the (protocol, port)
    rectangle that a rule takes out of a flow, and the translated tuple.

    `proto_subset`/`port_subset` are the claimed rectangle before
    translation, on every part including the `rule=None` remainder.
    Protocols are not translated. `new_port_subset` is the region after a
    port rewrite, equal to `port_subset` when nothing is translated."""
    new_src, new_dst = claimed_src, claimed_dst
    if not r.get("exclude") and r.get("xlate"):
        # a pool hands a connection any one of its addresses (`_translation_pool`)
        if r["rewrite"] == "dst":
            new_dst = (
                (list(r["xlate"]) if claimed_dst else [])
                if r.get("xlate_pool")
                else _translate_set(claimed_dst, r["match_dst"] or claimed_dst, r["xlate"])
            )
        else:
            new_src = (
                (list(r["xlate"]) if claimed_src else [])
                if r.get("xlate_pool")
                else _translate_set(claimed_src, r["match_src"] or claimed_src, r["xlate"])
            )
    protos, ports = region
    if r.get("exclude"):
        new_port, new_ports, translated, reason = port, ports, False, None
    else:
        new_port, new_ports, translated, reason = _translate_port(r, port, ports)
    if opaque or reason:
        r = {**r, "opaque": True}
        if opaque:
            r["predicate_unknown"] = True
        if reason:
            r["translation_unknown"] = reason
        if reason and not r.get("role_note"):
            r["role_note"] = reason
    return {
        "sources": claimed_src,
        "dst": claimed_dst,
        "new_src": new_src,
        "new_dst": new_dst,
        "port": new_port,
        "proto_subset": protos,
        "port_subset": ports,
        "new_port_subset": new_ports,
        "port_translated": translated,
        "rule": r,
    }


def _nat_step(
    device_uid: str,
    direction: str,
    part: dict[str, Any],
    *,
    rule_uid: str | None = None,
    post_src: list[tuple[int, int, int]] | None = None,
    context_uid: str | None = None,
) -> dict[str, Any]:
    """One (device, direction, pre-tuple, post-tuple) record of a leg's own
    translation, ordered by device visit.

    `direction` is 'dnat', 'snat' or 'lb' (a load-balancer VIP-to-member
    rewrite, gates/lb.py). `post_src` overrides the rule's own `new_src` for
    a masquerade or an unresolved-address sNAT part. `_apply_snat` resolves
    the downstream address of such a part outside `_nat_partition` (the
    interface's own address, or the address-family universe when that
    address was not collected).

    The record holds no ports."""
    src_after = part["new_src"] if post_src is None else post_src
    return {
        "device": device_uid,
        **({"context_uid": context_uid} if context_uid else {}),
        "direction": direction,
        "rule_uid": rule_uid,
        "pre": {"src": _to_cidrs(part["sources"]), "dst": _to_cidrs(part["dst"])},
        "post": {"src": _to_cidrs(src_after), "dst": _to_cidrs(part["new_dst"])},
    }


def _nat_partition(
    rules: list[dict[str, Any]],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    *,
    proto_set: frozenset[int] | None = None,
    port_ivals: list[tuple[int, int, int]] | None = None,
) -> list[dict[str, Any]]:
    """First-match partition of the flow space over one NAT stage's rules.

    Each rule dict is direction-resolved by the loader. `match_src`/`match_dst`
    are the interval sets it claims (empty list = any). `rewrite` is the side
    it translates ('src' or 'dst'). `xlate` is the translation set (None for
    masquerade/interface-address, resolved by the caller). A rule with
    `exclude` claims without translating. A rule may claim part of the flow
    space, and the remainders continue through later rules. Returns parts in
    claim order, then the untranslated remainder parts with rule=None.

    The flow space has 4 dimensions. They are the source addresses, the
    destination addresses, the protocol set and the destination-port
    intervals. A rule claims a (protocol, ports) rectangle out of the flow
    space, read from `_service_regions`.

    `proto_set`/`port_ivals` are the query's own range in each dimension.
    When a caller leaves them out, they are read from the scalars `proto`
    and `port` (`_protoset`/`_ports`). A point query is a one-element set
    and produces one rectangle per matching rule. None in both places means
    the query has no value for that dimension. The part of a rule that
    `_service_regions` cannot decide is marked opaque. A rule that misses
    one dimension is skipped.

    A query-side spec that `_protoset` or `_ports` cannot read raises
    ValueError.
    """
    if proto_set is None and proto is not None:
        proto_set = _protoset([proto])
    if port_ivals is None and port is not None:
        port_ivals = _ports(port)
    flows: list[_Flow] = [(src_set, dst_set, proto_set, port_ivals)]
    parts: list[dict[str, Any]] = []
    for r in rules:
        if not flows:
            break
        pairs: list[tuple[str | None, Any]] = [(_nat_proto_member(r.get("protos") or []), r.get("port_spec"))]
        nxt: list[_Flow] = []
        for srcs, dsts, q_protos, q_ports in flows:
            regions = _service_regions(pairs, q_protos, q_ports)
            claimed_src = _intersect(srcs, r["match_src"]) if r["match_src"] else srcs
            claimed_dst = _intersect(dsts, r["match_dst"]) if r["match_dst"] else dsts
            if r.get("af") in (4, 6):
                # A rule of one address family (VyOS `nat` or `nat66`) claims no
                # flow of the other family.
                claimed_src = _intersect(claimed_src, _UNIVERSE[r["af"]])
                claimed_dst = _intersect(claimed_dst, _UNIVERSE[r["af"]])
            decided_miss = not regions.claimed and not regions.unknown_dims
            if decided_miss or not claimed_src or not claimed_dst:
                nxt.append((srcs, dsts, q_protos, q_ports))
                continue
            rest_src = _subtract(srcs, claimed_src)
            if rest_src:
                nxt.append((rest_src, dsts, q_protos, q_ports))
            rest_dst = _subtract(dsts, claimed_dst)
            if rest_dst:
                nxt.append((claimed_src, rest_dst, q_protos, q_ports))
            unclaimed: list[_Region] = [(q_protos, q_ports)]
            for rect_protos, rect_ports in regions.claimed:
                still: list[_Region] = []
                for p, pv in unclaimed:
                    # A dimension that is None in the query stays None on the part.
                    part_p, rest_p = (
                        (None, frozenset[int]()) if p is None else (p & rect_protos, p - rect_protos)
                    )
                    part_pv, rest_pv = (
                        (None, []) if pv is None else (_intersect(pv, rect_ports), _subtract(pv, rect_ports))
                    )
                    if (p is not None and not part_p) or (pv is not None and not part_pv):
                        still.append((p, pv))
                        continue
                    parts.append(_nat_part(r, claimed_src, claimed_dst, (part_p, part_pv), port))
                    if rest_p:
                        still.append((rest_p, pv))
                    if rest_pv:
                        still.append((part_p if rest_p else p, rest_pv))
                unclaimed = still
            if regions.unknown_dims:
                # The rule is scoped to a protocol or a port that the flow tuple does not have.
                for p, pv in unclaimed:
                    parts.append(_nat_part(r, claimed_src, claimed_dst, (p, pv), port, opaque=True))
                unclaimed = []
            for p, pv in unclaimed:
                nxt.append((claimed_src, claimed_dst, p, pv))
        flows = nxt
    for srcs, dsts, q_protos, q_ports in flows:
        parts.append(
            {
                "sources": srcs,
                "dst": dsts,
                "new_src": srcs,
                "new_dst": dsts,
                "port": port,
                "proto_subset": q_protos,
                "port_subset": q_ports,
                "new_port_subset": q_ports,
                "port_translated": False,
                "rule": None,
            }
        )
    return parts


def _nat_rows(
    session: Any, dev_uid: str, *, strict: bool = False, in_if: str | None = None, af: int | None = None
) -> list[dict[str, Any]]:
    """Every NAT rule enforced on a device, rulebase-ordered.

    `in_if` is the ingress interface uid for the VSX context branch of the
    query. A read without `in_if` returns the device-bound rulebases only.
    """
    query = _NAT_RULES_QUERY_STRICT if strict else _NAT_RULES_QUERY
    return _path._read(session, query, dev=dev_uid, in_if=in_if or None, af=af)


def nat_rulebase_credits(session: Any, device_uid: str, in_if: str | None = None) -> list[dict[str, Any]]:
    """Every exact-current NAT rulebase bound to a device and its current rules.

    Empty rulebases are retained. Callers credit these objects only after the
    complete ordered NAT table has been evaluated. `in_if` is the ingress
    interface uid that keys the VSX context branch.
    """
    return _path._read(session, _NAT_CREDITS_QUERY, dev=device_uid, in_if=in_if or None)


def _nat_match_set(raw: Any, addrs: list[Any]) -> list[tuple[int, int, int]]:
    """A NAT rule column as an interval set. The raw config string takes
    precedence over the resolved edge targets. An empty set means any
    address."""
    if raw:
        text = str(raw)
        if text.startswith("!"):
            base = _intervals([text[1:]])
            if base:
                return _subtract(_UNIVERSE[base[0][0]], base)
            return []
        return _intervals([text])
    return _intervals([str(a) for a in addrs if a])


def _nat_installed(row: dict[str, Any]) -> dict[str, Any] | None:
    """The row as installed on the gateways of its rulebase bindings, or
    None when it is not installed there.

    The install-on column of a Check Point rule scopes the rule to some of
    the gateways that its package is bound to. The column is compared with
    `owners`, the management object uids of the gateways of the bindings. A
    rule whose install-on has one of the owners is returned as unscoped. A
    rule whose install-on has no owner and no unresolved entry is not
    installed here. Otherwise the rule cannot be placed and `_nat_base_rule`
    makes it opaque.
    """
    install_on = row.get("install_on") or []
    if not install_on and not row.get("install_on_unresolved"):
        return row
    owners = row.get("owners") or []
    if any(owner in install_on for owner in owners):
        return {**row, "install_on": [], "install_on_unresolved": False}
    if row.get("install_on_unresolved") or not owners:
        return row
    return None


def _checkpoint_manual(row: dict[str, Any]) -> bool:
    """Management API manual rules select both translations on the original tuple."""
    return (
        not row.get("kind")
        and str(row.get("method") or "").lower() in {"static", "hide"}
        and not row.get("auto_generated")
        and not row.get("static_flag")
    )


def _nat_rule_kind(row: dict[str, Any]) -> str:
    """The kind of a rule (`snat`, `dnat` or `static`), from the collector's
    own vocabulary.

    A Cisco rule with the `static` flag is bidirectional, and so is a rule
    with a VyOS or collector-set kind == 'static'. Check Point has a method
    and no kind. A rule with method == 'static' is bidirectional only when
    auto_generated is true (object-level Automatic NAT). A manual static rule
    is `dnat` when it has translated destination addresses, else `snat`.
    """
    if row.get("static_flag"):
        return "static"
    if (row.get("method") or "").lower() == "static" and row.get("auto_generated"):
        return "static"
    if row.get("kind"):
        return str(row["kind"])
    if row.get("xlate_dst_addrs") and any(row["xlate_dst_addrs"]):
        return "dnat"
    return "snat"


# an address column of a NAT rule as merged (version, lo, hi) intervals
_AddrSet = list[tuple[int, int, int]]


def _nat_stage_keeps(row: dict[str, Any], kind: str, manual: bool, stage: str, iface: str | None) -> bool:
    """Whether a rule belongs to this stage on this interface.

    The dNAT stage drops a plain sNAT rule and a rule bound to another
    ingress interface. The sNAT stage drops a plain dNAT rule and a rule
    bound to another egress interface. A Check Point manual rule selects
    both translations on the original tuple, and its kind does not drop it.
    """
    bound = _nat_binding(row, kind, stage)
    if stage == "dnat":
        return not (
            (kind == "snat" and not manual) or (bound and iface and not _iface_name_matches(bound, iface))
        )
    return not (
        (kind == "dnat" and not manual) or (bound and iface and not _iface_name_matches(bound, iface))
    )


def _nat_binding(row: dict[str, Any], kind: str, stage: str) -> str | None:
    """The interface a rule is bound to in this stage, or None when unbound.

    VyOS accepts the keyword `any` for every interface, and `any` binds
    nothing. A VyOS static rule has only `inbound-interface`. The router
    installs the reverse (source) translation of the rule on that same
    interface as the outbound one. In the sNAT stage a static rule with no
    `out_if` is bound to its `in_if`. Only the VyOS collector writes
    `in_if`/`out_if`."""
    bound = row.get("in_if") if stage == "dnat" else row.get("out_if")
    if stage == "snat" and not bound and kind == "static":
        bound = row.get("in_if")
    if bound and str(bound).strip().lower() == "any":
        return None
    return bound or None


def _nat_row_sets(row: dict[str, Any], kind: str) -> tuple[_AddrSet, _AddrSet, _AddrSet, _AddrSet]:
    """The rule's original and translated source and destination sets.

    A column whose object the collector resolved only in part (`*_opaque`)
    reads as an empty set. An original column is then present but
    unresolved, and `_nat_base_rule` makes the rule opaque."""
    orig_src = _nat_match_set(row.get("orig_src_raw"), row.get("orig_src_addrs") or [])
    orig_dst = _nat_match_set(row.get("orig_dst_raw"), row.get("orig_dst_addrs") or [])
    if row.get("orig_src_opaque"):
        orig_src = []
    if row.get("orig_dst_opaque"):
        orig_dst = []
    # A static rule encodes public and real on the source side (Check Point:
    # ORIG_SRC=real, XLATE_SRC=public) or on the destination side (VyOS:
    # ORIG_DST=public, XLATE_DST/translation=real). The raw translation
    # string is read into the xlate column that the rule's kind rewrites.
    xlate_src = _nat_match_set(
        row.get("translation") if kind == "snat" else None, row.get("xlate_src_addrs") or []
    )
    xlate_dst = _nat_match_set(
        row.get("translation") if kind in ("dnat", "static") else None, row.get("xlate_dst_addrs") or []
    )
    if row.get("xlate_src_opaque"):
        xlate_src = []
    if row.get("xlate_dst_opaque"):
        xlate_dst = []
    if kind == "static" and xlate_src:
        xlate_dst = []  # the source-side encoding takes precedence
    return orig_src, orig_dst, xlate_src, xlate_dst


def _nat_base_rule(
    row: dict[str, Any], kind: str, manual: bool, orig_src: _AddrSet, orig_dst: _AddrSet
) -> dict[str, Any]:
    """The fields that the rule of every stage has, before its direction is resolved."""
    # An empty match set from a present ORIG_SRC/ORIG_DST object makes the rule opaque.
    orig_src_unresolved = bool(row.get("orig_src_present")) and not orig_src
    orig_dst_unresolved = bool(row.get("orig_dst_present")) and not orig_dst
    rule: dict[str, Any] = {
        "uid": row["uid"],
        "rb_uid": row["rb_uid"],
        "rb_name": row["rb_name"],
        "pos": row["pos"],
        "kind": kind,
        "checkpoint_manual": manual,
        "exclude": bool(row["exclude"]),
        "protos": [row["protocol"]] if row.get("protocol") else [],
        "masquerade": False,
        "opaque": (
            bool(row.get("rule_approximate"))
            or bool(row.get("approximate"))
            or orig_src_unresolved
            or orig_dst_unresolved
            # A translated object is resolved only in part. The rule claims
            # what it matches, and its translation is not known.
            or bool(row.get("xlate_src_opaque"))
            or bool(row.get("xlate_dst_opaque"))
        ),
    }
    unmodeled = [
        label
        for key, label in (
            ("match_acl", "ACL match"),
            ("match_route_map", "route-map match"),
            ("overload", "dynamic overload/PAT allocation"),
            ("pool", "named translation pool"),
            ("pool_start", "translation pool start"),
            ("pool_end", "translation pool end"),
        )
        if row.get(key)
    ]
    if row.get("rule_approximate") and row.get("approximate_reason"):
        # `approximate_reason` is the scope the collector could not model (a
        # VyOS interface group, a negated source group). The leg note shows it.
        rule["role_note"] = str(row["approximate_reason"])
    service_note = _nat_service_unknown(row)
    if service_note:
        # The rule claims its protocol and ports. It is not known whether the
        # rule translates a flow there.
        rule["opaque"] = True
        rule["service_unknown"] = True
        rule.setdefault("role_note", service_note)
    if unmodeled:
        rule["strict_opaque"] = True
        rule["strict_opaque_reason"] = "the NAT rule carries unmodeled metadata: " + ", ".join(unmodeled)
    if _translation_pool(row, kind):
        rule["xlate_pool"] = True
    if row.get("install_on") or row.get("install_on_unresolved"):
        # `_nat_installed` left the install-on scope on the row. The rule
        # claims its part, and it is not known whether the rule translates on
        # this gateway.
        rule["opaque"] = True
        rule["role_note"] = "the rule's install-on column names a target that is not resolved to this gateway"
    return rule


def _translation_pool(row: dict[str, Any], kind: str) -> bool:
    """Whether the rule translates to any one address of a pool.

    A VyOS `translation address a-b` on a source or destination rule, and a
    Cisco dynamic pool, give each connection some address of the range. A
    range of the same size as the matched set is then no one-to-one map. A
    static rule (VyOS `static`, Cisco `static`, Check Point method static)
    and a prefix translation keep the offset mapping.

    The range is read from the raw `translation` of a collected VyOS rule,
    or from the translated column that the rule's kind rewrites
    (`xlate_src_addrs` for snat, `xlate_dst_addrs` for dnat). A proposed
    rule (`simul/fw_overlay.py`) has the range in that column."""
    if kind == "static" or str(row.get("method") or "").lower() == "static":
        return False
    if row.get("pool") or row.get("pool_start") or row.get("pool_end"):
        return True
    column = row.get("xlate_src_addrs" if kind == "snat" else "xlate_dst_addrs") or []
    return any(_address_range(value) for value in [row.get("translation"), *column])


def _address_range(value: Any) -> bool:
    """Whether one address spec is an `a-b` range (not a prefix or address)."""
    return isinstance(value, str) and "-" in value and "/" not in value


def _nat_service_unknown(row: dict[str, Any]) -> str | None:
    """Why a Check Point NAT rule's service match is not known, or None.

    The collector writes `service_unknown` (with the reason in
    `approximate_reason`) where the original service matches less than the
    protocol and ports the rule states, or the translated service rewrites
    a port it does not state.
    """
    if row.get("service_unknown"):
        return str(row.get("approximate_reason") or "the NAT rule's service match is not known")
    if row.get("service_unknown") is None:
        if row.get("orig_service") and not row.get("protocol"):
            return f"the original service {row['orig_service']!r} is not resolved to a protocol and port"
        if row.get("xlate_service") and not row.get("xlate_port"):
            return f"the port rewrite of the translated service {row['xlate_service']!r} is not known"
    return None


def _ingress_role_gate(rule: dict[str, Any], ingress_role: str | None, iface: str | None) -> bool:
    """A Cisco rule bound on the ingress interface's role alone.

    An uncollected role keeps the rule and makes it opaque. A known role
    other than 'outside' is a known non-match and drops the rule (False).
    """
    if ingress_role is None:
        rule["opaque"] = True
        rule["role_note"] = f"{iface} NAT role not collected" if iface else "ingress NAT role not collected"
    elif ingress_role != "outside":
        return False
    return True


def _role_state(role: str | None, wanted: str) -> _MatchState:
    """One interface's NAT role against the role a Cisco pairing needs."""
    if role is None:
        return _UNKNOWN
    return _MATCH if role == wanted else _NO_MATCH


# The Cisco directions whose translation applies between an inside and an
# outside interface. The inbound translation applies on an outside ingress,
# and the outbound translation from inside to outside.
_CISCO_INSIDE = ("inside-source", "inside-destination")


def _inside_outside_pairing(
    rule: dict[str, Any], iface: str | None, ingress_role: str | None, egress_role: str | None
) -> bool:
    """Whether a Cisco rule bound to a flow that enters an inside interface
    and leaves an outside interface applies. False is a known non-match.

    Each role is judged on its own dimension first (matches, disproves, or
    unknown). The 2 states are combined with the three-valued AND of
    `addrsets._combine_and`. A known role that disproves its side of the
    pairing decides a non-match for any value of the other role. The rule
    stays, opaque, only when no known role disproves the pairing and at
    least one role is not collected."""
    ingress_state = _role_state(ingress_role, "inside")
    pairing = _combine_and(ingress_state, _role_state(egress_role, "outside"))
    if pairing == _NO_MATCH:
        return False
    if pairing == _UNKNOWN:
        rule["opaque"] = True
        if ingress_state == _UNKNOWN:
            rule["role_note"] = "ingress NAT role not collected"
        elif iface:
            rule["role_note"] = f"{iface} NAT role not collected"
        else:
            rule["role_note"] = "egress NAT role not collected"
    return True


# the leg note of a Cisco static rule to an interface address the collector
# could not resolve
_STATIC_IFACE_NOTE = "the static translation's interface address was not resolved"


def _dnat_rule(
    row: dict[str, Any],
    rule: dict[str, Any],
    sets: tuple[_AddrSet, _AddrSet, _AddrSet, _AddrSet],
    manual: bool,
    kind: str,
    iface: str | None,
    ingress_role: str | None,
) -> dict[str, Any] | None:
    """Resolve a rule for the dNAT stage, or None when it does not apply."""
    orig_src, orig_dst, xlate_src, xlate_dst = sets
    if (row.get("direction") or "") == "outside-source":
        # Cisco `ip nat outside source` rewrites the source at ingress.
        if not _ingress_role_gate(rule, ingress_role, iface):
            return None  # known role, known non-match
        if not xlate_src:
            rule["opaque"] = True
        rule.update(match_src=orig_src, match_dst=orig_dst, xlate=xlate_src, rewrite="src")
    elif kind == "static":
        # a Cisco `ip nat inside source static` translates inbound only on a
        # flow that enters an outside interface, as the dynamic rule does
        if row.get("direction") in _CISCO_INSIDE and not _ingress_role_gate(rule, ingress_role, iface):
            return None
        if xlate_src:  # source-side encoding: public is XLATE_SRC
            rule.update(match_src=[], match_dst=xlate_src, xlate=orig_src, rewrite="dst")
        elif orig_dst and xlate_dst:  # dst-side encoding: public is ORIG_DST
            rule.update(match_src=[], match_dst=orig_dst, xlate=xlate_dst, rewrite="dst")
        elif row.get("translation") == "interface":
            # Cisco `static L interface <name>` whose interface address was not resolved
            rule.update(match_src=[], match_dst=[], xlate=[], rewrite="dst", opaque=True)
            rule["role_note"] = _STATIC_IFACE_NOTE
        else:
            return None  # No public side is collected, and the rule matches nothing inbound.
        # A static port mapping (Cisco `static tcp L LP G GP`) matches the
        # public port inbound and rewrites it to the real port.
        if row.get("translation_port"):
            rule["port_spec"] = row.get("translation_port")
            rule["xlate_port"] = _int_or_none(row.get("orig_port"))
            # the raw (uncoerced) translation target
            rule["xlate_port_spec"] = row.get("orig_port")
    else:
        # Cisco `ip nat inside destination` is decided on the ingress interface's role.
        if row.get("direction") == "inside-destination" and not _ingress_role_gate(rule, ingress_role, iface):
            return None
        xlate_port_spec = row.get("translation_port") or row.get("xlate_port")
        rule.update(
            match_src=orig_src,
            match_dst=orig_dst,
            xlate=xlate_dst,
            rewrite="dst",
            port_spec=row.get("orig_dst_port") or row.get("orig_port"),
            xlate_port=_int_or_none(xlate_port_spec),
            xlate_port_spec=xlate_port_spec,
        )
        if row.get("xlate_dst_original") or (
            manual and not xlate_dst and not row.get("xlate_dst_present") and not row.get("xlate_port")
        ):
            rule["exclude"] = True
        elif not rule["xlate"] and not rule["exclude"]:
            rule["opaque"] = True  # The rule claims traffic and its translation is unknown.
    return rule


def _snat_rule(
    row: dict[str, Any],
    rule: dict[str, Any],
    sets: tuple[_AddrSet, _AddrSet, _AddrSet, _AddrSet],
    manual: bool,
    kind: str,
    iface: str | None,
    ingress_role: str | None,
    egress_role: str | None,
) -> dict[str, Any] | None:
    """Resolve a rule for the sNAT stage, or None when it does not apply."""
    orig_src, orig_dst, xlate_src, xlate_dst = sets
    xlate_src_port_spec = row.get("translation_port") or row.get("xlate_port")
    if kind == "static":
        # The outbound direction of one-to-one NAT translates real to public.
        # A Cisco row is bound to the inside-to-outside pairing, as the dynamic
        # rule is.
        if row.get("direction") in _CISCO_INSIDE and not _inside_outside_pairing(
            rule, iface, ingress_role, egress_role
        ):
            return None
        if xlate_src:  # source-side encoding: real is ORIG_SRC
            if not orig_src:
                return None
            rule.update(match_src=orig_src, match_dst=[], xlate=xlate_src, rewrite="src")
        elif orig_dst and xlate_dst:  # dst-side encoding: real is XLATE_DST
            rule.update(match_src=xlate_dst, match_dst=[], xlate=orig_dst, rewrite="src")
        elif orig_src and row.get("translation") == "interface":
            # The public side is not known, as in `_dnat_rule`.
            rule.update(match_src=orig_src, match_dst=[], xlate=[], rewrite="src", opaque=True)
            rule["role_note"] = _STATIC_IFACE_NOTE
        else:
            return None
        rule.update(
            port_spec=None,
            xlate_port=None,
            src_port_spec=row.get("orig_port") or row.get("orig_src_port"),
            xlate_src_port_spec=xlate_src_port_spec,
        )
    else:
        if row.get("direction") == "inside-source" and not _inside_outside_pairing(
            rule, iface, ingress_role, egress_role
        ):
            return None
        rule.update(
            match_src=orig_src,
            match_dst=orig_dst,
            xlate=xlate_src,
            rewrite="src",
            port_spec=row.get("orig_dst_port") or row.get("orig_port"),
            xlate_port=None,
            src_port_spec=row.get("orig_src_port"),
            xlate_src_port_spec=xlate_src_port_spec,
        )
        # `_nat_stage_keeps` drops a plain dNAT rule from this stage. A rule
        # with kind == 'dnat' here is a Check Point manual rule.
        if row.get("xlate_src_original") or (
            kind == "dnat"
            and not xlate_src
            and not row.get("xlate_src_present")
            and str(row.get("method") or "").lower() != "hide"
        ):
            rule["exclude"] = True
        elif str(row.get("translation") or "") in ("masquerade", "interface") or (
            (row.get("method") or "").lower() == "hide" and not xlate_src and not row.get("xlate_src_present")
        ):
            rule["masquerade"] = True
        elif not rule["xlate"] and not rule["exclude"]:
            rule["opaque"] = True
    if manual:
        rule["xlate_src_port_spec"] = None
    return rule


def _src_port_scope(rule: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """Mark a rule that matches on a source port opaque at this stage."""
    rule["opaque_without_src_port"] = rule["opaque"]
    if row.get("orig_src_port"):
        # this stage does not decide a source port
        rule["opaque"] = True
        rule["src_port_scoped"] = True
        rule["orig_src_port"] = row.get("orig_src_port")
    return rule


def _nat_stage_rules(
    rows: list[dict[str, Any]],
    stage: str,
    iface: str | None,
    *,
    ingress_role: str | None = None,
    egress_role: str | None = None,
    unresolved_iface_undecided: bool = False,
) -> list[dict[str, Any]]:
    """Direction-resolve the device's NAT rules for one stage.

    `stage` is 'dnat' (applied at ingress, before routing) or 'snat' (applied
    at egress). Static rules contribute to both stages. Inbound they match
    the public side and rewrite the destination to the real side. Outbound
    they match the real side and rewrite the source to the public side.
    Rules bound to a different interface than the flow's are dropped here.
    A rule the engine cannot decide (source-port match, unresolvable
    translation) is kept with opaque=True.

    `ingress_role`/`egress_role` are the collected `Interface.nat_role` of the
    flow's ingress/egress interface for this call, or None when that role is
    not collected. They bind the 3 Cisco `direction` values
    (outside-source, inside-destination, inside-source) to the flow. A Cisco
    rule whose relevant role is unknown claims its part opaque.

    `iface` None keeps every rule with any interface binding. The analysis
    model and the assessment decide the binding themselves. A trace leg
    whose interface is not resolved passes `unresolved_iface_undecided`. A
    rule bound to an interface then claims its part undecided
    (`binding_unresolved`).
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        if not row["enabled"]:
            continue
        installed = _nat_installed(row)
        if installed is None:
            continue
        row = installed
        kind = _nat_rule_kind(row)
        manual = _checkpoint_manual(row)
        if not _nat_stage_keeps(row, kind, manual, stage, iface):
            continue
        sets = _nat_row_sets(row, kind)
        rule = _nat_base_rule(row, kind, manual, sets[0], sets[1])
        if stage == "dnat":
            resolved = _dnat_rule(row, rule, sets, manual, kind, iface, ingress_role)
        else:
            resolved = _snat_rule(row, rule, sets, manual, kind, iface, ingress_role, egress_role)
        if resolved is not None:
            bound = _nat_binding(row, kind, stage) if unresolved_iface_undecided and iface is None else None
            if bound:
                side = "ingress" if stage == "dnat" else "egress"
                note = (
                    f"the rule is bound to {side} interface {bound} and the {side} interface "
                    "of this leg is not resolved"
                )
                resolved["opaque"] = True
                resolved["binding_unresolved"] = True
                resolved["role_note"] = (
                    f"{resolved['role_note']}; {note}" if resolved.get("role_note") else note
                )
            resolved["af"] = _nat_rule_af(row, sets)
            out.append(_src_port_scope(resolved, row))
    return out


def _nat_rule_af(row: dict[str, Any], sets: tuple[_AddrSet, _AddrSet, _AddrSet, _AddrSet]) -> int | None:
    """The address family a NAT rule applies to, or None for both.

    The collector's `af` takes precedence. A row without `af` takes the one
    family of its original and translated addresses."""
    af = row.get("af")
    if af in (4, 6):
        return int(af)
    families = {iv[0] for cols in sets for iv in cols}
    return families.pop() if len(families) == 1 else None


def _apply_snat(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    nat_rows: list[dict[str, Any]],
    egress_uid: str | None,
    egress_name: str | None,
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    *,
    ingress_role: str | None = None,
    egress_role: str | None = None,
    device_uid: str | None = None,
    region: FlowRegion | None = None,
) -> list[tuple[int, int, int]]:
    """Source NAT at egress. The function partitions the leg's sources over
    the snat stage and records the translation of each part. sNAT does not
    change this device's forwarding decision and does not fork a lane.
    Returns the source set that the next device on the path sees (the union
    of every part's translation).

    `region`, when given, is the leg's own `FlowRegion` and the stage's
    rules decide on it through `NatTransition`. When `region` is None, the
    stage reads `port`/`proto`.

    `ingress_role`/`egress_role` are the flow's collected interface NAT roles,
    passed to `_nat_stage_rules` for the Cisco `inside-source` binding. They
    have no effect on a row without that direction.

    `device_uid`, when given, is the device of the ordered translation
    record that a reply walk replays. Each claimed, non-excluded part
    appends its own (device, 'snat', pre-tuple, post-tuple) step to
    `leg["nat_chain"]`, in claim order."""
    rules = _nat_stage_rules(
        nat_rows,
        "snat",
        egress_name,
        ingress_role=ingress_role,
        egress_role=egress_role,
        unresolved_iface_undecided=True,
    )
    if "checkpoint_nat_selection" in leg:
        selected = leg["checkpoint_nat_selection"]
        if selected:
            rules = [r for r in rules if r["uid"] == selected]
            # Ingress already selected this rule on the original tuple. The
            # egress leg is a subset of that selection after destination NAT.
            rules = [dict(r, match_dst=[], port_spec=None) for r in rules]
        else:
            rules = [r for r in rules if not r.get("checkpoint_manual")]
    if not rules:
        return sources
    if region is not None:
        parts = [dict(effect.data) for _reg, effect in NatTransition(rules).apply(region)]
    else:
        parts = _nat_partition(rules, sources, dsts, port, proto)
    downstream: list[tuple[int, int, int]] = []
    outcomes: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    for part in parts:
        rule = part["rule"]
        if rule is None or (rule.get("exclude") and not rule.get("opaque")):
            downstream = _merge(downstream + part["sources"])
            continue
        # An exclude rule whose match is not decided is also handled here. The
        # flow may be excluded or may reach a later rule that translates it.
        if rule.get("opaque"):
            leg["indeterminate"] = True
            reason = rule.get("role_note") or "translation not determinable"
            trail.warn(
                f"{_describe(part['sources'])}: sNAT {rule['rb_name']} rule {rule['pos']} matched, {reason}"
            )
            possible = part["sources"]
            if rule.get("binding_unresolved") and not rule.get("exclude"):
                # The rule may apply on the unresolved egress. The part leaves
                # untranslated or translated. The address of a masquerade is not
                # known without the interface, and the family universe is used.
                fams = sorted({iv[0] for iv in part["sources"]}) or [4]
                translated = (
                    [iv for af in fams for iv in _UNIVERSE[af]] if rule.get("masquerade") else part["new_src"]
                )
                possible = possible + translated
            downstream = _merge(downstream + possible)
            continue
        if rule.get("masquerade"):
            families = {iv[0] for iv in part["sources"]}
            addr = (
                _path._read_one(session, _NAT_IFACE_ADDR_QUERY, u=egress_uid, af=next(iter(families)))
                if egress_uid and len(families) == 1
                else None
            )
            to = addr["ip"] if addr else f"address of {egress_name or 'egress'}"
            if addr:
                real_src = _intervals([addr["ip"]])
                downstream = _merge(downstream + real_src)
                if device_uid:
                    steps.append(
                        _nat_step(
                            device_uid,
                            "snat",
                            part,
                            rule_uid=rule["uid"],
                            post_src=real_src,
                            context_uid=leg.get("context_uid"),
                        )
                    )
            else:
                # The unknown source is the flow's own address-family universe.
                leg["indeterminate"] = True
                # every family of the part's sources
                fams = sorted({iv[0] for iv in part["sources"]}) or [4]
                downstream = _merge(downstream + [iv for af in fams for iv in _UNIVERSE[af]])
                trail.warn(
                    f"{_describe(part['sources'])}: sNAT {rule['rb_name']} rule {rule['pos']} "
                    f"masquerades via {egress_name or 'egress'}, whose address was not "
                    "collected uniquely for this address family; the downstream source is unknown "
                    "and is evaluated as any source"
                )
        else:
            to = _describe(part["new_src"])
            downstream = _merge(downstream + part["new_src"])
            if device_uid:
                steps.append(
                    _nat_step(
                        device_uid, "snat", part, rule_uid=rule["uid"], context_uid=leg.get("context_uid")
                    )
                )
        trail.hop(rule["uid"], "NatRule", f"sNAT rule {rule['pos']}", f"→ {to}", stage=Stage.SNAT)
        trail.notes.append(f"{_describe(part['sources'])} via {egress_name or '?'}: source NAT → {to}")
        outcomes.append({"sources": _to_cidrs(part["sources"]), "to": to, "rule_uid": rule["uid"]})
    if outcomes:
        leg["snat"] = outcomes
    if steps:
        leg["nat_chain"] = leg.get("nat_chain", []) + steps
    return downstream or sources


# --- the NAT stages as a transition ---------------------------------------------------


@dataclass
class NatTransition:
    """One NAT stage over a `FlowRegion`. The stage is a rewrite.

    `rules` is the stage's direction-resolved rule list (`_nat_stage_rules`
    output). Every rectangle goes through `_nat_partition` on its own
    dimensions, and every part is returned as one `(FlowRegion, Effect)`
    pair. The region is the rectangle narrowed to the part's claim and, where
    the rule translates, rewritten to the translated tuple. `Effect.data` is
    the part dict. `Effect.unknown` holds the dimensions that the rule is
    scoped to and the rectangle leaves unset. The rectangle of a masquerade
    part has the untranslated source.
    """

    rules: list[dict[str, Any]]
    complete_service: bool = False

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        if self.complete_service:
            return self._apply_complete(region)
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            # a scalar or a range spec, read by `_translate_port`
            port: Any = port_spec(rect.dport)
            parts = _nat_partition(
                self.rules,
                list(rect.src),
                list(rect.dst),
                port,
                None,
                proto_set=rect.proto,
                port_ivals=None if rect.dport is None else list(rect.dport),
            )
            for part in parts:
                rule = part["rule"]
                dims: dict[str, Any] = {
                    "src": tuple(part["new_src"]),
                    "dst": tuple(part["new_dst"]),
                    "proto": part["proto_subset"],
                    "dport": None if part["new_port_subset"] is None else tuple(part["new_port_subset"]),
                }
                if rule is None:
                    kind = "pass"
                elif rule.get("exclude"):
                    kind = "exclude"
                else:
                    kind = "rewrite"
                sub = rect.rewrite(**dims) if kind == "rewrite" else rect.narrow(**dims)
                unknown: set[str] = set()
                if rule is not None:
                    if rule.get("protos") and rect.proto is None:
                        unknown.add("proto")
                    if rule.get("port_spec") and rect.dport is None:
                        unknown.add("dport")
                    if rule.get("src_port_scoped"):
                        unknown.add("sport")
                out.append(
                    (
                        FlowRegion.single(sub),
                        Effect(
                            kind,
                            "nat",
                            unknown=frozenset(unknown),
                            reason=(rule or {}).get("role_note"),
                            data=part,
                        ),
                    )
                )
        return out

    def _apply_complete(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        """Strict first-match NAT over all five tuple dimensions."""
        out: list[tuple[FlowRegion, Effect]] = []
        pending = list(region.rects)
        for rule in self.rules:
            later: list[Any] = []
            for rect in pending:
                parts = _nat_partition(
                    [rule],
                    list(rect.src),
                    list(rect.dst),
                    None,
                    None,
                    proto_set=rect.proto,
                    port_ivals=None if rect.dport is None else list(rect.dport),
                )
                for part in parts:
                    if part["rule"] is None:
                        later.append(
                            rect.narrow(
                                src=tuple(part["sources"]),
                                dst=tuple(part["dst"]),
                                proto=part["proto_subset"],
                                dport=(None if part["port_subset"] is None else tuple(part["port_subset"])),
                            )
                        )
                        continue
                    before = rect.narrow(
                        src=tuple(part["sources"]),
                        dst=tuple(part["dst"]),
                        proto=part["proto_subset"],
                        dport=(None if part["port_subset"] is None else tuple(part["port_subset"])),
                    )
                    matched, sport_rest, sport_unknown = self._source_port_claim(rule, before)
                    later.extend(sport_rest)
                    if matched is None:
                        continue
                    strict_part = {**part, "sport_subset": matched.sport, "new_sport_subset": matched.sport}
                    opaque = (
                        bool(rule.get("opaque_without_src_port", rule.get("opaque", False)))
                        or bool(rule.get("strict_opaque"))
                        or bool(part["rule"].get("predicate_unknown"))
                        or sport_unknown
                    )
                    if opaque:
                        reason = (
                            rule.get("strict_opaque_reason")
                            or rule.get("role_note")
                            or ("the NAT rule predicate or translation is not fully resolved")
                        )
                        unknown: set[str] = set()
                        if rule.get("protos") and matched.proto is None:
                            unknown.add("proto")
                        if rule.get("port_spec") and matched.dport is None:
                            unknown.add("dport")
                        if sport_unknown:
                            unknown.add("sport")
                        out.append(
                            (
                                FlowRegion.single(matched),
                                Effect(
                                    "indeterminate",
                                    "nat",
                                    unknown=frozenset(unknown),
                                    reason=reason,
                                    data=strict_part,
                                ),
                            )
                        )
                        continue
                    after, mappings, translation_unknown = self._strict_rewrite(rule, matched, strict_part)
                    strict_part["mappings"] = mappings
                    if translation_unknown:
                        out.append(
                            (
                                FlowRegion.single(matched),
                                Effect(
                                    "indeterminate",
                                    "nat",
                                    reason=translation_unknown,
                                    data=strict_part,
                                ),
                            )
                        )
                    else:
                        kind = "exclude" if rule.get("exclude") else "rewrite"
                        out.append((FlowRegion.single(after), Effect(kind, "nat", data=strict_part)))
            pending = later
        for rect in pending:
            out.append(
                (
                    FlowRegion.single(rect),
                    Effect(
                        "pass",
                        "nat",
                        data={
                            "sources": list(rect.src),
                            "dst": list(rect.dst),
                            "new_src": list(rect.src),
                            "new_dst": list(rect.dst),
                            "proto_subset": rect.proto,
                            "port_subset": rect.dport,
                            "new_port_subset": rect.dport,
                            "sport_subset": rect.sport,
                            "new_sport_subset": rect.sport,
                            "rule": None,
                            "mappings": {},
                        },
                    ),
                )
            )
        return out

    @staticmethod
    def _source_port_claim(rule: dict[str, Any], rect: Any) -> tuple[Any, list[Any], bool]:
        spec = rule.get("src_port_spec") or rule.get("orig_src_port")
        if not spec:
            return rect, [], False
        if rect.sport is None:
            return rect, [], True
        try:
            wanted = tuple(_ports(spec))
        except ValueError:
            return rect, [], True
        inside = tuple(_intersect(list(rect.sport), list(wanted)))
        if not inside:
            return None, [rect], False
        claimed = rect.narrow(sport=inside)
        return claimed, list(rect.subtract(claimed)), False

    @staticmethod
    def _strict_rewrite(
        rule: dict[str, Any], rect: Any, part: dict[str, Any]
    ) -> tuple[Any, dict[str, Any], str | None]:
        if rule.get("exclude"):
            return rect, {}, None
        dims: dict[str, Any] = {
            "src": tuple(part["new_src"]),
            "dst": tuple(part["new_dst"]),
            "dport": None if part["new_port_subset"] is None else tuple(part["new_port_subset"]),
        }
        mappings: dict[str, Any] = {}
        dport_target = rule.get("xlate_port_spec") or rule.get("xlate_port")
        if rect.dport is None and dport_target:
            constant = _int_or_none(dport_target)
            if constant is None:
                return rect, {}, "a destination-port pool cannot be mapped from an unstated input port"
            dims["dport"] = tuple(_ports(constant))
            part["new_port_subset"] = dims["dport"]
        translated_dim = rule.get("rewrite")
        if translated_dim in ("src", "dst") and tuple(getattr(rect, translated_dim)) != dims[translated_dim]:
            match = rule.get(f"match_{translated_dim}") or list(getattr(rect, translated_dim))
            xlate = rule.get("xlate") or []
            # A source pool (carrier-grade NAT) has no fixed address per client.
            # The flow continues from the whole pool. The flow is proven only
            # where every pool address is proven. A walk that separates the pool
            # leaves the clients not established. A destination pool picks a
            # server, and the rewrite is refused.
            if translated_dim == "dst" and (
                (rule.get("xlate_pool") and _size(xlate) > 1) or not _deterministic_map(match, xlate)
            ):
                return rect, {}, f"the {translated_dim} address pool does not define a deterministic mapping"
            mappings[translated_dim] = {
                "before": tuple(getattr(rect, translated_dim)),
                "after": dims[translated_dim],
            }
        if rect.dport != dims["dport"]:
            mappings["dport"] = {"before": rect.dport, "after": dims["dport"]}
        sport_rule = {
            "port_spec": rule.get("src_port_spec") or rule.get("orig_src_port"),
            "xlate_port_spec": rule.get("xlate_src_port_spec"),
            "xlate_port": _int_or_none(rule.get("xlate_src_port_spec")),
        }
        sport_target = rule.get("xlate_src_port_spec")
        new_sport: list[tuple[int, int, int]] | None
        if rect.sport is None and sport_target:
            constant = _int_or_none(sport_target)
            if constant is None:
                return rect, {}, "a source-port pool cannot be mapped from an unstated input port"
            new_sport, translated, reason = _ports(constant), True, None
        else:
            _scalar, new_sport, translated, reason = _translate_port(
                sport_rule,
                None,
                None if rect.sport is None else list(rect.sport),
            )
        if reason:
            return rect, {}, reason
        if translated:
            dims["sport"] = tuple(new_sport or [])
            mappings["sport"] = {"before": rect.sport, "after": dims["sport"]}
        else:
            dims["sport"] = rect.sport
        part["new_sport_subset"] = dims["sport"]
        return rect.rewrite(**dims), mappings, None


def _deterministic_map(match: list[tuple[int, int, int]], xlate: list[tuple[int, int, int]]) -> bool:
    """Whether the collected address map identifies one output per input."""
    return bool(len(xlate) == 1 and (_size(xlate) == 1 or (len(match) == 1 and _size(match) == _size(xlate))))
