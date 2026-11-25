"""The load balancer stage.

A flow whose destination is a VirtualService VIP is rewritten to a chosen
pool member (address:port). The server-side source is resolved per the
device's own snat_mode.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, NamedTuple

import hst.path as _path
from hst.core.config import Settings

from ..addrsets import (
    _MATCH,
    _NO_MATCH,
    _UNKNOWN,
    _combine_and,
    _int_or_none,
    _intersect,
    _intervals,
    _MatchState,
    _port_matches,
    _ports,
    _proto_matches,
    _protoset,
)
from ..state import Effect, FlowRegion, Ivals, Rect

_VIP_BINDING_QUERY = """
MATCH (vs:VirtualService:Obj)-[e1:VIP]->(vip:IpAddress {ip: $ip})
WHERE NOT vs:Retired AND e1._retired_at IS NULL AND vs.collection_ts = $snap
  AND NOT vip:Retired AND vip.collection_ts = $snap
MATCH (vs)-[eon:ON]->(target)
WHERE eon._retired_at IS NULL AND NOT target:Retired
  AND (
    target.uid = $dev
    OR EXISTS {
      MATCH (:Device {uid: $dev})-[em:MEMBER_OF]->(target:RedundancyGroup)
      WHERE em._retired_at IS NULL
    }
  )
RETURN vs.uid AS uid, vs.name AS name, vs.kind AS kind, vs.proto AS proto, vs.port AS port,
       vs.snat_mode AS snat_mode, vip.uid AS ip_uid
ORDER BY vs.uid"""


def _vip_bindings(session: Any, ip: str, dev_uid: str) -> list[dict[str, Any]]:
    """Every VirtualService with a VIP on `ip` that is bound to this device, in uid order."""
    return _path._read(session, _VIP_BINDING_QUERY, ip=ip, dev=dev_uid)


_VIP_ANY_BINDING_QUERY = """
MATCH (vs:VirtualService:Obj)-[e1:VIP]->(vip:IpAddress {ip: $ip})
WHERE NOT vs:Retired AND e1._retired_at IS NULL AND vs.collection_ts = $snap
  AND NOT vip:Retired AND vip.collection_ts = $snap
MATCH (vs)-[eon:ON]->(target)
WHERE eon._retired_at IS NULL AND NOT target:Retired
RETURN vs.uid AS uid, vs.name AS name, vs.kind AS kind, vs.proto AS proto, vs.port AS port,
       target.uid AS on_uid
ORDER BY vs.uid, target.uid
LIMIT 20"""


def _vip_elsewhere(
    session: Any, ip: str, proto: str | None, port: int | None, region: FlowRegion | None = None
) -> list[dict[str, Any]]:
    """The VirtualServices on `ip` bound to a device other than the one
    delivering the flow, minus those whose own protocol and port miss it. On
    the region path a service stays when it claims any rectangle of the region
    or leaves one undecided."""
    rows = _path._read(session, _VIP_ANY_BINDING_QUERY, ip=ip)
    if region is None:
        return [r for r in rows if _vip_claims(r, proto, port) != _NO_MATCH]
    return [r for r in rows if any(_vip_claims_region(r, rect).state != _NO_MATCH for rect in region.rects)]


_LB_DEVICE_INTERFACES_QUERY = """
CALL {
  MATCH (dev:Device:Obj {uid: $on, collection_ts: $snap})
  WHERE NOT dev:Retired
  RETURN dev, null AS lb_role
  UNION
  MATCH (g:RedundancyGroup:Obj {uid: $on, collection_ts: $snap})<-[m:MEMBER_OF]-(dev:Device)
  WHERE m._retired_at IS NULL AND NOT g:Retired AND NOT dev:Retired AND dev.collection_ts = $snap
  RETURN dev, m.role AS lb_role
}
MATCH (dev)<-[o:ON]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)
WHERE o._retired_at IS NULL AND h._retired_at IS NULL AND NOT i:Retired AND NOT ip:Retired
  AND i.collection_ts = $snap AND ip.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
RETURN DISTINCT dev.uid AS device_uid, dev.name AS device_name, lb_role,
       i.uid AS if_uid, i.name AS if_name, ip.ip AS ip, v.uid AS vrf_uid
ORDER BY device_uid, if_uid, ip"""


def _lb_segment_interfaces(session: Any, on_uid: str, segment: str, vip: str) -> list[dict[str, Any]]:
    """The interfaces of the load balancer `on_uid` names (a Device, or the
    members of a RedundancyGroup) that hold an address in `segment`, the
    prefix the VIP is delivered on, in device and interface uid order. An
    interface address equal to the VIP is left out."""
    try:
        net = ipaddress.ip_network(segment, strict=False)
    except ValueError:
        return []
    found: list[dict[str, Any]] = []
    for row in _path._read(session, _LB_DEVICE_INTERFACES_QUERY, on=on_uid):
        try:
            addr = ipaddress.ip_address(str(row.get("ip")).split("/")[0])
        except ValueError:
            continue
        if addr.version == net.version and addr in net and str(addr) != vip:
            found.append(row)
    return found


_VS_VIP_QUERY = """
MATCH (vs:VirtualService)-[ev:VIP]->(vip:IpAddress)
WHERE vs.uid IN $uids AND vs:Obj AND vs.collection_ts = $snap AND ev._retired_at IS NULL
  AND NOT vip:Retired AND vip.collection_ts = $snap
RETURN vs.uid AS uid, collect(DISTINCT vip.ip) AS vips"""


def _vip_addresses(session: Any, uids: list[str]) -> dict[str, list[str]]:
    """Each VirtualService's VIP addresses, by uid. A VirtualService with no
    VIP recorded is left out."""
    if not uids:
        return {}
    rows = _path._read(session, _VS_VIP_QUERY, uids=uids)
    return {r["uid"]: [ip for ip in r["vips"] if ip] for r in rows if r.get("vips")}


# VirtualService.kind values this stage evaluates. `cs` (content-switching,
# DISPATCHES to another VirtualService) and `gslb` have no direct USES/Pool to
# partition. A kind outside this set is named and marked indeterminate.
_SUPPORTED_KINDS = frozenset({"lb", "alb", "nlb", "azlb", "appgw", None})


def _vip_supported(vs_row: dict[str, Any]) -> bool:
    return (vs_row.get("kind") or None) in _SUPPORTED_KINDS


def _vs_label(vs_row: dict[str, Any]) -> str:
    """How a VirtualService is named in a hop, a note and a warning."""
    return str(vs_row.get("name") or vs_row["uid"])


def _vip_claims(vs_row: dict[str, Any], proto: str | None, port: int | None) -> str:
    """Whether this VirtualService's own proto/port claims the flow.

    A non-match on either dimension decides the claim. A dimension that the
    flow does not have leaves the claim undecided.
    """
    proto_specs = [vs_row["proto"]] if vs_row.get("proto") else []
    return _combine_and(_proto_matches(proto_specs, proto), _port_matches(vs_row.get("port"), port))


class VipClaim(NamedTuple):
    """The result of `_vip_claims_region`. `state` is the three-valued state
    that `_vip_claims` gives a point. `claimed` is the part of the rectangle
    that the VirtualService claims on a match."""

    state: _MatchState
    claimed: Rect | None


def _vip_claims_region(vs_row: dict[str, Any], rect: Rect) -> VipClaim:
    """`_vip_claims` over one rectangle of a `FlowRegion`.

    Each dimension has the same three-valued reading. A VirtualService
    scoped to a protocol or a port that the rectangle leaves unset is
    undecided. A VirtualService whose protocol or port lies outside the
    rectangle's own set is a definite non-match. Otherwise the VirtualService
    claims the overlap. For a rectangle with one protocol and one port the
    result equals `_vip_claims`, and the claimed rectangle is the input.
    """
    proto_state: _MatchState = _MATCH
    proto_dim = rect.proto
    if vs_row.get("proto"):
        if rect.proto is None:
            proto_state = _UNKNOWN
        else:
            try:
                want = _protoset([str(vs_row["proto"])])
            except ValueError:
                want = None
            if want is None:
                proto_state = _UNKNOWN
            else:
                proto_dim = rect.proto & want
                proto_state = _MATCH if proto_dim else _NO_MATCH
    port_state: _MatchState = _MATCH
    port_dim = rect.dport
    if vs_row.get("port") not in (None, "", []):
        if rect.dport is None:
            port_state = _UNKNOWN
        else:
            try:
                want_ports = _ports(vs_row["port"])
            except ValueError:
                want_ports = []
            if not want_ports:
                port_state = _UNKNOWN
            else:
                port_dim = tuple(_intersect(list(rect.dport), want_ports))
                port_state = _MATCH if port_dim else _NO_MATCH
    state = _combine_and(proto_state, port_state)
    if state != _MATCH:
        return VipClaim(state, None)
    return VipClaim(_MATCH, rect.narrow(proto=proto_dim, dport=port_dim))


# `(VirtualService)-[:USES]->(Pool)-[:HAS_MEMBER]->(PoolMember)-[:TARGETS]->(IpAddress)`.
# `state` is the collected health of the PoolMember. `_member_regions` reads
# a `state` that is absent on every member as not collected.
_POOL_MEMBERS_QUERY = """
MATCH (vsn:VirtualService {uid: $vs})-[eu:USES]->(pool:Pool)
WHERE vsn:Obj AND vsn.collection_ts = $snap
  AND eu._retired_at IS NULL AND NOT pool:Retired AND pool.collection_ts = $snap
MATCH (pool)-[eh:HAS_MEMBER]->(pm:PoolMember)
WHERE eh._retired_at IS NULL AND NOT pm:Retired AND pm.collection_ts = $snap
MATCH (pm)-[et:TARGETS]->(ip:IpAddress)
WHERE et._retired_at IS NULL AND NOT ip:Retired AND ip.collection_ts = $snap
RETURN pm.uid AS uid, pm.name AS name, pm.port AS port, pm.state AS state,
       pool.uid AS pool_uid, pool.name AS pool_name, ip.ip AS ip
ORDER BY pm.uid"""


def _pool_members(session: Any, vs_uid: str) -> list[dict[str, Any]]:
    """Every member of the pools this VirtualService USES, with the address each member TARGETS."""
    return _path._read(session, _POOL_MEMBERS_QUERY, vs=vs_uid)


class LbRegions(NamedTuple):
    """The result of `_member_regions`, with the members that a leg fans out through.

    `members` is empty when `collapsed` is True or the pool is empty.
    `surplus` counts the healthy members past the member cap.
    """

    members: list[dict[str, Any]]
    collapsed: bool
    note: str | None
    surplus: int = 0
    unknown: tuple[dict[str, Any], ...] = ()


def _member_names(members: list[dict[str, Any]]) -> str:
    return ", ".join(m.get("name") or m.get("ip") or m["uid"] for m in members)


def _region_cap(cap: int | None) -> int:
    """The configured fan-out width, or the caller's own explicit cap."""
    return Settings().lb_member_cap if cap is None else cap


def _member_regions(
    members: list[dict[str, Any]],
    cap: int | None = None,
    *,
    require_known_health: bool = False,
) -> LbRegions:
    """One region per healthy member, or one collapsed indeterminate region.

    A member with state == 'down' is skipped. When no member in the pool
    has a `state` property, the members collapse into one indeterminate
    region whose note lists every member.

    A pool wider than the `lb_member_cap` setting is followed up to the cap
    and reports the rest as `surplus`.
    """
    limit = _region_cap(cap)
    if not members:
        return LbRegions([], True, "the pool has no members")
    if require_known_health:
        healthy = [m for m in members if str(m.get("state") or "").strip().lower() == "up"]
        unknown = tuple(m for m in members if str(m.get("state") or "").strip().lower() not in ("up", "down"))
        down = [m for m in members if str(m.get("state") or "").strip().lower() == "down"]
        if down and not healthy and not unknown:
            return LbRegions([], True, f"every member of this pool is down ({_member_names(members)})")
        if not healthy:
            return LbRegions(
                [],
                False,
                None,
                unknown=unknown,
            )
        selected = healthy[:limit]
        surplus_count = max(0, len(healthy) - limit)
        return LbRegions(selected, False, None, surplus_count, unknown)
    if all(m.get("state") is None for m in members):
        return LbRegions(
            [], True, f"no member of this pool carries collected health state ({_member_names(members)})"
        )
    healthy = [m for m in members if (m.get("state") or "").strip().lower() != "down"]
    if not healthy:
        return LbRegions([], True, f"every member of this pool is down ({_member_names(members)})")
    if len(healthy) > limit:
        surplus = healthy[limit:]
        return LbRegions(
            healthy[:limit],
            False,
            f"the pool has {len(healthy)} healthy members, over the {limit}-member cap "
            f"(lb_member_cap); {len(surplus)} not followed ({_member_names(surplus)})",
            len(surplus),
        )
    return LbRegions(healthy, False, None)


_SNAT_FROM_QUERY = """
MATCH (vsn:VirtualService {uid: $vs})-[e:SNAT_FROM]->(ip:IpAddress)
WHERE vsn:Obj AND vsn.collection_ts = $snap
  AND e._retired_at IS NULL AND NOT ip:Retired AND ip.collection_ts = $snap
RETURN ip.ip AS ip ORDER BY ip.ip"""

_SNIP_CANDIDATES_QUERY = """
MATCH (dev:Device {uid: $dev})<-[o:ON]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)-[e:IN]->(p:Prefix)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND o._retired_at IS NULL AND h._retired_at IS NULL AND e._retired_at IS NULL
  AND NOT i:Retired AND NOT ip:Retired AND NOT p:Retired
  AND ip.collection_ts = $snap AND p.collection_ts = $snap
RETURN ip.ip AS ip, i.uid AS if_uid, i.name AS if_name, p.cidr AS cidr
ORDER BY ip.ip"""


def _snip_candidates(
    session: Any, dev_uid: str, member_ip: str, memo: dict[Any, Any] | None = None
) -> list[str]:
    """Every device interface address on the member's subnet, in graph order.

    `memo`, when given, keeps the device's address rows for the next member.
    The read takes the device only, and the rows are filtered by the member's
    subnet after the read."""
    try:
        member = ipaddress.ip_address(member_ip)
    except ValueError:
        return []
    candidates: list[str] = []
    for row in _memo_read(
        memo, ("snip", dev_uid), lambda: _path._read(session, _SNIP_CANDIDATES_QUERY, dev=dev_uid)
    ):
        cidr = row.get("cidr")
        if not cidr:
            continue
        try:
            if member in ipaddress.ip_network(cidr, strict=False):
                candidates.append(str(row["ip"]))
        except ValueError:
            continue
    return candidates


def _snip_for(session: Any, dev_uid: str, member_ip: str) -> str | None:
    """The first of this device's addresses on the member subnet, or None."""
    candidates = _snip_candidates(session, dev_uid, member_ip)
    return candidates[0] if candidates else None


def _memo_read(memo: dict[Any, Any] | None, key: Any, read: Any) -> Any:
    """The rows `read` returns, kept in `memo` under `key` when a memo is given."""
    if memo is None:
        return read()
    if key not in memo:
        memo[key] = read()
    return memo[key]


def _snat_mode_of(vs_row: dict[str, Any]) -> str:
    """The collected snat_mode, stripped and lower-cased, or an empty string when none was collected."""
    return (vs_row.get("snat_mode") or "").strip().lower()


def _lb_snat(
    session: Any,
    vs_row: dict[str, Any],
    dev_uid: str,
    member_ip: str,
    client_src: list[tuple[int, int, int]],
    *,
    require_unique: bool = False,
    memo: dict[Any, Any] | None = None,
) -> tuple[list[tuple[int, int, int]], str | None, bool]:
    """The server-side source, per the VirtualService's own snat_mode.

    Returns (new source set, a note describing the rewrite or None,
    indeterminate).

    `memo`, when given, keeps the rows of the reads that do not depend on the
    member for the next member of the same pool.
    """
    mode = _snat_mode_of(vs_row)
    if mode == "snat_from":
        if require_unique:
            rows = [row for row in _path._read(session, _SNAT_FROM_QUERY, vs=vs_row["uid"]) if row.get("ip")]
            if len(rows) > 1:
                return (
                    client_src,
                    "multiple SNAT_FROM addresses are collected; the server-side source is not determined",
                    True,
                )
            row = rows[0] if rows else None
        else:
            rows = _memo_read(
                memo,
                ("snat_from", vs_row["uid"]),
                lambda: [r for r in _path._read(session, _SNAT_FROM_QUERY, vs=vs_row["uid"]) if r.get("ip")],
            )
            ips = list(dict.fromkeys(str(r["ip"]) for r in rows))
            if len(ips) > 1:
                # The device rewrites to one of the addresses per connection.
                # The choice is not collected. The server-side source is the
                # set of all of the addresses.
                return (
                    _intervals(ips),
                    f"SNAT to one of {', '.join(ips)} (SNAT_FROM); which address the device uses "
                    "is not determined",
                    True,
                )
            row = rows[0] if rows else None
        if row and row.get("ip"):
            return _intervals([row["ip"]]), f"SNAT to {row['ip']} (SNAT_FROM)", False
        return (
            client_src,
            "snat_mode is snat_from but no SNAT_FROM address was collected; the server-side "
            "source is not determined",
            True,
        )
    if mode in ("snip", "automap"):
        label = "SNIP" if mode == "snip" else "automap"
        candidates = _snip_candidates(session, dev_uid, member_ip, memo)
        if require_unique and len(candidates) > 1:
            return (
                client_src,
                f"multiple collected interface addresses match {label}; "
                "the server-side source is not determined",
                True,
            )
        distinct = list(dict.fromkeys(candidates))
        if len(distinct) > 1:
            return (
                _intervals(distinct),
                f"SNAT to one of {', '.join(distinct)} ({label}); which address the device uses "
                "is not determined",
                True,
            )
        if candidates:
            return _intervals([candidates[0]]), f"SNAT to {candidates[0]} ({label})", False
        return (
            client_src,
            f"{label} could not be resolved to a collected interface address on the member's "
            "subnet; the server-side source is not determined",
            True,
        )
    if mode == "none":
        return client_src, "no SNAT: the client source is preserved", False
    if not mode:
        return client_src, "no snat_mode was collected; the server-side source is not determined", True
    return (
        client_src,
        f"unrecognized snat_mode {vs_row['snat_mode']!r}; the server-side source is not determined",
        True,
    )


def reply_indeterminate_reason(vip_name: str) -> str:
    """Why a reply leg that undoes this VirtualService's member rewrite is
    marked indeterminate."""
    return f"no connection table modeled for {vip_name}"


def _member_ivals(spec: Any) -> Ivals | None:
    port = _int_or_none(spec)
    return None if port is None else tuple(_ports(port))


# the two wordings `trace._lb_stage` uses for a VIP nothing claims
_VIP_UNSTATED_REASON = "this VIP is scoped to a protocol or port this flow does not carry"
_VIP_MISS_REASON = "the flow's protocol or port does not match this VIP"
# The wordings `trace._lb_unclaimed_stop` gives a part no VirtualService claims.
# A known miss is blocked at the VIP. A miss beside a VirtualService of an
# unevaluated kind is indeterminate.
_VIP_NO_SERVICE_REASON = "no virtual service on this VIP serves the flow's protocol and port"
_VIP_UNEVALUATED_KIND_REASON = "a virtual service on this VIP is of a kind this engine does not evaluate"


@dataclass
class LbTransition:
    """The load balancer stage over a `FlowRegion`. It relates the
    client-side connection to a server-side connection.

    `vs_rows` is every VirtualService bound to this device for the VIP
    (`_vip_bindings`), `dst_host` the VIP itself. Each rectangle is offered
    to every VirtualService in turn (`_vip_claims_region`), and the part one
    claims is related to each healthy pool member as a rewritten rectangle.
    The source port of a member rectangle is unstated. The remainder no
    VirtualService claims is a terminal `deny` at the VIP when every
    VirtualService on the VIP is of a kind this stage evaluates, and is
    `indeterminate` otherwise.
    """

    session: Any
    dev_uid: str
    vs_rows: list[dict[str, Any]]
    dst_host: str
    require_known_health: bool = False

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        if self.require_known_health:
            return self._apply_strict(region)
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            pending = [rect]
            for vs_row in self.vs_rows:
                still: list[Rect] = []
                for r in pending:
                    vc = _vip_claims_region(vs_row, r)
                    if vc.state == _NO_MATCH:
                        still.append(r)
                        continue
                    if vc.state == _UNKNOWN or vc.claimed is None:
                        out.append(
                            (
                                FlowRegion.single(r),
                                Effect(
                                    "indeterminate",
                                    "lb",
                                    unknown=frozenset(d for d in ("proto", "dport") if getattr(r, d) is None),
                                    reason=_VIP_UNSTATED_REASON,
                                    data={"vs": vs_row},
                                ),
                            )
                        )
                        continue
                    out.extend(self._relate(vs_row, vc.claimed))
                    still.extend(r.subtract(vc.claimed))
                pending = still
            out.extend((FlowRegion.single(r), self._unclaimed()) for r in pending)
        return out

    def _unclaimed(self) -> Effect:
        """The effect of a part no VirtualService on the VIP claims, the
        decision `trace._vip_known_miss` makes for the walk."""
        data = {"vs_rows": self.vs_rows, "vip": self.dst_host}
        if self.vs_rows and all(_vip_supported(r) for r in self.vs_rows):
            return Effect("deny", "lb", terminal=True, reason=_VIP_NO_SERVICE_REASON, data=data)
        return Effect("indeterminate", "lb", reason=_VIP_UNEVALUATED_KIND_REASON, data=data)

    def _apply_strict(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            if rect.proto is None or rect.dport is None:
                out.append(
                    (
                        FlowRegion.single(rect),
                        Effect(
                            "indeterminate",
                            "lb",
                            unknown=frozenset(d for d in ("proto", "dport") if getattr(rect, d) is None),
                            reason=_VIP_UNSTATED_REASON,
                            data={"vs_rows": self.vs_rows},
                        ),
                    )
                )
                continue
            cells: list[tuple[Rect, list[dict[str, Any]]]] = [(rect, [])]
            for vs_row in self.vs_rows:
                next_cells: list[tuple[Rect, list[dict[str, Any]]]] = []
                for cell, claims in cells:
                    claim = _vip_claims_region(vs_row, cell)
                    if claim.state == _NO_MATCH:
                        next_cells.append((cell, claims))
                    elif claim.state == _UNKNOWN or claim.claimed is None:
                        out.append(
                            (
                                FlowRegion.single(cell),
                                Effect(
                                    "indeterminate",
                                    "lb",
                                    reason=_VIP_UNSTATED_REASON,
                                    data={"vs": vs_row},
                                ),
                            )
                        )
                    else:
                        next_cells.append((claim.claimed, [*claims, vs_row]))
                        next_cells.extend((rest, claims) for rest in cell.subtract(claim.claimed))
                cells = next_cells
            for cell, claims in cells:
                if not claims:
                    out.append((FlowRegion.single(cell), self._unclaimed()))
                elif len(claims) > 1:
                    out.append(
                        (
                            FlowRegion.single(cell),
                            Effect(
                                "indeterminate",
                                "lb",
                                reason="multiple VirtualServices claim this protocol/port region",
                                data={"vs_rows": claims},
                            ),
                        )
                    )
                else:
                    out.extend(self._relate(claims[0], cell))
        return out

    def _relate(self, vs_row: dict[str, Any], claimed: Rect) -> list[tuple[FlowRegion, Effect]]:
        if not _vip_supported(vs_row):
            return [
                (
                    FlowRegion.single(claimed),
                    Effect("indeterminate", "lb", reason="kind not evaluated", data={"vs": vs_row}),
                )
            ]
        members = _pool_members(self.session, vs_row["uid"])
        regions = _member_regions(members, require_known_health=self.require_known_health)
        if regions.collapsed:
            all_down = bool(members) and all(
                str(member.get("state") or "").strip().lower() == "down" for member in members
            )
            return [
                (
                    FlowRegion.single(claimed),
                    Effect(
                        "deny" if self.require_known_health and all_down else "indeterminate",
                        "lb",
                        terminal=self.require_known_health and all_down,
                        reason=regions.note,
                        data={"vs": vs_row},
                    ),
                )
            ]
        out: list[tuple[FlowRegion, Effect]] = []
        for member in regions.members:
            new_src, snat_note, snat_indeterminate = _lb_snat(
                self.session,
                vs_row,
                self.dev_uid,
                member["ip"],
                list(claimed.src),
                require_unique=self.require_known_health,
            )
            member_port = _member_ivals(member.get("port"))
            related = claimed.rewrite(
                src=tuple(new_src),
                dst=tuple(_intervals([member["ip"]])),
                dport=member_port if member_port is not None else claimed.dport,
                sport=None,
            )
            out.append(
                (
                    FlowRegion.single(related),
                    Effect(
                        "indeterminate" if snat_indeterminate else "relate",
                        "lb",
                        reason=snat_note if snat_indeterminate else None,
                        data={"vs": vs_row, "member": member, "snat_note": snat_note},
                    ),
                )
            )
        for member in regions.unknown:
            member_port = _member_ivals(member.get("port"))
            related = claimed.rewrite(
                dst=tuple(_intervals([member["ip"]])),
                dport=member_port if member_port is not None else claimed.dport,
                sport=None,
            )
            out.append(
                (
                    FlowRegion.single(related),
                    Effect(
                        "indeterminate",
                        "lb",
                        reason=f"pool member {member.get('name') or member['uid']} health is not recognized",
                        data={"vs": vs_row, "member": member},
                    ),
                )
            )
        if regions.surplus:
            out.append(
                (
                    FlowRegion.single(claimed),
                    Effect("indeterminate", "lb", reason=regions.note, data={"vs": vs_row}),
                )
            )
        return out
