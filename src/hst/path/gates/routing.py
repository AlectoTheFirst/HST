"""The routing stage.

The module holds connected-prefix egress resolution, longest-prefix-match
partitioning of the destination set, the no-route leg, and next-hop device
resolution scoped to the estate being traced.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import hst.path as _path

from ..addrsets import _intersect, _intervals, _lpm_all, _set_bounds, _subtract, _to_cidrs
from ..state import Effect, FlowRegion
from . import _anchor_of, _Trail
from .firewall import _apply_firewall, _apply_firewall_reply

_NEXT_HOP_DEVICE_QUERY = """
MATCH (i:Interface)-[h:HAS_IP]->(ip:IpAddress:Obj)
WHERE ip.ip = $ip AND h._retired_at IS NULL AND NOT ip:Retired AND NOT i:Retired
  AND ip.collection_ts = $snap
MATCH (i)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT d:Retired
RETURN d.uid AS dev_uid, d.hostname AS dev_name, i.uid AS if_uid, i.name AS if_name,
       ip.l3dom AS l3dom, ip.anchor AS anchor, coalesce(d.carried, false) AS carried,
       d.carried_reason AS carried_reason,
       h.fhrp AS fhrp, h.group AS fhrp_group, h.state AS fhrp_state,
       i.vsx_cluster AS vsx_cluster, i.vsx_state AS vsx_state,
       i.firewall_instance_uid AS firewall_instance_uid, i.vsid AS vsid, i.vsx_kind AS vsx_kind
ORDER BY d.uid, i.uid"""


# The interfaces on the link out of the egress interface `$u` that hold the
# IPv6 link-local address `$ip`. The link is a global prefix that both
# interfaces hold, the cable from the egress port, or the bridge domain that
# both attach to. A link-local address repeats across links. The query looks
# the address up on that link alone, in the `ipv6_link_local` list of an
# interface (collectors/vyos.py).
_LINK_PEER_QUERY = """
CALL {
  MATCH (e:Interface:Obj {uid: $u, collection_ts: $snap})-[h1:HAS_IP]->(a:IpAddress)-[n1:IN]->(p:Prefix)
  MATCH (p)<-[n2:IN]-(b:IpAddress)<-[h2:HAS_IP]-(i:Interface)
  WHERE h1._retired_at IS NULL AND n1._retired_at IS NULL AND n2._retired_at IS NULL
    AND h2._retired_at IS NULL AND NOT a:Retired AND NOT p:Retired AND NOT b:Retired AND NOT i:Retired
    AND p.collection_ts = $snap AND i.collection_ts = $snap
  RETURN i
  UNION
  MATCH (e:Interface:Obj {uid: $u, collection_ts: $snap})-[r1:REALIZED_BY]->(pe:Port)
  MATCH (pe)-[c:CONNECTED_TO]-(pf:Port)<-[r2:REALIZED_BY]-(i:Interface)
  WHERE r1._retired_at IS NULL AND c._retired_at IS NULL AND r2._retired_at IS NULL
    AND NOT pe:Retired AND NOT pf:Retired AND NOT i:Retired AND i.collection_ts = $snap
  RETURN i
  UNION
  MATCH (e:Interface:Obj {uid: $u, collection_ts: $snap})-[t1:ATTACHED_TO]->(bd:BridgeDomain)
  MATCH (bd)<-[t2:ATTACHED_TO]-(i:Interface)
  WHERE t1._retired_at IS NULL AND t2._retired_at IS NULL AND NOT bd:Retired AND NOT i:Retired
    AND i.collection_ts = $snap
  RETURN i
}
WITH i
WHERE i.uid <> $u AND $ip IN coalesce(i.ipv6_link_local, [])
MATCH (i)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT d:Retired AND d.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired AND v.collection_ts = $snap
OPTIONAL MATCH (i)-[hx:HAS_IP]->(x:IpAddress)
WHERE hx._retired_at IS NULL AND NOT x:Retired AND x.collection_ts = $snap
WITH d, i, v, [dom IN collect(DISTINCT x.l3dom) WHERE dom IS NOT NULL] AS doms
RETURN d.uid AS dev_uid, d.hostname AS dev_name, i.uid AS if_uid, i.name AS if_name,
       head(doms) AS l3dom, v.uid AS anchor, coalesce(d.carried, false) AS carried,
       d.carried_reason AS carried_reason,
       i.vsx_cluster AS vsx_cluster, i.vsx_state AS vsx_state,
       i.firewall_instance_uid AS firewall_instance_uid, i.vsid AS vsid, i.vsx_kind AS vsx_kind
ORDER BY dev_uid, if_uid"""


def _link_local(ip: str | None) -> str | None:
    """The address of an IPv6 link-local next hop, without a `%zone` suffix,
    or None for any other next hop."""
    text = str(ip or "").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return text if addr.version == 6 and addr.is_link_local else None


def _link_local_owner(
    session: Any, ip: str, egress_uid: str | None, table_uid: str | None, leaked: bool
) -> tuple[dict[str, Any] | None, str | None]:
    """The device whose interface on the egress link holds the link-local
    next hop `ip` (`_LINK_PEER_QUERY`), or the reason it is not found.

    The result is undecided when no interface on the egress link holds the
    address."""
    if not egress_uid:
        return (
            None,
            f"next hop {ip} is a link-local address and the route names no egress interface to find it on",
        )
    rows = _path._read(session, _LINK_PEER_QUERY, u=egress_uid, ip=ip)
    if not rows:
        return None, (
            f"next hop {ip} is a link-local address that no collected interface on the egress link holds, "
            "so the neighbour it names is not established"
        )
    if len(rows) > 1:
        owners = ", ".join(
            f"{r.get('dev_name') or r['dev_uid']} {r.get('if_name') or r['if_uid']}" for r in rows
        )
        return None, (
            f"link-local next hop {ip} is held on the egress link by more than one interface ({owners})"
        )
    return _single_owner_scope(session, ip, rows[0], table_uid, leaked)


_NEXT_HOP_DOMAIN_QUERY = """
MATCH (tbl:VrfInstance {uid: $table})-[m1:MEMBER_OF]->(rd:RoutingDomain)<-[m2:MEMBER_OF]-(v:VrfInstance)
WHERE tbl:Obj AND tbl.collection_ts = $snap
  AND v.uid IN $anchors AND v:Obj AND v.collection_ts = $snap AND NOT rd:Retired AND NOT v:Retired
  AND m1._retired_at IS NULL AND m2._retired_at IS NULL
  AND coalesce(m1.basis, 'declared') = 'declared'
  AND coalesce(m2.basis, 'declared') = 'declared'
  AND rd.collection_ts = $snap
RETURN DISTINCT v.uid AS uid
UNION
MATCH (tbl:VrfInstance {uid: $table})-[r1:REALIZES]->(ld:L3Domain)<-[r2:REALIZES]-(v:VrfInstance)
WHERE tbl:Obj AND tbl.collection_ts = $snap
  AND v.uid IN $anchors AND v:Obj AND v.collection_ts = $snap AND NOT ld:Retired AND NOT v:Retired
  AND r1._retired_at IS NULL AND r2._retired_at IS NULL
  AND ld.collection_ts = $snap
RETURN DISTINCT v.uid AS uid"""


# The table a route resolves its next hop in and the context of the one owner
# found for it, for `_single_owner_scope`.
_NEXT_HOP_CONTEXTS_QUERY = """
MATCH (v:VrfInstance)
WHERE v.uid IN $uids AND v:Obj AND v.collection_ts = $snap AND NOT v:Retired
// the routing domains the context's addresses and routes resolve to: every
// collector stamps one on an address and a prefix, while only some declare a
// RoutingDomain for the VRF. A policy table has no interface, only routes.
OPTIONAL MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)
WHERE iv._retired_at IS NULL AND h._retired_at IS NULL AND NOT i:Retired AND NOT ip:Retired
  AND ip.collection_ts = $snap
WITH v, collect(DISTINCT ip.l3dom) AS held
OPTIONAL MATCH (v)-[r:STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES]->(p:Prefix)
WHERE r._retired_at IS NULL AND NOT p:Retired AND p.collection_ts = $snap
WITH v, held, collect(DISTINCT p.l3dom) AS routed
RETURN v.uid AS uid, v.name AS name, v.is_global AS is_global,
       [d IN held + routed WHERE d IS NOT NULL] AS l3doms
ORDER BY uid"""


# The member state that forwards for a first-hop group, per protocol. It is
# the HSRP active router or the VRRP master (core/labels.py `HAS_IP`).
_FHRP_FORWARDING_STATES: dict[str, str] = {"hsrp": "active", "vrrp": "master"}


def _fhrp_forwarding(row: dict[str, Any]) -> bool:
    """Whether a next-hop row's `HAS_IP` edge records the member as the one
    forwarding for its group."""
    kind = str(row.get("fhrp") or "").lower()
    state = str(row.get("fhrp_state") or "").lower()
    return bool(kind) and _FHRP_FORWARDING_STATES.get(kind) == state


def _fhrp_group_of(rows: list[dict[str, Any]]) -> tuple[str, Any] | None:
    """The one (protocol, group number) on the `HAS_IP` edge of every row, or
    None when any row is an interface's own address or the rows have more
    than one group."""
    keys = {(str(r.get("fhrp") or "").lower(), r.get("fhrp_group")) for r in rows}
    if len(keys) != 1:
        return None
    key = next(iter(keys))
    return key if key[0] else None


# The gateway interfaces of a connected prefix that `_connected_egress` tries
# in turn. The 3 queries read an interface on the device other than the
# ingress, the ingress itself, and the gateway interface of any device.
_CONNECTED_LOCAL_QUERY = """
MATCH (i:Interface)-[g:GATEWAY_FOR]->(p:Prefix {uid: $p})
WHERE p:Obj AND p.collection_ts = $snap
  AND g._retired_at IS NULL AND NOT i:Retired AND i.uid <> $in_if
  AND i.collection_ts = $snap
MATCH (i)-[:ON]->(dev:Device {uid: $dev})
WHERE dev:Obj AND dev.collection_ts = $snap
RETURN i.uid AS uid, i.name AS name
ORDER BY i.uid LIMIT 1"""

_CONNECTED_INGRESS_QUERY = """
MATCH (i:Interface {uid: $in_if})-[g:GATEWAY_FOR]->(p:Prefix {uid: $p})
WHERE g._retired_at IS NULL AND i:Obj AND i.collection_ts = $snap
  AND p:Obj AND p.collection_ts = $snap
RETURN i.uid AS uid, i.name AS name"""

_CONNECTED_REMOTE_QUERY = """
MATCH (i:Interface)-[g:GATEWAY_FOR]->(p:Prefix {uid: $p})
WHERE p:Obj AND p.collection_ts = $snap
  AND g._retired_at IS NULL AND NOT i:Retired AND i.collection_ts = $snap
RETURN i.uid AS uid, i.name AS name
ORDER BY i.uid"""


def _connected_egress(session: Any, prefix_uid: str, dev_uid: str, in_if_uid: str) -> dict[str, Any] | None:
    """The gateway interface serving a connected prefix.

    The function makes 3 attempts in this order.

      1. An interface on the device evaluating the trace, other than the
         ingress.
      2. The ingress interface itself, when the destination is on the
         source's own network. The flow has no L3 egress and crosses no zone
         boundary.
      3. The gateway interface of any device (`remote`), the first by uid.
    """
    local = _path._read_one(
        session,
        _CONNECTED_LOCAL_QUERY,
        p=prefix_uid,
        dev=dev_uid,
        in_if=in_if_uid,
    )
    if local:
        return {**local, "remote": False, "ingress": False}
    ingress = _path._read_one(
        session,
        _CONNECTED_INGRESS_QUERY,
        p=prefix_uid,
        in_if=in_if_uid,
    )
    if ingress:
        return {**ingress, "remote": False, "ingress": True}
    # every remote candidate, ordered by uid
    remote = _path._read(
        session,
        _CONNECTED_REMOTE_QUERY,
        p=prefix_uid,
    )
    if remote:
        return {**remote[0], "remote": True, "ingress": False, "remote_count": len(remote)}
    return None


def _rib_route(row: dict[str, Any]) -> dict[str, Any]:
    """A side-store RIB row in the shape the route legs consume.

    The row has no graph uid. The prefix of a store-only table has no Prefix
    node. The leg has a note for the prefix and no hop on it.

    A row of a compiled FIB (`hst.simul.rib.Fib`, marked `fib`) has the same
    shape and `kind` FIB. It is the selection of the routing calculation,
    and `_route_provenance` reads it as authoritative like an observed row.
    The row keeps `protocol` and `metric` for the leg text.

    A row out of Null0 is a discard route for any value of its `discard`
    column.
    """
    null_route = str(row.get("interface") or "").replace(" ", "").lower() == "null0"
    return {
        "uid": None,
        "cidr": row["prefix"],
        "kind": "FIB" if row.get("fib") else "RIB",
        "next_hop": None if null_route else row.get("next_hop"),
        "next_hop_vrf": row.get("next_hop_context_uid"),
        "ifname": row.get("interface"),
        "egress_uid": None,
        "egress_name": row.get("interface"),
        "rib": True,
        "derived": None,
        "via_rt": None,
        "discard": row.get("discard") or ("blackhole" if null_route else None),
        "protocol": row.get("protocol"),
        "metric": row.get("metric"),
    }


def _fib_lookup(fib: Any | None, dev_uid: str, table_uid: str | None) -> tuple[Any, Any] | None:
    """The `(lpm, overlapping)` pair `_route_partition` reads, over a compiled
    FIB (`hst.simul.rib.Fib`) in the side-store row shape, or None when there
    is no FIB or no table."""
    if fib is None or not table_uid:
        return None
    return (
        lambda probe: fib.lpm(dev_uid, table_uid, probe),
        lambda lo, hi, minlen, af: fib.overlapping(dev_uid, table_uid, lo, hi, minlen, af),
    )


def _is_connected(protocol: Any) -> bool:
    """Whether the protocol of a side-store row is a connected route, in the
    words the collectors use (`simul/rib.py` `_family`). The words are FRR's
    `connected`, the Cisco legend `C` and NX-OS `direct`."""
    head = str(protocol or "").strip().lower().split(" ")[0].split("-")[0]
    return head in ("c", "connected", "direct", "directly")


def _route_id(r: dict[str, Any]) -> tuple[Any, Any, Any]:
    """The identity key of a route is the next hop, else the interface, else the `discard` kind."""
    nh = r.get("next_hop")
    if nh:
        return (r.get("cidr"), nh, None)
    # The declared interface is used when the reasoner resolved none. The
    # store row of the same route has that interface as its egress.
    egress = r.get("egress_name") or r.get("ifname")
    return (r.get("cidr"), nh, egress or r.get("discard"))


def _route_provenance(
    routes: list[dict[str, Any]], *, observed: bool = False, connected: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The winners of an LPM tie, narrowed by the origin of each route.

    A route the device holds (a connected ORIGINATES prefix, an observed
    LEARNED_ROUTE, a side-store RIB row) outranks a route that is config or
    inference only (a bare STATIC_ROUTE, or a LEARNED_ROUTE the reasoner
    derived). Nothing is dropped when the authoritative bucket is empty.

    A route the RIB confirms (`rib`) is authoritative for any edge type. The
    flag is set in 2 places. `_route_partition` sets it in its merge when a
    graph static and a side-store row are the same route. A collector sets
    it when it read both the config stanza and the device's own RIB row for
    the route (collectors/vyos.py `_confirm_static_route`, read back as
    `rib_confirmed` by `_ROUTES_QUERY` of `trace.py`).

    A config-only route with `discard` (a blackhole or reject static) is not
    promoted into the authoritative bucket. Without `observed`, it is not
    dropped. With `observed`, a config-only discard that the RIB does not
    hold beside a route the RIB holds for the same prefix is not installed
    (a floating blackhole below the route it backs up) and is dropped like
    any other config-only static. A discard the RIB holds has `rib` and
    stays.

    A BGP aggregate (`AGGREGATE`, the summary's discard route) yields to any
    other route for the same prefix. A connected or static route installs at
    a lower distance, and a learned or RIB row for the prefix is the device's
    own selection.

    The collectors write a connected ORIGINATES prefix from the interface
    address alone, also for an interface that is down or disabled. With
    `connected` (the store answered for this table and records connected
    rows for it, `_store_records_connected`), a connected prefix with no
    connected row in the store has no `rib` flag from the fold of
    `_route_partition`. That prefix is config only like a bare static and
    loses a tie to the route the RIB holds. Without `connected`, every
    connected prefix stays authoritative.

    Returns (winners, dropped). The function mutates no row. Every lane of
    the trace that probes the same table reads the same route rows.
    """
    if any(r.get("kind") != "AGGREGATE" for r in routes):
        routes = [r for r in routes if r.get("kind") != "AGGREGATE"]
    authoritative: list[dict[str, Any]] = []
    config_only: list[dict[str, Any]] = []
    for r in routes:
        unconfirmed = (
            r.get("kind") == "STATIC_ROUTE"
            or r.get("derived")
            or (connected and r.get("kind") == "ORIGINATES")
        ) and not r.get("rib")
        (config_only if unconfirmed else authoritative).append(r)
    dropped = [r for r in config_only if observed or not r.get("discard")]
    if not authoritative or not dropped:
        return routes, []
    losers = {id(r) for r in dropped}
    return [r for r in routes if id(r) not in losers], dropped


def _outranked_note(route: dict[str, Any]) -> str:
    """Why a config-only or derived route was left out of the winners."""
    via = route.get("next_hop") or route.get("egress_name") or route.get("ifname")
    what = (
        "route-target derived route"
        if route.get("derived")
        else "connected prefix that the RIB does not hold"
        if route.get("kind") == "ORIGINATES"
        else f"config-only {route['discard']} static route"
        if route.get("discard")
        else "config-only static route"
    )
    return (
        f"{route['cidr']}: the {what}" + (f" via {via}" if via else "") + " is outranked by a route "
        "the device holds (connected, observed or from the RIB) and is not used"
    )


def _observed_selection(store_rows: list[dict[str, Any]]) -> str:
    """The side store's own answer for a probe, as text. The text is the
    selection of the device's RIB for that destination, or that the RIB holds
    no route for it."""
    if not store_rows:
        return "holds no route for this destination"
    vias = sorted(
        f"{r['cidr']} via {r.get('next_hop') or r.get('egress_name') or r.get('discard') or '?'}"
        for r in store_rows
    )
    return "selects " + ", ".join(vias)


def _mark_unconfirmed(
    best: list[dict[str, Any]],
    selection: str,
    unheld: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    """The winners, with every config-only static replaced by a copy marked
    `unconfirmed`. The mark holds the observed selection that the static
    disagrees with.

    Longest-prefix match runs over the graph rows and the store rows as one
    set, and `_route_provenance` narrows a tie only. A STATIC_ROUTE the
    device did not install wins when it is longer than the route the RIB
    selects (an uninstalled /24 over an observed /16). The observed table is
    the selection. A config static that the table does not hold is a
    hypothesis, and the leg built from it is marked (`trace.py`
    `_build_route_leg`). The marked winners are copies of the shared rows.
    The same row can win another part of the same destination set against a
    different observed answer.

    A connected ORIGINATES prefix and a BGP AGGREGATE that the store does not
    hold are marked the same way. The collectors write the connected prefix
    from an interface address also when the interface is down or disabled.
    They write the aggregate from the aggregate statement also when no
    contributing route makes the device install it. The store folds its own
    connected or discard row for the prefix onto them (`rib`). A missing row
    is evidence only where `unheld` returns True for that row. `unheld`
    returns True when the store records connected rows for the table, or
    when the aggregate has no contributing route.
    """

    def marked(r: dict[str, Any]) -> bool:
        if r.get("rib") or r.get("derived"):
            return False
        if r.get("kind") == "STATIC_ROUTE":
            return True
        return r.get("kind") in ("ORIGINATES", "AGGREGATE") and unheld is not None and unheld(r)

    return [{**r, "unconfirmed": selection} if marked(r) else r for r in best]


def _store_records_connected(routes: list[dict[str, Any]], overlapping: Any) -> bool:
    """Whether the store shows that it records connected rows for this
    table. It does when it folded a connected row onto a connected prefix, or
    holds a connected row inside a connected prefix of the table. A RIB file
    whose writer does not record connected rows holds none. Such a writer is
    an earlier VyOS collector, or a writer whose word for a connected route
    `_is_connected` does not read. A missing connected row is then no
    evidence that an interface is down. The function makes one query per
    connected prefix, over that prefix alone."""
    origins = [r for r in routes if r.get("kind") == "ORIGINATES" and r.get("cidr")]
    if any(r.get("rib") for r in origins):
        return True
    for r in origins:
        try:
            net = ipaddress.ip_network(r["cidr"])
        except ValueError:
            continue
        bounds = _set_bounds(_intervals([r["cidr"]]))
        if bounds is None:
            continue
        rows = overlapping(bounds[0], bounds[1], net.prefixlen - 1, net.version)
        if any(_is_connected(row.get("protocol")) for row in rows):
            return True
    return False


def _aggregate_uncontributed(
    aggregate: dict[str, Any], candidates: list[dict[str, Any]], overlapping: Any
) -> bool:
    """Whether nothing the device holds lies inside a BGP aggregate. The
    device installs the aggregate's discard route only while a contributing
    more-specific route exists. With none in the graph rows or the store,
    the missing aggregate row is evidence that the aggregate is not
    installed. With one, a missing row can come from a writer that records
    no discard rows, and the aggregate is not marked."""
    try:
        agg = ipaddress.ip_network(aggregate["cidr"])
    except (KeyError, ValueError):
        return False
    for c in candidates:
        try:
            net = ipaddress.ip_network(c["cidr"])
        except (KeyError, ValueError):
            continue
        if net.version == agg.version and net.prefixlen > agg.prefixlen and net.subnet_of(agg):  # type: ignore[arg-type]
            return False
    bounds = _set_bounds(_intervals([aggregate["cidr"]]))
    return bounds is not None and not overlapping(bounds[0], bounds[1], agg.prefixlen, agg.version)


def _mirror_unconfirmed(route: dict[str, Any]) -> bool:
    """Whether a route of a table mirrored from the RIB is a static the
    mirror did not confirm. Such a route is a forwarding static (a next hop
    or an interface) with no `rib`. The collector does not fold a discard
    static, and a discard static is never unconfirmed here."""
    return (
        route.get("kind") == "STATIC_ROUTE"
        and not route.get("rib")
        and not route.get("derived")
        and not route.get("discard")
        and bool(route.get("next_hop") or route.get("ifname") or route.get("egress_name"))
    )


def _mark_mirrored_unconfirmed(
    best: list[dict[str, Any]], candidates: list[dict[str, Any]], probe: str
) -> list[dict[str, Any]]:
    """`_mark_unconfirmed` for a table the collector mirrored from the RIB
    with no side store. The selection in the mark is the longest match among
    the rows the mirror holds, without the statics the mirror does not
    confirm."""
    if not any(_mirror_unconfirmed(r) for r in best):
        return best
    held = _lpm_all([r for r in candidates if not _mirror_unconfirmed(r)], probe)
    selection = _observed_selection(held)
    return [{**r, "unconfirmed": selection} if _mirror_unconfirmed(r) else r for r in best]


def _member_order(route: dict[str, Any]) -> tuple[Any, ...]:
    """The sort key of the members of one equal-cost set. The order is by
    next-hop address, then egress interface, then the route's own identity."""
    next_hop = str(route.get("next_hop") or "")
    try:
        address = ipaddress.ip_address(next_hop)
        by_address: tuple[int, int] = (address.version, int(address))
    except ValueError:
        by_address = (0, 0)
    return (
        by_address,
        next_hop,
        str(route.get("egress_uid") or ""),
        str(route.get("egress_name") or route.get("ifname") or ""),
        str(route.get("uid") or ""),
        str(route.get("kind") or ""),
        str(route.get("discard") or ""),
    )


def _route_partition(
    routes: list[dict[str, Any]],
    dst_set: list[tuple[int, int, int]],
    rib_lookup: Any | None = None,
    notes: list[str] | None = None,
    *,
    observed: bool = False,
    mirrored: bool = False,
    limit: int | None = None,
) -> list[tuple[list[tuple[int, int, int]], list[dict[str, Any]]]]:
    """Partition the destination set by longest-prefix match.

    Returns (sub-set, winners) pairs, one per distinct best route (an ECMP
    set). Winners is empty for the part no route covers.

    `rib_lookup`, when given, is `(lpm(probe), overlapping(lo, hi, minlen, af))`
    over the side-store RIB of the same routing instance. Graph rows take
    precedence over store rows for the same prefix and nexthop.

    `notes`, when given, is extended with one line per route `_route_provenance`
    dropped from a tie.

    `observed` is True when the store answered for this device's table. A
    config-only static among the winners that the store does not hold is then
    marked `unconfirmed` (`_mark_unconfirmed`).

    `mirrored` is True when the table's rows are the device's RIB mirrored
    into the graph by the collector in the same run (a VyOS table under
    `rib_graph_max_routes`). The collector folds the RIB row of an installed
    static onto the static as `rib`. When the store branch does not apply, a
    static among the winners with a next hop or an interface and no `rib` is
    not installed. It is marked `unconfirmed` with the selection of the
    mirrored table without the statics the table does not confirm
    (`_mark_mirrored_unconfirmed`). Only statics are marked. The mirror holds
    no connected or aggregate row, and the collector folds no discard row.

    `limit`, when given, stops the partition after that many parts. The
    caller reads the destinations that no part covers as not evaluated. With
    `limit` None the whole set is partitioned.
    """
    parts: list[tuple[list[tuple[int, int, int]], list[dict[str, Any]]]] = []
    remaining = dst_set
    evidence: list[bool] = []

    def records_connected() -> bool:
        # The store is asked at most once per partition, and only for a
        # connected prefix that the store did not confirm.
        if not evidence:
            evidence.append(rib_lookup is not None and _store_records_connected(routes, rib_lookup[1]))
        return evidence[0]

    while remaining and (limit is None or len(parts) < limit):
        probe = _to_cidrs(remaining)[0].split("/")[0]
        candidates = routes
        store_rows: list[dict[str, Any]] = []
        if rib_lookup is not None:
            lpm, _ = rib_lookup
            by_id = {_route_id(r): r for r in routes}
            origin_by_cidr = {r["cidr"]: r for r in routes if r.get("kind") == "ORIGINATES"}
            extra = []
            store_rows = list(map(_rib_route, lpm(probe)))
            for store_row in store_rows:
                graph_row = by_id.get(_route_id(store_row))
                if graph_row is None and _is_connected(store_row.get("protocol")):
                    # The store row is the device's own connected row for a
                    # prefix that the graph holds as ORIGINATES. The row
                    # confirms the graph route and adds no second leg. The
                    # ORIGINATES route has no egress in its identity key (its
                    # egress is resolved from GATEWAY_FOR), and `by_id` does
                    # not match it. The match is by prefix.
                    origin = origin_by_cidr.get(store_row["cidr"])
                    if origin is not None:
                        origin["rib"] = True
                        continue
                if graph_row is not None:
                    # The store holds the same route. A config static with no
                    # VIA edge and no declared interface takes the store's
                    # resolved interface.
                    if not graph_row["ifname"] and not graph_row["egress_name"]:
                        graph_row["ifname"] = store_row["ifname"]
                        graph_row["egress_name"] = store_row["egress_name"]
                    graph_row["rib"] = True
                    continue
                extra.append(store_row)
            candidates = routes + extra
        tied = _lpm_all(candidates, probe)
        store_answered = observed and rib_lookup is not None
        connected = (
            store_answered
            and any(r.get("kind") == "ORIGINATES" and not r.get("rib") for r in tied)
            and records_connected()
        )
        best, outranked = _route_provenance(tied, observed=store_answered, connected=connected)
        if store_answered and rib_lookup is not None:
            overlapping_rows = rib_lookup[1]

            def unheld(
                r: dict[str, Any],
                seen: list[dict[str, Any]] = candidates,
                overlapping: Any = overlapping_rows,
            ) -> bool:
                if r.get("kind") == "ORIGINATES":
                    return records_connected()
                return _aggregate_uncontributed(r, seen, overlapping)

            best = _mark_unconfirmed(best, _observed_selection(store_rows), unheld)
        elif mirrored:
            best = _mark_mirrored_unconfirmed(best, candidates, probe)
        # Neither read orders its rows. Every pick of one equal-cost member
        # reads best[0].
        best = sorted(best, key=_member_order)
        if notes is not None:
            notes.extend(_outranked_note(c) for c in outranked)
        win = ipaddress.ip_network(best[0]["cidr"]) if best else None
        region = _intersect(remaining, _intervals([best[0]["cidr"]])) if best else remaining
        carve = candidates
        if rib_lookup is not None:
            bounds = _set_bounds(region)
            if bounds is not None:
                _, overlapping = rib_lookup
                # With a winner, only a prefix longer than it can carve the
                # region up. With no winner, every length comes back (min_prefixlen -1).
                minlen = win.prefixlen if win is not None else -1
                af = win.version if win is not None else region[0][0]
                carve = candidates + [_rib_route(r) for r in overlapping(bounds[0], bounds[1], minlen, af)]
        for c in carve:
            try:
                net = ipaddress.ip_network(c["cidr"])
            except (KeyError, ValueError):
                continue
            # A longer prefix beats the winner wherever it overlaps. Subtracting
            # a route that does not overlap the region changes nothing, and the
            # loop makes no subnet test.
            if win is None or (net.version == win.version and net.prefixlen > win.prefixlen):
                region = _subtract(region, _intervals([c["cidr"]]))
        # The loop terminates. The probe address is in `region` and is never
        # carved out of it. `region` is non-empty and `remaining` shrinks in
        # every iteration. No subtracted prefix contains the probe. With a
        # winner, only prefixes longer than the winner are subtracted, and a
        # longer prefix that contains the probe wins the match. With no winner,
        # `lpm(probe)` returns a store prefix that contains the probe as a
        # candidate, and the rows that `overlapping` adds do not contain the
        # probe.
        parts.append((region, best))
        remaining = _subtract(remaining, region)
    return parts


def _connected_prefixes(routes: list[dict[str, Any]]) -> list[str]:
    """The device's own connected prefixes among a routing table's rows.

    An ORIGINATES edge is the graph's record that the device itself serves the
    prefix.
    """
    return [r["cidr"] for r in routes if r.get("kind") == "ORIGINATES" and r.get("cidr")]


def _host_prefixes(routes: list[dict[str, Any]]) -> list[str]:
    """The single-address prefixes a routing table holds.

    A /32 or /128 route for the next hop itself means that the table
    resolves this one address.

    Only a host route that the table resolves itself counts. Such a route has
    no next hop (a connected or interface host route, a PPP peer) or has the
    address itself as its next hop. A host route learned or configured via
    another router, such as an IGP route to a remote loopback, is left out.

    A discard host route (a blackhole or reject) is left out. The device
    drops the traffic that the route matches.
    """
    out = []
    for r in routes:
        cidr = r.get("cidr")
        if not cidr or r.get("discard"):
            continue
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:
            continue
        if net.prefixlen != net.max_prefixlen:
            continue
        nh = r.get("next_hop")
        if nh:
            try:
                via = ipaddress.ip_address(str(nh))
            except ValueError:
                continue
            if not via.is_unspecified and via != net.network_address:
                continue
        out.append(cidr)
    return out


def _next_hop_adjacent(ip: str, connected: list[str]) -> bool | None:
    """Whether a next-hop address sits on one of this device's connected prefixes.

    None means the table records no connected prefix of the next hop's family.
    """
    if _link_local(ip):
        # a link-local next hop is on the link the route leaves by
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    nets = []
    for cidr in connected:
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:
            continue
        if net.version == addr.version:
            nets.append(net)
    if not nets:
        return None
    return any(addr in net for net in nets)


def _no_route_leg(
    session: Any,
    trail: _Trail,
    grp: dict[str, Any],
    gw: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    lane: int,
    src_label: str,
    port: int | None,
    proto: str | None,
    *,
    conn_state: str = "new",
) -> dict[str, Any]:
    """The leg for a destination part no route covers.

    Without a firewall verdict, the leg's verdict is "no route found".

    `conn_state` 'new' calls the forward gate, and any other value calls
    `_apply_firewall_reply`.
    """
    leg = {
        "lane": lane,
        "sources": _to_cidrs(grp["sources"]),
        "cidr": None,
        "egress": None,
        "next_hop": None,
        "blocked": False,
        "indeterminate": False,
        "table": grp["table_name"],
        "src_label": src_label,
    }
    fw_gate = _apply_firewall if conn_state == "new" else _apply_firewall_reply
    fw_gate(session, trail, leg, gw, None, grp["sources"], dst_part, port, proto, src_label, "no egress")
    if "verdict" not in leg:
        leg["verdict"] = "no route found"
    return leg


# A fake graph in tests tells the 3 same-node queries apart by their text.
# `_NEXT_HOP_DOMAIN_QUERY` is the same-estate evidence for rung 2 of
# `_next_hop_device`. It reads declared membership only. An edge without the
# `basis` property is declared. An edge with `basis: "rt-component"` is not
# read. The REALIZES union reads the REALIZES/L3Domain rows that a graph
# loaded by an earlier release holds in place of MEMBER_OF/RoutingDomain.
def _next_hop_device(
    session: Any,
    ip: str,
    table_uid: str | None,
    gw: dict[str, Any],
    *,
    leaked: bool = False,
    egress_uid: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """The device that owns a next-hop address, scoped to the estate being traced.

    `table_uid` is the context the route resolves its next hop in. It is the
    route's own table, or the exporting context on a leaked route whose
    collector recorded that provenance (`next_hop_vrf`).

    With duplicate IP space the literal address is not a key. The `ip:`
    identity is per anchor, and one address can be owned once per context.
    When more than one context owns the address, the pick narrows by
    evidence in 4 rungs, strongest first.

      1. The route's own table owns the address.
      2. A context shares a declared RoutingDomain with that table.
      3. The `_anchor_of` key of a context matches the key of the gateway.
      4. A row without an anchor has the gateway's l3dom.

    The first rung with survivors decides. More than one surviving context
    fails closed with (None, why). An FHRP virtual address collected from
    Cisco members is anchored once per member device (each member's own
    VrfInstance uid). The members of one group count as one context when
    every row has the same protocol and group number on its `HAS_IP` edge.
    Two rows that both claim the forwarding role are two groups folded onto
    one address and fail closed. An anchor-keyed rung does not settle while a
    row without an anchor matches the trace's scope. `_single_owner_scope`
    checks a single owning context.

    An IPv6 link-local next hop is no key outside its link. It is found on
    the link out of `egress_uid`, the route's egress interface
    (`_link_local_owner`).
    """
    link_local = _link_local(ip)
    if link_local is not None:
        return _link_local_owner(session, link_local, egress_uid, table_uid, leaked)
    rows = _path._read(session, _NEXT_HOP_DEVICE_QUERY, ip=ip)
    if not rows:
        return None, None

    def settled(cands: list[dict[str, Any]]) -> dict[str, Any] | None:
        if any(r.get("vsx_cluster") for r in cands):
            instances = {r.get("firewall_instance_uid") for r in cands}
            if len(instances) != 1 or None in instances or not all(r.get("vsx_cluster") for r in cands):
                return None
            # The active check reads every row of the same firewall instance,
            # also the rows that the context narrowing removed.
            members = [r for r in rows if r.get("firewall_instance_uid") in instances]
            active_devices = {r["dev_uid"] for r in members if r.get("vsx_state") == "active"}
            if len(active_devices) != 1:
                return None
            cands = [r for r in cands if r.get("vsx_state") == "active"]
            if not cands:
                return None
        one_context = len({_anchor_of(r) for r in cands}) == 1
        group = _fhrp_group_of(cands)
        if not one_context and group is None:
            return None
        if len(cands) == 1:
            return cands[0]
        # Another lane of the same trace can reuse the read row.
        active = [r for r in cands if _fhrp_forwarding(r)]
        if len(active) > 1:
            # two members claiming the forwarding role of one group is two
            # groups folded onto one address, and the trace cannot pick
            return None
        rivals: list[dict[str, Any]] = []
        if active:
            won = active[0]
            basis = f"{won['fhrp']} {won['fhrp_state']} member"
        else:
            by_uid = sorted(cands, key=lambda r: (r.get("dev_uid") or "", r.get("if_uid") or ""))
            won, rivals = by_uid[0], by_uid[1:]
            basis = "lowest uid"
        where = "one forwarding context"
        if not one_context and group is not None:
            where = f"one {group[0]} group {group[1]}"
        owners = ", ".join(sorted(str(r.get("dev_name") or r.get("dev_uid")) for r in cands))
        return {
            **won,
            "tie_note": (
                f"{len(cands)} interfaces hold next hop {ip} in {where} "
                f"({owners}); traced via {won.get('dev_name') or won.get('dev_uid')} "
                f"{won.get('if_name')} ({basis})"
            ),
            # No row among `won` and these rows is the forwarding member.
            "tie_rivals": rivals,
        }

    pick = settled(rows)
    if pick is not None:
        owner, why = _single_owner_scope(session, ip, pick, table_uid, leaked)
        if owner is not None and owner.get("tie_rivals"):
            owner = {
                **owner,
                "tie_rivals": [_scoped_rival(session, ip, r, table_uid, leaked) for r in owner["tie_rivals"]],
            }
        return owner, why
    anchors = sorted({str(r["anchor"]) for r in rows if r.get("anchor")})
    mates = (
        {m["uid"] for m in _path._read(session, _NEXT_HOP_DOMAIN_QUERY, table=table_uid, anchors=anchors)}
        if table_uid and anchors
        else set()
    )
    # A row without an anchor that matches the gateway's scope stops the anchor-keyed rungs.
    contested = [
        r
        for r in rows
        if not r.get("anchor")
        and (
            (_anchor_of(gw) and _anchor_of(r) == _anchor_of(gw))
            or (r.get("l3dom") and r.get("l3dom") == gw.get("l3dom"))
        )
    ]
    tie = "nothing ties one to this trace"
    for anchor_keyed, scoped in (
        (True, [r for r in rows if table_uid and r.get("anchor") == table_uid]),
        (True, [r for r in rows if r.get("anchor") in mates]),
        (False, [r for r in rows if _anchor_of(gw) and _anchor_of(r) == _anchor_of(gw)]),
        (
            False,
            [r for r in rows if not r.get("anchor") and r.get("l3dom") and r.get("l3dom") == gw.get("l3dom")],
        ),
    ):
        if not scoped:
            continue
        if anchor_keyed and contested:
            rows = scoped + [r for r in contested if r not in scoped]
            tie = "the owners mix anchored rows with unanchored rows that match this trace's scope"
            break
        pick = settled(scoped)
        if pick is not None:
            return pick, None
        rows = scoped  # The address is ambiguous inside the estate. The note lists this set.
        tie = "every one of them tied to this trace, and the address is duplicated inside the estate"
        break
    # one display name per surviving context
    dom_by_anchor: dict[Any, list[str]] = {}
    for r in rows:
        a = _anchor_of(r)
        dom_by_anchor.setdefault(a, []).append(str(r.get("l3dom") or a or "?"))
    doms = [sorted(dom_by_anchor[a])[0] for a in sorted(dom_by_anchor, key=str)]
    owners = sorted({str(r["dev_name"] or r["dev_uid"]) for r in rows})
    return None, (
        f"next hop {ip} is owned in {len(dom_by_anchor)} forwarding contexts "
        f"({', '.join(doms)}; devices {', '.join(owners)}) and {tie}; "
        "trace stopped"
    )


def _scoped_rival(
    session: Any, ip: str, rival: dict[str, Any], table_uid: str | None, leaked: bool
) -> dict[str, Any]:
    """A tied owner of a next hop after `_single_owner_scope`. `tie_why` holds
    the reason when the scope check refuses the owner."""
    owner, why = _single_owner_scope(session, ip, rival, table_uid, leaked)
    return owner if owner is not None else {**rival, "tie_why": why}


def _single_owner_scope(
    session: Any, ip: str, pick: dict[str, Any], table_uid: str | None, leaked: bool
) -> tuple[dict[str, Any] | None, str | None]:
    """The one owning context of a next hop, checked against the table the
    route resolves it in.

    On a leaked route `table_uid` is the exporting context, and the owner is
    compared with that table.

    The owner is accepted when there is nothing to compare (no table, or a
    row without an anchor), when it is that table, when the two share a
    declared RoutingDomain or hold addresses of one resolved routing domain,
    when both are global tables, or when both have the same VRF name (a VRF
    handed from device to device, for which strict domain grouping gives no
    shared domain). Two non-global VRFs of different names with none of that
    evidence are an isolation boundary, and the pick fails closed. Any other
    pairing is followed, and the owner gets a `context_note`. The other
    pairings are a global table and a VRF, a context whose kind was not
    recorded, and an anchor or table that is not a recorded VrfInstance
    (APIC, manual and Nautobot addressing).
    """
    owner = pick.get("anchor")
    if not table_uid or not owner or owner == table_uid:
        return pick, None
    if _path._read(session, _NEXT_HOP_DOMAIN_QUERY, table=table_uid, anchors=[owner]):
        return pick, None
    ctx = {r["uid"]: r for r in _path._read(session, _NEXT_HOP_CONTEXTS_QUERY, uids=[table_uid, owner])}
    device = pick.get("dev_name") or pick.get("dev_uid")
    route_in = f"leaked from table {table_uid}" if leaked else f"in table {table_uid}"
    if table_uid not in ctx or owner not in ctx:
        # An anchor that is a source scope (APIC, manual and Nautobot
        # addressing) has no kind or name to compare. No evidence places the
        # owner in the route's estate.
        missing = owner if owner not in ctx else table_uid
        return {
            **pick,
            "context_note": (
                f"next hop {ip} is held only by {device} under {owner}, while the route is "
                f"{route_in}; {missing} is not a recorded forwarding context, so whether the hop "
                "stays in the route's routing domain is not established"
            ),
        }, None
    here, there = ctx[table_uid], ctx[owner]
    if here.get("is_global") is True and there.get("is_global") is True:
        return pick, None
    if here.get("name") and here.get("name") == there.get("name"):
        return pick, None
    if set(here.get("l3doms") or ()) & set(there.get("l3doms") or ()):
        # both contexts hold addresses of one resolved routing domain
        return pick, None
    here_name = here.get("name") or table_uid
    there_name = there.get("name") or owner
    if here.get("is_global") is False and there.get("is_global") is False:
        where = (
            f"the VRF {here_name} the route is leaked from" if leaked else f"VRF {here_name} the route is in"
        )
        return None, (
            f"next hop {ip} is held only by {device} in VRF {there_name}, which is not "
            f"{where}, shares no declared routing domain with it "
            "and is not a leak target; trace stopped at the boundary"
        )
    route_in = f"leaked from table {here_name}" if leaked else f"in table {here_name}"
    return {
        **pick,
        "context_note": (
            f"next hop {ip} is held only by {device} in table {there_name}, while the route "
            f"is {route_in}; the two share no declared routing domain, "
            "so the hop may cross into another estate through reused addressing"
        ),
    }, None


# --- the routing stage as a transition ------------------------------------------------


@dataclass
class RoutingTransition:
    """Longest-prefix match over a `FlowRegion`. It selects FIB actions.

    `_route_partition` reads `routes` and `rib_lookup`. `notes`, when given,
    collects the outranked-route lines that `_route_partition` writes. Every
    rectangle is partitioned on its destination set. Each part is returned
    as the rectangle narrowed to that part, with a `select` effect whose
    data holds the winning routes (an ECMP set when several tie), or a
    `no-route` effect where no route covers the part. A part that every
    winner discards is terminal, and so is a part with no route. A part
    with a next hop is not terminal.
    """

    routes: list[dict[str, Any]]
    rib_lookup: Any | None = None
    notes: list[str] | None = None
    # The `observed` argument of `_route_partition`. The store answered for
    # this table, and a config-only static that the store does not hold is
    # marked unconfirmed.
    observed: bool = False
    # The `mirrored` argument of `_route_partition`. The table is the RIB
    # mirrored into the graph in the same run, and a static that the table
    # does not confirm is marked unconfirmed.
    mirrored: bool = False

    @classmethod
    def from_fib(
        cls, fib: Any, dev_uid: str, table_uid: str | None, notes: list[str] | None = None
    ) -> RoutingTransition:
        """The routing stage over a compiled FIB alone (`hst.simul.rib.Fib`).
        The stage has no graph rows. Every candidate comes from the
        calculation's table for the device and context."""
        return cls(routes=[], rib_lookup=_fib_lookup(fib, dev_uid, table_uid), notes=notes)

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            for dst_part, best in _route_partition(
                self.routes,
                list(rect.dst),
                self.rib_lookup,
                self.notes,
                observed=self.observed,
                mirrored=self.mirrored,
            ):
                sub = rect.narrow(dst=tuple(dst_part))
                if not best:
                    out.append((FlowRegion.single(sub), Effect("no-route", "routing", terminal=True)))
                    continue
                discard = all(r.get("discard") for r in best)
                out.append(
                    (
                        FlowRegion.single(sub),
                        Effect("select", "routing", terminal=discard, data={"routes": best}),
                    )
                )
        return out
