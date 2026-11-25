"""The trace orchestrator.

Applies the pipeline `Stage` ordering device by device, resolves source and
destination attachment, and fans `trace()` out over every source candidate
and every L3 domain the address resolves to.
"""

from __future__ import annotations

import contextlib
import contextvars
import copy
import functools
import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, NamedTuple, cast

import neo4j

import hst.path as _path
from hst.core import ipenc, zpa_policy
from hst.core.config import Settings
from hst.core.mtu import MtuRequest, MtuResult
from hst.core.reasoner import RT_IMPORTED_ROUTES
from hst.reasoner import GATEWAY_ROLES
from hst.results.trace import L2_PATH_NOT_FOUND, NO_ROUTE_DETAIL, leg_result, walk_result

from . import reply_nat, vsx, walk_memo
from .addrsets import (
    _MATCH,
    _UNKNOWN,
    _describe,
    _int_or_none,
    _intersect,
    _intervals,
    _lpm_all,
    _merge,
    _size,
    _subtract,
    _to_cidrs,
)
from .gates import Stage, _anchor_of, _Trail, unevaluated_gates
from .gates import sdwan as sdwan_gate
from .gates import zia as zia_gate
from .gates.aci import aci_contract_verdict
from .gates.coverage import policy_evidence
from .gates.firewall import (
    _UNGOVERNED_VIEW,
    FirewallTransition,
    _apply_egress_acl,
    _apply_firewall,
    _apply_firewall_reply,
    _as_portset,
    _as_protoset,
    _cap_candidate_regions,
    _device_filter_view,
    _firewall_verdict_local,
    _partial_permit,
    _refuse_ranged_query,
    _states_a_range,
    _unwrap_single,
    _zone_of,
    state_policy_text,
)
from .gates.lb import (
    _lb_segment_interfaces,
    _lb_snat,
    _member_names,
    _member_regions,
    _memo_read,
    _pool_members,
    _snat_mode_of,
    _vip_addresses,
    _vip_bindings,
    _vip_claims,
    _vip_claims_region,
    _vip_elsewhere,
    _vip_supported,
    _vs_label,
)
from .gates.lb import (
    reply_indeterminate_reason as _lb_reply_indeterminate_reason,
)
from .gates.nat import (
    _IFACE_ADDR_QUERY,
    _NAT_IFACE_ADDR_QUERY,
    NatTransition,
    _apply_snat,
    _checkpoint_manual,
    _iface_nat_role,
    _nat_partition,
    _nat_rows,
    _nat_stage_rules,
    _nat_step,
)
from .gates.pbr import _default_table_uid, _other_interface_pbr_policies, _pbr_partition, interface_table
from .gates.routing import (
    _NEXT_HOP_DOMAIN_QUERY,
    RoutingTransition,
    _connected_egress,
    _connected_prefixes,
    _fhrp_forwarding,
    _host_prefixes,
    _next_hop_adjacent,
    _next_hop_device,
    _no_route_leg,
    _route_partition,
)
from .gates.tunnel import _wireguard_regions
from .gates.zpa import (
    SegmentResolution,
    _access_rule_match,
    _choose_segment,
    _connector_address,
    _connector_names,
    _connector_selection,
    _forwarding_match,
    _identity_group,
    _rule_label,
    _segment_port_match,
    _segment_resolution,
    _segment_state,
)
from .mtu_topology import boundary as _mtu_boundary
from .mtu_topology import carrier_crossing, connection_scope, ensure_result, mtu_request, trace_scope
from .mtu_topology import crossing as _mtu_crossing
from .mtu_topology import not_capturing as _mtu_not_capturing
from .mtu_topology import unresolved_crossing as _mtu_unresolved_crossing
from .session import GatewayRows, prefix_index
from .state import FlowRegion, Ivals, Rect, port_spec
from .trace_draw import (
    _dev_label,
    _draw_arrival,
    _indeterminate_stop,
    _reply_not_derived,
    _warn_carried,
    _zpa_early_result,
    _zpa_stop,
)
from .verdict import DENY, INDETERMINATE, PERMIT, classify_action
from .walk import WalkContext

_SOURCE_QUERY = """
MATCH (ip:IpAddress:Obj {ip: $ip}) WHERE NOT ip:Retired AND ip.collection_ts = $snap
OPTIONAL MATCH (ep:Endpoint)-[hi:HAS_IP]->(ip)
WHERE NOT ep:Retired AND hi._retired_at IS NULL
OPTIONAL MATCH (ep)-[at:ATTACHED]->(att)
WHERE NOT att:Retired AND at._retired_at IS NULL
OPTIONAL MATCH (att:Port)-[aon:ON]->(sw:Device)
WHERE aon._retired_at IS NULL AND NOT sw:Retired
OPTIONAL MATCH (ep)-[ein:IN]->(seg)
WHERE (seg:BridgeDomain OR seg:L2Segment) AND ein._retired_at IS NULL AND NOT seg:Retired
RETURN ip.uid AS ip_uid, ip.l3dom AS l3dom, ip.anchor AS anchor, ep.uid AS ep_uid,
       coalesce(ep.name, ep.hostname, ep.mac) AS ep_name,
       att.uid AS att_uid, coalesce(att.name, att.hostname) AS att_name,
       att:Port AS att_is_port, at.ssid AS ssid,
       sw.uid AS sw_uid, sw.hostname AS sw_name, seg.uid AS seg_uid,
       COUNT { (o)-[h:HAS_IP]->(ip) WHERE NOT o:Retired AND h._retired_at IS NULL } > 0
       AS owned"""

# The broadcast domains of an interface. The query returns the domain that the
# VLAN binding of the interface realizes and the domain that the reasoner
# attaches the interface to (`ATTACHED_TO`). A routed port cabled to the native
# VLAN of a switch (basis `cable`) has its domain through `ATTACHED_TO`. The map
# draws segment gateways from the same attachment (diagram/segments.py).
_IFACE_SEGMENT_QUERY = """
MATCH (i:Interface:Obj {uid: $u, collection_ts: $snap})
OPTIONAL MATCH (i)-[b:BOUND_TO]->(v:VlanInstance)-[rz:REALIZES]->(bound)
WHERE (bound:BridgeDomain OR bound:L2Segment) AND b._retired_at IS NULL AND rz._retired_at IS NULL
  AND NOT v:Retired AND NOT bound:Retired
OPTIONAL MATCH (i)-[a:ATTACHED_TO]->(attached:BridgeDomain)
WHERE a._retired_at IS NULL AND NOT attached:Retired
WITH collect(DISTINCT bound) + collect(DISTINCT attached) AS held
UNWIND held AS s
WITH DISTINCT s
OPTIONAL MATCH (s)-[x:EXTENDS*..2]-(s2)
WHERE (s2:BridgeDomain OR s2:L2Segment) AND NOT s2:Retired
  AND all(r IN x WHERE r._retired_at IS NULL)
WITH collect(DISTINCT s.uid) + collect(DISTINCT s2.uid) AS uids
UNWIND uids AS uid
WITH DISTINCT uid WHERE uid IS NOT NULL
RETURN uid ORDER BY uid"""

# `_IFACE_SEGMENT_QUERY` for several interfaces in one read. The interfaces are
# the gateway candidates of a source. An anycast gateway has one candidate per
# leaf. The query reads the same two relations as `_IFACE_SEGMENT_QUERY`.
_IFACE_SEGMENTS_QUERY = """
UNWIND $us AS u
MATCH (i:Interface:Obj {uid: u, collection_ts: $snap})
OPTIONAL MATCH (i)-[b:BOUND_TO]->(v:VlanInstance)-[rz:REALIZES]->(bound)
WHERE (bound:BridgeDomain OR bound:L2Segment) AND b._retired_at IS NULL AND rz._retired_at IS NULL
  AND NOT v:Retired AND NOT bound:Retired
OPTIONAL MATCH (i)-[a:ATTACHED_TO]->(attached:BridgeDomain)
WHERE a._retired_at IS NULL AND NOT attached:Retired
WITH u, collect(DISTINCT bound) + collect(DISTINCT attached) AS held
UNWIND held AS s
WITH DISTINCT u, s
OPTIONAL MATCH (s)-[x:EXTENDS*..2]-(s2)
WHERE (s2:BridgeDomain OR s2:L2Segment) AND NOT s2:Retired
  AND all(r IN x WHERE r._retired_at IS NULL)
WITH u, collect(DISTINCT s.uid) + collect(DISTINCT s2.uid) AS uids
RETURN u, [uid IN uids WHERE uid IS NOT NULL] AS segs
ORDER BY u"""


def _iface_segments(session: Any, if_uids: Iterable[str]) -> dict[str, set[str]]:
    """The L2 segments of each interface (`_IFACE_SEGMENTS_QUERY`), read in one
    query. An interface with no segment maps to an empty set."""
    wanted = sorted(set(if_uids))
    out: dict[str, set[str]] = {u: set() for u in wanted}
    if wanted:
        for r in _path._read(session, _IFACE_SEGMENTS_QUERY, us=wanted):
            out.setdefault(r["u"], set()).update(r["segs"] or ())
    return out


_GATEWAY_FHRP_QUERY = """
MATCH (i:Interface)-[h:HAS_IP]->(ip:IpAddress)
WHERE i.uid IN $interfaces AND i:Obj AND i.collection_ts = $snap AND NOT i:Retired AND NOT ip:Retired
  AND h._retired_at IS NULL AND h.fhrp IN ['hsrp', 'vrrp']
  AND ip.collection_ts = $snap
OPTIONAL MATCH (i)-[m:MEMBER_OF]->(f:FhrpGroup)
WHERE NOT f:Retired AND m._retired_at IS NULL
  AND f.collection_ts = $snap
  AND f.vip = ip.ip AND f.kind = h.fhrp
RETURN DISTINCT i.uid AS if_uid, ip.ip AS vip, f.uid AS group_uid,
       h.fhrp AS fhrp, h.group AS fhrp_group, h.state AS fhrp_state
ORDER BY if_uid, vip, group_uid, fhrp_state"""

# The L2 fabric chain from `a` to `z`, cable by cable. It holds every uplink
# port and switch on the way. `_gateway_walk` and `_delivery_walk` use it.
# `native_bds` and `tagged_bds` hold the CARRIES carriage of each port by
# `native` true and false (unifi.py, vyos.py) for the frame ceiling of
# `_l2_tag_depth`. `bds` holds the combined list for the bridge-domain
# mismatch gate. `conn_source` is the `source` property of the CONNECTED_TO
# cable that reaches this node. `forked` is true when a neighbour not yet
# visited also reaches `z`.
#
# `shortestPath` raises when its start and end are the same node. A neighbour
# that is `z` has its own EXISTS branch.
#
# The two anchors seek on obj_uid_cts at the pinned run. The loader writes an
# edge only between two nodes of the same run (core/loader.py
# rel_upsert_query). Every path from the anchors stays inside that run.
#
# A node pattern cannot start from an indexed expression such as
# `nodes(p)[idx]`. `idx` is unwound into rows.
_L2_CHAIN_QUERY = """
MATCH (a:Obj {uid: $a, collection_ts: $snap}), (z:Obj {uid: $z, collection_ts: $snap})
MATCH p = allShortestPaths((a)-[:ON|CONNECTED_TO*..12]-(z))
WHERE all(n IN nodes(p) WHERE NOT n:Retired)
  AND all(r IN relationships(p) WHERE r._retired_at IS NULL)
  AND none(x IN nodes(p) WHERE x.uid = $avoid)
WITH p, z ORDER BY [n IN nodes(p) | n.uid] LIMIT 1
UNWIND range(1, size(nodes(p)) - 1) AS idx
WITH p, z, idx, nodes(p)[idx] AS n, nodes(p)[idx - 1] AS prevn,
     relationships(p)[idx - 1] AS rel_in,
     CASE WHEN idx < size(relationships(p)) THEN relationships(p)[idx] ELSE null END AS rel_out
WITH p, z, idx, {
    uid: n.uid, is_port: n:Port,
    label: coalesce(n.name, n.hostname),
    dev: head([(n)-[:ON]->(d:Device) | coalesce(d.hostname, d.uid)]),
    lag: head([(n)-[m:MEMBER_OF]->(l:Lag)
          WHERE NOT l:Retired AND m._retired_at IS NULL | l.uid]),
    native_bds: [(n)-[c:CARRIES {native: true}]->(v:VlanInstance)-[rz:REALIZES]->(bd)
          WHERE NOT bd:Retired AND NOT v:Retired AND c._retired_at IS NULL
            AND rz._retired_at IS NULL | bd.uid],
    tagged_bds: [(n)-[c2:CARRIES {native: false}]->(v2:VlanInstance)-[rz2:REALIZES]->(bd2)
          WHERE NOT bd2:Retired AND NOT v2:Retired AND c2._retired_at IS NULL
            AND rz2._retired_at IS NULL | bd2.uid],
    bds: [(n)-[c3:CARRIES]->(v3:VlanInstance)-[rz3:REALIZES]->(bd3)
          WHERE NOT bd3:Retired AND NOT v3:Retired AND c3._retired_at IS NULL
            AND rz3._retired_at IS NULL | bd3.uid] +
         [(n)<-[rb:REALIZED_BY]-(:Interface)-[sw:SWITCHES]->(v4:VlanInstance)-[rz4:REALIZES]->(bd4)
          WHERE NOT bd4:Retired AND NOT v4:Retired AND rb._retired_at IS NULL
            AND sw._retired_at IS NULL AND rz4._retired_at IS NULL | bd4.uid],
    conn_source: CASE
        WHEN type(rel_in) = 'CONNECTED_TO' THEN rel_in.source
        WHEN rel_out IS NOT NULL AND type(rel_out) = 'CONNECTED_TO' THEN rel_out.source
        WHEN rel_out IS NULL
             THEN head([(n)-[oc:CONNECTED_TO]-(:Port) WHERE oc._retired_at IS NULL | oc.source])
        ELSE null END,
    forked: EXISTS {
        MATCH (prevn)-[az:ON|CONNECTED_TO]-(alt)
        WHERE alt = z AND az._retired_at IS NULL AND alt.uid <> n.uid
          AND NOT alt.uid IN [vn IN nodes(p)[0..idx] | vn.uid]
    } OR EXISTS {
        MATCH (prevn)-[:ON|CONNECTED_TO]-(alt)
        WHERE alt <> z AND NOT alt:Retired AND alt.uid <> n.uid
          AND NOT alt.uid IN [vn IN nodes(p)[0..idx] | vn.uid]
        MATCH q = shortestPath((alt)-[:ON|CONNECTED_TO*..12]-(z))
        WHERE all(qn IN nodes(q) WHERE NOT qn:Retired AND NOT qn.uid IN [vn IN nodes(p)[0..idx] | vn.uid])
          AND all(qr IN relationships(q) WHERE qr._retired_at IS NULL)
    }
} AS hop
WITH idx, hop ORDER BY idx
RETURN collect(hop) AS chain"""

_DST_INSTANCES_QUERY = """
MATCH (ip:IpAddress:Obj) WHERE ip.ip = $ip AND NOT ip:Retired
  AND ip.collection_ts = $snap
RETURN ip.uid AS uid, ip.anchor AS anchor, ip.l3dom AS l3dom
ORDER BY ip.uid"""

# One subquery reads the routes of the table and the routes that it imports
# over route targets. The ORDER BY after the subquery orders every row. After a
# bare UNION, a trailing ORDER BY belongs to the last branch alone. The rows of
# one prefix, with the members of an equal-cost route, have the same order on
# every read.
_ROUTES_QUERY = (
    """
CALL {
MATCH (v:VrfInstance {uid: $vrf})-[r:STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES]->(p:Prefix)
WHERE NOT p:Retired AND r._retired_at IS NULL AND v:Obj AND v.collection_ts = $snap
// A BGP `network` statement installs nothing: it advertises a route the
// table already holds, and that route (connected, static or from the RIB) is
// its own row here.
  AND NOT (type(r) = 'ORIGINATES' AND coalesce(r.proto, '') = 'network')
OPTIONAL MATCH (p)-[via:VIA {vrf: $vrf}]->(egress:Interface)
// pair each route edge with its own egress, so an N-way ECMP prefix gives N
// candidate legs. A route that declares no interface pairs with none of them:
// the comparison is NULL for every candidate, the OPTIONAL MATCH yields a NULL
// egress and the route is resolved by its next hop.
// `rib_interface` is the egress a collector read from the device's own RIB
// for a route whose config form declares only a next hop (collectors/vyos.py
// `_confirm_static_route`), or the interface a VyOS `next-hop X interface Y`
// form states (`_static_routes`). It is the route's own stated egress, held
// under a second property name because `interface` is a relationship key.
WHERE via._retired_at IS NULL AND NOT egress:Retired
  AND egress.name = coalesce(r.interface, r.rib_interface)
// A BGP aggregate is the discard route the device installs for the summary
// (Null0 on IOS and NX-OS, blackhole on FRR). Its own kind keeps it out of
// every reader that takes ORIGINATES as connected, and `_route_provenance`
// lets any other route for the same prefix win over it.
WITH p, r, egress, type(r) = 'ORIGINATES' AND coalesce(r.proto, '') = 'aggregate' AS is_aggregate
RETURN DISTINCT p.uid AS uid, p.cidr AS cidr,
       CASE WHEN is_aggregate THEN 'AGGREGATE' ELSE type(r) END AS kind,
       r.next_hop AS next_hop, coalesce(r.interface, r.rib_interface) AS ifname,
       egress.uid AS egress_uid, egress.name AS egress_name,
       r.derived AS derived, r.via_rt AS via_rt, r.rib_confirmed AS rib,
       r.next_hop_vrf AS next_hop_vrf,
       CASE WHEN is_aggregate THEN 'blackhole' ELSE r.discard END AS discard
UNION
// The routes the table receives over route targets, resolved here for this one
// table (core/reasoner.py RT_IMPORTED_ROUTES). Inferred from config: no next hop, no
// egress, no RIB confirmation.
MATCH (v:VrfInstance {uid: $vrf})
WHERE v:Obj AND v.collection_ts = $snap
"""
    + RT_IMPORTED_ROUTES
    + """RETURN p.uid AS uid, p.cidr AS cidr, 'LEARNED_ROUTE' AS kind,
       null AS next_hop, null AS ifname, null AS egress_uid, null AS egress_name,
       'rt-import' AS derived, via_rt, null AS rib, null AS next_hop_vrf, null AS discard
}
RETURN uid, cidr, kind, next_hop, ifname, egress_uid, egress_name, derived, via_rt, rib,
       next_hop_vrf, discard
ORDER BY cidr, kind, next_hop, egress_uid, ifname, next_hop_vrf, derived, via_rt, rib, discard, uid
"""
)

# Every address the device itself answers for, in the traced routing table. An
# interface with no IN_VRF edge is kept.
_OWN_ADDRS_QUERY = """
CALL {
  MATCH (dev:Device:Obj {uid: $dev, collection_ts: $snap})<-[o:ON]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)
  WHERE dev:Obj AND dev.collection_ts = $snap
    AND o._retired_at IS NULL AND h._retired_at IS NULL AND NOT i:Retired AND NOT ip:Retired
  RETURN i, ip
  UNION
  // an SD-WAN link's address after NAT: the device answers for it through the
  // NAT in front of it, on the interface the link leaves by
  MATCH (dev:Device:Obj {uid: $dev, collection_ts: $snap})-[hl:HAS_LINK]->(w:WanLink)
        -[lh:HAS_IP]->(ip:IpAddress)
  MATCH (w)-[won:ON]->(i:Interface)
  WHERE dev:Obj AND dev.collection_ts = $snap
    AND hl._retired_at IS NULL AND lh._retired_at IS NULL AND won._retired_at IS NULL
    AND NOT w:Retired AND NOT i:Retired AND NOT ip:Retired
  RETURN i, ip
}
WITH i, ip
WHERE ip.collection_ts = $snap
  AND ($vrf IS NULL
       OR EXISTS { MATCH (i)-[iv:IN_VRF]->(:VrfInstance {uid: $vrf}) WHERE iv._retired_at IS NULL }
       OR NOT EXISTS { MATCH (i)-[iv2:IN_VRF]->(:VrfInstance) WHERE iv2._retired_at IS NULL })
RETURN ip.ip AS ip, ip.uid AS ip_uid, i.uid AS if_uid, i.name AS if_name
ORDER BY ip.ip, i.uid"""

_IFACE_BY_NAME_QUERY = """
MATCH (i:Interface {name: $name})-[o:ON]->(d:Device {uid: $dev})
WHERE d:Obj AND d.collection_ts = $snap
  AND NOT i:Retired AND o._retired_at IS NULL AND i.collection_ts = $snap
  AND ($vrf IS NULL OR EXISTS {
    MATCH (i)-[iv:IN_VRF]->(:VrfInstance {uid: $vrf}) WHERE iv._retired_at IS NULL
  })
WITH collect({uid: i.uid, name: i.name}) AS candidates
WHERE size(candidates) = 1
RETURN candidates[0].uid AS uid, candidates[0].name AS name"""

_CARRIER_TUNNEL_QUERY = """
MATCH (t:Tunnel {uid: $uid})
WHERE t:Obj AND t.collection_ts = $snap
// every far end of the tunnel, counted once each, with a sample of up to 5 in
// uid order: more than one far end on a tunnel that does not end on a ZIA
// data center is several tunnels written onto one node, which the trace warns about
OPTIONAL MATCH (t)-[fr:TERMINATES_ON]->(f)
WHERE fr._retired_at IS NULL AND NOT f:Retired AND f.collection_ts = $snap
WITH t, f ORDER BY f.uid
WITH t, collect(DISTINCT f) AS fars
WITH t, size(fars) AS far_ends, [x IN fars | coalesce(x.ip, x.name, x.uid)][..5] AS far_sample
// the far end carries the retirement and snapshot guards of every other
// relationship read in this file. `ORDER BY` makes the pick deterministic
// when a tunnel has more than one far end, as a ZIA GRE tunnel with a primary
// and a secondary VIP has.
OPTIONAL MATCH (t)-[tr:TERMINATES_ON]->(far)
WHERE tr._retired_at IS NULL AND NOT far:Retired
  AND far.collection_ts = $snap
RETURN t.endpoint AS endpoint, t.endpoint_port AS endpoint_port,
       coalesce(t.carrier_proto, 'udp') AS carrier_proto, t.local_address AS local_address,
       t.encap AS encap, t.pair AS pair, far.ip AS far_ip, far.uid AS far_uid, far.name AS far_name,
       tr.role AS far_role, tr.vip AS far_vip,
       t.tunnel_mtu AS tunnel_mtu, t.gre_key AS gre_key, t.gre_checksum AS gre_checksum,
       t.gre_sequence AS gre_sequence, t.esp_encryption AS esp_encryption, t.esp_hash AS esp_hash,
       t.esp_mode AS esp_mode, t.esp_proposals AS esp_proposals,
       CASE WHEN far:ZscalerDc THEN 'ZscalerDc'
            WHEN far:SdwanGateway THEN 'SdwanGateway'
            WHEN far:IpAddress THEN 'IpAddress'
            ELSE NULL END AS far_kind,
       far_ends, far_sample
ORDER BY CASE tr.role WHEN 'primary' THEN 0 WHEN 'secondary' THEN 1 ELSE 2 END, far.uid LIMIT 1"""

_LOCAL_VRF_QUERY = """
MATCH (dev:Device {uid: $dev})<-[o:ON]-(:Interface)-[iv:IN_VRF]->(v:VrfInstance)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND o._retired_at IS NULL AND iv._retired_at IS NULL AND NOT v:Retired AND v.is_global = true
  AND v.collection_ts = $snap
RETURN v.uid AS vrf_uid, v.name AS vrf_name ORDER BY v.uid LIMIT 1"""

# --- header space: a leg's service range -----------------------------------------------
#
# `port`/`proto` reach every stage below as the query's own spec (a scalar, a
# range string or a list) and are parsed only where a stage needs a concrete set.

# Display names for the IANA numbers `_service_regions`/`_first_match_regions`
# decide on. A number with no name here shows as the number itself.
_PROTO_DISPLAY_NAME: dict[int, str] = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp"}
# every protocol number, the set "any" and "all" resolve to
_ALL_PROTO_NUMBERS: frozenset[int] = frozenset(range(256))


def _proto_display_names(subset: frozenset[int] | None) -> list[str]:
    """A decided protocol region as the names a leg's `service` field shows."""
    if not subset:
        return []
    return sorted(_PROTO_DISPLAY_NAME.get(n, str(n)) for n in subset)


def _port_pairs(ivals: list[tuple[int, int, int]] | None) -> list[list[int]]:
    """A decided port region as the `[lo, hi]` pairs a leg's `service` field shows."""
    if not ivals:
        return []
    return [[lo, hi] for _, lo, hi in ivals]


def _port_ivals_spec(ivals: list[tuple[int, int, int]] | None) -> int | str | None:
    """A decided port region as the value `_ports`/`_as_portset` and the point
    matchers read back unchanged.

    One port comes back as an `int`, and a wider region as a spec string.
    """
    if not ivals:
        return None
    if len(ivals) == 1 and ivals[0][1] == ivals[0][2]:
        return ivals[0][1]
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for _, lo, hi in ivals)


def _region_port_spec(ivals: list[tuple[int, int, int]] | None, fallback: Any) -> Any:
    """The port spec of one decided port rectangle for the rest of the walk.
    The result is `fallback`, the value of the query, where the gate stated no
    rectangle."""
    return fallback if ivals is None else _port_ivals_spec(ivals)


def _scalarize_for_legacy(value: Any) -> Any:
    """A protocol value for the gates without region support: a scalar, or
    `None` for a decided protocol set."""
    return None if isinstance(value, list | set | frozenset) else value


def _scalarize_port_for_legacy(value: Any) -> Any:
    """A port value for the gates without region support. A range string or a
    set gives `None`. A digit string gives its integer.
    """
    if isinstance(value, list | set | frozenset):
        return None
    if isinstance(value, str):
        spec = value.strip()
        if _states_a_range(spec, None):
            return None
        if spec.isdigit():
            return int(spec)
    return value


def _region_service(fw: dict[str, Any] | None, port: Any, proto: Any, sport: Any = None) -> dict[str, Any]:
    """The `service` field of one region leg. It is the (proto, port) rectangle
    that the rulebase decided when `fw` is set, and the full range of the query
    when `fw` is None. The field has `src_ports` only when the query states a
    source port (`sport`, a spec) or the region decided a source-port slice."""
    if fw is not None:
        proto_subset, port_subset = fw.get("proto_subset"), fw.get("port_subset")
    else:
        proto_subset, _ = _as_protoset(proto)
        port_subset, _ = _as_portset(port)
    service = {"proto": _proto_display_names(proto_subset), "ports": _port_pairs(port_subset)}
    sport_subset = fw["sport_subset"] if fw is not None and "sport_subset" in fw else _as_portset(sport)[0]
    if sport_subset is not None:
        service["src_ports"] = _port_pairs(sport_subset)
    return service


def _region_continuation(fw: dict[str, Any] | None, port: Any, proto: Any) -> tuple[Any, Any]:
    """The port and the protocol of the flow of one region after the gate that
    decided it. Each is the range that the rulebase narrowed when it decided
    one, and the value of the query otherwise."""
    if fw is None:
        return port, proto
    proto_subset, port_subset = fw.get("proto_subset"), fw.get("port_subset")
    cont_proto = proto if proto_subset is None else proto_subset
    cont_port = _region_port_spec(port_subset, port)
    return cont_port, cont_proto


def _region_sport(fw: dict[str, Any] | None, sport: Any) -> Any:
    """The source port of the flow of one region after the gate. It is the
    slice that the region decided where the rulebase partitioned on the source
    port, and the value of the query otherwise. No gate translates a source
    port."""
    if fw is None or "sport_subset" not in fw:
        return sport
    return _region_port_spec(fw["sport_subset"], sport)


def _query_region(
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: Any,
    proto: Any,
    sport: Any,
) -> FlowRegion:
    """The `FlowRegion` of the specs of a flow. Every dimension is parsed as
    the gates parse it. A dimension that the query does not state is `None`."""
    return FlowRegion.from_query(
        src_set,
        dst_set,
        _as_protoset(_unwrap_single(proto))[0],
        _as_portset(_unwrap_single(port))[0],
        _as_portset(_unwrap_single(sport))[0],
    )


def _states_a_region(port: Any, proto: Any, sport: Any) -> bool:
    """Whether a query is walked as a region. A query is a region when it
    states a port range, a protocol range or a source port."""
    return _states_a_range(_unwrap_single(port), _unwrap_single(proto)) or sport is not None


def _narrow_region(region: FlowRegion, **dims: Any) -> FlowRegion:
    """Every rectangle of a region narrowed to the same dimensions."""
    return region.map(lambda r: r.narrow(**dims))


def _ivals_of(spec: Any) -> Ivals | None:
    ivals, _ = _as_portset(_unwrap_single(spec))
    return None if ivals is None else tuple(ivals)


def _apply_filter_state(leg: dict[str, Any], state: dict[str, Any]) -> None:
    """Copies the leg fields of one `_filter_dst` read onto a region leg.

    The ranged path reads the filter view of the packet once per route part,
    before any region leg exists. The read writes to the stand-in dict
    `state`. This function copies `indeterminate` and `filter_view` from
    `state` onto each leg of the partition. `_filter_dst` sets `indeterminate`
    where the vendor view or the original destination could not be derived.
    The warning of the read is on the trail once per route part.
    """
    if state.get("indeterminate"):
        leg["indeterminate"] = True
    if state.get("filter_view"):
        _record_filter_view(leg, state["filter_view"])


def _region_in_flow_terms(
    trail: _Trail,
    leg: dict[str, Any],
    fw: dict[str, Any] | None,
    fw_port: Any,
    port: Any,
    src_label: str,
) -> dict[str, Any] | None:
    """One decided region in the ports of the flow after the destination NAT of
    this device.

    Where the destination NAT of this device changed the ports, a region that
    covers the whole filtered range becomes the translated range. A narrower
    region is widened to the translated range and reported indeterminate.
    """
    if fw is None or fw.get("port_subset") is None or fw_port == port:
        return fw
    if fw["port_subset"] != _as_portset(fw_port)[0]:
        leg["indeterminate"] = True
        trail.warn(
            f"{src_label}: this device matches its filter on the packet as it arrived and "
            f"its own destination NAT rewrote the port, so the part of {_spec_label(fw_port)} "
            f"this rule decided could not be restated in the ports the flow leaves with; the "
            f"whole of {_spec_label(port)} is carried on"
        )
    return {**fw, "port_subset": _as_portset(port)[0]}


def _spend_region_budget(trail: _Trail, regions: list[dict[str, Any] | None]) -> list[dict[str, Any] | None]:
    """Applies the region budget of the whole trace.

    `firewall._cap_regions` bounds the regions of one rulebase sweep and
    `_cap_candidate_regions` bounds the fold of one device. When the total of
    the trail reaches `path_region_cap`, every further partition is cut to the
    regions that are left. The surplus of the partition is one indeterminate
    region.
    """
    if not any(r is not None for r in regions):
        trail.regions_spent += len(regions)
        return regions
    cap = Settings().path_region_cap
    remaining = max(cap - trail.regions_spent, 1)
    if len(regions) > remaining:
        regions = cast(
            "list[dict[str, Any] | None]",
            _cap_candidate_regions([r for r in regions if r is not None], remaining, reason_cap=cap),
        )
    trail.regions_spent += len(regions)
    return regions


def _apply_firewall_region(
    trail: _Trail,
    leg: dict[str, Any],
    fw: dict[str, Any],
    src_label: str,
    via: str,
) -> str | None:
    """Writes the hops, the notes and the leg fields of one region that the
    rulebase walk of a ranged query decided.

    The function does the verdict half of `_apply_firewall` once per region
    (the hops, the leg fields `firewall`, `blocked` and `indeterminate`, the
    rule-skip notes and the global state-policy notes). `fw` is one entry that
    `_firewall_region_list` returned.

    A region with no `rb_uid` and no `rb_name` is the surplus of a spent
    region budget. Its leg is a truncated partition. A region with a name but
    no uid is the default action of a zone policy (a pair bound for the other
    address family only). It is handled as on the point path.
    """
    if fw["rb_uid"] is None and fw.get("rb_name") is None:
        cap = Settings().path_region_cap
        leg["firewall"] = f"partition truncated at the path_region_cap setting ({cap} regions)"
        leg["indeterminate"] = True
        nh = leg.get("next_hop")
        via_label = f"{via} → {nh}" if nh and via and nh != via else (via or nh or "?")
        trail.notes.append(f"{src_label} via {via_label}: {leg['firewall']}")
        reason = fw.get("indeterminate_reason")
        trail.warn(f"{src_label}: {leg['firewall']}" + (f": {reason}" if reason else ""))
        return INDETERMINATE
    trail.hop(
        fw["rb_uid"],
        "FwRulebase",
        fw["rb_name"],
        f"{fw['zones']} · {fw['action']} ({fw['by']})",
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
    by = f"rule {fw['pos']}" if fw["pos"] is not None else "default-action"
    leg["firewall"] = f"{fw['rb_name']} ({fw['zones']}) {fw['action']} by {by}"
    leg["fw_uid"] = fw["rb_uid"]
    if fw.get("partial"):
        leg["firewall"] += " (matches part of the range only)"
        trail.warn(
            f"{src_label}: {fw['rb_name']} {by} covers only part of the flow; narrow the query for a verdict"
        )
    nh = leg.get("next_hop")
    via_label = f"{via} → {nh}" if nh and via and nh != via else (via or nh or "?")
    trail.notes.append(f"{src_label} via {via_label}: {leg['firewall']}")
    for skip in fw.get("state_skips") or []:
        trail.notes.append(
            f"{src_label}: rule {skip['pos']} is scoped to connection state "
            f"{'/'.join(skip['states'])}; this trace models a new connection, so the rule "
            "does not govern it and evaluation continued to the next rule"
        )
    policy = fw.get("global_state_policy")
    if policy:
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
    return _partial_permit(leg, fw, outcome, by)


def _record_region_gate_state(
    leg: dict[str, Any],
    gw: dict[str, Any],
    fw: dict[str, Any] | None,
    outcome: str | None,
    considered: list[str],
) -> None:
    """Record the forward crossing of this device by one region leg, in the
    shape that `_apply_firewall` records on the point path. The record holds
    the state policy, whether the region was a permit with no undecided rule,
    and the rulebases that the read evaluated or ruled out."""
    if fw is None:
        # No rulebase governed the hop. The hop is a pass, except for a virtual
        # system or a bridge whose policy was not established (`_apply_firewall`).
        policy, permit = None, gw.get("vsx_kind") not in {"virtual-system", "bridge"}
    else:
        policy, permit = fw.get("global_state_policy"), outcome == PERMIT and not leg.get("indeterminate")
    models = (fw.get("models") or [fw]) if fw else []
    leg["gate_state"] = {
        **leg.get("gate_state", {}),
        _forwarding_visit(gw): {
            "policy": policy,
            "permit": permit,
            "credits": sorted({*considered, *(m["rb_uid"] for m in models if m.get("rb_uid"))}),
        },
    }


def _firewall_region_list(
    session: Any,
    gw: dict[str, Any],
    out_if: str | None,
    region: FlowRegion,
) -> tuple[list[dict[str, Any] | None], list[str]]:
    """The regions that the firewall decided for a leg walked as a region.

    A rulebase that governs the device gives one region dict per outcome of
    its rules. A `None` entry stands for a region that no rulebase governs.
    """
    # The inbound interface ACL is evaluated here. The outbound interface ACL
    # is evaluated after source NAT (`_apply_egress_acl`).
    gate = FirewallTransition(session, gw["dev_uid"], gw["if_uid"], out_if, acl_direction="in")
    results = gate.apply(region)
    regions: list[dict[str, Any] | None] = [
        None if effect.kind == "pass" else dict(effect.data) for _reg, effect in results
    ]
    if not regions:
        raise ValueError("the filter stage answered a region with no regions at all")
    return regions, gate.considered


def _spec_label(value: Any) -> str:
    """A port or protocol value of the query as a label for the verdict string
    of the flow. A list is joined with commas.

    A protocol range is the set of its numbers here. The label has the
    protocol names, and the whole range 0..255 has the label "any".
    """
    if isinstance(value, set | frozenset):
        if not value:
            return ""
        if all(isinstance(v, int) for v in value):
            return "any" if value == _ALL_PROTO_NUMBERS else ",".join(_proto_display_names(frozenset(value)))
        return ",".join(sorted(str(v) for v in value))
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


# --- the trace --------------------------------------------------------------------------


def _source_candidates(session: Any, probe: str) -> list[dict[str, Any]]:
    """One source row per forwarding context (or segment) that holds this address.

    An address is unique only within its context (uid `ip:{anchor}:{addr}`).
    The same probe can resolve in more than one context. The rows are grouped
    on `anchor` (see `_anchor_of`). Within a context the first row in uid order
    (address, endpoint, attachment, segment) stands for the endpoint.

    A row with `owned` false has no live HAS_IP from an endpoint or an
    interface. Such rows are used only when no row is owned.
    """
    rows = _path._read(session, _SOURCE_QUERY, ip=probe)
    if any(r.get("owned") for r in rows):
        rows = [r for r in rows if r.get("owned")]
    by_anchor: dict[Any, dict[str, Any]] = {}
    for row in sorted(
        rows,
        key=lambda r: (r["ip_uid"] or "", r["ep_uid"] or "", r.get("att_uid") or "", r.get("seg_uid") or ""),
    ):
        by_anchor.setdefault(_anchor_of(row), row)
    return [by_anchor[a] for a in sorted(by_anchor, key=lambda a: a or "")]


def _source_attachment(trail: _Trail, src: dict[str, Any] | None, src_ip: str) -> str | None:
    """Hops for the source endpoint and its physical attachment.

    Returns the device whose fabric position anchors the L2 walk.
    """
    attach = None
    _mtu_crossing(trail, src.get("ep_uid") if src else None, enforcement="source")
    if src and src["ep_uid"]:
        trail.hop(
            src["ep_uid"], "Endpoint", src["ep_name"] or src_ip, f"src {src_ip}", stage=Stage.SRC_ENDPOINT
        )
    if src and src["att_uid"]:
        if src["att_is_port"]:
            _mtu_crossing(trail, src["att_uid"], enforcement="l2", direction="rx")
            trail.hop(
                src["att_uid"],
                "Port",
                src["att_name"] or "port",
                f"on {src['sw_name'] or '?'}",
                stage=Stage.SRC_ATTACH,
            )
            if src["sw_uid"]:
                trail.hop(src["sw_uid"], "Device", src["sw_name"] or "switch", stage=Stage.SRC_ATTACH)
            attach = src["sw_uid"]
        else:
            # A wireless client associates with the AP device.
            trail.hop(
                src["att_uid"],
                "Device",
                src["att_name"] or "ap",
                f"via {src['ssid']}" if src["ssid"] else "wireless",
                stage=Stage.SRC_ATTACH,
            )
            attach = src["att_uid"]
    if src and src["seg_uid"]:
        trail.notes.append(f"src segment: {src['seg_uid']}")
    return attach


def _containing(gateways: list[dict[str, Any]], probe: str) -> list[dict[str, Any]]:
    """The gateway rows whose prefix contains the probe address, at any length,
    in the order of `gateways`. The function does one lookup per prefix length
    in the prefix index of the rows (`session.GatewayRows`). A plain list is
    indexed for the call."""
    try:
        addr = ipaddress.ip_address(probe)
    except ValueError:
        return []
    index = gateways.prefix_index() if isinstance(gateways, GatewayRows) else prefix_index(gateways)
    bits, value = addr.max_prefixlen, int(addr)
    positions: list[int] = []
    for length in range(bits + 1):
        positions += index.get((addr.version, length, value >> (bits - length) << (bits - length)), ())
    return [gateways[pos] for pos in sorted(positions)]


def _segment_tie(
    session: Any, containing: list[dict[str, Any]], seg_uid: str, probe: str, notes: list[str]
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Narrow the gateway prefixes containing the probe to the ones whose
    interface realizes the bridge domain of the source.

    `seg_uid` of the source row is the BridgeDomain that its endpoint is IN.
    The domains of a gateway interface, with those reached over EXTENDS, come
    from `_IFACE_SEGMENTS_QUERY`.

    Returns (candidates, unknown). A gateway on the segment of the source is a
    candidate, and the others are set aside with a note. When every interface
    that recorded its domains serves other segments, the pick is unknown and
    `unknown` holds the marker that the caller returns. When no interface
    recorded a domain, all candidates stay and a note is added.
    """
    segs_by_if = _iface_segments(session, (g["if_uid"] for g in containing))
    on_segment = [g for g in containing if seg_uid in segs_by_if[g["if_uid"]]]
    checked = [g for g in containing if segs_by_if[g["if_uid"]]]
    if on_segment:
        # One note lists the interfaces that realize other domains than the
        # domain of the source. Another note lists the interfaces that
        # recorded no domain.
        for what, aside in (
            ("realize other bridge domains than", [g for g in checked if g not in on_segment]),
            ("record no bridge domain to tie to", [g for g in containing if g not in checked]),
        ):
            if aside:
                names = sorted(
                    f"{g['if_name'] or g['if_uid']} on {g['dev_name'] or g['dev_uid']}" for g in aside
                )
                notes.append(
                    f"{len(names)} gateway interface(s) serving {probe} {what} the source's "
                    f"{seg_uid} ({', '.join(names)}); not candidates"
                )
        return on_segment, None
    if checked:
        served = sorted(
            f"{g['if_name'] or g['if_uid']} on {g['dev_name'] or g['dev_uid']} "
            f"({', '.join(sorted(segs_by_if[g['if_uid']]))})"
            for g in checked
        )
        return [], {
            "unknown": True,
            "reason": (
                f"the gateway prefixes containing {probe} are served on other bridge domains than "
                f"the source's {seg_uid}: {'; '.join(served)}; nothing links the source's segment "
                "to a gateway"
            ),
        }
    notes.append(
        f"no gateway interface serving {probe} records its bridge domain; "
        f"the source segment {seg_uid} was not checked against the gateway"
    )
    return containing, None


def _fhrp_gateway(
    session: Any, containing: list[dict[str, Any]], probe: str, trail: _Trail
) -> dict[str, Any] | None:
    """Resolve an unscoped first hop using one recorded redundancy group.

    A shared display label or group number alone is not membership evidence.
    Every candidate must participate in the same recorded group/VIP on the
    same prefix, with no contradictory segment evidence. An explicitly
    selected forwarding context bypasses this inference in `_pick_gateway`.
    """
    if not containing:
        return None
    interfaces = sorted({g["if_uid"] for g in containing})
    rows = _path._read(session, _GATEWAY_FHRP_QUERY, interfaces=interfaces)
    members = []
    for row in rows:
        try:
            vip = ipaddress.ip_address(row["vip"])
        except (ValueError, KeyError, TypeError):
            continue
        if any(
            g["if_uid"] == row["if_uid"] and vip in ipaddress.ip_network(g["cidr"], strict=False)
            for g in containing
        ):
            members.append(row)
    if not members:
        return None

    routers = ", ".join(sorted({g.get("dev_name") or g["dev_uid"] for g in containing}))

    def unknown(reason: str) -> dict[str, Any]:
        return {"unknown": True, "reason": f"first-hop redundancy for {probe} on {routers}: {reason}"}

    if {r["if_uid"] for r in members} != set(interfaces):
        return unknown("not every gateway candidate has recorded membership in the redundancy group")
    groups = {(r.get("group_uid"), r["fhrp"], r.get("fhrp_group"), r["vip"]) for r in members}
    if len(groups) != 1:
        return unknown(
            "multiple redundancy groups or virtual IPs match; the source gateway is not established"
        )
    group_uid, kind, group, vip_text = next(iter(groups))
    if group_uid is None or group is None:
        return unknown("redundancy group membership is incomplete")
    if len({g["cidr"] for g in containing}) != 1:
        return unknown("gateway candidates disagree on the source prefix")

    # The identity of an FhrpGroup includes a declared scope and VIP. Isolated
    # segments can reuse a scope. The pick is unknown when the recorded L2
    # segments of the members have no common segment. The segment query
    # includes EXTENDS.
    by_iface = _iface_segments(session, interfaces)
    segments = [by_iface[iface] for iface in interfaces]
    known_segments = [s for s in segments if s]
    if known_segments and not set.intersection(*known_segments):
        return unknown("group members serve different recorded L2 segments with no shared segment")

    states: dict[str, set[str]] = {}
    for member in members:
        states.setdefault(member["if_uid"], set()).add(str(member.get("fhrp_state") or "").lower())
    if any(len(s) != 1 or s & {"", "unknown"} for s in states.values()):
        return unknown(f"{kind.upper()} group {group} VIP {vip_text} has missing or conflicting member state")
    active = {r["if_uid"] for r in members if _fhrp_forwarding(r)}
    role = "active" if kind == "hsrp" else "master"
    if len(active) != 1:
        return unknown(
            f"{kind.upper()} group {group} VIP {vip_text} has {len(active)} {role} members recorded"
        )
    winners = [g for g in containing if g["if_uid"] in active]
    if len({_anchor_of(g) for g in winners}) != 1:
        return unknown("the forwarding member belongs to multiple gateway contexts")
    winner = sorted(winners, key=lambda g: (g["dev_uid"], g["if_uid"]))[0]
    trail.notes.append(
        f"source gateway selected by {kind.upper()} group {group} VIP {vip_text}: "
        f"{role} member {winner.get('dev_name') or winner['dev_uid']} on {winner['if_name']}; "
        "using the recorded snapshot state"
    )
    return winner


def _gateway_contexts(
    session: Any,
    containing: list[dict[str, Any]],
    anchors: list[Any],
    dom_by_anchor: dict[Any, list[str]],
) -> list[dict[str, Any]]:
    """One entry per context of a gateway ambiguity, labeled by its VRF name and
    the devices that hold its gateway prefixes. Contexts on different devices
    can share one `l3dom` display string, and then only the VRF and the device
    tell them apart in the message."""
    devices: dict[Any, set[str]] = {}
    for g in containing:
        devices.setdefault(_anchor_of(g), set()).add(str(g.get("dev_name") or g.get("dev_uid") or "?"))
    contexts = []
    for anchor in anchors:
        vrf = _vrf_name(session, anchor) if isinstance(anchor, str) else None
        name = f"VRF {vrf}" if vrf else sorted(dom_by_anchor[anchor])[0]
        where = ", ".join(sorted(devices.get(anchor, ())))
        contexts.append({"anchor": anchor, "label": f"{name} on {where}" if where else name})
    return contexts


# The addresses each gateway interface holds, for `_anycast_gateway`.
_GATEWAY_ADDRESSES_QUERY = """
UNWIND $interfaces AS iu
MATCH (i:Interface:Obj {uid: iu, collection_ts: $snap})-[h:HAS_IP]->(ip:IpAddress)
WHERE h._retired_at IS NULL AND NOT i:Retired AND NOT ip:Retired AND ip.collection_ts = $snap
RETURN i.uid AS if_uid, collect(DISTINCT ip.ip) AS addresses
ORDER BY if_uid"""


def _anycast_gateway(
    session: Any,
    containing: list[dict[str, Any]],
    anchors: list[Any],
    attach: str | None,
    probe: str,
) -> tuple[list[dict[str, Any]], str] | None:
    """The gateway rows of a distributed anycast gateway that serve this
    source and the note for the choice, or None when the contexts stay
    ambiguous.

    An EVPN fabric serves one subnet on every leaf, each leaf in its own
    VrfInstance. They are one gateway only when every candidate serves the
    same prefix with a common gateway address and every context shares a
    declared RoutingDomain with the others. The leaf the source attaches to,
    or else the leaf nearest the attachment by cable path, serves it. Without
    an attachment, or with two candidates at the same distance, the result is
    None.
    """
    if not attach or len({g["cidr"] for g in containing}) != 1:
        return None
    try:
        net = ipaddress.ip_network(containing[0]["cidr"], strict=False)
    except ValueError:
        return None
    rows = _path._read(
        session, _GATEWAY_ADDRESSES_QUERY, interfaces=sorted({g["if_uid"] for g in containing})
    )
    held: dict[str, set[str]] = {}
    for row in rows:
        inside = set()
        for a in row.get("addresses") or ():
            try:
                if ipaddress.ip_address(a) in net:
                    inside.add(a)
            except ValueError:
                continue
        held[row["if_uid"]] = inside
    if any(g["if_uid"] not in held for g in containing):
        return None
    shared = set.intersection(*(held[g["if_uid"]] for g in containing))
    if not shared:
        return None
    first, rest = anchors[0], [a for a in anchors[1:] if isinstance(a, str)]
    if len(rest) != len(anchors) - 1 or not isinstance(first, str):
        return None
    mates = {m["uid"] for m in _path._read(session, _NEXT_HOP_DOMAIN_QUERY, table=first, anchors=rest)}
    if set(rest) - mates:
        return None
    vip = sorted(shared)[0]
    local = [g for g in containing if g["dev_uid"] == attach]
    basis = "the device the source attaches to"
    if not local:
        distance: dict[str, int] = {}
        for dev in sorted({g["dev_uid"] for g in containing}):
            chain = _path._read_one(session, _L2_CHAIN_QUERY, a=attach, z=dev, avoid="")
            nodes = list(chain["chain"]) if chain and chain["chain"] else []
            if nodes:
                distance[dev] = len(nodes)
        if not distance:
            return None
        nearest = min(distance.values())
        closest = [d for d, n in distance.items() if n == nearest]
        if len(closest) != 1:
            return None
        local = [g for g in containing if g["dev_uid"] == closest[0]]
        basis = "the one nearest the source's attachment by cable path"
    if len({_anchor_of(g) for g in local}) != 1:
        return None
    dev = local[0].get("dev_name") or local[0]["dev_uid"]
    return local, (
        f"gateway {vip} for {probe} is a distributed anycast gateway on {len(anchors)} devices in one "
        f"routing domain; traced via {dev} {local[0]['if_name']}, {basis}"
    )


def _pick_gateway(
    gateways: list[dict[str, Any]],
    probe: str,
    domain: str | None,
    trail: _Trail,
    *,
    session: Any,
    seg_uid: str | None = None,
    attach: str | None = None,
) -> dict[str, Any] | None:
    """LPM over the gateway candidates of the context being traced.

    `attach` is the device the source attaches to (`_source_attachment`).
    When more than one context holds the probe, `attach` resolves a
    distributed anycast gateway (`_anycast_gateway`).

    An unscoped first hop uses the unique forwarding member of a recorded FHRP
    group before the test for context ambiguity. Other ties in one context go
    to the lowest dev_uid, and a warning lists the tied devices.

    `seg_uid` is the bridge domain of the source. The candidates are first
    narrowed to the gateways whose interface realizes it (`_segment_tie`). A
    source with no segment picks on prefixes alone.

    `domain` is an anchor key (see `_anchor_of`). An unscoped call (domain
    None) scopes the trace to the anchor of the prefixes that contain the
    probe when they all have one anchor. When more than one anchor holds such
    a prefix, the pick returns an ambiguity marker
    ({"ambiguous": True, "l3doms": [...]}) with one display string per
    anchor. A `domain` that no gateway has resolves as an unscoped call.
    """
    # A domain that no gateway has leaves the pick unscoped. The prefixes that
    # contain the probe are found once over the whole run (`_containing`) and
    # then narrowed to the domain. Longest-prefix match picks among those.
    if domain is not None and not any(_anchor_of(g) == domain for g in gateways):
        domain = None
    containing = [g for g in _containing(gateways, probe) if domain is None or _anchor_of(g) == domain]
    candidates = containing
    notes = trail.notes
    if any(g.get("vsx_cluster") for g in containing):
        selected = [g for g in containing if not g.get("vsx_cluster")]
        instances = {g.get("firewall_instance_uid") for g in containing if g.get("vsx_cluster")}
        for instance in instances:
            members = [g for g in containing if g.get("firewall_instance_uid") == instance]
            active = [g for g in members if g.get("vsx_state") == "active"]
            if not instance or len({g["dev_uid"] for g in active}) != 1:
                return {"ambiguous": True, "l3doms": ["VSX active member unresolved or conflicting"]}
            selected.extend(active)
        containing = candidates = selected
    if seg_uid and containing:
        containing, unknown = _segment_tie(session, containing, seg_uid, probe, notes)
        if unknown:
            return unknown
        # From here on the candidates are the gateways on the segment of the
        # source, in the scoped and in the unscoped resolution.
        candidates = containing
    if domain is None:
        fhrp = _fhrp_gateway(session, containing, probe, trail)
        if fhrp is not None:
            return fhrp
        # sorted() picks one l3dom string per anchor.
        dom_by_anchor: dict[Any, list[str]] = {}
        for g in containing:
            a = _anchor_of(g)
            if a:
                dom_by_anchor.setdefault(a, []).append(g.get("l3dom") or a)
        anchors = sorted(dom_by_anchor)
        anycast = _anycast_gateway(session, containing, anchors, attach, probe) if len(anchors) > 1 else None
        if anycast:
            notes.append(anycast[1])
            containing = candidates = anycast[0]
            anchors = [_anchor_of(anycast[0][0])]
        if len(anchors) > 1:
            return {
                "ambiguous": True,
                "l3doms": [sorted(dom_by_anchor[a])[0] for a in anchors],
                "contexts": _gateway_contexts(session, containing, anchors, dom_by_anchor),
            }
        if not anycast and len(anchors) == 1 and all(_anchor_of(g) for g in containing):
            candidates = containing
            notes.append(
                f"gateway prefixes for {probe} exist only in L3 domain "
                f"{sorted(dom_by_anchor[anchors[0]])[0]}; trace scoped"
            )
    winners = sorted(_lpm_all(candidates, probe), key=lambda g: g.get("dev_uid") or "")
    if not winners:
        return None
    if len(winners) > 1:
        names = ", ".join(g["dev_name"] or g["dev_uid"] for g in winners)
        trail.warn(
            f"{len(winners)} gateway candidates tie for {winners[0]['cidr']} ({names}); "
            f"traced via {winners[0]['dev_name'] or winners[0]['dev_uid']} (lowest uid), "
            "a representative drawing, not evidence of which device forwards"
        )
    return winners[0]


# CONNECTED_TO sources whose collector states the cable itself. The reasoner's
# "unifi-uplink" and "unifi-lldp" rules are stated (`derived: false`).
_L2_STATED_SOURCES = frozenset({"unifi", "unifi-uplink", "unifi-lldp", "nautobot-cable", "vcenter"})


def _l2_tag_depth(node: dict[str, Any], target_bds: set[str]) -> int | None:
    """The tag depth of the bridge domain of the flow on a port. The result is
    0 when the port carries the domain untagged (native or access) and 1 when
    tagged. The result is None when the carriage of that domain on the port was
    not recorded or the bridge domain of the flow is not known.
    """
    if not target_bds:
        return None
    if target_bds & set(node.get("native_bds") or ()):
        return 0
    if target_bds & set(node.get("tagged_bds") or ()):
        return 1
    return None


def _draw_l2_chain(
    trail: _Trail, session: Any, nodes: list[dict[str, Any]], via_uid: str | None, *, stage: Stage
) -> None:
    """Draws the hops of one resolved L2 chain. The members of a Lag become
    one hop. The carriage of each Port, or of each Lag, is checked against the
    bridge domain of the flow. `_gateway_walk` and `_delivery_walk` use it.

    `via_uid` is the interface whose realized bridge domains are the bridge
    domains of the flow. A Port whose bridge domains have no domain in common
    with them sets `trail.l2_mismatch` and writes a warning. The members of a
    Lag are checked as their union.

    The MTU crossing of a Port that is not a Lag member is "eligible" when the
    source of its cabling is in `_L2_STATED_SOURCES` and no node up to it has
    `forked` set. Otherwise the crossing is "possible". The crossing of a Lag
    member is "possible". Each Port crossing holds the tag depth of
    `_l2_tag_depth`.
    """
    if not nodes:
        return
    target_bds = (
        {r["uid"] for r in _path._read(session, _IFACE_SEGMENT_QUERY, u=via_uid)} if via_uid else set()
    )
    after_fork = False
    for node in nodes:
        # A node with `forked` set marks every later Port node as after a fork.
        if node.get("forked"):
            after_fork = True
        if node.get("is_port"):
            possible = True
            if not node.get("lag"):
                # A LAG member stays under the candidate-set rule
                # (expand_stages/TOPOLOGY_QUERY), whichever source cabled it.
                # A non-member port is eligible only when its own cabling is
                # stated by its source and no fork precedes it.
                possible = after_fork or node.get("conn_source") not in _L2_STATED_SOURCES
            depth = _l2_tag_depth(node, target_bds)
            _mtu_crossing(trail, node["uid"], enforcement="l2", possible=possible, tag_depth=depth)
            _mtu_crossing(
                trail, node["uid"], enforcement="l2", direction="rx", possible=possible, tag_depth=depth
            )
    seen_bds = False

    def _check_carriage(n: dict[str, Any], bds: set[str]) -> None:
        nonlocal seen_bds
        if not bds:
            return
        seen_bds = True
        if target_bds and not (bds & target_bds):
            trail.l2_mismatch = True
            trail.warn(
                f"{n['label'] or n['uid']} carries {sorted(bds)}, "
                f"not the flow's bridge domain {sorted(target_bds)}"
            )

    i = 0
    while i < len(nodes):
        n = nodes[i]
        if n["is_port"] and n.get("lag"):
            j = i
            lag_bds: set[str] = set()
            while j < len(nodes) and nodes[j]["is_port"] and nodes[j].get("lag") == n["lag"]:
                lag_bds |= set(nodes[j].get("bds") or [])
                j += 1
            _check_carriage(n, lag_bds)
            trail.hop(n["lag"], "Lag", n["label"] or "lag", f"on {n['dev']}" if n["dev"] else "", stage=stage)
            i = j
            continue
        if n["is_port"]:
            _check_carriage(n, set(n.get("bds") or []))
            trail.hop(
                n["uid"], "Port", n["label"] or "port", f"on {n['dev']}" if n["dev"] else "", stage=stage
            )
        else:
            trail.hop(n["uid"], "Device", n["label"] or "switch", stage=stage)
        i += 1
    if not seen_bds:
        note = (
            f"VLAN carriage not verified for the {stage.name} leg "
            "(no CARRIES/SWITCHES data collected on the path)"
        )
        trail.note_once(note)
    elif not target_bds:
        # The ports have carriage data. The interface `via_uid` has no bridge
        # domain (an untagged routed port). No comparison was made.
        trail.note_once(
            f"VLAN carriage not verified for the {stage.name} leg (the flow's own bridge domain "
            f"is not recorded on {via_uid or 'the interface this leg carries'}, so the carriage "
            "the ports report was not compared)"
        )


# The trunk of a gateway interface. It holds the Port that realizes the
# interface and every switch Port cabled to that Port in the run. The query
# returns one row for any count of cables. `rp`, `swp`, `swp_name` and
# `swp_dev` hold the first cable in uid order, and `peers` holds the uid of
# every cabled switch Port. `_TRUNK_BY_IF_UID_QUERY` resolves the interface by
# uid. `_TRUNK_BY_PARENT_NAME_QUERY` resolves the parent interface of a VLAN
# sub-interface by name on the gateway device. Both queries end with this tail.
_TRUNK_TAIL = """
WITH DISTINCT rp, swp, head([(swp)-[:ON]->(d:Device) | coalesce(d.hostname, d.uid)]) AS swp_dev
ORDER BY rp.uid, swp.uid
WITH collect({rp: rp.uid, rp_name: rp.name, swp: swp.uid, swp_name: swp.name, swp_dev: swp_dev}) AS rows
WITH [x IN rows WHERE x.swp IS NOT NULL] AS cables
RETURN head(cables).rp AS rp, head(cables).rp_name AS rp_name,
       head(cables).swp AS swp, head(cables).swp_name AS swp_name, head(cables).swp_dev AS swp_dev,
       [x IN cables | x.swp] AS peers"""

_TRUNK_BY_IF_UID_QUERY = (
    """
MATCH (i:Interface {uid: $if_uid})
WHERE i:Obj AND i.collection_ts = $snap
OPTIONAL MATCH (i)-[rb:REALIZED_BY]->(rp:Port)-[c:CONNECTED_TO]-(swp:Port)
WHERE NOT rp:Retired AND NOT swp:Retired
  AND rb._retired_at IS NULL AND c._retired_at IS NULL"""
    + _TRUNK_TAIL
)

_TRUNK_BY_PARENT_NAME_QUERY = (
    """
MATCH (i:Interface {name: $name})-[o:ON]->(pd:Device {uid: $dev})
WHERE pd:Obj AND pd.collection_ts = $snap
  AND NOT i:Retired AND o._retired_at IS NULL AND i.collection_ts = $snap
OPTIONAL MATCH (i)-[rb2:REALIZED_BY]->(rp:Port)-[c2:CONNECTED_TO]-(swp:Port)
WHERE NOT rp:Retired AND NOT swp:Retired
  AND rb2._retired_at IS NULL AND c2._retired_at IS NULL"""
    + _TRUNK_TAIL
)


def _trunk_peers(row: dict[str, Any]) -> list[str]:
    """The uid of every switch Port cabled to the router Port of the trunk
    row. A row with no `peers` column has the one cable of its `swp`."""
    peers = row.get("peers")
    if peers is None:
        return [row["swp"]] if row.get("swp") else []
    return [p for p in peers if p]


def _gateway_walk(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    attach: str | None,
    src_set: list[tuple[int, int, int]],
    *,
    expect_chain: bool = True,
) -> None:
    """The L2 leg from the attachment of the source to the gateway, cable by
    cable.

    The trunk row holds the router Port that realizes the gateway interface
    and the switch Port cabled to it. When the twin holds more than one cable
    on that router Port (`_trunk_peers`), the walk draws the router Port
    alone and warns with every peer.

    `expect_chain` is False only for a source with no attachment. When an
    expected chain cannot be drawn, the leg records one unresolved L2
    crossing.

    The trunk rows need `(Interface)-[:REALIZED_BY]->(Port)`. The Cisco
    collectors write that edge for physical ports only. An SVI gateway
    resolves no switch port, and `_gateway_device_walk` covers that case.
    """
    gw_set = _intervals([gw["cidr"]])
    outside = _subtract(src_set, gw_set)
    if outside:
        trail.warn(f"outside {gw['cidr']}: {_describe(outside)} (different gateway; trace those separately)")
    # The trunk of the gateway interface (a derived cable, if known).
    trunk = _path._read_one(session, _TRUNK_BY_IF_UID_QUERY, if_uid=gw["if_uid"])
    parent = (gw["if_name"] or "").split(".")[0]
    # The trunk of the parent interface is used only when the trunk of the interface has no switch port.
    row = trunk if trunk and trunk["swp"] else None
    if row is None and parent:
        ptrunk = _path._read_one(session, _TRUNK_BY_PARENT_NAME_QUERY, name=parent, dev=gw["dev_uid"])
        row = ptrunk if ptrunk and ptrunk["swp"] else None
    if row is None:
        _gateway_device_walk(session, trail, gw, attach, expect_chain=expect_chain)
    else:
        peers = _trunk_peers(row)
        if len(peers) > 1:
            # The leg is drawn as a jump to the router's own port.
            trail.warn(
                f"{row['rp_name'] or parent} on {_dev_label(gw)} carries "
                f"{len(peers)} cables in the twin ({', '.join(peers)}); the L2 leg is drawn as a jump"
            )
            trail.l2_boundary = True
            if expect_chain:
                _mtu_unresolved_crossing(trail, enforcement="l2")
        else:
            _trunk_chain(session, trail, gw, attach, row, expect_chain=expect_chain)
        trail.hop(row["rp"], "Port", row["rp_name"] or parent, "router port", stage=Stage.L2_FABRIC)
    _mtu_crossing(trail, gw["if_uid"], enforcement="l3", direction="rx")
    _draw_arrival(trail, gw, if_note=f"gateway for {gw['cidr']}", dev_fallback="router")
    if gw.get("dev_carried"):
        _warn_carried(trail, gw)


def _trunk_chain(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    attach: str | None,
    row: dict[str, Any],
    *,
    expect_chain: bool,
) -> None:
    """The L2 fabric from the attachment of the client to the switch port of
    the one cable on the trunk port of the router. Every uplink port and
    switch on the way is a hop."""
    chain = (
        _path._read_one(
            session,
            _L2_CHAIN_QUERY,
            a=attach,
            z=row["swp"],
            avoid=gw["dev_uid"],
        )
        if attach
        else None
    )
    if chain and chain["chain"]:
        _draw_l2_chain(trail, session, chain["chain"], gw["if_uid"], stage=Stage.L2_FABRIC)
        return
    if attach:
        trail.warn(f"no cable path from {attach} to {row['swp']} in the graph; the L2 leg is drawn as a jump")
        trail.l2_boundary = True
    # An unresolved `attach` draws a jump with no warning and no `l2_boundary`.
    if expect_chain:
        _mtu_unresolved_crossing(trail, enforcement="l2")
    trail.hop(
        row["swp"],
        "Port",
        row["swp_name"] or "uplink port",
        f"on {row['swp_dev']}" if row["swp_dev"] else "derived cable",
        stage=Stage.L2_FABRIC,
    )


def _gateway_device_walk(
    session: Any, trail: _Trail, gw: dict[str, Any], attach: str | None, *, expect_chain: bool
) -> None:
    """The L2 leg when no trunk port resolves for the gateway interface.

    An SVI is realized by no single physical port. The chain starts from the
    attachment of the source and ends on the gateway device. The switch port
    that faces the router and the port of the router are hops of this chain.
    The gateway device is not a hop of this chain.

    Two known ends with no chain between them give a warning, `l2_boundary`
    and an unresolved MTU crossing. An unknown attachment gives the MTU
    crossing only (see `_gateway_walk`). A source attached to the gateway
    device has no chain.
    """
    if not attach:
        if expect_chain:
            _mtu_unresolved_crossing(trail, enforcement="l2")
        return
    if attach == gw["dev_uid"]:
        return
    chain = _path._read_one(session, _L2_CHAIN_QUERY, a=attach, z=gw["dev_uid"], avoid="")
    nodes = list(chain["chain"]) if chain and chain["chain"] else []
    if nodes and nodes[-1]["uid"] == gw["dev_uid"]:
        nodes.pop()
    if nodes:
        _draw_l2_chain(trail, session, nodes, gw["if_uid"], stage=Stage.L2_FABRIC)
        return
    trail.warn(f"no cable path from {attach} to {gw['dev_uid']} in the graph; the L2 leg is drawn as a jump")
    trail.l2_boundary = True
    if expect_chain:
        _mtu_unresolved_crossing(trail, enforcement="l2")


# An interface is BOUND_TO its VlanInstance, and the VlanInstance REALIZES the
# broadcast domain (BridgeDomain or L2Segment). EXTENDS is a bounded traversal
# between domains that one L2 extension connects.
def _dst_attachment(
    session: Any,
    dst_set: list[tuple[int, int, int]],
    domain: str | None,
    via_uid: str | None = None,
) -> dict[str, Any] | None:
    """The physical attachment of the destination endpoint, when the
    destination is a single address that the twin knows. The row has the shape
    of a `_source_candidates` row.

    `via_uid` is the interface that the flow leaves through. It is the egress
    of the delivering route, or the gateway interface of an intra-segment
    flow. A row in an L2 segment of `via_uid` is returned first. Otherwise the
    first row is returned, limited to `domain` when it is set. The result is
    None when no row matches."""
    if _size(dst_set) != 1:
        return None
    ip = _to_cidrs(dst_set)[0].split("/")[0]
    rows = _source_candidates(session, ip)
    if via_uid:
        segs = {s["uid"] for s in _path._read(session, _IFACE_SEGMENT_QUERY, u=via_uid)}
        scoped = [r for r in rows if _anchor_of(r) in segs or r.get("seg_uid") in segs]
        if scoped:
            return scoped[0]
    if domain:
        rows = [r for r in rows if _anchor_of(r) == domain]
    return rows[0] if rows else None


# A fake graph in tests tells this query from `_SOURCE_QUERY` by its text.
def _dst_instances(session: Any, ip: str) -> list[dict[str, Any]]:
    """Every live IpAddress node answering to this literal address, across
    every forwarding context.

    `trace()` fetches this once, before any lane runs, and every lane reuses
    it.
    """
    return _path._read(session, _DST_INSTANCES_QUERY, ip=ip)


def _dst_duplicate_notes(
    reached_uid: str | None,
    dst_found: bool,
    dst_instances: list[dict[str, Any]],
    dst_ip: str,
    dst_context: str | None,
) -> list[str]:
    """Lane notes about other, unreached instances of the destination address.

    `dst_found` is whether this lane's `_dst_attachment` lookups landed on an
    instance, and `reached_uid` is that instance's ip uid. Every other known
    instance is reported. A mismatch with `dst_context` is noted, and the
    verdict stays.
    """
    if not dst_instances:
        return []
    reached = next((r for r in dst_instances if r["uid"] == reached_uid), None) if dst_found else None
    notes = [
        f"destination {dst_ip} also exists in {r.get('l3dom') or '?'} (not reached from this source)"
        for r in dst_instances
        if r is not reached
    ]
    if dst_context is not None and reached is not None and _anchor_of(reached) != dst_context:
        notes.append(
            f"reached the instance in {reached.get('l3dom') or '?'}; the requested context "
            f"{dst_context} is not reachable from this source"
        )
    return notes


def _reached_in_context(trail: _Trail, dst_instances: list[dict[str, Any]], dst_context: str) -> bool:
    """Whether the walk reached the destination address's own instance in
    `dst_context` (`trail.dst_uid`, the instance `_dst_attachment` landed on)."""
    if not trail.dst_found:
        return False
    return any(r["uid"] == trail.dst_uid and _anchor_of(r) == dst_context for r in dst_instances)


def _check_delivery_context(
    trail: _Trail,
    legs: list[dict[str, Any]],
    local: list[bool],
    dst_ip: str,
    dst_context: str,
    switched_in: list[str | None] | None = None,
) -> list[str]:
    """Checks the context in which each leg ends against `dst_context`. It
    applies to a destination that the walk did not reach in `dst_context`.
    Such a destination is a prefix, an address that the twin does not hold, or
    an address whose instance in that context the walk did not reach
    (`_reached_in_context`).

    A leg that ends outside `dst_context` is indeterminate, with the reason on
    the leg and in a warning. A leg ends when it is delivered (`local`) or
    leaves the twin (`boundary`). The context of a leg is its `context_uid`,
    or its entry in `switched_in`. The instance of an endpoint is anchored on
    its segment and a leg on its table. A leg whose context is `dst_context`
    passes for a reached instance in another anchor. The function returns the
    reasons for the verdict line."""
    reasons: list[str] = []
    for i, (leg, delivered) in enumerate(zip(legs, local, strict=True)):
        # A leg that is decided as not forwarded (blocked, no route) has no
        # end. The `boundary` mark of the L2 leg does not count as an exit.
        if _decided_false(leg) or (not delivered and not leg.get("boundary")):
            continue
        where = leg.get("context_uid") or (switched_in[i] if switched_in else None)
        if where == dst_context:
            continue
        ends = "is delivered" if delivered else "leaves the twin"
        why = (
            f"the path to {dst_ip} {ends} in context {where or '(not recorded)'}, "
            f"not in the requested destination context {dst_context}"
        )
        leg["indeterminate"] = True
        leg.setdefault("indeterminate_reason", why)
        trail.warn(why)
        if why not in reasons:
            reasons.append(why)
    return reasons


def _delivery_walk(
    session: Any,
    trail: _Trail,
    dst: dict[str, Any] | None,
    dst_ip: str,
    from_uid: str | None,
    avoid_dev: str | None,
    bd_if_uid: str | None,
) -> bool:
    """The L2 leg on the far side. It goes from the delivering interface, or
    from the attachment of the source for an intra-segment flow, to the switch
    port or AP of the destination and to the endpoint. Returns True when the
    destination endpoint was drawn.

    `from_uid` is the anchor of the chain walk, a Device, Port or Interface
    uid from `_source_attachment` or from the egress of the route. `bd_if_uid`
    is the interface uid for the bridge-domain lookup of `_draw_l2_chain`. It
    is the egress of the delivering route, or the gateway interface of an
    intra-segment flow, as in `_dst_attachment`.
    """
    if not dst:
        _mtu_boundary(trail)
        return False
    _mtu_crossing(trail, dst.get("att_uid"), enforcement="l2", possible=True)
    _mtu_crossing(trail, dst.get("ep_uid"), enforcement="destination", direction="rx")
    anchor = dst["sw_uid"] if dst["att_is_port"] else dst["att_uid"]
    chain = (
        _path._read_one(
            session,
            _L2_CHAIN_QUERY,
            a=from_uid,
            z=anchor,
            avoid=avoid_dev or "",
        )
        if from_uid and anchor and from_uid != anchor
        else None
    )
    # `dst` is set here. A chain to the attachment of the destination is expected.
    if from_uid and anchor and from_uid != anchor:
        if not (chain and chain["chain"]):
            trail.warn(
                f"no cable path from {from_uid} to {anchor} in the graph; "
                "the destination leg is drawn as a jump"
            )
            trail.l2_boundary = True
            _mtu_unresolved_crossing(trail, enforcement="l2")
    elif not anchor:
        # The attachment of the destination is not resolved. The MTU judgment
        # records the gap (it does nothing outside an active capture). No
        # warning is written and `l2_boundary` is not set.
        _mtu_unresolved_crossing(trail, enforcement="l2")
    nodes = chain["chain"] if chain and chain["chain"] else []
    _draw_l2_chain(trail, session, nodes, bd_if_uid, stage=Stage.DST_FABRIC)
    if dst["att_uid"]:
        if dst["att_is_port"]:
            if dst["sw_uid"]:
                trail.hop(dst["sw_uid"], "Device", dst["sw_name"] or "switch", stage=Stage.DST_ATTACH)
            trail.hop(
                dst["att_uid"],
                "Port",
                dst["att_name"] or "port",
                f"on {dst['sw_name'] or '?'}",
                stage=Stage.DST_ATTACH,
            )
        else:
            trail.hop(
                dst["att_uid"],
                "Device",
                dst["att_name"] or "ap",
                f"via {dst['ssid']}" if dst["ssid"] else "wireless",
                stage=Stage.DST_ATTACH,
            )
    if dst["ep_uid"]:
        trail.hop(
            dst["ep_uid"], "Endpoint", dst["ep_name"] or dst_ip, f"dst {dst_ip}", stage=Stage.DST_ENDPOINT
        )
        return True
    return False


def _blocked_destination(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    via_uid: str | None,
    src_label: str,
    local_net: bool,
) -> None:
    """End a blocked leg on the destination it was headed for.

    The hops past the gate are drawn without evaluating anything further.

    `local_net` (the destination sits on a network this device serves) draws
    the whole far-side L2 leg. Otherwise only the destination endpoint itself
    is drawn. `trail.dst_found` is not set here.
    """
    no_draw = f"{src_label}: destination not drawn past the block: no attachment resolved"
    if _size(dst_part) != 1:
        trail.notes.append(no_draw)
        return
    dst_host = _to_cidrs(dst_part)[0].split("/")[0]
    vs_rows = _vip_bindings(session, dst_host, gw["dev_uid"])
    if vs_rows:
        for row in vs_rows:
            trail.hop(
                row["uid"],
                "VirtualService",
                row.get("name") or dst_host,
                "past the block, not evaluated",
                stage=Stage.LOAD_BALANCER,
            )
        return
    # A note is added when the destination is a VIP of a device that is not on
    # the drawn path.
    elsewhere = _vip_elsewhere_reason(session, dst_host, None, None)
    if elsewhere:
        trail.notes.append(f"{src_label}: {elsewhere}")
    dst_row = _dst_attachment(session, dst_part, _anchor_of(gw), via_uid)
    if dst_row is not None and local_net:
        _delivery_walk(session, trail, dst_row, dst_host, via_uid, None, via_uid)
        # The far side is drawn for a leg that the gate blocked.
        leg["delivered"] = False
        return
    if dst_row is not None and dst_row["ep_uid"]:
        trail.hop(
            dst_row["ep_uid"],
            "Endpoint",
            dst_row["ep_name"] or dst_host,
            f"dst {dst_host}",
            stage=Stage.DST_ENDPOINT,
        )
        return
    trail.notes.append(no_draw)


def _rib_lookup(
    rib: Any | None, dev: str, table_uid: str | None, vrf_name: str | None
) -> tuple[Any, Any] | None:
    """LPM and overlap lookups over the parquet side store, scoped to one
    device and routing table. None when there is no store or no table."""
    if rib is None or not table_uid:
        return None
    return (
        lambda probe: rib.lpm(dev, table_uid, probe, legacy_vrf=vrf_name),
        lambda lo, hi, minlen, af: rib.overlapping(dev, table_uid, lo, hi, minlen, af, legacy_vrf=vrf_name),
    )


def _carrier_output_filter(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    carrier: dict[str, Any],
    gw: dict[str, Any],
    tun: dict[str, Any],
    egress_uid: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
) -> None:
    """The firewall verdict on the carrier packet that the device sends
    (`_firewall_verdict_local`). The verdict is that of the output chain. On a
    zone firewall with a local zone, it is that of the pair (local zone, zone
    of the egress of the carrier)."""
    fw = _firewall_verdict_local(session, gw["dev_uid"], egress_uid, src_set, dst_set, port, proto)
    if not fw:
        return
    trail.hop(
        fw["rb_uid"],
        "FwRulebase",
        fw["rb_name"],
        f"output · {fw['action']} ({fw['by']})",
        stage=Stage.CARRIER_FILTER,
    )
    by = f"rule {fw['pos']}" if fw.get("pos") is not None else "default-action"
    carrier["firewall"] = f"{fw['rb_name']} (output) {fw['action']} by {by}"
    # The output chain is read as a new flow. A note is added for each rule
    # that is skipped for its connection state.
    for skip in fw.get("state_skips") or []:
        trail.notes.append(
            f"{tun['name']}: rule {skip['pos']} is scoped to connection state "
            f"{'/'.join(skip['states'])}; this trace models a new connection, so the rule "
            "does not govern the carrier packet"
        )
    outcome = classify_action(fw["action"])
    if outcome == DENY:
        leg["blocked"] = True
        carrier["verdict"] = f"BLOCKED by {fw['rb_name']} {by}"
        trail.warn(f"{tun['name']}: carrier blocked by {fw['rb_name']} {by}")
    elif outcome == INDETERMINATE:
        leg["indeterminate"] = True
        why = fw.get("indeterminate_reason")
        trail.warn(
            f"{tun['name']}: carrier verdict from {fw['rb_name']} not decidable" + (f": {why}" if why else "")
        )
    leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), fw["rb_uid"]})


def _carrier_snat(
    trail: _Trail,
    leg: dict[str, Any],
    carrier: dict[str, Any],
    nat_rows: list[dict[str, Any]],
    egress_name: str | None,
    src_ip: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    tun_name: str,
    *,
    ingress_role: str | None = None,
    egress_role: str | None = None,
) -> None:
    """POSTROUTING on the carrier packet before it leaves the egress interface.

    `ingress_role`/`egress_role` are the collected NAT roles of the flow's
    ingress interface and this carrier packet's own egress interface,
    forwarded to `_nat_stage_rules` for Cisco `inside-source` binding."""
    rules = _nat_stage_rules(
        nat_rows, "snat", egress_name, ingress_role=ingress_role, egress_role=egress_role
    )
    for rule in rules:
        part = _nat_partition([rule], src_set, dst_set, port, proto)[0]
        # every check below reads the copy of the rule that the partition returns
        matched = part["rule"]
        if matched is None:
            continue
        # An exclude rule that matches ends the search (first match). An
        # exclude rule whose match is not decided goes to the opaque branch.
        if matched.get("exclude") and not matched.get("opaque"):
            break
        if matched.get("opaque"):
            leg["indeterminate"] = True
            reason = matched.get("role_note") or "not determinable"
            trail.warn(f"{tun_name}: carrier sNAT rule {matched['pos']} {reason}")
            break
        to = _describe(part["new_src"]) if not matched.get("masquerade") else (src_ip or "egress address")
        label = f"sNAT rule {matched['pos']}"
        trail.hop(matched["uid"], "NatRule", label, f"→ {to}", stage=Stage.CARRIER_SNAT)
        carrier["snat"] = to
        break


def _zia_forwarding(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    tun: dict[str, Any],
    inner: dict[str, Any],
    *,
    location: dict[str, Any] | None = None,
) -> None:
    """Applies the ZIA forwarding rules, first match, to the inner flow at the
    ZIA boundary (path/gates/zia.py). A drop rule blocks the leg. A rule with
    another method is drawn and the leg stays a boundary. An undecided rule
    adds one note. The function changes nothing when the tunnel has no
    location."""
    location = location or zia_gate.tunnel_location(session, tun["uid"])
    if location is None:
        return
    decision = zia_gate.forwarding_decision(
        location, zia_gate.tenant_rules(session, tun["uid"]), inner["src"], inner["dst"]
    )
    if decision.rule is not None:
        rule = decision.rule
        name = rule.get("name") or rule["uid"]
        method = str(rule.get("method") or "").lower()
        order = f" (order {rule['order']})" if rule.get("order") is not None else ""
        trail.hop(
            rule["uid"],
            "ZiaForwardingRule",
            name,
            f"{method} by ZIA forwarding rule {name}{order}",
            stage=Stage.DECAP,
        )
        if method == "drop":
            leg["blocked"] = True
            leg["blocking_uid"] = rule["uid"]
            leg["verdict"] = f"BLOCKED by ZIA forwarding rule {name}"
        else:
            leg["fw_uids"] = sorted(set(leg.get("fw_uids") or []) | {rule["uid"]})
        return
    if decision.undecided is not None:
        name = decision.undecided.get("name") or decision.undecided["uid"]
        trail.notes.append(
            f"ZIA forwarding rule {name}: {decision.reason}; the ZIA forwarding decision is not evaluated"
        )
    elif decision.reason:
        trail.notes.append(f"ZIA forwarding: {decision.reason}; the ZIA forwarding decision is not evaluated")


def _carrier_trace(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    tun: dict[str, Any],
    via_if_uid: str | None,
    nat_rows: list[dict[str, Any]],
    rib: Any | None,
    *,
    inner: dict[str, Any],
    ingress_role: str | None,
) -> None:
    """The path of the encapsulated packet to the tunnel peer.

    WireGuard emits a new, locally originated packet (source the router,
    destination the peer endpoint, udp/51820). The WAN firewall is evaluated
    against the carrier addresses.

    The results go on `leg["carrier"]`.

    No stage is drawn here for the encapsulation point of the tunnel.

    `ingress_role` is the collected NAT role of the interface that the inner
    flow arrived on. The caller reads it for its source NAT stage when
    `nat_rows` holds a rule.
    """
    row = _path._read_one(session, _CARRIER_TUNNEL_QUERY, uid=tun["uid"])
    if not row:
        _warn_peer_not_collected(trail, tun)
        return
    if row.get("far_kind") != "ZscalerDc" and (row.get("far_ends") or 0) > 1:
        # The query above keeps one far end.
        trail.warn(
            f"{tun['name']}: the tunnel has {row['far_ends']} far ends "
            f"({', '.join(str(s) for s in row.get('far_sample') or [])}); the carrier is drawn to "
            f"{row.get('far_ip') or row.get('far_name') or row.get('endpoint')} only, which may be "
            "the far end of another tunnel"
        )
        leg["indeterminate"] = True
    # `endpoint` is the fallback for a missing TERMINATES_ON far end.
    endpoint = row.get("far_ip") or row.get("endpoint")
    if not endpoint:
        _carrier_far_boundary(session, trail, leg, tun, row, inner)
        return
    dst_set = _intervals([str(endpoint)])
    if not dst_set:
        trail.warn(f"{tun['name']}: peer endpoint {endpoint!r} is not an address")
        return
    port = _int_or_none(row["endpoint_port"])
    proto = str(row["carrier_proto"] or "udp")

    af = dst_set[0][0]
    vrf, routes, lookup = _local_routes(session, rib, gw["dev_uid"], af)
    # The route of the carrier packet is selected by the provenance rule of
    # `_route_partition`. A note is added for each route that the rule dropped.
    outranked: list[str] = []
    parts = _route_partition(routes, dst_set, lookup, outranked)
    for note in outranked:
        trail.notes.append(f"{tun['name']}: {note}")
    best = parts[0][1] if parts else []
    if not best and via_if_uid:
        best = _wan_next_hop_route(session, trail, gw, tun, via_if_uid, af)
    if not best:
        trail.warn(f"{tun['name']}: no route to peer {endpoint}; carrier path unresolved")
        leg["carrier"] = {"endpoint": endpoint, "verdict": "no route to peer"}
        return

    route = best[0]
    if route.get("discard"):
        # the device drops the carrier itself, as `_discard_leg` drops a flow
        trail.hop(
            route["uid"] or f"{tun['uid']}#carrier:{route['cidr']}",
            "Prefix",
            route["cidr"],
            f"carrier route, {route['discard']}",
            stage=Stage.CARRIER_ROUTE,
        )
        leg["blocked"] = True
        leg["carrier"] = {
            "endpoint": endpoint,
            "port": port,
            "proto": proto,
            "cidr": route["cidr"],
            "verdict": f"BLOCKED by {route['discard']} route {route['cidr']}",
        }
        trail.warn(
            f"{tun['name']}: the route to peer {endpoint} is the {route['discard']} route "
            f"{route['cidr']}; the device drops the carrier and the tunnel cannot carry the flow"
        )
        return
    if route.get("derived") and route.get("kind") != "WAN_NEXT_HOP":
        # The reasoner derived the route from route targets, as on an ordinary
        # leg (`_build_route_leg`). A WAN_NEXT_HOP route is read from the
        # device and is not marked.
        leg["indeterminate"] = True
        trail.warn(
            f"{tun['name']}: the route to peer {endpoint} is {route['cidr']}, a route the reasoner "
            f"derived from route-target {route.get('via_rt')}, not a row read off the device; the "
            "carrier path is NOT confirmed"
        )
    _carrier_members(trail, leg, tun, endpoint, best)
    egress_uid, egress_name = route["egress_uid"], route["egress_name"]
    if not egress_uid and route["ifname"]:
        named = _path._read_one(
            session,
            _IFACE_BY_NAME_QUERY,
            name=route["ifname"],
            dev=gw["dev_uid"],
            vrf=vrf["vrf_uid"] if vrf else None,
        )
        if named:
            egress_uid, egress_name = named["uid"], named["name"]

    if (
        egress_uid
        and via_if_uid
        and egress_uid == via_if_uid
        and not _is_underlay_interface(session, via_if_uid, row)
    ):
        # the route to the peer leaves by the tunnel the peer terminates. An SD-WAN
        # tunnel ends on the physical WAN interface that also carries it.
        trail.warn(
            f"{tun['name']}: route to peer {endpoint} egresses {egress_name}: "
            "recursive routing, tunnel cannot establish"
        )
        leg["indeterminate"] = True
        leg["carrier"] = {
            "endpoint": endpoint,
            "verdict": f"recursive routing via {egress_name}",
        }
        return

    # `_Trail.hop` dedupes on (uid, lane). A route with no uid gets a synthetic uid.
    carrier_route_uid = route["uid"] or f"{tun['uid']}#carrier:{route['cidr']}"
    trail.hop(carrier_route_uid, "Prefix", route["cidr"], "carrier route", stage=Stage.CARRIER_ROUTE)

    # A locally originated packet has the source address of the egress
    # interface unless the tunnel sets `local_address`. The address is the
    # single address of the egress interface in the family of the peer
    # (`_NAT_IFACE_ADDR_QUERY`). The source is not known when the interface
    # holds none or more than one.
    src_ip = row["local_address"]
    if not src_ip and egress_uid:
        addr = _path._read_one(session, _NAT_IFACE_ADDR_QUERY, u=egress_uid, af=af)
        src_ip = addr["ip"] if addr else None
        if not src_ip:
            leg["indeterminate"] = True
            trail.warn(
                f"{tun['name']}: the carrier's source address is not known: the tunnel names no "
                f"local address and {egress_name or egress_uid} holds no single IPv{af} address; "
                "the carrier's filter, source NAT and far-end match are NOT confirmed"
            )
    src_set = _intervals([str(src_ip)]) if src_ip else []

    carrier: dict[str, Any] = {
        "endpoint": endpoint,
        "port": port,
        "proto": proto,
        "src": src_ip,
        "cidr": route["cidr"],
        "egress": egress_name,
        "verdict": f"egress via {egress_name}" if egress_name else f"matched {route['cidr']}",
    }

    _carrier_output_filter(session, trail, leg, carrier, gw, tun, egress_uid, src_set, dst_set, port, proto)

    if nat_rows and src_set:
        _carrier_snat(
            trail,
            leg,
            carrier,
            nat_rows,
            egress_name,
            src_ip,
            src_set,
            dst_set,
            port,
            proto,
            tun["name"],
            ingress_role=ingress_role,
            egress_role=_iface_nat_role(session, egress_uid),
        )

    if egress_uid:
        tunnel_evidence = {**row, "uid": tun["uid"], "interface_uid": via_if_uid}
        carrier_crossing(trail, egress_uid, tunnel=tunnel_evidence)
        trail.hop(egress_uid, "Interface", egress_name, "carrier egress", stage=Stage.CARRIER_EGRESS_IF)
    leg["carrier"] = carrier
    if carrier.get("verdict", "").startswith("BLOCKED"):
        return
    _carrier_walk(
        session,
        trail,
        leg,
        _CarrierHop(
            gw=gw,
            tun=tun,
            carrier=carrier,
            route=route,
            egress_uid=egress_uid,
            endpoint=endpoint,
            src_set=src_set,
            dst_set=dst_set,
            port=port,
            proto=proto,
            rib=rib,
            vrf=vrf,
            inner=inner,
            far_kind=row.get("far_kind"),
            far_uid=row.get("far_uid"),
            far_name=row.get("far_name"),
            encap=row.get("encap"),
            pair=row.get("pair"),
        ),
    )


def _carrier_members(
    trail: _Trail, leg: dict[str, Any], tun: dict[str, Any], endpoint: Any, best: list[dict[str, Any]]
) -> None:
    """Handles the members of an equal-cost route to the tunnel peer. The
    carrier is drawn by the first member. Members by one egress interface
    differ only in the next hop, and a note lists them. With members by
    different interfaces, the egress filter and the source NAT of the carrier
    are not known, and the leg is indeterminate."""

    def via(route: dict[str, Any]) -> str:
        return str(route.get("next_hop") or route.get("egress_name") or route.get("ifname") or "?")

    # The key is the interface name. A graph row has a uid and a store row has
    # only a name. The same route read from both is one member.
    def egress(route: dict[str, Any]) -> Any:
        return route.get("egress_name") or route.get("ifname")

    members = list({(egress(r), r.get("next_hop")): r for r in best}.values())
    if len(members) < 2:
        return
    egresses = {egress(r) for r in members}
    text = (
        f"{tun['name']}: {len(members)} equal-cost routes {members[0]['cidr']} lead to peer {endpoint}; "
        f"the carrier is drawn via {via(members[0])} and not via "
        f"{', '.join(via(r) for r in members[1:])}"
    )
    if len(egresses) < 2:
        trail.note_once(text)
        return
    leg["indeterminate"] = True
    names = ", ".join(sorted(str(r.get("egress_name") or r.get("ifname") or "?") for r in members))
    trail.warn(
        f"{text}; the members leave by different interfaces ({names}), so the carrier's "
        "filter and source NAT are NOT confirmed"
    )


def _warn_peer_not_collected(trail: _Trail, tun: dict[str, Any]) -> None:
    trail.warn(f"{tun['name']}: peer endpoint not collected; carrier path not traced")


def _zia_boundary_note(row: dict[str, Any]) -> str:
    """The note on a far end that is a ZIA data center, with its role and VIP where collected."""
    return (
        ", ".join(
            part
            for part in (
                "ZIA boundary",
                f"{row['far_role']} data center" if row.get("far_role") else None,
                f"VIP {row['far_vip']}" if row.get("far_vip") else None,
            )
            if part
        )
        + ": carrier path not evaluated"
    )


def _carrier_far_boundary(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    tun: dict[str, Any],
    row: Any,
    inner: dict[str, Any],
) -> None:
    """Handles a tunnel whose far end holds no address. A ZIA data center, an
    SD-WAN gateway or the location of a ZIA IPsec tunnel is a boundary. Any
    other far end is a peer endpoint that was not collected. `row` is the
    `_CARRIER_TUNNEL_QUERY` row of the tunnel."""
    far_kind = row.get("far_kind")
    if far_kind == "ZscalerDc":
        trail.hop(
            row.get("far_uid"),
            "ZscalerDc",
            row.get("far_name") or "ZIA",
            _zia_boundary_note(row),
            stage=Stage.CARRIER_ROUTE,
        )
        leg["boundary"] = True
        _zia_forwarding(session, trail, leg, tun, inner)
        return
    if far_kind == "SdwanGateway":
        # No address property is collected for SdwanGateway.
        trail.hop(
            row.get("far_uid"),
            "SdwanGateway",
            row.get("far_name") or "SD-WAN hub",
            "SD-WAN boundary: carrier path and policy not evaluated",
            stage=Stage.CARRIER_ROUTE,
        )
        leg["boundary"] = True
        return
    if str(tun["uid"]).startswith("zia:"):
        # A ZIA IPsec tunnel. ZIA gives no Zscaler endpoint for a VPN
        # credential. The location of the tunnel is the boundary.
        location = zia_gate.tunnel_location(session, tun["uid"])
        if location is not None:
            trail.hop(
                location["uid"],
                "ZiaLocation",
                location.get("name") or "ZIA location",
                "ZIA boundary, IPsec: ZIA names no Zscaler endpoint for a VPN credential; "
                "carrier path not evaluated",
                stage=Stage.CARRIER_ROUTE,
            )
            leg["boundary"] = True
            _zia_forwarding(session, trail, leg, tun, inner, location=location)
            return
    _warn_peer_not_collected(trail, tun)


def _local_routes(
    session: Any, rib: Any | None, dev_uid: str, af: int
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], tuple[Any, Any] | None]:
    """A device's global table, its routes of address family `af`, and the
    side-store lookup for that table."""
    vrf = _path._read_one(session, _LOCAL_VRF_QUERY, dev=dev_uid)
    vrf_uid = vrf["vrf_uid"] if vrf else None
    routes = _path._read(session, _ROUTES_QUERY, vrf=vrf_uid) if vrf else []
    routes = [r for r in routes if (":" in (r["cidr"] or "")) == (af == 6)]
    lookup = _rib_lookup(rib, dev_uid, vrf_uid, vrf["vrf_name"]) if vrf else None
    return vrf, routes, lookup


def _wan_next_hop_route(
    session: Any, trail: _Trail, gw: dict[str, Any], tun: dict[str, Any], via_if_uid: str, af: int
) -> list[dict[str, Any]]:
    """The route of the carrier on a device with no route table (a VeloCloud
    edge). The route goes to the next hop of the WAN settings, on the
    interface that the tunnel ends on. The route has the shape of a table row.
    The result is empty when the interface has no next hop."""
    wan_if = _path._read_one(session, _WAN_NEXT_HOP_QUERY, u=via_if_uid)
    if not (wan_if and wan_if.get("next_hop")):
        return []
    trail.notes.append(
        f"{tun['name']}: no route table on {_dev_label(gw)}; the carrier "
        f"leaves by {wan_if['name']} toward its WAN next hop {wan_if['next_hop']}"
    )
    return [
        {
            "uid": None,
            "cidr": "0.0.0.0/0" if af == 4 else "::/0",
            "kind": "WAN_NEXT_HOP",
            "next_hop": wan_if["next_hop"],
            "ifname": wan_if["name"],
            "egress_uid": wan_if["uid"],
            "egress_name": wan_if["name"],
            "derived": True,
            "via_rt": None,
            "rib": None,
            "next_hop_vrf": None,
            "discard": None,
        }
    ]


def _is_underlay_interface(session: Any, if_uid: str, tunnel_row: dict[str, Any]) -> bool:
    """Whether the interface that a tunnel ends on is the physical interface
    that the carrier leaves by. Such an interface holds the local address of
    the tunnel. A WireGuard or GRE interface holds the inner addresses, and a
    carrier that leaves by it is recursive routing. A VeloCloud WAN interface
    holds the source address of the carrier."""
    local = tunnel_row.get("local_address") or tunnel_row.get("source_ip")
    if not local:
        return False
    addr = _path._read_one(session, _IFACE_ADDR_QUERY, u=if_uid)
    if addr and addr.get("ip") == local:
        return True
    # The interface can hold more than one address. `_IFACE_ADDR_QUERY` returns
    # the lowest only. `_IFACE_HOLDS_ADDR_QUERY` checks every address.
    held = _path._read_one(session, _IFACE_HOLDS_ADDR_QUERY, u=if_uid, ip=str(local))
    return bool(held and held.get("ip") == local)


_IFACE_HOLDS_ADDR_QUERY = """
MATCH (i:Interface {uid: $u})-[h:HAS_IP]->(ip:IpAddress)
WHERE h._retired_at IS NULL AND NOT ip:Retired AND i:Obj AND i.collection_ts = $snap
  AND ip.ip = $ip
RETURN ip.ip AS ip ORDER BY ip.ip LIMIT 1"""

_WAN_NEXT_HOP_QUERY = """
MATCH (i:Interface {uid: $u})
WHERE NOT i:Retired AND i:Obj AND i.collection_ts = $snap
RETURN i.uid AS uid, i.name AS name, i.next_hop AS next_hop"""

# The uplink marks of the collector on one interface. The marks are a WanLink
# ON the interface (a VyOS DHCP or PPPoE uplink, a VeloCloud WAN interface, a
# static WAN link of the inventory) and the default route that the access
# client installs on it (VyOS `ipv4_default_origin`). A next hop beyond such an
# interface belongs to the provider. The Device of the interface in the pinned
# run holds the site zone of the operator (`site_zone`, `site_block`, absent
# when the run stamped none).
_EGRESS_UPLINK_QUERY = """
MATCH (i:Interface {uid: $u})
WHERE NOT i:Retired AND i:Obj AND i.collection_ts = $snap
OPTIONAL MATCH (i)-[don:ON]->(d:Device)
WHERE don._retired_at IS NULL AND NOT d:Retired AND d:Obj AND d.collection_ts = $snap
OPTIONAL MATCH (w:WanLink)-[won:ON]->(i)
WHERE won._retired_at IS NULL AND NOT w:Retired
RETURN i.ipv4_default_origin AS default_origin, w.uid AS link_uid, w.name AS link_name,
       w.kind AS link_kind, d.site_zone AS site_zone, d.site_block AS site_block
ORDER BY w.uid, d.uid LIMIT 1"""

# The default route of each family. An internet exit is taken only by a default route.
_DEFAULT_ROUTES = {"0.0.0.0/0": 4, "::/0": 6}

# The one site zone that makes a device the internet edge (the operator's
# declaration). "external" and "internal" have no effect on a trace.
_INTERNET_ZONE = "internet"


def exit_basis(
    *,
    link_kinds: Iterable[Any],
    default_origin: Any,
    site_zone: Any,
    family: int,
    next_hop: bool,
    sdwan: bool = False,
) -> str | None:
    """The basis on which a default route of `family` (4 or 6) out of an
    interface leaves the estate, or None. Every exit of the tracer
    (`_estate_exit`, `_mark_twin_exit`) and the uplink decision of the estate
    prefixes (`_uplink_interface`) use this rule.

    `link_kinds` are the kinds of the collected WAN links on the interface in
    WanLink uid order. Only the first kind counts. `next_hop` is True for a
    route whose next hop no collected interface has, and False for an
    interface-only route. `sdwan` marks an SD-WAN boundary row.

    - "wan-link": the first WAN link is not MPLS. An MPLS next hop is the PE
      of the operator, which belongs in the twin.
    - "access-client-default": IPv4 only, a route with a next hop, out of the
      interface that the access client installs the default on.
    - "site-zone": the zone of the device is "internet", the first WAN link of
      the interface is not MPLS, and the row is not an SD-WAN boundary row."""
    kinds = [str(k or "").lower() for k in link_kinds]
    first = kinds[0] if kinds else None
    if first is not None and first != "mpls":
        return "wan-link"
    if next_hop and default_origin and family == 4:
        return "access-client-default"
    if sdwan or site_zone != _INTERNET_ZONE or first == "mpls":
        return None
    return "site-zone"


def _site_zone_exit(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """The exit that the site zone of the operator declares on the device of
    the egress interface, or None. The exit exists when the zone of the device
    is "internet" in the pinned run and the WAN link of the row is not an MPLS
    link. A collected MPLS link outranks the declaration."""
    if not row or row.get("site_zone") != _INTERNET_ZONE:
        return None
    if row.get("link_uid") and str(row.get("link_kind") or "").lower() == "mpls":
        return None
    return {"uid": None, "name": None, "basis": "site-zone", "site_block": row.get("site_block")}


# The prefixes that the estate serves. The query returns every GATEWAY_FOR of
# an interface of the pinned run, from the interface or from an FhrpGroup that
# it is a member of. Each row has the facts that make its interface an edge
# (`_uplink_interface`). The facts are the WAN links of the interface in uid
# order, the mark of the access client, the zone of the device, and the
# default routes of the device from every table that it has. The tables are
# those of its interfaces and the policy tables OWNED_BY it. The mirrored RIB
# rows are LEARNED_ROUTE rows of these tables. Each default route has `held`,
# which is true when a collected interface has the next hop. For a link-local
# next hop, the interface must be on the link of the egress interface. The
# evaluator reads the same relation for `Network.estate_prefixes`
# (assessment/evaluation.py `_NETWORK_INTERFACES_QUERY`), and both engines
# apply `estate_prefixes`. GATEWAY_FOR goes to connected prefixes only.
_ESTATE_PREFIXES_QUERY = """
// 1. every default route of the run, once: the default Prefix nodes by their
//    indexed first address (core/db.py `prefix_lo_key`), then the route rows
//    to them, each with its table
MATCH (dp:Prefix:Obj)
WHERE dp.collection_ts = $snap AND NOT dp:Retired
  AND dp.lo_key IN ['4:00000000', '6:00000000000000000000000000000000'] AND dp.cidr IN ['0.0.0.0/0', '::/0']
OPTIONAL MATCH (dp)<-[r:STATIC_ROUTE|LEARNED_ROUTE]-(v:VrfInstance)
WHERE r._retired_at IS NULL AND NOT v:Retired
WITH collect(CASE WHEN r IS NULL THEN null ELSE {
       table: v, cidr: dp.cidr, next_hop: r.next_hop,
       interface: coalesce(r.interface, r.rib_interface)
     } END) AS routes
// 2. each device of the run once: its tables (those of its interfaces, and the
//    policy tables OWNED_BY it), and its default routes among them
MATCH (d:Device:Obj)
WHERE d.collection_ts = $snap AND NOT d:Retired
WITH d, routes,
     COLLECT {
       MATCH (d)<-[dv:ON]-(:Interface)-[iv:IN_VRF]->(v:VrfInstance)
       WHERE dv._retired_at IS NULL AND iv._retired_at IS NULL AND NOT v:Retired
       RETURN DISTINCT v
     } + COLLECT {
       MATCH (d)<-[ow:OWNED_BY]-(v:VrfInstance)
       WHERE ow._retired_at IS NULL AND NOT v:Retired
       RETURN v
     } AS tables
WITH d, [x IN routes WHERE x.table IN tables] AS own
WITH d, COLLECT {
       UNWIND own AS x
       WITH x, toLower(coalesce(x.next_hop, '')) AS hop
       RETURN DISTINCT {
         cidr: x.cidr, next_hop: x.next_hop, interface: x.interface,
         held: CASE
           WHEN x.next_hop IS NULL THEN false
           WHEN hop STARTS WITH 'fe8' OR hop STARTS WITH 'fe9' OR hop STARTS WITH 'fea'
             OR hop STARTS WITH 'feb' OR hop STARTS WITH '169.254.' THEN EXISTS {
             // a link-local next hop: an interface on the egress interface's own link has it
             MATCH (d)<-[eo:ON]-(eg:Interface)-[eh:HAS_IP]->(:IpAddress)
                   -[ein:IN]->(lp:Prefix)<-[hin:IN]-(:IpAddress)<-[hh:HAS_IP]-(hi:Interface)
                   -[h:HAS_IP]->(ia:IpAddress)
             WHERE eg.name = x.interface AND ia.ip = x.next_hop
               AND hi <> eg AND hi.collection_ts = $snap AND eg.collection_ts = $snap
               AND eo._retired_at IS NULL AND eh._retired_at IS NULL AND ein._retired_at IS NULL
               AND hin._retired_at IS NULL AND hh._retired_at IS NULL AND h._retired_at IS NULL
               AND NOT hi:Retired AND NOT ia:Retired AND NOT lp:Retired
               AND NOT lp.cidr STARTS WITH 'fe80' AND NOT lp.cidr STARTS WITH '169.254.'
           }
           ELSE EXISTS {
             MATCH (hi:Interface:Obj)-[h:HAS_IP]->(ia:IpAddress)
             WHERE hi.collection_ts = $snap AND ia.ip = x.next_hop
               AND h._retired_at IS NULL AND NOT hi:Retired AND NOT ia:Retired
           }
         END
       }
     } AS defaults
// 3. the device's interfaces and the prefixes they serve
MATCH (i:Interface:Obj)-[o:ON]->(d)
WHERE o._retired_at IS NULL AND NOT i:Retired AND i.collection_ts = $snap
MATCH (i)-[m:MEMBER_OF*0..1]->(gw)-[gf:GATEWAY_FOR]->(p:Prefix)
WHERE gf._retired_at IS NULL AND NOT p:Retired AND NOT gw:Retired
  AND all(r IN m WHERE r._retired_at IS NULL)
WITH DISTINCT p.cidr AS cidr, i, d, defaults
RETURN cidr, i.uid AS if_uid, i.name AS if_name, i.ipv4_default_origin AS default_origin,
       COLLECT {
         MATCH (w:WanLink)-[won:ON]->(i)
         WHERE won._retired_at IS NULL AND NOT w:Retired
         WITH w ORDER BY w.uid
         RETURN toLower(coalesce(w.kind, ''))
       } AS link_kinds,
       d.site_zone AS site_zone, defaults
ORDER BY cidr, if_uid"""


# Address space that is not a destination on the internet: private (RFC 1918),
# shared (RFC 6598), loopback, link-local and unique-local. A default route
# toward such an address is a route that is missing in the estate. The
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
# 2001:db8::/32) are not in the list. The demo estate uses them as internet
# addresses.
NOT_INTERNET: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)


def _networks(cidrs: Iterable[Any]) -> set[str]:
    """The cidrs that are networks of a length above 0, normalized."""
    specs: set[str] = set()
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        if net.prefixlen:
            specs.add(str(net))
    return specs


def estate_prefixes(
    cidrs: Iterable[Any], *, routed: Iterable[Any] = (), uplinks: Iterable[Any] = ()
) -> Ivals:
    """Every address of the estate, both families, merged. A destination in it
    that a device sends out by the edge of the estate is a route that is
    missing on that device and is no exit (`_estate_part`). The tracer and the
    evaluators (`Network.estate_prefixes`) use this rule. The result is the
    merge of:

    - `cidrs`: the prefixes that an interface of the estate serves (GATEWAY_FOR)
    - `routed`: the prefixes of the routes of a collected device
    - `NOT_INTERNET`: address space that is not on the internet

    `uplinks` are the prefixes served by an interface that is an edge by
    `_uplink_interface` (a WAN link that is not MPLS, the default mark of the
    access client, or the default-route egress of a device of zone
    "internet"). Such a prefix is the transfer network of the provider. Each
    one is removed from `cidrs` and `routed` by an exact network match.
    `NOT_INTERNET` stays whole.

    A cidr that is not a network and a prefix of length 0 are left out of
    `cidrs` and `routed`."""
    provider = _networks(uplinks)
    specs = ((_networks(cidrs) | _networks(routed)) - provider) | set(NOT_INTERNET)
    return tuple(_merge(_intervals(sorted(specs))))


# The estate prefixes of the running trace, read at most once per trace and
# only when an exit is in question (`_estate_part`). The public entry points
# set the memo (`_one_estate_read`). Outside them each call reads.
_ESTATE_MEMO: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "estate_memo", default=None
)


def _one_estate_read(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Read the estate's prefixes at most once for the whole trace `fn` answers,
    its reply walks and any trace it starts (the outer memo is kept)."""

    @functools.wraps(fn)
    def run(*args: Any, **kwargs: Any) -> Any:
        if _ESTATE_MEMO.get() is not None:
            return fn(*args, **kwargs)
        token = _ESTATE_MEMO.set({})
        try:
            return fn(*args, **kwargs)
        finally:
            _ESTATE_MEMO.reset(token)

    return run


# The prefixes of the routes of the collected devices of the pinned run that
# overlap a destination. Each span is one interval of the destination.
# `covering` holds the graph keys of the network address of every prefix
# length over the first address of the span (an exact index seek on
# `Prefix.lo_key`, core/db.py). `lo` and `hi` are the keys of the ends of the
# span (an index range bounded by the destination). The query also returns a
# default route, and `estate_prefixes` leaves it out. Each prefix has the
# devices whose tables have it, by OWNED_BY or else by an interface in the
# table. The uid of the table stands in when neither is recorded.
_ROUTED_PREFIXES_QUERY = """
UNWIND $spans AS span
MATCH (p:Prefix:Obj)
WHERE p.collection_ts = $snap AND NOT p:Retired
  AND (p.lo_key IN span.covering OR (p.lo_key >= span.lo AND p.lo_key <= span.hi))
  AND p.hi_key >= span.lo AND p.lo_key <= span.hi
WITH DISTINCT p
WITH p, COLLECT {
  MATCH (v:VrfInstance:Obj)-[r:ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE]->(p)
  WHERE v.collection_ts = $snap AND NOT v:Retired AND r._retired_at IS NULL
  RETURN DISTINCT coalesce(
    head([(v)-[:OWNED_BY]->(od:Device) WHERE NOT od:Retired | od.uid]),
    head([(v)<-[x:IN_VRF]-(:Interface)-[:ON]->(dd:Device)
          WHERE x._retired_at IS NULL AND NOT dd:Retired | dd.uid]),
    v.uid)
} AS devices
WHERE size(devices) > 0
RETURN p.cidr AS cidr, devices ORDER BY cidr"""


def _uplink_interface(row: dict[str, Any]) -> bool:
    """Whether an interface is the edge of the estate. It is the edge exactly
    when the exit rule (`exit_basis`) gives a basis for an exit by it. The
    prefixes that such an interface serves, of both families, are the transfer
    network of the provider (`estate_prefixes`, `uplinks`). The answer is per
    interface. `row["cidrs"]` holds all its served prefixes, or `row["cidr"]`
    holds the only one.

    The interface is an uplink when a default route of its device, of either
    family, leaves by it and `exit_basis` gives a basis. The route leaves by
    the interface when the route has the interface name or a next hop inside
    one of the prefixes of the interface. The route must have no next hop, or
    a next hop that no collected interface has (`held` false). For a
    link-local next hop, `held` is true only for an interface on the same
    link. When the engine reads no default route of the device (`defaults`
    empty, a table kept only in the side store), the link and the mark decide.
    The interface is then an uplink when its first WAN link is not MPLS or it
    has the mark of the access client. The mark of the access client is an
    IPv4 default route by the interface to the next hop of the provider. An
    interface with the mark is an uplink.

    Each default route is {cidr, next_hop, interface, held}. A row without
    `cidr` takes the family of its next hop, or else of the served prefix. A
    row without `held` is a next hop that no interface has."""
    cidrs = row.get("cidrs") or [row.get("cidr")]
    served = _merge(_intervals([str(c) for c in cidrs if c]))
    defaults = row.get("defaults") or []
    kinds = row.get("link_kinds") or []
    origin = row.get("default_origin")
    if not defaults:
        # No default route is known. The collected link and mark decide.
        return (
            exit_basis(link_kinds=kinds, default_origin=origin, site_zone=None, family=4, next_hop=True)
            is not None
        )
    if row.get("default_origin"):
        # the access client's own IPv4 default by this interface (`ipv4_default_origin`)
        defaults = [
            *defaults,
            {"cidr": "0.0.0.0/0", "next_hop": "access-client", "interface": row.get("if_name")},
        ]
    for default in defaults:
        hop = default.get("next_hop")
        hop_set = _intervals([str(hop)]) if hop else []
        by_name = bool(default.get("interface")) and default.get("interface") == row.get("if_name")
        if not by_name and not (hop_set and served and _intersect(hop_set, served)):
            continue
        if hop and default.get("held"):
            continue
        family = _DEFAULT_ROUTES.get(str(default.get("cidr")))
        if family is None:
            sample = hop_set or served
            family = sample[0][0] if sample else 4
        basis = exit_basis(
            link_kinds=kinds,
            default_origin=origin,
            site_zone=row.get("site_zone"),
            family=family,
            next_hop=bool(hop),
        )
        if basis is not None:
            return True
    return False


def _route_spans(dst: Iterable[tuple[int, int, int]]) -> list[dict[str, Any]]:
    """The spans `_ROUTED_PREFIXES_QUERY` reads for `dst` (graph keys, core/ipenc.py)."""
    spans = []
    for af, lo, hi in _merge(list(dst)):
        width = 32 if af == 4 else 128
        covering = sorted({ipenc._graph_key(af, lo & ~((1 << (width - n)) - 1)) for n in range(width + 1)})
        spans.append({"covering": covering, "lo": ipenc._graph_key(af, lo), "hi": ipenc._graph_key(af, hi)})
    return spans


def _estate_reads(session: Any, dst: list[tuple[int, int, int]]) -> dict[str, Any]:
    """The reads of `_estate_causes`, kept in the memo of the running trace
    (`_one_estate_read`). The served prefixes and the provider prefixes of the
    uplinks take one read per trace. The routed prefixes that overlap `dst`,
    with the devices that have them, take one read per destination of a
    trace."""
    memo: dict[str, Any] | None = _ESTATE_MEMO.get()
    reads = memo.get("served") if memo is not None else None
    if reads is None:
        rows = _path._read(session, _ESTATE_PREFIXES_QUERY)
        # one answer per interface, over all its served prefixes (`_uplink_interface`)
        by_interface: dict[Any, dict[str, Any]] = {}
        for r in rows:
            entry = by_interface.setdefault(r.get("if_uid"), {**r, "cidrs": []})
            entry["cidrs"].append(r["cidr"])
        uplinks = _networks(c for r in by_interface.values() if _uplink_interface(r) for c in r["cidrs"])
        served = _networks(r["cidr"] for r in rows) - uplinks
        reads = {"served": served, "uplinks": uplinks}
        if memo is not None:
            memo["served"] = reads
    key = f"routed:{_to_cidrs(_merge(list(dst)))}"
    routed = memo.get(key) if memo is not None else None
    if routed is None:
        spans = _route_spans(dst)
        rows = _path._read(session, _ROUTED_PREFIXES_QUERY, spans=spans) if spans else []
        routed = {}
        for row in rows:
            for net in _networks([row["cidr"]]) - reads["uplinks"]:
                routed.setdefault(net, set()).update(str(d) for d in row.get("devices") or [] if d)
        if memo is not None:
            memo[key] = routed
    return {**reads, "routed": routed}


def _estate_causes(
    session: Any, dst: Iterable[tuple[int, int, int]], dev_uid: str | None = None
) -> list[tuple[str, list[tuple[int, int, int]]]]:
    """The parts of `dst` that belong to the estate, each with its cause. The
    causes are "served" (a prefix that an interface of the estate serves),
    "routed" (a route of another device), "routed-here" (a route that only
    `dev_uid` has, in another of its tables) and "private" (`NOT_INTERNET`).
    Each part is counted once, in that order. The union of the parts is `dst`
    within `estate_prefixes`."""
    dst = _merge(list(dst))
    reads = _estate_reads(session, dst)
    served = _merge(_intervals(sorted(reads["served"])))
    elsewhere = [n for n, devs in reads["routed"].items() if devs - {dev_uid}]
    here = [n for n, devs in reads["routed"].items() if not devs - {dev_uid}]
    causes = []
    left = dst
    for cause, held in (
        ("served", served),
        ("routed", _merge(_intervals(sorted(elsewhere)))),
        ("routed-here", _merge(_intervals(sorted(here)))),
        ("private", _merge(_intervals(list(NOT_INTERNET)))),
    ):
        part = _intersect(left, held) if held and left else []
        if part:
            causes.append((cause, part))
            left = _subtract(left, part)
    return causes


def _estate_part(session: Any, dst: Iterable[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    """The part of `dst` that is an address of the estate (`estate_prefixes`)."""
    dst = _merge(list(dst))
    reads = _estate_reads(session, dst)
    held = estate_prefixes(reads["served"], routed=reads["routed"], uplinks=reads["uplinks"])
    return _intersect(dst, list(held)) if held and dst else []


def _warn_estate_destination(
    session: Any,
    trail: _Trail,
    label: str,
    gw: dict[str, Any],
    route: dict[str, Any],
    dst: list[tuple[int, int, int]],
) -> None:
    """Warn that a flow sent to the edge of the estate is addressed to the
    estate, with one warning per cause (`_estate_causes`). A route is missing
    on this device, and the edge is no exit."""
    by = route.get("egress_name") or route.get("egress_uid") or "its egress interface"
    tail = f"{_dev_label(gw)} has no route to it other than the default route {route.get('cidr')} by {by}"
    for cause, part in _estate_causes(session, dst, gw.get("dev_uid")):
        whole = not _subtract(list(dst), part)
        what = f"the destination {_describe(part)}" if whole else f"{_describe(part)} of the destination"
        if cause == "served":
            fact = f"{what} is an address of the estate"
        elif cause == "routed":
            fact = f"another device of the estate has a route to {what}"
        elif cause == "routed-here":
            # a route in another table of this same device (a policy table)
            fact = f"a device of the estate has a route to {what}"
        else:
            fact = f"{what} is a private address that no device of the estate serves"
        trail.warn(f"{label}: {fact}, and {tail}")


def _estate_exit(session: Any, route: dict[str, Any], egress_uid: str | None) -> dict[str, Any] | None:
    """The internet uplink by which a route leaves the estate, or None. The
    next hop of the route is one that no collected interface holds.

    The route must be the default route of its family. It is an exit (the
    edge of the estate, decided, with the reply start on the egress interface)
    when `exit_basis` gives a basis:

    - the egress interface has a WAN link that is not MPLS (an MPLS next hop
      is the PE of the operator, which belongs in the twin)
    - for IPv4 only, the collector marks the interface as the one on which its
      access client installs the default (`ipv4_default_origin`, no IPv6 mark
      is collected)
    - the site zone of the device is "internet" and no MPLS WAN link is on the
      interface (`_site_zone_exit`)

    A more specific route, and any other interface, give a boundary with a
    warning and no reply start.

    The result has `basis` "wan-link", "access-client-default" or "site-zone".
    A "site-zone" result has the name of the block."""
    family = _DEFAULT_ROUTES.get(str(route.get("cidr")))
    if not egress_uid or family is None:
        return None
    row = _path._read_one(session, _EGRESS_UPLINK_QUERY, u=egress_uid)
    if not row:
        return None
    basis = exit_basis(
        link_kinds=[row.get("link_kind")] if row.get("link_uid") else [],
        default_origin=row.get("default_origin"),
        site_zone=row.get("site_zone"),
        family=family,
        next_hop=True,
        # An SD-WAN boundary row belongs to the overlay. The site zone gives
        # no exit for it. Its exits come from its WAN links.
        sdwan=str(route.get("kind") or "").startswith("SDWAN_"),
    )
    if basis == "wan-link":
        return {"uid": row["link_uid"], "name": row.get("link_name"), "basis": "wan-link", "site_block": None}
    if basis == "access-client-default":
        return {"uid": None, "name": None, "basis": "access-client-default", "site_block": None}
    return _site_zone_exit(row) if basis == "site-zone" else None


def _left_estate(
    gw: dict[str, Any], route: dict[str, Any], if_uid: str | None, if_name: str | None, uplink: dict[str, Any]
) -> dict[str, Any]:
    """The `left_estate` marker of a leg at the edge of the estate. It holds
    the device, the interface and the next hop that the leg leaves by, and the
    basis of the exit."""
    wan = uplink.get("basis") == "wan-link"
    next_hop = route.get("next_hop")
    return {
        "basis": uplink["basis"],
        "device_uid": gw.get("dev_uid"),
        "device": gw.get("dev_name"),
        "interface_uid": if_uid,
        "interface": if_name,
        "next_hop": str(next_hop) if next_hop else None,
        "wan_link_uid": uplink.get("uid") if wan else None,
        "wan_link": uplink.get("name") if wan else None,
        "site_block": uplink.get("site_block") if uplink.get("basis") == "site-zone" else None,
    }


def _exit_basis_words(exit_: dict[str, Any]) -> str:
    """The basis of an estate exit in plain words."""
    basis = exit_.get("basis")
    if basis == "wan-link":
        link = exit_.get("wan_link") or exit_.get("wan_link_uid")
        return f"a collected WAN link {link}" if link else "a collected WAN link"
    if basis == "access-client-default":
        return "the access client's default"
    zone = f'the operator\'s site zone "{_INTERNET_ZONE}"'
    return f"{zone} of block {exit_['site_block']}" if exit_.get("site_block") else zone


def _exit_words(exit_: dict[str, Any]) -> str:
    """One estate exit in plain words: device, interface, next hop and basis."""
    hop = f"to next hop {exit_['next_hop']}" if exit_.get("next_hop") else "with no next hop"
    where = " ".join(
        str(p) for p in (exit_.get("device") or exit_.get("device_uid"), exit_.get("interface")) if p
    )
    return f"leaves the estate at {where} {hop} ({_exit_basis_words(exit_)})"


def estate_exit(
    session: Any,
    *,
    device_uid: str,
    device_name: str | None,
    table_uid: str | None,
    route: dict[str, Any],
    egress_uid: str,
    egress_name: str | None,
    destinations: Iterable[tuple[int, int, int]] | None = None,
) -> dict[str, Any] | None:
    """The `left_estate` marker that the tracer gives a route that leaves the
    twin at `device_uid` (routing table `table_uid`) by `egress_uid`, or None
    where the tracer gives none.

    A reader outside the tracer (the impact evaluator) calls it after it has
    found that the route leaves its model there. Such a route has a next hop
    that the reader holds no interface for, or no next hop and a destination
    that the interface does not serve. The function runs the code of the
    tracer on a scratch trail and leg. A route with a next hop is an exit only
    where the owner read of the tracer finds no holder and gives no reason
    (`_next_hop_device`, `vsx.resolve`). An unheld link-local next hop is
    undecided there and is no exit. `_estate_exit` then decides. An
    interface-only route goes through `_default_route_wan_hop` and
    `_mark_twin_exit`. The function changes no trace.

    `destinations` are the addresses that the route forwards there. When any
    of them is an address of the estate (`estate_prefixes`), there is no exit,
    as in a trace (`_estate_part`)."""
    if destinations is not None and _estate_part(session, destinations):
        return None
    gw = {"dev_uid": device_uid, "dev_name": device_name}
    route = {**route, "egress_uid": egress_uid, "egress_name": egress_name}
    if route.get("next_hop"):
        leaked = route.get("next_hop_vrf") if route.get("next_hop_vrf") != table_uid else None
        owner, why = _next_hop_device(
            session, route["next_hop"], leaked or table_uid, gw, leaked=bool(leaked), egress_uid=egress_uid
        )
        target, _crossings, transit_error = vsx.resolve(session, egress_uid, route["next_hop"])
        if owner or why or target or transit_error:
            return None
        uplink = _estate_exit(session, route, egress_uid)
        return _left_estate(gw, route, egress_uid, egress_name, uplink) if uplink else None
    trail = _Trail()
    wan = _default_route_wan_hop(session, trail, route, gw)
    scope = _RouteScope(
        grp={},
        gw=gw,
        route=route,
        dst_part=[],
        dst_label=None,
        src_label="",
        nat_rows=None,
        is_ranged=False,
        sport=None,
        filter_state={},
        fw_port=None,
        considered=None,
        zone_out_if=None,
        intra_network=False,
        local_net=False,
        via_uid=egress_uid,
    )
    leg: dict[str, Any] = {}
    _mark_twin_exit(session, trail, scope, leg, wan, [])
    exit_: dict[str, Any] | None = leg.get("left_estate")
    return exit_


def _exit_key(exit_: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(exit_.get(k) or "")
        for k in ("device_uid", "interface_uid", "next_hop", "basis", "wan_link_uid", "site_block")
    )


def _leg_exits(leg: dict[str, Any]) -> list[dict[str, Any]]:
    """Every `left_estate` marker on one leg. The markers are those of the
    leg, of its carrier, of the underlay legs of the carrier and of its outer
    carriers."""
    found: list[dict[str, Any]] = []
    carriers = [leg.get("carrier"), *(leg.get("outer_carriers") or [])]
    for item in [leg, *carriers]:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("left_estate"), dict):
            found.append(item["left_estate"])
        if item is not leg:
            found += [
                cl["left_estate"] for cl in item.get("legs") or [] if isinstance(cl.get("left_estate"), dict)
            ]
    return found


def _walk_exits(legs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The distinct `left_estate` markers of a walk's legs, in a fixed order."""
    distinct = {_exit_key(e): e for leg in legs for e in _leg_exits(leg)}
    return [distinct[k] for k in sorted(distinct)]


def _walk_reach(legs: list[dict[str, Any]], ends: list[str | None], indeterminate: bool) -> str | None:
    """The end of the candidate paths of a forwarded walk. The result is
    "destination" when each path ends at the destination inside the estate,
    "left_estate" when each ends at an edge of the estate, and "split" when
    both occur. The result is None when the answer of the walk is not "true",
    or when a path has another end or an unknown end. `ends` has one entry per
    leg, None for such an end."""
    if not legs or len(ends) != len(legs) or any(e is None for e in ends):
        return None
    if walk_result([leg_result(ll) for ll in legs], legs, indeterminate).answer != "true":
        return None
    kinds = set(ends)
    return "split" if len(kinds) > 1 else kinds.pop()


def _leg_end(leg: dict[str, Any], delivered: bool) -> str | None:
    """The end of one leg. The result is "destination" when the walk delivered
    the leg inside the estate (to a network that its device serves, switched
    in the prefix of the source, or to the device). The result is
    "left_estate" at an edge of the estate, and None otherwise."""
    if leg.get("left_estate"):
        return "left_estate"
    if (delivered or leg.get("router_local")) and not leg.get("boundary"):
        return "destination"
    return None


def _exit_prose(exits: list[dict[str, Any]]) -> str:
    """The verdict suffix for the exits whose basis is the site zone of the
    operator. The result is empty for every other walk."""
    zoned = [e for e in exits if e.get("basis") == "site-zone"]
    return "".join(f" · {_exit_words(e)}" for e in zoned)


def _with_edge_keys(result: dict[str, Any]) -> dict[str, Any]:
    """`result` with `left_estate` and `reach` on each of its walks (the
    forward walk and each reply walk of a reply answer). A walk that already
    has them keeps them. A walk without them gets an empty list and null. Such
    a walk stopped before it drew a leg, or a helper outside this module built
    it (a brokered stop, a reply not derived)."""
    walks: list[Any] = [result]
    if isinstance(result.get("forward"), dict):
        replies = result.get("reply")
        walks = [result["forward"], *(replies if isinstance(replies, list) else [replies])]
    for walk in walks:
        if isinstance(walk, dict):
            walk.setdefault("left_estate", [])
            walk.setdefault("reach", None)
    return result


_PROVIDER_OF_LINK_QUERY = """
MATCH (i:Interface:Obj {uid: $u, collection_ts: $snap})-[h:HAS_IP]->(ip:IpAddress)<-[lh:HAS_IP]-(w:WanLink)
MATCH (w)-[pb:PROVIDED_BY]->(pn:ProviderNetwork)
WHERE i:Obj AND i.collection_ts = $snap
  AND h._retired_at IS NULL AND lh._retired_at IS NULL AND pb._retired_at IS NULL
  AND NOT w:Retired AND NOT pn:Retired AND w.collection_ts = $snap
RETURN w.uid AS link_uid, w.name AS link_name, w.kind AS link_kind,
       pn.uid AS provider_uid, pn.name AS provider_name, pn.kind AS provider_kind
ORDER BY w.uid LIMIT 1"""

_FAR_ADDRESS_OWNER_QUERY = """
CALL {
  MATCH (ip:IpAddress {ip: $ip})<-[h:HAS_IP]-(i:Interface)-[on:ON]->(d:Device)
  WHERE h._retired_at IS NULL AND on._retired_at IS NULL
    AND NOT ip:Retired AND NOT i:Retired AND NOT d:Retired
    AND i.collection_ts = $snap
  RETURN ip, i, d, 0 AS rank
  UNION
  // an SD-WAN link's address after NAT: no interface holds it, the far
  // edge's WanLink does, and the carrier arrives on the interface it is ON
  MATCH (ip:IpAddress {ip: $ip})<-[lh:HAS_IP]-(w:WanLink)-[won:ON]->(i:Interface)-[on:ON]->(d:Device)
  WHERE lh._retired_at IS NULL AND won._retired_at IS NULL AND on._retired_at IS NULL
    AND NOT ip:Retired AND NOT w:Retired AND NOT i:Retired AND NOT d:Retired
    AND w.collection_ts = $snap
  RETURN ip, i, d, 1 AS rank
}
WITH ip, i, d, rank
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
RETURN d.uid AS dev_uid, d.hostname AS dev_name, i.uid AS if_uid, i.name AS if_name,
       v.uid AS anchor, coalesce(ip.l3dom, v.name) AS l3dom
ORDER BY rank, d.uid, i.uid LIMIT 1"""


# The owner read of `_FAR_ADDRESS_OWNER_QUERY`, from the far node of the
# tunnel. The WAN links of several edges can hold one address after NAT, and
# the far node belongs to one edge.
_FAR_NODE_OWNER_QUERY = _FAR_ADDRESS_OWNER_QUERY.replace(
    "(ip:IpAddress {ip: $ip})", "(ip:IpAddress:Obj {uid: $far, collection_ts: $snap})"
)

# The count of the devices that hold the far end of the carrier on an
# interface (the first arm of the owner read). More than one holder is the same
# private space in two contexts or an FHRP address on both routers. An address
# of a WAN link after NAT (the second arm) is not counted. The decap stage
# matches the far tunnel for it.
_FAR_ADDRESS_HOLDERS_QUERY = """
MATCH (ip:IpAddress {ip: $ip})<-[h:HAS_IP]-(i:Interface)-[on:ON]->(d:Device)
WHERE h._retired_at IS NULL AND on._retired_at IS NULL
  AND NOT ip:Retired AND NOT i:Retired AND NOT d:Retired
  AND i.collection_ts = $snap
RETURN count(DISTINCT d) AS holders, collect(DISTINCT coalesce(d.hostname, d.uid)) AS names"""

_FAR_NODE_HOLDERS_QUERY = _FAR_ADDRESS_HOLDERS_QUERY.replace(
    "(ip:IpAddress {ip: $ip})", "(ip:IpAddress:Obj {uid: $far, collection_ts: $snap})"
)


def _far_owner(session: Any, far_uid: str | None, far_kind: str | None, endpoint: Any) -> Any:
    """The device and the interface that hold the far end of the carrier. The
    read goes through the far node of the tunnel when it has one, and by the
    address otherwise."""
    if far_uid and far_kind == "IpAddress":
        return _path._read_one(session, _FAR_NODE_OWNER_QUERY, far=far_uid)
    return _path._read_one(session, _FAR_ADDRESS_OWNER_QUERY, ip=str(endpoint))


def _far_holders(session: Any, far_uid: str | None, far_kind: str | None, endpoint: Any) -> Any:
    """The count and the names of the devices that hold the far end of the
    carrier on an interface, read as `_far_owner` reads the owner. The result
    is None when the read returns no row."""
    if far_uid and far_kind == "IpAddress":
        return _path._read_one(session, _FAR_NODE_HOLDERS_QUERY, far=far_uid)
    return _path._read_one(session, _FAR_ADDRESS_HOLDERS_QUERY, ip=str(endpoint))


@dataclass(frozen=True)
class _CarrierHop:
    """The values that `_carrier_trace` resolved for the carrier packet on
    this device, for `_carrier_walk`. They are the tunnel and its `carrier`
    record, the route to the peer and its egress, the parsed address sets, the
    port and the protocol of the carrier flow, the table of the route, the
    inner flow that resumes on the far device, and the far node of the
    tunnel."""

    gw: dict[str, Any]
    tun: dict[str, Any]
    carrier: dict[str, Any]
    route: dict[str, Any]
    egress_uid: str | None
    endpoint: Any
    src_set: list[tuple[int, int, int]]
    dst_set: list[tuple[int, int, int]]
    port: int | None
    proto: str
    rib: Any | None
    vrf: dict[str, Any] | None
    inner: dict[str, Any]
    far_kind: str | None
    far_uid: str | None
    far_name: str | None
    # The encapsulation of the tunnel and the identifier that both of its
    # halves have. The decap stage matches the Tunnel of the far device by them.
    encap: str | None = None
    pair: str | None = None


def _far_owner_start(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    hop: _CarrierHop,
    ctx: dict[str, Any],
    *,
    draw_gateway: bool,
) -> Any:
    """The device that holds the far end of the carrier, where the inner flow
    comes out. The device is recorded on `ctx`. The result is None when no
    device in the twin holds the far end. The leg is then a boundary, and with
    `draw_gateway` a far node that is a cloud SD-WAN gateway is drawn as the
    last hop."""
    owner = _far_owner(session, hop.far_uid, hop.far_kind, hop.endpoint)
    if owner is None:
        if draw_gateway and hop.far_kind == "SdwanGateway" and hop.far_uid:
            trail.hop(
                hop.far_uid,
                "SdwanGateway",
                hop.far_name or "SD-WAN gateway",
                "cloud gateway; beyond the twin",
                stage=Stage.CARRIER_ROUTE,
            )
        leg["boundary"] = True
        hop.carrier["verdict"] = (
            f"{hop.carrier['verdict']}; far end {hop.endpoint} not held by any device in the twin"
        )
        return None
    # More than one device can hold the address on an interface (the same
    # private space in two contexts, an FHRP address on both routers). The
    # carrier is drawn to the first device by uid, and the leg is
    # indeterminate. An address after NAT that WAN links hold is not counted
    # (`_FAR_ADDRESS_HOLDERS_QUERY`). A read with no row counts as one holder.
    held = _far_holders(session, hop.far_uid, hop.far_kind, hop.endpoint) or {}
    if (held.get("holders") or 1) > 1:
        leg["indeterminate"] = True
        trail.warn(
            f"{hop.tun['name']}: the carrier's far end {hop.endpoint} is held by "
            f"{held['holders']} devices ({', '.join(str(n) for n in held.get('names') or [])}); "
            f"the carrier is drawn to {owner.get('dev_name') or owner['dev_uid']}, and which of them "
            "it reaches is NOT established"
        )
    # The inner flow comes out on this device.
    ctx["far_dev"] = owner["dev_uid"]
    return owner


def _carrier_walk(session: Any, trail: _Trail, leg: dict[str, Any], hop: _CarrierHop) -> None:
    """The path of the carrier packet beyond this device. It goes through the
    next-hop device and every device after it, to the device that holds the
    far address of the tunnel, where the decap stage resumes the inner flow.

    The encapsulated packet is an ordinary flow from here on (source the WAN
    address of this device, destination the peer, the carrier protocol and
    port). It goes through the device walk of every flow, with dNAT, PBR,
    routing, filters and sNAT on every device that it crosses. The context
    pushed on `trail.carrier_stack` marks it as a carrier. Every hop recorded
    during the walk has the marks of the context. The decap stage
    (`_group_legs`, the router-local branch) reads the context to select the
    inner flow that resumes on the far device, and stores the continuation in
    `resumed`. A walk that does not reach the far address, or that is blocked
    on the way, leaves `resumed` empty, and the verdict of the carrier has the
    reason.

    A public WAN link ends on a network that does not belong to the operator
    (`ProviderNetwork` of kind `internet`). The walk writes one hop on the
    provider node and resumes on the device that holds the far address, if
    the twin has it. The next hop of an MPLS link is the PE of the operator
    and is walked like any other device.
    """
    gw, tun, carrier, endpoint = hop.gw, hop.tun, hop.carrier, hop.endpoint
    next_hop = hop.route.get("next_hop")
    provider = _path._read_one(session, _PROVIDER_OF_LINK_QUERY, u=hop.egress_uid) if hop.egress_uid else None
    depth = trail.depth
    ctx = {
        "tunnel_uid": tun["uid"],
        "tunnel_name": tun["name"],
        "far_ip": str(endpoint),
        "encap": hop.encap,
        "pair": hop.pair,
        # The source of the carrier. The far Tunnel has this address as its endpoint.
        "local": carrier.get("src"),
        "inner": hop.inner,
        "resumed": [],
        "next_lane": None,
    }
    trail.carrier_stack.append(ctx)
    try:
        if provider and provider.get("provider_kind") == "internet":
            # The provider network is one hop. The walk resumes on the far side if the twin holds it.
            trail.hop(
                provider["provider_uid"],
                "ProviderNetwork",
                provider["provider_name"] or "internet",
                f"{provider['link_kind'] or 'dia'} link {provider['link_name'] or ''}; "
                "the provider's path is not collected",
                stage=Stage.LINK,
            )
            start = _far_owner_start(session, trail, leg, hop, ctx, draw_gateway=True)
            if start is None:
                return
            carrier["provider"] = provider["provider_name"]
        elif next_hop:
            nh_dev, why = _next_hop_device(
                session, next_hop, hop.vrf["vrf_uid"] if hop.vrf else None, gw, egress_uid=hop.egress_uid
            )
            if why or not nh_dev:
                leg["boundary"] = True
                # The rule of the next hop of a flow applies (`_estate_exit`).
                # Beyond a collected uplink the carrier leaves the estate at
                # its edge. Any other unknown next hop is a boundary with a
                # warning.
                uplink = None if why else _estate_exit(session, hop.route, hop.egress_uid)
                inside = _estate_part(session, hop.dst_set) if uplink is not None else []
                if inside:
                    # The carrier is addressed to the estate. A route is missing on this device.
                    _warn_estate_destination(session, trail, tun["name"], gw, hop.route, hop.dst_set)
                    uplink = None
                if uplink is not None:
                    exit_ = _left_estate(gw, hop.route, hop.egress_uid, hop.route.get("egress_name"), uplink)
                    carrier["left_estate"] = exit_
                    leg["left_estate"] = exit_
                    if uplink["basis"] == "site-zone":
                        trail.notes.append(
                            f"{tun['name']}: carrier next hop {next_hop}: {_exit_words(exit_)}"
                        )
                    else:
                        trail.notes.append(
                            f"{tun['name']}: carrier next hop {next_hop} is beyond the collected "
                            f"uplink {uplink.get('name') or hop.route.get('egress_name') or ''}".rstrip()
                        )
                    carrier["verdict"] = f"{carrier['verdict']}; next hop {next_hop} beyond the twin's edge"
                    return
                reason = why or "is not held by any interface in the graph"
                trail.warn(f"{tun['name']}: carrier next hop {next_hop} {reason}")
                carrier["verdict"] = f"{carrier['verdict']}; next hop {next_hop} not in the twin"
                return
            start = nh_dev
            _warn_context_crossing(trail, leg, nh_dev, tun["name"])
            _warn_carrier_tie(trail, leg, nh_dev, next_hop, tun["name"])
            if provider:
                carrier["provider"] = provider["provider_name"]
        else:
            start = _far_owner_start(session, trail, leg, hop, ctx, draw_gateway=False)
            if start is None:
                return
        trail.depth = depth + 1
        _mtu_crossing(trail, start["if_uid"], enforcement="l3", direction="rx")
        _draw_arrival(trail, start)
        gw2: dict[str, Any] = {
            "dev_uid": start["dev_uid"],
            "dev_name": start["dev_name"],
            "if_uid": start["if_uid"],
            "if_name": start["if_name"],
            "l3dom": start.get("l3dom") or gw.get("l3dom"),
            "anchor": start.get("anchor") or gw.get("anchor"),
        }
        carrier_legs, next_lane = _device_stage(
            session,
            trail,
            gw2,
            hop.src_set,
            hop.dst_set,
            hop.port,
            hop.proto,
            trail.lane,
            hop.rib,
            depth + 1,
            frozenset({gw["dev_uid"]}),
            max_hops=trail.max_hops,
        )
    finally:
        trail.carrier_stack.pop()
        trail.depth = depth
    carrier["legs"] = [
        {
            k: v
            for k, v in cl.items()
            if k
            in (
                "verdict",
                "blocked",
                "indeterminate",
                "boundary",
                "cidr",
                "egress_name",
                "next_hop",
                "fw_uid",
                "left_estate",
            )
        }
        for cl in carrier_legs
    ]
    carrier["next_lane"] = next_lane
    blocked = next((cl for cl in carrier_legs if cl.get("blocked")), None)
    if blocked is not None:
        carrier["verdict"] = blocked.get("verdict") or "BLOCKED on the carrier path"
        leg["blocked"] = True
        leg["blocking_uid"] = blocked.get("blocking_uid") or blocked.get("fw_uid")
        trail.warn(f"{tun['name']}: carrier packet blocked on its way to {endpoint}: {carrier['verdict']}")
        return
    if any(cl.get("indeterminate") for cl in carrier_legs):
        leg["indeterminate"] = True
    if ctx.get("arrival"):
        carrier["arrival"] = ctx["arrival"]
        if ctx["arrival"].get("indeterminate"):
            # the far end's input chain did not decide the carrier (`_decap_stage`)
            leg["indeterminate"] = True
    if ctx["resumed"]:
        carrier["resumed"] = ctx["resumed"]
        carrier["verdict"] = f"{carrier['verdict']}; decapsulated on {ctx.get('far_dev_name') or endpoint}"
    else:
        leg["boundary"] = leg.get("boundary") or any(cl.get("boundary") for cl in carrier_legs)
        # The carrier left the estate at its edge on a later device. The inner
        # flow ends there when every underlay leg ends at such an edge.
        if carrier_legs and all(cl.get("left_estate") for cl in carrier_legs) and not leg.get("left_estate"):
            leg["left_estate"] = _walk_exits(carrier_legs)[0]
        carrier["verdict"] = f"{carrier['verdict']}; far end {endpoint} not reached in the twin"


def _record_dnat_hop(trail: _Trail, nat_part: dict[str, Any], src_label: str) -> None:
    """This group's dNAT decision, recorded as a pre-fork hop."""
    r = nat_part["rule"]
    if r.get("exclude"):
        trail.hop(r["uid"], "NatRule", f"dNAT rule {r['pos']}", "excluded, no translation", stage=Stage.DNAT)
    elif r.get("opaque"):
        trail.hop(r["uid"], "NatRule", f"dNAT rule {r['pos']}", "match undecidable", stage=Stage.DNAT)
        reason = r.get("role_note") or "translation not determinable"
        trail.warn(f"{src_label}: dNAT {r['rb_name']} rule {r['pos']} matched, {reason}")
    elif r["rewrite"] == "src":
        # ingress source rewrite (Cisco outside-source)
        trail.hop(
            r["uid"],
            "NatRule",
            f"NAT rule {r['pos']}",
            f"src → {_describe(nat_part['new_src'])}",
            stage=Stage.DNAT,
        )
    else:
        # `port_translated` of the part is set when the rule rewrote the port.
        # A ranged PAT pool rewrites the port and leaves the scalar
        # `xlate_port` column empty.
        translated = nat_part.get("port_translated")
        if translated and nat_part["port"] is not None:
            port_text = f":{nat_part['port']}"
        elif translated and nat_part.get("new_port_subset"):
            port_text = ":" + ",".join(
                str(lo) if lo == hi else f"{lo}-{hi}" for _, lo, hi in nat_part["new_port_subset"]
            )
        else:
            port_text = ""
        to = _describe(nat_part["new_dst"]) + port_text
        trail.hop(r["uid"], "NatRule", f"dNAT rule {r['pos']}", f"→ {to}", stage=Stage.DNAT)


_VRF_NAME_QUERY = "MATCH (v:VrfInstance {uid: $u}) WHERE v:Obj AND v.collection_ts = $snap RETURN v.name AS n"

_RIB_MIRRORED_QUERY = (
    "MATCH (v:VrfInstance {uid: $u}) WHERE v:Obj AND v.collection_ts = $snap RETURN v.rib_mirrored AS m"
)


def _rib_mirrored(session: Any, table_uid: str | None) -> bool:
    """Whether the collector mirrored the whole RIB of `table_uid` into the graph
    in this run (`VrfInstance.rib_mirrored`). A graph without the property reads
    as not mirrored."""
    if not table_uid:
        return False
    row = _path._read_one(session, _RIB_MIRRORED_QUERY, u=table_uid)
    return bool(row) and row["m"] is True


def _vrf_name(session: Any, table_uid: str | None) -> str | None:
    """A routing table's display name, or None when it has none recorded."""
    if not table_uid:
        return None
    row = _path._read_one(session, _VRF_NAME_QUERY, u=table_uid)
    return row["n"] if row else None


# A dynamic routing process (BGP, OSPF) in the VRF of the table. It is a source
# of routes that the graph does not hold when no RIB is recorded for the device.
_DYNAMIC_ROUTING_QUERY = """
MATCH (rp:RoutingProcess)-[iv:IN_VRF]->(v:VrfInstance {uid: $u})
WHERE v:Obj AND v.collection_ts = $snap
  AND iv._retired_at IS NULL AND NOT rp:Retired AND rp.collection_ts = $snap
RETURN rp.proto AS proto ORDER BY rp.uid LIMIT 1"""


def _runs_dynamic_routing(session: Any, table_uid: str | None) -> bool:
    """Whether a dynamic routing process runs in the VRF of this table. The
    result is True for a table with no uid."""
    if not table_uid:
        return True
    return _path._read_one(session, _DYNAMIC_ROUTING_QUERY, u=table_uid) is not None


def _record_table_hops(session: Any, trail: _Trail, grp: dict[str, Any], table_note: str) -> str | None:
    """The PBR gate and routing-table hops for this group, in the pre-fork
    spine. Returns the table's display name for the RIB lookup."""
    if grp["pol_uid"]:
        trail.hop(grp["pol_uid"], "PbrPolicy", grp["pol_name"], "PBR gate", stage=Stage.PBR_POLICY)
        # After a fall-through, the target of the rule in the hop note differs
        # from the table that routes the flow.
        trail.hop(
            grp["rule_uid"],
            "FwRule",
            f"rule {grp['pos']}" + (f" ({grp['rule_name']})" if grp["rule_name"] else ""),
            f"→ {grp.get('pbr_target_desc') or grp['table_name']}",
            stage=Stage.PBR_RULE,
        )
    vrf_name = None
    if grp["table_uid"]:
        vrf_name = _vrf_name(session, grp["table_uid"])
        trail.hop(grp["table_uid"], "VrfInstance", vrf_name or "table", table_note, stage=Stage.VRF)
    return vrf_name


def _replay_hops(trail: _Trail, hops: list[dict[str, Any]]) -> None:
    """Re-record pre-fork hops into the lane the trail is now on.

    The hops keep uid, kind, label, note and stage. `rank_hops` puts them in
    the column of the original.
    """
    for h in hops:
        before = len(trail.hops)
        trail.hop(h["uid"], h["kind"], h["label"], h["note"], stage=Stage[h["stage"]])
        if len(trail.hops) > before:
            trail.hops[-1].update({k: h[k] for k in ("forwarding_visit", "virtual_context") if k in h})


def _prefix_len(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except ValueError:
        return -1


def _replay_upstream(trail: _Trail, hops: list[dict[str, Any]]) -> None:
    """Copy the hops of a lane from earlier devices into the current lane of
    the trail, each at its own pipeline position."""
    # The list is built before any hop is added. Two equal hops of `hops` are both copied.
    fresh = [h for h in hops if not trail.has_replayed(h)]
    for h in fresh:
        trail.append_hop({**h, "lane": trail.lane, "shared": False})


def _record_route_match(
    trail: _Trail,
    best: list[dict[str, Any]],
    src_label: str,
    dev_uid: str,
    table_uid: str | None,
) -> None:
    """The winning route as a hop, plus a note when it came from the side store."""
    # The label of LEARNED_ROUTE is "dynamic route". The label of an ECMP route has "N paths".
    kind_label = {"LEARNED_ROUTE": "dynamic route"}.get(
        best[0]["kind"], best[0]["kind"].lower().replace("_", " ")
    )
    # A side-store-only route has no Prefix node and no uid. The hop gets the
    # local uid rib:<device>:<table>:<cidr>, because _Trail.hop drops a hop with no uid.
    #
    # best[0]["uid"] stays unset for the side-store guard of _resolve_route_egress.
    hop_uid = best[0]["uid"] or f"rib:{dev_uid}:{table_uid or 'default'}:{best[0]['cidr']}"
    trail.hop(
        hop_uid,
        "Prefix",
        best[0]["cidr"],
        kind_label + (f" · {len(best)} paths" if len(best) > 1 else ""),
        stage=Stage.ROUTE,
    )
    if best[0].get("rib") and not best[0].get("uid"):
        via = (
            f" via {best[0]['egress_name'] or best[0]['next_hop']}"
            if len(best) == 1
            else f" ({len(best)} paths)"
        )
        trail.notes.append(f"{src_label}: rib matched {best[0]['cidr']}{via}")


def _resolve_route_egress(
    session: Any,
    trail: _Trail,
    route: dict[str, Any],
    gw: dict[str, Any],
    src_label: str,
    table_uid: str | None = None,
) -> tuple[dict[str, Any], str | None, bool, bool]:
    """Resolve this route's egress interface on the gateway device.

    Returns the route with its egress resolved, the remote gateway interface whose
    zone applies when no local egress exists, and the intra-network and
    local-delivery flags.
    """
    if not route["egress_uid"] and route["ifname"]:
        # The interface name of the store row is resolved on the gateway
        # device. The firewall and the Interface hop of the leg use the result.
        named = _path._read_one(
            session,
            _IFACE_BY_NAME_QUERY,
            name=route["ifname"],
            dev=gw["dev_uid"],
            vrf=table_uid,
        )
        if named:
            route = {**route, "egress_uid": named["uid"], "egress_name": named["name"]}
    # out_if for policy evaluation only, set when the destination's gateway
    # interface is on another device
    zone_out_if: str | None = None
    intra_network = False
    delivers_local = False
    # `route["uid"]` excludes the side-store rows. They have no Prefix node
    # for GATEWAY_FOR.
    if not route["egress_uid"] and route["uid"]:
        # A connected prefix has no VIA edge. Its egress is the router
        # interface that serves the prefix.
        found = _connected_egress(session, route["uid"], gw["dev_uid"], gw["if_uid"])
        if found and found["ingress"]:
            # no L3 egress and no zone boundary
            intra_network = True
            trail.notes.append(
                f"{src_label}: {route['cidr']} is served by the ingress interface: "
                "intra-network, no zone boundary to evaluate"
            )
        elif found and not found["remote"]:
            route = {**route, "egress_uid": found["uid"], "egress_name": found["name"]}
            delivers_local = True
        elif found:
            zone_out_if = found["uid"]
            trail.notes.append(
                f"{src_label}: {route['cidr']} is served by {found['name']} on another "
                "device; its zone policy is consulted but no local egress is asserted"
            )
            if found.get("remote_count", 1) > 1:
                trail.notes.append(
                    f"{src_label}: {found['remote_count']} interfaces on other devices serve "
                    f"{route['cidr']}; the zone of {found['name']} (lowest uid) was consulted"
                )
    return route, zone_out_if, intra_network, delivers_local


def _build_route_leg(
    trail: _Trail,
    grp: dict[str, Any],
    route: dict[str, Any],
    lane: int,
    src_label: str,
    dst_label: str | None,
    dev_uid: str | None = None,
) -> dict[str, Any]:
    """The leg record for one candidate route, before the gates are evaluated."""
    nat_part = grp.get("nat")
    leg: dict[str, Any] = {
        "lane": lane,
        "sources": _to_cidrs(grp["sources"]),
        "cidr": route["cidr"],
        "egress": route["egress_name"],
        "next_hop": route["next_hop"],
        "blocked": False,
        # the leg of an undecided PBR claim is indeterminate
        "indeterminate": bool((nat_part and nat_part["rule"].get("opaque")) or grp.get("opaque")),
        "table": grp["table_name"],
        "src_label": src_label,
        "gid": grp.get("gid"),
        "context_uid": grp.get("table_uid"),
        # The device whose table this leg leaves. A reader uses it to locate a
        # block or an undecided leg.
        "device_uid": dev_uid,
    }
    if "reply_nat_undone" in grp:
        leg["reply_nat_undone"] = list(grp["reply_nat_undone"])
    if grp.get("checkpoint_manual_nat"):
        leg["checkpoint_nat_selection"] = (
            nat_part["rule"]["uid"] if nat_part and nat_part["rule"].get("checkpoint_manual") else None
        )
    if grp.get("opaque"):
        why = grp.get("opaque_reason") or "the rule's service criteria could not be evaluated"
        leg["indeterminate_reason"] = why
        trail.warn(
            f"{src_label}: PBR {grp['pol_name']} rule {grp['pos']} claims this flow but "
            f"could not be decided: {why}. The table it steers to is NOT confirmed."
        )
    if route.get("derived"):
        # a reasoner-materialized LEARNED_ROUTE has no next_hop/interface
        trail.notes.append(
            f"{route['cidr']} learned via route-target {route['via_rt']} "
            "(derived from config, not an observed RIB)"
        )
        # No collected row confirms that the device installed this route.
        leg["indeterminate"] = True
        leg.setdefault(
            "indeterminate_reason",
            f"{route['cidr']} is a route derived from route-target {route['via_rt']}, not a row read "
            "off the device",
        )
        trail.warn(
            f"{src_label}: {route['cidr']} is a route the reasoner derived from route-target "
            f"{route['via_rt']}, not a row read off the device; the forwarding decision on "
            "this leg is NOT confirmed"
        )
    if route.get("unconfirmed"):
        # A config-only static route that the RIB of the device does not hold
        # (gates/routing.py `_mark_unconfirmed`). The RIB was read and it
        # answered for this table. The warning has the observed answer
        # (`route["unconfirmed"]`).
        via = route.get("next_hop") or route.get("egress_name") or route.get("discard")
        # a connected prefix or an aggregate is marked the same way
        what = (
            "connected prefix (its interface may be down or disabled)"
            if route.get("kind") == "ORIGINATES"
            else "BGP aggregate (no contributing route may be present)"
            if route.get("kind") == "AGGREGATE"
            else "config-only static route"
        )
        leg["indeterminate"] = True
        leg.setdefault(
            "indeterminate_reason",
            f"{route['cidr']} is a {what} that the RIB of table {grp['table_name']} does not hold",
        )
        trail.warn(
            f"{src_label}: {route['cidr']} is a {what}"
            + (f" via {via}" if via else "")
            + f" that the RIB of table {grp['table_name']} does not hold; the RIB "
            f"{route['unconfirmed']}, so the forwarding decision on this leg is NOT confirmed"
        )
    if nat_part and not nat_part["rule"].get("exclude"):
        # `dnat` is a list, like `snat`. A flow can be destination-translated
        # on more than one device of a path, and the leg keeps every translation.
        leg["dnat"] = [
            {
                "to": _to_cidrs(nat_part["new_dst"]),
                "port": nat_part["port"],
                "rule_uid": nat_part["rule"]["uid"],
            }
        ]
        if dev_uid:
            # the same translation in the form a reply walk undoes
            leg["nat_chain"] = [
                *leg.get("nat_chain", []),
                _nat_step(
                    dev_uid,
                    "dnat",
                    nat_part,
                    rule_uid=nat_part["rule"]["uid"],
                    context_uid=grp.get("table_uid"),
                ),
            ]
    if dst_label:
        leg["dst_label"] = dst_label
    return leg


def _note_unjudged_zone_pair(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    in_if: str,
    out_if: str | None,
    src_label: str,
) -> None:
    """Handles a zoned device for which the firewall produced no verdict.

    - Ingress and egress in the same zone: zone policy does not apply, and a
      note is added.
    - Ingress in a zone, egress in no zone or unresolved: the pair cannot be
      formed, and VyOS does not forward such traffic by default. The leg is
      indeterminate with a warning.
    - No zone on the ingress: the device is not zoned, and nothing is written.
    """
    src_zone = _zone_of(session, in_if)
    if not src_zone:
        return
    dst_zone = _zone_of(session, out_if)
    if dst_zone and dst_zone["name"] == src_zone["name"]:
        trail.notes.append(
            f"{src_label}: ingress and egress are both in zone {src_zone['name']}; "
            "zone policy applies between zones only"
        )
        return
    leg["indeterminate"] = True
    where = "the egress interface is in no zone" if out_if else "egress interface unresolved"
    trail.warn(
        f"{src_label}: zone firewall present (zone {src_zone['name']}) but not "
        f"evaluated: {where}. The flow is NOT confirmed permitted."
    )


def _record_filter_view(leg: dict[str, Any], view: str) -> None:
    """Record the view on the leg and on its dNAT entries.

    `leg["filter_view"]` is the view of the device that decided the filter
    verdict of this leg. `_merge_upstream_leg` folds the leg of an upstream
    device into the far leg, and one key cannot hold the views of two devices.
    The view is also set on each dNAT entry of the leg. A dNAT entry keeps its
    position in the ordered list across the merge.
    """
    leg["filter_view"] = view
    for entry in leg.get("dnat") or ():
        entry.setdefault("filter_view", view)


def _filter_dst(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    grp: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    port: Any,
    src_label: str,
) -> tuple[list[tuple[int, int, int]], Any]:
    """The destination and the port on which the access policy of this device
    is evaluated.

    `port` is the port value of the flow: a scalar, `None`, or the spec of the
    narrowed region of a ranged query. The function does not parse it.

    The order of destination NAT and the filter is a property of the device.
    The netfilter forwarding path translates the destination in PREROUTING,
    and the filter sees the translated packet. A Check Point gateway matches
    its access policy on the original packet. The order is derived from the
    vendor with which the access rulebase of the device was collected.

    A destination rewrite can include a port rewrite. A policy on the original
    destination is evaluated on the original port (`orig_port`).

    A group whose dNAT part did not change the destination (no rule, an
    exclude rule, or an ingress source rewrite) returns `dst_part` and `port`.
    """
    xlated = grp.get("nat_dst")
    if not xlated:
        return dst_part, port
    view, reason = (
        ("original", None)
        if gw.get("vsx_kind") in {"virtual-system", "bridge"}
        else _device_filter_view(session, trail, gw["dev_uid"])
    )
    if view == _UNGOVERNED_VIEW:
        return dst_part, port
    if view is None:
        leg["indeterminate"] = True
        trail.warn(
            f"{src_label}: {reason}, so where this device's filter sits relative to its own "
            "destination NAT could not be derived; the policy was evaluated on the "
            "translated destination"
        )
        return dst_part, port
    if view != "original":
        _record_filter_view(leg, "translated")
        return dst_part, port
    # The original destination can be recovered only for the whole translated
    # set. The translation is many-to-one in the general case. For a part of
    # the translated set, the matching part of the original destination cannot
    # be reconstructed. PBR narrows the set (the groups are built from
    # `_pbr_partition` over the translated destination) and the route
    # partition narrows it.
    if grp["dst"] != xlated:
        split = "a PBR rule claims only part of the translated destination"
    elif dst_part != xlated:
        split = "the translated destination is split across more than one route"
    else:
        _record_filter_view(leg, "original")
        return grp["orig_dst"], grp.get("orig_port")
    leg["indeterminate"] = True
    trail.warn(
        f"{src_label}: {split}, so the original destination this device's policy matches "
        "on could not be reconstructed for this part; the policy was evaluated on the "
        "translated destination"
    )
    return dst_part, port


# The 3 ways to find a Tunnel at an egress interface are unioned inside a
# subquery. The ORDER BY after the subquery applies to the whole union. After a
# bare `UNION`, a trailing ORDER BY belongs to the RETURN of the last branch.
# The query returns every candidate. A WireGuard interface ends one Tunnel per
# peer, and `_select_tunnel` picks the peer by its allowed IPs.
_EGRESS_TUNNEL_QUERY = """
CALL {
  MATCH (t:Tunnel:Obj)-[e:ENDPOINT]->(eif:Interface {uid: $u})
  WHERE eif:Obj AND eif.collection_ts = $snap
    AND e._retired_at IS NULL AND NOT t:Retired AND t.collection_ts = $snap
    // an SD-WAN WAN interface ends several tunnels (one per far edge and
    // gateway); the boundary's candidate route names the one this leg takes
    AND ($tunnel IS NULL OR t.uid = $tunnel)
    // with no tunnel named, a VCMP tunnel is the route's only when its far
    // end is the route's next hop: a static route toward the WAN gateway
    // leaves by the same interface and rides no tunnel
    AND (coalesce(t.encap, '') <> 'velocloud-vcmp' OR $tunnel IS NOT NULL OR EXISTS {
      MATCH (t)-[tr:TERMINATES_ON]->(far:IpAddress)
      WHERE tr._retired_at IS NULL AND NOT far:Retired
        AND far.collection_ts = $snap AND far.ip = $far
    })
  RETURN t, 'endpoint' AS binding, null AS via
  UNION
  // a ZIA GRE/IPsec tunnel has no ENDPOINT edge: the on-prem side is a
  // `source_ip` property, matched here against the egress interface's own
  // collected address. That
  // address is the customer's public one, which a physical WAN interface
  // holds, so the match names the tunnel only on a tunnel interface; anywhere
  // else it is a 'source' binding the caller does not draw
  MATCH (eif:Interface {uid: $u})-[h:HAS_IP]->(ip:IpAddress)
  WHERE eif:Obj AND eif.collection_ts = $snap
  MATCH (t:Tunnel:Obj {source_ip: ip.ip, collection_ts: $snap})
  WHERE h._retired_at IS NULL AND NOT ip:Retired AND NOT t:Retired
    AND t.collection_ts = $snap
  RETURN t, CASE WHEN coalesce(eif.kind, '') IN ['tunnel', 'vti', 'wireguard']
                 THEN 'tunnel' ELSE 'source' END AS binding, null AS via
  UNION
  // a router's GRE or IPsec tunnel interface toward ZIA holds the ZIA inside
  // range, not the public address: the router's own Tunnel ENDPOINT on the
  // interface sources the ZIA tunnel when its local address is the ZIA
  // tunnel's source_ip, of the same encapsulation, and its far end is one of
  // the ZIA tunnel's VIPs where ZIA names any. The ZIA tunnel is the one
  // this egress rides, in place of the router's own ('carried', `via`)
  MATCH (rt:Tunnel:Obj)-[e:ENDPOINT]->(eif:Interface {uid: $u})
  WHERE eif:Obj AND eif.collection_ts = $snap
    AND e._retired_at IS NULL AND NOT rt:Retired AND rt.collection_ts = $snap
    AND rt.local_address IS NOT NULL
  MATCH (t:Tunnel:Obj {source_ip: rt.local_address, collection_ts: $snap})
  WHERE NOT t:Retired AND t.uid <> rt.uid AND t.encap = rt.encap
    AND (NOT EXISTS {
           MATCH (t)-[v0:TERMINATES_ON]->(:ZscalerDc)
           WHERE v0._retired_at IS NULL AND v0.vip IS NOT NULL
         }
         OR EXISTS {
           MATCH (t)-[v1:TERMINATES_ON]->(:ZscalerDc)
           WHERE v1._retired_at IS NULL AND v1.vip = rt.endpoint
         })
  RETURN t, 'carried' AS binding, rt.uid AS via
}
RETURN t.uid AS uid, t.name AS name, t.encap AS encap, t.allowed_ips AS allowed_ips,
       binding, via
ORDER BY uid, binding"""


def _select_tunnel(
    rows: list[dict[str, Any]], dst_part: list[tuple[int, int, int]], egress: str
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """The Tunnel that a flow toward `dst_part` takes out of the egress
    interface `egress`, among the candidates of `_EGRESS_TUNNEL_QUERY`. Returns
    (tunnel, the reason why the choice is not decided, the reason why the
    interface drops the flow).

    WireGuard sends a packet to the peer whose allowed IPs hold its
    destination by longest prefix, and drops it when no peer has it. The
    impact engine makes the same selection
    (`gates.tunnel._wireguard_regions`). One candidate is the tunnel. The
    choice is undecided for a destination split across peers or across a peer
    and no peer, for a tie at one prefix, for a peer whose allowed IPs were
    not collected, and for more than one tunnel of another kind. The first
    candidate by uid among those in question is returned."""
    if not rows:
        return None, None, None
    wireguard = all(str(r.get("encap") or "").lower() == "wireguard" for r in rows)
    if not wireguard:
        if len(rows) == 1:
            return rows[0], None, None
        names = ", ".join(str(r.get("name") or r["uid"]) for r in rows)
        return (
            rows[0],
            f"{len(rows)} tunnels end on {egress} ({names}); the one this flow rides is not decided",
            None,
        )
    unknown = [r for r in rows if r.get("allowed_ips") is None]
    if unknown:
        if len(rows) == 1:
            return rows[0], None, None
        names = ", ".join(str(r.get("name") or r["uid"]) for r in unknown)
        return rows[0], f"the allowed IPs of WireGuard peer {names} on {egress} were not collected", None
    dst = _merge(dst_part)
    regions, ambiguous, unread, _known = _wireguard_regions(rows, FlowRegion.from_query(dst, dst))
    if unread:
        names = ", ".join(str(rows[i].get("name") or rows[i]["uid"]) for i in sorted(unread))
        return (
            rows[min(unread)],
            f"the allowed IPs of WireGuard peer {names} on {egress} could not be read",
            None,
        )
    if not regions:
        return None, None, f"no WireGuard peer on {egress} allows {_describe(dst)}"
    chosen = sorted(regions)
    names = ", ".join(str(rows[i].get("name") or rows[i]["uid"]) for i in chosen)
    covered = _merge([ival for i in chosen for rect in regions[i] for ival in rect.dst])
    if ambiguous:
        tied = ", ".join(str(rows[i].get("name") or rows[i]["uid"]) for i in sorted(ambiguous))
        return (
            rows[chosen[0]],
            f"WireGuard peers {tied} on {egress} allow {_describe(dst)} at the same prefix",
            None,
        )
    if len(chosen) > 1:
        return (
            rows[chosen[0]],
            f"{_describe(dst)} spans the allowed IPs of WireGuard peers {names} on {egress}",
            None,
        )
    rest = _subtract(dst, covered)
    if rest:
        return (
            rows[chosen[0]],
            f"WireGuard peer {names} on {egress} allows only part of {_describe(dst)}; "
            f"no peer allows {_describe(rest)}, which WireGuard drops",
            None,
        )
    return rows[chosen[0]], None, None


def _source_binding_note(
    trail: _Trail, src_label: str, route: dict[str, Any], unbound: list[dict[str, Any]]
) -> str | None:
    """Handles the tunnels whose source address the egress interface holds
    while it is not a tunnel interface. No tunnel is drawn. The flow takes
    such a tunnel only if a tunnel interface or a crypto map selects it. A GRE
    packet needs a tunnel interface, and a GRE tunnel gives a note only. A
    policy on the physical interface can select an IPsec tunnel, and the
    function returns the reason that leaves the leg undecided."""
    names = ", ".join(str(r.get("name") or r["uid"]) for r in unbound)
    note = f"{route['egress_name']} sources tunnel {names}; whether this flow rides it is not in the snapshot"
    if any(str(r.get("encap") or "").lower() == "ipsec" for r in unbound):
        return note
    trail.notes.append(f"{src_label}: {note}")
    return None


def _egress_snat_tunnel(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    sources: list[tuple[int, int, int]],
    snat_port: Any,
    snat_proto: Any,
    src_label: str,
    nat_rows: list[dict[str, Any]] | None,
    rib: Any | None,
    region: FlowRegion | None = None,
    conn_state: str = "new",
) -> tuple[bool, list[tuple[int, int, int]]]:
    """Source NAT, the outbound interface ACL, the egress hop and any tunnel
    beyond it. This part of a local-egress leg is the same for one firewall
    verdict and for one of several regions. Returns (denied by the outbound
    ACL, downstream source set).

    POSTROUTING runs after FORWARD and before the packet leaves, and source
    NAT is applied there. An outbound interface ACL runs after the translation
    on IOS-XE and is evaluated here on the translated source
    (`_apply_egress_acl`). A deny ends the leg before the egress hop.
    `conn_state` is the state of the reply walk for that read.

    `region` is the `FlowRegion` of the leg on the region path. The source NAT
    stage decides its rules on the whole service rectangle of the leg.
    `region` is `None` for a point leg.
    """
    downstream_src = sources
    if trail.reply_nat_chain is not None:
        downstream_src = _undo_reply_nat_hops(trail, trail.reply_nat_chain, leg, gw, sources)
    # The role is read once. The carrier trace uses it for its source NAT.
    ingress_role = _iface_nat_role(session, gw.get("if_uid")) if nat_rows else None
    if nat_rows:
        downstream_src = _apply_snat(
            session,
            trail,
            leg,
            nat_rows,
            route["egress_uid"],
            route["egress_name"],
            sources,
            dst_part,
            snat_port,
            snat_proto,
            src_label,
            ingress_role=ingress_role,
            egress_role=_iface_nat_role(session, route.get("egress_uid")),
            device_uid=gw["dev_uid"],
            region=region,
        )
    outbound = _apply_egress_acl(
        session,
        trail,
        leg,
        gw,
        route,
        downstream_src,
        dst_part,
        snat_port,
        snat_proto,
        src_label,
        conn_state=conn_state,
        region=region,
    )
    if outbound == DENY:
        return True, downstream_src
    trail.hop(route["egress_uid"], "Interface", route["egress_name"], "egress", stage=Stage.EGRESS_IF)
    # An SD-WAN direct exit leaves by a WAN interface that ends overlay
    # tunnels, and it takes none of them.
    rows = (
        []
        if route.get("kind") == "SDWAN_DIRECT"
        else _path._read(
            session,
            _EGRESS_TUNNEL_QUERY,
            u=route["egress_uid"],
            tunnel=route.get("tunnel_uid"),
            far=route.get("next_hop"),
        )
    )
    # A source-address match on an interface that is not a tunnel interface
    # gives no tunnel candidate. A tunnel that another binding also found
    # stays a candidate.
    bound = {r["uid"] for r in rows if r.get("binding") != "source"}
    unbound = [r for r in rows if r.get("binding") == "source" and r["uid"] not in bound]
    # A tunnel of the router that sources a ZIA tunnel is the carrier of that
    # ZIA tunnel. The ZIA tunnel is the candidate, and the 'endpoint' row of
    # the router tunnel is removed.
    carried_by = {r["uid"]: r["via"] for r in rows if r.get("binding") == "carried"}
    names = {r["uid"]: r.get("name") or r["uid"] for r in rows}
    replaced = set(carried_by.values())
    # One row per tunnel. Two bindings of the same tunnel are one candidate.
    rows = list(
        {
            r["uid"]: r
            for r in rows
            if r not in unbound and not (r.get("binding") == "endpoint" and r["uid"] in replaced)
        }.values()
    )
    tun, why, drop = _select_tunnel(rows, dst_part, route["egress_name"])
    if not tun and not why and not drop and unbound:
        why = _source_binding_note(trail, src_label, route, unbound)
    if drop:
        # No peer has the destination in its allowed IPs. WireGuard drops the packet.
        leg["blocked"] = True
        leg["blocking_uid"] = route["egress_uid"]
        leg["verdict"] = f"BLOCKED: {drop}"
        trail.notes.append(f"{src_label}: {drop}")
        return True, downstream_src
    if why:
        leg["indeterminate"] = True
        leg.setdefault("indeterminate_reason", why)
        trail.warn(f"{src_label}: {why}")
    _mtu_crossing(trail, route["egress_uid"], enforcement="tunnel" if tun else "l3")
    if tun:
        # The encapsulated packet is traced to the peer.
        sd = route.get("sdwan") or {}
        trail.hop(tun["uid"], "Tunnel", tun["name"], _encap_note(tun, sd), stage=Stage.ENCAP)
        if tun["uid"] in carried_by:
            trail.notes.append(
                f"{src_label}: {route['egress_name']} rides ZIA tunnel {names[tun['uid']]} through the "
                f"router's own tunnel {names.get(carried_by[tun['uid']], carried_by[tun['uid']])}, "
                "whose local address is the ZIA tunnel's source address"
            )
        _carrier_trace(
            session,
            trail,
            leg,
            gw,
            tun,
            route["egress_uid"],
            nat_rows or [],
            rib,
            inner=_inner_flow(sources, dst_part, snat_port, snat_proto, conn_state, sd),
            ingress_role=ingress_role,
        )
    return False, downstream_src


def _undo_reply_nat_hops(
    trail: _Trail,
    chain: tuple[dict[str, Any], ...],
    leg: dict[str, Any],
    gw: dict[str, Any],
    sources: list[tuple[int, int, int]],
) -> list[tuple[int, int, int]]:
    """The reply's source after this context undoes the forward walk's
    destination translations at egress, each one drawn as a NatRule hop and
    recorded on the leg's `reply_nat_undone`."""
    downstream_src, undone = reply_nat.undo(
        chain,
        device=gw["dev_uid"],
        context=leg.get("context_uid"),
        stage="egress",
        addresses=sources,
    )
    leg["reply_nat_undone"] = leg.get("reply_nat_undone", []) + undone
    for index in undone:
        step = chain[index]
        trail.hop(
            step["rule_uid"],
            "NatRule",
            "reply source NAT",
            "undoes destination translation in this context",
            stage=Stage.SNAT,
        )
    return downstream_src


def _encap_note(tun: dict[str, Any], sd: dict[str, Any]) -> str:
    """The note of the Tunnel hop. It has the encapsulation, and the SD-WAN
    link and the applications that the policy prefers the link for where the
    route has them."""
    note: str = tun["encap"] or "tunnel"
    if sd.get("link_kind"):
        note += f" over {sd['link_kind']}"
        if sd.get("preferred_for"):
            note += " · policy prefers for " + ", ".join(sd["preferred_for"])
    return note


def _inner_flow(
    sources: list[tuple[int, int, int]],
    dst_part: list[tuple[int, int, int]],
    port: Any,
    proto: Any,
    conn_state: str,
    sd: dict[str, Any],
) -> dict[str, Any]:
    """The flow a tunnel encapsulates, which the decap stage resumes on the
    far device."""
    return {
        "src": sources,
        "dst": dst_part,
        "port": port,
        "proto": proto,
        "conn_state": conn_state,
        # The overlay segment of the inner flow. The decap stage resumes the
        # flow in the table of the far device for that segment.
        "segment": {k: sd.get(k) for k in ("segment_id", "segment_name")} if sd.get("segment_id") else None,
    }


def _local_egress_stage(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    grp: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    nat_rows: list[dict[str, Any]] | None,
    rib: Any | None,
    *,
    conn_state: str = "new",
) -> tuple[bool, list[tuple[int, int, int]]]:
    """Filter, source NAT, egress interface and tunnel for a leg whose route
    resolved a local egress. Returns (denied, downstream source set).

    `conn_state` 'new' calls the forward gate (`_apply_firewall`), and any
    other value calls `_apply_firewall_reply`."""
    fw_dst, fw_port = _filter_dst(session, trail, leg, gw, grp, dst_part, port, src_label)
    fw_gate = _apply_firewall if conn_state == "new" else _apply_firewall_reply
    outcome = fw_gate(
        session,
        trail,
        leg,
        gw,
        route["egress_uid"],
        grp["sources"],
        fw_dst,
        fw_port,
        proto,
        src_label,
        route["egress_name"],
        acl_direction="in",
    )
    if outcome == DENY:
        return True, grp["sources"]
    if outcome is None:
        # No rulebase governs the pair. A zone firewall with the ingress in one
        # zone and the egress in none cannot form a pair, and VyOS does not
        # forward such traffic by default.
        _note_unjudged_zone_pair(session, trail, leg, gw["if_uid"], route["egress_uid"], src_label)
    denied, downstream_src = _egress_snat_tunnel(
        session,
        trail,
        leg,
        gw,
        route,
        dst_part,
        grp["sources"],
        port,
        proto,
        src_label,
        nat_rows,
        rib,
        conn_state=conn_state,
    )
    if denied:
        return True, downstream_src
    # a rule beyond the egress (the ZIA forwarding stage) keeps its own verdict
    if not leg.get("blocking_uid"):
        leg["verdict"] = f"egress via {route['egress_name']}"
    return False, downstream_src


def _local_egress_stage_ranged(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    grp: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    fw: dict[str, Any] | None,
    considered: list[str],
    cont_port: Any,
    cont_proto: Any,
    src_label: str,
    nat_rows: list[dict[str, Any]] | None,
    rib: Any | None,
    region: FlowRegion | None = None,
    *,
    conn_state: str = "new",
) -> tuple[bool, list[tuple[int, int, int]]]:
    """`_local_egress_stage` for one region that the rulebase walk of a ranged
    query decided. `region` is the `FlowRegion` of this leg.

    `fw` is one entry that `_firewall_region_list` returned (`None` when no
    rulebase governs this region). `considered` holds the interface-ACL
    candidates of the rulebase read. `cont_port` and `cont_proto` are the port
    and the protocol of the flow of this region after the gate
    (`_region_continuation`).
    """
    if considered:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *considered})
    if fw is None and gw.get("vsx_kind") in {"virtual-system", "bridge"}:
        leg["indeterminate"] = True
        leg["firewall"] = "VS policy not established"
        trail.warn(f"VS {gw.get('vsid', '?')}: no governing access policy was established for this context")
    outcome = (
        _apply_firewall_region(trail, leg, fw, src_label, route["egress_name"]) if fw is not None else None
    )
    if conn_state == "new":
        _record_region_gate_state(leg, gw, fw, outcome, considered)
    if outcome == DENY:
        return True, grp["sources"]
    if outcome is None:
        _note_unjudged_zone_pair(session, trail, leg, gw["if_uid"], route["egress_uid"], src_label)
    denied, downstream_src = _egress_snat_tunnel(
        session,
        trail,
        leg,
        gw,
        route,
        dst_part,
        grp["sources"],
        _scalarize_port_for_legacy(cont_port),
        _scalarize_for_legacy(cont_proto),
        src_label,
        nat_rows,
        rib,
        region=region,
    )
    if denied:
        return True, downstream_src
    # a rule beyond the egress (the ZIA forwarding stage) keeps its own verdict
    if not leg.get("blocking_uid"):
        leg["verdict"] = f"egress via {route['egress_name']}"
    return False, downstream_src


def _remote_zone_stage(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    grp: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    zone_out_if: str | None,
    intra_network: bool,
    *,
    conn_state: str = "new",
) -> bool:
    """Filter and verdict for a leg without a local egress interface.

    Returns True when the firewall denies the flow. `conn_state` selects the
    gate as in `_local_egress_stage`. A reply walk is evaluated by
    `_apply_firewall_reply` (session state, or the reply to a flow that the
    device terminated).
    """
    via = f"next-hop {route['next_hop']}" if route["next_hop"] else route["cidr"]
    fw_dst, fw_port = _filter_dst(session, trail, leg, gw, grp, dst_part, port, src_label)
    fw_gate = _apply_firewall if conn_state == "new" else _apply_firewall_reply
    outcome = fw_gate(
        session,
        trail,
        leg,
        gw,
        zone_out_if,
        grp["sources"],
        fw_dst,
        fw_port,
        proto,
        src_label,
        via,
    )
    if outcome == DENY:
        return True
    if outcome is None and not intra_network:
        _note_unjudged_zone_pair(session, trail, leg, gw["if_uid"], zone_out_if, src_label)
    if route["next_hop"]:
        leg["verdict"] = f"next-hop {route['next_hop']}"
    else:
        leg["verdict"] = f"matched {route['cidr']}"
    return False


def _remote_zone_stage_ranged(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    fw: dict[str, Any] | None,
    considered: list[str],
    src_label: str,
    zone_out_if: str | None,
    intra_network: bool,
    *,
    conn_state: str = "new",
) -> bool:
    """`_remote_zone_stage` for one region that the rulebase walk of a ranged
    query decided. `fw` and `considered` are as in
    `_local_egress_stage_ranged`."""
    via = f"next-hop {route['next_hop']}" if route["next_hop"] else route["cidr"]
    if considered:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *considered})
    outcome = _apply_firewall_region(trail, leg, fw, src_label, via) if fw is not None else None
    if conn_state == "new":
        _record_region_gate_state(leg, gw, fw, outcome, considered)
    if outcome == DENY:
        return True
    if outcome is None and not intra_network:
        _note_unjudged_zone_pair(session, trail, leg, gw["if_uid"], zone_out_if, src_label)
    if route["next_hop"]:
        leg["verdict"] = f"next-hop {route['next_hop']}"
    else:
        leg["verdict"] = f"matched {route['cidr']}"
    return False


def _default_route_wan_hop(
    session: Any, trail: _Trail, route: dict[str, Any], gw: dict[str, Any]
) -> dict[str, Any] | None:
    """Draws the WanLink hop for a default route that won LPM. The link is the
    link ON the egress interface of the route. Returns the drawn link, or None
    when no link is on the interface. `_mark_twin_exit` uses the link for the
    exit and for the reply start."""
    if route["cidr"] not in ("0.0.0.0/0", "::/0"):
        return None
    # An SD-WAN boundary row is a synthetic default and gets no WanLink hop.
    if route.get("kind") in ("SDWAN_TUNNEL", "SDWAN_BGP", "SDWAN_STATIC"):
        return None
    if route.get("kind") == "SDWAN_DIRECT":
        # A direct row has the WanLink that it leaves by in `sdwan`. The first
        # link of the edge by uid can be another link.
        sd = route.get("sdwan") or {}
        if not sd.get("link_uid"):
            return None
        wan = {"uid": sd["link_uid"], "name": sd.get("link_name"), "kind": sd.get("link_kind")}
        trail.hop(wan["uid"], "WanLink", wan["name"] or "wan", "default egress", stage=Stage.LINK)
        return wan
    # The link is read ON the egress interface of the route. A router with two
    # uplinks (PPPoE and a static WAN) leaves by one of them. A default in the
    # table of a tunnel leaves by the tunnel, and no WanLink is ON a tunnel.
    if not route.get("egress_uid"):
        return None
    wan = _path._read_one(
        session,
        """
MATCH (d:Device {uid: $dev})-[l:HAS_LINK]->(w:WanLink)-[won:ON]->(i:Interface {uid: $u})
WHERE l._retired_at IS NULL AND won._retired_at IS NULL AND NOT w:Retired
  AND d:Obj AND d.collection_ts = $snap
  AND i:Obj AND i.collection_ts = $snap AND NOT i:Retired
RETURN w.uid AS uid, w.name AS name, w.kind AS kind ORDER BY w.uid LIMIT 1""",
        dev=gw["dev_uid"],
        u=route["egress_uid"],
    )
    if wan:
        trail.hop(wan["uid"], "WanLink", wan["name"] or "wan", "default egress", stage=Stage.LINK)
    return wan


def _merge_upstream_leg(il: dict[str, Any], leg: dict[str, Any]) -> None:
    """Fold this device's translations and gate accounting into one far leg."""
    if leg.get("reply_nat_undone"):
        il["reply_nat_undone"] = leg["reply_nat_undone"] + il.get("reply_nat_undone", [])
    if leg.get("gate_state"):
        il["gate_state"] = {**leg["gate_state"], **il.get("gate_state", {})}
    # The translations of this device go on the final leg.
    if leg.get("dnat"):
        # upstream (nearer the source) first, then what the far device accumulated
        il["dnat"] = leg["dnat"] + il.get("dnat", [])
    # `filter_view` is not merged. The leg-level key describes the device whose
    # filter decided the leg, and after the fold that is the far device. The
    # view of this device is on its entry of the `dnat` list.
    if leg.get("snat"):
        il["snat"] = leg["snat"] + il.get("snat", [])
    if leg.get("nat_chain"):
        # nearer the source first, as dnat/snat above
        il["nat_chain"] = leg["nat_chain"] + il.get("nat_chain", [])
    il["indeterminate"] = il["indeterminate"] or leg["indeterminate"]
    fw_seen = (
        set(il.get("fw_uids") or [])
        | {u for u in (leg.get("fw_uid"), il.get("fw_uid")) if u}
        | set(leg.get("fw_uids") or [])
    )
    if fw_seen:
        il["fw_uids"] = sorted(fw_seen)
    il["nat_uids"] = sorted(set(il.get("nat_uids") or []) | set(leg.get("nat_uids") or []))
    il["lb_uids"] = sorted(set(il.get("lb_uids") or []) | set(leg.get("lb_uids") or []))
    pbr_seen = set(il.get("pbr_uids") or []) | set(leg.get("pbr_uids") or [])
    if pbr_seen:
        il["pbr_uids"] = sorted(pbr_seen)
    # The `service` of a leg stays to the end of the walk. A far device that
    # partitions the flow again sets a narrower `service` and keeps it. A far
    # device that reads the continuation as a point value (a region narrowed
    # to one port with no protocol range) sets no `service`, and the far leg
    # takes the `service` of this device.
    if leg.get("service") and "service" not in il:
        il["service"] = leg["service"]


def _build_reply_tuple(
    leg: dict[str, Any],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
) -> tuple[list[tuple[int, int, int]], list[tuple[int, int, int]], str | None]:
    """The (src, dst) tuple of the reply as it leaves the original
    destination. It is the final wire tuple of this forward leg, swapped, with
    the recorded translations of the leg (`leg["nat_chain"]`) undone in
    reverse device order.

    The recorded pre-tuple of each step is used directly.

    `src_set` and `dst_set` are the tuple of the original query. The undo of
    an 'lb' step is not confirmed. `lb_note` is the VirtualService name of the
    'lb' step nearest the source, or None.

    The source seed is `leg["sources"]`, the source partition of this leg, or
    the set of the query when the leg has none.

    The sNAT and lb undo (`reply_dst`) is the union of the pre-translation
    sources of the sNAT and lb steps of the earliest device and context, and
    the part of `leg_sources` that none of them claimed. The unclaimed part is
    added only when the claimed parts are inside `leg_sources`. The recorded
    value of a chain step outranks `leg_sources`
    (`test_a_recorded_translation_still_outranks_the_legs_own_partition`)."""
    chain = leg.get("nat_chain") or []
    leg_sources = _intervals(leg["sources"]) if leg.get("sources") else src_set
    final_src, final_dst = leg_sources, dst_set
    for step in chain:
        direction = step["direction"]
        if direction in ("dnat", "lb"):
            final_dst = _intervals(step["post"]["dst"])
        if direction in ("snat", "lb"):
            final_src = _intervals(step["post"]["src"])
    reply_src, reply_dst = final_dst, final_src
    lb_note: str | None = None
    for step in reversed(chain):
        direction = step["direction"]
        if direction in ("dnat", "lb"):
            reply_src = _intervals(step["pre"]["dst"])
        if direction == "lb":
            lb_note = step.get("vip_name")
    snat_steps = [step for step in chain if step["direction"] in ("snat", "lb")]
    if snat_steps:
        earliest_device = snat_steps[0]["device"]
        earliest_context = snat_steps[0].get("context_uid")
        earliest = [
            step
            for step in snat_steps
            if step["device"] == earliest_device and step.get("context_uid") == earliest_context
        ]
        claimed = _merge([iv for step in earliest for iv in _intervals(step["pre"]["src"])])
        remainder = [] if _subtract(claimed, leg_sources) else _subtract(leg_sources, claimed)
        reply_dst = _merge(claimed + remainder)
    return reply_src, reply_dst, lb_note


def _reply_gw(terminal: dict[str, Any]) -> dict[str, Any]:
    """The synthetic start device of a reply walk, from the `_terminal`
    capture of one forward leg (the device and interface that it delivered to,
    or terminated on as router-local).

    The result has the shape of a `_pick_gateway` winner (`dev_uid`,
    `dev_name`, `if_uid`, `if_name`)."""
    return {
        "dev_uid": terminal["dev_uid"],
        "dev_name": terminal["dev_name"],
        "if_uid": terminal["if_uid"],
        "if_name": terminal.get("if_name"),
        **{
            k: terminal[k]
            for k in ("firewall_instance_uid", "vsid", "vsx_kind", "context_uid")
            if k in terminal
        },
    }


@trace_scope(reverse=True)
def _walk_reply_leg(
    session: Any,
    forward_leg: dict[str, Any],
    terminal: dict[str, Any] | None,
    forward_sequence: list[str],
    device_gate_state: dict[str, dict[str, Any]],
    orig_src_set: list[tuple[int, int, int]],
    orig_dst_set: list[tuple[int, int, int]],
    rib: Any | None,
    *,
    max_hops: int,
    nat_rule_labels: dict[str, str] | None = None,
    lanes_spent: int = 0,
) -> dict[str, Any]:
    """The reply for one forward leg. The tuple of the reply is walked device
    by device from the terminal device of the forward leg toward the original
    source.

    Before the pipeline of that walk runs, the function records the stations
    of the reply on its first device: the origin of the reply, the ingress
    interface, and one NatRule hop per translation that the reply undoes at
    this device.

    `nat_rule_labels` maps the uid of every translation on the `nat_chain` of
    `forward_leg` to the NatRule hop label of the forward walk ("sNAT rule
    10"). The undo note has that label.

    Returns one walk dict in the PathResponse shape. It has `hops`, `notes`
    and `warnings` from the trail of the reply, `legs`, `verdict`,
    `indeterminate`, `boundary`, `destinations` (the destination set of this
    reply, which is the source partition of the forward leg with the forward
    translations undone), and `asymmetric` with `comparison_notes` for a reply
    whose device sequence, reversed, does not match the forward sequence.
    """
    reply_src, reply_dst, lb_note = _build_reply_tuple(forward_leg, orig_src_set, orig_dst_set)
    if terminal is None:
        # The forward leg did not confirm delivery to a device the reply can start from.
        return _reply_not_derived(
            "reply not derived: the forward leg never confirmed delivery", _to_cidrs(reply_dst)
        )
    reply_trail = _Trail()
    reply_trail.max_hops = max_hops
    # The lane budget is that of the whole trace (`path_lane_cap`).
    reply_trail.lanes_spent = lanes_spent
    _mtu_crossing(reply_trail, terminal.get("if_uid"), enforcement="source")
    # the reply's firewall gate reads the per-device state of the forward walk
    reply_trail.device_gate_state = dict(device_gate_state)
    if forward_leg.get("indeterminate") or forward_leg.get("blocked"):
        # The final state of the forward leg confirms a permit that a device
        # recorded at its forward filter. A mark set later on the leg (the gate
        # coverage, the delivery context, an L2 mark) leaves the flow
        # undecided. The reply is then not admitted from session state on that
        # device (`_apply_firewall_reply`, `unconfirmed`).
        reply_trail.device_gate_state = {
            key: ({**state, "permit": False, "unconfirmed": True} if state.get("permit") else state)
            for key, state in reply_trail.device_gate_state.items()
        }
    local_state = terminal.get("local_gate_state")
    if local_state:
        # The forward flow terminated on this device, and the device sends the
        # reply. `_apply_firewall_reply` reads that from `local`. The permit is
        # confirmed only by the final state of the forward leg. A mark set
        # after the input read (the unevaluated-gate safeguard, a VIP bound
        # elsewhere) leaves the leg undecided, and the reply is not admitted
        # from session state.
        confirmed = bool(local_state.get("permit")) and not (
            forward_leg.get("indeterminate") or forward_leg.get("blocked")
        )
        reply_trail.device_gate_state[_forwarding_visit(terminal)] = {**local_state, "permit": confirmed}
    chain = forward_leg.get("nat_chain") or []
    vsx_nat = bool(chain) and (
        any("|" in key for key in device_gate_state)
        or any(str(step.get("context_uid", "")).startswith("firewall-vrf-context:") for step in chain)
    )
    expected_reply_dst = reply_dst
    if vsx_nat and not reply_nat.valid_chain(chain):
        return _reply_not_derived(
            "reply not derived: NAT inversion is not established",
            _to_cidrs(expected_reply_dst),
            ["VSX reply NAT requires context-qualified translation evidence"],
        )
    if vsx_nat:
        reply_trail.reply_nat_chain = tuple(chain)
        reply_src, reply_dst = reply_nat.wire_reply(chain, expected_reply_dst, orig_dst_set)
        if terminal.get("wire_sources") and terminal.get("wire_destinations"):
            reply_src = _intervals(terminal["wire_destinations"])
            reply_dst = _intervals(terminal["wire_sources"])
    gw0 = _reply_gw(terminal)
    # the reply's own first-device stations, in order
    origin = terminal.get("origin")
    if origin and origin.get("uid"):
        origin_note = (
            f"reply origin: {_describe(reply_src)}, outside the twin"
            if forward_leg.get("boundary")
            else "reply origin"
        )
        reply_trail.hop(
            origin["uid"],
            origin["kind"],
            origin.get("label") or origin["uid"],
            origin_note,
            stage=Stage.SRC_ENDPOINT,
        )
    if terminal.get("if_uid"):
        reply_trail.hop(
            terminal["if_uid"],
            "Interface",
            terminal.get("if_name") or terminal["if_uid"],
            "reply ingress",
            stage=Stage.INGRESS_IF,
        )
    if reply_trail.reply_nat_chain is None:
        _reply_undo_hops(reply_trail, terminal, chain, nat_rule_labels or {})
    attachment = terminal.get("attachment_uid")
    _, crossings, gap = (
        vsx.resolve(session, attachment, None, target=terminal["if_uid"]) if attachment else (None, [], None)
    )
    if crossings or gap:
        seed = {
            "lane": 0,
            "blocked": False,
            "indeterminate": bool(gap),
            "sources": _to_cidrs(reply_src),
            "src_label": _describe(reply_src),
        }
        if gap:
            reply_trail.warn(gap)
        legs = _walk_crossing_parts(
            session,
            reply_trail,
            gw0,
            _transparent_parts(
                session,
                reply_trail,
                crossings,
                seed,
                _query_region(reply_src, reply_dst, None, None, None),
                "established",
            ),
            rib,
            max_hops=max_hops,
            conn_state="established",
        )
    else:
        legs, _lane = _device_stage(
            session,
            reply_trail,
            gw0,
            reply_src,
            reply_dst,
            None,
            None,
            0,
            rib,
            max_hops=max_hops,
            conn_state="established",
        )
    # count the groups before the loop below drops each leg's `gid`
    multi = len({ll.get("gid") for ll in legs}) > 1
    # The lanes that reached an end, read before `_terminal` is dropped. An end
    # is a delivery or an exit (`_terminal`), or a network that the device
    # serves (`_local_net`).
    ended = {ll.get("lane", 0) for ll in legs if ll.get("_terminal") or ll.get("_local_net")}
    # where each leg ends, read before `_terminal` is dropped (`_leg_end`)
    reply_ends = [_leg_end(ll, bool(ll.get("_local_net"))) for ll in legs]
    for ll in legs:
        ll.pop("gid", None)
        ll.pop("_terminal", None)
    reply_trail.rank_hops()
    # Each equal-cost reply lane is compared on its own device sequence. The
    # first device of the reply has no device hop, and `first` is put at the
    # start of each sequence.
    first = reply_trail.device_sequence[:1]
    reply_lanes: dict[int, list[str]] = {}
    for lane in sorted({ll.get("lane", 0) for ll in legs} or {0}):
        drawn = _leg_device_sequence(reply_trail.hops, lane)
        reply_lanes[lane] = drawn if drawn[:1] == first else first + drawn
    # A stopped lane reached no end, and every leg of it is blocked or
    # indeterminate. Such a lane is incomplete (`_reply_comparison`).
    stopped = frozenset(
        lane
        for lane in reply_lanes
        if lane not in ended
        and (lane_legs := [ll for ll in legs if ll.get("lane", 0) == lane])
        and all(ll.get("blocked") or ll.get("indeterminate") for ll in lane_legs)
    )
    asymmetric, comparison_notes = _reply_comparison(
        forward_sequence, reply_lanes, device_gate_state, stopped_lanes=stopped
    )
    # The safeguards of the forward walk apply to the devices of the reply. A
    # gate that the walk did not evaluate, and a device whose policy the pinned
    # run did not collect completely, leave the reply undecided.
    first_device = {terminal["dev_uid"]: terminal.get("dev_name") or ""} if terminal.get("dev_uid") else {}
    coverage = _gate_coverage(session, reply_trail, legs, _leg_gate_credits(legs), first_device)
    notes = list(reply_trail.notes)
    if vsx_nat:
        for ll in legs:
            applied = set(ll.pop("reply_nat_undone", []))
            missing = set(range(len(chain))) - applied
            reason = (
                "reply did not cross every original NAT context with the expected translated tuple"
                if missing
                else "reply NAT predicts the original connection; runtime session/PAT state was not observed"
            )
            ll["indeterminate"] = True
            ll["indeterminate_reason"] = reason
            if reason not in notes:
                notes.append(reason)
    indeterminate = any(ll.get("indeterminate") for ll in legs)
    boundary = any(ll.get("boundary") for ll in legs)
    if lb_note:
        # the reply through a VIP-to-member rewrite is not confirmed
        indeterminate = True
        reason = _lb_reply_indeterminate_reason(lb_note)
        notes.append(reason)
        for ll in legs:
            ll["indeterminate"] = True
            ll.setdefault("indeterminate_reason", reason)
    verdict = _combined_verdict(legs, "reply", multi) + coverage if legs else "reply: no leg produced"
    exits = _walk_exits(legs)
    return {
        "hops": reply_trail.hops,
        "legs": legs,
        "verdict": verdict + _exit_prose(exits),
        "notes": notes,
        "warnings": reply_trail.warnings,
        "indeterminate": indeterminate,
        "boundary": boundary,
        "left_estate": exits,
        "reach": _walk_reach(legs, reply_ends, indeterminate),
        "asymmetric": asymmetric,
        "comparison_notes": comparison_notes,
        "lanes_spent": reply_trail.lanes_spent,
        "destinations": _to_cidrs(expected_reply_dst),
    }


def _reply_undo_hops(
    reply_trail: _Trail, terminal: dict[str, Any], chain: list[dict[str, Any]], labels: dict[str, str]
) -> None:
    """Draws one NatRule hop per forward translation that the reply undoes at
    its first device, latest first. Each hop has the hop label of the forward
    walk."""
    for step in reversed(chain):
        if step.get("device") != terminal["dev_uid"] or step.get("direction") not in ("dnat", "snat"):
            # LB steps are undone in `_build_reply_tuple` and get no hop here.
            continue
        if step.get("context_uid") and step["context_uid"] != terminal.get("context_uid"):
            continue
        side = "dst" if step["direction"] == "dnat" else "src"
        frm = _describe(_intervals(step["post"][side]))
        to = _describe(_intervals(step["pre"][side]))
        rule_uid = step.get("rule_uid")
        label = labels.get(rule_uid) if rule_uid else None
        label = label or f"{step['direction']} rule"
        reply_trail.hop(
            rule_uid or f"{step['device']}:{step['direction']}:{frm}",
            "NatRule",
            label,
            f"undoes {label}: {frm} -> {to}",
            stage=Stage.DNAT if step["direction"] == "snat" else Stage.SNAT,
        )


def _reply_comparison(
    forward_sequence: list[str],
    reply_lanes: dict[int, list[str]],
    device_gate_state: dict[str, dict[str, Any]],
    *,
    stopped_lanes: frozenset[int] = frozenset(),
) -> tuple[bool, list[str]]:
    """Whether the reply is asymmetric, and the comparison notes.

    The reply is asymmetric when no lane of it retraces the forward lane
    reversed and a lane is not incomplete.

    A lane in `stopped_lanes` (every leg of it blocked or undecided) is
    incomplete when its devices are the start of the forward path reversed. An
    incomplete lane gets a note. It does not count as asymmetric, and it gets
    no note about missed session state.

    `reply_lanes` maps each reply lane to its device sequence. One lane that
    retraces the forward lane makes the round trip symmetric. The note of an
    asymmetric reply lists every lane. An equal-cost lane that crosses other
    devices beside a lane that retraces the forward path gets its own note.

    The comparison notes are returned apart from the `notes` of the reply. The
    caller puts them in the top-level `notes`."""
    reversed_forward = list(reversed(forward_sequence))
    forward_text = " → ".join(reversed_forward) or "(none)"
    retracing = [lane for lane, seq in sorted(reply_lanes.items()) if seq == reversed_forward]
    incomplete = {
        lane
        for lane, seq in reply_lanes.items()
        if lane in stopped_lanes and seq != reversed_forward and seq == reversed_forward[: len(seq)]
    }
    asymmetric = (
        bool(forward_sequence) and not retracing and any(lane not in incomplete for lane in reply_lanes)
    )
    comparison_notes: list[str] = []
    one_lane = len(reply_lanes) == 1
    for lane in sorted(incomplete) if forward_sequence else []:
        which = "the reply" if one_lane else f"reply lane {lane}"
        last = reply_lanes[lane][-1] if reply_lanes[lane] else "its first device"
        comparison_notes.append(
            f"{which} stops on {last} before it retraces the forward path reversed ({forward_text}); "
            "whether the return is symmetric is not established"
        )
    reply_lanes = {lane: seq for lane, seq in reply_lanes.items() if lane not in incomplete}
    if forward_sequence and retracing:
        retraced = ", ".join(map(str, retracing))
        for lane, reply_seq in sorted(reply_lanes.items()):
            if reply_seq != reversed_forward:
                comparison_notes.append(
                    f"reply lane {lane} ({' → '.join(reply_seq) or '(none)'}) does not match the forward "
                    f"path reversed ({forward_text}), which reply lane {retraced} retraces"
                )
    if asymmetric:
        if one_lane:
            reply_seq = next(iter(reply_lanes.values()))
            comparison_notes.append(
                f"asymmetric routing: the reply's own path ({' → '.join(reply_seq) or '(none)'}) does "
                f"not match the forward path reversed ({forward_text})"
            )
        else:
            paths = "; ".join(
                f"lane {lane}: {' → '.join(seq) or '(none)'}" for lane, seq in sorted(reply_lanes.items())
            )
            comparison_notes.append(
                f"asymmetric routing: no lane of the reply's own path ({paths}) matches the forward "
                f"path reversed ({forward_text})"
            )
    # A stateful gate the forward flow crossed that the reply's own route
    # does not visit has no session for the reply.
    for lane, reply_seq in sorted(reply_lanes.items()):
        if not forward_sequence or reply_seq == reversed_forward:
            continue
        which = "reply" if one_lane else f"reply lane {lane}"
        for dev in forward_sequence:
            if dev not in reply_seq and device_gate_state.get(dev):
                comparison_notes.append(f"{which} does not cross {dev}; its session state does not apply")
    return asymmetric, comparison_notes


def _leg_device_sequence(hops: list[dict[str, Any]], lane: int) -> list[str]:
    """The device sequence of one forward leg, derived from the `hops` of the
    forward answer.

    A hop belongs to the path of this leg when it was recorded before the walk
    forked (`shared`) or has the `lane` of this leg. The filter
    `stage == 'DEVICE'` keeps a routed device visit and drops an L2 attach
    switch (SRC_ATTACH, DST_ATTACH), as `trail.device_sequence` does. The
    sequence is ordered by `rank`."""
    return [
        h.get("forwarding_visit") or h["uid"]
        for h in sorted(
            (
                h
                for h in hops
                if h.get("kind") == "Device"
                and not h.get("virtual_context")
                and h.get("stage") == "DEVICE"
                and (h.get("shared") or h.get("lane") == lane)
            ),
            key=lambda h: h["rank"],
        )
    ]


def _compose_bidirectional(
    session: Any,
    forward: dict[str, Any],
    capture: dict[str, Any],
    orig_src_set: list[tuple[int, int, int]],
    orig_dst_set: list[tuple[int, int, int]],
    rib: Any | None,
    *,
    max_hops: int,
) -> dict[str, Any]:
    """The composed answer of trace(reply=True): {forward, reply, asymmetric, notes}.

    `forward` is the dict that `trace()` returns without `reply`. `capture` is
    the `reply_capture` of `_trace_domain`. Its `leg_terminals` and
    `leg_gate_states` are aligned by index with `forward['legs']`.

    The reply is derived and compared per forward leg, against the device
    sequence of that leg (`_leg_device_sequence`).

    `reply` has one of two shapes:

    - one forward leg (or none): a single dict in the shape of `forward`
    - several forward legs: a list with one entry per forward leg, in
      forward-leg order. Each entry has that shape plus `forward_leg` (its
      index in `forward['legs']`), `src_label` (the source partition of the
      forward leg, the label of the lane), `destinations` (the destination set
      of the reply) and `asymmetric` for that pair of forward leg and reply.
      The lanes inside an entry are numbered from zero.

    Top-level `asymmetric` is true when any pair is asymmetric. Top-level
    `notes` holds the comparison notes of every pair.
    """
    forward_legs = forward["legs"]
    forward_hops = forward.get("hops") or []
    terminals = capture.get("leg_terminals") or []
    leg_gate_states = capture.get("leg_gate_states") or []
    # every NatRule hop label the forward walk recorded, by uid
    nat_rule_labels = {h["uid"]: h["label"] for h in forward.get("hops") or [] if h.get("kind") == "NatRule"}
    # The first routing visit of the walk, the gateway, is on every lane. Its
    # DEVICE hop is not drawn when the gateway is also the attach switch of
    # the source, because a node has one hop per lane and depth and the
    # SRC_ATTACH hop holds it. `first` is put at the start of each lane
    # sequence, as for the reply lanes (`_walk_reply_leg`).
    first = list(capture.get("device_sequence") or [])[:1]
    walks: list[dict[str, Any]] = []
    lanes_spent = capture.get("lanes_spent", 0)
    for i, fleg in enumerate(forward_legs):
        terminal = terminals[i] if i < len(terminals) else None
        gate_state = leg_gate_states[i] if i < len(leg_gate_states) else {}
        drawn = _leg_device_sequence(forward_hops, fleg.get("lane", 0))
        walks.append(
            _walk_reply_leg(
                session,
                fleg,
                terminal,
                drawn if drawn[:1] == first else first + drawn,
                gate_state,
                orig_src_set,
                orig_dst_set,
                rib,
                max_hops=max_hops,
                nat_rule_labels=nat_rule_labels,
                lanes_spent=lanes_spent,
            )
        )
        lanes_spent = walks[-1].get("lanes_spent", lanes_spent)
    top_notes = [n for one in walks for n in one["comparison_notes"]]
    reply: dict[str, Any] | list[dict[str, Any]]
    if len(walks) > 1:
        reply = [
            {
                "forward_leg": i,
                "src_label": forward_legs[i].get("src_label") or _describe(orig_src_set),
                "destinations": one["destinations"],
                "hops": one["hops"],
                "legs": one["legs"],
                "verdict": one["verdict"],
                "notes": one["notes"],
                "warnings": one["warnings"],
                "indeterminate": one["indeterminate"],
                "boundary": one["boundary"],
                # a reply not derived (`_reply_not_derived`) drew no leg
                "left_estate": one.get("left_estate", []),
                "reach": one.get("reach"),
                "asymmetric": one["asymmetric"],
                **({"mtu": one["mtu"]} if "mtu" in one else {}),
            }
            for i, one in enumerate(walks)
        ]
    else:
        one = walks[0] if walks else None
        reply = {
            "hops": one["hops"] if one else [],
            "legs": one["legs"] if one else [],
            "verdict": one["verdict"] if one else "reply: no forward leg to derive from",
            "notes": one["notes"] if one else [],
            "warnings": one["warnings"] if one else [],
            "indeterminate": bool(one and one["indeterminate"]),
            "boundary": bool(one and one["boundary"]),
            "left_estate": one.get("left_estate", []) if one else [],
            "reach": one.get("reach") if one else None,
            # Every entry of the list shape also has `destinations`.
            "destinations": one["destinations"] if one else [],
            **({"mtu": one["mtu"]} if one and "mtu" in one else {}),
        }
    return {
        "forward": forward,
        "reply": reply,
        "asymmetric": any(one["asymmetric"] for one in walks),
        "notes": top_notes,
    }


def _table_adjacency(session: Any, trail: _Trail, gw: dict[str, Any], table_uid: str | None) -> list[str]:
    """The prefixes and addresses that one routing table records as directly
    attached to this device.

    The evidence has 3 kinds, all read from `table_uid`: the connected
    (ORIGINATES) prefixes of the table, its host routes, and the interface
    addresses of the device in it. A platform that installs a host route per
    neighbour records adjacency only that way. Inter-VRF leaking can point the
    next hop at an address of the device on the other side.

    A leaked route resolves its next hop in the exporting context (the
    collected `next_hop_vrf`), and the caller passes that table. An ordinary
    route uses the table that it is routed on.

    The result is cached per (device, table) on the trail. A trace crosses the
    same table on more than one lane and group.
    """
    key = (gw["dev_uid"], table_uid)
    cached = trail.table_adjacency.get(key)
    if cached is not None:
        return cached
    routes = _path._read(session, _ROUTES_QUERY, vrf=table_uid)
    own = _path._read(session, _OWN_ADDRS_QUERY, dev=gw["dev_uid"], vrf=table_uid)
    evidence = _connected_prefixes(routes) + _host_prefixes(routes) + [r["ip"] for r in own if r.get("ip")]
    trail.table_adjacency[key] = evidence
    return evidence


# The table of the far PE in the routing domain of the table of the route
# lookup, and one interface in it. The flow of a VPN route continues there on
# the egress PE. The VPN label decides the table on the egress PE. The loopback
# of the next hop is in the global table.
_DOMAIN_MATE_INTERFACE_QUERY = """
MATCH (tbl:VrfInstance {uid: $table})-[m1:MEMBER_OF]->(rd:RoutingDomain)<-[m2:MEMBER_OF]-(v:VrfInstance)
WHERE tbl:Obj AND tbl.collection_ts = $snap
  AND NOT rd:Retired AND NOT v:Retired AND m1._retired_at IS NULL AND m2._retired_at IS NULL
  AND coalesce(m1.basis, 'declared') = 'declared' AND coalesce(m2.basis, 'declared') = 'declared'
  AND v.collection_ts = $snap
MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[on:ON]->(d:Device {uid: $dev})
WHERE d:Obj AND d.collection_ts = $snap
  AND iv._retired_at IS NULL AND on._retired_at IS NULL AND NOT i:Retired
RETURN i.uid AS if_uid, i.name AS if_name, v.uid AS vrf_uid, v.name AS vrf_name
ORDER BY v.uid, i.uid LIMIT 1"""

# The count and the names of the tables of that routing domain on the far PE.
# With more than one table, the table that the VPN label selects is not collected.
_DOMAIN_MATE_TABLES_QUERY = (
    _DOMAIN_MATE_INTERFACE_QUERY.split("RETURN i.uid AS if_uid")[0]
    + "RETURN count(DISTINCT v.uid) AS tables, collect(DISTINCT coalesce(v.name, v.uid)) AS names"
)

_TE_INTERFACES_QUERY = """
MATCH (dev:Device {uid: $dev})<-[o:ON]-(i:Interface)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND o._retired_at IS NULL AND NOT i:Retired AND i.collection_ts = $snap
  AND (toLower(i.name) STARTS WITH 'tunnel-te' OR toLower(i.name) STARTS WITH 'tunnel-mte')
RETURN i.uid AS uid, i.name AS name ORDER BY i.uid"""


def _transport_walk(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    target_ip: str,
    target: dict[str, Any],
    rib: Any | None,
    depth: int,
    visited: frozenset[str],
    src_label: str,
) -> list[dict[str, Any]] | None:
    """The path to a recursive next hop. It holds the devices that reach the
    next hop of a route when the next hop is not on a connected prefix of this
    device.

    The next hop of a VRF route on a PE is the loopback of the egress PE. The
    loopback is reached through the global table, hop by hop across the P
    routers. Under LDP or SR-MPLS the label-switched path follows that IGP
    path, and the global RIB gives the transport. The walk reads the global
    table of each device for `target_ip`, moves to the owner of the next hop
    of that route, and stops when the owner is `target`. Every hop that it
    records has `transport` (`_Trail.hop`). The hops are drawn under the route
    of the next hop, at the depths between this device and the target.

    Returns the devices crossed (none when the global table has the target
    one hop away), or None when the transport cannot be walked. The walk fails
    with no global route, a discard route, an interface route that is not
    on-link, a next hop that the twin does not hold, a loop, the hop cap, or a
    traffic-engineered tunnel on this device. A TE tunnel or an SR policy
    steers the label-switched path away from the IGP path. The tunnel
    interfaces are collected and an SR policy is not, and only a TE tunnel is
    detected.
    """
    te = _path._read(session, _TE_INTERFACES_QUERY, dev=gw["dev_uid"])
    if te:
        names = ", ".join(str(r["name"]) for r in te)
        trail.warn(
            f"{src_label}: {_dev_label(gw)} has traffic-engineered tunnel(s) {names}; "
            f"the path to next hop {target_ip} may not follow the IGP path and is not traced"
        )
        return None
    probe = _intervals([target_ip])
    if not probe:
        return None
    af = probe[0][0]
    crossed: list[dict[str, Any]] = []
    here = gw
    seen = set(visited) | {gw["dev_uid"]}
    trail.transport += 1
    saved_depth = trail.depth
    try:
        # The route of the first device. Each later pass uses the route that
        # the pass before it read for the transport station.
        vrf, route = _global_best_route(session, trail, rib, here, probe, af, target_ip, src_label)
        while True:
            if route is None:
                trail.warn(
                    f"{src_label}: {_dev_label(here)} has no global route to "
                    f"next hop {target_ip}; the transport path is not traced"
                )
                return None
            if route.get("discard"):
                trail.warn(
                    f"{src_label}: {_dev_label(here)} holds a {route['discard']} route {route['cidr']} "
                    f"for next hop {target_ip}; the transport path is not traced"
                )
                return None
            if route.get("kind") == "ORIGINATES" or (not route.get("next_hop") and _on_link_route(route)):
                # the target sits on a connected prefix of this device
                return crossed
            if not route.get("next_hop"):
                # An interface route that is not connected (a default out of a
                # PPPoE or tunnel interface) gives only the egress of the
                # packet. The target is not known to be on that link.
                via = route.get("egress_name") or route.get("ifname") or "an interface"
                trail.warn(
                    f"{src_label}: {_dev_label(here)} reaches next hop {target_ip} by {route['cidr']} "
                    f"out of {via} with no next hop; the transport path is not traced"
                )
                return None
            owner, why = _next_hop_device(
                session,
                route["next_hop"],
                vrf["vrf_uid"] if vrf else None,
                here,
                egress_uid=route.get("egress_uid"),
            )
            if why or not owner or owner.get("context_note"):
                # An owner in an unrelated context is not walked as transport.
                # The walk returns None, as for an unresolved next hop.
                reason = why or (
                    f"is not traced: {owner['context_note']}"
                    if owner
                    else "is not held by any interface in the graph"
                )
                trail.warn(
                    f"{src_label}: transport next hop {route['next_hop']} on {_dev_label(here)} {reason}"
                )
                return None
            if owner["dev_uid"] == target["dev_uid"]:
                return crossed
            trail.probe_visit(owner["dev_uid"])
            if owner["dev_uid"] in seen:
                trail.warn(
                    f"{src_label}: transport path to {target_ip} returns to "
                    f"{_dev_label(owner)}: routing loop, not traced"
                )
                return None
            if depth + 1 + len(crossed) >= trail.max_hops:
                trail.warn(
                    f"{src_label}: transport path to {target_ip} exceeds {trail.max_hops} L3 hops; "
                    f"stopped at {_dev_label(owner)}"
                )
                return None
            seen.add(owner["dev_uid"])
            crossed.append(owner)
            trail.depth = depth + len(crossed)
            _draw_arrival(
                trail,
                owner,
                if_note=f"on {owner['dev_name']} · transport toward {target_ip}",
                dev_note="transport",
            )
            here = {
                "dev_uid": owner["dev_uid"],
                "dev_name": owner["dev_name"],
                "if_uid": owner["if_uid"],
                "if_name": owner["if_name"],
                "l3dom": owner.get("l3dom"),
                "anchor": owner.get("anchor"),
            }
            # The route by which this device forwards the transport, drawn as a station.
            vrf, route = _global_best_route(session, trail, rib, here, probe, af, target_ip, src_label)
            if route is not None:
                _draw_transport_station(trail, here["dev_uid"], vrf, route)
    finally:
        trail.transport -= 1
        trail.depth = saved_depth


# The protocol values of a side-store RIB row for a connected network (the
# spellings of the collectors: `cisco_common.expand_protocol`, `direct` of Gaia).
_ON_LINK_PROTOCOLS = frozenset({"connected", "local", "direct"})


def _on_link_route(route: dict[str, Any]) -> bool:
    """Whether the destination of a route with no next hop is on the link. It
    is on the link for a connected route, in the graph or in the side store,
    and for an interface host route (a PPP peer). `_host_prefixes` reads the
    same evidence as adjacency."""
    if route.get("kind") == "ORIGINATES" or str(route.get("protocol") or "").lower() in _ON_LINK_PROTOCOLS:
        return True
    try:
        net = ipaddress.ip_network(str(route.get("cidr")), strict=False)
    except ValueError:
        return False
    return net.prefixlen == net.max_prefixlen


def _global_best_route(
    session: Any,
    trail: _Trail,
    rib: Any | None,
    here: dict[str, Any],
    probe: list[tuple[int, int, int]],
    af: int,
    target_ip: str,
    src_label: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """A device's global table and the best route in it for `probe`. The
    route is None when the table has none.

    The transport is walked along the first member of an equal-cost set in
    the order of `_route_partition`. A note names the members it does not
    follow."""
    vrf, routes, lookup = _local_routes(session, rib, here["dev_uid"], af)
    parts = _route_partition(routes, probe, lookup, [])
    best = parts[0][1] if parts else []
    if len(best) > 1:

        def via(route: dict[str, Any]) -> str:
            return str(route.get("next_hop") or route.get("egress_name") or route.get("ifname") or "?")

        trail.note_once(
            f"{src_label}: {_dev_label(here)} holds {len(best)} equal-cost routes {best[0]['cidr']} "
            f"toward transport next hop {target_ip}; the transport path is drawn via {via(best[0])} "
            f"and not via {', '.join(via(route) for route in best[1:])}"
        )
    return vrf, (best[0] if best else None)


def _draw_transport_station(
    trail: _Trail, dev_uid: str, vrf: dict[str, Any] | None, route: dict[str, Any]
) -> None:
    """The route a transport device forwards by, and its egress interface."""
    trail.hop(
        route["uid"] or f"rib:{dev_uid}:{vrf['vrf_uid'] if vrf else 'default'}:{route['cidr']}",
        "Prefix",
        route["cidr"],
        "transport route",
        stage=Stage.TRANSPORT,
    )
    if route.get("egress_uid"):
        trail.hop(
            route["egress_uid"],
            "Interface",
            route["egress_name"],
            "transport egress",
            stage=Stage.EGRESS_IF,
        )


def _transparent_parts(session, trail, crossings, leg, region, conn_state="new"):
    """Evaluate every transparent gate and keep each service and address partition."""
    parts = [(dict(leg), region)]
    for ingress, egress in crossings:
        following = []
        for current, flow in parts:
            if current.get("blocked"):
                following.append((current, flow))
                continue
            trail.hop(
                ingress["uid"], "Interface", ingress.get("name") or "bridge ingress", stage=Stage.INGRESS_IF
            )
            if ingress.get("instance"):
                trail.hop(
                    ingress["instance"],
                    "FirewallInstance" if ingress.get("kind") == "bridge" else "Device",
                    f"VS {ingress.get('vsid', '?')}",
                    "transparent transit",
                    stage=Stage.DEVICE,
                )
            if ingress.get("kind") != "bridge":
                following.append((current, flow))
            else:
                gate = FirewallTransition(
                    session,
                    ingress["device"],
                    ingress["uid"],
                    egress["uid"],
                    acl_direction="in",
                    conn_state=conn_state,
                )
                for decided, effect in gate.apply(flow):
                    child = dict(current)
                    child["fw_uids"] = sorted(set(child.get("fw_uids", ())) | set(gate.considered))
                    if effect.kind == "pass":
                        child["indeterminate"] = True
                        child["indeterminate_reason"] = "bridge VS policy was not observed"
                    else:
                        _apply_firewall_region(
                            trail, child, dict(effect.data), child.get("src_label", "flow"), "bridge"
                        )
                    child["bridge_contexts"] = [*child.get("bridge_contexts", []), ingress.get("instance")]
                    following.append((child, decided))
            trail.hop(
                egress["uid"], "Interface", egress.get("name") or "bridge egress", stage=Stage.EGRESS_IF
            )
        parts = following
    return parts


def _next_hop_stage(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    grp: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    downstream_src: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    src_label: str,
    lane: int,
    rib: Any | None,
    depth: int,
    visited: frozenset[str],
    intra_network: bool,
    *,
    max_hops: int,
    conn_state: str = "new",
    src_port: Any = None,
    _vsx_target: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]] | None, int]:
    """Continue the trace through a resolvable next-hop device.

    Returns (inner legs, lane) when the far device answered for this flow
    part, and (None, lane) when the leg stays local. A next hop that cannot
    be followed (unresolvable, non-adjacent, a loop, or past the hop cap)
    marks the leg indeterminate, and the leg stays local.

    The adjacency evidence comes from the table that resolves the next hop.
    That is the exporting table for a route leaked from another context, and
    the table of this group for any other route. `max_hops` is the L3 hop cap
    of this trace. `src_port` is the source port of the flow as stated. It
    reaches the far device unchanged because no gate translates it.

    When several interfaces hold the next hop and no record names the one
    that forwards (`tie_rivals` of `_next_hop_device`), the walk is drawn
    through the lowest uid. Each other owner is walked on a copy of the trail.
    The legs are indeterminate when one of these walks gives another answer
    (`_walk_outcomes`), or when `_TIE_PROBE_CAP` leaves an owner unwalked.
    """
    owner: tuple[dict[str, Any] | None, str | None] = (None, None)
    # A VSX target from the crossings walk is the next hop and replaces the
    # result of the owner lookup.
    if route["next_hop"] and not intra_network and _vsx_target is None:
        # A leaked route resolves its next hop in the exporting context
        # (r.next_hop_vrf), and the owner pick is scoped to that context.
        leaked = route.get("next_hop_vrf") if route.get("next_hop_vrf") != grp["table_uid"] else None
        owner = _next_hop_device(
            session,
            route["next_hop"],
            leaked or grp["table_uid"],
            gw,
            leaked=bool(leaked),
            egress_uid=route.get("egress_uid"),
        )

    def walk(
        on: _Trail, on_leg: dict[str, Any], through: tuple[dict[str, Any] | None, str | None]
    ) -> tuple[list[dict[str, Any]] | None, int]:
        return _next_hop_walk(
            session,
            on,
            on_leg,
            grp,
            gw,
            route,
            dst_part,
            downstream_src,
            port,
            proto,
            src_label,
            lane,
            rib,
            depth,
            visited,
            intra_network,
            through,
            max_hops=max_hops,
            conn_state=conn_state,
            src_port=src_port,
            _vsx_target=_vsx_target,
        )

    won = owner[0]
    rivals: list[dict[str, Any]] = (won or {}).get("tie_rivals") or []
    if won is None or not rivals:
        return walk(trail, leg, owner)
    # The trail and the leg as they are at the start of each owner's walk.
    start = copy.deepcopy((trail, leg)) if trail.tie_probes < _TIE_PROBE_CAP else None
    inner, lane_after = walk(trail, leg, owner)
    drawn = inner if inner is not None else [leg]
    if all(ll.get("indeterminate") for ll in drawn):
        return inner, lane_after
    answered = _walk_outcomes(trail, drawn)
    reason = None
    for rival in rivals:
        if start is None or trail.tie_probes >= _TIE_PROBE_CAP:
            reason = (
                f"{src_label}: the trace did not follow {_owner_label(rival)} for next hop "
                f"{route['next_hop']} after {_TIE_PROBE_CAP} tied next hops, and no record names "
                "the device that forwards"
            )
            break
        trail.tie_probes += 1
        on, on_leg = copy.deepcopy(start)
        on.tie_probes = trail.tie_probes
        with _mtu_not_capturing():
            far, _ = walk(on, on_leg, (None, rival["tie_why"]) if rival.get("tie_why") else (rival, None))
        trail.tie_probes = on.tie_probes
        # An enclosing recorded walk depends on the visits that this walk tested (`walk_memo`).
        for probes, tested in zip(trail.visit_probes, on.visit_probes, strict=True):
            probes |= tested
        if _walk_outcomes(on, far if far is not None else [on_leg]) != answered:
            reason = (
                f"{src_label}: the trace through {_owner_label(rival)} and the trace through "
                f"{_owner_label(won)} answer differently for next hop {route['next_hop']}, and "
                "no record names the device that forwards"
            )
            break
    if reason is not None:
        for ll in drawn:
            ll["indeterminate"] = True
            ll.setdefault("indeterminate_reason", reason)
        trail.warn(reason)
    return inner, lane_after


# How many tied next-hop owners one trace walks on a copy of the trail.
_TIE_PROBE_CAP = 16


def _owner_label(row: dict[str, Any]) -> str:
    """The device and the interface of a next-hop owner, in the form of the tie note."""
    return f"{row.get('dev_name') or row.get('dev_uid')} {row.get('if_name')}"


def _leg_outcomes(legs: list[dict[str, Any]]) -> frozenset[tuple[str, bool, bool, bool]]:
    """The answers of a walk without the names of its devices. Each leg gives
    the answer of `leg_result`, whether the path leaves the twin, whether it
    leaves the estate, and whether it ends on the destination."""
    return frozenset(
        (
            str(leg_result(ll).answer),
            bool(ll.get("boundary")),
            bool(ll.get("left_estate")),
            bool(ll.get("delivered")),
        )
        for ll in legs
    )


def _walk_outcomes(trail: _Trail, legs: list[dict[str, Any]]) -> tuple[Any, ...]:
    """`_leg_outcomes` of `legs`, and of the legs and the arrival that the walk
    left on each carrier context of `trail` (`_decap_stage`)."""
    carried = tuple(
        (
            _leg_outcomes(ctx.get("resumed") or []),
            _leg_outcomes([ctx["arrival"]] if ctx.get("arrival") else []),
        )
        for ctx in trail.carrier_stack
    )
    return _leg_outcomes(legs), carried


def _next_hop_walk(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    grp: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    downstream_src: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    src_label: str,
    lane: int,
    rib: Any | None,
    depth: int,
    visited: frozenset[str],
    intra_network: bool,
    owner: tuple[dict[str, Any] | None, str | None],
    *,
    max_hops: int,
    conn_state: str,
    src_port: Any,
    _vsx_target: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]] | None, int]:
    """`_next_hop_stage` through `owner`, which holds the owner of the next hop
    and the reason it is not resolved (`_next_hop_device`)."""
    nh_dev, nh_why = owner
    leaked = route.get("next_hop_vrf") if route.get("next_hop_vrf") != grp["table_uid"] else None
    if _vsx_target is None:
        explicit_target, crossings, transit_error = vsx.resolve(
            session, route.get("egress_uid"), route.get("next_hop")
        )
    else:
        explicit_target, crossings, transit_error = _vsx_target, [], None
    if transit_error:
        return _indeterminate_stop(trail, leg, lane, transit_error, boundary=True)
    if explicit_target:
        nh_dev, nh_why = explicit_target, None
        if crossings:
            return _vsx_crossing_legs(
                session,
                trail,
                leg,
                grp,
                gw,
                route,
                dst_part,
                downstream_src,
                port,
                proto,
                src_label,
                lane,
                rib,
                depth,
                visited,
                intra_network,
                max_hops=max_hops,
                conn_state=conn_state,
                src_port=src_port,
                explicit_target=explicit_target,
                crossings=crossings,
            )
    # The owner of a next-hop address is one hop away only when the address
    # is on a prefix that this device is connected to.
    #
    # The evidence comes from the table that resolves the next hop.
    #
    # The table name is printed only for a resolved owner whose adjacency is
    # checked. An explicit target is adjacent by definition, and the code
    # reads neither the name nor the evidence for it.
    adj_table = grp["table_name"]
    if leaked:
        checked = nh_dev and not nh_why and not explicit_target
        adj_table = (_vrf_name(session, leaked) or leaked) if checked else leaked
    adjacent: bool | None = True
    if not explicit_target:
        evidence = _table_adjacency(session, trail, gw, leaked or grp["table_uid"])
        adjacent = (
            _next_hop_adjacent(route["next_hop"], evidence) if nh_dev and route.get("next_hop") else None
        )
    checked_adjacent = adjacent
    transport, adjacent = _resolve_transport(
        session, trail, gw, route, nh_dev, adjacent, rib, depth, visited, src_label
    )
    # The next hop resolved through the global table, with or without a
    # transport device. Two PEs on one link cross no device.
    resolved = checked_adjacent is False and adjacent is True
    skip = len(transport)
    # The gateway of the far leg is read before the stop check. A loop is a
    # return to a device in the table that it was already routed in, and that
    # table is the table of the far gateway.
    gw2, far_note, far_why = (
        _far_gateway(session, grp, gw, nh_dev, resolved, leaked or grp["table_uid"])
        if nh_dev and not nh_why and adjacent is not False
        else (None, None, None)
    )
    far_visit = _routing_visit(session, trail, gw2) if gw2 else None
    if far_visit is not None:
        # The loop check below reads the visited set (`walk_memo`).
        trail.probe_visit(far_visit)
    stop = _next_hop_stop_reason(
        gw,
        route,
        nh_dev,
        nh_why,
        adjacent,
        adj_table,
        far_visit,
        visited,
        depth + 1 + skip,
        max_hops,
        src_label,
    )
    if stop:
        leg["indeterminate"] = True
        leg.setdefault("indeterminate_reason", stop)
        trail.warn(stop)
    elif nh_dev and gw2:
        if nh_dev.get("tie_note"):
            trail.notes.append(f"{src_label}: {nh_dev['tie_note']}")
        _warn_context_crossing(trail, leg, nh_dev, src_label)
        if adjacent is None:
            # The table records no connected prefix of the address family of
            # the next hop. The hop is drawn with a note and without a flag.
            trail.notes.append(
                f"{src_label}: table {adj_table} records nothing of the address "
                f"family of next hop {route['next_hop']}, so the hop to "
                f"{_dev_label(nh_dev)} was drawn without checking adjacency"
            )
        trail.depth = depth + 1 + skip
        _mtu_crossing(trail, nh_dev["if_uid"], enforcement="l3", direction="rx")
        _draw_arrival(trail, nh_dev)
        if nh_dev.get("carried"):
            _warn_carried(trail, nh_dev)
        if far_note:
            trail.notes.append(f"{src_label}: {far_note}")
        far_visited = (
            visited
            | {d["dev_uid"] for d in transport}
            | {_routing_visit(session, trail, d) for d in transport}
        )
        start_lane = lane
        # Equal-cost lanes that reconverge enter this device in the same way.
        # One walk of the device serves every such lane (`walk_memo`).
        inner, lane = walk_memo.walk(
            trail,
            gw2,
            (downstream_src, dst_part, port, proto, src_port),
            depth + 1 + skip,
            conn_state,
            far_visited,
            start_lane,
            lambda: _device_stage(
                session,
                trail,
                gw2,
                downstream_src,
                dst_part,
                port,
                proto,
                start_lane,
                rib,
                depth + 1 + skip,
                far_visited,
                max_hops=max_hops,
                conn_state=conn_state,
                src_port=src_port,
            ),
        )
        if far_why:
            trail.warn(f"{src_label}: {far_why}")
        for il in inner:
            _merge_upstream_leg(il, leg)
            if transport:
                il["transport"] = [str(_dev_label(d)) for d in transport]
            if far_why:
                il["indeterminate"] = True
                il.setdefault("indeterminate_reason", f"{src_label}: {far_why}")
        trail.depth = depth  # back to this device for the sibling routes
        return inner, lane
    elif route["next_hop"] and not intra_network:
        # No interface in the twin holds the next hop, and the path leaves the
        # twin here. By a collected uplink, the leg is the edge of the estate
        # (`_estate_exit`). Anywhere else, the leg is in a warned `boundary` state.
        leg["boundary"] = True
        uplink = None if leg.get("carrier") else _estate_exit(session, route, route.get("egress_uid"))
        inside = _estate_part(session, dst_part) if uplink is not None else []
        if inside:
            # An address of the estate is sent to the edge. The route is missing
            # on this device, and the leg gets a warned boundary.
            uplink = None
        if uplink is not None:
            # The leg is the edge of the estate on the basis from `_estate_exit`.
            leg["left_estate"] = _left_estate(
                gw, route, route.get("egress_uid"), route.get("egress_name"), uplink
            )
            _mark_next_hop_exit(trail, leg, gw, route, uplink, dst_part, downstream_src, src_label)
            return None, lane
        trail.warn(
            f"{src_label}: next hop {route['next_hop']} is not held by any interface in the "
            f"graph; the path leaves the twin at {_dev_label(gw)}"
        )
        if inside:
            _warn_estate_destination(session, trail, src_label, gw, route, dst_part)
    return None, lane


def _mark_next_hop_exit(
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    uplink: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    downstream_src: list[tuple[int, int, int]],
    src_label: str,
) -> None:
    """Mark a route whose next hop is the provider's, beyond a collected uplink,
    as the edge of the estate. The note names the edge. The egress interface
    is where a reply enters the twin again, as `_mark_twin_exit` records it
    for an exit by interface only."""
    exit_name = route.get("egress_name") or "the egress interface"
    by = uplink.get("name") or exit_name
    if uplink.get("basis") == "site-zone":
        # An answer that rests on the declaration of the operator names that declaration.
        trail.notes.append(
            f"{src_label}: {route['cidr']} leaves by {exit_name} toward next hop {route['next_hop']}, "
            f"the internet by {_exit_basis_words(leg['left_estate'])}; the path leaves the twin at "
            f"{_dev_label(gw)}"
        )
    else:
        trail.notes.append(
            f"{src_label}: {route['cidr']} leaves by {by} toward next hop {route['next_hop']}, "
            f"beyond the collected uplink; the path leaves the twin at {_dev_label(gw)}"
        )
    leg["_terminal"] = {
        "dev_uid": gw["dev_uid"],
        "dev_name": gw["dev_name"],
        **{k: gw[k] for k in ("firewall_instance_uid", "vsid", "vsx_kind") if k in gw},
        "context_uid": leg.get("context_uid"),
        "wire_sources": _to_cidrs(downstream_src),
        "wire_destinations": _to_cidrs(dst_part),
        "if_uid": route.get("egress_uid"),
        "if_name": exit_name,
        "origin": (
            {"uid": uplink["uid"], "kind": "WanLink", "label": uplink.get("name") or "wan"}
            if uplink.get("uid")
            else {"uid": route.get("egress_uid"), "kind": "Interface", "label": exit_name}
        ),
    }


def _vsx_crossing_legs(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    grp: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    downstream_src: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    src_label: str,
    lane: int,
    rib: Any | None,
    depth: int,
    visited: frozenset[str],
    intra_network: bool,
    *,
    max_hops: int,
    conn_state: str,
    src_port: Any,
    explicit_target: dict[str, Any],
    crossings: list[Any],
) -> tuple[list[dict[str, Any]], int]:
    """The legs past the transparent VSX gates in front of an explicit next
    hop. Each decided rectangle continues to that next hop on its own lane,
    and a blocked rectangle ends there.

    The leg of each rectangle is a copy of its part. A field that the walk
    of one rectangle writes into its leg stays out of the next rectangle."""
    flow = _query_region(downstream_src, dst_part, port, proto, src_port)
    parts = _transparent_parts(session, trail, crossings, leg, flow, conn_state)
    result = []
    for part, decided in parts:
        for rect in decided:
            rect_leg = dict(
                part,
                lane=lane,
                service=_region_service(None, port_spec(rect.dport), rect.proto, port_spec(rect.sport)),
            )
            trail.lane = lane
            if rect_leg.get("blocked"):
                result.append(rect_leg)
                lane += 1
                continue
            inner, lane = _next_hop_stage(
                session,
                trail,
                rect_leg,
                grp,
                gw,
                route,
                list(rect.dst),
                list(rect.src),
                port_spec(rect.dport),
                rect.proto,
                src_label,
                lane,
                rib,
                depth,
                visited,
                intra_network,
                max_hops=max_hops,
                conn_state=conn_state,
                src_port=port_spec(rect.sport),
                _vsx_target=explicit_target,
            )
            result.extend(inner if inner is not None else [rect_leg])
            if inner is None:
                lane += 1
    return result, lane


def _resolve_transport(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    route: dict[str, Any],
    nh_dev: dict[str, Any] | None,
    adjacent: bool | None,
    rib: Any | None,
    depth: int,
    visited: frozenset[str],
    src_label: str,
) -> tuple[list[dict[str, Any]], bool | None]:
    """The transport devices to a non-adjacent next hop, and the adjacency
    after them.

    A next hop behind transit devices resolves through the global table by
    recursive resolution, drawn as the transport lane under this route. When
    it resolves, the owner is one recursive hop away, and the trace continues
    through the owner at the depth past the devices crossed."""
    if not (nh_dev and adjacent is False):
        return [], adjacent
    crossed = _transport_walk(session, trail, gw, route["next_hop"], nh_dev, rib, depth, visited, src_label)
    if crossed is None:
        return [], adjacent
    trail.notes.append(
        f"{src_label}: next hop {route['next_hop']} is not on a connected prefix of "
        f"{_dev_label(gw)}; resolved recursively in the global table"
        + (f" through {', '.join(str(_dev_label(d)) for d in crossed)}" if crossed else "")
    )
    return crossed, True


def _warn_context_crossing(
    trail: _Trail, leg: dict[str, Any], nh_dev: dict[str, Any], src_label: str
) -> None:
    """Mark the leg indeterminate when the one owner of the next hop is in a
    context that the table of the route has no recorded relation to
    (`gates.routing._single_owner_scope`). The hop is drawn."""
    note = nh_dev.get("context_note")
    if not note:
        return
    leg["indeterminate"] = True
    leg.setdefault("indeterminate_reason", f"{src_label}: {note}")
    trail.warn(f"{src_label}: {note}")


def _warn_carrier_tie(
    trail: _Trail, leg: dict[str, Any], nh_dev: dict[str, Any], next_hop: Any, label: str
) -> None:
    """Mark the leg indeterminate when other interfaces tie with `nh_dev` for
    the next hop of the carrier (`tie_rivals` of `_next_hop_device`). The
    carrier is walked through `nh_dev` only."""
    rivals = nh_dev.get("tie_rivals")
    if not rivals:
        return
    others = ", ".join(_owner_label(r) for r in rivals)
    reason = (
        f"{label}: carrier next hop {next_hop} is held by {_owner_label(nh_dev)} and by {others}, "
        f"the carrier is traced through {_owner_label(nh_dev)} only, and no record names the "
        "device that forwards"
    )
    leg["indeterminate"] = True
    leg.setdefault("indeterminate_reason", reason)
    trail.warn(reason)


def _next_hop_stop_reason(
    gw: dict[str, Any],
    route: dict[str, Any],
    nh_dev: dict[str, Any] | None,
    nh_why: str | None,
    adjacent: bool | None,
    adj_table: Any,
    far_visit: str | None,
    visited: frozenset[str],
    far_depth: int,
    max_hops: int,
    src_label: str,
) -> str | None:
    """The reason the walk cannot continue to the next-hop device, or None
    when it can. The owner is unresolved, not adjacent, already visited in the
    table that the far leg would be routed in (`far_visit`, a loop), or past
    the hop cap at `far_depth`."""
    if nh_why:
        return f"{src_label}: {nh_why}"
    if nh_dev and adjacent is False:
        return (
            f"{src_label}: no connected prefix, host route or own address of "
            f"{_dev_label(gw)} in table {adj_table} covers next hop "
            f"{route['next_hop']}; transit device(s) between here and {_dev_label(nh_dev)} "
            "are not represented, so the path is not traced through it"
        )
    if nh_dev and far_visit is not None and far_visit in visited:
        return (
            f"{src_label}: next hop {route['next_hop']} returns to "
            f"{_dev_label(nh_dev)}: routing loop, trace stopped"
        )
    if nh_dev and far_depth >= max_hops:
        return f"{src_label}: path exceeds {max_hops} L3 hops; trace stopped at {_dev_label(nh_dev)}"
    return None


def _far_gateway(
    session: Any,
    grp: dict[str, Any],
    gw: dict[str, Any],
    nh_dev: dict[str, Any],
    resolved: bool,
    nh_table: str | None,
) -> tuple[dict[str, Any], str | None, str | None]:
    """The next-hop device as the gateway that the far leg starts on, a note,
    and the reason the far leg is not decided.

    The note names the table that the far leg continues in when that table is
    another table than the table of the next hop. The far leg is not decided
    when the far PE holds several tables of the routing domain, or no table
    for a route of a table that is not global. `resolved` is whether the next
    hop was resolved through the global table (`_resolve_transport`).
    `nh_table` is the table that the next hop resolves in."""
    far_if_uid, far_if_name, far_anchor = nh_dev["if_uid"], nh_dev["if_name"], nh_dev.get("anchor")
    note = why = None
    stands_in = False
    if resolved:
        # A route resolved through the global table is a VPN route. The flow
        # continues on the far PE in the table of the same routing domain,
        # which the VPN label selects. The global table of the loopback is
        # not used.
        same_domain = _path._read_one(
            session, _DOMAIN_MATE_INTERFACE_QUERY, table=grp["table_uid"], dev=nh_dev["dev_uid"]
        )
        if same_domain:
            far_if_uid, far_if_name = same_domain["if_uid"], same_domain["if_name"]
            far_anchor = same_domain["vrf_uid"]
            stands_in = True
            # The interface stands in for the table. The flow arrives from the
            # core, and the arrival interface is not collected.
            note = (
                f"on {_dev_label(nh_dev)} the flow continues in "
                f"table {same_domain['vrf_name']}, the same routing domain as {grp['table_name']}; "
                f"{far_if_name} of that table stands in for the arrival interface"
            )
            mates = _path._read_one(
                session, _DOMAIN_MATE_TABLES_QUERY, table=grp["table_uid"], dev=nh_dev["dev_uid"]
            )
            # An answer without a count (a graph without the read) means one table.
            if mates and int(mates.get("tables") or 1) > 1:
                names = ", ".join(sorted(str(n) for n in mates.get("names") or []))
                why = (
                    f"{_dev_label(nh_dev)} holds {mates['tables']} tables of the routing domain of "
                    f"{grp['table_name']} ({names}); which one the VPN label selects is not collected"
                )
        elif not _is_global_table(session, gw, nh_table):
            why = (
                f"{_dev_label(nh_dev)} holds no table of the routing domain of {grp['table_name']}; "
                "the table the VPN label selects there is not known"
            )
    gw2: dict[str, Any] = {
        "dev_uid": nh_dev["dev_uid"],
        "dev_name": nh_dev["dev_name"],
        **{
            k: nh_dev[k]
            for k in ("firewall_instance_uid", "vsid", "vsx_kind", "vsx_cluster", "vsx_state")
            if k in nh_dev
        },
        "if_uid": far_if_uid,
        "if_name": far_if_name,
        # The far leg is scoped by the context of the picked owner. Rows without
        # scope keys keep the scope of the trace.
        "l3dom": nh_dev.get("l3dom") or gw.get("l3dom"),
        "anchor": far_anchor or gw.get("anchor"),
    }
    if stands_in:
        # The flow arrives from the core and not on `if_uid`. A PBR policy of
        # that interface does not see the flow (`_part_groups`).
        gw2["if_stands_in"] = True
    return gw2, note, why


def _is_global_table(session: Any, gw: dict[str, Any], table_uid: str | None) -> bool:
    """Whether `table_uid` is the global table of the device (`_LOCAL_VRF_QUERY`).
    A next hop resolved there continues in the global table of the far device."""
    vrf = _path._read_one(session, _LOCAL_VRF_QUERY, dev=gw["dev_uid"])
    return bool(vrf) and vrf.get("vrf_uid") == table_uid


@connection_scope
def _lb_stage(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    vs_rows: list[dict[str, Any]],
    dst_host: str,
    src_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    lane: int,
    depth: int,
    visited: frozenset[str],
    rib: Any | None,
    *,
    max_hops: int,
    conn_state: str = "new",
    region: FlowRegion | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """The LOAD_BALANCER stage, run in place of `_delivery_walk` on a VIP hit.

    Returns the legs of this VirtualService and the next free lane, as every
    other stage in this module does. `leg` is the leg of the device so far,
    with its dNAT, PBR, route, filter and sNAT recorded. One clone of it is
    folded into the recursed legs of each surviving member.

    `vs_rows` is every VirtualService bound to this device for `dst_host`, in
    uid order. Two vservers on one VIP (web-80 and web-443 on one address)
    are the ordinary appliance shape. The protocol and the port of the flow
    pick the vserver that claims the flow.

    `region` is the `FlowRegion` of the leg on the region path. The claim is
    then read on the region (`_vip_claims_region`). A VirtualService whose
    protocol and port lie inside the sets of the region claims the part of
    the region that it covers, and the member recursion continues on that
    part. The part of the region that no VirtualService claims is one further
    leg, marked indeterminate and named. A point leg leaves `region` None and
    reads `port` and `proto`.
    """
    # The mark where the recording of this stage starts, taken in the way
    # `_group_legs` takes `group_pre_start` and `part_pre_start`. The hops
    # recorded from here to the fan-out are the pre-fork chain of this device
    # for the pool. Only that chain is replayed into the further member lanes.
    pre_start = len(trail.hops)

    rect: Rect | None = region.rects[0] if region is not None and region.rects else None
    claims, claimed_rects = _lb_claims(vs_rows, rect, proto, port)
    claimed = [r for r, state in claims if state == _MATCH]
    if len(claimed) != 1:
        return _lb_unclaimed_stop(trail, leg, vs_rows, claims, claimed, dst_host, lane)
    vs_row = claimed[0]
    _pin_vip_instance(trail, [vs_row])
    vs_label = _vs_label(vs_row)
    # The part of the region that this VirtualService claims, and the part
    # that no VirtualService on the VIP claims (region path only).
    claimed_rect = claimed_rects.get(vs_row["uid"])
    unclaimed: tuple[Rect, ...] = ()
    if rect is not None and claimed_rect is not None:
        unclaimed = rect.subtract(claimed_rect)
        if unclaimed:
            leg["service"] = _region_service(
                None, port_spec(claimed_rect.dport), claimed_rect.proto, port_spec(claimed_rect.sport)
            )
    trail.hop(vs_row["uid"], "VirtualService", vs_label, f"VIP {dst_host}", stage=Stage.LOAD_BALANCER)
    if not _vip_supported(vs_row):
        # This engine has no evaluator for this VirtualService kind (gslb,
        # cs-only content switching). `lb_uids` stays unset.
        return [leg], lane + 1
    leg["lb_uids"] = [vs_row["uid"]]
    members = _pool_members(session, vs_row["uid"])
    members, loops = _lb_loop_members(members, dst_host)
    if loops:
        # A member whose own address is the VIP dispatches the flow back into
        # this same VirtualService. It is reported and not followed.
        leg["indeterminate"] = True
        trail.warn(
            f"{vs_label}: pool member(s) target the VIP {dst_host} itself, so this pool "
            f"dispatches back into the same virtual service: {_member_names(loops)}. Those "
            "members are named, not followed."
        )
    regions = _member_regions(members)
    if regions.collapsed:
        return _indeterminate_stop(trail, leg, lane, f"{vs_label}: {regions.note}; marked INDETERMINATE")
    followed = {r["uid"] for r in regions.members}
    skipped = [
        m for m in members if m["uid"] not in followed and (m.get("state") or "").strip().lower() == "down"
    ]
    if skipped:
        trail.notes.append(f"{vs_label}: pool member(s) skipped as down: {_member_names(skipped)}")
    if depth + 1 >= max_hops:
        # This check stops a VIP that load-balances back onto itself. It is a
        # hairpin on the same device (the recursion below reuses `gw`), and the
        # visited-loop guard of the next hop does not see it.
        return _indeterminate_stop(
            trail,
            leg,
            lane,
            f"{vs_label}: path exceeds {max_hops} L3 hops through the load balancer; trace "
            f"stopped at {_dev_label(gw)}",
        )
    # The pre-fork hops of this stage are replayed into each further member lane.
    pre = [dict(h) for h in trail.hops[pre_start:]]
    first_lane = lane
    vip_set = _intervals([dst_host])
    legs: list[dict[str, Any]] = []
    # The reads that are the same for every member, kept for the next member.
    member_reads: dict[Any, Any] = {}
    for member in regions.members:
        trail.at(lane)
        # The recursion below leaves the trail on the next pipeline depth. The
        # LB hops of each member belong to the pipeline of this device. The
        # depth is restored first, and the Pool and PoolMember of every member
        # stay in the column of the load balancer.
        trail.depth = depth
        if lane != first_lane:
            _replay_hops(trail, pre)
        if member.get("pool_uid"):
            trail.hop(
                member["pool_uid"], "Pool", member.get("pool_name") or "pool", stage=Stage.LOAD_BALANCER
            )
        member_port = _int_or_none(member.get("port")) or port
        trail.hop(
            member["uid"],
            "PoolMember",
            member.get("name") or member["ip"],
            f"→ {member['ip']}:{member_port}" if member_port else f"→ {member['ip']}",
            stage=Stage.LOAD_BALANCER,
        )
        member_set = _intervals([member["ip"]])
        member_leg, new_src = _lb_member_leg(
            session,
            trail,
            leg,
            gw,
            vs_row,
            vs_label,
            member,
            member_set,
            member_port,
            src_set,
            vip_set,
            member_reads,
        )
        cont_port, cont_proto = _lb_continuation(member_port, port, proto, claimed_rect)
        inner, lane = _device_stage(
            session,
            trail,
            gw,
            new_src,
            member_set,
            cont_port,
            cont_proto,
            lane,
            rib,
            depth + 1,
            visited,
            max_hops=max_hops,
            conn_state=conn_state,
        )
        for il in inner:
            _merge_upstream_leg(il, member_leg)
        legs.extend(inner)
        # `_device_stage` returns the next free lane.
    # The recursion of the last member left the trail on the device of the
    # pool member. The depth is restored here.
    trail.depth = depth
    _pin_vip_instance(trail, [vs_row])
    if unclaimed and claimed_rect is not None:
        # The part of the service range of the region that no VirtualService
        # on the VIP claims is one named leg.
        known_miss = _vip_known_miss(vs_rows, claims)
        claims_part = f"{vs_label}: claims {_rects_label((claimed_rect,))} of the flow's service range; "
        if known_miss:
            verdict = f"BLOCKED at VIP {dst_host}: no virtual service serves {_rects_label(unclaimed)}"
            warning = claims_part + f"no virtual service on VIP {dst_host} serves {_rects_label(unclaimed)}"
        else:
            verdict = f"{vs_label}: part of the flow's service range is not claimed by this VIP"
            warning = claims_part + (
                f"{_rects_label(unclaimed)} is not claimed by any virtual service on VIP {dst_host} "
                "and is marked INDETERMINATE"
            )
        legs.append(
            _lb_side_leg(
                trail,
                leg,
                lane,
                pre,
                blocked=known_miss,
                lb_uids=sorted(r["uid"] for r in vs_rows),
                service=_rects_service(unclaimed),
                verdict=verdict,
                warning=warning,
            )
        )
        lane += 1
    if regions.surplus:
        # The healthy members past the member cap are one leg that names the
        # cap and the members where it stopped.
        legs.append(
            _lb_side_leg(
                trail,
                leg,
                lane,
                pre,
                verdict=f"{vs_label}: pool members past the member cap, not followed",
                warning=f"{vs_label}: {regions.note}; those members are marked INDETERMINATE",
            )
        )
        lane += 1
    return legs, lane


def _pin_vip_instance(trail: _Trail, rows: list[dict[str, Any]]) -> None:
    """Record the VIP address the flow terminates on.

    The flow terminates on this address whatever the load-balancer stage
    decides next. A VirtualService is bound here, and no further device
    answers for the address. The address is recorded before the fan-out and
    again after it.

    The instance is taken from the vservers that the stage answers with."""
    ip_uid = next((r["ip_uid"] for r in rows if r.get("ip_uid")), None)
    if ip_uid:
        trail.find_dst(ip_uid)


def _vip_elsewhere_reason(
    session: Any, ip: str, proto: str | None, port: int | None, region: FlowRegion | None = None
) -> str | None:
    """The reason a flow delivered to `ip` is undecided when no VirtualService
    on `ip` is bound to the delivering device and the load balancer that it is
    bound to is not walked. The collectors bind a VirtualService to the Device
    or the RedundancyGroup of the load balancer. A one-arm layout reaches that
    device only through the server segment of the delivering router."""
    rows = _vip_elsewhere(session, ip, proto, port, region)
    return _vip_elsewhere_text(ip, rows) if rows else None


def _vip_elsewhere_text(ip: str, rows: list[dict[str, Any]], cause: str | None = None) -> str:
    """The reason from `_vip_elsewhere_reason` for the VirtualService rows
    `rows`, with the reason their load balancer was not walked when it is known."""
    names = ", ".join(sorted({_vs_label(r) for r in rows}))
    where = ", ".join(sorted({str(r["on_uid"]) for r in rows}))
    return (
        f"{ip} is the VIP of {names} on {where}, which is not on the drawn path"
        + (f"; {cause}" if cause else "")
        + "; the pool and the server-side path are not evaluated"
    )


def _offpath_lb(
    session: Any,
    trail: _Trail,
    ip: str,
    segment: str | None,
    proto: str | None,
    port: int | None,
    region: FlowRegion | None,
    visited: frozenset[str],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
    """The load balancer that answers for `ip` when no VirtualService on `ip`
    is bound to the device that delivers the flow onto `segment`, the prefix
    of the VIP.

    The collectors bind a VirtualService to the Device or the RedundancyGroup
    of the load balancer. In a one-arm layout the router delivers the VIP on
    its server segment. The load balancer is the Device that the
    VirtualService is ON, or a Device that is a MEMBER_OF the RedundancyGroup
    that it is ON. The flow arrives on the interface of that device that holds
    an address in `segment`.

    Returns (that device as the gateway of the load balancer stage, its
    VirtualService rows on `ip`, None). Returns (None, [], why) when a
    VirtualService bound elsewhere claims the flow or can claim it, and its
    load balancer or its interface on the segment cannot be named. Returns
    (None, [], None) when nothing bound elsewhere claims the flow. With
    several members of one group on the segment, the lowest device uid is
    walked and a note names the pick. No collector records the active member."""
    rows = _vip_elsewhere(session, ip, proto, port, region)
    if not rows:
        return None, [], None
    targets = sorted({str(r["on_uid"]) for r in rows})
    if len(targets) > 1:
        cause = f"they are bound to {len(targets)} load balancers, and which one answers is not decided"
        return None, [], _vip_elsewhere_text(ip, rows, cause)
    on_uid = targets[0]
    cands = _lb_segment_interfaces(session, on_uid, segment, ip) if segment else []
    if not cands:
        cause = f"no interface of {on_uid} holds an address in {segment or 'the delivering segment'}"
        return None, [], _vip_elsewhere_text(ip, rows, cause)
    pick = cands[0]
    lb_name = pick["device_name"] or pick["device_uid"]
    if pick["device_uid"] in visited:
        return None, [], _vip_elsewhere_text(ip, rows, f"the walk already crossed {lb_name}")
    vs_rows = _vip_bindings(session, ip, pick["device_uid"])
    if not vs_rows:
        cause = f"no virtual service on {ip} is bound to {lb_name}"
        return None, [], _vip_elsewhere_text(ip, rows, cause)
    devices = sorted({str(c["device_name"] or c["device_uid"]) for c in cands})
    if len(devices) > 1:
        trail.notes.append(
            f"{ip}: {', '.join(devices)} of {on_uid} each hold an address in {segment}; traced via "
            f"{lb_name} {pick['if_name']} (lowest uid), since no member is recorded as the active one"
        )
    lb_gw = {
        "dev_uid": pick["device_uid"],
        "dev_name": pick["device_name"],
        "if_uid": pick["if_uid"],
        "if_name": pick["if_name"],
        "cidr": segment,
        "anchor": pick.get("vrf_uid"),
        "l3dom": None,
    }
    return lb_gw, vs_rows, None


def _offpath_lb_stage(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    lb_gw: dict[str, Any],
    vs_rows: list[dict[str, Any]],
    dst_host: str,
    src_set: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    lane: int,
    depth: int,
    visited: frozenset[str],
    rib: Any | None,
    *,
    max_hops: int,
    conn_state: str = "new",
    region: FlowRegion | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """The arrival of the flow on the load balancer from `_offpath_lb`, on its
    interface on the delivering segment, and the LOAD_BALANCER stage run with
    that device as the gateway. `depth` is the pipeline depth of the load
    balancer. The trail is left on that depth, as `_lb_stage` leaves it."""
    trail.depth = depth
    _mtu_crossing(trail, lb_gw["if_uid"], enforcement="l3", direction="rx")
    _draw_arrival(trail, lb_gw)
    lb_visited = visited | {lb_gw["dev_uid"], _routing_visit(session, trail, lb_gw)}
    return _lb_stage(
        session,
        trail,
        leg,
        lb_gw,
        vs_rows,
        dst_host,
        src_set,
        port,
        proto,
        lane,
        depth,
        lb_visited,
        rib,
        max_hops=max_hops,
        conn_state=conn_state,
        region=region,
    )


def _offpath_lb_legs(
    ctx: WalkContext,
    leg: dict[str, Any],
    route: dict[str, Any],
    dst_host: str,
    downstream_src: list[tuple[int, int, int]],
    r_port: Any,
    r_proto: Any,
    leg_region: FlowRegion | None,
    lane: int,
) -> tuple[list[dict[str, Any]], int] | None:
    """The legs of a routed leg delivered to a VIP that no VirtualService on
    this device is bound to.

    The load balancer on the segment of the route answers for a VirtualService
    bound to it. The trace enters that device on its interface on the segment
    and returns its legs. Otherwise the function returns None. The leg is left
    undecided when a VirtualService bound elsewhere claims the flow or can
    claim it, and its load balancer cannot be named."""
    trail = ctx.trail
    lb_gw, lb_rows, lb_why = _offpath_lb(
        ctx.session,
        trail,
        dst_host,
        route.get("cidr"),
        _scalarize_for_legacy(r_proto),
        _scalarize_port_for_legacy(r_port),
        leg_region,
        ctx.visited,
    )
    if lb_gw is None:
        if lb_why:
            leg["indeterminate"] = True
            leg.setdefault("indeterminate_reason", lb_why)
            trail.warn(lb_why)
        return None
    legs, lane = _offpath_lb_stage(
        ctx.session,
        trail,
        leg,
        lb_gw,
        lb_rows,
        dst_host,
        downstream_src,
        _scalarize_port_for_legacy(r_port),
        _scalarize_for_legacy(r_proto),
        lane,
        ctx.depth + 1,
        ctx.visited,
        ctx.rib,
        max_hops=ctx.max_hops,
        conn_state=ctx.conn_state,
        region=None if leg_region is None else _narrow_region(leg_region, src=tuple(_merge(downstream_src))),
    )
    trail.depth = ctx.depth  # back to this device for the sibling routes
    return legs, lane


def _mark_vip_elsewhere(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    ip: str,
    proto: str | None,
    port: int | None,
    region: FlowRegion | None = None,
) -> None:
    """Leave the leg undecided when the address it ends on is a VIP bound to
    a device the trace did not visit."""
    why = _vip_elsewhere_reason(session, ip, proto, port, region)
    if why:
        leg["indeterminate"] = True
        leg.setdefault("indeterminate_reason", why)
        trail.warn(why)


def _lb_claims(
    vs_rows: list[dict[str, Any]], rect: Rect | None, proto: str | None, port: int | None
) -> tuple[list[tuple[dict[str, Any], str]], dict[str, Rect]]:
    """The claim of each VirtualService on the flow, and on the region path
    the part of the region that each one claims."""
    claimed_rects: dict[str, Rect] = {}
    if rect is None:
        return [(r, _vip_claims(r, proto, port)) for r in vs_rows], claimed_rects
    claims: list[tuple[dict[str, Any], str]] = []
    for r in vs_rows:
        vc = _vip_claims_region(r, rect)
        claims.append((r, vc.state))
        if vc.claimed is not None:
            claimed_rects[r["uid"]] = vc.claimed
    return claims, claimed_rects


def _vip_known_miss(vs_rows: list[dict[str, Any]], claims: list[tuple[dict[str, Any], str]]) -> bool:
    """Whether every VirtualService on the VIP that does not claim the flow
    misses it for certain. That is the case when each one is of a kind that
    this stage evaluates and no claim is undecided."""
    return all(_vip_supported(r) for r in vs_rows) and not any(state == _UNKNOWN for _r, state in claims)


def _lb_unclaimed_stop(
    trail: _Trail,
    leg: dict[str, Any],
    vs_rows: list[dict[str, Any]],
    claims: list[tuple[dict[str, Any], str]],
    claimed: list[dict[str, Any]],
    dst_host: str,
    lane: int,
) -> tuple[list[dict[str, Any]], int]:
    """Stop the leg when nothing on this VIP claims the flow or more than one
    VirtualService claims it. Both cases are INDETERMINATE and name every
    candidate. A VIP whose every VirtualService misses the flow blocks the leg."""
    named = claimed or vs_rows
    _pin_vip_instance(trail, named)
    for row in named:
        trail.hop(row["uid"], "VirtualService", _vs_label(row), f"VIP {dst_host}", stage=Stage.LOAD_BALANCER)
    labels = ", ".join(_vs_label(r) for r in named)
    lb_uids = sorted(r["uid"] for r in named)
    if not claimed and _vip_known_miss(vs_rows, claims):
        leg["blocked"] = True
        leg["verdict"] = f"BLOCKED at VIP {dst_host}: no virtual service serves this flow's protocol and port"
        leg["lb_uids"] = lb_uids
        trail.notes.append(f"{labels}: the flow's protocol or port does not match this VIP")
        return [leg], lane + 1
    if len(claimed) > 1:
        reason = (
            f"{labels}: {len(claimed)} virtual services on VIP {dst_host} claim this flow's "
            "protocol and port; which pool serves it is not determined"
        )
    else:
        why = (
            "this VIP is scoped to a protocol or port this flow does not carry"
            if any(state == _UNKNOWN for _r, state in claims)
            else "a virtual service on this VIP is of a kind this engine does not evaluate"
        )
        reason = f"{labels}: {why}; marked INDETERMINATE rather than evaluated"
    return _indeterminate_stop(trail, leg, lane, reason, lb_uids=lb_uids)


def _lb_member_leg(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    vs_row: dict[str, Any],
    vs_label: str,
    member: dict[str, Any],
    member_set: list[tuple[int, int, int]],
    member_port: Any,
    src_set: list[tuple[int, int, int]],
    vip_set: list[tuple[int, int, int]],
    member_reads: dict[Any, Any],
) -> tuple[dict[str, Any], list[tuple[int, int, int]]]:
    """A copy of the leg of the device for one pool member, with the rewrite
    from the VIP to the member and any server-side source rewrite recorded on
    it, and the source of the member-side connection.

    `member_reads` keeps the rows of the reads that do not depend on the
    member across the members of one pool: the SNAT_FROM address of the
    VirtualService, the SNIP candidates of the device and the table of the
    ingress interface."""
    member_leg = dict(leg)
    # The new translation is appended, and every earlier translation stays on the leg.
    member_leg["dnat"] = (leg.get("dnat") or []) + [
        {"to": _to_cidrs(member_set), "port": member_port, "rule_uid": member["uid"]}
    ]
    new_src, snat_note, snat_indeterminate = _lb_snat(
        session, vs_row, gw["dev_uid"], member["ip"], src_set, memo=member_reads
    )
    # The rewrite from the VIP to the member on this device as a NAT step with direction 'lb'.
    member_leg["nat_chain"] = (leg.get("nat_chain") or []) + [
        {
            "device": gw["dev_uid"],
            "direction": "lb",
            "context_uid": leg.get("context_uid")
            or _memo_read(
                member_reads,
                ("default_table", gw["if_uid"]),
                lambda: _default_table_uid(session, gw["if_uid"]),
            ),
            "rule_uid": member["uid"],
            "vip_name": vs_label,
            "pre": {"src": _to_cidrs(src_set), "dst": _to_cidrs(vip_set)},
            "post": {"src": _to_cidrs(new_src), "dst": _to_cidrs(member_set)},
        }
    ]
    if new_src is not src_set:
        # `mode` names the snat_mode that resolved the address.
        member_leg["snat"] = (leg.get("snat") or []) + [
            {
                "sources": _to_cidrs(src_set),
                "to": _describe(new_src),
                "mode": _snat_mode_of(vs_row),
                "rule_uid": vs_row["uid"],
            }
        ]
    if snat_note:
        # snat_mode none, and every mode that does not resolve to an address, leave this note.
        if snat_indeterminate:
            member_leg["indeterminate"] = True
            trail.warn(f"{vs_label}: {snat_note}")
        else:
            trail.notes.append(f"{vs_label}: {snat_note}")
    return member_leg, new_src


def _lb_continuation(
    member_port: Any, port: int | None, proto: str | None, claimed_rect: Rect | None
) -> tuple[Any, Any]:
    """The port and the protocol of the server-side connection. The port is
    the port of the member when it records one, and the port of the client
    otherwise. On the region path they are the port range and the protocol
    set of the claimed rectangle, because the point slots are neutralised there."""
    if claimed_rect is None:
        return member_port, proto
    return (member_port if member_port is not None else port_spec(claimed_rect.dport)), claimed_rect.proto


def _lb_side_leg(
    trail: _Trail,
    leg: dict[str, Any],
    lane: int,
    pre: list[dict[str, Any]],
    *,
    warning: str,
    blocked: bool = False,
    **fields: Any,
) -> dict[str, Any]:
    """One leg beside the members, on its own lane, with the pre-fork hops of
    the stage replayed into it. `fields` name what the leg stands for, and
    `warning` holds the reason it is not followed. The leg is indeterminate.
    With `blocked`, the leg is a decided block and `warning` goes to the notes."""
    trail.at(lane)
    _replay_hops(trail, pre)
    side = dict(leg)
    side["lane"] = lane
    if blocked:
        side["blocked"] = True
        trail.notes.append(warning)
    else:
        side["indeterminate"] = True
        trail.warn(warning)
    side.update(fields)
    return side


def _rects_service(rects: tuple[Rect, ...]) -> dict[str, Any]:
    """The `service` field for the union of the service dimensions of several
    rectangles. The protocols and the ports are each unioned. A dimension that
    one of the rectangles does not state is left out, as in `_region_service`."""
    protos: set[int] = set()
    ports: list[tuple[int, int, int]] = []
    sports: list[tuple[int, int, int]] = []
    proto_stated = port_stated = sport_stated = True
    for r in rects:
        proto_stated = proto_stated and r.proto is not None
        port_stated = port_stated and r.dport is not None
        sport_stated = sport_stated and r.sport is not None
        protos |= r.proto or set()
        ports.extend(r.dport or ())
        sports.extend(r.sport or ())
    service: dict[str, Any] = {
        "proto": _proto_display_names(frozenset(protos)) if proto_stated else [],
        "ports": _port_pairs(_merge(ports)) if port_stated else [],
    }
    if sport_stated:
        service["src_ports"] = _port_pairs(_merge(sports))
    return service


def _rects_label(rects: tuple[Rect, ...]) -> str:
    """The service dimensions of several rectangles as one compact label."""
    service = _rects_service(rects)
    proto = ",".join(service["proto"]) or "any protocol"
    ports = ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in service["ports"]) or "any port"
    return f"{proto}/{ports}"


def _lb_loop_members(
    members: list[dict[str, Any]], dst_host: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split a pool into the members to follow and the ones that are the VIP.

    A PoolMember whose TARGETS address is the VIP of the VirtualService sends
    the flow back into the stage that chose it. The caller reports it.
    """
    vip = _intervals([dst_host])
    loops = [m for m in members if m.get("ip") and _intersect(_intervals([m["ip"]]), vip)]
    if not loops:
        return members, []
    loop_uids = {m["uid"] for m in loops}
    return [m for m in members if m["uid"] not in loop_uids], loops


def _route_leg(
    session: Any,
    trail: _Trail,
    grp: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    dst_label: str | None,
    lane: int,
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    rib: Any | None,
    nat_rows: list[dict[str, Any]] | None,
    depth: int,
    visited: frozenset[str],
    src_label: str,
    *,
    max_hops: int,
    lane_pre: list[dict[str, Any]] | None = None,
    conn_state: str = "new",
) -> tuple[list[dict[str, Any]], int]:
    """The whole leg of one candidate route: egress resolution, filter, source
    NAT, tunnel, then next-hop recursion or local delivery.

    Returns the legs of this route (its own leg, or the legs of the far device
    when the trace continues through the next hop) and the next free lane.

    A scalar `port` and `proto` walk one leg for the whole flow part. A range
    fans out over the decided regions of the firewall
    (`_firewall_region_list`), with one cloned leg per region.

    `lane_pre` holds the group and route hops that this lane had when
    `_group_legs` called this function, and that `_group_legs` replays into
    its ECMP lanes. A region fork replays those hops and the pre-fork hops of
    this route. A sibling region lane then starts from the same point as an
    equal-cost sibling lane.

    The walk is `_walk_route` over a `WalkContext`.
    """
    ctx = WalkContext(
        session=session,
        trail=trail,
        port=port,
        proto=proto,
        rib=rib,
        max_hops=max_hops,
        depth=depth,
        visited=visited,
        conn_state=conn_state,
    )
    return _walk_route(ctx, grp, gw, route, dst_part, dst_label, lane, nat_rows, src_label, lane_pre)


@dataclass(frozen=True)
class _RouteScope:
    """The values that every region lane of one route shares (`_walk_route` builds it)."""

    grp: dict[str, Any]
    gw: dict[str, Any]
    route: dict[str, Any]
    dst_part: list[tuple[int, int, int]]
    dst_label: str | None
    src_label: str
    nat_rows: list[dict[str, Any]] | None
    is_ranged: bool
    sport: Any
    filter_state: dict[str, Any]
    fw_port: Any
    considered: Any
    zone_out_if: Any
    intra_network: bool
    # The destination is on a network that this device serves. The far side
    # is drawn from this device, and the flow is not routed further.
    local_net: bool
    # The interface that the far side is drawn from: the egress of the
    # delivering route, or the ingress of this device when the route resolved none.
    via_uid: Any


def _walk_route(
    ctx: WalkContext,
    grp: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    dst_label: str | None,
    lane: int,
    nat_rows: list[dict[str, Any]] | None,
    src_label: str,
    lane_pre: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], int]:
    """`_route_leg` over a walk context."""
    session, trail, port, proto = ctx.session, ctx.trail, ctx.port, ctx.proto
    route_pre_start = len(trail.hops)
    # The `FlowRegion` of the group, set by `_device_stage` for every group of
    # a query walked as a region. The leg takes it into the filter, the source
    # NAT and the next device, narrowed to the part of this route.
    grp_region: FlowRegion | None = grp.get("region")
    sport = grp.get("src_port")
    is_ranged = _states_a_range(_unwrap_single(port), _unwrap_single(proto)) or grp_region is not None
    if is_ranged and grp_region is None:
        grp_region = _query_region(grp["sources"], dst_part, port, proto, sport)
    if route.get("discard"):
        return _discard_leg(ctx, grp, gw, route, dst_part, dst_label, lane, src_label, is_ranged, sport)
    route, zone_out_if, intra_network, delivers_local = _resolve_route_egress(
        session, trail, route, gw, src_label, grp["table_uid"]
    )

    filter_state: dict[str, Any] = {}
    fw_port: Any = port
    if is_ranged and grp_region is not None:
        out_if = route.get("egress_uid") or zone_out_if
        # The regions are decided on what `_apply_firewall` gets on the point path.
        # The read gets a stand-in dict because the legs of its flags do not
        # exist yet. `_apply_filter_state` puts the flags on every leg that the
        # partition produces. The filter reads the region of the group as the
        # packet arrived: the destination part of this route, the view of the
        # filter on it, and the source port of the query.
        fw_dst, fw_port = _filter_dst(session, trail, filter_state, gw, grp, dst_part, port, src_label)
        fw_region = _narrow_region(
            grp_region, src=tuple(_merge(grp["sources"])), dst=tuple(_merge(fw_dst)), dport=_ivals_of(fw_port)
        )
        fw_regions, considered = _firewall_region_list(session, gw, out_if, fw_region)
        fw_regions = _spend_region_budget(trail, fw_regions)
    else:
        fw_regions, considered = [None], []

    # Every new region lane forks from `lane_pre` and the hops that this route
    # recorded before the partition.
    pre_fork = (
        [*(lane_pre or ()), *(dict(h) for h in trail.hops[route_pre_start:])] if len(fw_regions) > 1 else []
    )
    scope = _RouteScope(
        grp=grp,
        gw=gw,
        route=route,
        dst_part=dst_part,
        dst_label=dst_label,
        src_label=src_label,
        nat_rows=nat_rows,
        is_ranged=is_ranged,
        sport=sport,
        filter_state=filter_state,
        fw_port=fw_port,
        considered=considered,
        zone_out_if=zone_out_if,
        intra_network=intra_network,
        local_net=intra_network or delivers_local or route.get("kind") == "ORIGINATES",
        via_uid=route.get("egress_uid") or gw["if_uid"],
    )
    legs: list[dict[str, Any]] = []
    for idx, fw in enumerate(fw_regions):
        if idx:
            trail.at(lane)
            _replay_hops(trail, pre_fork)
        region_legs, lane = _route_region_legs(ctx, scope, fw, lane)
        legs.extend(region_legs)
    return legs, lane


def _discard_leg(
    ctx: WalkContext,
    grp: dict[str, Any],
    gw: dict[str, Any],
    route: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    dst_label: str | None,
    lane: int,
    src_label: str,
    is_ranged: bool,
    sport: Any,
) -> tuple[list[dict[str, Any]], int]:
    """The leg of a discard route. The flow is dropped on this device."""
    trail, discard = ctx.trail, route["discard"]
    via_uid = route.get("egress_uid") or gw["if_uid"]
    leg = _build_route_leg(trail, grp, route, lane, src_label, dst_label, gw["dev_uid"])
    leg["blocked"] = True
    leg["verdict"] = f"BLOCKED by {discard} route {route['cidr']}"
    if is_ranged:
        # This leg answers only for the range of its group.
        leg["service"] = _region_service(None, ctx.port, ctx.proto, sport)
    trail.notes.append(
        f"{src_label}: {route['cidr']} is a {discard} route on "
        f"{gw['dev_name'] or gw['dev_uid']}; the flow is dropped here"
    )
    _blocked_destination(ctx.session, trail, leg, gw, dst_part, via_uid, src_label, False)
    return [leg], lane + 1


def _route_egress(
    ctx: WalkContext,
    rs: _RouteScope,
    leg: dict[str, Any],
    fw: Any,
    r_port: Any,
    r_proto: Any,
    leg_region: FlowRegion | None,
) -> tuple[bool, list[tuple[int, int, int]]]:
    """The egress filter and the source NAT of one region lane. Returns whether
    the filter denied the flow, and the source set that the next device sees."""
    session, trail, grp, gw, route = ctx.session, ctx.trail, rs.grp, rs.gw, rs.route
    if route["egress_uid"]:
        if rs.is_ranged:
            return _local_egress_stage_ranged(
                session,
                trail,
                leg,
                gw,
                grp,
                route,
                rs.dst_part,
                fw,
                rs.considered,
                r_port,
                r_proto,
                rs.src_label,
                rs.nat_rows,
                ctx.rib,
                region=leg_region,
                conn_state=ctx.conn_state,
            )
        # `is_ranged` is False here, and `port` and `proto` have the scalar
        # shape that `_local_egress_stage` expects. `_first_match` uses the
        # same cast at the same kind of boundary.
        return _local_egress_stage(
            session,
            trail,
            leg,
            gw,
            grp,
            route,
            rs.dst_part,
            cast("int | None", ctx.port),
            cast("str | None", ctx.proto),
            rs.src_label,
            rs.nat_rows,
            ctx.rib,
            conn_state=ctx.conn_state,
        )
    if rs.is_ranged:
        denied = _remote_zone_stage_ranged(
            session,
            trail,
            leg,
            gw,
            route,
            fw,
            rs.considered,
            rs.src_label,
            rs.zone_out_if,
            rs.intra_network,
            conn_state=ctx.conn_state,
        )
        return denied, grp["sources"]
    denied = _remote_zone_stage(
        session,
        trail,
        leg,
        gw,
        grp,
        route,
        rs.dst_part,
        cast("int | None", ctx.port),
        cast("str | None", ctx.proto),
        rs.src_label,
        rs.zone_out_if,
        rs.intra_network,
        conn_state=ctx.conn_state,
    )
    return denied, grp["sources"]


def _resumed_legs(
    leg: dict[str, Any], resumed: list[dict[str, Any]], lane: int
) -> tuple[list[dict[str, Any]], int]:
    """The legs that the far device of the tunnel walked after it
    decapsulated the flow."""
    outer = {k: v for k, v in leg["carrier"].items() if k != "resumed"}
    for il in resumed:
        _merge_upstream_leg(il, leg)
        # The continuation names the tunnel that it came out of. A leg that
        # entered a second tunnel on the far side keeps its own carrier and
        # lists this tunnel as an outer carrier.
        if il.get("carrier"):
            il.setdefault("outer_carriers", []).insert(0, outer)
        else:
            il["carrier"] = outer
    return resumed, max(lane + 1, leg["carrier"].get("next_lane") or 0)


def _mark_twin_exit(
    session: Any,
    trail: _Trail,
    rs: _RouteScope,
    leg: dict[str, Any],
    wan: dict[str, Any] | None,
    downstream_src: list[tuple[int, int, int]],
) -> None:
    """Mark an interface-only route toward a network that this device does not
    serve, with no tunnel traced. The graph holds nothing beyond the
    interface. A drawn WAN link is the expected exit and gets a note. Any
    other exit gets a warning.
    """
    gw, route = rs.gw, rs.route
    leg["boundary"] = True
    exit_name = route.get("egress_name") or "the egress interface"
    by = wan["name"] if wan and wan.get("name") else exit_name
    # The edge of the estate (`left_estate`) is a drawn WAN link that is not
    # MPLS. Without a drawn link, it is a default route out of a device whose
    # site zone is "internet" (`_site_zone_exit`).
    uplink: dict[str, Any] | None = None
    if wan:
        # The drawn WAN link decides (`exit_basis`, an interface-only route).
        if exit_basis(
            link_kinds=[wan.get("kind")], default_origin=None, site_zone=None, family=4, next_hop=False
        ):
            uplink = {"uid": wan["uid"], "name": wan.get("name"), "basis": "wan-link"}
    elif str(route.get("cidr")) in _DEFAULT_ROUTES and route.get("egress_uid"):
        row = _path._read_one(session, _EGRESS_UPLINK_QUERY, u=route["egress_uid"]) or {}
        basis = exit_basis(
            # Without a drawn link, only an MPLS link on the interface outranks the zone.
            link_kinds=["mpls"]
            if row.get("link_uid") and str(row.get("link_kind") or "").lower() == "mpls"
            else [],
            default_origin=None,
            site_zone=row.get("site_zone"),
            family=_DEFAULT_ROUTES[str(route.get("cidr"))],
            next_hop=False,
            # An SD-WAN boundary row is a default route by construction
            # (`_default_route_wan_hop`).
            sdwan=str(route.get("kind") or "").startswith("SDWAN_"),
        )
        uplink = _site_zone_exit(row) if basis == "site-zone" else None
    inside = _estate_part(session, rs.dst_part) if uplink is not None else []
    if inside:
        # An address of the estate is sent to the edge, and the route is
        # missing on this device. The leg gets no marker. The note and the
        # reply start of every other interface-only exit stay, and a warning
        # names the address.
        _warn_estate_destination(session, trail, rs.src_label, gw, route, rs.dst_part)
        uplink = None
    zoned = ""
    if uplink is not None:
        # A field of the contract object is null when the egress interface has
        # no name.
        leg["left_estate"] = _left_estate(gw, route, rs.via_uid, route.get("egress_name"), uplink)
        if uplink["basis"] == "site-zone":
            zoned = f", the internet by {_exit_basis_words(leg['left_estate'])}"
    trail.notes.append(
        f"{rs.src_label}: {route['cidr']} leaves by {by} with no next hop in the graph{zoned}; "
        f"the path leaves the twin at {gw['dev_name'] or gw['dev_uid']}"
    )
    # A reply for this leg starts on this interface (`reply_capture` of `_trace_domain`).
    leg["_terminal"] = {
        "dev_uid": gw["dev_uid"],
        "dev_name": gw["dev_name"],
        **{k: gw[k] for k in ("firewall_instance_uid", "vsid", "vsx_kind") if k in gw},
        "context_uid": leg.get("context_uid"),
        "wire_sources": _to_cidrs(downstream_src),
        "wire_destinations": _to_cidrs(rs.dst_part),
        "if_uid": rs.via_uid,
        "if_name": exit_name,
        # The origin station of the reply: the WAN link that this leg drew, or
        # else the egress interface.
        "origin": (
            {"uid": wan["uid"], "kind": "WanLink", "label": wan["name"] or "wan"}
            if wan
            else {"uid": rs.via_uid, "kind": "Interface", "label": exit_name}
        ),
    }


def _deliver_locally(
    ctx: WalkContext,
    rs: _RouteScope,
    leg: dict[str, Any],
    dst_host: str,
    delivering_if: Any,
    downstream_src: list[tuple[int, int, int]],
) -> dict[str, Any] | None:
    """Walk the far side down to the switchport or AP and the endpoint of the
    destination, and record where a reply for this leg starts. Returns the
    attachment row of the destination, or None."""
    session, trail, gw, route = ctx.session, ctx.trail, rs.gw, rs.route
    dst_row = _dst_attachment(session, rs.dst_part, _anchor_of(gw), delivering_if)
    if dst_row is not None:
        trail.find_dst(dst_row["ip_uid"])
    if trail.dst_translated and trail.orig_dst is not None:
        # A dNAT fired on this lane. The instance that this lane landed on is
        # the row of the queried address in the context of this device.
        pub_row = _dst_attachment(session, trail.orig_dst, _anchor_of(gw), gw["if_uid"])
        if pub_row is not None:
            trail.pin_dst(pub_row["ip_uid"])
    leg["delivered"] = _delivery_walk(
        session,
        trail,
        dst_row,
        dst_host,
        delivering_if,
        None,
        delivering_if,
    )
    # The start of a reply for this leg (internal only, see `_trace_domain`).
    leg["_terminal"] = {
        "dev_uid": gw["dev_uid"],
        "dev_name": gw["dev_name"],
        **{k: gw[k] for k in ("firewall_instance_uid", "vsid", "vsx_kind") if k in gw},
        "context_uid": leg.get("context_uid"),
        "wire_sources": _to_cidrs(downstream_src),
        "wire_destinations": _to_cidrs(rs.dst_part),
        "if_uid": delivering_if,
        "attachment_uid": dst_row.get("att_uid") if dst_row and dst_row.get("att_is_port") else None,
        "if_name": route.get("egress_name") if route.get("egress_uid") else gw.get("if_name"),
        # The origin station of the reply: the Endpoint that the far-side walk
        # drew when the destination resolved one, or else the delivering
        # interface.
        "origin": (
            {
                "uid": dst_row["ep_uid"],
                "kind": "Endpoint",
                "label": dst_row.get("ep_name") or dst_host,
            }
            if dst_row and dst_row.get("ep_uid")
            else {
                "uid": delivering_if,
                "kind": "Interface",
                "label": route.get("egress_name") if route.get("egress_uid") else gw.get("if_name"),
            }
        ),
    }
    return dst_row


def _transparent_crossing_legs(
    ctx: WalkContext,
    rs: _RouteScope,
    leg: dict[str, Any],
    delivering_if: Any,
    dst_row: dict[str, Any],
    downstream_src: list[tuple[int, int, int]],
    r_port: Any,
    r_proto: Any,
    r_sport: Any,
    lane: int,
) -> tuple[list[dict[str, Any]], int] | None:
    """The legs of a transparent device between the delivering interface and
    the port of the destination, one per decided rectangle. None when no such
    device is between them."""
    trail = ctx.trail
    _, crossings, gap = vsx.resolve(ctx.session, delivering_if, None, target=dst_row["att_uid"])
    if gap:
        leg["indeterminate"] = True
        trail.warn(gap)
    if not crossings:
        return None
    legs: list[dict[str, Any]] = []
    for child, decided in _transparent_parts(
        ctx.session,
        trail,
        crossings,
        leg,
        _query_region(downstream_src, rs.dst_part, r_port, r_proto, r_sport),
        ctx.conn_state,
    ):
        for rect in decided:
            child = dict(
                child,
                lane=lane,
                service=_region_service(None, port_spec(rect.dport), rect.proto, port_spec(rect.sport)),
            )
            if child.get("blocked"):
                child["delivered"] = False
                child.pop("_terminal", None)
            legs.append(child)
            lane += 1
    return legs, lane


def _route_region_legs(
    ctx: WalkContext, rs: _RouteScope, fw: Any, lane: int
) -> tuple[list[dict[str, Any]], int]:
    """One region lane of a route: its leg through the egress stages, then the
    next hop, the far device of the tunnel, or the local delivery."""
    session, trail, gw, route = ctx.session, ctx.trail, rs.gw, rs.route
    port, proto = ctx.port, ctx.proto
    leg = _build_route_leg(trail, rs.grp, route, lane, rs.src_label, rs.dst_label, gw["dev_uid"])
    leg_region: FlowRegion | None = None
    r_sport = rs.sport
    if rs.is_ranged:
        _apply_filter_state(leg, rs.filter_state)
        flow_fw = _region_in_flow_terms(trail, leg, fw, rs.fw_port, port, rs.src_label)
        leg["service"] = _region_service(flow_fw, port, proto, rs.sport)
        r_port, r_proto = _region_continuation(flow_fw, port, proto)
        r_sport = _region_sport(flow_fw, rs.sport)
        # The flow of this region from here on: the part of the destination of
        # the route, on the service rectangle that the filter decided.
        leg_region = _query_region(rs.grp["sources"], rs.dst_part, r_port, r_proto, r_sport)
    else:
        r_port, r_proto = port, proto
    denied, downstream_src = _route_egress(ctx, rs, leg, fw, r_port, r_proto, leg_region)
    if denied:
        # The packet stops at the rulebase. The lane ends on its destination,
        # which is drawn past the gate.
        _blocked_destination(session, trail, leg, gw, rs.dst_part, rs.via_uid, rs.src_label, rs.local_net)
        return [leg], lane + 1
    wan = _default_route_wan_hop(session, trail, route, gw)

    # A carrier packet blocked on its way out stops the inner flow. That block
    # is the only block that reaches this point.
    if leg["blocked"]:
        _blocked_destination(session, trail, leg, gw, rs.dst_part, rs.via_uid, rs.src_label, rs.local_net)
        return [leg], lane + 1
    resumed = (leg.get("carrier") or {}).get("resumed")
    if resumed:
        return _resumed_legs(leg, resumed, lane)

    inner, lane = _next_hop_stage(
        session,
        trail,
        leg,
        rs.grp,
        gw,
        route,
        rs.dst_part,
        downstream_src,
        r_port,
        r_proto,
        rs.src_label,
        lane,
        ctx.rib,
        ctx.depth,
        ctx.visited,
        rs.intra_network,
        max_hops=ctx.max_hops,
        conn_state=ctx.conn_state,
        src_port=r_sport,
    )
    if inner is not None:
        return inner, lane  # the legs of the far device are the answer for this flow part
    if not rs.local_net and not route["next_hop"] and not leg.get("carrier"):
        _mark_twin_exit(session, trail, rs, leg, wan, downstream_src)
    if rs.local_net:
        # The walk ends on a network that this device serves. `_finish_trace`
        # reads and drops this internal field (`_check_delivery_context`).
        leg["_local_net"] = True
    if not (rs.local_net and _size(rs.dst_part) == 1):
        return [leg], lane + 1
    # The flow ends on a network that this device serves. The far side is
    # walked down to the switchport or AP and the endpoint of the destination.
    dst_host = _to_cidrs(rs.dst_part)[0].split("/")[0]
    delivering_if = route.get("egress_uid") or gw["if_uid"]
    vs_rows = _vip_bindings(session, dst_host, gw["dev_uid"])
    if vs_rows:
        # A VIP that is also an address of an own interface reaches this stage
        # from `_group_legs` before the route lookup runs. A point query gives
        # the load balancer stage its scalar port and protocol. A region gives
        # it the `FlowRegion` of the leg, which the claim of the stage reads
        # (`_vip_claims_region`). The scalar slots are then neutralised,
        # because a point matcher that reads the spec string of a region answers no.
        return _lb_stage(
            session,
            trail,
            leg,
            gw,
            vs_rows,
            dst_host,
            downstream_src,
            _scalarize_port_for_legacy(r_port),
            _scalarize_for_legacy(r_proto),
            lane,
            ctx.depth,
            ctx.visited,
            ctx.rib,
            max_hops=ctx.max_hops,
            conn_state=ctx.conn_state,
            region=None
            if leg_region is None
            else _narrow_region(leg_region, src=tuple(_merge(downstream_src))),
        )
    handed = _offpath_lb_legs(ctx, leg, route, dst_host, downstream_src, r_port, r_proto, leg_region, lane)
    if handed is not None:
        return handed
    dst_row = _deliver_locally(ctx, rs, leg, dst_host, delivering_if, downstream_src)
    if dst_row and dst_row.get("att_is_port"):
        crossed = _transparent_crossing_legs(
            ctx, rs, leg, delivering_if, dst_row, downstream_src, r_port, r_proto, r_sport, lane
        )
        if crossed is not None:
            return crossed
    return [leg], lane + 1


def _gateway_own_part(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
) -> list[tuple[int, int, int]]:
    """The part of a same-prefix destination that is an address of the
    gateway, read in the table of the gateway interface that the flow arrives
    on. Such a packet is addressed to the router and is not switched past it.

    The result is empty when the source covers an address of the gateway. A
    packet that the router sends to itself does not arrive on that interface.
    Its handling is not modelled, and the flow keeps the switched answer."""
    if not gw.get("dev_uid") or not gw.get("if_uid"):
        return []
    table_uid = interface_table(session, trail, gw["if_uid"])
    own, _rows = _router_local_part(session, gw, table_uid, dst_set)
    if own and _router_local_part(session, gw, table_uid, src_set)[0]:
        return []
    return own


def _router_local_part(
    session: Any,
    gw: dict[str, Any],
    table_uid: str | None,
    dst_set: list[tuple[int, int, int]],
) -> tuple[list[tuple[int, int, int]], list[dict[str, Any]]]:
    """The part of a destination set that is an address of this device.

    Returns (that subset, the interface rows that hold it). Both are empty
    when the destination is elsewhere, and the routing path below then runs
    unchanged.
    """
    if not dst_set:
        return [], []
    rows = _path._read(session, _OWN_ADDRS_QUERY, dev=gw["dev_uid"], vrf=table_uid)
    local = _intersect(dst_set, _intervals([r["ip"] for r in rows if r.get("ip")]))
    if not local:
        return [], []
    return local, _owners_of([r for r in rows if r.get("ip")], local)


def _owners_of(own_ifs: list[dict[str, Any]], dst_part: list[tuple[int, int, int]]) -> list[dict[str, Any]]:
    """The interface rows that hold one part of a router-local destination."""
    return [r for r in own_ifs if r.get("ip") and _intersect(dst_part, _intervals([r["ip"]]))]


def _local_vips(
    session: Any, gw: dict[str, Any], own_ifs: list[dict[str, Any]]
) -> list[tuple[str, list[dict[str, Any]]]]:
    """The addresses of this device that are also a VirtualService VIP.

    The read runs before the router-local split. The LOAD_BALANCER stage then
    answers for an address that the device holds on an interface and serves
    as a VIP. The addresses are in address order, and a device that holds two
    such addresses gets the same answer every time.
    """
    found: list[tuple[str, list[dict[str, Any]]]] = []
    for ip in sorted({str(r["ip"]) for r in own_ifs if r.get("ip")}):
        rows = _vip_bindings(session, ip, gw["dev_uid"])
        if rows:
            found.append((ip, rows))
    return found


_SEGMENT_INTERFACE_QUERY = """
MATCH (dev:Device {uid: $dev})<-[on:ON]-(i:Interface)-[iv:IN_VRF]->(v:VrfInstance)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND on._retired_at IS NULL AND iv._retired_at IS NULL AND NOT i:Retired AND NOT v:Retired
  AND v.collection_ts = $snap
  AND (v.table_id = $segment_id OR v.name = $segment_name)
RETURN i.uid AS if_uid, i.name AS if_name, v.uid AS vrf_uid, v.name AS vrf_name
ORDER BY i.uid LIMIT 1"""


# The Tunnels of the far device with the encapsulation of the carrier, with
# the overlay interface that each one ends on and its table. They are the
# candidates for the interface that the inner flow comes out of
# (`_far_overlay`). The two ENDPOINT shapes, an interface or one of its
# addresses, are those of gates/tunnel.py.
_FAR_OVERLAY_QUERY = """
CALL {
  MATCH (dev:Device:Obj {uid: $dev, collection_ts: $snap})<-[on:ON]-(oi:Interface)<-[e:ENDPOINT]-(peer:Tunnel)
  WHERE on._retired_at IS NULL AND e._retired_at IS NULL AND NOT oi:Retired AND NOT peer:Retired
    AND peer.collection_ts = $snap AND peer.uid <> $tunnel AND peer.encap = $encap
  RETURN peer, oi
  UNION
  MATCH (dev:Device:Obj {uid: $dev, collection_ts: $snap})<-[on:ON]-(oi:Interface)-[h:HAS_IP]->(lip:IpAddress)
  MATCH (peer:Tunnel)-[e:ENDPOINT]->(lip)
  WHERE on._retired_at IS NULL AND h._retired_at IS NULL AND e._retired_at IS NULL
    AND NOT oi:Retired AND NOT lip:Retired AND NOT peer:Retired
    AND peer.collection_ts = $snap AND peer.uid <> $tunnel AND peer.encap = $encap
  RETURN peer, oi
}
OPTIONAL MATCH (oi)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
RETURN DISTINCT peer.uid AS peer_uid, peer.pair AS pair, peer.local_address AS local_address,
       peer.endpoint AS endpoint, peer.allowed_ips AS allowed_ips,
       oi.uid AS if_uid, oi.name AS if_name, v.uid AS vrf_uid
ORDER BY if_uid, peer_uid"""


def _far_overlay(session: Any, gw: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any] | str:
    """The overlay interface that the inner flow comes out of on the far
    device, or the reason it cannot be named.

    The carrier arrives on the interface that holds the far address of the
    tunnel, the underlay. The inner packet comes out of the half of the tunnel
    on the far device, and the interface of that half has its own table,
    filters and zone. That half is the Tunnel of the far device with the same
    encapsulation. It is matched by the first evidence that names exactly one
    interface, in this order:

    1. The pair identifier that both halves of one configured tunnel hold.
    2. The address pair. The local address is the far address, and the
       endpoint is the source of the carrier.
    3. For WireGuard, the peer whose allowed IPs cover the inner source.
       WireGuard accepts the decapsulated packet from that peer. The hub-side
       peer of a dynamic spoke names no endpoint.
    """
    rows = (
        _path._read(
            session, _FAR_OVERLAY_QUERY, dev=gw["dev_uid"], tunnel=ctx["tunnel_uid"], encap=ctx["encap"]
        )
        if ctx.get("encap")
        else []
    )
    inner_src = ctx["inner"]["src"]

    def covers_source(row: dict[str, Any]) -> bool:
        allowed = _intervals([str(c) for c in row.get("allowed_ips") or ()])
        return bool(allowed and inner_src and not _subtract(inner_src, allowed))

    for match in (
        lambda r: bool(ctx.get("pair")) and r.get("pair") == ctx["pair"],
        lambda r: (
            r.get("local_address") == ctx["far_ip"]
            and bool(ctx.get("local"))
            and r.get("endpoint") == ctx["local"]
        ),
        lambda r: ctx.get("encap") == "wireguard" and covers_source(r),
    ):
        hits = [r for r in rows if match(r)]
        interfaces = {r["if_uid"] for r in hits}
        if len(interfaces) == 1:
            return hits[0]
        if len(interfaces) > 1:
            names = ", ".join(sorted(str(r["if_name"] or r["if_uid"]) for r in hits))
            return f"{len(interfaces)} of its tunnel interfaces match the tunnel ({names})"
    if not rows:
        return f"no {ctx.get('encap') or 'unrecorded'} tunnel of its own is recorded for it"
    return "none of its own tunnels is recorded as the other half of this one"


def _decap_stage(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    lane: int,
    depth: int,
    visited: frozenset[str],
    rib: Any | None,
    *,
    max_hops: int,
) -> int:
    """The far end of a tunnel. This device holds the destination of the
    carrier, and the inner flow comes out here and is forwarded by the
    decision of this device.

    The function runs only while the walk is inside a carrier
    (`trail.carrier_stack`) and the router-local part that just terminated is
    the far address of that carrier. The inner flow is walked from this device
    with the same `_device_stage` that every flow gets. The context is popped
    for that walk, and a second tunnel on the far side pushes its own context.
    The legs of the inner flow are left on the context, and `_carrier_walk`
    hands them back to the leg that encapsulated. A carrier that the input
    chain denied does not decapsulate, and the block of the router-local leg
    stays. Returns the next free lane.
    """
    if not trail.carrier_stack or leg.get("blocked"):
        return lane
    ctx = trail.carrier_stack[-1]
    if not _intersect(dst_part, _intervals([ctx["far_ip"]])):
        return lane
    if ctx.get("far_dev") and ctx["far_dev"] != gw["dev_uid"]:
        return lane
    inner = ctx["inner"]
    trail.hop(
        ctx["tunnel_uid"],
        "Tunnel",
        ctx["tunnel_name"] or "tunnel",
        f"decapsulated on {gw['dev_name'] or gw['dev_uid']}; the inner flow resumes here",
        stage=Stage.DECAP,
    )
    ctx["far_dev_name"] = gw["dev_name"] or gw["dev_uid"]
    popped = trail.carrier_stack.pop()
    saved_depth = trail.depth
    # An SD-WAN inner flow comes out in its overlay segment. It is resumed as
    # if it arrived on the interface of this device in the table of that
    # segment. The boundary and the BGP neighbors of the segment are read from
    # that table.
    far_gw = {**gw}
    unmatched = None
    segment = inner.get("segment")
    if not segment:
        overlay = _far_overlay(session, gw, ctx)
        if isinstance(overlay, str):
            # The flow is resumed on the arrival interface, and the path stays
            # drawn. Every inner leg states that its table and filters were read there.
            unmatched = (
                f"{gw['dev_name'] or gw['dev_uid']}: {overlay}, so the interface the inner flow of "
                f"{ctx['tunnel_name'] or ctx['tunnel_uid']} comes out of is not known; it is "
                f"traced from {gw['if_name'] or gw['if_uid']}, where the carrier arrives"
            )
            trail.warn(unmatched)
        elif overlay["if_uid"] != gw["if_uid"]:
            far_gw = {
                **gw,
                "if_uid": overlay["if_uid"],
                "if_name": overlay["if_name"],
                "anchor": overlay.get("vrf_uid") or gw.get("anchor"),
            }
            trail.notes.append(
                f"{gw['dev_name'] or gw['dev_uid']}: the inner flow comes out of "
                f"{overlay['if_name'] or overlay['if_uid']}, the far end of the tunnel"
            )
    if segment:
        seg_if = _path._read_one(
            session,
            _SEGMENT_INTERFACE_QUERY,
            dev=gw["dev_uid"],
            segment_id=str(segment.get("segment_id") or ""),
            segment_name=segment.get("segment_name"),
        )
        if seg_if:
            far_gw = {
                **gw,
                "if_uid": seg_if["if_uid"],
                "if_name": seg_if["if_name"],
                "anchor": seg_if["vrf_uid"],
            }
            trail.notes.append(
                f"{gw['dev_name'] or gw['dev_uid']}: the inner flow resumes in segment "
                f"{segment.get('segment_name') or segment.get('segment_id')} (table {seg_if['vrf_name']})"
            )
    try:
        resumed, lane = _device_stage(
            session,
            trail,
            far_gw,
            inner["src"],
            inner["dst"],
            inner["port"],
            inner["proto"],
            lane,
            rib,
            depth + 1,
            visited,
            max_hops=max_hops,
            conn_state=inner.get("conn_state", "new"),
        )
    finally:
        trail.carrier_stack.append(popped)
        trail.depth = saved_depth
    if unmatched:
        for il in resumed:
            il["indeterminate"] = True
            il.setdefault("indeterminate_reason", unmatched)
    if leg.get("indeterminate"):
        # The arrival leg is not part of the answer. When the input chain could
        # not decide the carrier, the inner flow that it lets in gets that state.
        arrival_why = leg.get("indeterminate_reason") or (
            f"{gw['dev_name'] or gw['dev_uid']}: the input chain could not decide the carrier of "
            f"{ctx['tunnel_name'] or ctx['tunnel_uid']}"
            + (f" ({leg['firewall']})" if leg.get("firewall") else "")
            + ", so the inner flow that resumes here is NOT confirmed"
        )
        for il in resumed:
            il["indeterminate"] = True
            il.setdefault("indeterminate_reason", arrival_why)
    ctx["resumed"] = resumed
    ctx["arrival"] = {
        k: v for k, v in leg.items() if k in ("verdict", "blocked", "indeterminate", "terminus", "fw_uid")
    }
    leg["decapsulated"] = True
    return lane


def _router_local_leg(
    session: Any,
    trail: _Trail,
    grp: dict[str, Any],
    gw: dict[str, Any],
    dst_part: list[tuple[int, int, int]],
    owners: list[dict[str, Any]],
    lane: int,
    port: int | None,
    proto: str | None,
    src_label: str,
    dst_label: str | None,
    *,
    conn_state: str = "new",
) -> dict[str, Any]:
    """The leg for a destination that the device itself answers for.

    Router-local traffic is not forwarded, and the transit stages do not
    apply: no route lookup, no egress interface, no forward zone pair, no
    source NAT and no next hop. The input chain judges the packet. On a zone
    firewall with a local zone, the pair (ingress zone, local zone) judges it.
    """
    leg = _build_route_leg(
        trail,
        grp,
        {"cidr": None, "egress_name": None, "next_hop": None},
        lane,
        src_label,
        dst_label,
        gw["dev_uid"],
    )
    leg["router_local"] = True
    for row in owners:
        trail.hop(
            row["if_uid"],
            "Interface",
            row["if_name"],
            "the destination is this device's own address",
            stage=Stage.DST_ATTACH,
        )
    if _size(dst_part) == 1 and owners:
        trail.find_dst(owners[0]["ip_uid"])
    ifs = ", ".join(sorted({str(r["if_name"]) for r in owners})) or "an unnamed interface"
    dev = gw["dev_name"] or gw["dev_uid"]
    # The place where the packet stops. The leg verdict below and the combined
    # verdict line both read it. `_trace_domain` drops this internal field
    # after it builds the verdict, as it drops `gid`.
    leg["terminus"] = f"{dev} {ifs}"
    trail.notes.append(
        f"{src_label}: {_describe(dst_part)} is an address of {dev} itself, so the flow "
        f"terminates on {ifs} and is judged by the input chain, not by forwarding policy"
    )
    _router_local_filter(
        session, trail, leg, gw, grp["sources"], dst_part, port, proto, src_label, conn_state=conn_state
    )
    if "verdict" not in leg:
        leg["verdict"] = f"router-local, terminates on {leg['terminus']}"
    local_gate_state = leg.pop("_local_gate_state", None)
    if leg.get("blocked"):
        # A flow that the input chain dropped gets no answer and no reply start.
        return leg
    # The reply starts on this device, on the interface that holds the address
    # that the flow terminated on (internal only, see the `reply_capture`
    # handling of `_trace_domain`).
    leg["_terminal"] = {
        "dev_uid": gw["dev_uid"],
        "dev_name": gw["dev_name"],
        **{k: gw[k] for k in ("firewall_instance_uid", "vsid", "vsx_kind") if k in gw},
        "context_uid": leg.get("context_uid"),
        "if_uid": owners[0]["if_uid"] if owners else gw["if_uid"],
        "if_name": owners[0]["if_name"] if owners else gw.get("if_name"),
        # The origin station of the reply: the address of the device that the
        # flow terminated on.
        "origin": {
            "uid": owners[0]["if_uid"] if owners else gw["if_uid"],
            "kind": "Interface",
            "label": owners[0]["if_name"] if owners else gw.get("if_name"),
        },
        # The input crossing, for the reply that this device sends (`_walk_reply_leg`).
        "local_gate_state": local_gate_state,
    }
    return leg


def _router_local_filter(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    *,
    conn_state: str = "new",
) -> None:
    """The input-chain verdict on a packet that the device terminates.

    The leg credits two kinds of gates only. The first kind is the rulebases
    of the chains that this packet does not cross (a recorded chain other
    than input). The second kind is the interface ACLs that the two reads
    examined. An inbound interface ACL has no chain, and it is evaluated here
    as a second pool with the ingress side only. The (ingress zone, local
    zone) rule sets are credited when the local-zone read evaluated the pair.
    A zone-bound ruleset that the read did not settle and a rulebase with no
    recorded chain stay uncredited, and the unevaluated-gate safeguard
    reports them.

    `conn_state` reaches `_firewall_verdict_local` unchanged.

    A forward ('new') call records the gate state of the device, marked
    `local`, for the reply start. The device itself sends the reply to this
    flow. `_apply_firewall_reply` judges that reply by the state policy and
    the output chain.
    """
    considered: list[str] = []
    fw = _router_local_verdict(
        session, trail, leg, gw, sources, dsts, port, proto, src_label, considered, conn_state=conn_state
    )
    if conn_state == "new":
        # The shape that `_apply_firewall` records. A missing gate on the input
        # chain is a pass there too. The state is kept apart from `gate_state`
        # because a leg that continues (a VIP, a decapsulated carrier) can cross
        # this device again, and only the first device of the reply answers.
        # `_router_local_leg` moves it onto the reply start.
        leg["_local_gate_state"] = {
            "policy": fw.get("global_state_policy") if fw else None,
            "permit": not leg.get("blocked") and not leg.get("indeterminate"),
            "credits": sorted({*considered, *([fw["rb_uid"]] if fw else [])}),
            "local": True,
        }


def _router_local_verdict(
    session: Any,
    trail: _Trail,
    leg: dict[str, Any],
    gw: dict[str, Any],
    sources: list[tuple[int, int, int]],
    dsts: list[tuple[int, int, int]],
    port: int | None,
    proto: str | None,
    src_label: str,
    considered: list[str],
    *,
    conn_state: str,
) -> dict[str, Any] | None:
    """The verdict and the leg fields of `_router_local_filter`. Returns the verdict."""
    # A source that is an address of this device means that the device sends
    # the packet to itself (`self_sent` of `_firewall_verdict_local`). The
    # addresses are read in the table of the ingress interface, as
    # `_gateway_own_part` reads them. A host whose address the device holds in
    # another table is not the device.
    own_table = interface_table(session, trail, gw["if_uid"]) if gw.get("if_uid") else None
    self_sent = bool(_router_local_part(session, gw, own_table, sources)[0])
    fw = _firewall_verdict_local(
        session,
        gw["dev_uid"],
        None,
        sources,
        dsts,
        port,
        proto,
        chain="input",
        in_if=gw["if_uid"],
        considered=considered,
        conn_state=conn_state,
        self_sent=self_sent,
    )
    if considered:
        leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), *considered})
    if not fw:
        return None
    trail.hop(
        fw["rb_uid"],
        "FwRulebase",
        fw["rb_name"],
        f"input · {fw['action']} ({fw['by']})",
        stage=Stage.FILTER_RB,
    )
    by = f"rule {fw['pos']}" if fw["pos"] is not None else "default-action"
    if fw["rule_uid"]:
        trail.hop(
            fw["rule_uid"],
            "FwRule",
            f"rule {fw['pos']}" + (f" ({fw['rule_name']})" if fw["rule_name"] else ""),
            fw["action"],
            stage=Stage.FILTER_RULE,
        )
    leg["firewall"] = f"{fw['rb_name']} (input) {fw['action']} by {by}"
    leg["fw_uid"] = fw["rb_uid"]
    leg["fw_uids"] = sorted({*(leg.get("fw_uids") or []), fw["rb_uid"]})
    if fw.get("partial"):
        leg["firewall"] += " (matches part of the range only)"
        trail.warn(
            f"{src_label}: {fw['rb_name']} {by} covers only part of the flow; narrow the query for a verdict"
        )
    trail.notes.append(f"{src_label} to this device: {leg['firewall']}")
    modeled = "an established connection (a reply)" if conn_state == "established" else "a new connection"
    for skip in fw.get("state_skips") or []:
        trail.notes.append(
            f"{src_label}: rule {skip['pos']} is scoped to connection state "
            f"{'/'.join(skip['states'])}; this trace models {modeled}, so the rule "
            "does not govern the router-local flow"
        )
    outcome = classify_action(fw["action"])
    if outcome == DENY:
        leg["blocked"] = True
        leg["verdict"] = f"BLOCKED by {fw['rb_name']} {by}"
    elif outcome == INDETERMINATE:
        leg["indeterminate"] = True
        why = fw.get("indeterminate_reason") or f"{by} has action {fw['action']!r}"
        trail.warn(
            f"{src_label}: {fw['rb_name']} input chain could not decide: {why}. "
            "The flow is NOT confirmed permitted."
        )
    _partial_permit(leg, fw, outcome, by)
    return fw


def _group_legs(
    session: Any,
    trail: _Trail,
    grp: dict[str, Any],
    gw: dict[str, Any],
    lane: int,
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    rib: Any | None = None,
    nat_rows: list[dict[str, Any]] | None = None,
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
    *,
    max_hops: int,
    conn_state: str = "new",
) -> tuple[list[dict[str, Any]], int]:
    """Route lookup for one source group (LPM, ECMP-aware), then one lane per leg.

    Returns the legs of the group and the next free lane. `rib` is a
    RibSource over the parquet side store. Tables too large for the graph
    mirror add candidates through it. `grp["dst"]` and `port` arrive
    destination-translated when a dNAT part produced this group. `nat_rows`
    feeds the source-NAT stage at egress. `max_hops` is the L3 hop cap of
    this trace.

    The walk is `_walk_group` over a `WalkContext`.
    """
    ctx = WalkContext(
        session=session,
        trail=trail,
        port=port,
        proto=proto,
        rib=rib,
        max_hops=max_hops,
        depth=depth,
        visited=visited,
        conn_state=conn_state,
    )
    return _walk_group(ctx, grp, gw, lane, nat_rows)


@dataclass(frozen=True)
class _GroupScope:
    """The values that every lane of one source group shares (`_walk_group` builds it)."""

    grp: dict[str, Any]
    gw: dict[str, Any]
    nat_rows: list[dict[str, Any]] | None
    src_label: str
    # The lane that the group started on. A later lane replays the hops of this lane.
    group_lane: int
    upstream: list[dict[str, Any]]
    group_pre: list[dict[str, Any]]
    # A ranged query reads as "not stated" on the router-local and the no-route reads.
    local_ranged: bool
    local_port: int | None
    local_proto: str | None
    region: FlowRegion | None
    sport: Any

    def start_lane(self, trail: _Trail, lane: int) -> None:
        """Move to `lane`. A lane other than the first lane of the group starts
        with the hops of the first lane up to the fork."""
        trail.at(lane)
        if lane != self.group_lane:
            _replay_upstream(trail, self.upstream)
            _replay_hops(trail, self.group_pre)


def _family_routes(
    session: Any, table_uid: str | None, dst: list[tuple[int, int, int]]
) -> list[dict[str, Any]]:
    """The graph routes of `table_uid` in the address family of the destination."""
    routes = _path._read(session, _ROUTES_QUERY, vrf=table_uid) if table_uid else []
    # A v4 flow is routed by v4 routes only, and a v6 flow by v6 routes only.
    # Routes of the other family are dropped before the fall-through probe below.
    if dst:
        dst_af = dst[0][0]
        routes = [r for r in routes if (":" in (r["cidr"] or "")) == (dst_af == 6)]
    return routes


def _pbr_fall_through(
    ctx: WalkContext, grp: dict[str, Any], gw: dict[str, Any], routes: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[tuple[int, int, int]]]:
    """The group and its routes after a PBR redirect that holds no route.

    A PBR rule whose target table does not resolve (no REDIRECTS_VIA) or holds
    no route for this flow falls through to the table of the ingress
    interface.

    Both route sources are read before the target table is called empty, and
    both are asked for a route to the destination of this flow.

    The kernel falls through per destination address. The question is asked
    of every part of the destination (`_table_cover`). A destination that the
    target table covers in part is split. The covered part is returned as the
    group, and the rest (the third element) is walked as a group of its own,
    which falls through here.
    """
    if grp["pos"] is None:
        return grp, routes, []
    session = ctx.session
    target_uid, target_name = grp["table_uid"], grp["table_name"]
    target_desc = f"table {target_name}" if target_uid else "no resolvable target table"
    covered = _table_cover(ctx, gw, target_uid, routes, grp["dst"]) if grp["dst"] else []
    holds = bool(covered) if grp["dst"] else bool(routes)
    rest = _subtract(grp["dst"], covered) if covered else []
    if holds and not rest:
        return grp, routes, []
    fallback_uid = _default_table_uid(session, gw["if_uid"])
    if not fallback_uid or fallback_uid == target_uid:
        return grp, routes, []
    if holds:
        ctx.trail.notes.append(
            f"PBR rule {grp['pos']} redirects to {target_desc}, which holds a route for "
            f"{_describe(covered)} only; {_describe(rest)} is evaluated separately"
        )
        return _with_dst(grp, covered), routes, rest
    fallback_name = _vrf_name(session, fallback_uid) or "main"
    ctx.trail.notes.append(
        f"PBR rule {grp['pos']} redirects to {target_desc}; neither the graph "
        f"nor the route store holds a route for this flow there, so the flow "
        f"falls through to the ingress interface's own table {fallback_name}"
    )
    grp = {
        **grp,
        "table_uid": fallback_uid,
        "table_name": fallback_name,
        "pbr_target_desc": target_desc,
    }
    return grp, _family_routes(session, grp["table_uid"], grp["dst"]), []


def _with_dst(grp: dict[str, Any], dst: list[tuple[int, int, int]]) -> dict[str, Any]:
    """`grp` narrowed to the destination part `dst`, with its region."""
    part = {**grp, "dst": dst}
    if grp.get("region") is not None:
        part["region"] = _narrow_region(grp["region"], dst=tuple(_merge(dst)))
    return part


def _table_cover(
    ctx: WalkContext,
    gw: dict[str, Any],
    table_uid: str | None,
    routes: list[dict[str, Any]],
    dst: list[tuple[int, int, int]],
) -> list[tuple[int, int, int]]:
    """The part of `dst` that one routing table holds a route for. The table
    is read from its graph rows (`routes`) and, when a side store is given,
    from the rows of the store for that table, with the longest-prefix
    partition that the walk routes with."""
    lookup = None
    if ctx.rib is not None and table_uid:
        lookup = _rib_lookup(ctx.rib, gw["dev_uid"], table_uid, _vrf_name(ctx.session, table_uid))
    # The partition marks the rows that it reads, and the walk reads them again. The rows are copies.
    parts = _route_partition([dict(r) for r in routes], dst, lookup)
    return _merge([iv for region, best in parts if best for iv in region])


def _table_note(grp: dict[str, Any]) -> str:
    """The note of the table hop, which names the table that routes this flow."""
    if grp["pos"] is None:
        return "main table (no PBR match)"
    if grp.get("pbr_target_desc"):
        return f"PBR rule {grp['pos']} fell through to {grp['table_name']}"
    return f"PBR rule {grp['pos']} → {grp['table_name']}"


def _walk_group(
    ctx: WalkContext,
    grp: dict[str, Any],
    gw: dict[str, Any],
    lane: int,
    nat_rows: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], int]:
    """`_group_legs` over a walk context."""
    session, trail, rib = ctx.session, ctx.trail, ctx.rib
    routes = _family_routes(session, grp["table_uid"], grp["dst"])
    claimed = grp
    grp, routes, rest = _pbr_fall_through(ctx, grp, gw, routes)
    if rest:
        # The PBR table covers a part of the destination. That part is walked
        # in the PBR table. The rest is walked as a group of its own that falls
        # through, on a lane that starts with the hops of this lane, as
        # `_walk_device` starts a later group.
        upstream = [h for h in trail.hops if h["lane"] == lane and not h["shared"]]
        incoming = lane
        covered_legs, lane = _walk_group(ctx, grp, gw, lane, nat_rows)
        if lane != incoming and upstream:
            trail.at(lane)
            _replay_upstream(trail, upstream)
        rest_legs, lane = _walk_group(ctx, _with_dst(claimed, rest), gw, lane, nat_rows)
        # Each half names the part of the destination that it answers for.
        return _label_split(covered_legs, grp["dst"]) + _label_split(rest_legs, rest), lane
    # The input-chain verdict of a router-local leg (`_router_local_filter`
    # through `_firewall_verdict_local`) and the filter read of a "no route
    # found" leg (`_no_route_leg`) read a range as "not stated".
    local_ranged = _states_a_range(_unwrap_single(ctx.port), _unwrap_single(ctx.proto))
    table_note = _table_note(grp)

    trail.at(lane)
    # The hops recorded from here until the route lookup forks are replayed into
    # every further lane of this group.
    group_pre_start = len(trail.hops)
    # The hops of this lane from the devices before this one. A fork here
    # starts its new lanes with them.
    upstream = [h for h in trail.hops if h["lane"] == lane and not h["shared"]]
    src_label = _describe(grp["sources"])
    nat_part = grp.get("nat")
    if nat_part:
        _record_dnat_hop(trail, nat_part, src_label)
    vrf_name = _record_table_hops(session, trail, grp, table_note)
    rib_lookup = _rib_lookup(rib, gw["dev_uid"], grp["table_uid"], vrf_name)
    rib_gap = _rib_gap(rib, gw["dev_uid"])
    # The store answered for this table. Its rows are the selection of the
    # device, and a config-only static route that the store does not hold is
    # unconfirmed (`_route_partition` in gates/routing.py).
    observed = rib_lookup is not None and rib_gap is None
    # No store answered, and the collector mirrored the whole RIB of this
    # table into the graph in this run. A forwarding static route that the RIB
    # does not confirm is not installed (`_mark_mirrored_unconfirmed` in
    # gates/routing.py).
    mirrored = not observed and _rib_mirrored(session, grp["table_uid"])
    if rib is not None and getattr(rib, "approximate", False):
        trail.note_once(_APPROXIMATE_RIB_NOTE)
    scope = _GroupScope(
        grp=grp,
        gw=gw,
        nat_rows=nat_rows,
        src_label=src_label,
        group_lane=lane,
        upstream=upstream,
        group_pre=[dict(h) for h in trail.hops[group_pre_start:]],
        local_ranged=local_ranged,
        local_port=None if local_ranged else cast("int | None", ctx.port),
        local_proto=None if local_ranged else cast("str | None", ctx.proto),
        # The `FlowRegion` of the group on the region path. It is routed
        # through the transition of the routing stage below, and the load
        # balancer stage gets it for a VIP that the device itself holds.
        region=grp.get("region"),
        sport=grp.get("src_port"),
    )

    legs: list[dict[str, Any]] = []
    # A destination that is an address of this device does not reach the
    # route lookup. It is split off first and terminated here, and only the
    # remainder is routed. A network-scoped destination that covers an own
    # address and other hosts is split by interval, and each part is handled
    # on its own. The own addresses are those of the table of the ingress
    # interface, also for a flow that a PBR rule claimed. The kernel delivers
    # a packet to a local address before it reads any policy rule, and no
    # interface is bound to a policy table.
    own_table = grp["table_uid"]
    if grp["pos"] is not None:
        own_table = interface_table(session, trail, gw["if_uid"]) or own_table
    local_dst, own_ifs = _router_local_part(session, gw, own_table, grp["dst"])
    routable = _subtract(grp["dst"], local_dst) if local_dst else grp["dst"]
    if local_dst and routable:
        trail.notes.append(
            f"{src_label}: {_describe(local_dst)} is this device's own address and "
            f"{_describe(routable)} is not; the two are evaluated separately"
        )
    parts = _routed_parts(trail, scope, routes, routable, rib_lookup, observed, mirrored)
    if local_dst:
        local_legs, lane = _router_local_legs(ctx, scope, local_dst, own_ifs, bool(routable), lane)
        legs.extend(local_legs)
    for dst_part, best in parts:
        # A router-local split leaves two legs that answer for different
        # halves of the destination, and the routed half names its half too.
        dst_label = _describe(dst_part) if len(parts) > 1 or local_dst else None
        part_legs, lane = _routed_part_legs(ctx, scope, dst_part, best, dst_label, lane)
        legs.extend(part_legs)
    if rib_gap:
        other_routes = rib_gap[1] or (
            getattr(rib, "available", True) is False or _runs_dynamic_routing(session, grp["table_uid"])
        )
        _mark_rib_gap(trail, scope, legs, rib_gap, other_routes)
    return legs, lane


def _routed_parts(
    trail: _Trail,
    scope: _GroupScope,
    routes: list[dict[str, Any]],
    routable: list[tuple[int, int, int]],
    rib_lookup: Any,
    observed: bool,
    mirrored: bool = False,
) -> list[tuple[list[tuple[int, int, int]], list[dict[str, Any]]]]:
    """The routed destination parts, one per distinct best route, with notes
    on the routes that lost a tie and on a destination that spans routes."""
    # A route that the provenance rule dropped from a tie is named before the
    # parts are walked, with the reason it lost the selection.
    outranked: list[str] = []
    if scope.region is not None:
        # On the region path, the longest-prefix match is the transition of the
        # routing stage over the region of the group, with one part per
        # distinct best route. It is the partition of `_route_partition`, read
        # back in the shape of the parts loop.
        routed = _narrow_region(scope.region, dst=tuple(_merge(routable))) if routable else FlowRegion()
        parts = [
            (list(reg.rects[0].dst), list(effect.data.get("routes", [])))
            for reg, effect in RoutingTransition(
                routes, rib_lookup, outranked, observed=observed, mirrored=mirrored
            ).apply(routed)
        ]
    else:
        parts = _route_partition(
            routes, routable, rib_lookup, outranked, observed=observed, mirrored=mirrored
        )
    for note in outranked:
        trail.notes.append(f"{scope.src_label}: {note}")
    if len(parts) > 1:
        trail.notes.append(
            f"{scope.src_label}: the destination set straddles {len(parts)} routes; "
            f"each part is evaluated separately"
        )
    return parts


def _router_local_legs(
    ctx: WalkContext,
    scope: _GroupScope,
    local_dst: list[tuple[int, int, int]],
    own_ifs: Any,
    has_routable: bool,
    lane: int,
) -> tuple[list[dict[str, Any]], int]:
    """The legs of the destination part that is an address of this device.

    The LOAD_BALANCER stage takes an own address that is also a
    VirtualService VIP. The leg records the router-local termination and its
    input-chain verdict, then the pool that the flow is dispatched into.
    """
    session, trail = ctx.session, ctx.trail
    grp, gw = scope.grp, scope.gw
    legs: list[dict[str, Any]] = []
    vip_parts = [
        (ip, rows, part)
        for ip, rows in _local_vips(session, gw, own_ifs)
        if (part := _intersect(local_dst, _intervals([ip])))
    ]
    plain_dst = local_dst
    for _ip, _rows, part in vip_parts:
        plain_dst = _subtract(plain_dst, part)
    # More than one leg answers for the destination, and each leg names its half.
    split = has_routable or len(vip_parts) + bool(plain_dst) > 1
    for ip, rows, part in vip_parts:
        scope.start_lane(trail, lane)
        vip_leg = _router_local_leg(
            session,
            trail,
            grp,
            gw,
            part,
            _owners_of(own_ifs, part),
            lane,
            scope.local_port,
            scope.local_proto,
            scope.src_label,
            _describe(part) if split else None,
            conn_state=ctx.conn_state,
        )
        if scope.local_ranged:
            vip_leg["service"] = _region_service(None, ctx.port, ctx.proto, scope.sport)
        if vip_leg["blocked"]:
            # The input chain denied the packet, and nothing crosses to the
            # virtual service. The virtual service is named and is not
            # evaluated, as `_blocked_destination` names one denied upstream.
            for row in rows:
                trail.hop(
                    row["uid"],
                    "VirtualService",
                    row.get("name") or ip,
                    "past the block, not evaluated",
                    stage=Stage.LOAD_BALANCER,
                )
            legs.append(vip_leg)
            lane += 1
            continue
        vip_legs, lane = _lb_stage(
            session,
            trail,
            vip_leg,
            gw,
            rows,
            ip,
            grp["sources"],
            scope.local_port,
            scope.local_proto,
            lane,
            ctx.depth,
            ctx.visited,
            ctx.rib,
            max_hops=ctx.max_hops,
            conn_state=ctx.conn_state,
            region=None if scope.region is None else _narrow_region(scope.region, dst=tuple(_merge(part))),
        )
        legs.extend(vip_legs)
    if plain_dst:
        scope.start_lane(trail, lane)
        plain_leg = _router_local_leg(
            session,
            trail,
            grp,
            gw,
            plain_dst,
            _owners_of(own_ifs, plain_dst),
            lane,
            scope.local_port,
            scope.local_proto,
            scope.src_label,
            _describe(plain_dst) if split else None,
            conn_state=ctx.conn_state,
        )
        if scope.local_ranged:
            plain_leg["service"] = _region_service(None, ctx.port, ctx.proto, scope.sport)
        # An own address that is a VIP bound to another device is terminated
        # here as a plain local endpoint only if that device does not answer
        # for it.
        for own_ip in sorted({str(r["ip"]) for r in _owners_of(own_ifs, plain_dst)}):
            _mark_vip_elsewhere(
                session,
                trail,
                plain_leg,
                own_ip,
                scope.local_proto,
                scope.local_port,
                scope.region,
            )
        # A carrier that arrived at its far address is not a leg of the
        # answer. The continuation of the inner flow takes over this lane, and
        # the arrival is recorded on the carrier.
        lane_after = _decap_stage(
            session,
            trail,
            plain_leg,
            gw,
            plain_dst,
            lane,
            ctx.depth,
            ctx.visited,
            ctx.rib,
            max_hops=ctx.max_hops,
        )
        if plain_leg.get("decapsulated"):
            lane = lane_after
        else:
            legs.append(plain_leg)
            lane += 1
    return legs, lane


def _sdwan_candidates(
    ctx: WalkContext,
    scope: _GroupScope,
    dst_part: list[tuple[int, int, int]],
    best: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """The routes of a part, and the verdict of the SD-WAN boundary when it decides.

    A device with a forwarding boundary is an SD-WAN edge. When the device
    has no route table, the candidates of the boundary stand in for the
    route lookup, with one lane per candidate, and the leg marks the set as
    a candidate set. When the device has its own rows, the overlay competes
    by prefix length. A LAN prefix of another edge (rule 1) or an Overlay
    Flow Control exit (rule 2) wins when it is longer than the own rows.
    """
    trail, grp, gw = ctx.trail, scope.grp, scope.gw
    candidates = sdwan_gate.candidate_routes(
        ctx.session,
        gw,
        grp["table_uid"],
        dst_part,
        ctx.rib,
        src_part=grp["sources"],
        port=ctx.port,
        proto=ctx.proto,
        src_port=grp.get("src_port"),
    )
    own_cidr = best[0].get("cidr") if best else None
    if candidates is not None and own_cidr:
        overlay = candidates[1].get("prefix")
        if not (candidates[0] and overlay and _prefix_len(overlay) > _prefix_len(own_cidr)):
            candidates = None
    if candidates is None:
        return best, None
    routes_from_boundary, sdwan_info = candidates
    trail.hop(
        sdwan_info["boundary_uid"],
        "ForwardingBoundary",
        f"SD-WAN {sdwan_info.get('segment_name') or 'segment'}",
        f"{sdwan_info['why']} · {sdwan_info['candidates']} candidate(s)",
        stage=Stage.ROUTE,
    )
    # The boundary hop holds the reason. The trail note keeps only the caveat.
    lead = (
        f"the overlay prefix {sdwan_info['prefix']} is longer than its own route {own_cidr}"
        if own_cidr
        else "has no route table"
    )
    trail.notes.append(
        f"{scope.src_label}: {gw['dev_name'] or gw['dev_uid']} {lead}. "
        "Dynamic path selection is not in the snapshot; the drawn candidates are not a decision"
    )
    if sdwan_info.get("not_drawn"):
        trail.warn(
            f"{scope.src_label}: the SD-WAN boundary of {gw['dev_name'] or gw['dev_uid']} selects "
            f"{sdwan_info['candidates'] + sdwan_info['not_drawn']} candidates; the "
            f"{sdwan_info['candidates']} with the lowest uids are drawn and "
            f"{sdwan_info['not_drawn']} are not"
        )
    return routes_from_boundary, sdwan_info


def _routed_part_legs(
    ctx: WalkContext,
    scope: _GroupScope,
    dst_part: list[tuple[int, int, int]],
    best: list[dict[str, Any]],
    dst_label: str | None,
    lane: int,
) -> tuple[list[dict[str, Any]], int]:
    """The legs of one routed destination part. They are a "no route found"
    leg, or one lane per best route (ECMP), each walked by `_walk_route`."""
    trail, grp, gw = ctx.trail, scope.grp, scope.gw
    scope.start_lane(trail, lane)
    part_lane = lane
    part_pre_start = len(trail.hops)
    best, sdwan_info = _sdwan_candidates(ctx, scope, dst_part, best)
    if not best:
        # `conn_state` reaches `_no_route_leg` as it reaches `_router_local_leg`.
        leg = _no_route_leg(
            ctx.session,
            trail,
            grp,
            gw,
            dst_part,
            lane,
            scope.src_label,
            scope.local_port,
            scope.local_proto,
            conn_state=ctx.conn_state,
        )
        if scope.local_ranged:
            leg["service"] = _region_service(None, ctx.port, ctx.proto, scope.sport)
        if dst_label:
            leg["dst_label"] = dst_label
        return [leg], lane + 1
    if sdwan_info is None:
        _record_route_match(trail, best, scope.src_label, gw["dev_uid"], grp["table_uid"])
    # The pre-fork hops of the part, up to the fork point.
    part_pre = [dict(h) for h in trail.hops[part_pre_start:]]
    legs: list[dict[str, Any]] = []
    ordered = sorted(best, key=lambda r: r["egress_name"] or r["next_hop"] or "")
    # Every equal-cost route is a lane walked to the end, and a lane can fork again below.
    # The trace spends one budget over all of them (`path_lane_cap`). The routes that do
    # not fit are named, and every leg of the part is reported indeterminate.
    room = max(Settings().path_lane_cap - trail.lanes_spent, 1)
    unwalked = ordered[room:]
    ordered = ordered[:room]
    trail.lanes_spent += len(ordered) - 1
    for route in ordered:
        trail.at(lane)
        if lane != part_lane:
            _replay_upstream(trail, scope.upstream)
            _replay_hops(trail, scope.group_pre)
            _replay_hops(trail, part_pre)
        nh_start = len(trail.hops)
        if len(best) > 1 and route.get("next_hop"):
            # One station per ECMP branch keeps equal-cost lanes apart
            # downstream. The gate hops that follow are the same node in every
            # lane. The uid is synthetic.
            trail.hop(
                f"{route['uid'] or best[0]['cidr']}#nh:{route['next_hop']}",
                "NextHop",
                route["next_hop"],
                f"next hop via {route['egress_name']}" if route.get("egress_name") else "next hop",
                stage=Stage.NEXT_HOP,
            )
        # The hops of this lane from the fork point, in the same slices that an
        # equal-cost lane above replays. A region fork inside the route below
        # starts its siblings from here.
        lane_pre = [dict(h) for h in (*scope.group_pre, *part_pre, *trail.hops[nh_start:])]
        route_legs, lane = _walk_route(
            ctx, grp, gw, route, dst_part, dst_label, lane, scope.nat_rows, scope.src_label, lane_pre
        )
        legs.extend(route_legs)
    if unwalked:
        named = ", ".join(sorted({str(r["next_hop"] or r["egress_name"] or r["uid"]) for r in unwalked}))
        reason = (
            f"{len(unwalked)} equal-cost next hops not walked ({named}): "
            f"the trace reached the path_lane_cap setting ({Settings().path_lane_cap} lanes)"
        )
        trail.warn(f"{scope.src_label}: {reason}")
        for ll in legs:
            ll["indeterminate"] = True
            ll.setdefault("indeterminate_reason", reason)
    if sdwan_info is not None:
        # The boundary and its policy were evaluated here, and the candidate
        # set is their verdict. The gate safeguard does not report them. The
        # leg marks the kind of answer.
        credited = [sdwan_info["boundary_uid"], *(sdwan_info.get("policy_uids") or [])]
        for ll in legs:
            ll["sdwan_uids"] = sorted(set(ll.get("sdwan_uids") or []) | set(credited))
            ll["candidate_set"] = True
            if sdwan_info.get("rules"):
                ll["sdwan_rules"] = sdwan_info["rules"]
            if not sdwan_info.get("complete", False):
                ll["indeterminate"] = True
    return legs, lane


def _mark_rib_gap(
    trail: _Trail,
    scope: _GroupScope,
    legs: list[dict[str, Any]],
    rib_gap: tuple[str, bool],
    other_routes: bool,
) -> None:
    """Mark the legs that a missing RIB leaves uncertain.

    Every routed leg is marked when the pinned run recorded the RIB table of
    the device. When nothing records a RIB for the device (`recorded` of
    `_rib_gap` is False), a part that found no route or fell to a default
    route is marked only with `other_routes`. `other_routes` is a dynamic
    routing process in the VRF of the table, or a side store that could not
    be read.

    A leg that continued to a next-hop device has the `gid` of that device.
    With a recorded gap, such a leg is marked too, because this device routed
    it there on graph edges only. Its `router_local` and `cidr` describe the
    far device and do not exempt it. The unrecorded case marks only the legs
    of this device, because its test reads the route of this device (`cidr`).
    """
    grp, gw = scope.grp, scope.gw
    why, recorded = rib_gap
    reason = (
        f"RIB of {gw['dev_name'] or gw['dev_uid']} table {grp['table_name']} not consulted ({why}); "
        "routed on graph edges only"
    )
    far_marked = warned = False
    for ll in legs:
        own = ll.get("gid") == grp.get("gid")
        if not own:
            if recorded:
                ll["indeterminate"] = True
                ll.setdefault("indeterminate_reason", reason)
                far_marked = True
            continue  # without a recorded gap, the group of the far device reports
        if ll.get("router_local"):
            continue  # never routed
        if recorded or (other_routes and (ll["cidr"] is None or ll["cidr"] in ("0.0.0.0/0", "::/0"))):
            ll["indeterminate"] = True
            ll.setdefault("indeterminate_reason", reason)
            trail.warn(f"{scope.src_label}: {reason}")
            warned = True
    if far_marked and not warned:
        trail.warn(f"{scope.src_label}: {reason}")


def _rib_gap(rib: Any | None, dev_uid: str) -> tuple[str, bool] | None:
    """The reason the side store could not answer for this device, or None.

    Returns `(why, recorded)`. `recorded` is True when the pinned run
    recorded an outcome for the RIB table of this device (failed, partial,
    empty, or a file that is lost). A RIB was then expected of the device,
    and every route that it is traced on is unconfirmed. `recorded` is False
    when nothing states that the device has a RIB (no rows and no recorded
    outcome, or no store to ask).

    The function reads the RibSource attributes by duck typing.

    `coverage` is read before `has_rows`. Both report that the store holds no
    rows, and only the recorded outcome of the pinned run separates the cases.
    """
    if rib is None:
        return None
    if getattr(rib, "available", True) is False:
        return "side store unavailable", False
    coverage = getattr(rib, "coverage", None)
    outcome = coverage(dev_uid) if callable(coverage) else None
    if outcome in ("failed", "partial"):
        return f"the pinned run recorded this device's RIB table as {outcome}", True
    if outcome == "complete-empty":
        return "the pinned run recorded this device's RIB table as empty", True
    if outcome == "missing":
        return "the RIB file the pinned run recorded is not on disk", True
    if outcome == "unknown":
        # The run that wrote the table is beyond the bounded manifest walk
        # (EVIDENCE_WALK_MAX in core/ribsource.py). The table is unconfirmed with or without rows.
        return (
            "the pinned run's outcome for this device's RIB table is recorded beyond the manifests read",
            True,
        )
    has_rows = getattr(rib, "has_rows", None)
    if callable(has_rows) and not has_rows(dev_uid):
        return "no RIB rows for this device in the pinned run", False
    return None


# The note is added once per trace when the store selects files by age without
# a published manifest (`RibSource.approximate` in core/ribsource.py). The
# routes that it answered can come from a run that did not publish.
_APPROXIMATE_RIB_NOTE = (
    "RIB evidence is approximate: the pinned run has no snapshot manifest, so each device "
    "answers from its newest side-store file at or before the pin rather than from a published file list"
)


def _combined_verdict(legs: list[dict[str, Any]], flow: str, multi: bool) -> str:
    """One line covering every leg."""
    if len(legs) == 1:
        verdict = f"{flow}: {legs[0]['verdict']}"
        if legs[0]["cidr"]:
            table = legs[0]["table"]
            verdict += (
                f" ({legs[0]['cidr']}, "
                + ("main table" if table in ("main", "default") else f"table {table}")
                + ")"
            )
        if legs[0].get("indeterminate"):
            # The cause recorded on the leg. A policy gate that could not decide
            # records no cause, and the default text names that case.
            why = legs[0].get("indeterminate_reason") or "policy on this path was not evaluated"
            verdict += f"; INDETERMINATE, {why}"
        return verdict
    blocked = [ll for ll in legs if ll["blocked"]]
    parts = []
    for ll in legs:
        if ll.get("router_local"):
            # A router-local leg has no egress and no next hop.
            where = f"terminates on {ll.get('terminus') or 'this device'}"
        elif str(ll.get("verdict") or "").startswith("switched in "):
            # The hosts of a same-subnet set whose gateway address was split off.
            where = ll["verdict"]
        else:
            where = ll["egress"] or ll["next_hop"] or "no route"
        label = f"{ll['src_label']} → {where}" if multi else str(where)
        if ll.get("dst_label"):
            label += f" for {ll['dst_label']}"
        if ll["blocked"]:
            parts.append(label + " BLOCKED")
        elif ll.get("indeterminate"):
            parts.append(label + " INDETERMINATE")
        else:
            parts.append(label)
    # Legs that match different routes are distinct paths, also inside one group.
    ecmp = not multi and len({ll["cidr"] for ll in legs}) == 1
    head = f"ECMP over {legs[0]['cidr']} · {len(legs)} paths" if ecmp else f"{len(legs)} paths"
    verdict = f"{flow}: {head}: " + "; ".join(parts)
    if blocked:
        verdict += f" · {len(blocked)} of {len(legs)} blocked"
    undecided = [ll for ll in legs if ll.get("indeterminate")]
    if undecided:
        verdict += f" · {len(undecided)} INDETERMINATE"
    return verdict


def _flow_gates(
    session: Any,
    trail: _Trail,
    legs: list[dict[str, Any]],
    verdict: str,
    src_ip: str,
    dst_ip: str,
    port: int | None,
    proto: str | None,
    split: list[list[dict[str, Any]]] | None = None,
) -> str:
    """Policy models that are not per leg, and the catch-all.

    ACI is evaluated on the endpoints of the flow.

    `split` holds the halves of a destination set split into switched hosts
    and the address of the gateway (`_trace_domain`). The catch-all runs per
    half, on the credits and the lanes of that half. The evaluation of the
    router-local half does not clear a gate that the switched half left
    unevaluated.
    """
    # The routing contexts that the legs leave scope an address that ACI reuses across VRFs.
    contexts = sorted({ll["context_uid"] for ll in legs if ll.get("context_uid")})
    aci = aci_contract_verdict(session, src_ip, dst_ip, port, proto, contexts)
    evaluated = _leg_gate_credits(legs)
    if aci:
        trail.notes.append(f"ACI {aci['epgs']}: {aci['action']}, {aci['reason']}")
        trail.notes.extend(aci.get("notes") or [])
        evaluated.update(aci.get("contract_uids") or [])
        if aci.get("contract_uid"):
            evaluated.add(aci["contract_uid"])
        if aci["action"] == DENY:
            # fw_uid stays the rulebase uid, and blocking_uid names the contract.
            # With contract_uid unresolved, the hop is not drawn and blocking_uid
            # stays None. The hop is drawn on the shared spine.
            saved_lane, saved_shared = trail.lane, trail.shared
            trail.lane, trail.shared = 0, True
            try:
                trail.hop(
                    aci["contract_uid"],
                    "Contract",
                    aci.get("contract") or "ACI contract",
                    f"deny: {aci['reason']}",
                    stage=Stage.FILTER_RB,
                )
            finally:
                trail.lane, trail.shared = saved_lane, saved_shared
            for ll in legs:
                ll["blocked"] = True
                ll["blocking_uid"] = aci["contract_uid"]
            verdict += f" · BLOCKED by ACI ({aci['reason']})"
        elif aci["action"] == INDETERMINATE:
            for ll in legs:
                ll["indeterminate"] = True
            verdict += f" · INDETERMINATE by ACI ({aci['reason']})"

    if split:
        flow_credits = evaluated - _leg_gate_credits(legs)
        suffixes: list[str] = []
        for half in split:
            seen_warnings, seen_notes = set(trail.warnings), set(trail.notes)
            w_start, n_start = len(trail.warnings), len(trail.notes)
            suffixes.append(
                _gate_coverage(
                    session,
                    trail,
                    half,
                    _leg_gate_credits(half) | flow_credits,
                    lanes={int(ll.get("lane") or 0) for ll in half},
                )
            )
            # A gate that both halves miss on a shared device is reported once.
            trail.warnings[w_start:] = [w for w in trail.warnings[w_start:] if w not in seen_warnings]
            trail.notes[n_start:] = [n for n in trail.notes[n_start:] if n not in seen_notes]
        return verdict + "".join(dict.fromkeys(suffixes))
    return verdict + _gate_coverage(session, trail, legs, evaluated)


def _leg_gate_credits(legs: list[dict[str, Any]]) -> set[str]:
    """The gate uids the walk evaluated for these legs."""
    evaluated = {ll["fw_uid"] for ll in legs if ll.get("fw_uid")}
    for ll in legs:
        # The rulebases evaluated on upstream devices of a multi-hop path, and
        # the NAT rulebases that the two NAT stages of the trace considered. A
        # NAT rule that the engine could not decide has marked its leg
        # INDETERMINATE. None of these gates belongs in the catch-all below.
        evaluated.update(ll.get("fw_uids") or [])
        evaluated.update(ll.get("nat_uids") or [])
        # A VirtualService that the LOAD_BALANCER stage evaluated.
        evaluated.update(ll.get("lb_uids") or [])
        # Every PBR policy that the PBR stage read for a group of this leg
        # (`_credit_device_gates`).
        evaluated.update(ll.get("pbr_uids") or [])
        # The SD-WAN boundary of the candidate set of this leg, and the
        # business policy read for the preference (`_routed_part_legs`).
        evaluated.update(ll.get("sdwan_uids") or [])
    return evaluated


def _gate_coverage(
    session: Any,
    trail: _Trail,
    legs: list[dict[str, Any]],
    evaluated: set[str],
    first_devices: dict[str, str] | None = None,
    *,
    lanes: set[int] | None = None,
) -> str:
    """Mark `legs` indeterminate for a gate on the devices of the trail that
    the walk did not evaluate, and for a device whose policy the pinned run
    did not collect completely. Returns the text that the verdict line gains.
    The forward walk (`_flow_gates`) and the reply walk (`_walk_reply_leg`)
    both run it. `first_devices` (uid to label) names devices that the walk
    crossed without a Device hop. The first device of the reply draws only
    its stations. `lanes`, when given, limits the devices to those drawn on
    the shared spine and on those lanes (one half of a split destination set).
    """
    suffix = ""
    labels = dict(first_devices or {})
    labels.update(
        {
            h["uid"]: h["label"]
            for h in trail.hops
            if h.get("kind") == "Device" and (lanes is None or h.get("shared") or h.get("lane") in lanes)
        }
    )
    # Legs switched between two hosts on one port of a device (`_switched_legs_with_crossings`)
    # do not enter the device. It is drawn as their attachment, and its gates are not on their path.
    same_port = {ll.get("_same_port") for ll in legs}
    if len(same_port) == 1 and None not in same_port:
        labels.pop(str(next(iter(same_port))), None)
    # Every :Gate of the schema on this path that produced no verdict, including
    # a gate model that this engine does not evaluate.
    device_uids = list(labels)
    missed = _vip_misses_removed(session, trail, unevaluated_gates(session, device_uids, evaluated))
    if missed:
        for g in missed:
            trail.warn(f"{g['kind'] or 'Gate'} {g['name'] or g['uid']}: on path, not evaluated")
        for ll in legs:
            ll["indeterminate"] = True
        suffix += f" · {len(missed)} gate(s) not evaluated"

    # A device whose policy sections the pinned run failed to read has no gate,
    # or the copy of a gate from an earlier run, and the walk above judged the
    # device on that. A missing gate there is no evidence that the device does
    # not filter.
    unread = 0
    for uid, label in labels.items():
        gaps, carried = policy_evidence(session, uid)
        if not gaps:
            if carried:
                trail.notes.append(f"policy of {label or uid}: {carried}")
            continue
        unread += 1
        reason = f"policy of {label or uid} not collected completely in the pinned run ({', '.join(gaps)})"
        if carried:
            reason += f"; {carried}"
        trail.warn(reason)
        for ll in legs:
            ll["indeterminate"] = True
            ll.setdefault("indeterminate_reason", reason)
    if unread:
        suffix += f" · policy of {unread} device(s) not collected completely"
    return suffix


def _vip_misses_removed(session: Any, trail: _Trail, missed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """`missed` without the VirtualServices that the flow cannot reach.

    A VirtualService acts only on a packet addressed to its VIP. A
    VirtualService whose every VIP lies outside each destination that a
    device on the path handled counts as evaluated. A VirtualService with no
    recorded VIP, or with a VIP inside a handled destination, stays reported.
    """
    vs_uids = [g["uid"] for g in missed if g.get("kind") == "VirtualService"]
    if not vs_uids:
        return missed
    handled = trail.dst_seen + (trail.orig_dst or [])
    vips = _vip_addresses(session, vs_uids)
    unreachable = {uid for uid, addrs in vips.items() if not _intersect(_intervals(addrs), handled)}
    return [g for g in missed if g["uid"] not in unreachable]


def _forwarding_visit(gateway: dict[str, Any]) -> str:
    from .gates import forwarding_visit

    return forwarding_visit(gateway)


def _routing_visit(session: Any, trail: _Trail, gateway: dict[str, Any]) -> str:
    """The visit of the gateway, keyed on the table of its interface
    (`gates.routing_visit`). Loop detection compares these visits."""
    from .gates import routing_visit

    return routing_visit(gateway, interface_table(session, trail, gateway["if_uid"]))


def _device_stage(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    lane: int,
    rib: Any | None,
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
    *,
    max_hops: int,
    conn_state: str = "new",
    src_port: Any = None,
) -> tuple[list[dict[str, Any]], int]:
    """The whole forwarding decision of one device: dNAT, PBR, routing,
    filter, sNAT, with recursion across resolvable next hops through
    `_group_legs`.

    `src_port` is the source port of the flow when the caller states one (a
    scalar, a range spec or a list, read like `port`). A stated source port
    walks the query as a region whatever the other dimensions state, because
    only the region path has that dimension.

    On the region path, every stage of this device reads and writes one
    `FlowRegion` (`state.py`), in the `Stage` order of the pipeline. The
    destination NAT stage runs through `NatTransition`, the route lookup
    through `RoutingTransition` (`_group_legs`), the filter through
    `FirewallTransition`, the source NAT stage through `NatTransition` again
    (`_route_leg`), and a load balancer VIP through the region-aware claim
    (`_lb_stage`). Each group holds its region in `grp["region"]` and the
    stated source port in `grp["src_port"]`. PBR reads the service rectangle
    of the part through the `service` keyword of `_pbr_partition`, as
    `gates.pbr.PbrTransition` reads it. A service-scoped rule then claims the
    part of the range that it covers and leaves the remainder to the main
    table. Each group holds the slice that it answers for.

    `conn_state` goes to every firewall gate call of the pipeline of this
    device ('new' for the forward walk, any other value for a reply walk),
    and to every recursive `_device_stage` call.

    Destination NAT happens before routing. Each dNAT part continues the
    trace with its translated destination and port.

    A range is parsed once here (`_as_protoset` and `_as_portset`) and given
    to `_nat_partition`. A dNAT rule that claims a part of the range then
    produces one group per rectangle.

    The walk is `_walk_device` over a `WalkContext`.
    """
    ctx = WalkContext(
        session=session,
        trail=trail,
        port=port,
        proto=proto,
        rib=rib,
        max_hops=max_hops,
        depth=depth,
        # The device visit stays for the transport walk, which reads only the
        # global table. Loops are detected on the table visit.
        visited=visited | {_forwarding_visit(gw), _routing_visit(session, trail, gw)},
        conn_state=conn_state,
    )
    return _walk_device(ctx, gw, src_set, dst_set, lane, src_port)


def _walk_device(
    ctx: WalkContext,
    gw: dict[str, Any],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    lane: int,
    src_port: Any,
) -> tuple[list[dict[str, Any]], int]:
    """`_device_stage` over a walk context whose visited set holds this device."""
    _enter_device(ctx.trail, gw, ctx.depth)
    dst_set, reply_undone = _undo_reply_nat(ctx, gw, dst_set)
    nat_rows = _nat_rows(
        ctx.session, gw["dev_uid"], in_if=gw.get("if_uid"), af=dst_set[0][0] if dst_set else None
    )
    if ctx.trail.reply_nat_chain is not None and _forwarding_visit(gw) in ctx.trail.device_gate_state:
        # A returning connection reuses its recorded translation. The NAT rule
        # selection for new connections does not apply.
        nat_rows = []
    groups, pbr_read = _device_groups(ctx, gw, src_set, dst_set, nat_rows, reply_undone, src_port)
    # The destinations that this device handles, before and after its dNAT. A
    # VirtualService whose VIP is in none of them cannot claim the flow.
    ctx.trail.dst_seen.extend(dst_set)
    for grp in groups:
        ctx.trail.dst_seen.extend(grp["dst"])

    legs: list[dict[str, Any]] = []
    # The hops of the incoming lane from the ingress of this device and from
    # the devices before it. Every later group starts on a new lane with these hops.
    incoming = lane
    upstream = [h for h in ctx.trail.hops if h["lane"] == incoming and not h["shared"]]
    for grp in groups:
        if lane != incoming and upstream:
            ctx.trail.at(lane)
            _replay_upstream(ctx.trail, upstream)
        grp_legs, lane = _walk_group(ctx.but(port=grp["port"], proto=grp["proto"]), grp, gw, lane, nat_rows)
        legs.extend(grp_legs)
    _credit_device_gates(legs, nat_rows, pbr_read)
    return legs, lane


def _enter_device(trail: _Trail, gw: dict[str, Any], depth: int) -> None:
    """Record the visit of this device, and the hop of its virtual context."""
    # The visit is recorded once per device visit, in call order, for the asymmetric-routing check.
    trail.device_sequence.append(_forwarding_visit(gw))
    # Every hop of this device is positioned against the pipeline of this device.
    trail.depth = depth
    if not gw.get("firewall_instance_uid"):
        return
    for hop in trail.hops:
        if hop["uid"] == gw["dev_uid"] and hop.get("_pos", (-1,))[0] == depth and hop["lane"] == trail.lane:
            hop["forwarding_visit"] = _forwarding_visit(gw)
    trail.hop(
        gw["firewall_instance_uid"],
        "FirewallInstance" if gw.get("vsx_kind") in {"virtual-system", "bridge"} else "Device",
        f"VS {gw.get('vsid', '?')}",
        str(gw.get("vsx_kind") or "virtual device"),
        stage=Stage.DEVICE,
    )
    for hop in trail.hops:
        if hop["uid"] == gw["firewall_instance_uid"] and hop.get("_pos", (-1,))[0] == depth:
            hop["virtual_context"] = True


def _undo_reply_nat(
    ctx: WalkContext, gw: dict[str, Any], dst_set: list[tuple[int, int, int]]
) -> tuple[list[tuple[int, int, int]], list[int]]:
    """On a reply walk, the destination set with the recorded source
    translations of this context undone, and the indexes of the undone steps."""
    trail = ctx.trail
    if trail.reply_nat_chain is None:
        return dst_set, []
    reply_context = _default_table_uid(ctx.session, gw["if_uid"])
    dst_set, reply_undone = reply_nat.undo(
        trail.reply_nat_chain,
        device=gw["dev_uid"],
        context=reply_context,
        stage="ingress",
        addresses=dst_set,
    )
    for index in reply_undone:
        step = trail.reply_nat_chain[index]
        trail.hop(
            step["rule_uid"],
            "NatRule",
            "reply destination NAT",
            "undoes source translation in this context",
            stage=Stage.DNAT,
        )
    return dst_set, reply_undone


def _device_groups(
    ctx: WalkContext,
    gw: dict[str, Any],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    nat_rows: list[dict[str, Any]],
    reply_undone: list[int],
    src_port: Any,
) -> tuple[list[dict[str, Any]], list[str]]:
    """The source groups of the device after destination NAT and PBR, and
    every PbrPolicy that the PBR stage read or ruled out."""
    session = ctx.session
    dnat_rules = _nat_stage_rules(
        nat_rows,
        "dnat",
        gw.get("if_name"),
        ingress_role=_iface_nat_role(session, gw.get("if_uid")) if nat_rows else None,
    )
    if ctx.conn_state != "new" and _forwarding_visit(gw) in ctx.trail.device_gate_state:
        # The state of the connection translates a reply of a connection that
        # the forward walk recorded on this device. That state is the reverse
        # of its forward translations, undone in the tuple of the reply. The
        # destination NAT rules for new connections do not apply. The rows stay
        # read and credited. When the forward crossing is not recorded, the
        # rules apply.
        dnat_rules = []
    u_port, u_proto = _unwrap_single(ctx.port), _unwrap_single(ctx.proto)
    ranged = _states_a_region(u_port, u_proto, src_port)
    dnat_parts: list[tuple[dict[str, Any], FlowRegion | None]]
    if ranged:
        # The query is one symbolic state, with every dimension parsed as the
        # gates parse it. The destination NAT stage is a transition over that
        # state, with one part per rectangle that a rule claimed. Each part
        # takes the rewritten region onward and keeps the request as its origin.
        region = _query_region(src_set, dst_set, u_port, u_proto, src_port)
        dnat_parts = [(dict(effect.data), out) for out, effect in NatTransition(dnat_rules).apply(region)]
    else:
        dnat_parts = [(p, None) for p in _nat_partition(dnat_rules, src_set, dst_set, u_port, u_proto)]

    groups: list[dict[str, Any]] = []
    # Every PbrPolicy that the PBR stage read on this ingress interface,
    # matched or not, collected across the dNAT parts. The PBR stage runs once
    # per part. The rule rows are read for the first part and kept for the others.
    pbr_read: list[str] = []
    pbr_rows: dict[str, Any] = {}
    query = _DnatQuery(
        ranged, u_port, u_proto, src_port, reply_undone, any(_checkpoint_manual(r) for r in nat_rows)
    )
    for part, part_region in dnat_parts:
        part_groups = _part_groups(ctx, gw, part, part_region, query, pbr_read, pbr_rows)
        for g in part_groups:
            # The group of a leg lets the verdict separate one flow split
            # across several groups (each needs a name) from one group that
            # fanned out over equal-cost routes (ECMP). Two groups can share a
            # source set and differ only by destination, and the identity is
            # therefore the group itself.
            g["gid"] = f"{ctx.depth}:{len(groups)}"
            groups.append(g)

    # Every PbrPolicy bound to another interface of this device is ruled out by
    # interface, once per device visit.
    arrival_if = None if gw.get("if_stands_in") else gw["if_uid"]
    pbr_read.extend(
        u for u in _other_interface_pbr_policies(session, gw["dev_uid"], arrival_if) if u not in pbr_read
    )
    return groups, pbr_read


class _DnatQuery(NamedTuple):
    """The values that every destination NAT part of one device visit reads in the same way."""

    ranged: bool
    u_port: Any
    u_proto: Any
    src_port: Any
    reply_undone: list[int]
    checkpoint_manual: bool


def _part_ports(ctx: WalkContext, part: dict[str, Any], query: _DnatQuery) -> tuple[Any, Any, Any]:
    """The (proto, port) rectangle of a part in the two forms that the rest of
    the walk needs: `pre_port`, `post_port` and the protocol of the part.

    `pre_port` is the port of the flow before the port rewrite of this rule,
    which a filter that reads the original packet matches on. `post_port` is
    the port that leaves the box. A range is spelled again as a spec for a
    narrowed rectangle (`_port_ivals_spec`).
    """
    if not query.ranged:
        return query.u_port, part["port"], ctx.proto
    pre_port = _region_port_spec(part.get("port_subset"), query.u_port)
    post_port = _region_port_spec(part.get("new_port_subset"), query.u_port)
    part_proto = part.get("proto_subset") if part.get("proto_subset") is not None else query.u_proto
    return pre_port, post_port, part_proto


def _group_service(
    g: dict[str, Any],
    pbr_service: tuple[frozenset[int] | None, Ivals | None, Ivals | None] | None,
    post_port: Any,
    part_proto: Any,
    src_port: Any,
) -> tuple[Any, Any, dict[str, Any], Any]:
    """The port, the protocol, the region service dimensions and the source
    port of a PBR group.

    The wire out of this device holds the region after the port rewrite of
    the rule. A decided service slice is spelled again as the specs that the
    rest of the walk reads (`_region_port_spec`), and a dimension that the
    query does not state stays `None`.
    """
    if pbr_service is None:
        return post_port, part_proto, {}, src_port
    return (
        _region_port_spec(g["port_subset"], post_port),
        g["proto_subset"] if g["proto_subset"] is not None else part_proto,
        {"proto": g["proto_subset"], "dport": g["port_subset"], "sport": g["sport_subset"]},
        _region_port_spec(g["sport_subset"], src_port),
    )


def _part_groups(
    ctx: WalkContext,
    gw: dict[str, Any],
    part: dict[str, Any],
    part_region: FlowRegion | None,
    query: _DnatQuery,
    pbr_read: list[str],
    pbr_rows: dict[str, Any],
) -> list[dict[str, Any]]:
    """The PBR groups of one destination NAT part. Each group holds what the
    rest of the walk reads: the translation of the part, the port and the
    protocol that the flow leaves with, and on the region path its region."""
    # A part rewrote the destination only when a rule claimed it, that rule
    # is not an exclude, and the set it produced differs.
    rewrote_dst = (
        part["rule"] is not None and not part["rule"].get("exclude") and part["new_dst"] != part["dst"]
    )
    if rewrote_dst:
        # The duplicate-note pin resolves against trail.orig_dst, the address
        # that the query named.
        ctx.trail.dst_translated = True
    pre_port, post_port, part_proto = _part_ports(ctx, part, query)
    # new_src differs from sources only for ingress source rewrites
    # (Cisco outside-source).
    #
    # On the region path, PBR reads the service rectangle of the part after
    # the destination NAT rewrite through the `service` keyword of
    # `_pbr_partition`. A point query gives the stage its scalar port and protocol.
    pbr_service: tuple[frozenset[int] | None, Ivals | None, Ivals | None] | None = None
    if part_region is not None and part_region.rects:
        pbr_rect = part_region.rects[0]
        pbr_service = (pbr_rect.proto, pbr_rect.dport, pbr_rect.sport)
    groups: list[dict[str, Any]] = []
    for g in _pbr_partition(
        ctx.session,
        ctx.trail,
        gw["if_uid"],
        part["new_src"],
        part["new_dst"],
        None if query.ranged else part["port"],
        None if query.ranged else query.u_proto,
        considered=pbr_read,
        service=pbr_service,
        memo=pbr_rows,
        arrives=not gw.get("if_stands_in"),
    ):
        if ctx.trail.reply_nat_chain is not None:
            g["reply_nat_undone"] = query.reply_undone
        g["nat"] = part if part["rule"] is not None else None
        g["checkpoint_manual_nat"] = query.checkpoint_manual
        # The pre-translation destination of this device, for a Check Point-style filter.
        g["orig_dst"] = part["dst"] if rewrote_dst else None
        # The translated destination of the part, and the port of the flow
        # before the rewrite. The original-destination view of the filter can
        # be recovered only while the group and the route part cover the whole
        # translated set. A policy written on the original destination was
        # written on the original port too.
        g["nat_dst"] = part["new_dst"] if rewrote_dst else None
        g["orig_port"] = pre_port if rewrote_dst else None
        g["port"], g["proto"], service_dims, group_sport = _group_service(
            g, pbr_service, post_port, part_proto, query.src_port
        )
        if part_region is not None:
            # The region of the group: the rewritten region of the part,
            # narrowed to the addresses that this group answers for and, when
            # PBR decided one, to its service slice. Every later stage of this
            # device and of the next device reads it from here.
            g["region"] = _narrow_region(
                part_region, src=tuple(_merge(g["sources"])), dst=tuple(_merge(g["dst"])), **service_dims
            )
            g["src_port"] = group_sport
        groups.append(g)
    return groups


def _credit_device_gates(
    legs: list[dict[str, Any]], nat_rows: list[dict[str, Any]], pbr_read: list[str]
) -> None:
    """Credit the NAT rulebases and the read PbrPolicies of the device on every leg.

    The two NAT stages considered every NAT rulebase on this device, and none
    of them belongs in the unevaluated-gate catch-all. Every PbrPolicy that
    the PBR stage read on this ingress interface is credited, also one whose
    rules miss. A policy on another interface of the same device is credited
    as excluded by interface.
    """
    nat_rb_uids = sorted({r["rb_uid"] for r in nat_rows})
    for ll in legs:
        ll["nat_uids"] = sorted(set(ll.get("nat_uids") or []) | set(nat_rb_uids))
        # The key is written only when there is a policy to name. A leg across
        # a device without PBR has no empty key.
        if pbr_read:
            ll["pbr_uids"] = sorted(set(ll.get("pbr_uids") or []) | set(pbr_read))


def _ambiguous_gateway_result(
    trail: _Trail, gw: dict[str, Any], src_set: list[tuple[int, int, int]]
) -> dict[str, Any]:
    """The whole-trace result for a gateway tie across isolated L3 domains."""
    # Gateway prefixes that contain the source exist in more than one isolated
    # L3 domain, and nothing in the question selects one. Prefix length does
    # not break that tie, and no path is traced.
    doms = gw["l3doms"]
    contexts = gw.get("contexts") or []
    named = "; ".join(c["label"] for c in contexts) if contexts else ", ".join(doms)
    trail.warn(
        f"source {_describe(src_set)} matches gateway prefixes in {len(doms)} isolated "
        f"L3 domains ({named}); no path traced; scope the question to one domain"
    )
    result = {
        "hops": trail.hops,
        "legs": [],
        "notes": trail.notes,
        "warnings": trail.warnings,
        "verdict": (
            f"ambiguous: source matches gateway prefixes in {len(doms)} isolated "
            f"L3 domains ({named}); scope the trace to one domain"
        ),
        "indeterminate": True,
        "ambiguous_domains": doms,
    }
    if contexts:
        result["ambiguous_contexts"] = contexts
    return result


def _unknown_gateway_result(
    trail: _Trail, gw: dict[str, Any], src_set: list[tuple[int, int, int]]
) -> dict[str, Any]:
    """The whole-trace result when no gateway is tied to the segment of the source."""
    # Every gateway prefix that contains the source is served on a bridge
    # domain that the segment of the source has no recorded link to (`_segment_tie`).
    trail.warn(f"source {_describe(src_set)}: {gw['reason']}; no path traced")
    return {
        "hops": trail.hops,
        "legs": [],
        "notes": trail.notes,
        "warnings": trail.warnings,
        "verdict": f"gateway not established: {gw['reason']}",
        "indeterminate": True,
    }


def _switched_leg(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    attach: str | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    dst_ip: str,
    domain: str | None,
    port: int | None = None,
    proto: str | None = None,
    rib: Any | None = None,
    *,
    max_hops: int = 32,
    region: FlowRegion | None = None,
) -> list[dict[str, Any]]:
    """The single leg for a flow switched inside one connected prefix.
    `region` is the `FlowRegion` of the query on the region path. The load
    balancer stage of a switched VIP hit gets it."""
    vs_rows = _vip_bindings(session, dst_ip, gw["dev_uid"])
    if vs_rows:
        leg = {
            "lane": 0,
            "sources": _to_cidrs(src_set),
            "cidr": None,
            "egress": None,
            "next_hop": None,
            "blocked": False,
            "indeterminate": False,
            "table": "-",
            "src_label": _describe(src_set),
            "verdict": f"switched in {gw['cidr']}",
            "delivered": False,
        }
        legs, _lane = _lb_stage(
            session,
            trail,
            leg,
            gw,
            vs_rows,
            dst_ip,
            src_set,
            port,
            proto,
            0,
            0,
            frozenset({gw["dev_uid"]}),
            rib,
            max_hops=max_hops,
            region=region,
        )
        return legs
    # The load balancer on this prefix answers for a VirtualService bound to
    # it. The trace enters that device on its interface on the prefix.
    lb_gw, lb_rows, lb_why = _offpath_lb(
        session,
        trail,
        dst_ip,
        gw.get("cidr"),
        _scalarize_for_legacy(proto),
        _scalarize_port_for_legacy(port),
        region,
        frozenset(),
    )
    if lb_gw is not None:
        leg = {
            "lane": 0,
            "sources": _to_cidrs(src_set),
            "cidr": None,
            "egress": None,
            "next_hop": None,
            "blocked": False,
            "indeterminate": False,
            "table": "-",
            "src_label": _describe(src_set),
            "verdict": f"switched in {gw['cidr']}",
            "delivered": False,
        }
        legs, _lane = _offpath_lb_stage(
            session,
            trail,
            leg,
            lb_gw,
            lb_rows,
            dst_ip,
            src_set,
            port,
            proto,
            0,
            0,
            frozenset(),
            rib,
            max_hops=max_hops,
            region=region,
        )
        return legs
    dst = _dst_attachment(session, dst_set, domain, gw.get("if_uid"))
    if dst is not None:
        trail.find_dst(dst["ip_uid"])
    delivered = _delivery_walk(session, trail, dst, dst_ip, attach, gw["dev_uid"], gw.get("if_uid"))
    if not dst:
        trail.warn(f"{dst_ip}: no attachment in the graph; path from addressing only")
    leg = {
        "lane": 0,
        "sources": _to_cidrs(src_set),
        "cidr": None,
        "egress": None,
        "next_hop": None,
        "blocked": False,
        "indeterminate": False,
        "table": "-",
        "src_label": _describe(src_set),
        "verdict": f"switched in {gw['cidr']}",
        "delivered": delivered,
    }
    if lb_why:
        leg["indeterminate"] = True
        leg.setdefault("indeterminate_reason", lb_why)
        trail.warn(lb_why)
    return [leg]


# The addressed interfaces on the connected prefix that holds an address, on a device whose role
# is neither a gateway role nor a firewall. An SVI on a switch is such an interface. No reasoner
# rule marks them GATEWAY_FOR the prefix, and a prefix with such interfaces has no gateway.
_UNROUTED_INTERFACES_QUERY = """
MATCH (p:Prefix:Obj {kind: 'connected'})
WHERE p.collection_ts = $snap AND NOT p:Retired AND p.lo_key <= $key AND p.hi_key >= $key
MATCH (d:Device:Obj)<-[o:ON]-(i:Interface:Obj)-[h:HAS_IP]->(ia:IpAddress:Obj)-[n:IN]->(p)
WHERE d.collection_ts = $snap AND i.collection_ts = $snap AND ia.collection_ts = $snap
  AND NOT d:Retired AND NOT i:Retired AND NOT ia:Retired
  AND NOT d.role IN $gateway_roles AND d.role <> 'firewall'
  AND o._retired_at IS NULL AND h._retired_at IS NULL AND n._retired_at IS NULL
  AND NOT EXISTS { MATCH (i)-[g:GATEWAY_FOR]->(p) WHERE g._retired_at IS NULL }
RETURN DISTINCT coalesce(d.hostname, d.uid) AS dev, coalesce(d.role, 'unknown') AS role, i.name AS iface
ORDER BY dev, iface
LIMIT 5"""


def _no_gateway_result(trail: _Trail, session: Any = None, probe: str | None = None) -> dict[str, Any]:
    """The whole-trace result when no gateway serves the source prefix."""
    verdict = (
        "no gateway found for the source prefix; no router, gateway or firewall interface is recorded on it"
    )
    key = ipenc.graph_key(probe)
    unrouted = (
        _path._read(session, _UNROUTED_INTERFACES_QUERY, key=key, gateway_roles=GATEWAY_ROLES) if key else []
    )
    if unrouted:
        held = ", ".join(f"{r['dev']} {r['iface']} (role {r['role']})" for r in unrouted)
        verdict = (
            "no gateway found for the source prefix; the interfaces recorded on it are on devices "
            f"whose role is not a gateway role: {held}"
        )
    return {
        "hops": trail.hops,
        "legs": [],
        "notes": trail.notes,
        "warnings": trail.warnings,
        "verdict": verdict,
    }


def _flow_label(endpoints: str, port: Any, proto: Any, src_port: Any = None) -> str:
    """The label of the flow in its combined verdict: the endpoints, then the
    service that the query states."""
    flow = endpoints
    if port:
        flow += f":{_spec_label(port)}" + (f"/{_spec_label(proto)}" if proto else "")
    if src_port is not None:
        flow += f" from port {_spec_label(src_port)}"
    return flow


def _mark_switched(
    legs: list[dict[str, Any]],
    src: dict[str, Any] | None,
    destination: dict[str, Any] | None,
    domain: str | None,
) -> None:
    """Mark the switched legs with internal keys that `_finish_trace` reads and drops.

    A switched leg ends in the context of the gateway
    (`_check_delivery_context`). When both ends attach to one port in one
    segment, the frame does not enter the device of that port, and the gates
    of that device are not on the leg (`_gate_coverage`). Two ports of one
    device, or two VLANs (segments) on one trunk port, cross the bridge of
    the device and keep its gates. An unrecorded segment keeps them too."""
    same_port = bool(
        src
        and src.get("att_is_port")
        and src.get("att_uid")
        and src.get("sw_uid")
        and src.get("seg_uid")
        and destination
        and destination.get("att_is_port")
        and destination.get("att_uid") == src.get("att_uid")
        and destination.get("seg_uid") == src.get("seg_uid")
    )
    for leg in legs:
        if str(leg.get("verdict") or "").startswith("switched in "):
            leg["_switched_in"] = domain or ""
            if same_port and src is not None:
                leg["_same_port"] = src["sw_uid"]


def _switched_legs_with_crossings(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    attach: str | None,
    src: dict[str, Any] | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    dst_ip: str,
    domain: str | None,
    port: Any,
    proto: Any,
    src_port: Any,
    rib: Any | None,
    max_hops: int,
    query_region: Callable[[], FlowRegion],
) -> list[dict[str, Any]]:
    """The legs of a flow switched inside one connected prefix, after every
    transparent gate between the ports of the source and the destination."""
    # The point slots are neutralised for the region-aware LOAD_BALANCER claim.
    switched_ranged = _states_a_region(port, proto, src_port)
    switched_port = None if switched_ranged else cast("int | None", port)
    switched_proto = None if switched_ranged else cast("str | None", proto)
    legs = _switched_leg(
        session,
        trail,
        gw,
        attach,
        src_set,
        dst_set,
        dst_ip,
        domain,
        switched_port,
        switched_proto,
        rib,
        max_hops=max_hops,
        region=query_region() if switched_ranged else None,
    )
    destination = _dst_attachment(session, dst_set, domain, gw.get("if_uid"))
    _mark_switched(legs, src, destination, domain)
    if not (src and src.get("att_is_port") and destination and destination.get("att_is_port")):
        return legs
    _, crossings, gap = vsx.resolve(session, src["att_uid"], None, target=destination["att_uid"])
    if gap:
        trail.warn(gap)
        for leg in legs:
            leg["indeterminate"] = True
    if not crossings:
        return legs
    switched = []
    for leg in legs:
        for part, decided in _transparent_parts(session, trail, crossings, leg, query_region()):
            for rect in decided:
                child = dict(
                    part,
                    service=_region_service(None, port_spec(rect.dport), rect.proto, port_spec(rect.sport)),
                )
                if child.get("blocked"):
                    child["delivered"] = False
                switched.append(child)
    return switched


def _walk_crossing_parts(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    parts: Iterable[tuple[dict[str, Any], Any]],
    rib: Any | None,
    *,
    max_hops: int,
    conn_state: str | None = None,
) -> list[dict[str, Any]]:
    """The legs of every part that the transparent gates left. Each decided
    rectangle is walked through the device pipeline of the gateway on its own
    lane.

    A blocked part appends a copy of the part per rectangle with its own
    lane and `delivered` False, and advances the lane. `conn_state` goes to
    `_device_stage` only when it is given.
    """
    legs: list[dict[str, Any]] = []
    lane = 0
    stage_kwargs: dict[str, Any] = {} if conn_state is None else {"conn_state": conn_state}
    for part, decided in parts:
        for rect in decided:
            trail.lane = lane
            if part.get("blocked"):
                legs.append(dict(part, lane=lane, delivered=False))
                lane += 1
                continue
            inner, lane = _device_stage(
                session,
                trail,
                gw,
                list(rect.src),
                list(rect.dst),
                port_spec(rect.dport),
                rect.proto,
                lane,
                rib,
                max_hops=max_hops,
                **stage_kwargs,
                src_port=port_spec(rect.sport),
            )
            for child in inner:
                _merge_upstream_leg(child, part)
            legs.extend(inner)
    return legs


def _decided_false(leg: dict[str, Any]) -> bool:
    """Whether the walk decided that this leg does not forward (blocked, or no route)."""
    return bool(leg.get("blocked")) or leg.get("verdict") == NO_ROUTE_DETAIL


def _finish_trace(
    session: Any,
    trail: _Trail,
    legs: list[dict[str, Any]],
    flow: str,
    gw: dict[str, Any],
    *,
    src_ip: str,
    dst_ip: str,
    port: Any,
    proto: Any,
    domain: str | None,
    dst_instances: list[dict[str, Any]],
    dst_context: str | None,
    split: list[list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """The whole-trace result after the walk has drawn its legs: the L2
    signals folded onto every leg, the combined verdict, the flow-level gates
    and the interpretation of each leg. `split` holds the two halves of a
    split same-subnet destination set (`_flow_gates`)."""
    # A VLAN or BridgeDomain mismatch on the L2 leg makes the leg indeterminate.
    # The hop cap or a missing path is a boundary (`L2_PATH_NOT_FOUND`).
    # A leg that the walk decided does not forward (blocked, or no route) stays
    # decided false where the mark does not touch the decision, and the L2
    # warning stays a warning. A missing cable path on either side does not
    # contradict the ingress interface, which is the gateway of the prefix of
    # the source. A mismatch after the forwarding decision (on the way to the
    # destination) comes after the decision. A mismatch on the source side
    # (`_source_walk`) contradicts the ingress interface, and with it the
    # ingress zone, the interface ACL and the table that judged the block or
    # the missing route. That leg stays undecided.
    src_mismatch = [bool(ll.pop("_l2_src_mismatch", False)) for ll in legs]
    if trail.l2_boundary:
        # No cable path was found inside the twin. The leg is not the edge of
        # the estate, the arrival of the frame is not established, and the leg is open.
        for ll in legs:
            ll["boundary"] = True
            if not _decided_false(ll):
                ll["indeterminate"] = True
                ll.setdefault("indeterminate_reason", L2_PATH_NOT_FOUND)
    if trail.l2_mismatch:
        for ll, source_side in zip(legs, src_mismatch, strict=True):
            if source_side or not _decided_false(ll):
                ll["indeterminate"] = True
    # `multi` is true when the flow was split across groups. The ECMP legs of
    # one group are one set of paths.
    multi = len({ll.get("gid") for ll in legs}) > 1
    for ll in legs:
        ll.pop("gid", None)  # internal grouping key, dropped from the response

    # A hop after the fork is kept in every lane. shared=True marks the
    # pre-branch source chain only.
    verdict = _combined_verdict(legs, flow, multi)
    for ll in legs:
        ll.pop("terminus", None)  # read by the verdict line above, dropped from the response
    # The contract gate of ACI evaluates one point per EPG pair. A range is
    # passed on as "not stated" here.
    flow_ranged = _states_a_range(_unwrap_single(port), _unwrap_single(proto))
    aci_port = None if flow_ranged else cast("int | None", port)
    aci_proto = None if flow_ranged else cast("str | None", proto)
    verdict = _flow_gates(session, trail, legs, verdict, src_ip, dst_ip, aci_port, aci_proto, split)
    trail.rank_hops()
    # Every lane states its interpretation, and every other known instance of
    # the destination is reported.
    interpretation = {"src_ip": src_ip, "anchor": domain, "display": gw.get("l3dom") or "?"}
    for ll in legs:
        ll["interpretation"] = dict(interpretation)
    trail.notes.extend(
        _dst_duplicate_notes(trail.dst_uid, trail.dst_found, dst_instances, dst_ip, dst_context)
    )
    switched_in = [ll.pop("_switched_in", None) for ll in legs]
    for ll in legs:
        ll.pop("_same_port", None)  # read by `_gate_coverage` above
    local = [
        bool(ll.pop("_local_net", False)) or sw is not None for ll, sw in zip(legs, switched_in, strict=True)
    ]
    if dst_context is not None and not _reached_in_context(trail, dst_instances, dst_context):
        for why in _check_delivery_context(trail, legs, local, dst_ip, dst_context, switched_in):
            # The prose of the walk was written before this check, and the check names the cause.
            verdict += f"; INDETERMINATE, {why}"
    indeterminate = any(ll.get("indeterminate") for ll in legs)
    exits = _walk_exits(legs)
    return {
        "hops": trail.hops,
        "legs": legs,
        "verdict": verdict + _exit_prose(exits),
        "notes": trail.notes,
        "warnings": trail.warnings,
        # A flag for the UI and the MCP tool. A trace that could not evaluate a
        # gate on the path is indeterminate.
        "indeterminate": indeterminate,
        # The path left the twin at a device. The part beyond it was not evaluated.
        "boundary": any(ll.get("boundary") for ll in legs),
        # The places where the path left the estate at its edge, and the end of
        # each candidate path.
        "left_estate": exits,
        "reach": _walk_reach(
            legs, [_leg_end(ll, here) for ll, here in zip(legs, local, strict=True)], indeterminate
        ),
    }


def _capture_reply_state(
    trail: _Trail, legs: list[dict[str, Any]], reply_capture: dict[str, Any] | None
) -> None:
    """Pop the internal per-leg keys that a reply walk reads, into
    `reply_capture` when the caller passed one."""
    leg_terminals = [ll.pop("_terminal", None) for ll in legs]
    # One gate_state dict per leg, popped as `_terminal` is. Two forward legs
    # that cross the same device can read different zone pairs.
    leg_gate_states = [ll.pop("gate_state", None) or {} for ll in legs]
    if reply_capture is not None:
        reply_capture["device_sequence"] = list(trail.device_sequence)
        reply_capture["leg_terminals"] = leg_terminals
        reply_capture["leg_gate_states"] = leg_gate_states
        reply_capture["lanes_spent"] = trail.lanes_spent


@trace_scope()
def _trace_domain(
    session: Any,
    src_ip: str,
    dst_ip: str,
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    gateways: list[dict[str, Any]],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    probe: str,
    src: dict[str, Any] | None,
    domain: str | None,
    rib: Any | None = None,
    *,
    max_hops: int,
    dst_instances: list[dict[str, Any]] | None = None,
    dst_context: str | None = None,
    reply_capture: dict[str, Any] | None = None,
    src_port: Any = None,
) -> dict[str, Any]:
    """One full trace inside a single L3 domain (None means unscoped).

    `src_port` is the source port of the flow when the caller states one. It
    walks the query as a region (see `_device_stage`).

    `dst_instances` is every live IpAddress row for `dst_ip`, fetched once by
    `trace()`. `dst_context` is the context that the caller expects the flow
    to reach (`_check_delivery_context`).

    `reply_capture`, when a caller passes a dict, is filled in with the
    internal state a reply walk needs. The internal keys are popped off the
    legs in both cases.
    """
    dst_instances = dst_instances or []
    trail = _Trail()
    trail.max_hops = max_hops
    # The address that the query named, before the dNAT of any device runs.
    trail.orig_dst = dst_set
    attach = _source_attachment(trail, src, src_ip)
    gw = _pick_gateway(
        gateways,
        probe,
        domain,
        trail,
        session=session,
        seg_uid=src.get("seg_uid") if src else None,
        attach=attach,
    )
    if gw and gw.get("ambiguous"):
        return _ambiguous_gateway_result(trail, gw, src_set)
    if gw and gw.get("unknown"):
        return _unknown_gateway_result(trail, gw, src_set)
    if not gw:
        return _no_gateway_result(trail, session, probe)
    # From here on, the gateway that won scopes the trace, and destination
    # lookups stay in its forwarding context. The anchor of the gateway
    # replaces a source anchor that is not a context (an L2 segment, a scope string).
    domain = _anchor_of(gw) or domain
    flow = _flow_label(f"{_describe(src_set)} → {_describe(dst_set)}", port, proto, src_port)
    # The region of the query is built at its first use and shared after it. A
    # point query that crosses no transparent gate does not build it, because
    # parsing a protocol name that the number table does not hold raises.
    query_region = functools.cache(lambda: _query_region(src_set, dst_set, port, proto, src_port))

    # When the source and the destination are inside the same connected
    # prefix, the flow is pure L2 and the packet does not visit the gateway.
    # An ingress taken from the route back to the source (`_rpf_ingress`) does
    # not make the flow switched.
    gw_set = _intervals([gw["cidr"]]) if gw.get("cidr") and not gw.get("rpf") else []
    same_prefix = bool(gw_set) and not _subtract(src_set, gw_set) and not _subtract(dst_set, gw_set)
    # The exception is a destination that is the address of the gateway in
    # that prefix. That packet is addressed to the router, which terminates it
    # and judges it by its input chain and local-zone policy (`_walk_group`).
    own_part = _gateway_own_part(session, trail, gw, src_set, dst_set) if same_prefix else []
    hosts = _subtract(dst_set, own_part) if own_part else dst_set
    # The two halves of a split set. The gate coverage judges each half on its own.
    split: list[list[dict[str, Any]]] | None = None
    if same_prefix and hosts:
        legs = _switched_legs_with_crossings(
            session,
            trail,
            gw,
            attach,
            src,
            src_set,
            hosts,
            dst_ip,
            domain,
            port,
            proto,
            src_port,
            rib,
            max_hops,
            query_region
            if not own_part
            else functools.cache(lambda: _query_region(src_set, hosts, port, proto, src_port)),
        )
        if own_part:
            # The address of the gateway in the set is judged on the router,
            # in its own lane beside the switched hosts.
            trail.notes.append(
                f"{_describe(own_part)} is an address of {gw.get('dev_name') or gw['dev_uid']} itself "
                f"and {_describe(hosts)} is not; the two are evaluated separately"
            )
            lane = 1 + max((int(leg.get("lane") or 0) for leg in legs), default=-1)
            trail.at(lane)
            own_legs = _walk_from_gateway(
                session, trail, gw, attach, src, src_set, own_part, port, proto, src_port, rib, max_hops, lane
            )
            split = [_label_split(legs, hosts), _label_split(own_legs, own_part)]
            legs = split[0] + split[1]
    else:
        legs = _walk_from_gateway(
            session, trail, gw, attach, src, src_set, dst_set, port, proto, src_port, rib, max_hops, 0
        )
        # A source set wider than the prefix of the gateway is walked whole
        # from this gateway (`_gateway_walk` warns). The part outside the prefix
        # has its own gateway and firewalls, which this walk did not cross.
        outside = _subtract(src_set, gw_set)
        if gw_set and outside:
            why = (
                f"{_describe(outside)} of the source is outside {gw['cidr']} "
                "and was not traced (different gateway)"
            )
            for leg in legs:
                leg["indeterminate"] = True
                leg.setdefault("indeterminate_reason", why)
    result = _finish_trace(
        session,
        trail,
        legs,
        flow,
        gw,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
        proto=proto,
        domain=domain,
        dst_instances=dst_instances,
        dst_context=dst_context,
        split=split,
    )
    _capture_reply_state(trail, legs, reply_capture)
    return result


def _label_split(legs: list[dict[str, Any]], part: list[tuple[int, int, int]]) -> list[dict[str, Any]]:
    """Name the destination half that each leg of a split same-subnet set answers for."""
    for leg in legs:
        if not leg.get("dst_label"):
            leg["dst_label"] = _describe(part)
    return legs


def _source_walk(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    attach: Any,
    src_set: list[tuple[int, int, int]],
    *,
    expect_chain: bool,
) -> bool:
    """`_gateway_walk`, and whether it proved a bridge-domain mismatch on the
    source side. Such a mismatch is before the gateway and contradicts the
    ingress interface of the forwarding decision (`_finish_trace`)."""
    prior, trail.l2_mismatch = trail.l2_mismatch, False
    _gateway_walk(session, trail, gw, attach, src_set, expect_chain=expect_chain)
    found = trail.l2_mismatch
    trail.l2_mismatch = prior or found
    return found


def _mark_source_mismatch(legs: list[dict[str, Any]], found: bool) -> list[dict[str, Any]]:
    """Mark the legs that have a source-side mismatch, with an internal key
    that `_finish_trace` reads and drops."""
    if found:
        for ll in legs:
            ll["_l2_src_mismatch"] = True
    return legs


def _walk_from_gateway(
    session: Any,
    trail: _Trail,
    gw: dict[str, Any],
    attach: Any,
    src: dict[str, Any] | None,
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    port: Any,
    proto: Any,
    src_port: Any,
    rib: Any | None,
    max_hops: int,
    lane: int,
) -> list[dict[str, Any]]:
    """The routed branch of `_trace_domain`: the walk to the gateway, then
    its device stage (or the transparent crossings in front of it), in `lane`."""
    endpoint = src.get("att_uid") if src and src.get("att_is_port") else None
    _target, crossings, gap = (
        vsx.resolve(session, endpoint, None, target=gw["if_uid"]) if endpoint else (None, [], None)
    )
    src_mismatch = False
    if gw.get("rpf"):
        # The source is behind a routed hop, and there is no L2 leg to draw.
        trail.hop(
            gw["if_uid"],
            "Interface",
            gw["if_name"],
            f"route to the source {gw['cidr']}",
            stage=Stage.INGRESS_IF,
        )
        trail.hop(gw["dev_uid"], "Device", gw["dev_name"] or "router", stage=Stage.DEVICE)
    else:
        src_mismatch = _source_walk(session, trail, gw, attach, src_set, expect_chain=src is not None)
    if crossings or gap:
        seed = {
            "blocked": False,
            "indeterminate": bool(gap),
            "sources": _to_cidrs(src_set),
            "src_label": _describe(src_set),
            "lane": lane,
        }
        if gap:
            seed["indeterminate_reason"] = gap
            trail.warn(gap)
        parts = _transparent_parts(
            session, trail, crossings, seed, _query_region(src_set, dst_set, port, proto, src_port)
        )
        return _mark_source_mismatch(
            _walk_crossing_parts(session, trail, gw, parts, rib, max_hops=max_hops), src_mismatch
        )
    legs, _lane = _device_stage(
        session,
        trail,
        gw,
        src_set,
        dst_set,
        port,
        proto,
        lane,
        rib,
        max_hops=max_hops,
        src_port=src_port,
    )
    return _mark_source_mismatch(legs, src_mismatch)


# The maximum number of contexts that a trace walks for one probe address. The
# "more interpretations exist" note of `trace` names the dropped contexts.
MAX_INTERPRETATIONS = 8


def _narrow_sources(
    sources: list[dict[str, Any]], src_context: str, src_ip: str
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Keep only the source candidates in the asserted context.

    The second item is the whole-trace result when none match, and None
    otherwise.
    """
    narrowed = [s for s in sources if _anchor_of(s) == src_context]
    if not narrowed:
        existing = sorted({str(_anchor_of(s) or "?") for s in sources})
        return sources, {
            "hops": [],
            "legs": [],
            "notes": [
                f"source {src_ip} exists in {len(sources)} anchor(s) ({', '.join(existing)}); "
                f"none match src_context {src_context!r}"
            ],
            "warnings": [],
            "verdict": f"source {src_ip} does not exist in context {src_context!r}",
        }
    return narrowed, None


# The device of a VrfInstance, by the same two ties that `_VRF_DEVICE` in
# queries.py follows: OWNED_BY first, else interface membership.
_TABLE_DEVICE = (
    "coalesce(head([(v)-[:OWNED_BY]->(od:Device) WHERE NOT od:Retired | od]), "
    "head([(v)<-[x:IN_VRF]-(:Interface)-[:ON]->(dd:Device) "
    "WHERE x._retired_at IS NULL AND NOT dd:Retired | dd]))"
)

_START_TABLES_QUERY = f"""
MATCH (v:VrfInstance:Obj)
WHERE NOT v:Retired AND v.collection_ts = $snap
WITH v, {_TABLE_DEVICE} AS d
WHERE d IS NOT NULL
RETURN v.uid AS uid, v.name AS name, d.hostname AS device
ORDER BY device, name, uid"""

_START_TABLE_QUERY = f"""
MATCH (v:VrfInstance {{uid: $u}})
WHERE NOT v:Retired AND v:Obj AND v.collection_ts = $snap
WITH v, {_TABLE_DEVICE} AS d
WHERE d IS NOT NULL
RETURN v.uid AS uid, v.name AS name, d.uid AS dev_uid, d.hostname AS dev_name
ORDER BY uid LIMIT 1"""

_NAMED_TABLES_QUERY = f"""
MATCH (v:VrfInstance:Obj)
WHERE NOT v:Retired AND v.collection_ts = $snap AND v.name = $name
WITH v, {_TABLE_DEVICE} AS d
WHERE d IS NOT NULL
RETURN v.uid AS uid, v.name AS name, d.uid AS dev_uid, d.hostname AS dev_name
ORDER BY dev_name, uid"""

# The prefixes that cover the source among the routes of every table of a VRF
# name, read in one statement (`vrf_starts`). The longest prefix is an upper
# bound on the route that `_rpf_ingress` takes back to the source. Only the
# tables whose bound can still match the best route found are resolved one by
# one. The query covers both kinds of route that `_ROUTES_QUERY` reads, and it
# resolves the route-target imports in the same way. A prefix without the keys
# is returned whatever it covers, and the caller filters it by address.
_RPF_BOUNDS_QUERY = (
    """
UNWIND $tables AS tu
MATCH (v:VrfInstance:Obj {uid: tu, collection_ts: $snap})
CALL (v) {
  MATCH (v)-[r:STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES]->(p:Prefix)
  WHERE NOT p:Retired AND r._retired_at IS NULL
    AND (p.lo_key IS NULL OR (p.lo_key <= $key AND p.hi_key >= $key))
  RETURN p
  UNION
"""
    + RT_IMPORTED_ROUTES
    + """  WITH p WHERE p.lo_key IS NULL OR (p.lo_key <= $key AND p.hi_key >= $key)
  RETURN p
}
RETURN v.uid AS table_uid, collect(DISTINCT p.cidr) AS cidrs"""
)

# A recursive next hop resolves through at most this many routes before the
# route back to the source is taken as having no interface.
_RPF_MAX_RECURSION = 4


def start_tables(session: Any) -> list[dict[str, Any]]:
    """Every VRF of the run that belongs to a device, sorted by device and
    name. These are the values that `trace()` accepts as `start_table`."""
    if not hasattr(session, "cts"):
        from hst.core import snapshot as _snapshotmod

        session = _path.pinned(session, _snapshotmod.resolve(session, Settings()))
    return [
        {"uid": r["uid"], "name": r["name"], "device": r["device"]}
        for r in _path._read(session, _START_TABLES_QUERY)
    ]


def start_vrfs(session: Any) -> list[dict[str, Any]]:
    """Every VRF name of the run with the number of devices that have a VRF
    of that name, sorted by name. These are the names that `trace_from_vrf`
    accepts. A VRF name is one name across the estate and is listed once."""
    devices: dict[str, set[str]] = {}
    for t in start_tables(session):
        if t["name"]:
            devices.setdefault(t["name"], set()).add(t["device"] or t["uid"])
    return [
        {"name": n, "devices": len(d)} for n, d in sorted(devices.items(), key=lambda kv: kv[0].casefold())
    ]


@dataclass(frozen=True)
class VrfStarts:
    """The start of a trace from a VRF name (`vrf_starts`)."""

    # Every VrfInstance of the name, with its device.
    tables: list[dict[str, Any]]
    # The instances that the trace starts in.
    starts: list[dict[str, Any]]
    # The way the instances were chosen, when it is not the gateway of the source.
    note: str | None


def _where(table: dict[str, Any]) -> str:
    return f"{table['name']} on {table['dev_name'] or table['dev_uid']}"


def _prefix_length(cidr: str | None) -> int:
    return int(cidr.rsplit("/", 1)[1]) if cidr and "/" in cidr else 0


def vrf_starts(
    session: Any, vrf: str, src_ip: str, gateways: list[dict[str, Any]] | None = None, rib: Any | None = None
) -> VrfStarts:
    """The instances of the VRF named `vrf` that a trace from `src_ip` starts in.

    The name matches exactly, case included. VRF names are case-sensitive on
    every platform that the collectors read. The instances are those whose
    gateway prefix holds the source, with the longest such prefix only. For a
    single address they are narrowed to the instances that the address is in
    (`_source_candidates`), because the same prefix can be on every leaf of a
    fabric and the host is behind one leaf. When the VRF has no gateway for
    the source, the instances are those whose route back to the source is
    the most specific (`_rpf_ingress`). Several instances of equal length all
    start the trace.
    """
    session = _pinned_session(session)
    tables = _path._read(session, _NAMED_TABLES_QUERY, name=vrf)
    src_set = _intervals([src_ip])
    if not tables or not src_set:
        return VrfStarts(tables, [], None)
    probe = _probe_of(src_set)
    gws = _path.load_gateways(session) if gateways is None else gateways
    # The connected prefix that holds the source. The longest prefix wins, as
    # a route lookup picks it. A /16 on one device then does not start the
    # trace beside the /24 that holds the source on another device.
    uids = {t["uid"] for t in tables}
    lengths: dict[str, int] = {}
    for g in _containing(gws, probe):
        anchor = _anchor_of(g)
        if anchor in uids:
            lengths[anchor] = max(lengths.get(anchor, -1), _prefix_length(g.get("cidr")))
    longest = max(lengths.values(), default=-1)
    held = {anchor for anchor, n in lengths.items() if n == longest}
    if held:
        if _size(src_set) == 1:
            seen = {_anchor_of(c) for c in _source_candidates(session, probe)} & held
            held = seen or held
        return VrfStarts(tables, [t for t in tables if t["uid"] in held], None)
    best: list[dict[str, Any]] = []
    length = -1
    # The longest bound comes first. When the bound of a table is below the
    # best route back found, neither that table nor any later table can match
    # that route. A table whose bound overstates its route (a discard, a next
    # hop that does not resolve) costs only its own resolution.
    bounds = _rpf_bounds(session, tables, probe, rib)
    for t in sorted(tables, key=lambda t: -bounds.get(t["uid"], -1)):
        bound = bounds.get(t["uid"], -1)
        if bound < 0 or bound < length:
            break
        ingress, _notes = _rpf_ingress(session, t, probe, rib)
        if ingress is None:
            continue
        n = _prefix_length(ingress["cidr"])
        if n > length:
            best, length = [t], n
        elif n == length:
            best.append(t)
    if not best:
        return VrfStarts(tables, [], None)
    rank = {t["uid"]: i for i, t in enumerate(tables)}
    best.sort(key=lambda t: rank[t["uid"]])
    where = ", ".join(_where(t) for t in best)
    note = (
        f"no gateway of VRF {tables[0]['name']} holds the source {src_ip}; "
        f"{where} {'has' if len(best) == 1 else 'have'} the most specific route back to it, a /{length}"
    )
    return VrfStarts(tables, best, note)


@_one_estate_read
def trace_from_vrf(
    session: Any,
    src_ip: str,
    dst_ip: str,
    vrf: str,
    port: int | str | list[Any] | None = None,
    proto: str | list[Any] | frozenset[int] | None = None,
    gateways: list[dict[str, Any]] | None = None,
    rib: Any | None = None,
    **options: Any,
) -> dict[str, Any]:
    """Trace `src_ip` to `dst_ip` from the VRF named `vrf`, on the devices
    that `vrf_starts` picks. Each of several starts is traced, and the
    results are merged (`_merge_lanes`). `options` go to `trace`. A reply is
    refused for more than one start."""
    session = _pinned_session(session)
    if not _intervals([src_ip]):
        # The input is not an address, and the plain trace answers with the input error.
        return trace(session, src_ip, dst_ip, port, proto, gateways, rib, **options)
    # The gateways are loaded once, for the start and for every trace from it.
    gateways = _path.load_gateways(session) if gateways is None else gateways
    found = vrf_starts(session, vrf, src_ip, gateways, rib)
    if not found.starts:
        verdict = (
            f"VRF {found.tables[0]['name']} has no gateway for the source {src_ip} and no route back to it"
            if found.tables
            else f"no VRF named {vrf!r} in this run"
        )
        return _with_edge_keys({"hops": [], "legs": [], "notes": [], "warnings": [], "verdict": verdict})
    picked, dropped = found.starts[:MAX_INTERPRETATIONS], found.starts[MAX_INTERPRETATIONS:]
    if len(picked) > 1 and options.get("reply"):
        raise ValueError(
            f"reply=True is not supported for VRF {vrf}: the trace starts on {len(found.starts)} devices, "
            "and nothing says which one a reply is for"
        )
    results = [
        trace(session, src_ip, dst_ip, port, proto, gateways, rib, start_table=t["uid"], **options)
        for t in picked
    ]
    notes = [found.note] if found.note else []
    if len(results) == 1 and not dropped:
        results[0]["notes"] = [*notes, *results[0].get("notes", [])]
        return results[0]
    starts = ", ".join(map(_where, picked))
    notes.insert(0, f"VRF {vrf} starts the trace on {len(picked)} devices ({starts}); each is traced")
    drop_warning = None
    if dropped:
        drop_warning = f"{len(dropped)} more devices have it ({', '.join(map(_where, dropped))})"
        notes.append(drop_warning)
    return _merge_lanes(
        [(_where(t), f"start:{t['uid']}", r) for t, r in zip(picked, results, strict=True)],
        notes,
        truncated=bool(dropped),
        drop_warning=drop_warning,
    )


def _rpf_bounds(session: Any, tables: list[dict[str, Any]], probe: str, rib: Any | None) -> dict[str, int]:
    """For each table uid, the prefix length of the longest route of the table,
    in the graph or in the side store, that covers `probe`. This length is an
    upper bound on the route back that `_rpf_ingress` takes. A table with no
    covering route is absent. The function makes one graph read and one
    side-store read for every table."""
    target = ipaddress.ip_address(probe)
    bounds: dict[str, int] = {}
    rows = _path._read(
        session, _RPF_BOUNDS_QUERY, tables=[t["uid"] for t in tables], key=ipenc.graph_key(probe)
    )
    for row in rows:
        for cidr in row.get("cidrs") or []:
            try:
                net = ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                continue
            if target in net:
                uid = row["table_uid"]
                bounds[uid] = max(bounds.get(uid, -1), net.prefixlen)
    for uid, n in _store_lengths(rib, tables, probe).items():
        bounds[uid] = max(bounds.get(uid, -1), n)
    return bounds


def _store_lengths(rib: Any | None, tables: list[dict[str, Any]], probe: str) -> dict[str, int]:
    """For each table uid, the prefix length of the longest route of the side
    store that covers `probe`. That route is the LPM answer of `_rib_lookup`.
    The parquet store answers every table in one statement
    (`RibSource.covering_lengths`). A store held in memory is asked per table."""
    if rib is None or not tables:
        return {}
    batch = getattr(rib, "covering_lengths", None)
    if batch is not None:
        lengths: dict[str, int] = batch([(t["dev_uid"], t["uid"], t["name"]) for t in tables], probe)
        return lengths
    out: dict[str, int] = {}
    for t in tables:
        for r in rib.lpm(t["dev_uid"], t["uid"], probe, legacy_vrf=t["name"]):
            n = r.get("prefixlen")
            n = int(n) if n is not None else ipaddress.ip_network(str(r["prefix"]), strict=False).prefixlen
            out[t["uid"]] = max(out.get(t["uid"], -1), n)
    return out


def _rpf_ingress(
    session: Any, table: dict[str, Any], probe: str, rib: Any | None
) -> tuple[dict[str, Any] | None, list[str]]:
    """The interface of the route back to the source in the start table, and
    the notes about it.

    A trace that starts in a VRF with no gateway prefix for the source takes
    the ingress interface as a reverse path check does, from the route in
    that table to the source address. A route with only a next hop is
    resolved through the next hop, in the same table. The interface is None
    when no route, a discard route, or no interface is found.
    """
    target = _intervals([probe])
    af = target[0][0]
    routes = [
        r
        for r in _path._read(session, _ROUTES_QUERY, vrf=table["uid"])
        if (":" in (r["cidr"] or "")) == (af == 6)
    ]
    lookup = _rib_lookup(rib, table["dev_uid"], table["uid"], table["name"])
    notes: list[str] = []
    first_cidr: str | None = None
    for _ in range(_RPF_MAX_RECURSION):
        parts = _route_partition(routes, target, lookup, [])
        best = parts[0][1] if parts else []
        if not best or best[0].get("discard"):
            return None, notes
        route = best[0]
        first_cidr = first_cidr or route["cidr"]
        if len(best) > 1 and not notes:
            others = ", ".join(
                str(r.get("egress_name") or r.get("ifname") or r.get("next_hop")) for r in best[1:]
            )
            notes.append(
                f"{len(best)} equal-cost routes {route['cidr']} to the source; the others leave by {others}"
            )
        egress_uid, egress_name = route["egress_uid"], route["egress_name"]
        if not egress_uid and route["ifname"]:
            named = _path._read_one(
                session, _IFACE_BY_NAME_QUERY, name=route["ifname"], dev=table["dev_uid"], vrf=table["uid"]
            )
            if named:
                egress_uid, egress_name = named["uid"], named["name"]
        if egress_uid:
            return {"cidr": first_cidr, "if_uid": egress_uid, "if_name": egress_name}, notes
        next_hop = route.get("next_hop")
        if not next_hop or not _intervals([next_hop]):
            return None, notes
        target = _intervals([next_hop])
    return None, notes


def _trace_from_table(
    session: Any,
    src_ip: str,
    dst_ip: str,
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    gws: list[dict[str, Any]],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    probe: str,
    start_table: str,
    rib: Any | None,
    *,
    max_hops: int,
    dst_instances: list[dict[str, Any]],
    dst_context: str | None,
    reply_capture: dict[str, Any],
    src_port: Any,
) -> dict[str, Any]:
    """A trace that starts in one VRF of one device (`trace(start_table=...)`).

    The first route lookup is in `start_table`. The source address is the
    source of the flow and does not select the start. The ingress interface
    is the gateway interface of that VRF whose prefix contains the source,
    else the interface of the route back to the source (`_rpf_ingress`).
    """

    def stopped(verdict: str, notes: list[str] | None = None) -> dict[str, Any]:
        return {"hops": [], "legs": [], "notes": notes or [], "warnings": [], "verdict": verdict}

    table = _path._read_one(session, _START_TABLE_QUERY, u=start_table)
    if not table:
        return stopped(f"no VRF {start_table!r} that belongs to a device in this run")
    where = f"VRF {table['name']} on {table['dev_name'] or table['dev_uid']}"
    own = [g for g in gws if _anchor_of(g) == start_table]
    if _containing(own, probe):
        gateways = gws
        start_note = f"trace starts in {where}"
    else:
        ingress, rpf_notes = _rpf_ingress(session, table, probe, rib)
        if ingress is None:
            return stopped(
                f"{where} has no route to the source {src_ip}; the ingress interface is not known",
                rpf_notes,
            )
        gateways = [
            {
                "cidr": ingress["cidr"],
                "l3dom": None,
                "anchor": start_table,
                "if_uid": ingress["if_uid"],
                "if_name": ingress["if_name"],
                "dev_uid": table["dev_uid"],
                "dev_name": table["dev_name"],
                "dev_carried": False,
                "rpf": True,
            }
        ]
        start_note = (
            f"trace starts in {where}; ingress {ingress['if_name']} is the interface of the "
            f"route {ingress['cidr']} to the source"
        )
        rpf_notes.insert(0, start_note)
        start_note = "; ".join(rpf_notes)
    result = _trace_domain(
        session,
        src_ip,
        dst_ip,
        port,
        proto,
        gateways,
        src_set,
        dst_set,
        probe,
        None,
        start_table,
        rib,
        max_hops=max_hops,
        dst_instances=dst_instances,
        dst_context=dst_context,
        reply_capture=reply_capture,
        src_port=src_port,
    )
    result["notes"] = [start_note, *result.get("notes", [])]
    return result


def _trace_interpretations(
    session: Any,
    src_ip: str,
    dst_ip: str,
    port: int | str | list[Any] | None,
    proto: str | list[Any] | frozenset[int] | None,
    gws: list[dict[str, Any]],
    src_set: list[tuple[int, int, int]],
    dst_set: list[tuple[int, int, int]],
    probe: str,
    sources: list[dict[str, Any]],
    rib: Any | None,
    dst_instances: list[dict[str, Any]],
    dst_context: str | None,
    *,
    max_hops: int,
    src_port: Any = None,
) -> dict[str, Any]:
    """One trace per source interpretation, merged into a single result.

    The same address exists in more than one L3 domain, and nothing in the
    question selects one. Every candidate is traced.
    """
    dropped: list[dict[str, Any]] = []
    if len(sources) > MAX_INTERPRETATIONS:
        # `_source_candidates` returns rows sorted by anchor. The traced subset
        # and the drop note are then deterministic.
        dropped, sources = sources[MAX_INTERPRETATIONS:], sources[:MAX_INTERPRETATIONS]
    doms = [s["l3dom"] or "?" for s in sources]
    notes = [f"source {src_ip} exists in {len(sources)} L3 domains ({', '.join(doms)}); each is traced"]
    drop_warning = None
    if dropped:
        more = ", ".join(str(_anchor_of(s) or "?") for s in dropped)
        drop_warning = f"{len(dropped)} more interpretations exist (anchors: {more}); narrow with src_context"
        notes.append(drop_warning)
    parts = [
        (
            src["l3dom"] or "?",
            f"interpretation:{_anchor_of(src)}",
            _trace_domain(
                session,
                src_ip,
                dst_ip,
                port,
                proto,
                gws,
                src_set,
                dst_set,
                probe,
                src,
                _anchor_of(src),
                rib,
                max_hops=max_hops,
                dst_instances=dst_instances,
                dst_context=dst_context,
                src_port=src_port,
            ),
        )
        for src in sources
    ]
    return _merge_lanes(parts, notes, truncated=bool(dropped), drop_warning=drop_warning)


def _merge_lanes(
    parts: list[tuple[str, str, dict[str, Any]]],
    notes: list[str],
    *,
    truncated: bool,
    drop_warning: str | None = None,
) -> dict[str, Any]:
    """Traces of one question from several starts, merged into one result.

    Each part is (label, connection id, result). The lanes are offset per
    part, and the answers do not collide in the viewer. Each hop, leg, note,
    warning and verdict names its part. A part that drew no leg was not
    traced, and the starts past the cap (`drop_warning`) were not traced. The
    merge is then undecided and states the reason."""
    hops: list[dict[str, Any]] = []
    legs: list[dict[str, Any]] = []
    warnings: list[str] = []
    verdicts: list[str] = []
    indeterminate = False
    boundary = False
    exits: list[dict[str, Any]] = []
    # The `reach` of each part. A part without a `reach` is not known.
    reaches: list[str | None] = []
    mtu_parts: list[MtuResult] = []
    lane_base = 0
    for dom, connection_id, result in parts:
        if "mtu" in result:
            part = MtuResult.model_validate(result["mtu"])
            part.connection_id = connection_id
            for stage in part.stages:
                stage.connection_id = part.connection_id
                stage.lane = str(int(stage.lane) + lane_base)
            mtu_parts.append(part)
        lanes = 1 + max([h["lane"] for h in result["hops"]] + [ll["lane"] for ll in result["legs"]] + [0])
        for h in result["hops"]:
            hops.append({**h, "lane": h["lane"] + lane_base, "domain": dom})
        for ll in result["legs"]:
            ll["lane"] += lane_base
            ll["domain"] = dom
            legs.append(ll)
        notes.extend(f"[{dom}] {n}" for n in result["notes"])
        warnings.extend(f"[{dom}] {w}" for w in result.get("warnings") or [])
        verdicts.append(f"[{dom}] {result['verdict']}")
        indeterminate = indeterminate or bool(result.get("indeterminate"))
        if not result["legs"]:
            # A start that drew no leg (no gateway, no route back to the
            # source) was not traced. The other parts do not answer for it.
            indeterminate = True
            warnings.append(f"[{dom}] not traced: {result['verdict']}")
        boundary = boundary or bool(result.get("boundary"))
        exits += result.get("left_estate") or []
        reaches.append(result.get("reach"))
        lane_base += lanes
    if drop_warning:
        indeterminate = True
        warnings.append(f"not traced: {drop_warning}")
        verdicts.append(f"not traced: {drop_warning}")
    merged = {
        "hops": hops,
        "legs": legs,
        "verdict": "; ".join(verdicts),
        "notes": notes,
        "warnings": warnings,
        "indeterminate": indeterminate,
        "boundary": boundary,
        "left_estate": [e for k, e in sorted({_exit_key(e): e for e in exits}.items())],
        # The merged reach is null when a part has no reach or the merge is undecided.
        "reach": (
            None
            if indeterminate or not reaches or any(r is None for r in reaches)
            else ("split" if len(set(reaches)) > 1 else reaches[0])
        ),
    }

    if mtu_parts:
        aggregate = MtuResult(mode=mtu_parts[0].mode, outcome="unknown", connections=mtu_parts)
        aggregate.coverage.truncated = truncated
        merged["mtu"] = aggregate.model_dump(mode="json")
    return merged


@_one_estate_read
def trace_from_identity(
    session: Any,
    identity_uid: str,
    segment_ref: str,
    port: int | None,
    proto: str | None,
    gateways: list[dict[str, Any]] | None = None,
    rib: Any | None = None,
    *,
    max_hops: int | None = None,
    reply: bool = False,
    mtu: MtuRequest | dict[str, Any] | None = None,
    follow_same_as: bool = False,
) -> dict[str, Any]:
    """The ZPA brokered entry point.

    The access rule is the first match (core/zpa_policy.py) over the enabled
    rules that apply to the segment, through FOR or as a rule with no
    application condition in the tenant of the segment. A disabled rule is
    skipped. A winner that is negated, OR-joined, require_approval or
    unknown-disabled is undecided.

    `follow_same_as` lets a connector without a RUNS_ON address originate
    from the campus address that its `private_ip` is linked to by `SAME_AS`.
    A note of the result names that basis. It is off by default, as every
    SAME_AS traversal is.

    `reply=True` raises ValueError.

    A caller supplies an IdentityGroup uid, a ZpaAppSegment uid or one of its
    collected FQDNs, and the port and protocol of the flow.
    `gateways` and `rib` are the same optional pre-loaded reads that
    `trace()` takes. When they are None, the gateways are loaded here from
    the session.

    A bare session is pinned to the current run of the pointer before the
    first read.

    The winning ZpaAccessRule is resolved first-match by integer position
    over GRANTS|DENIES(identity) and FOR(segment|segment group)
    (`gates.zpa._access_rule_match`). On ALLOW, the RESOLVES_TO chain of the
    segment resolves a destination address set, and a healthy connector is
    chosen (`gates.zpa._segment_resolution` and `_connector_selection`). The
    collected address of the connector (`_connector_address`) becomes the
    source of a new locally originated flow. That flow enters the ordinary
    device pipeline through `_pick_gateway`, `_gateway_walk` and
    `_device_stage`, as in the member recursion of `_lb_stage`.

    Every undecidable dimension is an INDETERMINATE leg that names the
    reason and draws no hop past the point of failure. The undecidable
    dimensions are an identity group that the graph does not contain, an
    ambiguous or absent rule match, an unsupported condition shape, port
    ranges that the segment did not collect, an unresolved segment address,
    no healthy connector, a connector with no collected address, and a
    connector address that resolves in more than one forwarding context. A
    DENY verdict and a port that the segment does not publish are each a
    blocked leg with `blocking_uid` set to the object that decided, as in
    the load balancer stage.

    No caller in `/api/path`, the CLI or the agent tools invokes it.
    """
    request = None
    if mtu is not None:
        request = mtu if isinstance(mtu, MtuRequest) else MtuRequest.model_validate(mtu)
        if request.mode == "off":
            request = None
    if reply:
        raise ValueError(
            "reply=True is not supported for a ZPA brokered trace: the broker's connector "
            "selection and segment resolution carry no per-leg translation chain for a reply "
            "to undo, and no routing of their own to walk backward"
        )
    _refuse_ranged_query(port, proto)
    settings = Settings()
    max_hops = settings.max_l3_hops if max_hops is None else max_hops
    session = _pinned_session(session, settings)
    gws = _path.load_gateways(session) if gateways is None else gateways
    start = _identity_preamble(session, identity_uid, segment_ref, port, proto, max_hops, follow_same_as)
    if isinstance(start, dict):
        start = _with_edge_keys(start)
        return start if request is None else ensure_result(start, request)
    scope: contextlib.AbstractContextManager[None] = contextlib.nullcontext()
    if request is not None:
        # The address family is known only after the address of the connector
        # and the destination addresses of the segment are resolved.
        families = {a[0] for a in _intervals([start.src_ip, *start.resolution.addresses])}
        if len(families) != 1:
            raise ValueError("MTU tracing requires one address family per request")
        scope = mtu_request(request, next(iter(families)))
    with scope:
        result = _with_edge_keys(
            _identity_forward(session, start, identity_uid, port, proto, gws, rib, max_hops)
        )
    return result if request is None else ensure_result(result, request)


@dataclass(frozen=True)
class _IdentityStart:
    """The state of a brokered trace after the address of the connector is known."""

    trail: _Trail
    segment_uid: str
    resolution: SegmentResolution
    src_ip: str


def _identity_preamble(
    session: Any,
    identity_uid: str,
    segment_ref: str,
    port: int | None,
    proto: str | None,
    max_hops: int,
    follow_same_as: bool,
) -> dict[str, Any] | _IdentityStart:
    """The brokered stages up to the address of the connector. Returns an
    early result when a stage stops the flow, else the state that the
    forward walk starts from."""
    trail = _Trail()
    trail.max_hops = max_hops
    identity_row = _identity_group(session, identity_uid)
    if identity_row is None:
        # No hop is drawn for an identity that the twin does not hold. A hop
        # states that the object is in the graph.
        reason = f"{identity_uid}: no IdentityGroup with this uid is in the graph"
        return _zpa_stop(trail, reason)
    trail.hop(
        identity_uid,
        "IdentityGroup",
        identity_row.get("name") or identity_uid,
        stage=Stage.IDENTITY,
    )

    choice = _choose_segment(session, segment_ref, port, proto)
    if choice.uid is None:
        return _zpa_stop(
            trail, choice.reason or f"{segment_ref}: no segment determined", blocking_uid=choice.blocking_uid
        )
    segment_uid = choice.uid

    # A disabled segment is blocked. A bypassed segment is not brokered, and
    # the answer is not decided here.
    state = _segment_state(session, segment_uid)
    if state != "active":
        reason = zpa_policy.segment_state_reason(segment_uid, state)
        if state == "disabled":
            return _zpa_stop(trail, reason, blocking_uid=segment_uid)
        return _zpa_stop(trail, reason)

    # The published ports of the segment decide whether this flow is brokered,
    # before any rule is read. A broker does not intercept a port that the
    # segment does not publish.
    ports = _segment_port_match(session, segment_uid, port, proto)
    if ports.indeterminate:
        reason = ports.reason or f"{segment_uid}: the published port ranges are not determined"
        return _zpa_stop(trail, reason)
    if not ports.matched:
        reason = ports.reason or f"{segment_uid}: the requested port is not published"
        return _zpa_stop(trail, reason, blocking_uid=segment_uid)
    if port is None or not proto:
        trail.notes.append(f"no port and proto given; {segment_uid}'s collected port ranges are not compared")

    # Client forwarding comes first. It decides whether ZCC sends the flow to ZPA.
    forwarding = _forwarding_match(session, identity_uid, segment_uid)
    if forwarding.rule is not None:
        trail.notes.append(
            f"client forwarding: {_rule_label(forwarding.rule)} ({forwarding.action or 'undecided'})"
        )
    if forwarding.note:
        trail.notes.append(forwarding.note)
    if not forwarding.go_on:
        reason = forwarding.reason or f"{segment_uid}: the client forwarding match is not determined"
        return _zpa_stop(trail, reason)

    decision = _access_rule_match(session, identity_uid, segment_uid)
    winning_rule = decision.rule
    if winning_rule is not None:
        trail.hop(winning_rule["uid"], "ZpaAccessRule", _rule_label(winning_rule), stage=Stage.ACCESS_RULE)
    if decision.indeterminate or winning_rule is None:
        reason = decision.reason or f"{segment_uid}: the access rule match is not determined"
        return _zpa_stop(trail, reason)
    if decision.action == "deny":
        return _zpa_early_result(
            trail,
            verdict=f"{_rule_label(winning_rule)}: denied",
            indeterminate=False,
            blocking_uid=winning_rule["uid"],
        )

    resolution = _segment_resolution(session, segment_uid)
    if resolution.indeterminate:
        reason = resolution.reason or f"{segment_uid}: destination address not determined"
        return _zpa_stop(trail, reason)
    if resolution.note:
        trail.notes.append(resolution.note)

    selection = _connector_selection(session, segment_uid, winning_rule["uid"])
    if selection.all_disabled:
        reason = selection.note or f"every connector of {segment_uid} is disabled"
        return _zpa_stop(trail, reason, blocking_uid=segment_uid)
    if selection.collapsed or selection.chosen is None:
        reason = selection.note or f"{segment_uid}: no connector determined"
        return _zpa_stop(trail, reason)
    connector = selection.chosen
    trail.hop(
        connector["uid"],
        "ZpaAppConnector",
        connector.get("name") or connector["uid"],
        stage=Stage.CONNECTOR,
    )
    # The skipped candidates are named, as `_pick_gateway` names its own tie.
    if selection.alternates:
        trail.notes.append(
            f"{len(selection.alternates)} other healthy connector(s) of {segment_uid} not traced: "
            f"{_connector_names(list(selection.alternates))}"
        )
    if selection.no_health:
        trail.notes.append(
            f"{len(selection.no_health)} connector(s) of {segment_uid} carry no collected health "
            f"and are not candidates: {_connector_names(list(selection.no_health))}"
        )

    addr = _connector_address(session, connector["uid"], follow_same_as=follow_same_as)
    if not addr.ip:
        reason = addr.reason or f"{connector['uid']}: no collected address"
        return _zpa_stop(trail, reason)
    if addr.basis == "private_ip":
        trail.notes.append(
            f"{connector['uid']} has no RUNS_ON address; the flow is originated from {addr.ip}, "
            "its collected private_ip"
        )
    if addr.same_as_confidence is not None:
        trail.notes.append(
            f"{connector['uid']} has no RUNS_ON address; the flow is originated from {addr.ip}, the "
            f"campus address its private_ip is linked to by SAME_AS (confidence {addr.same_as_confidence})"
        )
    if addr.alternates:
        trail.notes.append(
            f"{connector['uid']} also carries {', '.join(addr.alternates)}; the flow is originated "
            f"from {addr.ip}"
        )
    return _IdentityStart(trail, segment_uid, resolution, addr.ip)


@trace_scope()
def _identity_forward(
    session: Any,
    start: _IdentityStart,
    identity_uid: str,
    port: int | None,
    proto: str | None,
    gws: list[dict[str, Any]],
    rib: Any | None,
    max_hops: int,
) -> dict[str, Any]:
    """The flow of the connector, from its address through the ordinary
    device pipeline to the resolved destination of the segment."""
    trail, segment_uid, resolution, src_ip = start.trail, start.segment_uid, start.resolution, start.src_ip
    src_set = _intervals([src_ip])
    dst_set = _intervals(resolution.addresses)
    trail.orig_dst = dst_set
    dst_ip = resolution.addresses[0]
    if len(resolution.addresses) > 1:
        # The forwarding walk covers every resolved address. The gates that
        # take one destination (the ACI contract read, the delivery labels)
        # are evaluated for the first address only, and the note states this.
        trail.notes.append(
            f"{segment_uid} resolves to {', '.join(resolution.addresses)}; the walk covers all "
            f"of them and the destination-bound gates were evaluated for {dst_ip} only"
        )
    src_rows = _source_candidates(session, src_ip)
    if len(src_rows) > 1:
        # More than one source row stops the trace, and the reason names the anchors.
        anchors = ", ".join(sorted(str(_anchor_of(r) or "?") for r in src_rows))
        reason = (
            f"{src_ip}: the connector's own address resolves in {len(src_rows)} forwarding "
            f"contexts ({anchors}); the path is not traced"
        )
        return _zpa_stop(trail, reason)
    src_row = src_rows[0] if src_rows else None
    attach = _source_attachment(trail, src_row, src_ip)
    gw = _pick_gateway(
        gws,
        src_ip,
        _anchor_of(src_row) if src_row else None,
        trail,
        session=session,
        seg_uid=src_row.get("seg_uid") if src_row else None,
        attach=attach,
    )
    if gw is None or gw.get("ambiguous") or gw.get("unknown"):
        if gw is None:
            reason = f"{src_ip}: no gateway found for the connector's own address"
        elif gw.get("unknown"):
            reason = f"{src_ip}: {gw['reason']}; the path is not traced"
        else:
            reason = (
                f"{src_ip}: the connector's own address matches gateway prefixes in more than one "
                "L3 domain; the path is not traced"
            )
        return _zpa_stop(trail, reason)
    domain = _anchor_of(gw) or (_anchor_of(src_row) if src_row else None)
    dst_instances = _dst_instances(session, dst_ip) if len(resolution.addresses) == 1 else []

    # The same-prefix branch that `_trace_domain` makes for every other flow.
    gw_set = _intervals([gw["cidr"]]) if gw.get("cidr") else []
    same_prefix = bool(gw_set) and not _subtract(src_set, gw_set) and not _subtract(dst_set, gw_set)
    own_part = _gateway_own_part(session, trail, gw, src_set, dst_set) if same_prefix else []
    hosts = _subtract(dst_set, own_part) if own_part else dst_set
    # The two halves of a split set. The gate coverage judges each half on its own.
    split: list[list[dict[str, Any]]] | None = None
    if same_prefix and hosts:
        legs = _switched_leg(
            session, trail, gw, attach, src_set, hosts, dst_ip, domain, port, proto, rib, max_hops=max_hops
        )
        _mark_switched(legs, src_row, _dst_attachment(session, hosts, domain, gw.get("if_uid")), domain)
        if own_part:
            # The address of the gateway in the set is judged on the router,
            # in its own lane beside the switched hosts.
            lane = 1 + max((int(leg.get("lane") or 0) for leg in legs), default=-1)
            trail.at(lane)
            found = _source_walk(session, trail, gw, attach, src_set, expect_chain=src_row is not None)
            own_legs, _lane = _device_stage(
                session, trail, gw, src_set, own_part, port, proto, lane, rib, max_hops=max_hops
            )
            _mark_source_mismatch(own_legs, found)
            split = [_label_split(legs, hosts), _label_split(own_legs, own_part)]
            legs = split[0] + split[1]
    else:
        found = _source_walk(session, trail, gw, attach, src_set, expect_chain=src_row is not None)
        legs, _lane = _device_stage(
            session, trail, gw, src_set, dst_set, port, proto, 0, rib, max_hops=max_hops
        )
        _mark_source_mismatch(legs, found)
    # The L2 signals, the combined verdict, the flow-level gates and the
    # interpretation of each leg are folded in as `_trace_domain` folds them.
    return _finish_trace(
        session,
        trail,
        legs,
        _flow_label(f"{identity_uid} → {segment_uid}", port, proto),
        gw,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
        proto=proto,
        domain=domain,
        dst_instances=dst_instances,
        dst_context=None,
        split=split,
    )


@_one_estate_read
def trace(
    session: Any,
    src_ip: str,
    dst_ip: str,
    port: int | str | list[Any] | None = None,
    proto: str | list[Any] | frozenset[int] | None = None,
    gateways: list[dict[str, Any]] | None = None,
    rib: Any | None = None,
    *,
    src_context: str | None = None,
    dst_context: str | None = None,
    start_table: str | None = None,
    max_hops: int | None = None,
    reply: bool = False,
    src_port: int | str | list[Any] | None = None,
    mtu: MtuRequest | dict[str, Any] | None = None,
    dscp: int | None = None,
) -> dict[str, Any]:
    """Trace `src_ip` to `dst_ip`, with a fan-out over every source candidate
    that the address resolves to.

    `dscp` states the DSCP mark of the flow, 0 to 63. Only an SD-WAN business
    policy rule reads it (`gates/sdwan.py`). When it is `None`, such a rule
    is undecided, as for an unstated port, and the boundary note states this.

    `start_table` is a VrfInstance uid (`start_tables` lists them). When it
    is set, the trace starts in that VRF on its device, and the source
    address does not select the start (`_trace_from_table`). It cannot be
    combined with `src_context`.

    `src_port` states the source port of the flow, in the same shapes as
    `port` (a scalar, a range spec, a list). When it is `None`, the tuple has
    no source port. When it is stated, the query is walked as a region
    (`_device_stage`), and the `service` field of a leg then holds
    `src_ports` beside `proto` and `ports`. A reply walk does not read it.

    `reply=True` answers both directions of the flow: `{forward: <the plain
    trace dict>, reply: <that same shape, for the reply>, asymmetric: bool,
    notes: [...]}`.

    The reply is derived once per forward leg. A trace that fanned out into
    more than one forward leg answers with `reply` as a list, with one entry
    per forward leg (`_compose_bidirectional`).

    `reply=True` raises ValueError for an `src_ip` that resolves to more
    than one source interpretation.

    `src_context` and `dst_context` are anchor or context uids. `src_context`
    narrows the candidate set before the fan-out. A path delivered or leaving
    the twin outside `dst_context` is undecided, and the reason is named.

    `max_hops` caps the number of L3 hops that the trace follows. It defaults
    to the `max_l3_hops` setting.

    A bare session is pinned here to the current run of the pointer. A
    database session whose pointer names no run raises `NoRun`.

    A scalar or `None` `port` and `proto` draw one flow. A range (a port spec
    string such as "80,443", a protocol spec such as "tcp_udp", or a list)
    draws a set of flows, with one leg per region that a rule decided
    (`_route_leg`). An unreadable spec is a caller error, raised here before
    any read.
    """

    def again(target: Any, mtu_arg: MtuRequest | dict[str, Any] | None = None) -> dict[str, Any]:
        # The same request on `target`, without the DSCP. The MTU request is
        # left out too unless `mtu_arg` passes one.
        return trace(
            target,
            src_ip,
            dst_ip,
            port,
            proto,
            gateways,
            rib,
            src_context=src_context,
            dst_context=dst_context,
            start_table=start_table,
            max_hops=max_hops,
            reply=reply,
            src_port=src_port,
            mtu=mtu_arg,
        )

    if dscp is not None:
        if not 0 <= dscp <= 63:
            raise ValueError(f"dscp {dscp} is outside 0..63")
        with sdwan_gate.flow_dscp(dscp):
            return again(session, mtu)
    if mtu is not None:
        request = mtu if isinstance(mtu, MtuRequest) else MtuRequest.model_validate(mtu)
        if request.mode != "off":
            return _trace_with_mtu(session, request, src_ip, dst_ip, again)
    _check_trace_request(port, proto, src_port, start_table, src_context)
    session = _pinned_session(session)
    src_set = _intervals([src_ip])
    dst_set = _intervals([dst_ip])
    if not src_set or not dst_set:
        return _with_edge_keys(
            {
                "hops": [],
                "legs": [],
                "notes": [],
                "warnings": [],
                "verdict": f"{src_ip!r} → {dst_ip!r}: not an address, prefix or range",
            }
        )
    # The instances are fetched once and reused by every lane below.
    # Forwarding decides the instance of the destination that a lane reaches,
    # and every other instance is reported once per trace.
    dst_probe = _probe_of(dst_set) if _size(dst_set) == 1 else None
    req = _TraceRequest(
        session=session,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
        proto=proto,
        gws=_path.load_gateways(session) if gateways is None else gateways,
        src_set=src_set,
        dst_set=dst_set,
        probe=_probe_of(src_set),
        rib=rib,
        max_hops=Settings().max_l3_hops if max_hops is None else max_hops,
        dst_instances=_dst_instances(session, dst_probe) if dst_probe else [],
        src_context=src_context,
        dst_context=dst_context,
        src_port=src_port,
        reply=reply,
    )
    # Every walk result has `left_estate` and `reach`.
    if start_table is not None:
        return _with_edge_keys(_trace_start_table(req, start_table))
    # A single host walks the physical path. A network starts at its gateway.
    single = _size(src_set) == 1
    is_host = single and "/" not in src_ip
    if reply and not is_host and single:
        refused = _check_single_address_reply(req)
        if refused is not None:
            return _with_edge_keys(refused)
    if not is_host:
        return _with_edge_keys(_trace_network_source(req))
    return _with_edge_keys(_trace_host_source(req))


def _probe_of(addrs: list[tuple[int, int, int]]) -> str:
    """The first address of an address set, as a lookup key."""
    return _to_cidrs(addrs)[0].split("/")[0]


@dataclass(frozen=True)
class _TraceRequest:
    """One trace request after its validation, pinned to one run."""

    session: Any
    src_ip: str
    dst_ip: str
    port: int | str | list[Any] | None
    proto: str | list[Any] | frozenset[int] | None
    gws: list[dict[str, Any]]
    src_set: list[tuple[int, int, int]]
    dst_set: list[tuple[int, int, int]]
    # The first address of the source, which is the key of the gateway pick.
    probe: str
    rib: Any | None
    max_hops: int
    dst_instances: list[dict[str, Any]]
    src_context: str | None
    dst_context: str | None
    src_port: int | str | list[Any] | None
    reply: bool


def _pinned_session(session: Any, settings: Settings | None = None) -> Any:
    """`session`, pinned to the current run of the pointer when it has no pin.
    `settings` is the `Settings()` of the caller when it has one already.

    Raises `NoRun` when `session` is a database session and the pointer names
    no run. The anchors of the tracer seek on obj_uid_cts at an exact run,
    and an unpinned trace reads nothing. A session that is not a database
    session (a test fake) keeps the LIVE_SNAP binding.

    A wrapper (the change-simulation `OverlaySession`, the `_OverlaySession`
    of the impact engine) counts as a database session when the session that
    it wraps is one."""
    from hst.core import snapshot as _snapshotmod

    if getattr(session, "cts", None) is not None:
        return session
    if hasattr(session, "cts"):
        if _over_database(session):
            raise _snapshotmod.NoRun()
        return session
    snapshot = _snapshotmod.resolve(session, Settings() if settings is None else settings)
    if snapshot.cts is None and _over_database(session):
        raise _snapshotmod.NoRun()
    return _path.pinned(session, snapshot)


# The maximum number of wrapper sessions that `_over_database` looks through.
# The deepest stack is an overlay over a CycleSession over a driver session.
_SESSION_WRAP_DEPTH = 8


def _over_database(session: Any) -> bool:
    """Whether `session` is a driver session or wraps one through `_session`."""
    for _ in range(_SESSION_WRAP_DEPTH):
        if isinstance(session, neo4j.Session):
            return True
        session = getattr(session, "_session", None)
        if session is None:
            return False
    return False


def _trace_with_mtu(
    session: Any,
    request: MtuRequest,
    src_ip: str,
    dst_ip: str,
    again: Any,
) -> dict[str, Any]:
    """The trace under an MTU request. `again` runs the trace again on the
    pinned session inside the scope of the request, and the result holds the
    MTU answer."""
    families = {a[0] for a in _intervals([src_ip, dst_ip])}
    if len(families) != 1:
        raise ValueError("MTU tracing requires one address family per request")
    af = next(iter(families))
    session = _pinned_session(session)
    with mtu_request(request, af):
        result = again(session)
    return ensure_result(result, request)


def _check_trace_request(
    port: Any, proto: Any, src_port: Any, start_table: str | None, src_context: str | None
) -> None:
    """Raise on a request that no walk can answer."""
    if start_table is not None and src_context is not None:
        raise ValueError("start_table and src_context cannot both be set")
    if _states_a_region(port, proto, src_port):
        # Every dimension is parsed when a range is stated, and a bad spec fails early.
        _as_protoset(_unwrap_single(proto))
        _as_portset(_unwrap_single(port))
        _as_portset(_unwrap_single(src_port))


def _trace_start_table(req: _TraceRequest, start_table: str) -> dict[str, Any]:
    """The trace from a start table (`_trace_from_table`), with its reply."""
    table_capture: dict[str, Any] = {}
    forward_table = _trace_from_table(
        req.session,
        req.src_ip,
        req.dst_ip,
        req.port,
        req.proto,
        req.gws,
        req.src_set,
        req.dst_set,
        req.probe,
        start_table,
        req.rib,
        max_hops=req.max_hops,
        dst_instances=req.dst_instances,
        dst_context=req.dst_context,
        reply_capture=table_capture,
        src_port=req.src_port,
    )
    # A start that stopped before any walk has nothing to reply to. It answers
    # in the plain shape, as the other early stops do.
    if not req.reply or not table_capture:
        return forward_table
    return _compose_bidirectional(
        req.session, forward_table, table_capture, req.src_set, req.dst_set, req.rib, max_hops=req.max_hops
    )


def _check_single_address_reply(req: _TraceRequest) -> dict[str, Any] | None:
    """Refuse a reply for a single address in more than one interpretation.

    A single address is checked here, whatever its spelling, before the
    network-scoped branch runs. Returns the answer for a context without an
    interpretation, else None.
    """
    host_sources = _source_candidates(req.session, req.probe)
    if req.src_context is not None:
        host_sources, missing = _narrow_sources(host_sources, req.src_context, req.src_ip)
        if missing:
            return missing
    if len(host_sources) > 1:
        raise ValueError(
            f"reply=True is not supported for {req.src_ip!r}: it exists in {len(host_sources)} source "
            "interpretations, and there is no single flow tuple for a reply to answer for"
        )
    return None


def _trace_network_source(req: _TraceRequest) -> dict[str, Any]:
    """The trace of a network-scoped source, from its gateway.

    The reply is derived per forward leg from the source partition and the
    recorded translations of that leg.
    """
    net_capture: dict[str, Any] = {}
    # `src_context` scopes the gateway pick to the prefixes of that context.
    if req.src_context is not None and not any(_anchor_of(g) == req.src_context for g in req.gws):
        existing = sorted({str(_anchor_of(g) or "?") for g in _containing(req.gws, req.probe)})
        return {
            "hops": [],
            "legs": [],
            "notes": [
                f"no gateway prefix is anchored on src_context {req.src_context!r}; "
                + (
                    f"the gateway prefixes containing {req.probe} are anchored on {', '.join(existing)}"
                    if existing
                    else f"no gateway prefix contains {req.probe}"
                )
            ],
            "warnings": [],
            "verdict": f"source {req.src_ip} has no gateway in context {req.src_context!r}",
        }
    forward_net = _trace_domain(
        req.session,
        req.src_ip,
        req.dst_ip,
        req.port,
        req.proto,
        req.gws,
        req.src_set,
        req.dst_set,
        req.probe,
        None,
        req.src_context,
        req.rib,
        max_hops=req.max_hops,
        dst_instances=req.dst_instances,
        dst_context=req.dst_context,
        reply_capture=net_capture,
        src_port=req.src_port,
    )
    if not req.reply:
        return forward_net
    return _compose_bidirectional(
        req.session, forward_net, net_capture, req.src_set, req.dst_set, req.rib, max_hops=req.max_hops
    )


def _trace_host_source(req: _TraceRequest) -> dict[str, Any]:
    """The trace of a single host, over every source interpretation that it has."""
    sources = _source_candidates(req.session, req.probe)
    if not sources:
        return {
            "hops": [],
            "legs": [],
            "notes": [],
            "warnings": [],
            "verdict": f"source {req.src_ip} is not in the graph",
        }
    if req.src_context is not None:
        sources, missing = _narrow_sources(sources, req.src_context, req.src_ip)
        if missing:
            return missing
    if len(sources) == 1:
        src = sources[0]
        # The capture is filled in whatever the value of `reply`.
        capture: dict[str, Any] = {}
        forward = _trace_domain(
            req.session,
            req.src_ip,
            req.dst_ip,
            req.port,
            req.proto,
            req.gws,
            req.src_set,
            req.dst_set,
            req.probe,
            src,
            _anchor_of(src),
            req.rib,
            max_hops=req.max_hops,
            dst_instances=req.dst_instances,
            dst_context=req.dst_context,
            reply_capture=capture,
            src_port=req.src_port,
        )
        if not req.reply:
            return forward
        return _compose_bidirectional(
            req.session, forward, capture, req.src_set, req.dst_set, req.rib, max_hops=req.max_hops
        )
    if req.reply:
        raise ValueError(
            f"reply=True is not supported for {req.src_ip!r}: it exists in {len(sources)} source "
            "interpretations, and there is no single flow tuple for a reply to answer for"
        )
    return _trace_interpretations(
        req.session,
        req.src_ip,
        req.dst_ip,
        req.port,
        req.proto,
        req.gws,
        req.src_set,
        req.dst_set,
        req.probe,
        sources,
        req.rib,
        req.dst_instances,
        req.dst_context,
        max_hops=req.max_hops,
        src_port=req.src_port,
    )
