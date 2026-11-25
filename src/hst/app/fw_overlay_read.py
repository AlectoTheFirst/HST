"""The graph read and the trace comparison behind the policy change overlay."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from typing import Any, NamedTuple

from hst import path as pathmod
from hst.app import simul_read
from hst.core import mtu_read
from hst.core.mtu import MtuRequest
from hst.path.addrsets import _intersect, _intervals
from hst.results.trace import flow_side_result
from hst.simul import rib as ribmod
from hst.simul.errors import ErrorSink
from hst.simul.fw_overlay import (
    _GROUP_DEPTH,
    FW_KINDS,
    INTERFACE_KINDS,
    NAT_KINDS,
    ROUTING_KINDS,
    ZONE_KINDS,
    ZONE_OF_INTERFACE,
    ZONE_PAIR_RULEBASES,
    Catalog,
    ChangeSet,
    DeniedAddresses,
    Intent,
    ProposalError,
    _address_side,
    compare_paths,
    pair_paths,
    parse_intents,
    path_rows,
)

# --- object catalog -------------------------------------------------------

# NetObject with its direct addresses and its direct group members, for the
# objects whose uid is in $uids or whose name is in $names. Each side is a
# pattern comprehension. The nesting is closed in Python
# (`Catalog.net_addresses`), and the depth bound cuts a membership cycle.
# `read_catalog` asks for the members of each round in the next round, up to
# `_GROUP_DEPTH`.
_NET_OBJECTS = """
MATCH (o:NetObject:Obj)
WHERE NOT o:Retired AND o.collection_ts = $snap AND (o.uid IN $uids OR o.name IN $names)
RETURN o.uid AS uid, o.name AS name, o.ranges AS ranges,
       coalesce(o.opaque, false) AS opaque, o.opaque_reason AS opaque_reason,
       [(o)-[rt:RESOLVES_TO]->(t) WHERE rt._retired_at IS NULL AND NOT t:Retired
        | coalesce(t.cidr, t.ip)] AS addrs,
       [(o)<-[mo:MEMBER_OF]-(m:NetObject) WHERE mo._retired_at IS NULL AND NOT m:Retired
        | m.uid] AS members"""

# The member rounds of `_read_objects` look up members by uid only. Their
# text has no `name` disjunct and seeks on obj_uid_cts.
_NET_MEMBERS = _NET_OBJECTS.replace("(o.uid IN $uids OR o.name IN $names)", "o.uid IN $uids")

# The same for SvcObject. A Check Point service-group has no protocol or port
# of its own. It has only MEMBER_OF edges from its members. `opaque` marks an
# object that the collector could not state as a protocol and port. `src_port`
# marks an object scoped to a source port. A member of any other label is
# listed too. `Catalog.svc_pairs` refuses a group that holds such a member.
_SVC_OBJECTS = """
MATCH (s:SvcObject:Obj)
WHERE NOT s:Retired AND s.collection_ts = $snap AND (s.uid IN $uids OR s.name IN $names)
RETURN s.uid AS uid, s.name AS name, s.proto AS proto, s.ports AS ports, s.src_port AS src_port,
       coalesce(s.opaque, false) AS opaque, s.opaque_reason AS opaque_reason,
       [(s)<-[mo:MEMBER_OF]-(m) WHERE mo._retired_at IS NULL AND NOT m:Retired | m.uid] AS members"""
_SVC_MEMBERS = _SVC_OBJECTS.replace("(s.uid IN $uids OR s.name IN $names)", "s.uid IN $uids")

_DEVICE_HOSTNAMES = """
MATCH (d:Device:Obj) WHERE d.uid IN $uids AND NOT d:Retired AND d.collection_ts = $snap
RETURN d.uid AS uid, d.hostname AS hostname"""

_ZONES = """
MATCH (z:Zone:Obj)
WHERE NOT z:Retired AND z.collection_ts = $snap AND (z.uid IN $uids OR z.name IN $names)
OPTIONAL MATCH (z)-[c:CONTAINS]->(i:Interface)
WHERE c._retired_at IS NULL AND NOT i:Retired
RETURN z.uid AS uid, z.name AS name,
       z.default_action AS default_action, z.default_action_unknown AS default_action_unknown,
       z.established_default_unknown AS established_default_unknown,
       z.intra_zone_filtering AS intra_zone_filtering, z.intra_zone_action AS intra_zone_action,
       collect(DISTINCT i.name) AS interface_names,
       collect(DISTINCT i.uid) AS interface_uids"""

# The facts of one Interface that `interface.set_mtu` validation needs, for the
# uids that an `interface.*` intent names. The row holds the Device (`vendor`,
# `platform` and `os_version`, for `hst.simul.fw_overlay._platform_kind`), the
# `_sources` of the Device and the Cisco parent linkage that a collector writes
# as an Interface property (`hst.collectors.cisco_common`). It also holds the
# physical Port that a `REALIZED_BY` edge pairs with the interface, if there is
# one. A VyOS or Cisco frame-ceiling row derived from the MTU of the interface
# sits on that Port.
_INTERFACE_MTU_FACTS = """
UNWIND $uids AS iface_uid
MATCH (i:Interface:Obj {uid: iface_uid, collection_ts: $snap})
WHERE NOT i:Retired AND i._retired_at IS NULL
OPTIONAL MATCH (i)-[o:ON]->(d:Device {collection_ts: $snap})
WHERE o._retired_at IS NULL AND NOT d:Retired
OPTIONAL MATCH (i)-[rb:REALIZED_BY]->(p:Port {collection_ts: $snap})
WHERE rb._retired_at IS NULL AND NOT p:Retired
RETURN i.uid AS uid, i.name AS name,
       i.parent_interface_uid AS parent_interface_uid,
       i.parent_source_command AS parent_source_command,
       i.mtu_source AS mtu_source,
       d.uid AS device_uid, d.vendor AS vendor, d.platform AS platform, d.os_version AS os_version,
       d._sources AS device_sources,
       p.uid AS port_uid
ORDER BY uid
LIMIT $row_limit"""

# The most interfaces that the `interface.*` intents of one change set name.
_MAX_MTU_INTERFACES = 64

# The BGP peerings of the routing follow-on, matched against the address sets
# that the change denies. The match uses the `ip`-valued property. One address
# exists as one IpAddress node per anchor.
_BGP_PEERS = """
MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj)
WHERE NOT rp:Retired AND NOT b:Retired AND h._retired_at IS NULL
  AND b.collection_ts = $snap AND b.peer_ip IS NOT NULL
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
RETURN b.uid AS uid, b.peer_ip AS peer_ip, b.peer_asn AS peer_asn, b.local_asn AS local_asn,
       rp.uid AS process_uid, v.uid AS context_uid
ORDER BY b.uid"""

# The recorded route edges with a next hop. The read returns every route of a
# prefix that holds a denied next hop, and no other prefix. `$hits` holds the
# next hops that the change denies. They are read first (`_NEXT_HOP_VALUES`)
# and tested in Python. `$hits` is null for a read of a whole VRF
# (`$context`). The walk past the first level reads each VRF in which it
# stranded a prefix this way. `$prefixes` narrows the read to the given
# prefixes. These are the prefixes that a side-store route denies and no graph
# row denies. The graph rows of such a prefix are part of its table too. The
# graph mirrors a routing table only up to `rib_graph_max_routes` routes
# (core/config.py). A larger table is only in the RIB side store. `_RouteTable`
# reads the side store through the RibSource. The query returns the `protocol`
# property and does not filter on it.
_LEARNED_NEXT_HOPS = """
MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)
WHERE NOT v:Retired AND NOT p:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $snap AND r.next_hop IS NOT NULL
  AND ($context IS NULL OR v.uid = $context) AND ($hits IS NULL OR r.next_hop IN $hits)
  AND ($prefixes IS NULL OR p.cidr IN $prefixes)
WITH DISTINCT v, p
MATCH (v)-[e:LEARNED_ROUTE|STATIC_ROUTE]->(p)
WHERE e._retired_at IS NULL AND e.next_hop IS NOT NULL
RETURN type(e) AS kind, p.cidr AS prefix, e.next_hop AS next_hop, e.protocol AS protocol,
       e.interface AS interface, e.metric AS metric, v.uid AS context_uid
ORDER BY prefix, context_uid"""

# The distinct next hops the route edges record, and the VRFs that record a
# route edge.
_NEXT_HOP_VALUES = """
MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)
WHERE NOT v:Retired AND NOT p:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $snap AND r.next_hop IS NOT NULL
RETURN DISTINCT r.next_hop AS next_hop"""

_ROUTE_CONTEXTS = """
MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)
WHERE NOT v:Retired AND NOT p:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $snap AND r.next_hop IS NOT NULL
RETURN DISTINCT v.uid AS context_uid"""

# The devices a changed rulebase is bound to, and the device an interface named
# in a zone move sits on.
#
# The query reads every edge that binds a rulebase to an enforcement point in
# one read. `vyos.py` writes `ENFORCES` for filter chains only. A named ruleset
# acts where a zone pair binds it. A zone-pair rulebase reaches its device
# through FROM_ZONE or TO_ZONE. A cloud SG or NSG rulebase reaches it through
# PROTECTED_BY. A cluster policy reaches it through the group that the members
# belong to. An FGT VDOM policy reaches it through the interfaces of the VRF. A
# Check Point inline layer reaches it through the rule that jumps to it.
_RULEBASE_DEVICES = """
MATCH (d:Device)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
WHERE NOT d:Retired AND NOT rb:Retired AND e._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
UNION
MATCH (d:Device)
      -[m:MEMBER_OF]->(g:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
WHERE NOT d:Retired AND NOT g:Retired AND NOT rb:Retired
  AND m._retired_at IS NULL AND e._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
UNION
MATCH (v:VrfInstance)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[o:ON]->(d:Device)
WHERE NOT v:Retired AND NOT i:Retired AND NOT d:Retired AND NOT rb:Retired
  AND e._retired_at IS NULL AND iv._retired_at IS NULL AND o._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
UNION
MATCH (rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
      -[z:FROM_ZONE|TO_ZONE]->(zn:Zone)-[c:CONTAINS]->(i:Interface)
MATCH (i)-[o:ON]->(d:Device)
WHERE NOT rb:Retired AND NOT zn:Retired AND NOT i:Retired AND NOT d:Retired
  AND z._retired_at IS NULL AND c._retired_at IS NULL AND o._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
UNION
MATCH (rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
      -[hr:HAS_RULE]->(r:FwRule)-[z:FROM_ZONE|TO_ZONE]->(zn:Zone)
MATCH (zn)-[c:CONTAINS]->(i:Interface)-[o:ON]->(d:Device)
WHERE NOT rb:Retired AND NOT r:Retired AND NOT zn:Retired AND NOT i:Retired AND NOT d:Retired
  AND hr._retired_at IS NULL AND z._retired_at IS NULL AND c._retired_at IS NULL
  AND o._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
UNION
MATCH (x)-[p:PROTECTED_BY]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
MATCH (x)-[o:ON]->(d:Device)
WHERE NOT x:Retired AND NOT d:Retired AND NOT rb:Retired
  AND p._retired_at IS NULL AND o._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
UNION
MATCH (parent:FwRulebase)-[hr:HAS_RULE]->(r:FwRule)
      -[j:JUMPS_TO]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})
MATCH (d:Device)-[e:ENFORCES]->(parent)
WHERE NOT parent:Retired AND NOT r:Retired AND NOT rb:Retired AND NOT d:Retired
  AND hr._retired_at IS NULL AND j._retired_at IS NULL AND e._retired_at IS NULL
RETURN DISTINCT d.uid AS uid"""

_INTERFACE_DEVICE = """
MATCH (i:Interface:Obj {uid: $iface, collection_ts: $snap})-[o:ON]->(d:Device)
WHERE NOT i:Retired AND NOT d:Retired AND o._retired_at IS NULL
RETURN DISTINCT d.uid AS uid
ORDER BY uid"""

# The forwarding context that a routing intent names, and the devices that the
# context sits on. `_SESSION_CONTEXT` reads the VRF of the process that owns a
# BgpSession. `_OSPF_ROUTER_CONTEXTS` reads the VRF of every OSPF process with
# a router id. Both scope the integrated routing calculation
# (`_bgp_prediction`).
_SESSION_CONTEXT = """
MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj {uid: $sess, collection_ts: $snap})
WHERE NOT rp:Retired AND NOT b:Retired AND h._retired_at IS NULL
MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
OPTIONAL MATCH (v)<-[iv2:IN_VRF]-(i:Interface)-[o:ON]->(d:Device)
WHERE iv2._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
RETURN v.uid AS context_uid, collect(DISTINCT d.uid) AS device_uids
ORDER BY context_uid"""

_OSPF_ROUTER_CONTEXTS = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE toLower(coalesce(rp.proto, '')) = 'ospf' AND rp.router_id = $rid
  AND NOT rp:Retired AND NOT v:Retired AND iv._retired_at IS NULL
  AND rp.collection_ts = $snap
OPTIONAL MATCH (v)<-[iv2:IN_VRF]-(i:Interface)-[o:ON]->(d:Device)
WHERE iv2._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
RETURN v.uid AS context_uid, collect(DISTINCT d.uid) AS device_uids
ORDER BY context_uid"""

# The inverse of `_RULEBASE_DEVICES`. The query reads every rulebase that one
# device is bound to, through the same binding edges in the other direction.
#
# `binding` describes the edge chain. `side` is FROM_ZONE or TO_ZONE for a
# zone-scoped binding and null for any other binding. `iface` is the interface
# through which the binding reaches the device, if there is one. A zone-scoped
# binding governs one direction. The FROM_ZONE side decides a source-side deny.
# A binding without a zone governs both directions. A binding without an
# interface governs the whole device.
_DEVICE_RULEBASES = """
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})-[e:ENFORCES]->(rb:FwRulebase)
WHERE NOT d:Retired AND NOT rb:Retired AND e._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'the device ENFORCES it' AS binding, NULL AS side, NULL AS iface
UNION
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})
      -[m:MEMBER_OF]->(g:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase)
WHERE NOT d:Retired AND NOT g:Retired AND NOT rb:Retired
  AND m._retired_at IS NULL AND e._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'a RedundancyGroup the device belongs to ENFORCES it' AS binding, NULL AS side, NULL AS iface
UNION
MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)-[e:ENFORCES]->(rb:FwRulebase)
WHERE NOT i:Retired AND NOT d:Retired AND NOT v:Retired AND NOT rb:Retired
  AND o._retired_at IS NULL AND iv._retired_at IS NULL AND e._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'a VrfInstance on the device ENFORCES it' AS binding, NULL AS side, i.uid AS iface
UNION
MATCH (rb:FwRulebase:Obj {collection_ts: $snap})-[z:FROM_ZONE|TO_ZONE]->(zn:Zone)-[c:CONTAINS]->(i:Interface)
MATCH (i)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT rb:Retired AND NOT zn:Retired AND NOT i:Retired AND NOT d:Retired
  AND z._retired_at IS NULL AND c._retired_at IS NULL AND o._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'a zone pair binds it to an interface on the device' AS binding,
       type(z) AS side, i.uid AS iface
UNION
MATCH (rb:FwRulebase:Obj {collection_ts: $snap})-[hr:HAS_RULE]->(r:FwRule)-[z:FROM_ZONE|TO_ZONE]->(zn:Zone)
MATCH (zn)-[c:CONTAINS]->(i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT rb:Retired AND NOT r:Retired AND NOT zn:Retired AND NOT i:Retired AND NOT d:Retired
  AND hr._retired_at IS NULL AND z._retired_at IS NULL AND c._retired_at IS NULL
  AND o._retired_at IS NULL AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'one of its rules matches on a zone holding an interface on the device' AS binding,
       type(z) AS side, i.uid AS iface
UNION
MATCH (x)-[p:PROTECTED_BY]->(rb:FwRulebase:Obj {collection_ts: $snap})
MATCH (x)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT x:Retired AND NOT d:Retired AND NOT rb:Retired
  AND p._retired_at IS NULL AND o._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'an object on the device is PROTECTED_BY it' AS binding, NULL AS side,
       CASE WHEN x:Interface THEN x.uid ELSE NULL END AS iface
UNION
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})-[e:ENFORCES]->(parent:FwRulebase)
      -[hr:HAS_RULE]->(r:FwRule)
MATCH (r)-[j:JUMPS_TO]->(rb:FwRulebase)
WHERE NOT d:Retired AND NOT parent:Retired AND NOT r:Retired AND NOT rb:Retired
  AND e._retired_at IS NULL AND hr._retired_at IS NULL AND j._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name,
       'a rulebase the device enforces JUMPS_TO it' AS binding, NULL AS side, NULL AS iface"""

# The addresses that each interface on a device serves. The schema records an
# address behind an interface in 3 ways. These are the connected prefix of the
# address of the interface, the endpoints on the bridge domain that its VLAN
# realizes, and the endpoints attached to the interface. `hst.path.addrsets`
# does the containment test.
_DEVICE_SERVED_ADDRESSES = """
MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT i:Retired AND NOT d:Retired AND o._retired_at IS NULL
  AND i.collection_ts = $snap
OPTIONAL MATCH (i)-[hi:HAS_IP]->(ia:IpAddress)-[inp:IN]->(p:Prefix)
WHERE hi._retired_at IS NULL AND inp._retired_at IS NULL AND NOT ia:Retired AND NOT p:Retired
OPTIONAL MATCH (i)-[bt:BOUND_TO]->(vl:VlanInstance)-[rz:REALIZES]->(bd)<-[ein:IN]-(ep:Endpoint)
              -[eh:HAS_IP]->(eia:IpAddress)
WHERE bt._retired_at IS NULL AND rz._retired_at IS NULL AND ein._retired_at IS NULL
  AND eh._retired_at IS NULL AND (bd:BridgeDomain OR bd:L2Segment)
  AND NOT ep:Retired AND NOT eia:Retired
OPTIONAL MATCH (ae:Endpoint)-[at:ATTACHED]->(i)
WHERE at._retired_at IS NULL AND NOT ae:Retired
OPTIONAL MATCH (ae)-[ah:HAS_IP]->(aia:IpAddress)
WHERE ah._retired_at IS NULL AND NOT aia:Retired
RETURN i.uid AS uid, i.name AS name,
       collect(DISTINCT p.cidr) AS prefixes,
       collect(DISTINCT eia.ip) AS bridge_domain_ips,
       collect(DISTINCT aia.ip) AS attached_ips
ORDER BY uid"""

# The sites that the snapshot holds, and the sites that each VRF sits in. A
# VrfInstance has no Device edge. The sites of a VRF are the sites of the
# devices that its interfaces are on.
_SITES = """
MATCH (s:Site:Obj)
WHERE NOT s:Retired AND (s:Meta OR s.collection_ts = $snap)
RETURN s.uid AS uid, s.code AS code, s.name AS name
ORDER BY s.uid"""

_VRF_SITES = """
MATCH (v:VrfInstance:Obj)<-[iv:IN_VRF]-(i:Interface)-[o:ON]->(d:Device)-[li:LOCATED_IN]->(s:Site)
WHERE NOT v:Retired AND NOT i:Retired AND NOT d:Retired AND NOT s:Retired
  AND iv._retired_at IS NULL AND o._retired_at IS NULL AND li._retired_at IS NULL
  AND v.collection_ts = $snap
RETURN v.uid AS context_uid, collect(DISTINCT s.uid) AS site_uids
ORDER BY context_uid"""

# The device each VRF is placed on by its interfaces, for the side-store merge
# (`_RouteTable`).
_VRF_DEVICES = """
MATCH (v:VrfInstance:Obj)<-[iv:IN_VRF]-(i:Interface)-[o:ON]->(d:Device)
WHERE NOT v:Retired AND NOT i:Retired AND NOT d:Retired
  AND iv._retired_at IS NULL AND o._retired_at IS NULL
  AND v.collection_ts = $snap
RETURN DISTINCT v.uid AS context_uid, v.name AS vrf_name, d.uid AS device_uid
ORDER BY context_uid"""

_MAX_ROUTE_ROWS = 50

# The hard cap on how far the next-hop withdrawal follows the route dependency
# chain.
_MAX_WITHDRAWAL_DEPTH = 8

_DEFAULT_WITHDRAWAL_DEPTH = 1

_LEVEL_SAMPLE = 5

# The most out-of-scope VRFs that the site boundary report lists.
_MAX_BOUNDARY_VRFS = 10

# How many flows are derived from the change set when the caller supplies none.
_MAX_DERIVED_FLOWS = 8

# The IPv4 default route (`_default_route`).
_DEFAULT_ROUTE = "0.0.0.0/0"


def _mtu_intent_interfaces(intents: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return the interface uids that the `interface.*` intents name, deduplicated
    and sorted. The list keeps the lowest `_MAX_MTU_INTERFACES` uids."""
    uids: set[str] = set()
    for raw in intents or ():
        kind = str((raw or {}).get("kind", "")).strip()
        if kind not in INTERFACE_KINDS:
            continue
        iface = (raw.get("params") or {}).get("interface")
        if iface:
            uids.add(str(iface))
    return sorted(uids)[:_MAX_MTU_INTERFACES]


def _vyos_parent_selector(observations: Sequence[Any]) -> tuple[str | None, int | None]:
    """Return the `parent_subject_uid` and the `configured_tag_depth` of a VyOS vif.

    The values come from the first MTU observation whose selector holds one of
    them (`hst.collectors.vyos` selector context). Every observation that one
    `_mtu_stage` pass of an interface emits has the same selector context."""
    for obs in observations:
        try:
            selector = json.loads(obs.selector_json)
        except (TypeError, ValueError, AttributeError):
            continue
        if not isinstance(selector, dict):
            continue
        parent = selector.get("parent_subject_uid")
        depth = selector.get("configured_tag_depth")
        if parent or depth is not None:
            return (str(parent) if parent else None, depth if isinstance(depth, int) else None)
    return None, None


def _read_interface_mtu_facts(
    session: Any, intents: Sequence[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Read `Catalog.interfaces`, the Interface and Device facts and the MTU
    evidence that `interface.set_mtu` validation and the overlay need.

    The result holds the interfaces that an `interface.*` intent names and the
    MTU parent of each of them. The MTU parent is the `parent_subject_uid` of a
    VyOS vif or the `parent_interface_uid` of a Cisco subinterface.

    The named interfaces are read first, then their unresolved parents. Each of
    the 2 batches runs `_INTERFACE_MTU_FACTS` for the Interface, Device and Port
    facts and `hst.core.mtu_read.read_mtu` for the MTU evidence.
    """
    uids = _mtu_intent_interfaces(intents)
    if not uids:
        return {}
    facts: dict[str, dict[str, Any]] = {}

    def fetch(batch: list[str]) -> None:
        rows = pathmod._read(session, _INTERFACE_MTU_FACTS, uids=batch, row_limit=_MAX_MTU_INTERFACES)
        for row in rows:
            uid_ = str(row["uid"])
            facts[uid_] = {
                "uid": uid_,
                "name": row.get("name"),
                "device_uid": row.get("device_uid"),
                "vendor": row.get("vendor"),
                "platform": row.get("platform"),
                "os_version": row.get("os_version"),
                "device_sources": row.get("device_sources"),
                "parent_interface_uid": str(row["parent_interface_uid"])
                if row.get("parent_interface_uid")
                else None,
                "parent_source_command": row.get("parent_source_command"),
                "mtu_source": row.get("mtu_source"),
                "port_uid": str(row["port_uid"]) if row.get("port_uid") else None,
            }
        evidence = mtu_read.read_mtu(session, batch)
        for uid_, obs_list in evidence.by_subject.items():
            if uid_ in facts:
                facts[uid_]["observations"] = list(obs_list)

    fetch(uids)

    parent_uids: set[str] = set()
    for uid_ in uids:
        fact = facts.get(uid_)
        if fact is None:
            continue
        vyos_parent, tag_depth = _vyos_parent_selector(fact.get("observations") or ())
        fact["configured_tag_depth"] = tag_depth
        parent = fact.get("parent_interface_uid") or vyos_parent
        fact["parent_uid"] = parent
        if parent and parent not in facts:
            parent_uids.add(parent)

    if parent_uids:
        fetch(sorted(parent_uids)[:_MAX_MTU_INTERFACES])
    return facts


def _intent_tokens(value: Any) -> set[str]:
    """Return every string in the parameters of an intent, at any depth. A
    parameter that names an object (an address side, a service, a zone, a NAT
    original or translated side) is among them for every key."""
    if isinstance(value, str):
        text = value.strip()
        return {text} if text else set()
    if isinstance(value, Mapping):
        return set().union(*(_intent_tokens(v) for v in value.values())) if value else set()
    if isinstance(value, Iterable):
        return set().union(*(_intent_tokens(v) for v in value)) if value else set()
    return set()


def _read_objects(
    session: Any, query: str, member_query: str, tokens: Collection[str], depth: int
) -> dict[str, dict[str, Any]]:
    """Return the object rows by uid, in `depth` rounds at most.

    The first round runs `query` for the objects that `tokens` name, by uid or
    by name. Each later round runs `member_query` by uid for the new members
    that the previous round returned. A member uid that no round returns is
    absent from the result."""
    rows: dict[str, dict[str, Any]] = {}
    asked: set[str] = set(tokens)
    uids = sorted(tokens)
    for round_ in range(depth):
        if not uids:
            break
        if round_ == 0:
            found = pathmod._read(session, query, uids=uids, names=uids)
        else:
            found = pathmod._read(session, member_query, uids=uids)
        members: set[str] = set()
        for row in found:
            rows[str(row["uid"])] = row
            members.update(str(m) for m in (row.get("members") or ()) if m)
        uids = sorted(members - asked)
        asked.update(uids)
    return rows


def read_catalog(
    session: Any,
    intents: Sequence[Mapping[str, Any]] = (),
    source_kinds: Mapping[str, str] | None = None,
) -> Catalog:
    """Read the NetObject, SvcObject and Zone objects that the intents in
    `intents` name, as plain dicts, and the Interface facts
    (`Catalog.interfaces`) for `interface.set_mtu` validation and the overlay.

    Only the objects that an intent states are read. The members of each group
    are read one round at a time, up to `_GROUP_DEPTH` (`_read_objects`). A
    token that parses as an address, a prefix or a range is not looked up.

    `source_kinds` maps the name of each configured source of the twin to its
    collector kind (`hst.app.store.Source.name` to `.type`). It is copied to
    `Catalog.source_kinds` unchanged. With `None`, `_validate_interface_set_mtu`
    reports the collected-source check of a device as not checked.
    """
    tokens: set[str] = set()
    for intent in intents:
        tokens |= _intent_tokens(intent.get("params") or {})
    net_tokens = {t for t in tokens if t.lower() != "any" and not _intervals([t])}
    depth = _GROUP_DEPTH + 1

    net: dict[str, dict[str, Any]] = {}
    for uid_, row in _read_objects(session, _NET_OBJECTS, _NET_MEMBERS, net_tokens, depth).items():
        addrs = [str(a) for a in (row.get("addrs") or ()) if a]
        # `NetObject.ranges` holds the ranges and the values of an object that
        # the loader could not resolve to a node.
        addrs += [str(r) for r in (row.get("ranges") or ()) if r]
        net[uid_] = {
            "uid": uid_,
            "name": row.get("name"),
            "addrs": addrs,
            "members": [str(m) for m in (row.get("members") or ()) if m],
            "opaque": bool(row.get("opaque")),
            "opaque_reason": row.get("opaque_reason"),
        }

    svc: dict[str, dict[str, Any]] = {}
    for uid_, row in _read_objects(session, _SVC_OBJECTS, _SVC_MEMBERS, tokens, depth).items():
        ports = row.get("ports")
        svc[uid_] = {
            "uid": uid_,
            "name": row.get("name"),
            "protos": [str(row["proto"])] if row.get("proto") else [],
            "ports": [str(p) for p in (ports if isinstance(ports, list) else [ports]) if p],
            "src_port": str(row["src_port"]) if row.get("src_port") else None,
            "opaque": bool(row.get("opaque")),
            "opaque_reason": row.get("opaque_reason"),
            "members": [str(m) for m in (row.get("members") or ()) if m],
        }

    zones: dict[str, dict[str, Any]] = {}
    for row in pathmod._read(session, _ZONES, uids=sorted(tokens), names=sorted(tokens)) if tokens else ():
        zones[str(row["uid"])] = {
            "uid": str(row["uid"]),
            "name": row.get("name"),
            "default_action": row.get("default_action"),
            "default_action_unknown": row.get("default_action_unknown"),
            # The collection does not report the connection-state rules of the
            # zone. The tracer decides a reply into such a zone as undecided at
            # fall-through (`gates.firewall._state_rules_unreported`).
            "established_default_unknown": row.get("established_default_unknown"),
            # what decides traffic within the zone (`gates.firewall._intra_zone_verdict`)
            "intra_zone_filtering": row.get("intra_zone_filtering"),
            "intra_zone_action": row.get("intra_zone_action"),
            "interfaces": [str(n) for n in (row.get("interface_names") or ()) if n],
            "interface_uids": [str(u) for u in (row.get("interface_uids") or ()) if u],
        }

    interfaces = _read_interface_mtu_facts(session, intents)
    return Catalog(
        net_objects=net,
        svc_objects=svc,
        zones=zones,
        interfaces=interfaces,
        source_kinds=dict(source_kinds) if source_kinds is not None else None,
    )


# --- the overlaid session -------------------------------------------------


class OverlaySession:
    """A pinned session whose reads come back with the change set applied.

    The class is duck-typed on `CycleSession`. The tracer uses `cts` for the
    `$snap` binding and `execute_read` for the transaction. `overlay` is the
    hook that `path.session._read` calls with every query, its parameters and
    its rows.

    A zone move needs 2 supplementary reads through the same session. `_depth`
    keeps these reads out of the hook.
    """

    def __init__(self, session: Any, changes: ChangeSet) -> None:
        self._session = session
        self.cts = getattr(session, "cts", None)
        self._changes = changes
        self._depth = 0
        self._zone_cache: dict[str, str | None] = {}
        changes.zone_of = self._zone_of
        changes.pair_rows = self._pair_rows

    def execute_read(self, work: Any, /) -> Any:
        return self._session.execute_read(work)

    @property
    def _read_cache(self) -> dict[Any, Any] | None:
        """The read cache of the inner session. `path.session._read` stores raw
        rows below the overlay. This session, the session it wraps and the `_raw`
        reads share the cache."""
        return getattr(self._session, "_read_cache", None)

    def overlay(self, query: str, params: dict[str, Any], rows: Any) -> Any:
        if self._depth:
            return rows
        return self._changes.rewrite(query, params, rows)

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


# --- the answer -----------------------------------------------------------


def _flow_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Reduce one trace to the fields of a before and after comparison.

    The summary holds the result, the prose of the tracer as `detail`, the
    indeterminate flag, the firewall decision of each leg and every warning. It
    holds no hops.
    """
    legs = result.get("legs") or []
    side = {
        "detail": result.get("verdict"),
        "indeterminate": bool(result.get("indeterminate")),
        "blocked": any(leg.get("blocked") for leg in legs),
        "decided_by": [leg["firewall"] for leg in legs if leg.get("firewall")],
        # Every destination translation of every leg, in leg order and then in
        # the upstream-first order of the leg. Each entry holds the address view
        # on which the filter of its device was evaluated.
        "dnat": [d for leg in legs for d in (leg.get("dnat") or [])],
        "snat": [leg["snat"] for leg in legs if leg.get("snat")],
        "warnings": list(result.get("warnings") or ()),
    }
    side["result"] = flow_side_result(side).model_dump(mode="json")
    if "reach" in result:
        # The ends of the paths of the trace. `result_changed` does not compare them.
        side["reach"] = result.get("reach")
        side["left_estate"] = list(result.get("left_estate") or ())
    return side


def _trace_flow(
    session: Any,
    flow: dict[str, Any],
    rib: Any | None = None,
    gateways: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Trace one flow with the MTU request validation of `GET /api/path`
    (`hst.app.routes.path`).

    `flow["mtu"]` is `{mode, ip_packet_bytes, ipv4_df, traffic_class}`.
    `MtuRequest.model_validate` validates it. A request whose mode is not
    `"off"` goes to `hst.path.trace` as the `mtu` argument. A malformed request
    raises a `ProposalError`.

    `gateways` is the gateway load of the estate (`hst.path.load_gateways`).
    """
    port = flow.get("port")
    kwargs: dict[str, Any] = {}
    mtu_raw = flow.get("mtu")
    if not mtu_raw:
        return pathmod.trace(
            session,
            str(flow["src"]),
            str(flow["dst"]),
            port=None if port in (None, "") else int(port),
            proto=str(flow.get("proto") or "tcp"),
            rib=rib,
            gateways=gateways,
        )
    try:
        mtu_request = MtuRequest.model_validate(mtu_raw)
        if mtu_request.mode != "off":
            kwargs["mtu"] = mtu_request
        return pathmod.trace(
            session,
            str(flow["src"]),
            str(flow["dst"]),
            port=None if port in (None, "") else int(port),
            proto=str(flow.get("proto") or "tcp"),
            rib=rib,
            gateways=gateways,
            **kwargs,
        )
    except ValueError as exc:
        raise ProposalError(f"flow {flow.get('src')} -> {flow.get('dst')}: {exc}") from exc


# --- the next-hop withdrawal ----------------------------------------------


def _withdrawn_because(row: dict[str, Any], denied: DeniedAddresses) -> str | None:
    """Return why the next hop of this route edge stops being usable, or None if
    it stays usable.

    A destination-side deny removes the address as a next hop for any recorded
    route. A source-side deny removes it for a `LEARNED_ROUTE` only. The
    `protocol` property is not read.
    """
    next_hop = str(row.get("next_hop") or "").strip()
    if not next_hop:
        return None
    where = _intervals([next_hop])
    if not where:
        return None
    if _intersect(where, denied.to_set):
        return "the change denies traffic to this next hop, so it cannot be forwarded through"
    if str(row.get("kind") or "") == "LEARNED_ROUTE" and _intersect(where, denied.from_set):
        return (
            "the change denies traffic from this next hop, so the exchange that put this "
            "learned route in the table does not hold"
        )
    return None


def _next_hop_entry(row: dict[str, Any], because: str | None) -> dict[str, Any]:
    """One recorded next hop, as a before-and-after table row."""
    entry: dict[str, Any] = {
        "next_hop": str(row.get("next_hop") or ""),
        "kind": str(row.get("kind") or ""),
        "protocol": row.get("protocol"),
        "interface": row.get("interface"),
        "metric": row.get("metric"),
    }
    if because:
        entry["withdrawn_because"] = because
    return entry


def _static_route_kept(row: dict[str, Any], denied: DeniedAddresses) -> bool:
    """Return whether the row is a `STATIC_ROUTE` whose next hop is denied as a
    source only.

    A source-side deny does not withdraw a locally configured route.
    """
    if str(row.get("kind") or "") != "STATIC_ROUTE":
        return False
    where = _intervals([str(row.get("next_hop") or "").strip()])
    if not where or _intersect(where, denied.to_set):
        return False
    return bool(_intersect(where, denied.from_set))


# --- how far and where the withdrawal is followed -------------------------


def _normalize_depth(depth: Any) -> tuple[int, int]:
    """Return the depth that the caller asked for and the depth of the walk.

    A depth below 1 raises a `ProposalError`. A depth above
    `_MAX_WITHDRAWAL_DEPTH` runs at `_MAX_WITHDRAWAL_DEPTH`.
    """
    if depth is None:
        return _DEFAULT_WITHDRAWAL_DEPTH, _DEFAULT_WITHDRAWAL_DEPTH
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise ProposalError("depth must be a whole number of levels, 1 or more")
    if depth < 1:
        raise ProposalError("depth must be 1 or more")
    return depth, min(depth, _MAX_WITHDRAWAL_DEPTH)


class _PrefixIndex:
    """The prefixes of the recorded table of one VRF, looked up by the addresses
    that they hold.

    A prefix holds an address when the interval of the address lies inside the
    interval of the prefix (`_intervals`). The index does one lookup per block
    size of the table. Each range that is not an aligned block is tested
    separately.
    """

    def __init__(self, prefixes: Iterable[str]) -> None:
        self._blocks: dict[tuple[int, int], dict[int, list[str]]] = {}
        self._others: list[tuple[int, int, int, str]] = []
        self._covering: dict[str, frozenset[str]] = {}
        for prefix in prefixes:
            for version, lo, hi in _intervals([prefix]):
                size = hi - lo + 1
                if size & (size - 1) == 0 and lo % size == 0:
                    self._blocks.setdefault((version, size), {}).setdefault(lo, []).append(prefix)
                else:
                    self._others.append((version, lo, hi, prefix))

    def covering(self, address: str) -> frozenset[str]:
        """Return every prefix of the table whose interval holds the whole
        interval of `address`."""
        found = self._covering.get(address)
        if found is not None:
            return found
        out: set[str] = set()
        for version, lo, hi in _intervals([address]):
            for (block_version, size), starts in self._blocks.items():
                start = lo - lo % size
                if block_version == version and hi < start + size:
                    out.update(starts.get(start, ()))
            out.update(p for v, plo, phi, p in self._others if v == version and plo <= lo and hi <= phi)
        found = self._covering[address] = frozenset(out)
        return found

    def resolves_only_through(self, next_hop: str, stranded: Mapping[str, int], own: str) -> list[str]:
        """Return the stranded prefixes through which `next_hop` resolves, or an
        empty list.

        The method tests the prefixes of the recorded table of the VRF that
        cover the address. The prefix `own` of the route is excluded. A next hop
        is unusable only when every covering prefix is stranded. A next hop that
        no recorded prefix covers gives an empty list.
        """
        if not next_hop:
            return []
        covering = [p for p in self.covering(next_hop) if p != own]
        if not covering:
            return []
        if all(p in stranded for p in covering):
            return sorted(covering)
        return []


def _side_store_kind(protocol: Any) -> str:
    """Return the graph route edge kind of a side-store row.

    A row with the protocol `static` is a STATIC_ROUTE. Every other row is a
    LEARNED_ROUTE. The merged route table (`_RouteTable`) classifies the rows of
    both sources with these 2 kinds."""
    return "STATIC_ROUTE" if str(protocol or "").strip().lower() == "static" else "LEARNED_ROUTE"


def _route_identity(row: Mapping[str, Any], context_uid: str) -> tuple[str, str, str, str, str]:
    """Return the identity that a graph row and a side-store row of the same
    route share.

    The identity is (context_uid, prefix, next_hop, next_hop_context_uid,
    interface or discard kind). The tracer applies the same identity rule.

    `context_uid` is the VrfInstance in which the route is installed.

    `next_hop_context_uid` is the VrfInstance in which a leaked next hop
    resolves. It separates 2 routes to the same prefix and next hop from 2
    different exporting contexts. The last slot is empty when the row has a
    next hop. A graph row without an interface then merges with the side-store
    row that resolved an interface for it. For a row without a next hop, the
    last slot holds the interface, or the discard kind of a blackhole or reject
    route that has no interface.
    """
    prefix = str(row.get("prefix") or "")
    next_hop = str(row.get("next_hop") or "").strip()
    next_hop_context = str(row.get("next_hop_context_uid") or "")
    if next_hop:
        return (context_uid, prefix, next_hop, next_hop_context, "")
    egress = str(row.get("interface") or "") or str(row.get("discard") or "")
    return (context_uid, prefix, "", next_hop_context, egress)


def _side_store_row(route: Mapping[str, Any], context_uid: Any) -> dict[str, Any]:
    """A RIB side-store route in the shape of a `_LEARNED_NEXT_HOPS` row."""
    return {
        "kind": _side_store_kind(route.get("protocol")),
        "prefix": route.get("prefix"),
        "next_hop": route.get("next_hop"),
        "protocol": route.get("protocol"),
        "interface": route.get("interface"),
        "metric": route.get("metric"),
        "context_uid": context_uid,
    }


_NEXT_HOP_MEMO = 65_536

# A (VRF, prefix) key, and the recorded routes of one VRF per prefix.
_RouteKey = tuple[str, str]
_VrfTable = dict[str, list[dict[str, Any]]]
# One recorded route as the walk past the first level tests it
# (`_RouteTable.next_hops`). The value is the identity of the route without the
# VRF and the prefix. For a route with a next hop and no leaked context, the
# value is the next hop alone.
_Hop = str | tuple[str, str, str]
# The key of a side-store table as `_VRF_DEVICES` places it (device uid, VRF
# uid), and a route that `RibSource.routes_matching` read, with the keys of its
# table and the row.
_TableKey = tuple[str, str]
_Found = tuple[str, str | None, str | None, dict[str, Any]]


def _table_key(vd: Mapping[str, Any]) -> _TableKey:
    return (str(vd["device_uid"]), str(vd["context_uid"] or ""))


class _RouteTable:
    """The recorded route edges that the withdrawal reads, limited to the routes
    of the answer.

    The routes are the graph routes (`_LEARNED_NEXT_HOPS`) merged with every
    route that the RIB side store holds for the VRFs of the estate. The side
    store holds the routes of a device family whose collector writes routes
    only to the side store (every Cisco platform), and the routes above the row
    cap of the graph mirror (a large VyOS or FRR table). A route that both
    sources record counts once within its routing context (`_route_identity`).
    The graph row wins the tie. It takes the interface of the store row if the
    graph row has no interface.

    A side-store table is the whole RIB of a device, up to a full internet
    table on an edge router. Every VRF of the estate has one. A RibSource that
    reads by next hop and prefix (`routes_matching`) gets 2 reads for the
    estate. The first read asks for the routes of the denied next hops. The
    second read asks for the routes of their prefixes. The graph is read the
    same way (`_LEARNED_NEXT_HOPS`). A RibSource that offers only `routes` is
    read one VRF at a time, and each table is dropped after the read. The
    object keeps these attributes:

    - `relevant` holds every route whose next hop is a denied address, in the
      order of the merged table. The graph rows come first, then the
      side-store rows of each VRF in `_VRF_DEVICES` order.
    - `groups` holds every route of each (VRF, prefix) that holds a relevant
      route. With only `routes`, the side store of a VRF is read a second time
      for the groups if the first read found a relevant route in it.
    - `contexts` holds every VRF that records a route, for the counts of the
      site boundary.

    The walk past the first level tests through which prefixes a next hop
    resolves. This test covers every prefix of a VRF. The walk reads the next
    hops of the whole merged table of one VRF at a time (`next_hops`), and the
    rows of only the prefixes that a level reaches (`rows`).

    """

    def __init__(self, session: Any, rib: Any | None, denied: DeniedAddresses) -> None:
        self._rib: Any = rib
        self._denied = denied.to_set + denied.from_set
        self._memo: dict[str, bool] = {}
        self._session = session
        self._by_next_hop = rib is not None and hasattr(rib, "routes_matching")
        # The graph rows of the prefixes that hold a denied next hop. The rows
        # of a whole VRF are read when the walk asks for them. Without a denied
        # next hop, the read is not made.
        hits = [
            str(row["next_hop"])
            for row in pathmod._read(session, _NEXT_HOP_VALUES)
            if self._is_relevant({"next_hop": row["next_hop"]})
        ]
        self._graph = (
            list(pathmod._read(session, _LEARNED_NEXT_HOPS, hits=hits, context=None, prefixes=None))
            if hits
            else []
        )
        self._graph_of: dict[str, list[dict[str, Any]]] = {}
        for row in self._graph:
            self._graph_of.setdefault(str(row.get("context_uid") or ""), []).append(row)
        self._vrf_graph: dict[str, list[dict[str, Any]]] = {}
        self._first_level = False
        self._first_level_side: Mapping[_TableKey, list[dict[str, Any]]] | None = None
        self._devices = list(pathmod._read(session, _VRF_DEVICES)) if rib is not None else []
        self._devices_of: dict[str, list[dict[str, Any]]] = {}
        self._placed_by_context: set[_TableKey] = set()
        self._placed_by_name: dict[tuple[str, str | None], list[_TableKey]] = {}
        for vd in self._devices:
            self._devices_of.setdefault(str(vd["context_uid"] or ""), []).append(vd)
            key = _table_key(vd)
            self._placed_by_context.add(key)
            self._placed_by_name.setdefault((key[0], vd["vrf_name"]), []).append(key)
        self.relevant: list[dict[str, Any]] = []
        self.contexts: set[str] = {
            str(row["context_uid"]) for row in pathmod._read(session, _ROUTE_CONTEXTS) if row["context_uid"]
        }
        self.groups: dict[_RouteKey, list[dict[str, Any]]] = {}
        self._read_relevant()

    def _is_relevant(self, route: Mapping[str, Any]) -> bool:
        """Return whether the next hop of a route is an address that the change
        denies, in either direction."""
        next_hop = str(route.get("next_hop") or "").strip()
        if not next_hop:
            return False
        found = self._memo.get(next_hop)
        if found is None:
            if len(self._memo) >= _NEXT_HOP_MEMO:
                self._memo.clear()
            where = _intervals([next_hop])
            found = self._memo[next_hop] = bool(where) and bool(_intersect(where, self._denied))
        return found

    def _routes(self, vd: Mapping[str, Any]) -> Any:
        """Return the side-store table of one VRF. `vd` is a `_VRF_DEVICES` row.
        These rows are read only when a RibSource is given."""
        return self._rib.routes(vd["device_uid"], vd["context_uid"], legacy_vrf=vd["vrf_name"])

    def _graph_rows(self, context: str) -> list[dict[str, Any]]:
        """Every recorded route edge of one VRF, read once."""
        rows = self._vrf_graph.get(context)
        if rows is None:
            read = pathmod._read(self._session, _LEARNED_NEXT_HOPS, hits=None, context=context, prefixes=None)
            rows = self._vrf_graph[context] = [r for r in read if str(r.get("context_uid") or "") == context]
        return rows

    def _place(self, device_uid: str, context_uid: str | None, vrf: str | None) -> list[_TableKey]:
        """Return the (device, VRF) tables of `_VRF_DEVICES` that hold a
        side-store row.

        A row with a `context_uid` goes to the table of that context. A row
        without a `context_uid` goes to the tables whose VRF name matches `vrf`,
        as `RibSource.routes` matches it. A row of a table on which no VRF is
        placed is in no table."""
        if context_uid is not None:
            key = (device_uid, context_uid)
            return [key] if key in self._placed_by_context else []
        return self._placed_by_name.get((device_uid, vrf), [])

    def _tables_of(self, found: Iterable[_Found]) -> dict[_TableKey, list[dict[str, Any]]]:
        """Sort the routes read by next hop or prefix into their tables."""
        tables: dict[_TableKey, list[dict[str, Any]]] = {}
        for device_uid, context_uid, vrf, row in found:
            for key in self._place(device_uid, context_uid, vrf):
                tables.setdefault(key, []).append(row)
        return tables

    def _read_relevant(self) -> None:
        """Fill `relevant`, `contexts` and `groups` in one pass over every table."""
        by_identity: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        needed: dict[str, set[str]] = {}
        for row in self._graph:
            context = str(row.get("context_uid") or "")
            prefix = str(row.get("prefix") or "")
            if context and prefix:
                self.contexts.add(context)
            if self._is_relevant(row):
                copy = dict(row)
                # Every graph row stays. A side-store row merges into the last
                # graph row of its identity.
                by_identity[_route_identity(copy, context)] = copy
                self.relevant.append(copy)
                if context and prefix:
                    needed.setdefault(context, set()).add(prefix)
        if self._by_next_hop:
            tables = self._tables_by_next_hop()
            read: set[_TableKey] = set()
            for vd in self._devices:
                key = _table_key(vd)
                if key not in read:
                    read.add(key)
                    self._take(vd, tables.get(key, ()), by_identity, needed)
            side = self._tables_of(
                self._rib.routes_matching(prefixes=sorted({p for held in needed.values() for p in held}))
                if needed
                else ()
            )
        else:
            for vd in self._devices:
                self._take(vd, self._routes(vd), by_identity, needed)
            side = None
        self._read_graph_of_side_store_prefixes(needed)
        # The rows of the groups are among the rows that are already read.
        self._first_level, self._first_level_side = True, side
        try:
            for context, prefixes in needed.items():
                for prefix, entries in self._merged(context, prefixes.__contains__).items():
                    self.groups[(context, prefix)] = entries
        finally:
            self._first_level, self._first_level_side = False, None

    def _read_graph_of_side_store_prefixes(self, needed: Mapping[str, set[str]]) -> None:
        """Read the graph rows of the (VRF, prefix) pairs that a side-store route
        denies and no graph row denies.

        The first read leaves these rows out. The RIB and the graph can record a
        route of the same prefix with different next hops, for example a static
        route that a learned route shadows. Both rows belong to the table of the
        prefix."""
        held = {(str(row.get("context_uid") or ""), str(row.get("prefix") or "")) for row in self._graph}
        missing = {(context, prefix) for context, prefixes in needed.items() for prefix in prefixes} - held
        if not missing:
            return
        read = pathmod._read(
            self._session,
            _LEARNED_NEXT_HOPS,
            hits=None,
            context=None,
            prefixes=sorted({p for _, p in missing}),
        )
        for row in read:
            key = (str(row.get("context_uid") or ""), str(row.get("prefix") or ""))
            if key in missing:
                self._graph_of.setdefault(key[0], []).append(row)

    def _tables_by_next_hop(self) -> dict[_TableKey, list[dict[str, Any]]]:
        """Return the side-store routes whose next hop is a denied address, by
        table, and add every VRF that holds a route to `contexts`. Each of the 2
        results comes from one read of the estate."""
        for device_uid, context_uid, vrf in self._rib.route_tables():
            for key in self._place(device_uid, context_uid, vrf):
                if key[1]:
                    self.contexts.add(key[1])
        hits = [h for h in self._rib.next_hop_values() if self._is_relevant({"next_hop": h})]
        return self._tables_of(self._rib.routes_matching(next_hops=hits)) if hits else {}

    def _take(
        self,
        vd: Mapping[str, Any],
        routes: Iterable[Mapping[str, Any]],
        by_identity: dict[tuple[str, str, str, str, str], dict[str, Any]],
        needed: dict[str, set[str]],
    ) -> None:
        """Merge the relevant routes of the side-store table of one VRF into
        `relevant`, against the graph rows."""
        context = str(vd["context_uid"] or "")
        for route in routes:
            prefix = str(route.get("prefix") or "")
            if context and prefix:
                self.contexts.add(context)
            # A route and its duplicate share the next hop. A duplicate of a
            # relevant route is relevant, and a duplicate of any other route is
            # not relevant.
            if not self._is_relevant(route):
                continue
            identity = _route_identity(route, context)
            existing = by_identity.get(identity)
            if existing is not None:
                if not existing.get("interface") and route.get("interface"):
                    existing["interface"] = route.get("interface")
                continue
            row = _side_store_row(route, vd["context_uid"])
            by_identity[identity] = row
            self.relevant.append(row)
            if context and prefix:
                needed.setdefault(context, set()).add(prefix)

    def _merged(
        self,
        context: str,
        wanted: Callable[[str], bool],
    ) -> _VrfTable:
        """Return the merged routes of one VRF whose prefix `wanted` accepts, per
        prefix.

        The graph rows come first. The side-store rows of each table of the VRF
        follow in `_VRF_DEVICES` order, each in the order of its table. A route
        without a prefix is in no table.

        The groups of the first level are built from the rows that are already
        read for their prefixes (`_first_level`). These are the graph rows of
        the prefixes that hold a denied next hop, and the side-store routes of
        these prefixes by table if the side store was read by prefix. Every
        other call reads the whole VRF."""
        side = self._first_level_side
        table: _VrfTable = {}
        by_identity: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for row in self._graph_of.get(context, ()) if self._first_level else self._graph_rows(context):
            prefix = str(row.get("prefix") or "")
            if prefix and wanted(prefix):
                copy = dict(row)
                by_identity[_route_identity(copy, context)] = copy
                table.setdefault(prefix, []).append(copy)
        for vd in self._devices_of.get(context, ()):
            for route in self._routes(vd) if side is None else side.get(_table_key(vd), ()):
                prefix = str(route.get("prefix") or "")
                if not prefix or not wanted(prefix):
                    continue
                identity = _route_identity(route, context)
                existing = by_identity.get(identity)
                if existing is not None:
                    if not existing.get("interface") and route.get("interface"):
                        existing["interface"] = route.get("interface")
                    continue
                row = _side_store_row(route, vd["context_uid"])
                by_identity[identity] = row
                table.setdefault(prefix, []).append(row)
        return table

    def next_hops(self, context: str) -> dict[str, list[_Hop]]:
        """Return every recorded route of one VRF per prefix, each as a `_Hop`.

        The order and the merged routes are the same as in `_merged` for the
        whole table. The walk tests next hops across the whole table. It reads
        rows only for the prefixes that it reaches (`rows`).

        A route and its duplicate share the prefix. A route is compared only
        with the routes of its own prefix, and no identity is kept beyond its
        `_Hop`. A next hop string that recurs is stored once."""
        table: dict[str, list[_Hop]] = {}
        names: dict[str, str] = {}

        def hop(route: Mapping[str, Any]) -> _Hop:
            _, _, next_hop, next_hop_context, egress = _route_identity(route, context)
            next_hop = names.setdefault(next_hop, next_hop)
            if next_hop and not next_hop_context:
                return next_hop
            return (next_hop, next_hop_context, egress)

        for row in self._graph_rows(context):
            prefix = str(row.get("prefix") or "")
            if prefix:
                # Every graph row stays, as in `_merged`.
                table.setdefault(prefix, []).append(hop(row))
        for vd in self._devices_of.get(context, ()):
            for route in self._routes(vd):
                prefix = str(route.get("prefix") or "")
                if not prefix:
                    continue
                entry = hop(route)
                listed = table.get(prefix)
                if listed is None:
                    table[prefix] = [entry]
                elif entry not in listed:
                    listed.append(entry)
        return table

    def rows(self, context: str, prefixes: Collection[str]) -> _VrfTable:
        """Return the merged rows of the given prefixes of one VRF, per prefix."""
        return self._merged(context, prefixes.__contains__)


def _because_of_a_stranded_prefix(through: Sequence[str]) -> str:
    return (
        "this next hop resolves only through "
        + ", ".join(through)
        + ", which the change leaves with no recorded next hop"
    )


class _Walk(NamedTuple):
    """The result of `_walk_levels`.

    `withdrawn` holds the withdrawn route edges keyed by (VRF, prefix) and row
    index, each with the reason and the level. `stranded` holds the level at
    which each prefix lost its last recorded next hop. `entries` holds the
    recorded routes of every withdrawn prefix. The row indexes point into
    `entries`. `reached` is the last level that found a withdrawal.
    `exhausted` is whether the depth bound ended the walk.
    """

    withdrawn: dict[_RouteKey, dict[int, tuple[str, int]]]
    stranded: dict[_RouteKey, int]
    entries: dict[_RouteKey, list[dict[str, Any]]]
    reached: int
    exhausted: bool


def _walk_levels(
    groups: Mapping[_RouteKey, list[dict[str, Any]]],
    routes: _RouteTable,
    denied: DeniedAddresses,
    depth: int,
) -> _Walk:
    """Follow the route dependency chain, level by level, to `depth`.

    Level 1 applies the direction rule of `_withdrawn_because` to each route
    whose recorded next hop the change denies. `groups` holds every prefix of
    such a route, with all of its routes. At a level n above 1, a route is
    withdrawn if its next hop resolves only through prefixes stranded at a
    level below n. The test reads the next hops of the whole table of the VRF
    of the route (`routes.next_hops`), one VRF at a time, and only for a VRF
    that holds a stranded prefix. The rows of a prefix that the level reaches
    for the first time are read after the pass over the VRF (`routes.rows`), in
    the order in which its next hops were tested. The row indexes of its hits
    point into these rows.

    A prefix is stranded once and skipped after that. A level that withdraws no
    new route ends the walk.
    """
    withdrawn: dict[_RouteKey, dict[int, tuple[str, int]]] = {}
    stranded: dict[_RouteKey, int] = {}
    entries_of: dict[_RouteKey, list[dict[str, Any]]] = {}

    for key, entries in groups.items():
        hits = {
            index: (why, 1) for index, row in enumerate(entries) if (why := _withdrawn_because(row, denied))
        }
        if not hits:
            continue
        withdrawn[key] = hits
        entries_of[key] = entries
        if len(hits) == len(entries):
            stranded[key] = 1

    level = 1
    productive = 1
    exhausted = True
    while level < depth:
        level += 1
        added = False
        for context in sorted({c for c, _ in stranded}):
            below = {p: lv for (c, p), lv in stranded.items() if c == context and lv < level}
            if not below:
                continue
            table = routes.next_hops(context)
            index = _PrefixIndex(table)
            # The prefixes that this level reaches for the first time, with their hits.
            arrived: dict[str, dict[int, tuple[str, int]]] = {}
            for prefix, hops in table.items():
                key = (context, prefix)
                if key in stranded:
                    continue
                # A prefix that the walk already reached keeps the rows against
                # which its hits were counted.
                known = entries_of.get(key)
                next_hops = (
                    [h if isinstance(h, str) else h[0] for h in hops]
                    if known is None
                    else [str(row.get("next_hop") or "").strip() for row in known]
                )
                hits = withdrawn.get(key, {})
                for i, next_hop in enumerate(next_hops):
                    if i in hits:
                        continue
                    through = index.resolves_only_through(next_hop, below, prefix)
                    if through:
                        hits[i] = (_because_of_a_stranded_prefix(through), level)
                        added = True
                if not hits:
                    continue
                if known is None:
                    arrived[prefix] = hits
                    continue
                withdrawn[key] = hits
                if len(hits) == len(known):
                    stranded[key] = level
            del table, index
            if not arrived:
                continue
            for prefix, rows in routes.rows(context, arrived).items():
                key = (context, prefix)
                hits = arrived[prefix]
                withdrawn[key] = hits
                entries_of[key] = rows
                if len(hits) == len(rows):
                    stranded[key] = level
        if not added:
            exhausted = False
            break
        productive = level
    return _Walk(withdrawn, stranded, entries_of, productive, exhausted)


def _level_report(
    withdrawn: Mapping[tuple[str, str], dict[int, tuple[str, int]]],
    stranded: Mapping[tuple[str, str], int],
    depth: int,
) -> list[dict[str, Any]]:
    """Return the counts of each level up to `depth`.

    A prefix is counted at the level at which it first lost a recorded next
    hop. `prefixes_with_no_next_hop_left` counts it at the level at which it
    lost its last recorded next hop.
    """
    first: dict[tuple[str, str], int] = {
        key: min(level for _, level in hits.values()) for key, hits in withdrawn.items()
    }
    levels: list[dict[str, Any]] = []
    for level in range(1, depth + 1):
        arrived = sorted(key for key, lv in first.items() if lv == level)
        edges = sum(1 for hits in withdrawn.values() for _, lv in hits.values() if lv == level)
        emptied = sorted(key for key, lv in stranded.items() if lv == level)
        if not arrived and not edges and not emptied and level > 1:
            continue
        levels.append(
            {
                "level": level,
                "prefix_count": len(arrived),
                "prefixes_with_no_next_hop_left": len(emptied),
                "withdrawn_route_edge_count": edges,
                "vrf_count": len({context for context, _ in arrived}),
                "sample": [f"{prefix} in {context}" for context, prefix in arrived[:_LEVEL_SAMPLE]],
                "sample_truncated": len(arrived) > _LEVEL_SAMPLE,
            }
        )
    return levels


def _next_hop_withdrawal(
    groups: Mapping[_RouteKey, list[dict[str, Any]]],
    routes: _RouteTable,
    denied: DeniedAddresses,
    depth: int = _DEFAULT_WITHDRAWAL_DEPTH,
    row_limit: int | None = _MAX_ROUTE_ROWS,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], int, int]:
    """Build the before and after routing table for every prefix that a
    withdrawal reaches.

    The table is grouped per VRF and per prefix. A prefix that no withdrawal
    reaches is not in the table.

    Returns the table, the counts per level, the last level that withdrew a
    route, and how many prefixes the last level stranded.

    `_walk_levels` reads `groups` and `routes`. `groups` holds the prefixes of
    the denied next hops. `routes` is the recorded table of every VRF.

    `row_limit` bounds how many prefixes are listed beside the counts. None
    lists every prefix. The counts are always complete.
    """
    walk = _walk_levels(groups, routes, denied, depth)
    withdrawn, stranded, reached = walk.withdrawn, walk.stranded, walk.reached
    levels = _level_report(withdrawn, stranded, reached)
    open_at_the_last_level = sum(1 for lv in stranded.values() if lv == depth) if walk.exhausted else 0

    affected: dict[str, list[dict[str, Any]]] = {}
    prefix_count = 0
    emptied = 0
    withdrawn_edges = 0
    for context, prefix in sorted(withdrawn):
        hits = withdrawn[(context, prefix)]
        entries = walk.entries[(context, prefix)]
        prefix_count += 1
        withdrawn_edges += len(hits)
        before = [_next_hop_entry(row, hits.get(i, (None, 0))[0]) for i, row in enumerate(entries)]
        after = [_next_hop_entry(row, None) for i, row in enumerate(entries) if i not in hits]
        if not after:
            emptied += 1
        affected.setdefault(context, []).append(
            {
                "prefix": prefix,
                "next_hops_before": before,
                "next_hops_after": after,
                "withdrawn_next_hops": [
                    _next_hop_entry(entries[i], why) for i, (why, _) in sorted(hits.items())
                ],
                "no_next_hop_left": not after,
                # The level at which the withdrawal reached this prefix, and the
                # level at which the prefix lost its last recorded next hop.
                "level": min(level for _, level in hits.values()),
                "no_next_hop_left_at_level": stranded.get((context, prefix)),
            }
        )
    if not affected:
        return None, levels, reached, open_at_the_last_level

    vrfs: list[dict[str, Any]] = []
    budget = row_limit
    for context in sorted(affected):
        prefixes = affected[context]
        listed = prefixes if budget is None else prefixes[: max(budget, 0)]
        if budget is not None:
            budget -= len(listed)
        vrfs.append(
            {
                "context_uid": context,
                "prefix_count": len(prefixes),
                "prefixes_with_no_next_hop_left": sum(1 for p in prefixes if p["no_next_hop_left"]),
                "truncated": len(listed) < len(prefixes),
                "prefixes": listed,
            }
        )

    body: dict[str, Any] = {
        "vrfs": vrfs,
        "prefix_count": prefix_count,
        "prefixes_with_no_next_hop_left": emptied,
        "withdrawn_route_edge_count": withdrawn_edges,
        "truncated": any(v["truncated"] for v in vrfs),
    }
    if body["truncated"]:
        body["truncation"] = (
            f"{prefix_count} prefixes lose a recorded next hop; the first {row_limit} by "
            "VRF and prefix are listed and every count above is complete"
        )
    return body, levels, reached, open_at_the_last_level


# --- the site the walk is narrowed to -------------------------------------


class SiteScope:
    """The VRFs that the walk may enter, and everything that the site filter cut.

    `in_force` is false when the caller named no site. Every VRF is then in
    scope. A site is named by uid, by `code` or by `name`, matched
    case-insensitively.
    """

    def __init__(
        self,
        requested: Sequence[str] | None,
        sites: Sequence[Mapping[str, Any]],
        vrfs: Sequence[Mapping[str, Any]],
    ) -> None:
        self.requested = [str(s).strip() for s in (requested or ()) if str(s).strip()]
        self.in_force = bool(self.requested)
        self.resolved: list[str] = []
        self.not_found: list[str] = []
        self.sites_of: dict[str, set[str]] = {}
        if not self.in_force:
            return

        by_token: dict[str, str] = {}
        for row in sites:
            uid = str(row.get("uid") or "")
            if not uid:
                continue
            for token in (uid, row.get("code"), row.get("name")):
                if token:
                    by_token.setdefault(str(token).strip().lower(), uid)
        chosen: set[str] = set()
        for name in self.requested:
            found = by_token.get(name.lower())
            if found is None:
                self.not_found.append(name)
            else:
                chosen.add(found)
        self.resolved = sorted(chosen)

        for row in vrfs:
            context = str(row.get("context_uid") or "")
            if context:
                self.sites_of[context] = {str(s) for s in (row.get("site_uids") or ()) if s}

    def holds(self, context_uid: str) -> bool:
        if not self.in_force:
            return True
        return bool(self.sites_of.get(context_uid, set()) & set(self.resolved))

    def has_no_recorded_site(self, context_uid: str) -> bool:
        return self.in_force and not self.sites_of.get(context_uid)


def _read_site_scope(session: Any, sites: Sequence[str] | None) -> SiteScope:
    """Resolve the site filter against the pinned snapshot.

    The function makes 2 reads, and only when the caller named a filter. The
    first read returns the sites of the snapshot. The second read returns the
    sites of each VRF through the devices of its interfaces.
    """
    if not [s for s in (sites or ()) if str(s).strip()]:
        return SiteScope(None, (), ())
    return SiteScope(
        sites,
        [dict(r) for r in pathmod._read(session, _SITES)],
        [dict(r) for r in pathmod._read(session, _VRF_SITES)],
    )


def _sites_for_vrfs(session: Any, context_uids: Iterable[str]) -> tuple[list[dict[str, str]], int]:
    """Return the sites of the given VRFs, resolved from `_VRF_SITES` and `_SITES`.

    The returned integer counts each VRF for which the join finds no
    `LOCATED_IN` chain.
    """
    wanted = sorted({c for c in context_uids if c})
    if not wanted:
        return [], 0
    names = {str(r["uid"]): r.get("name") for r in pathmod._read(session, _SITES)}
    site_uids_by_vrf = {
        str(r["context_uid"]): [str(s) for s in (r.get("site_uids") or ()) if s]
        for r in pathmod._read(session, _VRF_SITES)
    }
    touched: set[str] = set()
    unplaced = 0
    for context in wanted:
        uids = site_uids_by_vrf.get(context) or []
        if not uids:
            unplaced += 1
            continue
        touched.update(uids)
    sites = sorted(
        ({"uid": uid, "name": str(names[uid]) if names.get(uid) else uid} for uid in touched),
        key=lambda s: s["uid"],
    )
    return sites, unplaced


def _boundary_report(
    contexts: Iterable[str],
    groups: Mapping[_RouteKey, list[dict[str, Any]]],
    denied: DeniedAddresses,
    scope: SiteScope,
) -> dict[str, Any]:
    """Report what the site boundary stopped the walk from following.

    `contexts` holds every VRF of the estate that records a route. `groups`
    holds every prefix of the estate with a denied next hop, with all of its
    routes. The first level is evaluated over the VRFs outside the filter and
    inside it. The report holds counts and at most `_MAX_BOUNDARY_VRFS` VRF
    uids.
    """
    contexts = set(contexts)
    outside = sorted(c for c in contexts if not scope.holds(c))
    groups_of: dict[str, list[list[dict[str, Any]]]] = {}
    for (context, _prefix), entries in groups.items():
        groups_of.setdefault(context, []).append(entries)
    prefixes = 0
    edges = 0
    touched: list[str] = []
    for context in outside:
        hit_here = 0
        for entries in groups_of.get(context, ()):
            withdrawn = [r for r in entries if _withdrawn_because(r, denied)]
            if withdrawn:
                hit_here += 1
                edges += len(withdrawn)
        if hit_here:
            prefixes += hit_here
            touched.append(context)

    body: dict[str, Any] = {
        "sites_requested": list(scope.requested),
        "sites_resolved": list(scope.resolved),
        "sites_not_found": list(scope.not_found),
        "vrfs_in_scope": sum(1 for c in contexts if scope.holds(c)),
        "vrfs_outside_the_selected_sites": len(outside),
        "vrfs_with_no_recorded_site": sum(1 for c in outside if scope.has_no_recorded_site(c)),
        "stopped_the_walk": bool(touched),
        "prefixes_not_followed": prefixes,
        "withdrawn_route_edges_not_followed": edges,
        "vrfs_not_followed": touched[:_MAX_BOUNDARY_VRFS],
        "vrfs_not_followed_count": len(touched),
        "vrfs_not_followed_truncated": len(touched) > _MAX_BOUNDARY_VRFS,
        "basis": (
            "a site groups devices (Device LOCATED_IN Site); a VrfInstance carries no device "
            "edge of its own, so a VRF is placed by the devices its interfaces are on, and a VRF "
            "the selected sites do not hold is where the walk stops"
        ),
    }
    body["note"] = "this filter narrows the question, not the estate. " + (
        f"{prefixes} prefix(es) in {len(touched)} VRF(s) outside the selected sites lose a "
        "recorded next hop and were not followed, so this result is smaller than the "
        "consequence, not evidence that the consequence is small"
        if touched
        else "no VRF outside the selected sites holds a prefix that loses a recorded next "
        "hop, so nothing was cut at the boundary"
    )
    if scope.not_found:
        body["note"] += (
            "; " + ", ".join(scope.not_found) + " matched no Site in this snapshot and narrowed "
            "the walk to nothing of their own"
        )
    return body


# --- the protocol-specific prediction beside it ---------------------------

# The routing model errors under which the rows of a calculation are not an
# answer. `hst.simul.rib` documents the rows as "the state at the last round".
_UNSETTLED_KINDS = frozenset({"no-routing-fixed-point", "no-rib-fixed-point"})

# The validation statuses of a computed route that disagrees with the observed
# RIB or has no observed route to compare with.
_UNVERIFIED_STATUSES = frozenset({ribmod.MISMATCH, ribmod.NOT_OBSERVED})


class _RoutingBasis(NamedTuple):
    """The facts that qualify the result of a flow under a routing calculation.

    `validation` holds the validation of the before state against the observed
    RIB. `gaps` holds the gaps of the after state. `context_devices` maps each
    forwarding context to its device, for the test of which contexts a flow
    crossed."""

    validation: tuple[Mapping[str, Any], ...]
    gaps: tuple[Mapping[str, Any], ...]
    context_devices: Mapping[str, str]


class _RoutingPrediction(NamedTuple):
    body: dict[str, Any]
    before_fib: Any | None = None
    after_fib: Any | None = None
    # The reason why no FIB is traced when either side did not settle.
    unsettled: str | None = None
    basis: _RoutingBasis | None = None


def _within(inner: Any, outer: Any) -> bool:
    """Return whether the network `inner` lies inside the network `outer` of the
    same family."""
    return (
        inner.version == outer.version
        and int(outer.network_address) <= int(inner.network_address)
        and int(inner.broadcast_address) <= int(outer.broadcast_address)
    )


def _flow_basis_reasons(
    routed: _RoutingPrediction | None, flow: Mapping[str, Any], crossed: set[str] | None
) -> list[str]:
    """Return the reasons why the routing calculation does not establish the
    before and after comparison of a flow. The list is empty when no reason
    applies.

    A reason applies when the calculation did not settle. A reason applies when
    a route of the flow disagrees with the observed RIB or has no observed route
    to compare with. The routes of the flow are the longest validated prefix
    that covers the destination in each context that the flow crossed, and
    every validated prefix inside a destination wider than a host. A reason
    applies when the after state has a gap for a context that the flow crossed.
    `crossed` holds the devices that the traces of the flow drew. It is None
    when the traces drew no device, and then every context counts.
    """
    if routed is None:
        return []
    if routed.unsettled:
        return [routed.unsettled]
    basis = routed.basis
    if basis is None:
        return []

    def on_path(context: Any) -> bool:
        device = basis.context_devices.get(str(context)) if context else None
        return crossed is None or device is None or device in crossed

    reasons: list[str] = []
    try:
        target = ipaddress.ip_network(str(flow["dst"]), strict=False)
    except (KeyError, ValueError):
        target = None
    if target is not None:
        covering: dict[str, tuple[int, str, str]] = {}
        for row in basis.validation:
            context = str(row["context_uid"])
            if not on_path(context):
                continue
            try:
                net = ipaddress.ip_network(str(row["prefix"]), strict=False)
            except ValueError:
                continue
            if net.version != target.version:
                continue
            status = str(row["status"])
            if _within(target, net):
                if context not in covering or net.prefixlen > covering[context][0]:
                    covering[context] = (net.prefixlen, str(row["prefix"]), status)
            elif _within(net, target) and status in _UNVERIFIED_STATUSES:
                reasons.append(f"route {row['prefix']} in {context} is {status}")
        for context, (_length, prefix, status) in sorted(covering.items()):
            if status in _UNVERIFIED_STATUSES:
                reasons.append(f"route {prefix} in {context} is {status}")
    for gap in basis.gaps:
        if on_path(gap.get("context_uid")):
            reasons.append(
                f"the routing calculation names a {gap.get('kind')} gap"
                + (f" for {gap['context_uid']}" if gap.get("context_uid") else "")
            )
    return list(dict.fromkeys(reasons))


def _routing_scope(session: Any, intents: Sequence[Intent], errors: ErrorSink) -> tuple[list[str], set[str]]:
    """Return the forwarding contexts that the routing intents name, and the
    devices that these contexts sit on. An intent that names a session or a
    router id that the snapshot does not hold is reported to `errors`."""
    contexts: set[str] = set()
    devices: set[str] = set()
    for intent in intents:
        params = intent.params
        if intent.kind == "bgp_session.shut":
            rows = pathmod._read(session, _SESSION_CONTEXT, sess=str(params["session"]))
            if not rows:
                errors.report(
                    "routing-intent-names-no-session",
                    f"intent {intent.kind} names BgpSession {params['session']!r}, which this snapshot "
                    "does not hold in any VrfInstance; the intent scopes nothing",
                    str(params["session"]),
                )
        elif intent.kind in ROUTING_KINDS:
            router_ids = (
                [str(params["router_id"])]
                if intent.kind == "ospf.interface_cost"
                else [str(params["router_a"]), str(params["router_b"])]
            )
            rows = []
            for router_id in router_ids:
                rows.extend(pathmod._read(session, _OSPF_ROUTER_CONTEXTS, rid=router_id))
            if not rows:
                errors.report(
                    "routing-intent-names-no-router",
                    f"intent {intent.kind} names OSPF router id(s) {', '.join(router_ids)}, which no "
                    "OSPF RoutingProcess in this snapshot advertises; the intent scopes nothing",
                    ", ".join(router_ids),
                )
        else:
            continue
        for row in rows:
            if row.get("context_uid"):
                contexts.add(str(row["context_uid"]))
            devices.update(str(d) for d in (row.get("device_uids") or ()) if d)
    return sorted(contexts), devices


_RESOLUTION_HOPS = 8


class _LongestMatch:
    """The rows of one calculated table indexed by network."""

    def __init__(self, rows: Sequence[Mapping[str, Any]]) -> None:
        self._nets: dict[tuple[int, int], dict[Any, list[Mapping[str, Any]]]] = {}
        for row in rows:
            try:
                net = ipaddress.ip_network(str(row["prefix"]), strict=False)
            except ValueError:
                continue
            self._nets.setdefault((net.version, net.prefixlen), {}).setdefault(net, []).append(row)
        self._lengths = sorted(self._nets, key=lambda key: -key[1])

    def longest(self, address: Any, skip: str) -> list[Mapping[str, Any]]:
        """Return the rows of the longest prefix other than `skip` that covers `address`."""
        for version, length in self._lengths:
            if version != address.version:
                continue
            net = ipaddress.ip_network(f"{address}/{length}", strict=False)
            found = [r for r in self._nets[(version, length)].get(net, ()) if str(r["prefix"]) != skip]
            if found:
                return found
        return []


def _egress_through(index: _LongestMatch, next_hop: Any, skip: str) -> str | None:
    """Return the interface through which a next hop leaves in one calculated
    table.

    The lookup takes the longest prefix other than `skip` that covers the next
    hop. `skip` is the prefix of the route itself. While the covering route has
    no interface, the lookup follows its next hop, up to `_RESOLUTION_HOPS`
    times. The result is None when no prefix covers the next hop, or when the
    covering routes disagree on the interface."""
    try:
        address = ipaddress.ip_address(str(next_hop))
    except ValueError:
        return None
    for _ in range(_RESOLUTION_HOPS):
        found = index.longest(address, skip)
        interfaces = {str(r["interface"]) for r in found if r.get("interface")}
        onward = {str(r["next_hop"]) for r in found if not r.get("interface") and r.get("next_hop")}
        if len(interfaces) == 1 and not onward:
            return next(iter(interfaces))
        if interfaces or len(onward) != 1:
            return None
        try:
            address = ipaddress.ip_address(next(iter(onward)))
        except ValueError:
            return None
        skip = ""
    return None


def _fib_route_rows(fib: Any) -> Callable[[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """Build the `ChangeSet.route_rows` hook over the FIB of a calculation.

    For a table that the calculation covers, the hook returns the FIB rows in
    the shape of the route read of the tracer. Each row is matched to the
    collected row of the same route if one exists. A connected prefix then
    keeps its Prefix uid, and a route keeps its egress. For a table that the
    calculation does not cover, the hook returns the collected rows.
    `_ScopedRib` reads the side-store RIB for these tables.

    A route is matched by its prefix and its next hop. A routing intent can
    move a prefix to another next hop, and the collected row of the old next
    hop holds the interface towards the old next hop. A BGP or OSPF route of
    the calculation has a next hop and no interface. Such a row takes the
    interface through which its next hop resolves in the resolving table. For
    a leaked route the resolving table is the exporting table
    (`next_hop_context_uid`), as the calculation and the tracer resolve it. The
    row gets no interface when the calculation does not hold the resolving
    table, or when the next hop does not resolve to one interface. The tracer
    then resolves the egress from the interface name, or leaves it undecided.
    """

    def rewrite(table_uid: str, collected: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = fib.table(table_uid)
        if rows is None:
            return collected
        # One longest-prefix index per resolving table, built on first use.
        indexes: dict[str, _LongestMatch | None] = {}

        def index_of(context: str) -> _LongestMatch | None:
            if context not in indexes:
                table = rows if context == table_uid else fib.table(context)
                indexes[context] = None if table is None else _LongestMatch(table)
            return indexes[context]

        by_connected: dict[str, dict[str, Any]] = {}
        by_route: dict[tuple[str, str | None], dict[str, Any]] = {}
        by_cidr: dict[str, dict[str, Any]] = {}
        by_egress: dict[str, str] = {}
        for row in collected:
            cidr = str(row.get("cidr"))
            if row.get("kind") == "ORIGINATES":
                by_connected.setdefault(cidr, row)
            by_route.setdefault((cidr, row.get("next_hop")), row)
            by_cidr.setdefault(cidr, row)
            if row.get("egress_uid") and row.get("egress_name"):
                by_egress.setdefault(str(row["egress_name"]), str(row["egress_uid"]))
        out = []
        for row in rows:
            protocol = str(row.get("protocol"))
            kind = (
                "ORIGINATES"
                if protocol == ribmod.CONNECTED
                else "STATIC_ROUTE"
                if protocol == ribmod.STATIC
                else "LEARNED_ROUTE"
            )
            prefix = str(row["prefix"])
            next_hop = row.get("next_hop")
            graph = by_route.get((prefix, next_hop))
            if graph is None and kind == "ORIGINATES":
                graph = by_connected.get(prefix)
            stated = row.get("interface")
            # The egress of the collected route applies only to the same route.
            # A route that the calculation puts on another interface is a
            # different route.
            same = graph is not None and (
                not stated or stated in (graph.get("ifname"), graph.get("egress_name"))
            )
            ifname = stated or (graph.get("ifname") if same and graph else None)
            if not ifname and next_hop and kind != "ORIGINATES":
                resolving = str(row.get("next_hop_context_uid") or table_uid)
                index = index_of(resolving)
                # The prefix of the route is skipped only in the table of the route.
                own = prefix if resolving == table_uid else ""
                ifname = _egress_through(index, next_hop, own) if index is not None else None
            if same and graph and graph.get("egress_uid"):
                egress_uid = graph.get("egress_uid")
                egress_name = graph.get("egress_name")
            else:
                egress_uid = by_egress.get(str(ifname)) if ifname else None
                egress_name = ifname
            # There is one Prefix node per (VRF, cidr). Every collected row of the
            # prefix holds its uid.
            uid_row = graph or by_cidr.get(prefix)
            out.append(
                {
                    "uid": uid_row.get("uid") if uid_row else None,
                    "cidr": row["prefix"],
                    "kind": kind,
                    "next_hop": next_hop,
                    "ifname": ifname,
                    "egress_uid": egress_uid,
                    "egress_name": egress_name,
                    "derived": None,
                    "via_rt": None,
                    "rib": True,
                    "next_hop_vrf": row.get("next_hop_context_uid"),
                    "discard": row.get("discard"),
                    "protocol": protocol,
                    "metric": row.get("metric"),
                }
            )
        return out

    return rewrite


class _ScopedRib:
    """The RIB that a trace reads under a routing intent.

    The trace reads the FIB of the calculation for every table that the
    calculation covers. It reads the side store of the caller (`RibSource`, or
    None) for every other table."""

    def __init__(self, fib: Any, rib: Any | None) -> None:
        self._fib = fib
        self._rib = rib

    @property
    def approximate(self) -> bool:
        return bool(self._rib is not None and getattr(self._rib, "approximate", False))

    def _store(self) -> Any | None:
        rib = self._rib
        return rib if rib is not None and getattr(rib, "available", True) is not False else None

    def has_rows(self, device_uid: str) -> bool:
        if self._fib.has_rows(device_uid):
            return True
        store = self._store()
        return bool(store is not None and store.has_rows(device_uid))

    def coverage(self, device_uid: str) -> str | None:
        if self._fib.has_rows(device_uid):
            return "computed"
        store = self._store()
        coverage = getattr(store, "coverage", None)
        return coverage(device_uid) if callable(coverage) else None

    def _computed(self, context_uid: str | None) -> bool:
        return context_uid is not None and self._fib.covers(context_uid)

    def lpm(
        self, device_uid: str, context_uid: str | None, probe_ip: str, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        if self._computed(context_uid):
            return list(self._fib.lpm(device_uid, context_uid, probe_ip))
        store = self._store()
        if store is None:
            return []
        return list(store.lpm(device_uid, context_uid, probe_ip, legacy_vrf=legacy_vrf))

    def overlapping(
        self,
        device_uid: str,
        context_uid: str | None,
        lo: Any,
        hi: Any,
        minlen: int,
        af: int,
        *,
        legacy_vrf: str | None = None,
    ) -> list[dict[str, Any]]:
        if self._computed(context_uid):
            return list(self._fib.overlapping(device_uid, context_uid, lo, hi, minlen, af))
        store = self._store()
        if store is None:
            return []
        return list(store.overlapping(device_uid, context_uid, lo, hi, minlen, af, legacy_vrf=legacy_vrf))

    def covering_lengths(
        self, tables: Sequence[tuple[str, str | None, str | None]], probe_ip: str
    ) -> dict[str, int]:
        out: dict[str, int] = {}
        stored = []
        for device_uid, context_uid, vrf in tables:
            if not self._computed(context_uid):
                stored.append((device_uid, context_uid, vrf))
                continue
            for r in self._fib.lpm(device_uid, context_uid, probe_ip):
                n = ipaddress.ip_network(str(r["prefix"]), strict=False).prefixlen
                out[str(context_uid)] = max(out.get(str(context_uid), -1), n)
        store = self._store()
        if stored and store is not None:
            batch = getattr(store, "covering_lengths", None)
            if batch is not None:
                out.update(batch(stored, probe_ip))
            else:
                for device_uid, context_uid, vrf in stored:
                    for r in store.lpm(device_uid, context_uid, probe_ip, legacy_vrf=vrf):
                        n = r.get("prefixlen")
                        n = (
                            int(n)
                            if n is not None
                            else ipaddress.ip_network(str(r["prefix"]), strict=False).prefixlen
                        )
                        key = str(context_uid)
                        out[key] = max(out.get(key, -1), n)
        return out


def _bgp_prediction(
    session: Any,
    intents: Sequence[Intent],
    errors: ErrorSink,
    *,
    rib: Any | None = None,
    bgp: Any | None = None,
    ospf: Any | None = None,
) -> _RoutingPrediction:
    """Run the integrated routing calculation (`hst.simul.rib`) before and after
    the explicit routing intents of a change set, and diff the results.

    The calculation runs only for an explicit `bgp_session.shut`,
    `ospf.interface_cost` or `ospf.adjacency_down` intent (`ROUTING_KINDS`). An
    address match in a firewall deny does not start it. The calculation is
    scoped to the contexts that the intents change. `simul_read.read_rib_input`
    widens the scope to every context that the change can alter and every
    context that those contexts read. The change cannot alter a table outside
    that scope. Both traces read the collected graph rows and the side-store RIB
    of the caller for such a table (`_ScopedRib`), as a trace without the
    intent does. The calculation reads the graph, `rib` (observed routes), `bgp`
    (observed paths and session state) and `ospf` (the link-state databases).

    Returns the report body, both FIBs, the reason why the calculation is not
    an answer when either side did not settle, and the validation and the gaps
    for the result of a flow (`_RoutingBasis`).
    """
    routing = [i for i in intents if i.kind in ROUTING_KINDS]
    scopes, _devices = _routing_scope(session, routing, errors)
    body: dict[str, Any] = {
        "intents": [i.as_dict() for i in routing],
        "evaluation": "integrated-routing",
        "basis": (
            "one routing calculation per forwarding context over the snapshot's connected and "
            "static routes, the OSPF link-state databases, the BGP sessions with their observed "
            "paths where captured, redistribution, route-target leaking and next-hop resolution, "
            "run to a fixed point before and after the intents; the rows are the main RIB the "
            "calculation installs, validated against the observed rib rows of each context"
        ),
        "scopes_predicted": scopes,
        "predicted_prefixes_withdrawn": [],
        "predicted_withdrawn_count": 0,
        "predicted_prefixes_added": [],
        "predicted_added_count": 0,
        "predicted_rows_changed": [],
        "predicted_changed_count": 0,
        "validation": [],
        "validation_summary": {},
        "gaps_before": [],
        "gaps_after": [],
        "rounds_before": 0,
        "rounds_after": 0,
    }
    if not scopes:
        return _RoutingPrediction(body)

    # The contexts of the intents are the change. The read adds every context
    # that the change can alter and every context that those contexts read.
    ospf_routers = sorted(
        {
            str(i.params[key])
            for i in routing
            if i.kind != "bgp_session.shut"
            for key in ("router_id", "router_a", "router_b")
            if i.params.get(key)
        }
    )
    graph = simul_read.read_rib_input(
        session,
        contexts=scopes,
        changed=scopes,
        ospf_routers=ospf_routers,
        rib_source=rib,
        bgp_source=bgp,
        ospf_source=ospf,
    )
    for err in graph.errors.as_dicts():
        errors.report(str(err["kind"]), str(err["detail"]), err.get("subject"))
    before = ribmod.compute(graph.input, ErrorSink())
    changed_input = ribmod.apply_intents(graph.input, [i.as_dict() for i in routing], errors)
    after = ribmod.compute(changed_input, ErrorSink())
    for err in before.model_errors + after.model_errors:
        errors.report(str(err["kind"]), str(err["detail"]), err.get("subject"))

    def key(row: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            str(row["context_uid"]),
            str(row["prefix"]),
            row.get("next_hop"),
            row.get("next_hop_context_uid"),
            row.get("interface"),
            row.get("discard"),
        )

    unsettled = [
        f"{side} state {result.convergence.get('status')}"
        for side, result in (("before", before), ("after", after))
        if result.convergence.get("status", "settled") != "settled"
        or any(e.get("kind") in _UNSETTLED_KINDS for e in result.model_errors)
    ]

    before_rows = {key(r): dict(r) for r in before.rib}
    after_rows = {key(r): dict(r) for r in after.rib}
    withdrawn = [before_rows[k] for k in before_rows if k not in after_rows]
    added = [after_rows[k] for k in after_rows if k not in before_rows]
    changed = [
        {"context_uid": k[0], "prefix": k[1], "before": before_rows[k], "after": after_rows[k]}
        for k in before_rows
        if k in after_rows and before_rows[k] != after_rows[k]
    ]
    summary: dict[str, int] = {}
    for row in before.validation:
        summary[str(row["status"])] = summary.get(str(row["status"]), 0) + 1
    body.update(
        {
            "predicted_prefixes_withdrawn": withdrawn[:_MAX_ROUTE_ROWS],
            "predicted_withdrawn_count": len(withdrawn),
            "predicted_prefixes_added": added[:_MAX_ROUTE_ROWS],
            "predicted_added_count": len(added),
            "predicted_rows_changed": changed[:_MAX_ROUTE_ROWS],
            "predicted_changed_count": len(changed),
            "validation": before.validation[:_MAX_ROUTE_ROWS],
            "validation_count": len(before.validation),
            "validation_summary": summary,
            "gaps_before": before.gaps,
            "gaps_after": after.gaps,
            "rounds_before": before.rounds,
            "rounds_after": after.rounds,
            "convergence_before": before.convergence,
            "convergence_after": after.convergence,
        }
    )
    unsettled_reason = (
        "the routing calculation did not settle (" + "; ".join(unsettled) + "), so its rows are the state "
        "at the last round and not an answer; both sides of every flow were traced over the collected "
        "routes, and the routing intents' effect on a flow is not established"
        if unsettled
        else None
    )
    return _RoutingPrediction(
        body,
        before_fib=before.fib,
        after_fib=after.fib,
        unsettled=unsettled_reason,
        basis=_RoutingBasis(
            validation=tuple(before.validation),
            gaps=tuple(after.gaps),
            context_devices={
                str(c["uid"]): str(c["device_uid"])
                for c in graph.input.contexts
                if c.get("uid") and c.get("device_uid")
            },
        ),
    )


def _walk_report(
    depth_requested: int,
    depth: int,
    reached: int,
    levels: list[dict[str, Any]],
    open_at_the_last_level: int,
    boundary: dict[str, Any] | None,
) -> dict[str, Any]:
    """Report how far the walk went, what stopped it, and what each limit cut.

    `levels_walked` is the last level that withdrew a route. `limits` lists
    the limits that cut the answer. The depth limit counts as a cut only when
    the last level strands a prefix.
    """
    limits: list[str] = []
    if open_at_the_last_level:
        limits.append("depth")
    if boundary is not None and boundary["stopped_the_walk"]:
        limits.append("site_boundary")

    report: dict[str, Any] = {
        "depth_requested": depth_requested,
        "depth": depth,
        "depth_cap": _MAX_WITHDRAWAL_DEPTH,
        "depth_clamped": depth_requested > depth,
        "levels_walked": reached,
        "levels": levels,
        "level_count": len(levels),
        "complete": not limits,
        "limits": limits,
        "prefixes_not_followed_at_the_depth_limit": open_at_the_last_level if "depth" in limits else 0,
        "prefixes_not_followed_at_the_site_boundary": (
            boundary["prefixes_not_followed"] if boundary is not None else 0
        ),
        "definition": (
            "level 1 is a route whose recorded next hop the change denies; level n after it is a "
            "route whose next hop resolves only through a prefix that lost every recorded next "
            "hop at a level below n, read against that VRF's own recorded prefixes. A next hop "
            "no recorded prefix covers is left alone. A prefix is stranded once and not "
            "revisited, so a dependency cycle ends the walk rather than extending it"
        ),
    }
    if not limits:
        report["note"] = (
            f"the walk ran to level {reached} and the level after it would have had nothing to "
            "follow, so this is the whole of the recorded next-hop consequence"
        )
    else:
        cut = []
        if "depth" in limits:
            cut.append(
                f"the depth limit of {depth} stopped it with {open_at_the_last_level} prefix(es) "
                "stranded at the last level, whose own dependents were not followed"
            )
        if "site_boundary" in limits and boundary is not None:
            cut.append(
                f"the site boundary stopped it at {boundary['vrfs_not_followed_count']} VRF(s) "
                f"outside the selected sites, holding {boundary['prefixes_not_followed']} "
                "prefix(es) that lose a recorded next hop"
            )
        report["note"] = (
            "this answer is smaller than the consequence: " + "; ".join(cut) + ". Raise depth or "
            "widen the sites to see the rest"
        )
    return report


def _withdrawal_headline(
    withdrawal: dict[str, Any] | None, peers: list[dict[str, Any]], walk: dict[str, Any]
) -> str:
    """Return the routing follow-on as one sentence of counts, at the prefix
    level.

    If a limit stopped the walk, the sentence states it, as `walk` does. At
    depth 1 without a site boundary cut, the sentence does not state it.
    """
    if withdrawal is None:
        head = "no recorded route uses a denied address as a next hop"
        if peers:
            head += f"; {len(peers)} BGP session(s) are to one"
    else:
        prefixes = withdrawal["prefix_count"]
        stranded = withdrawal["prefixes_with_no_next_hop_left"]
        vrfs = len(withdrawal["vrfs"])
        head = (
            f"{prefixes} prefix(es) across {vrfs} VRF(s) lose a recorded next hop, "
            f"{stranded} of them every next hop the snapshot records"
        )
        if walk["levels_walked"] > 1:
            head += f", following the dependency chain {walk['levels_walked']} levels deep"
    narrowed = walk["depth"] > _DEFAULT_WITHDRAWAL_DEPTH or "site_boundary" in walk["limits"]
    if not walk["complete"] and narrowed:
        head += (
            "; the walk was stopped by "
            + " and ".join(
                "the depth limit" if limit == "depth" else "the site boundary" for limit in walk["limits"]
            )
            + ", so this is part of the consequence and not all of it"
        )
    return head


def _route_consequence(
    changes: ChangeSet,
    denied: DeniedAddresses,
    routes: _RouteTable | None,
    session: Any,
    errors: ErrorSink,
    depth_requested: int = _DEFAULT_WITHDRAWAL_DEPTH,
    depth: int = _DEFAULT_WITHDRAWAL_DEPTH,
    scope: SiteScope | None = None,
    row_limit: int | None = _MAX_ROUTE_ROWS,
) -> dict[str, Any] | None:
    """Report what the change set does to the routes that the snapshot records.

    The report applies the next-hop withdrawal to the route edges of the graph
    (`_withdrawn_because`). A `BgpSession` record for a denied address is
    reported as an address dependency (`bgp_sessions_to_a_denied_address`).
    `implied_intents` stays empty. The protocol-specific prediction
    (`_bgp_prediction`) runs only for an explicit routing intent
    (`ROUTING_KINDS`).

    `depth` follows the route dependency chain past the first level. `scope`
    narrows the walk to a set of sites. The report states both in `walk`.

    `sites_affected` lists the sites of the VRFs of the withdrawal.
    `vrfs_with_no_recorded_site` counts each VRF for which the join finds no
    `LOCATED_IN` chain.

    `routes` is the recorded route table (`_RouteTable`), read for the same
    denied addresses. It is None when nothing is denied.

    Returns None when the change set denies no address, or when no route is
    withdrawn, no BGP session peers with a denied address, no static route is
    kept and no site filter is in force.
    """
    if not denied.any_denied() or routes is None:
        return None
    scope = scope if scope is not None else SiteScope(None, (), ())

    in_scope = {key: entries for key, entries in routes.groups.items() if scope.holds(key[0])}
    withdrawal, levels, reached, still_open = _next_hop_withdrawal(in_scope, routes, denied, depth, row_limit)
    boundary = _boundary_report(routes.contexts, routes.groups, denied, scope) if scope.in_force else None
    walk = _walk_report(depth_requested, depth, reached, levels, still_open, boundary)

    relevant = [row for row in routes.relevant if scope.holds(str(row.get("context_uid") or ""))]
    used = [row for row in relevant if _withdrawn_because(row, denied)]
    kept_static = [row for row in relevant if _static_route_kept(row, denied)]
    peers = [
        row
        for row in pathmod._read(session, _BGP_PEERS)
        if _intersect(_intervals([str(row["peer_ip"])]), denied.to_set + denied.from_set)
    ]
    if withdrawal is None and not peers and not kept_static and boundary is None:
        return None

    sites_affected, vrfs_with_no_recorded_site = _sites_for_vrfs(
        session, (v["context_uid"] for v in (withdrawal["vrfs"] if withdrawal else ()))
    )

    body: dict[str, Any] = {
        "headline": _withdrawal_headline(withdrawal, peers, walk),
        "evaluation": "address-dependency",
        "basis": (
            "the route edges and BGP peerings the snapshot records, matched against the "
            "addresses the change set denies. This is address-dependency analysis: it says "
            "which recorded routes and sessions name a denied address, not an evaluation of "
            "effective policy -- service, rule position, shadowing and traversal are not read "
            "here (that is `denied_directions()` in `hst.simul.fw_overlay`, which this "
            "reads from). The protocol that learned a route is a property on the edge and "
            "does not enter this."
        ),
        "direction_rule": (
            "denying traffic to an address marks it a dependency for every recorded route and "
            "session that uses it as a next hop; denying traffic from an address marks it a "
            "dependency for a LEARNED_ROUTE, whose presence depends on the exchange with it, "
            "and leaves a STATIC_ROUTE out of the dependency; denying both marks every route "
            "and session through it. This states which routes and sessions depend on the "
            "address, not which ones the change actually withdraws."
        ),
        "denied_addresses": {
            "traffic_to": sorted(set(denied.to_specs)),
            "traffic_from": sorted(set(denied.from_specs)),
        },
        "next_hop_withdrawal": withdrawal,
        "sites_affected": sites_affected,
        "sites_affected_count": len(sites_affected),
        "vrfs_with_no_recorded_site": vrfs_with_no_recorded_site,
        "walk": walk,
        "recorded_routes_via_a_denied_next_hop": used if row_limit is None else used[:row_limit],
        "recorded_route_count": len(used),
        "bgp_sessions_to_a_denied_address": peers,
        "bgp_sessions_to_a_denied_address_note": (
            "these BGP sessions peer through an address the change set denies; that is an "
            "address dependency, not a prediction that the session goes down. Whether it "
            "actually does needs a context-scoped control-plane evaluation -- service, rule "
            "position, shadowing and which VRF the session runs in -- that this address match "
            "does not perform"
        ),
        "implied_intents": [],
        "predicted_prefixes_withdrawn": [],
        "predicted_withdrawn_count": 0,
        "predicted_prefixes_added": [],
        "predicted_added_count": 0,
        "predicted_rows_changed": [],
        "predicted_changed_count": 0,
        "scopes_predicted": [],
        "bgp_prediction": (
            "bgp_sessions_to_a_denied_address is the address dependency: the BGP sessions that "
            "peer through a denied address, without service, position, shadowing or "
            "control-plane evaluation. implied_intents stays empty and predicted_prefixes_"
            "withdrawn, predicted_prefixes_added, predicted_rows_changed and scopes_predicted "
            "are not computed from that dependency -- an address match is not a control-plane "
            "shutdown. The route engine's protocol-specific prediction runs only for an "
            "explicit `bgp_session.shut` intent the caller supplies, when the change-intent "
            "catalog carries that kind. The next-hop withdrawal above is a separate, "
            "route-edge fact and does not depend on any of this."
        ),
    }
    if boundary is not None:
        body["site_scope"] = boundary
    if row_limit is not None and len(used) > row_limit:
        body["recorded_routes_truncated"] = (
            f"{len(used)} recorded routes lose a denied next hop; {row_limit} of them are listed"
        )
    if kept_static:
        body["static_routes_kept_under_a_source_side_deny"] = (
            kept_static if row_limit is None else kept_static[:row_limit]
        )
    return body


# --- deriving the rulebase from the device an intent names ----------------

# Maps `type(z)` of a zone-pair binding to the side of a rule that the binding
# governs. A rulebase bound by FROM_ZONE holds a source-side deny. TO_ZONE is
# the destination side.
_SIDE_OF_ZONE_EDGE = {"FROM_ZONE": "source", "TO_ZONE": "destination"}


def _device_bindings(session: Any, device: str) -> list[dict[str, Any]]:
    """Return every rulebase that the snapshot binds to one device, with its binding."""
    out: list[dict[str, Any]] = []
    for row in pathmod._read(session, _DEVICE_RULEBASES, dev=device):
        if not row.get("rb_uid"):
            continue
        out.append(
            {
                "rulebase": str(row["rb_uid"]),
                "rulebase_name": row.get("rb_name"),
                "binding": str(row.get("binding") or ""),
                "side": _SIDE_OF_ZONE_EDGE.get(str(row.get("side") or "")),
                "interface": str(row["iface"]) if row.get("iface") else None,
            }
        )
    return out


def _interfaces_serving(session: Any, device: str, specs: Sequence[str]) -> list[dict[str, Any]]:
    """Return the interfaces on `device` that the snapshot records as serving any
    of `specs`.

    An interface serves an address in 3 recorded cases. The address of the
    interface is in the same connected prefix. An endpoint with the address is
    on the bridge domain that the VLAN of the interface realizes. An endpoint
    with the address is attached to the interface. No other case counts.
    """
    where = _intervals(list(specs))
    if not where:
        return []
    found: list[dict[str, Any]] = []
    for row in pathmod._read(session, _DEVICE_SERVED_ADDRESSES, dev=device):
        served = [
            str(a)
            for key in ("prefixes", "bridge_domain_ips", "attached_ips")
            for a in (row.get(key) or ())
            if a
        ]
        hits = sorted({s for s in served if _intersect(_intervals([s]), where)})
        if hits:
            found.append({"uid": str(row["uid"]), "name": row.get("name"), "serves": hits})
    return found


def _binding_satisfies(binding: Mapping[str, Any], side: str, interfaces: set[str]) -> bool:
    """Return whether one binding puts its rulebase on `side` of the named traffic.

    A binding scoped to the other direction fails. A binding without a zone
    governs both directions. A binding that reaches the device through an
    interface must reach it through one of `interfaces`. A binding without an
    interface governs the whole device and passes.
    """
    if binding["side"] is not None and binding["side"] != side:
        return False
    return binding["interface"] is None or binding["interface"] in interfaces


def _derive_rulebases(
    session: Any, index: int, params: Mapping[str, Any], catalog: Catalog, errors: ErrorSink
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Derive the rulebases on a device that decide the traffic that an intent
    names.

    The candidates are the bindings of the device, narrowed by the sides that
    the intent states. A deny whose source is a set of addresses goes to the
    rulebases whose source side holds an interface on the device that serves
    those addresses. The destination side is narrowed the same way. A side
    stated as `any`, or a side that no interface on the device serves, does not
    narrow the candidates. Every remaining candidate is returned.
    """
    device = str(params["device"])
    bindings = _device_bindings(session, device)
    serving: dict[str, list[dict[str, Any]]] = {}
    for side in ("source", "destination"):
        specs, is_any = _address_side(side, params.get(side), catalog)
        if is_any or not specs:
            continue
        found = _interfaces_serving(session, device, specs)
        if found:
            serving[side] = found

    by_rulebase: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings:
        by_rulebase.setdefault(binding["rulebase"], []).append(binding)

    if serving:
        chosen = [
            uid
            for uid, rows in sorted(by_rulebase.items())
            if all(
                any(_binding_satisfies(r, side, {i["uid"] for i in found}) for r in rows)
                for side, found in serving.items()
            )
        ]
        basis = f"the rulebases bound to {device} whose " + " and ".join(
            f"{side} side holds an interface on the device serving "
            f"{', '.join(sorted({s for i in found for s in i['serves']}))}"
            for side, found in sorted(serving.items())
        )
    else:
        chosen = sorted(by_rulebase)
        basis = (
            f"every rulebase the snapshot binds to {device}: no interface on the device is "
            "recorded as serving the addresses this intent states, so nothing narrows them"
        )

    report: dict[str, Any] = {
        "intent_index": index,
        "device": device,
        "rulebases": [
            {
                "uid": uid,
                "name": next((r["rulebase_name"] for r in by_rulebase[uid] if r["rulebase_name"]), None),
                "bound_by": [
                    {"binding": r["binding"], "side": r["side"], "interface": r["interface"]}
                    for r in by_rulebase[uid]
                ],
            }
            for uid in chosen
        ],
        "rulebases_bound_to_the_device": sorted(by_rulebase),
        "interfaces_serving_the_stated_addresses": dict(sorted(serving.items())),
        "basis": basis,
    }
    if not chosen:
        detail = (
            f"the intent names device {device} instead of a rulebase, and no rulebase in this "
            "snapshot could be derived from it: "
            + (
                "the snapshot binds no rulebase to that device at all -- nothing on it enforces "
                "one, no zone pair binds one to an interface on it, no object on it is protected "
                "by one and no rulebase it enforces jumps to one"
                if not by_rulebase
                else "the device is bound to "
                + ", ".join(sorted(by_rulebase))
                + ", and none of them holds an interface serving the stated addresses on the side "
                "the intent denies"
            )
            + ". The intent was not applied; name a rulebase to state which one this change is to."
        )
        errors.report("rulebase-not-derivable-from-the-device", detail, device)
        report["model_error"] = "rulebase-not-derivable-from-the-device"
    return report["rulebases"], report


def _resolve_intent_rulebases(
    session: Any, intents: Sequence[Mapping[str, Any]], catalog: Catalog, errors: ErrorSink
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Expand every firewall intent of the change set that names a device.

    An intent that names its rulebase passes unchanged. An intent that names a
    device becomes one intent per rulebase derived from that device. An intent
    from which no rulebase is derived is dropped, with the model error of
    `_derive_rulebases`.
    """
    out: list[dict[str, Any]] = []
    derivations: list[dict[str, Any]] = []
    for index, raw in enumerate(intents):
        params = dict(raw.get("params") or {})
        kind = str(raw.get("kind", "")).strip()
        if kind not in FW_KINDS or params.get("rulebase") or not params.get("device"):
            out.append(dict(raw))
            continue
        if kind != "fw_rule.add":
            raise ProposalError(
                f"intent {index} ({kind}) names a rule uid, which belongs to one rulebase, so "
                "the rulebase cannot be derived from a device; state the rulebase that holds it"
            )
        rulebases, report = _derive_rulebases(session, index, params, catalog, errors)
        derivations.append(report)
        for entry in rulebases:
            out.append({**dict(raw), "params": {**params, "rulebase": entry["uid"]}})
    return out, derivations


# --- which flows to trace -------------------------------------------------


def _device_hostnames(session: Any, uids: set[str]) -> dict[str, str]:
    """Map the uid of each device with a recorded hostname to the hostname. A
    device without a hostname is absent."""
    if not uids:
        return {}
    rows = pathmod._read(session, _DEVICE_HOSTNAMES, uids=sorted(uids))
    return {str(r["uid"]): str(r["hostname"]) for r in rows if r.get("hostname")}


def _changed_devices(session: Any, changes: ChangeSet, errors: ErrorSink) -> set[str]:
    """Return the uids of the devices that the change set alters.

    A firewall intent names a rulebase. Its devices are the devices that the
    snapshot binds the rulebase to through any edge of `_RULEBASE_DEVICES`. A
    NAT intent names the device. A zone move names an interface, and its device
    is the device of the interface. A routing intent adds the devices of the
    contexts that it scopes (`_routing_scope`). A rulebase or an interface that
    the snapshot places on no device is reported.
    """
    devices: set[str] = set()
    for intent in changes.intents:
        params = intent.params
        if intent.kind in FW_KINDS and params.get("rulebase"):
            rows = pathmod._read(session, _RULEBASE_DEVICES, rb=str(params["rulebase"]))
            if not rows:
                errors.report(
                    "changed-rulebase-has-no-enforcement-point",
                    f"rulebase {params['rulebase']!r} has no recorded enforcement point in this "
                    "snapshot: nothing enforces it, no zone pair binds it, no object is protected "
                    "by it and no rulebase jumps to it, so whether a flow crosses the change could "
                    "not be established for it",
                    str(params["rulebase"]),
                )
            devices.update(str(r["uid"]) for r in rows if r.get("uid"))
        elif intent.kind in NAT_KINDS and params.get("device"):
            devices.add(str(params["device"]))
        elif intent.kind in ZONE_KINDS and params.get("interface"):
            rows = pathmod._read(session, _INTERFACE_DEVICE, iface=str(params["interface"]))
            if not rows:
                errors.report(
                    "changed-interface-has-no-device",
                    f"interface {params['interface']!r} is on no Device in this snapshot, so "
                    "whether a flow crosses the change could not be established for it",
                    str(params["interface"]),
                )
            devices.update(str(r["uid"]) for r in rows if r.get("uid"))
    routing = [intent for intent in changes.intents if intent.kind in ROUTING_KINDS]
    if routing:
        # A routing intent names a session or a router id. Its devices are the
        # devices of the contexts that it scopes.
        _contexts, on = _routing_scope(session, routing, ErrorSink())
        devices.update(on)
    return devices


def _default_route(spec: str) -> str:
    """Return the default route of the address family of `spec`."""
    return "::/0" if ":" in spec else _DEFAULT_ROUTE


def _served_sources(session: Any, devices: Iterable[str]) -> list[str]:
    """Return one address set behind each interface of the changed devices.

    The address set is the connected prefix that the interface serves. Without
    one, it is the first endpoint address that the snapshot records behind the
    interface (`_DEVICE_SERVED_ADDRESSES`). A flow from such a source towards a
    denied address crosses a changed device."""
    out: list[str] = []
    for device in sorted(devices):
        for row in pathmod._read(session, _DEVICE_SERVED_ADDRESSES, dev=device):
            for key in ("prefixes", "bridge_domain_ips", "attached_ips"):
                first = next((str(a) for a in (row.get(key) or ()) if a), None)
                if first:
                    out.append(first)
                    break
    return list(dict.fromkeys(out))


def _derived_flows(
    denied: DeniedAddresses,
    route_rows: Iterable[Mapping[str, Any]],
    inside: Sequence[str] = (),
) -> tuple[list[dict[str, Any]], int]:
    """Derive flows from the change set for a caller that supplied none.

    A rule on a router decides only the traffic that crosses that router. Each
    denied address is paired with traffic that crosses it. An address denied as
    a source is the source of its flows. Their destinations are the default
    route of its family, the prefixes that the snapshot records as served
    through it, and the addresses that the change set denies as destinations.
    An address denied as a destination is the destination of its flows. Their
    sources are the default route of its family and each address set of
    `inside` that does not contain the address. `inside` holds an address set
    behind each interface of the changed devices.

    `_MAX_DERIVED_FLOWS` bounds the flows. Returns the flows and how many
    candidates the cap left untraced.

    `route_rows` needs to hold only the routes whose next hop is a denied
    address (`_RouteTable.relevant`). Any other route is skipped.
    """
    served: dict[str, list[str]] = {}
    for row in route_rows:
        next_hop = str(row.get("next_hop") or "").strip()
        prefix = str(row.get("prefix") or "").strip()
        if not next_hop or not prefix:
            continue
        where = _intervals([next_hop])
        if not where or not _intersect(where, denied.to_set + denied.from_set):
            continue
        if prefix not in served.setdefault(next_hop, []):
            served[next_hop].append(prefix)

    def apart(a: str, b: str) -> bool:
        return not _intersect(_intervals([a]), _intervals([b]))

    # The candidates interleave the flows of the denied addresses. The cap cuts
    # the tail of the flows of every denied address equally.
    per_address: list[list[dict[str, Any]]] = []
    for source in sorted(set(denied.from_specs)):
        destinations = [
            _default_route(source),
            *sorted(served.get(source, ())),
            *(t for t in sorted(set(denied.to_specs)) if apart(source, t)),
        ]
        per_address.append(
            [{"src": source, "dst": destination} for destination in dict.fromkeys(destinations)]
        )
    for target in sorted(set(denied.to_specs)):
        sources = [
            _default_route(target),
            *(p for p in inside if (":" in p) == (":" in target) and apart(p, target)),
        ]
        per_address.append([{"src": source, "dst": target} for source in dict.fromkeys(sources)])
    candidates: list[dict[str, Any]] = []
    for column in range(max((len(f) for f in per_address), default=0)):
        candidates.extend(flows[column] for flows in per_address if column < len(flows))
    return candidates[:_MAX_DERIVED_FLOWS], max(0, len(candidates) - _MAX_DERIVED_FLOWS)


def _crossed_devices(results: list[dict[str, Any]]) -> set[str] | None:
    """Return the devices on the hops of the traces, or None when the traces have
    no hop."""
    seen: set[str] = set()
    drew_hops = False
    for result in results:
        hops = result.get("hops") or []
        drew_hops = drew_hops or bool(hops)
        seen.update(str(h.get("uid")) for h in hops if str(h.get("kind")) == "Device")
    return seen if drew_hops else None


def _traverses(results: list[dict[str, Any]], devices: set[str]) -> bool | None:
    """Return whether a traced flow crosses one of the devices that the change
    set alters.

    The result is None when the change set is placed on no device, or when the
    traces have no hop.
    """
    if not devices:
        return None
    seen: set[str] = set()
    drew_hops = False
    for result in results:
        hops = result.get("hops") or []
        if hops:
            drew_hops = True
        seen.update(str(h.get("uid")) for h in hops if str(h.get("kind")) == "Device")
    if not drew_hops:
        return None
    return bool(seen & devices)


def simulate_change(
    session: Any,
    *,
    intents: list[dict[str, Any]],
    flows: list[dict[str, Any]] | None = None,
    depth: int | None = None,
    sites: list[str] | None = None,
    detail: bool = False,
    rib: Any | None = None,
    bgp: Any | None = None,
    ospf: Any | None = None,
    source_kinds: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Trace every flow twice, as collected and with the change set applied.

    `session` must be pinned (`hst.path.pinned`). For each flow, the answer
    states the verdict before and the verdict after, each with the rule or the
    NAT rule that decides it. It also states the routing follow-on. The routing
    follow-on lists the next hops of each affected prefix before and after the
    change.

    Each flow has `paths`. These are the legs of the 2 traces, paired by path,
    grouped by their shared outcome, capped and counted
    (`fw_overlay.compare_paths`). The counts are summed over the flows into
    `path_count_before`, `path_count_after`, `paths_blocked_before`,
    `paths_blocked_after` and `paths_changed`.

    A firewall intent can name a `device` in place of a `rulebase`. The
    rulebases are then derived from the bindings of the snapshot for that
    device (`_resolve_intent_rulebases`) before any intent is parsed, and every
    candidate is applied. The derivation is reported under `rulebases_derived`.
    An intent that names its rulebase is unchanged.

    With `flows` empty or omitted, candidates are derived from the change set
    (`_derived_flows`). A flow that crosses none of the devices that the change
    set alters gets a named model error.

    `depth` follows the route dependency chain past the first level, up to
    `_MAX_WITHDRAWAL_DEPTH`. `sites` narrows the walk to the VRFs that the
    snapshot places in those sites. `routing_consequence.walk` states both,
    with the counts per level, whether a limit stopped the walk, and what each
    limit cut. `walk.complete` is false when a limit stopped the walk.

    `detail` is on for the export only. With `detail`, each flow also has
    `path_rows` (one row per compared path, ungrouped), and the routing
    follow-on lists every affected prefix.

    A change set that cannot be applied raises a `ProposalError`.

    A flow can also have `mtu`, the request `{mode, ip_packet_bytes, ipv4_df,
    traffic_class}` of `GET /api/path` and of the `reach_trace` tool. It is
    validated the same way (`_trace_flow`). The
    before and after path rows (`fw_overlay.path_rows`) of such a flow hold
    `mtu_outcome`, `mtu_known_ceiling_bytes`, `mtu_bottleneck` and
    `mtu_uncovered`. A group whose MTU outcome differs is `changed`. Each group
    also holds `mtu_before` and `mtu_after`. `mtu_subjects` of the answer lists
    every interface that an `interface.set_mtu` intent of the change set
    touched, and the physical Port of the interface where the catalog knows
    one.

    `rib` is a RibSource bounded to the same run as `session`, as the `rib`
    parameter of `hst.path.trace`. Every flow trace reads it. The route table
    of the next-hop withdrawal merges the recorded route edges of the graph
    with the side-store routes of the same devices.

    A routing intent (`ROUTING_KINDS`) is a BGP session shutdown, an OSPF
    interface cost or a lost OSPF adjacency. It runs the integrated routing
    calculation before and after the change set (`_bgp_prediction`), reported
    under `routing_prediction`. For every table that the calculation covers,
    the second trace of every flow reads the after-FIB of the calculation in
    place of the route edges of the graph and the observed RIB. `bgp` and
    `ospf` are the observation readers that seed the calculation (`BgpSource`
    and `OspfSource`, bound to the same snapshot as `rib`). Without them, the
    paths of the peers and the link-state databases are not observed. The
    calculation runs before any trace. The 3 readers share one store that
    admits one open reader at a time.

    `source_kinds` is passed to `read_catalog`. It maps the name of each
    configured source of the twin to its collector kind, for the
    collected-evidence check of `interface.set_mtu` validation
    (`fw_overlay._validate_interface_set_mtu`). Without it, that check is not
    performed.
    """
    depth_requested, depth_run = _normalize_depth(depth)
    errors = ErrorSink()
    catalog = read_catalog(session, intents, source_kinds)
    resolved, derivations = _resolve_intent_rulebases(session, intents, catalog, errors)
    parsed: list[Intent] = parse_intents(resolved, catalog)
    changes = ChangeSet(intents=parsed, catalog=catalog, errors=errors)
    overlaid = OverlaySession(session, changes)

    routed: _RoutingPrediction | None = None
    before_fib: Any | None = None
    after_fib: Any | None = None
    if any(intent.kind in ROUTING_KINDS for intent in parsed):
        routed = _bgp_prediction(session, parsed, errors, rib=rib, bgp=bgp, ospf=ospf)
        if routed.unsettled:
            errors.report("routing-after-state-unsettled", routed.unsettled, None)
        elif routed.after_fib is not None:
            before_fib, after_fib = routed.before_fib, routed.after_fib
            changes.route_rows = _fib_route_rows(after_fib)
    prediction = routed.body if routed is not None else None
    before_session: Any = session
    if before_fib is not None:
        before_changes = ChangeSet(intents=[], catalog=catalog, errors=ErrorSink())
        before_changes.route_rows = _fib_route_rows(before_fib)
        before_session = OverlaySession(session, before_changes)

    denied = changes.denied_directions()
    if not denied.any_denied():
        unevaluated = changes.unevaluated_for_routing()
        if unevaluated:
            kinds = sorted({intent.kind for intent in unevaluated})
            errors.report(
                "routing-consequence-not-evaluated",
                "the routing follow-on is derived from fw_rule.add deny intents alone; this "
                f"change set also carries {', '.join(kinds)} intent(s), whose effect on a "
                "route was not evaluated, so its absence here is not a statement that the "
                "change denies nothing",
                ", ".join(kinds),
            )
    routes = _RouteTable(session, rib, denied) if denied.any_denied() else None

    devices = _changed_devices(session, changes, errors)
    supplied = list(flows or ())
    derived = False
    untraced = 0
    if not supplied:
        supplied, untraced = _derived_flows(
            denied,
            routes.relevant if routes is not None else (),
            _served_sources(session, devices) if denied.to_specs else (),
        )
        derived = True
        if not supplied:
            errors.report(
                "no-flow-to-trace",
                "no flows were supplied and none could be derived from the change set: it "
                "denies no specific address, so there is no traffic the snapshot names for it "
                "to be traced against",
                None,
            )

    hostnames = _device_hostnames(session, devices)
    changed_names = ", ".join(sorted(hostnames.get(uid, uid) for uid in devices))
    changed_rulebases = changes.changed_rulebases()
    results: list[dict[str, Any]] = []
    undecided = 0
    # `ChangeSet.rewrite` matches no text of the gateway read. One gateway load
    # serves both sides of every flow.
    gateways: list[dict[str, Any]] | None = None
    for flow in supplied:
        if not flow.get("src") or not flow.get("dst"):
            raise ProposalError("every flow needs a src and a dst")
        if gateways is None:
            gateways = pathmod.load_gateways(session)
        before_rib = _ScopedRib(before_fib, rib) if before_fib is not None else rib
        after_rib = _ScopedRib(after_fib, rib) if after_fib is not None else rib
        before_raw = _trace_flow(before_session, flow, before_rib, gateways=gateways)
        after_raw = _trace_flow(overlaid, flow, after_rib, gateways=gateways)
        before = _flow_summary(before_raw)
        after = _flow_summary(after_raw)
        before_rows = path_rows(before_raw.get("legs") or [], changed_rulebases, mtu=before_raw.get("mtu"))
        after_rows = path_rows(after_raw.get("legs") or [], changed_rulebases, mtu=after_raw.get("mtu"))
        paths = compare_paths(before_rows, after_rows)
        entry: dict[str, Any] = {
            "flow": dict(flow),
            "before": before,
            "after": after,
            "result_changed": (before["result"], before["detail"]) != (after["result"], after["detail"]),
            "blocked_changed": before["blocked"] != after["blocked"],
            "paths": paths,
        }
        if detail:
            entry["path_rows"] = pair_paths(before_rows, after_rows)
        crosses = _traverses([before_raw, after_raw], devices)
        entry["crosses_a_changed_device"] = crosses
        reasons = _flow_basis_reasons(routed, flow, _crossed_devices([before_raw, after_raw]))
        if derived and not any(r["changed_rulebase_applies"] for r in after_rows):
            reasons.append(
                "no leg of the after trace is decided by a rulebase the change set alters, so this "
                "flow says nothing about the change"
            )
            undecided += 1
        entry["basis_uncertain"] = bool(reasons)
        if reasons:
            entry["basis_uncertain_reasons"] = reasons
        if crosses is False:
            reason = (
                f"the flow {flow['src']} to {flow['dst']} crosses none of the devices this "
                f"change set alters ({changed_names}), so the change was never "
                "consulted on it; its result says nothing about the change, and a flow whose "
                "path crosses one of those devices has to be traced instead"
            )
            entry["model_error"] = {
                "kind": "flow-does-not-cross-the-changed-device",
                "detail": reason,
                "subject": f"{flow['src']} -> {flow['dst']}",
            }
            errors.report("flow-does-not-cross-the-changed-device", reason, f"{flow['src']} -> {flow['dst']}")
        elif reasons:
            # A flow whose comparison basis is not established gets this model
            # error, whatever results the 2 sides show.
            entry["model_error"] = {
                "kind": "flow-result-not-established",
                "detail": "; ".join(reasons),
                "subject": f"{flow['src']} -> {flow['dst']}",
            }
        results.append(entry)
    uncertain = [r for r in results if r["basis_uncertain"]]
    if uncertain:
        errors.report(
            "flow-result-not-established",
            f"{len(uncertain)} of {len(results)} flow(s) are not counted as changed or unchanged: "
            "the basis of their comparison is not established (see basis_uncertain_reasons on each)",
            None,
        )
    if undecided:
        errors.report(
            "derived-flows-not-decided-by-the-change",
            f"{undecided} of {len(results)} derived flow(s) crossed no rulebase the change set "
            "alters, so their results say nothing about the change; a flow that exercises the "
            "change has to be supplied",
            None,
        )

    counts = [r["paths"] for r in results]
    body: dict[str, Any] = {
        "intents": [i.as_dict() for i in parsed],
        "flow_count": len(results),
        # A flow whose comparison basis is not established (`basis_uncertain`)
        # is counted in `results_not_established`.
        "results_changed": sum(1 for r in results if r["result_changed"] and not r["basis_uncertain"]),
        "results_not_established": sum(1 for r in results if r["basis_uncertain"]),
        "path_count_before": sum(c["path_count_before"] for c in counts),
        "path_count_after": sum(c["path_count_after"] for c in counts),
        "paths_blocked_before": sum(c["blocked_before"] for c in counts),
        "paths_blocked_after": sum(c["blocked_after"] for c in counts),
        "paths_changed": sum(r["paths"]["changed"] for r in results if not r["basis_uncertain"]),
        "flows": results,
        "changed_devices": sorted(devices),
        # The changed interfaces, and the physical Port of each where the
        # catalog knows one (`ChangeSet.mtu_subjects`).
        "mtu_subjects": sorted(changes.mtu_subjects()),
    }
    if hostnames:
        # The key is absent when no changed device records a hostname.
        body["changed_device_hostnames"] = dict(sorted(hostnames.items()))
    if derivations:
        body["rulebases_derived"] = derivations
        body["rulebase_derivation"] = (
            "one or more intents named a device instead of a rulebase, so the rulebases were "
            "derived from the snapshot's own bindings for that device. rulebases_derived lists, "
            "per intent, every rulebase derived, how the snapshot binds each one to the device, "
            "the interfaces on the device recorded as serving the addresses the intent states, "
            "and the basis the choice rests on. Every candidate was applied, so an intent that "
            "derived more than one rulebase was evaluated against all of them; the intents list "
            "above is the expansion that was evaluated."
        )
    if derived and results:
        body["flows_derived"] = (
            "no flows were supplied, so a bounded, representative set was derived from the "
            "change set: an address denied as a source is the source, towards the default "
            "route of its family, the prefixes the snapshot records as served through it and "
            "the addresses denied as destinations; an address denied as a destination is the "
            "destination, from the outside and from the prefixes behind the other interfaces "
            "of the changed devices. The default route stands for every address not named "
            "individually, and each flow's paths are grouped and counted, so this is a sample "
            "with counts rather than an enumeration. A flow that crosses no rulebase the "
            "change set alters is marked basis_uncertain"
        )
        body["flows_derived_count"] = len(results)
        body["flows_derived_not_traced"] = untraced
        body["flows_derived_truncated"] = untraced > 0
    scope = _read_site_scope(session, sites) if denied.any_denied() else SiteScope(None, (), ())
    routing = _route_consequence(
        changes,
        denied,
        routes,
        session,
        errors,
        depth_requested=depth_requested,
        depth=depth_run,
        scope=scope,
        row_limit=None if detail else _MAX_ROUTE_ROWS,
    )
    if routing is not None:
        body["routing_consequence"] = routing
    if prediction is not None:
        body["routing_prediction"] = prediction
    body["model_errors"] = errors.as_dicts()
    return body
