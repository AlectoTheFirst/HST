"""The canned query catalog imports no framework.

Each entry has a key, a title, a group, optional params (passed as Cypher
parameters) and the Cypher. A param can have a `picker`, the label and property
whose values the UI offers as suggestions (GET /api/explore/values).
Everything runs in a read-only transaction. Clients can also display the Cypher.

A column whose name starts with `_` does not reach the table. The runner
(app/tables.py) feeds it to the graph payload and drops it from the rows.
Every pattern-shaped query returns its matched nodes and relationships that
way. An aggregating RETURN holds them in collect(...).
"""

from __future__ import annotations

from typing import Any

# The label of a node, without the bookkeeping labels.
_PRIMARY = (
    "[l IN labels(n) WHERE NOT l IN ['Obj','Retired','Gate','Phys','L2','L3',"
    "'Transport','Policy','Service','Workload','App','Cloud','Meta']][0]"
)

# The device a VrfInstance belongs to, for a query that already bound the VRF as `v`.
# The base twin ties a VRF to its device through interface membership only. The BGP
# stage adds OWNED_BY for a VRF configured under `router bgp` that no interface uses.
_VRF_DEVICE = (
    "coalesce(head([(v)-[:OWNED_BY]->(od:Device) WHERE NOT od:Retired | od]), "
    "head([(v)<-[x:IN_VRF]-(:Interface)-[:ON]->(dd:Device) "
    "WHERE x._retired_at IS NULL AND NOT dd:Retired | dd]))"
)

# The optional device filter of the policy and routing queries. The value is a
# hostname, or "" for every device. A caller can leave an `optional` param out,
# and the param binds "".
_DEVICE_PARAM: dict[str, Any] = {
    "name": "device",
    "label": "Device",
    "placeholder": "Any device",
    "optional": True,
    "picker": {"label": "Device", "property": "hostname"},
}

# The hostnames of the devices that enforce rulebase `rb`, by every ownership of
# the schema (assessment/discovery.py `_OWNERS`). The owners are the device, a VRF
# on it, a redundancy group that it is a member of, and an interface on it.
_RULEBASE_HOSTNAMES = (
    "[(rb)<-[e1:ENFORCES]-(d1:Device) WHERE e1._retired_at IS NULL AND NOT d1:Retired | d1.hostname]"
    " + [(rb)<-[e2:ENFORCES]-(:VrfInstance)-[:ON]->(d2:Device)"
    " WHERE e2._retired_at IS NULL AND NOT d2:Retired | d2.hostname]"
    " + [(rb)<-[e3:ENFORCES]-(:RedundancyGroup)<-[:MEMBER_OF]-(d3:Device)"
    " WHERE e3._retired_at IS NULL AND NOT d3:Retired | d3.hostname]"
    " + [(rb)<-[e4:PROTECTED_BY]-(:Interface)-[:ON]->(d4:Device)"
    " WHERE e4._retired_at IS NULL AND NOT d4:Retired | d4.hostname]"
)
_RULEBASE_ON_DEVICE = f"($device = '' OR $device IN {_RULEBASE_HOSTNAMES})"
# The same hostnames, sorted and without duplicates. A device can own a rulebase
# twice, for example directly and through its redundancy group.
_RULEBASE_DEVICES = f"COLLECT {{ UNWIND {_RULEBASE_HOSTNAMES} AS h RETURN DISTINCT h ORDER BY h }}"


def _addresses(any_flag: str, values: str, ranges: str) -> str:
    """One rule side as a list. The list is ['any'] when `any_flag` is true.
    Otherwise it holds the resolved cidr and ip values, then the entries of the
    NetObject `ranges` lists that are not already in it."""
    return (
        f"CASE WHEN coalesce({any_flag}, false) THEN ['any'] ELSE "
        f"reduce(acc = {values}, x IN reduce(f = [], rs IN {ranges} | f + rs) | "
        "CASE WHEN x IN acc THEN acc ELSE acc + x END) END"
    )


# A route policy has no edge to its device. Its uid contains the device uid
# (core/uid.py `route_policy`: rtpol:<device uid>:<kind>:<name>).
_POLICY_ON_DEVICE = (
    "($device = '' OR EXISTS { MATCH (dd:Device:Obj {hostname: $device, collection_ts: $snap}) "
    "WHERE NOT dd:Retired AND pol.uid STARTS WITH 'rtpol:' + dd.uid + ':' })"
)

# The optional metro filter of the Equinix queries. The value is a Fabric metro
# code, or "" for every metro. The Equinix page opens these queries with its own
# metro.
_METRO_PARAM: dict[str, Any] = {
    "name": "metro",
    "label": "Metro",
    "placeholder": "Any metro",
    "optional": True,
    "picker": {"label": "FabricPort", "property": "metro"},
}


def _picker_param(
    name: str, label: str, placeholder: str, node: str, *, optional: bool = False
) -> dict[str, Any]:
    """A param whose form field suggests the `name` values of `node` nodes."""
    param: dict[str, Any] = {
        "name": name,
        "label": label,
        "placeholder": placeholder,
        "picker": {"label": node, "property": "name"},
    }
    if optional:
        param["optional"] = True
    return param


_ZPA_USER_GROUP_PARAM = _picker_param("user_group", "User group", "User group name", "IdentityGroup")
_ZPA_SEGMENT_PARAM = _picker_param("segment", "App segment", "App segment name", "ZpaAppSegment")
_ZPA_CONNECTOR_GROUP_PARAM = _picker_param(
    "connector_group", "App connector group", "App connector group name", "ZpaAppConnectorGroup"
)
_ZIA_LOCATION_PARAM = _picker_param("location", "Location", "Location name", "ZiaLocation")
_ZIA_LOCATION_GROUP_PARAM = _picker_param(
    "location_group", "Location group", "Location group name", "ZiaLocationGroup"
)
_ZIA_DC_PARAM = _picker_param("dc", "Data center", "Zscaler data center", "ZscalerDc")


def _zpa_state(var: str) -> str:
    """The state of a ZPA connector or service edge at collection time. `enabled`
    is configuration and takes precedence. `health` is the control-channel state."""
    return (
        f"CASE WHEN {var}.enabled = false THEN 'disabled' WHEN {var}.health = 'up' THEN 'active' "
        f"WHEN {var}.health = 'down' THEN 'down' ELSE 'unknown' END"
    )


# A connector that can carry traffic is not switched off, and its control channel is up.
_ZPA_CONN_ACTIVE = "coalesce(conn.enabled, true) AND conn.health = 'up'"
_ZPA_CONN_STATE = _zpa_state("conn")
_ZPA_EDGE_STATE = _zpa_state("edge")


# The states of an ended circuit, the same
# list as reasoner.ENDED_CIRCUIT_STATES (tests/test_equinix_queries.py).
_ENDED_CIRCUIT_STATES = "['DEPROVISIONED', 'DELETED', 'CANCELLED']"

# Whether the pinned run holds the link that cable-from-fabric-circuit drew for
# the circuit `vc`. The rule writes the edge from the port that the A end
# realizes (reasoner.py, cable-from-fabric-circuit). The check reads only
# the relationships of that port.
CIRCUIT_CABLED = (
    "EXISTS { MATCH (vc)-[:A_END]->()-[:REALIZED_BY]->(:Port)"
    "-[c:CONNECTED_TO {source: 'equinix-circuit', circuit_uid: vc.uid}]->(:Port) "
    "WHERE c._retired_at IS NULL AND c.collection_ts = $snap }"
)

# A Network Edge device is looked up as an :Obj with equality on uid and on
# collection_ts = $snap. The equalities are in WHERE. The Cypher guard reads
# `{uid: a.x}` in a property map as the label `:a`. Equality on both
# properties of the obj_uid_cts constraint is one index seek and returns at
# most the copy of the pinned run. Every Network Edge node has collection_ts.

# The metro of a circuit end. It is the metro of a FabricPort, or the metro of
# the Network Edge device that an Interface end belongs to.
_END_METRO = (
    "coalesce({e}.metro, head(COLLECT {{ MATCH (dd:Obj) "
    "WHERE dd.uid = {e}.edge_device_uid AND dd.collection_ts = $snap AND dd:Device RETURN dd.metro }}))"
)

# A circuit end as text. The text is the Fabric port name, or the Network Edge
# device and its interface.
_END_NAME = (
    "CASE WHEN {e} IS NULL THEN null "
    "WHEN {e}.edge_device_uid IS NULL THEN {e}.name "
    "ELSE coalesce(head(COLLECT {{ MATCH (dd:Obj) "
    "WHERE dd.uid = {e}.edge_device_uid AND dd.collection_ts = $snap AND dd:Device "
    "RETURN dd.hostname }}), '?')"
    " + ' ' + {e}.name END"
)

QUERIES: list[dict[str, Any]] = [
    {
        "key": "mtu-evidence",
        "group": "inventory",
        "title": "MTU evidence",
        "cypher": """
MATCH (s:Obj)-[r:HAS_MTU]->(o:MtuObservation)
WHERE s.collection_ts=$snap AND r.collection_ts=$snap AND o.collection_ts=$snap
AND NOT s:Retired AND NOT o:Retired AND s._retired_at IS NULL
AND r._retired_at IS NULL AND o._retired_at IS NULL AND o.subject_uid=s.uid
RETURN s.uid AS subject_uid, o.uid AS evidence_uid, o.raw_value_json AS raw_value,
       o.raw_basis AS raw_basis, o.metric AS metric, o.normalized_value AS normalized_value,
       o.assertion_kind AS assertion_kind, o.resolution_state AS resolution_state,
       o.source AS source, o.profile_id AS profile_id
ORDER BY subject_uid, evidence_uid LIMIT 100
""",
    },
    # --- inventory
    {
        "key": "overview",
        "group": "inventory",
        "title": "What is in the graph",
        "cypher": f"""
MATCH (n:Obj) WHERE n.collection_ts = $snap AND NOT n:Retired
WITH {_PRIMARY} AS label
RETURN label, count(*) AS count ORDER BY count DESC
""",
    },
    {
        "key": "devices",
        "group": "inventory",
        "title": "Devices",
        "cypher": """
MATCH (d:Device:Obj) WHERE d.collection_ts = $snap AND NOT d:Retired
OPTIONAL MATCH (d)-[loc:LOCATED_IN]->(s:Site)
RETURN d.hostname AS hostname, d.platform AS platform, d.role AS role,
       d.serial AS serial, d.mgmt_ip AS mgmt_ip, d.os_version AS version, s.code AS site,
       d AS _d, s AS _s, loc AS _loc
ORDER BY hostname
""",
    },
    {
        # The inventory objects a Business Application resolution bound, with the
        # devices that hold them. `uids` is the comma-separated list the
        # application's inventory graph returns (GET .../graph, `library_query`).
        "key": "application-inventory",
        "group": "inventory",
        "title": "Application inventory",
        "description": "the objects an application resolution bound, their addresses and the devices "
        "that hold them, at the pinned run",
        "params": [{"name": "uids", "label": "inventory uids", "placeholder": "ip:10.0.0.5"}],
        "cypher": f"""
UNWIND [u IN split($uids, ',') WHERE trim(u) <> '' | trim(u)] AS wanted
MATCH (n:Obj {{uid: wanted, collection_ts: $snap}}) WHERE NOT n:Retired
OPTIONAL MATCH (n)-[r:HAS_IP|RESOLVES_TO|IN_VRF|IN|ON]->(m:Obj)
WHERE r._retired_at IS NULL AND m.collection_ts = $snap AND NOT m:Retired
OPTIONAL MATCH (n)<-[h:HAS_IP]-(i:Interface)-[o:ON]->(d:Device)
WHERE h._retired_at IS NULL AND o._retired_at IS NULL
  AND d.collection_ts = $snap AND NOT i:Retired AND NOT d:Retired
RETURN n.uid AS uid, {_PRIMARY} AS kind,
       collect(DISTINCT coalesce(m.ip, m.cidr, m.name, m.uid)) AS related,
       collect(DISTINCT d.hostname) AS devices,
       n AS _n, collect(DISTINCT r) AS _r, collect(DISTINCT m) AS _m,
       collect(DISTINCT h) AS _h, collect(DISTINCT i) AS _i,
       collect(DISTINCT o) AS _o, collect(DISTINCT d) AS _d
ORDER BY uid
""",
    },
    {
        "key": "freshness",
        "group": "inventory",
        "title": "Collection freshness",
        "cypher": """
MATCH (r:CollectionRun)
WITH r ORDER BY r.finished_ms DESC
WITH r.source AS source, collect(r)[0] AS last
RETURN source, last.finished AS finished, last.nodes_upserted AS nodes,
       last.rels_upserted AS rels, last.nodes_retired AS retired,
       last.retirement_skipped AS retirement_skipped,
       last.rel_retirement_skipped AS rel_retirement_skipped
ORDER BY source
""",
    },
    {
        "key": "search",
        "group": "inventory",
        "title": "Search by name",
        "params": [{"name": "q", "label": "name or text", "placeholder": "webshop"}],
        "cypher": f"""
CALL db.index.fulltext.queryNodes('obj_names', $q) YIELD node, score
WITH node AS n, score WHERE NOT n:Retired AND n.collection_ts = $snap
RETURN {_PRIMARY} AS type, coalesce(n.name, n.hostname) AS name, n.uid AS uid,
       round(score, 2) AS score, n AS _n
LIMIT 25
""",
    },
    {
        "key": "find-vlan",
        "group": "inventory",
        "title": "VLAN",
        "params": [
            {
                "name": "vid",
                "label": "VLAN id",
                "placeholder": "10",
                "picker": {"label": "VlanInstance", "property": "vid"},
            }
        ],
        "cypher": """
MATCH (v:VlanInstance:Obj) WHERE v.collection_ts = $snap
  AND v.vid = toInteger($vid) AND NOT v:Retired
OPTIONAL MATCH (v)-[rz:REALIZES]->(seg) WHERE seg:BridgeDomain OR seg:L2Segment
OPTIONAL MATCH (i:Interface)-[b:BOUND_TO]->(v)
WHERE b._retired_at IS NULL AND NOT i:Retired
OPTIONAL MATCH (i)-[io:ON]->(d:Device)
OPTIONAL MATCH (i)-[h:HAS_IP]->(ip:IpAddress)
WHERE h._retired_at IS NULL AND NOT ip:Retired
OPTIONAL MATCH (ip)-[pin:IN]->(p:Prefix)
OPTIONAL MATCH (ep:Endpoint)-[:IN]->(seg) WHERE NOT ep:Retired
OPTIONAL MATCH (s:Ssid)-[sb:BRIDGED_TO]->(v) WHERE NOT s:Retired
RETURN v.uid AS vlan, v.vid AS vid, seg.uid AS segment,
       collect(DISTINCT coalesce(d.hostname, '?') + ' ' + i.name) AS interfaces,
       collect(DISTINCT ip.ip) AS gateway_ips, collect(DISTINCT p.cidr) AS prefixes,
       count(DISTINCT ep) AS endpoints, collect(DISTINCT s.name) AS ssids,
       v AS _v, seg AS _seg, rz AS _rz, collect(DISTINCT i) AS _ifs, collect(DISTINCT b) AS _bound,
       collect(DISTINCT d) AS _devs, collect(DISTINCT ip) AS _ips, collect(DISTINCT p) AS _pfx,
       collect(DISTINCT s) AS _ssids, collect(DISTINCT io) AS _on, collect(DISTINCT h) AS _hasip,
       collect(DISTINCT pin) AS _pin, collect(DISTINCT sb) AS _bridged
""",
    },
    {
        "key": "cabling",
        "group": "inventory",
        "title": "Cabling",
        # The device comes first among the graph columns. The result tree roots
        # each row at its first node, and the tree lists devices with their
        # cabled ports under them.
        "cypher": """
MATCH (a:Port:Obj)-[c:CONNECTED_TO]-(b:Port)
WHERE a.collection_ts = $snap AND a.uid < b.uid AND c._retired_at IS NULL
MATCH (a)-[o1:ON]->(da), (b)-[o2:ON]->(db)
RETURN da.hostname AS device_a, a.name AS port_a, db.hostname AS device_b,
       b.name AS port_b, c.source AS source, coalesce(c.derived, false) AS derived,
       da AS _da, a AS _a, c AS _c, b AS _b, db AS _db, o1 AS _o1, o2 AS _o2
ORDER BY device_a, port_a
""",
    },
    # --- topology
    {
        "key": "segments",
        "group": "topology",
        "title": "L2 segments",
        "cypher": """
CALL {
  MATCH (seg:BridgeDomain:Obj) WHERE seg.collection_ts = $snap RETURN seg
  UNION
  MATCH (seg:L2Segment:Obj) WHERE seg.collection_ts = $snap RETURN seg
}
WITH seg WHERE NOT seg:Retired
OPTIONAL MATCH (seg)<-[rz:REALIZES]-(realizer)
OPTIONAL MATCH (ep:Endpoint)-[:IN]->(seg)
RETURN seg.name AS segment, seg.uid AS uid, seg.security_class AS security,
       count(DISTINCT realizer) AS realized_by, count(DISTINCT ep) AS endpoints,
       seg AS _seg, collect(DISTINCT realizer) AS _realizers, collect(DISTINCT rz) AS _rz
ORDER BY segment
""",
    },
    {
        "key": "wlans",
        "group": "topology",
        "title": "Wi-Fi networks",
        "cypher": """
MATCH (s:Ssid:Obj) WHERE s.collection_ts = $snap AND NOT s:Retired
OPTIONAL MATCH (s)-[br:BRIDGED_TO]->(v:VlanInstance)
OPTIONAL MATCH (v)-[rz:REALIZES]->(seg) WHERE seg:BridgeDomain OR seg:L2Segment
RETURN s.name AS ssid, s.security AS security, v.vid AS vlan, seg.name AS segment,
       s AS _s, v AS _v, seg AS _seg, br AS _br, rz AS _rz
ORDER BY ssid
""",
    },
    {
        "key": "device-neighbors",
        "group": "topology",
        "title": "Device neighbors",
        "params": [
            {
                "name": "hostname",
                "label": "hostname",
                "placeholder": "gw",
                "picker": {"label": "Device", "property": "hostname"},
            }
        ],
        "cypher": """
MATCH (d:Device:Obj)
WHERE d.collection_ts = $snap
  AND (d.hostname = $hostname OR $hostname IN coalesce(d.identities, []))
  AND NOT d:Retired
OPTIONAL MATCH (d)<-[o1:ON]-(p:Port)-[cc:CONNECTED_TO]-(rp:Port)-[o2:ON]->(nbr)
WHERE o1._retired_at IS NULL AND cc._retired_at IS NULL AND o2._retired_at IS NULL
  AND NOT p:Retired AND NOT rp:Retired AND NOT nbr:Retired
OPTIONAL MATCH (d)<-[o3:ON]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)
WHERE o3._retired_at IS NULL AND h._retired_at IS NULL
  AND NOT i:Retired AND NOT ip:Retired
// what the device's own LLDP and CDP tables say per port, whether or not a
// cable resolved from it: a far end this run did not collect has no Port to
// cable to and shows here only
OPTIONAL MATCH (d)<-[o4:ON]-(hp:Port)
WHERE o4._retired_at IS NULL AND NOT hp:Retired
  AND (hp.cdp_neighbor_name IS NOT NULL OR hp.lldp_neighbor_name IS NOT NULL)
RETURN d.hostname AS device, collect(DISTINCT p.name + ' -> ' + coalesce(nbr.hostname, '?')
       + ' ' + coalesce(rp.name, '')) AS links,
       collect(DISTINCT hp.name + ' -> ' + coalesce(hp.cdp_neighbor_name, hp.lldp_neighbor_name)
       + ' ' + coalesce(hp.cdp_neighbor_port, hp.lldp_neighbor_port, '')
       + ' (' + CASE WHEN hp.cdp_neighbor_name IS NOT NULL THEN 'cdp' ELSE 'lldp' END + ')')
       AS neighbor_tables,
       collect(DISTINCT coalesce(i.name, '') + ': ' + coalesce(ip.ip, '')) AS addresses,
       d AS _d, collect(DISTINCT p) AS _ports, collect(DISTINCT rp) AS _rports,
       collect(DISTINCT nbr) AS _nbrs, collect(DISTINCT cc) AS _cables,
       collect(DISTINCT o1) AS _on1, collect(DISTINCT o2) AS _on2,
       collect(DISTINCT hp) AS _hports, collect(DISTINCT o4) AS _on4,
       collect(DISTINCT i) AS _ifs, collect(DISTINCT o3) AS _on3,
       collect(DISTINCT h) AS _hasip, collect(DISTINCT ip) AS _ips
""",
    },
    # --- addressing & endpoints
    {
        "key": "endpoints",
        "group": "endpoints",
        "title": "Clients",
        "cypher": """
MATCH (e:Endpoint:Obj) WHERE e.collection_ts = $snap AND NOT e:Retired
OPTIONAL MATCH (e)-[h:HAS_IP]->(ip:IpAddress) WHERE h._retired_at IS NULL
OPTIONAL MATCH (e)-[si:IN]->(seg) WHERE seg:BridgeDomain OR seg:L2Segment
OPTIONAL MATCH (e)-[a:ATTACHED]->(at) WHERE a._retired_at IS NULL AND NOT at:Retired
// a wired client is attached to a port: the port's device names it with the port
OPTIONAL MATCH (at)-[o:ON]->(od:Device) WHERE o._retired_at IS NULL AND NOT od:Retired
// e.infra is the reasoner's marker; e.kind stays collector-owned
RETURN coalesce(e.hostname, e.name, e.mac) AS name, e.mac AS mac,
       CASE WHEN e.infra THEN 'infra' ELSE e.kind END AS kind,
       collect(DISTINCT ip.ip) AS ips, seg.name AS segment,
       collect(DISTINCT CASE WHEN at:Port OR at:Interface
                             THEN coalesce(od.hostname + ' ', '') + at.name
                             ELSE coalesce(at.hostname, at.name) END) AS attached_to,
       collect(DISTINCT a.ssid) AS ssids,
       e AS _e, seg AS _seg, si AS _in, collect(DISTINCT ip) AS _ips,
       collect(DISTINCT h) AS _hasip, collect(DISTINCT a) AS _att,
       collect(DISTINCT at) AS _attached, collect(DISTINCT od) AS _devs,
       collect(DISTINCT o) AS _on
ORDER BY name
""",
    },
    {
        "key": "find-ip",
        "group": "endpoints",
        "title": "Where is this IP",
        "params": [
            {
                "name": "ip",
                "label": "IP address",
                "placeholder": "192.168.30.50",
                "picker": {"label": "IpAddress", "property": "ip"},
            }
        ],
        "cypher": f"""
MATCH (ip:IpAddress:Obj {{ip: $ip}}) WHERE ip.collection_ts = $snap AND NOT ip:Retired
OPTIONAL MATCH (ip)-[i:IN]->(p:Prefix) WHERE i._retired_at IS NULL
OPTIONAL MATCH (n)-[h:HAS_IP]->(ip) WHERE h._retired_at IS NULL
OPTIONAL MATCH (n)-[a:ATTACHED]->(at) WHERE a._retired_at IS NULL AND NOT at:Retired
OPTIONAL MATCH (at)-[ao:ON]->(ad:Device) WHERE ao._retired_at IS NULL AND NOT ad:Retired
WITH ip, p, n, i, h, a, at, ao, coalesce(ad, CASE WHEN at:Device THEN at END) AS adev
OPTIONAL MATCH (adev)<-[uo:ON]-(up:Port)-[c:CONNECTED_TO]-(rp:Port)-[ro:ON]->(ud:Device)
WHERE at:Device AND uo._retired_at IS NULL AND c._retired_at IS NULL
  AND ro._retired_at IS NULL AND NOT up:Retired AND NOT rp:Retired AND NOT ud:Retired
RETURN ip.uid AS uid, ip.l3dom AS l3dom, ip.anchor AS anchor, p.cidr AS prefix,
       {_PRIMARY} AS owner_type, coalesce(n.name, n.hostname, n.uid) AS owner,
       a.ssid AS ssid,
       coalesce(adev.hostname, adev.uid) AS attached_to,
       CASE WHEN at:Device THEN null ELSE at.name END AS attach_port,
       collect(DISTINCT coalesce(ud.hostname, ud.uid) + ' ' + coalesce(rp.name, '?')
               + ' ↔ ' + coalesce(up.name, '?')) AS uplink,
       ip AS _ip, p AS _p, n AS _owner, i AS _in, h AS _hasip,
       a AS _att, at AS _at, ao AS _on, adev AS _adev,
       collect(DISTINCT up) AS _up, collect(DISTINCT c) AS _c,
       collect(DISTINCT rp) AS _rp, collect(DISTINCT ud) AS _ud,
       collect(DISTINCT uo) AS _uo, collect(DISTINCT ro) AS _ro
""",
    },
    {
        "key": "prefixes",
        "group": "endpoints",
        "title": "Prefixes",
        "cypher": """
MATCH (p:Prefix:Obj) WHERE p.collection_ts = $snap AND NOT p:Retired
OPTIONAL MATCH (ip:IpAddress)-[:IN]->(p)
RETURN p.cidr AS prefix, p.l3dom AS l3dom, p.anchor AS anchor, p.kind AS kind, p.name AS name,
       p.dhcp AS dhcp, count(ip) AS addresses, p.ipam_description AS register,
       p.ipam_vlan AS register_vlan, p AS _p
ORDER BY prefix
""",
    },
    {
        "key": "ipam-register",
        "group": "endpoints",
        "title": "Register prefixes",
        "description": "the prefixes the IPAdmin import annotates, with the register entry; contexts above 1 "
        "is a CIDR the entry annotates in more than one forwarding context",
        "cypher": """
MATCH (p:Prefix:Obj)
WHERE p.collection_ts = $snap AND NOT p:Retired AND p.ipam_cidr IS NOT NULL
WITH p.cidr AS prefix, collect(p) AS held
WITH prefix, held, head(held) AS p
RETURN prefix, size(held) AS contexts, [x IN held | x.l3dom] AS l3doms, p.ipam_cidr AS register_cidr,
       p.ipam_match AS match_kind, p.ipam_description AS description, p.ipam_location AS location,
       p.ipam_vlan AS vlan, p.ipam_import AS import_id, held AS _p
ORDER BY prefix
""",
    },
    # --- policy
    {
        "key": "firewall",
        "group": "policy",
        "title": "Firewall rules",
        "description": "every rule per device and rulebase; for an interface ACL the rulebase is the ACL "
        "name, and each rule is listed once per interface and direction the ACL is bound to. src, dst and "
        "service read any when the "
        "rule matches every value; service is <proto>/<ports>, or icmp and its ICMP type; unresolved "
        "names in short what a trace cannot evaluate on the rule",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (rb:FwRulebase:Obj)
WHERE rb.collection_ts = $snap AND NOT rb:Retired
  AND {_RULEBASE_ON_DEVICE}
WITH rb, {_RULEBASE_DEVICES} AS device
// the interfaces the rulebase is bound to, one row per binding:
// an interface ACL is one rulebase per device and ACL name, and each PROTECTED_BY
// edge names one interface and its direction (collectors/cisco_common.py acl_stage)
OPTIONAL MATCH (bi:Interface)-[pb:PROTECTED_BY]->(rb) WHERE pb._retired_at IS NULL AND NOT bi:Retired
MATCH (rb)-[hr:HAS_RULE]->(r:FwRule)
WHERE NOT r:Retired AND hr._retired_at IS NULL
// A run loaded before rulebases carried their bindings has no edge: each binding was a
// rulebase of its own, named "<acl> <direction> <interface>", and every rule of it names
// the interface in in_interface or out_interface.
WITH device, rb, bi, pb, hr, r,
     CASE WHEN pb IS NOT NULL THEN bi.name
          WHEN rb.match_context = 'interface-acl' THEN coalesce(r.in_interface, r.out_interface)
     END AS interface,
     CASE WHEN pb IS NOT NULL THEN pb.direction
          WHEN rb.match_context = 'interface-acl' THEN
            CASE WHEN r.in_interface IS NOT NULL THEN 'in' WHEN r.out_interface IS NOT NULL THEN 'out' END
     END AS direction
// the object and its RESOLVES_TO target in two matches: a NetObject that holds
// only ranges, or an opaque one, has no target (path/gates/firewall.py reads it
// the same way). Each side is aggregated before the next one is matched.
// unresolved reads the short opaque_note a collector writes beside opaque_reason
// (collectors/cisco_common.py acl_stage), else the reason. An empty note is an
// object opaque only along what the service column shows: an ICMP type. toString
// types each list as strings, which the reduce of the three into unresolved needs.
OPTIONAL MATCH (r)-[sr:SRC]->(sno:NetObject) WHERE sr._retired_at IS NULL
OPTIONAL MATCH (sno)-[srt:RESOLVES_TO]->(st) WHERE srt._retired_at IS NULL
WITH device, rb, bi, pb, hr, r, interface, direction,
     collect(DISTINCT coalesce(st.cidr, st.ip)) AS src_values, collect(DISTINCT sno.ranges) AS src_ranges,
     [x IN collect(DISTINCT coalesce(sno.opaque_note, 'src: ' + sno.opaque_reason))
      WHERE x <> '' | toString(x)] AS src_reasons,
     collect(DISTINCT sr) AS _sr, collect(DISTINCT sno) AS _sno,
     collect(DISTINCT srt) AS _srt, collect(DISTINCT st) AS _st
OPTIONAL MATCH (r)-[dr:DST]->(dno:NetObject) WHERE dr._retired_at IS NULL
OPTIONAL MATCH (dno)-[drt:RESOLVES_TO]->(dt) WHERE drt._retired_at IS NULL
WITH device, rb, bi, pb, hr, r, interface, direction,
     src_values, src_ranges, src_reasons, _sr, _sno, _srt, _st,
     collect(DISTINCT coalesce(dt.cidr, dt.ip)) AS dst_values, collect(DISTINCT dno.ranges) AS dst_ranges,
     [x IN collect(DISTINCT coalesce(dno.opaque_note, 'dst: ' + dno.opaque_reason))
      WHERE x <> '' | toString(x)] AS dst_reasons,
     collect(DISTINCT dr) AS _dr, collect(DISTINCT dno) AS _dno,
     collect(DISTINCT drt) AS _drt, collect(DISTINCT dt) AS _dt
OPTIONAL MATCH (r)-[sv:SVC]->(svc) WHERE sv._retired_at IS NULL
WITH device, rb, bi, pb, hr, r, interface, direction,
     src_values, src_ranges, src_reasons, _sr, _sno, _srt, _st,
     dst_values, dst_ranges, dst_reasons, _dr, _dno, _drt, _dt,
     // a SvcObject is named <proto>/<ports>, any for a side it leaves open; a Cisco
     // ACE adds its source port, or is named icmp and the ICMP type it matches
     collect(DISTINCT svc.name) AS services,
     [x IN collect(DISTINCT coalesce(svc.opaque_note, 'service: ' + svc.opaque_reason))
      WHERE x <> '' | toString(x)] AS svc_reasons,
     collect(DISTINCT sv) AS _sv, collect(DISTINCT svc) AS _svc
RETURN device,
       CASE WHEN pb IS NULL AND interface IS NOT NULL AND rb.name ENDS WITH ' ' + direction + ' ' + interface
            THEN left(rb.name, size(rb.name) - size(' ' + direction + ' ' + interface))
            ELSE rb.name END AS rulebase,
       interface, direction,
       r.position AS pos, coalesce(r.name, '') AS rule, r.action AS action,
       {_addresses("r.src_any", "src_values", "src_ranges")} AS src,
       {_addresses("r.dst_any", "dst_values", "dst_ranges")} AS dst,
       CASE WHEN coalesce(r.svc_any, false) THEN ['any'] ELSE services END AS service,
       reduce(s = '', x IN src_reasons + dst_reasons + svc_reasons |
              s + CASE WHEN s = '' THEN '' ELSE '; ' END + x) AS unresolved,
       rb AS _rb, r AS _r, hr AS _hr, bi AS _bi, pb AS _pb,
       _sr, _sno, _srt, _st, _dr, _dno, _drt, _dt, _sv, _svc
ORDER BY device, rulebase, interface, direction, pos
""",
    },
    {
        "key": "nat",
        "group": "policy",
        "title": "NAT rules",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (rb:FwRulebase:Obj {{kind: 'nat'}})-[hr:HAS_RULE]->(n:NatRule)
WHERE rb.collection_ts = $snap
  AND NOT n:Retired AND NOT rb:Retired AND hr._retired_at IS NULL
  AND {_RULEBASE_ON_DEVICE}
OPTIONAL MATCH (n)-[ro:ORIG_SRC]->(os) WHERE ro._retired_at IS NULL
OPTIONAL MATCH (n)-[rx:XLATE_SRC]->(xs) WHERE rx._retired_at IS NULL
OPTIONAL MATCH (n)-[ro2:ORIG_DST]->(od) WHERE ro2._retired_at IS NULL
OPTIONAL MATCH (n)-[rx2:XLATE_DST]->(xd) WHERE rx2._retired_at IS NULL
RETURN rb.name AS rulebase, n.position AS pos, n.kind AS kind,
       coalesce(os.cidr, os.ip, os.name) AS orig_src,
       coalesce(n.translation, xs.ip) AS translated_src,
       coalesce(od.cidr, od.ip) AS orig_dst, xd.ip AS translated_dst,
       n.translation_port AS port,
       rb AS _rb, n AS _n, hr AS _hr, ro AS _ro, os AS _os,
       rx AS _rx, xs AS _xs, ro2 AS _ro2, od AS _od, rx2 AS _rx2, xd AS _xd
ORDER BY rulebase, pos
""",
    },
    # --- zscaler (ZPA and ZIA configuration topology). The picture of one object
    # stops at 300 nodes (app/tables.py MAX_GRAPH_NODES). The `zpa-app-group` query
    # returns the node count of the picture of each segment group.
    {
        "key": "zpa-app-group",
        "group": "zscaler",
        "title": "ZPA app group",
        "description": "one segment group, or every segment group when none is named: its "
        "segments, the access rules that name the group or one of its segments, the user groups "
        "those rules name, and the node count of its picture (the graph stops at 300 nodes and "
        "600 relationships, and the result says when it stopped); rules_without_named_apps lists "
        "the enabled rules that name no application, or carry an application condition this query "
        "does not read: they can apply to the group",
        "params": [
            _picker_param("app_group", "Segment group", "Any segment group", "ZpaSegmentGroup", optional=True)
        ],
        "cypher": """
MATCH (sg:ZpaSegmentGroup:Obj)
WHERE sg.collection_ts = $snap AND NOT sg:Retired
  AND ($app_group = '' OR sg.name = $app_group)
OPTIONAL MATCH (seg:ZpaAppSegment)-[m:MEMBER_OF]->(sg) WHERE m._retired_at IS NULL
OPTIONAL MATCH (sr:ZpaAccessRule)-[sf:FOR]->(seg)
WHERE sf._retired_at IS NULL AND sr.collection_ts = $snap AND NOT sr:Retired
WITH sg, collect(DISTINCT seg) AS segments, collect(DISTINCT m) AS member_of,
     collect(DISTINCT sr) AS segment_rules, collect(DISTINCT sf) AS segment_for
OPTIONAL MATCH (gr:ZpaAccessRule)-[gf:FOR]->(sg)
WHERE gf._retired_at IS NULL AND gr.collection_ts = $snap AND NOT gr:Retired
WITH sg, segments, member_of, segment_rules, segment_for,
     collect(DISTINCT gr) AS group_rules, collect(DISTINCT gf) AS group_for
WITH sg, segments, member_of, segment_for + group_for AS for_edges,
     reduce(acc = group_rules, x IN segment_rules | CASE WHEN x IN acc THEN acc ELSE acc + x END) AS rules
UNWIND (CASE WHEN rules = [] THEN [null] ELSE rules END) AS r
OPTIONAL MATCH (r)-[g:GRANTS|DENIES|APPLIES_TO]->(i:IdentityGroup) WHERE g._retired_at IS NULL
WITH sg, segments, member_of, for_edges,
     collect(DISTINCT r) AS rules, collect(DISTINCT i) AS user_groups, collect(DISTINCT g) AS grants
RETURN sg.name AS segment_group, size(segments) AS segments, size(rules) AS rules,
       size(user_groups) AS user_groups,
       1 + size(segments) + size(rules) + size(user_groups) AS picture_nodes,
       COLLECT {
         MATCH (c:ZpaAccessRule:Obj)
         WHERE c.collection_ts = $snap AND NOT c:Retired AND c._scope = sg._scope
           AND c.app_scope IN ['any', 'other'] AND coalesce(c.enabled, true)
         RETURN c.name ORDER BY c.position
       } AS rules_without_named_apps,
       sg AS _sg, rules AS _rules, user_groups AS _user_groups, grants AS _grants,
       for_edges AS _for, segments AS _segments, member_of AS _member_of
ORDER BY rules, picture_nodes DESC, segment_group
""",
    },
    {
        "key": "zpa-user-group",
        "group": "zscaler",
        "title": "ZPA user group",
        "description": "one user group (SCIM group): the access rules that name it, the segments "
        "and app groups those rules name, and the rules among them that name no application",
        "params": [_ZPA_USER_GROUP_PARAM],
        "cypher": """
MATCH (i:IdentityGroup:Obj {name: $user_group})
WHERE i.collection_ts = $snap AND NOT i:Retired
OPTIONAL MATCH (i)<-[g:GRANTS|DENIES|APPLIES_TO]-(r:ZpaAccessRule)
WHERE g._retired_at IS NULL
OPTIONAL MATCH (r)-[f:FOR]->(t) WHERE f._retired_at IS NULL
OPTIONAL MATCH (t)-[m:MEMBER_OF]->(sg:ZpaSegmentGroup) WHERE m._retired_at IS NULL
WITH i, collect(DISTINCT g) AS grants, collect(DISTINCT r) AS rules, collect(DISTINCT f) AS for_edges,
     collect(DISTINCT t) AS targets, collect(DISTINCT m) AS member_of, collect(DISTINCT sg) AS via_member
WITH i, grants, rules, for_edges, targets, member_of,
     reduce(acc = [], x IN via_member + [t IN targets WHERE t:ZpaSegmentGroup] |
            CASE WHEN x IN acc THEN acc ELSE acc + x END) AS app_groups
RETURN i.name AS user_group, i.idp_name AS identity_provider, size(rules) AS rules,
       [r IN rules | r.action] AS actions,
       [r IN rules WHERE r.app_scope IN ['any', 'other'] | r.name] AS rules_without_named_apps,
       size([t IN targets WHERE t:ZpaAppSegment]) AS segments, size(app_groups) AS segment_groups,
       i AS _i, grants AS _grants, rules AS _rules, for_edges AS _for, app_groups AS _app_groups,
       targets AS _targets, member_of AS _member_of
""",
    },
    {
        "key": "zpa-app-segment",
        "group": "zscaler",
        "title": "ZPA app segment",
        "description": "one application: its app group, the access rules and user groups for it, "
        "and its serving chain of server groups, connector groups and connectors with their state",
        "params": [_ZPA_SEGMENT_PARAM],
        "cypher": f"""
MATCH (seg:ZpaAppSegment:Obj {{name: $segment}})
WHERE seg.collection_ts = $snap AND NOT seg:Retired
OPTIONAL MATCH (seg)-[m:MEMBER_OF]->(grp:ZpaSegmentGroup) WHERE m._retired_at IS NULL
OPTIONAL MATCH (sr:ZpaAccessRule)-[sf:FOR]->(seg) WHERE sf._retired_at IS NULL
OPTIONAL MATCH (gr:ZpaAccessRule)-[gf:FOR]->(grp) WHERE gf._retired_at IS NULL
WITH seg, grp, m, collect(DISTINCT sr) + collect(DISTINCT gr) AS rules,
     collect(DISTINCT sf) + collect(DISTINCT gf) AS for_edges
UNWIND (CASE WHEN rules = [] THEN [null] ELSE rules END) AS r
OPTIONAL MATCH (r)-[g:GRANTS|DENIES|APPLIES_TO]->(i:IdentityGroup) WHERE g._retired_at IS NULL
WITH seg, grp, m, for_edges,
     collect(DISTINCT r) AS rules, collect(DISTINCT i) AS user_groups, collect(DISTINCT g) AS grants
OPTIONAL MATCH (seg)-[sb:SERVED_BY]->(srv:ZpaServerGroup) WHERE sb._retired_at IS NULL
OPTIONAL MATCH (srv)-[u:USES]->(cg:ZpaAppConnectorGroup) WHERE u._retired_at IS NULL
OPTIONAL MATCH (cg)-[h:HAS]->(conn:ZpaAppConnector) WHERE h._retired_at IS NULL
OPTIONAL MATCH (srv)-[c:CONTAINS]->(app_server:AppServer) WHERE c._retired_at IS NULL
WITH seg, grp, m, for_edges, rules, user_groups, grants,
     collect(DISTINCT sb) AS served_by, collect(DISTINCT srv) AS server_groups,
     collect(DISTINCT u) AS uses, collect(DISTINCT cg) AS connector_groups,
     collect(DISTINCT h) AS has, collect(DISTINCT conn) AS connectors,
     collect(DISTINCT c) AS contains, collect(DISTINCT app_server) AS app_servers
RETURN seg.name AS segment, grp.name AS segment_group, seg.domains AS domains,
       seg.tcp_port_ranges AS tcp_ports, seg.udp_port_ranges AS udp_ports, seg.enabled AS enabled,
       size(rules) AS rules, size(user_groups) AS user_groups,
       COLLECT {{
         MATCH (c:ZpaAccessRule:Obj)
         WHERE c.collection_ts = $snap AND NOT c:Retired AND c._scope = seg._scope
           AND c.app_scope IN ['any', 'other'] AND coalesce(c.enabled, true)
         RETURN c.name ORDER BY c.position
       }} AS rules_without_named_apps,
       size([conn IN connectors WHERE {_ZPA_CONN_ACTIVE}]) AS active_connectors,
       size(connectors) AS connectors,
       seg AS _seg, grp AS _grp, m AS _m, server_groups AS _server_groups, served_by AS _served_by,
       connector_groups AS _connector_groups, uses AS _uses, connectors AS _connectors, has AS _has,
       app_servers AS _app_servers, contains AS _contains,
       rules AS _rules, for_edges AS _for, user_groups AS _user_groups, grants AS _grants
""",
    },
    {
        "key": "zpa-connector-group",
        "group": "zscaler",
        "title": "ZPA connector group",
        "description": "one connector group: its connectors with their state, the server groups "
        "that use it and the number of segments those serve",
        "params": [_ZPA_CONNECTOR_GROUP_PARAM],
        "cypher": f"""
MATCH (cg:ZpaAppConnectorGroup:Obj {{name: $connector_group}})
WHERE cg.collection_ts = $snap AND NOT cg:Retired
OPTIONAL MATCH (cg)-[h:HAS]->(conn:ZpaAppConnector) WHERE h._retired_at IS NULL
WITH cg, collect(DISTINCT conn) AS connectors, collect(DISTINCT h) AS has
OPTIONAL MATCH (srv:ZpaServerGroup)-[u:USES]->(cg) WHERE u._retired_at IS NULL
OPTIONAL MATCH (seg:ZpaAppSegment)-[sb:SERVED_BY]->(srv) WHERE sb._retired_at IS NULL
WITH cg, connectors, has, collect(DISTINCT srv) AS server_groups, collect(DISTINCT u) AS uses,
     count(DISTINCT seg) AS segments
RETURN cg.name AS connector_group, cg.location AS location, size(connectors) AS connectors,
       size([conn IN connectors WHERE {_ZPA_CONN_ACTIVE}]) AS active,
       [conn IN connectors | conn.name + ': ' + {_ZPA_CONN_STATE}] AS connector_states,
       size(server_groups) AS server_groups, segments,
       cg AS _cg, connectors AS _connectors, has AS _has, server_groups AS _server_groups, uses AS _uses
""",
    },
    {
        "key": "zpa-connectors",
        "group": "zscaler",
        "title": "ZPA connectors",
        "description": "every ZPA app connector with its group, its state at collection time "
        "(active, down, disabled or unknown) and the segments it can serve, then every private "
        "service edge with its location and state; a named connector group lists its connectors only",
        "params": [
            _picker_param(
                "connector_group",
                "App connector group",
                "Any app connector group",
                "ZpaAppConnectorGroup",
                optional=True,
            )
        ],
        "cypher": f"""
CALL {{
  MATCH (cg:ZpaAppConnectorGroup)-[h:HAS]->(conn:ZpaAppConnector:Obj)
  WHERE conn.collection_ts = $snap AND NOT conn:Retired AND h._retired_at IS NULL
    AND ($connector_group = '' OR cg.name = $connector_group)
  OPTIONAL MATCH (seg:ZpaAppSegment)-[:SERVED_BY]->(:ZpaServerGroup)-[:USES]->(cg)
  RETURN 'app connector' AS kind, cg.name AS connector_group, cg.location AS location,
         conn.name AS name, {_ZPA_CONN_STATE} AS state, conn.control_channel_status AS status,
         conn.private_ip AS private_ip, count(DISTINCT seg) AS segments,
         cg AS _cg, h AS _h, conn AS _node
  UNION
  MATCH (edge:ZpaServiceEdge:Obj)
  WHERE edge.collection_ts = $snap AND NOT edge:Retired AND $connector_group = ''
  RETURN 'private service edge' AS kind, null AS connector_group, edge.location AS location,
         coalesce(edge.name, edge.uid) AS name, {_ZPA_EDGE_STATE} AS state,
         edge.control_channel_status AS status, null AS private_ip, null AS segments,
         null AS _cg, null AS _h, edge AS _node
}}
RETURN kind, connector_group, location, name AS connector, state, status, private_ip, segments,
       _cg, _h, _node
ORDER BY kind, connector_group, location, state, connector
""",
    },
    {
        "key": "zpa-segments-at-risk",
        "group": "zscaler",
        "title": "ZPA segments at risk",
        "description": "segments that are disabled, bypassed, or have no active connector: none "
        "recorded, every one down or disabled, or no connector state collected",
        "params": [
            _picker_param("app_group", "Segment group", "Any segment group", "ZpaSegmentGroup", optional=True)
        ],
        "cypher": f"""
MATCH (seg:ZpaAppSegment:Obj)
WHERE seg.collection_ts = $snap AND NOT seg:Retired
  AND ($app_group = '' OR EXISTS {{ (seg)-[:MEMBER_OF]->(:ZpaSegmentGroup {{name: $app_group}}) }})
OPTIONAL MATCH (seg)-[:SERVED_BY]->(:ZpaServerGroup)-[:USES]->(:ZpaAppConnectorGroup)
               -[:HAS]->(conn:ZpaAppConnector)
WITH seg, collect(DISTINCT conn) AS connectors
OPTIONAL MATCH (seg)-[:MEMBER_OF]->(grp:ZpaSegmentGroup)
WITH seg, connectors, grp,
     seg.enabled = false OR grp.enabled = false AS disabled,
     toUpper(coalesce(seg.bypass_type, '')) = 'ALWAYS' AS bypassed
WHERE disabled OR bypassed OR size([conn IN connectors WHERE {_ZPA_CONN_ACTIVE}]) = 0
RETURN grp.name AS segment_group, seg.name AS segment, size(connectors) AS connectors,
       CASE WHEN disabled THEN 'disabled'
            WHEN bypassed THEN 'bypassed'
            WHEN size(connectors) = 0 THEN 'no connector recorded'
            WHEN all(conn IN connectors WHERE conn.health IS NULL) THEN 'connector state not collected'
            ELSE 'every connector down or disabled' END AS reason
ORDER BY segment_group, segment
""",
    },
    {
        "key": "zpa-groups-without-rules",
        "group": "zscaler",
        "title": "ZPA groups without rules",
        "description": "app groups that no enabled access rule names, neither the group nor one of "
        "its segments; rules_without_named_apps lists the enabled rules that name no application, "
        "or carry an application condition this query does not read: they can apply to the group",
        "cypher": """
MATCH (sg:ZpaSegmentGroup:Obj)
WHERE sg.collection_ts = $snap AND NOT sg:Retired
  AND NOT EXISTS { MATCH (r:ZpaAccessRule)-[:FOR]->(sg) WHERE coalesce(r.enabled, true) }
  AND NOT EXISTS {
    MATCH (r:ZpaAccessRule)-[:FOR]->(:ZpaAppSegment)-[:MEMBER_OF]->(sg) WHERE coalesce(r.enabled, true)
  }
OPTIONAL MATCH (seg:ZpaAppSegment)-[:MEMBER_OF]->(sg)
WITH sg, count(seg) AS segments
RETURN sg.name AS segment_group, segments,
       COLLECT {
         MATCH (c:ZpaAccessRule:Obj)
         WHERE c.collection_ts = $snap AND NOT c:Retired AND c._scope = sg._scope
           AND c.app_scope IN ['any', 'other'] AND coalesce(c.enabled, true)
         RETURN c.name ORDER BY c.position
       } AS rules_without_named_apps
ORDER BY segments DESC, segment_group
""",
    },
    {
        "key": "zpa-policy-rules",
        "group": "zscaler",
        "title": "ZPA policy rules",
        "description": "the access rules and the client forwarding rules in evaluation order, with "
        "the action, whether the rule is enabled, its identity scope (everyone marks a rule whose "
        "conditions name no SCIM group and no other identity attribute), its application scope, "
        "the segments and segment groups it names, and its client criteria",
        "cypher": """
CALL {
  MATCH (r:ZpaAccessRule:Obj)
  WHERE r.collection_ts = $snap AND NOT r:Retired
  OPTIONAL MATCH (r)-[g:GRANTS|DENIES|APPLIES_TO]->(i:IdentityGroup) WHERE g._retired_at IS NULL
  OPTIONAL MATCH (r)-[f:FOR]->(t) WHERE f._retired_at IS NULL
  RETURN 'access' AS policy, r AS rule_node,
         coalesce(r.identity_scope = 'any', r.applies_to_all_identities = true, false) AS everyone,
         count(DISTINCT i) AS user_groups,
         count(DISTINCT CASE WHEN t:ZpaAppSegment THEN t END) AS segments,
         count(DISTINCT CASE WHEN t:ZpaSegmentGroup THEN t END) AS segment_groups,
         collect(DISTINCT i) AS _i, collect(DISTINCT g) AS _g
  UNION
  MATCH (r:ZpaClientForwardingRule:Obj)
  WHERE r.collection_ts = $snap AND NOT r:Retired
  OPTIONAL MATCH (r)-[g:APPLIES_TO]->(i:IdentityGroup) WHERE g._retired_at IS NULL
  OPTIONAL MATCH (r)-[f:FOR]->(t) WHERE f._retired_at IS NULL
  RETURN 'client forwarding' AS policy, r AS rule_node,
         coalesce(r.applies_to_all_identities, false) AS everyone,
         count(DISTINCT i) AS user_groups,
         count(DISTINCT CASE WHEN t:ZpaAppSegment THEN t END) AS segments,
         count(DISTINCT CASE WHEN t:ZpaSegmentGroup THEN t END) AS segment_groups,
         collect(DISTINCT i) AS _i, collect(DISTINCT g) AS _g
}
RETURN policy, rule_node.position AS position, rule_node.name AS rule, rule_node.action AS action,
       rule_node.enabled AS enabled, everyone, user_groups, rule_node.app_scope AS app_scope,
       segments, segment_groups, rule_node.conditions_summary AS conditions,
       rule_node AS _rule, _i, _g
ORDER BY policy, position
""",
    },
    {
        "key": "zia-forwarding-rules",
        "group": "zscaler",
        "title": "ZIA forwarding rules",
        "description": "ZIA forwarding rules in order, or one named rule: the method (ZPA, direct, "
        "drop), the locations and location groups a rule names (a rule that names none applies to "
        "every location), its other match criteria, the ZPA segments and segment groups a ZPA rule "
        "names and that this run resolved, and the segment groups and connector groups that serve "
        "them (only the server group of the rule's ZPA gateway, when it names one)",
        "params": [
            _picker_param(
                "forwarding_rule",
                "Forwarding rule",
                "Any forwarding rule",
                "ZiaForwardingRule",
                optional=True,
            )
        ],
        "cypher": """
MATCH (fwd:ZiaForwardingRule:Obj)
WHERE fwd.collection_ts = $snap AND NOT fwd:Retired
  AND ($forwarding_rule = '' OR fwd.name = $forwarding_rule)
OPTIONAL MATCH (fwd)-[f:FORWARDS_TO]->(named:ZpaAppSegment) WHERE f._retired_at IS NULL
WITH fwd, collect(DISTINCT named) AS named_segments, collect(DISTINCT f) AS segment_forwards
OPTIONAL MATCH (fwd)-[fg:FORWARDS_TO]->(grp:ZpaSegmentGroup) WHERE fg._retired_at IS NULL
OPTIONAL MATCH (member:ZpaAppSegment)-[mm:MEMBER_OF]->(grp) WHERE mm._retired_at IS NULL
WITH fwd, named_segments, segment_forwards, collect(DISTINCT fg) AS group_forwards,
     collect(DISTINCT grp) AS named_groups, collect(DISTINCT member) AS members
WITH fwd, named_segments, segment_forwards + group_forwards AS forwards, named_groups,
     reduce(acc = [], x IN named_segments + members |
            CASE WHEN x IN acc THEN acc ELSE acc + x END) AS segments
// the rule's ZPA gateway steers to one server group: only its connector groups count
OPTIONAL MATCH (fwd)-[sv:STEERS_VIA]->(gw_srv:ZpaServerGroup) WHERE sv._retired_at IS NULL
WITH fwd, named_segments, forwards, named_groups, segments, head(collect(gw_srv)) AS gw_srv
UNWIND (CASE WHEN segments = [] THEN [null] ELSE segments END) AS seg
OPTIONAL MATCH (seg)-[m:MEMBER_OF]->(sgrp:ZpaSegmentGroup) WHERE m._retired_at IS NULL
OPTIONAL MATCH (seg)-[sb:SERVED_BY]->(srv:ZpaServerGroup) WHERE sb._retired_at IS NULL
OPTIONAL MATCH (srv)-[u:USES]->(cg:ZpaAppConnectorGroup)
WHERE u._retired_at IS NULL AND (gw_srv IS NULL OR srv = gw_srv)
WITH fwd, named_segments, forwards, named_groups, segments,
     collect(DISTINCT sgrp) AS segment_groups, collect(DISTINCT m) AS member_of,
     collect(DISTINCT srv) AS server_groups, collect(DISTINCT sb) AS served_by,
     collect(DISTINCT cg) AS connector_groups, collect(DISTINCT u) AS uses
RETURN fwd.order AS order, fwd.name AS rule, fwd.forward_method AS method, fwd.enabled AS enabled,
       fwd.rule_type AS rule_type, size(coalesce(fwd.location_ids, [])) AS named_locations,
       size(coalesce(fwd.location_group_ids, [])) AS named_location_groups,
       fwd.other_criteria AS other_criteria, fwd.zpa_gateway AS zpa_gateway,
       size(coalesce(fwd.zpa_app_segment_ids, [])) AS named_segments,
       size(named_segments) AS resolved_segments,
       size(coalesce(fwd.zpa_segment_group_ids, [])) AS named_segment_groups,
       size(named_groups) AS resolved_segment_groups,
       [g IN segment_groups | g.name] AS segment_groups,
       [c IN connector_groups | c.name] AS connector_groups,
       fwd AS _fwd, forwards AS _f, segments AS _seg, named_groups AS _named_groups,
       segment_groups AS _grp, member_of AS _m, server_groups AS _srv, served_by AS _sb,
       connector_groups AS _cg, uses AS _u
ORDER BY order
""",
    },
    {
        "key": "zia-location-egress",
        "group": "zscaler",
        "title": "ZIA locations",
        "description": "every ZIA location with its parent, site, profile, GRE and IPsec tunnels, "
        "the primary and secondary data centers its GRE tunnels end on, its private service edges "
        "and location groups, and its gaps: no tunnel or no site for a top-level location, and "
        "GRE tunnels that end on fewer than 2 Zscaler data centers (a private service edge is "
        "not counted)",
        "params": [
            _picker_param(
                "location_group", "Location group", "Any location group", "ZiaLocationGroup", optional=True
            )
        ],
        "cypher": """
MATCH (loc:ZiaLocation:Obj)
WHERE loc.collection_ts = $snap AND NOT loc:Retired
  AND ($location_group = '' OR EXISTS { (loc)-[:MEMBER_OF]->(:ZiaLocationGroup {name: $location_group}) })
OPTIONAL MATCH (loc)-[po:PART_OF]->(parent:ZiaLocation) WHERE po._retired_at IS NULL
OPTIONAL MATCH (loc)-[rp:REPRESENTS]->(site:Site) WHERE rp._retired_at IS NULL
OPTIONAL MATCH (loc)-[mo:MEMBER_OF]->(grp:ZiaLocationGroup) WHERE mo._retired_at IS NULL
WITH loc, parent, po, site, rp, collect(DISTINCT grp) AS groups, collect(DISTINCT mo) AS member_of
OPTIONAL MATCH (loc)-[u:USES]->(t:Tunnel) WHERE u._retired_at IS NULL
OPTIONAL MATCH (t)-[te:TERMINATES_ON]->(dc:ZscalerDc) WHERE te._retired_at IS NULL
WITH loc, parent, po, site, rp, groups, member_of,
     collect(DISTINCT u) AS uses, collect(DISTINCT t) AS tunnels,
     collect(DISTINCT te) AS ends, collect(DISTINCT dc) AS dcs
WITH loc, parent, po, site, rp, groups, member_of, uses, tunnels, ends, dcs,
     [e IN ends WHERE startNode(e).encap = 'gre' AND NOT coalesce(endNode(e).private_service_edge, false)
      | endNode(e).name] AS gre_dc_names
WITH loc, parent, po, site, rp, groups, member_of, uses, tunnels, ends, dcs,
     reduce(acc = [], x IN gre_dc_names | CASE WHEN x IN acc THEN acc ELSE acc + x END) AS egress_dcs,
     size([t IN tunnels WHERE t.encap = 'gre']) AS gre_tunnels,
     size([t IN tunnels WHERE t.encap = 'ipsec']) AS ipsec_tunnels
RETURN loc.name AS location, parent.name AS parent, loc.zia_id AS zia_id, site.code AS site,
       loc.country AS country, loc.profile AS profile, gre_tunnels, ipsec_tunnels,
       reduce(acc = [], e IN [e IN ends WHERE e.role = 'primary'] |
              CASE WHEN endNode(e).name IN acc THEN acc ELSE acc + endNode(e).name END) AS primary_dcs,
       reduce(acc = [], e IN [e IN ends WHERE e.role = 'secondary'] |
              CASE WHEN endNode(e).name IN acc THEN acc ELSE acc + endNode(e).name END) AS secondary_dcs,
       egress_dcs,
       [d IN dcs WHERE coalesce(d.private_service_edge, false) | d.name] AS service_edges,
       [g IN groups | g.name] AS location_groups,
       [gap IN [
          CASE WHEN parent IS NULL AND size(tunnels) = 0 THEN 'no tunnel' END,
          CASE WHEN parent IS NULL AND site IS NULL THEN 'no site' END,
          CASE WHEN gre_tunnels > 0 AND size(egress_dcs) < 2 THEN 'fewer than 2 data centers' END
        ] WHERE gap IS NOT NULL] AS gaps,
       loc AS _loc, parent AS _parent, po AS _po, site AS _site, rp AS _rp, groups AS _grp,
       member_of AS _mo, tunnels AS _t, uses AS _u, dcs AS _dc, ends AS _te
ORDER BY size(gaps) DESC, location
""",
    },
    {
        "key": "zia-location",
        "group": "zscaler",
        "title": "ZIA location",
        "description": "one ZIA location: its parent and sublocations, profile, firewall and IPS options, "
        "GRE and IPsec tunnels, the data centers a GRE tunnel ends on, and its location groups",
        "params": [_ZIA_LOCATION_PARAM],
        "cypher": """
MATCH (loc:ZiaLocation:Obj {name: $location})
WHERE loc.collection_ts = $snap AND NOT loc:Retired
OPTIONAL MATCH (loc)-[po:PART_OF]->(parent:ZiaLocation) WHERE po._retired_at IS NULL
OPTIONAL MATCH (sub:ZiaLocation)-[ps:PART_OF]->(loc) WHERE ps._retired_at IS NULL
OPTIONAL MATCH (loc)-[mo:MEMBER_OF]->(grp:ZiaLocationGroup) WHERE mo._retired_at IS NULL
OPTIONAL MATCH (loc)-[u:USES]->(t:Tunnel) WHERE u._retired_at IS NULL
OPTIONAL MATCH (t)-[te:TERMINATES_ON]->(dc:ZscalerDc) WHERE te._retired_at IS NULL
OPTIONAL MATCH (loc)-[rp:REPRESENTS]->(site:Site) WHERE rp._retired_at IS NULL
RETURN loc.name AS location, loc.zia_id AS zia_id, site.code AS site, parent.name AS parent,
       loc.country AS country,
       size(coalesce(loc.egress_ips, [])) AS egress_ips,
       size(coalesce(loc.address_ranges, [])) AS address_ranges, loc.auth_required AS auth_required,
       loc.profile AS profile, loc.ofw_enabled AS ofw_enabled, loc.ips_control AS ips_control,
       COLLECT {
         MATCH (rule:ZiaForwardingRule:Obj)-[:APPLIES_TO]->(scope)
         WHERE (scope = loc OR EXISTS { MATCH (loc)-[:MEMBER_OF]->(scope:ZiaLocationGroup) })
           AND rule.collection_ts = $snap AND NOT rule:Retired
         WITH DISTINCT rule ORDER BY rule.order
         RETURN rule.name
       } AS forwarding_rules,
       count(DISTINCT sub) AS sublocations,
       collect(DISTINCT t.encap) AS tunnels, collect(DISTINCT dc.name) AS egress_dcs,
       collect(DISTINCT grp.name) AS location_groups,
       loc AS _loc, site AS _site, rp AS _rp, parent AS _parent, po AS _po,
       collect(DISTINCT sub) AS _sub, collect(DISTINCT ps) AS _ps,
       collect(DISTINCT grp) AS _grp, collect(DISTINCT mo) AS _mo, collect(DISTINCT t) AS _t,
       collect(DISTINCT u) AS _u, collect(DISTINCT dc) AS _dc, collect(DISTINCT te) AS _te
""",
    },
    {
        "key": "zia-location-group",
        "group": "zscaler",
        "title": "ZIA location group",
        "description": "one ZIA location group: its member locations, as ZIA lists them for static "
        "and dynamic groups alike, and the data centers each member egresses through",
        "params": [_ZIA_LOCATION_GROUP_PARAM],
        "cypher": """
MATCH (grp:ZiaLocationGroup:Obj {name: $location_group})
WHERE grp.collection_ts = $snap AND NOT grp:Retired
OPTIONAL MATCH (loc:ZiaLocation)-[mo:MEMBER_OF]->(grp) WHERE mo._retired_at IS NULL
OPTIONAL MATCH (loc)-[u:USES]->(t:Tunnel) WHERE u._retired_at IS NULL
OPTIONAL MATCH (t)-[te:TERMINATES_ON]->(dc:ZscalerDc) WHERE te._retired_at IS NULL
RETURN loc.name AS location, loc.country AS country, grp.dynamic AS dynamic_group,
       collect(DISTINCT t.encap) AS tunnels, collect(DISTINCT dc.name) AS egress_dcs,
       grp AS _grp, loc AS _loc, mo AS _mo, collect(DISTINCT t) AS _t, collect(DISTINCT u) AS _u,
       collect(DISTINCT dc) AS _dc, collect(DISTINCT te) AS _te
ORDER BY location
""",
    },
    {
        "key": "zia-dc-users",
        "group": "zscaler",
        "title": "ZIA data center users",
        "description": "the locations whose GRE tunnels end on one Zscaler data center, and which of "
        "them have no other recorded egress if that data center fails",
        "params": [_ZIA_DC_PARAM],
        "cypher": """
MATCH (dc:ZscalerDc:Obj {name: $dc})
WHERE dc.collection_ts = $snap AND NOT dc:Retired
MATCH (loc:ZiaLocation)-[u:USES]->(t:Tunnel)-[te:TERMINATES_ON]->(dc)
WHERE u._retired_at IS NULL AND te._retired_at IS NULL
OPTIONAL MATCH (loc)-[:USES]->(:Tunnel)-[:TERMINATES_ON]->(other:ZscalerDc) WHERE other <> dc
OPTIONAL MATCH (loc)-[:USES]->(ipsec:Tunnel {encap: 'ipsec'})
WITH dc, loc, collect(DISTINCT t) AS tunnels, collect(DISTINCT u) AS uses, collect(DISTINCT te) AS ends,
     collect(DISTINCT other.name) AS other_dcs, count(DISTINCT ipsec) AS ipsec_tunnels
RETURN loc.name AS location, loc.country AS country, size(tunnels) AS tunnels_to_this_dc,
       reduce(acc = [], r IN [e IN ends | e.role] |
              CASE WHEN r IS NULL OR r IN acc THEN acc ELSE acc + r END) AS roles, other_dcs,
       ipsec_tunnels, size(other_dcs) = 0 AND ipsec_tunnels = 0 AS no_other_egress,
       dc AS _dc, loc AS _loc, tunnels AS _t, uses AS _u, ends AS _te
ORDER BY no_other_egress DESC, location
""",
    },
    # --- routing (the BGP configuration of the devices). The parquet side store
    # holds the observed session state and the per-neighbor path tables.
    {
        "key": "bgp-sessions",
        "group": "routing",
        "title": "BGP sessions",
        "description": "every configured BGP neighbor with its VRF, ASNs and attached policies",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (rp:RoutingProcess:Obj {{proto: 'bgp'}})-[h:HAS]->(s:BgpSession)
WHERE rp.collection_ts = $snap
  AND NOT rp:Retired AND NOT s:Retired AND h._retired_at IS NULL
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance) WHERE iv._retired_at IS NULL AND NOT v:Retired
WITH rp, h, s, iv, v, {_VRF_DEVICE} AS d
WHERE $device = '' OR d.hostname = $device
RETURN d.hostname AS device, coalesce(v.name, 'default') AS vrf,
       coalesce(rp.asn, s.local_asn) AS local_asn, s.peer_ip AS peer, s.peer_asn AS peer_asn,
       s.afi_safi AS afi_safi, coalesce(s.state, '') AS admin_state, s.description AS description,
       s.import_policy_name AS import_policy, s.export_policy_name AS export_policy,
       d AS _d, v AS _v, rp AS _rp, s AS _s, h AS _h, iv AS _iv
ORDER BY device, vrf, peer
""",
    },
    {
        "key": "bgp-peers-by-asn",
        "group": "routing",
        "title": "BGP peers by ASN",
        "description": "sessions grouped by the remote AS: how many, in which VRFs, on which devices",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (rp:RoutingProcess:Obj {{proto: 'bgp'}})-[h:HAS]->(s:BgpSession)
WHERE rp.collection_ts = $snap
  AND NOT rp:Retired AND NOT s:Retired AND h._retired_at IS NULL
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance) WHERE iv._retired_at IS NULL AND NOT v:Retired
WITH rp, h, s, iv, v, {_VRF_DEVICE} AS d
WHERE $device = '' OR d.hostname = $device
RETURN s.peer_asn AS peer_asn, count(DISTINCT s) AS sessions,
       collect(DISTINCT d.hostname) AS devices,
       collect(DISTINCT coalesce(v.name, 'default')) AS vrfs, collect(DISTINCT s.peer_ip) AS peers,
       collect(DISTINCT s) AS _s, collect(DISTINCT rp) AS _rp, collect(DISTINCT h) AS _h,
       collect(DISTINCT v) AS _v, collect(DISTINCT iv) AS _iv, collect(DISTINCT d) AS _d
ORDER BY sessions DESC, peer_asn
""",
    },
    {
        "key": "bgp-per-vrf",
        "group": "routing",
        "title": "BGP per VRF",
        "description": "one row per BGP process: ASN, router-id, peers, originated prefixes, redistribution",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (rp:RoutingProcess:Obj {{proto: 'bgp'}})-[iv:IN_VRF]->(v:VrfInstance)
WHERE rp.collection_ts = $snap
  AND NOT rp:Retired AND NOT v:Retired AND iv._retired_at IS NULL
WITH rp, iv, v, {_VRF_DEVICE} AS d
WHERE $device = '' OR d.hostname = $device
OPTIONAL MATCH (rp)-[h:HAS]->(s:BgpSession) WHERE h._retired_at IS NULL AND NOT s:Retired
OPTIONAL MATCH (v)-[o:ORIGINATES]->(p:Prefix) WHERE o._retired_at IS NULL AND NOT p:Retired
RETURN d.hostname AS device, v.name AS vrf, rp.asn AS asn, rp.router_id AS router_id,
       count(DISTINCT s) AS sessions,
       collect(DISTINCT s.peer_ip + ' AS' + toString(s.peer_asn)) AS peers,
       collect(DISTINCT CASE o.proto WHEN 'aggregate' THEN p.cidr + ' (aggregate)' ELSE p.cidr END)
         AS originated,
       coalesce(rp.redistribute_protocols, []) AS redistributes,
       d AS _d, v AS _v, rp AS _rp, iv AS _iv, collect(DISTINCT s) AS _s, collect(DISTINCT h) AS _h,
       collect(DISTINCT p) AS _p, collect(DISTINCT o) AS _o
ORDER BY device, vrf
""",
    },
    {
        "key": "bgp-originated",
        "group": "routing",
        "title": "Originated prefixes",
        "description": "network and aggregate-address statements per VRF, with the network route-map",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (v:VrfInstance)-[o:ORIGINATES]->(p:Prefix:Obj)
WHERE p.collection_ts = $snap
  AND NOT p:Retired AND NOT v:Retired AND o._retired_at IS NULL
OPTIONAL MATCH (rp:RoutingProcess {{proto: 'bgp'}})-[iv:IN_VRF]->(v)
WHERE iv._retired_at IS NULL AND NOT rp:Retired
OPTIONAL MATCH (rp)-[f:FILTERED_BY {{direction: 'redistribute', protocol: 'network'}}]->(pol:RoutePolicy)
WHERE f._retired_at IS NULL AND NOT pol:Retired
WITH v, o, p, rp, iv, f, pol, {_VRF_DEVICE} AS d
WHERE $device = '' OR d.hostname = $device
RETURN d.hostname AS device, v.name AS vrf, p.cidr AS prefix, p.af AS af, o.proto AS statement,
       p.summary_only AS summary_only, p.as_set AS as_set,
       CASE o.proto WHEN 'network' THEN pol.name ELSE null END AS route_map,
       d AS _d, v AS _v, o AS _o, p AS _p, rp AS _rp, iv AS _iv, f AS _f, pol AS _pol
ORDER BY device, vrf, prefix
""",
    },
    {
        "key": "bgp-session-policies",
        "group": "routing",
        "title": "BGP session policies",
        "description": "import and export policy per session, whether it resolves, and its prefix-lists",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (rp:RoutingProcess:Obj {{proto: 'bgp'}})-[h:HAS]->(s:BgpSession)
WHERE rp.collection_ts = $snap
  AND NOT rp:Retired AND NOT s:Retired AND h._retired_at IS NULL
  AND (s.import_policy_name IS NOT NULL OR s.export_policy_name IS NOT NULL)
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance) WHERE iv._retired_at IS NULL AND NOT v:Retired
OPTIONAL MATCH (s)-[fi:FILTERED_BY {{direction: 'in'}}]->(pin:RoutePolicy)
WHERE fi._retired_at IS NULL AND NOT pin:Retired
OPTIONAL MATCH (s)-[fo:FILTERED_BY {{direction: 'out'}}]->(pout:RoutePolicy)
WHERE fo._retired_at IS NULL AND NOT pout:Retired
OPTIONAL MATCH (pin)-[hi:HAS_RULE]->(ei:RoutePolicyEntry)-[ri:REFERENCES]->(pli:RoutePolicy)
WHERE hi._retired_at IS NULL AND ri._retired_at IS NULL AND NOT pli:Retired
OPTIONAL MATCH (pout)-[ho:HAS_RULE]->(eo:RoutePolicyEntry)-[ro:REFERENCES]->(plo:RoutePolicy)
WHERE ho._retired_at IS NULL AND ro._retired_at IS NULL AND NOT plo:Retired
WITH rp, h, s, iv, v, fi, pin, fo, pout, hi, ei, ri, pli, ho, eo, ro, plo, {_VRF_DEVICE} AS d
WHERE $device = '' OR d.hostname = $device
RETURN d.hostname AS device, coalesce(v.name, 'default') AS vrf, s.peer_ip AS peer, s.peer_asn AS peer_asn,
       s.import_policy_name AS import_policy, s.import_policy_kind AS import_kind,
       pin IS NOT NULL AS import_resolved, collect(DISTINCT pli.name) AS import_matches,
       s.export_policy_name AS export_policy, s.export_policy_kind AS export_kind,
       pout IS NOT NULL AS export_resolved, collect(DISTINCT plo.name) AS export_matches,
       d AS _d, v AS _v, rp AS _rp, s AS _s, h AS _h, iv AS _iv, fi AS _fi, pin AS _pin, fo AS _fo,
       pout AS _pout, collect(DISTINCT hi) AS _hi, collect(DISTINCT ei) AS _ei, collect(DISTINCT ri) AS _ri,
       collect(DISTINCT pli) AS _pli, collect(DISTINCT ho) AS _ho, collect(DISTINCT eo) AS _eo,
       collect(DISTINCT ro) AS _ro, collect(DISTINCT plo) AS _plo
ORDER BY device, vrf, peer
""",
    },
    {
        "key": "route-maps",
        "group": "routing",
        "title": "Route-map clauses",
        "description": "every route-map clause with its match and set terms, the lines the engine does not "
        "model, references and attachments",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (pol:RoutePolicy:Obj {{kind: 'route-map'}})-[hr:HAS_RULE]->(e:RoutePolicyEntry)
WHERE pol.collection_ts = $snap
  AND NOT pol:Retired AND NOT e:Retired AND hr._retired_at IS NULL
  AND {_POLICY_ON_DEVICE}
OPTIONAL MATCH (e)-[rf:REFERENCES]->(ref:RoutePolicy) WHERE rf._retired_at IS NULL AND NOT ref:Retired
OPTIONAL MATCH (user)-[fb:FILTERED_BY]->(pol) WHERE fb._retired_at IS NULL AND NOT user:Retired
RETURN pol.name AS route_map, e.seq AS seq, e.action AS action,
       e.match_prefix_lists AS match_prefix_lists, e.match_as_path_lists AS match_as_paths,
       e.match_community_lists AS match_communities, e.match_tags AS match_tags,
       e.match_expr AS match_expr, e.match_unsupported AS match_unsupported,
       e.match_ignored AS match_ignored,
       e.set_local_pref AS set_local_pref, e.set_metric AS set_metric,
       e.set_as_path_prepend AS set_prepend, e.set_communities AS set_communities,
       e.set_next_hop AS set_next_hop, e.set_weight AS set_weight,
       e.set_comm_list_delete AS set_comm_list_delete, e.set_unsupported AS set_unsupported,
       e.continue_seq AS continue_seq, e.calls_policy AS calls,
       collect(DISTINCT ref.kind + ' ' + ref.name) AS references, count(DISTINCT user) AS attached_to,
       pol.uid AS policy_uid,
       pol AS _pol, e AS _e, hr AS _hr, collect(DISTINCT rf) AS _rf, collect(DISTINCT ref) AS _ref
ORDER BY policy_uid, seq
""",
    },
    {
        "key": "prefix-lists",
        "group": "routing",
        "title": "Prefix-list entries",
        "description": "every prefix-list line with its length range and the objects that use the list",
        "params": [_DEVICE_PARAM],
        "cypher": f"""
MATCH (pol:RoutePolicy:Obj {{kind: 'prefix-list'}})-[hr:HAS_RULE]->(e:PrefixListEntry)
WHERE pol.collection_ts = $snap
  AND NOT pol:Retired AND NOT e:Retired AND hr._retired_at IS NULL
  AND {_POLICY_ON_DEVICE}
OPTIONAL MATCH (user)-[fb:FILTERED_BY]->(pol) WHERE fb._retired_at IS NULL AND NOT user:Retired
OPTIONAL MATCH (rm:RoutePolicy)-[hc:HAS_RULE]->(clause:RoutePolicyEntry)-[rf:REFERENCES]->(pol)
WHERE hc._retired_at IS NULL AND rf._retired_at IS NULL AND NOT rm:Retired AND NOT clause:Retired
RETURN pol.name AS prefix_list, e.seq AS seq, e.action AS action, e.prefix AS prefix,
       e.min_len AS min_len, e.max_len AS max_len,
       count(DISTINCT user) AS attached_to, collect(DISTINCT rm.name) AS used_by_route_maps,
       pol.uid AS policy_uid,
       pol AS _pol, e AS _e, hr AS _hr
ORDER BY policy_uid, seq
""",
    },
    {
        "key": "prefix-in-policies",
        "group": "routing",
        "title": "Prefix in policies",
        "params": [
            {
                "name": "prefix",
                "label": "prefix",
                "placeholder": "10.0.0.0/8",
                "picker": {"label": "Prefix", "property": "cidr"},
            }
        ],
        "description": "prefix-list lines naming this exact prefix, and where each list is attached: "
        "directly or through a route-map",
        "cypher": """
MATCH (pl:RoutePolicy {kind: 'prefix-list'})-[hr:HAS_RULE]->(e:PrefixListEntry:Obj)
WHERE e.collection_ts = $snap AND e.prefix = $prefix
  AND NOT pl:Retired AND NOT e:Retired AND hr._retired_at IS NULL
OPTIONAL MATCH (pl)<-[fb:FILTERED_BY]-(direct) WHERE fb._retired_at IS NULL AND NOT direct:Retired
OPTIONAL MATCH (pl)<-[rf:REFERENCES]-(clause:RoutePolicyEntry)<-[hc:HAS_RULE]-(rm:RoutePolicy)
  <-[fb2:FILTERED_BY]-(via)
WHERE rf._retired_at IS NULL AND hc._retired_at IS NULL AND fb2._retired_at IS NULL
  AND NOT clause:Retired AND NOT rm:Retired AND NOT via:Retired
RETURN pl.name AS prefix_list, e.seq AS seq, e.action AS action, e.min_len AS min_len, e.max_len AS max_len,
       collect(DISTINCT coalesce(direct.peer_ip, direct.uid) + ' ' + fb.direction) AS attached_directly,
       collect(DISTINCT rm.name + ' seq ' + toString(clause.seq) + ' -> '
               + coalesce(via.peer_ip, via.uid) + ' ' + fb2.direction) AS via_route_maps,
       pl.uid AS policy_uid,
       pl AS _pl, e AS _e, hr AS _hr, collect(DISTINCT fb) AS _fb, collect(DISTINCT direct) AS _direct,
       collect(DISTINCT rf) AS _rf, collect(DISTINCT clause) AS _clause, collect(DISTINCT hc) AS _hc,
       collect(DISTINCT rm) AS _rm, collect(DISTINCT fb2) AS _fb2, collect(DISTINCT via) AS _via
ORDER BY policy_uid, seq
""",
    },
    # --- SD-WAN (shares the group with the cloud and WAN scenarios from demo.py)
    {
        "key": "sdwan-edges",
        "group": "cloud & wan",
        "title": "SD-WAN edges",
        "description": "every VeloCloud edge: enterprise, site, state, release, links, paths and segments",
        "cypher": """
MATCH (d:Device:Obj {platform: 'velocloud-edge'})
WHERE d.collection_ts = $snap AND NOT d:Retired
OPTIONAL MATCH (d)-[hl:HAS_LINK]->(l:WanLink) WHERE hl._retired_at IS NULL AND NOT l:Retired
OPTIONAL MATCH (d)-[hb:HAS_BOUNDARY]->(fb:ForwardingBoundary) WHERE hb._retired_at IS NULL AND NOT fb:Retired
OPTIONAL MATCH (d)<-[:ON]-(:Interface)<-[te:ENDPOINT]-(t:Tunnel {encap: 'velocloud-vcmp'})
WHERE te._retired_at IS NULL AND NOT t:Retired
RETURN d.hostname AS edge, d.enterprise_name AS enterprise, d.reported_location_name AS site,
       d.site_country AS country, d.edge_state AS state, coalesce(d.sdwan_role, 'spoke') AS role,
       d.model AS model, d.software_version AS release,
       count(DISTINCT l) AS wan_links, count(DISTINCT t) AS paths, count(DISTINCT fb) AS segments,
       count(DISTINCT CASE WHEN fb.gaps IS NOT NULL THEN fb END) > 0 AS discovery_gap,
       d AS _d, collect(DISTINCT l) AS _l, collect(DISTINCT hl) AS _hl,
       collect(DISTINCT fb) AS _fb, collect(DISTINCT hb) AS _hb
ORDER BY enterprise, edge
""",
    },
    {
        "key": "sdwan-wan-links",
        "group": "cloud & wan",
        "title": "SD-WAN WAN links",
        "description": "every WAN link per edge: kind, carrier, address, state and the configured bandwidth",
        "cypher": """
MATCH (d:Device {platform: 'velocloud-edge'})-[hl:HAS_LINK]->(l:WanLink:Obj)
WHERE l.collection_ts = $snap
  AND NOT d:Retired AND NOT l:Retired AND hl._retired_at IS NULL
OPTIONAL MATCH (l)-[pb:PROVIDED_BY]->(pn:ProviderNetwork) WHERE pb._retired_at IS NULL AND NOT pn:Retired
RETURN d.hostname AS edge, l.name AS link, l.interface AS interface, l.kind AS kind,
       l.carrier AS carrier, pn.kind AS network, l.public_ip AS public_ip, l.state AS state,
       l.link_mode AS mode, l.wan_mode AS wan_mode, l.access_type AS access_type,
       l.upstream_mbps AS upstream_mbps, l.downstream_mbps AS downstream_mbps, l.mtu AS mtu,
       l.origin_config_recorded AS kind_from_config,
       d AS _d, l AS _l, hl AS _hl, pn AS _pn, pb AS _pb
ORDER BY edge, link
""",
    },
    {
        "key": "sdwan-carriers",
        "group": "cloud & wan",
        "title": "SD-WAN carriers",
        "description": "WAN links grouped by carrier and kind: edges, states and the total bandwidth",
        "cypher": """
MATCH (d:Device {platform: 'velocloud-edge'})-[hl:HAS_LINK]->(l:WanLink:Obj)
WHERE l.collection_ts = $snap
  AND NOT d:Retired AND NOT l:Retired AND hl._retired_at IS NULL
OPTIONAL MATCH (l)-[pb:PROVIDED_BY]->(pn:ProviderNetwork) WHERE pb._retired_at IS NULL AND NOT pn:Retired
RETURN l.carrier AS carrier, l.kind AS kind, count(DISTINCT l) AS links, count(DISTINCT d) AS edges,
       collect(DISTINCT l.state) AS states,
       sum(coalesce(l.upstream_mbps, 0)) AS upstream_mbps,
       sum(coalesce(l.downstream_mbps, 0)) AS downstream_mbps,
       collect(DISTINCT l) AS _l, collect(DISTINCT d) AS _d, collect(DISTINCT hl) AS _hl,
       collect(DISTINCT pn) AS _pn, collect(DISTINCT pb) AS _pb
ORDER BY links DESC, carrier, kind
""",
    },
    {
        "key": "sdwan-paths",
        "group": "cloud & wan",
        "title": "SD-WAN overlay paths",
        "description": "every configured overlay tunnel from a local WAN link to an SD-WAN gateway, "
        "a hub or a branch; the two ends of a hub and branch tunnel are two rows with the same pair",
        "cypher": """
MATCH (t:Tunnel:Obj {encap: 'velocloud-vcmp'})
WHERE t.collection_ts = $snap AND NOT t:Retired
OPTIONAL MATCH (t)-[te:ENDPOINT]->(i:Interface)-[io:ON]->(ed:Device)
WHERE te._retired_at IS NULL AND NOT i:Retired AND NOT ed:Retired
// the uid names the edge and the WAN link at each end (collectors/velocloud.py
// _link_end): vco:<enterprise>:path:<edge>:<link>~gw:<gateway> or
// ~link:<far edge>:<far link>. A link with no interface has no ENDPOINT, and the
// uid still names its edge.
WITH t, te, i, io, ed, split(t.uid, ':path:') AS u
WITH t, te, i, io, ed, CASE WHEN ed IS NULL THEN u[0] + ':edge:' + split(u[1], ':')[0] END AS edge_uid
// both keys of the Obj(uid, collection_ts) index, so the edge is one index seek
OPTIONAL MATCH (ud:Obj)
WHERE ud.uid = edge_uid AND ud.collection_ts = $snap AND ud:Device AND NOT ud:Retired
WITH t, te, i, io, coalesce(ed, ud) AS d
// two WAN links can share one interface and its address: the uid tells them apart
OPTIONAL MATCH (d)-[hl:HAS_LINK]->(l:WanLink)
WHERE hl._retired_at IS NULL AND NOT l:Retired
  AND t.uid CONTAINS ':path:' + d.edge_logical_id + ':' + l.link_logical_id + '~'
OPTIONAL MATCH (t)-[tt:TERMINATES_ON]->(far) WHERE tt._retired_at IS NULL AND NOT far:Retired
// a hub or branch tunnel ends on an address. The far edge holds it on an
// interface, or after NAT on its WAN link only (app/routes/sdwan.py _TUNNELS)
OPTIONAL MATCH (far)<-[fh:HAS_IP]-(fi:Interface)-[:ON]->(fid:Device)
WHERE far:IpAddress AND fh._retired_at IS NULL AND NOT fi:Retired AND NOT fid:Retired
  AND fid.collection_ts = $snap
OPTIONAL MATCH (far)<-[flh:HAS_IP]-(fl:WanLink)<-[fhl:HAS_LINK]-(fld:Device)
WHERE far:IpAddress AND flh._retired_at IS NULL AND fhl._retired_at IS NULL
  AND NOT fl:Retired AND NOT fld:Retired AND fld.collection_ts = $snap
WITH t, te, i, io, d, hl, l, tt, far,
     min(coalesce(fid.hostname, fld.hostname)) AS far_edge,
     min(coalesce(fid.sdwan_role, fld.sdwan_role)) AS far_role,
     // the far link the uid names first: two links of the far edge can hold its address
     [x IN collect(DISTINCT fl) WHERE t.uid ENDS WITH ':' + x.link_logical_id]
       + collect(DISTINCT fl) AS far_links,
     min(fi.name) AS far_interface
OPTIONAL MATCH (t)-[c:CARRIES]->(seg:SdwanSegment) WHERE c._retired_at IS NULL AND NOT seg:Retired
WITH t, te, i, io, d, hl, l, tt, far, far_edge, far_role, far_links, far_interface,
     collect(DISTINCT seg.name) AS segments, collect(DISTINCT seg) AS _seg, collect(DISTINCT c) AS _c
// the collector writes peer_type edge for a far edge that is not a hub; a far
// device with sdwan_role hub is a hub whatever the peer_type (app/routes/sdwan.py _far_kind)
RETURN d.hostname AS edge, l.name AS wan_link, l.carrier AS carrier,
       coalesce(i.name, l.interface) AS interface, t.local_address AS local_ip,
       CASE WHEN t.peer_type = 'edge' AND coalesce(far_role, '') <> 'hub' THEN 'branch'
            WHEN t.peer_type = 'edge' THEN 'hub' ELSE t.peer_type END AS peer_type,
       CASE WHEN far:SdwanGateway THEN far.name ELSE far_edge END AS far_device,
       coalesce(head(far_links).name, far_interface) AS far_link, t.endpoint AS far_ip, segments,
       CASE WHEN t.peer_type = 'gateway' THEN NULL ELSE t.pair END AS pair,
       t AS _t, i AS _i, d AS _d, l AS _l, far AS _far,
       te AS _te, io AS _io, hl AS _hl, tt AS _tt, _seg, _c
ORDER BY edge, far_device, wan_link, far_link
""",
    },
    {
        "key": "sdwan-topology",
        "group": "cloud & wan",
        "title": "SD-WAN hubs and spokes",
        "description": "per edge: its role, its gateway tunnels, its tunnels to hubs and branches, "
        "its overlay connections with the device or gateway at the other end, and its WAN links per kind",
        "cypher": """
MATCH (d:Device:Obj {platform: 'velocloud-edge'})
WHERE d.collection_ts = $snap AND NOT d:Retired
OPTIONAL MATCH (d)<-[:ON]-(:Interface)<-[te:ENDPOINT]-(t:Tunnel {encap: 'velocloud-vcmp'})
WHERE te._retired_at IS NULL AND NOT t:Retired
OPTIONAL MATCH (t)-[tt:TERMINATES_ON]->(gw:SdwanGateway) WHERE tt._retired_at IS NULL AND NOT gw:Retired
OPTIONAL MATCH (d)-[hl:HAS_LINK]->(l:WanLink) WHERE hl._retired_at IS NULL AND NOT l:Retired
WITH d, count(DISTINCT gw) AS gateways,
     count(DISTINCT CASE WHEN gw IS NOT NULL THEN t END) AS gateway_tunnels,
     count(DISTINCT CASE WHEN t.peer_type IN ['hub', 'edge'] THEN t END) AS hub_tunnels,
     count(DISTINCT CASE WHEN l.kind = 'mpls' THEN l END) AS mpls_links,
     count(DISTINCT CASE WHEN l.kind <> 'mpls' THEN l END) AS internet_links,
     collect(DISTINCT gw.name) AS gateway_names,
     collect(DISTINCT t) AS _t, collect(DISTINCT gw) AS _gw, collect(DISTINCT l) AS _l,
     collect(DISTINCT te) AS _te, collect(DISTINCT tt) AS _tt, collect(DISTINCT hl) AS _hl
// one OverlayConnection per pair of ends: every link and direction realizes the same one
OPTIONAL MATCH (d)<-[cb:BETWEEN]-(c:OverlayConnection) WHERE cb._retired_at IS NULL AND NOT c:Retired
OPTIONAL MATCH (c)-[pb:BETWEEN]->(peer) WHERE pb._retired_at IS NULL AND peer <> d AND NOT peer:Retired
RETURN d.hostname AS edge, d.enterprise_name AS enterprise, coalesce(d.sdwan_role, 'spoke') AS role,
       gateways, gateway_tunnels, hub_tunnels, mpls_links, internet_links, gateway_names,
       count(DISTINCT c) AS connections,
       collect(DISTINCT coalesce(peer.hostname, peer.name, peer.uid)) AS peers,
       d AS _d, _t, _gw, _l, _te, _tt, _hl, collect(DISTINCT c) AS _oc, collect(DISTINCT cb) AS _cb
ORDER BY enterprise, role, edge
""",
    },
    {
        "key": "sdwan-segments",
        "group": "cloud & wan",
        "title": "SD-WAN segments",
        "description": "every segment with the edges that have a boundary in it and the paths that carry it",
        "cypher": """
MATCH (seg:SdwanSegment:Obj)
WHERE seg.collection_ts = $snap AND NOT seg:Retired
OPTIONAL MATCH (seg)<-[fin:IN]-(fb:ForwardingBoundary)<-[hb:HAS_BOUNDARY]-(d:Device)
WHERE fin._retired_at IS NULL AND hb._retired_at IS NULL AND NOT fb:Retired AND NOT d:Retired
OPTIONAL MATCH (seg)<-[c:CARRIES]-(t:Tunnel) WHERE c._retired_at IS NULL AND NOT t:Retired
RETURN seg.name AS segment, seg.segment_id AS segment_id, seg.enterprise_name AS enterprise,
       count(DISTINCT d) AS edges, count(DISTINCT t) AS paths, collect(DISTINCT d.hostname) AS edge_names,
       seg AS _seg, collect(DISTINCT fb) AS _fb, collect(DISTINCT d) AS _d, collect(DISTINCT t) AS _t,
       collect(DISTINCT fin) AS _fin, collect(DISTINCT hb) AS _hb, collect(DISTINCT c) AS _c
ORDER BY enterprise, segment
""",
    },
    {
        "key": "sdwan-link-steering",
        "group": "cloud & wan",
        "title": "SD-WAN link steering",
        "description": "business policy rules that name a WAN link or a class of link on each edge",
        "cypher": """
MATCH (d:Device)-[en:ENFORCES]->(bp:SdwanBusinessPolicy:Obj)-[sv:STEERS_VIA]->(l:WanLink)
WHERE bp.collection_ts = $snap
  AND NOT d:Retired AND NOT bp:Retired AND NOT l:Retired
  AND en._retired_at IS NULL AND sv._retired_at IS NULL
RETURN d.hostname AS edge, sv.application_class AS rule, sv.preference AS link_policy,
       l.name AS link, l.kind AS kind, l.carrier AS carrier, l.state AS state,
       d AS _d, bp AS _bp, l AS _l, en AS _en, sv AS _sv
ORDER BY edge, rule, link
""",
    },
    {
        "key": "sdwan-gaps",
        "group": "cloud & wan",
        "title": "SD-WAN discovery gaps",
        "description": "edges whose module read or profile read was refused, with the recorded reason",
        "cypher": """
MATCH (d:Device:Obj {platform: 'velocloud-edge'})
WHERE d.collection_ts = $snap AND NOT d:Retired
OPTIONAL MATCH (d)-[hb:HAS_BOUNDARY]->(fb:ForwardingBoundary)
WHERE hb._retired_at IS NULL AND NOT fb:Retired AND fb.gaps IS NOT NULL
OPTIONAL MATCH (d)-[en:ENFORCES]->(bp:SdwanBusinessPolicy)
WHERE en._retired_at IS NULL AND NOT bp:Retired AND bp.capability_gap IS NOT NULL
WITH d, hb, fb, en, bp WHERE fb IS NOT NULL OR bp IS NOT NULL
RETURN d.hostname AS edge, d.enterprise_name AS enterprise,
       collect(DISTINCT fb.segment_id) AS segments,
       head(collect(DISTINCT fb.gaps)) AS path_gaps, bp.capability_gap AS policy_gap,
       d AS _d, bp AS _bp, en AS _en, collect(DISTINCT fb) AS _fb, collect(DISTINCT hb) AS _hb
ORDER BY enterprise, edge
""",
    },
    # --- compliance (shares the group with the DORA scenarios from demo.py)
    {
        "key": "crypto",
        "group": "compliance",
        "title": "Crypto algorithm inventory",
        "cypher": """
MATCH (t:Tunnel:Obj) WHERE t.collection_ts = $snap AND NOT t:Retired
OPTIONAL MATCH (t)-[e:ENDPOINT]->(x)
OPTIONAL MATCH (x)-[xo:ON]->(d:Device) WHERE xo._retired_at IS NULL
WITH t,
     [h IN collect(DISTINCT d.hostname) WHERE h IS NOT NULL] AS ends,
     collect(DISTINCT x) AS _xs, collect(DISTINCT e) AS _es
RETURN 'tunnel' AS kind, t.name AS name, t.encap AS transport,
       ends AS terminates_on, t.endpoint AS remote,
       CASE t.encap
         WHEN 'wireguard' THEN 'Curve25519 + ChaCha20-Poly1305 + BLAKE2s'
         WHEN 'zpa-mtls' THEN 'mutual TLS (Zscaler ZPA)'
         WHEN 'ipsec' THEN 'IPsec (proposals not collected)'
         WHEN 'velocloud-vcmp' THEN 'VCMP/IPsec (proposals not collected)'
         WHEN 'gre' THEN 'none (cleartext)'
         WHEN 'vxlan' THEN 'none (cleartext)'
         ELSE coalesce(t.encap, 'unknown') END AS algorithms,
       CASE t.encap
         WHEN 'wireguard' THEN 'protocol-implied'
         WHEN 'zpa-mtls' THEN 'protocol-implied'
         WHEN 'gre' THEN 'none'
         WHEN 'vxlan' THEN 'none'
         ELSE 'configured, details not collected' END AS basis,
       t AS _t, _xs, _es, null AS _ssid
UNION ALL
MATCH (s:Ssid:Obj) WHERE s.collection_ts = $snap AND NOT s:Retired
RETURN 'wifi' AS kind, s.name AS name, 'wlan' AS transport,
       [] AS terminates_on, null AS remote,
       CASE s.security
         WHEN 'wpapsk' THEN 'WPA-PSK'
         WHEN 'wpaeap' THEN 'WPA-Enterprise (802.1X)'
         WHEN 'open' THEN 'none (open)'
         ELSE coalesce(s.security, 'unknown') END AS algorithms,
       CASE
         WHEN s.security IS NULL THEN 'unknown'
         WHEN s.security = 'open' THEN 'none'
         ELSE 'configured' END AS basis,
       null AS _t, [] AS _xs, [] AS _es, s AS _ssid
""",
    },
    # --- hygiene
    {
        "key": "ipam-vlan-mismatch",
        "group": "hygiene",
        "title": "Register VLAN mismatch",
        "description": "the prefixes whose IPAdmin import VLAN is not a VLAN of the SVI that serves "
        "the prefix in this run",
        "cypher": """
MATCH (p:Prefix:Obj)
WHERE p.collection_ts = $snap AND NOT p:Retired AND p.ipam_vlan IS NOT NULL
MATCH (i:Interface {kind: 'svi'})-[h:HAS_IP]->(ia:IpAddress)-[n:IN]->(p)
WHERE NOT i:Retired AND NOT ia:Retired AND h._retired_at IS NULL AND n._retired_at IS NULL
MATCH (i)-[b:BOUND_TO]->(v:VlanInstance) WHERE b._retired_at IS NULL AND NOT v:Retired
OPTIONAL MATCH (i)-[o:ON]->(d:Device) WHERE o._retired_at IS NULL AND NOT d:Retired
WITH p, i, d, collect(DISTINCT v.vid) AS vids
WHERE NOT p.ipam_vlan IN vids
RETURN p.cidr AS prefix, p.l3dom AS l3dom, p.ipam_vlan AS register_vlan, vids AS svi_vlans,
       d.hostname AS device, i.name AS svi, p.ipam_description AS register, p AS _p, i AS _i, d AS _d
ORDER BY prefix, device
""",
    },
    {
        "key": "drift-cables",
        "group": "hygiene",
        "title": "Cable drift",
        "description": "cabling documented in Nautobot but not seen, or seen but not documented",
        "cypher": """
MATCH (a:Port:Obj)-[r:CONNECTED_TO]-(b:Port)
WHERE a.collection_ts = $snap AND a.uid < b.uid AND r._retired_at IS NULL
WITH a, b, collect(DISTINCT r) AS rels, collect(DISTINCT r.source) AS srcs
WHERE ('nautobot-cable' IN srcs) <> any(s IN srcs WHERE s IN ['lldp', 'cdp', 'unifi'])
MATCH (a)-[oa:ON]->(da), (b)-[ob:ON]->(db)
RETURN da.hostname AS device_a, a.name AS port_a, db.hostname AS device_b, b.name AS port_b,
       CASE WHEN 'nautobot-cable' IN srcs THEN 'documented-but-not-seen'
            ELSE 'seen-but-not-documented' END AS drift,
       a AS _a, b AS _b, rels AS _rels, oa AS _oa, ob AS _ob, da AS _da, db AS _db
""",
    },
    {
        "key": "naming",
        "group": "hygiene",
        "title": "Duplicate device names",
        "description": "same box known by different names across systems (identities[] > 1)",
        "cypher": """
MATCH (d:Device:Obj) WHERE d.collection_ts = $snap
  AND size(coalesce(d.identities, [])) > 1
RETURN d.serial AS serial, d.hostname AS canonical, d.identities AS also_known_as, d AS _d
ORDER BY size(d.identities) DESC
""",
    },
    {
        "key": "policy-unresolved",
        "group": "hygiene",
        "title": "Unresolved policy names",
        "description": "sessions and route-map clauses naming a route-map or prefix-list the device lacks",
        "cypher": """
MATCH (s:BgpSession:Obj) WHERE s.collection_ts = $snap AND NOT s:Retired
  AND s.import_policy_name IS NOT NULL
  AND NOT EXISTS { MATCH (s)-[f:FILTERED_BY {direction: 'in'}]->(:RoutePolicy) WHERE f._retired_at IS NULL }
RETURN 'session import' AS where_used, s.uid AS owner, s.import_policy_kind AS kind,
       s.import_policy_name AS name, s AS _n
UNION
MATCH (s:BgpSession:Obj) WHERE s.collection_ts = $snap AND NOT s:Retired
  AND s.export_policy_name IS NOT NULL
  AND NOT EXISTS { MATCH (s)-[f:FILTERED_BY {direction: 'out'}]->(:RoutePolicy) WHERE f._retired_at IS NULL }
RETURN 'session export' AS where_used, s.uid AS owner, s.export_policy_kind AS kind,
       s.export_policy_name AS name, s AS _n
UNION
MATCH (e:RoutePolicyEntry:Obj) WHERE e.collection_ts = $snap AND NOT e:Retired
  AND e.match_prefix_lists IS NOT NULL
UNWIND e.match_prefix_lists AS pl
WITH e, pl
WHERE NOT EXISTS {
  MATCH (e)-[r:REFERENCES {kind: 'prefix-list'}]->(p:RoutePolicy) WHERE r._retired_at IS NULL AND p.name = pl
}
RETURN 'route-map match' AS where_used, e.uid AS owner, 'prefix-list' AS kind, pl AS name, e AS _n
UNION
MATCH (e:RoutePolicyEntry:Obj) WHERE e.collection_ts = $snap AND NOT e:Retired
  AND e.calls_policy IS NOT NULL
  AND NOT EXISTS {
    MATCH (e)-[r:REFERENCES {kind: 'call'}]->(p:RoutePolicy)
    WHERE r._retired_at IS NULL AND p.name = e.calls_policy
  }
RETURN 'route-map call' AS where_used, e.uid AS owner, 'route-map' AS kind, e.calls_policy AS name, e AS _n
""",
    },
    # --- Equinix Fabric and Network Edge (collectors/equinix.py)
    {
        "key": "equinix-fabric-ports",
        "group": "equinix",
        "title": "Fabric ports",
        "description": "every Fabric port of a metro, its cable ids, and the switch port it lands on",
        "params": [_METRO_PARAM],
        "cypher": """
MATCH (fp:FabricPort:Obj)
WHERE fp.collection_ts = $snap AND NOT fp:Retired AND ($metro = '' OR fp.metro = $metro)
OPTIONAL MATCH (fp)-[r:REALIZED_BY]->(p:Port) WHERE r._retired_at IS NULL AND NOT p:Retired
OPTIONAL MATCH (p)-[o:ON]->(d:Device) WHERE o._retired_at IS NULL AND NOT d:Retired
RETURN fp.metro AS metro, fp.ibx AS ibx, fp.name AS fabric_port, fp.state AS state,
       fp.speed_mbps AS speed_mbps, fp.redundancy AS redundancy, fp.lag_name AS lag,
       fp.cross_connect_ids AS cable_ids, d.hostname AS device, p.name AS device_port,
       CASE WHEN r IS NULL THEN null WHEN r.derived THEN coalesce(r.evidence, 'derived')
            ELSE 'operator binding' END AS bound_by,
       fp AS _fp, r AS _r, p AS _p, o AS _o, d AS _d
ORDER BY metro, ibx, fabric_port
""",
    },
    {
        "key": "equinix-unbound-ports",
        "group": "equinix",
        "title": "Unbound Fabric ports",
        "description": "the Fabric ports that no switch port realizes, the reason, and for a port "
        "without an operator binding the text to set on the switch port",
        "params": [_METRO_PARAM],
        "cypher": f"""
MATCH (fp:FabricPort:Obj)
WHERE fp.collection_ts = $snap AND NOT fp:Retired AND ($metro = '' OR fp.metro = $metro)
  AND NOT EXISTS {{
    MATCH (fp)-[r:REALIZED_BY]->(p:Port) WHERE r._retired_at IS NULL AND NOT p:Retired
  }}
OPTIONAL MATCH (vc:VirtualCircuit)-[e:A_END|Z_END]->(fp)
WHERE e._retired_at IS NULL AND NOT vc:Retired
  AND NOT toUpper(coalesce(vc.state, '')) IN {_ENDED_CIRCUIT_STATES}
RETURN fp.metro AS metro, fp.ibx AS ibx, fp.name AS fabric_port, fp.cross_connect_ids AS cable_ids,
       count(DISTINCT vc) AS circuits,
       CASE WHEN fp.bound_port_uid IS NOT NULL THEN 'binding-refused' ELSE fp.binding_issue END AS reason,
       CASE WHEN fp.bound_port_uid IS NOT NULL THEN [fp.bound_port_uid] ELSE fp.binding_ports END
         AS reason_ports,
       CASE WHEN fp.bound_port_uid IS NULL
            THEN 'TO EQUINIX FABRIC - ' + fp.name + ' - CABLE ID : '
                 + coalesce(head(fp.cross_connect_ids), '?')
       END AS description_to_set,
       collect(DISTINCT fp) AS _fp
ORDER BY metro, ibx, fabric_port
""",
    },
    {
        "key": "equinix-circuits",
        "group": "equinix",
        "title": "Circuits",
        "description": "the circuits with an end in a metro that are not ended: both ends, the VLAN "
        "tag per side, and whether the reasoner drew the link",
        "params": [_METRO_PARAM],
        "cypher": f"""
MATCH (vc:VirtualCircuit:Obj)
WHERE vc.collection_ts = $snap AND NOT vc:Retired
  AND NOT toUpper(coalesce(vc.state, '')) IN {_ENDED_CIRCUIT_STATES}
OPTIONAL MATCH (vc)-[ae:A_END]->(a) WHERE ae._retired_at IS NULL AND NOT a:Retired
OPTIONAL MATCH (vc)-[ze:Z_END]->(z) WHERE ze._retired_at IS NULL AND NOT z:Retired
WITH vc, a, z, ae, ze, {_END_METRO.format(e="a")} AS a_metro, {_END_METRO.format(e="z")} AS z_metro
WHERE $metro = '' OR $metro IN [a_metro, z_metro]
RETURN vc.name AS circuit, vc.type AS type, vc.state AS state, vc.bandwidth_mbps AS mbps,
       coalesce({_END_NAME.format(e="a")}, vc.a_virtual_device, vc.a_side_kind) AS a_end, a_metro,
       ae.vlan_tag AS a_vlan,
       coalesce({_END_NAME.format(e="z")}, vc.provider, vc.z_side_kind) AS z_end, z_metro,
       ze.vlan_tag AS z_vlan,
       {CIRCUIT_CABLED} AS cabled,
       vc AS _vc, a AS _a, z AS _z, ae AS _ae, ze AS _ze
ORDER BY circuit
LIMIT 1000
""",
    },
    {
        "key": "equinix-circuit-cables",
        "group": "equinix",
        "title": "Links from circuits",
        "description": "the switch-to-switch links the reasoner drew from active circuits, "
        "with the VLAN tag per side",
        "params": [_METRO_PARAM],
        "cypher": f"""
MATCH (pa:Port:Obj {{collection_ts: $snap}})-[c:CONNECTED_TO {{source: 'equinix-circuit'}}]->(pz:Port)
WHERE c._retired_at IS NULL AND c.collection_ts = $snap
MATCH (pa)-[oa:ON]->(da:Device), (pz)-[oz:ON]->(dz:Device)
WHERE oa._retired_at IS NULL AND oz._retired_at IS NULL
MATCH (vc:VirtualCircuit:Obj) WHERE vc.uid = c.circuit_uid AND vc.collection_ts = $snap
WITH c, pa, pz, oa, oz, da, dz, vc, [(vc)-[:A_END|Z_END]->(x) | {_END_METRO.format(e="x")}] AS metros
WHERE $metro = '' OR $metro IN metros
RETURN vc.name AS circuit, vc.type AS type, da.hostname AS a_device, pa.name AS a_port,
       c.vlan_tag_a AS a_vlan, dz.hostname AS z_device, pz.name AS z_port, c.vlan_tag_z AS z_vlan,
       pa AS _pa, pz AS _pz, c AS _c, oa AS _oa, oz AS _oz, da AS _da, dz AS _dz
ORDER BY a_device, a_port, circuit
""",
    },
    {
        "key": "equinix-ended-circuits",
        "group": "equinix",
        "title": "Ended circuits",
        "description": "the deprovisioned, deleted and cancelled circuits the account still lists; "
        "they draw no link",
        "params": [_METRO_PARAM],
        "cypher": f"""
MATCH (vc:VirtualCircuit:Obj)
WHERE vc.collection_ts = $snap AND NOT vc:Retired
  AND toUpper(coalesce(vc.state, '')) IN {_ENDED_CIRCUIT_STATES}
OPTIONAL MATCH (vc)-[e:A_END|Z_END]->(f:FabricPort) WHERE e._retired_at IS NULL
WITH vc, collect(DISTINCT f) AS ports
WHERE $metro = '' OR any(f IN ports WHERE f.metro = $metro)
RETURN vc.name AS circuit, vc.state AS state, vc.type AS type, [f IN ports | f.name] AS fabric_ports,
       vc AS _vc
ORDER BY circuit
""",
    },
    {
        "key": "equinix-network-edge",
        "group": "equinix",
        "title": "Network Edge devices",
        "description": "the Network Edge virtual devices, the device each one is bound to, "
        "and their interfaces",
        "params": [_METRO_PARAM],
        "cypher": """
MATCH (d:Device:Obj {platform: 'network-edge'})
WHERE d.collection_ts = $snap AND NOT d:Retired AND ($metro = '' OR d.metro = $metro)
OPTIONAL MATCH (d)-[s:SAME_AS]->(t:Device) WHERE s._retired_at IS NULL AND NOT t:Retired
RETURN d.hostname AS device, d.vendor AS vendor, d.model AS model, d.role AS role, d.ibx AS ibx,
       d.edge_status AS status, d.bound_device_uid AS bound_device_uid, t.hostname AS same_as,
       COUNT {
         MATCH (i:Interface:Obj)
         WHERE i.edge_device_uid = d.uid AND i.collection_ts = $snap AND NOT i:Retired
       } AS interfaces,
       d AS _d, s AS _s, t AS _t
ORDER BY device
""",
    },
    {
        "key": "equinix-device-links",
        "group": "equinix",
        "title": "Network Edge device links",
        "description": "each pair of members of a device link group, and whether the reasoner drew the link",
        "params": [_METRO_PARAM],
        "cypher": f"""
MATCH (vc:VirtualCircuit:Obj {{type: 'DEVICE_LINK'}})-[ae:A_END]->(a:Interface),
      (vc)-[ze:Z_END]->(z:Interface)
WHERE vc.collection_ts = $snap AND NOT vc:Retired
  AND ae._retired_at IS NULL AND ze._retired_at IS NULL
OPTIONAL MATCH (ad:Obj) WHERE ad.uid = a.edge_device_uid AND ad.collection_ts = $snap AND ad:Device
OPTIONAL MATCH (zd:Obj) WHERE zd.uid = z.edge_device_uid AND zd.collection_ts = $snap AND zd:Device
WITH vc, a, z, ae, ze, ad, zd
WHERE $metro = '' OR $metro IN [ad.metro, zd.metro]
RETURN vc.name AS link_group, vc.state AS state, vc.bandwidth_mbps AS mbps,
       ad.hostname AS a_device, a.name AS a_interface, zd.hostname AS z_device, z.name AS z_interface,
       {CIRCUIT_CABLED} AS cabled,
       vc AS _vc, a AS _a, z AS _z, ae AS _ae, ze AS _ze, ad AS _ad, zd AS _zd
ORDER BY link_group, a_device
""",
    },
]


# --- audit --------------------------------------------------------------------------
AUDIT_INTERFACES_MISSING_CONTEXT = """
MATCH (i:Interface:Obj)-[h:HAS_IP]->(ip:IpAddress)
WHERE i.collection_ts = $snap
  AND NOT i:Retired AND h._retired_at IS NULL AND NOT ip:Retired
  AND NOT EXISTS {
    MATCH (i)-[r:IN_VRF]->()
    WHERE r._retired_at IS NULL
  }
MATCH (i)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT d:Retired
RETURN d.uid AS device_uid, i.uid AS interface_uid, i.name AS interface_name,
       count(DISTINCT ip) AS address_count
ORDER BY device_uid, interface_name
"""


# --- name resolution -----------------------------------------------------------------
RESOLVE_CONTEXT_QUERY = """
MATCH (v:VrfInstance:Obj)
WHERE v.collection_ts = $snap
  AND NOT v:Retired AND toLower(v.name) = toLower($name)
OPTIONAL MATCH (v)-[m:MEMBER_OF]->(rd:RoutingDomain)
WHERE m._retired_at IS NULL AND NOT rd:Retired
WITH v, collect(DISTINCT rd.name) AS domains
WHERE $domain IS NULL OR any(dn IN domains WHERE toLower(dn) = toLower($domain))
OPTIONAL MATCH (v)-[owner:OWNED_BY]->(od:Device)
WHERE owner._retired_at IS NULL AND NOT od:Retired
  AND od.collection_ts = $snap
OPTIONAL MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[o:ON]->(id:Device)
WHERE iv._retired_at IS NULL AND NOT i:Retired AND o._retired_at IS NULL AND NOT id:Retired
  AND i.collection_ts = $snap AND id.collection_ts = $snap
WITH v, domains, collect(DISTINCT od) + collect(DISTINCT id) AS owners
UNWIND CASE WHEN size(owners) = 0 THEN [null] ELSE owners END AS d
RETURN v.uid AS uid, v.name AS name, v.table_id AS table_id, v.is_global AS is_global,
       v.rd AS rd, domains, collect(DISTINCT d.uid) AS devices
ORDER BY uid
"""


def resolve_context(tx: Any, name: str, domain: str | None = None, snap: Any = None) -> list[dict[str, Any]]:
    """Resolve a human name to forwarding-context (VrfInstance) rows.

    The match on `name` is exact and case-insensitive. Every live match is
    returned. Each row has uid, table_id, is_global, rd, the distinct names of the
    RoutingDomains that the context is MEMBER_OF (edges with `basis: declared` and
    with `basis: rt-component` are collected together), and the distinct uids of
    the devices that are recorded as owners or reached through its interfaces.
    `domain=` limits the rows to contexts that are MEMBER_OF a RoutingDomain with
    that name (case-insensitive). A returned row keeps all of its domain names.

    Device-local contexts record OWNED_BY, also without interfaces. Shared contexts
    and snapshots without OWNED_BY have the interface association. Conflicting owners
    are returned together. A context with neither association has an empty device list.

    `snap` pins the read to one run (`v.collection_ts = $snap` on the `:Obj`
    anchor). A caller that has resolved the pointer passes its `collection_ts`.
    Without `snap`, the query binds the live sentinel. No versioned node has the
    live sentinel, and the read returns no rows. A caller through
    `app/tables.run_readonly` does not pass `snap`.

    `tx` is an object with `.run(query, parameters=...)` that returns a result with `.data()`.
    The caller opens the read transaction (`@unit_of_work`).
    """
    from hst.path import LIVE_SNAP

    bound_snap = snap if snap is not None else LIVE_SNAP
    result = tx.run(RESOLVE_CONTEXT_QUERY, parameters={"name": name, "domain": domain, "snap": bound_snap})
    return result.data()


# The UI catalog does not list these scenarios. A canned query replaces each of them.
# `naming` replaces naming-hygiene (byte-identical Cypher). `drift-cables` replaces
# cable-drift (same intent). `drift-cables` also excludes retired cables and counts
# unifi as a seen source.
_SUPERSEDED_BY_QUERY = {"naming-hygiene", "cable-drift"}


# The zscaler group has a ZPA and a ZIA section. Each section lists lookups, then
# lists, then checks. Each entry has its section, its ZPA or ZIA console name as
# the title, and the words that the palette matches.
_ZPA_WORDS = [
    "segment group",
    "application segment",
    "server group",
    "app connector group",
    "SCIM group",
    "identity",
]
_ZIA_WORDS = ["location", "forwarding rule", "data center", "tunnel"]
_ZSCALER_LAYOUT: dict[str, tuple[str, str, list[str]]] = {
    "zpa-app-segment": ("ZPA", "App segment", _ZPA_WORDS),
    "zpa-app-group": ("ZPA", "Segment group", _ZPA_WORDS),
    "zpa-user-group": ("ZPA", "User group", _ZPA_WORDS),
    "zpa-connector-group": ("ZPA", "App connector group", _ZPA_WORDS),
    "zpa-connectors": ("ZPA", "App connectors", [*_ZPA_WORDS, "private service edge"]),
    "zpa-policy-rules": ("ZPA", "Policy rules", [*_ZPA_WORDS, "access policy", "client forwarding"]),
    "zpa-segments-at-risk": ("ZPA", "Segments at risk", _ZPA_WORDS),
    "zpa-groups-without-rules": ("ZPA", "Groups without rules", _ZPA_WORDS),
    "zia-location": ("ZIA", "Location", _ZIA_WORDS),
    "zia-location-group": ("ZIA", "Location group", _ZIA_WORDS),
    "zia-dc-users": ("ZIA", "Locations on a data center", _ZIA_WORDS),
    "scenario-zia-guest-egress": ("ZIA", "Guest Wi-Fi egress", [*_ZIA_WORDS, "guest", "ssid"]),
    "zia-forwarding-rules": ("ZIA", "Forwarding rules", [*_ZIA_WORDS, "ZPA"]),
    "zia-location-egress": ("ZIA", "Locations", [*_ZIA_WORDS, "egress", "site", "gaps"]),
}
for _entry in QUERIES:
    if _entry["key"] in _ZSCALER_LAYOUT:
        _entry["section"], _entry["title"], _entry["keywords"] = _ZSCALER_LAYOUT[_entry["key"]]


# The name the rail and the palette show for each group.
GROUP_TITLES: dict[str, str] = {
    "inventory": "Inventory",
    "topology": "Topology",
    "routing": "Routing",
    "policy": "Policy",
    "endpoints": "Endpoints",
    "hygiene": "Hygiene",
    "compliance": "Compliance",
    "cloud & wan": "Cloud and WAN",
    "zscaler": "Zscaler",
    "equinix": "Equinix",
}


def _library_order(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The zscaler entries in layout order, placed before the equinix group."""
    order = list(_ZSCALER_LAYOUT)
    zscaler = sorted((e for e in entries if e["key"] in _ZSCALER_LAYOUT), key=lambda e: order.index(e["key"]))
    rest = [e for e in entries if e["key"] not in _ZSCALER_LAYOUT]
    at = next((i for i, e in enumerate(rest) if e["group"] == "equinix"), len(rest))
    return rest[:at] + zscaler + rest[at:]


# The labels that show one vendor product holds data in a run. A catalog entry
# keyed on a product (`requires`) is listed only when one of them has a node.
# WanLink is not an SD-WAN key. vyos.py also writes WanLink.
PRODUCT_LABELS: dict[str, tuple[str, ...]] = {
    "zpa": ("ZpaAppSegment", "ZpaSegmentGroup", "ZpaAppConnector", "ZpaServiceEdge"),
    "zia": ("ZiaLocation", "ZiaForwardingRule"),
    "sdwan": ("SdwanSegment", "SdwanGateway", "SdwanBusinessPolicy"),
    "equinix": ("FabricPort", "VirtualCircuit"),
}
# Device platforms that also show a product. `velocloud-edge` covers the VeloCloud
# edges section. `network-edge` covers an Equinix account with Network Edge devices
# only.
PRODUCT_PLATFORMS: dict[str, tuple[str, ...]] = {
    "sdwan": ("velocloud-edge",),
    "equinix": ("network-edge",),
}


def _pinned_exists(match: str, var: str, extra: str = "") -> str:
    return f"EXISTS {{ MATCH {match} WHERE {var}.collection_ts = $snap AND NOT {var}:Retired{extra} }}"


def presence_cypher() -> str:
    """One statement with one boolean column per product. A column is true when
    the run pinned by `$snap` holds a node that shows the product."""
    columns = []
    for product, labels in PRODUCT_LABELS.items():
        checks = [_pinned_exists(f"(n:{label})", "n") for label in labels]
        platforms = PRODUCT_PLATFORMS.get(product)
        if platforms:
            checks.append(_pinned_exists("(n:Device)", "n", f" AND n.platform IN {list(platforms)!r}"))
        columns.append(f"({' OR '.join(checks)}) AS {product}")
    return "RETURN " + ", ".join(columns)


def _requires(key: str) -> str | None:
    product = key.split("-", 1)[0]
    return product if product in PRODUCT_LABELS else None


def catalog() -> list[dict[str, Any]]:
    """The canned queries and the validation scenarios, in one set of groups.

    A `title` fits on one line.
    """
    from hst.demo import SCENARIOS

    entries = [dict(q) for q in QUERIES]
    for entry in entries:
        product = _requires(entry["key"])
        if product:
            entry["requires"] = product
    for sc in SCENARIOS:
        if sc["key"] in _SUPERSEDED_BY_QUERY or sc.get("fixture_only"):
            continue
        entries.append(
            {
                "key": f"scenario-{sc['key']}",
                "group": sc.get("group", "scenarios"),
                "title": sc["title"],
                "description": sc.get("description", ""),
                "cypher": sc["cypher"],
                **({"requires": sc["requires"]} if sc.get("requires") else {}),
            }
        )
    for entry in entries:
        if entry["key"].startswith("scenario-") and entry["key"] in _ZSCALER_LAYOUT:
            entry["section"], entry["title"], entry["keywords"] = _ZSCALER_LAYOUT[entry["key"]]
        entry["group_title"] = GROUP_TITLES.get(entry["group"], entry["group"])
    return _library_order(entries)
