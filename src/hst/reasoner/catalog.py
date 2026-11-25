"""The rule catalog `run()` walks in order."""

from __future__ import annotations

# Every connected pattern component starts from `:Obj` with an equality on
# `collection_ts`.
#
# A rule with `query` None is resolved in Python by `run()` at its list position.
RULES: list[tuple[str, str | None]] = [
    ("cable-from-uplink-record", None),
    ("cable-from-lldp-record", None),
    ("cable-from-neighbor-name", None),
    # The pair guard reads the cables of the 3 rules above.
    #
    # The guards, in order:
    # 1. The port has no other endpoint in the run.
    # 2. Every neighbor record on the port is absent, or holds the MAC of the
    #    endpoint, or holds a MAC on the device of the endpoint. `dev_macs`
    #    is every Port and Interface MAC on that device, and its Device.mac.
    # 3. Neither port has a stated cable to a different peer.
    (
        "cable-from-endpoint-mac",
        """
MATCH (ep:Endpoint:Obj)-[at:ATTACHED]->(swp:Port)
WHERE ep.mac IS NOT NULL AND NOT ep:Retired AND NOT swp:Retired
  AND at._retired_at IS NULL
  AND ep.collection_ts = $cts
  AND NOT EXISTS {
    MATCH (other:Endpoint)-[at2:ATTACHED]->(swp)
    WHERE other.uid <> ep.uid AND NOT other:Retired AND at2._retired_at IS NULL
      AND other.collection_ts = $cts
  }
MATCH (i:Interface:Obj {mac: ep.mac, collection_ts: $cts})-[rb:REALIZED_BY]->(rp:Port)
WHERE rp.uid <> swp.uid AND NOT i:Retired AND NOT rp:Retired
  AND rb._retired_at IS NULL
OPTIONAL MATCH (i)-[ion:ON]->(idev:Device)
WHERE ion._retired_at IS NULL AND NOT idev:Retired
WITH ep, swp, i, rp,
     [(idev)<-[:ON]-(n) WHERE NOT n:Retired AND n.mac IS NOT NULL | n.mac]
       + CASE WHEN idev.mac IS NULL THEN [] ELSE [idev.mac] END AS dev_macs
WHERE all(h IN [swp.last_conn_mac, swp.lldp_neighbor_mac, swp.uplink_mac]
          WHERE h IS NULL OR h = ep.mac OR h IN dev_macs)
WITH DISTINCT swp, rp, ep,
     CASE WHEN swp.uid < rp.uid THEN swp ELSE rp END AS a,
     CASE WHEN swp.uid < rp.uid THEN rp ELSE swp END AS z
WHERE NOT EXISTS {
  MATCH (a)-[u:CONNECTED_TO]-(o:Port)
  WHERE o.uid <> z.uid AND u.collection_ts = $cts
    AND (u.source IN $stated_cable_sources OR u.derived = false)
}
AND NOT EXISTS {
  MATCH (z)-[u2:CONNECTED_TO]-(o2:Port)
  WHERE o2.uid <> a.uid AND u2.collection_ts = $cts
    AND (u2.source IN $stated_cable_sources OR u2.derived = false)
}
MERGE (a)-[c:CONNECTED_TO {source: 'reasoner'}]->(z)
SET c.derived = true, c.rule = 'cable-from-endpoint-mac',
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
SET ep.infra = true
RETURN count(DISTINCT a) AS n
""",
    ),
    (
        "cable-from-last-connection",
        """
MATCH (swp:Port:Obj)
WHERE swp.last_conn_mac IS NOT NULL AND NOT swp:Retired
  AND swp.collection_ts = $cts
MATCH (i:Interface:Obj {mac: swp.last_conn_mac, collection_ts: $cts})-[rb:REALIZED_BY]->(rp:Port)
WHERE rp.uid <> swp.uid AND NOT i:Retired AND NOT rp:Retired
  AND rb._retired_at IS NULL
WITH DISTINCT swp, rp,
     CASE WHEN swp.uid < rp.uid THEN swp ELSE rp END AS a,
     CASE WHEN swp.uid < rp.uid THEN rp ELSE swp END AS z
WHERE NOT EXISTS {
  MATCH (a)-[u:CONNECTED_TO]-()
  WHERE u.collection_ts = $cts
    AND (u.source IN $stated_cable_sources OR u.derived = false)
}
AND NOT EXISTS {
  MATCH (z)-[u2:CONNECTED_TO]-()
  WHERE u2.collection_ts = $cts
    AND (u2.source IN $stated_cable_sources OR u2.derived = false)
}
MERGE (a)-[c:CONNECTED_TO {source: 'reasoner'}]->(z)
SET c.derived = true, c.rule = 'cable-from-last-connection',
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN count(DISTINCT a) AS n
""",
    ),
    # `resolve_fabric_port_bindings` resolves this rule in Python with a
    # whole-word name match and a cable id parse. cable-from-fabric-circuit
    # reads the REALIZED_BY edges of this rule and runs after it.
    ("fabric-port-from-description", None),
    # `resolve_edge_device_bindings` resolves this rule in Python with a MAC
    # join against the ports of the bound device. cable-from-fabric-circuit
    # reads the ON and REALIZED_BY edges of this rule and runs after it.
    ("edge-device-from-binding", None),
    # `resolve_zpa_zia_ip_links` resolves this rule in Python with a join on
    # the address value. It reads only collected nodes and HAS_IP edges.
    ("zpa-zia-ip-same-as", None),
    (
        "zia-forwarding-to-zpa-segment",
        """
MATCH (f:ZiaForwardingRule:Obj)
WHERE NOT f:Retired AND f.collection_ts = $cts AND f.zpa_app_segment_ids IS NOT NULL
UNWIND f.zpa_app_segment_ids AS wanted
OPTIONAL MATCH (x:ZpaAppSegment:Obj {zpa_id: wanted})
WHERE NOT x:Retired AND x.collection_ts = $cts
WITH f, wanted, collect(x) AS found
// an edge only when one node of the run carries the id: two tenants can share it
FOREACH (target IN CASE WHEN size(found) = 1 THEN found ELSE [] END |
  MERGE (f)-[r:FORWARDS_TO {source: 'reasoner'}]->(target)
  SET r.derived = false, r.rule = 'zia-forwarding-to-zpa-segment',
      r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
)
RETURN sum(CASE WHEN size(found) = 1 THEN 1 ELSE 0 END) AS n,
       sum(CASE WHEN size(found) = 0 THEN 1 ELSE 0 END) AS unresolved,
       sum(CASE WHEN size(found) > 1 THEN 1 ELSE 0 END) AS ambiguous
""",
    ),
    (
        "zia-forwarding-to-zpa-segment-group",
        """
MATCH (f:ZiaForwardingRule:Obj)
WHERE NOT f:Retired AND f.collection_ts = $cts AND f.zpa_segment_group_ids IS NOT NULL
UNWIND f.zpa_segment_group_ids AS wanted
OPTIONAL MATCH (x:ZpaSegmentGroup:Obj {zpa_id: wanted})
WHERE NOT x:Retired AND x.collection_ts = $cts
WITH f, wanted, collect(x) AS found
// an edge only when one node of the run carries the id: two tenants can share it
FOREACH (target IN CASE WHEN size(found) = 1 THEN found ELSE [] END |
  MERGE (f)-[r:FORWARDS_TO {source: 'reasoner'}]->(target)
  SET r.derived = false, r.rule = 'zia-forwarding-to-zpa-segment-group',
      r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
)
RETURN sum(CASE WHEN size(found) = 1 THEN 1 ELSE 0 END) AS n,
       sum(CASE WHEN size(found) = 0 THEN 1 ELSE 0 END) AS unresolved,
       sum(CASE WHEN size(found) > 1 THEN 1 ELSE 0 END) AS ambiguous
""",
    ),
    (
        "zia-forwarding-to-zpa-server-group",
        """
MATCH (f:ZiaForwardingRule:Obj)
WHERE NOT f:Retired AND f.collection_ts = $cts AND f.zpa_server_group_id IS NOT NULL
UNWIND [f.zpa_server_group_id] AS wanted
OPTIONAL MATCH (x:ZpaServerGroup:Obj {zpa_id: wanted})
WHERE NOT x:Retired AND x.collection_ts = $cts
WITH f, wanted, collect(x) AS found
// an edge only when one node of the run carries the id: two tenants can share it
FOREACH (target IN CASE WHEN size(found) = 1 THEN found ELSE [] END |
  MERGE (f)-[r:STEERS_VIA {source: 'reasoner'}]->(target)
  SET r.derived = false, r.rule = 'zia-forwarding-to-zpa-server-group',
      r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
)
RETURN sum(CASE WHEN size(found) = 1 THEN 1 ELSE 0 END) AS n,
       sum(CASE WHEN size(found) = 0 THEN 1 ELSE 0 END) AS unresolved,
       sum(CASE WHEN size(found) > 1 THEN 1 ELSE 0 END) AS ambiguous
""",
    ),
    (
        # A segment's FQDN entry resolves through the DnsRecord of the same
        # name in the run. IP, CIDR and wildcard entries are not names.
        "zpa-segment-domain-to-dns",
        """
MATCH (s:ZpaAppSegment:Obj)
WHERE NOT s:Retired AND s.collection_ts = $cts AND s.domains IS NOT NULL
UNWIND s.domains AS domain
WITH s, domain
WHERE NOT domain STARTS WITH '*' AND NOT domain =~ '^[0-9.]+(/[0-9]+)?$' AND NOT domain CONTAINS ':'
OPTIONAL MATCH (d:DnsRecord:Obj)
WHERE toLower(d.fqdn) = toLower(domain) AND NOT d:Retired AND d.collection_ts = $cts
FOREACH (rec IN CASE WHEN d IS NULL THEN [] ELSE [d] END |
  MERGE (s)-[r:RESOLVES_TO {source: 'reasoner', domain: domain}]->(rec)
  SET r.derived = false, r.rule = 'zpa-segment-domain-to-dns',
      r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
)
RETURN count(d) AS n, count(*) - count(d) AS unresolved
""",
    ),
    # Two circuits between one port pair are two links.
    (
        "cable-from-fabric-circuit",
        """
MATCH (vc:VirtualCircuit:Obj)-[ae:A_END]->(fa)-[ra:REALIZED_BY]->(a:Port)
WHERE NOT vc:Retired AND NOT fa:Retired AND NOT a:Retired
  AND ae._retired_at IS NULL AND ra._retired_at IS NULL
  AND vc.collection_ts = $cts
  AND a.collection_ts = $cts
  AND toUpper(coalesce(vc.state, '')) IN $active_circuit_states
  AND (fa:FabricPort OR (fa:Interface AND EXISTS {
    MATCH (a)-[oa:ON]->(da:Device) WHERE oa._retired_at IS NULL AND NOT da:Retired
  }))
MATCH (vc)-[ze:Z_END]->(fz)-[rz:REALIZED_BY]->(z:Port)
WHERE NOT fz:Retired AND NOT z:Retired
  AND ze._retired_at IS NULL AND rz._retired_at IS NULL
  AND z.collection_ts = $cts
  AND (fz:FabricPort OR (fz:Interface AND EXISTS {
    MATCH (z)-[oz:ON]->(dz:Device) WHERE oz._retired_at IS NULL AND NOT dz:Retired
  }))
  AND a.uid <> z.uid
MERGE (a)-[c:CONNECTED_TO {source: 'equinix-circuit', circuit_uid: vc.uid}]->(z)
SET c.derived = true, c.rule = 'cable-from-fabric-circuit',
    c.vlan_tag_a = ae.vlan_tag, c.vlan_tag_z = ze.vlan_tag,
    c.link_protocol_a = ae.link_protocol, c.link_protocol_z = ze.link_protocol,
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
WITH count(DISTINCT vc) AS n
RETURN n, COUNT {
  MATCH (o:VirtualCircuit:Obj)
  WHERE NOT o:Retired AND o.collection_ts = $cts
    AND NOT toUpper(coalesce(o.state, '')) IN $active_circuit_states
    AND NOT toUpper(coalesce(o.state, '')) IN $ended_circuit_states
} AS not_active
""",
    ),
    (
        "gateway-from-router-interface",
        """
MATCH (d:Device:Obj)<-[o:ON]-(i:Interface)-[h:HAS_IP]->(ia:IpAddress)
      -[ip:IN]->(p:Prefix {kind: 'connected'})
WHERE d.role IN $gateway_roles
  AND NOT coalesce(i.vsx_kind, '') IN ['bridge', 'virtual-switch', 'management']
  AND NOT d:Retired AND NOT i:Retired AND NOT p:Retired AND NOT ia:Retired
  AND o._retired_at IS NULL AND h._retired_at IS NULL AND ip._retired_at IS NULL
  AND d.collection_ts = $cts
MERGE (i)-[c:GATEWAY_FOR {source: 'reasoner'}]->(p)
SET c.derived = true, c.rule = 'gateway-from-router-interface',
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN count(DISTINCT i) AS n
""",
    ),
    (
        "gateway-from-sole-firewall-interface",
        """
MATCH (d:Device:Obj)<-[o:ON]-(i:Interface)-[h:HAS_IP]->(ia:IpAddress)
      -[ip:IN]->(p:Prefix {kind: 'connected'})
WHERE d.role = 'firewall'
  AND NOT coalesce(i.vsx_kind, '') IN ['bridge', 'virtual-switch', 'management']
  AND NOT d:Retired AND NOT i:Retired AND NOT p:Retired AND NOT ia:Retired
  AND o._retired_at IS NULL AND h._retired_at IS NULL AND ip._retired_at IS NULL
  AND d.collection_ts = $cts
  AND NOT EXISTS {
    MATCH (d2:Device)<-[o2:ON]-(i2:Interface)-[h2:HAS_IP]->(ia2:IpAddress)-[ip2:IN]->(p)
    WHERE d2.role IN $gateway_roles
      AND NOT d2:Retired AND NOT i2:Retired AND NOT ia2:Retired
      AND o2._retired_at IS NULL AND h2._retired_at IS NULL AND ip2._retired_at IS NULL
      AND d2.collection_ts = $cts
  }
MERGE (i)-[c:GATEWAY_FOR {source: 'reasoner'}]->(p)
SET c.derived = true, c.rule = 'gateway-from-sole-firewall-interface',
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN count(DISTINCT i) AS n
""",
    ),
    # The rule attaches an interface to the bridge domain of the VLAN that it
    # binds to on its own device. The interface is an SVI (`kind: svi`, Cisco)
    # or a VLAN subinterface (a VyOS `vif`, a Check Point VLAN interface).
    # Their collectors write
    # `(Interface)-[:BOUND_TO]->(VlanInstance)-[:REALIZES]->(BridgeDomain)`.
    # A Cisco subinterface has no VLAN tag in the graph and no BOUND_TO, and
    # it gets no edge from this rule. A UniFi gateway SVI has no BOUND_TO either.
    (
        "attached-from-vlan-binding",
        """
MATCH (i:Interface:Obj)-[bt:BOUND_TO]->(v:VlanInstance)-[rz:REALIZES]->(bd:BridgeDomain)
WHERE NOT i:Retired AND NOT v:Retired AND NOT bd:Retired
  AND bt._retired_at IS NULL AND rz._retired_at IS NULL
  AND i.collection_ts = $cts
  AND bd.collection_ts = $cts
WITH DISTINCT i, bd
MERGE (i)-[a:ATTACHED_TO {source: 'reasoner'}]->(bd)
SET a.derived = true, a.rule = 'attached-from-vlan-binding',
    a.basis = CASE WHEN i.kind = 'svi' THEN 'svi' ELSE 'subif' END,
    a._scope = 'reasoner', a.collection_ts = $cts, a.collected_at = $ts
RETURN count(a) AS n
""",
    ),
    # The rule covers an untagged routed port. An interface that holds an
    # address, binds to no VLAN and is no SVI or subinterface is attached to
    # the bridge domain of the native VLAN of the switch port at the other end
    # of its cable. The rule runs after every cable rule.
    (
        "attached-from-cable",
        """
MATCH (i:Interface:Obj)-[rb:REALIZED_BY]->(p:Port)-[c:CONNECTED_TO]-(far:Port)
      -[cr:CARRIES]->(v:VlanInstance)-[rz:REALIZES]->(bd:BridgeDomain)
WHERE cr.native = true AND far.uid <> p.uid
  AND NOT coalesce(i.kind, '') IN ['svi', 'subif']
  AND NOT i:Retired AND NOT p:Retired AND NOT far:Retired AND NOT v:Retired AND NOT bd:Retired
  AND rb._retired_at IS NULL AND c._retired_at IS NULL
  AND cr._retired_at IS NULL AND rz._retired_at IS NULL
  AND i.collection_ts = $cts
  AND far.collection_ts = $cts
  AND c.collection_ts = $cts
  AND EXISTS {
    MATCH (i)-[h:HAS_IP]->(ia:IpAddress) WHERE h._retired_at IS NULL AND NOT ia:Retired
  }
  AND NOT EXISTS {
    MATCH (i)-[b:BOUND_TO]->(bv:VlanInstance) WHERE b._retired_at IS NULL AND NOT bv:Retired
  }
WITH DISTINCT i, bd
MERGE (i)-[a:ATTACHED_TO {source: 'reasoner'}]->(bd)
SET a.derived = true, a.rule = 'attached-from-cable', a.basis = 'cable',
    a._scope = 'reasoner', a.collection_ts = $cts, a.collected_at = $ts
RETURN count(a) AS n
""",
    ),
    # A connected prefix is IN the bridge domain of an interface that holds an
    # address in the prefix. An Endpoint has the same IN edge to its bridge
    # domain. The rule reads the ATTACHED_TO edges of the 2 rules above. It
    # skips a pair that a collector states.
    (
        "prefix-in-from-attachment",
        """
MATCH (i:Interface:Obj)-[a:ATTACHED_TO]->(bd:BridgeDomain)
WHERE NOT i:Retired AND NOT bd:Retired AND a._retired_at IS NULL
  AND a.collection_ts = $cts
  AND i.collection_ts = $cts
MATCH (i)-[h:HAS_IP]->(ia:IpAddress)-[n:IN]->(p:Prefix {kind: 'connected'})
WHERE NOT ia:Retired AND NOT p:Retired
  AND h._retired_at IS NULL AND n._retired_at IS NULL
  AND p.collection_ts = $cts
WITH DISTINCT p, bd
WHERE NOT EXISTS {
  MATCH (p)-[e:IN]->(bd) WHERE e._retired_at IS NULL AND coalesce(e.source, '') <> 'reasoner'
}
MERGE (p)-[r:IN {source: 'reasoner'}]->(bd)
SET r.derived = true, r.rule = 'prefix-in-from-attachment',
    r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
RETURN count(r) AS n
""",
    ),
    # The one addressed interface of a segment on its prefix is the gateway of
    # that prefix. The role of its device is neither a GATEWAY_ROLES role nor
    # `firewall`. The rule writes no gateway for a segment where another
    # interface also holds an address on the prefix (a management VLAN, where
    # every switch has an SVI). It writes no gateway for a prefix that has a
    # gateway in the same routing domain. The rule reads the ATTACHED_TO edges
    # of the attachment rules and runs after them.
    (
        "gateway-from-sole-segment-interface",
        """
MATCH (d:Device:Obj)<-[o:ON]-(i:Interface)-[a:ATTACHED_TO]->(bd:BridgeDomain)
WHERE NOT coalesce(d.role, '') IN $gateway_roles AND coalesce(d.role, '') <> 'firewall'
  AND NOT coalesce(i.vsx_kind, '') IN ['bridge', 'virtual-switch', 'management']
  AND NOT d:Retired AND NOT i:Retired AND NOT bd:Retired
  AND o._retired_at IS NULL AND a._retired_at IS NULL
  AND d.collection_ts = $cts
  AND i.collection_ts = $cts
MATCH (i)-[h:HAS_IP]->(ia:IpAddress)-[n:IN]->(p:Prefix {kind: 'connected'})
WHERE NOT ia:Retired AND NOT p:Retired
  AND h._retired_at IS NULL AND n._retired_at IS NULL
  AND NOT EXISTS {
    MATCH (bd)<-[a2:ATTACHED_TO]-(i2:Interface)-[h2:HAS_IP]->(ia2:IpAddress)-[n2:IN]->(p2:Prefix)
    WHERE i2.uid <> i.uid AND p2.cidr = p.cidr
      AND NOT i2:Retired AND NOT ia2:Retired AND NOT p2:Retired
      AND a2._retired_at IS NULL AND h2._retired_at IS NULL AND n2._retired_at IS NULL
  }
  AND NOT EXISTS {
    MATCH (p3:Prefix:Obj)<-[g:GATEWAY_FOR]-(i3:Interface)
    WHERE p3.collection_ts = $cts AND p3.cidr = p.cidr
      AND coalesce(p3.l3dom, '') = coalesce(p.l3dom, '')
      AND NOT p3:Retired AND NOT i3:Retired AND g._retired_at IS NULL
  }
WITH DISTINCT i, p
MERGE (i)-[c:GATEWAY_FOR {source: 'reasoner'}]->(p)
SET c.derived = true, c.rule = 'gateway-from-sole-segment-interface',
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN count(DISTINCT i) AS n
""",
    ),
    # Two BgpSessions are the 2 ends of one peering when an interface on the
    # device of each session holds the peer address of the other session, and
    # the peer ASN of each session is the local ASN of the other. The rule
    # matches on the address value. It reaches the device through the VRF
    # owner of the process and writes one edge per pair (`da.uid < db.uid`).
    (
        "bgp-peer-from-address",
        """
MATCH (da:Device)<-[oa:OWNED_BY]-(:VrfInstance)<-[iva:IN_VRF]-(rpa:RoutingProcess)
      -[ha:HAS]->(sa:BgpSession:Obj)
      -[ea:ENDPOINT]->(pa:IpAddress)
WHERE NOT da:Retired AND NOT sa:Retired AND NOT pa:Retired
  AND oa._retired_at IS NULL AND iva._retired_at IS NULL
  AND ha._retired_at IS NULL AND ea._retired_at IS NULL
  AND sa.collection_ts = $cts
MATCH (ipb:IpAddress {ip: pa.ip})<-[hb:HAS_IP]-(ib:Interface:Obj)-[onb:ON]->(db:Device)
WHERE NOT ipb:Retired AND NOT ib:Retired AND NOT db:Retired
  AND hb._retired_at IS NULL AND onb._retired_at IS NULL
  AND ib.collection_ts = $cts AND db.uid <> da.uid
MATCH (db)<-[ob:OWNED_BY]-(:VrfInstance)<-[ivb:IN_VRF]-(rpb:RoutingProcess)-[hb2:HAS]->(sb:BgpSession)
      -[eb:ENDPOINT]->(pb:IpAddress)
WHERE NOT sb:Retired AND NOT pb:Retired
  AND ob._retired_at IS NULL AND ivb._retired_at IS NULL
  AND hb2._retired_at IS NULL AND eb._retired_at IS NULL
  AND sb.collection_ts = $cts
  AND sa.peer_asn = sb.local_asn AND sb.peer_asn = sa.local_asn
MATCH (ipa:IpAddress {ip: pb.ip})<-[ha2:HAS_IP]-(ia:Interface)-[ona:ON]->(da)
WHERE NOT ipa:Retired AND NOT ia:Retired
  AND ha2._retired_at IS NULL AND ona._retired_at IS NULL
  AND ia.collection_ts = $cts
WITH DISTINCT sa, sb, da, db
WHERE da.uid < db.uid
MERGE (sa)-[p:PEERS_WITH {source: 'reasoner'}]->(sb)
SET p.derived = true, p.rule = 'bgp-peer-from-address', p.basis = 'peer-address',
    p._scope = 'reasoner', p.collection_ts = $cts, p.collected_at = $ts
RETURN count(DISTINCT sa) AS n
""",
    ),
    # Two batches can write one OverlayConnection (2 VyOS routers at the 2
    # ends of one tunnel). The loader keeps the `observed_from` and `name` of
    # the last writer. The rule sets both from the reported BETWEEN edges of
    # every writer. It reads only collector facts of the cycle and writes the
    # same values on every run. The rule has no clear step. A connection that
    # one end reports keeps the values of the collector.
    (
        "overlay-connection-ends",
        """
MATCH (c:OverlayConnection:Obj)-[b:BETWEEN]->(x)
WHERE NOT c:Retired AND c.collection_ts = $cts
  AND b._retired_at IS NULL AND NOT x:Retired AND b.reported = true
WITH c, b.end AS end, min(coalesce(x.hostname, x.name, x.ip, x.uid)) AS end_name
WITH c, collect(end) AS ends, collect([end, end_name]) AS named
WHERE size(ends) > 1
SET c.observed_from = [e IN ['a', 'b'] WHERE e IN ends],
    c.name = head([n IN named WHERE n[0] = 'a' | n[1]]) + ' to ' + head([n IN named WHERE n[0] = 'b' | n[1]])
RETURN count(c) AS n
""",
    ),
]
