"""The scenario validation suite checks that the schema answers the standard questions.

The suite runs against a database loaded with every fixture (mini-dc.yaml, then
mini-enterprise.yaml, then equinix-site.yaml). Each load derives into the run that
it builds. Each scenario is a cookbook-style query with a minimum expected row
count. `hst validate-demo` prints pass or fail per scenario.

A column whose name starts with `_` is graph-only when a scenario runs through
the Explore UI. app/tables.py drops the column from the table and feeds it to the
node-link view.
"""

from __future__ import annotations

from typing import Any

from neo4j import unit_of_work

READ_TIMEOUT_S = 30.0

# `fixture_only` marks a scenario that cannot answer collected data. Such a
# scenario needs a label or relationship type that no collector or reasoner rule
# writes (MATCHES, INTERCONNECTED_BY, RESOLVES_TO from a ZpaAppSegment,
# Vm-[ON]->EsxHost, and the Tgw, DxGw, DxVif, ErCircuit, VNetGw and CloudRoute
# circuit chain), or it binds names that only the demo fixture holds. The catalog
# (queries.py `catalog`) leaves these scenarios out. tests/test_queries_vendor.py
# checks the flag against the relationship types that collectors and the reasoner
# write.
SCENARIOS: list[dict[str, Any]] = [
    {
        "key": "derived-gateway",
        "title": "Derived gateways",
        "description": "reasoner: a routing device's interface inside a connected "
        "prefix is that prefix's gateway",
        "group": "hygiene",
        "min_rows": 1,
        "fixture_only": False,
        # path.py follows GATEWAY_FOR to leave L2. reasoner.py is the only writer of GATEWAY_FOR.
        "cypher": """
MATCH (d:Device:Obj)<-[o:ON]-(i:Interface)-[g:GATEWAY_FOR]->(p:Prefix)
WHERE d.collection_ts = $snap
  AND g.derived AND g.rule = 'gateway-from-router-interface' AND NOT p:Retired
RETURN d.hostname AS device, d.role AS role, i.name AS interface, p.cidr AS prefix,
       d AS _d, i AS _i, p AS _p, o AS _o, g AS _g
ORDER BY prefix, device
""",
    },
    {
        "key": "pbr-two-gates",
        "title": "ACI PBR chain",
        "description": "EPG pair → contract → PBR dest → CP cluster → permitting rule",
        "group": "policy",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (a:Epg:Obj {name:'frontend'})-[co:CONSUMES]->(c:Contract)<-[pv:PROVIDES]-(b:Epg {name:'backend'})
WHERE a.collection_ts = $snap
MATCH (c)-[h1:HAS]->(cs:ContractSubject)-[ag:APPLIES_GRAPH]->(sgt:ServiceGraphTemplate)
      -[hn:HAS_NODE]->(sn:ServiceNode)-[rv:REDIRECTS_VIA]->(pbr:PbrPolicy)
      -[hd:HAS_DEST]->(d:PbrDest)-[rt:RESOLVES_TO]->(ep:Endpoint)-[ob:OWNED_BY]->(fw:RedundancyGroup)
MATCH (fw)-[en:ENFORCES]->(rb:FwRulebase)-[hr:HAS_RULE]->(r:FwRule {action:'accept'})
RETURN c.name AS contract, pbr.name AS pbr, d.ip AS redirect_ip, fw.name AS firewall, r.name AS rule,
       a AS _a, c AS _c, b AS _b, cs AS _cs, sgt AS _sgt, sn AS _sn, pbr AS _pbr, d AS _dst,
       ep AS _ep, fw AS _fw, rb AS _rb, r AS _r, co AS _co, pv AS _pv, h1 AS _h1, ag AS _ag,
       hn AS _hn, rv AS _rv, hd AS _hd, rt AS _rt, ob AS _ob, en AS _en, hr AS _hr
""",
    },
    {
        "key": "lb-service-chain",
        "title": "NetScaler VIP chain",
        "description": "VIP → pool → member → VM → ESX host",
        "group": "service chains",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (vs:VirtualService:Obj)-[us:USES]->(po:Pool)-[hm:HAS_MEMBER]->(m:PoolMember)
      -[tg:TARGETS]->(ip:IpAddress)
      <-[hi:HAS_IP]-(vn:Vnic)-[of:OF]->(vm:Vm)-[o2:ON]->(h:EsxHost)
WHERE vs.collection_ts = $snap
RETURN vs.name AS vip, m.port AS member_port, ip.ip AS target, vm.name AS vm, h.hostname AS host,
       vs AS _vs, po AS _po, m AS _m, ip AS _ip, vn AS _vn, vm AS _vm, h AS _h,
       us AS _us, hm AS _hm, tg AS _tg, hi AS _hi, of AS _of, o2 AS _o2
""",
    },
    {
        "key": "blast-radius",
        "title": "vPC failure blast radius",
        "description": "vPC leaf pair failure → ESX → VMs → business service",
        "group": "service chains",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (rg:RedundancyGroup:Obj {kind:'vpc'})<-[mo:MEMBER_OF]-(d:Device)<-[o1:ON]-(pt:Port)
      -[ct:CONNECTED_TO]-(pn:Pnic)-[o2:ON]->(esx:EsxHost)<-[o3:ON]-(vm:Vm)
      -[p1:PART_OF]->(ac:AppComponent)-[p2:PART_OF]->(bs:BusinessService)
WHERE rg.collection_ts = $snap
RETURN DISTINCT rg.name AS failed_group, esx.hostname AS host, bs.name AS business_service,
       rg AS _rg, d AS _d, pt AS _pt, pn AS _pn, esx AS _esx, vm AS _vm, ac AS _ac, bs AS _bs,
       mo AS _mo, o1 AS _o1, ct AS _ct, o2 AS _o2, o3 AS _o3, p1 AS _p1, p2 AS _p2
""",
    },
    {
        "key": "zpa-user-to-app",
        "title": "ZPA user to app",
        "description": "identity group → access rule → app segment → DNS → the actual VIP",
        "group": "policy",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (idg:IdentityGroup:Obj)<-[gr:GRANTS]-(r:ZpaAccessRule)-[fo:FOR]->(seg:ZpaAppSegment)
      -[r1:RESOLVES_TO]->(dnsr:DnsRecord)-[r2:RESOLVES_TO]->(vip:IpAddress)<-[vp:VIP]-(vs:VirtualService)
WHERE idg.collection_ts = $snap
OPTIONAL MATCH (seg)-[sb:SERVED_BY]->(zsg:ZpaServerGroup)-[u1:USES]->(acg:ZpaAppConnectorGroup)
      -[h1:HAS]->(conn:ZpaAppConnector)-[ro:RUNS_ON]->(cvm:Vm)
RETURN idg.name AS who, r.name AS rule, seg.name AS app, vs.name AS lands_on_vip,
       collect(DISTINCT conn.name) AS via_connectors, collect(DISTINCT cvm.name) AS connector_vms,
       idg AS _idg, r AS _r, seg AS _seg, dnsr AS _dnsr, vip AS _vip, vs AS _vs,
       gr AS _gr, fo AS _fo, r1 AS _r1, r2 AS _r2, vp AS _vp,
       collect(DISTINCT zsg) AS _zsgs, collect(DISTINCT acg) AS _acgs,
       collect(DISTINCT conn) AS _conns, collect(DISTINCT cvm) AS _cvms,
       collect(DISTINCT sb) AS _sbs, collect(DISTINCT u1) AS _u1s,
       collect(DISTINCT h1) AS _h1s, collect(DISTINCT ro) AS _ros
""",
    },
    {
        "key": "guest-segmentation",
        "title": "Guest ↔ corp isolation",
        "description": "the crossing gate plus every rule that opens it",
        "group": "policy",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (g:RoutingDomain:Obj {name:'guest'})-[i1:INTERCONNECTED_BY]->(gate)
WHERE g.collection_ts = $snap
MATCH (gate)<-[i2:INTERCONNECTED_BY]-(cd:RoutingDomain {name:'corp'})
MATCH (gate)-[en:ENFORCES]->(rb:FwRulebase {kind:'access'})-[hr:HAS_RULE]->(r:FwRule {action:'accept'})
MATCH (r)-[s1:SRC]->(no1:NetObject)-[t1:RESOLVES_TO]->(sp) WHERE sp.l3dom = 'guest'
MATCH (r)-[d1:DST]->(no2:NetObject)-[t2:RESOLVES_TO]->(dp) WHERE dp.l3dom = 'corp'
OPTIONAL MATCH (r)-[sv:SVC]->(svc:SvcObject)
RETURN gate.hostname AS gate, rb.name AS rulebase, r.position AS pos, r.name AS rule,
       sp.uid AS from, dp.uid AS to, collect(svc.ports) AS ports,
       gate AS _gate, rb AS _rb, r AS _r, no1 AS _no1, sp AS _sp, no2 AS _no2, dp AS _dp,
       i1 AS _i1, i2 AS _i2, en AS _en, hr AS _hr, s1 AS _s1, t1 AS _t1, d1 AS _d1, t2 AS _t2,
       collect(DISTINCT svc) AS _svcs, collect(DISTINCT sv) AS _svs
""",
    },
    {
        "key": "guest-snat",
        "title": "Guest SNAT rewrite",
        "description": "guest SNAT rewrite at the FortiGate",
        "group": "policy",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (n:NatRule:Obj {kind:'snat'})-[os:ORIG_SRC]->(o:NetObject)
      -[rt:RESOLVES_TO]->(gp:Prefix {l3dom:'guest'})
WHERE n.collection_ts = $snap
MATCH (n)-[xs:XLATE_SRC]->(x:IpAddress)
RETURN n.name AS nat_rule, gp.cidr AS original_src, x.ip AS translated_to,
       n AS _n, o AS _o, gp AS _gp, x AS _x, os AS _os, rt AS _rt, xs AS _xs
""",
    },
    {
        "key": "evpn-rt-stitch",
        "title": "EVPN route-target stitch",
        "description": "VRF instances joined by a shared route target",
        "group": "topology",
        "min_rows": 1,
        "fixture_only": False,
        "cypher": """
MATCH (v1:VrfInstance:Obj)-[ex:EXPORTS]->(rt:RouteTarget)<-[im:IMPORTS]-(v2:VrfInstance)
WHERE v1.collection_ts = $snap AND v1.uid < v2.uid
OPTIONAL MATCH (e:EvpnInstance)-[ur:USES_RT]->(rt)
RETURN v1.uid AS vrf_a, v2.uid AS vrf_b, rt.value AS route_target, e.l3vni AS l3vni,
       v1 AS _v1, v2 AS _v2, rt AS _rt, e AS _e, ex AS _ex, im AS _im, ur AS _ur
""",
    },
    {
        "key": "hybrid-cloud-path",
        "title": "AWS to on-prem",
        "description": "route → TGW → DX gateway → DX vif → Equinix circuit → fabric port",
        "group": "cloud & wan",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (p:Prefix:Obj {uid: 'pfx:corp:10.0.0.0/8', collection_ts: $snap})<-[fo:FOR]-(r:CloudRoute)
      -[vi:VIA]->(t:Tgw)
      <-[ac:ASSOCIATED]-(dxgw:DxGw)<-[te:TERMINATES_ON]-(vif:DxVif)-[pf:PART_OF]->(dxc:DxConnection)
      <-[ze:Z_END]-(vc:VirtualCircuit)-[ae:A_END]->(fp:FabricPort)-[li:LOCATED_IN]->(s:Site)
RETURN r.dest AS route, t.name AS tgw, vif.vlan AS vif_vlan, vc.name AS equinix_circuit,
       s.code AS colo_site,
       p AS _p, r AS _r, t AS _t, dxgw AS _dxgw, vif AS _vif, dxc AS _dxc, vc AS _vc,
       fp AS _fp, s AS _s, fo AS _fo, vi AS _vi, ac AS _ac, te AS _te, pf AS _pf,
       ze AS _ze, ae AS _ae, li AS _li
""",
    },
    {
        "key": "azure-er-path",
        "title": "Azure ExpressRoute",
        "description": "UDR → ER gateway → ER circuit → Equinix circuit",
        "group": "cloud & wan",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (p:Prefix:Obj {uid: 'pfx:corp:10.0.0.0/8', collection_ts: $snap})<-[fo:FOR]-(r:CloudRoute)
      -[vi:VIA]->(gw:VNetGw)
      <-[te:TERMINATES_ON]-(er:ErCircuit)<-[ze:Z_END]-(vc:VirtualCircuit)
RETURN r.dest AS route, gw.name AS gateway, er.name AS er_circuit, vc.name AS equinix_circuit,
       p AS _p, r AS _r, gw AS _gw, er AS _er, vc AS _vc, fo AS _fo, vi AS _vi, te AS _te, ze AS _ze
""",
    },
    {
        "key": "sdwan-steering",
        "requires": "sdwan",
        "title": "SD-WAN steering",
        "description": "business policies steering to Zscaler and MPLS",
        "group": "cloud & wan",
        "min_rows": 2,
        "fixture_only": True,
        "cypher": """
MATCH (bp:SdwanBusinessPolicy:Obj)-[ma:MATCHES]->(m)
WHERE bp.collection_ts = $snap
MATCH (bp)-[sv:STEERS_VIA]->(target)
RETURN bp.name AS policy, m.cidr AS matches, labels(target)[1] AS target_kind,
       coalesce(target.name, target.uid) AS target,
       bp AS _bp, m AS _m, target AS _target, ma AS _ma, sv AS _sv
""",
    },
    {
        "key": "zia-guest-egress",
        "requires": "zia",
        "title": "Guest Wi-Fi egress",
        "description": "SSID → guest VLAN → its site → ZIA location → GRE tunnel → Zscaler DC",
        "group": "zscaler",
        "section": "ZIA",
        "min_rows": 1,
        "fixture_only": False,
        "cypher": """
MATCH (ssid:Ssid:Obj)-[br:BRIDGED_TO]->(vl:VlanInstance)-[re:REALIZES]->(seg)
WHERE ssid.collection_ts = $snap AND (seg:BridgeDomain OR seg:L2Segment)
MATCH (vl)<-[:BOUND_TO]-(:Interface)-[:ON]->(:Device)-[li:LOCATED_IN]->(s:Site)
MATCH (s)<-[rp:REPRESENTS]-(loc:ZiaLocation)-[us:USES]->(t:Tunnel {encap:'gre'})
      -[ep:TERMINATES_ON]->(z:ZscalerDc)
RETURN DISTINCT ssid.name AS ssid, seg.name AS l2segment, s.code AS site, loc.name AS zia_location,
       z.name AS zscaler_dc,
       ssid AS _ssid, vl AS _vl, seg AS _seg, s AS _s, loc AS _loc, t AS _t, z AS _z,
       br AS _br, re AS _re, rp AS _rp, us AS _us, ep AS _ep
""",
    },
    {
        "key": "dora-providers",
        "title": "DORA provider register",
        "description": "third-party providers across every site, plus WAN carriers",
        "group": "compliance",
        "min_rows": 3,
        "fixture_only": False,
        "cypher": """
MATCH (s:Site:Obj) WHERE (s:Meta OR s.collection_ts = $snap) AND NOT s:Retired
OPTIONAL MATCH (s)-[:SERVED_BY]->(:ProviderNetwork)-[:PROVIDED_BY]->(p1:Provider)
OPTIONAL MATCH (s)<-[:REPRESENTS]-(:ZiaLocation)-[:USES]->(:Tunnel)-[:TERMINATES_ON]->(:ZscalerDc)
               -[:PROVIDED_BY]->(p2:Provider)
WITH s, collect(DISTINCT p1) + collect(DISTINCT p2) AS ps
UNWIND ps AS p
RETURN DISTINCT s.code AS site, p.name AS provider, p.kind AS kind, p.contract_ref AS contract,
       p.criticality AS criticality, p AS _p, s AS _s
UNION
MATCH (d:Device:Obj)-[hl:HAS_LINK]->(w:WanLink)
WHERE d.collection_ts = $snap AND NOT w:Retired AND hl._retired_at IS NULL
OPTIONAL MATCH (d)-[:LOCATED_IN]->(st:Site)
OPTIONAL MATCH (w)-[pb:PROVIDED_BY]->(wp:Provider)
RETURN DISTINCT st.code AS site, coalesce(wp.name, w.name) AS provider,
       coalesce(wp.kind, 'wan-carrier (' + coalesce(w.kind, 'link') + ')') AS kind,
       wp.contract_ref AS contract, wp.criticality AS criticality,
       coalesce(wp, w) AS _p, st AS _s
""",
    },
    {
        "key": "cable-drift",
        "title": "Cable drift",
        "description": "documented-vs-seen cabling mismatches",
        "group": "hygiene",
        "min_rows": 2,
        "fixture_only": False,
        "cypher": """
MATCH (a:Port:Obj)-[r:CONNECTED_TO]-(b:Port)
WHERE a.collection_ts = $snap AND a.uid < b.uid
WITH a, b, collect(DISTINCT r) AS rels, collect(DISTINCT r.source) AS srcs
WHERE ('nautobot-cable' IN srcs) <> ('lldp' IN srcs OR 'cdp' IN srcs)
MATCH (a)-[oa:ON]->(da:Device), (b)-[ob:ON]->(db:Device)
RETURN da.hostname AS device_a, a.name AS port_a, db.hostname AS device_b, b.name AS port_b,
       CASE WHEN 'nautobot-cable' IN srcs THEN 'documented-but-not-seen'
            ELSE 'seen-but-not-documented' END AS drift,
       a AS _a, b AS _b, da AS _da, db AS _db, rels AS _rels, oa AS _oa, ob AS _ob
""",
    },
    {
        "key": "naming-hygiene",
        "title": "Duplicate device names",
        "description": "same box, different names across systems (identities[] > 1)",
        "group": "hygiene",
        "min_rows": 1,
        "fixture_only": False,
        "cypher": """
MATCH (d:Device:Obj) WHERE d.collection_ts = $snap
  AND size(coalesce(d.identities, [])) > 1
RETURN d.serial AS serial, d.hostname AS canonical, d.identities AS also_known_as, d AS _d
ORDER BY size(d.identities) DESC
""",
    },
    {
        "key": "l3out-contract",
        "title": "ACI L3Out contract",
        "description": "campus ExtEpg consumes frontend (contract without PBR)",
        "group": "policy",
        "min_rows": 1,
        "fixture_only": True,
        "cypher": """
MATCH (x:ExtEpg:Obj)-[ma:MATCHES]->(p:Prefix)
WHERE x.collection_ts = $snap
MATCH (x)-[co:CONSUMES]->(c:Contract)<-[pv:PROVIDES]-(e:Epg)
WHERE NOT (c)-[:HAS]->(:ContractSubject)-[:APPLIES_GRAPH]->()
RETURN x.name AS external, p.cidr AS classified_prefix, c.name AS contract, e.name AS provider_epg,
       x AS _x, p AS _p, c AS _c, e AS _e, ma AS _ma, co AS _co, pv AS _pv
""",
    },
    # The scenarios below read the objects of fixtures/equinix-site.yaml.
    {
        "key": "equinix-hsrp-core",
        "title": "Core HSRP gateway",
        "description": "HSRP group on the vPC core pair: virtual address, member SVIs, priorities",
        "group": "topology",
        "min_rows": 2,
        "fixture_only": False,
        "cypher": """
MATCH (f:FhrpGroup:Obj {kind:'hsrp'})<-[m:MEMBER_OF]-(i:Interface)-[o:ON]->(d:Device)
      -[mo:MEMBER_OF]->(rg:RedundancyGroup {kind:'vpc'})
WHERE f.collection_ts = $snap
MATCH (f)-[h:HAS_IP]->(vip:IpAddress)-[inp:IN]->(p:Prefix)
MATCH (f)-[g:GATEWAY_FOR]->(p)
RETURN vip.ip AS gateway, p.cidr AS prefix, d.hostname AS member, i.name AS svi,
       m.priority AS priority, m.state AS state, rg.name AS vpc_domain,
       f AS _f, i AS _i, d AS _d, rg AS _rg, vip AS _vip, p AS _p,
       m AS _m, o AS _o, mo AS _mo, h AS _h, inp AS _inp, g AS _g
ORDER BY priority DESC
""",
    },
    {
        "key": "equinix-vsx-context",
        "title": "VSX virtual systems",
        "description": "each virtual system: its context interfaces on the appliance and its bound layer",
        "group": "policy",
        "min_rows": 2,
        "fixture_only": False,
        # `gateway_object_uid` on the FirewallInstance equals `cp_raw_uid` on the
        # management Device of the same scope (`_scope` equals `authority`).
        "cypher": """
MATCH (i:Interface)-[c:IN_CONTEXT]->(fi:FirewallInstance:Obj)
      -[r:RUNS_ON]->(app:Device {platform:'checkpoint-gaia'})
WHERE fi.collection_ts = $snap
MATCH (vs:Device:Obj {collection_ts: $snap})-[e:ENFORCES]->(rb:FwRulebase {kind:'access'})
      -[hr:HAS_RULE]->(rule:FwRule)
WHERE vs.cp_raw_uid = fi.gateway_object_uid AND vs._scope = fi.authority
RETURN fi.name AS virtual_system, app.hostname AS appliance,
       collect(DISTINCT i.name) AS context_interfaces, rb.name AS rulebase,
       count(DISTINCT rule) AS rules,
       fi AS _fi, app AS _app, vs AS _vs, rb AS _rb,
       collect(DISTINCT i) AS _ifs, collect(DISTINCT c) AS _cs, collect(DISTINCT rule) AS _rules,
       r AS _r, e AS _e, collect(DISTINCT hr) AS _hrs
ORDER BY virtual_system
""",
    },
    {
        "key": "equinix-asr-egress",
        "title": "ASR egress",
        "description": "each ASR: its static default route and the source NAT rule on the way out",
        "group": "policy",
        "min_rows": 2,
        "fixture_only": False,
        "cypher": """
MATCH (d:Device:Obj {platform:'iosxe'})<-[o:ON]-(i:Interface)-[iv:IN_VRF]->(v:VrfInstance)
      -[og:ORIGINATES {proto:'static'}]->(p:Prefix {kind:'default'})
WHERE d.collection_ts = $snap
MATCH (d)-[en:ENFORCES]->(rb:FwRulebase {kind:'nat'})-[hr:HAS_RULE]->(n:NatRule {kind:'snat'})
      -[xs:XLATE_SRC]->(x:IpAddress)
MATCH (n)-[os:ORIG_SRC]->(no:NetObject)-[rt:RESOLVES_TO]->(inside:Prefix)
RETURN DISTINCT d.hostname AS router, v.name AS vrf, p.cidr AS default_route, og.next_hop AS next_hop,
       inside.cidr AS translated_from, x.ip AS translated_to, n.name AS nat_rule,
       d AS _d, v AS _v, p AS _p, rb AS _rb, n AS _n, x AS _x, no AS _no, inside AS _inside,
       og AS _og, en AS _en, hr AS _hr, xs AS _xs, os AS _os, rt AS _rt
ORDER BY router
""",
    },
    {
        "key": "equinix-fabric-circuit",
        "requires": "equinix",
        "title": "Equinix Fabric circuit",
        "description": "a circuit from the site's fabric port, behind the external switch, to another site",
        "group": "equinix",
        "min_rows": 1,
        "fixture_only": False,
        "cypher": """
MATCH (a:Site)<-[la:LOCATED_IN]-(fa:FabricPort)<-[ae:A_END]-(vc:VirtualCircuit:Obj)
      -[ze:Z_END]->(fz:FabricPort)
      -[lz:LOCATED_IN]->(z:Site)
WHERE vc.collection_ts = $snap
MATCH (fa)-[re:REALIZED_BY]->(pt:Port)-[o:ON]->(sw:Device)
RETURN vc.name AS circuit, vc.bandwidth_mbps AS bandwidth_mbps, vc.state AS state,
       a.code AS a_site, sw.hostname AS a_switch, pt.name AS a_port, ae.vlan_tag AS a_tag,
       z.code AS z_site, ze.vlan_tag AS z_tag,
       vc AS _vc, fa AS _fa, fz AS _fz, a AS _a, z AS _z, pt AS _pt, sw AS _sw,
       la AS _la, ae AS _ae, ze AS _ze, lz AS _lz, re AS _re, o AS _o
""",
    },
]


def _read(session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    """Run `query` as a managed read with the timeout `READ_TIMEOUT_S`."""

    @unit_of_work(timeout=READ_TIMEOUT_S)
    def work(tx: Any) -> list[dict[str, Any]]:
        return tx.run(query, **params).data()

    return session.execute_read(work)


def run_all(session: Any) -> list[dict[str, Any]]:
    """Run every scenario against one run.

    The run pointer is resolved once. The `$snap` of every scenario binds to
    that value."""
    from hst.core import cycle as cyclemod
    from hst.path import LIVE_SNAP

    cts = cyclemod.current_ts_or_none(session)
    snap = cts if cts is not None else LIVE_SNAP
    results = []
    for sc in SCENARIOS:
        try:
            rows = _read(session, sc["cypher"], snap=snap)
            results.append(
                {
                    **sc,
                    "rows": len(rows),
                    "ok": len(rows) >= sc["min_rows"],
                    "sample": rows[0] if rows else None,
                    "error": None,
                }
            )
        except Exception as exc:
            results.append({**sc, "rows": 0, "ok": False, "sample": None, "error": str(exc)})
    return results
