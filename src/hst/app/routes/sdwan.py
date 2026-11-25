"""GET /api/sdwan/edges lists the SD-WAN edges. GET /api/sdwan/topology returns
one SD-WAN edge and the devices that it connects to, as one picture.

The device map shows cables. An SD-WAN edge has no cable to the core. It
connects through overlay tunnels to the hubs and to the cloud gateways. The
hubs have cables to the switches. Thus the picture for one edge shows the
edge, its WAN links, its tunnels, the hubs and gateways at the far end, the
hub cables, the cables between the switches, and the sites.

A tunnel to a hub ends on an address (`TERMINATES_ON`). The hub interface and
the hub WAN link both hold that address. Each one identifies the hub. A
tunnel to a cloud gateway ends on the `SdwanGateway` node.

The collector writes both ends of a branch and hub pair. The hub end has
`peer_type` "edge" and ends on the branch address. Thus for a picked hub the
far device of such a tunnel is a branch. The branches go in their
own list (uid, name, site).

The payload also has the business policy of the edge. Its rules are in the
sequence that the edge reads them (`SdwanPolicyRule.position`). If the
collector did not write rule nodes, `rule_count` is null. After a refused QOS
read, `rule_count` is null and `capability_gap` has a value.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hst.app.auth import require_permission
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod

router = APIRouter()
_session = dbmod.session  # Tests replace this name.

_EDGES = """
MATCH (e:Device:Obj {platform: 'velocloud-edge'})
WHERE e.collection_ts = $snap AND NOT e:Retired
OPTIONAL MATCH (e)-[:LOCATED_IN]->(s:Site)
RETURN e.uid AS uid, coalesce(e.hostname, e.name, e.uid) AS name, e.sdwan_role AS role,
       e.reported_location_name AS location, e.site_country AS country, s.code AS site
ORDER BY name
"""

_EDGE = """
MATCH (e:Device:Obj {uid: $edge, collection_ts: $snap})
WHERE NOT e:Retired
RETURN e.uid AS uid, coalesce(e.hostname, e.name, e.uid) AS name, e.model AS model,
       e.reported_location_name AS location, e.site_city AS city, e.site_country AS country,
       e.ha_type AS ha_type, e.sdwan_role AS role
"""

_LINKS = """
MATCH (e:Device:Obj {uid: $edge, collection_ts: $snap})-[:HAS_LINK]->(w:WanLink)
OPTIONAL MATCH (w)-[:ON]->(i:Interface)
OPTIONAL MATCH (w)-[:PROVIDED_BY]->(pn:ProviderNetwork)
RETURN w.uid AS uid, w.name AS name, w.kind AS kind, w.carrier AS carrier, pn.name AS provider,
       w.public_ip AS public_ip, w.wan_mode AS mode, coalesce(i.name, w.interface) AS interface,
       w.upstream_mbps AS up_mbps, w.downstream_mbps AS down_mbps,
       coalesce(w.backup_only, false) AS backup_only
ORDER BY interface, name
"""

# `hub` is the device that holds the far address, through its interface or
# its WAN link. For a cloud gateway, `gateway` has a value and `hub` is null.
# `hub_role` is the `sdwan_role` of that device. `_far_kind` reads it with
# `peer_type` to tell a hub from a branch.
_TUNNELS = """
MATCH (e:Device:Obj {uid: $edge, collection_ts: $snap})<-[:ON]-(ei:Interface)<-[:ENDPOINT]-(t:Tunnel)
OPTIONAL MATCH (t)-[:TERMINATES_ON]->(g:SdwanGateway)
OPTIONAL MATCH (t)-[:TERMINATES_ON]->(ip:IpAddress)
OPTIONAL MATCH (ip)<-[:HAS_IP]-(:Interface)-[:ON]->(h1:Device)
OPTIONAL MATCH (ip)<-[:HAS_IP]-(:WanLink)<-[:HAS_LINK]-(h2:Device)
WITH t, ei, g, ip, coalesce(h1, h2) AS hub
RETURN t.uid AS uid, ei.name AS interface, t.peer_type AS peer_type,
       hub.uid AS hub, coalesce(hub.hostname, hub.name) AS hub_name, hub.sdwan_role AS hub_role,
       g.uid AS gateway, g.name AS gateway_name, ip.ip AS peer_ip
ORDER BY interface, coalesce(hub_name, gateway_name)
"""

# The cables from the hubs to devices that are not SD-WAN edges. The loader
# writes one directed CONNECTED_TO for each cable, and the hub can be at
# each end.
_HUB_CABLES = """
MATCH (h:Device:Obj)<-[:ON]-(hp:Port)-[:CONNECTED_TO]-(sp:Port)-[:ON]->(sw:Device)
WHERE h.uid IN $hubs AND h.collection_ts = $snap
  AND coalesce(sw.platform, '') <> 'velocloud-edge'
RETURN h.uid AS a_dev, hp.name AS a_port, sw.uid AS b_dev, sp.name AS b_port
ORDER BY a_dev, a_port
"""

# All the devices at the hub sites. Only the devices one cable hop from a hub
# are drawn. The others are counted per site.
_SITE_DEVICES = """
MATCH (s:Site)<-[:LOCATED_IN]-(d:Device:Obj)
WHERE s.code IN $sites AND d.collection_ts = $snap AND NOT d:Retired
RETURN DISTINCT d.uid AS uid, coalesce(d.hostname, d.name, d.uid) AS name, d.platform AS platform,
       s.code AS site, coalesce(s.name, s.code) AS site_name
ORDER BY site, name
"""

_HUB_SITES = """
MATCH (h:Device:Obj)-[:LOCATED_IN]->(s:Site)
WHERE h.uid IN $hubs AND h.collection_ts = $snap
RETURN DISTINCT s.code AS site
"""

# The sites of the branches at the far end of the tunnels of a picked hub.
_BRANCH_SITES = """
MATCH (b:Device:Obj)-[:LOCATED_IN]->(s:Site)
WHERE b.uid IN $branches AND b.collection_ts = $snap
RETURN b.uid AS uid, s.code AS site
ORDER BY uid, site
"""

# The cables between the site devices that are not hubs. These are the
# cables between the switches of the data centres.
_SITE_CABLES = """
MATCH (a:Device:Obj)<-[:ON]-(ap:Port)-[c:CONNECTED_TO]->(bp:Port)-[:ON]->(b:Device)
WHERE a.uid IN $devices AND b.uid IN $devices AND a.collection_ts = $snap
  AND coalesce(a.platform, '') <> 'velocloud-edge' AND coalesce(b.platform, '') <> 'velocloud-edge'
RETURN a.uid AS a_dev, ap.name AS a_port, b.uid AS b_dev, bp.name AS b_port, c.source AS source
ORDER BY a_dev, a_port
"""

_POLICY = """
MATCH (e:Device:Obj {uid: $edge, collection_ts: $snap})-[:ENFORCES]->(p:SdwanBusinessPolicy)
OPTIONAL MATCH (p)-[:HAS_RULE]->(r:SdwanPolicyRule)
WITH p, r ORDER BY r.segment_id, r.position
RETURN p.uid AS uid, p.name AS name, p.rule_count AS rule_count, p.capability_gap AS capability_gap,
       [x IN collect(r) | properties(x)] AS rules
"""

# The properties that the loader writes on a rule node. The payload leaves them out of a rule.
_RULE_DROP = frozenset({"uid", "collection_ts", "_scope", "_sources", "_run_id", "collected_at", "carried"})


def _snap(s: Any, settings: Any) -> Any:
    resolved = snapshotmod.resolve(s, settings)
    return snapshotmod.snap_param(resolved.cts)


def _far_kind(t: dict[str, Any]) -> str | None:
    """The kind of the far end of a tunnel row: hub, branch or gateway, or
    None when no device or gateway in the graph holds it. The hub end of a branch
    and hub pair has `peer_type` "edge". A far device with `sdwan_role` "hub"
    is a hub whatever the `peer_type`, as is a far device of a row without a
    `peer_type`."""
    if t.get("hub"):
        if t.get("peer_type") == "edge" and t.get("hub_role") != "hub":
            return "branch"
        return "hub"
    if t.get("gateway"):
        return "gateway"
    return None


@router.get("/sdwan/edges", dependencies=[Depends(require_permission("graph.read"))])
def get_edges(request: Request) -> dict[str, Any]:
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = _snap(s, settings)
        rows = s.run(_EDGES, snap=snap).data()
    return {"edges": rows}


@router.get("/sdwan/topology", dependencies=[Depends(require_permission("graph.read"))])
def get_topology(request: Request, edge: Annotated[str, Query(min_length=1)]) -> dict[str, Any]:
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = _snap(s, settings)
        found = s.run(_EDGE, edge=edge, snap=snap).data()
        if not found:
            raise HTTPException(status_code=404, detail="no SD-WAN edge with this uid in the run")
        links = s.run(_LINKS, edge=edge, snap=snap).data()
        tunnels = s.run(_TUNNELS, edge=edge, snap=snap).data()
        hub_uids = sorted({t["hub"] for t in tunnels if _far_kind(t) == "hub"})
        branch_uids = sorted({t["hub"] for t in tunnels if _far_kind(t) == "branch"} - set(hub_uids))
        branch_sites = s.run(_BRANCH_SITES, branches=branch_uids, snap=snap).data() if branch_uids else []
        hub_cables = s.run(_HUB_CABLES, hubs=hub_uids, snap=snap).data() if hub_uids else []
        sites = [r["site"] for r in s.run(_HUB_SITES, hubs=hub_uids, snap=snap).data()] if hub_uids else []
        site_devices = s.run(_SITE_DEVICES, sites=sites, snap=snap).data() if sites else []
        cabled = {c["b_dev"] for c in hub_cables}
        others = sorted(cabled - set(hub_uids))
        site_cables = s.run(_SITE_CABLES, devices=others, snap=snap).data() if others else []
        policy_rows = s.run(_POLICY, edge=edge, snap=snap).data()

    # _TUNNELS can give more than one row for a tunnel. Keep the first row.
    seen: set[str] = set()
    unique_tunnels = []
    for t in tunnels:
        if t["uid"] in seen:
            continue
        seen.add(t["uid"])
        unique_tunnels.append(t)

    hubs: dict[str, dict[str, Any]] = {}
    branches: dict[str, dict[str, Any]] = {}
    gateways: dict[str, dict[str, Any]] = {}
    site_of_branch: dict[str, str] = {}
    for r in branch_sites:
        site_of_branch.setdefault(r["uid"], r["site"])
    kinds = {t["uid"]: _far_kind(t) for t in unique_tunnels}
    for t in unique_tunnels:
        if t.get("hub") and t["hub"] in branch_uids:
            kinds[t["uid"]] = "branch"
            branches.setdefault(
                t["hub"],
                {"uid": t["hub"], "name": t["hub_name"] or t["hub"], "site": site_of_branch.get(t["hub"])},
            )
        elif t.get("hub"):
            kinds[t["uid"]] = "hub"
            hubs.setdefault(t["hub"], {"uid": t["hub"], "name": t["hub_name"] or t["hub"], "site": None})
        elif t.get("gateway"):
            gateways.setdefault(
                t["gateway"], {"uid": t["gateway"], "name": t["gateway_name"] or t["gateway"]}
            )
    devices: dict[str, dict[str, Any]] = {}
    not_drawn: dict[str, set[str]] = {}
    for d in site_devices:
        if d["uid"] in hubs:
            hubs[d["uid"]]["site"] = d["site"]
        elif d["uid"] in cabled:
            devices.setdefault(
                d["uid"], {"uid": d["uid"], "name": d["name"], "platform": d["platform"], "site": d["site"]}
            )
        else:
            not_drawn.setdefault(d["site"], set()).add(d["uid"])
    site_names = {d["site"]: d["site_name"] for d in site_devices}
    drawn = set(hubs) | set(devices)
    site_cables = [c for c in site_cables if c["a_dev"] in drawn and c["b_dev"] in drawn]

    policy = None
    if policy_rows:
        p = policy_rows[0]
        policy = {
            "uid": p["uid"],
            "name": p["name"],
            "rule_count": p["rule_count"],
            "capability_gap": p["capability_gap"],
            "rules": [{k: v for k, v in r.items() if k not in _RULE_DROP} for r in p["rules"]],
        }

    return {
        "edge": found[0],
        "links": links,
        "tunnels": [
            {
                "uid": t["uid"],
                "interface": t["interface"],
                "peer": t.get("hub") or t.get("gateway"),
                "peer_kind": kinds[t["uid"]],
                "peer_ip": t.get("peer_ip"),
            }
            for t in unique_tunnels
        ],
        "hubs": sorted(hubs.values(), key=lambda h: h["name"]),
        "branches": sorted(branches.values(), key=lambda b: (b["site"] or "", b["name"])),
        "gateways": sorted(gateways.values(), key=lambda g: g["name"]),
        "devices": sorted(devices.values(), key=lambda d: (d["site"] or "", d["name"])),
        "sites": [
            {
                "code": code,
                "name": site_names.get(code) or code,
                "other_devices": len(not_drawn.get(code, ())),
            }
            for code in sorted(site_names)
        ],
        "cables": [{**c, "source": None} for c in hub_cables] + site_cables,
        "policy": policy,
    }
