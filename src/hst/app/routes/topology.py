"""GET /api/topology returns the view model of the unified map."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from neo4j import unit_of_work

from hst.app.auth import require_permission
from hst.app.routes import endpoints as endpoint_routes
from hst.app.routes.run_lease import reading
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import entity_read
from hst.core import filters as filtermod
from hst.core import snapshot as snapshotmod
from hst.core import uid as uidmod
from hst.diagram import planner
from hst.diagram import segments as segmod

router = APIRouter()
_session = dbmod.session  # The tests replace this name.

# The transaction timeout of every read below, in seconds.
READ_TIMEOUT_S = 30.0

_DEVICE_ROW = """RETURN d.uid AS uid, coalesce(d.hostname, d.uid) AS name, d.role AS role, d.tier AS tier,
       d.role_basis AS role_basis, s.code AS site, d.vendor AS vendor, d.model AS model,
       d.mgmt_ip AS mgmt_ip, d.mac AS mac,
       coalesce(d.carried, false) AS carried, d.carried_reason AS carried_reason,
       coalesce(d.last_seen_ts, d.collected_at) AS last_seen,
       d._scope AS _scope, d._sources AS _sources
"""

# The read returns one row per device of the run. The site of a device
# LOCATED_IN 2 sites is the first by uid of the sites that `$site` admits.
_DEVICES = (
    """
MATCH (d:Device:Obj) WHERE d.collection_ts = $snap AND NOT d:Retired
OPTIONAL MATCH (d)-[li:LOCATED_IN]->(s:Site) WHERE li._retired_at IS NULL
WITH d, s ORDER BY s.uid
WITH d, collect(s) AS sites
WITH d, head([x IN sites WHERE $site IS NULL OR x.uid IN $site]) AS s
WHERE $site IS NULL OR s IS NOT NULL
"""
    + _DEVICE_ROW
)

# The read returns the devices LOCATED_IN one of the sites `$site`. It starts
# from the Site by its uid (index site_uid). `$site` holds the Site uids of the
# codes asked for. A Site that an operator created is a :Meta node with no run.
_SITE_DEVICES = (
    """
MATCH (s:Site:Obj) WHERE s.uid IN $site AND (s:Meta OR s.collection_ts = $snap)
MATCH (d:Device:Obj)-[li:LOCATED_IN]->(s)
WHERE d.collection_ts = $snap AND NOT d:Retired AND li._retired_at IS NULL
WITH d, s ORDER BY s.uid
WITH d, head(collect(s)) AS s
"""
    + _DEVICE_ROW
)

# Every read after the device read starts with one drawn device per row, by its
# uid at the run, on the obj_uid_cts constraint:
#   UNWIND $devs AS du MATCH (d:Device:Obj {uid: du, collection_ts: $snap})

# The read returns each cable with at least one end on a drawn device once, in
# the direction in which CONNECTED_TO was written. CONNECTED_TO is written once
# per cable. The planner keys a line on the sorted ends, and a graph that holds
# both directions draws one line. The link speed is the speed that the reasoner
# derived on the cable, else the lower of the 2 port speeds.
_CABLES = """
UNWIND $devs AS du
MATCH (dev:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT dev:Retired
MATCH (dev)<-[o:ON]-(:Port)-[c:CONNECTED_TO]-(:Port)
WHERE o._retired_at IS NULL AND c._retired_at IS NULL
WITH DISTINCT c
MATCH (p1:Port)-[c]->(p2:Port)
WHERE NOT p1:Retired AND NOT p2:Retired
MATCH (p1)-[o1:ON]->(d1:Device), (p2)-[o2:ON]->(d2:Device)
WHERE o1._retired_at IS NULL AND o2._retired_at IS NULL
RETURN d1.uid AS a_dev, p1.name AS a_port, coalesce(d1.hostname, d1.uid) AS a_name,
       d2.uid AS b_dev, p2.name AS b_port, coalesce(d2.hostname, d2.uid) AS b_name,
       c.source AS source,
       coalesce(c.speed_mbps,
                CASE WHEN p1.speed_mbps IS NULL THEN p2.speed_mbps
                     WHEN p2.speed_mbps IS NULL OR p1.speed_mbps <= p2.speed_mbps THEN p1.speed_mbps
                     ELSE p2.speed_mbps END) AS speed_mbps
"""

_LAGS = """
UNWIND $devs AS du
MATCH (d:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT d:Retired
MATCH (l:Lag)-[o:ON]->(d)
WHERE NOT l:Retired AND o._retired_at IS NULL
OPTIONAL MATCH (p:Port)-[m:MEMBER_OF]->(l) WHERE m._retired_at IS NULL AND NOT p:Retired
// the CDP or LLDP neighbor a member port reports (collectors/cisco_common.py `_neighbor_stage`): the
// planner draws it where no cable joins the port
WITH l, d, p, coalesce(p.lldp_neighbor_name, p.cdp_neighbor_name) AS neighbor
RETURN l.uid AS uid, d.uid AS dev, l.name AS name, collect(DISTINCT p.name) AS ports,
       [x IN collect(DISTINCT CASE WHEN neighbor IS NOT NULL THEN {
          port: p.name, name: neighbor,
          far_port: CASE WHEN p.lldp_neighbor_name IS NOT NULL THEN p.lldp_neighbor_port
                         ELSE p.cdp_neighbor_port END,
          proto: CASE WHEN p.lldp_neighbor_name IS NOT NULL THEN 'lldp' ELSE 'cdp' END} END)
        WHERE x IS NOT NULL] AS neighbors
"""

# The redundancy groups a drawn device is a member of, with every member.
_GROUPS = """
UNWIND $devs AS du
MATCH (d:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT d:Retired
MATCH (d)-[m:MEMBER_OF]->(g:RedundancyGroup)
WHERE NOT g:Retired AND m._retired_at IS NULL
WITH DISTINCT g
RETURN g.uid AS uid, g.kind AS kind, g.name AS name,
       COLLECT { MATCH (x:Device)-[mx:MEMBER_OF]->(g) WHERE mx._retired_at IS NULL AND NOT x:Retired
                 RETURN DISTINCT x.uid } AS members
"""

_WAN_DEVICES = """
UNWIND $devs AS du
MATCH (d:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT d:Retired
MATCH (d)-[h:HAS_LINK]->(w:WanLink)
WHERE NOT w:Retired AND h._retired_at IS NULL
RETURN DISTINCT d.uid AS dev
"""


# An attachment group lists at most this count of endpoints.
SAMPLE_CLIENTS = 50

# The site filter of the segment list (GET /topology/segment). It keeps the
# devices LOCATED_IN one of `$site` (Site uids), or every device when no site is
# asked for. The filter collects the Site uids of a device, and a device in 2
# sites gives its rows once.
_AT_SITE = """OPTIONAL MATCH (dev)-[li:LOCATED_IN]->(s:Site) WHERE li._retired_at IS NULL
WITH {carry}, collect(s.uid) AS site_uids
WHERE $site IS NULL OR any(uid IN site_uids WHERE uid IN $site)
"""

# The read returns one row per client endpoint and attachment. A wired
# endpoint attaches to an Interface or a Port that is ON the device. A wireless
# endpoint attaches to the AP Device, and the edge holds the ssid. `port` is
# null for an attachment to the Device. `bd` is the bridge domain that the
# endpoint is IN (`segments.py` joins on it). `cidrs` holds the prefixes of its
# addresses. `vendor` is the vendor name of its MAC as the source reports it
# (UniFi `oui`). `last_seen` is the time at which the source last saw it, else
# the time at which a run last collected it.
_CLIENTS = """
UNWIND $devs AS du
MATCH (dev:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT dev:Retired
CALL (dev) {
  MATCH (e:Endpoint)-[a:ATTACHED]->(dev) RETURN e, a, dev AS at
  UNION
  MATCH (e:Endpoint)-[a:ATTACHED]->(at)-[o:ON]->(dev) WHERE o._retired_at IS NULL RETURN e, a, at
}
WITH dev, e, a, at
WHERE NOT e:Retired AND a._retired_at IS NULL AND NOT at:Retired
OPTIONAL MATCH (e)-[h:HAS_IP]->(ip:IpAddress) WHERE h._retired_at IS NULL
OPTIONAL MATCH (ip)-[n:IN]->(pfx:Prefix) WHERE n._retired_at IS NULL AND NOT pfx:Retired
WITH dev, at, a.ssid AS ssid, e, collect(DISTINCT ip.ip) AS ips, collect(DISTINCT pfx.cidr) AS cidrs
RETURN dev.uid AS dev, ssid, CASE WHEN at:Port OR at:Interface THEN at.name END AS port,
       coalesce(e.hostname, e.name, e.mac, e.uid) AS name, e.uid AS uid, e.mac AS mac,
       e.wired AS wired, e.oui AS vendor, coalesce(e.last_seen, e.last_seen_ts) AS last_seen,
       head([(e)-[ib:IN]->(bd) WHERE (bd:BridgeDomain OR bd:L2Segment) AND ib._retired_at IS NULL
             AND NOT bd:Retired | bd.uid]) AS bd,
       ips, cidrs
ORDER BY name, uid
"""

# The read returns one row per (device, port or SVI, VLAN). CARRIES is the
# trunk or access membership that a platform states for a Port. BOUND_TO joins
# an SVI Interface to its VLAN. The bridge domain is the identity of the VLAN
# across devices. A trunk-only VLAN with no SVI has no REALIZES edge on that
# device, and the OPTIONAL match keeps its row for the overlay. The match also
# accepts an L2Segment.
_VLANS = """
UNWIND $devs AS du
MATCH (dev:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT dev:Retired
MATCH (x)-[o:ON]->(dev)
WHERE (x:Port OR x:Interface) AND NOT x:Retired AND o._retired_at IS NULL
MATCH (x)-[r:CARRIES|BOUND_TO]->(v:VlanInstance)
WHERE r._retired_at IS NULL AND NOT v:Retired
OPTIONAL MATCH (v)-[rz:REALIZES]->(seg)
WHERE (seg:BridgeDomain OR seg:L2Segment) AND rz._retired_at IS NULL
RETURN dev.uid AS dev, x.name AS port, x:Interface AS svi, v.vid AS vid, v.name AS name,
       coalesce(r.native, false) AS native, seg.name AS segment, seg.uid AS bd
"""

# The read returns one row per interface address on a connected prefix. The
# VRF is the VRF of the interface. The routing domain is the declared one
# (`basis: declared`), which the next-hop owner of the path engine also reads
# (path/gates/routing.py). 2 VRFs of one name at 2 sites that share a routing
# scope have one domain. `routes` is true when the reasoner marked the
# interface GATEWAY_FOR the prefix. The path engine uses only that gateway
# (path/session.py GATEWAYS). A Prefix uid holds the uid of its VrfInstance
# (core/uid.py `prefix`), and the same subnet on 2 routers is 2 nodes.
# `_subnet_groups` groups them by cidr within the domain.
_SUBNETS = """
UNWIND $devs AS du
MATCH (dev:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT dev:Retired
MATCH (i:Interface)-[o:ON]->(dev)
WHERE NOT i:Retired AND o._retired_at IS NULL
MATCH (i)-[h:HAS_IP]->(ip:IpAddress)-[n:IN]->(pfx:Prefix)
WHERE h._retired_at IS NULL AND n._retired_at IS NULL
  AND NOT ip:Retired AND NOT pfx:Retired AND pfx.kind = 'connected'
OPTIONAL MATCH (i)-[iv:IN_VRF]->(vrf:VrfInstance) WHERE iv._retired_at IS NULL
OPTIONAL MATCH (vrf)-[m:MEMBER_OF]->(rd:RoutingDomain)
WHERE m._retired_at IS NULL AND coalesce(m.basis, 'declared') = 'declared'
RETURN dev.uid AS dev, i.name AS iface, ip.ip AS ip, pfx.cidr AS cidr, pfx.af AS af,
       coalesce(vrf.name, 'default') AS vrf, rd.name AS domain, h.fhrp AS fhrp,
       EXISTS { MATCH (i)-[g:GATEWAY_FOR]->(pfx) WHERE g._retired_at IS NULL } AS routes
"""

# The read returns one row per (device, interface, bridge domain, basis) of an
# edge `(Interface)-[:ATTACHED_TO {basis}]->(BridgeDomain)` of the reasoner, and
# per address of the interface on a connected prefix. The address columns are
# the columns of `_SUBNETS`. An interface with no such address gives one row
# with a null address. `vid` and `segment` identify the bridge domain of a
# segment that no drawn VLAN row states. A snapshot without the edge returns no
# row. `routes` is true when the reasoner marked the interface GATEWAY_FOR the
# prefix. The path engine uses only that gateway (path/session.py GATEWAYS).
_ATTACHED = """
UNWIND $devs AS du
MATCH (dev:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT dev:Retired
MATCH (i:Interface)-[o:ON]->(dev)
WHERE NOT i:Retired AND o._retired_at IS NULL
MATCH (i)-[a:ATTACHED_TO]->(bd:BridgeDomain)
WHERE a._retired_at IS NULL AND NOT bd:Retired
OPTIONAL MATCH (i)-[h:HAS_IP]->(ip:IpAddress)-[n:IN]->(pfx:Prefix {kind: 'connected'})
WHERE h._retired_at IS NULL AND n._retired_at IS NULL AND NOT ip:Retired AND NOT pfx:Retired
OPTIONAL MATCH (i)-[iv:IN_VRF]->(vrf:VrfInstance) WHERE iv._retired_at IS NULL
OPTIONAL MATCH (vrf)-[m:MEMBER_OF]->(rd:RoutingDomain)
WHERE m._retired_at IS NULL AND coalesce(m.basis, 'declared') = 'declared'
RETURN DISTINCT dev.uid AS dev, i.name AS iface, bd.uid AS bd, a.basis AS basis,
       head([(bd)<-[rz:REALIZES]-(v:VlanInstance) WHERE rz._retired_at IS NULL AND NOT v:Retired
             | v.vid]) AS vid,
       bd.name AS segment, ip.ip AS ip, pfx.cidr AS cidr, pfx.af AS af,
       coalesce(vrf.name, 'default') AS vrf, rd.name AS domain, h.fhrp AS fhrp,
       EXISTS { MATCH (i)-[g:GATEWAY_FOR]->(pfx) WHERE g._retired_at IS NULL } AS routes
"""

# The read returns the prefixes of the bridge domains `$bds` of the drawing.
# The reasoner (rule `prefix-in-from-attachment`) and the APIC collector write
# `(Prefix)-[:IN]->(BridgeDomain)`. A snapshot of a schema before v0.31.0 holds
# the APIC relation as `WITHIN`, and the read matches both.
_SEGMENT_PREFIXES = """
MATCH (bd:BridgeDomain:Obj)
WHERE bd.uid IN $bds AND bd.collection_ts = $snap AND NOT bd:Retired
MATCH (p:Prefix)-[r:IN|WITHIN]->(bd)
WHERE r._retired_at IS NULL AND NOT p:Retired
RETURN DISTINCT bd.uid AS bd, p.cidr AS cidr, p.af AS af
"""


def _vlan_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group the rows per (device, VLAN). A group holds the ports that carry
    the VLAN, the native ports among them and the SVI that binds to it. Port
    names are sorted.
    """
    groups: dict[tuple[str, int], dict[str, Any]] = {}
    for r in rows:
        key = (r["dev"], int(r["vid"]))
        g = groups.setdefault(
            key,
            {
                "dev": r["dev"],
                "vid": int(r["vid"]),
                "name": None,
                "segment": None,
                "bd": None,
                "ports": set(),
                "native": set(),
                "svi": None,
            },
        )
        if r.get("name") and not g["name"]:
            g["name"] = r["name"]
        if r.get("segment") and not g["segment"]:
            g["segment"] = r["segment"]
        if r.get("bd") and not g["bd"]:
            g["bd"] = r["bd"]
        if r.get("svi"):
            g["svi"] = r["port"]
        elif r.get("port"):
            g["ports"].add(r["port"])
            if r.get("native"):
                g["native"].add(r["port"])
    out = []
    for _, g in sorted(groups.items()):
        out.append({**g, "ports": sorted(g["ports"]), "native": sorted(g["native"])})
    return out


def _subnet_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group the rows per (routing domain, cidr). A group holds every interface
    address on the cidr. The key holds the VRF name for a row with no declared
    RoutingDomain."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        domain = r.get("domain") or r["vrf"]
        key = (domain, r["cidr"])
        g = groups.setdefault(
            key,
            {"cidr": r["cidr"], "af": r["af"], "vrf": r["vrf"], "domain": r.get("domain"), "members": []},
        )
        g["members"].append({"dev": r["dev"], "iface": r["iface"], "ip": r["ip"], "fhrp": r.get("fhrp")})
    out = []
    for _, g in sorted(groups.items()):
        g["members"].sort(key=lambda m: (m["dev"], m["iface"] or "", m["ip"]))
        out.append(g)
    return out


def _freshened(
    row: dict[str, Any], snapshot: Any, index: cyclemod.DeviceIndex | None = None
) -> dict[str, Any]:
    """Return one drawn device with its freshness and without the keys `_scope` and `_sources`.

    `carried`, `carried_reason` and `last_seen` come from the node. `tables` is
    the age per table of the device. It comes from the manifest of the run
    through `_scope` and `_sources` of the object (`core/cycle.py
    freshness_for`). `tables` is empty when no manifest governs the run, when
    the object has no scope or no source, or when the count of manifest devices
    that match the object is not 1.
    """
    entry = cyclemod.freshness_for(snapshot, row, index)
    return {
        **{k: v for k, v in row.items() if not k.startswith("_")},
        "tables": {} if entry is None else entry["tables"],
    }


def _read(s: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    """Run one read of the drawing in a read transaction with the timeout READ_TIMEOUT_S."""

    @unit_of_work(timeout=READ_TIMEOUT_S)
    def work(tx: Any) -> list[dict[str, Any]]:
        return tx.run(query, **params).data()

    rows: list[dict[str, Any]] = s.execute_read(work)
    return rows


def _site_uids(site: list[str] | None) -> list[str] | None:
    """Return the Site uids of the codes asked for. A code is case-sensitive,
    and the graph holds one Site per uid. The reads compare uids."""
    return None if site is None else [uidmod.site(code) for code in site]


def _check_sites(site: list[str] | None) -> None:
    if site is not None and any(not code.strip() for code in site):
        raise HTTPException(400, detail="a site code is required")


def _drawn_devices(s: Any, site: list[str] | None, snap: Any) -> list[dict[str, Any]]:
    """Return the devices of the drawing. They are the devices of the sites
    asked for, read from the Site, or every device of the run when no site is
    asked for."""
    if site is None:
        return _read(s, _DEVICES, site=None, snap=snap)
    return _read(s, _SITE_DEVICES, site=_site_uids(site), snap=snap)


@router.get("/topology", dependencies=[Depends(require_permission("graph.read"))])
def get_topology(request: Request, site: Annotated[list[str] | None, Query()] = None) -> dict[str, Any]:
    _check_sites(site)
    settings = request.app.state.settings
    with _session(settings) as s:
        # Every read of the drawing uses this one resolved run.
        resolved = snapshotmod.resolve(s, settings)
        with reading(request, s, resolved):
            snap = snapshotmod.snap_param(resolved.cts)
            devices = _drawn_devices(s, site, snap)
            # Every later read starts from the drawn devices by uid.
            devs = sorted({d["uid"] for d in devices})
            cables = _read(s, _CABLES, devs=devs, snap=snap)
            lags = _read(s, _LAGS, devs=devs, snap=snap)
            groups = _read(s, _GROUPS, devs=devs, snap=snap)
            wan = [r["dev"] for r in _read(s, _WAN_DEVICES, devs=devs, snap=snap)]
            client_rows = _read(s, _CLIENTS, devs=devs, snap=snap)
            vlan_rows = _read(s, _VLANS, devs=devs, snap=snap)
            subnet_rows = _read(s, _SUBNETS, devs=devs, snap=snap)
            attached_rows = _read(s, _ATTACHED, devs=devs, snap=snap)
            keep = set(devs)
            # `bds` holds the bridge domains of the rows of the drawn devices. The
            # client filter `visible` runs below and only removes rows.
            bds = sorted(
                {r["bd"] for r in vlan_rows if r["dev"] in keep and r.get("bd")}
                | {r["bd"] for r in client_rows if r["dev"] in keep and r.get("bd")}
                | {r["bd"] for r in attached_rows if r["dev"] in keep and r.get("bd")}
            )
            prefix_rows = _read(s, _SEGMENT_PREFIXES, bds=bds, snap=snap) if bds else []
    model = planner.plan(devices, cables, lags, groups, wan)

    index = None if resolved.manifest is None else cyclemod.device_index(resolved.manifest.devices)
    fresh = {d["uid"]: _freshened(d, resolved, index) for d in devices}
    for node in model["nodes"]:
        if node["kind"] == "device":
            f = fresh[node["id"]]
            node.update(
                carried=f.get("carried", False),
                carried_reason=f.get("carried_reason"),
                last_seen=f.get("last_seen"),
                tables=f["tables"],
            )
    # The overlays and the clients are those of the drawn devices. `visible`
    # (segments.py) skips a client that is a drawn device or sits on a cabled port.
    macs = segmod.device_macs(devices)
    cabled = segmod.cabled_ports(cables)
    clients = [r for r in client_rows if r["dev"] in keep and segmod.visible(r, macs, cabled)]
    vlans = _vlan_groups([r for r in vlan_rows if r["dev"] in keep])
    subnets = [r for r in subnet_rows if r["dev"] in keep]
    attached = [r for r in attached_rows if r["dev"] in keep]
    return {
        "snapshot": resolved.cts,
        **model,
        "clients": _client_groups(clients),
        "vlans": vlans,
        "subnets": _subnet_groups(subnets),
        "segments": segmod.segments(
            vlans,
            subnets,
            clients,
            cabled,
            attached=attached,
            prefixes=prefix_rows,
            sites={d["uid"]: d.get("site") for d in devices},
        ),
    }


def _client(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": r["name"],
        "uid": r["uid"],
        "ips": r["ips"],
        "mac": r.get("mac"),
        "wired": r.get("wired"),
        "vendor": r.get("vendor"),
        "last_seen": r.get("last_seen"),
        "bd": r.get("bd"),
    }


def _client_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group the rows per attachment point, which is a port of a device, or an
    access point and an SSID. A group holds the endpoint count, the count per
    bridge domain and the first SAMPLE_CLIENTS endpoints."""
    groups: dict[tuple[str, str | None, str | None], dict[str, Any]] = {}
    for r in rows:
        port = r.get("port")
        g = groups.setdefault(
            (r["dev"], port, r["ssid"]),
            {"dev": r["dev"], "port": port, "ssid": r["ssid"], "count": 0, "by_bd": {}, "clients": []},
        )
        g["count"] += 1
        bd = r.get("bd")
        if bd:
            g["by_bd"][bd] = g["by_bd"].get(bd, 0) + 1
        if len(g["clients"]) < SAMPLE_CLIENTS:
            g["clients"].append(_client(r))
    return list(groups.values())


# The default page size and the largest page size of the segment list (GET /topology/segment).
SEGMENT_PAGE = 100
SEGMENT_PAGE_MAX = 500

# The read returns the client endpoints of one bridge domain that attach to the
# devices of the asked sites. A row holds the columns of `_CLIENTS` except
# `cidrs`, the name of the device, and `cabled` for an attachment port with a
# cable. The route reads a page of these rows (`_SEGMENT_PAGE_TAIL`) and passes
# the MACs of the drawn devices for the skip rule (segments.py `visible`). The
# marker `/*filter*/` takes the endpoint filter of the request
# (core/filters.py). `_SEGMENT_CLIENTS` is the query without the marker.
_SEGMENT_CLIENTS_FILTERED = (
    """
MATCH (bd:Obj {uid: $bd, collection_ts: $snap})
WHERE (bd:BridgeDomain OR bd:L2Segment) AND NOT bd:Retired
MATCH (e:Endpoint)-[ib:IN]->(bd)
WHERE e.collection_ts = $snap AND NOT e:Retired AND ib._retired_at IS NULL/*filter*/
MATCH (e)-[a:ATTACHED]->(at) WHERE a._retired_at IS NULL AND NOT at:Retired
OPTIONAL MATCH (at)-[o:ON]->(od:Device) WHERE o._retired_at IS NULL
WITH bd, e, a, at, coalesce(od, CASE WHEN at:Device THEN at END) AS dev
WHERE dev IS NOT NULL AND NOT dev:Retired
"""
    + _AT_SITE.format(carry="bd, e, a, at, dev")
    + """OPTIONAL MATCH (e)-[h:HAS_IP]->(ip:IpAddress) WHERE h._retired_at IS NULL
WITH bd, dev, at, a.ssid AS ssid, e, collect(DISTINCT ip.ip) AS ips
RETURN dev.uid AS dev, coalesce(dev.hostname, dev.uid) AS dev_name, ssid,
       CASE WHEN at:Port OR at:Interface THEN at.name END AS port,
       EXISTS { MATCH (at)-[c:CONNECTED_TO]-(far:Port)
                WHERE c._retired_at IS NULL AND NOT far:Retired } AS cabled,
       coalesce(e.hostname, e.name, e.mac, e.uid) AS name, e.uid AS uid, e.mac AS mac,
       e.wired AS wired, e.oui AS vendor, coalesce(e.last_seen, e.last_seen_ts) AS last_seen,
       bd.uid AS bd, ips
ORDER BY name, uid
"""
)
_SEGMENT_CLIENTS = _SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "")

# The read returns the same rows when sites are asked for. It starts from the
# devices of those sites (`$devs`, the uids of the drawn devices).
_SITE_SEGMENT_CLIENTS_FILTERED = """
UNWIND $devs AS du
MATCH (dev:Device:Obj {uid: du, collection_ts: $snap})
WHERE NOT dev:Retired
CALL (dev) {
  MATCH (e:Endpoint)-[a:ATTACHED]->(dev) RETURN e, a, dev AS at
  UNION
  MATCH (e:Endpoint)-[a:ATTACHED]->(at)-[o:ON]->(dev) WHERE o._retired_at IS NULL RETURN e, a, at
}
MATCH (bd:Obj {uid: $bd, collection_ts: $snap})
WHERE (bd:BridgeDomain OR bd:L2Segment) AND NOT bd:Retired
MATCH (e)-[ib:IN]->(bd)
WHERE e.collection_ts = $snap AND NOT e:Retired AND ib._retired_at IS NULL
  AND a._retired_at IS NULL AND NOT at:Retired/*filter*/
OPTIONAL MATCH (e)-[h:HAS_IP]->(ip:IpAddress) WHERE h._retired_at IS NULL
WITH bd, dev, at, a.ssid AS ssid, e, collect(DISTINCT ip.ip) AS ips
RETURN dev.uid AS dev, coalesce(dev.hostname, dev.uid) AS dev_name, ssid,
       CASE WHEN at:Port OR at:Interface THEN at.name END AS port,
       EXISTS { MATCH (at)-[c:CONNECTED_TO]-(far:Port)
                WHERE c._retired_at IS NULL AND NOT far:Retired } AS cabled,
       coalesce(e.hostname, e.name, e.mac, e.uid) AS name, e.uid AS uid, e.mac AS mac,
       e.wired AS wired, e.oui AS vendor, coalesce(e.last_seen, e.last_seen_ts) AS last_seen,
       bd.uid AS bd, ips
ORDER BY name, uid
"""
_SITE_SEGMENT_CLIENTS = _SITE_SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "")

# The tail cuts a page of one of the 2 reads above in the database. It applies
# the skips of the drawing (segments.py `visible`), which are a device that is
# not drawn, an endpoint on a cabled port and an endpoint with the MAC of a
# drawn device. MACs are compared in the canonical form of core/uid.py
# `norm_mac`. The tail orders the rows by (name, uid) and returns the total and
# `$limit` + 1 rows of the page. The extra row shows that a next page exists. A
# cursor starts the page after the rows that sort at or before its (name, uid),
# as core/filters.py `after` does.
_SEGMENT_PAGE_TAIL = """}
WITH dev, dev_name, ssid, port, cabled, name, uid, mac, wired, vendor, last_seen, bd, ips,
     reduce(m = '', ch IN split(toLower(coalesce(toString(mac), '')), '') |
            m + CASE WHEN ch IN $hex THEN ch ELSE '' END) AS mac12
WHERE dev IN $keep AND NOT cabled AND NOT (size(mac12) = 12 AND mac12 IN $macs)
WITH dev, dev_name, ssid, port, name, uid, mac, wired, vendor, last_seen, bd, ips
ORDER BY name, uid
WITH collect({dev: dev, dev_name: dev_name, ssid: ssid, port: port, name: name, uid: uid, mac: mac,
              wired: wired, vendor: vendor, last_seen: last_seen, bd: bd, ips: ips}) AS rows
WITH rows, CASE WHEN $after_name IS NULL THEN $offset
                ELSE size([r IN rows WHERE r.name < $after_name
                           OR (r.name = $after_name AND r.uid <= $after_uid)]) END AS start
RETURN size(rows) AS total, rows[start..start + $limit + 1] AS page
"""


def _segment_page(rows_query: str) -> str:
    """Return the segment list read `rows_query` with the page tail."""
    return "CALL () {" + rows_query + _SEGMENT_PAGE_TAIL


_SEGMENT_PAGE_QUERY = _segment_page(_SEGMENT_CLIENTS)
_SITE_SEGMENT_PAGE_QUERY = _segment_page(_SITE_SEGMENT_CLIENTS)

# The hex digits of a MAC. The page read compares only these characters of `mac`.
_HEX = list("0123456789abcdef")

# The cursor kind of the segment list.
SEGMENT_CURSOR = "segment_client"


def _segment_print(f: filtermod.EntityFilter, bd: str, site: list[str] | None) -> str:
    """Return the fingerprint of a segment cursor. It is a hash of the filter,
    the bridge domain and the sites. `decode_cursor` refuses a cursor with
    another fingerprint."""
    canon = json.dumps([f.fingerprint(), bd, sorted(site or [])])
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


@router.get("/topology/segment", dependencies=[Depends(require_permission("graph.read"))])
def get_segment(
    request: Request,
    bd: Annotated[str, Query(min_length=1)],
    values: Annotated[dict[str, Any], Depends(endpoint_routes.endpoint_filter_values)],
    site: Annotated[list[str] | None, Query()] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=SEGMENT_PAGE_MAX)] = SEGMENT_PAGE,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Return one page of the client endpoints of the bridge domain `bd` on the
    devices of the asked sites, ordered by name. It is the full list behind
    the counts of `GET /topology`. It skips the endpoints that `GET /topology`
    skips, which are a drawn device by its MAC and an endpoint on a cabled
    port.

    The endpoint filters of `GET /endpoints` apply, except `site` and
    `segment`. `offset` or `cursor` selects the page. `cursor` is the
    `next_cursor` of the page before, and it pins the run of that page.
    `total` counts every shown client of the filter."""
    _check_sites(site)
    f = endpoint_routes.filter_from(values)
    try:
        compiled = filtermod.compile_filter(f, "endpoint")
    except filtermod.FilterError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    fingerprint = _segment_print(f, bd, site)
    after = None
    if cursor:
        if offset:
            raise HTTPException(400, detail="offset and cursor cannot both be set")
        try:
            after = filtermod.decode_cursor(cursor, kind=SEGMENT_CURSOR, filter_print=fingerprint)
        except filtermod.FilterError as exc:
            raise HTTPException(400, detail=str(exc)) from exc
    settings = request.app.state.settings
    with _session(settings) as s:
        resolved = snapshotmod.resolve(s, settings, endpoint_routes.pinned_run(s, None, after))
        with reading(request, s, resolved):
            snap = snapshotmod.snap_param(resolved.cts)
            devices = _drawn_devices(s, site, snap)
            keep = sorted({d["uid"] for d in devices})
            # The read starts from the bridge domain when no site is asked for,
            # else from the devices of the asked sites.
            if site is None:
                reads: dict[str, Any] = {"bd": bd, "site": None, "snap": snap}
                plain, filtered = _SEGMENT_PAGE_QUERY, _SEGMENT_CLIENTS_FILTERED
            else:
                reads = {"bd": bd, "devs": keep, "snap": snap}
                plain, filtered = _SITE_SEGMENT_PAGE_QUERY, _SITE_SEGMENT_CLIENTS_FILTERED
            reads |= {
                "keep": keep,
                "macs": sorted(segmod.device_macs(devices)),
                "hex": _HEX,
                "offset": offset,
                "limit": limit,
                "after_name": after.key if after is not None else None,
                "after_uid": after.uid if after is not None else None,
            }
            if compiled.empty:
                [found] = _read(s, plain, **reads)
            else:
                where = "\n  AND " + compiled.where
                query = entity_read.timed(_segment_page(filtered.replace("/*filter*/", where)))
                [found] = s.run(query, **reads, **compiled.params).data()
    total, rest = found["total"], found["page"]
    page = rest[:limit]
    next_cursor = None
    if len(rest) > limit and page:
        next_cursor = filtermod.Cursor(
            kind=SEGMENT_CURSOR,
            run=resolved.cts,
            key=page[-1]["name"],
            uid=page[-1]["uid"],
            filter=fingerprint,
        ).encode()
    return {
        "snapshot": resolved.cts,
        "bd": bd,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_cursor": next_cursor,
        "clients": [
            {**_client(r), "dev": r["dev"], "dev_name": r.get("dev_name"), "port": r.get("port")}
            | {"ssid": r.get("ssid")}
            for r in page
        ],
    }
