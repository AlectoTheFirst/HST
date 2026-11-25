"""GET /api/equinix/metros lists the metros with a Fabric port or a Network Edge
device. GET /api/equinix/metro returns the Fabric ports, the Network Edge devices
and the circuits of one metro."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hst.app.auth import require_permission
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.queries import CIRCUIT_CABLED, QUERIES
from hst.reasoner import ACTIVE_CIRCUIT_STATES, ENDED_CIRCUIT_STATES

router = APIRouter()
_session = dbmod.session  # Tests replace this name.

_METROS = """
MATCH (fp:FabricPort:Obj)
WHERE fp.collection_ts = $snap AND NOT fp:Retired AND fp.metro IS NOT NULL
RETURN fp.metro AS metro, count(fp) AS ports, collect(DISTINCT fp.ibx) AS ibxs
ORDER BY metro
"""

_EDGE_METROS = """
MATCH (d:Device:Obj {platform: 'network-edge'})
WHERE d.collection_ts = $snap AND NOT d:Retired AND d.metro IS NOT NULL
RETURN d.metro AS metro, count(d) AS edge_devices
"""

_PORTS = """
MATCH (fp:FabricPort:Obj {metro: $metro})
WHERE fp.collection_ts = $snap AND NOT fp:Retired
OPTIONAL MATCH (fp)-[r:REALIZED_BY]->(p:Port)-[o:ON]->(d:Device)
WHERE r._retired_at IS NULL AND o._retired_at IS NULL AND NOT p:Retired AND NOT d:Retired
RETURN fp.uid AS uid, fp.name AS name, fp.ibx AS ibx, fp.state AS state, fp.speed_mbps AS speed_mbps,
       fp.redundancy AS redundancy, fp.lag_name AS lag, fp.cross_connect_ids AS cable_ids,
       p.uid AS port, p.name AS port_name, d.uid AS device, coalesce(d.hostname, d.uid) AS device_name,
       d.platform AS device_platform,
       CASE WHEN r IS NULL THEN null WHEN r.derived THEN coalesce(r.evidence, 'derived')
            ELSE 'operator' END AS bound_by,
       fp.bound_port_uid AS binding,
       EXISTS { MATCH (fp)-[r2:REALIZED_BY]->(:Port) WHERE r2._retired_at IS NULL } AS realized,
       fp.binding_issue AS issue, fp.binding_ports AS issue_ports
ORDER BY ibx, name
"""

_EDGE_DEVICES = """
MATCH (d:Device:Obj {platform: 'network-edge', metro: $metro})
WHERE d.collection_ts = $snap AND NOT d:Retired
OPTIONAL MATCH (d)-[s:SAME_AS]->(t:Device) WHERE s._retired_at IS NULL AND NOT t:Retired
RETURN d.uid AS uid, coalesce(d.hostname, d.uid) AS name, d.vendor AS vendor, d.model AS model,
       d.role AS role, d.ibx AS ibx, d.edge_status AS status, d.bound_device_uid AS bound_device,
       t.uid AS same_as, t.hostname AS same_as_name
ORDER BY name
"""

# Every circuit with an end on a Fabric port of the metro or on an interface of
# a Network Edge device of the metro, with both ends.
_CIRCUITS = (
    """
MATCH (vc:VirtualCircuit:Obj)-[:A_END|Z_END]->(x)
WHERE vc.collection_ts = $snap AND NOT vc:Retired
  AND ((x:FabricPort AND x.metro = $metro)
       OR (x:Interface AND EXISTS {
         MATCH (ed:Obj)
         WHERE ed.uid = x.edge_device_uid AND ed.collection_ts = $snap AND ed:Device AND ed.metro = $metro
       }))
WITH DISTINCT vc
OPTIONAL MATCH (vc)-[ae:A_END]->(a) WHERE ae._retired_at IS NULL AND NOT a:Retired
OPTIONAL MATCH (vc)-[ze:Z_END]->(z) WHERE ze._retired_at IS NULL AND NOT z:Retired
OPTIONAL MATCH (ad:Obj) WHERE ad.uid = a.edge_device_uid AND ad.collection_ts = $snap AND ad:Device
OPTIONAL MATCH (zd:Obj) WHERE zd.uid = z.edge_device_uid AND zd.collection_ts = $snap AND zd:Device
RETURN vc.uid AS uid, vc.name AS name, vc.type AS type, vc.state AS state,
       vc.bandwidth_mbps AS bandwidth_mbps, vc.provider AS provider,
       vc.a_side_kind AS a_side_kind, vc.z_side_kind AS z_side_kind, vc.a_virtual_device AS a_virtual_device,
       CASE WHEN a IS NULL THEN null ELSE {
         node: a.uid, name: a.name, fabric_port: a:FabricPort, ibx: coalesce(a.ibx, ad.ibx),
         metro: coalesce(a.metro, ad.metro), device: ad.uid, device_name: ad.hostname
       } END AS a,
       ae.vlan_tag AS a_tag,
       CASE WHEN z IS NULL THEN null ELSE {
         node: z.uid, name: z.name, fabric_port: z:FabricPort, ibx: coalesce(z.ibx, zd.ibx),
         metro: coalesce(z.metro, zd.metro), device: zd.uid, device_name: zd.hostname
       } END AS z,
       ze.vlan_tag AS z_tag,
       """
    + CIRCUIT_CABLED
    + """ AS cabled
ORDER BY name
"""
)


def _snap(s: Any, settings: Any) -> Any:
    resolved = snapshotmod.resolve(s, settings)
    return snapshotmod.snap_param(resolved.cts)


def _queries() -> list[dict[str, Any]]:
    return [
        {"key": q["key"], "title": q["title"], "description": q.get("description")}
        for q in QUERIES
        if q["group"] == "equinix"
    ]


def _end(row: dict[str, Any], side: str) -> dict[str, Any] | None:
    """One circuit end. A bound end is the account's Fabric port or Network Edge
    interface. An unbound end is a cloud on-ramp, a port of another party or a
    device outside the account. It has the name that the circuit gives it."""
    end = row[side]
    tag = row[f"{side}_tag"]
    if end is not None:
        return {
            "kind": "port" if end["fabric_port"] else "edge",
            "node": end["node"],
            "name": end["name"],
            "ibx": end["ibx"],
            "metro": end["metro"],
            "device": end["device"],
            "device_name": end["device_name"],
            "tag": tag,
        }
    side_kind = row[f"{side}_side_kind"]
    if side == "z" and row.get("provider"):
        return {"kind": "provider", "name": row["provider"], "tag": tag}
    if side == "a" and row.get("a_virtual_device"):
        return {"kind": "other", "name": row["a_virtual_device"], "tag": tag}
    return {"kind": "other", "name": side_kind or "unknown", "tag": tag}


def _unbound(p: dict[str, Any]) -> dict[str, Any] | None:
    """The reason that a Fabric port has no switch port. It is an operator
    binding to a port that is not in the run, or the issue that the
    fabric-port-from-description rule recorded."""
    if p.get("binding") and not p.get("realized"):
        return {"reason": "binding-refused", "ports": [p["binding"]]}
    if p.get("issue"):
        return {"reason": p["issue"], "ports": list(p.get("issue_ports") or [])}
    return None


@router.get("/equinix/metros", dependencies=[Depends(require_permission("graph.read"))])
def get_metros(request: Request) -> dict[str, Any]:
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = _snap(s, settings)
        rows = s.run(_METROS, snap=snap).data()
        edge = {r["metro"]: r["edge_devices"] for r in s.run(_EDGE_METROS, snap=snap).data()}
    metros = {
        r["metro"]: {"metro": r["metro"], "ports": r["ports"], "ibxs": sorted(r["ibxs"]), "edge_devices": 0}
        for r in rows
    }
    for metro, count in edge.items():
        metros.setdefault(metro, {"metro": metro, "ports": 0, "ibxs": [], "edge_devices": 0})
        metros[metro]["edge_devices"] = count
    return {"metros": [metros[m] for m in sorted(metros)], "queries": _queries()}


@router.get("/equinix/metro", dependencies=[Depends(require_permission("graph.read"))])
def get_metro(request: Request, metro: Annotated[str, Query(min_length=1)]) -> dict[str, Any]:
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = _snap(s, settings)
        ports = s.run(_PORTS, metro=metro, snap=snap).data()
        edge_devices = s.run(_EDGE_DEVICES, metro=metro, snap=snap).data()
        if not ports and not edge_devices:
            raise HTTPException(
                status_code=404, detail="no Fabric port and no Network Edge device in this metro"
            )
        circuit_rows = s.run(_CIRCUITS, metro=metro, snap=snap).data()

    devices: dict[str, dict[str, Any]] = {}
    for p in ports:
        if p["device"]:
            devices.setdefault(
                p["device"],
                {
                    "uid": p["device"],
                    "name": p["device_name"],
                    "platform": p["device_platform"],
                    "kind": "switch",
                },
            )
    circuits = []
    ended = 0
    other: dict[str, int] = {}
    for row in circuit_rows:
        state = str(row["state"] or "").upper()
        if state in ENDED_CIRCUIT_STATES:
            ended += 1
            continue
        if state not in ACTIVE_CIRCUIT_STATES:
            key = state or "none"
            other[key] = other.get(key, 0) + 1
            continue
        circuits.append(
            {
                "uid": row["uid"],
                "name": row["name"],
                "type": row["type"],
                "state": row["state"],
                "bandwidth_mbps": row["bandwidth_mbps"],
                "cabled": row["cabled"],
                "a": _end(row, "a"),
                "z": _end(row, "z"),
            }
        )
    return {
        "metro": metro,
        "ports": [
            {
                "uid": p["uid"],
                "name": p["name"],
                "ibx": p["ibx"],
                "state": p["state"],
                "speed_mbps": p["speed_mbps"],
                "redundancy": p["redundancy"],
                "lag": p["lag"],
                "cable_ids": p["cable_ids"] or [],
                "bound": (
                    {
                        "device": p["device"],
                        "port": p["port"],
                        "port_name": p["port_name"],
                        "by": p["bound_by"],
                    }
                    if p["device"]
                    else None
                ),
                "unbound": None if p["device"] else _unbound(p),
            }
            for p in ports
        ],
        "devices": sorted(devices.values(), key=lambda d: d["name"] or d["uid"]),
        "edge_devices": edge_devices,
        "circuits": circuits,
        "ended_circuits": ended,
        "other_circuits": other,
        "queries": _queries(),
    }
