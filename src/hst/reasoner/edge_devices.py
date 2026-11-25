"""The edge-device-from-binding rule and the edge-devices check."""

from __future__ import annotations

from typing import Any

from hst.core.identity import short_name

# The edge-device-from-binding rule.
#
# A Network Edge device and the device that a Cisco or VeloCloud collector
# reads can be one box. The operator states the pair on the Equinix source
# (`edge_device_bindings`). The collector records the pair as
# `bound_device_uid` and writes no `ON` edge from the interfaces and ports of
# the device. A Network Edge interface whose MAC address is on exactly one
# port of the bound device gets a `REALIZED_BY` edge to that port. A Cisco
# C8000V reports the MAC of each port. Without such a port (a VeloCloud edge
# reports no MAC), the interface and its port get an `ON` edge to the bound
# device.

EDGE_DEVICE_RULE = "edge-device-from-binding"

FETCH_EDGE_BINDINGS = """
MATCH (d:Device:Obj {platform: 'network-edge'})
WHERE NOT d:Retired AND d.collection_ts = $cts AND d.bound_device_uid IS NOT NULL
MATCH (t:Device:Obj {uid: d.bound_device_uid, collection_ts: $cts})
WHERE NOT t:Retired
OPTIONAL MATCH (tp:Port)-[o:ON]->(t)
WHERE NOT tp:Retired AND o._retired_at IS NULL AND tp.collection_ts = $cts
  AND tp.mac IS NOT NULL
RETURN d.uid AS edge_device, t.uid AS device,
       [x IN collect(DISTINCT {uid: tp.uid, mac: tp.mac}) WHERE x.uid IS NOT NULL] AS device_ports
"""

FETCH_EDGE_INTERFACES = """
MATCH (i:Interface:Obj)-[r:REALIZED_BY]->(p:Port)
WHERE i.edge_device_uid IN $edge_devices AND p.edge_device_uid = i.edge_device_uid
  AND NOT i:Retired AND NOT p:Retired AND r._retired_at IS NULL
  AND i.collection_ts = $cts AND p.collection_ts = $cts
RETURN i.edge_device_uid AS edge_device, i.uid AS interface, p.uid AS port, i.mac AS mac
"""

_EDGE_STAMP = """
SET r.derived = true, r.rule = 'edge-device-from-binding',
    r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
RETURN count(*) AS n
"""

EDGE_SAME_AS_WRITE = (
    """
UNWIND $rows AS e
MATCH (d:Device:Obj {uid: e.edge_device, collection_ts: $cts}) WHERE d.collection_ts = $cts
MATCH (t:Device:Obj {uid: e.device, collection_ts: $cts}) WHERE t.collection_ts = $cts
MERGE (d)-[r:SAME_AS {source: 'reasoner'}]->(t)"""
    + _EDGE_STAMP
)

EDGE_ON_WRITE = (
    """
UNWIND $rows AS e
MATCH (x:Obj {uid: e.node, collection_ts: $cts}) WHERE (x:Interface OR x:Port)
MATCH (t:Device:Obj {uid: e.device, collection_ts: $cts}) WHERE t.collection_ts = $cts
MERGE (x)-[r:ON {source: 'reasoner'}]->(t)"""
    + _EDGE_STAMP
)

EDGE_REALIZED_WRITE = (
    """
UNWIND $rows AS e
MATCH (i:Interface:Obj {uid: e.interface, collection_ts: $cts}) WHERE i.collection_ts = $cts
MATCH (p:Port:Obj {uid: e.port, collection_ts: $cts}) WHERE p.collection_ts = $cts
MERGE (i)-[r:REALIZED_BY {source: 'reasoner'}]->(p)"""
    + _EDGE_STAMP
)


def resolve_edge_device_bindings(
    bindings: list[dict[str, Any]], interfaces: list[dict[str, Any]]
) -> dict[str, Any]:
    """The edges that put the interfaces of each bound Network Edge device on
    the bound device, as `{"same_as": [{"edge_device", "device"}], "on":
    [{"node", "device"}], "realized": [{"interface", "port"}], "ambiguous": n}`.

    `ambiguous` counts the interfaces whose MAC address is on more than one
    port of the bound device. Such an interface and its port go `ON` the
    device, the same as an interface whose MAC matches no port."""
    by_edge = {row["edge_device"]: row for row in bindings}
    report: dict[str, Any] = {
        "same_as": [{"edge_device": row["edge_device"], "device": row["device"]} for row in bindings],
        "on": [],
        "realized": [],
        "ambiguous": 0,
    }
    for row in sorted(interfaces, key=lambda r: r["interface"]):
        binding = by_edge.get(row["edge_device"])
        if binding is None:
            continue
        mac = row.get("mac")
        same = sorted(p["uid"] for p in binding.get("device_ports") or [] if mac and p.get("mac") == mac)
        if len(same) == 1:
            report["realized"].append({"interface": row["interface"], "port": same[0]})
            continue
        if len(same) > 1:
            report["ambiguous"] += 1
        report["on"].append({"node": row["interface"], "device": binding["device"]})
        report["on"].append({"node": row["port"], "device": binding["device"]})
    return report


def _run_edge_device_rule(tx: Any, *, ts: int, cts: int) -> dict[str, Any]:
    bindings = tx.run(FETCH_EDGE_BINDINGS, cts=cts).data()
    if not bindings:
        return {"edges": 0, "on": 0, "realized": 0, "ambiguous": 0}
    interfaces = tx.run(
        FETCH_EDGE_INTERFACES, cts=cts, edge_devices=[row["edge_device"] for row in bindings]
    ).data()
    report = resolve_edge_device_bindings(bindings, interfaces)
    counts = {}
    for key, query in (
        ("same_as", EDGE_SAME_AS_WRITE),
        ("on", EDGE_ON_WRITE),
        ("realized", EDGE_REALIZED_WRITE),
    ):
        counts[key] = 0
        if report[key]:
            rows = tx.run(query, rows=report[key], ts=ts, cts=cts).data()
            counts[key] = rows[0]["n"] if rows else 0
    return {
        "edges": counts["same_as"],
        "on": counts["on"],
        "realized": counts["realized"],
        "ambiguous": report["ambiguous"],
    }


# The edge-devices check.
#
# A Network Edge device is its own Device (`eqx:device:`, collectors/equinix.py
# `_edge_stage`). The operator states the pair (`edge_device_bindings`,
# recorded as `bound_device_uid`). The check proposes for an unbound device the
# device of another source whose short hostname is the Network Edge device's
# name or host name. A VeloCloud edge also has the Network Edge management
# address on one of its WAN links. The check writes no edge.

FETCH_EDGE_DEVICES = """
MATCH (d:Device:Obj {platform: 'network-edge'})
WHERE NOT d:Retired AND d.collection_ts = $cts AND d.bound_device_uid IS NULL
RETURN d.uid AS uid, d.edge_device_uuid AS edge_device_uuid, d.edge_management_ip AS management_ip,
       [x IN coalesce(d.identities, []) + [d.hostname] WHERE x IS NOT NULL] AS names
"""

FETCH_EDGE_CANDIDATES = """
MATCH (d:Device:Obj)
WHERE NOT d:Retired AND d.collection_ts = $cts
  AND d.hostname IS NOT NULL AND coalesce(d.platform, '') <> 'network-edge'
OPTIONAL MATCH (d)-[h:HAS_LINK]->(w:WanLink)
WHERE h._retired_at IS NULL AND NOT w:Retired
RETURN d.uid AS uid, d.hostname AS hostname, d.platform AS platform,
       [ip IN collect(DISTINCT w.public_ip) WHERE ip IS NOT NULL] AS wan_ips
"""

FETCH_EDGE_BINDINGS_REFUSED = """
MATCH (d:Device:Obj {platform: 'network-edge'})
WHERE NOT d:Retired AND d.collection_ts = $cts AND d.bound_device_uid IS NOT NULL
  AND NOT EXISTS {
    MATCH (t:Device:Obj {uid: d.bound_device_uid, collection_ts: $cts})
    WHERE NOT t:Retired
  }
RETURN d.uid AS uid, d.bound_device_uid AS bound_device_uid
ORDER BY d.uid
"""


def edge_device_candidates(
    edge_devices: list[dict[str, Any]], devices: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """The binding each unbound Network Edge device can take, as `{"proposed":
    [{"edge_device", "edge_device_uuid", "device"}], "conflicts": [...],
    "ambiguous": [...]}`. A conflict is a VeloCloud edge with the hostname but
    without the management address on a WAN link."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        by_name.setdefault(short_name(device["hostname"]), []).append(device)
    report: dict[str, list[dict[str, Any]]] = {"proposed": [], "conflicts": [], "ambiguous": []}
    for edge in sorted(edge_devices, key=lambda e: e["uid"]):
        names = {short_name(n) for n in edge.get("names") or []} - {""}
        found = {d["uid"]: d for n in names for d in by_name.get(n, [])}
        if not found:
            continue
        if len(found) > 1:
            report["ambiguous"].append({"edge_device": edge["uid"], "devices": sorted(found)})
            continue
        device = next(iter(found.values()))
        if device.get("platform") == "velocloud-edge" and edge.get("management_ip") not in (
            device.get("wan_ips") or []
        ):
            report["conflicts"].append(
                {
                    "edge_device": edge["uid"],
                    "device": device["uid"],
                    "management_ip": edge.get("management_ip"),
                    "wan_ips": sorted(device.get("wan_ips") or []),
                }
            )
            continue
        report["proposed"].append(
            {
                "edge_device": edge["uid"],
                "edge_device_uuid": edge.get("edge_device_uuid"),
                "device": device["uid"],
            }
        )
    return report


def check_edge_devices(session: Any, *, collection_ts: int) -> dict[str, Any]:
    """The `edge-devices` check over one run. It only reads and writes no edge.

    Returns `{"proposed": [...], "warnings": [...]}`. `proposed` holds the
    bindings that `edge_device_candidates` proposes. `warnings` holds one
    warning per proposal, per conflict, per ambiguous name, and per binding
    whose device is not in the run."""

    def reads(tx: Any) -> tuple[list[dict[str, Any]], ...]:
        return (
            tx.run(FETCH_EDGE_DEVICES, cts=collection_ts).data(),
            tx.run(FETCH_EDGE_CANDIDATES, cts=collection_ts).data(),
            tx.run(FETCH_EDGE_BINDINGS_REFUSED, cts=collection_ts).data(),
        )

    edge_devices, devices, refused = session.execute_read(reads)
    report = edge_device_candidates(edge_devices, devices)
    warnings = [
        f"network edge device {row['edge_device']} has the hostname of {row['device']}; "
        f"proposed edge_device_bindings line: {row['edge_device_uuid']}, {row['device']}"
        for row in report["proposed"]
    ]
    warnings.extend(
        f"network edge device {row['edge_device']} has the hostname of {row['device']}, but its "
        f"management address {row['management_ip']} is on none of that edge's WAN links; no binding proposed"
        for row in report["conflicts"]
    )
    warnings.extend(
        f"network edge device {row['edge_device']} has the hostname of {len(row['devices'])} devices "
        f"({', '.join(row['devices'])}); no binding proposed"
        for row in report["ambiguous"]
    )
    warnings.extend(
        f"equinix edge device binding refused: {row['uid']} names device {row['bound_device_uid']}, "
        "which is not in this run"
        for row in refused
    )
    return {"proposed": report["proposed"], "warnings": warnings}
