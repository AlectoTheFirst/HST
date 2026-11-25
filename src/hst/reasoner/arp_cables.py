"""The cable-from-arp-port rule."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hst.core import uid as uidmod
from hst.reasoner._constants import STATED_CABLE_SOURCES
from hst.reasoner.stated_cables import _canonical_mac_or_none
from hst.reasoner.vlan_stretch import mac_rows_query

if TYPE_CHECKING:
    from hst.core.manifest import SidestoreFiles

logger = logging.getLogger(__name__)

# The rule derives a cable from the ARP table and the MAC table.
#
# A VeloCloud edge publishes no interface MAC (the VCO API has none) and
# speaks LLDP only from release 6.0 with a per-interface toggle. When the
# MAC table (side table `mac`) puts the MAC of an ARP row (side table `arp`)
# on exactly one physical port that holds no other MAC, the rule cables that
# port to the address owner with `derived: true`.
#
# `finalize` calls this rule after `run()`.

FETCH_SDWAN_ADDRESSES = """
MATCH (d:Device {platform: 'velocloud-edge'})<-[on:ON]-(i:Interface:Obj)-[h:HAS_IP]->(ip:IpAddress)
WHERE NOT d:Retired AND NOT i:Retired AND NOT ip:Retired
  AND on._retired_at IS NULL AND h._retired_at IS NULL
  AND i.collection_ts = $cts
OPTIONAL MATCH (i)-[rb:REALIZED_BY]->(p:Port)
WHERE rb._retired_at IS NULL AND NOT p:Retired
RETURN ip.ip AS ip, i.uid AS if_uid, d.uid AS device_uid, p.uid AS port_uid
"""

# The Devices of the run being built. The side store keeps the rows of every
# device uid it ever saw, and only these devices answer for an address.
FETCH_RUN_DEVICES = """
MATCH (d:Device:Obj)
WHERE NOT d:Retired AND d.collection_ts = $cts
RETURN d.uid AS uid
"""

ARP_CABLE_WRITE = """
UNWIND $edges AS e
MATCH (a:Port:Obj {uid: e.a, collection_ts: $cts}) WHERE NOT a:Retired
MATCH (z:Port:Obj {uid: e.z, collection_ts: $cts}) WHERE NOT z:Retired
WITH a, z, e
WHERE NOT EXISTS {
  MATCH (a)-[u:CONNECTED_TO]-()
  WHERE u.collection_ts = $cts AND (u.source IN $stated_cable_sources OR u.derived = false)
}
AND NOT EXISTS {
  MATCH (z)-[u2:CONNECTED_TO]-()
  WHERE u2.collection_ts = $cts AND (u2.source IN $stated_cable_sources OR u2.derived = false)
}
MERGE (a)-[c:CONNECTED_TO {source: 'reasoner'}]->(z)
SET c.derived = true, c.rule = 'cable-from-arp-port', c.basis = e.basis,
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN count(*) AS n
"""


def _quoted(values: list[str]) -> str:
    return ", ".join("'" + v.replace("'", "''") + "'" for v in sorted(set(values)))


def arp_rows_query(ips: list[str], cts: int) -> str:
    """The newest `arp` rows at or before the run that hold one of `ips`, on
    any device. The query quotes values as `mac_rows_query` does."""
    return (
        "SELECT device_uid, ip, mac, interface_name FROM arp "  # noqa: S608
        f"WHERE ip IN ({_quoted(ips)}) AND snapshot_ts <= {int(cts)} "
        "AND snapshot_ts = (SELECT max(a2.snapshot_ts) FROM arp a2 "
        f"WHERE a2.device_uid = arp.device_uid AND a2.snapshot_ts <= {int(cts)})"
    )


def resolve_arp_cables(
    addresses: list[dict[str, Any]],
    arp_rows: list[dict[str, Any]],
    mac_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """The (a, z) Port pairs that the 3 row sets give, and the counts of the
    addresses that did not resolve. The function is pure.

    `addresses` are `FETCH_SDWAN_ADDRESSES` rows. `arp_rows` are the
    side-store ARP rows for those addresses. `mac_rows` are the MAC rows of
    the devices that hold the ARP rows.

    An address resolves when all of these conditions hold.

    - Exactly one edge port holds the address.
    - Exactly one ARP row holds the address.
    - The MAC table of the device of that row has the MAC of the row on
      exactly one port.
    - That port has no other MAC.
    - The edge interface that holds the address realizes a Port.

    Any other address counts as `unresolved` (2 edges hold the address, no
    row, no port, the interface has no Port) or `shared` (the port has other
    MACs).
    """
    holders: dict[str, set[str]] = {}
    for addr in addresses:
        holders.setdefault(str(addr["ip"]), set()).add(str(addr.get("port_uid") or addr["if_uid"]))
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for row in arp_rows:
        if row.get("mac"):
            by_ip.setdefault(str(row["ip"]), []).append(row)
    ports_by_dev_mac: dict[tuple[str, str], set[str]] = {}
    macs_by_dev_port: dict[tuple[str, str], set[str]] = {}
    for row in mac_rows:
        key = (str(row["device_uid"]), str(row["mac"]))
        port = str(row.get("port_name") or "")
        if not port:
            continue
        ports_by_dev_mac.setdefault(key, set()).add(port)
        macs_by_dev_port.setdefault((str(row["device_uid"]), port), set()).add(str(row["mac"]))
    edges: list[dict[str, Any]] = []
    unresolved = shared = 0
    seen: set[tuple[str, str]] = set()
    for addr in addresses:
        rows = by_ip.get(str(addr["ip"]), [])
        edge_port = addr.get("port_uid")
        if len(holders[str(addr["ip"])]) != 1 or len(rows) != 1 or not edge_port:
            unresolved += 1
            continue
        row = rows[0]
        dev = str(row["device_uid"])
        mac = _canonical_mac_or_none(str(row["mac"])) or str(row["mac"])
        ports = ports_by_dev_mac.get((dev, mac), set())
        if len(ports) != 1:
            unresolved += 1
            continue
        port = next(iter(ports))
        if macs_by_dev_port.get((dev, port), set()) != {mac}:
            shared += 1
            continue
        cisco_port = uidmod.port(dev, port)
        a, z = sorted((cisco_port, str(edge_port)))
        if (a, z) in seen:
            continue
        seen.add((a, z))
        edges.append({"a": a, "z": z, "basis": f"arp {addr['ip']} mac {mac} port {port}"})
    return {"edges": edges, "unresolved": unresolved, "shared": shared}


def derive_arp_cables(
    session: Any,
    *,
    collection_ts: int,
    sidestore_dir: Path | None,
    ts_ms: int | None = None,
    sidestore_files: SidestoreFiles | None = None,
) -> dict[str, Any]:
    """The function runs cable-from-arp-port over one run. It reads the edge addresses
    from the graph and the ARP and MAC rows from the side store, and writes
    the cables. When the store fails, the result counts the edge addresses as
    `not_evaluated` and holds a warning.

    `sidestore_files` (the `manifest.SidestoreFiles` of the snapshot) limits
    the read to the files of the devices of the run. The store holds a file
    for every device of every run that it kept. With None, the function reads
    every file of the 2 tables."""
    from hst.core import sidestore

    cts = collection_ts
    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    addresses = session.run(FETCH_SDWAN_ADDRESSES, cts=cts).data()
    if not addresses or sidestore_dir is None:
        return {"rule": "cable-from-arp-port", "edges": 0, "unresolved": len(addresses), "shared": 0}
    # Only devices of the run answer for an address.
    in_run = {str(r["uid"]) for r in session.run(FETCH_RUN_DEVICES, cts=cts).data()}
    try:
        arp_sql = arp_rows_query([str(a["ip"]) for a in addresses], cts)
        if sidestore_files is None:
            found = sidestore.query(sidestore_dir, arp_sql)
        else:
            found = sidestore.query_files(sidestore_dir, arp_sql, "arp", sidestore_files.files("arp", in_run))
        arp_rows = [row for row in found if str(row["device_uid"]) in in_run]
        devices = sorted({str(r["device_uid"]) for r in arp_rows})
        mac_sql = mac_rows_query(devices, cts)
        if not devices:
            mac_rows = []
        elif sidestore_files is None:
            mac_rows = sidestore.query(sidestore_dir, mac_sql)
        else:
            mac_rows = sidestore.query_files(
                sidestore_dir, mac_sql, "mac", sidestore_files.files("mac", devices)
            )
    except Exception as exc:
        logger.warning("cable-from-arp-port: side store not read (%s: %s)", type(exc).__name__, exc)
        return {
            "rule": "cable-from-arp-port",
            "edges": 0,
            "not_evaluated": len(addresses),
            "warnings": [
                f"cable-from-arp-port: side store not read ({type(exc).__name__}); "
                f"{len(addresses)} edge address(es) not evaluated"
            ],
        }
    report = resolve_arp_cables(addresses, arp_rows, mac_rows)
    written = 0
    if report["edges"]:
        rows = session.run(
            ARP_CABLE_WRITE,
            edges=report["edges"],
            ts=ts,
            cts=cts,
            stated_cable_sources=STATED_CABLE_SOURCES,
        ).data()
        written = rows[0]["n"] if rows else 0
    return {
        "rule": "cable-from-arp-port",
        "edges": written,
        "unresolved": report["unresolved"],
        "shared": report["shared"],
    }
