"""The hostname role step."""

from __future__ import annotations

import logging
from typing import Any

from hst.core import device_roles
from hst.core.loader import CHUNK

logger = logging.getLogger(__name__)

# The role step (core/device_roles.py). `role_reported` keeps the value the
# collector wrote. A carried device is classified from that value. `has_routing` is a
# routing-protocol adjacency on an interface of the device (OSPF) or a BGP
# session of a process in a table the device's interfaces are in.
FETCH_DEVICE_ROLES = """
MATCH (d:Device:Obj)
WHERE NOT d:Retired AND d.collection_ts = $cts
RETURN d.uid AS uid, d.hostname AS hostname, coalesce(d.role_reported, d.role) AS reported,
       EXISTS {
         MATCH (d)<-[o:ON]-(i:Interface)-[m:MEMBER_OF]->(g:FhrpGroup)
         WHERE NOT i:Retired AND NOT g:Retired
           AND o._retired_at IS NULL AND m._retired_at IS NULL
           AND i.collection_ts = $cts
       } AS has_fhrp,
       EXISTS {
         MATCH (d)<-[o:ON]-(i:Interface:Obj)<-[e:ENDPOINT]-(a:OspfAdjacency:Obj)
         WHERE NOT i:Retired AND NOT a:Retired
           AND o._retired_at IS NULL AND e._retired_at IS NULL
           AND i.collection_ts = $cts AND a.collection_ts = $cts
       } OR EXISTS {
         MATCH (d)<-[o:ON]-(i:Interface:Obj)-[iv:IN_VRF]->(v:VrfInstance:Obj)
               <-[pv:IN_VRF]-(rp:RoutingProcess:Obj)-[h:HAS]->(s:BgpSession:Obj)
         WHERE NOT i:Retired AND NOT v:Retired AND NOT rp:Retired AND NOT s:Retired
           AND o._retired_at IS NULL AND iv._retired_at IS NULL
           AND pv._retired_at IS NULL AND h._retired_at IS NULL
           AND i.collection_ts = $cts AND v.collection_ts = $cts
           AND rp.collection_ts = $cts AND s.collection_ts = $cts
       } AS has_routing
"""

SET_DEVICE_ROLES = """
UNWIND $rows AS row
MATCH (d:Device:Obj {uid: row.uid, collection_ts: $cts}) WHERE NOT d:Retired
SET d.role = row.role, d.role_reported = row.reported, d.role_basis = row.basis, d.tier = row.tier
"""


def apply_device_roles(session: Any, collection_ts: int, tokens: dict[str, str]) -> dict[str, Any]:
    """Set `role`, `role_basis` and `tier` on every Device of the run from its
    hostname (core/device_roles.py). Returns how many devices it classified,
    how many of them by each basis, and how many got a role other than the one
    their collector wrote.

    It runs before the rules. Each chunk of CHUNK devices is written in a
    transaction of its own."""

    def fetch(tx: Any) -> list[dict[str, Any]]:
        return tx.run(FETCH_DEVICE_ROLES, cts=collection_ts).data()

    def write(tx: Any, chunk: list[dict[str, Any]]) -> None:
        tx.run(SET_DEVICE_ROLES, rows=chunk, cts=collection_ts).consume()

    rows = []
    for device in session.execute_read(fetch):
        reported = device["reported"] or "unknown"
        c = device_roles.classify(
            device["hostname"], reported, bool(device["has_fhrp"]), tokens, bool(device.get("has_routing"))
        )
        rows.append(
            {"uid": device["uid"], "role": c.role, "reported": reported, "basis": c.basis, "tier": c.tier}
        )
    for i in range(0, len(rows), CHUNK):
        session.execute_write(lambda tx, chunk=rows[i : i + CHUNK]: write(tx, chunk))
    basis: dict[str, int] = {}
    for row in rows:
        basis[row["basis"]] = basis.get(row["basis"], 0) + 1
    changed = sum(1 for row in rows if row["role"] != row["reported"])
    logger.info("device-roles: %d device(s), %d took the role of their hostname", len(rows), changed)
    return {"devices": len(rows), "changed": changed, "basis": dict(sorted(basis.items()))}
