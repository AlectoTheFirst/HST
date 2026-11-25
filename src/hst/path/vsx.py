"""VSX transit paths over warp and bridge edges."""

from __future__ import annotations

from typing import Any

import hst.path as path

# The loader writes an edge only between two nodes of the same run
# (core/loader.py rel_upsert_query). A path from the anchor of a run stays
# inside that run. QUERY has no run guard on the nodes and edges of the path.
QUERY = """
// VSX explicit transit: ON edges are deliberately not forwarding edges.
MATCH (a:Obj {uid: $start, collection_ts: $snap})
MATCH p=(a)-[:CONNECTED_TO|BRIDGED_TO|REALIZED_BY*1..16]-(z)-[owner:ON]->(d:Device)
WHERE (z:Interface OR ($target IS NOT NULL AND z:Port))
  AND NOT d:Retired AND NOT z:Retired AND owner._retired_at IS NULL
  AND all(n IN nodes(p) WHERE NOT n:Retired)
  AND all(r IN relationships(p) WHERE r._retired_at IS NULL)
  AND any(r IN relationships(p) WHERE r.source IN ['vsx-warp', 'vsx-bridge'])
  AND all(n IN nodes(p)[1..-1] WHERE NOT n:Interface OR n.vsx_kind IN ['bridge', 'virtual-switch'])
  AND NOT coalesce(z.vsx_kind,'') IN ['bridge', 'virtual-switch', 'management']
  AND ($target IS NULL OR z.uid = $target)
  AND ($ip IS NULL OR EXISTS {
    MATCH (z)-[h:HAS_IP]->(ip:IpAddress {ip: $ip}) WHERE h._retired_at IS NULL AND NOT ip:Retired
  })
WITH p, z, d
RETURN {
  if_uid: z.uid, if_name: z.name, dev_uid: d.uid, dev_name: coalesce(d.hostname,d.name,d.uid),
  firewall_instance_uid: z.firewall_instance_uid, vsid: z.vsid, vsx_kind: z.vsx_kind,
  vsx_cluster: z.vsx_cluster, vsx_state: z.vsx_state,
  anchor: head([(z)-[v:IN_VRF]->(vrf:VrfInstance) WHERE v._retired_at IS NULL | vrf.uid])
} AS target,
[n IN nodes(p) | {uid:n.uid, name:n.name, labels:labels(n), vsid:n.vsid, kind:n.vsx_kind,
  instance:n.firewall_instance_uid, cluster:n.vsx_cluster, state:n.vsx_state,
  device:head([(n)-[o:ON]->(device:Device) WHERE o._retired_at IS NULL | device.uid]),
  vlan:head([(n)-[b:BOUND_TO]->(vlan:VlanInstance) WHERE b._retired_at IS NULL | vlan.vid])}] AS nodes,
[r IN relationships(p) | {type:type(r), source:r.source}] AS edges
ORDER BY length(p), [n IN nodes(p)|n.uid] LIMIT 33
"""
# Each branch seeks on the composite (source, collection_ts) relationship index (core/db.py).
VSX_EDGES = """
WITH EXISTS {
  MATCH (:Obj {collection_ts: $snap})-[r:CONNECTED_TO]->()
  WHERE r.source = 'vsx-warp' AND r.collection_ts = $snap
    AND r._retired_at IS NULL
} OR EXISTS {
  MATCH (:Obj {collection_ts: $snap})-[r:BRIDGED_TO]->()
  WHERE r.source = 'vsx-bridge' AND r.collection_ts = $snap
    AND r._retired_at IS NULL
} AS present
WHERE present
RETURN present
"""
EGRESS = """
MATCH (i:Interface {uid:$u}) WHERE NOT i:Retired AND i:Obj AND i.collection_ts=$snap
RETURN i.kind AS kind, i.vsx_topology_complete AS complete
"""


def has_vsx_edges(session: Any) -> bool:
    """Whether the session's run holds a VSX warp or bridge edge.

    A pinned session runs this read once. CycleSession keeps the rows of each
    read by query and parameters. The run is the only parameter of this read.
    """
    return bool(path._read(session, VSX_EDGES))


def resolve(session: Any, start: str | None, ip: str | None, target: str | None = None):
    if not start:
        return None, [], None
    rows = path._read(session, QUERY, start=start, ip=ip, target=target) if has_vsx_edges(session) else []
    if len(rows) > 32:
        return None, [], "VSX transit path budget exceeded"
    paths = []
    for row in rows:
        nodes = row["nodes"]
        if any(n.get("cluster") and n.get("state") != "active" for n in nodes):
            continue
        if len({n["uid"] for n in nodes}) != len(nodes):
            continue
        tags = {n["vlan"] for n in nodes if n.get("vlan") is not None}
        if len(tags) > 1:
            continue
        paths.append(row)
    if paths:
        # Paths to one target that cross different BRIDGED_TO gates are different answers.
        signatures = {
            (
                p["target"]["if_uid"],
                tuple(
                    (p["nodes"][i]["uid"], p["nodes"][i + 1]["uid"])
                    for i, e in enumerate(p["edges"])
                    if e["type"] == "BRIDGED_TO"
                ),
            )
            for p in paths
        }
        if len(signatures) != 1:
            return None, [], "multiple VSX forwarding paths or bridge gate sequences"
        chosen = paths[0]
        crossings = []
        for index, edge in enumerate(chosen["edges"]):
            if edge["type"] == "BRIDGED_TO":
                crossings.append((chosen["nodes"][index], chosen["nodes"][index + 1]))
        return chosen["target"], crossings, None
    if rows:
        return None, [], "VSX transit lacks a compatible VLAN path through active contexts"
    egress = path._read_one(session, EGRESS, u=start)
    if egress and egress.get("kind") == "warp":
        return None, [], "warp egress has no unique observed forwarding path to the next context"
    return None, [], None
