"""The vlan-stretch check."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hst.core.normalize import iface_slug
from hst.reasoner._constants import ACTIVE_CIRCUIT_STATES

if TYPE_CHECKING:
    from hst.core.manifest import SidestoreFiles

logger = logging.getLogger(__name__)

# The check finds the VLANs that a Fabric circuit stretches. It writes no
# graph edge.
#
# The Fabric API states the link protocol and the tag per side of each
# circuit. `collectors/equinix.py` writes them on the A_END and Z_END edges.
# The trunk membership `(Port)-[:CARRIES]->(VlanInstance)` of the device
# collectors states the VLANs that a switch port carries. VLAN v at site A is
# stretched to site B when a circuit binds a device port at A with tag X to a
# device port at B with tag Y, the port at A carries v = X, and the port at B
# carries Y. The default single-fabric BridgeDomain identity
# (`uid.bridge_domain`) is correct when X, Y and v are equal. It is wrong in 2
# cases. In a translated pair, X and Y differ, and the identity per VLAN id
# does not join them. A VLAN id at 2 sites without a circuit is 2 separate
# domains, and the default merges them. A cabled trunk between 2 sites also
# joins its 2 sites for every VLAN id that both of its ports carry
# (`cable_joins`). Such a trunk is a metro link, a `CONNECTED_TO` with a
# source other than the source that `cable-from-fabric-circuit` writes per
# circuit.

STRETCHED = "stretched"
TRANSLATED = "translated"
ONE_SIDED = "one-sided"
PORT_BASED = "port-based"
STRETCH_KINDS = (STRETCHED, TRANSLATED, ONE_SIDED, PORT_BASED)

# Every circuit whose 2 ends realize a device Port, with the tags per side
# and the site of each device. A Network Edge device link has no tag per side
# and is left out. A device can have more than one LOCATED_IN row (a
# collected Site beside a Meta Site of the operator under one uid). The query
# reduces the site to one value per end.
FETCH_BOUND_CIRCUITS = """
MATCH (vc:VirtualCircuit:Obj)-[ae:A_END]->(fa)-[ra:REALIZED_BY]->(a:Port)-[oa:ON]->(da:Device)
WHERE (fa:FabricPort OR fa:Interface) AND coalesce(vc.type, '') <> 'DEVICE_LINK'
  AND NOT vc:Retired AND NOT fa:Retired AND NOT a:Retired AND NOT da:Retired
  AND ae._retired_at IS NULL AND ra._retired_at IS NULL AND oa._retired_at IS NULL
  AND vc.collection_ts = $cts
  AND a.collection_ts = $cts
  AND toUpper(coalesce(vc.state, '')) IN $active_circuit_states
MATCH (vc)-[ze:Z_END]->(fz)-[rz:REALIZED_BY]->(z:Port)-[oz:ON]->(dz:Device)
WHERE (fz:FabricPort OR fz:Interface)
  AND NOT fz:Retired AND NOT z:Retired AND NOT dz:Retired
  AND ze._retired_at IS NULL AND rz._retired_at IS NULL AND oz._retired_at IS NULL
  AND z.collection_ts = $cts
  AND a.uid <> z.uid
OPTIONAL MATCH (da)-[la:LOCATED_IN]->(sa:Site) WHERE la._retired_at IS NULL
OPTIONAL MATCH (dz)-[lz:LOCATED_IN]->(sz:Site) WHERE lz._retired_at IS NULL
RETURN vc.uid AS circuit,
       ae.vlan_tag AS tag_a, ae.link_protocol AS protocol_a,
       ze.vlan_tag AS tag_z, ze.link_protocol AS protocol_z,
       a.uid AS port_a, z.uid AS port_z, da.uid AS device_a, dz.uid AS device_z,
       head(collect(DISTINCT coalesce(sa.code, sa.uid))) AS site_a,
       head(collect(DISTINCT coalesce(sz.code, sz.uid))) AS site_z
"""

# Every CARRIES edge from a Port to a VlanInstance in the run. The
# bridge-domain audit of `core/reasoner.py` reads the same edges.
FETCH_CARRIAGE = """
MATCH (p:Port:Obj)-[c:CARRIES]->(v:VlanInstance)
WHERE NOT p:Retired AND NOT v:Retired AND c._retired_at IS NULL
  AND p.collection_ts = $cts
RETURN p.uid AS port_uid, v.vid AS vid
"""

# Every link between 2 device ports in the run, with its source and the site
# of the device of each port. The site is reduced to one value per end, as in
# `FETCH_BOUND_CIRCUITS`. The query has the filters of
# `PORT_LINKS_AT_CYCLE_QUERY` in `core/reasoner.py` (no retired edges, one row
# per port pair and source).
FETCH_PORT_LINKS = """
MATCH (a:Port:Obj)-[l:CONNECTED_TO]-(b:Port)
WHERE a.collection_ts = $cts
  AND NOT a:Retired AND NOT b:Retired AND l._retired_at IS NULL AND a.uid < b.uid
MATCH (a)-[oa:ON]->(da:Device), (b)-[ob:ON]->(db:Device)
WHERE oa._retired_at IS NULL AND ob._retired_at IS NULL AND NOT da:Retired AND NOT db:Retired
OPTIONAL MATCH (da)-[la:LOCATED_IN]->(sa:Site) WHERE la._retired_at IS NULL
OPTIONAL MATCH (db)-[lb:LOCATED_IN]->(sb:Site) WHERE lb._retired_at IS NULL
RETURN a.uid AS a, b.uid AS z, l.source AS source,
       head(collect(DISTINCT coalesce(sa.code, sa.uid))) AS site_a,
       head(collect(DISTINCT coalesce(sb.code, sb.uid))) AS site_z
"""

# The source that `cable-from-fabric-circuit` (reasoner/catalog.py) writes on
# the link of each Fabric circuit. Such a link carries only the tag of its
# circuit. `cable_joins` does not count it as a cable.
CIRCUIT_LINK_SOURCE = "equinix-circuit"


# The sites where each BridgeDomain has a VlanInstance, through the ports and
# SVIs that carry or bind the VLAN on a device with a site.
FETCH_VLAN_SITES = """
MATCH (v:VlanInstance:Obj)-[rz:REALIZES]->(bd:BridgeDomain)
WHERE NOT v:Retired AND NOT bd:Retired AND rz._retired_at IS NULL
  AND v.collection_ts = $cts
MATCH (v)<-[m:CARRIES|BOUND_TO]-(x)-[o:ON]->(d:Device)-[l:LOCATED_IN]->(s:Site)
WHERE m._retired_at IS NULL AND o._retired_at IS NULL AND l._retired_at IS NULL
  AND NOT x:Retired AND NOT d:Retired AND NOT s:Retired
RETURN DISTINCT bd.uid AS bridge_domain, v.vid AS vid, coalesce(s.code, s.uid) AS site
"""

# A FabricPort whose operator binding points to a device port that is not in
# this run. The loader dropped the REALIZED_BY edge, and
# `cable-from-fabric-circuit` writes no link for it. The check reports the
# binding.
FETCH_UNBOUND_FABRIC_PORTS = """
MATCH (fp:FabricPort:Obj)
WHERE fp.bound_port_uid IS NOT NULL AND NOT fp:Retired
  AND fp.collection_ts = $cts
  AND NOT EXISTS {
    MATCH (fp)-[r:REALIZED_BY]->(p:Port)
    WHERE r._retired_at IS NULL AND NOT p:Retired
  }
RETURN fp.uid AS fabric_port, fp.bound_port_uid AS port_uid
ORDER BY fp.uid
"""


def _port_slug(port_uid: str) -> str:
    """The name slug of a `<device uid>/port/<slug>` uid. `MacIndex` compares
    it with the `iface_slug` of a side-store `port_name`."""
    return port_uid.rsplit("/port/", 1)[-1]


def _carried_by_port(carriage: list[dict[str, Any]]) -> dict[str, set[int]]:
    """The VLAN ids each port carries, from `FETCH_CARRIAGE` rows."""
    carried: dict[str, set[int]] = {}
    for row in carriage:
        if row.get("vid") is None:
            continue
        carried.setdefault(row["port_uid"], set()).add(int(row["vid"]))
    return carried


def _observation(
    circuit: dict[str, Any], *, vid: int, vid_z: int, kind: str, tag_a: Any, tag_z: Any
) -> dict[str, Any]:
    return {
        "circuit": circuit["circuit"],
        "kind": kind,
        "vid": vid,
        "vid_z": vid_z,
        "tag_a": tag_a,
        "tag_z": tag_z,
        "port_a": circuit["port_a"],
        "port_z": circuit["port_z"],
        "device_a": circuit.get("device_a"),
        "device_z": circuit.get("device_z"),
        "site_a": circuit.get("site_a"),
        "site_z": circuit.get("site_z"),
        "observed_macs": None,
    }


def stretch_observations(
    circuits: list[dict[str, Any]], carriage: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """One observation per VLAN id per bound circuit, from the rows of
    `FETCH_BOUND_CIRCUITS` and `FETCH_CARRIAGE`, and the count of tagged
    circuits whose tag neither device port carries. The function is pure.

    The kind of an observation is one of these.

    - `stretched` when the tag is the same on both sides and both ports
      carry it.
    - `translated` when the 2 sides have different tags and each port
      carries the tag of its side.
    - `one-sided` when only one of the 2 ports carries the tag of its side.
    - `port-based` for an untagged circuit, once per VLAN id that both ports
      carry. A VLAN id that only one end of an untagged circuit carries is
      `one-sided`.

    A side with no tag on a tagged circuit takes the tag of the other side.
    `vid` is the VLAN id on the A side and `vid_z` is the id on the Z side.
    They differ only on a translated pair.
    """
    carried = _carried_by_port(carriage)
    observations: list[dict[str, Any]] = []
    uncarried = 0
    for circuit in sorted(circuits, key=lambda c: c["circuit"]):
        in_a = carried.get(circuit["port_a"], set())
        in_z = carried.get(circuit["port_z"], set())
        tag_a, tag_z = circuit.get("tag_a"), circuit.get("tag_z")
        protocols = {str(circuit.get(k) or "").lower() for k in ("protocol_a", "protocol_z")}
        untagged = "untagged" in protocols or (tag_a is None and tag_z is None)
        if untagged:
            for vid in sorted(in_a | in_z):
                kind = PORT_BASED if vid in in_a and vid in in_z else ONE_SIDED
                observations.append(
                    _observation(circuit, vid=vid, vid_z=vid, kind=kind, tag_a=None, tag_z=None)
                )
            continue
        stated = [int(t) for t in (tag_a, tag_z) if t is not None]
        x = int(tag_a) if tag_a is not None else stated[0]
        y = int(tag_z) if tag_z is not None else stated[0]
        carried_a, carried_z = x in in_a, y in in_z
        if not carried_a and not carried_z:
            uncarried += 1
            continue
        if not (carried_a and carried_z):
            kind = ONE_SIDED
        elif x == y:
            kind = STRETCHED
        else:
            kind = TRANSLATED
        observations.append(_observation(circuit, vid=x, vid_z=y, kind=kind, tag_a=x, tag_z=y))
    return observations, uncarried


def cable_joins(links: list[dict[str, Any]], carriage: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The site pairs that each cabled link joins, from `FETCH_PORT_LINKS` and
    `FETCH_CARRIAGE` rows. The result has one row (`vid`, `site_a`, `site_z`)
    per VLAN id that both ports of a link carry. The rows are sorted and have
    no duplicates. The function is pure.

    A link joins nothing in these cases.

    - Its ports carry no VLAN id in common.
    - A site is unknown, or both ends are at one site.
    - It has no source (no collector or rule asserted the edge).
    - It runs between the 2 ports of a Fabric circuit. This case covers the
      link of `cable-from-fabric-circuit` (`CIRCUIT_LINK_SOURCE`) and any
      other link on the same port pair, such as an LLDP neighbour seen
      through the circuit.
    """
    carried = _carried_by_port(carriage)
    circuit_pairs = {frozenset((x["a"], x["z"])) for x in links if x.get("source") == CIRCUIT_LINK_SOURCE}
    joins: set[tuple[int, str, str]] = set()
    for link in links:
        if not link.get("source") or frozenset((link["a"], link["z"])) in circuit_pairs:
            continue
        site_a, site_z = link.get("site_a"), link.get("site_z")
        if not site_a or not site_z or site_a == site_z:
            continue
        for vid in carried.get(link["a"], set()) & carried.get(link["z"], set()):
            joins.add((vid, str(site_a), str(site_z)))
    return [{"vid": v, "site_a": a, "site_z": z} for v, a, z in sorted(joins)]


class _SiteUnion:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _components(sites: set[str], union: _SiteUnion | None) -> str:
    """The sites of one domain in joined groups, as `fr2+fr6 | pa3 | pa4`.
    Each group is sorted, and the groups are in the order of their sorted
    members."""
    groups: dict[str, list[str]] = {}
    for site in sorted(sites):
        groups.setdefault(union.find(site) if union is not None else site, []).append(site)
    return " | ".join("+".join(g) for g in sorted(groups.values()))


def stretch_warnings(
    observations: list[dict[str, Any]],
    vlan_sites: list[dict[str, Any]],
    cable_joins: list[dict[str, Any]] | None = None,
) -> list[str]:
    """The warnings for the 2 cases where the default single-fabric identity
    is wrong. The function is pure.

    A `translated` observation gives a warning that the twin keeps the 2
    VLAN ids separate. A BridgeDomain with VlanInstances at 2 or more sites
    gives a warning when those sites are not all joined for that VLAN id. The
    join is transitive (3 sites joined by 2 circuits are one domain). A
    `stretched` or `port-based` observation joins its 2 sites. Each
    `cable_joins` row (`vid`, `site_a`, `site_z`) joins its 2 sites for its
    VLAN id. An observation with an unknown site joins nothing. The warning
    lists the groups of joined sites (`joined: fr2+fr6 | pa3 | pa4`). The
    result is sorted.
    """
    warnings: list[str] = []
    for o in observations:
        if o["kind"] == TRANSLATED:
            warnings.append(
                f"vlan {o['tag_a']} at {o.get('site_a') or o['port_a']} is vlan {o['tag_z']} "
                f"at {o.get('site_z') or o['port_z']}; the twin keeps them separate"
            )
    joined: dict[int, _SiteUnion] = {}
    for o in observations:
        if o["kind"] in (STRETCHED, PORT_BASED) and o.get("site_a") and o.get("site_z"):
            joined.setdefault(int(o["vid"]), _SiteUnion()).union(str(o["site_a"]), str(o["site_z"]))
    for join in cable_joins or []:
        joined.setdefault(int(join["vid"]), _SiteUnion()).union(str(join["site_a"]), str(join["site_z"]))
    sites_by_domain: dict[tuple[str, int], set[str]] = {}
    for row in vlan_sites:
        if row.get("vid") is None or not row.get("site"):
            continue
        sites_by_domain.setdefault((row["bridge_domain"], int(row["vid"])), set()).add(str(row["site"]))
    for (_domain, vid), sites in sorted(sites_by_domain.items()):
        if len(sites) < 2:
            continue
        union = joined.get(vid)
        roots = {union.find(s) for s in sites} if union is not None else set(sites)
        if len(roots) > 1:
            where = ", ".join(sorted(sites))
            warnings.append(
                f"vlan {vid} exists at {where} in one bridge domain but no circuit or link carries it "
                f"(joined: {_components(sites, union)})"
            )
    return sorted(warnings)


class MacIndex:
    """An index of side-store `mac` rows (`device_uid`, `vlan`, `mac`,
    `port_name`) for `observed_mac_count`.

    Per device uid and VLAN id, the index holds the lowercased MACs of each
    port. The key of a port is the slug of its name (`iface_slug`). The MACs
    of rows without a port name are under the key None. A row with no MAC is
    left out."""

    def __init__(self, mac_rows: list[dict[str, Any]]) -> None:
        self._ports: dict[tuple[Any, Any], dict[str | None, set[str]]] = {}
        for row in mac_rows:
            if not row.get("mac"):
                continue
            name = row.get("port_name")
            port = iface_slug(str(name)) if name else None
            by_port = self._ports.setdefault((row.get("device_uid"), row.get("vlan")), {})
            by_port.setdefault(port, set()).add(str(row["mac"]).lower())

    def macs(self, device: Any, vid: int, port_uid: str, *, on_circuit_port: bool) -> set[str]:
        """The MACs that `device` saw in `vid`. With `on_circuit_port`, the
        result is the MACs on the port of `port_uid`. Without it, the result
        is the MACs on every other port and in the rows without a port name."""
        slug = _port_slug(port_uid)
        by_port = self._ports.get((device, vid), {})
        if on_circuit_port:
            return set(by_port.get(slug, ()))
        return {mac for port, seen in by_port.items() if port != slug for mac in seen}


def observed_mac_count(observation: dict[str, Any], mac_rows: list[dict[str, Any]] | MacIndex) -> int:
    """The count of MAC addresses that corroborate one observation. The
    function is pure.

    A MAC counts when it is seen in the VLAN of the observation on the
    circuit-facing port at one end and on another port at the other end, in
    either direction. A MAC seen at one site only does not count. `mac_rows`
    are side-store `mac` rows (`device_uid`, `vlan`, `mac`, `port_name`) or a
    `MacIndex` of them. A caller that counts more than one observation
    builds the `MacIndex` once. A `stretched` observation with 0 MACs is
    still stretched.
    """
    index = mac_rows if isinstance(mac_rows, MacIndex) else MacIndex(mac_rows)
    dev_a, dev_z = observation.get("device_a"), observation.get("device_z")
    vid, vid_z = int(observation["vid"]), int(observation["vid_z"])
    through_a = index.macs(dev_a, vid, observation["port_a"], on_circuit_port=True)
    local_z = index.macs(dev_z, vid_z, observation["port_z"], on_circuit_port=False)
    through_z = index.macs(dev_z, vid_z, observation["port_z"], on_circuit_port=True)
    local_a = index.macs(dev_a, vid, observation["port_a"], on_circuit_port=False)
    return len((through_a & local_z) | (through_z & local_a))


def mac_rows_query(device_uids: list[str], cts: int) -> str:
    """The DuckDB query for the newest `mac` rows at or before the run for the
    given devices. `sidestore.query` binds no parameters. The function quotes
    the uids and doubles a quote inside a uid."""
    quoted = ", ".join("'" + u.replace("'", "''") + "'" for u in sorted(set(device_uids)))
    # Every interpolated value is an int or a quoted uid with doubled quotes.
    # `sidestore.query` opens the store read-only.
    return (
        "SELECT device_uid, vlan, mac, port_name FROM mac "  # noqa: S608
        f"WHERE device_uid IN ({quoted}) AND snapshot_ts <= {int(cts)} "
        "AND snapshot_ts = (SELECT max(m2.snapshot_ts) FROM mac m2 "
        f"WHERE m2.device_uid = mac.device_uid AND m2.snapshot_ts <= {int(cts)})"
    )


def read_mac_rows(
    sidestore_dir: Path, device_uids: list[str], cts: int, files: SidestoreFiles | None = None
) -> list[dict[str, Any]]:
    """The side-store rows that `observed_mac_count` reads, or an empty list
    when the store query fails (no `mac` table, DuckDB not installed).

    With `files` (the `manifest.SidestoreFiles` of the snapshot), the read
    opens only the `mac` files of the given devices. Without `files`, it
    opens every `mac` file of the store."""
    from hst.core import sidestore

    if not device_uids:
        return []
    try:
        sql = mac_rows_query(device_uids, cts)
        if files is None:
            return sidestore.query(sidestore_dir, sql)
        return sidestore.query_files(sidestore_dir, sql, "mac", files.files("mac", device_uids))
    except Exception as exc:
        logger.warning("vlan-stretch: MAC corroboration skipped (%s: %s)", type(exc).__name__, exc)
        return []


def check_vlan_stretch(
    session: Any,
    *,
    collection_ts: int,
    sidestore_dir: Path | None = None,
    sidestore_files: SidestoreFiles | None = None,
) -> dict[str, Any]:
    """The `vlan-stretch` check over one run. It only reads and writes no edge.

    Returns `{"observations": [...], "warnings": [...], "unbound_ports":
    [...], "uncarried": n}`.

    - `observations` has one row per VLAN id per bound circuit
      (`stretch_observations`).
    - `warnings` has the warnings of `stretch_warnings` and one warning per
      refused port binding. `stretch_warnings` also counts the sites that
      the cabled links of `FETCH_PORT_LINKS` join (`cable_joins`).
    - `unbound_ports` has the refused port bindings.
    - `uncarried` is the count of tagged circuits whose tag neither device
      port carries.

    With a `sidestore_dir`, each `stretched`, `translated` or `port-based`
    observation gets its `observed_macs` count from the `mac` table.
    """

    def reads(tx: Any) -> tuple[list[dict[str, Any]], ...]:
        return (
            tx.run(
                FETCH_BOUND_CIRCUITS, cts=collection_ts, active_circuit_states=ACTIVE_CIRCUIT_STATES
            ).data(),
            tx.run(FETCH_CARRIAGE, cts=collection_ts).data(),
            tx.run(FETCH_VLAN_SITES, cts=collection_ts).data(),
            tx.run(FETCH_UNBOUND_FABRIC_PORTS, cts=collection_ts).data(),
            tx.run(FETCH_PORT_LINKS, cts=collection_ts).data(),
        )

    circuits, carriage, vlan_sites, unbound, links = session.execute_read(reads)
    observations, uncarried = stretch_observations(circuits, carriage)
    if sidestore_dir is not None and observations:
        devices = [str(d) for o in observations for d in (o.get("device_a"), o.get("device_z")) if d]
        if sidestore_files is None:
            mac_rows = read_mac_rows(sidestore_dir, devices, collection_ts)
        else:
            mac_rows = read_mac_rows(sidestore_dir, devices, collection_ts, sidestore_files)
        if mac_rows:
            index = MacIndex(mac_rows)
            del mac_rows
            for o in observations:
                if o["kind"] in (STRETCHED, TRANSLATED, PORT_BASED):
                    o["observed_macs"] = observed_mac_count(o, index)
    warnings = stretch_warnings(observations, vlan_sites, cable_joins(links, carriage))
    warnings.extend(
        f"equinix port binding refused: {row['fabric_port']} names port {row['port_uid']}, "
        "which is not in this run"
        for row in unbound
    )
    return {
        "observations": observations,
        "warnings": warnings,
        "unbound_ports": list(unbound),
        "uncarried": uncarried,
    }
