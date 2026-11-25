"""GET /api/sites/graph returns the sites and the edges between them."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Iterator
from itertools import islice
from typing import Any

from fastapi import APIRouter, Depends, Request

from hst.app.auth import require_permission
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.core import uid as uidmod

router = APIRouter()
_session = dbmod.session  # Tests replace this name.

# Boundary pairs listed per edge before the rest collapse into the count.
SAMPLE_PAIRS = 50

# A connected prefix in one routing domain that is held at more sites than this
# is a shared segment, such as a DMVPN or mGRE tunnel subnet or a metro WAN. It is
# listed once in `shared_subnets` and draws no pair edges.
MAX_SUBNET_SITES = 32

# The tiers of the devices of a site (core/device_roles.py) and the kind of the
# graph Site (an Equinix site is `colo`) set the site marker on the network map.
_SITE_DEVICES = """
MATCH (d:Device:Obj)-[li:LOCATED_IN]->(s:Site)
WHERE d.collection_ts = $snap AND NOT d:Retired AND li._retired_at IS NULL
WITH s, d
RETURN s.code AS site, head(collect(DISTINCT s.kind)) AS kind, count(DISTINCT d) AS devices,
       collect(d.tier) AS tiers
"""

_CABLES = """
MATCH (p1:Port:Obj)-[c:CONNECTED_TO]->(p2:Port)
WHERE p1.collection_ts = $snap
  AND c._retired_at IS NULL AND NOT p1:Retired AND NOT p2:Retired
MATCH (p1)-[o1:ON]->(d1:Device), (p2)-[o2:ON]->(d2:Device)
WHERE o1._retired_at IS NULL AND o2._retired_at IS NULL AND NOT d1:Retired AND NOT d2:Retired
OPTIONAL MATCH (d1)-[l1:LOCATED_IN]->(s1:Site) WHERE l1._retired_at IS NULL
OPTIONAL MATCH (d2)-[l2:LOCATED_IN]->(s2:Site) WHERE l2._retired_at IS NULL
RETURN s1.code AS a_site, d1.uid AS a_dev, coalesce(d1.hostname, d1.uid) AS a_name, p1.name AS a_port,
       s2.code AS b_site, d2.uid AS b_dev, coalesce(d2.hostname, d2.uid) AS b_name, p2.name AS b_port,
       c.source AS source
"""

_CIRCUITS = """
MATCH (vc:VirtualCircuit:Obj)-[ea:A_END]->(fa:FabricPort), (vc)-[ez:Z_END]->(fz:FabricPort)
WHERE vc.collection_ts = $snap AND NOT vc:Retired
  AND ea._retired_at IS NULL AND ez._retired_at IS NULL AND NOT fa:Retired AND NOT fz:Retired
OPTIONAL MATCH (fa)-[la:LOCATED_IN]->(sa:Site) WHERE la._retired_at IS NULL
OPTIONAL MATCH (fz)-[lz:LOCATED_IN]->(sz:Site) WHERE lz._retired_at IS NULL
OPTIONAL MATCH (fa)-[ra:REALIZED_BY]->(pa:Port)-[oa:ON]->(da:Device)
WHERE ra._retired_at IS NULL AND oa._retired_at IS NULL
OPTIONAL MATCH (fz)-[rz:REALIZED_BY]->(pz:Port)-[oz:ON]->(dz:Device)
WHERE rz._retired_at IS NULL AND oz._retired_at IS NULL
RETURN vc.uid AS uid, vc.name AS name, vc.state AS state, vc.bandwidth_mbps AS bandwidth_mbps,
       sa.code AS a_site, fa.name AS a_fabric_port, ea.vlan_tag AS a_vlan,
       da.uid AS a_dev, coalesce(da.hostname, da.uid) AS a_name, pa.name AS a_port,
       sz.code AS b_site, fz.name AS b_fabric_port, ez.vlan_tag AS b_vlan,
       dz.uid AS b_dev, coalesce(dz.hostname, dz.uid) AS b_name, pz.name AS b_port
"""

# The query returns one row per tunnel end. An ENDPOINT points to an Interface
# (ON its device) or to an IpAddress (held by an Interface ON its device). The
# WITH folds the two cases into one device. A tunnel modeled from one side, such
# as a VeloCloud path with one ENDPOINT and TERMINATES_ON the far address, gets
# its far row from the address holder in the second or third arm. Python pairs
# the ends per tunnel. A tunnel with one end at a Zscaler DC has one row and is
# an exit. `pair` is `Tunnel.pair`, the key of the two directions of one overlay
# path, or the uid of the tunnel. `link_kind` is the kind of the WanLink (mpls,
# dia, lte) that holds the address of the near end.
_TUNNEL_ENDS = """
CALL {
  MATCH (t:Tunnel:Obj)-[e:ENDPOINT]->(x)
  WHERE t.collection_ts = $snap AND NOT t:Retired AND e._retired_at IS NULL
  OPTIONAL MATCH (x)-[o:ON]->(od:Device) WHERE o._retired_at IS NULL AND NOT od:Retired
  OPTIONAL MATCH (x)<-[h:HAS_IP]-(i:Interface)-[oi:ON]->(hd:Device)
  WHERE h._retired_at IS NULL AND oi._retired_at IS NULL AND NOT hd:Retired
  OPTIONAL MATCH (x)-[wh:HAS_IP]->(:IpAddress)<-[lh:HAS_IP]-(w:WanLink)
  WHERE wh._retired_at IS NULL AND lh._retired_at IS NULL AND NOT w:Retired
  RETURN t, x, coalesce(od, hd) AS d, w.kind AS link_kind, 'near' AS side
  UNION
  MATCH (t:Tunnel:Obj)-[tr:TERMINATES_ON]->(x:IpAddress)
  WHERE t.collection_ts = $snap AND NOT t:Retired AND tr._retired_at IS NULL
  MATCH (x)<-[h:HAS_IP]-(i:Interface)-[oi:ON]->(d:Device)
  WHERE h._retired_at IS NULL AND oi._retired_at IS NULL AND NOT d:Retired
  RETURN t, x, d, null AS link_kind, 'far' AS side
  UNION
  // an SD-WAN link's address after NAT: the far edge's WanLink holds it and
  // no interface does
  MATCH (t:Tunnel:Obj)-[tr:TERMINATES_ON]->(x:IpAddress)
  WHERE t.collection_ts = $snap AND NOT t:Retired AND tr._retired_at IS NULL
    AND NOT EXISTS { MATCH (x)<-[ih:HAS_IP]-(:Interface) WHERE ih._retired_at IS NULL }
  MATCH (x)<-[lh:HAS_IP]-(:WanLink)<-[hl:HAS_LINK]-(d:Device)
  WHERE lh._retired_at IS NULL AND hl._retired_at IS NULL AND NOT d:Retired
  RETURN t, x, d, null AS link_kind, 'far' AS side
}
WITH t, x, d, link_kind, side
WHERE d IS NOT NULL
OPTIONAL MATCH (d)-[l:LOCATED_IN]->(s:Site) WHERE l._retired_at IS NULL
RETURN t.uid AS uid, coalesce(t.pair, t.uid) AS pair, t.encap AS encap, t.state AS state,
       link_kind, side,
       s.code AS site, d.uid AS dev, coalesce(d.hostname, d.uid) AS name, coalesce(x.name, x.ip) AS end
"""

# The shared-segment read of the network map (routes/topology.py _SUBNETS) with
# the site of each member. `_subnet_edges` pairs the members across sites.
_SUBNET_MEMBERS = """
MATCH (i:Interface:Obj)-[o:ON]->(d:Device)
WHERE i.collection_ts = $snap
  AND NOT i:Retired AND NOT d:Retired AND o._retired_at IS NULL
MATCH (i)-[h:HAS_IP]->(ip:IpAddress)-[n:IN]->(pfx:Prefix)
WHERE h._retired_at IS NULL AND n._retired_at IS NULL
  AND NOT ip:Retired AND NOT pfx:Retired AND pfx.kind = 'connected'
OPTIONAL MATCH (i)-[iv:IN_VRF]->(vrf:VrfInstance) WHERE iv._retired_at IS NULL
OPTIONAL MATCH (vrf)-[m:MEMBER_OF]->(rd:RoutingDomain)
WHERE m._retired_at IS NULL AND coalesce(m.basis, 'declared') = 'declared'
OPTIONAL MATCH (d)-[l:LOCATED_IN]->(s:Site) WHERE l._retired_at IS NULL
RETURN s.code AS site, d.uid AS dev, coalesce(d.hostname, d.uid) AS name, i.name AS iface, ip.ip AS ip,
       pfx.cidr AS cidr, coalesce(vrf.name, 'default') AS vrf, rd.name AS domain
"""

# The device of a session owns the VRF of its routing process. A peer
# candidate is a device that holds the peer address on an interface in the same
# run. Each row holds the VRF and the declared routing domain of the session and
# of the holder interface. `reciprocal` is true when the holder runs a session
# back to an address of the session device with the ASNs reversed. This is the
# pairing test `bgp-peer-from-address` of the reasoner. `_bgp_peers` picks one
# holder per session from the rows.
_BGP = """
MATCH (rp:RoutingProcess)-[hs:HAS]->(bs:BgpSession:Obj)
WHERE bs.collection_ts = $snap AND NOT bs:Retired AND NOT rp:Retired
  AND hs._retired_at IS NULL
MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance)-[ob:OWNED_BY]->(d:Device)
WHERE iv._retired_at IS NULL AND ob._retired_at IS NULL AND NOT d:Retired
OPTIONAL MATCH (v)-[vm:MEMBER_OF]->(rd:RoutingDomain)
WHERE vm._retired_at IS NULL AND coalesce(vm.basis, 'declared') = 'declared'
MATCH (pi:IpAddress:Obj {collection_ts: $snap, ip: bs.peer_ip})<-[hi:HAS_IP]-(pif:Interface)
      -[oi:ON]->(pd:Device)
WHERE hi._retired_at IS NULL AND oi._retired_at IS NULL AND NOT pd:Retired AND pd <> d
OPTIONAL MATCH (pif)-[pv:IN_VRF]->(pvrf:VrfInstance) WHERE pv._retired_at IS NULL
OPTIONAL MATCH (pvrf)-[pm:MEMBER_OF]->(prd:RoutingDomain)
WHERE pm._retired_at IS NULL AND coalesce(pm.basis, 'declared') = 'declared'
OPTIONAL MATCH (d)-[l1:LOCATED_IN]->(s1:Site) WHERE l1._retired_at IS NULL
OPTIONAL MATCH (pd)-[l2:LOCATED_IN]->(s2:Site) WHERE l2._retired_at IS NULL
WITH bs, v, rd, pvrf, prd, s1, s2, d, pd,
     EXISTS {
       MATCH (pd)<-[ob2:OWNED_BY]-(:VrfInstance)<-[iv2:IN_VRF]-(rp2:RoutingProcess)
             -[hs2:HAS]->(sb:BgpSession:Obj {collection_ts: $snap})
       WHERE ob2._retired_at IS NULL AND iv2._retired_at IS NULL AND hs2._retired_at IS NULL
         AND NOT rp2:Retired AND NOT sb:Retired
         AND sb.peer_asn = bs.local_asn AND sb.local_asn = bs.peer_asn
         AND EXISTS {
           MATCH (d)<-[oa:ON]-(:Interface)-[ha:HAS_IP]->(ia:IpAddress:Obj)
           WHERE ia.collection_ts = $snap AND ia.ip = sb.peer_ip
             AND oa._retired_at IS NULL AND ha._retired_at IS NULL
         }
     } AS reciprocal
RETURN bs.uid AS uid, bs.state AS state, bs.kind AS kind, reciprocal,
       v.uid AS a_vrf, rd.name AS a_domain, pvrf.uid AS b_vrf, prd.name AS b_domain,
       s1.code AS a_site, d.uid AS a_dev, coalesce(d.hostname, d.uid) AS a_name,
       bs.local_ip AS a_ip, bs.local_asn AS a_asn,
       s2.code AS b_site, pd.uid AS b_dev, coalesce(pd.hostname, pd.uid) AS b_name,
       bs.peer_ip AS b_ip, bs.peer_asn AS b_asn
"""

_WAN = """
MATCH (d:Device)-[hl:HAS_LINK]->(w:WanLink:Obj)
WHERE w.collection_ts = $snap AND NOT w:Retired AND NOT d:Retired
  AND hl._retired_at IS NULL
OPTIONAL MATCH (d)-[l:LOCATED_IN]->(s:Site) WHERE l._retired_at IS NULL
RETURN s.code AS site, d.uid AS dev, coalesce(d.hostname, d.uid) AS name,
       w.kind AS kind, w.carrier AS carrier, w.bandwidth_mbps AS bandwidth_mbps
"""


class _Edges:
    """The (site A, site B, kind) buckets and the unplaced counts per site.

    The two sites of a pair are sorted, so FR2-FR6 and FR6-FR2 are one edge. A
    row with one site missing counts against the site it has. A row with no
    site is dropped. A row with the same site at both ends is not an edge.
    """

    def __init__(self) -> None:
        # A bucket keeps its count and the first SAMPLE_PAIRS pairs.
        self.buckets: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "pairs": []}
        )
        self.unplaced: dict[tuple[str, str], int] = defaultdict(int)

    def add(self, kind: str, a_site: str | None, b_site: str | None, pair: dict[str, Any]) -> None:
        if a_site is None or b_site is None:
            placed = a_site if a_site is not None else b_site
            if placed is None:
                return
            self.unplaced[(placed, kind)] += 1
            return
        if a_site == b_site:
            return
        if a_site > b_site:
            a_site, b_site = b_site, a_site
            pair = _flipped(pair)
        bucket = self.buckets[(a_site, b_site, kind)]
        bucket["count"] += 1
        if len(bucket["pairs"]) < SAMPLE_PAIRS:
            bucket["pairs"].append(pair)

    def add_counted(
        self, kind: str, a_site: str, b_site: str, count: int, pairs: Iterator[dict[str, Any]]
    ) -> None:
        """Add `count` pairs between two placed sites. `a_site` sorts before
        `b_site`, and each pair is in that order. Only the sample is read from
        `pairs`."""
        if count <= 0:
            return
        bucket = self.buckets[(a_site, b_site, kind)]
        bucket["count"] += count
        bucket["pairs"].extend(islice(pairs, SAMPLE_PAIRS - len(bucket["pairs"])))

    def edges(self) -> list[dict[str, Any]]:
        return [
            {"a": a, "b": b, "kind": kind, "count": bucket["count"], "pairs": bucket["pairs"]}
            for (a, b, kind), bucket in sorted(self.buckets.items())
        ]

    def unplaced_rows(self) -> list[dict[str, Any]]:
        return [{"site": site, "kind": kind, "count": n} for (site, kind), n in sorted(self.unplaced.items())]


def _flipped(pair: dict[str, Any]) -> dict[str, Any]:
    """Swap the a_ and b_ fields so the pair reads in the sorted site order."""
    out = {}
    for key, value in pair.items():
        if key.startswith("a_"):
            out["b_" + key[2:]] = value
        elif key.startswith("b_"):
            out["a_" + key[2:]] = value
        else:
            out[key] = value
    return out


def _tunnel_pairs(rows: list[dict[str, Any]]) -> list[tuple[str | None, str | None, dict[str, Any]]]:
    """Every pair of distinct devices on one tunnel, with their sites. The two
    directions of one overlay path (two `Tunnel` nodes with the same `pair`) fold
    into one line. The line holds the first WAN link kind in uid order and the
    lowest tunnel uid of the path."""
    by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        # The WAN links of several edges can hold one address after NAT. A far
        # row counts only for the far edge in the tunnel uid.
        if r.get("side") == "far" and not uidmod.names_far_device(r["uid"], r.get("dev")):
            continue
        by_pair[r.get("pair") or r["uid"]].append(r)
    out = []
    for _pair, ends in sorted(by_pair.items()):
        uid = min(e["uid"] for e in ends)
        link_kind = next(
            (e["link_kind"] for e in sorted(ends, key=lambda e: e["uid"]) if e.get("link_kind")), None
        )
        # A near end wins over a far row for the same device. The near end has
        # the interface, and the far row has only the address.
        by_dev: dict[str, dict[str, Any]] = {}
        for e in sorted(ends, key=lambda e: (e["dev"], e.get("side") != "near", e["uid"])):
            by_dev.setdefault(e["dev"], e)
        distinct = sorted(by_dev.values(), key=lambda e: e["dev"])
        for i in range(len(distinct)):
            for j in range(i + 1, len(distinct)):
                a, b = distinct[i], distinct[j]
                out.append(
                    (
                        a["site"],
                        b["site"],
                        {
                            "uid": uid,
                            "encap": a["encap"],
                            "state": a["state"],
                            "link_kind": link_kind,
                            "a_dev": a["dev"],
                            "a_name": a["name"],
                            "a_end": a["end"],
                            "b_dev": b["dev"],
                            "b_name": b["name"],
                            "b_end": b["end"],
                        },
                    )
                )
    return out


def _subnet_pair(a: dict[str, Any], b: dict[str, Any], cidr: str) -> dict[str, Any]:
    return {
        "cidr": cidr,
        "vrf": a["vrf"],
        "domain": a.get("domain"),
        "a_dev": a["dev"],
        "a_name": a["name"],
        "a_iface": a["iface"],
        "a_ip": a["ip"],
        "b_dev": b["dev"],
        "b_name": b["name"],
        "b_iface": b["iface"],
        "b_ip": b["ip"],
    }


def _cross_pairs(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> int:
    """How many (a member, b member) pairs sit on two distinct devices."""
    on_a: dict[str, int] = defaultdict(int)
    for m in a:
        on_a[m["dev"]] += 1
    return len(a) * len(b) - sum(on_a.get(m["dev"], 0) for m in b)


def _subnet_edges(rows: list[dict[str, Any]], edges: _Edges) -> list[dict[str, Any]]:
    """Add the pairs of distinct devices on one connected prefix in one routing
    domain to `edges`, counted per pair of sites. The domain key is the VRF name
    when the graph has no declared RoutingDomain, as on the device map.

    A prefix held at more than `MAX_SUBNET_SITES` sites is a shared segment. It
    draws no pair edge and returns as one record for `shared_subnets`. A member
    with no site counts against each placed site of its prefix, as `_Edges.add`
    counts a row with one site missing."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[(r.get("domain") or r["vrf"], r["cidr"])].append(r)
    shared = []
    for (domain, cidr), members in sorted(groups.items()):
        by_site: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
        for m in sorted(members, key=lambda m: (m["dev"], m["iface"] or "", m["ip"])):
            by_site[m["site"]].append(m)
        placed = sorted(site for site in by_site if site is not None)
        unplaced = by_site.get(None, [])
        for site in placed:
            edges.unplaced[(site, "l3")] += _cross_pairs(by_site[site], unplaced)
        if len(placed) > MAX_SUBNET_SITES:
            shared.append({"cidr": cidr, "domain": domain, "sites": len(placed), "members": len(members)})
            continue
        for i, a_site in enumerate(placed):
            for b_site in placed[i + 1 :]:
                a, b = by_site[a_site], by_site[b_site]
                edges.add_counted(
                    "l3",
                    a_site,
                    b_site,
                    _cross_pairs(a, b),
                    (_subnet_pair(x, y, cidr) for x in a for y in b if x["dev"] != y["dev"]),
                )
    return shared


def _bgp_peers(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One peer row per session, and the sessions left out as ambiguous.

    Several devices can hold the peer address, for example with overlapping
    ranges, an address in two VRFs, or a reused 169.254 or hand-off address. A
    holder is kept when it holds the address in the VRF of the session or in a
    VRF of the same declared routing domain, or when `reciprocal` is true. The
    rule applies to a sole holder too. If one device remains, it is the peer.
    Otherwise the session is skipped and counted against its site."""
    by_session: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        by_session[r["uid"]][r["b_dev"]].append(r)
    peers: list[dict[str, Any]] = []
    ambiguous: dict[str, int] = defaultdict(int)
    for _uid, holders in sorted(by_session.items()):
        chosen = [
            dev
            for dev in holders
            if any(
                r.get("reciprocal")
                or (r.get("a_vrf") is not None and r.get("b_vrf") == r.get("a_vrf"))
                or (r.get("a_domain") is not None and r.get("b_domain") == r.get("a_domain"))
                for r in holders[dev]
            )
        ]
        if len(chosen) != 1:
            first = next(iter(holders.values()))[0]
            if first["a_site"] is not None:
                ambiguous[first["a_site"]] += 1
            continue
        peers.append(holders[chosen[0]][0])
    return peers, dict(ambiguous)


def _read_graph(settings: Any) -> dict[str, Any]:
    with _session(settings) as s:
        resolved = snapshotmod.resolve(s, settings)
        snap = snapshotmod.snap_param(resolved.cts)
        return {
            "devices": s.run(_SITE_DEVICES, snap=snap).data(),
            "cables": s.run(_CABLES, snap=snap).data(),
            "circuits": s.run(_CIRCUITS, snap=snap).data(),
            "tunnel_ends": s.run(_TUNNEL_ENDS, snap=snap).data(),
            "subnet_members": s.run(_SUBNET_MEMBERS, snap=snap).data(),
            "bgp": s.run(_BGP, snap=snap).data(),
            "wan": s.run(_WAN, snap=snap).data(),
        }


def _fold_sites(graph: dict[str, Any], codes: list[str]) -> None:
    """Name each graph Site by the stored site code for its uid. A graph Site
    keeps the code of its writer, for example `FR5` from a collector for the
    stored site `fr5`. A code is case-sensitive, so the match uses the uid."""
    stored = {uidmod.site(code): code for code in codes}
    for rows in graph.values():
        for r in rows:
            for field in ("site", "a_site", "b_site"):
                if r.get(field) is not None:
                    r[field] = stored.get(uidmod.site(r[field]), r[field])


def _assemble(graph: dict[str, Any], rows: list[Any]) -> dict[str, Any]:
    _fold_sites(graph, [site.code for site in rows])

    edges = _Edges()
    for r in graph["cables"]:
        edges.add("cable", r["a_site"], r["b_site"], {k: v for k, v in r.items() if not k.endswith("_site")})
    for r in graph["circuits"]:
        edges.add(
            "circuit", r["a_site"], r["b_site"], {k: v for k, v in r.items() if not k.endswith("_site")}
        )
    for a_site, b_site, pair in _tunnel_pairs(graph["tunnel_ends"]):
        edges.add("tunnel", a_site, b_site, pair)
    shared_subnets = _subnet_edges(graph["subnet_members"], edges)
    peers, ambiguous = _bgp_peers(graph["bgp"])
    for r in peers:
        edges.add("bgp", r["a_site"], r["b_site"], {k: v for k, v in r.items() if not k.endswith("_site")})

    devices = {r["site"]: r["devices"] for r in graph["devices"]}
    kinds = {r["site"]: r.get("kind") for r in graph["devices"]}
    tiers: dict[str, dict[str, int]] = {}
    for r in graph["devices"]:
        counts: dict[str, int] = defaultdict(int)
        for tier in r.get("tiers") or []:
            if tier:
                counts[tier] += 1
        tiers[r["site"]] = dict(sorted(counts.items()))
    exits: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in graph["wan"]:
        if r["site"] is not None:
            exits[r["site"]].append({k: v for k, v in r.items() if k != "site"})

    sites = [
        {
            "code": site.code,
            "name": site.name,
            "lat": (site.params or {}).get("lat"),
            "lon": (site.params or {}).get("lon"),
            "devices": devices.get(site.code, 0),
            "kind": kinds.get(site.code),
            "tiers": tiers.get(site.code, {}),
            "exits": exits.get(site.code, []),
        }
        for site in rows
    ]
    return {
        "sites": sites,
        "edges": edges.edges(),
        "unplaced": edges.unplaced_rows(),
        "shared_subnets": shared_subnets,
        "ambiguous": [{"site": site, "kind": "bgp", "count": n} for site, n in sorted(ambiguous.items())],
    }


@router.get("/sites/graph", dependencies=[Depends(require_permission("graph.read"))])
async def get_site_graph(request: Request) -> dict[str, Any]:
    store = request.app.state.store
    rows = await store.list_sites()
    graph = await asyncio.to_thread(_read_graph, request.app.state.settings)
    return await asyncio.to_thread(_assemble, graph, rows)
