"""The reasoner derives route-target pairings and routing domains of VRFs, observed
broadcast-domain components and the speed of CONNECTED_TO links from the collected graph."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from neo4j import unit_of_work

from .config import Settings
from .l3domain import display_name
from .loader import load
from .model import Batch, NodeRecord, RelRecord, RunManifest
from .uid import routing_domain

# --- pure data shapes ----------------------------------------------------------------


@dataclass(frozen=True)
class RtPairing:
    """A directed pairing. `importer` receives the ORIGINATES prefixes of `exporter`.
    `exporter` exports a route target that `importer` imports. `via_rt` holds every
    such route target, sorted."""

    importer: str  # VrfInstance uid
    exporter: str  # VrfInstance uid
    via_rt: tuple[str, ...]


@dataclass(frozen=True)
class RtTopology:
    """The pairings and the components from one pass over the RT edges of the estate.
    `components` maps each VrfInstance uid with at least one IMPORTS or EXPORTS edge to
    the canonical id of its component, the lexicographically smallest member uid. The
    canonical id does not depend on the input order. `rts_by_vrf` holds every RT that
    each VRF imports or exports, sorted."""

    pairs: tuple[RtPairing, ...]
    components: dict[str, str]
    rts_by_vrf: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class DomainSplit:
    """One route-target-connected component whose members declare more than
    one domain. `hst audit domains` reports it."""

    rts: tuple[str, ...]
    members: tuple[tuple[str, str], ...]  # (vrf_uid, device_uid), sorted
    domains: tuple[str, ...]  # sorted, deduped declared-domain names


# --- pure functions --------------------------------------------------------------------


class _UnionFind:
    """Union-find over opaque string keys, path-compressed. The representative
    `find()` returns depends on call order."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for x in self._parent:
            out[self.find(x)].append(x)
        return out


def pair_and_group(rt_edges: Iterable[Mapping[str, Any]]) -> RtTopology:
    """Pair the VRFs by route target and group them into components. The function is
    pure. A row of `rt_edges` has the fields of a `RT_EDGES_AT_CYCLE_QUERY` row:
    `vrf_uid`, `kind` ("IMPORTS" or "EXPORTS") and `rt` (the value of the RouteTarget)."""
    exporters: dict[str, set[str]] = defaultdict(set)
    importers: dict[str, set[str]] = defaultdict(set)
    touched: dict[str, set[str]] = defaultdict(set)
    uf = _UnionFind()

    for row in rt_edges:
        vrf_uid, kind, rt = row["vrf_uid"], row["kind"], row["rt"]
        uf.find(vrf_uid)  # A VRF with no pairing also gets a component.
        touched[vrf_uid].add(rt)
        if kind == "EXPORTS":
            exporters[rt].add(vrf_uid)
        elif kind == "IMPORTS":
            importers[rt].add(vrf_uid)

    via: dict[tuple[str, str], set[str]] = defaultdict(set)
    for rt in sorted(set(exporters) | set(importers)):
        for exporter in sorted(exporters.get(rt, ())):
            for importer in sorted(importers.get(rt, ())):
                if importer == exporter:
                    continue
                via[(importer, exporter)].add(rt)
                uf.union(importer, exporter)

    pairs = tuple(
        RtPairing(importer=b, exporter=a, via_rt=tuple(sorted(rts))) for (b, a), rts in sorted(via.items())
    )
    components = {vrf_uid: min(members) for members in uf.groups().values() for vrf_uid in members}
    rts_by_vrf = {vrf_uid: tuple(sorted(rts)) for vrf_uid, rts in touched.items()}
    return RtTopology(pairs=pairs, components=components, rts_by_vrf=rts_by_vrf)


def build_rt_domains(topology: RtTopology) -> Batch:
    """Build a `Batch(source="reasoner", scope="derived:rt-domains")` of `RoutingDomain`
    nodes and `MEMBER_OF {basis: "rt-component"}` rels from `topology.components` (see
    `pair_and_group`). The function is pure. Only a component with 2 or more members
    produces a domain.

    The node uid is `uid.routing_domain("rt:" + canonical)`. `canonical` is the
    lexicographically smallest RT that a member of the component imports or exports
    (`topology.rts_by_vrf`).

    The rel key is the constant `{"basis": "rt-component"}`. The MERGE matches only a
    relationship with `basis: "rt-component"`.
    """
    groups: dict[str, list[str]] = defaultdict(list)
    for member_uid, canonical in topology.components.items():
        groups[canonical].append(member_uid)

    nodes: list[NodeRecord] = []
    rels: list[RelRecord] = []
    for canonical in sorted(groups):
        members = groups[canonical]
        if len(members) < 2:
            continue  # A component with one VRF gets no domain.
        # Each member of a component with 2 or more members has at least one RT
        # edge (`touched` in `pair_and_group`). `rts` is not empty.
        rts = sorted({rt for m in members for rt in topology.rts_by_vrf.get(m, ())})
        domain = "rt:" + rts[0]
        du = routing_domain(domain)
        nodes.append(
            NodeRecord(
                label="RoutingDomain",
                uid=du,
                props={"name": display_name(domain), "basis": "rt-component", "rts": ",".join(rts)},
            )
        )
        for member_uid in sorted(members):
            rels.append(
                RelRecord(
                    type="MEMBER_OF",
                    start_label="VrfInstance",
                    start_uid=member_uid,
                    end_label="RoutingDomain",
                    end_uid=du,
                    key={"basis": "rt-component"},
                    props={"basis": "rt-component", "rts": ",".join(rts)},
                )
            )
    return Batch(source="reasoner", scope="derived:rt-domains", nodes=nodes, rels=rels)


def _device_of(vrf_uid: str) -> str:
    """Return the device uid for display, parsed from a VrfInstance uid in the format
    of `core.uid.vrf()` (`vrf:<device_uid>:<name>`). A uid in another format is
    returned unchanged."""
    if not vrf_uid.startswith("vrf:"):
        return vrf_uid
    device_uid, sep, _name = vrf_uid[len("vrf:") :].rpartition(":")
    return device_uid if sep else vrf_uid


def find_domain_splits(topology: RtTopology, realizes: Iterable[Mapping[str, Any]]) -> list[DomainSplit]:
    """Return the components of `topology` (from `pair_and_group`) whose members
    declare more than one domain (see `DomainSplit`). The function is pure. A row of
    `realizes` has the fields of a `REALIZES_AT_CYCLE_QUERY` row: `vrf_uid` and
    `domain_name`."""
    domains_by_vrf: dict[str, set[str]] = defaultdict(set)
    for row in realizes:
        domains_by_vrf[row["vrf_uid"]].add(row["domain_name"])

    members_by_component: dict[str, set[str]] = defaultdict(set)
    for vrf_uid, canonical in topology.components.items():
        members_by_component[canonical].add(vrf_uid)

    splits = []
    for members in members_by_component.values():
        domains = {d for m in members for d in domains_by_vrf.get(m, ())}
        if len(domains) <= 1:
            continue
        rts = {rt for m in members for rt in topology.rts_by_vrf.get(m, ())}
        splits.append(
            DomainSplit(
                rts=tuple(sorted(rts)),
                members=tuple(sorted((m, _device_of(m)) for m in members)),
                domains=tuple(sorted(domains)),
            )
        )
    return sorted(splits, key=lambda s: s.members)


# --- graph access ------------------------------------------------------------------------
# Each query filters `NOT n:Retired` on every matched node and
# `rel._retired_at IS NULL` on every matched relationship, as in queries.py.

# Each read selects by the version key `collection_ts`. Inside
# `app/runs_exec.execute_cycle` the derivations run before the pointer moves.
RT_EDGES_AT_CYCLE_QUERY = """
MATCH (v:VrfInstance:Obj)-[r:IMPORTS|EXPORTS]->(rt:RouteTarget)
WHERE NOT v:Retired AND NOT rt:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $cts
  AND rt.collection_ts = $cts
RETURN v.uid AS vrf_uid, type(r) AS kind, rt.value AS rt
"""

# A Cypher fragment that matches the routes that `v` receives over route targets.
# The caller binds `$snap`, the run to read, and `v`, the importing VrfInstance. The
# fragment ends with `v`, `p` and `via_rt` in scope. `p` is an ORIGINATES prefix of
# another VRF that exports a route target that `v` imports. `via_rt` is the sorted,
# comma-joined list of every such route target. A caller that reads by prefix binds
# `p` and filters `v` after the fragment. The fragment follows one hop and excludes
# `v` itself. It filters retired objects and pins `rt`, `x` and `p` to `$snap`. The
# route targets are collected per row in a COLLECT subquery, and a LIMIT of the
# caller stops the expansion early.
RT_IMPORTED_ROUTES = """
MATCH (v)-[im:IMPORTS]->(rt:RouteTarget:Obj)<-[ex:EXPORTS]-(x:VrfInstance)-[o:ORIGINATES]->(p:Prefix)
WHERE x <> v AND im._retired_at IS NULL AND ex._retired_at IS NULL AND o._retired_at IS NULL
  AND NOT rt:Retired AND NOT x:Retired AND NOT p:Retired
  AND rt.collection_ts = $snap
  AND x.collection_ts = $snap
  AND p.collection_ts = $snap
WITH DISTINCT v, p
WITH v, p, COLLECT {
  MATCH (v)-[im2:IMPORTS]->(rt2:RouteTarget)<-[ex2:EXPORTS]-(x2:VrfInstance)-[o2:ORIGINATES]->(p)
  WHERE x2 <> v AND im2._retired_at IS NULL AND ex2._retired_at IS NULL AND o2._retired_at IS NULL
    AND NOT rt2:Retired AND NOT x2:Retired
    AND rt2.collection_ts = $snap
    AND x2.collection_ts = $snap
  RETURN DISTINCT rt2.value AS rt_value ORDER BY rt_value
} AS rts
WITH v, p,
     reduce(acc = '', rt_value IN rts | acc + CASE acc WHEN '' THEN '' ELSE ',' END + rt_value) AS via_rt
"""

REALIZES_AT_CYCLE_QUERY = """
MATCH (v:VrfInstance:Obj)-[m:MEMBER_OF {basis: 'declared'}]->(d:RoutingDomain)
WHERE NOT v:Retired AND NOT d:Retired AND m._retired_at IS NULL
  AND v.collection_ts = $cts
RETURN v.uid AS vrf_uid, d.name AS domain_name
UNION
// legacy fallback, same query: a graph loaded by an earlier release (or not yet
// re-collected since) carries REALIZES/L3Domain instead of MEMBER_OF/RoutingDomain --
// collectors stopped emitting it (core/labels.py), but old rows do not retire
// themselves, and a graph nobody has re-collected since the upgrade would otherwise
// report zero declared domains and read, wrongly, as a clean audit. Unioned so
// `hst audit domains` stays correct for a graph in either shape, or straddling
// both mid-migration, without the caller needing to know which.
MATCH (v:VrfInstance:Obj)-[r:REALIZES]->(d:L3Domain)
WHERE NOT v:Retired AND NOT d:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $cts
RETURN v.uid AS vrf_uid, d.name AS domain_name
"""


# The audit reads (`hst audit domains`, `hst audit segments`) have a 30 s
# transaction timeout. `execute_rt_domains` and `execute_link_speed` pass
# `Settings.reasoner_read_timeout_s`.
AUDIT_READ_TIMEOUT_S = 30.0


def _plain_run(tx: Any, query: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    return tx.run(query, **(params or {})).data()


_run = unit_of_work(timeout=AUDIT_READ_TIMEOUT_S)(_plain_run)


# The default of `collection_ts` when the caller passes none. `_read_cycle` then
# resolves the pointer. An explicit value, including None, is used as given.
_UNSET: Any = object()


def _read_cycle(
    session: Any, query: str, collection_ts: Any = _UNSET, timeout: float | None = AUDIT_READ_TIMEOUT_S
) -> list[dict[str, Any]]:
    """Run the cycle-scoped `query`, bound to `collection_ts`, under the
    transaction `timeout` in seconds. With `timeout` None, the timeout of the server
    applies.

    When `collection_ts` is omitted, the pointer is resolved once. An explicit int is
    the cycle to read. An explicit None means that the caller found no pointer, and
    the query binds `LIVE_SNAP`.
    """
    from hst.path import LIVE_SNAP

    if collection_ts is _UNSET:
        from . import cycle as cyclemod

        collection_ts = cyclemod.current_ts_or_none(session)
    cts = collection_ts if collection_ts is not None else LIVE_SNAP
    work = _run if timeout == AUDIT_READ_TIMEOUT_S else unit_of_work(timeout=timeout)(_plain_run)
    return list(session.execute_read(work, query, {"cts": cts}))


def read_topology(
    session: Any, collection_ts: Any = _UNSET, timeout: float | None = AUDIT_READ_TIMEOUT_S
) -> RtTopology:
    """Fetch the IMPORTS and EXPORTS edges of the estate and compute the pairs and the
    components. `collection_ts` is the cycle to read. When it is omitted,
    `_read_cycle` resolves the cycle of the pointer."""
    return pair_and_group(_read_cycle(session, RT_EDGES_AT_CYCLE_QUERY, collection_ts, timeout))


def read_realizes(session: Any, collection_ts: Any = _UNSET) -> list[dict[str, Any]]:
    """Fetch the declared-domain memberships of the estate, as rows of VrfInstance uid
    and domain name. The rows come from `MEMBER_OF {basis: "declared"}` rels to a
    RoutingDomain and from REALIZES rels to an L3Domain (see
    `REALIZES_AT_CYCLE_QUERY`). The cycle scoping is that of `read_topology`."""
    return _read_cycle(session, REALIZES_AT_CYCLE_QUERY, collection_ts)


# --- batch + load --------------------------------------------------------------------------


def derive_rt_domains_batch(
    session: Any, collection_ts: Any = _UNSET, timeout: float | None = AUDIT_READ_TIMEOUT_S
) -> Batch:
    """Read the graph (`read_topology`) and build the rt-component RoutingDomain
    batch (`build_rt_domains`)."""
    return build_rt_domains(read_topology(session, collection_ts, timeout))


def execute_rt_domains(
    session: Any, settings: Settings, collection_ts: int | None = None, ts_ms: int | None = None
) -> RunManifest:
    """Derive the rt-domains batch and load it through the loader, as
    `collectors.base.execute()` does for a collector.

    `collection_ts` is the cycle to read and to stamp. The orchestration passes the
    cycle that it builds. When `collection_ts` is None, the pointer is resolved once.

    `ts_ms` is the collection time that the load records (`collected_at`,
    `_first_seen`). When `ts_ms` is None, the current time is used."""
    from . import cycle as cyclemod

    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    pointer_cts = collection_ts if collection_ts is not None else cyclemod.current_ts_or_none(session)
    # The derived objects are loaded into the cycle of the reads. The endpoint
    # MATCH of the loader finds no node of another cycle.
    cts = pointer_cts if pointer_cts is not None else ts
    run_id = f"reasoner-rt-domains-{cts}-{uuid.uuid4().hex[:8]}"
    batch = derive_rt_domains_batch(session, pointer_cts, settings.reasoner_read_timeout_s)
    return load(session, batch, run_id=run_id, ts_ms=ts, collection_ts=cts)


# --- bridge domains (L2) -------------------------------------------------------------------
# The observed broadcast-domain components are computed from carriage evidence
# and compared with the declared segments.


@dataclass(frozen=True)
class SegmentMerge:
    """One observed broadcast domain realized as several declared segments."""

    vids: tuple[int, ...]
    segments: tuple[str, ...]  # distinct declared segment uids, sorted
    members: tuple[str, ...]  # the VlanInstance uids of the component, sorted


@dataclass(frozen=True)
class SegmentSplit:
    """One declared segment whose members with carriage evidence are in more than one
    carriage component. No collected trunk path joins the components. A member with
    no carriage evidence is excluded."""

    segment: str
    components: tuple[tuple[str, ...], ...]  # VlanInstance uid groups, sorted


CARRIAGE_AT_CYCLE_QUERY = """
MATCH (p:Port:Obj)-[c:CARRIES]->(v:VlanInstance)
WHERE p.collection_ts = $cts
  AND NOT p:Retired AND NOT v:Retired AND c._retired_at IS NULL
RETURN p.uid AS port_uid, v.uid AS vlan_uid, v.vid AS vid
"""

PORT_LINKS_AT_CYCLE_QUERY = """
MATCH (a:Port:Obj)-[l:CONNECTED_TO]-(b:Port)
WHERE a.collection_ts = $cts
  AND NOT a:Retired AND NOT b:Retired AND l._retired_at IS NULL AND a.uid < b.uid
RETURN a.uid AS a, b.uid AS z
"""

SEGMENT_REALIZES_AT_CYCLE_QUERY = """
MATCH (v:VlanInstance:Obj)-[r:REALIZES]->(s)
WHERE v.collection_ts = $cts
  AND (s:L2Segment OR s:BridgeDomain) AND NOT v:Retired AND NOT s:Retired
  AND r._retired_at IS NULL
RETURN v.uid AS vlan_uid, v.vid AS vid, s.uid AS segment_uid
"""


def bridge_components(
    links: Iterable[Mapping[str, Any]],
    carriage: Iterable[Mapping[str, Any]],
) -> list[tuple[str, ...]]:
    """Return the observed broadcast-domain components. The function is pure.
    VlanInstances are joined when one collected link has the same VID on both ends.
    In IEEE 802.1Q, a VID is significant per link. VlanInstances with the same VID and
    no joining link stay in separate components. The result does not depend on the
    row order."""
    by_port: dict[str, dict[int, str]] = defaultdict(dict)
    uf = _UnionFind()
    for row in carriage:
        if row.get("vid") is None:
            continue
        uf.find(row["vlan_uid"])  # A VLAN with no pairing also gets a component.
        by_port[row["port_uid"]][int(row["vid"])] = row["vlan_uid"]
    for link in links:
        a_side, z_side = by_port.get(link["a"], {}), by_port.get(link["z"], {})
        for vid, vlan_a in a_side.items():
            vlan_z = z_side.get(vid)
            if vlan_z is not None:
                uf.union(vlan_a, vlan_z)
    return sorted(tuple(sorted(members)) for members in uf.groups().values())


def find_segment_merges(
    components: Iterable[tuple[str, ...]],
    realizes: Iterable[Mapping[str, Any]],
) -> list[SegmentMerge]:
    """Return the components whose members realize more than one declared segment.
    The function is pure. A row of `realizes` has the fields of a
    `SEGMENT_REALIZES_AT_CYCLE_QUERY` row."""
    seg_of: dict[str, str] = {}
    vid_of: dict[str, Any] = {}
    for row in realizes:
        seg_of[row["vlan_uid"]] = row["segment_uid"]
        vid_of[row["vlan_uid"]] = row.get("vid")
    merges = []
    for comp in components:
        segments = sorted({seg_of[m] for m in comp if m in seg_of})
        if len(segments) <= 1:
            continue
        vids = sorted({int(vid_of[m]) for m in comp if vid_of.get(m) is not None})
        merges.append(SegmentMerge(vids=tuple(vids), segments=tuple(segments), members=comp))
    return sorted(merges, key=lambda m: m.segments)


def find_segment_splits(
    components: Iterable[tuple[str, ...]],
    realizes: Iterable[Mapping[str, Any]],
) -> list[SegmentSplit]:
    """Return the declared segments whose members with carriage evidence are in more
    than one component. The function is pure. A member that is in no component has no
    evidence and is excluded (see `SegmentSplit`)."""
    component_of = {m: i for i, comp in enumerate(components) for m in comp}
    by_segment: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in realizes:
        comp = component_of.get(row["vlan_uid"])
        if comp is not None:
            by_segment[row["segment_uid"]][comp].append(row["vlan_uid"])
    splits = []
    for segment, groups in sorted(by_segment.items()):
        if len(groups) > 1:
            parts = tuple(sorted(tuple(sorted(g)) for g in groups.values()))
            splits.append(SegmentSplit(segment=segment, components=parts))
    return splits


def read_carriage(session: Any, collection_ts: Any = _UNSET) -> list[dict[str, Any]]:
    """Fetch the carriage evidence of the estate, one row per CARRIES rel from a Port
    to a VlanInstance. `collection_ts` is the cycle to read, as in `read_topology`.
    When it is omitted, the pointer is resolved. A caller that reads `read_carriage`,
    `read_port_links` and `read_segment_realizes` for one report (`audit segments` in
    `cli.py`) resolves the pointer once and passes it to each."""
    return _read_cycle(session, CARRIAGE_AT_CYCLE_QUERY, collection_ts)


def read_port_links(session: Any, collection_ts: Any = _UNSET) -> list[dict[str, Any]]:
    """Fetch the cabling between the Ports of the estate, one row per link. The cycle
    scoping is that of `read_carriage`."""
    return _read_cycle(session, PORT_LINKS_AT_CYCLE_QUERY, collection_ts)


def read_segment_realizes(session: Any, collection_ts: Any = _UNSET) -> list[dict[str, Any]]:
    """Fetch the memberships of the VlanInstances of the estate in declared segments.
    The cycle scoping is that of `read_carriage`."""
    return _read_cycle(session, SEGMENT_REALIZES_AT_CYCLE_QUERY, collection_ts)


# --- CONNECTED_TO link speed -----------------
# The edge is written at collection time by collectors/unifi.py and
# collectors/nautobot.py. `speed_mbps` and `speed_agreement` need both ends and are
# derived here.

# The query matches each edge in its stored direction. The loader writes the
# speed with a directed `MERGE (a)-[r:CONNECTED_TO]->(b)` (`core/loader.py`
# `rel_upsert_query`). A row with the ends in the reverse direction matches no
# edge, and the MERGE creates a new edge with no source. A pair with 2 edges in
# opposite directions gives 2 rows. DISTINCT folds the edges with the same
# direction into one row.
CONNECTED_TO_SPEED_AT_CYCLE_QUERY = """
MATCH (a:Port:Obj)-[l:CONNECTED_TO]->(b:Port)
WHERE a.collection_ts = $cts
  AND NOT a:Retired AND NOT b:Retired AND l._retired_at IS NULL
// coalesce(speed_mbps, speed): a snapshot collected before the unifi.py speed
// rename still carries the old `speed`
// property only; this reads either shape without a migration.
RETURN DISTINCT a.uid AS a_uid, coalesce(a.speed_mbps, a.speed) AS a_speed,
       b.uid AS b_uid, coalesce(b.speed_mbps, b.speed) AS b_speed
"""


def link_speed_agreement(a_speed: int | None, b_speed: int | None) -> tuple[int | None, str]:
    """Return the `(speed_mbps, speed_agreement)` pair of a CONNECTED_TO edge from the
    `speed_mbps` of the 2 Ports. The function is pure.

    Equal speeds give the speed and `agree`. Different speeds give the lower speed
    and `disagree`. One known speed gives that speed and `one-side`. No known speed
    gives None and `unknown`."""
    if a_speed is not None and b_speed is not None:
        return (a_speed, "agree") if a_speed == b_speed else (min(a_speed, b_speed), "disagree")
    if a_speed is not None:
        return a_speed, "one-side"
    if b_speed is not None:
        return b_speed, "one-side"
    return None, "unknown"


def build_connected_to_speed(links: Iterable[Mapping[str, Any]]) -> list[RelRecord]:
    """Build one CONNECTED_TO RelRecord per row of `links`. The function is pure. A
    row has the fields of a `CONNECTED_TO_SPEED_AT_CYCLE_QUERY` row. The props of a
    record are the derived `speed_mbps` and `speed_agreement` only.

    The key is empty. An empty key puts no property filter into the MERGE pattern of
    the loader (`core/loader.py` `rel_upsert_query`). The write applies to every
    CONNECTED_TO edge between the 2 ports in the direction of the row."""
    rels = []
    for row in links:
        speed, agreement = link_speed_agreement(row.get("a_speed"), row.get("b_speed"))
        rels.append(
            RelRecord(
                type="CONNECTED_TO",
                start_label="Port",
                start_uid=row["a_uid"],
                end_label="Port",
                end_uid=row["b_uid"],
                key={},
                props={"speed_mbps": speed, "speed_agreement": agreement},
            )
        )
    return rels


def read_connected_to_speed(
    session: Any, collection_ts: Any = _UNSET, timeout: float | None = AUDIT_READ_TIMEOUT_S
) -> list[dict[str, Any]]:
    """Fetch the cabling between the Ports of the estate with the `speed_mbps` of both
    ends, one row per port pair and stored direction. The cycle scoping is that of
    `read_port_links`."""
    return _read_cycle(session, CONNECTED_TO_SPEED_AT_CYCLE_QUERY, collection_ts, timeout)


def derive_link_speed_batch(
    session: Any, collection_ts: Any = _UNSET, timeout: float | None = AUDIT_READ_TIMEOUT_S
) -> Batch:
    """Read the graph and build the CONNECTED_TO speed batch. The batch has no
    NodeRecords."""
    links = read_connected_to_speed(session, collection_ts, timeout)
    rels = build_connected_to_speed(links)
    return Batch(source="reasoner", scope="derived:link-speed", nodes=[], rels=rels)


def execute_link_speed(
    session: Any, settings: Settings, collection_ts: int | None = None, ts_ms: int | None = None
) -> RunManifest:
    """Derive the CONNECTED_TO speed batch and load it through the loader.
    `collection_ts` and `ts_ms` have the meaning that they have in
    `execute_rt_domains()`.

    `core/finalize.py` `finalize_derivations` calls this function after `rt-domains`
    and before the site assignments. `hst reason link-speed` calls it alone.
    """
    from . import cycle as cyclemod

    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    pointer_cts = collection_ts if collection_ts is not None else cyclemod.current_ts_or_none(session)
    cts = pointer_cts if pointer_cts is not None else ts
    run_id = f"reasoner-link-speed-{cts}-{uuid.uuid4().hex[:8]}"
    batch = derive_link_speed_batch(session, pointer_cts, settings.reasoner_read_timeout_s)
    return load(session, batch, run_id=run_id, ts_ms=ts, collection_ts=cts)
