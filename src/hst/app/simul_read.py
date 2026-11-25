"""The graph read behind provider 2 of the route-delta interface."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hst import path as pathmod
from hst.core import reasoner
from hst.path.gates import pbr as _pbr_gate
from hst.simul import certainty, provider, rib
from hst.simul.compile import LIST_KINDS, context_namespaces, policy_namespace, resolving_namespace
from hst.simul.errors import ErrorSink
from hst.simul.propagate import RouteDelta, SimulationInput

# The maximum length of a `HAS_RULE|REFERENCES` chain out of an attached
# policy. `RoutePolicyEntry-[:REFERENCES]->RoutePolicy` alternates with
# `HAS_RULE`. A bound of 8 covers 4 levels of `calls_policy` or
# `match_prefix_lists` nesting.
_REFERENCE_DEPTH = 8
_COMPLETE_TABLE = {"complete", "complete-empty"}
_COMPLETE_SECTION = {"ok", "empty"}

# `(VrfInstance)-[:ORIGINATES {proto}]->(Prefix)` values
# mapped onto the engine's `origin_mechanism` vocabulary
# (`simul/route.py` `ORIGINATION_RANK`).
_ORIGIN_MECHANISM = {
    "aggregate": "aggregate",
    "redistributed": "redistribute",
    "network": "network",
    "connected": "network",
    "static": "network",
}

# --- queries --------------------------------------------------------------

# A device owns a context through an OWNED_BY edge or through an interface on the device.
_SEED_BY_DEVICE = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE NOT rp:Retired AND NOT v:Retired AND iv._retired_at IS NULL
  AND toLower(coalesce(rp.proto, '')) = 'bgp'
  AND rp.collection_ts = $snap
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT d:Retired
  AND v.collection_ts = $snap
  AND (EXISTS {
    MATCH (v)-[owner:OWNED_BY]->(d) WHERE owner._retired_at IS NULL
  } OR EXISTS {
    MATCH (v)<-[iv2:IN_VRF]-(i:Interface)-[o:ON]->(d)
    WHERE iv2._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired
      AND i.collection_ts = $snap
  })
RETURN DISTINCT rp.uid AS uid
ORDER BY uid"""

_SEED_BY_VRF = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance:Obj {uid: $vrf, collection_ts: $snap})
WHERE NOT rp:Retired AND NOT v:Retired AND iv._retired_at IS NULL
  AND toLower(coalesce(rp.proto, '')) = 'bgp'
  AND rp.collection_ts = $snap
RETURN DISTINCT rp.uid AS uid
ORDER BY uid"""

# The query follows one peering hop out of the seed to the process that owns
# the peer address of the session. `ip.ip = b.peer_ip` selects the peer
# endpoint of the ENDPOINT pair.
_PEER_PROCESSES = """
MATCH (rp:RoutingProcess:Obj)-[h:HAS]->(b:BgpSession:Obj)-[e:ENDPOINT]->(ip:IpAddress)
WHERE rp.uid IN $procs AND h._retired_at IS NULL AND e._retired_at IS NULL
  AND NOT rp:Retired AND NOT b:Retired AND NOT ip:Retired
  AND b.collection_ts = $snap
  AND ip.ip = b.peer_ip
MATCH (ip)<-[hi:HAS_IP]-(i:Interface)-[iv:IN_VRF]->(v:VrfInstance)
      <-[iv2:IN_VRF]-(far:RoutingProcess)
WHERE hi._retired_at IS NULL AND iv._retired_at IS NULL AND iv2._retired_at IS NULL
  AND NOT i:Retired AND NOT v:Retired AND NOT far:Retired
  AND toLower(coalesce(far.proto, '')) = 'bgp'
RETURN DISTINCT far.uid AS uid
ORDER BY uid"""

# The interfaces of a VRF can be on more than one device. `platforms` is a list.
_PROCESSES = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE rp.uid IN $procs AND iv._retired_at IS NULL
  AND NOT rp:Retired AND NOT v:Retired
  AND toLower(coalesce(rp.proto, '')) = 'bgp'
  AND rp.collection_ts = $snap
OPTIONAL MATCH (v)-[owner:OWNED_BY]->(od:Device)
WHERE owner._retired_at IS NULL AND NOT od:Retired
  AND od.collection_ts = $snap
OPTIONAL MATCH (v)<-[iv2:IN_VRF]-(i:Interface)-[o:ON]->(id:Device)
WHERE iv2._retired_at IS NULL AND o._retired_at IS NULL
  AND NOT i:Retired AND NOT id:Retired
  AND i.collection_ts = $snap AND id.collection_ts = $snap
WITH rp, v, collect(DISTINCT od) + collect(DISTINCT id) AS owners
UNWIND CASE WHEN size(owners) = 0 THEN [null] ELSE owners END AS d
RETURN rp.uid AS uid, properties(rp) AS props, v.uid AS context_uid,
       collect(DISTINCT d.platform) AS platforms,
       collect(DISTINCT d.vendor) AS vendors,
       collect(DISTINCT d.uid) AS device_uids
ORDER BY rp.uid"""

_SESSIONS = """
MATCH (rp:RoutingProcess:Obj)-[h:HAS]->(b:BgpSession:Obj)
WHERE rp.uid IN $procs AND h._retired_at IS NULL
  AND NOT rp:Retired AND NOT b:Retired
  AND b.collection_ts = $snap
  // the engine carries IPv4 unicast: a session that activates other families
  // alone (an EVPN or IPv6 peering) carries none of its routes, and one that
  // states no families (NULL) is read as before
  AND (b.afi_safi IS NULL OR 'ipv4-unicast' IN b.afi_safi)
RETURN b.uid AS uid, rp.uid AS process_uid, properties(b) AS props
ORDER BY b.uid"""

_PROCESS_ADDRESSES = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)<-[iv2:IN_VRF]-(i:Interface)
      -[hi:HAS_IP]->(ip:IpAddress)
WHERE rp.uid IN $procs AND iv._retired_at IS NULL AND iv2._retired_at IS NULL
  AND hi._retired_at IS NULL
  AND NOT rp:Retired AND NOT v:Retired AND NOT i:Retired AND NOT ip:Retired
  AND rp.collection_ts = $snap
RETURN DISTINCT rp.uid AS process_uid, ip.ip AS ip
ORDER BY process_uid, ip"""

# One process attaches every `network` route-map and every aggregate
# `attribute-map` under one `FILTERED_BY {redistribute, <proto>}` key. The
# query selects the policy by the name on the `ORIGINATES` edge (`route_map`
# for a network statement, `attribute_map` for an aggregate). For an edge
# without a name it selects a policy that the process attaches for that
# protocol.
_ORIGINATED = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)-[og:ORIGINATES]->(p:Prefix)
WHERE rp.uid IN $procs AND iv._retired_at IS NULL AND og._retired_at IS NULL
  AND NOT rp:Retired AND NOT v:Retired AND NOT p:Retired
  AND rp.collection_ts = $snap
OPTIONAL MATCH (rp)-[filter:FILTERED_BY]->(policy:RoutePolicy)
WHERE filter._retired_at IS NULL AND NOT policy:Retired
  AND filter.direction = 'redistribute' AND filter.protocol = og.proto
  AND coalesce(og.attribute_map, og.route_map, policy.name) = policy.name
RETURN rp.uid AS process_uid, p.cidr AS prefix, og.proto AS proto,
       properties(og) AS origin_props, head(collect(DISTINCT policy.name)) AS origin_policy_name
ORDER BY process_uid, prefix, proto"""

# The query starts at the FILTERED_BY attachments of the sessions and follows
# HAS_RULE and REFERENCES. Each row has the process that reached the policy
# (`process_uid`). The policy of a Check Point virtual system has its routing
# context (`context_uid`).
_POLICIES = f"""
MATCH (rp:RoutingProcess:Obj)-[h:HAS]->(b:BgpSession:Obj)-[f:FILTERED_BY]->(seed:RoutePolicy)
WHERE b.uid IN $sessions AND h._retired_at IS NULL AND f._retired_at IS NULL
  AND NOT rp:Retired AND NOT b:Retired AND NOT seed:Retired
  AND rp.collection_ts = $snap AND b.collection_ts = $snap
MATCH (seed)-[ref:HAS_RULE|REFERENCES*0..{_REFERENCE_DEPTH}]->(pol:RoutePolicy)
WHERE all(r IN ref WHERE r._retired_at IS NULL) AND NOT pol:Retired
WITH DISTINCT pol, rp.uid AS process_uid
OPTIONAL MATCH (pol)-[hr:HAS_RULE]->(e)
WHERE hr._retired_at IS NULL AND NOT e:Retired
RETURN pol.uid AS uid, pol.name AS name, pol.kind AS kind, pol.context_uid AS context_uid, process_uid,
       collect(properties(e)) AS entries
ORDER BY pol.uid, process_uid"""

_ORIGIN_POLICIES = f"""
MATCH (rp:RoutingProcess:Obj)-[f:FILTERED_BY]->(seed:RoutePolicy)
WHERE rp.uid IN $procs AND f._retired_at IS NULL
  AND NOT rp:Retired AND NOT seed:Retired
  AND rp.collection_ts = $snap
  AND f.direction = 'redistribute' AND f.protocol IN ['network', 'aggregate']
MATCH (seed)-[ref:HAS_RULE|REFERENCES*0..{_REFERENCE_DEPTH}]->(pol:RoutePolicy)
WHERE all(r IN ref WHERE r._retired_at IS NULL) AND NOT pol:Retired
WITH DISTINCT pol, rp.uid AS process_uid
OPTIONAL MATCH (pol)-[hr:HAS_RULE]->(e)
WHERE hr._retired_at IS NULL AND NOT e:Retired
RETURN pol.uid AS uid, pol.name AS name, pol.kind AS kind, pol.context_uid AS context_uid, process_uid,
       collect(properties(e)) AS entries
ORDER BY pol.uid, process_uid"""


# --- result ---------------------------------------------------------------


@dataclass
class GraphInput:
    """The engine input that the graph supplies and the faults that the read
    found.

    `to_simulation_input()` returns the `SimulationInput` of the engine. A
    caller merges `errors` into `RouteDelta.model_errors`.
    """

    processes: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    local_routes: list[dict[str, Any]] = field(default_factory=list)
    platform: str = "iosxe"
    errors: ErrorSink = field(default_factory=ErrorSink)
    # Each (namespace, list kind, name) that more than one RoutePolicy node
    # defines (`_dedupe_policies`) or that a process reached outside the
    # namespace where it resolves names (`_report_foreign_policies`). The
    # namespace is the owning device, the routing context of a policy that
    # has one (a Check Point virtual system), or "" for a policy that no
    # device owns. The rows of a process that resolves such a name are not
    # established (`ambiguous_contexts`).
    ambiguous_policies: set[tuple[str, str, str]] = field(default_factory=set)

    def to_simulation_input(self) -> SimulationInput:
        return SimulationInput(
            processes=self.processes,
            sessions=self.sessions,
            policies=self.policies,
            local_routes=self.local_routes,
            platform=self.platform,
        )


# --- row shaping ----------------------------------------------------------


def _pick(values: Iterable[Any]) -> str | None:
    """One value out of a Cypher `collect(DISTINCT ...)`, chosen deterministically."""
    present = sorted({str(v) for v in values if v})
    return present[0] if present else None


def _process_platform(props: Mapping[str, Any], platforms: Any, vendors: Any) -> str | None:
    """The platform string of one process for `simul.platforms.normalize`.

    It is the `platform` property of the process, else the `platform` of the
    owning device, else its `vendor`. A `vyos` value becomes `vyos-traditional`
    or `vyos-datacenter` from `RoutingProcess.ebgp_requires_policy`.
    """
    raw = props.get("platform") or _pick(platforms or ()) or _pick(vendors or ())
    if raw is None:
        return None
    text = str(raw).strip().lower()
    if text == "vyos":
        requires = props.get("ebgp_requires_policy")
        if requires is not None:
            return "vyos-traditional" if requires else "vyos-datacenter"
    return text


def _process_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """One `RoutingProcess` as the engine reads it.

    The node's whole property bag is passed through. `context_uid` is the uid of
    the owning `VrfInstance`, from the `IN_VRF` edge.
    """
    props = dict(row.get("props") or {})
    out: dict[str, Any] = {
        **props,
        "uid": str(row["uid"]),
        "context_uid": str(row["context_uid"]),
    }
    platform = _process_platform(props, row.get("platforms"), row.get("vendors"))
    if platform:
        out["platform"] = platform
    else:
        out.pop("platform", None)
    device_uids = sorted({str(d) for d in (row.get("device_uids") or ()) if d})
    if len(device_uids) == 1:
        out["device_uid"] = device_uids[0]
    else:
        out.pop("device_uid", None)
    return out


def _session_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """One `BgpSession` as the engine reads it.

    The property bag is passed through untouched apart from `process_uid`, which
    is the `HAS` edge. A policy name that resolves to no `RoutePolicy` node is kept.
    """
    props = dict(row.get("props") or {})
    return {**props, "uid": str(row["uid"]), "process_uid": str(row["process_uid"])}


def _policy_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """One `RoutePolicy` with its `HAS_RULE` children as `entries`, sorted by `seq`."""
    entries = [dict(e) for e in (row.get("entries") or []) if e]
    entries.sort(key=lambda e: (int(e.get("seq", 0)), str(e.get("uid", ""))))
    out = {
        "uid": str(row["uid"]),
        "name": str(row["name"]),
        "kind": str(row["kind"] or ""),
        "entries": entries,
    }
    # the policy of a Check Point virtual system states its routing context
    if row.get("context_uid"):
        out["context_uid"] = str(row["context_uid"])
    return out


def _policy_owner(device_uid: Any) -> dict[str, Any]:
    """The `device_uid` key of a policy row. The dict is empty when the process
    that reached the policy has no device."""
    return {"device_uid": str(device_uid)} if device_uid else {}


def _local_route_row(row: Mapping[str, Any]) -> dict[str, Any]:
    proto = str(row.get("proto") or "").strip().lower()
    result = {
        **dict(row.get("origin_props") or {}),
        "process_uid": str(row["process_uid"]),
        "prefix": str(row["prefix"]),
        "origin_mechanism": _ORIGIN_MECHANISM.get(proto, "network"),
        "src_protocol": proto or None,
    }
    if proto in {"network", "aggregate"}:
        result["intent"] = True
    # An attribute-map that resolves to no RoutePolicy node reaches the engine by its raw name.
    policy_name = row.get("origin_policy_name") or result.get("attribute_map") or result.get("route_map")
    if policy_name:
        result["route_map"] = str(policy_name)
    return result


# --- pairing --------------------------------------------------------------


def _pair_local_ips(
    sessions: Sequence[dict[str, Any]],
    addresses: Mapping[str, set[str]],
    router_ids: Mapping[str, str | None],
    errors: ErrorSink,
) -> None:
    """Fill in `local_ip` (and `peer_router_id` and `peer_cluster_ids`) by
    matching the two sides of a peering.

    `propagate._pair_sessions` matches a session with the far end whose
    `(local_ip, peer_ip)` mirrors its own. No collector writes `local_ip`.
    The far end of session S on process P is the session T whose process owns
    S's `peer_ip` and whose own `peer_ip` is an address of P.

    A session whose far end is outside the estate (an external eBGP peer, or
    a device that is not in this snapshot) keeps `local_ip` unset. The engine
    reports it as `unpaired-bgp-session`.

    `peer_cluster_ids` are the cluster ids of the far process when it is a
    route reflector (`_cluster_ids`). The engine does not send the far process
    a route whose cluster list holds one of them (`bestpath.export_route`).
    `peer_router_id` is the router id of the far process.
    """
    clusters = _cluster_ids(sessions, router_ids)
    # `owners` maps an address to the processes whose VRF holds it. `peers_of`
    # maps a process and a peer address to the sessions.
    owners: dict[str, set[str]] = {}
    for owner, held in addresses.items():
        for address in held:
            owners.setdefault(address, set()).add(owner)
    peers_of: dict[str, dict[Any, list[dict[str, Any]]]] = {}
    for session in sessions:
        peers_of.setdefault(str(session["process_uid"]), {}).setdefault(session.get("peer_ip"), []).append(
            session
        )

    for session in sessions:
        if session.get("local_ip"):
            continue
        peer_ip = session.get("peer_ip")
        process_uid = str(session["process_uid"])
        if not peer_ip:
            continue
        local_addresses = addresses.get(process_uid, set())
        candidates: list[dict[str, Any]] = []
        for far_process in owners.get(peer_ip, ()):
            far_peers = peers_of.get(far_process, {})
            if len(local_addresses) < len(far_peers):
                matched = [far for address in local_addresses for far in far_peers.get(address, ())]
            else:
                matched = [
                    far for address, fars in far_peers.items() if address in local_addresses for far in fars
                ]
            candidates.extend(far for far in matched if far["uid"] != session["uid"])
        if not candidates:
            continue
        candidates.sort(key=lambda s: str(s["uid"]))
        if len(candidates) > 1:
            errors.report(
                "ambiguous-session-pairing",
                f"session {session['uid']} has {len(candidates)} candidate far-end "
                f"BgpSession nodes; {candidates[0]['uid']} was used",
                str(session["uid"]),
            )
        far = candidates[0]
        session["local_ip"] = far["peer_ip"]
        if not session.get("peer_router_id"):
            far_rid = router_ids.get(str(far["process_uid"]))
            if far_rid:
                session["peer_router_id"] = far_rid
        if not session.get("peer_cluster_ids") and clusters.get(str(far["process_uid"])):
            session["peer_cluster_ids"] = clusters[str(far["process_uid"])]


def _cluster_ids(
    sessions: Sequence[Mapping[str, Any]], router_ids: Mapping[str, str | None]
) -> dict[str, list[str]]:
    """The sorted cluster ids that each process uses as a route reflector, by
    process uid.

    A session's `cluster_id` is the one the collector read (`bgp cluster-id`,
    a neighbor's own `cluster-id`, VyOS `parameters cluster-id`). A process
    with a route-reflector client session that states none uses its router
    id, the default on every platform. A process that reflects nothing and
    states no cluster id has none."""
    out: dict[str, set[str]] = {}
    for session in sessions:
        process_uid = str(session["process_uid"])
        cluster = session.get("cluster_id")
        if not cluster and session.get("route_reflector_client"):
            cluster = router_ids.get(process_uid)
        if cluster:
            out.setdefault(process_uid, set()).add(str(cluster))
    return {process_uid: sorted(ids) for process_uid, ids in out.items()}


def _dedupe_policies(
    policies: Sequence[dict[str, Any]],
    errors: ErrorSink,
    ambiguous: set[tuple[str, str, str]] | None = None,
) -> list[dict[str, Any]]:
    """One policy per name in each namespace (`compile.policy_namespace`).

    `simul.compile.compile_policies` keys its output by `name`. The policies
    of each device are compiled apart. A name that 2 devices define (a
    templated `RM_IN`) keeps both policies. A policy that 2 processes of one
    device reached is one policy. A policy that has a routing context (a
    Check Point virtual system) is in the namespace of that context. 2 virtual
    systems of one gateway keep one policy each for a name. 2 different nodes
    of one name in one namespace are a collision. The first node by uid is
    kept, and the function reports `ambiguous-policy-name`.

    The key of a community list or an AS-path list has its list kind
    (`compile.match_lists`). The IOS lists `ip community-list 7` and
    `ip as-path access-list 7` of one device are both kept.
    """
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for policy in sorted(policies, key=lambda p: (str(p["uid"]), policy_namespace(p) or "")):
        name = policy["name"]
        kind = str(policy.get("kind") or "").lower()
        key = (policy_namespace(policy) or "", kind if kind in LIST_KINDS else "", name)
        if key in seen:
            if seen[key]["uid"] != policy["uid"]:
                if ambiguous is not None:
                    ambiguous.add(key)
                errors.report(
                    "ambiguous-policy-name",
                    f"route policy name {name!r} is defined by more than one RoutePolicy node "
                    f"in scope ({seen[key]['uid']} and {policy['uid']}); the first was used",
                    name,
                )
            continue
        seen[key] = policy
    return [seen[key] for key in sorted(seen, key=lambda k: (k[2], k[1], k[0]))]


def _report_foreign_policies(
    rows: Sequence[Mapping[str, Any]],
    reached_by: Sequence[str],
    processes: Sequence[Mapping[str, Any]],
    errors: ErrorSink,
    ambiguous: set[tuple[str, str, str]],
) -> None:
    """Report each policy that a process reached outside the namespace where
    it resolves names (`compile.resolving_namespace`).

    The cases are the route map of a virtual system reached from another
    context, and a policy keyed by its device reached by a process whose
    context is its own namespace (`_context_scoped`). `reached_by[i]` is the
    process that reached `rows[i]`.
    """
    contexts = context_namespaces(rows)
    by_uid = {str(p["uid"]): p for p in processes}
    for row, process_uid in zip(rows, reached_by, strict=True):
        process = by_uid.get(process_uid)
        if process is None:
            continue
        resolves = resolving_namespace(contexts, process.get("device_uid"), process.get("context_uid"))
        defined = policy_namespace(row)
        if defined == resolves:
            continue
        kind = str(row.get("kind") or "").lower()
        ambiguous.add((resolves or "", kind if kind in LIST_KINDS else "", str(row["name"])))
        errors.report(
            "policy-context-ambiguous",
            f"BGP process {process_uid} in {process.get('context_uid')} attaches route policy "
            f"{row['uid']} ({row['name']!r}), which is defined in {defined or 'no device'} and not "
            f"in {resolves or 'the policies no device owns'}, where the process resolves policy "
            "names; which policy the name means for this process is not decided",
            process_uid,
        )


def _context_scoped(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The policy rows with `context_uid` removed where the device identifies
    the policy.

    A row keeps `context_uid` when its context shares a name of one list kind
    with another context of the same device, as 2 Check Point virtual systems
    of one gateway that both define `out`. Every other row is keyed by its
    device.
    """
    defined: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        if row.get("context_uid"):
            kind = str(row.get("kind") or "").lower()
            key = (str(row.get("device_uid") or ""), kind if kind in LIST_KINDS else "", str(row["name"]))
            defined[key].add(str(row["context_uid"]))
    needed = set().union(*(contexts for contexts in defined.values() if len(contexts) > 1))
    return [
        row if row.get("context_uid") in needed else {k: v for k, v in row.items() if k != "context_uid"}
        for row in rows
    ]


# --- entry points ---------------------------------------------------------


def read_simulation_input(
    session: Any,
    *,
    device: str | None = None,
    vrf: str | None = None,
    platform: str = "iosxe",
) -> GraphInput:
    """Read the engine's input for one device or one VRF from a pinned graph.

    `session` must already be pinned (`hst.path.pinned`).

    Exactly one of `device` (a `Device.uid`) or `vrf` (a `VrfInstance.uid`) sets
    the scope. The scope selects the BGP `RoutingProcess` nodes of the
    prediction. The read then adds the processes one peering hop away. The
    engine carries an advertisement across a session only when the far-end
    process is in the input.

    `platform` is the fallback for a process whose device records none.
    """
    if (device is None) == (vrf is None):
        raise ValueError("read_simulation_input needs exactly one of device= or vrf=")

    errors = ErrorSink()
    if device is not None:
        seeds = [str(r["uid"]) for r in pathmod._read(session, _SEED_BY_DEVICE, dev=device)]
        scope = f"device {device}"
    else:
        seeds = [str(r["uid"]) for r in pathmod._read(session, _SEED_BY_VRF, vrf=vrf)]
        scope = f"vrf {vrf}"

    if not seeds:
        errors.report(
            "no-bgp-process-in-scope",
            f"{scope} has no BGP RoutingProcess in this snapshot",
            device or vrf,
        )
        return GraphInput(platform=platform, errors=errors)
    return _read_bgp(session, seeds, platform, errors)


def _read_bgp(
    session: Any,
    seeds: list[str],
    platform: str,
    errors: ErrorSink,
    *,
    infer_origins: bool = True,
) -> GraphInput:
    """The engine input for the BGP processes in `seeds` and for the processes
    one peering hop away."""
    peers = [str(r["uid"]) for r in pathmod._read(session, _PEER_PROCESSES, procs=seeds)]
    procs = sorted(set(seeds) | set(peers))

    processes = [_process_row(r) for r in pathmod._read(session, _PROCESSES, procs=procs)]
    sessions = [_session_row(r) for r in pathmod._read(session, _SESSIONS, procs=procs)]

    addresses: dict[str, set[str]] = {}
    for row in pathmod._read(session, _PROCESS_ADDRESSES, procs=procs):
        if row.get("ip"):
            addresses.setdefault(str(row["process_uid"]), set()).add(str(row["ip"]))
    router_ids = {p["uid"]: (str(p["router_id"]) if p.get("router_id") else None) for p in processes}
    _pair_local_ips(sessions, addresses, router_ids, errors)

    # `session_gaps` of a process lists the neighbors that a collector could
    # not write as sessions.
    for process in processes:
        if process.get("session_gaps"):
            errors.report(
                "bgp-session-not-recorded",
                f"BGP process {process['uid']} has configured neighbors that are not recorded as "
                "sessions: " + "; ".join(str(gap) for gap in process["session_gaps"]),
                str(process["uid"]),
            )

    session_uids = [s["uid"] for s in sessions]
    policy_rows: list[Mapping[str, Any]] = list(pathmod._read(session, _ORIGIN_POLICIES, procs=procs))
    if session_uids:
        policy_rows.extend(pathmod._read(session, _POLICIES, sessions=session_uids))
    device_of = {str(p["uid"]): p.get("device_uid") for p in processes}
    ambiguous: set[tuple[str, str, str]] = set()
    rows = _context_scoped(
        [{**_policy_row(r), **_policy_owner(device_of.get(str(r.get("process_uid"))))} for r in policy_rows]
    )
    _report_foreign_policies(
        rows, [str(r.get("process_uid")) for r in policy_rows], processes, errors, ambiguous
    )
    policies = _dedupe_policies(rows, errors, ambiguous)

    originated = pathmod._read(session, _ORIGINATED, procs=procs)
    explicit = [row for row in originated if str(row.get("proto") or "").lower() in {"aggregate", "network"}]
    local_routes = [_local_route_row(r) for r in (originated if infer_origins else explicit)]
    if infer_origins:
        context_gaps = [gap for process in processes for gap in process.get("origin_context_gaps") or []]
        if originated or context_gaps:
            errors.report(
                "origination-not-recorded",
                "some VRF prefixes have no recorded BGP network, aggregate, or matching "
                "redistribution statement; legacy provider mode seeded them as candidates",
                "; ".join(context_gaps) if context_gaps else None,
            )
    else:
        # Each process gets one error with the process as its subject.
        for process in processes:
            gaps = list(process.get("origin_context_gaps") or [])
            if process.get("origin_config_recorded") is not True:
                gaps.append(f"{process['uid']}: BGP origin configuration coverage was not recorded")
            if gaps:
                errors.report(
                    "origination-not-recorded",
                    "some VRF prefixes have no recorded BGP network, aggregate, or matching "
                    "redistribution statement; integrated strict mode could not prove complete "
                    "explicit origination intent: " + "; ".join(gaps),
                    str(process["uid"]),
                )

    return GraphInput(
        processes=processes,
        sessions=sessions,
        policies=policies,
        local_routes=local_routes,
        platform=platform,
        errors=errors,
        ambiguous_policies=ambiguous,
    )


# A Boundary takes the seed sessions whose far end can be left out, each with
# its far end and the context of the seed. It returns the uids of the sessions
# whose far end is left out.
Boundary = Callable[[list[tuple[dict[str, Any], dict[str, Any], str]]], set[str]]


def _shut(session: Mapping[str, Any]) -> bool:
    return str(session.get("state", "")).lower() == "shutdown"


def _policy_names(
    sessions: Iterable[Mapping[str, Any]],
    processes: Iterable[Mapping[str, Any]],
    local_routes: Iterable[Mapping[str, Any]],
    policies: Sequence[Mapping[str, Any]],
) -> set[str]:
    """The route policy names that the rows attach, closed over `calls_policy`.
    `simul.proof` attributes these names to a context of the rows."""
    names = {str(row[key]) for row in sessions for key in certainty.SESSION_POLICY_KEYS if row.get(key)}
    names.update(
        route_map
        for row in processes
        for _p, route_map in certainty.redistribute_statements(row)
        if route_map
    )
    names.update(
        str(row[key]) for row in local_routes for key in ("route_map", "attribute_map") if row.get(key)
    )
    calls = {
        str(policy.get("name")): {
            str(entry["calls_policy"]) for entry in policy.get("entries") or () if entry.get("calls_policy")
        }
        for policy in policies
    }
    pending = list(names)
    while pending:
        for callee in calls.get(pending.pop(), ()):
            if callee not in names:
                names.add(callee)
                pending.append(callee)
    return names


def _omit_far_ends(graph_input: GraphInput, seeds: Sequence[str], boundary: Boundary) -> GraphInput:
    """`graph_input` without the far-end processes that only the sessions
    left out by `boundary` reach.

    `_read_bgp` reads one peering hop out of the seeds and pairs each seed
    session, with `local_ip` and `peer_router_id` set. A seed session is
    offered to `boundary` when it has exactly one far end, the process of the
    far end is outside the seeds, the 2 sessions mirror the addresses and the
    ASNs of each other (the pairing rule of `certainty.paired_sessions` and of
    `propagate`), and neither side is shut down. The far-end process of a
    session that `boundary` leaves out is dropped with its sessions, its
    originations and its read faults, unless another seed session pairs with
    it. The seed session is then marked `certainty.OMITTED_FAR_END`. A
    policy-name fault is dropped when every row that attached the name was
    dropped.
    """
    seed_set = {str(s) for s in seeds}
    context_of = {str(p["uid"]): str(p["context_uid"]) for p in graph_input.processes}
    by_endpoints: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for item in graph_input.sessions:
        by_endpoints[(item.get("local_ip"), item.get("peer_ip"))].append(item)
    matches_of: dict[str, list[dict[str, Any]]] = {}
    for near in graph_input.sessions:
        if str(near["process_uid"]) not in seed_set or not near.get("local_ip") or not near.get("peer_ip"):
            continue
        matches_of[str(near["uid"])] = [
            far
            for far in by_endpoints.get((near.get("peer_ip"), near.get("local_ip")), ())
            if far["uid"] != near["uid"]
        ]
    offered: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    for near in graph_input.sessions:
        matches = matches_of.get(str(near["uid"]), [])
        if len(matches) != 1:
            continue
        far = matches[0]
        if (
            str(far["process_uid"]) not in seed_set
            and far.get("local_asn") == near.get("peer_asn")
            and far.get("peer_asn") == near.get("local_asn")
            and not _shut(near)
            and not _shut(far)
        ):
            offered.append((near, far, context_of.get(str(near["process_uid"]), "")))
    omitted = boundary(offered) if offered else set()
    still = {
        str(far["process_uid"])
        for near_uid, matches in matches_of.items()
        if near_uid not in omitted
        for far in matches
    }
    dropped = {str(far["process_uid"]) for near, far, _c in offered if str(near["uid"]) in omitted}
    dropped -= still | seed_set
    if not dropped:
        return graph_input
    for near, far, _context in offered:
        if str(near["uid"]) in omitted and str(far["process_uid"]) in dropped:
            near[certainty.OMITTED_FAR_END] = str(far["uid"])
    processes = [p for p in graph_input.processes if str(p["uid"]) not in dropped]
    sessions = [s for s in graph_input.sessions if str(s["process_uid"]) not in dropped]
    local_routes = [r for r in graph_input.local_routes if str(r["process_uid"]) not in dropped]
    attached = _policy_names(
        graph_input.sessions, graph_input.processes, graph_input.local_routes, graph_input.policies
    )
    kept = _policy_names(sessions, processes, local_routes, graph_input.policies)
    gone = dropped | {str(s["uid"]) for s in graph_input.sessions if str(s["process_uid"]) in dropped}
    gone |= attached - kept
    errors = ErrorSink()
    for fault in graph_input.errors.errors:
        if fault.subject not in gone:
            errors.report(fault.kind, fault.detail, fault.subject)
    return GraphInput(
        processes=processes,
        sessions=sessions,
        policies=graph_input.policies,
        local_routes=local_routes,
        platform=graph_input.platform,
        errors=errors,
        ambiguous_policies={k for k in graph_input.ambiguous_policies if k[2] not in gone},
    )


def ambiguous_contexts(graph_input: GraphInput) -> dict[str, list[str]]:
    """The ambiguous route policy names of each context, by context uid.

    A name is ambiguous when more than one RoutePolicy node defines it in the
    namespace where the process of the context resolves names
    (`compile.resolving_namespace`), or when the process reached it outside
    that namespace (`_report_foreign_policies`). `_dedupe_policies` keeps the
    first node by uid, and the rows of the engine for such a context are not
    established. A name that a process of the namespace attaches (a route map,
    closed over `calls_policy`) counts for the processes that attach it. A
    name that no process attaches (a prefix list, a community list or an
    AS-path list) counts for every process of the namespace.
    """
    contexts = context_namespaces(graph_input.policies)
    namespace_of = {
        str(p["uid"]): resolving_namespace(contexts, p.get("device_uid"), p.get("context_uid")) or ""
        for p in graph_input.processes
    }
    attached: dict[str, set[str]] = {}
    for process in graph_input.processes:
        uid = str(process["uid"])
        attached[uid] = _policy_names(
            [s for s in graph_input.sessions if str(s["process_uid"]) == uid],
            [process],
            [r for r in graph_input.local_routes if str(r["process_uid"]) == uid],
            graph_input.policies,
        )
    out: dict[str, set[str]] = defaultdict(set)
    for namespace, _kind, name in graph_input.ambiguous_policies:
        members = [p for p in graph_input.processes if namespace_of[str(p["uid"])] == namespace]
        direct = any(name in attached[str(p["uid"])] for p in members)
        for process in members:
            if direct and name not in attached[str(process["uid"])]:
                continue
            out[str(process["context_uid"])].add(name)
    return {context: sorted(names) for context, names in out.items()}


def mark_not_established(delta: RouteDelta, graph_input: GraphInput) -> None:
    """Set `not_established_because` on each row whose context `ambiguous_contexts` names."""
    affected = ambiguous_contexts(graph_input)
    for row in delta.rib:
        names = affected.get(str(row.get("context_uid")))
        if names:
            row["not_established_because"] = (
                "ambiguous-policy-name: "
                + ", ".join(repr(n) for n in names)
                + " is not defined by exactly one RoutePolicy node of this context's device or "
                "virtual system, so the policy the engine evaluated is not decided"
            )


def compute_route_delta(
    session: Any,
    *,
    device: str | None = None,
    vrf: str | None = None,
    platform: str = "iosxe",
) -> RouteDelta:
    """Provider 2 of the route-delta interface. It reads the pinned graph and runs the engine."""
    graph_input = read_simulation_input(session, device=device, vrf=vrf, platform=platform)
    delta = provider.compute_route_delta(
        processes=graph_input.processes,
        sessions=graph_input.sessions,
        policies=graph_input.policies,
        local_routes=graph_input.local_routes,
        platform=graph_input.platform,
    )
    delta.model_errors = graph_input.errors.as_dicts() + delta.model_errors
    mark_not_established(delta, graph_input)
    return delta


# --- the integrated routing calculation's input ------------------
#
# `hst.simul.rib.compute` takes a `RibInput` of plain dicts.

_CONTEXTS_OF_DEVICE = """
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT d:Retired
CALL {
  WITH d
  MATCH (v:VrfInstance)-[owner:OWNED_BY]->(d)
  WHERE owner._retired_at IS NULL
  RETURN v
  UNION
  WITH d
  MATCH (v:VrfInstance)<-[iv:IN_VRF]-(i:Interface)-[o:ON]->(d)
  WHERE iv._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired
    AND i.collection_ts = $snap
  RETURN v
}
WITH v
WHERE NOT v:Retired AND v.collection_ts = $snap
RETURN DISTINCT v.uid AS uid
ORDER BY uid"""

_SEED_BY_VRFS = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE v.uid IN $vrfs AND NOT rp:Retired AND NOT v:Retired AND iv._retired_at IS NULL
  AND toLower(coalesce(rp.proto, '')) = 'bgp'
  AND rp.collection_ts = $snap
RETURN DISTINCT rp.uid AS uid
ORDER BY uid"""

# A device-local context (a policy table, an empty VRF) has its owner on an
# OWNED_BY edge. `device_uids` holds each owner of a context.
_CONTEXTS = """
MATCH (v:VrfInstance:Obj)
WHERE v.uid IN $vrfs AND NOT v:Retired AND v.collection_ts = $snap
OPTIONAL MATCH (v)-[owner:OWNED_BY]->(od:Device)
WHERE owner._retired_at IS NULL AND NOT od:Retired
  AND od.collection_ts = $snap
OPTIONAL MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[o:ON]->(id:Device)
WHERE iv._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired AND NOT id:Retired
  AND i.collection_ts = $snap AND id.collection_ts = $snap
WITH v, collect(DISTINCT od) + collect(DISTINCT id) AS owners
UNWIND CASE WHEN size(owners) = 0 THEN [null] ELSE owners END AS d
RETURN v.uid AS uid, v.name AS name,
       collect(DISTINCT d.uid) AS device_uids,
       collect(DISTINCT d.platform) AS platforms,
       collect(DISTINCT d.vendor) AS vendors
ORDER BY v.uid"""

# The query reads the connected prefixes and the static routes of each
# context. A connected prefix is an `ORIGINATES` edge, returned with the
# interfaces that the reasoner marked as its gateway. A static route is a
# `STATIC_ROUTE` edge, returned with the next hop, the egress interface, the
# exporting context of a leaked next hop and the discard kind. The
# `_ROUTES_QUERY` of the tracer reads the same edges. The query skips the
# `ORIGINATES` edge of a BGP network or aggregate statement, which
# `_ORIGINATED` reads.
_CONTEXT_ROUTES = """
MATCH (v:VrfInstance:Obj)-[r:STATIC_ROUTE|ORIGINATES]->(p:Prefix)
WHERE v.uid IN $vrfs AND NOT v:Retired AND NOT p:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $snap
  AND NOT (type(r) = 'ORIGINATES' AND coalesce(r.proto, '') IN ['network', 'aggregate'])
OPTIONAL MATCH (gi:Interface)-[g:GATEWAY_FOR]->(p)
WHERE g._retired_at IS NULL AND NOT gi:Retired AND EXISTS { (gi)-[:IN_VRF]->(v) }
RETURN v.uid AS context_uid, p.cidr AS prefix, type(r) AS kind, r.proto AS proto,
       r.next_hop AS next_hop, coalesce(r.interface, r.rib_interface) AS interface,
       r.next_hop_vrf AS next_hop_context_uid, r.discard AS discard,
       collect(DISTINCT gi.name) AS gateways
ORDER BY context_uid, prefix, kind, next_hop, interface"""

_ACCESS_DEFAULTS = """
MATCH (i:Interface:Obj)-[iv:IN_VRF]->(v:VrfInstance), (i)-[ondev:ON]->(d:Device)
WHERE v.uid IN $vrfs AND NOT v:Retired AND NOT i:Retired AND NOT d:Retired
  AND iv._retired_at IS NULL AND ondev._retired_at IS NULL
  AND v.collection_ts = $snap
  AND i.collection_ts = $snap
  AND d.collection_ts = $snap
  AND i.ipv4_default_origin IN ['pppoe', 'dhcp']
RETURN DISTINCT v.uid AS context_uid, d.uid AS device_uid, i.name AS interface,
       i.ipv4_default_origin AS origin
ORDER BY context_uid, interface"""

_OSPF_PROCESSES = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE v.uid IN $vrfs AND iv._retired_at IS NULL AND NOT rp:Retired AND NOT v:Retired
  AND toLower(coalesce(rp.proto, '')) = 'ospf'
  AND rp.collection_ts = $snap
OPTIONAL MATCH (rp)-[h:HAS]->(a:OspfArea)
WHERE h._retired_at IS NULL AND NOT a:Retired
RETURN rp.uid AS uid, v.uid AS context_uid, properties(rp) AS props,
       collect(DISTINCT {area_id: a.area_id, type: a.type}) AS areas
ORDER BY rp.uid"""

# `_RT_EDGES` is `reasoner.RT_EDGES_AT_CYCLE_QUERY` bound to the `$snap` of the pinned session.
_RT_EDGES = """
MATCH (v:VrfInstance:Obj)-[r:IMPORTS|EXPORTS]->(rt:RouteTarget)
WHERE NOT v:Retired AND NOT rt:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $snap
RETURN v.uid AS vrf_uid, type(r) AS kind, rt.value AS rt
ORDER BY vrf_uid, kind, rt"""

# The query is the `PbrPolicy` read of `gates/pbr._pbr_partition` for a whole
# device. Each rule row has the enforcing interface and the context of that
# interface. The rule rows come from the fragment of the tracer
# (`gates/pbr._PBR_RULE_ROWS`), run per policy. The outer RETURN lists the
# columns of the fragment. tests/test_simul_read_pbr_bindings.py checks that
# the 2 lists are equal.
_PBR_BINDINGS = (
    """
MATCH (:Device:Obj {uid: $dev, collection_ts: $snap})<-[on:ON]-(i:Interface)-[e:ENFORCES]->(pol:PbrPolicy:Obj)
WHERE on._retired_at IS NULL AND NOT i:Retired
  AND NOT pol:Retired AND e._retired_at IS NULL AND pol.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(own:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT own:Retired
CALL {
WITH pol
"""
    + _pbr_gate._PBR_RULE_ROWS
    + """
}
RETURN DISTINCT i.uid AS if_uid, own.uid AS context_uid,
       pol_uid, pol_name, pol_af, rule_uid, pos, rule_name,
       src_cidrs, src_ips,
       dst_cidrs, dst_ips,
       src_ranges, dst_ranges, src_obj_count, dst_obj_count,
       table_uid, table_name,
       svc_obj_count, svc_protos, svc_port_specs, svc_opaque, svc_opaque_reasons, svc_src_port,
       svc_src_ports,
       states_opaque, states_opaque_reason, src_negate, dst_negate, addr_opaque_reasons
ORDER BY if_uid, pol_name, pos"""
)

_PBR_DEPENDENCIES = """
MATCH (d:Device)<-[on:ON]-(i:Interface)-[en:ENFORCES]->(pol:PbrPolicy:Obj)-[hr:HAS_RULE]->(r:FwRule)
      -[red:REDIRECTS_VIA]->(target:VrfInstance)
WHERE on._retired_at IS NULL AND en._retired_at IS NULL AND hr._retired_at IS NULL
  AND red._retired_at IS NULL AND NOT d:Retired AND NOT i:Retired AND NOT pol:Retired
  AND NOT r:Retired AND r.enabled AND NOT target:Retired
  AND pol.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(own:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT own:Retired
WITH d, i, own, target
WHERE own.uid IN $vrfs OR target.uid IN $vrfs OR EXISTS {
  MATCH (d)<-[on2:ON]-(:Interface)-[iv2:IN_VRF]->(seed:VrfInstance)
  WHERE on2._retired_at IS NULL AND iv2._retired_at IS NULL
    AND NOT seed:Retired AND seed.uid IN $vrfs
}
RETURN DISTINCT d.uid AS device_uid, i.uid AS if_uid,
       own.uid AS context_uid, target.uid AS target_context_uid
ORDER BY device_uid, if_uid, target_context_uid"""

_ROUTE_NEXT_HOP_CONTEXTS = """
MATCH (v:VrfInstance:Obj)-[r:STATIC_ROUTE]->(:Prefix)
WHERE v.uid IN $vrfs AND r._retired_at IS NULL AND NOT v:Retired
  AND r.next_hop IS NOT NULL AND v.collection_ts = $snap
MATCH (owner:Interface:Obj {collection_ts: $snap})-[has:HAS_IP]->(ip:IpAddress {ip: r.next_hop})
MATCH (owner)-[iv:IN_VRF]->(target:VrfInstance)
WHERE has._retired_at IS NULL AND iv._retired_at IS NULL
  AND NOT owner:Retired AND NOT ip:Retired AND NOT target:Retired
RETURN DISTINCT v.uid AS context_uid, target.uid AS target_context_uid
ORDER BY context_uid, target_context_uid"""

# The query returns the contexts whose static routes resolve in one of
# `$vrfs`, through `next_hop_vrf` or through the owner of the next-hop
# address. It is the inverse of `_ROUTE_NEXT_HOP_CONTEXTS`.
_NEXT_HOP_CONSUMERS = """
CALL {
  MATCH (v:VrfInstance:Obj)-[r:STATIC_ROUTE]->(:Prefix)
  WHERE r.next_hop_vrf IN $vrfs AND r._retired_at IS NULL AND NOT v:Retired
    AND v.collection_ts = $snap
  RETURN v
  UNION
  MATCH (target:VrfInstance:Obj)<-[iv:IN_VRF]-(owner:Interface)-[has:HAS_IP]->(ip:IpAddress)
  WHERE target.uid IN $vrfs AND iv._retired_at IS NULL AND has._retired_at IS NULL
    AND NOT target:Retired AND NOT owner:Retired AND NOT ip:Retired
    AND target.collection_ts = $snap
  MATCH (v:VrfInstance:Obj)-[r:STATIC_ROUTE]->(:Prefix)
  WHERE r.next_hop = ip.ip AND r._retired_at IS NULL AND NOT v:Retired
    AND v.collection_ts = $snap
  RETURN v
}
RETURN DISTINCT v.uid AS consumer_uid
ORDER BY consumer_uid"""

# The query returns the OSPF processes with one of `$router_ids` as their
# router id.
_OSPF_ROUTERS = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE rp.router_id IN $router_ids AND toLower(coalesce(rp.proto, '')) = 'ospf'
  AND iv._retired_at IS NULL AND NOT rp:Retired AND NOT v:Retired
  AND rp.collection_ts = $snap
RETURN rp.uid AS uid, v.uid AS context_uid, properties(rp) AS props
ORDER BY uid"""

# The query follows one adjacency hop out of a set of OSPF processes. The
# fixed point of the hops is the flooding domain.
_OSPF_NEIGHBOURS = """
MATCH (rp:RoutingProcess:Obj)-[h:HAS]->(adj:OspfAdjacency)
WHERE rp.uid IN $procs AND h._retired_at IS NULL AND NOT rp:Retired AND NOT adj:Retired
  AND rp.collection_ts = $snap
MATCH (far:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE far.router_id = adj.neighbor_router_id AND toLower(coalesce(far.proto, '')) = 'ospf'
  AND iv._retired_at IS NULL AND NOT far:Retired AND NOT v:Retired
  AND far.collection_ts = $snap
RETURN DISTINCT far.uid AS neighbour_uid, v.uid AS context_uid
ORDER BY neighbour_uid"""

_PROCESS_CONTEXTS = """
MATCH (rp:RoutingProcess:Obj)-[iv:IN_VRF]->(v:VrfInstance)
WHERE rp.uid IN $procs AND iv._retired_at IS NULL AND NOT rp:Retired AND NOT v:Retired
  AND rp.collection_ts = $snap
RETURN DISTINCT v.uid AS process_context_uid
ORDER BY process_context_uid"""

# The interval of every address of one address family, as 16-byte bounds.
# `RibSource.overlapping` with this interval and no prefix-length floor
# returns the whole table of a context.
_WHOLE_V4 = (bytes(10) + b"\xff\xff" + bytes(4), bytes(10) + b"\xff\xff" + b"\xff" * 4)
_WHOLE_V6 = (bytes(16), b"\xff" * 16)


@dataclass
class RibGraphInput:
    """The input of the integrated routing calculation from the graph and the
    side-store readers, with the faults that the read found. `scopes` holds
    the contexts that the caller asked for, before widening."""

    input: rib.RibInput
    scopes: list[str] = field(default_factory=list)
    errors: ErrorSink = field(default_factory=ErrorSink)


# The parts of a VyOS 1.3 configuration the collector leaves unread
# (collectors/vyos.py `legacy_unread`) that hold static routes missing from
# the STATIC_ROUTE edges.
_VYOS_UNREAD_STATICS = ("protocols static interface-route", "protocols vrf")


def _unread_static_config(session: Any, device_uid: str) -> str | None:
    """The reason that the graph lacks static routes of this device, or None.

    The manifest of the pinned run records the `config` section of a VyOS 1.3
    router as partial when the collector does not read its interface routes
    or its per-VRF statics. The detail of the section lists the unread parts.
    The graph holds none of those routes."""
    from hst.path.gates.coverage import _manifest_entries

    snapshot = getattr(session, "snapshot", None)
    manifest = getattr(snapshot, "manifest", None) if snapshot is not None else None
    if manifest is None:
        return None
    source_types = {source.name: str(source.type or "").lower() for source in manifest.sources}
    for entry in _manifest_entries(session, manifest, device_uid):
        if source_types.get(entry.source) != "vyos":
            continue
        section = entry.sections.get("config")
        detail = str(getattr(section, "detail", None) or "")
        if getattr(section, "status", None) != "partial":
            continue
        parts = [p.strip() for p in detail.split(":", 1)[-1].split(",")]
        unread = [p for p in parts if p.startswith(_VYOS_UNREAD_STATICS)]
        if unread:
            return (
                f"the collector did not read {', '.join(unread)} of this VyOS 1.3 configuration, "
                "so its static routes there are absent from the routing input"
            )
    return None


def _context_platform(row: Mapping[str, Any]) -> str | None:
    raw = _pick(row.get("platforms") or ()) or _pick(row.get("vendors") or ())
    return str(raw).strip().lower() if raw else None


def _observed_rib_afs(
    session: Any, device_uid: str, platform: str | None, coverage: str | None
) -> list[int] | None:
    """The address families for which absence from the observed RIB is evidence.

    The result comes from the manifest outcomes of the device. A complete
    empty IPv6 table and an uncollected IPv6 command both have no rows.
    """
    snapshot = getattr(session, "snapshot", None)
    manifest = snapshot.manifest if snapshot is not None else None
    if manifest is None:
        return None
    entries = [
        entry for entry in manifest.devices if device_uid in (getattr(entry, "device_uids", None) or ())
    ]
    if len(entries) != 1:
        return None
    entry = entries[0]
    raw_platform = str(platform or "").lower().replace("-", "").replace("_", "")
    if raw_platform == "apic" or "aci" in raw_platform:
        return []
    table_status = getattr(entry.tables.get("rib"), "status", None)
    if coverage is None or table_status is None:
        return None
    if coverage not in _COMPLETE_TABLE or table_status not in _COMPLETE_TABLE:
        return []
    if raw_platform in {"iosxe", "nxos", "iosxr"} or any(
        name in raw_platform for name in ("iosxe", "nxos", "iosxr")
    ):
        return [4]
    if raw_platform == "vyos":
        sections = entry.sections

        def complete(base: str) -> bool:
            if base not in sections or sections[base].status not in _COMPLETE_SECTION:
                return False
            table_prefix = f"{base}_table_"
            return all(
                outcome.status in _COMPLETE_SECTION
                for name, outcome in sections.items()
                if name.startswith(table_prefix)
            )

        families = []
        if complete("routes"):
            families.append(4)
        if complete("routes6"):
            families.append(6)
        return families
    return None


def _bgp_path_supported(row: Mapping[str, Any]) -> bool:
    """Whether one observed row has enough provenance to seed the IP RIB."""
    direction = str(row.get("direction") or "")
    expected_stage = {"received": "pre-import", "accepted": "post-import"}.get(direction)
    return (
        row.get("af") in (4, 6)
        and str(row.get("safi") or "").lower() == "unicast"
        and direction in {"received", "accepted", "advertised"}
        and (direction == "advertised" or row.get("policy_stage") == expected_stage)
    )


def _legacy_contexts(
    session: Any, device_uid: str, vrf: str, cache: dict[str, list[Mapping[str, Any]]]
) -> set[str]:
    """The contexts of one device whose observed rib rows the read matches by
    the `legacy_vrf` name of `RibSource.overlapping`. They are the contexts
    with the name `vrf` that have this device as their only device."""
    if device_uid not in cache:
        uids = sorted(str(r["uid"]) for r in pathmod._read(session, _CONTEXTS_OF_DEVICE, dev=device_uid))
        cache[device_uid] = list(pathmod._read(session, _CONTEXTS, vrfs=uids)) if uids else []
    return {
        str(row["uid"])
        for row in cache[device_uid]
        if row.get("name") == vrf
        and sorted({str(d) for d in (row.get("device_uids") or ()) if d}) == [device_uid]
    }


def _affected_contexts(
    session: Any,
    changed: set[str],
    ospf_routers: Sequence[str],
    importers_of: Mapping[str, set[str]],
    rib_source: Any | None = None,
    bgp_source: Any | None = None,
) -> set[str]:
    """The contexts that a change to `changed` and to the LSAs of the OSPF
    routers `ospf_routers` can alter. The result is the downstream closure of
    the change over the edges of `simul.certainty.dependencies`.

    The closure adds the contexts of the BGP peers of a changed process, the
    route-target importers of a changed exporter, and the contexts with a
    static route that resolves in a changed context. It adds the contexts of
    the flooding domain of a changed router and of a redistributing router,
    which the `OspfAdjacency` edges give. It adds a context whose observed rib
    rows (`rib_source`) or observed BGP paths (`bgp_source`) have a context of
    the closure as their next-hop context.
    """
    affected = set(changed)
    asked: set[str] = set()
    legacy: dict[str, list[Mapping[str, Any]]] = {}
    domain: set[str] = set()
    if ospf_routers:
        for row in pathmod._read(session, _OSPF_ROUTERS, router_ids=sorted({str(r) for r in ospf_routers})):
            affected.add(str(row["context_uid"]))
            domain.add(str(row["uid"]))
    followed: set[str] = set()
    while True:
        before = set(affected)
        seeds = [str(r["uid"]) for r in pathmod._read(session, _SEED_BY_VRFS, vrfs=sorted(affected))]
        if seeds:
            peers = [str(r["uid"]) for r in pathmod._read(session, _PEER_PROCESSES, procs=seeds)]
            if peers:
                affected.update(
                    str(r["process_context_uid"])
                    for r in pathmod._read(session, _PROCESS_CONTEXTS, procs=peers)
                    if r.get("process_context_uid")
                )
        for exporter in sorted(affected):
            affected.update(importers_of.get(exporter, ()))
        affected.update(
            str(r["consumer_uid"])
            for r in pathmod._read(session, _NEXT_HOP_CONSUMERS, vrfs=sorted(affected))
            if r.get("consumer_uid")
        )
        fresh = sorted(affected - asked)
        asked.update(fresh)
        if fresh and rib_source is not None:
            for device_uid, context_uid, vrf in rib_source.next_hop_context_consumers(fresh):
                if context_uid:
                    affected.add(str(context_uid))
                elif device_uid and vrf:
                    affected |= _legacy_contexts(session, str(device_uid), str(vrf), legacy)
        if fresh and bgp_source is not None:
            affected.update(
                str(context_uid)
                for _device_uid, context_uid in bgp_source.next_hop_context_consumers(fresh)
                if context_uid
            )
            bgp_source.close()
        for row in pathmod._read(session, _OSPF_PROCESSES, vrfs=sorted(affected)):
            if certainty.redistribute_statements(dict(row.get("props") or {})):
                domain.add(str(row["uid"]))
        frontier = domain - followed
        while frontier:
            followed |= frontier
            rows = pathmod._read(session, _OSPF_NEIGHBOURS, procs=sorted(frontier))
            affected.update(str(r["context_uid"]) for r in rows if r.get("context_uid"))
            frontier = {str(r["neighbour_uid"]) for r in rows if r.get("neighbour_uid")} - followed
        if affected == before:
            return affected


def _ospf_coverage(source: Any, device_uid: str, context_uid: str, rows: Sequence[Any]) -> str | None:
    """The coverage of the link-state database of one OSPF process, from the
    outcome of the device and the outcome of the context.

    An incomplete device outcome is returned as it is. Otherwise the outcome
    recorded for the context (`manifest.ospf_context_key`) decides, and
    `not-captured` becomes `not-observed`. Without a context outcome the rows
    decide. A context with rows gets the device outcome. A context without
    rows is `not-observed` when the device has no outcome or holds rows in
    another context. A database that was read has at least its own router
    LSA."""
    coverage: str | None = source.coverage(device_uid)
    if coverage is not None and coverage not in _COMPLETE_TABLE:
        return coverage
    recorded: str | None = source.context_coverage(context_uid)
    if recorded is not None:
        return "not-observed" if recorded == "not-captured" else recorded
    if rows:
        return coverage
    if coverage is None or source.contexts_with_rows(device_uid) - {context_uid}:
        return "not-observed"
    return coverage


@dataclass
class _Evidence:
    """The side-store observations of the contexts in scope. Each is read 1
    time as the closure grows. They are the context rows with the devices of
    each context, the BGP observations of each session, the database of each
    OSPF process and the observed rib rows of each context.

    The 3 readers share one store, and the first connection locks its
    configuration (`BgpSource.close`). Each pass reads them one after the
    other and closes the BGP reader and the OSPF reader. The caller keeps the
    RIB reader open for the trace.
    """

    session: Any
    rib_source: Any | None
    bgp_source: Any | None
    ospf_source: Any | None
    contexts: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    queried: set[str] = field(default_factory=set)
    paths: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    invalid_paths: dict[str, list[str]] = field(default_factory=dict)
    direction_status: dict[tuple[str, str], str | None] = field(default_factory=dict)
    session_state: dict[str, dict[str, Any]] = field(default_factory=dict)
    ospf: dict[str, dict[str, Any]] = field(default_factory=dict)
    ospf_read: set[str] = field(default_factory=set)
    routers: set[str] = field(default_factory=set)
    observed_rib: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    rib_coverage: dict[str, str | None] = field(default_factory=dict)
    rib_read: set[str] = field(default_factory=set)
    # The contexts whose observations resolve in each next-hop context, by next-hop context.
    required: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def device(self, context_uid: str | None) -> str | None:
        row = self.contexts.get(context_uid or "")
        if row is None:
            return None
        device_uids = sorted({str(d) for d in (row.get("device_uids") or ()) if d})
        return device_uids[0] if len(device_uids) == 1 else None

    def load_contexts(self, uids: Iterable[str]) -> None:
        fresh = sorted({str(u) for u in uids if u} - self.queried)
        if fresh:
            for row in pathmod._read(self.session, _CONTEXTS, vrfs=fresh):
                self.contexts[str(row["uid"])] = row
            self.queried.update(fresh)

    def load_sessions(self, sessions: Iterable[tuple[str, str | None]]) -> None:
        """Read the observations of each `(session uid, its context)` not
        read yet, then close the BGP reader."""
        if self.bgp_source is None:
            return
        pending = sorted({(str(uid), context) for uid, context in sessions if str(uid) not in self.paths})
        if not pending:
            return
        self.load_contexts(context for _uid, context in pending if context)
        for uid, session_context in pending:
            session_device = self.device(session_context)
            for direction in ("received", "accepted", "advertised"):
                self.direction_status[(uid, direction)] = self.bgp_source.direction_status(uid, direction)
            state = self.bgp_source.session_state(uid)
            if state is not None:
                self.session_state[uid] = dict(state)
            self.paths[uid] = []
            self.invalid_paths[uid] = []
            if not session_device:
                continue
            for raw in self.bgp_source.paths(session_device, session_context, session_uid=uid):
                row = dict(raw)
                if _bgp_path_supported(row):
                    self.paths[uid].append(row)
                    if row.get("next_hop_context_uid") and session_context:
                        self.required[str(row["next_hop_context_uid"])].add(session_context)
                else:
                    self.invalid_paths[uid].append(str(row.get("direction") or ""))
        self.bgp_source.close()

    def received_captured(self, uid: str) -> bool:
        """True when the calculation takes the received paths of the session
        from the observation (`rib._Run.observed_seeds`). The direction is
        recorded as captured, and no received row is invalid. `read_rib_input`
        records a direction with an invalid row as failed."""
        return self.direction_status.get(
            (uid, "received")
        ) in rib._CAPTURED and "received" not in self.invalid_paths.get(uid, ())

    def read(self, scope: set[str], bgp_input: GraphInput | None) -> dict[str, set[str]]:
        """Read the observations of the contexts and the sessions new to
        `scope`. Return each context that the evidence requires and `scope`
        lacks, with the contexts that require it."""
        required = self.required
        self.load_contexts(scope)

        if bgp_input is not None:
            context_of_process = {str(p["uid"]): str(p["context_uid"]) for p in bgp_input.processes}
            self.load_sessions(
                (str(s["uid"]), context_of_process.get(str(s.get("process_uid")))) for s in bgp_input.sessions
            )

        fresh = sorted(scope - self.ospf_read)
        if fresh:
            self.ospf_read.update(fresh)
            for row in pathmod._read(self.session, _OSPF_PROCESSES, vrfs=fresh):
                props = dict(row.get("props") or {})
                context_uid = str(row["context_uid"])
                process = props.get("process_id")
                entry: dict[str, Any] = {
                    **props,
                    "uid": str(row["uid"]),
                    "context_uid": context_uid,
                    "router_id": props.get("router_id"),
                    "process": str(process) if process else None,
                    "rows": [],
                    # The reader sets the coverage below. Without a reader the
                    # database is not observed.
                    "coverage": "not-observed",
                    "area_types": {
                        str(a["area_id"]): str(a["type"])
                        for a in (row.get("areas") or ())
                        if a and a.get("area_id") and a.get("type")
                    },
                }
                device_uid = self.device(context_uid)
                if self.ospf_source is not None and device_uid:
                    entry["rows"] = self.ospf_source.lsdb(device_uid, context_uid, process=entry["process"])
                    entry["coverage"] = _ospf_coverage(
                        self.ospf_source, device_uid, context_uid, entry["rows"]
                    )
                self.ospf[entry["uid"]] = entry
            if self.ospf_source is not None:
                self.ospf_source.close()
            # `rib._with_externals` replaces the type 5 LSAs of a
            # redistributing router in each database that holds its LSAs. The
            # context of the router is an input of the context of that database.
            holders: dict[str, set[str]] = defaultdict(set)
            for entry in self.ospf.values():
                for router in certainty.advertising_routers(entry):
                    holders[router].add(str(entry["context_uid"]))
            routers = sorted(set(holders) - self.routers)
            self.routers.update(routers)
            if routers:
                for row in pathmod._read(self.session, _OSPF_ROUTERS, router_ids=routers):
                    if certainty.redistribute_statements(dict(row.get("props") or {})):
                        router = str((row.get("props") or {}).get("router_id") or "")
                        required[str(row["context_uid"])].update(holders.get(router, ()))

        if self.rib_source is not None:
            for uid in sorted(scope - self.rib_read):
                self.rib_read.add(uid)
                device_uid = self.device(uid)
                if not device_uid:
                    continue
                name = self.contexts[uid].get("name")
                rows = []
                for lo, hi, af in ((*_WHOLE_V4, 4), (*_WHOLE_V6, 6)):
                    rows.extend(
                        self.rib_source.overlapping(
                            device_uid, uid, lo, hi, -1, af, legacy_vrf=str(name) if name else None
                        )
                    )
                self.observed_rib[uid] = sorted(
                    rows, key=lambda r: (str(r.get("prefix")), str(r.get("next_hop")))
                )
                self.rib_coverage[uid] = self.rib_source.coverage(device_uid)
                for row in rows:
                    if row.get("next_hop_context_uid"):
                        required[str(row["next_hop_context_uid"])].add(uid)
        return {target: sources for target, sources in required.items() if target not in scope}


def read_rib_input(
    session: Any,
    *,
    contexts: Sequence[str] = (),
    devices: Sequence[str] = (),
    changed: Sequence[str] = (),
    ospf_routers: Sequence[str] = (),
    rib_source: Any | None = None,
    bgp_source: Any | None = None,
    ospf_source: Any | None = None,
    platform: str = "iosxe",
) -> RibGraphInput:
    """Read the input of the integrated routing calculation from a pinned graph.

    `contexts` (VrfInstance uids) and `devices` (Device uids) set the scope.
    A device stands for every context that it owns or that its interfaces are
    in. `changed` holds the contexts that a change applies to. `ospf_routers`
    holds the OSPF router ids whose LSAs the change alters. Both are empty
    for a read of the snapshot as it is.

    The closure of the contexts that a change alters (`_affected_contexts`)
    joins the scope. The scope then grows to a fixed point over every context
    that the calculation reads to compute a context in it
    (`simul.certainty.dependencies`). These are the BGP peers, the exporters
    of a route target that an importer in scope takes, the leaked and the
    structurally resolved next-hop contexts, the next-hop contexts of observed
    BGP paths and rib rows, the redistributing OSPF routers whose LSAs a
    database in scope holds, and the PBR redirect targets. The far end of a
    session is left out when its received paths are captured and no change
    can alter the context of the session. The calculation reads the
    observation for that session, and the session is marked
    `certainty.OMITTED_FAR_END`. A context that only consumes what the scope
    produces, such as a route-target importer outside the closure, is not
    read. The rows, the validation and the gaps of every context in the scope
    are those of a read of the whole snapshot, except for a route policy name
    that 2 RoutePolicy nodes define in one namespace.

    `rib_source`, `bgp_source` and `ospf_source` are the 3 side-store readers
    bound to the same snapshot as `session` (`for_snapshot`). Each is
    optional. The engine reports the observations of an absent reader as not
    supplied.
    """
    errors = ErrorSink()
    scope: set[str] = {str(c) for c in (*contexts, *changed) if c}
    for device in sorted({str(d) for d in devices if d}):
        scope.update(str(r["uid"]) for r in pathmod._read(session, _CONTEXTS_OF_DEVICE, dev=device))
    requested = sorted(scope)
    routers = sorted({str(r) for r in ospf_routers if r})
    if not scope and not routers:
        errors.report(
            "no-context-in-scope",
            "no forwarding context is in scope: nothing names a VrfInstance, and no device named "
            "has an interface in one",
            None,
        )
        return RibGraphInput(rib.RibInput(platform=platform), requested, errors)

    topology = reasoner.pair_and_group(pathmod._read(session, _RT_EDGES))
    importers_of: dict[str, set[str]] = defaultdict(set)
    exporters_of: dict[str, set[str]] = defaultdict(set)
    for pair in topology.pairs:
        importers_of[pair.exporter].add(pair.importer)
        exporters_of[pair.importer].add(pair.exporter)
    affected: set[str] = set()
    if changed or routers:
        affected = _affected_contexts(
            session, {str(c) for c in changed if c}, routers, importers_of, rib_source, bgp_source
        )
        scope |= affected

    # The contexts in scope whose calculation reads each context, by context.
    required_by: dict[str, set[str]] = defaultdict(set)

    def require(target: Any, source: Any) -> None:
        if target:
            if source:
                required_by[str(target)].add(str(source))
            scope.add(str(target))

    evidence = _Evidence(session, rib_source, bgp_source, ospf_source)

    def omitted(offered: list[tuple[dict[str, Any], dict[str, Any], str]]) -> set[str]:
        # The far end is left out for a session with captured received paths
        # in a context that no change can alter. The calculation reads the
        # observation for that session. Inside the closure of a change the
        # calculation recomputes the paths from the far end.
        outside = [(near, context) for near, _far, context in offered if context not in affected]
        evidence.load_sessions((str(near["uid"]), context) for near, context in outside)
        return {
            str(near["uid"]) for near, _context in outside if evidence.received_captured(str(near["uid"]))
        }

    bgp_input: GraphInput | None = None
    bgp_errors = ErrorSink()
    pbr_devices: set[str] = set()
    route_rows: Sequence[Mapping[str, Any]] = []
    while True:
        settled = set(scope)
        # The inner loop adds the dependencies in the graph, to a fixed point.
        while True:
            before = set(scope)
            seeds = [str(r["uid"]) for r in pathmod._read(session, _SEED_BY_VRFS, vrfs=sorted(scope))]
            bgp_errors = ErrorSink()
            bgp_input = None
            if seeds:
                bgp_input = _omit_far_ends(
                    _read_bgp(session, seeds, platform, bgp_errors, infer_origins=False), seeds, omitted
                )
                bgp_errors = bgp_input.errors
            if bgp_input is not None:
                scope.update(str(p["context_uid"]) for p in bgp_input.processes)
            for importer in sorted(scope):
                for exporter in sorted(exporters_of.get(importer, ())):
                    require(exporter, importer)
            route_rows = pathmod._read(session, _CONTEXT_ROUTES, vrfs=sorted(scope))
            for row in route_rows:
                require(row.get("next_hop_context_uid"), row.get("context_uid"))
            for row in pathmod._read(session, _ROUTE_NEXT_HOP_CONTEXTS, vrfs=sorted(scope)):
                require(row.get("target_context_uid"), row.get("context_uid"))
            for row in pathmod._read(session, _PBR_DEPENDENCIES, vrfs=sorted(scope)):
                require(row.get("target_context_uid"), row.get("context_uid"))
                if row.get("device_uid"):
                    pbr_devices.add(str(row["device_uid"]))
            if scope == before:
                break
        # `evidence.read` returns the contexts that the side-store observations require.
        for target, sources in sorted(evidence.read(scope, bgp_input).items()):
            for source in sorted(sources):
                require(target, source)
        if scope == settled:
            break
    # The last pass read the closed scope. Its BGP faults are the faults of
    # the read.
    for fault in bgp_errors.errors:
        errors.report(fault.kind, fault.detail, fault.subject)

    pairs = [p for p in topology.pairs if p.importer in scope and p.exporter in scope]

    context_rows = [evidence.contexts[uid] for uid in sorted(scope) if uid in evidence.contexts]
    context_list: list[dict[str, Any]] = []
    device_of: dict[str, str | None] = {}
    name_of: dict[str, str | None] = {}
    observation_gaps: list[dict[str, Any]] = []
    unread_statics: dict[str, str | None] = {}
    for row in context_rows:
        uid = str(row["uid"])
        device_uids = sorted({str(d) for d in (row.get("device_uids") or ()) if d})
        device_uid = device_uids[0] if len(device_uids) == 1 else None
        device_of[uid] = device_uid
        name_of[uid] = str(row["name"]) if row.get("name") else None
        context_list.append(
            {
                "uid": uid,
                "name": name_of[uid],
                "device_uid": device_uid,
                "device_uids": device_uids,
                "platform": _context_platform(row),
            }
        )
        if len(device_uids) > 1:
            detail = (
                f"{uid} spans devices {', '.join(device_uids)}; device-keyed RIB, OSPF and BGP "
                "observations cannot be attributed to the shared context without provenance"
            )
            errors.report("context-observation-ambiguous", detail, uid)
            observation_gaps.append({"kind": "not-observed", "context_uid": uid, "detail": detail})
        elif device_uid is None:
            detail = (
                f"{uid} has no recorded owning Device or interface on a Device in this snapshot, "
                "so its observed rib rows, "
                "link-state database and BGP observations cannot be read"
            )
            errors.report(
                "context-has-no-device",
                detail,
                uid,
            )
            observation_gaps.append({"kind": "not-observed", "context_uid": uid, "detail": detail})
        for owner in device_uids:
            if owner not in unread_statics:
                unread_statics[owner] = _unread_static_config(session, owner)
            if unread_statics[owner]:
                detail = f"{uid} on {owner}: {unread_statics[owner]}"
                errors.report("static-config-not-read", detail, uid)
                observation_gaps.append({"kind": "not-observed", "context_uid": uid, "detail": detail})

    found_contexts = {str(context["uid"]) for context in context_list}
    for uid in sorted(scope - found_contexts):
        detail = f"forwarding context {uid} was required by scope closure but is absent from the snapshot"
        # The subject of the error is each context that reads the missing context.
        for subject in sorted(required_by.get(uid, set()) & found_contexts) or [uid]:
            errors.report("required-context-missing", detail, subject)
        observation_gaps.append({"kind": "not-observed", "context_uid": uid, "detail": detail})

    connected: list[dict[str, Any]] = []
    static: list[dict[str, Any]] = []
    for row in route_rows:
        entry = {
            "context_uid": str(row["context_uid"]),
            "prefix": row["prefix"],
            "interface": row.get("interface"),
        }
        if str(row.get("kind")) == "ORIGINATES":
            gateways = sorted(str(g) for g in (row.get("gateways") or ()) if g)
            connected.append(
                {**entry, "interface": entry["interface"] or (gateways[0] if gateways else None)}
            )
        else:
            static.append(
                {
                    **entry,
                    "next_hop": row.get("next_hop"),
                    "next_hop_context_uid": row.get("next_hop_context_uid"),
                    "discard": row.get("discard"),
                }
            )

    ospf_entries = [
        evidence.ospf[uid] for uid in sorted(evidence.ospf) if str(evidence.ospf[uid]["context_uid"]) in scope
    ]

    observed_paths: list[dict[str, Any]] = []
    direction_status: dict[tuple[str, str], str | None] = {}
    session_state: dict[str, dict[str, Any]] = {}
    if bgp_input is not None and bgp_source is not None:
        context_of_process = {str(p["uid"]): str(p["context_uid"]) for p in bgp_input.processes}
        for bgp_session in sorted(bgp_input.sessions, key=lambda s: str(s["uid"])):
            uid = str(bgp_session["uid"])
            session_context = context_of_process.get(str(bgp_session.get("process_uid")))
            for direction in ("received", "accepted", "advertised"):
                direction_status[(uid, direction)] = evidence.direction_status.get((uid, direction))
            if uid in evidence.session_state:
                session_state[uid] = evidence.session_state[uid]
            observed_paths.extend(evidence.paths.get(uid, ()))
            for direction in evidence.invalid_paths.get(uid, ()):
                detail = (
                    f"session {uid} has a BGP path without a supported AF, unicast SAFI, "
                    "direction and policy stage; it was not used as route evidence"
                )
                errors.report("bgp-path-provenance-invalid", detail, uid)
                if direction in {"received", "accepted", "advertised"}:
                    direction_status[(uid, direction)] = "failed"
                observation_gaps.append(
                    {"kind": "not-observed", "context_uid": session_context or "", "detail": detail}
                )

    observed_rib: dict[str, list[dict[str, Any]]] = {}
    rib_coverage: dict[str, str | None] = {
        str(context["uid"]): "ambiguous-device"
        for context in context_list
        if len(context.get("device_uids") or ()) > 1
    }
    if rib_source is not None:
        for context in context_list:
            uid = context["uid"]
            if context["device_uid"] and uid in evidence.observed_rib:
                observed_rib[uid] = evidence.observed_rib[uid]
                rib_coverage[uid] = evidence.rib_coverage.get(uid)
    for context in context_list:
        device_uid = context.get("device_uid")
        context["observed_rib_afs"] = (
            _observed_rib_afs(
                session,
                str(device_uid),
                context.get("platform"),
                rib_coverage.get(str(context["uid"])),
            )
            if device_uid
            else None
        )

    pbr: list[dict[str, Any]] = []
    for device_uid in sorted({d for d in device_of.values() if d} | pbr_devices):
        by_interface: dict[str, dict[str, Any]] = {}
        for row in pathmod._read(session, _PBR_BINDINGS, dev=device_uid):
            binding = by_interface.setdefault(
                str(row["if_uid"]),
                {
                    "if_uid": str(row["if_uid"]),
                    "device_uid": device_uid,
                    "context_uid": row.get("context_uid"),
                    "rules": [],
                },
            )
            binding["rules"].append({k: v for k, v in row.items() if k not in ("if_uid", "context_uid")})
        pbr.extend(by_interface[k] for k in sorted(by_interface))

    engine_input = rib.RibInput(
        contexts=context_list,
        connected=connected,
        static=static,
        access_defaults=[
            dict(row)
            for row in pathmod._read(session, _ACCESS_DEFAULTS, vrfs=sorted(scope))
            if row.get("device_uid") == device_of.get(str(row["context_uid"])) and row.get("device_uid")
        ],
        ospf=ospf_entries,
        bgp=bgp_input.to_simulation_input() if bgp_input is not None else None,
        observed_paths=observed_paths,
        direction_status=direction_status,
        session_state=session_state,
        rt_pairs=[{"importer": p.importer, "exporter": p.exporter, "via_rt": list(p.via_rt)} for p in pairs],
        pbr=pbr,
        observed_rib=observed_rib,
        rib_coverage=rib_coverage,
        observation_gaps=observation_gaps,
        platform=platform,
    )
    # The import is local because proof's public types include RibInput.
    from hst.simul import proof

    compiler_gaps = []
    for context_uid, faults in proof.affected_contexts(engine_input, errors.as_dicts()).items():
        for error in faults:
            detail = f"{error['kind']}: {error['detail']}"
            if any(
                gap.get("context_uid") == context_uid and gap.get("detail") == detail
                for gap in engine_input.observation_gaps
            ):
                continue
            compiler_gaps.append(
                {
                    "kind": "not-observed",
                    "context_uid": context_uid,
                    "detail": detail,
                    "model_error_kind": error["kind"],
                    "subject": error["subject"],
                }
            )
    engine_input.observation_gaps = [*engine_input.observation_gaps, *compiler_gaps]
    return RibGraphInput(engine_input, requested, errors)
