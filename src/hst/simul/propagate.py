"""Propagation to a fixed point over a set of BGP processes and sessions.

This module models the BGP part of a round. Redistribution from the main RIB, next-hop
resolution, cross-VRF leaking and the push back into the main RIB need the main RIB
of `simul/rib.py`. The main RIB reaches this module through two inputs. The caller
supplies the locally originated routes, which are its `network` statements and the
routes that it redistributed. The `resolver` answers, for the context of one process,
whether the next hop of a candidate resolves in the main RIB and at what IGP cost.
Without a resolver every next hop resolves. The engine does not reproduce the
node-parallel scheduler, the oscillation detection or the iteration-hashcode
bookkeeping of Batfish.

Two kinds of input seed the candidate set of a process before the first round.

`local_routes` holds the locally originated routes.

`seeds` holds the observed adj-RIB-in rows of a session whose received or accepted
direction the snapshot captured (`core/bgpsource.py`), and the routes leaked from
another forwarding context. A seed at the `pre-import` stage runs the import
processing of the session as an advertisement does. A seed at the `post-import`
stage is a route that the device already admitted. It is merged without import
processing.

The snapshot supplies the received paths of a session in `observed_sessions`. No
advertisement is propagated across that session from a far end in the input.

The iteration order is fixed at every level (processes by uid, sessions by uid,
prefixes by string, candidates by insertion). Two runs over the same input
produce byte-identical rows.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import bestpath, platforms
from .compile import compile_policies, context_namespaces, resolving_namespace, scoped_policies
from .convergence import ConvergenceBudget, RepeatedStateDetector, freeze
from .errors import ErrorSink
from .policy import Policy
from .route import DEFAULT_LOCAL_PREFERENCE, DEFAULT_LOCAL_WEIGHT, Route

# `(context_uid, route) -> igp cost`, or None when the route's next hop does
# not resolve in that context (or in the route's own `next_hop_context_uid`).
Resolver = Callable[[str, Route], "int | None"]

PRE_IMPORT = "pre-import"
POST_IMPORT = "post-import"

# A round that changes nothing ends the run.
MAX_ROUNDS = 64


@dataclass
class SimulationInput:
    """The input of the engine. The rows are plain dicts in the shape of the
    schema nodes."""

    processes: Sequence[Mapping[str, Any]] = ()
    sessions: Sequence[Mapping[str, Any]] = ()
    policies: Sequence[Mapping[str, Any]] = ()
    local_routes: Sequence[Mapping[str, Any]] = ()
    platform: str = platforms.IOSXE
    # Observed adj-RIB-in rows and leaked routes. Each row holds the
    # `process_uid` that it seeds, its `session_uid`, its `stage` (`pre-import`
    # or `post-import`) and the attributes of the path.
    seeds: Sequence[Mapping[str, Any]] = ()
    # The uids of the sessions whose received paths the snapshot supplies. No
    # advertisement is propagated across them from a far end in the input.
    observed_sessions: Sequence[str] = ()


@dataclass
class RouteDelta:
    """The output of the route-delta provider.

    `rib` holds the per-VRF RIB rows keyed by `context_uid`. `model_errors`
    holds every model error of the run.

    `selected` holds the same selection as `Route` objects, keyed by
    `context_uid`. `simul/rib.py` composes a main RIB from them. `unresolved`
    holds every candidate that a resolver refused. The process holds such a
    path and cannot use it.

    `history_dependent` holds every prefix whose selection the arrival-order
    tie-break decided. Arrival order is the message history of the real
    network. `selected` holds one of its stable outcomes.
    """

    rib: list[dict[str, Any]] = field(default_factory=list)
    model_errors: list[dict[str, str | None]] = field(default_factory=list)
    # The count of rounds, including the final round that changed nothing. It
    # equals the round budget (`MAX_ROUNDS` by default) when the run did not
    # settle within the budget.
    rounds: int = 0
    selected: dict[str, list[Route]] = field(default_factory=dict)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    history_dependent: list[dict[str, Any]] = field(default_factory=list)
    # Every (process, session, prefix) that a `summary-only` aggregate kept out
    # of an advertisement, with the aggregate. The route stays in the table of
    # the process.
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    # The paths that a process in multipath mode installs beside each selected
    # best path (`_multipath`), keyed by `context_uid`. Only the best path is
    # advertised.
    multipath: dict[str, list[Route]] = field(default_factory=dict)
    # Every prefix with more than one equal path on a process whose
    # `maximum-paths` is not known.
    multipath_unknown: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _Process:
    node: Mapping[str, Any]
    platform: str
    policies: dict[str, Policy]
    prefix_lists: dict[str, list[dict[str, Any]]]
    rib: dict[str, list[Route]] = field(default_factory=dict)
    # The prefixes of the `summary-only` aggregates of the process. While such
    # an aggregate is in the table, every more-specific route is held back from
    # advertisement (`aggregate-address ... summary-only` on Cisco and FRR).
    summary_only: set[str] = field(default_factory=set)

    @property
    def uid(self) -> str:
        return str(self.node["uid"])

    @property
    def context_uid(self) -> str:
        return str(self.node["context_uid"])

    @property
    def asn(self) -> int:
        return int(self.node["asn"])

    @property
    def router_id(self) -> str | None:
        rid = self.node.get("router_id")
        return str(rid) if rid else None

    @property
    def always_compare_med(self) -> bool:
        return bool(self.node.get("always_compare_med"))

    @property
    def multipath_relax(self) -> bool:
        return bool(self.node.get("multipath_relax"))

    def maximum_paths(self, session_type: str, family: int) -> int | None:
        """The count of equal paths of `session_type` (ebgp or ibgp) that the
        process installs for a prefix of `family`.

        The count is the configured `maximum-paths`, or the platform default
        when none is configured. The count is None when the collector did not
        record the multipath configuration (`multipath_config_recorded`)."""
        if not self.node.get("multipath_config_recorded"):
            return None
        configured = self.node.get(f"maximum_paths_{session_type}_v{family}")
        if type(configured) is int and configured >= 1:
            return configured
        return platforms.bgp_maximum_paths(self.platform)


def _seed_route(row: Mapping[str, Any]) -> Route:
    """A locally originated route.

    The weight is the `weight` of the row, or the IOS default 32768 of a locally
    originated or redistributed route.
    """
    return Route(
        prefix=str(row["prefix"]),
        next_hop=row.get("next_hop"),
        protocol="bgp",
        src_protocol=row.get("src_protocol"),
        origin_mechanism=str(row.get("origin_mechanism") or "network"),
        local_pref=int(row.get("local_pref", 100)),
        med=row.get("med"),
        weight=int(row.get("weight", DEFAULT_LOCAL_WEIGHT)),
        as_path=_as_path(row.get("as_path")),
        origin=str(row.get("origin") or "igp"),
        tag=row.get("tag"),
        communities=_communities(row.get("communities")),
        originator_ip=row.get("originator_ip"),
        next_hop_context_uid=row.get("next_hop_context_uid"),
    )


def _as_path(value: Any) -> tuple[int, ...]:
    """An AS path from a sequence of numbers or from the space-separated
    string that the side store holds (`bgp_session_routes.as_path`). The braces
    and the commas of an AS set are dropped, and the path is flat."""
    if value is None:
        return ()
    if isinstance(value, str):
        tokens = value.replace("{", " ").replace("}", " ").replace(",", " ").split()
    else:
        tokens = [str(v) for v in value]
    out = []
    for token in tokens:
        try:
            out.append(int(token))
        except ValueError:
            continue
    return tuple(out)


def _communities(value: Any) -> frozenset[str]:
    """Communities from a sequence or from the space-separated string that the
    side store holds (`bgp_session_routes.communities`)."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset(value.split())
    return frozenset(str(c) for c in value)


def _seed_from_observation(
    row: Mapping[str, Any],
    session: Mapping[str, Any] | None,
    process: _Process,
    errors: ErrorSink,
) -> Route | None:
    """One `seeds` row as a candidate in the RIB of the receiving process.

    A `pre-import` row is a path that the peer sent (adj-RIB-in). It goes
    through `import_route` with the session that it arrived on. A `post-import`
    row is a path that the device already admitted (loc-RIB) or a route leaked
    from another context. It is merged without import processing. Its protocol
    and administrative distance come from the session type, or from the row
    when the row has no session.
    """
    stage = str(row.get("stage") or PRE_IMPORT)
    session_uid = row.get("session_uid")
    route = Route(
        prefix=str(row["prefix"]),
        next_hop=row.get("next_hop"),
        protocol="bgp",
        src_protocol=row.get("src_protocol"),
        origin_mechanism=str(row.get("origin_mechanism") or "learned"),
        local_pref=int(row["local_pref"]) if row.get("local_pref") is not None else DEFAULT_LOCAL_PREFERENCE,
        med=int(row["med"]) if row.get("med") is not None else None,
        weight=int(row.get("weight") or 0),
        as_path=_as_path(row.get("as_path")),
        origin=str(row.get("origin") or "igp").lower(),
        communities=_communities(row.get("communities")),
        originator_ip=row.get("originator_ip"),
        next_hop_context_uid=row.get("next_hop_context_uid"),
        leak_path=tuple(str(c) for c in (row.get("leak_path") or ())),
        learned_from_session=str(session_uid) if session_uid else None,
    )
    if stage == PRE_IMPORT:
        if session is None:
            errors.report(
                "seed-without-session",
                f"an observed path for {route.prefix} names session {session_uid!r}, which is not "
                f"a BgpSession of process {process.uid} in the input; the path was left out",
                str(session_uid),
            )
            return None
        return bestpath.import_route(
            route,
            session,
            platform=process.platform,
            local_asn=process.asn,
            policies=process.policies,
            prefix_lists=process.prefix_lists,
            errors=errors,
        )
    if session is not None:
        stype = bestpath.session_type(session)
        protocol = "bgp" if stype == bestpath.EBGP else "ibgp"
        admin = session.get("admin")
        if admin is None:
            admin = bestpath.DEFAULT_EBGP_ADMIN if stype == bestpath.EBGP else bestpath.DEFAULT_IBGP_ADMIN
        peer_ip = session.get("peer_ip")
        return route.with_(
            protocol=protocol,
            admin=int(admin),
            received_from_kind="ip" if peer_ip else "interface",
            received_from_ip=peer_ip,
            src_protocol=route.src_protocol or protocol,
        )
    protocol = str(row.get("session_protocol") or "bgp")
    admin = row.get("admin")
    return route.with_(
        protocol=protocol,
        admin=int(admin) if admin is not None else None,
        src_protocol=route.src_protocol or protocol,
    )


def _session_carries(sender: Mapping[str, Any], receiver: Mapping[str, Any]) -> bool:
    """Whether an advertisement can cross a peering.

    A side that is shut down in the configuration blocks the advertisement. A
    side whose observed state (`bgp_sessions.state`, in `observed_state`) is
    not established blocks it."""
    for session in (sender, receiver):
        if str(session.get("state", "")).lower() == "shutdown":
            return False
        observed = session.get("observed_state")
        if observed is not None and str(observed).strip().lower() != "established":
            return False
    return True


def _report_unknown_reflection(
    sessions: Sequence[Mapping[str, Any]], processes: Mapping[str, Any], errors: ErrorSink
) -> None:
    """Report each process whose iBGP reflection the input cannot decide.

    A route learned over iBGP is exported to another iBGP peer only when it is
    reflected. Reflection depends on the `route_reflector_client` of each
    session (`bestpath.is_reflectable`). A collector writes it true or false,
    and a session can lack it. A process with two or more iBGP sessions, at
    least one of them without the setting, is reported
    (`proof.UNCERTAIN_KINDS`). A process with one iBGP session reflects
    nothing."""
    ibgp: dict[str, list[Mapping[str, Any]]] = {}
    for session in sessions:
        process_uid = str(session.get("process_uid"))
        if process_uid in processes and bestpath.session_type(session) == bestpath.IBGP:
            ibgp.setdefault(process_uid, []).append(session)
    for process_uid, held in sorted(ibgp.items()):
        unknown = sorted(str(s.get("uid")) for s in held if s.get("route_reflector_client") is None)
        if len(held) < 2 or not unknown:
            continue
        errors.report(
            "bgp-reflection-unknown",
            f"BGP process {process_uid} has {len(held)} iBGP sessions and the route-reflector-client "
            f"setting of {', '.join(unknown)} is not recorded; the routes it would reflect between "
            "iBGP peers are not computed",
            process_uid,
        )


def _pair_sessions(
    sessions: Sequence[Mapping[str, Any]], errors: ErrorSink, observed: set[str] | None = None
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Match each session node with the session node of the far end.

    The graph holds one `BgpSession` per process per peering. A peering is the
    pair of sessions whose local and peer addresses mirror each other. A
    session with no far end in the input is reported. A session whose received
    paths the snapshot observed (`observed`) and a session that is shut down
    are not reported.
    """
    by_endpoints = {(s.get("local_ip"), s.get("peer_ip")): s for s in sessions}
    pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for session in sorted(sessions, key=lambda s: str(s.get("uid"))):
        far = by_endpoints.get((session.get("peer_ip"), session.get("local_ip")))
        if far is None:
            if observed and str(session.get("uid")) in observed:
                continue
            if str(session.get("state", "")).lower() == "shutdown":
                continue
            errors.report(
                "unpaired-bgp-session",
                f"session {session.get('uid')} has no far-end BgpSession node in the "
                "input, so no advertisement can be computed across it",
                str(session.get("uid")),
            )
            continue
        pairs.append((session, far))
    return pairs


def _merge(rib: dict[str, list[Route]], route: Route) -> bool:
    """Add a route to a per-prefix candidate set. Returns whether it changed."""
    candidates = rib.setdefault(route.prefix, [])
    # The session that a path arrived on is its identity. One session
    # contributes at most one path per prefix. A re-advertisement with other
    # attributes replaces the path.
    for index, existing in enumerate(candidates):
        if existing.learned_from_session == route.learned_from_session:
            # A re-advertisement that differs only in `arrival` is the same
            # path. The existing route stays with its arrival number.
            if existing.with_(arrival=route.arrival) == route:
                return False
            candidates[index] = route
            return True
    candidates.append(route)
    return True


def _withdraw(rib: dict[str, list[Route]], session_uid: str, keep: set[str], held: set[str]) -> set[str]:
    """Drop the paths that the session stopped advertising.

    `held` is every prefix that holds a path from the session. Only those
    prefixes are visited. On return `held` has only the prefixes in `keep`.
    Returns the prefixes that changed."""
    dropped: set[str] = set()
    for prefix in sorted(held - keep):
        remaining = [r for r in rib[prefix] if r.learned_from_session != session_uid]
        if len(remaining) != len(rib[prefix]):
            rib[prefix] = remaining
            dropped.add(prefix)
    held &= keep
    return dropped


def run(
    inp: SimulationInput,
    errors: ErrorSink | None = None,
    *,
    resolver: Resolver | None = None,
    budget: ConvergenceBudget | None = None,
) -> RouteDelta:
    """Propagate to a fixed point and return the predicted per-VRF RIB rows.

    `resolver` gives the answer of the main RIB for the next hop of a
    candidate. A candidate that it refuses is not selected, not exported and
    not installed. `RouteDelta.unresolved` lists it.
    """
    errors = errors or ErrorSink()
    budget = budget or ConvergenceBudget(bgp_rounds=MAX_ROUNDS)
    default_platform = platforms.normalize(inp.platform, errors)

    processes: dict[str, _Process] = {}
    # The processes of one policy namespace (a device, or a Check Point
    # virtual system's context) on one platform compile the same policies.
    compiled_for: dict[tuple[Any, str], tuple[dict[str, Policy], dict[str, list[dict[str, Any]]]]] = {}
    contexts = context_namespaces(inp.policies)
    for node in sorted(inp.processes, key=lambda n: str(n["uid"])):
        if str(node.get("proto", "")).lower() != "bgp":
            continue
        platform = platforms.normalize(node.get("platform") or default_platform, errors)
        scope = (resolving_namespace(contexts, node.get("device_uid"), node.get("context_uid")), platform)
        if scope not in compiled_for:
            compiled_for[scope] = compile_policies(scoped_policies(inp.policies, scope[0]), platform, errors)
        compiled, prefix_lists = compiled_for[scope]
        processes[str(node["uid"])] = _Process(
            node=node, platform=platform, policies=compiled, prefix_lists=prefix_lists
        )

    for row in inp.local_routes:
        owner = processes.get(str(row["process_uid"]))
        if owner is None:
            errors.report(
                "unknown-origination-process",
                f"a locally originated route names process {row['process_uid']!r}, "
                "which is not a BGP RoutingProcess in the input",
                str(row["process_uid"]),
            )
            continue
        _merge(owner.rib, _seed_route(row))
        if str(row.get("origin_mechanism") or "") == "aggregate" and row.get("summary_only"):
            owner.summary_only.add(str(row["prefix"]))

    # Maps (process uid, session uid) to the first session node with that pair.
    session_of: dict[tuple[str, str], Mapping[str, Any]] = {}
    for session in inp.sessions:
        session_of.setdefault((str(session.get("process_uid")), str(session.get("uid"))), session)
    observed = {str(uid) for uid in inp.observed_sessions}
    pairs = _pair_sessions(inp.sessions, errors, observed)
    _report_unknown_reflection(inp.sessions, processes, errors)

    # Seeds get their arrival numbers in input order.
    arrival = 0
    for row in inp.seeds:
        owner = processes.get(str(row.get("process_uid")))
        if owner is None:
            errors.report(
                "unknown-seed-process",
                f"a seed for {row.get('prefix')!r} names process {row.get('process_uid')!r}, "
                "which is not a BGP RoutingProcess in the input",
                str(row.get("process_uid")),
            )
            continue
        seed_session = _session_by_uid(session_of, owner.uid, row.get("session_uid"))
        route = _seed_from_observation(row, seed_session, owner, errors)
        if route is None:
            continue
        if _merge(owner.rib, route.with_(arrival=arrival + 1)):
            arrival += 1

    unresolved: dict[tuple[str, str, str, str | None], dict[str, Any]] = {}
    suppressed: dict[tuple[str, str, str], dict[str, Any]] = {}

    def resolve_for(process: _Process) -> bestpath.Resolver | None:
        if resolver is None:
            return None

        def resolve(route: Route) -> int | None:
            cost = resolver(process.context_uid, route)
            if cost is None:
                key = (process.uid, route.prefix, str(route.next_hop), route.learned_from_session)
                unresolved.setdefault(
                    key,
                    {
                        "process_uid": process.uid,
                        "context_uid": process.context_uid,
                        "prefix": route.prefix,
                        "next_hop": route.next_hop,
                        "next_hop_context_uid": route.next_hop_context_uid or process.context_uid,
                        "session_uid": route.learned_from_session,
                    },
                )
            return cost

        return resolve

    # The best path of each (process, prefix) within one round. An entry is
    # dropped when the candidate set of its prefix changes. The cache is
    # cleared at the start of each round.
    best_of: dict[tuple[str, str], Route | None] = {}

    def best_of_round(process: _Process, prefix: str) -> Route | None:
        key = (process.uid, prefix)
        if key not in best_of:
            best_of[key] = bestpath.best_path(
                process.rib[prefix],
                resolver=resolve_for(process),
                always_compare_med=process.always_compare_med,
            )
        return best_of[key]

    # Maps (process uid, session uid) to the prefixes that hold a path learned
    # from that session. A withdrawal visits only these prefixes.
    carried: dict[tuple[str, Any], set[str]] = {}
    for uid, process in processes.items():
        for prefix, routes in process.rib.items():
            for route in routes:
                if route.learned_from_session is not None:
                    carried.setdefault((uid, route.learned_from_session), set()).add(prefix)

    rounds = 0
    states = RepeatedStateDetector()
    for _ in range(budget.bgp_rounds):
        rounds += 1
        changed = False
        best_of.clear()
        for sender_session, receiver_session in pairs:
            sender = processes.get(str(sender_session.get("process_uid")))
            receiver = processes.get(str(receiver_session.get("process_uid")))
            if sender is None or receiver is None:
                continue
            if not _session_carries(sender_session, receiver_session):
                continue
            if str(receiver_session.get("uid")) in observed:
                # The seeds hold the paths that the snapshot observed on this
                # session.
                continue

            advertised: set[str] = set()
            for prefix in sorted(sender.rib):
                candidate = best_of_round(sender, prefix)
                if candidate is None:
                    continue
                aggregate = _suppressing_aggregate(sender, prefix, resolve_for(sender))
                if aggregate is not None:
                    suppressed[(sender.uid, str(sender_session.get("uid")), prefix)] = {
                        "process_uid": sender.uid,
                        "context_uid": sender.context_uid,
                        "session_uid": str(sender_session.get("uid")),
                        "prefix": prefix,
                        "aggregate": aggregate,
                    }
                    continue
                sending_session = (
                    _session_by_uid(session_of, sender.uid, candidate.learned_from_session)
                    if candidate.learned_from_session
                    else None
                )
                exported = bestpath.export_route(
                    candidate,
                    sender_session,
                    platform=sender.platform,
                    local_asn=sender.asn,
                    local_router_id=sender.router_id,
                    policies=sender.policies,
                    prefix_lists=sender.prefix_lists,
                    errors=errors,
                    sending_session=sending_session,
                    remote_admin=None,
                )
                if exported is None:
                    continue
                imported = bestpath.import_route(
                    exported,
                    receiver_session,
                    platform=receiver.platform,
                    local_asn=receiver.asn,
                    policies=receiver.policies,
                    prefix_lists=receiver.prefix_lists,
                    errors=errors,
                )
                if imported is None:
                    continue
                advertised.add(prefix)
                if imported.learned_from_session is not None:
                    carried.setdefault((receiver.uid, imported.learned_from_session), set()).add(prefix)
                # The arrival counter advances only when the path is new or its
                # attributes changed.
                if _merge(receiver.rib, imported.with_(arrival=arrival + 1)):
                    arrival += 1
                    changed = True
                    best_of.pop((receiver.uid, imported.prefix), None)
            receiver_uid = str(receiver_session.get("uid"))
            held = carried.setdefault((receiver.uid, receiver_uid), set())
            dropped = _withdraw(receiver.rib, receiver_uid, advertised, held)
            for prefix in dropped:
                best_of.pop((receiver.uid, prefix), None)
            if dropped:
                changed = True
        if not changed:
            break
        state = freeze({uid: process.rib for uid, process in processes.items()})
        prior = states.observe(state, rounds)
        if prior is not None:
            errors.report(
                "no-routing-fixed-point",
                f"propagation repeated its exact state from round {prior} at round {rounds}",
            )
            break
    else:
        errors.report(
            "no-routing-fixed-point",
            f"propagation did not settle within {budget.bgp_rounds} rounds; the rows below "
            "are the state at the last round",
        )

    rib: list[dict[str, Any]] = []
    selected: dict[str, list[Route]] = {}
    multipath: dict[str, list[Route]] = {}
    multipath_unknown: list[dict[str, Any]] = []
    history_dependent: list[dict[str, Any]] = []
    for uid in sorted(processes):
        process = processes[uid]
        for prefix in sorted(process.rib):
            best, by_arrival = bestpath.best_path_with_tie(
                process.rib[prefix],
                resolver=resolve_for(process),
                always_compare_med=process.always_compare_med,
            )
            if best is None:
                continue
            if by_arrival:
                history_dependent.append(
                    {"context_uid": process.context_uid, "process_uid": uid, "prefix": prefix}
                )
            rib.extend(bestpath.rib_rows(process.context_uid, [best]))
            selected.setdefault(process.context_uid, []).append(best)
            peers, known = _multipath(process, best, process.rib[prefix], resolve_for(process))
            if peers:
                multipath.setdefault(process.context_uid, []).extend(peers)
            if not known:
                multipath_unknown.append(
                    {"context_uid": process.context_uid, "process_uid": uid, "prefix": prefix}
                )
    return RouteDelta(
        rib=rib,
        model_errors=errors.as_dicts(),
        rounds=rounds,
        selected=selected,
        unresolved=[unresolved[key] for key in sorted(unresolved, key=lambda k: tuple(str(x) for x in k))],
        history_dependent=history_dependent,
        suppressed=[suppressed[key] for key in sorted(suppressed)],
        multipath=multipath,
        multipath_unknown=multipath_unknown,
    )


def _multipath(
    process: _Process, best: Route, routes: list[Route], resolver: bestpath.Resolver | None
) -> tuple[list[Route], bool]:
    """The paths that `process` installs beside `best` for its prefix, and
    whether that is known.

    A learned best path takes the equal paths that `bestpath.multipath_peers`
    admits, up to the `maximum-paths` of the process for its session type and
    family. The answer is known when there is no equal path. When there is an
    equal path and the count is not known (`_Process.maximum_paths`), no path
    is added and the answer is not known."""
    # An eBGP path and a locally originated path both have protocol `bgp`.
    if best.protocol == "ibgp":
        session_type = "ibgp"
    elif best.origin_mechanism == "learned":
        session_type = "ebgp"
    else:
        return [], True
    eligible: list[Route] = []
    for route in routes:
        if resolver is not None:
            cost = resolver(route)
            if cost is None:
                continue
            route = route.with_(igp_cost=cost)
        eligible.append(route)
    peers = bestpath.multipath_peers(
        best, eligible, always_compare_med=process.always_compare_med, relax=process.multipath_relax
    )
    if not peers:
        return [], True
    family = ipaddress.ip_network(best.prefix, strict=False).version
    limit = process.maximum_paths(session_type, family)
    if limit is None:
        return [], False
    return peers[: limit - 1], True


def _suppressing_aggregate(process: _Process, prefix: str, resolver: bestpath.Resolver | None) -> str | None:
    """The `summary-only` aggregate of `process` that holds `prefix` back from
    advertisement, or None. The aggregate must be in the table with a usable
    path. `prefix` must be more specific than the aggregate and in the same
    address family."""
    if not process.summary_only:
        return None
    network = ipaddress.ip_network(prefix, strict=False)
    for candidate in sorted(process.summary_only):
        aggregate = ipaddress.ip_network(candidate, strict=False)
        if aggregate.version != network.version or network.prefixlen <= aggregate.prefixlen:
            continue
        if not (
            int(aggregate.network_address) <= int(network.network_address)
            and int(network.broadcast_address) <= int(aggregate.broadcast_address)
        ):
            continue
        if (
            candidate not in process.rib
            or bestpath.best_path(
                process.rib[candidate], resolver=resolver, always_compare_med=process.always_compare_med
            )
            is None
        ):
            continue
        return candidate
    return None


def _session_by_uid(
    sessions: Mapping[tuple[str, str], Mapping[str, Any]], process_uid: str, uid: Any
) -> Mapping[str, Any] | None:
    if not isinstance(uid, str):
        return None
    return sessions.get((process_uid, uid))
