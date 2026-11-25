"""Best-path selection, and import/export processing.

Two steps follow the vendor rule:

  * Local origination is compared after local preference and before AS-path
    length. Within local origination a network- or redistribute-originated
    route ranks above an aggregate.
  * MED is compared only between routes received from the same neighbouring
    AS, and a missing MED compares as 0.

The originator-ID and cluster-list-length tie-breaks run for every
`BgpTieBreaker` value.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from . import platforms as plat
from . import policy as p
from .errors import ErrorSink
from .route import (
    DEFAULT_LOCAL_PREFERENCE,
    NO_ADVERTISE,
    NO_EXPORT,
    ORIGIN_PREFERENCE,
    ORIGINATION_RANK,
    RECEIVED_FROM_RANK,
    Route,
)

# The Cisco default administrative distances of eBGP and iBGP. `admin` on a session overrides them.
DEFAULT_EBGP_ADMIN = 20
DEFAULT_IBGP_ADMIN = 200

EBGP = "ebgp"
IBGP = "ibgp"

# The values of `AllowRemoteAsOutMode`. NEVER blocks a route with the AS of the
# peer at any position of the path. EXCEPT_FIRST blocks a route with the AS of
# the peer as the first AS of the path. EXCEPT_RECEIVED_FROM blocks a route
# received from the peer. ALWAYS blocks no route.
ALLOW_REMOTE_AS_NEVER = "never"
ALLOW_REMOTE_AS_EXCEPT_FIRST = "except-first"
ALLOW_REMOTE_AS_ALWAYS = "always"
ALLOW_REMOTE_AS_EXCEPT_RECEIVED_FROM = "except-received-from"

# The values of `BgpSession.next_hop_self`. An iBGP export sets the next hop of
# the selected routes to the local address. `ebgp` is the plain `next-hop-self`
# and selects the routes that are not reflected from an iBGP peer. `all` is
# `next-hop-self all` or `force` and selects every route.
NEXT_HOP_SELF_EBGP = "ebgp"
NEXT_HOP_SELF_ALL = "all"


def session_type(session: Mapping[str, Any]) -> str:
    """eBGP when the two AS numbers differ, iBGP when they match."""
    return EBGP if int(session["local_asn"]) != int(session["peer_asn"]) else IBGP


def _default_allow_remote_as_out(platform: str) -> str:
    # IOS-XR uses ALWAYS. The other platforms default to EXCEPT_FIRST. On NX-OS
    # `disable-peer-as-check` turns the check off.
    return ALLOW_REMOTE_AS_ALWAYS if platform == plat.IOSXR else ALLOW_REMOTE_AS_EXCEPT_FIRST


# --- comparator -----------------------------------------------------------


def _cmp(a: int, b: int) -> int:
    return (a > b) - (a < b)


def _type_cost(route: Route) -> int:
    """eBGP outranks iBGP."""
    return 0 if route.protocol == "ibgp" else 1


def compare_preference(a: Route, b: Route, *, always_compare_med: bool = False) -> int:
    """The preference comparison. Positive when `a` is preferred, negative when `b` is.

    MED is compared before eBGP over iBGP. Cisco IOS-XE, NX-OS, IOS-XR, FRR,
    Junos and Arista document this order. `always_compare_med` is
    `bgp always-compare-med` of the process (`bestpath med always` on IOS-XR).
    With it, MED also compares across neighbouring ASes.

    A RIB in multipath mode installs beside the best path the paths that tie
    with it in this comparison and that `multipath_peers` admits.
    """
    order = (
        _cmp(a.weight, b.weight),
        _cmp(a.local_pref, b.local_pref),
        _cmp(
            ORIGINATION_RANK.get(a.origin_mechanism, 0),
            ORIGINATION_RANK.get(b.origin_mechanism, 0),
        ),
        -_cmp(a.as_path_length, b.as_path_length),
        _cmp(ORIGIN_PREFERENCE.get(a.origin, 0), ORIGIN_PREFERENCE.get(b.origin, 0)),
        _med_comparison(a, b, always=always_compare_med),
        _cmp(_type_cost(a), _type_cost(b)),
        _igp_cost_comparison(a, b),
    )
    for step in order:
        if step:
            return step
    return 0


def _med_comparison(a: Route, b: Route, *, always: bool = False) -> int:
    """The MED step.

    MED compares only between routes of the same neighbouring AS, unless
    `always` is set. A missing MED compares as 0. The lower MED wins.
    """
    if not always and a.neighbor_as != b.neighbor_as:
        return 0
    return -_cmp(a.effective_med, b.effective_med)


def _igp_cost_comparison(a: Route, b: Route) -> int:
    """The IGP cost step.

    The step is skipped when either route has no resolved cost. The caller
    supplies the cost through a resolver (`best_path_with_tie`).
    """
    if a.igp_cost is None or b.igp_cost is None:
        return 0
    return -_cmp(a.igp_cost, b.igp_cost)


def _ip_key(ip: str | None) -> tuple[int, ...]:
    if not ip:
        return (1 << 40,)
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (1 << 40,)


def _compare_received_from(a: Route, b: Route) -> int:
    """The received-from tie-break.

    The order is the neighbour IP (lower wins), the subtype rank (lower wins)
    and the interface name (lexicographically lower wins).
    """
    step = -_cmp_tuple(_ip_key(a.received_from_ip), _ip_key(b.received_from_ip))
    if step:
        return step
    step = -_cmp(
        RECEIVED_FROM_RANK.get(a.received_from_kind, 2),
        RECEIVED_FROM_RANK.get(b.received_from_kind, 2),
    )
    if step:
        return step
    if a.received_from_kind == "interface" and b.received_from_kind == "interface":
        left, right = a.received_from_interface or "", b.received_from_interface or ""
        return -((left > right) - (left < right))
    return 0


def _cmp_tuple(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    return (a > b) - (a < b)


def _path_id_comparison(a: Route, b: Route) -> int:
    """The path ID tie-break.

    A route without a path ID beats a route with one. The lower path ID wins.
    """
    if a.path_id is None and b.path_id is None:
        return 0
    if a.path_id is None:
        return 1
    if b.path_id is None:
        return -1
    return -_cmp(a.path_id, b.path_id)


def _arrival_step(a: Route, b: Route, *, tie_breaker: str) -> int:
    """The arrival-order tie-break, or 0 when the step does not apply to this pair."""
    if tie_breaker == "arrival-order" and a.protocol == "bgp" and b.protocol == "bgp":
        return -_cmp(a.arrival, b.arrival)
    return 0


def _comparator_after_arrival(a: Route, b: Route) -> int:
    """The tie-breaks after the arrival-order step."""
    # The originator and cluster-list steps run for every configured tie-breaker.
    step = -_cmp_tuple(_ip_key(a.originator_ip), _ip_key(b.originator_ip))
    if step:
        return step
    step = -_cmp(len(a.cluster_list), len(b.cluster_list))
    if step:
        return step
    step = _compare_received_from(a, b)
    if step:
        return step
    return _path_id_comparison(a, b)


def best_path_comparator(a: Route, b: Route, *, tie_breaker: str = "arrival-order") -> int:
    """The tie-breaks, applied only when the RIB is single-path and `compare_preference` tied."""
    step = _arrival_step(a, b, tie_breaker=tie_breaker)
    if step:
        return step
    return _comparator_after_arrival(a, b)


def compare_routes(
    a: Route, b: Route, *, tie_breaker: str = "arrival-order", always_compare_med: bool = False
) -> int:
    step = compare_preference(a, b, always_compare_med=always_compare_med)
    if step:
        return step
    return best_path_comparator(a, b, tie_breaker=tie_breaker)


# A resolver returns the IGP cost of the main RIB to the next hop of one
# candidate, or None when the next hop does not resolve in the main RIB.
# `simul/rib.py` supplies a resolver bound to the forwarding context of the
# process. Without a resolver every candidate is eligible.
Resolver = Callable[[Route], "int | None"]


def best_path(
    routes: Sequence[Route],
    *,
    tie_breaker: str = "arrival-order",
    resolver: Resolver | None = None,
    always_compare_med: bool = False,
) -> Route | None:
    """The single best path among the candidates for one prefix.

    With a `resolver`, a candidate whose next hop does not resolve is not
    eligible. A BGP path is valid only when its next hop resolves in the
    context of the session or in `next_hop_context_uid`. Every eligible
    candidate compares with the `igp_cost` that the resolver returned. The
    returned route has that cost.
    """
    return best_path_with_tie(
        routes, tie_breaker=tie_breaker, resolver=resolver, always_compare_med=always_compare_med
    )[0]


def best_path_with_tie(
    routes: Sequence[Route],
    *,
    tie_breaker: str = "arrival-order",
    resolver: Resolver | None = None,
    always_compare_med: bool = False,
) -> tuple[Route | None, bool]:
    """The best path, and whether the selection is uncertain.

    The arrival order of a path depends on the message history of the network.
    The engine numbers arrivals in its input order. A selection that the
    arrival-order tie-break decides is one of 2 or more stable outcomes of the
    same configuration, and the caller reports it as uncertainty. The later
    tie-breaks do not remove this uncertainty. An older arrival of the other
    path selects that path before those steps run. The selection is also
    uncertain when the winner ties in preference with a candidate and one of
    the 2 routes has no originator IP, and when the winner does not beat every
    other eligible candidate (a non-transitive preference comparison such as
    conditional MED).
    """
    med = always_compare_med
    eligible: list[Route] = []
    for route in routes:
        if resolver is not None:
            cost = resolver(route)
            if cost is None:
                continue
            route = route.with_(igp_cost=cost)
        eligible.append(route)
    best: Route | None = None
    for route in eligible:
        if best is None or compare_routes(route, best, tie_breaker=tie_breaker, always_compare_med=med) > 0:
            best = route
    if best is None:
        return None, False
    decided = any(
        compare_routes(best, other, tie_breaker=tie_breaker, always_compare_med=med) <= 0
        or (
            compare_preference(best, other, always_compare_med=med) == 0
            and (
                (tie_breaker == "arrival-order" and best.protocol == other.protocol == "bgp")
                or not best.originator_ip
                or not other.originator_ip
            )
        )
        for other in eligible
        if other is not best
    )
    return best, decided


def multipath_peers(
    best: Route,
    eligible: Sequence[Route],
    *,
    always_compare_med: bool = False,
    relax: bool = False,
) -> list[Route]:
    """The paths that a multipath RIB may install beside `best`, best-ranked first.

    A peer ties with `best` in the preference comparison with the IGP cost
    (`compare_preference`). It has the session type and the origin mechanism of
    `best` and a next hop that no earlier path uses. Its AS path equals the AS
    path of `best`. With `bestpath as-path multipath-relax` (`relax`) an AS
    path of the same length is enough, and the preference tie ensures the
    length. `eligible` holds the routes with the resolved IGP costs (the
    resolver of `best_path_with_tie`). The caller limits the count to the
    `maximum-paths` of the process.
    """
    peers: list[Route] = []
    hops = {best.next_hop}

    def ranked_first(a: Route, b: Route) -> int:
        return compare_routes(b, a, always_compare_med=always_compare_med)

    ranked = sorted((route for route in eligible if route != best), key=functools.cmp_to_key(ranked_first))
    for route in ranked:
        if (
            route.protocol == best.protocol
            and route.origin_mechanism == best.origin_mechanism
            and route.next_hop not in hops
            and compare_preference(best, route, always_compare_med=always_compare_med) == 0
            and (relax or route.as_path == best.as_path)
        ):
            peers.append(route)
            hops.add(route.next_hop)
    return peers


# --- policy attachment ----------------------------------------------------


def _run_policy(
    name: str,
    route: Route,
    *,
    direction: str,
    policies: Mapping[str, p.Policy],
    prefix_lists: Mapping[str, Any],
    errors: ErrorSink,
    stype: str,
    peer_as: int | None,
) -> Route | None:
    env = p.Environment(
        original_route=route,
        output_route=route,
        direction=direction,
        policies=dict(policies),
        prefix_lists=dict(prefix_lists),
        errors=errors,
        session_type=stype,
        peer_as=peer_as,
    )
    accepted = p.process(policies[name], env)
    return env.output_route if accepted else None


def apply_attached_policy(
    route: Route,
    session: Mapping[str, Any],
    *,
    direction: str,
    platform: str,
    policies: Mapping[str, p.Policy],
    prefix_lists: Mapping[str, Any],
    errors: ErrorSink,
) -> Route | None:
    """Run the policy attached to one session in one direction, or apply the
    no-policy default when nothing is attached.

    A neighbour `route-map` with an undefined name denies every route in that
    direction. An IOS-XR `route-policy` with an undefined name gives the
    no-policy default. An NX-OS neighbour `prefix-list` with an undefined name
    imposes no filter.

    A neighbour AS-path `filter-list` (`import_filter_list_name`/
    `export_filter_list_name`) is not evaluated. Every route is denied in that
    direction and the session is reported. A prefix-list attached beside a
    route-map in the same direction (`import_prefix_list_name`/
    `export_prefix_list_name`) is applied first, and the route-map runs on the
    routes that it permits.
    """
    stype = session_type(session)
    peer_as = int(session["peer_asn"])
    prefix = "import" if direction == "in" else "export"
    key = f"{prefix}_policy_name"
    kind_key = f"{prefix}_policy_kind"
    name = session.get(key)

    filter_list = session.get(f"{prefix}_filter_list_name")
    if filter_list:
        errors.report(
            "neighbor-filter-list-not-modeled",
            f"session {session.get('uid')} attaches AS-path filter-list {str(filter_list)!r} "
            f"{direction}bound, which this engine does not evaluate; every route is denied in "
            "that direction",
            str(session.get("uid")),
        )
        return None

    prefix_list = session.get(f"{prefix}_prefix_list_name")
    if prefix_list:
        prefix_list = str(prefix_list)
        if prefix_list in prefix_lists:
            if not _prefix_list_filter(prefix_list, route, prefix_lists):
                return None
        else:
            errors.report(
                "undefined-neighbor-prefix-list",
                f"session {session.get('uid')} attaches prefix list {prefix_list!r} {direction}bound, "
                "which no RoutePolicy node defines; no filter was imposed",
                prefix_list,
            )

    if not name:
        return route if plat.no_policy_permits(platform, stype) else None

    name = str(name)
    if name in policies:
        return _run_policy(
            name,
            route,
            direction=direction,
            policies=policies,
            prefix_lists=prefix_lists,
            errors=errors,
            stype=stype,
            peer_as=peer_as,
        )

    kind = str(session.get(kind_key) or "route-map").lower()
    if kind == "prefix-list":
        if name in prefix_lists:
            permitted = _prefix_list_filter(name, route, prefix_lists)
            return route if permitted else None
        errors.report(
            "undefined-neighbor-prefix-list",
            f"session {session.get('uid')} attaches prefix list {name!r} {direction}bound, "
            "which no RoutePolicy node defines; no filter was imposed",
            name,
        )
        # An undefined neighbor prefix-list gives the no-policy default. On NX-OS
        # and IOS-XE the default accepts every route.
        return route if plat.no_policy_permits(platform, stype) else None

    errors.report(
        "undefined-neighbor-route-map",
        f"session {session.get('uid')} attaches route map {name!r} {direction}bound, "
        "which no RoutePolicy node defines; every route is denied in that direction",
        name,
    )
    # An undefined IOS-XE or NX-OS neighbor route-map denies every route in both
    # directions. On IOS-XR an unresolved name gives the no-policy default. The
    # default denies every route of an eBGP peer and permits every route of an
    # iBGP peer.
    if platform == plat.IOSXR:
        return route if plat.no_policy_permits(platform, stype) else None
    return None


def _prefix_list_filter(name: str, route: Route, prefix_lists: Mapping[str, Any]) -> bool:
    from .prefixlist import evaluate as prefix_list_permits

    return prefix_list_permits(prefix_lists[name], route.prefix)


# --- import ---------------------------------------------------------------


def import_route(
    route: Route,
    session: Mapping[str, Any],
    *,
    platform: str,
    local_asn: int,
    policies: Mapping[str, p.Policy],
    prefix_lists: Mapping[str, Any],
    errors: ErrorSink,
) -> Route | None:
    """Import processing of one route on one session. Returns None when the route is
    filtered at step 1 or step 9."""
    stype = session_type(session)

    # 1. AS-path loop check.
    if local_asn in route.as_path and not session.get("allow_local_as_in"):
        return None

    protocol = "bgp" if stype == EBGP else "ibgp"
    admin = session.get("admin")
    if admin is None:
        admin = DEFAULT_EBGP_ADMIN if stype == EBGP else DEFAULT_IBGP_ADMIN
    peer_ip = session.get("peer_ip")

    candidate = route.with_(
        protocol=protocol,  # 2
        admin=int(admin),  # 3
        # 4. The next hop is the one that export stage 3 of the neighbour set.
        received_from_kind="ip" if peer_ip else "interface",  # 5
        received_from_ip=peer_ip,
        src_protocol=protocol,  # 6
        origin_mechanism="learned",  # 7
        learned_from_session=session.get("uid"),
    )

    # 8. The route-reflector-client origin applies to an iBGP session only.
    # `is_reflectable` reads it on export.

    # 9. The import policy runs, or the no-policy default applies.
    return apply_attached_policy(
        candidate,
        session,
        direction="in",
        platform=platform,
        policies=policies,
        prefix_lists=prefix_lists,
        errors=errors,
    )


# --- export ---------------------------------------------------------------


def is_reflectable(
    route: Route,
    session: Mapping[str, Any],
    sending_session: Mapping[str, Any] | None,
    *,
    client_to_client: bool = True,
) -> bool:
    """Whether a route is reflected to `session` (`isReflectable`).

    The session and the route must be iBGP. A route from a client is reflected
    to every peer, or to non-clients only when `client_to_client` is false. A
    route from a non-client is reflected to clients only.
    """
    if session_type(session) != IBGP or route.protocol != "ibgp":
        return False
    from_client = bool(sending_session and sending_session.get("route_reflector_client"))
    to_client = bool(session.get("route_reflector_client"))
    if from_client:
        return client_to_client or not to_client
    return to_client


def _pre_export(
    route: Route,
    session: Mapping[str, Any],
    *,
    stype: str,
    local_router_id: str | None,
    cluster_id: str | None,
    reflecting: bool,
    remote_admin: int | None,
) -> Route:
    """The attribute rewrites before export policy runs."""
    locally_originated = route.is_locally_originated
    if stype == EBGP:
        return route.with_(
            protocol="bgp",
            src_protocol=route.protocol,
            admin=remote_admin,
            originator_ip=local_router_id,
            cluster_list=(),
            # `advertiseUnchangedMed()` is true for iBGP and for locally
            # originated routes. An eBGP export of a learned route sets MED to 0.
            med=route.med if locally_originated else 0,
            next_hop=None,
            tag=None,
        )
    originator = route.originator_ip if route.protocol == "ibgp" else local_router_id
    cluster_list = route.cluster_list
    if reflecting and cluster_id and not locally_originated:
        cluster_list = (*cluster_list, cluster_id)
    return route.with_(
        protocol="ibgp",
        src_protocol=route.protocol,
        admin=remote_admin,
        originator_ip=originator,
        cluster_list=cluster_list,
        next_hop=None,
        tag=None,
    )


def _post_export(
    route: Route,
    session: Mapping[str, Any],
    *,
    stype: str,
    local_asn: int,
    local_ip: str | None,
    original_next_hop: str | None,
    policy_set_next_hop: bool,
    reflecting: bool,
) -> Route:
    """The attribute rewrites after the export policy accepts.

    An iBGP export keeps the next hop unless `next_hop_self` of the session
    rewrites it. `all` rewrites every route. `ebgp` (the plain `next-hop-self`
    of IOS-XE, NX-OS and IOS-XR) rewrites a route that is not reflected from an
    iBGP peer. A route without a next hop gets the local address. A next hop
    that the export policy set is kept.
    """
    communities = route.communities
    if not session.get("send_community", True):
        communities = frozenset()

    if stype == EBGP:
        next_hop = route.next_hop if policy_set_next_hop else local_ip
        return route.with_(
            as_path=(local_asn, *route.as_path),
            weight=0,
            local_pref=DEFAULT_LOCAL_PREFERENCE,
            tag=None,
            communities=communities,
            next_hop=next_hop,
            protocol="bgp",
        )
    nhs = session.get("next_hop_self")
    if policy_set_next_hop:
        next_hop = route.next_hop
    elif (
        nhs == NEXT_HOP_SELF_ALL
        or (nhs == NEXT_HOP_SELF_EBGP and not reflecting)
        or original_next_hop is None
    ):
        next_hop = local_ip
    else:
        next_hop = original_next_hop
    return route.with_(
        weight=0,
        tag=None,
        communities=communities,
        next_hop=next_hop,
        protocol="ibgp",
    )


def export_route(
    route: Route,
    session: Mapping[str, Any],
    *,
    platform: str,
    local_asn: int,
    local_router_id: str | None,
    policies: Mapping[str, p.Policy],
    prefix_lists: Mapping[str, Any],
    errors: ErrorSink,
    sending_session: Mapping[str, Any] | None = None,
    remote_admin: int | None = None,
) -> Route | None:
    """The three export stages, in order: pre-export transform, export
    policy, post-export transform. Returns None when the route is dropped."""
    stype = session_type(session)
    peer_asn = int(session["peer_asn"])

    # The rejection rules run before any rewrite.
    if NO_ADVERTISE in route.communities:
        return None
    if stype == EBGP:
        mode = str(session.get("allow_remote_as_out") or _default_allow_remote_as_out(platform))
        if mode == ALLOW_REMOTE_AS_NEVER and peer_asn in route.as_path:
            return None
        if mode == ALLOW_REMOTE_AS_EXCEPT_FIRST and route.as_path[:1] == (peer_asn,):
            return None
        if (
            mode == ALLOW_REMOTE_AS_EXCEPT_RECEIVED_FROM
            and route.received_from_ip
            and route.received_from_ip == session.get("peer_ip")
        ):
            return None
        if NO_EXPORT in route.communities:
            return None
    reflecting = False
    # A reflector's cluster id is its router id unless one is configured
    # (RFC 4456), on every platform this engine models.
    cluster_id = session.get("cluster_id") or local_router_id
    if stype == IBGP:
        if session.get("peer_router_id") and session["peer_router_id"] == route.originator_ip:
            return None
        reflecting = is_reflectable(route, session, sending_session)
        if route.protocol == "ibgp" and not reflecting:
            return None
        # `peer_cluster_ids` holds the cluster ids of the receiving reflector
        # (`app.simul_read`). The receiver drops a route whose cluster list
        # holds one of them. A route that this export reflects also has the
        # cluster id of this reflector in its cluster list.
        receiver_clusters = set(session.get("peer_cluster_ids") or ())
        if receiver_clusters & set(route.cluster_list):
            return None
        if reflecting and cluster_id and cluster_id in receiver_clusters:
            return None

    original_next_hop = route.next_hop
    candidate = _pre_export(
        route,
        session,
        stype=stype,
        local_router_id=local_router_id,
        cluster_id=cluster_id,
        reflecting=reflecting,
        remote_admin=remote_admin,
    )

    accepted = apply_attached_policy(
        candidate,
        session,
        direction="out",
        platform=platform,
        policies=policies,
        prefix_lists=prefix_lists,
        errors=errors,
    )
    if accepted is None:
        return None

    return _post_export(
        accepted,
        session,
        stype=stype,
        local_asn=local_asn,
        local_ip=session.get("local_ip"),
        original_next_hop=original_next_hop,
        policy_set_next_hop=accepted.next_hop is not None,
        reflecting=reflecting,
    )


def rib_rows(context_uid: str, routes: Iterable[Route]) -> list[dict[str, Any]]:
    """Per-VRF RIB rows keyed by `context_uid`, the output shape
    of every route-delta provider."""
    rows = []
    for route in routes:
        rows.append(
            {
                "context_uid": context_uid,
                "prefix": route.prefix,
                "next_hop": route.next_hop,
                "protocol": "bgp",
                "metric": route.effective_med,
                "local_pref": route.local_pref,
                "med": route.med,
                "weight": route.weight,
                "as_path": list(route.as_path),
                "origin": route.origin,
                "origin_mechanism": route.origin_mechanism,
                "session_protocol": route.protocol,
                "admin": route.admin,
                "communities": sorted(route.communities),
                "originator_ip": route.originator_ip,
                "cluster_list": list(route.cluster_list),
                "tag": route.tag,
            }
        )
    return rows
