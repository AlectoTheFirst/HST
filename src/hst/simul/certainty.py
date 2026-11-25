"""Conservative certificates for routing evidence and stable-state proofs.

A converged iteration gives one stable state without a proof of uniqueness.
The sufficient condition of this module admits independent BGP selections from
fixed boundary inputs, with next hops independent of BGP. Feedback,
redistribution, conditional origination and leaking are outside the
certificate. `proof_gaps` returns a gap for each context that one of them
affects.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Any

from hst.path.addrsets import _merge

from .compile import context_namespaces, policy_namespace, policy_scoped, resolving_namespace

if TYPE_CHECKING:
    from .rib import RibInput

UNIQUENESS = "routing-uniqueness-not-established"
EXTERNAL_RESPONSE = "external-route-response-unobserved"
# A session property that `app/simul_read.read_rib_input` sets when it paired
# the session with a far-end BgpSession node of the estate and left the process
# of that node out of the input. The received paths of the session are
# captured, and the calculation reads the observation. The context of the
# session is outside the closure of every change. The value is the uid of the
# far-end session.
OMITTED_FAR_END = "omitted_far_session_uid"
# The direction statuses of a captured direction. `rib._Run.observed_seeds`
# uses a captured direction as the input.
CAPTURED = frozenset({"complete", "complete-empty"})
# The `cause` of a `not-observed` gap for the routes that a BGP peer sends. The
# gap has this cause when no direction of the session is captured and its far
# end is not in the input, or when only its accepted paths are captured
# (`rib._Run.observed_seeds`). The collected table of the router holds the
# routes that the peer sent and the router installed. For a context with a
# complete table and routing that the request cannot alter, the per-prefix
# calibration decides (`impact.evaluate.Network.incomplete`).
PEER_SUPPLY = "peer-supply-not-observed"


def observed_sessions(inp: RibInput) -> set[str]:
    """The sessions whose received paths the calculation takes from the
    observation (`rib._Run.observed_seeds`).

    A session qualifies when it is not shut down and its received or accepted
    direction is captured, or has rows without a recorded status. The sessions
    of `inp.bgp.observed_sessions` qualify too. A session of a superseded
    context is left out, and the change recomputes it from the far end. The
    faults and gaps of the far end are no input of the context of an observed
    session.
    """
    if inp.bgp is None:
        return set()
    rows = {(str(row.get("session_uid")), str(row.get("direction"))) for row in inp.observed_paths}
    contexts = process_contexts(inp)
    context_of = {str(s.get("uid")): contexts.get(str(s.get("process_uid"))) for s in inp.bgp.sessions}
    out = {str(uid) for uid in inp.bgp.observed_sessions}
    for session in inp.bgp.sessions:
        uid = str(session.get("uid"))
        if str(session.get("state", "")).lower() == "shutdown":
            continue
        for direction in ("received", "accepted"):
            status = inp.direction_status.get((uid, direction))
            if status in CAPTURED or (status is None and (uid, direction) in rows):
                out.add(uid)
    return {uid for uid in out if context_of.get(uid) not in inp.superseded_contexts}


def paired_sessions(inp: RibInput) -> dict[str, Mapping[str, Any]]:
    """Matches each session to its peer session by reciprocal endpoints and ASNs.

    A session has a pair only when exactly one other session matches.
    """
    sessions = inp.bgp.sessions if inp.bgp else ()
    by_endpoints: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in sessions:
        by_endpoints[
            (row.get("local_ip"), row.get("peer_ip"), row.get("local_asn"), row.get("peer_asn"))
        ].append(row)
    pairs: dict[str, Mapping[str, Any]] = {}
    for row in sessions:
        if not row.get("local_ip") or not row.get("peer_ip"):
            continue
        matches = [
            other
            for other in by_endpoints.get(
                (row.get("peer_ip"), row.get("local_ip"), row.get("peer_asn"), row.get("local_asn")), ()
            )
            if other.get("uid") != row.get("uid")
        ]
        if len(matches) == 1:
            pairs[str(row["uid"])] = matches[0]
    return pairs


def process_contexts(inp: RibInput) -> dict[str, str]:
    return {str(p["uid"]): str(p["context_uid"]) for p in inp.bgp.processes} if inp.bgp else {}


# The BgpSession properties that hold the name of a policy of the session.
# They are the import policy, the export policy and a prefix-list attached
# beside a route-map in the same direction (`bestpath.apply_attached_policy`).
SESSION_POLICY_KEYS = (
    "import_policy_name",
    "export_policy_name",
    "import_prefix_list_name",
    "export_prefix_list_name",
)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def redistribute_statements(node: Mapping[str, Any]) -> list[tuple[str, str | None]]:
    """The `redistribute` statements of a process node as `(protocol, route_map)` pairs.

    The sources are the `redist_<protocol>_route_map` properties, the
    `redistribute` list of `{protocol, route_map}` of an input built by hand,
    and the `redistribute_protocols` list.
    """
    out: dict[str, str | None] = {}
    for key in sorted(node):
        if key.startswith("redist_") and key.endswith("_route_map") and node[key]:
            out.setdefault(key[len("redist_") : -len("_route_map")].lower(), str(node[key]))
    for item in node.get("redistribute") or ():
        protocol = str(item.get("protocol") or "").lower()
        if protocol:
            out.setdefault(protocol, _text(item.get("route_map")))
    for protocol in node.get("redistribute_protocols") or ():
        text = str(protocol).strip().lower()
        if text:
            out.setdefault(text, None)
    return sorted(out.items())


def advertising_routers(entry: Mapping[str, Any]) -> set[str]:
    """The router ids of the LSAs in the database of one OSPF process.

    `rib._with_externals` uses the same evidence for two routers in one
    flooding domain. The LSAs of a prepared model replace the raw rows.
    """
    lsas = getattr(entry.get("model"), "lsas", None)
    if lsas is not None:
        return {str(lsa.adv_router) for lsa in lsas.values()}
    return {text for row in entry.get("rows") or () if (text := _text(row.get("adv_router")))}


def dependencies(inp: RibInput, *, observed: Iterable[str] = ()) -> dict[str, set[str]]:
    """The consumer contexts of each producer context.

    The edges come from every input candidate, installed or not installed.
    Each edge is an input that the calculation reads across contexts. The
    results of a context depend only on the contexts upstream of it.
    `app/simul_read.read_rib_input` reads that upstream closure.

    `observed` holds the sessions whose received paths one run took from the
    observation (`rib._Run.observed_seeds`). A session in `observed` gives no
    edge. The closure of a change is computed without `observed` and includes
    the edges of those sessions.
    """
    edges: dict[str, set[str]] = defaultdict(set)
    contexts = process_contexts(inp)
    sessions = {str(s["uid"]): s for s in inp.bgp.sessions} if inp.bgp else {}
    skipped = {str(uid) for uid in observed}
    for uid, far in paired_sessions(inp).items():
        if uid in skipped:
            continue
        near = sessions[uid]
        edges[contexts[str(far["process_uid"])]].add(contexts[str(near["process_uid"])])
    for pair in inp.rt_pairs:
        edges[str(pair["exporter"])].add(str(pair["importer"]))
    rows = [
        *inp.static,
        *inp.observed_paths,
        *(inp.bgp.seeds if inp.bgp else ()),
        *(
            {**row, "context_uid": context}
            for context, observed in inp.observed_rib.items()
            for row in observed
        ),
    ]
    for row in rows:
        owner = row.get("context_uid") or contexts.get(str(row.get("process_uid")))
        if owner and row.get("next_hop_context_uid"):
            edges[str(row["next_hop_context_uid"])].add(str(owner))
    # Redistribution into OSPF replaces the type 5 LSAs of the redistributing
    # router in every database that holds LSAs of that router
    # (`rib._with_externals`). The context of that router is a producer for
    # the contexts of those databases. Every other OSPF route is computed from
    # the database of its own process. A recorded `default-information
    # originate` gives the same edges. The default LSA of the router depends
    # on the default route in its main RIB.
    holders: dict[str, set[str]] = defaultdict(set)
    for entry in inp.ospf:
        for router in advertising_routers(entry):
            holders[router].add(str(entry["context_uid"]))
    for entry in inp.ospf:
        redistributor = _text(entry.get("router_id"))
        if redistributor is not None and (
            redistribute_statements(entry) or entry.get("default_information_originate")
        ):
            edges[str(entry["context_uid"])].update(holders.get(redistributor, ()))
    return dict(edges)


def closure(
    inp: RibInput, roots: Iterable[str], *, edges: Mapping[str, set[str]] | None = None
) -> frozenset[str]:
    if edges is None:
        edges = dependencies(inp)
    found = set(roots)
    queue = deque(sorted(found))
    while queue:
        for consumer in edges.get(queue.popleft(), ()):
            if consumer not in found:
                found.add(consumer)
                queue.append(consumer)
    return frozenset(found)


def _components(nodes: Iterable[str], edges: Mapping[str, set[str]]) -> list[list[str]]:
    """The strongly connected components by an iterative form of Tarjan's algorithm.

    A component is listed after every component that it feeds.
    """
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    out: list[list[str]] = []
    for root in sorted(nodes):
        if root in index:
            continue
        index[root] = low[root] = len(index)
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(sorted(edges.get(root, ()))))]
        while work:
            node, children = work[-1]
            descended = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = len(index)
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(edges.get(child, ())))))
                    descended = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component: list[str] = []
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.append(item)
                    if item == node:
                        break
                out.append(component)
    return out


class _UpstreamCover:
    """For each context, the merged address intervals of the BGP prefixes
    held in it or in a context upstream of it.

    The calculation can install only these BGP prefixes in the context,
    directly, by leaking or by redistribution.
    """

    def __init__(self, edges: Mapping[str, set[str]], held: Mapping[str, list[tuple[int, int, int]]]) -> None:
        nodes = set(edges) | set(held)
        for targets in edges.values():
            nodes.update(targets)
        components = _components(nodes, edges)
        self.component_of = {
            member: number for number, members in enumerate(components) for member in members
        }
        producers: dict[int, set[int]] = defaultdict(set)
        for source, targets in edges.items():
            for target in targets:
                if self.component_of[source] != self.component_of[target]:
                    producers[self.component_of[target]].add(self.component_of[source])
        self.cover: dict[int, list[tuple[int, int, int]]] = {}
        # The loop visits producers before consumers. The cover of a producer is
        # complete when a consumer reads it.
        for number in reversed(range(len(components))):
            intervals = [item for member in components[number] for item in held.get(member, ())]
            for producer in producers.get(number, ()):
                intervals.extend(self.cover[producer])
            self.cover[number] = _merge(intervals) if intervals else []
        self._starts: dict[int, list[tuple[int, int]]] = {}

    def covers(self, context_uid: str, hop: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        number = self.component_of.get(context_uid)
        if number is None:
            return False
        merged = self.cover[number]
        if number not in self._starts:
            self._starts[number] = [(af, lo) for af, lo, _hi in merged]
        position = bisect_right(self._starts[number], (hop.version, int(hop))) - 1
        return position >= 0 and merged[position][0] == hop.version and int(hop) <= merged[position][2]


PolicyKey = tuple[str | None, str]


def policy_scope(inp: RibInput) -> Callable[[Mapping[str, Any], str | None], str | None]:
    """Returns the function that gives the namespace of a route policy name on a node.

    The namespace is the device that owns the node, or the context of the node
    when policies are defined per context (a Check Point virtual system,
    `compile.resolving_namespace`). A BGP process has `device_uid` and
    `context_uid`, and its sessions and originations use them. An OSPF process
    has no `device_uid`, and the function uses the device of the `context`
    argument. The function returns None for every node when no policy of the
    input has a namespace (`compile.policy_scoped`).
    """
    if inp.bgp is None or not policy_scoped(inp.bgp.policies):
        return lambda _node, _context: None
    devices = {str(c.get("uid")): c.get("device_uid") or None for c in inp.contexts}
    namespaces = context_namespaces(inp.bgp.policies)
    return lambda node, context: resolving_namespace(
        namespaces,
        node.get("device_uid") or (devices.get(str(context)) if context else None),
        node.get("context_uid") or context,
    )


def policy_key(policy: Mapping[str, Any], scoped: bool) -> PolicyKey:
    """The key of one `RoutePolicy` row.

    The key is the namespace (`compile.policy_namespace`) and the name. The
    namespace is None when the input is not scoped (`scoped`).
    """
    return policy_namespace(policy) if scoped else None, str(policy.get("name"))


def _policy_owners(inp: RibInput, contexts: Mapping[str, str]) -> dict[PolicyKey, set[str]]:
    """The contexts whose routes each policy can rewrite, keyed by (policy namespace, policy name).

    The contexts come from every attachment in the input. A policy called
    through `calls_policy` in the same namespace gets the contexts of its
    callers.
    """
    assert inp.bgp is not None  # noqa: S101 - proof_gaps checks inp.bgp before the call
    scope = policy_scope(inp)
    scoped = policy_scoped(inp.bgp.policies)
    process_of = {str(p["uid"]): p for p in inp.bgp.processes}
    owners: dict[PolicyKey, set[str]] = defaultdict(set)
    for session in inp.bgp.sessions:
        process = process_of.get(str(session.get("process_uid")), {})
        context = contexts.get(str(session.get("process_uid")))
        for key in SESSION_POLICY_KEYS:
            name = _text(session.get(key))
            if context and name:
                owners[(scope(process, None), name)].add(context)
    for process in (*inp.bgp.processes, *inp.ospf):
        for _protocol, route_map in redistribute_statements(process):
            if route_map:
                owners[(scope(process, process.get("context_uid")), route_map)].add(
                    str(process["context_uid"])
                )
    for row in inp.bgp.local_routes:
        process = process_of.get(str(row.get("process_uid")), {})
        context = contexts.get(str(row.get("process_uid")))
        for key in ("route_map", "attribute_map"):
            name = _text(row.get(key))
            if context and name:
                owners[(scope(process, None), name)].add(context)
    callers: dict[PolicyKey, set[PolicyKey]] = defaultdict(set)
    for policy in inp.bgp.policies:
        pkey = policy_key(policy, scoped)
        for entry in policy.get("entries") or ():
            callee = _text(entry.get("calls_policy"))
            if callee:
                callers[(pkey[0], callee)].add(pkey)
    changed = True
    while changed:
        changed = False
        for called, calling in callers.items():
            inherited = set().union(*(owners.get(caller, set()) for caller in calling))
            if not inherited <= owners[called]:
                owners[called].update(inherited)
                changed = True
    return owners


def proof_gaps(inp: RibInput) -> list[dict[str, Any]]:
    """The contexts that the sufficient uniqueness condition does not cover.

    Each condition makes the context that it applies to a root. The result is
    the closure of the roots over `dependencies`. The gaps of a context depend
    only on its upstream closure.
    """
    if inp.bgp is None:
        return []
    contexts = process_contexts(inp)
    every = set(contexts.values())
    edges = dependencies(inp)
    roots: set[str] = set()
    pairs = paired_sessions(inp)
    for session in inp.bgp.sessions:
        far = pairs.get(str(session["uid"]))
        if far and all(str(s.get("state", "")).lower() != "shutdown" for s in (session, far)):
            roots.add(contexts[str(session["process_uid"])])
        elif (
            far is None
            and session.get(OMITTED_FAR_END)
            and str(session.get("state", "")).lower() != "shutdown"
        ):
            # The read omitted the far end of an internal peering. It omits only
            # a far end that is not shut down. The context is a root, as for a
            # paired session.
            roots.add(contexts[str(session["process_uid"])])
    for row in inp.bgp.local_routes:
        if row.get("intent"):
            roots.add(contexts[str(row["process_uid"])])
    for process in (*inp.bgp.processes, *inp.ospf):
        if process.get("redistribute") or any(
            key.startswith("redist_") and value for key, value in process.items()
        ):
            roots.add(str(process["context_uid"]))
    # A leak adds candidates to the importer. The exporter is affected only
    # through a path back to it, and the closure follows that path.
    for pair in inp.rt_pairs:
        roots.add(str(pair["importer"]))
    session_context = {
        str(s["uid"]): contexts[str(s["process_uid"])]
        for s in inp.bgp.sessions
        if str(s.get("process_uid")) in contexts
    }

    def owner_of(row: Mapping[str, Any]) -> str | None:
        return (
            _text(row.get("context_uid"))
            or contexts.get(str(row.get("process_uid")))
            or session_context.get(str(row.get("session_uid")))
        )

    def root(owner: str | None) -> None:
        # Only an input built by hand holds a row without an owning context.
        # Such a row makes every context a root.
        if owner is None:
            roots.update(every)
        else:
            roots.add(owner)

    # The check reads every input prefix and every next hop that a policy sets,
    # selected or not selected.
    rows = [*inp.observed_paths, *inp.bgp.seeds, *inp.bgp.local_routes]
    held: dict[str, list[tuple[int, int, int]]] = defaultdict(list)
    for row in rows:
        owner = owner_of(row)
        try:
            prefix = ipaddress.ip_network(str(row.get("prefix")), strict=False)
        except ValueError:
            root(owner)
            continue
        if owner is not None:
            held[owner].append((prefix.version, int(prefix.network_address), int(prefix.broadcast_address)))
    cover = _UpstreamCover(edges, held)
    # Each item is (owner, resolving context, next hop). A next hop depends on
    # BGP when a BGP prefix that the calculation can install in its resolving
    # context covers it.
    hops: list[tuple[str | None, str | None, Any]] = []
    for row in (*rows, *inp.static):
        owner = owner_of(row)
        hops.append((owner, _text(row.get("next_hop_context_uid")) or owner, row.get("next_hop")))
    for context, observed in inp.observed_rib.items():
        for row in observed:
            hops.append(
                (str(context), _text(row.get("next_hop_context_uid")) or str(context), row.get("next_hop"))
            )
    owners = _policy_owners(inp, contexts)
    scoped = policy_scoped(inp.bgp.policies)
    for policy in inp.bgp.policies:
        for entry in policy.get("entries") or ():
            if entry.get("set_next_hop"):
                for owner in sorted(owners.get(policy_key(policy, scoped), ())):
                    hops.append((owner, owner, entry.get("set_next_hop")))
    for owner, resolving, value in hops:
        if not value:
            continue
        try:
            hop = ipaddress.ip_address(str(value))
        except ValueError:
            root(owner)
            continue
        if resolving is None:
            if any(cover.covers(context, hop) for context in held):
                roots.update(every)
        elif cover.covers(resolving, hop):
            root(owner)
    # Two or more processes of one context compete through its main table.
    counts: dict[str, int] = defaultdict(int)
    for context in contexts.values():
        counts[context] += 1
    roots.update(context for context, count in counts.items() if count > 1)
    return [
        {
            "kind": UNIQUENESS,
            "context_uid": context,
            "detail": "routing feedback is outside the independent-selection uniqueness certificate; "
            "one converged state cannot establish success or failure across all stable states",
        }
        for context in sorted(closure(inp, roots, edges=edges))
    ]
