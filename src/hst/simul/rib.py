"""One routing calculation per forwarding context.

The main RIB composes, per forwarding context (a `VrfInstance` uid), every route
that the collectors give the engine an input for. It selects among the routes,
resolves their next hops and compiles the table that the tracer reads.

The calculation takes the inputs in this order:

1. The connected and static routes of the graph (`ORIGINATES` and `STATIC_ROUTE`
   edges, read by `app/simul_read.py`).
2. The OSPF routes that `simul/ospf.py` computes from the observed link-state
   database of each process.
3. The BGP routes that `simul/propagate.py` computes. The seeds are the observed
   adj-RIB-in of every session whose received or accepted direction the snapshot
   captured (`core/bgpsource.py`). The engine propagates across a session that
   the snapshot did not capture.
4. The observed `rib` rows of each context (`core/ribsource.py`). They are read
   for validation. The exceptions below use them as a route input.

Selection is by administrative distance per platform and protocol
(`platforms.admin_distance`). A next hop is resolved recursively by longest
prefix match over the routes installed in the resolving context. The resolving
context is the context of the route, or `next_hop_context_uid` for a leaked
route. A route whose next hop does not resolve is not installed and is reported
as a gap. The IGP cost of a BGP path is the metric of the route that its next
hop resolves through. `simul/bestpath.py` compares it at its IGP cost step.

Redistribution follows the statements that the collectors parse. Static,
connected and OSPF routes enter BGP, through the route-map when the statement
has one. BGP, static and connected routes enter OSPF as type 5 external LSAs
that the redistributing router originates. The computed LSAs replace the
observed externals that those statements explain, in every observed database
that holds LSAs of the router. An observed external that no recorded statement
explains is kept and reported. A default route is originated only by
`default-information originate`.

VRF leaking has two mechanisms. The first is `next_hop_context_uid` on a route.
The second is the import and export pairing of the route-target reasoner
(`core/reasoner.py`). Under the pairing, the BGP selection of the exporter is
offered to the importer, and its next hop resolves in the exporting context.

The calculation runs to a fixed point. A round computes OSPF, then BGP over the
main RIB of the previous round, then the main RIB, then the redistributions and
the leaks that the next round reads. The run ends when a round changes nothing.
A run that does not settle within its outer-round budget reports
`no-routing-fixed-point`, and its rows are the state at the last round.

Validation compares the computed main RIB with the observed `rib` rows of the
same context, prefix by prefix. A prefix is `validated` when the device holds it
through the same protocol family with the same next hops, and with the same
metric for OSPF and BGP. A prefix is `mismatch` when the two sides disagree, or
when one side holds a prefix that the other side lacks and the inputs are
complete. A prefix is `not-observed` when an input is missing. The missing
input is a peer whose paths are not captured, an LSA that the database lacks, a
next hop that did not resolve, a context with no observed rows, or a protocol
that no collector models. A mismatch is reported as a model error through the
sink.

The collectors do not read the configured static route stanza on the Cisco
platforms. A static route is visible there only as a `rib` row. For a context
without a static route in the graph, the observed static rows are used as static
inputs, and a `not-collected` gap reports it.

An enabled PPPoE or DHCP IPv4 default producer is recorded separately from the
static routes (`access_defaults`). With complete pinned IPv4 RIB evidence, its
observed static default is a candidate of the unchanged context. A superseded
context does not take that candidate and reports an external-response gap.

The contexts, the prefixes and the candidates are processed in a fixed order
(candidates by administrative distance, then protocol, then next hop). Two runs
over the same input produce identical rows.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from hst.core.ipenc import addr_bytes
from hst.path.addrsets import _merge, _to_cidrs
from hst.path.gates.pbr import partition_rules
from hst.path.gates.routing import _route_partition
from hst.path.state import Ivals

from . import bestpath, certainty, ospf, platforms
from .compile import compile_policies, context_namespaces, resolving_namespace, scoped_policies
from .convergence import ConvergenceBudget, ConvergenceCertificate, RepeatedStateDetector
from .dependencies import PrefixPredicate, RoutingDependencies, RoutingWorklist
from .errors import ErrorSink
from .policy import Policy
from .propagate import POST_IMPORT, PRE_IMPORT, RouteDelta, SimulationInput
from .propagate import run as propagate
from .route import DEFAULT_LOCAL_WEIGHT, Route

CONNECTED = platforms.CONNECTED
STATIC = platforms.STATIC
OSPF = platforms.OSPF
BGP = "bgp"
OTHER = "other"

VALIDATED = ospf.VALIDATED
MISMATCH = ospf.MISMATCH
NOT_OBSERVED = ospf.NOT_OBSERVED
NOT_COLLECTED = "not-collected"
UNRESOLVED = "unresolved-next-hop"
# The gap kind of a best path that the arrival-order tie-break decided. No
# snapshot records the arrival order. The prefix has more than one stable
# outcome under the same configuration, and the computed rows hold one of them.
HISTORY_DEPENDENT = "history-dependent-selection"

# A bound for the outer rounds (OSPF, BGP, main RIB, redistribution, leaking).
# Each BGP run inside a round runs to its own fixed point (`propagate.MAX_ROUNDS`).
MAX_ROUNDS = 16
# The bound for the passes of the next-hop resolution loop in one main-RIB
# composition.
MAX_RESOLUTION_PASSES = 64

# The change intents this engine applies.
INTENT_BGP_SESSION_SHUT = "bgp_session.shut"
INTENT_OSPF_INTERFACE_COST = "ospf.interface_cost"
INTENT_OSPF_ADJACENCY_DOWN = "ospf.adjacency_down"
INTENT_KINDS: frozenset[str] = frozenset(
    {INTENT_BGP_SESSION_SHUT, INTENT_OSPF_INTERFACE_COST, INTENT_OSPF_ADJACENCY_DOWN}
)

# The direction outcomes under which the observed rows of a direction are complete.
_CAPTURED = certainty.CAPTURED

# Maps the protocol word of a `redistribute <protocol>` statement to a protocol
# family. The words are the vocabulary of the collectors (nxos.py
# `REDIST_PROTOCOLS`, iosxr_bgp.py, cisco_common.py `OSPF_REDIST_PROTOCOLS`).
_SOURCE_FAMILY = {
    "static": STATIC,
    "connected": CONNECTED,
    "direct": CONNECTED,
    "ospf": OSPF,
    "bgp": BGP,
}

# The order of the candidates within one administrative distance.
_PROTOCOL_ORDER = {CONNECTED: 0, STATIC: 1, OSPF: 2, BGP: 3}

ROW_KEYS: tuple[str, ...] = (
    "context_uid",
    "device_uid",
    "prefix",
    "prefixlen",
    "af",
    "protocol",
    "session_protocol",
    "admin",
    "metric",
    "igp_cost",
    "next_hop",
    "next_hop_context_uid",
    "interface",
    "discard",
    "source",
    "path_type",
    "local_pref",
    "med",
    "weight",
    "as_path",
    "origin",
    "origin_mechanism",
    "communities",
    "originator_ip",
    "cluster_list",
    "tag",
    "learned_from_session",
    "leak_path",
)


# --- helpers ------------------------------------------------------------------------


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _prefix(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def _prefix_key(prefix: str) -> tuple[int, int, int]:
    net = ipaddress.ip_network(prefix)
    return (net.version, int(net.network_address), net.prefixlen)


def _addr_key(value: str | None) -> tuple[int, int, str]:
    if value is None:
        return (2, 0, "")
    try:
        return (0, int(ipaddress.ip_address(value)), "")
    except ValueError:
        return (1, 0, value)


def _family(protocol: Any) -> str:
    """The protocol family of the protocol column of an observed `rib` row.

    The column holds a one-letter code or its legend word
    (`collectors/cisco_common.py`), an NX-OS client name (`ospf-1`,
    `bgp-65001`, `direct`) or an FRR protocol name. Any other value is `other`."""
    text = str(protocol or "").strip().lower()
    if not text:
        return OTHER
    head = text.split()[0].split("-")[0]
    if head in ("c", "connected", "direct", "directly"):
        return CONNECTED
    if head in ("s", "static"):
        return STATIC
    if head in ("o", "ospf", "ospfv2"):
        return OSPF
    if head in ("b", "bgp"):
        return BGP
    return OTHER


# --- input ----------------------------------------------------------------------------


@dataclass
class RibInput:
    """The input of the engine as plain dicts in the shape of the schema and of
    the side-store rows. `app/simul_read.read_rib_input` builds one from a
    pinned graph and the three side-store readers.

    `contexts` holds `{uid, device_uid, name, platform}` per forwarding context.
    `connected` holds `{context_uid, prefix, interface}`.
    `static` holds `{context_uid, prefix, next_hop, interface,
    next_hop_context_uid, discard, admin}`.
    `access_defaults` holds `{context_uid, interface, origin}` of the enabled
    IPv4 default-route producers in the interface configuration. `origin` is
    `pppoe` or `dhcp`.
    `ospf` holds one entry per OSPF process, `{uid, context_uid, router_id,
    process, rows, area_types, coverage, redist_<proto>_route_map...}`. `rows`
    has the `ospf_lsdb` shape. A prepared `model` (`LsdbModel`) replaces `rows`.
    `bgp` is the `SimulationInput` of the BGP engine. It is None when no context
    in scope runs BGP.
    `observed_paths` holds `BgpSource.paths` rows. `direction_status` maps
    `(session_uid, direction)` to an outcome. `session_state` maps `session_uid`
    to a `bgp_sessions` row.
    `rt_pairs` holds `{importer, exporter, via_rt}` from `reasoner.pair_and_group`.
    `pbr` holds `{if_uid, device_uid, context_uid, rules}` per interface that
    enforces a `PbrPolicy`. `rules` has the row shape that
    `gates/pbr._pbr_partition` reads.
    `observed_rib` maps `context_uid` to `rib` rows. `rib_coverage` maps
    `context_uid` to the recorded outcome of the device for the `rib` table.
    `observation_gaps` holds the context gaps that the compiler found. The
    result holds them among its gaps.
    """

    contexts: Sequence[Mapping[str, Any]] = ()
    connected: Sequence[Mapping[str, Any]] = ()
    static: Sequence[Mapping[str, Any]] = ()
    # The configured IPv4 access-default producers. The observed default route
    # of a producer is a candidate only for an unchanged context with complete
    # IPv4 RIB evidence.
    access_defaults: Sequence[Mapping[str, Any]] = ()
    ospf: Sequence[Mapping[str, Any]] = ()
    bgp: SimulationInput | None = None
    observed_paths: Sequence[Mapping[str, Any]] = ()
    direction_status: Mapping[tuple[str, str], str | None] = field(default_factory=dict)
    session_state: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    rt_pairs: Sequence[Mapping[str, Any]] = ()
    pbr: Sequence[Mapping[str, Any]] = ()
    observed_rib: Mapping[str, Sequence[Mapping[str, Any]]] = field(default_factory=dict)
    rib_coverage: Mapping[str, str | None] = field(default_factory=dict)
    observation_gaps: Sequence[Mapping[str, Any]] = ()
    # The changed routing contexts and their dependency closure. The observed
    # paths of a paired session in these contexts are not used as seeds.
    superseded_contexts: frozenset[str] = frozenset()
    # The external sessions whose supply the caller declares as fixed. A
    # superseded context reports no external-response gap for these sessions.
    fixed_external_sessions: frozenset[str] = frozenset()
    platform: str = platforms.IOSXE


# --- change intents ---------------------------------------------------------------------


def _ospf_model(entry: Mapping[str, Any], errors: ErrorSink) -> ospf.LsdbModel:
    model = entry.get("model")
    if isinstance(model, ospf.LsdbModel):
        return model
    return ospf.LsdbModel.from_rows(
        entry.get("rows") or (), area_types=entry.get("area_types"), errors=errors
    )


def shut_session(inp: RibInput, session_uid: str, errors: ErrorSink | None = None) -> RibInput:
    """The input with one `BgpSession` shut down.

    The session and its far end get the state `shutdown`. Their seeds and their
    entries in `observed_sessions` are removed. `inp` is not modified."""
    if inp.bgp is None or not any(str(s.get("uid")) == session_uid for s in inp.bgp.sessions):
        if errors is not None:
            errors.report(
                "unknown-bgp-session",
                f"session {session_uid!r} is not a BgpSession in the input; the shutdown changed nothing",
                session_uid,
            )
        return inp
    shut = {session_uid}
    far = certainty.paired_sessions(inp).get(session_uid)
    if far is not None:
        shut.add(str(far["uid"]))
    sessions = [
        {**s, "state": "shutdown"} if str(s.get("uid")) in shut else dict(s) for s in inp.bgp.sessions
    ]
    bgp = SimulationInput(
        processes=list(inp.bgp.processes),
        sessions=sessions,
        policies=list(inp.bgp.policies),
        local_routes=list(inp.bgp.local_routes),
        platform=inp.bgp.platform,
        seeds=[row for row in inp.bgp.seeds if str(row.get("session_uid")) not in shut],
        observed_sessions=[uid for uid in inp.bgp.observed_sessions if str(uid) not in shut],
    )
    contexts = certainty.process_contexts(inp)
    roots = {contexts[str(s["process_uid"])] for s in inp.bgp.sessions if str(s["uid"]) in shut}
    return _replace(
        inp,
        bgp=bgp,
        superseded_contexts=certainty.closure(inp, roots) | inp.superseded_contexts,
    )


def with_ospf_interface_cost(
    inp: RibInput, router_id: str, address: str, cost: int, errors: ErrorSink | None = None
) -> RibInput:
    """The input with the cost `cost` on the links that `router_id` originates
    from the interface at `address`. The change applies to every observed
    database that holds the LSA of the router
    (`LsdbModel.with_interface_cost`)."""
    return _change_models(
        inp,
        lambda model: model.with_interface_cost(router_id, address, cost),
        f"router {router_id} advertises no link for interface address {address} in any observed "
        "database; the cost change altered nothing",
        f"{router_id}/{address}",
        errors,
    )


def without_ospf_adjacency(
    inp: RibInput, router_a: str, router_b: str, errors: ErrorSink | None = None
) -> RibInput:
    """The input without the adjacency between two routers. The change applies
    to every observed database that holds both routers
    (`LsdbModel.without_adjacency`)."""
    return _change_models(
        inp,
        lambda model: model.without_adjacency(router_a, router_b),
        f"routers {router_a} and {router_b} share no link whose loss changes any observed database",
        f"{router_a}/{router_b}",
        errors,
    )


def _change_models(
    inp: RibInput, change: Any, no_effect: str, subject: str, errors: ErrorSink | None
) -> RibInput:
    sink = errors if errors is not None else ErrorSink()
    entries = []
    # The contexts whose database the change alters. `certainty.closure` adds
    # the contexts that depend on them.
    roots: set[str] = set()
    for entry in inp.ospf:
        model = _ospf_model(entry, sink)
        changed = change(model)
        if changed.lsas != model.lsas:
            roots.add(str(entry["context_uid"]))
            entries.append({**entry, "model": changed})
        else:
            entries.append({**entry, "model": model})
    if not roots and errors is not None:
        errors.report("ospf-change-no-effect", no_effect, subject)
    return _replace(
        inp,
        ospf=entries,
        superseded_contexts=certainty.closure(inp, roots) | inp.superseded_contexts,
    )


def apply_intents(
    inp: RibInput, intents: Sequence[Mapping[str, Any]], errors: ErrorSink | None = None
) -> RibInput:
    """The input with every routing intent applied, in order. An intent kind
    outside `INTENT_KINDS` raises `ValueError`."""
    out = inp
    for intent in intents:
        kind = str(intent.get("kind") or "")
        params = dict(intent.get("params") or {})
        if kind == INTENT_BGP_SESSION_SHUT:
            out = shut_session(out, str(params["session"]), errors)
        elif kind == INTENT_OSPF_INTERFACE_COST:
            out = with_ospf_interface_cost(
                out, str(params["router_id"]), str(params["address"]), int(params["cost"]), errors
            )
        elif kind == INTENT_OSPF_ADJACENCY_DOWN:
            out = without_ospf_adjacency(out, str(params["router_a"]), str(params["router_b"]), errors)
        else:
            raise ValueError(
                f"intent kind {kind!r} is not a routing intent; the catalog is {sorted(INTENT_KINDS)}"
            )
    return out


def _replace(inp: RibInput, **changes: Any) -> RibInput:
    return replace(inp, **changes)


# --- candidates and the installed table ---------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """One route offered to a context's main RIB by one protocol."""

    context_uid: str
    prefix: str
    protocol: str
    admin: int
    metric: int
    next_hop: str | None = None
    next_hop_context_uid: str | None = None
    interface: str | None = None
    discard: str | None = None
    source: str = ""
    session_protocol: str | None = None
    path_type: str | None = None
    route: Route | None = None
    # True for a BGP path that the process installs beside its best path
    # (`propagate._multipath`).
    multipath: bool = False

    @property
    def resolving_context(self) -> str:
        return self.next_hop_context_uid or self.context_uid

    @property
    def attached(self) -> bool:
        """Whether the route forwards without a recursive lookup.

        This holds for a connected route, an OSPF route, a route without a next
        hop and a static route with an egress interface."""
        if self.protocol in (CONNECTED, OSPF):
            return True
        if self.next_hop is None:
            return True
        return self.protocol == STATIC and self.interface is not None

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.admin,
            _PROTOCOL_ORDER.get(self.protocol, 9),
            _addr_key(self.next_hop),
            self.next_hop_context_uid or "",
            self.interface or "",
            self.discard or "",
            self.source,
        )


@dataclass(frozen=True)
class Installed:
    """A candidate that the main RIB holds, with the IGP cost of a lookup
    through it.

    The cost is 0 for a connected or static route, the metric for an OSPF
    route, and the cost at which the next hop resolved for a BGP route."""

    candidate: Candidate
    igp_cost: int


class Table:
    """The installed main RIB of every context, with longest-prefix match.

    Each context also keeps its prefixes indexed by address family and length,
    keyed by network address.
    """

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, list[Installed]]] = {}
        self._nets: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
        # Maps context, address family, prefix length and network address to the prefix.
        self._by_len: dict[str, dict[int, dict[int, dict[int, str]]]] = {}
        # Maps context and address family to the lengths present, longest first.
        self._lengths: dict[str, dict[int, list[int]]] = {}

    def _net(self, prefix: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        net = self._nets.get(prefix)
        if net is None:
            net = ipaddress.ip_network(prefix)
            self._nets[prefix] = net
        return net

    def _key(self, prefix: str) -> tuple[int, int, int]:
        net = self._net(prefix)
        return (net.version, int(net.network_address), net.prefixlen)

    def _index(self, context_uid: str, prefix: str, *, present: bool) -> None:
        net = self._net(prefix)
        lengths = self._by_len.setdefault(context_uid, {}).setdefault(net.version, {})
        held = lengths.setdefault(net.prefixlen, {})
        if present:
            held[int(net.network_address)] = prefix
        else:
            held.pop(int(net.network_address), None)
            if not held:
                del lengths[net.prefixlen]
        self._lengths.setdefault(context_uid, {})[net.version] = sorted(lengths, reverse=True)

    def set(self, context_uid: str, prefix: str, entries: list[Installed]) -> bool:
        """Install `entries` for one prefix (none removes it). Returns whether
        the table changed."""
        held = self.entries.get(context_uid, {}).get(prefix)
        if not entries:
            if held is None:
                return False
            del self.entries[context_uid][prefix]
            self._index(context_uid, prefix, present=False)
            return True
        if held == entries:
            return False
        self.entries.setdefault(context_uid, {})[prefix] = entries
        if held is None:
            self._index(context_uid, prefix, present=True)
        return True

    def lpm(self, context_uid: str, address: str | None, *, exclude: str | None = None) -> list[Installed]:
        """The installed entries of the longest prefix that covers `address` in
        one context. The prefix `exclude` is skipped."""
        if not address:
            return []
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return []
        lengths = self._by_len.get(context_uid, {}).get(addr.version)
        if not lengths:
            return []
        value, bits = int(addr), addr.max_prefixlen
        for length in self._lengths[context_uid][addr.version]:
            mask = ((1 << length) - 1) << (bits - length)
            prefix = lengths[length].get(value & mask)
            if prefix is not None and prefix != exclude:
                return list(self.entries[context_uid][prefix])
        return []

    def of_protocol(self, context_uid: str, protocol: str) -> list[Installed]:
        out: list[Installed] = []
        for prefix in sorted(self.entries.get(context_uid, {}), key=self._key):
            out.extend(e for e in self.entries[context_uid][prefix] if e.candidate.protocol == protocol)
        return out

    def installed(self) -> list[Installed]:
        out: list[Installed] = []
        for context_uid in sorted(self.entries):
            for prefix in sorted(self.entries[context_uid], key=self._key):
                out.extend(self.entries[context_uid][prefix])
        return out

    def signature(self) -> tuple[Any, ...]:
        return tuple((e.candidate, e.igp_cost) for e in self.installed())


def _resolve(table: Table, candidate: Candidate) -> int | None:
    """The IGP cost at which a candidate's next hop resolves in the installed
    table, or None when it does not resolve."""
    if candidate.attached:
        return candidate.metric if candidate.protocol == OSPF else 0
    context = candidate.resolving_context
    exclude = candidate.prefix if context == candidate.context_uid else None
    through = table.lpm(context, candidate.next_hop, exclude=exclude)
    if not through:
        return None
    cost = min(e.igp_cost for e in through)
    return cost if candidate.protocol == BGP else 0


def _select(
    table: Table, candidates: Sequence[Candidate], *, always_compare_med: bool = False
) -> list[Installed]:
    """The entries that one prefix installs.

    The lowest administrative distance with a candidate whose next hop resolves
    wins. Every resolvable route of the first protocol at that distance is
    installed as an ECMP set. For BGP the set is the path that
    `bestpath.compare_routes` prefers and the multipath candidates
    (`Candidate.multipath`) at the same IGP cost."""
    ordered = sorted(candidates, key=lambda c: c.sort_key)
    levels: dict[int, list[Candidate]] = {}
    for candidate in ordered:
        levels.setdefault(candidate.admin, []).append(candidate)
    for admin in sorted(levels):
        resolvable = []
        for candidate in levels[admin]:
            cost = _resolve(table, candidate)
            if cost is not None:
                resolvable.append(Installed(candidate, cost))
        if not resolvable:
            continue
        protocol = resolvable[0].candidate.protocol
        same = [e for e in resolvable if e.candidate.protocol == protocol]
        if protocol == BGP and len(same) > 1:
            single = [e for e in same if not e.candidate.multipath] or same
            best = single[0]
            for entry in single[1:]:
                left, right = entry.candidate.route, best.candidate.route
                if (
                    left is not None
                    and right is not None
                    and bestpath.compare_routes(left, right, always_compare_med=always_compare_med) > 0
                ):
                    best = entry
            same = [best] + [
                e for e in same if e is not best and e.candidate.multipath and e.igp_cost == best.igp_cost
            ]
        return same
    return []


def _install(
    candidates: Mapping[str, Mapping[str, Sequence[Candidate]]],
    errors: ErrorSink,
    *,
    resolution_passes: int = MAX_RESOLUTION_PASSES,
    always_compare_med: Collection[str] = (),
) -> tuple[Table, list[Candidate]]:
    """Compose the main RIB of every context from its candidates.

    Selection by administrative distance and recursive next-hop resolution
    repeat until a pass changes nothing. Returns the table and every candidate
    whose next hop did not resolve. `always_compare_med` holds the contexts
    whose BGP process compares MED across neighbouring ASes."""
    table = Table()
    # Every pass visits the prefixes in this order.
    order = [
        (context_uid, sorted(candidates[context_uid], key=table._key)) for context_uid in sorted(candidates)
    ]
    for _ in range(resolution_passes):
        changed = False
        for context_uid, prefixes in order:
            for prefix in prefixes:
                selected = _select(
                    table,
                    candidates[context_uid][prefix],
                    always_compare_med=context_uid in always_compare_med,
                )
                if table.set(context_uid, prefix, selected):
                    changed = True
        if not changed:
            break
    else:
        errors.report(
            "no-rib-fixed-point",
            f"next-hop resolution did not settle within {resolution_passes} passes; the table "
            "is the state at the last pass",
        )
    unresolved: list[Candidate] = []
    for context_uid, prefixes in order:
        for prefix in prefixes:
            for candidate in sorted(candidates[context_uid][prefix], key=lambda c: c.sort_key):
                if not candidate.attached and _resolve(table, candidate) is None:
                    unresolved.append(candidate)
    return table, unresolved


def _offer(store: dict[str, dict[str, list[Candidate]]], candidate: Candidate) -> None:
    held = store.setdefault(candidate.context_uid, {}).setdefault(candidate.prefix, [])
    if candidate not in held:
        held.append(candidate)


# --- rows -------------------------------------------------------------------------------


def _row(entry: Installed, device_uid: str | None, table: Table) -> dict[str, Any]:
    candidate = entry.candidate
    route = candidate.route
    net = ipaddress.ip_network(candidate.prefix)
    interface = candidate.interface
    if candidate.protocol == BGP and interface is None and candidate.next_hop is None:
        # A route leaked from the context that originates it takes the interface
        # of the prefix in the exporting context.
        exporter = candidate.next_hop_context_uid
        if exporter is not None:
            for held in table.entries.get(exporter, {}).get(candidate.prefix, []):
                if held.candidate.interface:
                    interface = held.candidate.interface
                    break
    row: dict[str, Any] = {
        "context_uid": candidate.context_uid,
        "device_uid": device_uid,
        "prefix": candidate.prefix,
        "prefixlen": net.prefixlen,
        "af": net.version,
        "protocol": candidate.protocol,
        "session_protocol": candidate.session_protocol,
        "admin": candidate.admin,
        "metric": candidate.metric,
        "igp_cost": entry.igp_cost,
        "next_hop": candidate.next_hop,
        "next_hop_context_uid": candidate.next_hop_context_uid,
        "interface": interface,
        "discard": candidate.discard,
        "source": candidate.source,
        "path_type": candidate.path_type,
        "local_pref": route.local_pref if route else None,
        "med": route.med if route else None,
        "weight": route.weight if route else None,
        "as_path": list(route.as_path) if route else None,
        "origin": route.origin if route else None,
        "origin_mechanism": route.origin_mechanism if route else None,
        "communities": sorted(route.communities) if route else None,
        "originator_ip": route.originator_ip if route else None,
        "cluster_list": list(route.cluster_list) if route else None,
        "tag": route.tag if route else None,
        "learned_from_session": route.learned_from_session if route else None,
        "leak_path": list(route.leak_path) if route else None,
    }
    return row


def _row_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        str(row.get("context_uid") or ""),
        _prefix_key(str(row["prefix"])),
        _PROTOCOL_ORDER.get(str(row.get("protocol")), 9),
        _addr_key(row.get("next_hop")),
        str(row.get("next_hop_context_uid") or ""),
        str(row.get("interface") or ""),
        str(row.get("discard") or ""),
    )


# --- the compiled FIB ------------------------------------------------------------------


class Fib:
    """The forwarding table that the tracer reads, compiled from the main RIB.

    `Fib` has the members of `core/ribsource.RibSource` (`lpm`, `overlapping`,
    `routes`, `available`, `approximate`, `has_rows`, `coverage`) with the same
    row shape. `path/trace.py` and `path/gates/routing.py` read it as they read
    the observed table. Every row has `fib: True` beside the `rib` columns.

    `partition` applies the PBR policies bound to an ingress interface with the
    semantics of `gates/pbr._pbr_partition` over plain rows. The first matching
    rule claims its part of the flow set as a group. The remainder continues to
    the later rules and then to the table of the interface. `forward` routes
    each group through the table that the group selects, by the longest-prefix
    partition of the tracer (`gates/routing._route_partition`).
    """

    available = True
    approximate = False

    def __init__(
        self,
        rows: Iterable[Mapping[str, Any]],
        pbr: Iterable[Mapping[str, Any]] = (),
        contexts: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self._rows: dict[str, list[dict[str, Any]]] = {}
        self._bounds: dict[str, list[tuple[bytes, bytes]]] = {}
        self._devices: dict[str, str | None] = {}
        for row in sorted(rows, key=_row_key):
            context_uid = str(row["context_uid"])
            held = {**row, "fib": True}
            self._rows.setdefault(context_uid, []).append(held)
            net = ipaddress.ip_network(str(row["prefix"]))
            self._bounds.setdefault(context_uid, []).append(
                (addr_bytes(str(net.network_address)), addr_bytes(str(net.broadcast_address)))
            )
            self._devices.setdefault(context_uid, row.get("device_uid"))
        for uid, context in (contexts or {}).items():
            self._devices.setdefault(str(uid), context.get("device_uid"))
        self._pbr: dict[str, dict[str, Any]] = {}
        for binding in sorted(pbr, key=lambda b: str(b.get("if_uid"))):
            rules = sorted(
                (dict(r) for r in binding.get("rules") or ()),
                key=lambda r: (
                    str(r.get("pol_name") or ""),
                    r.get("pos") if r.get("pos") is not None else -1,
                ),
            )
            self._pbr[str(binding["if_uid"])] = {
                "device_uid": binding.get("device_uid"),
                "context_uid": binding.get("context_uid"),
                "rules": rules,
            }

    # -- the RibSource surface

    def has_rows(self, device_uid: str) -> bool:
        return any(dev == device_uid and rows for dev, rows in self._device_rows())

    def coverage(self, device_uid: str) -> str | None:
        """`computed` for a device with rows, None otherwise. `_rib_gap` of the
        tracer treats `computed` as an answered outcome."""
        return "computed" if self.has_rows(device_uid) else None

    def _device_rows(self) -> Iterable[tuple[str | None, list[dict[str, Any]]]]:
        for context_uid in sorted(self._rows):
            yield self._devices.get(context_uid), self._rows[context_uid]

    def table(self, context_uid: str) -> list[dict[str, Any]] | None:
        """Every row of one context, or None when the calculation did not
        cover the context. A covered context with no route has no rows."""
        if context_uid not in self._devices:
            return None
        return [dict(r) for r in self._rows.get(context_uid, [])]

    def covers(self, context_uid: str) -> bool:
        """Whether the calculation covered the context."""
        return context_uid in self._devices

    def contexts(self) -> list[str]:
        return sorted(self._devices)

    def rows(self) -> list[dict[str, Any]]:
        return [dict(r) for context_uid in sorted(self._rows) for r in self._rows[context_uid]]

    def _scoped(self, device_uid: str, context_uid: str | None) -> list[dict[str, Any]]:
        if context_uid is None or self._devices.get(context_uid) != device_uid:
            return []
        return self._rows.get(context_uid, [])

    def lpm(
        self, device_uid: str, context_uid: str | None, probe_ip: str, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        """The ECMP set of routes that cover `probe_ip` in one context. The set
        is every row of the longest matching prefix. `legacy_vrf` is ignored."""
        try:
            addr = ipaddress.ip_address(probe_ip)
        except ValueError:
            return []
        best = -1
        winners: list[dict[str, Any]] = []
        for row in self._scoped(device_uid, context_uid):
            if row["af"] != addr.version:
                continue
            net = ipaddress.ip_network(str(row["prefix"]))
            if addr not in net:
                continue
            if net.prefixlen > best:
                best, winners = net.prefixlen, [dict(row)]
            elif net.prefixlen == best:
                winners.append(dict(row))
        return winners

    def overlapping(
        self,
        device_uid: str,
        context_uid: str | None,
        lo: bytes,
        hi: bytes,
        min_prefixlen: int,
        af: int,
        *,
        legacy_vrf: str | None = None,
    ) -> list[dict[str, Any]]:
        """Rows of family `af` whose interval intersects [lo, hi] and whose
        prefix is longer than `min_prefixlen` (`RibSource.overlapping`)."""
        rows = self._scoped(device_uid, context_uid)
        if not rows or context_uid is None:
            return []
        out = []
        for row, (row_lo, row_hi) in zip(rows, self._bounds[context_uid], strict=True):
            if row["af"] != af or row["prefixlen"] <= min_prefixlen:
                continue
            if row_lo <= hi and row_hi >= lo:
                out.append(dict(row))
        return out

    def routes(
        self, device_uid: str, context_uid: str | None, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        """Every row of one context that has a next hop (`RibSource.routes`)."""
        return [dict(r) for r in self._scoped(device_uid, context_uid) if r.get("next_hop")]

    def lookup(self, device_uid: str, context_uid: str | None) -> tuple[Any, Any] | None:
        """The `(lpm, overlapping)` pair that `gates/routing._route_partition`
        reads, bound to one device and context."""
        if not context_uid:
            return None
        return (
            lambda probe: self.lpm(device_uid, context_uid, probe),
            lambda lo, hi, minlen, af: self.overlapping(device_uid, context_uid, lo, hi, minlen, af),
        )

    # -- PBR and forwarding

    def partition(
        self,
        if_uid: str,
        src_set: list[tuple[int, int, int]],
        dst_set: list[tuple[int, int, int]],
        port: int | None = None,
        proto: str | None = None,
        *,
        service: tuple[frozenset[int] | None, Ivals | None, Ivals | None] | None = None,
    ) -> list[dict[str, Any]]:
        """The first-match partition of the PBR rules bound to `if_uid`
        (`gates/pbr.partition_rules`)."""
        binding = self._pbr.get(if_uid, {"rules": [], "context_uid": None})
        return partition_rules(
            binding["rules"],
            src_set,
            dst_set,
            binding.get("context_uid"),
            port=port,
            proto=proto,
            service=service,
        )

    def forward(
        self,
        if_uid: str,
        src_set: list[tuple[int, int, int]],
        dst_set: list[tuple[int, int, int]],
        port: int | None = None,
        proto: str | None = None,
    ) -> list[dict[str, Any]]:
        """The forwarding decision for a flow that arrives on `if_uid`.

        Each group of the PBR partition is routed through the table that it
        selects, by longest-prefix match. When the target table of a rule holds
        no route for a part of the destination, that part falls through to the
        table of the interface, and its group holds the target table in
        `fell_through_from`. Each group has `parts`, a list of `(destinations,
        routes)` pairs. `routes` is empty where no route covers the part. A
        group that `partition` marks `opaque` is returned with empty `parts`
        and without fallback. Its `opaque_reason` holds the reason."""
        binding = self._pbr.get(if_uid, {"device_uid": None, "context_uid": None, "rules": []})
        device_uid = str(binding.get("device_uid") or "")
        default_uid = binding.get("context_uid")
        out = []
        for group in self.partition(if_uid, src_set, dst_set, port, proto):
            if group.get("opaque"):
                out.append({**group, "parts": []})
                continue
            table_uid = group["table_uid"]
            lookup = self.lookup(device_uid, table_uid)
            parts = _route_partition([], list(group["dst"]), lookup)
            fallback = group["pos"] is not None and default_uid and default_uid != table_uid
            selected = [(part, winners) for part, winners in parts if winners or not fallback]
            missing = [interval for part, winners in parts if not winners and fallback for interval in part]
            if selected:
                entry = dict(group)
                entry["dst"] = _merge([interval for part, _ in selected for interval in part])
                entry["parts"] = [(_to_cidrs(part), winners) for part, winners in selected]
                out.append(entry)
            if missing:
                entry = dict(group)
                entry["dst"] = _merge(missing)
                entry["fell_through_from"] = table_uid
                entry["table_uid"] = default_uid
                entry["parts"] = [
                    (_to_cidrs(part), winners)
                    for part, winners in _route_partition(
                        [], entry["dst"], self.lookup(device_uid, default_uid)
                    )
                ]
                out.append(entry)
        return out


# --- the calculation ---------------------------------------------------------------------


@dataclass
class RibResult:
    """The output of the calculation.

    It holds the installed main RIB of every context with the keys of
    `ROW_KEYS`, the compiled FIB, the validation report, every gap, every model
    error, the last BGP run and each OSPF calculation."""

    rib: list[dict[str, Any]] = field(default_factory=list)
    fib: Fib = field(default_factory=lambda: Fib(()))
    validation: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    model_errors: list[dict[str, str | None]] = field(default_factory=list)
    rounds: int = 0
    bgp: RouteDelta | None = None
    ospf: dict[str, ospf.OspfCalculation] = field(default_factory=dict)
    convergence: dict[str, Any] = field(default_factory=dict)
    # `compute_incremental` sets this field.
    incremental: dict[str, Any] = field(default_factory=dict)


@dataclass
class IncrementalRib:
    """A reusable routing calculation split into independent execution islands.

    A caller keeps this value with its pinned counterfactual model. A
    policy-only overlay passes the same ``RibInput`` and an empty dirty set,
    and the routing result is reused. A routing overlay supplies the changed
    ``(context, AF, prefix)`` keys, and only their dependency islands are
    recalculated.
    """

    input: RibInput
    dependencies: RoutingDependencies
    components: dict[tuple[str, ...], RibResult]
    result: RibResult


@dataclass
class _Externals:
    """The type 5 LSAs that the redistribution statements of the OSPF routers
    in the input produce in one round.

    `lsas` holds the computed LSAs of each router with a modelled statement.
    `withdrawn` holds the routers whose observed default LSA is withdrawn.
    `unestablished_default` holds the routers that keep an observed default LSA
    without a default route in their main RIB and without a recorded
    `default-information originate`."""

    lsas: dict[str, list[ospf.Lsa]] = field(default_factory=dict)
    withdrawn: set[str] = field(default_factory=set)
    unestablished_default: set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.lsas or self.withdrawn or self.unestablished_default)


class _Run:
    """The state that the rounds of one calculation share."""

    def __init__(self, inp: RibInput, errors: ErrorSink) -> None:
        self.inp = inp
        self.errors = errors
        self.contexts: dict[str, dict[str, Any]] = {str(c["uid"]): dict(c) for c in inp.contexts}
        self.gaps: list[dict[str, Any]] = []
        # per context, the protocol families whose inputs are incomplete
        self.incomplete: dict[str, set[str]] = {}
        # the families of `incomplete` marked without a cause (`mark_incomplete`)
        self.incomplete_uncaused: dict[str, set[str]] = {}
        self._compiled: dict[tuple[Any, str], tuple[dict[str, Policy], dict[str, list[dict[str, Any]]]]] = {}
        self._policy_contexts: frozenset[str] | None = None
        self._origin_gaps: set[tuple[str, str, str]] = set()
        self._explained: dict[str, frozenset[str]] | None = None
        self._external_context: dict[str, str] = {}
        self._external_gaps: set[tuple[str, str, str]] = set()
        self.bgp_processes: list[Mapping[str, Any]] = (
            sorted(
                (p for p in inp.bgp.processes if str(p.get("proto", "bgp")).lower() == "bgp"),
                key=lambda p: str(p["uid"]),
            )
            if inp.bgp is not None
            else []
        )
        self.process_by_context: dict[str, Mapping[str, Any]] = {}
        for process in self.bgp_processes:
            self.process_by_context.setdefault(str(process["context_uid"]), process)
        self.always_compare_med = frozenset(
            str(p["context_uid"]) for p in self.bgp_processes if p.get("always_compare_med")
        )

    # -- platforms and policies

    def platform(self, context_uid: str, *, local: bool = False) -> str:
        """The platform profile of a context. A platform with no profile is
        reported and gets the IOS-XE profile.

        `local` is for the distance of a connected or a static route. Each
        profile has the same 2 values, so a platform with no profile is not
        reported."""
        raw = str((self.contexts.get(context_uid) or {}).get("platform") or self.inp.platform)
        known = platforms.known(raw)
        if known is not None:
            return known
        if raw.strip().lower() == "vyos":
            # The two FRR profiles differ only in the no-policy default of BGP. A
            # BGP process reads its profile from its node (`process_platform`).
            return platforms.FRR_TRADITIONAL
        return platforms.IOSXE if local else platforms.normalize(raw, self.errors)

    def process_platform(self, process: Mapping[str, Any]) -> str:
        raw = process.get("platform")
        if raw:
            return platforms.normalize(str(raw), self.errors)
        return self.platform(str(process["context_uid"]))

    def context_device(self, context_uid: str) -> str | None:
        """The device that owns a context. An OSPF process row has no
        `device_uid`."""
        return (self.contexts.get(context_uid) or {}).get("device_uid") or None

    def policy_namespace(self, device_uid: Any, context_uid: Any) -> str | None:
        """The namespace in which a policy name of `context_uid` on `device_uid`
        resolves (`compile.resolving_namespace`).

        It is the context when a policy row is defined in that context, as for
        a Check Point virtual system, and the device otherwise."""
        if self._policy_contexts is None:
            self._policy_contexts = context_namespaces(
                self.inp.bgp.policies if self.inp.bgp is not None else ()
            )
        return resolving_namespace(self._policy_contexts, device_uid, context_uid)

    def compiled(
        self, platform: str, namespace: str | None = None
    ) -> tuple[dict[str, Policy], dict[str, list[dict[str, Any]]]]:
        """The policies defined in `namespace` (`policy_namespace`), compiled
        for `platform`."""
        key = (namespace or None, platform)
        if key not in self._compiled:
            policies = self.inp.bgp.policies if self.inp.bgp is not None else ()
            self._compiled[key] = compile_policies(
                scoped_policies(policies, namespace), platform, self.errors
            )
        return self._compiled[key]

    def through_route_map(
        self, name: str, route: Route, platform: str, subject: str, namespace: str | None = None
    ) -> Route | None:
        """A candidate for redistribution through its route-map, or None when
        the map denies it. An undefined map follows the platform's rule
        (`platforms.redistribute_undefined_permits`) and is reported. The
        route-map is the one defined in `namespace` (`policy_namespace`)."""
        policies, prefix_lists = self.compiled(platform, namespace)
        if name not in policies:
            permits = platforms.redistribute_undefined_permits(platform)
            self.errors.report(
                "undefined-redistribute-route-map",
                f"{subject} names route map {name!r}, which no RoutePolicy node defines; "
                + (
                    "the redistribution proceeds unfiltered"
                    if permits
                    else "the redistribution does not occur"
                ),
                name,
            )
            return route if permits else None
        return bestpath._run_policy(
            name,
            route,
            direction="out",
            policies=policies,
            prefix_lists=prefix_lists,
            errors=self.errors,
            stype=bestpath.EBGP,
            peer_as=None,
        )

    def mark_incomplete(self, context_uid: str, family: str, *, cause: str | None = None) -> None:
        """Mark a family of the context as incomplete.

        `cause` is the structured cause of the gap when the evaluator can
        discharge it (`certainty.PEER_SUPPLY`). A mark without a cause is also
        recorded in `incomplete_uncaused`."""
        self.incomplete.setdefault(context_uid, set()).add(family)
        if cause is None:
            self.incomplete_uncaused.setdefault(context_uid, set()).add(family)

    # -- the static inputs

    def base_candidates(self) -> dict[str, dict[str, list[Candidate]]]:
        """The connected and static candidates. A context without a configured
        static route takes its observed static rows as candidates."""
        store: dict[str, dict[str, list[Candidate]]] = {}
        for row in self.inp.connected:
            context_uid = str(row["context_uid"])
            prefix = _prefix(row.get("prefix"))
            if prefix is None:
                self.errors.report(
                    "malformed-route", f"connected prefix {row.get('prefix')!r} is not a network; left out"
                )
                continue
            platform = self.platform(context_uid, local=True)
            _offer(
                store,
                Candidate(
                    context_uid,
                    prefix,
                    CONNECTED,
                    platforms.admin_distance(platform, CONNECTED),
                    0,
                    interface=_text(row.get("interface")),
                    source=CONNECTED,
                ),
            )
        configured: set[str] = set()
        for row in self.inp.static:
            candidate = self._static_candidate(row, STATIC)
            if candidate is not None:
                configured.add(candidate.context_uid)
                _offer(store, candidate)
        for context_uid in sorted(self.contexts):
            observed = [
                r for r in self.inp.observed_rib.get(context_uid, ()) if _family(r.get("protocol")) == STATIC
            ]
            unmodeled = []
            for row in observed:
                if self._access_default(context_uid, row):
                    self._offer_access_default(store, context_uid, row)
                else:
                    unmodeled.append(row)
            observed = unmodeled
            if context_uid in configured:
                continue
            if not observed:
                continue
            for row in observed:
                candidate = self._static_candidate({**row, "context_uid": context_uid}, "observed-static")
                if candidate is not None:
                    _offer(store, candidate)
                    self.gaps.append(
                        {
                            "kind": NOT_OBSERVED,
                            "context_uid": context_uid,
                            "prefix": candidate.prefix,
                            "scope": "context" if context_uid in self.inp.superseded_contexts else "prefix",
                            "detail": f"static configuration for {candidate.prefix} is missing; "
                            "selected RIB observations do not establish unselected static alternatives",
                        }
                    )
            self.gaps.append(
                {
                    "kind": NOT_COLLECTED,
                    "context_uid": context_uid,
                    "detail": (
                        f"the static route configuration of {context_uid} is not collected on its platform; "
                        f"{len(observed)} selected static rib row(s) are representative inputs only; "
                        "unselected static alternatives are not observed"
                    ),
                }
            )
        return store

    def _access_default(self, context_uid: str, row: Mapping[str, Any]) -> bool:
        return (
            row.get("prefix") == "0.0.0.0/0"
            and not row.get("discard")
            and row.get("next_hop_context_uid") in (None, context_uid)
            and any(
                producer.get("context_uid") == context_uid
                and producer.get("interface") == row.get("interface")
                and producer.get("interface")
                and producer.get("origin") in {"pppoe", "dhcp"}
                for producer in self.inp.access_defaults
            )
        )

    def _offer_access_default(
        self, store: dict[str, dict[str, list[Candidate]]], context_uid: str, row: Mapping[str, Any]
    ) -> None:
        if context_uid in self.inp.superseded_contexts:
            self.mark_incomplete(context_uid, STATIC)
            self.gaps.append(
                {
                    "kind": certainty.EXTERNAL_RESPONSE,
                    "context_uid": context_uid,
                    "detail": f"access default via {row.get('interface')}: the pinned PPPoE/DHCP "
                    "route does not establish post-change supply or hidden alternatives",
                }
            )
            return
        if any(
            configured.get("context_uid") == context_uid and configured.get("prefix") == row.get("prefix")
            for configured in self.inp.static
        ):
            # A configured default route already supplies the candidate.
            return
        context = self.contexts[context_uid]
        if self.inp.rib_coverage.get(context_uid) != "complete" or 4 not in (
            context.get("observed_rib_afs") or ()
        ):
            self.mark_incomplete(context_uid, STATIC)
            self.gaps.append(
                {
                    "kind": NOT_OBSERVED,
                    "context_uid": context_uid,
                    "prefix": row["prefix"],
                    "scope": "prefix",
                    "detail": "access default requires a complete pinned IPv4 RIB; "
                    "the selected PPPoE/DHCP next hops are not established",
                }
            )
            return
        candidate = self._static_candidate({**row, "context_uid": context_uid}, "observed-access-default")
        if candidate is not None:
            _offer(store, candidate)

    def _static_candidate(self, row: Mapping[str, Any], source: str) -> Candidate | None:
        context_uid = str(row["context_uid"])
        prefix = _prefix(row.get("prefix"))
        if prefix is None:
            self.errors.report(
                "malformed-route", f"static prefix {row.get('prefix')!r} is not a network; left out"
            )
            return None
        platform = self.platform(context_uid, local=True)
        admin = row.get("admin")
        next_hop_context = _text(row.get("next_hop_context_uid"))
        return Candidate(
            context_uid,
            prefix,
            STATIC,
            int(admin) if admin is not None else platforms.admin_distance(platform, STATIC),
            0,
            next_hop=_text(row.get("next_hop")),
            next_hop_context_uid=next_hop_context if next_hop_context != context_uid else None,
            interface=_text(row.get("interface")),
            discard=_text(row.get("discard")),
            source=source,
        )

    # -- OSPF

    def explained_externals(self) -> dict[str, frozenset[str]]:
        """Per router id, the prefixes that its recorded `redistribute`
        statements explain.

        A prefix is explained when the observed RIB of the router holds it
        under a protocol family that one of those statements redistributes. The
        computed set replaces only an explained type 5 LSA. A default route is
        not explained."""
        if self._explained is None:
            explained: dict[str, frozenset[str]] = {}
            for entry in self.inp.ospf:
                router_id = _text(entry.get("router_id"))
                if router_id is None:
                    continue
                self._external_context.setdefault(router_id, str(entry["context_uid"]))
                families = {
                    family
                    for protocol, _route_map in _redistribute_statements(entry)
                    if (family := _SOURCE_FAMILY.get(protocol)) not in (None, OSPF)
                }
                prefixes: set[str] = set()
                for row in self.inp.observed_rib.get(str(entry["context_uid"]), ()):
                    prefix = _prefix(row.get("prefix"))
                    if (
                        prefix is not None
                        and _family(row.get("protocol")) in families
                        and ipaddress.ip_network(prefix).prefixlen > 0
                    ):
                        prefixes.add(prefix)
                explained[router_id] = frozenset(prefixes)
            self._explained = explained
        return self._explained

    def _external_gap(self, router_id: str, lsa: ospf.Lsa, detail: str) -> None:
        key = (router_id, lsa.lsid, detail)
        if key in self._external_gaps:
            return
        self._external_gaps.add(key)
        context_uid = self._external_context.get(router_id, "")
        self.gaps.append(
            {
                "kind": NOT_OBSERVED,
                "context_uid": context_uid,
                "prefix": lsa.prefix,
                "scope": "prefix",
                "detail": f"{lsa.describe()}: {detail}",
            }
        )
        if context_uid:
            self.mark_incomplete(context_uid, OSPF)

    def ospf_round(
        self,
        models: Mapping[str, tuple[Mapping[str, Any], ospf.LsdbModel]],
        externals: _Externals,
    ) -> tuple[dict[str, ospf.OspfCalculation], dict[str, dict[str, list[Candidate]]]]:
        calculations: dict[str, ospf.OspfCalculation] = {}
        store: dict[str, dict[str, list[Candidate]]] = {}
        for uid in sorted(models):
            entry, model = models[uid]
            context_uid = str(entry["context_uid"])
            router_id = _text(entry.get("router_id"))
            if router_id is None:
                self.errors.report(
                    "ospf-router-id-unknown",
                    f"OSPF process {uid} records no router id, so its database cannot be rooted; "
                    "no OSPF route was computed for it",
                    uid,
                )
                self.mark_incomplete(context_uid, OSPF)
                continue
            platform = self.platform(context_uid)
            calc = ospf.calculate(
                _with_externals(model, externals, self.explained_externals(), self._external_gap),
                router_id,
                platform=platform,
                errors=self.errors,
            )
            calculations[uid] = calc
            if calc.gaps:
                self.mark_incomplete(context_uid, OSPF)
            for row in ospf.rib_rows(context_uid, calc, platform=platform):
                _offer(
                    store,
                    Candidate(
                        context_uid,
                        str(row["prefix"]),
                        OSPF,
                        int(row["admin"]),
                        int(row["metric"]),
                        next_hop=row["next_hop"],
                        source=f"ospf:{uid}",
                        path_type=row.get("path_type"),
                    ),
                )
        return calculations, store

    def externals(self, table: Table) -> _Externals:
        """The type 5 LSAs that every OSPF process in the input originates from
        its `redistribute` statements, keyed by router id, and the state of the
        observed default LSA of each router (`_default_origination`).

        A default route is not redistributed into OSPF. IOS-XE, NX-OS, IOS-XR
        and FRR originate it only through `default-information originate`. A
        router is in `lsas` only when at least one of its statements was
        modelled."""
        out = _Externals()
        for entry in sorted(self.inp.ospf, key=lambda e: str(e.get("uid"))):
            router_id = _text(entry.get("router_id"))
            if router_id is None:
                continue
            context_uid = str(entry["context_uid"])
            self._default_origination(table, entry, router_id, context_uid, out)
            statements = _redistribute_statements(entry)
            if not statements:
                continue
            platform = self.platform(context_uid)
            lsas: dict[str, ospf.Lsa] = {}
            modelled = False
            for protocol, route_map in statements:
                family = _SOURCE_FAMILY.get(protocol)
                if family is None or family == OSPF:
                    self.errors.report(
                        "redistribution-not-modeled",
                        f"OSPF process {entry.get('uid')} redistributes {protocol}, which this engine has no "
                        "routes for; the redistribution was not applied",
                        str(entry.get("uid")),
                    )
                    continue
                modelled = True
                for installed in table.of_protocol(context_uid, family):
                    net = ipaddress.ip_network(installed.candidate.prefix)
                    if net.version != 4 or net.prefixlen == 0:
                        continue
                    # The metric of the source route is not used. A `set metric`
                    # in the route-map supplies the OSPF metric, and the
                    # platform default applies otherwise.
                    offered = _redistribution_route(installed, family).with_(med=None)
                    if route_map:
                        passed = self.through_route_map(
                            route_map,
                            offered,
                            platform,
                            f"OSPF process {entry.get('uid')} redistribute {protocol}",
                            self.policy_namespace(self.context_device(context_uid), context_uid),
                        )
                        if passed is None:
                            continue
                        offered = passed
                    metric = offered.med
                    if metric is None:
                        metric = platforms.ospf_redistribute_metric(platform, family)
                    lsa = ospf.Lsa(
                        ospf.EXTERNAL,
                        str(net.network_address),
                        router_id,
                        area=None,
                        metric=metric,
                        mask=str(net.netmask),
                        forwarding_address=ospf.NO_FORWARDING_ADDRESS,
                        metric_type=2,
                    )
                    lsas.setdefault(lsa.lsid, lsa)
            if modelled:
                out.lsas[router_id] = [lsas[k] for k in sorted(lsas, key=_addr_key)]
        return out

    def _default_origination(
        self, table: Table, entry: Mapping[str, Any], router_id: str, context_uid: str, out: _Externals
    ) -> None:
        """Decide the observed default LSA of a router from
        `default-information originate`.

        A router with the recorded statement keeps its observed default LSA
        when the statement is `always` or the main RIB holds a default route
        from another protocol. Otherwise the LSA is withdrawn. A router without
        the recorded statement keeps the LSA. It is added to
        `unestablished_default` when the main RIB holds no such default route."""
        recorded = bool(entry.get("default_information_originate"))
        if recorded and entry.get("default_information_originate_always"):
            return
        held = any(
            installed.candidate.protocol != OSPF
            for installed in table.entries.get(context_uid, {}).get("0.0.0.0/0", ())
        )
        if held:
            return
        if recorded:
            out.withdrawn.add(router_id)
        else:
            out.unestablished_default.add(router_id)

    # -- BGP

    def local_originations(self, table: Table, bgp: RouteDelta | None) -> list[dict[str, Any]]:
        """Evaluate the recorded BGP origination intent against the main RIB of
        the preceding round.

        A ``SimulationInput.local_routes`` row without ``intent`` passes
        through unchanged. A network or aggregate row with ``intent=True`` is
        conditional. A network row under import-check requires an exact
        main-RIB route that is a non-BGP route or a learned BGP route. An
        aggregate row requires a selected more-specific BGP path. The
        ``route_map`` of the row (the route-map of a network statement or the
        ``attribute-map`` of an aggregate) then runs against the route that the
        statement originates, with origin IGP, weight 32768 and an empty AS
        path by default.

        Sources:
        https://www.cisco.com/c/en/us/td/docs/ios/iproute_bgp/command/reference/irg_book/irg_bgp1.html
        and https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/19345-bgp-noad.html
        FRR states the same aggregate condition at
        https://docs.frrouting.org/en/stable-10.1/bgp.html#route-aggregation
        """
        if self.inp.bgp is None:
            return []
        rows: list[dict[str, Any]] = []
        for row in self.inp.bgp.local_routes:
            if not row.get("intent"):
                rows.append(dict(row))
                continue
            process_uid = str(row.get("process_uid"))
            context_uid = self._process_context(process_uid)
            prefix = _prefix(row.get("prefix"))
            mechanism = str(row.get("origin_mechanism") or "network").lower()
            if context_uid is None or prefix is None:
                continue
            process = next(p for p in self.bgp_processes if str(p["uid"]) == process_uid)
            if mechanism == "network":
                import_check = process.get("network_import_check")
                platform = self.process_platform(process)
                if import_check is None and platform in {
                    platforms.IOSXE,
                    platforms.IOSXR,
                    platforms.NXOS,
                }:
                    import_check = True
                if import_check is None:
                    self._origin_uncertain(
                        context_uid,
                        process_uid,
                        prefix,
                        "BGP network import-check behavior was not recorded for this platform",
                    )
                    continue
                installed = table.entries.get(context_uid, {}).get(prefix, ()) if import_check else ()
                # An exact learned BGP route satisfies the IP-RIB check. The
                # candidate that this network statement originated in the
                # previous round does not satisfy it.
                if import_check and not any(
                    entry.candidate.protocol != BGP
                    or (
                        entry.candidate.route is not None
                        and entry.candidate.route.learned_from_session is not None
                    )
                    for entry in installed
                ):
                    continue
            elif mechanism == "aggregate":
                # `attribute_map` runs below as the route-map of the aggregate.
                # `summary_only` is applied at export
                # (propagate._suppressing_aggregate). This stage does not model
                # `as_set`, `suppress_map` and `advertise_map` (as-set path
                # merging, per-contributor suppression, conditional
                # advertisement).
                unsupported = sorted(
                    key for key in ("as_set", "suppress_map", "advertise_map") if row.get(key)
                )
                if row.get("unsupported_options"):
                    unsupported.extend(str(option) for option in row["unsupported_options"])
                if unsupported:
                    self._origin_uncertain(
                        context_uid,
                        process_uid,
                        prefix,
                        f"aggregate {prefix} uses unsupported attributes {', '.join(unsupported)}",
                    )
                    continue
                aggregate = ipaddress.ip_network(prefix)
                contributors = bgp.selected.get(context_uid, ()) if bgp is not None else ()
                if not any(
                    (candidate := ipaddress.ip_network(route.prefix)).version == aggregate.version
                    and int(aggregate.network_address) <= int(candidate.network_address)
                    and int(candidate.broadcast_address) <= int(aggregate.broadcast_address)
                    and candidate.prefixlen > aggregate.prefixlen
                    for route in contributors
                ):
                    continue
            else:
                self._origin_uncertain(
                    context_uid,
                    process_uid,
                    prefix,
                    f"BGP origin intent {mechanism!r} is not modeled",
                )
                continue
            held = dict(row)
            route_map = _text(row.get("route_map") or row.get("policy_name"))
            if route_map:
                route = Route(
                    prefix=prefix,
                    protocol=BGP,
                    src_protocol=str(row.get("src_protocol") or mechanism),
                    origin_mechanism=mechanism,
                    local_pref=int(row.get("local_pref", 100)),
                    med=int(row["med"]) if row.get("med") is not None else None,
                    weight=int(row.get("weight", DEFAULT_LOCAL_WEIGHT)),
                    as_path=tuple(int(asn) for asn in (row.get("as_path") or ())),
                    origin=str(row.get("origin") or "igp"),
                    communities=frozenset(str(c) for c in (row.get("communities") or ())),
                )
                passed = self.through_route_map(
                    route_map,
                    route,
                    self.process_platform(process),
                    f"BGP process {process_uid} {mechanism} {prefix}",
                    self.policy_namespace(process.get("device_uid"), process.get("context_uid")),
                )
                if passed is None:
                    if mechanism == "aggregate":
                        # The route-map of a network statement is a filter,
                        # and a deny drops the origination. NX-OS, IOS-XE and
                        # IOS-XR document the attribute-map of an aggregate as
                        # setting attributes only. A deny by an attribute-map
                        # is reported as a gap.
                        self._origin_uncertain(
                            context_uid,
                            process_uid,
                            prefix,
                            f"aggregate {prefix} attribute-map {route_map!r} denied the route; "
                            "an attribute-map is expected to set attributes only",
                        )
                    continue
                held.update(
                    local_pref=passed.local_pref,
                    med=passed.med,
                    weight=passed.weight,
                    as_path=list(passed.as_path),
                    origin=passed.origin,
                    communities=sorted(passed.communities),
                )
            rows.append(held)
        return rows

    def _peer_label(self, session: Mapping[str, Any], context_uid: str) -> str:
        """The label of the peer of a session for a gap detail. It holds the
        peer address, the router, and the VRF when the VRF is not the default
        one."""
        peer = session.get("peer_ip") or session.get("uid")
        context = self.contexts.get(context_uid, {})
        where = str(context.get("device_uid") or context_uid or "a router not in the input")
        vrf = str(context.get("name") or "")
        if vrf and vrf.lower() not in {"default", "global"}:
            where = f"{where} VRF {vrf}"
        return f"BGP peer {peer} on {where}"

    def _origin_uncertain(self, context_uid: str, process_uid: str, prefix: str, detail: str) -> None:
        key = (process_uid, prefix, detail)
        if key in self._origin_gaps:
            return
        self._origin_gaps.add(key)
        self.gaps.append(
            {
                "kind": NOT_OBSERVED,
                "context_uid": context_uid,
                "process_uid": process_uid,
                "prefix": prefix,
                "detail": detail + "; the route was not originated",
            }
        )
        self.mark_incomplete(context_uid, BGP)

    def observed_seeds(self) -> tuple[list[dict[str, Any]], list[str], list[Mapping[str, Any]]]:
        """The seeds from the observed paths, the sessions that they cover, and
        the session dicts for the BGP engine with their observed state.

        A session with no captured direction and no far end in the input is
        reported as a `not-observed` gap."""
        assert self.inp.bgp is not None  # noqa: S101 - callers check
        paired = certainty.paired_sessions(self.inp)
        by_session: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
        for row in self.inp.observed_paths:
            by_session.setdefault((str(row.get("session_uid")), str(row.get("direction"))), []).append(row)
        seeds: list[dict[str, Any]] = []
        observed: list[str] = []
        sessions: list[Mapping[str, Any]] = []
        for session in sorted(self.inp.bgp.sessions, key=lambda s: str(s.get("uid"))):
            uid = str(session.get("uid"))
            held = dict(session)
            state = self.inp.session_state.get(uid)
            if state is not None and state.get("state") is not None and "observed_state" not in held:
                held["observed_state"] = state.get("state")
            sessions.append(held)
            if str(held.get("state", "")).lower() == "shutdown":
                continue
            context_uid = str(self._process_context(str(held.get("process_uid"))) or "")
            if context_uid in self.inp.superseded_contexts:
                if uid in paired:
                    # The far end is in the input. The engine recomputes the
                    # paths of this session from the changed far end.
                    continue
                if held.get(certainty.OMITTED_FAR_END):
                    # The read left out the far end of this session. The
                    # received paths cannot be recomputed.
                    self.gaps.append(
                        {
                            "kind": NOT_OBSERVED,
                            "context_uid": context_uid,
                            "session_uid": uid,
                            "detail": f"session {uid}: the change can alter what far end "
                            f"{held.get(certainty.OMITTED_FAR_END)} sends, and that far end is not in "
                            "the input, so the received paths cannot be recomputed",
                        }
                    )
                    self.mark_incomplete(context_uid, BGP)
                    continue
                if uid not in self.inp.fixed_external_sessions:
                    self.gaps.append(
                        {
                            "kind": certainty.EXTERNAL_RESPONSE,
                            "context_uid": context_uid,
                            "session_uid": uid,
                            "detail": f"session {uid}: external advertisements may change; "
                            "complete Adj-RIB-in records pre-change supply, not hidden alternatives",
                        }
                    )
            received = self.inp.direction_status.get((uid, "received"))
            accepted = self.inp.direction_status.get((uid, "accepted"))
            rows_received = by_session.get((uid, "received"), [])
            rows_accepted = by_session.get((uid, "accepted"), [])
            if received in _CAPTURED or (received is None and rows_received):
                stage, rows = PRE_IMPORT, rows_received
                if received not in _CAPTURED or (received == "complete-empty" and rows_received):
                    self.gaps.append(
                        {
                            "kind": NOT_OBSERVED,
                            "context_uid": context_uid,
                            "session_uid": uid,
                            "detail": f"session {uid}: received-path completeness is "
                            "missing or contradictory",
                        }
                    )
            elif accepted in _CAPTURED or (accepted is None and rows_accepted):
                stage, rows = POST_IMPORT, rows_accepted
                # The cause `certainty.PEER_SUPPLY` marks a gap whose only
                # unknown is the set of routes that the peer sends.
                self.gaps.append(
                    {
                        "kind": NOT_OBSERVED,
                        "cause": certainty.PEER_SUPPLY,
                        "context_uid": context_uid,
                        "session_uid": uid,
                        "detail": f"{self._peer_label(held, context_uid)}: only the routes the router "
                        "accepted are collected, not the routes the peer sends before import policy",
                    }
                )
            else:
                has_far_end = uid in paired
                if not has_far_end:
                    context_uid = str(self._process_context(str(held.get("process_uid"))) or "")
                    self.gaps.append(
                        {
                            "kind": NOT_OBSERVED,
                            "cause": certainty.PEER_SUPPLY,
                            "context_uid": context_uid,
                            "session_uid": uid,
                            "detail": (
                                f"{self._peer_label(held, context_uid)}: the routes it sends are not "
                                f"collected (received {received or 'not recorded'}, accepted "
                                f"{accepted or 'not recorded'}), and no session of the peer is in the input"
                            ),
                        }
                    )
                    if context_uid:
                        self.mark_incomplete(context_uid, BGP, cause=certainty.PEER_SUPPLY)
                continue
            observed.append(uid)
            for row in sorted(rows, key=lambda r: (str(r.get("prefix")), str(r.get("path_id") or ""))):
                seeds.append(
                    {
                        "process_uid": held.get("process_uid"),
                        "session_uid": uid,
                        "stage": stage,
                        "prefix": row.get("prefix"),
                        "next_hop": row.get("next_hop"),
                        "next_hop_context_uid": row.get("next_hop_context_uid"),
                        "as_path": row.get("as_path"),
                        "local_pref": row.get("local_pref"),
                        "med": row.get("med"),
                        "origin": row.get("origin"),
                        "communities": row.get("communities"),
                    }
                )
        return seeds, observed, sessions

    def _process_context(self, process_uid: str) -> str | None:
        for process in self.bgp_processes:
            if str(process["uid"]) == process_uid:
                return str(process["context_uid"])
        return None

    def _default_redistributed(self, process: Mapping[str, Any], platform: str, version: int) -> bool:
        """Whether a default route of this address family enters BGP through a
        `redistribute` statement.

        It enters only with `default-information originate` for the family.
        When the rule of the platform is not established, or the configuration
        of the process was not recorded, the default route is left out and
        reported as a gap."""
        if version in (process.get("default_information_originate_afs") or ()):
            return True
        context_uid, process_uid = str(process["context_uid"]), str(process["uid"])
        default = "0.0.0.0/0" if version == 4 else "::/0"
        if platforms.redistribute_excludes_default(platform) is None:
            self._origin_uncertain(
                context_uid,
                process_uid,
                default,
                f"whether {platform} redistributes a default route into BGP is not established",
            )
        elif process.get("origin_config_recorded") is not True:
            self._origin_uncertain(
                context_uid,
                process_uid,
                default,
                "default-information originate was not recorded for this process",
            )
        return False

    def redistributed(self, table: Table) -> list[dict[str, Any]]:
        """The locally originated BGP routes from the `redistribute` statements
        of every BGP process over the installed main RIB, through the named
        route-map."""
        rows: list[dict[str, Any]] = []
        for process in self.bgp_processes:
            context_uid = str(process["context_uid"])
            platform = self.process_platform(process)
            for protocol, route_map in _redistribute_statements(process):
                family = _SOURCE_FAMILY.get(protocol)
                if family is None or family == BGP:
                    self.errors.report(
                        "redistribution-not-modeled",
                        f"BGP process {process['uid']} redistributes {protocol}, which this engine has no "
                        "routes for; the redistribution was not applied",
                        str(process["uid"]),
                    )
                    continue
                internal_only = family == OSPF and platforms.redistribute_ospf_internal_only(platform)
                for installed in table.of_protocol(context_uid, family):
                    candidate = installed.candidate
                    if internal_only and candidate.path_type not in (ospf.INTRA_AREA, ospf.INTER_AREA):
                        continue
                    net = ipaddress.ip_network(candidate.prefix)
                    if net.prefixlen == 0 and not self._default_redistributed(process, platform, net.version):
                        continue
                    route = _redistribution_route(installed, family)
                    if route_map:
                        passed = self.through_route_map(
                            route_map,
                            route,
                            platform,
                            f"BGP process {process['uid']} redistribute {protocol}",
                            self.policy_namespace(process.get("device_uid"), process.get("context_uid")),
                        )
                        if passed is None:
                            continue
                        route = passed
                    rows.append(
                        {
                            "process_uid": str(process["uid"]),
                            "prefix": route.prefix,
                            "next_hop": route.next_hop,
                            "next_hop_context_uid": route.next_hop_context_uid,
                            "src_protocol": family,
                            "origin_mechanism": "redistribute",
                            "local_pref": route.local_pref,
                            "med": route.med,
                            "weight": route.weight,
                            "as_path": list(route.as_path),
                            "origin": route.origin,
                            "tag": route.tag,
                            "communities": sorted(route.communities),
                        }
                    )
        return rows

    def leaks(self, delta: RouteDelta) -> tuple[list[dict[str, Any]], dict[str, dict[str, list[Candidate]]]]:
        """The routes leaked under the route-target pairing. An importer with a
        BGP process gets seeds. An importer without a BGP process gets direct
        candidates."""
        seeds: list[dict[str, Any]] = []
        direct: dict[str, dict[str, list[Candidate]]] = {}
        pairs = sorted(
            ((str(p["importer"]), str(p["exporter"])) for p in self.inp.rt_pairs),
        )
        for importer, exporter in pairs:
            if importer == exporter:
                continue
            for route in sorted(delta.selected.get(exporter, []), key=lambda r: _prefix_key(r.prefix)):
                path = (*route.leak_path, exporter)
                if importer in path:
                    continue
                leaked = route.with_(
                    next_hop_context_uid=route.next_hop_context_uid or exporter,
                    leak_path=path,
                    weight=0,
                    origin_mechanism="learned",
                    learned_from_session=f"leak:{exporter}",
                )
                process = self.process_by_context.get(importer)
                admin = route.admin
                if admin is None:
                    admin = platforms.admin_distance(
                        self.platform(importer),
                        platforms.IBGP if route.protocol == "ibgp" else platforms.EBGP,
                    )
                if process is not None:
                    seeds.append(
                        {
                            "process_uid": str(process["uid"]),
                            "session_uid": f"leak:{exporter}",
                            "stage": POST_IMPORT,
                            "prefix": leaked.prefix,
                            "next_hop": leaked.next_hop,
                            "next_hop_context_uid": leaked.next_hop_context_uid,
                            "as_path": list(leaked.as_path),
                            "local_pref": leaked.local_pref,
                            "med": leaked.med,
                            "origin": leaked.origin,
                            "communities": sorted(leaked.communities),
                            "originator_ip": leaked.originator_ip,
                            "origin_mechanism": "learned",
                            "src_protocol": leaked.src_protocol,
                            "session_protocol": leaked.protocol,
                            "admin": admin,
                            "leak_path": list(path),
                        }
                    )
                    continue
                _offer(direct, self.bgp_candidate(importer, leaked.with_(admin=admin)))
        return seeds, direct

    def bgp_candidate(self, context_uid: str, route: Route) -> Candidate:
        admin = route.admin
        if admin is None:
            if route.is_locally_originated:
                admin = platforms.admin_distance(self.platform(context_uid), platforms.LOCAL_BGP)
            else:
                admin = platforms.admin_distance(
                    self.platform(context_uid), platforms.IBGP if route.protocol == "ibgp" else platforms.EBGP
                )
        return Candidate(
            context_uid,
            route.prefix,
            BGP,
            int(admin),
            route.effective_med,
            next_hop=route.next_hop,
            next_hop_context_uid=route.next_hop_context_uid,
            # An aggregate installs as a discard route. The tracer uses the
            # discard value `blackhole` for an aggregate (path/trace.py).
            discard="blackhole" if route.origin_mechanism == "aggregate" else None,
            source=BGP,
            session_protocol=route.protocol,
            route=route,
        )


def _redistribution_route(installed: Installed, family: str) -> Route:
    """The BGP path of a redistributed main-RIB route.

    It has origin incomplete, the local weight, the metric of the source route
    as MED and the next hop of the source route. A connected route has no next
    hop."""
    candidate = installed.candidate
    return Route(
        prefix=candidate.prefix,
        next_hop=None if family == CONNECTED else candidate.next_hop,
        protocol="bgp",
        src_protocol=family,
        origin_mechanism="redistribute",
        weight=DEFAULT_LOCAL_WEIGHT,
        med=candidate.metric,
        origin="incomplete",
        next_hop_context_uid=candidate.next_hop_context_uid,
    )


# `certainty.dependencies` derives its OSPF edges from the same statements.
_redistribute_statements = certainty.redistribute_statements


def _with_externals(
    model: ospf.LsdbModel,
    externals: _Externals,
    explained: Mapping[str, frozenset[str]],
    report: Callable[[str, ospf.Lsa, str], None],
) -> ospf.LsdbModel:
    """The database with the explained type 5 LSAs of each redistributing
    router replaced by the computed set. The replacement applies to every
    router that has an LSA in the database.

    An observed type 5 LSA of such a router that no recorded statement
    explains is kept and reported. The default LSA follows
    `default-information originate` (`_Run._default_origination`)."""
    if not externals:
        return model
    present = {lsa.adv_router for lsa in model.lsas.values()}
    new = model.copy()
    routers = set(externals.lsas) | externals.withdrawn | externals.unestablished_default
    for router_id in sorted(routers, key=_addr_key):
        if router_id not in present:
            continue
        for key, lsa in [
            (k, lsa)
            for k, lsa in new.lsas.items()
            if lsa.lsa_type == ospf.EXTERNAL and lsa.adv_router == router_id
        ]:
            prefix = lsa.prefix
            if prefix is not None and ipaddress.ip_network(prefix).prefixlen == 0:
                if router_id in externals.withdrawn:
                    del new.lsas[key]
                elif router_id in externals.unestablished_default:
                    report(
                        router_id,
                        lsa,
                        "kept as observed; no default route in the router's main RIB and no "
                        "recorded default-information originate establishes it",
                    )
            elif router_id in externals.lsas:
                if prefix in explained.get(router_id, ()):
                    del new.lsas[key]
                else:
                    report(
                        router_id,
                        lsa,
                        "kept as observed; no recorded redistribute statement of the router explains it",
                    )
        for lsa in externals.lsas.get(router_id, ()):
            new.lsas[lsa.key] = lsa
    return new


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((str(k), _freeze(v)) for k, v in value.items()))
    if isinstance(value, list | tuple | set | frozenset):
        return tuple(_freeze(v) for v in value)
    return value


def compute(
    inp: RibInput,
    errors: ErrorSink | None = None,
    *,
    validate_observed: bool = True,
    budget: ConvergenceBudget | None = None,
    checkpoint: Callable[[], bool | None] | None = None,
) -> RibResult:
    """The main RIB, the FIB and the validation report of every context in
    the input.

    `checkpoint` is called before each outer round. When it returns False, the
    calculation stops and reports `no-routing-fixed-point` with a
    `budget-exhausted` certificate."""
    errors = errors or ErrorSink()
    budget = budget or ConvergenceBudget()
    dependency_model = RoutingDependencies(inp)
    run = _Run(inp, errors)
    base = run.base_candidates()
    models = {
        str(entry.get("uid") or f"ospf:{entry['context_uid']}"): (entry, _ospf_model(entry, errors))
        for entry in inp.ospf
    }
    for uid, (entry, _model) in sorted(models.items()):
        coverage = entry.get("coverage")
        if coverage not in (None, "complete", "complete-empty"):
            run.mark_incomplete(str(entry["context_uid"]), OSPF)
            run.gaps.append(
                {
                    "kind": NOT_OBSERVED,
                    "context_uid": str(entry["context_uid"]),
                    "process_uid": uid,
                    "detail": f"the link-state database of OSPF process {uid} is recorded as {coverage}",
                }
            )

    seeds: list[dict[str, Any]] = []
    observed_sessions: list[str] = []
    sessions: list[Mapping[str, Any]] = []
    if inp.bgp is not None:
        seeds, observed_sessions, sessions = run.observed_seeds()
    paired = certainty.paired_sessions(inp)
    process_context = certainty.process_contexts(inp)
    superseded_sessions = {
        str(s["uid"])
        for s in sessions
        if str(s.get("state", "")).lower() == "shutdown"
        or (str(s["uid"]) in paired and process_context[str(s["process_uid"])] in inp.superseded_contexts)
    }

    externals = _Externals()
    redistributed: list[dict[str, Any]] = []
    leak_seeds: list[dict[str, Any]] = []
    leak_direct: dict[str, dict[str, list[Candidate]]] = {}
    previous_bgp: dict[str, dict[str, list[Candidate]]] = {}
    signature: tuple[Any, ...] | None = None
    states = RepeatedStateDetector()
    convergence: ConvergenceCertificate | None = None
    table = Table()
    delta: RouteDelta | None = None
    calculations: dict[str, ospf.OspfCalculation] = {}
    unresolved: list[Candidate] = []
    rounds = 0
    timed_out = False

    def exhausted(detail: str, why: str) -> ConvergenceCertificate:
        predicates = [
            PrefixPredicate(item.candidate.context_uid, item.candidate.prefix) for item in table.installed()
        ]
        affected = dependency_model.certificate(predicates)
        errors.report(
            "no-routing-fixed-point",
            f"the routing calculation {why}; the rows are the state at the last round and are not the answer",
        )
        return ConvergenceCertificate(
            "budget-exhausted",
            rounds,
            affected.downstream_contexts,
            tuple((item.context_uid, item.prefix) for item in affected.affected),
            downstream_contexts=affected.downstream_contexts,
            detail=detail,
        )

    for _ in range(budget.outer_rounds):
        if checkpoint is not None and checkpoint() is False:
            timed_out = True
            break
        rounds += 1
        calculations, ospf_candidates = run.ospf_round(models, externals)
        resolver_base, _left = _install(
            _merged(base, ospf_candidates, previous_bgp, leak_direct),
            errors,
            resolution_passes=budget.resolution_passes,
            always_compare_med=run.always_compare_med,
        )

        bgp_candidates: dict[str, dict[str, list[Candidate]]] = {}
        if inp.bgp is not None:

            def resolve(context_uid: str, route: Route, _base: Table = resolver_base) -> int | None:
                if route.next_hop is None:
                    return 0
                context = route.next_hop_context_uid or context_uid
                exclude = route.prefix if context == context_uid else None
                through = _base.lpm(context, route.next_hop, exclude=exclude)
                return min(e.igp_cost for e in through) if through else None

            delta = propagate(
                SimulationInput(
                    processes=list(inp.bgp.processes),
                    sessions=sessions,
                    policies=list(inp.bgp.policies),
                    local_routes=[*run.local_originations(resolver_base, delta), *redistributed],
                    platform=inp.bgp.platform,
                    seeds=[
                        *(
                            row
                            for row in inp.bgp.seeds
                            if str(row.get("session_uid")) not in superseded_sessions
                        ),
                        *seeds,
                        *leak_seeds,
                    ],
                    observed_sessions=[
                        *(uid for uid in inp.bgp.observed_sessions if str(uid) not in superseded_sessions),
                        *observed_sessions,
                    ],
                ),
                errors,
                resolver=resolve,
                budget=budget,
            )
            for context_uid in sorted(delta.selected):
                for route in delta.selected[context_uid]:
                    _offer(bgp_candidates, run.bgp_candidate(context_uid, route))
            for context_uid in sorted(delta.multipath):
                for route in delta.multipath[context_uid]:
                    _offer(bgp_candidates, replace(run.bgp_candidate(context_uid, route), multipath=True))
        table, unresolved = _install(
            _merged(base, ospf_candidates, bgp_candidates, leak_direct),
            errors,
            resolution_passes=budget.resolution_passes,
            always_compare_med=run.always_compare_med,
        )
        now = (table.signature(), _freeze(delta.rib) if delta is not None else None)
        if now == signature:
            convergence = ConvergenceCertificate("settled", rounds)
            break
        prior = states.observe(now, rounds)
        if prior is not None:
            predicates = [
                PrefixPredicate(item.candidate.context_uid, item.candidate.prefix)
                for item in table.installed()
            ]
            affected = dependency_model.certificate(predicates)
            convergence = ConvergenceCertificate(
                "cycle",
                rounds,
                affected.downstream_contexts,
                tuple((item.context_uid, item.prefix) for item in affected.affected),
                prior,
                rounds,
                affected.downstream_contexts,
                "the outer routing state repeated exactly",
            )
            errors.report(
                "no-routing-fixed-point",
                f"the routing calculation repeated its exact state from round {prior} at round {rounds}",
            )
            break
        signature = now
        previous_bgp = bgp_candidates
        redistributed = run.redistributed(table)
        externals = run.externals(table)
        if delta is not None:
            leak_seeds, leak_direct = run.leaks(delta)
    else:
        convergence = exhausted(
            "the configured outer-round budget was exhausted without a repeated state",
            f"did not settle within {budget.outer_rounds} rounds",
        )
    if timed_out:
        convergence = exhausted(
            "the time budget was exhausted without a repeated state",
            f"stopped at its time budget after {rounds} rounds",
        )

    if convergence is None:
        convergence = ConvergenceCertificate("settled", rounds)

    gaps = [*map(dict, inp.observation_gaps), *run.gaps, *certainty.proof_gaps(inp)]
    for context_uid, families in sorted(run.incomplete.items()):
        held = [g for g in gaps if g.get("kind") == NOT_OBSERVED and g.get("context_uid") == context_uid]
        if any(g.get("cause") != certainty.PEER_SUPPLY for g in held):
            continue
        if held:
            # Every `not-observed` gap of the context has the cause
            # `certainty.PEER_SUPPLY`. Only the families marked without a cause
            # get a context-wide gap.
            families = run.incomplete_uncaused.get(context_uid, set())
            if not families:
                continue
        gaps.append(
            {
                "kind": NOT_OBSERVED,
                "context_uid": context_uid,
                "detail": (
                    f"{context_uid}: incomplete {', '.join(sorted(families))} inputs cannot establish "
                    "the forwarding table"
                ),
            }
        )
    unresolved_prefixes: dict[str, set[str]] = {}
    for candidate in unresolved:
        unresolved_prefixes.setdefault(candidate.context_uid, set()).add(candidate.prefix)
        gaps.append(
            {
                "kind": UNRESOLVED,
                "context_uid": candidate.context_uid,
                "prefix": candidate.prefix,
                "protocol": candidate.protocol,
                "next_hop": candidate.next_hop,
                "next_hop_context_uid": candidate.resolving_context,
                "detail": (
                    f"{candidate.protocol} route {candidate.prefix} via {candidate.next_hop} in "
                    f"{candidate.context_uid}: no installed route in {candidate.resolving_context} "
                    "covers the next hop, so the route is not installed"
                ),
            }
        )
    if delta is not None:
        for item in delta.unresolved:
            context_uid = str(item["context_uid"])
            unresolved_prefixes.setdefault(context_uid, set()).add(str(item["prefix"]))
            gaps.append(
                {
                    "kind": UNRESOLVED,
                    "context_uid": context_uid,
                    "prefix": item["prefix"],
                    "protocol": BGP,
                    "next_hop": item["next_hop"],
                    "next_hop_context_uid": item["next_hop_context_uid"],
                    "session_uid": item.get("session_uid"),
                    "detail": (
                        f"BGP path {item['prefix']} via {item['next_hop']} on process {item['process_uid']}: "
                        f"no installed route in {item['next_hop_context_uid']} covers the next hop, so the "
                        "path is not eligible and is not installed"
                    ),
                }
            )
        by_uid = {str(s["uid"]): s for s in sessions}
        by_ends = {(s.get("local_ip"), s.get("peer_ip")): s for s in sessions}
        for item in delta.unresolved:
            # The advertiser of an iBGP path did not rewrite a next hop that
            # differs from the peer address. When the advertising session
            # records no `next-hop-self`, the unresolved next hop is also a
            # `not-observed` gap.
            receiving = by_uid.get(str(item.get("session_uid")))
            if (
                receiving is None
                or bestpath.session_type(receiving) != bestpath.IBGP
                or item["next_hop"] == receiving.get("peer_ip")
            ):
                continue
            advertising = by_ends.get((receiving.get("peer_ip"), receiving.get("local_ip")))
            if advertising is not None and advertising.get("next_hop_self"):
                continue
            gaps.append(
                {
                    "kind": NOT_OBSERVED,
                    "context_uid": str(item["context_uid"]),
                    "prefix": item["prefix"],
                    "scope": "prefix",
                    "session_uid": item.get("session_uid"),
                    "detail": (
                        f"iBGP path {item['prefix']} via {item['next_hop']} on process "
                        f"{item['process_uid']}: the next hop does not resolve, and next-hop-self is not "
                        "recorded for the advertising session, so whether the device holds the route "
                        "with the advertiser as next hop is not known"
                    ),
                }
            )
        for item in delta.history_dependent:
            gaps.append(
                {
                    "kind": HISTORY_DEPENDENT,
                    "context_uid": str(item["context_uid"]),
                    "process_uid": item["process_uid"],
                    "prefix": item["prefix"],
                    "protocol": BGP,
                    "detail": (
                        f"BGP prefix {item['prefix']} on process {item['process_uid']}: the selection "
                        "is not invariant across arrival histories, missing tie-break attributes or "
                        "candidate comparison orders; another selection is not ruled out"
                    ),
                }
            )
        for item in delta.multipath_unknown:
            gaps.append(
                {
                    "kind": NOT_OBSERVED,
                    "context_uid": str(item["context_uid"]),
                    "process_uid": item["process_uid"],
                    "prefix": item["prefix"],
                    "scope": "prefix",
                    "protocol": BGP,
                    "detail": (
                        f"BGP prefix {item['prefix']} on process {item['process_uid']}: more than one "
                        "equal path, and the process's maximum-paths is not recorded, so how many of "
                        "them the RIB installs is not known"
                    ),
                }
            )
    # A gap of a context is copied to every context that depends on it.
    propagated = []
    # The context of an observed session does not depend on the far end of
    # that session.
    dependency_edges = certainty.dependencies(
        inp,
        observed={
            *observed_sessions,
            *(
                str(uid)
                for uid in (inp.bgp.observed_sessions if inp.bgp is not None else ())
                if str(uid) not in superseded_sessions
            ),
        },
    )
    dependency_closures: dict[str, frozenset[str]] = {}
    for gap in gaps:
        if gap.get("kind") not in {NOT_OBSERVED, HISTORY_DEPENDENT, certainty.EXTERNAL_RESPONSE}:
            continue
        context = str(gap.get("context_uid") or "")
        if context not in dependency_closures:
            dependency_closures[context] = certainty.closure(inp, {context}, edges=dependency_edges)
        for consumer in sorted(dependency_closures[context] - {context}):
            propagated.append({**gap, "context_uid": consumer, "origin_context_uid": context})
    gaps.extend(propagated)
    for uid, calc in sorted(calculations.items()):
        context_uid = str(models[uid][0]["context_uid"])
        for gap in calc.gaps:
            gaps.append({**gap, "context_uid": context_uid, "process_uid": uid})

    rows = [
        _row(entry, run.contexts.get(entry.candidate.context_uid, {}).get("device_uid"), table)
        for entry in table.installed()
    ]
    rows.sort(key=_row_key)
    fib = Fib(rows, inp.pbr, run.contexts)
    validation = (
        validate(rows, inp, incomplete=run.incomplete, unresolved=unresolved_prefixes, errors=errors)
        if validate_observed
        else []
    )
    return RibResult(
        rib=rows,
        fib=fib,
        validation=validation,
        gaps=gaps,
        model_errors=errors.as_dicts(),
        rounds=rounds,
        bgp=delta,
        ospf=calculations,
        convergence=convergence.as_dict(),
    )


def compute_incremental(
    inp: RibInput,
    *,
    previous: IncrementalRib | None = None,
    dirty: Iterable[PrefixPredicate] = (),
    dependency_complete: bool = True,
    validate_observed: bool = True,
    budget: ConvergenceBudget | None = None,
    checkpoint: Callable[[], bool | None] | None = None,
) -> IncrementalRib:
    """Compute a routing overlay with component reuse.

    The caller provides the route keys an overlay changed. An empty dirty set
    reuses a prior result only when the routing input is identical.
    """
    dependencies = RoutingDependencies(inp)
    dirty_keys = tuple(sorted(set(dirty)))
    if previous is None:
        all_keys = tuple(
            predicate
            for context_uid in sorted(dependencies.contexts)
            for predicate in sorted(dependencies.prefixes.get(context_uid, ()))
        )
        worklist = RoutingWorklist(
            all_keys,
            all_keys,
            dependencies.execution_components,
            (),
            dependency_complete,
            "INITIAL_COMPONENT_BUILD" if dependency_complete else "DEPENDENCY_INDEX_INCOMPLETE",
        )
    elif not dirty_keys:
        if previous.input == inp and dependency_complete:
            reused = dependencies.execution_components
            worklist = RoutingWorklist((), (), (), reused, True, "POLICY_ONLY_ROUTING_REUSE")
            result = replace(previous.result, incremental=worklist.as_dict())
            return IncrementalRib(inp, dependencies, previous.components, result)
        worklist = dependencies.worklist((), complete=False)
    else:
        topology_matches = previous.dependencies.execution_components == dependencies.execution_components
        worklist = dependencies.worklist(dirty_keys, complete=dependency_complete and topology_matches)

    if not worklist.complete:
        # An incomplete worklist runs one calculation over the whole input.
        cold = compute(inp, validate_observed=validate_observed, budget=budget, checkpoint=checkpoint)
        return IncrementalRib(inp, dependencies, {}, replace(cold, incremental=worklist.as_dict()))

    changed_reused = tuple(
        component
        for component in worklist.reused_components
        if previous is None
        or component not in previous.components
        or _component_input(previous.input, set(component)) != _component_input(inp, set(component))
    )
    if changed_reused:
        recompute = tuple(sorted({*worklist.components, *changed_reused}))
        reused = tuple(
            component for component in worklist.reused_components if component not in changed_reused
        )
        additional = {
            predicate
            for component in changed_reused
            for context_uid in component
            for predicate in dependencies.prefixes.get(context_uid, ())
        }
        affected = tuple(sorted(set(worklist.affected) | additional))
        worklist = RoutingWorklist(
            worklist.dirty,
            affected,
            recompute,
            reused,
            True,
            "DIRTY_HINT_INCOMPLETE",
        )

    components: dict[tuple[str, ...], RibResult] = {}
    for component in dependencies.execution_components:
        if previous is not None and component in worklist.reused_components:
            prior = previous.components.get(component)
            if prior is not None:
                components[component] = prior
                continue
            # A component without a previous result is recomputed.
        component_input = _component_input(inp, set(component))
        components[component] = compute(
            component_input,
            validate_observed=validate_observed,
            budget=budget,
            checkpoint=checkpoint,
        )
    result = _merge_component_results(inp, components, worklist, validate_observed=validate_observed)
    return IncrementalRib(inp, dependencies, components, result)


def incremental_from_result(inp: RibInput, result: RibResult) -> IncrementalRib | None:
    """Make an `IncrementalRib` from a settled result of ``compute``.

    Returns ``None`` when the result has a model error, when it is not settled,
    or when a validation row or a gap has no context of the input.
    """
    dependencies = RoutingDependencies(inp)
    if result.model_errors or result.convergence.get("status") != "settled":
        return None
    all_contexts = dependencies.contexts
    scoped = (result.validation, result.gaps)
    if any(str(item.get("context_uid") or "") not in all_contexts for entries in scoped for item in entries):
        return None
    components: dict[tuple[str, ...], RibResult] = {}
    for component in dependencies.execution_components:
        contexts = set(component)
        component_input = _component_input(inp, contexts)
        rows = [dict(row) for row in result.rib if str(row.get("context_uid") or "") in contexts]
        components[component] = RibResult(
            rib=rows,
            fib=Fib(rows, component_input.pbr, {str(row["uid"]): row for row in component_input.contexts}),
            validation=[
                dict(item) for item in result.validation if str(item.get("context_uid") or "") in contexts
            ],
            gaps=[dict(item) for item in result.gaps if str(item.get("context_uid") or "") in contexts],
            rounds=result.rounds,
            bgp=_slice_route_delta(result.bgp, contexts),
            ospf={
                key: value
                for key, value in result.ospf.items()
                if any(
                    str(entry.get("uid") or f"ospf:{entry['context_uid']}") == key
                    and str(entry.get("context_uid") or "") in contexts
                    for entry in inp.ospf
                )
            },
            convergence=ConvergenceCertificate("settled", result.rounds).as_dict(),
        )
    return IncrementalRib(inp, dependencies, components, result)


def _slice_route_delta(delta: RouteDelta | None, contexts: set[str]) -> RouteDelta | None:
    if delta is None:
        return None
    selected = {
        context_uid: list(routes) for context_uid, routes in delta.selected.items() if context_uid in contexts
    }
    return RouteDelta(
        rib=[dict(row) for row in delta.rib if str(row.get("context_uid") or "") in contexts],
        model_errors=[],
        rounds=delta.rounds,
        selected=selected,
        unresolved=[
            dict(item) for item in delta.unresolved if str(item.get("context_uid") or "") in contexts
        ],
        history_dependent=[
            dict(item) for item in delta.history_dependent if str(item.get("context_uid") or "") in contexts
        ],
        suppressed=[
            dict(item) for item in delta.suppressed if str(item.get("context_uid") or "") in contexts
        ],
        multipath={
            context_uid: list(routes)
            for context_uid, routes in delta.multipath.items()
            if context_uid in contexts
        },
        multipath_unknown=[
            dict(item) for item in delta.multipath_unknown if str(item.get("context_uid") or "") in contexts
        ],
    )


def _component_input(inp: RibInput, contexts: set[str]) -> RibInput:
    """The routing input of the contexts of one execution island."""

    def context_rows(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        return [row for row in rows if str(row.get("context_uid") or "") in contexts]

    bgp: SimulationInput | None = None
    process_uids: set[str] = set()
    session_uids: set[str] = set()
    if inp.bgp is not None:
        processes = context_rows(inp.bgp.processes)
        process_uids = {str(row["uid"]) for row in processes}
        sessions = [row for row in inp.bgp.sessions if str(row.get("process_uid") or "") in process_uids]
        session_uids = {str(row["uid"]) for row in sessions}
        bgp = SimulationInput(
            processes=processes,
            sessions=sessions,
            # Every island keeps every policy.
            policies=list(inp.bgp.policies),
            local_routes=[
                row for row in inp.bgp.local_routes if str(row.get("process_uid") or "") in process_uids
            ],
            platform=inp.bgp.platform,
            seeds=[row for row in inp.bgp.seeds if str(row.get("process_uid") or "") in process_uids],
            observed_sessions=[uid for uid in inp.bgp.observed_sessions if str(uid) in session_uids],
        )
    return RibInput(
        contexts=[row for row in inp.contexts if str(row.get("uid") or "") in contexts],
        connected=context_rows(inp.connected),
        static=context_rows(inp.static),
        access_defaults=context_rows(inp.access_defaults),
        ospf=context_rows(inp.ospf),
        bgp=bgp,
        observed_paths=[
            row
            for row in inp.observed_paths
            if str(row.get("context_uid") or "") in contexts
            or str(row.get("process_uid") or "") in process_uids
        ],
        direction_status={
            key: value for key, value in inp.direction_status.items() if str(key[0]) in session_uids
        },
        session_state={key: value for key, value in inp.session_state.items() if str(key) in session_uids},
        rt_pairs=[
            row
            for row in inp.rt_pairs
            if str(row.get("importer") or "") in contexts and str(row.get("exporter") or "") in contexts
        ],
        pbr=context_rows(inp.pbr),
        observed_rib={key: value for key, value in inp.observed_rib.items() if str(key) in contexts},
        rib_coverage={key: value for key, value in inp.rib_coverage.items() if str(key) in contexts},
        observation_gaps=context_rows(inp.observation_gaps),
        superseded_contexts=inp.superseded_contexts & contexts,
        fixed_external_sessions=inp.fixed_external_sessions & session_uids,
        platform=inp.platform,
    )


def _merge_component_results(
    inp: RibInput,
    components: Mapping[tuple[str, ...], RibResult],
    worklist: RoutingWorklist,
    *,
    validate_observed: bool,
) -> RibResult:
    """Merge the results of the islands into one `RibResult`."""
    results = [components[key] for key in sorted(components)]
    rows = sorted((dict(row) for result in results for row in result.rib), key=_row_key)
    errors: list[dict[str, str | None]] = []
    seen_errors: set[tuple[str | None, str | None, str | None]] = set()
    for result in results:
        for error in result.model_errors:
            key = (error.get("kind"), error.get("detail"), error.get("subject"))
            if key not in seen_errors:
                seen_errors.add(key)
                errors.append(dict(error))
    convergence_statuses = [str(result.convergence.get("status") or "settled") for result in results]
    status = "settled" if all(item == "settled" for item in convergence_statuses) else "dependency-unsettled"
    convergence = ConvergenceCertificate(
        status,
        max((result.rounds for result in results), default=0),
        tuple(sorted({context for component in worklist.components for context in component})),
        tuple((item.context_uid, item.prefix) for item in worklist.affected),
        detail="component worklist" if worklist.complete else worklist.reason,
    ).as_dict()
    return RibResult(
        rib=rows,
        fib=Fib(rows, inp.pbr, {str(row["uid"]): row for row in inp.contexts}),
        validation=(
            [dict(item) for result in results for item in result.validation] if validate_observed else []
        ),
        gaps=[dict(item) for result in results for item in result.gaps],
        model_errors=errors,
        rounds=max((result.rounds for result in results), default=0),
        bgp=_merge_route_deltas(results),
        ospf={key: value for result in results for key, value in result.ospf.items()},
        convergence=convergence,
        incremental=worklist.as_dict(),
    )


def _merge_route_deltas(results: Sequence[RibResult]) -> RouteDelta | None:
    """Merge the BGP outputs of the islands into one `RouteDelta`."""
    deltas = [result.bgp for result in results if result.bgp is not None]
    if not deltas:
        return None
    selected: dict[str, list[Route]] = {}
    for delta in deltas:
        if delta is None:
            continue
        for context_uid, routes in delta.selected.items():
            selected[context_uid] = list(routes)
    return RouteDelta(
        rib=[dict(row) for delta in deltas for row in delta.rib],
        model_errors=[dict(item) for delta in deltas for item in delta.model_errors],
        rounds=max(delta.rounds for delta in deltas),
        selected=selected,
        unresolved=[dict(item) for delta in deltas for item in delta.unresolved],
        history_dependent=[dict(item) for delta in deltas for item in delta.history_dependent],
        suppressed=[dict(item) for delta in deltas for item in delta.suppressed],
        multipath={
            context_uid: list(routes)
            for delta in deltas
            if delta is not None
            for context_uid, routes in delta.multipath.items()
        },
        multipath_unknown=[dict(item) for delta in deltas for item in delta.multipath_unknown],
    )


def _merged(
    *stores: Mapping[str, Mapping[str, Sequence[Candidate]]],
) -> dict[str, dict[str, list[Candidate]]]:
    out: dict[str, dict[str, list[Candidate]]] = {}
    for store in stores:
        for context_uid in store:
            for prefix in store[context_uid]:
                for candidate in store[context_uid][prefix]:
                    _offer(out, candidate)
    return out


# --- validation --------------------------------------------------------------------------


def _hops(rows: Iterable[Mapping[str, Any]]) -> set[tuple[str | None, str | None]]:
    return {(_text(r.get("next_hop")), _text(r.get("next_hop_context_uid"))) for r in rows}


def _egress(row: Mapping[str, Any]) -> str | None:
    """The egress of a row without a next hop.

    It is the interface of the row, or `discard` for a discard route. IOS and
    NX-OS show a discard route with the interface `Null0`. The graph and the
    computed rows hold a `discard` kind."""
    interface = _text(row.get("interface"))
    if _text(row.get("discard")) or (interface is not None and interface.lower() in ("null0", "null 0")):
        return "discard"
    return interface


def _egresses(rows: Iterable[Mapping[str, Any]]) -> set[str | None]:
    return {_egress(r) for r in rows}


def validate(
    rows: Sequence[Mapping[str, Any]],
    inp: RibInput,
    *,
    incomplete: Mapping[str, set[str]] | None = None,
    unresolved: Mapping[str, set[str]] | None = None,
    errors: ErrorSink | None = None,
) -> list[dict[str, Any]]:
    """Compare the computed main RIB with the observed `rib` rows, per context
    and prefix. Every mismatch is reported to `errors` as a
    `rib-route-mismatch` model error."""
    errors = errors or ErrorSink()
    incomplete = incomplete or {}
    unresolved = unresolved or {}
    computed: dict[str, dict[str, list[Mapping[str, Any]]]] = {}
    for row in rows:
        computed.setdefault(str(row["context_uid"]), {}).setdefault(str(row["prefix"]), []).append(row)
    contexts = sorted({str(c["uid"]) for c in inp.contexts} | set(computed) | set(inp.observed_rib))
    out: list[dict[str, Any]] = []
    for context_uid in contexts:
        observed: dict[str, list[Mapping[str, Any]]] = {}
        for row in inp.observed_rib.get(context_uid, ()):
            prefix = _prefix(row.get("prefix"))
            if prefix is not None:
                observed.setdefault(prefix, []).append(row)
        coverage = inp.rib_coverage.get(context_uid)
        holds = computed.get(context_uid, {})
        if not observed and coverage not in ("complete", "complete-empty"):
            for prefix in sorted(holds, key=_prefix_key):
                out.append(
                    _report(
                        context_uid,
                        prefix,
                        NOT_OBSERVED,
                        holds[prefix],
                        [],
                        f"no observed rib row for {context_uid} (coverage {coverage or 'not recorded'}); the "
                        "computed route is unverified",
                    )
                )
            continue
        connected_observed = any(
            _family(row.get("protocol")) == CONNECTED for rows_ in observed.values() for row in rows_
        )
        for prefix in sorted(set(holds) | set(observed), key=_prefix_key):
            mine = holds.get(prefix, [])
            theirs = observed.get(prefix, [])
            status, detail = _compare(
                context_uid,
                prefix,
                mine,
                theirs,
                incomplete,
                unresolved,
                connected_observed=connected_observed,
            )
            out.append(_report(context_uid, prefix, status, mine, theirs, detail))
            if status == MISMATCH:
                errors.report("rib-route-mismatch", detail, f"{context_uid}/{prefix}")
    return out


def _report(
    context_uid: str,
    prefix: str,
    status: str,
    mine: Sequence[Mapping[str, Any]],
    theirs: Sequence[Mapping[str, Any]],
    detail: str,
) -> dict[str, Any]:
    return {
        "context_uid": context_uid,
        "prefix": prefix,
        "status": status,
        "computed_protocol": mine[0]["protocol"] if mine else None,
        "observed_protocols": sorted({str(r.get("protocol") or "?") for r in theirs}),
        "computed_next_hops": sorted((h for h, _c in _hops(mine) if h), key=_addr_key),
        "observed_next_hops": sorted((h for h, _c in _hops(theirs) if h), key=_addr_key),
        "detail": detail,
    }


def _compare(
    context_uid: str,
    prefix: str,
    mine: Sequence[Mapping[str, Any]],
    theirs: Sequence[Mapping[str, Any]],
    incomplete: Mapping[str, set[str]],
    unresolved: Mapping[str, set[str]],
    *,
    connected_observed: bool = True,
) -> tuple[str, str]:
    """The verdict of one prefix.

    `connected_observed` is True when the observed RIB of the context holds a
    connected row. A collector that models connected prefixes only as
    ORIGINATES edges (collectors/vyos.py `_rib_entries`) exports no connected
    row. A computed connected route without an observed row is then
    `validated`."""
    families = {_family(r.get("protocol")) for r in theirs}
    missing = incomplete.get(context_uid, set())
    if mine and theirs:
        protocol = str(mine[0]["protocol"])
        if families == {OTHER}:
            return NOT_OBSERVED, (
                f"the device holds {prefix} through {_protocols(theirs)}, a protocol no collector "
                "models; the computed route is unverified"
            )
        if families != {protocol}:
            return MISMATCH, (
                f"computed {protocol} route; the device holds {prefix} through {', '.join(sorted(families))}"
            )
        if protocol == CONNECTED:
            return VALIDATED, "connected"
        mine_hops = {h for h in _hops(mine) if h[0]}
        their_hops = {h for h in _hops(theirs) if h[0]}
        if mine_hops or their_hops:
            if mine_hops != their_hops:
                return MISMATCH, (
                    f"computed {protocol} via {_describe(mine_hops)}; the device holds {prefix} via "
                    f"{_describe(their_hops)}"
                )
        elif _egresses(mine) != _egresses(theirs):
            return MISMATCH, (
                f"computed {protocol} through {', '.join(sorted(str(e) for e in _egresses(mine)))}; the "
                f"device holds {prefix} through {', '.join(sorted(str(e) for e in _egresses(theirs)))}"
            )
        if protocol in (OSPF, BGP):
            observed_metrics = {int(r["metric"]) for r in theirs if r.get("metric") is not None}
            computed_metric = mine[0].get("metric")
            if (
                observed_metrics
                and computed_metric is not None
                and observed_metrics != {int(computed_metric)}
            ):
                return MISMATCH, (
                    f"computed {protocol} metric {computed_metric}; the device holds {prefix} with metric "
                    f"{', '.join(str(m) for m in sorted(observed_metrics))}"
                )
        return VALIDATED, f"{protocol} route, {len(mine)} next hop(s)"
    if mine:
        protocol = str(mine[0]["protocol"])
        if protocol == CONNECTED and not connected_observed:
            # The RIB export holds no connected rows, and the interface address
            # is the observation of the connected route. An export that holds
            # connected rows and lacks this row gets the mismatch below, as for
            # an interface that is down.
            return VALIDATED, (
                "connected; the RIB export holds no connected routes, the interface address is the "
                "observation"
            )
        return (
            MISMATCH,
            f"computed {protocol} route {prefix} via {_describe(_hops(mine))}; the device holds no "
            "route for it",
        )
    if families == {OTHER}:
        return NOT_OBSERVED, (
            f"the device holds {prefix} through {_protocols(theirs)}, a protocol no collector models"
        )
    family = sorted(families)[0]
    if prefix in unresolved.get(context_uid, set()):
        return NOT_OBSERVED, (
            f"the device holds {prefix} through {family}; the calculation holds a candidate whose next hop "
            "did not resolve (see gaps), so it makes no claim about it"
        )
    if family in missing:
        return NOT_OBSERVED, (
            f"the device has {prefix} by {family} via {_describe(_hops(theirs))}, and the computed table "
            f"has no route for it: the {family} input of {context_uid} is incomplete"
        )
    return MISMATCH, (
        f"the device holds {prefix} through {family} via {_describe(_hops(theirs))}; the calculation "
        "produced no route for it from complete inputs"
    )


def _protocols(rows: Iterable[Mapping[str, Any]]) -> str:
    return ", ".join(sorted({str(r.get("protocol") or "?") for r in rows}))


def _describe(hops: Iterable[tuple[str | None, str | None]]) -> str:
    parts = []
    for hop, context in sorted(hops, key=lambda h: (_addr_key(h[0]), h[1] or "")):
        if hop is None:
            continue
        parts.append(f"{hop} in {context}" if context else hop)
    return ", ".join(parts) or "-"
