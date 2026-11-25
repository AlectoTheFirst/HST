"""Immutable, owner-scoped NAT/session bindings for compiled evaluations."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from ipaddress import ip_network

from hst.analysis_model.compile import AnalysisModel, CompiledEdge, CompiledNode
from hst.analysis_model.model import StateKey
from hst.policy.ir import ExecutionContext
from hst.symbolic import PacketSet, SymbolicManager
from hst.symbolic.address_render import address_prefixes
from hst.symbolic.relations import PacketRelation
from hst.symbolic.session import (
    BindingOwner,
    NatBinding,
    ReverseBindingResult,
    SynchronizationEvidence,
    reverse_nat_relation,
)


@dataclass(frozen=True, slots=True)
class SessionCatalog:
    bindings: tuple[NatBinding, ...] = ()
    synchronization: tuple[SynchronizationEvidence, ...] = ()
    complete: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "bindings", tuple(self.bindings))
        object.__setattr__(self, "synchronization", tuple(self.synchronization))
        if len({binding.binding_id for binding in self.bindings}) != len(self.bindings):
            raise ValueError("duplicate NAT binding identity")
        if type(self.complete) is not bool:
            raise TypeError("session catalog completeness must be explicit")

    def reverse(
        self,
        manager: SymbolicManager,
        binding_id: str,
        *,
        reply_context: ExecutionContext,
        request_id: str,
        choice_scope: tuple[str, ...],
    ) -> ReverseBindingResult:
        binding = next((item for item in self.bindings if item.binding_id == binding_id), None)
        if binding is None and self.complete:
            return ReverseBindingResult("rejected", gap_code="NAT_BINDING_ABSENT")
        sync = next(
            (
                item
                for item in self.synchronization
                if item.binding_id == binding_id
                and item.reply_context == reply_context
                and binding is not None
                and item.owner_context == binding.owner.execution_context
            ),
            None,
        )
        return reverse_nat_relation(
            manager,
            binding,
            reply_owner=BindingOwner(reply_context, request_id, choice_scope),
            synchronization=sync,
        )

    def binding(self, binding_id: str) -> NatBinding | None:
        return next((item for item in self.bindings if item.binding_id == binding_id), None)


def install_reverse_binding(
    model: AnalysisModel,
    relation: PacketRelation,
    *,
    owner_context: ExecutionContext,
    choice_scope: tuple[str, ...],
) -> AnalysisModel:
    """Place an exact observed binding at its owner, after translated routing."""
    owner_entries = _context_entries(model.nodes, owner_context)
    if not owner_entries:
        return _poison_permits(model, {"SESSION_TRANSLATION_OWNER_UNREACHABLE"})
    assignments = [
        choice
        for choice in model.choices
        if tuple(value for _scope, value in choice.bindings) == choice_scope
    ]
    if len(assignments) != 1:
        return _poison_permits(model, {"SESSION_BINDING_SCOPE_MISMATCH"})
    nodes = {node.key: node for node in model.nodes}
    entries = list(model.entries)
    gates: set[StateKey] = set()
    for index, entry in enumerate(owner_entries):
        key = StateKey(
            f"session-binding:{owner_context.firewall_instance}:{owner_context.vrf}:{index}",
            owner_context,
            "session",
        )
        edge = CompiledEdge(
            "session-binding:restore",
            entry,
            relation.preimage(model.universe),
            model.universe.manager.empty(),
            relation,
            assignments[0].bindings,
        )
        nodes = _redirect_to_owner(tuple(nodes.values()), owner_context, entry, key)
        nodes[key] = CompiledNode(key, (edge,), (), True, ())
        entries = [replace(item, key=key) if item.key == entry else item for item in entries]
        gates.add(key)
    candidate = replace(model, nodes=tuple(nodes.values()), entries=tuple(entries))
    if _permit_bypasses(candidate, gates):
        return _poison_permits(candidate, {"SESSION_TRANSLATION_OWNER_BYPASSED"})
    fingerprint = hashlib.sha256(f"{model.fingerprint}:observed-session:{key}".encode()).hexdigest()
    return replace(candidate, fingerprint=fingerprint)


def reject_session(model: AnalysisModel, code: str) -> AnalysisModel:
    """Turn reply permits into scoped unknowns for an unusable required binding."""
    return _poison_permits(model, {code})


def install_reverse_translations(
    forward: AnalysisModel,
    reply: AnalysisModel,
    *,
    interface_addresses: Mapping[str, Mapping[str, tuple[tuple[int, int, int], ...]]] | None = None,
    request: PacketSet | None = None,
    binding_required: frozenset[str] = frozenset(),
    reply_order: Callable[[ExecutionContext, str], str | None] | None = None,
) -> AnalysisModel:
    """Install deterministic inverse transformations at their owning contexts.

    The original-bank guard ties each inverse rule to the forward request that
    selected it, on each header field no other translation rewrote before
    it. Reply traffic routes to the owner with its translated tuple before
    the restoration.

    An owner is a context that translated the request. Every reply that
    enters an owner by an entry whose reply handling is decided skips the
    destination NAT stage of the owner. The connection table matches a packet
    of an existing connection, and NAT rules are read for the first packet of
    a connection only (as conntrack does). An unsolicited packet from outside
    is a forward flow of its own and takes the destination NAT rules of the
    forward model.

    `reply_order(context, ingress)` takes an owner and the interface that the
    reply enters by. It returns a gap code if the device does not apply the
    inbound filter, the reverse translation and the state admission to the
    reply in the order of the model. It returns None otherwise. The replies
    that the owner would restore are not decided under that gap code. Without
    `reply_order` every owner is decided.

    A rewrite that maps many values of a header field to one (a masquerade, a
    hide NAT, a source NAT of a range to one address) is reversed to the
    value that the forward request had in that field (its original bank, over
    the values of `request`). The connection entry of the device maps the
    field back to the same value. This holds only where no other translation
    on the forward path rewrote the field before. In the other case, without
    `request`, and for a many-to-many rewrite, the reply is not decided
    (`SESSION_REVERSE_TRANSLATION_AMBIGUOUS`). A field with more than
    `MAX_RESTORED_VALUES` values gives `SESSION_REVERSE_TRANSLATION_TOO_WIDE`.

    In a firewall instance of `binding_required` (a VSX virtual system), only
    an observed runtime binding establishes a hide or pool inverse (as in the
    tracer). The many-to-one rewrite is not decided there
    (`NAT_BINDING_NOT_OBSERVED`).

    A load balancer keeps no connection table. Its many-to-one rewrite is not
    decided.

    `interface_addresses` holds the addresses of each interface, by VRF uid
    and then interface uid. A masquerade (`free_source_ports`) translates to
    the address of the uplink that it leaves by. A reply to it that enters
    the owner by an interface without that address is not decided
    (`SESSION_REPLY_INGRESS_NOT_TRANSLATING`).
    """
    if forward.universe.manager is not reply.universe.manager:
        raise ValueError("forward and reply models must share one symbolic manager")
    # A dead state has no edge and no permit terminal that holds packets.
    # Every compiled node holds an empty `deny` terminal.
    dead = {
        node.key
        for node in forward.nodes
        if not node.edges
        and not any(name == "permit" and not packets.is_empty() for name, packets in node.terminals)
    }
    by_context: dict[ExecutionContext, list[tuple[int, CompiledNode]]] = {}
    order = {"load-balancer": 0, "snat": 1, "dnat": 2}
    for node in forward.nodes:
        if node.key.stage in order:
            usable = tuple(edge for edge in node.edges if edge.target not in dead)
            if usable:
                by_context.setdefault(node.key.context, []).append(
                    (order[node.key.stage], replace(node, edges=usable))
                )
    if not by_context:
        return reply

    nodes = {node.key: node for node in reply.nodes}
    entries = list(reply.entries)
    gaps: set[str] = set()
    required_gates: list[tuple[ExecutionContext, set[StateKey]]] = []
    rewrites = _rewrite_map(forward)
    inverses = {
        (definition.key, edge.uid): _inverse(
            rewrites, reply, definition, edge, interface_addresses, request, binding_required
        )
        for definitions in by_context.values()
        for _rank, definition in definitions
        for edge in definition.edges
        if "fallthrough" not in edge.uid
    }
    for context, definitions in by_context.items():
        owner_entries = _owner_entries(tuple(nodes.values()), context)
        if not owner_entries:
            gaps.add(f"SESSION_TRANSLATION_OWNER_UNREACHABLE:{context.firewall_instance}:{context.vrf}")
            continue
        context_gates: set[StateKey] = set()
        for ingress_index, (owner_entry, ingress) in enumerate(owner_entries):
            order_gap = reply_order(context, ingress) if reply_order is not None else None
            # A decided reply starts after the destination NAT stages of the owner entry.
            target = owner_entry if order_gap is not None else _past_dnat(nodes, owner_entry)
            created: list[CompiledNode] = []
            grouped = {
                rank: tuple(node for candidate_rank, node in definitions if candidate_rank == rank)
                for rank in {rank for rank, _node in definitions}
            }
            for index, rank in enumerate(sorted(grouped, reverse=True)):
                stage_nodes = grouped[rank]
                key = StateKey(
                    "session-inverse:"
                    f"{context.firewall_instance}:{stage_nodes[0].key.stage}:{ingress_index}:{index}",
                    context,
                    "session",
                )
                edges: list[CompiledEdge] = []
                for definition in stage_nodes:
                    for edge in definition.edges:
                        if "fallthrough" in edge.uid:
                            continue
                        reverse, guard, code, holders = inverses[definition.key, edge.uid]
                        if code is None and holders and ingress not in holders:
                            code = "SESSION_REPLY_INGRESS_NOT_TRANSLATING"
                        if code is None:
                            code = order_gap
                        edge_target = target
                        if code is not None:
                            edge_target = StateKey(f"session-inverse:unknown:{code}", context, "session")
                            if edge_target not in nodes:
                                nodes[edge_target] = CompiledNode(
                                    edge_target, (), (("unknown", reply.universe),), False, (code,)
                                )
                            reverse = PacketRelation.identity(reply.universe.manager)
                        edges.append(
                            CompiledEdge(
                                f"session-inverse:{definition.key.location}:{edge.uid}",
                                edge_target,
                                guard,
                                reply.universe.manager.empty(),
                                reverse,
                                edge.choices,
                            )
                        )
                # A reply outside every guard of this stage goes on unchanged.
                translated = reply.universe.manager.empty()
                for compiled_edge in edges:
                    translated = translated.union(compiled_edge.guard)
                edges.append(
                    CompiledEdge(
                        f"session-inverse:{key.location}:fallthrough",
                        target,
                        reply.universe.subtract(translated),
                        reply.universe.manager.empty(),
                        PacketRelation.identity(reply.universe.manager),
                        (),
                    )
                )
                created.append(CompiledNode(key, tuple(edges), (), True, ()))
                target = key
            first = target
            nodes = _redirect_to_owner(tuple(nodes.values()), context, owner_entry, first)
            entries = [replace(entry, key=first) if entry.key == owner_entry else entry for entry in entries]
            nodes.update({node.key: node for node in created})
            context_gates.add(first)
        required_gates.append((context, context_gates))
    result_model = replace(reply, nodes=tuple(nodes.values()), entries=tuple(entries))
    for context, barriers in required_gates:
        if _permit_bypasses(result_model, barriers):
            gaps.add(f"SESSION_TRANSLATION_OWNER_BYPASSED:{context.firewall_instance}:{context.vrf}")
    if gaps:
        poisoned = _poison_permits(result_model, gaps)
        nodes = {node.key: node for node in poisoned.nodes}
    fingerprint = hashlib.sha256(
        f"{reply.fingerprint}:session-inverse:{forward.fingerprint}".encode()
    ).hexdigest()
    return replace(reply, fingerprint=fingerprint, nodes=tuple(nodes.values()), entries=tuple(entries))


def _redirect_to_owner(
    source: tuple[CompiledNode, ...],
    context: ExecutionContext,
    owner_entry: StateKey,
    replacement: StateKey,
) -> dict[StateKey, CompiledNode]:
    return {
        node.key: replace(
            node,
            edges=tuple(
                replace(edge, target=replacement)
                if edge.target == owner_entry and node.key.context != context
                else edge
                for edge in node.edges
            ),
        )
        for node in source
    }


def _poison_permits(model: AnalysisModel, gaps: set[str]) -> AnalysisModel:
    return replace(
        model,
        nodes=tuple(
            replace(
                node,
                terminals=tuple(
                    ("unknown", packets) if name == "permit" else (name, packets)
                    for name, packets in node.terminals
                ),
                complete=False,
                gap_refs=tuple(sorted({*node.gap_refs, *gaps})),
            )
            for node in model.nodes
        ),
    )


def _permit_bypasses(model: AnalysisModel, barriers: set[StateKey]) -> bool:
    nodes = {node.key: node for node in model.nodes}
    pending = [entry.key for entry in model.entries]
    reached: set[StateKey] = set()
    while pending:
        key = pending.pop()
        if key in reached or key in barriers:
            continue
        reached.add(key)
        node = nodes.get(key)
        if node is None:
            continue
        if any(name == "permit" and not packets.is_empty() for name, packets in node.terminals):
            return True
        pending.extend(edge.target for edge in node.edges)
    return False


# The greatest count of values of a header field that `_equal_to_original`
# restores. 2**12 values are a /20 of sources.
MAX_RESTORED_VALUES = 1 << 12

_SWAPPED = {
    "source_address": "destination_address",
    "destination_address": "source_address",
    "source_port": "destination_port",
    "destination_port": "source_port",
}


def _inverse(
    rewrites: Mapping[tuple[ExecutionContext, str], frozenset[str]],
    reply: AnalysisModel,
    definition: CompiledNode,
    edge: CompiledEdge,
    interface_addresses: Mapping[str, Mapping[str, tuple[tuple[int, int, int], ...]]] | None,
    request: PacketSet | None,
    binding_required: frozenset[str] = frozenset(),
) -> tuple[PacketRelation, PacketSet, str | None, frozenset[str]]:
    """Return the inverse of one forward NAT edge for the reply.

    The result holds the relation, the guard, a gap code where the inverse
    cannot be decided, and the interfaces of the owner that hold the one
    source address of the translation."""
    reverse = PacketRelation.filter(edge.guard).compose(edge.relation).reverse_flow()
    code: str | None = None
    holders: frozenset[str] = frozenset()
    if not edge.guard.is_empty():
        out = edge.relation.image(edge.guard)
        for field, peer in _SWAPPED.items():
            if out.cardinality([field]) >= edge.guard.cardinality([field]):
                continue
            # The rewrite maps many values of `field` to fewer values.
            if definition.key.context.firewall_instance in binding_required:
                code = "NAT_BINDING_NOT_OBSERVED"
                continue
            if (
                request is None
                # a load balancer keeps no connection table the reply is matched by
                or definition.key.stage == "load-balancer"
                or out.cardinality([field]) != 1
                or field not in request.known_fields
                or _rewritten_elsewhere(rewrites, definition, field)
            ):
                code = "SESSION_REVERSE_TRANSLATION_AMBIGUOUS"
                continue
            # the connection entry maps it back to the request's own value
            restored = _equal_to_original(request, peer, field)
            if restored is None:
                code = "SESSION_REVERSE_TRANSLATION_TOO_WIDE"
                continue
            reverse = reverse.compose(PacketRelation.filter(restored))
        if (
            edge.uid in definition.free_source_ports
            and interface_addresses is not None
            and out.cardinality(["source_address"]) == 1
        ):
            holders = _holders(out, interface_addresses.get(definition.key.context.vrf, {}))
    guard = reverse.preimage(reply.universe)
    if definition.key.stage in {"dnat", "snat"}:
        # The guard of the rule, renamed to the original bank, ties the inverse
        # to the requests that the rule selected. A swapped field that another
        # translation rewrites is projected out of the guard.
        names = reply.universe.manager.schema.field_names
        kept = [
            name
            for name in names
            if name not in _SWAPPED or not _rewritten_elsewhere(rewrites, definition, name)
        ]
        tie = edge.guard if len(kept) == len(names) else edge.guard.project(kept)
        guard = guard.intersect(tie.rename(from_bank="current", to_bank="original"))
    return reverse, guard, code, holders


def _rewrite_map(forward: AnalysisModel) -> dict[tuple[ExecutionContext, str], frozenset[str]]:
    """The header fields that each translation stage of each context rewrites."""
    result: dict[tuple[ExecutionContext, str], set[str]] = {}
    for node in forward.nodes:
        if node.key.stage not in {"load-balancer", "snat", "dnat"}:
            continue
        fields = result.setdefault((node.key.context, node.key.stage), set())
        for edge in node.edges:
            if "fallthrough" in edge.uid or edge.guard.is_empty():
                continue
            out = edge.relation.image(edge.guard)
            fields.update(
                field
                for field in _SWAPPED
                if field not in fields and not out.project([field]).equivalent(edge.guard.project([field]))
            )
    return {key: frozenset(value) for key, value in result.items()}


def _rewritten_elsewhere(
    rewrites: Mapping[tuple[ExecutionContext, str], frozenset[str]], definition: CompiledNode, field: str
) -> bool:
    """Return whether a translation stage other than the stage of `definition`
    in its context rewrites `field`."""
    own = (definition.key.context, definition.key.stage)
    return any(field in fields for key, fields in rewrites.items() if key != own)


def _equal_to_original(request: PacketSet, current_field: str, original_field: str) -> PacketSet | None:
    """Return the set where `current_field` equals `original_field` of the
    original bank, over the values of that field in `request`.

    The 2 fields are far apart in the variable order. The set grows with the
    count of those values. The result is None for more than
    `MAX_RESTORED_VALUES` values."""
    manager, schema = request.manager, request.manager.schema
    values = request.project([original_field]).rename(from_bank="current", to_bank="original")
    if values.cardinality([original_field], bank="original") > MAX_RESTORED_VALUES:
        return None
    node = values._node
    bdd = manager._bdd
    # The equality is conjoined bit by bit onto the values of the request.
    for left, right in zip(
        schema.bits("current", current_field), schema.bits("original", original_field), strict=True
    ):
        a, b = bdd.var(left), bdd.var(right)
        node &= (a & b) | (~a & ~b)
    return manager._wrap(node)


def _holders(out: PacketSet, interfaces: Mapping[str, tuple[tuple[int, int, int], ...]]) -> frozenset[str]:
    try:
        page = address_prefixes(out, field="source_address", bank="current", limit=1)
    except ValueError:
        return frozenset()
    if not page.items:
        return frozenset()
    address = int(ip_network(page.items[0]).network_address)
    af = out.manager.schema.address_family
    return frozenset(
        uid
        for uid, ranges in interfaces.items()
        if any(family == af and low <= address <= high for family, low, high in ranges)
    )


def _past_dnat(nodes: Mapping[StateKey, CompiledNode], key: StateKey) -> StateKey:
    """The state after the destination NAT stages that `key` starts with."""
    seen: set[StateKey] = set()
    while key not in seen:
        seen.add(key)
        node = nodes.get(key)
        if node is None or node.key.stage != "dnat":
            break
        following = next((edge.target for edge in node.edges if edge.uid.endswith("dnat:fallthrough")), None)
        if following is None:
            break
        key = following
    return key


def _context_entries(nodes: tuple[CompiledNode, ...], context: ExecutionContext) -> tuple[StateKey, ...]:
    return tuple(entry for entry, _ingress in _owner_entries(nodes, context))


def _owner_entries(
    nodes: tuple[CompiledNode, ...], context: ExecutionContext
) -> tuple[tuple[StateKey, str], ...]:
    """The reply entries of `context`, each with the interface uid it enters by."""
    result: list[tuple[StateKey, str]] = []
    prefix = f"routing:{context.vrf}:ingress:"
    routing = [
        node.key for node in nodes if node.key.context == context and node.key.location.startswith(prefix)
    ]
    for routing_key in routing:
        entry = routing_key
        while True:
            predecessors = [
                node.key
                for node in nodes
                if node.key.context == context
                and node.key.stage in {"dnat", "pbr"}
                and any(edge.target == entry for edge in node.edges)
            ]
            if len(predecessors) != 1:
                break
            entry = predecessors[0]
        if entry not in {item for item, _ingress in result}:
            result.append((entry, routing_key.location.removeprefix(prefix)))
    return tuple(result)
