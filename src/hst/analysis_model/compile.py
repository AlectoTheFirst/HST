"""Compile explicit pinned network inputs before symbolic traversal."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from ipaddress import ip_network

from hst.policy.bounds import Bounds
from hst.policy.compile import PolicyCompiler
from hst.policy.ir import AllOf, AnyOf, Atom, ExecutionContext, Not
from hst.policy.predicates import PredicateCompiler
from hst.symbolic import PacketSet, SymbolicManager
from hst.symbolic.relations import PacketRelation

from .evidence import evaluate_evidence
from .model import (
    ChoiceAssignment,
    EdgeSpec,
    EvidenceRef,
    ExitRecord,
    ModelInput,
    NodeSpec,
    StateKey,
    Terminal,
    evidence_dependency_fingerprints,
    semantic_fingerprint,
    semantic_value_fingerprint,
)


@dataclass(frozen=True, slots=True)
class CompiledEdge:
    uid: str
    target: StateKey
    guard: PacketSet
    uncertain: PacketSet
    relation: PacketRelation
    choices: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class CompiledNode:
    key: StateKey
    edges: tuple[CompiledEdge, ...]
    terminals: tuple[tuple[Terminal, PacketSet], ...]
    complete: bool
    gap_refs: tuple[str, ...]
    # The `left_estate` of the source node (`NodeSpec`). No outcome reads it.
    left_estate: tuple[ExitRecord, ...] = ()
    # The `incomplete_reasons` of the source node (`NodeSpec`). No outcome reads it.
    incomplete_reasons: tuple[str, ...] = ()
    # The `free_source_ports` of the source node (`NodeSpec`).
    free_source_ports: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledEntry:
    key: StateKey
    guard: PacketSet
    uncertain: PacketSet
    choices: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class AnalysisModel:
    manifest_digest: str
    fingerprint: str
    universe: PacketSet
    nodes: tuple[CompiledNode, ...]
    entries: tuple[CompiledEntry, ...]
    choices: tuple[ChoiceAssignment, ...]
    choices_complete: bool


def compile_model(
    source: ModelInput,
    manager: SymbolicManager,
    known_fields: frozenset[str],
    *,
    policy_compilers: dict[tuple[int, ExecutionContext, frozenset[str]], PolicyCompiler] | None = None,
    metrics: dict[str, int] | None = None,
    node_cache: dict[str, CompiledNode] | None = None,
    reusable_nodes: frozenset[StateKey] = frozenset(),
) -> AnalysisModel:
    if policy_compilers is None:
        policy_compilers = {}
    # One PredicateCompiler serves one model build. The gate predicates that it
    # shares by identity (the per-EPG address sets of the ACI gate) compile once.
    predicates = PredicateCompiler(manager, known_fields, share_identical=True)
    evidence_global, evidence_by_ref = evidence_dependency_fingerprints(source.evidence)
    node_context_fingerprint = compiled_node_context_fingerprint(
        source, manager, known_fields, evidence_global
    )
    universe = predicates.universe
    nodes: list[CompiledNode] = []
    evidence_catalog: set[EvidenceRef] = set()
    evidence_gaps: dict[EvidenceRef, set[str]] = {}
    if source.evidence is not None:
        checked = evaluate_evidence(
            source.evidence.windows, source.evidence.policy, analysis_time=source.evidence.analysis_time
        )
        for window in checked.windows:
            evidence_catalog.add(
                EvidenceRef(window.source, window.subject, window.section, window.address_family, window.vrf)
            )
        for gap in checked.gaps:
            ref = EvidenceRef(gap.source, gap.subject, gap.section, gap.address_family, gap.vrf)
            evidence_gaps.setdefault(ref, set()).add(gap.code.value)
    for definition in source.nodes:
        if definition.key.context.address_family != manager.schema.address_family:
            raise ValueError("model context and manager address families differ")
        node_fingerprint = compiled_node_fingerprint(
            node_context_fingerprint,
            definition,
            tuple(sorted(evidence_by_ref.get(reference, "missing") for reference in definition.evidence)),
        )
        if node_cache is not None and definition.key in reusable_nodes:
            cached = node_cache.get(node_fingerprint)
            if cached is not None:
                nodes.append(cached)
                if metrics is not None:
                    metrics["incremental_nodes_reused"] = metrics.get("incremental_nodes_reused", 0) + 1
                continue
        gaps: list[str] = []
        for reference in definition.evidence:
            if reference not in evidence_catalog:
                gaps.append("EVIDENCE_NOT_COLLECTED")
            gaps.extend(evidence_gaps.get(reference, ()))
        evidence_unknown = bool(gaps)
        permit = Bounds.terminal(universe, "permit")
        if definition.policy is not None:
            if definition.policy.manifest_digest != source.manifest_digest:
                raise ValueError("policy must be pinned to the model manifest")
            policy_key = id(manager), definition.key.context, known_fields
            policy_compiler = policy_compilers.get(policy_key)
            if policy_compiler is None:
                if len(policy_compilers) >= 64:
                    del policy_compilers[next(iter(policy_compilers))]
                policy_compiler = PolicyCompiler(manager, definition.key.context, known_fields)
                policy_compilers[policy_key] = policy_compiler
            elif policy_compiler.universe.manager is not manager:
                raise ValueError("policy compiler cache crosses native manager ownership")
            policy = policy_compiler.compile(definition.policy)
            if metrics is not None:
                for name in ("compiled_blocks", "reused_blocks", "compiled_objects", "reused_objects"):
                    metrics[name] = metrics.get(name, 0) + getattr(policy.stats, name)
            if definition.policy_bank == "original":
                permit = Bounds(
                    policy.bounds.universe.rename(from_bank="current", to_bank="original"),
                    policy.bounds.lower.rename(from_bank="current", to_bank="original"),
                    policy.bounds.upper.rename(from_bank="current", to_bank="original"),
                )
            else:
                permit = policy.bounds
            gaps.extend(gap.reason.code for gap in policy.gaps)
        terminals: list[tuple[Terminal, PacketSet]] = [("deny", universe.subtract(permit.lower))]
        if evidence_unknown:
            terminals.append(("unknown", universe))
        edges: list[CompiledEdge] = []
        if definition.terminal is not None:
            terminals.append((definition.terminal, permit.upper))
        else:
            for edge in definition.edges:
                predicate = predicates.compile(edge.predicate)
                guard = predicate.bounds.upper.intersect(permit.upper)
                uncertain = predicate.bounds.upper.subtract(predicate.bounds.lower).intersect(permit.upper)
                relation = PacketRelation.rewrite(manager, dict(edge.rewrites))
                for rewrite in edge.ranges:
                    relation = relation.compose(
                        PacketRelation.range_rewrite(
                            manager,
                            rewrite.field,
                            rewrite.source_low,
                            rewrite.source_high,
                            rewrite.target_low,
                        )
                    )
                domain = relation.preimage(universe)
                uncertain = uncertain.union(guard.subtract(domain))
                edges.append(
                    CompiledEdge(
                        edge.uid, edge.target, guard.intersect(domain), uncertain, relation, edge.choices
                    )
                )
                gaps.extend(gap.code for gap in predicate.gaps)
        if not definition.complete:
            terminals.append(("unknown", permit.upper))
            gaps.append("MODEL_SCOPE_INCOMPLETE")
        compiled_node = CompiledNode(
            definition.key,
            tuple(edges),
            tuple(terminals),
            definition.complete,
            tuple(sorted(set(gaps))),
            definition.left_estate,
            definition.incomplete_reasons,
            definition.free_source_ports,
        )
        nodes.append(compiled_node)
        if node_cache is not None:
            node_cache[node_fingerprint] = compiled_node
        if metrics is not None:
            metrics["incremental_nodes_compiled"] = metrics.get("incremental_nodes_compiled", 0) + 1
    entries: list[CompiledEntry] = []
    for entry in source.entries:
        if entry.key.context.address_family != manager.schema.address_family:
            raise ValueError("entry and manager address families differ")
        predicate = predicates.compile(entry.predicate)
        entries.append(
            CompiledEntry(
                entry.key,
                predicate.bounds.upper,
                predicate.bounds.upper.subtract(predicate.bounds.lower),
                entry.choices,
            )
        )
    present = {node.key for node in nodes}
    referenced = {entry.key for entry in entries} | {edge.target for node in nodes for edge in node.edges}
    for key in sorted(referenced - present, key=repr):
        if key.context.address_family != manager.schema.address_family:
            raise ValueError("edge target and manager address families differ")
        nodes.append(CompiledNode(key, (), (("unknown", universe),), False, ("MODEL_NODE_MISSING",)))
    fingerprint = compiled_fingerprint(source, manager, known_fields)
    # An empty model or an empty attachment set is a valid incomplete observation.
    return AnalysisModel(
        source.manifest_digest,
        fingerprint,
        universe,
        tuple(nodes),
        tuple(entries),
        source.choices,
        source.choices_complete,
    )


def with_estate_exits(model: AnalysisModel, source: ModelInput) -> AnalysisModel:
    """`model` with each node's `left_estate`, `incomplete_reasons` and
    `free_source_ports` taken from `source`, the normalized network it was
    compiled from. A stored compiled model holds none of them. The key of a
    stored model is the fingerprint of `source`, and the fingerprint covers them."""
    exits = {node.key: node.left_estate for node in source.nodes if node.left_estate}
    reasons = {node.key: node.incomplete_reasons for node in source.nodes if node.incomplete_reasons}
    free = {node.key: node.free_source_ports for node in source.nodes if node.free_source_ports}
    if (
        not exits
        and not reasons
        and not free
        and not any(
            node.left_estate or node.incomplete_reasons or node.free_source_ports for node in model.nodes
        )
    ):
        return model
    return replace(
        model,
        nodes=tuple(
            replace(
                node,
                left_estate=exits.get(node.key, ()),
                incomplete_reasons=reasons.get(node.key, ()),
                free_source_ports=free.get(node.key, ()),
            )
            for node in model.nodes
        ),
    )


def compiled_fingerprint(source: ModelInput, manager: SymbolicManager, known_fields: frozenset[str]) -> str:
    identity = {
        "input": semantic_fingerprint(source),
        "known_fields": sorted(known_fields),
        "schema": manager.capabilities.schema_version,
        "ordering": manager.capabilities.ordering_version,
        "backend": manager.capabilities.backend,
        "backend_version": manager.capabilities.backend_version,
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def compiled_node_context_fingerprint(
    source: ModelInput,
    manager: SymbolicManager,
    known_fields: frozenset[str],
    evidence_global: str,
) -> str:
    identity = (
        source.manifest_digest,
        source.schema_version,
        source.choices,
        source.choices_complete,
        evidence_global,
        tuple(sorted(known_fields)),
        manager.capabilities.schema_version,
        manager.capabilities.ordering_version,
        manager.capabilities.backend,
        manager.capabilities.backend_version,
    )
    return semantic_value_fingerprint(identity)


def compiled_node_fingerprint(
    context_fingerprint: str,
    node: NodeSpec,
    evidence_fingerprints: tuple[str, ...],
) -> str:
    identity = (
        f"{context_fingerprint}:{semantic_value_fingerprint(node)}:"
        f"{semantic_value_fingerprint(evidence_fingerprints)}"
    )
    return hashlib.sha256(identity.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class RouteSpec:
    uid: str
    prefix: str
    target: StateKey
    preference: int = 0
    choices: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.uid or type(self.preference) is not int:
            raise ValueError("route identity and integer preference are required")
        value = tuple(sorted(tuple(pair) for pair in self.choices))
        if len({scope for scope, _ in value}) != len(value):
            raise ValueError("duplicate route choice scope")
        object.__setattr__(self, "choices", value)


def fib_edges(routes: tuple[RouteSpec, ...], *, address_family: int) -> tuple[EdgeSpec, ...]:
    """Normalize an already selected FIB into disjoint best-prefix groups.

    Equal-prefix/preference alternatives require explicit joint-choice constraints.
    """
    if len({route.uid for route in routes}) != len(routes):
        raise ValueError("duplicate route identity")
    groups: dict[tuple[int, int], list[RouteSpec]] = {}
    width = 32 if address_family == 4 else 128
    if address_family not in (4, 6):
        raise ValueError("invalid route address family")
    for route in routes:
        network = ip_network(route.prefix, strict=True)
        if network.version != address_family:
            raise ValueError("route and model address families differ")
        group_key = (network.prefixlen, int(network.network_address))
        group = groups.setdefault(group_key, [])
        if not group or route.preference < group[0].preference:
            groups[group_key] = [route]
        elif route.preference == group[0].preference:
            group.append(route)
    children: dict[tuple[int, int], list[tuple[int, int]]] = {key: [] for key in groups}
    full = (1 << width) - 1
    for length, address in groups:
        for parent_length in range(length - 1, -1, -1):
            parent = (parent_length, address & ((full << (width - parent_length)) & full))
            if parent in groups:
                children[parent].append((length, address))
                break

    def match(key: tuple[int, int]) -> Atom:
        length, address = key
        return Atom("destination_address", "mask", address, (full << (width - length)) & full)

    result: list[EdgeSpec] = []
    for group_key in sorted(groups):
        group = groups[group_key]
        for index, left in enumerate(group):
            for right in group[index + 1 :]:
                right_choices = dict(right.choices)
                if not any(
                    scope in right_choices and right_choices[scope] != value for scope, value in left.choices
                ):
                    raise ValueError("equal-rank FIB alternatives require mutually exclusive joint choices")
        excluded = AnyOf(tuple(match(child) for child in sorted(children[group_key])))
        guard = AllOf((match(group_key), Not(excluded)))
        result.extend(
            EdgeSpec(route.uid, route.target, guard, choices=route.choices)
            for route in sorted(group, key=lambda r: r.uid)
        )
    return tuple(result)
