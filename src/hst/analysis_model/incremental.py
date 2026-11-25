"""Conservative dependency-scoped incremental recomputation planning."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from .dependencies import DependencyIndex, QualifiedRef
from .model import (
    ModelInput,
    NodeSpec,
    StateKey,
    evidence_dependency_fingerprints,
    semantic_value_fingerprint,
)


@dataclass(frozen=True, slots=True)
class IncrementalPlan:
    affected: frozenset[QualifiedRef]
    routing: frozenset[QualifiedRef]
    policy: frozenset[QualifiedRef]
    reused: frozenset[QualifiedRef]
    broad_rebuild: bool
    reason: str = ""

    @property
    def counters(self) -> dict[str, int]:
        return {
            "affected": len(self.affected),
            "routing_recomputed": len(self.routing),
            "policy_recomputed": len(self.policy),
            "reused": len(self.reused),
            "broad_rebuild": int(self.broad_rebuild),
        }


def plan_incremental(
    *,
    current: DependencyIndex,
    changed: Iterable[QualifiedRef],
    universe: Iterable[QualifiedRef],
    previous: DependencyIndex | None = None,
    complete: bool = True,
) -> IncrementalPlan:
    """Invalidate the old and new transitive closure, or rebuild when capture is incomplete."""
    all_refs = frozenset(universe)
    if not complete:
        return IncrementalPlan(
            all_refs,
            frozenset(r for r in all_refs if _routing(r)),
            frozenset(r for r in all_refs if not _routing(r)),
            frozenset(),
            True,
            "DEPENDENCY_INDEX_INCOMPLETE",
        )
    affected = current.invalidate(changed, old=previous) & all_refs
    routing = frozenset(ref for ref in affected if _routing(ref))
    policy = frozenset(ref for ref in affected if not _routing(ref))
    return IncrementalPlan(affected, routing, policy, all_refs - affected, False)


def _routing(ref: QualifiedRef) -> bool:
    return ref.kind in {
        "route",
        "rib",
        "fib",
        "next-hop",
        "aggregate",
        "redistribution",
        "leak",
        "routing-component",
    }


@dataclass(frozen=True, slots=True)
class ModelDependencyState:
    index: DependencyIndex
    fingerprints: dict[QualifiedRef, str]
    keys: dict[QualifiedRef, StateKey]
    complete: bool


def model_dependency_state(source: ModelInput) -> ModelDependencyState:
    """Build exact node dependencies, including missing edge-target identities."""
    index = DependencyIndex()
    fingerprints: dict[QualifiedRef, str] = {}
    keys: dict[QualifiedRef, StateKey] = {}
    refs = {_node_ref(node): node for node in source.nodes}
    evidence_global, evidence_by_ref = evidence_dependency_fingerprints(source.evidence)
    global_fingerprint = semantic_value_fingerprint(
        (
            source.manifest_digest,
            source.schema_version,
            source.choices,
            source.choices_complete,
            evidence_global,
        )
    )
    for ref, node in refs.items():
        dependencies = tuple(_state_ref(edge.target) for edge in node.edges)
        index.add(ref, dependencies)
        evidence_fingerprints = tuple(
            sorted(evidence_by_ref.get(reference, "missing") for reference in node.evidence)
        )
        fingerprints[ref] = _node_fingerprint(global_fingerprint, node, evidence_fingerprints)
        keys[ref] = node.key
    return ModelDependencyState(
        index,
        fingerprints,
        keys,
        source.choices_complete and all(node.complete for node in source.nodes),
    )


def plan_model_incremental(
    source: ModelInput, previous: ModelDependencyState | None
) -> tuple[ModelDependencyState, IncrementalPlan]:
    """Plan node reuse from old and new exact semantic fingerprints."""
    current = model_dependency_state(source)
    universe = frozenset(current.fingerprints)
    if previous is None:
        changed: frozenset[QualifiedRef] = universe
    else:
        changed = frozenset(
            ref
            for ref in universe | frozenset(previous.fingerprints)
            if current.fingerprints.get(ref) != previous.fingerprints.get(ref)
        )
    plan = plan_incremental(
        current=current.index,
        previous=previous.index if previous is not None else None,
        changed=changed,
        universe=universe,
        complete=current.complete and (previous is None or previous.complete),
    )
    return current, plan


def _state_ref(key: StateKey) -> QualifiedRef:
    context = key.context
    authority = f"{context.estate}/{context.authority}/{context.domain}"
    return QualifiedRef("model-node", authority, repr(key))


def _node_ref(node: NodeSpec) -> QualifiedRef:
    return _state_ref(node.key)


def _node_fingerprint(global_fingerprint: str, node: NodeSpec, evidence_fingerprints: tuple[str, ...]) -> str:
    value = (
        f"{global_fingerprint}:{semantic_value_fingerprint(node)}:"
        f"{semantic_value_fingerprint(evidence_fingerprints)}"
    )
    return hashlib.sha256(value.encode()).hexdigest()
