"""Public value types for symbolic execution contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .manager import PacketSet


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    backend: str
    backend_version: str
    semantic_version: str = "symbolic-v2"
    schema_version: str = "1"
    ordering_version: str = "1"
    operations: frozenset[str] = frozenset(
        {"set_algebra", "project", "exact_cardinality", "bounded_render", "relation"}
    )


@dataclass(frozen=True, slots=True)
class PredicateBounds:
    must_match: PacketSet
    may_match: PacketSet
    required_dimensions: frozenset[str] = frozenset()
    gap_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.must_match.subtract(self.may_match).is_empty():
            raise ValueError("must_match must be a subset of may_match")
        object.__setattr__(self, "required_dimensions", frozenset(self.required_dimensions))
        object.__setattr__(self, "gap_ids", tuple(self.gap_ids))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))


@dataclass(frozen=True, slots=True)
class SymbolicState:
    packets: PacketSet
    location: str
    execution_context: Mapping[str, str] = field(default_factory=dict)
    stage: str = ""
    tunnel_state: Any = None
    connection_state: Any = None
    choice_scope: tuple[str, ...] = ()
    knowledge_mask: frozenset[str] | None = None
    provenance_root: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "execution_context", MappingProxyType(dict(self.execution_context)))
        object.__setattr__(self, "choice_scope", tuple(self.choice_scope))
        knowledge = self.packets.known_fields if self.knowledge_mask is None else self.knowledge_mask
        object.__setattr__(self, "knowledge_mask", frozenset(knowledge))


@dataclass(frozen=True, slots=True)
class Successor:
    state: SymbolicState
    action: str
    explanation_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "explanation_refs", tuple(self.explanation_refs))


@dataclass(frozen=True, slots=True)
class CompiledGate:
    """Foundation adapter for a relation whose required dimensions are known.

    The adapter refuses an unknown required dimension.
    """

    transition: Any
    action: str
    explanation_refs: tuple[str, ...] = ()
    required_dimensions: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "explanation_refs", tuple(self.explanation_refs))
        object.__setattr__(self, "required_dimensions", frozenset(self.required_dimensions))

    def apply(self, state: SymbolicState) -> tuple[Successor, ...]:
        knowledge = state.knowledge_mask
        if knowledge is None:  # normalized by SymbolicState, retained for static typing
            knowledge = frozenset()
        missing = self.required_dimensions - knowledge
        if missing:
            raise RequiredDimensionsUnknownError(missing)
        packets = self.transition.image(state.packets)
        if packets.is_empty():
            return ()
        return (
            Successor(
                SymbolicState(
                    packets=packets,
                    location=state.location,
                    execution_context=state.execution_context,
                    stage=state.stage,
                    tunnel_state=state.tunnel_state,
                    connection_state=state.connection_state,
                    choice_scope=state.choice_scope,
                    knowledge_mask=state.knowledge_mask,
                    provenance_root=state.provenance_root,
                ),
                self.action,
                self.explanation_refs,
            ),
        )


@dataclass(frozen=True, slots=True)
class DecisionBounds:
    lower: PacketSet
    upper: PacketSet
    request_universe: PacketSet
    complete: bool
    gap_refs: tuple[str, ...] = ()
    metrics: Mapping[str, int | float | str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.lower.subtract(self.upper).is_empty():
            raise ValueError("lower must be a subset of upper")
        if not self.upper.subtract(self.request_universe).is_empty():
            raise ValueError("upper must be a subset of request_universe")
        object.__setattr__(self, "gap_refs", tuple(self.gap_refs))
        object.__setattr__(self, "metrics", MappingProxyType(dict(self.metrics)))


@dataclass(frozen=True, slots=True)
class RenderedPacketSet:
    rows: tuple[Mapping[str, int], ...]
    truncated: bool
    fields: tuple[str, ...]
    bank: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "rows", tuple(MappingProxyType(dict(row)) for row in self.rows))
        object.__setattr__(self, "fields", tuple(self.fields))


class RequiredDimensionsUnknownError(RuntimeError):
    def __init__(self, dimensions: frozenset[str]) -> None:
        self.dimensions = dimensions
        super().__init__(f"required request dimensions are unstated: {sorted(dimensions)!r}")
