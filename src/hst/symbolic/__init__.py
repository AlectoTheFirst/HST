"""Packet-set algebra on a native manager."""

from .manager import (
    BackendUnavailableError,
    ManagerClosedError,
    ManagerMismatchError,
    PacketSet,
    SymbolicManager,
    backend_available,
)
from .predicates import (
    MaskedValue,
    ValueRange,
    any_of,
    complement,
    equals,
    header,
    masked,
    prefix,
    value_range,
)
from .relations import PacketRelation, initial_relation
from .schema import BANKS, Bank, FieldSpec, HeaderSchema
from .types import (
    BackendCapabilities,
    CompiledGate,
    DecisionBounds,
    PredicateBounds,
    RenderedPacketSet,
    RequiredDimensionsUnknownError,
    Successor,
    SymbolicState,
)

__all__ = [
    "BANKS",
    "BackendCapabilities",
    "BackendUnavailableError",
    "Bank",
    "CompiledGate",
    "DecisionBounds",
    "FieldSpec",
    "HeaderSchema",
    "ManagerClosedError",
    "ManagerMismatchError",
    "MaskedValue",
    "PacketRelation",
    "PacketSet",
    "PredicateBounds",
    "RenderedPacketSet",
    "RequiredDimensionsUnknownError",
    "Successor",
    "SymbolicManager",
    "SymbolicState",
    "ValueRange",
    "any_of",
    "backend_available",
    "complement",
    "equals",
    "header",
    "initial_relation",
    "masked",
    "prefix",
    "value_range",
]
