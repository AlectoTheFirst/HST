"""Exact NAT binding ownership and reverse tuple restoration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from hst.policy.ir import ExecutionContext

from .manager import SymbolicManager
from .predicates import header
from .relations import PacketRelation


@dataclass(frozen=True, slots=True)
class FlowTuple:
    protocol: Literal[6, 17]
    source_address: int
    destination_address: int
    source_port: int
    destination_port: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.protocol, int)
            or isinstance(self.protocol, bool)
            or self.protocol not in (6, 17)
        ):
            raise ValueError("exact NAT bindings support TCP and UDP only")
        for value in (self.source_address, self.destination_address, self.source_port, self.destination_port):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("flow tuple values must be unsigned integers")
        if self.source_port > 65535 or self.destination_port > 65535:
            raise ValueError("flow tuple port exceeds 16 bits")

    def fields(self) -> dict[str, int]:
        return {
            "protocol": self.protocol,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
        }

    def reversed_fields(self) -> dict[str, int]:
        return {
            "protocol": self.protocol,
            "source_address": self.destination_address,
            "destination_address": self.source_address,
            "source_port": self.destination_port,
            "destination_port": self.source_port,
        }


@dataclass(frozen=True, slots=True)
class BindingOwner:
    execution_context: ExecutionContext
    request_id: str
    choice_scope: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.request_id or self.request_id.strip() != self.request_id:
            raise ValueError("request_id must be a nonempty normalized string")
        object.__setattr__(self, "choice_scope", tuple(self.choice_scope))


@dataclass(frozen=True, slots=True)
class NatBinding:
    binding_id: str
    owner: BindingOwner
    original_forward: FlowTuple
    translated_forward: FlowTuple

    def __post_init__(self) -> None:
        if not self.binding_id or self.binding_id.strip() != self.binding_id:
            raise ValueError("binding_id must be a nonempty normalized string")
        if self.original_forward.protocol != self.translated_forward.protocol:
            raise ValueError("binding cannot change TCP/UDP protocol")
        width = 32 if self.owner.execution_context.address_family == 4 else 128
        limit = 1 << width
        addresses = (
            self.original_forward.source_address,
            self.original_forward.destination_address,
            self.translated_forward.source_address,
            self.translated_forward.destination_address,
        )
        if any(address >= limit for address in addresses):
            raise ValueError("binding address does not fit owner address family")


@dataclass(frozen=True, slots=True)
class SynchronizationEvidence:
    binding_id: str
    owner_context: ExecutionContext
    reply_context: ExecutionContext
    validated: bool
    evidence_id: str

    def __post_init__(self) -> None:
        if not self.binding_id or self.binding_id.strip() != self.binding_id:
            raise ValueError("binding_id must be a nonempty normalized string")
        if type(self.validated) is not bool:
            raise TypeError("validated must be an explicit boolean")
        if self.owner_context.address_family != self.reply_context.address_family:
            raise ValueError("synchronization contexts must use the same address family")
        if self.validated and (not self.evidence_id or self.evidence_id.strip() != self.evidence_id):
            raise ValueError("validated synchronization requires a normalized evidence_id")


@dataclass(frozen=True, slots=True)
class ReverseBindingResult:
    status: Literal["exact", "unknown", "rejected"]
    relation: PacketRelation | None = None
    gap_code: str | None = None


def reverse_nat_relation(
    manager: SymbolicManager,
    binding: NatBinding | None,
    *,
    reply_owner: BindingOwner,
    synchronization: SynchronizationEvidence | None = None,
) -> ReverseBindingResult:
    """Return exact reverse NAT only for the binding's complete owner scope."""

    if binding is None:
        return ReverseBindingResult("unknown", gap_code="NAT_BINDING_NOT_OBSERVED")
    if manager.schema.address_family != binding.owner.execution_context.address_family:
        raise ValueError("binding family does not match symbolic manager")
    if manager.schema.address_family != reply_owner.execution_context.address_family:
        raise ValueError("reply owner family does not match symbolic manager")
    same_context = reply_owner.execution_context == binding.owner.execution_context
    synchronized = (
        synchronization is not None
        and synchronization.validated
        and bool(synchronization.evidence_id)
        and synchronization.binding_id == binding.binding_id
        and synchronization.owner_context == binding.owner.execution_context
        and synchronization.reply_context == reply_owner.execution_context
    )
    if not same_context and not synchronized:
        return ReverseBindingResult("rejected", gap_code="NAT_BINDING_OWNER_MISMATCH")
    if (
        reply_owner.request_id != binding.owner.request_id
        or reply_owner.choice_scope != binding.owner.choice_scope
    ):
        return ReverseBindingResult("rejected", gap_code="NAT_BINDING_SCOPE_MISMATCH")
    # The current bank holds the observed reverse packet. The original bank
    # holds the established forward request. The guard on both banks excludes a
    # different request with the same translated tuple.
    current_guard = header(
        manager,
        {**binding.translated_forward.reversed_fields(), "fragment_offset": 0},
    )
    original_guard = header(
        manager,
        {**binding.original_forward.fields(), "fragment_offset": 0},
        bank="original",
    )
    guard = current_guard.intersect(original_guard)
    relation = PacketRelation.rewrite(
        manager,
        binding.original_forward.reversed_fields(),
        guard=guard,
    )
    return ReverseBindingResult("exact", relation=relation)
