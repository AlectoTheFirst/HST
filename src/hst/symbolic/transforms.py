"""Exact, bounded header transformations built from :class:`PacketRelation`."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

from .manager import PacketSet, SymbolicManager
from .relations import PacketRelation


@dataclass(frozen=True, slots=True)
class TranslationAlternative:
    """One exact allocation, with the choice id a caller scopes it by."""

    choice_id: str
    relation: PacketRelation


@dataclass(frozen=True, slots=True)
class TranslationBoundary:
    """A finite set of exact alternatives or an explicit unknown boundary."""

    alternatives: tuple[TranslationAlternative, ...] = ()
    status: Literal["exact", "unknown"] = "exact"
    gap_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "alternatives", tuple(self.alternatives))
        if self.status == "exact" and self.gap_code is not None:
            raise ValueError("an exact translation cannot carry an unknown gap")
        if self.status == "unknown" and not self.gap_code:
            raise ValueError("an unknown translation requires a gap code")


def _value(manager: SymbolicManager, field: str, value: int | str) -> int:
    canonical = manager.schema.canonical_field(field)
    if canonical in {"source_address", "destination_address"} and isinstance(value, str):
        address = ipaddress.ip_address(value)
        if address.version != manager.schema.address_family:
            raise ValueError("address family does not match symbolic manager")
        value = int(address)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("translation values must be integers")
    if value < 0 or value >= 1 << manager.schema.width(canonical):
        raise ValueError(f"value does not fit {canonical}")
    return value


def constant_translation(
    manager: SymbolicManager,
    field: str,
    value: int | str,
    *,
    guard: PacketSet | None = None,
) -> PacketRelation:
    """Rewrite one field to a constant and preserve every other field."""

    canonical = manager.schema.canonical_field(field)
    return PacketRelation.rewrite(manager, {canonical: _value(manager, canonical, value)}, guard=guard)


def exact_range_translation(
    manager: SymbolicManager,
    field: str,
    source_lower: int | str,
    source_upper: int | str,
    target_lower: int | str,
) -> PacketRelation:
    """Translate an inclusive range by offset without enumerating its values."""

    canonical = manager.schema.canonical_field(field)
    lower = _value(manager, canonical, source_lower)
    upper = _value(manager, canonical, source_upper)
    target = _value(manager, canonical, target_lower)
    return PacketRelation.range_rewrite(manager, canonical, lower, upper, target)


def unknown_pool_allocation(gap_code: str = "NAT_POOL_ALLOCATION_UNKNOWN") -> TranslationBoundary:
    """Represent allocation that has no established exact relation alternatives."""

    if not gap_code or gap_code.strip() != gap_code:
        raise ValueError("gap_code must be a nonempty normalized string")
    return TranslationBoundary(status="unknown", gap_code=gap_code)


def prefix_translation(
    manager: SymbolicManager,
    field: str,
    source_prefix: str,
    target_prefix: str,
) -> PacketRelation:
    """Replace equal-length network bits while retaining host bits exactly."""

    canonical = manager.schema.canonical_field(field)
    if canonical not in {"source_address", "destination_address"}:
        raise ValueError("prefix translation applies only to address fields")
    source = ipaddress.ip_network(source_prefix, strict=True)
    target = ipaddress.ip_network(target_prefix, strict=True)
    if source.version != manager.schema.address_family or target.version != source.version:
        raise ValueError("prefix family does not match symbolic manager")
    if source.prefixlen != target.prefixlen:
        raise ValueError("prefix-preserving translation requires equal prefix lengths")
    return PacketRelation.prefix_rewrite(
        manager,
        canonical,
        match_value=int(source.network_address),
        match_mask=int(source.netmask),
        set_value=int(target.network_address),
        set_mask=int(target.netmask),
    )
