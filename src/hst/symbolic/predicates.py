"""Compile exact header bit predicates into opaque packet sets.

The validity mask gives fields that do not exist on a packet a canonical zero
encoding. A field predicate alone does not prove that the real header exists.
Destination-port zero also matches the zero padding on GRE and on non-initial
fragments. Policy compilers must add the applicable protocol and
header-availability guards, or preserve a typed unknown when their profile cannot
establish those guards.

This module is a Python port of `HeaderSpaceToBDD.java` of Batfish at commit
2a513d04a14b99d72fe0079f85ad8be3f5b6f4fa. The Batfish authors license that file
under the Apache License 2.0. The port changes it.
`third_party/symbolic/licenses/batfish-2a513d0-Apache-2.0.txt` holds the licence
text.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .manager import PacketSet, SymbolicManager
from .schema import Bank


@dataclass(frozen=True, slots=True)
class ValueRange:
    lower: int
    upper: int


@dataclass(frozen=True, slots=True)
class MaskedValue:
    value: int
    mask: int


def _integer(manager: SymbolicManager, field: str, value: int | str) -> int:
    canonical = manager.schema.canonical_field(field)
    if canonical in {"source_address", "destination_address"} and isinstance(value, str):
        address = ipaddress.ip_address(value)
        if address.version != manager.schema.address_family:
            raise ValueError("address family does not match symbolic manager")
        return int(address)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{canonical} value must be an integer")
    return value


def equals(manager: SymbolicManager, field: str, value: int | str, *, bank: Bank = "current") -> PacketSet:
    canonical = manager.schema.canonical_field(field)
    node = manager.vector(bank, canonical).equals(_integer(manager, canonical, value))
    return manager._wrap(node & manager.validity(bank)._node, (canonical,))


def value_range(
    manager: SymbolicManager,
    field: str,
    lower: int | str,
    upper: int | str,
    *,
    bank: Bank = "current",
) -> PacketSet:
    canonical = manager.schema.canonical_field(field)
    node = manager.vector(bank, canonical).between(
        _integer(manager, canonical, lower), _integer(manager, canonical, upper)
    )
    return manager._wrap(node & manager.validity(bank)._node, (canonical,))


def masked(
    manager: SymbolicManager,
    field: str,
    value: int | str,
    mask: int | str,
    *,
    bank: Bank = "current",
) -> PacketSet:
    canonical = manager.schema.canonical_field(field)
    numeric_value = _integer(manager, canonical, value)
    numeric_mask = _integer(manager, canonical, mask) if isinstance(mask, str) else mask
    node = manager.vector(bank, canonical).masked_equals(numeric_value, numeric_mask)
    return manager._wrap(node & manager.validity(bank)._node, (canonical,))


def prefix(
    manager: SymbolicManager,
    field: str,
    network: str,
    *,
    bank: Bank = "current",
) -> PacketSet:
    canonical = manager.schema.canonical_field(field)
    if canonical not in {"source_address", "destination_address"}:
        raise ValueError("prefix predicates apply only to address fields")
    parsed = ipaddress.ip_network(network, strict=False)
    if parsed.version != manager.schema.address_family:
        raise ValueError("prefix family does not match symbolic manager")
    mask = int(parsed.netmask)
    return masked(manager, canonical, int(parsed.network_address), mask, bank=bank)


def any_of(
    manager: SymbolicManager,
    field: str,
    values: Iterable[int | str | ValueRange | MaskedValue],
    *,
    bank: Bank = "current",
) -> PacketSet:
    canonical = manager.schema.canonical_field(field)
    node = manager._bdd.false
    for constraint in values:
        if isinstance(constraint, ValueRange):
            part = manager.vector(bank, canonical).between(constraint.lower, constraint.upper)
        elif isinstance(constraint, MaskedValue):
            part = manager.vector(bank, canonical).masked_equals(constraint.value, constraint.mask)
        else:
            part = manager.vector(bank, canonical).equals(_integer(manager, canonical, constraint))
        node |= part
    return manager._wrap(node & manager.validity(bank)._node, (canonical,))


def header(
    manager: SymbolicManager,
    constraints: Mapping[str, Any] | None = None,
    *,
    bank: Bank = "current",
    explicitly_all: Iterable[str] = (),
) -> PacketSet:
    """Build a conjunction. `known_fields` holds the fields of `constraints` and `explicitly_all`.

    A two-integer tuple means an inclusive range. ``MaskedValue`` represents a
    possibly non-contiguous wildcard mask. Other iterables are alternatives.
    """

    result = manager.universe(bank=bank)
    known = {manager.schema.canonical_field(field) for field in explicitly_all}
    for field, constraint in (constraints or {}).items():
        canonical = manager.schema.canonical_field(field)
        known.add(canonical)
        if isinstance(constraint, ValueRange):
            part = value_range(manager, canonical, constraint.lower, constraint.upper, bank=bank)
        elif isinstance(constraint, MaskedValue):
            part = masked(manager, canonical, constraint.value, constraint.mask, bank=bank)
        elif isinstance(constraint, tuple) and len(constraint) == 2:
            part = value_range(manager, canonical, constraint[0], constraint[1], bank=bank)
        elif isinstance(constraint, (list, set, frozenset, tuple)):
            part = any_of(manager, canonical, constraint, bank=bank)
        else:
            part = equals(manager, canonical, constraint, bank=bank)
        result = manager._wrap(result._node & part._node)
    return result.with_knowledge(known)


def complement(predicate: PacketSet, *, bank: Bank = "current") -> PacketSet:
    return predicate.complement(bank=bank)
