"""Exact current-to-next header relations that retain original request bits.

This module is a Python port of `EraseAndSet.java` of Batfish at commit
2a513d04a14b99d72fe0079f85ad8be3f5b6f4fa. The Batfish authors license that file
under the Apache License 2.0. The port changes it.
`third_party/symbolic/licenses/batfish-2a513d0-Apache-2.0.txt` holds the licence
text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .bitvector import BitVector
from .manager import ManagerMismatchError, PacketSet, SymbolicManager


@dataclass(frozen=True, slots=True)
class _RelationStep:
    node: Any


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class PacketRelation:
    """An immutable relation, or a composed pipeline of relations."""

    manager: SymbolicManager
    _steps: tuple[_RelationStep, ...]

    def __post_init__(self) -> None:
        self.manager._register_relation(self)

    @classmethod
    def identity(cls, manager: SymbolicManager) -> PacketRelation:
        return cls._from_parts(manager, manager._bdd.true, {})

    @classmethod
    def filter(cls, predicate: PacketSet) -> PacketRelation:
        predicate.manager._assert_sets(predicate)
        return cls._from_parts(predicate.manager, predicate._node, {})

    @classmethod
    def rewrite(
        cls,
        manager: SymbolicManager,
        rewrites: Mapping[str, int],
        *,
        guard: PacketSet | None = None,
    ) -> PacketRelation:
        if guard is not None:
            manager._assert_sets(guard)
        guard_node = guard._node if guard is not None else manager._bdd.true
        return cls._from_parts(manager, guard_node, rewrites, guard)

    @classmethod
    def prefix_rewrite(
        cls,
        manager: SymbolicManager,
        field: str,
        *,
        match_value: int,
        match_mask: int,
        set_value: int,
        set_mask: int | None = None,
    ) -> PacketRelation:
        """Replace selected bits and preserve every unselected bit exactly."""

        canonical = manager.schema.canonical_field(field)
        width = manager.schema.width(canonical)
        full_mask = (1 << width) - 1
        if set_mask is None:
            set_mask = match_mask
        for name, value in {
            "match_value": match_value,
            "match_mask": match_mask,
            "set_value": set_value,
            "set_mask": set_mask,
        }.items():
            if value < 0 or value > full_mask:
                raise ValueError(f"{name} does not fit {width} bits")
        guard = manager.vector("current", canonical).masked_equals(match_value, match_mask)
        relation = guard
        current = manager.schema.bits("current", canonical)
        successor = manager.schema.bits("next", canonical)
        for offset, (left_name, right_name) in enumerate(zip(current, successor, strict=True)):
            bit = 1 << (width - offset - 1)
            left, right = manager._bdd.var(left_name), manager._bdd.var(right_name)
            if set_mask & bit:
                relation &= right if set_value & bit else ~right
            else:
                relation &= (left & right) | (~left & ~right)
        return cls._from_parts(manager, relation, {}, rewritten_fields=frozenset({canonical}))

    @classmethod
    def range_rewrite(
        cls,
        manager: SymbolicManager,
        field: str,
        source_low: int,
        source_high: int,
        target_low: int,
    ) -> PacketRelation:
        """Translate an inclusive range by a fixed signed offset.

        The offset is compiled as a ripple-carry Boolean circuit. The relation
        size depends on the field width. Every field outside ``field`` keeps
        its value.
        """

        canonical = manager.schema.canonical_field(field)
        width = manager.schema.width(canonical)
        limit = 1 << width
        for name, value in {
            "source_low": source_low,
            "source_high": source_high,
            "target_low": target_low,
        }.items():
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
            if value < 0 or value >= limit:
                raise ValueError(f"{name} does not fit {width} bits")
        if source_low > source_high:
            raise ValueError("source range is reversed")
        target_high = target_low + source_high - source_low
        if target_high >= limit:
            raise ValueError("translated range exceeds field width")

        current = manager.vector("current", canonical)
        successor = manager.vector("next", canonical)
        relation = current.between(source_low, source_high)
        # Constant addition modulo 2**width is exact here because validation
        # above proves that every guarded result lies inside the field.
        encoded_delta = (target_low - source_low) % limit
        carry = manager._bdd.false
        for offset in range(width - 1, -1, -1):
            left = manager._bdd.var(current.variables[offset])
            right = manager._bdd.var(successor.variables[offset])
            constant = bool(encoded_delta & (1 << (width - offset - 1)))
            left_xor_carry = (left & ~carry) | (~left & carry)
            total = ~left_xor_carry if constant else left_xor_carry
            relation &= (right & total) | (~right & ~total)
            carry = (left | carry) if constant else (left & carry)
        return cls._from_parts(manager, relation, {}, rewritten_fields=frozenset({canonical}))

    @classmethod
    def _from_parts(
        cls,
        manager: SymbolicManager,
        guard_node: Any,
        rewrites: Mapping[str, int],
        guard: PacketSet | None = None,
        *,
        rewritten_fields: frozenset[str] | None = None,
    ) -> PacketRelation:
        manager._ensure_open()
        if guard is not None:
            manager._assert_sets(guard)
        canonical_rewrites = {
            manager.schema.canonical_field(field): value for field, value in rewrites.items()
        }
        changed = rewritten_fields or frozenset(canonical_rewrites)
        relation = guard_node & manager.validity("current")._node & manager.validity("next")._node
        for field in manager.schema.field_names:
            current = manager.vector("current", field)
            successor = manager.vector("next", field)
            if field in canonical_rewrites:
                relation &= successor.equals(canonical_rewrites[field])
            elif field not in changed:
                relation &= current.equals_vector(successor)
        return cls(manager, (_RelationStep(relation),))

    def compose(self, other: PacketRelation) -> PacketRelation:
        """Apply ``self`` and then ``other``."""

        self.manager._ensure_open()
        if self.manager is not other.manager:
            raise ManagerMismatchError("relations belong to different managers")
        return PacketRelation(self.manager, self._steps + other._steps)

    def inverse(self) -> PacketRelation:
        """Reverse this relation, including the order of composed steps."""
        swap = {
            **dict(self.manager.schema.rename_bank("current", "next")),
            **dict(self.manager.schema.rename_bank("next", "current")),
        }
        return PacketRelation(
            self.manager,
            tuple(_RelationStep(self.manager._bdd.let(swap, step.node)) for step in reversed(self._steps)),
        )

    def reverse_flow(self) -> PacketRelation:
        """Invert a forward relation for the reversed transport tuple."""
        swapped = {
            "source_address": "destination_address",
            "destination_address": "source_address",
            "source_port": "destination_port",
            "destination_port": "source_port",
        }
        rename: dict[str, str] = {}
        for field in self.manager.schema.field_names:
            peer = swapped.get(field, field)
            rename.update(
                zip(
                    self.manager.schema.bits("current", field),
                    self.manager.schema.bits("next", peer),
                    strict=True,
                )
            )
            rename.update(
                zip(
                    self.manager.schema.bits("next", field),
                    self.manager.schema.bits("current", peer),
                    strict=True,
                )
            )
        return PacketRelation(
            self.manager,
            tuple(_RelationStep(self.manager._bdd.let(rename, step.node)) for step in reversed(self._steps)),
        )

    def image(self, packets: PacketSet) -> PacketSet:
        self.manager._assert_sets(packets)
        result = packets
        current = set(self.manager.schema.bank_variables("current"))
        rename = dict(self.manager.schema.rename_bank("next", "current"))
        for step in self._steps:
            node = self.manager._bdd.exist(current, result._node & step.node)
            node = self.manager._bdd.let(rename, node)
            result = self.manager._wrap(node, result.known_fields)
        return result

    def preimage(self, packets: PacketSet) -> PacketSet:
        self.manager._assert_sets(packets)
        result = packets
        successor = set(self.manager.schema.bank_variables("next"))
        current_to_next = dict(self.manager.schema.rename_bank("current", "next"))
        for step in reversed(self._steps):
            target = self.manager._bdd.let(current_to_next, result._node)
            node = self.manager._bdd.exist(successor, target & step.node)
            result = self.manager._wrap(node, result.known_fields)
        return result


def initial_relation(request: PacketSet) -> PacketSet:
    """Bind original and current headers without losing request knowledge."""

    manager = request.manager
    manager._assert_sets(request)
    node = request._node
    # Unknown dimensions are not bound across banks.
    for field in request.known_fields:
        node &= BitVector(manager._bdd, manager.schema.bits("original", field)).equals_vector(
            BitVector(manager._bdd, manager.schema.bits("current", field))
        )
    node &= manager.validity("original")._node & manager.validity("current")._node
    return manager._wrap(node, request.known_fields)
