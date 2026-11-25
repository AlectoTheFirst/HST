"""Native CUDD manager ownership and opaque packet sets."""

from __future__ import annotations

import importlib
import importlib.metadata
import weakref
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from .bitvector import BitVector
from .schema import BANKS, Bank, HeaderSchema
from .types import BackendCapabilities, RenderedPacketSet


class BackendUnavailableError(RuntimeError):
    """The required native symbolic backend could not be loaded."""


class ManagerMismatchError(ValueError):
    """An operation mixed handles owned by different native managers."""


class ManagerClosedError(RuntimeError):
    """An operation used a manager after its analysis-child lifetime ended."""


def backend_available() -> bool:
    """Return whether the production backend imports."""

    try:
        importlib.import_module("dd.cudd")
    except (ImportError, OSError):
        return False
    return True


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class PacketSet:
    """An immutable, opaque Boolean set tied to exactly one manager.

    ``known_fields`` holds the dimensions that the request states. An
    intersection has the known fields of both operands. :meth:`as_predicate`
    returns a policy predicate without known fields, and an intersection with it
    keeps an unstated request dimension unstated.
    """

    _manager: SymbolicManager = dataclass_field(repr=False)
    _node: Any = dataclass_field(repr=False)
    known_fields: frozenset[str] = frozenset()

    @property
    def manager(self) -> SymbolicManager:
        return self._manager

    def _binary(self, other: PacketSet, operation: str) -> PacketSet:
        self._manager._assert_sets(self, other)
        if operation == "union":
            node = self._node | other._node
            if self._node == self._manager._bdd.false:
                knowledge = other.known_fields
            elif other._node == self._manager._bdd.false:
                knowledge = self.known_fields
            else:
                knowledge = self.known_fields & other.known_fields
        elif operation == "intersect":
            node = self._node & other._node
            knowledge = self.known_fields | other.known_fields
        elif operation == "subtract":
            node = self._node & ~other._node
            knowledge = self.known_fields
        else:  # pragma: no cover - private exhaustive dispatch
            raise AssertionError(operation)
        return self._manager._wrap(node, knowledge)

    def union(self, other: PacketSet) -> PacketSet:
        return self._binary(other, "union")

    def intersect(self, other: PacketSet) -> PacketSet:
        return self._binary(other, "intersect")

    def subtract(self, other: PacketSet) -> PacketSet:
        return self._binary(other, "subtract")

    def complement(self, *, bank: Bank = "current") -> PacketSet:
        return self._manager.universe(bank=bank, known_fields=self.known_fields).subtract(self)

    def is_empty(self) -> bool:
        self._manager._assert_sets(self)
        return self._node == self._manager._bdd.false

    def equivalent(self, other: PacketSet) -> bool:
        """Compare the represented packets. `known_fields` is not compared."""

        self._manager._assert_sets(self, other)
        return self._node == other._node

    def with_knowledge(self, fields: Iterable[str]) -> PacketSet:
        canonical = frozenset(self._manager.schema.canonical_field(name) for name in fields)
        return self._manager._wrap(self._node, canonical)

    def as_predicate(self) -> PacketSet:
        """The same packets as a filter with no known fields."""

        return self._manager._wrap(self._node)

    def project(self, fields: Iterable[str], *, bank: Bank = "current") -> PacketSet:
        return self._manager.project(self, fields, bank=bank)

    def rename(
        self,
        mapping: Mapping[str, str] | None = None,
        *,
        from_bank: Bank | None = None,
        to_bank: Bank | None = None,
    ) -> PacketSet:
        return self._manager.rename(self, mapping, from_bank=from_bank, to_bank=to_bank)

    def cardinality(self, fields: Iterable[str], *, bank: Bank = "current") -> int:
        return self._manager.cardinality(self, fields, bank=bank)

    def render(
        self,
        fields: Iterable[str],
        *,
        bank: Bank = "current",
        limit: int = 32,
    ) -> RenderedPacketSet:
        from .codec import render

        return render(self, fields, bank=bank, limit=limit)


class SymbolicManager:
    """One address-family native manager owned by one analysis child."""

    def __init__(self, schema: HeaderSchema) -> None:
        self.schema = schema
        try:
            cudd = importlib.import_module("dd.cudd")
        except (ImportError, OSError) as exc:
            raise BackendUnavailableError(
                "enterprise symbolic analysis requires the native dd.cudd backend"
            ) from exc
        self._bdd: Any = cudd.BDD()
        self._closed = False
        try:
            self._bdd.configure(reordering=False)
        except (AttributeError, TypeError, ValueError) as exc:
            raise BackendUnavailableError("dd.cudd cannot disable dynamic reordering") from exc
        self._bdd.declare(*schema.variables)
        self._validity_nodes: dict[Bank, Any] = {}
        self._packet_sets: weakref.WeakSet[PacketSet] = weakref.WeakSet()
        self._relations: weakref.WeakSet[Any] = weakref.WeakSet()
        try:
            backend_version = importlib.metadata.version("dd")
        except importlib.metadata.PackageNotFoundError:
            backend_version = "unknown"
        self.capabilities = BackendCapabilities(
            backend="dd.cudd",
            backend_version=backend_version,
            schema_version=schema.schema_version,
            ordering_version=schema.ordering_version,
        )

    def __enter__(self) -> SymbolicManager:
        self._ensure_open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ManagerClosedError("symbolic manager is closed")

    @property
    def node_count(self) -> int:
        self._ensure_open()
        return len(self._bdd)

    def _assert_sets(self, *sets: PacketSet) -> None:
        self._ensure_open()
        if any(packet_set._manager is not self for packet_set in sets):
            raise ManagerMismatchError("packet sets belong to different managers")

    def _wrap(self, node: Any, known_fields: Iterable[str] = ()) -> PacketSet:
        self._ensure_open()
        canonical = frozenset(self.schema.canonical_field(name) for name in known_fields)
        packet_set = PacketSet(self, node, canonical)
        self._packet_sets.add(packet_set)
        return packet_set

    def _register_relation(self, relation: Any) -> None:
        self._ensure_open()
        self._relations.add(relation)

    def vector(self, bank: Bank, field: str) -> BitVector:
        self._ensure_open()
        return BitVector(self._bdd, self.schema.bits(bank, field))

    def empty(self, *, known_fields: Iterable[str] = ()) -> PacketSet:
        return self._wrap(self._bdd.false, known_fields)

    def validity(self, bank: Bank = "current") -> PacketSet:
        self._ensure_open()
        if bank not in BANKS:
            raise ValueError(f"unknown header bank: {bank}")
        cached = self._validity_nodes.get(bank)
        if cached is None:
            cached = self._build_validity(bank)
            self._validity_nodes[bank] = cached
        return self._wrap(cached)

    def universe(self, *, bank: Bank = "current", known_fields: Iterable[str] = ()) -> PacketSet:
        valid = self.validity(bank)
        return self._wrap(valid._node, known_fields)

    def _zero(self, bank: Bank, *fields: str) -> Any:
        result = self._bdd.true
        for field in fields:
            result &= self.vector(bank, field).equals(0)
        return result

    def _one_of(self, bank: Bank, field: str, values: Iterable[int]) -> Any:
        result = self._bdd.false
        vector = self.vector(bank, field)
        for value in values:
            result |= vector.equals(value)
        return result

    def _build_validity(self, bank: Bank) -> Any:
        # Canonical zeroes make inapplicable fields a single representation. A
        # non-initial fragment has no transport header available to inspect.
        initial_fragment = self.vector(bank, "fragment_offset").equals(0)
        transport = self._one_of(bank, "protocol", (6, 17, 33, 132)) & initial_fragment
        tcp = self.vector(bank, "protocol").equals(6) & initial_fragment
        icmp_protocol = 1 if self.schema.address_family == 4 else 58
        icmp = self.vector(bank, "protocol").equals(icmp_protocol) & initial_fragment
        ports_zero = self._zero(bank, "source_port", "destination_port")
        flags_zero = self._zero(bank, "tcp_flags")
        icmp_zero = self._zero(bank, "icmp_type", "icmp_code")
        return (transport | ports_zero) & (tcp | flags_zero) & (icmp | icmp_zero)

    def collect_garbage(self) -> None:
        self._ensure_open()
        collect = getattr(self._bdd, "collect_garbage", None)
        if collect is not None:
            collect()

    def close(self) -> None:
        if self._closed:
            return
        for packet_set in tuple(self._packet_sets):
            object.__setattr__(packet_set, "_node", None)
        for relation in tuple(self._relations):
            object.__setattr__(relation, "_steps", ())
        self._packet_sets.clear()
        self._relations.clear()
        self._validity_nodes.clear()
        collect = getattr(self._bdd, "collect_garbage", None)
        if collect is not None:
            collect()
        self._closed = True

    def project(self, packet_set: PacketSet, fields: Iterable[str], *, bank: Bank = "current") -> PacketSet:
        self._assert_sets(packet_set)
        canonical = tuple(dict.fromkeys(self.schema.canonical_field(field) for field in fields))
        keep = {variable for field in canonical for variable in self.schema.bits(bank, field)}
        remove = set(self.schema.variables) - keep
        node = self._bdd.exist(remove, packet_set._node) if remove else packet_set._node
        return self._wrap(node, packet_set.known_fields & set(canonical))

    def rename(
        self,
        packet_set: PacketSet,
        mapping: Mapping[str, str] | None = None,
        *,
        from_bank: Bank | None = None,
        to_bank: Bank | None = None,
    ) -> PacketSet:
        self._assert_sets(packet_set)
        if mapping is not None and (from_bank is not None or to_bank is not None):
            raise ValueError("pass either a variable mapping or a bank rename")
        if mapping is None:
            if from_bank is None or to_bank is None:
                raise ValueError("both from_bank and to_bank are required")
            mapping = self.schema.rename_bank(from_bank, to_bank)
        unknown = (set(mapping) | set(mapping.values())) - set(self.schema.variables)
        if unknown:
            raise KeyError(f"rename references unknown variables: {sorted(unknown)!r}")
        return self._wrap(self._bdd.let(dict(mapping), packet_set._node), packet_set.known_fields)

    def cardinality(self, packet_set: PacketSet, fields: Iterable[str], *, bank: Bank = "current") -> int:
        self._assert_sets(packet_set)
        canonical = tuple(dict.fromkeys(self.schema.canonical_field(field) for field in fields))
        variables = tuple(
            sorted(
                (variable for field in canonical for variable in self.schema.bits(bank, field)),
                key=self._bdd.level_of_var,
            )
        )
        projected = self.project(packet_set, canonical, bank=bank)
        return self._exact_count(projected._node, variables)

    def _exact_count(self, node: Any, variables: tuple[str, ...]) -> int:
        """Count a projected DAG using Python integers, including skipped levels."""

        levels = tuple(self._bdd.level_of_var(variable) for variable in variables)
        if tuple(sorted(levels)) != levels or len(set(levels)) != len(levels):
            raise ValueError("count variables must be unique and in manager order")
        position = {level: index for index, level in enumerate(levels)}
        support = set(self._bdd.support(node))
        if not support <= set(variables):
            raise ValueError("DAG was not projected onto the counted variables")
        memo: dict[tuple[Any, int], int] = {}
        try:
            return self._count_node(node, 0, variables, position, memo)
        finally:
            # The CUDD Functions in memo are native roots. A root retained in a
            # recursive closure can outlive manager.close().
            memo.clear()

    def _count_node(
        self,
        current: Any,
        next_position: int,
        variables: tuple[str, ...],
        position: Mapping[int, int],
        memo: dict[tuple[Any, int], int],
    ) -> int:
        if current == self._bdd.false:
            return 0
        if current == self._bdd.true:
            return 1 << (len(variables) - next_position)
        key = (current, next_position)
        cached = memo.get(key)
        if cached is not None:
            return cached
        level, low, high = self._bdd.succ(current)
        if current.negated:
            low, high = ~low, ~high
        current_position = position.get(level)
        if current_position is None or current_position < next_position:
            raise ValueError("malformed or out-of-order projected BDD DAG")
        skipped = current_position - next_position
        answer = (1 << skipped) * (
            self._count_node(low, current_position + 1, variables, position, memo)
            + self._count_node(high, current_position + 1, variables, position, memo)
        )
        memo[key] = answer
        return answer
