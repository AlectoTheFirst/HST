"""Exact conversion between v1 rectangles and symbolic packet sets within explicit limits.

A conversion returns the complete represented set or raises a typed error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hst.path.addrsets import _PORT_FAMILY
from hst.path.state import FlowRegion, Rect

from .manager import PacketSet, SymbolicManager
from .schema import BANKS, Bank

_ADDRESS_FIELDS = ("source_address", "destination_address")
_SERVICE_FIELDS = ("protocol", "destination_port", "source_port")
_LEGACY_FIELDS = frozenset((*_ADDRESS_FIELDS, *_SERVICE_FIELDS))
_RECT_TO_FIELD = {
    "src": "source_address",
    "dst": "destination_address",
    "proto": "protocol",
    "dport": "destination_port",
    "sport": "source_port",
}
_FIELD_TO_RECT = {field: rect for rect, field in _RECT_TO_FIELD.items()}


class LegacyAdapterError(RuntimeError):
    """Base class for a conversion that the v1 shape cannot represent exactly."""


class LegacyFamilyError(LegacyAdapterError, ValueError):
    """A rectangle or interval uses a family other than the family of its manager."""


class LegacyOriginError(LegacyAdapterError):
    """A v1 origin/current pair does not define an exact packet relation."""


class LegacyKnowledgeError(LegacyAdapterError):
    """The per-region v1 shape cannot preserve the supplied knowledge mask."""


class LegacyRepresentationError(LegacyAdapterError):
    """The symbolic set has predicates or correlations outside the v1 shape."""


class LegacyLimitError(LegacyAdapterError):
    """A complete reverse conversion exceeded an explicit work or output limit."""

    def __init__(self, limit: str, maximum: int) -> None:
        self.limit = limit
        self.maximum = maximum
        super().__init__(f"complete legacy conversion exceeds {limit}={maximum}")


@dataclass(frozen=True, slots=True)
class LegacyAdapterLimits:
    """Hard bounds for symbolic-to-v1 conversion.

    ``max_bdd_paths`` bounds true paths before rectangle merging,
    ``max_bdd_visits`` bounds recursive BDD edge work,
    ``max_intervals_per_dimension`` bounds one cube's compact masked-value
    expansion, ``max_merge_attempts`` bounds coalescing work, and
    ``max_rectangles`` bounds the final merged region.
    """

    max_rectangles: int = 256
    max_intervals_per_dimension: int = 256
    max_bdd_paths: int = 4096
    max_bdd_visits: int = 100_000
    max_merge_attempts: int = 100_000

    def __post_init__(self) -> None:
        for name in (
            "max_rectangles",
            "max_intervals_per_dimension",
            "max_bdd_paths",
            "max_bdd_visits",
            "max_merge_attempts",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def flow_region_to_packet_set(
    manager: SymbolicManager,
    region: FlowRegion,
    *,
    bank: Bank = "current",
) -> PacketSet:
    """Import a v1 region exactly without expanding address intervals.

    All nonempty rectangles must use the manager's address family and the same
    stated service dimensions. Populated ``Rect.origin`` values are rejected.
    An origin rectangle and a current rectangle do not specify which original
    packet maps to which current packet.
    """

    manager._ensure_open()
    _validate_bank(bank)
    imported: list[PacketSet] = []
    knowledge: frozenset[str] | None = None
    for rect in region:
        _validate_rect(manager, rect)
        if rect.origin is not None:
            raise LegacyOriginError("Rect.origin records two sets without an exact original/current mapping")
        if rect.is_empty():
            continue
        rect_knowledge = frozenset(
            _RECT_TO_FIELD[name]
            for name in ("src", "dst", "proto", "dport", "sport")
            if name in {"src", "dst"} or getattr(rect, name) is not None
        )
        if knowledge is not None and rect_knowledge != knowledge:
            raise LegacyKnowledgeError("FlowRegion rectangles have different stated service dimensions")
        knowledge = rect_knowledge
        imported.append(_rect_to_packet_set(manager, rect, bank=bank, knowledge=rect_knowledge))

    if not imported:
        return manager.empty()
    result = imported[0]
    for packet_set in imported[1:]:
        result = result.union(packet_set)
    return result


def packet_set_to_flow_region(
    packet_set: PacketSet,
    *,
    bank: Bank = "current",
    limits: LegacyAdapterLimits | None = None,
) -> FlowRegion:
    """Return a complete exact v1 region or raise a typed error.

    Before rendering, the function proves that the original and next banks and
    the non-v1 header fields add no restriction beyond the validity mask of the
    selected bank. It also proves that an unstated service field is
    unconstrained.
    """

    bounded = LegacyAdapterLimits() if limits is None else limits
    prepared = _v1_projection(packet_set, bank)
    if prepared is None:
        return FlowRegion()
    projected, active_fields = prepared
    assignments = _true_path_cubes(projected, active_fields, bank=bank, limits=bounded)
    rects = [
        _cube_to_rect(packet_set.manager, assignment, active_fields, bank=bank, limits=bounded)
        for assignment in assignments
    ]
    rects = _merge_rectangles(rects, limits=bounded)
    if len(rects) > bounded.max_rectangles:
        raise LegacyLimitError("max_rectangles", bounded.max_rectangles)
    return FlowRegion(tuple(rects))


def partial_flow_region(
    packet_set: PacketSet,
    *,
    max_rectangles: int,
    bank: Bank = "current",
    limits: LegacyAdapterLimits | None = None,
) -> tuple[FlowRegion, int]:
    """The first `max_rectangles` true paths of the set as rectangles, and
    the number of its true paths, for a set whose complete region exceeds
    the conversion limits.

    The true paths of a BDD are disjoint cubes. Each rectangle is an exact
    subset of the set, and no two rectangles overlap. The rectangles are the
    whole set only when their count equals the path count. The projection
    proof of `packet_set_to_flow_region` runs first."""
    bounded = LegacyAdapterLimits() if limits is None else limits
    prepared = _v1_projection(packet_set, bank)
    if prepared is None:
        return FlowRegion(), 0
    projected, active_fields = prepared
    manager = packet_set.manager
    level_to_bit = {
        manager._bdd.level_of_var(variable): (field, bit)
        for field in active_fields
        for bit, variable in enumerate(manager.schema.bits(bank, field))
    }
    rects: list[Rect] = []
    assignment: dict[tuple[str, int], bool] = {}
    counts: dict[Any, int] = {}

    def children(node: Any) -> tuple[tuple[str, int], Any, Any]:
        level, low, high = manager._bdd.succ(node)
        if node.negated:
            low, high = ~low, ~high
        field_bit = level_to_bit.get(level)
        if field_bit is None:
            raise LegacyRepresentationError("projected BDD still contains a non-v1 variable")
        return field_bit, low, high

    def walk(node: Any) -> None:
        if len(rects) >= max_rectangles or node == manager._bdd.false:
            return
        if node == manager._bdd.true:
            rects.append(_cube_to_rect(manager, dict(assignment), active_fields, bank=bank, limits=bounded))
            return
        field_bit, low, high = children(node)
        assignment[field_bit] = False
        walk(low)
        assignment[field_bit] = True
        walk(high)
        del assignment[field_bit]

    def count(node: Any) -> int:
        if node == manager._bdd.false:
            return 0
        if node == manager._bdd.true:
            return 1
        cached = counts.get(node)
        if cached is None:
            _field_bit, low, high = children(node)
            cached = counts[node] = count(low) + count(high)
        return cached

    try:
        walk(projected._node)
        total = count(projected._node)
    finally:
        # The native roots must not outlive the manager in a retained closure.
        counts.clear()
    return FlowRegion(tuple(rects)), total


def _v1_projection(packet_set: PacketSet, bank: Bank) -> tuple[PacketSet, tuple[str, ...]] | None:
    """The set projected onto its stated v1 fields, or None for an empty set.
    The function first proves that the projection loses nothing."""
    manager = packet_set.manager
    manager._assert_sets(packet_set)
    _validate_bank(bank)
    knowledge = packet_set.known_fields
    extra_knowledge = knowledge - _LEGACY_FIELDS
    if extra_knowledge:
        raise LegacyKnowledgeError(f"v1 cannot preserve knowledge for fields: {sorted(extra_knowledge)!r}")
    if packet_set.is_empty():
        if knowledge:
            raise LegacyKnowledgeError("an empty FlowRegion cannot preserve a nonempty knowledge mask")
        return None
    missing_addresses = frozenset(_ADDRESS_FIELDS) - knowledge
    if missing_addresses:
        raise LegacyKnowledgeError(f"v1 requires stated address dimensions: {sorted(missing_addresses)!r}")
    active_fields = tuple(field for field in (*_ADDRESS_FIELDS, *_SERVICE_FIELDS) if field in knowledge)
    projected = packet_set.project(active_fields, bank=bank)
    reconstructed = manager._wrap(projected._node & manager.validity(bank)._node, knowledge)
    if not packet_set.equivalent(reconstructed):
        raise LegacyRepresentationError(
            "packet set depends on another bank, an extra header field, or an unstated service field"
        )
    return projected, active_fields


def _validate_rect(manager: SymbolicManager, rect: Rect) -> None:
    family = manager.schema.address_family
    if rect.af != family:
        raise LegacyFamilyError(f"rectangle family {rect.af} does not match symbolic manager family {family}")
    _validate_intervals(rect.src, family=family, maximum=(1 << manager.schema.width("src")) - 1)
    _validate_intervals(rect.dst, family=family, maximum=(1 << manager.schema.width("dst")) - 1)
    if rect.proto is not None and any(
        type(value) is not int or value < 0 or value > 255 for value in rect.proto
    ):
        raise LegacyRepresentationError("protocol values must be integers from 0 through 255")
    if rect.dport is not None:
        _validate_intervals(rect.dport, family=_PORT_FAMILY, maximum=65535)
    if rect.sport is not None:
        _validate_intervals(rect.sport, family=_PORT_FAMILY, maximum=65535)


def _validate_bank(bank: Bank) -> None:
    if bank not in BANKS:
        raise ValueError(f"unknown header bank: {bank}")


def _validate_intervals(
    intervals: tuple[tuple[int, int, int], ...],
    *,
    family: int,
    maximum: int,
) -> None:
    for actual_family, lower, upper in intervals:
        if actual_family != family:
            raise LegacyFamilyError(
                f"interval family {actual_family} does not match required family {family}"
            )
        if type(lower) is not int or type(upper) is not int or lower < 0 or upper < lower or upper > maximum:
            raise LegacyRepresentationError(f"invalid family-{family} interval ({lower!r}, {upper!r})")


def _rect_to_packet_set(
    manager: SymbolicManager,
    rect: Rect,
    *,
    bank: Bank,
    knowledge: frozenset[str],
) -> PacketSet:
    node = _interval_node(manager, bank, "source_address", rect.src)
    node &= _interval_node(manager, bank, "destination_address", rect.dst)
    if rect.proto is not None:
        protocol = manager._bdd.false
        vector = manager.vector(bank, "protocol")
        for value in rect.proto:
            protocol |= vector.equals(value)
        node &= protocol
    if rect.dport is not None:
        node &= _interval_node(manager, bank, "destination_port", rect.dport)
    if rect.sport is not None:
        node &= _interval_node(manager, bank, "source_port", rect.sport)

    valid_node = node & manager.validity(bank)._node
    keep = {variable for field in knowledge for variable in manager.schema.bits(bank, field)}
    remove = set(manager.schema.variables) - keep
    raw_projection = manager._bdd.exist(remove, node)
    valid_projection = manager._bdd.exist(remove, valid_node)
    if raw_projection != valid_projection:
        raise LegacyRepresentationError("symbolic header validity removes explicitly stated v1 tuples")
    return manager._wrap(valid_node, knowledge)


def _interval_node(
    manager: SymbolicManager,
    bank: Bank,
    field: str,
    intervals: tuple[tuple[int, int, int], ...],
) -> Any:
    node = manager._bdd.false
    vector = manager.vector(bank, field)
    for _family, lower, upper in intervals:
        node |= vector.between(lower, upper)
    return node


def _true_path_cubes(
    packet_set: PacketSet,
    fields: tuple[str, ...],
    *,
    bank: Bank,
    limits: LegacyAdapterLimits,
) -> list[dict[tuple[str, int], bool]]:
    manager = packet_set.manager
    level_to_bit = {
        manager._bdd.level_of_var(variable): (field, bit)
        for field in fields
        for bit, variable in enumerate(manager.schema.bits(bank, field))
    }
    paths: list[dict[tuple[str, int], bool]] = []
    assignment: dict[tuple[str, int], bool] = {}
    visits = 0

    def walk(node: Any) -> None:
        nonlocal visits
        if node == manager._bdd.false:
            return
        if node == manager._bdd.true:
            if len(paths) >= limits.max_bdd_paths:
                raise LegacyLimitError("max_bdd_paths", limits.max_bdd_paths)
            paths.append(dict(assignment))
            return
        visits += 1
        if visits > limits.max_bdd_visits:
            raise LegacyLimitError("max_bdd_visits", limits.max_bdd_visits)
        level, low, high = manager._bdd.succ(node)
        if node.negated:
            low, high = ~low, ~high
        field_bit = level_to_bit.get(level)
        if field_bit is None:
            raise LegacyRepresentationError("projected BDD still contains a non-v1 variable")
        assignment[field_bit] = False
        walk(low)
        assignment[field_bit] = True
        walk(high)
        del assignment[field_bit]

    walk(packet_set._node)
    return paths


def _cube_to_rect(
    manager: SymbolicManager,
    assignment: dict[tuple[str, int], bool],
    fields: tuple[str, ...],
    *,
    bank: Bank,
    limits: LegacyAdapterLimits,
) -> Rect:
    del bank  # assignment bit indexes already refer to the requested bank
    values: dict[str, Any] = {}
    for field in fields:
        fixed = {bit: value for (assigned_field, bit), value in assignment.items() if assigned_field == field}
        intervals = _masked_intervals(
            manager.schema.width(field),
            fixed,
            limit=limits.max_intervals_per_dimension,
        )
        rect_name = _FIELD_TO_RECT[field]
        if field == "protocol":
            values[rect_name] = frozenset(
                value for lower, upper in intervals for value in range(lower, upper + 1)
            )
        else:
            family = manager.schema.address_family if field in _ADDRESS_FIELDS else _PORT_FAMILY
            values[rect_name] = tuple((family, lower, upper) for lower, upper in intervals)
    for field in _SERVICE_FIELDS:
        if field not in fields:
            values[_FIELD_TO_RECT[field]] = None
    return Rect(manager.schema.address_family, **values)


def _masked_intervals(
    width: int,
    fixed: dict[int, bool],
    *,
    limit: int,
) -> tuple[tuple[int, int], ...]:
    intervals: list[tuple[int, int]] = []

    def walk(bit: int, prefix_value: int) -> None:
        remaining_constraints = [position for position in fixed if position >= bit]
        if not remaining_constraints:
            remaining = width - bit
            lower = prefix_value << remaining
            upper = lower | ((1 << remaining) - 1)
            if len(intervals) >= limit:
                raise LegacyLimitError("max_intervals_per_dimension", limit)
            intervals.append((lower, upper))
            return
        selected = fixed.get(bit)
        if selected is None:
            walk(bit + 1, prefix_value << 1)
            walk(bit + 1, (prefix_value << 1) | 1)
        else:
            walk(bit + 1, (prefix_value << 1) | int(selected))

    walk(0, 0)
    return tuple(intervals)


def _merge_rectangles(rects: list[Rect], *, limits: LegacyAdapterLimits) -> list[Rect]:
    changed = True
    attempts = 0
    while changed:
        changed = False
        for left_index, left in enumerate(rects):
            for right_index in range(left_index + 1, len(rects)):
                attempts += 1
                if attempts > limits.max_merge_attempts:
                    raise LegacyLimitError("max_merge_attempts", limits.max_merge_attempts)
                merged = _merge_pair(left, rects[right_index])
                if merged is None:
                    continue
                rects = [rect for index, rect in enumerate(rects) if index not in {left_index, right_index}]
                rects.append(merged)
                changed = True
                break
            if changed:
                break
    return rects


def _merge_pair(left: Rect, right: Rect) -> Rect | None:
    dimensions = ("src", "dst", "proto", "dport", "sport")
    differing = [name for name in dimensions if getattr(left, name) != getattr(right, name)]
    if len(differing) != 1:
        return None
    dimension = differing[0]
    left_value = getattr(left, dimension)
    right_value = getattr(right, dimension)
    if left_value is None or right_value is None:
        return None
    if dimension == "proto":
        combined: Any = left_value | right_value
    else:
        combined = _merge_intervals((*left_value, *right_value))
    values = {name: getattr(left, name) for name in dimensions}
    values[dimension] = combined
    return Rect(left.af, **values)


def _merge_intervals(
    intervals: tuple[tuple[int, int, int], ...],
) -> tuple[tuple[int, int, int], ...]:
    merged: list[tuple[int, int, int]] = []
    for family, lower, upper in sorted(intervals):
        if merged and merged[-1][0] == family and lower <= merged[-1][2] + 1:
            previous = merged[-1]
            merged[-1] = (family, previous[1], max(previous[2], upper))
        else:
            merged.append((family, lower, upper))
    return tuple(merged)


__all__ = [
    "LegacyAdapterError",
    "LegacyAdapterLimits",
    "LegacyFamilyError",
    "LegacyKnowledgeError",
    "LegacyLimitError",
    "LegacyOriginError",
    "LegacyRepresentationError",
    "flow_region_to_packet_set",
    "packet_set_to_flow_region",
]
