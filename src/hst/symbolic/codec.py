"""Rendering of opaque packet sets with a row limit."""

from __future__ import annotations

from collections.abc import Iterable

from .manager import PacketSet
from .schema import Bank
from .types import RenderedPacketSet


def render(
    packet_set: PacketSet,
    fields: Iterable[str],
    *,
    bank: Bank = "current",
    limit: int = 32,
) -> RenderedPacketSet:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("render limit must be a non-negative integer")
    manager = packet_set.manager
    manager._assert_sets(packet_set)
    canonical = tuple(dict.fromkeys(manager.schema.canonical_field(field) for field in fields))
    projected = packet_set.project(canonical, bank=bank)
    variables = tuple(variable for field in canonical for variable in manager.schema.bits(bank, field))
    rows: list[dict[str, int]] = []
    truncated = False
    for assignment in manager._bdd.pick_iter(projected._node, care_vars=set(variables)):
        if len(rows) == limit:
            truncated = True
            break
        row: dict[str, int] = {}
        for field in canonical:
            value = 0
            for variable in manager.schema.bits(bank, field):
                value = (value << 1) | int(bool(assignment[variable]))
            row[field] = value
        rows.append(row)
    return RenderedPacketSet(tuple(rows), truncated, canonical, bank)
