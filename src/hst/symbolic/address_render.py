"""Paginated prefix covers with exact counts, without address enumeration."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import Any

from .manager import PacketSet
from .schema import Bank


@dataclass(frozen=True, slots=True)
class PrefixPage:
    items: tuple[str, ...]
    count: int
    addresses: int
    offset: int
    next_offset: int | None


def address_prefixes(
    packets: PacketSet,
    *,
    field: str = "source_address",
    bank: Bank = "original",
    offset: int = 0,
    limit: int = 250,
    max_states: int = 200_000,
) -> PrefixPage:
    """Count a minimal prefix cover with DAG cofactors and render one page of it.

    The count is exact for noncontiguous masks.
    """
    if (
        any(type(value) is not int for value in (offset, limit, max_states))
        or offset < 0
        or limit < 1
        or max_states < 1
    ):
        raise ValueError("invalid prefix page budgets")
    manager = packets.manager
    if field not in {"source_address", "destination_address"}:
        raise ValueError("prefix rendering requires an address field")
    projected = packets.project((field,), bank=bank)
    width = manager.schema.width(field)
    bdd = manager._bdd
    cache: dict[tuple[Any, int], int] = {}

    def halves(node: Any, depth: int) -> tuple[Any, Any]:
        variable = manager.schema.variable(bank, field, depth)
        return bdd.let({variable: False}, node), bdd.let({variable: True}, node)

    def count(node: Any, depth: int) -> int:
        if node == bdd.false:
            return 0
        if node == bdd.true:
            return 1
        key = (node, depth)
        if key in cache:
            return cache[key]
        if depth >= width:
            raise ValueError("projected address set retained other dimensions")
        if len(cache) >= max_states:
            raise ValueError("prefix count state limit exceeded")
        cache[key] = 0
        left, right = halves(node, depth)
        cache[key] = count(left, depth + 1) + count(right, depth + 1)
        return cache[key]

    pending: list[tuple[Any, int, int]] = []
    try:
        total = count(projected._node, 0)
        pending = [(projected._node, 0, 0)]
        remaining_skip = offset
        items: list[str] = []
        network_type = IPv4Network if width == 32 else IPv6Network
        while pending and len(items) < limit:
            node, depth, start = pending.pop()
            size = count(node, depth)
            if size <= remaining_skip:
                remaining_skip -= size
                continue
            if node == bdd.true:
                items.append(str(network_type((start, depth))))
                continue
            left, right = halves(node, depth)
            pending.append((right, depth + 1, start + (1 << (width - depth - 1))))
            pending.append((left, depth + 1, start))
        next_offset = offset + len(items) if offset + len(items) < total else None
        return PrefixPage(
            tuple(items), total, projected.cardinality((field,), bank=bank), offset, next_offset
        )
    finally:
        cache.clear()
        pending.clear()
