"""Prefix-list evaluation.

The three platforms share one behaviour. The lines are walked in ascending
`seq`. A line matches when the address block of its prefix contains the network
address of the candidate and the prefix length of the candidate is inside the
resolved length range of the line. The action of the first matching line is the
result. A candidate that no line matches is denied.

The engine reads the resolved `min_len`/`max_len` the collector stored.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .route import prefix_network

MAX_PREFIX_LENGTH = 32


def resolve_length_range(prefix: str, ge: int | None, le: int | None, eq: int | None) -> tuple[int, int]:
    """The `[min_len, max_len]` range of a vendor line.

    A line without a qualifier has the exact length of the prefix. `ge` alone gives
    `[ge, 32]`. `le` alone gives `[prefixlen, le]`. `ge` with `le` gives `[ge, le]`.
    `eq` is applied last and overrides `ge` and `le`.
    """
    base = prefix_network(prefix).prefixlen
    lo, hi = base, base
    if ge is not None:
        lo, hi = ge, MAX_PREFIX_LENGTH
    if le is not None:
        hi = le
        if ge is None:
            lo = base
    if eq is not None:
        lo = hi = eq
    return lo, hi


def _line_matches(entry: Mapping[str, Any], candidate: str) -> bool:
    net = prefix_network(candidate)
    line_net = prefix_network(str(entry["prefix"]))
    if net.network_address not in line_net:
        return False
    lo = entry.get("min_len")
    hi = entry.get("max_len")
    if lo is None or hi is None:
        lo, hi = resolve_length_range(str(entry["prefix"]), entry.get("ge"), entry.get("le"), entry.get("eq"))
    return int(lo) <= net.prefixlen <= int(hi)


def evaluate(entries: Iterable[Mapping[str, Any]], candidate: str) -> bool:
    """True when the prefix list permits `candidate`."""
    for entry in sorted(entries, key=lambda e: int(e["seq"])):
        if _line_matches(entry, candidate):
            return str(entry["action"]).lower() == "permit"
    # A candidate that no line matches is denied.
    return False
