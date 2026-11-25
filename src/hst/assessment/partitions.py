"""The cells of a repair scope, split at the match boundaries of the policy rows."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from contextlib import suppress
from itertools import pairwise
from typing import Any

from hst.path.addrsets import _intervals, _ports, _protoset


def _split(
    scope: list[tuple[int, int, int]], boundaries: list[tuple[int, int, int]]
) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    for family, lo, hi in scope:
        points = {lo, hi + 1}
        for af, start, end in boundaries:
            if af == family:
                points.update(value for value in (start, end + 1) if lo < value <= hi)
        ordered = sorted(points)
        out.extend((family, start, end - 1) for start, end in pairwise(ordered))
        if len(out) > 4096:
            raise ValueError("repair policy partition exceeds 4096 cells in one dimension")
    return out


def policy_partitions(scope: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Split the declared scope into cells at the address, port and protocol boundaries of `rows`."""
    result = {}
    for name, side in (("source", "src"), ("destination", "dst")):
        specs = scope[name]
        for spec in specs:
            if not _intervals([str(spec)]):
                raise ValueError(f"repair {name} needs literal address intervals: {spec!r}")
        boundaries = []
        for row in rows:
            for suffix in ("cidrs", "ips", "ranges"):
                for value in row.get(f"{side}_{suffix}") or ():
                    boundaries.extend(_intervals(value if isinstance(value, list) else [value]))
        cells = _split(_intervals(specs), boundaries)
        values = []
        for af, lo, hi in cells:
            address = ipaddress.IPv4Address if af == 4 else ipaddress.IPv6Address
            values.append(str(address(lo)) if lo == hi else f"{address(lo)}-{address(hi)}")
        result[name] = values
    ports = _ports(scope["ports"])
    boundaries = []
    for row in rows:
        for port in row.get("ports") or ():
            # An opaque port value defines no cell boundary.
            with suppress(ValueError):
                boundaries.extend(_ports(port))
    result["ports"] = [str(lo) if lo == hi else f"{lo}-{hi}" for _, lo, hi in _split(ports, boundaries)]
    protocols = _protoset(list(scope["protocols"]))
    if protocols is None or not protocols:
        raise ValueError("repair protocols must describe a nonempty explicit universe")
    predicates = []
    for row in rows:
        for protocol in row.get("protos") or ():
            try:
                predicate = _protoset([protocol]) if protocol is not None else None
                if predicate is not None:
                    predicates.append(predicate)
            except ValueError:
                pass
    groups: dict[tuple[bool, ...], list[int]] = {}
    for protocol in sorted(protocols):
        groups.setdefault(tuple(protocol in predicate for predicate in predicates), []).append(protocol)
    # The protocol grammar of the overlay accepts a comma-separated union.
    result["protocols"] = [",".join(map(str, group)) for group in groups.values()]
    return result
