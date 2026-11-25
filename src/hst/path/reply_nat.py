"""Context-bound inverse translations for the original forward flow.

Static ranges retain offsets. Hide and pool ranges represent possible original
clients. No PAT or session binding is read. The steps of one group are applied
to the same input.
"""

from __future__ import annotations

from itertools import groupby
from typing import Any

from .addrsets import _intersect, _intervals, _merge, _size, _subtract


def point_chain(chain: list[dict[str, Any]]) -> bool:
    return valid_chain(chain) and all(
        _size(_intervals(step[when][side])) == 1
        for step in chain
        for when in ("pre", "post")
        for side in ("src", "dst")
    )


def valid_chain(chain: list[dict[str, Any]]) -> bool:
    return bool(chain) and all(
        step.get("context_uid")
        and step.get("device")
        and step.get("direction") in {"snat", "dnat", "lb"}
        and all(
            _intervals(step.get(when, {}).get(side, []))
            for when in ("pre", "post")
            for side in ("src", "dst")
        )
        for step in chain
    )


def translate(claimed, match, translated):
    """Rank-preserving mapping for equal-cardinality interval sets."""
    if _size(match) != _size(translated) or {a[0] for a in match} != {a[0] for a in translated}:
        return list(translated) if claimed else []
    result = []
    offset = 0
    for af, lo, hi in match:
        for _, start, end in _intersect(claimed, [(af, lo, hi)]):
            rank_lo, rank_hi = offset + start - lo, offset + end - lo
            target_offset = 0
            for target_af, target_lo, target_hi in translated:
                size = target_hi - target_lo + 1
                left, right = max(rank_lo, target_offset), min(rank_hi, target_offset + size - 1)
                if left <= right:
                    result.append(
                        (target_af, target_lo + left - target_offset, target_lo + right - target_offset)
                    )
                target_offset += size
        offset += hi - lo + 1
    return _merge(result)


def _groups(chain):
    return [
        list(group)
        for _, group in groupby(
            enumerate(chain),
            key=lambda pair: (pair[1]["device"], pair[1].get("context_uid"), pair[1]["direction"]),
        )
    ]


def _apply(group, addresses, side, reverse=False):
    before, after = ("post", "pre") if reverse else ("pre", "post")
    remaining, output, applied = list(addresses), [], []
    for index, step in group:
        if step["direction"] not in ({"snat", "lb"} if side == "src" else {"dnat", "lb"}):
            continue
        match, target = _intervals(step[before][side]), _intervals(step[after][side])
        claimed = _intersect(addresses, match)
        if not claimed:
            continue
        output.extend(translate(claimed, match, target))
        remaining = _subtract(remaining, claimed)
        applied.append(index)
    return _merge(remaining + output), applied


def wire_reply(chain, sources, destinations):
    for group in _groups(chain):
        sources, _ = _apply(group, sources, "src")
        destinations, _ = _apply(group, destinations, "dst")
    return destinations, sources


def undo(chain, *, device: str, context: str | None, stage: str, addresses):
    side = "src" if stage == "ingress" else "dst"
    applied = []
    for group in reversed(_groups(chain)):
        step = group[0][1]
        owners = {(step["device"], step.get("context_uid"))}
        owners.update(tuple(owner) for owner in step.get("synchronized_contexts", ()))
        if (device, context) not in owners:
            continue
        addresses, indices = _apply(group, addresses, side, reverse=True)
        applied.extend(indices)
    return addresses, applied
