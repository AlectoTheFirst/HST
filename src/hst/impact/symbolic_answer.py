"""Compound conditions are evaluated inside a common joint-choice assignment."""

from __future__ import annotations

from collections.abc import Sequence

from hst.policy.bounds import Bounds, ChoiceMode, at_least, choices
from hst.symbolic import PacketSet

from .symbolic_walk import WalkResult


def compound_members(
    members: Sequence[WalkResult], *, count: int, mode: ChoiceMode = "unspecified"
) -> Bounds[PacketSet]:
    """Combine member bounds already mapped into identical original request units."""
    if not members:
        raise ValueError("compound evaluation requires a declared member population")
    first = members[0]
    if type(count) is not int or not 0 <= count <= len(members):
        raise ValueError("threshold must be an integer between zero and member count")
    universe = first.bounds.universe
    assignments = tuple(result.assignment for result in first.by_choice)
    for member in members:
        if member.manifest_digest != first.manifest_digest or member.request_id != first.request_id:
            raise ValueError("compound members must share snapshot and request identity")
        if not member.bounds.universe.equivalent(universe):
            raise ValueError("compound members must use identical original request units")
        if tuple(result.assignment for result in member.by_choice) != assignments:
            raise ValueError("compound members must retain the same joint choice assignments")
    joint = tuple(
        at_least(universe, tuple(member.by_choice[index].bounds for member in members), count)
        for index in range(len(assignments))
    )
    result = choices(universe, joint, mode=mode)
    if not all(member.choices_complete for member in members):
        return Bounds.terminal(universe, "unknown")
    return result
