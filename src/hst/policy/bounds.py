from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, Self


class SymbolicSet(Protocol):
    def union(self, other: Self) -> Self: ...

    def intersect(self, other: Self) -> Self: ...

    def subtract(self, other: Self) -> Self: ...

    def is_empty(self) -> bool: ...

    def equivalent(self, other: Self) -> bool: ...


Outcome = Literal["permit", "deny", "unknown"]
ChoiceMode = Literal["possible", "guaranteed", "unspecified"]


@dataclass(frozen=True, slots=True)
class Bounds[S: SymbolicSet]:
    """The sets satisfy lower <= actual <= upper <= universe."""

    universe: S
    lower: S
    upper: S

    def __post_init__(self) -> None:
        if not self.lower.subtract(self.upper).is_empty():
            raise ValueError("lower bound must be contained in upper bound")
        if not self.upper.subtract(self.universe).is_empty():
            raise ValueError("upper bound must be contained in request universe")

    @classmethod
    def terminal(cls, universe: S, outcome: Outcome) -> Bounds[S]:
        empty = universe.subtract(universe)
        if outcome == "permit":
            return cls(universe, universe, universe)
        if outcome == "deny":
            return cls(universe, empty, empty)
        if outcome == "unknown":
            return cls(universe, empty, universe)
        raise ValueError(f"unsupported terminal outcome: {outcome}")


def _same_universe[S: SymbolicSet](universe: S, bounds: Iterable[Bounds[S]]) -> None:
    for bound in bounds:
        if not universe.equivalent(bound.universe):
            raise ValueError("bounds must describe the same request universe")


def conditional[S: SymbolicSet](predicate: Bounds[S], on_match: Bounds[S], on_miss: Bounds[S]) -> Bounds[S]:
    """Where truth is unknown, both continuations must prove success for the lower bound."""
    universe = predicate.universe
    _same_universe(universe, (on_match, on_miss))
    definite_match = predicate.lower
    definite_miss = universe.subtract(predicate.upper)
    undecided = predicate.upper.subtract(predicate.lower)
    lower = (
        definite_match.intersect(on_match.lower)
        .union(definite_miss.intersect(on_miss.lower))
        .union(undecided.intersect(on_match.lower).intersect(on_miss.lower))
    )
    upper = (
        definite_match.intersect(on_match.upper)
        .union(definite_miss.intersect(on_miss.upper))
        .union(undecided.intersect(on_match.upper.union(on_miss.upper)))
    )
    return Bounds(universe, lower, upper)


@dataclass(frozen=True, slots=True)
class TerminalRule[S: SymbolicSet]:
    """Inline calls and nonterminal vendor actions are not of this type."""

    match: Bounds[S]
    outcome: Outcome


def first_match[S: SymbolicSet](
    universe: S, rules: Sequence[TerminalRule[S]], *, default: Outcome
) -> Bounds[S]:
    """Fold terminal rules from their fallback while preserving first-match order."""
    _same_universe(universe, (rule.match for rule in rules))
    result = Bounds.terminal(universe, default)
    for rule in reversed(rules):
        result = conditional(rule.match, Bounds.terminal(universe, rule.outcome), result)
    return result


def choices[S: SymbolicSet](universe: S, branches: Sequence[Bounds[S]], *, mode: ChoiceMode) -> Bounds[S]:
    """Unknown/missing alternatives must be represented by an unknown branch."""
    if mode not in {"possible", "guaranteed", "unspecified"}:
        raise ValueError(f"unsupported forwarding-choice mode: {mode}")
    _same_universe(universe, branches)
    if not branches:
        return Bounds.terminal(universe, "unknown")
    empty = universe.subtract(universe)
    lower = empty if mode == "possible" else universe
    upper = universe if mode == "guaranteed" else empty
    for branch in branches:
        lower = lower.union(branch.lower) if mode == "possible" else lower.intersect(branch.lower)
        upper = upper.intersect(branch.upper) if mode == "guaranteed" else upper.union(branch.upper)
    return Bounds(universe, lower, upper)


def at_least[S: SymbolicSet](universe: S, members: Sequence[Bounds[S]], count: int) -> Bounds[S]:
    """Members aggregated existentially one by one are invalid when their forwarding
    choices are correlated."""
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= len(members):
        raise ValueError("threshold must be an integer between zero and member count")
    _same_universe(universe, members)
    empty = universe.subtract(universe)
    lower, upper = [universe] + [empty] * count, [universe] + [empty] * count
    for member in members:
        for needed in range(count, 0, -1):
            lower[needed] = lower[needed].union(lower[needed - 1].intersect(member.lower))
            upper[needed] = upper[needed].union(upper[needed - 1].intersect(member.upper))
    return Bounds(universe, lower[count], upper[count])


def for_all_requested_flows[S: SymbolicSet, P: SymbolicSet](
    bounds: Bounds[S], population: P, project: Callable[[S], P]
) -> Bounds[P]:
    """Projection is existential."""
    if not project(bounds.universe).equivalent(population):
        raise ValueError("request universe must project to the declared population")
    return Bounds(
        population,
        population.subtract(project(bounds.universe.subtract(bounds.lower))),
        population.subtract(project(bounds.universe.subtract(bounds.upper))),
    )
