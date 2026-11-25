"""Concrete finite-world checks for backend-neutral policy bound operations."""

from dataclasses import dataclass
from itertools import combinations, product

import pytest

from hst.policy.bounds import Bounds, TerminalRule, at_least, choices, first_match, for_all_requested_flows


@dataclass(frozen=True)
class Finite:
    values: frozenset

    def union(self, other):
        return Finite(self.values | other.values)

    def intersect(self, other):
        return Finite(self.values & other.values)

    def subtract(self, other):
        return Finite(self.values - other.values)

    def is_empty(self):
        return not self.values

    def equivalent(self, other):
        return self.values == other.values


def finite(*values):
    return Finite(frozenset(values))


def test_terminal_policy_matches_all_consistent_predicate_worlds():
    universe = finite(0, 1)
    statuses = ("miss", "match", "unknown")
    # Every two-rule match assignment for two packets, and both terminal actions.
    for assignments in product(statuses, repeat=4):
        matches = [assignments[:2], assignments[2:]]
        predicates = [
            Bounds(
                universe,
                finite(*(packet for packet, status in enumerate(match) if status == "match")),
                finite(*(packet for packet, status in enumerate(match) if status != "miss")),
            )
            for match in matches
        ]
        for actions in product(("permit", "deny"), repeat=3):
            actual = first_match(
                universe,
                [
                    TerminalRule(predicate, action)
                    for predicate, action in zip(predicates, actions[:2], strict=True)
                ],
                default=actions[-1],
            )
            lower, upper = set(), set()
            for packet in (0, 1):
                possibilities = [
                    (False, True) if match[packet] == "unknown" else (match[packet] == "match",)
                    for match in matches
                ]
                results = []
                for world in product(*possibilities):
                    outcome = actions[-1]
                    for truth, action in zip(world, actions[:2], strict=True):
                        if truth:
                            outcome = action
                            break
                    results.append(outcome == "permit")
                if all(results):
                    lower.add(packet)
                if any(results):
                    upper.add(packet)
            assert actual.lower == finite(*lower)
            assert actual.upper == finite(*upper)


def test_unknown_action_does_not_become_permit_or_deny():
    universe = finite("client")
    match = Bounds.terminal(universe, "permit")
    result = first_match(universe, [TerminalRule(match, "unknown")], default="deny")
    assert result == Bounds.terminal(universe, "unknown")


def test_unknown_predicate_preserves_identical_continuation_outcomes():
    universe = finite(1)
    unknown = Bounds.terminal(universe, "unknown")
    for action in ("permit", "deny"):
        assert first_match(universe, [TerminalRule(unknown, action)], default=action) == Bounds.terminal(
            universe, action
        )


@pytest.mark.parametrize("mode", ["possible", "guaranteed", "unspecified"])
def test_choice_modes_and_missing_alternatives(mode):
    universe = finite(1)
    permitted = Bounds.terminal(universe, "permit")
    denied = Bounds.terminal(universe, "deny")
    expected = {
        "possible": permitted,
        "guaranteed": denied,
        "unspecified": Bounds.terminal(universe, "unknown"),
    }
    assert choices(universe, [permitted, denied], mode=mode) == expected[mode]
    assert choices(universe, [], mode=mode) == Bounds.terminal(universe, "unknown")


def test_threshold_matches_finite_truth_assignments():
    universe = finite(0)
    for statuses in product(("permit", "deny", "unknown"), repeat=4):
        possible_worlds = list(
            product(*[(False, True) if s == "unknown" else (s == "permit",) for s in statuses])
        )
        for needed in range(5):
            expected = [sum(world) >= needed for world in possible_worlds]
            actual = at_least(universe, [Bounds.terminal(universe, s) for s in statuses], needed)
            assert actual.lower == (universe if all(expected) else finite())
            assert actual.upper == (universe if any(expected) else finite())


def test_member_projection_requires_every_requested_port_and_deduplicates_clients():
    universe = finite(("a", 80), ("a", 443), ("b", 80), ("b", 443))
    successes = finite(("a", 80), ("b", 80), ("b", 443))
    result = for_all_requested_flows(
        Bounds(universe, successes, successes),
        finite("a", "b"),
        lambda packets: finite(*(client for client, _port in packets.values)),
    )
    assert result.lower == result.upper == finite("b")


def test_projection_keeps_unknown_distinct_from_a_known_failure():
    universe = finite(("a", 80), ("a", 443))
    result = for_all_requested_flows(
        Bounds(universe, finite(("a", 80)), universe),
        finite("a"),
        lambda packets: finite(*(client for client, _port in packets.values)),
    )
    assert result.lower == finite()
    assert result.upper == finite("a")


def test_invalid_bounds_and_unrelated_universes_are_rejected():
    with pytest.raises(ValueError, match="lower bound"):
        Bounds(finite(1), finite(1), finite())
    with pytest.raises(ValueError, match="upper bound"):
        Bounds(finite(1), finite(), finite(2))
    with pytest.raises(ValueError, match="same request universe"):
        choices(finite(1), [Bounds.terminal(finite(2), "deny")], mode="possible")
    with pytest.raises(ValueError, match="declared population"):
        for_all_requested_flows(Bounds.terminal(finite(1), "permit"), finite(1, 2), lambda x: x)


def test_invalid_threshold_and_modes_are_rejected():
    for invalid in (-1, 2, True, 0.5):
        with pytest.raises(ValueError, match="threshold"):
            at_least(finite(1), [Bounds.terminal(finite(1), "permit")], invalid)
    with pytest.raises(ValueError, match="mode"):
        choices(finite(1), [], mode="invented")


def test_choices_agree_with_exhaustive_independent_worlds():
    universe = finite(0, 1, 2)
    subsets = [finite(*subset) for n in range(4) for subset in combinations(range(3), n)]
    for left, right in product(subsets, repeat=2):
        branches = [Bounds(universe, left, left), Bounds(universe, right, right)]
        for mode in ("possible", "guaranteed"):
            actual = choices(universe, branches, mode=mode)
            quantifier = any if mode == "possible" else all
            expected = finite(*(q for q in range(3) if quantifier(q in s.values for s in (left, right))))
            assert actual.lower == actual.upper == expected
