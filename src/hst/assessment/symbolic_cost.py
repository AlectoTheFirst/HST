"""Exact permitted-scope costs over original packet sets, without rectangles."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from hst.assessment.cost import scope_requests
from hst.assessment.symbolic_results import SymbolicAnswer
from hst.impact.evaluate import Network, RequestSet
from hst.policy.bounds import Bounds, choices, for_all_requested_flows
from hst.symbolic import PacketSet

FIELDS = ("source_address", "destination_address", "protocol", "destination_port", "source_port")


def _scope_bounds(answer: SymbolicAnswer) -> Bounds[PacketSet]:
    """A cost tuple succeeds only if all of its requested header variants do."""
    first = next(iter(answer.members.values()))
    manager = first.bounds.universe.manager
    universe, lower, upper = manager.empty(), manager.empty(), manager.empty()
    mode = answer.mode if answer.choice_mode is None else answer.choice_mode
    for member in answer.members.values():
        population = member.bounds.universe.project(FIELDS, bank="original")
        branches = tuple(
            for_all_requested_flows(
                branch.bounds,
                population,
                lambda packets: packets.project(FIELDS, bank="original"),
            )
            for branch in member.by_choice
        )
        selected = choices(population, branches, mode=mode)
        if not member.choices_complete:
            selected = Bounds.terminal(population, "unknown")
        universe = universe.union(population)
        lower = lower.union(selected.lower)
        upper = upper.union(selected.upper)
    return Bounds(universe, lower, upper)


def permitted_scope_cost(before: Sequence[SymbolicAnswer], after: Sequence[SymbolicAnswer]) -> dict[str, Any]:
    if len(before) != len(after) or not before:
        raise ValueError("cost comparison requires matching nonempty scope requests")
    lower = upper = population = 0
    families: set[int] = set()
    for left, right in zip(before, after, strict=True):
        if (
            left.request_set != right.request_set
            or left.mode != right.mode
            or left.choice_mode != right.choice_mode
        ):
            raise ValueError("cost comparison changed the request or forwarding assumptions")
        lb, rb = _scope_bounds(left), _scope_bounds(right)
        family = lb.universe.manager.schema.address_family
        if family in families:
            raise ValueError("cost requests must contain one deduplicated scope per address family")
        families.add(family)
        if not lb.universe.equivalent(rb.universe):
            raise ValueError("cost comparison changed the declared universe")
        lower += rb.lower.subtract(lb.upper).cardinality(FIELDS, bank="original")
        upper += rb.upper.subtract(lb.lower).cardinality(FIELDS, bank="original")
        population += lb.universe.cardinality(FIELDS, bank="original")
    if lower > upper:
        raise ValueError("invalid permitted-scope cost bounds")
    return {
        "lower": lower,
        "upper": upper,
        "exact": lower == upper,
        "value": lower if lower == upper else None,
        "lower_decimal": str(lower),
        "upper_decimal": str(upper),
        "universe_flows_decimal": str(population),
        "dimensions": list(FIELDS),
        "unit": "valid-five-tuple-requests",
        "method": "symbolic-request-set-difference",
        "semantic_version": "symbolic-v2",
    }


class SymbolicScopeCostOracle:
    """Reuse the shared native evaluator and its job-owned baseline handles."""

    def __init__(
        self,
        before: Network,
        template: RequestSet,
        scope: Mapping[str, Sequence[str]],
        *,
        evaluate: Callable[[Network, RequestSet, str], SymbolicAnswer],
    ) -> None:
        self.before, self.evaluate = before, evaluate
        self.requests = scope_requests(template, scope)
        self.baseline: tuple[SymbolicAnswer, ...] | None = None

    def __call__(self, after: Network) -> dict[str, Any]:
        if self.baseline is None:
            self.baseline = tuple(
                self.evaluate(self.before, request, "possible") for request in self.requests
            )
        changed = tuple(self.evaluate(after, request, "possible") for request in self.requests)
        return permitted_scope_cost(self.baseline, changed)
