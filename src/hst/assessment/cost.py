"""The count of newly permitted flows inside a finite scope."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from math import prod
from typing import Any

from hst.impact.evaluate import Answer, Member, Network, RequestSet, Service, answer, member
from hst.path.addrsets import _intervals, _merge, _ports, _protoset
from hst.path.state import FlowRegion


def disjoint(region: FlowRegion, *, max_rectangles: int = 10000) -> FlowRegion:
    """Return `region` as rectangles that do not overlap."""
    out = FlowRegion()
    for rect in region:
        unseen = FlowRegion.single(rect).subtract(out)
        if len(out) + len(unseen) > max_rectangles:
            raise ValueError("exact cost region exceeds its rectangle budget")
        out = out.union(unseen)
    return out


def cardinality(region: FlowRegion) -> int:
    result = 0
    for rect in disjoint(region):
        dimensions = (
            sum(hi - lo + 1 for _af, lo, hi in _merge(list(rect.src))),
            sum(hi - lo + 1 for _af, lo, hi in _merge(list(rect.dst))),
            256 if rect.proto is None else len(rect.proto),
            65536 if rect.dport is None else sum(hi - lo + 1 for _af, lo, hi in _merge(list(rect.dport))),
            65536 if rect.sport is None else sum(hi - lo + 1 for _af, lo, hi in _merge(list(rect.sport))),
        )
        result += prod(dimensions)
    return result


def answer_regions(answers: Sequence[Answer]) -> tuple[FlowRegion, FlowRegion]:
    """The union of the member flow bounds of `answers`, as a lower and an upper region."""
    lower, upper = FlowRegion(), FlowRegion()
    for result in answers:
        for value in result.members.values():
            lower = lower.union(value.lower)
            upper = upper.union(value.upper)
    return disjoint(lower), disjoint(upper)


def permitted_scope_cost(
    before: Sequence[Answer],
    after: Sequence[Answer],
    universe: FlowRegion,
) -> dict[str, Any]:
    """The bounds of the count of newly permitted flows inside `universe`.

    The lower bound counts the lower region after minus the upper region
    before. The upper bound counts the upper region after minus the lower
    region before. `exact` is true when the 2 bounds are equal.
    """
    lb, ub = answer_regions(before)
    la, ua = answer_regions(after)
    lower = cardinality(la.subtract(ub).intersect(universe))
    upper = cardinality(ua.subtract(lb).intersect(universe))
    if lower > upper:
        raise ValueError("invalid cost bounds: evaluator lower is not contained in upper")
    return {
        "lower": lower,
        "upper": upper,
        "exact": lower == upper,
        "value": lower if lower == upper else None,
        "lower_decimal": str(lower),
        "upper_decimal": str(upper),
        "universe_flows_decimal": str(cardinality(universe)),
        "dimensions": ["source", "destination", "protocol", "destination_port", "source_port"],
        "method": "whole-flow-region-difference",
    }


def scope_requests(template: RequestSet, scope: Mapping[str, Sequence[str]]) -> tuple[RequestSet, ...]:
    """Build one request per address family over the whole scope.

    The scope must state `source`, `destination`, `protocols` and `ports`.
    """
    for field in ("source", "destination", "protocols", "ports"):
        if not scope.get(field):
            raise ValueError(f"cost scope requires explicit {field}")
    sources, destinations = _intervals(list(scope["source"])), _intervals(list(scope["destination"]))
    if not sources or not destinations:
        raise ValueError("cost scope addresses must resolve to literal finite address intervals")
    protocols = _protoset(list(scope["protocols"]))
    if protocols is None:
        raise ValueError("cost scope protocols must be explicit, including any for all protocols")
    service = Service(
        protocols,
        tuple(_ports(list(scope["ports"]))),
        tuple(_ports(list(scope.get("source_ports", ["any"])))),
    )
    out = []
    for af in sorted({row[0] for row in sources} & {row[0] for row in destinations}):
        name = f"cost-ipv{af}"
        out.append(
            replace(
                template,
                name=name,
                destination=name,
                sources=tuple(row for row in sources if row[0] == af),
                members=(Member(name, tuple(row for row in destinations if row[0] == af), service),),
                condition=member(name),
                service=service,
            )
        )
    if not out or {r[0] for r in sources} != {r[0] for r in destinations}:
        raise ValueError("cost scope source and destination address families must match")
    return tuple(out)


class ScopeCostOracle:
    """The scope cost of a changed network against one baseline network.

    The baseline answers are computed once. `evaluate` answers one request.
    """

    def __init__(
        self,
        before: Network,
        template: RequestSet,
        scope: Mapping[str, Sequence[str]],
        *,
        evaluate: Callable[[Network, RequestSet, str], Answer] = answer,
    ) -> None:
        self.before = before
        self.requests = scope_requests(template, scope)
        self.evaluate = evaluate
        self.baseline: tuple[Answer, ...] | None = None
        self.universe = disjoint(
            FlowRegion(
                tuple(rect for request in self.requests for rect in request.member_region(request.members[0]))
            )
        )

    def __call__(self, after: Network) -> dict[str, Any]:
        # The scope cost counts every permitted path, and both sides are evaluated in
        # the mode `possible`. The request and session semantics of the template are kept.
        if self.baseline is None:
            self.baseline = tuple(
                self.evaluate(self.before, request, "possible") for request in self.requests
            )
        changed = tuple(self.evaluate(after, request, "possible") for request in self.requests)
        return permitted_scope_cost(self.baseline, changed, self.universe)
