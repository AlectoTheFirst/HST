"""A concrete packet algebra, the independent symbolic test oracle."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from itertools import product

Header = tuple[tuple[str, int], ...]
HeaderPredicate = Callable[[Mapping[str, int]], bool]
HeaderRewrite = Callable[[Mapping[str, int]], Mapping[str, int]]


def freeze(header: Mapping[str, int]) -> Header:
    return tuple(sorted(header.items()))


def thaw(header: Header) -> dict[str, int]:
    return dict(header)


def enumerate_headers(domain: Mapping[str, Sequence[int]]) -> frozenset[Header]:
    fields = tuple(domain)
    return frozenset(
        freeze(dict(zip(fields, values, strict=True)))
        for values in product(*(domain[field] for field in fields))
    )


def select(headers: Iterable[Header], predicate: HeaderPredicate) -> frozenset[Header]:
    return frozenset(header for header in headers if predicate(thaw(header)))


def union(left: Iterable[Header], right: Iterable[Header]) -> frozenset[Header]:
    return frozenset(left) | frozenset(right)


def intersect(left: Iterable[Header], right: Iterable[Header]) -> frozenset[Header]:
    return frozenset(left) & frozenset(right)


def subtract(left: Iterable[Header], right: Iterable[Header]) -> frozenset[Header]:
    return frozenset(left) - frozenset(right)


def project(headers: Iterable[Header], fields: Iterable[str]) -> frozenset[Header]:
    selected = frozenset(fields)
    return frozenset(tuple((name, value) for name, value in header if name in selected) for header in headers)


def rewrite(headers: Iterable[Header], changes: Mapping[str, int]) -> frozenset[Header]:
    out: set[Header] = set()
    for header in headers:
        changed = thaw(header)
        changed.update(changes)
        out.add(freeze(changed))
    return frozenset(out)


def apply(headers: Iterable[Header], transition: HeaderRewrite) -> frozenset[Header]:
    return frozenset(freeze(transition(thaw(header))) for header in headers)


def compose(*transitions: HeaderRewrite) -> HeaderRewrite:
    def composed(header: Mapping[str, int]) -> Mapping[str, int]:
        current: Mapping[str, int] = dict(header)
        for transition in transitions:
            current = transition(current)
        return current

    return composed
