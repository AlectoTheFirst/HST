"""One symbolic flow state for every gate.

`None` on a service dimension means that the query does not state it. A rule
scoped to that dimension cannot be decided against such a query. `claim`
reports the dimension in `Claim.unknown` and keeps `None` on the hit. In the
set algebra (`intersect`, `subtract`, `union`), an unstated dimension is
every value of it.

Nothing here reads the graph.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, NamedTuple, Protocol

from .addrsets import _ALL_PROTOS, _PORT_UNIVERSE, _intersect, _merge, _ports, _subtract

# A merged interval set with family tags, as `_intervals` and `_ports` return it.
Ivals = tuple[tuple[int, int, int], ...]

# The dimensions of a rectangle, in the order in which `subtract` and `claim`
# carve them. The address sides come before the service dimensions.
_ADDRESS_DIMS = ("src", "dst")
_SERVICE_DIMS = ("proto", "dport", "sport")
DIMS = (*_ADDRESS_DIMS, *_SERVICE_DIMS)


def _ivals(items: Sequence[tuple[int, int, int]] | None) -> Ivals | None:
    return None if items is None else tuple(_merge(list(items)))


def _meet_set(a: frozenset[int] | None, b: frozenset[int] | None) -> frozenset[int] | None:
    """Protocol intersection under the set-algebra reading of `None`."""
    if a is None:
        return b
    if b is None:
        return a
    return a & b


def _meet_ivals(a: Ivals | None, b: Ivals | None) -> Ivals | None:
    """Interval intersection under the set-algebra reading of `None`."""
    if a is None:
        return b
    if b is None:
        return a
    return tuple(_intersect(list(a), list(b)))


def _diff_set(a: frozenset[int] | None, b: frozenset[int] | None) -> frozenset[int]:
    if b is None:
        return frozenset()
    return (_ALL_PROTOS if a is None else a) - b


def _diff_ivals(a: Ivals | None, b: Ivals | None) -> Ivals:
    if b is None:
        return ()
    return tuple(_subtract(list(_PORT_UNIVERSE) if a is None else list(a), list(b)))


def _empty_dim(value: Any) -> bool:
    """Whether a stated dimension covers nothing. `None` is unstated and gives False."""
    return value is not None and len(value) == 0


@dataclass(frozen=True, slots=True)
class Rect:
    """One rectangle of the flow space.

    `af` is the family in which the packet is routed. It is the family of
    the first destination interval, as in `_group_legs`. `src` and `dst` are
    address interval sets and are always stated. `proto` is a set of IANA
    numbers. `dport` and `sport` are port interval sets under
    `addrsets._PORT_FAMILY`. Each of these 3 is `None` where the query does
    not state that dimension.

    `origin` is the request that this rectangle answers for. Equality ignores
    it.
    """

    af: int
    src: Ivals
    dst: Ivals
    proto: frozenset[int] | None
    dport: Ivals | None
    sport: Ivals | None
    origin: Rect | None = field(default=None, compare=False)

    @property
    def request(self) -> Rect:
        """The flow that the caller asked about."""
        return self if self.origin is None else self.origin

    def is_empty(self) -> bool:
        return (
            not self.src
            or not self.dst
            or _empty_dim(self.proto)
            or _empty_dim(self.dport)
            or _empty_dim(self.sport)
        )

    def stated(self) -> frozenset[str]:
        """The service dimensions this rectangle states a value for."""
        return frozenset(d for d in _SERVICE_DIMS if getattr(self, d) is not None)

    def narrow(self, **dims: Any) -> Rect:
        """A copy with the dimensions in `dims` replaced. The origin is kept."""
        return replace(self, **dims)

    def rewrite(self, **dims: Any) -> Rect:
        """A copy with the dimensions in `dims` replaced, for a header rewrite.
        The origin of the copy is the origin of this rectangle, or this
        rectangle if it has none."""
        return replace(self, origin=self.request, **dims)

    def intersect(self, other: Rect) -> Rect | None:
        """The flows both rectangles cover, or None when there are none."""
        if self.af != other.af:
            return None
        out = replace(
            self,
            src=tuple(_intersect(list(self.src), list(other.src))),
            dst=tuple(_intersect(list(self.dst), list(other.dst))),
            proto=_meet_set(self.proto, other.proto),
            dport=_meet_ivals(self.dport, other.dport),
            sport=_meet_ivals(self.sport, other.sport),
        )
        return None if out.is_empty() else out

    def subtract(self, other: Rect) -> tuple[Rect, ...]:
        """The flows that this rectangle covers and `other` does not, as
        disjoint rectangles.

        Each dimension gives at most 1 rectangle. The rectangle has the rest
        of this rectangle on that dimension, the common value on the
        dimensions before it and the value of this rectangle on the dimensions
        after it. `_nat_partition` carves its 4 dimensions the same way."""
        common = self.intersect(other)
        if common is None:
            return (self,)
        pieces: list[Rect] = []
        rests: dict[str, Any] = {
            "src": tuple(_subtract(list(self.src), list(other.src))),
            "dst": tuple(_subtract(list(self.dst), list(other.dst))),
            "proto": _diff_set(self.proto, other.proto),
            "dport": _diff_ivals(self.dport, other.dport),
            "sport": _diff_ivals(self.sport, other.sport),
        }
        for k, dim in enumerate(DIMS):
            rest = rests[dim]
            if not rest:
                continue
            values = {d: getattr(common, d) for d in DIMS[:k]}
            values[dim] = rest
            piece = replace(self, **values)
            if not piece.is_empty():
                pieces.append(piece)
        return tuple(pieces)


@dataclass(frozen=True, slots=True)
class FlowRegion:
    """A set of flows as a list of rectangles.

    Every operation here keeps the rectangles of a region disjoint. `union`
    concatenates and drops duplicates and does not merge rectangles.
    """

    rects: tuple[Rect, ...] = ()

    @classmethod
    def from_query(
        cls,
        src_set: Sequence[tuple[int, int, int]],
        dst_set: Sequence[tuple[int, int, int]],
        proto_set: frozenset[int] | None = None,
        port_ivals: Sequence[tuple[int, int, int]] | None = None,
        sport_ivals: Sequence[tuple[int, int, int]] | None = None,
    ) -> FlowRegion:
        """The region of a query as one rectangle. A service dimension that
        the query does not state is `None`."""
        src, dst = _ivals(src_set), _ivals(dst_set)
        if not src or not dst:
            return cls()
        af = dst[0][0]
        return cls((Rect(af, src, dst, proto_set, _ivals(port_ivals), _ivals(sport_ivals)),))

    @classmethod
    def single(cls, rect: Rect) -> FlowRegion:
        return cls(() if rect.is_empty() else (rect,))

    def __iter__(self) -> Iterator[Rect]:
        return iter(self.rects)

    def __len__(self) -> int:
        return len(self.rects)

    def __bool__(self) -> bool:
        return not self.is_empty()

    def is_empty(self) -> bool:
        return all(r.is_empty() for r in self.rects)

    def map(self, fn: Any) -> FlowRegion:
        """`fn` applied to every rectangle, empties dropped."""
        return FlowRegion(tuple(out for r in self.rects if not (out := fn(r)).is_empty()))

    def intersect(self, other: FlowRegion) -> FlowRegion:
        out: list[Rect] = []
        for a in self.rects:
            for b in other.rects:
                common = a.intersect(b)
                if common is not None:
                    out.append(common)
        return FlowRegion(tuple(out))

    def subtract(self, other: FlowRegion) -> FlowRegion:
        remaining = [r for r in self.rects if not r.is_empty()]
        for b in other.rects:
            remaining = [piece for a in remaining for piece in a.subtract(b)]
        return FlowRegion(tuple(remaining))

    def union(self, other: FlowRegion) -> FlowRegion:
        """Every rectangle of either region, once each, this region's first."""
        out: list[Rect] = []
        for r in (*self.rects, *other.rects):
            if not r.is_empty() and r not in out:
                out.append(r)
        return FlowRegion(tuple(out))


class Predicate(NamedTuple):
    """The match side of a rule. `None` on a dimension is unconstrained and
    every value passes."""

    src: Ivals | None = None
    dst: Ivals | None = None
    proto: frozenset[int] | None = None
    dport: Ivals | None = None
    sport: Ivals | None = None


class Claim(NamedTuple):
    """The answer of `claim`.

    `hit` is the part of the rectangle that the predicate takes, or `None`
    for a miss. `rest` holds the parts left for a later rule. `unknown` holds
    the dimensions that the predicate constrains and the rectangle does not
    state. With a non-empty `unknown`, the caller reports `hit` as undecided."""

    hit: Rect | None
    rest: tuple[Rect, ...]
    unknown: frozenset[str]


def claim(rect: Rect, pred: Predicate) -> Claim:
    """The predicate of one rule against one rectangle, three-valued per dimension.

    A constrained dimension that the rectangle states either overlaps or
    misses. The overlap is the hit on that dimension. A miss on one dimension
    is a miss of the rule. An address side is always stated.

    A service dimension that the rectangle leaves `None` cannot be decided
    against a predicate that constrains it. The hit keeps `None` on that
    dimension, no rest is carved on it, and `unknown` holds its name.

    A predicate with an empty set on a dimension (`!all`) misses every
    rectangle, as `_service_regions` reads an empty member.
    """
    hit_values: dict[str, Any] = {}
    rest_values: dict[str, Any] = {}
    unknown: set[str] = set()
    for dim in DIMS:
        have, want = getattr(rect, dim), getattr(pred, dim)
        if want is None:
            hit_values[dim] = have
            rest_values[dim] = None
            continue
        if len(want) == 0:
            return Claim(None, (rect,), frozenset())
        if have is None:
            hit_values[dim] = None
            rest_values[dim] = None
            unknown.add(dim)
            continue
        if dim == "proto":
            inter, rest = have & want, have - want
        else:
            inter = tuple(_intersect(list(have), list(want)))
            rest = tuple(_subtract(list(have), list(want)))
        if not inter:
            return Claim(None, (rect,), frozenset())
        hit_values[dim] = inter
        rest_values[dim] = rest or None
    hit = replace(rect, **hit_values)
    rest_rects: list[Rect] = []
    for k, dim in enumerate(DIMS):
        rest = rest_values[dim]
        if not rest:
            continue
        values = {d: hit_values[d] for d in DIMS[:k]}
        values[dim] = rest
        piece = replace(rect, **values)
        if not piece.is_empty():
            rest_rects.append(piece)
    return Claim(hit, tuple(rest_rects), frozenset(unknown))


@dataclass(frozen=True, slots=True)
class Effect:
    """What one transition did to one output region.

    `kind` is one of `permit`,
    `deny` and `indeterminate` for a predicate, `rewrite` and `pass` for a
    rewrite, `select` for a table or route choice, `no-route`, `relate` for
    a load balancer member, `broker` for a ZPA connector. `terminal` is True
    when the flow goes no further on this branch (a deny, a discard route, a
    broker that stops before any packet). `unknown` holds the dimensions that
    the decision could not read. `data` is the row or part dict of the gate.
    """

    kind: str
    gate: str
    terminal: bool = False
    unknown: frozenset[str] = frozenset()
    reason: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)


class Transition(Protocol):
    """A processing step as a relation over regions. `apply` returns the
    output regions of an input region and the effect on each."""

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]: ...


def compose(
    region: FlowRegion, transitions: Sequence[Transition]
) -> list[tuple[FlowRegion, tuple[Effect, ...]]]:
    """Apply the transitions in the order given. Each transition takes the
    regions of the one before it. A terminal effect ends its branch."""
    branches: list[tuple[FlowRegion, tuple[Effect, ...]]] = [(region, ())]
    for t in transitions:
        nxt: list[tuple[FlowRegion, tuple[Effect, ...]]] = []
        for reg, effects in branches:
            if effects and effects[-1].terminal:
                nxt.append((reg, effects))
                continue
            if reg.is_empty():
                continue
            for out, effect in t.apply(reg):
                nxt.append((out, (*effects, effect)))
        branches = nxt
    return branches


def pipeline(stages: Mapping[int, Transition]) -> tuple[Transition, ...]:
    """The transitions of `stages`, keyed by `gates.Stage`, in the order of
    the stage values."""
    return tuple(stages[k] for k in sorted(stages))


# Conversions between a rectangle and the specs the gates read.


def port_spec(ivals: Ivals | Sequence[tuple[int, int, int]] | None) -> int | str | None:
    """A port dimension as a value that the point matchers and `_ports`
    read. One port is an int. A wider set is a spec string that
    `_states_a_range` reads as a range."""
    if not ivals:
        return None
    items = list(ivals)
    if len(items) == 1 and items[0][1] == items[0][2]:
        return items[0][1]
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for _, lo, hi in items)


def port_ivals(spec: Any) -> Ivals | None:
    """A port spec as a dimension value. An unstated spec gives `None`."""
    if spec is None or spec == "" or (isinstance(spec, list | set | frozenset) and not spec):
        return None
    return tuple(_ports(list(spec) if isinstance(spec, set | frozenset) else spec))


def proto_spec(protos: frozenset[int] | None) -> frozenset[int] | None:
    """A protocol dimension as the spec that the gates read. The spec is the
    set itself. `_as_protoset` resolves it number by number."""
    return protos
