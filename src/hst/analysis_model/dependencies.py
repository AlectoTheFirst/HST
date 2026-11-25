"""Exact semantic dependencies and negative (absence) selectors."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class QualifiedRef:
    kind: str
    authority: str
    uid: str

    def __post_init__(self) -> None:
        values = (self.kind, self.authority, self.uid)
        if not all(isinstance(v, str) and v and v.strip() == v for v in values):
            raise ValueError("qualified references require nonempty canonical strings")


@dataclass(frozen=True, slots=True, order=True)
class AbsenceSelector:
    kind: str
    authority: str
    key: str

    def matches(self, ref: QualifiedRef) -> bool:
        return (
            self.kind in ("*", ref.kind)
            and self.authority in ("*", ref.authority)
            and self.key in ("*", ref.uid)
        )


class DependencyIndex:
    """A direct dependency graph. `invalidate` traverses the transitive closure."""

    def __init__(self) -> None:
        self.forward: dict[QualifiedRef, set[QualifiedRef]] = defaultdict(set)
        self.reverse: dict[QualifiedRef, set[QualifiedRef]] = defaultdict(set)
        self.absences: dict[AbsenceSelector, set[QualifiedRef]] = defaultdict(set)

    def add(self, dependent: QualifiedRef, references: Iterable[QualifiedRef] = ()) -> None:
        for ref in references:
            self.forward[dependent].add(ref)
            self.reverse[ref].add(dependent)

    record = add

    def record_absence(self, dependent: QualifiedRef, selector: AbsenceSelector) -> None:
        self.absences[selector].add(dependent)

    def invalidate(
        self, changed: Iterable[QualifiedRef], *, old: DependencyIndex | None = None
    ) -> frozenset[QualifiedRef]:
        """Return all affected dependents, including cycles and old graph edges."""
        seeds = set(changed)
        for selector, dependents in self.absences.items():
            if any(selector.matches(ref) for ref in seeds):
                seeds.update(dependents)
        if old is not None:
            for selector, dependents in old.absences.items():
                if any(selector.matches(ref) for ref in seeds):
                    seeds.update(dependents)
        result: set[QualifiedRef] = set()
        queue = deque(seeds)
        while queue:
            item = queue.popleft()
            if item in result:
                continue
            result.add(item)
            for dependent in self.reverse.get(item, ()):
                queue.append(dependent)
            if old is not None:
                for dependent in old.reverse.get(item, ()):
                    queue.append(dependent)
        return frozenset(result)


DependencyRecorder = DependencyIndex
