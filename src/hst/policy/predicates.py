"""Compiles predicates and shared object definitions into bounds of packet sets."""

from __future__ import annotations

from dataclasses import dataclass

from hst.symbolic import PacketSet, SymbolicManager, equals, header, masked, value_range

from .bounds import Bounds
from .ir import AllOf, AnyOf, Atom, Constant, Not, ObjectDefinition, ObjectKey, Predicate, Ref, Unknown


@dataclass(frozen=True, slots=True)
class CompiledPredicate:
    """`dependencies` holds the keys of the objects that the predicate references directly.

    PredicateCompiler.update propagates changes through the reverse graph of the object references.
    A group in more than one rule has one compiled result.
    """

    bounds: Bounds[PacketSet]
    gaps: frozenset[Unknown] = frozenset()
    dependencies: frozenset[ObjectKey] = frozenset()


def references(predicate: Predicate) -> frozenset[ObjectKey]:
    pending = [predicate]
    found: set[ObjectKey] = set()
    while pending:
        term = pending.pop()
        if isinstance(term, Ref):
            found.add(term.key)
        elif isinstance(term, (AllOf, AnyOf)):
            pending.extend(term.terms)
        elif isinstance(term, Not):
            pending.append(term.term)
    return frozenset(found)


class PredicateCompiler:
    """A compiler for one manager and one set of known fields.

    `update` drops the compiled result of each changed object and of each
    object that references it. A changed object includes an object that had no
    definition before. An object compiles once, and each rule that references
    it reuses the result.
    """

    def __init__(
        self,
        manager: SymbolicManager,
        known_fields: frozenset[str],
        *,
        depth_limit: int = 128,
        share_identical: bool = False,
    ):
        self.manager = manager
        self.known_fields = frozenset(manager.schema.canonical_field(field) for field in known_fields)
        self.universe = manager.universe(known_fields=self.known_fields)
        if not 1 <= depth_limit <= 128:
            raise ValueError("predicate depth limit must be between 1 and 128")
        self.depth_limit = depth_limit
        self.objects: dict[ObjectKey, ObjectDefinition] = {}
        self._objects: dict[ObjectKey, CompiledPredicate] = {}
        self._expressions: dict[Predicate, CompiledPredicate] = {}
        # With `share_identical`, a composite expression that a caller shares
        # by object identity (one AnyOf of the addresses of an EPG under many
        # edges) compiles at most 2 times. The second compilation of the same
        # object at the same depth stores its result. `_seen` and `_shared`
        # hold a reference to the object, and its id stays unique. Only a
        # compiler that lives for one model build sets `share_identical`.
        self.share_identical = share_identical
        self._seen: dict[tuple[int, int], Predicate] = {}
        self._shared: dict[tuple[int, int], tuple[Predicate, CompiledPredicate]] = {}
        self.compiled_objects = 0
        self.reused_objects = 0

    def update(self, definitions: tuple[ObjectDefinition, ...]) -> frozenset[ObjectKey]:
        current = {obj.key: obj for obj in definitions}
        changed = {
            key for key in self.objects.keys() | current.keys() if self.objects.get(key) != current.get(key)
        }
        reverse: dict[ObjectKey, set[ObjectKey]] = {}
        for obj in (*self.objects.values(), *current.values()):
            for reference in references(obj.predicate):
                reverse.setdefault(reference, set()).add(obj.key)
        pending = list(changed)
        while pending:
            for parent in reverse.get(pending.pop(), ()):
                if parent not in changed:
                    changed.add(parent)
                    pending.append(parent)
        for key in changed:
            self._objects.pop(key, None)
        self.objects = current
        self._expressions.clear()
        self._seen.clear()
        self._shared.clear()
        self.compiled_objects = self.reused_objects = 0
        return frozenset(changed)

    def unknown(self, gap: Unknown, dependencies: frozenset[ObjectKey] = frozenset()) -> CompiledPredicate:
        return CompiledPredicate(Bounds.terminal(self.universe, "unknown"), frozenset({gap}), dependencies)

    def compile(self, predicate: Predicate) -> CompiledPredicate:
        return self._compile(predicate, (), 0)

    def _compile(self, predicate: Predicate, stack: tuple[ObjectKey, ...], depth: int) -> CompiledPredicate:
        if depth >= self.depth_limit:
            return self.unknown(Unknown("PREDICATE_DEPTH_LIMIT", "predicate"), references(predicate))
        cacheable = isinstance(predicate, (Atom, Constant, Unknown, Ref)) and not stack
        if cacheable and predicate in self._expressions:
            return self._expressions[predicate]
        identity = (id(predicate), depth)
        shared = (
            self.share_identical
            and not cacheable
            and not stack
            and isinstance(predicate, (AllOf, AnyOf, Not))
        )
        if shared:
            hit = self._shared.get(identity)
            if hit is not None:
                return hit[1]
        if isinstance(predicate, Constant):
            result = CompiledPredicate(
                Bounds.terminal(self.universe, "permit" if predicate.value else "deny")
            )
        elif isinstance(predicate, Unknown):
            result = self.unknown(predicate)
        elif isinstance(predicate, Atom):
            result = self._atom(predicate)
        elif isinstance(predicate, Ref):
            result = self._object(predicate.key, stack, depth)
        elif isinstance(predicate, Not):
            inner = self._compile(predicate.term, stack, depth + 1)
            result = CompiledPredicate(
                Bounds(
                    self.universe,
                    self.universe.subtract(inner.bounds.upper),
                    self.universe.subtract(inner.bounds.lower),
                ),
                inner.gaps,
                inner.dependencies,
            )
        elif isinstance(predicate, (AllOf, AnyOf)):
            conjunction = isinstance(predicate, AllOf)
            initial = Bounds.terminal(self.universe, "permit" if conjunction else "deny")
            lower, upper = initial.lower, initial.upper
            gaps: set[Unknown] = set()
            dependencies: set[ObjectKey] = set()
            for term in predicate.terms:
                child = self._compile(term, stack, depth + 1)
                lower = (
                    lower.intersect(child.bounds.lower) if conjunction else lower.union(child.bounds.lower)
                )
                upper = (
                    upper.intersect(child.bounds.upper) if conjunction else upper.union(child.bounds.upper)
                )
                gaps.update(child.gaps)
                dependencies.update(child.dependencies)
            result = CompiledPredicate(
                Bounds(self.universe, lower, upper), frozenset(gaps), frozenset(dependencies)
            )
        else:
            raise TypeError("unknown predicate node; use an explicit Unknown leaf")
        if cacheable:
            self._expressions[predicate] = result
        elif shared:
            if identity in self._seen:
                self._shared[identity] = (predicate, result)
            else:
                self._seen[identity] = predicate
        return result

    def _object(self, key: ObjectKey, stack: tuple[ObjectKey, ...], depth: int) -> CompiledPredicate:
        if key in stack:
            return self.unknown(Unknown("OBJECT_CYCLE", repr(key)), frozenset({key}))
        if key in self._objects:
            self.reused_objects += 1
            return self._objects[key]
        definition = self.objects.get(key)
        if definition is None:
            result = self.unknown(Unknown("OBJECT_MISSING", repr(key)), frozenset({key}))
        else:
            inner = self._compile(definition.predicate, (*stack, key), depth + 1)
            result = CompiledPredicate(inner.bounds, inner.gaps, frozenset({key}))
            if not definition.complete:
                result = CompiledPredicate(
                    Bounds(self.universe, inner.bounds.lower, self.universe),
                    inner.gaps | {Unknown("OBJECT_INCOMPLETE", repr(key), definition.evidence)},
                    result.dependencies,
                )
        # A result with an OBJECT_CYCLE or a PREDICATE_DEPTH_LIMIT gap depends on
        # the current traversal stack. It is not cached.
        if not any(gap.code in {"OBJECT_CYCLE", "PREDICATE_DEPTH_LIMIT"} for gap in result.gaps):
            self._objects[key] = result
        self.compiled_objects += 1
        return result

    def _atom(self, atom: Atom) -> CompiledPredicate:
        try:
            field = self.manager.schema.canonical_field(atom.field)
        except KeyError:
            return self.unknown(Unknown("UNSUPPORTED_FIELD", atom.field))
        if atom.operation == "eq":
            exact = equals(self.manager, field, atom.value)
        elif atom.operation == "range":
            if atom.other is None:
                raise ValueError("range requires an upper bound")
            exact = value_range(self.manager, field, atom.value, atom.other)
        else:
            if atom.other is None:
                raise ValueError("masked comparison requires a mask")
            exact = masked(self.manager, field, atom.value, atom.other)
        required = {field}
        availability: dict[str, int | list[int]] = {}
        if field in {"source_port", "destination_port", "tcp_flags", "icmp_type", "icmp_code"}:
            required.update(("protocol", "fragment_offset"))
            availability["fragment_offset"] = 0
            if field in {"source_port", "destination_port"}:
                availability["protocol"] = [6, 17, 33, 132]
            elif field == "tcp_flags":
                availability["protocol"] = 6
            else:
                availability["protocol"] = 1 if self.manager.schema.address_family == 4 else 58
        exact = self.universe.intersect(exact.as_predicate()).intersect(
            header(self.manager, availability).as_predicate()
        )
        missing = required - self.known_fields
        if missing:
            # The upper bound is the exact set projected onto the known fields.
            # The lower bound is empty.
            upper = self.universe.intersect(exact.project(self.known_fields).as_predicate())
            gaps = frozenset(Unknown("UNSTATED_DIMENSION", field) for field in missing)
            return CompiledPredicate(Bounds(self.universe, self.manager.empty(), upper), gaps)
        return CompiledPredicate(Bounds(self.universe, exact, exact))
