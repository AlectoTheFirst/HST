"""Routing dependency components and prefix/context invalidation certificates."""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from . import certainty

if TYPE_CHECKING:
    from .rib import RibInput


@dataclass(frozen=True, order=True)
class PrefixPredicate:
    context_uid: str
    prefix: str
    address_family: int | None = None

    def as_dict(self) -> dict[str, str | int]:
        value: dict[str, str | int] = {
            "context_uid": self.context_uid,
            "prefix": self.prefix,
        }
        family = self.address_family
        if family is None:
            try:
                family = ipaddress.ip_network(self.prefix, strict=False).version
            except ValueError:
                family = None
        if family is not None:
            value["address_family"] = family
        return value


@dataclass(frozen=True)
class DependencyCertificate:
    roots: tuple[PrefixPredicate, ...]
    affected: tuple[PrefixPredicate, ...]
    downstream_contexts: tuple[str, ...]
    components: tuple[tuple[str, ...], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "roots": [item.as_dict() for item in self.roots],
            "affected_prefixes": [item.as_dict() for item in self.affected],
            "downstream_contexts": list(self.downstream_contexts),
            "components": [list(component) for component in self.components],
        }


@dataclass(frozen=True)
class RoutingWorklist:
    """The exact routing components an incremental calculation must visit.

    An island holds the unchanged producers of every consumer it recomputes.
    """

    dirty: tuple[PrefixPredicate, ...]
    affected: tuple[PrefixPredicate, ...]
    components: tuple[tuple[str, ...], ...]
    reused_components: tuple[tuple[str, ...], ...]
    complete: bool
    reason: str = ""

    @property
    def counters(self) -> dict[str, int]:
        return {
            "dirty_keys": len(self.dirty),
            "affected_keys": len(self.affected),
            "components_recomputed": len(self.components),
            "components_reused": len(self.reused_components),
            "dependency_fallback": int(not self.complete),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "dirty_keys": [item.as_dict() for item in self.dirty],
            "affected_keys": [item.as_dict() for item in self.affected],
            "components": [list(item) for item in self.components],
            "reused_components": [list(item) for item in self.reused_components],
            "complete": self.complete,
            "reason": self.reason,
            "counters": self.counters,
        }


class RoutingDependencies:
    """Semantic context and prefix dependencies, including unselected inputs."""

    def __init__(self, inp: RibInput) -> None:
        self.inp = inp
        self.context_edges = {key: set(value) for key, value in certainty.dependencies(inp).items()}
        self.contexts = {str(item["uid"]) for item in inp.contexts}
        self.prefixes: dict[str, set[PrefixPredicate]] = defaultdict(set)
        rows: list[Mapping[str, Any]] = [*inp.connected, *inp.static, *inp.observed_paths]
        if inp.bgp is not None:
            rows.extend((*inp.bgp.seeds, *inp.bgp.local_routes))
            process_context = certainty.process_contexts(inp)
            rows.extend(
                {**row, "context_uid": process_context.get(str(row.get("process_uid")), "")}
                for row in (*inp.bgp.seeds, *inp.bgp.local_routes)
            )
        for context_uid, observed in inp.observed_rib.items():
            rows.extend({**row, "context_uid": context_uid} for row in observed)
        for row in rows:
            context_uid, prefix = str(row.get("context_uid") or ""), str(row.get("prefix") or "")
            if context_uid and prefix:
                self.prefixes[context_uid].add(PrefixPredicate(context_uid, prefix))
        self.components = self._components()
        self.execution_components = self._execution_components()

    def _components(self) -> tuple[tuple[str, ...], ...]:
        """Returns the strongly connected components of the context graph by Tarjan's algorithm.

        A context outside every cycle is a component of its own.
        """
        graph = {context: set(self.context_edges.get(context, ())) for context in self.contexts}
        for targets in self.context_edges.values():
            for context in targets:
                graph.setdefault(context, set())
        index = 0
        indexes: dict[str, int] = {}
        low: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        out: list[tuple[str, ...]] = []

        # An explicit work stack does not hit the recursion limit.
        for root in sorted(graph):
            if root in indexes:
                continue
            indexes[root] = low[root] = index
            index += 1
            stack.append(root)
            on_stack.add(root)
            work = [(root, iter(sorted(graph[root])))]
            while work:
                node, pending = work[-1]
                descended = False
                for target in pending:
                    if target not in indexes:
                        indexes[target] = low[target] = index
                        index += 1
                        stack.append(target)
                        on_stack.add(target)
                        work.append((target, iter(sorted(graph[target]))))
                        descended = True
                        break
                    if target in on_stack:
                        low[node] = min(low[node], indexes[target])
                if descended:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == indexes[node]:
                    component: list[str] = []
                    while True:
                        target = stack.pop()
                        on_stack.remove(target)
                        component.append(target)
                        if target == node:
                            break
                    out.append(tuple(sorted(component)))
        return tuple(sorted(out))

    def _execution_components(self) -> tuple[tuple[str, ...], ...]:
        """Undirected islands which can be executed independently.

        Each island holds both ends of every producer-to-consumer relation.
        """
        graph: dict[str, set[str]] = {context: set() for context in self.contexts}
        for source, targets in self.context_edges.items():
            graph.setdefault(source, set())
            for target in targets:
                graph.setdefault(target, set())
                graph[source].add(target)
                graph[target].add(source)
        out: list[tuple[str, ...]] = []
        remaining = set(graph)
        while remaining:
            start = min(remaining)
            found = {start}
            todo = deque([start])
            remaining.remove(start)
            while todo:
                for target in sorted(graph[todo.popleft()]):
                    if target not in found:
                        found.add(target)
                        remaining.discard(target)
                        todo.append(target)
            out.append(tuple(sorted(found)))
        return tuple(sorted(out))

    def closure(self, roots: Iterable[str]) -> frozenset[str]:
        found = {str(root) for root in roots}
        todo = deque(sorted(found))
        while todo:
            for consumer in sorted(self.context_edges.get(todo.popleft(), ())):
                if consumer not in found:
                    found.add(consumer)
                    todo.append(consumer)
        return frozenset(found)

    def certificate(self, roots: Iterable[PrefixPredicate]) -> DependencyCertificate:
        root_set = tuple(sorted(set(roots)))
        downstream = self.closure(item.context_uid for item in root_set)
        affected = tuple(
            predicate
            for context_uid in sorted(downstream)
            for predicate in sorted(self.prefixes.get(context_uid, ()))
        )
        components = tuple(component for component in self.components if set(component) & set(downstream))
        return DependencyCertificate(root_set, affected, tuple(sorted(downstream)), components)

    def worklist(
        self,
        roots: Iterable[PrefixPredicate],
        *,
        complete: bool = True,
    ) -> RoutingWorklist:
        """The dirty-component worklist.

        An unknown context or an incomplete dependency index recalculates every
        execution component. A missing prefix in a known context uses the
        context-level dependency.
        """
        dirty = tuple(sorted(set(roots)))
        unknown_contexts = sorted({item.context_uid for item in dirty} - self.contexts)
        if not complete or unknown_contexts:
            reason = "DEPENDENCY_INDEX_INCOMPLETE" if not complete else "UNKNOWN_ROUTING_CONTEXT"
            affected = tuple(
                predicate
                for context_uid in sorted(self.contexts)
                for predicate in sorted(self.prefixes.get(context_uid, ()))
            )
            return RoutingWorklist(dirty, affected, self.execution_components, (), False, reason)

        certificate = self.certificate(dirty)
        affected_contexts = set(certificate.downstream_contexts)
        components = tuple(
            component for component in self.execution_components if set(component) & affected_contexts
        )
        selected = set(components)
        reused = tuple(component for component in self.execution_components if component not in selected)
        return RoutingWorklist(dirty, certificate.affected, components, reused, True)
