"""The routing dependency graph is walked without recursion: a chain or
a full mesh of more contexts than the interpreter's recursion limit must not
raise RecursionError before any route is computed."""

from __future__ import annotations

import random
import sys

from hst.simul import rib
from hst.simul.dependencies import RoutingDependencies


def _contexts(count):
    return [
        {"uid": f"vrf:pe{i}:blue", "device_uid": f"dev:pe{i}", "name": "blue", "platform": "iosxe"}
        for i in range(count)
    ]


def _chain_input(count):
    """PE i+1 imports what PE i exports, so the dependency chain is `count` deep."""
    return rib.RibInput(
        contexts=_contexts(count),
        connected=[
            {"context_uid": f"vrf:pe{i}:blue", "prefix": f"10.{i // 250}.{i % 250}.0/24", "interface": "Gi1"}
            for i in range(count)
        ],
        rt_pairs=[
            {"importer": f"vrf:pe{i + 1}:blue", "exporter": f"vrf:pe{i}:blue"} for i in range(count - 1)
        ],
    )


def test_a_chain_deeper_than_the_recursion_limit_builds_its_components():
    count = 5000
    assert count > 4 * sys.getrecursionlimit()
    dependencies = RoutingDependencies(_chain_input(count))
    assert len(dependencies.components) == count
    assert all(len(component) == 1 for component in dependencies.components)


def test_a_ring_deeper_than_the_recursion_limit_is_one_component():
    count = 5000
    inp = _chain_input(count)
    inp.rt_pairs.append({"importer": "vrf:pe0:blue", "exporter": f"vrf:pe{count - 1}:blue"})
    dependencies = RoutingDependencies(inp)
    assert [len(component) for component in dependencies.components] == [count]


def test_the_components_match_a_recursive_reference_on_random_graphs():
    def reference(graph):
        index, indexes, low, stack, on_stack, out = 0, {}, {}, [], set(), []

        def visit(node):
            nonlocal index
            indexes[node] = low[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)
            for target in sorted(graph[node]):
                if target not in indexes:
                    visit(target)
                    low[node] = min(low[node], low[target])
                elif target in on_stack:
                    low[node] = min(low[node], indexes[target])
            if low[node] == indexes[node]:
                component = []
                while True:
                    target = stack.pop()
                    on_stack.remove(target)
                    component.append(target)
                    if target == node:
                        break
                out.append(tuple(sorted(component)))

        for node in sorted(graph):
            if node not in indexes:
                visit(node)
        return tuple(sorted(out))

    rng = random.Random(7)
    for _ in range(60):
        count = rng.randint(2, 25)
        inp = rib.RibInput(contexts=_contexts(count))
        uids = [c["uid"] for c in inp.contexts]
        inp.rt_pairs = [
            {"importer": rng.choice(uids), "exporter": rng.choice(uids)}
            for _ in range(rng.randint(0, 3 * count))
        ]
        dependencies = RoutingDependencies(inp)
        graph = {
            context: set(dependencies.context_edges.get(context, ())) for context in dependencies.contexts
        }
        for targets in dependencies.context_edges.values():
            for context in targets:
                graph.setdefault(context, set())
        assert dependencies.components == reference(graph)


def test_a_route_target_chain_deeper_than_the_recursion_limit_computes():
    count = 1200
    assert count > sys.getrecursionlimit()
    result = rib.compute(_chain_input(count))
    assert result.model_errors == []
    assert any(row["context_uid"] == f"vrf:pe{count - 1}:blue" for row in result.rib)
