"""Bounded traversal of explicit member-local VSX forwarding edges."""

from __future__ import annotations

from collections import deque

from .graph import GraphInventory


def resolve(graph: GraphInventory, start: str, next_hop: str | None):
    queue: deque[tuple[str, tuple[str, ...], tuple[tuple[str, str], ...], bool]] = deque(
        [(start, (start,), (), False)]
    )
    candidates = {}
    explored = 0
    inactive = False
    while queue:
        current, visited, crossings, explicit = queue.popleft()
        explored += 1
        if explored > 2048:
            return None, (), "VSX_TRANSIT_BUDGET"
        node = graph.nodes.get(current)
        if node is None:
            continue
        if node.props.get("vsx_cluster") and node.props.get("vsx_state") != "active":
            inactive = True
            continue
        tags = {
            v.props.get("vid")
            for visited_uid in visited
            for v in graph.targets(visited_uid, "BOUND_TO")
            if v.props.get("vid") is not None
        }
        if len(tags) > 1:
            continue
        kind = node.props.get("vsx_kind")
        if current != start and "Interface" in node.labels and kind not in {"bridge", "virtual-switch"}:
            if (
                explicit
                and kind != "management"
                and (
                    next_hop is None
                    or any(ip.props.get("ip") == next_hop for ip in graph.targets(current, "HAS_IP"))
                )
            ):
                contexts = graph.targets(current, "IN_VRF")
                if len(contexts) == 1:
                    candidates[current, crossings] = (current, contexts[0].uid)
            continue
        if len(visited) > 16:
            return None, (), "VSX_TRANSIT_DEPTH"
        for relation_kind in ("CONNECTED_TO", "BRIDGED_TO", "REALIZED_BY"):
            links = (
                *graph.outgoing.get((current, relation_kind), ()),
                *graph.incoming.get((current, relation_kind), ()),
            )
            for link in links:
                target = link.end if link.start == current else link.start
                if target in visited:
                    continue
                crossing = ((current, target),) if relation_kind == "BRIDGED_TO" else ()
                queue.append(
                    (
                        target,
                        (*visited, target),
                        (*crossings, *crossing),
                        explicit or link.props.get("source") in {"vsx-bridge", "vsx-warp"},
                    )
                )
    if len(candidates) == 1:
        (_, crossings), selected = next(iter(candidates.items()))
        return selected, crossings, None
    if candidates:
        return None, (), "VSX_TRANSIT_AMBIGUOUS"
    if inactive:
        return None, (), "VSX_ACTIVE_CONTEXT_UNKNOWN"
    node = graph.nodes.get(start)
    return None, (), "VSX_WARP_PEER_UNKNOWN" if node and node.props.get("kind") == "warp" else None
