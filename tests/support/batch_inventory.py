"""A collector batch as the GraphInventory the analysis child loads.

`inventory(batch)` merges each node's rows the way the loader's
`SET n += row.props` does and adds the bookkeeping the loader writes on every
node (`uid`, `collection_ts`, `collected_at`, `carried`), so a policy built
from it sees the same rule properties a published snapshot holds.
"""

from __future__ import annotations

from collections import defaultdict
from types import MappingProxyType
from typing import Any

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.core.model import Batch

CTS = 4000


def inventory(batch: Batch, *, loaded: bool = True) -> GraphInventory:
    """The batch's nodes and relationships as one GraphInventory. `loaded`
    adds the loader's bookkeeping properties to every node."""
    props: dict[str, dict[str, Any]] = {}
    labels: dict[str, set[str]] = defaultdict(set)
    for node in batch.nodes:
        entry = props.setdefault(node.uid, {"uid": node.uid})
        entry.update({key: value for key, value in node.props.items() if value is not None})
        labels[node.uid].add(node.label)
    if loaded:
        for entry in props.values():
            entry.update({"collection_ts": CTS, "collected_at": CTS, "carried": False})
    catalog = {
        uid: GraphNode(uid, frozenset(labels[uid]), MappingProxyType(entry)) for uid, entry in props.items()
    }
    outgoing: dict[tuple[str, str], list[GraphRelation]] = defaultdict(list)
    incoming: dict[tuple[str, str], list[GraphRelation]] = defaultdict(list)
    seen: set[tuple[str, str, str, tuple[tuple[str, Any], ...]]] = set()
    for rel in batch.rels:
        key = (rel.rel_type, rel.start_uid, rel.end_uid, tuple(sorted(rel.key.items())))
        if key in seen:
            continue
        seen.add(key)
        relation = GraphRelation(
            f"{rel.start_uid}>{rel.rel_type}>{rel.end_uid}>{len(seen)}",
            rel.rel_type,
            rel.start_uid,
            rel.end_uid,
            MappingProxyType({**rel.key, **{k: v for k, v in rel.props.items() if v is not None}}),
        )
        outgoing[rel.start_uid, rel.rel_type].append(relation)
        incoming[rel.end_uid, rel.rel_type].append(relation)
    by_label: dict[str, list[str]] = defaultdict(list)
    for uid, node in catalog.items():
        for label in node.labels:
            by_label[label].append(uid)
    return GraphInventory(
        "a" * 64,
        "batch",
        MappingProxyType(catalog),
        MappingProxyType({key: tuple(sorted(value)) for key, value in by_label.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )
