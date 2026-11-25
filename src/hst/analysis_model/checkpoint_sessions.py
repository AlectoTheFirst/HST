"""Turn collected, unexpired VSX tuple observations into owner-bound sessions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal, cast

from hst.collectors.checkpoint_evidence import Session
from hst.policy.ir import ExecutionContext
from hst.symbolic.session import BindingOwner, FlowTuple, NatBinding, SynchronizationEvidence

from .graph import GraphInventory, GraphNode
from .sessions import SessionCatalog


def catalog_from_graph(
    graph: GraphInventory,
    *,
    estate: str,
    request_id: str,
    choice_scope: tuple[str, ...],
    binding_id: str | None = None,
) -> SessionCatalog:
    """The runtime NAT bindings that the graph's VrfInstances hold, and their
    explicit synchronization to peer contexts of the same firewall instance.

    With `binding_id`, the read is limited to the contexts whose uid is a prefix
    of the binding (a binding is named `<context uid>:<binding uid>`) and, as
    sync peers, the contexts IN_CONTEXT of their firewall instance.
    A peer that this read misses leaves the reply unproven."""
    bindings = []
    sync = []
    if binding_id is None:
        holders = [graph.nodes[uid] for uid in graph.labels.get("VrfInstance", ())]
        contexts = holders
    else:
        holders = _binding_contexts(graph, binding_id)
        contexts = list({node.uid: node for node in holders + _peer_contexts(graph, holders)}.values())
    now = datetime.now(UTC)

    def execution(node, af):
        props = node.props
        return ExecutionContext(
            estate,
            props["authority"],
            props["domain"],
            props["firewall_instance_uid"],
            node.uid,
            cast(Literal[4, 6], af),
        )

    for node in holders:
        payload = node.props.get("vsx_runtime_sessions")
        if not payload:
            continue
        for raw in json.loads(payload):
            item = Session.model_validate(raw)
            if not item.observed_at <= now < item.expires_at or item.protocol not in {"tcp", "udp"}:
                continue
            af = item.original_source.version
            owner = execution(node, af)
            protocol: Literal[6, 17] = 6 if item.protocol == "tcp" else 17
            original = FlowTuple(
                protocol,
                int(item.original_source),
                int(item.original_destination),
                item.original_source_port,
                item.original_destination_port,
            )
            translated = FlowTuple(
                protocol,
                int(item.translated_source),
                int(item.translated_destination),
                item.translated_source_port,
                item.translated_destination_port,
            )
            binding_uid = f"{node.uid}:{item.binding_uid}"
            bindings.append(
                NatBinding(binding_uid, BindingOwner(owner, request_id, choice_scope), original, translated)
            )
            for peer in contexts:
                if peer.uid == node.uid or peer.props.get("firewall_instance_uid") != owner.firewall_instance:
                    continue
                owners = graph.targets(peer.uid, "OWNED_BY")
                if len(owners) == 1 and owners[0].uid in item.synchronized_members:
                    sync.append(
                        SynchronizationEvidence(
                            binding_uid, owner, execution(peer, af), True, item.evidence_uid
                        )
                    )
    # A filtered capture is never a complete dump of the runtime connection table.
    return SessionCatalog(tuple(bindings), tuple(sync), complete=False)


def _binding_contexts(graph: GraphInventory, binding_id: str) -> list[GraphNode]:
    """The VrfInstances whose uid, with a ':' after it, begins `binding_id`."""
    found = []
    for at, char in enumerate(binding_id):
        if char != ":" or at == 0:
            continue
        node = graph.nodes.get(binding_id[:at])
        if node is not None and "VrfInstance" in node.labels:
            found.append(node)
    return found


def _peer_contexts(graph: GraphInventory, owners: list[GraphNode]) -> list[GraphNode]:
    """The VrfInstances IN_CONTEXT of an owner's firewall instance."""
    peers = []
    for instance in {str(node.props.get("firewall_instance_uid")) for node in owners}:
        if instance not in graph.nodes:
            continue
        for relation in graph.incoming.get((instance, "IN_CONTEXT"), ()):
            node = graph.nodes.get(relation.start)
            if node is not None and "VrfInstance" in node.labels:
                peers.append(node)
    return peers
