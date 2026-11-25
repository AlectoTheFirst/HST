"""Preserve collected opaque SD-WAN forwarding boundaries in compiled models."""

from collections.abc import Mapping
from dataclasses import replace

from hst.policy.ir import Unknown
from hst.policy.sdwan import OPAQUE_SELECTION

from .graph import GraphInventory
from .model import EdgeSpec, ModelInput, NodeSpec


def project_sdwan(model: ModelInput, graph: GraphInventory, context_devices: Mapping[str, str]) -> ModelInput:
    """Replace the edges of each routing node of a context whose device has a
    forwarding boundary with one unknown edge.

    The edge has the unknown `OPAQUE_SELECTION` and ends at an unknown
    terminal. The policy of the routing node applies before the boundary.
    """
    boundaries = {
        context: tuple(
            node for node in graph.targets(device, "HAS_BOUNDARY") if "ForwardingBoundary" in node.labels
        )
        for context, device in context_devices.items()
    }
    if not any(boundaries.values()):
        return model
    nodes = []
    for node in model.nodes:
        selected = boundaries.get(node.key.context.vrf, ())
        if not selected or not node.key.location.startswith("routing:"):
            nodes.append(node)
            continue
        terminal = replace(node.key, location=f"sdwan-boundary:{node.key.location}", stage="sdwan-boundary")
        nodes.append(
            replace(
                node,
                terminal=None,
                edges=(
                    EdgeSpec(
                        "sdwan:opaque",
                        terminal,
                        Unknown(OPAQUE_SELECTION, selected[0].uid, tuple(item.uid for item in selected)),
                    ),
                ),
            )
        )
        nodes.append(NodeSpec(terminal, terminal="unknown"))
    return replace(model, nodes=tuple(nodes))
