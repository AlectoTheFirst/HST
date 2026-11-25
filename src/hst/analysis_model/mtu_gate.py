"""Project collected local MTU constraints into the symbolic routing model."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from hst.core.mtu import MtuContext, MtuObservation, MtuStage
from hst.core.mtu_read import resolve_constraints
from hst.impact.evaluate import Interface, MtuRequirement
from hst.path.mtu import evaluate_stage
from hst.path.mtu_feedback import request_for_connection
from hst.policy.ir import Unknown

from .model import EdgeSpec, ModelInput, NodeSpec, StateKey


def project_mtu(
    model: ModelInput,
    requirement: MtuRequirement | None,
    egresses: Mapping[StateKey, Interface],
    *,
    reply: bool = False,
) -> ModelInput:
    """Turn each egress state whose local L3 MTU check fails into a deny terminal.

    The states downstream of a load balancer, a tunnel or a proxy are not
    checked. The packet length of the request does not apply to them. Each
    permit terminal is reached through an edge with the unknown
    `MTU_PATH_COVERAGE_INCOMPLETE`. A deny terminal and a state without a
    route keep their outcome.
    """
    if requirement is None or requirement.mode in {"off", "inventory"}:
        return model
    nodes = {node.key: node for node in model.nodes}
    pending = [
        edge.target
        for node in model.nodes
        if node.key.stage in {"load-balancer", "tunnel", "proxy"}
        for edge in node.edges
        if edge.uid != "load-balancer:fallthrough"
    ]
    changed: set[StateKey] = set()
    while pending:
        key = pending.pop()
        if key in changed:
            continue
        changed.add(key)
        node = nodes.get(key)
        if node is not None:
            pending.extend(edge.target for edge in node.edges)
    # The routing adapter places the egress state before the post-routing NAT,
    # load balancer and tunnel chain. The `mtu` and `snat` states that lead to
    # a load balancer or a tunnel state are added to `changed`.
    predecessors: dict[StateKey, list[StateKey]] = {}
    for node in model.nodes:
        for edge in node.edges:
            predecessors.setdefault(edge.target, []).append(node.key)
    pending = [node.key for node in model.nodes if node.key.stage in {"load-balancer", "tunnel"}]
    upstream: set[StateKey] = set()
    while pending:
        key = pending.pop()
        if key in upstream:
            continue
        upstream.add(key)
        pending.extend(key for key in predecessors.get(key, ()) if key.stage in {"mtu", "snat"})
    changed.update(upstream)
    request, _gaps = request_for_connection(
        requirement.as_request(), direction="reverse" if reply else "forward"
    )
    if request is not None:
        for key, interface in egresses.items():
            if key in changed:
                continue
            context = MtuContext(
                af=key.context.address_family, enforcement="l3", traffic_class=request.traffic_class
            )
            observations = [
                MtuObservation.model_validate_json(raw) for raw in interface.mtu_observations_json
            ]
            resolved = resolve_constraints(observations, context)
            stage = MtuStage(
                stage_id=key.location,
                direction="reverse" if reply else "forward",
                context=context,
                egress_subject_uid=interface.uid,
                enforcement="l3",
                selection="selected",
                constraints=[item for item in resolved.constraints if item.enforcement == "l3"],
            )
            if evaluate_stage(stage, request).outcome == "fail":
                nodes[key] = NodeSpec(key, terminal="deny")
    for node in model.nodes:
        if node.terminal != "permit":
            continue
        terminal = replace(node.key, location=f"mtu-delivery:{node.key.location}")
        nodes[node.key] = replace(
            node,
            terminal=None,
            left_estate=(),
            edges=(
                EdgeSpec(
                    "mtu:path-coverage",
                    terminal,
                    Unknown("MTU_PATH_COVERAGE_INCOMPLETE", node.key.location),
                ),
            ),
        )
        nodes[terminal] = NodeSpec(terminal, terminal="permit", left_estate=node.left_estate)
    return replace(model, nodes=tuple(nodes.values()))
