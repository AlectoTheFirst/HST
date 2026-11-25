"""Rebuild strict Check Point policy IR from immutable graph envelopes."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from hst.core import uid as uidmod
from hst.policy.checkpoint import normalize_checkpoint_policy
from hst.policy.ir import ExecutionContext, Layer, Policy, Predicate, Rule, Unknown
from hst.policy.profiles import CheckpointProfile

from .graph import GraphInventory, GraphNode


def checkpoint_scope(graph: GraphInventory, rulebase_uid: str) -> tuple[str, str] | None:
    """Return the single authoritative management/domain scope for a rulebase."""
    packages = graph.sources(rulebase_uid, "HAS_LAYER")
    if len(packages) != 1:
        return None
    authority = packages[0].props.get("authority_uid")
    domain = packages[0].props.get("domain_uid")
    if not isinstance(authority, str) or not authority or not isinstance(domain, str) or not domain:
        return None
    return authority, domain


def checkpoint_policy(
    graph: GraphInventory,
    rulebase_uids: Sequence[str],
    context: ExecutionContext,
    installation: Predicate,
) -> Policy | None:
    """Return strict vendor policy when one qualified package owns the bindings."""
    selected = set(rulebase_uids)
    if not selected or any(
        uid not in graph.nodes or graph.nodes[uid].props.get("vendor") != "checkpoint" for uid in selected
    ):
        return None
    packages = {
        relation.start
        for rulebase_uid in selected
        for relation in graph.incoming.get((rulebase_uid, "HAS_LAYER"), ())
        if relation.start in graph.nodes
    }
    if len(packages) != 1:
        return None
    package_node = graph.nodes[next(iter(packages))]
    try:
        package = _envelope(package_node)
    except (TypeError, ValueError):
        return None
    releases = (
        package_node.props.get("management_release"),
        package_node.props.get("gateway_release"),
        package_node.props.get("api_version"),
    )
    try:
        profile = CheckpointProfile(*(str(value or "") for value in releases))
    except ValueError:
        return None

    authority = package_node.props.get("authority_uid")
    domain = package_node.props.get("domain_uid")
    if not isinstance(authority, str) or not authority or not isinstance(domain, str) or not domain:
        return None
    prefix = uidmod.checkpoint(authority, domain, "")

    layers: dict[str, Mapping[str, Any]] = {}
    rulebases: dict[str, list[Mapping[str, Any]]] = {}
    referenced_objects: set[str] = set()
    pending = [str(_raw_uid(item)) for item in package.get("access-layers", ())]
    seen: set[str] = set()
    try:
        by_raw_uid = _scoped_envelopes(graph, "FwRulebase", prefix)
    except (TypeError, ValueError):
        return None
    while pending:
        layer_uid = pending.pop()
        if not layer_uid or layer_uid in seen or layer_uid not in by_raw_uid:
            continue
        seen.add(layer_uid)
        layer_node = by_raw_uid[layer_uid]
        layers[layer_uid] = _envelope(layer_node)
        rules = sorted(
            graph.targets(layer_node.uid, "HAS_RULE"),
            key=lambda node: (node.props.get("position") is None, node.props.get("position"), node.uid),
        )
        raw_rules = [_envelope(rule) for rule in rules]
        pending_objects = [
            target.uid
            for rule in rules
            for relation in ("SRC", "DST", "SVC")
            for target in graph.targets(rule.uid, relation)
        ]
        while pending_objects:
            object_uid = pending_objects.pop()
            if object_uid in referenced_objects:
                continue
            referenced_objects.add(object_uid)
            pending_objects.extend(node.uid for node in graph.sources(object_uid, "MEMBER_OF"))
        rulebases[layer_uid] = raw_rules
        pending.extend(
            str(inline) for rule in raw_rules if (inline := _raw_uid(rule.get("inline-layer"))) is not None
        )

    try:
        object_nodes: dict[str, GraphNode] = {}
        for label in ("NetObject", "SvcObject", "CpPolicyObject"):
            for raw_uid, node in _scoped_envelopes(graph, label, prefix).items():
                if raw_uid in object_nodes:
                    raise ValueError("ambiguous Check Point policy object identity")
                object_nodes[raw_uid] = node
        for node_uid in referenced_objects:
            node = graph.nodes[node_uid]
            ref_raw_uid = _raw_uid(_envelope(node))
            if ref_raw_uid is None or (
                ref_raw_uid in object_nodes and object_nodes[ref_raw_uid].uid != node_uid
            ):
                raise ValueError("ambiguous Check Point referenced object identity")
            object_nodes[ref_raw_uid] = node
    except (TypeError, ValueError):
        return None
    objects = [_envelope(node) for node in object_nodes.values()]
    targets: dict[str, tuple[str, ...]] = {}
    for node in graph.nodes_carrying("cp_uid"):
        cp_uid = node.props.get("cp_uid")
        target_raw_uid = node.props.get("cp_raw_uid")
        if not isinstance(cp_uid, str) or not cp_uid.startswith(prefix):
            continue
        if not isinstance(target_raw_uid, str) or not target_raw_uid or target_raw_uid in targets:
            return None
        targets[target_raw_uid] = (node.uid,)
    # The install-on column is read the way the path gate reads it
    # (gates/firewall.py `_installed_rules`). The context of a virtual system
    # is the FirewallInstance that the Gaia source writes. It is joined to
    # the Device of the virtual system by its management object uid and
    # management scope. A rule installed on that virtual system is installed
    # in its context too. Policy Targets means every target of the package.
    # It maps to this firewall instance, to which the package is bound.
    for node_uid in graph.labels.get("FirewallInstance", ()):
        instance = graph.nodes[node_uid]
        target_raw_uid = instance.props.get("gateway_object_uid")
        bound = targets.get(target_raw_uid) if isinstance(target_raw_uid, str) else None
        authority = instance.props.get("authority")
        # An absent authority or scope joins nothing. Cypher's `null = null`
        # joins nothing in the VSX branch of the path gate.
        if bound and isinstance(authority, str) and authority == graph.nodes[bound[0]].props.get("_scope"):
            targets[str(target_raw_uid)] = (*bound, instance.uid)
    for raw_uid, node in object_nodes.items():
        if _envelope(node).get("name") == "Policy Targets" and raw_uid not in targets:
            targets[raw_uid] = (context.firewall_instance,)
    try:
        normalized = normalize_checkpoint_policy(
            profile=profile,
            context=context,
            manifest_digest=graph.manifest_digest,
            package=package,
            layers=layers,
            rulebases=rulebases,
            objects=objects,
            installation=installation,
            target_bindings=targets,
            capture_complete=package_node.props.get("capture_complete") is True,
            implied_complete=package_node.props.get("implied_complete") is True,
        )
    except (TypeError, ValueError):
        return None
    return normalized.policy


def checkpoint_bound(graph: GraphInventory, rulebase_uids: Sequence[str]) -> bool:
    """Return whether every selected rulebase declares Check Point semantics."""
    return bool(rulebase_uids) and all(
        uid in graph.nodes and graph.nodes[uid].props.get("vendor") == "checkpoint" for uid in rulebase_uids
    )


def unknown_checkpoint_policy(
    graph: GraphInventory,
    context: ExecutionContext,
    installation: Predicate,
    *,
    reason: str = "CHECKPOINT_CAPTURE_UNQUALIFIED",
) -> Policy:
    """Fail closed when a Check Point capture cannot be qualified or decoded."""
    layer_uid = "checkpoint-unqualified"
    return Policy(
        uid="checkpoint-unqualified",
        revision=graph.fingerprint,
        context=context,
        layers=(
            Layer(
                layer_uid,
                (
                    Rule(
                        "checkpoint-unqualified",
                        Unknown(reason, context.domain),
                        "unknown",
                    ),
                ),
                "unknown",
            ),
        ),
        ordered_layers=(layer_uid,),
        installation=installation,
        manifest_digest=graph.manifest_digest,
    )


def _raw_uid(value: Any) -> str | None:
    result = value.get("uid") if isinstance(value, Mapping) else value
    return result if isinstance(result, str) and result else None


def _envelope(node: GraphNode) -> Mapping[str, Any]:
    raw = node.props.get("checkpoint_envelope")
    if not isinstance(raw, str):
        raise ValueError(f"{node.uid} lacks a Check Point policy envelope")
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError(f"{node.uid} has a malformed Check Point policy envelope")
    return decoded


def _scoped_envelopes(graph: GraphInventory, label: str, prefix: str) -> dict[str, GraphNode]:
    result: dict[str, GraphNode] = {}
    for node_uid in graph.labels.get(label, ()):
        node = graph.nodes[node_uid]
        if not node.uid.startswith(prefix):
            continue
        if label == "FwRulebase" and node.props.get("kind") == "nat":
            # The NAT rulebase of a package is not an access layer and has no
            # envelope. The NAT stages read it (`policy.nat`).
            continue
        raw_uid = _raw_uid(_envelope(node))
        if raw_uid is None or raw_uid in result:
            raise ValueError(f"ambiguous Check Point {label} identity")
        result[raw_uid] = node
    return result
