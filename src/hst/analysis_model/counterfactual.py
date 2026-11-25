"""Project typed counterfactual network wrappers into immutable native inputs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import Any

from hst.assessment.semantic import digest
from hst.impact.evaluate import Network
from hst.simul.fw_overlay import ProposalError

from .catalogs import _bindings, _envelope, _fingerprint
from .graph import GraphInventory, GraphNode, GraphRelation
from .model import ModelInput, NodeSpec
from .overlay import _node, _rebuild


def graph_for_counterfactual(
    graph: GraphInventory, network: Network, *, apply_policy_edits: bool = True
) -> GraphInventory:
    """Apply the failure facts of a counterfactual Network to its graph."""
    gates: Any = network.gates
    devices: set[str] = set()
    interfaces: set[str] = set()
    tunnels: set[str] = set()
    addresses: set[str] = set()
    while gates is not None:
        devices.update(getattr(gates, "devices", ()))
        interfaces.update(getattr(gates, "interfaces", ()))
        tunnels.update(getattr(gates, "failed_tunnels", ()))
        addresses.update(getattr(gates, "addresses", ()))
        gates = getattr(gates, "inner", None)
    edits = _policy_edits(network) if apply_policy_edits else ()
    if not (devices or interfaces or tunnels or addresses or edits):
        return graph
    nodes = dict(graph.nodes)
    for uid, node in tuple(nodes.items()):
        failed = uid in devices or uid in interfaces or uid in tunnels
        if "ZpaAppConnector" in node.labels:
            hosts = graph.targets(uid, "RUNS_ON")
            connector_addresses = {
                str(address.props.get("ip"))
                for host in hosts
                for interface in graph.sources(host.uid, "OF")
                for address in graph.targets(interface.uid, "HAS_IP")
                if address.props.get("ip") is not None
            }
            failed |= any(host.uid in devices for host in hosts)
            failed |= bool(connector_addresses) and connector_addresses <= addresses
        if failed:
            props = {**node.props, "state": "down", "health": "down", "counterfactual_failed": True}
            nodes[uid] = GraphNode(uid, node.labels, MappingProxyType(props))
    relations = list({item.uid: item for rows in graph.outgoing.values() for item in rows}.values())
    for edit_group, direction in edits:
        _apply_policy_edits(nodes, relations, edit_group, direction)
    return _rebuild(graph, nodes, relations)


def apply_policy_counterfactual(graph: GraphInventory, change: Any) -> GraphInventory:
    """Apply one observed policy change at its exact place in overlay chronology."""
    edits = getattr(change, "edits", None)
    direction = getattr(change, "direction", None)
    if edits is None or direction is None:
        raise ProposalError("counterfactual policy change is malformed")
    nodes = dict(graph.nodes)
    relations = list({item.uid: item for rows in graph.outgoing.values() for item in rows}.values())
    _apply_policy_edits(nodes, relations, list(edits), str(direction))
    return _rebuild(graph, nodes, relations)


def project_counterfactual(source: ModelInput, network: Network) -> ModelInput:
    """Fail closed compiled states owned by failed devices or ingress interfaces."""
    gates: Any = network.gates
    devices: set[str] = set()
    interfaces: set[str] = set()
    while gates is not None:
        devices.update(getattr(gates, "devices", ()))
        interfaces.update(getattr(gates, "interfaces", ()))
        gates = getattr(gates, "inner", None)
    if not devices and not interfaces:
        return source
    failed_contexts = {
        str(row["uid"]) for row in network.routing.contexts if str(row.get("device_uid") or "") in devices
    }

    def failed(node: NodeSpec) -> bool:
        if node.key.context.vrf in failed_contexts:
            return True
        scopes = {
            value.removeprefix("ingress:").removeprefix("reply-ingress:") for value in node.key.binding_scope
        }
        return bool(scopes & interfaces)

    nodes = tuple(
        (
            replace(node, edges=(), terminal="deny", policy=None, complete=True, left_estate=())
            if failed(node)
            else node
        )
        for node in source.nodes
    )
    return replace(source, nodes=nodes)


def _policy_edits(network: Network) -> tuple[tuple[list[Any], str], ...]:
    result: list[tuple[list[Any], str]] = []
    session = getattr(network.gates, "session", None)
    while session is not None:
        changes = getattr(session, "_changes", None)
        edits = getattr(changes, "edits", None)
        direction = getattr(changes, "direction", None)
        if edits is not None and direction is not None:
            result.append((list(edits), str(direction)))
        session = getattr(session, "_session", None)
    changes = getattr(network, "changes", None)
    edits = getattr(changes, "edits", None)
    direction = getattr(changes, "direction", None)
    if (
        edits is not None
        and direction is not None
        and not any(changes is getattr(item, "_changes", None) for item in _sessions(network))
    ):
        result.append((list(edits), str(direction)))
    return tuple(reversed(result))


def _sessions(network: Network) -> tuple[Any, ...]:
    result = []
    session = getattr(network.gates, "session", None)
    while session is not None:
        result.append(session)
        session = getattr(session, "_session", None)
    return tuple(result)


def _apply_policy_edits(
    nodes: dict[str, GraphNode],
    relations: list[GraphRelation],
    edits: list[Any],
    direction: str,
) -> None:
    if direction not in {"forward", "reverse"}:
        raise ProposalError("policy edit direction is invalid")
    for raw_edit in edits:
        edit = dict(raw_edit)
        family = str(edit.get("family") or "")
        if family not in {"firewall", "nat"}:
            continue
        selector = edit.get("selector")
        if not isinstance(selector, (tuple, list)) or len(selector) != 2:
            raise ProposalError("policy edit selector is malformed")
        target, uid = map(str, selector)
        current_rows = edit["before"] if direction == "forward" else edit["after"]
        replacement = edit["after"] if direction == "forward" else edit["before"]
        if digest(current_rows) != edit.get("preconditions", {}).get(direction):
            raise ProposalError(f"policy edit precondition failed for {target}/{uid}")
        current = nodes.get(uid)
        if bool(current_rows) != (current is not None):
            raise ProposalError(f"policy graph precondition failed for {target}/{uid}")
        if current is not None and current_rows:
            expected = current_rows[0]
            rulebase_uid = str(expected.get("graph_rulebase_uid") or expected.get("rb_uid") or target)
            bindings = _bindings(_inventory(nodes, relations), rulebase_uid)
            actual = _envelope(_inventory(nodes, relations), rulebase_uid, current, bindings, {}, {})
            if (
                str(expected.get("uid")) != uid
                or expected.get("graph_semantic_fingerprint") != _fingerprint(actual)
                or not any(
                    item.kind == "HAS_RULE" and item.start == rulebase_uid and item.end == uid
                    for item in relations
                )
                or (family == "nat" and target not in {device for device, _item in bindings})
            ):
                raise ProposalError(f"policy graph precondition failed for {target}/{uid}")
        nodes.pop(uid, None)
        relations[:] = [item for item in relations if item.start != uid and item.end != uid]
        if not replacement:
            continue
        if len(replacement) != 1 or str(replacement[0].get("uid")) != uid:
            raise ProposalError("one policy edit must replace at most one stable rule identity")
        row = dict(replacement[0])
        envelope = row.get("graph_envelope")
        if not isinstance(envelope, Mapping) or row.get("graph_semantic_fingerprint") != _fingerprint(
            envelope
        ):
            raise ProposalError("policy replacement lacks a valid native graph envelope")
        bundles = edit.get("graph_object_bundles")
        if not isinstance(bundles, Mapping):
            raise ProposalError("policy replacement lacks its object bundle registry")
        _restore_envelope(nodes, relations, dict(envelope), family, bundles)


def _inventory(nodes: dict[str, GraphNode], relations: list[GraphRelation]) -> GraphInventory:
    seed = GraphInventory("0" * 64, "0" * 64, {}, {}, {}, {}, True, (), 0)
    return _rebuild(seed, nodes, relations)


def _restore_envelope(
    nodes: dict[str, GraphNode],
    relations: list[GraphRelation],
    envelope: dict[str, Any],
    family: str,
    bundles: Mapping[str, Any],
) -> None:
    rule_uid = str(envelope["rule_uid"])
    nodes[rule_uid] = _node(
        rule_uid,
        frozenset({"NatRule" if family == "nat" else "FwRule"}),
        dict(envelope["rule_props"]),
    )
    object_relations: list[Any] = []
    for bundle_id in envelope.get("object_bundle_ids", ()):
        bundle = bundles.get(str(bundle_id))
        if not isinstance(bundle, Mapping) or _fingerprint(bundle) != bundle_id:
            raise ProposalError(f"policy object bundle {bundle_id} is absent or corrupt")
        for uid, record in bundle.get("nodes", {}).items():
            object_node = _node(str(uid), frozenset(record["labels"]), dict(record["props"]))
            if uid in nodes and nodes[uid] != object_node:
                raise ProposalError(f"shared policy object {uid} changed outside the edited rule")
            nodes[str(uid)] = object_node
        object_relations.extend(bundle.get("relations", {}).values())
    records = [
        *envelope.get("has_rule", ()),
        *envelope.get("rule_relations", ()),
        *object_relations,
    ]
    existing = {item.uid: item for item in relations}
    for binding in envelope.get("bindings", ()):
        record = binding["relation"]
        actual = existing.get(str(record["uid"]))
        if (
            actual is None
            or actual.start != str(record["start"])
            or actual.end != str(record["end"])
            or dict(actual.props) != dict(record.get("props") or {})
        ):
            raise ProposalError("policy installation binding differs from the captured envelope")
    for record in records:
        candidate_relation = GraphRelation(
            str(record["uid"]),
            str(record["kind"]),
            str(record["start"]),
            str(record["end"]),
            MappingProxyType(dict(record.get("props") or {})),
        )
        if candidate_relation.uid in existing and existing[candidate_relation.uid] != candidate_relation:
            raise ProposalError(f"policy relation {candidate_relation.uid} changed outside the edited rule")
        if candidate_relation.uid not in existing:
            relations.append(candidate_relation)
