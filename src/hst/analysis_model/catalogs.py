"""Policy-edit catalogs projected from one immutable graph inventory."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .graph import GraphInventory, GraphNode, GraphRelation


@dataclass(frozen=True, slots=True)
class CatalogProjection:
    catalogs: Mapping[str, Mapping[str, tuple[Mapping[str, Any], ...]]]
    complete_firewall: frozenset[str]
    complete_nat: frozenset[str]
    complete_contexts: frozenset[str]
    graph_fingerprint: str
    object_bundles: Mapping[str, Mapping[str, Any]]
    bindings: Mapping[str, tuple[Mapping[str, Any], ...]]

    def model_catalogs(self) -> tuple[dict[str, Any], set[str], set[str], set[str]]:
        return (
            {
                family: {target: [_materialize(row) for row in rows] for target, rows in values.items()}
                for family, values in self.catalogs.items()
            }
            | {
                "graph_object_bundles": {
                    bundle: _plain(payload) for bundle, payload in self.object_bundles.items()
                },
                "graph_fingerprint": self.graph_fingerprint,
                "graph_bindings": {
                    rulebase: [_plain(item) for item in values] for rulebase, values in self.bindings.items()
                },
            },
            set(self.complete_firewall),
            set(self.complete_nat),
            set(self.complete_contexts),
        )


def project_catalogs(
    graph: GraphInventory,
    *,
    manifest: Any | None,
    device_uids: Iterable[str] = (),
    context_owners: Mapping[str, str] | None = None,
) -> CatalogProjection:
    """Project firewall/NAT edit rows without database reads or object expansion.

    ``manifest`` is the pinned manifest.  A catalog is reversible only when
    each installed binding has a complete matching device observation.  A
    configured package target or an approximate binding does not qualify.
    """
    requested = set(device_uids)
    context_owners = context_owners or {}
    device_records = _device_records(manifest)
    firewall: dict[str, tuple[Mapping[str, Any], ...]] = {}
    nat: dict[str, list[Mapping[str, Any]]] = {device: [] for device in requested}
    complete_fw: set[str] = set()
    complete_nat: set[str] = set()
    bundle_cache: dict[str, str] = {}
    object_bundles: dict[str, Mapping[str, Any]] = {}
    binding_map: dict[str, tuple[Mapping[str, Any], ...]] = {}

    for rulebase_uid in sorted(graph.labels.get("FwRulebase", ())):
        rulebase = graph.nodes.get(rulebase_uid)
        if rulebase is None:
            continue
        kind = str(rulebase.props.get("kind") or "access").lower()
        bindings = _bindings(graph, rulebase_uid)
        binding_map[rulebase_uid] = tuple(
            MappingProxyType({"owner_uid": owner, "relation": _freeze(_relation_record(relation))})
            for owner, relation in bindings
        )
        rows = tuple(
            _firewall_row(graph, rulebase_uid, rule, bindings, bundle_cache, object_bundles)
            for rule in _ordered_rules(graph, rulebase_uid, "FwRule")
        )
        if kind == "nat":
            nat_rows = tuple(
                _nat_row(graph, rulebase_uid, rule, bindings, bundle_cache, object_bundles)
                for rule in _ordered_rules(graph, rulebase_uid, "NatRule")
            )
            for device, _relation in bindings:
                if not requested or device in requested:
                    nat.setdefault(device, []).extend(nat_rows)
            if _complete_binding(rulebase, bindings, device_records):
                complete_nat.update(device for device, _ in bindings if not requested or device in requested)
            continue
        firewall[rulebase_uid] = rows
        if _complete_binding(rulebase, bindings, device_records):
            complete_fw.add(rulebase_uid)

    contexts = {
        context
        for context, device in context_owners.items()
        if _complete_device(device_records.get(device, ()))
    }
    return CatalogProjection(
        MappingProxyType(
            {
                "firewall": MappingProxyType(
                    {rulebase: tuple(_freeze(row) for row in rows) for rulebase, rows in firewall.items()}
                ),
                "nat": MappingProxyType(
                    {device: tuple(_freeze(row) for row in rows) for device, rows in nat.items()}
                ),
            }
        ),
        frozenset(complete_fw),
        frozenset(complete_nat),
        frozenset(contexts),
        graph.fingerprint,
        MappingProxyType({key: _freeze(value) for key, value in sorted(object_bundles.items())}),
        MappingProxyType(binding_map),
    )


def _ordered_rules(graph: GraphInventory, rulebase_uid: str, label: str) -> tuple[GraphNode, ...]:
    rules = tuple(rule for rule in graph.targets(rulebase_uid, "HAS_RULE") if label in rule.labels)
    return tuple(sorted(rules, key=lambda rule: (_position(rule), rule.uid)))


def _position(rule: GraphNode) -> int:
    value = rule.props.get("position")
    return value if type(value) is int else -1


def _bindings(graph: GraphInventory, rulebase_uid: str) -> tuple[tuple[str, GraphRelation], ...]:
    result: list[tuple[str, GraphRelation]] = []
    for relation in graph.incoming.get((rulebase_uid, "ENFORCES"), ()):
        owner = graph.nodes.get(relation.start)
        if owner is not None:
            result.append((relation.start, relation))
    unique = {(device, relation.uid): (device, relation) for device, relation in result}
    return tuple(sorted(unique.values(), key=lambda item: (item[0], item[1].uid)))


def _firewall_row(
    graph: GraphInventory,
    rulebase_uid: str,
    rule: GraphNode,
    bindings: Sequence[tuple[str, GraphRelation]],
    bundle_cache: dict[str, str],
    object_bundles: dict[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    props = rule.props
    src, src_opaque = _addresses(graph, graph.targets(rule.uid, "SRC"))
    dst, dst_opaque = _addresses(graph, graph.targets(rule.uid, "DST"))
    service, svc_opaque = _services(graph, graph.targets(rule.uid, "SVC"))
    envelope = _envelope(graph, rulebase_uid, rule, bindings, bundle_cache, object_bundles)
    row = {
        "uid": rule.uid,
        "pos": props.get("position"),
        "action": props.get("action"),
        "name": props.get("name"),
        # the named ruleset a VyOS `action jump` evaluates
        "jump_target": props.get("jump_target") or None,
        "in_if": props.get("in_interface"),
        "out_if": props.get("out_interface"),
        "in_if_group": props.get("in_interface_group"),
        "out_if_group": props.get("out_interface_group"),
        "states": tuple(props.get("states") or ()),
        "states_opaque": bool(props.get("states_opaque")),
        "states_opaque_reason": props.get("states_opaque_reason"),
        "unmodeled_fields": tuple(props.get("unmodeled_fields") or ()),
        # A row without install-on applies on every gateway.
        "install_on": tuple(props.get("install_on") or ()),
        "install_on_unresolved": props.get("install_on_unresolved") is True,
        "src_any": props.get("src_any") is True,
        "dst_any": props.get("dst_any") is True,
        "svc_any": props.get("svc_any") is True,
        "svc_any_stated": props.get("svc_any") is not None,
        "src_negate": props.get("src_negate") is True,
        "dst_negate": props.get("dst_negate") is True,
        "svc_negate": props.get("svc_negate") is True,
        "src_cidrs": tuple(src["cidrs"]),
        "src_ips": tuple(src["ips"]),
        "src_ranges": tuple(src["ranges"]),
        "dst_cidrs": tuple(dst["cidrs"]),
        "dst_ips": tuple(dst["ips"]),
        "dst_ranges": tuple(dst["ranges"]),
        "protos": tuple(pair[0] for pair in service["pairs"]),
        "ports": tuple(pair[1] for pair in service["pairs"]),
        "src_ports": tuple(pair[2] for pair in service["pairs"]),
        "svc_src_port": any(pair[2] not in (None, "") for pair in service["pairs"]),
        "src_obj_count": len(src["refs"]),
        "dst_obj_count": len(dst["refs"]),
        "svc_obj_count": len(service["refs"]),
        "src_opaque": src_opaque,
        "dst_opaque": dst_opaque,
        "svc_opaque": svc_opaque,
        "src_opaque_reasons": _opaque_reasons(graph.targets(rule.uid, "SRC")),
        "dst_opaque_reasons": _opaque_reasons(graph.targets(rule.uid, "DST")),
        "svc_opaque_reasons": _opaque_reasons(graph.targets(rule.uid, "SVC")),
        "graph_rulebase_uid": rulebase_uid,
        "graph_object_refs": {"src": src["refs"], "dst": dst["refs"], "svc": service["refs"]},
        "graph_rule_fingerprint": _fingerprint(envelope),
        "graph_semantic_fingerprint": _fingerprint(envelope),
        "graph_envelope": envelope,
        "graph_object_bundle_ids": envelope["object_bundle_ids"],
        "graph_evidence": (rule.uid, rulebase_uid),
    }
    return row


def _nat_row(
    graph: GraphInventory,
    rulebase_uid: str,
    rule: GraphNode,
    bindings: Sequence[tuple[str, GraphRelation]],
    bundle_cache: dict[str, str],
    object_bundles: dict[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    props = rule.props
    columns = {
        kind: _addresses(graph, graph.targets(rule.uid, kind))[0]
        for kind in ("ORIG_SRC", "ORIG_DST", "XLATE_SRC", "XLATE_DST")
    }
    opaque = any(_addresses(graph, graph.targets(rule.uid, kind))[1] for kind in columns)
    envelope = _envelope(graph, rulebase_uid, rule, bindings, bundle_cache, object_bundles)
    return {
        **dict(props),
        "uid": rule.uid,
        "rb_uid": rulebase_uid,
        "rb_name": graph.nodes[rulebase_uid].props.get("name"),
        "pos": props.get("position"),
        "enabled": props.get("enabled", True),
        "exclude": props.get("exclude", False),
        "kind": props.get("kind"),
        "method": props.get("method"),
        "protocol": props.get("protocol"),
        "in_if": props.get("in_if"),
        "out_if": props.get("out_if"),
        "orig_src_addrs": tuple(columns["ORIG_SRC"]["cidrs"] + columns["ORIG_SRC"]["ips"]),
        "orig_dst_addrs": tuple(columns["ORIG_DST"]["cidrs"] + columns["ORIG_DST"]["ips"]),
        "xlate_src_addrs": tuple(columns["XLATE_SRC"]["cidrs"] + columns["XLATE_SRC"]["ips"]),
        "xlate_dst_addrs": tuple(columns["XLATE_DST"]["cidrs"] + columns["XLATE_DST"]["ips"]),
        "approximate": any(relation.props.get("approximate") is True for _, relation in bindings),
        "rule_approximate": opaque or props.get("approximate") is True,
        "graph_object_refs": {key: values["refs"] for key, values in columns.items()},
        "graph_rule_fingerprint": _fingerprint(envelope),
        "graph_semantic_fingerprint": _fingerprint(envelope),
        "graph_envelope": envelope,
        "graph_object_bundle_ids": envelope["object_bundle_ids"],
        "graph_evidence": (rule.uid, rulebase_uid),
    }


def _addresses(graph: GraphInventory, nodes: Sequence[GraphNode]) -> tuple[dict[str, tuple[str, ...]], bool]:
    result: dict[str, list[str]] = {"cidrs": [], "ips": [], "ranges": [], "refs": []}
    opaque = False
    for node in nodes:
        result["refs"].append(node.uid)
        props = node.props
        for key, target in (("cidr", "cidrs"), ("ip", "ips")):
            if isinstance(props.get(key), str):
                result[target].append(props[key])
        if isinstance(props.get("ranges"), (tuple, list)) and all(
            isinstance(item, str) for item in props["ranges"]
        ):
            result["ranges"].extend(props["ranges"])
        if (
            graph.targets(node.uid, "RESOLVES_TO")
            or graph.sources(node.uid, "MEMBER_OF")
            or props.get("opaque") is True
        ):
            opaque = True
        if not any((props.get("cidr"), props.get("ip"), props.get("ranges"))):
            opaque = True
    return {key: tuple(sorted(set(value))) for key, value in result.items()}, opaque


def _opaque_reasons(nodes: Sequence[GraphNode]) -> tuple[str, ...]:
    """The reasons of the opaque objects of one rule side, in the form in
    which the rules query of the gate lists them."""
    return tuple(
        sorted(
            {
                str(node.props["opaque_reason"])
                for node in nodes
                if node.props.get("opaque") is True and node.props.get("opaque_reason")
            }
        )
    )


def _services(graph: GraphInventory, nodes: Sequence[GraphNode]) -> tuple[dict[str, tuple[Any, ...]], bool]:
    refs, pairs, opaque = [], [], False
    for node in nodes:
        refs.append(node.uid)
        props = node.props
        proto, ports, sport = props.get("proto"), props.get("ports"), props.get("src_port")
        if proto is None and ports is None and sport is None:
            opaque = True
        else:
            pairs.append((proto, ports, sport))
        if graph.sources(node.uid, "MEMBER_OF") or props.get("opaque") is True:
            opaque = True
    unique = {repr(pair): pair for pair in pairs}
    return {"refs": tuple(sorted(refs)), "pairs": tuple(unique[key] for key in sorted(unique))}, opaque


def _envelope(
    graph: GraphInventory,
    rulebase_uid: str,
    rule: GraphNode,
    bindings: Sequence[tuple[str, GraphRelation]],
    bundle_cache: dict[str, str],
    object_bundles: dict[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Rule-local identity plus references to shared content-addressed object bundles."""
    rule_relations = []
    ownership = []
    for relation in graph.incoming.get((rule.uid, "HAS_RULE"), ()):
        if relation.start == rulebase_uid:
            ownership.append(_relation_record(relation))
    for kind in ("SRC", "DST", "SVC", "ORIG_SRC", "ORIG_DST", "XLATE_SRC", "XLATE_DST"):
        for relation in graph.outgoing.get((rule.uid, kind), ()):
            rule_relations.append(_relation_record(relation))
    direct_uids = sorted({str(relation["end"]) for relation in rule_relations})
    bundle_ids = tuple(
        _object_bundle(graph, object_uid, bundle_cache, object_bundles) for object_uid in direct_uids
    )
    return {
        "rulebase_uid": rulebase_uid,
        "rule_uid": rule.uid,
        "rule_props": _plain(rule.props),
        "has_rule": tuple(sorted(ownership, key=lambda relation: str(relation["uid"]))),
        "bindings": tuple(
            {
                "device_uid": device,
                "relation": _relation_record(relation),
            }
            for device, relation in sorted(bindings, key=lambda item: (item[0], item[1].uid))
        ),
        "rule_relations": tuple(sorted(rule_relations, key=lambda relation: str(relation["uid"]))),
        "object_bundle_ids": bundle_ids,
    }


def _relation_record(relation: GraphRelation) -> Mapping[str, Any]:
    return {
        "uid": relation.uid,
        "kind": relation.kind,
        "start": relation.start,
        "end": relation.end,
        "props": _plain(relation.props),
    }


def _object_bundle(
    graph: GraphInventory,
    root_uid: str,
    cache: dict[str, str],
    bundles: dict[str, Mapping[str, Any]],
) -> str:
    """Iteratively snapshot one shared object DAG once, including cycles.

    The DAG holds what the policy normalization reads for the object
    (`hst.policy.graph.GraphPolicyNormalizer._object`). These are the members
    of a group (incoming MEMBER_OF) and the addresses of the object (outgoing
    RESOLVES_TO), and the members and addresses of those in turn. An incoming
    RESOLVES_TO is not followed. An object whose bundle is already built
    contributes that bundle and is not walked again. The bundle is keyed by
    its content alone. The envelope holds the objects of the rule
    (`rule_relations`)."""
    if root_uid in cache:
        return cache[root_uid]
    pending = [root_uid]
    seen: set[str] = set()
    nodes: dict[str, Mapping[str, Any]] = {}
    relations: dict[str, Mapping[str, Any]] = {}
    while pending:
        uid = pending.pop()
        if uid in seen:
            continue
        seen.add(uid)
        if uid != root_uid and uid in cache:
            built = bundles[cache[uid]]
            nodes.update(built["nodes"])
            relations.update(built["relations"])
            seen.update(built["nodes"])
            continue
        node = graph.nodes.get(uid)
        if node is None:
            continue
        nodes[uid] = {"labels": tuple(sorted(node.labels)), "props": _plain(node.props)}
        related = (
            *graph.incoming.get((uid, "MEMBER_OF"), ()),
            *graph.outgoing.get((uid, "RESOLVES_TO"), ()),
        )
        for relation in related:
            relations[relation.uid] = _relation_record(relation)
            next_uid = relation.start if relation.end == uid else relation.end
            if next_uid not in seen:
                pending.append(next_uid)
    payload: Mapping[str, Any] = {
        "nodes": {uid: nodes[uid] for uid in sorted(nodes)},
        "relations": {uid: relations[uid] for uid in sorted(relations)},
    }
    identity = _fingerprint(payload)
    bundles.setdefault(identity, payload)
    cache[root_uid] = identity
    return identity


def _materialize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _materialize(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_materialize(item) for item in value)
    if isinstance(value, list):
        return [_materialize(item) for item in value]
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, tuple | list):
        return tuple(_freeze(item) for item in value)
    return value


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(_plain(payload), sort_keys=True, default=str).encode()).hexdigest()


def _device_records(manifest: Any | None) -> dict[str, tuple[Any, ...]]:
    records: dict[str, list[Any]] = {}
    for record in getattr(manifest, "devices", ()) if manifest is not None else ():
        for device in getattr(record, "device_uids", ()):
            records.setdefault(str(device), []).append(record)
    return {device: tuple(values) for device, values in records.items()}


def _complete_binding(
    rulebase: GraphNode, bindings: Sequence[tuple[str, GraphRelation]], records: Mapping[str, Sequence[Any]]
) -> bool:
    configured = rulebase.props.get("configured_revision")
    return (
        isinstance(configured, str)
        and bool(bindings)
        and all(
            relation.props.get("installed") is True
            and relation.props.get("coverage") in {"complete", "complete-empty"}
            and isinstance(relation.props.get("installed_revision"), str)
            and relation.props.get("installed_revision") == configured
            and _complete_device(records.get(device, ()))
            for device, relation in bindings
        )
    )


def _complete_device(records: Sequence[Any]) -> bool:
    return bool(records) and all(
        getattr(record, "outcome", None) in {"collected", "unchanged"}
        and not getattr(record, "carried", False)
        and bool(getattr(record, "expected_sections", ()))
        and all(
            getattr(getattr(record, "sections", {}).get(section), "status", None)
            in {"ok", "empty", "complete", "complete-empty"}
            for section in getattr(record, "expected_sections", ())
        )
        for record in records
    )
