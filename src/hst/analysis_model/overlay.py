"""Immutable ordered graph overlay for proposed policy changes."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from itertools import product
from types import MappingProxyType
from typing import Any

from hst.core import uid as uidmod
from hst.simul.fw_overlay import ChangeSet, ProposalError
from hst.simul.intents import FW_KINDS, NAT_KINDS, ROUTING_KINDS, ZONE_KINDS

from .graph import GraphInventory, GraphNode, GraphRelation


def _attach(
    nodes: dict[str, GraphNode],
    relations: list[GraphRelation],
    rule: str,
    relation: str,
    value: Any,
    nonce: str,
) -> None:
    """Attach explicit graph objects. Existing group nodes stay references."""
    values = [value] if isinstance(value, str) else list(value or ())
    for index, token in enumerate(values):
        target = str(token)
        if target.lower() == "any":
            continue
        if target not in nodes:
            uid = f"overlay:object:{rule}:{relation}:{nonce}:{index}"
            props: dict[str, Any]
            if relation == "SVC":
                props = {"proto": target} if target in {"tcp", "udp", "icmp", "icmp6"} else {"ports": target}
            else:
                props = (
                    {"ranges": (target,)}
                    if "-" in target
                    else {"cidr": target}
                    if "/" in target
                    else {"ip": target}
                )
            nodes[uid] = _node(uid, frozenset({"SvcObject" if relation == "SVC" else "NetObject"}), props)
            target = uid
        relations.append(
            GraphRelation(
                f"overlay:{rule}:{relation}:{nonce}:{index}", relation, rule, target, MappingProxyType({})
            )
        )


def _any(value: Any) -> bool:
    values = (value,) if isinstance(value, str) else tuple(value or ())
    return not values or all(str(item).lower() == "any" for item in values)


def _node(uid: str, labels: frozenset[str], props: dict[str, Any]) -> GraphNode:
    def freeze(value: Any) -> Any:
        if isinstance(value, dict):
            return MappingProxyType({key: freeze(item) for key, item in value.items()})
        if isinstance(value, list | tuple):
            return tuple(freeze(item) for item in value)
        return value

    return GraphNode(uid, labels, MappingProxyType({key: freeze(value) for key, value in props.items()}))


def _checkpoint_scope(
    nodes: dict[str, GraphNode], relations: list[GraphRelation], rulebase: str
) -> tuple[str, str, str, GraphNode] | None:
    owners = [rel.start for rel in relations if rel.kind == "HAS_LAYER" and rel.end == rulebase]
    if len(owners) != 1 or owners[0] not in nodes:
        return None
    package = nodes[owners[0]]
    authority, domain = package.props.get("authority_uid"), package.props.get("domain_uid")
    if not isinstance(authority, str) or not isinstance(domain, str):
        return None
    return authority, domain, uidmod.checkpoint(authority, domain, ""), package


def _checkpoint_object(nodes: dict[str, GraphNode], node_uid: str, *, service: bool, domain: str) -> str:
    node = nodes[node_uid]
    raw = node.props.get("checkpoint_envelope")
    if isinstance(raw, str):
        decoded = json.loads(raw)
        if isinstance(decoded, dict) and isinstance(decoded.get("uid"), str):
            return decoded["uid"]
    props = node.props
    envelope: dict[str, Any] = {
        "uid": node_uid,
        "name": props.get("name", node_uid),
        "domain": {"uid": domain},
    }
    if service:
        proto = str(props.get("proto") or "").lower()
        if proto in {"icmp", "icmp6"}:
            envelope.update(
                type=f"service-{proto}",
                **{"strata-unconstrained-icmp-fields": True},
            )
        elif proto in {"tcp", "udp"}:
            envelope.update(
                type=f"service-{proto}",
                port=str(props.get("ports") or ""),
                **{
                    "source-port": "",
                    "protocol": "",
                    "match-by-protocol-signature": False,
                },
            )
        else:
            raise ProposalError("Check Point overlay service requires TCP, UDP, ICMP or ICMPv6 semantics")
    elif props.get("ip6"):
        envelope.update(type="host", **{"ipv6-address": props["ip6"]})
    elif props.get("ip"):
        envelope.update(type="host", **{"ipv4-address": props["ip"]})
    elif props.get("cidr6"):
        address, mask = str(props["cidr6"]).split("/", 1)
        envelope.update(type="network", subnet6=address, **{"mask-length6": int(mask)})
    elif props.get("cidr"):
        address, mask = str(props["cidr"]).split("/", 1)
        envelope.update(type="network", subnet4=address, **{"mask-length4": int(mask)})
    elif props.get("ranges"):
        ranges = tuple(props["ranges"])
        if len(ranges) != 1 or "-" not in str(ranges[0]):
            raise ProposalError("Check Point overlay address range must be one bounded range")
        first, last = str(ranges[0]).split("-", 1)
        fields = (
            {"ipv6-address-first": first, "ipv6-address-last": last}
            if ":" in first or ":" in last
            else {"ipv4-address-first": first, "ipv4-address-last": last}
        )
        envelope.update(type="address-range", **fields)
    else:
        raise ProposalError("Check Point overlay object lacks representable native semantics")
    updated = dict(props)
    updated["checkpoint_envelope"] = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    nodes[node_uid] = _node(node_uid, node.labels, updated)
    return node_uid


def _sync_checkpoint_rule(
    nodes: dict[str, GraphNode], relations: list[GraphRelation], rulebase: str, rule_uid: str
) -> None:
    scope = _checkpoint_scope(nodes, relations, rulebase)
    if scope is None:
        return
    _, domain, prefix, package_node = scope
    rule = nodes[rule_uid]
    raw = rule.props.get("checkpoint_envelope")
    decoded = json.loads(raw) if isinstance(raw, str) else {"uid": rule_uid, "type": "access-rule"}
    if not isinstance(decoded, dict):
        raise ProposalError("Check Point rule envelope is malformed")
    decoded.update(
        enabled=rule.props.get("enabled", True),
        **{"rule-number": rule.props.get("position")},
    )
    action = str(rule.props.get("action") or "").lower()
    action_family = {
        "accept": "permit",
        "permit": "permit",
        "drop": "deny",
        "deny": "deny",
        "reject": "deny",
    }.get(action, action)
    matches = []
    any_uid = None
    for candidate in nodes.values():
        envelope = candidate.props.get("checkpoint_envelope")
        if not candidate.uid.startswith(prefix) or not isinstance(envelope, str):
            continue
        value = json.loads(envelope)
        if not isinstance(value, dict):
            continue
        candidate_action = str(value.get("name", "")).lower()
        candidate_family = {
            "accept": "permit",
            "permit": "permit",
            "drop": "deny",
            "deny": "deny",
            "reject": "deny",
        }.get(candidate_action, candidate_action)
        if value.get("type") == "RulebaseAction" and candidate_family == action_family:
            matches.append(value.get("uid"))
        if value.get("type") == "CpmiAnyObject":
            any_uid = value.get("uid")
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ProposalError("Check Point overlay action lacks one native action object")
    decoded["action"] = matches[0]
    for field, relation, prop, service in (
        ("source", "SRC", "src_any", False),
        ("destination", "DST", "dst_any", False),
        ("service", "SVC", "svc_any", True),
    ):
        if rule.props.get(prop):
            if not isinstance(any_uid, str):
                raise ProposalError("Check Point overlay wildcard lacks native Any object")
            decoded[field] = [any_uid]
        else:
            targets = [rel.end for rel in relations if rel.start == rule_uid and rel.kind == relation]
            decoded[field] = [
                _checkpoint_object(nodes, target, service=service, domain=domain) for target in targets
            ]
        decoded.setdefault(f"{field}-negate", False)
    decoded.setdefault("time", [any_uid] if any_uid else [])
    decoded.setdefault("vpn", [any_uid] if any_uid else [])
    decoded.setdefault("content", [any_uid] if any_uid else [])
    if "install-on" not in decoded:
        package_raw = package_node.props.get("checkpoint_envelope")
        package = json.loads(package_raw) if isinstance(package_raw, str) else {}
        install_on = package.get("installation-targets", ()) if isinstance(package, dict) else ()
        decoded["install-on"] = list(install_on) if isinstance(install_on, (list, tuple)) else []
    decoded.setdefault("domain", {"uid": domain})
    updated = dict(rule.props)
    updated["checkpoint_envelope"] = json.dumps(decoded, sort_keys=True, separators=(",", ":"))
    nodes[rule_uid] = _node(rule_uid, rule.labels, updated)


def _rebuild(
    graph: GraphInventory, nodes: dict[str, GraphNode], relations: list[GraphRelation]
) -> GraphInventory:
    labels: dict[str, list[str]] = defaultdict(list)
    outgoing: dict[tuple[str, str], list[GraphRelation]] = defaultdict(list)
    incoming: dict[tuple[str, str], list[GraphRelation]] = defaultdict(list)
    for uid, node in nodes.items():
        for label in node.labels:
            labels[label].append(uid)
    for relation in relations:
        if relation.start in nodes and relation.end in nodes:
            outgoing[relation.start, relation.kind].append(relation)
            incoming[relation.end, relation.kind].append(relation)
    identity = (
        graph.fingerprint,
        tuple(sorted((uid, tuple(sorted(node.labels)), dict(node.props)) for uid, node in nodes.items())),
        tuple((r.uid, r.kind, r.start, r.end, dict(r.props)) for r in relations),
    )
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()
    return GraphInventory(
        graph.manifest_digest,
        fingerprint,
        MappingProxyType(nodes),
        MappingProxyType({key: tuple(sorted(value)) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        graph.complete,
        graph.gaps,
        graph.database_reads,
    )


def apply_overlay(graph: GraphInventory, changes: ChangeSet) -> GraphInventory:
    """Apply every non-routing proposal in order without changing the baseline graph."""
    nodes = dict(graph.nodes)
    relations = list({rel.uid: rel for rels in graph.outgoing.values() for rel in rels}.values())
    for ordinal, intent in enumerate(changes.intents):
        kind, params = intent.kind, intent.params
        nonce = hashlib.sha256(
            json.dumps((graph.fingerprint, ordinal, kind, params), sort_keys=True, default=str).encode()
        ).hexdigest()[:20]
        if kind in ROUTING_KINDS:
            raise ProposalError(f"routing intent {kind!r} must be applied to RibInput, not GraphInventory")
        if kind not in FW_KINDS | NAT_KINDS | ZONE_KINDS:
            raise ProposalError(f"unsupported graph overlay intent {kind!r}")
        if kind in ZONE_KINDS:
            zone, interface = str(params["zone"]), str(params["interface"])
            if zone not in nodes or interface not in nodes:
                raise ProposalError("zone move names an object absent from the pinned graph")
            relations = [
                rel
                for rel in relations
                if not (rel.kind == "CONTAINS" and rel.start == zone and rel.end == interface)
            ]
            if kind == "zone.add_interface":
                relations.append(
                    GraphRelation(
                        f"overlay:contains:{nonce}", "CONTAINS", zone, interface, MappingProxyType({})
                    )
                )
            continue
        family = "FwRule" if kind in FW_KINDS else "NatRule"
        if kind.endswith(".add"):
            uid = str(params.get("uid") or f"overlay:{family}:{nonce}")
            if uid in nodes:
                raise ProposalError(f"proposed {family} {uid!r} already exists")
            semantic_fields = {
                "source",
                "destination",
                "services",
                "protocols",
                "ports",
                "orig_src",
                "orig_dst",
                "xlate_src",
                "xlate_dst",
                "from_zone",
                "to_zone",
            }
            base = {
                key: value
                for key, value in params.items()
                if key not in {"rulebase", "device", "uid"} | semantic_fields
            }
            base.update(
                {
                    "uid": uid,
                    "position": params.get("position"),
                    "action": params.get("action"),
                    "enabled": params.get("enabled", True),
                }
            )
            if family == "FwRule":
                base["src_any"] = _any(params.get("source", "any"))
                base["dst_any"] = _any(params.get("destination", "any"))
                base["svc_any"] = ("services" in params and _any(params["services"])) or not bool(
                    params.get("services") or params.get("protocols") or params.get("ports")
                )
                for field, prop in (("from_zone", "in_interfaces"), ("to_zone", "out_interfaces")):
                    if params.get(field):
                        base[prop] = tuple(
                            interface.uid for interface in graph.targets(str(params[field]), "CONTAINS")
                        )
            nodes[uid] = _node(uid, frozenset({family}), dict(base))
            rulebase = params.get("rulebase")
            if not rulebase and family == "NatRule":
                device = str(params.get("device") or "")
                candidates = [rel.end for rel in relations if rel.kind == "ENFORCES" and rel.start == device]
                rulebase = candidates[0] if len(candidates) == 1 else None
            if not rulebase:
                raise ProposalError(f"{kind} requires one unambiguous installed rulebase in graph overlay")
            if str(rulebase) not in nodes:
                raise ProposalError(f"rulebase {rulebase!r} is absent from the pinned graph")
            relations.append(
                GraphRelation(
                    f"overlay:has-rule:{nonce}", "HAS_RULE", str(rulebase), uid, MappingProxyType({})
                )
            )
            if family == "FwRule":
                for field, relation in (("source", "SRC"), ("destination", "DST"), ("services", "SVC")):
                    _attach(nodes, relations, uid, relation, params.get(field), nonce)
                if params.get("protocols") or params.get("ports"):
                    protocols = params.get("protocols") or (None,)
                    ports = params.get("ports") or (None,)
                    protocols = (protocols,) if isinstance(protocols, str) else tuple(protocols)
                    ports = (ports,) if isinstance(ports, str) else tuple(ports)
                    for service_index, (proto, port) in enumerate(product(protocols, ports)):
                        service_uid = f"overlay:object:{uid}:SVC:{nonce}:{service_index}"
                        nodes[service_uid] = _node(
                            service_uid, frozenset({"SvcObject"}), {"proto": proto, "ports": port}
                        )
                        relations.append(
                            GraphRelation(
                                f"overlay:{uid}:SVC:{nonce}:{service_index}",
                                "SVC",
                                uid,
                                service_uid,
                                MappingProxyType({}),
                            )
                        )
            else:
                for field, relation in (
                    ("orig_src", "ORIG_SRC"),
                    ("orig_dst", "ORIG_DST"),
                    ("xlate_src", "XLATE_SRC"),
                    ("xlate_dst", "XLATE_DST"),
                ):
                    _attach(nodes, relations, uid, relation, params.get(field), nonce)
            if family == "FwRule":
                _sync_checkpoint_rule(nodes, relations, str(rulebase), uid)
            continue
        target = str(params.get("rule") or "")
        node = nodes.get(target)
        if node is None or family not in node.labels:
            raise ProposalError(f"{kind} names missing {family} {target!r}")
        named_rulebase = params.get("rulebase")
        if named_rulebase and not any(
            rel.kind == "HAS_RULE" and rel.start == named_rulebase and rel.end == target for rel in relations
        ):
            raise ProposalError(f"rule {target!r} is not owned by rulebase {named_rulebase!r}")
        if kind.endswith(".remove"):
            del nodes[target]
            relations = [rel for rel in relations if rel.start != target and rel.end != target]
            continue
        props = dict(node.props)
        props.update(
            {
                key: value
                for key, value in params.items()
                if key
                not in {
                    "rulebase",
                    "device",
                    "rule",
                    "source",
                    "destination",
                    "services",
                    "protocols",
                    "ports",
                    "orig_src",
                    "orig_dst",
                    "xlate_src",
                    "xlate_dst",
                    "from_zone",
                    "to_zone",
                }
            }
        )
        nodes[target] = _node(target, node.labels, props)
        if family == "FwRule":
            for field, relation in (("source", "SRC"), ("destination", "DST"), ("services", "SVC")):
                if field in params:
                    relations = [
                        rel for rel in relations if not (rel.start == target and rel.kind == relation)
                    ]
                    _attach(nodes, relations, target, relation, params[field], nonce)
            if "source" in params or "destination" in params:
                current = dict(nodes[target].props)
                if "source" in params:
                    current["src_any"] = _any(params["source"])
                if "destination" in params:
                    current["dst_any"] = _any(params["destination"])
                nodes[target] = _node(target, node.labels, current)
            if "protocols" in params or "ports" in params:
                existing_services = [
                    nodes[rel.end]
                    for rel in relations
                    if rel.start == target and rel.kind == "SVC" and rel.end in nodes
                ]
                relations = [rel for rel in relations if not (rel.start == target and rel.kind == "SVC")]
                empty_service = all(
                    params[key] in (None, "", (), []) for key in ("protocols", "ports") if key in params
                )
                if empty_service:
                    current = dict(nodes[target].props)
                    current["svc_any"] = True
                    nodes[target] = _node(target, node.labels, current)
                else:
                    protocols = (
                        params.get("protocols")
                        or tuple(service.props.get("proto") for service in existing_services)
                        or (None,)
                    )
                    ports = (
                        params.get("ports")
                        or tuple(service.props.get("ports") for service in existing_services)
                        or (None,)
                    )
                    protocols = (protocols,) if isinstance(protocols, str) else tuple(protocols)
                    ports = (ports,) if isinstance(ports, str) else tuple(ports)
                    for index, proto in enumerate(protocols):
                        for port_index, port in enumerate(ports):
                            service_uid = f"overlay:object:{target}:SVC:{nonce}:modify:{index}:{port_index}"
                            nodes[service_uid] = _node(
                                service_uid,
                                frozenset({"SvcObject"}),
                                {"proto": proto, "ports": port},
                            )
                            relations.append(
                                GraphRelation(
                                    f"overlay:{target}:SVC:{nonce}:modify:{index}:{port_index}",
                                    "SVC",
                                    target,
                                    service_uid,
                                    MappingProxyType({}),
                                )
                            )
                    current = dict(nodes[target].props)
                    current["svc_any"] = False
                    nodes[target] = _node(target, node.labels, current)
            elif "services" in params:
                current = dict(nodes[target].props)
                current["svc_any"] = _any(params["services"])
                nodes[target] = _node(target, node.labels, current)
            for field, prop in (("from_zone", "in_interfaces"), ("to_zone", "out_interfaces")):
                if field in params:
                    current = dict(nodes[target].props)
                    current[prop] = tuple(
                        interface.uid for interface in graph.targets(str(params[field]), "CONTAINS")
                    )
                    nodes[target] = _node(target, node.labels, current)
        else:
            for field, relation in (
                ("orig_src", "ORIG_SRC"),
                ("orig_dst", "ORIG_DST"),
                ("xlate_src", "XLATE_SRC"),
                ("xlate_dst", "XLATE_DST"),
            ):
                if field in params:
                    relations = [
                        rel for rel in relations if not (rel.start == target and rel.kind == relation)
                    ]
                    _attach(nodes, relations, target, relation, params[field], nonce)
        if family == "FwRule":
            owners = [rel.start for rel in relations if rel.kind == "HAS_RULE" and rel.end == target]
            if len(owners) == 1:
                _sync_checkpoint_rule(nodes, relations, owners[0], target)
    return _rebuild(graph, nodes, relations)
