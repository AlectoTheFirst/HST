"""Graph-native proposal validation for symbolic-v2 policy overlays."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from ipaddress import ip_address, ip_network
from typing import Any

from hst.path.addrsets import _ports, _protoset
from hst.simul.fw_overlay import Catalog, ChangeSet, Intent, ProposalError
from hst.simul.intents import FW_KINDS, NAT_KINDS, OVERLAY_KINDS, ZONE_KINDS

from .graph import GraphInventory


def native_changes(graph: GraphInventory, intents: Sequence[Mapping[str, Any]]) -> ChangeSet:
    """Validate ownership/object identity without flattening shared groups."""
    out: list[Intent] = []
    for ordinal, raw in enumerate(intents):
        kind, params = str(raw.get("kind") or ""), dict(raw.get("params") or {})
        if kind not in OVERLAY_KINDS:
            raise ProposalError(f"intent {ordinal} has unsupported kind {kind!r}")
        if kind in FW_KINDS:
            _firewall(graph, kind, params, ordinal)
        elif kind in NAT_KINDS:
            _nat(graph, kind, params, ordinal)
        elif kind in ZONE_KINDS and not {
            str(params.get("zone") or ""),
            str(params.get("interface") or ""),
        } <= set(graph.nodes):
            raise ProposalError(f"intent {ordinal} names an absent zone or interface")
        out.append(Intent(kind, params))
    return ChangeSet(out, catalog=Catalog())


def _firewall(graph: GraphInventory, kind: str, params: dict[str, Any], ordinal: int) -> None:
    if not params.get("rulebase") and params.get("device"):
        candidates = [
            node.uid
            for node in graph.targets(str(params["device"]), "ENFORCES")
            if "FwRulebase" in node.labels
        ]
        if len(candidates) == 1:
            params["rulebase"] = candidates[0]
    rulebase, rule = str(params.get("rulebase") or ""), str(params.get("rule") or "")
    base = graph.nodes.get(rulebase)
    if base is None or "FwRulebase" not in base.labels:
        raise ProposalError(f"intent {ordinal} needs an existing firewall rulebase")
    if kind != "fw_rule.add" and not _owns(graph, rulebase, rule, "FwRule"):
        raise ProposalError(f"intent {ordinal} names a rule not owned by its rulebase")
    if "action" in params and str(params["action"]).lower() not in {
        "accept",
        "permit",
        "drop",
        "deny",
        "reject",
    }:
        raise ProposalError(f"intent {ordinal} has an unsupported firewall action")
    if "enabled" in params and type(params["enabled"]) is not bool:
        raise ProposalError(f"intent {ordinal} enabled must be boolean")
    if "position" in params and type(params["position"]) is not int:
        raise ProposalError(f"intent {ordinal} position must be an integer")
    for field, labels in (
        ("source", {"NetObject"}),
        ("destination", {"NetObject"}),
        ("services", {"SvcObject"}),
    ):
        if field in params:
            params[field] = _references(graph, params[field], labels, field)
    if "protocols" in params:
        try:
            protocols = params["protocols"]
            _protoset([protocols] if isinstance(protocols, str) else protocols)
        except (TypeError, ValueError):
            raise ProposalError(f"intent {ordinal} has unsupported protocols") from None
    if "ports" in params:
        try:
            _ports(params["ports"])
        except (TypeError, ValueError):
            raise ProposalError(f"intent {ordinal} has unsupported ports") from None
    for field in ("from_zone", "to_zone"):
        if field in params:
            value = str(params[field])
            matches = [
                uid
                for uid in graph.labels.get("Zone", ())
                if uid == value or graph.nodes[uid].props.get("name") == value
            ]
            if len(matches) != 1:
                raise ProposalError(f"intent {ordinal} names an absent or ambiguous {field}")
            params[field] = matches[0]
    if kind == "fw_rule.add" and (
        str(params.get("action") or "").lower()
        not in {
            "accept",
            "permit",
            "drop",
            "deny",
            "reject",
        }
        or not isinstance(params.get("position"), int)
    ):
        raise ProposalError(f"intent {ordinal} needs a supported action and integer position")


def _nat(graph: GraphInventory, kind: str, params: dict[str, Any], ordinal: int) -> None:
    device, rule = str(params.get("device") or ""), str(params.get("rule") or "")
    if device not in graph.nodes:
        raise ProposalError(f"intent {ordinal} needs an existing device")
    if kind != "nat_rule.add" and not any(
        _owns(graph, rb.uid, rule, "NatRule") for rb in graph.targets(device, "ENFORCES")
    ):
        raise ProposalError(f"intent {ordinal} names a NAT rule not owned by its device")
    for field in ("orig_src", "orig_dst", "xlate_src", "xlate_dst"):
        if field in params:
            params[field] = _references(graph, params[field], {"NetObject"}, field)


def _references(graph: GraphInventory, value: Any, labels: set[str], field: str) -> list[str]:
    resolved = []
    for item in (value,) if isinstance(value, str) else tuple(value or ()):
        text = str(item)
        if text.lower() == "any" or _literal(text):
            resolved.append(text)
            continue
        matches = [
            graph.nodes[uid]
            for uid in sorted({uid for label in labels for uid in graph.labels.get(label, ())})
            if uid == text or graph.nodes[uid].props.get("name") == text
        ]
        if len(matches) != 1:
            raise ProposalError(f"{field} reference {text!r} is absent or ambiguous")
        resolved.append(matches[0].uid)
    return resolved


def _literal(value: str) -> bool:
    try:
        if "-" in value:
            left, right = (ip_address(part.strip()) for part in value.split("-", 1))
            return left.version == right.version and int(left) <= int(right)
        ip_address(value) if "/" not in value else ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _owns(graph: GraphInventory, rulebase: str, rule: str, label: str) -> bool:
    return (
        rule in graph.nodes
        and label in graph.nodes[rule].labels
        and any(relation.end == rule for relation in graph.outgoing.get((rulebase, "HAS_RULE"), ()))
    )
