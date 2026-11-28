"""Expand immutable graph gates into the compiled model's ordered stage graph."""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import product
from types import MappingProxyType
from typing import Any

from hst.core import zpa_policy
from hst.core.aci_filter import contract_bypass, filter_applies, stored_entry, vrf_enforcement
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Not, Predicate, Unknown
from hst.policy.nat import NatRuleSpec, normalize_nat_rules

from .graph import GraphInventory, GraphNode
from .model import ChoiceAssignment, EdgeSpec, NodeSpec, StateKey


@dataclass(frozen=True, slots=True)
class GateExpansion:
    entry: StateKey
    nodes: tuple[NodeSpec, ...]
    choices: tuple[ChoiceAssignment, ...]
    complete: bool
    gaps: tuple[str, ...] = ()
    # The source NAT edges whose source port the device picks, each as (the
    # state of the stage, the edge uid). The model builder checks that
    # nothing after them reads the source port (`NatRuleSpec.free_source_port`).
    free_source_ports: tuple[tuple[StateKey, str], ...] = ()


def expand_device_gates(
    graph: GraphInventory,
    context: ExecutionContext,
    device_uid: str,
    ingress_interface_uid: str | None,
    egress_interface_uid: str | None,
    downstream: StateKey,
    *,
    phases: tuple[str, ...] = ("dnat", "pbr", "snat", "load-balancer", "tunnel"),
    routing_targets: Mapping[str, StateKey] | None = None,
    tunnel_targets: Mapping[str, StateKey] | None = None,
    reroute: StateKey | None = None,
    choices_so_far: tuple[ChoiceAssignment, ...] = (),
    max_choices: int | None = None,
) -> GateExpansion:
    """Return a deterministic gate chain ending at ``downstream``.

    Every lookup is against the already materialized GraphInventory. Unsupported
    or incomplete bindings become explicit unknown terminals.

    ``choices_so_far`` is the joint choice catalogue that the caller holds, and
    ``max_choices`` is its limit. The load-balancer stage returns only the choices
    of scopes that the catalogue does not bind yet, and keeps their product within
    the limit (`_load_balancer_edges`).
    """
    failed = graph.nodes.get(device_uid)
    failed_interfaces = tuple(
        graph.nodes.get(uid) for uid in (ingress_interface_uid, egress_interface_uid) if uid
    )
    if (failed and failed.props.get("counterfactual_failed") is True) or any(
        interface is not None and interface.props.get("counterfactual_failed") is True
        for interface in failed_interfaces
    ):
        key = StateKey(f"gate:{device_uid}:counterfactual-failure", context, "failure")
        return GateExpansion(
            key,
            (NodeSpec(key, terminal="deny"),),
            (),
            True,
            ("COUNTERFACTUAL_COMPONENT_FAILED",),
        )
    stages: list[tuple[str, tuple[EdgeSpec, ...], tuple[NodeSpec, ...]]] = []
    gaps: set[str] = set(graph.gaps)
    choices: list[ChoiceAssignment] = []
    supported = {"dnat", "pbr", "snat", "load-balancer", "tunnel"}
    if unknown := set(phases) - supported:
        raise ValueError(f"unknown gate phases: {sorted(unknown)}")

    nat = normalize_nat_rules(
        graph,
        device_uid,
        ingress_interface_uid=ingress_interface_uid,
        egress_interface_uid=egress_interface_uid,
        address_family=context.address_family,
    )
    dnat = tuple(rule for rule in nat if rule.stage == "dnat") if "dnat" in phases else ()
    if dnat:
        edges, terminals, stage_gaps = _nat_edges(dnat, context, device_uid, "dnat")
        stages.append(("dnat", edges, terminals))
        gaps.update(stage_gaps)

    pbr = (
        _pbr_edges(graph, context, device_uid, ingress_interface_uid, routing_targets or {})
        if "pbr" in phases
        else ((), (), ())
    )
    if pbr[0]:
        stages.append(("pbr", pbr[0], pbr[1]))
        gaps.update(pbr[2])

    snat = tuple(rule for rule in nat if rule.stage == "snat") if "snat" in phases else ()
    if snat:
        edges, terminals, stage_gaps = _nat_edges(snat, context, device_uid, "snat")
        stages.append(("snat", edges, terminals))
        gaps.update(stage_gaps)

    lb_edges, lb_terminals, lb_choices, lb_gaps = (
        _load_balancer_edges(graph, context, device_uid, reroute, choices_so_far, max_choices)
        if "load-balancer" in phases
        else ((), (), (), ())
    )
    if lb_edges:
        stages.append(("load-balancer", lb_edges, lb_terminals))
        choices.extend(lb_choices)
        gaps.update(lb_gaps)

    tunnel_edges, tunnel_terminals, tunnel_gaps = (
        _tunnel_edges(graph, context, device_uid, egress_interface_uid, tunnel_targets or {})
        if "tunnel" in phases
        else ((), (), ())
    )
    if tunnel_edges:
        stages.append(("tunnel", tunnel_edges, tunnel_terminals))
        gaps.update(tunnel_gaps)

    if not stages:
        return GateExpansion(downstream, (), (), graph.complete, tuple(sorted(gaps)))
    nodes: list[NodeSpec] = []
    target = downstream
    free = {rule.uid for rule in snat if rule.free_source_port}
    free_source_ports: list[tuple[StateKey, str]] = []
    # Build backwards while retaining the forwarding stage order.
    for stage, templates, terminals in reversed(stages):
        key = StateKey(
            f"gate:{device_uid}:{stage}:{target.location}",
            context,
            stage,
            target.tunnel_stack,
            target.binding_scope,
        )
        edges = tuple(
            EdgeSpec(
                edge.uid,
                target if edge.target.location == "@next" else edge.target,
                edge.predicate,
                edge.rewrites,
                edge.choices,
                edge.evidence,
                edge.ranges,
            )
            for edge in templates
        )
        if stage == "snat":
            free_source_ports.extend((key, edge.uid) for edge in edges if edge.uid in free)
        nodes.extend(terminals)
        # Unknown subsets have their own explicit terminal edges.
        nodes.append(NodeSpec(key, edges, complete=True))
        target = key
    return GateExpansion(
        target, tuple(nodes), tuple(choices), not gaps, tuple(sorted(gaps)), tuple(free_source_ports)
    )


def merge_choice_assignments(
    existing: tuple[ChoiceAssignment, ...], additions: tuple[ChoiceAssignment, ...]
) -> tuple[ChoiceAssignment, ...]:
    """Form the compatible joint product used by routing and gate choices."""
    if not additions:
        return existing
    if not existing:
        return additions
    result = []
    for left, right in product(existing, additions):
        bindings = dict(left.bindings)
        if any(scope in bindings and bindings[scope] != value for scope, value in right.bindings):
            continue
        bindings.update(right.bindings)
        result.append(ChoiceAssignment(f"{left.uid}+{right.uid}", tuple(sorted(bindings.items()))))
    return tuple(result)


def _zpa_rule_rows(
    graph: GraphInventory, identity_uid: str, segment_uid: str, *, label: str = "ZpaAccessRule"
) -> list[dict[str, Any]]:
    """The ZpaAccessRule rows of the `_ACCESS_RULE_QUERY` of `path/gates/zpa.py`,
    read from the inventory. A row is a rule FOR the segment or one of its groups,
    or a rule with no application condition (app_scope any or other) whose `_scope`
    equals the `_scope` of the segment."""
    segment = graph.nodes.get(segment_uid)
    if segment is None:
        return []
    segment_targets = {segment_uid} | {item.uid for item in graph.targets(segment_uid, "MEMBER_OF")}
    segment_scope = segment.props.get("_scope")
    rows = []
    for uid in graph.labels.get(label, ()):
        rule = graph.nodes[uid]
        segment_named = bool({item.uid for item in graph.targets(uid, "FOR")} & segment_targets)
        rule_scope = rule.props.get("_scope")
        same_tenant = rule_scope is not None and segment_scope is not None and rule_scope == segment_scope
        if not segment_named and not (rule.props.get("app_scope") in ("any", "other") and same_tenant):
            continue
        named = {
            item.uid
            for rel in ("GRANTS", "DENIES", "APPLIES_TO")
            for item in graph.targets(uid, rel)
            if "IdentityGroup" in item.labels
        }
        props = rule.props
        rows.append(
            {
                "uid": uid,
                "name": props.get("name"),
                "position": props.get("position"),
                "action": props.get("action"),
                "applies_to_all_identities": props.get("applies_to_all_identities"),
                "conditions": props.get("conditions"),
                "action_raw": props.get("action_raw"),
                "operator": props.get("operator"),
                "enabled": props.get("enabled"),
                "disabled_raw": props.get("disabled_raw"),
                "identity_scope": props.get("identity_scope"),
                "app_scope": props.get("app_scope"),
                "segment_named": segment_named,
                "identity_named": identity_uid in named,
            }
        )
    return rows


def zpa_forwarding_decision(
    graph: GraphInventory, identity_uid: str, segment_uid: str
) -> zpa_policy.ForwardingDecision:
    """The client forwarding decision over the inventory, as path/gates/zpa.py
    reads it."""
    rows = _zpa_rule_rows(graph, identity_uid, segment_uid, label="ZpaClientForwardingRule")
    return zpa_policy.forwarding_decision(rows, identity_uid, segment_uid)


def zpa_rule_decision(
    graph: GraphInventory, identity_uid: str, segment_uid: str
) -> zpa_policy.AccessDecision:
    """The shared first-match decision (core/zpa_policy.py) over the inventory."""
    return zpa_policy.access_decision(
        _zpa_rule_rows(graph, identity_uid, segment_uid), identity_uid, segment_uid
    )


def expand_zpa_broker(
    graph: GraphInventory,
    context: ExecutionContext,
    identity_uid: str,
    segment_uid: str,
    downstream: StateKey,
) -> GateExpansion:
    """Compile a ZPA identity/segment decision and healthy connector choices."""
    segment = graph.nodes.get(segment_uid)
    identity = graph.nodes.get(identity_uid)
    key = StateKey(f"gate:zpa:{segment_uid}", context, "proxy")
    if not segment or "ZpaAppSegment" not in segment.labels or not identity:
        unknown = StateKey(f"gate:zpa:unknown:{segment_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec("zpa:missing", unknown),), complete=False),
                NodeSpec(unknown, terminal="unknown", complete=False),
            ),
            (),
            False,
            ("ZPA_IDENTITY_OR_SEGMENT_MISSING",),
        )
    groups = [g for g in graph.targets(segment.uid, "MEMBER_OF") if "ZpaSegmentGroup" in g.labels]
    state = zpa_policy.segment_state(
        {
            "enabled": segment.props.get("enabled"),
            "bypass_type": segment.props.get("bypass_type"),
            "group_enabled": False if any(g.props.get("enabled") is False for g in groups) else None,
        }
    )
    if state == "disabled":
        denied = StateKey(f"gate:zpa:deny:{segment_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec(f"zpa:segment-disabled:{segment_uid}", denied),)),
                NodeSpec(denied, terminal="deny"),
            ),
            (),
            True,
        )
    if state != "active":
        unknown = StateKey(f"gate:zpa:undecided:{segment_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec(f"zpa:not-brokered:{segment_uid}", unknown),), complete=False),
                NodeSpec(unknown, terminal="unknown", complete=False),
            ),
            (),
            False,
            ("ZPA_NOT_BROKERED",),
        )
    predicate = _zpa_segment_predicate(graph, segment, context.address_family)
    forwarding = zpa_forwarding_decision(graph, identity_uid, segment_uid)
    if not forwarding.go_on:
        rule_uid = forwarding.rule["uid"] if forwarding.rule else None
        unknown = StateKey(f"gate:zpa:undecided:{rule_uid or segment_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec(rule_uid or "zpa:forwarding", unknown, predicate),), complete=False),
                NodeSpec(unknown, terminal="unknown", complete=False),
            ),
            (),
            False,
            (forwarding.gap,) if forwarding.gap else (),
        )
    decision = zpa_rule_decision(graph, identity_uid, segment_uid)
    if decision.indeterminate:
        rule_uid = decision.rule["uid"] if decision.rule else None
        edge_name = rule_uid or (
            "zpa:rule-order" if decision.gap == zpa_policy.GAP_RULE_ORDER_UNKNOWN else "zpa:no-rule"
        )
        unknown = StateKey(f"gate:zpa:undecided:{rule_uid or segment_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec(edge_name, unknown, predicate),), complete=False),
                NodeSpec(unknown, terminal="unknown", complete=False),
            ),
            (),
            False,
            (decision.gap,) if decision.gap else (),
        )
    winner_uid = decision.rule["uid"] if decision.rule else segment_uid
    if decision.action == "deny":
        denied = StateKey(f"gate:zpa:deny:{winner_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec(winner_uid, denied, predicate),)),
                NodeSpec(denied, terminal="deny"),
            ),
            (),
            True,
        )
    # The connectors of the enabled groups. When the winning rule has STEERS_VIA
    # targets, only the connectors of those servers and groups count.
    # path/gates/zpa.py chooses the connectors in the same way.
    named = {g.uid for g in graph.targets(winner_uid, "STEERS_VIA")} if decision.rule else set()
    connectors: list[GraphNode] = []
    for server in graph.targets(segment.uid, "SERVED_BY"):
        if server.props.get("enabled") is False:
            continue
        for group in graph.targets(server.uid, "USES"):
            if group.props.get("enabled") is False:
                continue
            if named and server.uid not in named and group.uid not in named:
                continue
            connectors.extend(c for c in graph.targets(group.uid, "HAS") if c not in connectors)
    if connectors and all(c.props.get("enabled") is False for c in connectors):
        denied = StateKey(f"gate:zpa:deny:{segment_uid}", context, "proxy")
        return GateExpansion(
            key,
            (
                NodeSpec(key, (EdgeSpec(f"zpa:connectors-disabled:{segment_uid}", denied, predicate),)),
                NodeSpec(denied, terminal="deny"),
            ),
            (),
            True,
        )
    edges, assignments, gaps = [], [], set()
    for connector in connectors:
        health = str(connector.props.get("health") or "").lower()
        # `enabled` is configuration. A connector that is switched off cannot
        # serve at any collected health value (as in path/gates/zpa.py).
        if connector.props.get("enabled") is False or health in {"down", "unhealthy", "disabled"}:
            continue
        if health not in {"up", "healthy", "enabled"}:
            gaps.add("ZPA_CONNECTOR_HEALTH_UNKNOWN")
            continue
        addresses = _connector_addresses(graph, connector, context.address_family)
        if not addresses:
            gaps.add("ZPA_CONNECTOR_ADDRESS_UNKNOWN")
            continue
        scope = f"zpa:{context.authority}:{segment.uid}"
        for address in addresses:
            choice = f"{connector.uid}:{address}"
            assignments.append(ChoiceAssignment(f"{scope}:{choice}", ((scope, choice),)))
            edges.append(
                EdgeSpec(choice, downstream, predicate, (("source_address", address),), ((scope, choice),))
            )
    nodes = []
    if not edges:
        gaps.add("ZPA_CONNECTOR_UNAVAILABLE")
    if gaps or not edges:
        unknown = StateKey(f"gate:zpa:connector-unknown:{segment.uid}", context, "proxy")
        nodes.append(NodeSpec(unknown, terminal="unknown", complete=False))
        edges.append(EdgeSpec("zpa:connector-unknown", unknown, predicate))
    nodes.append(NodeSpec(key, tuple(edges), complete=not gaps))
    return GateExpansion(key, tuple(nodes), tuple(assignments), not gaps, tuple(sorted(gaps)))


def expand_aci_contracts(
    graph: GraphInventory,
    context: ExecutionContext,
    downstream: StateKey,
    *,
    sources: tuple[tuple[int, int, int], ...] | None = None,
    destinations: tuple[tuple[int, int, int], ...] | None = None,
    redirect_targets: Mapping[str, StateKey] | None = None,
) -> GateExpansion:
    """Compile known ACI EPG-pair contracts with implicit deny.

    A contract decision depends only on the EPG of each endpoint. The endpoint
    addresses are grouped by EPG. The union of the source x destination address
    products of a group is the product of the unions. The edges and terminal
    states grow with the EPG pairs that hold a contract and with the EPGs. The
    EPG pairs without a contract of one source EPG share one edge per outcome.

    The governing VRF decides as in path/gates/aci.py (core/aci_filter.py
    `vrf_enforcement`). An unenforced VRF shared by both EPGs permits the pair
    before any contract is consulted. When the enforcement mode cannot be
    determined for the pair, the flows that no contract permits are unknown.

    An address that no endpoint and no subnet of a fabric holds has the
    external EPG of the VRF whose longest subnet matches it
    (`_AciIndex._scope`). A flow with 1 end at an endpoint and no EPG and no
    external EPG at its other end is unknown.

    The gates run where the request enters. The first gate is the gate of
    `context.vrf`, with the endpoints scoped to that VRF (`_AciIndex.scope`). A
    source endpoint is one of that VRF. A destination is an endpoint of a VRF
    of the same fabric or an external EPG of the fabric. 1 gate for each other
    fabric follows (`_AciIndex.external_scopes`). It judges the packets to an
    endpoint of that fabric, and their source is an external EPG of that
    fabric. An address that two EPGs of one side hold is unknown, as an
    endpoint with several EPG identities is in the trace and the symbolic gate.

    A contract with a service graph redirects the packets that its filter
    permits to the destination of the redirect policy of its consumer connector
    (`_aci_contract_redirect`). `redirect_targets` holds the state of each
    destination address. The pair is unknown when the redirect is not
    established, when a second contract joins the pair, when an address has no
    state, and in the gate of another fabric.

    The EPG index is built once per graph. With the `sources` and `destinations`
    of the request given, a request whose sources hold no source endpoint and
    whose destinations hold no destination endpoint passes the gate without
    expanding it. Every packet of such a request is non-endpoint.
    """
    index = _aci_index(graph, context.address_family)
    if not index.epg_intervals:
        return GateExpansion(downstream, (), (), True)
    af = context.address_family
    entry = downstream
    nodes: list[NodeSpec] = []
    gap_refs: set[str] = set()
    for scope in reversed((index.scope(context.vrf), *index.external_scopes(context.vrf))):
        if not scope.source_all and not scope.destination_endpoint_all:
            continue
        if (
            sources is not None
            and destinations is not None
            and not _intervals_meet(
                scope.source_all if scope.external is None else (),
                [(lo, hi) for family, lo, hi in sources if family == af],
            )
            and not _intervals_meet(
                scope.destination_endpoint_all, [(lo, hi) for family, lo, hi in destinations if family == af]
            )
        ):
            continue
        expansion = _expand_aci_scope(graph, index, scope, context, entry, redirect_targets or {})
        entry = expansion.entry
        nodes.extend(expansion.nodes)
        gap_refs.update(expansion.gaps)
    return GateExpansion(entry, tuple(nodes), (), not gap_refs, tuple(sorted(gap_refs)))


def _expand_aci_scope(
    graph: GraphInventory,
    index: _AciIndex,
    scope: _AciScope,
    context: ExecutionContext,
    downstream: StateKey,
    redirect_targets: Mapping[str, StateKey],
) -> GateExpansion:
    """The gate of 1 scope of `expand_aci_contracts`."""
    where = context.vrf if scope.external is None else f"{context.vrf}:external:{scope.external}"
    key = StateKey(f"gate:aci:{where}", context, "aci-contract")
    edges: list[EdgeSpec] = []
    terminals: list[NodeSpec] = []
    gaps: set[str] = set()
    source_side, destination_side = scope.source_predicates, scope.destination_predicates
    # The flows that no contract permits, for the EPG pairs whose enforcement mode is not known.
    undecided: list[Predicate] = []
    # The flows that no contract permits in an enforced VRF where an input
    # that no gate evaluates may permit the pair. Such an input is a contract
    # in the reverse orientation, vzAny, the preferred group or an ESG.
    reversed_pairs: list[Predicate] = []
    bypassed: list[Predicate] = []
    for source_epg in sorted(source_side):
        source = source_side[source_epg]
        source_vrf, pref = index.epg_vrf[source_epg]
        bypass = index.epg_bypass[source_epg]
        # the EPGs that consume a contract this EPG provides
        reverse = {
            consumer
            for contract in index.provides.get(source_epg, frozenset())
            for consumer in index.consumers.get(contract, ())
        } - {source_epg}
        consumed = index.consumes.get(source_epg, frozenset())
        same_vrf = scope.vrf_destinations.get(source_vrf, frozenset()) if source_vrf else frozenset()
        same_vrf_destinations = scope.vrf_predicates[source_vrf] if source_vrf and same_vrf else None
        mode = vrf_enforcement(source_vrf, source_vrf, pref)
        contracted = {
            provider for contract in consumed for provider in index.providers.get(contract, ())
        } & destination_side.keys()
        contracted.discard(source_epg)
        if mode == "unenforced":
            # the VRF permits every pair inside it before any contract is consulted
            contracted -= same_vrf
        if source_epg in destination_side:
            unknown = StateKey(f"gate:aci:intra:{source_epg}", context, "aci-contract")
            terminals.append(NodeSpec(unknown, terminal="unknown", complete=False))
            edges.append(
                EdgeSpec(f"aci:intra:{source_epg}", unknown, AllOf((source, destination_side[source_epg])))
            )
            gaps.add("ACI_INTRA_EPG_ISOLATION_UNKNOWN")
        for destination_epg in sorted(contracted):
            pair = AllOf((source, destination_side[destination_epg]))
            label = f"{source_epg}:{destination_epg}"
            contracts = consumed & index.provides.get(destination_epg, frozenset())
            enforcement = vrf_enforcement(source_vrf, index.epg_vrf[destination_epg][0], pref)
            filters = [index.contract_filter(graph, uid) for uid in sorted(contracts)]
            permitted, kind = downstream, "permit"
            if any(index.has_graph(graph, uid) for uid in contracts):
                # the consumer connector of the 1 contract of the pair
                redirect = (
                    index.redirect(graph, next(iter(contracts)))
                    if len(contracts) == 1 and scope.external is None
                    else None
                )
                if redirect is not None and all(address in redirect_targets for address in redirect):
                    permitted, kind = redirect_targets[redirect[0]], "redirect"
                    filters = [index.graph_filter(graph, next(iter(contracts)))]
                else:
                    filters = [None]
            if filters and all(predicate is not None for predicate in filters):
                allowed = AnyOf(tuple(predicate for predicate in filters if predicate is not None))
                edges.append(EdgeSpec(f"aci:{kind}:{label}", permitted, AllOf((pair, allowed))))
                if enforcement == "enforced" and bypass:
                    bypassed.append(AllOf((pair, Not(allowed))))
                elif enforcement == "enforced" and destination_epg in reverse:
                    reversed_pairs.append(AllOf((pair, Not(allowed))))
                elif enforcement == "enforced":
                    denied = StateKey(f"gate:aci:filter-deny:{label}", context, "aci-contract")
                    terminals.append(NodeSpec(denied, terminal="deny"))
                    edges.append(EdgeSpec(f"aci:filter-deny:{label}", denied, AllOf((pair, Not(allowed)))))
                else:
                    undecided.append(AllOf((pair, Not(allowed))))
                continue
            unknown = StateKey(f"gate:aci:filter-unknown:{label}", context, "aci-contract")
            terminals.append(NodeSpec(unknown, terminal="unknown", complete=False))
            edges.append(EdgeSpec(f"aci:unknown:{label}", unknown, pair))
            gaps.add("ACI_CONTRACT_FILTER_UNKNOWN")
        # The destination EPGs of one side hold disjoint addresses. The
        # destinations of this VRF less those of the contracted EPGs and of the
        # own EPG equal the union of the uncontracted EPGs.
        own = (destination_side[source_epg],) if source_epg in destination_side else ()
        decided_same = tuple(destination_side[epg] for epg in sorted(contracted & same_vrf))
        # same_vrf is empty whenever same_vrf_destinations is None
        if same_vrf_destinations is not None and same_vrf - contracted - {source_epg}:
            excluded = (*decided_same, *own)
            guard: Predicate = AllOf(
                (source, same_vrf_destinations, *((Not(AnyOf(excluded)),) if excluded else ()))
            )
            uncontracted = same_vrf - contracted - {source_epg}
            reverse_same = uncontracted & reverse
            if mode == "enforced" and bypass:
                bypassed.append(guard)
            elif mode == "enforced":
                if reverse_same:
                    reversed_pairs.append(
                        AllOf((source, AnyOf(tuple(destination_side[epg] for epg in sorted(reverse_same)))))
                    )
                if uncontracted - reverse_same:
                    if reverse_same:
                        excluded = (*excluded, *(destination_side[epg] for epg in sorted(reverse_same)))
                        guard = AllOf((source, same_vrf_destinations, Not(AnyOf(excluded))))
                    denied = StateKey(f"gate:aci:deny:{source_epg}", context, "aci-contract")
                    terminals.append(NodeSpec(denied, terminal="deny"))
                    edges.append(EdgeSpec(f"aci:deny:{source_epg}", denied, guard))
            elif mode == "unenforced":
                edges.append(EdgeSpec(f"aci:unenforced:{source_epg}", downstream, guard))
            else:
                undecided.append(guard)
        if destination_side.keys() - same_vrf - contracted - {source_epg}:
            excluded = (
                *((same_vrf_destinations,) if same_vrf_destinations is not None else ()),
                *(destination_side[epg] for epg in sorted(contracted - same_vrf)),
                *(own if source_epg not in same_vrf else ()),
            )
            undecided.append(
                AllOf(
                    (
                        source,
                        scope.destination_exclusive,
                        *((Not(AnyOf(excluded)),) if excluded else ()),
                    )
                )
            )
    if undecided:
        unknown = StateKey(f"gate:aci:enforcement-unknown:{where}", context, "aci-contract")
        terminals.append(NodeSpec(unknown, terminal="unknown", complete=False))
        edges.append(EdgeSpec("aci:enforcement-unknown", unknown, AnyOf(tuple(undecided))))
        gaps.add("ACI_VRF_ENFORCEMENT_UNKNOWN")
    if reversed_pairs:
        unknown = StateKey(f"gate:aci:reverse-contract:{where}", context, "aci-contract")
        terminals.append(NodeSpec(unknown, terminal="unknown", complete=False))
        edges.append(EdgeSpec("aci:reverse-contract", unknown, AnyOf(tuple(reversed_pairs))))
        gaps.add("ACI_REVERSE_CONTRACT_UNEVALUATED")
    if bypassed:
        unknown = StateKey(f"gate:aci:contract-bypass:{where}", context, "aci-contract")
        terminals.append(NodeSpec(unknown, terminal="unknown", complete=False))
        edges.append(EdgeSpec("aci:contract-bypass", unknown, AnyOf(tuple(bypassed))))
        gaps.add("ACI_CONTRACT_BYPASS_UNKNOWN")
    any_source, any_destination = scope.source_any, scope.destination_any
    if scope.source_all and scope.destination_all and scope.ambiguous is not None:
        # the endpoint pairs above leave out the addresses two EPGs of one side hold
        ambiguous = StateKey(f"gate:aci:ambiguous:{where}", context, "aci-contract")
        terminals.append(NodeSpec(ambiguous, terminal="unknown", complete=False))
        edges.append(
            EdgeSpec("aci:ambiguous", ambiguous, AllOf((any_source, any_destination, scope.ambiguous)))
        )
        gaps.add("ACI_ENDPOINT_IDENTITY_UNKNOWN")
    # The endpoint pairs and the ambiguous addresses cover exactly the product
    # of all sources and all destinations. An address that an external EPG
    # classifies is a source or a destination. A flow with exactly 1 end at
    # an endpoint and no class at its other end is unknown, as in
    # path/gates/aci.py. An external scope judges only the packets to an
    # endpoint of its fabric.
    to_endpoint = scope.destination_endpoint_any
    if scope.external is None:
        edges.append(EdgeSpec("aci:non-endpoint", downstream, AllOf((Not(any_source), Not(to_endpoint)))))
        one_end_guard: Predicate = AnyOf(
            (AllOf((any_source, Not(any_destination))), AllOf((Not(any_source), to_endpoint)))
        )
    else:
        edges.append(EdgeSpec("aci:non-endpoint", downstream, Not(to_endpoint)))
        one_end_guard = AllOf((Not(any_source), to_endpoint))
    one_end = StateKey(f"gate:aci:one-endpoint:{where}", context, "aci-contract")
    terminals.append(NodeSpec(one_end, terminal="unknown", complete=False))
    edges.append(EdgeSpec("aci:one-endpoint", one_end, one_end_guard))
    gaps.add("ACI_ONE_ENDPOINT_UNKNOWN")
    # The unknown EPG pairs end in their own unknown terminals.
    return GateExpansion(
        key, (*terminals, NodeSpec(key, tuple(edges), complete=True)), (), not gaps, tuple(sorted(gaps))
    )


def expand_aci_reply_redirects(
    graph: GraphInventory,
    context: ExecutionContext,
    downstream: StateKey,
    redirect_targets: Mapping[str, StateKey],
) -> GateExpansion:
    """Redirect the replies of the EPG pairs whose contract has a service graph.

    The reply of a pair enters in the VRF of the provider EPG. The gate sends
    the packets from the provider EPG to the consumer EPG to the destination
    of the redirect policy of the provider connector. Each other packet goes
    to `downstream`. The pairs are those that `expand_aci_contracts`
    redirects. Such a pair has 1 contract, and each packet that the forward
    gate permits for the pair is redirected."""
    index = _aci_index(graph, context.address_family)
    if not index.epg_intervals or not redirect_targets:
        return GateExpansion(downstream, (), (), True)
    scope = index.scope(context.vrf)
    edges: list[EdgeSpec] = []
    claimed: list[Predicate] = []
    for provider in sorted(scope.source_predicates):
        for contract in sorted(index.provides.get(provider, frozenset())):
            redirect = index.redirect(graph, contract) if index.has_graph(graph, contract) else None
            if redirect is None or not all(address in redirect_targets for address in redirect):
                continue
            known = index.graph_filter(graph, contract) is not None
            for consumer in sorted(index.consumers.get(contract, frozenset())):
                if (
                    not known
                    or consumer == provider
                    or consumer not in scope.destination_predicates
                    or index.consumes[consumer] & index.provides[provider] != {contract}
                ):
                    continue
                predicate = AllOf((scope.source_predicates[provider], scope.destination_predicates[consumer]))
                edges.append(
                    EdgeSpec(
                        f"aci:reply-redirect:{provider}:{consumer}", redirect_targets[redirect[1]], predicate
                    )
                )
                claimed.append(predicate)
    if not edges:
        return GateExpansion(downstream, (), (), True)
    key = StateKey(f"gate:aci:reply-redirect:{downstream.location}", context, "aci-contract")
    edges.append(EdgeSpec("aci:reply-direct", downstream, Not(AnyOf(tuple(claimed)))))
    return GateExpansion(key, (NodeSpec(key, tuple(edges), complete=True),), (), True)


def aci_fabric_contexts(graph: GraphInventory, af: int) -> frozenset[str]:
    """The VRFs of the ACI fabrics of the graph."""
    return _aci_index(graph, af).aci_vrfs


def _next(context: ExecutionContext) -> StateKey:
    return StateKey("@next", context)


def _nat_edges(
    rules: tuple[NatRuleSpec, ...], context: ExecutionContext, device: str, stage: str
) -> tuple[tuple[EdgeSpec, ...], tuple[NodeSpec, ...], tuple[str, ...]]:
    previous: list[Predicate] = []
    edges: list[EdgeSpec] = []
    terminals: list[NodeSpec] = []
    gaps: set[str] = set()
    for rule in rules:
        claim = AllOf((rule.predicate, Not(AnyOf(tuple(previous)))))
        previous.append(rule.predicate)
        if rule.gap_code:
            terminal = StateKey(f"gate:{device}:{stage}:unknown:{rule.uid}", context, stage)
            terminals.append(NodeSpec(terminal, terminal="unknown", complete=False))
            edges.append(EdgeSpec(rule.uid, terminal, claim))
            gaps.add(rule.gap_code)
        else:
            edges.append(
                EdgeSpec(
                    rule.uid,
                    _next(context),
                    claim,
                    () if rule.exclude else rule.rewrites,
                    ranges=() if rule.exclude else rule.ranges,
                )
            )
    edges.append(EdgeSpec(f"{stage}:fallthrough", _next(context), Not(AnyOf(tuple(previous)))))
    return tuple(edges), tuple(terminals), tuple(sorted(gaps))


def _pbr_edges(
    graph: GraphInventory,
    context: ExecutionContext,
    device: str,
    ingress: str | None,
    routing_targets: Mapping[str, StateKey],
) -> tuple[tuple[EdgeSpec, ...], tuple[NodeSpec, ...], tuple[str, ...]]:
    if not ingress:
        interfaces = graph.sources(device, "ON")
        if any(
            "PbrPolicy" in policy.labels
            for interface in interfaces
            for policy in graph.targets(interface.uid, "ENFORCES")
        ):
            terminal = StateKey(f"gate:{device}:pbr:interface-unknown", context, "pbr")
            return (
                (EdgeSpec("pbr:interface-unknown", terminal),),
                (NodeSpec(terminal, terminal="unknown", complete=False),),
                ("PBR_INGRESS_INTERFACE_UNKNOWN",),
            )
        return (), (), ()
    policies = graph.targets(ingress, "ENFORCES")
    policies = tuple(policy for policy in policies if "PbrPolicy" in policy.labels)
    if not policies:
        return (), (), ()
    edges: list[EdgeSpec] = []
    terminals: list[NodeSpec] = []
    previous: list[Predicate] = []
    gaps: set[str] = set()
    # The order of the PBR read of the trace (gates/pbr._PBR_RULE_ROWS). Policies
    # sort by name, rules sort by position, and a disabled rule is left out.
    for policy in sorted(policies, key=lambda p: (str(p.props.get("name") or ""), p.uid)):
        rules = sorted(graph.targets(policy.uid, "HAS_RULE"), key=lambda n: _position(n))
        for rule in rules:
            if rule.props.get("enabled") is False:
                continue
            predicate = _rule_predicate(graph, rule, context.address_family, policy)
            claim = AllOf((predicate, Not(AnyOf(tuple(previous)))))
            previous.append(predicate)
            targets = graph.targets(rule.uid, "REDIRECTS_VIA")
            if len(targets) == 1 and targets[0].uid in routing_targets:
                target = routing_targets[targets[0].uid]
            else:
                target = StateKey(f"gate:{device}:pbr:unknown:{rule.uid}", context, "pbr")
                terminals.append(NodeSpec(target, terminal="unknown", complete=False))
                gaps.add("PBR_TARGET_UNKNOWN")
            edges.append(EdgeSpec(rule.uid, target, claim))
    edges.append(EdgeSpec("pbr:default", _next(context), Not(AnyOf(tuple(previous)))))
    return tuple(edges), tuple(terminals), tuple(sorted(gaps))


def _load_balancer_edges(
    graph: GraphInventory,
    context: ExecutionContext,
    device: str,
    reroute: StateKey | None,
    choices_so_far: tuple[ChoiceAssignment, ...] = (),
    max_choices: int | None = None,
):
    """The VIP edges of every virtual service on the device or its group.

    A service with live members is one choice scope, and the scopes of a
    device multiply. A scope that `choices_so_far` already binds (the same
    service on another FIB row) adds no choices. A new scope is kept while the
    product of the catalogue and the new scopes stays within `max_choices`.
    A service past the limit keeps its claim on its VIP, toward an unknown
    terminal (LOAD_BALANCER_CHOICE_CUTOFF). Traffic to other addresses stays
    decided."""
    services = []
    owners = {device, *(node.uid for node in graph.targets(device, "MEMBER_OF"))}
    for uid in graph.labels.get("VirtualService", ()):
        service = graph.nodes[uid]
        if any(target.uid in owners for target in graph.targets(uid, "ON")):
            services.append(service)
    edges, terminals, gaps = [], [], set()
    choices: tuple[ChoiceAssignment, ...] = (ChoiceAssignment("gates:only"),)
    claims: list[Predicate] = []
    bound = {scope for assignment in choices_so_far for scope, _value in assignment.bindings}
    budget = max_choices // max(len(choices_so_far), 1) if max_choices is not None else None
    product_size = 1
    for service in services:
        predicate = _virtual_service_predicate(graph, service, context.address_family)
        claims.append(predicate)
        members: list[GraphNode] = []
        for pool in graph.targets(service.uid, "USES"):
            members.extend(graph.targets(pool.uid, "HAS_MEMBER"))
        live = [
            member for member in members if str(member.props.get("state") or "").lower() in {"up", "enabled"}
        ]
        unknown = [
            member
            for member in members
            if str(member.props.get("state") or "").lower() not in {"up", "enabled", "down", "disabled"}
        ]
        if not live and not unknown:
            terminal = StateKey(f"gate:{device}:lb:down:{service.uid}", context, "load-balancer")
            pools = graph.targets(service.uid, "USES")
            complete = bool(pools) and all(_complete_collection(pool) for pool in pools)
            terminals.append(
                NodeSpec(terminal, terminal="deny" if complete else "unknown", complete=complete)
            )
            edges.append(EdgeSpec(service.uid, terminal, predicate))
            if not complete:
                gaps.add("LOAD_BALANCER_POOL_COVERAGE_UNKNOWN")
            continue
        scope = f"lb:{context.authority}:{context.domain}:{service.uid}"
        targeted = []
        for member in live:
            address = _single_address(graph.targets(member.uid, "TARGETS"), context.address_family)
            if address is None:
                unknown.append(member)
            else:
                targeted.append((member, address))
        new_scope = bool(targeted) and scope not in bound
        if new_scope and budget is not None and product_size * len(targeted) > budget:
            terminal = StateKey(f"gate:{device}:lb:choice-cutoff:{service.uid}", context, "load-balancer")
            terminals.append(NodeSpec(terminal, terminal="unknown", complete=False))
            edges.append(EdgeSpec(f"{service.uid}:choice-cutoff", terminal, predicate))
            gaps.add("LOAD_BALANCER_CHOICE_CUTOFF")
            continue
        assignments = []
        for member, address in targeted:
            choice = f"member:{member.uid}"
            assignments.append(ChoiceAssignment(f"{scope}:{choice}", ((scope, choice),)))
            rewrites = [("destination_address", address)]
            if type(member.props.get("port")) is int:
                rewrites.append(("destination_port", int(member.props["port"])))
            edges.append(
                EdgeSpec(
                    f"{service.uid}:{member.uid}",
                    reroute
                    or StateKey(
                        f"gate:{device}:lb:reroute-unknown:{service.uid}",
                        context,
                        "load-balancer",
                    ),
                    predicate,
                    tuple(rewrites),
                    ((scope, choice),),
                )
            )
        if assignments and reroute is None:
            target = StateKey(f"gate:{device}:lb:reroute-unknown:{service.uid}", context, "load-balancer")
            terminals.append(NodeSpec(target, terminal="unknown", complete=False))
            gaps.add("LOAD_BALANCER_REROUTE_UNKNOWN")
        if assignments and new_scope:
            product_size *= len(assignments)
            choices = merge_choice_assignments(choices, tuple(assignments))
        if unknown:
            terminal = StateKey(f"gate:{device}:lb:unknown:{service.uid}", context, "load-balancer")
            terminals.append(NodeSpec(terminal, terminal="unknown", complete=False))
            edges.append(EdgeSpec(f"{service.uid}:unknown-health", terminal, predicate))
            gaps.add("LOAD_BALANCER_MEMBER_HEALTH_UNKNOWN")
    if services:
        edges.append(EdgeSpec("load-balancer:fallthrough", _next(context), Not(AnyOf(tuple(claims)))))
    # Without a new scope, the catalogue of the caller holds every choice, and no choices are returned.
    return tuple(edges), tuple(terminals), choices if len(choices[0].bindings) else (), tuple(sorted(gaps))


def _tunnel_edges(
    graph: GraphInventory,
    context: ExecutionContext,
    device: str,
    egress: str | None,
    tunnel_targets: Mapping[str, StateKey],
):
    if not egress:
        bound = [
            tunnel
            for interface in graph.sources(device, "ON")
            for tunnel in graph.sources(interface.uid, "ENDPOINT")
            if "Tunnel" in tunnel.labels
        ]
        if bound:
            target = StateKey(f"gate:{device}:tunnel:interface-unknown", context, "tunnel")
            return (
                (EdgeSpec("tunnel:interface-unknown", target),),
                (NodeSpec(target, terminal="unknown", complete=False),),
                ("TUNNEL_EGRESS_INTERFACE_UNKNOWN",),
            )
        return (), (), ()
    tunnels = graph.sources(egress, "ENDPOINT")
    tunnels = tuple(node for node in tunnels if "Tunnel" in node.labels)
    edges, terminals, gaps = [], [], set()
    for tunnel in tunnels:
        state = str(tunnel.props.get("state") or "unknown").lower()
        if state in {"down", "disabled"}:
            target = StateKey(f"gate:{device}:tunnel:down:{tunnel.uid}", context, "tunnel")
            terminals.append(NodeSpec(target, terminal="no_route"))
        elif state not in {"up", "established"} or not graph.targets(tunnel.uid, "TERMINATES_ON"):
            target = StateKey(f"gate:{device}:tunnel:unknown:{tunnel.uid}", context, "tunnel")
            terminals.append(NodeSpec(target, terminal="unknown", complete=False))
            gaps.add("TUNNEL_CARRIER_UNKNOWN")
        elif tunnel.uid in tunnel_targets:
            target = tunnel_targets[tunnel.uid]
        else:
            target = StateKey(f"gate:{device}:tunnel:underlay-unknown:{tunnel.uid}", context, "tunnel")
            terminals.append(NodeSpec(target, terminal="unknown", complete=False))
            gaps.add("TUNNEL_UNDERLAY_ROUTE_UNKNOWN")
        edges.append(EdgeSpec(tunnel.uid, target, Constant(True)))
    return tuple(edges), tuple(terminals), tuple(sorted(gaps))


def _address_specs(graph: GraphInventory, node: GraphNode) -> list[str]:
    """The address specs of one SRC or DST target, as the PBR read of the trace
    takes them (path/gates/pbr.py). The specs are the ip or cidr of the node and,
    for a NetObject, the ip or cidr of each RESOLVES_TO target and the `ranges`
    of the NetObject."""
    specs = [str(value) for value in (node.props.get("ip"), node.props.get("cidr")) if value]
    if "NetObject" in node.labels:
        for target in graph.targets(node.uid, "RESOLVES_TO"):
            specs.extend(str(value) for value in (target.props.get("ip"), target.props.get("cidr")) if value)
        ranges = node.props.get("ranges")
        if isinstance(ranges, (list, tuple)):
            specs.extend(str(value) for value in ranges if value)
    return specs


def _pbr_rule_row(graph: GraphInventory, rule: GraphNode, policy: GraphNode | None) -> dict[str, Any]:
    """One PBR rule in the row shape that `gates/pbr._PBR_RULE_ROWS` returns and
    `partition_rules` reads. The row holds the address side only. `_rule_predicate`
    reads the service side. Every address spec of a side goes in its `cidrs` list,
    and `partition_rules` parses that list as one list."""
    row: dict[str, Any] = {
        "pol_uid": None if policy is None else policy.uid,
        "pol_name": None if policy is None else policy.props.get("name"),
        "pol_af": None if policy is None else policy.props.get("af"),
        "rule_uid": rule.uid,
        "pos": rule.props.get("position"),
        "states_opaque": bool(rule.props.get("states_opaque")),
        "states_opaque_reason": rule.props.get("states_opaque_reason"),
        "src_negate": bool(rule.props.get("src_negate")),
        "dst_negate": bool(rule.props.get("dst_negate")),
        "addr_opaque_reasons": [],
    }
    for relation, side in (("SRC", "src"), ("DST", "dst")):
        targets = graph.targets(rule.uid, relation)
        row[f"{side}_cidrs"] = [spec for target in targets for spec in _address_specs(graph, target)]
        row[f"{side}_obj_count"] = len(targets)
        row["addr_opaque_reasons"].extend(
            str(t.props["opaque_reason"]) for t in targets if t.props.get("opaque_reason")
        )
    return row


def _rule_predicate(
    graph: GraphInventory, rule: GraphNode, af: int, policy: GraphNode | None = None
) -> Predicate:
    """The flows that one PBR rule claims, in family `af`.

    The address side is the reading of the trace (`gates/pbr.partition_rules`
    over the whole family). The reading covers negation, the address family of
    the policy, and a rule that it leaves undecided (a clause the collector
    could not model, an unresolved address object, a side with objects and no
    address). An undecided rule becomes an Unknown term with the reason."""
    from hst.path.addrsets import _ALL_PROTOS, _ports, _protoset
    from hst.path.gates.firewall import _OPAQUE_SVC_FALLBACK, _SRC_PORT_REASON
    from hst.path.gates.pbr import partition_rules

    terms: list[Predicate] = []
    row = _pbr_rule_row(graph, rule, policy)
    universe = [(af, 0, (1 << (32 if af == 4 else 128)) - 1)]
    claim = next((g for g in partition_rules([row], universe, universe, None) if g["rule_uid"]), None)
    if claim is None:
        # the rule claims no flow of this family
        return Constant(False)
    for field, values in (("source_address", claim["sources"]), ("destination_address", claim["dst"])):
        if list(values) != universe:
            terms.append(AnyOf(tuple(Atom(field, "range", lo, hi) for _family, lo, hi in values)))
    # A side whose targets partly parse is read over the targets that parse,
    # as the trace reads it. A flow outside them is a decided miss. An
    # undecided claim (below) covers only the flows inside them.
    if claim["opaque"]:
        code = "PBR_RULE_MATCH_UNKNOWN" if row["states_opaque"] else "RULE_ADDRESS_SELECTOR_UNKNOWN"
        terms.append(Unknown(code, rule.uid, (str(claim["opaque_reason"]),)))
    services = graph.targets(rule.uid, "SVC")
    service_terms: list[Predicate] = []
    for service in services:
        selected: list[Predicate] = []
        # Any other spelling is read as the tracer reads it (`pbr._service_state`).
        # Examples are a VyOS `tcp_udp` and a list of port tokens (frozen to a tuple).
        proto_value, ports_value = service.props.get("proto"), service.props.get("ports")
        proto = {"tcp": 6, "udp": 17}.get(str(proto_value or "").lower())
        if proto is not None:
            selected.append(Atom("protocol", "eq", proto))
        elif proto_value is not None:
            try:
                protocols = _protoset([str(proto_value)])
                if protocols is None:
                    raise ValueError("protocol is not explicit")
                selected.append(
                    Constant(True)
                    if protocols == _ALL_PROTOS
                    else AnyOf(tuple(Atom("protocol", "eq", n) for n in sorted(protocols)))
                )
            except ValueError:
                selected.append(Unknown("RULE_SERVICE_PROTOCOL_UNKNOWN", service.uid))
        if type(ports_value) is int:
            selected.append(Atom("destination_port", "eq", int(ports_value)))
        elif ports_value is not None:
            try:
                intervals = _ports(ports_value)
                if not intervals:
                    raise ValueError("empty service port expression")
                selected.append(
                    AnyOf(tuple(Atom("destination_port", "range", lo, hi) for _af, lo, hi in intervals))
                )
            except (ValueError, TypeError):
                selected.append(Unknown("RULE_SERVICE_PORT_UNKNOWN", service.uid))
        if not selected:
            selected.append(Unknown("RULE_SERVICE_UNKNOWN", service.uid))
        service_terms.append(AllOf(tuple(selected)))
    if service_terms:
        # The precedence of `gates/pbr._service_state`. A member that the
        # collector could not map makes a miss of the known members undecided.
        # A source port scope makes a match undecided (the tuple of the trace
        # has no source port). A miss over the known members stays a miss.
        opaque = [s for s in services if s.props.get("opaque") is True]
        if opaque:
            reasons = "; ".join(
                dict.fromkeys(str(s.props["opaque_reason"]) for s in opaque if s.props.get("opaque_reason"))
            )
            service_terms.append(
                Unknown("RULE_SERVICE_UNKNOWN", rule.uid, (reasons or _OPAQUE_SVC_FALLBACK,))
            )
        service_side: Predicate = AnyOf(tuple(service_terms))
        if any(str(s.props.get("src_port") or "") for s in services):
            service_side = AllOf(
                (service_side, Unknown("RULE_SERVICE_SOURCE_PORT_UNKNOWN", rule.uid, (_SRC_PORT_REASON,)))
            )
        terms.append(service_side)
    return AllOf(tuple(terms))


def _virtual_service_predicate(graph: GraphInventory, service: GraphNode, af: int) -> Predicate:
    terms: list[Predicate] = []
    addresses = []
    for node in graph.targets(service.uid, "VIP"):
        addresses.extend(_node_intervals(node, af))
    if addresses:
        terms.append(AnyOf(tuple(Atom("destination_address", "range", lo, hi) for lo, hi in addresses)))
    proto = {"tcp": 6, "udp": 17}.get(str(service.props.get("proto") or "").lower())
    if proto is not None:
        terms.append(Atom("protocol", "eq", proto))
    if type(service.props.get("port")) is int:
        terms.append(Atom("destination_port", "eq", int(service.props["port"])))
    return AllOf(tuple(terms)) if terms else Unknown("VIRTUAL_SERVICE_MATCH_UNKNOWN", service.uid)


def _node_intervals(node: GraphNode, af: int) -> list[tuple[int, int]]:
    result = []
    for raw in (node.props.get("ip"), node.props.get("cidr")):
        if raw:
            try:
                network = ipaddress.ip_network(str(raw), strict=False)
                if network.version == af:
                    result.append((int(network.network_address), int(network.broadcast_address)))
            except ValueError:
                pass
    return result


def _single_address(nodes: tuple[GraphNode, ...], af: int) -> int | None:
    values = [lo for node in nodes for lo, hi in _node_intervals(node, af) if lo == hi]
    return values[0] if len(set(values)) == 1 else None


def _complete_collection(node: GraphNode) -> bool:
    return node.props.get("coverage") in {"complete", "complete-empty", "ok", "empty"}


def _connector_addresses(graph: GraphInventory, connector: GraphNode, af: int) -> tuple[int, ...]:
    values: list[int] = []
    for host in graph.targets(connector.uid, "RUNS_ON"):
        interfaces = graph.sources(host.uid, "OF")
        for interface in interfaces:
            for address in graph.targets(interface.uid, "HAS_IP"):
                values.extend(lo for lo, hi in _node_intervals(address, af) if lo == hi)
        for address in graph.targets(host.uid, "HAS_IP"):
            values.extend(lo for lo, hi in _node_intervals(address, af) if lo == hi)
    if not values and connector.props.get("private_ip"):
        # No RUNS_ON target gives an address. The `private_ip` of the connector is the address.
        own = GraphNode(f"{connector.uid}:private_ip", frozenset(), {"ip": connector.props["private_ip"]})
        values.extend(lo for lo, hi in _node_intervals(own, af) if lo == hi)
    return tuple(sorted(set(values)))


def _merge_intervals(values: Any) -> tuple[tuple[int, int], ...]:
    """Sorted, disjoint, non-adjacent intervals covering `values`."""
    merged: list[list[int]] = []
    for low, high in sorted(values):
        if merged and low <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return tuple((low, high) for low, high in merged)


def _subtract_intervals(
    values: tuple[tuple[int, int], ...], removed: tuple[tuple[int, int], ...]
) -> tuple[tuple[int, int], ...]:
    """`values` without `removed`. Both arguments are merged intervals."""
    result: list[tuple[int, int]] = []
    index = 0
    for low, high in values:
        while index < len(removed) and removed[index][1] < low:
            index += 1
        cursor, probe = low, index
        while probe < len(removed) and removed[probe][0] <= high:
            if removed[probe][0] > cursor:
                result.append((cursor, removed[probe][0] - 1))
            cursor = max(cursor, removed[probe][1] + 1)
            probe += 1
        if cursor <= high:
            result.append((cursor, high))
    return tuple(result)


def _held_twice(groups: Mapping[str, tuple[tuple[int, int], ...]]) -> tuple[tuple[int, int], ...]:
    """The addresses that two or more groups hold. The intervals of each group are merged."""
    events: list[tuple[int, int]] = []
    for values in groups.values():
        for low, high in values:
            events.extend(((low, 1), (high + 1, -1)))
    events.sort()
    held: list[tuple[int, int]] = []
    depth, start = 0, 0
    for point, step in events:
        if depth >= 2 and depth + step < 2:
            held.append((start, point - 1))
        elif depth < 2 <= depth + step:
            start = point
        depth += step
    return _merge_intervals(held)


def _intervals_meet(values: tuple[tuple[int, int], ...], others: list[tuple[int, int]]) -> bool:
    """Whether any of `others` overlaps the merged `values`."""
    lows = [low for low, _high in values]
    for low, high in others:
        position = bisect_right(lows, high) - 1
        if position >= 0 and values[position][1] >= low:
            return True
    return False


def _ranges(field: str, values: tuple[tuple[int, int], ...]) -> Predicate:
    return AnyOf(tuple(Atom(field, "range", low, high) for low, high in values))


@dataclass(frozen=True, slots=True)
class _AciScope:
    """The endpoints of one entry context, as `expand_aci_contracts` uses them.

    The per-EPG predicates hold the addresses of each EPG less the ambiguous
    addresses, and the EPGs of one side are disjoint. `*_all` and `*_any` hold
    every endpoint address of a side, the ambiguous addresses included."""

    source_predicates: Mapping[str, Predicate]
    destination_predicates: Mapping[str, Predicate]
    vrf_destinations: Mapping[str, frozenset[str]]
    vrf_predicates: Mapping[str, Predicate]
    destination_exclusive: Predicate
    source_all: tuple[tuple[int, int], ...]
    destination_all: tuple[tuple[int, int], ...]
    source_any: Predicate
    destination_any: Predicate
    ambiguous: Predicate | None
    # The destination endpoints, without the addresses of the external EPGs.
    destination_endpoint_all: tuple[tuple[int, int], ...]
    destination_endpoint_any: Predicate
    # The name of the fabric of an external scope (`_AciIndex.external_scopes`),
    # None for the scope of the entry context.
    external: str | None = None


class _AciIndex:
    """The ACI endpoint and contract index of one graph and address family.

    The index is built once per GraphInventory (`_aci_index`). The addresses
    of an endpoint count for every EPG it is in."""

    def __init__(self, graph: GraphInventory, af: int) -> None:
        self.af = af
        grouped: dict[str, list[tuple[int, int]]] = {}
        for uid in graph.labels.get("Endpoint", ()):
            intervals = [
                item for target in graph.targets(uid, "HAS_IP") for item in _node_intervals(target, af)
            ]
            if not intervals:
                continue
            for membership in graph.targets(uid, "IN_EPG"):
                grouped.setdefault(membership.uid, []).extend(intervals)
        self.epg_intervals = {epg: _merge_intervals(values) for epg, values in grouped.items()}
        self.epg_vrf = {epg: _aci_epg_vrf(graph, epg) for epg in self.epg_intervals}
        # The external EPGs with 1 VRF and a subnet, and the addresses that
        # each classifies in its VRF. The longest subnet of the VRF wins. The
        # addresses of the endpoints and of the subnets of a fabric are no
        # part of them (`_scope`).
        self.external_intervals: dict[str, tuple[tuple[int, int], ...]] = {}
        external_vrf: dict[str, Any] = {}
        subnets: dict[str, dict[str, list[tuple[int, int]]]] = {}
        for uid in graph.labels.get("ExtEpg", ()):
            vrfs = _aci_external_vrfs(graph, uid)
            matched = [
                item for target in graph.targets(uid, "MATCHES") for item in _node_intervals(target, af)
            ]
            if len(vrfs) == 1 and matched:
                external_vrf[uid] = next(iter(vrfs.values()))
                subnets.setdefault(external_vrf[uid].uid, {})[uid] = matched
        for groups in subnets.values():
            for uid, matched in groups.items():
                longer = [
                    (low, high)
                    for other, values in groups.items()
                    if other != uid
                    for low, high in values
                    if any(outer != (low, high) and outer[0] <= low and high <= outer[1] for outer in matched)
                ]
                self.external_intervals[uid] = _subtract_intervals(
                    _merge_intervals(matched), _merge_intervals(longer)
                )
        self.epg_vrf.update(
            {uid: (vrf.uid, vrf.props.get("pc_enf_pref")) for uid, vrf in external_vrf.items()}
        )
        members = (*self.epg_intervals, *self.external_intervals)
        self.consumes = {
            epg: frozenset(item.uid for item in graph.targets(epg, "CONSUMES")) for epg in members
        }
        self.provides = {
            epg: frozenset(item.uid for item in graph.targets(epg, "PROVIDES")) for epg in members
        }
        providers: dict[str, set[str]] = {}
        for epg, contracts in self.provides.items():
            for contract in contracts:
                providers.setdefault(contract, set()).add(epg)
        self.providers = {contract: frozenset(epgs) for contract, epgs in providers.items()}
        consumers: dict[str, set[str]] = {}
        for epg, contracts in self.consumes.items():
            for contract in contracts:
                consumers.setdefault(contract, set()).add(epg)
        self.consumers = {contract: frozenset(epgs) for contract, epgs in consumers.items()}
        # The reason why an enforced VRF cannot implicitly deny the pairs of the EPG.
        self.epg_bypass = {epg: _aci_epg_bypass(graph, epg) for epg in self.epg_intervals}
        self.epg_bypass.update(
            {uid: contract_bypass(vrf.props.get("contract_bypass")) for uid, vrf in external_vrf.items()}
        )
        self.aci_vrfs = frozenset(
            vrf.uid for bd in graph.labels.get("BridgeDomain", ()) for vrf in graph.targets(bd, "IN_VRF")
        )
        # A fabric VRF spans its leaves. The devices of its interfaces are members of the fabric.
        fabrics = {
            vrf: frozenset(
                fabric.uid
                for interface in graph.sources(vrf, "IN_VRF")
                if "Interface" in interface.labels
                for device in graph.targets(interface.uid, "ON")
                for fabric in graph.targets(device.uid, "MEMBER_OF")
                if "Fabric" in fabric.labels
            )
            for vrf in self.aci_vrfs
        }
        self.fabric_vrfs = {
            vrf: frozenset({vrf, *(other for other, names in fabrics.items() if names & fabrics[vrf])})
            for vrf in self.aci_vrfs
        }
        # The subnets of each fabric VRF: the subnets of its bridge domains and
        # its connected prefixes. No external EPG classifies their addresses.
        fabric_subnets: dict[str, list[tuple[int, int]]] = {}
        for bd in graph.labels.get("BridgeDomain", ()):
            held = [item for prefix in graph.sources(bd, "IN") for item in _node_intervals(prefix, af)]
            for vrf in graph.targets(bd, "IN_VRF"):
                fabric_subnets.setdefault(vrf.uid, []).extend(held)
        for vrf_uid in self.aci_vrfs:
            fabric_subnets.setdefault(vrf_uid, []).extend(
                item
                for relation in graph.outgoing.get((vrf_uid, "ORIGINATES"), ())
                if relation.props.get("proto") == "connected" and relation.end in graph.nodes
                for item in _node_intervals(graph.nodes[relation.end], af)
            )
        self.fabric_subnets = {vrf: _merge_intervals(values) for vrf, values in fabric_subnets.items()}
        self._scopes: dict[str, _AciScope] = {}
        self._external_scopes: dict[str, tuple[_AciScope, ...]] = {}
        self._filters: dict[str, Predicate | None] = {}
        self._graph_filters: dict[str, Predicate | None] = {}
        self._redirects: dict[str, tuple[str, str] | None] = {}

    def contract_filter(self, graph: GraphInventory, contract_uid: str) -> Predicate | None:
        if contract_uid not in self._filters:
            self._filters[contract_uid] = _aci_contract_filter(graph, contract_uid, self.af)
        return self._filters[contract_uid]

    def has_graph(self, graph: GraphInventory, contract_uid: str) -> bool:
        return any(
            graph.targets(subject.uid, "APPLIES_GRAPH") for subject in graph.targets(contract_uid, "HAS")
        )

    def graph_filter(self, graph: GraphInventory, contract_uid: str) -> Predicate | None:
        """The filter of a contract with a service graph."""
        if contract_uid not in self._graph_filters:
            self._graph_filters[contract_uid] = _aci_contract_filter(
                graph, contract_uid, self.af, graphs=True
            )
        return self._graph_filters[contract_uid]

    def redirect(self, graph: GraphInventory, contract_uid: str) -> tuple[str, str] | None:
        if contract_uid not in self._redirects:
            self._redirects[contract_uid] = _aci_contract_redirect(graph, contract_uid)
        return self._redirects[contract_uid]

    def scope(self, context_vrf: str) -> _AciScope:
        """The source and destination endpoints of a packet that enters in `context_vrf`.

        In a fabric VRF the source endpoints are the endpoints of that VRF, and
        the destination endpoints are those of the VRFs of the same fabric. An
        address that the entry VRF holds is the endpoint of that VRF. An EPG
        whose VRF does not resolve counts on both sides, and its pairs have no
        known enforcement mode. The external EPGs of the fabric are
        destinations (`_scope`). A VRF outside every fabric has an empty
        scope, and `external_scopes` holds the fabrics of its packets."""
        cached = self._scopes.get(context_vrf)
        if cached is not None:
            return cached
        vrf_of = {epg: vrf for epg, (vrf, _pref) in self.epg_vrf.items()}
        if context_vrf in self.aci_vrfs:
            fabric = self.fabric_vrfs.get(context_vrf, frozenset({context_vrf}))
            sources = {
                epg: values
                for epg, values in self.epg_intervals.items()
                if vrf_of[epg] in (context_vrf, None)
            }
            owned = _merge_intervals(
                value
                for epg, values in self.epg_intervals.items()
                if vrf_of[epg] == context_vrf
                for value in values
            )
            destinations: dict[str, tuple[tuple[int, int], ...]] = {}
            for epg, values in self.epg_intervals.items():
                if vrf_of[epg] in (context_vrf, None):
                    destinations[epg] = values
                elif vrf_of[epg] in fabric and (rest := _subtract_intervals(values, owned)):
                    destinations[epg] = rest
        else:
            # `external_scopes` holds the fabrics of a packet from outside.
            sources, destinations = {}, {}
            fabric = frozenset()
        scope = self._scope(sources, destinations, fabric, None)
        self._scopes[context_vrf] = scope
        return scope

    def external_scopes(self, context_vrf: str) -> tuple[_AciScope, ...]:
        """The scopes of the fabrics that `context_vrf` is not in, one per
        fabric. A packet from outside a fabric has the external EPG of its
        source address as its source, and the endpoints of the fabric are its
        destinations. The endpoints of an EPG whose VRF does not resolve are
        a scope with no source."""
        cached = self._external_scopes.get(context_vrf)
        if cached is not None:
            return cached
        vrf_of = {epg: vrf for epg, (vrf, _pref) in self.epg_vrf.items()}
        own = self.fabric_vrfs.get(context_vrf, frozenset())
        out = []
        for fabric in sorted(set(self.fabric_vrfs.values()) - {own}, key=sorted):
            destinations = {
                epg: values for epg, values in self.epg_intervals.items() if vrf_of[epg] in fabric
            }
            if destinations:
                out.append(self._scope({}, destinations, fabric, min(fabric)))
        if context_vrf not in self.aci_vrfs:
            unresolved = {epg: values for epg, values in self.epg_intervals.items() if vrf_of[epg] is None}
            if unresolved:
                out.append(self._scope({}, unresolved, frozenset(), "unresolved"))
        self._external_scopes[context_vrf] = tuple(out)
        return self._external_scopes[context_vrf]

    def _scope(
        self,
        sources: dict[str, tuple[tuple[int, int], ...]],
        destinations: dict[str, tuple[tuple[int, int], ...]],
        fabric: frozenset[str],
        external: str | None,
    ) -> _AciScope:
        """The scope of the endpoint `sources` and `destinations` of the VRFs
        `fabric`. The external EPGs of these VRFs classify the addresses that
        no endpoint of the 2 sides and no subnet of these VRFs holds. They are
        destinations in the scope of the entry context and sources in an
        external scope."""
        vrf_of = {epg: vrf for epg, (vrf, _pref) in self.epg_vrf.items()}
        endpoints = _merge_intervals(
            (
                *(
                    value
                    for group in (sources, destinations)
                    for values in group.values()
                    for value in values
                ),
                *(value for vrf in fabric for value in self.fabric_subnets.get(vrf, ())),
            )
        )
        destination_endpoint_all = _merge_intervals(
            value for values in destinations.values() for value in values
        )
        classified = {
            uid: rest
            for uid, values in self.external_intervals.items()
            if vrf_of[uid] in fabric and (rest := _subtract_intervals(values, endpoints))
        }
        if external is None:
            destinations = {**destinations, **classified}
        else:
            sources = {**sources, **classified}
        source_held, destination_held = _held_twice(sources), _held_twice(destinations)
        source_predicates = {
            epg: _ranges("source_address", rest)
            for epg, values in sources.items()
            if (rest := _subtract_intervals(values, source_held))
        }
        destination_exclusive = {
            epg: rest
            for epg, values in destinations.items()
            if (rest := _subtract_intervals(values, destination_held))
        }
        destination_predicates = {
            epg: _ranges("destination_address", rest) for epg, rest in destination_exclusive.items()
        }
        vrf_destinations: dict[str, set[str]] = {}
        for epg in destination_predicates:
            if (vrf := vrf_of[epg]) is not None:
                vrf_destinations.setdefault(vrf, set()).add(epg)
        ambiguous = tuple(
            part
            for part in (
                _ranges("source_address", source_held) if source_held else None,
                _ranges("destination_address", destination_held) if destination_held else None,
            )
            if part is not None
        )
        source_all = _merge_intervals(value for values in sources.values() for value in values)
        destination_all = _merge_intervals(value for values in destinations.values() for value in values)
        destination_any = _ranges("destination_address", destination_all)
        return _AciScope(
            MappingProxyType(source_predicates),
            MappingProxyType(destination_predicates),
            MappingProxyType({vrf: frozenset(epgs) for vrf, epgs in vrf_destinations.items()}),
            MappingProxyType(
                {
                    vrf: AnyOf(tuple(destination_predicates[epg] for epg in sorted(epgs)))
                    for vrf, epgs in vrf_destinations.items()
                }
            ),
            AnyOf(tuple(destination_predicates[epg] for epg in sorted(destination_predicates))),
            source_all,
            destination_all,
            _ranges("source_address", source_all),
            destination_any,
            AnyOf(ambiguous) if ambiguous else None,
            destination_endpoint_all,
            # one object for the 2 fields of a scope with no external destination
            destination_any
            if destination_endpoint_all == destination_all
            else _ranges("destination_address", destination_endpoint_all),
            external,
        )


def _aci_index(graph: GraphInventory, af: int) -> _AciIndex:
    """The graph's ACI index for one address family, built on first use."""
    key = ("aci-index", af)
    index = graph.derived.get(key)
    if index is None:
        index = graph.derived[key] = _AciIndex(graph, af)
    return index


def _aci_external_vrfs(graph: GraphInventory, uid: str) -> dict[str, GraphNode]:
    """The VRFs of the L3Outs of an external EPG, by uid. The L3Out holds the
    external EPG (`HAS`), or the external EPG is a part of it (`PART_OF`)."""
    l3outs = [
        node
        for node in (*graph.sources(uid, "HAS"), *graph.targets(uid, "PART_OF"))
        if "L3Out" in node.labels
    ]
    return {vrf.uid: vrf for l3out in l3outs for vrf in graph.targets(l3out.uid, "IN_VRF")}


def _aci_epg_vrf(graph: GraphInventory, epg_uid: str) -> tuple[str | None, Any]:
    """The uid of the governing VRF of the EPG and its pc_enf_pref, through IN_BD
    and IN_VRF as path/gates/aci.py reads them. The result is (None, None) unless
    exactly one VRF resolves."""
    vrfs = {
        vrf.uid: vrf.props.get("pc_enf_pref")
        for bd in graph.targets(epg_uid, "IN_BD")
        for vrf in graph.targets(bd.uid, "IN_VRF")
    }
    if len(vrfs) != 1:
        return None, None
    return next(iter(vrfs.items()))


def _aci_epg_bypass(graph: GraphInventory, epg_uid: str) -> str | None:
    """core/aci_filter.py `contract_bypass` for the governing VRF of the EPG.

    The result is None unless exactly one VRF resolves. The enforcement mode of
    an EPG without exactly one VRF is unknown."""
    vrfs = {
        vrf.uid: vrf.props.get("contract_bypass")
        for bd in graph.targets(epg_uid, "IN_BD")
        for vrf in graph.targets(bd.uid, "IN_VRF")
    }
    if len(vrfs) != 1:
        return None
    return contract_bypass(next(iter(vrfs.values())))


def _aci_contract_redirect(graph: GraphInventory, contract_uid: str) -> tuple[str, str] | None:
    """Return the addresses that the consumer connector and the provider
    connector of the service graph of a contract redirect to, or None when the
    redirect is not established.

    The redirect is established when each subject of the contract applies the
    same 1 graph, the graph has 1 node, and 1 REDIRECTS_VIA relationship of the
    contract binds each of the 2 connectors of that node to a redirect policy
    with 1 destination address (collectors/apic.py `_service_stage`)."""
    templates: set[str] = set()
    for subject in graph.targets(contract_uid, "HAS"):
        applied = graph.targets(subject.uid, "APPLIES_GRAPH")
        if len(applied) != 1:
            return None
        templates.add(applied[0].uid)
    if len(templates) != 1:
        return None
    (template,) = templates
    nodes = graph.targets(template, "HAS_NODE")
    if len(nodes) != 1:
        return None
    names = {"any", str(nodes[0].props.get("name") or "")}
    policies: dict[str, list[str]] = {"consumer": [], "provider": []}
    for relation in graph.outgoing.get((contract_uid, "REDIRECTS_VIA"), ()):
        connector = relation.props.get("connector")
        if (
            relation.props.get("graph") == template
            and relation.props.get("node") in names
            and connector in policies
        ):
            policies[connector].append(relation.end)
    addresses: list[str] = []
    for connector in ("consumer", "provider"):
        if len(policies[connector]) != 1:
            return None
        destinations = graph.targets(policies[connector][0], "HAS_DEST")
        if len(destinations) != 1 or not destinations[0].props.get("ip"):
            return None
        addresses.append(str(destinations[0].props["ip"]))
    return addresses[0], addresses[1]


def _aci_contract_filter(
    graph: GraphInventory,
    contract_uid: str,
    af: int | None = None,
    *,
    graphs: bool = False,
) -> Predicate | None:
    """Return the collected permit filter, or None when its semantics are incomplete.

    Each entry is read by core/aci_filter.py, as the trace and symbolic gates
    read it. An entry for a non-IP ether type, or for the other address family,
    matches no packet of the model and adds nothing. An entry with a field that
    cannot be read makes the whole filter unknown. Only the filters that apply
    from the consumer to the provider count (`filter_applies`). A vzOutTerm
    filter makes its contract one with collected entries.

    A subject with a service graph makes the filter unknown. With `graphs`, the
    filter of such a subject counts."""
    predicates: list[Predicate] = []
    collected = False
    for subject in graph.targets(contract_uid, "HAS"):
        if graph.targets(subject.uid, "APPLIES_GRAPH") and not graphs:
            return None
        for relation in graph.outgoing.get((subject.uid, "USES_FILTER"), ()):
            applies = filter_applies(relation.props.get("direction"))
            action = str(relation.props.get("action") or "permit").lower()
            if applies and action not in {"", "permit"}:
                return None
            for entry in graph.targets(relation.end, "HAS"):
                if "FilterEntry" in entry.labels:
                    collected = True
                    if not applies:
                        continue
                    spec = stored_entry(entry.props)
                    if not spec.families:
                        continue
                    if spec.unknown or (af is None and spec.families != frozenset({4, 6})):
                        return None
                    if af is not None and af not in spec.families:
                        continue
                    terms: list[Predicate] = []
                    if spec.protocol is not None:
                        terms.append(Atom("protocol", "eq", spec.protocol))
                    for field, ports in (
                        ("source_port", spec.source_ports),
                        ("destination_port", spec.destination_ports),
                    ):
                        if ports is not None:
                            terms.append(Atom(field, "range", ports[0], ports[1]))
                    predicates.append(AllOf(tuple(terms)))
    return AnyOf(tuple(predicates)) if collected else None


def _zpa_segment_predicate(graph: GraphInventory, segment: GraphNode, af: int) -> Predicate:
    terms: list[Predicate] = []
    destinations = []
    pending = [segment]
    seen = {segment.uid}
    for _depth in range(5):
        following = []
        for item in pending:
            for target in graph.targets(item.uid, "RESOLVES_TO"):
                destinations.extend(_node_intervals(target, af))
                if target.uid not in seen:
                    seen.add(target.uid)
                    following.append(target)
        pending = following
    # the segment's own IP and CIDR entries are destinations too
    for cidr in segment.props.get("ranges") or ():
        destinations.extend(
            _node_intervals(GraphNode(f"{segment.uid}:{cidr}", frozenset(), {"cidr": cidr}), af)
        )
    if destinations:
        known: Predicate = AnyOf(
            tuple(Atom("destination_address", "range", low, high) for low, high in destinations)
        )
        # A wildcard entry matches destinations that no address set holds.
        if segment.props.get("opaque"):
            known = AnyOf((known, Unknown("ZPA_SEGMENT_DESTINATION_UNRESOLVED", segment.uid)))
        terms.append(known)
    service_terms = []
    for name, protocol in (("tcp_port_ranges", 6), ("udp_port_ranges", 17)):
        values = segment.props.get(name)
        if isinstance(values, (tuple, list)) and len(values) % 2 == 0:
            for index in range(0, len(values), 2):
                try:
                    low, high = int(values[index]), int(values[index + 1])
                except (TypeError, ValueError):
                    continue
                service_terms.append(
                    AllOf(
                        (
                            Atom("protocol", "eq", protocol),
                            Atom("destination_port", "range", low, high),
                        )
                    )
                )
    if service_terms:
        terms.append(AnyOf(tuple(service_terms)))
    else:
        terms.append(Unknown("ZPA_SEGMENT_SERVICE_UNKNOWN", segment.uid))
    return AllOf(tuple(terms))


def _position(node: GraphNode) -> tuple[int, str]:
    value = node.props.get("position", 0)
    return (value if type(value) is int else 0, node.uid)
