"""Compile the existing routed ``Network`` and pinned graph into ``ModelInput``."""

from __future__ import annotations

import weakref
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from ipaddress import ip_address, ip_interface, ip_network
from itertools import product
from typing import Any, Literal, cast

from hst.impact.evaluate import Interface, Member, Network, RequestSet, _OverlaySession
from hst.path.gates.routing import _rib_route
from hst.path.trace import _exit_key
from hst.path.verdict import DENY, INDETERMINATE, classify_action
from hst.policy.graph import INTRA_ZONE, ZONE_INGRESS_UNKNOWN, GraphPolicyNormalizer, acl_governs
from hst.policy.ir import (
    AllOf,
    AnyOf,
    Atom,
    Constant,
    ExecutionContext,
    Layer,
    Not,
    Policy,
    Predicate,
    Unknown,
)

from . import vsx_topology
from .checkpoint_graph import checkpoint_bound, checkpoint_policy, unknown_checkpoint_policy
from .evidence import EvidenceEvaluation, scope_evidence
from .gates import (
    aci_fabric_contexts,
    expand_aci_contracts,
    expand_aci_reply_redirects,
    expand_device_gates,
    expand_zpa_broker,
    merge_choice_assignments,
)
from .graph import GraphInventory
from .model import ChoiceAssignment, EdgeSpec, EntrySpec, ExitRecord, ModelInput, NodeSpec, StateKey
from .mtu_gate import project_mtu
from .sdwan_gate import project_sdwan
from .temporal import refs_for_context

MAX_JOINT_CHOICES = 1024


def _intervals(field: str, values: tuple[tuple[int, int, int], ...]) -> Predicate:
    return AnyOf(tuple(Atom(field, "range", lo, hi) for _af, lo, hi in values))


def _af(request: RequestSet) -> int:
    return request.sources[0][0]


def _owning_device(routing_contexts: Mapping[str, Mapping[str, Any]], context_uid: str) -> str | None:
    """Return the one Device that owns the context, or None when the snapshot
    records none or several.

    An ACI fabric VRF spans its leaves. A PBR redirect table has no interface
    of its own."""
    device = (routing_contexts.get(context_uid) or {}).get("device_uid")
    return device if isinstance(device, str) and device else None


def _state_device(
    network: Network,
    routing_contexts: Mapping[str, Mapping[str, Any]],
    context_uid: str,
    ingress: str | None,
) -> str | None:
    """Return the Device that processes a packet in one context after it
    entered by `ingress`.

    The result is the owning device of the context. For a context without an
    owning device it is the device of the ingress interface. The result is
    None when neither is known. That state is an unknown terminal
    (`_device_unknown_key`)."""
    owner = _owning_device(routing_contexts, context_uid)
    if owner is not None or ingress is None:
        return owner
    devices = {str(item.device_uid) for item in network.interfaces if item.uid == ingress}
    return next(iter(devices)) if len(devices) == 1 else None


def _device_unknown_key(context_uid: str, ingress: str | None, estate: str, af: int) -> StateKey:
    """Return the state of a context whose processing device is not known.

    The context spans several devices or has none, and the ingress interface
    of the packet belongs to no single device. The location holds the context
    and the ingress."""
    return StateKey(
        f"terminal:context-device-unknown:{context_uid}:ingress:{ingress or 'none'}",
        ExecutionContext(estate, "graph", "graph", "unknown", context_uid, cast(Literal[4, 6], af)),
    )


def _redirect_targets(graph: GraphInventory, interface_uid: str) -> set[str]:
    """The contexts a PBR policy enforced on the interface redirects into."""
    return {
        target.uid
        for policy in graph.targets(interface_uid, "ENFORCES")
        if "PbrPolicy" in policy.labels
        for rule in graph.targets(policy.uid, "HAS_RULE")
        for target in graph.targets(rule.uid, "REDIRECTS_VIA")
        if "VrfInstance" in target.labels
    }


def _aci_redirect_owners(graph: GraphInventory, interfaces: _Interfaces) -> dict[str, Interface]:
    """The interface that holds each redirect destination of a contract with a
    service graph (`gates._aci_contract_redirect`).

    An address that no interface holds, or that several interfaces hold, has
    no entry."""
    found: dict[str, Interface] = {}
    for contract in graph.labels.get("Contract", ()):
        for relation in graph.outgoing.get((contract, "REDIRECTS_VIA"), ()):
            for destination in graph.targets(relation.end, "HAS_DEST"):
                address = destination.props.get("ip")
                owners = interfaces.holding(address) if address else ()
                if len(owners) == 1 and owners[0].context_uid:
                    found[str(address)] = owners[0]
    return found


def _attachment_interface(
    network: Network, context_uid: str, ranges: Sequence[tuple[int, int, int]], af: int
) -> str | None:
    """Return the one interface of the context whose prefixes hold every
    source range.

    The sources enter the context by this gateway interface. The result is
    None when no interface or several interfaces hold the ranges, and when an
    interface holds only a part of them."""
    holders: list[str] = []
    for item in network.interfaces:
        if item.context_uid != context_uid:
            continue
        prefixes = [ip_network(text, strict=False) for text in item.prefixes]
        prefixes = [prefix for prefix in prefixes if prefix.version == af]
        overlaps = [
            (low, high)
            for _family, low, high in ranges
            if any(max(low, int(p.network_address)) <= min(high, int(p.broadcast_address)) for p in prefixes)
        ]
        if not overlaps:
            continue
        covered = all(
            any(int(p.network_address) <= low and high <= int(p.broadcast_address) for p in prefixes)
            for _family, low, high in ranges
        )
        if not covered:
            return None
        holders.append(item.uid)
    return holders[0] if len(holders) == 1 else None


def _context(
    routing_contexts: Mapping[str, Mapping[str, Any]],
    graph: GraphInventory,
    context_uid: str,
    estate: str,
    af: int,
    device_uid: str | None = None,
) -> ExecutionContext:
    """Build the execution context from the collected qualified context.

    The firewall instance defaults to the owning device of the context.
    `device_uid` is the device of the state (`_state_device`) for a context
    without an owning device."""
    device = _owning_device(routing_contexts, context_uid) or device_uid
    if not device:
        raise ValueError(f"routing context {context_uid!r} lacks its device identity")
    graph_context = graph.nodes.get(context_uid)
    props = graph_context.props if graph_context is not None else {}
    firewall = props.get("firewall_instance_uid") or props.get("logical_instance_uid") or device
    # The vendor of a rulebase is read before its `ENFORCES` relations.
    packages = {
        package.uid
        for rulebase_uid in graph.labels.get("FwRulebase", ())
        for rulebase in (graph.nodes[rulebase_uid],)
        if rulebase.props.get("vendor") == "checkpoint"
        for relation in graph.incoming.get((rulebase_uid, "ENFORCES"), ())
        if (
            relation.start == device
            or any(node.uid == device for node in graph.targets(relation.start, "ON"))
        )
        for package in graph.sources(rulebase.uid, "HAS_LAYER")
    }
    checkpoint_package = graph.nodes[next(iter(packages))] if len(packages) == 1 else None
    authority = (
        props.get("authority")
        or (checkpoint_package.props.get("authority_uid") if checkpoint_package else None)
        or "graph"
    )
    domain = (
        props.get("domain")
        or (checkpoint_package.props.get("domain_uid") if checkpoint_package else None)
        or "graph"
    )
    if not all(isinstance(value, str) and value for value in (firewall, authority, domain)):
        raise ValueError(f"routing context {context_uid!r} has malformed qualified graph identity")
    return ExecutionContext(estate, authority, domain, firewall, context_uid, cast(Literal[4, 6], af))


def _interfaces(network: Network, context_uid: str, name: str | None) -> tuple[Any, ...]:
    return tuple(
        item
        for item in network.interfaces
        if item.context_uid == context_uid and (name is None or item.name == name or item.uid == name)
    )


def _bindings(
    graph: GraphInventory,
    context: ExecutionContext,
    ingress: str | None,
    egress: str | None,
    af: int,
) -> tuple[tuple[str, ...], Predicate]:
    """Installed access rulebases for one exact logical firewall and routing context.

    A NAT rulebase is skipped. The NAT stages of the device gates apply its
    rules (`policy.nat`). A zone-pair rulebase receives only the flows that
    enter by an interface of its source zone and leave by an interface of its
    destination zone (`flow_match.receives`). A zone-pair rulebase that does
    not receive the flow is not bound. A zone-pair rulebase for which
    `receives` returns None is bound with the gap RULEBASE_SCOPE_UNKNOWN.

    The candidates are those of the hop tracer
    (`path.gates.firewall._firewall_verdict`). A candidate is a rulebase that
    the firewall enforces, or a zone-pair rulebase bound to a zone of the
    device. Such a zone-pair rulebase has no ENFORCES relation (a VyOS named
    ruleset, a UniFi zone policy). A rulebase of the other address family is
    no candidate. An input or output chain is no candidate. These chains
    judge traffic to and from the device itself. An interface ACL with each
    binding on another interface than those of the flow is no candidate
    (`_acl_governs`). Beside a zone pair that
    receives the flow, a device-wide rulebase is bound only when the graph
    records its chain. A zone pair has no installation relation. Its policy
    establishes a permit proof only when the rulebase records its own
    installation evidence (`_node_installed`). Otherwise the installation is
    INSTALLATION_UNKNOWN.

    A flow between 2 different zones that no zone-pair rulebase of its
    address family receives takes the default action of the destination zone
    (the tracer's `_zone_pair_verdict`). The destination Zone node is bound,
    and `GraphPolicyNormalizer` reads its default as a layer with no rules."""
    from hst.assessment.flow_match import receives

    bound: set[str] = set()
    scope_gaps: list[Predicate] = []
    exact = True
    candidates: list[tuple[str, list[Mapping[str, Any]]]] = []
    zone_received = False
    zone_pair_bound = False
    ingress_name, egress_name = _interface_name(graph, ingress), _interface_name(graph, egress)
    for rulebase_uid in graph.labels.get("FwRulebase", ()):
        base = graph.nodes[rulebase_uid]
        if base.props.get("kind") == "nat" or _rulebase_af(base) not in (None, af):
            continue
        # An input or output chain (a VyOS chain, a UniFi LOCAL ruleset)
        # judges traffic to or from the device.
        if base.props.get("chain") in ("input", "output"):
            continue
        applicable: list[Mapping[str, Any]] = []
        for relation in graph.incoming.get((rulebase_uid, "ENFORCES"), ()):
            props = relation.props
            owner = props.get("firewall_instance_uid", relation.start)
            if owner != context.firewall_instance:
                continue
            # "*" is a binding that applies in every context (a VyOS forward
            # filter, a UniFi classic ruleset)
            if props.get("context_uid") not in (None, "*", context.vrf):
                continue
            for key, value in (("ingress_interface_uid", ingress), ("egress_interface_uid", egress)):
                if props.get(key) not in (None, "*", value):
                    break
            else:
                if props.get("address_family") in (None, af):
                    applicable.append(props)
        zone_pair = base.props.get("match_context") == "zone-pair"
        if not applicable and not (zone_pair and _zone_bound(graph, rulebase_uid, context.firewall_instance)):
            continue
        if zone_pair:
            received = receives(
                graph, rulebase_uid, _interface_name(graph, ingress), _interface_name(graph, egress)
            )
            if received is False:
                continue
            if received is None:
                scope_gaps.append(Unknown("RULEBASE_SCOPE_UNKNOWN", rulebase_uid))
            else:
                zone_received = True
            zone_pair_bound = True
        if _acl_governs(graph, rulebase_uid, ingress_name, egress_name) is False:
            continue
        candidates.append((rulebase_uid, applicable))
    source_zone, destination_zone = _zone_of(graph, ingress), _zone_of(graph, egress)
    if (
        not zone_pair_bound
        and source_zone is not None
        and destination_zone is not None
        and source_zone.props.get("name") != destination_zone.props.get("name")
    ):
        # No ruleset of this family binds the pair. The default action of the
        # destination zone decides. The zone has no installation relation, and
        # `_node_installed` reads the installation from the zone properties.
        bound.add(destination_zone.uid)
        exact = _node_installed(destination_zone.props)
        zone_received = True
    elif (
        not zone_pair_bound
        and source_zone is not None
        and destination_zone is not None
        and source_zone.props.get("intra_zone_filtering") is not None
    ):
        # No (Z, Z) ruleset of this family receives the flow inside one zone.
        # The intra-zone filtering of the zone decides (the tracer's
        # `_intra_zone_verdict`, `GraphPolicyNormalizer`, `INTRA_ZONE`).
        bound.add(source_zone.uid + INTRA_ZONE)
        exact = _node_installed(source_zone.props)
        zone_received = True
    if ingress is None and _device_zoned(graph, context.firewall_instance):
        # The zone that the packet enters by is not known. An unknown layer is
        # bound beside the other layers.
        bound.add(ZONE_INGRESS_UNKNOWN + context.firewall_instance)
    for rulebase_uid, applicable in candidates:
        base_props = graph.nodes[rulebase_uid].props
        if zone_received and not (
            base_props.get("match_context") in ("zone-pair", "interface-acl") or base_props.get("chain")
        ):
            # a chain-less device-wide rulebase beside a zone policy is not
            # known to run beside it
            continue
        bound.add(rulebase_uid)
        if not applicable:
            # A zone-pair rulebase has no installation relation. The collector
            # records the installation evidence on the rulebase itself.
            exact &= base_props.get("match_context") == "zone-pair" and _node_installed(base_props)
            continue
        configured = graph.nodes[rulebase_uid].props.get("configured_revision")
        row_exact: list[bool] = []
        for props in applicable:
            scoped = all(
                key in props
                for key in (
                    "context_uid",
                    "ingress_interface_uid",
                    "egress_interface_uid",
                    "address_family",
                )
            )
            complete = props.get("installed") is True and (
                props.get("coverage") in {"complete", "complete-empty"}
                or (
                    props.get("coverage") == "partial"
                    and _unreported_elsewhere(graph, base_props, ingress, egress)
                )
            )
            installed = props.get("installed_revision")
            revision_exact = bool(installed)
            if graph.nodes[rulebase_uid].props.get("vendor") == "checkpoint":
                revision_exact = bool(configured) and installed == configured
            row_exact.append(scoped and complete and revision_exact)
        exact &= any(row_exact) and all(row_exact)
    if not bound:
        return (), Unknown("INSTALLATION_UNKNOWN", context.firewall_instance)
    # Installation relations without full scope/revision evidence preserve a
    # possible policy but cannot establish a permit proof.
    installation: Predicate = (
        Constant(True) if exact else Unknown("INSTALLATION_UNKNOWN", context.firewall_instance)
    )
    if scope_gaps:
        installation = AllOf((installation, *scope_gaps))
    return tuple(sorted(bound)), installation


def _acl_governs(
    graph: GraphInventory, rulebase_uid: str, ingress_name: str | None, egress_name: str | None
) -> bool | None:
    """Return `acl_governs` for the interface ACL `rulebase_uid` and the
    interface names of a flow.

    The result is True for a rulebase that is no interface ACL and for a
    Check Point rulebase."""
    base = graph.nodes.get(rulebase_uid)
    if (
        base is None
        or base.props.get("match_context") != "interface-acl"
        or base.props.get("vendor") == "checkpoint"
    ):
        return True
    return acl_governs(graph, base, ingress_name, egress_name)


def _unreported_elsewhere(
    graph: GraphInventory, base_props: Mapping[str, Any], ingress: str | None, egress: str | None
) -> bool:
    """Return whether the partial installation of an interface ACL is partial
    only on interfaces that this packet does not use.

    A UniFi classic ruleset (`collectors.unifi`, ENFORCES) is partial only
    for its `unreported_bindings`. An entry has the form "<name> <direction>"
    and holds an interface that the device did not report. An entry concerns
    the packet only on its own side (ingress for "in", egress for "out"). The
    entry does not concern the packet when the graph has another name for the
    interface of that side. The result is False for a side that the walk does
    not know or the graph does not name, for an entry that does not parse,
    for a name equal to the interface name of the packet without regard to
    case, and for a rulebase with no unreported binding. A Cisco list with an
    unreported binding records installed False."""
    if base_props.get("match_context") != "interface-acl" or base_props.get("vendor") == "checkpoint":
        return False
    unreported = base_props.get("unreported_bindings")
    if not isinstance(unreported, (list, tuple)) or not unreported:
        return False
    for entry in unreported:
        spelled, _sep, side = str(entry).rpartition(" ")
        if not spelled or side not in ("in", "out"):
            return False
        observed = _interface_name(graph, ingress if side == "in" else egress)
        if observed is None or observed.casefold() == spelled.casefold():
            return False
    return True


def _node_installed(props: Mapping[str, Any]) -> bool:
    """Return whether a zone-pair rulebase or a zone records its own installation.

    The record is installed, complete and at a revision equal to the
    configured revision. The VyOS and UniFi collectors write it."""
    installed = props.get("installed_revision")
    return (
        props.get("installed") is True
        and props.get("coverage") in {"complete", "complete-empty"}
        and isinstance(installed, str)
        and bool(installed)
        and props.get("configured_revision") in (None, installed)
    )


def _rulebase_af(base: Any) -> int | None:
    """Return the address family that a rulebase judges, or None for both or
    unknown (`path.gates.firewall._rb_af`).

    The result is the collected `af`. A rulebase without `af` whose uid
    contains `:ipv6` gives 6."""
    if base.props.get("af"):
        return int(base.props["af"])
    return 6 if ":ipv6" in base.uid else None


def _zone_of(graph: GraphInventory, interface_uid: str | None) -> Any | None:
    """The zone that contains an interface, the first by name as the tracer
    picks it (`path.gates.firewall._zone_of`), or None."""
    if interface_uid is None:
        return None
    zones = [zone for zone in graph.sources(interface_uid, "CONTAINS") if "Zone" in zone.labels]
    return min(zones, key=lambda zone: str(zone.props.get("name") or "")) if zones else None


def _device_zoned(graph: GraphInventory, device_uid: str) -> bool:
    """Whether a Zone is owned by the device or holds an interface on it."""
    return any("Zone" in zone.labels for zone in graph.sources(device_uid, "OWNED_BY")) or any(
        "Zone" in zone.labels
        for interface in graph.sources(device_uid, "ON")
        for zone in graph.sources(interface.uid, "CONTAINS")
    )


def _zone_bound(graph: GraphInventory, rulebase_uid: str, device_uid: str) -> bool:
    """Return whether a zone of the pair of the rulebase is owned by the
    device or holds an interface on it."""
    return any(
        owner.uid == device_uid
        for kind in ("FROM_ZONE", "TO_ZONE")
        for zone in graph.targets(rulebase_uid, kind)
        for owner in (
            *graph.targets(zone.uid, "OWNED_BY"),
            *(
                device
                for interface in graph.targets(zone.uid, "CONTAINS")
                for device in graph.targets(interface.uid, "ON")
            ),
        )
    )


def _interface_name(graph: GraphInventory, interface_uid: str | None) -> str | None:
    """Return the name of an interface uid of the walk, or None when the graph
    has no name for it.

    Rule interface scopes and ACL bindings use this name."""
    node = graph.nodes.get(interface_uid) if interface_uid is not None else None
    name = node.props.get("name") if node is not None and "Interface" in node.labels else None
    return str(name) if name else None


def _policy_egress(
    network: Network, context_uid: str, egresses: tuple[Any, ...], next_hop: Any
) -> str | None:
    """Return the interface uid that a FIB row leaves by, for an egress-scoped
    policy.

    The result is the interface of the row. For a next-hop row without an
    interface it is the single interface of the context whose connected
    prefix holds the next hop."""
    if len(egresses) == 1:
        return str(egresses[0].uid)
    if egresses or not next_hop:
        return None
    try:
        address = ip_address(str(next_hop))
    except ValueError:
        return None
    holders = [
        item
        for item in network.interfaces
        if item.context_uid == context_uid
        and any(
            address.version == network_.version and address in network_
            for network_ in (ip_network(prefix, strict=False) for prefix in item.prefixes)
        )
    ]
    return str(holders[0].uid) if len(holders) == 1 else None


def _egress_scoped(graph: GraphInventory, context: ExecutionContext, ingress: str | None, af: int) -> bool:
    """Return whether a rulebase bound for this ingress decides by the egress
    interface.

    True for a rule with `out_interface` or `out_interfaces`, for an
    interface ACL bound outbound and for a zone pair. True also for an
    ingress in a zone. The policy is then applied on each FIB edge."""
    if _zone_of(graph, ingress) is not None:
        return True
    rulebases, _installation = _bindings(graph, context, ingress, None, af)
    for uid in rulebases:
        base = graph.nodes.get(uid)
        if base is None or base.props.get("vendor") == "checkpoint":
            continue
        if base.props.get("match_context") == "zone-pair":
            return True
        if base.props.get("match_context") == "interface-acl":
            outbound = any(
                relation.props.get("direction") == "out"
                for relation in graph.incoming.get((uid, "PROTECTED_BY"), ())
            )
            unreported = base.props.get("unreported_bindings")
            if outbound or any(
                str(entry).endswith(" out")
                for entry in (unreported if isinstance(unreported, (list, tuple)) else ())
            ):
                return True
        for rule in graph.targets(uid, "HAS_RULE"):
            if rule.props.get("out_interface") or "out_interfaces" in rule.props:
                return True
    return False


def _state_admission(
    graph: GraphInventory, context: ExecutionContext, rulebases: tuple[str, ...], state: str
) -> Literal["permit", "deny", "unknown"] | None:
    """Return the action of the recorded state policy of the device for a
    packet of `state`, or None when no recorded policy decides it.

    The impact engine's `_StatePolicyFilter` reads the same rulebase property.

    `global_state_policy` decides established and related traffic ahead of
    every ruleset. It holds a VyOS state-policy or the fixed stateful
    behaviour of Check Point (state_policy_basis "vendor-default"). 2
    different recorded policies, or an entry without an action, give
    "unknown". The context of a VSX virtual system gives None. A chassis-wide
    policy is no evidence of the session handling of that context.
    """
    if state == "new":
        return None
    firewall = graph.nodes.get(context.firewall_instance)
    if firewall is not None and "FirewallInstance" in firewall.labels:
        return None
    policies = {
        tuple(sorted(str(item) for item in node.props["global_state_policy"]))
        for uid in rulebases
        if (node := graph.nodes.get(uid)) is not None
        and "FwRulebase" in node.labels
        and node.props.get("global_state_policy")
    }
    if not policies:
        return None
    if len(policies) != 1:
        return "unknown"
    entries = [item.partition("=") for item in next(iter(policies))]
    if any(not sep or not action for _state, sep, action in entries):
        return "unknown"
    actions = {classify_action(action) for entry_state, _sep, action in entries if entry_state == state}
    if not actions:
        return None
    if len(actions) != 1 or INDETERMINATE in actions:
        return "unknown"
    return "deny" if DENY in actions else "permit"


def _access_policy(graph, context, device_uid, ingress, egress, af, state):
    rulebases, installation = _bindings(graph, context, ingress, egress, af)
    policy = None
    admission = _state_admission(graph, context, rulebases, state) if rulebases else None
    if admission is not None:
        # interface ACLs still judge a packet the state policy admits
        acls = tuple(
            uid
            for uid in rulebases
            if (node := graph.nodes.get(uid)) is not None
            and node.props.get("match_context") == "interface-acl"
        )
        if admission != "permit" or not acls:
            layer_uid = f"state-policy:{state}"
            return Policy(
                uid=layer_uid,
                revision=graph.fingerprint,
                context=context,
                layers=(Layer(layer_uid, (), admission),),
                ordered_layers=(layer_uid,),
                installation=installation,
                manifest_digest=graph.manifest_digest,
            )
        rulebases = acls
    if rulebases:
        policy = checkpoint_policy(graph, rulebases, context, installation)
        if policy is None:
            if checkpoint_bound(graph, rulebases):
                policy = unknown_checkpoint_policy(graph, context, installation)
            else:
                # The walk identifies interfaces by uid. Rule scopes and ACL
                # bindings use the interface name.
                ingress_name, egress_name = _interface_name(graph, ingress), _interface_name(graph, egress)
                policy = GraphPolicyNormalizer(graph, context).policy(
                    rulebases,
                    installation=installation,
                    ingress=ingress_name,
                    egress=egress_name,
                    state=state,
                )
                # The default action of an interface ACL is unknown when the
                # flow has no interface name on the side of its binding.
                undecided = {
                    uid for uid in rulebases if _acl_governs(graph, uid, ingress_name, egress_name) is None
                }
                if undecided:
                    policy = replace(
                        policy,
                        layers=tuple(
                            replace(layer, default="unknown") if layer.uid in undecided else layer
                            for layer in policy.layers
                        ),
                    )
    else:
        firewall_node = graph.nodes.get(context.firewall_instance)
        device_node = graph.nodes.get(device_uid)
        known_firewall = (firewall_node is not None and "FirewallInstance" in firewall_node.labels) or (
            device_node is not None
            and (
                device_node.props.get("role") == "firewall"
                or device_node.props.get("platform") == "checkpoint"
            )
        )
        if known_firewall:
            policy = unknown_checkpoint_policy(
                graph,
                context,
                installation,
                reason="FIREWALL_POLICY_INSTALLATION_UNKNOWN",
            )
        elif egress is None and _zone_of(graph, ingress) is not None:
            # A zone default action can apply, and the egress zone is not known.
            policy = unknown_checkpoint_policy(
                graph, context, installation, reason="ZONE_POLICY_EGRESS_UNKNOWN"
            )
    return policy


def _tunnel_targets(
    graph: GraphInventory,
    network: Network,
    rows: Sequence[Mapping[str, Any]],
    keys: Mapping[tuple[str, str | None], StateKey],
    tunnels: Iterable[str] | None = None,
    interfaces: _Interfaces | None = None,
) -> dict[str, StateKey]:
    """Prove carrier routing and reciprocal decapsulation before linking overlays.

    `tunnels` limits the proof to the tunnels that the tunnel gates can
    consult. These are the tunnels on an egress interface of a routing state
    (`_egress_tunnels`). Without `tunnels`, every Tunnel of the graph is
    proven. `rows` holds every FIB row of the address family. The carrier
    route can be a row outside the discovery."""
    index = interfaces or _Interfaces(network)
    by_context: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_context[str(row.get("context_uid"))].append(row)
    result: dict[str, StateKey] = {}
    for tunnel_uid in graph.labels.get("Tunnel", ()) if tunnels is None else sorted(tunnels):
        tunnel = graph.nodes[tunnel_uid]
        local = str(tunnel.props.get("local_address") or tunnel.props.get("source_ip") or "")
        far_nodes = graph.targets(tunnel_uid, "TERMINATES_ON")
        far = str(
            (far_nodes[0].props.get("ip") if len(far_nodes) == 1 else None)
            or tunnel.props.get("endpoint")
            or ""
        )
        if not local or not far:
            continue
        try:
            far_address = ip_address(far)
        except ValueError:
            continue
        local_interfaces = tuple(interface for interface in index.holding(local) if interface.context_uid)
        if len(local_interfaces) != 1:
            continue
        local_interface = local_interfaces[0]
        candidates = [
            row
            for row in by_context.get(str(local_interface.context_uid), ())
            if not row.get("discard") and far_address in ip_network(str(row.get("prefix")), strict=False)
        ]
        if not candidates:
            continue
        prefix_length = max(ip_network(str(row["prefix"]), strict=False).prefixlen for row in candidates)
        best = [
            row
            for row in candidates
            if ip_network(str(row["prefix"]), strict=False).prefixlen == prefix_length
        ]
        egresses = {
            interface.uid
            for row in best
            for interface in index.named(str(local_interface.context_uid), str(row.get("interface") or ""))
        }
        overlay_interfaces = {node.uid for node in graph.targets(tunnel_uid, "ENDPOINT")}
        if not egresses or egresses & overlay_interfaces:
            continue
        local_device = str(local_interface.device_uid)
        policy_bound = any(
            relation.start == local_device
            or any(node.uid == local_device for node in graph.targets(relation.start, "ON"))
            for label in ("FwRulebase", "NatRulebase")
            for rulebase_uid in graph.labels.get(label, ())
            for relation in graph.incoming.get((rulebase_uid, "ENFORCES"), ())
        )
        nested_tunnel = any(
            "Tunnel" in node.labels
            for egress_uid in egresses
            for node in graph.sources(egress_uid, "ENDPOINT")
        )
        if policy_bound or nested_tunnel:
            # Carrier output policy, carrier NAT and nested encapsulation need an
            # outer-header model. Such a tunnel is not linked.
            continue
        remote_devices = {
            device.uid
            for far_node in far_nodes
            for interface in graph.sources(far_node.uid, "HAS_IP")
            for device in graph.targets(interface.uid, "ON")
        }
        peer_candidates = [
            peer
            for device_uid in remote_devices
            for interface in graph.sources(device_uid, "ON")
            for peer in graph.sources(interface.uid, "ENDPOINT")
            if "Tunnel" in peer.labels
            and str(peer.props.get("local_address") or peer.props.get("source_ip") or "") == far
            and peer.props.get("encap") == tunnel.props.get("encap")
            and peer.props.get("carrier_proto") == tunnel.props.get("carrier_proto")
        ]
        peers = [
            peer
            for peer in peer_candidates
            if str(
                (
                    graph.targets(peer.uid, "TERMINATES_ON")[0].props.get("ip")
                    if len(graph.targets(peer.uid, "TERMINATES_ON")) == 1
                    else None
                )
                or peer.props.get("endpoint")
                or ""
            )
            == local
        ]
        remote_overlays = {
            interface.uid
            for peer in peers
            for interface in graph.targets(peer.uid, "ENDPOINT")
            if "Interface" in interface.labels
        }
        targets = [
            key
            for (context_uid, ingress), key in keys.items()
            if ingress in remote_overlays
            and any(str(interface.context_uid) == context_uid for interface in index.by_uid.get(ingress, ()))
        ]
        if len(peers) == 1 and len(targets) == 1:
            result[tunnel_uid] = targets[0]
    return result


def _carrier_addresses(graph: GraphInventory, tunnels: Iterable[str], af: int) -> set[int]:
    """Return the far end address of each of `tunnels` of family `af`, as
    `_tunnel_targets` reads it.

    The carrier route goes toward this address."""
    found: set[int] = set()
    for tunnel_uid in tunnels:
        tunnel = graph.nodes.get(tunnel_uid)
        if tunnel is None:
            continue
        far_nodes = graph.targets(tunnel_uid, "TERMINATES_ON")
        far = str(
            (far_nodes[0].props.get("ip") if len(far_nodes) == 1 else None)
            or tunnel.props.get("endpoint")
            or ""
        )
        try:
            address = ip_address(far)
        except ValueError:
            continue
        if address.version == af:
            found.add(int(address))
    return found


ChoiceMap = dict[tuple[str, str], tuple[tuple[str, str], ...]]


def _egress_tunnels(
    graph: GraphInventory,
    interfaces: _Interfaces,
    rows_by_context: Mapping[str, Sequence[Mapping[str, Any]]],
    contexts: Iterable[str],
) -> set[str]:
    """Return the Tunnels on the one egress interface of a routed FIB row of
    these contexts.

    A tunnel gate of the model can consult these tunnels."""
    found: set[str] = set()
    for context_uid in sorted(contexts):
        for row in rows_by_context.get(context_uid, ()):
            if row.get("discard"):
                continue
            egresses = interfaces.named(context_uid, str(row.get("interface") or ""))
            if len(egresses) == 1:
                found.update(
                    node.uid for node in graph.sources(egresses[0].uid, "ENDPOINT") if "Tunnel" in node.labels
                )
    return found


def _choice_catalog(
    rows: Sequence[Mapping[str, Any]], *, maximum: int = MAX_JOINT_CHOICES
) -> tuple[tuple[ChoiceAssignment, ...], ChoiceMap, bool]:
    """Complete Cartesian assignments for every ECMP group in the FIB rows."""
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["context_uid"]), str(row["prefix"])].append(row)
    alternatives: dict[tuple[str, str], tuple[tuple[str, str], ...]] = {}
    dimensions: list[tuple[str, tuple[str, ...]]] = []
    for key, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        scope = f"ecmp:{key[0]}:{key[1]}"
        values = tuple(
            f"route:{key[0]}:{key[1]}:{index}" for index, _row in enumerate(sorted(group, key=repr))
        )
        alternatives[key] = tuple((scope, value) for value in values)
        dimensions.append((scope, values))
    if not dimensions:
        return (ChoiceAssignment("routing:only"),), alternatives, True
    cardinality = 1
    for _scope, values in dimensions:
        cardinality *= len(values)
        if cardinality > maximum:
            return (ChoiceAssignment("routing:resource-cutoff"),), {}, False
    assignments = tuple(
        ChoiceAssignment("routing:" + "/".join(value for _scope, value in selected), tuple(selected))
        for selected in product(*(tuple((scope, value) for value in values) for scope, values in dimensions))
    )
    return assignments, alternatives, True


class _Interfaces:
    """The interfaces of a network indexed by context and by held address,
    each list in the order of `network.interfaces`."""

    def __init__(self, network: Network) -> None:
        self.by_context: dict[str | None, list[Interface]] = defaultdict(list)
        self.by_address: dict[str, list[Interface]] = defaultdict(list)
        self.by_uid: dict[str, list[Interface]] = defaultdict(list)
        for item in network.interfaces:
            self.by_context[item.context_uid].append(item)
            self.by_uid[item.uid].append(item)
            for address in item.addresses:
                holders = self.by_address[address]
                if not holders or holders[-1] is not item:
                    holders.append(item)

    def holding(self, address: Any) -> tuple[Interface, ...]:
        """Return the interfaces that hold `address`, or an empty tuple for an empty address."""
        return tuple(self.by_address.get(str(address), ())) if address else ()

    def named(self, context_uid: str, name: str | None) -> tuple[Interface, ...]:
        """Return the interfaces of the context, filtered by name or uid as in `_interfaces`."""
        return tuple(
            item
            for item in self.by_context.get(context_uid, ())
            if name is None or item.name == name or item.uid == name
        )


# `_EXITS` holds the estate exit records of the tracer per pinned session
# (`_pinned`), keyed by the id of the session. The key of a record is
# (device, context, prefix, next hop, next hop table, egress).
_EXITS: dict[int, tuple[weakref.ref[Any], dict[tuple[Any, ...], ExitRecord | None]]] = {}


def _pinned(gates: Any) -> Any:
    """Return the object that the estate exit records depend on.

    The result is the pinned session under every change-set overlay and every
    failure scenario. A change set rewrites rule, NAT, zone, route and MTU
    reads and none of the reads of `estate_exit`. A failure scenario
    delegates its session to the gates that it wraps. Gates without a session
    are returned themselves (a test harness that reads a monkeypatched
    graph)."""
    session = getattr(gates, "session", None)
    while isinstance(session, _OverlaySession):
        session = session._session
    return gates if session is None else session


def _exit_memo(gates: Any) -> dict[tuple[Any, ...], ExitRecord | None] | None:
    """Return the estate exit records read for `gates` (a session or a gates
    object).

    The records are kept while `gates` lives. The result is None for an
    object that cannot be weakly referenced."""
    key = id(gates)
    entry = _EXITS.get(key)
    if entry is None or entry[0]() is not gates:

        def forget(_ref: weakref.ref[Any]) -> None:
            _EXITS.pop(key, None)

        try:
            ref = weakref.ref(gates, forget)
        except TypeError:
            return None
        entry = (ref, {})
        _EXITS[key] = entry
    return entry[1]


def _edge_exit(
    network: Network,
    device_uid: str,
    context_uid: str,
    row: Mapping[str, Any],
    egresses: tuple[Interface, ...],
) -> tuple[ExitRecord, Interface] | None:
    """Return the tracer's `left_estate` object for a FIB row whose route ends
    the model, and the egress that the row leaves by.

    Such a route is an interface-only delivery or a route to a next hop that
    no interface holds. The result is None where the tracer recognizes no
    edge.

    Only the default route of its family with exactly one egress is read. The
    egress is the interface of the row. For a next-hop row without an
    interface it is the single interface whose connected prefix holds the
    next hop (`_policy_egress`). `GraphGates.estate_exit` runs
    `path.trace.estate_exit` on the pinned session and gives none at an
    SD-WAN edge. Gates without `estate_exit` (a pure model) give None. Each
    route is read once per pinned session (`_pinned`)."""
    read = getattr(network.gates, "estate_exit", None)
    if read is None or ip_network(str(row["prefix"]), strict=False).prefixlen != 0:
        return None
    egress_uid = _policy_egress(network, context_uid, egresses, row.get("next_hop"))
    egress = next(
        (
            item
            for item in egresses or network.interfaces
            if item.uid == egress_uid and item.context_uid == context_uid
        ),
        None,
    )
    if egress is None:
        return None
    route = _rib_route({**row, "fib": True})
    key = (device_uid, context_uid, route["cidr"], route["next_hop"], route["next_hop_vrf"], egress.uid)
    memo = _exit_memo(_pinned(network.gates))
    if memo is None:
        memo = _exit_memo(network.gates)
    if memo is None:
        memo = {}
    if key not in memo:
        found = read(device_uid, context_uid, route, egress)
        memo[key] = cast(ExitRecord, tuple(found.items())) if found else None
    exit_ = memo[key]
    return None if exit_ is None else (exit_, egress)


def _edge_exits(found: Sequence[ExitRecord | None]) -> tuple[ExitRecord, ...]:
    """Return the exit records of a terminal that several rows reach
    (equal-cost routes, the states of one context).

    The result holds each distinct record in the tracer's order. The result
    is empty unless every row that reaches the terminal leaves the estate
    there."""
    if not found or any(item is None for item in found):
        return ()
    distinct = {_exit_key(dict(item)): item for item in found if item is not None}
    return tuple(distinct[key] for key in sorted(distinct))


def _at_estate_edge(node: NodeSpec, exits: tuple[ExitRecord, ...]) -> NodeSpec:
    """Return `node` with the tracer's exit records in `left_estate`.

    Every route that reaches this terminal leaves the estate at its edge."""
    return replace(node, left_estate=exits)


def _estate_split(
    network: Network,
    af: int,
    split: StateKey,
    edge: StateKey,
    estate: NodeSpec,
) -> tuple[StateKey, tuple[NodeSpec, ...]]:
    """Return the entry and the nodes of a route that the tracer recognizes as
    the edge of the estate.

    A destination outside the estate goes to `edge`, a permit terminal that
    gets the tracer's exit record (`edge_rows`). `Network.estate_prefixes`
    holds the estate by the tracer's rule (interface prefixes, routed
    prefixes and the space never on the internet). A destination inside the
    estate goes to `estate`, a terminal with no exit record. A route to that
    destination is missing on this device. Without estate prefixes of the
    family, every destination goes to `edge`."""
    held = tuple(item for item in network.estate_prefixes if item[0] == af)
    terminal = NodeSpec(edge, terminal="permit")
    if not held:
        return edge, (terminal,)
    inside = _intervals("destination_address", held)
    return split, (
        NodeSpec(
            split,
            (EdgeSpec("estate:held", estate.key, inside), EdgeSpec("estate:outside", edge, Not(inside))),
        ),
        estate,
        terminal,
    )


def _next_hop_edge(
    network: Network,
    af: int,
    context: ExecutionContext,
    context_uid: str,
    row: Mapping[str, Any],
    unknown: StateKey,
    egress: Interface,
) -> tuple[StateKey, StateKey, tuple[NodeSpec, ...]]:
    """Build the nodes of a default route to a next hop that no interface
    holds and that the tracer recognizes as the edge of the estate.

    The terminal is a `permit` bound to the egress interface
    (`reply-ingress`). A destination inside the estate keeps the unknown-hop
    terminal (`_estate_split`). The result holds the entry, the permit
    terminal and the nodes."""
    tail = f"{context_uid}:{row['prefix']}:{row['next_hop']}"
    edge = StateKey(f"estate-edge:{tail}", context, binding_scope=(f"reply-ingress:{egress.uid}",))
    entry, nodes = _estate_split(
        network,
        af,
        StateKey(f"estate-edge-split:{tail}", context),
        edge,
        NodeSpec(unknown, terminal="unknown", complete=False),
    )
    return entry, edge, nodes


def _delivery_edge(
    network: Network, af: int, delivery: StateKey
) -> tuple[StateKey, StateKey, tuple[NodeSpec, ...]]:
    """Build the nodes of an interface-only default route that the tracer
    recognizes as the edge of the estate (a PPPoE or DHCP uplink).

    A destination outside the estate ends at a permit terminal
    (`estate-delivery:`) with the reply binding of `delivery`. A destination
    inside the estate ends at the unknown terminal
    `terminal:estate-destination:`. The result holds the entry, the permit
    terminal and the nodes."""
    tail = delivery.location.removeprefix("delivery:")
    edge = replace(delivery, location=f"estate-delivery:{tail}")
    entry, nodes = _estate_split(
        network,
        af,
        replace(delivery, location=f"estate-delivery-split:{tail}", binding_scope=()),
        edge,
        NodeSpec(
            StateKey(f"terminal:estate-destination:{tail}", delivery.context),
            terminal="unknown",
            complete=False,
        ),
    )
    return entry, edge, nodes


def _by_context(rows: Sequence[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["context_uid"])].append(row)
    return grouped


def _discover(
    interfaces: _Interfaces,
    af: int,
    by_context: Mapping[str, list[dict[str, Any]]],
    starts: set[str | None] | frozenset[str],
    ranges: Sequence[tuple[int, int]],
    graph: GraphInventory | None = None,
    redirects: GraphInventory | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Return the FIB rows whose prefix overlaps one of `ranges`, and the
    contexts that discovery visited.

    Discovery starts in `starts` and follows the next hops of those rows.
    With `graph`, a route that leaves by a VSX warp or bridge interface is
    followed to the context beyond the interface. With `redirects`, discovery
    also visits the tables that a PBR policy on an interface of a visited
    context redirects into."""

    def overlaps(row: Mapping[str, Any]) -> bool:
        prefix = ip_network(str(row["prefix"]), strict=False)
        low, high = int(prefix.network_address), int(prefix.broadcast_address)
        return prefix.version == af and any(low <= end and start <= high for start, end in ranges)

    selected: dict[int, dict[str, Any]] = {}
    pending = [item for item in starts if item]
    visited: set[str] = set()
    while pending:
        context_uid = pending.pop()
        if context_uid in visited:
            continue
        visited.add(context_uid)
        if redirects is not None:
            for interface in interfaces.named(context_uid, None):
                pending.extend(sorted(_redirect_targets(redirects, interface.uid)))
        for row in by_context.get(context_uid, []):
            # Enclosing routes are kept for `_lpm_predicate`.
            if id(row) in selected or not overlaps(row):
                continue
            selected[id(row)] = row
            next_hop = row.get("next_hop")
            pending.extend(
                interface.context_uid for interface in interfaces.holding(next_hop) if interface.context_uid
            )
            if graph is not None:
                for interface in interfaces.named(context_uid, row.get("interface")):
                    target, _, _ = vsx_topology.resolve(graph, interface.uid, next_hop)
                    if target:
                        pending.append(target[1])
    return list(selected.values()), visited


def _declared_domain(graph: GraphInventory, context_uid: str) -> frozenset[str]:
    """Return the contexts that share a declared RoutingDomain or an L3Domain
    with `context_uid` (`path.gates.routing._NEXT_HOP_DOMAIN_QUERY`).

    A `MEMBER_OF` relation whose `basis` is not "declared" does not count."""
    found: set[str] = set()
    for kind, label in (("MEMBER_OF", "RoutingDomain"), ("REALIZES", "L3Domain")):
        for relation in graph.outgoing.get((context_uid, kind), ()):
            domain = graph.nodes.get(relation.end)
            if domain is None or label not in domain.labels:
                continue
            if kind == "MEMBER_OF" and (relation.props.get("basis") or "declared") != "declared":
                continue
            for member in graph.incoming.get((relation.end, kind), ()):
                if kind == "MEMBER_OF" and (member.props.get("basis") or "declared") != "declared":
                    continue
                found.add(member.start)
    return frozenset(found)


def _context_l3doms(graph: GraphInventory, context_uid: str) -> set[str]:
    """The routing domains the addresses and routes of a context resolve to,
    as the tracer's `_NEXT_HOP_CONTEXTS_QUERY` collects them."""
    found: set[str] = set()
    for interface in graph.sources(context_uid, "IN_VRF"):
        found.update(
            str(ip.props["l3dom"]) for ip in graph.targets(interface.uid, "HAS_IP") if ip.props.get("l3dom")
        )
    for kind in ("STATIC_ROUTE", "LEARNED_ROUTE", "ORIGINATES"):
        found.update(
            str(prefix.props["l3dom"])
            for prefix in graph.targets(context_uid, kind)
            if prefix.props.get("l3dom")
        )
    return found


def _single_owner_scope(graph: GraphInventory, owner: str, table: str) -> str | None:
    """Return the scope reason for the one context that owns a next hop,
    compared with the table in which the route resolves the next hop
    (`path.gates.routing._single_owner_scope`).

    The result is None when the owner is accepted. It is
    "next-hop-owner-foreign-context" when 2 non-global VRFs of different
    names share no evidence of one routing domain. That hop is not followed.
    It is "next-hop-owner-unshared-context" for any other pair without that
    evidence. That hop is followed and is not decided."""
    if owner == table or owner in _declared_domain(graph, table):
        return None
    here, there = graph.nodes.get(table), graph.nodes.get(owner)
    if here is None or there is None or "VrfInstance" not in here.labels or "VrfInstance" not in there.labels:
        return "next-hop-owner-unshared-context"
    if here.props.get("is_global") is True and there.props.get("is_global") is True:
        return None
    if here.props.get("name") and here.props.get("name") == there.props.get("name"):
        return None
    if _context_l3doms(graph, table) & _context_l3doms(graph, owner):
        return None
    if here.props.get("is_global") is False and there.props.get("is_global") is False:
        return "next-hop-owner-foreign-context"
    return "next-hop-owner-unshared-context"


def _next_hop_owners(
    graph: GraphInventory, owners: tuple[Interface, ...], row: Mapping[str, Any], context_uid: str
) -> tuple[tuple[Interface, ...], str | None]:
    """Return the owners of the next hop of a route and the scope reason of a
    single owner (`_single_owner_scope`).

    When several contexts own the address, the tracer's ladder narrows the
    owners (`path.gates.routing._next_hop_device`). The route resolves its
    next hop in the exporting context of a leaked route
    (`next_hop_context_uid`) or in its own context. The owners in that table
    are taken first, then the owners in a context of the same declared
    routing domain. If neither step finds an owner, all owners are returned,
    and the caller does not decide a hop with owners in more than one
    context. A single owning context is compared with that table."""
    table = str(row.get("next_hop_context_uid") or context_uid)
    contexts = {owner.context_uid for owner in owners}
    if len(contexts) == 1:
        (owner_context,) = contexts
        return owners, (_single_owner_scope(graph, str(owner_context), table) if owner_context else None)
    if not contexts:
        return owners, None
    domain = _declared_domain(graph, table)
    for scoped in (
        tuple(owner for owner in owners if owner.context_uid == table),
        tuple(owner for owner in owners if owner.context_uid in domain),
    ):
        if scoped:
            return scoped, None
    return owners, None


def _relevant_rows(
    network: Network, request: RequestSet, rows: list[dict[str, Any]], graph: GraphInventory | None = None
) -> list[dict[str, Any]]:
    """Discover only FIB components reachable for any requested member address.

    A row is selected when its prefix overlaps a member range. The selection
    holds the routes that enclose a member and the more specific routes
    inside it. `_lpm_predicate` partitions every member address among these
    routes. Discovery starts in `request.source_context`, or in every context
    that a source range attaches to (`_source_attachments`)."""
    af = _af(request)
    return _discover(
        _Interfaces(network),
        af,
        _by_context(rows),
        _request_starts(network, request, af),
        _member_ranges(request, af),
        graph,
    )[0]


def _request_starts(network: Network, request: RequestSet, af: int) -> set[str | None]:
    return (
        {request.source_context} if request.source_context else set(_source_attachments(network, request, af))
    )


def _member_ranges(request: RequestSet, af: int) -> list[tuple[int, int]]:
    return [
        (low, high)
        for candidate in request.members
        for family, low, high in candidate.addresses
        if family == af
    ]


def _rewritten_destinations(nodes: Iterable[NodeSpec]) -> set[tuple[int, int]]:
    """Return the destination ranges that the edges of the model rewrite to.

    A range is the translated address or range of a DNAT rule, or a
    load-balancer pool member."""
    found: set[tuple[int, int]] = set()
    for node in nodes:
        for edge in node.edges:
            found.update((value, value) for field, value in edge.rewrites if field == "destination_address")
            found.update(
                (item.target_low, item.target_low + item.source_high - item.source_low)
                for item in edge.ranges
                if item.field == "destination_address"
            )
    return found


def _local_addresses(
    network: Network,
    context_uid: str,
    device_uid: str,
    af: int,
    routed: Sequence[tuple[int, int]] | None,
) -> tuple[int, ...]:
    """Return the addresses that the device holds on its interfaces of the
    context and that lie in `routed`.

    `routed` None selects every address."""
    found: set[int] = set()
    for item in network.interfaces:
        if item.context_uid != context_uid or item.device_uid != device_uid:
            continue
        for text in item.addresses:
            try:
                address = ip_interface(str(text)).ip
            except ValueError:
                continue
            value = int(address)
            if address.version == af and (
                routed is None or any(low <= value <= high for low, high in routed)
            ):
                found.add(value)
    return tuple(sorted(found))


def request_devices(network: Network, request: RequestSet) -> frozenset[str]:
    """Return the devices whose graph objects one request reads first.

    The result holds the owners of every context that the forward discovery
    visits, and of every context that a reply toward the sources visits from
    there. A context without an owning device contributes the devices of its
    interfaces. The source device of the request is included. A scoped load
    starts with these devices. A model that needs another device widens the
    load (`graph.ScopeExtension`)."""
    af = _af(request)
    interfaces = _Interfaces(network)
    by_context = _by_context([row for row in network.routes.rib if row.get("af") == af])
    _rows, forward = _discover(
        interfaces, af, by_context, _request_starts(network, request, af), _member_ranges(request, af)
    )
    sources = [(low, high) for family, low, high in request.sources if family == af]
    _rows, reply = _discover(interfaces, af, by_context, frozenset(forward), sources)
    owners = {str(item["uid"]): item.get("device_uid") for item in network.routing.contexts}
    devices: set[str] = {request.source_device_uid} if request.source_device_uid else set()
    for context_uid in forward | reply:
        owner = owners.get(context_uid)
        if isinstance(owner, str) and owner:
            devices.add(owner)
        else:
            devices.update(str(item.device_uid) for item in interfaces.by_context.get(context_uid, ()))
    return frozenset(devices)


# The location prefix of the unknown terminal of a routing state whose context
# has no collected routing table (`Network.unobserved`).
ROUTE_NOT_OBSERVED = "terminal:route-not-observed:"


class _LongestMatch:
    """The rows of one context sorted on (family, network address)."""

    def __init__(self, rows: Sequence[Mapping[str, Any]]) -> None:
        self.parsed = [ip_network(str(row["prefix"]), strict=False) for row in rows]
        self.position = {id(row): index for index, row in enumerate(rows)}
        self.order = sorted(
            range(len(rows)),
            key=lambda index: (self.parsed[index].version, int(self.parsed[index].network_address)),
        )
        self.keys = [
            (self.parsed[index].version, int(self.parsed[index].network_address)) for index in self.order
        ]

    def predicate(self, row: Mapping[str, Any]) -> Predicate:
        """The address region this row selects after longer prefixes win.
        The excluded prefixes keep the order of the context's rows."""
        index = self.position[id(row)]
        prefix = self.parsed[index]
        low, high = int(prefix.network_address), int(prefix.broadcast_address)
        start = bisect_left(self.keys, (prefix.version, low))
        end = bisect_right(self.keys, (prefix.version, high))
        inner = sorted(
            candidate
            for candidate in self.order[start:end]
            if candidate != index
            and self.parsed[candidate].prefixlen > prefix.prefixlen
            and int(self.parsed[candidate].broadcast_address) <= high
        )
        more_specific = tuple(
            Atom(
                "destination_address",
                "range",
                int(self.parsed[candidate].network_address),
                int(self.parsed[candidate].broadcast_address),
            )
            for candidate in inner
        )
        selected = Atom("destination_address", "range", low, high)
        return AllOf((selected, Not(AnyOf(more_specific)))) if more_specific else selected


def _lpm_predicate(row: Mapping[str, Any], rows: Sequence[Mapping[str, Any]], af: int) -> Predicate:
    """The address region selected by this FIB row after longer prefixes win."""
    context = str(row["context_uid"])
    return _LongestMatch([item for item in rows if str(item.get("context_uid")) == context]).predicate(row)


# The state of the member that forwards for a first-hop redundancy group
# (core/labels.py `HAS_IP`).
_FHRP_FORWARDING = {"hsrp": "active", "vrrp": "master"}


def _fhrp_standby_addresses(graph: GraphInventory, interface_uid: str) -> tuple[str, ...]:
    """The virtual addresses of the first-hop redundancy groups in which the
    interface does not forward. The rule is the rule of the tracer
    (path/trace.py). Each member of the group has a recorded state, and 1
    other member has the forwarding state."""
    out = []
    for held in graph.outgoing.get((interface_uid, "HAS_IP"), ()):
        kind = str(held.props.get("fhrp") or "").lower()
        if kind not in _FHRP_FORWARDING:
            continue
        states = [
            str(member.props.get("state") or "").lower()
            for member in graph.incoming.get((held.end, "HAS_IP"), ())
            if str(member.props.get("fhrp") or "").lower() == kind
            and member.props.get("group") == held.props.get("group")
        ]
        own = str(held.props.get("state") or "").lower()
        address = graph.nodes[held.end].props.get("ip") if held.end in graph.nodes else None
        if (
            address
            and not {"", "unknown"} & set(states)
            and states.count(_FHRP_FORWARDING[kind]) == 1
            and own != _FHRP_FORWARDING[kind]
        ):
            out.append(str(address))
    return tuple(out)


def _source_attachments(
    network: Network, request: RequestSet, af: int, graph: GraphInventory | None = None
) -> dict[str, tuple[tuple[int, int, int], ...]]:
    """Intersect every source interval with every qualified interface prefix.

    With `graph`, a prefix whose first-hop redundancy group has another
    member as its forwarder is no attachment of the interface
    (`_fhrp_standby_addresses`)."""
    attached: dict[str, set[tuple[int, int, int]]] = defaultdict(set)
    for interface in network.interfaces:
        if interface.context_uid is None:
            continue
        standby = (
            [ip_address(value) for value in _fhrp_standby_addresses(graph, interface.uid)]
            if graph is not None
            else []
        )
        for prefix_text in interface.prefixes:
            prefix = ip_network(prefix_text, strict=False)
            if prefix.version != af or any(address in prefix for address in standby):
                continue
            low, high = int(prefix.network_address), int(prefix.broadcast_address)
            for family, source_low, source_high in request.sources:
                if family == af and max(low, source_low) <= min(high, source_high):
                    attached[str(interface.context_uid)].add(
                        (af, max(low, source_low), min(high, source_high))
                    )
    return {context: tuple(sorted(values)) for context, values in attached.items()}


def _entry_predicate(source: Predicate, member: Member) -> Predicate:
    """Return the predicate of an entry.

    The predicate selects the source addresses of the entry toward the
    addresses of the member. The walked request holds the service."""
    return AllOf((source, _intervals("destination_address", member.addresses)))


def normalize_network(
    network: Network,
    graph: GraphInventory,
    request: RequestSet,
    member: Member,
    estate: str,
    *,
    _all_routes: bool = False,
    evidence: EvidenceEvaluation | None = None,
    _policy_state: str = "new",
    _reply: bool = False,
    _reply_ingresses: Mapping[str, frozenset[str]] | None = None,
    _reply_scope: tuple[frozenset[str], tuple[tuple[int, int, int], ...]] | None = None,
    _rewrite_seeds: tuple[tuple[int, int], ...] = (),
) -> ModelInput:
    """Produce a pinned symbolic routing model for one member of a request.

    The ECMP assignment catalogue is built from the FIB rows that discovery
    selects for every member of the request (`_discover`), before the entry
    predicate of the member is selected. Repeated calls for members of one
    ``RequestSet`` keep identical joint choices. `_reply_scope` replaces the
    discovery of the request with the discovery of the reply. It holds the
    start contexts and the addresses that a reply is routed toward
    (`normalize_reply_network`).

    A routing state is one context entered by one interface. Its execution
    context holds the device that processes it. This is the owning device of
    the context. For a context that spans devices (an ACI fabric VRF) or has
    no device (a PBR redirect table) it is the device of the ingress
    interface. A PBR redirect table is consulted on the device that redirects
    and is entered by the redirecting interface. Sources in a context without
    an owning device enter by the one interface that holds them. A state
    whose device is not known is an unknown terminal whose location holds its
    context and ingress. `_reply_ingresses` adds, per context, the interfaces
    that a reply model enters by (`normalize_reply_network`).

    Discovery also selects the rows toward every destination that a DNAT rule
    or a load balancer of the model rewrites to (`_rewrite_seeds`). A
    destination that the device of a routing state holds itself is an unknown
    terminal.
    """
    if member not in request.members:
        raise ValueError("member is not part of this request set")
    if not graph.complete:
        raise ValueError("an incomplete graph inventory cannot establish a routing model")
    af = _af(request)
    result = network.routes
    all_rows = [row for row in result.rib if row.get("af") == af]
    has_vsx_transit = graph.has_vsx_transit()
    interfaces = _Interfaces(network)
    all_by_context = _by_context(all_rows)
    transit_graph = graph if has_vsx_transit else None
    visited: set[str] = set()
    starts: set[str | None] | frozenset[str] = frozenset()
    # `routed` holds the destinations that discovery routes toward. None selects every route.
    routed: list[tuple[int, int]] | None = None
    if _all_routes:
        rows = all_rows
    elif _reply_scope is not None:
        starts, destinations = _reply_scope
        routed = [(low, high) for family, low, high in destinations if family == af] + list(_rewrite_seeds)
        rows, visited = _discover(
            interfaces,
            af,
            all_by_context,
            starts,
            routed,
            transit_graph,
            redirects=graph,
        )
    else:
        routed = _member_ranges(request, af) + list(_rewrite_seeds)
        starts = _request_starts(network, request, af)
        rows, visited = _discover(interfaces, af, all_by_context, starts, routed, transit_graph)
    redirect_owners = _aci_redirect_owners(graph, interfaces)
    if routed is not None and redirect_owners and visited & aci_fabric_contexts(graph, af):
        # A contract with a service graph redirects into the context of its redirect destination.
        redirected = {str(owner.context_uid) for owner in redirect_owners.values()} - visited
        if redirected:
            rows, visited = _discover(
                interfaces,
                af,
                all_by_context,
                {*starts, *redirected},
                routed,
                transit_graph,
                redirects=graph if _reply_scope is not None else None,
            )
    choices, alternatives, choices_complete = _choice_catalog(rows)
    routing_contexts = {str(item["uid"]): item for item in network.routing.contexts}
    contexts = {str(row["context_uid"]) for row in rows}
    if _reply_scope is not None:
        # A visited context with routes and with no route toward the reply is
        # a routing state. The reply has no route there.
        contexts.update(context_uid for context_uid in visited if context_uid in all_by_context)
    if request.source_context:
        contexts.add(request.source_context)
    rows_by_context = _by_context(rows)
    ingresses: dict[str, set[str | None]] = {context_uid: {None} for context_uid in contexts}
    for row in rows:
        for interface in interfaces.holding(row.get("next_hop")):
            if interface.context_uid:
                ingresses.setdefault(interface.context_uid, set()).add(interface.uid)
    if has_vsx_transit:
        for interface in network.interfaces:
            if interface.context_uid in contexts:
                ingresses.setdefault(interface.context_uid, set()).add(interface.uid)
    for context_uid, extra in (_reply_ingresses or {}).items():
        if context_uid in contexts:
            ingresses.setdefault(context_uid, {None}).update(extra)
    # A redirected packet enters the context of its redirect destination by the
    # interface that holds the destination.
    for owner in redirect_owners.values():
        if owner.context_uid in contexts:
            ingresses.setdefault(str(owner.context_uid), {None}).add(owner.uid)
    # Sources enter by the interface that holds them. The ingress-scoped policy
    # and the zone policy of that gateway interface judge them. In a context
    # without an owning device, the device of that interface is the device of
    # the source state.
    attachments = _source_attachments(network, request, af, graph) if request.source_context is None else None
    attached: dict[str, tuple[tuple[int, int, int], ...]] = (
        dict(attachments)
        if attachments is not None
        else {str(request.source_context): tuple(item for item in request.sources if item[0] == af)}
    )
    source_ingress: dict[str, str] = {}
    for context_uid, ranges in attached.items():
        if context_uid not in contexts:
            continue
        interface_uid = (
            request.ingress_interface_uid
            if request.source_context and request.ingress_interface_uid
            else _attachment_interface(network, context_uid, ranges, af)
        )
        if interface_uid is None:
            continue
        source_ingress[context_uid] = interface_uid
        ingresses.setdefault(context_uid, {None}).add(interface_uid)
    # A redirect table without an owning device is consulted on the device
    # that redirects, for the packet that entered by the redirecting interface.
    for values in list(ingresses.values()):
        for redirecting in [value for value in values if value]:
            for table in _redirect_targets(graph, redirecting):
                if table in contexts and _owning_device(routing_contexts, table) is None:
                    ingresses.setdefault(table, {None}).add(redirecting)
    devices = {
        (context_uid, ingress): _state_device(network, routing_contexts, context_uid, ingress)
        for context_uid, values in ingresses.items()
        for ingress in values
    }
    keys = {
        (context_uid, ingress): StateKey(
            f"routing:{context_uid}:ingress:{ingress or 'none'}",
            _context(routing_contexts, graph, context_uid, estate, af, device),
            binding_scope=(f"ingress:{ingress or 'none'}",),
        )
        if device is not None
        else _device_unknown_key(context_uid, ingress, estate, af)
        for (context_uid, ingress), device in devices.items()
    }
    nodes: list[NodeSpec] = []
    mtu_egresses: dict[StateKey, Interface] = {}
    # `edge_rows` holds, per terminal where a route ends the model, the estate
    # exit of each row or None.
    edge_rows: dict[StateKey, list[ExitRecord | None]] = defaultdict(list)
    # `free_ports` holds the masquerade edges whose source port the device picks.
    free_ports: list[tuple[StateKey, str]] = []
    pre_keys: dict[tuple[str, str | None], StateKey] = {}
    ordered_keys = sorted(keys.items(), key=lambda item: (item[0][0], item[0][1] or ""))
    for (context_uid, ingress), routing_key in ordered_keys:
        physical_device = devices[context_uid, ingress]
        if physical_device is None:
            nodes.append(NodeSpec(routing_key, terminal="unknown", complete=False))
            pre_keys[context_uid, ingress] = routing_key
            continue
        pre = expand_device_gates(
            graph,
            routing_key.context,
            physical_device,
            ingress,
            None,
            routing_key,
            phases=("dnat", "pbr"),
            routing_targets={
                target_context: keys[target_context, ingress]
                if (target_context, ingress) in keys
                else keys[target_context, None]
                for target_context in contexts
                if (target_context, ingress) in keys or (target_context, None) in keys
            },
        )
        if pre.choices and len(choices) * len(pre.choices) > MAX_JOINT_CHOICES:
            choices_complete = False
            cutoff = StateKey(
                f"terminal:choice-cutoff:{context_uid}:{ingress or 'none'}", routing_key.context
            )
            nodes.append(NodeSpec(cutoff, terminal="unknown", complete=False))
            pre_keys[context_uid, ingress] = cutoff
        else:
            choices = merge_choice_assignments(choices, pre.choices)
            nodes.extend(pre.nodes)
            pre_keys[context_uid, ingress] = pre.entry
    redirect_targets = {
        address: pre_keys[str(owner.context_uid), owner.uid]
        for address, owner in redirect_owners.items()
        if (str(owner.context_uid), owner.uid) in pre_keys
    }
    tunnel_targets = _tunnel_targets(
        graph,
        network,
        all_rows,
        pre_keys,
        _egress_tunnels(
            graph,
            interfaces,
            rows_by_context,
            {context for (context, _), device in devices.items() if device},
        ),
        interfaces,
    )
    # `scope` holds the destinations that the routing states of this model
    # route, in the form that `Network.incomplete` scopes its gaps by. None
    # selects every route. The carrier address of a tunnel that the model
    # links to its far end is in the scope. The scope is sound only while the
    # model does not follow recursive next hops. A next hop that no interface
    # holds ends the model at an unknown or edge terminal.
    scope = (
        None
        if routed is None
        else tuple(
            sorted(
                {(af, low, high) for low, high in routed}
                | {(af, value, value) for value in _carrier_addresses(graph, tunnel_targets, af)}
            )
        )
    )
    for context_uid, ingress in sorted(keys, key=lambda item: (item[0], item[1] or "")):
        key = keys[context_uid, ingress]
        state_device = devices[context_uid, ingress]
        if state_device is None:
            # the unknown terminal was recorded with the gates above
            continue
        device_uid = state_device
        route_scoped_policy = any(
            rel.props.get("egress_interface_uid") not in (None, "*")
            for rel in graph.outgoing.get((key.context.firewall_instance, "ENFORCES"), ())
        )
        egress_scoped_policy = not route_scoped_policy and _egress_scoped(graph, key.context, ingress, af)
        policy = (
            None
            if route_scoped_policy or egress_scoped_policy
            else _access_policy(graph, key.context, device_uid, ingress, None, af, _policy_state)
        )
        context_rows = rows_by_context.get(context_uid, [])
        if not context_rows and not (_reply_scope is not None and context_uid in all_by_context):
            nodes.append(NodeSpec(key, terminal="unknown", complete=False))
            continue
        edges: list[EdgeSpec] = []
        # A destination that the device holds is delivered to the device
        # itself. The forward policy of this state is applied on the FIB
        # edges, and the held addresses take an edge of their own.
        local = _local_addresses(network, context_uid, device_uid, af, routed)
        held = AnyOf(tuple(Atom("destination_address", "range", value, value) for value in local))
        forward_policy = policy if local else None
        if local:
            policy = None
        longest = _LongestMatch(context_rows)
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in context_rows:
            groups[str(row["prefix"])].append(row)
        ordered = {prefix: sorted(group, key=repr) for prefix, group in groups.items() if len(group) > 1}
        for row in context_rows:
            egresses = interfaces.named(context_uid, str(row.get("interface") or ""))
            route_key = (context_uid, str(row["prefix"]))
            route_choices = alternatives.get(route_key, ())
            row_choice: tuple[tuple[str, str], ...] = ()
            if route_choices:
                index = ordered[route_key[1]].index(row)
                row_choice = (route_choices[index],)
            predicate = longest.predicate(row)
            # `gate_egress` is the interface that the row leaves by, for the
            # gates after routing. At a recognized next-hop edge it is the
            # resolved uplink.
            gate_egress: Interface | None = egresses[0] if len(egresses) == 1 else None
            if row.get("discard"):
                target = StateKey(f"terminal:discard:{context_uid}:{row['prefix']}", key.context)
                nodes.append(NodeSpec(target, terminal="no_route"))
            else:
                next_hop = row.get("next_hop")
                owners, owner_scope = _next_hop_owners(graph, interfaces.holding(next_hop), row, context_uid)
                transit, crossings, transit_gap = (
                    vsx_topology.resolve(graph, egresses[0].uid, str(next_hop) if next_hop else None)
                    if len(egresses) == 1
                    else (None, (), None)
                )
                if transit_gap:
                    target = StateKey(f"terminal:{transit_gap}:{context_uid}:{row['prefix']}", key.context)
                    nodes.append(NodeSpec(target, terminal="unknown", complete=False))
                elif transit:
                    transit_target = pre_keys.get((transit[1], transit[0]))
                    if transit_target is None:
                        target = StateKey(f"terminal:vsx-context-missing:{transit[1]}", key.context)
                        nodes.append(NodeSpec(target, terminal="unknown", complete=False))
                    else:
                        target = transit_target
                    for bridge_in, bridge_out in reversed(crossings):
                        bridge = graph.nodes[bridge_in]
                        if bridge.props.get("vsx_kind") != "bridge":
                            continue
                        vrfs = graph.targets(bridge_in, "IN_VRF")
                        owners_of_bridge = graph.targets(bridge_in, "ON")
                        if len(vrfs) != 1 or len(owners_of_bridge) != 1:
                            target = StateKey(f"terminal:vsx-bridge-owner:{bridge_in}", key.context)
                            nodes.append(NodeSpec(target, terminal="unknown", complete=False))
                            continue
                        bridge_context = _context(
                            {vrfs[0].uid: {"device_uid": owners_of_bridge[0].uid}},
                            graph,
                            vrfs[0].uid,
                            estate,
                            af,
                        )
                        bound, installed = _bindings(graph, bridge_context, bridge_in, bridge_out, af)
                        bridge_policy = (
                            checkpoint_policy(graph, bound, bridge_context, installed) if bound else None
                        )
                        if bridge_policy is None:
                            bridge_policy = unknown_checkpoint_policy(graph, bridge_context, installed)
                        bridge_key = StateKey(
                            f"vsx-bridge:{bridge_in}:{bridge_out}:{target.location}",
                            bridge_context,
                            binding_scope=(bridge_in, bridge_out),
                        )
                        nodes.append(
                            NodeSpec(bridge_key, (EdgeSpec("bridge:forward", target),), policy=bridge_policy)
                        )
                        target = bridge_key
                elif owner_scope == "next-hop-owner-foreign-context":
                    # The one owner is in a VRF of another name with no shared
                    # routing domain. The hop is not followed, as in the tracer.
                    target = StateKey(f"terminal:{owner_scope}:{context_uid}:{row['prefix']}", key.context)
                    nodes.append(NodeSpec(target, terminal="unknown", complete=False))
                elif owners and len({item.context_uid for item in owners}) == 1:
                    next_key = pre_keys.get((str(owners[0].context_uid), owners[0].uid))
                    if next_key is None:
                        owner_context = str(owners[0].context_uid)
                        owner_device = _state_device(network, routing_contexts, owner_context, owners[0].uid)
                        target = (
                            StateKey(
                                f"routing:{owner_context}:ingress:{owners[0].uid}",
                                _context(routing_contexts, graph, owner_context, estate, af, owner_device),
                                binding_scope=(f"ingress:{owners[0].uid}",),
                            )
                            if owner_device is not None
                            else _device_unknown_key(owner_context, owners[0].uid, estate, af)
                        )
                    else:
                        target = next_key
                    if owner_scope is not None:
                        # The hop is followed. The routing domain of the hop is
                        # not established, and the incomplete node adds an
                        # unknown outcome beside the forwarding.
                        unshared = StateKey(
                            f"{owner_scope}:{context_uid}:{row['prefix']}:{owners[0].uid}", key.context
                        )
                        nodes.append(
                            NodeSpec(unshared, (EdgeSpec("next-hop:follow", target),), complete=False)
                        )
                        target = unshared
                elif next_hop is None and egresses:
                    reply_binding = (f"reply-ingress:{egresses[0].uid}",) if len(egresses) == 1 else ()
                    target = StateKey(
                        f"delivery:{context_uid}:{row['prefix']}",
                        key.context,
                        binding_scope=reply_binding,
                    )
                    found = _edge_exit(network, device_uid, context_uid, row, egresses)
                    if found is None:
                        nodes.append(NodeSpec(target, terminal="permit"))
                    else:
                        target, edge, edge_nodes = _delivery_edge(network, af, target)
                        nodes.extend(edge_nodes)
                        edge_rows[edge].append(found[0])
                else:
                    # Several contexts own the next hop and `_next_hop_owners`
                    # selected none of them, or no context owns the next hop.
                    reason = "next-hop-owner-ambiguous" if owners else "unknown-hop"
                    target = StateKey(f"terminal:{reason}:{context_uid}:{row['prefix']}", key.context)
                    found = (
                        _edge_exit(network, device_uid, context_uid, row, egresses)
                        if reason == "unknown-hop"
                        else None
                    )
                    if found is None:
                        nodes.append(NodeSpec(target, terminal="unknown", complete=False))
                    else:
                        target, edge, edge_nodes = _next_hop_edge(
                            network, af, key.context, context_uid, row, target, found[1]
                        )
                        nodes.extend(edge_nodes)
                        edge_rows[edge].append(found[0])
                        gate_egress = found[1]
                expansion = expand_device_gates(
                    graph,
                    key.context,
                    device_uid,
                    ingress,
                    gate_egress.uid if gate_egress is not None else None,
                    target,
                    phases=("snat", "load-balancer", "tunnel"),
                    tunnel_targets=tunnel_targets,
                    reroute=key,
                    choices_so_far=choices,
                    max_choices=MAX_JOINT_CHOICES,
                )
                if expansion.choices and len(choices) * len(expansion.choices) > MAX_JOINT_CHOICES:
                    choices_complete = False
                    target = StateKey(f"terminal:choice-cutoff:{context_uid}:{row['prefix']}", key.context)
                    nodes.append(NodeSpec(target, terminal="unknown", complete=False))
                else:
                    choices = merge_choice_assignments(choices, expansion.choices)
                    nodes.extend(expansion.nodes)
                    free_ports.extend(expansion.free_source_ports)
                    target = expansion.entry
                if (
                    gate_egress is not None
                    and request.mtu is not None
                    and request.mtu.mode not in {"off", "inventory"}
                ):
                    mtu_key = StateKey(f"gate:mtu:{key.location}:{len(edges)}", key.context, "mtu")
                    nodes.append(NodeSpec(mtu_key, (EdgeSpec("mtu:continue", target),)))
                    mtu_egresses[mtu_key] = gate_egress
                    target = mtu_key
            if route_scoped_policy or egress_scoped_policy:
                scoped_policy = _access_policy(
                    graph,
                    key.context,
                    device_uid,
                    ingress,
                    gate_egress.uid
                    if route_scoped_policy and gate_egress is not None
                    else _policy_egress(network, context_uid, egresses, row.get("next_hop"))
                    if egress_scoped_policy
                    else None,
                    af,
                    _policy_state,
                )
                prefix = "vsx-filter" if route_scoped_policy else "egress-filter"
                filter_key = StateKey(f"{prefix}:{key.location}:{len(edges)}", key.context)
                nodes.append(
                    NodeSpec(filter_key, (EdgeSpec("filter:continue", target),), policy=scoped_policy)
                )
                target = filter_key
            if forward_policy is not None:
                forward_key = StateKey(f"forward-filter:{key.location}:{len(edges)}", key.context)
                nodes.append(
                    NodeSpec(forward_key, (EdgeSpec("filter:continue", target),), policy=forward_policy)
                )
                target = forward_key
            edges.append(
                EdgeSpec(
                    f"fib:{context_uid}:{row['prefix']}:{len(edges)}",
                    target,
                    AllOf((predicate, Not(held))) if local else predicate,
                    choices=row_choice,
                )
            )
        if local:
            # the input chain or local zone that judges it is not modeled
            local_key = StateKey(f"terminal:router-local:{key.location}", key.context)
            nodes.append(NodeSpec(local_key, terminal="unknown", complete=False))
            edges.append(EdgeSpec(f"local:{context_uid}", local_key, held))
        # `Network.incomplete` returns the gaps of the context that can change
        # the route of a destination in `scope`. A gap scoped to a prefix that
        # holds no such destination, or to a route of the other family, is
        # left out. A gap of the whole context counts (an unread table, a run
        # that did not settle). With `scope` None, every gap counts.
        #
        # The gaps of `Network.unobserved` leave the state complete. The model
        # follows the computed routes of the context. A destination that no
        # computed route and no address of the device holds ends at an unknown
        # terminal.
        unobserved = tuple(dict.fromkeys(network.unobserved(context_uid, scope)))
        reasons = tuple(
            reason
            for reason in dict.fromkeys(network.incomplete(context_uid, scope))
            if reason not in unobserved
        )
        if unobserved:
            covered = tuple(
                Atom(
                    "destination_address", "range", int(prefix.network_address), int(prefix.broadcast_address)
                )
                for prefix in longest.parsed
                if prefix.version == af
            )
            unrouted_key = StateKey(f"{ROUTE_NOT_OBSERVED}{key.location}", key.context)
            nodes.append(
                NodeSpec(unrouted_key, terminal="unknown", complete=False, incomplete_reasons=unobserved)
            )
            edges.append(
                EdgeSpec(f"unrouted:{context_uid}", unrouted_key, Not(AnyOf((*covered, *held.terms))))
            )
        incomplete = bool(reasons) or not choices_complete
        node_evidence = (
            refs_for_context(evidence, device_uid, frozenset({"interfaces", "routes", "access", "nat"}))
            if evidence is not None
            else ()
        )
        nodes.append(
            NodeSpec(
                key,
                tuple(edges),
                policy=policy,
                complete=not incomplete,
                evidence=node_evidence,
                incomplete_reasons=reasons,
            )
        )
    source_context = request.source_context
    # `entry_specs` holds the entries that the source gates wrap (ACI, then
    # ZPA). `unattached` holds the entry for the sources that no attachment
    # holds. The source gates do not wrap that entry.
    entry_specs: list[EntrySpec] = []
    unattached: list[EntrySpec] = []
    if attachments is not None and len(attachments) > 1:
        attachment_predicates = {
            context: _intervals("source_address", ranges) for context, ranges in attachments.items()
        }
        for context, predicate in sorted(attachment_predicates.items()):
            others = AnyOf(
                tuple(value for candidate, value in attachment_predicates.items() if candidate != context)
            )
            attached_ingress = source_ingress.get(context)
            entry_key = (
                pre_keys.get((context, attached_ingress))
                or keys.get((context, attached_ingress))
                or pre_keys.get((context, None))
                or keys.get((context, None))
            )
            if entry_key is not None:
                # each attachment enters in its own context, and the ACI
                # gate scopes its endpoints to that context
                attached_aci = expand_aci_contracts(
                    graph,
                    entry_key.context,
                    entry_key,
                    sources=attachments[context],
                    destinations=member.addresses,
                    redirect_targets=redirect_targets,
                )
                nodes.extend(attached_aci.nodes)
                entry_specs.append(
                    EntrySpec(attached_aci.entry, _entry_predicate(AllOf((predicate, Not(others))), member))
                )
        unknown_context = ExecutionContext(
            estate, "graph", "graph", "unknown", "unknown", cast(Literal[4, 6], af)
        )
        unknown_key = StateKey("routing:source-attachment:unknown", unknown_context)
        nodes.append(NodeSpec(unknown_key, terminal="unknown", complete=False))
        known = AnyOf(tuple(attachment_predicates.values()))
        unattached.append(
            EntrySpec(
                unknown_key,
                _entry_predicate(AllOf((_intervals("source_address", request.sources), Not(known))), member),
            )
        )
    else:
        if attachments is not None:
            source_context = next(iter(attachments), None)
        source_context = str(source_context) if source_context is not None else None
        entry_ingress = (
            source_ingress.get(source_context, request.ingress_interface_uid) if source_context else None
        )
        source_key = keys.get((source_context, entry_ingress)) if source_context else None
        source_key = source_key or (keys.get((source_context, None)) if source_context else None)
        if source_key is None:
            source_context = str(source_context or "unknown")
            unknown_context = ExecutionContext(
                estate, "graph", "graph", "unknown", source_context, cast(Literal[4, 6], af)
            )
            source_key = StateKey(f"routing:{source_context}:unknown", unknown_context)
            nodes.append(NodeSpec(source_key, terminal="unknown", complete=False))
        else:
            source_context_key = str(source_context)
            source_key = (
                pre_keys.get((source_context_key, entry_ingress))
                or pre_keys.get((source_context_key, None))
                or source_key
            )
        aci = expand_aci_contracts(
            graph,
            source_key.context,
            source_key,
            sources=request.sources,
            destinations=member.addresses,
            redirect_targets=redirect_targets,
        )
        nodes.extend(aci.nodes)
        entry_specs.append(
            EntrySpec(aci.entry, _entry_predicate(_intervals("source_address", request.sources), member))
        )
    if request.segment_uid and request.identity_uid:
        # Each entry gets one broker expansion. Entries whose expansions offer
        # the same connector choices join the catalogue once. The cutoff
        # counts each choice scope once.
        joined: dict[tuple[str, ...], bool] = {}
        wrapped: list[EntrySpec] = []
        for entry in entry_specs:
            zpa = expand_zpa_broker(
                graph,
                entry.key.context,
                request.identity_uid,
                request.segment_uid,
                entry.key,
            )
            offered = tuple(choice.uid for choice in zpa.choices)
            if offered not in joined:
                joined[offered] = not (zpa.choices and len(choices) * len(zpa.choices) > MAX_JOINT_CHOICES)
                if joined[offered]:
                    choices = merge_choice_assignments(choices, zpa.choices)
                else:
                    choices_complete = False
            if joined[offered]:
                nodes.extend(zpa.nodes)
                wrapped.append(replace(entry, key=zpa.entry))
            else:
                cutoff = StateKey("terminal:zpa-choice-cutoff", entry.key.context, "proxy")
                nodes.append(NodeSpec(cutoff, terminal="unknown", complete=False))
                wrapped.append(replace(entry, key=cutoff))
        entry_specs = wrapped
    rewritten = _rewritten_destinations(nodes)
    if routed is not None and any(
        not any(low <= start and end <= high for low, high in routed) for start, end in rewritten
    ):
        # Discovery did not route toward a translated destination. The model
        # is built again with that destination as a seed. The seeds only grow
        # within the finite set of rewrite targets of the graph, and the
        # recursion ends.
        return normalize_network(
            network,
            graph,
            request,
            member,
            estate,
            evidence=evidence,
            _policy_state=_policy_state,
            _reply=_reply,
            _reply_ingresses=_reply_ingresses,
            _reply_scope=_reply_scope,
            _rewrite_seeds=tuple(sorted({*_rewrite_seeds, *rewritten})),
        )
    edges_found = {key: exits for key, found in edge_rows.items() if (exits := _edge_exits(found))}
    if edges_found:
        nodes = [
            _at_estate_edge(node, edges_found[node.key])
            if node.terminal is not None and node.key in edges_found
            else node
            for node in nodes
        ]
    if free_ports:
        nodes = _free_source_ports(nodes, free_ports)
    # the SD-WAN boundaries and the MTU requirement apply to every entry alike
    unique = tuple({node.key: node for node in nodes}.values())
    model = ModelInput(
        graph.manifest_digest,
        unique,
        (*entry_specs, *unattached),
        choices,
        choices_complete,
        # `scope_evidence` limits the evidence to the observations that the
        # states of the model depend on.
        evidence=scope_evidence(
            evidence,
            {
                (r.source, r.subject, r.section, r.address_family, r.vrf)
                for node in unique
                for r in node.evidence
            },
        )
        if evidence is not None
        else None,
    )
    model = project_sdwan(
        model,
        graph,
        {uid: device for uid in routing_contexts if (device := _owning_device(routing_contexts, uid))},
    )
    return project_mtu(model, request.mtu, mtu_egresses, reply=_reply)


def _reads_source_port(predicate: Predicate, field: str = "source_port") -> bool:
    """Whether a predicate compares the port `field`. An object that a `Ref`
    refers to is read with the policy that holds it."""
    if isinstance(predicate, Atom):
        return predicate.field == field
    if isinstance(predicate, (AllOf, AnyOf)):
        return any(_reads_source_port(term, field) for term in predicate.terms)
    if isinstance(predicate, Not):
        return _reads_source_port(predicate.term, field)
    return False


def _policy_reads_source_port(policy: Policy, field: str = "source_port") -> bool:
    return (
        _reads_source_port(policy.installation, field)
        or any(_reads_source_port(item.predicate, field) for item in policy.objects)
        or any(_reads_source_port(rule.predicate, field) for layer in policy.layers for rule in layer.rules)
    )


def _node_reads(node: NodeSpec, field: str) -> bool:
    return (node.policy is not None and _policy_reads_source_port(node.policy, field)) or any(
        _reads_source_port(edge.predicate, field) for edge in node.edges
    )


def _picked_port_replies(
    nodes: dict[StateKey, NodeSpec], entries: list[EntrySpec], owners: frozenset[ExecutionContext]
) -> None:
    """Lead the reply states that compare the picked port to an unknown
    terminal, in place.

    `owners` holds the contexts that masqueraded the request. A state that
    the reply passes before it comes back to such a context sees the port
    that the device picked as its destination port. The model holds the port
    of the request there. A state of this kind that compares the destination
    port leads every packet to an unknown terminal whose location holds the
    state (`NAT_SOURCE_PORT_UNKNOWN`). A reply that enters the masquerading
    context first is restored there and is unchanged."""
    seen: set[StateKey] = set()
    queue = [entry.key for entry in entries if entry.key.context not in owners]
    while queue:
        key = queue.pop(0)
        if key in seen:
            continue
        seen.add(key)
        node = nodes.get(key)
        if node is None or key.context in owners:
            continue
        if node.terminal is None and _node_reads(node, "destination_port"):
            terminal = StateKey(f"terminal:picked-port-read-at:{key.location}", key.context, key.stage)
            nodes[terminal] = NodeSpec(terminal, terminal="unknown", complete=False)
            nodes[key] = replace(
                node,
                edges=(
                    EdgeSpec(
                        "nat:picked-port",
                        terminal,
                        AllOf((Constant(True), Unknown("NAT_SOURCE_PORT_UNKNOWN", key.location))),
                    ),
                ),
                policy=None,
            )
            continue
        queue.extend(edge.target for edge in node.edges if edge.target.context not in owners)


def _free_source_ports(nodes: list[NodeSpec], free: list[tuple[StateKey, str]]) -> list[NodeSpec]:
    """Record the masquerade edges in `free` on their gates, or lead them to
    an unknown terminal.

    A masquerade keeps the source port of the packet in the model, and the
    device picks another port that no snapshot holds. Where no state after
    the edge compares the source port, the outcome of a packet does not
    depend on the port, and the gate records the edge in `free_source_ports`.
    Where a state compares the source port, the edge leads to an unknown
    terminal whose location holds the first such state
    (`NAT_SOURCE_PORT_UNKNOWN`)."""
    by_key = {node.key: node for node in nodes}
    replaced: dict[StateKey, NodeSpec] = {}
    added: list[NodeSpec] = []
    for gate_key, edge_uid in dict.fromkeys(free):
        gate = replaced.get(gate_key) or by_key.get(gate_key)
        if gate is None:
            continue
        edge = next((item for item in gate.edges if item.uid == edge_uid), None)
        if edge is None:
            continue
        reader = _source_port_reader(by_key, edge.target)
        if reader is None:
            # The gate records the edge for the check of the picked port in the
            # reply model (`_picked_port_replies`).
            replaced[gate_key] = replace(gate, free_source_ports=(*gate.free_source_ports, edge_uid))
            continue
        # The location of the terminal holds the state that reads the port.
        # `compile` keeps only the code of the `Unknown` term.
        terminal = StateKey(
            f"{gate_key.location}:source-port:{edge_uid}:read-at:{reader.location}",
            gate_key.context,
            gate_key.stage,
        )
        added.append(NodeSpec(terminal, terminal="unknown", complete=False))
        unknown = EdgeSpec(
            edge.uid,
            terminal,
            AllOf((edge.predicate, Unknown("NAT_SOURCE_PORT_UNKNOWN", reader.location))),
            choices=edge.choices,
            evidence=edge.evidence,
        )
        replaced[gate_key] = replace(
            gate, edges=tuple(unknown if item is edge else item for item in gate.edges)
        )
    return [replaced.get(node.key, node) for node in nodes] + added


def _source_port_reader(by_key: Mapping[StateKey, NodeSpec], start: StateKey) -> StateKey | None:
    """Return the first state from `start` on, in breadth-first order, whose
    policy or edge compares the source port, or None."""
    seen = {start}
    queue = [start]
    while queue:
        key = queue.pop(0)
        node = by_key.get(key)
        if node is None:
            continue
        if _node_reads(node, "source_port"):
            return key
        for edge in node.edges:
            if edge.target not in seen:
                seen.add(edge.target)
                queue.append(edge.target)
    return None


def normalize_request_network(
    network: Network,
    graph: GraphInventory,
    request: RequestSet,
    estate: str,
    *,
    evidence: EvidenceEvaluation | None = None,
) -> dict[str, ModelInput]:
    """Compile every member while preserving the same exhaustive joint choices."""
    return {
        member.name: normalize_network(network, graph, request, member, estate, evidence=evidence)
        for member in request.members
    }


def normalize_reply_network(
    network: Network,
    graph: GraphInventory,
    request: RequestSet,
    member: Member,
    estate: str,
    entry_states: tuple[StateKey, ...],
    *,
    evidence: EvidenceEvaluation | None = None,
    destinations: tuple[tuple[int, int, int], ...] = (),
    masquerading: frozenset[ExecutionContext] = frozenset(),
) -> ModelInput:
    """Build reply entries from bound symbolic terminals.

    ``entry_states`` are qualified delivery contexts selected by the forward
    walker. Their packet predicate is ``True``. The caller keeps the reversed
    terminal PacketSet as the symbolic entry restriction.

    A reply enters the delivery context by the interface that the request
    left it by. The reply model holds a routing state for that interface. In
    a context that spans devices, that state belongs to the device of the
    interface.

    The reply is routed from its entry contexts through the FIB rows toward
    the addresses it is sent to, and through the contexts that those rows
    lead to (`_discover`). It is sent to the sources of the request and to
    `destinations`, the source addresses that the forward path translated the
    request to (its source NAT targets). The reply holds these addresses
    until the translating context restores them. The routing choices of the
    reply are those of these rows only. `masquerading` holds the contexts
    that masqueraded the request with a source port of their own pick
    (`NodeSpec.free_source_ports` of the forward model). A reply state before
    them that compares the destination port is not decided
    (`_picked_port_replies`).
    """

    def reply_ingress(terminal: StateKey) -> str | None:
        return next(
            (
                value.removeprefix("reply-ingress:")
                for value in terminal.binding_scope
                if value.startswith("reply-ingress:")
            ),
            None,
        )

    reply_ingresses: dict[str, set[str]] = defaultdict(set)
    for terminal in entry_states:
        if (interface_uid := reply_ingress(terminal)) is not None:
            reply_ingresses[terminal.context.vrf].add(interface_uid)
    af = _af(request)
    toward = tuple(dict.fromkeys(item for item in (*request.sources, *destinations) if item[0] == af))
    source = normalize_network(
        network,
        graph,
        request,
        member,
        estate,
        evidence=evidence,
        _policy_state="established",
        _reply=True,
        _reply_ingresses={context: frozenset(values) for context, values in reply_ingresses.items()},
        _reply_scope=(frozenset(terminal.context.vrf for terminal in entry_states), toward),
    )
    nodes = {node.key: node for node in source.nodes}
    by_location: dict[tuple[str, str], StateKey] = {}
    for key in nodes:
        by_location.setdefault((key.context.vrf, key.location), key)
    feeding: dict[StateKey, list[StateKey]] = defaultdict(list)
    for node in nodes.values():
        if node.key.stage in {"dnat", "pbr"}:
            for target in dict.fromkeys(edge.target for edge in node.edges):
                feeding[target].append(node.key)

    def entered(routing: StateKey) -> StateKey:
        """The first state of the DNAT and PBR gates before a routing state."""
        entry = routing
        while True:
            predecessors = [key for key in feeding.get(entry, ()) if key.context == routing.context]
            if len(predecessors) != 1:
                return entry
            entry = predecessors[0]

    redirect_targets: dict[str, StateKey] = {}
    for address, owner in _aci_redirect_owners(graph, _Interfaces(network)).items():
        owner_context = str(owner.context_uid)
        owner_state = by_location.get((owner_context, f"routing:{owner_context}:ingress:{owner.uid}"))
        if owner_state is not None:
            redirect_targets[address] = entered(owner_state)
    entries: list[EntrySpec] = []
    for terminal in entry_states:
        ingress = reply_ingress(terminal)
        vrf = terminal.context.vrf
        routing = by_location.get((vrf, f"routing:{vrf}:ingress:{ingress or 'none'}"))
        if routing is None:
            unknown = StateKey(f"reply-entry:unknown:{terminal.location}", terminal.context)
            nodes[unknown] = NodeSpec(unknown, terminal="unknown", complete=False)
            entries.append(EntrySpec(unknown, Constant(True)))
            continue
        # The reply of a pair whose contract has a service graph goes to the
        # redirect destination of the provider connector.
        redirected = expand_aci_reply_redirects(graph, routing.context, entered(routing), redirect_targets)
        nodes.update({node.key: node for node in redirected.nodes})
        entries.append(EntrySpec(redirected.entry, Constant(True)))
    if masquerading:
        _picked_port_replies(nodes, entries, masquerading)
    return ModelInput(
        source.manifest_digest,
        tuple(nodes.values()),
        tuple(entries),
        source.choices,
        source.choices_complete,
        evidence=source.evidence,
    )
