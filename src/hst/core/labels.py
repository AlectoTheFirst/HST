"""Every node is written with the labels `:Obj:<Primary>:<Layer...>[:Gate]`."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "0.32.0"

LAYERS = ("Phys", "L2", "L3", "Transport", "Policy", "Service", "Workload", "App", "Cloud", "Meta")
# The diff and the table view pick a node's primary label as the one label outside this set.
RESERVED_LABELS = {"Obj", "Retired", "Gate", "Latest", *LAYERS}

# The values and the order are those of STRATA_LAYERS in web/src/flowdesk/strata/layers.ts.
STRATA_TIERS = ("physical", "routing", "policy", "application")


@dataclass(frozen=True)
class LabelSpec:
    layers: tuple[str, ...]
    gate: bool = False
    doc: str = field(default="", compare=False)
    # The props that a node of this label must have. Batch.validate_registry checks them.
    requires: tuple[str, ...] = ()


LABELS: dict[str, LabelSpec] = {
    # --- location / physical
    "Site": LabelSpec(("Phys",)),
    "Rack": LabelSpec(("Phys",)),
    # The reasoner reads `role` against GATEWAY_ROLES (reasoner/_constants.py) to derive
    # GATEWAY_FOR. The path traversals follow GATEWAY_FOR from L2 into routing.
    "Device": LabelSpec(("Phys",), requires=("role",)),
    # Properties: kind, name. A vPC domain (kind=vpc) also has domain_id. The role,
    # peer_link and peer_status of a member are on its
    # `(Device)-[:MEMBER_OF {role, priority, peer_link, peer_status}]->(RedundancyGroup)`
    # edge.
    "RedundancyGroup": LabelSpec(("Phys",)),
    "FailureDomain": LabelSpec(
        ("Phys",), doc="Shared failure membership with independently recorded provenance"
    ),
    "Module": LabelSpec(("Phys",)),
    # speed_mbps and duplex hold the operational values that a collector observed.
    # speed_configured_mbps and duplex_configured hold the configured values. They are null
    # for `auto`. speed_source holds the collector field of the value, for example
    # "unifi:port_table.speed".
    "Port": LabelSpec(("Phys",)),
    "Provider": LabelSpec(("Meta",), doc="DORA third-party register"),
    "ProviderNetwork": LabelSpec(("Transport",)),
    "Pnic": LabelSpec(("Phys",)),
    # --- L2
    "Interface": LabelSpec(("L2",)),
    "Lag": LabelSpec(("L2",)),
    "VlanInstance": LabelSpec(("L2",)),
    "BridgeDomain": LabelSpec(("L2",)),
    "L2Vni": LabelSpec(("L2",)),
    # No collector writes it.
    "L2Segment": LabelSpec(("L2",)),
    # Properties: kind (hsrp/vrrp), group_id, vip, af, virtual_mac. The priority and the
    # state of a member are on its `(Interface)-[:MEMBER_OF {priority, state}]->(FhrpGroup)`
    # edge. The virtual address is `(Interface)-[:HAS_IP {fhrp, group, state}]->
    # (IpAddress)` on every member and `(FhrpGroup)-[:HAS_IP]->(IpAddress)`.
    "FhrpGroup": LabelSpec(("L2", "L3")),
    "Endpoint": LabelSpec(("L2",)),
    "Ssid": LabelSpec(("L2",)),
    # --- L3 / routing
    "VrfInstance": LabelSpec(("L3",)),
    # A logical gateway or VS that the management defines. Each physical Device that
    # runs it is a separate node.
    "FirewallInstance": LabelSpec(("L3", "Policy")),
    "RoutingDomain": LabelSpec(("L3",)),
    # No collector writes it.
    "L3Domain": LabelSpec(("L3",)),
    "Prefix": LabelSpec(("L3",)),
    "IpAddress": LabelSpec(("L3",)),
    "RouteTarget": LabelSpec(("L3",)),
    # hst.simul evaluates a RoutingProcess as BGP policy input only when proto == "bgp".
    "RoutingProcess": LabelSpec(("L3",), requires=("proto",)),
    # The engine compares local_asn and peer_asn to tell eBGP from iBGP.
    "BgpSession": LabelSpec(("L3",), requires=("local_asn", "peer_asn")),
    "BgpPeerRange": LabelSpec(("L3",), requires=("local_asn", "prefix")),
    "OspfArea": LabelSpec(("L3",)),
    "OspfAdjacency": LabelSpec(("L3",)),
    # `kind` decides the label of the HAS_RULE children: RoutePolicyEntry (route-map/rpl),
    # PrefixListEntry (prefix-list) or MatchListEntry (community-list/as-path-list).
    "RoutePolicy": LabelSpec(("L3",), gate=True, requires=("kind",)),
    # seq is the native clause number on IOS-XE/NX-OS and a 1-based ordinal on IOS-XR RPL.
    "RoutePolicyEntry": LabelSpec(("L3",), requires=("seq", "kind")),
    "PrefixListEntry": LabelSpec(("L3",), requires=("seq", "prefix", "action", "min_len", "max_len")),
    # match_type sets how `value` is read (simul/matchlist.py).
    "MatchListEntry": LabelSpec(("L3",), requires=("seq", "action", "match_type")),
    # --- overlay / transport
    "Fabric": LabelSpec(("Transport",)),
    "Pod": LabelSpec(("Transport",)),
    # An operator states bandwidth_mbps and bandwidth_source in the sources settings.
    "Tunnel": LabelSpec(("Transport",)),
    # The undirected overlay connection between 2 ends. One or more Tunnels realize it
    # (collectors/util.py `overlay_connection`).
    "OverlayConnection": LabelSpec(("Transport",)),
    "EvpnInstance": LabelSpec(("Transport",)),
    "SdwanSegment": LabelSpec(("Transport",)),
    "ForwardingBoundary": LabelSpec(("Transport",), gate=True),
    # No collector fills bandwidth_mbps and bandwidth_source.
    "WanLink": LabelSpec(("Transport",)),
    "SdwanGateway": LabelSpec(("Transport",)),
    "SdwanBusinessPolicy": LabelSpec(("Policy",), gate=True),
    "SdwanPolicyRule": LabelSpec(("Policy",)),
    "SdwanStaticRoute": LabelSpec(("L3",)),
    "NdoSchema": LabelSpec(("Meta",)),
    "NdoTemplate": LabelSpec(("Meta",)),
    # --- ACI policy & service insertion
    "Tenant": LabelSpec(("Policy",)),
    "AppProfile": LabelSpec(("Policy",)),
    "Epg": LabelSpec(("Policy",)),
    "Esg": LabelSpec(("Policy",)),
    "ExtEpg": LabelSpec(("Policy",)),
    "L3Out": LabelSpec(("L3",)),
    "Contract": LabelSpec(("Policy",), gate=True),
    "ContractSubject": LabelSpec(("Policy",)),
    "AciFilter": LabelSpec(("Policy",)),
    "FilterEntry": LabelSpec(("Policy",)),
    "VzAny": LabelSpec(("Policy",), gate=True),
    "ServiceGraphTemplate": LabelSpec(("Policy",)),
    "ServiceGraphInstance": LabelSpec(("Policy",)),
    "ServiceNode": LabelSpec(("Policy",)),
    "PbrPolicy": LabelSpec(("Policy",), gate=True),
    "PbrDest": LabelSpec(("Policy",)),
    # --- generic firewall model
    "FwRulebase": LabelSpec(("Policy",), gate=True),
    "FwRule": LabelSpec(("Policy",)),
    "FwSection": LabelSpec(("Policy",)),
    "CpPolicyPackage": LabelSpec(("Policy",)),
    "CpPolicyObject": LabelSpec(("Policy",)),
    # A collector writes it only when the gateway evidence identifies the installed
    # revision and its logical context.
    "PolicyInstallation": LabelSpec(("Meta",)),
    "NetObject": LabelSpec(("Policy",)),
    "SvcObject": LabelSpec(("Policy",)),
    "Zone": LabelSpec(("Policy",)),
    "NatRule": LabelSpec(("Policy",), gate=True),
    # --- LB / DNS
    "VirtualService": LabelSpec(("Service",), gate=True),
    "Pool": LabelSpec(("Service",)),
    "PoolMember": LabelSpec(("Service",)),
    "Monitor": LabelSpec(("Service",)),
    "DnsRecord": LabelSpec(("Service",)),
    # --- Zscaler
    "ZscalerDc": LabelSpec(("Transport",)),
    "ZiaLocation": LabelSpec(("Policy",)),
    "ZiaLocationGroup": LabelSpec(("Policy",)),
    "ZiaForwardingRule": LabelSpec(("Policy",), gate=True),
    "ZpaAppSegment": LabelSpec(("Policy",)),
    "ZpaSegmentGroup": LabelSpec(("Policy",)),
    "ZpaServerGroup": LabelSpec(("Policy",)),
    "AppServer": LabelSpec(("Workload",)),
    "ZpaAppConnectorGroup": LabelSpec(("Policy",)),
    "ZpaAppConnector": LabelSpec(("Workload",)),
    "ZpaAccessRule": LabelSpec(("Policy",), gate=True),
    "ZpaClientForwardingRule": LabelSpec(("Policy",), gate=True),
    "ZpaProvisioningKey": LabelSpec(("Policy",)),
    "ZpaServiceEdge": LabelSpec(("Transport",)),
    "IdentityGroup": LabelSpec(("App",)),
    # --- AWS
    "Organization": LabelSpec(("Cloud",)),
    "Account": LabelSpec(("Cloud",)),
    "Region": LabelSpec(("Cloud",)),
    "Az": LabelSpec(("Cloud",)),
    "Vpc": LabelSpec(("Cloud", "L3")),
    "Subnet": LabelSpec(("Cloud", "L3")),
    "RouteTable": LabelSpec(("Cloud", "L3")),
    "CloudRoute": LabelSpec(("Cloud", "L3")),
    "Igw": LabelSpec(("Cloud",)),
    "NatGw": LabelSpec(("Cloud",), gate=True),
    "Eni": LabelSpec(("Cloud",)),
    "VpcPeering": LabelSpec(("Cloud",)),
    "Tgw": LabelSpec(("Cloud", "Transport")),
    "TgwAttachment": LabelSpec(("Cloud", "Transport")),
    "TgwRouteTable": LabelSpec(("Cloud", "Transport")),
    "VpcEndpoint": LabelSpec(("Cloud",)),
    "EndpointService": LabelSpec(("Cloud",)),
    "DxConnection": LabelSpec(("Transport",)),
    "DxVif": LabelSpec(("Transport",)),
    "DxGw": LabelSpec(("Transport",)),
    "VpnConnection": LabelSpec(("Transport",)),
    "Instance": LabelSpec(("Workload",)),
    # --- Azure
    "Subscription": LabelSpec(("Cloud",)),
    "ResourceGroup": LabelSpec(("Cloud",)),
    "VNet": LabelSpec(("Cloud", "L3")),
    "Nic": LabelSpec(("Cloud",)),
    "VNetPeering": LabelSpec(("Cloud", "Transport")),
    "VirtualWan": LabelSpec(("Transport",)),
    "VHub": LabelSpec(("Transport",)),
    "HubRouteTable": LabelSpec(("Transport",)),
    "ErCircuit": LabelSpec(("Transport",)),
    "ErPeering": LabelSpec(("Transport",)),
    "VNetGw": LabelSpec(("Transport",)),
    "AzFirewall": LabelSpec(("Cloud",), gate=True),
    "PrivateEndpoint": LabelSpec(("Cloud",)),
    "PrivateLinkService": LabelSpec(("Cloud",)),
    # --- Equinix
    "FabricPort": LabelSpec(("Transport",)),
    "VirtualCircuit": LabelSpec(("Transport",)),
    # --- virtualization / compute / app
    "Vcenter": LabelSpec(("Workload",)),
    "VmwCluster": LabelSpec(("Workload",)),
    "EsxHost": LabelSpec(("Workload",)),
    "Vm": LabelSpec(("Workload",)),
    "Vnic": LabelSpec(("Workload",)),
    "Dvs": LabelSpec(("L2",)),
    "DvPortgroup": LabelSpec(("L2",)),
    "Server": LabelSpec(("Workload",)),
    "BusinessService": LabelSpec(("App",)),
    "AppComponent": LabelSpec(("App",)),
    # A ServiceRequirement has one DependencyGroup as the root of its condition.
    "ServiceRequirement": LabelSpec(("App",)),
    # `kind` is one of DEPENDENCY_GROUP_KINDS. It decides how the parts of the group combine.
    "DependencyGroup": LabelSpec(("App",), requires=("kind",)),
    # --- meta
    "CollectionRun": LabelSpec(("Meta",)),
    "MtuObservation": LabelSpec(
        ("Meta",),
        requires=("subject_uid", "source", "source_field", "raw_value_json", "metric", "bound_kind"),
    ),
}

# The value is that of FALLBACK_LAYER in layers.ts.
FALLBACK_TIER = 0  # physical

# The order and the values are those of LAYER_BY_KIND in web/src/flowdesk/strata/layers.ts.
# Tier indices: 0 physical, 1 routing, 2 policy, 3 application (STRATA_TIERS).
TIER_BY_KIND: dict[str, int] = {
    # --- location / physical: devices, interfaces, ports, sites
    "Site": 0,
    "Rack": 0,
    "Device": 0,
    "RedundancyGroup": 0,
    "FailureDomain": 0,
    "Module": 0,
    "Port": 0,
    "Provider": 0,
    "ProviderNetwork": 0,
    "Pnic": 0,
    # --- L2: interfaces, bridging, VLANs, SSIDs
    "Interface": 0,
    "Lag": 0,
    "VlanInstance": 0,
    "BridgeDomain": 0,
    "L2Vni": 0,
    "L2Segment": 0,
    "FhrpGroup": 1,
    "Endpoint": 3,
    "Ssid": 0,
    # --- L3 / routing
    "VrfInstance": 1,
    "FirewallInstance": 2,
    "RoutingDomain": 1,
    "L3Domain": 1,
    "Prefix": 1,
    "IpAddress": 1,
    "RouteTarget": 1,
    "RoutingProcess": 1,
    "BgpSession": 1,
    "BgpPeerRange": 1,
    "OspfArea": 1,
    "OspfAdjacency": 1,
    "RoutePolicy": 1,
    "RoutePolicyEntry": 1,
    "PrefixListEntry": 1,
    "MatchListEntry": 1,
    # --- overlay / transport
    "Fabric": 0,
    "Pod": 0,
    "Tunnel": 1,
    "OverlayConnection": 1,
    "EvpnInstance": 1,
    "SdwanSegment": 1,
    "ForwardingBoundary": 1,
    "WanLink": 0,
    "SdwanGateway": 0,  # a device that terminates SD-WAN tunnels
    "SdwanBusinessPolicy": 2,
    "SdwanPolicyRule": 2,  # one rule of an SdwanBusinessPolicy, as FwRule is of FwRulebase
    "SdwanStaticRoute": 1,  # one route of a boundary, as CloudRoute is of RouteTable
    "NdoSchema": 0,
    "NdoTemplate": 0,
    # --- ACI policy & service insertion
    "Tenant": 2,  # the container of the ACI policy objects of a tenant
    "AppProfile": 2,
    "Epg": 2,
    "Esg": 2,
    "ExtEpg": 2,
    "L3Out": 1,
    "Contract": 2,
    "ContractSubject": 2,
    "AciFilter": 2,
    "FilterEntry": 2,
    "VzAny": 2,
    "ServiceGraphTemplate": 2,
    "ServiceGraphInstance": 2,
    "ServiceNode": 2,
    "PbrPolicy": 2,
    "PbrDest": 2,
    # --- generic firewall model
    "FwRulebase": 2,
    "FwRule": 2,
    "FwSection": 2,
    "CpPolicyPackage": 2,
    "CpPolicyObject": 2,
    "NetObject": 3,
    "SvcObject": 3,
    "Zone": 2,
    "NatRule": 2,
    # --- LB / DNS
    "VirtualService": 3,
    "Pool": 3,
    "PoolMember": 3,
    "Monitor": 3,
    "DnsRecord": 3,
    # --- Zscaler
    "ZscalerDc": 0,
    "ZiaLocation": 2,
    "ZiaLocationGroup": 2,
    "ZiaForwardingRule": 2,
    "ZpaAppSegment": 2,
    "ZpaSegmentGroup": 2,
    "ZpaServerGroup": 2,
    "AppServer": 0,
    "ZpaAppConnectorGroup": 2,
    "ZpaAppConnector": 0,
    "ZpaAccessRule": 2,
    "ZpaClientForwardingRule": 2,
    "ZpaProvisioningKey": 2,
    "ZpaServiceEdge": 0,
    "IdentityGroup": 3,
    # --- AWS
    "Organization": 0,
    "Account": 0,
    "Region": 0,
    "Az": 0,
    "Vpc": 1,  # an L3 routing domain, the cloud analogue of a VRF
    "Subnet": 1,  # the cloud analogue of a Prefix
    "RouteTable": 1,
    "CloudRoute": 1,
    "Igw": 0,
    "NatGw": 2,
    "Eni": 0,  # the cloud analogue of Interface
    "VpcPeering": 1,
    "Tgw": 1,  # a routing hub between VPCs
    "TgwAttachment": 1,
    "TgwRouteTable": 1,
    "VpcEndpoint": 3,
    "EndpointService": 3,
    "DxConnection": 0,  # the physical cross-connect circuit
    "DxVif": 1,
    "DxGw": 1,  # routes between VIFs and VPN/VPC gateways
    "VpnConnection": 1,
    "Instance": 0,
    # --- Azure
    "Subscription": 0,
    "ResourceGroup": 0,
    "VNet": 1,  # the Azure analogue of Vpc
    "Nic": 0,  # the Azure analogue of Eni
    "VNetPeering": 1,
    "VirtualWan": 1,
    "VHub": 1,
    "HubRouteTable": 1,
    "ErCircuit": 0,  # the physical ExpressRoute circuit, analogue of DxConnection
    "ErPeering": 1,
    "VNetGw": 1,
    "AzFirewall": 2,
    "PrivateEndpoint": 3,  # the Azure analogue of VpcEndpoint
    "PrivateLinkService": 3,
    # --- Equinix
    "FabricPort": 0,
    "VirtualCircuit": 0,  # the Equinix analogue of WanLink
    # --- virtualization / compute / app
    "Vcenter": 0,
    "VmwCluster": 0,
    "EsxHost": 0,
    "Vm": 0,
    "Vnic": 0,  # the virtualization analogue of Interface/Eni
    "Dvs": 0,
    "DvPortgroup": 0,
    "Server": 0,
    "BusinessService": 3,
    "AppComponent": 3,
    "ServiceRequirement": 3,
    "DependencyGroup": 3,
    # --- meta
    "CollectionRun": 0,
    "PolicyInstallation": 0,
    "MtuObservation": 0,
}

SYNTHETIC_KIND_TIER: dict[str, int] = {
    "NextHop": 1,  # a next hop that the path builder synthesizes
}


def layer_of(kind: str) -> tuple[str, ...]:
    """The layers of a kind in LABELS. () for a kind that LABELS does not have,
    such as the synthetic hop kind NextHop."""
    spec = LABELS.get(kind)
    return spec.layers if spec else ()


def tier_of(kind: str) -> int:
    """The tier index (STRATA_TIERS) of a hop kind or a node kind in the Strata
    view. A kind that TIER_BY_KIND does not have gets the index of
    SYNTHETIC_KIND_TIER. A kind in neither table gets FALLBACK_TIER."""
    if kind in TIER_BY_KIND:
        return TIER_BY_KIND[kind]
    return SYNTHETIC_KIND_TIER.get(kind, FALLBACK_TIER)


RELS: frozenset[str] = frozenset(
    {
        # structural
        "LOCATED_IN",
        "IN_RACK",
        # (Interface)->(FhrpGroup) has {priority, state}.
        # (Device)->(RedundancyGroup) has {role, priority} and, for a vPC domain,
        # {peer_link, peer_status}.
        # (VrfInstance)->(RoutingDomain) has {basis}.
        "MEMBER_OF",
        "PART_OF",
        "ON",
        "OF",
        "IN",
        "IN_POD",
        "IN_VRF",
        "IN_BD",
        "IN_EPG",
        "IN_AREA",
        "IN_ACCOUNT",
        "IN_ORG",
        "IN_REGION",
        "IN_AZ",
        "HAS",
        "HAS_PORT",
        "HAS_MTU",
        "HAS_LINK",
        "HAS_BOUNDARY",
        "HAS_INSTALLATION",
        "HAS_RULE",
        "HAS_LAYER",
        "HAS_DEST",
        "HAS_MEMBER",
        "REALIZED_BY",
        "CONTAINS",
        "RUNS_ON",
        "IN_CONTEXT",
        "INSTALLS",
        # identity / meta
        "SAME_AS",
        "REPRESENTS",
        "PROVIDED_BY",
        # The 2 BgpSessions of one peering. The reasoner derives the edge from the peer
        # addresses (`bgp-peer-from-address`).
        "PEERS_WITH",
        "SERVED_BY",
        "DEFINES",
        # topology
        # core/reasoner.py's link-speed derivation writes speed_mbps and speed_agreement.
        "CONNECTED_TO",
        "SWITCHES",
        "BOUND_TO",
        "EXTENDS",
        "ATTACHED",
        # The reasoner derives (Interface)->(BridgeDomain) with {basis: svi|subif|cable}.
        "ATTACHED_TO",
        "BRIDGED_TO",
        "GATEWAY_FOR",
        "L3_ADJACENT",
        "INTERCONNECTED_BY",
        "ENDPOINT",
        "CARRIES",
        "TERMINATES_ON",
        # (OverlayConnection)->(Device|SdwanGateway|IpAddress|ZiaLocation|ZscalerDc)
        # has {end: a|b, role, reported}.
        "BETWEEN",
        "A_END",
        "Z_END",
        "PLUGGED_INTO",
        # L3 / routing
        "REALIZES",
        # (Interface)->(IpAddress) holds {fhrp: hsrp|vrrp, group, state} for a first-hop virtual address.
        "HAS_IP",
        "WITHIN",
        "ORIGINATES",
        "IMPORTS",
        "EXPORTS",
        "USES_RT",
        "STATIC_ROUTE",
        "LEARNED_ROUTE",
        "VIA",
        "FOR",
        "ASSOCIATED",
        "PROPAGATES",
        "FILTERED_BY",
        # (RoutePolicyEntry)->(RoutePolicy). It is written only when the name resolves to a
        # node of the batch.
        "REFERENCES",
        # policy
        "PROVIDES",
        "CONSUMES",
        "USES_FILTER",
        "APPLIES_GRAPH",
        "HAS_NODE",
        "REDIRECTS_VIA",
        "RESOLVES_TO",
        "MATCHES",
        "STATIC_BINDING",
        "VMM_BINDING",
        "ENFORCES",
        "PROTECTED_BY",
        "SRC",
        "DST",
        "SVC",
        "FROM_ZONE",
        "TO_ZONE",
        "JUMPS_TO",
        "ORIG_SRC",
        "ORIG_DST",
        "XLATE_SRC",
        "XLATE_DST",
        "GRANTS",
        "DENIES",
        "EGRESSES_VIA",
        "USES",
        "OWNED_BY",
        "STEERS_VIA",
        # (ZpaClientForwardingRule)-[:APPLIES_TO]->(IdentityGroup) has no verdict.
        "APPLIES_TO",
        # (ZiaForwardingRule)-[:FORWARDS_TO]->(ZpaAppSegment|ZpaSegmentGroup). The reasoner
        # writes it only when exactly one node of the run has the id.
        "FORWARDS_TO",
        # service / app
        "VIP",
        "DISPATCHES",
        "TARGETS",
        "CHECKED_BY",
        "SNAT_FROM",
        "FRONTS",
        "DEPENDS_ON",
        "ROUTES",
        "HAS_ROUTE",
    }
)


def labels_clause(label: str) -> str:
    """The label string of a write, for example ':Obj:Contract:Policy:Gate'.

    Raises ValueError for an unregistered label."""
    spec = LABELS.get(label)
    if spec is None:
        raise ValueError(f"unregistered label: {label!r}")
    parts = ["Obj", label, *spec.layers]
    if spec.gate:
        parts.append("Gate")
    return ":" + ":".join(parts)


def validate_label(label: str) -> None:
    if label not in LABELS:
        raise ValueError(f"unregistered label: {label!r}")


def validate_props(label: str, props: dict) -> None:
    """None and `""` count as missing."""
    spec = LABELS.get(label)
    if spec is None:
        return
    missing = [p for p in spec.requires if props.get(p) is None or props.get(p) == ""]
    if missing:
        raise ValueError(f"{label} is missing required prop(s) {missing}; 'unknown' is a valid value")


def validate_rel(rel_type: str) -> None:
    if rel_type not in RELS:
        raise ValueError(f"unregistered relationship type: {rel_type!r}")


class IdentityCollision(ValueError):
    """Two different objects were declared under one uid inside one batch."""


class CycleIdentityCollision(IdentityCollision):
    """The collision fails the run."""


# `name` and `hostname` are identity props of the 2 labels whose uid comes from a
# serial or a source reference.
_IDENTITY_PROPS: dict[str, tuple[str, ...]] = {
    "Device": ("anchor", "name", "hostname"),
    "VrfInstance": ("anchor", "name", "hostname"),
}
_ANCHOR_ONLY = ("anchor",)


def check_identity(seen: dict[str, dict[str, Any]], label: str, uid: str, props: Mapping[str, Any]) -> None:
    known = seen.setdefault(uid, {})
    for key in _IDENTITY_PROPS.get(label, _ANCHOR_ONLY):
        value = props.get(key)
        if value is None:
            continue
        prior = known.get(key)
        if prior is not None and prior != value:
            raise IdentityCollision(
                f"uid {uid!r} was declared with {key}={prior!r} and again with {key}={value!r}: "
                f"one uid cannot name two objects"
            )
        known[key] = value


# tests/test_schema_contract.py checks every collector's output against the rules below.

# Each entry is a Cypher path fragment from the device hop `d` to the gate `g`,
# with relationship variables e1..eN.
NOT_DEVICE_BOUND = "not-device-bound"

GATE_BINDINGS: dict[str, tuple[str, ...] | tuple[str, str]] = {
    "ForwardingBoundary": ("(d)-[e1:HAS_BOUNDARY]->(g)",),
    # The engine evaluates the rulebase. NatRule and FwRule are credited through it.
    "FwRulebase": (
        "(d)-[e1:ENFORCES]->(g)",
        "(d)-[e1:MEMBER_OF]->(:RedundancyGroup)-[e2:ENFORCES]->(g)",
        "(d)<-[e1:ON]-(:Interface)-[e2:IN_VRF]->(:VrfInstance)-[e3:ENFORCES]->(g)",
        "(d)-[e1:PROTECTED_BY]->(g)",
        "(d)<-[e1:ON]-(:Interface)-[e2:PROTECTED_BY]->(g)",
        "(d)<-[e1:ON]-(:Interface)<-[e2:CONTAINS]-(:Zone)<-[e3:FROM_ZONE|TO_ZONE]-(g)",
    ),
    "NatRule": (NOT_DEVICE_BOUND, "credited through its FwRulebase kind=nat (path/trace.py nat_uids)"),
    "PbrPolicy": (
        "(d)<-[e1:ON]-(:Interface)-[e2:ENFORCES]->(g)",
        # The pattern of an ACI service-graph redirect. `d` is the fabric leaf that the
        # flow enters. The Interface that enforces the policy is on a Device of the same
        # Fabric.
        "(d)-[e1:MEMBER_OF]->(:Fabric)<-[e2:MEMBER_OF]-(:Device)<-[e3:ON]-(:Interface)-[e4:ENFORCES]->(g)",
    ),
    "Contract": (
        NOT_DEVICE_BOUND,
        "evaluated per flow on the EPG pair (path/gates/aci.py); credited by contract uid",
    ),
    "VzAny": (
        NOT_DEVICE_BOUND,
        "evaluated with the ACI contract gate once collected",
    ),
    "RoutePolicy": (
        NOT_DEVICE_BOUND,
        "a route-policy filters advertisements, not flows; consulted by the BGP model",
    ),
    "VirtualService": (
        "(d)<-[e1:ON]-(g)",
        "(d)-[e1:MEMBER_OF]->(:RedundancyGroup)<-[e2:ON]-(g)",
    ),
    "SdwanBusinessPolicy": (
        "(d)-[e1:HAS_LINK]->(:WanLink)<-[e2:STEERS_VIA]-(g)",
        "(d)<-[e1:ON]-(:Interface)<-[e2:ENDPOINT]-(:Tunnel)<-[e3:STEERS_VIA]-(g)",
    ),
    "ZpaAccessRule": (
        NOT_DEVICE_BOUND,
        "identity-keyed; first match runs in core/zpa_policy.py for hst.path.trace.trace_from_identity, "
        "the impact engine and the analysis model",
    ),
    "ZpaClientForwardingRule": (
        NOT_DEVICE_BOUND,
        "identity-keyed; first match runs in core/zpa_policy.py before the access rule, for "
        "hst.path.trace.trace_from_identity, the impact engine and the analysis model",
    ),
    "ZiaForwardingRule": (
        NOT_DEVICE_BOUND,
        "a ZIA forwarding decision (ZPA, DIRECT, DROP); first match runs in path/gates/zia.py "
        "at the ZIA boundary of a traced tunnel",
    ),
    "NatGw": (
        NOT_DEVICE_BOUND,
        "cloud route target; no cloud collector exists",
    ),
    "AzFirewall": (
        NOT_DEVICE_BOUND,
        "cloud route target; no cloud collector exists",
    ),
}

# The engine branches on these closed vocabularies. A collector writes one of these values
# or leaves the property absent. A reader that finds another value must treat the object
# as indeterminate.
FWRULEBASE_KINDS = frozenset({"access", "nat", "zone", "ips-profile", "sg", "nsg", "azfw-collection"})
NATRULE_KINDS = frozenset({"snat", "dnat", "static"})
# FwRulebase.match_context states the flow attributes that the rules of a rulebase match.
#   zone-pair        the ingress and egress zones of the flow (VyOS, UniFi zone policies)
#   device           every flow through the device. A rule can scope by interface name
#                    (Check Point, VyOS filter chains)
#   interface-acl    the flow's ingress or egress interface, one direction each (Cisco ACL)
#   object-attached  the object the rulebase PROTECTS (cloud SG and NSG)
MATCH_CONTEXTS = frozenset({"zone-pair", "device", "interface-acl", "object-attached"})
# ZpaAccessRule and ZpaClientForwardingRule identity_scope and app_scope:
#   any     no operand limits that dimension
#   listed  an AND-joined rule limits it to the operands of one positive block
#   other   any other shape: a rule-level OR, a negated or mixed block, or an
#           operand type the readers do not compare
ZPA_RULE_SCOPES = frozenset({"any", "listed", "other"})
# ZpaAccessRule.action is absent for any other value. action_raw holds the payload value.
ZPA_ACCESS_ACTIONS = frozenset({"allow", "deny", "require_approval"})

# DependencyGroup.kind states how the parts of a group combine into the declared
# success condition of the application.
#   and        every part must hold
#   or         at least one part must hold
#   threshold  at least `n` parts must hold. `n` is required and is between 1
#              and the number of parts
#   capacity   a capacity requirement that evaluates to not-established
DEPENDENCY_GROUP_KINDS = frozenset({"and", "or", "threshold", "capacity"})

# Device.role has one of these values. The second column has the collector that writes it.
#   router / switch / ap / gateway   cisco_common.py, vyos.py and the UniFi ROLE map
#                                     (usw/uap/ugw/udm/uxg)
#   firewall                         checkpoint.py
#   leaf / spine / controller        apic.py, from the role attribute of the ACI
#                                     fabricNode (_ACI_PLATFORM)
#   "access point"                   nautobot.py, from the Nautobot role name in
#                                     lowercase
#   unknown                          each collector when no role is known, and
#                                     manual.py for a blank role column of the CSV
DEVICE_ROLES = frozenset(
    {
        "router",
        "switch",
        "ap",
        "gateway",
        "firewall",
        "leaf",
        "spine",
        "controller",
        "access point",
        # A Check Point management or log server (collectors/checkpoint.py
        # MANAGEMENT_TYPES). The Device has no policy of its own.
        "management",
        # collectors/velocloud.py writes `sdwan-hub` for an edge in its hub set (`_hubs`),
        # else `sdwan-edge`.
        "sdwan-hub",
        "sdwan-edge",
        "unknown",
    }
)

# The address set of a NetObject that a rule matches on is its RESOLVES_TO edges to
# Prefix or IpAddress nodes (anchored on the source scope string), its `ranges` list
# property, or both. A group has the RESOLVES_TO closure of its members beside
# MEMBER_OF.
# A NetObject whose set the engine cannot express (fqdn, dynamic, geo, identity,
# zone, wildcard, exclusion group) has opaque=True and opaque_reason. A rule that
# references an opaque object evaluates INDETERMINATE. No reader uses NetObject.ip or
# NetObject.cidr.
NETOBJECT_ADDRESS_REL = "RESOLVES_TO"
NETOBJECT_RANGE_PROP = "ranges"
OPAQUE_PROP = "opaque"
# The addresses of an Endpoint are HAS_IP edges to IpAddress nodes. Endpoint.ip is for
# display only.
ENDPOINT_ADDRESS_REL = "HAS_IP"
# The local end of a Tunnel is ENDPOINT to the encapsulating Interface, or to an
# address of that interface. The far end is TERMINATES_ON to an IpAddress, a
# ZscalerDc or an SdwanGateway. The target of ENDPOINT is always a local object.
TUNNEL_LOCAL_END_REL = "ENDPOINT"
TUNNEL_FAR_END_REL = "TERMINATES_ON"


def gate_binding_patterns() -> dict[str, tuple[str, ...]]:
    """The device-bound gate labels and their path fragments.

    The entries with NOT_DEVICE_BOUND are left out."""
    return {
        label: patterns
        for label, patterns in GATE_BINDINGS.items()
        if not (patterns and patterns[0] == NOT_DEVICE_BOUND)
    }


# The labels that the start of a HAS_MTU edge to an MtuObservation can have.
MTU_SUBJECT_LABELS = frozenset(
    {
        "Port",
        "Interface",
        "Lag",
        "Device",
        "Fabric",
        "BridgeDomain",
        "Tunnel",
        "Endpoint",
        "Pnic",
        "Vnic",
        "Dvs",
        "DvPortgroup",
        "EsxHost",
        "Vm",
        "Server",
    }
)
