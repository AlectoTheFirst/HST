"""Derived-edge rules, run inside the run that collected the facts.

Every run drops all reasoner-owned writes for its cycle (the derived edges,
the `Endpoint.infra` marker and the `FabricPort.binding_issue` and
`binding_ports` markers) and recreates them from that cycle's facts. Every
edge here holds the rule name. An edge has `derived: true` unless the rule
only joins two sources' own stated facts by a shared key.

`resolve_stated_cables` never uses the MAC-named port as the cable end.

The reasoner works inside one cycle. Every rule reads only nodes with the
`collection_ts` of the cycle and writes the same value on its derived edges.
A historical cycle keeps the conclusions drawn from it. Each rule starts from
an `:Obj` anchor with `x.collection_ts = $cts`.

Rules:

- overlay-connection-ends: two batches can write one `OverlayConnection`, for
  two VyOS routers at the two ends of one tunnel. The rule sets
  `observed_from` to every end with a reported `BETWEEN` edge, and `name` to
  the names of those ends, end `a` first. It reads collector facts only and
  writes the same values on every run. No clear step drops these values.
- cable-from-endpoint-mac: UniFi reports which MAC is behind each switch port
  (client table). When that MAC belongs to a known interface of another device
  (VyOS reports its MACs via `ip -j link show`), and the port has nothing
  else attached, the rule writes the Port-to-Port cable and marks the endpoint
  as infrastructure. The port has nothing else attached when it has no other
  endpoint in the run and its neighbor records (`last_conn_mac`,
  `lldp_neighbor_mac`, `uplink_mac`) hold the MAC of no other device. The
  rule runs after the 3 stated rules below. It writes no cable when a stated
  cable on either port has a different peer.
- cable-from-uplink-record: UniFi reports the uplink neighbor of each device
  (`uplink.uplink_mac`/`uplink_remote_port`, `collectors/unifi.py`), for a
  UniFi peer and for any other peer. `resolve_stated_cables` resolves the
  neighbor Device that owns `uplink_mac`, then the Port on it. The Port
  comes from the LLDP port id of the switch port when the LLDP MAC agrees
  with this MAC, else from the remote port index of the uplink, else it is
  the sole Port of the device. When no device, an ambiguous device or no
  Port resolves, the rule writes nothing for that port and counts it in its
  detail. The edge has `derived: false`. The rule runs before
  cable-from-last-connection and wins the pair when both would cable the
  same 2 ports.
- cable-from-lldp-record: the same 2-step resolution from the per-port LLDP
  neighbor hint of the switch (`Port.lldp_neighbor_mac`/`lldp_neighbor_port`,
  `collectors/unifi.py`). The rule resolves the neighbor Device that owns
  `lldp_neighbor_mac`, then the Port on it, by the same precedence. The
  switch observed the neighbor over LLDP. The edge has `derived: false`. A
  UniFi neighbor resolves through `Device.mac`, the chassis MAC that
  `collectors/unifi.py` writes on its Device nodes. `FETCH_MAC_OWNERS` reads
  it beside every Port and Interface MAC. Two UniFi switches that each see
  the other over LLDP are cabled from those records alone. When the MAC
  belongs to more than one Device, or resolves to no single Port on its one
  Device, the rule resolves nothing for that port and counts it in its
  detail. The rule runs after cable-from-uplink-record and yields to it when
  both would state the same pair. It runs before cable-from-last-connection,
  and that rule yields to it the same way.
- cable-from-neighbor-name: the same per-port hint, resolved by the name that
  the neighbor gives itself (`Port.cdp_neighbor_name`/`cdp_neighbor_port`,
  and `cdp_neighbor_serial` for a Nexus far end). The serial joins the
  `serial` or `identities` of a Device exactly. A name joins the `hostname`
  or `identities` of a Device through `normalize_hostname`, by full name
  first and by short name when no full name matches. The Port on the
  resolved Device comes from the port id of the hint, else it is the sole
  Port of the device. The edge has `derived: false` and the source `cdp` or
  `lldp`. A name that no Device has, or that more than one Device has,
  resolves nothing. The rule runs after cable-from-lldp-record and yields to
  any pair that a MAC-resolved rule stated. It runs before
  cable-from-last-connection, and that rule yields to it.
- cable-from-last-connection: the same conclusion from the record of the
  switch for the device connected to a port (`port_table[].last_connection`).
  It writes nothing when either port of the pair has a stated cable
  (`STATED_CABLE_SOURCES`, or any edge with `derived: false`) to any peer.
- fabric-port-from-description: a device `Port` whose description has the
  name of an Equinix `FabricPort` as a whole word realizes that Fabric port,
  when the cable id in the description is one of the cross-connect ids of
  the Fabric port or the description states no cable id. A description with
  a different cable id is a conflict. A Fabric port whose name is in 2 port
  descriptions is ambiguous, and so is a port whose description has 2 Fabric
  port names. The rule counts these cases and writes no edge for them. A
  Fabric port that the operator bound (`port_bindings`), and a port that the
  operator bound a Fabric port to, are left to that binding. A port whose
  description has 2 Fabric port names is ambiguous also when the operator
  bound one of them.
- edge-device-from-binding: a Network Edge device that its source binds to
  the device of another source (`bound_device_uid`) is that device. The rule
  writes `SAME_AS` from the Network Edge node to the bound device. For each
  Network Edge interface it writes either a `REALIZED_BY` to the one port of
  the bound device with the same MAC address, or, without such a port, an
  `ON` from the interface and its port to the bound device. The rule runs
  after every load, and its result does not depend on the order in which the
  sources load.
- cable-from-fabric-circuit: an Equinix Fabric circuit (`collectors/equinix.py`)
  whose A and Z ends both realize a device `Port` is a link between those 2
  ports. An end is a `FabricPort` that realizes a port (the `port_bindings`
  of the operator, or fabric-port-from-description), or a Network Edge
  `Interface` that realizes a port on a device (the port of the collector,
  or the rule above). A circuit in state ACTIVE or PROVISIONED gives a link.
  A circuit in another state or without a state gives none. The edge holds
  the circuit uid, and the VLAN tag and link protocol per side. A binding
  whose device port is not in the run is reported by `check_vlan_stretch`.
- gateway-from-router-interface: an interface of a routing device that holds
  an address inside a connected prefix is the gateway of that prefix. Path
  traversals use this edge to move from L2 into routing.
- gateway-from-sole-firewall-interface: an interface of a firewall that holds
  an address inside a connected prefix is the gateway of that prefix when no
  interface of a GATEWAY_ROLES device also serves the prefix.
- attached-from-vlan-binding: an interface bound to a VLAN of its own device
  (`(Interface)-[:BOUND_TO]->(VlanInstance)-[:REALIZES]->(BridgeDomain)`) is
  attached to that bridge domain. The rule writes
  `(Interface)-[:ATTACHED_TO {basis}]->(BridgeDomain)` with `basis: svi` for
  an SVI and `subif` for every other bound interface (a VyOS `vif`, a Check
  Point VLAN interface).
- attached-from-cable: an interface that holds an address, binds to no VLAN
  and is no SVI or subinterface is attached to the bridge domain of the
  native VLAN of the port at the far end of its cable (`basis: cable`). An
  example is the untagged LAN port of a router that is cabled to a UniFi
  switch port.
- prefix-in-from-attachment: a connected prefix in which an attached
  interface holds an address is `IN` the bridge domain of that interface. An
  Endpoint has the same edge type to its bridge domain. A pair that a
  collector states is left to the collector.
- gateway-from-sole-segment-interface: the one interface attached to a bridge
  domain that holds an address on a connected prefix is the gateway of that
  prefix. The map draws this gateway for the segment. The role of the device
  of the interface is neither a GATEWAY_ROLES role nor `firewall`. A segment
  where another attached interface holds an address on the same prefix gets
  no gateway (a management VLAN). A prefix that has a gateway in the same
  routing domain keeps that gateway.
- address-containment: every held address (Endpoint, Interface or Device via a
  live HAS_IP) gains an IN edge to each live connected Prefix instance that
  contains it in its forwarding context. The rule runs after the Cypher
  rules.
- zpa-zia-ip-same-as: the `private_ip` of a `ZpaAppConnector`, the `address`
  of a static `AppServer` and the `source_ip` of a ZIA `Tunnel` are linked
  `SAME_AS {confidence, basis}` to every campus `IpAddress` held (via
  `HAS_IP`) with the same value. The rule matches the address value only and
  states no shared subnet or VRF. It writes no `HAS_IP`, `IN` or `Prefix`
  edge. A globally routable address gets the higher confidence. The
  `public_ip` of a connector is not linked. Traversal is opt-in
  (`trace_from_identity(..., follow_same_as=True)`).
- zia-forwarding-to-zpa-segment and zia-forwarding-to-zpa-segment-group: a
  `ZiaForwardingRule` lists the ids of the ZPA segments and segment groups
  that it forwards to (`zpa_app_segment_ids`, `zpa_segment_group_ids`). An
  id that exactly one `ZpaAppSegment` or `ZpaSegmentGroup` (`zpa_id`) of the
  run has gets a `FORWARDS_TO`. zia-forwarding-to-zpa-server-group writes
  `STEERS_VIA` to the one `ZpaServerGroup` of the ZPA gateway of the rule.
  These rules join the stated keys of 2 sources, and their edges have
  `derived: false`. Each result counts the ids that no node has
  (`unresolved`) and the ids that 2 or more nodes have (`ambiguous`).

Two checks run beside the rules and write no edge. They are
`check_vlan_stretch` (`reasoner/vlan_stretch.py`) and `check_edge_devices`
(`reasoner/edge_devices.py`). `core/finalize.py` runs them after `run()` and
records their results in the detail of the run and in the snapshot manifest.
"""

from __future__ import annotations

from hst.reasoner._constants import (
    ACTIVE_CIRCUIT_STATES,
    CLEAR,
    CLEAR_PROPS,
    ENDED_CIRCUIT_STATES,
    GATEWAY_ROLES,
    STATED_CABLE_SOURCES,
)
from hst.reasoner.arp_cables import (
    FETCH_RUN_DEVICES,
    FETCH_SDWAN_ADDRESSES,
    derive_arp_cables,
    resolve_arp_cables,
)
from hst.reasoner.catalog import RULES
from hst.reasoner.containment import (
    CONTAINMENT_ADDRESSES,
    CONTAINMENT_BD_MAP,
    CONTAINMENT_PREFIXES,
    CONTAINMENT_WRITE,
    containment_pairs,
)
from hst.reasoner.device_roles import FETCH_DEVICE_ROLES, SET_DEVICE_ROLES, apply_device_roles
from hst.reasoner.edge_devices import (
    EDGE_DEVICE_RULE,
    EDGE_ON_WRITE,
    EDGE_REALIZED_WRITE,
    EDGE_SAME_AS_WRITE,
    FETCH_EDGE_BINDINGS,
    FETCH_EDGE_BINDINGS_REFUSED,
    FETCH_EDGE_CANDIDATES,
    FETCH_EDGE_DEVICES,
    FETCH_EDGE_INTERFACES,
    _run_edge_device_rule,
    check_edge_devices,
    edge_device_candidates,
    resolve_edge_device_bindings,
)
from hst.reasoner.fabric_ports import (
    FABRIC_PORT_ISSUE_WRITE,
    FABRIC_PORT_RULE,
    _fabric_port_matcher,
    fabric_port_issues,
    fabric_port_warnings,
    resolve_fabric_port_bindings,
)
from hst.reasoner.runner import run
from hst.reasoner.stated_cables import (
    FETCH_DEVICE_PORTS,
    FETCH_MAC_OWNERS,
    FETCH_STATED_CABLE_PORTS,
    STATED_CABLE_WRITE,
    _canonical_mac_or_none,
    resolve_stated_cables,
)
from hst.reasoner.vlan_stretch import (
    FETCH_BOUND_CIRCUITS,
    ONE_SIDED,
    PORT_BASED,
    STRETCHED,
    TRANSLATED,
    MacIndex,
    check_vlan_stretch,
    mac_rows_query,
    observed_mac_count,
    read_mac_rows,
    stretch_observations,
    stretch_warnings,
)
from hst.reasoner.zscaler import (
    FETCH_SHARED_ZSCALER_SCOPES,
    FETCH_ZIA_ONLY_SITES,
    FETCH_ZSCALER_ADDRESSES,
    GLOBAL_ADDRESS_CONFIDENCE,
    PRIVATE_ADDRESS_CONFIDENCE,
    ZPA_ZIA_SAME_AS_RULE,
    check_zscaler,
    resolve_zpa_zia_ip_links,
)

__all__ = [
    "ACTIVE_CIRCUIT_STATES",
    "CLEAR",
    "CLEAR_PROPS",
    "CONTAINMENT_ADDRESSES",
    "CONTAINMENT_BD_MAP",
    "CONTAINMENT_PREFIXES",
    "CONTAINMENT_WRITE",
    "EDGE_DEVICE_RULE",
    "EDGE_ON_WRITE",
    "EDGE_REALIZED_WRITE",
    "EDGE_SAME_AS_WRITE",
    "ENDED_CIRCUIT_STATES",
    "FABRIC_PORT_ISSUE_WRITE",
    "FABRIC_PORT_RULE",
    "FETCH_BOUND_CIRCUITS",
    "FETCH_DEVICE_PORTS",
    "FETCH_DEVICE_ROLES",
    "FETCH_EDGE_BINDINGS",
    "FETCH_EDGE_BINDINGS_REFUSED",
    "FETCH_EDGE_CANDIDATES",
    "FETCH_EDGE_DEVICES",
    "FETCH_EDGE_INTERFACES",
    "FETCH_MAC_OWNERS",
    "FETCH_RUN_DEVICES",
    "FETCH_SDWAN_ADDRESSES",
    "FETCH_SHARED_ZSCALER_SCOPES",
    "FETCH_STATED_CABLE_PORTS",
    "FETCH_ZIA_ONLY_SITES",
    "FETCH_ZSCALER_ADDRESSES",
    "GATEWAY_ROLES",
    "GLOBAL_ADDRESS_CONFIDENCE",
    "ONE_SIDED",
    "PORT_BASED",
    "PRIVATE_ADDRESS_CONFIDENCE",
    "RULES",
    "SET_DEVICE_ROLES",
    "STATED_CABLE_SOURCES",
    "STATED_CABLE_WRITE",
    "STRETCHED",
    "TRANSLATED",
    "ZPA_ZIA_SAME_AS_RULE",
    "MacIndex",
    "_canonical_mac_or_none",
    "_fabric_port_matcher",
    "_run_edge_device_rule",
    "apply_device_roles",
    "check_edge_devices",
    "check_vlan_stretch",
    "check_zscaler",
    "containment_pairs",
    "derive_arp_cables",
    "edge_device_candidates",
    "fabric_port_issues",
    "fabric_port_warnings",
    "mac_rows_query",
    "observed_mac_count",
    "read_mac_rows",
    "resolve_arp_cables",
    "resolve_edge_device_bindings",
    "resolve_fabric_port_bindings",
    "resolve_stated_cables",
    "resolve_zpa_zia_ip_links",
    "run",
    "stretch_observations",
    "stretch_warnings",
]
