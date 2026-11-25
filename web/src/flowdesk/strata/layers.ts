/**
 * The array index of `STRATA_LAYERS`, bottom-up, is the layer id of the Strata modules.
 */

export const STRATA_LAYERS = ["physical", "routing", "policy", "application"] as const;


/** Layer index for a kind with no entry in `LAYER_BY_KIND`. */
export const FALLBACK_LAYER = 0; // physical

/**
 * One entry per `LABELS` key in `core/labels.py`, in that file's order.
 *
 * Layer indices: 0 physical, 1 routing, 2 policy, 3 application (STRATA_LAYERS).
 */
export const LAYER_BY_KIND: Readonly<Record<string, number>> = {
  // --- location / physical (labels.py §1): devices, interfaces, ports, sites
  Site: 0,
  Rack: 0,
  Device: 0,
  RedundancyGroup: 0,
  FailureDomain: 0,
  Module: 0,
  Port: 0,
  Provider: 0,
  ProviderNetwork: 0,
  Pnic: 0,

  // --- L2 (labels.py §2): interfaces, bridging, VLANs, SSIDs
  Interface: 0,
  Lag: 0,
  VlanInstance: 0,
  BridgeDomain: 0,
  L2Vni: 0,
  L2Segment: 0,
  FhrpGroup: 1,
  Endpoint: 3,
  Ssid: 0,

  // --- L3 / routing (labels.py §3)
  VrfInstance: 1,
  FirewallInstance: 2,
  RoutingDomain: 1,
  L3Domain: 1,
  Prefix: 1,
  IpAddress: 1,
  RouteTarget: 1,
  RoutingProcess: 1,
  BgpSession: 1,
  BgpPeerRange: 1,
  OspfArea: 1,
  OspfAdjacency: 1,
  RoutePolicy: 1,
  RoutePolicyEntry: 1,
  PrefixListEntry: 1,
  MatchListEntry: 1,

  // --- overlay / transport (labels.py §4)
  Fabric: 0,
  Pod: 0,
  Tunnel: 1,
  OverlayConnection: 1,
  EvpnInstance: 1,
  SdwanSegment: 1,
  ForwardingBoundary: 1,
  WanLink: 0,
  SdwanGateway: 0,
  SdwanBusinessPolicy: 2,
  SdwanPolicyRule: 2,
  SdwanStaticRoute: 1,
  NdoSchema: 0,
  NdoTemplate: 0,

  // --- ACI policy & service insertion (labels.py §5)
  Tenant: 2,
  AppProfile: 2,
  Epg: 2,
  Esg: 2,
  ExtEpg: 2,
  L3Out: 1,
  Contract: 2,
  ContractSubject: 2,
  AciFilter: 2,
  FilterEntry: 2,
  VzAny: 2,
  ServiceGraphTemplate: 2,
  ServiceGraphInstance: 2,
  ServiceNode: 2,
  PbrPolicy: 2,
  PbrDest: 2,

  // --- generic firewall model (labels.py §6)
  FwRulebase: 2,
  FwRule: 2,
  FwSection: 2,
  CpPolicyPackage: 2,
  CpPolicyObject: 2,
  NetObject: 3,
  SvcObject: 3,
  Zone: 2,
  NatRule: 2,

  // --- LB / DNS (labels.py §7)
  VirtualService: 3,
  Pool: 3,
  PoolMember: 3,
  Monitor: 3,
  DnsRecord: 3,

  // --- Zscaler (labels.py §8)
  ZscalerDc: 0,
  ZiaLocation: 2,
  ZiaLocationGroup: 2,
  ZiaForwardingRule: 2,
  ZpaAppSegment: 2,
  ZpaSegmentGroup: 2,
  ZpaServerGroup: 2,
  AppServer: 0,
  ZpaAppConnectorGroup: 2,
  ZpaAppConnector: 0,
  ZpaAccessRule: 2,
  ZpaClientForwardingRule: 2,
  ZpaProvisioningKey: 2,
  ZpaServiceEdge: 0,
  IdentityGroup: 3,

  // --- AWS (labels.py §9)
  Organization: 0,
  Account: 0,
  Region: 0,
  Az: 0,
  Vpc: 1,
  Subnet: 1,
  RouteTable: 1,
  CloudRoute: 1,
  Igw: 0,
  NatGw: 2,
  Eni: 0,
  VpcPeering: 1,
  Tgw: 1,
  TgwAttachment: 1,
  TgwRouteTable: 1,
  VpcEndpoint: 3,
  EndpointService: 3,
  DxConnection: 0,
  DxVif: 1,
  DxGw: 1,
  VpnConnection: 1,
  Instance: 0,

  // --- Azure (labels.py §10)
  Subscription: 0,
  ResourceGroup: 0,
  VNet: 1,
  Nic: 0,
  VNetPeering: 1,
  VirtualWan: 1,
  VHub: 1,
  HubRouteTable: 1,
  ErCircuit: 0,
  ErPeering: 1,
  VNetGw: 1,
  AzFirewall: 2,
  PrivateEndpoint: 3,
  PrivateLinkService: 3,

  // --- Equinix (labels.py §11)
  FabricPort: 0,
  VirtualCircuit: 0,

  // --- virtualization / compute / app (labels.py §12)
  Vcenter: 0,
  VmwCluster: 0,
  EsxHost: 0,
  Vm: 0,
  Vnic: 0,
  Dvs: 0,
  DvPortgroup: 0,
  Server: 0,
  BusinessService: 3,
  AppComponent: 3,
  ServiceRequirement: 3,
  DependencyGroup: 3,

  // --- meta
  CollectionRun: 0,
  PolicyInstallation: 0,
  MtuObservation: 0,

  // --- synthetic (SYNTHETIC_KINDS)
  NextHop: 1,
};

/** Hop kinds that the path builder synthesizes and that `core/labels.py` does not declare. */
export const SYNTHETIC_KINDS: ReadonlySet<string> = new Set(["NextHop"]);

export function layerOf(kind: string): number {
  const layer = LAYER_BY_KIND[kind];
  return layer === undefined ? FALLBACK_LAYER : layer;
}
