/**
 * A small site for the L2 and L3 layers: one
 * router with twelve connected prefixes (six VLANs on subinterfaces, each
 * dual stack, and the untagged eth0 on the default network of the switches),
 * a WAN interface, a tunnel and a loopback that belong to no segment, one
 * core switch, two access switches and three access points. Every name and
 * address is invented.
 */

import type {
  MapSubnet,
  SegmentCarrier,
  SegmentGateway,
  TopologyModel,
  TopologyNode,
  TopologySegment,
} from "../../api/types";

const ROUTER = "dev:gw-01";
const CORE = "dev:sw-core";
const ACCESS = ["dev:sw-office", "dev:sw-attic"];
const APS = ["dev:ap-hall", "dev:ap-office", "dev:ap-garden"];

const device = (
  id: string,
  label: string,
  role: string,
  tier: string,
  mgmt: string,
): TopologyNode => ({
  id,
  kind: "device",
  parent: "block:home:campus",
  label,
  role,
  tier,
  mgmt_ip: mgmt,
});

const cable = (
  a: string,
  aPort: string,
  b: string,
  bPort: string,
  mbps = 1000,
) => ({
  id: `${a}|${aPort}~${b}|${bPort}`,
  from: { dev: a, port: aPort },
  to: { dev: b, port: bPort },
  source: "lldp",
  lateral: false,
  speed_mbps: mbps,
});

/** vid, name, IPv4 /24 third octet; the router's subinterface eth0.<vid>, VLAN 1 untagged on eth0 */
const VLANS: [number, string][] = [
  [1, "Default"],
  [10, "VL_10_HOME"],
  [20, "VL_20_IOT"],
  [30, "VL_30_GUEST"],
  [40, "VL_40_CAMERAS"],
  [50, "VL_50_LAB"],
];

const bd = (vid: number) => `bd:vlan:fab-home:${vid}`;
const v4 = (vid: number) => `192.168.${vid === 1 ? 2 : vid}.0/24`;
const v6 = (vid: number) => `2001:db8:${vid === 1 ? 2 : vid}::/64`;
const iface = (vid: number) => (vid === 1 ? "eth0" : `eth0.${vid}`);

function gateway(vid: number, af: 4 | 6): SegmentGateway {
  const cidr = af === 4 ? v4(vid) : v6(vid);
  const ip =
    af === 4 ? cidr.replace("0/24", "1") : cidr.replace("::/64", "::1");
  return {
    dev: ROUTER,
    iface: iface(vid),
    ip,
    cidr,
    af,
    vrf: "default",
    domain: null,
    fhrp: null,
    basis: vid === 1 ? "cable" : "subif",
  };
}

const ACCESS_PORTS: Record<string, Record<number, string[]>> = {
  [CORE]: { 1: ["Port 7", "Port 8"], 40: ["Port 6"], 50: ["Port 5"] },
  "dev:sw-office": {
    1: ["Port 8"],
    10: ["Port 2", "Port 3", "Port 4", "Port 5", "Port 6"],
    20: ["Port 7"],
  },
  "dev:sw-attic": { 10: ["Port 2"], 40: ["Port 3", "Port 4"] },
};

function carriers(vid: number): SegmentCarrier[] {
  const out: SegmentCarrier[] = [];
  const trunk: Record<string, string[]> = {
    [CORE]: ["Port 1", "Port 2", "Port 3", "Port 4"],
    "dev:sw-office": ["Port 1", "Port 9"],
    "dev:sw-attic": ["Port 1", "Port 8"],
  };
  for (const dev of [CORE, ...ACCESS]) {
    const access = ACCESS_PORTS[dev][vid] ?? [];
    out.push({
      dev,
      ports: [...trunk[dev], ...access].sort(),
      native: vid === 1 ? [trunk[dev][0], ...access] : access,
      access,
    });
  }
  if (vid === 10 || vid === 20 || vid === 30)
    for (const ap of APS)
      out.push({ dev: ap, ports: ["eth0"], native: [], access: [] });
  return out;
}

const SEGMENTS: TopologySegment[] = VLANS.map(([vid, name]) => ({
  bd: bd(vid),
  vid,
  name,
  cidrs: [v4(vid), v6(vid)],
  cidr_basis: "gateway",
  gateways: [gateway(vid, 4), gateway(vid, 6)],
  carriers: carriers(vid),
  clients: 0,
  attachments: [],
}));

const subnet = (
  cidr: string,
  members: [string, string, string][],
): MapSubnet => ({
  cidr,
  af: cidr.includes(":") ? 6 : 4,
  vrf: "default",
  domain: null,
  members: members.map(([dev, i, ip]) => ({ dev, iface: i, ip, fhrp: null })),
});

const SUBNETS: MapSubnet[] = [
  ...SEGMENTS.flatMap((s) =>
    s.gateways.map((g) => subnet(g.cidr!, [[g.dev, g.iface, g.ip!]])),
  ),
  subnet("203.0.113.0/24", [[ROUTER, "eth1", "203.0.113.20"]]),
  subnet("10.255.0.0/24", [[ROUTER, "wg0", "10.255.0.1"]]),
  subnet("10.0.0.1/32", [[ROUTER, "lo", "10.0.0.1"]]),
];

export const HOME_SITE: TopologyModel = {
  snapshot: 1_760_000_000_000,
  nodes: [
    { id: "site:home", kind: "site", parent: null, label: "home" },
    {
      id: "block:home:campus",
      kind: "block",
      parent: "site:home",
      label: "Campus",
      block_kind: "campus",
    },
    device(ROUTER, "gw-01", "router", "core", "192.168.2.1"),
    device(CORE, "sw-core", "switch", "distribution", "192.168.2.10"),
    device("dev:sw-office", "sw-office", "switch", "access", "192.168.2.11"),
    device("dev:sw-attic", "sw-attic", "switch", "access", "192.168.2.12"),
    device("dev:ap-hall", "ap-hall", "ap", "access", "192.168.2.21"),
    device("dev:ap-office", "ap-office", "ap", "access", "192.168.2.22"),
    device("dev:ap-garden", "ap-garden", "ap", "access", "192.168.2.23"),
  ],
  cables: [
    cable(ROUTER, "eth0", CORE, "Port 1"),
    cable(CORE, "Port 2", "dev:sw-office", "Port 1"),
    cable(CORE, "Port 3", "dev:sw-attic", "Port 1"),
    cable(CORE, "Port 4", "dev:ap-hall", "eth0"),
    cable("dev:sw-office", "Port 9", "dev:ap-office", "eth0"),
    cable("dev:sw-attic", "Port 8", "dev:ap-garden", "eth0"),
  ],
  exits: [],
  lags: [],
  split_groups: [],
  clients: [],
  vlans: SEGMENTS.flatMap((s) => [
    ...(s.vid === 1
      ? []
      : [
          {
            dev: ROUTER,
            vid: s.vid!,
            name: s.name,
            segment: s.name,
            bd: s.bd,
            ports: ["eth0"],
            native: [],
            svi: iface(s.vid!),
          },
        ]),
    ...s.carriers.map((c) => ({
      dev: c.dev,
      vid: s.vid!,
      name: s.name,
      segment: s.name,
      bd: s.bd,
      ports: c.ports,
      native: c.native,
      svi: null,
    })),
  ]),
  subnets: SUBNETS,
  segments: SEGMENTS,
};

