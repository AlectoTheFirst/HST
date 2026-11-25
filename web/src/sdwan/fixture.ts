import type { SdwanTopology } from "../api/types";

/** One edge with 2 WAN links, tunnels to 2 hubs at 2 sites and to 1 cloud
 *  gateway, the hub cables, and 2 parallel cables between the switches. */
export const TOPOLOGY: SdwanTopology = {
  edge: { uid: "e1", name: "XX-CITY-BR-RTS-01", model: "edge3800", city: "Berlin", ha_type: "ACTIVE_STANDBY" },
  links: [
    {
      uid: "l4", name: "BT DIA 2", kind: "dia", carrier: "BT", provider: "BT", public_ip: "192.0.2.165",
      mode: "PUBLIC", interface: "GE4", up_mbps: 600, down_mbps: 600, backup_only: false,
    },
    {
      uid: "l3", name: "BT DIA 1", kind: "dia", carrier: "BT", provider: "BT", public_ip: "192.0.2.61",
      mode: "PUBLIC", interface: "GE3", up_mbps: 600, down_mbps: 600, backup_only: false,
    },
  ],
  tunnels: [
    { uid: "t1", interface: "GE3", peer: "h1", peer_kind: "hub", peer_ip: "203.0.113.1" },
    { uid: "t2", interface: "GE4", peer: "h2", peer_kind: "hub", peer_ip: "203.0.113.2" },
    { uid: "t3", interface: "GE3", peer: "g1", peer_kind: "gateway", peer_ip: null },
    { uid: "t4", interface: "GE9", peer: "h1", peer_kind: "hub", peer_ip: null },
    { uid: "t5", interface: "GE3", peer: null, peer_kind: null, peer_ip: "198.51.100.9" },
  ],
  hubs: [
    { uid: "h1", name: "XX-DC1-RTH-03", site: "FR2" },
    { uid: "h2", name: "XX-DC2-RTH-03", site: "FR6" },
  ],
  gateways: [{ uid: "g1", name: "XX-DC1-VCG-02" }],
  devices: [
    { uid: "sw2", name: "XX-DC1-SWC-02", platform: "nxos", site: "FR2" },
    { uid: "sw1", name: "XX-DC1-SWC-01", platform: "nxos", site: "FR2" },
    { uid: "sw6", name: "XX-DC2-SWC-01", platform: "nxos", site: "FR6" },
  ],
  sites: [
    { code: "FR6", name: "FR6" },
    { code: "FR2", name: "FR2" },
  ],
  cables: [
    { a_dev: "h1", a_port: "GE5", b_dev: "sw1", b_port: "Ethernet1/1", source: null },
    { a_dev: "sw1", a_port: "Ethernet1/101", b_dev: "sw6", b_port: "Ethernet1/101", source: "cdp" },
    { a_dev: "sw1", a_port: "Ethernet1/102", b_dev: "sw6", b_port: "Ethernet1/102", source: "cdp" },
  ],
  policy: {
    uid: "p1",
    name: "Business Policy",
    rule_count: 2,
    capability_gap: null,
    rules: [
      {
        name: "default", position: 2, default: true, segment_id: "0", segment_name: "Global Segment",
        match_summary: "any", qos_class: "bulk",
      },
      {
        name: "voice", position: 1, default: false, segment_id: "0", segment_name: "Global Segment",
        match_summary: "dscp 46 udp", qos_class: "realtime", priority_tx: "high", priority_rx: "high",
        route_type: "edge2Cloud", edge2cloud_route_policy: "gateway", edge2cloud_link_policy: "auto",
        edge2datacenter_route_policy: "backhaul", sla_latency_ms: 150,
      },
    ],
  },
};
