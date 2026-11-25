import type { Row } from "../render/types";
import type { Tables } from "./estate";

/** One device of a showcase block: its name, role and tier. */
type Spec = [name: string, role: string, tier: string];

interface Block {
  kind: string;
  label: string;
  devices: Spec[];
  /** Device pairs cabled inside the block, by index. */
  links: [number, number, number?][];
}

interface Site {
  code: string;
  label: string;
  blocks: Block[];
}

const W = 4;
const H = 3;
const GAP = 3;
const PAD = 3;
const BAND_GAP = 6;
const SITE_GAP = 14;

const SITES: Site[] = [
  {
    code: "hq",
    label: "Headquarters",
    blocks: [
      {
        kind: "internet-edge",
        label: "Internet Edge",
        devices: [
          ["isp-a", "cloud", "internet-edge"],
          ["isp-b", "cloud", "internet-edge"],
          ["edge-rt-1", "router", "internet-edge"],
          ["edge-rt-2", "router", "internet-edge"],
        ],
        links: [[0, 2], [1, 3], [2, 3, 2]],
      },
      {
        kind: "firewall",
        label: "Perimeter",
        devices: [
          ["fw-1", "firewall", "firewall"],
          ["fw-2", "firewall", "firewall"],
        ],
        links: [[0, 1, 2]],
      },
      {
        kind: "wan-edge",
        label: "WAN Region",
        devices: [
          ["wan-hub-1", "sdwan-hub", "sdwan-hub"],
          ["wan-hub-2", "sdwan-hub", "sdwan-hub"],
          ["wan-rt-1", "router", "wan-edge"],
        ],
        links: [[0, 2], [1, 2]],
      },
      {
        kind: "dc",
        label: "Data Center North",
        devices: [
          ["spine-1", "spine", "spine"],
          ["spine-2", "spine", "spine"],
          ["leaf-1", "leaf", "access"],
          ["leaf-2", "leaf", "access"],
          ["leaf-3", "leaf", "access"],
          ["leaf-4", "leaf", "access"],
          ["srv-1", "server", "access"],
          ["srv-2", "server", "access"],
          ["srv-3", "server", "access"],
          ["srv-4", "server", "access"],
        ],
        links: [[0, 2], [0, 3], [0, 4], [0, 5], [1, 2], [1, 3], [1, 4], [1, 5], [2, 6], [3, 7], [4, 8], [5, 9]],
      },
      {
        kind: "campus",
        label: "Campus",
        devices: [
          ["core-1", "l3switch", "core"],
          ["core-2", "l3switch", "core"],
          ["acc-1", "switch", "access"],
          ["acc-2", "switch", "access"],
          ["acc-3", "switch", "access"],
          ["acc-4", "switch", "access"],
          ["ap-1", "ap", "access-point"],
          ["ap-2", "ap", "access-point"],
          ["ap-3", "ap", "access-point"],
          ["ap-4", "ap", "access-point"],
          ["wlc-1", "controller", "wireless"],
        ],
        links: [[0, 1, 4], [0, 2], [0, 3], [1, 4], [1, 5], [2, 6], [3, 7], [4, 8], [5, 9], [0, 10]],
      },
    ],
  },
  {
    code: "br1",
    label: "Branch Network",
    blocks: [
      {
        kind: "campus",
        label: "Branch Floor",
        devices: [
          ["br-edge", "sdwan-edge", "wan-edge"],
          ["br-sw-1", "switch", "access"],
          ["br-ap-1", "ap", "access-point"],
          ["br-ap-2", "ap", "access-point"],
        ],
        links: [[0, 1], [1, 2], [1, 3]],
      },
    ],
  },
  {
    code: "dc2",
    label: "Data Center South",
    blocks: [
      {
        kind: "dc",
        label: "Compute",
        devices: [
          ["s-spine-1", "spine", "spine"],
          ["s-leaf-1", "leaf", "access"],
          ["s-leaf-2", "leaf", "access"],
          ["s-srv-1", "server", "access"],
          ["s-srv-2", "server", "access"],
          ["s-fw", "firewall", "firewall"],
        ],
        links: [[0, 1], [0, 2], [1, 3], [2, 4], [0, 5]],
      },
    ],
  },
];

/** Cables between blocks and sites: [device, device, cables]. */
const UPLINKS: [string, string, number][] = [
  ["edge-rt-1", "fw-1", 1],
  ["edge-rt-2", "fw-2", 1],
  ["fw-1", "core-1", 2],
  ["fw-2", "core-2", 2],
  ["core-1", "spine-1", 4],
  ["core-2", "spine-2", 4],
  ["wan-rt-1", "core-1", 1],
  ["s-spine-1", "spine-1", 2],
];

/** Tunnels between sites: [device, device, tunnels]. */
const TUNNELS: [string, string, number][] = [
  ["wan-hub-1", "br-edge", 2],
  ["wan-hub-2", "br-edge", 1],
];

/**
 * An estate of a headquarters site with every block kind, a branch
 * and a second data centre, in the shape of the HST tables, with every device's role and tier.
 */
export function showcase(): Tables {
  const t: Tables = {
    layout: [],
    render_t0: [],
    render_t1: [],
    render_t1_edges: [],
    render_t1_circuits: [],
    render_t1_fabric_ports: [],
    render_t1_contexts: [],
    context_identity: [],
    render_t2_ports: [],
    render_t2_cables: [],
    render_t2_contexts: [],
    render_t2_segments: [],
    render_t2_port_groups: [],
  };
  const uidOf = (name: string) => `dev:${name}`;
  const portCount = new Map<string, number>();
  const blockOf = new Map<string, string>();
  const place = new Map<string, Row>();
  const nextPort = (device: string, side: string) => {
    const n = portCount.get(device) ?? 0;
    portCount.set(device, n + 1);
    const d = place.get(device)!;
    const u = Number(d.u) + (side === "e" ? W - 1 : n % W);
    const v = Number(d.v) + (side === "e" ? Math.min(H - 1, 1 + Math.floor(n / W)) : H - 1);
    const uid = `${device}/port/Ethernet1/${n + 1}`;
    t.layout.push({ uid, kind: "port", parent_uid: device, u, v, w: 1, h: 1, side, slot: n });
    t.render_t2_ports.push({
      uid,
      device_uid: device,
      tile: blockOf.get(device),
      name: `Ethernet1/${n + 1}`,
      name_short: `Eth1/${n + 1}`,
      admin_status: "up",
      oper_status: n % 7 === 6 ? "down" : "up",
      speed_mbps: 10_000,
      change: "none",
    });
    return { uid, u, v };
  };
  const cable = (a: string, b: string, cables: number, tunnels = 0) => {
    const pair = [a, b].sort();
    t.render_t1_edges.push({ pair_id: pair.join("|"), a_uid: pair[0], b_uid: pair[1], cable_count: cables, lag_count: 0, tunnel_count: tunnels, change: "none" });
    for (let i = 0; i < cables; i++) {
      const pa = nextPort(a, "s");
      const pb = nextPort(b, "e");
      const id = [pa.uid, pb.uid].sort().join("~");
      t.layout.push({ uid: id, kind: "cable", parent_uid: null, u: 0, v: 0, w: 1, h: 1, points: JSON.stringify([[pa.u, pa.v], [pb.u, pb.v]]) });
      const tile = blockOf.get(a);
      t.render_t2_cables.push({ cable_id: id, tile_a: tile, tile_b: blockOf.get(b), a_port: pa.uid, b_port: pb.uid, a_dev: a, b_dev: b, speed_mbps: 10_000, change: "none" });
    }
  };

  let siteU = 0;
  for (const site of SITES) {
    const siteUid = `site:${site.code}`;
    const plateUid = `plate:${site.code}`;
    let v = PAD;
    let width = 0;
    const bands: Row[] = [];
    for (const block of site.blocks) {
      const cols = Math.ceil(Math.sqrt(1.5 * block.devices.length));
      const rows = Math.ceil(block.devices.length / cols);
      const bw = cols * (W + GAP) + GAP;
      const bh = rows * (H + GAP) + GAP;
      const uid = `block:${site.code}:${block.kind}`;
      bands.push({ uid, kind: "block", parent_uid: plateUid, u: siteU + PAD, v, w: bw, h: bh });
      t.render_t0.push({ uid, kind: "block", parent_uid: plateUid, block_kind: block.kind, label: block.label, device_count: block.devices.length, observed_count: block.devices.length, failed_count: 0, carried_count: 0 });
      block.devices.forEach(([name, role, tier], i) => {
        const dev = uidOf(name);
        const row: Row = { uid: dev, kind: "device", parent_uid: uid, u: siteU + PAD + GAP + (i % cols) * (W + GAP), v: v + GAP + Math.floor(i / cols) * (H + GAP), w: W, h: H };
        t.layout.push(row);
        place.set(dev, row);
        blockOf.set(dev, uid);
        const status = name === "acc-3" ? "carried" : name === "srv-4" ? "failed" : "observed";
        t.render_t1.push({ uid: dev, site_uid: siteUid, block_uid: uid, label: name, role, tier, vendor: "showcase", model: role, status, change: "none", n_ports: 48, n_ports_connected: 4, n_ports_up: 40 });
        t.render_t1_contexts.push({ device_uid: dev, context_uid: `vrf:${dev}:default`, identity_uid: "ident:default" });
      });
      v += bh + BAND_GAP;
      width = Math.max(width, bw);
    }
    const plateW = width + 2 * PAD;
    const plateH = v - BAND_GAP + PAD;
    t.layout.push({ uid: siteUid, kind: "site", parent_uid: null, u: siteU, v: 0, w: plateW, h: plateH });
    t.layout.push({ uid: plateUid, kind: "plate", parent_uid: siteUid, u: siteU, v: 0, w: plateW, h: plateH });
    t.layout.push(...bands);
    const count = site.blocks.reduce((n, b) => n + b.devices.length, 0);
    t.render_t0.push({ uid: siteUid, kind: "site", label: site.label, code: site.code, device_count: count, observed_count: count, failed_count: 0, carried_count: 0 });
    t.render_t0.push({ uid: plateUid, kind: "plate", parent_uid: siteUid, device_count: count });
    siteU += plateW + SITE_GAP;
  }
  for (const site of SITES) {
    for (const block of site.blocks) {
      for (const [a, b, n] of block.links) cable(uidOf(block.devices[a][0]), uidOf(block.devices[b][0]), n ?? 1);
    }
  }
  for (const [a, b, n] of UPLINKS) cable(uidOf(a), uidOf(b), n);
  for (const [a, b, n] of TUNNELS) {
    const pair = [uidOf(a), uidOf(b)].sort();
    t.render_t1_edges.push({ pair_id: pair.join("|"), a_uid: pair[0], b_uid: pair[1], cable_count: 0, lag_count: 0, tunnel_count: n, change: "none" });
  }
  const total = t.render_t1.length;
  t.context_identity.push({ identity_uid: "ident:default", basis: "name", name: "default", member_count: total });
  return t;
}
