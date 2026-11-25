import type { Row, TableName } from "../render/types";

export interface Spec {
  sites: number;
  devices: number;
  ports: number;
}

export type Tables = Record<TableName, Row[]>;

const PITCH_U = 6;
const PITCH_V = 5;

/** A small estate in the shape of the HST tables: `devices` per site in one block, a cable chain per block,
 * a VRF on every device and a second one on the even devices, and 3 tunnels between the first devices of
 * sites 0 and 1. */
export function estate(spec: Spec): Tables {
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
  const cols = Math.ceil(Math.sqrt(spec.devices));
  const rows = Math.ceil(spec.devices / cols);
  const plateW = cols * PITCH_U + 4;
  const plateH = rows * PITCH_V + 10;
  for (let s = 0; s < spec.sites; s++) {
    const site = `site:s${s}`;
    const plate = `plate:s${s}`;
    const block = `block:s${s}:campus`;
    const u0 = s * (plateW + 8);
    t.layout.push({ uid: site, kind: "site", parent_uid: null, u: u0, v: 0, w: plateW, h: plateH });
    t.layout.push({ uid: plate, kind: "plate", parent_uid: site, u: u0, v: 0, w: plateW, h: plateH });
    t.layout.push({ uid: block, kind: "block", parent_uid: plate, u: u0 + 2, v: 6, w: plateW - 4, h: rows * PITCH_V });
    t.render_t0.push({ uid: site, kind: "site", label: `s${s}`, device_count: spec.devices, failed_count: 0, carried_count: 0 });
    t.render_t0.push({ uid: plate, kind: "plate", parent_uid: site, device_count: spec.devices });
    t.render_t0.push({ uid: block, kind: "block", parent_uid: plate, block_kind: "campus", label: "campus" });
    for (let i = 0; i < spec.devices; i++) {
      const uid = `dev:s${s}d${i}`;
      const u = u0 + 3 + (i % cols) * PITCH_U;
      const v = 7 + Math.floor(i / cols) * PITCH_V;
      t.layout.push({ uid, kind: "device", parent_uid: block, u, v, w: 4, h: 3 });
      t.render_t1.push({ uid, site_uid: site, block_uid: block, label: `s${s}d${i}`, status: "observed", change: "none" });
      t.render_t1_contexts.push({ device_uid: uid, context_uid: `vrf:${uid}:default`, identity_uid: "ident:default" });
      t.render_t2_contexts.push({ uid: `vrf:${uid}:default`, device_uid: uid, tile: block, name: "default", is_default: true, order: 0 });
      if (i % 2 === 0) {
        t.render_t1_contexts.push({ device_uid: uid, context_uid: `vrf:${uid}:blue`, identity_uid: `ident:blue:s${s}` });
        t.render_t2_contexts.push({ uid: `vrf:${uid}:blue`, device_uid: uid, tile: block, name: "blue", is_default: false, order: 1 });
      }
      for (let p = 0; p < spec.ports; p++) {
        const port = `${uid}/port/eth${p}`;
        // The ports share the cells of their device wall, as the planner places them: slot modulo the wall length.
        t.layout.push({ uid: port, kind: "port", parent_uid: uid, u: u + (p % 4), v, w: 1, h: 1, side: "n", slot: p });
        t.render_t2_ports.push({
          uid: port,
          device_uid: uid,
          tile: block,
          name: `eth${p}`,
          name_short: `e${p}`,
          admin_status: "up",
          oper_status: "up",
          context_uid: `vrf:${uid}:${p === 0 && i % 2 === 0 ? "blue" : "default"}`,
          change: "none",
        });
      }
      if (i > 0 && spec.ports >= 2) {
        const prev = `dev:s${s}d${i - 1}`;
        const a = `${prev}/port/eth1`;
        const b = `${uid}/port/eth0`;
        const id = [a, b].sort().join("~");
        const pa = t.layout.find((r) => r.uid === a)!;
        const pb = t.layout.find((r) => r.uid === b)!;
        t.layout.push({ uid: id, kind: "cable", parent_uid: plate, u: 0, v: 0, w: 1, h: 1, points: JSON.stringify([[pa.u, pa.v], [pb.u, pb.v]]) });
        t.render_t2_cables.push({ cable_id: id, tile_a: block, tile_b: block, a_port: a, b_port: b, a_dev: prev, b_dev: uid, change: "none" });
        t.render_t1_edges.push({ pair_id: `${prev}|${uid}`, a_uid: prev, b_uid: uid, cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
      }
    }
  }
  if (spec.sites >= 2) {
    t.render_t1_edges.push({ pair_id: "dev:s0d0|dev:s1d0", a_uid: "dev:s0d0", b_uid: "dev:s1d0", cable_count: 0, lag_count: 0, tunnel_count: 3, change: "none" });
    t.render_t1_edges.push({ pair_id: "dev:s0d1|dev:s1d1", a_uid: "dev:s0d1", b_uid: "dev:s1d1", cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
  }
  t.context_identity.push({ identity_uid: "ident:default", basis: "name", name: "default", member_count: spec.sites * spec.devices });
  for (let s = 0; s < spec.sites; s++) {
    t.context_identity.push({ identity_uid: `ident:blue:s${s}`, basis: "rd", name: "blue", rd: `65000:${s}`, member_count: Math.ceil(spec.devices / 2) });
  }
  return t;
}

/** The rows of a tiled table that belong to `tile`, and the layout rows of its ports and cables. */
export function tile(t: Tables, name: TableName, block: string): Row[] {
  if (name === "layout") {
    const devices = new Set(t.layout.filter((r) => r.kind === "device" && r.parent_uid === block).map((r) => r.uid));
    const ports = new Set(t.layout.filter((r) => r.kind === "port" && devices.has(r.parent_uid)).map((r) => r.uid));
    return t.layout.filter(
      (r) => ports.has(r.uid) || (r.kind === "cable" && String(r.uid).split("~").some((p) => ports.has(p))),
    );
  }
  return t[name].filter((r) => r.tile === block || r.tile_a === block || r.tile_b === block);
}

export function base(t: Tables): Row[] {
  return t.layout.filter((r) => r.kind !== "port" && r.kind !== "cable");
}
