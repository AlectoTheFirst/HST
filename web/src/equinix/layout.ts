import type { EquinixCircuit, EquinixEnd, EquinixMetroView } from "../api/types";
import type { View } from "../diagram/useCanvas";

export type EquinixNodeKind = "switch" | "edge" | "port" | "metro" | "provider" | "other";

export interface EquinixNode {
  uid: string;
  kind: EquinixNodeKind;
  name: string;
  caption: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface EquinixFrame {
  key: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

/** A switch port to the Fabric port it realizes. */
export interface EquinixCable {
  device: string;
  fabricPort: string;
  portName: string;
  by: string | null;
}

/** The circuits between one pair of nodes. */
export interface EquinixBundle {
  key: string;
  a: string;
  b: string;
  circuits: EquinixCircuit[];
}

export interface EquinixLayout {
  frames: EquinixFrame[];
  nodes: EquinixNode[];
  cables: EquinixCable[];
  bundles: EquinixBundle[];
  /** circuits with no end on a node of this picture: listed, not drawn */
  undrawn: number;
  fit: View;
}

export const METRICS = {
  chipW: 176,
  chipH: 36,
  portW: 200,
  portH: 40,
  gapX: 22,
  framePadTop: 34,
  framePad: 16,
  frameGap: 30,
  rowGap: 150,
  // the space above the top row, for the arcs between nodes of one row
  arcRoom: 80,
  margin: 40,
};

export const OTHER_PARTIES = "far:other";

function speed(mbps: number | null): string {
  if (mbps == null) return "";
  return mbps >= 1000 && mbps % 1000 === 0 ? `${mbps / 1000}G` : `${mbps}M`;
}

function portCaption(p: EquinixMetroView["ports"][number]): string {
  return [speed(p.speed_mbps), p.redundancy, p.lag, p.bound ? null : "no switch port"].filter(Boolean).join(", ");
}

/** The node an end of a circuit lands on in this picture. */
export function anchorOf(end: EquinixEnd | null, metro: string, drawn: Set<string>): string {
  if (!end) return OTHER_PARTIES;
  if (end.kind === "port" || end.kind === "edge") {
    const own = end.kind === "port" ? end.node : end.device;
    if (end.metro === metro && own && drawn.has(own)) return own;
    if (end.metro && end.metro !== metro) return `far:metro:${end.metro}`;
    return OTHER_PARTIES;
  }
  if (end.kind === "provider" && end.name) return `far:provider:${end.name}`;
  return OTHER_PARTIES;
}

/** Row `uids` centred on `centre`, or starting at `left` when that is larger. */
function row(count: number, w: number, gap: number, centre: number, left: number): number[] {
  const width = count * w + Math.max(count - 1, 0) * gap;
  const start = Math.max(centre - width / 2, left) + w / 2;
  return Array.from({ length: count }, (_, i) => start + i * (w + gap));
}

export function layoutMetro(v: EquinixMetroView, m = METRICS): EquinixLayout {
  const nodes: EquinixNode[] = [];
  const frames: EquinixFrame[] = [];
  const top = m.margin + m.arcRoom;

  // the middle row first: the switches above sit over their ports
  const portsY = top + m.chipH + m.rowGap + m.framePadTop + m.portH / 2;
  const byIbx = new Map<string, EquinixMetroView["ports"]>();
  for (const p of v.ports) {
    const key = p.ibx ?? "";
    byIbx.set(key, [...(byIbx.get(key) ?? []), p]);
  }
  let x = m.margin;
  const portX = new Map<string, number>();
  for (const [ibx, ports] of [...byIbx].sort(([a], [b]) => a.localeCompare(b))) {
    const sorted = [...ports].sort((a, b) => a.name.localeCompare(b.name));
    const width = sorted.length * m.portW + (sorted.length - 1) * m.gapX + 2 * m.framePad;
    frames.push({
      key: ibx,
      label: ibx ? `IBX ${ibx}` : "No IBX",
      x,
      y: portsY - m.portH / 2 - m.framePadTop,
      width,
      height: m.framePadTop + m.portH + m.framePad,
    });
    let cx = x + m.framePad + m.portW / 2;
    for (const p of sorted) {
      nodes.push({ uid: p.uid, kind: "port", name: p.name, caption: portCaption(p), x: cx, y: portsY, w: m.portW, h: m.portH });
      portX.set(p.uid, cx);
      cx += m.portW + m.gapX;
    }
    x += width + m.frameGap;
  }
  const portsRight = Math.max(x - m.frameGap, m.margin + m.portW);
  const centre = (m.margin + portsRight) / 2;

  // the top row: each switch in the order of the mean position of its ports,
  // then the Network Edge devices by name
  const cables: EquinixCable[] = [];
  const meanX = new Map<string, number[]>();
  for (const p of v.ports) {
    if (!p.bound) continue;
    cables.push({ device: p.bound.device, fabricPort: p.uid, portName: p.bound.port_name ?? "", by: p.bound.by });
    meanX.set(p.bound.device, [...(meanX.get(p.bound.device) ?? []), portX.get(p.uid) ?? 0]);
  }
  const mean = (uid: string) => {
    const xs = meanX.get(uid) ?? [];
    return xs.length ? xs.reduce((s, n) => s + n, 0) / xs.length : Number.MAX_SAFE_INTEGER;
  };
  const switches = [...v.devices].sort((a, b) => mean(a.uid) - mean(b.uid) || a.name.localeCompare(b.name));
  const edges = [...v.edge_devices].sort((a, b) => a.name.localeCompare(b.name));
  const topY = top + m.chipH / 2;
  const topXs = row(switches.length + edges.length, m.chipW, m.gapX, centre, m.margin);
  switches.forEach((d, i) =>
    nodes.push({ uid: d.uid, kind: "switch", name: d.name, caption: d.platform ?? "", x: topXs[i], y: topY, w: m.chipW, h: m.chipH }),
  );
  edges.forEach((d, i) =>
    nodes.push({
      uid: d.uid,
      kind: "edge",
      name: d.name,
      caption: ["Network Edge", d.model, d.same_as_name ? `is ${d.same_as_name}` : null].filter(Boolean).join(", "),
      x: topXs[switches.length + i],
      y: topY,
      w: m.chipW,
      h: m.chipH,
    }),
  );

  // the bundles, and the far ends they need
  const drawn = new Set(nodes.map((n) => n.uid));
  const far = new Map<string, { kind: EquinixNodeKind; name: string; count: number }>();
  const bundles = new Map<string, EquinixBundle>();
  let undrawn = 0;
  const nearAnchor = (c: EquinixCircuit) => {
    for (const [near, other] of [
      [c.a, c.z],
      [c.z, c.a],
    ] as const) {
      const a = anchorOf(near, v.metro, drawn);
      if (drawn.has(a)) return [a, anchorOf(other, v.metro, drawn)];
    }
    return null;
  };
  for (const c of v.circuits) {
    const ends = nearAnchor(c);
    if (!ends) {
      undrawn += 1;
      continue;
    }
    const [a, b] = ends;
    if (!drawn.has(b)) {
      const kind: EquinixNodeKind = b.startsWith("far:metro:") ? "metro" : b.startsWith("far:provider:") ? "provider" : "other";
      const name =
        kind === "metro" ? `Metro ${b.slice("far:metro:".length)}` : kind === "provider" ? b.slice("far:provider:".length) : "Other parties";
      const entry = far.get(b) ?? { kind, name, count: 0 };
      entry.count += 1;
      far.set(b, entry);
    }
    const key = [a, b].sort().join("|");
    const bundle = bundles.get(key) ?? { key, a, b, circuits: [] };
    bundle.circuits.push(c);
    bundles.set(key, bundle);
  }

  // the bottom row: metros by code, providers by circuit count, other parties last
  const rank = { metro: 0, provider: 1, other: 2 } as Record<string, number>;
  const farList = [...far].sort(
    ([ka, a], [kb, b]) => rank[a.kind] - rank[b.kind] || (a.kind === "provider" ? b.count - a.count : 0) || ka.localeCompare(kb),
  );
  const farY = portsY + m.portH / 2 + m.framePad + m.rowGap + m.chipH / 2;
  const farXs = row(farList.length, m.chipW, m.gapX, centre, m.margin);
  farList.forEach(([uid, f], i) =>
    nodes.push({
      uid,
      kind: f.kind,
      name: f.name,
      caption: f.count === 1 ? "1 circuit" : `${f.count} circuits`,
      x: farXs[i],
      y: farY,
      w: m.chipW,
      h: m.chipH,
    }),
  );

  const right = Math.max(portsRight, ...nodes.map((n) => n.x + n.w / 2));
  const fit: View = { x: 0, y: 0, w: right + m.margin, h: farY + m.chipH / 2 + m.margin };
  return { frames, nodes, cables, bundles: [...bundles.values()], undrawn, fit };
}
