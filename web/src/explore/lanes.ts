/** GROUP_MIN or more seeds with the same label become 1 group box. */

import type { GraphNode } from "../api/types";
import { captionFull, OTHER_SLOT, primaryLabel, SLOT_COUNT } from "./graphElements";
import type { Adjacency } from "./treeModel";

/** The schema layers, in the order of `LAYERS` in src/hst/core/labels.py. */
export const LAYERS = ["Phys", "L2", "L3", "Transport", "Policy", "Service", "Workload", "App", "Cloud", "Meta"] as const;
export const OTHER_LANE = "Other";

export const PICTURE_CAP = 40;
export const GROUP_MIN = 8;
export const BOX_W = 164;
export const BOX_H = 30;
/** A box with a second line, and the head of a group box. */
export const BOX_H2 = 42;
export const COL_GAP = 78;
export const ROW_GAP = 10;
export const PAD = 6;
/** Room above the boxes for the layer name. */
export const HEAD = 26;
/** One member line of an open group box, and the most lines it shows. */
export const MEMBER_H = 16;
export const MEMBER_MAX = 10;
export const CAPTION_CUT = 19;
/** How far a loop between 2 boxes of 1 column goes out to the right. */
const LOOP = 30;
/** Top down: the space between 2 boxes of a line, between 2 lines of a band,
 *  between 2 bands, and above the first band of a layer. */
export const GAP_X = 14;
export const LINE_GAP = 14;
export const BAND_GAP = 44;
export const LAYER_HEAD = 20;
/** Top down: the panel width when it is not known. */
export const DEFAULT_WIDTH = 520;

export type PictureDir = "tb" | "lr";

/** The first layer of a node, in LAYERS order, or "Other". */
export function layerOf(node: GraphNode): string {
  return LAYERS.find((l) => node.labels.includes(l)) ?? OTHER_LANE;
}

/** Cut a text once, in the middle, so that its start and its end stay. */
export function cutMiddle(value: string, max: number): string {
  if (value.length <= max) return value;
  const head = Math.ceil((max - 3) / 2);
  return `${value.slice(0, head)}...${value.slice(value.length - (max - 3 - head))}`;
}

interface Group {
  id: string;
  label: string;
  ids: string[];
  seed: boolean;
}

export interface Model {
  seedIds: string[];
  seedSet: Set<string>;
  seedSingles: string[];
  seedGroups: Group[];
  singles: string[];
  groups: Group[];
  /** Each drawn node id to the id of its box. */
  itemOf: Map<string, string>;
  /** Neighbours that the cap kept out. */
  hidden: number;
}

const byCaption = (adj: Adjacency) => (a: string, b: string) =>
  captionFull(adj.nodes.get(a)!).localeCompare(captionFull(adj.nodes.get(b)!)) || a.localeCompare(b);

/** The boxes of the picture before the layout. */
export function pictureModel(adj: Adjacency, seeds: readonly string[], cap = PICTURE_CAP, neighbours = false): Model {
  const seedIds = [...new Set(seeds)].filter((id) => adj.nodes.has(id));
  const seedSet = new Set(seedIds);
  const sort = byCaption(adj);
  const itemOf = new Map<string, string>();

  const byLabel = new Map<string, string[]>();
  for (const id of seedIds) {
    const label = primaryLabel(adj.nodes.get(id)!);
    byLabel.set(label, [...(byLabel.get(label) ?? []), id]);
  }
  const seedGroups: Group[] = [];
  let seedSingles: string[] = [];
  for (const [label, ids] of byLabel) {
    if (ids.length >= GROUP_MIN) {
      const g = { id: `s:${label}`, label, ids: [...ids].sort(sort), seed: true };
      seedGroups.push(g);
      ids.forEach((id) => itemOf.set(id, g.id));
    } else seedSingles.push(...ids);
  }
  const seedRoom = Math.max(0, cap - seedGroups.length);
  const cutSeeds = Math.max(0, seedSingles.length - seedRoom);
  seedSingles = seedSingles.slice(0, seedRoom);
  seedSingles.forEach((id) => itemOf.set(id, id));

  const links = new Map<string, Set<string>>();
  for (const s of neighbours ? seedIds : []) {
    const box = itemOf.get(s);
    if (box === undefined) continue;
    for (const edge of adj.edges.get(s) ?? []) {
      if (seedSet.has(edge.other)) continue;
      const set = links.get(edge.other) ?? new Set<string>();
      set.add(`${box}|${edge.rel.type}`);
      links.set(edge.other, set);
    }
  }
  const byKey = new Map<string, Group>();
  for (const [id, set] of links) {
    const label = primaryLabel(adj.nodes.get(id)!);
    const key = `${label}|${[...set].sort().join(",")}`;
    const g = byKey.get(key) ?? { id: `g:${key}`, label, ids: [], seed: false };
    g.ids.push(id);
    byKey.set(key, g);
  }
  const groups: Group[] = [];
  const singles: string[] = [];
  for (const g of byKey.values()) {
    // seeds over the cap: no neighbours at all
    if (g.ids.length >= GROUP_MIN && cutSeeds === 0) groups.push({ ...g, ids: [...g.ids].sort(sort) });
    else singles.push(...g.ids);
  }
  singles.sort((a, b) => links.get(b)!.size - links.get(a)!.size || sort(a, b));
  const room = Math.max(0, cap - seedSingles.length - seedGroups.length - groups.length);
  const shown = cutSeeds > 0 ? [] : singles.slice(0, room);
  shown.forEach((id) => itemOf.set(id, id));
  groups.forEach((g) => g.ids.forEach((id) => itemOf.set(id, g.id)));
  return { seedIds, seedSet, seedSingles, seedGroups, singles: shown, groups, itemOf, hidden: cutSeeds + singles.length - shown.length };
}

/** The node ids that the picture of these seeds draws, in a box or in a group. */
export function drawnIds(adj: Adjacency, seeds: readonly string[], cap = PICTURE_CAP, neighbours = false): Set<string> {
  return new Set(pictureModel(adj, seeds, cap, neighbours).itemOf.keys());
}

export interface PictureItem {
  id: string;
  kind: "node" | "group";
  seed: boolean;
  /** The band: 1 for each layer and seed or neighbour, in LAYERS order. */
  col: number;
  /** The line of boxes. Top down, a band can have more lines; left to right, the line is the band. */
  line: number;
  x: number;
  y: number;
  h: number;
  label: string;
  layer: string;
  slot: number;
  /** node: the cut caption. group: the count and the label. */
  caption: string;
  /** node: the full caption. */
  full: string;
  /** node: a second line when another drawn box has the same caption. */
  second?: string;
  /** group: the node ids, by caption. */
  members?: string[];
  open?: boolean;
}

export interface PictureEdge {
  id: string;
  from: string;
  to: string;
  type: string;
  count: number;
  d: string;
  /** The middle of the curve, for the label. */
  lx: number;
  ly: number;
}

export interface Picture {
  dir: PictureDir;
  items: PictureItem[];
  edges: PictureEdge[];
  /** The layer names: centred above the columns (lr), or at the left above the first band (tb). */
  layers: { name: string; x: number; y: number; anchor: "middle" | "start" }[];
  width: number;
  height: number;
  seedCount: number;
  neighbourCount: number;
  hidden: number;
  itemOf: Map<string, string>;
}

/** A second line for a box: the owner, else the address, else the end of the uid. */
function secondLine(adj: Adjacency, id: string): string {
  const edges = adj.edges.get(id) ?? [];
  const owner = edges.find((e) => e.direction === "in" && e.rel.type.startsWith("HAS_"));
  if (owner) return captionFull(adj.nodes.get(owner.other)!);
  const ip = edges.find((e) => e.direction === "out" && e.rel.type === "HAS_IP");
  if (ip) return captionFull(adj.nodes.get(ip.other)!);
  const uid = adj.nodes.get(id)!.properties.uid;
  const text = typeof uid === "string" && uid ? uid : id;
  return text.length > 14 ? `...${text.slice(-14)}` : text;
}

export function picture(
  adj: Adjacency,
  seeds: readonly string[],
  slotOf: (label: string) => number,
  openGroups: ReadonlySet<string> = new Set(),
  cap = PICTURE_CAP,
  layout: { dir?: PictureDir; width?: number; neighbours?: boolean } = {},
): Picture {
  const dir = layout.dir ?? "tb";
  const m = pictureModel(adj, seeds, cap, layout.neighbours ?? false);
  const slot = (label: string) => {
    const s = slotOf(label);
    return s < SLOT_COUNT ? s : OTHER_SLOT;
  };
  const nodeIds = [...m.seedSingles, ...m.singles];
  const captions = new Map<string, number>();
  for (const id of nodeIds) {
    const c = captionFull(adj.nodes.get(id)!);
    captions.set(c, (captions.get(c) ?? 0) + 1);
  }
  const items: PictureItem[] = [];
  const nodeBox = (id: string, seed: boolean) => {
    const node = adj.nodes.get(id)!;
    const full = captionFull(node);
    const dup = (captions.get(full) ?? 0) > 1;
    const label = primaryLabel(node);
    items.push({
      id, kind: "node", seed, col: 0, line: 0, x: 0, y: 0, h: dup ? BOX_H2 : BOX_H, label, layer: layerOf(node), slot: slot(label),
      caption: cutMiddle(full, CAPTION_CUT), full, second: dup ? cutMiddle(secondLine(adj, id), CAPTION_CUT + 1) : undefined,
    });
  };
  const groupBox = (g: Group) => {
    const open = openGroups.has(g.id);
    const lines = Math.min(MEMBER_MAX, g.ids.length) + (g.ids.length > MEMBER_MAX ? 1 : 0);
    items.push({
      id: g.id, kind: "group", seed: g.seed, col: 0, line: 0, x: 0, y: 0, h: open ? BOX_H2 + lines * MEMBER_H + 6 : BOX_H2,
      label: g.label, layer: layerOf(adj.nodes.get(g.ids[0])!), slot: slot(g.label),
      caption: `${g.ids.length} ${g.label}`, full: `${g.ids.length} ${g.label}`, members: g.ids, open,
    });
  };
  m.seedSingles.forEach((id) => nodeBox(id, true));
  m.singles.forEach((id) => nodeBox(id, false));
  m.seedGroups.forEach(groupBox);
  m.groups.forEach(groupBox);

  // columns: for each layer, the seeds, then the neighbours
  const cols: PictureItem[][] = [];
  const colLayer: string[] = [];
  for (const layer of [...LAYERS, OTHER_LANE]) {
    for (const seed of [true, false]) {
      const list = items
        .filter((it) => it.layer === layer && it.seed === seed)
        .sort((a, b) => (a.kind === b.kind ? 0 : a.kind === "group" ? 1 : -1) || a.slot - b.slot || a.full.localeCompare(b.full) || a.id.localeCompare(b.id));
      if (list.length > 0) {
        cols.push(list);
        colLayer.push(layer);
      }
    }
  }
  const layers: Picture["layers"] = [];
  let width = 0;
  let height = 0;
  if (dir === "tb") {
    // each band is a row of boxes that wraps at the width; the lines are centred
    const avail = Math.max(BOX_W + 2 * PAD, (layout.width ?? DEFAULT_WIDTH) - 4);
    const perLine = Math.max(1, Math.floor((avail - 2 * PAD + GAP_X) / (BOX_W + GAP_X)));
    width = cols.length === 0 ? 0 : 2 * PAD + Math.min(perLine, Math.max(...cols.map((l) => l.length))) * (BOX_W + GAP_X) - GAP_X;
    let y = 4;
    let line = 0;
    cols.forEach((list, ci) => {
      if (colLayer[ci] !== colLayer[ci - 1]) {
        layers.push({ name: colLayer[ci], x: PAD, y: y + 11, anchor: "start" });
        y += LAYER_HEAD;
      }
      for (let i = 0; i < list.length; i += perLine) {
        const part = list.slice(i, i + perLine);
        let x = (width - (part.length * (BOX_W + GAP_X) - GAP_X)) / 2;
        for (const it of part) {
          Object.assign(it, { col: ci, line, x, y });
          x += BOX_W + GAP_X;
        }
        y += Math.max(...part.map((it) => it.h)) + LINE_GAP;
        line += 1;
      }
      y += BAND_GAP - LINE_GAP;
    });
    // room under the last line for an arc between 2 of its boxes
    height = cols.length === 0 ? 0 : y - BAND_GAP + 30;
  } else {
    const colH = cols.map((list) => list.reduce((s, it) => s + it.h + ROW_GAP, -ROW_GAP));
    const maxH = Math.max(0, ...colH);
    cols.forEach((list, ci) => {
      let y = HEAD + (maxH - colH[ci]) / 2;
      const x = PAD + ci * (BOX_W + COL_GAP);
      for (const it of list) {
        Object.assign(it, { col: ci, line: ci, x, y });
        y += it.h + ROW_GAP;
      }
    });
    colLayer.forEach((name, ci) => {
      const x = PAD + ci * (BOX_W + COL_GAP) + BOX_W / 2;
      const last = layers[layers.length - 1];
      if (last?.name === name) last.x = (last.x + x) / 2;
      else layers.push({ name, x, y: 14, anchor: "middle" });
    });
    width = cols.length === 0 ? 0 : PAD * 2 + cols.length * (BOX_W + COL_GAP) - COL_GAP + LOOP;
    height = cols.length === 0 ? 0 : HEAD + maxH + PAD;
  }
  const curve = dir === "tb" ? curveDown : curveAcross;

  const at = new Map(items.map((it) => [it.id, it]));
  const pairs = new Map<string, PictureEdge>();
  const seen = new Set<string>();
  for (const s of m.seedIds) {
    for (const edge of adj.edges.get(s) ?? []) {
      if (seen.has(edge.rel.id)) continue;
      seen.add(edge.rel.id);
      const a = m.itemOf.get(edge.rel.start);
      const b = m.itemOf.get(edge.rel.end);
      if (a === undefined || b === undefined || a === b) continue;
      const key = `${[a, b].sort().join("~")}~${edge.rel.type}`;
      const found = pairs.get(key);
      if (found) found.count += 1;
      else pairs.set(key, { id: key, from: a, to: b, type: edge.rel.type, count: 1, ...curve(at.get(a)!, at.get(b)!) });
    }
  }
  const neighbourCount = m.singles.length + m.groups.reduce((s, g) => s + g.ids.length, 0);
  return {
    dir, items, edges: [...pairs.values()], layers, width, height,
    seedCount: m.seedIds.length, neighbourCount, hidden: m.hidden, itemOf: m.itemOf,
  };
}

/** Top down: from the bottom of the upper box to the top of the lower box. 2 boxes
 *  on 1 line get an arc under them. The label point is 4 px under the text base. */
function curveDown(p: PictureItem, q: PictureItem): { d: string; lx: number; ly: number } {
  const [a, b] = p.y < q.y || (p.y === q.y && p.x <= q.x) ? [p, q] : [q, p];
  const x1 = a.x + BOX_W / 2;
  const x2 = b.x + BOX_W / 2;
  if (a.line === b.line) {
    const base = a.y + Math.max(a.h, b.h);
    const bend = base + 14 + Math.min(10, (x2 - x1) / 30);
    return { d: `M${x1},${a.y + a.h} C${x1},${bend} ${x2},${bend} ${x2},${b.y + b.h}`, lx: (x1 + x2) / 2, ly: base + (bend - base) * 0.75 + 8 };
  }
  const y1 = a.y + a.h;
  const y2 = b.y;
  const my = (y1 + y2) / 2;
  return { d: `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`, lx: (x1 + x2) / 2 + 4, ly: my + 7 };
}

/** Left to right: from the right side of the left box to the left side of the
 *  right box. 2 boxes in 1 column get a loop out to the right. */
function curveAcross(a: PictureItem, b: PictureItem): { d: string; lx: number; ly: number } {
  const ya = a.y + Math.min(a.h, BOX_H2) / 2;
  const yb = b.y + Math.min(b.h, BOX_H2) / 2;
  if (a.col === b.col) {
    const x = a.x + BOX_W;
    const bend = x + 16 + Math.min(14, Math.abs(ya - yb) / 8);
    return { d: `M${x},${ya} C${bend},${ya} ${bend},${yb} ${x},${yb}`, lx: bend + 2, ly: (ya + yb) / 2 };
  }
  const [l, r, yl, yr] = a.col < b.col ? [a, b, ya, yb] : [b, a, yb, ya];
  const x1 = l.x + BOX_W;
  const x2 = r.x;
  const dx = (x2 - x1) / 2;
  return { d: `M${x1},${yl} C${x1 + dx},${yl} ${x2 - dx},${yr} ${x2},${yr}`, lx: (x1 + x2) / 2, ly: (yl + yr) / 2 };
}

/** The middle of a box on the axis along a line: x top down, y left to right. */
const along = (pic: Picture, n: PictureItem) => (pic.dir === "tb" ? n.x + BOX_W / 2 : n.y + n.h / 2);

/** The box in the line before or after the line of `id`, nearest along the line.
 *  Top down: the line above or below. Left to right: the column at the left or right. */
export function sideStep(pic: Picture, id: string, dir: -1 | 1): string | null {
  const from = pic.items.find((n) => n.id === id);
  if (!from) return null;
  const line = pic.items.filter((n) => n.line === from.line + dir);
  if (line.length === 0) return null;
  const c = along(pic, from);
  return line.reduce((best, n) => (Math.abs(along(pic, n) - c) < Math.abs(along(pic, best) - c) ? n : best)).id;
}

/** The box before or after `id` in its line. Top down: at the left or right.
 *  Left to right: above or below. */
export function laneStep(pic: Picture, id: string, dir: -1 | 1): string | null {
  const from = pic.items.find((n) => n.id === id);
  if (!from) return null;
  const line = pic.items.filter((n) => n.line === from.line).sort((a, b) => along(pic, a) - along(pic, b));
  const i = line.findIndex((n) => n.id === id);
  return line[i + dir]?.id ?? null;
}

/**
 * The silhouette of a slot as an SVG path in a `size` square, the same 8
 * shapes as `SHAPES` in graphStyle.ts. The picture, the tree and the legend use
 * it, so a label reads the same in every view. Past the eighth slot, a circle;
 * the caller draws it dashed.
 */
export function shapePath(slot: number, size: number): string {
  const s = size;
  const c = s / 2;
  const f = (n: number) => Math.round(n * 100) / 100;
  const poly = (pts: [number, number][]) => `M${pts.map(([x, y]) => `${f(x)},${f(y)}`).join(" L")} Z`;
  switch (slot) {
    case 1: {
      const r = s * 0.22;
      return `M${f(r)},0 H${f(s - r)} Q${s},0 ${s},${f(r)} V${f(s - r)} Q${s},${s} ${f(s - r)},${s} H${f(r)} Q0,${s} 0,${f(s - r)} V${f(r)} Q0,0 ${f(r)},0 Z`;
    }
    case 2:
      return poly([[c, 0], [s, c], [c, s], [0, c]]);
    case 3:
      return poly([[c, 0], [s, s], [0, s]]);
    case 4: {
      const pts: [number, number][] = [];
      for (let i = 0; i < 10; i++) {
        const r = i % 2 === 0 ? c : c * 0.45;
        const a = -Math.PI / 2 + (i * Math.PI) / 5;
        pts.push([c + r * Math.cos(a), c + r * Math.sin(a)]);
      }
      return poly(pts);
    }
    case 5: {
      const pts: [number, number][] = [];
      for (let i = 0; i < 6; i++) {
        const a = (i * Math.PI) / 3;
        pts.push([c + c * Math.cos(a), c + c * Math.sin(a)]);
      }
      return poly(pts);
    }
    case 6:
      return poly([[s * 0.28, 0], [s, 0], [s * 0.72, s], [0, s]]);
    case 7:
      return poly([[0, 0], [c, s * 0.38], [s, 0], [c, s]]);
    default:
      return `M0,${f(c)} A${f(c)},${f(c)} 0 1,0 ${s},${f(c)} A${f(c)},${f(c)} 0 1,0 0,${f(c)} Z`;
  }
}
