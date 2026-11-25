/**
 * Where the port tags of the cables sit, without a DOM.
 *
 * A cable is a straight line between the centres of two device symbols, and
 * its port tag at each end is a label on that line (`source-label` and
 * `target-label`), along the line or level. Each tag gets the distance at
 * which it starts outside the box of its device
 * (the symbol and the caption under it) and clear of every tag placed before
 * it, the device boxes and the boxes the caller names (the segment bars and
 * their tags). Tags are placed in cable order, so the same drawing gives the
 * same tags.
 *
 * When no distance on the line clears a tag, the tag drops the interface
 * address and keeps the port name, then takes the short form of the name
 * ("Te1/0/12" for "TenGigabitEthernet1/0/12"); when that still collides, it
 * moves to the side of the line. Cables between the same two devices are
 * drawn as parallel lines, a tag's height apart, so their tags never share
 * a line.
 */

import type { TopologyModel } from "../api/types";
import type { Point } from "./layout";
import type { Box, Measure } from "./segrow";

/** The cable tags in style.ts: 9 px text with 2 px padding. */
export const CABLE_TAG_FONT = 9;
const TAG_PAD = 3;
const TAG_H = Math.ceil(CABLE_TAG_FONT * 1.25 + 2 * TAG_PAD);
/** The room a tag keeps from a box and from another tag. */
const GAP = 4;
/** The step a tag moves along its line when it collides. */
const STEP = 3;
/** Past this many steps from its first place at one end, a tag is dropped. */
const MAX_STEPS = 80;
/** The side of a cell of the grid that holds the boxes a tag keeps clear of. */
const CELL = 64;
/** The distance between two parallel cables. */
export const PARALLEL_GAP = TAG_H + 4;
/** The half size of a device symbol (style.ts `SYMBOL_WIDTH`, layout.ts `DEVICE_HEIGHT`). */
const SYMBOL_HALF = { x: 27, y: 20 };

export interface TagLook {
  ports: boolean;
  addresses: boolean;
  along: boolean;
}

export interface CableEnds {
  id: string;
  source: string;
  target: string;
  /** the port names, and the tags with the interface address */
  sourcePort: string;
  targetPort: string;
  sourceTag: string;
  targetTag: string;
}

export interface TagPlace {
  sourceLabel: string;
  targetLabel: string;
  /** the distance of the tag's centre from the end of the line, as Cytoscape takes it */
  sourceOffset: number;
  targetOffset: number;
  /** a shift of the tag off the line, in drawing coordinates */
  sourceMargin: Point;
  targetMargin: Point;
  /** the ends of a parallel cable, from the device centres (`source-endpoint`) */
  sourceEndpoint: string | null;
  targetEndpoint: string | null;
  /** the box each tag takes, with its margin of room */
  sourceBox: Quad | null;
  targetBox: Quad | null;
}

/** An oriented box: a centre, the unit axis along its width, and the half sizes. */
export interface Quad {
  c: Point;
  u: Point;
  hw: number;
  hh: number;
}

/**
 * Boxes on a uniform grid. A query meets only the boxes that share a cell with the query box.
 */
export class Grid {
  private readonly cells = new Map<string, Quad[]>();

  /** The keys of the cells the axis-aligned bounds of `q` touch. */
  private keys(q: Quad): string[] {
    const ex = q.hw * Math.abs(q.u.x) + q.hh * Math.abs(q.u.y);
    const ey = q.hw * Math.abs(q.u.y) + q.hh * Math.abs(q.u.x);
    const out: string[] = [];
    // a box that is not finite overlaps nothing (`overlaps` compares against NaN)
    if (![q.c.x, q.c.y, ex, ey].every(Number.isFinite)) return out;
    for (let x = Math.floor((q.c.x - ex) / CELL); x <= Math.floor((q.c.x + ex) / CELL); x++) {
      for (let y = Math.floor((q.c.y - ey) / CELL); y <= Math.floor((q.c.y + ey) / CELL); y++) out.push(`${x},${y}`);
    }
    return out;
  }

  add(q: Quad): void {
    for (const key of this.keys(q)) {
      const cell = this.cells.get(key);
      if (cell) cell.push(q);
      else this.cells.set(key, [q]);
    }
  }

  remove(q: Quad): void {
    for (const key of this.keys(q)) {
      const cell = this.cells.get(key);
      const at = cell ? cell.indexOf(q) : -1;
      if (cell && at >= 0) cell.splice(at, 1);
    }
  }

  /** Whether `q` overlaps a box on the grid. */
  hits(q: Quad): boolean {
    return this.keys(q).some((key) => this.cells.get(key)?.some((o) => overlaps(q, o)) ?? false);
  }
}

/** An axis-aligned box from its corners. */
export interface Rect {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

const quadOfRect = (r: Rect): Quad => ({
  c: { x: (r.x0 + r.x1) / 2, y: (r.y0 + r.y1) / 2 },
  u: { x: 1, y: 0 },
  hw: (r.x1 - r.x0) / 2,
  hh: (r.y1 - r.y0) / 2,
});

/** Whether two oriented boxes overlap (separating axes). */
export function overlaps(a: Quad, b: Quad): boolean {
  const axes = [a.u, { x: -a.u.y, y: a.u.x }, b.u, { x: -b.u.y, y: b.u.x }];
  const d = { x: b.c.x - a.c.x, y: b.c.y - a.c.y };
  const extent = (q: Quad, n: Point) =>
    q.hw * Math.abs(q.u.x * n.x + q.u.y * n.y) +
    q.hh * Math.abs(-q.u.y * n.x + q.u.x * n.y);
  return axes.every(
    (n) => Math.abs(d.x * n.x + d.y * n.y) < extent(a, n) + extent(b, n),
  );
}

/** The distance along `u` from `p` at which the ray leaves the box `r` (0 when it starts outside). */
function exitDistance(p: Point, u: Point, r: Rect): number {
  let t0 = -Infinity;
  let t1 = Infinity;
  for (const [pc, uc, lo, hi] of [
    [p.x, u.x, r.x0, r.x1],
    [p.y, u.y, r.y0, r.y1],
  ] as const) {
    if (Math.abs(uc) < 1e-9) {
      if (pc < lo || pc > hi) return 0;
      continue;
    }
    const a = (lo - pc) / uc;
    const b = (hi - pc) / uc;
    t0 = Math.max(t0, Math.min(a, b));
    t1 = Math.min(t1, Math.max(a, b));
  }
  return t1 >= Math.max(t0, 0) ? t1 : 0;
}

/** The box of a device around the centre of its symbol: the symbol, and the caption under it. */
export function deviceRect(at: Point, box: Box): Rect {
  const top = at.y - SYMBOL_HALF.y;
  return {
    x0: at.x - box.width / 2,
    x1: at.x + box.width / 2,
    y0: top,
    y1: top + box.height,
  };
}

const symbolRect = (at: Point): Rect => ({
  x0: at.x - SYMBOL_HALF.x,
  x1: at.x + SYMBOL_HALF.x,
  y0: at.y - SYMBOL_HALF.y,
  y1: at.y + SYMBOL_HALF.y,
});

const round = (v: number) => Math.round(v * 100) / 100;

/**
 * The tags of every straight cable. `at` holds the centre of each device
 * symbol, `boxes` the box of each device, `obstacles` the other boxes a tag
 * keeps clear of. A cable whose device is not drawn gets no tag.
 */
export function placeTags(
  cables: CableEnds[],
  at: ReadonlyMap<string, Point>,
  boxes: ReadonlyMap<string, Box>,
  measure: Measure,
  look: TagLook,
  obstacles: Rect[] = [],
): Map<string, TagPlace> {
  const out = new Map<string, TagPlace>();
  const devices = new Map<string, Rect>();
  for (const [id, p] of at) {
    const box = boxes.get(id);
    if (box) devices.set(id, deviceRect(p, box));
  }
  // the boxes a tag keeps clear of, and the tags placed so far
  const grid = new Grid();
  for (const rect of [...devices.values(), ...obstacles]) grid.add(quadOfRect(rect));
  // cables between one pair of devices are parallel lines, in id order
  const pairs = new Map<string, CableEnds[]>();
  for (const c of [...cables].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  )) {
    const key = [c.source, c.target].sort().join("~");
    pairs.set(key, [...(pairs.get(key) ?? []), c]);
  }
  for (const group of pairs.values()) {
    group.forEach((c, index) => {
      const a = at.get(c.source);
      const b = at.get(c.target);
      if (!a || !b) return;
      // the shift of a parallel line, on the normal of the pair in a fixed order
      const [first, second] = c.source < c.target ? [a, b] : [b, a];
      const len = Math.hypot(second.x - first.x, second.y - first.y) || 1;
      const normal = {
        x: -(second.y - first.y) / len,
        y: (second.x - first.x) / len,
      };
      const shift = (index - (group.length - 1) / 2) * PARALLEL_GAP;
      const off = { x: normal.x * shift, y: normal.y * shift };
      const s = { x: a.x + off.x, y: a.y + off.y };
      const t = { x: b.x + off.x, y: b.y + off.y };
      out.set(
        c.id,
        placeCable(
          c,
          s,
          t,
          group.length > 1 ? off : null,
          devices,
          grid,
          measure,
          look,
        ),
      );
    });
  }
  return out;
}

function placeCable(
  c: CableEnds,
  s: Point,
  t: Point,
  shift: Point | null,
  devices: Map<string, Rect>,
  grid: Grid,
  measure: Measure,
  look: TagLook,
): TagPlace {
  const length = Math.hypot(t.x - s.x, t.y - s.y);
  const u = length
    ? { x: (t.x - s.x) / length, y: (t.y - s.y) / length }
    : { x: 1, y: 0 };
  const back = { x: -u.x, y: -u.y };
  const n = { x: -u.y, y: u.x };
  // the line leaves each symbol here: Cytoscape measures a tag's distance from that point
  const sStart = exitDistance(s, u, symbolRect(sub(s, shift)));
  const tStart = exitDistance(t, back, symbolRect(sub(t, shift)));
  const sBox = devices.get(c.source);
  const tBox = devices.get(c.target);
  const result: TagPlace = {
    sourceLabel: "",
    targetLabel: "",
    sourceOffset: 0,
    targetOffset: 0,
    sourceMargin: { x: 0, y: 0 },
    targetMargin: { x: 0, y: 0 },
    sourceEndpoint: shift
      ? `${round(shift.x + u.x * sStart)}px ${round(shift.y + u.y * sStart)}px`
      : null,
    targetEndpoint: shift
      ? `${round(shift.x + back.x * tStart)}px ${round(shift.y + back.y * tStart)}px`
      : null,
    sourceBox: null,
    targetBox: null,
  };
  if (!look.ports) return result;
  /** the quad of a tag `text` centred at distance `d` from `from` along `dir`, moved off the line by `side` */
  const quad = (
    from: Point,
    dir: Point,
    d: number,
    w: number,
    side: number,
  ): Quad => {
    const c0 = {
      x: from.x + dir.x * d + n.x * side,
      y: from.y + dir.y * d + n.y * side,
    };
    const hh = side ? TAG_H / 2 + 1 : TAG_H / 2 + GAP / 2;
    return { c: c0, u: look.along ? dir : { x: 1, y: 0 }, hw: w / 2 + GAP / 2, hh };
  };
  const clear = (q: Quad) => !grid.hits(q);
  /** the first distance from `from` at which the tag clears everything, before the far end of the line */
  const fit = (from: Point, dir: Point, own: Rect | undefined, w: number, side: number): number | null => {
    const first = (own ? exitDistance(from, dir, own) : 0) + (look.along ? w / 2 : 0);
    for (let k = 0, d = first; k < MAX_STEPS && d + (look.along ? w / 2 : 0) <= length; k++, d += STEP) {
      if (clear(quad(from, dir, d, w, side))) return d;
    }
    return null;
  };
  type End = { from: Point; dir: Point; own: Rect | undefined; start: number; texts: string[] };
  const textsOf = (full: string, port: string) => [...new Set([look.addresses ? full : port, port, shortPort(port)].filter(Boolean))];
  const ends: End[] = [
    { from: s, dir: u, own: sBox, start: sStart, texts: textsOf(c.sourceTag, c.sourcePort) },
    { from: t, dir: back, own: tBox, start: tStart, texts: textsOf(c.targetTag, c.targetPort) },
  ];
  /** the tag of one end on `side` of the line, in the texts from `level` on: the longest that fits, placed */
  const place = (end: End, side: number, level = 0, only = false) => {
    const texts = only ? [end.texts[Math.min(level, end.texts.length - 1)]] : end.texts.slice(Math.min(level, end.texts.length - 1));
    for (const text of texts) {
      const w = measure(text, CABLE_TAG_FONT) + 2 * TAG_PAD + 2;
      const d = fit(end.from, end.dir, end.own, w, side);
      if (d === null) continue;
      const q = quad(end.from, end.dir, d, w, side);
      grid.add(q);
      return { text, offset: round(d - end.start), margin: { x: round(n.x * side) || 0, y: round(n.y * side) || 0 }, q };
    }
    return null;
  };
  // both tags on the line, else side by side off it: on a short cable, or where other tags crowd it
  const half = TAG_H / 2 + 1.5;
  const sides: [number, number][] = [
    [0, 0],
    [-half, half],
    [half, -half],
    [0, half],
    [0, -half],
    [-half, 0],
    [half, 0],
    [-half, -half],
    [half, half],
  ];
  const undo = (p: ReturnType<typeof place>) => {
    if (p) grid.remove(p.q);
  };
  let pair: [ReturnType<typeof place>, ReturnType<typeof place>] = [null, null];
  // each side pair takes the texts in order, both ends at one level (full, port name, short name)
  const levels = Math.max(ends[0].texts.length, ends[1].texts.length);
  search: for (const [sa, sb] of sides) {
    for (let level = 0; level < levels; level++) {
      const a = place(ends[0], sa, level, true);
      const b = a ? place(ends[1], sb, level, true) : null;
      if (a && b) {
        pair = [a, b];
        break search;
      }
      undo(b);
      undo(a);
    }
  }
  // nothing fits both: each end takes what room there is
  const any = (end: End) => place(end, 0) ?? place(end, -half) ?? place(end, half);
  if (!pair[0]) pair = [any(ends[0]), any(ends[1])];
  const [a, b] = pair;
  if (a) Object.assign(result, { sourceLabel: a.text, sourceOffset: a.offset, sourceMargin: a.margin, sourceBox: a.q });
  if (b) Object.assign(result, { targetLabel: b.text, targetOffset: b.offset, targetMargin: b.margin, targetBox: b.q });
  return result;
}

/** The short forms of the long interface names, as the platforms print them. */
const SHORT: [RegExp, string][] = [
  [/^HundredGig(?:abit)?E(?:thernet)?/i, "Hu"],
  [/^FortyGig(?:abit)?E(?:thernet)?/i, "Fo"],
  [/^TwentyFiveGig(?:abit)?E(?:thernet)?/i, "Twe"],
  [/^TenGig(?:abit)?E(?:thernet)?/i, "Te"],
  [/^GigabitEthernet/i, "Gi"],
  [/^FastEthernet/i, "Fa"],
  [/^Ethernet/i, "Eth"],
  [/^Port-channel/i, "Po"],
];

/** "Te1/0/12" for "TenGigabitEthernet1/0/12"; any other name as it is. */
export function shortPort(port: string): string {
  for (const [long, short] of SHORT) if (long.test(port)) return port.replace(long, short);
  return port;
}

const sub = (p: Point, shift: Point | null) =>
  shift ? { x: p.x - shift.x, y: p.y - shift.y } : p;

/** The room ELK keeps between two devices in one layer (layout.ts `elk.spacing.nodeNode`). */
const NODE_SPACING = 56;

/**
 * The device boxes the layout takes: the box of each device, wider for a
 * device with a lateral cable (a peer-link, a sync link), so the gap between
 * the two ends holds the port tags of both on one line. ELK leaves lateral
 * cables out of the layout and so keeps no room for them.
 */
export function layoutBoxes(model: TopologyModel, boxes: ReadonlyMap<string, Box>, measure: Measure): Map<string, Box> {
  const out = new Map(boxes);
  const room = (port: string | null) => (port ? measure(shortPort(port), CABLE_TAG_FONT) + 2 * TAG_PAD + 2 : 0);
  for (const c of model.cables) {
    if (!c.lateral) continue;
    const needed = room(c.from.port) + room(c.to.port) + 5 * GAP;
    const extra = Math.max(0, (needed - NODE_SPACING) / 2);
    for (const dev of [c.from.dev, c.to.dev]) {
      const box = boxes.get(dev);
      const now = out.get(dev);
      if (box && now) out.set(dev, { ...now, width: Math.max(now.width, Math.ceil(box.width + 2 * extra)) });
    }
  }
  return out;
}
