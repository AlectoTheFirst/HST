import { LEVEL_ZOOM, onScreen, toPlane, toScreen, zoomOf } from "./camera";
import {
  PALETTES,
  TINT_FILL,
  countClass,
  speedClass,
  tintOf,
  type Palette,
} from "./style";
import { MODELS, round } from "./models";
import { symbolOf, type SymbolName } from "./symbols";
import { wire, type Footprint, type Socket, type Wiring } from "./wiring";
import {
  DEFAULT_STYLE,
  keyOf,
  type CameraState,
  type ElementChange,
  type Label,
  type Level,
  type Marker,
  type Row,
  type Route,
  type Style,
  type TableName,
  type Viewport,
} from "./types";

export interface Placement {
  uid: string;
  kind: string;
  parent: string | null;
  u: number;
  v: number;
  w: number;
  h: number;
  side: string | null;
  slot: number | null;
  points: [number, number][] | null;
}

export type BoxClass =
  | "plate"
  | "band"
  | "bracket"
  | "device"
  | "context"
  | "tier"
  | "port"
  | "glyph"
  | "node"
  | "dot"
  | "segment";
export type LineClass =
  "site-link" | "bundle" | "summary" | "cable" | "tunnel" | "circuit" | "outline";

/** Instances of one element class. `data` holds u, y, v, w, height, h per instance; `colors` r, g, b.
 *  A `proxy` batch is not drawn: it is the pick and label footprint of elements another batch draws. */
export interface BoxBatch {
  cls: BoxClass;
  ids: string[];
  data: number[];
  colors: number[];
  proxy?: boolean;
}

/** Device models of one symbol. `data` holds u, y, v, w, height, h per instance like a box; `colors` r, g, b. */
export interface ModelBatch {
  name: SymbolName;
  ids: string[];
  data: number[];
  colors: number[];
}

/** Line segments of one class. `positions` holds two x, y, z vertices per segment, `colors` one rgb per vertex. */
export interface LineBatch {
  cls: LineClass;
  key: string;
  ids: string[];
  positions: number[];
  colors: number[];
}

/** Device symbols of one kind, flat on the top face. `data` holds u, y, v, size per instance; `colors` r, g, b. */
export interface SymbolBatch {
  name: SymbolName;
  ids: string[];
  data: number[];
  colors: number[];
}

/** Soft rounded areas under the plates and bands. `data` holds u, v, w, h per area; `colors` the tint r, g, b;
 *  `kinds` 0 for a plate, 1 for a band, 2 for a country block; `selected` 1 for the selected area. */
export interface AreaBatch {
  ids: string[];
  data: number[];
  colors: number[];
  kinds: number[];
  selected: number[];
}

/** A name painted on the ground: it runs along +u from its foot at (u, v), its letters `size` grid cells tall towards
 *  -v, and it shows between `minZoom` and `maxZoom`, where its letters read on the screen. A site name is `strong`. */
export interface GroundText {
  id: string;
  text: string;
  u: number;
  v: number;
  size: number;
  minZoom: number;
  maxZoom: number;
  strong: boolean;
}

/** `outlines` are the glows under the backbone and around the selected area, apart from the network lines. */
export interface Batches {
  areas: AreaBatch;
  boxes: BoxBatch[];
  lines: LineBatch[];
  outlines: LineBatch[];
  symbols: SymbolBatch[];
  models: ModelBatch[];
  texts: GroundText[];
}

/** The letter heights in pixels between which a ground name shows, the screen length of one grid cell along v per
 *  unit of zoom, and the width of a letter per unit of its height. */
export const NAME_PX = { min: 10, max: 200 } as const;
const ISO_V = Math.sqrt(1 / 2 + 1 / 6);
export const NAME_CHAR = 0.62;
/** The tallest ground name of a top-level box, in the gap above it, and of a box inside a site group. */
const NAME_ROOM = { top: 12, nested: 4.5 } as const;

/** The world height of each layer. */
export const Y = {
  plateTop: 0.08,
  bandTop: 0.14,
  bracketTop: 0.18,
  deviceTop: 0.48,
  portTop: 0.3,
  cable: 0.2,
  bundle: 0.3,
  summary: 0.2,
  siteLink: 0.5,
  route: 1.6,
  glyph: 6,
} as const;

/** The fewest segments of one tunnel arc; a longer arc takes one segment per dash step. */
export const ARC_STEPS = 48;
/** The screen length of one dash step at the lowest zoom of a level, in pixels. */
export const DASH_STEP_PX = 5;
const MAX_ARC_STEPS = 1200;
/** The length of the stub of a link to another site, in grid cells: from the device centre at block zoom, from the
 *  socket at port zoom. */
const STUB = 6;
const PORT_STUB = 3;
/** The side of the dot that ends a cable on a device that is not selected, and of the dot of a port of the selected
 *  device and of the far ends of its cables, in grid cells. */
const END_DOT = 0.3;
const PORT_DOT = 0.45;
/** The pick distance of a line, in pixels. */
export const LINE_PICK_PX = 8;
/** The share of the shorter slab side the symbol takes. */
const SYMBOL_SHARE = 0.72;
/** The device tiers drawn as models at site zoom; the other devices of a block collapse into its cluster. */
export const KEY_TIERS: ReadonlySet<string> = new Set([
  "core",
  "distribution",
  "internet-edge",
  "wan-edge",
  "firewall",
  "sdwan-hub",
  "sdwan-edge",
  "spine",
]);
/** The side of a backbone midpoint node, in grid cells. */
const NODE_SIZE = 1.2;
/** The side of the dot node on a device pair line, in grid cells. */
const DOT_SIZE = 0.5;
/** The screen height of a card label: the chip, the padding and the border of `.hst-card` in hst.css. */
const CARD_HEIGHT_PX = 48;
/** How far a card sits above its anchor point. */
export const CARD_LIFT_PX = 34;
/** The width of `.hst-card` without its text: the padding, the chip, the column gap and the border. */
export const CARD_FIXED_PX = 66;

export const CONTEXT_CAP = 16;
export const LABEL_BUDGET = {
  device: 300,
  port: 200,
  tunnel: 200,
  count: 200,
} as const;
/** The estimated screen size of a label, for the overlap test of port labels. */
export const LABEL_CHAR_PX = 6.5;
export const LABEL_PAD_PX = 8;
export const LABEL_HEIGHT_PX = 14;
/** The share of the font size one character takes, from `LABEL_CHAR_PX` at the 11 px label font. */
const CHAR_EM = LABEL_CHAR_PX / 11;
/** A character of the 13 px card title. */
export const CARD_TITLE_CHAR_PX = 13 * CHAR_EM;
/** `.hst-label-cluster` and `.hst-label-stub`: a 10 px character, and the padding and the border. */
const PILL_CHAR_PX = 10 * CHAR_EM;
const PILL_PAD_PX = 18;
const PILL_HEIGHT_PX = 18;
/** The planner's block of the sites whose code and hostnames name no country, its block of the cloud sites, and its
 *  block of the CNC sites. */
const OTHER_REGION = "region:other";
const CLOUD_REGION = "region:cloud";
const CORE_REGION = "region:core";
/** A site group of the planner, or one of CNC sites only, and the site of the Fabric spine of a metro. */
const GROUP = /^region:(group|core):/;
const SPINE_PREFIX = "site:EQUINIX-FABRIC-";

export function regionName(region: string): string {
  if (region === OTHER_REGION) return "Other";
  if (region === CLOUD_REGION) return "Cloud";
  if (region === CORE_REGION) return "Core";
  if (GROUP.test(region)) return region.replace(GROUP, "").split(" / ").pop() ?? region;
  return region.replace(/^region:/, "");
}

/** The core block, the cloud block and the site groups of CNC sites hold the backbone of the estate. */
function backboneRegion(region: string): boolean {
  return region === CORE_REGION || region === CLOUD_REGION || region.startsWith(`${CORE_REGION}:`);
}

/** The light palette, which the default style draws with. */
export const PALETTE = PALETTES.light;

const GHOST_MIX = 0.72;
const DIM_MIX = 0.55;

export function rgb(hex: number): [number, number, number] {
  return [
    ((hex >> 16) & 255) / 255,
    ((hex >> 8) & 255) / 255,
    (hex & 255) / 255,
  ];
}

function mix(a: number, b: number, t: number): [number, number, number] {
  const x = rgb(a);
  const y = rgb(b);
  return [
    x[0] + (y[0] - x[0]) * t,
    x[1] + (y[1] - x[1]) * t,
    x[2] + (y[2] - x[2]) * t,
  ];
}

export function placement(row: Row): Placement {
  const points =
    typeof row.points === "string" && row.points
      ? (JSON.parse(row.points) as [number, number][])
      : null;
  return {
    uid: String(row.uid),
    kind: String(row.kind),
    parent: row.parent_uid == null ? null : String(row.parent_uid),
    u: Number(row.u),
    v: Number(row.v),
    w: Number(row.w),
    h: Number(row.h),
    side: row.side == null ? null : String(row.side),
    slot: row.slot == null ? null : Number(row.slot),
    points,
  };
}

interface TableState {
  rows: Map<string, Row>;
  absent: Set<string>;
  /** The keys each loaded tile brought; "" for an untiled table. */
  tiles: Map<string, Set<string>>;
}

/** The selected device draws up to twice the port label budget. */
export const PORT_CAP = 48;
/** How far a port label sits outside its port, away from the device centre, in grid cells. */
const PORT_LABEL_OUT = 1.2;

interface Derived {
  site: Map<string, string | null>;
  block: Map<string, string | null>;
  contexts: Map<string, Row[]>;
  context: {
    devices: Set<string>;
    sites: Set<string>;
    contexts: Set<string>;
  } | null;
  neighbors: Set<string>;
  /** The ports drawn at port zoom: per device the connected ones first, then by name, up to the cap. */
  ports: Set<string>;
  /** The sites that hold a device of `HUB_ROLE`. */
  hubs: Set<string>;
  /** The first plate of each site, by the site uid. */
  plates: Map<string, string>;
  /** The sites of each country block. */
  regions: Map<string, string[]>;
  blocksOf: Map<string, string[]>;
  /** The stubs of the links to other sites, one per device and direction, with the device pairs they carry. */
  stubs: Map<string, { end: [number, number]; items: { pair: string; a: string; b: string; far: string; links: number }[] }>;
}

/** A tunnel line of a focused site or device: an arc to one far end, a bundle to a country block, or the own
 *  block of a hub, which glows and carries the count instead of a line. */
interface Spoke {
  id: string;
  from: [number, number];
  to: [number, number];
  tunnels: number;
  sites: number;
  /** The device pair of an arc between two devices, which draws one arc per transport. */
  pair?: [Row, Placement, Placement];
  local?: string;
}

interface Box {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

function apart(p: Box, q: Box): boolean {
  return p.x1 <= q.x0 || q.x1 <= p.x0 || p.y1 <= q.y0 || q.y1 <= p.y0;
}

/** The screen box a label takes, from its text length. */
export function labelBox(l: Label): Box {
  if (l.sub !== undefined) {
    const w =
      Math.max(l.text.length * CARD_TITLE_CHAR_PX, l.sub.length * LABEL_CHAR_PX) + CARD_FIXED_PX;
    const y = l.y - CARD_LIFT_PX;
    return {
      x0: l.x - w / 2,
      y0: y - CARD_HEIGHT_PX / 2,
      x1: l.x + w / 2,
      y1: y + CARD_HEIGHT_PX / 2,
    };
  }
  const [char, pad, height] =
    l.kind === "cluster" || l.kind === "stub"
      ? [PILL_CHAR_PX, PILL_PAD_PX, PILL_HEIGHT_PX]
      : [LABEL_CHAR_PX, LABEL_PAD_PX, LABEL_HEIGHT_PX];
  const w = l.text.length * char + pad;
  return {
    x0: l.x - w / 2,
    y0: l.y - height / 2,
    x1: l.x + w / 2,
    y1: l.y + height / 2,
  };
}

/** One end of a circuit arc: the drawn element it touches, its point and its height. */
export interface CircuitEnd {
  uid: string;
  at: [number, number];
  y: number;
}

/** A circuit line: the circuits of a site pair or a device pair, which draw as one arc per pair of drawn end
 *  elements, the arc with the most circuits first. */
export interface CircuitLine {
  id: string;
  circuits: Row[];
  arcs: { from: CircuitEnd; to: CircuitEnd }[];
}

/** The point at `t` of a circuit arc from `a` to `b`: one step above a tunnel arc of the same pair, its base rising
 *  from the height of `a` to the height of `b`. */
function circuitAt(a: CircuitEnd, b: CircuitEnd, t: number): [number, number, number] {
  const [u, y, v] = arcAt(a.at, b.at, a.y, 1, t);
  return [u, y + (b.y - a.y) * t, v];
}

/** Whether a device row draws as a model at site zoom. */
export function keyDevice(row: Row | undefined): boolean {
  return (
    row !== undefined &&
    (KEY_TIERS.has(String(row.tier)) || row.role === "firewall")
  );
}

/** The point halfway along a polyline. */
function midpoint(points: [number, number][]): [number, number] {
  const lengths = points
    .slice(1)
    .map((p, i) => Math.hypot(p[0] - points[i][0], p[1] - points[i][1]));
  let rest = lengths.reduce((a, b) => a + b, 0) / 2;
  for (let i = 0; i < lengths.length; i++) {
    if (rest <= lengths[i] && lengths[i] > 0) {
      const t = rest / lengths[i];
      return [
        points[i][0] + (points[i + 1][0] - points[i][0]) * t,
        points[i][1] + (points[i + 1][1] - points[i][1]) * t,
      ];
    }
    rest -= lengths[i];
  }
  return points[points.length - 1];
}

function overlaps(a: Label, b: Label): boolean {
  return !apart(labelBox(a), labelBox(b));
}

/** The labels of `candidates`, in order, that overlap neither `placed` nor each other, at most `budget`. */
export function spread(
  candidates: Label[],
  placed: Label[],
  budget: number,
): Label[] {
  const out: Label[] = [];
  for (const l of candidates) {
    if (out.length >= budget) break;
    if (placed.some((p) => overlaps(l, p)) || out.some((p) => overlaps(l, p)))
      continue;
    out.push(l);
  }
  return out;
}

function center(p: Placement): [number, number] {
  return [p.u + p.w / 2, p.v + p.h / 2];
}

/** The path from `a` to `b` on the iso axes: along the longer axis to the middle, across, and on. */
export function orthogonal(
  a: [number, number],
  b: [number, number],
): [number, number][] {
  const [ua, va] = a;
  const [ub, vb] = b;
  if (ua === ub || va === vb) return [a, b];
  if (Math.abs(ub - ua) >= Math.abs(vb - va)) {
    const mu = (ua + ub) / 2;
    return [a, [mu, va], [mu, vb], b];
  }
  const mv = (va + vb) / 2;
  return [a, [ua, mv], [ub, mv], b];
}

/** The segments of a tunnel arc from `a` to `b` at `level`, one per dash step along the chord within the bounds,
 *  and the dash steps each segment spans. Estate zoom counts its dash at the zoom where site zoom starts. */
function arcDash(a: [number, number], b: [number, number], level: Level): { steps: number; per: number } {
  const zoom = level === 1 ? LEVEL_ZOOM[0] : zoomOf(level);
  const dashes = (Math.hypot(b[0] - a[0], b[1] - a[1]) * zoom) / DASH_STEP_PX;
  const steps = Math.min(MAX_ARC_STEPS, Math.max(ARC_STEPS, Math.ceil(dashes)));
  return { steps, per: dashes / steps };
}

/** The point at `t` of the `k`-th tunnel arc from `a` to `b` at base height `y`: higher for a longer span and for
 *  each further transport. */
function arcAt(a: [number, number], b: [number, number], y: number, k: number, t: number): [number, number, number] {
  const peak = 3 + Math.hypot(b[0] - a[0], b[1] - a[1]) * 0.08 + k * 1.5;
  return [a[0] + (b[0] - a[0]) * t, y + peak * 4 * t * (1 - t), a[1] + (b[1] - a[1]) * t];
}

/** The first `length` cells of the way from `a` towards `b` on the iso axes: the stub of a link to another site. */
export function stubOf(a: [number, number], b: [number, number], length = STUB): [number, number][] {
  const du = b[0] - a[0];
  const dv = b[1] - a[1];
  const [nu, nv] = Math.abs(du) >= Math.abs(dv) ? [Math.sign(du), 0] : [0, Math.sign(dv)];
  return [a, [a[0] + nu * length, a[1] + nv * length]];
}

/** Whether segment `i` of a tunnel arc of encapsulation `encap` is drawn; the gaps make the dash. */
export function dashOn(encap: string | null | undefined, i: number): boolean {
  if (encap === "ipsec") return i % 4 < 3;
  if (encap === "gre") return i % 2 === 0;
  return i % 6 < 4;
}

function segmentDistance(
  px: number,
  py: number,
  ax: number,
  ay: number,
  bx: number,
  by: number,
): number {
  const dx = bx - ax;
  const dy = by - ay;
  const len = dx * dx + dy * dy;
  const t =
    len === 0
      ? 0
      : Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / len));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/** The zoom, in pixels per grid cell, from which port names draw beside their sockets; below it the panel carries them. */
export const PORT_LABEL_ZOOM = 28;
/** A site that holds a device of this role is a hub: its card names the spoke count. */
export const HUB_ROLE = "sdwan-hub";

/** The tunnel line of a site card: the total, or the spoke count of a hub. */
function tunnelText(entry: { total: number; far: Map<string, number> } | undefined, hub: boolean): string | null {
  if (!entry) return null;
  return hub ? `hub of ${entry.far.size} sites, ${entry.total} tunnels` : `${entry.total} tunnels`;
}
/** The segment bar: its depth and its lift above the ground, the tick size, all in grid cells. */
const BAR_DEPTH = 0.18;
const BAR_TICK = 0.14;
const BAR_TICK_H = 0.5;
/** The smallest plane size a port socket answers a pick in, in grid cells. */
const SOCKET_PICK = 0.4;
/** The screen distance from a socket to its label, along its cable. */
const SOCKET_LABEL_PX = 12;
const SOCKET_LABEL_STEPS = 3;

function besideSocket(
  cam: CameraState,
  vp: Viewport,
  s: Socket,
  text: string,
  uid: string,
): Label {
  const ou = s.u + s.nu * s.size;
  const ov = s.v + s.nv * s.size;
  const [x0, y0] = toScreen(cam, vp, ou, ov, Y.portTop);
  const [x1, y1] = toScreen(cam, vp, ou + s.nu, ov + s.nv, Y.portTop);
  const len = Math.hypot(x1 - x0, y1 - y0) || 1;
  const [dx, dy] = [(x1 - x0) / len, (y1 - y0) / len];
  // The label sits on the left of the cable as seen from the socket.
  const [px, py] = [-dy, dx];
  const half = (text.length * LABEL_CHAR_PX + LABEL_PAD_PX) / 2;
  const off = Math.abs(px) * half + Math.abs(py) * (LABEL_HEIGHT_PX / 2) + 3;
  const along = SOCKET_LABEL_PX + (s.index % SOCKET_LABEL_STEPS) * (LABEL_HEIGHT_PX + 2);
  const [x, y] = [x0 + dx * along + px * off, y0 + dy * along + py * off];
  // `at` is the point under (x, y) that the overlap check uses.
  const [u, v] = toPlane(cam, vp, x, y, Y.portTop);
  return { uid, text, x, y, at: [u, Y.portTop, v], kind: "port" };
}

/** Whether `next` differs from `before` in the hovered device alone. */
function hoverOnly(before: Style, next: Style): boolean {
  if (before === next) return true;
  const keys = Object.keys(next) as (keyof Style)[];
  return keys.length === Object.keys(before).length && keys.every((k) => k === "hovered" || next[k] === before[k]);
}

function count(row: Row | undefined, column: string): number {
  return row ? Number(row[column] ?? 0) : 0;
}

/** The map state the backends draw: the layout, the loaded tier rows, the style and the routes. */
export class Scene {
  readonly layout = new Map<string, Placement>();
  style: Style = DEFAULT_STYLE;
  routes: readonly Route[] = [];
  /** Counts every change that redraws the batches: the data, and the style but for the hovered device. */
  version = 0;
  /** Counts the changes of the rows, the layout and the tiles: what the derived data and the wiring read. */
  dataVersion = 0;
  private readonly tables = new Map<TableName, TableState>();
  private batchCache: {
    version: number;
    level: Level;
    batches: Batches;
  } | null = null;
  private derivedCache: { key: string; derived: Derived } | null = null;
  private wiringCache: { key: string; wiring: Wiring } | null = null;

  /** The palette of the style's theme. */
  get p(): Palette {
    return PALETTES[this.style.theme];
  }

  private table(name: TableName): TableState {
    let t = this.tables.get(name);
    if (!t) {
      t = { rows: new Map(), absent: new Set(), tiles: new Map() };
      this.tables.set(name, t);
    }
    return t;
  }

  private touch(): void {
    this.version += 1;
  }

  private touchData(): void {
    this.dataVersion += 1;
    this.touch();
  }

  /** The row of `key` when it is present at t. */
  row(name: TableName, key: string): Row | undefined {
    const t = this.tables.get(name);
    return t && !t.absent.has(key) ? t.rows.get(key) : undefined;
  }

  *rows(name: TableName): Iterable<Row> {
    const t = this.tables.get(name);
    if (!t) return;
    for (const [key, row] of t.rows) if (!t.absent.has(key)) yield row;
  }

  /** Whether `key` has a row that is absent at t: it renders ghosted. */
  absent(name: TableName, key: string): boolean {
    return this.tables.get(name)?.absent.has(key) ?? false;
  }

  tiles(): Set<string> {
    const out = new Set<string>();
    for (const t of this.tables.values())
      for (const tile of t.tiles.keys()) if (tile) out.add(tile);
    return out;
  }

  private place(key: string, row: Row | null): void {
    if (row) this.layout.set(key, placement(row));
    else this.layout.delete(key);
  }

  private shared(t: TableState, key: string, except: string): boolean {
    for (const [tile, keys] of t.tiles)
      if (tile !== except && keys.has(key)) return true;
    return false;
  }

  setTier(name: TableName, rows: Row[], tile?: string): void {
    const t = this.table(name);
    const tileKey = tile ?? "";
    const keys = new Set<string>();
    for (const row of rows) {
      const key = keyOf(name, row);
      keys.add(key);
      t.rows.set(key, row);
      t.absent.delete(key);
      if (name === "layout") this.place(key, row);
    }
    for (const key of t.tiles.get(tileKey) ?? []) {
      if (keys.has(key) || this.shared(t, key, tileKey)) continue;
      t.rows.delete(key);
      t.absent.delete(key);
      if (name === "layout") this.place(key, null);
    }
    t.tiles.set(tileKey, keys);
    this.touchData();
  }

  applyDelta(name: TableName, changes: ElementChange[], tile?: string): void {
    const t = this.table(name);
    const keys = t.tiles.get(tile ?? "") ?? new Set<string>();
    t.tiles.set(tile ?? "", keys);
    for (const { key, row } of changes) {
      if (row) {
        t.rows.set(key, row);
        t.absent.delete(key);
        keys.add(key);
      } else if (t.rows.has(key)) {
        t.absent.add(key);
      }
      if (name === "layout") this.place(key, row);
    }
    this.touchData();
  }

  dropTile(tile: string): void {
    for (const [name, t] of this.tables) {
      const keys = t.tiles.get(tile);
      if (!keys) continue;
      for (const key of keys) {
        if (this.shared(t, key, tile)) continue;
        t.rows.delete(key);
        t.absent.delete(key);
        if (name === "layout") this.place(key, null);
      }
      t.tiles.delete(tile);
    }
    this.touchData();
  }

  setStyle(style: Style): void {
    const before = this.style;
    this.style = style;
    // The hovered device reaches the labels only, which are read on each frame: the batches, the derived data
    // and the wiring stay as they are.
    if (hoverOnly(before, style)) return;
    this.touch();
  }

  /** The routes do not count in the version. */
  setRoutes(routes: Route[]): void {
    this.routes = routes;
  }

  /** The plane rectangle of every placed site. */
  bounds(): { u0: number; v0: number; u1: number; v1: number } {
    let u0 = Infinity;
    let v0 = Infinity;
    let u1 = -Infinity;
    let v1 = -Infinity;
    for (const p of this.layout.values()) {
      if (p.kind !== "plate") continue;
      u0 = Math.min(u0, p.u);
      v0 = Math.min(v0, p.v);
      u1 = Math.max(u1, p.u + p.w);
      v1 = Math.max(v1, p.v + p.h);
    }
    return u0 === Infinity
      ? { u0: 0, v0: 0, u1: 1, v1: 1 }
      : { u0, v0, u1, v1 };
  }

  private ancestor(uid: string, kind: string): string | null {
    let p = this.layout.get(uid);
    for (let i = 0; p && i < 6; i++) {
      if (p.kind === kind) return p.uid;
      p = p.parent ? this.layout.get(p.parent) : undefined;
    }
    return p?.kind === kind ? p.uid : null;
  }

  siteOf(uid: string): string | null {
    return this.derived().site.get(uid) ?? this.ancestor(uid, "site");
  }

  blockOf(uid: string): string | null {
    return this.derived().block.get(uid) ?? this.ancestor(uid, "block");
  }

  neighbors(uid: string): Set<string> {
    const out = new Set<string>();
    for (const e of this.rows("render_t1_edges")) {
      if (e.a_uid === uid) out.add(String(e.b_uid));
      if (e.b_uid === uid) out.add(String(e.a_uid));
    }
    return out;
  }

  private derived(): Derived {
    const key = `${this.dataVersion}|${this.style.selected}|${this.style.context}`;
    if (this.derivedCache?.key === key) return this.derivedCache.derived;
    const site = new Map<string, string | null>();
    const block = new Map<string, string | null>();
    const plates = new Map<string, string>();
    for (const p of this.layout.values()) {
      if (p.kind === "plate" && p.parent !== null && !plates.has(p.parent)) plates.set(p.parent, p.uid);
      if (p.kind !== "device") continue;
      site.set(p.uid, this.ancestor(p.uid, "site"));
      block.set(p.uid, this.ancestor(p.uid, "block"));
    }
    const contexts = new Map<string, Row[]>();
    for (const row of this.rows("render_t2_contexts")) {
      const list = contexts.get(String(row.device_uid)) ?? [];
      list.push(row);
      contexts.set(String(row.device_uid), list);
    }
    for (const list of contexts.values()) {
      list.sort(
        (a, b) =>
          Number(Boolean(b.is_default)) - Number(Boolean(a.is_default)) ||
          Number(a.order ?? 0) - Number(b.order ?? 0) ||
          String(a.name ?? "").localeCompare(String(b.name ?? "")),
      );
    }
    let context: Derived["context"] = null;
    if (this.style.context) {
      context = { devices: new Set(), sites: new Set(), contexts: new Set() };
      for (const row of this.rows("render_t1_contexts")) {
        if (row.identity_uid !== this.style.context) continue;
        context.devices.add(String(row.device_uid));
        context.contexts.add(String(row.context_uid));
      }
      for (const d of context.devices) {
        const s = site.get(d);
        if (s) context.sites.add(s);
      }
    }
    const neighbors = this.style.selected
      ? this.neighbors(this.style.selected)
      : new Set<string>();
    const hubs = new Set<string>();
    for (const row of this.rows("render_t1")) {
      if (row.role === HUB_ROLE && row.site_uid != null) hubs.add(String(row.site_uid));
    }
    const regions = new Map<string, string[]>();
    const blocksOf = new Map<string, string[]>();
    for (const p of this.layout.values()) {
      const [map, key] =
        p.kind === "site" && p.parent !== null && this.layout.get(p.parent)?.kind === "region"
          ? [regions, p.parent]
          : p.kind === "block"
            ? [blocksOf, this.ancestor(p.uid, "site")]
            : [null, null];
      if (map === null || key === null) continue;
      const list = map.get(key) ?? [];
      list.push(p.uid);
      map.set(key, list);
    }
    const stubs: Derived["stubs"] = new Map();
    for (const e of this.rows("render_t1_edges")) {
      const links = count(e, "cable_count") + count(e, "lag_count");
      const pa = this.layout.get(String(e.a_uid));
      const pb = this.layout.get(String(e.b_uid));
      if (links === 0 || !pa || !pb) continue;
      const sa = site.get(pa.uid) ?? null;
      const sb = site.get(pb.uid) ?? null;
      if (sa === null || sb === null || sa === sb || this.spinePair(sa, sb)) continue;
      for (const [from, to, far] of [[pa, pb, sb], [pb, pa, sa]] as const) {
        const [start, end] = stubOf(center(from), center(to));
        const key = `${from.uid}:${Math.sign(end[0] - start[0])}:${Math.sign(end[1] - start[1])}`;
        const entry = stubs.get(key) ?? { end, items: [] };
        entry.items.push({ pair: String(e.pair_id), a: pa.uid, b: pb.uid, far, links });
        stubs.set(key, entry);
      }
    }
    const derived = {
      site,
      block,
      contexts,
      context,
      neighbors,
      ports: this.cappedPorts(),
      hubs,
      plates,
      regions,
      blocksOf,
      stubs,
    };
    this.derivedCache = { key, derived };
    return derived;
  }

  private cappedPorts(): Set<string> {
    const ends = new Set<string>();
    for (const c of this.rows("render_t2_cables"))
      ends.add(String(c.a_port)).add(String(c.b_port));
    const byDevice = new Map<string, Placement[]>();
    for (const p of this.layout.values()) {
      if (p.kind !== "port" || !p.parent) continue;
      const list = byDevice.get(p.parent) ?? [];
      list.push(p);
      byDevice.set(p.parent, list);
    }
    const out = new Set<string>();
    for (const [device, ports] of byDevice) {
      const cap =
        device === this.style.selected ? 2 * LABEL_BUDGET.port : PORT_CAP;
      const name = (p: Placement) =>
        String(this.row("render_t2_ports", p.uid)?.name ?? p.uid);
      if (ports.length > cap)
        ports.sort(
          (a, b) =>
            Number(ends.has(b.uid)) - Number(ends.has(a.uid)) ||
            name(a).localeCompare(name(b), undefined, { numeric: true }),
        );
      for (const p of ports.slice(0, cap)) out.add(p.uid);
    }
    return out;
  }

  /** The base of the model of device `p`, as `build` draws it. */
  footprint(p: Placement): Footprint {
    const row = this.row("render_t1", p.uid);
    const spec = MODELS[symbolOf(row?.role, row?.tier)];
    let w = Math.max(0.4, p.w - 2 * spec.inset);
    let h = Math.max(0.4, p.h - 2 * spec.inset);
    const isRound = round(spec.shape);
    if (isRound) w = h = Math.min(w, h);
    const [cu, cv] = center(p);
    return {
      uid: p.uid,
      u: p.u,
      v: p.v,
      w: p.w,
      h: p.h,
      cu,
      cv,
      hw: w / 2,
      hh: h / 2,
      round: isRound,
      area: this.derived().site.get(p.uid) ?? null,
    };
  }

  /** The port sockets on the model walls and the cable routes between them, cached until the data or the selection changes. */
  wiring(): Wiring {
    // The selection is part of the key.
    const key = `${this.dataVersion}|${this.style.selected}`;
    if (this.wiringCache?.key === key) return this.wiringCache.wiring;
    const d = this.derived();
    const devices = new Map<string, Footprint>();
    const ports: {
      uid: string;
      device: string;
      side: string | null;
      slot: number | null;
    }[] = [];
    for (const p of this.layout.values())
      if (p.kind === "device") devices.set(p.uid, this.footprint(p));
    // A socket draws for a cabled port; the other ports sit in their group segment and in the panel.
    const ends = new Set<string>();
    for (const c of this.rows("render_t2_cables")) ends.add(String(c.a_port)).add(String(c.b_port));
    for (const p of this.layout.values()) {
      const wanted = p.kind === "port" && ends.has(p.uid);
      const owner =
        wanted && p.parent && d.ports.has(p.uid)
          ? devices.get(p.parent)
          : undefined;
      // A port the layout places outside its device keeps that cell.
      if (
        !owner ||
        p.u < owner.u ||
        p.v < owner.v ||
        p.u + p.w > owner.u + owner.w ||
        p.v + p.h > owner.v + owner.h
      )
        continue;
      ports.push({ uid: p.uid, device: owner.uid, side: p.side, slot: p.slot });
    }
    const cables = [];
    for (const [key, row] of this.tables.get("render_t2_cables")?.rows ?? []) {
      const a = this.layout.get(String(row.a_port));
      const b = this.layout.get(String(row.b_port));
      if (
        !a?.parent ||
        !b?.parent ||
        d.site.get(a.parent) !== d.site.get(b.parent)
      )
        continue;
      cables.push({ key, a: a.uid, b: b.uid });
    }
    const wiring = wire(devices, ports, cables);
    this.wiringCache = { key, wiring };
    return wiring;
  }

  /** The tiers of a chassis at device zoom: one per context, the default first, capped with a "+N" tier. */
  contextTiers(device: string): { uid: string; name: string }[] {
    const d = this.derived();
    let rows = d.contexts.get(device) ?? [];
    if (d.context)
      rows = rows.filter((r) => d.context!.contexts.has(String(r.uid)));
    const tiers = rows.map((r) => ({
      uid: String(r.uid),
      name: String(r.name ?? r.uid),
    }));
    if (tiers.length <= CONTEXT_CAP) return tiers;
    const rest = tiers.length - (CONTEXT_CAP - 1);
    return [
      ...tiers.slice(0, CONTEXT_CAP - 1),
      { uid: `${device}#more`, name: `+${rest}` },
    ];
  }

  private deviceColor(uid: string, d: Derived): [number, number, number] {
    const row = this.row("render_t1", uid);
    if (!row) return mix(this.p.unknown, this.p.ghost, GHOST_MIX);
    if (d.context && !d.context.devices.has(uid))
      return mix(this.p.unknown, this.p.ghost, GHOST_MIX);
    if (this.style.selected === uid) return rgb(this.p.selected);
    let hex: number;
    if (this.style.changes) {
      const change = String(row.change ?? "none");
      hex =
        change === "added"
          ? this.p.added
          : change === "changed"
            ? this.p.changed
            : change === "not-observed"
              ? this.p.unknown
              : this.p.unchanged;
    } else {
      const status = String(row.status ?? "unknown");
      const symbol = symbolOf(row.role, row.tier);
      hex =
        status === "observed"
          ? symbol === "firewall"
            ? this.p.firewallBody
            : symbol === "cloud"
              ? this.p.cloudBody
              : this.p.observed
          : status === "carried"
            ? this.p.carried
            : status === "failed"
              ? this.p.failed
              : this.p.unknown;
    }
    if (this.style.selected && !d.neighbors.has(uid))
      return mix(hex, this.p.ghost, DIM_MIX);
    if (this.style.highlight && !this.style.highlight.has(uid))
      return mix(hex, this.p.ghost, DIM_MIX);
    return rgb(hex);
  }

  private plateColor(uid: string): [number, number, number] {
    const row = this.row("render_t0", uid);
    if (!row) return mix(this.p.plate, this.p.ghost, GHOST_MIX);
    if (this.style.changes) {
      const n =
        count(row, "added_count") +
        count(row, "removed_count") +
        count(row, "changed_count");
      return n > 0 ? mix(this.p.plate, this.p.changed, 0.4) : rgb(this.p.plate);
    }
    if (count(row, "failed_count") > 0)
      return mix(this.p.plate, this.p.failed, 0.35);
    if (count(row, "carried_count") > 0)
      return mix(this.p.plate, this.p.carried, 0.25);
    return rgb(this.p.plate);
  }

  private changeColor(change: unknown, base: number): number {
    if (!this.style.changes) return base;
    return change === "added"
      ? this.p.added
      : change === "changed"
        ? this.p.changed
        : change === "removed"
          ? this.p.removed
          : this.p.unchanged;
  }

  /** The instances and line segments of `level`, cached until the scene changes. */
  batches(level: Level): Batches {
    if (
      this.batchCache &&
      this.batchCache.version === this.version &&
      this.batchCache.level === level
    ) {
      return this.batchCache.batches;
    }
    const batches = this.build(level);
    this.batchCache = { version: this.version, level, batches };
    return batches;
  }

  private build(level: Level): Batches {
    const d = this.derived();
    const style = this.style;
    const P = this.p;
    const boxes = new Map<BoxClass, BoxBatch>();
    const lines = new Map<string, LineBatch>();
    const outlines = new Map<string, LineBatch>();
    const symbols = new Map<SymbolName, SymbolBatch>();
    const models = new Map<SymbolName, ModelBatch>();
    const areas: AreaBatch = {
      ids: [],
      data: [],
      colors: [],
      kinds: [],
      selected: [],
    };
    const area = (
      p: Placement,
      kind: 0 | 1 | 2,
      c: [number, number, number],
      selected: boolean,
    ) => {
      areas.ids.push(p.uid);
      areas.data.push(p.u, p.v, p.w, p.h);
      areas.colors.push(...c);
      areas.kinds.push(kind);
      areas.selected.push(selected ? 1 : 0);
    };
    const box = (
      cls: BoxClass,
      id: string,
      u: number,
      v: number,
      w: number,
      h: number,
      y0: number,
      y1: number,
      c: [number, number, number],
    ) => {
      let b = boxes.get(cls);
      if (!b) boxes.set(cls, (b = { cls, ids: [], data: [], colors: [] }));
      b.ids.push(id);
      b.data.push(u, y0, v, w, y1 - y0, h);
      b.colors.push(...c);
    };
    const into =
      (target: Map<string, LineBatch>) =>
      (
        cls: LineClass,
        key: string,
        id: string,
        a: [number, number, number],
        b: [number, number, number],
        c: [number, number, number],
      ) => {
        let l = target.get(key);
        if (!l)
          target.set(
            key,
            (l = { cls, key, ids: [], positions: [], colors: [] }),
          );
        l.ids.push(id);
        l.positions.push(...a, ...b);
        l.colors.push(...c, ...c);
      };
    const segment = into(lines);
    const edge = into(outlines);
    const path = (
      cls: LineClass,
      key: string,
      id: string,
      points: [number, number][],
      y: number,
      c: [number, number, number],
    ) => {
      for (let i = 1; i < points.length; i++) {
        segment(
          cls,
          key,
          id,
          [points[i - 1][0], y, points[i - 1][1]],
          [points[i][0], y, points[i][1]],
          c,
        );
      }
    };
    const backbone = (
      cls: "site-link" | "bundle",
      id: string,
      points: [number, number][],
      y: number,
    ) => {
      path(cls, cls, id, points, y, rgb(P.linkCore));
      for (let i = 1; i < points.length; i++) {
        edge(
          "outline",
          "glow:backbone",
          id,
          [points[i - 1][0], y - 0.01, points[i - 1][1]],
          [points[i][0], y - 0.01, points[i][1]],
          rgb(P.line),
        );
      }
      const [mu, mv] = midpoint(points);
      box(
        "node",
        `node:${id}`,
        mu - NODE_SIZE / 2,
        mv - NODE_SIZE / 2,
        NODE_SIZE,
        NODE_SIZE,
        y - 0.05,
        y + 0.25,
        rgb(P.line),
      );
    };
    const outline = (
      key: string,
      p: Placement,
      y: number,
      c: [number, number, number],
    ) => {
      const corners: [number, number][] = [
        [p.u, p.v],
        [p.u + p.w, p.v],
        [p.u + p.w, p.v + p.h],
        [p.u, p.v + p.h],
      ];
      for (let i = 0; i < 4; i++) {
        const [a, b] = [corners[i], corners[(i + 1) % 4]];
        edge("outline", key, p.uid, [a[0], y, a[1]], [b[0], y, b[1]], c);
      }
    };
    const symbol = (
      id: string,
      name: SymbolName,
      u: number,
      y: number,
      v: number,
      size: number,
      c: [number, number, number],
    ) => {
      let s = symbols.get(name);
      if (!s) symbols.set(name, (s = { name, ids: [], data: [], colors: [] }));
      s.ids.push(id);
      s.data.push(u, y + 0.01, v, size);
      s.colors.push(...c);
    };
    const model = (
      id: string,
      p: Placement,
      name: SymbolName,
      c: [number, number, number],
    ): [number, number, number, number] => {
      const spec = MODELS[name];
      let w = Math.max(0.4, p.w - 2 * spec.inset);
      let h = Math.max(0.4, p.h - 2 * spec.inset);
      if (round(spec.shape)) w = h = Math.min(w, h);
      const [cu, cv] = center(p);
      let m = models.get(name);
      if (!m) models.set(name, (m = { name, ids: [], data: [], colors: [] }));
      m.ids.push(id);
      m.data.push(cu - w / 2, Y.bracketTop, cv - h / 2, w, spec.height, h);
      m.colors.push(...c);
      return [cu, Y.bracketTop + spec.height, cv, Math.min(w, h)];
    };

    const tunnelEdges = this.tunnelEdges(d);
    // The own block of a focused hub glows in place of its spokes.
    const glow = new Set(this.focusSpokes(level, d, tunnelEdges).flatMap((s) => (s.local ? [s.local] : [])));
    const ctx = d.context;
    // A box draws when a site in the context filter sits in it, also inside a site group in it.
    const shown = (region: string): boolean => {
      if (!ctx) return true;
      for (const site of ctx.sites)
        for (let r = this.regionOf(site); r !== null; r = this.layout.get(r)?.parent ?? null) if (r === region) return true;
      return false;
    };
    for (const p of this.layout.values()) {
      if (p.kind !== "region" || !shown(p.uid)) continue;
      area(p, 2, rgb(P.line), style.area === p.uid || glow.has(p.uid));
    }
    const plates = [...this.layout.values()].filter((p) => p.kind === "plate");
    for (const p of plates) {
      if (d.context && p.parent && !d.context.sites.has(p.parent)) continue;
      box(
        "plate",
        p.uid,
        p.u,
        p.v,
        p.w,
        p.h,
        0,
        Y.plateTop,
        this.plateColor(p.uid),
      );
      const chosen =
        style.area !== null &&
        (style.area === p.uid || style.area === p.parent);
      area(p, 0, this.plateColor(p.uid), chosen);
      if (chosen && level <= 2)
        outline("glow:selected", p, Y.plateTop + 0.01, rgb(P.selected));
    }
    const visibleSite = (s: string | null) =>
      !d.context || (s !== null && d.context.sites.has(s));

    if (level >= 2) {
      for (const p of this.layout.values()) {
        if (p.kind !== "block" || !visibleSite(this.ancestor(p.uid, "site")))
          continue;
        const row = this.row("render_t0", p.uid);
        const tint = tintOf(row?.block_kind);
        const fill = row
          ? mix(P.band, tint, TINT_FILL)
          : mix(P.band, P.ghost, GHOST_MIX);
        box("band", p.uid, p.u, p.v, p.w, p.h, Y.plateTop, Y.bandTop, fill);
        area(p, 1, row ? rgb(tint) : rgb(P.ghost), style.area === p.uid);
        if (style.area === p.uid)
          outline(
            "glow:selected",
            p,
            Y.bandTop + 0.01,
            mix(tint, P.selected, 0.35),
          );
      }
    }

    const tiles = this.tiles();
    if (level === 2) {
      for (const p of this.layout.values()) {
        if (p.kind !== "device" || !visibleSite(d.site.get(p.uid) ?? null))
          continue;
        const row = this.row("render_t1", p.uid);
        if (!keyDevice(row)) continue;
        const slab = this.deviceColor(p.uid, d);
        box(
          "device",
          p.uid,
          p.u + 0.1,
          p.v + 0.1,
          p.w - 0.2,
          p.h - 0.2,
          Y.bracketTop,
          Y.deviceTop,
          slab,
        );
        const name = symbolOf(row?.role, row?.tier);
        const [cu, top, cv, size] = model(p.uid, p, name, slab);
        symbol(p.uid, name, cu, top, cv, size * SYMBOL_SHARE, rgb(P.symbol));
      }
    }
    if (level >= 3) {
      for (const p of this.layout.values()) {
        if (p.kind === "group" && visibleSite(this.ancestor(p.uid, "site"))) {
          box(
            "bracket",
            p.uid,
            p.u,
            p.v,
            p.w,
            p.h,
            Y.bandTop,
            Y.bracketTop,
            rgb(P.bracket),
          );
        }
        if (p.kind !== "device" || !visibleSite(d.site.get(p.uid) ?? null))
          continue;
        const tiers =
          level === 4 && style.layers.l3 ? this.contextTiers(p.uid) : [];
        const chassis =
          tiers.length > 1 || (d.context !== null && tiers.length === 1);
        if (chassis) {
          const step = (Y.deviceTop - Y.bracketTop) / tiers.length;
          const slab = this.deviceColor(p.uid, d);
          tiers.forEach((tier, i) => {
            const y0 = Y.bracketTop + i * step;
            const c =
              i % 2
                ? (slab.map((x, k) => x + (rgb(P.context)[k] - x) * 0.35) as [
                    number,
                    number,
                    number,
                  ])
                : slab;
            box(
              "context",
              tier.uid,
              p.u + 0.15,
              p.v + 0.15,
              p.w - 0.3,
              p.h - 0.3,
              y0,
              y0 + step * 0.9,
              c,
            );
          });
        }
        const slab = this.deviceColor(p.uid, d);
        box(
          "device",
          p.uid,
          p.u + 0.1,
          p.v + 0.1,
          p.w - 0.2,
          p.h - 0.2,
          Y.bracketTop,
          Y.deviceTop,
          slab,
        );
        const row = this.row("render_t1", p.uid);
        const dimmed =
          !row ||
          (d.context !== null && !d.context.devices.has(p.uid)) ||
          (style.selected !== null &&
            style.selected !== p.uid &&
            !d.neighbors.has(p.uid)) ||
          (style.highlight !== null && !style.highlight.has(p.uid));
        const name = symbolOf(row?.role, row?.tier);
        const [cu, top, cv, size] = model(p.uid, p, name, slab);
        symbol(
          p.uid,
          name,
          cu,
          top,
          cv,
          size * SYMBOL_SHARE,
          dimmed ? mix(P.symbol, P.ghost, 0.6) : rgb(P.symbol),
        );
      }
    }

    if (level >= 3 && style.layers.physical) this.segmentBars(d, box, edge);

    if (level === 4 && style.layers.physical) {
      const focus = style.selected;
      const wiring = this.wiring();
      const chosen = this.chosenPorts();
      for (const p of this.layout.values()) {
        if (
          p.kind !== "port" ||
          !p.parent ||
          !d.ports.has(p.uid) ||
          !visibleSite(d.site.get(p.parent) ?? null)
        )
          continue;
        const row = this.row("render_t2_ports", p.uid);
        let hex: number = P.unknown;
        if (row) {
          if (style.changes) hex = this.changeColor(row.change, P.unchanged);
          else if (row.admin_status === "down") hex = P.portAdminDown;
          else if (row.oper_status === "up") hex = P.portUp;
          else if (row.oper_status === "down") hex = P.portDown;
          if (d.context && !d.context.contexts.has(String(row.context_uid)))
            hex = P.ghost;
        }
        const c =
          focus && focus !== p.parent ? mix(hex, P.ghost, DIM_MIX) : rgb(hex);
        const s = wiring.sockets.get(p.uid);
        if (!s) continue;
        const side = chosen.ports.has(p.uid) ? PORT_DOT : END_DOT;
        box("dot", p.uid, s.u - side / 2, s.v - side / 2, side, side, Y.cable - 0.02, Y.cable + 0.1, c);
      }
      for (const [key, row] of this.tables.get("render_t2_cables")?.rows ??
        []) {
        const p = this.layout.get(key);
        if (!p?.points || p.points.length < 2) continue;
        if (d.context) {
          const a = this.row("render_t2_ports", String(row.a_port));
          const b = this.row("render_t2_ports", String(row.b_port));
          if (
            !d.context.contexts.has(String(a?.context_uid)) &&
            !d.context.contexts.has(String(b?.context_uid))
          )
            continue;
        }
        const tile = tiles.has(String(row.tile_a))
          ? String(row.tile_a)
          : String(row.tile_b);
        let hex: number =
          row.speed_agreement === false ? P.mismatch : P.line;
        hex = this.changeColor(row.change, hex);
        let c = this.absent("render_t2_cables", key)
          ? mix(hex, P.ghost, GHOST_MIX)
          : rgb(hex);
        if (row.carried) c = mix(hex, P.ghost, 0.4);
        const speed = speedClass(row.speed_mbps);
        const batch = speed ? `cable:${tile}:${speed}` : `cable:${tile}`;
        const sa = d.site.get(String(row.a_dev)) ?? null;
        const sb = d.site.get(String(row.b_dev)) ?? null;
        // A cross-connect to a Fabric spine follows the planner's route across the gap between the plates.
        if (this.layout.get(p.parent ?? "")?.kind === "region") {
          const points: [number, number][] = [];
          for (const [u, v] of p.points) {
            const next: [number, number] = [u + 0.5, v + 0.5];
            const last = points[points.length - 1];
            points.push(...(last ? orthogonal(last, next).slice(1) : [next]));
          }
          path("cable", batch, key, points, Y.cable, c);
          continue;
        }
        if (sa !== null && sb !== null && sa !== sb) {
          const [ea, eb] = [wiring.sockets.get(String(row.a_port)), wiring.sockets.get(String(row.b_port))];
          const mine = style.selected === String(row.a_dev) || style.selected === String(row.b_dev);
          if (mine && ea && eb) {
            let prev = arcAt([ea.u, ea.v], [eb.u, eb.v], Y.cable, 0, 0);
            for (let i = 1; i <= ARC_STEPS; i++) {
              const next = arcAt([ea.u, ea.v], [eb.u, eb.v], Y.cable, 0, i / ARC_STEPS);
              segment("cable", batch, key, prev, next, c);
              prev = next;
            }
            continue;
          }
          for (const s of [ea, eb]) {
            if (s) path("cable", batch, key, [[s.u, s.v], [s.u + s.nu * PORT_STUB, s.v + s.nv * PORT_STUB]], Y.cable, c);
          }
          continue;
        }
        let points = wiring.routes.get(key);
        if (!points) {
          points = [];
          for (const [u, v] of p.points) {
            const next: [number, number] = [u + 0.5, v + 0.5];
            const last = points[points.length - 1];
            points.push(...(last ? orthogonal(last, next).slice(1) : [next]));
          }
        }
        path("cable", batch, key, points, Y.cable, c);
      }
    }

    const sitePairs = new Map<string, [string, string]>();
    const blockPairs = new Map<string, [string, string]>();
    for (const e of this.rows("render_t1_edges")) {
      const a = String(e.a_uid);
      const b = String(e.b_uid);
      const pa = this.layout.get(a);
      const pb = this.layout.get(b);
      if (!pa || !pb) continue;
      const physical = count(e, "cable_count") + count(e, "lag_count") > 0;
      const sa = d.site.get(a) ?? null;
      const sb = d.site.get(b) ?? null;
      const ba = d.block.get(a) ?? null;
      const bb = d.block.get(b) ?? null;
      const inContext =
        !d.context || (d.context.devices.has(a) && d.context.devices.has(b));
      if (physical && style.layers.physical && inContext) {
        if (sa && sb && sa !== sb)
          sitePairs.set([sa, sb].sort().join("|"), [sa, sb]);
        else if (ba && bb && ba !== bb)
          blockPairs.set([ba, bb].sort().join("|"), [ba, bb]);
        const cabled =
          level === 4 &&
          ba !== null &&
          bb !== null &&
          tiles.has(ba) &&
          tiles.has(bb);
        if (level >= 3 && !cabled) {
          let hex: number =
            style.layers.l2 && count(e, "lag_count") > 0 ? P.lag : P.line;
          hex = this.changeColor(e.change, hex);
          if (style.selected === a || style.selected === b) hex = P.selected;
          const c =
            style.selected && hex !== P.selected
              ? mix(hex, P.ghost, DIM_MIX)
              : rgb(hex);
          const links = count(e, "cable_count") + count(e, "lag_count");
          const width = countClass(links);
          if (sa !== null && sb !== null && sa !== sb && (style.selected === a || style.selected === b)) {
            // The selected device draws its links to other sites in full, as an arc above the map.
            let prev = arcAt(center(pa), center(pb), Y.summary, 0, 0);
            for (let i = 1; i <= ARC_STEPS; i++) {
              const next = arcAt(center(pa), center(pb), Y.summary, 0, i / ARC_STEPS);
              segment("summary", width ? `summary:${width}` : "summary", String(e.pair_id), prev, next, c);
              prev = next;
            }
          } else if (sa !== null && sb !== null && sa !== sb && !this.spinePair(sa, sb)) {
            for (const [from, to] of [[pa, pb], [pb, pa]] as const) {
              path("summary", width ? `summary:${width}` : "summary", String(e.pair_id), stubOf(center(from), center(to)), Y.summary, c);
            }
          } else {
            const points = orthogonal(center(pa), center(pb));
            path(
              "summary",
              width ? `summary:${width}` : "summary",
              String(e.pair_id),
              points,
              Y.summary,
              c,
            );
            const [mu, mv] = midpoint(points);
            box(
              "dot",
              `dot:${e.pair_id}`,
              mu - DOT_SIZE / 2,
              mv - DOT_SIZE / 2,
              DOT_SIZE,
              DOT_SIZE,
              Y.summary - 0.02,
              Y.summary + 0.12,
              c,
            );
          }
        }
      }
    }
    this.tunnelOverlay(tunnelEdges, level, d, box, segment);
    // A circuit line rides one step above a tunnel arc of the same pair. At estate and site zoom it ends at the
    // glyphs of its sites, which draw for it where no tunnel draws them.
    const glyphs = new Set(boxes.get("glyph")?.ids ?? []);
    for (const line of this.circuitLines(level)) {
      const c = rgb(style.tunnel === line.id ? P.selected : P.circuit);
      for (const { from, to } of line.arcs) {
        let prev = circuitAt(from, to, 0);
        for (let i = 1; i <= ARC_STEPS; i++) {
          const next = circuitAt(from, to, i / ARC_STEPS);
          segment("circuit", "circuit", line.id, prev, next, c);
          prev = next;
        }
        if (level >= 3) continue;
        for (const e of [from, to]) {
          if (glyphs.has(`glyph:${e.uid}`)) continue;
          glyphs.add(`glyph:${e.uid}`);
          box("glyph", `glyph:${e.uid}`, e.at[0] - 1, e.at[1] - 1, 2, 2, Y.glyph, Y.glyph + 1, rgb(P.circuit));
        }
      }
    }
    // A link between two sites draws while one of the two is selected, and the backbone with no selection, in one
    // form at every zoom.
    const chosen = this.focusSites(d, false);
    for (const [key, [sa, sb]] of sitePairs) {
      if (sa === "site:unassigned" || sb === "site:unassigned") continue;
      if (!chosen.has(sa) && !chosen.has(sb) && !(this.backbone(sa) && this.backbone(sb))) continue;
      if (level >= 3 && this.spinePair(sa, sb)) continue;
      const pa = this.layout.get(this.plateOf(sa));
      const pb = this.layout.get(this.plateOf(sb));
      if (!pa || !pb) continue;
      path("site-link", "site-link", key, orthogonal(center(pa), center(pb)), Y.siteLink, rgb(P.line));
    }
    if (level === 2) {
      for (const [key, [ba, bb]] of blockPairs) {
        const pa = this.layout.get(ba);
        const pb = this.layout.get(bb);
        if (!pa || !pb) continue;
        backbone("bundle", key, orthogonal(center(pa), center(pb)), Y.bundle);
      }
    }
    for (const cls of ["device", "plate", "band", "context"] as const) {
      const b = boxes.get(cls);
      if (b) b.proxy = true;
    }
    return {
      areas,
      boxes: [...boxes.values()],
      lines: [...lines.values()],
      outlines: [...outlines.values()],
      symbols: [...symbols.values()],
      models: [...models.values()],
      texts: this.groundTexts(),
    };
  }

  /** The names of the boxes, the sites and the blocks, painted on the ground. */
  groundTexts(): GroundText[] {
    const d = this.derived();
    const out: GroundText[] = [];
    const paint = (id: string, text: string, u: number, v: number, room: number, width: number, strong: boolean) => {
      const size = Math.min(room, width / (text.length * NAME_CHAR + 1));
      if (!text || size <= 0) return;
      const at = (px: number) => px / (size * ISO_V);
      out.push({ id, text, u, v, size, minZoom: at(NAME_PX.min), maxZoom: at(NAME_PX.max), strong });
    };
    for (const p of this.layout.values()) {
      if (p.kind === "region") {
        paint(`name:${p.uid}`, regionName(p.uid), p.u, p.v - 0.5, p.parent ? NAME_ROOM.nested : NAME_ROOM.top, p.w, false);
      } else if (p.kind === "plate" && p.parent) {
        const site = p.parent;
        const cell = this.layout.get(site);
        if (!cell || (d.context && !d.context.sites.has(site))) continue;
        if (site === "site:unassigned" && count(this.row("render_t0", site), "device_count") === 0) continue;
        // The annex rows of the cell hold the name; a cell with none still gets a strip under its plate.
        const room = Math.max(cell.v + cell.h - p.v - p.h, 2) * 0.45;
        const size = Math.min(room, p.w / (this.siteName(site).length * NAME_CHAR + 1));
        paint(`name:${site}`, this.siteName(site), p.u, p.v + p.h + 0.5 + size, room, p.w, true);
      } else if (p.kind === "block") {
        const label = String(this.row("render_t0", p.uid)?.label ?? "");
        paint(`name:${p.uid}`, label, p.u + 0.3, p.v + p.h - 0.1, 0.8, p.w - 0.6, false);
      }
    }
    return out;
  }

  private plateOf(site: string): string {
    return this.derived().plates.get(site) ?? site;
  }

  private siteName(site: string): string {
    const row = this.row("render_t0", site);
    return String(row?.label ?? (site === "site:unassigned" ? "Unassigned" : site.replace(/^site:/, "")));
  }

  /**
   * The tunnel lines of a focused site at estate and site zoom: a spoke to each far site
   * of its own country block and to a lone far site of another block, and one bundle to the centre of each other
   * block with two or more far sites.
   */
  siteSpokes(site: string, entry: { total: number; far: Map<string, number> }): Spoke[] {
    const from = this.glyphOf(site);
    if (!from) return [];
    const own = this.regionOf(site);
    const hub = this.derived().hubs.has(site);
    const out: Spoke[] = [];
    const spoke = (far: string, n: number) => {
      const to = this.glyphOf(far);
      if (to) out.push({ id: `tunnel:${[site, far].sort().join("|")}`, from, to, tunnels: n, sites: 1 });
    };
    const bundles = new Map<string, [string, number][]>();
    for (const [far, n] of entry.far) {
      const region = this.regionOf(far);
      if (region === null || (region === own && !hub)) spoke(far, n);
      else bundles.set(region, [...(bundles.get(region) ?? []), [far, n]]);
    }
    for (const [region, members] of bundles) {
      const p = this.layout.get(region);
      const tunnels = members.reduce((sum, [, n]) => sum + n, 0);
      const id = `tunnel:${site}|${region}`;
      if (p && region === own) out.push({ id, from, to: center(p), tunnels, sites: members.length, local: region });
      else if (members.length === 1 || !p) for (const [far, n] of members) spoke(far, n);
      else out.push({ id, from, to: center(p), tunnels, sites: members.length });
    }
    return out;
  }

  /**
   * The tunnel lines of a focused device at block and port zoom, by the rule of `siteSpokes`: an arc per device
   * pair inside its site, to its own country block unless it is a hub, and to a lone far site of another block;
   * one bundle to the centre of each other block with two or more far sites.
   */
  deviceSpokes(device: string, edges: [Row, Placement, Placement][]): Spoke[] {
    const d = this.derived();
    const p = this.layout.get(device);
    if (!p) return [];
    const site = d.site.get(device) ?? null;
    const own = site === null ? null : this.regionOf(site);
    const hub = this.row("render_t1", device)?.role === HUB_ROLE;
    const out: Spoke[] = [];
    const arc = (edge: [Row, Placement, Placement]) => {
      const [e, pa, pb] = edge;
      out.push({ id: String(e.pair_id), from: center(pa), to: center(pb), tunnels: count(e, "tunnel_count"), sites: 1, pair: edge });
    };
    const farSite = ([, pa, pb]: [Row, Placement, Placement]) => d.site.get(pa.uid === device ? pb.uid : pa.uid) ?? null;
    const groups = new Map<string, [Row, Placement, Placement][]>();
    for (const edge of edges) {
      if (edge[1].uid !== device && edge[2].uid !== device) continue;
      const far = farSite(edge);
      const region = far !== null && far !== site ? this.regionOf(far) : null;
      if (region === null || (region === own && !hub)) arc(edge);
      else groups.set(region, [...(groups.get(region) ?? []), edge]);
    }
    for (const [region, list] of groups) {
      const r = this.layout.get(region);
      const sites = new Set(list.map(farSite)).size;
      const tunnels = list.reduce((sum, [e]) => sum + count(e, "tunnel_count"), 0);
      const id = `tunnel:${device}|${region}`;
      if (r && region === own) out.push({ id, from: center(p), to: center(r), tunnels, sites, local: region });
      else if (sites === 1 || !r) list.forEach(arc);
      else out.push({ id, from: center(p), to: center(r), tunnels, sites });
    }
    return out;
  }

  /** The circuits of the scene with both end devices placed and distinct. */
  private circuitEdges(): [Row, Placement, Placement][] {
    const out: [Row, Placement, Placement][] = [];
    if (!this.style.layers.l2) return out;
    for (const c of this.rows("render_t1_circuits")) {
      const pa = this.layout.get(String(c.a_device));
      const pb = this.layout.get(String(c.z_device));
      if (pa && pb && pa.uid !== pb.uid) out.push([c, pa, pb]);
    }
    return out;
  }

  /**
   * The circuit lines of the selection: at estate and site zoom one per far site of the
   * selected site, at every zoom one per backbone site pair, and at block and port zoom one per far device of the
   * selected device outside the backbone, each with its circuits. Every arc ends at an element that draws: at estate
   * and site zoom the glyph of each site, at block and port zoom each end device, or at port zoom its Fabric port
   * where the port draws.
   */
  circuitLines(level: Level): CircuitLine[] {
    const d = this.derived();
    type Group = { circuits: Row[]; arcs: Map<string, { from: CircuitEnd; to: CircuitEnd; n: number }> };
    const lines = new Map<string, Group>();
    const add = (id: string, from: CircuitEnd, to: CircuitEnd, c: Row) => {
      const line: Group = lines.get(id) ?? { circuits: [], arcs: new Map() };
      line.circuits.push(c);
      const key = `${from.uid}|${to.uid}`;
      const arc = line.arcs.get(key) ?? { from, to, n: 0 };
      arc.n += 1;
      line.arcs.set(key, arc);
      lines.set(id, line);
    };
    const visible = (site: string | null) => !d.context || (site !== null && d.context.sites.has(site));
    const glyph = (site: string): CircuitEnd | null => {
      const at = this.glyphOf(site);
      return at ? { uid: site, at, y: Y.glyph } : null;
    };
    const sockets = level === 4 && this.style.layers.physical ? this.wiring().sockets : null;
    const end = (device: Placement, port: unknown): CircuitEnd => {
      const s = sockets && port != null && d.ports.has(String(port)) ? sockets.get(String(port)) : undefined;
      return s ? { uid: String(port), at: [s.u, s.v], y: Y.cable } : { uid: device.uid, at: center(device), y: Y.deviceTop };
    };
    const chosen = level <= 2 ? this.focusSites(d, false) : new Set<string>();
    const selected = this.style.selected;
    for (const [c, pa, pb] of this.circuitEdges()) {
      const sa = d.site.get(pa.uid) ?? null;
      const sb = d.site.get(pb.uid) ?? null;
      if (!visible(sa) || !visible(sb)) continue;
      const ends = [[sa, pa, c.a_port], [sb, pb, c.z_port]] as const;
      let spined = false;
      for (const [[from, a, ap], [to, b, bp]] of [[ends[0], ends[1]], [ends[1], ends[0]]] as const) {
        if (!from || !to || from === to) continue;
        // The backbone draws one line per site pair with no selection, at every zoom.
        const spine = this.backbone(from) && this.backbone(to) && !chosen.has(to) && from < to;
        if (!chosen.has(from) && !spine) continue;
        if (level >= 3) {
          spined = true;
          add(`circuit:${from}|${to}`, end(a, ap), end(b, bp), c);
          continue;
        }
        const [ga, gb] = [glyph(from), glyph(to)];
        if (ga && gb) add(`circuit:${from}|${to}`, ga, gb, c);
      }
      // A circuit of the backbone draws on its backbone line, which runs between the same devices.
      if (level <= 2 || spined) continue;
      const own = pa.uid === selected ? 0 : pb.uid === selected ? 1 : null;
      if (own === null) continue;
      const [[, mine, mp], [, far, fp]] = own === 0 ? [ends[0], ends[1]] : [ends[1], ends[0]];
      add(`circuit:${mine.uid}|${far.uid}`, end(mine, mp), end(far, fp), c);
    }
    return [...lines].map(([id, line]) => ({
      id,
      circuits: line.circuits,
      arcs: [...line.arcs]
        .sort(([ka, a], [kb, b]) => b.n - a.n || (ka < kb ? -1 : ka > kb ? 1 : 0))
        .map(([, { from, to }]) => ({ from, to })),
    }));
  }

  /** The circuits of a picked circuit line, between two sites or two devices; null for another id. */
  circuitDetail(id: string): { from: string; to: string; circuits: Row[] } | null {
    if (!id.startsWith("circuit:")) return null;
    const rest = id.slice("circuit:".length);
    const cut = rest.lastIndexOf("|");
    const [from, to] = [rest.slice(0, cut), rest.slice(cut + 1)];
    const d = this.derived();
    const sites = this.layout.get(from)?.kind === "site";
    const end = (uid: string) => (sites ? (d.site.get(uid) ?? null) : uid);
    const circuits = this.circuitEdges()
      .filter(([, pa, pb]) => {
        const [a, b] = [end(pa.uid), end(pb.uid)];
        return (a === from && b === to) || (a === to && b === from);
      })
      .map(([c]) => c);
    return circuits.length > 0 ? { from, to, circuits } : null;
  }

  /** The country block of `site`, or null for a site outside the blocks. */
  private regionOf(site: string): string | null {
    const parent = this.layout.get(site)?.parent ?? null;
    return parent !== null && this.layout.get(parent)?.kind === "region" ? parent : null;
  }

  /** Whether `site` is in the core block or the cloud block: the backbone runs between such sites. */
  private backbone(site: string): boolean {
    const region = this.regionOf(site);
    return region !== null && backboneRegion(region);
  }

  /** Whether one of sites `a` and `b` is a Fabric spine and the other sits inside its site group: their links are
   *  cross-connects that draw in full. */
  private spinePair(a: string, b: string): boolean {
    const within = (site: string, region: string | null): boolean => {
      for (let r = this.regionOf(site); r !== null; r = this.layout.get(r)?.parent ?? null) if (r === region) return true;
      return false;
    };
    return (a.startsWith(SPINE_PREFIX) && within(b, this.regionOf(a))) || (b.startsWith(SPINE_PREFIX) && within(a, this.regionOf(b)));
  }

  /** The tunnel device pairs of the scene in the context filter, with both devices placed. */
  private tunnelEdges(d: Derived): [Row, Placement, Placement][] {
    const out: [Row, Placement, Placement][] = [];
    if (!this.style.layers.l3) return out;
    for (const e of this.rows("render_t1_edges")) {
      const pa = this.layout.get(String(e.a_uid));
      const pb = this.layout.get(String(e.b_uid));
      const inContext = !d.context || (d.context.devices.has(pa?.uid ?? "") && d.context.devices.has(pb?.uid ?? ""));
      if (count(e, "tunnel_count") > 0 && pa && pb && inContext) out.push([e, pa, pb]);
    }
    return out;
  }

  /** The tunnel lines of the selected site at estate and site zoom, or of the selected device at block and port
   *  zoom. Hovering draws none. */
  private focusSpokes(level: Level, d: Derived, edges: [Row, Placement, Placement][]): Spoke[] {
    const out: Spoke[] = [];
    const seen = new Set<string>();
    const add = (list: Spoke[]) => {
      for (const s of list) {
        if (seen.has(s.id)) continue;
        seen.add(s.id);
        out.push(s);
      }
    };
    if (level <= 2) {
      const sites = this.siteTunnels(edges, d);
      for (const site of this.focusSites(d, false)) {
        const entry = sites.get(site);
        if (entry) add(this.siteSpokes(site, entry));
      }
      return out;
    }
    const uid = this.style.selected;
    if (uid && this.layout.get(uid)?.kind === "device") add(this.deviceSpokes(uid, edges));
    return out;
  }

  /** The fabric glyph of a site: a marker above the plate's north-east corner. */
  glyphOf(site: string): [number, number] | null {
    const plate = this.layout.get(this.plateOf(site));
    return plate ? [plate.u + plate.w - 2, plate.v + 2] : null;
  }

  /** The site each focus device sits in, plus the site `style.area` names or whose block it names; without
   *  `hover`, the selection only. */
  private focusSites(d: Derived, hover = true): Set<string> {
    const out = new Set<string>();
    for (const uid of [this.style.selected, hover ? this.style.hovered : null]) {
      const site = uid ? d.site.get(uid) : null;
      if (site) out.add(site);
    }
    const area = this.style.area;
    if (area) {
      const p = this.layout.get(area);
      if (p?.kind === "site") out.add(area);
      else if (p?.kind === "block") {
        const site = this.ancestor(area, "site");
        if (site) out.add(site);
      } else if (p?.kind === "plate" && p.parent) out.add(p.parent);
    }
    return out;
  }

  /** The tunnel line of a site's card, from the edges in the scene: the total, or the spoke count of a hub. */
  tunnelLine(site: string): string | null {
    const d = this.derived();
    const edges: [Row, Placement, Placement][] = [];
    for (const e of this.rows("render_t1_edges")) {
      const pa = this.layout.get(String(e.a_uid));
      const pb = this.layout.get(String(e.b_uid));
      if (count(e, "tunnel_count") > 0 && pa && pb) edges.push([e, pa, pb]);
    }
    return tunnelText(this.siteTunnels(edges, d).get(site), d.hubs.has(site));
  }

  /** The tunnels per site: the total and the count per far site, from the device pairs. */
  siteTunnels(edges: [Row, Placement, Placement][], d: Derived): Map<string, { total: number; far: Map<string, number> }> {
    const out = new Map<string, { total: number; far: Map<string, number> }>();
    for (const [e, pa, pb] of edges) {
      const n = count(e, "tunnel_count");
      const sa = d.site.get(pa.uid) ?? null;
      const sb = d.site.get(pb.uid) ?? null;
      for (const [site, other] of [[sa, sb], [sb, sa]] as const) {
        if (!site) continue;
        const entry = out.get(site) ?? { total: 0, far: new Map<string, number>() };
        entry.total += n;
        if (other && other !== site) entry.far.set(other, (entry.far.get(other) ?? 0) + n);
        out.set(site, entry);
      }
    }
    return out;
  }

  /**
   * The tunnel overlay, one dashed arc at every zoom. No tunnel draws on its own: at
   * estate and site zoom a hub site and a site outside a country block carry a glyph, and the hovered or selected
   * site draws its spokes and bundles; at block and device zoom the hovered or selected device does.
   */
  private tunnelOverlay(
    edges: [Row, Placement, Placement][],
    level: Level,
    d: Derived,
    box: (cls: BoxClass, id: string, u: number, v: number, w: number, h: number, y0: number, y1: number, c: [number, number, number]) => void,
    segment: (cls: LineClass, key: string, id: string, a: [number, number, number], b: [number, number, number], c: [number, number, number]) => void,
  ): void {
    if (edges.length === 0) return;
    if (level <= 2) {
      const focus = this.focusSites(d, false);
      for (const site of this.siteTunnels(edges, d).keys()) {
        const glyph = this.glyphOf(site);
        if (glyph && (focus.has(site) || this.marked(site, d)))
          box("glyph", `glyph:${site}`, glyph[0] - 1, glyph[1] - 1, 2, 2, Y.glyph, Y.glyph + 1, rgb(this.p.tunnel));
      }
    }
    const y = level <= 2 ? Y.glyph : Y.deviceTop;
    for (const s of this.focusSpokes(level, d, edges)) {
      if (s.local) continue;
      if (s.pair) this.tunnel(s.pair[0], s.pair[1], s.pair[2], level, segment);
      else this.arc(s.id, s.from, s.to, y, 0, null, level, rgb(this.style.tunnel === s.id ? this.p.selected : this.p.tunnel), segment);
    }
  }

  /** The points of the tunnel arc from device `a` to device `b`, for a route that rides the tunnel. */
  tunnelArc(a: string, b: string): [number, number, number][] {
    const pa = this.layout.get(a);
    const pb = this.layout.get(b);
    if (!pa || !pb) return [];
    const out: [number, number, number][] = [];
    for (let i = 0; i <= ARC_STEPS; i++) out.push(this.arcPoint(pa, pb, 0, i / ARC_STEPS));
    return out;
  }

  /** The arc of a tunnel pair: above the straight line between the device centers, higher for each further transport. */
  private arcPoint(
    pa: Placement,
    pb: Placement,
    k: number,
    t: number,
  ): [number, number, number] {
    return arcAt(center(pa), center(pb), Y.deviceTop, k, t);
  }

  /** The dashed tunnel arc `id` from `a` to `b` at base height `y`, the `k`-th of its pair. */
  private arc(
    id: string,
    a: [number, number],
    b: [number, number],
    y: number,
    k: number,
    encap: string | null,
    level: Level,
    c: [number, number, number],
    segment: (cls: LineClass, key: string, id: string, a: [number, number, number], b: [number, number, number], c: [number, number, number]) => void,
  ): void {
    const { steps, per } = arcDash(a, b, level);
    let prev = arcAt(a, b, y, k, 0);
    for (let i = 1; i <= steps; i++) {
      const next = arcAt(a, b, y, k, i / steps);
      segment("tunnel", "tunnel", id, prev, dashOn(encap, Math.floor((i - 1) * per)) ? next : prev, c);
      prev = next;
    }
  }

  /** Whether `site` stands for itself at estate and site zoom: a hub site, a core or cloud site, or a site outside a
   *  country block. */
  private marked(site: string, d: Derived): boolean {
    if (d.hubs.has(site) || this.backbone(site)) return true;
    const parent = this.layout.get(site)?.parent ?? null;
    return parent === null || parent === OTHER_REGION || this.layout.get(parent)?.kind !== "region";
  }

  /** The device the selection names, and the ports that draw a socket at port zoom: its own ports and the far
   *  ends of its cables. */
  private chosenPorts(): { device: string | null; ports: Set<string> } {
    const ports = new Set<string>();
    const sel = this.style.selected ? this.layout.get(this.style.selected) : undefined;
    const device = sel?.kind === "device" ? sel.uid : sel?.kind === "port" ? sel.parent : null;
    if (!device) return { device: null, ports };
    for (const c of this.rows("render_t2_cables")) {
      const [a, b] = [String(c.a_port), String(c.b_port)];
      if (this.layout.get(a)?.parent === device || this.layout.get(b)?.parent === device) ports.add(a).add(b);
    }
    for (const q of this.layout.values()) if (q.kind === "port" && q.parent === device) ports.add(q.uid);
    return { device, ports };
  }

  private tunnel(
    e: Row,
    pa: Placement,
    pb: Placement,
    level: Level,
    segment: (
      cls: LineClass,
      key: string,
      id: string,
      a: [number, number, number],
      b: [number, number, number],
      c: [number, number, number],
    ) => void,
  ): void {
    const id = String(e.pair_id);
    const c = rgb(this.style.tunnel === `tunnel:pair:${id}` ? this.p.selected : this.p.tunnel);
    const transports = this.style.transports.get(id);
    const arcs: (string | null)[] =
      transports && transports.length > 0
        ? transports.map((t) => t.encap)
        : [null];
    arcs.forEach((encap, k) => this.arc(id, center(pa), center(pb), Y.deviceTop, k, encap, level, c, segment));
  }

  /**
   * The route markers on the screen. A trace route gives a start pin, an end pin, and a numbered marker or a
   * stop at each hop between. A flow route gives a marker only at a pinned point and a stop at a blocked one.
   */
  markers(cam: CameraState, vp: Viewport): Marker[] {
    const out: Marker[] = [];
    for (const route of this.routes) {
      const points = route.points;
      const trace = route.state === "trace";
      if (trace && points.length < 2) continue;
      points.forEach((p, i) => {
        const height = Math.max(Y.route, p.y ?? Y.route);
        const [x, y] = toScreen(cam, vp, p.u, p.v, height);
        const at: [number, number, number] = [p.u, height, p.v];
        if (trace) {
          if (i === 0) out.push({ kind: "start", text: p.label ?? "A", x, y, at });
          else if (i === points.length - 1) out.push({ kind: "end", text: p.label ?? "B", x, y, at });
          else out.push({ kind: p.blocked ? "stop" : "hop", text: String(i), x, y, at });
          return;
        }
        if (p.blocked) out.push({ kind: "stop", text: p.label ?? "Stop", x, y, at });
        else if (p.pin === "start") out.push({ kind: "start", text: p.label ?? "A", x, y, at });
        else if (p.pin === "end") out.push({ kind: "end", text: p.label ?? "B", x, y, at });
      });
    }
    return out;
  }

  /** The labels of `level` that fall in the viewport, within the budget of the level. */
  labels(cam: CameraState, vp: Viewport, level: Level): Label[] {
    const d = this.derived();
    const out: Label[] = [];
    const at = (
      p: Placement,
      y: number,
    ): [number, number, [number, number, number]] => {
      const [u, v] = center(p);
      const [x, sy] = toScreen(cam, vp, u, v, y);
      return [x, sy, [u, y, v]];
    };
    const inside = (x: number, y: number) =>
      x >= 0 && y >= 0 && x <= vp.width && y <= vp.height;
    const tunnelEdges = this.tunnelEdges(d);
    // The names of the boxes, the sites and the blocks are painted on the ground (`texts` of the batches).
    const cx = vp.width / 2;
    const cy = vp.height / 2;
    const focus = this.style.selected ?? this.style.hovered;
    const device = focus ? this.layout.get(focus) : undefined;
    // Every device in view carries its hostname under the front edge of its model, clear of the line to a
    // neighbour in its row. The selected and the hovered device always do; the others where they still fit after
    // the port labels. The tunnel and circuit counts take the room the names leave, so a count is the label a
    // collision drops.
    const named: Label[] = [];
    if (level >= 3) {
      const devices: Label[] = [];
      for (const p of this.layout.values()) {
        if (p.kind !== "device") continue;
        const front: Placement = { ...p, u: p.u + p.w / 2, v: p.v + p.h + 0.2, w: 0, h: 0 };
        const [x, y, w] = at(front, Y.bandTop);
        if (!inside(x, y)) continue;
        devices.push({ uid: p.uid, text: String(this.row("render_t1", p.uid)?.label ?? p.uid), x, y, at: w, kind: "device" });
      }
      const rank = (l: Label) => (l.uid === this.style.selected ? 0 : l.uid === this.style.hovered ? 1 : 2);
      devices.sort((a, b) => rank(a) - rank(b) || Math.hypot(a.x - cx, a.y - cy) - Math.hypot(b.x - cx, b.y - cy));
      out.push(...devices.filter((l) => rank(l) < 2));
      named.push(...devices.filter((l) => rank(l) === 2));
    }
    if (level === 4 && this.style.layers.physical) {
      for (const p of this.layout.values()) {
        if (p.kind !== "segment" || !p.parent) continue;
        const text = this.segmentText(p.parent);
        if (text === null) continue;
        const below: Placement = { ...p, v: p.v + p.h / 2 + 0.6, h: 0 };
        const [x, y, w] = at(below, Y.portTop);
        if (inside(x, y)) out.push({ uid: p.uid, text, x, y, at: w, kind: "segment" });
      }
    }
    const ports: Label[] = [];
    const seen = new Set<string>();
    const sockets =
      level === 4 ? this.wiring().sockets : new Map<string, Socket>();
    const port = (uid: string) => {
      const p = this.layout.get(uid);
      if (!p || p.kind !== "port" || seen.has(uid) || !d.ports.has(uid)) return;
      seen.add(uid);
      const r = this.row("render_t2_ports", uid);
      const text = String(r?.name_short ?? r?.name ?? uid);
      const socket = sockets.get(uid);
      if (socket) {
        const label = besideSocket(cam, vp, socket, text, uid);
        if (inside(label.x, label.y)) ports.push(label);
        return;
      }
      const owner = p.parent ? this.layout.get(p.parent) : undefined;
      const [cu, cv] = owner ? center(owner) : center(p);
      const [pu, pv] = center(p);
      const len = Math.hypot(pu - cu, pv - cv) || 1;
      const out_: Placement = {
        ...p,
        u: p.u + ((pu - cu) / len) * PORT_LABEL_OUT,
        v: p.v + ((pv - cv) / len) * PORT_LABEL_OUT,
      };
      const [px, py, w] = at(out_, Y.portTop);
      if (!inside(px, py)) return;
      ports.push({ uid, text, x: px, y: py, at: w, kind: "port" });
    };
    // The selected device names its cabled ports and their far ends; its other ports sit in the panel.
    const portNames = level === 4 && cam.zoom >= PORT_LABEL_ZOOM;
    if (portNames && device?.kind === "device") {
      const far: string[] = [];
      for (const c of this.rows("render_t2_cables")) {
        const [a, b] = [String(c.a_port), String(c.b_port)];
        const own = this.layout.get(a)?.parent === device.uid ? a : this.layout.get(b)?.parent === device.uid ? b : null;
        if (!own) continue;
        port(own);
        far.push(own === a ? b : a);
      }
      far.forEach(port);
    }
    if (portNames && this.style.layers.physical) {
      const ends: string[] = [];
      for (const c of this.rows("render_t2_cables"))
        ends.push(String(c.a_port), String(c.b_port));
      const before = ports.length;
      ends.forEach(port);
      const cx = vp.width / 2;
      const cy = vp.height / 2;
      const rest = ports
        .splice(before)
        .sort(
          (a, b) =>
            Math.hypot(a.x - cx, a.y - cy) - Math.hypot(b.x - cx, b.y - cy),
        );
      ports.push(...rest);
    }
    const placedPorts = spread(ports, out, LABEL_BUDGET.port);
    out.push(...placedPorts);
    // The transports of the selected device's tunnels place before the hostnames.
    const tunnels: Label[] = [];
    const asked: Label[] = [];
    if (this.style.layers.l3) {
      const edges = tunnelEdges;
      // A spoke carries its count at the top of its arc; the own block of a hub carries it above the hub.
      const y0 = level <= 2 ? Y.glyph : Y.deviceTop;
      for (const s of this.focusSpokes(level, d, edges)) {
        const transports = s.pair ? this.style.transports.get(s.id) : undefined;
        const at3: [number, number, number] = s.local ? [s.from[0], y0 + 2, s.from[1]] : arcAt(s.from, s.to, y0, 0, 0.5);
        const [x, y] = toScreen(cam, vp, at3[0], at3[2], at3[1]);
        if (!inside(x, y)) continue;
        const country = s.local ? regionName(s.local) : undefined;
        const text = s.local
          ? `${s.sites} sites in ${country}, ${s.tunnels} tunnels`
          : transports
            ? transports.map((t) => `${t.encap} ${t.count}`).join(", ")
            : s.sites > 1
              ? `${s.sites} sites, ${s.tunnels} tunnels`
              : String(s.tunnels);
        (transports && !s.local ? asked : tunnels).push({ uid: s.id, text, x, y, at: at3, kind: "tunnel" });
      }
    }
    const placedAsked = spread(asked, out, LABEL_BUDGET.tunnel);
    out.push(...placedAsked);
    const forced = out.filter((l) => l.kind === "device").length;
    out.push(...spread(named, out, LABEL_BUDGET.device - forced));
    out.push(...spread(tunnels, out, LABEL_BUDGET.tunnel - placedAsked.length));
    if (this.style.layers.l2) {
      const counts: Label[] = [];
      for (const line of this.circuitLines(level)) {
        const top = circuitAt(line.arcs[0].from, line.arcs[0].to, 0.5);
        const [x, y] = toScreen(cam, vp, top[0], top[2], top[1]);
        const n = line.circuits.length;
        if (inside(x, y)) counts.push({ uid: line.id, text: `${n} ${n === 1 ? "circuit" : "circuits"}`, x, y, at: top, kind: "tunnel" });
      }
      out.push(...spread(counts, out, LABEL_BUDGET.tunnel));
    }
    if (level === 2) {
      const rest = new Map<string, number>();
      for (const p of this.layout.values()) {
        if (p.kind !== "device" || keyDevice(this.row("render_t1", p.uid)))
          continue;
        const block = d.block.get(p.uid);
        if (block) rest.set(block, (rest.get(block) ?? 0) + 1);
      }
      for (const [block, n] of rest) {
        const p = this.layout.get(block);
        if (
          !p ||
          (d.context &&
            !d.context.sites.has(this.ancestor(block, "site") ?? ""))
        )
          continue;
        let badge: Label | null = null;
        for (let step = 0; step < 8; step++) {
          const spot: Placement = {
            ...p,
            u: p.u + (step * p.w) / 10,
            v: p.v + (step * p.h) / 10,
          };
          const [x, y, w] = at(spot, Y.bracketTop);
          const candidate: Label = {
            uid: `cluster:${block}`,
            text: n === 1 ? "1 device" : `${n} devices`,
            x,
            y,
            at: w,
            kind: "cluster",
          };
          if (!out.some((l) => overlaps(candidate, l))) {
            badge = candidate;
            break;
          }
        }
        if (badge && inside(badge.x, badge.y)) out.push(badge);
      }
    }
    if (level >= 3 && this.style.layers.physical) {
      const counts: Label[] = [];
      const tiles = this.tiles();
      const stubs: Label[] = [];
      for (const e of this.rows("render_t1_edges")) {
        const links = count(e, "cable_count") + count(e, "lag_count");
        const pa = this.layout.get(String(e.a_uid));
        const pb = this.layout.get(String(e.b_uid));
        if (links === 0 || !pa || !pb) continue;
        const ba = d.block.get(pa.uid);
        const bb = d.block.get(pb.uid);
        if (level === 4 && ba && bb && tiles.has(ba) && tiles.has(bb)) continue;
        const sa = d.site.get(pa.uid) ?? null;
        const sb = d.site.get(pb.uid) ?? null;
        if (links < 2 || (sa !== null && sb !== null && sa !== sb)) continue;
        const [mu, mv] = midpoint(orthogonal(center(pa), center(pb)));
        const [x, y] = toScreen(cam, vp, mu, mv, Y.summary);
        if (inside(x, y))
          counts.push({
            uid: String(e.pair_id),
            text: `${links} links`,
            x,
            y,
            at: [mu, Y.summary, mv],
            kind: "count",
          });
      }
      for (const [key, { end, items }] of d.stubs) {
        const far = new Map<string, number>();
        for (const it of items) {
          const ba = d.block.get(it.a);
          const bb = d.block.get(it.b);
          if (level === 4 && ba && bb && tiles.has(ba) && tiles.has(bb)) continue;
          if (d.context && !(d.context.devices.has(it.a) && d.context.devices.has(it.b))) continue;
          far.set(it.far, (far.get(it.far) ?? 0) + it.links);
        }
        if (far.size === 0) continue;
        const [x, y] = toScreen(cam, vp, end[0], end[1], Y.summary);
        if (!inside(x, y)) continue;
        const names = [...far]
          .map(([site, n]) => (n > 1 ? `${this.siteName(site)} (${n})` : this.siteName(site)))
          .sort((a, b) => a.localeCompare(b));
        const text = `to ${names.slice(0, 3).join(", ")}${names.length > 3 ? `, +${names.length - 3}` : ""}`;
        stubs.push({ uid: `stub:${key}`, text, x, y, at: [end[0], Y.summary, end[1]], kind: "stub" });
      }
      if (level === 4) {
        const wiring = this.wiring();
        for (const c of this.rows("render_t2_cables")) {
          const sa = d.site.get(String(c.a_dev)) ?? null;
          const sb = d.site.get(String(c.b_dev)) ?? null;
          if (sa === null || sb === null || sa === sb || this.spinePair(sa, sb)) continue;
          const ends = [[c.a_port, sb, c.b_port, c.b_dev], [c.b_port, sa, c.a_port, c.a_dev]] as const;
          for (const [port, far, farPort, farDevice] of ends) {
            const s = wiring.sockets.get(String(port));
            if (!s) continue;
            const end: [number, number] = [s.u + s.nu * PORT_STUB, s.v + s.nv * PORT_STUB];
            const [x, y] = toScreen(cam, vp, end[0], end[1], Y.cable);
            const r = this.row("render_t2_ports", String(farPort));
            const host = String(this.row("render_t1", String(farDevice))?.label ?? farDevice);
            const name = r?.name_short ?? r?.name;
            const text = `to ${this.siteName(far)}, ${host}${name ? ` ${String(name)}` : ""}`;
            if (inside(x, y)) stubs.push({ uid: `stub:${String(port)}`, text, x, y, at: [end[0], Y.cable, end[1]], kind: "stub" });
          }
        }
      }
      out.push(...spread(stubs, out, LABEL_BUDGET.count));
      out.push(...spread(counts, out, LABEL_BUDGET.count));
    }
    return out;
  }

  /** The segments of `device` in `render_t2_segments` with clients, in prefix order. */
  segmentsOf(device: string): Row[] {
    const out = [...this.rows("render_t2_segments")].filter((r) => r.device_uid === device && count(r, "client_count") > 0);
    return out.sort((a, b) => String(a.prefix ?? a.vid ?? "").localeCompare(String(b.prefix ?? b.vid ?? ""), undefined, { numeric: true }));
  }

  /** The text of a segment bar: the prefix or the VLAN of one segment, else the count. */
  segmentText(device: string): string | null {
    const segments = this.segmentsOf(device);
    if (segments.length === 0) return null;
    if (segments.length > 1) return `${segments.length} segments`;
    const s = segments[0];
    return String(s.prefix ?? (s.vid !== null && s.vid !== undefined ? `VLAN ${s.vid}` : (s.name ?? "no VLAN")));
  }

  /**
   * A bus bar under each device with segments: a bar across the cell, 3 ticks on it and a stub up to the device's
   * south wall. A device whose segments all lost their clients draws no bar.
   */
  private segmentBars(
    d: Derived,
    box: (cls: BoxClass, id: string, u: number, v: number, w: number, h: number, y0: number, y1: number, c: [number, number, number]) => void,
    edge: (cls: LineClass, key: string, id: string, a: [number, number, number], b: [number, number, number], c: [number, number, number]) => void,
  ): void {
    const P = this.p;
    for (const p of this.layout.values()) {
      if (p.kind !== "segment" || !p.parent) continue;
      const device = this.layout.get(p.parent);
      const site = d.site.get(p.parent) ?? null;
      if (!device || (d.context && (site === null || !d.context.sites.has(site)))) continue;
      if (this.segmentsOf(p.parent).length === 0) continue;
      const dimmed = this.style.selected !== null && this.style.selected !== p.parent && !d.neighbors.has(p.parent);
      const c = dimmed ? mix(P.line, P.ghost, DIM_MIX) : rgb(P.line);
      const cv = p.v + p.h / 2;
      box("segment", p.uid, p.u + 0.2, cv - BAR_DEPTH / 2, p.w - 0.4, BAR_DEPTH, Y.bracketTop, Y.portTop, c);
      for (const t of [0.25, 0.5, 0.75]) {
        const u = p.u + 0.2 + (p.w - 0.4) * t - BAR_TICK / 2;
        box("segment", `${p.uid}#tick${t}`, u, cv - BAR_DEPTH / 2 - BAR_TICK_H, BAR_TICK, BAR_TICK_H, Y.bracketTop, Y.portTop, c);
      }
      const [su, sv] = [p.u + p.w / 2, cv - BAR_DEPTH / 2];
      edge("outline", "segment-stub", p.uid, [su, Y.portTop, sv], [su, Y.portTop, device.v + device.h - 0.1], c);
    }
  }

  /** The uid of the topmost element under screen point (x, y) at `level`. */
  pick(
    cam: CameraState,
    vp: Viewport,
    x: number,
    y: number,
    level: Level,
  ): string | null {
    const hit = (p: Placement, top: number) => {
      const [u, v] = toPlane(cam, vp, x, y, top);
      return u >= p.u && u <= p.u + p.w && v >= p.v && v <= p.v + p.h;
    };
    const order: [string, number, Level][] = [
      ["port", Y.portTop, 4],
      ["segment", Y.portTop, 3],
      ["device", Y.deviceTop, 3],
      ["line", 0, 1],
      ["block", Y.bandTop, 2],
      ["plate", Y.plateTop, 1],
    ];
    if (level === 4) {
      const [u, v] = toPlane(cam, vp, x, y, Y.portTop);
      for (const [uid, s] of this.wiring().sockets) {
        const r = Math.max(s.size, SOCKET_PICK) / 2;
        const cu = s.u + (s.nu * s.size) / 2;
        const cv = s.v + (s.nv * s.size) / 2;
        if (Math.abs(u - cu) <= r && Math.abs(v - cv) <= r) return uid;
      }
    }
    for (const [kind, top, from] of order) {
      if (level < from) continue;
      if (kind === "line") {
        const line = this.pickLine(cam, vp, x, y, level);
        if (line) return line;
        continue;
      }
      for (const p of this.layout.values()) {
        if (p.kind !== kind || !hit(p, top)) continue;
        // A segment bar picks its device; the panel opens the segments.
        return kind === "segment" ? (p.parent ?? p.uid) : p.uid;
      }
    }
    return null;
  }

  /** The cable or device pair whose line passes within `LINE_PICK_PX` of screen point (x, y): its cable key or its `pair_id`,
   *  else the tunnel line in range: its spoke or bundle id, or `tunnel:pair:` and the `pair_id` of a device pair arc.
   *  A cable in range wins over a summary line in range: the summary line of a pair with one tile loaded runs along the cables of that tile. */
  pickLine(
    cam: CameraState,
    vp: Viewport,
    x: number,
    y: number,
    level: Level,
  ): string | null {
    const lines = this.batches(level).lines;
    for (const cls of ["cable", "summary", "tunnel", "circuit"] as const) {
      let best: string | null = null;
      let near: number = LINE_PICK_PX;
      for (const l of lines) {
        if (l.cls !== cls) continue;
        for (let i = 0; i < l.ids.length; i++) {
          const o = i * 6;
          const [ax, ay] = toScreen(
            cam,
            vp,
            l.positions[o],
            l.positions[o + 2],
            l.positions[o + 1],
          );
          const [bx, by] = toScreen(
            cam,
            vp,
            l.positions[o + 3],
            l.positions[o + 5],
            l.positions[o + 4],
          );
          const dist = segmentDistance(x, y, ax, ay, bx, by);
          if (dist <= near) {
            near = dist;
            best = l.ids[i];
          }
        }
      }
      if (best) return cls === "tunnel" && !best.startsWith("tunnel:") ? `tunnel:pair:${best}` : best;
    }
    return null;
  }

  /**
   * The far ends of a chosen tunnel line, for the panel: a device pair arc (`tunnel:pair:` and its `pair_id`), a spoke
   * between two sites, or a bundle or a glowing own block from a site or a device to a country block.
   */
  tunnelDetail(id: string): { from: string; title: string; ends: { uid: string; tunnels: number }[] } | null {
    if (!id.startsWith("tunnel:")) return null;
    const d = this.derived();
    const edges = this.tunnelEdges(d);
    const rest = id.slice("tunnel:".length);
    if (rest.startsWith("pair:")) {
      const pair = rest.slice("pair:".length);
      const edge = edges.find(([e]) => String(e.pair_id) === pair);
      if (!edge) return null;
      const [e, pa, pb] = edge;
      return { from: pa.uid, title: pb.uid, ends: [{ uid: pb.uid, tunnels: count(e, "tunnel_count") }] };
    }
    const cut = rest.lastIndexOf("|");
    const [from, to] = [rest.slice(0, cut), rest.slice(cut + 1)];
    const ends = new Map<string, number>();
    const farOf = (pa: Placement, pb: Placement) => (pa.uid === from ? pb.uid : pb.uid === from ? pa.uid : null);
    for (const [e, pa, pb] of edges) {
      const n = count(e, "tunnel_count");
      if (this.layout.get(from)?.kind === "device") {
        const far = farOf(pa, pb);
        const site = far ? (d.site.get(far) ?? null) : null;
        if (far && site && this.regionOf(site) === to) ends.set(far, (ends.get(far) ?? 0) + n);
        continue;
      }
      const sa = d.site.get(pa.uid) ?? null;
      const sb = d.site.get(pb.uid) ?? null;
      const far = sa === from ? sb : sb === from ? sa : null;
      if (far && far !== from && (far === to || this.regionOf(far) === to)) ends.set(far, (ends.get(far) ?? 0) + n);
    }
    if (ends.size === 0) return null;
    return { from, title: to, ends: [...ends].map(([uid, tunnels]) => ({ uid, tunnels })) };
  }

  /** The loaded and unloaded blocks whose band is on the screen. */
  visibleBlocks(cam: CameraState, vp: Viewport): string[] {
    const out: string[] = [];
    for (const p of this.layout.values()) {
      if (
        p.kind === "block" &&
        onScreen(cam, vp, { u0: p.u, v0: p.v, u1: p.u + p.w, v1: p.v + p.h })
      )
        out.push(p.uid);
    }
    return out;
  }
}
