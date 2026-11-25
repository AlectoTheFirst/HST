import type { Theme } from "./style";

export type Row = Record<string, unknown>;

export type TableName =
  | "layout"
  | "render_t0"
  | "render_t1"
  | "render_t1_edges"
  | "render_t1_circuits"
  | "render_t1_fabric_ports"
  | "render_t1_contexts"
  | "context_identity"
  | "render_t2_ports"
  | "render_t2_cables"
  | "render_t2_contexts"
  | "render_t2_segments"
  | "render_t2_port_groups";

/** The key columns of each table, joined with "|" like `key_of` in `hst/map/tiers/schemas.py`. */
export const KEYS: Record<TableName, readonly string[]> = {
  layout: ["uid"],
  render_t0: ["uid"],
  render_t1: ["uid"],
  render_t1_edges: ["pair_id"],
  render_t1_circuits: ["uid"],
  render_t1_fabric_ports: ["uid"],
  render_t1_contexts: ["device_uid", "context_uid"],
  context_identity: ["identity_uid"],
  render_t2_ports: ["uid"],
  render_t2_cables: ["cable_id"],
  render_t2_contexts: ["device_uid", "uid"],
  render_t2_segments: ["uid"],
  render_t2_port_groups: ["device_uid", "group_key"],
};

export function keyOf(name: TableName, row: Row): string {
  return KEYS[name].map((k) => String(row[k])).join("|");
}

/** One element after a scrub step: its row at t, or null when it is absent at t. */
export interface ElementChange {
  key: string;
  row: Row | null;
}

/** `u`, `v`: the plane point at the viewport center. `zoom`: pixels per grid unit. `view`: the isometric
 *  3D view, the default, or the 2D view straight down. */
export interface CameraState {
  u: number;
  v: number;
  zoom: number;
  view?: "iso" | "top";
}

export interface Viewport {
  width: number;
  height: number;
}

export type Level = 1 | 2 | 3 | 4;

/** One hop of a route on the plane. A blocked hop shows a stop marker. */
export interface RoutePoint {
  u: number;
  v: number;
  /** The height of the point; a point on a tunnel arc rises above the route's own height. */
  y?: number;
  label?: string;
  blocked?: boolean;
  /** A pin of a flow route: its start or end marker. */
  pin?: "start" | "end";
}

/**
 * How a route draws. `trace` is the directions of a handed-over trace. The others are application flow states
 * (web/src/applications/flows.ts), each with its own line pattern: passes
 * solid, fails solid red up to its stop marker, decided a thin solid line up to the first unknown step,
 * open dashed, not-evaluated dotted, unresolved no line at all.
 */
export type RouteState = "trace" | "passes" | "fails" | "decided" | "open" | "not-evaluated" | "unresolved";

/** A route on the plane: a line through its points, unless `line` is false, and its markers. */
export interface Route {
  id: string;
  state: RouteState;
  points: RoutePoint[];
  /** False for a route that only places markers (endpoint pins, a stop). */
  line?: boolean;
}

/** Whether `route` draws a line: two points or more, and not a marker-only route or an unresolved flow. */
export function drawsLine(route: Route): boolean {
  return route.line !== false && route.state !== "unresolved" && route.points.length > 1;
}

/** A route marker on the screen: the start pin, the end pin, a numbered hop, or a stop at a blocked hop. */
export interface Marker {
  kind: "start" | "end" | "hop" | "stop";
  text: string;
  x: number;
  y: number;
  at: [number, number, number];
}

export interface Label {
  uid: string;
  text: string;
  /** The screen point. */
  x: number;
  y: number;
  /** The world point the screen point projects from, x = u, z = v. */
  at: [number, number, number];
  kind: "region" | "site" | "block" | "device" | "port" | "tunnel" | "cluster" | "count" | "segment" | "stub";
  /** A site label of a hub site: named at every zoom. */
  hub?: boolean;
  /** The second line of a card label. */
  sub?: string;
  /** The tint of a card label's chip, as 0xrrggbb. */
  tint?: number;
  /** The icon key of a card label: a block kind, or `site`. */
  icon?: string;
}

export interface FrameStats {
  level: Level;
  drawCalls: number;
  instances: number;
  labels: Label[];
  markers: Marker[];
  /** True while a cross-fade or a symbol load needs more frames. */
  animating: boolean;
}

export interface Layers {
  physical: boolean;
  l2: boolean;
  l3: boolean;
}

/** A transport of the tunnels between one device pair, from the Tier 3 tunnel list. */
export interface Transport {
  encap: string;
  count: number;
}

export interface Style {
  changes: boolean;
  layers: Layers;
  selected: string | null;
  hovered: string | null;
  /** The selected site or block uid, drawn with a glow. */
  area: string | null;
  /** The chosen overlay line: a tunnel bundle or spoke id, `tunnel:pair:` and the `pair_id` of an arc, or a
   *  circuit line id. */
  tunnel: string | null;
  /** An `identity_uid` of `context_identity`, or null for every context. */
  context: string | null;
  /** Tunnel arcs expanded by transport, keyed by `pair_id`. */
  transports: ReadonlyMap<string, readonly Transport[]>;
  /** The devices on a shown application flow; when set, every other device is dimmed. */
  highlight: ReadonlySet<string> | null;
  theme: Theme;
}

export const DEFAULT_STYLE: Style = {
  changes: false,
  layers: { physical: true, l2: true, l3: true },
  selected: null,
  hovered: null,
  area: null,
  tunnel: null,
  context: null,
  transports: new Map(),
  highlight: null,
  theme: "light",
};

/** The map renderer. Nothing outside `web/src/hst/render/` imports three.js. */
export interface Renderer {
  setTier(name: TableName, rows: Row[], tile?: string): void;
  applyDelta(name: TableName, changes: ElementChange[], tile?: string): void;
  dropTile(tile: string): void;
  /** The routes to draw, in drawing order; an empty list clears them. */
  setRoutes(routes: Route[]): void;
  setStyle(style: Style): void;
  setCamera(camera: CameraState, viewport: Viewport): void;
  pick(x: number, y: number): string | null;
  frame(): FrameStats;
  dispose(): void;
}
