/**
 * The network map's layout, without a DOM: the planner's view model
 * (GET /api/topology) as an ELK graph, and the laid-out ELK graph as Cytoscape
 * elements.
 *
 * ELK lays out the whole hierarchy in one pass (`INCLUDE_CHILDREN`): sites,
 * their blocks, the redundancy groups in a block, and the devices. It layers
 * the drawing from the cable directions the planner set, outer end first, so
 * the WAN edge sits above the firewall and the firewall above the core. Inside
 * a block the tier is the partition, so core stays above distribution.
 *
 * A lateral cable (a peer-link, a cluster sync link) joins two devices at one
 * depth. It is left out of the layout.
 *
 * The tiered and the organic layouts of the page start from a flat graph
 * (`toFlatElkGraph`): the devices alone, with no box, layered the same way.
 *
 * Every cable is its own line. ELK routes the lines orthogonally; Cytoscape
 * draws a route as a `segments` edge, whose points are stated relative to the
 * line between the two ends (`segmentsFor`).
 */

import type { ElkExtendedEdge, ElkNode, LayoutOptions } from "elkjs/lib/elk-api";
import type { TopologyCable, TopologyModel, TopologyNode } from "../api/types";

export const DEVICE_HEIGHT = 40;
const DEVICE_MIN_WIDTH = 120;
/** px per caption character at the device label size, plus the padding */
const CHAR_WIDTH = 7.2;
const DEVICE_PADDING = 28;
const EXIT_HEIGHT = 24;

export function deviceWidth(label: string): number {
  return Math.max(DEVICE_MIN_WIDTH, Math.round(label.length * CHAR_WIDTH + DEVICE_PADDING));
}

const ROOT_OPTIONS: LayoutOptions = {
  "elk.algorithm": "layered",
  "elk.direction": "DOWN",
  "elk.hierarchyHandling": "INCLUDE_CHILDREN",
  "elk.edgeRouting": "ORTHOGONAL",
  // the room for the caption under each symbol and for the port tags on a line (look.ts)
  "elk.layered.spacing.nodeNodeBetweenLayers": "130",
  "elk.spacing.nodeNode": "56",
  "elk.spacing.edgeNode": "20",
  "elk.spacing.edgeEdge": "8",
  "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
  "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
  // the same model gives the same drawing (graphElements.ts has the same rule)
  "elk.randomSeed": "1",
};

/** A box holds its caption in its top padding. */
const COMPOUND_OPTIONS: Record<string, LayoutOptions> = {
  site: { "elk.padding": "[top=40,left=20,bottom=20,right=20]" },
  block: { "elk.padding": "[top=32,left=16,bottom=16,right=16]", "elk.partitioning.activate": "true" },
  group: { "elk.padding": "[top=26,left=10,bottom=10,right=10]" },
};

const exitId = (index: number) => `exit:${index}`;

/** A small box beside a device that a line ends at: a cable whose far end is
 *  outside the drawing (an exit), or the member ports of a LAG with no cable,
 *  one box per LAG. */
interface Stub {
  id: string;
  dev: string;
  port: string | null;
  label: string;
  /** the device at the far end of an exit; none for a loose LAG member */
  farName: string | null;
  /** the label at the stub's end of the line */
  farPort: string | null;
  source: string | null;
  kind: "exit" | "loose";
}

export function stubs(model: TopologyModel): Stub[] {
  const out: Stub[] = model.exits.map((e, i) => ({
    id: exitId(i),
    dev: e.dev,
    port: e.port,
    label: exitLabel(e.far_name, e.far_port),
    farName: e.far_name,
    farPort: e.far_port,
    source: e.source,
    kind: "exit",
  }));
  for (const lag of model.lags) {
    const ports = lag.ports_without_cable;
    if (ports.length === 0) continue;
    const name = lag.name ?? "LAG";
    out.push({
      id: `loose:${lag.id}:${ports.join(",")}`,
      dev: lag.dev,
      port: ports.join(", "),
      label: ports.length === 1 ? `${name} member, no cable` : `${name}, ${ports.length} members, no cable`,
      farName: null,
      farPort: null,
      source: null,
      kind: "loose",
    });
  }
  return out;
}

/** The ELK graph of a model. Lateral cables are left out; see the file note. */
export function toElkGraph(model: TopologyModel): ElkNode {
  const root: ElkNode = { id: "root", layoutOptions: ROOT_OPTIONS, children: [], edges: [] };
  const byId = new Map<string, ElkNode>();
  for (const n of model.nodes) byId.set(n.id, elkNode(n));
  for (const n of model.nodes) {
    const parent = n.parent ? byId.get(n.parent) : root;
    (parent ?? root).children!.push(byId.get(n.id)!);
  }
  const edges: ElkExtendedEdge[] = [];
  for (const c of model.cables) {
    if (c.lateral || !byId.has(c.from.dev) || !byId.has(c.to.dev)) continue;
    edges.push({ id: c.id, sources: [c.from.dev], targets: [c.to.dev] });
  }
  // a stub sits beside its device: one small box, one line to it
  for (const stub of stubs(model)) {
    const home = model.nodes.find((n) => n.id === stub.dev)?.parent;
    if (!byId.has(stub.dev) || !home) continue;
    byId.get(home)!.children!.push({ id: stub.id, width: deviceWidth(stub.label) - 20, height: EXIT_HEIGHT });
    edges.push({ id: `${stub.id}:cable`, sources: [stub.dev], targets: [stub.id] });
  }
  root.edges = edges;
  return root;
}

/** The flat ELK graph of a model: the devices and the stubs alone, with no
 *  site, block or HA box, so the cable directions alone layer the drawing,
 *  outer end first (the tiered layout). Lateral cables are left out, so the two
 *  ends of a peer-link stay on one row. */
export function toFlatElkGraph(model: TopologyModel): ElkNode {
  const { "elk.hierarchyHandling": _nested, ...flat } = ROOT_OPTIONS;
  const root: ElkNode = { id: "root", layoutOptions: flat, children: [], edges: [] };
  const devices = new Set<string>();
  for (const n of model.nodes) {
    if (n.kind !== "device") continue;
    devices.add(n.id);
    root.children!.push({ id: n.id, width: deviceWidth(n.label), height: DEVICE_HEIGHT });
  }
  const edges: ElkExtendedEdge[] = [];
  for (const c of model.cables) {
    if (c.lateral || !devices.has(c.from.dev) || !devices.has(c.to.dev)) continue;
    edges.push({ id: c.id, sources: [c.from.dev], targets: [c.to.dev] });
  }
  for (const stub of stubs(model)) {
    if (!devices.has(stub.dev)) continue;
    root.children!.push({ id: stub.id, width: deviceWidth(stub.label) - 20, height: EXIT_HEIGHT });
    edges.push({ id: `${stub.id}:cable`, sources: [stub.dev], targets: [stub.id] });
  }
  root.edges = edges;
  return root;
}

function elkNode(n: TopologyNode): ElkNode {
  if (n.kind === "device") {
    const layoutOptions: LayoutOptions = {};
    if (n.partition != null) layoutOptions["elk.partitioning.partition"] = String(n.partition);
    return { id: n.id, width: deviceWidth(n.label), height: DEVICE_HEIGHT, layoutOptions };
  }
  return { id: n.id, children: [], layoutOptions: COMPOUND_OPTIONS[n.kind] };
}

export function exitLabel(farName: string, farPort: string | null): string {
  return `to ${farName}${farPort ? ` ${farPort}` : ""}`;
}

export interface Point {
  x: number;
  y: number;
}

/** The absolute top-left corner of every laid-out node. ELK states a child
 *  relative to its parent. */
export function absolutePositions(laid: ElkNode): Map<string, Point & { width: number; height: number }> {
  const out = new Map<string, Point & { width: number; height: number }>();
  const walk = (node: ElkNode, ox: number, oy: number) => {
    for (const child of node.children ?? []) {
      const x = ox + (child.x ?? 0);
      const y = oy + (child.y ?? 0);
      out.set(child.id, { x, y, width: child.width ?? 0, height: child.height ?? 0 });
      walk(child, x, y);
    }
  };
  walk(laid, 0, 0);
  return out;
}

/** The Cytoscape `segments` values that draw a route through `bends`, for an
 *  edge with manual endpoints `start` and `end` (`edge-distances: endpoints`).
 *  Cytoscape puts a segment point at start + w * (end - start) + d * n, where n
 *  is the unit normal (-dy, dx) / l of the line from start to end. */
export function segmentsFor(start: Point, end: Point, bends: Point[]): { weights: number[]; distances: number[] } {
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  const l2 = dx * dx + dy * dy;
  const l = Math.sqrt(l2);
  const weights: number[] = [];
  const distances: number[] = [];
  if (l === 0) return { weights, distances };
  for (const p of bends) {
    const px = p.x - start.x;
    const py = p.y - start.y;
    weights.push((px * dx + py * dy) / l2);
    distances.push((-px * dy + py * dx) / l);
  }
  return { weights, distances };
}

export interface CyElement {
  group: "nodes" | "edges";
  data: Record<string, unknown>;
  position?: Point;
  classes?: string;
}

const round = (v: number) => Math.round(v * 100) / 100;

/** The Cytoscape elements of a laid-out model. Compound boxes take their size
 *  from their children, so only devices and exit stubs carry a position: the
 *  centre of the ELK box. */
export function toElements(model: TopologyModel, laid: ElkNode): CyElement[] {
  const pos = absolutePositions(laid);
  const devices = new Set(model.nodes.filter((n) => n.kind === "device").map((n) => n.id));
  // a device's position is the centre of its symbol, at the top of its box: the
  // box of a tiered layout with segments holds the caption under it (segrow.ts)
  const centre = (id: string): Point | null => {
    const p = pos.get(id);
    if (!p) return null;
    return { x: p.x + p.width / 2, y: devices.has(id) ? p.y + Math.min(p.height, DEVICE_HEIGHT) / 2 : p.y + p.height / 2 };
  };
  const out: CyElement[] = [];
  for (const n of model.nodes) {
    const data: Record<string, unknown> = { id: n.id, label: n.label, kind: n.kind };
    if (n.parent) data.parent = n.parent;
    if (n.kind === "device") {
      const p = pos.get(n.id);
      data.width = p?.width ?? deviceWidth(n.label);
      data.tier = n.tier ?? "";
      data.role = n.role ?? "";
      const stale = n.carried || n.carried_reason === "failed" ? " stale" : "";
      out.push({
        group: "nodes",
        data,
        position: centre(n.id) ?? { x: 0, y: 0 },
        classes: `device tier-${n.tier ?? "none"}${stale}`,
      });
    } else {
      out.push({ group: "nodes", data, classes: n.kind + (n.block_kind ? ` block-${n.block_kind}` : "") });
    }
  }
  const placed = stubs(model).filter((stub) => pos.has(stub.id));
  for (const stub of placed) {
    const home = model.nodes.find((n) => n.id === stub.dev)?.parent;
    if (!home) continue;
    out.push({
      group: "nodes",
      data: { id: stub.id, parent: home, label: stub.label, kind: stub.kind, width: pos.get(stub.id)!.width },
      position: centre(stub.id)!,
      classes: stub.kind === "exit" ? "exit" : "exit loose",
    });
  }

  const routes = edgeRoutes(laid, pos);
  const lags = lagOf(model);
  for (const c of model.cables) out.push(withLag(cableElement(c, routes.get(c.id), centre), lags.get(c.id)));
  for (const stub of placed) {
    const id = `${stub.id}:cable`;
    const cable = cableElement(
      { id, from: { dev: stub.dev, port: stub.port }, to: { dev: stub.id, port: stub.farPort }, source: stub.source, lateral: false },
      routes.get(id),
      centre,
    );
    out.push(stub.kind === "loose" ? { ...cable, classes: `${cable.classes} loose` } : cable);
  }
  return out;
}

interface Route {
  start: Point;
  end: Point;
  bends: Point[];
}

/** The absolute route of every laid-out edge. A section is stated relative to
 *  the edge's container, the node ELK names in `container`. */
function edgeRoutes(laid: ElkNode, pos: Map<string, Point>): Map<string, Route> {
  const out = new Map<string, Route>();
  const visit = (node: ElkNode) => {
    for (const edge of node.edges ?? []) {
      const section = edge.sections?.[0];
      if (!section) continue;
      const host = edge.container && edge.container !== "root" ? pos.get(edge.container) : undefined;
      const ox = host?.x ?? 0;
      const oy = host?.y ?? 0;
      const shift = (p: Point) => ({ x: p.x + ox, y: p.y + oy });
      out.set(edge.id, {
        start: shift(section.startPoint),
        end: shift(section.endPoint),
        bends: (section.bendPoints ?? []).map(shift),
      });
    }
    for (const child of node.children ?? []) visit(child);
  };
  visit(laid);
  return out;
}

function cableElement(c: TopologyCable, route: Route | undefined, centre: (id: string) => Point | null): CyElement {
  const data: Record<string, unknown> = {
    id: c.id,
    source: c.from.dev,
    target: c.to.dev,
    sourcePort: c.from.port ?? "",
    targetPort: c.to.port ?? "",
  };
  const from = centre(c.from.dev);
  const to = centre(c.to.dev);
  if (!route || !from || !to || route.bends.length === 0) {
    return { group: "edges", data, classes: c.lateral ? "cable lateral" : "cable" };
  }
  const { weights, distances } = segmentsFor(route.start, route.end, route.bends);
  data.sourceEndpoint = `${round(route.start.x - from.x)}px ${round(route.start.y - from.y)}px`;
  data.targetEndpoint = `${round(route.end.x - to.x)}px ${round(route.end.y - to.y)}px`;
  data.segmentWeights = weights.map(round).join(" ");
  data.segmentDistances = distances.map(round).join(" ");
  return { group: "edges", data, classes: "cable routed" };
}

/** The block a node sits in: itself for a block, else its nearest block ancestor. */
function blockOf(id: string, parents: Map<string, TopologyNode>): string | null {
  let n = parents.get(id);
  while (n && n.kind !== "block") n = n.parent ? parents.get(n.parent) : undefined;
  return n?.id ?? null;
}

/** Level 2 of a site: one line per pair of blocks with the count of the cables
 *  between them. */
export function blockBundles(model: TopologyModel): CyElement[] {
  const byId = new Map(model.nodes.map((n) => [n.id, n]));
  const counts = new Map<string, { a: string; b: string; count: number }>();
  for (const c of model.cables) {
    const a = blockOf(c.from.dev, byId);
    const b = blockOf(c.to.dev, byId);
    if (!a || !b || a === b) continue;
    const key = `${a}~${b}`;
    const bucket = counts.get(key) ?? { a, b, count: 0 };
    bucket.count += 1;
    counts.set(key, bucket);
  }
  return [...counts.entries()]
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))
    .map(([key, { a, b, count }]) => ({
      group: "edges" as const,
      data: { id: `bundle:${key}`, source: a, target: b, label: count === 1 ? "1 cable" : `${count} cables` },
      classes: "bundle",
    }));
}

/** Whether a cable crosses from one block to another: the cables a bundle
 *  stands for at level 2. */
export function crossesBlocks(model: TopologyModel): Set<string> {
  const byId = new Map(model.nodes.map((n) => [n.id, n]));
  const out = new Set<string>();
  for (const c of model.cables) {
    const a = blockOf(c.from.dev, byId);
    const b = blockOf(c.to.dev, byId);
    if (a && b && a !== b) out.add(c.id);
  }
  return out;
}

/** The elements with the positions people moved (GET /api/network-map/layouts).
 *  A stored position wins over ELK for that device or segment bar. A cable of
 *  a moved device loses its ELK route and is drawn straight; a drop of a moved device or bar is marked `moved`, for
 *  a right-angle route of its own (segrow.ts `routeMovedDrops`). A bar takes
 *  its tags and the ends of its drops along. Only devices and bars move: a box
 *  follows its children. */
export function withPositions(
  elements: CyElement[],
  positions: Record<string, { x: number; y: number }>,
): CyElement[] {
  const movable = (e: CyElement) => e.group === "nodes" && (e.data.kind === "device" || e.data.kind === "segbar");
  const shift = new Map<string, Point>();
  for (const e of elements) {
    const to = positions[e.data.id as string];
    if (!movable(e) || !to) continue;
    const from = e.position ?? to;
    shift.set(e.data.id as string, { x: to.x - from.x, y: to.y - from.y });
  }
  if (shift.size === 0) return elements;
  return elements.map((e) => {
    const id = e.data.id as string;
    if (e.group === "nodes") {
      if (shift.has(id)) return { ...e, position: { ...positions[id] } };
      const carried = shift.get(e.data.bar as string);
      return carried && e.position ? { ...e, position: { x: e.position.x + carried.x, y: e.position.y + carried.y } } : e;
    }
    if (!shift.has(e.data.source as string) && !shift.has(e.data.target as string) && !shift.has(e.data.bar as string)) return e;
    return { ...e, classes: unrouted(e.classes) };
  });
}

/** The drawing without a segment row. Its stored positions are keyed by the
 *  element id alone; a drawing with a row (`l2/<vid>`, `l3/<domain>`) keys
 *  them `<drawing>|<id>`. */
export const PLAIN_DRAWING = "phys";

const ofRow = (key: string) => key.startsWith("l2/") || key.startsWith("l3/");

/** The stored positions of one drawing, by element id. */
export function drawingPositions(
  all: Record<string, { x: number; y: number }>,
  drawing: string,
): Record<string, { x: number; y: number }> {
  const prefix = `${drawing}|`;
  const out: Record<string, { x: number; y: number }> = {};
  for (const [key, p] of Object.entries(all)) {
    if (drawing === PLAIN_DRAWING ? !ofRow(key) : key.startsWith(prefix)) out[drawing === PLAIN_DRAWING ? key : key.slice(prefix.length)] = p;
  }
  return out;
}

/** The stored positions with those of one drawing replaced by `mine`. */
export function withDrawingPositions(
  all: Record<string, { x: number; y: number }>,
  drawing: string,
  mine: Record<string, { x: number; y: number }>,
): Record<string, { x: number; y: number }> {
  const prefix = `${drawing}|`;
  const out = Object.fromEntries(
    Object.entries(all).filter(([key]) => (drawing === PLAIN_DRAWING ? ofRow(key) : !key.startsWith(prefix))),
  );
  for (const [id, p] of Object.entries(mine)) out[drawing === PLAIN_DRAWING ? id : prefix + id] = p;
  return out;
}

/** The classes of a cable drawn straight, without its ELK route or its way through the segment row. */
export function unrouted(classes: string | undefined): string {
  return (classes ?? "cable").replace(/\b(routed|via)\b/g, "").replace(/\s+/g, " ").trim() + " moved";
}

interface LagMark {
  /** the device the LAG is on: its end of the line carries the LAG name */
  dev: string;
  name: string;
  multi: boolean;
}

/** The LAG of each member cable. A cable can be a member at both ends (a LAG
 *  to a LAG); the first LAG by id names it, and both ends keep their ports. */
function lagOf(model: TopologyModel): Map<string, LagMark> {
  const out = new Map<string, LagMark>();
  for (const lag of [...model.lags].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    for (const cable of lag.cables) {
      if (!out.has(cable)) out.set(cable, { dev: lag.dev, name: lag.name ?? "LAG", multi: lag.multi_chassis });
    }
  }
  return out;
}

/** Level 4 of a LAG member cable: a shared halo, and the LAG name beside the
 *  port name at the LAG's end. A multi-chassis LAG, whose members reach two
 *  peers of one redundancy group, has its own halo; the join is inferred. */
function withLag(edge: CyElement, mark: LagMark | undefined): CyElement {
  if (!mark) return edge;
  const data: Record<string, unknown> = { ...edge.data, lag: mark.name };
  if (data.source === mark.dev) data.sourcePort = `${data.sourcePort} ${mark.name}`.trim();
  else if (data.target === mark.dev) data.targetPort = `${data.targetPort} ${mark.name}`.trim();
  return { ...edge, data, classes: `${edge.classes} lag${mark.multi ? " lag-multi" : ""}` };
}
