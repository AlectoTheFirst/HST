/** Two runs of one query draw the same picture. */

import type { ElementDefinition, LayoutOptions } from "cytoscape";
import type { DagreLayoutOptions } from "cytoscape-dagre";
import type { FcoseLayoutOptions } from "cytoscape-fcose";
import type { ResultGraph } from "../api/types";

/** Node box in model units, which is its size in device pixels at zoom 1. */
export const NODE_SIZE = 34;
/** Node caption size at zoom 1. */
export const LABEL_PX = 12;
export const EDGE_LABEL_PX = 10;

/** The zoom bounds are absolute. */
export const MIN_ZOOM = 0.05;
export const MAX_ZOOM = 4;

/** The categorical palette has 8 slots. */
export const SLOT_COUNT = 8;

/** Every label past the eighth gets this slot. */
export const OTHER_SLOT = SLOT_COUNT;

/** Slots are assigned by how many nodes have the label, then by name. */
export function slots(graph: ResultGraph): Map<string, number> {
  const ranked = [...counts(graph).entries()].sort(
    ([aKind, aCount], [bKind, bCount]) => bCount - aCount || aKind.localeCompare(bKind),
  );
  return new Map(ranked.map(([kind], i) => [kind, i < SLOT_COUNT ? i : OTHER_SLOT]));
}

/** The slots of a grown picture: every label already drawn keeps its slot for
 *  the life of the picture, so no drawn node changes colour or shape. A new
 *  label takes the lowest free slot, in the ranking order of `slots`, or
 *  OTHER_SLOT when none is free. */
export function growSlots(drawn: ReadonlyMap<string, number>, graph: ResultGraph): Map<string, number> {
  const out = new Map(drawn);
  const taken = new Set(drawn.values());
  for (const kind of slots(graph).keys()) {
    if (out.has(kind)) continue;
    let free = 0;
    while (free < SLOT_COUNT && taken.has(free)) free += 1;
    const slot = free < SLOT_COUNT ? free : OTHER_SLOT;
    out.set(kind, slot);
    taken.add(slot);
  }
  return out;
}

function counts(graph: ResultGraph): Map<string, number> {
  const tally = new Map<string, number>();
  for (const node of graph.nodes) {
    const kind = primaryLabel(node);
    tally.set(kind, (tally.get(kind) ?? 0) + 1);
  }
  return tally;
}

/** The longest drawn caption, in characters. */
export const CAPTION_MAX = 28;

function shorten(value: string): string {
  if (value.length <= CAPTION_MAX) return value;
  return `…${value.slice(value.length - (CAPTION_MAX - 1))}`;
}

export function captionFull(node: {
  labels: string[];
  properties: Record<string, unknown>;
}): string {
  for (const key of ["hostname", "name", "ip", "cidr", "address", "uid"]) {
    const value = node.properties[key];
    if (typeof value === "string" && value) return value;
  }
  return node.labels[0] ?? "node";
}

/** The drawn caption: `captionFull`, shortened. `captionFull` keeps the
 *  whole value for the property panel and the text alternative. */
export function caption(node: { labels: string[]; properties: Record<string, unknown> }): string {
  return shorten(captionFull(node));
}

/** The label a node is coloured and grouped by. `_ordered_labels` in
 *  app/tables.py puts the collector's own label first. */
export function primaryLabel(node: { labels: string[] }): string {
  return node.labels[0] ?? "node";
}

/** Spacing of the start spiral, in model units. */
const START_STEP = 60;
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/** The start position of the node at `index`: a spiral that depends on the
 *  element order only, never on the stage size. */
export function startPosition(index: number): { x: number; y: number } {
  const r = START_STEP * Math.sqrt(index);
  const a = index * GOLDEN_ANGLE;
  return { x: Math.round(r * Math.cos(a) * 100) / 100, y: Math.round(r * Math.sin(a) * 100) / 100 };
}

export function toElements(graph: ResultGraph, slot: ReadonlyMap<string, number> = slots(graph)): ElementDefinition[] {
  const present = new Set(graph.nodes.map((n) => n.id));
  const nodes: ElementDefinition[] = graph.nodes.map((node, index) => ({
    group: "nodes",
    position: startPosition(index),
    data: {
      id: node.id,
      caption: caption(node),
      full: captionFull(node),
      kind: primaryLabel(node),
      slot: slot.get(primaryLabel(node)) ?? OTHER_SLOT,
    },
  }));
  const edges: ElementDefinition[] = graph.relationships
    // Cytoscape rejects the whole batch over an edge whose endpoint the server
    // capped away.
    .filter((rel) => present.has(rel.start) && present.has(rel.end))
    .map((rel) => ({
      group: "edges",
      data: { id: rel.id, source: rel.start, target: rel.end, type: rel.type },
    }));
  return [...nodes, ...edges];
}

export interface LegendEntry {
  kind: string;
  slot: number;
  count: number;
}

export function legend(graph: ResultGraph, slot: ReadonlyMap<string, number> = slots(graph)): LegendEntry[] {
  const tally = counts(graph);
  return [...slot.entries()]
    .filter(([kind]) => tally.has(kind))
    .sort(([, a], [, b]) => a - b)
    .map(([kind, slot]) => ({
    kind,
    slot,
    count: tally.get(kind) ?? 0,
  }));
}

export const LAYOUTS = [
  { name: "fcose", label: "Force" },
  { name: "dagre", label: "Layered" },
  { name: "breadthfirst", label: "Tree" },
  { name: "concentric", label: "Concentric" },
  { name: "circle", label: "Circle" },
  { name: "grid", label: "Grid" },
] as const;

export type LayoutName = (typeof LAYOUTS)[number]["name"];

export const DEFAULT_LAYOUT: LayoutName = "fcose";

/** The extensions declare their own option types, and Cytoscape's own union
 *  knows the built-in layouts only. */
export type GraphLayoutOptions = FcoseLayoutOptions | DagreLayoutOptions | LayoutOptions;

/** Padding between the outermost node and the viewport edge, in model units. */
const PAD = 28;

/** The most the ideal edge length grows over its 12-node value. */
export const MAX_SPREAD = 1.3;

export function layoutOptions(name: LayoutName, nodeCount: number): GraphLayoutOptions {
  // The ideal edge grows with sqrt(n), up to MAX_SPREAD.
  const spread = Math.min(MAX_SPREAD, Math.max(1, Math.sqrt(nodeCount / 12)));
  const common = { animate: false as const, fit: true, padding: PAD, nodeDimensionsIncludeLabels: true };

  switch (name) {
    case "fcose":
      return {
        name: "fcose",
        // fcose accepts `randomize: false` only at "proof" quality.
        quality: "proof",
        randomize: false,
        ...common,
        idealEdgeLength: 100 * spread,
        nodeRepulsion: 6000,
      } satisfies FcoseLayoutOptions;
    case "dagre":
      return {
        name: "dagre",
        ...common,
        rankDir: "TB",
        nodeSep: 40,
        edgeSep: 12,
        rankSep: 100,
      } satisfies DagreLayoutOptions;
    case "breadthfirst":
      return { name: "breadthfirst", ...common, directed: true, grid: true, spacingFactor: 1.3 };
    case "concentric":
      return { name: "concentric", ...common, minNodeSpacing: 28 };
    case "circle":
      return { name: "circle", ...common, spacingFactor: 1.2 };
    case "grid":
      return { name: "grid", ...common, avoidOverlapPadding: 16 };
  }
}

/** The most nodes a grown picture holds. A growth past it adds no more nodes
 *  and marks the picture partial. */
export const MAX_GROWN_NODES = 500;

/** Add a payload to a picture, each node and relationship once. The order of
 *  `into` is kept, so a grown graph lays out from the same element order. Past
 *  `cap` nodes no node is added, a relationship to a node that is not drawn is
 *  dropped, and the picture is marked truncated. */
export function mergeGraphs(into: ResultGraph, add: ResultGraph | undefined, cap = MAX_GROWN_NODES): ResultGraph {
  if (!add) return into;
  const nodes = new Map(into.nodes.map((n) => [n.id, n]));
  let dropped = false;
  for (const n of add.nodes) {
    if (nodes.has(n.id) || nodes.size < cap) nodes.set(n.id, n);
    else dropped = true;
  }
  const rels = new Map(into.relationships.map((r) => [r.id, r]));
  for (const r of add.relationships) if (nodes.has(r.start) && nodes.has(r.end)) rels.set(r.id, r);
  const truncated = into.truncated || add.truncated || dropped;
  return { nodes: [...nodes.values()], relationships: [...rels.values()], truncated };
}

/** True when `next` holds every node already drawn. */
export function extendsDrawn(drawn: ReadonlySet<string>, next: ResultGraph): boolean {
  if (drawn.size === 0) return false;
  const ids = new Set(next.nodes.map((n) => n.id));
  for (const id of drawn) if (!ids.has(id)) return false;
  return true;
}

export interface Point {
  x: number;
  y: number;
}

/** Each new node starts on a ring around the drawn node it connects to. */
export function seedPositions(graph: ResultGraph, placed: ReadonlyMap<string, Point>): Map<string, Point> {
  const anchor = new Map<string, string>();
  for (const rel of graph.relationships) {
    if (placed.has(rel.start) && !placed.has(rel.end) && !anchor.has(rel.end)) anchor.set(rel.end, rel.start);
    if (placed.has(rel.end) && !placed.has(rel.start) && !anchor.has(rel.start)) anchor.set(rel.start, rel.end);
  }
  const rings = new Map<string | null, string[]>();
  for (const node of graph.nodes) {
    if (placed.has(node.id)) continue;
    const key = anchor.get(node.id) ?? null;
    rings.set(key, [...(rings.get(key) ?? []), node.id]);
  }
  let right = 0;
  let sumY = 0;
  for (const p of placed.values()) {
    right = Math.max(right, p.x);
    sumY += p.y;
  }
  const loose: Point = { x: right + 4 * NODE_SIZE, y: placed.size > 0 ? sumY / placed.size : 0 };
  const seeds = new Map<string, Point>();
  for (const [key, ids] of rings) {
    const centre = key === null ? loose : placed.get(key)!;
    // room for a node and its caption on the ring, never closer than one edge
    const radius = Math.max(110, (ids.length * 2 * NODE_SIZE) / (2 * Math.PI));
    ids.forEach((id, i) => {
      const angle = (2 * Math.PI * i) / ids.length;
      seeds.set(id, { x: centre.x + radius * Math.cos(angle), y: centre.y + radius * Math.sin(angle) });
    });
  }
  return seeds;
}

/** The force layout holds every drawn node where it is. */
export function growthLayoutOptions(
  name: LayoutName,
  nodeCount: number,
  fixed: ReadonlyMap<string, Point>,
): GraphLayoutOptions {
  const options = layoutOptions(name, nodeCount);
  if (options.name !== "fcose") return options;
  return {
    ...(options as FcoseLayoutOptions),
    // a growth keeps the zoom and the pan: the viewport moves only as far as
    // the new nodes need (GraphView)
    fit: false,
    fixedNodeConstraint: [...fixed].map(([nodeId, position]) => ({ nodeId, position })),
  } satisfies FcoseLayoutOptions;
}
