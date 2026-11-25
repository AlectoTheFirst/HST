/**
 * No function touches a WebGL context.
 */

import { Vector3 } from "three";
import type { Hop } from "../../api/types";
import type { Selection } from "../selection";
import type { SceneCell, SceneNode } from "./scene";

// --- CSS token resolution ---------------------------------------------------

/** The one set of kinds whose label is set in the mono font (Station.tsx). */
export { MONO_KINDS } from "../hopStyle";

/** theme.css's `--kind-fallback` light value. */
const HARD_FALLBACK = "#8b8f96";

function readVar(root: Element, name: string): string {
  return getComputedStyle(root).getPropertyValue(name).trim();
}

/** Reads `--kind-<kind>` off `root`, then `--kind-fallback`, then a hardcoded colour. */
export function resolveKindColor(kind: string, root: Element = document.documentElement): string {
  return readVar(root, `--kind-${kind}`) || readVar(root, "--kind-fallback") || HARD_FALLBACK;
}

export function resolveToken(
  name: string,
  hardFallback: string,
  root: Element = document.documentElement,
): string {
  return readVar(root, name) || hardFallback;
}

// --- colour maths -------------------------------------------------------------

interface Rgb {
  r: number;
  g: number;
  b: number;
}

export function clamp(value: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, value));
}

/** `#rgb`, `#rrggbb` or `rgb()/rgba()` to a channel triple, or null for any other string. */
export function parseCssColor(value: string): Rgb | null {
  const v = value.trim();
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(v);
  if (hex) {
    const h = hex[1];
    const full = h.length === 3 ? h[0] + h[0] + h[1] + h[1] + h[2] + h[2] : h;
    return {
      r: parseInt(full.slice(0, 2), 16),
      g: parseInt(full.slice(2, 4), 16),
      b: parseInt(full.slice(4, 6), 16),
    };
  }
  const rgb = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(v);
  if (rgb) return { r: Number(rgb[1]), g: Number(rgb[2]), b: Number(rgb[3]) };
  return null;
}

export function toHexColor({ r, g, b }: Rgb): string {
  const part = (c: number) => clamp(Math.round(c), 0, 255).toString(16).padStart(2, "0");
  return `#${part(r)}${part(g)}${part(b)}`;
}

/** WCAG relative luminance. */
export function relativeLuminance({ r, g, b }: Rgb): number {
  const channel = (c: number) => {
    const s = clamp(c, 0, 255) / 255;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/** `amount` of `fg` mixed into `bg`, in sRGB space. */
export function mixColor(fg: Rgb, bg: Rgb, amount: number): Rgb {
  const t = clamp(amount, 0, 1);
  return {
    r: fg.r * t + bg.r * (1 - t),
    g: fg.g * t + bg.g * (1 - t),
    b: fg.b * t + bg.b * (1 - t),
  };
}

export function isDarkBackground(bg: Rgb): boolean {
  return relativeLuminance(bg) < 0.5;
}

/** Rescales `colour`'s channels by a single factor until its relative
 *  luminance matches `reference`'s. */
export function matchLuminance(colour: Rgb, reference: Rgb): Rgb {
  const want = relativeLuminance(reference);
  let lo = 0;
  let hi = 4;
  let best = colour;
  for (let i = 0; i < 24; i++) {
    const k = (lo + hi) / 2;
    const scaled = { r: colour.r * k, g: colour.g * k, b: colour.b * k };
    best = scaled;
    if (relativeLuminance(scaled) < want) lo = k;
    else hi = k;
  }
  return { r: clamp(best.r, 0, 255), g: clamp(best.g, 0, 255), b: clamp(best.b, 0, 255) };
}

// --- plate palette -------------------------------------------------------------

/** How much `--text` is mixed into `--bg` for a plate's neutral base. */
const PLATE_MIX_LIGHT = 0.1;
const PLATE_MIX_DARK = 0.2;
const PLATE_EDGE_MIX_LIGHT = 0.19;
const PLATE_EDGE_MIX_DARK = 0.33;
/** The 1px rim around a plate. */
const PLATE_RIM_MIX_LIGHT = 0.28;
const PLATE_RIM_MIX_DARK = 0.46;
export const PLATE_OPACITY_LIGHT = 0.09;
export const PLATE_OPACITY_DARK = 0.12;
export const PLATE_RIM_OPACITY = 0.55;
export const PLATE_EDGE_OPACITY = 0.34;
export const HEX_GRID_OPACITY = 0.04;

/** The hue mixed into each layer's plate: 0 physical neutral gray, 1 routing
 *  cool gray-blue, 2 policy cool gray-violet, 3 application warm gray. */
const LAYER_HUE: ReadonlyArray<Rgb | null> = [
  null,
  { r: 0x5c, g: 0x84, b: 0xc2 }, // cool blue
  { r: 0x84, g: 0x6f, b: 0xc2 }, // cool violet
  { r: 0xc2, g: 0x99, b: 0x63 }, // warm
];

/** How far toward its hue anchor a plate is tinted before the luminance is
 *  matched back. */
const LAYER_HUE_MIX = 0.42;

export interface PlatePalette {
  /** The plate's surface colour, drawn at `opacity` without depth writes. */
  fill: string;
  opacity: number;
  /** The 1px rim around the footprint. */
  rim: string;
  /** The vertical thickness face under the surface, drawn at
   *  `PLATE_EDGE_OPACITY` and `PLATE_EDGE_HEIGHT` tall. */
  edge: string;
  /** The hex grid drawn on the surface, at `HEX_GRID_OPACITY`. */
  grid: string;
  dark: boolean;
}

/** Falls back to the light `:root` values when a token does not parse. */
export function platePalette(bgToken: string, textToken: string, layer: number): PlatePalette {
  const bg = parseCssColor(bgToken) ?? { r: 0xee, g: 0xf1, b: 0xf5 };
  const text = parseCssColor(textToken) ?? { r: 0x1c, g: 0x27, b: 0x33 };
  const dark = isDarkBackground(bg);
  const base = mixColor(text, bg, dark ? PLATE_MIX_DARK : PLATE_MIX_LIGHT);
  const rimBase = mixColor(text, bg, dark ? PLATE_RIM_MIX_DARK : PLATE_RIM_MIX_LIGHT);
  const edgeBase = mixColor(text, bg, dark ? PLATE_EDGE_MIX_DARK : PLATE_EDGE_MIX_LIGHT);
  const hue = LAYER_HUE[layer] ?? null;
  const tint = (c: Rgb) => (hue ? matchLuminance(mixColor(hue, c, LAYER_HUE_MIX), c) : c);
  return {
    fill: toHexColor(tint(base)),
    opacity: dark ? PLATE_OPACITY_DARK : PLATE_OPACITY_LIGHT,
    rim: toHexColor(tint(rimBase)),
    edge: toHexColor(tint(edgeBase)),
    grid: toHexColor(tint(rimBase)),
    dark,
  };
}

// --- geometry sizing ---------------------------------------------------------

/** World units per hop slot along X. */
export const CELL = 2.4;
/** World units per lane step along Z. */
export const LANE_SPACING = CELL * 1.15;
/** Circumradius of a node's flat-top hexagon, as a fraction of the hop slot. */
export const HEX_RADIUS = CELL * 0.33;
export const HEX_THICKNESS = HEX_RADIUS * 0.45;
/** The plate's own thickness, in the same node-radius unit. */
export const PLATE_EDGE_HEIGHT = HEX_RADIUS * 0.15;
export const CONTACT_SHADOW_RADIUS = HEX_RADIUS * 1.9;
export const CONTACT_SHADOW_OPACITY = 0.35;
export const NODE_HEIGHT = HEX_RADIUS * 2;

/** The layer gap as a multiple of `NODE_HEIGHT`. */
export const DENSITY_MIN = 1.4;
export const DENSITY_MAX = 4;
export const DENSITY_DEFAULT = 2.2;
export const DENSITY_STEP = 0.05;

/** World units between two adjacent plates at a given density. */
export function layerGap(density: number): number {
  return clamp(density, DENSITY_MIN, DENSITY_MAX) * NODE_HEIGHT;
}

/** Padding the plate footprint keeps past the outermost occupied slot. */
export const PLATE_MARGIN_X = CELL * 1.4;
export const PLATE_MARGIN_Z = CELL * 0.85;

export const GRID_HEX_RADIUS = CELL / Math.sqrt(3);

export function nodeWorldPosition(cell: SceneCell, layerY: number): Vector3 {
  return new Vector3(cell.q * CELL, layerY, cell.r * LANE_SPACING);
}

export function slotX(rank: number): number {
  return rank * CELL;
}

/** The flat-top hexagon's six corners, in local XZ space (a node extrudes
 *  along Y). */
export function hexCorners(radius: number): Array<[number, number]> {
  const corners: Array<[number, number]> = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i;
    corners.push([radius * Math.cos(angle), radius * Math.sin(angle)]);
  }
  return corners;
}

// --- station identity, placement, lookups -------------------------------------

/** The station-key format `uid:lane:rank`. */
export function sceneStationKey(n: { uid: string; lane: number; rank: number }): string {
  return `${n.uid}:${n.lane}:${n.rank}`;
}

export interface PositionedNode {
  node: SceneNode;
  position: Vector3;
}

/** Every scene node's world position, keyed by station key. */
export function positionNodes(
  nodes: SceneNode[],
  offsets: readonly number[],
): Map<string, PositionedNode> {
  const map = new Map<string, PositionedNode>();
  for (const node of nodes) {
    map.set(sceneStationKey(node), {
      node,
      position: nodeWorldPosition(node.cell, offsets[node.layer] ?? 0),
    });
  }
  return map;
}

export function findHopForNode(hops: Hop[], node: SceneNode): Hop | undefined {
  return hops.find((h) => h.uid === node.uid && h.lane === node.lane && h.rank === node.rank);
}

export function isSelectedNode(selection: Selection | null, node: SceneNode): boolean {
  return (
    selection?.type === "hop" &&
    selection.data.uid === node.uid &&
    selection.data.lane === node.lane &&
    selection.data.rank === node.rank
  );
}

// --- off-path treatment ---------------------------------------------------------

/** Opacity of off-path content: `dimmed` nodes and `dead` segments. */
export const OFF_PATH_OPACITY = 0.25;
/** How far an off-path node's colour is pulled toward gray. */
export const OFF_PATH_DESATURATION = 0.75;

export function desaturate(colour: Rgb, amount: number): Rgb {
  const gray = 0.2126 * colour.r + 0.7152 * colour.g + 0.0722 * colour.b;
  return mixColor({ r: gray, g: gray, b: gray }, colour, clamp(amount, 0, 1));
}

// --- layer flatten state ---------------------------------------------------------

/** The set of layer indices toggled off. */
export type FlatLayers = ReadonlySet<number>;

export function isLayerFlat(flat: FlatLayers, layer: number): boolean {
  return flat.has(layer);
}

export function toggleLayer(flat: FlatLayers, layer: number): FlatLayers {
  const next = new Set(flat);
  if (next.has(layer)) next.delete(layer);
  else next.add(layer);
  return next;
}

/** "Only" on the isolated layer restores the whole stack. */
export function isolateLayer(flat: FlatLayers, layer: number, layerCount: number): FlatLayers {
  const onlyThisStanding = layerCount - flat.size === 1 && !flat.has(layer);
  if (onlyThisStanding) return new Set();
  const next = new Set<number>();
  for (let i = 0; i < layerCount; i++) {
    if (i !== layer) next.add(i);
  }
  return next;
}

// --- level of detail ------------------------------------------------------------

/** Below this many CSS pixels per hop slot, off-path labels are not drawn. */
export const OFF_PATH_LABEL_SLOT_PX = 44;
/** Below this, the kind caption under a label is dropped before the label. */
export const CAPTION_SLOT_PX = 52;
export const GRID_SLOT_PX = 22;

interface LevelOfDetail {
  offPathLabels: boolean;
  captions: boolean;
  grid: boolean;
}

export function levelOfDetail(slotPx: number): LevelOfDetail {
  return {
    offPathLabels: slotPx >= OFF_PATH_LABEL_SLOT_PX,
    captions: slotPx >= CAPTION_SLOT_PX,
    grid: slotPx >= GRID_SLOT_PX,
  };
}
