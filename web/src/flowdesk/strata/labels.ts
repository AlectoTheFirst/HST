/** A chip never covers the path. */

import { Vector3, type Camera } from "three";
import type { SceneNode } from "./scene";
import { clamp, levelOfDetail } from "./view-helpers";

export interface Viewport {
  width: number;
  height: number;
}

// --- projection ------------------------------------------------------------------

interface ScreenProjection {
  x: number;
  y: number;
  /** false when the point is outside the camera's clip volume. */
  visible: boolean;
}

/** `camera`'s matrices must be current. */
export function projectToScreen(
  point: Vector3,
  camera: Camera,
  width: number,
  height: number,
): ScreenProjection {
  const p = point.clone().project(camera);
  return {
    x: (p.x * 0.5 + 0.5) * width,
    y: (-p.y * 0.5 + 0.5) * height,
    visible: p.z >= -1 && p.z <= 1,
  };
}

// --- plate occlusion ----------------------------------------------------------------

/** A plate as a horizontal rectangle, for the occlusion test. Nothing else
 *  in the scene occludes a label. */
export interface PlateOccluder {
  y: number;
  minX: number;
  maxX: number;
  minZ: number;
  maxZ: number;
}

/** `epsilon` keeps a label's own plate from counting as its occluder. */
export function isOccludedByPlate(
  point: Vector3,
  cameraPosition: Vector3,
  plates: readonly PlateOccluder[],
  epsilon = 1e-3,
): boolean {
  const dy = cameraPosition.y - point.y;
  if (Math.abs(dy) < 1e-9) return false;
  for (const plate of plates) {
    const t = (plate.y - point.y) / dy;
    if (t <= epsilon || t >= 1) continue;
    const x = point.x + (cameraPosition.x - point.x) * t;
    const z = point.z + (cameraPosition.z - point.z) * t;
    if (x >= plate.minX && x <= plate.maxX && z >= plate.minZ && z <= plate.maxZ) return true;
  }
  return false;
}

// --- priority ------------------------------------------------------------------------

/** The label tiers, as numbers the solver sorts on. Everything at
 *  `PATH` or above is a path label and is never dropped. */
export const LABEL_PRIORITY = {
  hovered: 6,
  selected: 5,
  verdict: 4,
  endpoint: 3,
  path: 2,
  offPath: 1,
} as const;

/** The lowest on-path priority. */
export const PATH_PRIORITY_FLOOR: number = LABEL_PRIORITY.path;

export function labelPriority(
  node: SceneNode,
  flags: { selected?: boolean; endpoint?: boolean; hovered?: boolean } = {},
): number {
  if (flags.hovered) return LABEL_PRIORITY.hovered;
  if (flags.selected) return LABEL_PRIORITY.selected;
  if (node.verdict) return LABEL_PRIORITY.verdict;
  // `dimmed` is scene.ts's off-path marker.
  if (node.dimmed) return LABEL_PRIORITY.offPath;
  return flags.endpoint ? LABEL_PRIORITY.endpoint : LABEL_PRIORITY.path;
}

// --- the solver -------------------------------------------------------------------------

/** Gap between two placed boxes. */
export const LABEL_GAP_PX = 5;
/** Horizontal offset from the node's projected point to the label's anchor. */
const LABEL_OFFSET_PX = 16;
/** Size of the dot a collapsed label leaves behind. */
const LABEL_DOT_PX = 9;

/** The clearance a chip keeps from the path, on top of its own height. */
export const LABEL_BAND_PAD_PX = 6;

/** Side of the path a hop's chip hangs from, alternating by hop number. */
type LabelSide = "above" | "below";

export function labelSide(rank: number): LabelSide {
  return rank % 2 === 0 ? "above" : "below";
}

/** Half-height of the no-label band around the path, for a chip this tall. */
export function bandHalfHeight(chipHeight: number): number {
  return chipHeight + LABEL_BAND_PAD_PX;
}

/** How many staggered rows a label may try before it collapses. */
const LABEL_STAGGER_ROWS = 10;

/** One screen-space run of the path tube, in CSS pixels. */
export interface ScreenSegment {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** True when `box` enters the no-label band around `segment`. */
export function intersectsPathBand(box: Box, segment: ScreenSegment, pad: number): boolean {
  const segMinX = Math.min(segment.x1, segment.x2) - LABEL_BAND_PAD_PX;
  const segMaxX = Math.max(segment.x1, segment.x2) + LABEL_BAND_PAD_PX;
  const left = Math.max(box.x, segMinX);
  const right = Math.min(box.x + box.w, segMaxX);
  if (left > right) return false;
  const run = segment.x2 - segment.x1;
  let yLo: number;
  let yHi: number;
  if (Math.abs(run) < 1e-6) {
    yLo = Math.min(segment.y1, segment.y2);
    yHi = Math.max(segment.y1, segment.y2);
  } else {
    const at = (x: number) =>
      segment.y1 + (segment.y2 - segment.y1) * clamp((x - segment.x1) / run, 0, 1);
    const a = at(left);
    const b = at(right);
    yLo = Math.min(a, b);
    yHi = Math.max(a, b);
  }
  return box.y < yHi + pad && box.y + box.h > yLo - pad;
}

/** Width of the x bins of path segments. */
const SEGMENT_BIN_PX = 128;

class SegmentIndex {
  private readonly bins = new Map<number, ScreenSegment[]>();
  private readonly empty: ScreenSegment[] = [];

  constructor(segments: readonly ScreenSegment[]) {
    for (const segment of segments) {
      const lo = Math.floor(
        (Math.min(segment.x1, segment.x2) - LABEL_BAND_PAD_PX) / SEGMENT_BIN_PX,
      );
      const hi = Math.floor(
        (Math.max(segment.x1, segment.x2) + LABEL_BAND_PAD_PX) / SEGMENT_BIN_PX,
      );
      for (let bin = lo; bin <= hi; bin++) {
        const bucket = this.bins.get(bin);
        if (bucket) bucket.push(segment);
        else this.bins.set(bin, [segment]);
      }
    }
  }

  blocks(box: Box, pad: number): boolean {
    if (this.bins.size === 0) return false;
    const lo = Math.floor(box.x / SEGMENT_BIN_PX);
    const hi = Math.floor((box.x + box.w) / SEGMENT_BIN_PX);
    for (let bin = lo; bin <= hi; bin++) {
      for (const segment of this.bins.get(bin) ?? this.empty) {
        if (intersectsPathBand(box, segment, pad)) return true;
      }
    }
    return false;
  }
}

export interface LabelRequest {
  key: string;
  /** The point the label hangs off: the node's top, in world space. */
  world: Vector3;
  width: number;
  height: number;
  priority: number;
  /** The hop number. Decides which side of the path the chip hangs from. */
  rank: number;
}

type LabelMode = "full" | "dot" | "hidden";

/** A chip that collapsed to a dot gets a standalone badge. */
export function badgeDisplay(mode: LabelMode): "chip" | "standalone" | "hidden" {
  if (mode === "full") return "chip";
  if (mode === "dot") return "standalone";
  return "hidden";
}

export interface PlacedLabel {
  key: string;
  /** Top-left of the chip (mode "full") or centre-left of the dot ("dot"). */
  x: number;
  y: number;
  mode: LabelMode;
  /** Which side of the path the chip hangs from. */
  side: LabelSide;
  /** The node's projected point, the end of the leader line. */
  anchorX: number;
  anchorY: number;
  /** A nearer plate stands between this label and the camera. */
  occluded: boolean;
}

interface PlanOptions {
  /** CSS pixels per hop slot, the input of the off-path zoom threshold. */
  slotPx: number;
  /** True during an orbit or pan gesture. */
  navigating?: boolean;
  /** The plates, for the occlusion test. Empty skips the test. */
  occluders?: readonly PlateOccluder[];
  cameraPosition?: Vector3;
  /** The path tube's screen-space runs. */
  pathSegments?: readonly ScreenSegment[];
  /** Boxes a standalone hop badge may occupy. A chip never covers one. */
  badges?: readonly Box[];
}

function overlaps(a: Box, b: Box): boolean {
  return !(
    a.x + a.w + LABEL_GAP_PX <= b.x ||
    b.x + b.w + LABEL_GAP_PX <= a.x ||
    a.y + a.h + LABEL_GAP_PX <= b.y ||
    b.y + b.h + LABEL_GAP_PX <= a.y
  );
}

/** The same camera and the same requests give the same placement. */
export function planLabels(
  requests: readonly LabelRequest[],
  camera: Camera,
  viewport: Viewport,
  options: PlanOptions,
): PlacedLabel[] {
  const lod = levelOfDetail(options.slotPx);
  const occluders = options.occluders ?? [];
  const cameraPosition = options.cameraPosition;
  const segments = new SegmentIndex(options.pathSegments ?? []);
  const badges = options.badges ?? [];

  const candidates = requests.map((request) => {
    const p = projectToScreen(request.world, camera, viewport.width, viewport.height);
    const onPath = request.priority >= PATH_PRIORITY_FLOOR;
    const side = labelSide(request.rank);
    const pad = bandHalfHeight(request.height);
    const x = p.x + LABEL_OFFSET_PX;
    const xLeft = p.x - LABEL_OFFSET_PX - request.width;
    // The chip hangs above the path for an even hop and below it for an odd one.
    const y = side === "above" ? p.y - pad - request.height : p.y + pad;
    const onScreen =
      p.visible &&
      p.x >= -LABEL_OFFSET_PX &&
      p.x <= viewport.width + LABEL_OFFSET_PX &&
      p.y >= -request.height &&
      p.y <= viewport.height + request.height;
    const occluded =
      occluders.length > 0 && cameraPosition
        ? isOccludedByPlate(request.world, cameraPosition, occluders)
        : false;
    const eligible =
      onScreen && (onPath || (lod.offPathLabels && !options.navigating && !occluded));
    return {
      request,
      onPath,
      side,
      pad,
      x,
      xLeft,
      y,
      anchorX: p.x,
      anchorY: p.y,
      onScreen,
      occluded,
      eligible,
    };
  });

  const order = [...candidates].sort((a, b) => {
    if (a.request.priority !== b.request.priority) return b.request.priority - a.request.priority;
    if (a.y !== b.y) return a.y - b.y;
    if (a.x !== b.x) return a.x - b.x;
    return a.request.key < b.request.key ? -1 : 1;
  });

  const placed: Box[] = [];
  const spots = new Map<string, Box>();
  for (const candidate of order) {
    if (!candidate.eligible) continue;
    const { width: w, height: h } = candidate.request;
    const step = h + LABEL_GAP_PX;
    // Rows climb away from the path on the label's own side, never across it.
    const direction = candidate.side === "above" ? -1 : 1;
    let spot: Box | null = null;
    for (let row = 0; row < LABEL_STAGGER_ROWS && !spot; row++) {
      for (const x of [candidate.x, candidate.xLeft]) {
        const box: Box = { x, y: candidate.y + direction * row * step, w, h };
        if (segments.blocks(box, candidate.pad)) continue;
        if (badges.some((badge) => overlaps(box, badge))) continue;
        if (placed.some((other) => overlaps(box, other))) continue;
        spot = box;
        break;
      }
    }
    if (!spot) continue;
    placed.push(spot);
    spots.set(candidate.request.key, spot);
  }

  return candidates.map((candidate) => {
    const spot = spots.get(candidate.request.key);
    if (spot) {
      return {
        key: candidate.request.key,
        x: spot.x,
        y: spot.y,
        mode: "full",
        side: candidate.side,
        anchorX: candidate.anchorX,
        anchorY: candidate.anchorY,
        occluded: candidate.occluded,
      };
    }
    // The component promotes a hovered label to `LABEL_PRIORITY.hovered`.
    const dot = candidate.onScreen && (candidate.onPath || candidate.eligible);
    return {
      key: candidate.request.key,
      x: candidate.anchorX - LABEL_DOT_PX / 2,
      y: candidate.anchorY - LABEL_DOT_PX / 2,
      mode: dot ? "dot" : "hidden",
      side: candidate.side,
      anchorX: candidate.anchorX,
      anchorY: candidate.anchorY,
      occluded: candidate.occluded,
    };
  });
}
