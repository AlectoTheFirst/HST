/**
 * The geometry of the stack and of the path on it.
 */

import { Vector3 } from "three";
import type { SceneCell, SceneDescription, SceneNode } from "./scene";
import {
  CELL,
  GRID_HEX_RADIUS,
  LANE_SPACING,
  PLATE_MARGIN_X,
  PLATE_MARGIN_Z,
  clamp,
  hexCorners,
  sceneStationKey,
  type PositionedNode,
} from "./view-helpers";

// --- plate footprint and its hex grid ------------------------------------------

export interface PlateBounds {
  minX: number;
  maxX: number;
  minZ: number;
  maxZ: number;
}

/** The least depth a plate may have along the lane axis, in lane widths. */
export const PLATE_MIN_LANES = 4;

/** Widens a footprint about its own centre until it is at least
 *  `PLATE_MIN_LANES` lane widths deep. Never narrows one. */
export function withMinimumDepth(bounds: PlateBounds): PlateBounds {
  const wanted = PLATE_MIN_LANES * LANE_SPACING;
  const depth = bounds.maxZ - bounds.minZ;
  if (depth >= wanted) return bounds;
  const centre = (bounds.minZ + bounds.maxZ) / 2;
  return { ...bounds, minZ: centre - wanted / 2, maxZ: centre + wanted / 2 };
}

/** The padded footprint covering every cell handed in. */
export function plateBounds(cells: SceneCell[]): PlateBounds {
  if (cells.length === 0) {
    return withMinimumDepth({
      minX: -PLATE_MARGIN_X,
      maxX: PLATE_MARGIN_X,
      minZ: -PLATE_MARGIN_Z,
      maxZ: PLATE_MARGIN_Z,
    });
  }
  let minX = Infinity;
  let maxX = -Infinity;
  let minZ = Infinity;
  let maxZ = -Infinity;
  for (const c of cells) {
    const x = c.q * CELL;
    const z = c.r * LANE_SPACING;
    minX = Math.min(minX, x);
    maxX = Math.max(maxX, x);
    minZ = Math.min(minZ, z);
    maxZ = Math.max(maxZ, z);
  }
  return withMinimumDepth({
    minX: minX - PLATE_MARGIN_X,
    maxX: maxX + PLATE_MARGIN_X,
    minZ: minZ - PLATE_MARGIN_Z,
    maxZ: maxZ + PLATE_MARGIN_Z,
  });
}

/** The one footprint every layer plate uses. */
export function sceneFootprint(nodes: SceneNode[]): PlateBounds {
  return plateBounds(nodes.map((n) => n.cell));
}

/** Hex-grid line-segment endpoints (each quad is one segment: x1,z1,x2,z2). */
export function hexGridSegments(bounds: PlateBounds, radius: number = GRID_HEX_RADIUS): number[] {
  const corners = hexCorners(radius);
  const stepX = radius * 1.5;
  const stepZ = radius * Math.sqrt(3);
  const segments: number[] = [];
  const cols = Math.ceil((bounds.maxX - bounds.minX) / stepX) + 2;
  const rows = Math.ceil((bounds.maxZ - bounds.minZ) / stepZ) + 2;
  for (let col = -1; col < cols; col++) {
    for (let row = -1; row < rows; row++) {
      const cx = bounds.minX + col * stepX;
      const cz = bounds.minZ + row * stepZ + (col % 2 !== 0 ? stepZ / 2 : 0);
      if (cx < bounds.minX - radius || cx > bounds.maxX + radius) continue;
      if (cz < bounds.minZ - radius || cz > bounds.maxZ + radius) continue;
      for (let i = 0; i < 6; i++) {
        const [x1, z1] = corners[i];
        const [x2, z2] = corners[(i + 1) % 6];
        segments.push(cx + x1, cz + z1, cx + x2, cz + z2);
      }
    }
  }
  return segments;
}

export function clipSegmentsToBounds(segments: number[], bounds: PlateBounds): number[] {
  const out: number[] = [];
  for (let i = 0; i < segments.length; i += 4) {
    const x1 = segments[i];
    const z1 = segments[i + 1];
    const dx = segments[i + 2] - x1;
    const dz = segments[i + 3] - z1;
    let t0 = 0;
    let t1 = 1;
    const p = [-dx, dx, -dz, dz];
    const q = [x1 - bounds.minX, bounds.maxX - x1, z1 - bounds.minZ, bounds.maxZ - z1];
    let inside = true;
    for (let k = 0; k < 4; k++) {
      if (p[k] === 0) {
        if (q[k] < 0) {
          inside = false;
          break;
        }
        continue;
      }
      const r = q[k] / p[k];
      if (p[k] < 0) {
        if (r > t1) {
          inside = false;
          break;
        }
        if (r > t0) t0 = r;
      } else {
        if (r < t0) {
          inside = false;
          break;
        }
        if (r < t1) t1 = r;
      }
    }
    if (!inside || t1 <= t0) continue;
    out.push(x1 + dx * t0, z1 + dz * t0, x1 + dx * t1, z1 + dz * t1);
  }
  return out;
}

// --- flatten interpolation -----------------------------------------------------

/**
 * The Y of each plate, given a per-layer flatten amount in [0, 1] (0 = the
 * plate stands at full height, 1 = flat).
 */
export function layerOffsets(layerCount: number, gap: number, flatten: readonly number[]): number[] {
  const amount = (i: number) => clamp(flatten[i] ?? 0, 0, 1);
  const out: number[] = [];
  let y = 0;
  for (let i = 0; i < layerCount; i++) {
    if (i > 0) y += gap * (1 - (i === 1 ? Math.max(amount(0), amount(1)) : amount(i)));
    out.push(y);
  }
  return out;
}

/** Total vertical span of the stack at these offsets. */
export function stackHeight(offsets: readonly number[]): number {
  if (offsets.length === 0) return 0;
  return offsets[offsets.length - 1] - offsets[0];
}

export function flattenTargets(flat: ReadonlySet<number>, layerCount: number): number[] {
  return Array.from({ length: layerCount }, (_, i) => (flat.has(i) ? 1 : 0));
}

// --- the path itself -------------------------------------------------------------

export interface PathSegment {
  points: Vector3[];
  from: string;
  to: string;
  /** scene.ts's flag: the flow did not cross this segment. */
  dead: boolean;
  riser: boolean;
  fromLayer: number;
  toLayer: number;
  /** Distance along the owning route at which this segment starts. */
  offset: number;
  length: number;
}

interface PathRoute {
  segments: PathSegment[];
  length: number;
}

interface PathGeometry {
  routes: PathRoute[];
  /** Every segment, flattened out of the routes, in route order. */
  segments: PathSegment[];
}

interface Link {
  from: string;
  to: string;
  dead: boolean;
}

function polylineLength(points: Vector3[]): number {
  let total = 0;
  for (let i = 1; i < points.length; i++) total += points[i].distanceTo(points[i - 1]);
  return total;
}

/**
 * The points a single link contributes.
 *
 * Same layer: a straight run from A to B.
 */
export function linkPoints(from: Vector3, to: Vector3, crossesLayer: boolean): Vector3[] {
  if (!crossesLayer) return [from.clone(), to.clone()];
  const corner = new Vector3(to.x, from.y, to.z);
  if (corner.distanceTo(from) < 1e-9) return [from.clone(), to.clone()];
  return [from.clone(), corner, to.clone()];
}

/**
 * scene.ts's `edges` and `drops`, resolved against a position map and
 * joined into ordered routes.
 */
export function buildPathGeometry(
  scene: SceneDescription,
  positions: ReadonlyMap<string, PositionedNode>,
): PathGeometry {
  const links: Link[] = [...scene.edges, ...scene.drops];
  const outgoing = new Map<string, Link[]>();
  const hasIncoming = new Set<string>();
  for (const link of links) {
    if (!positions.has(link.from) || !positions.has(link.to)) continue;
    const bucket = outgoing.get(link.from);
    if (bucket) bucket.push(link);
    else outgoing.set(link.from, [link]);
    hasIncoming.add(link.to);
  }

  const used = new Set<Link>();
  const routes: PathRoute[] = [];

  function walk(start: string): void {
    const segments: PathSegment[] = [];
    let cursor = start;
    let offset = 0;
    for (;;) {
      const next = (outgoing.get(cursor) ?? []).find((l) => !used.has(l));
      if (!next) break;
      used.add(next);
      const a = positions.get(next.from)!;
      const b = positions.get(next.to)!;
      const points = linkPoints(a.position, b.position, a.node.layer !== b.node.layer);
      const length = polylineLength(points);
      segments.push({
        points,
        from: next.from,
        to: next.to,
        dead: next.dead,
        riser: a.node.layer !== b.node.layer,
        fromLayer: a.node.layer,
        toLayer: b.node.layer,
        offset,
        length,
      });
      offset += length;
      cursor = next.to;
    }
    if (segments.length > 0) routes.push({ segments, length: offset });
  }

  // Roots first, in the order scene.ts emitted their outgoing links.
  for (const link of links) {
    if (!hasIncoming.has(link.from)) walk(link.from);
  }
  // Then each fork, and last the links of a cycle unreachable from a root.
  for (const link of links) {
    if (!used.has(link)) walk(link.from);
  }

  return { routes, segments: routes.flatMap((r) => r.segments) };
}

// --- scene extents ---------------------------------------------------------------

export interface SceneBounds {
  min: Vector3;
  max: Vector3;
  center: Vector3;
  /** Half the diagonal. */
  radius: number;
}

export function sceneBounds(nodes: SceneNode[], offsets: readonly number[]): SceneBounds {
  const b = sceneFootprint(nodes);
  const minY = offsets.length ? Math.min(...offsets) : 0;
  const maxY = offsets.length ? Math.max(...offsets) : 0;
  const min = new Vector3(b.minX, minY, b.minZ);
  const max = new Vector3(b.maxX, maxY, b.maxZ);
  const center = min.clone().add(max).multiplyScalar(0.5);
  return { min, max, center, radius: max.distanceTo(min) / 2 };
}

export function pathCentroid(
  nodes: SceneNode[],
  positions: ReadonlyMap<string, PositionedNode>,
): Vector3 {
  const onPath = nodes.filter((n) => !n.dimmed);
  const chosen = onPath.length > 0 ? onPath : nodes;
  const sum = new Vector3();
  let count = 0;
  for (const node of chosen) {
    const p = positions.get(sceneStationKey(node));
    if (!p) continue;
    sum.add(p.position);
    count++;
  }
  return count > 0 ? sum.divideScalar(count) : new Vector3();
}
