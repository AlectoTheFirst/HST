import { describe, it, expect } from "vitest";
import { Vector3 } from "three";
import type { SceneDescription, SceneNode } from "./scene";
import {
  buildPathGeometry,
  clipSegmentsToBounds,
  flattenTargets,
  hexGridSegments,
  layerOffsets,
  linkPoints,
  pathCentroid,
  plateBounds,
  PLATE_MIN_LANES,
  sceneBounds,
  sceneFootprint,
  stackHeight,
  withMinimumDepth,
} from "./path";
import {
  CELL,
  DENSITY_DEFAULT,
  LANE_SPACING,
  PLATE_MARGIN_X,
  PLATE_MARGIN_Z,
  layerGap,
  positionNodes,
  sceneStationKey,
  slotX,
} from "./view-helpers";

const LAYER_COUNT = 4;
const GAP = layerGap(DENSITY_DEFAULT);

function node(overrides: Partial<SceneNode> & { rank: number; lane: number }): SceneNode {
  const { rank, lane } = overrides;
  return {
    uid: `u${rank}-${lane}`,
    kind: "Device",
    label: `hop ${rank}`,
    note: "",
    shared: lane === 0,
    layer: 0,
    cell: { q: rank, r: lane },
    dimmed: false,
    verdict: null,
    ...overrides,
  };
}

function makeScene(hops: number, lanes: number): SceneDescription {
  const nodes: SceneNode[] = [];
  for (let lane = 0; lane < lanes; lane++) {
    for (let rank = 0; rank < hops; rank++) {
      nodes.push(node({ rank, lane, layer: rank % LAYER_COUNT }));
    }
  }
  const edges: SceneDescription["edges"] = [];
  const drops: SceneDescription["drops"] = [];
  for (let lane = 0; lane < lanes; lane++) {
    for (let rank = 1; rank < hops; rank++) {
      const from = nodes.find((n) => n.lane === lane && n.rank === rank - 1)!;
      const to = nodes.find((n) => n.lane === lane && n.rank === rank)!;
      const link = { from: sceneStationKey(from), to: sceneStationKey(to), dead: false };
      if (from.layer === to.layer) edges.push(link);
      else drops.push(link);
    }
  }
  return { nodes, edges, drops, layerCount: LAYER_COUNT };
}

describe("the X invariant", () => {
  it("puts a hop slot at the same X on every layer and every lane", () => {
    const scene = makeScene(12, 4);
    const offsets = layerOffsets(LAYER_COUNT, GAP, []);
    const positions = positionNodes(scene.nodes, offsets);
    const byRank = new Map<number, number[]>();
    for (const n of scene.nodes) {
      const x = positions.get(sceneStationKey(n))!.position.x;
      const bucket = byRank.get(n.rank) ?? [];
      bucket.push(x);
      byRank.set(n.rank, bucket);
    }
    expect(byRank.size).toBe(12);
    for (const [rank, xs] of byRank) {
      for (const x of xs) expect(x).toBeCloseTo(slotX(rank), 12);
      expect(new Set(xs.map((x) => x.toFixed(9))).size).toBe(1);
    }
  });

  it("is unaffected by density, flatten state or lane", () => {
    const scene = makeScene(6, 3);
    const dense = positionNodes(scene.nodes, layerOffsets(LAYER_COUNT, layerGap(1.4), []));
    const loose = positionNodes(
      scene.nodes,
      layerOffsets(LAYER_COUNT, layerGap(4), [1, 0, 0, 1]),
    );
    for (const n of scene.nodes) {
      const key = sceneStationKey(n);
      expect(dense.get(key)!.position.x).toBeCloseTo(loose.get(key)!.position.x, 12);
      expect(dense.get(key)!.position.z).toBeCloseTo(loose.get(key)!.position.z, 12);
    }
  });

  it("spreads lanes along Z and only along Z", () => {
    const offsets = layerOffsets(LAYER_COUNT, GAP, []);
    const a = positionNodes([node({ rank: 3, lane: 0 })], offsets);
    const b = positionNodes([node({ rank: 3, lane: 2 })], offsets);
    const pa = [...a.values()][0].position;
    const pb = [...b.values()][0].position;
    expect(pb.x).toBeCloseTo(pa.x, 12);
    expect(pb.y).toBeCloseTo(pa.y, 12);
    expect(pb.z - pa.z).toBeCloseTo(2 * LANE_SPACING, 12);
  });
});

describe("risers", () => {
  it("splits a cross-layer link into a horizontal run and a vertical riser", () => {
    const from = new Vector3(0, 0, 0);
    const to = new Vector3(CELL, GAP, LANE_SPACING);
    const points = linkPoints(from, to, true);
    expect(points).toHaveLength(3);
    expect(points[1].x).toBeCloseTo(points[2].x, 12);
    expect(points[1].z).toBeCloseTo(points[2].z, 12);
    expect(points[1].y).toBeCloseTo(from.y, 12);
    expect(points[2].y).toBeCloseTo(to.y, 12);
  });

  it("leaves an in-layer link a straight two-point run", () => {
    const points = linkPoints(new Vector3(0, 0, 0), new Vector3(CELL, 0, 0), false);
    expect(points).toHaveLength(2);
  });

  it("collapses to two points when the layer change happens in place", () => {
    const points = linkPoints(new Vector3(1, 0, 2), new Vector3(1, GAP, 2), true);
    expect(points).toHaveLength(2);
  });

  it("puts every riser at the X of the slot the transition lands on", () => {
    const scene = makeScene(15, 2);
    const offsets = layerOffsets(LAYER_COUNT, GAP, []);
    const positions = positionNodes(scene.nodes, offsets);
    const geometry = buildPathGeometry(scene, positions);
    const risers = geometry.segments.filter((s) => s.riser);
    expect(risers.length).toBeGreaterThan(0);
    for (const segment of risers) {
      const points = segment.points;
      const a = points[points.length - 2];
      const b = points[points.length - 1];
      expect(a.x).toBeCloseTo(b.x, 12);
      expect(a.z).toBeCloseTo(b.z, 12);
      expect(Math.abs(a.y - b.y)).toBeGreaterThan(1e-6);
      const destination = positions.get(segment.to)!;
      expect(b.x).toBeCloseTo(slotX(destination.node.rank), 12);
      expect(a.x).toBeCloseTo(slotX(destination.node.rank), 12);
    }
  });

  it("covers each link in the scene once", () => {
    const scene = makeScene(9, 3);
    const positions = positionNodes(scene.nodes, layerOffsets(LAYER_COUNT, GAP, []));
    const geometry = buildPathGeometry(scene, positions);
    expect(geometry.segments).toHaveLength(scene.edges.length + scene.drops.length);
    const seen = new Set(geometry.segments.map((s) => `${s.from}->${s.to}`));
    expect(seen.size).toBe(geometry.segments.length);
  });

  it("stitches links into routes whose segment offsets run continuously", () => {
    const scene = makeScene(8, 1);
    const positions = positionNodes(scene.nodes, layerOffsets(LAYER_COUNT, GAP, []));
    const { routes } = buildPathGeometry(scene, positions);
    expect(routes.length).toBeGreaterThan(0);
    for (const route of routes) {
      let running = 0;
      for (const segment of route.segments) {
        expect(segment.offset).toBeCloseTo(running, 9);
        running += segment.length;
      }
      expect(route.length).toBeCloseTo(running, 9);
    }
  });

  it("starts each route where the previous segment ended", () => {
    const scene = makeScene(10, 1);
    const positions = positionNodes(scene.nodes, layerOffsets(LAYER_COUNT, GAP, []));
    const { routes } = buildPathGeometry(scene, positions);
    for (const route of routes) {
      for (let i = 1; i < route.segments.length; i++) {
        const previousEnd = route.segments[i - 1].points.at(-1)!;
        const nextStart = route.segments[i].points[0];
        expect(previousEnd.distanceTo(nextStart)).toBeLessThan(1e-9);
      }
    }
  });
});

describe("flatten interpolation", () => {
  it("is the plain stack when nothing is flattened", () => {
    for (const flatten of [[], [0, 0, 0, 0]]) {
      const offsets = layerOffsets(4, GAP, flatten);
      expect(offsets).toHaveLength(4);
      offsets.forEach((y, i) => expect(y).toBeCloseTo(i * GAP, 9));
    }
  });

  it("compresses the stack by one gap per flattened plate", () => {
    const full = stackHeight(layerOffsets(4, GAP, [0, 0, 0, 0]));
    expect(full).toBeCloseTo(3 * GAP, 9);
    for (const layer of [0, 1, 2, 3]) {
      const flatten = [0, 0, 0, 0];
      flatten[layer] = 1;
      const height = stackHeight(layerOffsets(4, GAP, flatten));
      expect(height).toBeCloseTo(2 * GAP, 9);
      expect(height).toBeLessThan(full);
    }
    expect(stackHeight(layerOffsets(4, GAP, [0, 1, 1, 0]))).toBeCloseTo(GAP, 9);
    expect(stackHeight(layerOffsets(4, GAP, [1, 1, 1, 1]))).toBeCloseTo(0, 9);
  });

  it("leaves no hole: a flattened plate lands on a neighbour", () => {
    const offsets = layerOffsets(4, GAP, [0, 1, 0, 0]);
    expect(offsets[1]).toBeCloseTo(offsets[0], 9);
    const top = layerOffsets(4, GAP, [0, 0, 0, 1]);
    expect(top[3]).toBeCloseTo(top[2], 9);
  });

  it("interpolates continuously", () => {
    const half = layerOffsets(4, GAP, [0, 0.5, 0, 0]);
    expect(half[1]).toBeCloseTo(GAP * 0.5, 9);
    expect(half[1]).toBeGreaterThan(layerOffsets(4, GAP, [0, 1, 0, 0])[1]);
    expect(half[1]).toBeLessThan(layerOffsets(4, GAP, [0, 0, 0, 0])[1]);
  });

  it("clamps an amount outside [0, 1]", () => {
    const offsets = layerOffsets(4, GAP, [0, -3, 9, 0]);
    for (let i = 1; i < offsets.length; i++) expect(offsets[i]).toBeGreaterThanOrEqual(offsets[i - 1]);
  });

  it("turns a toggled-off layer set into flatten targets", () => {
    expect(flattenTargets(new Set([1, 3]), 4)).toEqual([0, 1, 0, 1]);
    expect(flattenTargets(new Set(), 4)).toEqual([0, 0, 0, 0]);
  });
});

describe("plate footprint and grid", () => {
  it("pads the occupied slots on both axes, less along the lane axis", () => {
    const b = plateBounds([
      { q: 0, r: 0 },
      { q: 4, r: 6 },
    ]);
    expect(b.minX).toBeCloseTo(-PLATE_MARGIN_X, 9);
    expect(b.maxX).toBeCloseTo(4 * CELL + PLATE_MARGIN_X, 9);
    expect(b.minZ).toBeCloseTo(-PLATE_MARGIN_Z, 9);
    expect(b.maxZ).toBeCloseTo(6 * LANE_SPACING + PLATE_MARGIN_Z, 9);
    expect(PLATE_MARGIN_Z).toBeLessThan(PLATE_MARGIN_X);
  });

  it("gives a one-lane trace a plate at least four lane widths deep, centred on it", () => {
    const b = plateBounds([
      { q: 0, r: 0 },
      { q: 4, r: 0 },
    ]);
    expect(2 * PLATE_MARGIN_Z).toBeLessThan(PLATE_MIN_LANES * LANE_SPACING);
    expect(b.maxZ - b.minZ).toBeCloseTo(PLATE_MIN_LANES * LANE_SPACING, 9);
    expect(b.minZ + b.maxZ).toBeCloseTo(0, 9);
    expect(b.maxX - b.minX).toBeCloseTo(4 * CELL + 2 * PLATE_MARGIN_X, 9);
  });

  it("never narrows a plate that is already deeper than the floor", () => {
    const wide = plateBounds([
      { q: 0, r: 0 },
      { q: 1, r: 9 },
    ]);
    expect(wide.maxZ - wide.minZ).toBeGreaterThan(PLATE_MIN_LANES * LANE_SPACING);
    expect(withMinimumDepth(wide)).toEqual(wide);
  });

  it("gives every layer the one shared footprint", () => {
    const scene = makeScene(7, 2);
    const shared = sceneFootprint(scene.nodes);
    const perLayer = [0, 1, 2, 3].map((layer) =>
      plateBounds(scene.nodes.filter((n) => n.layer === layer).map((n) => n.cell)),
    );
    for (const b of perLayer) {
      expect(shared.minX).toBeLessThanOrEqual(b.minX);
      expect(shared.maxX).toBeGreaterThanOrEqual(b.maxX);
    }
  });

  it("returns a small centred box for an empty scene", () => {
    const b = plateBounds([]);
    expect(b.minX).toBeLessThan(0);
    expect(b.maxX).toBeGreaterThan(0);
  });

  it("clips the hex grid to the plate it sits on", () => {
    const b = plateBounds([{ q: 0, r: 0 }, { q: 5, r: 0 }]);
    const clipped = clipSegmentsToBounds(hexGridSegments(b), b);
    expect(clipped.length).toBeGreaterThan(0);
    for (let i = 0; i < clipped.length; i += 2) {
      expect(clipped[i]).toBeGreaterThanOrEqual(b.minX - 1e-6);
      expect(clipped[i]).toBeLessThanOrEqual(b.maxX + 1e-6);
      expect(clipped[i + 1]).toBeGreaterThanOrEqual(b.minZ - 1e-6);
      expect(clipped[i + 1]).toBeLessThanOrEqual(b.maxZ + 1e-6);
    }
  });
});

describe("scene extents", () => {
  it("bounds the whole stack and shrinks with it as plates flatten", () => {
    const scene = makeScene(10, 2);
    const full = sceneBounds(scene.nodes, layerOffsets(4, GAP, [0, 0, 0, 0]));
    const flattened = sceneBounds(scene.nodes, layerOffsets(4, GAP, [0, 1, 1, 0]));
    expect(full.max.y - full.min.y).toBeCloseTo(3 * GAP, 9);
    expect(flattened.max.y - flattened.min.y).toBeCloseTo(GAP, 9);
    expect(flattened.radius).toBeLessThan(full.radius);
  });

  it("centres the pivot on the path, ignoring off-path nodes", () => {
    const nodes = [
      node({ rank: 0, lane: 0 }),
      node({ rank: 2, lane: 0 }),
      node({ rank: 40, lane: 0, dimmed: true }),
    ];
    const positions = positionNodes(nodes, layerOffsets(4, GAP, []));
    const centroid = pathCentroid(nodes, positions);
    expect(centroid.x).toBeCloseTo(slotX(1), 9);
  });

  it("falls back to every node when nothing is on the path", () => {
    const nodes = [node({ rank: 0, lane: 0, dimmed: true }), node({ rank: 4, lane: 0, dimmed: true })];
    const positions = positionNodes(nodes, layerOffsets(4, GAP, []));
    expect(pathCentroid(nodes, positions).x).toBeCloseTo(slotX(2), 9);
  });
});
