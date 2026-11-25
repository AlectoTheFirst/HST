import { describe, it, expect } from "vitest";
import { Vector3 } from "three";
import type { SceneNode } from "./scene";
import {
  LABEL_BAND_PAD_PX,
  LABEL_GAP_PX,
  LABEL_PRIORITY,
  PATH_PRIORITY_FLOOR,
  badgeDisplay,
  bandHalfHeight,
  intersectsPathBand,
  isOccludedByPlate,
  labelPriority,
  labelSide,
  planLabels,
  projectToScreen,
  type Box,
  type LabelRequest,
  type PlacedLabel,
  type PlateOccluder,
  type ScreenSegment,
} from "./labels";
import { cameraFor, homeView } from "./camera";
import { layerOffsets, linkPoints, sceneBounds } from "./path";
import {
  DENSITY_DEFAULT,
  HEX_THICKNESS,
  OFF_PATH_LABEL_SLOT_PX,
  layerGap,
  positionNodes,
  sceneStationKey,
} from "./view-helpers";

const LAYER_COUNT = 4;
const GAP = layerGap(DENSITY_DEFAULT);
/** The test chip is larger than the real 11.5px/9px chip. */
const CHIP = { width: 132, height: 38 };

const PANES = [
  { name: "wide", width: 1440, height: 760 },
  { name: "narrow", width: 720, height: 520 },
];

function node(rank: number, lane: number, overrides: Partial<SceneNode> = {}): SceneNode {
  return {
    uid: `u${rank}-${lane}`,
    kind: "Device",
    label: `hop ${rank}`,
    note: "",
    rank,
    lane,
    shared: lane === 0,
    layer: rank % LAYER_COUNT,
    cell: { q: rank, r: lane },
    dimmed: false,
    verdict: null,
    ...overrides,
  };
}

function trace(hops: number, lanes: number): SceneNode[] {
  const nodes: SceneNode[] = [];
  for (let lane = 0; lane < lanes; lane++) {
    for (let rank = 0; rank < hops; rank++) nodes.push(node(rank, lane));
  }
  return nodes;
}

/** The badge box equals StrataView's BADGE_PX and BADGE_RISE_PX. */
const BADGE_PX = 16;
const BADGE_RISE_PX = 24;

function solveAtHome(nodes: SceneNode[], viewport: { width: number; height: number }) {
  const offsets = layerOffsets(LAYER_COUNT, GAP, []);
  const positions = positionNodes(nodes, offsets);
  const bounds = sceneBounds(nodes, offsets);
  const orbit = homeView(bounds, viewport.width / viewport.height);
  const camera = cameraFor(orbit, viewport);
  const maxRank = Math.max(...nodes.map((n) => n.rank));
  const requests: LabelRequest[] = nodes.map((n) => {
    const p = positions.get(sceneStationKey(n))!.position;
    return {
      key: sceneStationKey(n),
      world: new Vector3(p.x, p.y + HEX_THICKNESS + 0.05, p.z),
      width: CHIP.width,
      height: CHIP.height,
      rank: n.rank,
      priority: labelPriority(n, { endpoint: n.rank === 0 || n.rank === maxRank }),
    };
  });

  const pathSegments: ScreenSegment[] = [];
  const lanes = new Set(nodes.map((n) => n.lane));
  for (const lane of lanes) {
    const chain = nodes.filter((n) => n.lane === lane).sort((a, b) => a.rank - b.rank);
    for (let i = 1; i < chain.length; i++) {
      const a = chain[i - 1];
      const b = chain[i];
      const points = linkPoints(
        positions.get(sceneStationKey(a))!.position,
        positions.get(sceneStationKey(b))!.position,
        a.layer !== b.layer,
      );
      for (let k = 1; k < points.length; k++) {
        const p0 = projectToScreen(points[k - 1], camera, viewport.width, viewport.height);
        const p1 = projectToScreen(points[k], camera, viewport.width, viewport.height);
        if (!p0.visible || !p1.visible) continue;
        pathSegments.push({ x1: p0.x, y1: p0.y, x2: p1.x, y2: p1.y });
      }
    }
  }

  const badges: Box[] = [];
  for (const request of requests) {
    const p = projectToScreen(request.world, camera, viewport.width, viewport.height);
    if (!p.visible) continue;
    badges.push({
      x: p.x - BADGE_PX / 2,
      y: p.y - BADGE_RISE_PX - BADGE_PX / 2,
      w: BADGE_PX,
      h: BADGE_PX,
    });
  }

  const placed = planLabels(requests, camera, viewport, {
    slotPx: OFF_PATH_LABEL_SLOT_PX * 2,
    pathSegments,
    badges,
  });
  return { requests, placed, pathSegments, badges };
}

function overlapping(placed: PlacedLabel[], requests: LabelRequest[]): number {
  const byKey = new Map(requests.map((r) => [r.key, r]));
  const boxes = placed
    .filter((p) => p.mode === "full")
    .map((p) => {
      const r = byKey.get(p.key)!;
      return { x: p.x, y: p.y, w: r.width, h: r.height };
    });
  let count = 0;
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i];
      const b = boxes[j];
      const apart =
        a.x + a.w + LABEL_GAP_PX <= b.x ||
        b.x + b.w + LABEL_GAP_PX <= a.x ||
        a.y + a.h + LABEL_GAP_PX <= b.y ||
        b.y + b.h + LABEL_GAP_PX <= a.y;
      if (!apart) count++;
    }
  }
  return count;
}

describe("priority", () => {
  it("ranks selection over a verdict, a verdict over an endpoint, and an endpoint over a plain hop", () => {
    const plain = node(2, 0);
    expect(labelPriority(plain, { selected: true })).toBe(LABEL_PRIORITY.selected);
    expect(labelPriority(node(2, 0, { verdict: "bad" }))).toBe(LABEL_PRIORITY.verdict);
    expect(labelPriority(plain, { endpoint: true })).toBe(LABEL_PRIORITY.endpoint);
    expect(labelPriority(plain)).toBe(LABEL_PRIORITY.path);
    expect(labelPriority(node(2, 0, { dimmed: true }))).toBe(LABEL_PRIORITY.offPath);
    expect(labelPriority(plain, { hovered: true })).toBe(LABEL_PRIORITY.hovered);
  });

  it("puts every on-path tier at or above the never-drop floor, and off-path below it", () => {
    expect(LABEL_PRIORITY.path).toBe(PATH_PRIORITY_FLOOR);
    expect(LABEL_PRIORITY.offPath).toBeLessThan(PATH_PRIORITY_FLOOR);
    for (const tier of [LABEL_PRIORITY.endpoint, LABEL_PRIORITY.verdict, LABEL_PRIORITY.selected]) {
      expect(tier).toBeGreaterThanOrEqual(PATH_PRIORITY_FLOOR);
    }
  });

  it("keeps a dimmed verdict node on the path", () => {
    expect(labelPriority(node(2, 1, { dimmed: true, verdict: "bad" }))).toBe(
      LABEL_PRIORITY.verdict,
    );
  });
});

describe("the solver at Home framing", () => {
  for (const hops of [3, 15, 60]) {
    for (const lanes of [1, 4]) {
      for (const pane of PANES) {
        it(`${hops} hops / ${lanes} lane(s) / ${pane.name}: every path label stays visible, no chips overlap`, () => {
          const nodes = trace(hops, lanes);
          const { requests, placed } = solveAtHome(nodes, pane);
          expect(placed).toHaveLength(nodes.length);
          for (const label of placed) {
            expect(label.mode).not.toBe("hidden");
          }
          expect(overlapping(placed, requests)).toBe(0);
        });
      }
    }
  }

  it("gives each label of a short trace a full chip", () => {
    const { placed } = solveAtHome(trace(3, 1), PANES[0]);
    expect(placed.every((p) => p.mode === "full")).toBe(true);
  });

  it("collapses labels of a long trace to dots and hides none", () => {
    const { placed } = solveAtHome(trace(60, 4), PANES[1]);
    expect(placed.some((p) => p.mode === "dot")).toBe(true);
    expect(placed.some((p) => p.mode === "hidden")).toBe(false);
  });

  it("gives the same placement for the same view twice", () => {
    const nodes = trace(15, 2);
    const first = solveAtHome(nodes, PANES[0]).placed;
    const second = solveAtHome(nodes, PANES[0]).placed;
    expect(second).toEqual(first);
  });
});

describe("the no-label band around the path", () => {
  it("keeps a box clear of a horizontal run, and reports one that sits on it", () => {
    const run: ScreenSegment = { x1: 100, y1: 200, x2: 400, y2: 200 };
    const pad = bandHalfHeight(38);
    expect(intersectsPathBand({ x: 150, y: 190, w: 120, h: 38 }, run, pad)).toBe(true);
    // The box's bottom edge is the band's top.
    expect(intersectsPathBand({ x: 150, y: 200 - pad - 38, w: 120, h: 38 }, run, pad)).toBe(false);
    // Outside the run's x window.
    expect(intersectsPathBand({ x: 900, y: 190, w: 120, h: 38 }, run, pad)).toBe(false);
  });

  it("tests a box against the riser line", () => {
    const riser: ScreenSegment = { x1: 400, y1: 400, x2: 400, y2: 100 };
    const pad = bandHalfHeight(38);
    expect(intersectsPathBand({ x: 380, y: 240, w: 120, h: 38 }, riser, pad)).toBe(true);
    expect(intersectsPathBand({ x: 700, y: 240, w: 120, h: 38 }, riser, pad)).toBe(false);
  });

  it("states the band as the chip's own height plus the pad", () => {
    expect(bandHalfHeight(38)).toBe(38 + LABEL_BAND_PAD_PX);
    expect(LABEL_BAND_PAD_PX).toBe(6);
  });

  it("hangs even hops above the path and odd hops below it", () => {
    expect(labelSide(0)).toBe("above");
    expect(labelSide(1)).toBe("below");
    expect(labelSide(2)).toBe("above");
    expect(labelSide(7)).toBe("below");
  });

  for (const hops of [3, 15, 60]) {
    for (const lanes of [1, 4]) {
      for (const pane of PANES) {
        it(`${hops} hops / ${lanes} lane(s) / ${pane.name}: no chip covers the path or a badge`, () => {
          const nodes = trace(hops, lanes);
          const { requests, placed, pathSegments, badges } = solveAtHome(nodes, pane);
          const byKey = new Map(requests.map((r) => [r.key, r]));
          const chips = placed.filter((p) => p.mode === "full");
          expect(pathSegments.length).toBeGreaterThan(0);
          for (const chip of chips) {
            const request = byKey.get(chip.key)!;
            const box: Box = { x: chip.x, y: chip.y, w: request.width, h: request.height };
            const pad = bandHalfHeight(request.height);
            for (const segment of pathSegments) {
              expect(intersectsPathBand(box, segment, pad)).toBe(false);
            }
            for (const badge of badges) {
              const apart =
                box.x + box.w + LABEL_GAP_PX <= badge.x ||
                badge.x + badge.w + LABEL_GAP_PX <= box.x ||
                box.y + box.h + LABEL_GAP_PX <= badge.y ||
                badge.y + badge.h + LABEL_GAP_PX <= box.y;
              expect(apart).toBe(true);
            }
          }
          expect(overlapping(placed, requests)).toBe(0);
          for (const label of placed) expect(label.mode).not.toBe("hidden");
        });
      }
    }
  }
});

describe("the hop number", () => {
  it("sits inside a full chip and stands alone for a dot", () => {
    expect(badgeDisplay("full")).toBe("chip");
    expect(badgeDisplay("dot")).toBe("standalone");
    expect(badgeDisplay("hidden")).toBe("hidden");
  });

  it("never draws a standalone badge for a label that got a chip", () => {
    const { placed } = solveAtHome(trace(60, 4), PANES[1]);
    const standalone = placed.filter((p) => badgeDisplay(p.mode) === "standalone");
    const chipped = placed.filter((p) => badgeDisplay(p.mode) === "chip");
    // The fixture holds both cases.
    expect(standalone.length).toBeGreaterThan(0);
    expect(chipped.length).toBeGreaterThan(0);
    for (const label of standalone) expect(label.mode).toBe("dot");
    for (const label of chipped) expect(label.mode).toBe("full");
  });
});

describe("off-path labels", () => {
  const nodes = [node(0, 0), node(1, 0, { dimmed: true }), node(2, 0)];

  function solve(options: { slotPx: number; navigating?: boolean }) {
    const offsets = layerOffsets(LAYER_COUNT, GAP, []);
    const positions = positionNodes(nodes, offsets);
    const bounds = sceneBounds(nodes, offsets);
    const viewport = PANES[0];
    const camera = cameraFor(homeView(bounds, viewport.width / viewport.height), viewport);
    const requests: LabelRequest[] = nodes.map((n) => ({
      key: sceneStationKey(n),
      world: positions.get(sceneStationKey(n))!.position.clone(),
      width: CHIP.width,
      height: CHIP.height,
      rank: n.rank,
      priority: labelPriority(n),
    }));
    const placed = planLabels(requests, camera, viewport, options);
    return new Map(placed.map((p) => [p.key, p]));
  }

  const offKey = sceneStationKey(nodes[1]);
  const onKey = sceneStationKey(nodes[0]);

  it("appears above the zoom threshold", () => {
    expect(solve({ slotPx: OFF_PATH_LABEL_SLOT_PX + 10 }).get(offKey)!.mode).toBe("full");
  });

  it("is hidden below the zoom threshold, path labels stay", () => {
    const solved = solve({ slotPx: OFF_PATH_LABEL_SLOT_PX - 10 });
    expect(solved.get(offKey)!.mode).toBe("hidden");
    expect(solved.get(onKey)!.mode).not.toBe("hidden");
  });

  it("is hidden during an orbit, path labels stay", () => {
    const solved = solve({ slotPx: OFF_PATH_LABEL_SLOT_PX + 10, navigating: true });
    expect(solved.get(offKey)!.mode).toBe("hidden");
    expect(solved.get(onKey)!.mode).not.toBe("hidden");
  });
});

describe("plate occlusion", () => {
  const plate: PlateOccluder = { y: 10, minX: -20, maxX: 20, minZ: -20, maxZ: 20 };

  it("reports a point under a plate the camera looks down through", () => {
    expect(isOccludedByPlate(new Vector3(0, 0, 0), new Vector3(0, 40, 0), [plate])).toBe(true);
  });

  it("does not report a point above the plate", () => {
    expect(isOccludedByPlate(new Vector3(0, 20, 0), new Vector3(0, 40, 0), [plate])).toBe(false);
  });

  it("does not report a crossing outside the plate's own footprint", () => {
    expect(isOccludedByPlate(new Vector3(200, 0, 0), new Vector3(200, 40, 0), [plate])).toBe(false);
  });

  it("does not treat a label's own plate as its occluder", () => {
    expect(isOccludedByPlate(new Vector3(0, 10, 0), new Vector3(0, 40, 0), [plate])).toBe(false);
  });

  it("reports nothing for a level camera", () => {
    expect(isOccludedByPlate(new Vector3(0, 0, 0), new Vector3(40, 0, 0), [plate])).toBe(false);
  });

  it("hides an occluded off-path label", () => {
    const viewport = PANES[0];
    const nodes = [node(0, 0, { dimmed: true })];
    const positions = positionNodes(nodes, layerOffsets(LAYER_COUNT, GAP, []));
    const bounds = sceneBounds(nodes, layerOffsets(LAYER_COUNT, GAP, []));
    const camera = cameraFor(homeView(bounds, viewport.width / viewport.height), viewport);
    const world = positions.get(sceneStationKey(nodes[0]))!.position.clone();
    const requests: LabelRequest[] = [
      {
        key: sceneStationKey(nodes[0]),
        world,
        width: CHIP.width,
        height: CHIP.height,
        rank: nodes[0].rank,
        priority: labelPriority(nodes[0]),
      },
    ];
    const cover: PlateOccluder = {
      y: world.y + 1,
      minX: world.x - 50,
      maxX: world.x + 50,
      minZ: world.z - 50,
      maxZ: world.z + 50,
    };
    const placed = planLabels(requests, camera, viewport, {
      slotPx: OFF_PATH_LABEL_SLOT_PX * 2,
      occluders: [cover],
      cameraPosition: camera.position,
    });
    expect(placed[0].occluded).toBe(true);
    expect(placed[0].mode).toBe("hidden");
  });
});

describe("projectToScreen", () => {
  it("projects a point in front of the camera into the viewport", () => {
    const viewport = PANES[0];
    const nodes = trace(4, 1);
    const offsets = layerOffsets(LAYER_COUNT, GAP, []);
    const bounds = sceneBounds(nodes, offsets);
    const camera = cameraFor(homeView(bounds, viewport.width / viewport.height), viewport);
    const p = projectToScreen(bounds.center, camera, viewport.width, viewport.height);
    expect(p.visible).toBe(true);
    expect(p.x).toBeGreaterThan(0);
    expect(p.x).toBeLessThan(viewport.width);
    expect(p.y).toBeGreaterThan(0);
    expect(p.y).toBeLessThan(viewport.height);
  });

  it("marks a point behind the camera as not visible", () => {
    const viewport = PANES[0];
    const nodes = trace(4, 1);
    const offsets = layerOffsets(LAYER_COUNT, GAP, []);
    const bounds = sceneBounds(nodes, offsets);
    const orbit = homeView(bounds, viewport.width / viewport.height);
    const camera = cameraFor(orbit, viewport);
    const behind = camera.position
      .clone()
      .add(camera.position.clone().sub(orbit.pivot).normalize().multiplyScalar(50));
    expect(projectToScreen(behind, camera, viewport.width, viewport.height).visible).toBe(false);
  });
});
