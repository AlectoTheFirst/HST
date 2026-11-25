import { describe, it, expect } from "vitest";
import { Vector3 } from "three";
import {
  FOV,
  HOME_PITCH_DEG,
  HOME_YAW_DEG,
  MAX_POLAR,
  MIN_POLAR,
  MIN_RADIUS,
  SNAP_ORIENTATION,
  TWEEN_MS,
  WORLD_UP,
  cameraBasis,
  cameraFor,
  cameraPosition,
  configureCamera,
  easeOut,
  fitView,
  flattenTargetsChanged,
  frameRadius,
  homeView,
  isSceneOffScreen,
  lerpOrbit,
  orbitBy,
  orbitFromPosition,
  orbitOffset,
  panBy,
  pointerNdc,
  shortestAzimuthDelta,
  slotPixels,
  snapTarget,
  viewCubeTransform,
  worldPerPixel,
  wrapAzimuth,
  zoomToCursor,
  type OrbitState,
} from "./camera";
import type { SceneBounds } from "./path";

const VIEWPORT = { width: 1280, height: 720 };

function state(overrides: Partial<OrbitState> = {}): OrbitState {
  return {
    pivot: new Vector3(3, 2, -1),
    azimuth: 0.7,
    polar: 1.1,
    radius: 40,
    ...overrides,
  };
}

function bounds(): SceneBounds {
  const min = new Vector3(-10, 0, -6);
  const max = new Vector3(30, 15, 6);
  const center = min.clone().add(max).multiplyScalar(0.5);
  return { min, max, center, radius: max.distanceTo(min) / 2 };
}

describe("camera type", () => {
  it("is perspective at a 35 degree field of view", () => {
    expect(FOV).toBe(35);
    const camera = cameraFor(state(), VIEWPORT);
    expect(camera.isPerspectiveCamera).toBe(true);
    expect(camera.fov).toBe(35);
    expect(camera.aspect).toBeCloseTo(VIEWPORT.width / VIEWPORT.height, 10);
  });
});

describe("roll lock", () => {
  it("keeps world up as the camera up vector at every orientation", () => {
    for (const polar of [MIN_POLAR, 0.4, Math.PI / 2, 2.4, MAX_POLAR]) {
      for (const azimuth of [0, 1.3, Math.PI, 5.9]) {
        const camera = cameraFor(state({ azimuth, polar }), VIEWPORT);
        expect(camera.up.equals(WORLD_UP)).toBe(true);
      }
    }
  });

  it("keeps the camera's right axis horizontal", () => {
    for (const polar of [0.3, 1.0, Math.PI / 2, 2.2]) {
      const camera = cameraFor(state({ polar, azimuth: 2.1 }), VIEWPORT);
      const right = new Vector3().setFromMatrixColumn(camera.matrixWorld, 0);
      expect(Math.abs(right.y)).toBeLessThan(1e-9);
    }
  });

  it("has no roll term: an OrbitState is pivot, azimuth, polar, radius", () => {
    expect(Object.keys(state()).sort()).toEqual(["azimuth", "pivot", "polar", "radius"]);
  });
});

describe("orbit maths", () => {
  it("turns a horizontal drag into azimuth and a vertical drag into pitch", () => {
    const before = state();
    const after = orbitBy(before, 40, 25);
    expect(after.azimuth).not.toBeCloseTo(before.azimuth, 6);
    expect(after.polar).toBeGreaterThan(before.polar);
  });

  it("wraps azimuth into [0, 2*PI)", () => {
    let s = state({ azimuth: 0.05 });
    s = orbitBy(s, 4000, 0); // a 4000 px drag one way
    expect(s.azimuth).toBeGreaterThanOrEqual(0);
    expect(s.azimuth).toBeLessThan(Math.PI * 2);
    expect(wrapAzimuth(-0.25)).toBeCloseTo(Math.PI * 2 - 0.25, 10);
    expect(wrapAzimuth(Math.PI * 2)).toBeCloseTo(0, 10);
    expect(wrapAzimuth(Math.PI * 6.5)).toBeCloseTo(Math.PI * 0.5, 10);
  });

  it("lets the camera pass below the horizon", () => {
    const s = orbitBy(state({ polar: Math.PI / 2 }), 0, 300);
    expect(s.polar).toBeGreaterThan(Math.PI / 2);
    expect(orbitOffset(s).y).toBeLessThan(0); // the camera is under the stack
  });

  it("stops a tenth of a degree short of each pole", () => {
    expect(orbitBy(state(), 0, -100000).polar).toBeCloseTo(MIN_POLAR, 12);
    expect(orbitBy(state(), 0, 100000).polar).toBeCloseTo(MAX_POLAR, 12);
    expect(MIN_POLAR).toBeGreaterThan(0);
    expect(MAX_POLAR).toBeLessThan(Math.PI);
  });

  it("Shift constrains the orbit to azimuth alone", () => {
    const before = state();
    const after = orbitBy(before, 60, 90, { azimuthOnly: true });
    expect(after.polar).toBe(before.polar);
    expect(after.azimuth).not.toBe(before.azimuth);
  });

  it("does not mutate the state it is given", () => {
    const before = state();
    const pivot = before.pivot.clone();
    orbitBy(before, 100, 100);
    expect(before.pivot.equals(pivot)).toBe(true);
  });

  it("round-trips through orbitFromPosition", () => {
    const s = state({ azimuth: 2.4, polar: 0.9, radius: 33 });
    const back = orbitFromPosition(cameraPosition(s), s.pivot);
    expect(back.azimuth).toBeCloseTo(s.azimuth, 9);
    expect(back.polar).toBeCloseTo(s.polar, 9);
    expect(back.radius).toBeCloseTo(s.radius, 9);
  });
});

describe("pan", () => {
  it("moves the pivot in the camera's screen plane only", () => {
    const s = state();
    const { forward } = cameraBasis(s);
    const panned = panBy(s, 50, -30, VIEWPORT);
    const delta = panned.pivot.clone().sub(s.pivot);
    expect(delta.length()).toBeGreaterThan(0);
    expect(Math.abs(delta.dot(forward))).toBeLessThan(1e-9);
    expect(panned.radius).toBe(s.radius);
    expect(panned.azimuth).toBe(s.azimuth);
  });

  it("scales with the pivot distance", () => {
    const near = panBy(state({ radius: 20 }), 100, 0, VIEWPORT);
    const far = panBy(state({ radius: 40 }), 100, 0, VIEWPORT);
    const nearDelta = near.pivot.distanceTo(state({ radius: 20 }).pivot);
    const farDelta = far.pivot.distanceTo(state({ radius: 40 }).pivot);
    expect(farDelta / nearDelta).toBeCloseTo(2, 6);
  });
});

describe("zoom to cursor", () => {
  const focus = new Vector3(9, 4, -5);

  function pixelOf(s: OrbitState): { x: number; y: number } {
    const projected = focus.clone().project(cameraFor(s, VIEWPORT));
    return {
      x: (projected.x * 0.5 + 0.5) * VIEWPORT.width,
      y: (-projected.y * 0.5 + 0.5) * VIEWPORT.height,
    };
  }

  it("keeps the point under the cursor on the same pixel", () => {
    const before = state();
    for (const factor of [1.12, 1 / 1.12, 2.5, 0.3]) {
      const after = zoomToCursor(before, focus, factor);
      const a = pixelOf(before);
      const b = pixelOf(after);
      expect(b.x).toBeCloseTo(a.x, 6);
      expect(b.y).toBeCloseTo(a.y, 6);
    }
  });

  it("dollies in for a factor above one and out below it", () => {
    expect(zoomToCursor(state(), focus, 2).radius).toBeLessThan(state().radius);
    expect(zoomToCursor(state(), focus, 0.5).radius).toBeGreaterThan(state().radius);
  });

  it("keeps the point fixed at the radius clamp", () => {
    const before = state({ radius: MIN_RADIUS * 1.05 });
    const after = zoomToCursor(before, focus, 1000);
    expect(after.radius).toBeCloseTo(MIN_RADIUS, 9);
    const a = pixelOf(before);
    const b = pixelOf(after);
    expect(b.x).toBeCloseTo(a.x, 6);
    expect(b.y).toBeCloseTo(a.y, 6);
  });

  it("leaves the orientation alone", () => {
    const after = zoomToCursor(state(), focus, 1.4);
    expect(after.azimuth).toBe(state().azimuth);
    expect(after.polar).toBe(state().polar);
  });
});

describe("screen scale", () => {
  it("reports zero for a zero-height viewport", () => {
    expect(worldPerPixel(30, 0)).toBe(0);
    expect(slotPixels(30, 0)).toBe(0);
  });

  it("halves the pixels per hop slot as the camera pulls twice as far back", () => {
    const near = slotPixels(20, VIEWPORT.height);
    const far = slotPixels(40, VIEWPORT.height);
    expect(near / far).toBeCloseTo(2, 6);
  });
});

describe("framing", () => {
  it("projects every corner of the scene box inside the frame", () => {
    const b = bounds();
    const home = homeView(b, VIEWPORT.width / VIEWPORT.height);
    const camera = cameraFor(home, VIEWPORT);
    for (const x of [b.min.x, b.max.x]) {
      for (const y of [b.min.y, b.max.y]) {
        for (const z of [b.min.z, b.max.z]) {
          const p = new Vector3(x, y, z).project(camera);
          expect(Math.abs(p.x)).toBeLessThanOrEqual(1);
          expect(Math.abs(p.y)).toBeLessThanOrEqual(1);
        }
      }
    }
    expect(isSceneOffScreen(b, camera)).toBe(false);
  });

  it("home is a three-quarter view with X to the right", () => {
    const home = homeView(bounds(), 1.7);
    expect(90 - (home.polar * 180) / Math.PI).toBeCloseTo(HOME_PITCH_DEG, 6);
    expect(HOME_PITCH_DEG).toBe(32);
    expect(home.azimuth).toBeCloseTo(wrapAzimuth((HOME_YAW_DEG * Math.PI) / 180), 12);
    expect(HOME_YAW_DEG).toBe(-14);
    const camera = cameraFor(home, VIEWPORT);
    const left = new Vector3(0, home.pivot.y, home.pivot.z).project(camera);
    const right = new Vector3(20, home.pivot.y, home.pivot.z).project(camera);
    expect(right.x).toBeGreaterThan(left.x);
  });

  it("keeps Front as its own square-on snap, distinct from Home", () => {
    expect(SNAP_ORIENTATION.front.azimuth).toBe(0);
    expect(90 - (SNAP_ORIENTATION.front.polar * 180) / Math.PI).toBeCloseTo(20, 9);
    expect(SNAP_ORIENTATION.home.polar).not.toBeCloseTo(SNAP_ORIENTATION.front.polar, 6);
    expect(SNAP_ORIENTATION.home.azimuth).not.toBeCloseTo(SNAP_ORIENTATION.front.azimuth, 6);
  });

  it("Top is a plan view off the pole", () => {
    const top = snapTarget("top", bounds(), 1.7);
    expect(top.polar).toBe(MIN_POLAR);
    expect(orbitOffset(top).y).toBeGreaterThan(0);
  });

  it("Left and Right look along the lane axis, a quarter turn either way", () => {
    expect(snapTarget("right", bounds(), 1.7).azimuth).toBeCloseTo(Math.PI / 2, 12);
    expect(snapTarget("left", bounds(), 1.7).azimuth).toBeCloseTo((3 * Math.PI) / 2, 12);
  });

  it("pulls further back for a bigger scene and for a narrower frame", () => {
    expect(frameRadius(20, 1.7)).toBeGreaterThan(frameRadius(10, 1.7));
    expect(frameRadius(20, 0.5)).toBeGreaterThan(frameRadius(20, 1.7));
  });

  it("Fit keeps the orientation and frames around the centroid", () => {
    const b = bounds();
    const chosen = state({ azimuth: 2.9, polar: 0.45 });
    const centroid = new Vector3(5, 5, 0);
    const fitted = fitView(chosen, b, centroid, VIEWPORT.width / VIEWPORT.height);
    expect(fitted.azimuth).toBe(chosen.azimuth);
    expect(fitted.polar).toBe(chosen.polar);
    expect(fitted.pivot.equals(centroid)).toBe(true);
    const camera = cameraFor(fitted, VIEWPORT);
    expect(isSceneOffScreen(b, camera)).toBe(false);
  });

  it("reports a scene dragged far off the frame as off-screen", () => {
    const b = bounds();
    const lost = { ...homeView(b, 1.7), pivot: new Vector3(9000, 0, 0) };
    expect(isSceneOffScreen(b, cameraFor(lost, VIEWPORT))).toBe(true);
  });
});

describe("tweening", () => {
  it("eases out and lands on both ends", () => {
    expect(easeOut(0)).toBe(0);
    expect(easeOut(1)).toBe(1);
    expect(easeOut(0.5)).toBeGreaterThan(0.5);
    expect(easeOut(-2)).toBe(0);
    expect(easeOut(4)).toBe(1);
    expect(TWEEN_MS).toBeGreaterThanOrEqual(250);
    expect(TWEEN_MS).toBeLessThanOrEqual(350);
  });

  it("takes the short way round the azimuth wrap", () => {
    const from = (350 * Math.PI) / 180;
    const to = (10 * Math.PI) / 180;
    expect(shortestAzimuthDelta(from, to)).toBeCloseTo((20 * Math.PI) / 180, 9);
    expect(shortestAzimuthDelta(to, from)).toBeCloseTo((-20 * Math.PI) / 180, 9);
    // through 0, compared modulo the wrap
    const mid = lerpOrbit(state({ azimuth: from }), state({ azimuth: to }), 0.5);
    expect(Math.min(mid.azimuth, Math.PI * 2 - mid.azimuth)).toBeLessThan(1e-6);
  });

  it("lands on the target at t = 1", () => {
    const from = state();
    const to = snapTarget("top", bounds(), 1.7);
    const end = lerpOrbit(from, to, 1);
    expect(end.polar).toBeCloseTo(to.polar, 12);
    expect(end.radius).toBeCloseTo(to.radius, 12);
    expect(end.pivot.distanceTo(to.pivot)).toBeLessThan(1e-9);
  });
});

describe("flattenTargetsChanged", () => {
  it("is false when nothing moved", () => {
    expect(flattenTargetsChanged([0, 0, 0, 0], [0, 0, 0, 0])).toBe(false);
    expect(flattenTargetsChanged([1, 0, 1, 0], [1, 0, 1, 0])).toBe(false);
  });

  it("is true when any single layer's target moved", () => {
    expect(flattenTargetsChanged([0, 1, 0, 0], [0, 0, 0, 0])).toBe(true);
  });

  it("is true toggling every layer off at once", () => {
    expect(flattenTargetsChanged([1, 1, 1, 1], [0, 0, 0, 0])).toBe(true);
  });

  it("is true toggling back from the all-off state", () => {
    expect(flattenTargetsChanged([0, 0, 0, 0], [1, 1, 1, 1])).toBe(true);
  });
});

describe("pointer and view cube helpers", () => {
  it("maps a pointer position onto normalised device coordinates", () => {
    const rect = { left: 100, top: 50, width: 800, height: 400 };
    expect(pointerNdc(500, 250, rect).x).toBeCloseTo(0, 10);
    expect(pointerNdc(500, 250, rect).y).toBeCloseTo(0, 10);
    expect(pointerNdc(900, 50, rect).x).toBeCloseTo(1, 10);
    expect(pointerNdc(900, 50, rect).y).toBeCloseTo(1, 10);
  });

  it("turns the orbit state into a cube transform that tracks it", () => {
    const front = viewCubeTransform(snapTarget("front", bounds(), 1.7));
    expect(front).toContain("rotateX(20.00deg)");
    expect(front).toContain("rotateY(0.00deg)");
    const right = viewCubeTransform(snapTarget("right", bounds(), 1.7));
    expect(right).toContain("rotateY(90.00deg)");
  });
});

describe("configureCamera", () => {
  it("writes position, up and matrices from one state", () => {
    const s = state();
    const camera = cameraFor(s, VIEWPORT);
    expect(camera.position.distanceTo(cameraPosition(s))).toBeLessThan(1e-9);
    const forward = new Vector3(0, 0, -1).applyQuaternion(camera.quaternion);
    const toPivot = s.pivot.clone().sub(camera.position).normalize();
    expect(forward.distanceTo(toPivot)).toBeLessThan(1e-6);
  });

  it("falls back to a square aspect for a zero-height viewport", () => {
    const camera = configureCamera(cameraFor(state(), VIEWPORT), state(), { width: 10, height: 0 });
    expect(camera.aspect).toBe(1);
  });
});
