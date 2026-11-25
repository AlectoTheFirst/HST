import { describe, expect, it } from "vitest";
import { LEVEL_ZOOM, fit, fly, levelOf, pan, screenBox, toPlane, toScreen, zoomAt, zoomOf } from "./camera";
import type { CameraState, Viewport } from "./types";

const vp: Viewport = { width: 1000, height: 700 };
const cam: CameraState = { u: 40, v: 25, zoom: 3 };

function close(a: number[], b: number[]): void {
  a.forEach((x, i) => expect(x).toBeCloseTo(b[i], 6));
}

describe("the isometric camera", () => {
  it("maps a plane point to the screen and back, on the floor and on a surface", () => {
    for (const h of [0, 2.2]) {
      const [x, y] = toScreen(cam, vp, 12, 70, h);
      close(toPlane(cam, vp, x, y, h), [12, 70]);
    }
    close(toScreen(cam, vp, cam.u, cam.v), [vp.width / 2, vp.height / 2]);
  });

  it("draws the u axis right and down and the v axis left and down", () => {
    const [x0, y0] = toScreen(cam, vp, 0, 0);
    const [xu, yu] = toScreen(cam, vp, 1, 0);
    const [xv, yv] = toScreen(cam, vp, 0, 1);
    expect(xu > x0 && yu > y0).toBe(true);
    expect(xv < x0 && yv > y0).toBe(true);
    expect(Math.atan2(yu - y0, xu - x0)).toBeCloseTo(Math.PI / 6, 6);
  });

  it("keeps the point under the cursor in place when it zooms", () => {
    const before = toPlane(cam, vp, 230, 610);
    const after = zoomAt(cam, vp, 230, 610, 2.5);
    expect(after.zoom).toBeCloseTo(7.5);
    close(toPlane(after, vp, 230, 610), before);
  });

  it("moves the scene with the pointer when it pans", () => {
    const point = toPlane(cam, vp, 300, 200);
    close(toScreen(pan(cam, vp, 40, -25), vp, point[0], point[1]), [340, 175]);
  });

  it("switches the four levels at fixed zooms", () => {
    expect([0.5, 1.5, 5, 14, 40].map(levelOf)).toEqual([1, 2, 3, 4, 4]);
    expect(LEVEL_ZOOM).toEqual([...LEVEL_ZOOM].sort((a, b) => a - b));
    for (const level of [1, 2, 3, 4] as const) expect(levelOf(zoomOf(level))).toBe(level);
  });

  it("fits a rectangle inside the viewport", () => {
    const r = { u0: 0, v0: 0, u1: 900, v1: 400 };
    const b = screenBox(fit(r, vp), vp, r);
    expect(b.u0).toBeGreaterThanOrEqual(0);
    expect(b.v0).toBeGreaterThanOrEqual(0);
    expect(b.u1).toBeLessThanOrEqual(vp.width);
    expect(b.v1).toBeLessThanOrEqual(vp.height);
  });

  it("flies from one camera to the other", () => {
    const b = { u: 500, v: -40, zoom: 20 };
    close(Object.values(fly(cam, b, 0)), Object.values(cam));
    close(Object.values(fly(cam, b, 1)), Object.values(b));
    const mid = fly(cam, b, 0.5);
    expect(mid.zoom).toBeGreaterThan(cam.zoom);
    expect(mid.zoom).toBeLessThan(b.zoom);
  });
});
