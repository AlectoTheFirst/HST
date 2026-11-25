import type { CameraState, Level, Viewport } from "./types";

// The camera looks down the world direction (-1, -1, -1): the isometric angle. The grid
// plane (u, v) is the world xz plane and height is y, so a world point moves by
// ((u - v) / sqrt 2, (u + v - 2y) / sqrt 6) grid units on the screen, right and down.
const SQRT2 = Math.SQRT2;
const SQRT6 = Math.sqrt(6);

export const MIN_ZOOM = 0.02;
export const MAX_ZOOM = 96;
/** The zoom, in pixels per grid unit, at which levels 2, 3 and 4 start. */
export const LEVEL_ZOOM: readonly [number, number, number] = [1.5, 5, 14];
export const FLY_MS = 450;

export interface Rect {
  u0: number;
  v0: number;
  u1: number;
  v1: number;
}

export function clampZoom(zoom: number): number {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, zoom));
}

export function levelOf(zoom: number): Level {
  if (zoom < LEVEL_ZOOM[0]) return 1;
  if (zoom < LEVEL_ZOOM[1]) return 2;
  if (zoom < LEVEL_ZOOM[2]) return 3;
  return 4;
}

/** The lowest zoom of `level`. */
export function zoomOf(level: Level): number {
  return level === 1 ? MIN_ZOOM : LEVEL_ZOOM[level - 2];
}

export function toScreen(cam: CameraState, vp: Viewport, u: number, v: number, y = 0): [number, number] {
  const du = u - cam.u;
  const dv = v - cam.v;
  if (cam.view === "top") return [vp.width / 2 + du * cam.zoom, vp.height / 2 + dv * cam.zoom];
  return [vp.width / 2 + ((du - dv) / SQRT2) * cam.zoom, vp.height / 2 + ((du + dv - 2 * y) / SQRT6) * cam.zoom];
}

/** The plane point under screen point (x, y), on the surface at `height`. */
export function toPlane(cam: CameraState, vp: Viewport, x: number, y: number, height = 0): [number, number] {
  if (cam.view === "top") return [cam.u + (x - vp.width / 2) / cam.zoom, cam.v + (y - vp.height / 2) / cam.zoom];
  const a = ((x - vp.width / 2) / cam.zoom) * SQRT2;
  const b = ((y - vp.height / 2) / cam.zoom) * SQRT6 + 2 * height;
  return [cam.u + (a + b) / 2, cam.v + (b - a) / 2];
}

/** The camera after a drag of (dx, dy) pixels: the scene follows the pointer. */
export function pan(cam: CameraState, vp: Viewport, dx: number, dy: number): CameraState {
  const [u, v] = toPlane(cam, vp, vp.width / 2 - dx, vp.height / 2 - dy);
  return { ...cam, u, v };
}

/** The camera after a zoom by `factor` that keeps the plane point under (x, y) in place. */
export function zoomAt(cam: CameraState, vp: Viewport, x: number, y: number, factor: number): CameraState {
  const zoom = clampZoom(cam.zoom * factor);
  const [pu, pv] = toPlane(cam, vp, x, y);
  const k = cam.zoom / zoom;
  return { ...cam, u: pu - (pu - cam.u) * k, v: pv - (pv - cam.v) * k, zoom };
}

/** The screen box of a plane rectangle. */
export function screenBox(cam: CameraState, vp: Viewport, r: Rect, height = 0): Rect {
  const corners = [
    toScreen(cam, vp, r.u0, r.v0, height),
    toScreen(cam, vp, r.u1, r.v0, height),
    toScreen(cam, vp, r.u0, r.v1, height),
    toScreen(cam, vp, r.u1, r.v1, height),
    toScreen(cam, vp, r.u0, r.v0, 0),
    toScreen(cam, vp, r.u1, r.v1, 0),
  ];
  const xs = corners.map((c) => c[0]);
  const ys = corners.map((c) => c[1]);
  return { u0: Math.min(...xs), v0: Math.min(...ys), u1: Math.max(...xs), v1: Math.max(...ys) };
}

export function onScreen(cam: CameraState, vp: Viewport, r: Rect, margin = 0): boolean {
  const b = screenBox(cam, vp, r);
  return b.u1 >= -margin && b.v1 >= -margin && b.u0 <= vp.width + margin && b.v0 <= vp.height + margin;
}

/** The camera that shows all of `r` with a margin of 5 percent, in `view`. */
export function fit(r: Rect, vp: Viewport, view: CameraState["view"] = "iso"): CameraState {
  const du = Math.max(1, r.u1 - r.u0);
  const dv = Math.max(1, r.v1 - r.v0);
  const width = view === "top" ? du : (du + dv) / SQRT2;
  const height = view === "top" ? dv : (du + dv) / SQRT6;
  const zoom = clampZoom(0.9 * Math.min(vp.width / width, vp.height / height));
  const cam: CameraState = { u: (r.u0 + r.u1) / 2, v: (r.v0 + r.v1) / 2, zoom };
  return view === "top" ? { ...cam, view } : cam;
}

/** The camera at fraction `t` of a flight from `a` to `b`; zoom moves in log space. */
export function fly(a: CameraState, b: CameraState, t: number): CameraState {
  const s = t <= 0 ? 0 : t >= 1 ? 1 : 1 - (1 - t) ** 3;
  return {
    ...b,
    u: a.u + (b.u - a.u) * s,
    v: a.v + (b.v - a.v) * s,
    zoom: Math.exp(Math.log(a.zoom) + (Math.log(b.zoom) - Math.log(a.zoom)) * s),
  };
}

/** The screen box of the main viewport on a minimap that draws the plane with camera `mini` in `size`. */
export function minimapView(cam: CameraState, vp: Viewport, mini: CameraState, size: Viewport): { x0: number; y0: number; x1: number; y1: number } {
  const corners = [
    toPlane(cam, vp, 0, 0),
    toPlane(cam, vp, vp.width, vp.height),
  ].map(([u, v]) => toScreen(mini, size, u, v));
  return {
    x0: Math.min(corners[0][0], corners[1][0]),
    y0: Math.min(corners[0][1], corners[1][1]),
    x1: Math.max(corners[0][0], corners[1][0]),
    y1: Math.max(corners[0][1], corners[1][1]),
  };
}
