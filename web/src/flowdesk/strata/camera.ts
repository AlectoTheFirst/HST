/** `configureCamera` is the only place a real `PerspectiveCamera` is written to. */

import { PerspectiveCamera, Vector2, Vector3 } from "three";
import { CELL, clamp } from "./view-helpers";
import type { SceneBounds } from "./path";

/** Vertical field of view, in degrees. */
export const FOV = 35;
const NEAR = 0.1;
const FAR = 4000;

/** The up vector of the camera. It locks the roll. */
export const WORLD_UP = Object.freeze(new Vector3(0, 1, 0));

/** At 0 or π, `lookAt` has no defined right axis. */
export const MIN_POLAR = (0.1 * Math.PI) / 180;
export const MAX_POLAR = ((180 - 0.1) * Math.PI) / 180;

export const MIN_RADIUS = 1.5;
const MAX_RADIUS = 2000;

/** Radians of orbit per pixel dragged. */
const ORBIT_SENSITIVITY = 0.006;
/** Multiplier per wheel notch / pinch step. */
export const WHEEL_STEP = 1.12;

/** Snaps and plate flattening share one 350ms ease-out. */
export const TWEEN_MS = 350;

export interface OrbitState {
  /** The point the camera looks at and orbits around. */
  pivot: Vector3;
  /** Radians around +Y, measured from +Z toward +X. Always in [0, 2π). */
  azimuth: number;
  /** Radians from +Y. π/2 is level with the pivot; smaller looks down. */
  polar: number;
  /** Distance from pivot to camera. */
  radius: number;
}

export interface Viewport {
  width: number;
  height: number;
}

export function wrapAzimuth(azimuth: number): number {
  const twoPi = Math.PI * 2;
  const wrapped = azimuth % twoPi;
  return wrapped < 0 ? wrapped + twoPi : wrapped;
}

/** Vector from pivot to camera. */
export function orbitOffset(state: OrbitState): Vector3 {
  const sinPolar = Math.sin(state.polar);
  return new Vector3(
    state.radius * sinPolar * Math.sin(state.azimuth),
    state.radius * Math.cos(state.polar),
    state.radius * sinPolar * Math.cos(state.azimuth),
  );
}

export function cameraPosition(state: OrbitState): Vector3 {
  return state.pivot.clone().add(orbitOffset(state));
}

/** Spherical coordinates for a camera at `position` looking at `pivot`. */
export function orbitFromPosition(position: Vector3, pivot: Vector3): OrbitState {
  const offset = position.clone().sub(pivot);
  const radius = Math.max(offset.length(), 1e-6);
  return {
    pivot: pivot.clone(),
    radius,
    polar: clamp(Math.acos(clamp(offset.y / radius, -1, 1)), MIN_POLAR, MAX_POLAR),
    azimuth: wrapAzimuth(Math.atan2(offset.x, offset.z)),
  };
}

/** `azimuthOnly` keeps the pitch. */
export function orbitBy(
  state: OrbitState,
  dxPx: number,
  dyPx: number,
  options: { azimuthOnly?: boolean } = {},
): OrbitState {
  return {
    ...state,
    pivot: state.pivot.clone(),
    azimuth: wrapAzimuth(state.azimuth - dxPx * ORBIT_SENSITIVITY),
    polar: options.azimuthOnly
      ? state.polar
      : clamp(state.polar + dyPx * ORBIT_SENSITIVITY, MIN_POLAR, MAX_POLAR),
  };
}

/** World units one CSS pixel covers at the pivot's depth. */
export function worldPerPixel(radius: number, viewportHeight: number, fov: number = FOV): number {
  if (viewportHeight <= 0) return 0;
  return (2 * radius * Math.tan(((fov / 2) * Math.PI) / 180)) / viewportHeight;
}

/** CSS pixels one hop slot covers on screen, the level-of-detail figure. */
export function slotPixels(radius: number, viewportHeight: number, fov: number = FOV): number {
  const perPx = worldPerPixel(radius, viewportHeight, fov);
  return perPx > 0 ? CELL / perPx : 0;
}

/** The camera's right, up and forward axes in world space. */
export function cameraBasis(state: OrbitState): { right: Vector3; up: Vector3; forward: Vector3 } {
  const forward = orbitOffset(state).normalize().negate(); // camera -> pivot
  let right = new Vector3().crossVectors(forward, WORLD_UP);
  if (right.lengthSq() < 1e-12) right = new Vector3(1, 0, 0);
  right.normalize();
  const up = new Vector3().crossVectors(right, forward).normalize();
  return { right, up, forward };
}

/** Right-drag / two-finger drag pans, moving the pivot with the
 *  camera. Dragging right moves the scene right, so the pivot travels left. */
export function panBy(
  state: OrbitState,
  dxPx: number,
  dyPx: number,
  viewport: Viewport,
  fov: number = FOV,
): OrbitState {
  const perPx = worldPerPixel(state.radius, viewport.height, fov);
  const { right, up } = cameraBasis(state);
  const pivot = state.pivot
    .clone()
    .addScaledVector(right, -dxPx * perPx)
    .addScaledVector(up, dyPx * perPx);
  return { ...state, pivot };
}

/** The scale factor comes from the radius after the clamp. */
export function zoomToCursor(state: OrbitState, focus: Vector3, factor: number): OrbitState {
  const wanted = state.radius / Math.max(factor, 1e-6);
  const radius = clamp(wanted, MIN_RADIUS, MAX_RADIUS);
  const scale = radius / state.radius;
  const pivot = focus.clone().addScaledVector(state.pivot.clone().sub(focus), scale);
  return { ...state, pivot, radius };
}

// --- framing ---------------------------------------------------------------------

/** Margin `frameRadius` leaves around the scene. */
const FIT_MARGIN = 1.16;

/** The orbit radius at which a bounding sphere of `sceneRadius` fits the
 *  frame in both axes. */
export function frameRadius(sceneRadius: number, aspect: number, fov: number = FOV): number {
  const vHalf = ((fov / 2) * Math.PI) / 180;
  const hHalf = Math.atan(Math.tan(vHalf) * Math.max(aspect, 1e-6));
  const half = Math.min(vHalf, hHalf);
  const needed = (Math.max(sceneRadius, 1e-3) * FIT_MARGIN) / Math.max(Math.sin(half), 1e-6);
  return clamp(needed, MIN_RADIUS, MAX_RADIUS);
}

export type SnapName = "front" | "top" | "left" | "right" | "home";

/** The look-down of the front, left and right snaps, in degrees. */
const SNAP_PITCH_DEG = 20;

/** Home looks 32° down and 14° to the left. */
export const HOME_PITCH_DEG = 32;
export const HOME_YAW_DEG = -14;

/** Azimuth 0 puts the camera on +Z looking down -Z. */
export const SNAP_ORIENTATION: Readonly<Record<SnapName, { azimuth: number; polar: number }>> = {
  front: { azimuth: 0, polar: ((90 - SNAP_PITCH_DEG) * Math.PI) / 180 },
  home: {
    azimuth: wrapAzimuth((HOME_YAW_DEG * Math.PI) / 180),
    polar: ((90 - HOME_PITCH_DEG) * Math.PI) / 180,
  },
  top: { azimuth: 0, polar: MIN_POLAR },
  right: { azimuth: Math.PI / 2, polar: ((90 - SNAP_PITCH_DEG) * Math.PI) / 180 },
  left: { azimuth: (3 * Math.PI) / 2, polar: ((90 - SNAP_PITCH_DEG) * Math.PI) / 180 },
};

/** The full camera state a view-cube snap animates to: the snap's
 *  orientation, framing `bounds`. */
export function snapTarget(name: SnapName, bounds: SceneBounds, aspect: number): OrbitState {
  const orientation = SNAP_ORIENTATION[name];
  return {
    pivot: bounds.center.clone(),
    azimuth: orientation.azimuth,
    polar: orientation.polar,
    radius: frameRadius(bounds.radius, aspect),
  };
}

export function homeView(bounds: SceneBounds, aspect: number): OrbitState {
  return snapTarget("home", bounds, aspect);
}

/** Fit keeps the current orientation. */
export function fitView(
  state: OrbitState,
  bounds: SceneBounds,
  centroid: Vector3,
  aspect: number,
): OrbitState {
  const reach = Math.max(centroid.distanceTo(bounds.min), centroid.distanceTo(bounds.max));
  return {
    pivot: centroid.clone(),
    azimuth: state.azimuth,
    polar: state.polar,
    radius: frameRadius(reach, aspect),
  };
}

/** True when new per-layer flatten targets differ from the current ones. */
export function flattenTargetsChanged(
  next: readonly number[],
  current: readonly number[],
): boolean {
  return next.length !== current.length || next.some((t, i) => t !== current[i]);
}

// --- tweening --------------------------------------------------------------------

export function easeOut(t: number): number {
  const x = clamp(t, 0, 1);
  return 1 - Math.pow(1 - x, 3);
}

/** The signed short way round from one azimuth to another. */
export function shortestAzimuthDelta(from: number, to: number): number {
  const twoPi = Math.PI * 2;
  let delta = (to - from) % twoPi;
  if (delta > Math.PI) delta -= twoPi;
  if (delta < -Math.PI) delta += twoPi;
  return delta;
}

/** Interpolates two camera states. Azimuth takes the short way round, so a
 *  snap from 350° to 10° turns 20°, not 340°. */
export function lerpOrbit(from: OrbitState, to: OrbitState, t: number): OrbitState {
  const k = clamp(t, 0, 1);
  return {
    pivot: from.pivot.clone().lerp(to.pivot, k),
    azimuth: wrapAzimuth(from.azimuth + shortestAzimuthDelta(from.azimuth, to.azimuth) * k),
    polar: from.polar + (to.polar - from.polar) * k,
    radius: from.radius + (to.radius - from.radius) * k,
  };
}

// --- writing it to a real camera ---------------------------------------------------

/** The only place camera fields are assigned. */
export function configureCamera(
  camera: PerspectiveCamera,
  state: OrbitState,
  viewport: Viewport,
): PerspectiveCamera {
  camera.fov = FOV;
  camera.near = NEAR;
  camera.far = FAR;
  camera.aspect = viewport.height > 0 ? viewport.width / viewport.height : 1;
  camera.up.copy(WORLD_UP);
  camera.position.copy(cameraPosition(state));
  camera.lookAt(state.pivot);
  camera.updateProjectionMatrix();
  camera.updateMatrixWorld(true);
  return camera;
}

export function cameraFor(state: OrbitState, viewport: Viewport): PerspectiveCamera {
  return configureCamera(new PerspectiveCamera(), state, viewport);
}

/** NDC (-1..1) for a pointer position inside an element's bounding rect. */
export function pointerNdc(
  clientX: number,
  clientY: number,
  rect: { left: number; top: number; width: number; height: number },
): Vector2 {
  return new Vector2(
    ((clientX - rect.left) / Math.max(rect.width, 1)) * 2 - 1,
    -((clientY - rect.top) / Math.max(rect.height, 1)) * 2 + 1,
  );
}

/**
 * True when each of the eight corners of the bounding box falls
 * outside the viewport or behind the camera.
 */
export function isSceneOffScreen(bounds: SceneBounds, camera: PerspectiveCamera): boolean {
  for (const x of [bounds.min.x, bounds.max.x]) {
    for (const y of [bounds.min.y, bounds.max.y]) {
      for (const z of [bounds.min.z, bounds.max.z]) {
        const p = new Vector3(x, y, z).project(camera);
        if (p.z >= -1 && p.z <= 1 && p.x >= -1 && p.x <= 1 && p.y >= -1 && p.y <= 1) return false;
      }
    }
  }
  return true;
}

/** The view cube transform is the inverse of the camera's rotation. */
export function viewCubeTransform(state: OrbitState): string {
  const pitchDeg = (90 - (state.polar * 180) / Math.PI).toFixed(2);
  const yawDeg = ((state.azimuth * 180) / Math.PI).toFixed(2);
  return `rotateX(${pitchDeg}deg) rotateY(${yawDeg}deg)`;
}
