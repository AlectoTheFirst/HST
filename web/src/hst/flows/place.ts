import type { Hop } from "../../api/types";
import { outcomeOf, shownState, type FlowConnection, type FlowPath, type FlowSegment } from "../../applications/flows";
import { Y, type Scene } from "../render/scene";
import type { Route, RoutePoint, RouteState } from "../render/types";
import { routePoints, type Step } from "../route/place";

export const REPLY_LIFT = 0.35;

export interface PlacedFlows {
  routes: Route[];
  /** The devices on a shown path or endpoint that the map holds. */
  highlight: Set<string>;
  /** Per connection id, the devices of its paths and endpoints that are not in the drawing. */
  offMap: Map<string, number>;
}

/** Whether the layout holds `uid` as a device. */
function onMap(scene: Scene, uid: string): boolean {
  return scene.layout.get(uid)?.kind === "device";
}

/** A device as a step for `routePoints`, at the center of its layout cell. */
function stepOf(scene: Scene, device: string): Step {
  const p = scene.layout.get(device)!;
  const label = String(scene.row("render_t1", device)?.label ?? device);
  const hop = { uid: device, kind: "Device", label, note: "", rank: 0, lane: 0, shared: true } as unknown as Hop;
  return { hop, uid: device, device, u: p.u + p.w / 2, v: p.v + p.h / 2, blocked: false };
}

/** The points of one segment: along its cable when the tile is loaded, else straight. No labels. */
function segmentPoints(scene: Scene, s: FlowSegment): RoutePoint[] {
  return routePoints(scene, [stepOf(scene, s.from), stepOf(scene, s.to)]).map((p) => {
    const point: RoutePoint = { u: p.u, v: p.v };
    if (p.y !== undefined) point.y = p.y;
    if (s.phase === "reply") point.y = (p.y ?? Y.route) + REPLY_LIFT;
    return point;
  });
}

function center(scene: Scene, device: string): RoutePoint {
  const p = scene.layout.get(device)!;
  return { u: p.u + p.w / 2, v: p.v + p.h / 2 };
}

/**
 * The routes of one evaluated path: one route per run of consecutive segments in one state and one phase, both
 * ends in the drawing. A segment with an end outside the drawing breaks the route there; nothing is drawn across
 * a device the map does not hold. A failing path gets a stop marker at its stop device.
 */
function pathRoutes(scene: Scene, connection: string, path: FlowPath): Route[] {
  const out: Route[] = [];
  let current: Route | null = null;
  let last: string | null = null;
  let phase: string | null = null;
  path.segments.forEach((s, i) => {
    if (!onMap(scene, s.from) || !onMap(scene, s.to)) {
      current = null;
      return;
    }
    const points = segmentPoints(scene, s);
    const state: RouteState = s.state;
    if (current && current.state === state && last === s.from && phase === s.phase) {
      const prev = current.points[current.points.length - 1];
      const next = points[0];
      current.points.push(...(prev && Math.abs(prev.u - next.u) < 1e-6 && Math.abs(prev.v - next.v) < 1e-6 ? points.slice(1) : points));
    } else {
      current = { id: `${connection}:${path.id}:${i}`, state, points };
      out.push(current);
    }
    last = s.to;
    phase = s.phase;
  });
  if (outcomeOf(path.result) === "fails" && path.stop_device && onMap(scene, path.stop_device)) {
    out.push({ id: `${connection}:${path.id}:stop`, state: "fails", line: false, points: [{ ...center(scene, path.stop_device), blocked: true }] });
  }
  return out;
}

/** The first endpoint device of a side that the drawing holds, and the endpoint devices it does not hold. */
function endpointDevices(scene: Scene, side: FlowConnection["endpoints"]["source"]): { shown: string[]; missing: string[] } {
  const all = [...new Set(side.flatMap((e) => e.devices))];
  return { shown: all.filter((d) => onMap(scene, d)), missing: all.filter((d) => !onMap(scene, d)) };
}

/**
 * The routes of the shown application connections on the twin.
 *
 * An evaluated connection draws each of its paths by segment state. A connection that is not evaluated draws a
 * dotted arc from its first source device to its first destination device, never a success. An unresolved
 * connection draws its endpoint pins only. Every device a path or an endpoint names that the drawing does not
 * hold is counted in `offMap`. The devices on a shown path are path hops, not application components.
 */
export function placeFlows(scene: Scene, connections: FlowConnection[]): PlacedFlows {
  const routes: Route[] = [];
  const highlight = new Set<string>();
  const offMap = new Map<string, number>();
  for (const c of connections) {
    const missing = new Set<string>();
    const source = endpointDevices(scene, c.endpoints.source);
    const destination = endpointDevices(scene, c.endpoints.destination);
    const pins: RoutePoint[] = [];
    if (c.state === "unresolved" || c.state === "not-evaluated") {
      for (const d of [...source.missing, ...destination.missing]) missing.add(d);
      for (const d of [...source.shown, ...destination.shown]) highlight.add(d);
      const a = source.shown[0];
      const b = destination.shown[0];
      if (c.state === "not-evaluated" && a && b && a !== b) {
        const arc = scene.tunnelArc(a, b).map(([u, y, v]) => ({ u, v, y }));
        routes.push({ id: `${c.id}:not-evaluated`, state: "not-evaluated", points: arc });
      }
      for (const d of source.shown) pins.push({ ...center(scene, d), pin: "start" });
      for (const d of destination.shown) pins.push({ ...center(scene, d), pin: "end" });
      if (pins.length) routes.push({ id: `${c.id}:pins`, state: c.state, line: false, points: pins });
    } else {
      for (const path of c.paths) {
        for (const d of path.devices) {
          if (onMap(scene, d)) highlight.add(d);
          else missing.add(d);
        }
        routes.push(...pathRoutes(scene, c.id, path));
      }
      const first = c.paths.find((p) => p.devices.length > 0);
      const start = first?.devices[0];
      const forward = first ? first.devices.filter((_, i) => first.phases[i] === "forward") : [];
      const end = forward[forward.length - 1];
      if (start && onMap(scene, start)) pins.push({ ...center(scene, start), pin: "start" });
      if (end && end !== start && onMap(scene, end) && (!first || outcomeOf(first.result) !== "fails")) pins.push({ ...center(scene, end), pin: "end" });
      if (pins.length) routes.push({ id: `${c.id}:pins`, state: shownState(c), line: false, points: pins });
    }
    offMap.set(c.id, missing.size);
  }
  return { routes, highlight, offMap };
}
