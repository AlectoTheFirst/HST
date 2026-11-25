import type { Hop, PathResponse } from "../../api/types";
import { legOutcome, legWord } from "../../flowdesk/verdict";
import type { Scene } from "../render/scene";
import type { RoutePoint } from "../render/types";

/** One hop of the trace on the map: the layout element it took and the device it belongs to. */
export interface Step {
  hop: Hop;
  /** The layout element the hop sits on: a port when its tile is loaded, else its device. */
  uid: string;
  device: string;
  u: number;
  v: number;
  blocked: boolean;
  /** The walk's word for the leg the step ends, set only on the last step of a leg that is not forwarded or not decided. */
  word?: string;
  /** A tunnel step: the carrier's own hops under it, the trip of the encapsulated packet. */
  carrier?: Hop[];
}

export interface Placed {
  steps: Step[];
  offMap: Hop[];
}

/** The device uid a port, interface or device hop names, from its uid; null for any other hop. */
export function deviceOf(hop: Hop): string | null {
  if (hop.kind === "Device") return hop.uid;
  if (hop.kind === "Port" || hop.kind === "Interface") {
    const m = /^(.*?)\/(?:port|if)\//.exec(hop.uid);
    return m ? m[1] : null;
  }
  return null;
}

/** The lanes of `result` in order: one per equal-cost path, region split or merged source part the walk drew. */
export function lanesOf(result: PathResponse): number[] {
  const lanes = new Set<number>([0]);
  for (const leg of result.legs) lanes.add(leg.lane ?? 0);
  for (const h of result.hops) if (!(h.overlay ?? 0)) lanes.add(h.lane ?? 0);
  return [...lanes].sort((a, b) => a - b);
}

/**
 * Each hop of `lane` of `result` to a map point: the lane's own hops and
 * the shared hops before the walk forked. A device hop takes its device; an interface or port hop takes its port
 * when the tile is loaded and its device otherwise; any other hop takes the device of the hop before it. A hop
 * with no device on the map goes to `offMap`. Only the legs of the lane mark a step blocked.
 */
export function placeHops(scene: Scene, result: PathResponse, lane = 0): Placed {
  const hops = result.hops
    .filter((h) => ((h.lane ?? 0) === lane || (h.shared && (h.lane ?? 0) === 0)) && !(h.overlay ?? 0))
    .sort((a, b) => a.rank - b.rank);
  // The carrier hops of each tunnel: the encapsulated packet's own trip, nested under the tunnel step.
  const carriers = new Map<string, Hop[]>();
  for (const h of result.hops) {
    if (!(h.overlay ?? 0) || !h.tunnel) continue;
    const list = carriers.get(h.tunnel) ?? [];
    list.push(h);
    carriers.set(h.tunnel, list);
  }
  for (const list of carriers.values()) list.sort((a, b) => a.rank - b.rank);
  const blockedDevices = new Set<string>();
  for (const leg of result.legs) {
    if (!leg.blocked || (leg.lane ?? 0) !== lane) continue;
    for (const uid of [leg.blocking_uid, leg.fw_uid]) if (uid) blockedDevices.add(uid);
  }
  const portByInterface = new Map<string, string>();
  for (const p of scene.rows("render_t2_ports")) if (p.interface_uid) portByInterface.set(String(p.interface_uid), String(p.uid));
  const steps: Step[] = [];
  const offMap: Hop[] = [];
  let previous: string | null = null;
  for (const hop of hops) {
    let device = deviceOf(hop);
    let element: string | null = null;
    if (hop.kind === "Port" && scene.layout.get(hop.uid)?.kind === "port") element = hop.uid;
    if (hop.kind === "Interface") {
      const port = portByInterface.get(hop.uid);
      if (port && scene.layout.get(port)?.kind === "port") element = port;
    }
    if (device === null) device = previous;
    if (device !== null && scene.layout.get(device)?.kind !== "device") device = null;
    if (device === null) {
      offMap.push(hop);
      continue;
    }
    previous = device;
    const p = scene.layout.get(element ?? device)!;
    const socket = element ? scene.wiring().sockets.get(element) : undefined;
    const [u, v] = socket ? [socket.u, socket.v] : [p.u + p.w / 2, p.v + p.h / 2];
    const blocked = blockedDevices.has(hop.uid) || (hop.kind === "Device" && blockedDevices.has(device));
    const carrier = hop.kind === "Tunnel" ? carriers.get(hop.uid) : undefined;
    steps.push({ hop, uid: element ?? device, device, u, v, blocked, ...(carrier?.length ? { carrier } : {}) });
  }
  // A leg with no route or an undecided leg names no rulebase device.
  const leg = result.legs.find((l) => (l.lane ?? 0) === lane);
  const last = steps[steps.length - 1];
  if (leg && last && legOutcome(leg) !== "ok" && !steps.some((s) => s.blocked)) {
    if (legOutcome(leg) === "bad") last.blocked = true;
    last.word = legWord(leg);
  }
  return { steps, offMap };
}

/**
 * The route through the placed steps: between two steps of different devices the cable between them when
 * its tile is loaded, else the straight line. A step's point repeats nowhere.
 */
export function routePoints(scene: Scene, steps: Step[]): RoutePoint[] {
  const out: RoutePoint[] = [];
  const push = (u: number, v: number, label?: string, blocked?: boolean) => {
    const last = out[out.length - 1];
    if (last && Math.abs(last.u - u) < 1e-6 && Math.abs(last.v - v) < 1e-6) {
      if (blocked) last.blocked = true;
      if (label) last.label = label;
      return;
    }
    out.push({ u, v, ...(label ? { label } : {}), ...(blocked ? { blocked } : {}) });
  };
  const cables = [...scene.rows("render_t2_cables")];
  const wiring = scene.wiring();
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const label = i === 0 ? step.hop.label : i === steps.length - 1 ? step.hop.label : undefined;
    push(step.u, step.v, label, step.blocked);
    const next = steps[i + 1];
    if (!next || next.device === step.device) continue;
    if (step.hop.kind === "Tunnel") {
      for (const [u, y, v] of scene.tunnelArc(step.device, next.device)) {
        const last = out[out.length - 1];
        if (last && Math.abs(last.u - u) < 1e-6 && Math.abs(last.v - v) < 1e-6) continue;
        out.push({ u, v, y });
      }
      continue;
    }
    const cable = cables.find(
      (c) =>
        (c.a_dev === step.device && c.b_dev === next.device) || (c.a_dev === next.device && c.b_dev === step.device),
    );
    if (!cable) continue;
    const route = wiring.routes.get(String(cable.cable_id));
    if (!route) continue;
    const forward = cable.a_dev === step.device;
    for (const [u, v] of forward ? route : [...route].reverse()) push(u, v);
  }
  return out;
}
