/**
 * Application flows over a site diagram, without a DOM, in the paint shape of
 * the L2 and L3 layers (overlays.ts). The flows are the stored evaluation
 * paths of GET /api/business-applications/{id}/flows (applications/flows.ts).
 *
 * Each pair of consecutive devices on a path lights the cable between them
 * when the drawing has one, and adds a dashed logical line when it does not.
 * A device of a path that is not in this drawing is counted, not drawn. A
 * connection with no stored evaluation draws a dotted line between its
 * endpoint devices, never a path; an unresolved one marks its endpoint
 * devices only. The state is in the line style and the device marker as well
 * as the colour: solid when it passes, solid with a stop marker for a failure,
 * dashed from the first unknown step, dotted for not evaluated.
 */

import type { TopologyModel } from "../api/types";
import type { FlowConnection, SegmentState } from "../applications/flows";
import type { CyElement } from "./layout";
import type { LayerPaint } from "./overlays";

/** Every class the flow paint sets, for a repaint from clean. */
export const FLOW_CLASSES =
  "fl-on fl-off fl-stop fl-unknown fl-endpoint fl-passes fl-fails fl-decided fl-open";
/** The class of the lines the flow paint adds. */
export const FLOW_LINK = "flow-link";
/** The most dotted lines one connection with no evaluation draws. */
const MAX_PLACEHOLDER_LINES = 20;

const WORST: readonly SegmentState[] = ["fails", "open", "decided", "passes"];
const worse = (a: SegmentState | undefined, b: SegmentState): SegmentState =>
  a === undefined || WORST.indexOf(b) < WORST.indexOf(a) ? b : a;

const pairKey = (a: string, b: string) => (a < b ? `${a}~${b}` : `${b}~${a}`);

export interface FlowPaint extends LayerPaint {
  /** distinct path devices that are not in this drawing */
  offDrawing: number;
}

const NONE: FlowPaint = { classes: new Map(), extra: [], note: "", offDrawing: 0 };

/** The paint of the shown `connections` over `model`. */
export function flowPaint(model: TopologyModel, connections: FlowConnection[]): FlowPaint {
  if (connections.length === 0) return NONE;
  const drawn = new Set(model.nodes.filter((n) => n.kind === "device").map((n) => n.id));
  const cables = new Map<string, string>();
  for (const c of model.cables) if (!cables.has(pairKey(c.from.dev, c.to.dev))) cables.set(pairKey(c.from.dev, c.to.dev), c.id);

  const cableState = new Map<string, SegmentState>();
  const logical = new Map<string, { a: string; b: string; state: SegmentState }>();
  const lit = new Set<string>();
  const marks = new Map<string, Set<string>>();
  const mark = (device: string, cls: string) => {
    if (!drawn.has(device)) return;
    const set = marks.get(device) ?? new Set<string>();
    set.add(cls);
    marks.set(device, set);
  };
  const off = new Set<string>();
  const extra: CyElement[] = [];
  let paths = 0;

  for (const c of connections) {
    if (c.state === "unresolved") {
      for (const e of [...c.endpoints.source, ...c.endpoints.destination]) for (const d of e.devices) mark(d, "fl-endpoint");
      continue;
    }
    if (c.state === "not-evaluated" || c.paths.length === 0) {
      const sources = [...new Set(c.endpoints.source.flatMap((e) => e.devices))].filter((d) => drawn.has(d));
      const targets = [...new Set(c.endpoints.destination.flatMap((e) => e.devices))].filter((d) => drawn.has(d));
      for (const d of [...sources, ...targets]) mark(d, "fl-endpoint");
      let n = 0;
      for (const a of sources)
        for (const b of targets) {
          if (a === b || n >= MAX_PLACEHOLDER_LINES) continue;
          n++;
          extra.push({
            group: "edges",
            data: { id: `flow:${c.id}:pending:${a}~${b}`, source: a, target: b, label: c.name },
            classes: `${FLOW_LINK} fl-not-evaluated`,
          });
        }
      continue;
    }
    for (const p of c.paths) {
      paths++;
      for (const d of p.devices) {
        if (drawn.has(d)) lit.add(d);
        else off.add(d);
      }
      if (p.stop_device) mark(p.stop_device, "fl-stop");
      if (p.unknown_device) mark(p.unknown_device, "fl-unknown");
      for (const s of p.segments) {
        if (!drawn.has(s.from) || !drawn.has(s.to)) continue;
        const key = pairKey(s.from, s.to);
        const cable = cables.get(key);
        if (cable) cableState.set(cable, worse(cableState.get(cable), s.state));
        else {
          const id = `flow:${c.id}:${key}`;
          const known = logical.get(id);
          logical.set(id, { a: s.from, b: s.to, state: worse(known?.state, s.state) });
        }
      }
    }
  }

  const classes = new Map<string, string>();
  for (const d of drawn) {
    const set = new Set(marks.get(d) ?? []);
    set.add(lit.has(d) || set.size > 0 ? "fl-on" : "fl-off");
    classes.set(d, [...set].sort().join(" "));
  }
  for (const c of model.cables) {
    const state = cableState.get(c.id);
    classes.set(c.id, state ? `fl-${state}` : "fl-off");
  }
  for (const [id, line] of logical) {
    extra.push({ group: "edges", data: { id, source: line.a, target: line.b }, classes: `${FLOW_LINK} fl-${line.state}` });
  }
  const parts = [`${connections.length} ${connections.length === 1 ? "connection" : "connections"}`, `${paths} ${paths === 1 ? "path" : "paths"}`];
  if (off.size) parts.push(`${off.size} ${off.size === 1 ? "device" : "devices"} off this drawing`);
  return { classes, extra, note: parts.join(", "), offDrawing: off.size };
}
