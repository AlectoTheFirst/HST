/**
 * The L2 and L3 layers of a site diagram, without a DOM. The readings are the
 * device map's (diagram/overlay.ts): a VLAN carried on both ends of a cable is a
 * trunk, on one end a mismatch; two devices with an address on one connected
 * prefix in one routing domain are L3 adjacent, cabled or not. Here they
 * become classes on the drawn elements, and one dashed line for each
 * adjacency that no cable joins. The segment bars of both layers are drawn
 * from the same facts in segments.ts.
 */

import type { MapVlan, TopologyModel } from "../api/types";
import { vlanOverlay, vrfOverlay, type OverlayEdge } from "../diagram/overlay";
import type { CyElement } from "./layout";

export type Layer = "phys" | "l2" | "l3";

/** The cables in the shape the overlay readings take, in model order. */
export function overlayEdges(model: TopologyModel): OverlayEdge[] {
  return model.cables.map((c) => ({ a: c.from.dev, aPort: c.from.port ?? "", b: c.to.dev, bPort: c.to.port ?? "" }));
}

export interface LayerPaint {
  /** element id to the one overlay class it takes */
  classes: Map<string, string>;
  /** the lines the layer adds: L3 adjacencies with no cable */
  extra: CyElement[];
  /** what the layer lit, for the toolbar */
  note: string;
}

const NONE: LayerPaint = { classes: new Map(), extra: [], note: "" };

/** "1 device", "2 devices": a count with its noun, singular for one. */
export function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** The gateway interfaces of the VLAN's segments as VLAN rows: a device whose
 *  interface is attached to the segment is in the layer, and an untagged
 *  routed port carries the VLAN on its cable (`basis` cable, the port has the
 *  interface's name). */
function gatewayVlans(model: TopologyModel, vid: number): MapVlan[] {
  // a device with a VLAN row of its own keeps it: the overlay takes one row per device
  const stated = new Set((model.vlans ?? []).filter((v) => v.vid === vid).map((v) => v.dev));
  return (model.segments ?? [])
    .filter((s) => s.vid === vid)
    .flatMap((s) =>
      s.gateways
        .filter((g) => !g.fhrp && !stated.has(g.dev))
        .map((g) => ({ dev: g.dev, vid, name: s.name, segment: s.name, bd: s.bd, ports: g.basis === "cable" ? [g.iface] : [], native: [], svi: g.basis === "cable" ? null : g.iface })),
    );
}

/** The paint of `layer` for the VLAN `vid` or the routing domain key `domain`. */
export function paint(model: TopologyModel, layer: Layer, vid: number | null, domain: string | null): LayerPaint {
  const devices = model.nodes.filter((n) => n.kind === "device").map((n) => n.id);
  const edges = overlayEdges(model);
  if (layer === "l2") {
    if (vid === null) return { ...NONE, note: "no VLAN data" };
    const o = vlanOverlay([...(model.vlans ?? []), ...gatewayVlans(model, vid)], edges, vid);
    const classes = new Map<string, string>();
    for (const d of devices) classes.set(d, o.devices.has(d) ? "ov-on" : "ov-off");
    model.cables.forEach((c, i) => {
      const carriage = o.edges[i];
      classes.set(c.id, carriage === "both" ? "ov-both" : carriage === "none" ? "ov-off" : "ov-half");
    });
    const trunks = o.edges.filter((c) => c === "both").length;
    const half = o.edges.filter((c) => c === "a" || c === "b").length;
    return {
      classes,
      extra: [],
      note: `${count(o.devices.size, "device", "devices")}, ${count(trunks, "trunked cable", "trunked cables")}` + (half ? `, ${half} one-sided` : ""),
    };
  }
  if (layer === "l3") {
    if (domain === null) return { ...NONE, note: "no connected prefixes" };
    const o = vrfOverlay(model.subnets ?? [], edges, domain);
    const classes = new Map<string, string>();
    for (const d of devices) classes.set(d, o.devices.has(d) ? "ov-on" : "ov-off");
    model.cables.forEach((c, i) => classes.set(c.id, o.edges[i] ? "ov-both" : "ov-off"));
    const cabled = new Set(edges.map((e) => [e.a, e.b].sort().join("~")));
    const drawn = new Set(devices);
    const extra: CyElement[] = [];
    o.adjacencies.forEach((adj, i) => {
      if (cabled.has(`${adj.a}~${adj.b}`) || !drawn.has(adj.a) || !drawn.has(adj.b)) return;
      extra.push({
        group: "edges",
        data: { id: `adj:${i}`, source: adj.a, target: adj.b, label: adj.subnet.cidr },
        classes: "adjacency",
      });
    });
    return {
      classes,
      extra,
      note: `${count(o.devices.size, "device", "devices")}, ${count(o.adjacencies.length, "shared prefix", "shared prefixes")}`,
    };
  }
  return NONE;
}
