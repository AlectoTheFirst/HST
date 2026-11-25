/**
 * The Equinix Fabric of one metro as a network map drawing. The grouping is
 * the Equinix pane's (equinix/layout.ts `layoutMetro`): the own devices, the
 * Fabric ports in one block per IBX, and the far ends of the circuits. The
 * geometry is the network map's.
 */

import type { EquinixCircuit, EquinixMetroView, TopologyCable, TopologyModel, TopologyNode } from "../api/types";
import { layoutMetro, type EquinixNodeKind } from "../equinix/layout";

/** The workspace scope of a Fabric drawing: `fabric/<metro>`. */
export const FABRIC_SCOPE = "fabric/";

export const isFabric = (site: string) => site.startsWith(FABRIC_SCOPE);
export const metroOf = (site: string) => site.slice(FABRIC_SCOPE.length);

export interface FabricDrawing {
  model: TopologyModel;
  /** per line between a Fabric port and a far end: its circuits, one text each */
  circuits: Map<string, string[]>;
}

/** The symbol of each node: a role the network map's look knows (netmap/look.ts). */
const ROLE: Record<EquinixNodeKind, string> = {
  switch: "switch",
  edge: "router",
  port: "cloud",
  metro: "cloud",
  provider: "cloud",
  other: "cloud",
};

function circuitText(c: EquinixCircuit): string {
  const tags = c.a?.tag != null || c.z?.tag != null ? `VLAN ${c.a?.tag ?? "none"} / ${c.z?.tag ?? "none"}` : null;
  const facts = [c.type, c.bandwidth_mbps != null ? `${c.bandwidth_mbps} Mbit/s` : null, c.state, tags].filter(Boolean);
  return `${c.name ?? c.uid}${facts.length ? `: ${facts.join(", ")}` : ""}`;
}

export function fabricModel(v: EquinixMetroView): FabricDrawing {
  const laid = layoutMetro(v);
  const site = `fabric:${v.metro}`;
  const ours = `${site}:ours`;
  const far = `${site}:far`;
  const ibxBlock = (ibx: string) => `${site}:ibx:${ibx}`;
  const nodes: TopologyNode[] = [
    { id: site, kind: "site", parent: null, label: `Equinix Fabric ${v.metro}` },
    { id: ours, kind: "block", parent: site, label: "Own devices", block_kind: "dc" },
    ...laid.frames.map((f): TopologyNode => ({ id: ibxBlock(f.key), kind: "block", parent: site, label: f.label, block_kind: "wan-edge" })),
    { id: far, kind: "block", parent: site, label: "Far ends", block_kind: "other" },
  ];
  const ports = new Map(v.ports.map((p) => [p.uid, p]));
  const edges = new Map(v.edge_devices.map((d) => [d.uid, d]));
  for (const n of laid.nodes) {
    const port = ports.get(n.uid);
    const parent = n.kind === "port" ? ibxBlock(port?.ibx ?? "") : n.kind === "switch" || n.kind === "edge" ? ours : far;
    nodes.push({
      id: n.uid,
      kind: "device",
      parent,
      label: n.name,
      role: ROLE[n.kind],
      vendor: n.kind === "port" ? "Equinix" : (edges.get(n.uid)?.vendor ?? null),
      model: n.caption || null,
    });
  }

  const kinds = new Map(laid.nodes.map((n) => [n.uid, n.kind]));
  const cables: TopologyCable[] = laid.cables.map((c) => ({
    id: `fabric:cable:${c.device}|${c.fabricPort}`,
    from: { dev: c.device, port: c.portName || null },
    to: { dev: c.fabricPort, port: null },
    source: c.by ? `bound by ${c.by}` : "bound",
    speed_mbps: ports.get(c.fabricPort)?.speed_mbps ?? null,
    lateral: false,
  }));
  const circuits = new Map<string, string[]>();
  for (const b of laid.bundles) {
    const id = `fabric:bundle:${b.key}`;
    const speeds = b.circuits.map((c) => c.bandwidth_mbps).filter((s): s is number => s != null);
    const count = b.circuits.length;
    cables.push({
      id,
      from: { dev: b.a, port: null },
      to: { dev: b.b, port: count === 1 ? "1 circuit" : `${count} circuits` },
      source: "Equinix Fabric",
      speed_mbps: speeds.length ? speeds.reduce((s, n) => s + n, 0) : null,
      // a circuit between two Fabric ports of the metro joins two nodes of one row
      lateral: kinds.get(b.a) === kinds.get(b.b),
    });
    circuits.set(id, b.circuits.map(circuitText));
  }

  return { model: { snapshot: null, nodes, cables, exits: [], lags: [], split_groups: [] }, circuits };
}
