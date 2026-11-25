/** The overlay functions mark a drawn line as a trunked link, a VLAN mismatch or an L3 adjacency. */

import type { MapSubnet, MapVlan } from "../api/types";

/** The two ends of a drawn cable, by device uid and port name. */
export interface OverlayEdge {
  a: string;
  aPort: string;
  b: string;
  bPort: string;
}

export interface VlanOption {
  vid: number;
  label: string;
  /** how many drawn devices have the VLAN at all */
  devices: number;
}

export function vlanOptions(vlans: MapVlan[]): VlanOption[] {
  const byVid = new Map<number, { name: string | null; devices: Set<string> }>();
  for (const v of vlans) {
    const entry = byVid.get(v.vid) ?? { name: null, devices: new Set<string>() };
    entry.name = entry.name ?? v.name ?? v.segment;
    entry.devices.add(v.dev);
    byVid.set(v.vid, entry);
  }
  return [...byVid.entries()]
    .sort(([x], [y]) => x - y)
    .map(([vid, e]) => ({
      vid,
      label: e.name ? `VLAN ${vid} ${e.name}` : `VLAN ${vid}`,
      devices: e.devices.size,
    }));
}

/** What one cable carries of the selected VLAN: on both end ports, on one
 *  named side only, or not at all. */
export type Carriage = "both" | "a" | "b" | "none";

export interface VlanOverlay {
  /** devices that have the VLAN on any port or as an SVI */
  devices: ReadonlySet<string>;
  /** device uid to the name of the SVI bound to the VLAN there */
  svi: ReadonlyMap<string, string>;
  /** one entry per edge, in the edges' own order */
  edges: Carriage[];
}

export function vlanOverlay(vlans: MapVlan[], edges: OverlayEdge[], vid: number): VlanOverlay {
  const ports = new Map<string, Set<string>>();
  const devices = new Set<string>();
  const svi = new Map<string, string>();
  for (const v of vlans) {
    if (v.vid !== vid) continue;
    devices.add(v.dev);
    ports.set(v.dev, new Set(v.ports));
    if (v.svi) svi.set(v.dev, v.svi);
  }
  const carries = (dev: string, port: string) => ports.get(dev)?.has(port) ?? false;
  return {
    devices,
    svi,
    edges: edges.map((e) => {
      const a = carries(e.a, e.aPort);
      const b = carries(e.b, e.bPort);
      return a && b ? "both" : a ? "a" : b ? "b" : "none";
    }),
  };
}

export interface VrfOption {
  key: string;
  label: string;
  devices: number;
}

/** The server groups the members by the same key. */
export function domainKey(s: Pick<MapSubnet, "domain" | "vrf">): string {
  return s.domain ?? `vrf:${s.vrf}`;
}

export function vrfOptions(subnets: MapSubnet[]): VrfOption[] {
  const byKey = new Map<string, { label: string; devices: Set<string> }>();
  for (const s of subnets) {
    const key = domainKey(s);
    const entry = byKey.get(key) ?? {
      label: s.domain ?? `VRF ${s.vrf}`,
      devices: new Set<string>(),
    };
    for (const m of s.members) entry.devices.add(m.dev);
    byKey.set(key, entry);
  }
  return [...byKey.entries()]
    .sort(([x], [y]) => x.localeCompare(y))
    .map(([key, e]) => ({ key, label: e.label, devices: e.devices.size }));
}

/** Two drawn devices that share one connected prefix in the selected domain. */
export interface Adjacency {
  a: string;
  b: string;
  subnet: MapSubnet;
}

export interface VrfOverlay {
  /** devices with an address in the domain */
  devices: ReadonlySet<string>;
  /** one per shared prefix per device pair, a < b, in subnet order */
  adjacencies: Adjacency[];
  /** one entry per edge: whether the cable's two devices are adjacent in this domain */
  edges: boolean[];
}

export function vrfOverlay(subnets: MapSubnet[], edges: OverlayEdge[], key: string): VrfOverlay {
  const devices = new Set<string>();
  const adjacencies: Adjacency[] = [];
  const pairs = new Set<string>();
  for (const s of subnets) {
    if (domainKey(s) !== key) continue;
    const here = [...new Set(s.members.map((m) => m.dev))].sort();
    for (const d of here) devices.add(d);
    for (let i = 0; i < here.length; i++) {
      for (let j = i + 1; j < here.length; j++) {
        pairs.add(`${here[i]}~${here[j]}`);
        adjacencies.push({ a: here[i], b: here[j], subnet: s });
      }
    }
  }
  return {
    devices,
    adjacencies,
    edges: edges.map((e) => pairs.has([e.a, e.b].sort().join("~"))),
  };
}
