/**
 * The segments and the clients of a site diagram, without a DOM: the names
 * of a segment, the bridge domains whose clients a layer shows, and the client
 * badges. The segment bars are nodes of the tiered layout (segrow.ts).
 *
 * Clients are badges per attachment point, a port or an access point and
 * SSID, under the device ("Port 2: 3 clients"). A badge is collapsed; an
 * expanded badge shows up to `GLYPHS` clients as small glyphs with the name,
 * the address and the vendor. Clients are what the run collected, never a
 * current reading.
 */

import type { MapClient, MapClientGroup, TopologyModel, TopologySegment } from "../api/types";
import { domainKey } from "../diagram/overlay";
import type { CyElement } from "./layout";
import type { Layer } from "./overlays";

/** A drawn device: the centre of its symbol and the width of its caption box. */
export interface Placed {
  x: number;
  y: number;
  width: number;
  /** the bottom of its caption, from the centre of its symbol */
  bottom?: number;
}

/** The clients an expanded badge shows; the side panel lists them all. */
export const GLYPHS = 24;
/** What a device occupies under its centre when the caller states no box: the symbol, and the caption. */
const DEVICE_BOTTOM = 52;
const BADGE_H = 16;
const BADGE_CHAR = 5.8;
const GLYPH_COLUMNS = 4;
const GLYPH_W = 118;
const GLYPH_H = 50;

/** The key of a client group: its device, its port and its SSID. */
export function groupKey(g: Pick<MapClientGroup, "dev" | "port" | "ssid">): string {
  return `${g.dev}|${g.port ?? ""}|${g.ssid ?? ""}`;
}

/** Where a group attaches, as a reader names it: the port, else the SSID. */
export function whereText(g: Pick<MapClientGroup, "port" | "ssid">): string {
  return g.port ?? g.ssid ?? "Wired";
}

export const clientsText = (n: number) => (n === 1 ? "1 client" : `${n} clients`);

/** "VLAN 10 Office 192.168.10.0/24": the IPv4 prefixes, else the others. */
export function segmentLabel(s: Pick<TopologySegment, "vid" | "name" | "cidrs">): string {
  const v4 = s.cidrs.filter((c) => !c.includes(":"));
  const cidrs = v4.length ? v4 : s.cidrs.slice(0, 1);
  return [s.vid !== null ? `VLAN ${s.vid}` : null, s.name, ...cidrs].filter(Boolean).join(" ");
}

/** The segments of a VLAN id: one per bridge domain, more than one only across L2 fabrics. */
export function segmentsOfVid(model: TopologyModel, vid: number | null): TopologySegment[] {
  return vid === null ? [] : (model.segments ?? []).filter((s) => s.vid === vid);
}

/** The bridge domains whose clients a layer shows: every one (null) in the
 *  physical layer, the picked VLAN's in L2, and in L3 those whose prefixes are
 *  connected prefixes of the picked routing domain. */
export function shownDomains(model: TopologyModel, layer: Layer, vid: number | null, domain: string | null): Set<string> | null {
  if (layer === "phys") return null;
  if (layer === "l2") return new Set(segmentsOfVid(model, vid).map((s) => s.bd));
  const cidrs = new Set((model.subnets ?? []).filter((s) => domain !== null && domainKey(s) === domain).map((s) => s.cidr));
  return new Set((model.segments ?? []).filter((s) => s.cidrs.some((c) => cidrs.has(c))).map((s) => s.bd));
}

/** The count of a group in the shown bridge domains, and its clients there. */
export function groupIn(g: MapClientGroup, bds: Set<string> | null): { count: number; clients: MapClient[] } {
  if (bds === null) return { count: g.count, clients: g.clients };
  const count = Object.entries(g.by_bd ?? {}).reduce((sum, [bd, n]) => sum + (bds.has(bd) ? n : 0), 0);
  return { count, clients: g.clients.filter((c) => c.bd && bds.has(c.bd)) };
}

/** The client badges of the drawn devices, in the bridge domains the layer
 *  shows, with the glyphs of each expanded one. A device's badges sit in rows
 *  of four under its caption, in group order. */
export function clientElements(
  model: TopologyModel,
  layer: Layer,
  vid: number | null,
  domain: string | null,
  at: ReadonlyMap<string, Placed>,
  expanded: ReadonlySet<string>,
): CyElement[] {
  const bds = shownDomains(model, layer, vid, domain);
  const perDevice = new Map<string, { g: MapClientGroup; count: number; clients: MapClient[] }[]>();
  const groups = [...(model.clients ?? [])].sort((a, b) => (groupKey(a) < groupKey(b) ? -1 : groupKey(a) > groupKey(b) ? 1 : 0));
  for (const g of groups) {
    if (!at.has(g.dev)) continue;
    const shown = groupIn(g, bds);
    if (shown.count === 0) continue;
    perDevice.set(g.dev, [...(perDevice.get(g.dev) ?? []), { g, ...shown }]);
  }
  const out: CyElement[] = [];
  for (const [dev, list] of perDevice) {
    const p = at.get(dev)!;
    let rowY = p.y + (p.bottom ?? DEVICE_BOTTOM) + BADGE_H;
    for (let start = 0; start < list.length; start += GLYPH_COLUMNS) {
      const row = list.slice(start, start + GLYPH_COLUMNS).map((item) => {
        const label = `${whereText(item.g)}: ${clientsText(item.count)}`;
        return { ...item, label, w: Math.round(label.length * BADGE_CHAR + 14) };
      });
      const total = row.reduce((sum, r) => sum + r.w, 0) + (row.length - 1) * 8;
      let x = p.x - total / 2;
      let below = 0;
      for (const r of row) {
        const key = groupKey(r.g);
        const id = `cl:${key}`;
        const open = expanded.has(key);
        const cx = x + r.w / 2;
        out.push({
          group: "nodes",
          data: { id, label: r.label, kind: "clientbadge", group: key, width: r.w },
          position: { x: cx, y: rowY },
          classes: open ? "clientbadge open" : "clientbadge",
        });
        if (open) below = Math.max(below, glyphs(out, id, r.clients.slice(0, GLYPHS), cx, rowY));
        x += r.w + 8;
      }
      rowY += BADGE_H + 8 + below;
    }
  }
  return out;
}

/** The glyphs of an expanded badge in a grid under it; returns the height they take. */
function glyphs(out: CyElement[], badge: string, clients: MapClient[], cx: number, y: number): number {
  const columns = Math.min(GLYPH_COLUMNS, clients.length);
  const left = cx - ((columns - 1) * GLYPH_W) / 2;
  clients.forEach((c, i) => {
    const label = [c.name, c.ips[0], c.vendor].filter(Boolean).join("\n");
    out.push({
      group: "nodes",
      data: { id: `${badge}:${c.uid}`, label, kind: "clientglyph", badge, uid: c.uid },
      position: { x: left + (i % GLYPH_COLUMNS) * GLYPH_W, y: y + BADGE_H + 12 + Math.floor(i / GLYPH_COLUMNS) * GLYPH_H },
      classes: "clientglyph",
    });
  });
  return clients.length ? Math.ceil(clients.length / GLYPH_COLUMNS) * GLYPH_H + 8 : 0;
}

/** "11:22:33:44:55:66" for the canonical 12 hex digits; any other form as it is. */
export function macText(mac: string | null | undefined): string {
  if (!mac) return "";
  return /^[0-9a-f]{12}$/.test(mac) ? (mac.match(/../g) ?? []).join(":") : mac;
}
