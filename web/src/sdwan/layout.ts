/**
 * The geometry of the SD-WAN pane: one edge and the devices it connects to.
 *
 * The picture has 3 rows. At the top, each hub site is a frame: its switches
 * and other devices in the upper row, its hubs in the lower row. The cloud
 * gateways have a frame of their own at the right. At the bottom is the edge,
 * and between the edge and the frames are its WAN links. A tunnel goes from
 * the WAN link that it leaves on (the same edge interface) to its hub or
 * gateway. A tunnel with no matching WAN link goes from the edge.
 */

import type { SdwanTopology } from "../api/types";
import type { View } from "../diagram/useCanvas";

export type SdwanNodeKind = "device" | "hub" | "branches" | "gateway" | "edge" | "link";

export interface SdwanNode {
  uid: string;
  kind: SdwanNodeKind;
  name: string;
  caption: string;
  x: number;
  y: number;
  w: number;
  h: number;
  /** the branch names of a "branches" chip, in name order */
  members?: string[];
}

export interface SdwanFrame {
  key: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface SdwanCableLine {
  a: string;
  b: string;
  aPort: string;
  bPort: string;
  source: string | null;
  /** the index of the cable among the cables between one device pair, from 0 */
  lane: number;
}

export interface SdwanTunnelLine {
  uid: string;
  /** the WAN link node, or the edge node when no WAN link has the interface */
  from: string;
  to: string;
  kind: "hub" | "branch" | "gateway";
  interface: string;
  peerIp: string | null;
  /** the tunnels the line stands for: more than 1 only on a line to branches */
  count: number;
  /** the lane of the line among the lines with the same two ends */
  lane: number;
}

/** The most chips in one row of a frame; a longer row wraps. */
export const MAX_ROW_CHIPS = 8;

function rows(uids: string[]): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < uids.length; i += MAX_ROW_CHIPS) out.push(uids.slice(i, i + MAX_ROW_CHIPS));
  return out;
}

export interface SdwanLayout {
  frames: SdwanFrame[];
  nodes: SdwanNode[];
  cables: SdwanCableLine[];
  tunnels: SdwanTunnelLine[];
  /** the count of tunnels whose far end is not in the graph */
  unresolved: number;
  fit: View;
}

export const METRICS = {
  chipW: 176,
  chipH: 36,
  linkW: 168,
  linkH: 44,
  gapX: 24,
  // the space above the upper row of a frame, for its label
  framePadTop: 36,
  framePad: 18,
  rowGap: 70,
  frameGap: 40,
  // from the bottom of the frames to the WAN link row, and on to the edge
  linkDrop: 200,
  edgeDrop: 110,
  // the space above the frames, for the arcs of cables in one row
  arcRoom: 90,
  margin: 40,
};

export const GATEWAY_FRAME = "gateways";
export const BRANCH_FRAME = "branches";

/** The uid of the chip of the branches of one site. */
export function branchGroupUid(site: string | null): string {
  return `sdwan-branches:${site ?? ""}`;
}

function linkCaption(l: SdwanTopology["links"][number]): string {
  const speed = l.up_mbps != null && l.down_mbps != null ? `${l.down_mbps}/${l.up_mbps} Mbit/s` : "";
  return [l.carrier ?? l.provider ?? l.kind ?? "", l.public_ip ?? "", speed].filter(Boolean).join(", ");
}

export function layoutSdwan(t: SdwanTopology, m = METRICS): SdwanLayout {
  const nodes: SdwanNode[] = [];
  const frames: SdwanFrame[] = [];

  // the frames: one for each site, in code order, then the gateways
  const sites = new Map<string, { label: string; upper: string[]; lower: string[] }>();
  for (const s of t.sites) {
    sites.set(s.code, { label: s.name || s.code, upper: [], lower: [] });
  }
  const siteOf = (code: string | null) => {
    const key = code ?? "";
    if (!sites.has(key)) sites.set(key, { label: code ?? "No site", upper: [], lower: [] });
    return sites.get(key)!;
  };
  const named = new Map<string, { name: string; caption: string; kind: SdwanNodeKind; members?: string[] }>();
  for (const d of [...t.devices].sort((a, b) => a.name.localeCompare(b.name))) {
    siteOf(d.site).upper.push(d.uid);
    named.set(d.uid, { name: d.name, caption: d.platform ?? "", kind: "device" });
  }
  for (const h of [...t.hubs].sort((a, b) => a.name.localeCompare(b.name))) {
    siteOf(h.site).lower.push(h.uid);
    named.set(h.uid, { name: h.name, caption: "hub", kind: "hub" });
  }
  const columns = [...sites]
    .filter(([, s]) => s.upper.length + s.lower.length > 0)
    .sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
  // the branches of a picked hub: one counted chip for each site
  const groupOf = new Map<string, string>();
  const groups = new Map<string, { site: string | null; members: string[] }>();
  for (const b of t.branches ?? []) {
    const uid = branchGroupUid(b.site);
    if (!groups.has(uid)) groups.set(uid, { site: b.site, members: [] });
    groups.get(uid)!.members.push(b.name);
    groupOf.set(b.uid, uid);
  }
  if (groups.size > 0) {
    const label = (site: string | null) => (site ? (sites.get(site)?.label ?? site) : "No site");
    const ordered = [...groups].sort(([, a], [, b]) =>
      a.site === null ? 1 : b.site === null ? -1 : a.site.localeCompare(b.site),
    );
    for (const [uid, g] of ordered) {
      const n = g.members.length;
      named.set(uid, {
        name: label(g.site),
        caption: n === 1 ? "1 branch" : `${n} branches`,
        kind: "branches",
        members: [...g.members].sort((a, b) => a.localeCompare(b)),
      });
    }
    columns.push([BRANCH_FRAME, { label: "Branches", upper: [], lower: ordered.map(([uid]) => uid) }]);
  }
  if (t.gateways.length > 0) {
    const gws = [...t.gateways].sort((a, b) => a.name.localeCompare(b.name));
    for (const g of gws) named.set(g.uid, { name: g.name, caption: "cloud gateway", kind: "gateway" });
    columns.push([GATEWAY_FRAME, { label: "Cloud gateways", upper: [], lower: gws.map((g) => g.uid) }]);
  }

  const top = m.margin + m.arcRoom;
  const upperRows = Math.max(1, ...columns.map(([, col]) => rows(col.upper).length));
  const lowerRows = Math.max(1, ...columns.map(([, col]) => rows(col.lower).length));
  const rowY = (i: number) => top + m.framePadTop + m.chipH / 2 + i * (m.chipH + m.rowGap);
  const rowCount = upperRows + lowerRows;
  const frameH = m.framePadTop + rowCount * m.chipH + (rowCount - 1) * m.rowGap + m.framePad;
  let x = m.margin;
  for (const [key, col] of columns) {
    const count = Math.min(Math.max(col.upper.length, col.lower.length, 1), MAX_ROW_CHIPS);
    const width = count * m.chipW + (count - 1) * m.gapX + 2 * m.framePad;
    frames.push({ key, label: col.label, x, y: top, width, height: frameH });
    const place = (uids: string[], y: number) => {
      // a row with fewer chips sits in the middle of its frame
      const rowW = uids.length * m.chipW + (uids.length - 1) * m.gapX;
      let cx = x + (width - rowW) / 2 + m.chipW / 2;
      for (const uid of uids) {
        const n = named.get(uid)!;
        const { kind, name, caption, members } = n;
        nodes.push({ uid, kind, name, caption, x: cx, y, w: m.chipW, h: m.chipH, ...(members ? { members } : {}) });
        cx += m.chipW + m.gapX;
      }
    };
    rows(col.upper).forEach((row, i) => place(row, rowY(i)));
    rows(col.lower).forEach((row, i) => place(row, rowY(upperRows + i)));
    x += width + m.frameGap;
  }
  const framesW = Math.max(x - m.frameGap - m.margin, m.chipW);
  const centre = m.margin + framesW / 2;

  // the WAN links in interface order, then the edge under them
  const linkY = top + frameH + m.linkDrop;
  const links = [...t.links].sort((a, b) => (a.interface ?? "").localeCompare(b.interface ?? ""));
  const linksW = links.length * m.linkW + Math.max(links.length - 1, 0) * m.gapX * 2;
  let lx = centre - linksW / 2 + m.linkW / 2;
  const linkByInterface = new Map<string, string>();
  for (const l of links) {
    nodes.push({
      uid: l.uid,
      kind: "link",
      name: [l.interface, l.name].filter(Boolean).join(" ") || l.uid,
      caption: linkCaption(l),
      x: lx,
      y: linkY,
      w: m.linkW,
      h: m.linkH,
    });
    if (l.interface && !linkByInterface.has(l.interface)) linkByInterface.set(l.interface, l.uid);
    lx += m.linkW + m.gapX * 2;
  }
  const edgeY = linkY + m.linkH / 2 + m.edgeDrop;
  const e = t.edge;
  nodes.push({
    uid: e.uid,
    kind: "edge",
    name: e.name,
    caption: [e.model, e.city ?? e.location, e.ha_type && e.ha_type !== "NONE" ? e.ha_type : null]
      .filter(Boolean)
      .join(", "),
    x: centre,
    y: edgeY,
    w: m.chipW + 40,
    h: m.chipH + 8,
  });

  const drawn = new Set(nodes.map((n) => n.uid));
  const tunnels: SdwanTunnelLine[] = [];
  const branchLines = new Map<string, SdwanTunnelLine>();
  let unresolved = 0;
  for (const tn of t.tunnels) {
    const to = tn.peer && tn.peer_kind === "branch" ? groupOf.get(tn.peer) : tn.peer;
    if (!to || !tn.peer_kind || !drawn.has(to)) {
      unresolved += 1;
      continue;
    }
    const from = (tn.interface && linkByInterface.get(tn.interface)) || e.uid;
    if (tn.peer_kind === "branch") {
      // one line from a WAN link to the branches of one site
      const key = `${to}~${from}`;
      const line = branchLines.get(key);
      if (line) {
        line.count += 1;
        continue;
      }
      const first: SdwanTunnelLine = {
        uid: key,
        from,
        to,
        kind: "branch",
        interface: tn.interface ?? "",
        peerIp: null,
        count: 1,
        lane: 0,
      };
      branchLines.set(key, first);
      tunnels.push(first);
      continue;
    }
    tunnels.push({
      uid: tn.uid,
      from,
      to,
      kind: tn.peer_kind,
      interface: tn.interface ?? "",
      peerIp: tn.peer_ip,
      count: 1,
      lane: 0,
    });
  }

  // a lane for each tunnel after the first between one link and one far end
  const tunnelLanes = new Map<string, number>();
  for (const tl of tunnels) {
    const pair = `${tl.from}|${tl.to}`;
    tl.lane = tunnelLanes.get(pair) ?? 0;
    tunnelLanes.set(pair, tl.lane + 1);
  }

  // a lane for each cable after the first between one device pair
  const lanes = new Map<string, number>();
  const cables: SdwanCableLine[] = [];
  for (const c of t.cables) {
    if (!drawn.has(c.a_dev) || !drawn.has(c.b_dev)) continue;
    const pair = [c.a_dev, c.b_dev].sort().join("|");
    const lane = lanes.get(pair) ?? 0;
    lanes.set(pair, lane + 1);
    cables.push({ a: c.a_dev, b: c.b_dev, aPort: c.a_port ?? "", bPort: c.b_port ?? "", source: c.source, lane });
  }

  const right = Math.max(m.margin + framesW, centre + linksW / 2, centre + (m.chipW + 40) / 2);
  const fit: View = { x: 0, y: 0, w: right + m.margin, h: edgeY + m.chipH + m.margin };
  return { frames, nodes, cables, tunnels, unresolved, fit };
}
