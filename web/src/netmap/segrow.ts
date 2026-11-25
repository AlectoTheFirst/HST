/**
 * The segment row of the L2 and L3 layers, without a DOM.
 *
 * A segment is a bridge domain: a VLAN at a site, or an ACI bridge domain. It
 * is drawn as a bar, and every bar is a node of the tiered layout. ELK places the bars in a row of their own, between the
 * devices above it (the gateways and every device upstream of them) and the
 * devices under it.
 *
 * A bar node is a box. A blue line runs across it; the VLAN and the name of
 * the segment, and each prefix of the segment on a line of its own, sit under
 * the line at its left end. A drop from a device above ends at the top of the
 * box, a drop from a device under it at the bottom; each drop has a slot of
 * its own on the box, wide enough for its tag, so no two tags overlap. The
 * tag of a gateway drop names the interface and its addresses in the segment;
 * the tag of a switch drop names its ports.
 *
 * L2 draws the picked VLAN: one bar, with a drop to each gateway interface and
 * to each device that carries the VLAN. L3 draws every segment with a gateway
 * interface in the picked routing domain, one bar each, ordered by VLAN id,
 * with a drop to each of those interfaces. A prefix that no segment holds has
 * no bar: a routed link between two devices is named on its cable
 * (`linkPrefixes`), and a loopback is in the device's Interfaces tab.
 *
 * Every drop leaves its device at a port of its own on the lower edge of the
 * device's box, which holds the symbol and the caption, so ELK routes the drops
 * with right angles and never along one line. The slots of a bar side follow
 * the order of the devices under or over it: a first pass learns that order
 * when a side has more than one slot (`layoutRow`).
 */

import type {
  ElkExtendedEdge,
  ElkNode,
  ElkPort,
  LayoutOptions,
} from "elkjs/lib/elk-api";
import type {
  SegmentGateway,
  TopologyModel,
  TopologySegment,
} from "../api/types";
import { domainKey } from "../diagram/overlay";
import {
  DEVICE_HEIGHT,
  deviceWidth,
  segmentsFor,
  stubs,
  type CyElement,
  type Point,
} from "./layout";
import { caption } from "./look";
import { segmentLabel } from "./segments";
import type { Layer } from "./overlays";
import { FONT } from "./style";

/** The width of `text` in px at the font size `size` of the drawing's font. */
export type Measure = (text: string, size: number) => number;

/** A width for a test or a page with no canvas: a wide average glyph. */
export const estimate: Measure = (text, size) => text.length * size * 0.62;

/** The width a canvas gives the text in the drawing's font, with a margin; the estimate without a canvas. */
export function canvasMeasure(): Measure {
  let context: CanvasRenderingContext2D | null = null;
  try {
    context =
      typeof document === "undefined"
        ? null
        : document.createElement("canvas").getContext("2d");
  } catch {
    context = null;
  }
  if (!context) return estimate;
  const ctx = context;
  return (text, size) => {
    ctx.font = `${size}px ${FONT}`;
    return Math.ceil(ctx.measureText(text).width * 1.04);
  };
}

/** The caption under a device symbol (style.ts `node.device`): 11 px, line height 1.25, 3 px below the symbol. */
const CAPTION_FONT = 11;
const CAPTION_LINE = CAPTION_FONT * 1.25;
const CAPTION_TOP = 3;
/** The room a device box keeps beside and under its caption. */
const BOX_SIDE = 16;
const BOX_FOOT = 6;

export interface Box {
  width: number;
  height: number;
}

/** The box of a device: the symbol, and the caption under it as the canvas draws it. */
export function deviceBox(
  label: string,
  address: string | null | undefined,
  measure: Measure,
): Box {
  const lines = caption(label, address).split("\n");
  const text = Math.max(...lines.map((l) => measure(l, CAPTION_FONT)));
  return {
    width: Math.max(deviceWidth(label), Math.ceil(text + BOX_SIDE)),
    height: Math.ceil(
      DEVICE_HEIGHT + CAPTION_TOP + lines.length * CAPTION_LINE + BOX_FOOT,
    ),
  };
}

/** The boxes of the drawn devices. */
export function deviceBoxes(
  model: TopologyModel,
  measure: Measure,
): Map<string, Box> {
  return new Map(
    model.nodes
      .filter((n) => n.kind === "device")
      .map((n) => [n.id, deviceBox(n.label, n.mgmt_ip, measure)]),
  );
}

/** One drop of a bar: a gateway interface, or the ports of a device that carries the VLAN. */
export interface RowDrop {
  /** unique in its bar: the device, and the interface of a gateway */
  key: string;
  /** the device, or the joint of a first-hop pair (`jointId`) */
  dev: string;
  /** the lines of its tag */
  lines: string[];
  gateway: boolean;
  /** the routers of a first-hop pair, whose one drop this is */
  members?: string[];
}

/** The joint of the routers of a first-hop pair: one point between them their drops leave from. */
export const jointId = (members: string[]) => `fhrp:${[...members].sort().join("+")}`;
const isJoint = (id: string) => id.startsWith("fhrp:");

/** ".3" for 10.15.30.3 next to 10.15.30.1: the address from its first part that differs. */
export function shortAddress(ip: string, from: string): string {
  const sep = ip.includes(":") ? ":" : ".";
  const a = ip.split(sep);
  const b = from.split(sep);
  let k = 0;
  while (k < a.length - 1 && a[k] === b[k]) k++;
  return k ? sep + a.slice(k).join(sep) : ip;
}

/** The element id of a segment: `seg:` and the bridge domain, and the site
 *  when the drawing keeps one record of the bridge domain per site. */
export function segmentId(s: { bd: string; site?: string | null }): string {
  return s.site ? `seg:${s.bd}@${s.site}` : `seg:${s.bd}`;
}

export interface RowBar {
  /** the element id, from segmentId */
  id: string;
  bd: string;
  site: string | null;
  /** "VLAN 10 Office" */
  title: string;
  /** the prefixes of the segment, IPv4 first, one line each */
  prefixes: string[];
  drops: RowDrop[];
  /** the name of the bar in the drawing's text alternative */
  text: string;
}

/** The ports a switch drop's tag names before it counts the rest. */
const TAG_PORTS = 3;

/** The longest line of ports a tag writes on one line. */
const TAG_LINE_CHARS = 36;

/** "Port 2, Port 3, Port 4 and 5 more", on one line, or one port per line when the names are long. */
export function portsText(ports: string[]): string[] {
  const shown = ports.slice(0, TAG_PORTS);
  const more =
    ports.length > TAG_PORTS ? `and ${ports.length - TAG_PORTS} more` : null;
  const line = more ? `${shown.join(", ")} ${more}` : shown.join(", ");
  if (line.length <= TAG_LINE_CHARS) return [line];
  return more ? [...shown, more] : shown;
}

const isV6 = (cidr: string) => cidr.includes(":");

/** IPv4 first, each family in address order. */
export function byAddress(a: string, b: string): number {
  if (isV6(a) !== isV6(b)) return isV6(a) ? 1 : -1;
  if (!isV6(a)) {
    const n = (s: string) => s.split(/[./]/).map(Number);
    const x = n(a);
    const y = n(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++)
      if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
    return 0;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

/** "VLAN 10 Office": the VLAN and the name of a segment. */
export function vlanTitle(s: Pick<TopologySegment, "vid" | "name">): string {
  return [s.vid !== null ? `VLAN ${s.vid}` : null, s.name]
    .filter(Boolean)
    .join(" ");
}

const withLength = (ip: string, cidr: string | null) =>
  cidr && cidr.includes("/") ? `${ip}/${cidr.split("/")[1]}` : ip;

/** The gateway drops of a segment: one per interface, with its addresses, IPv4 first. A
 *  first-hop virtual address is no address of the interface. */
function gatewayDrops(gateways: SegmentGateway[], drawn: ReadonlySet<string>): RowDrop[] {
  // the routers that share a first-hop virtual address on the segment are one gateway, drawn once
  const vips = new Map<string, Set<string>>();
  for (const g of gateways) {
    if (!g.fhrp || !g.ip || !drawn.has(g.dev)) continue;
    vips.set(g.ip, (vips.get(g.ip) ?? new Set()).add(g.dev));
  }
  const pairs = new Map<string, { members: string[]; vips: string[] }>();
  for (const [vip, devs] of vips) {
    if (devs.size < 2) continue;
    const members = [...devs].sort();
    const id = jointId(members);
    const pair = pairs.get(id) ?? { members, vips: [] };
    pair.vips.push(vip);
    pairs.set(id, pair);
  }
  const paired = new Set([...pairs.values()].flatMap((p) => p.members));
  const out: RowDrop[] = [];
  for (const [id, pair] of [...pairs].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const lines = [...pair.vips].sort(byAddress).map((vip) => {
      const cidr = gateways.find((g) => g.ip === vip)?.cidr ?? null;
      const own = gateways.filter((g) => !g.fhrp && g.ip && g.cidr === cidr && pair.members.includes(g.dev)).map((g) => g.ip!);
      const shorts = [...new Set(own)].sort(byAddress).map((ip) => shortAddress(ip, vip));
      return shorts.length ? `${vip} (${shorts.join(" ")})` : vip;
    });
    const ifaces = [...new Set(gateways.filter((g) => pair.members.includes(g.dev)).map((g) => g.iface))];
    if (ifaces.length === 1) lines[0] = `${ifaces[0]} ${lines[0]}`;
    out.push({ key: id, dev: id, lines, gateway: true, members: pair.members });
  }
  const byIface = new Map<string, { dev: string; iface: string; ips: string[] }>();
  for (const g of gateways) {
    if (!drawn.has(g.dev) || g.fhrp || paired.has(g.dev)) continue;
    const key = `${g.dev}|${g.iface}`;
    const entry = byIface.get(key) ?? { dev: g.dev, iface: g.iface, ips: [] };
    if (g.ip && !entry.ips.includes(withLength(g.ip, g.cidr))) entry.ips.push(withLength(g.ip, g.cidr));
    byIface.set(key, entry);
  }
  for (const [key, g] of [...byIface.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const ips = [...g.ips].sort(byAddress);
    const lines = ips.length ? [`${g.iface} ${ips[0]}`, ...ips.slice(1)] : [g.iface];
    out.push({ key, dev: g.dev, lines, gateway: true });
  }
  return out;
}

function bar(s: TopologySegment, drops: RowDrop[], text: string): RowBar {
  const prefixes = [...s.cidrs].sort(byAddress);
  const title = vlanTitle(s);
  return {
    id: segmentId(s),
    bd: s.bd,
    site: s.site ?? null,
    title: title || prefixes[0] || s.bd,
    prefixes: title ? prefixes : prefixes.slice(1),
    drops,
    text,
  };
}

const byBar = (a: TopologySegment, b: TopologySegment) =>
  (a.vid === null ? 1 : 0) - (b.vid === null ? 1 : 0) ||
  (a.vid ?? 0) - (b.vid ?? 0) ||
  (a.bd < b.bd ? -1 : a.bd > b.bd ? 1 : 0) ||
  ((a.site ?? "") < (b.site ?? "") ? -1 : (a.site ?? "") > (b.site ?? "") ? 1 : 0);

/** The bars a layer draws: in L2 the picked VLAN's segments, in L3 the
 *  segments with a gateway interface in the picked routing domain; each with
 *  one drop at least. */
export function rowBars(
  model: TopologyModel,
  layer: Layer,
  vid: number | null,
  domain: string | null,
): RowBar[] {
  const drawn = new Set(
    model.nodes.filter((n) => n.kind === "device").map((n) => n.id),
  );
  const segments = [...(model.segments ?? [])].sort(byBar);
  const out: RowBar[] = [];
  if (layer === "l2" && vid !== null) {
    for (const s of segments) {
      if (s.vid !== vid) continue;
      const drops = gatewayDrops(s.gateways, drawn);
      const routed = new Set(drops.flatMap((d) => d.members ?? [d.dev]));
      for (const c of [...s.carriers].sort((a, b) =>
        a.dev < b.dev ? -1 : a.dev > b.dev ? 1 : 0,
      )) {
        if (!drawn.has(c.dev) || routed.has(c.dev) || c.ports.length === 0)
          continue;
        drops.push({
          key: c.dev,
          dev: c.dev,
          lines: portsText(c.access.length ? c.access : c.ports),
          gateway: false,
        });
      }
      if (drops.length) out.push(bar(s, drops, segmentLabel(s)));
    }
  }
  if (layer === "l3" && domain !== null) {
    for (const s of segments) {
      const mine = s.gateways.filter(
        (g) =>
          domainKey({ domain: g.domain, vrf: g.vrf ?? "default" }) === domain,
      );
      const drops = gatewayDrops(mine, drawn);
      if (drops.length)
        out.push(
          bar(
            s,
            drops,
            [...[...s.cidrs].sort(byAddress), vlanTitle(s)]
              .filter(Boolean)
              .join(" "),
          ),
        );
    }
  }
  return out;
}

/** The prefix of each routed link of the picked domain, by cable id: a
 *  connected prefix that no segment holds, on exactly two drawn devices that a
 *  cable joins, with an address on a port of that cable. */
export function linkPrefixes(
  model: TopologyModel,
  domain: string | null,
): Map<string, string> {
  const out = new Map<string, string>();
  if (domain === null) return out;
  const held = new Set((model.segments ?? []).flatMap((s) => s.cidrs));
  const drawn = new Set(
    model.nodes.filter((n) => n.kind === "device").map((n) => n.id),
  );
  const cables = [...model.cables].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
  for (const s of [...(model.subnets ?? [])].sort((a, b) =>
    byAddress(a.cidr, b.cidr),
  )) {
    if (domainKey(s) !== domain || held.has(s.cidr)) continue;
    const members = s.members.filter((m) => !m.fhrp && drawn.has(m.dev));
    const devs = [...new Set(members.map((m) => m.dev))];
    if (devs.length !== 2) continue;
    const between = cables.filter(
      (c) =>
        !out.has(c.id) &&
        new Set([c.from.dev, c.to.dev]).size === 2 &&
        devs.includes(c.from.dev) &&
        devs.includes(c.to.dev),
    );
    const on = (dev: string, port: string | null) =>
      members.some((m) => m.dev === dev && port !== null && m.iface === port);
    // the addresses sit on the ports of the cable: a loopback pair on two cabled devices is no link
    const cable = between.find(
      (c) => on(c.from.dev, c.from.port) || on(c.to.dev, c.to.port),
    );
    if (cable)
      out.set(
        cable.id,
        out.has(cable.id) ? `${out.get(cable.id)} ${s.cidr}` : s.cidr,
      );
  }
  return out;
}

// --- the geometry of a bar box

/** A drop tag: 9 px text in a box with a 1 px border (style.ts `node.segtag`). */
export const TAG_FONT = 9;
const TAG_LINE = TAG_FONT * 1.25;
const TAG_PAD_X = 4;
const TAG_PAD_Y = 2;
/** The bar label: 10 px, line height 1.3 (style.ts `node.segbar`). */
export const LABEL_FONT = 10;
export const LABEL_LINE = LABEL_FONT * 1.3;
/** The room at the ends of a bar, between two slots, and between a tag and the line. */
const BAR_PAD = 10;
const SLOT_GAP = 12;
const TAG_GAP = 4;
const LABEL_GAP = 5;
const BAR_MIN = 120;

export interface Tag extends Box {
  lines: string[];
}

export function tagBox(lines: string[], measure: Measure): Tag {
  const text = Math.max(...lines.map((l) => measure(l, TAG_FONT)));
  return {
    lines,
    width: Math.ceil(text + 2 * TAG_PAD_X + 2),
    height: Math.ceil(lines.length * TAG_LINE + 2 * TAG_PAD_Y + 2),
  };
}

export interface Slot {
  drop: RowDrop;
  tag: Tag;
  /** the centre of the slot, from the left of the box */
  x: number;
}

export interface BarBox extends Box {
  bar: RowBar;
  /** the height of the line, from the top of the box */
  lineY: number;
  /** the label block under the line, from the left of the box */
  labelX: number;
  labelWidth: number;
  labelHeight: number;
  /** the drops from above, and the drops from under the bar */
  north: Slot[];
  south: Slot[];
}

function slotsWidth(slots: { tag: Tag }[]): number {
  return (
    slots.reduce((sum, s) => sum + s.tag.width, 0) +
    Math.max(0, slots.length - 1) * SLOT_GAP
  );
}

/** The box of a bar, its slots in the order given. */
export function barBox(
  bar: RowBar,
  north: RowDrop[],
  south: RowDrop[],
  measure: Measure,
): BarBox {
  const lines = [bar.title, ...bar.prefixes];
  const labelWidth = Math.ceil(
    Math.max(...lines.map((l) => measure(l, LABEL_FONT))),
  );
  const labelHeight = Math.ceil(lines.length * LABEL_LINE);
  const n = north.map((drop) => ({
    drop,
    tag: tagBox(drop.lines, measure),
    x: 0,
  }));
  const s = south.map((drop) => ({
    drop,
    tag: tagBox(drop.lines, measure),
    x: 0,
  }));
  const northTag = Math.max(0, ...n.map((x) => x.tag.height));
  const southTag = Math.max(0, ...s.map((x) => x.tag.height));
  const lineY = n.length ? northTag + TAG_GAP : TAG_GAP;
  const southStart = BAR_PAD + labelWidth + 2 * SLOT_GAP;
  const width = Math.ceil(
    Math.max(
      BAR_MIN,
      2 * BAR_PAD + labelWidth,
      2 * BAR_PAD + slotsWidth(n),
      s.length ? southStart + slotsWidth(s) + BAR_PAD : 0,
    ),
  );
  let x = (width - slotsWidth(n)) / 2;
  for (const slot of n) {
    slot.x = x + slot.tag.width / 2;
    x += slot.tag.width + SLOT_GAP;
  }
  x = southStart;
  for (const slot of s) {
    slot.x = x + slot.tag.width / 2;
    x += slot.tag.width + SLOT_GAP;
  }
  const below = Math.max(
    LABEL_GAP + labelHeight,
    s.length ? TAG_GAP + southTag : 0,
  );
  return {
    bar,
    width,
    height: Math.ceil(lineY + below + TAG_GAP),
    lineY,
    labelX: BAR_PAD,
    labelWidth,
    labelHeight,
    north: n,
    south: s,
  };
}

// --- the row in the layout

export interface Row {
  bars: BarBox[];
  /** the devices above the row: each gateway and every device upstream of one */
  upper: ReadonlySet<string>;
  boxes: ReadonlyMap<string, Box>;
  /** the joint of each first-hop pair, once a pass placed its routers: as wide as they are apart, its routers left to right */
  joints?: ReadonlyMap<string, { width: number; members: string[] }>;
}

/** The devices from which a cable path runs down to one of `from`, and `from` itself. */
function upstream(model: TopologyModel, from: Iterable<string>): Set<string> {
  const up = new Map<string, string[]>();
  for (const c of model.cables) {
    if (c.lateral) continue;
    up.set(c.to.dev, [...(up.get(c.to.dev) ?? []), c.from.dev]);
  }
  const out = new Set<string>(from);
  const queue = [...out];
  while (queue.length) {
    for (const p of up.get(queue.pop()!) ?? []) {
      if (out.has(p)) continue;
      out.add(p);
      queue.push(p);
    }
  }
  return out;
}

/** The row of a layer's bars: which devices sit above it, and the box of every bar and device. */
export function planRow(
  model: TopologyModel,
  bars: RowBar[],
  measure: Measure,
  boxes = deviceBoxes(model, measure),
): Row {
  const gateways = bars.flatMap((b) => b.drops.filter((d) => d.gateway).flatMap((d) => d.members ?? [d.dev]));
  let upper: Set<string>;
  if (gateways.length) upper = upstream(model, gateways);
  else {
    // no gateway in the drawing: the bar sits over the topmost devices that carry it
    const carriers = [
      ...new Set(bars.flatMap((b) => b.drops.map((d) => d.dev))),
    ];
    const above = new Map(carriers.map((c) => [c, upstream(model, [c])]));
    const top = carriers.filter(
      (c) => !carriers.some((o) => o !== c && above.get(c)!.has(o)),
    );
    upper = upstream(model, top);
    for (const c of top) upper.delete(c);
  }
  return {
    bars: bars.map((b) =>
      barBox(
        b,
        b.drops.filter((d) => upper.has(d.members?.[0] ?? d.dev)),
        b.drops.filter((d) => !upper.has(d.members?.[0] ?? d.dev)),
        measure,
      ),
    ),
    upper,
    boxes,
  };
}

const PART_UPPER = 0;
const PART_ROW = 1;
const PART_LOWER = 2;
const portId = (bar: string, side: "n" | "s", key: string) =>
  `${bar}:${side}:${key}`;
const devPortId = (bar: string, key: string) => `${bar}:from:${key}`;
const dropId = (bar: string, key: string) => `${bar}:drop:${key}`;
/** The width of the joint of a first-hop pair before a pass placed its routers, the least it takes, and its height. */
const JOINT = 16;
const JOINT_H = 3;
/** The line from a router of a first-hop pair to its joint. */
const joinId = (joint: string, member: string) => `${joint}:join:${member}`;
/** The id prefix of a layout-only edge (`rowGraph`). */
export const GLUE = "glue:";

/** The ELK options of a tiered layout with a row: the partitions keep the row
 *  between the devices above it and the devices under it, and the caption is
 *  in the device box, so the layers need less room between them. */
const ROW_OPTIONS: LayoutOptions = {
  "elk.partitioning.activate": "true",
  "elk.layered.spacing.nodeNodeBetweenLayers": "70",
  "elk.spacing.nodeNode": "56",
  "elk.spacing.edgeEdge": "10",
  "elk.spacing.edgeNode": "16",
};

/**
 * The flat ELK graph (layout.ts `toFlatElkGraph`) with the row: each device
 * in its box with the caption, each bar a node with a port per slot, and a
 * drop edge per slot. A device above the row has a port per drop on its lower
 * edge, in the order of the bars, with its cables down in the middle of them.
 * `fixed` false leaves the order of each bar's ports to ELK (the first pass).
 */
export function rowGraph(
  flat: ElkNode,
  model: TopologyModel,
  row: Row,
  fixed = true,
): ElkNode {
  const devPorts = new Map<string, { id: string; order: number }[]>();
  const addDevPort = (dev: string, id: string, order: number) =>
    devPorts.set(dev, [...(devPorts.get(dev) ?? []), { id, order }]);
  const children: ElkNode[] = (flat.children ?? []).map((c) => {
    const box = row.boxes.get(c.id);
    return box ? { ...c, width: box.width, height: box.height } : { ...c };
  });
  const edges: ElkExtendedEdge[] = (flat.edges ?? []).map((e) => ({ ...e }));
  // the joint of each first-hop pair: a short line under its routers, as wide as they are apart; a
  // line comes down from each router to its end, and the pair's drops leave from it in bar order
  const pairDrops = new Map<string, { members: string[]; ports: string[] }>();
  row.bars.forEach((b) => {
    for (const s of b.north) {
      if (!s.drop.members) continue;
      const entry = pairDrops.get(s.drop.dev) ?? { members: s.drop.members, ports: [] };
      entry.ports.push(devPortId(b.bar.id, s.drop.key));
      pairDrops.set(s.drop.dev, entry);
    }
  });
  for (const [id, { members, ports }] of pairDrops) {
    const shape = fixed ? row.joints?.get(id) : undefined;
    const order = shape?.members ?? members;
    const w = shape?.width ?? JOINT;
    const ins: ElkPort[] = order.map((m, k) => ({
      id: `${id}:in:${m}`,
      width: 1,
      height: 1,
      ...(shape ? { x: (order.length > 1 ? (k * w) / (order.length - 1) : w / 2) - 0.5, y: -1 } : {}),
      layoutOptions: { "elk.port.side": "NORTH" },
    }));
    const outs: ElkPort[] = ports.map((port, k) => ({
      id: port,
      width: 1,
      height: 1,
      ...(shape ? { x: ((k + 0.5) * w) / ports.length - 0.5, y: JOINT_H } : {}),
      layoutOptions: { "elk.port.side": "SOUTH" },
    }));
    children.push({ id, width: w, height: JOINT_H, ports: [...ins, ...outs], layoutOptions: { "elk.portConstraints": shape ? "FIXED_POS" : "FIXED_SIDE" } });
    for (const m of order) edges.push({ id: joinId(id, m), sources: [m], targets: [`${id}:in:${m}`] });
  }
  const barNodes: ElkNode[] = [];
  row.bars.forEach((b, i) => {
    const sideOf = (slots: Slot[], side: "n" | "s"): ElkPort[] =>
      slots.map((s, j) => {
        const port: ElkPort = {
          id: portId(b.bar.id, side, s.drop.key),
          width: 1,
          height: 1,
          layoutOptions: { "elk.port.side": side === "n" ? "NORTH" : "SOUTH" },
        };
        if (fixed) {
          port.x = s.x - 0.5;
          port.y = side === "n" ? -1 : b.height;
        } else
          port.layoutOptions!["elk.port.index"] = String(
            side === "n" ? j : slots.length - 1 - j,
          );
        return port;
      });
    barNodes.push({
      id: b.bar.id,
      width: b.width,
      height: b.height,
      ports: [...sideOf(b.north, "n"), ...sideOf(b.south, "s")],
      layoutOptions: {
        "elk.partitioning.partition": String(PART_ROW),
        "elk.portConstraints": fixed ? "FIXED_POS" : "FIXED_SIDE",
      },
    });
    for (const s of b.north) {
      const from = devPortId(b.bar.id, s.drop.key);
      // the ports of a joint are its own (above)
      if (!s.drop.members) addDevPort(s.drop.dev, from, i * 1000 + b.north.indexOf(s));
      edges.push({
        id: dropId(b.bar.id, s.drop.key),
        sources: [from],
        targets: [portId(b.bar.id, "n", s.drop.key)],
      });
    }
    for (const s of b.south) {
      edges.push({
        id: dropId(b.bar.id, s.drop.key),
        sources: [portId(b.bar.id, "s", s.drop.key)],
        targets: [s.drop.dev],
      });
    }
  });
  // A cable from a device above the row to one under it crosses the row as a
  // straight line, behind the bars.
  const side = (dev: string) => row.upper.has(dev);
  const cables = new Map(model.cables.map((c) => [c.id, c]));
  const crossing = new Set(
    edges
      .filter((e) => {
        const c = cables.get(e.id);
        return c !== undefined && side(c.from.dev) !== side(c.to.dev);
      })
      .map((e) => e.id),
  );
  const dropped = new Set(
    row.bars.flatMap((b) => b.south.map((s) => s.drop.dev)),
  );
  // the middle one of the bars a device drops to
  const barsOf = new Map<string, string[]>();
  for (const b of row.bars)
    for (const s of b.north)
      barsOf.set(s.drop.dev, [...(barsOf.get(s.drop.dev) ?? []), b.bar.id]);
  const barOf = new Map(
    [...barsOf].map(([dev, ids]) => [
      dev,
      ids[Math.floor((ids.length - 1) / 2)],
    ]),
  );
  const kept = edges.filter((e) => !crossing.has(e.id));
  for (const id of [...crossing].sort()) {
    const c = cables.get(id)!;
    const [up, down] = side(c.from.dev)
      ? [c.from.dev, c.to.dev]
      : [c.to.dev, c.from.dev];
    if (dropped.has(down) || !row.bars.length) continue;
    kept.push({
      id: `${GLUE}${id}`,
      sources: [
        barOf.get(up) ?? row.bars[Math.floor((row.bars.length - 1) / 2)].bar.id,
      ],
      targets: [down],
    });
  }
  edges.length = 0;
  edges.push(...kept);
  // the cables down from a device with drops leave between its drops
  const stubIds = new Set(stubs(model).map((s) => s.id));
  for (const [dev, ports] of devPorts) {
    const down = edges.filter(
      (e) =>
        e.sources[0] === dev &&
        !stubIds.has(e.targets[0]) &&
        !e.id.includes(":drop:"),
    );
    const middle = ports.length
      ? ports[Math.floor((ports.length - 1) / 2)].order + 0.5
      : 0;
    for (const e of down) {
      const id = `${dev}:cable:${e.id}`;
      ports.push({ id, order: middle });
      e.sources = [id];
    }
  }
  const stubDev = new Map(stubs(model).map((s) => [s.id, s.dev]));
  const partitionOf = (id: string): number =>
    isJoint(id) || row.upper.has(stubDev.get(id) ?? id) ? PART_UPPER : PART_LOWER;
  const nodes = children.map((c) => {
    const ports = devPorts.get(c.id);
    const options: LayoutOptions = {
      ...(c.layoutOptions ?? {}),
      "elk.partitioning.partition": String(partitionOf(c.id)),
    };
    if (!ports) return { ...c, layoutOptions: options };
    const sorted = [...ports].sort((a, b) => a.order - b.order);
    return {
      ...c,
      layoutOptions: { ...options, "elk.portConstraints": "FIXED_ORDER" },
      // ELK counts a side clockwise: the lower edge runs right to left
      ports: sorted.map((p, k) => ({
        id: p.id,
        width: 1,
        height: 1,
        layoutOptions: {
          "elk.port.side": "SOUTH",
          "elk.port.index": String(sorted.length - 1 - k),
        },
      })),
    };
  });
  return {
    ...flat,
    layoutOptions: { ...flat.layoutOptions, ...ROW_OPTIONS },
    children: [...nodes, ...barNodes],
    edges,
  };
}

/** The flat ELK graph with each device in its box with the caption, as the
 *  row has them: the room between two layers is then room for the port tags. */
export function withBoxes(flat: ElkNode, boxes: ReadonlyMap<string, Box>): ElkNode {
  return {
    ...flat,
    children: (flat.children ?? []).map((c) => {
      const box = boxes.get(c.id);
      return box ? { ...c, width: box.width, height: box.height } : c;
    }),
  };
}

/**
 * The row with each slot under its device as a pass of the layout placed it,
 * so a drop runs as straight down as the room allows and the drops of one
 * bar side keep the order of their devices. Slots keep their order and the
 * room between them. A bar under a gateway keeps its width: its slots stay
 * on it, one end each for a gateway pair. A bar with drops from under it (L2)
 * grows to reach its devices, to the left as well, so the label stays at its
 * left end.
 */
export function align(row: Row, laid: ElkNode): Row {
  const byId = new Map((laid.children ?? []).map((c) => [c.id, c]));
  return {
    ...row,
    bars: row.bars.map((b) => {
      const bar = byId.get(b.bar.id);
      if (!bar) return b;
      const centre = (dev: string) => {
        const d = byId.get(dev);
        return d ? (d.x ?? 0) + (d.width ?? 0) / 2 - (bar.x ?? 0) : b.width / 2;
      };
      const portX = (side: "n" | "s", key: string) => bar.ports?.find((q) => q.id === portId(b.bar.id, side, key))?.x ?? 0;
      const wants = (slots: Slot[], side: "n" | "s") =>
        slots
          .map((slot) => ({ slot, c: centre(slot.drop.dev), p: portX(side, slot.drop.key) }))
          .sort((x, y) => x.c - y.c || x.p - y.p || (x.slot.drop.key < y.slot.drop.key ? -1 : 1));
      const north = wants(b.north, "n");
      const south = wants(b.south, "s");
      const grows = south.length > 0 || row.bars.length === 1;
      const labelEnd = BAR_PAD + b.labelWidth + 2 * SLOT_GAP;
      // a slot that wants the place of the label moves everything right: the bar grows to the left
      const shift = south.length ? Math.max(0, labelEnd - (south[0].c - south[0].slot.tag.width / 2)) : 0;
      /** the slots from `lo` on, each at its place or pushed right of the one before it */
      const place = (list: { slot: Slot; c: number }[], lo: number, hi: number): Slot[] => {
        let edge = lo;
        const out = list.map(({ slot, c }) => {
          const x = Math.max(Math.min(c + shift, hi - slot.tag.width / 2), edge + slot.tag.width / 2);
          edge = x + slot.tag.width / 2 + SLOT_GAP;
          return { ...slot, x };
        });
        // a side pushed past its end moves back left as far as its start allows
        const over = out.length ? out[out.length - 1].x + out[out.length - 1].tag.width / 2 - hi : 0;
        if (over > 0 && Number.isFinite(hi)) {
          const room = out.length ? out[0].x - out[0].tag.width / 2 - lo : 0;
          const back = Math.min(over, Math.max(0, room));
          for (const slot of out) slot.x -= back;
        }
        return out;
      };
      const s = place(south, labelEnd, Infinity);
      const southEnd = s.length ? s[s.length - 1].x + s[s.length - 1].tag.width / 2 + BAR_PAD : 0;
      const hi = grows ? Infinity : b.width - BAR_PAD;
      const n = place(north, BAR_PAD, hi);
      const northEnd = n.length ? n[n.length - 1].x + n[n.length - 1].tag.width / 2 + BAR_PAD : 0;
      const width = Math.ceil(Math.max(grows ? 0 : b.width, BAR_MIN, 2 * BAR_PAD + b.labelWidth, southEnd, northEnd));
      return { ...b, width, north: n, south: s };
    }),
    joints: jointsOf(row, byId),
  };
}

/** The joints of the first-hop pairs, from where a pass placed their routers. */
function jointsOf(row: Row, byId: Map<string, ElkNode>): Map<string, { width: number; members: string[] }> {
  const out = new Map<string, { width: number; members: string[] }>();
  for (const b of row.bars) {
    for (const s of b.north) {
      if (!s.drop.members || out.has(s.drop.dev)) continue;
      const cx = (m: string) => {
        const n = byId.get(m);
        return n ? (n.x ?? 0) + (n.width ?? 0) / 2 : 0;
      };
      const members = [...s.drop.members].sort((a, c) => cx(a) - cx(c) || (a < c ? -1 : 1));
      const width = Math.max(JOINT, Math.round(cx(members[members.length - 1]) - cx(members[0])));
      out.set(s.drop.dev, { width, members });
    }
  }
  return out;
}

/** Lays out the flat graph with the row: a first pass with the slots free,
 *  then two with each slot under its device as the pass before placed it. */
export async function layoutRow(
  layout: (graph: ElkNode) => Promise<ElkNode>,
  flat: ElkNode,
  model: TopologyModel,
  row: Row,
): Promise<{ laid: ElkNode; row: Row }> {
  let final = align(row, await layout(rowGraph(flat, model, row, false)));
  let laid = await layout(rowGraph(flat, model, final, true));
  final = align(final, laid);
  laid = await layout(rowGraph(flat, model, final, true));
  return { laid, row: final };
}

// --- the row as Cytoscape elements

interface Abs extends Point {
  width: number;
  height: number;
}

function absolute(laid: ElkNode): Map<string, Abs> {
  const out = new Map<string, Abs>();
  for (const c of laid.children ?? [])
    out.set(c.id, {
      x: c.x ?? 0,
      y: c.y ?? 0,
      width: c.width ?? 0,
      height: c.height ?? 0,
    });
  return out;
}

const round = (v: number) => Math.round(v * 100) / 100;
/** A weight of a segment point: a long line needs more places than a pixel does. */
const fine = (v: number) => Math.round(v * 1e5) / 1e5;

/** The centre of a device's symbol in a laid-out flat graph: the top of its box holds the symbol. */
export function symbolCentre(p: Abs): Point {
  return { x: p.x + p.width / 2, y: p.y + DEVICE_HEIGHT / 2 };
}

/** The elements of the row: per bar its line with the label (`segbar`), a tag
 *  per slot (`segtag`), the point on the line each drop ends at (`segtap`),
 *  and the drop line from the device along its ELK route (`segdrop`). */
export function rowElements(row: Row, laid: ElkNode): CyElement[] {
  const pos = absolute(laid);
  const routes = new Map<string, Point[]>();
  for (const e of laid.edges ?? []) {
    const s = e.sections?.[0];
    if (s)
      routes.set(e.id, [s.startPoint, ...(s.bendPoints ?? []), s.endPoint]);
  }
  const out: CyElement[] = [];
  /** the start of a drop: the centre of the symbol of a device, or a joint */
  const centreOf = (id: string, p: Abs): Point => (isJoint(id) ? { x: p.x + p.width / 2, y: p.y + p.height / 2 } : symbolCentre(p));
  // each first-hop pair: its joint, and a line from each router to it along its ELK route
  const joints = new Map<string, string[]>();
  for (const b of row.bars) for (const s of b.north) if (s.drop.members) joints.set(s.drop.dev, s.drop.members);
  for (const [id, members] of joints) {
    const at = pos.get(id);
    if (!at) continue;
    const centre = centreOf(id, at);
    out.push({ group: "nodes", data: { id, kind: "segjoint", members, width: at.width }, position: centre, classes: "segjoint" });
    for (const m of members) {
      const dev = pos.get(m);
      const route = routes.get(joinId(id, m));
      const data: Record<string, unknown> = { id: joinId(id, m), source: m, target: id };
      let classes = "segdrop gateway join";
      if (dev && route) {
        const start = route[0];
        const end = route[route.length - 1];
        const from = symbolCentre(dev);
        data.sourceEndpoint = `${round(start.x - from.x)}px ${round(start.y - from.y)}px`;
        data.targetEndpoint = `${round(end.x - centre.x)}px ${round(end.y - centre.y)}px`;
        const bends = route.slice(1, -1);
        if (bends.length) {
          const { weights, distances } = segmentsFor(start, end, bends);
          data.segmentWeights = weights.map(fine).join(" ");
          data.segmentDistances = distances.map(fine).join(" ");
          classes += " routed";
        }
      }
      out.push({ group: "edges", data, classes });
    }
  }
  for (const b of row.bars) {
    const at = pos.get(b.bar.id);
    if (!at) continue;
    const lineY = at.y + b.lineY;
    out.push({
      group: "nodes",
      data: {
        id: b.bar.id,
        kind: "segbar",
        label: [b.bar.title, ...b.bar.prefixes].join("\n"),
        width: b.width,
        labelDx: round(b.labelX + b.labelWidth / 2 - b.width / 2),
        bd: b.bar.bd,
        site: b.bar.site,
        cidr: null,
      },
      position: { x: at.x + b.width / 2, y: lineY },
      classes: "segbar",
    });
    const slots: [Slot, "n" | "s"][] = [
      ...b.north.map((s) => [s, "n"] as [Slot, "n"]),
      ...b.south.map((s) => [s, "s"] as [Slot, "s"]),
    ];
    for (const [s, side] of slots) {
      const x = at.x + s.x;
      const tagY =
        side === "n"
          ? lineY - TAG_GAP - s.tag.height / 2 + 1
          : lineY + TAG_GAP + s.tag.height / 2 - 1;
      const tap = `${b.bar.id}:tap:${s.drop.key}`;
      out.push({
        group: "nodes",
        data: {
          id: `${b.bar.id}:tag:${s.drop.key}`,
          kind: "segtag",
          bar: b.bar.id,
          label: s.tag.lines.join("\n"),
          width: s.tag.width,
          height: s.tag.height,
        },
        position: { x, y: tagY },
        classes: s.drop.gateway ? "segtag gateway" : "segtag",
      });
      out.push({
        group: "nodes",
        data: { id: tap, kind: "segtap", bar: b.bar.id },
        position: { x, y: lineY },
        classes: "segtap",
      });
      const dev = pos.get(s.drop.dev);
      const route = routes.get(dropId(b.bar.id, s.drop.key));
      const data: Record<string, unknown> = {
        id: dropId(b.bar.id, s.drop.key),
        source: s.drop.dev,
        target: tap,
        bar: b.bar.id,
      };
      let classes = s.drop.gateway ? "segdrop gateway" : "segdrop";
      if (dev && route) {
        // the route runs from the device's port to the bar's port (north) or back (south)
        const points = side === "n" ? route : [...route].reverse();
        const centre = centreOf(s.drop.dev, dev);
        const start = points[0];
        const end = { x, y: lineY };
        const bends = points.slice(1, -1);
        data.sourceEndpoint = `${round(start.x - centre.x)}px ${round(start.y - centre.y)}px`;
        if (bends.length) {
          const { weights, distances } = segmentsFor(start, end, bends);
          data.segmentWeights = weights.map(fine).join(" ");
          data.segmentDistances = distances.map(fine).join(" ");
          classes += " routed";
        }
      }
      out.push({ group: "edges", data, classes });
    }
  }
  return out;
}

/** The room a cable keeps from the bars when it passes the row, and between two cables in one gap. */
const GAP_MARGIN = 8;
const LANE = 6;

/**
 * The cables that cross the row, from a device above it to one under it,
 * marked `behind`. With the laid-out
 * graph, a cable crosses the row where no bar has its label, its prefixes or
 * a tag (`via`): straight when its line already does, else bent at the top
 * and the bottom of the row at the free place nearest its line, a lane each.
 */
export function behindRow(elements: CyElement[], row: Row): CyElement[] {
  const crossing = (e: CyElement) =>
    e.group === "edges" && /\bcable\b/.test(e.classes ?? "") && row.upper.has(e.data.source as string) !== row.upper.has(e.data.target as string);
  // the classes again from clean: a drag draws the way of a cable anew
  const plain = (e: CyElement) => (e.classes ?? "").replace(/\b(behind|via)\b/g, "").replace(/\s+/g, " ").trim();
  const mark = (e: CyElement) => ({ ...e, classes: `${plain(e)} behind` });
  // the box of each bar where its line is drawn now
  const byId = new Map<string, { x: number; y: number }>();
  for (const e of elements) {
    const b = e.data.kind === "segbar" && e.position ? row.bars.find((x) => x.bar.id === e.data.id) : undefined;
    if (b) byId.set(b.bar.id, { x: e.position!.x - b.width / 2, y: e.position!.y - b.lineY });
  }
  const placed = row.bars.filter((b) => byId.has(b.bar.id));
  if (!placed.length) return elements.map((e) => (crossing(e) ? mark(e) : e));
  const top = Math.min(...placed.map((b) => byId.get(b.bar.id)!.y)) - GAP_MARGIN;
  const bottom = Math.max(...placed.map((b) => byId.get(b.bar.id)!.y + b.height)) + GAP_MARGIN;
  // what a cable must not cross: the label block and the tags of each bar; the line itself it may
  const blocked = placed
    .flatMap((b) => {
      const x = byId.get(b.bar.id)!.x;
      return [
        [x + b.labelX, x + b.labelX + b.labelWidth] as const,
        ...[...b.north, ...b.south].map((t) => [x + t.x - t.tag.width / 2, x + t.x + t.tag.width / 2] as const),
      ];
    })
    .map(([x0, x1]) => [x0 - GAP_MARGIN, x1 + GAP_MARGIN] as [number, number])
    .sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const span of blocked) {
    const last = merged[merged.length - 1];
    if (last && span[0] <= last[1]) last[1] = Math.max(last[1], span[1]);
    else merged.push([...span]);
  }
  const gaps: [number, number][] = [[-Infinity, merged[0][0]]];
  for (let k = 1; k < merged.length; k++) gaps.push([merged[k - 1][1], merged[k][0]]);
  gaps.push([merged[merged.length - 1][1], Infinity]);
  const at = new Map(elements.filter((e) => e.group === "nodes" && e.position).map((e) => [String(e.data.id), e.position!]));
  const xAt = (a: Point, b: Point, y: number) => (b.y === a.y ? a.x : a.x + ((y - a.y) * (b.x - a.x)) / (b.y - a.y));
  const free = (x: number) => gaps.findIndex(([g0, g1]) => x > g0 && x < g1);
  // each bent cable takes the free stretch nearest the place its line meets the row, and the place in it nearest that
  const lanes = new Map<number, { id: string; want: number; a: Point; b: Point }[]>();
  for (const e of [...elements].filter(crossing).sort((p, q) => (String(p.data.id) < String(q.data.id) ? -1 : 1))) {
    const a = at.get(String(e.data.source));
    const b = at.get(String(e.data.target));
    if (!a || !b) continue;
    const g = free(xAt(a, b, top));
    if (g >= 0 && g === free(xAt(a, b, bottom))) continue;
    const mid = xAt(a, b, (top + bottom) / 2);
    const distance = ([g0, g1]: [number, number]) => (mid < g0 ? g0 - mid : mid > g1 ? mid - g1 : 0);
    const best = gaps.map((gap, k) => ({ k, d: distance(gap) })).sort((p, q) => p.d - q.d || p.k - q.k)[0].k;
    lanes.set(best, [...(lanes.get(best) ?? []), { id: String(e.data.id), want: mid, a, b }]);
  }
  const routes = new Map<string, { x: number; a: Point; b: Point }>();
  for (const [k, list] of lanes) {
    const [g0, g1] = gaps[k];
    const lo = g0 + LANE;
    const hi = g1 - LANE;
    list.sort((p, q) => p.want - q.want || (p.id < q.id ? -1 : 1));
    let edge = -Infinity;
    const xs = list.map((c) => {
      const x = Math.max(Math.min(Math.max(c.want, lo), hi), edge + LANE);
      edge = x;
      return x;
    });
    // pushed past the end of the stretch: back left as far as its start allows
    const over = xs.length ? xs[xs.length - 1] - hi : 0;
    if (over > 0 && Number.isFinite(over)) {
      const back = Math.min(over, Math.max(0, xs[0] - lo));
      for (let n = 0; n < xs.length; n++) xs[n] -= back;
    }
    list.forEach((c, n) => routes.set(c.id, { x: xs[n], a: c.a, b: c.b }));
  }
  return elements.map((e) => {
    if (!crossing(e)) return e;
    const r = routes.get(String(e.data.id));
    if (!r) return mark(e);
    // the bends from the source's end of the line
    const [p, q] = row.upper.has(String(e.data.source)) ? [top, bottom] : [bottom, top];
    const { weights, distances } = segmentsFor(r.a, r.b, [
      { x: r.x, y: p },
      { x: r.x, y: q },
    ]);
    return {
      ...e,
      data: { ...e.data, viaWeights: weights.map(fine).join(" "), viaDistances: distances.map(fine).join(" ") },
      classes: `${plain(e)} behind via`,
    };
  });
}

// --- a moved device or bar

/** The room between the turns of two drops from one device. */
const TURN_STEP = 10;

/**
 * Right-angle routes for drops whose device or bar moved: down from the
 * device's port, across, and down to the bar (or up, for a device under it).
 * The drops of one device turn at heights of their own, the outer ones first,
 * so no two run along one line.
 */
export function dropRoutes(
  drops: { id: string; dev: string; start: Point; end: Point }[],
): Map<string, Point[]> {
  const out = new Map<string, Point[]>();
  const bySource = new Map<
    string,
    { id: string; start: Point; end: Point }[]
  >();
  for (const d of drops) {
    const key = `${d.dev}|${Math.sign(d.end.y - d.start.y)}`;
    bySource.set(key, [...(bySource.get(key) ?? []), d]);
  }
  for (const list of bySource.values()) {
    const left = list
      .filter((d) => d.end.x < d.start.x)
      .sort((a, b) => a.start.x - b.start.x);
    const right = list
      .filter((d) => d.end.x > d.start.x)
      .sort((a, b) => b.start.x - a.start.x);
    for (const d of list.filter((x) => x.end.x === x.start.x))
      out.set(d.id, []);
    for (const side of [left, right]) {
      side.forEach((d, rank) => {
        const dir = Math.sign(d.end.y - d.start.y) || 1;
        const span = Math.abs(d.end.y - d.start.y);
        const turn =
          d.start.y + dir * Math.min(span - 4, TURN_STEP * (rank + 1));
        out.set(d.id, [
          { x: d.start.x, y: turn },
          { x: d.end.x, y: turn },
        ]);
      });
    }
  }
  return out;
}

/** The offset `"12px 30px"` of a drop's start from its device's centre. */
export function endpointOffset(value: unknown): Point {
  const [x, y] = String(value ?? "0px 0px")
    .split(" ")
    .map((v) => parseFloat(v) || 0);
  return { x: x ?? 0, y: y ?? 0 };
}

/** The data and classes that draw a drop along `bends`. */
export function dropPath(
  start: Point,
  end: Point,
  bends: Point[],
  classes: string,
): { data: Record<string, unknown>; classes: string } {
  const plain = classes
    .replace(/\brouted\b/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!bends.length)
    return {
      data: { segmentWeights: "", segmentDistances: "" },
      classes: plain,
    };
  const { weights, distances } = segmentsFor(start, end, bends);
  return {
    data: {
      segmentWeights: weights.map(fine).join(" "),
      segmentDistances: distances.map(fine).join(" "),
    },
    classes: `${plain} routed`,
  };
}

/** The elements with right-angle routes for the drops whose device or bar moved (layout.ts `withPositions`). */
export function routeMovedDrops(elements: CyElement[]): CyElement[] {
  const at = new Map(
    elements
      .filter((e) => e.group === "nodes" && e.position)
      .map((e) => [String(e.data.id), e.position!]),
  );
  const moved = elements.filter(
    (e) =>
      e.group === "edges" &&
      /\bsegdrop\b/.test(e.classes ?? "") &&
      /\bmoved\b/.test(e.classes ?? ""),
  );
  if (!moved.length) return elements;
  const drops = moved.flatMap((e) => {
    const dev = at.get(String(e.data.source));
    const end = at.get(String(e.data.target));
    if (!dev || !end) return [];
    const off = endpointOffset(e.data.sourceEndpoint);
    return [
      {
        id: String(e.data.id),
        dev: String(e.data.source),
        start: { x: dev.x + off.x, y: dev.y + off.y },
        end,
      },
    ];
  });
  const routes = dropRoutes(drops);
  const byId = new Map(drops.map((d) => [d.id, d]));
  return elements.map((e) => {
    const d = byId.get(String(e.data.id));
    if (!d || e.group !== "edges") return e;
    const path = dropPath(
      d.start,
      d.end,
      routes.get(d.id) ?? [],
      e.classes ?? "",
    );
    return { ...e, data: { ...e.data, ...path.data }, classes: path.classes };
  });
}
