/**
 * The look of a site diagram, without a DOM: a symbol for each device, the
 * hostname and the management address under it, and a color for each cable by
 * its link speed.
 *
 * The symbols are blue and have a lit top face. A router is a cylinder, a
 * switch is a flat box and a layer-3 switch is a cube. The
 * role and the tier choose the symbol by the rule of the HST map: a switch or
 * a router in a routing tier is a layer-3 switch.
 */

import type { TopologyModel } from "../api/types";
import type { CyElement } from "./layout";

export type SymbolName =
  | "router"
  | "l3switch"
  | "switch"
  | "firewall"
  | "ap"
  | "controller"
  | "loadbalancer"
  | "sdwan"
  | "server"
  | "cloud"
  | "unknown";

/** The device groups the legend shows and hides. */
export type Category = "l3" | "l2" | "host" | "other";

export const CATEGORIES: ReadonlyArray<{ key: Category; label: string }> = [
  { key: "l3", label: "Layer 3" },
  { key: "l2", label: "Layer 2" },
  { key: "host", label: "Servers" },
  { key: "other", label: "Other devices" },
];

const CATEGORY: Readonly<Record<SymbolName, Category>> = {
  router: "l3",
  l3switch: "l3",
  firewall: "l3",
  loadbalancer: "l3",
  sdwan: "l3",
  switch: "l2",
  ap: "l2",
  controller: "l2",
  server: "host",
  cloud: "other",
  unknown: "other",
};

const ROLE_SYMBOL: Readonly<Record<string, SymbolName>> = {
  router: "router",
  gateway: "router",
  switch: "switch",
  leaf: "l3switch",
  spine: "l3switch",
  firewall: "firewall",
  ap: "ap",
  "access point": "ap",
  controller: "controller",
  management: "server",
  "sdwan-hub": "sdwan",
  "sdwan-edge": "sdwan",
  "load-balancer": "loadbalancer",
  server: "server",
  cloud: "cloud",
};

/** The tiers whose switches route. */
const ROUTING_TIERS: ReadonlySet<string> = new Set(["core", "distribution", "spine"]);

/** A tier states the function when the role is generic: the server gives a device with no role "unknown". */
const TIER_SYMBOL: Readonly<Record<string, SymbolName>> = {
  core: "l3switch",
  distribution: "l3switch",
  access: "switch",
  "internet-edge": "router",
  "wan-edge": "router",
  "sdwan-hub": "sdwan",
  "sdwan-edge": "sdwan",
  wireless: "controller",
  "access-point": "ap",
  firewall: "firewall",
  leaf: "l3switch",
  spine: "l3switch",
};

/** The symbol of a device role and tier. */
export function symbolOf(role: string | null | undefined, tier: string | null | undefined): SymbolName {
  const named = role && Object.hasOwn(ROLE_SYMBOL, role) ? ROLE_SYMBOL[role] : undefined;
  if (named === "switch" || named === "router") return tier && ROUTING_TIERS.has(tier) ? "l3switch" : named;
  return named ?? (tier && Object.hasOwn(TIER_SYMBOL, tier) ? TIER_SYMBOL[tier] : undefined) ?? "unknown";
}

export function categoryOf(symbol: SymbolName): Category {
  return CATEGORY[symbol];
}

const BODY = "#2f86c8";
const TOP = "#78b9e8";
const SIDE = "#1f6299";
const EDGE = "#174b75";
const GREY = "#c9ced5";
const GREY_TOP = "#e3e7ec";
const GREY_SIDE = "#9fa6af";
const GREY_EDGE = "#6d7580";
const SKY = "#8cc8ee";
const SKY_EDGE = "#4b8fbf";

const W = 'stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" fill="none"';

/** An arrow from (x1, y1) to (x2, y2) with its head at the second point. */
function arrow(x1: number, y1: number, x2: number, y2: number, head = 4): string {
  const a = Math.atan2(y2 - y1, x2 - x1);
  const f = (n: number) => n.toFixed(1);
  const l = [x2 - head * Math.cos(a - 0.55), y2 - head * Math.sin(a - 0.55)];
  const r = [x2 - head * Math.cos(a + 0.55), y2 - head * Math.sin(a + 0.55)];
  return `<path ${W} d="M${x1} ${y1}L${x2} ${y2}M${f(l[0])} ${f(l[1])}L${x2} ${y2}L${f(r[0])} ${f(r[1])}"/>`;
}

const stroke = (c: string) => `stroke="${c}" stroke-width="1" stroke-linejoin="round"`;

/** A box seen from above and the right: front face, top face and side face. */
function box(x: number, y: number, w: number, h: number, d: number, body: string, top: string, side: string, edge: string): string {
  return (
    `<path fill="${top}" ${stroke(edge)} d="M${x} ${y}L${x + d} ${y - d * 0.6}H${x + w + d}L${x + w} ${y}Z"/>` +
    `<path fill="${side}" ${stroke(edge)} d="M${x + w} ${y}L${x + w + d} ${y - d * 0.6}V${y + h - d * 0.6}L${x + w} ${y + h}Z"/>` +
    `<rect fill="${body}" ${stroke(edge)} x="${x}" y="${y}" width="${w}" height="${h}"/>`
  );
}

/** The inner markup of each symbol, in a 64 by 48 view box. */
function drawings(): Readonly<Record<SymbolName, string>> {
  const cylinder = (top: number, height: number) =>
    `<path fill="${BODY}" ${stroke(EDGE)} d="M6 ${top}V${top + height}A26 9 0 0 0 58 ${top + height}V${top}Z"/>` +
    `<ellipse fill="${TOP}" ${stroke(EDGE)} cx="32" cy="${top}" rx="26" ry="9"/>`;
  return {
    router:
      cylinder(17, 16) +
      arrow(35, 15, 46, 11) +
      arrow(29, 19, 18, 23) +
      arrow(15, 12, 26, 15) +
      arrow(49, 22, 38, 19),
    loadbalancer: cylinder(17, 16) + arrow(16, 17, 28, 17) + arrow(32, 17, 46, 12) + arrow(32, 17, 48, 17) + arrow(32, 17, 46, 22),
    switch: box(4, 26, 42, 13, 16, BODY, TOP, SIDE, EDGE) + arrow(20, 19, 48, 19) + arrow(48, 23, 16, 23),
    l3switch:
      box(10, 14, 32, 30, 12, BODY, TOP, SIDE, EDGE) +
      arrow(26, 29, 26, 19) +
      arrow(26, 29, 26, 39) +
      arrow(26, 29, 15, 29) +
      arrow(26, 29, 37, 29),
    firewall:
      box(8, 12, 38, 30, 10, BODY, TOP, SIDE, EDGE) +
      `<path stroke="${EDGE}" stroke-width="1.2" fill="none" d="M8 22H46M8 32H46M20 12V22M34 12V22M14 22V32M27 22V32M40 22V32M20 32V42M34 32V42"/>`,
    ap:
      `<ellipse fill="${SIDE}" ${stroke(EDGE)} cx="32" cy="38" rx="20" ry="6"/>` +
      `<ellipse fill="${TOP}" ${stroke(EDGE)} cx="32" cy="35" rx="20" ry="6"/>` +
      `<path stroke="${BODY}" stroke-width="2.6" stroke-linecap="round" fill="none" d="M32 33V17M24 15A11 11 0 0 1 40 15M18 10A19 19 0 0 1 46 10"/>`,
    controller:
      box(4, 26, 42, 13, 16, BODY, TOP, SIDE, EDGE) +
      `<path ${W} d="M19 35A8 8 0 0 1 31 35M14 31A15 15 0 0 1 36 31"/><circle fill="#fff" cx="25" cy="37" r="1.6"/>`,
    sdwan:
      `<path fill="${BODY}" ${stroke(EDGE)} d="M16 38H48A9 9 0 0 0 48 20A13 13 0 0 0 23 17A10 10 0 0 0 16 38Z"/>` +
      arrow(20, 30, 44, 30) +
      arrow(44, 25, 26, 25),
    server:
      box(20, 8, 20, 36, 8, GREY, GREY_TOP, GREY_SIDE, GREY_EDGE) +
      `<path stroke="${GREY_EDGE}" stroke-width="1.4" fill="none" d="M23 15H37M23 20H37M23 25H37"/><circle fill="#4caf50" cx="25" cy="38" r="1.6"/>`,
    cloud: `<path fill="${SKY}" stroke="${SKY_EDGE}" stroke-width="1" d="M14 38H50A10 10 0 0 0 50 18A14 14 0 0 0 23 15A11 11 0 0 0 14 38Z"/>`,
    unknown:
      box(10, 16, 34, 24, 10, GREY, GREY_TOP, GREY_SIDE, GREY_EDGE) +
      `<path stroke="${GREY_EDGE}" stroke-width="1.6" stroke-dasharray="3 3" fill="none" d="M16 28H38"/>`,
  };
}

const DRAWINGS = drawings();

/** A complete SVG document of a symbol. */
export function svgOf(name: SymbolName): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="48" viewBox="0 0 64 48">${DRAWINGS[name]}</svg>`;
}

/** The symbol as an image source for the canvas and for the legend. */
export function iconUri(name: SymbolName): string {
  return `data:image/svg+xml;utf8,${encodeURIComponent(svgOf(name))}`;
}

export type SpeedKey = "s1" | "s2" | "s3" | "s4" | "s5" | "s6" | "unknown";

interface SpeedBin {
  key: SpeedKey;
  label: string;
  /** the highest speed in the bin, in Mbit/s */
  max: number;
  light: string;
  dark: string;
}

/** The link speed bins, slowest first. A gigabit link is in the 100 to 1000 Mbps bin. */
export const SPEED_BINS: ReadonlyArray<SpeedBin> = [
  { key: "s1", label: "Up to 1.5 Mbps", max: 1.5, light: "#8a5a2b", dark: "#c99263" },
  { key: "s2", label: "1.5 to 10 Mbps", max: 10, light: "#3d9a4b", dark: "#71cc7e" },
  { key: "s3", label: "10 to 100 Mbps", max: 100, light: "#2591cc", dark: "#62c2f0" },
  { key: "s4", label: "100 to 1000 Mbps", max: 1000, light: "#cc33ad", dark: "#ef6ed8" },
  { key: "s5", label: "1 to 10 Gbps", max: 10_000, light: "#5c33a8", dark: "#a98ced" },
  { key: "s6", label: "Above 10 Gbps", max: Infinity, light: "#dd7d12", dark: "#f5aa4d" },
];

export const UNKNOWN_SPEED_LABEL = "Unknown";

/** The bin of a link speed; no speed is unknown. */
export function speedKey(mbps: number | null | undefined): SpeedKey {
  if (mbps == null || !(mbps > 0)) return "unknown";
  return SPEED_BINS.find((b) => mbps <= b.max)!.key;
}

/** A link speed as text: 100 Mbps, 1 Gbps, 2.5 Gbps. */
export function speedText(mbps: number | null | undefined): string {
  if (mbps == null || !(mbps > 0)) return "";
  if (mbps >= 1000) return `${Number((mbps / 1000).toFixed(1))} Gbps`;
  return `${Number(mbps.toFixed(1))} Mbps`;
}

/** The color of a bin in a light or a dark theme; unknown takes `unknown`. */
export function speedColor(key: SpeedKey, dark: boolean, unknown: string): string {
  const bin = SPEED_BINS.find((b) => b.key === key);
  return bin ? (dark ? bin.dark : bin.light) : unknown;
}

/** The caption under a device: the hostname, and the management address on a second line. */
export function caption(label: string, address: string | null | undefined): string {
  return address ? `${label}\n${address}` : label;
}

/** The address of each interface on a connected prefix, with the prefix length, keyed `dev|iface`. A
 *  first-hop virtual address is not the address of the interface. */
export function interfaceAddresses(model: TopologyModel): Map<string, string> {
  const out = new Map<string, string>();
  for (const s of model.subnets ?? []) {
    const length = s.cidr.split("/")[1];
    for (const m of s.members) {
      const key = `${m.dev}|${m.iface}`;
      if (m.fhrp || out.has(key)) continue;
      out.set(key, length ? `${m.ip}/${length}` : m.ip);
    }
  }
  return out;
}

/** The tag fields of a cable before tags.ts places its tags: none drawn. */
const UNPLACED = { sourceLabel: "", targetLabel: "", sourceOffset: 48, targetOffset: 48, sourceMarginX: 0, sourceMarginY: 0, targetMarginX: 0, targetMarginY: 0 };

/** A port tag: the port name, and the interface address when the port has one. */
export function portTag(label: string, address: string | undefined): string {
  return [label, address].filter(Boolean).join(" ");
}

/**
 * The laid-out elements with the look: each device takes its symbol in both
 * hues, its category and its caption, and each cable its speed bin, its speed
 * as text, and the port tags with the interface addresses. A cable to a stub
 * has no speed. The input is not changed.
 */
export function decorate(elements: CyElement[], model: TopologyModel): CyElement[] {
  const nodes = new Map(model.nodes.map((n) => [n.id, n]));
  const cables = new Map(model.cables.map((c) => [c.id, c]));
  const addresses = interfaceAddresses(model);
  const addressOf = (dev: unknown, port: string | null | undefined) =>
    port ? addresses.get(`${String(dev)}|${port}`) : undefined;
  return elements.map((e) => {
    if (e.group === "nodes") {
      if (e.data.kind !== "device") return e;
      const n = nodes.get(e.data.id as string);
      const symbol = symbolOf(n?.role, n?.tier);
      return {
        ...e,
        data: {
          ...e.data,
          symbol,
          icon: iconUri(symbol),
          caption: caption(String(e.data.label), n?.mgmt_ip),
        },
        classes: `${e.classes ?? ""} sym-${symbol} cat-${categoryOf(symbol)}`.trim(),
      };
    }
    if (!String(e.classes ?? "").split(" ").includes("cable")) return e;
    const cable = cables.get(e.data.id as string);
    const mbps = cable?.speed_mbps;
    // a stub cable has one port of its own: the near end's, as drawn
    const sourcePort = cable ? cable.from.port : String(e.data.sourcePort ?? "");
    return {
      ...e,
      data: {
        ...e.data,
        speedText: speedText(mbps),
        sourceTag: portTag(String(e.data.sourcePort ?? ""), addressOf(e.data.source, sourcePort)),
        targetTag: portTag(String(e.data.targetPort ?? ""), cable ? addressOf(e.data.target, cable.to.port) : undefined),
        // the tags as drawn, until the page places them (tags.ts)
        ...UNPLACED,
      },
      classes: `${e.classes} spd-${speedKey(mbps)}`,
    };
  });
}

/** The scale and the offset that fit a model box into an overview of `width` by `height`, centred. */
export function fitTransform(
  box: { x1: number; y1: number; w: number; h: number },
  width: number,
  height: number,
  pad = 6,
): { scale: number; ox: number; oy: number } {
  const w = Math.max(box.w, 1);
  const h = Math.max(box.h, 1);
  const scale = Math.min((width - 2 * pad) / w, (height - 2 * pad) / h);
  return { scale, ox: (width - w * scale) / 2 - box.x1 * scale, oy: (height - h * scale) / 2 - box.y1 * scale };
}
