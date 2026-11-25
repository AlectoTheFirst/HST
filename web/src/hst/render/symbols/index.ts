/**
 * Each device symbol is the inner markup of a 64 by 64 SVG in one stroke color.
 */

export type SymbolName =
  | "router"
  | "l3switch"
  | "switch"
  | "firewall"
  | "ap"
  | "controller"
  | "loadbalancer"
  | "server"
  | "cloud"
  | "sdwan"
  | "unknown";

const S = 'fill="none" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"';

/** An arrow from (x1, y1) to (x2, y2) with its head at the second point. */
function arrow(x1: number, y1: number, x2: number, y2: number): string {
  const a = Math.atan2(y2 - y1, x2 - x1);
  const h = 6;
  const l = [x2 - h * Math.cos(a - 0.5), y2 - h * Math.sin(a - 0.5)];
  const r = [x2 - h * Math.cos(a + 0.5), y2 - h * Math.sin(a + 0.5)];
  const f = (n: number) => n.toFixed(1);
  return `<path ${S} d="M${x1} ${y1}L${x2} ${y2}M${f(l[0])} ${f(l[1])}L${x2} ${y2}L${f(r[0])} ${f(r[1])}"/>`;
}

const ROUTER_ARROWS =
  arrow(24, 24, 14, 14) + arrow(40, 40, 50, 50) + arrow(14, 50, 24, 40) + arrow(50, 14, 40, 24);

export const SYMBOLS: Readonly<Record<SymbolName, string>> = {
  router: `<circle ${S} cx="32" cy="32" r="27"/>${ROUTER_ARROWS}`,
  l3switch: `<rect ${S} x="6" y="6" width="52" height="52" rx="4"/>${ROUTER_ARROWS}`,
  switch:
    `<rect ${S} x="6" y="6" width="52" height="52" rx="4"/>` +
    arrow(14, 20, 48, 20) +
    arrow(50, 28, 16, 28) +
    arrow(14, 36, 48, 36) +
    arrow(50, 44, 16, 44),
  firewall:
    `<rect ${S} x="6" y="10" width="52" height="44" rx="3"/>` +
    `<path ${S} d="M6 24.7H58M6 39.3H58M24 10V24.7M42 10V24.7M15 24.7V39.3M33 24.7V39.3M51 24.7V39.3M24 39.3V54M42 39.3V54"/>`,
  ap:
    `<circle ${S} cx="32" cy="40" r="5"/>` +
    `<path ${S} d="M20 30A17 17 0 0 1 44 30M13 23A27 27 0 0 1 51 23M32 45V56"/>`,
  controller:
    `<rect ${S} x="6" y="6" width="52" height="52" rx="4"/>` +
    `<circle ${S} cx="32" cy="42" r="3.5"/>` +
    `<path ${S} d="M23 33A13 13 0 0 1 41 33M16 26A23 23 0 0 1 48 26"/>`,
  loadbalancer:
    `<circle ${S} cx="32" cy="32" r="27"/>` +
    arrow(14, 32, 30, 32) +
    arrow(32, 32, 48, 20) +
    arrow(32, 32, 50, 32) +
    arrow(32, 32, 48, 44),
  server:
    `<rect ${S} x="14" y="6" width="36" height="52" rx="3"/>` +
    `<path ${S} d="M14 20H50M14 34H50M14 48H50M21 13H31M21 27H31M21 41H31"/>`,
  cloud: `<path ${S} d="M18 48H46A11 11 0 0 0 46 26A15 15 0 0 0 18 24A12 12 0 0 0 18 48Z"/>`,
  sdwan:
    `<path ${S} d="M18 44H46A10 10 0 0 0 46 24A14 14 0 0 0 18 22A11 11 0 0 0 18 44Z"/>` +
    arrow(20, 54, 44, 54),
  unknown: `<circle ${S} cx="32" cy="32" r="22" stroke-dasharray="7 6"/><circle cx="32" cy="32" r="4" fill="#fff"/>`,
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
  unknown: "unknown",
};

/** A switch or a router in one of these tiers draws as a layer-3 switch. */
const ROUTING_TIERS: ReadonlySet<string> = new Set(["core", "distribution", "spine"]);

/** The symbol of a device role and tier; a role without a symbol of its own draws as unknown. */
export function symbolOf(role: unknown, tier?: unknown): SymbolName {
  const name = typeof role === "string" && Object.hasOwn(ROLE_SYMBOL, role) ? ROLE_SYMBOL[role] : "unknown";
  return (name === "switch" || name === "router") && typeof tier === "string" && ROUTING_TIERS.has(tier) ? "l3switch" : name;
}

/** The roles with a symbol of their own. */
export const SYMBOL_ROLES: readonly string[] = Object.keys(ROLE_SYMBOL);

/** A complete SVG document of `name`, for an image source. */
export function svgOf(name: SymbolName, size = 128): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 64 64">${SYMBOLS[name]}</svg>`;
}
