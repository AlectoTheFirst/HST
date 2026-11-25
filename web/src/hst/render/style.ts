export type Theme = "light" | "dark";

const LIGHT = {
  plate: 0xe8edf2,
  plateEdge: 0xbfc9d3,
  band: 0xdce3ea,
  bandEdge: 0xc6d0da,
  bracket: 0xd0d8e0,
  observed: 0x3c74de,
  carried: 0xc98f1e,
  failed: 0xd0453a,
  unknown: 0x8d97a1,
  added: 0x2f9e5f,
  changed: 0xd99a14,
  removed: 0xd0453a,
  unchanged: 0x7d8a97,
  portUp: 0x7fb59d,
  portDown: 0xd0453a,
  portAdminDown: 0x9aa3ac,
  line: 0x4a83e6,
  lag: 0x8f63c9,
  mismatch: 0xd99a14,
  tunnel: 0x1196a6,
  circuit: 0xb4419e,
  context: 0x8eaac6,
  selected: 0xf2a900,
  ghost: 0xd3d9df,
  route: 0x1a73e8,
  routeHalo: 0x0b4fb3,
  symbol: 0xffffff,
  firewallBody: 0xd8473f,
  cloudBody: 0xf4f7fb,
  linkCore: 0xb9d3ff,
  grid: 0xd9e0ea,
  name: 0x5b6672,
} as const;

export type PaletteKey = keyof typeof LIGHT;
export type Palette = Readonly<Record<PaletteKey, number>>;

const DARK: Palette = {
  plate: 0x111a24,
  plateEdge: 0x2b4b63,
  band: 0x15202c,
  bandEdge: 0x243a4d,
  bracket: 0x1c2a38,
  observed: 0x2f6fe0,
  carried: 0xb9862a,
  failed: 0xd9534a,
  unknown: 0x4d5a66,
  added: 0x34b277,
  changed: 0xe0a526,
  removed: 0xe0574d,
  unchanged: 0x42505d,
  portUp: 0x2c8a68,
  portDown: 0xe0574d,
  portAdminDown: 0x56636f,
  line: 0x4aa3ff,
  lag: 0xa58be0,
  mismatch: 0xe0a526,
  tunnel: 0x39d0d8,
  circuit: 0xd57bc6,
  context: 0x2b5677,
  selected: 0xffd34d,
  ghost: 0x26313c,
  route: 0x4f9dff,
  routeHalo: 0x08203f,
  symbol: 0xeaf4ff,
  firewallBody: 0xc9433b,
  cloudBody: 0xdfe8f5,
  linkCore: 0xa8d4ff,
  grid: 0x1b2734,
  name: 0xa9b4c0,
};

/** The map colors of each theme. The base is muted; strong color marks state, change, selection and the route. */
export const PALETTES: Readonly<Record<Theme, Palette>> = { light: LIGHT, dark: DARK };

/** The tint of an area by block kind. */
export const KIND_TINT: Readonly<Record<string, number>> = {
  "internet-edge": 0xe0574d,
  "wan-edge": 0x8d6be0,
  firewall: 0xe08a3c,
  campus: 0x3faa6a,
  dc: 0x3d7fd6,
  other: 0x8d97a1,
  role: 0x8d97a1,
};

/** The tint of a block kind; a named block (`named:<zone>:<name>`) takes the tint of its zone. */
export function tintOf(kind: unknown): number {
  const k = String(kind);
  if (k.startsWith("named:")) {
    const zone = k.split(":")[1];
    return zone === "external" || zone === "internet" ? KIND_TINT["internet-edge"] : zone === "internal" ? KIND_TINT.campus : KIND_TINT.other;
  }
  return Object.hasOwn(KIND_TINT, k) ? KIND_TINT[k] : KIND_TINT.other;
}

/** The share of the kind tint in an area's proxy fill. */
export const TINT_FILL = 0.16;

/** The pixel width of the soft glow under a backbone link and around a selected area. */
export const GLOW_PX = { backbone: 6, selected: 5 } as const;

/** The line width in pixels of each line class; a cable of 10 Gbit/s or more is wider, and so is a pair line that carries more links. */
export const LINE_PX = {
  outline: 1,
  summary: 1.25,
  "summary-2": 1.4,
  "summary-5": 1.5,
  cable: 1,
  "cable-10g": 1.25,
  "cable-40g": 1.5,
  bundle: 1.5,
  "site-link": 1.5,
  tunnel: 1.25,
  circuit: 1.5,
} as const;

/** The count class of a collapsed pair line: the suffix of its batch key, "" for one link. */
export function countClass(n: number): "" | "2" | "5" {
  return n >= 5 ? "5" : n >= 2 ? "2" : "";
}

/** The speed class of a cable: the suffix of its line batch key, "" below 10 Gbit/s or unknown. */
export function speedClass(mbps: unknown): "" | "10g" | "40g" {
  const n = Number(mbps);
  if (!Number.isFinite(n) || n < 10_000) return "";
  return n >= 40_000 ? "40g" : "10g";
}

export function pageTheme(root: HTMLElement = document.documentElement): Theme {
  const value = getComputedStyle(root).getPropertyValue("--bg").trim().replace("#", "");
  const hex = value.length === 3 ? [...value].map((c) => c + c).join("") : value;
  if (!/^[0-9a-f]{6}$/i.test(hex)) return "light";
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.4 ? "dark" : "light";
}
