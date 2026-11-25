/** A canvas cannot resolve CSS custom properties. */

import type { Css, StylesheetJson } from "cytoscape";
import { EDGE_LABEL_PX, LABEL_PX, NODE_SIZE, SLOT_COUNT } from "./graphElements";

export interface Palette {
  panel: string;
  panel2: string;
  border: string;
  line: string;
  text: string;
  muted: string;
  muted2: string;
  accent: string;
  /** Which column of the categorical palette applies, derived from the
   *  lightness of the surface. */
  dark: boolean;
}

/** The categorical palette has 8 slots, each a colour and a silhouette. */
const SERIES_LIGHT = [
  "#2a78d6", // blue
  "#eb6834", // orange
  "#1baf7a", // aqua
  "#eda100", // yellow
  "#e87ba4", // magenta
  "#008300", // green
  "#4a3aa7", // violet
  "#e34948", // red
];

const SERIES_DARK = [
  "#3987e5",
  "#d95926",
  "#199e70",
  "#c98500",
  "#d55181",
  "#008300",
  "#9085e9",
  "#e66767",
];

/** Cytoscape shape names, one per slot, in the same order as the colours. */
export const SHAPES = [
  "ellipse",
  "round-rectangle",
  "diamond",
  "triangle",
  "star",
  "hexagon",
  "rhomboid",
  "vee",
] as const;

/** The colour for one slot. `OTHER_SLOT` takes the theme's `muted` colour. */
export function slotColor(palette: Palette, slot: number): string {
  if (slot < 0 || slot >= SLOT_COUNT) return palette.muted;
  return (palette.dark ? SERIES_DARK : SERIES_LIGHT)[slot];
}

/** The silhouette for one slot. Outside the 8 slots it is the ellipse. */
export function slotShape(slot: number): string {
  if (slot < 0 || slot >= SLOT_COUNT) return "ellipse";
  return SHAPES[slot];
}

/** The light palette from theme.css `:root`. */
const FALLBACK = {
  panel: "#ffffff",
  panel2: "#f9fafc",
  border: "#e1e6ed",
  line: "#b8c4d0",
  text: "#1a2230",
  muted: "#7c8794",
  muted2: "#56626f",
  accent: "#2f6fe4",
} as const;

/** The font stack of `--ui`. */
const FONT = 'Archivo, system-ui, -apple-system, "Segoe UI", Arial, sans-serif';

/** Perceived lightness of a `#rgb` or `#rrggbb` surface, 0 to 1. A value it
 *  cannot parse returns 1. */
function lightness(color: string): number {
  const hex = color.trim().replace("#", "");
  const full = hex.length === 3 ? [...hex].map((c) => c + c).join("") : hex;
  if (!/^[0-9a-f]{6}$/i.test(full)) return 1;
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function readPalette(root: HTMLElement = document.documentElement): Palette {
  const style = getComputedStyle(root);
  const read = (name: keyof typeof FALLBACK): string =>
    style.getPropertyValue(`--${name}`).trim() || FALLBACK[name];
  const panel2 = read("panel2");
  return {
    panel: read("panel"),
    panel2,
    border: read("border"),
    line: read("line"),
    text: read("text"),
    muted: read("muted"),
    muted2: read("muted2"),
    accent: read("accent"),
    dark: lightness(panel2) < 0.4,
  };
}

/** Call `onChange` when the resolved theme changes. Returns an unsubscribe. */
export function watchTheme(onChange: () => void): () => void {
  if (typeof MutationObserver === "undefined") return () => {};
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}

/** Class put on everything outside a selected node's own neighbourhood. */
export const FADED = "gv-faded";

export function stylesheet(palette: Palette): StylesheetJson {
  const nodeStyle: Css.Node = {
    width: NODE_SIZE,
    height: NODE_SIZE,
    // the slot rules below override this "Other" mark
    "background-color": palette.muted,
    shape: "ellipse",
    "border-style": "dashed",
    "border-width": 2,
    "border-color": palette.panel,
    label: "data(caption)",
    "text-valign": "bottom",
    "text-halign": "center",
    "text-margin-y": 6,
    "font-family": FONT,
    "font-size": LABEL_PX,
    "min-zoomed-font-size": 9,
    color: palette.muted2,
    "text-background-color": palette.panel,
    "text-background-opacity": 0.78,
    "text-background-padding": "2px",
    "text-background-shape": "roundrectangle",
  };

  const edgeStyle: Css.Edge = {
    width: 1.6,
    "line-color": palette.line,
    "curve-style": "bezier",
    "control-point-step-size": 36,
    "target-arrow-shape": "triangle",
    "target-arrow-color": palette.line,
    "arrow-scale": 0.85,
    label: "data(type)",
    "font-family": FONT,
    "font-size": EDGE_LABEL_PX,
    "min-zoomed-font-size": 11,
    color: palette.muted,
    "text-rotation": "autorotate",
    "text-background-color": palette.panel2,
    "text-background-opacity": 0.85,
    "text-background-padding": "2px",
    "text-background-shape": "roundrectangle",
  };

  const slotStyles = Array.from({ length: SLOT_COUNT }, (_unused, slot) => ({
    selector: `node[slot = ${slot}]`,
    style: {
      "background-color": slotColor(palette, slot),
      shape: slotShape(slot),
      "border-style": "solid",
    } as Css.Node,
  }));

  return [
    { selector: "node", style: nodeStyle },
    ...slotStyles,
    { selector: "edge", style: edgeStyle },
    {
      selector: "node:selected",
      style: { "border-width": 4, "border-color": palette.accent, "z-index": 20 },
    },
    {
      selector: "edge:selected",
      style: { width: 2.8, "line-color": palette.accent, "target-arrow-color": palette.accent },
    },
    {
      selector: `.${FADED}`,
      style: { opacity: 0.18, "text-opacity": 0 },
    },
    {
      // `Css.Core` types every core property as required, so a partial block
      // needs the cast.
      selector: "core",
      style: { "active-bg-opacity": 0, "selection-box-color": palette.accent } as Css.Core,
    },
  ];
}
