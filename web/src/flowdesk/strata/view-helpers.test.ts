import { describe, it, expect, afterEach } from "vitest";
import type { SceneNode } from "./scene";
import type { Hop } from "../../api/types";
import {
  CAPTION_SLOT_PX,
  CELL,
  CONTACT_SHADOW_OPACITY,
  CONTACT_SHADOW_RADIUS,
  DENSITY_DEFAULT,
  DENSITY_MAX,
  DENSITY_MIN,
  GRID_SLOT_PX,
  HEX_RADIUS,
  HEX_THICKNESS,
  LANE_SPACING,
  MONO_KINDS,
  NODE_HEIGHT,
  OFF_PATH_DESATURATION,
  OFF_PATH_LABEL_SLOT_PX,
  OFF_PATH_OPACITY,
  PLATE_EDGE_HEIGHT,
  PLATE_OPACITY_DARK,
  PLATE_OPACITY_LIGHT,
  clamp,
  desaturate,
  findHopForNode,
  hexCorners,
  isDarkBackground,
  isLayerFlat,
  isSelectedNode,
  isolateLayer,
  layerGap,
  levelOfDetail,
  matchLuminance,
  mixColor,
  nodeWorldPosition,
  parseCssColor,
  platePalette,
  positionNodes,
  relativeLuminance,
  resolveKindColor,
  resolveToken,
  sceneStationKey,
  slotX,
  toHexColor,
  toggleLayer,
} from "./view-helpers";
import { layerOffsets } from "./path";

function node(overrides: Partial<SceneNode> = {}): SceneNode {
  return {
    uid: "u1",
    kind: "Device",
    label: "core-1",
    note: "",
    rank: 0,
    lane: 0,
    shared: true,
    layer: 0,
    cell: { q: 0, r: 0 },
    dimmed: false,
    verdict: null,
    ...overrides,
  };
}

afterEach(() => {
  document.documentElement.removeAttribute("style");
});

describe("token resolution", () => {
  it("reads --kind-<kind> off the root element", () => {
    document.documentElement.style.setProperty("--kind-Device", "#123456");
    expect(resolveKindColor("Device")).toBe("#123456");
  });

  it("falls back to --kind-fallback when the kind has no entry", () => {
    document.documentElement.style.setProperty("--kind-fallback", "#abcdef");
    expect(resolveKindColor("NotAKind")).toBe("#abcdef");
  });

  it("falls back to a hardcoded colour when neither var resolves", () => {
    expect(resolveKindColor("NotAKind")).toBe("#8b8f96");
  });

  it("reads an arbitrary theme token, or the caller's fallback", () => {
    document.documentElement.style.setProperty("--accent", "#0f0f0f");
    expect(resolveToken("--accent", "#ffffff")).toBe("#0f0f0f");
    expect(resolveToken("--not-a-token", "#ffffff")).toBe("#ffffff");
  });

  it("sets the address and interface kinds in the mono font", () => {
    for (const kind of ["IpAddress", "Prefix", "Interface", "Tunnel", "WanLink", "VrfInstance", "Port", "Endpoint"]) {
      expect(MONO_KINDS.has(kind)).toBe(true);
    }
    expect(MONO_KINDS.has("Device")).toBe(false);
  });
});

describe("colour maths", () => {
  it("parses hex and rgb, and rejects anything else", () => {
    expect(parseCssColor("#fff")).toEqual({ r: 255, g: 255, b: 255 });
    expect(parseCssColor("#102030")).toEqual({ r: 16, g: 32, b: 48 });
    expect(parseCssColor("rgb(1, 2, 3)")).toEqual({ r: 1, g: 2, b: 3 });
    expect(parseCssColor("rgba(1 2 3 / 0.5)")).toEqual({ r: 1, g: 2, b: 3 });
    expect(parseCssColor("rebeccapurple")).toBeNull();
    expect(parseCssColor("")).toBeNull();
  });

  it("round-trips through toHexColor, clamping out-of-range channels", () => {
    expect(toHexColor({ r: 16, g: 32, b: 48 })).toBe("#102030");
    expect(toHexColor({ r: -20, g: 300, b: 0 })).toBe("#00ff00");
  });

  it("mixes in plain sRGB, the way color-mix does", () => {
    const mid = mixColor({ r: 0, g: 0, b: 0 }, { r: 100, g: 200, b: 40 }, 0.5);
    expect(mid).toEqual({ r: 50, g: 100, b: 20 });
    expect(mixColor({ r: 9, g: 9, b: 9 }, { r: 1, g: 1, b: 1 }, 0)).toEqual({ r: 1, g: 1, b: 1 });
  });

  it("scores luminance the WCAG way, and calls a dark background dark", () => {
    expect(relativeLuminance({ r: 255, g: 255, b: 255 })).toBeCloseTo(1, 6);
    expect(relativeLuminance({ r: 0, g: 0, b: 0 })).toBeCloseTo(0, 6);
    expect(isDarkBackground({ r: 16, g: 22, b: 29 })).toBe(true);
    expect(isDarkBackground({ r: 238, g: 241, b: 245 })).toBe(false);
  });

  it("matchLuminance moves a colour onto a reference's luminance", () => {
    const reference = { r: 180, g: 180, b: 180 };
    for (const colour of [
      { r: 40, g: 90, b: 160 },
      { r: 220, g: 200, b: 120 },
    ]) {
      const matched = matchLuminance(colour, reference);
      expect(relativeLuminance(matched)).toBeCloseTo(relativeLuminance(reference), 3);
    }
  });

  it("desaturates toward gray without changing the overall weight much", () => {
    const colour = { r: 200, g: 40, b: 40 };
    const gray = desaturate(colour, 1);
    expect(gray.r).toBeCloseTo(gray.g, 6);
    expect(gray.g).toBeCloseTo(gray.b, 6);
    const partial = desaturate(colour, 0.5);
    expect(partial.r).toBeLessThan(colour.r);
    expect(partial.g).toBeGreaterThan(colour.g);
    expect(desaturate(colour, 0)).toEqual(colour);
    expect(OFF_PATH_DESATURATION).toBeGreaterThan(0);
    expect(OFF_PATH_OPACITY).toBeCloseTo(0.25, 6);
  });

  it("clamps", () => {
    expect(clamp(5, 0, 3)).toBe(3);
    expect(clamp(-5, 0, 3)).toBe(0);
    expect(clamp(1.5, 0, 3)).toBe(1.5);
  });
});

describe("plate palette in both themes", () => {
  const THEMES = [
    { name: "light", bg: "#eef1f5", text: "#1c2733", dark: false },
    { name: "dark", bg: "#10161d", text: "#e8eef4", dark: true },
    { name: "dracula", bg: "#282a36", text: "#f8f8f2", dark: true },
    { name: "catppuccin", bg: "#1e1e2e", text: "#cdd6f4", dark: true },
  ];
  const SEPARATION = 0.02;

  for (const theme of THEMES) {
    it(`${theme.name}: every plate is at least ${SEPARATION} of luminance from --bg`, () => {
      const background = relativeLuminance(parseCssColor(theme.bg)!);
      for (let layer = 0; layer < 4; layer++) {
        const palette = platePalette(theme.bg, theme.text, layer);
        const fill = relativeLuminance(parseCssColor(palette.fill)!);
        expect(Math.abs(fill - background)).toBeGreaterThanOrEqual(SEPARATION);
      }
    });

    it(`${theme.name}: the rim is a further step again, so a plate has an edge`, () => {
      const background = relativeLuminance(parseCssColor(theme.bg)!);
      for (let layer = 0; layer < 4; layer++) {
        const palette = platePalette(theme.bg, theme.text, layer);
        const fill = relativeLuminance(parseCssColor(palette.fill)!);
        const rim = relativeLuminance(parseCssColor(palette.rim)!);
        expect(Math.abs(rim - background)).toBeGreaterThan(Math.abs(fill - background));
      }
    });

    it(`${theme.name}: the thickness edge is brighter than the surface but under the rim`, () => {
      const background = relativeLuminance(parseCssColor(theme.bg)!);
      for (let layer = 0; layer < 4; layer++) {
        const palette = platePalette(theme.bg, theme.text, layer);
        const fill = relativeLuminance(parseCssColor(palette.fill)!);
        const edge = relativeLuminance(parseCssColor(palette.edge)!);
        const rim = relativeLuminance(parseCssColor(palette.rim)!);
        expect(Math.abs(edge - background)).toBeGreaterThan(Math.abs(fill - background));
        expect(Math.abs(edge - background)).toBeLessThan(Math.abs(rim - background));
      }
    });

    it(`${theme.name}: the four plates differ in hue, not in weight`, () => {
      const palettes = [0, 1, 2, 3].map((layer) => platePalette(theme.bg, theme.text, layer));
      const fills = palettes.map((p) => p.fill);
      expect(new Set(fills).size).toBe(4);
      const luminances = fills.map((f) => relativeLuminance(parseCssColor(f)!));
      // matched before the 8-bit round-trip, so the tolerance is one rounding step
      for (const l of luminances) expect(Math.abs(l - luminances[0])).toBeLessThan(0.01);
    });

    it(`${theme.name}: reports the theme it derived, at 8-12% opacity`, () => {
      const palette = platePalette(theme.bg, theme.text, 0);
      expect(palette.dark).toBe(theme.dark);
      expect(palette.opacity).toBeGreaterThanOrEqual(0.08);
      expect(palette.opacity).toBeLessThanOrEqual(0.12);
    });
  }

  it("draws the dark theme's plate the more opaque of the two", () => {
    expect(PLATE_OPACITY_DARK).toBeGreaterThan(PLATE_OPACITY_LIGHT);
  });

  it("leaves the physical plate neutral, with no hue", () => {
    const neutral = platePalette("#eef1f5", "#1c2733", 0);
    expect(neutral.fill).toBe(toHexColor(mixColor({ r: 0x1c, g: 0x27, b: 0x33 }, { r: 0xee, g: 0xf1, b: 0xf5 }, 0.1)));
  });

  it("falls back to the light theme's values when a token does not parse", () => {
    const fallback = platePalette("not-a-colour", "also-not", 0);
    expect(fallback.dark).toBe(false);
    expect(fallback.opacity).toBe(PLATE_OPACITY_LIGHT);
  });

  it("treats an unknown layer index as neutral", () => {
    expect(() => platePalette("#eef1f5", "#1c2733", 9)).not.toThrow();
  });
});

describe("geometry constants", () => {
  it("derives every size from the hop-slot step", () => {
    expect(HEX_RADIUS).toBeCloseTo(CELL * 0.33, 9);
    expect(NODE_HEIGHT).toBeCloseTo(HEX_RADIUS * 2, 9);
    expect(LANE_SPACING).toBeGreaterThan(HEX_RADIUS * 2);
  });

  it("keeps the node thinner than its radius and a quarter of the layer gap", () => {
    expect(HEX_THICKNESS).toBeLessThan(HEX_RADIUS);
    expect(layerGap(DENSITY_DEFAULT)).toBeGreaterThan(HEX_THICKNESS * 4);
  });

  it("extrudes a node deep enough to light as a prism, and a plate to a thin slab", () => {
    expect(HEX_THICKNESS).toBeCloseTo(HEX_RADIUS * 0.45, 9);
    expect(PLATE_EDGE_HEIGHT).toBeCloseTo(HEX_RADIUS * 0.15, 9);
    expect(PLATE_EDGE_HEIGHT).toBeLessThan(HEX_THICKNESS);
  });

  it("sizes the contact shadow wider than the prism that casts it", () => {
    expect(CONTACT_SHADOW_RADIUS).toBeGreaterThan(HEX_RADIUS);
    expect(CONTACT_SHADOW_OPACITY).toBeCloseTo(0.35, 9);
  });

  it("expresses the layer gap as a multiple of the node's own size, clamped to the slider", () => {
    expect(layerGap(DENSITY_DEFAULT)).toBeCloseTo(DENSITY_DEFAULT * NODE_HEIGHT, 9);
    expect(layerGap(0)).toBeCloseTo(DENSITY_MIN * NODE_HEIGHT, 9);
    expect(layerGap(100)).toBeCloseTo(DENSITY_MAX * NODE_HEIGHT, 9);
    expect(DENSITY_DEFAULT).toBeGreaterThanOrEqual(DENSITY_MIN);
    expect(DENSITY_DEFAULT).toBeLessThanOrEqual(DENSITY_MAX);
  });

  it("returns six hexagon corners at the given radius", () => {
    const corners = hexCorners(3);
    expect(corners).toHaveLength(6);
    for (const [x, z] of corners) expect(Math.hypot(x, z)).toBeCloseTo(3, 9);
    expect(hexCorners(6)[0][0]).toBeCloseTo(hexCorners(3)[0][0] * 2, 9);
  });
});

describe("node placement", () => {
  it("reads X from the hop slot, Y from the layer and Z from the lane", () => {
    const position = nodeWorldPosition({ q: 4, r: 2 }, 7);
    expect(position.x).toBeCloseTo(4 * CELL, 9);
    expect(position.y).toBe(7);
    expect(position.z).toBeCloseTo(2 * LANE_SPACING, 9);
    expect(slotX(4)).toBeCloseTo(4 * CELL, 9);
    expect(slotX(0)).toBe(0);
  });

  it("keys every node by scene.ts's own uid:lane:rank", () => {
    expect(sceneStationKey({ uid: "sw1", lane: 2, rank: 5 })).toBe("sw1:2:5");
    const positions = positionNodes(
      [node({ uid: "a", rank: 1, cell: { q: 1, r: 0 }, layer: 2 })],
      layerOffsets(4, 10, []),
    );
    expect(positions.get("a:0:1")!.position.y).toBe(20);
  });

  it("places a node on a layer that has no offset at the floor", () => {
    const positions = positionNodes([node({ layer: 9 })], layerOffsets(4, 10, []));
    expect(positions.get("u1:0:0")!.position.y).toBe(0);
  });
});

describe("hop and selection lookups", () => {
  const hops: Hop[] = [
    { uid: "a", kind: "Device", label: "a", rank: 0, lane: 0, shared: true } as Hop,
    { uid: "a", kind: "Device", label: "a", rank: 3, lane: 1, shared: false } as Hop,
  ];

  it("matches by uid, lane and rank on a hairpin path", () => {
    const found = findHopForNode(hops, node({ uid: "a", rank: 3, lane: 1 }));
    expect(found).toBe(hops[1]);
    expect(findHopForNode(hops, node({ uid: "a", rank: 9, lane: 1 }))).toBeUndefined();
  });

  it("selects on the same triple", () => {
    expect(isSelectedNode({ type: "hop", data: hops[1] }, node({ uid: "a", rank: 3, lane: 1 }))).toBe(true);
    expect(isSelectedNode({ type: "hop", data: hops[1] }, node({ uid: "a", rank: 0, lane: 0 }))).toBe(false);
    expect(isSelectedNode(null, node())).toBe(false);
  });
});

describe("layer flatten state", () => {
  it("toggles a layer in and out of the flattened set, without mutating its input", () => {
    const empty = new Set<number>();
    const one = toggleLayer(empty, 2);
    expect(isLayerFlat(one, 2)).toBe(true);
    expect(empty.size).toBe(0);
    expect(isLayerFlat(toggleLayer(one, 2), 2)).toBe(false);
  });

  it("Only flattens every other plate", () => {
    const only = isolateLayer(new Set(), 1, 4);
    expect([...only].sort()).toEqual([0, 2, 3]);
  });

  it("a second Only on the standing plate restores the whole stack", () => {
    const only = isolateLayer(new Set(), 1, 4);
    expect(isolateLayer(only, 1, 4).size).toBe(0);
  });
});

describe("level of detail", () => {
  it("keeps everything on at a comfortable zoom", () => {
    const lod = levelOfDetail(CAPTION_SLOT_PX + 20);
    expect(lod).toEqual({ offPathLabels: true, captions: true, grid: true });
  });

  it("sheds captions, then off-path labels, then the plate grid", () => {
    expect(levelOfDetail(CAPTION_SLOT_PX - 1).captions).toBe(false);
    expect(levelOfDetail(CAPTION_SLOT_PX - 1).offPathLabels).toBe(true);
    expect(levelOfDetail(OFF_PATH_LABEL_SLOT_PX - 1).offPathLabels).toBe(false);
    expect(levelOfDetail(OFF_PATH_LABEL_SLOT_PX - 1).grid).toBe(true);
    expect(levelOfDetail(GRID_SLOT_PX - 1).grid).toBe(false);
  });

  it("orders the thresholds so detail always drops in that order", () => {
    expect(GRID_SLOT_PX).toBeLessThan(OFF_PATH_LABEL_SLOT_PX);
    expect(OFF_PATH_LABEL_SLOT_PX).toBeLessThan(CAPTION_SLOT_PX);
  });
});
