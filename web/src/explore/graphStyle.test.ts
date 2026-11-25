import { describe, it, expect } from "vitest";
import { SLOT_COUNT, OTHER_SLOT, NODE_SIZE } from "./graphElements";
import { SHAPES, readPalette, slotColor, slotShape, stylesheet } from "./graphStyle";
import type { Palette } from "./graphStyle";

const LIGHT: Palette = {
  panel: "#ffffff",
  panel2: "#f9fafc",
  border: "#e1e6ed",
  line: "#b8c4d0",
  text: "#1a2230",
  muted: "#7c8794",
  muted2: "#56626f",
  accent: "#2f6fe4",
  dark: false,
};

const DARK: Palette = { ...LIGHT, panel: "#0f1419", panel2: "#131a23", dark: true };

/** One block of the stylesheet, as a plain bag of properties. */
function rule(palette: Palette, selector: string): Record<string, unknown> {
  const found = stylesheet(palette).find((entry) => entry.selector === selector);
  expect(found, `no rule for ${selector}`).toBeDefined();
  return (found as unknown as { style: Record<string, unknown> }).style;
}

describe("the categorical palette", () => {
  it("gives every slot its own colour, in both modes", () => {
    for (const palette of [LIGHT, DARK]) {
      const colors = Array.from({ length: SLOT_COUNT }, (_unused, slot) =>
        slotColor(palette, slot),
      );
      expect(new Set(colors).size).toBe(SLOT_COUNT);
    }
  });

  it("has a dark column that differs from the light column", () => {
    const differs = Array.from({ length: SLOT_COUNT }, (_unused, slot) => slot).filter(
      (slot) => slotColor(LIGHT, slot) !== slotColor(DARK, slot),
    );
    expect(differs.length).toBeGreaterThan(SLOT_COUNT / 2);
  });

  it("gives every slot its own silhouette", () => {
    const shapes = Array.from({ length: SLOT_COUNT }, (_unused, slot) => slotShape(slot));
    expect(new Set(shapes).size).toBe(SLOT_COUNT);
    expect(shapes).toEqual([...SHAPES]);
  });

  it("marks a label past the eighth with the neutral colour", () => {
    expect(slotColor(LIGHT, OTHER_SLOT)).toBe(LIGHT.muted);
    const owned = Array.from({ length: SLOT_COUNT }, (_unused, slot) => slotColor(LIGHT, slot));
    expect(owned).not.toContain(LIGHT.muted);
  });
});

describe("stylesheet", () => {
  it("paints a node from its slot", () => {
    for (let slot = 0; slot < SLOT_COUNT; slot += 1) {
      expect(rule(DARK, `node[slot = ${slot}]`)).toMatchObject({
        "background-color": slotColor(DARK, slot),
        shape: slotShape(slot),
        "border-style": "solid",
      });
    }
  });

  it("falls back to the dashed neutral mark for an unslotted node", () => {
    expect(rule(LIGHT, "node")).toMatchObject({
      "background-color": LIGHT.muted,
      shape: "ellipse",
      "border-style": "dashed",
      width: NODE_SIZE,
    });
    expect(stylesheet(LIGHT).some((entry) => entry.selector === `node[slot = ${SLOT_COUNT}]`)).toBe(
      false,
    );
  });

  it("hides a caption below a minimum zoomed font size", () => {
    expect(rule(LIGHT, "node")["min-zoomed-font-size"]).toBeGreaterThan(0);
    expect(rule(LIGHT, "edge")["min-zoomed-font-size"]).toBeGreaterThan(
      rule(LIGHT, "node")["min-zoomed-font-size"] as number,
    );
  });

  it("gives an edge a direction and a curve", () => {
    expect(rule(LIGHT, "edge")).toMatchObject({
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
    });
    expect(rule(LIGHT, "edge")["control-point-step-size"]).toBeGreaterThan(0);
  });
});

describe("readPalette", () => {
  it("reads the mode off the surface colour", () => {
    const root = document.createElement("div");
    root.style.setProperty("--panel2", "#131a23");
    document.body.append(root);
    expect(readPalette(root).dark).toBe(true);

    root.style.setProperty("--panel2", "#f9fafc");
    expect(readPalette(root).dark).toBe(false);
    root.remove();
  });

  it("falls back to the light palette without a stylesheet", () => {
    expect(readPalette(document.createElement("div"))).toMatchObject({
      panel2: "#f9fafc",
      dark: false,
    });
  });
});
