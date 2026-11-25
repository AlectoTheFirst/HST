import { describe, expect, it } from "vitest";
import { estate, base, tile, type Tables } from "../test/estate";
import { fit, minimapView, toScreen, zoomOf } from "./camera";
import { createNullRenderer, type NullRenderer } from "./null";
import { ARC_STEPS, LINE_PICK_PX, Y, orthogonal, rgb, type LineBatch } from "./scene";
import { LINE_PX, PALETTES, speedClass } from "./style";
import { SYMBOLS, symbolOf, svgOf } from "./symbols";
import { DEFAULT_STYLE, type Level, type TableName } from "./types";

const vp = { width: 1200, height: 800 };
const UNTILED: TableName[] = ["render_t0", "render_t1", "render_t1_edges", "render_t1_contexts", "context_identity"];

function load(t: Tables, tiles: string[] = []): NullRenderer {
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of UNTILED) r.setTier(name, t[name]);
  for (const block of tiles) {
    r.setTier("layout", tile(t, "layout", block), block);
    for (const name of ["render_t2_ports", "render_t2_cables", "render_t2_contexts", "render_t2_segments"] as TableName[]) {
      r.setTier(name, tile(t, name, block), block);
    }
  }
  return r;
}

function at(r: NullRenderer, level: Level, uid?: string): void {
  const p = uid ? r.scene.layout.get(uid)! : null;
  const where = p ? { u: p.u + p.w / 2, v: p.v + p.h / 2 } : fit(r.scene.bounds(), vp);
  r.setCamera({ u: where.u, v: where.v, zoom: level === 1 ? 1 : zoomOf(level) * 1.2 }, vp);
}

function segments(l: LineBatch): [number[], number[]][] {
  return l.ids.map((_, i) => [l.positions.slice(i * 6, i * 6 + 3), l.positions.slice(i * 6 + 3, i * 6 + 6)]);
}

describe("the style tokens", () => {
  it("give every palette key a light and a dark value", () => {
    const keys = Object.keys(PALETTES.light).sort();
    expect(Object.keys(PALETTES.dark).sort()).toEqual(keys);
    for (const k of keys) {
      for (const theme of ["light", "dark"] as const) {
        const v = PALETTES[theme][k as keyof typeof PALETTES.light];
        expect(Number.isInteger(v) && v >= 0 && v <= 0xffffff, `${theme}.${k}`).toBe(true);
      }
    }
  });

  it("draw a device in the palette of the style's theme", () => {
    const r = load(estate({ sites: 1, devices: 4, ports: 0 }));
    at(r, 3);
    const color = (uid: string) => {
      const b = r.scene.batches(3).boxes.find((x) => x.cls === "device")!;
      const i = b.ids.indexOf(uid);
      return b.colors.slice(i * 3, i * 3 + 3);
    };
    expect(color("dev:s0d1")).toEqual(rgb(PALETTES.light.observed));
    r.setStyle({ ...DEFAULT_STYLE, theme: "dark" });
    expect(color("dev:s0d1")).toEqual(rgb(PALETTES.dark.observed));
  });

  it("keep thin lines and a speed class for fast cables", () => {
    for (const w of Object.values(LINE_PX)) expect(w >= 1 && w <= 1.5).toBe(true);
    expect([speedClass(null), speedClass(1000), speedClass(10_000), speedClass(100_000)]).toEqual(["", "", "10g", "40g"]);
  });
});

describe("the device symbols", () => {
  it("draw an unknown role as the unknown symbol", () => {
    expect(symbolOf("toaster")).toBe("unknown");
    expect(symbolOf(undefined)).toBe("unknown");
    expect(symbolOf("router")).toBe("router");
  });

  it("parse as SVG", () => {
    for (const name of Object.keys(SYMBOLS) as (keyof typeof SYMBOLS)[]) {
      const doc = new DOMParser().parseFromString(svgOf(name), "image/svg+xml");
      expect(doc.querySelector("parsererror"), name).toBeNull();
      expect(doc.documentElement.childElementCount, name).toBeGreaterThan(0);
    }
  });

  it("put one symbol on the top face of every device box", () => {
    const t = estate({ sites: 1, devices: 6, ports: 0 });
    t.render_t1[0] = { ...t.render_t1[0], role: "firewall" };
    const r = load(t);
    at(r, 3);
    const { boxes, symbols } = r.scene.batches(3);
    const devices = boxes.find((b) => b.cls === "device")!.ids;
    expect(symbols.flatMap((s) => s.ids).sort()).toEqual([...devices].sort());
    expect(symbols.find((s) => s.name === "firewall")?.ids).toEqual([String(t.render_t1[0].uid)]);
    const unknown = symbols.find((s) => s.name === "unknown")!;
    expect(unknown.data[1]).toBeGreaterThanOrEqual(Y.deviceTop);
  });
});

describe("the links", () => {
  const t = estate({ sites: 3, devices: 12, ports: 4 });

  it("draw every physical device pair at device zoom", () => {
    const r = load(t);
    at(r, 3);
    const placed = (uid: unknown) => r.scene.layout.has(String(uid));
    const pairs = t.render_t1_edges
      .filter((e) => Number(e.cable_count) + Number(e.lag_count) > 0 && placed(e.a_uid) && placed(e.b_uid))
      .map((e) => String(e.pair_id));
    const drawn = new Set(r.scene.batches(3).lines.filter((l) => l.cls === "summary").flatMap((l) => l.ids));
    expect(pairs.length).toBeGreaterThan(0);
    expect(pairs.filter((p) => !drawn.has(p))).toEqual([]);
  });

  it("keep every physical segment on the iso axes", () => {
    const r = load(t, ["block:s0:campus"]);
    for (const level of [1, 2, 3, 4] as Level[]) {
      at(r, level, level === 4 ? "dev:s0d5" : undefined);
      for (const l of r.scene.batches(level).lines) {
        if (l.cls === "tunnel") continue;
        for (const [a, b] of segments(l)) expect(a[0] === b[0] || a[2] === b[2], `${l.cls} ${a} ${b}`).toBe(true);
      }
    }
    expect(orthogonal([0, 0], [10, 4])).toEqual([[0, 0], [5, 0], [5, 4], [10, 4]]);
  });

  it("draw tunnel arcs with a dash by encapsulation", () => {
    const r = load(t);
    at(r, 3);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0", transports: new Map([["dev:s0d0|dev:s1d0", [{ encap: "ipsec", count: 2 }, { encap: "gre", count: 1 }]]]) });
    const arc = r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!;
    const segs = segments(arc);
    expect(segs).toHaveLength(2 * ARC_STEPS);
    const gaps = (from: number) => segs.slice(from, from + ARC_STEPS).filter(([a, b]) => a.every((x, i) => x === b[i])).length;
    expect(gaps(0)).toBeGreaterThan(0);
    expect(gaps(ARC_STEPS)).toBeGreaterThan(0);
    expect(gaps(0)).not.toBe(gaps(ARC_STEPS));
    for (const [a, b] of segs) expect(Math.min(a[1], b[1])).toBeGreaterThanOrEqual(Y.deviceTop);
  });

  it("pick a device pair line and a cable", () => {
    const r = load(t, ["block:s0:campus"]);
    at(r, 3, "dev:s0d5");
    const summary = r.scene.batches(3).lines.find((l) => l.cls === "summary")!;
    const target = summary.ids.findIndex((id) => id === "dev:s0d4|dev:s0d5");
    const [a, b] = segments(summary)[target];
    const [x, y] = toScreen(r.camera, r.viewport, (a[0] + b[0]) / 2, (a[2] + b[2]) / 2, a[1]);
    expect(r.scene.pickLine(r.camera, r.viewport, x, y, 3)).toBe("dev:s0d4|dev:s0d5");
    at(r, 4, "dev:s0d5");
    const cable = r.scene.batches(4).lines.find((l) => l.cls === "cable")!;
    const [c0, c1] = segments(cable)[0];
    const [cx, cy] = toScreen(r.camera, r.viewport, (c0[0] + c1[0]) / 2, (c0[2] + c1[2]) / 2, c0[1]);
    expect(r.scene.pickLine(r.camera, r.viewport, cx, cy, 4)).toBe(cable.ids[0]);
    expect(r.scene.pickLine(r.camera, r.viewport, -100, -100, 4)).toBeNull();
  });

  it("pick a cable before a summary line that runs along it", () => {
    const r = load(t, ["block:s0:campus"]);
    at(r, 4, "dev:s0d5");
    const { camera, viewport } = r;
    const screen = (a: number[], b: number[]): [number, number] =>
      toScreen(camera, viewport, (a[0] + b[0]) / 2, (a[2] + b[2]) / 2, a[1]);
    const lines = r.scene.batches(4).lines;
    const summaries = lines.filter((l) => l.cls === "summary").flatMap(segments);
    expect(summaries.length).toBeGreaterThan(0);
    const dist = (p: [number, number], [a, b]: [number[], number[]]) => {
      const [ax, ay] = toScreen(camera, viewport, a[0], a[2], a[1]);
      const [bx, by] = toScreen(camera, viewport, b[0], b[2], b[1]);
      const dx = bx - ax;
      const dy = by - ay;
      const len = dx * dx + dy * dy;
      const t = len === 0 ? 0 : Math.max(0, Math.min(1, ((p[0] - ax) * dx + (p[1] - ay) * dy) / len));
      return Math.hypot(p[0] - (ax + t * dx), p[1] - (ay + t * dy));
    };
    let shared: { id: string; at: [number, number] } | null = null;
    for (const l of lines) {
      if (l.cls !== "cable") continue;
      segments(l).forEach(([a, b], i) => {
        const at = screen(a, b);
        if (!shared && summaries.some((s) => dist(at, s) <= LINE_PICK_PX)) shared = { id: l.ids[i], at };
      });
    }
    expect(shared).not.toBeNull();
    expect(r.scene.pickLine(camera, viewport, shared!.at[0], shared!.at[1], 4)).toBe(shared!.id);
  });
});

describe("the labels", () => {
  it("place by priority: site, block, the selected device and its ports, device, port, tunnel", () => {
    const rank = (kind: string, selected: boolean) =>
      ({ site: 0, block: 1, device: selected ? 2 : 4, port: 3, tunnel: 5 })[kind] ?? 9;
    const r = load(estate({ sites: 2, devices: 20, ports: 6 }), ["block:s0:campus"]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d3" });
    for (const level of [1, 2, 3, 4] as Level[]) {
      at(r, level, level >= 3 ? "dev:s0d3" : undefined);
      const ranks = r.frame().labels.map((l) => rank(l.kind, l.uid === "dev:s0d3" && level === 4));
      expect(ranks, `level ${level}`).toEqual([...ranks].sort((a, b) => a - b));
    }
  });
});

describe("the route", () => {
  it("gives a start pin, an end pin and one marker per hop, a stop at a blocked hop", () => {
    const r = load(estate({ sites: 1, devices: 6, ports: 0 }));
    at(r, 3);
    r.setRoutes([
      {
        id: "trace",
        state: "trace",
        points: [
          { u: 2, v: 2, label: "A" },
          { u: 10, v: 2 },
          { u: 10, v: 8, blocked: true },
          { u: 16, v: 8, label: "B" },
        ],
      },
    ]);
    const markers = r.frame().markers;
    expect(markers.map((m) => [m.kind, m.text])).toEqual([
      ["start", "A"],
      ["hop", "1"],
      ["stop", "2"],
      ["end", "B"],
    ]);
    const [x, y] = toScreen(r.camera, r.viewport, 10, 2, Y.route);
    expect(markers[1].x).toBeCloseTo(x);
    expect(markers[1].y).toBeCloseTo(y);
    r.setRoutes([]);
    expect(r.frame().markers).toEqual([]);
  });
});

describe("the minimap", () => {
  it("shows the viewport as a rectangle at a known camera", () => {
    const view = minimapView({ u: 50, v: 50, zoom: 2 }, { width: 800, height: 600 }, { u: 50, v: 50, zoom: 0.5 }, { width: 160, height: 120 });
    expect(view.x0).toBeCloseTo(80 - 100);
    expect(view.x1).toBeCloseTo(80 + 100);
    expect(view.y0).toBeCloseTo(60 - 75);
    expect(view.y1).toBeCloseTo(60 + 75);
  });
});
