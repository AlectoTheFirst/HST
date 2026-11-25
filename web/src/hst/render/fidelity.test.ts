import { describe, expect, it } from "vitest";
import { estate, base, tile, type Tables } from "../test/estate";
import { showcase } from "../test/showcase";
import { fit, minimapView, toScreen, zoomOf } from "./camera";
import { createNullRenderer, type NullRenderer } from "./null";
import { labelBox, rgb, Y, PORT_LABEL_ZOOM } from "./scene";
import { PALETTES, tintOf } from "./style";
import { symbolOf } from "./symbols";
import { DEFAULT_STYLE, type Label, type Level, type TableName } from "./types";

const vp = { width: 1600, height: 1000 };
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

function overlap(a: Label, b: Label): boolean {
  const p = labelBox(a);
  const q = labelBox(b);
  return p.x0 < q.x1 && q.x0 < p.x1 && p.y0 < q.y1 && q.y0 < p.y1;
}

describe("the showcase estate", () => {
  it("holds every block kind and a role and tier on every device", () => {
    const t = showcase();
    const kinds = new Set(t.render_t0.filter((x) => x.kind === "block").map((x) => x.block_kind));
    expect([...kinds].sort()).toEqual(["campus", "dc", "firewall", "internet-edge", "wan-edge"]);
    expect(t.render_t1.every((d) => d.role && d.tier)).toBe(true);
  });
});

describe("the areas", () => {
  it("draw a faint area per plate and a tinted area per band, and flag the selected one", () => {
    const t = showcase();
    const r = load(t);
    at(r, 2);
    r.setStyle({ ...DEFAULT_STYLE, area: "block:hq:dc" });
    const { areas, boxes } = r.scene.batches(2);
    const i = areas.ids.indexOf("block:hq:dc");
    expect(areas.kinds[i]).toBe(1);
    expect(areas.colors.slice(i * 3, i * 3 + 3)).toEqual(rgb(tintOf("dc")));
    expect(areas.selected[i]).toBe(1);
    expect(areas.kinds[areas.ids.indexOf("plate:hq")]).toBe(0);
    expect(boxes.find((b) => b.cls === "band")?.proxy).toBe(true);
    expect(boxes.find((b) => b.cls === "plate")?.proxy).toBe(true);
  });
});

describe("the device bodies", () => {
  it("give an observed firewall the brick body and an observed router the brand blue", () => {
    const r = load(showcase());
    at(r, 3, "dev:fw-1");
    const models = r.scene.batches(3).models;
    const colorOf = (uid: string) => {
      const m = models.find((x) => x.ids.includes(uid))!;
      const i = m.ids.indexOf(uid);
      return m.colors.slice(i * 3, i * 3 + 3);
    };
    expect(colorOf("dev:fw-1")).toEqual(rgb(PALETTES.light.firewallBody));
    expect(colorOf("dev:edge-rt-1")).toEqual(rgb(PALETTES.light.observed));
    expect(colorOf("dev:srv-4")).toEqual(rgb(PALETTES.light.failed));
  });

  it("keep the model of a chassis when it is selected, and draw no context tier slabs", () => {
    const t = estate({ sites: 1, devices: 4, ports: 2 });
    const r = load(t, ["block:s0:campus"]);
    at(r, 4, "dev:s0d0");
    const drawn = () => r.scene.batches(4).boxes.find((b) => b.cls === "tier")?.ids ?? [];
    expect(drawn()).toEqual([]);
    expect(r.scene.batches(4).models.flatMap((m) => m.ids)).toContain("dev:s0d0");
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    expect(drawn()).toEqual([]);
    expect(r.scene.batches(4).models.flatMap((m) => m.ids)).toContain("dev:s0d0");
  });
});

describe("the cards", () => {
  it("never overlap each other and keep the clusters clear", () => {
    const r = load(showcase());
    for (const level of [2, 3] as Level[]) {
      at(r, level);
      const labels = r.frame().labels.filter((l) => l.sub !== undefined || l.kind === "cluster");
      for (const a of labels) for (const b of labels) if (a !== b) expect(overlap(a, b), `${a.uid} over ${b.uid}`).toBe(false);
    }
  });

  it("stand above their anchor point", () => {
    const card: Label = { uid: "b", text: "Campus", sub: "11 devices", x: 100, y: 200, at: [0, 0, 0], kind: "block" };
    expect(labelBox(card).y1).toBeLessThan(200);
  });

  it("leave out an empty Unassigned site", () => {
    const t = estate({ sites: 1, devices: 3, ports: 0 });
    t.layout.push({ uid: "site:unassigned", kind: "site", parent_uid: null, u: 200, v: 0, w: 10, h: 10 });
    t.layout.push({ uid: "plate:unassigned", kind: "plate", parent_uid: "site:unassigned", u: 200, v: 0, w: 10, h: 10 });
    t.render_t0.push({ uid: "site:unassigned", kind: "site", label: "Unassigned", device_count: 0 });
    const r = load(t);
    at(r, 1);
    expect(r.frame().labels.some((l) => l.uid === "site:unassigned")).toBe(false);
  });
});

describe("the port labels", () => {
  it("sit outside their port, away from the device", () => {
    const t = estate({ sites: 1, devices: 4, ports: 4 });
    const r = load(t, ["block:s0:campus"]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d1" });
    const dev0 = r.scene.layout.get("dev:s0d1")!;
    r.setCamera({ u: dev0.u + dev0.w / 2, v: dev0.v + dev0.h / 2, zoom: PORT_LABEL_ZOOM }, vp);
    const label = r.frame().labels.find((l) => l.kind === "port" && l.uid.startsWith("dev:s0d1/"))!;
    const port = r.scene.layout.get(label.uid)!;
    const dev = r.scene.layout.get("dev:s0d1")!;
    const [dx, dy] = toScreen(r.camera, r.viewport, dev.u + dev.w / 2, dev.v + dev.h / 2, Y.portTop);
    const [px, py] = toScreen(r.camera, r.viewport, port.u + port.w / 2, port.v + port.h / 2, Y.portTop);
    expect(Math.hypot(label.x - dx, label.y - dy)).toBeGreaterThan(Math.hypot(px - dx, py - dy));
  });
});

describe("the minimap in 2D", () => {
  it("draws the viewport as a rectangle in the top view", () => {
    const view = minimapView({ u: 50, v: 50, zoom: 2, view: "top" }, { width: 800, height: 600 }, { u: 50, v: 50, zoom: 0.5, view: "top" }, { width: 160, height: 120 });
    expect([view.x0, view.y0, view.x1, view.y1]).toEqual([80 - 100, 60 - 75, 80 + 100, 60 + 75]);
  });
});

describe("the symbol by tier", () => {
  it("draws a switch of a routing tier as a layer-3 switch", () => {
    expect(symbolOf("switch", "core")).toBe("l3switch");
    expect(symbolOf("switch", "distribution")).toBe("l3switch");
    expect(symbolOf("switch", "access")).toBe("switch");
    // The server gives a core or distribution device the role router; it is a layer-3 switch.
    expect(symbolOf("router", "core")).toBe("l3switch");
    expect(symbolOf("router", "wan-edge")).toBe("router");
  });
});
