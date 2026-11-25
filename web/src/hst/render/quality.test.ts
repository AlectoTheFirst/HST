import { describe, expect, it } from "vitest";
import { portGroups } from "../data/portGroups";
import { estate, base, tile, type Tables } from "../test/estate";
import { fit, toPlane, toScreen, zoomOf } from "./camera";
import { MODELS } from "./models";
import { showcase } from "../test/showcase";
import { createNullRenderer, type NullRenderer } from "./null";
import { LABEL_BUDGET, PORT_CAP, PORT_LABEL_ZOOM, rgb } from "./scene";
import { countClass, tintOf } from "./style";
import { SYMBOLS } from "./symbols";
import { DEFAULT_STYLE, type Level, type Row, type TableName } from "./types";

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
    r.setTier("render_t2_port_groups", portGroups(tile(t, "render_t2_ports", block), tile(t, "render_t2_cables", block)), block);
  }
  return r;
}

function at(r: NullRenderer, level: Level, uid?: string, size = vp): void {
  const p = uid ? r.scene.layout.get(uid)! : null;
  const where = p ? { u: p.u + p.w / 2, v: p.v + p.h / 2 } : fit(r.scene.bounds(), size);
  r.setCamera({ u: where.u, v: where.v, zoom: level === 1 ? 1 : zoomOf(level) * 1.2 }, size);
}

/** An estate whose device 0 of site 0 is a core router and whose device 1 is a firewall. */
function tiered(): Tables {
  const t = estate({ sites: 2, devices: 12, ports: 4 });
  t.render_t1 = t.render_t1.map((r) =>
    r.uid === "dev:s0d0" ? { ...r, tier: "core", role: "router" } : r.uid === "dev:s0d1" ? { ...r, tier: "firewall", role: "firewall" } : r,
  );
  return t;
}

describe("the device models", () => {
  it("give every symbol a model", () => {
    expect(Object.keys(MODELS).sort()).toEqual(Object.keys(SYMBOLS).sort());
  });

  it("draw one batch per model kind, counted as one draw call each", () => {
    const r = load(tiered());
    at(r, 3);
    const { models, boxes } = r.scene.batches(3);
    // The core router of the estate is a layer-3 switch.
    expect(models.map((m) => m.name).sort()).toEqual(["firewall", "l3switch", "unknown"]);
    expect(models.reduce((n, m) => n + m.ids.length, 0)).toBe(24);
    expect(boxes.find((b) => b.cls === "device")?.proxy).toBe(true);
    const before = r.frame().drawCalls;
    r.applyDelta("render_t1", [{ key: "dev:s1d5", row: { ...tiered().render_t1.find((x) => x.uid === "dev:s1d5")!, role: "switch" } }]);
    expect(r.frame().drawCalls).toBe(before + 2);
  });
});

describe("the areas and clusters", () => {
  it("tint a block by its kind and paint its name on the ground, with no card", () => {
    const r = load(tiered());
    at(r, 2);
    const { areas, texts } = r.scene.batches(2);
    const i = areas.ids.indexOf("block:s0:campus");
    expect(areas.kinds[i]).toBe(1);
    expect(areas.colors.slice(3 * i, 3 * i + 3)).toEqual(rgb(tintOf("campus")));
    expect(texts.find((x) => x.id === "name:block:s0:campus")?.text).toBe("campus");
    expect(r.frame().labels.find((l) => l.uid === "block:s0:campus")).toBeUndefined();
  });

  it("draw the key devices as models at site zoom and collapse the others into one cluster per block", () => {
    const r = load(tiered());
    at(r, 2);
    const ids = r.scene.batches(2).models.flatMap((m) => m.ids).sort();
    expect(ids).toEqual(["dev:s0d0", "dev:s0d1"]);
    const clusters = r.frame().labels.filter((l) => l.kind === "cluster");
    expect(clusters.map((l) => [l.uid, l.text])).toEqual([
      ["cluster:block:s0:campus", "10 devices"],
      ["cluster:block:s1:campus", "12 devices"],
    ]);
    at(r, 3);
    expect(r.frame().labels.some((l) => l.kind === "cluster")).toBe(false);
  });

  it("glows the selected area", () => {
    const r = load(tiered());
    at(r, 2);
    r.setStyle({ ...DEFAULT_STYLE, area: "block:s0:campus" });
    const glow = r.scene.batches(2).outlines.find((l) => l.key === "glow:selected")!;
    expect(new Set(glow.ids)).toEqual(new Set(["block:s0:campus"]));
  });
});

describe("the link hierarchy", () => {
  it("widens a pair line by the links it collapses and badges it with the count", () => {
    expect([countClass(1), countClass(2), countClass(4), countClass(5), countClass(40)]).toEqual(["", "2", "2", "5", "5"]);
    const t = tiered();
    t.render_t1_edges = t.render_t1_edges.map((e) => (e.pair_id === "dev:s0d1|dev:s0d2" ? { ...e, cable_count: 3, lag_count: 3 } : e));
    const r = load(t);
    at(r, 3, "dev:s0d2");
    const wide = r.scene.batches(3).lines.find((l) => l.key === "summary:5")!;
    expect(new Set(wide.ids)).toEqual(new Set(["dev:s0d1|dev:s0d2"]));
    at(r, 4, "dev:s0d2");
    expect(r.frame().labels.find((l) => l.kind === "count")).toMatchObject({ uid: "dev:s0d1|dev:s0d2", text: "6 links" });
  });

  it("gives the backbone a glow and a midpoint node", () => {
    // The backbone is the bundle between two blocks at site zoom; a link between two sites is a plain line.
    const r = load(showcase());
    at(r, 2);
    const { outlines, boxes } = r.scene.batches(2);
    expect(outlines.some((l) => l.key === "glow:backbone" && l.ids.length > 0)).toBe(true);
    expect(boxes.find((b) => b.cls === "node")?.ids.length).toBeGreaterThan(0);
  });
});

describe("the ports at scale", () => {
  function big(): Tables {
    const t = estate({ sites: 1, devices: 3, ports: 2000 });
    return t;
  }

  it("collapse a 2,000-port device into groups with state counts", () => {
    const t = big();
    const groups = portGroups(tile(t, "render_t2_ports", "block:s0:campus"), tile(t, "render_t2_cables", "block:s0:campus"));
    const dev = groups.filter((g) => g.device_uid === "dev:s0d1");
    expect(dev.reduce((n, g) => n + Number(g.port_count), 0)).toBe(2000);
    expect(dev.length).toBeLessThan(10);
  });

  it("draw a 2,000-port device within the budget at every zoom, connected ports first", () => {
    const t = big();
    const r = load(t, ["block:s0:campus"]);
    const cabled = new Set(tile(t, "render_t2_cables", "block:s0:campus").flatMap((c: Row) => [String(c.a_port), String(c.b_port)]));
    // The sockets draw for the selected device.
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d1" });
    for (const level of [1, 2, 3, 4] as Level[]) {
      at(r, level, level >= 3 ? "dev:s0d1" : undefined);
      const f = r.frame();
      const ports = (r.scene.batches(level).boxes.find((b) => b.cls === "dot")?.ids ?? []).filter((id) => !id.startsWith("dot:"));
      const own = ports.filter((p) => p.startsWith("dev:s0d1/"));
      expect(own.length, `level ${level}`).toBeLessThanOrEqual(PORT_CAP);
      expect(f.labels.filter((l) => l.kind === "port").length).toBeLessThanOrEqual(LABEL_BUDGET.port);
      if (level === 4) expect(own.filter((p) => cabled.has(p))).toEqual([...cabled].filter((p) => p.startsWith("dev:s0d1/")).sort().filter((p) => own.includes(p)));
      if (level === 4) expect([...cabled].filter((p) => p.startsWith("dev:s0d1/")).every((p) => own.includes(p))).toBe(true);
    }
  });

  it("draws a 400-port device as dots on its cable ends, larger for the selected device, and no port group bars", () => {
    const t = estate({ sites: 1, devices: 3, ports: 400 });
    const r = load(t, ["block:s0:campus"]);
    at(r, 4, "dev:s0d1");
    const ends = new Set<string>();
    for (const c of r.scene.rows("render_t2_cables")) ends.add(String(c.a_port)).add(String(c.b_port));
    const boxes = (cls: string) => r.scene.batches(4).boxes.find((b) => b.cls === cls)?.ids ?? [];
    expect(boxes("port")).toEqual([]);
    const dots = boxes("dot").filter((id) => id.startsWith("dev:s0d1/"));
    expect(dots.length).toBeGreaterThan(0);
    expect(dots.length).toBeLessThan(400);
    for (const id of dots) expect(ends.has(id), id).toBe(true);
    const groups = [...r.scene.rows("render_t2_port_groups")].filter((g) => g.device_uid === "dev:s0d1");
    expect(groups.length).toBeGreaterThan(0);
    const side = (id: string) => {
      const b = r.scene.batches(4).boxes.find((x) => x.cls === "dot")!;
      return b.data[b.ids.indexOf(id) * 6 + 3];
    };
    const before = side(dots[0]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d1" });
    expect(side(dots[0])).toBeGreaterThan(before);
    expect(boxes("port")).toEqual([]);
  });

  it("draws a segment bar under a device with clients, labelled by its prefix or its count, and picks its device", () => {
    const t = estate({ sites: 1, devices: 3, ports: 2 });
    const block = "block:s0:campus";
    const dev = t.layout.find((r) => r.uid === "dev:s0d1")!;
    t.layout.push({ uid: "dev:s0d1/segments", kind: "segment", parent_uid: "dev:s0d1", u: dev.u, v: Number(dev.v) + 5, w: 4, h: 3, side: null, slot: 0 });
    t.render_t2_segments.push({ uid: "dev:s0d1/segment/bd:10", device_uid: "dev:s0d1", tile: block, vid: 10, name: "users", prefix: "10.1.10.0/24", client_count: 3 });
    const r = load(t, [block]);
    at(r, 4, "dev:s0d1");
    const bars = r.scene.batches(4).boxes.find((b) => b.cls === "segment")!;
    expect(bars.ids.filter((id) => !id.includes("#tick"))).toEqual(["dev:s0d1/segments"]);
    expect(bars.ids.filter((id) => id.includes("#tick"))).toHaveLength(3);
    const label = r.frame().labels.find((l) => l.kind === "segment")!;
    expect(label.text).toBe("10.1.10.0/24");
    t.render_t2_segments.push({ uid: "dev:s0d1/segment/bd:20", device_uid: "dev:s0d1", tile: block, vid: 20, name: "guests", prefix: null, client_count: 1 });
    r.setTier("render_t2_segments", tile(t, "render_t2_segments", block), block);
    expect(r.frame().labels.find((l) => l.kind === "segment")!.text).toBe("2 segments");
    const bar = r.scene.layout.get("dev:s0d1/segments")!;
    const [x, y] = toScreen(r.camera, r.viewport, bar.u + bar.w / 2, bar.v + bar.h / 2, 0.3);
    expect(r.scene.pick(r.camera, r.viewport, x, y, 4)).toBe("dev:s0d1");
    for (const row of t.render_t2_segments) row.client_count = 0;
    r.setTier("render_t2_segments", tile(t, "render_t2_segments", block), block);
    expect(r.scene.batches(4).boxes.find((b) => b.cls === "segment")).toBeUndefined();
  });

  it("names the cabled ports of the selected device and their far ends, and no other port", () => {
    const t = estate({ sites: 1, devices: 6, ports: 8 });
    const r = load(t, ["block:s0:campus"]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d1" });
    at(r, 4, "dev:s0d1");
    expect(r.frame().labels.filter((l) => l.kind === "port")).toEqual([]);
    const p = r.scene.layout.get("dev:s0d1")!;
    r.setCamera({ u: p.u + p.w / 2, v: p.v + p.h / 2, zoom: PORT_LABEL_ZOOM }, vp);
    const named = new Set(r.frame().labels.filter((l) => l.kind === "port").map((l) => l.uid));
    const cabled = new Set<string>();
    for (const c of r.scene.rows("render_t2_cables")) cabled.add(String(c.a_port)).add(String(c.b_port));
    for (const uid of named) expect(cabled.has(uid), uid).toBe(true);
    const own = [...cabled].filter((p) => p.startsWith("dev:s0d1/"));
    expect(own.length).toBeGreaterThan(0);
    for (const p of own) expect(named.has(p), p).toBe(true);
    expect(r.frame().labels.some((l) => l.text.includes(" ports"))).toBe(false);
  });
});

describe("the port labels", () => {
  it("draw a label beside a socket at the point the overlap check placed it", () => {
    const t = estate({ sites: 1, devices: 6, ports: 8 });
    const r = load(t, ["block:s0:campus"]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d1" });
    const p = r.scene.layout.get("dev:s0d1")!;
    r.setCamera({ u: p.u + p.w / 2, v: p.v + p.h / 2, zoom: PORT_LABEL_ZOOM }, vp);
    const labels = r.frame().labels.filter((l) => l.kind === "port");
    expect(labels.length).toBeGreaterThan(0);
    for (const l of labels) {
      const [x, y] = toScreen(r.camera, r.viewport, l.at[0], l.at[2], l.at[1]);
      expect(Math.abs(x - l.x), l.uid).toBeLessThan(0.5);
      expect(Math.abs(y - l.y), l.uid).toBeLessThan(0.5);
    }
  });
});

describe("the 2D view", () => {
  it("maps the plane straight down and fits a rectangle", () => {
    const cam = { u: 10, v: 20, zoom: 4, view: "top" as const };
    const [x, y] = toScreen(cam, vp, 15, 18);
    expect([x, y]).toEqual([600 + 20, 400 - 8]);
    expect(toPlane(cam, vp, x, y)).toEqual([15, 18]);
    const f = fit({ u0: 0, v0: 0, u1: 100, v1: 50 }, vp, "top");
    expect(f.view).toBe("top");
    expect(f.zoom).toBeCloseTo(0.9 * Math.min(1200 / 100, 800 / 50));
  });
});
