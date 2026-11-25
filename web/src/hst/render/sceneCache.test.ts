import { describe, expect, it } from "vitest";
import { base, estate, type Tables } from "../test/estate";
import { zoomOf } from "./camera";
import { createNullRenderer, type NullRenderer } from "./null";
import { DEFAULT_STYLE, type TableName } from "./types";
import { wire, type CableEnds, type Footprint, type PortEnd } from "./wiring";

const UNTILED: TableName[] = ["render_t0", "render_t1", "render_t1_edges", "render_t1_contexts", "context_identity"];

function load(t: Tables): NullRenderer {
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of UNTILED) r.setTier(name, t[name]);
  return r;
}

describe("what a change of the scene redraws", () => {
  const t = estate({ sites: 3, devices: 12, ports: 4 });

  it("keeps the batches, the derived data and the wiring when only the hovered device changes", () => {
    const r = load(t);
    const scene = r.scene;
    const batches = scene.batches(3);
    const wiring = scene.wiring();
    const version = scene.version;
    scene.setStyle({ ...scene.style, hovered: "dev:s0d1" });
    scene.setStyle({ ...scene.style, hovered: "dev:s0d2" });
    scene.setStyle({ ...scene.style, hovered: null });
    expect(scene.version).toBe(version);
    expect(scene.batches(3)).toBe(batches);
    expect(scene.wiring()).toBe(wiring);
  });

  it("still ranks the hovered device in the labels", () => {
    const r = load(t);
    const p = r.scene.layout.get("dev:s0d5")!;
    r.setCamera({ u: p.u + p.w / 2, v: p.v + p.h / 2, zoom: zoomOf(3) * 1.2 }, { width: 1200, height: 800 });
    const names = (hovered: string | null) => {
      r.scene.setStyle({ ...r.scene.style, hovered });
      return r.scene.labels(r.camera, r.viewport, 3).filter((l) => l.kind === "device").map((l) => l.uid);
    };
    const level3 = names(null);
    expect(level3.length).toBeGreaterThan(0);
    const last = level3[level3.length - 1];
    expect(names(last)[0]).toBe(last);
  });

  it("redraws the batches and the wiring when the selection changes", () => {
    const r = load(t);
    const scene = r.scene;
    const batches = scene.batches(3);
    const wiring = scene.wiring();
    scene.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d1" });
    expect(scene.batches(3)).not.toBe(batches);
    expect(scene.wiring()).not.toBe(wiring);
  });

  it("keeps the wiring when only a style that it does not read changes", () => {
    const r = load(t);
    const scene = r.scene;
    const wiring = scene.wiring();
    const dataVersion = scene.dataVersion;
    scene.setStyle({ ...scene.style, changes: true });
    expect(scene.wiring()).toBe(wiring);
    expect(scene.dataVersion).toBe(dataVersion);
  });

  it("keeps the batches when the routes change", () => {
    const r = load(t);
    const scene = r.scene;
    const batches = scene.batches(3);
    scene.setRoutes([]);
    expect(scene.batches(3)).toBe(batches);
  });

  it("derives again when the data changes", () => {
    const r = load(t);
    const scene = r.scene;
    const wiring = scene.wiring();
    const dataVersion = scene.dataVersion;
    r.applyDelta("render_t1", [{ key: "dev:s0d0", row: { ...t.render_t1[0], label: "renamed" } }]);
    expect(scene.dataVersion).toBe(dataVersion + 1);
    expect(scene.wiring()).not.toBe(wiring);
  });

  it("reads the plate of a site from the layout, and again after the plate moves", () => {
    const r = load(t);
    const plate = r.scene.layout.get("plate:s1")!;
    expect(r.scene.glyphOf("site:s1")).toEqual([plate.u + plate.w - 2, plate.v + 2]);
    const row = base(t).find((x) => x.uid === "plate:s1")!;
    r.applyDelta("layout", [{ key: "plate:s1", row: { ...row, u: 900 } }]);
    expect(r.scene.glyphOf("site:s1")).toEqual([900 + plate.w - 2, plate.v + 2]);
    expect(r.scene.glyphOf("site:none")).toBeNull();
  });
});

function footprint(uid: string, u: number, v: number, area: string): Footprint {
  return { uid, u, v, w: 4, h: 3, cu: u + 2, cv: v + 1.5, hw: 1.88, hh: 1.38, round: false, area };
}

describe("the channel width of the cable routes", () => {
  it("is set by the devices of one area, not by a device of another area that faces them", () => {
    const devices = new Map([
      ["hub", footprint("hub", 0, 0, "x")],
      ["sw0", footprint("sw0", 0, 7, "x")],
      ["sw", footprint("sw", 8, 7, "x")],
      // another site's device in the same columns, half a cell from the hub
      ["far", footprint("far", 0, 3.5, "y")],
    ]);
    const ports: PortEnd[] = [
      { uid: "hub/0", device: "hub", side: null, slot: 0 },
      { uid: "sw/0", device: "sw", side: null, slot: 0 },
    ];
    const cables: CableEnds[] = [{ key: "sw~hub", a: "sw/0", b: "hub/0" }];
    const points = wire(devices, ports, cables).routes.get("sw~hub")!;
    // the gap between the hub and sw0 is 4, so the channel runs 2 below the hub
    expect(points).toHaveLength(4);
    expect(points[1][1]).toBeCloseTo(5);
    expect(points[2][1]).toBeCloseTo(5);
  });
});
