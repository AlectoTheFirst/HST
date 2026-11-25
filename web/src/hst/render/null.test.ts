import { describe, expect, it } from "vitest";
import { estate, base, tile, type Tables } from "../test/estate";
import { fit, toScreen, zoomOf } from "./camera";
import { portGroups } from "../data/portGroups";
import { createNullRenderer, type NullRenderer } from "./null";
import { CONTEXT_CAP, LABEL_BUDGET, PALETTE, PORT_LABEL_ZOOM, Y, keyDevice, labelBox, rgb } from "./scene";
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
  }
  return r;
}

function at(r: NullRenderer, level: Level, focus?: string): void {
  const where = focus ? center(r, focus) : fit(r.scene.bounds(), vp);
  r.setCamera({ u: where.u, v: where.v, zoom: level === 1 ? 1 : zoomOf(level) * 1.2 }, vp);
}

function center(r: NullRenderer, uid: string): { u: number; v: number } {
  const p = r.scene.layout.get(uid)!;
  return { u: p.u + p.w / 2, v: p.v + p.h / 2 };
}

function batch(r: NullRenderer, cls: string): { ids: string[]; colors: number[] } {
  const level = r.frame().level;
  return r.scene.batches(level).boxes.find((b) => b.cls === cls) ?? { ids: [], colors: [] };
}

function colorOf(r: NullRenderer, cls: string, uid: string): number[] {
  const b = batch(r, cls);
  const i = b.ids.indexOf(uid);
  return b.colors.slice(i * 3, i * 3 + 3);
}

describe("the renderer against the null backend", () => {
  const t = estate({ sites: 3, devices: 12, ports: 4 });

  it("draws site plates and inter-site lines at estate zoom, with site names that never overlap", () => {
    const r = load(t);
    at(r, 1);
    const f = r.frame();
    expect(f.level).toBe(1);
    expect(batch(r, "plate").ids).toEqual(["plate:s0", "plate:s1", "plate:s2"]);
    expect(batch(r, "device").ids).toEqual([]);
    // A link between two sites draws while one of them is selected.
    expect(r.scene.batches(1).lines.map((l) => l.cls)).not.toContain("site-link");
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    expect(r.scene.batches(1).lines.map((l) => l.cls)).toContain("site-link");
    r.setStyle(DEFAULT_STYLE);
    const names = r.scene.batches(1).texts.filter((x) => x.strong);
    expect(names.map((x) => x.text).sort()).toEqual(["s0", "s1", "s2"]);
    for (const x of names) {
      const plate = r.scene.layout.get(x.id.replace("name:site:", "plate:"))!;
      expect(x.v - x.size).toBeGreaterThanOrEqual(plate.v + plate.h);
    }
    expect(f.labels.filter((l) => l.kind === "site")).toEqual([]);
    expect(f.drawCalls).toBeLessThanOrEqual(10);
  });

  it("paints the name of every site on the ground, a hub site with a device of the hub role too", () => {
    const big = estate({ sites: 40, devices: 40, ports: 0 });
    const hub = big.render_t1.find((row) => row.uid === "dev:s7d0");
    if (hub) hub.role = "sdwan-hub";
    const r = load(big);
    r.setCamera({ ...center(r, "dev:s20d20"), zoom: 1 }, { width: 6000, height: 4000 });
    const names = r.scene.batches(1).texts.filter((x) => x.strong).map((x) => x.id);
    expect(names).toHaveLength(40);
    expect(names).toContain("name:site:s7");
    expect(r.frame().labels.filter((l) => l.kind === "site")).toEqual([]);
  });

  it("adds the block bands at site zoom and the device boxes at device zoom", () => {
    const r = load(t);
    at(r, 2);
    expect(batch(r, "band").ids).toHaveLength(3);
    expect(r.scene.batches(2).texts.filter((x) => x.id.startsWith("name:block:"))).toHaveLength(3);
    at(r, 3);
    expect(batch(r, "device").ids).toHaveLength(36);
    expect(r.scene.batches(3).lines.find((l) => l.cls === "summary")?.ids.length).toBeGreaterThan(0);
  });

  it("draws ports and cables at port zoom for the loaded tiles only, one buffer per tile", () => {
    const r = load(t, ["block:s0:campus"]);
    r.setTier("render_t2_port_groups", portGroups(tile(t, "render_t2_ports", "block:s0:campus"), tile(t, "render_t2_cables", "block:s0:campus")), "block:s0:campus");
    at(r, 4, "dev:s0d5");
    // A cabled port draws as a dot where its cable ends; no port stud and no port group bar draws.
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d5" });
    const ends = new Set<string>();
    for (const c of r.scene.rows("render_t2_cables")) ends.add(String(c.a_port)).add(String(c.b_port));
    const dots = batch(r, "dot").ids.filter((id) => !id.startsWith("dot:"));
    expect(dots.length).toBeGreaterThan(0);
    expect(dots.filter((id) => !ends.has(id))).toEqual([]);
    expect(batch(r, "port").ids).toEqual([]);
    const cables = r.scene.batches(4).lines.filter((l) => l.cls === "cable");
    expect(cables.map((l) => l.key)).toEqual(["cable:block:s0:campus"]);
    r.dropTile("block:s0:campus");
    expect(batch(r, "dot").ids.filter((id) => !id.startsWith("dot:"))).toEqual([]);
  });

  it("names every device in view at block zoom, the selected and the hovered device first, within the label budget", () => {
    const big = load(estate({ sites: 1, devices: 900, ports: 0 }));
    big.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d450", hovered: "dev:s0d451" });
    big.setCamera({ ...center(big, "dev:s0d450"), zoom: zoomOf(3) }, { width: 4000, height: 3000 });
    const labels = big.frame().labels.filter((l) => l.kind === "device");
    expect(labels.length).toBeGreaterThan(0);
    expect(labels.length).toBeLessThanOrEqual(LABEL_BUDGET.device);
    const named = new Set(labels.map((l) => l.uid));
    expect(named.has("dev:s0d450") && named.has("dev:s0d451")).toBe(true);
    expect(labels.slice(0, 2).map((l) => l.uid)).toEqual(["dev:s0d450", "dev:s0d451"]);
    expect([...named].some((uid) => !keyDevice(big.scene.row("render_t1", uid)))).toBe(true);
  });

  it("labels the cabled ports of the selected device within the port budget, and none of its loose ports", () => {
    const wide = estate({ sites: 1, devices: 2, ports: 260 });
    const r = load(wide, ["block:s0:campus"]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    r.setCamera({ ...center(r, "dev:s0d0"), zoom: 60 }, { width: 40000, height: 40000 });
    const ports = r.frame().labels.filter((l) => l.kind === "port");
    const cabled = new Set<string>();
    for (const c of r.scene.rows("render_t2_cables")) cabled.add(String(c.a_port)).add(String(c.b_port));
    expect(ports.length).toBeGreaterThan(0);
    expect(ports.length).toBeLessThanOrEqual(LABEL_BUDGET.port);
    expect(ports.every((l) => cabled.has(l.uid))).toBe(true);
  });

  it("labels both ends of every cable at port zoom", () => {
    const r = load(t, ["block:s0:campus"]);
    r.setCamera({ ...center(r, "dev:s0d5"), zoom: 40 }, { width: 6000, height: 6000 });
    const shown = new Set(r.frame().labels.filter((l) => l.kind === "port").map((l) => l.uid));
    const ends = tile(t, "render_t2_cables", "block:s0:campus").flatMap((c) => [String(c.a_port), String(c.b_port)]);
    expect(ends.length).toBeGreaterThan(0);
    expect(ends.filter((e) => !shown.has(e))).toEqual([]);
  });

  it("places no port label over another label at any zoom", () => {
    const r = load(estate({ sites: 2, devices: 30, ports: 12 }), ["block:s0:campus", "block:s1:campus"]);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d7" });
    for (const zoom of [0.8, 2, 6, 15, 30]) {
      r.setCamera({ ...center(r, "dev:s0d7"), zoom }, vp);
      const labels = r.frame().labels;
      const ports = labels.filter((l) => l.kind === "port");
      if (zoom >= PORT_LABEL_ZOOM) expect(ports.length, `zoom ${zoom}`).toBeGreaterThan(0);
      else expect(ports.length, `zoom ${zoom}`).toBe(0);
      expect(ports.length).toBeLessThanOrEqual(LABEL_BUDGET.port);
      for (const p of ports) {
        const a = labelBox(p);
        for (const q of labels) {
          if (q === p) continue;
          const b = labelBox(q);
          expect(a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1, `${p.uid} over ${q.uid} at ${zoom}`).toBe(false);
        }
      }
    }
  });

  it("ghosts a removed device, keeps its slot and recolors a changed one", () => {
    const r = load(t);
    at(r, 3);
    const observed = colorOf(r, "device", "dev:s0d3");
    expect(observed).toEqual(rgb(PALETTE.observed));
    r.applyDelta("render_t1", [{ key: "dev:s0d3", row: null }]);
    expect(batch(r, "device").ids).toContain("dev:s0d3");
    expect(colorOf(r, "device", "dev:s0d3")).not.toEqual(observed);
    const row = t.render_t1.find((x) => x.uid === "dev:s0d4") as Row;
    r.applyDelta("render_t1", [{ key: "dev:s0d4", row: { ...row, status: "failed" } }]);
    expect(colorOf(r, "device", "dev:s0d4")).toEqual(rgb(PALETTE.failed));
    r.setStyle({ ...DEFAULT_STYLE, changes: true });
    r.applyDelta("render_t1", [{ key: "dev:s0d4", row: { ...row, change: "added" } }]);
    expect(colorOf(r, "device", "dev:s0d4")).toEqual(rgb(PALETTE.added));
  });

  it("moves a device when its layout row changes", () => {
    const r = load(t);
    const row = t.layout.find((x) => x.uid === "dev:s0d0") as Row;
    r.applyDelta("layout", [{ key: "dev:s0d0", row: { ...row, u: 500 } }]);
    expect(r.scene.layout.get("dev:s0d0")?.u).toBe(500);
    r.applyDelta("layout", [{ key: "dev:s0d0", row: null }]);
    expect(r.scene.layout.has("dev:s0d0")).toBe(false);
  });

  it("picks the device under the pointer at device zoom and the plate at estate zoom", () => {
    const r = load(t);
    at(r, 3, "dev:s1d7");
    const c = center(r, "dev:s1d7");
    const [x, y] = toScreen(r.camera, r.viewport, c.u, c.v, Y.deviceTop);
    expect(r.pick(x, y)).toBe("dev:s1d7");
    at(r, 1);
    const p = center(r, "plate:s2");
    const [px, py] = toScreen(r.camera, r.viewport, p.u, p.v, Y.plateTop);
    expect(r.pick(px, py)).toBe("plate:s2");
    expect(r.pick(-50, -50)).toBeNull();
  });

  it("draws the route as one more draw call", () => {
    const r = load(t);
    at(r, 3);
    const before = r.frame().drawCalls;
    r.setRoutes([
      {
        id: "trace",
        state: "trace",
        points: [
          { u: 0, v: 0 },
          { u: 30, v: 20 },
        ],
      },
    ]);
    expect(r.frame().drawCalls).toBe(before + 1);
  });

  it("hides the sites without the selected context and ghosts the chassis outside it", () => {
    const r = load(t);
    at(r, 3);
    r.setStyle({ ...DEFAULT_STYLE, context: "ident:blue:s0" });
    expect(batch(r, "plate").ids).toEqual(["plate:s0"]);
    expect(colorOf(r, "device", "dev:s0d1")).not.toEqual(rgb(PALETTE.observed));
    expect(colorOf(r, "device", "dev:s0d2")).toEqual(rgb(PALETTE.observed));
  });

  it("opens a chassis into its context tiers at port zoom and caps them", () => {
    const r = load(t, ["block:s0:campus"]);
    at(r, 4, "dev:s0d0");
    expect(batch(r, "context").ids).toEqual(expect.arrayContaining(["vrf:dev:s0d0:default", "vrf:dev:s0d0:blue"]));
    expect(batch(r, "device").ids).toContain("dev:s0d1");
    const many = Array.from({ length: CONTEXT_CAP + 4 }, (_, i) => ({
      uid: `vrf:x${i}`,
      device_uid: "dev:s0d1",
      tile: "block:s0:campus",
      name: `v${i}`,
      order: i,
    }));
    r.setTier("render_t2_contexts", [...tile(t, "render_t2_contexts", "block:s0:campus"), ...many], "block:s0:campus");
    const tiers = r.scene.contextTiers("dev:s0d1");
    expect(tiers).toHaveLength(CONTEXT_CAP);
    expect(tiers[tiers.length - 1].name).toBe("+6");
    r.setStyle({ ...DEFAULT_STYLE, context: "ident:blue:s0" });
    expect(r.scene.contextTiers("dev:s0d0").map((x) => x.uid)).toEqual(["vrf:dev:s0d0:blue"]);
  });

  it("draws tunnels as site badges at estate and site zoom, spokes for the selected site, arcs for the selected device", () => {
    const r = load(t);
    at(r, 1);
    r.frame();
    expect(batch(r, "glyph").ids.sort()).toEqual(["glyph:site:s0", "glyph:site:s1"]);
    expect(r.scene.batches(1).lines.find((l) => l.cls === "tunnel")).toBeUndefined();
    at(r, 2);
    expect(r.scene.batches(2).lines.find((l) => l.cls === "tunnel")).toBeUndefined();
    expect(r.frame().labels.filter((l) => l.kind === "tunnel")).toEqual([]);
    expect(r.scene.tunnelLine("site:s0")).toBe("3 tunnels");
    expect(r.scene.tunnelLine("site:s2")).toBeNull();
    for (const card of r.frame().labels.filter((l) => l.kind === "site" && l.uid === "site:s0")) expect(card.sub).toContain("3 tunnels");
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    const spokes = r.scene.batches(2).lines.find((l) => l.cls === "tunnel")!;
    // A spoke is a dashed arc of many segments with one id.
    expect([...new Set(spokes.ids)]).toEqual(["tunnel:site:s0|site:s1"]);
    const spoke = r.frame().labels.find((l) => l.uid === "tunnel:site:s0|site:s1");
    if (spoke) expect(spoke.text).toBe("3");
    at(r, 3, "dev:s0d0");
    r.setStyle(DEFAULT_STYLE);
    expect(r.scene.batches(3).lines.find((l) => l.cls === "tunnel")).toBeUndefined();
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    const arc = r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!;
    const single = arc.ids.length;
    expect(r.frame().labels.find((l) => l.uid === "dev:s0d0|dev:s1d0")?.text).toBe("3");
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0", transports: new Map([["dev:s0d0|dev:s1d0", [{ encap: "ipsec", count: 2 }, { encap: "gre", count: 1 }]]]) });
    expect(r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!.ids).toHaveLength(2 * single);
    expect(r.frame().labels.find((l) => l.uid === "dev:s0d0|dev:s1d0")?.text).toBe("ipsec 2, gre 1");
  });

  it("names a hub site by its spoke count and draws no spoke until the site is chosen", () => {
    const big = estate({ sites: 6, devices: 12, ports: 0 });
    for (let k = 1; k < 6; k++) {
      big.render_t1_edges.push({ pair_id: `dev:s0d0|dev:s${k}d0`, a_uid: "dev:s0d0", b_uid: `dev:s${k}d0`, cable_count: 0, lag_count: 0, tunnel_count: 4 });
    }
    const hub = big.render_t1.find((row) => row.uid === "dev:s0d0");
    if (hub) hub.role = "sdwan-hub";
    const r = load(big);
    at(r, 1);
    expect(r.scene.batches(1).lines.find((l) => l.cls === "tunnel")).toBeUndefined();
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s3" });
    expect([...new Set(r.scene.batches(1).lines.find((l) => l.cls === "tunnel")!.ids)]).toEqual(["tunnel:site:s0|site:s3"]);
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    expect(new Set(r.scene.batches(1).lines.find((l) => l.cls === "tunnel")!.ids).size).toBe(5);
    expect(r.scene.tunnelLine("site:s0")).toBe("hub of 5 sites, 20 tunnels");
    expect(r.scene.tunnelLine("site:s3")).toBe("4 tunnels");
  });

  it("highlights the selected device and dims the devices that are not its neighbors", () => {
    const r = load(t);
    at(r, 3);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d3" });
    expect(colorOf(r, "device", "dev:s0d3")).toEqual(rgb(PALETTE.selected));
    expect(colorOf(r, "device", "dev:s0d4")).toEqual(rgb(PALETTE.observed));
    expect(colorOf(r, "device", "dev:s0d9")).not.toEqual(rgb(PALETTE.observed));
  });

  it("filters the physical layer and the tunnel overlay", () => {
    const r = load(t);
    at(r, 3);
    r.setStyle({ ...DEFAULT_STYLE, layers: { physical: false, l2: true, l3: false } });
    expect(r.scene.batches(3).lines).toEqual([]);
  });
});
