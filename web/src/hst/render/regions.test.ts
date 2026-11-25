import { describe, expect, it } from "vitest";
import { estate, base, tile, type Tables } from "../test/estate";
import { fit, toScreen, zoomOf } from "./camera";
import { panelOf } from "../panel/model";
import { createNullRenderer, type NullRenderer } from "./null";
import { ARC_STEPS, DASH_STEP_PX, NAME_PX, Y, labelBox } from "./scene";
import { DEFAULT_STYLE, type Label, type Level, type TableName } from "./types";

const vp = { width: 1200, height: 800 };
const UNTILED: TableName[] = ["render_t0", "render_t1", "render_t1_edges", "render_t1_contexts", "context_identity"];

function load(t: Tables): NullRenderer {
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of UNTILED) r.setTier(name, t[name]);
  return r;
}

function at(r: NullRenderer, level: Level, uid?: string, zoom = level === 1 ? 1 : zoomOf(level) * 1.2): void {
  const p = uid ? r.scene.layout.get(uid)! : null;
  const where = p ? { u: p.u + p.w / 2, v: p.v + p.h / 2 } : fit(r.scene.bounds(), vp);
  r.setCamera({ u: where.u, v: where.v, zoom }, vp);
}

function apart(a: Label, b: Label): boolean {
  const p = labelBox(a);
  const q = labelBox(b);
  return p.x1 <= q.x0 || q.x1 <= p.x0 || p.y1 <= q.y0 || q.y1 <= p.y0;
}

function tunnel(t: Tables, a: number, b: number, n: number): void {
  const [da, db] = [`dev:s${a}d0`, `dev:s${b}d0`];
  t.render_t1_edges.push({ pair_id: `${da}|${db}`, a_uid: da, b_uid: db, cable_count: 0, lag_count: 0, tunnel_count: n, change: "none" });
}

/** Six one-device SD-WAN sites in a row: s0 to s2 in the block FR, s3 to s5 in DE; s0 and s3 hold a hub device. */
function sdwan(): Tables {
  const t = estate({ sites: 6, devices: 1, ports: 0 });
  t.render_t1_edges = [];
  for (const row of t.render_t1) {
    row.role = row.uid === "dev:s0d0" || row.uid === "dev:s3d0" ? "sdwan-hub" : "sdwan-edge";
    row.tier = row.role;
  }
  t.render_t0 = t.render_t0.map((x) =>
    x.kind === "block" ? { ...x, block_kind: "wan-edge", label: "WAN edge", device_count: 1 } : x,
  );
  for (const [slot, region, sites] of [[0, "region:FR", [0, 1, 2]], [1, "region:DE", [3, 4, 5]]] as const) {
    const rows = t.layout.filter((r) => r.kind === "site" && sites.some((s) => r.uid === `site:s${s}`));
    for (const r of rows) r.parent_uid = region;
    const u = Math.min(...rows.map((r) => Number(r.u))) - 2;
    const v = Math.min(...rows.map((r) => Number(r.v))) - 2;
    const w = Math.max(...rows.map((r) => Number(r.u) + Number(r.w))) + 2 - u;
    const h = Math.max(...rows.map((r) => Number(r.v) + Number(r.h))) + 2 - v;
    t.layout.push({ uid: region, kind: "region", parent_uid: null, u, v, w, h, slot });
  }
  tunnel(t, 0, 1, 2);
  tunnel(t, 0, 2, 2);
  tunnel(t, 0, 3, 2);
  tunnel(t, 0, 4, 2);
  tunnel(t, 1, 5, 2);
  return t;
}

/** Five one-device sites far apart: s1 and s2 in the core block, s3 in the cloud block, s0 in FR and s4 in DE; s0 and
 *  s1 hold a hub device. */
function backbone(): Tables {
  const t = estate({ sites: 5, devices: 1, ports: 0 });
  t.render_t1_edges = [];
  for (const row of t.render_t1) {
    row.role = row.uid === "dev:s0d0" || row.uid === "dev:s1d0" ? "sdwan-hub" : "sdwan-edge";
    row.tier = row.role;
  }
  for (const row of t.layout) {
    const site = /s(\d+)/.exec(String(row.uid));
    if (site) row.u = Number(row.u) + 120 * Number(site[1]);
  }
  const blocks = [[0, "region:core", [1, 2]], [1, "region:cloud", [3]], [2, "region:FR", [0]], [3, "region:DE", [4]]] as const;
  for (const [slot, region, sites] of blocks) {
    const rows = t.layout.filter((r) => r.kind === "site" && sites.some((s) => r.uid === `site:s${s}`));
    for (const r of rows) r.parent_uid = region;
    const u = Math.min(...rows.map((r) => Number(r.u))) - 40;
    const v = Math.min(...rows.map((r) => Number(r.v))) - 40;
    const w = Math.max(...rows.map((r) => Number(r.u) + Number(r.w))) + 40 - u;
    const h = Math.max(...rows.map((r) => Number(r.v) + Number(r.h))) + 40 - v;
    t.layout.push({ uid: region, kind: "region", parent_uid: null, u, v, w, h, slot });
  }
  return t;
}

describe("the country blocks on the map", () => {
  it("draw each block as an area under its sites and paint its name on the ground at estate zoom", () => {
    const r = load(sdwan());
    at(r, 1);
    const { areas, texts } = r.scene.batches(1);
    expect(areas.ids.slice(0, 2)).toEqual(["region:FR", "region:DE"]);
    expect(areas.kinds.slice(0, 2)).toEqual([2, 2]);
    expect(areas.ids.indexOf("plate:s0")).toBeGreaterThan(1);
    expect(texts.filter((x) => x.id.startsWith("name:region:")).map((x) => x.text)).toEqual(["FR", "DE"]);
    expect(r.frame().labels.filter((l) => l.kind === "region")).toEqual([]);
  });

  it("paint the name of a one-device site on the ground, open no card on hover, and name its device at block zoom", () => {
    const r = load(sdwan());
    at(r, 2);
    expect(r.scene.batches(2).texts.find((x) => x.id === "name:site:s1")?.text).toBe("s1");
    expect(r.frame().labels.filter((l) => l.kind === "site" || l.kind === "block")).toEqual([]);
    r.setStyle({ ...DEFAULT_STYLE, hovered: "dev:s1d0" });
    at(r, 2, "site:s1");
    expect(r.frame().labels.find((l) => l.uid === "block:s1:campus")).toBeUndefined();
    // At block zoom the hostname of the device stands for a one-device site.
    r.setStyle(DEFAULT_STYLE);
    at(r, 3, "dev:s1d0", zoomOf(3) * 2.6);
    const block = r.frame().labels;
    expect(block.find((l) => l.uid === "block:s1:campus")).toBeUndefined();
    expect(block.find((l) => l.uid === "dev:s1d0")).toMatchObject({ kind: "device", text: "s1d0" });
  });

  it("draw an SD-WAN edge as a model at site zoom, with no cluster badge on its block", () => {
    const r = load(sdwan());
    at(r, 2);
    expect(r.scene.batches(2).models.flatMap((m) => m.ids)).toContain("dev:s1d0");
    expect(r.frame().labels.filter((l) => l.kind === "cluster")).toEqual([]);
  });

  it("put no cluster badge under a card", () => {
    const r = load(estate({ sites: 3, devices: 12, ports: 0 }));
    at(r, 2);
    const labels = r.frame().labels;
    const badges = labels.filter((l) => l.kind === "cluster");
    expect(badges.length).toBeGreaterThan(0);
    for (const badge of badges) for (const c of labels.filter((l) => l.sub !== undefined)) expect(apart(badge, c)).toBe(true);
  });

  it("bundle the tunnels of a site to another block, light the own block of a hub, and draw a spoke to each site of its own block and to a lone far site", () => {
    const r = load(sdwan());
    const far = (pairs: [string, number][]) => ({ total: 0, far: new Map(pairs) });
    const hub = r.scene.siteSpokes("site:s0", far([["site:s1", 2], ["site:s2", 2], ["site:s3", 2], ["site:s4", 2]]));
    // s0 is a hub: its own block FR glows with the count in place of its spokes.
    expect(hub.map((s) => [s.id, s.sites, s.tunnels, s.local ?? null])).toEqual([
      ["tunnel:site:s0|region:FR", 2, 4, "region:FR"],
      ["tunnel:site:s0|region:DE", 2, 4, null],
    ]);
    const de = r.scene.layout.get("region:DE")!;
    expect(hub[1].to).toEqual([de.u + de.w / 2, de.v + de.h / 2]);
    const spoke = r.scene.siteSpokes("site:s1", far([["site:s0", 2], ["site:s5", 2]]));
    expect(spoke.map((s) => s.id)).toEqual(["tunnel:site:s0|site:s1", "tunnel:site:s1|site:s5"]);
    at(r, 2);
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    const lines = r.scene.batches(2).lines.find((l) => l.cls === "tunnel")!;
    expect([...new Set(lines.ids)].sort()).toEqual(["tunnel:site:s0|region:DE"]);
    const count = r.frame().labels.find((l) => l.uid === "tunnel:site:s0|region:DE");
    if (count) expect(count.text).toBe("2 sites, 4 tunnels");
  });

  it("name at estate zoom only the hub sites of a country block, and give only them a tunnel glyph", () => {
    const r = load(sdwan());
    at(r, 1);
    const names = r.frame().labels.filter((l) => l.kind === "site").map((l) => l.uid);
    expect(names.every((uid) => uid === "site:s0" || uid === "site:s3")).toBe(true);
    const glyphs = r.scene.batches(1).boxes.find((b) => b.cls === "glyph")?.ids ?? [];
    expect([...glyphs].sort()).toEqual(["glyph:site:s0", "glyph:site:s3"]);
  });

  it("draw the tunnel spokes of a site at site zoom as arcs above the glyphs", () => {
    const r = load(sdwan());
    at(r, 2);
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s1" });
    const arcs = r.scene.batches(2).lines.find((l) => l.cls === "tunnel")!;
    const heights = arcs.positions.filter((_, i) => i % 3 === 1);
    expect(Math.min(...heights)).toBeGreaterThanOrEqual(Y.glyph);
    expect(Math.max(...heights)).toBeGreaterThan(Y.glyph + 3);
  });

  it("end a link to another site in a stub named by the far site, and draw no line to the Unassigned plate", () => {
    const t = sdwan();
    t.layout.push(
      { uid: "site:unassigned", kind: "site", parent_uid: null, u: 200, v: 0, w: 10, h: 15, slot: -1 },
      { uid: "plate:unassigned", kind: "plate", parent_uid: "site:unassigned", u: 200, v: 0, w: 10, h: 15 },
      { uid: "block:unassigned:router", kind: "block", parent_uid: "plate:unassigned", u: 202, v: 6, w: 6, h: 5 },
      { uid: "dev:u0", kind: "device", parent_uid: "block:unassigned:router", u: 203, v: 7, w: 4, h: 3 },
    );
    t.render_t1.push({ uid: "dev:u0", site_uid: null, block_uid: "block:unassigned:router", label: "u0", role: "router", tier: "core", status: "observed", change: "none" });
    for (const [b, id] of [["dev:s5d0", "dev:s0d0|dev:s5d0"], ["dev:u0", "dev:s0d0|dev:u0"]]) {
      t.render_t1_edges.push({ pair_id: id, a_uid: "dev:s0d0", b_uid: b, cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
    }
    const r = load(t);
    at(r, 1);
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    const links = r.scene.batches(1).lines.filter((l) => l.cls === "site-link").flatMap((l) => l.ids);
    expect(new Set(links)).toEqual(new Set(["site:s0|site:s5"]));
    at(r, 3, "dev:s0d0", zoomOf(3) * 2.6);
    const summary = r.scene.batches(3).lines.filter((l) => l.cls === "summary");
    const stubs = summary.flatMap((l) =>
      l.ids.flatMap((id, i) => (id === "dev:s0d0|dev:s5d0" ? [l.positions.slice(i * 6, i * 6 + 6)] : [])),
    );
    expect(stubs).toHaveLength(2);
    for (const [u0, , v0, u1, , v1] of stubs) expect(Math.hypot(u1 - u0, v1 - v0)).toBeLessThan(10);
    // One label names the far sites of the stubs of one device and direction; port zoom draws no block card over it.
    at(r, 4, "dev:s0d0", 20);
    expect(r.frame().labels.find((l) => l.uid === "stub:dev:s0d0:1:0")?.text).toBe("to s5, Unassigned");
  });

  it("light the own block of a selected hub device in place of its spokes, and bundle the other blocks", () => {
    const t = sdwan();
    tunnel(t, 3, 4, 2);
    tunnel(t, 3, 5, 2);
    const r = load(t);
    at(r, 3, "dev:s0d0");
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    const lines = r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!;
    expect([...new Set(lines.ids)].sort()).toEqual(["tunnel:dev:s0d0|region:DE"]);
    const { areas } = r.scene.batches(3);
    expect(areas.selected[areas.ids.indexOf("region:FR")]).toBe(1);
    expect(areas.selected[areas.ids.indexOf("region:DE")]).toBe(0);
    const own = r.frame().labels.find((l) => l.uid === "tunnel:dev:s0d0|region:FR");
    if (own) expect(own.text).toBe("2 sites in FR, 4 tunnels");
  });

  it("draw an arc from a selected branch device to each far device of its own block and to a lone far site", () => {
    const r = load(sdwan());
    at(r, 3, "dev:s1d0");
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s1d0" });
    const lines = r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!;
    expect([...new Set(lines.ids)].sort()).toEqual(["dev:s0d0|dev:s1d0", "dev:s1d0|dev:s5d0"]);
    expect(r.scene.batches(3).areas.selected.every((x) => x === 0)).toBe(true);
  });

  it("draw no tunnel line on hover, and open a clicked bundle in the panel with its far ends", () => {
    const r = load(sdwan());
    at(r, 3, "dev:s0d0");
    r.setStyle({ ...DEFAULT_STYLE, hovered: "dev:s0d0" });
    expect(r.scene.batches(3).lines.find((l) => l.cls === "tunnel")).toBeUndefined();
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    const lines = r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!;
    // A drawn segment near the top of the bundle arc, away from the device the arc starts at.
    const drawn = lines.ids.flatMap((id, k) => (id === "tunnel:dev:s0d0|region:DE" && lines.positions[k * 6] !== lines.positions[k * 6 + 3] ? [k] : []));
    const i = drawn[Math.floor(drawn.length / 2)];
    const [x0, y0] = toScreen(r.camera, r.viewport, lines.positions[i * 6], lines.positions[i * 6 + 2], lines.positions[i * 6 + 1]);
    const [x1, y1] = toScreen(r.camera, r.viewport, lines.positions[i * 6 + 3], lines.positions[i * 6 + 5], lines.positions[i * 6 + 4]);
    const hit = r.pick((x0 + x1) / 2, (y0 + y1) / 2);
    expect(hit).toBe("tunnel:dev:s0d0|region:DE");
    const panel = panelOf(r.scene, "dev:s0d0", null, hit);
    expect(panel).toMatchObject({ kind: "tunnel", title: "s0d0 to DE", subtitle: "2 far ends, 4 tunnels" });
    expect(panel?.tabs[0].items?.map((item) => [item.label, item.meta])).toEqual([
      ["s3d0", "2 tunnels"],
      ["s4d0", "2 tunnels"],
    ]);
  });

  it("draw the links of the selected device to other sites in full, as an arc", () => {
    const t = sdwan();
    t.render_t1_edges.push({ pair_id: "dev:s0d0|dev:s5d0", a_uid: "dev:s0d0", b_uid: "dev:s5d0", cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
    const r = load(t);
    at(r, 3, "dev:s0d0");
    const segments = () =>
      r.scene.batches(3).lines.filter((l) => l.cls === "summary").flatMap((l) => l.ids.flatMap((id, k) => (id === "dev:s0d0|dev:s5d0" ? [l.positions.slice(k * 6, k * 6 + 6)] : [])));
    expect(segments()).toHaveLength(2);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    expect(segments()).toHaveLength(ARC_STEPS);
    expect(Math.max(...segments().map((s) => s[1]))).toBeGreaterThan(Y.summary + 3);
  });

  it("draw the circuits of the selection as arcs, and open a picked circuit line in the panel", () => {
    const t = sdwan();
    t.render_t1_circuits.push({
      uid: "vc:1", name: "c1", type: "EVPL", state: "ACTIVE", bandwidth_mbps: 500, provider: null, family: null,
      a_device: "dev:s0d0", a_port: null, a_vlan: "100", z_device: "dev:s4d0", z_port: null, z_vlan: "200", cable_id: null,
    });
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    at(r, 3, "dev:s0d0");
    const circuits = () => r.scene.batches(3).lines.find((l) => l.cls === "circuit");
    expect(circuits()).toBeUndefined();
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    expect([...new Set(circuits()!.ids)]).toEqual(["circuit:dev:s0d0|dev:s4d0"]);
    const panel = panelOf(r.scene, "dev:s0d0", null, "circuit:dev:s0d0|dev:s4d0");
    expect(panel).toMatchObject({ kind: "circuit", title: "s0d0 to s4d0", subtitle: "1 circuit" });
    expect(panel?.tabs[0].items?.[0]).toMatchObject({ label: "c1", meta: "EVPL, 500 Mbps, ACTIVE, VLAN 100 / 200" });
    expect(panelOf(r.scene, "dev:s0d0", null)?.tabs.find((tab) => tab.name === "Circuits")?.items).toHaveLength(1);
    at(r, 2);
    r.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    expect([...new Set(r.scene.batches(2).lines.find((l) => l.cls === "circuit")!.ids)]).toEqual(["circuit:site:s0|site:s4"]);
  });

  it("dash a short and a long tunnel arc with the same dash length", () => {
    const t = estate({ sites: 6, devices: 1, ports: 0 });
    t.render_t1_edges = [];
    tunnel(t, 0, 1, 1);
    tunnel(t, 0, 5, 1);
    const r = load(t);
    at(r, 3, "dev:s0d0");
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    const arcs = r.scene.batches(3).lines.find((l) => l.cls === "tunnel")!;
    const step = DASH_STEP_PX / zoomOf(3);
    const runs = (id: string) => {
      const out: number[] = [];
      let run = 0;
      arcs.ids.forEach((x, i) => {
        if (x !== id) return;
        const [u0, , v0, u1, , v1] = arcs.positions.slice(i * 6, i * 6 + 6);
        const len = Math.hypot(u1 - u0, v1 - v0);
        if (len > 0) run += len;
        else if (run > 0) {
          out.push(run);
          run = 0;
        }
      });
      return out;
    };
    expect(arcs.ids.filter((x) => x === "dev:s0d0|dev:s1d0")).toHaveLength(ARC_STEPS);
    expect(arcs.ids.filter((x) => x === "dev:s0d0|dev:s5d0").length).toBeGreaterThan(ARC_STEPS);
    // The default dash draws 4 steps and leaves out 2.
    for (const id of ["dev:s0d0|dev:s1d0", "dev:s0d0|dev:s5d0"]) {
      const dashes = runs(id);
      expect(dashes.length).toBeGreaterThan(1);
      for (const dash of dashes) expect(Math.abs(dash - 4 * step)).toBeLessThanOrEqual(0.5 * step);
    }
  });
});

describe("the core block on the map", () => {
  it("paints the names of the core and cloud blocks and of their sites on the ground", () => {
    const r = load(backbone());
    at(r, 1, undefined, 1.4);
    const texts = new Map(r.scene.batches(1).texts.map((x) => [x.id, x.text]));
    expect(texts.get("name:region:core")).toBe("Core");
    expect(texts.get("name:region:cloud")).toBe("Cloud");
    for (const site of ["s1", "s2", "s3"]) expect(texts.get(`name:site:${site}`)).toBe(site);
    expect(r.frame().labels.filter((l) => l.kind === "site" || l.kind === "region")).toEqual([]);
  });

  it("draws the backbone links and circuits with no selection, and no other site link or circuit", () => {
    const t = backbone();
    for (const [a, b] of [["dev:s1d0", "dev:s2d0"], ["dev:s0d0", "dev:s4d0"]]) {
      t.render_t1_edges.push({ pair_id: `${a}|${b}`, a_uid: a, b_uid: b, cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
    }
    for (const [uid, a, z] of [["vc:1", "dev:s1d0", "dev:s3d0"], ["vc:2", "dev:s0d0", "dev:s4d0"]]) {
      t.render_t1_circuits.push({
        uid, name: uid, type: "EVPL", state: "ACTIVE", bandwidth_mbps: 500, provider: null, family: null,
        a_device: a, a_port: null, a_vlan: null, z_device: z, z_port: null, z_vlan: null, cable_id: null,
      });
    }
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    at(r, 1, undefined, 1.4);
    const lines = (cls: string) => [...new Set(r.scene.batches(1).lines.filter((l) => l.cls === cls).flatMap((l) => l.ids))];
    expect(lines("site-link")).toEqual(["site:s1|site:s2"]);
    expect(lines("circuit")).toEqual(["circuit:site:s1|site:s3"]);
  });

  it("draws the backbone as one line per site pair at block zoom, and the links to other sites as stubs", () => {
    const t = backbone();
    for (const [a, b] of [["dev:s1d0", "dev:s2d0"], ["dev:s0d0", "dev:s4d0"]]) {
      t.render_t1_edges.push({ pair_id: `${a}|${b}`, a_uid: a, b_uid: b, cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
    }
    for (const [uid, a, z] of [["vc:1", "dev:s1d0", "dev:s3d0"], ["vc:2", "dev:s0d0", "dev:s4d0"]]) {
      t.render_t1_circuits.push({
        uid, name: uid, type: "EVPL", state: "ACTIVE", bandwidth_mbps: 500, provider: null, family: null,
        a_device: a, a_port: null, a_vlan: null, z_device: z, z_port: null, z_vlan: null, cable_id: null,
      });
    }
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    at(r, 3, "dev:s1d0");
    const lines = r.scene.batches(3).lines;
    const segments = (cls: string, id: string) =>
      lines.filter((l) => l.cls === cls).flatMap((l) => l.ids).filter((x) => x === id).length;
    expect(segments("site-link", "site:s1|site:s2")).toBeGreaterThan(0);
    expect(segments("site-link", "site:s0|site:s4")).toBe(0);
    for (const pair of ["dev:s1d0|dev:s2d0", "dev:s0d0|dev:s4d0"]) {
      expect(segments("summary", pair), pair).toBeGreaterThan(0);
      expect(segments("summary", pair), pair).toBeLessThan(ARC_STEPS);
    }
    expect(segments("circuit", "circuit:site:s1|site:s3")).toBe(ARC_STEPS);
    expect(segments("circuit", "circuit:dev:s1d0|dev:s3d0")).toBe(0);
    expect(segments("circuit", "circuit:site:s0|site:s4")).toBe(0);
  });
});

describe("the lines between sites", () => {
  it("keep a site link and a backbone circuit line in one form at every zoom", () => {
    const t = backbone();
    t.render_t1_edges.push({ pair_id: "dev:s1d0|dev:s2d0", a_uid: "dev:s1d0", b_uid: "dev:s2d0", cable_count: 1, lag_count: 0, tunnel_count: 0, change: "none" });
    t.render_t1_circuits.push({
      uid: "vc:1", name: "vc:1", type: "EVPL", state: "ACTIVE", bandwidth_mbps: 500, provider: null, family: null,
      a_device: "dev:s1d0", a_port: null, a_vlan: null, z_device: "dev:s3d0", z_port: null, z_vlan: null, cable_id: null,
    });
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    for (const level of [1, 2, 3, 4] as Level[]) {
      at(r, level, level >= 3 ? "dev:s1d0" : undefined);
      const lines = r.scene.batches(level).lines;
      const ids = (cls: string) => new Set(lines.filter((l) => l.cls === cls).flatMap((l) => l.ids));
      expect(ids("site-link").has("site:s1|site:s2"), `level ${level}`).toBe(true);
      expect(ids("circuit").has("circuit:site:s1|site:s3"), `level ${level}`).toBe(true);
    }
  });
});

describe("the ground names", () => {
  it("paint a box above its top edge, a site under its plate and a block in its margin, and leave no card", () => {
    const t = sdwan();
    // The site cell holds the annex rows under the plate, as the planner writes it.
    for (const row of t.layout) if (row.kind === "site") row.h = Number(row.h) + 10;
    const r = load(t);
    const texts = r.scene.batches(1).texts;
    const country = texts.find((x) => x.id === "name:region:FR")!;
    const box = r.scene.layout.get("region:FR")!;
    expect(country).toMatchObject({ text: "FR", strong: false, u: box.u });
    expect(country.v).toBeLessThan(box.v);
    const site = texts.find((x) => x.id === "name:site:s0")!;
    const plate = r.scene.layout.get("plate:s0")!;
    expect(site).toMatchObject({ text: "s0", strong: true });
    expect(site.v - site.size).toBeGreaterThanOrEqual(plate.v + plate.h);
    expect(texts.find((x) => x.id === "name:block:s0:campus")?.text).toBe("WAN edge");
    // A name shows while its letters are between the two pixel heights.
    const iso = Math.sqrt(1 / 2 + 1 / 6);
    for (const x of texts) {
      expect(x.size * iso * x.minZoom).toBeCloseTo(NAME_PX.min);
      expect(x.size * iso * x.maxZoom).toBeCloseTo(NAME_PX.max);
    }
    for (const level of [1, 2, 3] as Level[]) {
      at(r, level);
      const cards = r.frame().labels.filter((l) => l.kind === "region" || l.kind === "block" || l.kind === "site");
      expect(cards, `level ${level}`).toEqual([]);
    }
  });
});

/** A circuit from `a` to `z`, on the Fabric ports `ap` and `zp` when given. */
function circuit(t: Tables, uid: string, a: string, z: string, ap: string | null = null, zp: string | null = null): void {
  t.render_t1_circuits.push({
    uid, name: uid, type: "EVPL", state: "ACTIVE", bandwidth_mbps: 500, provider: null, family: null,
    a_device: a, a_port: ap, a_vlan: null, z_device: z, z_port: zp, z_vlan: null, cable_id: null,
  });
}

/** The start and the end of each arc of circuit line `id` at `level`, as [u, y, v]. */
function arcEnds(r: NullRenderer, level: Level, id: string): [number[], number[]][] {
  const segments = r.scene.batches(level).lines
    .filter((l) => l.cls === "circuit")
    .flatMap((l) => l.ids.flatMap((x, k) => (x === id ? [l.positions.slice(k * 6, k * 6 + 6)] : [])));
  expect(segments.length % ARC_STEPS, id).toBe(0);
  const out: [number[], number[]][] = [];
  for (let k = 0; k < segments.length; k += ARC_STEPS) out.push([segments[k].slice(0, 3), segments[k + ARC_STEPS - 1].slice(3, 6)]);
  return out;
}

function centre(r: NullRenderer, uid: string, y: number): number[] {
  const p = r.scene.layout.get(uid)!;
  return [p.u + p.w / 2, y, p.v + p.h / 2];
}

function close(actual: number[], expected: number[], what: string): void {
  expect(actual.length, what).toBe(expected.length);
  actual.forEach((x, i) => expect(x, `${what} [${i}]`).toBeCloseTo(expected[i], 6));
}

/** Two sites of two devices each in the core block: the backbone between them draws with no selection. */
function core(): Tables {
  const t = estate({ sites: 2, devices: 2, ports: 0 });
  t.render_t1_edges = [];
  for (const row of t.layout) if (row.kind === "site") row.parent_uid = "region:core";
  t.layout.push({ uid: "region:core", kind: "region", parent_uid: null, u: -10, v: -10, w: 200, h: 100, slot: 0 });
  return t;
}

describe("the circuit arcs", () => {
  it("end at the site glyphs at estate and site zoom, and the glyph of each end draws without a tunnel", () => {
    const t = backbone();
    circuit(t, "vc:1", "dev:s1d0", "dev:s3d0");
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    for (const level of [1, 2] as Level[]) {
      at(r, level);
      const glyphs = r.scene.batches(level).boxes.find((b) => b.cls === "glyph")?.ids ?? [];
      expect([...glyphs].sort(), `level ${level}`).toEqual(["glyph:site:s1", "glyph:site:s3"]);
      const [[from, to]] = arcEnds(r, level, "circuit:site:s1|site:s3");
      const [g1, g3] = [r.scene.glyphOf("site:s1")!, r.scene.glyphOf("site:s3")!];
      close(from, [g1[0], Y.glyph, g1[1]], `level ${level} from`);
      close(to, [g3[0], Y.glyph, g3[1]], `level ${level} to`);
    }
    // The far site of a selected site has no tunnel glyph of its own, and takes one for the circuit.
    const s = sdwan();
    circuit(s, "vc:1", "dev:s0d0", "dev:s4d0");
    const q = load(s);
    q.setTier("render_t1_circuits", s.render_t1_circuits);
    at(q, 2);
    q.setStyle({ ...DEFAULT_STYLE, area: "site:s0" });
    expect(q.scene.batches(2).boxes.find((b) => b.cls === "glyph")?.ids).toContain("glyph:site:s4");
    q.setTier("render_t1_circuits", []);
    expect(q.scene.batches(2).boxes.find((b) => b.cls === "glyph")?.ids ?? []).not.toContain("glyph:site:s4");
  });

  it("end at the devices of each circuit from block zoom: one arc per device pair of a backbone site pair", () => {
    const t = core();
    circuit(t, "vc:1", "dev:s0d0", "dev:s1d0");
    circuit(t, "vc:2", "dev:s1d1", "dev:s0d1");
    circuit(t, "vc:3", "dev:s0d0", "dev:s1d0");
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    for (const selected of [null, "dev:s0d0"]) {
      for (const level of [3, 4] as Level[]) {
        at(r, level, "dev:s0d1");
        r.setStyle({ ...DEFAULT_STYLE, selected });
        const what = `level ${level}, selected ${selected}`;
        expect(r.frame().level, what).toBe(level);
        const lines = r.scene.batches(level).lines.filter((l) => l.cls === "circuit");
        // A circuit of the backbone draws on its backbone line only, also from a selected device.
        expect([...new Set(lines.flatMap((l) => l.ids))], what).toEqual(["circuit:site:s0|site:s1"]);
        const arcs = arcEnds(r, level, "circuit:site:s0|site:s1");
        expect(arcs, what).toHaveLength(2);
        // The arc with the most circuits first, each from the end in the first site of the pair.
        close(arcs[0][0], centre(r, "dev:s0d0", Y.deviceTop), `${what} first from`);
        close(arcs[0][1], centre(r, "dev:s1d0", Y.deviceTop), `${what} first to`);
        close(arcs[1][0], centre(r, "dev:s0d1", Y.deviceTop), `${what} second from`);
        close(arcs[1][1], centre(r, "dev:s1d1", Y.deviceTop), `${what} second to`);
        expect(r.frame().labels.find((l) => l.uid === "circuit:site:s0|site:s1")?.text, what).toBe("3 circuits");
      }
    }
    const panel = panelOf(r.scene, null, null, "circuit:site:s0|site:s1");
    expect(panel).toMatchObject({ kind: "circuit", title: "s0 to s1", subtitle: "3 circuits" });
    expect(panel?.tabs[0].items?.map((i) => i.label)).toEqual(["vc:1", "vc:2", "vc:3"]);
  });

  it("end at the selected device and its far device at block zoom, and at their Fabric ports where the ports draw", () => {
    const t = estate({ sites: 2, devices: 2, ports: 2 });
    // The cable chain cables s0d0 eth1 and s1d1 eth0, so both draw a socket at port zoom.
    circuit(t, "vc:1", "dev:s0d0", "dev:s1d1", "dev:s0d0/port/eth1", "dev:s1d1/port/eth0");
    const r = load(t);
    for (const block of ["block:s0:campus", "block:s1:campus"]) {
      r.setTier("layout", tile(t, "layout", block), block);
      for (const name of ["render_t2_ports", "render_t2_cables"] as TableName[]) r.setTier(name, tile(t, name, block), block);
    }
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d0" });
    at(r, 3, "dev:s0d0");
    const [[from, to]] = arcEnds(r, 3, "circuit:dev:s0d0|dev:s1d1");
    close(from, centre(r, "dev:s0d0", Y.deviceTop), "block zoom from");
    close(to, centre(r, "dev:s1d1", Y.deviceTop), "block zoom to");
    at(r, 4, "dev:s0d0");
    const sockets = r.scene.wiring().sockets;
    const [a, z] = [sockets.get("dev:s0d0/port/eth1")!, sockets.get("dev:s1d1/port/eth0")!];
    expect(a && z).toBeTruthy();
    const [[pf, pt]] = arcEnds(r, 4, "circuit:dev:s0d0|dev:s1d1");
    close(pf, [a.u, Y.cable, a.v], "port zoom from");
    close(pt, [z.u, Y.cable, z.v], "port zoom to");
    const panel = panelOf(r.scene, "dev:s0d0", null, "circuit:dev:s0d0|dev:s1d1");
    expect(panel).toMatchObject({ kind: "circuit", title: "s0d0 to s1d1", subtitle: "1 circuit" });
  });
});

describe("the labels", () => {
  it("place the device names before the circuit counts, so a count is the label a collision drops", () => {
    const t = estate({ sites: 1, devices: 9, ports: 0 });
    t.render_t1_edges = [];
    for (let i = 0; i < 9; i++) if (i !== 4) circuit(t, `vc:${i}`, "dev:s0d4", `dev:s0d${i}`);
    const r = load(t);
    r.setTier("render_t1_circuits", t.render_t1_circuits);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d4" });
    at(r, 3, "dev:s0d4");
    const names = (labels: Label[]) => labels.filter((l) => l.kind === "device").map((l) => l.uid).sort();
    const labels = r.frame().labels;
    const counts = labels.filter((l) => l.uid.startsWith("circuit:"));
    expect(counts.length).toBeGreaterThan(0);
    expect(counts.length).toBeLessThan(8);
    r.setStyle({ ...DEFAULT_STYLE, selected: "dev:s0d4", layers: { ...DEFAULT_STYLE.layers, l2: false } });
    const without = r.frame().labels;
    expect(without.filter((l) => l.uid.startsWith("circuit:"))).toEqual([]);
    expect(names(labels)).toEqual(names(without));
    expect(names(labels).length).toBeGreaterThan(1);
    for (const c of counts) for (const l of labels) if (l !== c) expect(apart(c, l), `${c.uid} and ${l.uid}`).toBe(true);
  });
});
