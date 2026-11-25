import { describe, expect, it } from "vitest";
import { project, WORLD_H, WORLD_W } from "../diagram/projection";
import { majorsOf } from "./backbone";
import { fitView, MIN_FIT_W, siteClass, spread, SPREAD_PX, visibleLabels, type Box } from "./estate";
import { SITES } from "./fixture";

/** the placed major sites of the fixture, at their projected coordinates */
const PLACED = majorsOf(SITES)
  .filter((m) => m.site.lat !== null && m.site.lon !== null)
  .map((m) => ({ code: m.code, at: project(m.site.lat as number, m.site.lon as number) }));

/** px per user unit at the first view of the fixture on a 1000 px wide map */
const FIRST = 1000 / MIN_FIT_W;

describe("siteClass", () => {
  it("reads the tiers and the graph kind", () => {
    expect(SITES.map(siteClass)).toEqual(["hub", "hub", "colo", "dc", "branch", "branch", "branch", "branch"]);
  });
});

describe("fitView", () => {
  it("frames the major sites at 2:1, no narrower than the minimum width", () => {
    const view = fitView(PLACED.map((p) => p.at));
    expect(view.w).toBe(MIN_FIT_W);
    expect(view.w / view.h).toBeCloseTo(2, 6);
    for (const p of PLACED) {
      expect(p.at.x).toBeGreaterThan(view.x);
      expect(p.at.x).toBeLessThan(view.x + view.w);
      expect(p.at.y).toBeGreaterThan(view.y);
      expect(p.at.y).toBeLessThan(view.y + view.h);
    }
  });

  it("centers a single site at the minimum width", () => {
    const at = project(50.11, 8.68);
    const view = fitView([at]);
    expect(view).toEqual({ x: at.x - MIN_FIT_W / 2, y: at.y - MIN_FIT_W / 4, w: MIN_FIT_W, h: MIN_FIT_W / 2 });
  });

  it("frames sites on two continents with a margin", () => {
    const view = fitView([project(50, 8), project(40, -74)]);
    expect(view.w).toBeGreaterThan((8 + 74) * 4);
    expect(view.w / view.h).toBeCloseTo(2, 6);
  });

  it("shows the world when no major site has coordinates", () => {
    expect(fitView([])).toEqual({ x: 0, y: 0, w: WORLD_W, h: WORLD_H });
  });
});

describe("spread", () => {
  const dist = (p: { x: number; y: number }, q: { x: number; y: number }) => Math.hypot(p.x - q.x, p.y - q.y);

  it("spreads the Frankfurt sites on a small circle and leaves Amsterdam where it is", () => {
    const { at, around } = spread(PLACED, FIRST);
    const reach = SPREAD_PX / FIRST;
    const frankfurt = ["FR2", "fra-hub1", "fra-hub2"];
    for (const a of frankfurt)
      for (const b of frankfurt) if (a < b) expect(dist(at.get(a)!, at.get(b)!)).toBeGreaterThanOrEqual(reach - 1e-9);
    expect(at.get("ams-dc")).toEqual(PLACED.find((p) => p.code === "ams-dc")!.at);
    expect(around.has("ams-dc")).toBe(false);
    // the circle is centered on the mean of the three
    const mean = {
      x: frankfurt.reduce((t, c) => t + PLACED.find((p) => p.code === c)!.at.x, 0) / 3,
      y: frankfurt.reduce((t, c) => t + PLACED.find((p) => p.code === c)!.at.y, 0) / 3,
    };
    for (const c of frankfurt) expect(around.get(c)).toEqual(mean);
    // FR2 is first in code point order, so it is at the top of the circle
    expect(at.get("FR2")!.x).toBeCloseTo(mean.x, 9);
    expect(at.get("FR2")!.y).toBeLessThan(mean.y);
  });

  it("gives the same positions whatever the input order", () => {
    const one = spread(PLACED, FIRST).at;
    const two = spread([...PLACED].reverse(), FIRST).at;
    expect([...two].sort()).toEqual([...one].sort());
  });

  it("draws every site at its coordinates once the zoom keeps them apart", () => {
    const { at, around } = spread(PLACED, 2000);
    for (const p of PLACED) expect(at.get(p.code)).toEqual(p.at);
    expect(around.size).toBe(0);
  });
});

describe("visibleLabels", () => {
  const box = (id: string, x: number, y: number, owner = id): Box => ({ id, owner, x, y, w: 40, h: 12 });

  it("hides a label that covers an earlier label or another site's marker, and keeps the first", () => {
    const labels = [box("a", 0, 0), box("b", 20, 4), box("c", 100, 0), box("d", 200, 0)];
    const obstacles = [box("a", 0, 0), box("m", 210, 2)];
    expect([...visibleLabels(labels, obstacles)].sort()).toEqual(["a", "c"]);
  });

  it("shows the first label even when it covers a marker", () => {
    expect([...visibleLabels([box("a", 0, 0)], [box("m", 0, 0)])]).toEqual(["a"]);
  });
});
