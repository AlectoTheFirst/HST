import { describe, expect, it } from "vitest";
import { LANE, wire, type CableEnds, type Footprint, type PortEnd } from "./wiring";

const EPS = 1e-6;

function dev(uid: string, u: number, v: number): Footprint {
  const w = 4 - 0.24;
  const h = 3 - 0.24;
  return { uid, u, v, w: 4, h: 3, cu: u + 2, cv: v + 1.5, hw: w / 2, hh: h / 2, round: false, area: "block" };
}

function estate(cells: [string, number, number][], pairs: [string, string][]) {
  const devices = new Map(cells.map(([uid, u, v]) => [uid, dev(uid, u, v)]));
  const ports: PortEnd[] = [];
  const cables: CableEnds[] = [];
  pairs.forEach(([a, b], i) => {
    ports.push({ uid: `${a}/${i}`, device: a, side: null, slot: i }, { uid: `${b}/${i}`, device: b, side: null, slot: i });
    cables.push({ key: `${a}~${b}`, a: `${a}/${i}`, b: `${b}/${i}` });
  });
  return { devices, ports, cables };
}

function axisAligned(p: [number, number], q: [number, number]): boolean {
  return Math.abs(p[0] - q[0]) < EPS || Math.abs(p[1] - q[1]) < EPS;
}

function diagonals(points: [number, number][]): number {
  let n = 0;
  for (let i = 1; i < points.length; i++) if (!axisAligned(points[i - 1], points[i])) n++;
  return n;
}

function crossesCell(p: [number, number], q: [number, number], f: Footprint): boolean {
  const m = 0.1;
  return Math.max(p[0], q[0]) > f.u + m && Math.min(p[0], q[0]) < f.u + f.w - m && Math.max(p[1], q[1]) > f.v + m && Math.min(p[1], q[1]) < f.v + f.h - m;
}

describe("the cable routes", () => {
  it("cross no device cell, in centred rows with offset columns", () => {
    const cells: [string, number, number][] = [];
    for (const [row, v, shift] of [[0, 0, 0], [1, 5, 3], [2, 10, 0]] as const) for (let c = 0; c < 3; c++) cells.push([`d${row}${c}`, shift + 6 * c, v]);
    const pairs: [string, string][] = [];
    for (let i = 0; i < cells.length; i++) for (let j = i + 1; j < cells.length; j++) pairs.push([cells[i][0], cells[j][0]]);
    const { devices, ports, cables } = estate(cells, pairs);
    const { routes } = wire(devices, ports, cables);
    expect(routes.size).toBe(pairs.length);
    for (const c of cables) {
      const points = routes.get(c.key)!;
      const ends = new Set([c.a.split("/")[0], c.b.split("/")[0]]);
      for (let i = 1; i < points.length; i++) {
        for (const f of devices.values()) {
          if (ends.has(f.uid)) continue;
          expect(crossesCell(points[i - 1], points[i], f), `${c.key} leg ${i} over ${f.uid}`).toBe(false);
        }
      }
    }
  });

  it("join two neighbouring rows in one channel in the middle of a wide gap", () => {
    // Rows and columns 4 cells apart, the planner's device gap.
    const { devices, ports, cables } = estate([["hub", 0, 0], ["sw0", 0, 7], ["sw", 8, 7]], [["sw", "hub"]]);
    const points = wire(devices, ports, cables).routes.get("sw~hub")!;
    expect(points).toHaveLength(4);
    expect(points[1][1]).toBeCloseTo(5);
    expect(points[2][1]).toBeCloseTo(5);
  });

  it("keep the lane pitch for parallel cables in one channel", () => {
    const { devices, ports, cables } = estate(
      [["a", 0, 0], ["b", 6, 0], ["c", 12, 0], ["d", 0, 5], ["e", 6, 5], ["f", 12, 5]],
      [["a", "f"], ["b", "f"], ["c", "d"]],
    );
    const { routes } = wire(devices, ports, cables);
    const ys = cables.map((c) => {
      const points = routes.get(c.key)!;
      const legs = points.slice(1, -1).filter((p, i, list) => i > 0 && Math.abs(p[1] - list[i - 1][1]) < EPS);
      expect(legs.length).toBeGreaterThan(0);
      return legs[0][1];
    });
    const sorted = [...ys].sort((x, y) => x - y);
    expect(new Set(sorted.map((y) => y.toFixed(3))).size).toBe(3);
    for (let i = 1; i < sorted.length; i++) expect(sorted[i] - sorted[i - 1]).toBeCloseTo(LANE, 6);
    for (const y of ys) expect(Math.abs(y - 4)).toBeLessThan(1);
  });

  it("take a staircase through the rows a cable skips, with at most two bends per row", () => {
    const cells: [string, number, number][] = [["core", 6, 0], ["sw0", 0, 5], ["sw1", 6, 5], ["sw2", 12, 5], ["ap", 12, 10]];
    const { devices, ports, cables } = estate(cells, [["core", "ap"]]);
    ports[0].side = "s";
    ports[1].side = "n";
    const points = wire(devices, ports, cables).routes.get("core~ap")!;
    expect(diagonals(points)).toBe(0);
    const bends = points.length - 2;
    expect(bends).toBeLessThanOrEqual(2 + 2 * 1);
    for (let i = 1; i < points.length; i++) {
      for (const f of devices.values()) if (f.uid !== "core" && f.uid !== "ap") expect(crossesCell(points[i - 1], points[i], f)).toBe(false);
    }
    const through = [];
    for (let i = 1; i < points.length; i++) {
      const [p, q] = [points[i - 1], points[i]];
      if (Math.abs(p[0] - q[0]) < EPS && Math.min(p[1], q[1]) <= 5 && Math.max(p[1], q[1]) >= 8) through.push(p[0]);
    }
    expect(through).toHaveLength(1);
    expect(through[0]).toBeGreaterThanOrEqual(10);
    expect(through[0]).toBeLessThanOrEqual(12);
  });

  it("cross two cables without a jump", () => {
    const cells: [string, number, number][] = [["a", 0, 0], ["b", 6, 0], ["c", 0, 5], ["d", 12, 5]];
    const crossing = estate(cells, [["a", "d"], ["b", "c"]]);
    const { routes } = wire(crossing.devices, crossing.ports, crossing.cables);
    expect(diagonals(routes.get("a~d")!)).toBe(0);
    expect(diagonals(routes.get("b~c")!)).toBe(0);
  });
});
