import { describe, expect, it } from "vitest";
import type { Point } from "./layout";
import type { Box } from "./segrow";
import { deviceRect, Grid, overlaps, placeTags, type CableEnds, type Quad, type TagLook } from "./tags";

const LOOK: TagLook = { ports: true, addresses: true, along: true };
const measure = (text: string) => text.length * 5;

function rng(seed: number): () => number {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}

function randomQuad(next: () => number): Quad {
  const angle = next() * Math.PI;
  return {
    c: { x: next() * 600 - 300, y: next() * 600 - 300 },
    u: { x: Math.cos(angle), y: Math.sin(angle) },
    hw: 4 + next() * 90,
    hh: 3 + next() * 20,
  };
}

describe("the grid of boxes", () => {
  it("finds an overlap exactly when a box on the grid overlaps, for oriented boxes", () => {
    const next = rng(7);
    const boxes = Array.from({ length: 150 }, () => randomQuad(next));
    const grid = new Grid();
    for (const q of boxes) grid.add(q);
    for (let i = 0; i < 400; i++) {
      const probe = randomQuad(next);
      expect(grid.hits(probe), `probe ${i}`).toBe(boxes.some((q) => overlaps(probe, q)));
    }
  });

  it("forgets a box that is removed", () => {
    const q: Quad = { c: { x: 10, y: 10 }, u: { x: 1, y: 0 }, hw: 80, hh: 8 };
    const grid = new Grid();
    grid.add(q);
    expect(grid.hits({ c: { x: 85, y: 12 }, u: { x: 0, y: 1 }, hw: 6, hh: 6 })).toBe(true);
    grid.remove(q);
    expect(grid.hits({ c: { x: 85, y: 12 }, u: { x: 0, y: 1 }, hw: 6, hh: 6 })).toBe(false);
  });

  it("ignores a box that is not finite", () => {
    const grid = new Grid();
    grid.add({ c: { x: Number.NaN, y: 0 }, u: { x: 1, y: 0 }, hw: 5, hh: 5 });
    grid.add({ c: { x: 0, y: 0 }, u: { x: 1, y: 0 }, hw: Number.POSITIVE_INFINITY, hh: 5 });
    expect(grid.hits({ c: { x: 0, y: 0 }, u: { x: 1, y: 0 }, hw: 5, hh: 5 })).toBe(false);
  });
});

describe("the tags of a core with many downlinks", () => {
  /** Two cores and `n` access switches, each cabled to both cores. */
  function tiered(n: number) {
    const at = new Map<string, Point>([
      ["core1", { x: (n * 70) / 3, y: 0 }],
      ["core2", { x: (n * 70 * 2) / 3, y: 0 }],
    ]);
    const cables: CableEnds[] = [];
    for (let i = 0; i < n; i++) {
      at.set(`acc${i}`, { x: i * 70, y: 320 });
      for (const core of ["core1", "core2"]) {
        cables.push({
          id: `${core}-acc${i}`,
          source: core,
          target: `acc${i}`,
          sourcePort: `Te1/0/${i}`,
          targetPort: `Te1/1/${core === "core1" ? 1 : 2}`,
          sourceTag: `Te1/0/${i} 10.0.${i}.1`,
          targetTag: `Te1/1/${core === "core1" ? 1 : 2} 10.0.${i}.2`,
        });
      }
    }
    const boxes = new Map<string, Box>([...at.keys()].map((id) => [id, { width: 60, height: 50 }]));
    return { at, boxes, cables };
  }

  it("places every tag clear of the device boxes and of the other tags at 40 access switches", () => {
    const { at, boxes, cables } = tiered(40);
    const places = placeTags(cables, at, boxes, measure, LOOK);
    const tags: Quad[] = [];
    for (const c of cables) {
      const p = places.get(c.id)!;
      for (const q of [p.sourceBox, p.targetBox]) if (q) tags.push(q);
    }
    expect(tags.length).toBeGreaterThan(0);
    const devices = [...at].map(([id, p]) => {
      const r = deviceRect(p, boxes.get(id)!);
      return { c: { x: (r.x0 + r.x1) / 2, y: (r.y0 + r.y1) / 2 }, u: { x: 1, y: 0 }, hw: (r.x1 - r.x0) / 2, hh: (r.y1 - r.y0) / 2 };
    });
    tags.forEach((t, i) => {
      for (const d of devices) expect(overlaps(t, d), `tag ${i} over a device`).toBe(false);
      for (let j = i + 1; j < tags.length; j++) expect(overlaps(t, tags[j]), `tag ${i} over tag ${j}`).toBe(false);
    });
  });

  it("places 100 access switches in a bounded time", () => {
    const { at, boxes, cables } = tiered(100);
    const started = performance.now();
    const places = placeTags(cables, at, boxes, measure, LOOK);
    expect(places.size).toBe(cables.length);
    expect(performance.now() - started).toBeLessThan(2500);
  });
});
