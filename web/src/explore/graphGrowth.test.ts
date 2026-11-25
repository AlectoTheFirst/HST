import { describe, it, expect } from "vitest";
import {
  NODE_SIZE,
  extendsDrawn,
  growthLayoutOptions,
  layoutOptions,
  mergeGraphs,
  seedPositions,
  type Point,
} from "./graphElements";
import type { ResultGraph } from "../api/types";

const node = (id: string) => ({ id, labels: ["Device"], properties: { name: id } });
const rel = (id: string, start: string, end: string) => ({ id, type: "CABLED", start, end, properties: {} });

describe("mergeGraphs", () => {
  it("adds each node and relationship once and keeps the first order", () => {
    const a: ResultGraph = { nodes: [node("n1"), node("n2")], relationships: [rel("r1", "n1", "n2")], truncated: false };
    const b: ResultGraph = { nodes: [node("n2"), node("n3")], relationships: [rel("r1", "n1", "n2"), rel("r2", "n2", "n3")], truncated: true };
    const merged = mergeGraphs(a, b);
    expect(merged.nodes.map((n) => n.id)).toEqual(["n1", "n2", "n3"]);
    expect(merged.relationships.map((r) => r.id)).toEqual(["r1", "r2"]);
    expect(merged.truncated).toBe(true);
  });

  it("returns the graph unchanged when there is nothing to add", () => {
    const a: ResultGraph = { nodes: [node("n1")], relationships: [], truncated: false };
    expect(mergeGraphs(a, undefined)).toBe(a);
  });
});

describe("extendsDrawn", () => {
  const next: ResultGraph = { nodes: [node("n1"), node("n2")], relationships: [], truncated: false };

  it("is true when every drawn node is still in the graph", () => {
    expect(extendsDrawn(new Set(["n1"]), next)).toBe(true);
    expect(extendsDrawn(new Set(["n1", "n2"]), next)).toBe(true);
  });

  it("is false when a drawn node is gone, or nothing is drawn yet", () => {
    expect(extendsDrawn(new Set(["n1", "n9"]), next)).toBe(false);
    expect(extendsDrawn(new Set(), next)).toBe(false);
  });
});

describe("seedPositions", () => {
  const placed = new Map<string, Point>([
    ["hub", { x: 100, y: 50 }],
    ["far", { x: 400, y: -50 }],
  ]);
  const graph: ResultGraph = {
    nodes: [node("hub"), node("far"), node("a"), node("b"), node("lone")],
    relationships: [rel("r1", "hub", "a"), rel("r2", "b", "hub")],
    truncated: false,
  };

  it("seeds only the new nodes", () => {
    expect([...seedPositions(graph, placed).keys()].sort()).toEqual(["a", "b", "lone"]);
  });

  it("puts a new neighbour on a ring around the drawn node it connects to", () => {
    const seeds = seedPositions(graph, placed);
    for (const id of ["a", "b"]) {
      const p = seeds.get(id)!;
      expect(Math.hypot(p.x - 100, p.y - 50)).toBeCloseTo(110);
    }
    expect(seeds.get("a")).not.toEqual(seeds.get("b"));
  });

  it("starts a node with no drawn neighbour right of the picture", () => {
    const p = seedPositions(graph, placed).get("lone")!;
    expect(p.x).toBeGreaterThan(400 + 4 * NODE_SIZE);
  });

  it("widens the ring for a large group so the nodes do not overlap", () => {
    const many: ResultGraph = {
      nodes: [node("hub"), ...Array.from({ length: 60 }, (_, i) => node(`m${i}`))],
      relationships: Array.from({ length: 60 }, (_, i) => rel(`r${i}`, "hub", `m${i}`)),
      truncated: false,
    };
    const seeds = seedPositions(many, new Map([["hub", { x: 0, y: 0 }]]));
    const [first, second] = [seeds.get("m0")!, seeds.get("m1")!];
    expect(Math.hypot(first.x - second.x, first.y - second.y)).toBeGreaterThan(NODE_SIZE);
  });
});

describe("growthLayoutOptions", () => {
  const fixed = new Map<string, Point>([["n1", { x: 1, y: 2 }]]);

  it("holds the drawn nodes in place under the force layout", () => {
    expect(growthLayoutOptions("fcose", 3, fixed)).toMatchObject({
      name: "fcose",
      randomize: false,
      fixedNodeConstraint: [{ nodeId: "n1", position: { x: 1, y: 2 } }],
    });
  });

  it("runs any other layout again over the whole graph", () => {
    expect(growthLayoutOptions("dagre", 3, fixed)).toEqual(layoutOptions("dagre", 3));
  });
});
