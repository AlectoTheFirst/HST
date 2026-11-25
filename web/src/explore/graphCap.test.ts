import { describe, expect, it } from "vitest";
import {
  MAX_GROWN_NODES,
  growthLayoutOptions,
  mergeGraphs,
} from "./graphElements";
import type { ResultGraph } from "../api/types";

const node = (id: string) => ({ id, labels: ["Device"], properties: {} });

describe("a grown picture", () => {
  it("stops adding nodes past the cap and marks the picture partial", () => {
    const into: ResultGraph = {
      nodes: [node("a"), node("b")],
      relationships: [],
      truncated: false,
    };
    const add: ResultGraph = {
      nodes: [node("b"), node("c"), node("d")],
      relationships: [
        { id: "r1", type: "LINK", start: "a", end: "c", properties: {} },
        { id: "r2", type: "LINK", start: "a", end: "d", properties: {} },
      ],
      truncated: false,
    };
    const grown = mergeGraphs(into, add, 3);
    expect(grown.nodes.map((n) => n.id)).toEqual(["a", "b", "c"]);
    expect(grown.relationships.map((r) => r.id)).toEqual(["r1"]);
    expect(grown.truncated).toBe(true);
    expect(
      mergeGraphs(into, { ...add, nodes: [node("c")], relationships: [] }, 3)
        .truncated,
    ).toBe(false);
    expect(MAX_GROWN_NODES).toBe(500);
  });

  it("keeps the zoom on a force layout growth", () => {
    expect(
      (growthLayoutOptions("fcose", 3, new Map()) as { fit?: boolean }).fit,
    ).toBe(false);
  });
});
