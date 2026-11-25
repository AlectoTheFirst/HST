import { describe, expect, it } from "vitest";
import { RESULT } from "../test/resultFixture";
import type { ResultRow } from "../api/types";
import { EMPTY_SELECTION, hitIndex, nodesOf, pick, pickable, seedsFor } from "./resultSelection";

const ROWS: ResultRow[] = [
  ...RESULT.data,
  { row: ["x"] }, // no row node index
  { row: ["y"], nodes: ["s1"] },
];

describe("pick", () => {
  it("picks one row and clears the focus", () => {
    const s = pick({ ...EMPTY_SELECTION, focus: "d1" }, ROWS, 1, "one");
    expect([...s.picked]).toEqual([1]);
    expect(s.anchor).toBe(1);
    expect(s.focus).toBeNull();
  });

  it("adds the range from the anchor and skips rows that cannot be picked", () => {
    const one = pick(EMPTY_SELECTION, ROWS, 0, "one");
    const range = pick(one, ROWS, 3, "range");
    expect([...range.picked].sort()).toEqual([0, 1, 3]);
    expect(range.anchor).toBe(0);
  });

  it("adds or removes one row and keeps the focus", () => {
    const one = { ...pick(EMPTY_SELECTION, ROWS, 0, "one"), focus: "p1" };
    const added = pick(one, ROWS, 1, "toggle");
    expect([...added.picked]).toEqual([0, 1]);
    expect(added.focus).toBe("p1");
    expect([...pick(added, ROWS, 0, "toggle").picked]).toEqual([1]);
  });

  it("does nothing for a row without a row node index", () => {
    const one = pick(EMPTY_SELECTION, ROWS, 0, "one");
    expect(pick(one, ROWS, 2, "one")).toBe(one);
    expect(pickable(ROWS[2])).toBe(false);
    expect(pickable({ row: [], nodes: [] })).toBe(false);
  });
});

describe("derived values", () => {
  it("finds the hit rows of a node", () => {
    const index = hitIndex(ROWS);
    expect(index.get("p1")).toEqual([0, 1]);
    expect(index.get("s1")).toEqual([0, 1, 3]);
    expect(index.get("d2")).toEqual([1]);
  });

  it("joins the nodes of the picked rows in row order, once each", () => {
    expect(nodesOf(ROWS, new Set([1, 0]))).toEqual(["d1", "i1", "a1", "p1", "s1", "d2", "i2", "a2"]);
  });

  it("keeps the row seeds while the picture of them shows the focus", () => {
    const drawn = (seeds: readonly string[]) => new Set([...seeds, "n9"]);
    expect(seedsFor(["d1"], null, drawn)).toEqual(["d1"]);
    expect(seedsFor(["d1"], "n9", drawn)).toEqual(["d1"]);
    expect(seedsFor(["d1"], "far", drawn)).toEqual(["far"]);
    expect(seedsFor([], "far", drawn)).toEqual(["far"]);
  });
});
