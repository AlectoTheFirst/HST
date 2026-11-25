import { describe, it, expect } from "vitest";
import { changeRows, defaultPair, formatValue, isEmptyDiff } from "./diffmodel";
import { FIXTURE_SNAPSHOTS } from "../test/fixtures";
import type { DiffCounts, Snapshot } from "../api/types";

describe("defaultPair", () => {
  it("pairs the newest snapshot as B and the second-newest as A", () => {
    expect(defaultPair(FIXTURE_SNAPSHOTS.snapshots)).toEqual({
      a: FIXTURE_SNAPSHOTS.snapshots[1].id,
      b: FIXTURE_SNAPSHOTS.snapshots[0].id,
    });
  });

  it("returns null with fewer than two snapshots", () => {
    expect(defaultPair([])).toBeNull();
    expect(defaultPair([FIXTURE_SNAPSHOTS.snapshots[0]])).toBeNull();
  });

  it("picks the newest two of three snapshots", () => {
    const third: Snapshot = { ...FIXTURE_SNAPSHOTS.snapshots[1], id: "1723000000000", ts_ms: 1723000000000 };
    const snapshots = [...FIXTURE_SNAPSHOTS.snapshots, third];
    expect(defaultPair(snapshots)).toEqual({
      a: FIXTURE_SNAPSHOTS.snapshots[1].id,
      b: FIXTURE_SNAPSHOTS.snapshots[0].id,
    });
  });
});

describe("isEmptyDiff", () => {
  const zero: DiffCounts = {
    nodes: { added: 0, removed: 0, changed: 0 },
    rels: { added: 0, removed: 0, changed: 0 },
  };

  it("is true when every count is zero", () => {
    expect(isEmptyDiff(zero)).toBe(true);
  });

  it("is false when any single count is nonzero", () => {
    expect(isEmptyDiff({ ...zero, nodes: { ...zero.nodes, added: 1 } })).toBe(false);
    expect(isEmptyDiff({ ...zero, rels: { ...zero.rels, changed: 1 } })).toBe(false);
  });
});

describe("changeRows", () => {
  it("flattens a changes map into a key-sorted before/after list", () => {
    expect(changeRows({ role: ["router", "firewall"], name: ["old", "new"] })).toEqual([
      { key: "name", before: "old", after: "new" },
      { key: "role", before: "router", after: "firewall" },
    ]);
  });

  it("returns an empty list for an empty changes map", () => {
    expect(changeRows({})).toEqual([]);
  });

  it("lists only the keys that differ in a JSON object string property", () => {
    const before = '{"command":"show configuration json","target_release":"a","version":1}';
    const after = '{"command":"show configuration json","target_release":"b","version":1,"x":null}';
    expect(changeRows({ selector_json: [before, after] })).toEqual([
      { key: "selector_json.target_release", before: "a", after: "b" },
      { key: "selector_json.x", before: undefined, after: null },
    ]);
  });

  it("keeps the whole value when only one side is a JSON object", () => {
    expect(changeRows({ selector_json: [null, '{"version":1}'] })).toEqual([
      { key: "selector_json", before: null, after: '{"version":1}' },
    ]);
  });

  it("keeps the whole value when the JSON objects parse equal", () => {
    expect(changeRows({ s: ['{"a":1,"b":2}', '{"b":2,"a":1}'] })).toEqual([
      { key: "s", before: '{"a":1,"b":2}', after: '{"b":2,"a":1}' },
    ]);
  });
});

describe("formatValue", () => {
  it("renders null and undefined as not set", () => {
    expect(formatValue(null)).toBe("not set");
    expect(formatValue(undefined)).toBe("not set");
  });

  it("passes a string through unchanged", () => {
    expect(formatValue("firewall")).toBe("firewall");
  });

  it("joins an array with commas", () => {
    expect(formatValue(["vyos", "unifi"])).toBe("vyos, unifi");
  });

  it("JSON-stringifies a nested object", () => {
    expect(formatValue({ a: 1 })).toBe('{"a":1}');
  });

  it("stringifies numbers and booleans", () => {
    expect(formatValue(42)).toBe("42");
    expect(formatValue(true)).toBe("true");
  });
});
