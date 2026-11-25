import { describe, expect, it } from "vitest";
import { LCS_LIMIT, sideBySide } from "./diff";

describe("the side-by-side comparison", () => {
  it("aligns equal lines and pairs a removed line with the added one as changed", () => {
    const a = ["interface eth0", " description uplink", " no shutdown", " mtu 1500"];
    const b = ["interface eth0", " description uplink", " shutdown", " mtu 1500", " speed 1000"];
    expect(sideBySide(a, b)).toEqual([
      { a: "interface eth0", b: "interface eth0", kind: "same" },
      { a: " description uplink", b: " description uplink", kind: "same" },
      { a: " no shutdown", b: " shutdown", kind: "changed" },
      { a: " mtu 1500", b: " mtu 1500", kind: "same" },
      { a: null, b: " speed 1000", kind: "added" },
    ]);
  });

  it("marks lines only one side has", () => {
    expect(sideBySide(["x", "y"], ["x"])).toEqual([
      { a: "x", b: "x", kind: "same" },
      { a: "y", b: null, kind: "removed" },
    ]);
    expect(sideBySide([], [])).toEqual([]);
  });

  it("compares by position past the size limit", () => {
    const n = Math.ceil(Math.sqrt(LCS_LIMIT)) + 1;
    const a = Array.from({ length: n }, (_, i) => `l${i}`);
    const pairs = sideBySide(a, [...a.slice(1), "z"]);
    expect(pairs).toHaveLength(n);
    expect(pairs.every((p) => p.kind === "changed")).toBe(true);
  });
});
