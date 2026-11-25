import { describe, expect, it } from "vitest";
import { viewHasData } from "./types";

describe("viewHasData", () => {
  it("lists a vendor view only when its product holds data", () => {
    const catalog = { queries: [], products: ["sdwan"] };
    expect(viewHasData("sdwan", catalog)).toBe(true);
    expect(viewHasData("equinix", catalog)).toBe(false);
    expect(viewHasData("map", catalog)).toBe(true);
  });

  it("lists every view when products is left out", () => {
    expect(viewHasData("equinix", { queries: [] })).toBe(true);
    expect(viewHasData("sdwan", undefined)).toBe(true);
  });
});
