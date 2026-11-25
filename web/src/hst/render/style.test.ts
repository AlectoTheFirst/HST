/** A named block takes the tint of its zone. */

import { describe, expect, it } from "vitest";
import { KIND_TINT, tintOf } from "./style";

describe("named block tint", () => {
  it("draws a block of zone internet as one of zone external", () => {
    expect(tintOf("named:internet:uplink")).toBe(tintOf("named:external:dmz"));
    expect(tintOf("named:external:dmz")).toBe(KIND_TINT["internet-edge"]);
    expect(tintOf("named:internal:core")).toBe(KIND_TINT.campus);
    expect(tintOf("named::other")).toBe(KIND_TINT.other);
  });
});

describe("block kind tint", () => {
  it("gives the tint of other for a kind that is an inherited member of the table", () => {
    for (const kind of ["constructor", "toString", "__proto__"]) expect(tintOf(kind), kind).toBe(KIND_TINT.other);
  });
});
