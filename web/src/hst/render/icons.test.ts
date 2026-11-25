import { describe, expect, it } from "vitest";
import { AREA_ICONS, areaIcon } from "./icons";

describe("areaIcon", () => {
  it("gives the icon of other for a kind that is an inherited member of the table", () => {
    for (const kind of ["constructor", "toString", "__proto__"]) expect(areaIcon(kind), kind).toBe(AREA_ICONS.other);
  });
});
