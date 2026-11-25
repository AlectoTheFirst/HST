import { describe, expect, it } from "vitest";
import { objectQueries } from "./objectQueries";
import type { CannedQuery } from "../api/types";

const q = (key: string, params: CannedQuery["params"]): CannedQuery => ({
  key,
  group: "zscaler",
  title: key,
  cypher: "RETURN 1",
  params,
});
const picker = (name: string, label: string, optional = false) => ({
  name,
  label: name,
  picker: { label, property: "name" },
  ...(optional ? { optional: true } : {}),
});

const CATALOG = [
  q("zpa-app-segment", [picker("segment", "ZpaAppSegment")]),
  q("zpa-segments-at-risk", [picker("app_group", "ZpaSegmentGroup", true)]),
  q("zpa-app-group", [picker("app_group", "ZpaSegmentGroup", true)]),
  q("two-required", [picker("segment", "ZpaAppSegment"), { name: "port", label: "Port" }]),
  q("devices", []),
];

describe("objectQueries", () => {
  it("matches entries by picker label and property, and fills the value from the object", () => {
    const found = objectQueries(CATALOG, ["ZpaAppSegment"], { name: "app-crm" });
    expect(found.map((f) => [f.entry.key, f.param, f.value, f.lookup])).toEqual([
      ["zpa-app-segment", "segment", "app-crm", true],
    ]);
  });

  it("lists a query that only filters by the object as a filter", () => {
    const found = objectQueries(CATALOG, ["ZpaSegmentGroup"], { name: "corp-apps" });
    expect(found.map((f) => [f.entry.key, f.lookup])).toEqual([
      ["zpa-segments-at-risk", false],
      ["zpa-app-group", false],
    ]);
  });

  it("leaves out an object that does not carry the picked property", () => {
    expect(objectQueries(CATALOG, ["ZpaAppSegment"], { uid: "x" })).toEqual([]);
  });
});
