import { describe, expect, it } from "vitest";
import { unboundText } from "./EquinixPage";
import type { EquinixPort } from "../api/types";

const port = (unbound: EquinixPort["unbound"]): EquinixPort => ({
  uid: "fp:1", name: "ACME-XX1-EXT-PRI-01", ibx: "XX1", state: "ACTIVE", speed_mbps: 10000,
  redundancy: "primary", lag: null, cable_ids: ["21000001"], bound: null, unbound,
});

describe("unboundText", () => {
  it("names the cause the run states", () => {
    expect(unboundText(port({ reason: "binding-refused", ports: ["port:gone"] }))).toBe(
      "port:gone (not in this run)",
    );
    expect(unboundText(port({ reason: "cable-conflict", ports: ["port:c"] }))).toBe(
      "cable ID conflict on port:c",
    );
    expect(unboundText(port({ reason: "several-ports", ports: ["port:1", "port:2"] }))).toBe(
      "2 port descriptions (port:1, port:2)",
    );
    expect(unboundText(port({ reason: "several-fabric-ports", ports: ["port:x"] }))).toBe(
      "another Fabric port in the description of port:x",
    );
  });

  it("keeps the default text without a reason", () => {
    expect(unboundText(port(null))).toBe("none");
    expect(unboundText(port(undefined))).toBe("none");
  });
});
