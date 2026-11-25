import { describe, expect, it } from "vitest";
import { GATE_KINDS, isGate } from "./gate";

describe("isGate", () => {
  it("takes the server's gate flag, and the kind set for a response without the flag", () => {
    expect(isGate({ kind: "SomethingNew", gate: true })).toBe(true);
    expect(isGate({ kind: "FwRulebase", gate: false })).toBe(false);
    expect(isGate({ kind: "ForwardingBoundary" })).toBe(true);
    expect(isGate({ kind: "NatRule" })).toBe(false);
  });

  it("follows the labels.py gate registry, less NatRule and FwRule", () => {
    expect(GATE_KINDS.has("FwRulebase")).toBe(true);
    expect(GATE_KINDS.has("FwRule")).toBe(false);
    expect(GATE_KINDS.has("NatRule")).toBe(false);
  });
});
