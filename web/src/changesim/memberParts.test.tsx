import { describe, expect, it } from "vitest";

import type { ServiceImpactMember } from "./assessImpact";
import { memberParts } from "./ServiceImpactPane";

function member(over: Partial<ServiceImpactMember>): ServiceImpactMember {
  return {
    name: "app",
    triage: {},
    before: {},
    after: {},
    ...over,
  };
}

describe("memberParts", () => {
  it("labels a member once for one part", () => {
    expect(memberParts(member({ triage: { decided_loss: true } }))).toEqual([
      "passes before, fails after",
    ]);
  });

  it("separates the three situations possible loss merged", () => {
    expect(memberParts(member({ triage: { passes_then_open: true } }))).toEqual([
      "passes before, not decided after",
    ]);
    expect(memberParts(member({ triage: { open_then_fails: true } }))).toEqual([
      "not decided before, fails after",
    ]);
    expect(memberParts(member({ triage: { open_throughout: true } }))).toEqual([
      "not decided before or after",
    ]);
  });

  it("reads a member that moved in a loss part and a gain part", () => {
    expect(
      memberParts(member({ triage: { decided_loss: true, open_then_passes: true } })),
    ).toEqual(["passes before, fails after", "not decided before, passes after"]);
  });

  it("says unchanged when nothing moved", () => {
    expect(memberParts(member({ triage: {} }))).toEqual([]);
  });
});
