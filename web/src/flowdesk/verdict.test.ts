import { describe, expect, it } from "vitest";
import { VERDICT_WORD, legOutcome } from "./verdict";
import { buildPathGraph } from "./pathGraph";
import { FIXTURE_PATH_SINGLE } from "../test/fixtures";
import type { Leg } from "../api/types";

describe("VERDICT_WORD", () => {
  it("states each verdict as a plain word", () => {
    expect(VERDICT_WORD).toEqual({ ok: "permitted", bad: "blocked", warn: "not decided" });
    for (const word of Object.values(VERDICT_WORD)) expect(word).toMatch(/^[a-z]+( [a-z]+)*$/);
  });
});

function legWith(patch: Partial<Leg> & { answer?: string }): Leg {
  const base = FIXTURE_PATH_SINGLE.legs[0];
  const { answer, ...rest } = patch;
  return { ...base, ...rest, result: { ...base.result, answer: answer ?? "true" } };
}

describe("legOutcome", () => {
  it("reads a leg with no route as bad although no rulebase blocked it", () => {
    expect(legOutcome(legWith({ blocked: false, answer: "false" }))).toBe("bad");
  });
  it("reads an undecided leg as warn", () => {
    expect(legOutcome(legWith({ blocked: false, answer: "open" }))).toBe("warn");
    expect(legOutcome(legWith({ blocked: false, indeterminate: true }))).toBe("warn");
  });
  it("reads a blocked leg as bad and a forwarded leg as ok", () => {
    expect(legOutcome(legWith({ blocked: true, answer: "true" }))).toBe("bad");
    expect(legOutcome(legWith({ blocked: false, answer: "true" }))).toBe("ok");
  });
  it("gives the last box of each lane in the path graph its leg's outcome", () => {
    const last = (legs: Leg[]) => {
      const g = buildPathGraph({ ...FIXTURE_PATH_SINGLE, legs }, "devices");
      return g.boxes.find((b) => b.ends.length > 0)?.endOutcome;
    };
    expect(last([legWith({ blocked: false, answer: "false" })])).toBe("bad");
    expect(last([legWith({ blocked: false, answer: "open" })])).toBe("warn");
    expect(last(FIXTURE_PATH_SINGLE.legs)).toBe("ok");
  });
});
