import { describe, expect, it } from "vitest";
import { initial, panes, reduce } from "../workspace/layout";
import { conditionSentence, emptyRequirement, requirementError } from "./types";

describe("Assessment requirement and navigation invariants", () => {
  it("rejects dangling members and thresholds beyond their children", () => {
    const request = {
      ...emptyRequirement(),
      name: "Test",
      destination: "Service",
      sources: ["10.0.0.1"],
      members: [{ name: "one", addresses: ["192.0.2.1"] }],
    };
    expect(requirementError(request)).toMatch(/Success condition/);
    expect(
      requirementError({
        ...request,
        condition: { kind: "threshold", n: 2, parts: [{ kind: "member", member: "one" }] },
      }),
    ).toMatch(/threshold/);
    expect(
      requirementError({
        ...request,
        condition: { kind: "threshold", n: 1, parts: [{ kind: "member", member: "one" }] },
      }),
    ).toBeNull();
  });
  it("describes nested AND and OR groups without flattening their meaning", () => {
    expect(
      conditionSentence({
        kind: "and",
        parts: [
          { kind: "member", member: "auth" },
          {
            kind: "or",
            parts: [
              { kind: "member", member: "east" },
              { kind: "member", member: "west" },
            ],
          },
        ],
      }),
    ).toBe("All of (auth, Any of (east, west))");
  });
  it("opens a saved assessment in only the addressed pane", () => {
    const workspace = initial();
    const split = reduce(workspace, { type: "split", id: workspace.focus, dir: "row" });
    const next = reduce(split, {
      type: "open-assessment",
      id: split.focus,
      assessmentId: "a1",
      runId: "r1",
    });
    expect(panes(next.root).find((p) => p.id === workspace.focus)?.view).toBe("trace");
    expect(panes(next.root).find((p) => p.id === split.focus)).toMatchObject({
      view: "assessments",
      assessmentId: "a1",
      assessmentRunId: "r1",
    });
  });
});
