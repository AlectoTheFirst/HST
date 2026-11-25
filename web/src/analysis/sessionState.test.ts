import { describe, expect, it } from "vitest";
import type { AnalysisRunSummary } from "./contracts";
import { sessionState } from "./AnalysisWorkspace";

const run = (execution: AnalysisRunSummary["execution"], coverage: AnalysisRunSummary["coverage"]): AnalysisRunSummary => ({ id: execution, item_id: execution, execution, coverage });

describe("sessionState", () => {
  it("is complete only when every run completed with complete coverage and nothing was omitted", () => {
    expect(sessionState([run("completed", "complete"), run("completed", "complete")], 0)).toEqual({ execution: "completed", coverage: "complete" });
    expect(sessionState([run("completed", "complete"), run("completed", "partial")], 0)).toEqual({ execution: "completed", coverage: "partial" });
    expect(sessionState([run("completed", "complete")], 1)).toEqual({ execution: "completed", coverage: "partial" });
  });

  it("reports a failed or cancelled child run as the session execution", () => {
    expect(sessionState([run("completed", "complete"), run("failed", "not_started")], 0)).toEqual({ execution: "failed", coverage: "partial" });
    expect(sessionState([run("completed", "complete"), run("cancelled", "not_started")], 0)).toEqual({ execution: "cancelled", coverage: "partial" });
    expect(sessionState([run("queued", "not_started"), run("failed", "not_started")], 0).execution).toBe("running");
  });

  it("has not started without runs", () => {
    expect(sessionState([], 0)).toEqual({ execution: "not started", coverage: "not started" });
  });
});
