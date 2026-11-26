/**
 * Release scenario "Historical integrity", run comparison:
 * the session "Frontend to API" ran at snapshot 4000. The snapshot advanced,
 * and the session "Frontend to API again" ran at snapshot 4001. The History
 * section compares the two runs from their saved records. The response shapes
 * are those of tests/app/test_release_scenarios_sessions.py
 * `test_an_old_and_a_new_session_run_stay_readable_for_a_comparison`.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import AnalysisWorkspace from "../analysis/AnalysisWorkspace";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";

const PASSES = { kind: "result", statement: "condition-holds", answer: "true", word: "passes" };
const OPEN = { kind: "result", statement: "condition-holds", answer: "open", word: "not decided" };

// the summary of the stored session definition, written when the run was queued
function queued(id: string) {
  return { id, item_id: "frontend-to-api", execution: "queued", result: null, coverage: "not_started", result_ref: null };
}

function session(id: string, title: string, snapshot: string, digest: string, runId: string) {
  return {
    id,
    revision: 2,
    title,
    created_by: 1,
    created_at: "2026-11-25T00:00:00Z",
    input_digest: digest,
    results: {},
    definition: {
      schema_version: 1,
      id,
      revision: 2,
      title,
      input: {
        kind: "connection",
        snapshot: { snapshot, manifest_sha256: `manifest-${snapshot}`, estate: "synthetic" },
        connections: [],
        changes: [],
        mode: "possible",
      },
      runs: [queued(runId)],
    },
  };
}

function savedRun(id: string, snapshot: string, digest: string, result: typeof PASSES) {
  return {
    summary: queued(id),
    run: {
      id,
      assessment_id: `assessment-${id}`,
      assessment_revision: 1,
      kind: "evaluate",
      state: "completed",
      inputs: {},
      input_digest: digest,
      snapshot_refs: [
        { estate: "synthetic", manifest_sha256: `manifest-${snapshot}`, observation_floor_ms: null, snapshot },
      ],
      engine_version: "engine-release-test",
      created_at: `2026-11-25T0${snapshot === "4000" ? 1 : 2}:00:00+00:00`,
      result: { result },
    },
  };
}

const OLD = session("session-old", "Frontend to API", "4000", "1".repeat(64), "run-old");
const NEW = session("session-new", "Frontend to API again", "4001", "2".repeat(64), "run-new");

function wrap(node: React.ReactNode) {
  return (
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <AuthProvider>{node}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("Historical integrity", () => {
  it("compares the run of an old session with the run of a new session from their saved records", async () => {
    const reads: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: [NEW, OLD] } }),
      "GET /api/analysis-sessions/session-new": () => ({ body: NEW }),
      "GET /api/analysis-sessions/session-new/history": () => ({ body: { revisions: [NEW] } }),
      "GET /api/analysis-jobs/run-new": () => ({ body: savedRun("run-new", "4001", "2".repeat(64), OPEN).run }),
      "GET /api/analysis-sessions/session-old/runs/run-old": (req) => {
        reads.push(req);
        return { body: savedRun("run-old", "4000", "1".repeat(64), PASSES) };
      },
      "GET /api/analysis-sessions/session-new/runs/run-new": (req) => {
        reads.push(req);
        return { body: savedRun("run-new", "4001", "2".repeat(64), OPEN) };
      },
    });
    const user = userEvent.setup();
    render(wrap(<AnalysisWorkspace sessionId="session-new" onNavigate={() => undefined} />));
    await user.click(await screen.findByRole("tab", { name: "History" }));

    const compare = await screen.findByRole("region", { name: "Compare runs" });
    await user.selectOptions(within(compare).getByLabelText("Session A"), "session-old");
    await user.selectOptions(within(compare).getByLabelText("Run A"), "run-old");
    await user.selectOptions(within(compare).getByLabelText("Run B"), "run-new");

    const table = await within(compare).findByRole("table");
    const row = (label: string) =>
      within(within(table).getByRole("rowheader", { name: label }).closest("tr")!)
        .getAllByRole("cell")
        .map((cell) => cell.textContent);
    expect(row("Session")).toEqual(["Frontend to API", "Frontend to API again", "different"]);
    expect(row("Snapshot")).toEqual(["4000", "4001", "different"]);
    expect(row("Input digest")).toEqual(["1".repeat(64), "2".repeat(64), "different"]);
    expect(row("Engine version")).toEqual(["engine-release-test", "engine-release-test", "same"]);
    // the saved run, not the queued summary of the session definition
    expect(row("Execution")).toEqual(["completed", "completed", "same"]);
    expect(row("Result")).toEqual(["passes", "not decided", "different"]);
    expect(within(compare).getByRole("region", { name: "Saved result of run A" })).toHaveTextContent("passes");
    expect(within(compare).getByRole("region", { name: "Saved result of run B" })).toHaveTextContent("not decided");
    expect(reads.map((req) => req.path)).toEqual([
      "/api/analysis-sessions/session-old/runs/run-old",
      "/api/analysis-sessions/session-new/runs/run-new",
    ]);
  });
});
