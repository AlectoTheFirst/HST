/**
 * Release scenario "Compatibility":
 * stored assessment and proposal documents, deep links and pane layouts
 * open in the Analysis shell.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import type { Assessment } from "../assessments/types";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";

const P = { kind: "result", statement: "condition-holds", answer: "true", word: "passes", quantifier: "some", condition: "forward", missing: [] };

const ASSESSMENT: Assessment = {
  id: "asm-legacy", title: "Legacy checkout reachability", revision: 4,
  created_at: "2025-03-01T08:00:00Z", updated_at: "2025-03-02T08:00:00Z",
  definition: {
    snapshot: "1000", mode: "possible", freshness_s: 3600, intents: [],
    request: { name: "Checkout", destination: "API", sources: ["10.0.0.0/24"], members: [{ name: "api", addresses: ["192.0.2.10"], proto: "tcp", port: "443" }], condition: { kind: "member", member: "api" }, success: "session" },
  },
};
const RUNS = [
  { id: "run-new", kind: "evaluate", state: "completed", created_at: "2025-03-03T08:00:00Z", inputs: { snapshot: "1000" } },
  { id: "run-old", kind: "verify", state: "completed", created_at: "2025-03-02T09:00:00Z", inputs: { snapshot: "900" } },
];
const PROPOSAL = {
  id: "chg-7", revision: 2, title: "Legacy checkout proposal 1",
  definition: { intents: [], preconditions: [], verification_state: "needs_evaluation", source_run_id: "run-old", source_assessment_revision: 3, requirements: {} },
};

function job(id: string) {
  return { id, kind: id === "run-old" ? "verify" : "evaluate", state: "completed", created_at: "2025-03-03T08:00:00Z", inputs: { snapshot: "1000" }, progress: null, error: null, result: { kind: "evaluate", result: P } };
}

function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), removeItem: (k: string) => void data.delete(k), clear: () => data.clear() },
  });
}

function routes() {
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: false } }),
    "GET /api/queries": () => ({ body: { queries: [] } }),
    "GET /api/snapshots": () => ({ body: { snapshots: [], current: null, truncated: false } }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [] } }),
    "GET /api/assessments": () => ({ body: { assessments: [ASSESSMENT] } }),
    "GET /api/assessments/asm-legacy": () => ({ body: { assessment: ASSESSMENT, runs: RUNS, proposals: [PROPOSAL] } }),
    "GET /api/analysis-jobs/run-new": () => ({ body: job("run-new") }),
    "GET /api/analysis-jobs/run-old": () => ({ body: job("run-old") }),
    "GET /api/change-revisions/chg-7/revisions": () => ({ body: { revisions: [PROPOSAL] } }),
  });
}

function renderWorkspace() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter><AuthProvider><WorkspaceProvider><Workspace /></WorkspaceProvider></AuthProvider></MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Compatibility", () => {
  beforeEach(() => {
    installStorage();
    window.history.replaceState({}, "", "/");
  });

  it("restores stored assessments and changesim panes as Analysis panes", async () => {
    window.localStorage.setItem("hst-workspace", JSON.stringify({
      root: {
        type: "split", id: "s1", dir: "row", ratio: 0.5,
        a: { type: "leaf", id: "p1", view: "assessments", assessmentId: "asm-legacy", assessmentRunId: "run-old" },
        b: { type: "leaf", id: "p2", view: "changesim" },
      },
      focus: "p1",
    }));
    routes();
    renderWorkspace();

    const panes = await screen.findAllByRole("region", { name: /^Analysis pane/ });
    expect(panes).toHaveLength(2);
    // the assessment pane opens its assessment and the stored run inside Analysis
    expect(await within(panes[0]).findByRole("heading", { name: "Legacy checkout reachability" })).toBeInTheDocument();
    expect(within(panes[0]).getByRole("tablist", { name: "Analysis sections" })).toBeInTheDocument();
    expect(await within(panes[0]).findByRole("button", { name: /^verify \/ completed/ })).toHaveAttribute("aria-pressed", "true");
    expect(within(panes[0]).getByRole("button", { name: /^evaluate \/ completed/ })).toHaveAttribute("aria-pressed", "false");
    // the changesim pane is Analysis in its simulation mode
    expect(within(panes[1]).getByRole("tablist", { name: "Analysis sections" })).toBeInTheDocument();

    const stored = JSON.parse(window.localStorage.getItem("hst-workspace")!);
    expect(stored.root.a).toMatchObject({ view: "analysis", analysisMode: "connection", assessmentId: "asm-legacy", assessmentRunId: "run-old" });
    expect(stored.root.b).toMatchObject({ view: "analysis", analysisMode: "simulation" });
  });

  it("opens an assessment link with its run in Analysis and keeps the link", async () => {
    window.history.replaceState({}, "", "/?assessment=asm-legacy&assessment_run=run-old");
    routes();
    renderWorkspace();

    const pane = await screen.findByRole("region", { name: /^Analysis pane/ });
    expect(await within(pane).findByRole("heading", { name: "Legacy checkout reachability" })).toBeInTheDocument();
    expect(await within(pane).findByRole("button", { name: /^verify \/ completed/ })).toHaveAttribute("aria-pressed", "true");
    expect(within(pane).getByRole("button", { name: /^evaluate \/ completed/ })).toHaveAttribute("aria-pressed", "false");
    await waitFor(() => expect(window.location.search).toBe("?assessment=asm-legacy&assessment_run=run-old"));
  });

  it("opens a saved proposal of a stored assessment through the Analysis History section", async () => {
    window.history.replaceState({}, "", "/?assessment=asm-legacy");
    routes();
    const user = userEvent.setup();
    renderWorkspace();

    const pane = await screen.findByRole("region", { name: /^Analysis pane/ });
    await within(pane).findByRole("heading", { name: "Legacy checkout reachability" });
    await user.click(within(pane).getByRole("tab", { name: "History" }));

    expect(await within(pane).findByRole("heading", { name: "Saved repair proposals" })).toBeInTheDocument();
    expect(within(pane).getByRole("heading", { name: "Legacy checkout proposal 1 / revision 2" })).toBeInTheDocument();
    expect(within(pane).getByText("Needs evaluation")).toBeInTheDocument();
    expect(within(pane).getByText("Original run run-old, assessment revision 3")).toBeInTheDocument();
  });
});
