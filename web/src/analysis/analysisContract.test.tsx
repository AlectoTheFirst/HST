import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { panes } from "../workspace/layout";
import { useWorkspace, WorkspaceProvider } from "../workspace/WorkspaceContext";
import AnalysisWorkspace from "./AnalysisWorkspace";

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };

function wrap(node: React.ReactNode) {
  return (
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>{node}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

it("saves a simulation draft without running it", async () => {
  const created: unknown[] = [];
  let ran = false;
  const navigated: Array<string | undefined> = [];
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [] } }),
    "GET /api/snapshots": () => ({
      body: {
        snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }],
        current: 4000,
        truncated: false,
      },
    }),
    "GET /api/business-applications": () => ({ body: { applications: [] } }),
    "GET /api/requirements": () => ({ body: { requirements: [] } }),
    "GET /api/analysis-snapshot": () => ({ body: SNAPSHOT }),
    "POST /api/analysis-sessions": (req) => {
      created.push(req.body);
      return { status: 201, body: { id: "draft-1", revision: 1, input_digest: "a".repeat(64) } };
    },
    "POST /api/analysis-sessions/draft-1/runs": () => {
      ran = true;
      return { status: 202, body: {} };
    },
  });
  render(wrap(<AnalysisWorkspace onNavigate={(id) => navigated.push(id)} />));
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "New analysis" }));
  await screen.findByRole("option", { name: /\[full\]/ });
  await user.selectOptions(screen.getByLabelText("Pinned snapshot"), "4000");
  await user.click(screen.getByRole("button", { name: "Add firewall change" }));
  await user.click(screen.getByRole("button", { name: "Save draft" }));

  await waitFor(() => expect(navigated).toContain("draft-1"));
  expect(created).toHaveLength(1);
  expect(ran).toBe(false);
});

const connectionSession = {
  id: "session-9",
  revision: 2,
  title: "Checkout connections",
  created_by: 1,
  created_at: "2026-01-01T00:00:00Z",
  input_digest: "d".repeat(64),
  definition: {
    schema_version: 1,
    id: "session-9",
    revision: 2,
    title: "Checkout connections",
    input: {
      kind: "connection",
      snapshot: SNAPSHOT,
      connections: [],
      changes: [],
      mode: "possible",
    },
    runs: [
      {
        id: "run-1",
        item_id: "web-to-api",
        execution: "completed",
        result: {
          kind: "result",
          statement: "condition-holds",
          answer: "open",
          word: "not decided",
          quantifier: null,
          condition: null,
          missing: [],
        },
        coverage: "partial",
        result_ref: "analysis-run:run-1",
      },
    ],
  },
  results: {
    bindings: { "web-to-api": { assessment_id: "a1", assessment_revision: 1 } },
    admission: {
      omitted: ["api-to-db"],
      limit: 8,
      reason:
        "at most 8 unfinished analyses per actor; run the session again once runs finish to submit the omitted connections",
    },
  },
};

it("shows each run's coverage and the connections admission left out, and runs those", async () => {
  let reran = false;
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [connectionSession] } }),
    "GET /api/analysis-sessions/session-9": () => ({ body: connectionSession }),
    "GET /api/analysis-jobs/run-1": () => ({
      body: {
        id: "run-1",
        kind: "evaluate",
        state: "completed",
        progress: null,
        error: null,
        result: null,
      },
    }),
    "POST /api/analysis-sessions/session-9/runs": (req) => {
      reran = (req.body as { session_revision: number }).session_revision === 2;
      return { status: 202, body: connectionSession };
    },
  });
  render(wrap(<AnalysisWorkspace sessionId="session-9" onNavigate={() => undefined} />));
  expect(await screen.findByText("Coverage: partial")).toBeInTheDocument();
  const omitted = screen.getByRole("region", { name: "Omitted connections" });
  expect(omitted).toHaveTextContent("api-to-db");
  expect(omitted).toHaveTextContent("at most 8 unfinished analyses per actor");
  await userEvent.click(screen.getByRole("button", { name: "Run omitted connections" }));
  await waitFor(() => expect(reran).toBe(true));
});

function LinkHarness() {
  const workspace = useWorkspace()!;
  const focused = panes(workspace.state.root).find((pane) => pane.id === workspace.state.focus)!;
  return (
    <>
      <output>
        {focused.view}:{focused.analysisSessionId ?? ""}:{focused.analysisSection ?? ""}
      </output>
      <button
        type="button"
        onClick={() =>
          workspace.dispatch({ type: "set-analysis-section", id: focused.id, section: "history" })
        }
      >
        History
      </button>
    </>
  );
}

it("opens the contract link form and writes the section into it", async () => {
  window.history.replaceState({}, "", "/?analysis=session-4&analysis_section=verification");
  render(
    <WorkspaceProvider>
      <LinkHarness />
    </WorkspaceProvider>,
  );
  expect(document.querySelector("output")).toHaveTextContent("analysis:session-4:verification");
  await userEvent.click(screen.getByRole("button", { name: "History" }));
  await waitFor(() =>
    expect(window.location.search).toBe("?analysis=session-4&analysis_section=history"),
  );
});

function PaneAnalysis() {
  const workspace = useWorkspace()!;
  const pane = panes(workspace.state.root).find((item) => item.id === workspace.state.focus)!;
  return (
    <AnalysisWorkspace
      sessionId={pane.analysisSessionId}
      section={pane.analysisSection}
      onSection={(section) =>
        workspace.dispatch({ type: "set-analysis-section", id: pane.id, section })
      }
      onNavigate={(id) => workspace.dispatch({ type: "open-analysis", id: pane.id, sessionId: id })}
    />
  );
}

it("returns to Results when Back leaves the entry where a section was chosen", async () => {
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [connectionSession] } }),
    "GET /api/analysis-sessions/session-9": () => ({ body: connectionSession }),
    "GET /api/analysis-sessions/session-9/history": () => ({
      body: { revisions: [connectionSession] },
    }),
    "GET /api/analysis-jobs/run-1": () => ({
      body: {
        id: "run-1",
        kind: "evaluate",
        state: "completed",
        progress: null,
        error: null,
        result: null,
      },
    }),
  });
  window.history.replaceState({}, "", "/?analysis=session-9");
  render(
    wrap(
      <WorkspaceProvider>
        <PaneAnalysis />
      </WorkspaceProvider>,
    ),
  );
  await waitFor(() => expect(window.history.state.hstWorkspace).toBeDefined());
  const before = window.history.state;
  await userEvent.click(await screen.findByRole("tab", { name: "History" }));
  await waitFor(() =>
    expect(window.location.search).toBe("?analysis=session-9&analysis_section=history"),
  );
  window.dispatchEvent(new PopStateEvent("popstate", { state: before }));
  await waitFor(() =>
    expect(screen.getByRole("tab", { name: "Results" })).toHaveAttribute("aria-selected", "true"),
  );
  expect(window.location.search).toBe("?analysis=session-9");
});

function PaneRunAnalysis() {
  const workspace = useWorkspace()!;
  const pane = panes(workspace.state.root).find((item) => item.id === workspace.state.focus)!;
  return (
    <AnalysisWorkspace
      sessionId={pane.analysisSessionId}
      section={pane.analysisSection}
      onSection={(section) =>
        workspace.dispatch({ type: "set-analysis-section", id: pane.id, section })
      }
      runId={pane.analysisRunId}
      onRun={(runId) => workspace.dispatch({ type: "set-analysis-run", id: pane.id, runId })}
      onNavigate={(id) => workspace.dispatch({ type: "open-analysis", id: pane.id, sessionId: id })}
    />
  );
}

it("selects the run a link names and writes the selected run into the link", async () => {
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [connectionSession] } }),
    "GET /api/analysis-sessions/session-9": () => ({ body: connectionSession }),
    "GET /api/analysis-jobs/run-1": () => ({
      body: {
        id: "run-1",
        kind: "evaluate",
        state: "completed",
        progress: null,
        error: null,
        result: null,
      },
    }),
  });
  window.history.replaceState({}, "", "/?analysis=session-9&analysis_run=run-1");
  render(<WorkspaceProvider>{wrap(<PaneRunAnalysis />)}</WorkspaceProvider>);
  const run = await screen.findByRole("button", { name: "web-to-api" });
  expect(run).toHaveAttribute("aria-pressed", "true");
  expect(run.closest("[aria-current]")).toHaveAttribute("aria-current", "true");
  await userEvent.click(run);
  await waitFor(() => expect(window.location.search).toBe("?analysis=session-9"));
  await userEvent.click(run);
  await waitFor(() =>
    expect(window.location.search).toBe("?analysis=session-9&analysis_run=run-1"),
  );
});

const simulationSession = (runs: unknown[]) => ({
  id: "sim-1",
  revision: 2,
  title: "Firewall change",
  created_by: 1,
  created_at: "2026-01-01T00:00:00Z",
  input_digest: "e".repeat(64),
  definition: {
    schema_version: 1,
    id: "sim-1",
    revision: 2,
    title: "Firewall change",
    input: {
      kind: "simulation",
      snapshot: SNAPSHOT,
      changes: [],
      scope: { flows: [], sites: [] },
      bounds: { max_flows: 50, max_seconds: 30 },
      protected: [],
    },
    runs,
  },
  results: {},
});

it.each([
  ["running", "running", "partial", "partial"],
  ["failed", "failed", "not_started", "partial"],
  ["completed", "completed", "complete", "complete"],
])(
  "states a simulation run's execution and the session's state in words (%s)",
  async (execution, sessionExecution, coverage, sessionCoverage) => {
    const session = simulationSession([
      { id: "run-s", item_id: "simulation", execution, result: null, coverage, result_ref: null },
    ]);
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: [session] } }),
      "GET /api/analysis-sessions/sim-1": () => ({ body: session }),
    });
    render(wrap(<AnalysisWorkspace sessionId="sim-1" onNavigate={() => undefined} />));
    expect(await screen.findByText(`Execution: ${execution}`)).toBeInTheDocument();
    expect(screen.getByText(`Coverage: ${coverage.replace("_", " ")}`)).toBeInTheDocument();
    expect(screen.getByText(`Session execution: ${sessionExecution}`)).toBeInTheDocument();
    expect(screen.getByText(`Session coverage: ${sessionCoverage}`)).toBeInTheDocument();
  },
);

it("does not call a connection session complete while admission left connections out", async () => {
  const done = {
    ...connectionSession,
    definition: {
      ...connectionSession.definition,
      runs: [{ ...connectionSession.definition.runs[0], coverage: "complete" }],
    },
  };
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [done] } }),
    "GET /api/analysis-sessions/session-9": () => ({ body: done }),
    "GET /api/analysis-jobs/run-1": () => ({
      body: {
        id: "run-1",
        kind: "evaluate",
        state: "completed",
        progress: null,
        error: null,
        result: null,
      },
    }),
  });
  render(wrap(<AnalysisWorkspace sessionId="session-9" onNavigate={() => undefined} />));
  expect(await screen.findByText("Session execution: completed")).toBeInTheDocument();
  expect(screen.getByText("Session coverage: partial")).toBeInTheDocument();
});

it("still opens a link of the earlier analysis_session form", () => {
  window.history.replaceState({}, "", "/?analysis_session=session-5");
  render(
    <WorkspaceProvider>
      <LinkHarness />
    </WorkspaceProvider>,
  );
  expect(document.querySelector("output")).toHaveTextContent("analysis:session-5:");
});

it("runs a connection session again for its failed and cancelled connections", async () => {
  const mixed = {
    ...connectionSession,
    results: { bindings: connectionSession.results.bindings },
    definition: {
      ...connectionSession.definition,
      runs: [
        connectionSession.definition.runs[0],
        {
          id: "run-2",
          item_id: "api-to-db",
          execution: "failed",
          result: null,
          coverage: "not_started",
          result_ref: null,
        },
      ],
    },
  };
  let reran = false;
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [mixed] } }),
    "GET /api/analysis-sessions/session-9": () => ({ body: mixed }),
    "GET /api/analysis-jobs/run-1": () => ({
      body: {
        id: "run-1",
        kind: "evaluate",
        state: "completed",
        progress: null,
        error: null,
        result: null,
      },
    }),
    "GET /api/analysis-jobs/run-2": () => ({
      body: {
        id: "run-2",
        kind: "evaluate",
        state: "failed",
        progress: null,
        error: "engine error",
        result: null,
      },
    }),
    "POST /api/analysis-sessions/session-9/runs": (req) => {
      reran = (req.body as { session_revision: number }).session_revision === 2;
      return { status: 202, body: mixed };
    },
  });
  render(wrap(<AnalysisWorkspace sessionId="session-9" onNavigate={() => undefined} />));
  expect(await screen.findByText("Session execution: failed")).toBeInTheDocument();
  await userEvent.click(
    screen.getByRole("button", { name: "Run failed and cancelled connections again" }),
  );
  await waitFor(() => expect(reran).toBe(true));
});

it("offers no second run when every connection completed", async () => {
  const done = { ...connectionSession, results: { bindings: connectionSession.results.bindings } };
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [done] } }),
    "GET /api/analysis-sessions/session-9": () => ({ body: done }),
    "GET /api/analysis-jobs/run-1": () => ({
      body: {
        id: "run-1",
        kind: "evaluate",
        state: "completed",
        progress: null,
        error: null,
        result: null,
      },
    }),
  });
  render(wrap(<AnalysisWorkspace sessionId="session-9" onNavigate={() => undefined} />));
  expect(await screen.findByText("Session execution: completed")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /again|omitted/ })).not.toBeInTheDocument();
});
