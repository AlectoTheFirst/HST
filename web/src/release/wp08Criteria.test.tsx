/**
 * WP-08 "Done when": panes of the Analysis workspace keep their own session,
 * section, run selection and draft.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };

const run = (id: string, item: string) => ({ id, item_id: item, execution: "completed", result: null, coverage: "complete", result_ref: `analysis-run:${id}` });

function session(id: string, title: string, items: string[]) {
  return {
    id, revision: 1, title, created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "d".repeat(64),
    definition: {
      schema_version: 1, id, revision: 1, title,
      input: { kind: "connection", snapshot: SNAPSHOT, connections: [], changes: [], mode: "possible" },
      runs: items.map((item, index) => run(`${id}-run-${index + 1}`, item)),
    },
    results: {},
  };
}

const ALPHA = session("alpha", "Alpha analysis", ["web-to-api", "api-to-db"]);
const BETA = session("beta", "Beta analysis", ["clients-to-web", "web-to-api"]);
const job = (id: string) => ({ id, kind: "evaluate", state: "completed", created_at: "2026-01-01T00:00:00Z", inputs: { snapshot: "4000" }, progress: null, error: null, result: null });

function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), removeItem: (k: string) => void data.delete(k), clear: () => data.clear() },
  });
}

function mockSessions() {
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: false } }),
    "GET /api/queries": () => ({ body: { queries: [] } }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [ALPHA, BETA] } }),
    "GET /api/analysis-sessions/alpha": () => ({ body: ALPHA }),
    "GET /api/analysis-sessions/beta": () => ({ body: BETA }),
    "GET /api/analysis-jobs/alpha-run-1": () => ({ body: job("alpha-run-1") }),
    "GET /api/analysis-jobs/alpha-run-2": () => ({ body: job("alpha-run-2") }),
    "GET /api/analysis-jobs/beta-run-1": () => ({ body: job("beta-run-1") }),
    "GET /api/analysis-jobs/beta-run-2": () => ({ body: job("beta-run-2") }),
    "GET /api/business-applications": () => ({ body: { applications: [] } }),
    "GET /api/requirements": () => ({ body: { requirements: [] } }),
    "GET /api/snapshots": () => ({ body: { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false } }),
  });
}

function renderWorkspace() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter><AuthProvider><WorkspaceProvider><Workspace /></WorkspaceProvider></AuthProvider></MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Two Analysis panes", () => {
  beforeEach(() => {
    installStorage();
    window.history.replaceState({}, "", "/");
    window.localStorage.setItem("hst-workspace", JSON.stringify({
      root: {
        type: "split", id: "s1", dir: "row", ratio: 0.5,
        a: { type: "leaf", id: "p1", view: "analysis", analysisSessionId: "alpha" },
        b: { type: "leaf", id: "p2", view: "analysis", analysisSessionId: "beta" },
      },
      focus: "p1",
    }));
  });

  it("keeps the session, section and selected run of each pane while focus moves between them", async () => {
    mockSessions();
    const user = userEvent.setup();
    renderWorkspace();

    const first = await screen.findByRole("region", { name: "Analysis pane 1" });
    const second = screen.getByRole("region", { name: "Analysis pane 2" });
    expect(await within(first).findByRole("heading", { name: "Alpha analysis" })).toBeInTheDocument();
    expect(await within(second).findByRole("heading", { name: "Beta analysis" })).toBeInTheDocument();

    // pane 1 selects a run of its session
    await user.click(within(first).getByRole("button", { name: "api-to-db" }));
    expect(within(first).getByRole("button", { name: "api-to-db" })).toHaveAttribute("aria-pressed", "true");
    await waitFor(() => expect(window.location.search).toBe("?analysis=alpha&analysis_run=alpha-run-2"));

    // pane 2 selects another run and opens Scope
    await user.click(within(second).getByRole("button", { name: "clients-to-web" }));
    await user.click(within(second).getByRole("tab", { name: "Scope" }));
    await waitFor(() => expect(window.location.search).toBe("?analysis=beta&analysis_run=beta-run-1&analysis_section=scope"));
    expect(within(second).getByRole("heading", { name: "Scope" })).toBeInTheDocument();

    // pane 1 is unchanged
    expect(within(first).getByRole("tab", { name: "Results" })).toHaveAttribute("aria-selected", "true");
    expect(within(first).getByRole("heading", { name: "Alpha analysis" })).toBeInTheDocument();
    expect(within(first).getByRole("button", { name: "api-to-db" })).toHaveAttribute("aria-pressed", "true");
    expect(within(first).getByRole("button", { name: "web-to-api" })).toHaveAttribute("aria-pressed", "false");

    // focus returns to pane 1, and both panes keep their state
    await user.click(within(first).getByRole("heading", { name: "Alpha analysis" }));
    await waitFor(() => expect(window.location.search).toBe("?analysis=alpha&analysis_run=alpha-run-2"));
    expect(within(first).getByRole("button", { name: "api-to-db" })).toHaveAttribute("aria-pressed", "true");
    expect(within(second).getByRole("tab", { name: "Scope" })).toHaveAttribute("aria-selected", "true");
    expect(within(second).getByRole("heading", { name: "Scope" })).toBeInTheDocument();
  });

  it("keeps a New analysis draft in its own pane", async () => {
    mockSessions();
    const user = userEvent.setup();
    renderWorkspace();

    const first = await screen.findByRole("region", { name: "Analysis pane 1" });
    const second = screen.getByRole("region", { name: "Analysis pane 2" });
    await within(second).findByRole("heading", { name: "Beta analysis" });

    await user.click(within(first).getByRole("button", { name: "New analysis" }));
    const builder = await within(first).findByRole("region", { name: "Change simulation" });
    const title = within(builder).getByLabelText("Analysis title");
    await user.clear(title);
    await user.type(title, "Pane one draft");

    expect(within(second).queryByRole("region", { name: "Change simulation" })).not.toBeInTheDocument();
    expect(within(second).getByRole("heading", { name: "Beta analysis" })).toBeInTheDocument();
    expect(within(second).getByRole("tab", { name: "Results" })).toHaveAttribute("aria-selected", "true");

    await user.click(within(second).getByRole("button", { name: "New analysis" }));
    const other = await within(second).findByRole("region", { name: "Change simulation" });
    expect(within(other).getByLabelText("Analysis title")).toHaveValue("Change analysis");
    expect(within(builder).getByLabelText("Analysis title")).toHaveValue("Pane one draft");
  });
});

