/**
 * Release scenario "Deployment verification",
 * Analysis text: agreement with later observations verifies a prediction and
 * is not application health; a service-free simulation offers verification
 * only with an eligible prediction; a connection session leads to
 * deployment and verification through the assessment bound to each connection.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import AnalysisWorkspace from "../analysis/AnalysisWorkspace";
import type { Assessment } from "../assessments/types";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };
const FLOW = { src: "10.9.0.5", dst: "10.30.0.10", proto: "tcp", port: 443 };

function simulation(result: Record<string, unknown>) {
  return {
    id: "sim-1", revision: 2, title: "Firewall change", created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "e".repeat(64),
    definition: {
      schema_version: 1, id: "sim-1", revision: 2, title: "Firewall change",
      input: { kind: "simulation", snapshot: SNAPSHOT, changes: [{ kind: "firewall_rule", params: {} }], scope: { flows: [FLOW], sites: [] }, bounds: { max_flows: 50, max_seconds: 30 }, protected: [] },
      runs: [{ id: "run-s", item_id: "simulation", execution: "completed", result: null, coverage: "complete", result_ref: "analysis-run:run-s" }],
    },
    results: { simulation: result },
  };
}

function wrap(node: React.ReactNode) {
  return <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuthProvider>{node}</AuthProvider></MemoryRouter></QueryClientProvider>;
}

async function openVerification(session: ReturnType<typeof simulation>) {
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [session] } }),
    "GET /api/analysis-sessions/sim-1": () => ({ body: session }),
  });
  const user = userEvent.setup();
  render(wrap(<AnalysisWorkspace sessionId="sim-1" onNavigate={() => undefined} />));
  await screen.findByText("Session execution: completed");
  return user;
}

describe("Deployment verification text", () => {
  it("shows no missing prediction in Verification for a simulation with a prediction", async () => {
    const user = await openVerification(simulation({ flows: [{ flow: FLOW, before: { result: "permitted" }, after: { result: "denied" } }] }));
    // the prediction exists on Results
    expect(screen.getByRole("heading", { name: "Predicted" }).parentElement).toHaveTextContent("denied");
    await user.click(screen.getByRole("tab", { name: "Verification" }));
    const section = screen.getByRole("heading", { name: "Verification" }).parentElement!;
    expect(section).not.toHaveTextContent("No prediction");
  });

  it("does not offer verification for a simulation result that holds no prediction", async () => {
    const user = await openVerification(simulation({ flows: [{ flow: FLOW, before: { result: "permitted" }, after: null }] }));
    // Results says there is no prediction
    expect(screen.getByText("No prediction")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Verification" }));
    const section = screen.getByRole("heading", { name: "Verification" }).parentElement!;
    expect(section).toHaveTextContent("No prediction");
  });
});

describe("Deployment verification for a connection session", () => {
  const ASSESSMENT: Assessment = {
    id: "asm-api", title: "Checkout: Frontend to API", revision: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
    definition: { snapshot: "4000", mode: "possible", freshness_s: 3600, intents: [], request: { name: "web-to-api", destination: "API", sources: ["10.20.0.10"], members: [{ name: "api", addresses: ["10.30.0.10"] }], condition: { kind: "member", member: "api" }, proto: "tcp", port: "8443", success: "forward" } },
  };
  const run = (id: string, item: string) => ({ id, item_id: item, execution: "completed", result: null, coverage: "complete", result_ref: `analysis-run:${id}` });
  const session = {
    id: "session-9", revision: 2, title: "Checkout connections", created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "d".repeat(64),
    definition: { schema_version: 1, id: "session-9", revision: 2, title: "Checkout connections", input: { kind: "connection", snapshot: SNAPSHOT, connections: [], changes: [], mode: "possible" }, runs: [run("run-1", "web-to-api"), run("run-2", "api-to-db")] },
    results: { bindings: { "web-to-api": { assessment_id: "asm-api", assessment_revision: 1 }, "api-to-db": { assessment_id: "asm-db", assessment_revision: 1 } } },
  };
  const job = (id: string) => ({ id, kind: "evaluate", state: "completed", created_at: "2026-01-01T00:00:00Z", inputs: { snapshot: "4000" }, progress: null, error: null, result: null });

  beforeEach(() => {
    const data = new Map<string, string>();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), removeItem: (k: string) => void data.delete(k), clear: () => data.clear() },
    });
  });

  it("offers deployment and verification for each bound connection and opens it on the bound assessment", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: false } }),
      "GET /api/queries": () => ({ body: { queries: [] } }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: [session] } }),
      "GET /api/analysis-sessions/session-9": () => ({ body: session }),
      "GET /api/analysis-jobs/run-1": () => ({ body: job("run-1") }),
      "GET /api/analysis-jobs/run-2": () => ({ body: job("run-2") }),
      "GET /api/assessments": () => ({ body: { assessments: [ASSESSMENT] } }),
      "GET /api/assessments/asm-api": () => ({ body: { assessment: ASSESSMENT, runs: [], deployments: [] } }),
    });
    window.history.replaceState({}, "", "/?analysis=session-9&analysis_section=verification");
    const user = userEvent.setup();
    render(wrap(<WorkspaceProvider><Workspace /></WorkspaceProvider>));

    const pane = await screen.findByRole("region", { name: /^Analysis pane/ });
    const section = (await within(pane).findByRole("heading", { name: "Verification" })).parentElement!;
    const paths = within(section).getAllByRole("button").map((button) => button.textContent);
    expect(paths).toEqual(["Open deployment and verification for web-to-api", "Open deployment and verification for api-to-db"]);

    await user.click(within(section).getByRole("button", { name: "Open deployment and verification for web-to-api" }));
    await waitFor(() => expect(window.location.search).toBe("?assessment=asm-api"));
    expect(await within(pane).findByRole("heading", { name: "Deployment and verification" })).toBeInTheDocument();
    expect(within(pane).getByRole("button", { name: "Record deployment" })).toBeInTheDocument();
    expect(within(pane).getByRole("tab", { name: "Verification" })).toHaveAttribute("aria-selected", "true");
  });
});
