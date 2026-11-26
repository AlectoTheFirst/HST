/**
 * Release scenario "Navigation/accessibility",
 * keyboard part: the Analysis section tabs, the run selection and the main
 * Business Applications actions are reached with Tab and operated with Enter
 * or Space, and result, execution state and coverage are stated in words.
 * A narrow split pane and reading without colour stay manual checks.
 */

import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import AnalysisWorkspace from "../analysis/AnalysisWorkspace";
import ApplicationsPage from "../applications/ApplicationsPage";
import type { ApplicationRevision, BusinessApplicationDefinition } from "../applications/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";

type User = ReturnType<typeof userEvent.setup>;

async function tabTo(user: User, target: HTMLElement, limit = 80) {
  for (let i = 0; i < limit && document.activeElement !== target; i++) await user.tab();
  expect(target).toHaveFocus();
}

function wrap(node: React.ReactNode) {
  return <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><AuthProvider>{node}</AuthProvider></MemoryRouter></QueryClientProvider>;
}

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };
const P = { kind: "result", statement: "condition-holds", answer: "true", word: "passes", quantifier: "some", condition: "forward", missing: [] };

describe("Keyboard use of Analysis", () => {
  const run = (id: string, item: string, execution: string, coverage: string) => ({ id, item_id: item, execution, result: null, coverage, result_ref: `analysis-run:${id}` });
  const session = {
    id: "session-9", revision: 2, title: "Checkout connections", created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "d".repeat(64),
    definition: { schema_version: 1, id: "session-9", revision: 2, title: "Checkout connections", input: { kind: "connection", snapshot: SNAPSHOT, connections: [], changes: [], mode: "possible" }, runs: [run("run-1", "web-to-api", "completed", "complete"), run("run-2", "api-to-db", "failed", "not_started")] },
    results: {},
  };

  it("reaches and operates the section tabs and the run selection, and states state in words", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: [session] } }),
      "GET /api/analysis-sessions/session-9": () => ({ body: session }),
      "GET /api/analysis-sessions/session-9/history": () => ({ body: { revisions: [session] } }),
      "GET /api/analysis-jobs/run-1": () => ({ body: { id: "run-1", kind: "evaluate", state: "completed", progress: null, error: null, result: { kind: "evaluate", result: P } } }),
      "GET /api/analysis-jobs/run-2": () => ({ body: { id: "run-2", kind: "evaluate", state: "failed", progress: null, error: "the engine stopped", result: null } }),
    });
    const selected: Array<string | undefined> = [];
    const user = userEvent.setup();
    function Harness() {
      const [runId, setRunId] = useState<string>();
      return <AnalysisWorkspace sessionId="session-9" onNavigate={() => undefined} runId={runId} onRun={(id) => { selected.push(id); setRunId(id); }} />;
    }
    render(wrap(<Harness />));

    // result, execution state and coverage are words, not only colour
    expect(await screen.findByText("Session execution: failed")).toBeInTheDocument();
    expect(screen.getByText("Session coverage: partial")).toBeInTheDocument();
    expect(screen.getByText("Coverage: complete")).toBeInTheDocument();
    expect(screen.getByText("Coverage: not started")).toBeInTheDocument();
    expect(await screen.findByText("Execution: completed")).toBeInTheDocument();
    expect(await screen.findByText("Execution: failed")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("the engine stopped");
    expect(screen.getAllByText("Passes").length).toBeGreaterThan(0);

    // the section tabs
    const history = screen.getByRole("tab", { name: "History" });
    await tabTo(user, history);
    await user.keyboard("{Enter}");
    expect(history).toHaveAttribute("aria-selected", "true");
    expect(history).toHaveFocus();
    expect(await screen.findByRole("heading", { name: "History" })).toBeInTheDocument();
    const verification = screen.getByRole("tab", { name: "Verification" });
    await user.tab();
    expect(verification).toHaveFocus();
    await user.keyboard(" ");
    expect(verification).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("heading", { name: "Verification" })).toBeInTheDocument();
    const results = screen.getByRole("tab", { name: "Results" });
    await user.tab({ shift: true });
    await user.tab({ shift: true });
    await user.tab({ shift: true });
    expect(results).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(results).toHaveAttribute("aria-selected", "true");

    // the run selection
    const second = await screen.findByRole("button", { name: "api-to-db" });
    await tabTo(user, second);
    await user.keyboard("{Enter}");
    expect(second).toHaveAttribute("aria-pressed", "true");
    expect(second).toHaveFocus();
    expect(selected).toEqual(["run-2"]);
    await user.keyboard(" ");
    expect(second).toHaveAttribute("aria-pressed", "false");
    expect(selected).toEqual(["run-2", undefined]);
  });
});

describe("Keyboard use of Business Applications", () => {
  const definition = {
    schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "ready",
    services: [{ id: "storefront", name: "Storefront", connection_ids: ["web-to-api", "api-to-db"], component_roles: [] }],
    groups: [{ id: "web", name: "Web", members: [{ id: "web-1", address: "10.20.0.10" }] }, { id: "api", name: "API", members: [{ id: "api-1", address: "10.30.0.10" }] }, { id: "db", name: "Database", members: [{ id: "db-1", address: "10.40.0.10" }] }],
    connections: [
      { id: "web-to-api", name: "Frontend to API", source: "web", destination: "api", protocol: "tcp", destination_ports: [8443], success: "forward", destination_condition: { kind: "member", member: "api-1", parts: [] } },
      { id: "api-to-db", name: "API to database", source: "api", destination: "db", protocol: "tcp", destination_ports: [5432], success: "forward", destination_condition: { kind: "member", member: "db-1", parts: [] } },
    ],
  } as unknown as BusinessApplicationDefinition;
  const application: ApplicationRevision = { id: "checkout", revision: 2, name: "Checkout", digest: "f".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition };
  const request = { name: "web-to-api", destination: "API", sources: ["10.20.0.10"], members: [{ name: "api", addresses: ["10.30.0.10"] }], condition: { kind: "member", member: "api" }, proto: "tcp", port: "8443", success: "forward" };

  it("opens an application, selects connections, resolves coverage and starts analysis from the keyboard", async () => {
    const resolves: MockRequest[] = [];
    const sessions: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application } }),
      "GET /api/snapshots": () => ({ body: { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false } }),
      "POST /api/business-applications/checkout/resolve": (req) => {
        resolves.push(req);
        return { body: { application: { id: "checkout", revision: 2, digest: application.digest }, snapshot: SNAPSHOT, digest: "9".repeat(64), ready: true, selection: { service_ids: [], connection_ids: ["web-to-api"] }, groups: {}, connections: [{ id: "web-to-api", service_id: "storefront", readiness: "ready", request, issues: [] }], issues: [] } };
      },
      "POST /api/analysis-sessions": (req) => { sessions.push(req); return { status: 201, body: { id: "kb-session", revision: 1, input_digest: "1".repeat(64) } }; },
      "POST /api/analysis-sessions/kb-session/runs": () => ({ status: 202, body: { id: "kb-session", results: {} } }),
    });
    const opened: string[] = [];
    function Harness() {
      const [applicationId, setApplicationId] = useState<string | undefined>("checkout");
      return <ApplicationsPage applicationId={applicationId} onNavigate={setApplicationId} onOpenAnalysis={(id) => opened.push(id)} />;
    }
    const user = userEvent.setup();
    render(wrap(<Harness />));

    expect(await screen.findByRole("heading", { name: "Checkout" })).toBeInTheDocument();

    // the section tabs
    const connections = screen.getByRole("tab", { name: "Connections" });
    await tabTo(user, connections);
    await user.keyboard("{Enter}");
    expect(connections).toHaveAttribute("aria-selected", "true");
    const dropDb = screen.getByRole("checkbox", { name: "Select API to database" });
    await tabTo(user, dropDb);
    await user.keyboard(" ");
    expect(dropDb).not.toBeChecked();

    const coverage = screen.getByRole("tab", { name: "Coverage" });
    await tabTo(user, coverage);
    await user.keyboard("{Enter}");
    expect(coverage).toHaveAttribute("aria-selected", "true");
    const picker = screen.getByLabelText("Coverage snapshot");
    await screen.findByRole("option", { name: /\[full\]/ });
    await tabTo(user, picker);
    // user-event has no keyboard model for a native select; the choice itself is made with selectOptions
    await user.selectOptions(picker, "4000");
    expect(await screen.findByText("All selected connections ready")).toBeInTheDocument();
    expect(screen.getByText("web-to-api: ready")).toBeInTheDocument();
    expect(resolves.map((req) => req.body)).toEqual([{ snapshot: "4000", connection_ids: ["web-to-api"] }]);

    const analyze = screen.getByRole("button", { name: "Analyze ready connections" });
    await tabTo(user, analyze);
    await user.keyboard("{Enter}");
    await waitFor(() => expect(opened).toEqual(["kb-session"]));
    expect(sessions).toHaveLength(1);
  });

  it("previews and commits a YAML import from the keyboard", async () => {
    const commits: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: { snapshots: [], current: null, truncated: false } }),
      "POST /api/business-applications/import/preview": () => ({ body: { application_id: "checkout", base_revision: 0, base_digest: "", result_digest: "a".repeat(64), preview_digest: "b".repeat(64), definition: {}, changes: { services_created: ["storefront"] }, mapping_issues: [], no_op: false } }),
      "POST /api/business-applications/import/commit": (req) => { commits.push(req); return { body: application }; },
    });
    const navigated: Array<string | undefined> = [];
    const user = userEvent.setup();
    render(wrap(<ApplicationsPage onNavigate={(id) => navigated.push(id)} onOpenAnalysis={() => undefined} />));

    const editor = await screen.findByRole("textbox", { name: "Definition YAML" });
    await tabTo(user, editor);
    await user.keyboard("id: checkout");
    const previewButton = screen.getByRole("button", { name: "Preview import" });
    await tabTo(user, previewButton);
    await user.keyboard("{Enter}");
    const preview = await screen.findByRole("region", { name: "Import preview" });
    expect(within(preview).getByText("services created:").parentElement).toHaveTextContent("storefront");
    const commit = within(preview).getByRole("button", { name: "Commit revision" });
    await tabTo(user, commit);
    await user.keyboard("{Enter}");
    await waitFor(() => expect(navigated).toEqual(["checkout"]));
    expect(commits).toHaveLength(1);
  });
});
