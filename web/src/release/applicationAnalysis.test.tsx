/**
 * Release scenario "Application analysis":
 * select connections, review snapshot, run, inspect each finding and its
 * sources without recursive drilling. Driven through the workspace, from
 * Business Applications to the Analysis pane that shows the results.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import type { ApplicationRevision, BusinessApplicationDefinition, ResolvedApplication } from "../applications/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";

const SNAPSHOTS = { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false };
const REFERENCE = { snapshot: "4000", manifest_sha256: "a".repeat(64), estate: "test", observation_floor_ms: null };
const P = { kind: "result", statement: "condition-holds", answer: "true", word: "passes", quantifier: "some", condition: "forward", missing: [] };
const F = { ...P, answer: "false", word: "fails" };

const member = (id: string, address: string) => ({ id, address });
const connection = (id: string, name: string, source: string, destination: string, target: string) => ({ id, name, source, destination, protocol: "tcp", destination_ports: [443], success: "forward", destination_condition: { kind: "member", member: target, parts: [] } });
const DEFINITION = {
  schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "ready",
  services: [{ id: "storefront", name: "Storefront", connection_ids: ["clients-to-web", "web-to-api"], component_roles: [] }],
  groups: [
    { id: "clients", name: "Clients", members: [member("lan", "10.9.0.0/24")] },
    { id: "frontend", name: "Frontend", members: [member("web-1", "10.20.0.10")] },
    { id: "api", name: "API", members: [member("api-1", "10.30.0.10")] },
    { id: "database", name: "Database", members: [member("db-1", "10.40.0.10")] },
  ],
  connections: [
    connection("clients-to-web", "Clients to frontend", "clients", "frontend", "web-1"),
    connection("web-to-api", "Frontend to API", "frontend", "api", "api-1"),
    connection("api-to-db", "API to database", "api", "database", "db-1"),
  ],
} as unknown as BusinessApplicationDefinition;
const APPLICATION: ApplicationRevision = { id: "checkout", revision: 5, name: "Checkout", digest: "f".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition: DEFINITION };

const request = (id: string) => ({ name: id, destination: id, sources: ["10.9.0.0/24"], members: [{ name: "target", addresses: ["10.30.0.10"] }], condition: { kind: "member", member: "target" }, proto: "tcp", port: "443", success: "forward" });

/** The resolution of exactly the requested connections: clients-to-web is
 *  ready and in a service, web-to-api is unresolved at the snapshot. */
function resolve(ids: string[]): ResolvedApplication {
  const all = {
    "clients-to-web": { id: "clients-to-web", service_id: "storefront", readiness: "ready" as const, request: request("clients-to-web"), issues: [] },
    "web-to-api": { id: "web-to-api", service_id: "storefront", readiness: "unresolved" as const, request: null, issues: [{ code: "inventory-not-found", path: "groups.api.members.api-1", detail: "api-1 was not found at snapshot 4000", severity: "error" }] },
    "api-to-db": { id: "api-to-db", service_id: null, readiness: "ready" as const, request: request("api-to-db"), issues: [] },
  };
  return {
    application: { id: "checkout", revision: 5, digest: APPLICATION.digest }, snapshot: REFERENCE, digest: "9".repeat(64), ready: false,
    selection: { service_ids: [], connection_ids: ids }, groups: {},
    connections: ids.map((id) => all[id as keyof typeof all]),
    issues: [],
  } as unknown as ResolvedApplication;
}

const RESULT = {
  kind: "evaluate",
  findings: [
    { id: "edge-acl", candidates: ["fw-edge rule 10"], result: P, reason: "permit tcp/443 from clients" },
    { id: "web-acl", candidates: ["fw-web rule 40"], result: F, reason: "default deny on the frontend segment" },
  ],
};

function sessionRecord(input: Record<string, unknown>, review: unknown) {
  return {
    id: "app-session-1", revision: 2, title: "Checkout analysis", created_by: 1, created_at: "2026-01-02T00:00:00Z", input_digest: "1".repeat(64),
    definition: {
      schema_version: 1, id: "app-session-1", revision: 2, title: "Checkout analysis", input,
      runs: [{ id: "run-cw", item_id: "clients-to-web", execution: "completed", result: F, coverage: "complete", result_ref: "analysis-run:run-cw" }],
    },
    results: { review, bindings: { "clients-to-web": { assessment_id: "asm-cw", assessment_revision: 1 } } },
  };
}

function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), removeItem: (k: string) => void data.delete(k), clear: () => data.clear() },
  });
}

describe("Application analysis", () => {
  beforeEach(() => {
    installStorage();
    window.history.replaceState({}, "", "/");
    window.localStorage.setItem("hst-workspace", JSON.stringify({ root: { type: "leaf", id: "p1", view: "applications", applicationId: "checkout" }, focus: "p1" }));
  });

  it("analyzes the selected ready connections and follows the session to its displayed findings", async () => {
    const resolves: MockRequest[] = [];
    const created: MockRequest[] = [];
    const queued: MockRequest[] = [];
    let session: ReturnType<typeof sessionRecord> | undefined;
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: false } }),
      "GET /api/queries": () => ({ body: { queries: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "GET /api/business-applications": () => ({ body: { applications: [APPLICATION] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: APPLICATION } }),
      "POST /api/business-applications/checkout/resolve": (req) => { resolves.push(req); return { body: resolve((req.body as { connection_ids: string[] }).connection_ids) }; },
      "POST /api/analysis-sessions": (req) => {
        created.push(req);
        const body = req.body as { input: Record<string, unknown>; review: unknown };
        session = sessionRecord(body.input, body.review);
        return { status: 201, body: { ...session, revision: 1, definition: { ...session.definition, revision: 1, runs: [] } } };
      },
      "POST /api/analysis-sessions/app-session-1/runs": (req) => { queued.push(req); return { status: 202, body: session }; },
      "GET /api/analysis-sessions": () => ({ body: { sessions: session ? [session] : [] } }),
      "GET /api/analysis-sessions/app-session-1": () => ({ body: session }),
      "GET /api/analysis-jobs/run-cw": () => ({ body: { id: "run-cw", kind: "evaluate", state: "completed", progress: null, error: null, result: RESULT } }),
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter><AuthProvider><WorkspaceProvider><Workspace /></WorkspaceProvider></AuthProvider></MemoryRouter>
      </QueryClientProvider>,
    );

    // select two of the three explicit connections
    await user.click(await screen.findByRole("tab", { name: "Connections" }));
    await user.click(screen.getByRole("checkbox", { name: "Select API to database" }));
    // review the snapshot of the selection
    await user.click(screen.getByRole("tab", { name: "Coverage" }));
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Coverage snapshot"), "4000");
    expect(await screen.findByText("Not all selected connections ready")).toBeInTheDocument();
    expect(screen.getByText("web-to-api: unresolved")).toBeInTheDocument();
    expect(resolves.map((req) => req.body)).toEqual([{ snapshot: "4000", connection_ids: ["clients-to-web", "web-to-api"] }]);

    await user.click(screen.getByRole("button", { name: "Analyze ready connections" }));

    // one session of the selected ready connection; the unresolved one is
    // recorded in the review and not submitted
    await waitFor(() => expect(queued).toHaveLength(1));
    expect(created).toHaveLength(1);
    const body = created[0].body as { input: { kind: string; snapshot: unknown; connections: Array<{ id: string; source: { kind: string; reference: { application: { id: string; revision: number }; connection_id: string; service_id: string } } }> }; review: { selected_connection_ids: string[]; unresolved: Array<{ id: string }> } };
    expect(body.input.kind).toBe("connection");
    expect(body.input.snapshot).toEqual(REFERENCE);
    expect(body.input.connections.map((item) => item.id)).toEqual(["clients-to-web"]);
    expect(body.input.connections[0].source).toMatchObject({ kind: "application_connection", reference: { application: { id: "checkout", revision: 5 }, service_id: "storefront", connection_id: "clients-to-web" } });
    expect(body.review.selected_connection_ids).toEqual(["clients-to-web", "web-to-api"]);
    expect(body.review.unresolved.map((item) => item.id)).toEqual(["web-to-api"]);
    expect(queued[0].body).toMatchObject({ session_revision: 1, input_digest: "1".repeat(64) });

    // the pane is now Analysis on that session, and shows its results
    const pane = await screen.findByRole("region", { name: "Analysis pane" });
    await waitFor(() => expect(window.location.search).toBe("?analysis=app-session-1"));
    expect(await within(pane).findByRole("tab", { name: "Results" })).toHaveAttribute("aria-selected", "true");
    expect(await within(pane).findByText("Session execution: completed")).toBeInTheDocument();
    expect(within(pane).getByText("Session coverage: complete")).toBeInTheDocument();
    expect(within(pane).getByRole("button", { name: "clients-to-web" })).toBeInTheDocument();

    // each finding is listed flat, and opening one shows its sources directly
    const first = await within(pane).findByRole("button", { name: /Inspect finding 1/ });
    const second = within(pane).getByRole("button", { name: /Inspect finding 2/ });
    expect(first).toHaveTextContent("fw-edge rule 10");
    expect(second).toHaveTextContent("fw-web rule 40");
    await user.click(second);
    const inspector = within(pane).getByRole("region", { name: "Finding evidence inspector" });
    expect(within(inspector).getByRole("heading", { name: "fw-web rule 40" })).toBeInTheDocument();
    expect(inspector).toHaveTextContent("default deny on the frontend segment");
    await user.click(within(pane).getByRole("button", { name: "Back to findings" }));
    await user.click(within(pane).getByRole("button", { name: /Inspect finding 1/ }));
    const firstInspector = within(pane).getByRole("region", { name: "Finding evidence inspector" });
    expect(within(firstInspector).getByRole("heading", { name: "fw-edge rule 10" })).toBeInTheDocument();
    expect(firstInspector).toHaveTextContent("permit tcp/443 from clients");
  });
});
