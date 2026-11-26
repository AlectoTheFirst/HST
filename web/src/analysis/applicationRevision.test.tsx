import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_VIEWER } from "../test/fixtures";
import type { ApplicationRevision } from "../applications/types";
import AnalysisWorkspace from "./AnalysisWorkspace";
import { applicationReferences, staleRevisionTexts } from "./applicationRevision";
import type { AnalysisSession, AnalysisSessionRecord, ConnectionSelection } from "./contracts";

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "a".repeat(64), estate: "test" };
const REQUEST = { name: "web", destination: "api", sources: [], members: [], condition: { kind: "member" as const, member: "api" } };

function selection(id: string, application: string, revision: number): ConnectionSelection {
  return {
    id,
    name: id,
    source: {
      kind: "application_connection",
      reference: { application: { id: application, revision }, service_id: "shop", connection_id: id },
      request: REQUEST as never,
      resolved_scope_digest: "d".repeat(64),
    },
  };
}

function session(connections: ConnectionSelection[]): AnalysisSession {
  return {
    schema_version: 1,
    id: "session-1",
    revision: 1,
    title: "Checkout proof",
    input: { kind: "connection", snapshot: SNAPSHOT, connections, changes: [], mode: "possible" },
    runs: connections.map((item) => ({ id: `run-${item.id}`, item_id: item.id, execution: "completed", coverage: "complete" })),
  };
}

const CURRENT = new Map([
  ["checkout", { revision: 2, name: "Checkout" }],
  ["billing", { revision: 4, name: "Billing" }],
]);

describe("staleRevisionTexts", () => {
  it("names the older revision of one application", () => {
    const definition = session([selection("web", "checkout", 1), selection("db", "checkout", 2)]);
    expect(staleRevisionTexts(applicationReferences(definition), CURRENT)).toEqual([
      "Application revision 1, not revision 2",
    ]);
    expect(staleRevisionTexts(applicationReferences(definition, "db"), CURRENT)).toEqual([]);
    expect(staleRevisionTexts(applicationReferences(definition, "web"), CURRENT)).toEqual([
      "Application revision 1, not revision 2",
    ]);
  });

  it("names each application when a session binds more than one", () => {
    const definition = session([selection("web", "checkout", 1), selection("pay", "billing", 3)]);
    expect(staleRevisionTexts(applicationReferences(definition), CURRENT)).toEqual([
      "Checkout revision 1, not revision 2",
      "Billing revision 3, not revision 4",
    ]);
  });

  it("returns nothing without the current revisions", () => {
    expect(staleRevisionTexts(applicationReferences(session([selection("web", "checkout", 1)])), undefined)).toEqual([]);
  });
});

describe("Analysis workspace", () => {
  it("marks a session and a run bound to an older application revision", async () => {
    const definition = session([selection("web", "checkout", 1), selection("db", "checkout", 2)]);
    const record: AnalysisSessionRecord = {
      id: "session-1",
      revision: 1,
      title: "Checkout proof",
      definition,
      results: {},
      input_digest: "1".repeat(64),
      created_by: 1,
      created_at: "2026-11-20T10:00:00Z",
    };
    const application = { id: "checkout", revision: 2, name: "Checkout" } as ApplicationRevision;
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: [record] } }),
      "GET /api/analysis-sessions/session-1": () => ({ body: record }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/analysis-jobs/run-web": () => ({ body: { id: "run-web", kind: "evaluate", state: "completed" } }),
      "GET /api/analysis-jobs/run-db": () => ({ body: { id: "run-db", kind: "evaluate", state: "completed" } }),
    });
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <AuthProvider>
            <AnalysisWorkspace sessionId="session-1" onNavigate={() => undefined} />
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const list = await screen.findByRole("listitem");
    expect(await within(list).findByRole("note")).toHaveTextContent("Application revision 1, not revision 2");
    const main = screen.getByRole("main");
    await screen.findByRole("button", { name: "web" });
    // The session header and the run of "web" show the note. The run of "db" is bound to revision 2.
    expect(within(main).getAllByRole("note").map((note) => note.textContent)).toEqual([
      "Application revision 1, not revision 2",
      "Application revision 1, not revision 2",
    ]);
    const webRow = screen.getByRole("button", { name: "web" }).closest("div")!;
    expect(within(webRow).getByRole("note")).toBeInTheDocument();
    const dbRow = screen.getByRole("button", { name: "db" }).closest("div")!;
    expect(within(dbRow).queryByRole("note")).not.toBeInTheDocument();
  });
});
