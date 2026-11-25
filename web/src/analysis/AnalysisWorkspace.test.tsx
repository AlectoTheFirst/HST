import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";
import { AiDrawerProvider, CONVERSATION_KEY, useAiDrawer } from "../ai/drawer";
import type { ApplicationRevision, ResolvedApplication } from "../applications/types";
import AnalysisWorkspace from "./AnalysisWorkspace";

const record = {
  id: "session-1",
  revision: 2,
  title: "Route change",
  created_by: 1,
  created_at: "2026-01-01T00:00:00Z",
  definition: {
    schema_version: 1,
    id: "session-1",
    revision: 2,
    title: "Route change",
    input: {
      kind: "simulation",
      snapshot: { snapshot: "100", manifest_sha256: "abc", estate: "test" },
      changes: [{ kind: "route.add", params: { prefix: "192.0.2.0/24" } }],
      scope: { flows: [], sites: [] },
      bounds: { max_flows: 50, max_seconds: 30 },
      protected: [],
    },
    runs: [
      {
        id: "simulation:session-1:r2",
        item_id: "simulation",
        execution: "completed",
        outcome: null,
        result: {
          kind: "result",
          statement: "condition-holds",
          answer: "open",
          word: "not decided",
          quantifier: null,
          condition: null,
          missing: [{ code: "not-decided", subject: null, detail: "the evaluation is open" }],
        },
        coverage: "complete",
        result_ref: "analysis-session:session-1:r2",
      },
    ],
  },
  results: {
    simulation: {
      flows: [
        {
          flow: { src: "10.0.0.1", dst: "192.0.2.1" },
          before: { detail: "denied" },
          after: { detail: "permitted" },
        },
      ],
    },
    protected: [],
  },
};

it("reopens a durable simulation with Baseline and Predicted results", async () => {
  mockApi({
    "GET /api/me": () => ({ body: ME_VIEWER }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [record] } }),
    "GET /api/analysis-sessions/session-1": () => ({ body: record }),
  });
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <AnalysisWorkspace sessionId="session-1" onNavigate={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  expect(await screen.findByRole("heading", { name: "Baseline" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Predicted" })).toBeInTheDocument();
  expect(screen.getByText(/"denied"/)).toBeInTheDocument();
  expect(screen.getByText(/"permitted"/)).toBeInTheDocument();
  expect(screen.queryByText(/Run and save simulation/)).not.toBeInTheDocument();
});

it("shows the error of a failed run export", async () => {
  mockApi({
    "GET /api/me": () => ({ body: ME_VIEWER }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [record] } }),
    "GET /api/analysis-sessions/session-1": () => ({ body: record }),
    "GET /api/analysis-sessions/session-1/export": () => ({
      status: 404,
      body: { error: "revision 2 has no export" },
    }),
  });
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <AnalysisWorkspace sessionId="session-1" onNavigate={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await userEvent.click(await screen.findByRole("button", { name: "Export run" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("revision 2 has no export");
});

it("executes a saved inline connection draft", async () => {
  const draft = {
    ...record,
    revision: 1,
    title: "Saved trace connection",
    input_digest: "a".repeat(64),
    definition: {
      schema_version: 1,
      id: "session-1",
      revision: 1,
      title: "Saved trace connection",
      input: {
        kind: "connection",
        snapshot: { snapshot: "100", manifest_sha256: "abc", estate: "test" },
        connections: [],
        changes: [],
        mode: "possible",
      },
      runs: [],
    },
    results: {},
  };
  let submitted = false;
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [draft] } }),
    "GET /api/analysis-sessions/session-1": () => ({ body: draft }),
    "POST /api/analysis-sessions/session-1/runs": () => {
      submitted = true;
      return { status: 202, body: draft };
    },
  });
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <AnalysisWorkspace sessionId="session-1" onNavigate={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await userEvent.click(await screen.findByRole("button", { name: "Run analysis" }));
  expect(submitted).toBe(true);
});

it("resolves an application connection for a protection with a POST at the pinned snapshot", async () => {
  const application: ApplicationRevision = {
    id: "checkout",
    revision: 3,
    name: "Checkout",
    digest: "a".repeat(64),
    created_by: 1,
    created_at: "2026-01-01T00:00:00Z",
    definition: {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "checkout",
      name: "Checkout",
      state: "ready",
      services: [{ id: "shop", name: "Shop", connection_ids: ["c1"], component_roles: [] }],
      groups: [],
      connections: [
        {
          id: "c1",
          name: "Web to API",
          source: "web",
          destination: "api",
          success: "session",
          destination_condition: { kind: "member", member: "api-one", parts: [] },
        },
      ],
    },
  };
  const resolved: ResolvedApplication = {
    application: { id: "checkout", revision: 3, digest: "a".repeat(64) },
    snapshot: { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" },
    digest: "c".repeat(64),
    ready: true,
    selection: { service_ids: [], connection_ids: ["c1"] },
    groups: {},
    connections: [{ id: "c1", service_id: "shop", readiness: "ready", request: null, issues: [] }],
    issues: [],
  };
  const resolves: unknown[] = [];
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
    "GET /api/business-applications": () => ({ body: { applications: [application] } }),
    "GET /api/requirements": () => ({ body: { requirements: [] } }),
    "POST /api/business-applications/checkout/resolve": (req) => {
      resolves.push(req.body);
      return { body: resolved };
    },
  });
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <AnalysisWorkspace onNavigate={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();

  await user.click(await screen.findByRole("button", { name: "New analysis" }));
  await screen.findByRole("option", { name: /\[full\]/ });
  await user.selectOptions(screen.getByLabelText("Pinned snapshot"), "4000");
  await screen.findByRole("option", { name: "Checkout" });
  await user.selectOptions(screen.getByLabelText("Business application"), "checkout");
  await user.selectOptions(screen.getByLabelText("Connection"), "c1");
  await user.click(screen.getByRole("button", { name: "Add application protection" }));

  expect(await screen.findByText("Checkout: c1")).toBeInTheDocument();
  expect(resolves).toEqual([{ snapshot: "4000", connection_ids: ["c1"] }]);
});

/** Whether the drawer is open and on which conversation. */
function DrawerState() {
  const drawer = useAiDrawer();
  return (
    <output aria-label="HST AI drawer">
      {drawer?.open ? `open on ${drawer.conversationId ?? "none"}` : "closed"}
    </output>
  );
}

function renderDiscuss(session: typeof record, routes: Record<string, MockHandler>) {
  mockApi({
    "GET /api/me": () => ({ body: ME_VIEWER }),
    "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: true } }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [session] } }),
    "GET /api/analysis-sessions/session-1": () => ({ body: session }),
    ...routes,
  });
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <AiDrawerProvider>
            <AnalysisWorkspace sessionId="session-1" onNavigate={() => undefined} />
            <DrawerState />
          </AiDrawerProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** A session saved from a step of conversation `c-origin`. */
const fromChat = {
  ...record,
  results: {
    ...record.results,
    review: { origin: { conversation_id: "c-origin", message_id: "m-1", step_id: "st-1" } },
  },
};

describe("Discuss in HST AI", () => {
  afterEach(() => {
    try {
      window.localStorage.removeItem(CONVERSATION_KEY);
    } catch {
      // this origin keeps no storage
    }
  });

  function creating(created: unknown[]): MockHandler {
    return (req) => {
      created.push(req.body);
      return { status: 201, body: { id: "c-new", surface: "assessment_qa", message_count: 0 } };
    };
  }

  it("opens a conversation with the saved session as its context", async () => {
    const created: unknown[] = [];
    renderDiscuss(record, { "POST /api/ai/conversations": creating(created) });

    await userEvent.click(await screen.findByRole("button", { name: "Discuss in HST AI" }));

    await waitFor(() =>
      expect(screen.getByRole("status", { name: "HST AI drawer" })).toHaveTextContent(
        "open on c-new",
      ),
    );
    expect(created).toEqual([
      expect.objectContaining({
        surface: "assessment_qa",
        context: expect.objectContaining({
          analysis_session: { id: "session-1", revision: 2 },
          snapshot: { id: "100", origin: "pinned" },
        }),
      }),
    ]);
  });

  it("reopens the conversation a session was saved from", async () => {
    const created: unknown[] = [];
    renderDiscuss(fromChat, {
      "GET /api/ai/conversations/c-origin": () => ({
        body: { id: "c-origin", surface: "drawer", message_count: 2, messages: [] },
      }),
      "POST /api/ai/conversations": creating(created),
    });

    await userEvent.click(await screen.findByRole("button", { name: "Discuss in HST AI" }));

    await waitFor(() =>
      expect(screen.getByRole("status", { name: "HST AI drawer" })).toHaveTextContent(
        "open on c-origin",
      ),
    );
    expect(created).toEqual([]);
  });

  it("starts a conversation about the session when its origin belongs to another user", async () => {
    const created: unknown[] = [];
    renderDiscuss(fromChat, {
      "GET /api/ai/conversations/c-origin": () => ({
        status: 404,
        body: { error: "no such conversation" },
      }),
      "POST /api/ai/conversations": creating(created),
    });

    await userEvent.click(await screen.findByRole("button", { name: "Discuss in HST AI" }));

    await waitFor(() =>
      expect(screen.getByRole("status", { name: "HST AI drawer" })).toHaveTextContent(
        "open on c-new",
      ),
    );
    expect(created).toHaveLength(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
