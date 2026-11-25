import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import { ME_OPERATOR } from "../test/fixtures";
import { mockApi } from "../test/fetchMock";
import AssessmentsPage from "./AssessmentsPage";
import type { Assessment } from "./types";

vi.mock("./AnalysisForm", () => ({
  AnalysisForm: ({ onSubmit }: { onSubmit: (input: Record<string, unknown>) => void }) => (
    <button type="button" onClick={() => onSubmit({ kind: "evaluate" })}>
      Submit mocked analysis
    </button>
  ),
}));
vi.mock("./ProposalPanel", () => ({
  ProposalPanel: ({
    onEvaluate,
  }: {
    onEvaluate: (definition: Record<string, unknown>, protectedRequirements: unknown[]) => void;
  }) => (
    <button type="button" onClick={() => onEvaluate({}, [])}>
      Evaluate mocked proposal
    </button>
  ),
}));
vi.mock("./RevisionHistory", () => ({ RevisionHistory: () => null }));
vi.mock("./LifecyclePanels", () => ({
  CollectionFollowup: () => null,
  RetentionPanel: () => null,
  RunComparison: () => null,
  proposalSummary: () => "Saved proposal",
}));

const assessment: Assessment = {
  id: "a1",
  title: "Checkout",
  revision: 1,
  created_at: "2026-09-21T08:00:00Z",
  updated_at: "2026-09-21T08:00:00Z",
  definition: {
    snapshot: "1000",
    mode: "possible",
    freshness_s: 3600,
    intents: [],
    request: {
      name: "Checkout",
      destination: "API",
      sources: ["10.0.0.0/24"],
      members: [{ name: "api", addresses: ["192.0.2.10"], proto: "tcp", port: "443" }],
      condition: { kind: "member", member: "api" },
      success: "session",
    },
  },
};

function Wrapper({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>{children}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}
function Page() {
  const [runId, setRunId] = useState<string>();
  return <AssessmentsPage assessmentId="a1" runId={runId} onNavigate={(_, run) => setRunId(run)} />;
}
function routes(runId: string) {
  const run = {
    id: runId,
    kind: "evaluate",
    state: "queued",
    created_at: assessment.created_at,
    inputs: { snapshot: "1000" },
  };
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/assessments": () => ({ body: { assessments: [assessment] } }),
    "GET /api/assessments/a1": () => ({ body: { assessment, runs: [] } }),
    "PATCH /api/assessments/a1": () => ({ body: assessment }),
    "POST /api/assessments/a1/analyses": () => ({ body: run }),
    [`GET /api/analysis-jobs/${runId}`]: () => ({ body: run }),
  });
}

describe("analysis submission navigation", () => {
  it("opens Results after starting an analysis from Scope", async () => {
    routes("scope-run");
    render(
      <Wrapper>
        <Page />
      </Wrapper>,
    );
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Scope" }));
    await user.click(screen.getByRole("button", { name: "Run analysis" }));
    await user.click(screen.getByRole("button", { name: /Check a service/ }));
    await user.click(screen.getByRole("button", { name: "Submit mocked analysis" }));

    expect(await screen.findByText(/Job: queued/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Results" })).toHaveAttribute("aria-pressed", "true");
  });

  it("opens Results after evaluating a proposal from History", async () => {
    routes("proposal-run");
    render(
      <Wrapper>
        <Page />
      </Wrapper>,
    );
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "History" }));
    await user.click(screen.getByRole("button", { name: "Evaluate mocked proposal" }));

    expect(await screen.findByText(/Job: queued/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Results" })).toHaveAttribute("aria-pressed", "true");
  });
});
