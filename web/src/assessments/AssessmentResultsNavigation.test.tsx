import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { ME_OPERATOR } from "../test/fixtures";
import { mockApi } from "../test/fetchMock";
import AssessmentsPage from "./AssessmentsPage";
import type { Assessment } from "./types";

// The answers a stored run records, as the server writes them.
const P = { kind: "result", statement: "condition-holds", answer: "true", word: "passes", quantifier: "some", condition: "forward", missing: [] };
const F = { ...P, answer: "false", word: "fails" };

const assessment: Assessment = {
  id: "assessment-1",
  title: "Checkout analysis",
  revision: 4,
  created_at: "2026-09-21T08:00:00Z",
  updated_at: "2026-09-21T08:00:00Z",
  definition: {
    snapshot: "snapshot-current",
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

const run = {
  id: "run-1",
  kind: "repair",
  state: "completed",
  assessment_revision: 3,
  engine_version: "engine:1",
  created_at: "2026-09-21T08:05:00Z",
  inputs: { snapshot: "snapshot-run" },
  result: {
    findings: [
      { id: "first", candidates: ["rule-a"], result: P, reason: "First result" },
      { id: "second", candidates: ["rule-b"], result: F, reason: "Second result" },
    ],
  },
};

function Wrapper({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }));
  return <QueryClientProvider client={client}><MemoryRouter><AuthProvider>{children}</AuthProvider></MemoryRouter></QueryClientProvider>;
}

describe("assessment result navigation", () => {
  it("renders a saved run once and restores its selected finding after section navigation", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/assessments": () => ({ body: { assessments: [assessment] } }),
      "GET /api/assessments/assessment-1": () => ({ body: { assessment, runs: [run] } }),
      "GET /api/analysis-jobs/run-1": () => ({ body: run }),
      "GET /api/assessments/assessment-1/retention": () => ({ body: { retained: true } }),
      "GET /api/assessments/assessment-1/runs/run-1/replay-status": () => ({ body: { replayable: true } }),
    });
    render(<Wrapper><AssessmentsPage assessmentId="assessment-1" onNavigate={() => undefined} /></Wrapper>);
    const user = userEvent.setup();

    expect(await screen.findAllByRole("region", { name: "Saved analysis run" })).toHaveLength(1);
    const runRegion = screen.getByRole("region", { name: "Saved analysis run" });
    expect(runRegion).toHaveTextContent("3 (current is 4)");
    expect(runRegion).toHaveTextContent("snapshot-run");
    expect(runRegion).toHaveTextContent("Engine1");
    await user.click(screen.getByRole("button", { name: /Inspect finding 2/ }));
    expect(within(screen.getByRole("region", { name: "Finding evidence inspector" })).getByRole("heading", { name: "rule-b" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Evidence" }));
    expect(screen.queryByRole("region", { name: "Saved analysis run" })).not.toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Evidence retention and replay" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Results" }));
    expect(await screen.findAllByRole("region", { name: "Saved analysis run" })).toHaveLength(1);
    expect(within(screen.getByRole("region", { name: "Finding evidence inspector" })).getByRole("heading", { name: "rule-b" })).toBeInTheDocument();
  });
});
