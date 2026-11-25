import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { ME_OPERATOR } from "../test/fixtures";
import { mockApi } from "../test/fetchMock";
import AssessmentsPage from "./AssessmentsPage";
import { ProposalPanel } from "./ProposalPanel";
import { CollectionFollowup } from "./LifecyclePanels";
import { traceDraft } from "./context";
import type { Assessment } from "./types";

const draft = traceDraft(
  { src: "10.0.0.1", dst: "192.0.2.1", proto: "tcp", port: "443", reply: true },
  "1000",
)!;
const assessment: Assessment = {
  id: "a",
  revision: 1,
  title: draft.title,
  definition: draft.definition,
  created_at: "2026-09-08T12:00:00Z",
  updated_at: "2026-09-08T12:00:00Z",
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

describe("assessment lifecycle review", () => {
  it("reviews a contextual draft before saving and queues its exact pinned troubleshooting request", async () => {
    const calls: unknown[] = [];
    const navigate = vi.fn();
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/assessments": () => ({ body: { assessments: [] } }),
      "GET /api/snapshots": () => ({
        body: { snapshots: [{ id: "1000", ts_ms: 1000 }], current: 1000 },
      }),
      "POST /api/assessments": ({ body }) => {
        calls.push(body);
        return { body: assessment };
      },
      "POST /api/assessments/a/analyses": ({ body }) => {
        calls.push(body);
        return { body: { id: "r" } };
      },
    });
    render(
      <Wrapper>
        <AssessmentsPage draft={draft} onNavigate={navigate} />
      </Wrapper>,
    );
    const save = await screen.findByRole("button", { name: "Review analysis scope" });
    expect(calls).toEqual([]);
    await userEvent.click(save);
    await userEvent.click(screen.getByRole("button", { name: "Continue to scope" }));
    await userEvent.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(calls).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(navigate).toHaveBeenCalledWith("a", "r");
    expect(calls).toEqual([
      expect.objectContaining({
        definition: expect.objectContaining({
          snapshot: "1000",
          request: expect.objectContaining({ success: "session", port: "443" }),
        }),
      }),
      { kind: "troubleshoot", snapshot: "1000" },
    ]);
  });

  it("reopens exact proposal evidence and reevaluates its protected requirements", async () => {
    const proposal = {
      id: "p",
      revision: 2,
      title: "Web repair",
      definition: {
        intents: [],
        requirements: draft.definition,
        protected: [{ name: "Payroll", desired: "isolated" }],
        verification_state: "needs-evaluation",
        source_run_id: "original",
        source_assessment_revision: 1,
        verified_result: null,
      },
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/change-revisions/p/revisions": () => ({ body: { revisions: [proposal] } }),
    });
    const evaluate = vi.fn();
    render(
      <Wrapper>
        <ProposalPanel
          proposals={[proposal]}
          canOperate
          assessment={assessment}
          onRefresh={vi.fn()}
          onEvaluate={evaluate}
        />
      </Wrapper>,
    );
    expect(screen.getByText("Needs evaluation")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Evaluate proposal revision" }));
    expect(evaluate).toHaveBeenCalledWith(
      expect.objectContaining({ change_id: "p", change_revision: 2, snapshot: "1000" }),
      [{ name: "Payroll", desired: "isolated" }],
    );
  });

  it("links collection results to their two immutable runs and preserves an open gap", async () => {
    const navigate = vi.fn();
    render(
      <CollectionFollowup
        assessment={{
          ...assessment,
          definition: {
            ...assessment.definition,
            collection_actions: [
              {
                source: "cp",
                host: "",
                state: "reevaluated",
                gap_closed: false,
                run_id: "before",
                reevaluation_run_id: "after",
                published_snapshot: "2000",
              },
            ],
          },
        }}
        onNavigate={navigate}
      />,
    );
    await userEvent.click(screen.getByText("cp / controller: reevaluated"));
    expect(screen.getByText("Requested evidence gap open")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Open run before collection" }));
    await userEvent.click(
      screen.getByRole("button", { name: "Open run after collection at snapshot 2000" }),
    );
    expect(navigate.mock.calls).toEqual([
      ["a", "before"],
      ["a", "after"],
    ]);
  });
});
