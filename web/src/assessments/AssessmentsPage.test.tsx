import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";
import { mockApi, type MockRequest } from "../test/fetchMock";
import AssessmentsPage from "./AssessmentsPage";
import { AnalysisForm } from "./AnalysisForm";
import type { Assessment, Requirement } from "./types";
import { AiContextProvider } from "../ai/context";
import { PageContextProbe, readPageContext } from "../test/aiContext";

// The answers a stored run records, as the server writes them.
const P = {
  kind: "result",
  statement: "condition-holds",
  answer: "true",
  word: "passes",
  quantifier: "some",
  condition: "forward",
  missing: [],
};
const O = {
  ...P,
  answer: "open",
  word: "not decided",
  missing: [{ code: "not-decided", subject: null, detail: "the evaluation is open" }],
};

const request: Requirement = {
  name: "Checkout",
  destination: "API",
  sources: ["10.0.0.0/24"],
  members: [
    {
      name: "api",
      addresses: ["192.0.2.10"],
      proto: "tcp",
      port: "443",
      source_port: "1024-65535",
    },
  ],
  condition: { kind: "member", member: "api" },
  success: "session",
};
const assessment: Assessment = {
  id: "a1",
  title: "Checkout change",
  revision: 1,
  created_at: "2026-09-08T12:00:00Z",
  updated_at: "2026-09-08T12:00:00Z",
  definition: { request, intents: [], snapshot: "1000", mode: "possible", freshness_s: 3600 },
};
const snapshots = {
  snapshots: ["1000", "2000"].map((id) => ({ id, ts_ms: Number(id), kind: "full" })),
  current: 2000,
  truncated: false,
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
function Page({ initial }: { initial?: string }) {
  const [selection, setSelection] = useState({ id: initial, run: undefined as string | undefined });
  return (
    <AssessmentsPage
      assessmentId={selection.id}
      runId={selection.run}
      onNavigate={(id, run) => setSelection({ id, run })}
    />
  );
}
function base(extra = {}, viewer = false) {
  mockApi({
    "GET /api/me": () => ({ body: viewer ? ME_VIEWER : ME_OPERATOR }),
    "GET /api/snapshots": () => ({ body: snapshots }),
    "GET /api/requirements": () => ({ body: { requirements: [] } }),
    "GET /api/assessment-options": () => ({
      body: { snapshot: "1000", items: [], truncated: false },
    }),
    "GET /api/assessments": () => ({ body: { assessments: [assessment] } }),
    "GET /api/assessments/a1": () => ({
      body: { assessment, runs: [], freshness: { state: "fresh", reasons: [] } },
    }),
    ...extra,
  });
}

describe("Assessments workflow", () => {
  it("creates a structured pinned requirement with per-member service and multiple client prefixes", async () => {
    let submitted: any;
    base({
      "POST /api/assessments": ({ body }: any) => {
        submitted = body;
        return { body: { ...assessment, ...body } };
      },
    });
    render(
      <Wrapper>
        <Page />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "New assessment" }));
    await user.type(screen.getByLabelText("Assessment title"), "Web reachability");
    await user.selectOptions(screen.getByLabelText("Pinned snapshot"), "1000");
    await user.click(screen.getByRole("button", { name: "Define service manually" }));
    await user.type(screen.getByLabelText("Requirement name"), "Web clients");
    await user.type(screen.getByLabelText("Logical destination"), "Web service");
    await user.type(
      screen.getByLabelText("Client addresses or prefixes"),
      "10.1.0.0/24, 10.2.0.0/24",
    );
    await user.type(screen.getByLabelText("Member 1 addresses"), "192.0.2.8");
    await user.type(screen.getByLabelText("Member 1 protocol"), "tcp");
    await user.type(screen.getByLabelText("Member 1 destination port"), "443");
    await user.type(screen.getByLabelText("Member 1 source port"), "1024-65535");
    await user.selectOptions(screen.getByLabelText("Connectivity success"), "session");
    await user.click(screen.getByRole("button", { name: "Save assessment" }));
    expect(await screen.findByRole("heading", { name: assessment.title })).toBeInTheDocument();
    expect(submitted.definition).toMatchObject({
      snapshot: "1000",
      mode: "possible",
      request: {
        sources: ["10.1.0.0/24", "10.2.0.0/24"],
        success: "session",
        members: [
          {
            name: "member-1",
            addresses: ["192.0.2.8"],
            proto: "tcp",
            port: "443",
            source_port: "1024-65535",
          },
        ],
      },
    });
    expect(submitted.definition).not.toHaveProperty("requirement");
  });

  it("reopens a stored unknown run without rerunning it, preserving missing evidence", async () => {
    const run = {
      id: "r1",
      kind: "resilience",
      state: "completed",
      inputs: { snapshot_refs: [{ snapshot: "1000" }] },
      created_at: assessment.created_at,
      result: {
        result: O,
        gaps: [{ kind: "not-collected", detail: "Provider diversity missing" }],
        stop_reason: "max_evaluations",
        search_complete: false,
      },
    };
    base({
      "GET /api/assessments/a1": () => ({
        body: {
          assessment,
          runs: [run],
          freshness: { state: "needs-reassessment", reasons: ["freshness-expired"] },
        },
      }),
      "GET /api/analysis-jobs/r1": () => ({ body: run }),
    });
    render(
      <Wrapper>
        <Page initial="a1" />
      </Wrapper>,
    );
    expect(await screen.findByRole("heading", { name: "Not decided" })).toBeInTheDocument();
    expect(screen.getByText("Provider diversity missing")).toBeInTheDocument();
    expect(screen.getByText(/freshness-expired/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Link to this run" })).toHaveAttribute(
      "href",
      "/?assessment=a1&assessment_run=r1",
    );
    expect(screen.getByRole("button", { name: "Export exact run" })).toBeEnabled();
    expect(
      vi
        .mocked(fetch)
        .mock.calls.every(([, options]) => !options?.method || options.method === "GET"),
    ).toBe(true);
  });

  it("submits regression snapshots and limits explicitly", async () => {
    base();
    const submit = vi.fn();
    render(
      <Wrapper>
        <AnalysisForm assessment={assessment} busy={false} onSubmit={submit} />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText("Analysis"), "regression");
    await user.selectOptions(await screen.findByLabelText("Before snapshot A"), "1000");
    await user.selectOptions(screen.getByLabelText("After snapshot B"), "2000");
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(submit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(submit).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "regression",
        snapshot: "2000",
        before_snapshot: "1000",
        limits: expect.objectContaining({ max_combination_size: 2 }),
      }),
    );
  });

  it("cancels the selected job and displays its terminal cancellation", async () => {
    let state = "running";
    const run = () => ({
      id: "r1",
      kind: "evaluate",
      state,
      inputs: {},
      created_at: assessment.created_at,
      progress: { evaluated: 3 },
      result: null,
    });
    const cancel = vi.fn(() => {
      state = "cancelled";
      return { body: run() };
    });
    base({
      "GET /api/assessments/a1": () => ({ body: { assessment, runs: [run()] } }),
      "GET /api/analysis-jobs/r1": () => ({ body: run() }),
      "POST /api/analysis-jobs/r1/cancel": cancel,
    });
    render(
      <Wrapper>
        <Page initial="a1" />
      </Wrapper>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: "Cancel analysis" }));
    expect(await screen.findByText(/Job: cancelled/)).toBeInTheDocument();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("queues only explicitly selected available evidence recipes", async () => {
    const run = {
      id: "r1",
      kind: "troubleshoot",
      state: "completed",
      inputs: {},
      created_at: assessment.created_at,
      result: {
        gaps: [],
        actions: [
          {
            id: "route",
            recipe_id: "routing",
            source: "router",
            host: "r1",
            commands: ["show ip route"],
            state: "available",
          },
          {
            id: "opaque",
            recipe_id: "unsupported",
            state: "unavailable",
            reason: "Unsupported source",
          },
        ],
      },
    };
    const collect = vi.fn((_request: MockRequest) => ({ body: { actions: [] } }));
    base({
      "GET /api/assessments/a1": () => ({ body: { assessment, runs: [run] } }),
      "GET /api/analysis-jobs/r1": () => ({ body: run }),
      "POST /api/assessments/a1/collection-actions": collect,
    });
    render(
      <Wrapper>
        <Page initial="a1" />
      </Wrapper>,
    );
    const user = userEvent.setup();
    expect(await screen.findByRole("checkbox", { name: "Select unsupported" })).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: "Select routing" }));
    await user.click(screen.getByRole("button", { name: "Collect selected evidence" }));
    expect(await screen.findByText(/Collection queued/)).toBeInTheDocument();
    expect(collect.mock.calls[0][0].body).toEqual({ run_id: "r1", action_ids: ["route"] });
  });

  it("explains a failed run from the recorded engine exception and hides failed runs from the list until asked", async () => {
    const failed = {
      id: "r1",
      kind: "evaluate",
      state: "failed",
      inputs: { analysis: { kind: "evaluate" } },
      created_at: assessment.created_at,
      engine_version: "0.1.0:8ceceefdd32b7366c96e4b9c88d05d29dd7cdcaf:abc",
      error: "Analysis execution failed. Review pinned inputs and runtime compatibility.",
      result: {
        stop_reason: "execution-failed",
        runtime_exception: {
          kind: "TypeError",
          file: "ipaddress.py",
          line: 583,
          function: "__lt__",
        },
      },
    };
    const done = {
      id: "r2",
      kind: "evaluate",
      state: "completed",
      inputs: {},
      created_at: assessment.created_at,
      result: { outcomes: { before: { result: P }, after: { result: P } } },
    };
    base({
      "GET /api/assessments/a1": () => ({ body: { assessment, runs: [done, failed] } }),
      "GET /api/analysis-jobs/r1": () => ({ body: failed }),
      "GET /api/analysis-jobs/r2": () => ({ body: done }),
    });
    render(
      <Wrapper>
        <Page initial="a1" />
      </Wrapper>,
    );
    const user = userEvent.setup();
    expect(await screen.findByRole("checkbox", { name: "Show 1 failed run" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /evaluate \/ failed/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Show 1 failed run" }));
    await user.click(screen.getByRole("button", { name: /evaluate \/ failed/ }));
    expect(
      await screen.findByText(
        /Engine build 8ceceefdd32b stopped with TypeError in ipaddress.py, function __lt__, line 583/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry with current revision" })).toBeInTheDocument();
  });

  it("keeps viewer access read-only", async () => {
    base({}, true);
    render(
      <Wrapper>
        <Page initial="a1" />
      </Wrapper>,
    );
    await screen.findByRole("heading", { name: assessment.title });
    expect(screen.queryByRole("button", { name: "Edit assessment" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New assessment" })).not.toBeInTheDocument();
    expect(
      within(screen.getByRole("group", { name: "Assessment sections" })).getByRole("button", {
        name: "Evidence",
      }),
    ).toBeInTheDocument();
  });

  it("starts from a named service and saves and runs only after the final review", async () => {
    const create = vi.fn(({ body }: MockRequest) => ({
      body: { ...assessment, ...(body as object) },
    }));
    const analyze = vi.fn(() => ({
      body: { id: "new-run", kind: "troubleshoot", state: "queued" },
    }));
    base({
      "GET /api/assessment-options": () => ({
        body: {
          snapshot: "2000",
          items: [
            {
              uid: "service:checkout",
              kind: "service",
              name: "Checkout",
              selectable: true,
              definition: request,
            },
          ],
          truncated: false,
        },
      }),
      "POST /api/assessments": create,
      "POST /api/assessments/a1/analyses": analyze,
      "GET /api/analysis-jobs/new-run": () => ({
        body: {
          id: "new-run",
          kind: "troubleshoot",
          state: "queued",
          created_at: assessment.created_at,
          inputs: {},
        },
      }),
    });
    render(
      <Wrapper>
        <Page />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Troubleshoot a service/ }));
    await user.click(await screen.findByRole("button", { name: /Checkout Recorded service/ }));
    expect(screen.queryByLabelText("Requirement name")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review analysis scope" }));
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(screen.getByRole("region", { name: "Analysis review" })).toHaveTextContent("Checkout");
    expect(create).not.toHaveBeenCalled();
    expect(analyze).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    await screen.findByText(/Job: queued/);
    expect(create.mock.calls[0][0].body).toMatchObject({
      definition: {
        request,
        snapshot: "2000",
        origin_requirement: "service:checkout",
        origin_snapshot: "2000",
      },
    });
    expect(analyze).toHaveBeenCalledOnce();
  });

  it("reads the runs again after an edited assessment starts its analysis", async () => {
    const order: string[] = [];
    const run = {
      id: "new-run",
      kind: "troubleshoot",
      state: "completed",
      created_at: assessment.created_at,
      inputs: {},
      result: null,
    };
    base({
      "GET /api/assessments/a1": () => {
        order.push("detail");
        return { body: { assessment, runs: [], freshness: { state: "fresh", reasons: [] } } };
      },
      "PATCH /api/assessments/a1": () => ({ body: { ...assessment, revision: 2 } }),
      "POST /api/assessments/a1/analyses": () => {
        order.push("analyze");
        return { body: run };
      },
      "GET /api/analysis-jobs/new-run": () => ({ body: run }),
    });
    render(
      <Wrapper>
        <Page initial="a1" />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit assessment" }));
    await user.click(await screen.findByRole("button", { name: "Review analysis scope" }));
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    await waitFor(() =>
      expect(order.lastIndexOf("detail")).toBeGreaterThan(order.indexOf("analyze")),
    );
    expect(order).toContain("analyze");
  });

  it("clears a recorded service when its snapshot changes", async () => {
    const create = vi.fn();
    base({
      "GET /api/assessment-options": () => ({
        body: {
          snapshot: "2000",
          items: [
            {
              uid: "service:checkout",
              kind: "service",
              name: "Checkout",
              selectable: true,
              definition: request,
            },
          ],
          truncated: false,
        },
      }),
      "POST /api/assessments": create,
    });
    render(
      <Wrapper>
        <Page />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "New assessment" }));
    await user.click(await screen.findByRole("button", { name: /Checkout Recorded service/ }));
    await user.selectOptions(screen.getByLabelText("Pinned snapshot"), "1000");
    expect(screen.queryByRole("region", { name: "Selected service" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review analysis scope" }));
    expect(create).not.toHaveBeenCalled();
    expect(screen.getByText("Service cleared for the new snapshot")).toBeInTheDocument();
  });

  it("keeps the saved assessment accessible when analysis admission fails", async () => {
    const navigate = vi.fn();
    const create = vi.fn(() => ({ body: assessment }));
    base({
      "POST /api/assessments": create,
      "POST /api/assessments/a1/analyses": () => ({
        status: 429,
        body: { error: "Analysis queue is full" },
      }),
    });
    render(
      <Wrapper>
        <AssessmentsPage
          draft={{
            title: assessment.title,
            definition: assessment.definition,
            kind: "troubleshoot",
          }}
          onNavigate={navigate}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Review analysis scope" }));
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    await screen.findByText(/Analysis queue is full/);
    expect(create).toHaveBeenCalledOnce();
    expect(navigate).toHaveBeenCalledWith("a1");
  });

  it("opens deployment verification from the workflow card using an existing assessment", async () => {
    const deployed = {
      ...assessment,
      definition: {
        ...assessment.definition,
        deployments: [
          { reference: "Change 42", deployed_at: assessment.created_at, assessment_revision: 1 },
        ],
      },
    };
    base({
      "GET /api/assessments": () => ({
        body: {
          assessments: [deployed, { ...assessment, id: "undeployed", title: "Unreleased change" }],
        },
      }),
      "GET /api/assessments/a1": () => ({ body: { assessment: deployed, runs: [] } }),
    });
    render(
      <Wrapper>
        <Page />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Verify a deployment/ }));
    expect(screen.queryByRole("button", { name: /Unreleased change/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: /Checkout change/ }));
    expect(
      await screen.findByRole("heading", { name: "Deployment and verification" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Analysis")).toHaveValue("verify");
    expect(
      vi
        .mocked(fetch)
        .mock.calls.every(([, options]) => !options?.method || options.method === "GET"),
    ).toBe(true);
  });
});

describe("Assessments page context", () => {
  it("registers the assessment, the run in view, its snapshot and the selected finding", async () => {
    const run = {
      id: "r1",
      kind: "resilience",
      state: "completed",
      inputs: { snapshot_refs: [{ snapshot: "1000" }] },
      created_at: assessment.created_at,
      result: {
        result: O,
        gaps: [{ kind: "not-collected", detail: "Provider diversity missing" }],
        stop_reason: "max_evaluations",
        search_complete: false,
      },
    };
    base({
      "GET /api/assessments/a1": () => ({
        body: { assessment, runs: [run], freshness: { state: "current", reasons: [] } },
      }),
      "GET /api/analysis-jobs/r1": () => ({ body: run }),
    });
    render(
      <Wrapper>
        <AiContextProvider>
          <Page initial="a1" />
          <PageContextProbe />
        </AiContextProvider>
      </Wrapper>,
    );
    const user = userEvent.setup();

    await waitFor(() =>
      expect(readPageContext()).toMatchObject({
        route: { section: "results" },
        assessment: { assessment_id: "a1", revision: 1, run_id: "r1" },
        snapshot: { id: "1000", origin: "pinned" },
      }),
    );
    expect(readPageContext().assessment.finding_id).toBeUndefined();

    await screen.findByText("Provider diversity missing");
    await user.click(document.querySelector<HTMLButtonElement>("button[data-finding-button]")!);
    const findingId = (await screen.findByText(/^Finding ID: /)).textContent!.replace(
      "Finding ID: ",
      "",
    );
    await waitFor(() =>
      expect(readPageContext().assessment).toEqual({
        assessment_id: "a1",
        revision: 1,
        run_id: "r1",
        finding_id: findingId,
      }),
    );
  });
});
