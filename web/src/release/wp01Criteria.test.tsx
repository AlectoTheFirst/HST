/**
 * WP-01 done-when criteria: the finding inspector shows its evidence outside any
 * disclosure, a not decided result, a failing result and an execution error stay
 * distinct runs, a retry submits the failed run's analysis, and both exports
 * download the file the server names.
 */

import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import { AnalysisResult } from "../assessments/AnalysisResult";
import AssessmentsPage from "../assessments/AssessmentsPage";
import type { Assessment } from "../assessments/types";
import { mockApi, type MockHandler, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";

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
const F = { ...P, answer: "false", word: "fails" };
const O = {
  ...P,
  answer: "open",
  word: "not decided",
  missing: [
    { code: "not-decided", subject: null, detail: "the evaluation is open" },
  ],
};

const assessment: Assessment = {
  id: "a1",
  title: "Checkout change",
  revision: 1,
  created_at: "2026-09-08T12:00:00Z",
  updated_at: "2026-09-08T12:00:00Z",
  definition: {
    request: {
      name: "Checkout",
      destination: "API",
      sources: ["10.0.0.0/24"],
      members: [
        { name: "api", addresses: ["192.0.2.10"], proto: "tcp", port: "443" },
      ],
      condition: { kind: "member", member: "api" },
      success: "session",
    },
    intents: [],
    snapshot: "1000",
    mode: "possible",
    freshness_s: 3600,
  },
};

function Wrapper({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { retry: false },
          mutations: { retry: false },
        },
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
function Page({ run }: { run?: string }) {
  const [selection, setSelection] = useState({
    id: "a1" as string | undefined,
    run,
  });
  return (
    <AssessmentsPage
      assessmentId={selection.id}
      runId={selection.run}
      onNavigate={(id, next) => setSelection({ id, run: next })}
    />
  );
}
function serve(
  runs: Record<string, unknown>[],
  extra: Record<string, MockHandler> = {},
) {
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/snapshots": () => ({
      body: {
        snapshots: [{ id: "1000", ts_ms: 1000, kind: "full" }],
        current: 1000,
        truncated: false,
      },
    }),
    "GET /api/requirements": () => ({ body: { requirements: [] } }),
    "GET /api/assessment-options": () => ({
      body: { snapshot: "1000", items: [], truncated: false },
    }),
    "GET /api/assessments": () => ({ body: { assessments: [assessment] } }),
    "GET /api/assessments/a1": () => ({ body: { assessment, runs } }),
    ...Object.fromEntries(
      runs.map((run) => [
        `GET /api/analysis-jobs/${String(run.id)}`,
        () => ({ body: run }),
      ]),
    ),
    ...extra,
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const INSPECTED: Array<{
  kind: string;
  result: Record<string, unknown>;
  button: RegExp | string;
  evidence: string[];
}> = [
  {
    kind: "evaluate",
    result: {
      kind: "evaluate",
      findings: [
        {
          id: "f1",
          candidates: ["rule-a"],
          result: F,
          reason: "rule-a denies tcp/443",
          drop_rule: "rule-a",
          evidence_refs: ["obs:fw-1:policy"],
        },
      ],
    },
    button: /Inspect finding 1/,
    evidence: ["rule-a denies tcp/443", "obs:fw-1:policy"],
  },
  {
    kind: "repair",
    result: {
      kind: "repair",
      findings: [
        {
          id: "f1",
          candidates: ["rule-b"],
          result: P,
          cost: [1, 2, 3],
          diff: [
            {
              rule: "rule-b",
              before: { action: "drop" },
              after: { action: "accept" },
            },
          ],
          intents: [{ kind: "fw_rule.modify", params: { rule_uid: "rule-b" } }],
        },
      ],
    },
    button: /Inspect finding 1/,
    evidence: ["drop", "accept", "Ordered proposal operations"],
  },
  {
    kind: "regression",
    result: {
      kind: "regression",
      findings: [
        {
          id: "f1",
          candidates: ["edit-1"],
          result: P,
          forward_replay: {
            reproduces_failure: true,
            evaluation: { path: "r1 to r2" },
          },
        },
      ],
    },
    button: /Inspect finding 1/,
    evidence: ["Failure reproduced", "r1 to r2"],
  },
  {
    kind: "resilience",
    result: {
      kind: "resilience",
      expanded_domains: {
        "rack-7": {
          evidence_complete: false,
          effects: [{ kind: "device", uid: "dev:r7" }],
          evidence: {
            missing: ["power feed map"],
            evidence_refs: ["obs:rack-7"],
          },
        },
      },
    },
    button: "rack-7: Evidence incomplete",
    evidence: ["power feed map", "obs:rack-7"],
  },
  {
    kind: "verify",
    result: {
      kind: "verify",
      state: "deviation",
      configuration_realization: "partial",
      protected_comparison: {
        predicted: { checkout: "holds" },
        observed: { checkout: "broken" },
      },
      observation_coverage: {
        qualifies: false,
        missing: ["new policy observation"],
      },
    },
    button: "Post-deployment comparison: Deviation",
    evidence: ["new policy observation", "broken"],
  },
];

describe("finding inspector", () => {
  it.each(INSPECTED)(
    "shows the $kind evidence of one selected finding outside any disclosure",
    async ({ result, button, evidence }) => {
      render(<AnalysisResult result={result} />);
      await userEvent.click(screen.getByRole("button", { name: button }));

      const inspector = screen.getByRole("region", {
        name: "Finding evidence inspector",
      });
      for (const value of evidence) {
        const shown = within(inspector).getAllByText(
          new RegExp(value.replace(/[/]/g, "\\/")),
        );
        for (const element of shown)
          expect(element.closest("details")).toBeNull();
      }
      const disclosures = inspector.querySelectorAll("details");
      expect(disclosures).toHaveLength(1);
      expect(disclosures[0]).not.toHaveAttribute("open");
      expect(
        within(disclosures[0]).getByText("Exact finding record"),
      ).toBeInTheDocument();
      expect(inspector.querySelector("details details")).toBeNull();
    },
  );
});

describe("run outcomes", () => {
  it("keeps a not decided run, a failing run and an execution error distinct", async () => {
    const created_at = assessment.created_at;
    const open = {
      id: "r-open",
      kind: "evaluate",
      state: "completed",
      inputs: {},
      created_at,
      result: {
        result: O,
        gaps: [{ code: "rib-missing", detail: "No routing table for r1" }],
      },
    };
    const failing = {
      id: "r-fail",
      kind: "troubleshoot",
      state: "completed",
      inputs: {},
      created_at,
      result: { result: F },
    };
    const error = {
      id: "r-error",
      kind: "repair",
      state: "failed",
      inputs: { analysis: { kind: "repair" } },
      created_at,
      engine_version: "0.1.0:8ceceefdd32b7366c96e4b9c88d05d29dd7cdcaf:abc",
      error:
        "Analysis execution failed. Review pinned inputs and runtime compatibility.",
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
    serve([open, failing, error]);
    render(
      <Wrapper>
        <Page run="r-open" />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("checkbox", { name: "Show 1 failed run" }),
    );
    expect(
      screen.getByRole("button", { name: /^evaluate \/ completed/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^troubleshoot \/ completed/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^repair \/ failed/ }),
    ).toBeInTheDocument();

    const summary = () =>
      screen.getByRole("region", { name: "Outcome summary" });
    expect(await screen.findByText(/Job: completed/)).toBeInTheDocument();
    expect(
      within(summary()).getByRole("heading", { name: "Not decided" }),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText("No routing table for r1").length,
    ).toBeGreaterThan(0);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /^troubleshoot \/ completed/ }),
    );
    await waitFor(() =>
      expect(
        within(summary()).getByRole("heading", { name: "Fails" }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByText("No routing table for r1"),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^repair \/ failed/ }));
    expect(await screen.findByText(/Job: failed/)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Analysis execution failed. Review pinned inputs and runtime compatibility.",
    );
    expect(
      screen.getByText(
        /Engine build 8ceceefdd32b stopped with TypeError in ipaddress.py/,
      ),
    ).toBeInTheDocument();
    expect(
      within(summary()).queryByRole("heading", { name: "Fails" }),
    ).not.toBeInTheDocument();
    expect(
      within(summary()).queryByRole("heading", { name: "Not decided" }),
    ).not.toBeInTheDocument();
  });
});

describe("run actions", () => {
  it("retries a failed run with its recorded analysis and opens the new run", async () => {
    const failed = {
      id: "r1",
      kind: "evaluate",
      state: "failed",
      inputs: {
        analysis: { kind: "evaluate", limits: { max_evaluations: 100 } },
      },
      created_at: assessment.created_at,
      error:
        "Analysis execution failed. Review pinned inputs and runtime compatibility.",
      result: { stop_reason: "execution-failed" },
    };
    const retry = {
      id: "r2",
      kind: "evaluate",
      state: "queued",
      inputs: failed.inputs,
      created_at: assessment.created_at,
      result: null,
    };
    const submitted: MockRequest[] = [];
    serve([failed], {
      "POST /api/assessments/a1/analyses": (req) => {
        submitted.push(req);
        return { status: 202, body: retry };
      },
      "GET /api/analysis-jobs/r2": () => ({ body: retry }),
    });
    render(
      <Wrapper>
        <Page run="r1" />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", {
        name: "Retry with current revision",
      }),
    );

    expect(await screen.findByText(/Job: queued/)).toBeInTheDocument();
    expect(submitted).toHaveLength(1);
    expect(submitted[0].body).toEqual({
      kind: "evaluate",
      limits: { max_evaluations: 100 },
      retry_of: "r1",
    });
  });

  it.each([
    [
      "Export exact run",
      "/api/assessments/a1/runs/r1/export",
      "assessment-r1.json",
    ],
    [
      "Export evidence package",
      "/api/assessments/a1/runs/r1/export?portable=true",
      "assessment-r1.zip",
    ],
  ])(
    "downloads %s as the file the server names",
    async (name, url, filename) => {
      const run = {
        id: "r1",
        kind: "evaluate",
        state: "completed",
        inputs: {},
        created_at: assessment.created_at,
        result: { result: P },
      };
      serve([run], {
        "GET /api/assessments/a1/runs/r1/export": () => ({
          raw: "file-bytes",
          headers: {
            "Content-Disposition": `attachment; filename="${filename}"`,
          },
        }),
      });
      vi.stubGlobal(
        "URL",
        Object.assign(globalThis.URL, {
          createObjectURL: vi.fn(() => "blob:hst"),
          revokeObjectURL: vi.fn(),
        }),
      );
      const downloads: string[] = [];
      vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
        function (this: HTMLAnchorElement) {
          downloads.push(this.download);
        },
      );
      render(
        <Wrapper>
          <Page run="r1" />
        </Wrapper>,
      );
      await userEvent
        .setup()
        .click(await screen.findByRole("button", { name }));

      await waitFor(() => expect(downloads).toEqual([filename]));
      const requested = vi
        .mocked(fetch)
        .mock.calls.map(([input]) => String(input))
        .filter((input) => input.includes("/export"));
      expect(requested).toEqual([url]);
    },
  );
});
