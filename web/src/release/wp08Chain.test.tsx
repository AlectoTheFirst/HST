/**
 * WP-08 "Done when": application, proposed change, simulation, evidence,
 * revision, recorded deployment and verification in one workspace pane.
 * The Analysis session of the application opens the assessment bound to its
 * connection in the same Analysis pane. The later steps run in that assessment.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "../auth";
import type { ApplicationRevision, BusinessApplicationDefinition, ResolvedApplication } from "../applications/types";
import type { AnalysisRun, Assessment } from "../assessments/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";

const SNAPSHOTS = {
  snapshots: [{ id: "5000", ts_ms: 5000, kind: "full" }, { id: "4000", ts_ms: 4000, kind: "full" }],
  current: 5000,
  truncated: false,
};
const REFERENCE = { snapshot: "4000", manifest_sha256: "a".repeat(64), estate: "test", observation_floor_ms: null };
const P = { kind: "result", statement: "condition-holds", answer: "true", word: "passes", quantifier: "some", condition: "forward", missing: [] };
const F = { ...P, answer: "false", word: "fails" };

const DEFINITION = {
  schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "ready",
  services: [{ id: "storefront", name: "Storefront", connection_ids: ["clients-to-web"], component_roles: [] }],
  groups: [
    { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
    { id: "frontend", name: "Frontend", members: [{ id: "web-1", address: "10.20.0.10" }] },
  ],
  connections: [{
    id: "clients-to-web", name: "Clients to frontend", source: "clients", destination: "frontend", protocol: "tcp",
    destination_ports: [443], success: "forward", destination_condition: { kind: "member", member: "web-1", parts: [] },
  }],
} as unknown as BusinessApplicationDefinition;
const APPLICATION: ApplicationRevision = { id: "checkout", revision: 5, name: "Checkout", digest: "f".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition: DEFINITION };

const REQUEST = { name: "clients-to-web", destination: "Frontend", sources: ["10.9.0.0/24"], members: [{ name: "web-1", addresses: ["10.20.0.10"] }], condition: { kind: "member", member: "web-1" }, proto: "tcp", port: "443", success: "forward" };

const RESOLUTION = {
  application: { id: "checkout", revision: 5, digest: APPLICATION.digest }, snapshot: REFERENCE, digest: "9".repeat(64), ready: true,
  selection: { service_ids: [], connection_ids: ["clients-to-web"] }, groups: {},
  connections: [{ id: "clients-to-web", service_id: "storefront", readiness: "ready", request: REQUEST, issues: [] }],
  issues: [],
} as unknown as ResolvedApplication;

const RULEBASE = { uid: "rulebase:fw-edge:LAN-WAN", name: "LAN-WAN", kind: "rulebase", device: { uid: "device:fw-edge", name: "fw-edge" }, selectable: true };
const INTENT = { kind: "fw_rule.add", params: { rulebase: RULEBASE.uid, action: "accept", position: 0 } };

const REPAIR_RESULT = {
  kind: "repair",
  cost_order: ["devices", "newly_permitted_scope", "rule_edits"],
  findings: [{ candidates: ["fw-edge rule 15"], reason: "permit tcp/443 to the frontend", result: P, desired: P, protected: {}, verified: true, intents: [INTENT], cost: [1, 1, 1], minimum_cost: true }],
};
const EVALUATE_RESULT = {
  kind: "evaluate",
  outcomes: { before: { result: F }, after: { result: P } },
  findings: [{ id: "edge-acl", candidates: ["fw-edge rule 15"], result: P, reason: "the proposed rule permits tcp/443" }],
};
const VERIFY_RESULT = { kind: "verify", state: "agreement", configuration_realization: "realized", observation_coverage: { qualifies: true }, protected_comparison: { predicted: [], observed: [] } };

function job(id: string, kind: AnalysisRun["kind"], result: Record<string, unknown>, revision: number): AnalysisRun {
  return { id, kind, state: "completed", inputs: { snapshot: "4000" }, result, created_at: "2026-01-03T00:00:00Z", assessment_revision: revision };
}

function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), removeItem: (k: string) => void data.delete(k), clear: () => data.clear() },
  });
}

describe("WP-08 workspace chain", () => {
  beforeEach(() => {
    installStorage();
    window.history.replaceState({}, "", "/");
    window.localStorage.setItem("hst-workspace", JSON.stringify({ root: { type: "leaf", id: "p1", view: "applications", applicationId: "checkout" }, focus: "p1" }));
  });

  it("goes from an application to a recorded deployment and its verification in one Analysis pane", async () => {
    const requests: Record<string, MockRequest[]> = {};
    const record = (key: string, req: MockRequest) => (requests[key] ??= []).push(req);

    let session: Record<string, unknown> | undefined;
    let assessment: Assessment = {
      id: "asm-cw", title: "Checkout: Clients to frontend", revision: 1, created_at: "2026-01-02T00:00:00Z", updated_at: "2026-01-02T00:00:00Z",
      definition: { snapshot: "4000", mode: "possible", freshness_s: 3600, intents: [], request: REQUEST },
    } as unknown as Assessment;
    const runs: AnalysisRun[] = [];
    const jobs: Record<string, AnalysisRun> = {};
    let proposal: { id: string; revision: number; title: string; definition: Record<string, unknown> } | undefined;
    const deployments: Record<string, unknown>[] = [];

    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: false } }),
      "GET /api/queries": () => ({ body: { queries: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "GET /api/requirements": () => ({ body: { requirements: [] } }),
      "GET /api/assessment-options": () => ({ body: { items: [RULEBASE], truncated: false } }),
      "GET /api/business-applications": () => ({ body: { applications: [APPLICATION] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: APPLICATION } }),
      "POST /api/business-applications/checkout/resolve": () => ({ body: RESOLUTION }),
      "POST /api/analysis-sessions": (req) => {
        record("session", req);
        const body = req.body as { input: Record<string, unknown>; review: unknown };
        session = {
          id: "app-session-1", revision: 2, title: "Checkout analysis", created_by: 1, created_at: "2026-01-02T00:00:00Z", input_digest: "1".repeat(64),
          definition: { schema_version: 1, id: "app-session-1", revision: 2, title: "Checkout analysis", input: body.input, runs: [{ id: "run-cw", item_id: "clients-to-web", execution: "completed", result: F, coverage: "complete", result_ref: "analysis-run:run-cw" }] },
          results: { review: body.review, bindings: { "clients-to-web": { assessment_id: "asm-cw", assessment_revision: 1 } } },
        };
        return { status: 201, body: { ...session, revision: 1 } };
      },
      "POST /api/analysis-sessions/app-session-1/runs": () => ({ status: 202, body: session }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: session ? [session] : [] } }),
      "GET /api/analysis-sessions/app-session-1": () => ({ body: session }),
      "GET /api/analysis-jobs/run-cw": () => ({ body: { id: "run-cw", kind: "evaluate", state: "completed", progress: null, error: null, result: { kind: "evaluate", findings: [] } } }),
      "GET /api/analysis-jobs/run-repair": () => ({ body: jobs["run-repair"] }),
      "GET /api/analysis-jobs/run-eval": () => ({ body: jobs["run-eval"] }),
      "GET /api/analysis-jobs/run-verify": () => ({ body: jobs["run-verify"] }),
      "GET /api/assessments": () => ({ body: { assessments: [assessment] } }),
      "GET /api/assessments/asm-cw": () => ({ body: { assessment, runs: [...runs].reverse(), deployments, proposals: proposal ? [proposal] : [] } }),
      "PATCH /api/assessments/asm-cw": (req) => {
        record("revise-assessment", req);
        const body = req.body as { title: string; definition: Assessment["definition"] };
        assessment = { ...assessment, title: body.title, definition: body.definition, revision: assessment.revision + 1 };
        return { body: assessment };
      },
      "POST /api/assessments/asm-cw/analyses": (req) => {
        record("analysis", req);
        const kind = (req.body as { kind: AnalysisRun["kind"] }).kind;
        const id = { repair: "run-repair", evaluate: "run-eval", verify: "run-verify" }[kind as "repair" | "evaluate" | "verify"];
        const result = { repair: REPAIR_RESULT, evaluate: EVALUATE_RESULT, verify: VERIFY_RESULT }[kind as "repair" | "evaluate" | "verify"];
        jobs[id] = job(id, kind, result, assessment.revision);
        runs.push(jobs[id]);
        return { status: 202, body: jobs[id] };
      },
      "POST /api/assessments/asm-cw/runs/run-repair/proposals": (req) => {
        record("proposal", req);
        proposal = {
          id: "chg-1", revision: 1, title: (req.body as { title: string }).title,
          definition: { intents: [INTENT], requirements: assessment.definition, protected: [], verification_state: "verified", source_run_id: "run-repair", source_assessment_revision: 1, verified_result: P },
        };
        return { status: 201, body: proposal };
      },
      "GET /api/change-revisions/chg-1/revisions": () => ({ body: { revisions: proposal ? [proposal] : [] } }),
      "PATCH /api/change-revisions/chg-1": (req) => {
        record("revise-proposal", req);
        const body = req.body as { title: string };
        proposal = { ...proposal!, title: body.title, revision: proposal!.revision + 1, definition: { ...proposal!.definition, verification_state: "needs-evaluation" } };
        return { body: proposal };
      },
      "POST /api/assessments/asm-cw/deployments": (req) => {
        record("deployment", req);
        const body = req.body as Record<string, unknown>;
        deployments.push(body);
        assessment = { ...assessment, definition: { ...assessment.definition, deployments: [...deployments] } } as Assessment;
        return { status: 201, body };
      },
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter><AuthProvider><WorkspaceProvider><Workspace /></WorkspaceProvider></AuthProvider></MemoryRouter>
      </QueryClientProvider>,
    );
    const analysisPane = () => screen.getByRole("region", { name: "Analysis pane" });

    // application: analyze the ready connection
    await user.click(await screen.findByRole("tab", { name: "Coverage" }));
    await screen.findAllByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Coverage snapshot"), "4000");
    await user.click(await screen.findByRole("button", { name: "Analyze ready connections" }));
    await waitFor(() => expect(window.location.search).toBe("?analysis=app-session-1"));
    expect(requests.session[0].body).toMatchObject({ input: { kind: "connection", connections: [{ id: "clients-to-web" }] } });

    // the session's Verification section opens the bound assessment in the same pane
    await user.click(await within(analysisPane()).findByRole("tab", { name: "Verification" }));
    await user.click(await within(analysisPane()).findByRole("button", { name: "Open deployment and verification for clients-to-web" }));
    await waitFor(() => expect(window.location.search).toBe("?assessment=asm-cw"));
    expect(await within(analysisPane()).findByRole("heading", { name: "Deployment and verification" })).toBeInTheDocument();

    // propose a change: a repair analysis, and its finding saved as a proposal
    await user.click(within(analysisPane()).getByRole("button", { name: "Scope" }));
    await user.click(within(analysisPane()).getByRole("button", { name: "Run analysis" }));
    await user.click(within(analysisPane()).getByRole("button", { name: /Find a safe repair/ }));
    await user.click(within(analysisPane()).getByRole("button", { name: "Continue to scope" }));
    await user.click(await within(analysisPane()).findByRole("button", { name: /^LAN-WAN fw-edge/ }));
    await user.click(within(analysisPane()).getByRole("button", { name: "Review analysis" }));
    await user.click(await within(analysisPane()).findByRole("button", { name: "Start analysis" }));
    await waitFor(() => expect(requests.analysis).toHaveLength(1));
    expect(requests.analysis[0].body).toMatchObject({
      kind: "repair", snapshot: "4000", allowed_targets: { [RULEBASE.uid]: "device:fw-edge" }, allowed_kinds: ["fw_rule.add"],
      scope: { source: ["10.9.0.0/24"], destination: ["10.20.0.10"], protocols: ["tcp"], ports: ["443"] },
    });
    await waitFor(() => expect(window.location.search).toBe("?assessment=asm-cw&assessment_run=run-repair"));
    await user.click(await within(analysisPane()).findByRole("button", { name: /^Inspect finding 1: fw-edge rule 15/ }));
    await user.click(within(analysisPane()).getByRole("button", { name: "Save proposal 1" }));
    await waitFor(() => expect(requests.proposal).toHaveLength(1));
    expect(requests.proposal[0].body).toEqual({ finding_index: 0, title: "Checkout: Clients to frontend proposal 1" });

    // simulate: the proposal revision is evaluated against the assessment
    await user.click(within(analysisPane()).getByRole("button", { name: "History" }));
    await user.click(await within(analysisPane()).findByRole("button", { name: "Evaluate proposal revision" }));
    await waitFor(() => expect(requests.analysis).toHaveLength(2));
    expect(requests["revise-assessment"][0].body).toMatchObject({
      expected_revision: 1, definition: { intents: [INTENT], change_id: "chg-1", change_revision: 1 },
    });
    expect(requests.analysis[1].body).toEqual({ kind: "evaluate", protected: [] });

    // evidence: the evaluated run shows Baseline and Predicted, and its finding's sources
    await waitFor(() => expect(window.location.search).toBe("?assessment=asm-cw&assessment_run=run-eval"));
    expect(await within(analysisPane()).findByRole("heading", { name: /^Predicted: / })).toHaveTextContent("Predicted: Passes");
    expect(within(analysisPane()).getByRole("heading", { name: /^Baseline: / })).toHaveTextContent("Baseline: Fails");
    await user.click(within(analysisPane()).getByRole("button", { name: /^Inspect finding 1: fw-edge rule 15/ }));
    const inspector = within(analysisPane()).getByRole("region", { name: "Finding evidence inspector" });
    expect(inspector).toHaveTextContent("the proposed rule permits tcp/443");

    // revise: the proposal gets a new revision
    await user.click(within(analysisPane()).getByRole("button", { name: "History" }));
    await user.click(await within(analysisPane()).findByRole("button", { name: "Edit proposal chg-1" }));
    const title = within(analysisPane()).getByLabelText("Proposal title");
    await user.clear(title);
    await user.type(title, "Edge rule for checkout");
    await user.click(within(analysisPane()).getByRole("button", { name: "Save proposal revision" }));
    await waitFor(() => expect(requests["revise-proposal"]).toHaveLength(1));
    expect(requests["revise-proposal"][0].body).toMatchObject({ title: "Edge rule for checkout", intents: [INTENT], expected_revision: 1 });
    expect(await within(analysisPane()).findByRole("heading", { name: "Edge rule for checkout / revision 2" })).toBeInTheDocument();

    // record deployment
    await user.click(within(analysisPane()).getByRole("button", { name: "Verification" }));
    await user.type(within(analysisPane()).getByLabelText("Deployment reference"), "Change 42");
    fireEvent.change(within(analysisPane()).getByLabelText("Deployment time"), { target: { value: "2026-01-03T10:00" } });
    await user.click(within(analysisPane()).getByRole("button", { name: "Record deployment" }));
    await waitFor(() => expect(requests.deployment).toHaveLength(1));
    expect(requests.deployment[0].body).toEqual({ reference: "Change 42", deployed_at: new Date("2026-01-03T10:00").toISOString(), assessment_revision: 2 });

    // verify: the saved prediction against a post-deployment snapshot
    await waitFor(() => expect(within(analysisPane()).getByText(/Change 42/)).toBeInTheDocument());
    await user.selectOptions(within(analysisPane()).getByLabelText("Post-deployment snapshot"), "5000");
    await user.click(within(analysisPane()).getByRole("button", { name: "Continue to scope" }));
    await user.click(within(analysisPane()).getByRole("button", { name: "Review analysis" }));
    await user.click(await within(analysisPane()).findByRole("button", { name: "Start analysis" }));
    await waitFor(() => expect(requests.analysis).toHaveLength(3));
    expect(requests.analysis[2].body).toMatchObject({ kind: "verify", snapshot: "5000" });
    await waitFor(() => expect(window.location.search).toBe("?assessment=asm-cw&assessment_run=run-verify"));
    expect(await within(analysisPane()).findByRole("heading", { name: "Prediction matches collected model" })).toBeInTheDocument();

    // every hop stayed in the one Analysis pane
    expect(screen.getAllByRole("region", { name: /pane/ })).toHaveLength(1);
  }, 30_000);
});
