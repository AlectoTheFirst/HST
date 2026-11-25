/**
 * Release scenario "Optional AI":
 * with the AI provider unavailable, structured authoring and analysis still
 * work. The health poll reports no agent and every AI route fails; the
 * structured YAML import and the structured simulation builder complete
 * without any AI request.
 */

import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import { AiContextProvider } from "../ai/context";
import { AiDrawerProvider } from "../ai/drawer";
import AnalysisWorkspace from "../analysis/AnalysisWorkspace";
import ApplicationsPage from "../applications/ApplicationsPage";
import { mockApi, type MockHandler, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";

const SNAPSHOTS = { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false };
const REFERENCE = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };
const AI_DOWN = { status: 503, body: { error: "the AI provider is unavailable" } };

function install(routes: Record<string, MockHandler>): string[] {
  const paths: string[] = [];
  mockApi({
    "GET /api/me": () => ({ body: ME_OPERATOR }),
    "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: false } }),
    "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
    "POST /api/ai/conversations": () => AI_DOWN,
    ...routes,
  });
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => {
    paths.push(new URL(typeof input === "string" ? input : input.toString(), "http://localhost").pathname);
    return inner(input, init);
  });
  return paths;
}

function shell(node: React.ReactNode) {
  return <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><MemoryRouter><AuthProvider><AiContextProvider><AiDrawerProvider>{node}</AiDrawerProvider></AiContextProvider></AuthProvider></MemoryRouter></QueryClientProvider>;
}

const isAi = (path: string) => path.startsWith("/api/ai/") || path.startsWith("/api/business-applications/generations");

describe("Optional AI", () => {
  it("imports a structured YAML definition after AI generation failed", async () => {
    const commits: MockRequest[] = [];
    const generations: MockRequest[] = [];
    const yaml = "schema_version: 1\nkind: BusinessApplication\nid: checkout\nname: Checkout\n";
    const saved = { id: "checkout", revision: 1, name: "Checkout", digest: "a".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition: { schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "draft", services: [], groups: [], connections: [] } };
    const paths = install({
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "POST /api/business-applications/generations": (req) => { generations.push(req); return AI_DOWN; },
      "POST /api/business-applications/import/preview": () => ({ body: { application_id: "checkout", base_revision: 0, base_digest: "", result_digest: "a".repeat(64), preview_digest: "b".repeat(64), definition: {}, changes: { services_created: [], groups_created: [], connections_created: [] }, mapping_issues: [], no_op: false } }),
      "POST /api/business-applications/import/commit": (req) => { commits.push(req); return { body: saved }; },
    });
    const navigated: Array<string | undefined> = [];
    const user = userEvent.setup();
    render(shell(<ApplicationsPage onNavigate={(id) => navigated.push(id)} onOpenAnalysis={() => undefined} />));

    // the generator fails because the provider is unavailable
    await user.click(await screen.findByRole("button", { name: "Generate from a description" }));
    const draft = screen.getByRole("region", { name: "Application draft" });
    await user.type(within(draft).getByRole("textbox", { name: "Description" }), "Checkout web shop");
    await within(draft).findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(within(draft).getByLabelText("Snapshot"), "4000");
    await user.click(within(draft).getByRole("button", { name: "Generate" }));
    expect(await within(draft).findByRole("alert")).toHaveTextContent("the AI provider is unavailable");
    expect(generations).toHaveLength(1);
    await user.click(within(draft).getByRole("button", { name: "Close draft" }));

    // the structured import works without AI
    const before = paths.length;
    await user.click(screen.getByRole("textbox", { name: "Definition YAML" }));
    await user.paste(yaml);
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    await user.click(await screen.findByRole("button", { name: "Commit revision" }));

    await waitFor(() => expect(navigated).toEqual(["checkout"]));
    expect(commits.map((req) => req.body)).toEqual([{ yaml, mode: "merge", base_revision: 0, base_digest: "", preview_digest: "b".repeat(64) }]);
    expect(paths.slice(before).filter(isAi)).toEqual([]);
    expect(generations).toHaveLength(1);
  });

  it("saves and then runs a structured simulation with no AI offered or requested", async () => {
    const created: MockRequest[] = [];
    const runs: MockRequest[] = [];
    const draft = {
      id: "sim-draft", revision: 1, title: "Change analysis", created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "c".repeat(64),
      definition: { schema_version: 1, id: "sim-draft", revision: 1, title: "Change analysis", input: { kind: "simulation", snapshot: REFERENCE, changes: [], scope: { flows: [], sites: [] }, bounds: { max_flows: 50, max_seconds: 30 }, protected: [] }, runs: [] },
      results: {},
    };
    const paths = install({
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/requirements": () => ({ body: { requirements: [] } }),
      "GET /api/analysis-snapshot": () => ({ body: REFERENCE }),
      "GET /api/analysis-sessions": () => ({ body: { sessions: created.length ? [draft] : [] } }),
      "POST /api/analysis-sessions": (req) => { created.push(req); return { status: 201, body: draft }; },
      "GET /api/analysis-sessions/sim-draft": () => ({ body: draft }),
      "POST /api/analysis-sessions/sim-draft/runs": (req) => { runs.push(req); return { status: 202, body: draft }; },
    });
    function Harness() {
      const [sessionId, setSessionId] = useState<string>();
      return <AnalysisWorkspace sessionId={sessionId} onNavigate={setSessionId} />;
    }
    const user = userEvent.setup();
    render(shell(<Harness />));

    // the health poll answered that no agent is available
    await waitFor(() => expect(paths).toContain("/api/health"));
    await user.click(await screen.findByRole("button", { name: "New analysis" }));
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Pinned snapshot"), "4000");
    await user.click(screen.getByRole("button", { name: "Add firewall change" }));
    await user.click(screen.getByRole("button", { name: "Save draft" }));

    // the saved draft opens with its run offered and no AI discussion offered
    const run = await screen.findByRole("button", { name: "Run analysis" });
    expect(created).toHaveLength(1);
    expect((created[0].body as { input: { kind: string } }).input.kind).toBe("simulation");
    expect(runs).toHaveLength(0);
    expect(screen.queryByRole("button", { name: "Discuss in HST AI" })).not.toBeInTheDocument();
    await user.click(run);
    await waitFor(() => expect(runs).toHaveLength(1));
    expect(runs[0].body).toEqual({ session_revision: 1, input_digest: "c".repeat(64) });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(paths.filter(isAi)).toEqual([]);
  });
});
