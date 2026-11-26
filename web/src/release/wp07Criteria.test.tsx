/**
 * WP-07 "Done when" criteria of the Business Applications plan: a simulation
 * session whose run produced no result shows no prediction, the export of a
 * saved run and the legacy change-simulation export are separate controls on
 * separate routes, and a late answer of a turn that a reset discarded stays
 * out of the next conversation.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import AnalysisWorkspace from "../analysis/AnalysisWorkspace";
import { useConversation } from "../ai/useConversation";
import { ExportControl } from "../changesim/ExportControl";
import { mockApi, type MockHandler, type MockRequest } from "../test/fetchMock";
import { FIXTURE_SIMULATE_POLICY_CHANGE, ME_VIEWER } from "../test/fixtures";

const SNAPSHOT = { snapshot: "4000", manifest_sha256: "b".repeat(64), estate: "test" };
const FLOW = { src: "10.9.0.5", dst: "10.30.0.10", proto: "tcp", port: 443 };

function simulation(execution: string, results: Record<string, unknown>) {
  return {
    id: "sim-1", revision: 2, title: "Firewall change", created_by: 1, created_at: "2026-01-01T00:00:00Z", input_digest: "e".repeat(64),
    definition: {
      schema_version: 1, id: "sim-1", revision: 2, title: "Firewall change",
      input: { kind: "simulation", snapshot: SNAPSHOT, changes: [{ kind: "fw_rule.remove", params: { rulebase: "rb:r1", rule: "deny-8443" } }], scope: { flows: [FLOW], sites: [] }, bounds: { max_flows: 50, max_seconds: 30 }, protected: [] },
      runs: [{ id: "run-s", item_id: "simulation", execution, result: null, coverage: execution === "completed" ? "complete" : "partial", result_ref: "analysis-run:run-s" }],
    },
    results,
  };
}

function openSession(record: ReturnType<typeof simulation>, routes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ body: ME_VIEWER }),
    "GET /api/analysis-sessions": () => ({ body: { sessions: [record] } }),
    "GET /api/analysis-sessions/sim-1": () => ({ body: record }),
    ...routes,
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter><AuthProvider><AnalysisWorkspace sessionId="sim-1" onNavigate={() => undefined} /></AuthProvider></MemoryRouter>
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

describe("A simulation without a prediction", () => {
  it("shows no prediction in Results and in Verification for a failed run with no saved result", async () => {
    const user = openSession(simulation("failed", { stop_reason: "execution-failed" }));

    expect(await screen.findByText("Session execution: failed")).toBeInTheDocument();
    expect(screen.getByText("Execution: failed")).toBeInTheDocument();
    const predicted = screen.getByRole("heading", { name: "Predicted" }).parentElement!;
    expect(predicted).toHaveTextContent("No prediction");
    expect(predicted.querySelector("pre")).toBeNull();
    const baseline = screen.getByRole("heading", { name: "Baseline" }).parentElement!;
    expect(baseline).toHaveTextContent("No traffic flow evaluated");

    await user.click(screen.getByRole("tab", { name: "Verification" }));
    const verification = screen.getByRole("heading", { name: "Verification" }).parentElement!;
    expect(verification).toHaveTextContent("No prediction");
  });

  it("shows no prediction for a completed run that traced no flow and changed no device", async () => {
    const user = openSession(
      simulation("completed", { simulation: { flows: [], changed_devices: [], stop_reason: "no-flow-to-trace" } }),
    );

    expect(await screen.findByText("Session execution: completed")).toBeInTheDocument();
    const predicted = screen.getByRole("heading", { name: "Predicted" }).parentElement!;
    expect(predicted).toHaveTextContent("No prediction");
    expect(predicted.querySelector("pre")).toBeNull();

    await user.click(screen.getByRole("tab", { name: "Verification" }));
    const verification = screen.getByRole("heading", { name: "Verification" }).parentElement!;
    expect(verification).toHaveTextContent("No prediction");
  });
});

describe("Saved run export and legacy export", () => {
  let click: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.stubGlobal(
      "URL",
      Object.assign(globalThis.URL, { createObjectURL: vi.fn(() => "blob:hst"), revokeObjectURL: vi.fn() }),
    );
    click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("offers Export run for a saved simulation and reads the saved revision from the session export", async () => {
    const seen: MockRequest[] = [];
    const record = simulation("completed", { simulation: { flows: [{ flow: FLOW, before: { result: "denied" }, after: { result: "permitted" } }] } });
    const user = openSession(record, {
      "GET /api/analysis-sessions/sim-1/export": (req) => {
        seen.push(req);
        return { raw: "{}", headers: { "Content-Type": "application/json", "Content-Disposition": 'attachment; filename="analysis-sim-1-r2.json"', "X-HST-Export-Mode": "exact-saved-run" } };
      },
    });

    await user.click(await screen.findByRole("button", { name: "Export run" }));

    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(seen.map((req) => `${req.method} ${req.path}`)).toEqual(["GET /api/analysis-sessions/sim-1/export"]);
    const urls = vi.mocked(globalThis.fetch).mock.calls.map(([input]) => String(input));
    expect(urls).toContain("/api/analysis-sessions/sim-1/export?revision=2");
    expect(urls.some((url) => url.includes("/changesim/export"))).toBe(false);
    expect(screen.queryByRole("button", { name: /Download current data/ })).not.toBeInTheDocument();
  });

  it("offers Download current data for a chat simulation and posts its change set to the legacy export", async () => {
    const seen: MockRequest[] = [];
    mockApi({
      "POST /api/changesim/export": (req) => {
        seen.push(req);
        return { raw: "zip-bytes", headers: { "Content-Type": "application/zip", "X-HST-Snapshot": String(FIXTURE_SIMULATE_POLICY_CHANGE.snapshot) } };
      },
    });
    render(<ExportControl policy={FIXTURE_SIMULATE_POLICY_CHANGE} />);

    expect(screen.queryByRole("button", { name: "Export run" })).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Download current data" }));

    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0].path).toBe("/api/changesim/export");
    expect(seen[0].body).toMatchObject({ intents: FIXTURE_SIMULATE_POLICY_CHANGE.intents });
    expect(seen[0].body).not.toHaveProperty("session_revision");
  });
});

function poll(status: "running" | "done", answer = "") {
  return {
    status: 200,
    body: { status, state: status, answer, declined: false, steps: [], context: null, snapshot: null, context_entries: [], page_context: null, prompt_hash: null },
  };
}

describe("A late answer after a draft reset", () => {
  it("keeps the answer of a discarded turn out of the conversation asked after the reset", async () => {
    let releaseFirst: () => void = () => undefined;
    const firstHeld = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstPolled = false;
    let firstAnswered = false;
    let conversations = 0;
    let cancels = 0;
    mockApi({
      "POST /api/ai/conversations": () => {
        conversations += 1;
        return { status: 201, body: { id: `c${conversations}` } };
      },
      "POST /api/ai/conversations/c1/messages": () => ({ status: 202, body: { message_id: "m1" } }),
      "POST /api/ai/conversations/c2/messages": () => ({ status: 202, body: { message_id: "m2" } }),
      "GET /api/ai/messages/m1": async () => {
        firstPolled = true;
        await firstHeld;
        firstAnswered = true;
        return poll("done", "The first answer.");
      },
      "POST /api/ai/messages/m1/cancel": () => {
        cancels += 1;
        return { status: 200, body: { cancel_requested: true } };
      },
      "GET /api/ai/messages/m2": () => poll("done", "The second answer."),
    });
    const onConversation = vi.fn();
    const { result } = renderHook(() => useConversation({ surface: "changesim", onConversation }));

    act(() => result.current.send("what if leaf101 reloads?"));
    await waitFor(() => expect(firstPolled).toBe(true));
    act(() => result.current.reset());
    await waitFor(() => expect(cancels).toBe(1));

    act(() => result.current.send("what if leaf102 reloads?"));
    await waitFor(() => expect(result.current.turns).toHaveLength(2));
    releaseFirst();
    await waitFor(() => expect(firstAnswered).toBe(true));
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    expect(result.current.turns.map((turn) => turn.content)).toEqual(["what if leaf102 reloads?", "The second answer."]);
    expect(result.current.isPending).toBe(false);
    expect(onConversation.mock.calls.map(([id]) => id)).toEqual(["c1", undefined, "c2"]);
  });
});
