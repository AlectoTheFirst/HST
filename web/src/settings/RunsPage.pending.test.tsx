import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import RunsPage from "./RunsPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { JOB_HISTORY_IDLE, ME_OPERATOR, RUN_HISTORY_IDLE } from "../test/fixtures";
import type { Job, QueuedRun, RunHistory } from "../api/types";

// With RUN_EXECUTION=queue, GET /api/runs lists every queued or running
// `collect.run` job as `pending_runs`.

function runJob(source: string, state: "queued" | "running"): Job {
  return {
    id: 12,
    kind: "collect.run",
    source,
    device: null,
    state,
    attempt: state === "queued" ? 0 : 1,
    max_attempts: 1,
    enqueued_at: "2026-07-23T11:00:00+00:00",
    started_at: state === "queued" ? null : "2026-07-23T11:00:01+00:00",
    finished_at: null,
    not_before: "2026-07-23T11:00:00+00:00",
    duration_s: null,
    detail: "",
    triggered_by: "runs:2",
  };
}

function pending(source: string, state: "queued" | "running" = "queued"): RunHistory {
  return { ...RUN_HISTORY_IDLE, pending_runs: [runJob(source, state)] };
}

function queued(source: string): QueuedRun {
  return { job_id: 12, kind: "collect.run", source, status: "queued", enqueued_at: "2026-07-23T11:00:00+00:00" };
}

function renderRuns(routes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
    "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
    // the job listing never holds the pending run: it is past the window
    "GET /api/jobs": () => ({ status: 200, body: JOB_HISTORY_IDLE }),
    "GET /api/runs/http-traces": () => ({ status: 200, body: { enabled: "", traces: [] } }),
    ...routes,
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <RunsPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function flush(stepMs = 50, rounds = 10) {
  for (let i = 0; i < rounds; i++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(stepMs);
    });
  }
}

describe("RunsPage: pending runs from the run listing", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("disables the trigger of a source whose run is pending, and no other", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: pending("home-unifi") }) });

    const btn = await screen.findByRole("button", { name: "Trigger home-unifi" });
    await waitFor(() => expect(btn).toBeDisabled());
    expect(btn).toHaveTextContent("Queued");
    expect(screen.getByRole("button", { name: "Trigger reasoner" })).toBeEnabled();
  });

  it("reads the run listing again when the trigger answers with a queued job", async () => {
    let runCalls = 0;
    renderRuns({
      "GET /api/runs": () => {
        runCalls += 1;
        return { status: 200, body: runCalls > 1 ? pending("reasoner") : RUN_HISTORY_IDLE };
      },
      "POST /api/runs": () => ({ status: 202, body: queued("reasoner") }),
    });

    const btn = await screen.findByRole("button", { name: "Trigger reasoner" });
    await waitFor(() => expect(runCalls).toBe(1));
    await userEvent.setup().click(btn);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Trigger reasoner" })).toHaveTextContent("Queued"),
    );
    expect(screen.getByRole("button", { name: "Trigger reasoner" })).toBeDisabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("polls the run history while a run is pending, and stops once none is", async () => {
    let runCalls = 0;
    vi.useFakeTimers();
    renderRuns({
      "GET /api/runs": () => {
        runCalls += 1;
        // queued, then claimed, then its row replaces it from the third call on
        if (runCalls === 1) return { status: 200, body: pending("home-unifi", "queued") };
        if (runCalls === 2) return { status: 200, body: pending("home-unifi", "running") };
        return { status: 200, body: RUN_HISTORY_IDLE };
      },
    });

    await flush();
    expect(runCalls).toBe(1);

    await flush(5000, 1);
    await flush();
    expect(runCalls).toBe(2);

    await flush(5000, 1);
    await flush();
    expect(runCalls).toBe(3);

    await flush(5000, 3);
    expect(runCalls).toBe(3);
  });
});
