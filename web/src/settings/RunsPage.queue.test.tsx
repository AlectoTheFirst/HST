import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import RunsPage from "./RunsPage";
import { ConnectionDetailPage } from "../inventory/connections/ConnectionDetailPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { JOB_HISTORY_IDLE, JOB_HISTORY_PENDING, ME_OPERATOR, RUN_HISTORY_IDLE } from "../test/fixtures";
import type { QueuedRun } from "../api/types";
import type { ConnectionView } from "../api/inventory";

// With RUN_EXECUTION=queue, POST /api/runs answers with a `collect.run` job, and
// the run row appears only once a worker claims it.

function queued(source: string): QueuedRun {
  return { job_id: 12, kind: "collect.run", source, status: "queued", enqueued_at: "2026-07-23T11:00:00+00:00" };
}

function renderRuns(routes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
    "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
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

describe("RunsPage: queued runs", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not poll the run history for a pending maintenance job", async () => {
    let runCalls = 0;
    vi.useFakeTimers();
    renderRuns({
      "GET /api/runs": () => {
        runCalls += 1;
        return { status: 200, body: RUN_HISTORY_IDLE };
      },
      "GET /api/jobs": () => ({ status: 200, body: JOB_HISTORY_PENDING }),
    });

    await flush();
    expect(runCalls).toBe(1);
    await flush(5000, 3);
    expect(runCalls).toBe(1);
  });
});

const CONNECTION: ConnectionView = {
  id: "c1",
  name: "controller-key",
  display_name: "Controller",
  kind: "controller",
  collector_type: "ctrl",
  enabled: true,
  config: { host: "controller.example" },
  profile_id: "p1",
  revision: 1,
  frozen_normalization: null,
  health: {
    state: "never",
    last_success_at: null,
    last_attempt_at: null,
    failing_targets: 0,
    target_count: 0,
    device_count: 0,
  },
  created_at: "",
  updated_at: "",
};

describe("ConnectionDetailPage: a queued collection", () => {
  it("names the queued job", async () => {
    let posted: unknown = null;
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
      "GET /api/inventory/connections/c1": () => ({ status: 200, body: CONNECTION }),
      "GET /api/inventory/targets": () => ({ status: 200, body: [] }),
      "POST /api/runs": (req) => {
        posted = req.body;
        return { status: 202, body: queued("controller-key") };
      },
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/detail/c1"]}>
          <AuthProvider>
            <Routes>
              <Route path="/detail/:id" element={<ConnectionDetailPage />} />
            </Routes>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await userEvent.setup().click(await screen.findByRole("button", { name: "Collect connection once" }));

    expect(await screen.findByText("Collection job 12 queued")).toBeInTheDocument();
    expect(posted).toEqual({ source: "controller-key" });
  });
});
