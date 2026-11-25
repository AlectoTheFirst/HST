import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import RunsPage from "./RunsPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { JOB_HISTORY_IDLE, ME_ADMIN, ME_OPERATOR, RUN_HISTORY_IDLE } from "../test/fixtures";
import type { Me, Run, RunHistory } from "../api/types";

// The demo estate load: offered on a demo instance (GET /api/runs `demo`) to an admin,
// started as a `demo` run, and reported from the newest `demo` row of the history.

const DEMO_INSTANCE: RunHistory = { ...RUN_HISTORY_IDLE, demo: true };

function demoRun(status: Run["status"], detail = ""): Run {
  return {
    id: 7,
    source: "demo",
    status,
    started_at: "2026-10-16T12:00:00+00:00",
    finished_at: status === "running" ? null : "2026-10-16T12:02:00+00:00",
    detail,
  };
}

function renderRuns(runs: RunHistory, me: Me = ME_ADMIN, routes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/runs": () => ({ status: 200, body: runs }),
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

describe("RunsPage: the demo estate load", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("is not offered on an instance that is not a demo instance", async () => {
    renderRuns(RUN_HISTORY_IDLE);
    await screen.findByRole("button", { name: "Purge graph" });
    expect(screen.queryByRole("button", { name: "Load demo estate" })).not.toBeInTheDocument();
  });

  it("is not offered to an operator on a demo instance", async () => {
    renderRuns(DEMO_INSTANCE, ME_OPERATOR);
    await screen.findByRole("button", { name: "Trigger reasoner" });
    expect(screen.queryByRole("button", { name: "Load demo estate" })).not.toBeInTheDocument();
  });

  it("starts a demo run after confirmation", async () => {
    const user = userEvent.setup();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    let posted: unknown = null;
    renderRuns(DEMO_INSTANCE, ME_ADMIN, {
      "POST /api/runs": (req) => {
        posted = req.body;
        return { status: 202, body: demoRun("running") };
      },
    });

    await user.click(await screen.findByRole("button", { name: "Load demo estate" }));
    expect(confirm).toHaveBeenCalledOnce();
    expect(posted).toEqual({ source: "demo" });
  });

  it("starts nothing when the confirmation is declined", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    let posted = false;
    renderRuns(DEMO_INSTANCE, ME_ADMIN, {
      "POST /api/runs": () => {
        posted = true;
        return { status: 202, body: demoRun("running") };
      },
    });

    await user.click(await screen.findByRole("button", { name: "Load demo estate" }));
    expect(posted).toBe(false);
  });

  it("is disabled while a demo run is running", async () => {
    renderRuns({ ...DEMO_INSTANCE, runs: [demoRun("running"), ...RUN_HISTORY_IDLE.runs] });
    expect(await screen.findByRole("button", { name: "Loading" })).toBeDisabled();
  });

  it("reports the outcome of the last demo run", async () => {
    const detail = "demo estate: estate-v1 run 101, estate-v2 run 102, estate-v3 run 103";
    renderRuns({ ...DEMO_INSTANCE, runs: [demoRun("ok", detail), ...RUN_HISTORY_IDLE.runs] });
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Last demo load: ok");
    expect(status).toHaveTextContent(detail);
    expect(screen.getByRole("button", { name: "Load demo estate" })).toBeEnabled();
  });

  it("surfaces a refusal from the server", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderRuns(DEMO_INSTANCE, ME_ADMIN, {
      "POST /api/runs": () => ({ status: 409, body: { error: "demo is already running" } }),
    });

    await user.click(await screen.findByRole("button", { name: "Load demo estate" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("demo is already running");
  });
});
