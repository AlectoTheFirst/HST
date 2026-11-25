import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import RunsPage from "./RunsPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import {
  JOB_HISTORY_IDLE,
  JOB_HISTORY_PENDING,
  ME_ADMIN,
  ME_OPERATOR,
  RUN_HISTORY_IDLE,
  RUN_HISTORY_CYCLE,
  RUN_HISTORY_RUNNING,
} from "../test/fixtures";
import type { Me } from "../api/types";

function renderRuns(routes: Record<string, MockHandler> = {}, me: Me = ME_OPERATOR) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    // every test renders the whole page, and the maintenance table loads with it
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

describe("RunsPage: trigger disabled while running", () => {
  it("disables the trigger for a source with a running row, but not an idle one", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_RUNNING }) });

    const runningBtn = await screen.findByRole("button", { name: "Trigger home-unifi" });
    expect(runningBtn).toBeDisabled();

    const reasonerBtn = screen.getByRole("button", { name: "Trigger reasoner" });
    expect(reasonerBtn).toBeEnabled();
  });

  it("posts {source} and shows the new run once triggered", async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "POST /api/runs": (req) => {
        posted = req.body;
        return { status: 202, body: { id: 9, source: "reasoner", status: "running", started_at: "now", finished_at: null, detail: "" } };
      },
    });

    const btn = await screen.findByRole("button", { name: "Trigger reasoner" });
    await user.click(btn);

    expect(posted).toEqual({ source: "reasoner" });
  });

  it("shows a 409 inline when the source is already running", async () => {
    const user = userEvent.setup();
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "POST /api/runs": () => ({ status: 409, body: { error: "reasoner is already running" } }),
    });

    const btn = await screen.findByRole("button", { name: "Trigger reasoner" });
    await user.click(btn);

    expect(await screen.findByRole("alert")).toHaveTextContent("reasoner is already running");
  });

  it("surfaces a 400 for an unknown source", async () => {
    const user = userEvent.setup();
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: { sources: ["ghost"], runs: [] } }),
      "POST /api/runs": () => ({ status: 400, body: { error: "unknown source 'ghost' (try: reasoner)" } }),
    });

    const btn = await screen.findByRole("button", { name: "Trigger ghost" });
    await user.click(btn);

    expect(await screen.findByRole("alert")).toHaveTextContent(/unknown source/i);
  });
});

describe("RunsPage: polling", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls every 5s while a run is running, and stops once everything is idle", async () => {
    let calls = 0;
    vi.useFakeTimers();
    renderRuns({
      "GET /api/runs": () => {
        calls += 1;
        // running on the first two calls, idle from the third call onward
        return { status: 200, body: calls < 3 ? RUN_HISTORY_RUNNING : RUN_HISTORY_IDLE };
      },
    });

    await flush();
    expect(calls).toBe(1);

    await flush(5000, 1);
    await flush();
    expect(calls).toBe(2);

    await flush(5000, 1);
    await flush();
    expect(calls).toBe(3); // now idle

    // no further polling once idle
    await flush(5000, 3);
    expect(calls).toBe(3);
  });
});

describe("RunsPage: purge graph", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("is offered to admins only", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }) });
    await screen.findByRole("button", { name: "Trigger reasoner" });
    expect(screen.queryByRole("button", { name: "Purge graph" })).not.toBeInTheDocument();
  });

  it("purges after confirmation and reports the count", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    let purged = false;
    renderRuns(
      {
        "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
        "POST /api/graph/purge": () => {
          purged = true;
          return { status: 200, body: { deleted_nodes: 2601 } };
        },
      },
      ME_ADMIN,
    );

    await user.click(await screen.findByRole("button", { name: "Purge graph" }));
    expect(purged).toBe(true);
    expect(await screen.findByRole("status")).toHaveTextContent("2601 nodes deleted");
  });

  it("does nothing when the confirmation is declined", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    let purged = false;
    renderRuns(
      {
        "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
        "POST /api/graph/purge": () => {
          purged = true;
          return { status: 200, body: { deleted_nodes: 0 } };
        },
      },
      ME_ADMIN,
    );

    await user.click(await screen.findByRole("button", { name: "Purge graph" }));
    expect(purged).toBe(false);
  });

  it("surfaces the 409 while a collection is running", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderRuns(
      {
        "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
        "POST /api/graph/purge": () => ({
          status: 409,
          body: { error: "a collection is running: run 7 (unifi)" },
        }),
      },
      ME_ADMIN,
    );

    await user.click(await screen.findByRole("button", { name: "Purge graph" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/collection is running/);
  });
});

describe("RunsPage: the maintenance queue", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows each scheduled job with what it did and how long it took", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }) });

    expect(await screen.findByText("maintenance.purge_sessions")).toBeInTheDocument();
    const swept = screen.getByText("maintenance.purge_sessions").closest("tr")!;
    expect(swept).toHaveTextContent("ok");
    expect(swept).toHaveTextContent("deleted 3 expired session(s)");
    expect(swept).toHaveTextContent("120 ms");
  });

  it("shows a failed job's error text", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }) });

    const failed = (await screen.findByText("maintenance.prune_graph")).closest("tr")!;
    expect(failed).toHaveTextContent("dead");
    expect(failed).toHaveTextContent("twin unreachable");
    expect(failed).toHaveTextContent("4 of 4"); // every attempt used
    expect(failed).toHaveTextContent("2.4 s");
  });

  it("reports nothing for a job that has not run yet", async () => {
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "GET /api/jobs": () => ({ status: 200, body: JOB_HISTORY_PENDING }),
    });

    const queued = (await screen.findByText("maintenance.purge_login_events")).closest("tr")!;
    expect(queued).toHaveTextContent("queued");
    expect(queued.querySelectorAll("td")[2]).toBeEmptyDOMElement();
    expect(queued.querySelectorAll("td")[5]).toBeEmptyDOMElement();
  });

  it("shows the empty queue", async () => {
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "GET /api/jobs": () => ({ status: 200, body: { jobs: [], depth: {} } }),
    });

    expect(await screen.findByText("No maintenance jobs")).toBeInTheDocument();
  });

  it("shows a failed load of the queue", async () => {
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "GET /api/jobs": () => ({ status: 500, body: { error: "internal error" } }),
    });

    expect(await screen.findByText("internal error")).toBeInTheDocument();
  });

  it("polls every 5s while a job is pending, and stops once the queue settles", async () => {
    let calls = 0;
    vi.useFakeTimers();
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "GET /api/jobs": () => {
        calls += 1;
        // something pending on the first two calls, settled from the third
        return { status: 200, body: calls < 3 ? JOB_HISTORY_PENDING : JOB_HISTORY_IDLE };
      },
    });

    await flush();
    expect(calls).toBe(1);

    await flush(5000, 1);
    await flush();
    expect(calls).toBe(2);

    await flush(5000, 1);
    await flush();
    expect(calls).toBe(3); // now settled

    await flush(5000, 3);
    expect(calls).toBe(3);
  });

  it("offers a cancel on a running row and posts it", async () => {
    const posted: string[] = [];
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_RUNNING }),
      "POST /api/runs/3/cancel": () => {
        posted.push("3");
        return { status: 200, body: { id: 3, status: "cancelled" } };
      },
    });
    const cancel = await screen.findByRole("button", { name: "Cancel run 3" });
    expect(screen.queryByRole("button", { name: /Cancel run 2/ })).not.toBeInTheDocument();
    await userEvent.setup().click(cancel);
    await waitFor(() => expect(posted).toEqual(["3"]));
  });

  it("draws a bar and a cancel for every source a cycle is collecting", async () => {
    const posted: unknown[] = [];
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_CYCLE }),
      "POST /api/runs/7/cancel": (req) => {
        posted.push(req.body);
        return { status: 200, body: { id: 7, source: "nxos-edge", status: "cancelled" } };
      },
    });
    await screen.findByRole("status", { name: "Collection progress for nxos-edge" });
    screen.getByRole("status", { name: "Collection progress for iosxe-core" });
    screen.getByText("Fetching devices: 12 of 40");
    screen.getByText("Fetching devices: 3 of 8");

    const one = screen.getByRole("button", { name: "Cancel nxos-edge in run 7" });
    screen.getByRole("button", { name: "Cancel iosxe-core in run 7" });
    screen.getByRole("button", { name: "Cancel run 7" });

    await userEvent.setup().click(one);
    await waitFor(() => expect(posted).toEqual([{ source: "nxos-edge" }]));
  });

  it("offers no per-source cancel when a run collects one source", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_RUNNING }) });
    await screen.findByRole("button", { name: "Cancel run 3" });
    expect(screen.queryByRole("button", { name: /in run 3/ })).not.toBeInTheDocument();
  });

  it("shows no HTTP trace section while tracing is off and nothing is on disk", async () => {
    renderRuns({ "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }) });
    await screen.findByText("History");
    expect(screen.queryByText("HTTP traces")).not.toBeInTheDocument();
  });

  it("lists the traces on disk with a download link that carries the path segments", async () => {
    renderRuns({
      "GET /api/runs": () => ({ status: 200, body: RUN_HISTORY_IDLE }),
      "GET /api/runs/http-traces": () => ({
        status: 200,
        body: {
          enabled: "cloud-vco-1",
          traces: [
            { source: "cloud-vco-1", host: "", run_id: "1790000000000-abcdef12", fetch_ts_ms: 1790000000000, size: 2048 },
          ],
        },
      }),
    });
    expect(await screen.findByText("HTTP traces")).toBeInTheDocument();
    expect(screen.getByText("Tracing on: cloud-vco-1")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "1790000000000-abcdef12.http.jsonl" });
    expect(link).toHaveAttribute("href", "/api/runs/http-traces/1790000000000-abcdef12?source=cloud-vco-1&host=");
    expect(screen.getByText("2.0 KiB")).toBeInTheDocument();
  });
});
