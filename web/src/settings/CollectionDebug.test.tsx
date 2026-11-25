import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CollectionDebug, capturesOfRun, runBundleHref } from "./CollectionDebug";
import { mockApi } from "../test/fetchMock";
import type { DebugOverview, Run } from "../api/types";

const BEGIN = Date.parse("2026-09-26T10:00:05Z");

const OVERVIEW: DebugOverview = {
  sources: [
    { name: "edge", type: "iosxe", until_ms: null, by: null },
    { name: "core", type: "nxos", until_ms: BEGIN + 3_600_000, by: "otto" },
  ],
  captures: [
    {
      id: "a1",
      source: "edge",
      source_name: "edge",
      host: "r1",
      run_id: "1790000000000-abcdef12",
      loads: 1,
      begin_ms: BEGIN,
      last_ms: BEGIN + 40_000,
      finished: false,
      status: null,
      error: null,
      open_steps: [
        { step: "iosxe.parse", command: null, started_ms: BEGIN },
        { step: "textfsm", command: "show ip route vrf *", started_ms: BEGIN + 1000 },
      ],
      peak_rss_kb: 1_800_000,
      has_stack: true,
      unreadable_lines: 0,
      size: 4096,
    },
  ],
  limits: { capture_hours: 24, stack_after_s: 20, reparse_memory_mb: 1024, reparse_timeout_s: 120 },
};

function renderDebug(overview: DebugOverview = OVERVIEW) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <CollectionDebug overview={overview} />
    </QueryClientProvider>,
  );
}

describe("CollectionDebug", () => {
  it("shows a capture with no finish record and the step that was running", () => {
    renderDebug();
    expect(screen.getByText("No finish record, stack dump")).toBeInTheDocument();
    expect(screen.getByText("textfsm (show ip route vrf *)")).toBeInTheDocument();
    expect(screen.getByText("1758 MiB")).toBeInTheDocument();
    const bundle = screen.getAllByRole("link", { name: "Bundle" })[0];
    expect(bundle).toHaveAttribute(
      "href",
      "/api/debug-capture/bundle?source=edge&host=r1&run_id=1790000000000-abcdef12&raw=redacted",
    );
  });

  it("turns the switch on for a source", async () => {
    const user = userEvent.setup();
    let put: unknown = null;
    mockApi({
      "PUT /api/debug-capture/sources/edge": (req) => {
        put = req.body;
        return { status: 200, body: { name: "edge", until_ms: BEGIN, by: "otto" } };
      },
    });
    renderDebug();
    expect(screen.getByText(/^On until .*, by otto$/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Turn on debug capture for edge" }));
    expect(put).toEqual({ enabled: true });
  });

  it("lists a source's payloads and starts a re-parse", async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    mockApi({
      "GET /api/debug-capture/payloads": () => ({
        status: 200,
        body: {
          source: "edge",
          payloads: [
            {
              id: "p1",
              source: "edge",
              host: "r1",
              run_id: "1790000000000-abcdef12",
              fetch_ts_ms: BEGIN,
              size: 2048,
              has_capture: false,
              reparse: { state: "timeout", error: "the parse did not finish within 120 s" },
            },
          ],
        },
      }),
      "POST /api/debug-capture/reparse": (req) => {
        posted = req.body;
        return { status: 202, body: { state: "running" } };
      },
    });
    renderDebug();
    await user.click(screen.getAllByRole("button", { name: "Payloads" })[0]);
    expect(await screen.findByText("timeout: the parse did not finish within 120 s")).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Parse r1 1790000000000-abcdef12 again in isolation" }),
    );
    expect(posted).toEqual({ source: "edge", host: "r1", run_id: "1790000000000-abcdef12" });
  });
});

describe("capturesOfRun", () => {
  const run = (source: string, started: string, finished: string | null): Run =>
    ({ id: 7, source, status: "error", started_at: started, finished_at: finished, detail: "" }) as Run;

  it("matches a cycle to any source's capture inside its window", () => {
    expect(capturesOfRun(run("cycle", "2026-09-26T10:00:00Z", "2026-09-26T10:05:00Z"), OVERVIEW)).toHaveLength(1);
    expect(capturesOfRun(run("cycle", "2026-09-26T10:01:00Z", "2026-09-26T10:05:00Z"), OVERVIEW)).toHaveLength(0);
  });

  it("matches a source run only to its own source", () => {
    const end = "2026-09-26T10:05:00Z";
    expect(capturesOfRun(run("core", "2026-09-26T10:00:00Z", end), OVERVIEW)).toHaveLength(0);
    expect(capturesOfRun(run("edge", "2026-09-26T10:00:00Z", end), OVERVIEW)).toHaveLength(1);
    expect(runBundleHref(7)).toBe("/api/runs/7/debug-bundle?raw=redacted");
  });
});

describe("CollectionDebug unredacted download", () => {
  function renderWith(unredacted?: boolean) {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={queryClient}>
        <CollectionDebug overview={OVERVIEW} unredacted={unredacted} />
      </QueryClientProvider>,
    );
  }

  it("hides the unredacted download without the permission", () => {
    renderWith();
    expect(screen.queryByRole("button", { name: "Unredacted" })).not.toBeInTheDocument();
  });

  it("offers the unredacted download with the permission", () => {
    renderWith(true);
    expect(screen.getAllByRole("button", { name: "Unredacted" })).toHaveLength(1);
  });
});
