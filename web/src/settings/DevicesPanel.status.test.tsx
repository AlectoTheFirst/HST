/**
 * Collection state per device row.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DevicesPanel } from "./DevicesPanel";
import { mockApi } from "../test/fetchMock";
import type { SourceDevice } from "../api/types";

const HEALTHY: SourceDevice = {
  host: "r1",
  port: null,
  enabled: true,
  updated_at: null,
  status: {
    last_attempt_at: "2026-08-28T08:00:00+00:00",
    last_success_at: "2026-08-28T08:00:00+00:00",
    consecutive_failures: 0,
    last_error: "",
    fetch_ms: 843,
    load_ms: 12,
  },
};

const FLAPPING: SourceDevice = {
  host: "r2",
  port: null,
  enabled: true,
  updated_at: null,
  status: {
    last_attempt_at: "2026-08-28T07:59:00+00:00",
    last_success_at: "2026-08-27T22:00:00+00:00",
    consecutive_failures: 3,
    last_error: "SshUnreachable: cannot reach device r2:22",
    fetch_ms: null,
    load_ms: null,
  },
};

const FRESH: SourceDevice = {
  host: "r3",
  port: null,
  enabled: true,
  updated_at: null,
  status: null,
};

function renderPanel() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <DevicesPanel sourceName="edge" canManage={true} />
    </QueryClientProvider>,
  );
}

describe("DevicesPanel: collection state", () => {
  it("shows collecting with timings, failure counts with the error, and never-collected", async () => {
    mockApi({
      "GET /api/sources/edge/devices": () => ({
        status: 200,
        body: { devices: [HEALTHY, FLAPPING, FRESH] },
      }),
    });
    renderPanel();

    expect(await screen.findByText("collecting")).toBeInTheDocument();
    expect(screen.getByText(/fetch 843ms, load 12ms/)).toBeInTheDocument();
    expect(screen.getByText("3 consecutive failures")).toBeInTheDocument();
    expect(screen.getByText("SshUnreachable: cannot reach device r2:22")).toBeInTheDocument();
    expect(screen.getByText("never collected")).toBeInTheDocument();
  });
});
