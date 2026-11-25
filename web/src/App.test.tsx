import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act, within, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { AuthProvider } from "./auth";
import { mockApi } from "./test/fetchMock";
import { ME_VIEWER, ME_OPERATOR, ME_ADMIN } from "./test/fixtures";
import type { Me } from "./api/types";

const HEALTHY = { path: true, neo4j: true, postgres: true };

function renderApp(initialEntries: string[]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mockMeAndHealth(me: Me, health: Record<string, unknown> = HEALTHY) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/health": () => ({ status: 200, body: health }),
  });
}

describe("top bar x role", () => {
  it("carries no mode switch", async () => {
    mockMeAndHealth(ME_VIEWER);
    renderApp(["/"]);

    const header = within(await screen.findByRole("banner"));
    await screen.findByRole("region", { name: "Trace pane" });
    expect(header.queryByRole("button", { name: "Trace" })).not.toBeInTheDocument();
    expect(header.queryByRole("button", { name: "Explore" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
  });

  it("the rail is where the view is switched", async () => {
    mockMeAndHealth(ME_VIEWER);
    renderApp(["/"]);

    await screen.findByRole("region", { name: "Trace pane" });
    const rail = within(screen.getByRole("navigation", { name: "Navigation" }));
    expect(rail.getByRole("button", { name: "Explore" })).toBeInTheDocument();
  });

  it("operator gets the gear", async () => {
    mockMeAndHealth(ME_OPERATOR);
    renderApp(["/"]);

    expect(await screen.findByRole("link", { name: "Settings" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Runs" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });
});

describe("settings sections x role", () => {
  it("operator sees Runs, Groups, and Devices but not Users or the AI agent", async () => {
    mockMeAndHealth(ME_OPERATOR);
    renderApp(["/settings/runs"]);

    expect(await screen.findByRole("link", { name: "Runs" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Groups" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Devices" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "AI agent" })).not.toBeInTheDocument();
  });

  it("admin sees every settings section", async () => {
    mockMeAndHealth(ME_ADMIN);
    renderApp(["/settings/runs"]);

    for (const label of ["Runs", "Groups", "Devices", "Users", "AI agent"]) {
      expect(await screen.findByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("/settings opens a section", async () => {
    mockMeAndHealth(ME_ADMIN);
    renderApp(["/settings"]);

    // the index route's <Navigate> sets `on` a tick after mount
    await waitFor(() => expect(screen.getByRole("link", { name: "Runs" })).toHaveClass("on"));
  });
});

describe("direct URL access below role", () => {
  it("viewer hitting a settings URL directly gets the forbidden panel", async () => {
    mockMeAndHealth(ME_VIEWER);
    renderApp(["/settings/users"]);

    expect(await screen.findByRole("alert")).toHaveTextContent("Forbidden");
    expect(screen.queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
  });

  it("operator hitting the admin-only Users section gets the forbidden panel", async () => {
    mockMeAndHealth(ME_OPERATOR);
    renderApp(["/settings/users"]);

    expect(await screen.findByRole("alert")).toHaveTextContent("Forbidden");
    // but they keep the sections they can reach
    expect(screen.getByRole("link", { name: "Runs" })).toBeInTheDocument();
  });
});

describe("health dot", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("reflects a mocked degraded response on the 30s poll", async () => {
    let calls = 0;
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/health": () => {
        calls += 1;
        return {
          status: 200,
          body: calls === 1 ? HEALTHY : { path: true, neo4j: false, postgres: true },
        };
      },
    });

    vi.useFakeTimers();
    renderApp(["/"]);

    // each timer advance runs in its own `act`
    await flush();
    expect(screen.getByRole("status", { name: /connected/i })).toBeInTheDocument();

    await flush(30_000, 1);
    await flush();
    expect(screen.getByRole("status", { name: /degraded/i })).toBeInTheDocument();
    expect(calls).toBeGreaterThanOrEqual(2);
  });
});

/** Advances the fake clock by `stepMs` `rounds` times, each in its own `act`. */
async function flush(stepMs = 50, rounds = 10) {
  for (let i = 0; i < rounds; i++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(stepMs);
    });
  }
}

describe("an unknown path", () => {
  it("goes to the workspace", async () => {
    mockMeAndHealth(ME_VIEWER);
    renderApp(["/explore"]);
    expect(await screen.findByRole("region", { name: "Trace pane" })).toBeInTheDocument();
    expect(screen.getByRole("banner")).toBeInTheDocument();
  });
});
