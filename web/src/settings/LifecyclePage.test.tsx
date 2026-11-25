import { describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import LifecyclePage from "./LifecyclePage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler, type MockRequest } from "../test/fetchMock";
import { ME_ADMIN, ME_OPERATOR } from "../test/fixtures";
import type { Me, RetentionSettings } from "../api/types";

const SETTINGS: RetentionSettings = {
  cycle_keep_runs: 30,
  cycle_keep_device_runs: 48,
  login_event_retention_days: 90,
  cypher_event_retention_days: 180,
  job_history_retention_days: 30,
  ai_conversation_retention_days: 90,
  ai_step_result_days: 14,
  ai_event_retention_days: 180,
  updated_at: null,
};

function renderPage(me: Me = ME_ADMIN, extraRoutes: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/settings/retention": () => ({ status: 200, body: SETTINGS }),
    ...extraRoutes,
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <LifecyclePage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("LifecyclePage: role gate", () => {
  it("renders nothing for an operator", async () => {
    renderPage(ME_OPERATOR);
    await waitFor(() => expect(screen.queryByText(/loading/i)).not.toBeInTheDocument());
    expect(screen.queryByRole("form", { name: "Retention settings" })).not.toBeInTheDocument();
  });
});

describe("LifecyclePage: the keep limits", () => {
  it("shows the values in force and their origin", async () => {
    renderPage();

    expect(await screen.findByLabelText(/Graph history/)).toHaveValue(30);
    expect(screen.getByLabelText(/Sign-in records/)).toHaveValue(90);
    expect(screen.getByLabelText(/Cypher records/)).toHaveValue(180);
    expect(screen.getByLabelText(/Maintenance job records/)).toHaveValue(30);
    expect(screen.getByText("environment defaults")).toBeInTheDocument();
  });

  it("patches every value and reports when they were saved", async () => {
    const bodies: unknown[] = [];
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/retention": (req: MockRequest) => {
        bodies.push(req.body);
        return {
          status: 200,
          body: { ...SETTINGS, cycle_keep_runs: 7, updated_at: "2026-08-23T09:00:00+00:00" },
        };
      },
    });

    const keep = await screen.findByLabelText(/Graph history/);
    await user.clear(keep);
    await user.type(keep, "7");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      cycle_keep_runs: 7,
      cycle_keep_device_runs: 48,
      login_event_retention_days: 90,
      cypher_event_retention_days: 180,
      job_history_retention_days: 30,
      ai_conversation_retention_days: 90,
      ai_step_result_days: 14,
      ai_event_retention_days: 180,
    });
    expect(await screen.findByText(/saved 2026-08-23/)).toBeInTheDocument();
  });

  it("accepts 0 for a day count", async () => {
    const bodies: unknown[] = [];
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/retention": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ...SETTINGS, login_event_retention_days: 0 } };
      },
    });

    const days = await screen.findByLabelText(/Sign-in records/);
    await user.clear(days);
    await user.type(days, "0");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect((bodies[0] as { login_event_retention_days: number }).login_event_retention_days).toBe(0);
  });

  it("refuses a below-bounds keep count without asking the server", async () => {
    const bodies: unknown[] = [];
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/retention": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: SETTINGS };
      },
    });

    const keep = (await screen.findByLabelText(/Graph history/)) as HTMLInputElement;
    await user.clear(keep);
    await user.type(keep, "0");
    await user.click(screen.getByRole("button", { name: "Save" }));

    // the input's min bound rejects 0
    expect(keep.checkValidity()).toBe(false);
    expect(bodies).toEqual([]);
  });
});

describe("LifecyclePage: the device run count", () => {
  it("shows the device and refresh run count and saves 0", async () => {
    const bodies: unknown[] = [];
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/retention": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ...SETTINGS, cycle_keep_device_runs: 0 } };
      },
    });

    const runs = await screen.findByLabelText(/Device and refresh runs/);
    expect(runs).toHaveValue(48);
    await user.clear(runs);
    await user.type(runs, "0");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ cycle_keep_runs: 30, cycle_keep_device_runs: 0 });
  });
});

describe("LifecyclePage: the AI limits", () => {
  it("shows the three AI limits", async () => {
    renderPage();

    expect(await screen.findByLabelText(/AI conversations/)).toHaveValue(90);
    expect(screen.getByLabelText(/AI tool results/)).toHaveValue(14);
    expect(screen.getByLabelText(/AI events/)).toHaveValue(180);
  });

  it("saves 0 for an AI limit, which turns its purge off", async () => {
    const bodies: unknown[] = [];
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/retention": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ...SETTINGS, ai_step_result_days: 0 } };
      },
    });

    const days = await screen.findByLabelText(/AI tool results/);
    await user.clear(days);
    await user.type(days, "0");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({
      ai_conversation_retention_days: 90,
      ai_step_result_days: 0,
      ai_event_retention_days: 180,
    });
  });
});

describe("LifecyclePage: server errors", () => {
  it("shows the server's error when a save is refused", async () => {
    const user = userEvent.setup();
    renderPage(ME_ADMIN, {
      "PATCH /api/settings/retention": () => ({
        status: 422,
        body: { error: "invalid request: cycle_keep_runs: Input should be less than or equal to 10000" },
      }),
    });

    await screen.findByLabelText(/Graph history/);
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/less than or equal to 10000/);
  });

  it("shows a failed load and no form", async () => {
    renderPage(ME_ADMIN, {
      "GET /api/settings/retention": () => ({ status: 500, body: { error: "internal error" } }),
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("internal error");
    expect(screen.queryByLabelText(/Graph history/)).not.toBeInTheDocument();
  });
});
