import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AiSettingsPage from "./AiSettingsPage";
import { mockApi, type MockRequest } from "../test/fetchMock";
import type { AiEvents, AiProviders, AiSettings } from "../api/types";

const PROVIDERS: AiProviders = {
  prompt_layers: [
    { id: "base", label: "Base policy", text: "You answer questions about a network digital twin." },
    {
      id: "tools",
      label: "Tool guidance for roles offered run_cypher",
      text: "Use `run_cypher` for inventory and topology questions.",
    },
  ],
  providers: [
    {
      id: "anthropic",
      label: "Anthropic",
      credentials: [{ name: "api_key", label: "API key", secret: true }],
      models: ["claude-opus-5"],
      supports_effort: true,
    },
    {
      id: "openrouter",
      label: "OpenRouter",
      credentials: [{ name: "api_key", label: "API key", secret: true }],
      models: ["anthropic/claude-opus-5"],
      supports_effort: false,
    },
  ],
};

const SETTINGS: AiSettings = {
  enabled: false,
  provider: "anthropic",
  model: "claude-opus-5",
  effort: "high",
  system_prompt: "custom prompt",
  stored_credentials: [],
  configured: false,
};

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AiSettingsPage />
    </QueryClientProvider>,
  );
}

function mock(settings: Partial<AiSettings> = {}, extra: Record<string, unknown> = {}) {
  mockApi({
    "GET /api/settings/ai/providers": () => ({ status: 200, body: PROVIDERS }),
    "GET /api/settings/ai": () => ({ status: 200, body: { ...SETTINGS, ...settings } }),
    ...extra,
  });
}

describe("AiSettingsPage", () => {
  it("builds its form from the server's provider descriptors", async () => {
    mock();
    renderPage();

    expect(await screen.findByRole("combobox", { name: "Provider" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Anthropic" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "OpenRouter" })).toBeInTheDocument();
    // the credential field is whatever the descriptor declares
    expect(screen.getByLabelText(/API key/)).toBeInTheDocument();
  });

  it("hides the effort control for a provider without effort", async () => {
    mock();
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByRole("combobox", { name: "Effort" })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "openrouter");
    expect(screen.queryByRole("combobox", { name: "Effort" })).not.toBeInTheDocument();
  });

  it("shows that a credential is on file without ever showing its value", async () => {
    mock({ stored_credentials: ["api_key"], configured: true, enabled: true });
    renderPage();

    expect(await screen.findByText(/stored/)).toBeInTheDocument();
    const field = screen.getByLabelText(/API key/) as HTMLInputElement;
    expect(field.value).toBe("");
    expect(field.placeholder).toBe("stored value");
  });

  it("omits the credential from the payload when left blank", async () => {
    const bodies: unknown[] = [];
    mock({ stored_credentials: ["api_key"], configured: true }, {
      "PUT /api/settings/ai": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ...SETTINGS, model: "claude-sonnet-5" } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    // `<input list>` reports as a combobox, not a textbox
    const model = await screen.findByRole("combobox", { name: "Model" });
    await user.clear(model);
    await user.type(model, "claude-sonnet-5");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(bodies).toHaveLength(1);
    expect(bodies[0]).not.toHaveProperty("credentials");
  });

  it("invalidates the health query on save", async () => {
    mock({ stored_credentials: ["api_key"], configured: true }, {
      "PUT /api/settings/ai": () => ({
        status: 200,
        body: { ...SETTINGS, enabled: true, configured: true, stored_credentials: ["api_key"] },
      }),
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    queryClient.setQueryData(["health"], { path: true, neo4j: true, postgres: true, agent: false });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={queryClient}>
        <AiSettingsPage />
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("checkbox", { name: /Enable the AI agent/ }));
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(queryClient.getQueryState(["health"])?.isInvalidated).toBe(true);
  });

  it("reports a failed connection test with the provider's own words", async () => {
    mock({ stored_credentials: ["api_key"], configured: true }, {
      "POST /api/settings/ai/test": () => ({
        status: 200,
        body: { ok: false, provider: "anthropic", model: "claude-opus-5",
                error: "AuthenticationError: invalid x-api-key" },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/invalid x-api-key/)).toBeInTheDocument();
  });

  it("reports a test POST that fails with an HTTP error", async () => {
    mock({ stored_credentials: ["api_key"], configured: true }, {
      "POST /api/settings/ai/test": () => ({
        status: 502,
        body: { error: "agent backend unreachable" },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/agent backend unreachable/)).toBeInTheDocument();
  });

  it("probes the settings on screen", async () => {
    const bodies: unknown[] = [];
    mock({ stored_credentials: ["api_key"], configured: true }, {
      "POST /api/settings/ai/test": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ok: true, provider: "anthropic", model: "claude-sonnet-5" } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    const model = await screen.findByRole("combobox", { name: "Model" });
    await user.clear(model);
    await user.type(model, "claude-sonnet-5");
    await user.click(screen.getByRole("button", { name: "Test connection" }));

    expect(bodies).toEqual([
      { provider: "anthropic", model: "claude-sonnet-5", effort: "high", options: {} },
    ]);
    // no secrets key: the stored credential is what gets probed
    expect(bodies[0]).not.toHaveProperty("secrets");
  });

  it("sends a typed credential with the probe so it is tested before saving", async () => {
    const bodies: unknown[] = [];
    mock({ stored_credentials: ["api_key"], configured: true }, {
      "POST /api/settings/ai/test": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ok: true, provider: "anthropic", model: "claude-opus-5" } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.type(await screen.findByLabelText(/API key/), "sk-new-key");
    await user.click(screen.getByRole("button", { name: "Test connection" }));

    expect(bodies).toHaveLength(1);
    expect((bodies[0] as { secrets?: unknown }).secrets).toEqual({ api_key: "sk-new-key" });
  });

  it("edits only the site instructions and shows the fixed layers read-only", async () => {
    mock({ prompt_mode: "append" });
    renderPage();

    const site = (await screen.findByRole("textbox", { name: "Site instructions" })) as
      HTMLTextAreaElement;
    expect(site.value).toBe("custom prompt");
    // the site instructions are the only editable text
    expect(screen.getAllByRole("textbox")).toEqual([site]);
    expect(screen.getByText("Base policy")).toBeInTheDocument();
    expect(
      screen.getByText("You answer questions about a network digital twin.").tagName,
    ).toBe("PRE");
    expect(screen.getByText(/run_cypher. for inventory/).tagName).toBe("PRE");
    expect(screen.queryByRole("button", { name: "Reset to default" })).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("warns while replace mode is active and saves append once the admin switches", async () => {
    const bodies: unknown[] = [];
    mock({ prompt_mode: "replace", stored_credentials: ["api_key"], configured: true }, {
      "PUT /api/settings/ai": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ...SETTINGS, prompt_mode: "append" } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(/replace mode/);
    await user.click(
      screen.getByRole("button", { name: "Append to the fixed layers" }),
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({ system_prompt: "custom prompt", prompt_mode: "append" });
  });

  it("keeps replace mode on a save that does not switch it", async () => {
    const bodies: unknown[] = [];
    mock({ prompt_mode: "replace", stored_credentials: ["api_key"], configured: true }, {
      "PUT /api/settings/ai": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { ...SETTINGS, prompt_mode: "replace" } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(bodies[0]).toMatchObject({ prompt_mode: "replace" });
    expect(await screen.findByRole("alert")).toHaveTextContent(/replace mode/);
  });
});

const EVENTS: AiEvents = {
  events: [
    {
      id: 2,
      at: "2026-09-28T10:00:00+00:00",
      user_id: 3,
      username: "ada",
      origin: "web",
      surface: null,
      event: "tool.call",
      conversation_id: null,
      message_id: null,
      step_id: "5d2c7a52-7f6e-4b44-9a4a-0d4c1d3b1e11",
      provider: "anthropic",
      model_requested: "claude-opus-5",
      model_served: null,
      prompt_hash: null,
      tool: "trace_path",
      tool_version: null,
      snapshot: "3000",
      latency_ms: 41,
      tokens_in: null,
      tokens_out: null,
      outcome: "error",
      error_class: "ValueError",
      detail: null,
    },
  ],
  daily_tokens: [
    { day: "2026-09-28", user_id: 3, username: "ada", tokens_in: 1200, tokens_out: 340 },
    { day: "2026-09-27", user_id: null, username: null, tokens_in: 8, tokens_out: 2 },
  ],
};

describe("AiSettingsPage: AI events", () => {
  it("lists tokens per user per day and the newest events", async () => {
    mock({}, { "GET /api/settings/ai/events": () => ({ status: 200, body: EVENTS }) });
    renderPage();

    const daily = await screen.findByRole("table", { name: "Tokens per day" });
    const dailyRows = within(daily).getAllByRole("row");
    expect(dailyRows[1]).toHaveTextContent(/2026-09-28\s*ada\s*1200\s*340/);
    expect(dailyRows[2]).toHaveTextContent(/2026-09-27\s*none\s*8\s*2/);

    const events = screen.getByRole("table", { name: "AI events" });
    const row = within(events).getAllByRole("row")[1];
    expect(row).toHaveTextContent("tool.call");
    expect(row).toHaveTextContent("trace_path");
    expect(row).toHaveTextContent("claude-opus-5");
    expect(row).toHaveTextContent("error (ValueError)");
    expect(row).toHaveTextContent("41 ms");
  });

  it("says when there is nothing to show", async () => {
    mock({}, {
      "GET /api/settings/ai/events": () => ({ status: 200, body: { events: [], daily_tokens: [] } }),
    });
    renderPage();

    expect(await screen.findByText("No token counts in the last 30 days")).toBeInTheDocument();
    expect(screen.getByText("No AI events")).toBeInTheDocument();
  });

  it("reports a refused read without hiding the settings form", async () => {
    mock({}, {
      "GET /api/settings/ai/events": () => ({ status: 403, body: { error: "forbidden" } }),
    });
    renderPage();

    expect(await screen.findByText("forbidden")).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "AI agent settings" })).toBeInTheDocument();
  });
});
