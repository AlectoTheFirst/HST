import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import AiSettingsPage from "./AiSettingsPage";
import { mockApi, type MockRequest } from "../test/fetchMock";
import type { AiEvents, AiProviders, AiSettings } from "../api/types";

const providers: AiProviders = {
  prompt_layers: [],
  providers: [
    {
      id: "openrouter", label: "OpenRouter", models: ["anthropic/claude-opus-5"],
      supports_effort: false,
      credentials: [{ name: "api_key", label: "API key", secret: true, required: true }],
      options: [{ name: "base_url", label: "Base URL", secret: false }],
    },
    {
      id: "bedrock", label: "AWS Bedrock", models: ["anthropic.claude-opus-5"],
      supports_effort: true,
      credentials: [
        { name: "aws_bedrock_api_key", label: "Bedrock API key (optional)", secret: true, placeholder: "ABSK..." },
        { name: "aws_access_key_id", label: "Access key id (optional)", secret: true },
        { name: "aws_secret_access_key", label: "Secret access key (optional)", secret: true },
        { name: "aws_session_token", label: "Session token (optional)", secret: true },
      ],
      options: [
        {
          name: "aws_region", label: "AWS region", secret: false, required: true,
          help: "Required, including when using a Bedrock API key.",
        },
        {
          name: "base_url", label: "Endpoint URL (optional)", secret: false,
          help: "Leave blank to use the selected region's Bedrock endpoint.",
        },
        { name: "tls_skip_verify", label: "Skip TLS certificate verification", secret: false, kind: "checkbox" },
        { name: "tls_ca_bundle", label: "CA certificate (PEM, optional)", secret: false, kind: "textarea" },
      ],
    },
    {
      id: "anthropic", label: "Anthropic", models: ["claude-opus-5"],
      supports_effort: true,
      credentials: [{ name: "api_key", label: "API key", secret: true, required: true }],
    },
  ],
};

const saved: AiSettings = {
  enabled: true, configured: true, provider: "openrouter", model: "openai/gpt-5",
  effort: "medium", system_prompt: "Site instructions to keep", stored_credentials: ["api_key"],
  options: { base_url: "https://openrouter.ai/api/v1" },
};

const bedrock: AiSettings = {
  enabled: true, configured: true, provider: "bedrock", model: "anthropic.claude-opus-5",
  effort: "high", system_prompt: "", stored_credentials: ["aws_bedrock_api_key"],
  options: { aws_region: "eu-central-1" },
};

function setup(stored: AiSettings = saved, refusal?: string) {
  const probes: Record<string, unknown>[] = [];
  const saves: Record<string, unknown>[] = [];
  mockApi({
    "GET /api/settings/ai/providers": () => ({ body: providers }),
    "GET /api/settings/ai": () => ({ body: stored }),
    "POST /api/settings/ai/test": (req: MockRequest) => {
      const body = req.body as Record<string, unknown>;
      probes.push(body);
      return { body: { ok: true, provider: body.provider, model: body.model } };
    },
    "PUT /api/settings/ai": (req: MockRequest) => {
      const body = req.body as Record<string, unknown>;
      saves.push(body);
      if (refusal) return { status: 400, body: { error: refusal } };
      return { body: { ...stored, ...body } };
    },
    "GET /api/settings/ai/events": () => ({ body: { events: [], daily_tokens: [] } satisfies AiEvents }),
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={queryClient}><AiSettingsPage /></QueryClientProvider>);
  return { user: userEvent.setup(), probes, saves };
}

describe("AI provider connection settings", () => {
  it("switches Bedrock to its own model and endpoint and tests the entered key and region", async () => {
    const { user, probes } = setup();
    await user.selectOptions(await screen.findByLabelText("Provider"), "bedrock");
    expect(screen.getByLabelText("Model")).toHaveValue("anthropic.claude-opus-5");
    expect(screen.getByLabelText("Endpoint URL (optional)")).toHaveValue("");
    expect(screen.getByLabelText("Site instructions")).toHaveValue(saved.system_prompt);
    expect(screen.queryByPlaceholderText("stored value")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(/Bedrock API key/), "ABSK-test");
    const region = screen.getByLabelText("AWS region");
    expect(region).toBeRequired();
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(probes).toHaveLength(0);
    expect(region).toBeInvalid();
    await user.type(region, " eu-central-1 ");
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(probes).toEqual([{
      provider: "bedrock", model: "anthropic.claude-opus-5", effort: "high",
      options: { aws_region: "eu-central-1" }, secrets: { aws_bedrock_api_key: "ABSK-test" },
    }]);
  });

  it("requires a region on save but permits AWS identity authentication without a key", async () => {
    const { user, saves } = setup();
    await user.selectOptions(await screen.findByLabelText("Provider"), "bedrock");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(0);
    await user.type(screen.getByLabelText("AWS region"), "eu-central-1");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(1);
    expect(saves[0]).toMatchObject({ provider: "bedrock", options: { aws_region: "eu-central-1" } });
    expect(saves[0]).not.toHaveProperty("credentials");
  });

  it("restores the saved provider connection settings when switching back", async () => {
    const { user } = setup();
    await user.selectOptions(await screen.findByLabelText("Provider"), "bedrock");
    await user.type(screen.getByLabelText(/Bedrock API key/), "ABSK-test");
    await user.selectOptions(screen.getByLabelText("Provider"), "openrouter");
    expect(screen.getByLabelText("Model")).toHaveValue(saved.model);
    expect(screen.getByLabelText("Base URL")).toHaveValue(saved.options?.base_url);
    expect(screen.getByPlaceholderText("stored value")).toHaveValue("");
  });

  it("does not reuse an OpenRouter API key when switching to Anthropic", async () => {
    const { user, probes } = setup();
    await user.selectOptions(await screen.findByLabelText("Provider"), "anthropic");
    const key = screen.getByLabelText("API key");
    expect(key).toBeRequired();
    expect(screen.getByLabelText("Model")).toHaveValue("claude-opus-5");
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(probes).toHaveLength(0);
    await user.type(key, "sk-ant-test");
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(probes[0]).toMatchObject({ provider: "anthropic", options: {}, secrets: { api_key: "sk-ant-test" } });
  });

  it("clears stale test results when connection settings change", async () => {
    const { user } = setup();
    await user.click(await screen.findByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/Reached openrouter/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Model"));
    expect(screen.queryByText(/Reached openrouter/)).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Model"), "openai/gpt-5");
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/Reached openrouter/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Provider"), "bedrock");
    expect(screen.queryByText(/Reached openrouter/)).not.toBeInTheDocument();
  });
});

describe("AI provider credentials and the stored endpoint", () => {
  async function changeRegion(user: ReturnType<typeof userEvent.setup>) {
    const region = await screen.findByLabelText("AWS region");
    await user.clear(region);
    await user.type(region, "eu-west-1");
  }

  it("requires the stored credential again when the region changes", async () => {
    const { user, saves } = setup(bedrock);
    await changeRegion(user);
    const key = screen.getByLabelText(/Bedrock API key/);
    expect(screen.getByText(/re-entry required/)).toBeInTheDocument();
    expect(key).toBeRequired();
    expect(key).toHaveAttribute("placeholder", "ABSK...");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(0);
    await user.type(key, "ABSK-new");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(1);
    expect(saves[0]).toMatchObject({
      options: { aws_region: "eu-west-1" }, credentials: { aws_bedrock_api_key: "ABSK-new" },
    });
  });

  it("sends null for the stored API key when the region and the auth mode change", async () => {
    const { user, saves, probes } = setup(bedrock);
    await changeRegion(user);
    await user.type(screen.getByLabelText(/Access key id/), "AKIA-new");
    await user.type(screen.getByLabelText(/Secret access key/), "new-secret");
    expect(screen.getByText(/removed on save/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Bedrock API key/)).not.toBeRequired();
    const credentials = {
      aws_bedrock_api_key: null, aws_access_key_id: "AKIA-new", aws_secret_access_key: "new-secret",
    };
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(probes).toHaveLength(1);
    expect(probes[0].secrets).toEqual(credentials);
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(1);
    expect(saves[0].credentials).toEqual(credentials);
  });

  it("sends null for the stored API key when only the auth mode changes", async () => {
    const { user, saves } = setup(bedrock);
    await user.type(await screen.findByLabelText(/Access key id/), "AKIA-new");
    await user.type(screen.getByLabelText(/Secret access key/), "new-secret");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves[0].credentials).toEqual({
      aws_bedrock_api_key: null, aws_access_key_id: "AKIA-new", aws_secret_access_key: "new-secret",
    });
  });

  it("requires the stored credential again when the TLS check gets weaker", async () => {
    const { user, saves } = setup(bedrock);
    const key = await screen.findByLabelText(/Bedrock API key/);
    expect(key).not.toBeRequired();
    await user.click(screen.getByLabelText(/Skip TLS certificate verification/));
    expect(key).toBeRequired();
    await user.click(screen.getByLabelText(/Skip TLS certificate verification/));
    expect(key).not.toBeRequired();
    await user.type(screen.getByLabelText(/CA certificate/), "-----BEGIN CERTIFICATE-----");
    expect(key).toBeRequired();
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(0);
  });

  it("keeps the stored credential on a save that changes only the model", async () => {
    const { user, saves } = setup(bedrock);
    const model = await screen.findByLabelText("Model");
    await user.clear(model);
    await user.type(model, "eu.anthropic.claude-opus-5-5");
    const key = screen.getByLabelText(/Bedrock API key/);
    expect(key).not.toBeRequired();
    expect(key).toHaveAttribute("placeholder", "stored value");
    expect(screen.queryByText(/re-entry required|removed on save/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves).toHaveLength(1);
    expect(saves[0]).toMatchObject({ model: "eu.anthropic.claude-opus-5-5", options: bedrock.options });
    expect(saves[0]).not.toHaveProperty("credentials");
  });

  it("sends null for a stored credential of the provider that the form switches to", async () => {
    const { user, saves } = setup({ ...saved, stored_credentials: ["api_key", "aws_bedrock_api_key"] });
    await user.selectOptions(await screen.findByLabelText("Provider"), "bedrock");
    expect(screen.queryByText(/stored|removed on save/)).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("AWS region"), "eu-central-1");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(saves[0].credentials).toEqual({ aws_bedrock_api_key: null });
  });

  it("shows the 400 detail of a refused save", async () => {
    const refusal = "credentials required for an endpoint other than the stored one: aws_bedrock_api_key";
    const { user } = setup(bedrock, refusal);
    await user.click(await screen.findByRole("button", { name: "Save" }));
    expect(await screen.findByText(refusal)).toBeInTheDocument();
  });
});
