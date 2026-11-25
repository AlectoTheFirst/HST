import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { mockApi } from "../../test/fetchMock";
import { Onboarding } from "./Onboarding";
import type { CollectorFieldMetadata, ConnectionView, CredentialView, ProfileView } from "../../api/inventory";
import type { SourceTypeSchema } from "../../api/types";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { permissions: ["runs.manage", "sources.write", "sites.write", "graph.read"] }, loading: false }) }));

const schema = {
  type: "object",
  properties: {
    vanity_domain: { type: "string", title: "Vanity domain" },
    tenant: { type: "string", title: "Tenant" },
    auth: { type: "object", properties: { method: { const: "oauth_client" }, client_id: { type: "string" }, client_secret: { type: "string", format: "password" } } },
  },
} as unknown as SourceTypeSchema;

const field = (path: string, category: "connection" | "profile" | "credential", label: string) => ({
  path, category, label, secret: category === "credential", variant: null, identity_sensitivity: "none" as const, profile_applicability: "",
});
const meta = (type: string): CollectorFieldMetadata => ({
  collector_type: type,
  kind: "controller",
  fields: [field("vanity_domain", "connection", "Vanity domain"), field("tenant", "connection", "Tenant"),
    field("auth.client_id", "profile", "Client ID"), field("auth.client_secret", "credential", "Client secret")],
});

const zia: ConnectionView = {
  id: "zia1", name: "zia-acme", display_name: "ZIA acme", kind: "controller", collector_type: "zia", enabled: true,
  config: { vanity_domain: "acme", tenant: "acme" }, profile_id: "p-zia", revision: 1, frozen_normalization: null,
  health: { state: "never", last_success_at: null, last_attempt_at: null, failing_targets: 0, target_count: 1, device_count: 0 },
  created_at: "", updated_at: "",
};
const ziaProfile: ProfileView = {
  id: "p-zia", display_name: "ZIA access", collector_type: "zia", current_revision: 1, archived_at: null,
  credential_id: "cred1", credential_revision: 1, settings: { auth: { method: "oauth_client", client_id: "cid-1" } },
  usage: { targets: 1, connections: 1 }, created_at: "", updated_at: "",
};
const credential: CredentialView = {
  id: "cred1", display_name: "OneAPI client", current_revision: 1, secret_paths: ["auth.client_secret"], archived_at: null,
  profiles_using: 1, created_at: "", updated_at: "",
};

describe("Zscaler onboarding", () => {
  it("copies the vanity domain, the client ID and the credential of an existing Zscaler connection", async () => {
    mockApi({
      "GET /api/source-types": () => ({ body: { types: ["zia", "zpa"].map((type) => ({ type, schema })) } }),
      "GET /api/inventory/field-metadata": () => ({ body: [meta("zia"), meta("zpa")] }),
      "GET /api/inventory/connections": () => ({ body: [zia] }),
      "GET /api/inventory/profiles": () => ({ body: [ziaProfile] }),
      "GET /api/inventory/credentials": () => ({ body: [credential] }),
      "GET /api/inventory/sites": () => ({ body: [] }),
    });
    const user = userEvent.setup();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><Onboarding onCancel={() => {}} /></MemoryRouter></QueryClientProvider>);
    await user.selectOptions(screen.getByLabelText("Onboarding type"), "controller");
    await waitFor(() => expect(screen.getByRole("option", { name: "zpa" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Collector type"), "zpa");
    await user.selectOptions(await screen.findByLabelText("Copy from a Zscaler connection"), "zia1");
    expect(screen.getByLabelText(/Vanity domain/)).toHaveValue("acme");
    await user.click(screen.getByRole("button", { name: "Create profile inline" }));
    expect(await screen.findByLabelText(/Client ID/)).toHaveValue("cid-1");
    expect(screen.getByLabelText("Credential")).toHaveValue("cred1");
  });
});
