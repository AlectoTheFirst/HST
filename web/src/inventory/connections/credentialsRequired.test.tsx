import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockHandler } from "../../test/fetchMock";
import { ConnectionDetailPage } from "./ConnectionDetailPage";
import type { CollectorFieldMetadata, ConnectionView, ProfileView, TargetView } from "../../api/inventory";
import type { SourceTypeSchema } from "../../api/types";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { permissions: ["runs.manage", "sources.write", "sites.write", "graph.read"] }, loading: false }) }));

// the text of src/hst/app/source_egress.py OTHER_ENDPOINT_DETAIL
const REFUSAL = "credentials required for an endpoint other than the stored one: auth.password";

const schema: SourceTypeSchema = { type: "object", properties: { url: { type: "string", title: "APIC URL" } } };
const meta: CollectorFieldMetadata = { collector_type: "apic", kind: "controller", fields: [
  { path: "url", category: "connection", secret: false, variant: null, identity_sensitivity: "none", profile_applicability: "", label: "APIC URL", endpoint: "destination" },
  { path: "auth.password", category: "credential", secret: true, variant: null, identity_sensitivity: "none", profile_applicability: "", label: "Password" },
] };
const connection: ConnectionView = { id: "c1", name: "aci", display_name: "ACI", kind: "controller", collector_type: "apic", enabled: false, config: { url: "https://apic1.example" }, profile_id: "p1", revision: 1, frozen_normalization: null, health: { state: "never", last_success_at: null, last_attempt_at: null, failing_targets: 0, target_count: 1, device_count: 0 }, created_at: "", updated_at: "" };
const profile: ProfileView = { id: "p1", display_name: "APIC access", collector_type: "apic", current_revision: 1, archived_at: null, credential_id: "k1", credential_revision: 1, settings: {}, usage: { targets: 0, connections: 1 }, created_at: "", updated_at: "" };
const target: TargetView = { id: "t1", connection_id: "c1", source_key: "aci", host: "", port: null, kind: "controller", enabled: false, host_key_pinned: false, profile_id: null, onboarding_site_id: null, legacy_device_id: null, revision: 1, archived_at: null, observed_device_ids: [], last_attempt_at: null, last_success_at: null, consecutive_failures: 0, last_error: "" };

function routes(overrides: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/source-types": () => ({ body: { types: [{ type: "apic", schema }] } }),
    "GET /api/inventory/field-metadata": () => ({ body: [meta] }),
    "GET /api/inventory/connections/c1": () => ({ body: connection }),
    "GET /api/inventory/profiles": () => ({ body: [profile] }),
    "GET /api/inventory/sites": () => ({ body: [] }),
    "GET /api/inventory/targets": () => ({ body: [target] }),
    ...overrides,
  });
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/inventory/connections/c1"]}>
        <Routes>
          <Route path="/inventory/connections/:id" element={<ConnectionDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("connection editor: a new endpoint needs the stored secret again", () => {
  it("asks for each secret the refusal names and sends it with the new URL", async () => {
    const user = userEvent.setup();
    const bodies: Record<string, unknown>[] = [];
    const patch = vi.fn((req: { body?: unknown }) => {
      const body = req.body as Record<string, unknown>;
      bodies.push(body);
      return body.secrets
        ? { body: { ...connection, config: { url: "https://apic2.example" }, revision: 2 } }
        : { status: 422, body: { error: REFUSAL, code: "validation", references: [], detail: { credentials: ["auth.password"] } } };
    });
    routes({ "PATCH /api/inventory/connections/c1": patch });
    mount();

    await user.click(await screen.findByRole("tab", { name: "Configuration" }));
    await user.click(await screen.findByRole("button", { name: "Edit connection" }));
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    const url = screen.getByLabelText("APIC URL");
    await user.clear(url);
    await user.type(url, "https://apic2.example");
    await user.click(screen.getByRole("button", { name: "Save connection" }));

    expect(await screen.findByText(REFUSAL)).toBeInTheDocument();
    const password = await screen.findByLabelText("Password");
    expect(password).toHaveAttribute("type", "password");
    await user.type(password, "typed-again");
    await user.click(screen.getByRole("button", { name: "Save connection" }));

    await waitFor(() => expect(patch).toHaveBeenCalledTimes(2));
    expect(bodies[0].secrets).toBeUndefined();
    expect(bodies[1]).toMatchObject({ config: { url: "https://apic2.example" }, secrets: { "auth.password": "typed-again" } });
    await screen.findByRole("button", { name: "Edit connection" });
  });
});
