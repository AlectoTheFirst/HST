import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockHandler } from "../../test/fetchMock";
import { ConnectionDetailPage } from "./ConnectionDetailPage";
import { Onboarding } from "./Onboarding";
import type { CollectorFieldMetadata, ConnectionView, ProfileView, TargetView } from "../../api/inventory";
import type { SourceTypeSchema } from "../../api/types";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { permissions: ["runs.manage", "sources.write", "sites.write", "graph.read"] }, loading: false }) }));

// the text src/hst/app/sources.py shared_routing_scope_warnings returns
const SCOPE_WARNING = "routing scope 'home' is also the routing scope of office-unifi: prefixes and addresses these sources report for one subnet are one node";

const schema: SourceTypeSchema = { type: "object", properties: { host: { type: "string", title: "Endpoint" }, interval_s: { type: "integer", default: 60 } } };
const meta: CollectorFieldMetadata = { collector_type: "ctrl", kind: "controller", fields: [
  { path: "host", category: "connection", secret: false, variant: null, identity_sensitivity: "identity", profile_applicability: "", label: "Endpoint" },
  { path: "interval_s", category: "profile", secret: false, variant: null, identity_sensitivity: "none", profile_applicability: "", label: "Interval" },
] };
const connection: ConnectionView = { id: "c1", name: "controller-key", display_name: "Controller", kind: "controller", collector_type: "ctrl", enabled: false, config: { host: "controller.example" }, profile_id: "p1", revision: 1, frozen_normalization: null, health: { state: "never", last_success_at: null, last_attempt_at: null, failing_targets: 0, target_count: 1, device_count: 0 }, created_at: "", updated_at: "" };
const profile: ProfileView = { id: "p1", display_name: "Standard access", collector_type: "ctrl", current_revision: 2, archived_at: null, credential_id: null, credential_revision: null, settings: { interval_s: 60 }, usage: { targets: 0, connections: 1 }, created_at: "", updated_at: "" };
const target: TargetView = { id: "t1", connection_id: "c1", source_key: connection.name, host: "controller.example", port: null, kind: "controller", enabled: false, host_key_pinned: false, profile_id: null, onboarding_site_id: null, legacy_device_id: null, revision: 1, archived_at: null, observed_device_ids: [], last_attempt_at: null, last_success_at: null, consecutive_failures: 0, last_error: "" };

function routes(overrides: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/source-types": () => ({ body: { types: [{ type: "ctrl", schema }] } }),
    "GET /api/inventory/field-metadata": () => ({ body: [meta] }),
    "GET /api/inventory/connections": () => ({ body: [connection] }),
    "GET /api/inventory/connections/c1": () => ({ body: connection }),
    "GET /api/inventory/profiles": () => ({ body: [profile] }),
    "GET /api/inventory/sites": () => ({ body: [] }),
    "GET /api/inventory/targets": () => ({ body: [target] }),
    ...overrides,
  });
}

function mount(entry: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/inventory/connections" element={<Onboarding onCancel={() => {}} />} />
          <Route path="/inventory/connections/:id" element={<ConnectionDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("connection save warnings", () => {
  it("shows the routing scope warning an edit returns, until it is dismissed", async () => {
    const user = userEvent.setup();
    const patch = vi.fn((_req: unknown) => ({ body: { ...connection, revision: 2, warnings: [SCOPE_WARNING] } }));
    routes({ "PATCH /api/inventory/connections/c1": patch });
    mount("/inventory/connections/c1");

    await user.click(await screen.findByRole("tab", { name: "Configuration" }));
    await user.click(await screen.findByRole("button", { name: "Edit connection" }));
    await user.click(await screen.findByRole("button", { name: "Save connection" }));

    const banner = await screen.findByRole("status", { name: "Save warnings for Controller" });
    expect(within(banner).getByText(SCOPE_WARNING)).toBeInTheDocument();
    expect(patch).toHaveBeenCalledTimes(1);
    // the editor closes: the save committed
    expect(screen.queryByRole("button", { name: "Save connection" })).not.toBeInTheDocument();

    await user.click(within(banner).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("status", { name: "Save warnings for Controller" })).not.toBeInTheDocument();
  });

  it("shows no banner when the edit returns no warnings", async () => {
    const user = userEvent.setup();
    const patch = vi.fn((_req: unknown) => ({ body: { ...connection, revision: 2 } }));
    routes({ "PATCH /api/inventory/connections/c1": patch });
    mount("/inventory/connections/c1");

    await user.click(await screen.findByRole("tab", { name: "Configuration" }));
    await user.click(await screen.findByRole("button", { name: "Edit connection" }));
    await user.click(await screen.findByRole("button", { name: "Save connection" }));
    await waitFor(() => expect(patch).toHaveBeenCalledTimes(1));
    await screen.findByRole("button", { name: "Edit connection" });
    expect(screen.queryByRole("status", { name: /Save warnings/ })).not.toBeInTheDocument();
  });

  it("shows the warning an enable toggle returns", async () => {
    const user = userEvent.setup();
    routes({ "PATCH /api/inventory/connections/c1": () => ({ body: { ...connection, enabled: true, revision: 2, warnings: [SCOPE_WARNING] } }) });
    mount("/inventory/connections/c1");

    await user.click(await screen.findByRole("button", { name: "Enable connection" }));
    const banner = await screen.findByRole("status", { name: "Save warnings for Controller" });
    expect(within(banner).getByText(SCOPE_WARNING)).toBeInTheDocument();
  });

  it("carries the warning an onboarding create returns to the connection page", async () => {
    const user = userEvent.setup();
    const create = vi.fn((_req: unknown) => ({ body: { ...connection, warnings: [SCOPE_WARNING] } }));
    routes({ "POST /api/inventory/connections": create });
    mount("/inventory/connections");

    await user.selectOptions(screen.getByLabelText("Onboarding type"), "controller");
    await waitFor(() => expect(screen.getByRole("option", { name: "ctrl" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Collector type"), "ctrl");
    await user.type(screen.getByLabelText("Source key"), "controller-key");
    await user.type(screen.getByLabelText("Endpoint"), "controller.example");
    await user.selectOptions(screen.getByLabelText("Collection profile"), "p1");
    await user.click(screen.getByRole("button", { name: "Preview onboarding" }));
    await user.click(await screen.findByRole("button", { name: "Save reviewed onboarding" }));

    const banner = await screen.findByRole("status", { name: "Save warnings for Controller" });
    expect(within(banner).getByText(SCOPE_WARNING)).toBeInTheDocument();
    expect(create).toHaveBeenCalledTimes(1);
  });
});
