import { expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi } from "../../test/fetchMock";
import type { ConnectionView } from "../../api/inventory";
import { AddTargets } from "./Onboarding";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { permissions: ["sources.write"] } }) }));

it("keeps each onboarding identity override on its own target", async () => {
  const saved: unknown[] = [];
  mockApi({
    "GET /api/inventory/profiles": () => ({ body: [] }),
    "GET /api/inventory/sites": () => ({ body: [] }),
    "GET /api/source-types": () => ({ body: { types: [{ type: "checkpoint_gateway", schema: {
      type: "object", properties: { appliance_uid: { type: "string" } },
    } }] } }),
    "GET /api/inventory/field-metadata": () => ({ body: [{ collector_type: "checkpoint_gateway", kind: "direct", fields: [
      { path: "appliance_uid", category: "target", label: "Appliance UID", secret: false },
    ] }] }),
    "POST /api/inventory/targets": request => { saved.push(request.body); return { body: {} }; },
  });
  const connection = { id: "fleet", collector_type: "checkpoint_gateway" } as ConnectionView;
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <AddTargets connection={connection} />
  </QueryClientProvider>);
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Hosts and optional ports"), "one\ntwo");
  await user.click(screen.getByRole("button", { name: "Preview targets" }));
  await waitFor(() => expect(screen.getAllByText("Target identity overrides")).toHaveLength(2));
  await user.click(screen.getAllByText("Target identity overrides")[0]);
  await user.type(screen.getAllByLabelText("Appliance UID")[0], "appliance-one");
  await user.click(screen.getByRole("button", { name: "Save targets" }));
  await waitFor(() => expect(saved).toHaveLength(2));
  expect(saved[0]).toMatchObject({ host: "one", endpoint_config: { appliance_uid: "appliance-one" } });
  expect(saved[1]).not.toHaveProperty("endpoint_config");
});
