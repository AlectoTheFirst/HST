import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi } from "../test/fetchMock";
import { ApplicationEditor } from "./ApplicationEditor";
import type { ApplicationRevision } from "./types";

const threshold = { kind: "threshold", n: 1, parts: [{ kind: "member", member: "api-primary", parts: [] }] };

const record = {
  id: "checkout", revision: 1, name: "Checkout", digest: "a".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z",
  definition: {
    schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "draft",
    services: [{ id: "shop", name: "Shop", connection_ids: ["frontend-to-api"], component_roles: [] }],
    groups: [
      { id: "frontend", name: "Frontend", members: [{ id: "web-primary", address: "198.51.100.10" }] },
      { id: "api", name: "API", members: [{ id: "api-primary", address: "198.51.100.20" }] },
      { id: "api-dr", name: "API DR", members: [{ id: "api-dr-primary", address: "198.51.100.30" }] },
    ],
    connections: [{ id: "frontend-to-api", name: "Frontend to API", source: "frontend", destination: "api", success: "round-trip", destination_condition: threshold }],
  },
} as unknown as ApplicationRevision;

it("keeps an advanced destination condition when the destination group changes", async () => {
  const saved: unknown[] = [];
  mockApi({
    "PUT /api/business-applications/checkout": (req) => {
      saved.push(req.body);
      return { body: { ...record, revision: 2 } };
    },
  });
  render(<QueryClientProvider client={new QueryClient()}><ApplicationEditor record={record} canEdit onSaved={() => undefined} /></QueryClientProvider>);
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText("Destination"), "api-dr");
  expect(screen.queryByLabelText("Required destination")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Save revision" }));
  await waitFor(() => expect(saved).toHaveLength(1));
  const body = saved[0] as { definition: { connections: Array<{ destination: string; destination_condition: unknown }> } };
  expect(body.definition.connections[0].destination).toBe("api-dr");
  expect(body.definition.connections[0].destination_condition).toEqual(threshold);
});
