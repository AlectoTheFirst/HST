import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ApplicationEditor } from "./ApplicationEditor";
import type { ApplicationRevision, BusinessApplicationDefinition } from "./types";

const SNAPSHOTS = { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false };
const CONTEXT_OBJECTS = {
  identity: [
    { uid: "zpa:t:idp:okta-finance", name: "Finance", kind: "identity", source: "Okta", selectable: true },
    { uid: "zpa:t:idp:azure-finance", name: "Finance", kind: "identity", source: "Azure", selectable: true },
  ],
  segment: [{ uid: "zpa:t:seg:101", name: "Finance portal", kind: "segment", selectable: true }],
};

const definition: BusinessApplicationDefinition = {
  schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "draft",
  services: [{ id: "shop", name: "Shop", connection_ids: ["frontend-to-api"], component_roles: [] }],
  groups: [
    { id: "frontend", name: "Frontend", members: [{ id: "web-primary", address: "198.51.100.10" }] },
    { id: "api", name: "API", members: [{ id: "api-primary", address: "198.51.100.20" }] },
  ],
  connections: [{
    id: "frontend-to-api", name: "Frontend to API", source: "frontend", destination: "api", success: "forward",
    destination_condition: { kind: "member", member: "api-primary", parts: [] },
  }],
};
const record: ApplicationRevision = {
  id: "checkout", revision: 1, name: "Checkout", digest: "a".repeat(64), created_by: 1,
  created_at: "2026-01-01T00:00:00Z", definition,
};

function optionRequests(): URLSearchParams[] {
  return vi
    .mocked(fetch)
    .mock.calls.map(([input]) => new URL(String(input), "http://localhost"))
    .filter((url) => url.pathname === "/api/assessment-options")
    .map((url) => url.searchParams);
}

it("picks the source identity and the destination segment by name at the selected snapshot", async () => {
  const saved: MockRequest[] = [];
  mockApi({
    "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
    "GET /api/assessment-options": () => {
      const kind = optionRequests().at(-1)!.get("kind") as "identity" | "segment";
      return { body: { snapshot: "4000", items: CONTEXT_OBJECTS[kind], truncated: false } };
    },
    "PUT /api/business-applications/checkout": (req) => {
      saved.push(req);
      return { body: { ...record, revision: 2 } };
    },
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ApplicationEditor record={record} canEdit onSaved={() => undefined} />
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  const snapshot = within(screen.getByRole("group", { name: "Component groups" })).getByLabelText("Inventory snapshot");
  await user.selectOptions(snapshot, await within(snapshot).findByRole("option", { name: /\[full\]/ }));
  const source = screen.getByRole("group", { name: "Source context" });
  const destination = screen.getByRole("group", { name: "Destination context" });

  await user.click(within(source).getByRole("button", { name: "Choose source identity" }));
  const identities = within(source).getByRole("list", { name: "Find source identity results" });
  await user.click(await within(identities).findByRole("button", { name: "Finance Azure" }));
  await user.click(within(destination).getByRole("button", { name: "Choose destination segment" }));
  const segments = within(destination).getByRole("list", { name: "Find destination segment results" });
  await user.click(await within(segments).findByRole("button", { name: "Finance portal" }));

  expect(source).toHaveTextContent("Source identity zpa:t:idp:azure-finance");
  expect(destination).toHaveTextContent("Destination segment zpa:t:seg:101");
  expect(optionRequests().map((params) => [params.get("snapshot"), params.get("kind")])).toEqual([
    ["4000", "identity"],
    ["4000", "segment"],
  ]);

  await user.click(screen.getByRole("button", { name: "Save revision" }));
  await waitFor(() => expect(saved).toHaveLength(1));
  const connection = (saved[0].body as { definition: BusinessApplicationDefinition }).definition.connections[0];
  expect(connection.source_context).toEqual({ identity_uid: "zpa:t:idp:azure-finance" });
  expect(connection.destination_context).toEqual({ segment_uid: "zpa:t:seg:101" });
});
