/**
 * WP-09 "Done when": the visual application editor builds the Checkout
 * structure from names and pickers, shows the connections of each group, and
 * saves the fields it has no control for unchanged.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ApplicationEditor } from "../applications/ApplicationEditor";
import type { ApplicationRevision, BusinessApplicationDefinition } from "../applications/types";
import { mockApi, type MockRequest } from "../test/fetchMock";

const SNAPSHOTS = { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false };
const API_INTERFACE = { uid: "interface:api-primary", name: "api-primary", kind: "interface", device_name: "api-1", site: "DC1", selectable: true };

function revision(definition: BusinessApplicationDefinition): ApplicationRevision {
  return { id: definition.id, revision: 1, name: definition.name, digest: "a".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition };
}

function renderEditor(record: ApplicationRevision, saved: MockRequest[]) {
  mockApi({
    "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
    "GET /api/assessment-options": () => ({ body: { snapshot: "4000", items: [API_INTERFACE], truncated: false } }),
    "PUT /api/business-applications/checkout-production": (req) => {
      saved.push(req);
      return { body: { ...record, revision: 2, definition: (req.body as { definition: BusinessApplicationDefinition }).definition } };
    },
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ApplicationEditor record={record} canEdit onSaved={() => undefined} />
    </QueryClientProvider>,
  );
}

const section = (name: string) => screen.getByRole("group", { name });
const cards = (name: string) => within(section(name)).queryAllByRole("article");
const last = <T,>(items: T[]) => items[items.length - 1];

describe("Building Checkout in the visual editor", () => {
  it("builds the groups, members, connections and service of Checkout from names and pickers", async () => {
    const empty = {
      schema_version: 1, kind: "BusinessApplication", id: "checkout-production", name: "Checkout", state: "draft",
      services: [], groups: [], connections: [],
    } as unknown as BusinessApplicationDefinition;
    const saved: MockRequest[] = [];
    renderEditor(revision(empty), saved);
    const user = userEvent.setup();

    async function addGroup(name: string) {
      await user.click(within(section("Component groups")).getByRole("button", { name: "Add component group" }));
      const card = last(cards("Component groups"));
      await user.clear(within(card).getByLabelText("Name"));
      await user.type(within(card).getByLabelText("Name"), name);
      await user.click(within(card).getByRole("button", { name: "Add member" }));
      return card;
    }
    async function literal(card: HTMLElement, address: string) {
      await user.clear(within(card).getByLabelText("Address or prefix"));
      await user.type(within(card).getByLabelText("Address or prefix"), address);
    }

    await literal(await addGroup("Branch clients"), "192.0.2.0/24");
    await literal(await addGroup("Frontend"), "198.51.100.10");
    const api = await addGroup("API");
    await literal(await addGroup("Checkout database"), "203.0.113.20");

    // the API member is the recorded interface found by name
    await user.selectOptions(within(api).getByLabelText("Source"), "Inventory reference");
    await user.selectOptions(within(api).getByLabelText("Kind"), "Interface");
    const snapshot = within(section("Component groups")).getByLabelText("Inventory snapshot");
    await user.selectOptions(snapshot, await within(snapshot).findByRole("option", { name: /\[full\]/ }));
    await user.type(within(api).getByLabelText("Find interface"), "api");
    await user.click(await within(api).findByRole("button", { name: "api-primary api-1, DC1" }));

    async function addConnection(name: string, source: string, destination: string, port: string) {
      await user.click(within(section("Connections")).getByRole("button", { name: "Add connection" }));
      const card = last(cards("Connections"));
      await user.clear(within(card).getByLabelText("Name"));
      await user.type(within(card).getByLabelText("Name"), name);
      await user.selectOptions(within(card).getByLabelText("Source"), source);
      await user.selectOptions(within(card).getByLabelText("Destination"), destination);
      await user.type(within(card).getByLabelText("Protocol"), "tcp");
      await user.type(within(card).getByLabelText("Destination ports"), port);
      return card;
    }
    await addConnection("Branch clients to frontend", "Branch clients", "Frontend", "443");
    const toApi = await addConnection("Frontend to API", "Frontend", "API", "8443");
    await addConnection("API to database", "API", "Checkout database", "5432");
    expect(within(toApi).getByLabelText("Required destination")).toHaveDisplayValue("api-primary");

    await user.click(within(section("Services")).getByRole("button", { name: "Add service" }));
    const service = last(cards("Services"));
    await user.clear(within(service).getByLabelText("Name"));
    await user.type(within(service).getByLabelText("Name"), "Checkout frontend");
    for (const name of ["Branch clients to frontend", "Frontend to API", "API to database"]) {
      await user.click(within(service).getByRole("checkbox", { name }));
    }

    await user.click(screen.getByRole("button", { name: "Save revision" }));
    await waitFor(() => expect(saved).toHaveLength(1));
    const body = saved[0].body as { definition: BusinessApplicationDefinition; expected_revision: number; source: string };
    expect(body).toMatchObject({ expected_revision: 1, source: "editor" });
    const { groups, connections, services } = body.definition;

    const groupId = Object.fromEntries(groups.map((group) => [group.name, group.id]));
    expect(Object.keys(groupId)).toEqual(["Branch clients", "Frontend", "API", "Checkout database"]);
    expect(new Set(Object.values(groupId)).size).toBe(4);
    expect(groups.find((group) => group.name === "API")!.members).toEqual([
      { id: expect.any(String), name: "api-primary", inventory: { kind: "interface", uid: "interface:api-primary", role: "component" } },
    ]);
    expect(groups.map((group) => group.members.map((member) => member.address ?? member.inventory?.uid))).toEqual([
      ["192.0.2.0/24"], ["198.51.100.10"], ["interface:api-primary"], ["203.0.113.20"],
    ]);

    expect(connections.map((item) => [item.name, item.source, item.destination, item.protocol, item.destination_ports])).toEqual([
      ["Branch clients to frontend", groupId["Branch clients"], groupId.Frontend, "tcp", [443]],
      ["Frontend to API", groupId.Frontend, groupId.API, "tcp", [8443]],
      ["API to database", groupId.API, groupId["Checkout database"], "tcp", [5432]],
    ]);
    expect(new Set(connections.map((item) => item.id)).size).toBe(3);
    // each condition holds the first member of its destination group
    for (const connection of connections) {
      const destination = groups.find((group) => group.id === connection.destination)!;
      expect(connection.destination_condition).toEqual({ kind: "member", member: destination.members[0].id, parts: [] });
    }

    expect(services).toEqual([{ id: expect.any(String), name: "Checkout frontend", connection_ids: connections.map((item) => item.id), component_roles: [] }]);
  });
});

const member = (id: string, address: string) => ({ id, address });
const CHECKOUT = {
  schema_version: 1, kind: "BusinessApplication", id: "checkout-production", name: "Checkout", state: "draft",
  services: [{ id: "checkout-frontend", name: "Checkout frontend", connection_ids: ["clients-to-frontend", "frontend-to-api", "api-to-database"], component_roles: [] }],
  groups: [
    { id: "branch-clients", name: "Branch clients", members: [member("branch-ipv4", "192.0.2.0/24")] },
    { id: "frontend", name: "Frontend", members: [member("web-primary", "198.51.100.10")] },
    { id: "api", name: "API", members: [member("api-primary", "198.51.100.20")] },
    { id: "database", name: "Checkout database", members: [member("database-primary", "203.0.113.20")] },
    { id: "monitoring", name: "Monitoring", members: [member("probe", "198.51.100.99")] },
  ],
  connections: [
    { id: "clients-to-frontend", name: "Branch clients to frontend", source: "branch-clients", destination: "frontend", success: "session", destination_condition: { kind: "member", member: "web-primary", parts: [] } },
    { id: "frontend-to-api", name: "Frontend to API", source: "frontend", destination: "api", success: "round-trip", destination_condition: { kind: "member", member: "api-primary", parts: [] } },
    { id: "api-to-database", name: "API to database", source: "api", destination: "database", success: "session", destination_condition: { kind: "member", member: "database-primary", parts: [] } },
  ],
} as unknown as BusinessApplicationDefinition;

describe("Affected connections of a group", () => {
  it("lists the connections of each group and follows a connection edit", async () => {
    renderEditor(revision(CHECKOUT), []);
    const user = userEvent.setup();
    const group = (name: string) => cards("Component groups").find((card) => within(card).getByLabelText("Name").getAttribute("value") === name)!;

    expect(group("Frontend")).toHaveTextContent("Affects Branch clients to frontend, Frontend to API");
    expect(group("API")).toHaveTextContent("Affects Frontend to API, API to database");
    expect(group("Checkout database")).toHaveTextContent("Affects API to database");
    expect(group("Monitoring")).not.toHaveTextContent("Affects");

    const toDatabase = cards("Connections").find((card) => within(card).getByLabelText("Name").getAttribute("value") === "API to database")!;
    await user.selectOptions(within(toDatabase).getByLabelText("Source"), "Monitoring");

    expect(group("API")).toHaveTextContent("Affects Frontend to API");
    expect(group("API")).not.toHaveTextContent("API to database");
    expect(group("Monitoring")).toHaveTextContent("Affects API to database");

    await user.clear(within(toDatabase).getByLabelText("Name"));
    await user.type(within(toDatabase).getByLabelText("Name"), "Monitoring to database");
    expect(group("Checkout database")).toHaveTextContent("Affects Monitoring to database");
  });
});

describe("Advanced fields through an editor save", () => {
  it("saves the fields without a form control unchanged beside the edited fields", async () => {
    const advanced = structuredClone(CHECKOUT) as unknown as Record<string, unknown> & BusinessApplicationDefinition;
    advanced.description = "Synthetic production checkout example";
    advanced.services[0].description = "Customer checkout";
    advanced.services[0].component_roles = [{ group_id: "frontend", role: "endpoint" }];
    advanced.groups[0].description = "Branch client prefixes";
    advanced.groups[0].members[0] = { ...advanced.groups[0].members[0], name: "Branch IPv4", context: "vrf:branch" };
    advanced.connections[0] = {
      ...advanced.connections[0],
      description: "Client sessions",
      protocol: "tcp", destination_ports: [443], source_ports: ["1024-65535"],
      source_context: { vrf: "vrf:branch" },
      mtu: { mode: "packet", ip_packet_bytes: 1500, ipv4_df: true },
      header_constraints: { dscp: [[46, 46]] },
      provenance: { source: "trace", trace_id: "trace-7" },
    };
    advanced.connections[1] = {
      ...advanced.connections[1],
      protocol: "tcp", destination_ports: [8443],
      destination_context: { vrf: "vrf:production" },
      destination_condition: { kind: "threshold", n: 1, parts: [{ kind: "member", member: "api-primary", parts: [] }] },
    };
    const saved: MockRequest[] = [];
    renderEditor(revision(advanced), saved);
    const user = userEvent.setup();

    // edit the connection that holds the threshold condition and a context
    const toApi = cards("Connections").find((card) => within(card).getByLabelText("Name").getAttribute("value") === "Frontend to API")!;
    await user.clear(within(toApi).getByLabelText("Destination ports"));
    await user.type(within(toApi).getByLabelText("Destination ports"), "9443");
    // and the service that holds the component roles
    const service = cards("Services")[0];
    await user.clear(within(service).getByLabelText("Name"));
    await user.type(within(service).getByLabelText("Name"), "Checkout storefront");

    await user.click(screen.getByRole("button", { name: "Save revision" }));
    await waitFor(() => expect(saved).toHaveLength(1));
    const definition = (saved[0].body as { definition: BusinessApplicationDefinition }).definition;

    const expected = structuredClone(advanced);
    expected.connections[1].destination_ports = [9443];
    expected.services[0].name = "Checkout storefront";
    expect(definition).toEqual(expected);
  });
});
