import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { ApplicationEditor } from "./ApplicationEditor";
import ApplicationsPage from "./ApplicationsPage";
import type { ApplicationRevision, BusinessApplicationDefinition } from "./types";

const SNAPSHOTS = { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false };
const OBJECTS = [
  { uid: "device:edge-1", name: "edge-1", kind: "device", site: "DC1", selectable: true },
  { uid: "interface:edge-1:eth0", name: "eth0", kind: "interface", device_name: "edge-1", site: "DC1", selectable: true },
];

function definition(): BusinessApplicationDefinition {
  return {
    schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "draft",
    services: [{ id: "shop", name: "Shop", connection_ids: ["frontend-to-api"], component_roles: [{ group_id: "api", role: "dependency" }] }],
    groups: [
      { id: "frontend", name: "Frontend", members: [{ id: "web-primary", address: "198.51.100.10" }] },
      {
        id: "api", name: "API", members: [
          { id: "api-primary", address: "198.51.100.20" },
          { id: "api-secondary", address: "198.51.100.21" },
        ],
      },
    ],
    connections: [{
      id: "frontend-to-api", name: "Frontend to API", source: "frontend", destination: "api", success: "forward",
      destination_condition: { kind: "member", member: "api-primary", parts: [] },
    }],
  };
}

function revision(value: BusinessApplicationDefinition): ApplicationRevision {
  return { id: value.id, revision: 1, name: value.name, digest: "a".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition: value };
}

function renderEditor(value: BusinessApplicationDefinition = definition()) {
  const saved: MockRequest[] = [];
  mockApi({
    "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
    "GET /api/assessment-options": () => ({ body: { snapshot: "4000", items: OBJECTS, truncated: false } }),
    "PUT /api/business-applications/checkout": (req) => {
      saved.push(req);
      return { body: { ...revision(value), revision: 2 } };
    },
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ApplicationEditor record={revision(value)} canEdit onSaved={() => undefined} />
    </QueryClientProvider>,
  );
  return saved;
}

const card = (section: string, index = 0) =>
  within(screen.getByRole("group", { name: section })).getAllByRole("article")[index];

async function save(user: ReturnType<typeof userEvent.setup>, saved: MockRequest[]) {
  await user.click(screen.getByRole("button", { name: "Save revision" }));
  await waitFor(() => expect(saved).toHaveLength(1));
  return (saved[0].body as { definition: BusinessApplicationDefinition }).definition;
}

describe("Destination condition", () => {
  it("builds an at least N condition over the destination members", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const connection = card("Connections");
    await user.selectOptions(within(connection).getByLabelText("Condition type"), "At least N");
    expect(within(connection).queryByLabelText("Required destination")).not.toBeInTheDocument();
    await user.click(within(connection).getByRole("button", { name: "Add condition" }));
    const members = within(connection).getAllByLabelText("Required member");
    await user.selectOptions(members[1], "api-secondary");
    await user.clear(within(connection).getByLabelText("Minimum members or groups"));
    await user.type(within(connection).getByLabelText("Minimum members or groups"), "2");

    expect((await save(user, saved)).connections[0].destination_condition).toEqual({
      kind: "threshold", n: 2, parts: [
        { kind: "member", member: "api-primary", parts: [] },
        { kind: "member", member: "api-secondary", parts: [] },
      ],
    });
  });

  it("builds an all condition with a nested any condition", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const connection = card("Connections");
    await user.selectOptions(within(connection).getByLabelText("Condition type"), "All");
    await user.click(within(connection).getByRole("button", { name: "Add condition" }));
    const types = within(connection).getAllByLabelText("Condition type");
    await user.selectOptions(types[2], "Any");

    expect((await save(user, saved)).connections[0].destination_condition).toEqual({
      kind: "and", parts: [
        { kind: "member", member: "api-primary", parts: [] },
        { kind: "or", parts: [{ kind: "member", member: "api-primary", parts: [] }] },
      ],
    });
  });

  it("returns to a single member condition", async () => {
    const value = definition();
    value.connections[0].destination_condition = {
      kind: "or", parts: [{ kind: "member", member: "api-primary", parts: [] }, { kind: "member", member: "api-secondary", parts: [] }],
    };
    const saved = renderEditor(value);
    const user = userEvent.setup();
    const connection = card("Connections");
    await user.selectOptions(within(connection).getAllByLabelText("Condition type")[0], "One member");
    await user.selectOptions(within(connection).getByLabelText("Required destination"), "api-secondary");

    expect((await save(user, saved)).connections[0].destination_condition).toEqual({ kind: "member", member: "api-secondary", parts: [] });
  });
});

describe("Endpoint contexts", () => {
  it("sets the VRF and picks the device and the ingress interface by name", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const snapshot = within(screen.getByRole("group", { name: "Component groups" })).getByLabelText("Inventory snapshot");
    await user.selectOptions(snapshot, await within(snapshot).findByRole("option", { name: /\[full\]/ }));
    const source = within(card("Connections")).getByRole("group", { name: "Source context" });
    const destination = within(card("Connections")).getByRole("group", { name: "Destination context" });

    await user.type(within(source).getByLabelText("Source VRF"), "vrf:branch");
    await user.click(within(source).getByRole("button", { name: "Choose source device" }));
    await user.click(within(destination).getByRole("button", { name: "Choose destination ingress interface" }));
    await user.click(await within(within(source).getByRole("list", { name: "Find source device results" })).findByRole("button", { name: /^edge-1/ }));
    await user.click(await within(within(destination).getByRole("list", { name: "Find destination ingress interface results" })).findByRole("button", { name: /^eth0/ }));
    expect(source).toHaveTextContent("Source device device:edge-1");
    expect(within(source).queryByLabelText("Find source device")).not.toBeInTheDocument();
    expect(destination).toHaveTextContent("Destination ingress interface interface:edge-1:eth0");

    const connection = (await save(user, saved)).connections[0];
    expect(connection.source_context).toEqual({ vrf: "vrf:branch", device_uid: "device:edge-1" });
    expect(connection.destination_context).toEqual({ ingress_interface_uid: "interface:edge-1:eth0" });
  });

  it("shows the identity and the segment and removes a context field", async () => {
    const value = definition();
    value.connections[0].source_context = { identity_uid: "identity:staff", segment_uid: "segment:checkout", device_uid: "device:edge-1" };
    const saved = renderEditor(value);
    const user = userEvent.setup();
    const source = within(card("Connections")).getByRole("group", { name: "Source context" });
    expect(source).toHaveTextContent("Source identity identity:staff");
    expect(source).toHaveTextContent("Source segment segment:checkout");

    await user.click(within(source).getByRole("button", { name: "Remove source device" }));
    expect((await save(user, saved)).connections[0].source_context).toEqual({ identity_uid: "identity:staff", segment_uid: "segment:checkout" });
  });

  it("removes the context when its last field is cleared", async () => {
    const value = definition();
    value.connections[0].destination_context = { vrf: "vrf:production" };
    const saved = renderEditor(value);
    const user = userEvent.setup();
    await user.clear(within(card("Connections")).getByLabelText("Destination VRF"));
    expect((await save(user, saved)).connections[0]).not.toHaveProperty("destination_context");
  });
});

describe("Connection MTU", () => {
  it("sets and clears the packet size requirement", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const connection = card("Connections");
    await user.selectOptions(within(connection).getByLabelText("MTU assessment"), "Require unfragmented packet size");
    await user.clear(within(connection).getByLabelText("Complete IP packet bytes"));
    await user.type(within(connection).getByLabelText("Complete IP packet bytes"), "9000");
    await user.type(within(connection).getByLabelText("MTU traffic class"), "bulk");
    expect((await save(user, saved)).connections[0].mtu).toEqual({ mode: "unfragmented", ip_packet_bytes: 9000, traffic_class: "bulk" });
  });

  it("hides the IPv4 Don't Fragment choice for an IPv6 source group", async () => {
    const value = definition();
    value.groups[0].members = [{ id: "web-primary", address: "2001:db8::10" }];
    value.connections[0].mtu = { mode: "packet", ip_packet_bytes: 1500 };
    renderEditor(value);
    expect(within(card("Connections")).queryByLabelText("IPv4 Don't Fragment")).not.toBeInTheDocument();
  });
});

describe("Members", () => {
  it("names a literal member and sets the role of an inventory member", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const api = card("Component groups", 1);
    const [primary, secondary] = within(api).getAllByLabelText("Member ID").map((input) => input.closest<HTMLElement>(".application-member")!);
    await user.type(within(primary).getByLabelText("Member name"), "API primary");
    await user.selectOptions(within(secondary).getByLabelText("Source"), "Inventory reference");
    expect(within(secondary).getByLabelText("Role")).toHaveDisplayValue("Component");
    await user.selectOptions(within(secondary).getByLabelText("Role"), "Shared");
    await user.type(within(secondary).getByLabelText("Inventory UID"), "interface:api-2");

    expect((await save(user, saved)).groups[1].members).toEqual([
      { id: "api-primary", name: "API primary", address: "198.51.100.20" },
      { id: "api-secondary", inventory: { kind: "interface", uid: "interface:api-2", role: "shared" } },
    ]);
  });
});

describe("Stable IDs", () => {
  it("renames a group, a member and a connection in the references", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const api = card("Component groups", 1);
    await user.clear(within(api).getByLabelText("Stable ID"));
    await user.type(within(api).getByLabelText("Stable ID"), "api-tier");
    await user.clear(within(api).getAllByLabelText("Member ID")[0]);
    await user.type(within(api).getAllByLabelText("Member ID")[0], "api-node-1");
    const connection = card("Connections");
    await user.clear(within(connection).getByLabelText("Stable ID"));
    await user.type(within(connection).getByLabelText("Stable ID"), "web-to-api");

    const value = await save(user, saved);
    expect(value.groups[1].id).toBe("api-tier");
    expect(value.connections[0]).toMatchObject({
      id: "web-to-api", destination: "api-tier",
      destination_condition: { kind: "member", member: "api-node-1", parts: [] },
    });
    expect(value.services[0]).toMatchObject({ connection_ids: ["web-to-api"], component_roles: [{ group_id: "api-tier", role: "dependency" }] });
  });
});

describe("Stable ID checks", () => {
  it("reverts an id that a sibling holds and an empty id", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const api = card("Component groups", 1);
    await user.clear(within(api).getByLabelText("Stable ID"));
    await user.type(within(api).getByLabelText("Stable ID"), "frontend");
    await user.clear(within(api).getAllByLabelText("Member ID")[1]);
    expect(within(api).getByLabelText("Stable ID")).toHaveValue("api");
    await user.click(within(api).getByLabelText("Name"));
    expect(within(api).getAllByLabelText("Member ID")[1]).toHaveValue("api-secondary");
    await user.type(within(api).getByLabelText("Name"), " tier");

    const value = await save(user, saved);
    expect(value.groups.map((group) => group.id)).toEqual(["frontend", "api"]);
    expect(value.connections[0]).toMatchObject({ source: "frontend", destination: "api" });
  });

  it("drops leading digits and hyphens of a typed id", async () => {
    renderEditor();
    const user = userEvent.setup();
    const field = within(card("Connections")).getByLabelText("Stable ID");
    await user.clear(field);
    await user.type(field, "-9Web To API");
    expect(field).toHaveValue("web-to-api");
  });
});

describe("Placeholder members", () => {
  it("binds the candidate of the remaining placeholder after a removal", async () => {
    const value = definition();
    value.schema_version = 2;
    value.groups[1].members = [
      { id: "web-a", placeholder: { text: "web a", expected_kind: "ip", status: "ambiguous", candidates: ["ip:a1", "ip:a2"] } },
      { id: "web-b", placeholder: { text: "web b", expected_kind: "ip", status: "unresolved", candidates: ["ip:b1"] } },
    ];
    value.connections[0].destination_condition = { kind: "member", member: "web-b", parts: [] };
    const saved = renderEditor(value);
    const user = userEvent.setup();
    const first = screen.getByRole("group", { name: "Placeholder web-a" });
    await user.selectOptions(within(first).getByLabelText("Candidate"), "ip:a2");
    await user.click(within(first).getByRole("button", { name: "Remove member" }));
    await user.click(within(screen.getByRole("group", { name: "Placeholder web-b" })).getByRole("button", { name: "Bind" }));

    expect((await save(user, saved)).groups[1].members).toEqual([
      { id: "web-b", inventory: { kind: "ip", uid: "ip:b1", role: "component" } },
    ]);
  });
});

describe("Service component roles", () => {
  it("adds, changes and removes a component role", async () => {
    const saved = renderEditor();
    const user = userEvent.setup();
    const service = card("Services");
    await user.click(within(service).getByRole("button", { name: "Add component role" }));
    const groups = within(service).getAllByLabelText("Component group");
    await user.selectOptions(groups[1], "Frontend");
    await user.selectOptions(within(service).getAllByLabelText("Role")[1], "Client");
    await user.click(within(service).getAllByRole("button", { name: "Remove component role" })[0]);

    expect((await save(user, saved)).services[0].component_roles).toEqual([{ group_id: "frontend", role: "client" }]);
  });
});

function renderPage(routes: Parameters<typeof mockApi>[0], applicationId?: string) {
  const navigate = vi.fn();
  mockApi({ "GET /api/me": () => ({ body: ME_OPERATOR }), ...routes });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <AuthProvider>
          <ApplicationsPage applicationId={applicationId} onNavigate={navigate} onOpenAnalysis={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return navigate;
}

describe("New application", () => {
  it("creates an application from the empty editor with a POST", async () => {
    const created: MockRequest[] = [];
    const navigate = renderPage({
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "POST /api/business-applications": (req) => {
        created.push(req);
        const value = (req.body as { definition: BusinessApplicationDefinition }).definition;
        return { status: 201, body: revision(value) };
      },
    });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "New application" }));
    const metadata = screen.getByRole("group", { name: "Application metadata" });
    expect(within(metadata).getByLabelText("Stable ID")).toBeEnabled();
    await user.type(within(metadata).getByLabelText("Name"), "Payments");
    await user.type(within(metadata).getByLabelText("Stable ID"), "payments");
    await user.click(screen.getByRole("button", { name: "Save revision" }));

    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0].body).toEqual({
      expected_revision: 0, source: "editor",
      definition: { schema_version: 1, kind: "BusinessApplication", id: "payments", name: "Payments", state: "draft", services: [], groups: [], connections: [] },
    });
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("payments"));
  });
});

describe("Connections detail", () => {
  it("shows the condition, the contexts, the source ports and the MTU of a connection", async () => {
    const value = definition();
    value.connections[0] = {
      ...value.connections[0],
      protocol: "tcp", destination_ports: [8443], source_ports: ["1024-65535"],
      destination_condition: { kind: "threshold", n: 1, parts: [{ kind: "member", member: "api-primary", parts: [] }, { kind: "member", member: "api-secondary", parts: [] }] },
      source_context: { vrf: "vrf:branch", device_uid: "device:edge-1" },
      destination_context: { vrf: "vrf:production", ingress_interface_uid: "interface:edge-1:eth0" },
      mtu: { mode: "packet", ip_packet_bytes: 1500, ipv4_df: true },
    };
    const record = revision(value);
    renderPage({
      "GET /api/business-applications": () => ({ body: { applications: [record] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: record } }),
    }, "checkout");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Connections" }));
    const row = screen.getByText("Select Frontend to API").closest("article")!;
    expect(row).toHaveTextContent("Source ports: 1024-65535");
    expect(row).toHaveTextContent("Destination condition: At least 1 of (api-primary, api-secondary)");
    expect(row).toHaveTextContent("Source context: VRF vrf:branch, device device:edge-1");
    expect(row).toHaveTextContent("Destination context: VRF vrf:production, ingress interface interface:edge-1:eth0");
    expect(row).toHaveTextContent("MTU: packet behavior, IP packet 1500 bytes, IPv4 Don't Fragment set");
  });
});
