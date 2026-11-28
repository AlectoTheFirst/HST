import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../../auth";
import type { Me } from "../../api/types";
import { mockApi, type MockHandler, type MockRequest } from "../../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../../test/fixtures";
import type { BusinessApplicationDefinition } from "../types";
import type { ApplicationAnalysis, CatalogEntry, Review } from "./api";
import { ApplicationsLayout } from "./ApplicationsLayout";
import { ApplicationDetailPage, ApplicationImportPage, ApplicationsListPage, ApplicationsReviewPage } from "./pages";

vi.mock("./ComponentGraph", () => ({
  default: ({ definition }: { definition: BusinessApplicationDefinition }) => (
    <div role="img" aria-label="Component graph">
      {definition.groups.length} components
    </div>
  ),
}));

const ME_NO_REVIEW: Me = { ...ME_OPERATOR, permissions: ME_OPERATOR.permissions.filter((item) => item !== "changes.write") };

const WEBSHOP_DEFINITION: BusinessApplicationDefinition = {
  schema_version: 1,
  kind: "BusinessApplication",
  id: "webshop",
  name: "Webshop production",
  state: "ready",
  services: [{ id: "storefront", name: "Storefront", connection_ids: ["frontend-api"], component_roles: [] }],
  groups: [
    { id: "frontend", name: "Frontend", members: [{ id: "vip", name: "webshop-vip", address: "10.1.10.5" }] },
    { id: "api", name: "API", members: [{ id: "api-01", name: "webshop-api-01", address: "10.1.20.11" }] },
  ],
  connections: [
    {
      id: "frontend-api",
      name: "Frontend to API",
      source: "frontend",
      destination: "api",
      protocol: "tcp",
      destination_ports: [8443],
      success: "forward",
      destination_condition: { kind: "member", member: "api-01", parts: [] },
    },
  ],
};

function entry(id: string, name: string, extra: Partial<CatalogEntry> = {}): CatalogEntry {
  return {
    id,
    revision: 2,
    name,
    digest: "2".repeat(64),
    created_by: 1,
    created_at: "2026-11-20T14:02:00Z",
    definition: { ...WEBSHOP_DEFINITION, id, name },
    ...extra,
  };
}

const WEBSHOP = entry("webshop", "Webshop production", { review: "open", analyses: 4, connections: 1 });
const PAYMENTS = entry("payments", "Payments production", {
  review: null,
  analyses: 0,
  connections: 4,
  definition: { ...WEBSHOP_DEFINITION, id: "payments", name: "Payments production", state: "draft" },
});

const OPEN_REVIEW: Review = {
  id: "8c1f",
  application_id: "webshop",
  state: "open",
  reason: "revision 2 saved",
  revision: 2,
  opened_at: "2026-11-20T14:02:00Z",
  opened_by: null,
  opened_by_name: null,
  closed_at: null,
  closed_by: null,
  closed_by_name: null,
};
const CLOSED_REVIEW: Review = {
  ...OPEN_REVIEW,
  id: "77aa",
  state: "closed",
  reason: "check after import",
  revision: 1,
  opened_at: "2026-11-02T10:15:00Z",
  opened_by: 3,
  closed_at: "2026-11-03T09:30:00Z",
  closed_by: 3,
};

const ANALYSES: ApplicationAnalysis[] = [
  {
    session_id: "s-1",
    title: "Demo proof webshop api to db",
    kind: "connection",
    session_revision: 1,
    bound_revisions: [1],
    current_revision: 2,
    stale: true,
    runs: [{ id: "r-1", execution: "completed" }],
  },
  {
    session_id: "s-2",
    title: "Demo proof run 5",
    kind: "connection",
    session_revision: 1,
    bound_revisions: [2],
    current_revision: 2,
    stale: false,
    runs: [],
  },
];

function routes(me: Me, extra: Record<string, MockHandler> = {}): Record<string, MockHandler> {
  return {
    "GET /api/me": () => ({ body: me }),
    "GET /api/business-applications": () => ({ body: { applications: [WEBSHOP, PAYMENTS] } }),
    "GET /api/business-applications/webshop": () => ({ body: { application: WEBSHOP } }),
    "GET /api/business-applications/webshop/analyses": () => ({ body: { analyses: ANALYSES } }),
    "GET /api/business-applications/webshop/review": () => ({ body: { current: OPEN_REVIEW, history: [OPEN_REVIEW, CLOSED_REVIEW] } }),
    "GET /api/business-applications/webshop/history": () => ({ body: { revisions: [WEBSHOP] } }),
    "GET /api/snapshots": () => ({ body: { snapshots: [], current: null, truncated: false } }),
    ...extra,
  };
}

function Where() {
  const location = useLocation();
  return <output aria-label="Location">{location.pathname + location.search}</output>;
}

function mount(path: string) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <Where />
          <Routes>
            <Route path="/applications" element={<ApplicationsLayout />}>
              <Route index element={<ApplicationsListPage />} />
              <Route path="review" element={<ApplicationsReviewPage />} />
              <Route path="import" element={<ApplicationImportPage />} />
              <Route path=":id" element={<ApplicationDetailPage />} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function requests(): MockRequest[] {
  return (fetch as unknown as { mock: { calls: Array<[RequestInfo | URL, RequestInit?]> } }).mock.calls.map(([input, init]) => ({
    method: (init?.method ?? "GET").toUpperCase(),
    path: new URL(String(input), "http://localhost").pathname,
    headers: {},
    body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
  }));
}

describe("Applications table", () => {
  it("lists the applications with their counts and review state", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications");
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual([
      "",
      "Name",
      "Id",
      "Revision",
      "State",
      "Connections",
      "Analyses",
      "Review",
      "Updated",
    ]);
    const row = within(table).getByRole("link", { name: "Webshop production" }).closest("tr")!;
    expect(within(row).getAllByRole("cell").slice(2, 8).map((cell) => cell.textContent)).toEqual([
      "webshop",
      "2",
      "ready",
      "1",
      "4",
      "needs review",
    ]);
    expect(within(row).getByRole("link", { name: "Webshop production" })).toHaveAttribute("href", "/applications/webshop");
    const nav = screen.getByRole("navigation", { name: "Applications" });
    expect(within(nav).getByRole("link", { name: "Review 1" })).toHaveAttribute("href", "/applications/review");
    expect(within(nav).getByRole("link", { name: "Applications" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "New application" })).toHaveAttribute("href", "/applications/new");
    expect(screen.getByRole("link", { name: "Import YAML" })).toHaveAttribute("href", "/applications/import");
  });

  it("filters by search, state and review", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications");
    const user = userEvent.setup();
    await screen.findByRole("table");
    const names = () => screen.getAllByRole("link", { name: /production/ }).map((link) => link.textContent);
    await user.type(screen.getByRole("searchbox", { name: "Search" }), "pay");
    expect(names()).toEqual(["Payments production"]);
    await user.clear(screen.getByRole("searchbox", { name: "Search" }));
    await user.selectOptions(screen.getByRole("combobox", { name: "State" }), "draft");
    expect(names()).toEqual(["Payments production"]);
    await user.selectOptions(screen.getByRole("combobox", { name: "State" }), "");
    await user.selectOptions(screen.getByRole("combobox", { name: "Review" }), "open");
    expect(names()).toEqual(["Webshop production"]);
  });

  it("flags, marks reviewed and exports the selected applications", async () => {
    const posts: MockRequest[] = [];
    const exports: string[] = [];
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL: () => undefined }));
    mockApi(
      routes(ME_OPERATOR, {
        "POST /api/business-applications/payments/review": (req) => {
          posts.push(req);
          return { status: 201, body: { ...OPEN_REVIEW, application_id: "payments" } };
        },
        "POST /api/business-applications/webshop/review/close": (req) => {
          posts.push(req);
          return { body: { ...OPEN_REVIEW, state: "closed" } };
        },
        "GET /api/business-applications/webshop/export": (req) => {
          exports.push(req.path);
          return { raw: "id: webshop\n", headers: { "content-disposition": 'attachment; filename="webshop.yaml"' } };
        },
        "GET /api/business-applications/payments/export": (req) => {
          exports.push(req.path);
          return { raw: "id: payments\n", headers: { "content-disposition": 'attachment; filename="payments.yaml"' } };
        },
      }),
    );
    mount("/applications");
    const user = userEvent.setup();
    await screen.findByRole("table");
    expect(screen.queryByRole("group", { name: "Selected application actions" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Select all" }));
    const actions = screen.getByRole("group", { name: "Selected application actions" });
    expect(within(actions).getByText("2 selected")).toBeInTheDocument();
    expect(within(actions).getByRole("button", { name: "Flag for review" })).toBeDisabled();
    await user.type(within(actions).getByRole("textbox", { name: "Reason" }), "firewall change");
    await user.click(within(actions).getByRole("button", { name: "Flag for review" }));
    await user.click(within(actions).getByRole("button", { name: "Mark reviewed" }));
    await waitFor(() => expect(posts).toHaveLength(2));
    // the open flag of Webshop is not opened again
    expect(posts.map((req) => [req.path, req.body])).toEqual([
      ["/api/business-applications/payments/review", { reason: "firewall change" }],
      ["/api/business-applications/webshop/review/close", undefined],
    ]);
    await user.click(within(actions).getByRole("button", { name: "Export YAML" }));
    await waitFor(() =>
      expect(exports).toEqual(["/api/business-applications/webshop/export", "/api/business-applications/payments/export"]),
    );
  });

  it("lists only the applications with an open flag in Review", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications/review");
    expect(await screen.findByRole("heading", { name: "Review" })).toBeInTheDocument();
    await screen.findByRole("table");
    expect(screen.getAllByRole("link", { name: /production/ }).map((link) => link.textContent)).toEqual(["Webshop production"]);
  });
});

describe("Import and new application", () => {
  it("holds the YAML import in the Import section", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications/import");
    expect(await screen.findByRole("heading", { name: "Import" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Definition YAML" })).toBeEnabled());
    expect(screen.getByRole("button", { name: "Preview import" })).toBeDisabled();
    const nav = screen.getByRole("navigation", { name: "Applications" });
    expect(within(nav).getByRole("link", { name: "Import" })).toHaveAttribute("aria-current", "page");
  });

  it("creates an application and opens it", async () => {
    const created: MockRequest[] = [];
    const saved = entry("intranet", "Intranet production");
    mockApi(
      routes(ME_OPERATOR, {
        "POST /api/business-applications": (req) => {
          created.push(req);
          return { status: 201, body: saved };
        },
        "GET /api/business-applications/intranet": () => ({ body: { application: saved } }),
        "GET /api/business-applications/intranet/analyses": () => ({ body: { analyses: [] } }),
        "GET /api/business-applications/intranet/review": () => ({ body: { current: null, history: [] } }),
        "GET /api/business-applications/intranet/history": () => ({ body: { revisions: [saved] } }),
      }),
    );
    mount("/applications/new");
    const user = userEvent.setup();
    expect(await screen.findByRole("heading", { name: "New application" })).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Name" }), "Intranet production");
    const id = screen.getByRole("textbox", { name: "Stable ID" });
    await user.type(id, "intranet");
    await user.tab();
    await user.click(screen.getByRole("button", { name: "Save revision" }));
    await waitFor(() => expect(screen.getByRole("status", { name: "Location" })).toHaveTextContent("/applications/intranet"));
    expect(created.map((req) => (req.body as { definition: { id: string; name: string } }).definition)).toMatchObject([
      { id: "intranet", name: "Intranet production" },
    ]);
    expect(await screen.findByRole("heading", { name: "Intranet production" })).toBeInTheDocument();
  });
});

describe("Permission rule", () => {
  it("shows no review column, section, filter or action without changes.write", async () => {
    mockApi(routes(ME_NO_REVIEW));
    mount("/applications");
    const user = userEvent.setup();
    const table = await screen.findByRole("table");
    expect(within(table).queryByRole("columnheader", { name: "Review" })).not.toBeInTheDocument();
    expect(within(table).queryByText("needs review")).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Review" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("navigation", { name: "Applications" })).queryByRole("link", { name: /Review/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Select Webshop production" }));
    const actions = screen.getByRole("group", { name: "Selected application actions" });
    expect(within(actions).getAllByRole("button").map((button) => button.textContent)).toEqual(["Export YAML"]);
  });

  it("sends the Review route to the table and reads no review without changes.write", async () => {
    mockApi(routes(ME_NO_REVIEW));
    mount("/applications/review");
    await waitFor(() => expect(screen.getByRole("status", { name: "Location" })).toHaveTextContent(/^\/applications$/));
    expect(requests().some((req) => req.path.endsWith("/review"))).toBe(false);
  });

  it("shows no review state on the detail to a viewer", async () => {
    mockApi(routes(ME_VIEWER));
    mount("/applications/webshop");
    expect(await screen.findByRole("heading", { name: "Webshop production" })).toBeInTheDocument();
    await screen.findByRole("region", { name: "Analyses" });
    expect(screen.queryByRole("region", { name: "Review" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Mark reviewed" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Review history" })).not.toBeInTheDocument();
    expect(requests().some((req) => req.path.endsWith("/review"))).toBe(false);
  });
});

describe("Application detail", () => {
  it("shows the review, the analyses with the bound revision and the review history", async () => {
    const posts: MockRequest[] = [];
    mockApi(
      routes(ME_OPERATOR, {
        "POST /api/business-applications/webshop/review/close": (req) => {
          posts.push(req);
          return { body: { ...OPEN_REVIEW, state: "closed", closed_at: "2026-11-21T08:00:00Z", closed_by: 7 } };
        },
      }),
    );
    mount("/applications/webshop");
    expect(await screen.findByRole("heading", { name: "Webshop production" })).toBeInTheDocument();
    expect(screen.getByText("Revision 2")).toBeInTheDocument();
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual([
      "Overview",
      "Components",
      "Connections",
      "Services",
      "Revisions",
    ]);
    const review = await screen.findByRole("region", { name: "Review" });
    expect(await within(review).findByText("needs review")).toBeInTheDocument();
    expect(within(review).getByText(/^Opened 2026-11-20/)).not.toHaveTextContent(" by ");

    const analyses = screen.getByRole("region", { name: "Analyses" });
    const rows = await within(analyses).findAllByRole("row");
    expect(rows.slice(1).map((row) => within(row).getAllByRole("cell").slice(0, 3).map((cell) => cell.textContent))).toEqual([
      ["Demo proof webshop api to db", "1, not 2", "completed"],
      ["Demo proof run 5", "2", "no run"],
    ]);

    const history = screen.getByRole("region", { name: "Review history" });
    const events = within(history).getAllByRole("row").slice(1).map((row) => within(row).getAllByRole("cell").slice(1, 4).map((cell) => cell.textContent));
    expect(events).toEqual([
      ["opened", "2", "automatic"],
      ["closed", "1", "user 3"],
      ["opened", "1", "user 3"],
    ]);

    const user = userEvent.setup();
    await user.click(within(review).getByRole("button", { name: "Mark reviewed" }));
    await waitFor(() => expect(posts.map((req) => req.path)).toEqual(["/api/business-applications/webshop/review/close"]));
  });

  it("flags an application by hand with a reason", async () => {
    const posts: MockRequest[] = [];
    mockApi(
      routes(ME_OPERATOR, {
        "GET /api/business-applications/webshop/review": () => ({ body: { current: null, history: [CLOSED_REVIEW] } }),
        "POST /api/business-applications/webshop/review": (req) => {
          posts.push(req);
          return { status: 201, body: OPEN_REVIEW };
        },
      }),
    );
    mount("/applications/webshop");
    const user = userEvent.setup();
    const review = await screen.findByRole("region", { name: "Review" });
    await user.type(await within(review).findByRole("textbox", { name: "Reason" }), "new database");
    await user.click(within(review).getByRole("button", { name: "Flag for review" }));
    await waitFor(() => expect(posts.map((req) => req.body)).toEqual([{ reason: "new database" }]));
  });

  it("edits a component in the draft and saves the next revision", async () => {
    const puts: MockRequest[] = [];
    mockApi(
      routes(ME_OPERATOR, {
        "PUT /api/business-applications/webshop": (req) => {
          puts.push(req);
          return { body: { ...WEBSHOP, revision: 3, definition: (req.body as { definition: BusinessApplicationDefinition }).definition } };
        },
      }),
    );
    mount("/applications/webshop?tab=components");
    const user = userEvent.setup();
    expect(await screen.findByRole("img", { name: "Component graph" })).toBeInTheDocument();
    const components = screen.getByRole("region", { name: "Components" });
    const rows = within(components).getAllByRole("row").slice(1);
    expect(rows.map((row) => within(row).getAllByRole("cell").map((cell) => cell.textContent))).toEqual([
      ["Frontend", "webshop-vip", "1"],
      ["API", "webshop-api-01", "1"],
    ]);
    await user.click(within(components).getByRole("button", { name: "API" }));
    const form = screen.getByRole("complementary", { name: "Component API" });
    expect(within(form).getByText("Frontend to API tcp/8443")).toBeInTheDocument();

    await user.click(within(form).getByRole("button", { name: "Address or network" }));
    await user.type(within(form).getByRole("textbox", { name: "Address or network" }), "10.1.20.12");
    const add = within(form).getByRole("region", { name: "Add member" });
    await user.type(within(add).getByRole("textbox", { name: "Name" }), "webshop-api-02");
    await user.click(within(add).getByRole("button", { name: "Add member" }));

    expect(screen.getByText("Revision 2, draft changes")).toBeInTheDocument();
    // the draft stays across tabs
    await user.click(screen.getByRole("tab", { name: "Connections" }));
    await user.click(screen.getByRole("tab", { name: "Components" }));
    expect(within(screen.getByRole("region", { name: "Components" })).getAllByRole("row")[2]).toHaveTextContent("webshop-api-01, webshop-api-02");

    await user.click(screen.getByRole("button", { name: "Save revision 3" }));
    await waitFor(() => expect(puts).toHaveLength(1));
    const body = puts[0].body as { definition: BusinessApplicationDefinition; expected_revision: number };
    expect(body.expected_revision).toBe(2);
    expect(body.definition.groups[1].members).toEqual([
      { id: "api-01", name: "webshop-api-01", address: "10.1.20.11" },
      { id: "member-2", name: "webshop-api-02", address: "10.1.20.12" },
    ]);
    expect(await screen.findByText("Revision 3")).toBeInTheDocument();
  });

  it("discards the draft", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications/webshop?tab=components");
    const user = userEvent.setup();
    await user.click(await within(await screen.findByRole("region", { name: "Components" })).findByRole("button", { name: "Add component" }));
    expect(screen.getByRole("button", { name: "Save revision 3" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(screen.queryByRole("button", { name: "Save revision 3" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Components" })).getAllByRole("row")).toHaveLength(3);
  });

  it("lists the connections and opens the connection form", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications/webshop?tab=connections");
    const user = userEvent.setup();
    const connections = await screen.findByRole("region", { name: "Connections" });
    const row = within(connections).getAllByRole("row")[1];
    expect(within(row).getAllByRole("cell").map((cell) => cell.textContent)).toEqual([
      "Frontend to API",
      "Frontend",
      "API",
      "tcp/8443",
      "webshop-api-01",
      "Storefront",
    ]);
    await user.click(within(connections).getByRole("button", { name: "Frontend to API" }));
    const form = screen.getByRole("complementary", { name: "Connection Frontend to API" });
    expect(within(form).getByRole("combobox", { name: "Source" })).toHaveValue("frontend");
    expect(within(form).getByRole("combobox", { name: "Destination" })).toHaveValue("api");
    expect(within(form).getByRole("textbox", { name: "Destination ports" })).toHaveValue("8443");
    expect(within(form).getByRole("group", { name: "Source context" })).toBeInTheDocument();
    expect(within(form).getByRole("group", { name: "Destination context" })).toBeInTheDocument();

    await user.selectOptions(within(form).getByRole("combobox", { name: "Service" }), "");
    expect(within(row).getAllByRole("cell")[5]).toHaveTextContent("none");
    expect(screen.getByRole("button", { name: "Save revision 3" })).toBeInTheDocument();
  });

  it("shows the services and the revisions", async () => {
    mockApi(routes(ME_OPERATOR));
    mount("/applications/webshop?tab=services");
    const user = userEvent.setup();
    expect(await screen.findByRole("group", { name: "Services" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("Storefront");
    await user.click(screen.getByRole("tab", { name: "Revisions" }));
    expect(await screen.findByRole("button", { name: "Export revision 2" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Location" })).toHaveTextContent("/applications/webshop?tab=revisions");
  });
});

describe("Member search", () => {
  it("searches devices, IP addresses and networks at the current snapshot and adds a result with its kind", async () => {
    const puts: MockRequest[] = [];
    mockApi(
      routes(ME_OPERATOR, {
        "GET /api/snapshots": () => ({ body: { snapshots: [], current: 300, truncated: false } }),
        "GET /api/assessment-options": () => ({
          body: {
            snapshot: "300",
            truncated: false,
            items: [
              { uid: "prefix:home:10.1.20.0/24", name: "10.1.20.0/24", kind: "network", selectable: true },
              { uid: "ip:home:10.1.20.12", name: "10.1.20.12", kind: "ip", selectable: true },
              { uid: "device:api-02", name: "api-02", kind: "device", selectable: true },
              { uid: "interface:api-02:eth0", name: "eth0", kind: "interface", device_name: "api-02", selectable: true },
            ],
          },
        }),
        "PUT /api/business-applications/webshop": (req) => {
          puts.push(req);
          return { body: { ...WEBSHOP, revision: 3, definition: (req.body as { definition: BusinessApplicationDefinition }).definition } };
        },
      }),
    );
    mount("/applications/webshop?tab=components");
    const user = userEvent.setup();
    await user.click(await within(await screen.findByRole("region", { name: "Components" })).findByRole("button", { name: "API" }));
    const add = screen.getByRole("region", { name: "Add member" });
    expect(within(add).queryByRole("combobox", { name: "Kind" })).not.toBeInTheDocument();

    await user.type(within(add).getByRole("searchbox", { name: "Find member" }), "10");
    const results = await within(add).findByRole("list", { name: "Member results" });
    await waitFor(() =>
      expect(within(results).getAllByRole("button").map((button) => button.textContent)).toEqual([
        "10.1.20.0/24 network",
        "10.1.20.12 IP address",
        "api-02 device",
      ]),
    );
    const searches = (fetch as unknown as { mock: { calls: Array<[RequestInfo | URL]> } }).mock.calls
      .map(([input]) => new URL(String(input), "http://localhost"))
      .filter((url) => url.pathname === "/api/assessment-options");
    expect(searches.at(-1)!.searchParams.get("snapshot")).toBe("300");
    expect(searches.at(-1)!.searchParams.get("kind")).toBe("device,ip,network");
    expect(searches.at(-1)!.searchParams.get("q")).toBe("10");

    await user.click(within(results).getByRole("button", { name: /^10\.1\.20\.12/ }));
    await user.click(within(add).getByRole("button", { name: "Add member" }));
    await user.click(screen.getByRole("button", { name: "Save revision 3" }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expect((puts[0].body as { definition: BusinessApplicationDefinition }).definition.groups[1].members[1]).toEqual({
      id: "member-2",
      name: "10.1.20.12",
      inventory: { kind: "ip", uid: "ip:home:10.1.20.12", role: "component" },
    });
  });

  it("adds an interface from the interfaces of the selected device", async () => {
    const puts: MockRequest[] = [];
    const searches = () =>
      (fetch as unknown as { mock: { calls: Array<[RequestInfo | URL]> } }).mock.calls
        .map(([input]) => new URL(String(input), "http://localhost"))
        .filter((url) => url.pathname === "/api/assessment-options")
        .map((url) => url.searchParams);
    mockApi(
      routes(ME_OPERATOR, {
        "GET /api/snapshots": () => ({ body: { snapshots: [], current: 300, truncated: false } }),
        "GET /api/assessment-options": () => ({
          body: {
            snapshot: "300",
            truncated: false,
            items:
              searches().at(-1)!.get("kind") === "interface"
                ? [{ uid: "interface:api-02:eth0", name: "eth0", kind: "interface", device_name: "api-02", selectable: true }]
                : [{ uid: "device:api-02", name: "api-02", kind: "device", selectable: true }],
          },
        }),
        "PUT /api/business-applications/webshop": (req) => {
          puts.push(req);
          return { body: { ...WEBSHOP, revision: 3, definition: (req.body as { definition: BusinessApplicationDefinition }).definition } };
        },
      }),
    );
    mount("/applications/webshop?tab=components");
    const user = userEvent.setup();
    await user.click(await within(await screen.findByRole("region", { name: "Components" })).findByRole("button", { name: "API" }));
    const add = screen.getByRole("region", { name: "Add member" });

    await user.click(await within(await within(add).findByRole("list", { name: "Member results" })).findByRole("button", { name: /^api-02/ }));
    await user.click(await within(within(add).getByRole("list", { name: "Find interface results" })).findByRole("button", { name: /^eth0/ }));
    expect([searches().at(-1)!.get("kind"), searches().at(-1)!.get("device")]).toEqual(["interface", "device:api-02"]);
    await user.click(within(add).getByRole("button", { name: "Add member" }));
    await user.click(screen.getByRole("button", { name: "Save revision 3" }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expect((puts[0].body as { definition: BusinessApplicationDefinition }).definition.groups[1].members[1]).toEqual({
      id: "member-2",
      name: "eth0",
      inventory: { kind: "interface", uid: "interface:api-02:eth0", role: "component" },
    });
  });

  it("searches at the snapshot chosen on the page", async () => {
    mockApi(
      routes(ME_OPERATOR, {
        "GET /api/snapshots": () => ({
          body: {
            snapshots: [{ id: "200", ts_ms: 200, kind: "full", degraded: false }],
            current: 300,
            truncated: false,
          },
        }),
        "GET /api/assessment-options": () => ({ body: { snapshot: "200", truncated: false, items: [] } }),
        "POST /api/business-applications/webshop/resolve": () => ({ body: { groups: [], connections: [] } }),
      }),
    );
    mount("/applications/webshop?tab=components");
    const user = userEvent.setup();
    const components = await screen.findByRole("region", { name: "Components" });
    await user.selectOptions(await within(components).findByRole("combobox", { name: "Snapshot" }), "200");
    await user.click(within(components).getByRole("button", { name: "API" }));
    const add = screen.getByRole("region", { name: "Add member" });
    expect(await within(add).findByText("No matching objects")).toBeInTheDocument();
    const searches = (fetch as unknown as { mock: { calls: Array<[RequestInfo | URL]> } }).mock.calls
      .map(([input]) => new URL(String(input), "http://localhost"))
      .filter((url) => url.pathname === "/api/assessment-options");
    expect(searches.map((url) => url.searchParams.get("snapshot"))).toEqual(["200"]);
  });
});

describe("Review user names", () => {
  it("shows the username of each review event", async () => {
    const opened: Review = { ...OPEN_REVIEW, opened_by: 5, opened_by_name: "otto" };
    const closed: Review = { ...CLOSED_REVIEW, opened_by: 3, opened_by_name: "ada", closed_by: 4, closed_by_name: null };
    mockApi(
      routes(ME_OPERATOR, {
        "GET /api/business-applications/webshop/review": () => ({ body: { current: opened, history: [opened, closed] } }),
      }),
    );
    mount("/applications/webshop");
    const review = await screen.findByRole("region", { name: "Review" });
    expect(await within(review).findByText(/^Opened 2026-11-20/)).toHaveTextContent(/ by otto$/);
    const history = screen.getByRole("region", { name: "Review history" });
    await waitFor(() => expect(within(history).getAllByRole("row")).toHaveLength(4));
    const events = within(history).getAllByRole("row").slice(1).map((row) => within(row).getAllByRole("cell").slice(1, 4).map((cell) => cell.textContent));
    expect(events).toEqual([
      ["opened", "2", "otto"],
      ["closed", "1", "user 4"],
      ["opened", "1", "ada"],
    ]);
  });
});
