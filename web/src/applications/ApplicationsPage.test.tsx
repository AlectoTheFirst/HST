import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import type { MockRequest } from "../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";
import ApplicationsPage from "./ApplicationsPage";
import type { ApplicationRevision, BusinessApplicationDefinition } from "./types";
import { AiContextProvider } from "../ai/context";
import { PageContextProbe, readPageContext } from "../test/aiContext";

function renderPage() {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <ApplicationsPage onNavigate={() => undefined} onOpenAnalysis={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Business Applications catalog", () => {
  it("shows an empty catalog and a read-only import to a viewer", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
    });
    renderPage();
    expect(await screen.findByText("No applications")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toBeDisabled();
  });

  it("previews and commits a first YAML definition without discarding the draft", async () => {
    const commit = vi.fn(() => ({
      body: {
        id: "checkout",
        revision: 1,
        name: "Checkout",
        digest: "a".repeat(64),
        created_by: 1,
        created_at: "2026-01-01T00:00:00Z",
        definition: {
          schema_version: 1,
          kind: "BusinessApplication",
          id: "checkout",
          name: "Checkout",
          state: "draft",
          services: [],
          groups: [],
          connections: [],
        },
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "POST /api/business-applications/import/preview": () => ({
        body: {
          application_id: "checkout",
          base_revision: 0,
          base_digest: "",
          result_digest: "a".repeat(64),
          preview_digest: "b".repeat(64),
          definition: {},
          changes: { services_created: [], groups_created: [], connections_created: [] },
          mapping_issues: [],
          no_op: false,
        },
      }),
      "POST /api/business-applications/import/commit": commit,
    });
    const user = userEvent.setup();
    renderPage();
    const yaml = "schema_version: 1\nkind: BusinessApplication\nid: checkout\nname: Checkout\n";
    await user.type(await screen.findByRole("textbox", { name: "Definition YAML" }), yaml);
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    expect(await screen.findByRole("region", { name: "Import preview" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Commit revision" }));
    expect(commit).toHaveBeenCalledTimes(1);
  });

  it("sends the selected import mode with the preview and the commit", async () => {
    const preview = vi.fn((_request: MockRequest) => ({
      body: {
        application_id: "checkout",
        base_revision: 0,
        base_digest: "",
        result_digest: "a".repeat(64),
        preview_digest: "b".repeat(64),
        definition: {},
        changes: { services_created: [], groups_created: [], connections_created: [] },
        mapping_issues: [],
        no_op: false,
      },
    }));
    const commit = vi.fn((_request: MockRequest) => ({
      body: {
        id: "checkout",
        revision: 1,
        name: "Checkout",
        digest: "a".repeat(64),
        created_by: 1,
        created_at: "2026-01-01T00:00:00Z",
        definition: {
          schema_version: 1,
          kind: "BusinessApplication",
          id: "checkout",
          name: "Checkout",
          state: "draft",
          services: [],
          groups: [],
          connections: [],
        },
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "POST /api/business-applications/import/preview": preview,
      "POST /api/business-applications/import/commit": commit,
    });
    const user = userEvent.setup();
    renderPage();
    const yaml = "schema_version: 1\nkind: BusinessApplication\nid: checkout\nname: Checkout\n";
    await user.type(await screen.findByRole("textbox", { name: "Definition YAML" }), yaml);
    expect(screen.getByLabelText("Import mode")).toHaveValue("merge");
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    expect(await screen.findByRole("region", { name: "Import preview" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Import mode"), "replace");
    expect(screen.queryByRole("region", { name: "Import preview" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    expect(await screen.findByRole("region", { name: "Import preview" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Commit revision" }));
    expect(preview.mock.calls.map(([request]) => request.body)).toEqual([
      { yaml, mode: "merge" },
      { yaml, mode: "replace" },
    ]);
    expect(commit.mock.calls.map(([request]) => request.body)).toEqual([
      { yaml, mode: "replace", base_revision: 0, base_digest: "", preview_digest: "b".repeat(64) },
    ]);
  });
});

function renderApplication(applicationId: string) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter>
        <AuthProvider>
          <ApplicationsPage
            applicationId={applicationId}
            onNavigate={() => undefined}
            onOpenAnalysis={() => undefined}
          />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const SNAPSHOTS = {
  snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }],
  current: 4000,
  truncated: false,
};
const REFERENCE = {
  snapshot: "4000",
  manifest_sha256: "a".repeat(64),
  estate: "test",
  observation_floor_ms: null,
};

describe("Business Applications validation", () => {
  it("validates YAML at a snapshot, shows errors by line and then the structure view", async () => {
    const yaml =
      "schema_version: 1\nid: webshop\nname: Webshop\ngroups:\n  - id: clients\n    name: Clients\n    members:\n      - id: lan\n        address: ten-nine\n";
    const failed = {
      errors: [
        {
          path: "groups.0.members.0",
          message: "Value error, address must be an IPv4/IPv6 address or prefix",
          line: 8,
          column: 9,
        },
      ],
      warnings: [],
      definition: null,
      preview: null,
      resolution: null,
      blocking: ["groups.0.members.0"],
      snapshot: REFERENCE,
    };
    const definition = {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "webshop",
      name: "Webshop",
      state: "draft",
      services: [{ id: "shop", name: "Shop", connection_ids: ["web"], component_roles: [] }],
      groups: [
        { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
        {
          id: "servers",
          name: "Servers",
          members: [
            { id: "web", inventory: { kind: "ip", uid: "ip:10.0.0.5", role: "component" } },
          ],
        },
      ],
      connections: [
        {
          id: "web",
          name: "Web",
          source: "clients",
          destination: "servers",
          protocol: "tcp",
          destination_ports: [443],
          success: "forward",
          destination_condition: { kind: "member", member: "web", parts: [] },
        },
      ],
    };
    const resolution = {
      application: { id: "webshop", revision: 0, digest: "b".repeat(64) },
      snapshot: REFERENCE,
      digest: "c".repeat(64),
      ready: false,
      selection: { service_ids: [], connection_ids: ["web"] },
      groups: {
        clients: {
          lan: { bindings: [{ address: "10.9.0.0/24" }], inventory_uid: null, evidence: [] },
        },
        servers: { web: { bindings: [], inventory_uid: "ip:10.0.0.5", evidence: [] } },
      },
      connections: [
        { id: "web", service_id: "shop", readiness: "unresolved", request: null, issues: [] },
      ],
      issues: [
        {
          code: "inventory-not-found",
          path: "groups.servers.members.web",
          detail: "ip:10.0.0.5 was not found at snapshot 4000",
          severity: "error",
        },
      ],
    };
    const passed = {
      errors: [],
      warnings: [
        {
          code: "address-normalized",
          path: "groups.clients.members.lan.address",
          message: "address 10.9.0.5/24 is stored as 10.9.0.0/24",
        },
      ],
      definition,
      preview: null,
      resolution,
      blocking: ["groups.servers.members.web"],
      snapshot: REFERENCE,
    };
    let answer: unknown = failed;
    const validate = vi.fn((_request: MockRequest) => ({ body: answer }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/validate": validate,
    });
    const user = userEvent.setup();
    const { container } = renderPage();
    await user.click(await screen.findByRole("textbox", { name: "Definition YAML" }));
    await user.paste(yaml);
    expect(screen.getByRole("button", { name: "Validate" })).toBeDisabled();
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Validation snapshot"), "4000");
    await user.click(screen.getByRole("button", { name: "Validate" }));

    const errors = await screen.findByRole("list", { name: "Validation errors" });
    expect(
      within(errors).getByText(
        "Line 8, column 9: groups.0.members.0: Value error, address must be an IPv4/IPv6 address or prefix",
      ),
    ).toBeInTheDocument();
    expect(container.querySelector(".yaml-editor-gutter .error")).toHaveTextContent("8");
    expect(screen.getByText("1 path blocks the ready state")).toBeInTheDocument();
    expect(validate.mock.calls[0][0].body).toEqual({ yaml, mode: "merge", snapshot: "4000" });

    answer = passed;
    await user.click(screen.getByRole("button", { name: "Validate" }));
    const structure = await screen.findByRole("region", { name: "Structure" });
    expect(within(structure).getByRole("cell", { name: "tcp, ports 443" })).toBeInTheDocument();
    expect(within(structure).getByRole("cell", { name: "unresolved" })).toBeInTheDocument();
    expect(
      within(structure).getByText(/ip ip:10\.0\.0\.5 \(inventory-not-found\)/),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("list", { name: "Validation warnings" })).getByText(
        /is stored as 10\.9\.0\.0\/24/,
      ),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("list", { name: "Resolution issues" })).getByText(
        /was not found at snapshot 4000/,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Validation errors" })).not.toBeInTheDocument();
    expect(container.querySelector(".yaml-editor-gutter .error")).toBeNull();
  });

  it("checks flows on request and shows a verdict per connection that blocks nothing", async () => {
    const yaml = "schema_version: 1\nid: webshop\nname: Webshop\n";
    const connection = (id: string) => ({
      id,
      name: id,
      source: "clients",
      destination: "servers",
      protocol: "tcp",
      destination_ports: [443],
      success: "forward",
      destination_condition: { kind: "member", member: "web", parts: [] },
    });
    const definition = {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "webshop",
      name: "Webshop",
      state: "draft",
      services: [],
      groups: [
        { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
        { id: "servers", name: "Servers", members: [{ id: "web", address: "10.0.0.5" }] },
      ],
      connections: ["web", "api", "db"].map(connection),
    };
    const resolution = {
      application: { id: "webshop", revision: 0, digest: "b".repeat(64) },
      snapshot: REFERENCE,
      digest: "c".repeat(64),
      ready: true,
      selection: { service_ids: [], connection_ids: ["web", "api", "db"] },
      groups: {},
      connections: ["web", "api", "db"].map((id) => ({
        id,
        service_id: null,
        readiness: "ready",
        request: null,
        issues: [],
      })),
      issues: [],
    };
    const flow = (connection_id: string, fields: Record<string, unknown>) => ({
      connection_id,
      readiness: "ready",
      result: null,
      passes: [],
      fails: [],
      open: [],
      missing_evidence: [],
      not_evaluated_reason: null,
      detail: null,
      ...fields,
    });
    const flows = [
      flow("web", {
        result: {
          kind: "result",
          statement: "condition-holds",
          answer: "false",
          word: "fails",
          quantifier: "every",
          condition: "forward",
          missing: [],
        },
        fails: ["10.9.0.0/25"],
      }),
      flow("api", { not_evaluated_reason: "capacity-busy" }),
      flow("db", { not_evaluated_reason: "over-cap" }),
    ];
    const validate = vi.fn((_request: MockRequest) => ({
      body: {
        errors: [],
        warnings: [],
        definition,
        preview: null,
        resolution,
        flows,
        blocking: [],
        snapshot: REFERENCE,
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/validate": validate,
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("textbox", { name: "Definition YAML" }));
    await user.paste(yaml);
    expect(screen.getByRole("button", { name: "Check flows" })).toBeDisabled();
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Validation snapshot"), "4000");
    await user.click(screen.getByRole("button", { name: "Check flows" }));

    const verdicts = await screen.findByRole("list", { name: "Flow results" });
    expect(validate.mock.calls[0][0].body).toEqual({
      yaml,
      mode: "merge",
      snapshot: "4000",
      evaluate: true,
    });
    expect(
      within(verdicts).getByText("web: Fails, failing sources 10.9.0.0/25"),
    ).toBeInTheDocument();
    expect(
      within(verdicts).getByText("api: Not checked, no free analysis process slot"),
    ).toBeInTheDocument();
    expect(
      within(verdicts).getByText("db: Not checked, after the first 20 ready connections"),
    ).toBeInTheDocument();
    // a flow that does not hold leaves the ready state unblocked
    expect(screen.getByText("Nothing blocks the ready state")).toBeInTheDocument();
  });
});

describe("Business Applications coverage", () => {
  const application = {
    id: "checkout",
    revision: 3,
    name: "Checkout",
    digest: "a".repeat(64),
    created_by: 1,
    created_at: "2026-01-01T00:00:00Z",
    definition: {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "checkout",
      name: "Checkout",
      state: "draft",
      services: [{ id: "shop", name: "Shop", connection_ids: ["c1"], component_roles: [] }],
      groups: [],
      connections: [
        {
          id: "c1",
          name: "Web to API",
          source: "web",
          destination: "api",
          success: "session",
          destination_condition: { kind: "member", member: "api-one", parts: [] },
        },
      ],
    },
  };

  it("resolves coverage through a POST that names the selected connections", async () => {
    const resolve = vi.fn((_request: MockRequest) => ({
      body: {
        application: { id: "checkout", revision: 3, digest: "a".repeat(64) },
        snapshot: REFERENCE,
        digest: "c".repeat(64),
        ready: true,
        selection: { service_ids: [], connection_ids: ["c1"] },
        groups: {},
        connections: [
          { id: "c1", service_id: "shop", readiness: "ready", request: null, issues: [] },
        ],
        issues: [],
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/checkout/resolve": resolve,
    });
    const user = userEvent.setup();
    renderApplication("checkout");
    await user.click(await screen.findByRole("tab", { name: "Coverage" }));
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Coverage snapshot"), "4000");

    expect(await screen.findByText("All selected connections ready")).toBeInTheDocument();
    expect(resolve).toHaveBeenCalled();
    expect(resolve.mock.calls[0][0].body).toEqual({ snapshot: "4000", connection_ids: ["c1"] });
  });

  it("does not resolve coverage for a viewer", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
    });
    const user = userEvent.setup();
    renderApplication("checkout");
    await user.click(await screen.findByRole("tab", { name: "Coverage" }));
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Coverage snapshot"), "4000");

    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes("/resolve"))).toBe(
      false,
    );
    expect(screen.queryByText("Could not resolve coverage")).not.toBeInTheDocument();
  });
});

describe("Business Applications history", () => {
  it("shows where each revision came from", async () => {
    const definition = {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "checkout",
      name: "Checkout",
      state: "draft",
      services: [],
      groups: [],
      connections: [],
    };
    const revision = (number: number, origin: unknown) => ({
      id: "checkout",
      revision: number,
      name: "Checkout",
      digest: String(number).repeat(64),
      created_by: 1,
      created_at: "2026-01-01T00:00:00Z",
      definition,
      ...(origin === undefined ? {} : { origin }),
    });
    const validated = {
      source: "import",
      generation_id: null,
      generated_digest: null,
      validation: {
        validation_digest: "c".repeat(64),
        snapshot: { snapshot: "4000", manifest_sha256: "a".repeat(64), estate: "test" },
        definition_digest: "3".repeat(64),
        ready: false,
        blocking_count: 2,
      },
    };
    const edited = {
      source: "editor",
      generation_id: null,
      generated_digest: null,
      validation: null,
    };
    const application = revision(3, validated);
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application } }),
      "GET /api/business-applications/checkout/history": () => ({
        body: { revisions: [application, revision(2, edited), revision(1, undefined)] },
      }),
    });
    const user = userEvent.setup();
    renderApplication("checkout");
    await user.click(await screen.findByRole("tab", { name: "History" }));

    expect(
      await screen.findByText(
        "Imported from YAML, validated at snapshot 4000, 2 paths blocked the ready state",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Saved in the visual editor, not validated")).toBeInTheDocument();
    expect(screen.getByText("Origin not recorded")).toBeInTheDocument();
  });
});

describe("Business Applications export", () => {
  it("shows the error of a failed export", async () => {
    const definition = {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "checkout",
      name: "Checkout",
      state: "draft",
      services: [],
      groups: [],
      connections: [],
    };
    const application = {
      id: "checkout",
      revision: 3,
      name: "Checkout",
      digest: "3".repeat(64),
      created_by: 1,
      created_at: "2026-01-01T00:00:00Z",
      definition,
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application } }),
      "GET /api/business-applications/checkout/export": () => ({
        status: 500,
        body: { error: "export failed on the server" },
      }),
    });
    renderApplication("checkout");
    await userEvent
      .setup()
      .click(await screen.findByRole("button", { name: "Export this revision" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("export failed on the server");
  });
});

describe("Business Applications page context", () => {
  it("registers the open application, its revision and the selected connections", async () => {
    const connection = (id: string, name: string) => ({
      id,
      name,
      source: "web",
      destination: "api",
      success: "session",
      destination_condition: { kind: "any" },
    });
    const application = {
      id: "checkout",
      revision: 3,
      name: "Checkout",
      digest: "a".repeat(64),
      created_by: 1,
      created_at: "2026-01-01T00:00:00Z",
      definition: {
        schema_version: 1,
        kind: "BusinessApplication",
        id: "checkout",
        name: "Checkout",
        state: "draft",
        services: [],
        groups: [],
        connections: [connection("c1", "Web to API"), connection("c2", "API to database")],
      },
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application } }),
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <AuthProvider>
            <AiContextProvider>
              <ApplicationsPage
                applicationId="checkout"
                onNavigate={() => undefined}
                onOpenAnalysis={() => undefined}
              />
              <PageContextProbe />
            </AiContextProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await waitFor(() =>
      expect(readPageContext()).toMatchObject({
        route: { section: "components" },
        application: { application_id: "checkout", revision: 3, connection_ids: ["c1", "c2"] },
      }),
    );
    await user.click(screen.getByRole("tab", { name: "Connections" }));
    await user.click(screen.getByRole("checkbox", { name: "Select Web to API" }));
    await waitFor(() =>
      expect(readPageContext()).toMatchObject({
        route: { section: "connections" },
        application: { connection_ids: ["c2"] },
      }),
    );
  });
});

describe("Business Applications placeholders", () => {
  const placeholder = {
    text: "web01",
    expected_kind: "ip",
    status: "ambiguous",
    candidates: ["ip:blue:10.0.0.5", "ip:red:10.0.0.5"],
    note: "one address on two IpAddress nodes",
  };
  const definition = {
    schema_version: 2,
    kind: "BusinessApplication",
    id: "webshop",
    name: "Webshop",
    state: "draft",
    services: [],
    groups: [
      { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
      { id: "servers", name: "Servers", members: [{ id: "web", name: "web01", placeholder }] },
    ],
    connections: [
      {
        id: "web",
        name: "Web",
        source: "clients",
        destination: "servers",
        success: "forward",
        destination_condition: { kind: "member", member: "web", parts: [] },
      },
    ],
  };
  const application = {
    id: "webshop",
    revision: 1,
    name: "Webshop",
    digest: "a".repeat(64),
    created_by: 1,
    created_at: "2026-01-01T00:00:00Z",
    definition,
  };

  it("lists a placeholder member with its status and text", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/webshop": () => ({ body: { application } }),
    });
    renderApplication("webshop");
    expect(await screen.findByText(/ambiguous placeholder: web01/)).toBeInTheDocument();
    expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
  });

  it("shows a placeholder in the editor, blocks ready and binds it to a candidate", async () => {
    const save = vi.fn((request: MockRequest) => ({
      body: {
        ...application,
        revision: 2,
        definition: (request.body as { definition: unknown }).definition,
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [application] } }),
      "GET /api/business-applications/webshop": () => ({ body: { application } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "PUT /api/business-applications/webshop": save,
    });
    const user = userEvent.setup();
    renderApplication("webshop");
    await user.click(await screen.findByRole("tab", { name: "Edit" }));

    const member = screen.getByRole("group", { name: "Placeholder web" });
    expect(
      within(member).getByText("Ambiguous placeholder: web01 (expected ip)"),
    ).toBeInTheDocument();
    expect(within(member).getByText("one address on two IpAddress nodes")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Ready intent" })).toBeDisabled();

    await user.selectOptions(within(member).getByLabelText("Candidate"), "ip:red:10.0.0.5");
    await user.click(within(member).getByRole("button", { name: "Bind" }));

    expect(screen.queryByRole("group", { name: "Placeholder web" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Inventory UID")).toHaveValue("ip:red:10.0.0.5");
    expect(screen.getByRole("option", { name: "Ready intent" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Save revision" }));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const body = save.mock.calls[0][0].body as {
      definition: typeof definition;
      expected_revision: number;
    };
    expect(body.expected_revision).toBe(1);
    expect(body.definition.schema_version).toBe(2);
    expect(body.definition.groups[1].members).toEqual([
      {
        id: "web",
        name: "web01",
        inventory: { kind: "ip", uid: "ip:red:10.0.0.5", role: "component" },
      },
    ]);
  });

  it("keeps the member context when it binds a placeholder", async () => {
    const scoped: BusinessApplicationDefinition = {
      schema_version: 2,
      kind: "BusinessApplication",
      id: "webshop",
      name: "Webshop",
      state: "draft",
      services: [],
      groups: [
        { id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] },
        {
          id: "servers",
          name: "Servers",
          members: [
            {
              id: "web",
              name: "web01",
              context: "blue",
              placeholder: {
                text: "web01",
                expected_kind: "ip",
                status: "unresolved",
                candidates: ["ip:blue:10.0.0.5"],
              },
            },
          ],
        },
      ],
      connections: [
        {
          id: "web",
          name: "Web",
          source: "clients",
          destination: "servers",
          success: "forward",
          destination_condition: { kind: "member", member: "web", parts: [] },
        },
      ],
    };
    const revision: ApplicationRevision = {
      id: "webshop",
      revision: 1,
      name: "Webshop",
      digest: "a".repeat(64),
      created_by: 1,
      created_at: "2026-01-01T00:00:00Z",
      definition: scoped,
    };
    const save = vi.fn((request: MockRequest) => ({
      body: {
        ...revision,
        revision: 2,
        definition: (request.body as { definition: unknown }).definition,
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [revision] } }),
      "GET /api/business-applications/webshop": () => ({ body: { application: revision } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "PUT /api/business-applications/webshop": save,
    });
    const user = userEvent.setup();
    renderApplication("webshop");
    await user.click(await screen.findByRole("tab", { name: "Edit" }));

    await user.click(
      within(screen.getByRole("group", { name: "Placeholder web" })).getByRole("button", {
        name: "Bind",
      }),
    );
    await user.click(screen.getByRole("button", { name: "Save revision" }));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const body = save.mock.calls[0][0].body as { definition: BusinessApplicationDefinition };
    expect(body.definition.groups[1].members).toEqual([
      {
        id: "web",
        name: "web01",
        context: "blue",
        inventory: { kind: "ip", uid: "ip:blue:10.0.0.5", role: "component" },
      },
    ]);
  });
});

describe("Business Applications generated drafts", () => {
  const yaml =
    "schema_version: 1\nkind: BusinessApplication\nid: checkout\nname: Checkout\nstate: draft\nservices: []\ngroups: []\nconnections: []\n";
  const definition = {
    schema_version: 1,
    kind: "BusinessApplication",
    id: "checkout",
    name: "Checkout",
    state: "draft",
    services: [],
    groups: [],
    connections: [],
  };
  const preview = {
    application_id: "checkout",
    base_revision: 0,
    base_digest: "",
    result_digest: "a".repeat(64),
    preview_digest: "b".repeat(64),
    definition,
    changes: { services_created: [], groups_created: [], connections_created: [] },
    mapping_issues: [],
    no_op: false,
  };
  const generation = {
    status: "done",
    generation_id: "g1",
    created_at: "2026-09-29T00:00:00Z",
    snapshot: REFERENCE,
    yaml,
    errors: [],
    report: {
      generation_id: "g1",
      snapshot: REFERENCE,
      definition_digest: "e".repeat(64),
      references: [],
      related: [],
      blocking: [],
    },
    validation: {
      errors: [],
      warnings: [],
      definition,
      preview,
      resolution: null,
      flows: null,
      blocking: [],
      snapshot: REFERENCE,
    },
    validation_digest: "c".repeat(64),
  };

  it("opens the draft workspace from the import block and closes it again", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Generate from a description" }));

    const draft = screen.getByRole("region", { name: "Application draft" });
    expect(within(draft).getByLabelText("Description")).toBeInTheDocument();
    expect(within(draft).getByRole("button", { name: "Generate" })).toBeDisabled();
    await user.click(within(draft).getByRole("button", { name: "Close draft" }));
    expect(screen.queryByRole("region", { name: "Application draft" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "No application selected" })).toBeInTheDocument();
  });

  it("offers no Generate entry to a user who may not ask", async () => {
    mockApi({
      "GET /api/me": () => ({ body: { ...ME_VIEWER, permissions: ["graph.read"] } }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
    });
    renderPage();
    expect(await screen.findByText("No applications")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Generate from a description" }),
    ).not.toBeInTheDocument();
  });

  it("saves an unchanged draft in replace mode with its generation and opens the saved application", async () => {
    const commit = vi.fn((_request: MockRequest) => ({
      status: 201,
      body: {
        id: "checkout",
        revision: 1,
        name: "Checkout",
        digest: "a".repeat(64),
        created_by: 1,
        created_at: "2026-01-01T00:00:00Z",
        definition,
      },
    }));
    const navigate = vi.fn();
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/generations": () => ({
        status: 202,
        body: { generation_id: "g1" },
      }),
      "GET /api/business-applications/generations/g1": () => ({ body: generation }),
      "POST /api/business-applications/import/commit": commit,
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MemoryRouter>
          <AuthProvider>
            <ApplicationsPage onNavigate={navigate} onOpenAnalysis={() => undefined} />
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await user.click(await screen.findByRole("button", { name: "Generate from a description" }));
    const draft = screen.getByRole("region", { name: "Application draft" });
    await user.type(within(draft).getByLabelText("Description"), "Checkout for the shop.");
    await within(draft).findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(within(draft).getByLabelText("Snapshot"), "4000");
    await user.click(within(draft).getByRole("button", { name: "Generate" }));

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(yaml);
    await user.click(screen.getByRole("button", { name: "Save as draft revision" }));

    await waitFor(() => expect(navigate).toHaveBeenCalledWith("checkout"));
    expect(commit.mock.calls[0][0].body).toEqual({
      yaml,
      mode: "replace",
      base_revision: 0,
      base_digest: "",
      preview_digest: "b".repeat(64),
      generation_id: "g1",
      validation_digest: "c".repeat(64),
    });
    expect(screen.queryByRole("region", { name: "Application draft" })).not.toBeInTheDocument();
  });
});
