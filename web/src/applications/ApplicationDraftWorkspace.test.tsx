import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import type { MockRequest } from "../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";
import { draftSourceMessages } from "../ai/DraftApplication";
import { ASK_POLL_MS } from "../ai/useConversation";
import type { ConversationMessage } from "../api/types";
import { TopBar } from "../shell/TopBar";
import { WorkspaceProvider, useWorkspace } from "../workspace/WorkspaceContext";
import { initial, panes, reduce } from "../workspace/layout";
import ApplicationsPage from "./ApplicationsPage";
import { ApplicationDraftWorkspace, bindPlaceholder } from "./ApplicationDraftWorkspace";
import { AiDrawerProvider } from "../ai/drawer";
import { AiContextProvider, MAX_DRAFT_MEMBERS, MAX_DRAFT_YAML_CHARS } from "../ai/context";
import { PageContextProbe, readPageContext } from "../test/aiContext";

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

// the canonical YAML the generator writes for a draft with one ambiguous member
const PLACEHOLDER_YAML = `schema_version: 2
kind: BusinessApplication
id: webshop
name: Webshop
state: draft
services: []
groups:
- id: clients
  name: Clients
  members:
  - id: lan
    address: 10.9.0.0/24
- id: servers
  name: Servers
  members:
  - id: web
    name: web01
    placeholder:
      text: web01
      expected_kind: ip
      status: ambiguous
      candidates:
      - ip:blue:10.0.0.5
      - ip:red:10.0.0.5
      note: address 10.0.0.5 is recorded as 2 IpAddress nodes
  - id: db
    name: db01
    inventory:
      kind: ip
      uid: ip:corp:10.0.0.9
      role: component
connections: []
`;

const BOUND_YAML = PLACEHOLDER_YAML.replace(
  `    placeholder:
      text: web01
      expected_kind: ip
      status: ambiguous
      candidates:
      - ip:blue:10.0.0.5
      - ip:red:10.0.0.5
      note: address 10.0.0.5 is recorded as 2 IpAddress nodes
`,
  `    inventory:
      kind: ip
      uid: "ip:red:10.0.0.5"
      role: component
`,
);

const PLACEHOLDER = {
  text: "web01",
  expected_kind: "ip",
  status: "ambiguous",
  candidates: ["ip:blue:10.0.0.5", "ip:red:10.0.0.5"],
  note: "address 10.0.0.5 is recorded as 2 IpAddress nodes",
};

function definition(web: Record<string, unknown>) {
  return {
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
          { id: "web", name: "web01", ...web },
          {
            id: "db",
            name: "db01",
            inventory: { kind: "ip", uid: "ip:corp:10.0.0.9", role: "component" },
          },
        ],
      },
    ],
    connections: [],
  };
}

function validation(document: unknown, blocking: string[], extra: Record<string, unknown> = {}) {
  return {
    errors: [],
    warnings: [],
    definition: document,
    preview: null,
    resolution: null,
    flows: null,
    blocking,
    snapshot: REFERENCE,
    ...extra,
  };
}

const REPORT = {
  generation_id: "g1",
  snapshot: REFERENCE,
  definition_digest: "e".repeat(64),
  references: [
    {
      path: "groups.clients.members.lan",
      phrase: "10.9.0.0/24",
      status: "resolved",
      selection: "exact",
      kind: null,
      uid: null,
      bindings: [{ address: "10.9.0.0/24", context: null }],
      alternatives: [],
      chain: [],
      evidence: [],
      issues: [],
    },
    {
      path: "groups.servers.members.web",
      phrase: "web01",
      status: "ambiguous",
      selection: "none",
      kind: null,
      uid: null,
      bindings: [],
      alternatives: ["ip:blue:10.0.0.5", "ip:red:10.0.0.5"],
      chain: [],
      evidence: [
        { step: 2, tool: "inventory_resolve", arguments: { kind: "address", address: "10.0.0.5" } },
      ],
      issues: [],
    },
    {
      path: "groups.servers.members.db",
      phrase: "db01",
      status: "resolved",
      selection: "model-choice",
      kind: "ip",
      uid: "ip:corp:10.0.0.9",
      bindings: [{ address: "10.0.0.9", context: "corp" }],
      alternatives: ["ip:corp:10.0.0.19"],
      chain: [{ from: "vm:db01", rel: "HAS_IP", to: "ip:corp:10.0.0.9" }],
      evidence: [{ step: 1, tool: "search_objects", arguments: { kind: "vm", q: "db01" } }],
      issues: [],
    },
  ],
  related: [],
  blocking: ["groups.servers.members.web"],
};

const PREVIEW = {
  application_id: "webshop",
  base_revision: 0,
  base_digest: "",
  result_digest: "a".repeat(64),
  preview_digest: "b".repeat(64),
  definition: {},
  changes: {
    services_created: [],
    groups_created: ["clients", "servers"],
    connections_created: [],
  },
  mapping_issues: [],
  no_op: false,
};

function generated(overrides: Record<string, unknown> = {}) {
  return {
    status: "done",
    generation_id: "g1",
    created_at: "2026-09-29T00:00:00Z",
    snapshot: REFERENCE,
    yaml: PLACEHOLDER_YAML,
    errors: [],
    report: REPORT,
    validation: validation(definition({ placeholder: PLACEHOLDER }), [
      "groups.servers.members.web",
    ]),
    validation_digest: null,
    ...overrides,
  };
}

const SAVED = {
  id: "webshop",
  revision: 1,
  name: "Webshop",
  digest: "f".repeat(64),
  created_by: 1,
  created_at: "2026-09-29T00:00:00Z",
  definition: definition({ inventory: { kind: "ip", uid: "ip:red:10.0.0.5", role: "component" } }),
};

function client() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderWorkspace(canCommit: boolean) {
  const onCommitted = vi.fn();
  const view = render(
    <QueryClientProvider client={client()}>
      <ApplicationDraftWorkspace
        generationId="g1"
        canCommit={canCommit}
        onGenerated={() => undefined}
        onClose={() => undefined}
        onCommitted={onCommitted}
      />
    </QueryClientProvider>,
  );
  return { ...view, onCommitted };
}

describe("Application draft workspace", () => {
  it("lets a viewer generate a draft from a description and keeps the save disabled", async () => {
    const start = vi.fn((_request: MockRequest) => ({
      status: 202,
      body: { generation_id: "g1" },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_VIEWER }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/generations": start,
      "GET /api/business-applications/generations/g1": () => ({ body: generated() }),
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <AuthProvider>
            <ApplicationsPage onNavigate={() => undefined} onOpenAnalysis={() => undefined} />
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Generate from a description" }));
    const draft = screen.getByRole("region", { name: "Application draft" });
    await user.type(
      within(draft).getByLabelText("Description"),
      "Webshop: office users reach web01 on tcp 443.",
    );
    await within(draft).findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(within(draft).getByLabelText("Snapshot"), "4000");
    await user.click(within(draft).getByRole("button", { name: "Generate" }));

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(
      PLACEHOLDER_YAML,
    );
    expect(start.mock.calls[0][0].body).toEqual({
      description: "Webshop: office users reach web01 on tcp 443.",
      snapshot: "4000",
    });
    const save = screen.getByRole("region", { name: "Save draft revision" });
    expect(within(save).getByRole("button", { name: "Save as draft revision" })).toBeDisabled();
    expect(within(save).queryByRole("button", { name: "Preview changes" })).not.toBeInTheDocument();
  });

  it("binds a placeholder in the YAML text and commits the draft in replace mode", async () => {
    const validate = vi.fn((request: MockRequest) => ({
      body: validation(
        definition({ inventory: { kind: "ip", uid: "ip:red:10.0.0.5", role: "component" } }),
        [],
        (request.body as { record?: boolean }).record ? { validation_digest: "d".repeat(64) } : {},
      ),
    }));
    const preview = vi.fn((_request: MockRequest) => ({ body: PREVIEW }));
    const commit = vi.fn((_request: MockRequest) => ({ status: 201, body: SAVED }));
    mockApi({
      "GET /api/business-applications/generations/g1": () => ({
        body: generated({
          validation: validation(
            definition({ placeholder: PLACEHOLDER }),
            ["groups.servers.members.web"],
            { preview: PREVIEW },
          ),
          validation_digest: "c".repeat(64),
        }),
      }),
      "POST /api/business-applications/validate": validate,
      "POST /api/business-applications/import/preview": preview,
      "POST /api/business-applications/import/commit": commit,
    });
    const user = userEvent.setup();
    const { onCommitted } = renderWorkspace(true);

    const row = await screen.findByRole("article", {
      name: "Reference groups.servers.members.web",
    });
    expect(within(row).getByText("Ambiguous placeholder")).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("article", { name: "Reference groups.servers.members.db" }),
      ).getByText("Chain: vm:db01 HAS_IP ip:corp:10.0.0.9"),
    ).toBeInTheDocument();
    expect(screen.getByText("1 path blocks the ready state")).toBeInTheDocument();
    // the generated text carries the generation's own import preview
    expect(screen.getByRole("button", { name: "Save as draft revision" })).toBeEnabled();

    await user.selectOptions(within(row).getByLabelText("Candidate"), "ip:red:10.0.0.5");
    await user.click(within(row).getByRole("button", { name: "Bind" }));
    expect(screen.getByRole("textbox", { name: "Draft YAML" })).toHaveValue(BOUND_YAML);
    // an edited text needs its own preview
    expect(screen.getByRole("button", { name: "Save as draft revision" })).toBeDisabled();

    expect(await screen.findByText("Nothing blocks the ready state")).toBeInTheDocument();
    expect(validate.mock.calls[0][0].body).toEqual({
      yaml: BOUND_YAML,
      snapshot: "4000",
      mode: "replace",
    });
    expect(
      within(
        screen.getByRole("article", { name: "Reference groups.servers.members.web" }),
      ).getByText(/Bound to/),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Preview changes" }));
    expect(await screen.findByRole("region", { name: "Save preview" })).toHaveTextContent(
      "groups created: clients, servers",
    );
    expect(validate.mock.calls[1][0].body).toEqual({
      yaml: BOUND_YAML,
      snapshot: "4000",
      mode: "replace",
      record: true,
    });
    // the preview names the recorded validation, whose resolution notes the inventory members
    expect(preview.mock.calls.map(([request]) => request.body)).toEqual([
      { yaml: BOUND_YAML, mode: "replace", validation_digest: "d".repeat(64) },
    ]);

    await user.click(screen.getByRole("button", { name: "Save as draft revision" }));
    await waitFor(() => expect(onCommitted).toHaveBeenCalledTimes(1));
    expect(commit.mock.calls[0][0].body).toEqual({
      yaml: BOUND_YAML,
      mode: "replace",
      base_revision: 0,
      base_digest: "",
      preview_digest: "b".repeat(64),
      generation_id: "g1",
      validation_digest: "d".repeat(64),
    });
  });

  it("previews the save with the recorded validation, so a resolved member carries no snapshot note", async () => {
    const generic = {
      code: "inventory-resolution-required",
      path: "groups.servers.members.db.inventory",
      detail: "Select a pinned snapshot to resolve this inventory reference.",
    };
    const preview = vi.fn((request: MockRequest) => ({
      body: {
        ...PREVIEW,
        mapping_issues:
          (request.body as { validation_digest?: string }).validation_digest === "c".repeat(64)
            ? []
            : [generic],
      },
    }));
    mockApi({
      "GET /api/business-applications/generations/g1": () => ({
        body: generated({
          validation: validation(definition({ placeholder: PLACEHOLDER }), [
            "groups.servers.members.web",
          ]),
          validation_digest: "c".repeat(64),
        }),
      }),
      "POST /api/business-applications/import/preview": preview,
    });
    const user = userEvent.setup();
    renderWorkspace(true);

    await user.click(await screen.findByRole("button", { name: "Preview changes" }));
    const review = await screen.findByRole("region", { name: "Save preview" });
    expect(review).toHaveTextContent("groups created: clients, servers");
    expect(review).not.toHaveTextContent("Select a pinned snapshot");
    expect(preview.mock.calls.map(([request]) => request.body)).toEqual([
      { yaml: PLACEHOLDER_YAML, mode: "replace", validation_digest: "c".repeat(64) },
    ]);
  });

  it("shows YAML that does not parse as the raw text with the error of each line", async () => {
    const raw = "schema_version: 2\nkind: BusinessApplication\nid: webshop\ngroups: [\n";
    const errors = [
      {
        path: "$",
        message: "while parsing a flow sequence: expected ',' or ']', but got '<stream end>'",
        line: 5,
        column: 1,
      },
    ];
    mockApi({
      "GET /api/business-applications/generations/g1": () => ({
        body: generated({
          yaml: raw,
          errors,
          report: { ...REPORT, definition_digest: null, references: [], blocking: [] },
          validation: { ...validation(null, ["$"]), errors },
        }),
      }),
    });
    const { container } = renderWorkspace(false);

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(raw);
    expect(
      within(screen.getByRole("list", { name: "YAML errors" })).getByText(
        "Line 5, column 1: $: while parsing a flow sequence: expected ',' or ']', but got '<stream end>'",
      ),
    ).toBeInTheDocument();
    expect(container.querySelector(".yaml-editor-gutter .error")).toHaveTextContent("5");
    expect(screen.queryByRole("region", { name: "Resolution report" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Structure" })).not.toBeInTheDocument();
  });

  it("says why a generation failed", async () => {
    mockApi({
      "GET /api/business-applications/generations/g1": () => ({
        body: { status: "error", detail: "the model declined to write the application" },
      }),
    });
    renderWorkspace(true);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "the model declined to write the application",
    );
    expect(screen.queryByRole("textbox", { name: "Draft YAML" })).not.toBeInTheDocument();
  });

  it("lists the post-processor's errors of a generated text that parsed and holds its preview", async () => {
    const raw =
      "schema_version: 1\nkind: BusinessApplication\nid: webshop\nname: Webshop\nservices: []\ngroups: []\nconnections: []\n";
    const errors = [
      {
        path: "groups.1.members.0.placeholder",
        message: "Extra inputs are not permitted",
        line: null,
        column: null,
      },
    ];
    mockApi({
      "GET /api/business-applications/generations/g1": () => ({
        body: generated({
          yaml: raw,
          errors,
          report: { ...REPORT, definition_digest: null, references: [], blocking: [] },
          validation: validation(definition({ address: "10.0.0.5" }), []),
          validation_digest: "c".repeat(64),
        }),
      }),
    });
    renderWorkspace(true);

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(raw);
    expect(
      within(screen.getByRole("list", { name: "YAML errors" })).getByText(
        "groups.1.members.0.placeholder: Extra inputs are not permitted",
      ),
    ).toBeInTheDocument();
    const save = screen.getByRole("region", { name: "Save draft revision" });
    expect(within(save).getByRole("button", { name: "Preview changes" })).toBeDisabled();
    expect(within(save).getByRole("button", { name: "Save as draft revision" })).toBeDisabled();
  });
});

describe("Edit with AI", () => {
  it("edits a saved revision and commits onto the revision the edit started from", async () => {
    const saved = { ...SAVED, revision: 3, digest: "3".repeat(64) };
    const source = {
      kind: "edit",
      application_id: "webshop",
      base_revision: 3,
      base_digest: "3".repeat(64),
    };
    // revision 4 was saved while the edit ran, so the preview states it
    const moved = { ...PREVIEW, base_revision: 4, base_digest: "4".repeat(64) };
    const edit = generated({
      source,
      validation: validation(
        definition({ placeholder: PLACEHOLDER }),
        ["groups.servers.members.web"],
        { preview: moved },
      ),
      validation_digest: "c".repeat(64),
    });
    const start = vi.fn((_request: MockRequest) => ({
      status: 202,
      body: { generation_id: "g1" },
    }));
    const commit = vi.fn((_request: MockRequest) => ({
      status: 409,
      body: {
        error:
          "the edit started from revision 3 of webshop; start the edit again from the current revision",
      },
    }));
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [saved] } }),
      "GET /api/business-applications/webshop": () => ({ body: { application: saved } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/generations": start,
      "GET /api/business-applications/generations/g1": () => ({ body: edit }),
      "POST /api/business-applications/import/commit": commit,
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <AuthProvider>
            <ApplicationsPage
              applicationId="webshop"
              onNavigate={() => undefined}
              onOpenAnalysis={() => undefined}
            />
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "Edit with AI" }));
    const draft = screen.getByRole("region", { name: "Application draft" });
    expect(within(draft).getByRole("heading", { name: "Edit with AI" })).toBeInTheDocument();
    await user.type(within(draft).getByLabelText("Change"), "Add the web server web01.");
    await within(draft).findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(within(draft).getByLabelText("Snapshot"), "4000");
    await user.click(within(draft).getByRole("button", { name: "Generate the edit" }));

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(
      PLACEHOLDER_YAML,
    );
    expect(start.mock.calls[0][0].body).toEqual({
      description: "Add the web server web01.",
      snapshot: "4000",
      application_id: "webshop",
      base_revision: 3,
    });
    expect(screen.getByText("Edit of webshop revision 3 at snapshot 4000")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save as draft revision" }));
    expect(await screen.findByText(/changed after revision 3/)).toBeInTheDocument();
    // the commit states the revision the edit started from
    expect(commit.mock.calls[0][0].body).toEqual({
      yaml: PLACEHOLDER_YAML,
      mode: "replace",
      base_revision: 3,
      base_digest: "3".repeat(64),
      preview_digest: "b".repeat(64),
      generation_id: "g1",
      validation_digest: "c".repeat(64),
    });
  });
});

async function flush(stepMs = 50, rounds = 10) {
  for (let i = 0; i < rounds; i++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(stepMs);
    });
  }
}

describe("the generation poll", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("reads a running generation again until it finishes", async () => {
    let reads = 0;
    vi.useFakeTimers();
    mockApi({
      "GET /api/business-applications/generations/g1": () => {
        reads += 1;
        return { body: reads === 1 ? { status: "running" } : generated() };
      },
    });
    renderWorkspace(true);

    await flush();
    expect(reads).toBe(1);
    expect(screen.getByRole("status")).toHaveTextContent("Generating the definition");

    await flush(ASK_POLL_MS, 1);
    await flush();
    expect(reads).toBe(2);
    expect(screen.getByRole("textbox", { name: "Draft YAML" })).toHaveValue(PLACEHOLDER_YAML);

    await flush(ASK_POLL_MS, 3);
    expect(reads).toBe(2);
  });

  it("reads a generation the server refuses once and says why", async () => {
    let reads = 0;
    vi.useFakeTimers();
    mockApi({
      "GET /api/business-applications/generations/g1": () => {
        reads += 1;
        return { status: 404, body: { error: "no such generation" } };
      },
    });
    renderWorkspace(true);

    await flush();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "The draft could not be read: no such generation",
    );

    await flush(ASK_POLL_MS, 5);
    expect(reads).toBe(1);
  });

  it("reads a refused generation again on request", async () => {
    let reads = 0;
    mockApi({
      "GET /api/business-applications/generations/g1": () => {
        reads += 1;
        return reads === 1
          ? { status: 503, body: { error: "the store is unavailable" } }
          : { body: generated() };
      },
    });
    const user = userEvent.setup();
    renderWorkspace(true);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The draft could not be read: the store is unavailable",
    );
    await user.click(screen.getByRole("button", { name: "Read again" }));

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(
      PLACEHOLDER_YAML,
    );
    expect(reads).toBe(2);
  });
});

describe("bindPlaceholder", () => {
  const inventory = { kind: "ip" as const, uid: "ip:red:10.0.0.5", role: "component" as const };

  it("replaces the placeholder of the member and keeps every other line", () => {
    expect(bindPlaceholder(PLACEHOLDER_YAML, "groups.servers.members.web", inventory)).toBe(
      BOUND_YAML,
    );
  });

  it("finds the member in its own group and keeps the dash of a first entry", () => {
    const text =
      "groups:\n  - id: clients\n    members:\n      - id: web\n        address: 10.9.0.1\n  - id: servers\n    members:\n      - placeholder:\n          text: web01\n          candidates: [ip:red:10.0.0.5]\n        id: web\n";
    expect(bindPlaceholder(text, "groups.clients.members.web", inventory)).toBeNull();
    expect(bindPlaceholder(text, "groups.servers.members.web", inventory)).toBe(
      'groups:\n  - id: clients\n    members:\n      - id: web\n        address: 10.9.0.1\n  - id: servers\n    members:\n      - inventory:\n          kind: ip\n          uid: "ip:red:10.0.0.5"\n          role: component\n        id: web\n',
    );
  });

  it("answers null for a path the text does not hold", () => {
    expect(bindPlaceholder(PLACEHOLDER_YAML, "groups.servers.members.cache", inventory)).toBeNull();
    expect(bindPlaceholder(PLACEHOLDER_YAML, "groups.servers.members.db", inventory)).toBeNull();
    expect(bindPlaceholder(PLACEHOLDER_YAML, "connections.web", inventory)).toBeNull();
  });
});

describe("the draft on the workspace pane", () => {
  it("keeps the draft until another application opens", () => {
    const start = initial();
    const drafted = reduce(start, {
      type: "set-application-draft",
      id: start.focus,
      draft: { generationId: "g1" },
    });
    expect(panes(drafted.root)[0]).toMatchObject({
      view: "applications",
      applicationDraft: { generationId: "g1" },
    });
    expect(
      panes(reduce(drafted, { type: "open-application", id: start.focus }).root)[0]
        .applicationDraft,
    ).toEqual({ generationId: "g1" });
    expect(
      panes(
        reduce(drafted, { type: "open-application", id: start.focus, applicationId: "checkout" })
          .root,
      )[0].applicationDraft,
    ).toBeUndefined();
  });
});

/** The focused pane's view and the generation of its draft. */
function FocusedPane() {
  const workspace = useWorkspace()!;
  const pane = panes(workspace.state.root).find((item) => item.id === workspace.state.focus)!;
  return (
    <output aria-label="Focused pane">
      {pane.view}:{pane.applicationDraft?.generationId ?? ""}
    </output>
  );
}

function message(
  id: string,
  seq: number,
  role: "user" | "assistant",
  content: string,
): ConversationMessage {
  return {
    id,
    seq,
    role,
    status: "done",
    content,
    context: null,
    envelope: null,
    error: null,
    snapshot: null,
    created_at: null,
    finished_at: null,
    steps: [],
  };
}

describe("a chat description to the draft workspace", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("takes the newest questions before the answer that fit the description bound", () => {
    const messages = [
      message("q0", 0, "user", "a".repeat(3200)),
      message("m0", 1, "assistant", "noted"),
      message("q1", 2, "user", "b".repeat(900)),
      message("q2", 3, "user", "  "),
      message("m1", 4, "assistant", "noted"),
      message("q3", 5, "user", "later"),
    ];
    expect(draftSourceMessages(messages, "m1")).toEqual(["q1"]);
    expect(draftSourceMessages(messages.slice(2), "m1")).toEqual(["q1"]);
    expect(
      draftSourceMessages([message("q0", 0, "user", "short"), ...messages.slice(2)], "m1"),
    ).toEqual(["q0", "q1"]);
  });

  it("drafts a Business Application from the questions of a drawer answer and opens it in the focused pane", async () => {
    window.history.replaceState({}, "", "/");
    const drafts: MockRequest[] = [];
    const envelope = {
      version: 2,
      message_id: "m2",
      conversation_id: "c1",
      kind: "answer",
      snapshot: { id: "4000", origin: "pointer", others_used: [] },
      model: { provider: "anthropic", requested: "claude-opus-5" },
      prompt_hash: "h",
      tools_used: [],
      answer_markdown: "Noted.",
      claims: [],
      grounding: { status: "no-evidence", cited: 0, uncited: 0, invalid: 0, cross_snapshot: 0 },
      links: [],
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: true } }),
      "POST /api/ai/conversations": () => ({
        status: 201,
        body: { id: "c1", surface: "drawer", message_count: 0 },
      }),
      "POST /api/ai/conversations/c1/messages": () => ({ status: 202, body: { message_id: "m2" } }),
      "GET /api/ai/messages/m2": () => ({
        body: { status: "done", declined: false, answer: "Noted.", steps: [], envelope },
      }),
      "GET /api/ai/conversations/c1": () => ({
        body: {
          id: "c1",
          surface: "drawer",
          message_count: 4,
          messages: [
            message("q1", 0, "user", "Webshop: office users reach web01 on tcp 443."),
            message("m2", 1, "assistant", "Noted."),
          ],
        },
      }),
      "POST /api/ai/service-drafts": (request) => {
        drafts.push(request);
        return { status: 202, body: { generation_id: "g9" } };
      },
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <AiDrawerProvider>
                <TopBar />
              </AiDrawerProvider>
              <FocusedPane />
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(
      within(drawer).getByLabelText("Ask HST AI"),
      "Webshop: office users reach web01 on tcp 443.",
    );
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    await user.click(
      await within(drawer).findByRole("button", { name: "Draft Business Application" }),
    );

    await waitFor(() =>
      expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent(
        "applications:g9",
      ),
    );
    expect(drafts.map((request) => request.body)).toEqual([
      { conversation_id: "c1", message_ids: ["q1"], snapshot: "4000" },
    ]);
    expect(within(drawer).getByText("Draft started at run 4000")).toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: "Open draft" })).toBeInTheDocument();
  });

  it("offers no draft on a route that does not show the workspace", async () => {
    const envelope = {
      version: 2,
      message_id: "m2",
      conversation_id: "c1",
      kind: "answer",
      snapshot: { id: "4000", origin: "pointer", others_used: [] },
      model: { provider: "anthropic", requested: "claude-opus-5" },
      prompt_hash: "h",
      tools_used: [],
      answer_markdown: "Recorded.",
      claims: [],
      grounding: { status: "no-evidence", cited: 0, uncited: 0, invalid: 0, cross_snapshot: 0 },
      links: [],
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true, agent: true } }),
      "POST /api/ai/conversations": () => ({
        status: 201,
        body: { id: "c1", surface: "drawer", message_count: 0 },
      }),
      "POST /api/ai/conversations/c1/messages": () => ({ status: 202, body: { message_id: "m2" } }),
      "GET /api/ai/messages/m2": () => ({
        body: { status: "done", declined: false, answer: "Recorded.", steps: [], envelope },
      }),
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter initialEntries={["/inventory"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <AiDrawerProvider>
                <TopBar />
              </AiDrawerProvider>
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "HST AI" }));
    const drawer = screen.getByRole("complementary", { name: "HST AI" });
    await user.type(
      within(drawer).getByLabelText("Ask HST AI"),
      "Webshop: office users open web01 on tcp 443.",
    );
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));

    expect(await within(drawer).findByText("Recorded.")).toBeInTheDocument();
    expect(
      within(drawer).queryByRole("button", { name: "Draft Business Application" }),
    ).not.toBeInTheDocument();
  });
});

describe("the page context of the open draft", () => {
  const GENERATION = "6f1c2a4e-1b2c-4d5e-8f90-0a1b2c3d4e5f";
  const route = `GET /api/business-applications/generations/${GENERATION}`;

  function renderWithContext() {
    return render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <AiContextProvider>
            <ApplicationDraftWorkspace
              generationId={GENERATION}
              canCommit={false}
              onGenerated={() => undefined}
              onClose={() => undefined}
              onCommitted={() => undefined}
            />
            <PageContextProbe />
          </AiContextProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  it("publishes the generation, its run, the YAML on screen and the report's members with their notes", async () => {
    mockApi({
      [route]: () => ({ body: generated({ generation_id: GENERATION }) }),
      "POST /api/business-applications/validate": () => ({
        body: validation(definition({ placeholder: PLACEHOLDER }), ["groups.servers.members.web"]),
      }),
    });
    const user = userEvent.setup();
    renderWithContext();

    await waitFor(() =>
      expect(readPageContext()).toMatchObject({
        route: { section: "draft" },
        // the turn reads the run the draft was resolved at
        snapshot: { id: "4000", origin: "pinned" },
        application_draft: {
          generation_id: GENERATION,
          status: "done",
          run_id: "4000",
          edited: false,
          yaml: PLACEHOLDER_YAML,
        },
      }),
    );
    expect(readPageContext().application_draft.members).toEqual([
      { path: "groups.clients.members.lan", status: "resolved", phrase: "10.9.0.0/24" },
      {
        path: "groups.servers.members.web",
        status: "ambiguous",
        phrase: "web01",
        candidates: ["ip:blue:10.0.0.5", "ip:red:10.0.0.5"],
        note: "address 10.0.0.5 is recorded as 2 IpAddress nodes",
      },
      {
        path: "groups.servers.members.db",
        status: "resolved",
        phrase: "db01",
        uid: "ip:corp:10.0.0.9",
        candidates: ["ip:corp:10.0.0.19"],
      },
    ]);

    // an edit reaches the context with the text on screen
    await user.type(screen.getByRole("textbox", { name: "Draft YAML" }), "#");
    await waitFor(() =>
      expect(readPageContext().application_draft).toMatchObject({
        edited: true,
        yaml: `${PLACEHOLDER_YAML}#`,
      }),
    );
  });

  it("cuts the YAML and the members to the schema's caps and says so", async () => {
    const yaml = "key: value\n".repeat(1500);
    const references = Array.from({ length: MAX_DRAFT_MEMBERS + 5 }, (_, index) => ({
      path: `groups.peers.members.m${index}`,
      phrase: `peer ${index}`,
      status: "unresolved",
      selection: "none",
      kind: null,
      uid: null,
      bindings: [],
      alternatives: [],
      chain: [],
      evidence: [],
      issues: [
        {
          code: "unresolved",
          path: `groups.peers.members.m${index}`,
          detail: "x".repeat(400),
          severity: "error",
        },
      ],
    }));
    mockApi({
      [route]: () => ({
        body: generated({
          generation_id: GENERATION,
          yaml,
          report: { ...REPORT, references },
          validation: null,
        }),
      }),
    });
    renderWithContext();

    await waitFor(() => expect(readPageContext().application_draft?.yaml).toBeDefined());
    const draft = readPageContext().application_draft;
    expect(yaml.length).toBeGreaterThan(MAX_DRAFT_YAML_CHARS);
    expect(draft.yaml).toBe(yaml.slice(0, MAX_DRAFT_YAML_CHARS));
    expect(draft.yaml_truncated).toBe(true);
    expect(draft.members).toHaveLength(MAX_DRAFT_MEMBERS);
    expect(draft.members_truncated).toBe(true);
    expect(draft.members[0].issues[0]).toHaveLength(300);
  });

  it("publishes a running generation before its YAML exists", async () => {
    mockApi({ [route]: () => ({ body: { status: "running" } }) });
    renderWithContext();

    await waitFor(() =>
      expect(readPageContext()).toMatchObject({
        route: { section: "draft" },
        application_draft: { generation_id: GENERATION, status: "running" },
      }),
    );
    expect(readPageContext().application_draft.yaml).toBeUndefined();
  });

  it("leaves out a draft whose generation id the server would reject", async () => {
    mockApi({ "GET /api/business-applications/generations/g1": () => ({ body: generated() }) });
    render(
      <QueryClientProvider client={client()}>
        <MemoryRouter>
          <AiContextProvider>
            <ApplicationDraftWorkspace
              generationId="g1"
              canCommit={false}
              onGenerated={() => undefined}
              onClose={() => undefined}
              onCommitted={() => undefined}
            />
            <PageContextProbe />
          </AiContextProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByRole("textbox", { name: "Draft YAML" })).toHaveValue(
      PLACEHOLDER_YAML,
    );
    await waitFor(() => expect(readPageContext().route.section).toBe("draft"));
    expect(readPageContext().application_draft).toBeUndefined();
  });
});
