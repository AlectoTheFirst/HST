/**
 * Business Applications page: a revision by pasted YAML, the export of a
 * revision, the pasted YAML after server diagnostics, and a Coverage resolve
 * that writes no revision.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import ApplicationsPage from "../applications/ApplicationsPage";
import type { ApplicationRevision } from "../applications/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";

function revision(number: number, extra: Partial<ApplicationRevision["definition"]> = {}): ApplicationRevision {
  return {
    id: "checkout",
    revision: number,
    name: "Checkout",
    digest: String(number).repeat(64),
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
      ...extra,
    },
  };
}

const SNAPSHOTS = { snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }], current: 4000, truncated: false };
const REFERENCE = { snapshot: "4000", manifest_sha256: "a".repeat(64), estate: "test", observation_floor_ms: null };

const YAML = [
  "schema_version: 1",
  "kind: BusinessApplication",
  "id: checkout",
  "name: Checkout",
  "description: Checkout with the payment group",
  "groups:",
  "  - id: payment",
  "    name: Payment",
  "    members:",
  "      - id: pay-1",
  "        address: 203.0.113.30",
  "",
].join("\n");

function preview(base: number) {
  return {
    application_id: "checkout",
    base_revision: base,
    base_digest: String(base).repeat(64),
    result_digest: String(base + 1).repeat(64),
    preview_digest: "p".repeat(64),
    definition: {},
    changes: { groups_created: ["payment"] },
    mapping_issues: [],
    no_op: false,
  };
}

function renderPage(onNavigate: (id?: string) => void = () => undefined, applicationId = "checkout") {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <AuthProvider>
          <ApplicationsPage applicationId={applicationId} onNavigate={onNavigate} onOpenAnalysis={() => undefined} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function pasteYaml(user: ReturnType<typeof userEvent.setup>, text: string) {
  await user.click(screen.getByText("Import YAML"));
  const editor = await screen.findByRole("textbox", { name: "Definition YAML" });
  await user.click(editor);
  await user.paste(text);
  return editor;
}

describe("Revision by pasted YAML", () => {
  it("commits pasted YAML onto the open revision and shows the next revision", async () => {
    let current = revision(2);
    const commits: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [current] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: current } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/import/preview": () => ({ body: preview(2) }),
      "POST /api/business-applications/import/commit": (req) => {
        commits.push(req);
        current = revision(3, { description: "Checkout with the payment group" });
        return { status: 201, body: { ...current, resolution_digest: null, resolution_error: null } };
      },
    });
    const navigated = vi.fn();
    const user = userEvent.setup();
    renderPage(navigated);
    expect(await screen.findByText("Revision 2")).toBeInTheDocument();

    await pasteYaml(user, YAML);
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    const shown = await screen.findByRole("region", { name: "Import preview" });
    await user.click(within(shown).getByRole("button", { name: "Commit revision" }));

    expect(await screen.findByText("Revision 3")).toBeInTheDocument();
    expect(screen.getByText("Checkout with the payment group")).toBeInTheDocument();
    expect(commits.map((req) => req.body)).toEqual([
      { yaml: YAML, mode: "merge", base_revision: 2, base_digest: "2".repeat(64), preview_digest: "p".repeat(64) },
    ]);
    expect(navigated).toHaveBeenCalledWith("checkout");
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toHaveValue("");
  });
});

describe("Export of a revision", () => {
  const downloads: Array<{ name: string; blob: Blob }> = [];
  let blobs: Blob[] = [];

  beforeEach(() => {
    downloads.length = 0;
    blobs = [];
    vi.stubGlobal(
      "URL",
      Object.assign(globalThis.URL, {
        createObjectURL: vi.fn((blob: Blob) => {
          blobs.push(blob);
          return `blob:hst-${blobs.length}`;
        }),
        revokeObjectURL: vi.fn(),
      }),
    );
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloads.push({ name: this.download, blob: blobs[blobs.length - 1] });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("downloads the served YAML of the open revision and of an older revision unchanged", async () => {
    const served = [
      { name: "checkout-r3.yaml", text: "schema_version: 1\nid: checkout\nname: Checkout\n# revision 3\n" },
      { name: "checkout-r1.yaml", text: "schema_version: 1\nid: checkout\nname: Checkout\n# revision 1\n" },
    ];
    const answers = [...served];
    const current = revision(3);
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [current] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: current } }),
      "GET /api/business-applications/checkout/history": () => ({
        body: { revisions: [current, revision(2), revision(1)] },
      }),
      "GET /api/business-applications/checkout/export": () => {
        const next = answers.shift()!;
        return {
          raw: next.text,
          headers: {
            "Content-Type": "application/yaml",
            "Content-Disposition": `attachment; filename="${next.name}"`,
          },
        };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Export this revision" }));
    await waitFor(() => expect(downloads).toHaveLength(1));
    await user.click(screen.getByRole("tab", { name: "History" }));
    await user.click(await screen.findByRole("button", { name: "Export revision 1" }));
    await waitFor(() => expect(downloads).toHaveLength(2));

    const exportUrls = vi
      .mocked(fetch)
      .mock.calls.map(([input]) => String(input))
      .filter((url) => url.includes("/export"));
    expect(exportUrls).toEqual([
      "/api/business-applications/checkout/export",
      "/api/business-applications/checkout/export?revision=1",
    ]);
    expect(downloads.map((item) => item.name)).toEqual(["checkout-r3.yaml", "checkout-r1.yaml"]);
    expect(await Promise.all(downloads.map((item) => item.blob.text()))).toEqual(served.map((item) => item.text));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("Pasted YAML after server diagnostics", () => {
  it("keeps the pasted YAML after a refused preview, a failed validation and a refused commit", async () => {
    const previews: MockRequest[] = [];
    const validations: MockRequest[] = [];
    let previewAnswer: { status: number; body: unknown } = {
      status: 422,
      body: { error: "groups.0.members.0: Value error, address must be an IPv4/IPv6 address or prefix" },
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [] } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/import/preview": (req) => {
        previews.push(req);
        return previewAnswer;
      },
      "POST /api/business-applications/validate": (req) => {
        validations.push(req);
        return {
          body: {
            errors: [{ path: "groups.0.members.0", message: "Value error, address is not valid", line: 11, column: 9 }],
            warnings: [],
            definition: null,
            preview: null,
            resolution: null,
            blocking: ["groups.0.members.0"],
            snapshot: REFERENCE,
          },
        };
      },
      "POST /api/business-applications/import/commit": () => ({
        status: 422,
        body: { error: "unknown application validation " + "v".repeat(64) },
      }),
    });
    const user = userEvent.setup();
    renderPage(() => undefined, "");
    const editor = await screen.findByRole("textbox", { name: "Definition YAML" });
    await user.click(editor);
    await user.paste(YAML);

    await user.click(screen.getByRole("button", { name: "Preview import" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("address must be an IPv4/IPv6 address or prefix");
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toHaveValue(YAML);

    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Validation snapshot"), "4000");
    await user.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByRole("list", { name: "Validation errors" })).toHaveTextContent("Line 11, column 9");
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toHaveValue(YAML);

    previewAnswer = { status: 200, body: preview(0) };
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    const shown = await screen.findByRole("region", { name: "Import preview" });
    await user.click(within(shown).getByRole("button", { name: "Commit revision" }));
    await waitFor(() =>
      expect(screen.getAllByRole("alert").some((item) => item.textContent?.includes("unknown application validation"))).toBe(true),
    );
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toHaveValue(YAML);

    expect(previews.map((req) => req.body)).toEqual([
      { yaml: YAML, mode: "merge" },
      { yaml: YAML, mode: "merge" },
    ]);
    expect(validations.map((req) => req.body)).toEqual([{ yaml: YAML, mode: "merge", snapshot: "4000" }]);
  });
});

describe("Coverage and the authored definition", () => {
  it("resolves Coverage at a snapshot and writes no revision", async () => {
    const current = revision(3, {
      services: [{ id: "shop", name: "Shop", connection_ids: ["c1"], component_roles: [] }],
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
    });
    const writes: MockRequest[] = [];
    const resolves: MockRequest[] = [];
    const write = (req: MockRequest) => {
      writes.push(req);
      return { status: 500, body: { error: "unexpected write" } };
    };
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [current] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: current } }),
      "GET /api/snapshots": () => ({ body: SNAPSHOTS }),
      "POST /api/business-applications/checkout/resolve": (req) => {
        resolves.push(req);
        return {
          body: {
            application: { id: "checkout", revision: 3, digest: "3".repeat(64) },
            snapshot: REFERENCE,
            digest: "c".repeat(64),
            ready: true,
            selection: { service_ids: [], connection_ids: ["c1"] },
            groups: {},
            connections: [{ id: "c1", service_id: "shop", readiness: "ready", request: null, issues: [] }],
            issues: [],
          },
        };
      },
      "PUT /api/business-applications/checkout": write,
      "POST /api/business-applications": write,
      "POST /api/business-applications/import/preview": write,
      "POST /api/business-applications/import/commit": write,
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("tab", { name: "Coverage" }));
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Coverage snapshot"), "4000");

    expect(await screen.findByText("All selected connections ready")).toBeInTheDocument();
    expect(resolves.map((req) => req.body)).toEqual([{ snapshot: "4000", connection_ids: ["c1"] }]);
    expect(writes).toHaveLength(0);
    expect(screen.getByText("Revision 3")).toBeInTheDocument();
  });
});
