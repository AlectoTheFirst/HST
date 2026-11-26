import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import type { AssessmentDraft } from "../assessments/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import ApplicationsPage from "./ApplicationsPage";
import { TraceConnectionActions } from "./TraceConnectionActions";
import type { ApplicationRevision } from "./types";

const client = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

describe("Trace connection ID", () => {
  it("keeps the hyphens a user types and saves the typed ID", async () => {
    const sessions: MockRequest[] = [];
    mockApi({
      "GET /api/analysis-snapshot": () => ({
        body: { snapshot: "4000", manifest_sha256: "c".repeat(64), estate: "test" },
      }),
      "POST /api/analysis-sessions": (req) => {
        sessions.push(req);
        return { status: 201, body: { id: "s1", revision: 1, input_digest: "e".repeat(64) } };
      },
    });
    const draft = {
      definition: {
        snapshot: "4000",
        request: {
          name: "",
          sources: ["10.0.0.1"],
          destination: "10.0.0.2",
          members: [{ name: "destination", addresses: ["10.0.0.2"] }],
          condition: { kind: "member", member: "destination" },
          success: "forward",
        },
      },
    } as unknown as AssessmentDraft;
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={client()}>
        <TraceConnectionActions
          draft={draft}
          onOpenAnalysis={() => undefined}
          onOpenApplication={() => undefined}
        />
      </QueryClientProvider>,
    );
    await user.click(screen.getByRole("button", { name: "Save connection" }));
    const field = screen.getByRole("textbox", { name: "Connection ID" });
    await user.clear(field);
    await user.type(field, "web-to-api");
    expect(field).toHaveValue("web-to-api");
    await user.click(screen.getByRole("button", { name: "Save connection draft" }));
    await waitFor(() => expect(sessions).toHaveLength(1));
    const input = (sessions[0].body as { input: { connections: Array<{ id: string }> } }).input;
    expect(input.connections[0].id).toBe("web-to-api");
  });
});

const APPLICATION: ApplicationRevision = {
  id: "checkout",
  revision: 2,
  name: "Checkout",
  digest: "2".repeat(64),
  created_by: 1,
  created_at: "2026-01-01T00:00:00Z",
  definition: {
    schema_version: 1,
    kind: "BusinessApplication",
    id: "checkout",
    name: "Checkout",
    state: "draft",
    services: [{ id: "front", name: "Front", connection_ids: ["web"], component_roles: [] }],
    groups: [],
    connections: [
      {
        id: "web",
        name: "Web",
        source: "a",
        destination: "b",
        protocol: "tcp",
        destination_ports: [443],
        success: "forward",
        destination_condition: { kind: "member", member: "b1", parts: [] },
      },
    ],
  },
} as ApplicationRevision;

function renderPage(open = vi.fn()) {
  render(
    <QueryClientProvider client={client()}>
      <MemoryRouter>
        <AuthProvider>
          <ApplicationsPage
            applicationId="checkout"
            onNavigate={() => undefined}
            onOpenAnalysis={open}
          />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return open;
}

describe("Applications page", () => {
  it("states why Analyze ready connections could not start", async () => {
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [APPLICATION] } }),
      "GET /api/business-applications/checkout": () => ({ body: { application: APPLICATION } }),
      "GET /api/snapshots": () => ({
        body: {
          snapshots: [{ id: "4000", ts_ms: 4000, kind: "full" }],
          current: 4000,
          truncated: false,
        },
      }),
      "POST /api/business-applications/checkout/resolve": () => ({
        body: {
          snapshot: { snapshot: "4000", manifest_sha256: "c".repeat(64), estate: "test" },
          digest: "r",
          ready: true,
          issues: [],
          connections: [
            {
              id: "web",
              service_id: "front",
              readiness: "ready",
              request: { name: "Web" },
              issues: [],
            },
          ],
        },
      }),
      "POST /api/analysis-sessions": () => ({
        status: 429,
        body: { detail: "at most 8 unfinished analyses per actor" },
      }),
    });
    const user = userEvent.setup();
    const open = renderPage();
    await user.click(await screen.findByRole("tab", { name: "Coverage" }));
    await screen.findByRole("option", { name: /\[full\]/ });
    await user.selectOptions(screen.getByLabelText("Coverage snapshot"), "4000");
    await user.click(await screen.findByRole("button", { name: "Analyze ready connections" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("429");
    expect(open).not.toHaveBeenCalled();
  });

  it("drops the stale preview after a conflict", async () => {
    const commits: MockRequest[] = [];
    mockApi({
      "GET /api/me": () => ({ body: ME_OPERATOR }),
      "GET /api/business-applications": () => ({ body: { applications: [APPLICATION] } }),
      "GET /api/snapshots": () => ({ body: { snapshots: [], current: null, truncated: false } }),
      "POST /api/business-applications/import/preview": () => ({
        body: {
          application_id: "checkout",
          base_revision: 2,
          base_digest: "2".repeat(64),
          result_digest: "3".repeat(64),
          preview_digest: "4".repeat(64),
          definition: {},
          changes: { connections_updated: ["web"] },
          mapping_issues: [],
          no_op: false,
        },
      }),
      "POST /api/business-applications/import/commit": (req) => {
        commits.push(req);
        return { status: 409, body: { detail: "conflict" } };
      },
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
    await waitFor(() => expect(screen.getByText("Import YAML").closest("details")).not.toHaveAttribute("open"));
    await user.click(screen.getByText("Import YAML"));
    await user.click(await screen.findByRole("textbox", { name: "Definition YAML" }));
    await user.paste("id: checkout\n");
    await user.click(screen.getByRole("button", { name: "Preview import" }));
    const preview = await screen.findByRole("region", { name: "Import preview" });
    await user.click(within(preview).getByRole("button", { name: "Commit revision" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Application changed after this preview",
    );
    expect(screen.queryByRole("region", { name: "Import preview" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Commit revision" })).not.toBeInTheDocument();
    expect(commits).toHaveLength(1);
    expect(screen.getByRole("textbox", { name: "Definition YAML" })).toHaveValue("id: checkout\n");
  });
});
