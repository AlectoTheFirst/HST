/**
 * Release scenario "Trace capture":
 * save a connection candidate from submitted trace inputs, choose an
 * application/service and create a revision; no service is inferred and no
 * scope is widened.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";
import TracePage from "../flowdesk/TracePage";
import { TraceConnectionActions } from "../applications/TraceConnectionActions";
import type { ApplicationRevision, BusinessApplicationDefinition } from "../applications/types";
import type { AssessmentDraft } from "../assessments/types";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { FIXTURE_PATH_SINGLE, FIXTURE_SNAPSHOTS } from "../test/fixtures";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";

const SNAPSHOT_ID = String(FIXTURE_SNAPSHOTS.current);
const REFERENCE = { snapshot: SNAPSHOT_ID, manifest_sha256: "c".repeat(64), estate: "test" };
const SRC = "192.168.10.44";
const DST = "8.8.8.8";
const CONNECTION_ID = "connection-192-168-10-44-to-8-8-8-8";

const DEFINITION: BusinessApplicationDefinition = {
  schema_version: 1, kind: "BusinessApplication", id: "checkout", name: "Checkout", state: "draft",
  services: [
    { id: "storefront", name: "Storefront", connection_ids: ["web-to-api"], component_roles: [] },
    { id: "payments", name: "Payments", connection_ids: [], component_roles: [] },
  ],
  groups: [
    { id: "web", name: "Web", members: [{ id: "web-1", address: "10.20.0.10" }] },
    { id: "api", name: "API", members: [{ id: "api-1", address: "10.30.0.10" }] },
  ],
  connections: [{ id: "web-to-api", name: "Web to API", source: "web", destination: "api", protocol: "tcp", destination_ports: [8443], success: "forward", destination_condition: { kind: "member", member: "api-1", parts: [] } }],
} as BusinessApplicationDefinition;

const APPLICATION: ApplicationRevision = { id: "checkout", revision: 3, name: "Checkout", digest: "d".repeat(64), created_by: 1, created_at: "2026-01-01T00:00:00Z", definition: DEFINITION };

interface Recorded { sessions: MockRequest[]; catalogWrites: MockRequest[] }

function routes(recorded: Recorded) {
  const write = (req: MockRequest) => { recorded.catalogWrites.push(req); return { body: { ...APPLICATION, revision: 4 } }; };
  mockApi({
    "GET /api/queries": () => ({ body: { queries: [] } }),
    "GET /api/snapshots": () => ({ body: FIXTURE_SNAPSHOTS }),
    "GET /api/path/vrfs": () => ({ body: { vrfs: [] } }),
    "GET /api/path": () => ({ body: FIXTURE_PATH_SINGLE }),
    "GET /api/analysis-snapshot": () => ({ body: REFERENCE }),
    "POST /api/analysis-sessions": (req) => { recorded.sessions.push(req); return { status: 201, body: { id: "trace-draft-1", revision: 1, input_digest: "e".repeat(64) } }; },
    "GET /api/business-applications": () => ({ body: { applications: [APPLICATION] } }),
    "GET /api/business-applications/checkout": () => ({ body: { application: APPLICATION } }),
    "PUT /api/business-applications/checkout": write,
    "POST /api/business-applications": write,
    "POST /api/business-applications/import/commit": write,
  });
}

function renderTrace() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <WorkspaceProvider>
          <TracePage />
        </WorkspaceProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Submit a trace of SRC to DST tcp/443 at the pinned snapshot and open the
 *  Save connection popover. */
async function traceAndOpen() {
  const user = userEvent.setup();
  renderTrace();
  const source = screen.getByRole("textbox", { name: "Source" });
  await user.clear(source); await user.type(source, SRC);
  const destination = screen.getByRole("textbox", { name: "Destination" });
  await user.clear(destination); await user.type(destination, DST);
  const port = screen.getByRole("textbox", { name: "Port" });
  await user.clear(port); await user.type(port, "443");
  await user.selectOptions(screen.getByRole("combobox", { name: "Protocol" }), "tcp");
  await waitFor(() => expect(within(screen.getByRole("combobox", { name: "Snapshot" })).getAllByRole("option").length).toBeGreaterThan(1));
  await user.selectOptions(screen.getByRole("combobox", { name: "Snapshot" }), SNAPSHOT_ID);
  await user.click(screen.getByRole("button", { name: /^Trace/ }));
  await user.click(await screen.findByRole("button", { name: "Advanced options" }));
  await user.click(await screen.findByRole("button", { name: "Save connection" }));
  return { user, dialog: screen.getByRole("dialog", { name: "Save trace connection" }) };
}

describe("Trace capture", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  it("saves the submitted trace as an inline Analysis session and writes nothing to the catalog", async () => {
    const recorded: Recorded = { sessions: [], catalogWrites: [] };
    routes(recorded);
    const { user, dialog } = await traceAndOpen();

    await user.click(within(dialog).getByRole("button", { name: "Save connection draft" }));

    await waitFor(() => expect(window.location.search).toBe("?analysis=trace-draft-1"));
    expect(recorded.sessions).toHaveLength(1);
    const input = (recorded.sessions[0].body as { input: Record<string, unknown> }).input;
    expect(input).toMatchObject({ kind: "connection", snapshot: REFERENCE, changes: [] });
    const connections = input.connections as Array<{ id: string; source: { kind: string; request: Record<string, unknown> } }>;
    expect(connections).toHaveLength(1);
    expect(connections[0].id).toBe(CONNECTION_ID);
    expect(connections[0].source.kind).toBe("inline");
    expect(connections[0].source.request).toMatchObject({
      sources: [SRC],
      destination: DST,
      members: [{ name: "destination", addresses: [DST] }],
      proto: "tcp",
      port: "443",
    });
    // no catalog service or application is created or revised
    expect(recorded.catalogWrites).toHaveLength(0);
    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("adds the connection only to the chosen application and service, with endpoints from the submitted source and destination", async () => {
    const recorded: Recorded = { sessions: [], catalogWrites: [] };
    routes(recorded);
    const { user, dialog } = await traceAndOpen();
    const add = within(dialog).getByRole("button", { name: "Add connection to service" });

    // nothing is chosen for the user
    expect(within(dialog).getByRole("combobox", { name: "Business application" })).toHaveValue("");
    expect(within(dialog).getByRole("combobox", { name: "Service" })).toHaveValue("");
    expect(add).toBeDisabled();
    await within(dialog).findByRole("option", { name: "Checkout" });
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Business application" }), "checkout");
    expect(add).toBeDisabled();
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Service" }), "payments");
    expect(add).toBeEnabled();
    await user.click(add);

    await waitFor(() => expect(window.location.search).toBe("?application=checkout"));
    expect(recorded.sessions).toHaveLength(0);
    expect(recorded.catalogWrites).toHaveLength(1);
    expect(recorded.catalogWrites[0].method).toBe("PUT");
    const body = recorded.catalogWrites[0].body as { definition: BusinessApplicationDefinition; expected_revision: number; source: string };
    expect(body.expected_revision).toBe(3);
    expect(body.source).toBe("trace");

    // a new revision: the existing entities are kept and two endpoint groups are appended
    const { definition } = body;
    expect(definition.groups.slice(0, 2)).toEqual(DEFINITION.groups);
    const added = definition.groups.slice(2);
    expect(added).toHaveLength(2);
    // the endpoint members are exactly the submitted source and destination,
    // never a transit hop of the returned path
    const addresses = added.flatMap((group) => group.members.map((member) => member.address));
    expect(addresses).toEqual([SRC, DST]);
    const transit = FIXTURE_PATH_SINGLE.hops.filter((hop) => hop.kind !== "Endpoint").map((hop) => hop.uid);
    expect(transit).toContain("dev:core1");
    for (const uid of transit) expect(JSON.stringify(definition)).not.toContain(uid);
    for (const group of added) for (const member of group.members) expect(member.inventory ?? null).toBeNull();

    // one connection, between those two groups, with the submitted traffic
    expect(definition.connections.slice(0, 1)).toEqual(DEFINITION.connections);
    expect(definition.connections).toHaveLength(2);
    expect(definition.connections[1]).toMatchObject({ id: CONNECTION_ID, source: added[0].id, destination: added[1].id, protocol: "tcp", destination_ports: [443] });

    // only the chosen service gains the connection; nothing else is inferred
    expect(definition.services).toEqual([
      DEFINITION.services[0],
      { ...DEFINITION.services[1], connection_ids: [CONNECTION_ID] },
    ]);
  });
});

describe("Trace capture refuses to widen scope", () => {
  const draft = (members: Array<{ name: string; addresses: string[] }>): AssessmentDraft => ({
    title: "Clients to API",
    kind: "troubleshoot",
    definition: {
      snapshot: SNAPSHOT_ID, mode: "possible", freshness_s: 86400, intents: [],
      request: {
        name: "Clients to API", destination: "API", sources: ["10.1.0.0/24"], members,
        condition: { kind: "member", member: members[0].name }, proto: "tcp", port: "443", success: "forward",
      },
    },
  });

  it("does not add a destination member with 2 addresses to the catalog", async () => {
    const recorded: Recorded = { sessions: [], catalogWrites: [] };
    routes(recorded);
    const opened: string[] = [];
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TraceConnectionActions draft={draft([{ name: "api", addresses: ["10.30.0.10", "10.30.0.11"] }])} onOpenAnalysis={() => undefined} onOpenApplication={(id) => opened.push(id)} />
      </QueryClientProvider>,
    );
    await user.click(screen.getByRole("button", { name: "Save connection" }));
    await screen.findByRole("option", { name: "Checkout" });
    await user.selectOptions(screen.getByRole("combobox", { name: "Business application" }), "checkout");
    await user.selectOptions(screen.getByRole("combobox", { name: "Service" }), "storefront");
    await user.click(screen.getByRole("button", { name: "Add connection to service" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("multiple addresses");
    expect(recorded.catalogWrites).toHaveLength(0);
    expect(opened).toEqual([]);
  });
});
