/**
 * The source list is split by kind: Groups shows the rows that carry a device
 * list, Orchestrators shows the rows that discover their own devices.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import GroupsPage from "./GroupsPage";
import OrchestratorsPage from "./OrchestratorsPage";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN, SCHEMA_UNIFI, SOURCE_UNIFI } from "../test/fixtures";
import type { Source, SourceTypeSchema } from "../api/types";
import fixtures from "./schema.fixtures.json";

const NXOS_SCHEMA = fixtures.nxos as unknown as SourceTypeSchema;

const EDGE_GROUP: Source = {
  name: "dc1-edge",
  type: "nxos",
  kind: "group",
  config: { site_code: "dc1", interval_s: 60 },
  secrets: {},
  enabled: true,
  updated_at: null,
};

function renderPage(page: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>{page}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function routes() {
  return {
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/source-types": () => ({
      status: 200,
      body: {
        types: [
          { type: "unifi", kind: "orchestrator", schema: SCHEMA_UNIFI },
          { type: "nxos", kind: "group", schema: NXOS_SCHEMA },
        ],
      },
    }),
    "GET /api/sources": () => ({ status: 200, body: { sources: [SOURCE_UNIFI, EDGE_GROUP] } }),
  };
}

describe("the settings pages split the source list by kind", () => {
  it("lists only groups on Groups", async () => {
    mockApi(routes());
    renderPage(<GroupsPage />);

    expect(await screen.findByText("dc1-edge")).toBeInTheDocument();
    expect(screen.queryByText(SOURCE_UNIFI.name)).not.toBeInTheDocument();
  });

  it("lists only orchestrators on Orchestrators", async () => {
    mockApi(routes());
    renderPage(<OrchestratorsPage />);

    expect(await screen.findByText(SOURCE_UNIFI.name)).toBeInTheDocument();
    expect(screen.queryByText("dc1-edge")).not.toBeInTheDocument();
  });

  it("offers only group types when adding a group", async () => {
    mockApi(routes());
    renderPage(<GroupsPage />);

    await screen.findByText("dc1-edge");
    expect(screen.getByRole("button", { name: /add group/i })).toBeInTheDocument();
  });

  it("shows a group's polling cadence", async () => {
    mockApi(routes());
    renderPage(<GroupsPage />);

    expect(await screen.findByText("polls every 60s")).toBeInTheDocument();
    expect(screen.getAllByText(/polls every/)).toHaveLength(1);
  });
});
