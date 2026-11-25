/**
 * The persistent rail.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { WorkspaceProvider, useWorkspace } from "../workspace/WorkspaceContext";
import { panes } from "../workspace/layout";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SideRail } from "./SideRail";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_VIEWER } from "../test/fixtures";
import type { QueryCatalog } from "../api/types";

const CATALOG: QueryCatalog = {
  queries: [
    { key: "overview", group: "inventory", title: "What is in the graph", cypher: "MATCH (n) RETURN n" },
    { key: "cabling", group: "topology", title: "Cabling (incl. derived)", cypher: "MATCH (a)-[c]-(b) RETURN a" },
  ],
};

/** Shows the focused pane's view and query, so clicks are observable. */
function PaneProbe() {
  const ws = useWorkspace();
  const focused = ws ? panes(ws.state.root).find((p) => p.id === ws.state.focus) : undefined;
  return <div data-testid="pane">{`${focused?.view} ${focused?.queryKey ?? ""}`.trim()}</div>;
}

function renderRail() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <WorkspaceProvider>
            <SideRail />
            <PaneProbe />
          </WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** This suite's jsdom runs on an opaque origin, where `window.localStorage` is
 *  undefined. */
function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
}

describe("SideRail", () => {
  beforeEach(installStorage);

  it("groups the catalog by topic and starts collapsed", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderRail();

    // topic headers, with a count, are what the rail shows at rest
    const inventory = await screen.findByRole("button", { name: /inventory/ });
    expect(inventory).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("button", { name: /topology/ })).toBeInTheDocument();

    // ...and the queries inside are not in the a11y tree until expanded
    expect(screen.queryByRole("button", { name: "What is in the graph" })).not.toBeInTheDocument();
  });

  it("shows an alert when the catalog does not load", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 500, body: { error: "graph not reachable" } }),
    });
    renderRail();

    expect(await screen.findByRole("alert")).toHaveTextContent("Queries not loaded");
  });

  it("expands a group to reveal its queries", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderRail();
    const user = userEvent.setup();

    const inventory = await screen.findByRole("button", { name: /inventory/ });
    await user.click(inventory);
    expect(inventory).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("button", { name: "What is in the graph" })).toBeInTheDocument();
    // an unrelated group stays shut
    expect(screen.queryByRole("button", { name: "Cabling (incl. derived)" })).not.toBeInTheDocument();
  });

  it("remembers which groups were open", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    const user = userEvent.setup();

    const first = renderRail();
    await user.click(await screen.findByRole("button", { name: /inventory/ }));
    first.unmount();

    renderRail();
    expect(await screen.findByRole("button", { name: /inventory/ })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });

  it("opens the picked query in the focused pane", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderRail();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /topology/ }));
    await user.click(screen.getByRole("button", { name: "Cabling (incl. derived)" }));
    expect(screen.getByTestId("pane")).toHaveTextContent("explore cabling");
  });
});

describe("map entry", () => {
  it("switches the focused pane", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    installStorage();
    const { WorkspaceProvider, useWorkspace } = await import("../workspace/WorkspaceContext");
    const { panes } = await import("../workspace/layout");

    function PaneProbe() {
      const ws = useWorkspace();
      const focused = ws ? panes(ws.state.root).find((p) => p.id === ws.state.focus) : undefined;
      return <div data-testid="pane-view">{focused?.view}</div>;
    }

    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <SideRail />
              <PaneProbe />
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const map = await screen.findByRole("button", { name: "Map" });
    expect(screen.getByTestId("pane-view")).toHaveTextContent("trace");
    await userEvent.setup().click(map);
    expect(screen.getByTestId("pane-view")).toHaveTextContent("map");
  });

});

describe("change simulation entry", () => {
  it("opens Analysis in the focused pane, and lists no separate Change simulation or Assessments entry", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    installStorage();
    const { WorkspaceProvider, useWorkspace } = await import("../workspace/WorkspaceContext");
    const { panes } = await import("../workspace/layout");

    function PaneProbe() {
      const ws = useWorkspace();
      const focused = ws ? panes(ws.state.root).find((p) => p.id === ws.state.focus) : undefined;
      return <div data-testid="pane-view">{focused?.view}</div>;
    }

    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <WorkspaceProvider>
              <SideRail />
              <PaneProbe />
            </WorkspaceProvider>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    // Change simulation and Assessments are sections of Analysis, not rail entries
    const entry = await screen.findByRole("button", { name: "Analysis" });
    expect(screen.queryByRole("button", { name: "Change simulation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Assessments" })).not.toBeInTheDocument();
    expect(screen.getByTestId("pane-view")).toHaveTextContent("trace");
    await userEvent.setup().click(entry);
    expect(screen.getByTestId("pane-view")).toHaveTextContent("analysis");
  });

});

describe("version text", () => {
  it("shows the running build's version at the foot of the rail", async () => {
    installStorage();
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "GET /api/health": () => ({
        status: 200,
        body: {
          path: true,
          neo4j: true,
          postgres: true,
          version: "0.9.0",
          revision: "0b0d31db9dc521c4cb2b1fe4685152b6a5a0bf8e",
        },
      }),
    });
    renderRail();
    expect(await screen.findByText("v0.9.0 0b0d31d")).toBeInTheDocument();
  });

  it("shows nothing when the health payload carries no version", async () => {
    installStorage();
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true } }),
    });
    renderRail();
    await screen.findByText("What is in the graph");
    expect(screen.queryByText(/^v\d/)).not.toBeInTheDocument();
  });
});

describe("SideRail sections and one open group", () => {
  beforeEach(installStorage);

  const SECTIONED: QueryCatalog = {
    queries: [
      ...CATALOG.queries,
      { key: "zpa-app-segment", group: "zscaler", section: "ZPA", title: "App segment", cypher: "RETURN 1" },
      { key: "zia-location", group: "zscaler", section: "ZIA", title: "Location", cypher: "RETURN 1" },
    ],
  };

  it("renders the section headings inside a group", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: SECTIONED }),
    });
    renderRail();
    await userEvent.setup().click(await screen.findByRole("button", { name: /zscaler/ }));
    expect(screen.getByRole("group", { name: "ZPA" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "ZIA" })).toBeInTheDocument();
  });

  it("opening a group closes the other open group", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderRail();
    const user = userEvent.setup();
    const inventory = await screen.findByRole("button", { name: /inventory/ });
    const topology = screen.getByRole("button", { name: /topology/ });
    await user.click(inventory);
    await user.click(topology);
    expect(topology).toHaveAttribute("aria-expanded", "true");
    expect(inventory).toHaveAttribute("aria-expanded", "false");
  });
});
