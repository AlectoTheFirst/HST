import { describe, it, expect } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ExplorePage from "./ExplorePage";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";
import type { QueryCatalog } from "../api/types";

const CATALOG: QueryCatalog = {
  queries: [
    { key: "overview", group: "inventory", title: "What is in the graph", cypher: "MATCH (n) RETURN n" },
    {
      key: "search",
      group: "inventory",
      title: "Search by name",
      cypher: "CALL db.index.fulltext.queryNodes(...) YIELD node RETURN node",
      params: [{ name: "q", label: "name or text", placeholder: "webshop" }],
    },
    { key: "cabling", group: "topology", title: "Cabling (incl. derived)", cypher: "MATCH (a)-[c]-(b) RETURN a" },
  ],
};

function renderExplore(queryKey?: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <ExplorePage queryKey={queryKey} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ExplorePage catalog", () => {
  it("owns no rail of its own", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderExplore();

    await screen.findByText("No result");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    expect(screen.queryByText("inventory")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "What is in the graph" })).not.toBeInTheDocument();
  });

  it("preselects the query that the pane names (the rail sets it)", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderExplore("search");

    expect(await screen.findByLabelText("name or text")).toBeInTheDocument();
  });

  it("opens on the ad-hoc editor for an operator when nothing is selected", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderExplore();

    expect(await screen.findByRole("form", { name: "Ad-hoc Cypher" })).toBeInTheDocument();
    expect(screen.queryByText(/pick a query from the catalog/i)).not.toBeInTheDocument();
  });

  it("shows no form when nothing is selected", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
    });
    renderExplore();

    expect(await screen.findByText("No result")).toBeInTheDocument();
    expect(screen.queryByRole("form")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("name or text")).not.toBeInTheDocument();
  });
});

describe("ExplorePage result state follows the selection", () => {
  function renderWithKey(queryKey: string) {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const page = (key: string) => (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/explore"]}>
          <AuthProvider>
            <ExplorePage queryKey={key} />
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>
    );
    const view = render(page(queryKey));
    return { ...view, setKey: (key: string) => view.rerender(page(key)) };
  }

  it("drops query A's rows when the pane switches to query B", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "POST /api/queries/overview": () => ({
        status: 200,
        body: { columns: ["name"], data: [{ row: ["core1"] }], truncated: false },
      }),
    });
    const user = userEvent.setup();
    const { setKey } = renderWithKey("overview");

    await user.click(await screen.findByRole("button", { name: "Run" }));
    expect(await screen.findByText("core1")).toBeInTheDocument();

    setKey("search");
    expect(await screen.findByLabelText("name or text")).toBeInTheDocument();
    // query A's rows must not sit under query B's form
    expect(screen.queryByText("core1")).not.toBeInTheDocument();
    expect(screen.getByText("No result")).toBeInTheDocument();
  });

  it("draws the graph under the table when the result carries entities", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "POST /api/queries/overview": () => ({
        status: 200,
        body: {
          columns: ["d"],
          data: [{ row: [{ hostname: "core1" }] }],
          truncated: false,
          graph: {
            nodes: [
              { id: "n1", labels: ["Device"], properties: { hostname: "core1" } },
              { id: "n2", labels: ["Device"], properties: { hostname: "edge1" } },
            ],
            relationships: [
              { id: "r1", type: "CABLED", start: "n1", end: "n2", properties: {} },
            ],
            truncated: false,
          },
        },
      }),
    });
    const user = userEvent.setup();
    renderWithKey("overview");

    await user.click(await screen.findByRole("button", { name: "Run" }));
    // the Tree view is the default; the canvas is the Canvas view
    expect(await screen.findByRole("tree", { name: "Result tree" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Canvas" }));
    expect(
      await screen.findByRole("img", { name: /2 nodes and 1 relationships/ }),
    ).toBeInTheDocument();
    expect(screen.getByText("CABLED")).toBeInTheDocument();
  });

  it("starts a new run with an empty selection", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "POST /api/queries/overview": () => ({
        status: 200,
        body: {
          columns: ["d"],
          data: [{ row: ["core1"], nodes: ["n1"] }],
          truncated: false,
          graph: { nodes: [{ id: "n1", labels: ["Device"], properties: { hostname: "core1" } }], relationships: [], truncated: false },
        },
      }),
    });
    const user = userEvent.setup();
    renderWithKey("overview");

    await user.click(await screen.findByRole("button", { name: "Run" }));
    await user.click(await screen.findByRole("button", { name: "Table" }));
    await user.click(screen.getByRole("cell", { name: "core1" }));
    expect(screen.getAllByRole("row")[1]).toHaveAttribute("aria-selected", "true");

    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getAllByRole("row")[1]).toHaveAttribute("aria-selected", "false"));
  });

  it("shows no graph for a result with no entities", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "POST /api/queries/overview": () => ({
        status: 200,
        body: {
          columns: ["n"],
          data: [{ row: [7] }],
          truncated: false,
          graph: { nodes: [], relationships: [], truncated: false },
        },
      }),
    });
    const user = userEvent.setup();
    const { container } = renderWithKey("overview");

    await user.click(await screen.findByRole("button", { name: "Run" }));
    expect(await screen.findByText("7")).toBeInTheDocument();
    expect(container.querySelector(".graphview")).toBeNull();
  });

  it("drops query A's error when the pane switches to query B", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "POST /api/queries/overview": () => ({
        status: 422,
        body: { error: "graph unavailable" },
      }),
    });
    const user = userEvent.setup();
    const { setKey } = renderWithKey("overview");

    await user.click(await screen.findByRole("button", { name: "Run" }));
    expect(await screen.findByText("graph unavailable")).toBeInTheDocument();

    setKey("search");
    expect(await screen.findByLabelText("name or text")).toBeInTheDocument();
    expect(screen.queryByText("graph unavailable")).not.toBeInTheDocument();
  });
});
