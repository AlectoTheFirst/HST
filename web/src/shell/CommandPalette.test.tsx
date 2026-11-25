/**
 * The palette acts on the focused pane: a view entry switches its view, a
 * catalog entry opens Explore on that query, and typed text becomes the
 * parameter of the matching lookup query.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TopBar } from "./TopBar";
import { Workspace } from "../workspace/Workspace";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_VIEWER } from "../test/fixtures";
import type { QueryCatalog } from "../api/types";
import { AiDrawerProvider } from "../ai/drawer";

const CATALOG: QueryCatalog = {
  queries: [
    { key: "overview", group: "inventory", title: "What is in the graph", cypher: "MATCH (n) RETURN n" },
    {
      key: "search",
      group: "inventory",
      title: "Search by name",
      params: [{ name: "q", label: "name or text" }],
      cypher: "MATCH (n) RETURN n",
    },
    {
      key: "find-ip",
      group: "endpoints",
      title: "Where is this IP",
      params: [{ name: "ip", label: "IP address" }],
      cypher: "MATCH (n) RETURN n",
    },
  ],
};

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

function renderShell() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <WorkspaceProvider>
            <AiDrawerProvider><TopBar /></AiDrawerProvider>
            <Workspace />
          </WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("CommandPalette", () => {
  beforeEach(() => {
    installStorage();
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true } }),
      "GET /api/queries": () => ({ status: 200, body: CATALOG }),
      "GET /api/snapshots": () => ({ status: 200, body: { snapshots: [], current: null, truncated: false } }),
    });
  });

  it("opens from the search field and lists views and catalog queries", async () => {
    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole("button", { name: "Search" }));
    const list = await screen.findByRole("listbox");
    expect(within(list).getByRole("option", { name: /^Map/ })).toBeInTheDocument();
    expect(await within(list).findByRole("option", { name: /What is in the graph/ })).toBeInTheDocument();
  });

  it("switches the focused pane to a view on Enter", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole("region", { name: "Trace pane" });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByRole("combobox", { name: "Search views and queries" }), "explore{Enter}");
    expect(screen.getByRole("region", { name: "Explore pane" })).toBeInTheDocument();
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  });

  it("opens the address lookup with the typed address filled in", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole("region", { name: "Trace pane" });
    await user.click(await screen.findByRole("button", { name: "Search" }));
    await screen.findByRole("option", { name: /What is in the graph/ });
    await user.type(screen.getByRole("combobox", { name: "Search views and queries" }), "10.0.0.1");
    const first = screen.getAllByRole("option")[0];
    expect(first).toHaveTextContent("Where is this IP: 10.0.0.1");
    await user.keyboard("{Enter}");
    const form = await screen.findByRole("form", { name: "Where is this IP" });
    expect(within(form).getByLabelText("IP address")).toHaveValue("10.0.0.1");
  });

  it("offers the name search for other text", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole("region", { name: "Trace pane" });
    await user.click(await screen.findByRole("button", { name: "Search" }));
    await screen.findByRole("option", { name: /What is in the graph/ });
    await user.type(screen.getByRole("combobox", { name: "Search views and queries" }), "webshop");
    expect(screen.getAllByRole("option")[0]).toHaveTextContent("Search by name: webshop");
    await user.keyboard("{Enter}");
    const form = await screen.findByRole("form", { name: "Search by name" });
    expect(within(form).getByLabelText("name or text")).toHaveValue("webshop");
  });

  it("closes on Escape without changing the pane", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole("region", { name: "Trace pane" });
    await user.keyboard("{Control>}k{/Control}");
    await screen.findByRole("listbox");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Trace pane" })).toBeInTheDocument();
  });
});

describe("CommandPalette keywords", () => {
  beforeEach(() => {
    installStorage();
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true } }),
      "GET /api/queries": () => ({
        status: 200,
        body: {
          queries: [
            ...CATALOG.queries,
            {
              key: "zpa-app-group",
              group: "zscaler",
              section: "ZPA",
              title: "Segment group",
              keywords: ["segment group", "SCIM group"],
              cypher: "RETURN 1",
            },
          ],
        },
      }),
      "GET /api/snapshots": () => ({ status: 200, body: { snapshots: [], current: null, truncated: false } }),
    });
  });

  it("finds an entry by a keyword and shows its section", async () => {
    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole("button", { name: "Search" }));
    await user.type(screen.getByRole("combobox", { name: "Search views and queries" }), "scim");
    const list = await screen.findByRole("listbox");
    const option = await within(list).findByRole("option", { name: /Segment group/ });
    expect(option.textContent).toContain("ZPA");
  });
});

describe("CommandPalette vendor views", () => {
  function withProducts(products: string[] | undefined) {
    installStorage();
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true } }),
      "GET /api/queries": () => ({ status: 200, body: { ...CATALOG, ...(products ? { products } : {}) } }),
      "GET /api/snapshots": () => ({ status: 200, body: { snapshots: [], current: null, truncated: false } }),
    });
  }

  it("hides the SD-WAN and Equinix views when the run holds no data for them", async () => {
    withProducts(["zia"]);
    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole("button", { name: "Search" }));
    const list = await screen.findByRole("listbox");
    await within(list).findByRole("option", { name: /What is in the graph/ });
    expect(within(list).queryByRole("option", { name: /^SD-WAN/ })).not.toBeInTheDocument();
    expect(within(list).queryByRole("option", { name: /^Equinix Fabric/ })).not.toBeInTheDocument();
    expect(within(list).getByRole("option", { name: /^Map/ })).toBeInTheDocument();
  });

  it("keeps every view when the catalog does not say which products hold data", async () => {
    withProducts(undefined);
    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole("button", { name: "Search" }));
    const list = await screen.findByRole("listbox");
    await within(list).findByRole("option", { name: /What is in the graph/ });
    expect(within(list).getByRole("option", { name: /^SD-WAN/ })).toBeInTheDocument();
    expect(within(list).getByRole("option", { name: /^Equinix Fabric/ })).toBeInTheDocument();
  });
});
