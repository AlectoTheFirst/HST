/**
 * The palette finds the graph objects the Explore search finds, and opens
 * them in Explore's Search tab in the focused pane.
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
import { AiDrawerProvider } from "../ai/drawer";

const PREFIX = {
  snapshot: 1758283200000,
  node: {
    id: "4:x:7", uid: "pfx:blue/10.1.2.0/24", label: "Prefix", labels: ["Prefix", "Obj", "L3"], name: "10.1.2.0/24",
    properties: { uid: "pfx:blue/10.1.2.0/24", cidr: "10.1.2.0/24" }, bookkeeping: {},
  },
  neighbors: [],
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

describe("CommandPalette objects", () => {
  beforeEach(() => {
    installStorage();
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
      "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true } }),
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: { snapshots: [], current: null, truncated: false } }),
      "GET /api/explore/search": () => {
        return {
          body: {
            query: "10.1.2",
            total: 12,
            labels: [{ label: "Prefix", count: 12 }],
            items: [
              { uid: "pfx:blue/10.1.2.0/24", label: "Prefix", name: "10.1.2.0/24", detail: "", matched: "address" },
              { uid: "ip:blue/10.1.2.7", label: "IpAddress", name: "10.1.2.7", detail: "", matched: "address" },
            ],
          },
        };
      },
      "GET /api/explore/node": () => ({ body: PREFIX }),
    });
  });

  it("lists the objects the Explore search finds and opens one in Explore", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole("region", { name: "Trace pane" });
    await user.click(await screen.findByRole("button", { name: "Search" }));
    await user.type(screen.getByRole("combobox", { name: "Search views and queries" }), "10.1.2");
    const list = screen.getByRole("listbox");
    const prefix = await within(list).findByRole("option", { name: /10\.1\.2\.0\/24.*Prefix/ });
    expect(prefix).toHaveTextContent("pfx:blue/10.1.2.0/24");
    expect(within(list).getByRole("option", { name: /Open all 12 in Explore/ })).toBeInTheDocument();
    await user.click(prefix);
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Explore pane" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Search" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText("Search the graph")).toHaveValue("10.1.2");
    const panel = await screen.findByRole("region", { name: "Node details" });
    expect(await within(panel).findByRole("heading", { name: "10.1.2.0/24" })).toBeInTheDocument();
  });

  it("opens all of the matches in Explore's Search tab", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole("region", { name: "Trace pane" });
    await user.click(await screen.findByRole("button", { name: "Search" }));
    await user.type(screen.getByRole("combobox", { name: "Search views and queries" }), "10.1.2");
    await user.click(await screen.findByRole("option", { name: /Open all 12 in Explore/ }));
    expect(screen.getByRole("tab", { name: "Search" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText("Search the graph")).toHaveValue("10.1.2");
    expect(await screen.findByRole("button", { name: /10\.1\.2\.7/ })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Node details" })).not.toBeInTheDocument();
  });
});
