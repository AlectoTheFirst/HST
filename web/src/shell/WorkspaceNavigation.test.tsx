import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Navigate, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "../auth";
import { InventoryLayout } from "../inventory/InventoryLayout";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN, ME_VIEWER } from "../test/fixtures";
import { TopBar } from "./TopBar";
import { AiDrawerProvider } from "../ai/drawer";

function mount(path: string, { active = true, viewer = false } = {}) {
  mockApi({
    "GET /api/me": () => ({ body: viewer ? ME_VIEWER : ME_ADMIN }),
    "GET /api/health": () => ({ body: { path: true, neo4j: true, postgres: true } }),
    "GET /api/inventory/state": () => ({ body: {
      activation_state: active ? "active" : "inactive",
      resolver_version: active ? 2 : 1,
    } }),
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <AiDrawerProvider><TopBar /></AiDrawerProvider>
          <Routes>
            <Route path="/" element={<p>Analysis content</p>} />
            <Route path="/inventory" element={<InventoryLayout />}>
              <Route index element={<Navigate to="devices" replace />} />
              <Route path="*" element={<p>Inventory content</p>} />
            </Route>
            <Route path="/settings/*" element={<p>Settings content</p>} />
            <Route path="/applications/*" element={<p>Applications content</p>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Workspace navigation", () => {
  it("switches between inventory and analysis for viewers", async () => {
    mount("/", { viewer: true });
    const user = userEvent.setup();
    const nav = within(await screen.findByRole("navigation", { name: "Workspaces" }));
    expect(nav.getByRole("link", { name: "Analysis" })).toHaveAttribute("aria-current", "page");
    await user.click(nav.getByRole("link", { name: "Inventory" }));
    expect(await screen.findByText("Inventory content")).toBeInTheDocument();
    expect(nav.getByRole("link", { name: "Inventory" })).toHaveClass("on");
    expect(nav.getByRole("link", { name: "Analysis" })).not.toHaveAttribute("aria-current");
    expect(screen.queryByRole("link", { name: "Connections" })).not.toBeInTheDocument();
    await user.click(nav.getByRole("link", { name: "Analysis" }));
    expect(await screen.findByText("Analysis content")).toBeInTheDocument();
    expect(nav.getByRole("link", { name: "Analysis" })).toHaveClass("on");
  });

  it.each([
    ["/inventory/devices/device-1?tab=collection", "Devices"],
    ["/inventory/sites", "Sites"],
    ["/inventory/connections/connection-1", "Connections"],
    ["/inventory/connections/profiles", "Connections"],
    ["/inventory/routing-groups", "Routing groups"],
  ])("keeps workspace and section selected at %s", async (path, section) => {
    mount(path);
    const workspace = within(await screen.findByRole("navigation", { name: "Workspaces" }));
    expect(workspace.getByRole("link", { name: "Inventory" })).toHaveClass("on");
    expect(workspace.getByRole("link", { name: "Inventory" })).toHaveAttribute("aria-current", "page");
    const inventory = within(screen.getByRole("navigation", { name: "Inventory" }));
    expect(inventory.getByRole("link", { name: section })).toHaveAttribute("aria-current", "page");
  });

  it("keeps both workspaces reachable from settings without selecting either", async () => {
    mount("/settings/users");
    const nav = within(await screen.findByRole("navigation", { name: "Workspaces" }));
    for (const link of nav.getAllByRole("link")) {
      expect(link).not.toHaveAttribute("aria-current");
      expect(link).not.toHaveClass("on");
    }
    expect(screen.getByRole("link", { name: "Settings" })).toHaveClass("on");
  });

  it("opens the applications page from the top bar", async () => {
    mount("/");
    const user = userEvent.setup();
    const nav = within(await screen.findByRole("navigation", { name: "Workspaces" }));
    expect(nav.getAllByRole("link").map((link) => link.textContent)).toEqual(["Analysis", "Inventory", "Applications"]);
    await user.click(nav.getByRole("link", { name: "Applications" }));
    expect(await screen.findByText("Applications content")).toBeInTheDocument();
    expect(nav.getByRole("link", { name: "Applications" })).toHaveAttribute("aria-current", "page");
  });

  it("preserves the activation gate on existing installations", async () => {
    mount("/", { active: false });
    await screen.findByRole("button", { name: ME_ADMIN.username });
    expect(screen.queryByRole("navigation", { name: "Workspaces" })).not.toBeInTheDocument();
  });
});
