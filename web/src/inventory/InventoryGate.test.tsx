import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN } from "../test/fixtures";
import { InventoryGate, InventoryRedirect } from "./InventoryGate";

function Location() {
  const location = useLocation();
  return <p>{location.pathname}{location.search}</p>;
}

function mount(active: boolean, redirect = false) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/inventory/state": () => ({ status: 200, body: {
      resolver_version: active ? 2 : 1,
      activation_state: active ? "active" : "inactive",
      inventory_sync_pending: active,
    } }),
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={["/settings/groups?q=branch"]}><AuthProvider>
      <Routes>
        <Route path="/settings/groups" element={redirect
          ? <InventoryRedirect to="/inventory/connections?kind=direct"><p>Legacy groups</p></InventoryRedirect>
          : <InventoryGate><p>Device inventory</p></InventoryGate>} />
        <Route path="/inventory/connections" element={<Location />} />
      </Routes>
    </AuthProvider></MemoryRouter>
  </QueryClientProvider>);
}

describe("inventory activation", () => {
  it("does not render the new workspace before activation", async () => {
    mount(false);
    expect(await screen.findByRole("heading", { name: "Inventory not activated" })).toBeInTheDocument();
    expect(screen.queryByText("Device inventory")).not.toBeInTheDocument();
  });
  it("shows the active workspace and pending publication separately", async () => {
    mount(true);
    expect(await screen.findByText("Device inventory")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Inventory publication pending");
  });
  it("preserves legacy bookmarks until activation", async () => {
    mount(false, true);
    expect(await screen.findByText("Legacy groups")).toBeInTheDocument();
  });
  it("redirects activated bookmarks while preserving query parameters", async () => {
    mount(true, true);
    expect(await screen.findByText("/inventory/connections?q=branch&kind=direct")).toBeInTheDocument();
  });
});
