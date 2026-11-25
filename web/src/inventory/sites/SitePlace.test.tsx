import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockRequest } from "../../test/fetchMock";
import { InventorySitesPage } from "./SitesPage";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { username: "ada", permissions: ["graph.read", "sites.write"] }, loading: false }) }));

const site = { id: "7", code: "DCBER", name: "DC Berlin", location: "Berlin, Germany", lat: null, lon: null, revision: 3, device_count: 1, location_count: 0 };
const berlin = { country_code: "DE", postal_code: "10115", name: "Berlin", admin1: "Berlin", admin2: "", lat: 52.5323, lon: 13.3846 };

function mount() {
  sessionStorage.clear();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/inventory/sites"]}>
    <Routes><Route path="/inventory/sites" element={<InventorySitesPage />} /></Routes>
  </MemoryRouter></QueryClientProvider>);
}

describe("site geography lookup", () => {
  it("writes the chosen place and its map position into the site patch", async () => {
    const patches: unknown[] = [];
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, offset: 0, limit: 50 } }),
      "GET /api/geo-places": () => ({ body: { items: [berlin], available: true } }),
      "PATCH /api/inventory/sites/7": (req: MockRequest) => {
        patches.push(req.body);
        return { body: { ...site, revision: 4 } };
      },
    });
    mount();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit DCBER" }));
    expect(screen.getByText("No map position")).toBeInTheDocument();
    const field = screen.getByRole("combobox", { name: "Geography" });
    await user.clear(field);
    await user.type(field, "Berli");
    await user.click(await screen.findByRole("option", { name: "10115 Berlin, Berlin, Germany" }));
    expect(field).toHaveValue("10115 Berlin, Berlin, Germany");
    expect(screen.getByText(/Map position 52\.5323, 13\.3846/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { name: "DC Berlin", location: "10115 Berlin, Berlin, Germany", expected_revision: 3, lat: 52.5323, lon: 13.3846 },
    ]));
  });

  it("leaves the map position out of a patch that does not change it, and says when no place data is loaded", async () => {
    const patches: unknown[] = [];
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [{ ...site, lat: 52.53, lon: 13.38 }], total: 1, offset: 0, limit: 50 } }),
      "GET /api/geo-places": () => ({ body: { items: [], available: false } }),
      "PATCH /api/inventory/sites/7": (req: MockRequest) => {
        patches.push(req.body);
        return { body: { ...site, revision: 4 } };
      },
    });
    mount();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit DCBER" }));
    expect(screen.getByText(/Map position 52\.5300, 13\.3800/)).toBeInTheDocument();
    await user.type(screen.getByRole("combobox", { name: "Geography" }), " DC");
    expect(await screen.findByText("No place data")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { name: "DC Berlin", location: "Berlin, Germany DC", expected_revision: 3 },
    ]));
  });
});
