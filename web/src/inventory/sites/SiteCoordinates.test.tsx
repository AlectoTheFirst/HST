import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockRequest } from "../../test/fetchMock";
import { InventorySitesPage } from "./SitesPage";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { username: "ada", permissions: ["graph.read", "sites.write"] }, loading: false }) }));

const site = { id: "7", code: "DCBER", name: "DC Berlin", location: "Berlin, Germany", lat: null, lon: null, revision: 3, device_count: 1, location_count: 0 };
const other = { ...site, id: "8", code: "DCFRA", name: "DC Frankfurt" };

function mount(entry = "/inventory/sites") {
  sessionStorage.clear();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>
    <Routes><Route path="/inventory/sites" element={<InventorySitesPage />} /></Routes>
  </MemoryRouter></QueryClientProvider>);
}

describe("site coordinates", () => {
  it("sets the map position from typed coordinates when no place data is loaded", async () => {
    const patches: unknown[] = [];
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, offset: 0, limit: 50 } }),
      "GET /api/geo-places": () => ({ body: { items: [], available: false } }),
      "PATCH /api/inventory/sites/7": (req: MockRequest) => {
        patches.push(req.body);
        return { body: { ...site, revision: 4 } };
      },
    });
    mount();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit DCBER" }));
    await user.type(screen.getByRole("textbox", { name: "Latitude" }), "52.53");
    expect(screen.getByText("No map position")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Longitude" }), "13.38");
    expect(screen.getByText(/Map position 52\.5300, 13\.3800/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { name: "DC Berlin", location: "Berlin, Germany", expected_revision: 3, lat: 52.53, lon: 13.38 },
    ]));
  });

  it("marks a coordinate out of range and sets no position", async () => {
    mockApi({ "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, offset: 0, limit: 50 } }) });
    mount();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit DCBER" }));
    const latitude = screen.getByRole("textbox", { name: "Latitude" });
    await user.type(latitude, "91");
    await user.type(screen.getByRole("textbox", { name: "Longitude" }), "8");
    expect(latitude).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("No map position")).toBeInTheDocument();
  });

  it("clearing the position empties both fields", async () => {
    mockApi({ "GET /api/inventory/sites/search": () => ({ body: { items: [{ ...site, lat: 52.53, lon: 13.38 }], total: 1, offset: 0, limit: 50 } }) });
    mount();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Edit DCBER" }));
    expect(screen.getByRole("textbox", { name: "Latitude" })).toHaveValue("52.53");
    await user.click(screen.getByRole("button", { name: "Clear map position" }));
    expect(screen.getByRole("textbox", { name: "Latitude" })).toHaveValue("");
    expect(screen.getByRole("textbox", { name: "Longitude" })).toHaveValue("");
  });

  it("a link with edit opens the editor of that site once, with the search set", async () => {
    const searches: string[] = [];
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [other, site], total: 2, offset: 0, limit: 50 } }),
    });
    const fetchSpy = vi.mocked(fetch);
    mount("/inventory/sites?q=DCBER&edit=DCBER");
    const user = userEvent.setup();
    expect(await screen.findByRole("heading", { name: "Edit DCBER" })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search sites" })).toHaveValue("DCBER");
    for (const [input] of fetchSpy.mock.calls) searches.push(new URL(String(input), "http://localhost").searchParams.get("q") ?? "");
    expect(searches).toContain("DCBER");
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(screen.queryByRole("heading", { name: "Edit DCBER" })).not.toBeInTheDocument();
  });
});
