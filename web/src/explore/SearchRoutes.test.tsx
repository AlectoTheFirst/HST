import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi } from "../test/fetchMock";
import { SearchView } from "./SearchView";

const ROUTE = {
  device_uid: "dev:fdo2335abc",
  device: "leaf-a",
  vrf: "hosting",
  context_uid: "vrf:dev:fdo2335abc:hosting",
  prefix: "10.24.0.0/16",
  next_hop: "10.0.0.2",
  interface: "Eth1/1",
  protocol: "bgp",
  metric: 0,
};

function mount() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SearchView />
    </QueryClientProvider>,
  );
}

describe("search routes", () => {
  it("lists the routes of every device for an address the node search does not find", async () => {
    mockApi({
      "GET /api/explore/search": () => ({ body: { query: "10.24.0.0", items: [], total: 0, labels: [] } }),
      "GET /api/explore/route-search": () => ({ body: { query: "10.24.0.0", total: 1, items: [ROUTE] } }),
    });
    mount();
    await userEvent.setup().type(screen.getByRole("searchbox"), "10.24.0.0");

    const table = await screen.findByRole("table", { name: "Routes" });
    const row = within(table).getAllByRole("row")[1];
    expect(within(row).getByRole("button", { name: "leaf-a" })).toHaveAttribute("title", "dev:fdo2335abc");
    expect(row).toHaveTextContent("hosting");
    expect(row).toHaveTextContent("10.24.0.0/16");
    expect(row).toHaveTextContent("10.0.0.2 via Eth1/1");
    expect(screen.getByText("No matching nodes")).toBeInTheDocument();
  });

  it("does not look in the route tables for a name", async () => {
    mockApi({
      "GET /api/explore/search": () => ({ body: { query: "leaf", items: [], total: 0, labels: [] } }),
    });
    mount();
    await userEvent.setup().type(screen.getByRole("searchbox"), "leaf");

    await screen.findByText("No matching nodes");
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes("route-search"))).toBe(false);
  });
});
