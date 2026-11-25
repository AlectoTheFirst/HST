/**
 * The map's object search: a device found from the estate opens the site it
 * is located in and is selected there. The stand-ins follow
 * NetworkMapPage.test.tsx: the bundled ELK engine for the worker, and a size
 * for the stage.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { TopologyModel } from "../api/types";
import NetworkMapPage from "./NetworkMapPage";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
vi.mock("../api/client", () => ({
  api: apiMock,
  ApiError: class ApiError extends Error {},
}));
vi.mock("./elk", async () => {
  const ELK = (await import("elkjs/lib/elk.bundled.js")).default;
  const engine = new ELK();
  return { layout: (graph: object) => engine.layout(graph as never) };
});

const MODEL: TopologyModel = {
  snapshot: 7,
  nodes: [
    { id: "site:ber1", kind: "site", parent: null, label: "ber1" },
    { id: "block:ber1:campus", kind: "block", parent: "site:ber1", label: "Campus", block_kind: "campus" },
    { id: "rth-01", kind: "device", parent: "block:ber1:campus", label: "rth-01", tier: "core", role: "router", role_basis: "hostname", block_basis: "tier", depth: 0, partition: 0 },
    { id: "swc-01", kind: "device", parent: "block:ber1:campus", label: "swc-01", tier: "core", role: "router", role_basis: "hostname", block_basis: "tier", depth: 1, partition: 0 },
  ],
  cables: [{ id: "c1", from: { dev: "rth-01", port: "GE1" }, to: { dev: "swc-01", port: "Eth1/1" }, source: "lldp", lateral: false }],
  exits: [],
  lags: [],
  split_groups: [],
};

const ESTATE = {
  sites: [{ code: "ber1", name: "Berlin 1", lat: 52.52, lon: 13.4, devices: 2, kind: null, tiers: { core: 2 }, exits: [] }],
  edges: [],
  unplaced: [],
};

const FOUND = {
  query: "swc",
  items: [{ uid: "swc-01", label: "Device", name: "swc-01", detail: "", matched: "text" }],
  total: 1,
  labels: [{ label: "Device", count: 1 }],
  mode: "text",
  snapshot: 7,
  kinds: [{ kind: "device", count: 1, count_exact: true }],
  groups: {
    device: {
      items: [
        {
          kind: "device", key: "swc-01", uid: "swc-01", name: "swc-01", detail: "", source: "graph", matched: "text",
          run: 7, source_run: null, target: { kind: "device", uid: "swc-01" }, fields: {},
        },
      ],
      next_cursor: null,
    },
  },
  side_store: { available: true, approximate: false, capped: [], timed_out: [] },
};

const SIZE = { width: 900, height: 520 };
const original = {
  width: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth"),
  height: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight"),
};

beforeAll(() => {
  Object.defineProperties(HTMLElement.prototype, {
    clientWidth: { configurable: true, get: () => SIZE.width },
    clientHeight: { configurable: true, get: () => SIZE.height },
  });
});

afterAll(() => {
  if (original.width) Object.defineProperty(HTMLElement.prototype, "clientWidth", original.width);
  if (original.height) Object.defineProperty(HTMLElement.prototype, "clientHeight", original.height);
});

describe("the map's object search", () => {
  it("opens the site of a device found from the estate and selects the device there", async () => {
    apiMock.mockImplementation((path: string) => {
      if (path === "/sites") return Promise.resolve({ sites: [{ code: "ber1", name: "Berlin 1" }] });
      if (path === "/sites/graph") return Promise.resolve(ESTATE);
      if (path === "/network-map/views") return Promise.resolve({ views: [] });
      if (path.startsWith("/explore/search?")) return Promise.resolve(FOUND);
      if (path.startsWith("/explore/neighbors?")) return Promise.resolve({ total: 1, offset: 0, limit: 1, items: [{ uid: "site:ber1", label: "Site", name: "Berlin 1" }] });
      if (path === "/topology?site=ber1") return Promise.resolve(MODEL);
      if (path === "/network-map/layouts/site/ber1")
        return Promise.resolve({ scope: "site/ber1", positions: {}, revision: 0, updated_by: null, updated_at: null });
      return Promise.reject(new Error(`unexpected ${path}`));
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <NetworkMapPage />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await user.type(screen.getByRole("searchbox", { name: "Search the map" }), "swc");
    const results = await screen.findByRole("list", { name: "Search results" });
    await user.click(within(results).getByRole("button", { name: /swc-01/ }));

    const panel = await screen.findByRole("complementary", { name: "Device details" });
    expect(within(panel).getByText("router, from the hostname")).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search the map" })).toHaveValue("");
    const asked = apiMock.mock.calls.map(([path]) => String(path));
    expect(asked.some((p) => p.startsWith("/explore/search?") && p.includes("typed=true") && p.includes("kind=segment"))).toBe(true);
    expect(asked.some((p) => p.startsWith("/explore/neighbors?") && p.includes("uid=swc-01") && p.includes("type=LOCATED_IN"))).toBe(true);
    expect(asked).toContain("/topology?site=ber1");
  });
});
