import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ExplorePage from "./ExplorePage";
import { QueryForm } from "./QueryForm";
import { AuthProvider } from "../auth";
import { mockApi, type MockRequest } from "../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";

const NODE = {
  snapshot: 1758283200000,
  node: {
    id: "4:x:1", uid: "dev:1", label: "Device", labels: ["Device", "Obj", "Phys"], name: "edge1",
    properties: { uid: "dev:1", hostname: "edge1", platform: "vyos" }, bookkeeping: { _sources: ["lab"] },
  },
  neighbors: [{ type: "ON", direction: "in", label: "Interface", count: 60 }],
};
const IFACE = {
  snapshot: 1758283200000,
  node: { id: "4:x:2", uid: "dev:1/if/eth0", label: "Interface", labels: ["Interface", "Obj", "L2"], name: "eth0", properties: { uid: "dev:1/if/eth0", name: "eth0" }, bookkeeping: {} },
  neighbors: [],
};
const STATS = {
  snapshot: 1758283200000,
  total_nodes: 1234,
  labels: [{ label: "Interface", count: 1200, layers: ["L2"], doc: "" }, { label: "Device", count: 34, layers: ["Phys"], doc: "" }],
  layers: [{ layer: "L2", count: 1200 }, { layer: "Phys", count: 34 }],
  devices: { total: 34, by_vendor: [{ value: "cisco", count: 30 }, { value: "unknown", count: 4 }], by_platform: [], by_role: [{ value: "router", count: 34 }] },
};
const LABEL = {
  label: "Device", layers: ["Phys"], doc: "", count: 34, sampled: false,
  properties: [{ name: "hostname", share: 1 }, { name: "serial", share: 0.5 }],
  relationships: [{ type: "LOCATED_IN", direction: "out", other: "Site", count: 34 }],
  examples: [{ uid: "dev:1", name: "edge1" }],
  cypher: "MATCH (n:Device)\nRETURN n\nLIMIT 25",
};

const ROUTE = (prefix: string, prefixlen: number, protocol: string, next_hop = "10.0.0.3") => ({
  vrf: "blue", context_uid: "vrf:1:blue", prefix, next_hop, next_hop_context_uid: null, interface: "eth0",
  protocol, discard: null, metric: 1, prefixlen, af: 4,
});

function setup(me = ME_VIEWER, extra: Record<string, (req: MockRequest) => { status?: number; body?: unknown }> = {}) {
  const calls: string[] = [];
  mockApi({
    "GET /api/me": () => ({ body: me }),
    "GET /api/queries": () => ({ body: { queries: [] } }),
    "GET /api/explore/search": () => ({ body: { query: "edge", total: 1, labels: [{ label: "Device", count: 1 }], items: [{ uid: "dev:1", label: "Device", name: "edge1", detail: "vyos", matched: "text" }] } }),
    "GET /api/explore/node": () => {
      const url = String(vi.mocked(fetch).mock.calls.at(-1)?.[0]);
      return { body: url.includes("eth0") ? IFACE : NODE };
    },
    "GET /api/explore/neighbors": () => {
      calls.push(String(vi.mocked(fetch).mock.calls.at(-1)?.[0]));
      const offset = calls.filter((c) => c.includes("/neighbors")).length === 1 ? 0 : 50;
      return { body: { total: 60, offset, limit: 50, items: offset === 0 ? [{ uid: "dev:1/if/eth0", label: "Interface", name: "eth0" }] : [{ uid: "dev:1/if/eth9", label: "Interface", name: "eth9" }], graph: { nodes: [], relationships: [], truncated: false } } };
    },
    "GET /api/explore/routes": () => {
      const url = String(vi.mocked(fetch).mock.calls.at(-1)?.[0]);
      calls.push(url);
      // the server marks the longest match of each table before the protocol filter
      const rows = url.includes("address=10.1.2.7") && url.includes("protocol=ospf")
        ? [{ ...ROUTE("10.1.0.0/16", 16, "ospf"), longest: false }]
        : url.includes("address=10.1.2.7")
        ? [{ ...ROUTE("10.1.2.0/24", 24, "bgp"), longest: true }, { ...ROUTE("10.1.2.0/24", 24, "bgp", "10.0.0.4"), longest: true }, { ...ROUTE("10.1.0.0/16", 16, "ospf"), longest: false }]
        : [ROUTE("0.0.0.0/0", 0, "static"), ROUTE("10.1.0.0/16", 16, "ospf"), ROUTE("10.1.2.0/24", 24, "bgp")];
      return { body: { available: true, approximate: false, coverage: "complete", device_uid: "dev:1", context_uid: null, run_id: "r1", total: rows.length, offset: 0, limit: 50, protocols: [{ protocol: "bgp", count: 1 }, { protocol: "ospf", count: 1 }], items: rows } };
    },
    "GET /api/explore/stats": () => ({ body: STATS }),
    "GET /api/explore/labels/Device": () => ({ body: LABEL }),
    ...extra,
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/explore"]}><AuthProvider><ExplorePage /></AuthProvider></MemoryRouter>
    </QueryClientProvider>,
  );
  return calls;
}

describe("Explore search", () => {
  it("finds a node, opens it, pages a relationship group and follows a neighbor", async () => {
    const calls = setup();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Search" }));
    await user.type(screen.getByLabelText("Search the graph"), "edge");
    await user.click(await screen.findByRole("button", { name: /edge1/ }));
    const panel = await screen.findByRole("region", { name: "Node details" });
    expect(await within(panel).findByRole("heading", { name: "edge1" })).toBeInTheDocument();
    expect(within(panel).getByText("vyos")).toBeInTheDocument();
    expect(within(panel).getByText("Loader bookkeeping")).toBeInTheDocument();
    await user.click(within(panel).getByRole("button", { name: /ON from Interface/ }));
    expect(await within(panel).findByRole("button", { name: "eth0" })).toBeInTheDocument();
    const neighborCalls = () => calls.filter((c) => c.includes("/neighbors"));
    expect(neighborCalls()[0]).toContain("type=ON");
    expect(neighborCalls()[0]).toContain("direction=in");
    await user.click(within(panel).getByRole("button", { name: "Show 50 more" }));
    expect(await within(panel).findByRole("button", { name: "eth9" })).toBeInTheDocument();
    expect(neighborCalls()[1]).toContain("offset=1");
    await user.click(within(panel).getByRole("button", { name: "eth0" }));
    const next = await screen.findByRole("region", { name: "Node details" });
    expect(await within(next).findByRole("heading", { name: "eth0" })).toBeInTheDocument();
    await user.click(within(next).getByRole("button", { name: "Back" }));
    expect(await screen.findByRole("heading", { name: "edge1" })).toBeInTheDocument();
  });

  it("opens on the queries view and, for an operator, on the editor", async () => {
    setup(ME_OPERATOR);
    expect(await screen.findByRole("tab", { name: "Queries" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByLabelText("Cypher query")).toBeInTheDocument();
  });
});

describe("Explore routes", () => {
  it("lists a device's routes from the side store and marks the longest match for an address", async () => {
    const calls = setup();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Search" }));
    await user.type(screen.getByLabelText("Search the graph"), "edge");
    await user.click(await screen.findByRole("button", { name: /edge1/ }));
    const routes = await screen.findByRole("region", { name: "Routes" });
    expect(await within(routes).findByText("0.0.0.0/0")).toBeInTheDocument();
    expect(within(routes).getByRole("columnheader", { name: "VRF" })).toBeInTheDocument();
    expect(within(routes).queryByText("Longest match")).not.toBeInTheDocument();
    await user.type(within(routes).getByLabelText("Longest match for address"), "10.1.2.7");
    expect(await within(routes).findAllByText("Longest match")).toHaveLength(2);
    expect(calls.some((c) => c.includes("/routes") && c.includes("uid=dev%3A1") && c.includes("address=10.1.2.7"))).toBe(true);
    await user.click(within(routes).getByRole("button", { name: /ospf/ }));
    await waitFor(() => expect(calls.at(-1)).toContain("protocol=ospf"));
    // the /16 is the first row the filter keeps, but not the longest match of its table
    await waitFor(() => expect(within(routes).getAllByRole("row")).toHaveLength(2));
    expect(within(routes).queryByText("Longest match")).not.toBeInTheDocument();
  });
});

describe("Explore schema", () => {
  it("shows the statistics, opens a node type and opens an example node in search", async () => {
    setup();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Schema" }));
    expect(await screen.findByText("1,234")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Devices by vendor" })).getByText("cisco")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Device\s*Phys/ }));
    const panel = await screen.findByRole("region", { name: "Node type Device" });
    expect(await within(panel).findByText("50%")).toBeInTheDocument();
    expect(within(panel).getByText("LOCATED_IN")).toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: "Open in the Cypher editor" })).not.toBeInTheDocument();
    await user.click(within(panel).getByRole("button", { name: "edge1" }));
    expect(screen.getByRole("tab", { name: "Search" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("heading", { name: "edge1" })).toBeInTheDocument();
  });

  it("hands a starter query to the Cypher editor for an operator", async () => {
    setup(ME_OPERATOR);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Schema" }));
    await user.click(await screen.findByRole("button", { name: /Device\s*Phys/ }));
    await user.click(await screen.findByRole("button", { name: "Open in the Cypher editor" }));
    expect(screen.getByRole("tab", { name: "Queries" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText("Cypher query")).toHaveValue(LABEL.cypher);
  });
});

describe("Query form pickers", () => {
  it("suggests values from the graph and accepts typed text", async () => {
    mockApi({ "GET /api/explore/values": () => ({ body: { items: [{ value: "edge1", count: 1 }, { value: "edge2", count: 1 }] } }) });
    const onRun = vi.fn();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <QueryForm pending={false} onRun={onRun} query={{
          key: "device-neighbors", group: "topology", title: "Device neighbors", cypher: "RETURN $hostname",
          params: [{ name: "hostname", label: "hostname", placeholder: "gw", picker: { label: "Device", property: "hostname" } }],
        }} />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    const input = screen.getByLabelText("hostname");
    await user.type(input, "edg");
    await user.click(await screen.findByRole("option", { name: "edge2" }));
    expect(input).toHaveValue("edge2");
    await waitFor(() => expect(String(vi.mocked(fetch).mock.calls.at(-1)?.[0])).toContain("label=Device"));
    await user.clear(input);
    await user.type(input, "not-in-graph{Enter}");
    expect(onRun).toHaveBeenCalledWith({ hostname: "not-in-graph" });
  });
});

describe("Explore route table pages", () => {
  const body = (over: Record<string, unknown> = {}) => ({
    available: true, approximate: false, coverage: "complete", snapshot: 1000, device_uid: "dev:1", context_uid: null,
    run_id: "r1", total: 3, offset: 0, limit: 50, protocols: [], items: [ROUTE("0.0.0.0/0", 0, "static")], ...over,
  });
  const offsetOf = (url: string) => Number(new URL(url, "http://localhost").searchParams.get("offset") ?? 0);

  async function openRoutes(handler: (url: string) => { status?: number; body?: unknown }) {
    const urls: string[] = [];
    setup(ME_VIEWER, {
      "GET /api/explore/routes": () => {
        const url = String(vi.mocked(fetch).mock.calls.at(-1)?.[0]);
        urls.push(url);
        return handler(url);
      },
    });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Search" }));
    await user.type(screen.getByLabelText("Search the graph"), "edge");
    await user.click(await screen.findByRole("button", { name: /edge1/ }));
    return { user, urls, routes: await screen.findByRole("region", { name: "Routes" }) };
  }

  it("dims the previous rows and keeps their pager label while the next page loads", async () => {
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => { release = resolve; });
    setup(ME_VIEWER, {
      "GET /api/explore/routes": async () => {
        const url = String(vi.mocked(fetch).mock.calls.at(-1)?.[0]);
        const offset = offsetOf(url);
        if (offset > 0) await held;
        return { body: body({ total: 120, offset, items: [ROUTE(`10.${offset}.0.0/16`, 16, "bgp")] }) };
      },
    } as Parameters<typeof setup>[1]);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("tab", { name: "Search" }));
    await user.type(screen.getByLabelText("Search the graph"), "edge");
    await user.click(await screen.findByRole("button", { name: /edge1/ }));
    const routes = await screen.findByRole("region", { name: "Routes" });
    expect(await within(routes).findByText("Rows 1 to 50 of 120")).toBeInTheDocument();
    await user.click(within(routes).getByRole("button", { name: "Next" }));
    expect(await within(routes).findByText("Loading")).toBeInTheDocument();
    expect(routes.querySelector(".xr-table")).toHaveClass("xr-stale");
    // the label names the rows on screen, not the page being read
    expect(within(routes).getByText("Rows 1 to 50 of 120")).toBeInTheDocument();
    release();
    expect(await within(routes).findByText("Rows 51 to 100 of 120")).toBeInTheDocument();
    expect(routes.querySelector(".xr-table")).not.toHaveClass("xr-stale");
  });

  it("reads the next page with Next", async () => {
    const { user, urls, routes } = await openRoutes((url) => {
      const offset = offsetOf(url);
      return { body: body({ total: 120, offset, items: [ROUTE(`10.${offset}.0.0/16`, 16, "bgp")] }) };
    });
    expect(await within(routes).findByText("10.0.0.0/16")).toBeInTheDocument();
    await user.click(within(routes).getByRole("button", { name: "Next" }));
    await waitFor(() => expect(urls.some((u) => offsetOf(u) === 50)).toBe(true));
    expect(await within(routes).findByText("Rows 51 to 100 of 120")).toBeInTheDocument();
    expect(within(routes).queryByText("Snapshot changed")).not.toBeInTheDocument();
  });

  it("starts again at the first page when a later page comes from another snapshot", async () => {
    let published = false;
    const { user, urls, routes } = await openRoutes((url) => {
      const offset = offsetOf(url);
      if (offset === 50) published = true;
      return { body: body({ total: 120, offset, snapshot: published ? 2000 : 1000, items: [ROUTE(`10.${offset}.0.0/16`, 16, "bgp")] }) };
    });
    expect(await within(routes).findByText("10.0.0.0/16")).toBeInTheDocument();
    await user.click(within(routes).getByRole("button", { name: "Next" }));
    expect(await within(routes).findByText("Snapshot changed")).toBeInTheDocument();
    await waitFor(() => expect(offsetOf(urls.at(-1) ?? "")).toBe(0));
    expect(await within(routes).findByText("Rows 1 to 50 of 120")).toBeInTheDocument();
    expect(within(routes).getByRole("button", { name: "Previous" })).toBeDisabled();
  });

  it("shows the error of a failed read", async () => {
    const { routes } = await openRoutes(() => ({ status: 500, body: { error: "the route table read failed" } }));
    expect(await within(routes).findByText("the route table read failed")).toBeInTheDocument();
  });

  it("shows the coverage the snapshot recorded for an incomplete route table", async () => {
    const { routes } = await openRoutes(() => ({ body: body({ coverage: "partial" }) }));
    expect(await within(routes).findByText("Partial route table")).toBeInTheDocument();
  });

  it("states a missing route table file and shows no banner for an empty table", async () => {
    const { routes } = await openRoutes(() => ({ body: body({ coverage: "missing" }) }));
    expect(await within(routes).findByText("Route table file missing")).toBeInTheDocument();
  });

  it("shows no warning for a table the snapshot recorded as empty", async () => {
    const { routes } = await openRoutes(() => ({ body: body({ coverage: "complete-empty" }) }));
    await within(routes).findByRole("table");
    expect(routes.querySelector(".banner.warn")).toBeNull();
  });
});
