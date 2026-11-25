/**
 * The page around the canvas: the site picker, the states before a drawing,
 * and the text alternative with the details panel. What the drawing is made of
 * is asserted in layout.test.ts. jsdom has no worker, so the bundled ELK
 * engine stands in for elk.ts, and the stage gets a size, as in
 * explore/GraphView.test.tsx.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { TopologyModel } from "../api/types";
import NetworkMapPage, { diagramOf, expandedOf, siteOfScope } from "./NetworkMapPage";
import { conditionResult } from "./flowFixture";

const { apiMock, userMock } = vi.hoisted(() => ({
  apiMock: vi.fn(),
  // outside an AuthProvider there is no user; a test that saves a view gives one sites.write
  userMock: vi.fn((): { permissions: string[] } | null => null),
}));
vi.mock("../api/client", () => ({
  api: apiMock,
  ApiError: class ApiError extends Error {},
}));
vi.mock("../auth", async (original) => ({ ...(await original<typeof import("../auth")>()), useCurrentUser: userMock }));
vi.mock("./elk", async () => {
  const ELK = (await import("elkjs/lib/elk.bundled.js")).default;
  const engine = new ELK();
  return { layout: (graph: object) => engine.layout(graph as never) };
});

const MODEL: TopologyModel = {
  snapshot: 7,
  nodes: [
    { id: "site:ber1", kind: "site", parent: null, label: "ber1" },
    { id: "block:ber1:wan-edge", kind: "block", parent: "site:ber1", label: "WAN edge", block_kind: "wan-edge" },
    { id: "block:ber1:campus", kind: "block", parent: "site:ber1", label: "Campus", block_kind: "campus" },
    {
      id: "rth-01",
      kind: "device",
      parent: "block:ber1:wan-edge",
      label: "rth-01",
      tier: "sdwan-hub",
      role: "sdwan-hub",
      role_basis: "collector",
      block_basis: "tier",
      depth: 0,
      anchor: "wan-link",
      partition: 0,
    },
    {
      id: "swc-01",
      kind: "device",
      parent: "block:ber1:campus",
      label: "swc-01",
      tier: "core",
      role: "router",
      role_basis: "hostname",
      block_basis: "tier",
      depth: 1,
      partition: 0,
    },
  ],
  cables: [
    { id: "c1", from: { dev: "rth-01", port: "GE1" }, to: { dev: "swc-01", port: "Eth1/1" }, source: "lldp", lateral: false },
  ],
  exits: [],
  lags: [],
  split_groups: [],
};

/** ham1: one VLAN with its gateway SVI, an access port and two clients on it. */
const BD = "bd:vlan:fab0:10";
const GROUP = "swc-01|Gi1/0/2|";
const SEG_MODEL: TopologyModel = {
  ...MODEL,
  snapshot: 1_760_000_000_000,
  vlans: [
    { dev: "swc-01", vid: 10, name: "Office", segment: "Office", bd: BD, ports: ["Eth1/1", "Gi1/0/2"], native: ["Gi1/0/2"], svi: "Vlan10" },
  ],
  subnets: [{ cidr: "10.10.0.0/24", af: 4, vrf: "default", domain: null, members: [{ dev: "swc-01", iface: "Vlan10", ip: "10.10.0.1", fhrp: null }] }],
  segments: [
    {
      bd: BD,
      vid: 10,
      name: "Office",
      cidrs: ["10.10.0.0/24"],
      cidr_basis: "gateway",
      gateways: [{ dev: "swc-01", iface: "Vlan10", ip: "10.10.0.1", cidr: "10.10.0.0/24", af: 4, vrf: "default", domain: null, fhrp: null, basis: "svi" }],
      carriers: [{ dev: "swc-01", ports: ["Eth1/1", "Gi1/0/2"], native: ["Gi1/0/2"], access: ["Gi1/0/2"] }],
      clients: 2,
      attachments: [{ dev: "swc-01", port: "Gi1/0/2", ssid: null, count: 2 }],
    },
  ],
  clients: [
    {
      dev: "swc-01",
      port: "Gi1/0/2",
      ssid: null,
      count: 2,
      by_bd: { [BD]: 2 },
      clients: [
        { name: "nas", uid: "ep:1", ips: ["10.10.0.20"], mac: "112233445566", vendor: "Synology", last_seen: 1_760_000_000_000, bd: BD },
        { name: "printer", uid: "ep:2", ips: ["10.10.0.21"], mac: "aabbccddeeff", vendor: null, last_seen: null, bd: BD },
      ],
    },
  ],
};

const SEGMENT_PAGE = {
  snapshot: 1_760_000_000_000,
  bd: BD,
  total: 2,
  offset: 0,
  limit: 100,
  clients: SEG_MODEL.clients![0].clients.map((c) => ({ ...c, dev: "swc-01", dev_name: "swc-01", port: "Gi1/0/2", ssid: null })),
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

const ESTATE = {
  sites: [
    { code: "ber1", name: "Berlin 1", lat: 52.52, lon: 13.4, devices: 2, kind: null, tiers: { "sdwan-hub": 1, core: 1 }, exits: [] },
    { code: "lab", name: "Lab", lat: null, lon: null, devices: 1, kind: null, tiers: {}, exits: [] },
    { code: "dc9", name: "DC 9", lat: null, lon: null, devices: 4, kind: "dc", tiers: { spine: 2, leaf: 2 }, exits: [] },
  ],
  edges: [
    {
      a: "ber1",
      b: "lab",
      kind: "cable",
      count: 3,
      pairs: [{ a_name: "swc-01", a_port: "Eth1/49", b_name: "lab-sw", b_port: "1", source: "lldp" }],
    },
  ],
  unplaced: [],
};

/** `extraViews` are saved views past the fixture's, `extra` answers paths the fixture does not,
 *  and `initialSite` opens a site diagram first. */
function renderPage(extraViews: object[] = [], extra: (path: string) => unknown = () => undefined, initialSite?: string) {
  apiMock.mockImplementation((path: string, init?: { method?: string; body?: unknown }) => {
    if (path === "/network-map/views" && init?.method === "POST")
      return Promise.resolve({ id: "v9", name: "saved", state: {}, owner_id: 1, revision: 1, created_at: "", updated_at: "" });
    const answer = extra(path);
    if (answer !== undefined) return Promise.resolve(answer);
    if (path === "/sites") return Promise.resolve({ sites: [{ code: "ber1", name: "Berlin 1" }] });
    if (path === "/sites/graph") return Promise.resolve(ESTATE);
    if (path === "/network-map/views")
      return Promise.resolve({
        views: [
          {
            id: "v1",
            name: "Berlin diagram",
            state: { site: "ber1", kinds: ["cable"] },
            owner_id: null,
            revision: 1,
            created_at: "",
            updated_at: "",
          },
          {
            id: "v2",
            name: "Old estate",
            state: { site: "", kinds: ["cable"], estate: { x: 1, y: 2, w: 300, h: 150 } },
            owner_id: null,
            revision: 1,
            created_at: "",
            updated_at: "",
          },
          {
            id: "v3",
            name: "Europe on the map",
            state: { site: "", kinds: ["cable"], mode: "geographic", estate: { x: 10, y: 20, w: 400, h: 200 } },
            owner_id: null,
            revision: 1,
            created_at: "",
            updated_at: "",
          },
          {
            id: "v4",
            name: "Old backbone",
            state: { site: "", kinds: ["cable"], mode: "backbone", backbone: { expanded: ["ber1"], zoom: 1.5, pan: { x: 1, y: 2 } } },
            owner_id: null,
            revision: 1,
            created_at: "",
            updated_at: "",
          },
          {
            id: "v5",
            name: "Berlin with its branches",
            state: { site: "", kinds: ["cable"], estate: { x: 50, y: 60, w: 200, h: 100 }, expanded: ["ber1"] },
            owner_id: null,
            revision: 1,
            created_at: "",
            updated_at: "",
          },
          {
            id: "v7",
            name: "Office VLAN with its clients",
            state: { site: "ham1", kinds: ["cable"], layer: "l2", vid: 10, segments: true, clients: true, groups: [GROUP] },
            owner_id: null,
            revision: 1,
            created_at: "",
            updated_at: "",
          },
          ...extraViews,
        ],
      });
    if (path === "/network-map/layouts/site/ber1")
      return Promise.resolve({ scope: "site/ber1", positions: {}, revision: 0, updated_by: null, updated_at: null });
    if (path === "/topology?site=ber1") return Promise.resolve(MODEL);
    if (path === "/topology?site=ber1&site=lab") return Promise.resolve(MODEL);
    if (path === "/topology?site=ham1") return Promise.resolve(SEG_MODEL);
    if (path === "/network-map/layouts/site/ham1")
      return Promise.resolve({ scope: "site/ham1", positions: {}, revision: 0, updated_by: null, updated_at: null });
    if (path.startsWith("/topology/segment?")) return Promise.resolve(SEGMENT_PAGE);
    return Promise.reject(new Error(`unexpected ${path}`));
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <NetworkMapPage initialSite={initialSite} />
    </QueryClientProvider>,
  );
}

/** The world map of the estate: hidden from assistive technology, so it is
 *  found by its class. */
const worldMap = (container: HTMLElement) => container.querySelector("svg.nm-estate") as SVGSVGElement;

describe("NetworkMapPage", () => {
  it("opens on the backbone on the world map: a site is a button, and a second press opens its diagram", async () => {
    const user = userEvent.setup();
    renderPage();
    const node = await screen.findByRole("button", { name: "Berlin 1, SD-WAN hub" });
    expect(screen.queryByRole("radiogroup", { name: "Estate view" })).not.toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Counted links" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show 1 branch of ber1" })).toBeInTheDocument();
    expect(apiMock).not.toHaveBeenCalledWith(expect.stringContaining("/topology"));
    await user.click(node);
    const panel = screen.getByRole("complementary", { name: "Site details" });
    expect(within(panel).getByText("1 sdwan-hub, 1 core")).toBeInTheDocument();
    expect(within(panel).getByText("3")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Berlin 1, SD-WAN hub" }));
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    await user.click(screen.getByRole("button", { name: "Estate" }));
    expect(await screen.findByRole("button", { name: "Show 1 branch of ber1" })).toBeInTheDocument();
  });

  it("keeps the open badges and the camera when a site opens and the estate returns", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    await user.click(await screen.findByRole("button", { name: "Show 1 branch of ber1" }));
    expect(container.querySelector('[data-marker="site"][data-code="lab"]')).not.toBeNull();
    await user.click(screen.getByRole("button", { name: "Zoom in" }));
    const camera = worldMap(container).getAttribute("viewBox");
    await user.click(screen.getByRole("button", { name: "Berlin 1, SD-WAN hub" }));
    await user.click(screen.getByRole("button", { name: "Open the diagram" }));
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    await user.click(screen.getByRole("button", { name: "Estate" }));
    expect(await screen.findByRole("button", { name: "Show 1 branch of ber1" })).toHaveAttribute("aria-expanded", "true");
    expect(worldMap(container).getAttribute("viewBox")).toBe(camera);
  });

  it("opens a saved view, and offers no save to a reader", async () => {
    const user = userEvent.setup();
    renderPage();
    const picker = await screen.findByLabelText("Saved view");
    await waitFor(() => expect(within(picker).getByText("Berlin diagram")).toBeInTheDocument());
    // outside an AuthProvider there is no user, so nothing may be written
    expect(screen.queryByRole("button", { name: "Save view" })).not.toBeInTheDocument();
    await user.selectOptions(picker, "v1");
    expect(await screen.findByRole("button", { name: "swc-01, core, in Campus" })).toBeInTheDocument();
    expect(apiMock).toHaveBeenCalledWith("/network-map/layouts/site/ber1");
  });

  it("restores a saved view with its camera and its open badges", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    const picker = await screen.findByLabelText("Saved view");
    await waitFor(() => expect(within(picker).getByText("Berlin with its branches")).toBeInTheDocument());
    await user.selectOptions(picker, "v5");
    expect(await screen.findByRole("button", { name: "Show 1 branch of ber1" })).toHaveAttribute("aria-expanded", "true");
    expect(worldMap(container).getAttribute("viewBox")).toBe("50 60 200 100");
  });

  it("opens the views with a mode or a backbone field on the world map", async () => {
    const user = userEvent.setup();
    const { container } = renderPage();
    const picker = await screen.findByLabelText("Saved view");
    await waitFor(() => expect(within(picker).getByText("Old backbone")).toBeInTheDocument());
    await user.selectOptions(picker, "v2");
    await screen.findByRole("button", { name: "Show 1 branch of ber1" });
    expect(worldMap(container).getAttribute("viewBox")).toBe("1 2 300 150");
    await user.selectOptions(picker, "v3");
    await waitFor(() => expect(worldMap(container).getAttribute("viewBox")).toBe("10 20 400 200"));
    expect(screen.getByRole("button", { name: "Show 1 branch of ber1" })).toHaveAttribute("aria-expanded", "false");
    await user.selectOptions(picker, "v4");
    expect(await screen.findByRole("button", { name: "Show 1 branch of ber1" })).toHaveAttribute("aria-expanded", "true");
    expect(container.querySelector('[data-marker="site"][data-code="lab"]')).not.toBeNull();
    expect(worldMap(container).getAttribute("viewBox")).not.toBe("10 20 400 200");
  });

  it("lists a site's connections with their device pairs, and opens both sites as one drawing", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Berlin 1, SD-WAN hub" }));
    await user.click(screen.getByRole("button", { name: "lab: 3 cables" }));
    expect(screen.getByText("swc-01 Eth1/49 to lab-sw 1, lldp")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Trace ber1 to lab" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open both" }));
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    expect(apiMock).toHaveBeenCalledWith("/topology?site=ber1&site=lab");
    // a union of sites keeps no layout of its own
    expect(apiMock).not.toHaveBeenCalledWith(expect.stringContaining("/network-map/layouts/site/ber1,lab"));
  });

  it("lists the shared prefixes not drawn, and the BGP sessions of a site with an ambiguous peer", async () => {
    const user = userEvent.setup();
    // one object for every read, as a query cache holds it
    const estate = {
      ...ESTATE,
      shared_subnets: [{ cidr: "10.0.0.0/8", domain: "global", sites: 12, members: 40 }],
      ambiguous: [{ site: "ber1", kind: "bgp", count: 2 }],
    };
    renderPage([], (path) => (path === "/sites/graph" ? estate : undefined));
    await user.click(await screen.findByRole("button", { name: "Berlin 1, SD-WAN hub" }));
    // the note goes with the shared prefixes, which the estate does not count by default
    expect(screen.queryByText(/Shared prefixes not drawn/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Shared prefixes" }));
    expect(screen.getByText("Shared prefixes not drawn: 10.0.0.0/8 on 12 sites")).toBeInTheDocument();
    expect(screen.getByText("2 BGP sessions with an ambiguous peer address")).toBeInTheDocument();
  });

  it("switches the site diagram to the L2 layer", async () => {
    const user = userEvent.setup();
    renderPage();
    const picker = await screen.findByLabelText("Site");
    await waitFor(() => expect(within(picker).getByText("ber1, Berlin 1")).toBeInTheDocument());
    await user.selectOptions(picker, "ber1");
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    await user.click(screen.getByRole("radio", { name: "L2" }));
    expect(screen.getByText("no VLAN data")).toBeInTheDocument();
  });

  it("lists the major sites with no coordinates beside the map, and a row selects the site", async () => {
    const user = userEvent.setup();
    renderPage();
    const list = await screen.findByRole("region", { name: "Not on the map" });
    // lab is a branch: a branch needs no coordinates
    expect(within(list).queryByRole("button", { name: "lab" })).not.toBeInTheDocument();
    await user.click(within(list).getByRole("button", { name: "dc9" }));
    const panel = screen.getByRole("complementary", { name: "Site details" });
    expect(within(panel).getByText("dc9, DC 9")).toBeInTheDocument();
    expect(within(panel).getByText("Data center")).toBeInTheDocument();
  });

  it("draws the picked site and shows a device's tier and its basis", async () => {
    const user = userEvent.setup();
    renderPage();
    const picker = await screen.findByLabelText("Site");
    await waitFor(() => expect(within(picker).getByText("ber1, Berlin 1")).toBeInTheDocument());
    await user.selectOptions(picker, "ber1");

    const button = await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    expect(apiMock).toHaveBeenCalledWith("/topology?site=ber1");
    await waitFor(() => expect(screen.queryByText(/Laying out/)).not.toBeInTheDocument());
    await user.click(button);

    const panel = screen.getByRole("complementary", { name: "Device details" });
    expect(within(panel).getByText("core")).toBeInTheDocument();
    expect(within(panel).getByText("router, from the hostname")).toBeInTheDocument();
    expect(screen.getByText("rth-01 GE1 to swc-01 Eth1/1")).toBeInTheDocument();
  });
});

describe("segments and clients on the site diagram", () => {
  const openHam = async () => {
    renderPage([], undefined, "ham1");
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    await waitFor(() => expect(screen.queryByText(/Laying out/)).not.toBeInTheDocument());
  };

  it("draws the picked VLAN as a segment in L2, and lists its clients in the side panel", async () => {
    const user = userEvent.setup();
    await openHam();
    expect(screen.queryByRole("button", { name: /segment$/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "L2" }));
    await user.click(screen.getByRole("button", { name: "VLAN 10 Office 10.10.0.0/24, segment" }));
    const panel = screen.getByRole("complementary", { name: "Segment details" });
    expect(within(panel).getByText("swc-01 Vlan10 10.10.0.1")).toBeInTheDocument();
    // the access port, in the details and in the client rows
    expect(within(panel).getAllByText("swc-01 Gi1/0/2").map((e) => e.tagName)).toContain("LI");
    expect(await within(panel).findByText("11:22:33:44:55:66")).toBeInTheDocument();
    expect(within(panel).getByText("Synology")).toBeInTheDocument();
    expect(within(panel).getByText(/^1 to 2 of 2, as of run /)).toBeInTheDocument();
    expect(apiMock).toHaveBeenCalledWith(`/topology/segment?bd=${encodeURIComponent(BD)}&site=ham1&offset=0&limit=100`);
    // the clients are a run's, never a current reading
    expect(panel.textContent).not.toMatch(/\blive\b/i);
  });

  it("opens a segment record kept per site, and lists the clients of that site only", async () => {
    const user = userEvent.setup();
    renderPage(
      [],
      (path) => (path === "/topology?site=ham1" ? { ...SEG_MODEL, segments: SEG_MODEL.segments!.map((g) => ({ ...g, site: "ham2" })) } : undefined),
      "ham1",
    );
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    await waitFor(() => expect(screen.queryByText(/Laying out/)).not.toBeInTheDocument());
    await user.click(screen.getByRole("radio", { name: "L2" }));
    await user.click(screen.getByRole("button", { name: "VLAN 10 Office 10.10.0.0/24, segment" }));
    const panel = screen.getByRole("complementary", { name: "Segment details" });
    expect(within(panel).getByText("swc-01 Vlan10 10.10.0.1")).toBeInTheDocument();
    expect(await within(panel).findByText("11:22:33:44:55:66")).toBeInTheDocument();
    expect(apiMock).toHaveBeenCalledWith(`/topology/segment?bd=${encodeURIComponent(BD)}&site=ham2&offset=0&limit=100`);
  });

  it("draws every connected prefix of the domain in L3, and hides the bars with the Segments option", async () => {
    const user = userEvent.setup();
    await openHam();
    await user.click(screen.getByRole("button", { name: "Options" }));
    const legend = screen.getByRole("complementary", { name: "Options" });
    expect(within(legend).getByRole("button", { name: "Segments" })).toHaveAttribute("aria-pressed", "true");
    expect(within(legend).getByRole("button", { name: "Clients" })).toHaveAttribute("aria-pressed", "false");
    await user.click(screen.getByRole("radio", { name: "L3" }));
    // the prefix has one gateway, and still is a bar
    expect(screen.getByRole("button", { name: "10.10.0.0/24 VLAN 10 Office, segment" })).toBeInTheDocument();
    await user.click(within(legend).getByRole("button", { name: "Segments" }));
    expect(screen.queryByRole("button", { name: /segment$/ })).not.toBeInTheDocument();
  });

  it("shows the clients as a collapsed badge per attachment point when the legend turns them on", async () => {
    const user = userEvent.setup();
    await openHam();
    expect(screen.queryByRole("button", { name: "swc-01 Gi1/0/2: 2 clients" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Options" }));
    const legend = screen.getByRole("complementary", { name: "Options" });
    await user.click(within(legend).getByRole("button", { name: "Clients" }));
    const badge = screen.getByRole("button", { name: "swc-01 Gi1/0/2: 2 clients" });
    expect(badge).toHaveAttribute("aria-expanded", "false");
    await user.click(badge);
    expect(screen.getByRole("button", { name: "swc-01 Gi1/0/2: 2 clients" })).toHaveAttribute("aria-expanded", "true");
    const panel = screen.getByRole("complementary", { name: "Client details" });
    expect(within(panel).getByText("aa:bb:cc:dd:ee:ff")).toBeInTheDocument();
    expect(within(panel).getByText(/^2 clients, as of run /)).toBeInTheDocument();
    await user.click(within(panel).getByRole("button", { name: "All clients of VLAN 10 Office 10.10.0.0/24" }));
    expect(screen.getByRole("complementary", { name: "Segment details" })).toBeInTheDocument();
  });

  it("opens a saved view with its layer, its VLAN, its options and its expanded badges", async () => {
    const user = userEvent.setup();
    renderPage();
    const picker = await screen.findByLabelText("Saved view");
    await waitFor(() => expect(within(picker).getByText("Office VLAN with its clients")).toBeInTheDocument());
    await user.selectOptions(picker, "v7");
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    expect(screen.getByRole("radio", { name: "L2" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByLabelText("VLAN")).toHaveValue("10");
    await user.click(screen.getByRole("button", { name: "Options" }));
    expect(within(screen.getByRole("complementary", { name: "Options" })).getByRole("button", { name: "Clients" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "swc-01 Gi1/0/2: 2 clients" })).toHaveAttribute("aria-expanded", "true");
  });

  it("saves the layer, the VLAN, the options and the expanded badges with the view", async () => {
    userMock.mockReturnValue({ permissions: ["sites.write"] });
    try {
      const user = userEvent.setup();
      await openHam();
      await user.click(screen.getByRole("radio", { name: "L2" }));
      await user.click(screen.getByRole("button", { name: "Options" }));
      await user.click(within(screen.getByRole("complementary", { name: "Options" })).getByRole("button", { name: "Clients" }));
      await user.click(screen.getByRole("button", { name: "swc-01 Gi1/0/2: 2 clients" }));
      await user.click(screen.getByRole("button", { name: "Save view" }));
      await user.type(screen.getByLabelText("View name"), "Office");
      await user.click(screen.getByRole("button", { name: "Save" }));
      await waitFor(() => expect(apiMock).toHaveBeenCalledWith("/network-map/views", expect.objectContaining({ method: "POST" })));
      const [, init] = apiMock.mock.calls.find(([path, i]) => path === "/network-map/views" && i?.method === "POST")!;
      const state = (init.body as { state: Record<string, unknown> }).state;
      expect(state).toMatchObject({ site: "ham1", layer: "l2", vid: 10, segments: true, clients: true, groups: [GROUP] });
      // what was saved opens as it was saved
      expect(diagramOf(state)).toEqual({ layer: "l2", vid: 10, domain: "vrf:default", segments: true, clients: true, groups: [GROUP] });
    } finally {
      userMock.mockReturnValue(null);
    }
  });
});

describe("diagramOf", () => {
  it("reads each diagram field of a saved view that has its type, and nothing else", () => {
    expect(diagramOf({ site: "ber1", kinds: ["cable"] })).toEqual({});
    expect(diagramOf({ layer: "l3", vid: 10, domain: "global", segments: false, clients: true, groups: ["a||Home", 3] })).toEqual({
      layer: "l3",
      vid: 10,
      domain: "global",
      segments: false,
      clients: true,
      groups: ["a||Home"],
    });
    expect(diagramOf({ layer: "l4", vid: "10", segments: "yes", groups: "a" })).toEqual({});
  });
});

describe("NetworkMapPage flows", () => {
  const CATALOG = { applications: [{ id: "shop", revision: 3, name: "Shop", digest: "d", definition: { services: [], connections: [], groups: [] } }] };
  const FLOWS = {
    application: { id: "shop", revision: 3, digest: "d", name: "Shop" },
    snapshot: { snapshot: "7", manifest_sha256: "m", estate: "test" },
    resolution_digest: "r",
    connections: [
      {
        id: "web",
        name: "Web",
        service_id: null,
        source: "clients",
        destination: "servers",
        protocol: "tcp",
        destination_ports: [443],
        success: "forward",
        readiness: "ready",
        state: "evaluated",
        result: conditionResult("passes"),
        issues: [],
        endpoints: { source: [], destination: [] },
        evaluation: null,
        paths: [
          {
            id: "p1",
            result: conditionResult("passes"),
            count: 1,
            members: ["db"],
            devices: ["rth-01", "swc-01", "far-01"],
            phases: ["forward", "forward", "forward"],
            segments: [
              { from: "rth-01", to: "swc-01", phase: "forward", state: "passes" },
              { from: "swc-01", to: "far-01", phase: "forward", state: "passes" },
            ],
            steps: [],
            stop_index: null,
            stop_device: null,
            unknown_index: null,
            unknown_device: null,
            missing: [],
          },
        ],
        more_paths: 0,
        counts: { passes: 1, fails: 0, open: 0 },
        missing: [],
        evidence_truncated: false,
      },
    ],
    evaluated: { snapshots: ["7"], revisions: [3] },
    stale: { snapshot: false, revision: false },
    max_paths: 50,
  };
  const answer = (path: string) =>
    path === "/business-applications" ? CATALOG : path === "/business-applications/shop/flows?snapshot=7" ? FLOWS : undefined;

  it("reads no flow until the Flows toggle is on and a connection is picked, then reads them at the drawing's run", async () => {
    const user = userEvent.setup();
    renderPage([], answer);
    const picker = await screen.findByLabelText("Site");
    await waitFor(() => expect(within(picker).getByText("ber1, Berlin 1")).toBeInTheDocument());
    await user.selectOptions(picker, "ber1");
    await screen.findByRole("button", { name: "swc-01, core, in Campus" });
    expect(apiMock).not.toHaveBeenCalledWith(expect.stringContaining("/flows"));
    await user.click(screen.getByRole("button", { name: "Flows" }));
    expect(screen.getByRole("button", { name: "Flows" })).toHaveAttribute("aria-pressed", "true");
    const panel = screen.getByRole("complementary", { name: "Application flows" });
    await user.selectOptions(await within(panel).findByLabelText("Application"), "shop");
    await user.click(await within(panel).findByRole("checkbox", { name: "Web" }));
    expect(apiMock).toHaveBeenCalledWith("/business-applications/shop/flows?snapshot=7");
    expect(await within(panel).findByText("1 connection, 1 path, 1 device off this drawing")).toBeInTheDocument();
    expect(apiMock).not.toHaveBeenCalledWith(expect.stringContaining("/analysis-sessions"), expect.anything());
  });

  it("opens a saved view with its flows shown", async () => {
    const user = userEvent.setup();
    renderPage(
      [{ id: "v6", name: "Shop flows", state: { site: "ber1", kinds: ["cable"], flows: { application: "shop", connections: ["web"] } }, owner_id: null, revision: 1, created_at: "", updated_at: "" }],
      answer,
    );
    const picker = await screen.findByLabelText("Saved view");
    await waitFor(() => expect(within(picker).getByText("Shop flows")).toBeInTheDocument());
    await user.selectOptions(picker, "v6");
    const panel = await screen.findByRole("complementary", { name: "Application flows" });
    expect(await within(panel).findByRole("checkbox", { name: "Web" })).toBeChecked();
    expect(within(panel).getByText("Passes")).toBeInTheDocument();
  });
});

describe("expandedOf", () => {
  it("reads the open badges of a saved view in either shape, and drops what is not a group", () => {
    expect(expandedOf({ expanded: ["FR2", null] })).toEqual(["FR2", null]);
    expect(expandedOf({ backbone: { expanded: ["ber1", 3, null] } })).toEqual(["ber1", null]);
    expect(expandedOf({})).toEqual([]);
  });
});

describe("siteOfScope", () => {
  it("opens a site, a pair of sites, or the estate for a routing scope", () => {
    expect(siteOfScope(undefined)).toBe("");
    expect(siteOfScope("FR2")).toBe("FR2");
    expect(siteOfScope("sites/FR6,FR2")).toBe("FR2,FR6");
    expect(siteOfScope("scope/ACME-EMEA")).toBe("");
  });
});
