import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import DeviceTabs from "./DeviceTabs";

const { apiMock, user } = vi.hoisted(() => ({
  apiMock: vi.fn(),
  user: { permissions: ["graph.read", "interfaces.read"] as string[] },
}));
vi.mock("../api/client", () => ({
  api: apiMock,
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));
vi.mock("../auth", () => ({ useCurrentUser: () => user }));

const DEVICE = {
  uid: "dev:sw1",
  snapshot: 7,
  state: "warm",
  categories: {
    n_interfaces: [
      { uid: "dev:sw1/if/Ethernet1/10", name: "Ethernet1/10" },
      { uid: "dev:sw1/if/Ethernet1/2", name: "Ethernet1/2" },
    ],
  },
  contexts: [],
};
const FACTS = {
  uid: "dev:sw1/if/Ethernet1/2",
  snapshot: 7,
  label: "Interface",
  device_uid: "dev:sw1",
  name: "Ethernet1/2",
  interface: { name: "Ethernet1/2", description: "to core", admin_up: true, kind: "phys" },
  port: null,
  contexts: ["vrf:dev:sw1:hosting"],
  addresses: ["ip:vrf:dev:sw1:hosting:10.0.0.1/31"],
  lags: [],
};
const TEXT = {
  uid: "dev:sw1",
  snapshot: 7,
  fetched_ts: 1_700_000_000_000,
  sections: [
    {
      key: "routing",
      title: "Routing",
      parts: [{ command: "show running-config bgp", text: "router bgp 65000\n  router-id 10.0.0.1" }],
    },
  ],
};

async function serve(path: string): Promise<unknown> {
  const { ApiError } = await import("../api/client");
  if (path.startsWith("/hst/device-text")) return TEXT;
  if (path.startsWith("/hst/device?")) return DEVICE;
  if (path.startsWith("/hst/interface-text")) return { uid: FACTS.uid, command: "c", fetched_ts: 1, text: "interface Ethernet1/2\n  no shutdown" };
  if (path.startsWith("/hst/interface?")) return FACTS;
  throw new (ApiError as unknown as new (status: number, message: string) => Error)(404, "not found");
}

function renderTabs() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <DeviceTabs
        uid="dev:sw1"
        snapshot={7}
        overview={<p>the overview</p>}
        links={new Map([["Ethernet1/2", "core-01 Ethernet1/1"]])}
      />
    </QueryClientProvider>,
  );
}

const calls = () => apiMock.mock.calls.map(([path]) => String(path));

describe("the device tabs", () => {
  beforeEach(() => {
    apiMock.mockReset();
    apiMock.mockImplementation(serve);
    user.permissions = ["graph.read", "interfaces.read"];
  });

  it("opens on the overview and reads nothing until another tab opens", () => {
    renderTabs();

    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual([
      "Overview",
      "Interfaces",
      "Routing",
      "ACLs",
      "NAT",
      "Version",
    ]);
    expect(screen.getByText("the overview")).toBeInTheDocument();
    expect(apiMock).not.toHaveBeenCalled();
  });

  it("lists the interfaces by name with their far end, and opens one with its facts and configuration", async () => {
    renderTabs();
    const u = userEvent.setup();

    await u.click(screen.getByRole("tab", { name: "Interfaces" }));
    const names = await screen.findAllByRole("button", { name: /^Ethernet/ });
    expect(names.map((b) => b.textContent)).toEqual(["Ethernet1/2", "Ethernet1/10"]);
    expect(screen.getByText("to core-01 Ethernet1/1")).toBeInTheDocument();

    await u.click(names[0]);

    expect(await screen.findByText("to core")).toBeInTheDocument();
    expect(screen.getByText("hosting")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1/31")).toBeInTheDocument();
    expect(await screen.findByLabelText("Configuration of Ethernet1/2")).toHaveTextContent("no shutdown");
  });

  it("reads every tab at the run the drawing shows", async () => {
    renderTabs();
    const u = userEvent.setup();

    await u.click(screen.getByRole("tab", { name: "Interfaces" }));
    const names = await screen.findAllByRole("button", { name: /^Ethernet/ });
    await u.click(names[0]);
    await screen.findByLabelText("Configuration of Ethernet1/2");
    await u.click(screen.getByRole("tab", { name: "Routing" }));
    await screen.findByText("show running-config bgp");

    const hst = calls().filter((c) => c.startsWith("/hst/"));
    expect(hst.length).toBeGreaterThanOrEqual(4);
    for (const c of hst) expect(new URLSearchParams(c.split("?")[1]).get("snapshot")).toBe("7");
  });

  it("shows each command of a section with its answer", async () => {
    renderTabs();
    const u = userEvent.setup();

    await u.click(screen.getByRole("tab", { name: "Routing" }));

    expect(await screen.findByLabelText("show running-config bgp")).toHaveTextContent("router bgp 65000");
    await u.click(screen.getByRole("tab", { name: "ACLs" }));
    expect(screen.getByText("No ACLs section")).toBeInTheDocument();
    expect(calls().filter((p) => p.startsWith("/hst/device-text"))).toHaveLength(1);
  });

  it("asks for no configuration without interfaces.read", async () => {
    user.permissions = ["graph.read"];
    renderTabs();
    const u = userEvent.setup();

    await u.click(screen.getByRole("tab", { name: "Routing" }));
    expect(screen.getByText("No interfaces.read permission")).toBeInTheDocument();

    await u.click(screen.getByRole("tab", { name: "Interfaces" }));
    await u.click((await screen.findAllByRole("button", { name: /^Ethernet/ }))[0]);
    expect(await screen.findByText("to core")).toBeInTheDocument();
    expect(calls().some((p) => p.startsWith("/hst/device-text") || p.startsWith("/hst/interface-text"))).toBe(false);
  });

  it("says when the run holds no configuration for the device", async () => {
    apiMock.mockImplementation(async (path: string) => {
      if (path.startsWith("/hst/device-text")) return serve("/missing");
      return serve(path);
    });
    renderTabs();
    const u = userEvent.setup();

    await u.click(screen.getByRole("tab", { name: "Version" }));

    expect(await screen.findByText("No configuration collected")).toBeInTheDocument();
  });
});
