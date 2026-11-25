import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SdwanPage from "./SdwanPage";
import { TOPOLOGY } from "./fixture";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
vi.mock("../api/client", () => ({ api: apiMock, ApiError: class extends Error {} }));

const EDGES = {
  edges: [
    { uid: "e1", name: "XX-CITY-BR-RTS-01", role: null, location: "Berlin", country: "DE", site: null },
    { uid: "h1", name: "XX-DC1-RTH-03", role: "hub", location: null, country: "DE", site: "FR2" },
  ],
};

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <SdwanPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  apiMock.mockReset();
  apiMock.mockImplementation((path: string) =>
    Promise.resolve(path === "/sdwan/edges" ? EDGES : TOPOLOGY),
  );
});

async function pick() {
  const user = userEvent.setup();
  mount();
  await screen.findByText("2 edges");
  await user.type(screen.getByRole("combobox", { name: "SD-WAN edge" }), "XX-CITY-BR-RTS-01");
  await screen.findByRole("group", { name: "SD-WAN topology" });
  return user;
}

describe("SdwanPage", () => {
  it("loads the topology of the edge that the picker names", async () => {
    await pick();
    expect(apiMock).toHaveBeenCalledWith("/sdwan/topology?edge=e1");
    expect(screen.getByText("GE3 BT DIA 1")).toBeTruthy();
    expect(screen.getByText("XX-DC1-RTH-03")).toBeTruthy();
    expect(screen.getByText("Cloud gateways")).toBeTruthy();
  });

  it("opens the details of a WAN link on a click", async () => {
    const user = await pick();
    await user.click(screen.getByText("GE3 BT DIA 1"));
    const panel = await screen.findByRole("complementary", { name: "Device details" });
    expect(panel.textContent).toContain("192.0.2.61");
    expect(panel.textContent).toContain("600 Mbit/s down, 600 Mbit/s up");
  });

  it("shows the business policy as rules in position order", async () => {
    const user = await pick();
    await user.click(screen.getByRole("radio", { name: "Business policy" }));
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows.map((r) => r.querySelector("td")?.textContent)).toEqual(["1", "2"]);
    expect(rows[0].textContent).toContain("realtime; priority high");
    expect(rows[0].textContent).toContain("to the cloud: gateway; link auto");
    expect(rows[1].textContent).toContain("default");
  });

  it("states that the policy has no rules", async () => {
    apiMock.mockImplementation((path: string) =>
      Promise.resolve(
        path === "/sdwan/edges"
          ? EDGES
          : { ...TOPOLOGY, policy: { ...TOPOLOGY.policy!, rule_count: null, rules: [] } },
      ),
    );
    const user = await pick();
    await user.click(screen.getByRole("radio", { name: "Business policy" }));
    await waitFor(() => expect(screen.getByText("No policy rules")).toBeTruthy());
  });

  it("states the missing rule nodes without naming a collection", async () => {
    apiMock.mockImplementation((path: string) =>
      Promise.resolve(
        path === "/sdwan/edges"
          ? EDGES
          : { ...TOPOLOGY, policy: { ...TOPOLOGY.policy!, rule_count: null, rules: [] } },
      ),
    );
    const user = await pick();
    await user.click(screen.getByRole("radio", { name: "Business policy" }));
    await waitFor(() => expect(screen.getByText("No policy rules")).toBeTruthy());
    expect(document.body.textContent ?? "").not.toMatch(/collection/i);
  });
});

describe("SdwanPage after a refused policy read", () => {
  const GAP = JSON.stringify({
    operation: "/portal/rest/enterprise/getEnterpriseConfigurations",
    reason: "no QOS profile body answered for this edge",
    status: "unavailable",
  });
  const LABEL = "No QOS profile body from getEnterpriseConfigurations";

  for (const [title, ruleCount] of [
    ["a run that writes no rule count", null],
    ["a run with rule count 0 beside the gap", 0],
  ] as const) {
    it(`states the gap and shows no rule count, for ${title}`, async () => {
      apiMock.mockImplementation((path: string) =>
        Promise.resolve(
          path === "/sdwan/edges"
            ? EDGES
            : { ...TOPOLOGY, policy: { ...TOPOLOGY.policy!, rule_count: ruleCount, capability_gap: GAP, rules: [] } },
        ),
      );
      const user = await pick();
      await user.click(screen.getByRole("radio", { name: "Business policy" }));
      await screen.findByText(LABEL);
      const text = document.body.textContent ?? "";
      expect(text).not.toMatch(/\d+ rules/);
      expect(text).not.toContain("unavailable");
      expect(text).not.toContain("{");
      expect(screen.queryByText(/No policy rules/)).toBeNull();
      expect(screen.queryAllByRole("table")).toEqual([]);
    });
  }
});

describe("SdwanPage for a picked hub", () => {
  it("shows the branches as one counted chip for each site, and names them in the panel", async () => {
    apiMock.mockImplementation((path: string) =>
      Promise.resolve(
        path === "/sdwan/edges"
          ? EDGES
          : {
              ...TOPOLOGY,
              edge: { uid: "h1", name: "XX-DC1-RTH-03", role: "hub" },
              tunnels: [
                { uid: "b1-a", interface: "GE3", peer: "b1", peer_kind: "branch", peer_ip: "198.51.100.1" },
                { uid: "b2-a", interface: "GE3", peer: "b2", peer_kind: "branch", peer_ip: "198.51.100.2" },
              ],
              hubs: [],
              branches: [
                { uid: "b2", name: "XX-BER-BR-02", site: "BER" },
                { uid: "b1", name: "XX-BER-BR-01", site: "BER" },
              ],
              gateways: [],
              devices: [],
              sites: [],
              cables: [],
            },
      ),
    );
    const user = await pick();
    expect(screen.getByText("2 branches")).toBeTruthy();
    expect(screen.queryByText("hub")).toBeNull();
    await user.click(screen.getByText("BER"));
    const panel = await screen.findByRole("complementary", { name: "Device details" });
    expect(panel.textContent).toContain("XX-BER-BR-01, XX-BER-BR-02");
  });
});

describe("SdwanPage with no edge", () => {
  it("states that the pinned run has no SD-WAN edge", async () => {
    apiMock.mockImplementation((path: string) => Promise.resolve(path === "/sdwan/edges" ? { edges: [] } : TOPOLOGY));
    mount();
    expect(await screen.findByText("No SD-WAN edge")).toBeTruthy();
  });
});

describe("SdwanPage with parallel tunnels", () => {
  it("draws two tunnels from one WAN link to one hub as two lines on separate lanes", async () => {
    const parallel = {
      ...TOPOLOGY,
      tunnels: [
        { uid: "t1", interface: "GE3", peer: "h1", peer_kind: "hub" as const, peer_ip: "203.0.113.1" },
        { uid: "t1b", interface: "GE3", peer: "h1", peer_kind: "hub" as const, peer_ip: "203.0.113.11" },
      ],
    };
    apiMock.mockImplementation((path: string) => Promise.resolve(path === "/sdwan/edges" ? EDGES : parallel));
    await pick();
    const lines = Array.from(document.querySelectorAll(".sdwan-tunnel-hub path:not(.netmap-cablehit)"));
    expect(lines).toHaveLength(2);
    expect(lines[0].getAttribute("d")).not.toBe(lines[1].getAttribute("d"));
    expect(lines.map((l) => l.textContent)).toEqual([
      "GE3 to XX-DC1-RTH-03 (203.0.113.1)",
      "GE3 to XX-DC1-RTH-03 (203.0.113.11)",
    ]);
  });
});

describe("SdwanPage from the keyboard", () => {
  it("opens a node's details with Enter and a tunnel's with Space", async () => {
    const user = await pick();
    const node = screen.getByRole("button", { name: "XX-DC1-RTH-03" });
    node.focus();
    await user.keyboard("{Enter}");
    expect(node).toHaveAttribute("aria-pressed", "true");
    expect(await screen.findByRole("complementary")).toBeInTheDocument();
    const tunnel = screen.getAllByRole("button", { name: /^Tunnel GE3 to / })[0];
    tunnel.focus();
    await user.keyboard(" ");
    expect(tunnel).toHaveAttribute("aria-pressed", "true");
  });
});
