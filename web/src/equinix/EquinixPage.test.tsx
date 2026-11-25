import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import EquinixPage from "./EquinixPage";
import { METRO, METROS } from "./fixture";

const { apiMock, openQuery } = vi.hoisted(() => ({ apiMock: vi.fn(), openQuery: vi.fn() }));
vi.mock("../api/client", () => ({ api: apiMock, ApiError: class extends Error {} }));
vi.mock("../workspace/WorkspaceContext", () => ({ useWorkspace: () => ({ openQuery }) }));

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EquinixPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  apiMock.mockReset();
  openQuery.mockReset();
  apiMock.mockImplementation((path: string) => Promise.resolve(path === "/equinix/metros" ? METROS : METRO));
});

async function pick() {
  const user = userEvent.setup();
  mount();
  await screen.findByText("No metro picked");
  await user.click(screen.getByRole("radio", { name: "XX" }));
  await screen.findByRole("group", { name: "Equinix Fabric" });
  return user;
}

describe("EquinixPage", () => {
  it("loads the metro that the picker names and draws its rows", async () => {
    await pick();
    expect(apiMock).toHaveBeenCalledWith("/equinix/metro?metro=XX");
    expect(screen.getByText("XX-SWC-02")).toBeTruthy();
    expect(screen.getByText("XX-EDGE-01")).toBeTruthy();
    expect(screen.getByText("ACME-XX1-EXT-PRI-01")).toBeTruthy();
    expect(screen.getByText("IBX XX1")).toBeTruthy();
    expect(screen.getByText("AWS Direct Connect")).toBeTruthy();
    expect(screen.getByText("Metro YY")).toBeTruthy();
    expect(screen.getByText("Other parties")).toBeTruthy();
    expect(screen.getByText(/3 Fabric ports, 6 circuits, 4 ended/)).toBeTruthy();
  });

  it("shows a Fabric port with its switch port and its circuits on a click", async () => {
    const user = await pick();
    await user.click(screen.getByText("ACME-XX1-EXT-PRI-01"));
    const panel = await screen.findByRole("complementary", { name: "Details" });
    expect(panel.textContent).toContain("Ethernet1/3");
    expect(panel.textContent).toContain("21000001");
    const rows = within(panel).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.querySelector("td")?.textContent)).toEqual([
      "XX_CLOUD_100EVPL_VC, 1000 Mbit/s",
      "XX_CLOUD_101EVPL_VC, 1000 Mbit/s",
    ]);
  });

  it("says when a Fabric port has no switch port", async () => {
    const user = await pick();
    await user.click(screen.getByText("ACME-XX2-INT-PRI-01"));
    const panel = await screen.findByRole("complementary", { name: "Details" });
    expect(within(panel).getByText("none")).toBeTruthy();
  });

  it("opens a catalog query in Explore with the metro", async () => {
    const user = await pick();
    await user.click(screen.getByRole("radio", { name: "Queries" }));
    await user.click(screen.getAllByRole("button", { name: "Open in Explore" })[1]);
    expect(openQuery).toHaveBeenCalledWith("equinix-circuits", false, { metro: "XX" });
  });

  it("says when the run has no Fabric port", async () => {
    apiMock.mockImplementation(() => Promise.resolve({ metros: [], queries: [] }));
    mount();
    expect(await screen.findByText("No Fabric port in the pinned run")).toBeTruthy();
  });
});

describe("EquinixPage text", () => {
  const far = (node: string, metro: string) => ({
    kind: "port" as const,
    node,
    name: node,
    ibx: `${metro}1`,
    metro,
    device: null,
    device_name: null,
    tag: 300,
  });

  it("counts a circuit with no end on the picture without the word live", async () => {
    const circuit = {
      uid: "vc:yy-zz",
      name: "YY_ZZ_300",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 100,
      cabled: false,
      a: far("eqx:port:yy2", "YY"),
      z: far("eqx:port:zz", "ZZ"),
    };
    apiMock.mockImplementation((path: string) =>
      Promise.resolve(path === "/equinix/metros" ? METROS : { ...METRO, circuits: [...METRO.circuits, circuit] }),
    );
    await pick();
    expect(await screen.findByText(/1 circuit not drawn/)).toBeTruthy();
  });

  it("does not use the word live", async () => {
    await pick();
    expect(document.body.textContent ?? "").not.toMatch(/\blive\b/i);
  });
});

describe("EquinixPage from the keyboard", () => {
  it("opens a Fabric port's details with Enter", async () => {
    const user = await pick();
    const port = screen.getByRole("button", { name: "ACME-XX1-EXT-PRI-01" });
    port.focus();
    await user.keyboard("{Enter}");
    const panel = await screen.findByRole("complementary", { name: "Details" });
    expect(panel.textContent).toContain("Ethernet1/3");
  });
});
