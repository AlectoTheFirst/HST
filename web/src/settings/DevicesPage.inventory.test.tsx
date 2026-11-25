/**
 * The device inventory names where each device came from and the place its
 * source reports, and assigns many devices to one site in a single pass.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN } from "../test/fixtures";
import DevicesPage from "./DevicesPage";

const DEVICES = [
  {
    uid: "dev:ap1",
    hostname: "ap1",
    platform: "unifi-uap",
    site: null,
    can_place: true,
    graph_site: null,
    source: "unifi1",
    location_id: "default",
    location_name: "Office",
  },
  {
    uid: "dev:ap2",
    hostname: "ap2",
    platform: "unifi-uap",
    site: null,
    can_place: true,
    graph_site: null,
    source: "unifi1",
    location_id: "branch",
    location_name: "Branch office",
  },
  {
    uid: "dev:core1",
    hostname: "core1",
    platform: "vyos",
    site: "dcber1",
    can_place: false,
    graph_site: "dcber1",
    source: "edge",
    location_id: "",
    location_name: "",
  },
];

function setup(assigned: { device_uid: string; site: string | null }[]) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({
      status: 200,
      body: { sites: [{ code: "dcber1", name: "Berlin", location: "", device_count: 1 }] },
    }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: DEVICES } }),
    "GET /api/sources": () => ({ status: 200, body: { sources: [] } }),
    "GET /api/source-types": () => ({ status: 200, body: { types: [] } }),
    "POST /api/sites/assign": (request) => {
      assigned.push(request.body as { device_uid: string; site: string | null });
      return { status: 200, body: { detail: "ok" } };
    },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <DevicesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

it("names the source and the reported location of every device", async () => {
  setup([]);
  const row = (await screen.findByText("ap1")).closest("tr") as HTMLElement;
  expect(within(row).getByText("unifi1")).toBeInTheDocument();
  expect(within(row).getByText("Office")).toBeInTheDocument();

  const core = (await screen.findByText("core1")).closest("tr") as HTMLElement;
  expect(within(core).getByText("edge")).toBeInTheDocument();
});

it("filters the inventory by reported location", async () => {
  const user = setup([]);
  await screen.findByText("ap1");

  await user.selectOptions(screen.getByLabelText("Reported location"), "unifi1 branch");
  expect(screen.getByText("ap2")).toBeInTheDocument();
  expect(screen.queryByText("ap1")).not.toBeInTheDocument();
  expect(screen.queryByText("core1")).not.toBeInTheDocument();
});

it("places every selected device at one site in a single pass", async () => {
  const assigned: { device_uid: string; site: string | null }[] = [];
  const user = setup(assigned);
  await screen.findByText("ap1");

  await user.click(screen.getByLabelText("Select ap1"));
  await user.click(screen.getByLabelText("Select ap2"));
  await user.selectOptions(screen.getByLabelText("Place selected at"), "dcber1");
  await user.click(screen.getByRole("button", { name: "Place 2 selected" }));

  expect(assigned).toEqual([
    { device_uid: "dev:ap1", site: "dcber1" },
    { device_uid: "dev:ap2", site: "dcber1" },
  ]);
});

it("keeps two orchestrators apart when they report the same location id", async () => {
  // UniFi names its first site "default".
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({ status: 200, body: { sites: [] } }),
    "GET /api/sites/devices": () => ({
      status: 200,
      body: {
        devices: [
          { uid: "dev:a", hostname: "north-ap", platform: "unifi-uap", site: null,
            can_place: true, graph_site: null, source: "unifi-north", location_id: "default",
            location_name: "Head office" },
          { uid: "dev:b", hostname: "south-ap", platform: "unifi-uap", site: null,
            can_place: true, graph_site: null, source: "unifi-south", location_id: "default",
            location_name: "Depot" },
        ],
      },
    }),
    "GET /api/sources": () => ({ status: 200, body: { sources: [] } }),
    "GET /api/source-types": () => ({ status: 200, body: { types: [] } }),
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <DevicesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  await screen.findByText("north-ap");

  expect(screen.getByRole("option", { name: "Head office" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "Depot" })).toBeInTheDocument();

  await user.selectOptions(screen.getByLabelText("Reported location"), "unifi-south default");
  expect(screen.getByText("south-ap")).toBeInTheDocument();
  expect(screen.queryByText("north-ap")).not.toBeInTheDocument();
});

it("names the devices a bulk assignment could not place, and keeps them selected", async () => {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({
      status: 200,
      body: { sites: [{ code: "dcber1", name: "Berlin", location: "", device_count: 1 }] },
    }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: DEVICES } }),
    "GET /api/sources": () => ({ status: 200, body: { sources: [] } }),
    "GET /api/source-types": () => ({ status: 200, body: { types: [] } }),
    // the first device of the pass is refused; the rest must still be tried
    "POST /api/sites/assign": (request) => {
      const body = request.body as { device_uid: string };
      return body.device_uid === "dev:ap1"
        ? { status: 409, body: { error: "dev:ap1 is gone" } }
        : { status: 200, body: {} };
    },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <DevicesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  await screen.findByText("ap1");

  await user.click(screen.getByLabelText("Select ap1"));
  await user.click(screen.getByLabelText("Select ap2"));
  await user.selectOptions(screen.getByLabelText("Place selected at"), "dcber1");
  await user.click(screen.getByRole("button", { name: "Place 2 selected" }));

  expect(await screen.findByText(/Not placed: ap1/)).toBeInTheDocument();
  expect(screen.getByLabelText("Select ap1")).toBeChecked();
  expect(screen.getByLabelText("Select ap2")).not.toBeChecked();
});

it("offers a picker only where a placement would be accepted", async () => {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({
      status: 200,
      body: { sites: [{ code: "DCBER1", name: "Berlin", location: "", device_count: 3 }] },
    }),
    "GET /api/sites/devices": () => ({
      status: 200,
      body: {
        devices: [
          // its group puts it there, and no control here can move it
          { uid: "dev:core1", hostname: "core1", platform: "vyos", site: "DCBER1",
            hand_placed: false, can_place: false, source: "vyos-lts",
            location_id: "", location_name: "" },
          // its bound location puts it there, and a person may overrule that
          { uid: "dev:ap1", hostname: "ap1", platform: "unifi-uap", site: "DCBER1",
            hand_placed: false, can_place: true, source: "unifi1",
            location_id: "default", location_name: "default" },
        ],
      },
    }),
    "GET /api/sources": () => ({ status: 200, body: { sources: [] } }),
    "GET /api/source-types": () => ({ status: 200, body: { types: [] } }),
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <DevicesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );

  await screen.findByText("core1");
  const table = within(screen.getByRole("table"));
  expect(table.queryByRole("combobox", { name: "Site for core1" })).not.toBeInTheDocument();
  expect(table.getByRole("combobox", { name: "Site for ap1" })).toBeInTheDocument();
  const core = (await screen.findByText("core1")).closest("tr") as HTMLElement;
  expect(within(core).getByText("DCBER1")).toBeInTheDocument();
  // nothing may be ticked for a bulk placement that would be refused
  expect(screen.queryByLabelText("Select core1")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Select ap1")).toBeInTheDocument();
});
