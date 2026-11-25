/** A site lists the groups that collect at it, and moves a group onto itself. */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN } from "../test/fixtures";
import SitesPage from "./SitesPage";

const SITES = [
  { code: "fra", name: "Frankfurt", location: "", device_count: 0, params: {} },
  { code: "ams", name: "Amsterdam", location: "", device_count: 0, params: {} },
];

const SOURCES = [
  { name: "edge", type: "vyos", kind: "group", config: { site_code: "ams" }, secrets: {}, enabled: true, updated_at: null },
  { name: "here", type: "nxos", kind: "group", config: { site_code: "fra" }, secrets: {}, enabled: true, updated_at: null },
  { name: "unifi1", type: "unifi", kind: "orchestrator", config: {}, secrets: {}, enabled: true, updated_at: null },
];

function setup(onPatch: (name: string, body: unknown) => void) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({ status: 200, body: { sites: SITES } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
    "GET /api/sources": () => ({ status: 200, body: { sources: SOURCES } }),
    "PATCH /api/sources/edge": (request) => {
      onPatch("edge", request.body);
      return { status: 200, body: { ...SOURCES[0], config: { site_code: "fra" } } };
    },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <SitesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

it("moves a group onto the selected site and leaves orchestrators out", async () => {
  let patched: unknown = null;
  const user = setup((_name, body) => {
    patched = body;
  });

  await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
  const block = await screen.findByRole("group", { name: "Groups at fra" });

  // the orchestrator is not a group and never appears here
  expect(within(block).queryByText(/unifi1/)).not.toBeInTheDocument();

  // the group already here is listed; the one elsewhere is only in the picker
  expect(within(block).getByText(/here \(nxos\)/)).toBeInTheDocument();
  expect(within(block).queryByText(/edge \(vyos\)/)).not.toBeInTheDocument();

  await user.selectOptions(screen.getByLabelText("Move a group here"), "edge");
  await user.click(screen.getByRole("button", { name: "Move here" }));
  expect(patched).toEqual({ config: { site_code: "fra" } });
  expect(block).toBeInTheDocument();
});

it("binds a reported location to the selected site and unbinds one", async () => {
  const patched: { url: string; body: unknown }[] = [];
  const locations = [
    { source: "unifi1", location_id: "default", name: "Office", site: "fra", device_count: 2 },
    { source: "unifi1", location_id: "branch", name: "Branch office", site: null, device_count: 3 },
  ];
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({ status: 200, body: { sites: SITES } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
    "GET /api/sources": () => ({ status: 200, body: { sources: SOURCES } }),
    "GET /api/locations": () => ({ status: 200, body: { locations } }),
    "PATCH /api/locations/unifi1/branch": (request) => {
      patched.push({ url: "branch", body: request.body });
      return { status: 200, body: { detail: "ok" } };
    },
    "PATCH /api/locations/unifi1/default": (request) => {
      patched.push({ url: "default", body: request.body });
      return { status: 200, body: { detail: "ok" } };
    },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <SitesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();

  await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
  await screen.findByRole("group", { name: "Reported locations at fra" });

  await user.click(screen.getByRole("button", { name: "Bind Branch office to fra" }));
  await user.click(screen.getByRole("button", { name: "Unbind Office" }));

  expect(patched).toEqual([
    { url: "branch", body: { site: "fra" } },
    { url: "default", body: { site: null } },
  ]);
});

it("clears a group's site when it is removed from the site", async () => {
  let patched: unknown = null;
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({ status: 200, body: { sites: SITES } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
    "GET /api/sources": () => ({ status: 200, body: { sources: SOURCES } }),
    "GET /api/locations": () => ({ status: 200, body: { locations: [] } }),
    "PATCH /api/sources/here": (request) => {
      patched = request.body;
      return { status: 200, body: { ...SOURCES[1], config: { site_code: "" } } };
    },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>
          <SitesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();

  await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
  await user.click(await screen.findByRole("button", { name: "Remove here from fra" }));

  // an empty site_code is the unplaced state
  expect(patched).toEqual({ config: { site_code: "" } });
});
