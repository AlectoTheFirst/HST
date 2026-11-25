import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { expect, it } from "vitest";
import { AuthProvider } from "../auth";
import type { SourceDeviceIn } from "../api/types";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN, ME_OPERATOR } from "../test/fixtures";
import DevicesPage from "./DevicesPage";

function setup(operator = false, inventoryFails = false) {
  let devices: SourceDeviceIn[] = [{ host: "r1", port: null, enabled: true }];
  const saved: SourceDeviceIn[][] = [];
  mockApi({
    "GET /api/me": () => ({ body: operator ? ME_OPERATOR : ME_ADMIN }),
    "GET /api/sites": () => ({ body: { sites: [] } }),
    "GET /api/sites/devices": () => inventoryFails ? { status: 503, body: { error: "Inventory unavailable" } } : { body: { devices: [] } },
    "GET /api/sources": () => ({ body: { sources: ["edge", "branch"].map((name) => ({ name, type: "vyos", kind: "group" })) } }),
    "GET /api/source-types": () => ({ body: { types: [{ type: "vyos", kind: "group", schema: { properties: { host: { type: "string" } } } }] } }),
    "GET /api/sources/edge/devices": () => ({ body: { devices } }),
    "GET /api/sources/branch/devices": () => ({ body: { devices: [] } }),
    "PUT /api/sources/edge/devices": ({ body }) => {
      devices = (body as { devices: SourceDeviceIn[] }).devices;
      saved.push(devices);
      return { body: { devices } };
    },
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter><AuthProvider><DevicesPage /></AuthProvider></MemoryRouter>
  </QueryClientProvider>);
  return { saved, user: userEvent.setup() };
}

it("adds and removes configured devices from the Devices page even when inventory is unavailable", async () => {
  const { saved, user } = setup(false, true);
  await user.click(await screen.findByRole("button", { name: "Add device" }));
  const hosts = screen.getAllByLabelText("Host");
  await user.type(hosts[1], "r2");
  await user.click(screen.getByRole("button", { name: "Save devices" }));
  await waitFor(() => expect(saved[0]?.map((device) => device.host)).toEqual(["r1", "r2"]));
  await user.click(await screen.findByRole("button", { name: "Remove r1" }));
  await user.click(screen.getByRole("button", { name: "Save devices" }));
  await waitFor(() => expect(saved[1]?.map((device) => device.host)).toEqual(["r2"]));
});

it("preserves unsaved device edits when switching groups", async () => {
  const { user } = setup();
  await user.click(await screen.findByRole("button", { name: "Add device" }));
  await user.type(screen.getAllByLabelText("Host")[1], "unsaved-router");
  await user.selectOptions(screen.getByLabelText("Group"), "branch");
  await user.selectOptions(screen.getByLabelText("Group"), "edge");
  expect(screen.getByDisplayValue("unsaved-router")).toBeVisible();
});

it("shows the configured devices read-only to an operator", async () => {
  setup(true);
  expect(await screen.findByDisplayValue("r1")).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Add device" })).not.toBeInTheDocument();
});
