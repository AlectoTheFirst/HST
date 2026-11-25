import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_ADMIN, ME_OPERATOR } from "../test/fixtures";
import SitesPage from "./SitesPage";

it("states the routing scope a site groups its VRFs by, and clears it back to the site code", async () => {
  let patched: unknown;
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/sites": () => ({ status: 200, body: { sites: [{ code: "fra", name: "Frankfurt", location: "", device_count: 0, params: { routing_scope: "wan" } }] } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
    "PATCH /api/sites/fra": (request) => {
      const body = request.body as { params: { routing_scope: string | null } };
      patched = body;
      return { status: 200, body: { code: "fra", name: "Frankfurt", location: "", device_count: 0, params: body.params } };
    },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><AuthProvider><SitesPage /></AuthProvider></MemoryRouter></QueryClientProvider>);
  const user = userEvent.setup();

  expect(await screen.findByText(/Routing scope/)).toHaveTextContent("wan");
  expect(screen.queryByText(/L2 fabric/i)).not.toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Change" }));
  await user.clear(screen.getByLabelText("Routing scope"));
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(patched).toEqual({ params: { routing_scope: null } });
});

it("keeps network identity defaults out of the operator site form", async () => {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
    "GET /api/sites": () => ({ status: 200, body: { sites: [] } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><AuthProvider><SitesPage /></AuthProvider></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByLabelText("Code")).toBeInTheDocument();
  expect(screen.queryByLabelText("Default routing scope")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Default L2 fabric")).not.toBeInTheDocument();
});
