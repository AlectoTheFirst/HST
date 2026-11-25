import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { expect, it } from "vitest";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { metroOf } from "./metros";
import SitesPage from "./SitesPage";

function mount(sites: unknown[], onPatch: (body: unknown) => void) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
    "GET /api/sites": () => ({ status: 200, body: { sites } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
    "PATCH /api/sites/FR2": (request) => {
      onPatch(request.body);
      const body = request.body as { params: Record<string, unknown> };
      return { status: 200, body: { ...(sites[0] as object), params: body.params } };
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
}

it("reads an IBX code as its metro", () => {
  expect(metroOf("FR2")?.name).toBe("Frankfurt");
  expect(metroOf("am3")?.name).toBe("Amsterdam");
  expect(metroOf("DC11")?.name).toBe("Washington DC");
  expect(metroOf("hq")).toBeNull();
  expect(metroOf("DEU-FRA-1")).toBeNull();
  expect(metroOf("XX1")).toBeNull();
});

it("lets an operator place a site, offering the metro its code names", async () => {
  let patched: unknown;
  mount([{ code: "FR2", name: "Equinix FR2", location: "", device_count: 0, params: { routing_scope: "ACME-EMEA" } }], (b) => {
    patched = b;
  });
  const user = userEvent.setup();
  expect(await screen.findByText("Not on the map")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Place on map" }));
  // the pair is required: one box filled saves nothing
  await user.type(screen.getByLabelText("Latitude"), "50");
  expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Use Frankfurt" }));
  expect(screen.getByLabelText("Latitude")).toHaveValue("50.11");
  expect(screen.getByLabelText("Longitude")).toHaveValue("8.68");
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(patched).toEqual({ params: { lat: 50.11, lon: 8.68 } });
});

it("states where a placed site is and clears it with empty boxes", async () => {
  let patched: unknown;
  mount([{ code: "FR2", name: "Equinix FR2", location: "", device_count: 0, params: { lat: 50.11, lon: 8.68 } }], (b) => {
    patched = b;
  });
  const user = userEvent.setup();
  expect(await screen.findByText(/On the map at/)).toHaveTextContent("50.11, 8.68");
  await user.click(screen.getByRole("button", { name: "Move" }));
  await user.clear(screen.getByLabelText("Latitude"));
  await user.clear(screen.getByLabelText("Longitude"));
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(patched).toEqual({ params: { lat: null, lon: null } });
});
