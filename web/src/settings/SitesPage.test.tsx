import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SitesPage from "./SitesPage";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR, ME_VIEWER } from "../test/fixtures";
import type { MockRequest } from "../test/fetchMock";

const SITES = [
  {
    code: "DEU-FRA-123123",
    name: "Frankfurt",
    location: "Example Street 1",
    device_count: 1,
    group_count: 2,
    location_count: 1,
    placed_count: 1,
  },
  {
    code: "NLD-AMS-9",
    name: "Amsterdam",
    location: "",
    device_count: 0,
    group_count: 0,
    location_count: 0,
    placed_count: 0,
  },
];

const DEVICES = [
  // a controller device a person moved here
  {
    uid: "dev:1",
    hostname: "fra-gw",
    platform: "unifi-uap",
    site: "DEU-FRA-123123",
    hand_placed: true,
    can_place: true,
    source: "unifi1",
    location_name: "Office",
  },
  // a controller device whose location is not bound yet
  {
    uid: "dev:2",
    hostname: "spare",
    platform: "unifi-uap",
    site: null,
    hand_placed: false,
    can_place: true,
    source: "unifi1",
  },
  // a group device: its site is its group's, and nothing here can move it
  {
    uid: "dev:3",
    hostname: "ams-gw",
    platform: "vyos",
    site: "NLD-AMS-9",
    hand_placed: false,
    can_place: false,
    source: "edge",
  },
];

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <SitesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mock(me = ME_OPERATOR, extra: Record<string, unknown> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: me }),
    "GET /api/sites": () => ({ status: 200, body: { sites: SITES } }),
    "GET /api/sites/devices": () => ({ status: 200, body: { devices: DEVICES } }),
    ...extra,
  });
}

describe("SitesPage", () => {
  it("lists sites with their device counts", async () => {
    mock();
    renderPage();

    expect(await screen.findByText("DEU-FRA-123123")).toBeInTheDocument();
    expect(screen.getByText("Frankfurt")).toBeInTheDocument();
    expect(screen.getByText("Example Street 1")).toBeInTheDocument();
    expect(screen.getByText("1 device")).toBeInTheDocument();
    expect(screen.getByText("0 devices")).toBeInTheDocument();
  });

  it("accepts any site code the operator uses", async () => {
    const bodies: unknown[] = [];
    mock(ME_OPERATOR, {
      "POST /api/sites": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 201, body: { code: "x", name: "", location: "", device_count: 0 } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.type(await screen.findByLabelText("Code"), "DEU-BER-7");
    await user.type(screen.getByLabelText("Name"), "Berlin");
    await user.click(screen.getByRole("button", { name: "Add site" }));

    expect(bodies).toEqual([{ code: "DEU-BER-7", name: "Berlin", location: "" }]);
  });

  it("shows the error of a duplicate code", async () => {
    mock(ME_OPERATOR, {
      "POST /api/sites": () => ({ status: 409, body: { error: "site hq already exists" } }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.type(await screen.findByLabelText("Code"), "hq");
    await user.click(screen.getByRole("button", { name: "Add site" }));
    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
  });

  it("places a controller device at a site by hand", async () => {
    const bodies: unknown[] = [];
    mock(ME_OPERATOR, {
      "POST /api/sites/assign": (req: MockRequest) => {
        bodies.push(req.body);
        return {
          status: 200,
          body: {
            ...(req.body as object),
            detail: "the placement appears in the graph at the next collection run",
          },
        };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Site for spare" }),
      "DEU-FRA-123123",
    );
    expect(bodies).toEqual([{ device_uid: "dev:2", site: "DEU-FRA-123123" }]);
  });

  it("clears a hand placement, returning the device to its reported location", async () => {
    const bodies: unknown[] = [];
    mock(ME_OPERATOR, {
      "POST /api/sites/assign": (req: MockRequest) => {
        bodies.push(req.body);
        return {
          status: 200,
          body: {
            ...(req.body as object),
            detail: "the placement appears in the graph at the next collection run",
          },
        };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
    await user.selectOptions(screen.getByRole("combobox", { name: "Site for fra-gw" }), "");
    expect(bodies).toEqual([{ device_uid: "dev:1", site: null }]);
  });

  it("shows the devices at this site and the unplaced devices", async () => {
    mock();
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
    const table = within(screen.getByRole("table"));
    expect(table.getByText("fra-gw")).toBeInTheDocument();
    expect(table.getByText("spare")).toBeInTheDocument();
    expect(table.queryByText("ams-gw")).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Show devices at other sites" }));
    expect(table.getByText("ams-gw")).toBeInTheDocument();
  });

  it("gives a viewer no way to change anything", async () => {
    mock(ME_VIEWER);
    renderPage();

    expect(await screen.findByText("DEU-FRA-123123")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add site" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rename" })).not.toBeInTheDocument();
  });

  it("shows the error of a failed placement", async () => {
    mock(ME_OPERATOR, {
      "POST /api/sites/assign": () => ({
        status: 422,
        body: { error: "unknown device dev:2" },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Site for spare" }),
      "DEU-FRA-123123",
    );
    expect(await screen.findByText(/unknown device dev:2/)).toBeInTheDocument();
  });

  it("lists what a person placed here by hand, and clears one", async () => {
    const bodies: unknown[] = [];
    mock(ME_OPERATOR, {
      "POST /api/sites/assign": (req: MockRequest) => {
        bodies.push(req.body);
        return { status: 200, body: { detail: "ok" } };
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Devices" }))[0]);
    const block = screen.getByRole("group", { name: /placed by hand/i });
    expect(within(block).getByText(/fra-gw/)).toBeInTheDocument();
    expect(within(block).queryByText(/ams-gw/)).not.toBeInTheDocument();

    await user.click(within(block).getByRole("button", { name: /clear the placement of fra-gw/i }));
    expect(bodies).toEqual([{ device_uid: "dev:1", site: null }]);
  });

  it("says what a delete releases before it happens, and what it moved after", async () => {
    mock(ME_OPERATOR, {
      "DELETE /api/sites/DEU-FRA-123123": () => ({
        status: 200,
        body: {
          groups: ["edge", "core"],
          locations: [{ source: "unifi1", location_id: "default" }],
          devices: ["dev:1"],
        },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Delete" }))[0]);
    const ask = await screen.findByRole("group", { name: "Delete DEU-FRA-123123" });
    expect(ask).toHaveTextContent("2 groups");
    expect(ask).toHaveTextContent("1 reported location");
    expect(ask).toHaveTextContent("1 device placed by hand");

    await user.click(within(ask).getByRole("button", { name: "Delete DEU-FRA-123123" }));
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent("2 groups");
    expect(banner).toHaveTextContent("until the next collection run");
  });

  it("shows the error of a failed delete", async () => {
    mock(ME_OPERATOR, {
      "DELETE /api/sites/DEU-FRA-123123": () => ({
        status: 409,
        body: { error: "site DEU-FRA-123123 is mid-collection" },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Delete" }))[0]);
    await user.click(await screen.findByRole("button", { name: "Delete DEU-FRA-123123" }));
    expect(await screen.findByText(/mid-collection/)).toBeInTheDocument();
  });

  it("shows the error of a failed rename", async () => {
    mock(ME_OPERATOR, {
      "PATCH /api/sites/DEU-FRA-123123": () => ({
        status: 422,
        body: { error: "name too long" },
      }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Rename" }))[0]);
    const form = await screen.findByRole("group", { name: "Rename DEU-FRA-123123" });
    await user.click(within(form).getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/name too long/)).toBeInTheDocument();
  });

  it("shows the error of a failed load", async () => {
    mockApi({
      "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }),
      "GET /api/sites": () => ({ status: 500, body: { error: "postgres unreachable" } }),
      "GET /api/sites/devices": () => ({ status: 200, body: { devices: [] } }),
    });
    renderPage();
    expect(await screen.findByText(/postgres unreachable/)).toBeInTheDocument();
  });
});
