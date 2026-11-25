/** A site's site group and its named blocks, saved through the inventory site patch. */

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockRequest } from "../../test/fetchMock";
import { InventorySitesPage } from "./SitesPage";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { username: "ada", permissions: ["graph.read", "sites.write"] }, loading: false }) }));

const fra = { id: "1", code: "fra", name: "Frankfurt", location: "", lat: null, lon: null, site_group: null, blocks: null, revision: 3, device_count: 2, location_count: 0 };
const ams = {
  id: "2", code: "ams", name: "Amsterdam", location: "", lat: null, lon: null,
  site_group: "Area A / Area A3", blocks: [{ name: "edge", zone: null, devices: ["dev:3"] }],
  revision: 5, device_count: 1, location_count: 0,
};
const SITES = [fra, ams];

// The device pages of each site id, one page per cursor.
const DEVICES: Record<string, Array<Array<{ graph_uid: string; hostname: string }>>> = {
  "1": [[{ graph_uid: "dev:1", hostname: "fra-gw" }], [{ graph_uid: "dev:2", hostname: "fra-fw" }]],
  "2": [[{ graph_uid: "dev:3", hostname: "ams-gw" }]],
};

function mount() {
  const patches: Array<{ id: string; body: unknown }> = [];
  const deviceQueries: string[] = [];
  const answer = (site: (typeof SITES)[number]) => (req: MockRequest) => {
    patches.push({ id: site.id, body: req.body });
    return { body: { ...site, ...(req.body as object), revision: site.revision + 1 } };
  };
  mockApi({
    "GET /api/inventory/sites/search": () => ({ body: { items: SITES, total: 2, offset: 0, limit: 50 } }),
    "GET /api/inventory/sites": () => ({ body: SITES }),
    "GET /api/inventory/devices": () => {
      const url = new URL(String(vi.mocked(fetch).mock.calls.at(-1)?.[0]), "http://localhost");
      deviceQueries.push(url.search);
      const pages = DEVICES[url.searchParams.get("site_id") ?? ""] ?? [[]];
      const index = Number(url.searchParams.get("cursor") ?? 0);
      return { body: { items: pages[index], next_cursor: index + 1 < pages.length ? String(index + 1) : null, generation: {} } };
    },
    "PATCH /api/inventory/sites/1": answer(fra),
    "PATCH /api/inventory/sites/2": answer(ams),
  });
  sessionStorage.clear();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/inventory/sites"]}>
    <Routes><Route path="/inventory/sites" element={<InventorySitesPage />} /></Routes>
  </MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), patches, deviceQueries };
}

const offered = (input: HTMLElement) => {
  const list = input.getAttribute("list");
  return list ? [...document.getElementById(list)!.querySelectorAll("option")].map(o => o.getAttribute("value")) : [];
};

describe("site group and named blocks", () => {
  it("sets a site group, offering the paths the other sites use", async () => {
    const { user, patches } = mount();
    await user.click(await screen.findByRole("button", { name: "Edit fra" }));
    const field = screen.getByLabelText("Site group");
    expect(field).toHaveValue("");
    expect(offered(field)).toEqual([]);
    await user.click(field);
    await waitFor(() => expect(offered(field)).toEqual(["Area A / Area A3"]));
    await user.type(field, "Area A / Area A1");
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { id: "1", body: { name: "Frankfurt", location: "", expected_revision: 3, site_group: "Area A / Area A1" } },
    ]));
  });

  it("clears the site group with an empty box", async () => {
    const { user, patches } = mount();
    await user.click(await screen.findByRole("button", { name: "Edit ams" }));
    const field = screen.getByLabelText("Site group");
    expect(field).toHaveValue("Area A / Area A3");
    await user.clear(field);
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { id: "2", body: { name: "Amsterdam", location: "", expected_revision: 5, site_group: null } },
    ]));
  });

  it("leaves the site group and the blocks out of a patch that does not change them", async () => {
    const { user, patches } = mount();
    await user.click(await screen.findByRole("button", { name: "Edit ams" }));
    const name = screen.getByLabelText("Site name");
    await user.type(name, " DC");
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { id: "2", body: { name: "Amsterdam DC", location: "", expected_revision: 5 } },
    ]));
  });

  it("puts the devices placed at the site in named blocks and shows one another block holds as taken", async () => {
    const { user, patches, deviceQueries } = mount();
    await user.click(await screen.findByRole("button", { name: "Edit fra" }));
    expect(screen.getByText(/No named blocks/)).toBeInTheDocument();
    expect(deviceQueries).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Add named blocks" }));
    const editor = screen.getByRole("group", { name: "Named blocks at fra" });

    await user.click(within(editor).getByRole("button", { name: "Add block" }));
    const first = within(editor).getByRole("group", { name: "Block 1" });
    await user.type(within(first).getByLabelText("Block name"), "core");
    await user.selectOptions(within(first).getByLabelText("Zone"), "internal");
    await user.click(await within(first).findByRole("checkbox", { name: /fra-gw/ }));
    // the second page of the site's devices is read too, and a device of another site is not offered
    expect(within(first).getByRole("checkbox", { name: /fra-fw/ })).not.toBeChecked();
    expect(within(first).queryByRole("checkbox", { name: /ams-gw/ })).not.toBeInTheDocument();
    expect(deviceQueries).toEqual(["?site_id=1&limit=200", "?site_id=1&limit=200&cursor=1"]);

    await user.click(within(editor).getByRole("button", { name: "Add block" }));
    const second = within(editor).getByRole("group", { name: "Block 2" });
    await user.type(within(second).getByLabelText("Block name"), " DMZ ");
    await user.selectOptions(within(second).getByLabelText("Zone"), "external");
    const taken = within(second).getByRole("checkbox", { name: /fra-gw/ });
    expect(taken).toBeDisabled();
    expect(taken.closest("label")).toHaveTextContent("fra-gw (in core)");
    await user.click(within(second).getByRole("checkbox", { name: /fra-fw/ }));

    await user.click(within(editor).getByRole("button", { name: "Add block" }));
    const third = within(editor).getByRole("group", { name: "Block 3" });
    await user.type(within(third).getByLabelText("Block name"), "uplink");
    await user.selectOptions(within(third).getByLabelText("Zone"), "internet");
    expect(within(third).getByLabelText("Zone")).toHaveValue("internet");

    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      {
        id: "1",
        body: {
          name: "Frankfurt", location: "", expected_revision: 3,
          blocks: [
            { name: "core", zone: "internal", devices: ["dev:1"] },
            { name: "DMZ", zone: "external", devices: ["dev:2"] },
            { name: "uplink", zone: "internet", devices: [] },
          ],
        },
      },
    ]));
  });

  it("refuses to save two blocks of one name", async () => {
    const { user } = mount();
    await user.click(await screen.findByRole("button", { name: "Edit ams" }));
    expect(screen.getByText(/Named blocks: edge \(1 device\)/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Edit named blocks" }));
    const editor = screen.getByRole("group", { name: "Named blocks at ams" });
    await user.click(within(editor).getByRole("button", { name: "Add block" }));
    const name = within(within(editor).getByRole("group", { name: "Block 2" })).getByLabelText("Block name");
    await user.type(name, "EDGE");
    expect(screen.getByRole("button", { name: "Save site" })).toBeDisabled();
    await user.clear(name);
    await user.type(name, "dmz");
    expect(screen.getByRole("button", { name: "Save site" })).toBeEnabled();
  });

  it("clears the blocks by removing the last one", async () => {
    const { user, patches } = mount();
    await user.click(await screen.findByRole("button", { name: "Edit ams" }));
    await user.click(screen.getByRole("button", { name: "Edit named blocks" }));
    const editor = screen.getByRole("group", { name: "Named blocks at ams" });
    const only = within(editor).getByRole("group", { name: "Block 1" });
    expect(within(only).getByLabelText("Block name")).toHaveValue("edge");
    expect(await within(only).findByRole("checkbox", { name: /ams-gw/ })).toBeChecked();
    await user.click(within(only).getByRole("button", { name: "Remove block" }));
    await user.click(screen.getByRole("button", { name: "Save site" }));
    await waitFor(() => expect(patches).toEqual([
      { id: "2", body: { name: "Amsterdam", location: "", expected_revision: 5, blocks: null } },
    ]));
  });
});
