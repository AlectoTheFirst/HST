import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockRequest } from "../../test/fetchMock";
import { parseCsv, toCsv } from "../ui/csv";
import { InventorySitesPage } from "./SitesPage";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { username: "ada", permissions: ["graph.read", "sites.write"] }, loading: false }) }));

const site = { id: "2", code: "FRA", name: "Frankfurt", location: "Germany", revision: 5, device_count: 2, location_count: 1 };
const counts = { all: 2, mapped: 0, unmapped: 2, suggested: 2 };
const row = (id: string, name: string) => ({
  location: { id, connection_id: "1", source_key: "vco", location_id: `loc-${id}`, name, site_id: null, site_code: null, revision: 3, device_count: 1 },
  suggestion: { site_id: "2", site_code: "FRA", rule: "code_in_name" },
});

function mount(entry = "/inventory/sites") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>
    <Routes><Route path="/inventory/sites" element={<InventorySitesPage />} /></Routes>
  </MemoryRouter></QueryClientProvider>);
}

describe("CSV", () => {
  it("reads quotes, a semicolon delimiter, a byte order mark and CRLF line ends", () => {
    expect(parseCsv('﻿code;name\r\nfra;"Frankfurt; Main"\r\n\r\nams;"Say ""hi"""\r\n')).toEqual([
      ["code", "name"], ["fra", "Frankfurt; Main"], ["ams", 'Say "hi"'],
    ]);
    expect(parseCsv(toCsv([["a", "b,c"], ["d\ne", null]]))).toEqual([["a", "b,c"], ["d\ne", ""]]);
  });

  it("writes a single quote in front of a text cell that a spreadsheet runs as a formula", () => {
    expect(toCsv([["=1+1", "+1", "-1", "@a", "\tb", "\rc"], ["a=b", -5, "'s-Hertogenbosch"]])).toBe(
      "'=1+1,'+1,'-1,'@a,'\tb,\"'\rc\"\r\na=b,-5,'s-Hertogenbosch\r\n",
    );
  });

  it("reads an exported file back to the exported cells", () => {
    const rows = [["code", "name"], ["=1+1", "+1"], ["-1", "@a"], ["\tb", "\rc"], ["'=1", "''-1"], ["'s-Hertogenbosch", "a=b"]];
    expect(parseCsv(toCsv(rows))).toEqual(rows);
  });
});

describe("site bulk work", () => {
  it("checks a site import first and applies it when no row is refused", async () => {
    const calls: Array<Record<string, unknown>> = [];
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, offset: 0, limit: 50 } }),
      "POST /api/inventory/sites/import": (req: MockRequest) => {
        const body = req.body as Record<string, unknown>;
        calls.push(body);
        return { body: { applied: !body.dry_run, created: 1, updated: 1, unchanged: 0, errors: 0, rows: [] } };
      },
    });
    mount();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Import CSV" }));
    const dialog = screen.getByRole("dialog", { name: "Import CSV" });
    const text = within(dialog).getByLabelText("CSV text");
    await user.click(text);
    await user.paste("code,name,location\nber,Berlin,\nbad code,Nowhere,\n");
    await user.click(within(dialog).getByRole("button", { name: "Check file" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent('Row 3: site code bad code not valid');
    expect(calls).toHaveLength(0);
    await user.clear(text);
    await user.click(text);
    await user.paste("code,name,location\nber,Berlin,\nFRA,Frankfurt am Main,\n");
    await user.click(within(dialog).getByRole("button", { name: "Check file" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toEqual({ sites: [{ code: "ber", name: "Berlin" }, { code: "FRA", name: "Frankfurt am Main" }], dry_run: true });
    await user.click(within(dialog).getByRole("button", { name: "Apply" }));
    expect(await within(dialog).findByText("1 site created, 1 site updated")).toBeInTheDocument();
    expect(calls[1]).toEqual({ sites: calls[0].sites });
  });

  it("accepts every suggested site across pages after one confirmation", async () => {
    const searches: string[] = [];
    const binds: Array<Record<string, unknown>> = [];
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, offset: 0, limit: 50 } }),
      "GET /api/inventory/locations/search": () => {
        searches.push(String(vi.mocked(fetch).mock.calls.at(-1)?.[0]));
        return { body: { items: [row("a", "FRA edge 1"), row("b", "FRA edge 2")], total: 2, offset: 0, limit: 50, counts, connections: [] } };
      },
      "POST /api/inventory/locations/bindings": (req: MockRequest) => {
        const body = req.body as { bindings: unknown[]; dry_run?: boolean };
        binds.push(body);
        return { body: { applied: !body.dry_run, changed: 2, unchanged: 0, errors: 0, devices_recomputed: 2, rows: [] } };
      },
    });
    mount("/inventory/sites?tab=locations");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Accept 2 suggested sites" }));
    const dialog = await screen.findByRole("dialog", { name: "Accept suggested sites" });
    expect(searches.some(url => url.includes("state=suggested") && url.includes("limit=1000"))).toBe(true);
    const bindings = [
      { id: "a", site_id: "2", expected_revision: 3 },
      { id: "b", site_id: "2", expected_revision: 3 },
    ];
    expect(binds).toEqual([{ bindings, dry_run: true }]);
    await user.click(within(dialog).getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("2 locations changed, 2 devices placed again")).toBeInTheDocument();
    expect(binds[1]).toEqual({ bindings });
  });

  it("does not offer Apply when the dry run refuses a row", async () => {
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, offset: 0, limit: 50 } }),
      "GET /api/inventory/locations/search": () => ({ body: { items: [row("a", "FRA edge 1")], total: 1, offset: 0, limit: 50, counts: { ...counts, suggested: 1 }, connections: [] } }),
      "POST /api/inventory/locations/bindings": () => ({ body: { applied: false, changed: 0, unchanged: 0, errors: 1, devices_recomputed: 0, rows: [
        { index: 0, id: "a", source_key: "vco", location_id: "loc-a", name: "FRA edge 1", site_before: null, site_after: null, status: "error", error: "the location changed; current revision 4" },
      ] } }),
    });
    mount("/inventory/sites?tab=locations");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Accept 1 suggested site" }));
    const dialog = await screen.findByRole("dialog", { name: "Accept suggested sites" });
    expect(within(dialog).getByText(/the location changed; current revision 4/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Apply" })).toBeDisabled();
  });
});
