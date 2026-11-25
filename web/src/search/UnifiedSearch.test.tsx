import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi } from "../test/fetchMock";
import UnifiedSearch from "./UnifiedSearch";
import type { SearchHit } from "./types";

const device = (n: number): SearchHit => ({
  kind: "device",
  key: `dev:edge${n}`,
  uid: `dev:edge${n}`,
  name: `edge${n}`,
  detail: "vyos",
  source: "graph",
  matched: "text",
  run: 7,
  source_run: null,
  target: { kind: "device", uid: `dev:edge${n}` },
  fields: {},
});

const ARP: SearchHit = {
  kind: "arp",
  key: "arp:1",
  uid: null,
  name: "10.1.2.7",
  detail: "",
  source: "arp",
  matched: "text",
  run: 7,
  source_run: "r7",
  target: { kind: "device", uid: "dev:edge1" },
  fields: { device: "edge1", device_uid: "dev:edge1", interface: "Gi0/1", ip: "10.1.2.7", mac: "aa:bb:cc:dd:ee:ff", vlan: 20, vrf: null },
};

const TYPED = {
  query: "edge",
  items: [],
  total: 10003,
  labels: [],
  mode: "text",
  snapshot: 7,
  kinds: [
    { kind: "device", count: 3, count_exact: true },
    { kind: "arp", count: 10000, count_exact: false },
  ],
  groups: {
    device: { items: [device(1), device(2)], next_cursor: "c1" },
    arp: { items: [ARP], next_cursor: null },
  },
  side_store: { available: true, approximate: false, capped: ["arp"], timed_out: [] },
};

const urls = () => vi.mocked(fetch).mock.calls.map(([input]) => new URL(String(input), "http://localhost"));

function mount(onOpen = vi.fn()) {
  render(<UnifiedSearch label="Find" defaultKinds={["device", "arp"]} onOpen={onOpen} />);
  return onOpen;
}

describe("UnifiedSearch", () => {
  it("asks for the typed answer with the page's kinds, and shows a chip per kind with its count", async () => {
    mockApi({ "GET /api/explore/search": () => ({ body: TYPED }) });
    const user = userEvent.setup();
    mount();
    await user.type(screen.getByRole("searchbox", { name: "Find" }), "edge");
    const chips = await screen.findByRole("group", { name: "Filter by kind" });
    expect(within(chips).getByRole("button", { name: "Devices 3" })).toBeInTheDocument();
    expect(within(chips).getByRole("button", { name: "ARP entries 10000+" })).toBeInTheDocument();
    const url = urls().at(-1)!;
    expect(url.pathname).toBe("/api/explore/search");
    expect(url.searchParams.get("q")).toBe("edge");
    expect(url.searchParams.get("typed")).toBe("true");
    expect(url.searchParams.getAll("kind")).toEqual(["device", "arp"]);

    // a side-store row in one line, with its table
    const arp = within(screen.getByRole("list", { name: "ARP entries" })).getByRole("button");
    expect(arp).toHaveTextContent("10.1.2.7 at aa:bb:cc:dd:ee:ff on edge1 Gi0/1, VLAN 20");
    expect(arp).toHaveTextContent("ARP table");

    await user.click(within(chips).getByRole("button", { name: "ARP entries 10000+" }));
    expect(within(chips).getByRole("button", { name: "ARP entries 10000+" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("list", { name: "Devices" })).not.toBeInTheDocument();
    await user.click(within(chips).getByRole("button", { name: "ARP entries 10000+" }));
    expect(screen.getByRole("list", { name: "Devices" })).toBeInTheDocument();
  });

  it("reads the next page of one kind with its cursor and appends it", async () => {
    mockApi({
      "GET /api/explore/search": () => {
        const url = urls().at(-1)!;
        if (url.searchParams.get("cursor") === "c1")
          return { body: { ...TYPED, kinds: [], groups: { device: { items: [device(3)], next_cursor: null } } } };
        return { body: TYPED };
      },
    });
    const user = userEvent.setup();
    mount();
    await user.type(screen.getByRole("searchbox", { name: "Find" }), "edge");
    await user.click(await screen.findByRole("button", { name: "Show more devices" }));
    const devices = screen.getByRole("list", { name: "Devices" });
    expect(await within(devices).findByRole("button", { name: /edge3/ })).toBeInTheDocument();
    expect(within(devices).getAllByRole("button")).toHaveLength(3);
    expect(screen.queryByRole("button", { name: "Show more devices" })).not.toBeInTheDocument();
    const next = urls().at(-1)!;
    expect(next.searchParams.get("cursor")).toBe("c1");
    expect(next.searchParams.getAll("kind")).toEqual(["device"]);
    expect(next.searchParams.get("snapshot")).toBe("7");
  });

  it("moves through the hits with the arrow keys across the groups and opens with Enter", async () => {
    mockApi({ "GET /api/explore/search": () => ({ body: TYPED }) });
    const user = userEvent.setup();
    const onOpen = mount();
    const input = screen.getByRole("searchbox", { name: "Find" });
    await user.type(input, "edge");
    const results = await screen.findByRole("list", { name: "Search results" });
    const hits = within(results).getAllByRole("button").filter((b) => b.hasAttribute("data-search-item"));
    expect(hits).toHaveLength(3);
    await user.keyboard("{ArrowDown}");
    expect(hits[0]).toHaveFocus();
    await user.keyboard("{ArrowDown}{ArrowDown}");
    expect(hits[2]).toHaveFocus();
    await user.keyboard("{ArrowUp}");
    expect(hits[1]).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ key: "dev:edge2" }));
    await user.keyboard("{Home}{ArrowUp}");
    expect(input).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ key: "dev:edge1" }));
    await user.keyboard("{Escape}");
    expect(input).toHaveValue("");
  });

  it("groups an older server's legacy answer by kind, with the label counts and no next page", async () => {
    mockApi({
      "GET /api/explore/search": () => ({
        body: {
          query: "10.1.2",
          total: 13,
          labels: [{ label: "Prefix", count: 12 }, { label: "IpAddress", count: 1 }],
          items: [
            { uid: "pfx:blue/10.1.2.0/24", label: "Prefix", name: "10.1.2.0/24", detail: "", matched: "address" },
            { uid: "ip:blue/10.1.2.7", label: "IpAddress", name: "10.1.2.7", detail: "", matched: "address" },
          ],
        },
      }),
    });
    const user = userEvent.setup();
    const onOpen = mount();
    await user.type(screen.getByRole("searchbox", { name: "Find" }), "10.1.2");
    expect(await screen.findByRole("button", { name: "Prefixes 12" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "IP addresses 1" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Show more/ })).not.toBeInTheDocument();
    await user.click(within(screen.getByRole("list", { name: "IP addresses" })).getByRole("button", { name: /10\.1\.2\.7/ }));
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ kind: "ip_address", target: { kind: "ip_address", uid: "ip:blue/10.1.2.7" } }));
  });

  it("shows the server's message for a refused query", async () => {
    mockApi({ "GET /api/explore/search": () => ({ status: 400, body: { error: "the pattern has a backreference" } }) });
    const user = userEvent.setup();
    mount();
    await user.type(screen.getByRole("searchbox", { name: "Find" }), "/(a)\\1/");
    expect(await screen.findByText("the pattern has a backreference")).toBeInTheDocument();
  });

  it("lists the page's local hits as it is typed, before the server answers", async () => {
    mockApi({ "GET /api/explore/search": () => ({ body: { ...TYPED, kinds: [], groups: {} } }) });
    const user = userEvent.setup();
    const local = (text: string) => [
      {
        id: "here",
        title: "On this page",
        items: text === "e" ? [{ ...device(9), source: "local" as const, key: "local:9" }] : [],
      },
    ];
    render(<UnifiedSearch label="Find" localGroups={local} onOpen={vi.fn()} />);
    await user.type(screen.getByRole("searchbox", { name: "Find" }), "e");
    expect(within(screen.getByRole("list", { name: "On this page" })).getByRole("button", { name: /edge9/ })).toBeInTheDocument();
    await waitFor(() => expect(urls().length).toBe(1));
  });
});
