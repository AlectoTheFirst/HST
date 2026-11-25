/**
 * The result card: the Table, Tree and picture views of one result, and the
 * selection they share.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi } from "../test/fetchMock";
import { GRAPH, hub, RESULT } from "../test/resultFixture";
import type { QueryResult } from "../api/types";
import { ResultCard, VIEW_KEY } from "./ResultCard";

const DETAIL = (uid: string, groups: { type: string; direction: "out" | "in"; label: string; count: number }[]) => ({
  snapshot: 1,
  node: { id: "x", uid, label: null, labels: [], name: uid, properties: { uid }, bookkeeping: {} },
  neighbors: groups,
});

const R1_GROUPS = [
  { type: "HAS_INTERFACE", direction: "out" as const, label: "Interface", count: 1 },
  { type: "LOCATED_IN", direction: "out" as const, label: "Site", count: 1 },
];

function installStorage(): Map<string, string> {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
  return data;
}

const storageBefore = Object.getOwnPropertyDescriptor(window, "localStorage");
beforeEach(() => {
  installStorage();
});
afterEach(() => {
  if (storageBefore) Object.defineProperty(window, "localStorage", storageBefore);
  else delete (window as { localStorage?: Storage }).localStorage;
});

function renderCard(result: QueryResult = RESULT, onOpen = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <ResultCard result={result} onOpen={onOpen} />
    </QueryClientProvider>,
  );
  return { ...view, onOpen };
}

const tree = () => screen.getByRole("tree", { name: "Result tree" });
const active = () => {
  const id = tree().getAttribute("aria-activedescendant")!;
  return document.getElementById(id)!;
};
const view = (name: string) => screen.getByRole("button", { name, pressed: true });

/** The fetch mock matches the path without its query, so every node gets the
 *  same groups. Only r1 opens in these tests. */
function mockDetails(groups: typeof R1_GROUPS = R1_GROUPS) {
  return { "GET /api/explore/node": () => ({ body: DETAIL("dev:r1", groups) }) };
}

/** Wait until the open nodes have their detail. */
const loaded = () => waitFor(() => expect(within(tree()).queryAllByText(/^Loading/)).toHaveLength(0));

describe("ResultCard", () => {
  it("defaults to Tree view with one root per row, first root expanded", async () => {
    mockApi(mockDetails());
    renderCard();
    expect(view("Tree")).toBeInTheDocument();
    await loaded();
    const items = within(tree()).getAllByRole("treeitem");
    expect(items.map((i) => i.getAttribute("aria-level"))).toEqual(["1", "2", "2", "1"]);
    expect(items[0]).toHaveTextContent("[-]r1");
    expect(items[0]).not.toHaveTextContent("row 1");
    expect(items[1]).toHaveTextContent("|-- [+]HAS_INTERFACE to Interface (1)");
    expect(items[2]).toHaveTextContent("`-- [+]LOCATED_IN to Site (1)");
  });

  it("node detail shows row count, selects matching rows, hides _ properties", async () => {
    mockApi(mockDetails());
    const user = userEvent.setup();
    renderCard({
      ...RESULT,
      graph: { ...GRAPH, nodes: GRAPH.nodes.map((n) => (n.id === "s1" ? { ...n, properties: { ...n.properties, _run_id: "r-1", _sources: "a" } } : n)) },
    });
    await loaded();
    tree().focus();
    await user.keyboard("jj");
    await user.keyboard("l");
    await user.keyboard("l");
    expect(active()).toHaveTextContent("ams");
    const detail = screen.getByRole("region", { name: "Node detail" });
    expect(detail).toHaveTextContent("In 2 of 2 result rows");
    expect(within(detail).queryByText("_run_id")).toBeNull();
    await user.click(within(detail).getByRole("button", { name: "Show 2 internal properties" }));
    expect(within(detail).getByText("_run_id")).toBeInTheDocument();
    await user.click(within(detail).getByRole("button", { name: "Select these rows" }));
    expect(within(detail).getByRole("button", { name: "Select these rows" })).toBeDisabled();
    expect(screen.getByRole("region", { name: "Selection picture" })).toHaveTextContent("Rows 1, 2");
  });

  it("disables Tree and Canvas when the result has no graph nodes", () => {
    renderCard({ columns: ["n"], data: [{ row: [7] }], truncated: false });
    expect(view("Table")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Tree" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Canvas" })).toBeDisabled();
    expect(screen.getByText("7")).toBeInTheDocument();
  });

  it("picture draws the selected row; clicking a node highlights its rows", async () => {
    mockApi(mockDetails());
    const user = userEvent.setup();
    renderCard();
    await user.click(screen.getByRole("button", { name: "Table" }));
    // no boxes: only the direction switch
    expect(within(screen.getByRole("region", { name: "Selection picture" })).queryAllByRole("button").map((b) => b.textContent)).toEqual(["Top down", "Left to right"]);

    const rows = screen.getAllByRole("row").slice(1);
    await user.click(within(rows[0]).getByText("10.0.0.1"));
    expect(rows[0]).toHaveAttribute("aria-selected", "true");
    expect(rows[1]).toHaveAttribute("aria-selected", "false");
    const picture = screen.getByRole("region", { name: "Selection picture" });
    expect(within(picture).getByRole("button", { name: "r1, Device, layer Phys, selected" })).toBeInTheDocument();
    // a2 is only a neighbour of the prefix: not drawn
    expect(within(picture).queryByRole("button", { name: /^10\.0\.0\.2/ })).toBeNull();

    await user.click(within(picture).getByRole("button", { name: /^10\.0\.0\.0\/31/ }));
    expect(within(picture).getByRole("button", { name: /^10\.0\.0\.0\/31/ })).toHaveAttribute("aria-pressed", "true");
    expect(rows[0]).toHaveClass("rt-hit");
    expect(rows[1]).toHaveClass("rt-hit");
  });

  it("row selection: Shift-click range, Ctrl-click toggle, Space key", async () => {
    const user = userEvent.setup();
    renderCard();
    await user.click(screen.getByRole("button", { name: "Table" }));
    const grid = screen.getByRole("grid", { name: "Result rows" });
    const rows = within(grid).getAllByRole("row").slice(1);
    await user.click(within(rows[0]).getByText("r1"));
    await user.keyboard("{Shift>}");
    await user.click(within(rows[1]).getByText("r2"));
    await user.keyboard("{/Shift}");
    expect(rows.map((r) => r.getAttribute("aria-selected"))).toEqual(["true", "true"]);
    await user.keyboard("{Control>}");
    await user.click(within(rows[0]).getByText("r1"));
    await user.keyboard("{/Control}");
    expect(rows.map((r) => r.getAttribute("aria-selected"))).toEqual(["false", "true"]);

    grid.focus();
    await user.keyboard("{Home}[Space]");
    expect(rows.map((r) => r.getAttribute("aria-selected"))).toEqual(["true", "false"]);
    await user.keyboard("{ArrowDown}{Shift>}[Space]{/Shift}");
    expect(rows.map((r) => r.getAttribute("aria-selected"))).toEqual(["true", "true"]);
  });

  it("tree keyboard navigation; Enter opens node in Search", async () => {
    mockApi(mockDetails());
    const user = userEvent.setup();
    const { onOpen } = renderCard();
    tree().focus();
    await user.keyboard("j");
    expect(active()).toHaveTextContent("HAS_INTERFACE to Interface");
    await user.keyboard("l");
    expect(active()).toHaveAttribute("aria-expanded", "true");
    await user.keyboard("l");
    expect(active()).toHaveTextContent("ge-0/0/1");
    await user.keyboard("{Enter}");
    expect(onOpen).toHaveBeenCalledWith("dev:r1/if/ge-0/0/1");
    await user.keyboard("h");
    expect(active()).toHaveTextContent("HAS_INTERFACE to Interface");
    await user.keyboard("h");
    expect(active()).toHaveAttribute("aria-expanded", "false");
    await user.keyboard("{End}");
    expect(active()).toHaveTextContent("r2");
  });

  it("paginates group snapshot items", async () => {
    mockApi({
      ...mockDetails([{ type: "HAS_INTERFACE", direction: "out", label: "Interface", count: 2 }, R1_GROUPS[1]]),
      "GET /api/explore/neighbors": () => ({
        body: {
          total: 2,
          offset: 0,
          limit: 50,
          items: [],
          graph: {
            nodes: [GRAPH.nodes[0], { id: "i9", labels: ["Interface", "L2"], properties: { uid: "dev:r1/if/ge-0/0/9", name: "ge-0/0/9" } }],
            relationships: [{ id: "r9", type: "HAS_INTERFACE", start: "d1", end: "i9", properties: {} }],
            truncated: false,
          },
        },
      }),
    });
    const user = userEvent.setup();
    renderCard();
    const group = await within(tree()).findByText(/1 in result, 2 in snapshot/);
    await user.click(group);
    tree().focus();
    await user.keyboard("l");
    await user.click(await within(tree()).findByText("Load 2 more from the snapshot"));
    const added = await within(tree()).findByText("ge-0/0/9");
    expect(added.closest("[role=treeitem]")).toHaveTextContent("snapshot");
    expect(within(tree()).queryByText(/Load .* more from the snapshot/)).toBeNull();
  });

  it("copy branch falls back to visible text when clipboard is blocked", async () => {
    mockApi(mockDetails());
    const user = userEvent.setup();
    renderCard();
    await loaded();
    await user.click(screen.getAllByRole("button", { name: "Copy branch" })[0]);
    expect(await screen.findByText("Copied 3 lines")).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(
      ["r1  Device  Juniper, MX204, router", "|-- HAS_INTERFACE to Interface (1)", "`-- LOCATED_IN to Site (1)"].join("\n"),
    );

    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    await user.click(screen.getAllByRole("button", { name: "Copy branch" })[0]);
    expect(screen.getByRole("textbox", { name: "Branch text" })).toHaveValue(
      ["r1  Device  Juniper, MX204, router", "|-- HAS_INTERFACE to Interface (1)", "`-- LOCATED_IN to Site (1)"].join("\n"),
    );
  });

  it("filter expands the path to each match", async () => {
    mockApi(mockDetails());
    const user = userEvent.setup();
    renderCard();
    await user.type(screen.getByRole("searchbox", { name: "Filter" }), "10.0.0.2");
    const match = within(tree()).getByText("10.0.0.2").closest("[role=treeitem]")!;
    expect(match).toHaveClass("rt-match");
    expect(within(tree()).queryByText("r1")).toBeNull();
  });

  it("switching to Tree reveals the selected row", async () => {
    mockApi(mockDetails());
    const user = userEvent.setup();
    renderCard();
    await user.click(screen.getByRole("button", { name: "Table" }));
    await user.click(within(screen.getAllByRole("row")[2]).getByText("r2"));
    await user.click(screen.getByRole("button", { name: "Show in tree" }));
    expect(view("Tree")).toBeInTheDocument();
    expect(within(tree()).getByText("10.0.0.0/31")).toBeInTheDocument();
    expect(active()).toHaveTextContent("r2");
  });

  it("persists the last selected view", async () => {
    const user = userEvent.setup();
    const first = renderCard();
    await user.click(screen.getByRole("button", { name: "Table" }));
    expect(window.localStorage.getItem(VIEW_KEY)).toBe('"table"');
    first.unmount();
    renderCard();
    expect(view("Table")).toBeInTheDocument();
  });

  it("falls back to payload nodes as roots without row links", () => {
    renderCard({ ...RESULT, data: RESULT.data.map((d) => ({ row: d.row })) });
    // the roots are the payload nodes
    const roots = within(tree()).getAllByRole("treeitem").filter((i) => i.getAttribute("aria-level") === "1");
    expect(roots).toHaveLength(GRAPH.nodes.length);
  });

  it("flags a truncated graph", () => {
    renderCard({ columns: ["d"], data: [{ row: ["hub"], nodes: ["h"] }], truncated: false, graph: { ...hub(3), truncated: true } });
    expect(screen.getByText("partial graph")).toBeInTheDocument();
  });

  it("renders 2,000 tree items", async () => {
    // a picked row that holds every interface pins each one past the page limit
    mockApi(mockDetails([]));
    const g = hub(1999);
    const user = userEvent.setup();
    renderCard({ columns: ["d"], data: [{ row: ["hub"], nodes: g.nodes.map((n) => n.id) }], truncated: false, graph: g });
    await user.click(screen.getByRole("button", { name: "Table" }));
    await user.click(screen.getByText("hub"));
    await user.click(screen.getByRole("button", { name: "Show in tree" }));
    await loaded();
    expect(within(tree()).getAllByRole("treeitem")).toHaveLength(2001);
  }, 20000);
});
