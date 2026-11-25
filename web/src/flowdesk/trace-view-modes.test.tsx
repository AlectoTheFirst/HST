import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import TracePage from "./TracePage";
import { mockApi } from "../test/fetchMock";
import {
  FIXTURE_PATH_BLOCKED,
  FIXTURE_PATH_LEAF_SPINE,
  FIXTURE_PATH_SINGLE,
  FIXTURE_SNAPSHOTS,
} from "../test/fixtures";
import type { BidirectionalPathResponse, PathResponse } from "../api/types";

// Same jsdom opaque-origin storage stand-in as trace-view-toggle.test.tsx.
function installStorage(): void {
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
}

function renderTracePage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <TracePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function trace() {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^trace/i }));
  return user;
}

function serve(body: PathResponse | BidirectionalPathResponse) {
  mockApi({
    "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
    "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    "GET /api/path": () => ({ status: 200, body }),
  });
}

beforeEach(() => {
  installStorage();
  serve(FIXTURE_PATH_SINGLE);
});

describe("TracePage: Graph and Tree view modes", () => {
  it("offers Graph, Tree and 3D, Graph the default", () => {
    renderTracePage();
    const group = screen.getByRole("group", { name: "Trace view" });
    expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["Graph", "Tree", "3D"]);
    expect(screen.getByRole("button", { name: "Graph" })).toHaveAttribute("aria-pressed", "true");
    for (const name of ["Tree", "3D"]) {
      expect(screen.getByRole("button", { name })).toHaveAttribute("aria-pressed", "false");
    }
  });

  it("switching to Tree renders the tree view", async () => {
    renderTracePage();
    const user = await trace();
    await screen.findByRole("group", { name: "Path graph" });

    await user.click(screen.getByRole("button", { name: "Tree" }));
    expect(await screen.findByRole("tree", { name: "Path tree" })).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Path graph" })).not.toBeInTheDocument();
  });

  it("shows the hop detail control with the Graph only, and keeps every hop in All hops", async () => {
    renderTracePage();
    const user = await trace();
    const graph = await screen.findByRole("group", { name: "Path graph" });
    expect(within(graph).getAllByRole("button")).toHaveLength(4);
    await user.click(screen.getByRole("button", { name: "All hops" }));
    expect(within(screen.getByRole("group", { name: "Path graph" })).getAllByRole("button")).toHaveLength(
      FIXTURE_PATH_SINGLE.hops.length,
    );
    await user.click(screen.getByRole("button", { name: "Tree" }));
    expect(screen.queryByRole("group", { name: "Hop detail" })).not.toBeInTheDocument();
  });

  it("persists the choice in localStorage across a remount", async () => {
    const { unmount } = renderTracePage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Tree" }));
    expect(window.localStorage.getItem("hst.trace.view")).toBe('"tree"');
    unmount();

    renderTracePage();
    expect(screen.getByRole("button", { name: "Tree" })).toHaveAttribute("aria-pressed", "true");
  });

  it("reads a stored ribbon or serpentine value as the Graph and a stored ledger value as the Tree", () => {
    for (const [stored, name] of [
      ["ribbon", "Graph"],
      ["serpentine", "Graph"],
      ["ledger", "Tree"],
      ["strata", "3D"],
      ["nonsense", "Graph"],
    ] as const) {
      window.localStorage.setItem("hst.trace.view", JSON.stringify(stored));
      const { unmount } = renderTracePage();
      expect(screen.getByRole("button", { name })).toHaveAttribute("aria-pressed", "true");
      unmount();
    }
  });

  it("the reply toggle renders both panes in Tree view too", async () => {
    serve({
      forward: FIXTURE_PATH_SINGLE,
      reply: FIXTURE_PATH_BLOCKED,
      asymmetric: true,
      notes: ["asymmetric routing: the reply's own path does not retrace the forward one"],
    });
    renderTracePage();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Tree" }));
    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.click(screen.getByRole("button", { name: /^trace/i }));

    const trees = await screen.findAllByRole("tree", { name: "Path tree" });
    expect(trees).toHaveLength(2);
    expect(screen.getByText(/asymmetric routing/)).toBeInTheDocument();
  });

  it("a path click fills the inspector with its leg, and Esc in the graph clears it", async () => {
    serve(FIXTURE_PATH_LEAF_SPINE);
    renderTracePage();
    const user = await trace();
    const paths = await screen.findByRole("group", { name: "Paths" });
    const path2 = within(paths).getByRole("button", { name: /^Path 2/ });
    await user.click(path2);
    expect(path2).toHaveAttribute("aria-pressed", "true");
    const inspector = document.querySelector(".inspector") as HTMLElement;
    expect(within(inspector).getAllByText("leg 1").length).toBeGreaterThan(0);

    const box = screen.getByRole("button", { name: /^border2, Device/ });
    box.focus();
    await user.keyboard("{Escape}");
    expect(path2).toHaveAttribute("aria-pressed", "false");
  });
});
