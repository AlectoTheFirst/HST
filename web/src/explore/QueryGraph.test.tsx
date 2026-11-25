/**
 * The drill-down around the Queries graph. The canvas itself is Cytoscape and
 * is not readable in jsdom (see GraphView.test.tsx), so these tests read the
 * text alternative and the selected node's panel.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import QueryGraph from "./QueryGraph";
import { mergeGraphs } from "./graphElements";
import { mockApi } from "../test/fetchMock";
import type { ResultGraph } from "../api/types";

const RESULT: ResultGraph = {
  nodes: [
    { id: "4:x:1", labels: ["Device"], properties: { uid: "dev:core1", hostname: "core1" } },
    { id: "4:x:9", labels: ["Site"], properties: { uid: "site:dcber", name: "site:dcber" } },
  ],
  relationships: [{ id: "5:x:1", type: "LOCATED_IN", start: "4:x:1", end: "4:x:9", properties: {} }],
  truncated: false,
};

const NODE = {
  snapshot: 1758283200000,
  node: {
    id: "4:x:1", uid: "dev:core1", label: "Device", labels: ["Device"], name: "core1",
    properties: { uid: "dev:core1", hostname: "core1" }, bookkeeping: {},
  },
  neighbors: [{ type: "ON", direction: "in", label: "Interface", count: 1 }],
};

const PAGE = {
  total: 1, offset: 0, limit: 50,
  items: [{ uid: "dev:core1/if/eth0", label: "Interface", name: "eth0" }],
  graph: {
    nodes: [
      { id: "4:x:1", labels: ["Device"], properties: { uid: "dev:core1", hostname: "core1" } },
      { id: "4:x:2", labels: ["Interface"], properties: { uid: "dev:core1/if/eth0", name: "eth0" } },
    ],
    relationships: [{ id: "5:x:2", type: "ON", start: "4:x:2", end: "4:x:1", properties: {} }],
    truncated: false,
  },
};

const SIZE = { width: 900, height: 520 };
const original = {
  rect: HTMLElement.prototype.getBoundingClientRect,
  width: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth"),
  height: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight"),
};

beforeAll(() => {
  Object.defineProperties(HTMLElement.prototype, {
    clientWidth: { configurable: true, get: () => SIZE.width },
    clientHeight: { configurable: true, get: () => SIZE.height },
  });
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({ x: 0, y: 0, top: 0, left: 0, right: SIZE.width, bottom: SIZE.height, ...SIZE, toJSON: () => ({}) }) as DOMRect;
});

afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = original.rect;
  if (original.width) Object.defineProperty(HTMLElement.prototype, "clientWidth", original.width);
  if (original.height) Object.defineProperty(HTMLElement.prototype, "clientHeight", original.height);
});

function Owner({ onOpen }: { onOpen: (uid: string) => void }) {
  const [graph, setGraph] = useState(RESULT);
  return <QueryGraph graph={graph} onGraph={(p) => setGraph((g) => mergeGraphs(g, p))} onOpen={onOpen} />;
}

function renderGraph(onOpen = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Owner onOpen={onOpen} />
    </QueryClientProvider>,
  );
  return onOpen;
}

describe("QueryGraph", () => {
  it("lists the relationships of the selected node", async () => {
    mockApi({ "GET /api/explore/node": () => ({ body: NODE }) });
    const user = userEvent.setup();
    renderGraph();

    await user.click(screen.getByRole("button", { name: "Device core1" }));
    expect(await screen.findByRole("button", { name: /ON from Interface/ })).toBeInTheDocument();
  });

  it("adds a group's neighbors to the graph in place", async () => {
    mockApi({
      "GET /api/explore/node": () => ({ body: NODE }),
      "GET /api/explore/neighbors": () => ({ body: PAGE }),
    });
    const user = userEvent.setup();
    renderGraph();
    expect(screen.getByRole("img", { name: /2 nodes and 1 relationships/ })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Device core1" }));
    await user.click(await screen.findByRole("button", { name: /ON from Interface/ }));
    expect(await screen.findByRole("img", { name: /3 nodes and 2 relationships/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Interface eth0" })).toBeInTheDocument();
    // the node that was expanded stays selected
    expect(screen.getByRole("button", { name: "Open core1" })).toBeInTheDocument();
  });

  it("opens a neighbor in the Search tab", async () => {
    mockApi({
      "GET /api/explore/node": () => ({ body: NODE }),
      "GET /api/explore/neighbors": () => ({ body: PAGE }),
    });
    const user = userEvent.setup();
    const onOpen = renderGraph();

    await user.click(screen.getByRole("button", { name: "Device core1" }));
    await user.click(await screen.findByRole("button", { name: /ON from Interface/ }));
    await user.click(await screen.findByRole("button", { name: "eth0" }));
    expect(onOpen).toHaveBeenCalledWith("dev:core1/if/eth0");
  });

  it("says so when the relationships fail to load", async () => {
    mockApi({ "GET /api/explore/node": () => ({ status: 404, body: { error: "node not found" } }) });
    const user = userEvent.setup();
    renderGraph();

    await user.click(screen.getByRole("button", { name: "Device core1" }));
    expect(await screen.findByText("node not found")).toBeInTheDocument();
  });
});
