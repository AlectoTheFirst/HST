/** jsdom reports every element as 0x0. */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import GraphView from "./GraphView";
import type { Core } from "cytoscape";
import type { ResultGraph } from "../api/types";

const GRAPH: ResultGraph = {
  nodes: [
    { id: "n1", labels: ["Device", "Phys"], properties: { hostname: "core1", vendor: "vyos" } },
    { id: "n2", labels: ["Iface"], properties: { name: "eth0" } },
    { id: "n3", labels: ["Device"], properties: { uid: "dev:x:edge1" } },
  ],
  relationships: [{ id: "r1", type: "HAS_IFACE", start: "n1", end: "n2", properties: {} }],
  truncated: false,
};

const { instances } = vi.hoisted(() => ({ instances: [] as Core[] }));
vi.mock("../graph/cytoscape", async (importOriginal) => {
  const actual = (await importOriginal()) as { withLayouts: () => (options?: unknown) => Core };
  return {
    withLayouts: () => {
      const build = actual.withLayouts();
      return Object.assign((options?: unknown) => {
        const core = build(options);
        instances.push(core);
        return core;
      }, build);
    },
  };
});

const SIZE = { width: 900, height: 520 };
const original = {
  rect: HTMLElement.prototype.getBoundingClientRect,
  client: {
    width: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth"),
    height: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight"),
  },
};

beforeAll(() => {
  Object.defineProperties(HTMLElement.prototype, {
    clientWidth: { configurable: true, get: () => SIZE.width },
    clientHeight: { configurable: true, get: () => SIZE.height },
  });
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      right: SIZE.width,
      bottom: SIZE.height,
      ...SIZE,
      toJSON: () => ({}),
    }) as DOMRect;
});

afterAll(() => {
  HTMLElement.prototype.getBoundingClientRect = original.rect;
  if (original.client.width) {
    Object.defineProperty(HTMLElement.prototype, "clientWidth", original.client.width);
  }
  if (original.client.height) {
    Object.defineProperty(HTMLElement.prototype, "clientHeight", original.client.height);
  }
});

function zoomPercent(): number {
  return Number(screen.getByText(/%$/).textContent!.replace("%", ""));
}

/** The relationship lines of the text alternative, one string per line. */
function relationshipLines(container: HTMLElement): string[] {
  return [...container.querySelectorAll(".gv-sr li")]
    .filter((li) => !li.querySelector("button"))
    .map((li) => li.textContent!);
}

describe("GraphView", () => {
  it("names the picture and counts what is in it", () => {
    render(<GraphView graph={GRAPH} />);
    expect(
      screen.getByRole("img", { name: "Graph of 3 nodes and 1 relationships" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/3 nodes, 1 relationship$/)).toBeInTheDocument();
  });

  it("carries the same graph as text", () => {
    const { container } = render(<GraphView graph={GRAPH} />);
    // a node per button, captioned by the property an operator knows it by
    expect(screen.getByRole("button", { name: "Device core1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Iface eth0" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Device dev:x:edge1" })).toBeInTheDocument();
    // and the relationship, in the direction it points
    expect(relationshipLines(container)).toEqual(["core1 HAS_IFACE eth0"]);
  });

  it("shows a node's properties when it is selected", async () => {
    const user = userEvent.setup();
    render(<GraphView graph={GRAPH} />);
    expect(screen.queryByText("vyos")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Device core1" }));
    expect(screen.getByText("vendor")).toBeInTheDocument();
    expect(screen.getByText("vyos")).toBeInTheDocument();
    expect(screen.getByText("Device, Phys")).toBeInTheDocument();
  });

  it("says so when the server capped the graph", () => {
    render(<GraphView graph={{ ...GRAPH, truncated: true }} />);
    expect(screen.getByText(/partial/)).toBeInTheDocument();
  });

  it("renders nothing for a result with no nodes", () => {
    const { container } = render(
      <GraphView graph={{ nodes: [], relationships: [], truncated: false }} />,
    );
    expect(container.querySelector(".graphview")).toBeNull();
  });

  it("lists only the relationships it could draw", () => {
    const { container } = render(
      <GraphView
        graph={{
          ...GRAPH,
          relationships: [
            ...GRAPH.relationships,
            // the far end is not in the graph
            { id: "r2", type: "CABLED", start: "n1", end: "gone", properties: {} },
          ],
        }}
      />,
    );
    expect(relationshipLines(container)).toEqual(["core1 HAS_IFACE eth0"]);
    expect(screen.queryByText("CABLED")).not.toBeInTheDocument();
  });

  it("keys the marks by node label", () => {
    const { container } = render(<GraphView graph={GRAPH} />);
    const entries = [...container.querySelectorAll(".gv-legend li")].map((li) => li.textContent);
    // most common label first: two Devices, one Iface
    expect(entries).toEqual(["Device2", "Iface1"]);
    // each swatch has the shape and the colour of the slot
    const swatches = [...container.querySelectorAll(".gv-legend .gv-swatch")];
    expect(swatches.map((s) => s.className)).toEqual([
      "gv-swatch gv-slot0",
      "gv-swatch gv-slot1",
    ]);
  });

  it("offers the layout catalogue and keeps the graph across a change", async () => {
    const user = userEvent.setup();
    render(<GraphView graph={GRAPH} />);
    const picker = screen.getByRole("combobox", { name: "Layout" });
    expect((picker as HTMLSelectElement).value).toBe("fcose");

    await user.selectOptions(picker, "dagre");
    expect((picker as HTMLSelectElement).value).toBe("dagre");
    expect(screen.getByRole("img", { name: /3 nodes/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Device core1" })).toBeInTheDocument();
  });

  it("zooms in and out in absolute steps, and frames the whole graph again", async () => {
    const user = userEvent.setup();
    render(<GraphView graph={GRAPH} />);
    const framed = zoomPercent();

    await user.click(screen.getByRole("button", { name: "Zoom in" }));
    const closer = zoomPercent();
    expect(closer).toBeGreaterThan(framed);

    await user.click(screen.getByRole("button", { name: "Zoom out" }));
    expect(zoomPercent()).toBeLessThan(closer);

    await user.click(screen.getByRole("button", { name: "Fit" }));
    expect(zoomPercent()).toBe(framed);
  });

  it("fills the window and leaves full screen on Escape", async () => {
    const user = userEvent.setup();
    const { container } = render(<GraphView graph={GRAPH} />);
    expect(container.querySelector(".gv-full")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Full screen" }));
    expect(container.querySelector(".gv-full")).not.toBeNull();

    await user.keyboard("{Escape}");
    expect(container.querySelector(".gv-full")).toBeNull();
  });

  it("fits the view to a new result", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<GraphView graph={GRAPH} />);
    await user.click(screen.getByRole("button", { name: "Zoom in" }));
    const closeIn = zoomPercent();

    rerender(
      <GraphView
        graph={{
          nodes: [...GRAPH.nodes, { id: "n4", labels: ["Site"], properties: { name: "muc" } }],
          relationships: GRAPH.relationships,
          truncated: false,
        }}
      />,
    );
    expect(screen.getByRole("img", { name: /4 nodes/ })).toBeInTheDocument();
    expect(zoomPercent()).not.toBe(closeIn);
  });
});

describe("GraphView in a hidden pane", () => {
  it("fits the view again when the stage first gets a size", () => {
    const observers: Array<() => void> = [];
    const saved = globalThis.ResizeObserver;
    globalThis.ResizeObserver = class {
      constructor(callback: () => void) {
        observers.push(callback);
      }
      observe() {}
      disconnect() {}
      unobserve() {}
    } as unknown as typeof ResizeObserver;
    const rect = HTMLElement.prototype.getBoundingClientRect;
    try {
      HTMLElement.prototype.getBoundingClientRect = () => ({ width: 0, height: 0 }) as DOMRect;
      render(<GraphView graph={GRAPH} />);
      const core = instances[instances.length - 1];
      const fit = vi.spyOn(core, "fit");
      observers.forEach((callback) => callback());
      expect(fit).not.toHaveBeenCalled();
      HTMLElement.prototype.getBoundingClientRect = rect;
      observers.forEach((callback) => callback());
      expect(fit).toHaveBeenCalledTimes(1);
      observers.forEach((callback) => callback());
      expect(fit).toHaveBeenCalledTimes(1);
    } finally {
      HTMLElement.prototype.getBoundingClientRect = rect;
      globalThis.ResizeObserver = saved;
    }
  });
});

describe("GraphView kept height", () => {
  it("leaves the stored height after a 0x0 observation", () => {
    const observers: Array<() => void> = [];
    const saved = globalThis.ResizeObserver;
    globalThis.ResizeObserver = class {
      constructor(callback: () => void) {
        observers.push(callback);
      }
      observe() {}
      disconnect() {}
      unobserve() {}
    } as unknown as typeof ResizeObserver;
    const store = new Map<string, string>([["hst-graph-height", "480"]]);
    const storage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
    };
    const had = Object.getOwnPropertyDescriptor(window, "localStorage");
    Object.defineProperty(window, "localStorage", { configurable: true, value: storage });
    const rect = HTMLElement.prototype.getBoundingClientRect;
    try {
      HTMLElement.prototype.getBoundingClientRect = () => ({ width: 0, height: 0 }) as DOMRect;
      render(<GraphView graph={GRAPH} />);
      vi.useFakeTimers();
      observers.forEach((callback) => callback());
      window.dispatchEvent(new Event("pointerup"));
      vi.advanceTimersByTime(1000);
      expect(store.get("hst-graph-height")).toBe("480");
    } finally {
      vi.useRealTimers();
      HTMLElement.prototype.getBoundingClientRect = rect;
      globalThis.ResizeObserver = saved;
      if (had) Object.defineProperty(window, "localStorage", had);
      else Reflect.deleteProperty(window, "localStorage");
    }
  });
});

describe("GraphView node list", () => {
  it("is one tab stop: arrow keys move and Enter selects", async () => {
    const user = userEvent.setup();
    render(<GraphView graph={GRAPH} />);
    const list = screen.getByRole("list", { name: "Nodes and relationships" });
    const buttons = within(list).getAllByRole("button");
    expect(buttons.map((b) => b.tabIndex)).toEqual([0, -1, -1]);
    buttons[0].focus();
    await user.keyboard("{ArrowDown}");
    expect(document.activeElement).toBe(buttons[1]);
    expect(buttons.map((b) => b.tabIndex)).toEqual([-1, 0, -1]);
    await user.keyboard("{End}");
    expect(document.activeElement).toBe(buttons[2]);
    await user.keyboard("{Enter}");
    const core = instances[instances.length - 1];
    expect(core.$(":selected").map((n) => n.id())).toEqual(["n3"]);
  });
});
