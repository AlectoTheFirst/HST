import { describe, it, expect, vi } from "vitest";
import {
  MAX_PANES,
  MIN_RATIO,
  initial,
  neighbour,
  panes,
  reduce,
  tile,
  type Node,
  type Rect,
  type Workspace,
} from "./layout";

function split(state: Workspace, dir: "row" | "col" = "row"): Workspace {
  return reduce(state, { type: "split", id: state.focus, dir });
}

describe("pane tree", () => {
  it("starts as a single trace pane", () => {
    const ws = initial();
    expect(panes(ws.root)).toHaveLength(1);
    expect(ws.root.type).toBe("leaf");
    expect(panes(ws.root)[0].view).toBe("trace");
  });

  it("splitting produces two panes and focuses the new one", () => {
    const ws = split(initial());
    const ids = panes(ws.root).map((p) => p.id);
    expect(ids).toHaveLength(2);
    expect(ws.focus).toBe(ids[1]);
    expect(ws.root.type).toBe("split");
  });

  it("gives the new pane the view of the split pane", () => {
    let ws = initial();
    ws = reduce(ws, { type: "view", id: ws.focus, view: "explore" });
    ws = split(ws);
    expect(panes(ws.root).map((p) => p.view)).toEqual(["explore", "explore"]);
  });

  it("open-map switches the pane to the map with the scope it was handed", () => {
    let ws = initial();
    ws = reduce(ws, { type: "open-map", id: ws.focus, scope: "sites/FR2,FR6" });
    expect(panes(ws.root)[0]).toMatchObject({ view: "map", mapScope: "sites/FR2,FR6" });
    // the rail's own map entry hands no scope, and clears one a site map left
    ws = reduce(ws, { type: "open-map", id: ws.focus });
    expect(panes(ws.root)[0]).toMatchObject({ view: "map", mapScope: undefined });
  });

  it("closing a pane collapses its parent split into the sibling", () => {
    const ws = split(initial());
    const [first, second] = panes(ws.root);
    const closed = reduce(ws, { type: "close", id: second.id });
    // no empty split is ever left behind
    expect(closed.root).toEqual({ ...first, });
    expect(panes(closed.root)).toHaveLength(1);
  });

  it("closing the focused pane moves focus to a surviving one", () => {
    const ws = split(initial());
    const closed = reduce(ws, { type: "close", id: ws.focus });
    expect(panes(closed.root).some((p) => p.id === closed.focus)).toBe(true);
  });

  it("closing the last pane is a no-op", () => {
    const ws = initial();
    expect(reduce(ws, { type: "close", id: ws.focus })).toBe(ws);
  });

  it("survives repeated split/close without leaking splits", () => {
    let ws = initial();
    // splits past the cap are no-ops, so six attempts still yield MAX_PANES
    for (let i = 0; i < 6; i++) ws = split(ws, i % 2 ? "col" : "row");
    expect(panes(ws.root)).toHaveLength(MAX_PANES);
    while (panes(ws.root).length > 1) {
      ws = reduce(ws, { type: "close", id: panes(ws.root)[0].id });
    }
    expect(ws.root.type).toBe("leaf");
  });

  it("clamps ratios to MIN_RATIO on both sides", () => {
    const ws = split(initial());
    const splitId = ws.root.type === "split" ? ws.root.id : "";
    const tiny = reduce(ws, { type: "ratio", id: splitId, ratio: 0.001 });
    const huge = reduce(ws, { type: "ratio", id: splitId, ratio: 0.999 });
    expect(tiny.root.type === "split" && tiny.root.ratio).toBe(MIN_RATIO);
    expect(huge.root.type === "split" && huge.root.ratio).toBe(1 - MIN_RATIO);
  });

  it("ignores focus and close for panes that do not exist", () => {
    const ws = split(initial());
    expect(reduce(ws, { type: "focus", id: "nope" })).toBe(ws);
    expect(panes(reduce(ws, { type: "close", id: "nope" }).root)).toHaveLength(2);
  });

  it("opening a query targets one pane and switches it to explore", () => {
    let ws = split(initial());
    const target = panes(ws.root)[0];
    ws = reduce(ws, { type: "open-query", id: target.id, queryKey: "cabling" });
    const [a, b] = panes(ws.root);
    expect(a.view).toBe("explore");
    expect(a.queryKey).toBe("cabling");
    expect(b.view).toBe("trace");
    expect(b.queryKey).toBeUndefined();
  });
});

describe("the pane cap", () => {
  function fill(): Workspace {
    let ws = initial();
    while (panes(ws.root).length < MAX_PANES) ws = split(ws);
    return ws;
  }

  it("refuses a split at the cap, returning the same state", () => {
    const ws = fill();
    expect(panes(ws.root)).toHaveLength(MAX_PANES);
    expect(reduce(ws, { type: "split", id: ws.focus, dir: "row" })).toBe(ws);
    expect(reduce(ws, { type: "split", id: ws.focus, dir: "col" })).toBe(ws);
  });

  it("splits again once a pane is closed", () => {
    const ws = fill();
    const closed = reduce(ws, { type: "close", id: panes(ws.root)[0].id });
    expect(panes(split(closed).root)).toHaveLength(MAX_PANES);
  });
});

describe("reset", () => {
  it("returns a fresh single pane with a new id", () => {
    const before = initial();
    const ws = reduce(split(before), { type: "reset" });
    expect(panes(ws.root)).toHaveLength(1);
    expect(ws.root.type).toBe("leaf");
    expect(ws.focus).toBe(panes(ws.root)[0].id);
    expect(panes(ws.root)[0].id).not.toBe(panes(before.root)[0].id);
    expect(panes(ws.root)[0].view).toBe("trace");
  });

});

describe("tile", () => {
  const full: Rect = { top: 0, left: 0, width: 100, height: 100 };

  it("gives a lone pane the whole box and no dividers", () => {
    const ws = initial();
    const t = tile(ws.root);
    expect(t.panes).toHaveLength(1);
    expect(t.panes[0].rect).toEqual(full);
    expect(t.dividers).toHaveLength(0);
  });

  it("halves a row split and puts the seam on the boundary", () => {
    const ws = split(initial(), "row");
    const t = tile(ws.root);
    expect(t.panes.map((p) => p.rect)).toEqual([
      { top: 0, left: 0, width: 50, height: 100 },
      { top: 0, left: 50, width: 50, height: 100 },
    ]);
    expect(t.dividers).toHaveLength(1);
    expect(t.dividers[0].dir).toBe("row");
    expect(t.dividers[0].rect).toEqual({ top: 0, left: 50, width: 0, height: 100 });
    expect(t.dividers[0].box).toEqual(full);
  });

  it("stacks a col split and puts the seam on the boundary", () => {
    const ws = split(initial(), "col");
    const t = tile(ws.root);
    expect(t.panes.map((p) => p.rect)).toEqual([
      { top: 0, left: 0, width: 100, height: 50 },
      { top: 50, left: 0, width: 100, height: 50 },
    ]);
    expect(t.dividers[0].rect).toEqual({ top: 50, left: 0, width: 100, height: 0 });
  });

  it("multiplies nested ratios and hands each divider its own box", () => {
    let ws = split(initial(), "row");
    const rootId = ws.root.type === "split" ? ws.root.id : "";
    ws = reduce(ws, { type: "ratio", id: rootId, ratio: 0.3 });
    // split the second pane vertically, then set that split's ratio
    ws = reduce(ws, { type: "split", id: panes(ws.root)[1].id, dir: "col" });
    const inner = ws.root.type === "split" && ws.root.b.type === "split" ? ws.root.b.id : "";
    ws = reduce(ws, { type: "ratio", id: inner, ratio: 0.6 });

    const t = tile(ws.root);
    expect(t.panes.map((p) => p.rect)).toEqual([
      { top: 0, left: 0, width: 30, height: 100 },
      { top: 0, left: 30, width: 70, height: 60 },
      { top: 60, left: 30, width: 70, height: 40 },
    ]);
    const innerDivider = t.dividers.find((d) => d.id === inner)!;
    expect(innerDivider.box).toEqual({ top: 0, left: 30, width: 70, height: 100 });
    expect(innerDivider.rect).toEqual({ top: 60, left: 30, width: 70, height: 0 });
  });

  it("sibling rects sum to the parent box at an awkward ratio", () => {
    let ws = split(initial(), "row");
    const rootId = ws.root.type === "split" ? ws.root.id : "";
    ws = reduce(ws, { type: "ratio", id: rootId, ratio: 1 / 3 });
    const [a, b] = tile(ws.root).panes.map((p) => p.rect);
    expect(a.left).toBe(0);
    expect(a.left + a.width).toBe(b.left);
    expect(b.left + b.width).toBe(100);
  });
});

describe("restored trees and the id counter", () => {
  function allIds(node: Node): string[] {
    return node.type === "leaf"
      ? [node.id]
      : [node.id, ...allIds(node.a), ...allIds(node.b)];
  }

  async function freshLayout() {
    vi.resetModules();
    return await import("./layout");
  }

  it("a split after seeding a restored two-pane layout mints no colliding id", async () => {
    const layout = await freshLayout();
    const saved = {
      root: {
        type: "split", id: "s4", dir: "row", ratio: 0.5,
        a: { type: "leaf", id: "p1", view: "trace" },
        b: { type: "leaf", id: "p2", view: "trace" },
      },
      focus: "p1",
    } as Workspace;

    layout.seedIds(saved.root);
    const ws = layout.reduce(saved, { type: "split", id: "p1", dir: "row" });

    const ids = allIds(ws.root);
    expect(layout.panes(ws.root)).toHaveLength(3);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("closing the pane minted after a restore removes only that pane", async () => {
    const layout = await freshLayout();
    const saved = {
      root: {
        type: "split", id: "s4", dir: "row", ratio: 0.5,
        a: { type: "leaf", id: "p1", view: "trace" },
        b: { type: "leaf", id: "p2", view: "trace" },
      },
      focus: "p1",
    } as Workspace;

    layout.seedIds(saved.root);
    const ws = layout.reduce(saved, { type: "split", id: "p1", dir: "row" });
    const closed = layout.reduce(ws, { type: "close", id: ws.focus });

    expect(layout.panes(closed.root).map((p) => p.id).sort()).toEqual(["p1", "p2"]);
  });

  function collided(): Workspace {
    return {
      root: {
        type: "split", id: "s2", dir: "row", ratio: 0.5,
        a: { type: "leaf", id: "p1", view: "trace" },
        b: { type: "leaf", id: "p1", view: "trace" },
      },
      focus: "p1",
    } as Workspace;
  }

  it("a repaired layout closes down to one pane and switches views singly", async () => {
    const layout = await freshLayout();
    const { node: root } = layout.repairIds(collided().root);
    const ws: Workspace = { root, focus: layout.panes(root)[0].id };
    const [first, second] = layout.panes(root);

    const viewed = layout.reduce(ws, { type: "view", id: second.id, view: "explore" });
    expect(layout.panes(viewed.root).map((p) => p.view)).toEqual(["trace", "explore"]);

    const closed = layout.reduce(viewed, { type: "close", id: second.id });
    expect(layout.panes(closed.root).map((p) => p.id)).toEqual([first.id]);
  });

  it("remints duplicate pane ids so a view change hits exactly one pane", async () => {
    const layout = await freshLayout();
    const saved = {
      type: "split", id: "s1", dir: "row", ratio: 0.5,
      a: { type: "leaf", id: "p1", view: "trace" },
      b: { type: "leaf", id: "p1", view: "trace" },
    } as Node;

    const { node: root, changed } = layout.repairIds(saved);
    const ids = allIds(root);

    expect(changed).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
    const ws = layout.reduce({ root, focus: "p1" }, { type: "view", id: "p1", view: "explore" });
    expect(layout.panes(ws.root).map((p) => p.view)).toEqual(["explore", "trace"]);
  });

  it("the first bearer keeps its id, so a stored focus stays valid", async () => {
    const layout = await freshLayout();
    const saved = {
      type: "split", id: "s1", dir: "row", ratio: 0.5,
      a: { type: "leaf", id: "p1", view: "trace" },
      b: { type: "leaf", id: "p1", view: "trace" },
    } as Node;

    const { node: root } = layout.repairIds(saved);
    expect(layout.panes(root)[0].id).toBe("p1");
  });

  it("remints duplicate split ids with the split prefix", async () => {
    const layout = await freshLayout();
    const saved = {
      type: "split", id: "s1", dir: "row", ratio: 0.5,
      a: {
        type: "split", id: "s1", dir: "col", ratio: 0.5,
        a: { type: "leaf", id: "p1", view: "trace" },
        b: { type: "leaf", id: "p2", view: "trace" },
      },
      b: { type: "leaf", id: "p3", view: "trace" },
    } as Node;

    const { node: root } = layout.repairIds(saved);
    const ids = allIds(root);
    expect(new Set(ids).size).toBe(ids.length);
    const splitIds = ids.filter((id) => id.startsWith("s"));
    expect(splitIds).toHaveLength(2);
  });

  it("leaves a healthy tree untouched and reports no change", async () => {
    const layout = await freshLayout();
    const saved = {
      type: "split", id: "s4", dir: "row", ratio: 0.5,
      a: { type: "leaf", id: "p1", view: "trace" },
      b: { type: "leaf", id: "p2", view: "trace" },
    } as Node;

    const { node: root, changed } = layout.repairIds(saved);
    expect(changed).toBe(false);
    expect(allIds(root)).toEqual(["s4", "p1", "p2"]);
    const ws = layout.reduce({ root, focus: "p1" }, { type: "split", id: "p1", dir: "row" });
    const ids = allIds(ws.root);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("directional focus", () => {
  // two side-by-side panes over a full-width third
  const rects = new Map([
    ["left", { x: 0, y: 0, w: 100, h: 100 }],
    ["right", { x: 100, y: 0, w: 100, h: 100 }],
    ["bottom", { x: 0, y: 100, w: 200, h: 100 }],
  ]);

  it("moves by geometry", () => {
    expect(neighbour(rects, "left", "right")).toBe("right");
    expect(neighbour(rects, "right", "left")).toBe("left");
    expect(neighbour(rects, "left", "down")).toBe("bottom");
    expect(neighbour(rects, "bottom", "up")).toBe("left");
  });

  it("returns null at the edge", () => {
    expect(neighbour(rects, "left", "left")).toBeNull();
    expect(neighbour(rects, "bottom", "down")).toBeNull();
  });

  it("returns null for an unknown pane", () => {
    expect(neighbour(rects, "ghost", "left")).toBeNull();
  });
});

describe("the change-simulation conversation of a pane", () => {
  it("is set and cleared on one pane only", () => {
    let ws = split(initial());
    const second = ws.focus;
    ws = reduce(ws, { type: "set-conversation", id: second, conversationId: "c1" });
    expect(panes(ws.root).map((p) => p.conversationId)).toEqual([undefined, "c1"]);
    ws = reduce(ws, { type: "set-conversation", id: second, conversationId: undefined });
    expect(panes(ws.root).map((p) => p.conversationId)).toEqual([undefined, undefined]);
  });

  it("survives a view switch and the open of an analysis pane", () => {
    let ws = initial();
    ws = reduce(ws, { type: "view", id: ws.focus, view: "changesim" });
    ws = reduce(ws, { type: "set-conversation", id: ws.focus, conversationId: "c1" });
    ws = reduce(ws, { type: "view", id: ws.focus, view: "trace" });
    ws = reduce(ws, { type: "view", id: ws.focus, view: "changesim" });
    expect(panes(ws.root)[0].conversationId).toBe("c1");
    ws = reduce(ws, { type: "open-analysis", id: ws.focus, mode: "simulation" });
    expect(panes(ws.root)[0]).toMatchObject({ view: "analysis", analysisMode: "simulation", conversationId: "c1" });
  });

  it("is not copied to the pane a split creates", () => {
    let ws = initial();
    ws = reduce(ws, { type: "view", id: ws.focus, view: "changesim" });
    ws = reduce(ws, { type: "set-conversation", id: ws.focus, conversationId: "c1" });
    ws = split(ws);
    expect(panes(ws.root).map((p) => p.conversationId)).toEqual(["c1", undefined]);
  });
});

describe("open-query", () => {
  it("raises queryNonce on every pick, also of the query the pane holds", () => {
    let ws = initial();
    const id = panes(ws.root)[0].id;
    ws = reduce(ws, { type: "open-query", id, queryKey: "cabling" });
    const first = panes(ws.root)[0].queryNonce;
    ws = reduce(ws, { type: "open-query", id, queryKey: "cabling" });
    const second = panes(ws.root)[0].queryNonce;
    expect(first).toBe(1);
    expect(second).toBe(2);
  });
});
