import { describe, expect, it } from "vitest";
import { GRAPH, hub, NODES, RESULT } from "../test/resultFixture";
import {
  adjacency,
  branchText,
  buildRows,
  filterTree,
  findPath,
  groupText,
  itemText,
  keepFiltered,
  reveal,
  revealNode,
  rootsOf,
  summary,
  type DetailState,
  type PageState,
  type TreeInput,
} from "./treeModel";

const IFACE = "n:d1|g:HAS_INTERFACE:out:Interface";

function input(over: Partial<TreeInput> = {}, graph = GRAPH, rows = RESULT.data): TreeInput {
  const { roots, rowsOfRoot } = rootsOf(rows, graph);
  return {
    adj: adjacency(graph),
    roots,
    rowsOfRoot,
    resultRels: new Set(graph.relationships.map((r) => r.id)),
    detail: () => undefined,
    page: () => undefined,
    open: new Set(),
    limits: new Map(),
    full: false,
    ...over,
  };
}

const keys = (inp: TreeInput, extra?: Set<string>, pinned?: Set<string>) => buildRows(inp, extra, pinned).map((i) => i.key);

describe("roots", () => {
  it("takes the first node of each row, once, in row order", () => {
    const { roots, rowsOfRoot } = rootsOf(
      [...RESULT.data, { row: [], nodes: ["d1", "p1"] }],
      GRAPH,
    );
    expect(roots).toEqual(["d1", "d2"]);
    expect(rowsOfRoot.get("d1")).toEqual([0, 2]);
  });

  it("uses the payload nodes when no row has a row node index", () => {
    const { roots } = rootsOf([{ row: [1] }], GRAPH);
    expect(roots).toEqual(GRAPH.nodes.map((n) => n.id));
  });
});

describe("buildRows", () => {
  it("shows the roots, and the groups of an open node sorted by type", () => {
    const items = buildRows(input({ open: new Set(["n:d1"]) }));
    expect(items.map((i) => [i.key, i.kind, i.level, i.posinset, i.setsize])).toEqual([
      ["n:d1", "node", 1, 1, 2],
      [IFACE, "group", 2, 1, 2],
      ["n:d1|g:LOCATED_IN:out:Site", "group", 2, 2, 2],
      ["n:d2", "node", 1, 2, 2],
    ]);
    expect(items[0].rows).toEqual([0]);
  });

  it("shows a node already open above as a reference item", () => {
    const back = `${IFACE}|n:i1|g:HAS_INTERFACE:in:Device`;
    const items = buildRows(input({ open: new Set(["n:d1", IFACE, `${IFACE}|n:i1`, back]) }));
    const ref = items.find((i) => i.key === `${back}|n:d1`)!;
    expect(ref.kind).toBe("ref");
    expect(ref.reason).toBe("above");
    expect(ref.target).toBe("n:d1");
    expect(itemText(adjacency(GRAPH), ref)).toBe("r1  (already open above)");
  });

  it("shows another root as a reference item to its own branch", () => {
    const site = "n:d1|g:LOCATED_IN:out:Site|n:s1";
    const back = `${site}|g:LOCATED_IN:in:Device`;
    const items = buildRows(input({ open: new Set(["n:d1", "n:d1|g:LOCATED_IN:out:Site", site, back]) }));
    const refs = items.filter((i) => i.parent === back);
    expect(refs.map((r) => [r.nodeId, r.reason, r.target])).toEqual([
      ["d1", "above", "n:d1"],
      ["d2", "root", "n:d2"],
    ]);
  });

  it("joins the snapshot counts and adds the snapshot-only groups", () => {
    const detail = (uid: string): DetailState | undefined =>
      uid === "dev:r1"
        ? {
            status: "ok",
            groups: [
              { type: "HAS_INTERFACE", direction: "out", label: "Interface", count: 48 },
              { type: "HAS_VLAN", direction: "out", label: "Vlan", count: 3 },
              { type: "LOCATED_IN", direction: "out", label: "Site", count: 1 },
            ],
          }
        : undefined;
    const items = buildRows(input({ open: new Set(["n:d1", IFACE]), detail }));
    const groups = items.filter((i) => i.kind === "group").map((i) => groupText(i.group!));
    expect(groups).toEqual([
      "HAS_INTERFACE to Interface (1 in result, 48 in snapshot)",
      "HAS_VLAN to Vlan (0 in result, 3 in snapshot)",
      "LOCATED_IN to Site (1)",
    ]);
    const load = items.find((i) => i.key === `${IFACE}|load`)!;
    expect(load.kind).toBe("more");
    expect(itemText(adjacency(GRAPH), load)).toBe("Load 48 more from the snapshot");
  });

  it("shows the state of a snapshot page load", () => {
    const detail = (): DetailState => ({ status: "ok", groups: [{ type: "HAS_INTERFACE", direction: "out", label: "Interface", count: 120 }] });
    const at = (page: PageState) => buildRows(input({ open: new Set(["n:d1", IFACE]), detail, page: () => page })).filter((i) => i.parent === IFACE);
    expect(at({ offset: 50, status: "idle" }).at(-1)!.count).toBe(50);
    expect(at({ offset: 100, status: "idle" }).at(-1)!.count).toBe(20);
    expect(at({ offset: 50, status: "loading" }).at(-1)!.kind).toBe("loading");
    const err = at({ offset: 50, status: "error", message: "boom" }).at(-1)!;
    expect([err.kind, err.message, err.retry]).toEqual(["error", "boom", { kind: "page", uid: "dev:r1", gid: "HAS_INTERFACE:out:Interface" }]);
  });

  it("turns off a page load when the view graph is full", () => {
    const detail = (): DetailState => ({ status: "ok", groups: [{ type: "HAS_INTERFACE", direction: "out", label: "Interface", count: 9 }] });
    const load = buildRows(input({ open: new Set(["n:d1", IFACE]), detail, full: true })).find((i) => i.kind === "more")!;
    expect(load.disabled).toBe(true);
    expect(itemText(adjacency(GRAPH), load)).toBe("Node limit reached");
  });

  it("shows a loading item and an error item for the node detail", () => {
    const loading = buildRows(input({ open: new Set(["n:d1"]), detail: () => ({ status: "loading" }) }));
    expect(loading.some((i) => i.key === "n:d1|loading")).toBe(true);
    const failed = buildRows(input({ open: new Set(["n:d1"]), detail: () => ({ status: "error", message: "no" }) }));
    const err = failed.find((i) => i.key === "n:d1|error")!;
    expect(err.retry).toEqual({ kind: "detail", uid: "dev:r1" });
    // the result groups still show
    expect(failed.filter((i) => i.kind === "group")).toHaveLength(2);
  });

  it("shows 20 result items of a group, then a Show more item, and pinned items past the limit", () => {
    const g = hub(25);
    const group = "n:h|g:HAS_INTERFACE:out:Interface";
    const base = input({ open: new Set(["n:h", group]) }, g, [{ row: [], nodes: ["h"] }]);
    const kids = buildRows(base).filter((i) => i.parent === group);
    expect(kids).toHaveLength(21);
    expect(itemText(base.adj, kids[20])).toBe("Show 5 more");
    const more = buildRows({ ...base, limits: new Map([[group, 40]]) }).filter((i) => i.parent === group);
    expect(more).toHaveLength(25);
    const pinned = buildRows(base, undefined, new Set([`${group}|n:h24`])).filter((i) => i.parent === group);
    expect(pinned.map((i) => i.nodeId)).toContain("h24");
  });

  it("tags a node reached by a relationship the query did not return", () => {
    const grown = { ...GRAPH, relationships: [...GRAPH.relationships, { id: "x", type: "HAS_INTERFACE", start: "d1", end: "i2", properties: {} }] };
    const inp = { ...input({ open: new Set(["n:d1", IFACE]) }), adj: adjacency(grown) };
    const kids = buildRows(inp).filter((i) => i.parent === IFACE);
    expect(kids.map((k) => [k.nodeId, k.snapshot])).toEqual([["i1", false], ["i2", true]]);
  });
});

describe("summary", () => {
  it("shows up to 3 key properties of the primary label", () => {
    expect(summary(NODES.d1)).toBe("Juniper, MX204, router");
    expect(summary(NODES.i1)).toBe("phys, 9192");
    expect(summary(NODES.a1)).toBe("");
  });
});

describe("filterTree", () => {
  it("finds a closed match and opens the path to it", () => {
    const f = filterTree(input(), "10.0.0.2");
    const target = "n:d2|g:HAS_INTERFACE:out:Interface|n:i2|g:HAS_IP:out:IpAddress|n:a2";
    expect([...f.matches]).toEqual([target]);
    expect([...f.open]).toEqual([
      "n:d2",
      "n:d2|g:HAS_INTERFACE:out:Interface",
      "n:d2|g:HAS_INTERFACE:out:Interface|n:i2",
      "n:d2|g:HAS_INTERFACE:out:Interface|n:i2|g:HAS_IP:out:IpAddress",
    ]);
    expect(keys(input(), f.open, f.onPath)).toContain(target);
  });

  it("searches 3 node levels under each root only", () => {
    expect(filterTree(input(), "10.0.0.0/31").matches.size).toBeGreaterThan(0);
    expect(filterTree(input(), "10.0.0.0/31", 2).matches.size).toBe(0);
  });

  it("matches without case and ignores an empty filter", () => {
    expect(filterTree(input(), "JUNIPER").matches).toEqual(new Set(["n:d1"]));
    expect(filterTree(input(), "  ").matches.size).toBe(0);
  });
});

describe("keepFiltered", () => {
  it("hides the items off the path to a match and renumbers the kept siblings", () => {
    const f = filterTree(input(), "10.0.0.2");
    const kept = keepFiltered(buildRows(input(), f.open, f.onPath), f);
    const target = "n:d2|g:HAS_INTERFACE:out:Interface|n:i2|g:HAS_IP:out:IpAddress|n:a2";
    expect(kept.map((i) => i.key)).toEqual([
      "n:d2",
      "n:d2|g:HAS_INTERFACE:out:Interface",
      "n:d2|g:HAS_INTERFACE:out:Interface|n:i2",
      "n:d2|g:HAS_INTERFACE:out:Interface|n:i2|g:HAS_IP:out:IpAddress",
      target,
    ]);
    expect(kept.map((i) => [i.posinset, i.setsize])).toEqual(kept.map(() => [1, 1]));
  });

  it("keeps what an open match shows under it", () => {
    const f = filterTree(input(), "JUNIPER");
    const rows = buildRows(input({ open: new Set(["n:d1"]) }), f.open, f.onPath);
    const kept = keepFiltered(rows, f).map((i) => i.key);
    expect(kept[0]).toBe("n:d1");
    expect(kept).toEqual(rows.filter((i) => i.key.startsWith("n:d1")).map((i) => i.key));
    expect(kept).not.toContain("n:d2");
  });
});

describe("branchText", () => {
  it("writes the item and its visible children as plain text", () => {
    const inp = input({ open: new Set(["n:d1", IFACE]) });
    const items = buildRows(inp);
    expect(branchText(inp.adj, items, 0)).toBe(
      [
        "r1  Device  Juniper, MX204, router",
        "|-- HAS_INTERFACE to Interface (1)",
        "|   `-- ge-0/0/1  Interface  phys, 9192",
        "`-- LOCATED_IN to Site (1)",
      ].join("\n"),
    );
    expect(branchText(inp.adj, items, 1)).toBe("HAS_INTERFACE to Interface (1)\n`-- ge-0/0/1  Interface  phys, 9192");
  });
});

describe("reveal", () => {
  it("opens the path from the row root to each node of the row", () => {
    const adj = adjacency(GRAPH);
    const r = reveal(adj, ["d1", "d2"], "d1", ["i1", "a1", "p1", "s1"]);
    expect(r.keyOf.get("p1")).toBe(`${IFACE}|n:i1|g:HAS_IP:out:IpAddress|n:a1|g:IN:out:Prefix|n:p1`);
    expect(r.open.has(`${IFACE}|n:i1`)).toBe(true);
    expect(r.open.has(`${IFACE}|n:i1|g:HAS_IP:out:IpAddress|n:a1|g:IN:out:Prefix|n:p1`)).toBe(false);
    expect(r.missing).toEqual([]);
    const items = buildRows(input({ open: r.open }), undefined, r.pinned);
    expect(items.map((i) => i.key)).toContain(r.keyOf.get("p1"));
  });

  it("reports a node with no path from the root", () => {
    const g = { ...GRAPH, nodes: [...GRAPH.nodes, { id: "z", labels: ["Zone"], properties: {} }] };
    expect(reveal(adjacency(g), ["d1"], "d1", ["z"]).missing).toEqual(["z"]);
  });

  it("does not pass through another root", () => {
    const adj = adjacency(GRAPH);
    // the short way from d1 to i2 runs through the site and d2, and d2 is a root
    expect(findPath(adj, new Set(["d1"]), "d1", "i2")).toHaveLength(3);
    expect(findPath(adj, new Set(["d1", "d2"]), "d1", "i2")).toHaveLength(5);
    expect(findPath(adj, new Set(["d1", "d2"]), "d1", "i2", 4)).toBeNull();
  });

  it("reveals a node from the nearest root", () => {
    const r = revealNode(adjacency(GRAPH), ["d1", "d2"], "a2")!;
    expect(r.keyOf.get("a2")).toBe("n:d2|g:HAS_INTERFACE:out:Interface|n:i2|g:HAS_IP:out:IpAddress|n:a2");
  });
});

describe("size", () => {
  it("builds 2,000 visible items in under 50 ms", () => {
    const g = hub(1999);
    const group = "n:h|g:HAS_INTERFACE:out:Interface";
    const inp = input({ open: new Set(["n:h", group]), limits: new Map([[group, 2000]]) }, g, [{ row: [], nodes: ["h"] }]);
    buildRows(inp); // warm up
    const t0 = performance.now();
    const items = buildRows(inp);
    const ms = performance.now() - t0;
    expect(items).toHaveLength(2001);
    expect(ms).toBeLessThan(50);
  });
});
