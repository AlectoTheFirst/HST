import ELK from "elkjs/lib/elk.bundled.js";
import { describe, expect, it } from "vitest";
import type { TopologyModel, TopologyNode } from "../api/types";
import {
  absolutePositions,
  blockBundles,
  crossesBlocks,
  segmentsFor,
  toElements,
  toElkGraph,
  withPositions,
  type Point,
} from "./layout";

function device(id: string, parent: string, tier: string, partition: number | null, depth: number): TopologyNode {
  return { id, kind: "device", parent, label: id, tier, role: "router", partition, depth };
}

/** Two hubs, a firewall pair, a vPC core pair, one distribution and two access
 *  switches at one site; the planner's model of it, cut down. */
const MODEL: TopologyModel = {
  snapshot: 1,
  nodes: [
    { id: "site:ber1", kind: "site", parent: null, label: "ber1" },
    { id: "block:ber1:wan-edge", kind: "block", parent: "site:ber1", label: "WAN edge", block_kind: "wan-edge" },
    {
      id: "block:ber1:firewall:campus+wan-edge",
      kind: "block",
      parent: "site:ber1",
      label: "Firewall (Campus, WAN edge)",
      block_kind: "firewall",
    },
    { id: "block:ber1:campus", kind: "block", parent: "site:ber1", label: "Campus", block_kind: "campus" },
    { id: "rgrp:vpc", kind: "group", parent: "block:ber1:campus", label: "vpc-domain-10", group_kind: "vpc" },
    device("rth-01", "block:ber1:wan-edge", "sdwan-hub", 0, 0),
    device("rth-02", "block:ber1:wan-edge", "sdwan-hub", 0, 0),
    device("fw-01", "block:ber1:firewall:campus+wan-edge", "firewall", 0, 1),
    device("fw-02", "block:ber1:firewall:campus+wan-edge", "firewall", 0, 1),
    device("swc-01", "rgrp:vpc", "core", 0, 2),
    device("swc-02", "rgrp:vpc", "core", 0, 2),
    device("swd-01", "block:ber1:campus", "distribution", 1, 3),
    device("swa-01", "block:ber1:campus", "access", 2, 4),
    device("swa-02", "block:ber1:campus", "access", 2, 4),
  ],
  cables: [
    ["rth-01", "fw-01"],
    ["rth-02", "fw-02"],
    ["fw-01", "swc-01"],
    ["fw-02", "swc-02"],
    ["swc-01", "swd-01"],
    ["swc-02", "swd-01"],
    ["swd-01", "swa-01"],
    ["swd-01", "swa-02"],
  ]
    .map(([a, b]) => ({
      id: `${a}~${b}`,
      from: { dev: a, port: "e1" },
      to: { dev: b, port: "e2" },
      source: "lldp",
      lateral: false,
    }))
    .concat([
      {
        id: "swc-01~swc-02",
        from: { dev: "swc-01", port: "Eth1/48" },
        to: { dev: "swc-02", port: "Eth1/48" },
        source: "lldp",
        lateral: true,
      },
    ]),
  exits: [{ dev: "swc-01", port: "Eth1/49", far_dev: "spine-1", far_port: "Eth1/1", far_name: "spine-1", source: "lldp" }],
  lags: [],
  split_groups: [],
};

async function laidOut() {
  return new ELK().layout(toElkGraph(MODEL));
}

describe("toElkGraph", () => {
  it("nests the boxes by parent and leaves the lateral cables out", () => {
    const graph = toElkGraph(MODEL);
    const site = graph.children![0];
    expect(site.id).toBe("site:ber1");
    expect(site.children!.map((c) => c.id)).toEqual([
      "block:ber1:wan-edge",
      "block:ber1:firewall:campus+wan-edge",
      "block:ber1:campus",
    ]);
    const ids = graph.edges!.map((e) => e.id);
    expect(ids).not.toContain("swc-01~swc-02");
    expect(ids).toContain("exit:0:cable");
  });
});

describe("the laid-out model", () => {
  it("layers the drawing from the outside in", async () => {
    const pos = absolutePositions(await laidOut());
    const y = (id: string) => pos.get(id)!.y;
    expect(y("rth-01")).toBeLessThan(y("fw-01"));
    expect(y("fw-01")).toBeLessThan(y("swc-01"));
    expect(y("swc-01")).toBeLessThan(y("swd-01"));
    expect(y("swd-01")).toBeLessThan(y("swa-01"));
    // a block is wholly above the next
    const wan = pos.get("block:ber1:wan-edge")!;
    expect(wan.y + wan.height).toBeLessThanOrEqual(pos.get("block:ber1:firewall:campus+wan-edge")!.y);
  });

  it("keeps every device inside its box", async () => {
    const pos = absolutePositions(await laidOut());
    for (const n of MODEL.nodes) {
      if (!n.parent) continue;
      const child = pos.get(n.id)!;
      const box = pos.get(n.parent)!;
      expect(child.x).toBeGreaterThanOrEqual(box.x);
      expect(child.y).toBeGreaterThanOrEqual(box.y);
      expect(child.x + child.width).toBeLessThanOrEqual(box.x + box.width + 0.01);
      expect(child.y + child.height).toBeLessThanOrEqual(box.y + box.height + 0.01);
    }
  });

  it("gives one edge per cable, and the segments give back the ELK route", async () => {
    const laid = await laidOut();
    const elements = toElements(MODEL, laid);
    const edges = elements.filter((e) => e.group === "edges");
    expect(edges).toHaveLength(MODEL.cables.length + MODEL.exits.length);
    const lateral = edges.find((e) => e.data.id === "swc-01~swc-02")!;
    expect(lateral.classes).toBe("cable lateral");
    // ELK routes the cables between layers; only straight drops need no bend
    const routed = edges.filter((e) => e.classes === "cable routed");
    const straight = edges.filter((e) => e.classes === "cable");
    expect(routed.length + straight.length).toBe(edges.length - 1);
    expect(routed.length).toBeGreaterThan(0);
    // every routed edge starts and ends on the border of its devices
    const nodes = new Map(elements.filter((e) => e.group === "nodes").map((e) => [e.data.id as string, e]));
    for (const edge of edges.filter((e) => e.classes === "cable routed")) {
      const src = nodes.get(edge.data.source as string)!;
      const [sx, sy] = String(edge.data.sourceEndpoint).split(" ").map(parseFloat);
      expect(Math.abs(sx)).toBeLessThanOrEqual((src.data.width as number) / 2 + 0.01);
      expect(Math.abs(sy)).toBeLessThanOrEqual(20.01);
    }
  });

  it("puts the exit stub in the block of its device", async () => {
    const elements = toElements(MODEL, await laidOut());
    const stub = elements.find((e) => e.data.id === "exit:0")!;
    expect(stub.data.parent).toBe("rgrp:vpc");
    expect(stub.data.label).toBe("to spine-1 Eth1/1");
  });
});

describe("segmentsFor", () => {
  /** Cytoscape's own placement of a segment point (findSegmentsPoints with
   *  edge-distances: endpoints). */
  function place(start: Point, end: Point, w: number, d: number): Point {
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const l = Math.sqrt(dx * dx + dy * dy);
    return { x: start.x + dx * w + (-dy / l) * d, y: start.y + dy * w + (dx / l) * d };
  }

  it("states each bend so that Cytoscape puts it back in place", () => {
    const start = { x: 10, y: 20 };
    const end = { x: 200, y: 300 };
    const bends = [
      { x: 10, y: 160 },
      { x: 200, y: 160 },
    ];
    const { weights, distances } = segmentsFor(start, end, bends);
    bends.forEach((b, i) => {
      const p = place(start, end, weights[i], distances[i]);
      expect(p.x).toBeCloseTo(b.x, 6);
      expect(p.y).toBeCloseTo(b.y, 6);
    });
  });

  it("gives nothing for an edge whose ends meet", () => {
    expect(segmentsFor({ x: 1, y: 1 }, { x: 1, y: 1 }, [{ x: 2, y: 2 }])).toEqual({ weights: [], distances: [] });
  });
});

describe("blockBundles", () => {
  it("gives one line per block pair with the count of its cables", () => {
    const bundles = blockBundles(MODEL);
    expect(bundles.map((b) => [b.data.source, b.data.target, b.data.label])).toEqual([
      ["block:ber1:firewall:campus+wan-edge", "block:ber1:campus", "2 cables"],
      ["block:ber1:wan-edge", "block:ber1:firewall:campus+wan-edge", "2 cables"],
    ]);
    // the cables inside one block, and the peer-link in the vPC group, stay out
    expect(crossesBlocks(MODEL)).toEqual(new Set(["rth-01~fw-01", "rth-02~fw-02", "fw-01~swc-01", "fw-02~swc-02"]));
  });
});

describe("withPositions", () => {
  it("moves a stored device and draws its cables straight", async () => {
    const elements = toElements(MODEL, await laidOut());
    const moved = withPositions(elements, { "swd-01": { x: 900, y: 900 }, "not-drawn": { x: 1, y: 1 } });
    const swd = moved.find((e) => e.data.id === "swd-01")!;
    expect(swd.position).toEqual({ x: 900, y: 900 });
    for (const e of moved.filter((x) => x.group === "edges")) {
      const touches = e.data.source === "swd-01" || e.data.target === "swd-01";
      expect(String(e.classes).includes("moved")).toBe(touches);
      if (touches) expect(String(e.classes)).not.toMatch(/\brouted\b/);
    }
    // nothing stored: the same elements
    expect(withPositions(elements, {})).toBe(elements);
  });
});

describe("LAGs at level 4", () => {
  const LAGGED: TopologyModel = {
    ...MODEL,
    cables: MODEL.cables.map((c) => (c.id === "swc-01~swd-01" ? { ...c, to: { dev: "swd-01", port: "Eth1/1" } } : c)),
    lags: [
      {
        id: "lag:swd-01:po1",
        dev: "swd-01",
        name: "Po1",
        cables: ["swc-01~swd-01", "swc-02~swd-01"],
        far: ["swc-01", "swc-02"],
        ports_without_cable: ["Eth1/3"],
        neighbors_without_cable: [],
        multi_chassis: true,
        basis: "inferred",
      },
    ],
  };

  it("marks the member cables, names the LAG at its end, and draws a loose member as a stub", async () => {
    const elements = toElements(LAGGED, await new ELK().layout(toElkGraph(LAGGED)));
    const member = elements.find((e) => e.data.id === "swc-01~swd-01")!;
    expect(String(member.classes)).toMatch(/\blag\b.*\blag-multi\b/);
    expect(member.data.targetPort).toBe("Eth1/1 Po1");
    expect(member.data.sourcePort).toBe("e1");
    const stub = elements.find((e) => e.data.id === "loose:lag:swd-01:po1:Eth1/3")!;
    expect(stub.data.label).toBe("Po1 member, no cable");
    expect(stub.data.parent).toBe("block:ber1:campus");
    const line = elements.find((e) => e.data.id === "loose:lag:swd-01:po1:Eth1/3:cable")!;
    expect(String(line.classes)).toContain("loose");
    expect(line.data.sourcePort).toBe("Eth1/3");
    // a cable of no LAG has no halo
    expect(String(elements.find((e) => e.data.id === "rth-01~fw-01")!.classes)).not.toContain("lag");
  });
});

describe("loose LAG members", () => {
  it("draws the loose members of one LAG as one stub", async () => {
    const model: TopologyModel = {
      ...MODEL,
      lags: [
        {
          id: "lag:swd-01:po51",
          dev: "swd-01",
          name: "Po51",
          cables: [],
          far: [],
          ports_without_cable: ["Eth1/5", "Eth1/6"],
          neighbors_without_cable: [],
          multi_chassis: false,
          basis: "collector",
        },
      ],
    };
    const elements = toElements(model, await new ELK().layout(toElkGraph(model)));
    const loose = elements.filter((e) => String(e.classes).includes("exit loose"));
    expect(loose.map((e) => e.data.label)).toEqual(["Po51, 2 members, no cable"]);
    const line = elements.find((e) => e.data.id === "loose:lag:swd-01:po51:Eth1/5,Eth1/6:cable")!;
    expect(line.data.sourcePort).toBe("Eth1/5, Eth1/6");
  });

  it("draws a loose member with a neighbor as its own stub with the neighbor and the far port", async () => {
    const model: TopologyModel = {
      ...MODEL,
      lags: [
        {
          id: "lag:swd-01:po51",
          dev: "swd-01",
          name: "Po51",
          cables: [],
          far: [],
          ports_without_cable: ["Eth1/5", "Eth1/6", "Eth1/7"],
          neighbors_without_cable: [
            { port: "Eth1/6", far_name: "swc-01", far_port: "Gi0/1", source: "cdp, no cable" },
            { port: "Eth1/7", far_name: "swc-02", far_port: null, source: "lldp, no cable" },
          ],
          multi_chassis: false,
          basis: "collector",
        },
      ],
    };
    const elements = toElements(model, await new ELK().layout(toElkGraph(model)));
    const loose = elements.filter((e) => String(e.classes).includes("exit loose"));
    expect(loose.map((e) => e.data.label)).toEqual([
      "Po51 member, no cable",
      "Po51 member, no cable, swc-01 Gi0/1",
      "Po51 member, no cable, swc-02",
    ]);
    const line = elements.find((e) => e.data.id === "loose:lag:swd-01:po51:Eth1/6:cable")!;
    expect(String(line.classes)).toContain("loose");
    expect(line.data.sourcePort).toBe("Eth1/6");
    expect(line.data.targetPort).toBe("Gi0/1");
  });

  it("marks an exit to a neighbor with no device as undiscovered", async () => {
    const model: TopologyModel = {
      ...MODEL,
      exits: [
        ...MODEL.exits,
        { dev: "swc-01", port: "Eth1/50", far_dev: "", far_port: "Gi0/1", far_name: "ap-07", source: "cdp, no cable" },
      ],
    };
    const elements = toElements(model, await new ELK().layout(toElkGraph(model)));
    const classes = (id: string) => elements.find((e) => e.data.id === id)!.classes;
    expect(classes("exit:0")).toBe("exit");
    expect(classes("exit:1")).toBe("exit undiscovered");
  });
});
