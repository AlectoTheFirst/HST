import { describe, expect, it } from "vitest";
import type { GraphNode, GraphRelationship, ResultGraph } from "../api/types";
import { GRAPH, hub, NODES } from "../test/resultFixture";
import { adjacency } from "./treeModel";
import {
  BOX_H,
  BOX_H2,
  BOX_W,
  COL_GAP,
  cutMiddle,
  drawnIds,
  GAP_X,
  GROUP_MIN,
  HEAD,
  laneStep,
  layerOf,
  MEMBER_H,
  PAD,
  picture,
  PICTURE_CAP,
  pictureModel,
  shapePath,
  sideStep,
} from "./lanes";

const adj = adjacency(GRAPH);
const slotOf = (label: string) => ["Device", "Interface", "IpAddress", "Prefix", "Site", "Endpoint", "BridgeDomain"].indexOf(label);
const item = (pic: ReturnType<typeof picture>, id: string) => pic.items.find((n) => n.id === id)!;
/** The left-to-right layout. */
const lr = (g: ReturnType<typeof adjacency>, seeds: string[], open: ReadonlySet<string> = new Set()) =>
  picture(g, seeds, slotOf, open, PICTURE_CAP, { dir: "lr", neighbours: true });

/** A bridge domain with `n` endpoints in it, each with an address. */
function bridge(n: number): ResultGraph {
  const nodes: GraphNode[] = [{ id: "bd", labels: ["BridgeDomain", "L2"], properties: { uid: "bd:105", name: "VL_105_IOT" } }];
  const relationships: GraphRelationship[] = [];
  for (let i = 0; i < n; i++) {
    nodes.push({ id: `e${i}`, labels: ["Endpoint", "L2"], properties: { uid: `ep:unifi:default:02:00:00:00:00:${i}`, hostname: `host-${String(i).padStart(2, "0")}` } });
    nodes.push({ id: `a${i}`, labels: ["IpAddress", "L3"], properties: { uid: `ip:${i}`, ip: `10.105.0.${i}` } });
    relationships.push({ id: `in${i}`, type: "IN", start: `e${i}`, end: "bd", properties: {} });
    relationships.push({ id: `ip${i}`, type: "HAS_IP", start: `e${i}`, end: `a${i}`, properties: {} });
  }
  return { nodes, relationships, truncated: false };
}

describe("layerOf and cutMiddle", () => {
  it("takes the first schema layer in LAYERS order, else Other", () => {
    expect(layerOf(NODES.d1)).toBe("Phys");
    expect(layerOf(NODES.a1)).toBe("L3");
    expect(layerOf({ id: "x", labels: ["Thing", "Meta", "L2"], properties: {} })).toBe("L2");
    expect(layerOf({ id: "x", labels: ["Thing"], properties: {} })).toBe("Other");
  });

  it("cuts a long text once, in the middle, and keeps a short one", () => {
    expect(cutMiddle("thermostat-room-001", 19)).toBe("thermostat-room-001");
    const cut = cutMiddle("ep:unifi-ckey-1:default:02:00:00:01:aa:10", 19);
    expect(cut).toHaveLength(19);
    expect(cut.startsWith("ep:unifi")).toBe(true);
    expect(cut.endsWith("01:aa:10")).toBe(true);
  });
});

describe("pictureModel", () => {
  it("draws only the seeds and the links between them by default", () => {
    const g = adjacency(bridge(GROUP_MIN + 2));
    const pic = picture(g, ["e0", "bd", "a0"], slotOf);
    expect(pic.items.map((n) => n.id).sort()).toEqual(["a0", "bd", "e0"]);
    expect(pic.neighbourCount).toBe(0);
    expect(pic.edges.map((e) => e.type).sort()).toEqual(["HAS_IP", "IN"]);
    expect(drawnIds(g, ["e0"])).toEqual(new Set(["e0"]));
  });

  it("draws the seeds and their neighbours, ranked by links to the seeds, then by caption", () => {
    const m = pictureModel(adj, ["a1", "a2", "d1"], PICTURE_CAP, true);
    expect(m.seedSingles).toEqual(["a1", "a2", "d1"]);
    expect(m.singles).toEqual(["p1", "i1", "s1", "i2"]);
    expect(m.groups).toEqual([]);
    expect(m.hidden).toBe(0);
  });

  it("puts GROUP_MIN or more neighbours with the same label and the same links in 1 group", () => {
    const g = adjacency(bridge(26));
    const m = pictureModel(g, ["bd"], PICTURE_CAP, true);
    expect(m.singles).toEqual([]);
    expect(m.groups).toHaveLength(1);
    expect(m.groups[0].ids).toHaveLength(26);
    expect(m.groups[0].ids[0]).toBe("e0");
    expect(m.itemOf.get("e5")).toBe(m.groups[0].id);
  });

  it("keeps fewer than GROUP_MIN neighbours as single boxes", () => {
    const m = pictureModel(adjacency(bridge(GROUP_MIN - 1)), ["bd"], PICTURE_CAP, true);
    expect(m.groups).toEqual([]);
    expect(m.singles).toHaveLength(GROUP_MIN - 1);
  });

  it("puts GROUP_MIN or more seeds with the same label in 1 seed group", () => {
    const g = adjacency(bridge(26));
    const seeds = Array.from({ length: 26 }, (_, i) => [`e${i}`, `a${i}`, "bd"]).flat();
    const m = pictureModel(g, seeds, PICTURE_CAP, true);
    expect(m.seedGroups.map((x) => x.id).sort()).toEqual(["s:Endpoint", "s:IpAddress"]);
    expect(m.seedSingles).toEqual(["bd"]);
    expect(drawnIds(g, seeds, PICTURE_CAP, true).size).toBe(53);
  });

  it("keeps the seeds and cuts the neighbours at the cap", () => {
    const m = pictureModel(adj, ["a1", "a2"], 3, true);
    expect(m.singles).toEqual(["p1"]);
    expect(m.hidden).toBe(2);
  });

  it("draws no neighbours when the seeds are over the cap", () => {
    const g = adjacency(hub(50));
    const seeds = ["h", ...Array.from({ length: 5 }, (_, i) => `h${i}`)];
    const m = pictureModel(g, seeds, 3, true);
    expect(m.seedSingles).toEqual(["h", "h0", "h1"]);
    expect(m.groups).toEqual([]);
    expect(m.singles).toEqual([]);
    expect(m.hidden).toBe(3 + 45);
  });
});

describe("picture, left to right", () => {
  it("gives each layer a seed column, then a neighbour column, in LAYERS order", () => {
    const pic = lr(adj, ["d1", "i1"]);
    expect(pic.layers.map((l) => l.name)).toEqual(["Phys", "L2", "L3"]);
    const col = (id: string) => item(pic, id).col;
    expect(col("d1")).toBeLessThan(col("s1"));
    expect(col("s1")).toBeLessThan(col("i1"));
    expect(col("i1")).toBeLessThan(col("a1"));
    expect(item(pic, "d1").x).toBe(PAD);
    expect(item(pic, "s1").x).toBe(PAD + BOX_W + COL_GAP);
  });

  it("draws 26 endpoints of a bridge domain as 1 group box with 1 counted link", () => {
    const g = adjacency(bridge(26));
    const pic = lr(g, ["bd"]);
    expect(pic.items.map((n) => n.kind)).toEqual(["node", "group"]);
    const group = pic.items[1];
    expect(group.caption).toBe("26 Endpoint");
    expect(group.h).toBe(BOX_H2);
    expect(pic.edges).toHaveLength(1);
    expect(pic.edges[0]).toMatchObject({ type: "IN", count: 26 });
    expect(pic.neighbourCount).toBe(26);
    // the seed and the group are in 2 columns of 1 layer: a curve, not a loop
    expect(group.col).toBe(item(pic, "bd").col + 1);
    expect(pic.edges[0].d.startsWith(`M${item(pic, "bd").x + BOX_W},`)).toBe(true);
  });

  it("opens a group box to a list of its first members", () => {
    const g = adjacency(bridge(26));
    const id = pictureModel(g, ["bd"], PICTURE_CAP, true).groups[0].id;
    const pic = lr(g, ["bd"], new Set([id]));
    const group = item(pic, id);
    expect(group.open).toBe(true);
    expect(group.h).toBe(BOX_H2 + 11 * MEMBER_H + 6);
  });

  it("adds a second line when 2 boxes have the same caption", () => {
    const pic = lr(adj, ["i1", "i2"]);
    expect([item(pic, "i1").second, item(pic, "i1").h]).toEqual(["r1", BOX_H2]);
    expect(item(pic, "d1").second).toBeUndefined();
    expect(item(pic, "d1").h).toBe(BOX_H);
  });

  it("starts the boxes under the layer names", () => {
    const pic = lr(adj, ["d1"]);
    expect(Math.min(...pic.items.map((n) => n.y))).toBeGreaterThanOrEqual(HEAD);
  });

  it("is empty without seeds", () => {
    const pic = lr(adj, []);
    expect([pic.items.length, pic.layers.length, pic.width, pic.height]).toEqual([0, 0, 0, 0]);
  });

  it("moves inside a column and to the nearest box of the next column", () => {
    const pic = lr(adj, ["d1", "d2"]);
    expect(laneStep(pic, "d1", 1)).toBe("d2");
    expect(laneStep(pic, "d1", -1)).toBeNull();
    expect(sideStep(pic, "d1", 1)).not.toBeNull();
    expect(sideStep(pic, "d1", -1)).toBeNull();
  });
});

describe("picture, top down", () => {
  it("is the default and puts each band in 1 row, the seeds above the neighbours", () => {
    const pic = picture(adj, ["d1", "i1"], slotOf, new Set(), PICTURE_CAP, { neighbours: true });
    expect(pic.dir).toBe("tb");
    expect(pic.layers.map((l) => [l.name, l.anchor])).toEqual([["Phys", "start"], ["L2", "start"], ["L3", "start"]]);
    const y = (id: string) => item(pic, id).y;
    expect(y("d1")).toBeLessThan(y("s1"));
    expect(y("s1")).toBeLessThan(y("i1"));
    expect(y("i1")).toBeLessThan(y("a1"));
  });

  it("wraps a band at the width and keeps the picture inside it", () => {
    const g = adjacency(bridge(GROUP_MIN - 1));
    const pic = picture(g, ["bd"], slotOf, new Set(), PICTURE_CAP, { width: 400, neighbours: true });
    const ends = pic.items.filter((n) => n.label === "Endpoint");
    expect(ends).toHaveLength(GROUP_MIN - 1);
    expect(new Set(ends.map((n) => n.y)).size).toBe(4);
    expect(pic.width).toBeLessThanOrEqual(400);
    expect(pic.width).toBe(PAD * 2 + 2 * (BOX_W + GAP_X) - GAP_X);
  });

  it("draws a link from the bottom of the upper box to the top of the lower box", () => {
    const g = adjacency(bridge(26));
    const pic = picture(g, ["bd"], slotOf, new Set(), PICTURE_CAP, { neighbours: true });
    const bd = item(pic, "bd");
    const group = pic.items[1];
    expect(pic.edges[0].d).toBe(`M${bd.x + BOX_W / 2},${bd.y + bd.h} C${bd.x + BOX_W / 2},${(bd.y + bd.h + group.y) / 2} ${group.x + BOX_W / 2},${(bd.y + bd.h + group.y) / 2} ${group.x + BOX_W / 2},${group.y}`);
  });

  it("moves inside a line with laneStep and to the next line with sideStep", () => {
    const pic = picture(adj, ["d1", "d2"], slotOf, new Set(), PICTURE_CAP, { neighbours: true });
    expect(laneStep(pic, "d1", 1)).toBe("d2");
    expect(laneStep(pic, "d1", -1)).toBeNull();
    const below = sideStep(pic, "d1", 1);
    expect(below).not.toBeNull();
    expect(item(pic, below!).y).toBeGreaterThan(item(pic, "d1").y);
    expect(sideStep(pic, "d1", -1)).toBeNull();
  });
});

describe("shapePath", () => {
  it("draws a closed path for each slot and for Other", () => {
    for (let slot = 0; slot <= 8; slot++) {
      const d = shapePath(slot, 12);
      expect(d.startsWith("M")).toBe(true);
      expect(d.endsWith("Z")).toBe(true);
    }
    expect(new Set(Array.from({ length: 8 }, (_, i) => shapePath(i, 12))).size).toBe(8);
  });
});
