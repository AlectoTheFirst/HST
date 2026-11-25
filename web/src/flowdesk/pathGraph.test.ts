import { describe, expect, it } from "vitest";
import { boxOfHop, buildPathGraph, laneWalks, pathVia, selectedLanes, type GraphBox, type PathGraph } from "./pathGraph";
import {
  FIXTURE_PATH_BLOCKED,
  FIXTURE_PATH_ECMP,
  FIXTURE_PATH_LEAF_SPINE,
  FIXTURE_PATH_PARTITION,
  FIXTURE_PATH_SINGLE,
} from "../test/fixtures";
import type { Hop, Leg } from "../api/types";

/** The boxes of a hop uid, optionally only those a lane crosses. */
const boxesOf = (g: PathGraph, uid: string, lane?: number) =>
  g.boxes.filter((b) => b.hop.uid === uid && (lane === undefined || b.lanes.includes(lane)));
/** The 1 box of a hop uid; fails when there is none or more than 1. */
const box = (g: PathGraph, uid: string, lane?: number): GraphBox => {
  const list = boxesOf(g, uid, lane);
  if (list.length !== 1) throw new Error(`${list.length} boxes for ${uid}`);
  return list[0];
};
const link = (g: PathGraph, from: GraphBox, to: GraphBox) => g.links.find((l) => l.from === from.key && l.to === to.key);
const uids = (g: PathGraph, keys: string[]) => keys.map((k) => g.byKey.get(k)!.hop.uid);

function leg(lane: number, extra: Partial<Leg> = {}): Leg {
  return {
    ...FIXTURE_PATH_SINGLE.legs[0],
    lane,
    ...extra,
  };
}
function dev(uid: string, rank: number, lane = 0, extra: Partial<Hop> = {}): Hop {
  return { uid, kind: "Device", label: uid, note: "", rank, lane, shared: false, ...extra };
}

describe("laneWalks", () => {
  it("walks the shared hops by rank, then the lane's own hops by rank", () => {
    const walks = laneWalks(FIXTURE_PATH_ECMP);
    expect(walks.map((w) => w.lane)).toEqual([0, 1]);
    expect(walks[0].hops.map((h) => h.uid)).toEqual([
      "if:core1/eth0.10",
      "dev:core1",
      "vrf:default",
      "pfx:0.0.0.0/0#a",
      "if:core1/eth0.1",
    ]);
    expect(walks[1].hops.map((h) => h.uid)).toEqual(["if:core1/eth0.10", "dev:core1", "tun:wg0"]);
  });
});

describe("buildPathGraph: a single path", () => {
  it("keeps the source, the devices and the destination, on 1 track", () => {
    const g = buildPathGraph(FIXTURE_PATH_SINGLE, "devices");
    expect(g.boxes.map((b) => b.hop.uid)).toEqual(["ep:host44", "dev:sw1", "dev:core1", "if:core1/eth0.1"]);
    expect(g.boxes.map((b) => b.col)).toEqual([0, 1, 2, 3]);
    expect(g.boxes.every((b) => b.row === 0)).toBe(true);
    expect(g.links).toHaveLength(3);
    expect(g.cols).toBe(4);
    expect(g.rows).toBe(1);
  });

  it("names the interfaces between 2 kept hops on the link", () => {
    const g = buildPathGraph(FIXTURE_PATH_SINGLE, "devices");
    expect(link(g, box(g, "ep:host44"), box(g, "dev:sw1"))?.via.get(0)).toBe("eth1");
    expect(link(g, box(g, "dev:sw1"), box(g, "dev:core1"))?.via.get(0)).toBe("eth0.10");
    expect(link(g, box(g, "dev:core1"), box(g, "if:core1/eth0.1"))?.via.has(0)).toBe(false);
  });

  it("keeps every hop in All hops mode, with no link names", () => {
    const g = buildPathGraph(FIXTURE_PATH_SINGLE, "all");
    expect(g.boxes).toHaveLength(FIXTURE_PATH_SINGLE.hops.length);
    expect(g.links).toHaveLength(FIXTURE_PATH_SINGLE.hops.length - 1);
    expect(g.links.every((l) => l.via.size === 0)).toBe(true);
  });

  it("puts the gate verdict and the leg outcome on the boxes", () => {
    const g = buildPathGraph(FIXTURE_PATH_BLOCKED, "devices");
    expect(box(g, "fwrb:IOT-LAN").verdict).toBe("bad");
    expect(box(g, "fwrb:IOT-LAN").endOutcome).toBe("bad");
    expect(box(g, "dev:core1").verdict).toBeNull();
  });
});

describe("buildPathGraph: ECMP", () => {
  it("forks after the shared device and centres it over the 2 tracks", () => {
    const g = buildPathGraph(FIXTURE_PATH_ECMP, "devices");
    // the VRF only lane 0 takes is kept: it is where the 2 lanes differ
    expect(g.boxes.map((b) => b.hop.uid)).toEqual([
      "if:core1/eth0.10",
      "dev:core1",
      "vrf:default",
      "tun:wg0",
      "if:core1/eth0.1",
    ]);
    const core = box(g, "dev:core1");
    expect(uids(g, core.out)).toEqual(["vrf:default", "tun:wg0"]);
    expect(core.lanes).toEqual([0, 1]);
    expect(core.ecmp).toBe(true);
    expect(core.row).toBe(0.5);
    expect(box(g, "vrf:default").row).toBe(0);
    expect(box(g, "if:core1/eth0.1").row).toBe(0);
    expect(box(g, "tun:wg0").row).toBe(1);
    expect(box(g, "tun:wg0").col).toBe(2);
    expect(link(g, box(g, "if:core1/eth0.10"), core)?.lanes).toEqual([0, 1]);
  });

  it("shows no ECMP badge on a split between 2 sources", () => {
    const g = buildPathGraph(FIXTURE_PATH_PARTITION, "devices");
    const core = box(g, "dev:core1");
    expect(core.out).toHaveLength(2);
    expect(core.ecmp).toBe(false);
  });
});

describe("buildPathGraph: 4-lane leaf and spine", () => {
  const g = buildPathGraph(FIXTURE_PATH_LEAF_SPINE, "devices");

  it("shares a box only on a common start or a common end", () => {
    expect(g.boxes.map((b) => b.hop.uid).sort()).toEqual(
      [
        "src",
        "dev:leaf1",
        "dev:spine1",
        "dev:spine2",
        "dev:border1",
        "dev:border2",
        "dev:fw-dc",
        "gate:fw-dc/rules",
        "gate:border2/acl-in",
        "dev:dc-core",
        "dst",
      ].sort(),
    );
    expect(box(g, "dev:border1").lanes).toEqual([0, 2]);
    expect(box(g, "dev:border2").lanes).toEqual([1, 3]);
    expect(box(g, "src").lanes).toEqual([0, 1, 2, 3]);
  });

  it("shows the splits as forks and the joins as merges", () => {
    expect(uids(g, box(g, "dev:leaf1").out)).toEqual(["dev:spine1", "dev:spine2"]);
    expect(uids(g, box(g, "dev:spine1").out)).toEqual(["dev:border1", "dev:border2"]);
    expect(uids(g, box(g, "dev:border1").in)).toEqual(["dev:spine1", "dev:spine2"]);
    expect(link(g, box(g, "dev:leaf1"), box(g, "dev:spine1"))?.lanes).toEqual([0, 1]);
    expect(link(g, box(g, "dev:border1"), box(g, "dev:fw-dc"))?.lanes).toEqual([0, 2]);
    expect(g.links).toHaveLength(12);
    expect(box(g, "dev:leaf1").ecmp).toBe(true);
    expect(box(g, "dev:spine1").ecmp).toBe(true);
  });

  it("sets the column to the longest path and keeps the rows on a grid of half tracks", () => {
    expect(box(g, "src").col).toBe(0);
    expect(box(g, "dev:spine1").col).toBe(2);
    expect(box(g, "dev:border2").col).toBe(3);
    expect(box(g, "gate:border2/acl-in").col).toBe(4);
    expect(box(g, "dst").col).toBe(7);
    // a straight track, then a fork around it, then 2 joins side by side
    expect(box(g, "src").row).toBe(0.5);
    expect(box(g, "dev:leaf1").row).toBe(0.5);
    expect(box(g, "dev:spine1").row).toBe(0);
    expect(box(g, "dev:spine2").row).toBe(1);
    expect(box(g, "dev:border1").row).toBe(0);
    expect(box(g, "dev:border2").row).toBe(1);
    expect(box(g, "dev:fw-dc").row).toBe(0);
    expect(g.boxes.every((b) => Number.isInteger(b.row * 2))).toBe(true);
  });

  it("names the interfaces of each lane on the link", () => {
    expect(link(g, box(g, "dev:leaf1"), box(g, "dev:spine1"))?.via.get(0)).toBe("eth49 > eth1");
    expect(link(g, box(g, "dev:spine2"), box(g, "dev:border1"))?.via.get(2)).toBe("eth3 > eth2");
  });

  it("carries the gate verdicts and the outcome at the end of each lane", () => {
    expect(box(g, "gate:fw-dc/rules").verdict).toBe("ok");
    expect(box(g, "gate:border2/acl-in").verdict).toBe("bad");
    expect(box(g, "gate:border2/acl-in").ends).toEqual([1, 3]);
    expect(box(g, "dst").ends).toEqual([0, 2]);
    expect(box(g, "dst").endOutcome).toBe("ok");
  });

  it("names the first box after each fork of a path", () => {
    expect(pathVia(g, 0)).toEqual(["spine1", "border1"]);
    expect(pathVia(g, 3)).toEqual(["spine2", "border2"]);
  });

  it("lights the lanes of a selected leg, or the lanes through a selected hop", () => {
    expect([...selectedLanes(g, { type: "leg", data: FIXTURE_PATH_LEAF_SPINE.legs[2] })!]).toEqual([2]);
    const border1 = FIXTURE_PATH_LEAF_SPINE.hops.find((h) => h.uid === "dev:border1" && h.lane === 2)!;
    expect([...selectedLanes(g, { type: "hop", data: border1 })!]).toEqual([0, 2]);
    const vrf = FIXTURE_PATH_LEAF_SPINE.hops.find((h) => h.kind === "VrfInstance")!;
    expect(boxOfHop(g, vrf)).toBeUndefined();
    expect(selectedLanes(g, { type: "hop", data: vrf })).toBeNull();
    expect(selectedLanes(g, null)).toBeNull();
  });
});

describe("buildPathGraph: tracks", () => {
  it("gives each visit of a hairpin its own box, so the graph has no cycle", () => {
    const hops = [dev("a", 0), dev("b", 1), dev("a", 2), dev("c", 3)];
    const g = buildPathGraph({ hops, legs: [leg(0)] }, "devices");
    expect(g.boxes.map((b) => b.hop.uid)).toEqual(["a", "b", "a", "c"]);
    expect(g.boxes.map((b) => b.col)).toEqual([0, 1, 2, 3]);
    expect(boxOfHop(g, hops[2])?.col).toBe(2);
  });

  it("keeps the carrier's hops as boxes of their own", () => {
    const hops = [
      dev("edge1", 0, 0, { shared: true }),
      { uid: "tun:a", kind: "Tunnel", label: "tun-a", note: "", rank: 1, lane: 0, shared: false } as Hop,
      dev("transit", 2, 0, { overlay: 1, tunnel: "tun:a" }),
      dev("edge2", 3),
    ];
    const g = buildPathGraph({ hops, legs: [leg(0)] }, "devices");
    expect(g.boxes.map((b) => b.hop.uid)).toEqual(["edge1", "transit", "edge2"]);
    expect(box(g, "transit").hop.overlay).toBe(1);
    expect(link(g, box(g, "edge1"), box(g, "transit"))?.via.get(0)).toBe("tun-a");
  });

  it("draws a hop that 2 lanes cross at different places once on each track", () => {
    const hops = [dev("s", 0, 0, { shared: true }), dev("x", 1, 0), dev("y", 2, 0), dev("y", 1, 1), dev("x", 2, 1)];
    const g = buildPathGraph({ hops, legs: [leg(0), leg(1)] }, "devices");
    expect(g.boxes).toHaveLength(5);
    expect(boxesOf(g, "x")).toHaveLength(2);
    expect(boxesOf(g, "y")).toHaveLength(2);
    expect(g.boxes.every((b) => Number.isFinite(b.col) && b.col >= 0)).toBe(true);
  });

  it("joins 2 tracks again on a common end", () => {
    const hops = [dev("s", 0, 0, { shared: true }), dev("x", 1, 0), dev("z", 2, 0), dev("y", 1, 1), dev("z", 2, 1)];
    const g = buildPathGraph({ hops, legs: [leg(0), leg(1)] }, "devices");
    expect(box(g, "z").lanes).toEqual([0, 1]);
    expect(uids(g, box(g, "z").in)).toEqual(["x", "y"]);
    expect(box(g, "z").row).toBe(0.5);
  });

  it("gives the same layout for the same response, whatever the order of the hops", () => {
    const place = (g: PathGraph) => g.boxes.map((b) => [b.key, b.col, b.row]).sort();
    const a = buildPathGraph(FIXTURE_PATH_LEAF_SPINE, "devices");
    const b = buildPathGraph(FIXTURE_PATH_LEAF_SPINE, "devices");
    const shuffled = buildPathGraph(
      { ...FIXTURE_PATH_LEAF_SPINE, hops: [...FIXTURE_PATH_LEAF_SPINE.hops].reverse() },
      "devices",
    );
    expect(place(b)).toEqual(place(a));
    expect(place(shuffled)).toEqual(place(a));
  });
});
