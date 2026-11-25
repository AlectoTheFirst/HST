import { describe, expect, it } from "vitest";
import { buildPathTree, ownedHops, rowText, treeRows, treeText, type TreeRow } from "./pathTree";
import { buildPathGraph, laneWalks } from "./pathGraph";
import { FIXTURE_PATH_ECMP, FIXTURE_PATH_LEAF_SPINE, FIXTURE_PATH_SINGLE } from "../test/fixtures";

const items = (rows: TreeRow[]) => rows.filter((r) => r.type === "item");
const line = (r: TreeRow) => r.prefix + (r.type === "item" ? r.node.box.hop.label : r.type === "hop" ? r.hop.label : "leg");

describe("pathTree: a single path", () => {
  it("lists the devices on 1 indent, with no guides", () => {
    const tree = buildPathTree(FIXTURE_PATH_SINGLE);
    const rows = treeRows(tree, new Set());
    expect(rows.map(line)).toEqual(["host44", "sw1", "core1", "eth0.1"]);
    expect(rows.every((r) => r.level === 1)).toBe(true);
  });
});

describe("pathTree: 4-lane leaf and spine", () => {
  const tree = buildPathTree(FIXTURE_PATH_LEAF_SPINE);
  const rows = treeRows(tree, new Set());

  it("indents only at a fork, and shows each branch's full path to the end", () => {
    expect(rows.map(line)).toEqual([
      "10.20.1.15",
      "leaf1",
      "|-- spine1",
      "|   |-- border1",
      "|   |   fw-dc",
      "|   |   rules",
      "|   |   dc-core",
      "|   |   10.40.2.20",
      "|   `-- border2",
      "|       acl-in",
      "`-- spine2",
      "    |-- border1",
      "    |   fw-dc",
      "    |   rules",
      "    |   dc-core",
      "    |   10.40.2.20",
      "    `-- border2",
      "        acl-in",
    ]);
    expect(items(rows).map((r) => r.level)).toEqual([1, 1, 2, 3, 3, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3]);
  });

  it("ends each lane on its own item, once", () => {
    const ends = items(rows).flatMap((r) => (r.type === "item" ? r.node.ends : []));
    expect(ends.sort()).toEqual([0, 1, 2, 3]);
    const last = items(rows).filter((r) => r.type === "item" && r.node.ends.length > 0);
    expect(last.map((r) => (r.type === "item" ? r.node.lanes : []))).toEqual([[0], [1], [2], [3]]);
  });

  it("carries the fork, the verdict and the end of each lane in the text", () => {
    const text = treeText(tree, rows).split("\n");
    expect(text[1]).toBe("leaf1  Device  leaf1 note  ECMP 2");
    expect(text[5]).toBe("|   |   rules  permitted  permit (rule 210 app-https)");
    expect(text[7]).toBe("|   |   10.40.2.20  IpAddress  10.40.2.20 note  Path 1 forwarded");
    expect(text[9]).toBe("|       acl-in  blocked  deny (rule 40 iot-to-dc)  Path 2 blocked by acl-in rule 40");
  });

  it("opens an item's hops for each lane under it, with the guide kept", () => {
    const id = rows[1].id;
    const open = treeRows(tree, new Set([id]));
    const hops = open.filter((r) => r.type === "hop" && r.parent === id);
    expect(hops.map((r) => (r.type === "hop" ? `${r.lane} ${r.hop.label}` : ""))).toEqual([
      "0 vlan20", "0 prod", "0 10.40.0.0/16", "0 eth49",
      "1 vlan20", "1 prod", "1 10.40.0.0/16", "1 eth49",
      "2 vlan20", "2 prod", "2 10.40.0.0/16", "2 eth50",
      "3 vlan20", "3 prod", "3 10.40.0.0/16", "3 eth50",
    ]);
    expect(hops.every((r) => r.prefix === "|   " && r.level === 2)).toBe(true);
    const hop = hops[0];
    expect(rowText(hop, tree)).toBe("Path 1  vlan20  Interface  vlan20 note");
  });

  it("adds a leg line on the last item of a lane when asked", () => {
    const end = rows.find((r) => r.type === "item" && r.node.ends.includes(1))!;
    const open = treeRows(tree, new Set([end.id]), (lane) => lane === 1);
    const legs = open.filter((r) => r.type === "leg");
    expect(legs).toHaveLength(1);
    expect(legs[0].prefix).toBe("|           ");
  });
});

describe("ownedHops", () => {
  it("gives each left-out hop to the device before it, and the way in to the device after", () => {
    const walk = laneWalks(FIXTURE_PATH_LEAF_SPINE)[0];
    const owned = ownedHops(walk, buildPathGraph(FIXTURE_PATH_LEAF_SPINE, "devices").kept.get(walk.lane)!);
    const of = (uid: string) => owned.get(walk.hops.findIndex((h) => h.uid === uid))!.map((h) => h.uid);
    expect(of("dev:leaf1")).toEqual(["if:leaf1/vlan20", "vrf:leaf1/prod", "pfx:leaf1/10.40.0.0/16", "if:leaf1/eth49"]);
    expect(of("dev:spine1")).toEqual(["if:spine1/eth1", "pfx:spine1/10.40.0.0/16", "if:spine1/eth3"]);
    // the gate is an item of its own: the hops after it go back to its device
    expect(of("gate:fw-dc/rules")).toEqual([]);
    expect(of("dev:fw-dc")).toEqual(["if:fw-dc/eth1", "if:fw-dc/eth2"]);
    expect(of("dev:dc-core")).toEqual(["if:dc-core/eth1", "if:dc-core/vlan40"]);
  });
});

describe("pathTree: ECMP", () => {
  it("forks the 2 lanes under the shared device, each branch to its end", () => {
    const tree = buildPathTree(FIXTURE_PATH_ECMP);
    const rows = treeRows(tree, new Set());
    expect(rows.map(line)).toEqual(["eth0.10", "core1", "|-- default", "|   eth0.1", "`-- wg0"]);
    const core = rows[1];
    expect(core.type === "item" && core.node.ecmp).toBe(true);
    // the route is a hidden hop of the VRF that only lane 0 takes
    expect(rows[2].type === "item" && rows[2].hasDetail).toBe(true);
    expect(rows[4].type === "item" && rows[4].hasDetail).toBe(false);
  });
});
