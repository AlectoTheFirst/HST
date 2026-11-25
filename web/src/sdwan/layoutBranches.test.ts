import { describe, expect, it } from "vitest";
import type { SdwanTopology } from "../api/types";
import { BRANCH_FRAME, branchGroupUid, layoutSdwan } from "./layout";
import { TOPOLOGY } from "./fixture";

/** A picked hub: 2 WAN links, tunnels to 3 branches at 2 sites and to 1
 *  branch without a site. */
const HUB: SdwanTopology = {
  ...TOPOLOGY,
  edge: { uid: "h1", name: "XX-DC1-RTH-03", role: "hub" },
  tunnels: [
    { uid: "b1-a", interface: "GE3", peer: "b1", peer_kind: "branch", peer_ip: "198.51.100.1" },
    { uid: "b1-b", interface: "GE4", peer: "b1", peer_kind: "branch", peer_ip: "198.51.100.2" },
    { uid: "b2-a", interface: "GE3", peer: "b2", peer_kind: "branch", peer_ip: "198.51.100.3" },
    { uid: "b3-a", interface: "GE3", peer: "b3", peer_kind: "branch", peer_ip: "198.51.100.4" },
    { uid: "b4-a", interface: "GE3", peer: "b4", peer_kind: "branch", peer_ip: "198.51.100.5" },
  ],
  hubs: [],
  branches: [
    { uid: "b2", name: "XX-BER-BR-02", site: "BER" },
    { uid: "b1", name: "XX-BER-BR-01", site: "BER" },
    { uid: "b3", name: "XX-MUC-BR-01", site: "MUC" },
    { uid: "b4", name: "XX-LONE-BR-01", site: null },
  ],
  gateways: [],
  devices: [],
  sites: [],
  cables: [],
};

describe("layoutSdwan for a picked hub", () => {
  it("draws the branches as one counted chip for each site in a frame of their own", () => {
    const l = layoutSdwan(HUB);
    expect(l.frames.map((f) => [f.key, f.label])).toEqual([[BRANCH_FRAME, "Branches"]]);
    const groups = l.nodes.filter((n) => n.kind === "branches");
    expect(groups.map((n) => [n.uid, n.name, n.caption])).toEqual([
      [branchGroupUid("BER"), "BER", "2 branches"],
      [branchGroupUid("MUC"), "MUC", "1 branch"],
      [branchGroupUid(null), "No site", "1 branch"],
    ]);
    expect(groups[0].members).toEqual(["XX-BER-BR-01", "XX-BER-BR-02"]);
    expect(l.nodes.some((n) => n.kind === "hub")).toBe(false);
    expect(l.nodes.some((n) => n.caption === "hub")).toBe(false);
  });

  it("draws one line from a WAN link to the branches of one site, with the tunnel count", () => {
    const l = layoutSdwan(HUB);
    const lines = l.tunnels.map((t) => [t.from, t.to, t.kind, t.count]);
    expect(lines).toEqual([
      ["l3", branchGroupUid("BER"), "branch", 2],
      ["l4", branchGroupUid("BER"), "branch", 1],
      ["l3", branchGroupUid("MUC"), "branch", 1],
      ["l3", branchGroupUid(null), "branch", 1],
    ]);
    expect(l.unresolved).toBe(0);
  });
});
