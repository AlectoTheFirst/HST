import { describe, expect, it } from "vitest";
import { GATEWAY_FRAME, layoutSdwan } from "./layout";
import { TOPOLOGY } from "./fixture";

const node = (uid: string) => layoutSdwan(TOPOLOGY).nodes.find((n) => n.uid === uid)!;

describe("layoutSdwan", () => {
  it("puts one frame for each site in code order, and the gateways last", () => {
    const { frames } = layoutSdwan(TOPOLOGY);
    expect(frames.map((f) => f.key)).toEqual(["FR2", "FR6", GATEWAY_FRAME]);
    for (let i = 1; i < frames.length; i++) {
      expect(frames[i].x).toBeGreaterThan(frames[i - 1].x + frames[i - 1].width);
    }
  });

  it("puts the switches above the hubs, and the WAN links above the edge", () => {
    expect(node("sw1").y).toBeLessThan(node("h1").y);
    expect(node("h1").y).toBe(node("g1").y);
    expect(node("h1").y).toBeLessThan(node("l3").y);
    expect(node("l3").y).toBeLessThan(node("e1").y);
  });

  it("puts the devices of a site in name order and the WAN links in interface order", () => {
    expect(node("sw1").x).toBeLessThan(node("sw2").x);
    expect(node("l3").x).toBeLessThan(node("l4").x);
    expect(node("l3").name).toBe("GE3 BT DIA 1");
    expect(node("l3").caption).toBe("BT, 192.0.2.61, 600/600 Mbit/s");
  });

  it("starts a tunnel at the WAN link of its interface, or at the edge", () => {
    const tunnels = new Map(layoutSdwan(TOPOLOGY).tunnels.map((t) => [t.uid, t]));
    expect(tunnels.get("t1")).toMatchObject({ from: "l3", to: "h1", kind: "hub" });
    expect(tunnels.get("t2")).toMatchObject({ from: "l4", to: "h2" });
    expect(tunnels.get("t3")).toMatchObject({ from: "l3", to: "g1", kind: "gateway" });
    expect(tunnels.get("t4")).toMatchObject({ from: "e1", to: "h1" });
  });

  it("counts a tunnel without a far end and does not draw it", () => {
    const l = layoutSdwan(TOPOLOGY);
    expect(l.tunnels.map((t) => t.uid)).not.toContain("t5");
    expect(l.unresolved).toBe(1);
  });

  it("gives each parallel cable of one device pair its own lane", () => {
    const lanes = layoutSdwan(TOPOLOGY).cables.map((c) => [c.a, c.b, c.lane]);
    expect(lanes).toEqual([
      ["h1", "sw1", 0],
      ["sw1", "sw6", 0],
      ["sw1", "sw6", 1],
    ]);
  });

  it("keeps all the nodes in the fit frame", () => {
    const l = layoutSdwan(TOPOLOGY);
    for (const n of l.nodes) {
      expect(n.x - n.w / 2).toBeGreaterThanOrEqual(l.fit.x);
      expect(n.x + n.w / 2).toBeLessThanOrEqual(l.fit.x + l.fit.w);
      expect(n.y + n.h / 2).toBeLessThanOrEqual(l.fit.y + l.fit.h);
    }
  });

  it("puts a hub without a site in a frame of its own", () => {
    const l = layoutSdwan({ ...TOPOLOGY, hubs: [...TOPOLOGY.hubs, { uid: "h9", name: "LONE-RTH", site: null }] });
    expect(l.frames.map((f) => f.label)).toEqual(["FR2", "FR6", "No site", "Cloud gateways"]);
  });
});
